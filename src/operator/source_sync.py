"""Bounded private publication receipts; a queued export is never a Git receipt.

The backup worker supplies versions read from the snapshot it actually pushed.
Neither the latest queue id nor a previous successful push proves inclusion.
All mutations use the same process-independent lock and atomic durable replace.
"""
from contextlib import contextmanager
import copy
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile
import time
import uuid


SESSION = re.compile(r'session-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}')
IDENT = re.compile(r'[a-f0-9]{32}')
VERSION = re.compile(r'[a-f0-9]{16,64}')
COMMIT = re.compile(r'[a-f0-9]{40,64}')
REPOSITORY = re.compile(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+')
REASONS = {'program_publish', 'tool_publish', 'skill_publish', 'policy_apply',
           'audit_plan_set', 'audit_plan_enable', 'native_observe'}
ERROR_CODES = {'push_rejected', 'sync_failed', 'unexpected_branch',
               'uncommitted_repository_changes', 'diverged_history_requires_review',
               'remote_program_changes_require_deployment', 'invalid_publication_request',
               'publication_snapshot_mismatch', 'snapshot_not_verified',
               'CalledProcessError', 'TimeoutExpired', 'OSError', 'ValueError'}
TERMINAL = {'success', 'superseded'}
MAX_BYTES = 512 * 1024
ARTIFACT_GROUP = {'audit_plan_set': 'audit-plan', 'audit_plan_enable': 'audit-plan',
                  'native_observe': 'audit-plan'}


def valid_session(value):
    return isinstance(value, str) and SESSION.fullmatch(value) is not None


def snapshot_versions(files):
    """Version only the bytes in the exported snapshot, never live mutable state."""
    artifacts = {'program_publish': 'src/maintained/diagnostic.py',
                 'tool_publish': 'src/maintained/tool.py', 'skill_publish': 'src/dsh/skill/SKILL.md',
                 'policy_apply': 'preferences/network-policy.json',
                 'audit_plan_set': 'preferences/audit-plan.json',
                 'audit_plan_enable': 'preferences/audit-plan.json',
                 'native_observe': 'preferences/audit-plan.json'}
    return {reason: hashlib.sha256(files[name]).hexdigest()[:16]
            for reason, name in artifacts.items() if name in files}


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _notice_id(record):
    return f"gateway-source-sync-{record['id']}-{record['revision']}"


class SourceSyncRegistry:
    def __init__(self, path, max_records=256):
        self.path = Path(path)
        if not isinstance(max_records, int) or not 1 <= max_records <= 512:
            raise ValueError('invalid receipt capacity')
        self.max_records = max_records

    @contextmanager
    def _locked(self, mutate=False):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(str(self.path) + '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX if mutate else fcntl.LOCK_SH)
            try:
                descriptor = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
            except FileNotFoundError:
                state = {'format': 1, 'sequence': 0, 'records': []}
            else:
                with os.fdopen(descriptor, 'r') as stream:
                    raw = stream.read(MAX_BYTES + 1)
                if len(raw.encode()) > MAX_BYTES:
                    raise ValueError('receipt registry exceeds byte budget')
                try:
                    state = json.loads(raw)
                except (ValueError, TypeError):
                    raise ValueError('receipt registry requires recovery') from None
                if (not isinstance(state, dict) or state.get('format') != 1 or
                        not isinstance(state.get('sequence'), int) or
                        type(state.get('notice_cursor', 0)) is not int or
                        not 0 <= state.get('notice_cursor', 0) <= state['sequence'] or
                        not isinstance(state.get('records'), list) or len(state['records']) > 512):
                    raise ValueError('receipt registry requires recovery')
            previous = json.dumps(state, sort_keys=True)
            yield state
            if mutate and json.dumps(state, sort_keys=True) != previous:
                self._save(state)

    def _save(self, state):
        data = (json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()
        if len(data) > MAX_BYTES:
            raise ValueError('receipt registry exceeds byte budget')
        descriptor, temporary = tempfile.mkstemp(prefix=self.path.name + '.', dir=self.path.parent)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            Path(temporary).unlink(missing_ok=True)

    @staticmethod
    def _time(now):
        value = time.time() if now is None else now
        if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError('invalid receipt timestamp')
        return value

    def register(self, reason, session_id=None, version=None, request_id=None, now=None):
        if reason not in REASONS:
            raise ValueError('invalid publication reason')
        if session_id is not None and not valid_session(session_id):
            raise ValueError('invalid originating session')
        if version is not None and not _matches(VERSION, version):
            raise ValueError('invalid publication version')
        request_id = uuid.uuid4().hex if request_id is None else request_id
        if not _matches(IDENT, request_id):
            raise ValueError('invalid publication request')
        timestamp = self._time(now)
        with self._locked(mutate=True) as state:
            for record in state['records']:
                if record['id'] == request_id:
                    if (record['reason'], record['session_id'], record['version']) != (reason, session_id, version):
                        raise ValueError('publication request identity conflict')
                    return copy.deepcopy(record)
            removable = [r for r in state['records'] if r['status'] in TERMINAL and
                         (r['session_id'] is None or r.get('delivered_revision') == r['revision'])]
            while len(state['records']) >= self.max_records and removable:
                state['records'].remove(removable.pop(0))
            if len(state['records']) >= self.max_records:
                raise ValueError('publication receipt capacity reached')
            state['sequence'] += 1
            record = {'id': request_id, 'sequence': state['sequence'], 'reason': reason,
                      'artifact': reason, 'version': version, 'session_id': session_id,
                      'status': 'pending', 'revision': 1, 'delivered_revision': 0,
                      'requested_at': timestamp, 'updated_at': timestamp}
            state['records'].append(record)
            return copy.deepcopy(record)

    @staticmethod
    def _transition(record, status, now, **details):
        current = {key: record[key] for key in ('error_code', 'remote_commit', 'repository_url',
                    'branch', 'acknowledged_request', 'superseded_by') if key in record}
        if record['status'] == status and current == details:
            return
        for key in current:
            record.pop(key)
        record.update(status=status, updated_at=now, revision=record['revision'] + 1, **details)

    def reconcile(self, status=None, held=False, now=None):
        timestamp = self._time(now)
        status = status if isinstance(status, dict) else {}
        with self._locked(mutate=True) as state:
            by_id = {r['id']: r for r in state['records']}
            acknowledged = by_id.get(status.get('acknowledged_request'))
            attempted = by_id.get(status.get('attempted_request'))
            versions = status.get('acknowledged_versions')
            versions = versions if isinstance(versions, dict) else {}
            verified_commit = ((status.get('result') == 'success' and
                                status.get('local_commit') == status.get('remote_commit')) or
                               (status.get('result') == 'failed' and
                                status.get('acknowledged_commit') == status.get('remote_commit')))
            proof = (verified_commit and acknowledged is not None and
                     _matches(COMMIT, status.get('remote_commit')) and
                     status.get('branch') == 'main' and status.get('expected_branch') == 'main' and
                     _matches(REPOSITORY, status.get('repository_url')))
            for record in state['records']:
                if record['status'] in TERMINAL:
                    continue
                # A durable successful push outranks a hold introduced afterwards.
                if proof and record['sequence'] <= acknowledged['sequence']:
                    version = record['version']
                    included = versions.get(record['artifact'])
                    if version is not None and included == version:
                        self._transition(record, 'success', timestamp,
                                         remote_commit=status['remote_commit'], repository_url=status['repository_url'],
                                         branch='main', acknowledged_request=acknowledged['id'])
                        continue
                    replacement = next((r for r in reversed(state['records'])
                                        if record['sequence'] < r['sequence'] <= acknowledged['sequence'] and
                                        ARTIFACT_GROUP.get(r['artifact'], r['artifact']) ==
                                        ARTIFACT_GROUP.get(record['artifact'], record['artifact']) and r['version'] is not None and
                                        r['version'] == included), None)
                    if replacement is not None:
                        self._transition(record, 'superseded', timestamp, superseded_by=replacement['id'])
                    else:
                        self._transition(record, 'failed', timestamp, error_code='publication_snapshot_mismatch')
                elif held:
                    self._transition(record, 'held', timestamp)
                elif status.get('result') == 'failed' and attempted and record['sequence'] <= attempted['sequence']:
                    code = status.get('error_code')
                    self._transition(record, 'failed', timestamp, error_code=code if code in ERROR_CODES else 'sync_failed')
                elif record['status'] == 'held' or not status:
                    self._transition(record, 'pending', timestamp)
            return {'pending': any(r['status'] not in TERMINAL for r in state['records']),
                    'held': bool(held), 'receipt_count': len(state['records'])}

    def records(self):
        with self._locked() as state:
            return copy.deepcopy(state['records'])

    def pending(self):
        return any(r['status'] not in TERMINAL for r in self.records())

    def notices(self, limit=32):
        if not isinstance(limit, int) or not 1 <= limit <= 64:
            raise ValueError('invalid notice limit')
        with self._locked(mutate=True) as state:
            records = [r for r in state['records'] if valid_session(r['session_id']) and r['delivered_revision'] < r['revision']]
            cursor = state.get('notice_cursor', 0)
            # Advance when offered, even if an unavailable recipient cannot
            # acknowledge. Persisting the cursor makes process restarts fair.
            ordered = [r for r in records if r['sequence'] > cursor]
            ordered.extend(r for r in records if r['sequence'] <= cursor)
            selected = ordered[:limit]
            if selected:
                state['notice_cursor'] = selected[-1]['sequence']
            return {'notices': [copy.deepcopy({**r, 'notice_id': _notice_id(r)}) for r in selected],
                    'pending': len(records)}

    def acknowledge(self, request_id, revision, session_id, message_id):
        with self._locked(mutate=True) as state:
            record = next((r for r in state['records'] if r['id'] == request_id), None)
            if (record is None or not valid_session(session_id) or record['session_id'] != session_id or
                    type(revision) is not int or record['revision'] != revision or message_id != _notice_id(record)):
                return {'acknowledged': False}
            record['delivered_revision'] = revision
            return {'acknowledged': True}
