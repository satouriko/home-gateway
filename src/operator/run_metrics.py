"""Bounded native token accounting, separate from claims about repair success."""
import json
from pathlib import Path
import re

PROJECTIONS=Path('/var/lib/dsh/state/storages/session_projcache/sessions')
TOKEN_KEYS=['uncachedInputTokens','outputTokens','cacheReadTokens','cacheWriteTokens']


def summarize(events,session_id,root=None):
    calls=[e for e in events if e.get('type')=='tool_call']
    result={'tool_calls':len(calls),'completed_tool_results':sum(e.get('type')=='tool_result' and e.get('status')=='completed' for e in events),
            'incident_decision_attempts':sum(e.get('tool')=='gateway_incidents' and isinstance(e.get('input'),dict) and e['input'].get('operation')=='decide' for e in calls),
            'publication_attempts':sum(str(e.get('tool','')).startswith('gateway_') and isinstance(e.get('input'),dict) and e['input'].get('operation')=='publish' for e in calls),
            'repair_success':'requires explicit incident and target verification evidence',
            'usage':{'available':False,'reason':'native persisted totals not available'}}
    if not isinstance(session_id,str) or not re.fullmatch(r'session-[a-f0-9-]{36}',session_id):return result
    try:
        path=(Path(root) if root is not None else PROJECTIONS)/(session_id+'.json')
        if path.is_symlink() or path.stat().st_size>2*1024**2:return result
        data=json.loads(path.read_text())['record']['rows']['tokenUsage']
        totals=data['val']['totals']
        if any(type(totals.get(k)) is not int or totals[k]<0 for k in TOKEN_KEYS):return result
        result['usage']={'available':True,'source':'native session tokenUsage projection','projection_seq':data.get('seq'),
                         **{k:totals[k] for k in TOKEN_KEYS},'scope':'persisted session totals; provider billing may differ',
                         'freshness':'read after native projection refresh; unavailable or stale projection is not zero usage'}
    except (OSError,ValueError,KeyError,TypeError):pass
    return result
