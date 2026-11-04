"""Bounded publication prose; no model calls and no private runtime evidence."""
import json
import re


MAX_MESSAGE_BYTES = 4096
TITLE = re.compile(r'(?:feat|fix|refactor|perf|docs|test|build|ci|chore|revert)\([a-zA-Z0-9_.-]+\): [^\n]+')
SECRET_PATTERNS = [r'sk-[A-Za-z0-9_-]{16,}', r'(?:ghp_|github_pat_|gho_)[A-Za-z0-9_]{20,}',
                   r'-----BEGIN [A-Z ]*PRIVATE KEY-----', r'https?://[^\s/\"\']+:[^\s/\"\']+@',
                   r'https?://[^\s/\"\']+/link/[A-Za-z0-9_-]{12,}',
                   r'(?i)Bearer\s+[A-Za-z0-9_.-]{20,}']
ARTIFACT_PATHS = {'program_publish': 'src/maintained/diagnostic.py',
                  'workflow_publish': 'src/maintained/workflow.py',
                  'tool_publish': 'src/maintained/tool.py', 'skill_publish': 'src/dsh/skill/SKILL.md',
                  'policy_apply': 'preferences/network-policy.json',
                  'route_apply': 'preferences/network-policy.json',
                  'audit_plan_set': 'preferences/audit-plan.json',
                  'audit_plan_enable': 'preferences/audit-plan.json',
                  'native_observe': 'preferences/audit-plan.json'}


def validate_commit_message(value, forbidden=()):
    """Return normalized prose or a safe error; never include rejected values."""
    if not isinstance(value, str) or not value or len(value.encode()) > MAX_MESSAGE_BYTES:
        raise ValueError('invalid commit message')
    if any(ord(char) < 32 and char != '\n' for char in value):
        raise ValueError('invalid commit message')
    value = value.strip()
    paragraphs = value.split('\n\n')
    title = paragraphs[0]
    if (len(title) > 120 or TITLE.fullmatch(title) is None or
            re.search(r'[\u4e00-\u9fff]', title) is None or len(paragraphs) < 4 or
            not paragraphs[1].strip() or re.match(r'[^\n：:]{1,24}[：:]', paragraphs[1]) or
            not any(re.match(r'[^\n：:]{1,24}[：:]\s*\S', paragraph) for paragraph in paragraphs[2:-1]) or
            re.match(r'验证[：:]\s*\S', paragraphs[-1]) is None):
        raise ValueError('invalid commit message structure')
    if (any(re.search(pattern, value) for pattern in SECRET_PATTERNS) or
            any(secret in value for secret in forbidden if isinstance(secret, str) and secret) or
            re.search(r'(?im)^Co-authored-by:', value)):
        raise ValueError('sensitive commit message rejected')
    return value


def build_commit_message(versions, staged_paths, request=None, forbidden=()):
    """Describe only staged paths and exact exported versions, never latest live state.

    The caller validates the descriptor before changing its repository. Model
    validation text is attributed to its publisher; export checks are separate.
    """
    paths = sorted(set(staged_paths))
    selected = {}
    for publication in (request or {}).get('publications', []):
        reason = publication['reason']
        path = ARTIFACT_PATHS[reason]
        message = publication.get('commit_message')
        if (message and path in paths and publication['version'] is not None and
                versions.get(reason) == publication['version']):
            selected[path] = (publication, validate_commit_message(message, forbidden))
    messages = list(selected.values())
    if len(messages) == 1:
        publication, prose = messages[0]
        title, body = prose.split('\n\n', 1)
        result = f'{title}\n\n{body}\n\n发布说明：以上背景、模块改动及验证由维护会话记录。'
    elif messages:
        result = (f'chore(snapshot): 合并发布{len(messages)}项程序与偏好更新\n\n'
                  '多个发布在本次有限快照中一起导出，需要保留各自的背景、改动和验证记录。')
        for publication, prose in messages:
            result += f'\n\n发布说明（{publication["reason"]}，{publication["version"]}）：\n{prose}'
    else:
        result = (f'chore(snapshot): 同步{len(paths)}个程序与偏好文件\n\n'
                  '允许清单中的生效文件已发生变化，需要保留本次实际暂存内容以供恢复。\n\n'
                  '发布说明：本次没有同时匹配暂存文件和导出版本的维护会话说明。')
    result += '\n\n暂存文件：\n' + '\n'.join('- ' + json.dumps(path, ensure_ascii=False) for path in paths)
    if messages:
        result += '\n\n匹配版本：\n' + '\n'.join(
            f'- {publication["reason"]}: {publication["version"]}' for publication, _ in messages)
    result += '\n\n导出核验：提交前已检查网络事务状态并扫描公开目录；版本取自本次导出字节。\n'
    return result
