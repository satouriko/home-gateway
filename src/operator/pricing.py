"""Data-backed pricing clock. This gates routine reasoning, never fault recovery/chat."""
import datetime as dt
import json
from pathlib import Path
from zoneinfo import ZoneInfo

CONFIG = Path('/etc/net-gateway-agent/pricing.json')
DEFAULT = {'timezone':'Asia/Shanghai', 'peak_weekdays':[0,1,2,3,4],
    'peak_windows':[['09:00','12:00'],['14:00','18:00']], 'public_holidays':[],
    'verified_on':'2026-11-01', 'source':'https://api-docs.deepseek.com/zh-cn/quick_start/pricing/',
    'holiday_handling':'verified date overrides only; unknown holidays use conservative weekday pricing'}

def load_policy():
    return json.loads(CONFIG.read_text()) if CONFIG.exists() else DEFAULT

def pricing_state(now, policy=None):
    policy = {**load_policy(), **(policy or {})}
    local = dt.datetime.fromtimestamp(now, ZoneInfo(policy['timezone']))
    def peak_at(value):
        if value.weekday() not in policy['peak_weekdays'] or value.date().isoformat() in policy['public_holidays']: return False
        clock=value.strftime('%H:%M')
        return any(start <= clock < end for start,end in policy['peak_windows'])
    peak=peak_at(local)
    remaining=0
    if not peak:
        # The next transition is only used to bound a nine-minute routine job.
        for minute in range(1, 8*24*60+1):
            if peak_at(local+dt.timedelta(minutes=minute)):
                remaining=max(0,minute*60-local.second);break
    return {'peak':peak,'local_time':local.isoformat(),'timezone':policy['timezone'],
        'off_peak_seconds_remaining':remaining,'policy_verified_on':policy['verified_on'],'source':policy['source']}

def routine_allowed(now, policy=None):
    state=pricing_state(now,policy)
    return not state['peak'] and (state['off_peak_seconds_remaining']==0 or state['off_peak_seconds_remaining']>=660)
