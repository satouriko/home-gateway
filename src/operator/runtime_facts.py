"""Read-only, cached runtime facts; restart counters are never lifecycle history.

Only fixed commands and allowlisted numeric/identity fields cross this boundary.
Journal MESSAGE, Wi-Fi SSID/MAC, routes and raw command errors are never returned.
The journal window and row budget cannot establish a service's lifetime history.
"""
import copy
import json
import math
from pathlib import Path
import re
import threading
import time

from bounded import run as bounded_run

SERVICES=('net-gateway.service','dsh.service')
CACHE_SECONDS=60
JOURNAL_SECONDS=24*3600
JOURNAL_LIMIT=128
_START='39f53479d3a045ac8e11786248231fbf'
_STOP='9d1aaa27d60140bd96365438aad20286b'
_cache=None
_lock=threading.Lock()


def _command(args,limit=16384):
    try:
        result=bounded_run(args,timeout=2,stdout_limit=limit,stderr_limit=2048)
        if result.returncode==0:return result.stdout
    except (OSError,ValueError):pass
    return None


def _number(value,minimum=0):
    try:
        number=float(value)
        return number if math.isfinite(number) and number>=minimum else None
    except (ValueError,TypeError,OverflowError):return None


def _integer(value):
    if not isinstance(value,str) or not re.fullmatch(r'[0-9]{1,20}',value):return None
    return int(value)


def _read(path):
    try:return Path(path).read_text()[:8192]
    except (OSError,UnicodeError):return None


def _service(name):
    raw=_command(['systemctl','show',name,'--no-pager',
        '--property=MainPID,ActiveState,SubState,NRestarts,InvocationID,ExecMainStartTimestampMonotonic,ActiveEnterTimestampMonotonic'])
    data=dict(line.split('=',1) for line in (raw or '').splitlines() if '=' in line)
    invocation=data.get('InvocationID','')
    return {'status':'observed' if raw is not None else 'unknown','main_pid':_integer(data.get('MainPID')),
        'active_state':data.get('ActiveState') if data.get('ActiveState') in ['active','inactive','failed','activating','deactivating','reloading','maintenance'] else None,
        'sub_state':data.get('SubState') if re.fullmatch(r'[a-z-]{1,32}',data.get('SubState','')) else None,
        'invocation_id':invocation if re.fullmatch(r'[a-f0-9]{32}',invocation) else None,
        'process_start_monotonic_usec':_integer(data.get('ExecMainStartTimestampMonotonic')),
        'active_enter_monotonic_usec':_integer(data.get('ActiveEnterTimestampMonotonic')),
        'automatic_restart_count':_integer(data.get('NRestarts')),
        'restart_counter_scope':'systemd NRestarts counts automatic restarts only; manual start/stop and deployment lifecycle require journal evidence'}


def _lifecycle(now):
    start=max(0,now-JOURNAL_SECONDS)
    # PID 1 fields are trusted journal metadata. Manager MESSAGE_ID and UNIT
    # identify starts/stops without parsing or returning credential-bearing text.
    raw=_command(['journalctl','--no-pager','--output=json','--quiet','_PID=1',
        '--since=@'+str(int(start)),'--until=@'+str(int(now)),
        '--lines='+str(JOURNAL_LIMIT),
        '--output-fields=_PID,UNIT,MESSAGE_ID,__REALTIME_TIMESTAMP',
        'UNIT='+SERVICES[0],'UNIT='+SERVICES[1]],128*1024)
    records={name:[] for name in SERVICES};invalid=0
    lines=(raw or '').splitlines()
    for line in lines:
        try:
            row=json.loads(line)
            if not isinstance(row,dict):invalid+=1;continue
            if str(row.get('_PID'))!='1' or row.get('UNIT') not in SERVICES:continue
            if row.get('MESSAGE_ID') not in [_START,_STOP]:continue
            stamp=_integer(row.get('__REALTIME_TIMESTAMP'))
            if stamp is None or not start<=stamp/1000000<=now:invalid+=1;continue
            records[row['UNIT']].append({'at':stamp/1000000,'kind':'started' if row['MESSAGE_ID']==_START else 'stopped',
                                         'origin':'systemd_manager_journal'})
        except (ValueError,TypeError):invalid+=1
    coverage={'query_succeeded':raw is not None,'complete':False,'requested_since':start,'requested_until':now,
              'row_limit':JOURNAL_LIMIT,'row_limit_reached':len(lines)>=JOURNAL_LIMIT,
              'retention_start_at':None,'invalid_event_count':invalid,
              'gaps':['retention_unknown','bounded_window_not_lifetime_history']}
    if raw is None:coverage['gaps'].append('journal_unavailable')
    if len(lines)>=JOURNAL_LIMIT:coverage['gaps'].append('journal_row_limit')
    if invalid:coverage['gaps'].append('invalid_journal_records')
    return {name:{'observed_start_count':sum(r['kind']=='started' for r in rows) if raw is not None else None,
                  'observed_stop_count':sum(r['kind']=='stopped' for r in rows) if raw is not None else None,
                  'events':sorted(rows,key=lambda r:r['at'])[-16:],
                  'event_more_count':max(0,len(rows)-16),'coverage':copy.deepcopy(coverage)}
            for name,rows in records.items()}


def _host():
    uptime=_read('/proc/uptime'); memory=_read('/proc/meminfo');temp=_read('/sys/class/thermal/thermal_zone0/temp')
    result={'uptime_seconds':_number(uptime.split()[0]) if uptime and uptime.split() else None,
            'memory_total_bytes':None,'memory_available_bytes':None,'temperature_celsius':None,'throttled_flags':None}
    for key,field in [('MemTotal','memory_total_bytes'),('MemAvailable','memory_available_bytes')]:
        match=re.search(r'^'+key+r':\s*([0-9]+) kB\s*$',memory or '',re.M)
        if match:result[field]=int(match.group(1))*1024
    temperature=_number((temp or '').strip())
    if temperature is not None and temperature<=150000:result['temperature_celsius']=temperature/1000
    throttle=_command(['vcgencmd','get_throttled'],256)
    match=re.fullmatch(r'throttled=0x([0-9a-fA-F]{1,8})\s*',throttle or '')
    if match:result['throttled_flags']=int(match.group(1),16)
    result['evidence_limits']=['missing_metrics_unknown','throttled_flags_include_current_and_historical_bits']
    return result


def _uplink():
    # Route lookup does not send traffic and follows the live routing decision.
    raw=_command(['ip','-j','route','get','1.1.1.1'],4096)
    result={'status':'unknown','interface':None,'carrier':None,'signal_dbm':None,
            'rx_phy_mbit_s':None,'tx_phy_mbit_s':None,
            'evidence_limits':['single_sample','PHY_rates_not_measured_bandwidth','signal_does_not_establish_fault_cause',
                               'route_lookup_destination_1.1.1.1_only']}
    try:
        rows=json.loads(raw or 'null')
        interface=rows[0].get('dev') if isinstance(rows,list) and rows and isinstance(rows[0],dict) else None
        if not isinstance(interface,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}',interface):return result
    except (ValueError,TypeError,IndexError):return result
    result.update(status='observed',interface=interface)
    carrier=(_read('/sys/class/net/'+interface+'/carrier') or '').strip()
    if carrier in ['0','1']:result['carrier']=carrier=='1'
    link=_command(['iw','dev',interface,'link'],4096)
    signal=re.search(r'^\s*signal:\s*(-?[0-9]+(?:\.[0-9]+)?) dBm\s*$',link or '',re.M)
    if signal:result['signal_dbm']=_number(signal.group(1),-150)
    for direction in ['rx','tx']:
        match=re.search(r'^\s*'+direction+r' bitrate:\s*([0-9]+(?:\.[0-9]+)?) MBit/s(?:\s|$)',link or '',re.M)
        if match:result[direction+'_phy_mbit_s']=_number(match.group(1))
    return result


def collect(now=None):
    """Return independent cached facts, refreshed no more than once per minute.

    Missing binaries, insufficient journal access, incomplete retention and
    unavailable interfaces remain explicit unknowns. No command changes state.
    """
    global _cache
    now=time.time() if now is None else now
    if type(now) not in [int,float] or not math.isfinite(now) or now<0:raise ValueError('valid collection time required')
    with _lock:
        if _cache is not None and 0<=now-_cache['observed_at']<CACHE_SECONDS:return copy.deepcopy(_cache)
        lifecycle=_lifecycle(now)
        services={name:{**_service(name),'lifecycle':lifecycle[name]} for name in SERVICES}
        _cache={'schema_version':1,'observed_at':now,'cache_seconds':CACHE_SECONDS,
                'services':services,'host':_host(),'uplink':_uplink(),
                'evidence_limits':['runtime_facts_are_samples','deployment_success_is_not_network_or_logged_in_application_verification']}
        return copy.deepcopy(_cache)
