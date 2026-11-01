"""Bounded node-pool incident evidence shared by selector and AI dispatcher."""
import hashlib
import json
import math
import re

MAX_EVENTS=64
RETENTION=6*3600
MAX_GAP=180


def sequence(value):return value if isinstance(value,list) else []

def number(value):return type(value) in [int,float] and math.isfinite(value) and value>=0

def identity(value,size):return isinstance(value,str) and re.fullmatch('[a-f0-9]{'+str(size)+'}',value) is not None

def valid_events(document,now):
    values=sequence(document.get('recent_events')) if isinstance(document,dict) else []
    result=[]
    for row in values[-128:]:
        if not isinstance(row,dict) or not identity(row.get('id'),20) or not identity(row.get('policy_id'),16) or not number(row.get('at')) or not now-RETENTION<=row['at']<=now:continue
        if 'selected_region' not in row or row['selected_region'] not in ['US_AUTO','OTHER_AUTO','DIRECT',None]:continue
        if type(row.get('preferred_failed')) is not bool or type(row.get('unavailable')) is not bool:continue
        value={k:row[k] for k in ['at','id','policy_id','selected_region','preferred_failed','unavailable']}
        value['attempts']=[{'region':r['region'],'ok':r['ok']} for r in sequence(row.get('attempts'))[:4] if isinstance(r,dict) and r.get('region') in ['US_AUTO','OTHER_AUTO'] and type(r.get('ok')) is bool]
        value['incident_id']=row.get('incident_id') if identity(row.get('incident_id'),20) else row['id']
        start=row.get('incident_started_at');value['incident_started_at']=start if number(start) and start<=row['at'] else row['at']
        value['unavailable_seen']=row.get('unavailable_seen') is True or row['unavailable']
        result.append(value)
    return sorted(result,key=lambda x:x['at'])[-MAX_EVENTS:]

def valid_incidents(document,now):
    values=sequence(document.get('incident_history')) if isinstance(document,dict) else []
    return [{k:row[k] for k in ['id','policy_id','started_at','recovered_at']} for row in values[-32:]
            if isinstance(row,dict) and identity(row.get('id'),20) and identity(row.get('policy_id'),16)
            and number(row.get('started_at')) and number(row.get('recovered_at'))
            and row['started_at']<=row['recovered_at'] and now-86400<=row['recovered_at']<=now][-16:]


def policy_id(policy):
    return hashlib.sha256(json.dumps(policy.get('preferences',{}),sort_keys=True).encode()).hexdigest()[:16]


def event(at,region,attempts,policy):
    if not isinstance(at,(int,float)) or not math.isfinite(at):raise ValueError('valid observation timestamp required')
    if region not in ['US_AUTO','OTHER_AUTO','DIRECT',None]:raise ValueError('unknown selected pool')
    rows=[{'region':r['region'],'ok':r.get('ok') is True} for r in attempts[:4] if isinstance(r,dict) and r.get('region') in ['US_AUTO','OTHER_AUTO']]
    preferred=[r['ok'] for r in rows if r['region']=='US_AUTO']
    failed=len(preferred)>=2 and not any(preferred)
    ident=hashlib.sha256(json.dumps([at,region,rows,policy_id(policy)]).encode()).hexdigest()[:20]
    return {'at':at,'id':ident,'incident_id':ident,'incident_started_at':at,'selected_region':region,'attempts':rows,
            'preferred_failed':failed,'unavailable':region is None and bool(rows),'policy_id':policy_id(policy)}


def append(document,current,now):
    rows=valid_events(document,now)
    current=dict(current)
    connected=rows and rows[-1]['policy_id']==current['policy_id'] and 0<=current['at']-rows[-1]['at']<=MAX_GAP
    if current['preferred_failed'] and connected and rows[-1]['preferred_failed']:
        current['incident_id']=rows[-1].get('incident_id',rows[-1]['id'])
        current['incident_started_at']=rows[-1].get('incident_started_at',rows[-1]['at'])
        current['unavailable_seen']=current['unavailable'] or rows[-1].get('unavailable_seen',rows[-1].get('unavailable',False))
    history=valid_incidents(document,now)
    if not current['preferred_failed'] and connected and rows[-1]['preferred_failed']:
        last=rows[-1];start=last.get('incident_started_at',last['at'])
        if last.get('unavailable_seen',last.get('unavailable')) or last['at']-start>=120:
            history.append({'id':last.get('incident_id',last['id']),'started_at':start,'recovered_at':current['at'],'policy_id':current['policy_id']})
    return {'recent_events':[*rows,current][-MAX_EVENTS:],'incident_history':history[-16:]}


def summarize(document,policy,now):
    unknown={'state':'unknown','urgent':False,'review_due':False,'events':[],'fingerprint':None}
    if policy.get('preferences',{}).get('mode')=='direct':return {**unknown,'state':'not_used'}
    if not isinstance(document,dict):return unknown
    rows=[r for r in valid_events(document,now) if r['policy_id']==policy_id(policy)]
    if not rows:return unknown
    last=rows[-1];active=0<=now-last['at']<=180
    segments=[];segment=[];previous=None
    for row in rows:
        if previous is not None and row['at']-previous['at']>MAX_GAP:
            if segment:segments.append(segment);segment=[]
            row['incident_started_at']=row['at'];row['incident_id']=row['id']
        if row.get('preferred_failed'):segment.append(row)
        elif segment:segments.append(segment);segment=[]
        previous=row
    if segment:segments.append(segment)
    significant=[s for s in segments if any(x.get('unavailable') for x in s) or (len(s)>=2 and s[-1]['at']-s[0]['at']>=120)]
    current=next((s for s in segments if s[-1]['id']==last['id']),[])
    sustained=len(current)>=2 and current[-1]['at']-current[0].get('incident_started_at',current[0]['at'])>=120
    urgent=active and (last.get('unavailable') is True or sustained)
    state='unavailable' if active and last.get('unavailable') else 'preferred_degraded' if urgent else 'observing' if active and last.get('preferred_failed') else 'healthy' if active else 'stale'
    history=[x for x in valid_incidents(document,now) if x['policy_id']==policy_id(policy)]
    incident=current if urgent else significant[-1] if significant else []
    ident=incident[0].get('incident_id',incident[0]['id']) if incident else history[-1]['id'] if history else None
    return {'state':state,'urgent':bool(urgent),'review_due':bool((significant or history) and not urgent),'checked_at':last['at'],
            'fingerprint':'node-pool:'+ident if ident else None,'events':rows[-12:],
            'incident_history':history,
            'reason':'confirmed pool unavailable or preferred pool failed across multiple cycles' if urgent else 'recovered pool incident retained for bounded review' if significant or history else 'no persistent node-pool incident'}
