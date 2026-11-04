"""User-changeable preferences, separate from the technical survival boundary."""
import copy
import hashlib
import json
import re
from traffic import hostname

DEFAULTS={'mode':'rule','preferred_label':'美国','preferred_keywords':['美国','美國','🇺🇸','United States','USA','US'],
    'allow_other_regions':True,'allow_proxy_direct_fallback':False,'mainland_direct':True,'direct_domains':[],'proxy_domains':[], 'excluded_keywords':None,
    'adaptive_routes':{},'routing_strategy':{'require_degraded_current':True,'require_public_service_basis':True,'require_route_conflict':True,'allow_latency_only':False}}
AUTO_CONTROL_DOMAINS=('api.deepseek.com','dns.alidns.com','doh.pub','cloudflare-dns.com','dns.google')
DOMESTIC=['https://dns.alidns.com/dns-query','https://doh.pub/dns-query']
FOREIGN=['https://1.1.1.1/dns-query#PROXY','https://8.8.8.8/dns-query#PROXY']

def merge_preferences(current, patch):
    if not isinstance(patch,dict) or set(patch)-set(DEFAULTS):raise ValueError('unsupported preference field')
    merged={**copy.deepcopy(DEFAULTS),**copy.deepcopy(current),**copy.deepcopy(patch)}
    if merged['mode'] not in ['rule','direct','global']:raise ValueError('unsupported routing mode')
    for key in ['allow_other_regions','allow_proxy_direct_fallback','mainland_direct']:
        if not isinstance(merged[key],bool):raise ValueError('boolean preference required')
    if not isinstance(merged['preferred_label'],str) or not 1<=len(merged['preferred_label'])<=40:raise ValueError('short preference label required')
    keywords=merged['preferred_keywords']
    if not isinstance(keywords,list) or len(keywords)>8 or any(not isinstance(k,str) or not 1<=len(k)<=40 for k in keywords):raise ValueError('at most eight literal node-name keywords')
    excluded=merged['excluded_keywords']
    if excluded is not None and (not isinstance(excluded,list) or len(excluded)>100 or any(not isinstance(k,str) or not 1<=len(k)<=40 for k in excluded)):raise ValueError('bounded exclusion keywords required')
    for key in ['direct_domains','proxy_domains']:
        values=merged[key]
        if not isinstance(values,list) or len(values)>100:raise ValueError('bounded domain list required')
        if any(not isinstance(v,str) or len(v)>253 or not re.fullmatch(r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}',v) for v in values):raise ValueError('plain DNS domains required')
        merged[key]=sorted(set(value.lower() for value in values))
    if set(merged['direct_domains'])&set(merged['proxy_domains']):raise ValueError('a domain cannot have conflicting overrides')
    routes=merged['adaptive_routes']
    if not isinstance(routes,dict) or len(routes)>128:raise ValueError('bounded exact automatic route map required')
    normalized={}
    for name,path in routes.items():
        domain=hostname(name)
        if not domain or path not in ('direct','proxy') or any(domain==host or domain.endswith('.'+host) for host in AUTO_CONTROL_DOMAINS):
            raise ValueError('public non-control exact domain and direct/proxy path required')
        if domain in normalized and normalized[domain]!=path:raise ValueError('conflicting automatic route')
        normalized[domain]=path
    merged['adaptive_routes']=dict(sorted(normalized.items()))
    strategy=merged['routing_strategy']
    if not isinstance(strategy,dict) or set(strategy)!=set(DEFAULTS['routing_strategy']) or any(type(value) is not bool for value in strategy.values()):
        raise ValueError('complete boolean routing strategy required')
    return merged


def explicit_path(domain,preferences):
    for path,key in [('direct','direct_domains'),('proxy','proxy_domains')]:
        if any(domain==suffix or domain.endswith('.'+suffix) for suffix in preferences.get(key,[])):return path
    return None

def render(config, preferences, previous_preferences=None):
    p=merge_preferences({},preferences);candidate=copy.deepcopy(config)
    candidate['mode']=p['mode']
    patterns=[]
    for word in p['preferred_keywords']:
        escaped=re.escape(word)
        patterns.append(r'\b'+escaped+r'\b' if word.isascii() and word.isalnum() else escaped)
    preferred='(?i)('+'|'.join(patterns)+')' if patterns else ''
    providers=candidate['proxy-providers'];base_exclude=providers['us'].get('exclude-filter','')
    if p['excluded_keywords'] is not None:base_exclude='(?i)('+'|'.join(re.escape(k) for k in p['excluded_keywords'])+')' if p['excluded_keywords'] else ''
    providers['us']['exclude-filter']=base_exclude
    if preferred:providers['us']['filter']=preferred
    else:providers['us'].pop('filter',None)
    providers['other']['exclude-filter']='|'.join(filter(None,[base_exclude,preferred]))
    chain=['US_AUTO']
    if p['allow_other_regions'] and preferred:chain.append('OTHER_AUTO')
    if p['allow_proxy_direct_fallback']:chain.append('DIRECT')
    if p['mode']=='direct':chain=['DIRECT']
    for group in candidate['proxy-groups']:
        if group['name']=='PROXY':group['proxies']=chain
    rules=['IP-CIDR,192.168.0.0/16,DIRECT,no-resolve','IP-CIDR,10.0.0.0/8,DIRECT,no-resolve','IP-CIDR,172.16.0.0/12,DIRECT,no-resolve',
        'DOMAIN,ai.lan,DIRECT','DOMAIN,ai.local,DIRECT']
    rules += ['DOMAIN-SUFFIX,'+domain+',DIRECT' for domain in p['direct_domains']]
    rules += ['DOMAIN-SUFFIX,'+domain+',PROXY' for domain in p['proxy_domains']]
    automatic={domain:path for domain,path in p['adaptive_routes'].items() if p['mode']=='rule' and explicit_path(domain,p) is None}
    rules += ['DOMAIN,'+domain+','+path.upper() for domain,path in automatic.items()]
    if candidate.get('rule-providers',{}).get('proxy-domains'):rules.append('RULE-SET,proxy-domains,PROXY')
    mainland='DIRECT' if p['mainland_direct'] else 'PROXY'
    rules+=['GEOSITE,private,DIRECT','GEOSITE,cn,'+mainland,'GEOSITE,geolocation-!cn,PROXY','GEOIP,CN,'+mainland,'MATCH,PROXY']
    candidate['rules']=rules
    dns=candidate.setdefault('dns',{})
    dns['nameserver']=DOMESTIC if p['mode']=='direct' else FOREIGN
    ns=dns.setdefault('nameserver-policy',{})
    for domain in (previous_preferences or {}).get('direct_domains',[])+(previous_preferences or {}).get('proxy_domains',[]):ns.pop('+.'+domain,None)
    for domain in (previous_preferences or {}).get('adaptive_routes',{}):ns.pop(domain,None)
    ns.pop('geosite:cn,private',None)
    ns['geosite:private']=DOMESTIC
    ns['geosite:cn']=DOMESTIC if p['mode']=='direct' or (p['mode']=='rule' and p['mainland_direct']) else FOREIGN
    ns['geosite:geolocation-!cn']=DOMESTIC if p['mode']=='direct' else FOREIGN
    if 'rule-set:proxy-domains' in ns:ns['rule-set:proxy-domains']=DOMESTIC if p['mode']=='direct' else FOREIGN
    for domain in p['direct_domains']:ns['+.'+domain]=DOMESTIC
    for domain in p['proxy_domains']:ns['+.'+domain]=FOREIGN
    for domain,path in automatic.items():ns[domain]=DOMESTIC if path=='direct' else FOREIGN
    approved={'mode':p['mode'],'proxy_chain':chain,'region_providers':{'US_AUTO':'us','OTHER_AUTO':'other'},
        'default_rule':'MATCH,PROXY','scope':'user-approved household preferences','preferences':p,
        'preferred_label':p['preferred_label'],'pool_aliases':{'US_AUTO':'preferred pool (identifier is historical, not a country assertion)','OTHER_AUTO':'other pool'}}
    approved['version']=hashlib.sha256(json.dumps(p,sort_keys=True).encode()).hexdigest()[:16]
    return candidate,approved
