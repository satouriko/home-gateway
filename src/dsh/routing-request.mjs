const fields={
  status:['target'],get:['evidence_ids'],collect:['url'],
  requirement:['target','path','source_ids','quotes','rationale','region_context'],
  evaluate:['target','path','evidence_ids','business_requirement_evidence_ids'],apply:['proposal'],
};
const jsonFields=new Set(['source_ids','quotes','evidence_ids','business_requirement_evidence_ids','proposal']);

/** A shared form may retain values from another action; send only this action's inputs. */
export function routingPayload(args){
  const selected=fields[args.operation];
  if(!selected)throw Error('unknown routing operation');
  const payload={operation:'route_'+(args.operation==='collect'?'source':args.operation)};
  for(const key of selected)if(args[key]!==undefined)payload[key]=jsonFields.has(key)?JSON.parse(args[key]):args[key];
  return payload;
}
