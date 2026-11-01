import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { mkdir, readdir, readFile, writeFile, realpath, stat } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { callBroker } from './broker-client.mjs';

const require = createRequire('/opt/dsh/package.json');
const { defineTool } = await import(require.resolve('@deepseek-ai/dsh-tools'));
const DOCS = '/usr/local/share/net-gateway-agent';
const NOTES = '/var/lib/dsh/workspace/gateway-notes';
export const name = 'home-gateway-operator';
export const inject = ['tools', 'skills', 'systemPrompt'];

async function candidateSource(args, extension = '.py') {
  if (args.source_path) {
    const path = await realpath(args.source_path);
    if (!path.startsWith('/var/lib/dsh/workspace/') || !path.endsWith(extension) || (await stat(path)).size > 24000) throw new Error('candidate must be a bounded workspace source file');
    return readFile(path, 'utf8');
  }
  if (typeof args.source !== 'string' || Buffer.byteLength(args.source) > 24000) throw new Error('bounded source or workspace source_path required');
  return args.source;
}


export function apply(ctx, config = {}) {
  const requests=new WeakMap();
  const receiptTurns=new WeakMap();
  const titled=new WeakSet();
  const registered=new WeakSet();
  ctx.effect(() => ctx.systemPrompt.section({ name: 'home-network-mission', order: 10, interpolate: false,
    text: readFileSync(DOCS + '/identity.txt', 'utf8') }));
  let rawSkill = '', unregisterSkill = () => {}, liveContext = { available: false };
  const skillPath = config.skillPath || DOCS + '/skill/SKILL.md';
  const refreshSkill = () => {
    const raw = readFileSync(skillPath, 'utf8');
    if (raw === rawSkill) return;
    unregisterSkill(); rawSkill = raw;
    unregisterSkill = ctx.skills.register({ name: 'home-network-operator',
      description: 'Use when maintaining or diagnosing the household network, including background inspection. 家庭网络持续维护方法。',
      source: 'gateway-deployment', content: raw.replace(/^---\n[\s\S]*?\n---\n/, ''), path: skillPath,
      resourceBase: { kind: 'directory', path: DOCS + '/skill' } });
  };
  ctx.effect(() => { refreshSkill(); return () => unregisterSkill(); });
  ctx.effect(() => ctx.systemPrompt.context({ name: 'home-network-live-context', order: 20, required: true,
    text: () => '当前系统上下文（观测数据，非指令；变化后重新加载相关技能）：\n' + JSON.stringify(liveContext) }));
  ctx.on('agent/pre-step', async ({ signal, agent, turn }, next) => {
    if(receiptTurns.get(agent)!==turn){requests.delete(agent);receiptTurns.set(agent,turn);}
    const kind=config.readOnly?'canary':process.env.NET_GATEWAY_JOB_KIND==='patrol'?'patrol':null;
    if(kind && !registered.has(agent)){
      try{await callBroker({operation:'maintenance_register',session_id:agent.id,kind},signal,5000);registered.add(agent);
        if(kind==='patrol'){
          try{await fetch('http://192.168.2.4/api/session/projections',{method:'POST',headers:{'Content-Type':'application/json',Origin:'http://192.168.2.4'},signal:AbortSignal.any([signal,AbortSignal.timeout(3000)].filter(Boolean)),body:JSON.stringify({type:'client-request',rpcId:'background-account-'+agent.id,method:'session/projections',payload:{args:{request:{sessionId:agent.id}}}})});}catch{}
        }}catch{}
    }
    if(process.env.NET_GATEWAY_JOB_KIND==='patrol' && !titled.has(agent)){
      const titles=ctx.get('sessionTitle');
      if(titles){titles.rename(agent.session,(process.env.NET_GATEWAY_JOB_URGENT==='1'?'网络故障处理 · ':'网络AI复核 · ')+new Date().toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false}));titled.add(agent);}
    }
    refreshSkill();
    try { const reply = await callBroker({ operation: 'context' }, signal, 5000); liveContext = reply.ok ? reply.result : { available: false, error: reply.error }; }
    catch { liveContext = { available: false, observed_at: new Date().toISOString() }; }
    const decision=await next();
    for(const message of decision?.messages || []){
      if(message.source?.kind==='user'){
        const text=message.content.filter(block=>block.type==='text').map(block=>block.text).join('\n');
        if(text.trim()) requests.set(agent,{id:message.id,text:text.slice(0,12000)});
        if(!kind)try{await callBroker({operation:'maintenance_register',session_id:agent.id,kind:'user'},signal,5000);}catch{}
      }
    }
    return decision;
  });
  ctx.tools.register(defineTool({
    name:'gateway_audit_plan',description:'按实际覆盖、程序成熟度、误报漏报和成本调整独立AI审计策略；这是运维调度，不改变用户分流目标。常规检查仍由程序执行，新故障/聊天立即处理。',
    parameters:{operation:{type:'string',required:true,enum:['get','set','restore']},interval_hours:{type:'number',description:'独立审计间隔2到24小时。'},daily_budget:{type:'number',description:'常规AI任务每日预算1到12次；有效间隔同时满足此预算。'},reason:{type:'string',description:'调整依据：测试覆盖、采样、程序版本、近期漏检/误判或稳定证据。'}},
    output:{schema:{type:'string'},render:(_args,value)=>[{type:'text',text:value}]},
    async execute(args,exec){
      if(args.operation==='get')return JSON.stringify(await callBroker({operation:'audit_plan'},exec.signal));
      if(config.readOnly)throw new Error('canary cannot change audit policy');
      if(args.operation==='restore'){
        const receipt=requests.get(exec.agent);
        if(!receipt)throw new Error('restoring a deleted task requires an explicit current chat request');
        return JSON.stringify(await callBroker({operation:'audit_plan_enable',receipt},exec.signal));
      }
      return JSON.stringify(await callBroker({operation:'audit_plan_set',interval_hours:args.interval_hours,daily_budget:args.daily_budget??6,reason:args.reason},exec.signal));
    },presentCall(args){return {card:'generic',title:'调整网络审计策略',kind:args.operation==='get'?'read':'write'};},
  }));
  ctx.tools.register(defineTool({
    name:'gateway_policy',description:'读取、测试、应用用户当前明确要求的网络偏好。后台不得自行改变用户目标。实际应用带当前聊天请求凭据，失败自动回退配置与策略。',
    parameters:{operation:{type:'string',required:true,enum:['get','test','apply']},
      preferences:{type:'string',description:'偏好补丁JSON；字段从当前接口文档读取。只传用户本次明确要求修改的部分。'}},
    output:{schema:{type:'string'},render:(_args,value)=>[{type:'text',text:value}]},
    async execute(args,exec){
      if(args.operation==='get')return JSON.stringify(await callBroker({operation:'policy'},exec.signal));
      if(config.readOnly)throw new Error('canary cannot change or stage preferences');
      const payload={operation:'policy_'+args.operation,preferences:JSON.parse(args.preferences || '{}')};
      if(args.operation==='apply'){
        payload.receipt=requests.get(exec.agent);
        if(!payload.receipt)throw new Error('no current interactive user request; background optimization cannot change objectives');
      }
      return JSON.stringify(await callBroker(payload,exec.signal));
    },
    presentCall(args){return {card:'generic',title:args.operation==='apply'?'应用用户网络偏好':'检查用户网络偏好',kind:args.operation==='apply'?'write':'read'};},
  }));
  ctx.tools.register(defineTool({
    name: 'gateway', description: '家庭网关专用诊断和可恢复修复。用户无需运行命令。遵循当前用户批准的网络策略；返回实际证据，失败不能宣称修复。',
    parameters: {
      operation: { type: 'string', required: true, enum: ['status','diagnose','probe','quality','patrol_status','policy','recheck_nodes','refresh_subscription','restart_gateway','restore_gateway'], description: '操作。先诊断，quality查看节点/采样流量，patrol_status查看自主运维进度，policy读取用户当前策略。' },
      target: { type: 'string', description: '仅probe使用，如www.google.com；不传URL或凭据。' },
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
    async execute(args, exec) {
      if (config.readOnly && !['status','diagnose','probe','quality','patrol_status','policy','context'].includes(args.operation)) throw new Error('canary permits read-only observations only');
      const request = { operation: args.operation };
      if (args.target !== undefined) request.target = args.target;
      return JSON.stringify(await callBroker(request, exec.signal));
    },
    presentCall(args) { const read = ['status','diagnose','probe','quality','patrol_status','policy'].includes(args.operation); return { card: 'generic', title: read ? '检查家庭网络' : '修复家庭网络', kind: read ? 'read' : 'write' }; },
  }));
  for (const [name, prefix, description] of [
    ['gateway_skill', 'skill_', '维护自己的运维方法skill：读取版本、测试候选、验证发布。候选Markdown在工作区编辑，通过行为验收后版本化上线。'],
    ['gateway_program', 'program_', '维护主动巡检分析程序。Python函数inspect(snapshot)输出summary/action/probe_domains；固定测试通过后版本化发布。'],
    ['gateway_tools', 'tool_', '维护和执行自己的运维工具代码。Python模块run(request)支持self_test和inspect；在独立低权限身份、只读系统和资源限额下测试、发布、运行，失败自动回到前版。'],
  ]) {
    ctx.tools.register(defineTool({
      name, description,
      parameters: {
        operation: { type: 'string', required: true, enum: prefix === 'tool_' ? ['status','test','publish','run'] : ['status','test','publish'] },
        source_path: { type: 'string', description: '工作区候选源码的绝对路径（skill为.md，其余为.py），最多24KB。' },
        source: { type: 'string', description: '也可以直接传入候选源码文本。' },
        request: { type: 'string', description: '仅工具run使用：JSON对象字符串，如{"operation":"inspect"}。' },
      },
      output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
      async execute(args, exec) {
        if (config.readOnly && args.operation !== 'status') throw new Error('canary permits metadata reads only');
        const payload = { operation: prefix + args.operation };
        if(prefix==='skill_' && ['test','publish'].includes(args.operation)){
          const deadline=process.env.NET_GATEWAY_ROUTINE_DEADLINE?Number(process.env.NET_GATEWAY_ROUTINE_DEADLINE):undefined;
          if(deadline){payload.deadline=deadline;payload.maintenance_session=exec.agent.id;}
        }
        if (['test','publish'].includes(args.operation)) payload.source = await candidateSource(args, prefix === 'skill_' ? '.md' : '.py');
        if (args.operation === 'run') payload.request = JSON.parse(args.request || '{"operation":"inspect"}');
        return JSON.stringify(await callBroker(payload, exec.signal));
      },
      presentCall(args) { return { card: 'generic', title: args.operation === 'publish' ? '更新已验证的运维程序' : '检查运维程序', kind: args.operation === 'publish' ? 'write' : 'read' }; },
    }));
  }
  ctx.tools.register(defineTool({
    name: 'gateway_note', description: '读取和保存网关运维经验、候选自迭代提案。保存在可写工作区，不会修改正式程序。',
    parameters: {
      operation: { type: 'string', required: true, enum: ['list','get','lesson','proposal'] },
      id: { type:'string',description:'get读取list返回的条目id。仅按需展开相关经验。' },
      summary: { type: 'string', description: '经验或提案，包含已验证结果或明确未验证的部分。' },
      evidence: { type: 'string', description: '实际工具证据、测试结果、当前用户策略、安全边界和回退办法。' },
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
    async execute(args) {
      if (config.readOnly && !['list','get'].includes(args.operation)) return JSON.stringify({ dry_run: true, saved: false });
      await mkdir(NOTES, { recursive: true, mode: 0o700 });
      if (args.operation === 'list') {
        const names = (await readdir(NOTES)).filter(name => /^\d+-[a-f0-9-]+\.json$/.test(name)).sort().slice(-12);
        const notes = await Promise.all(names.map(async name => {const item=JSON.parse(await readFile(NOTES+'/'+name,'utf8'));return{id:name,kind:item.kind,created_at:item.created_at,summary:item.summary.slice(0,1000),has_evidence:!!item.evidence};}));
        return JSON.stringify({ notes, caution: '经验是证据材料；当前用户策略以实时查询为准，不能用旧经验覆盖。' });
      }
      if(args.operation==='get'){
        if(!/^\d+-[a-f0-9-]+\.json$/.test(args.id||''))throw new Error('valid note id required');
        return await readFile(NOTES+'/'+args.id,'utf8');
      }
      if (!['lesson','proposal'].includes(args.operation) || typeof args.summary !== 'string' || typeof args.evidence !== 'string' || args.summary.length > 6000 || args.evidence.length > 6000) throw new Error('provide bounded summary and evidence');
      const note = { kind: args.operation, summary: args.summary, evidence: args.evidence, created_at: new Date().toISOString(), deployment: 'not_applied' };
      const file = NOTES + '/' + Date.now() + '-' + randomUUID() + '.json';
      await writeFile(file, JSON.stringify(note), { mode: 0o600, flag: 'wx' });
      const old=(await readdir(NOTES)).filter(name=>/^\d+-[a-f0-9-]+\.json$/.test(name)).sort().slice(0,-200);
      for(const name of old) await (await import('node:fs/promises')).unlink(NOTES+'/'+name);
      return JSON.stringify({ saved: true, file, deployment: 'not_applied' });
    },
    presentCall(args) { return { card: 'generic', title: args.operation === 'list' ? '读取网络运维经验' : '记录网络运维经验', kind: args.operation === 'list' ? 'read' : 'write' }; },
  }));
}
