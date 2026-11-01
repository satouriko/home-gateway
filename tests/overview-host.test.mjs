import test from 'node:test';
import assert from 'node:assert/strict';
let install;
try{({installOverview:install}=await import('../src/dsh/network-overview/index.mjs'));}catch{}
function harness({reject=false,fail=false}={}){
  assert.equal(typeof install,'function','native overview host must exist');
  let route;const calls=[];
  const ctx={webServer:{register(value){route=value;return()=>{};}},connection:{admit:()=>reject?{rejection:403}:{}},effect:fn=>fn()};
  install(ctx,async request=>{calls.push(request);if(fail)throw new Error('private password');return{ok:true,result:{node:{name:'US Example'}}};});
  return {calls,async request(method='GET',origin='http://ai.lan'){
    let status,body,headers;
    await route.handler({method,url:'/api/home-network/overview',headers:{host:'ai.lan',origin},socket:{}},
      {writeHead(code,value){status=code;headers=value;},end(value){body=JSON.parse(value);}});
    return{status,body,headers};
  }};
}
test('overview GET exposes the finite broker result and never accepts mutation operations',async()=>{
  const h=harness(),result=await h.request();assert.equal(result.status,200);assert.equal(result.body.node.name,'US Example');
  assert.deepEqual(h.calls,[{operation:'overview'}]);assert.equal(result.headers['Cache-Control'],'no-store');
  for(const method of ['POST','PUT','DELETE'])assert.equal((await h.request(method)).status,405);
  assert.equal(h.calls.length,1);
});
test('rejected and cross-origin requests never reach privileged collection',async()=>{
  const rejected=harness({reject:true});assert.equal((await rejected.request()).status,403);assert.equal(rejected.calls.length,0);
  const h=harness();assert.equal((await h.request('GET','http://outside.invalid')).status,403);assert.equal(h.calls.length,0);
});
test('internal collection errors return a generic failure without exception data',async()=>{
  const h=harness({fail:true}),result=await h.request();assert.equal(result.status,503);assert(!JSON.stringify(result.body).includes('private password'));
});
