import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rename, rm, symlink, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

const modules=process.env.SDK_RUNTIME||resolve('runtime/dsh/node_modules');
const sdkRequire=createRequire(resolve(modules,'@deepseek-ai/dsh-session-projection-cache/package.json'));
const sdk=specifier=>import(pathToFileURL(sdkRequire.resolve(specifier)).href);
const { Context,Service }=await sdk('@deepseek-ai/cordis');
const { Storage }=await sdk('@deepseek-ai/dsh-storage');
const { DomainFacility }=await sdk('@deepseek-ai/dsh-storage-domain');
const { JsonStorageBackend }=await sdk('@deepseek-ai/dsh-storage-json');
const { SessionProjectionRegistry }=await sdk('@deepseek-ai/dsh-session-projection');
const { SessionProjectionCache }=await sdk('@deepseek-ai/dsh-session-projection-cache');
const { z }=await sdk('zod');
const { ApiSessionList }=await import(pathToFileURL(resolve(modules,'@deepseek-ai/dsh-api-session-controller/lib/types/list.js')).href);

const header={id:'session-11111111-1111-4111-8111-111111111111',version:4,createdAt:1000,cwd:'/workspace',isSeeded:false};
const record=(title,seq=10)=>({version:7,record:{identity:{formatVersion:4,createdAt:1000,cwd:'/workspace',isSeeded:false,inheritedEventCount:0},rows:{title:{ver:1,seq,val:title}}}});

async function fixture(t,initial=record('Old title')) {
 const root=await mkdtemp(join(tmpdir(),'dsh-title-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const folder=join(root,'session_projcache','sessions');await mkdir(folder,{recursive:true});
 const file=join(folder,header.id+'.json');
 if(initial)await writeFile(file,JSON.stringify(initial));
 const ctx=new Context(),live=new Map();new Storage(ctx);
 const backend=new JsonStorageBackend(root);ctx.storage.backend.register('json',backend);
 const domain=new DomainFacility(ctx,{backend:'json'});ctx.provide('storageDomain',domain);
 ctx.provide('sessions',{get:id=>live.get(id),list:()=>[...live.values()],flush:async()=>assert.fail('list must not flush any session')});
 ctx.provide('agents',{get:()=>undefined});
 ctx.provide('sessionQuery',{listSessions:async()=>[{header,formatStatus:'current'}],observeSession:()=>assert.fail('list must not open or resume session logs')});
 ctx.provide('logger',{warn:()=>{},error:message=>assert.fail(message)});
 const projections=new SessionProjectionRegistry(ctx);
 projections.register({key:'title',stateVersion:1,stateSchema:z.string().min(1).nullable(),init:()=>null,
   apply:(value,event)=>event.type==='session/title'?event.data.title:value,
   wire:{viewSchema:z.string().min(1).nullable(),view:value=>value}});
 const cache=new SessionProjectionCache(ctx,{writeEveryEvents:100,writeIntervalMs:100000});await cache[Service.init]();
 const list=new ApiSessionList(ctx,3);
 t.after(async()=>{await domain.closeAll();await backend.close();await ctx.fiber.dispose()});
 const external=async value=>{const next=file+'.next';await writeFile(next,typeof value==='string'?value:JSON.stringify(value));await rename(next,file)};
 return {root,file,ctx,live,cache,projections,list,external};
}

// The real Web-owned domain already loaded its Map before a separate writer publishes a title.
test('cold list reads an external durable title without opening a session or rewriting the Web cache',async t=>{
 const f=await fixture(t,null);await f.external(record('External title',20));
 const before=await readFile(f.file),identity=await stat(f.file);
 const rows=await f.list.list();
 assert.equal(rows[0].projections?.kind,'cached');assert.equal(rows[0].projections?.values.title,'External title');
 assert.equal(f.cache.cachedSnapshot(header),undefined);
 assert.deepEqual(await readFile(f.file),before);assert.equal((await stat(f.file)).mtimeMs,identity.mtimeMs);
 assert.equal(f.live.size,0);
});

test('newer external titles become visible on later list calls while memory keeps its original checkpoint',async t=>{
 const f=await fixture(t);assert.equal((await f.list.list())[0].projections.values.title,'Old title');
 await f.external(record('External title',20));
 assert.equal((await f.list.list())[0].projections.values.title,'External title');
 assert.equal(f.cache.cachedSnapshot(header).values.title,'Old title');
 await f.external(record('Another title',30));
 assert.equal((await f.list.list())[0].projections.values.title,'Another title');
});

test('an older external checkpoint cannot replace a newer Web-owned checkpoint',async t=>{
 const f=await fixture(t,record('Web title',50));await f.external(record('Stale external title',10));
 assert.equal((await f.list.list())[0].projections.values.title,'Web title');
});

test('live Web projections retain authority over a newer on-disk cold hint',async t=>{
 const f=await fixture(t);await f.external(record('External title',100));
 const session={id:header.id,header,seq:1,inheritedEventCount:0,snapshotEvents:()=>[]};
 f.projections.hydrate(session,{},[{seq:0,type:'session/title',data:{title:'Active Web title'}}],0);f.live.set(header.id,session);
 assert.equal((await f.list.list())[0].projections.values.title,'Active Web title');
});

test('a session attached while the title file is read wins over the returned cold hint',async t=>{
 const f=await fixture(t);await f.external(record('External title',100));
 const session={id:header.id,header,seq:1,inheritedEventCount:0,snapshotEvents:()=>[]};
 f.projections.hydrate(session,{},[{seq:0,type:'session/title',data:{title:'Newly attached title'}}],0);
 const fresh=f.cache.freshTitleHint.bind(f.cache);
 f.cache.freshTitleHint=async(...args)=>{const result=await fresh(...args);f.live.set(header.id,session);return result};
 assert.equal((await f.list.list())[0].projections.values.title,'Newly attached title');
});

test('equal sequence external rows cannot replace a different Web checkpoint',async t=>{
 const f=await fixture(t,record('Web title',50));await f.external(record('External title at same cut',50));
 assert.equal((await f.list.list())[0].projections.values.title,'Web title');
});

test('invalid lifecycle, schema, projection version and oversized records keep safe existing hints',async t=>{
 const f=await fixture(t);
 const invalid=[{...record('Wrong envelope',50),version:99},record('Wrong lifecycle',50),record('Wrong projection',50),'{broken', {...record('Oversized title',70),padding:'x'.repeat(262145)},record({bad:'title schema'},100)];
 invalid[1].record.identity.createdAt=2000;invalid[2].record.rows.title.ver=999;
 for(const value of invalid){await f.external(value);assert.equal((await f.list.list())[0].projections.values.title,'Old title')}
 const unrelated=record('Title only',50);unrelated.record.rows.permissions={ver:1,seq:50,val:'untrusted other projection'};
 await f.external(unrelated);const values=(await f.list.list())[0].projections.values;
 assert.equal(values.title,'Title only');assert.equal(values.permissions,undefined);
});

test('symlinks are not followed and cancellation remains visible',async t=>{
 const f=await fixture(t),outside=join(f.root,'outside.json');await writeFile(outside,JSON.stringify(record('Outside title',50)));
 await rm(f.file);await symlink(outside,f.file);
 assert.equal((await f.list.list())[0].projections.values.title,'Old title');
 const controller=new AbortController();controller.abort(new Error('cancelled audit'));
 await assert.rejects(f.list.list(controller.signal),/cancelled audit/);
});
