import test from 'node:test';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
const root=process.env.SDK_RUNTIME||resolve('runtime/dsh/node_modules');
if(existsSync(resolve(root,'@deepseek-ai/dsh-session-projection-cache/lib/index.js'))){
 await import('./dsh-title/history.test.mjs');
}else{
 test('DSH title read-through requires the pinned SDK runtime',{skip:'install runtime/dsh dependencies to execute real SDK integration tests'},()=>{});
}
