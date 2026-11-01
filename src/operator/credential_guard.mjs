import { createRequire } from 'node:module';
import { readFile, chown, writeFile, rename } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
const require=createRequire('/opt/dsh/package.json');
const { withFileLock }=await import(require.resolve('@deepseek-ai/dsh-atomic-write'));
const { parse, stringify }=require('yaml');
const path='/var/lib/dsh-login/credentials.yaml';
await withFileLock(path,async()=>{
  let value;
  try{value=parse(await readFile(path,'utf8'));if(!value || value.version!==1 || !value.records || typeof value.records!=='object' || Array.isArray(value.records))throw Error('invalid store');}
  catch{value=parse(await readFile('/var/lib/net-gateway-agent/known-login.yaml','utf8'));}
  delete value.refs;
  const temporary=path+'.'+randomUUID()+'.tmp';
  await writeFile(temporary,stringify(value),{mode:0o600,flag:'wx'});
  await chown(temporary,Number(process.argv[2]),Number(process.argv[3]));
  await rename(temporary,path);
},{waitMs:3000});
