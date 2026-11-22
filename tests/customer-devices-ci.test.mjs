import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {handleDeviceRoute} from '../customer-device-routes.mjs';
import {createRealDeviceHandlers} from '../agent/real-device-handlers.mjs';
import {DeviceDispatch,signedRequest} from '../agent/dispatch.mjs';

const ROOT=path.dirname(fileURLToPath(import.meta.url));
const tenantId='c27b10c2-7238-4564-86d2-6c9a7aa85d73';
const owner='henry.shannon@shanxservices.com';
const db=new DatabaseSync(':memory:');
const sql=(await readFile(path.join(ROOT,'../schema.sql'),'utf8'))+'\n'+(await readFile(path.join(ROOT,'../customer-device-schema.sql'),'utf8'));
db.exec(sql);
db.prepare('INSERT INTO accounts(email,tenant_id,role,active,subscription_status) VALUES(?,?,?,?,?)').run(owner,tenantId,'customer',1,'trial');
db.prepare('INSERT INTO accounts(email,tenant_id,role,active,subscription_status) VALUES(?,?,?,?,?)').run('other-customer@example.net','other-tenant','customer',1,'active');
db.prepare('INSERT INTO accounts(email,tenant_id,role,active,subscription_status) VALUES(?,?,?,?,?)').run('suspended@example.net','tenant-suspended','customer',1,'suspended');
const adapter={
 prepare(sql){return {bind(...values){return {
   async first(){return db.prepare(sql).get(...values)||null},
   async all(){return {results:db.prepare(sql).all(...values)}},
   async run(){const q=db.prepare(sql).run(...values);return {meta:{changes:Number(q.changes)}}}
 }}}},
 async batch(statements){const results=[];db.exec('BEGIN');try{for(const stmt of statements)results.push(await stmt.run());db.exec('COMMIT')}catch(e){db.exec('ROLLBACK');throw e}return results}
};
const env={DB:adapter,ACCESS_TEAM_DOMAIN:'team.cloudflareaccess.com',ACCESS_AUD:'signed-test-aud',OWNER_EMAILS:owner};
const verify=async jwt=>{
 if(jwt==='first-user-signed')return {email:owner};
 if(jwt==='other-user-signed')return {email:'other-customer@example.net'};
 if(jwt==='suspended-signed')return {email:'suspended@example.net'};
 return null;
};
const API='https://test.shanx.local';
function request(path,{method='GET',body,who='first-user-signed',agentToken}={}){
 const headers={};
 if(who)headers['CF-Access-Jwt-Assertion']=who;
 if(agentToken)headers.authorization='Bearer '+agentToken;
 if(body!==undefined)headers['content-type']='application/json';
 return new Request(API+path,{method,headers,body:body!==undefined?JSON.stringify(body):undefined});
}
async function ask(path,options){
 const res=await handleDeviceRoute(request(path,options),env,verify);
 assert.ok(res,'Route was not handled');
 return {status:res.status,data:await res.json(),headers:res.headers};
}
const state={agent:null,token:null,dispatch:null,filepath:null,work:null};
test('Customer #1 identity and self-service trial entitlement verified from same schema',async()=>{
 const r=await ask('/api/customer/me');
 assert.equal(r.status,200);assert.equal(r.data.tenant_id,tenantId);assert.equal(r.data.subscription_status,'trial');
});
test('unsigned and suspended customers cannot access device routes',async()=>{
 assert.equal((await ask('/api/customer/me',{who:null})).status,401);
 assert.equal((await ask('/api/customer/me',{who:'suspended-signed'})).status,401);
});
test('Customer #1 enrolls own device with one-time secret stored as hash',async()=>{
 const r=await ask('/api/customer/devices/enroll',{method:'POST',body:{device_id:'commercial-pilot-01'}});
 assert.equal(r.status,201);
 assert.equal(r.data.mode,'STOP');assert.equal(r.data.tenant_id,tenantId);
 state.agent=r.data.agent_id;state.token=r.data.one_time_agent_token;
 assert.match(state.token,/^[a-f0-9]{96}$/);
 assert.equal(db.prepare('SELECT token_hash FROM agents WHERE agent_id=?').get(state.agent).token_hash,
   createHash('sha256').update(state.token).digest('hex'));
});
test('Customer #2 is isolated from first customer device records',async()=>{
 const r=await ask('/api/customer/devices',{who:'other-user-signed'});
 assert.deepEqual(r.data.devices,[]);
 assert.equal((await ask('/api/customer/jobs',{method:'POST',who:'other-user-signed',body:{device_id:'commercial-pilot-01',action:'system_info',arguments:{}}})).status,404);
});
test('Default STOP prevents remote job submission even with signed customer login',async()=>{
 const r=await ask('/api/customer/jobs',{method:'POST',body:{device_id:'commercial-pilot-01',action:'system_info',arguments:{}}});
 assert.equal(r.status,423);
});
test('Real device customer pilot can publish locally approved LIMITED mode',async()=>{
 const d=new DeviceDispatch({tenantId,deviceId:'commercial-pilot-01',secret:randomBytes(48).toString('hex'),
  approvedHandlers:((a)=>({read_file:a.read_file,list_dir:a.list_dir,write_file:a.write_file}))(
   createRealDeviceHandlers({workspaceRoot:path.resolve(ROOT,'fixtures/Customer Workspace')})),
  authorizeResume:async x=>x==='LIMITED'||x==='GO',
  authorizeWrite:async j=>j.tool==='write_file'&&/^documents\/cloud-chain-[a-f0-9-]+\.txt$/.test(j.arguments.path)
 });
 await d.changeLocalMode('LIMITED');state.dispatch=d;
 const r=await ask('/api/agent/control/state',{method:'POST',who:null,agentToken:state.token,body:{mode:'LIMITED',local_epoch:d.epoch}});
 assert.equal(r.status,200);assert.equal(r.data.mode,'LIMITED');
});
test('First customer submits a legitimate job and real device executes it with separate receipt',async()=>{
 const submit=await ask('/api/customer/jobs',{method:'POST',body:{device_id:'commercial-pilot-01',action:'list_dir',arguments:{path:'documents'}}});
 assert.equal(submit.status,202);const id=submit.data.request_id;
 const poll=await ask('/api/agent/control/poll',{method:'POST',who:null,agentToken:state.token,body:{}});
 assert.equal(poll.data.job.request_id,id);
 const start=await ask('/api/agent/control/start',{method:'POST',who:null,agentToken:state.token,body:{request_id:id}});
 assert.equal(start.status,200);
 const signed=signedRequest(state.dispatch,{requestId:id,tool:poll.data.job.action,arguments:poll.data.job.arguments});
 const receipt=await state.dispatch.handle(signed);
 assert.equal(receipt.payload.state,'EXECUTED');
 assert.ok(receipt.payload.result.handlerResult.entries.length>=1);
 const complete=await ask('/api/agent/control/receipt',{method:'POST',who:null,agentToken:state.token,
   body:{request_id:id,state:receipt.payload.state,result:{entries:receipt.payload.result.handlerResult.entries.length}}});
 assert.equal(complete.status,202);assert.equal(complete.data.independently_verified,false);
 const status=await ask('/api/customer/jobs/status?request_id='+encodeURIComponent(id));
 assert.equal(status.data.state,'EXECUTED');assert.equal(status.data.independently_verified,false);
});
test('LIMITED blocks remote write requests even if customer authenticated',async()=>{
 const r=await ask('/api/customer/jobs',{method:'POST',
 body:{device_id:'commercial-pilot-01',action:'write_file',arguments:{path:'documents/cloud-chain-denied.txt',content:'x'}}});
 assert.equal(r.status,423);
});
test('Cloud receives locally approved GO, then customer submits exact new-file write',async()=>{
 await state.dispatch.changeLocalMode('GO');
 const current=await ask('/api/agent/control/state',{method:'POST',who:null,agentToken:state.token,body:{mode:'GO',local_epoch:state.dispatch.epoch}});
 assert.equal(current.data.mode,'GO');
 const pathName='documents/cloud-chain-'+randomUUID()+'.txt',content='ShanX13 Commercial Customer #1 Cloud Queue Integration Test\n';
 state.filepath=pathName;
 const submit=await ask('/api/customer/jobs',{method:'POST',body:{device_id:'commercial-pilot-01',action:'write_file',arguments:{path:pathName,content}}});
 assert.equal(submit.status,202);
 const poll=await ask('/api/agent/control/poll',{method:'POST',who:null,agentToken:state.token,body:{}});
 assert.equal(poll.data.job.request_id,submit.data.request_id);
 assert.equal((await ask('/api/agent/control/start',{method:'POST',who:null,agentToken:state.token,body:{request_id:submit.data.request_id}})).status,200);
 const signed=signedRequest(state.dispatch,{tool:poll.data.job.action,requestId:submit.data.request_id,arguments:poll.data.job.arguments});
 const receipt=await state.dispatch.handle(signed);
 assert.equal(receipt.payload.state,'EXECUTED');
 const written=receipt.payload.result.handlerResult;
 assert.equal(written.verified,true);
 assert.equal(written.sha256,createHash('sha256').update(content).digest('hex'));
 const ret=await ask('/api/agent/control/receipt',{method:'POST',who:null,agentToken:state.token,
  body:{request_id:submit.data.request_id,state:'EXECUTED',result:{sha256:written.sha256,bytes:written.bytes,agentConfirmed:true}}});
 assert.equal(ret.status,202);
 const got=await readFile(path.resolve(ROOT,'fixtures/Customer Workspace',...pathName.split('/')),'utf8');
 assert.equal(got,content);
});
test('Cloud STOP latches, cancels new jobs and eventually reaches device',async()=>{
 const result=await ask('/api/customer/devices/stop',{method:'POST',body:{agent_id:state.agent}});
 assert.equal(result.status,200);assert.equal(result.data.locked,true);
 const poll=await ask('/api/agent/control/poll',{method:'POST',who:null,agentToken:state.token,body:{}});
 assert.equal(poll.data.mode,'STOP');state.dispatch.stop();
 const blocked=await ask('/api/customer/jobs',{method:'POST',body:{device_id:'commercial-pilot-01',action:'system_info',arguments:{}}});
 assert.equal(blocked.status,423);
});
test('Cannot spoof an agent with arbitrary token',async()=>{
 const r=await ask('/api/agent/control/poll',{method:'POST',who:null,agentToken:'a'.repeat(96),body:{}});
 assert.equal(r.status,401);
});
test('Customer #2 cannot retrieve Customer #1 job details or unlock device',async()=>{
 const job=db.prepare('SELECT request_id FROM customer_device_jobs WHERE tenant_id=? LIMIT 1').get(tenantId);
 const r=await ask('/api/customer/jobs/status?request_id='+job.request_id,{who:'other-user-signed'});
 assert.equal(r.status,404);
 const unlock=await ask('/api/customer/devices/unlock',{method:'POST',who:'other-user-signed',body:{agent_id:state.agent,confirm:'ENABLE_DEVICE_AFTER_LOCAL_APPROVAL'}});
 assert.equal(unlock.status,404);
});
