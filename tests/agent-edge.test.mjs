import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import agentWorker from '../agent-worker.mjs';
import {handleDeviceRoute} from '../customer-device-routes.mjs';

const here=path.dirname(fileURLToPath(import.meta.url));
const d=new DatabaseSync(':memory:');
d.exec((await readFile(path.join(here,'../schema.sql'),'utf8'))+'\n'+(await readFile(path.join(here,'../customer-device-schema.sql'),'utf8')));
d.prepare('INSERT INTO accounts(email,tenant_id,role,active,subscription_status) VALUES(?,?,?,?,?)')
 .run('customer-one@example.net','tenant-1','customer',1,'trial');
d.prepare('INSERT INTO accounts(email,tenant_id,role,active,subscription_status) VALUES(?,?,?,?,?)')
 .run('customer-two@example.net','tenant-2','customer',1,'active');
const DB={
 prepare(q){return {bind(...x){return{
  async first(){return d.prepare(q).get(...x)||null},
  async all(){return {results:d.prepare(q).all(...x)}},
  async run(){const r=d.prepare(q).run(...x);return {meta:{changes:Number(r.changes)}}}
 }}}},
 async batch(queries){const out=[];d.exec('BEGIN');try{for(const x of queries)out.push(await x.run());d.exec('COMMIT')}catch(e){d.exec('ROLLBACK');throw e}return out}
};
const full={DB,ACCESS_TEAM_DOMAIN:'access.example.com',ACCESS_AUD:'test',OWNER_EMAILS:'owner@example.net'};
const verify=async x=>x==='a'?{email:'customer-one@example.net'}:x==='b'?{email:'customer-two@example.net'}:null;
const base='https://agent.example.net';
const req=(url,{method='GET',body,token,origin}={})=>{
 const headers={}; if(body!==undefined)headers['content-type']='application/json';
 if(token)headers.authorization='Bearer '+token;
 if(origin)headers.origin=origin;
 return new Request(base+url,{method,headers,body:body===undefined?undefined:JSON.stringify(body)});
};
async function call(url,options){
 const response=await agentWorker.fetch(req(url,options),{DB});
 return {status:response.status,data:await response.json()};
}
test('agent edge is agent-only and denies browser/unauthed traffic',async()=>{
 assert.equal((await call('/health')).status,200);
 assert.equal((await call('/customer')).status,404);
 assert.equal((await call('/api/customer/me')).status,404);
 assert.equal((await call('/api/agent/control/bootstrap')).status,405);
 assert.equal((await call('/api/agent/control/bootstrap',{method:'POST',body:{}})).status,401);
 assert.equal((await call('/api/agent/control/bootstrap',{method:'POST',body:{},origin:'https://untrusted.example.net'})).status,403);
});
test('real shared D1 records authorize only the enrolled device bearer in STOP',async()=>{
 const enroll=await handleDeviceRoute(new Request(base+'/api/customer/devices/enroll',{
  method:'POST',headers:{'content-type':'application/json','CF-Access-Jwt-Assertion':'a'},
  body:JSON.stringify({device_id:'customer-one-monster-01'})
 }),full,verify);
 assert.equal(enroll.status,201);const e=await enroll.json();
 const good=await call('/api/agent/control/bootstrap',{method:'POST',body:{},token:e.one_time_agent_token});
 assert.equal(good.status,200);assert.equal(good.data.agent_id,e.agent_id);
 assert.equal(good.data.tenant_id,'tenant-1');assert.equal(good.data.mode,'STOP');
 assert.equal((await call('/api/agent/control/bootstrap',{method:'POST',body:{},token:'a'.repeat(96)})).status,401);
 const heartbeat=await call('/api/agent/control/state',{method:'POST',token:e.one_time_agent_token,body:{mode:'STOP',local_epoch:1}});
 assert.equal(heartbeat.status,200);assert.equal(heartbeat.data.mode,'STOP');
 assert.ok(d.prepare('SELECT last_seen_at FROM customer_device_control WHERE agent_id=?').get(e.agent_id).last_seen_at);
 const poll=await call('/api/agent/control/poll',{method:'POST',token:e.one_time_agent_token,body:{}});
 assert.equal(poll.status,200);assert.equal(poll.data.mode,'STOP');assert.equal(poll.data.job,null);
 assert.equal(d.prepare('SELECT COUNT(*) AS n FROM customer_device_jobs').get().n,0);
});
