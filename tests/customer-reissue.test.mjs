import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {handleDeviceRoute} from '../customer-device-routes.mjs';

const here=path.dirname(fileURLToPath(import.meta.url));
const owner='henry.shannon@shanxservices.com';
const tenant='c27b10c2-7238-4564-86d2-6c9a7aa85d73';
const db=new DatabaseSync(':memory:');
db.exec((await readFile(path.resolve(here,'../schema.sql'),'utf8'))+'\n'+(await readFile(path.resolve(here,'../customer-device-schema.sql'),'utf8')));
db.prepare('INSERT INTO accounts(email,tenant_id,role,active,subscription_status) VALUES(?,?,?,?,?)').run(owner,tenant,'customer',1,'trial');
db.prepare('INSERT INTO accounts(email,tenant_id,role,active,subscription_status) VALUES(?,?,?,?,?)').run('other@example.net','another-tenant','customer',1,'active');
const adapter={
 prepare(q){return {bind(...values){return {
  async first(){return db.prepare(q).get(...values)||null},
  async all(){return {results:db.prepare(q).all(...values)}},
  async run(){const v=db.prepare(q).run(...values);return {meta:{changes:Number(v.changes)}}}
 }}}},
 async batch(stmts){const results=[];db.exec('BEGIN');try{for(const s of stmts)results.push(await s.run());db.exec('COMMIT')}catch(e){db.exec('ROLLBACK');throw e}return results}
};
const env={DB:adapter,ACCESS_TEAM_DOMAIN:'test.cloudflareaccess.com',ACCESS_AUD:'test-aud',OWNER_EMAILS:owner};
const verifier=async id=>id==='first'?{email:owner}:id==='second'?{email:'other@example.net'}:null;
async function request(route,{who='first',token,body,method='GET'}={}){
 const headers={};if(who)headers['CF-Access-Jwt-Assertion']=who;
 if(token)headers.authorization='Bearer '+token;
 if(body!==undefined)headers['content-type']='application/json';
 const result=await handleDeviceRoute(new Request('https://test.example.net'+route,{method,headers,body:body===undefined?undefined:JSON.stringify(body)}),env,verifier);
 return {status:result.status,json:await result.json()};
}
test('existing STOP and never-seen device can safely reissue its credential only to owner',async()=>{
 const created=await request('/api/customer/devices/enroll',{method:'POST',body:{device_id:'customer-one-monster-01'}});
 assert.equal(created.status,201);
 const original=created.json.one_time_agent_token,agent=created.json.agent_id;
 const before=db.prepare('SELECT COUNT(*) AS n FROM agents').get().n;
 assert.equal((await request('/api/customer/devices/reissue',{method:'POST',who:'second',body:{agent_id:agent,confirm:'REISSUE_STOPPED_UNSEEN_DEVICE'}})).status,404);
 assert.equal((await request('/api/customer/devices/reissue',{method:'POST',body:{agent_id:agent,confirm:'NO'}})).status,400);
 const reissued=await request('/api/customer/devices/reissue',{method:'POST',body:{agent_id:agent,confirm:'REISSUE_STOPPED_UNSEEN_DEVICE'}});
 assert.equal(reissued.status,200);
 assert.equal(reissued.json.agent_id,agent);assert.equal(reissued.json.device_id,'customer-one-monster-01');
 assert.match(reissued.json.one_time_agent_token,/^[a-f0-9]{96}$/);
 assert.notEqual(reissued.json.one_time_agent_token,original);
 const row=db.prepare('SELECT token_hash FROM agents WHERE agent_id=?').get(agent);
 assert.equal(row.token_hash,createHash('sha256').update(reissued.json.one_time_agent_token).digest('hex'));
 assert.equal((await request('/api/agent/control/bootstrap',{method:'POST',who:null,token:original,body:{}})).status,401);
 const boot=await request('/api/agent/control/bootstrap',{method:'POST',who:null,token:reissued.json.one_time_agent_token,body:{}});
 assert.equal(boot.status,200);assert.equal(boot.json.mode,'STOP');assert.equal(boot.json.device_id,'customer-one-monster-01');
 assert.equal(db.prepare('SELECT COUNT(*) AS n FROM agents').get().n,before);
 // STOP heartbeat proves that a device that has connected cannot use this recovery flow.
 const beat=await request('/api/agent/control/state',{method:'POST',who:null,token:reissued.json.one_time_agent_token,body:{mode:'STOP',local_epoch:1}});
 assert.equal(beat.status,200);
 assert.equal((await request('/api/customer/devices/reissue',{method:'POST',body:{agent_id:agent,confirm:'REISSUE_STOPPED_UNSEEN_DEVICE'}})).status,409);
 assert.ok(db.prepare('SELECT last_seen_at FROM customer_device_control WHERE agent_id=?').get(agent).last_seen_at);
});
test('queued/delivered/running outstanding work prohibits recovery rotation',async()=>{
 const c=await request('/api/customer/devices/enroll',{method:'POST',body:{device_id:'pending-monster-02'}});
 assert.equal(c.status,201);
 const agent=c.json.agent_id;
 const now=new Date().toISOString();
 db.prepare('INSERT INTO customer_device_jobs(request_id,agent_id,tenant_id,device_id,action,arguments_json,state,control_epoch,created_at,updated_at,expires_at_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run('pending-test-01',agent,tenant,'pending-monster-02','system_info','{}','QUEUED',1,now,now,Date.now()+60000);
 const r=await request('/api/customer/devices/reissue',{method:'POST',body:{agent_id:agent,confirm:'REISSUE_STOPPED_UNSEEN_DEVICE'}});
 assert.equal(r.status,409);
 assert.equal((await request('/api/agent/control/bootstrap',{method:'POST',who:null,token:c.json.one_time_agent_token,body:{}})).status,200);
});
