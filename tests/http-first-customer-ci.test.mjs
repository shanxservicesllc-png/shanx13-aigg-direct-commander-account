import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {createServer} from 'node:http';
import {randomUUID,createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {handleDeviceRoute} from '../customer-device-routes.mjs';
import {CommercialDeviceAgent} from '../agent/cloud-agent.mjs';

const HERE=path.dirname(fileURLToPath(import.meta.url));
const ROOT=path.resolve(HERE,'../');
const WORK=path.resolve(HERE,'fixtures/Customer Workspace');
const tenant='c27b10c2-7238-4564-86d2-6c9a7aa85d73';
const originalEmail='henry.shannon@shanxservices.com';

function makeD1(){
 const db=new DatabaseSync(':memory:');
 return (async()=>{
  db.exec((await readFile(path.join(ROOT,'schema.sql'),'utf8'))+'\n'+(await readFile(path.join(ROOT,'customer-device-schema.sql'),'utf8')));
  db.prepare('INSERT INTO accounts(email,tenant_id,role,active,subscription_status) VALUES(?,?,?,?,?)').run(originalEmail,tenant,'customer',1,'trial');
  db.prepare('INSERT INTO accounts(email,tenant_id,role,active,subscription_status) VALUES(?,?,?,?,?)').run('neighbor@example.net','neighbor-tenant','customer',1,'active');
  const d1={prepare(sql){return {bind(...args){return{
    first:async()=>db.prepare(sql).get(...args)||null,
    all:async()=>({results:db.prepare(sql).all(...args)}),
    run:async()=>({meta:{changes:Number(db.prepare(sql).run(...args).changes)}})
  }}}},batch:async stmts=>{db.exec('BEGIN');try{const out=[];for(const s of stmts)out.push(await s.run());db.exec('COMMIT');return out}catch(e){db.exec('ROLLBACK');throw e}}};
  return {db,d1};
 })();
}
const verify=async jwt=>jwt==='customer-one-jwt-fixture'?{email:originalEmail}:jwt==='neighbor-jwt-fixture'?{email:'neighbor@example.net'}:null;
test('Actual HTTP customer request -> queue -> token-authenticated poll -> physical device action -> cloud receipt -> STOP',async()=>{
 const {db,d1}=await makeD1();
 const env={DB:d1,ACCESS_TEAM_DOMAIN:'team.cloudflareaccess.com',ACCESS_AUD:'aud-test',OWNER_EMAILS:originalEmail};
 const server=createServer(async(incoming,out)=>{
  try{
   const chunks=[];for await(const chunk of incoming)chunks.push(chunk);
   const request=new Request('http://127.0.0.1'+incoming.url,
    {method:incoming.method,headers:incoming.headers,body:chunks.length?Buffer.concat(chunks):undefined});
   const response=await handleDeviceRoute(request,env,verify);
   out.writeHead(response?.status??404,Object.fromEntries(response?.headers??[]));
   out.end(response?Buffer.from(await response.arrayBuffer()):'NOT_FOUND');
  }catch{out.writeHead(500);out.end('ERROR')}
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const base='http://127.0.0.1:'+server.address().port;
 const customer=async(path,payload,jwt='customer-one-jwt-fixture')=>{
  const res=await fetch(base+path,{method:payload?'POST':'GET',headers:{'CF-Access-Jwt-Assertion':jwt,...(payload?{'content-type':'application/json'}:{})},body:payload?JSON.stringify(payload):undefined});
  const data=await res.json().catch(()=>null);return {status:res.status,data};
 };
 try{
  const enrolled=await customer('/api/customer/devices/enroll',{device_id:'commercial-pilot-02'});
  assert.equal(enrolled.status,201);
  const token=enrolled.data.one_time_agent_token;assert.equal(token.length,96);
  const deviceId=enrolled.data.device_id;
  const agent=new CommercialDeviceAgent({
   serviceUrl:base+'/',allowLocalHttpTest:true,tenantId:tenant,deviceId,
   agentToken:token,workspaceRoot:WORK,journalPath:path.resolve(HERE,'Network Agent Journal '+randomUUID()+'.ndjson'),
   approvedResume:async mode=>mode==='LIMITED'||mode==='GO',
   approvedWrite:async job=>job.tool==='write_file'&&/^documents\/network-proof-[a-f0-9-]+\.txt$/.test(job.arguments.path)
  });
  await agent.initialize();await agent.localMode('LIMITED');
  let idle=await agent.cycle();assert.equal(idle.status,'IDLE');
  const queued=await customer('/api/customer/jobs',{device_id:deviceId,action:'list_dir',arguments:{path:'documents'}});
  assert.equal(queued.status,202);
  const executed=await agent.cycle();
  assert.equal(executed.status,'EXECUTED');
  assert.equal(executed.requestId,queued.data.request_id);
  let status=await customer('/api/customer/jobs/status?request_id='+queued.data.request_id);
  assert.equal(status.data.state,'EXECUTED');assert.equal(status.data.independently_verified,false);
  const neighbor=await customer('/api/customer/jobs/status?request_id='+queued.data.request_id,null,'neighbor-jwt-fixture');
  assert.equal(neighbor.status,404);
  const notReady=await customer('/api/customer/jobs',{device_id:deviceId,action:'write_file',arguments:{path:'documents/unapproved.txt',content:'cannot'}});
  assert.equal(notReady.status,423);
  await agent.localMode('GO');await agent.cycle();
  const file='documents/network-proof-'+randomUUID()+'.txt';
  const content='ShanX13 AiGG first-customer network control proof via HTTP relay and local device adapter.\n';
  const submitted=await customer('/api/customer/jobs',{device_id:deviceId,action:'write_file',arguments:{path:file,content}});
  assert.equal(submitted.status,202);
  const result=await agent.cycle();assert.equal(result.status,'EXECUTED');
  const disk=await readFile(path.resolve(WORK,...file.split('/')),'utf8');
  assert.equal(disk,content);
  const hash=createHash('sha256').update(content).digest('hex');
  assert.equal(result.deviceProof,hash);
  status=await customer('/api/customer/jobs/status?request_id='+submitted.data.request_id);
  assert.equal(status.data.result.sha256,hash);
  assert.equal(status.data.independently_verified,false);
  const stop=await customer('/api/customer/devices/stop',{agent_id:enrolled.data.agent_id});
  assert.equal(stop.status,200);
  const stopped=await agent.cycle();assert.equal(stopped.status,'STOP');assert.equal(agent.dispatch.mode,'STOP');
  const denied=await customer('/api/customer/jobs',{device_id:deviceId,action:'system_info',arguments:{}});
  assert.equal(denied.status,423);
  const page=await fetch(base+'/customer',{headers:{'CF-Access-Jwt-Assertion':'customer-one-jwt-fixture'}});
  assert.equal(page.status,200);assert.match(await page.text(),/Control your authorized devices/);
  console.log('PHYSICAL_HTTP_PILOT_VERIFIED '+JSON.stringify({tenantId:tenant,deviceId,customerNumber:1,networkTransport:'HTTP loopback',realDiskWrite:true,sha256:hash,deviceAgentPostTest:'STOP',cloudDeployed:false}));
 }finally{await new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()));db.close()}
});
