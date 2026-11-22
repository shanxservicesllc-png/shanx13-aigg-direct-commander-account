// ShanX13 AiGG Direct Commander — generic physically executable commercial customer agent v0.2.
// Uses HTTPS polling; no open inbound ports, arbitrary shell, global file access or background startup.
// Every action runs only inside the locally chosen workspace after independent device-side approval.
// Agent credentials remain in memory. Never log bearer tokens or save them in configuration files.
import fs from 'node:fs/promises';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {DeviceDispatch,signedRequest} from './dispatch.mjs';
import {createRealDeviceHandlers} from './real-device-handlers.mjs';

const fail=code=>Object.assign(new Error(code),{code});
const modes=new Set(['STOP','LIMITED','GO']);
const eventStates=new Set(['EXECUTED','FAILED','REJECTED','UNKNOWN']);
function validateUrl(url,allowLocalHttpTest){
 const u=new URL(url);
 if(u.username||u.password||u.search||u.hash||u.pathname!=='/'&&u.pathname!=='')throw fail('INVALID_SERVICE_URL');
 if(u.protocol==='https:')return u.origin;
 if(allowLocalHttpTest&&u.protocol==='http:'&&['127.0.0.1','localhost'].includes(u.hostname))return u.origin;
 throw fail('SECURE_HTTPS_REQUIRED');
}
function sanitize(result,kind){
 if(result?.reason)return {reason:String(result.reason).slice(0,120)};
 const d=result?.handlerResult;
 if(!d||typeof d!=='object')return {reason:'No device handler result'};
 if(kind==='system_info')return {hostname:d.hostname,platform:d.platform,arch:d.arch,release:d.release,observedAt:d.observedAt};
 if(kind==='list_dir')return {path:d.path,entries:(d.entries||[]).slice(0,100).map(e=>({name:e.name,type:e.type}))};
 if(kind==='read_file')return {path:d.path,sha256:d.sha256,bytes:d.bytes,contentPreview:d.content?.slice(0,300)};
 if(kind==='write_file')return {path:d.path,sha256:d.sha256,bytes:d.bytes,verifiedOnDevice:d.verified===true};
 return {reason:'Unsupported result'};
}
export class CommercialDeviceAgent{
 constructor({tenantId,deviceId,agentToken,serviceUrl,workspaceRoot,journalPath,
   approvedResume=async()=>false,approvedWrite=async()=>false,fetcher=fetch,allowLocalHttpTest=false}={}){
  if(typeof tenantId!=='string'||!tenantId||typeof deviceId!=='string'||!deviceId)throw fail('DEVICE_IDENTITY_REQUIRED');
  if(typeof agentToken!=='string'||!/^[a-f0-9]{96}$/.test(agentToken))throw fail('ONE_TIME_AGENT_TOKEN_REQUIRED');
  if(typeof workspaceRoot!=='string'||!path.isAbsolute(workspaceRoot)||typeof journalPath!=='string'||!path.isAbsolute(journalPath))throw fail('LOCAL_DIRECTORY_REQUIRED');
  if(typeof approvedResume!=='function'||typeof approvedWrite!=='function')throw fail('LOCAL_POLICY_REQUIRED');
  this.service=validateUrl(serviceUrl,allowLocalHttpTest);
  this.token=agentToken;this.tenantId=tenantId;this.deviceId=deviceId;
  this.journalPath=journalPath;this.fetcher=fetcher;this.seen=new Set();
  this.dispatch=new DeviceDispatch({tenantId,deviceId,secret:randomBytes(48).toString('hex'),
    approvedHandlers:createRealDeviceHandlers({workspaceRoot}),authorizeResume:approvedResume,authorizeWrite:approvedWrite});
 }
 async initialize(){
  try{
   const logs=await fs.readFile(this.journalPath,'utf8');
   for(const line of logs.split(/\r?\n/)){
    if(!line)continue;
    const event=JSON.parse(line);
    if(typeof event.requestId==='string')this.seen.add(event.requestId);
   }
  }catch(e){if(e.code!=='ENOENT')throw e}
 }
 async record(requestId,state){
  const file=await fs.open(this.journalPath,'a',0o600);
  try{await file.writeFile(JSON.stringify({requestId,state,at:new Date().toISOString()})+'\n');await file.sync()}
  finally{await file.close()}
  this.seen.add(requestId);
 }
 async request(api,body){
  const res=await this.fetcher(this.service+api,{
    method:'POST',redirect:'error',signal:AbortSignal.timeout(10000),
    headers:{'content-type':'application/json','authorization':'Bearer '+this.token},
    body:JSON.stringify(body)});
  const data=await res.json().catch(()=>null);
  if(!res.ok)throw fail('SERVICE_'+res.status);
  if(!data||typeof data!=='object')throw fail('INVALID_CLOUD_RESPONSE');
  return data;
 }
 async localMode(mode){
  if(!modes.has(mode))throw fail('INVALID_MODE');
  return this.dispatch.changeLocalMode(mode);
 }
 async cycle(){
  const mode=this.dispatch.mode;
  const state=await this.request('/api/agent/control/state',{mode,local_epoch:this.dispatch.epoch});
  if(state.mode==='STOP'||state.locked){
   if(this.dispatch.mode!=='STOP')this.dispatch.stop();
   return {status:'STOP',cloudStopObserved:true,mode:this.dispatch.mode};
  }
  if(state.mode!==this.dispatch.mode)throw fail('MODE_MISMATCH');
  const next=await this.request('/api/agent/control/poll',{});
  if(next.mode==='STOP'){
   if(this.dispatch.mode!=='STOP')this.dispatch.stop();
   return {status:'STOP',cloudStopObserved:true};
  }
  if(!next.job)return {status:'IDLE',mode:this.dispatch.mode};
  const job=next.job;
  if(typeof job.request_id!=='string'||job.device_id!==this.deviceId||
     !['system_info','list_dir','read_file','write_file'].includes(job.action)||
     !Number.isSafeInteger(job.expires_at_ms)||job.expires_at_ms<=Date.now())throw fail('INVALID_REMOTE_JOB');
  if(this.seen.has(job.request_id))return {status:'REPLAY_SUPPRESSED',requestId:job.request_id};
  const start=await this.request('/api/agent/control/start',{request_id:job.request_id});
  if(start.started!==true)throw fail('CLOUD_START_NOT_ACCEPTED');
  // Fsync prior to local execution: a lost response cannot replay an earlier side effect.
  await this.record(job.request_id,'STARTED');
  const signed=signedRequest(this.dispatch,{requestId:job.request_id,tool:job.action,arguments:job.arguments});
  const receipt=await this.dispatch.handle(signed);
  const result=sanitize(receipt.payload.result,job.action);
  const stateName=eventStates.has(receipt.payload.state)?receipt.payload.state:'UNKNOWN';
  await this.record(job.request_id,stateName);
  await this.request('/api/agent/control/receipt',{request_id:job.request_id,state:stateName,result});
  return {status:stateName,requestId:job.request_id,action:job.action,
    deviceProof:result.sha256??null,remoteReported:true,independentlyVerified:false};
 }
 async run({maxCycles=1}={}){
  if(!Number.isInteger(maxCycles)||maxCycles<1||maxCycles>100)throw fail('INVALID_CYCLE_COUNT');
  const output=[];
  for(let i=0;i<maxCycles;i++)output.push(await this.cycle());
  return output;
 }
}
