// ShanX13 AiGG Direct Commander — isolated per-customer device dispatch prototype.
// This file never starts a process, reads an actual user file or makes a network call.
// Local approved handlers are injected explicitly by the packaged device agent.
// Not production: persistent nonce storage, TLS/pairing, OS isolation and packaging remain required.
import {createHmac, timingSafeEqual, randomUUID} from 'node:crypto';

const SAFE_ID=/^[a-zA-Z0-9_-]{3,100}$/;
const HEX=/^[a-f0-9]{64}$/;
const MODES=new Set(['STOP','LIMITED','GO']);
export const ACTIONS=Object.freeze({
 system_info:{readOnly:true},
 read_file:{readOnly:true},
 list_dir:{readOnly:true},
 file_stat:{readOnly:true},
 write_file:{readOnly:false},
 run_command:{readOnly:false}
});
const canonical = object=>JSON.stringify(object);
export const sign = (body,secret)=>createHmac('sha256',secret).update(canonical(body)).digest('hex');
const macMatches=(body,signature,secret)=>{
 if(typeof signature!=='string'||!HEX.test(signature))return false;
 return timingSafeEqual(Buffer.from(signature,'hex'),Buffer.from(sign(body,secret),'hex'));
};
const sane=(s)=>typeof s==='string'&&SAFE_ID.test(s);
const fail=(code)=>Object.assign(new Error(code),{code});

export class DeviceDispatch {
 constructor({deviceId,tenantId,secret,approvedHandlers={},authorizeWrite=async()=>false,authorizeResume=async()=>false,clock=()=>Date.now(),maxAgeMs=60000,ttlMs=60000}={}){
  if(!sane(deviceId)||!sane(tenantId))throw fail('INVALID_DEVICE_IDENTITY');
  if(typeof secret!=='string'||secret.length<32)throw fail('WEAK_DEVICE_SECRET');
  if(!Number.isInteger(maxAgeMs)||maxAgeMs<1000||maxAgeMs>3600000||!Number.isInteger(ttlMs)||ttlMs<1000||ttlMs>3600000)throw fail('INVALID_TTL');
  for(const [name,handler] of Object.entries(approvedHandlers))if(!(name in ACTIONS)||typeof handler!=='function')throw fail('UNKNOWN_HANDLER');
  if(typeof authorizeWrite!=='function'||typeof authorizeResume!=='function')throw fail('INVALID_OWNER_POLICY');
  this.deviceId=deviceId;this.tenantId=tenantId;this.secret=secret;this.handlers=Object.freeze({...approvedHandlers});
  this.authorizeWrite=authorizeWrite;this.authorizeResume=authorizeResume;
  this.clock=clock;this.maxAgeMs=maxAgeMs;this.ttlMs=ttlMs;
  this.mode='STOP';this.epoch=1;
  this.used=new Set();this.receipts=[];
 }
 snapshot(){
  return Object.freeze({deviceId:this.deviceId,tenantId:this.tenantId,mode:this.mode,epoch:this.epoch,availableTools:Object.keys(this.handlers)});
 }
 // A local owner control gate; a cloud request may STOP but may never resume.
 stop(){
  this.mode='STOP';this.epoch++;return this.snapshot();
 }
 async changeLocalMode(next){
  if(!MODES.has(next))throw fail('INVALID_MODE');
  if(next!=='STOP'&&!await this.authorizeResume(next))throw fail('LOCAL_OWNER_APPROVAL_REQUIRED');
  if(next==='STOP')return this.stop();
  this.mode=next;this.epoch++;return this.snapshot();
 }
 packageReceipt(requestId,state,result){
  const payload={requestId,tenantId:this.tenantId,deviceId:this.deviceId,epoch:this.epoch,state,at:this.clock(),result};
  const receipt={payload,signature:sign(payload,this.secret)};
  this.receipts.push(receipt);
  if(this.receipts.length>200)this.receipts.shift();
  return receipt;
 }
 async handle(message){
  const id=message?.body?.requestId;
  const response=(state,reason)=>this.packageReceipt(sane(id)?id:'invalid-request',state,{reason});
  if(!message||typeof message!=='object'||!message.body||typeof message.body!=='object'||!macMatches(message.body,message.signature,this.secret))return response('REJECTED','BAD_SIGNATURE');
  const b=message.body;
  if(!sane(b.requestId)||!sane(b.tenantId)||!sane(b.deviceId))return response('REJECTED','INVALID_ID');
  if(b.tenantId!==this.tenantId||b.deviceId!==this.deviceId)return response('REJECTED','IDENTITY_MISMATCH');
  if(!Number.isSafeInteger(b.epoch)||b.epoch!==this.epoch)return response('REJECTED','CONTROL_EPOCH_CHANGED');
  if(!Number.isSafeInteger(b.issuedAt)||!Number.isSafeInteger(b.expiresAt)||b.issuedAt>this.clock()+5000||b.issuedAt<this.clock()-this.maxAgeMs||b.expiresAt<=this.clock()||b.expiresAt-b.issuedAt>this.ttlMs)return response('REJECTED','REQUEST_EXPIRED');
  if(!Object.hasOwn(ACTIONS,b.tool)||typeof this.handlers[b.tool]!=='function')return response('REJECTED','TOOL_UNAVAILABLE');
  if(!b.arguments||typeof b.arguments!=='object'||Array.isArray(b.arguments)||JSON.stringify(b.arguments).length>65536)return response('REJECTED','BAD_ARGUMENTS');
  if(this.used.has(b.requestId))return response('REJECTED','DUPLICATE_REQUEST_ID');
  this.used.add(b.requestId);
  if(this.used.size>10000)return response('REJECTED','RESTART_FOR_PERSISTENT_DEDUP_STORAGE');
  if(this.mode==='STOP')return response('REJECTED','OWNER_STOP');
  if(this.mode==='LIMITED'&&!ACTIONS[b.tool].readOnly)return response('REJECTED','READ_ONLY_MODE');
  if(!ACTIONS[b.tool].readOnly&&!await this.authorizeWrite(Object.freeze({...b})))return response('REJECTED','LOCAL_WRITE_APPROVAL_REQUIRED');
  const checkpoint=this.epoch;
  const receipt=this.packageReceipt(b.requestId,'RECEIVED',{tool:b.tool});
  if(checkpoint!==this.epoch||this.mode==='STOP')return response('CANCELLED','OWNER_STOP');
  try{
   // Execution delegated to a real privileged engine only after an explicit host authorization gate.
   // No built-in shell or file access in this prototype.
   const answer=await this.handlers[b.tool](Object.freeze({...b.arguments}),Object.freeze({deviceId:this.deviceId,tenantId:this.tenantId,epoch:checkpoint,requestId:b.requestId}));
   if(checkpoint!==this.epoch||this.mode==='STOP')return response('UNKNOWN','CONTROL_CHANGED_DURING_EXECUTION');
   return this.packageReceipt(b.requestId,'EXECUTED',{handlerResult:answer,verified:false});
  }catch(e){return this.packageReceipt(b.requestId,'FAILED',{reason:typeof e?.code==='string'?e.code:'HANDLER_FAILED'});}
 }
}
export function signedRequest(dispatch,{tool='read_file',arguments:args={},requestId=randomUUID(),issuedAt=dispatch.clock(),expiresAt=issuedAt+30000,epoch=dispatch.epoch,tenantId=dispatch.tenantId,deviceId=dispatch.deviceId}={}){
 const body={requestId,tenantId,deviceId,issuedAt,expiresAt,epoch,tool,arguments:args};
 return {body,signature:sign(body,dispatch.secret)};
}
