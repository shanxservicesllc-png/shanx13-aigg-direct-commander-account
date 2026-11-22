// ShanX13 AiGG commercial multi-tenant device job routing, v0.2 candidate.
// Uses existing independent D1 account schema. No global owner device backdoor.
// All customer authorization is derived from a verified Cloudflare Access identity.
// Agent credentials are separate 48-byte random secrets; only SHA-256 hashes stored in D1.
const JSON_HEADERS={"content-type":"application/json; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff","referrer-policy":"no-referrer"};
const respond=(obj,status=200)=>new Response(JSON.stringify(obj),{status,headers:JSON_HEADERS});
const deny=(code='Unauthorized',status=401)=>respond({error:code},status);
const short=s=>typeof s==="string"&&s.length>0&&s.length<=100;
const validId=s=>short(s)&&/^[A-Za-z0-9_-]{3,100}$/.test(s);
const validPath=s=>typeof s==="string"&&s.length>=1&&s.length<=300&&
  !s.includes("\\")&&!s.includes("\0")&&!s.startsWith("/")&&
  s.split("/").every(k=>k&&k!=="."&&k!==".."&&k.length<=100);
const post=(req)=>req.method==="POST";
const iso=()=>new Date().toISOString();
const epoch=()=>Date.now();
const stmt=(db,sql,...args)=>db.prepare(sql).bind(...args);
const digest=async secret=>Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(secret))),b=>b.toString(16).padStart(2,"0")).join("");
async function body(req,max=3500){
 if(!req.headers.get('content-type')?.startsWith('application/json'))throw Error('CONTENT_TYPE');
 const length=Number(req.headers.get('content-length')||0);
 if(length>max)throw Error('TOO_LARGE');
 const raw=await req.text();
 if(raw.length>max)throw Error('TOO_LARGE');
 const value=JSON.parse(raw);
 if(!value||typeof value!=='object'||Array.isArray(value))throw Error('BAD_BODY');
 return value;
}
const configured=env=>Boolean(env?.DB&&env.ACCESS_TEAM_DOMAIN&&env.ACCESS_AUD&&env.OWNER_EMAILS);
async function viewer(req,env,verify){
 const signed=req.headers.get('CF-Access-Jwt-Assertion');
 if(!signed)return null;
 const claim=await verify(signed,env);
 if(!claim||typeof claim.email!=='string')return null;
 const row=await stmt(env.DB,'SELECT email,tenant_id,role,active,subscription_status FROM accounts WHERE email=?',claim.email.toLowerCase()).first();
 if(!row||row.active!==1||row.role!=='customer'||!['active','trial'].includes(row.subscription_status))return null;
 return {email:row.email,tenantId:row.tenant_id,status:row.subscription_status};
}
async function agentViewer(req,env){
 const header=req.headers.get('authorization')||'';
 if(!/^Bearer [a-f0-9]{96}$/.test(header))return null;
 const token=header.slice(7);
 const agent=await stmt(env.DB,'SELECT agent_id,tenant_id,device_id FROM agents WHERE token_hash=? AND active=1',await digest(token)).first();
 if(!agent)return null;
 const account=await stmt(env.DB,'SELECT active,subscription_status FROM accounts WHERE tenant_id=?',agent.tenant_id).first();
 if(!account||account.active!==1||!['trial','active'].includes(account.subscription_status))return null;
 return agent;
}
async function control(db,agent){
 const state=await stmt(db,'SELECT mode,epoch,locked,last_seen_at FROM customer_device_control WHERE agent_id=? AND tenant_id=?',agent.agent_id,agent.tenant_id).first();
 return state??{mode:'STOP',epoch:1,locked:1,last_seen_at:null};
}
async function customer(req,env,verify,path){
 const user=await viewer(req,env,verify);if(!user)return deny();
 if(path==='/customer'&&req.method==='GET')return customerPage();
 if(path==='/api/customer/me'&&req.method==='GET')return respond({email:user.email,tenant_id:user.tenantId,subscription_status:user.status});
 if(path==='/api/customer/devices'&&req.method==='GET'){
  const data=await stmt(env.DB,`SELECT a.agent_id,a.device_id,c.mode,c.epoch,c.locked,c.last_seen_at FROM agents a
    LEFT JOIN customer_device_control c ON c.agent_id=a.agent_id
    WHERE a.tenant_id=? AND a.active=1 ORDER BY a.device_id LIMIT 50`,user.tenantId).all();
  return respond({devices:(data.results||[]).map(d=>({...d,mode:d.mode||'STOP',locked:d.locked??1}))});
 }
 if(path==='/api/customer/devices/enroll'&&post(req)){
  let x;try{x=await body(req,900)}catch{return deny('Invalid enrollment request',400)}
  if(!validId(x.device_id))return deny('Invalid device identifier',400);
  const existing=await stmt(env.DB,'SELECT COUNT(*) AS total FROM agents WHERE tenant_id=? AND active=1',user.tenantId).first();
  if(Number(existing?.total||0)>=10)return deny('Device capacity reached',409);
  const secret=Array.from(crypto.getRandomValues(new Uint8Array(48)),b=>b.toString(16).padStart(2,'0')).join('');
  const agentId=crypto.randomUUID();const now=iso();
  try{
   await env.DB.batch([
    stmt(env.DB,'INSERT INTO agents(agent_id,tenant_id,device_id,token_hash,active) VALUES(?,?,?,?,1)',agentId,user.tenantId,x.device_id,await digest(secret)),
    stmt(env.DB,"INSERT INTO customer_device_control(agent_id,tenant_id,device_id,mode,epoch,locked,updated_at) VALUES(?,?,?,'STOP',1,0,?)",agentId,user.tenantId,x.device_id,now)
   ]);
  }catch{return deny('Device already enrolled or unavailable',409)}
  return respond({agent_id:agentId,device_id:x.device_id,tenant_id:user.tenantId,mode:'STOP',
     one_time_agent_token:secret,note:'Copy this once to your approved device. Never share publicly.'},201);
 }
  // Tenant-authenticated reissue for the SAME existing STOP/unseen agent.
  // Previous token is revoked atomically, no new tenant or device is created.
  if(path==='/api/customer/devices/reissue'&&post(req)){
   let x;try{x=await body(req,500)}catch{return deny('Invalid reissue request',400)}
   if(!validId(x.agent_id)||x.confirm!=='REISSUE_STOPPED_UNSEEN_DEVICE')return deny('Explicit confirmation required',400);
   const found=await stmt(env.DB,`SELECT a.device_id,c.mode,c.last_seen_at FROM agents a
     JOIN customer_device_control c ON a.agent_id=c.agent_id AND a.tenant_id=c.tenant_id
     WHERE a.agent_id=? AND a.tenant_id=? AND a.active=1`,x.agent_id,user.tenantId).first();
   if(!found)return deny('Device not found',404);
   if(found.mode!=='STOP'||found.last_seen_at!==null)return deny('Device has already connected or is not STOP',409);
   const pending=await stmt(env.DB,`SELECT COUNT(*) AS total FROM customer_device_jobs
     WHERE agent_id=? AND tenant_id=? AND state IN ('QUEUED','DELIVERED','RUNNING')`,x.agent_id,user.tenantId).first();
   if(Number(pending?.total||0)>0)return deny('Device still has outstanding work',409);
   const token=Array.from(crypto.getRandomValues(new Uint8Array(48)),b=>b.toString(16).padStart(2,'0')).join('');
   const changed=await stmt(env.DB,`UPDATE agents SET token_hash=?
     WHERE agent_id=? AND tenant_id=? AND active=1 AND EXISTS (
       SELECT 1 FROM customer_device_control c WHERE c.agent_id=agents.agent_id
       AND c.tenant_id=agents.tenant_id AND c.mode='STOP' AND c.last_seen_at IS NULL
     )`,await digest(token),x.agent_id,user.tenantId).run();
   if(changed.meta?.changes!==1)return deny('Device state changed before reissue',409);
   return respond({agent_id:x.agent_id,device_id:found.device_id,mode:'STOP',
     one_time_agent_token:token,note:'Old device token revoked. Save this new token only on your authorized device.'});
  }
 if(path==='/api/customer/devices/stop'&&post(req)){
  let x;try{x=await body(req,400)}catch{return deny('Invalid stop request',400)}
  if(!validId(x.agent_id))return deny('Invalid agent',400);
  const active=await stmt(env.DB,'SELECT agent_id,device_id FROM agents WHERE agent_id=? AND tenant_id=? AND active=1',x.agent_id,user.tenantId).first();
  if(!active)return deny('Device not found',404);
  const now=iso();
  await env.DB.batch([
   stmt(env.DB,"UPDATE customer_device_control SET mode='STOP',locked=1,epoch=epoch+1,updated_at=? WHERE agent_id=? AND tenant_id=?",now,active.agent_id,user.tenantId),
   stmt(env.DB,"UPDATE customer_device_jobs SET state='CANCELLED',updated_at=? WHERE agent_id=? AND tenant_id=? AND state IN ('QUEUED','DELIVERED')",now,active.agent_id,user.tenantId),
   stmt(env.DB,"UPDATE customer_device_jobs SET state='UNKNOWN',updated_at=? WHERE agent_id=? AND tenant_id=? AND state='RUNNING'",now,active.agent_id,user.tenantId)
  ]);
  return respond({mode:'STOP',locked:true,queued_cancelled:true,
     note:'STOP sent to cloud. An offline device must observe STOP before its local agent can acknowledge it.'});
 }
 if(path==='/api/customer/devices/unlock'&&post(req)){
  let x;try{x=await body(req,300)}catch{return deny('Invalid request',400)}
  if(!validId(x.agent_id)||x.confirm!=='ENABLE_DEVICE_AFTER_LOCAL_APPROVAL')return deny('Explicit confirmation required',400);
  const active=await stmt(env.DB,'SELECT agent_id FROM agents WHERE agent_id=? AND tenant_id=? AND active=1',x.agent_id,user.tenantId).first();
  if(!active)return deny('Device not found',404);
  await stmt(env.DB,"UPDATE customer_device_control SET locked=0,mode='STOP',epoch=epoch+1,updated_at=? WHERE agent_id=? AND tenant_id=?",iso(),x.agent_id,user.tenantId).run();
  return respond({mode:'STOP',locked:false,note:'Cloud lock cleared. Device still requires independent local owner authorization.'});
 }
 if(path==='/api/customer/jobs'&&req.method==='GET'){
  const items=await stmt(env.DB,'SELECT request_id,device_id,action,state,created_at,updated_at,result_json FROM customer_device_jobs WHERE tenant_id=? ORDER BY created_at DESC LIMIT 30',user.tenantId).all();
  return respond({jobs:(items.results||[]).map(j=>({...j,result:j.result_json?JSON.parse(j.result_json):null,result_json:undefined}))});
 }
 if(path==='/api/customer/jobs'&&post(req)){
  let x;try{x=await body(req,4400)}catch{return deny('Invalid job request',400)}
  if(!validId(x.device_id)||!['system_info','list_dir','read_file','write_file'].includes(x.action)||!x.arguments||typeof x.arguments!=='object'||Array.isArray(x.arguments))return deny('Invalid job',400);
  if(x.action==='read_file'||x.action==='write_file'||x.action==='list_dir'){
    if(!validPath(x.arguments.path))return deny('Unsafe relative workspace path',400);
  }
  if(x.action==='write_file'&&(typeof x.arguments.content!=='string'||x.arguments.content.length>1800))return deny('Invalid content',400);
  if(x.action==='system_info'&&Object.keys(x.arguments).length!==0)return deny('No arguments for system info',400);
  const agent=await stmt(env.DB,'SELECT agent_id,tenant_id,device_id FROM agents WHERE tenant_id=? AND device_id=? AND active=1',user.tenantId,x.device_id).first();
  if(!agent)return deny('Device not enrolled',404);
  const gate=await control(env.DB,agent);
  if(gate.mode==='STOP'||gate.locked|| (x.action==='write_file'&&gate.mode!=='GO'))return deny('Device not authorized for this operation',423);
  const requestId=crypto.randomUUID(),when=iso();
  const count=await stmt(env.DB,"SELECT COUNT(*) AS n FROM customer_device_jobs WHERE agent_id=? AND state IN ('QUEUED','DELIVERED','RUNNING')",agent.agent_id).first();
  if((count?.n??0)>=10)return deny('Device queue full',429);
  await stmt(env.DB,"INSERT INTO customer_device_jobs(request_id,agent_id,tenant_id,device_id,action,arguments_json,state,control_epoch,created_at,updated_at,expires_at_ms) VALUES(?,?,?,?,?,?,'QUEUED',?,?,?,?)",
    requestId,agent.agent_id,user.tenantId,x.device_id,x.action,JSON.stringify(x.arguments),gate.epoch,when,when,epoch()+60000).run();
  return respond({request_id:requestId,device_id:x.device_id,state:'QUEUED',verified:false},202);
 }
 if(path==='/api/customer/jobs/status'&&req.method==='GET'){
  const id=new URL(req.url).searchParams.get('request_id');
  if(!validId(id))return deny('Invalid request',400);
  const j=await stmt(env.DB,'SELECT request_id,device_id,action,state,created_at,updated_at,result_json FROM customer_device_jobs WHERE request_id=? AND tenant_id=?',id,user.tenantId).first();
  if(!j)return deny('Job not found',404);
  return respond({request_id:j.request_id,device_id:j.device_id,action:j.action,state:j.state,at:j.updated_at,
    result:j.result_json?JSON.parse(j.result_json):null,independently_verified:false});
 }
 return deny('Not found',404);
}
async function device(req,env,path){
 const agent=await agentViewer(req,env);if(!agent)return deny();
 const gate=await control(env.DB,agent);
 if(path==='/api/agent/control/bootstrap'&&post(req)){
  return respond({agent_id:agent.agent_id,tenant_id:agent.tenant_id,device_id:agent.device_id,
    mode:gate.mode,locked:!!gate.locked,epoch:gate.epoch,
    note:'Token-verified identity. Device still starts in local STOP.'});
 }
 if(path==='/api/agent/control/state'&&post(req)){
  let x;try{x=await body(req,600)}catch{return deny('Invalid state',400)}
  if(!['STOP','LIMITED','GO'].includes(x.mode)||!Number.isSafeInteger(x.local_epoch)||x.local_epoch<1)return deny('Invalid local mode',400);
  if(gate.locked)return respond({mode:'STOP',locked:true,epoch:gate.epoch});
  const mode=x.mode;
  if(mode!==gate.mode){
    await stmt(env.DB,'UPDATE customer_device_control SET mode=?,epoch=epoch+1,last_seen_at=?,updated_at=? WHERE agent_id=?',
      mode,iso(),iso(),agent.agent_id).run();
  }else await stmt(env.DB,'UPDATE customer_device_control SET last_seen_at=? WHERE agent_id=?',iso(),agent.agent_id).run();
  const latest=await control(env.DB,agent);
  return respond({mode:latest.mode,locked:!!latest.locked,epoch:latest.epoch});
 }
 if(path==='/api/agent/control/poll'&&post(req)){
  if(gate.mode==='STOP'||gate.locked)return respond({mode:'STOP',locked:!!gate.locked,epoch:gate.epoch,job:null});
  const item=await stmt(env.DB,"SELECT request_id,action,arguments_json,control_epoch,expires_at_ms FROM customer_device_jobs WHERE agent_id=? AND state='QUEUED' ORDER BY created_at LIMIT 1",agent.agent_id).first();
  if(!item)return respond({mode:gate.mode,epoch:gate.epoch,job:null});
  if(item.expires_at_ms<=epoch()||item.control_epoch!==gate.epoch){
    await stmt(env.DB,"UPDATE customer_device_jobs SET state='EXPIRED',updated_at=? WHERE request_id=? AND state='QUEUED'",iso(),item.request_id).run();
    return respond({mode:gate.mode,epoch:gate.epoch,job:null});
  }
  if(gate.mode==='LIMITED'&&item.action==='write_file')return respond({mode:gate.mode,epoch:gate.epoch,job:null});
  const move=await stmt(env.DB,"UPDATE customer_device_jobs SET state='DELIVERED',updated_at=? WHERE request_id=? AND agent_id=? AND state='QUEUED'",
    iso(),item.request_id,agent.agent_id).run();
  if(move.meta?.changes!==1)return respond({mode:gate.mode,epoch:gate.epoch,job:null});
  return respond({mode:gate.mode,epoch:gate.epoch,job:{request_id:item.request_id,device_id:agent.device_id,
    action:item.action,arguments:JSON.parse(item.arguments_json),expires_at_ms:item.expires_at_ms}});
 }
 if(path==='/api/agent/control/start'&&post(req)){
  let x;try{x=await body(req,300)}catch{return deny('Invalid start',400)}
  if(!validId(x.request_id))return deny('Invalid request',400);
  if(gate.mode==='STOP'||gate.locked)return deny('STOP active',423);
  const moved=await stmt(env.DB,"UPDATE customer_device_jobs SET state='RUNNING',updated_at=? WHERE request_id=? AND agent_id=? AND control_epoch=? AND state='DELIVERED' AND expires_at_ms>?",
    iso(),x.request_id,agent.agent_id,gate.epoch,epoch()).run();
  return moved.meta?.changes===1?respond({started:true}):deny('Not startable',409);
 }
 if(path==='/api/agent/control/receipt'&&post(req)){
  let x;try{x=await body(req,2500)}catch{return deny('Invalid receipt',400)}
  if(!validId(x.request_id)||!['EXECUTED','FAILED','REJECTED','UNKNOWN'].includes(x.state)||!x.result||
    typeof x.result!=='object'||Array.isArray(x.result))return deny('Invalid receipt',400);
  const moved=await stmt(env.DB,"UPDATE customer_device_jobs SET state=?,result_json=?,updated_at=? WHERE request_id=? AND agent_id=? AND state='RUNNING'",
    x.state,JSON.stringify(x.result),iso(),x.request_id,agent.agent_id).run();
  if(moved.meta?.changes!==1)return deny('Receipt not expected',409);
  // Do not label agent-reported execution as independently verified.
  return respond({recorded:true,agent_reported_state:x.state,independently_verified:false},202);
 }
 return deny('Not found',404);
}
function customerPage(){
 const html=`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ShanX13 AiGG Direct Commander — Customer Control</title><meta name="robots" content="noindex,nofollow">
<style>:root{font-family:system-ui; color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#091b11;color:#f1f6e7}
header{padding:22px;background:#153322;border-bottom:1px solid #55764a}header b{color:#eac67d}main{max-width:1000px;margin:50px auto;padding:0 20px}
h1{letter-spacing:-.04em;font-size:clamp(28px,4vw,44px)}p{color:#a9c2a4}button,select,input{padding:12px;border-radius:9px;background:#1c3a28;border:1px solid #78945f;color:#eaf7d8}
button{cursor:pointer;background:#c4ed8c;color:#13281a;font-weight:800}button.danger{background:#9c473c;color:white}.panels{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:15px}
article{background:#12291c;border:1px solid #55764a;border-radius:15px;padding:24px}.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px;white-space:pre-wrap;overflow-wrap:anywhere}
label{display:block;margin:12px 0 5px;font-size:12px;color:#dcca82}input,select{width:100%}@media(max-width:670px){.panels{grid-template-columns:1fr}}</style></head><body>
<header>SHANX13 <b>AIGG</b> / DIRECT COMMANDER <span style="float:right">Customer Control</span></header>
<main><h1>Control your authorized devices.</h1><p id="identity">Checking verified customer identity...</p>
<div class="panels"><article><h2>My devices</h2><button id="loadDevices">Refresh devices</button><div id="devices" class="mono"></div></article>
<article><h2>Enroll your computer</h2><p>Your account owns this device. Enrollment starts in STOP mode and requires an on-device agent installation.</p>
<label for="newDevice">Device identifier</label><input id="newDevice" placeholder="my-computer-01">
<p><button id="enrollDevice">Create one-time pairing token</button></p>
<div id="pairToken" class="mono" aria-live="polite">No token generated.</div><p><button id="copyToken">Copy pairing token</button></p><p><button id="reissueToken">Reissue token for selected STOP/unseen device</button></p><p>Previous token is revoked. Only for devices that have never connected.</p></article>
<article><h2>Device request</h2><label for="device">My device</label><select id="device"></select>
<label for="action">Action</label><select id="action"><option value="system_info">System information</option><option value="list_dir">List approved folder</option><option value="read_file">Read approved file</option></select>
<label for="target">Relative path in locally authorized workspace</label><input id="target" value="documents">
<p><button id="submit">Queue approved request</button></p><div id="result" class="mono"></div></article>
<article><h2>Actual activity</h2><button id="loadJobs">Refresh request receipts</button><div id="jobs" class="mono"></div></article>
<article><h2>Owner STOP</h2><p>STOP cancels queued commands. Any running operation is marked UNKNOWN until reconciled.</p><button id="stop" class="danger">STOP selected device</button><div id="stopResult" class="mono"></div></article></div></main>
<script>
const $=id=>document.getElementById(id);
async function api(url,body){const r=await fetch(url,{cache:'no-store',headers:body?{'content-type':'application/json'}:{},method:body?'POST':'GET',body:body?JSON.stringify(body):undefined});
const x=await r.json();if(!r.ok)throw Error(x.error||'Server rejected request');return x}
async function devices(){try{let x=await api('/api/customer/devices');$('devices').textContent=JSON.stringify(x.devices,null,2);
const select=$('device');select.replaceChildren();x.devices.forEach(d=>{const o=document.createElement('option');o.value=d.device_id;o.textContent=d.device_id+' / '+d.mode;select.append(o)})}catch(e){$('devices').textContent=e.message}}
async function jobs(){try{$('jobs').textContent=JSON.stringify((await api('/api/customer/jobs')).jobs,null,2)}catch(e){$('jobs').textContent=e.message}}
$('loadDevices').onclick=devices;$('loadJobs').onclick=jobs;
let oneTimeToken='';
$('enrollDevice').onclick=async()=>{try{
 const device=$('newDevice').value.trim();
 const x=await api('/api/customer/devices/enroll',{device_id:device});
 oneTimeToken=x.one_time_agent_token;
 $('pairToken').textContent='One-time token for '+x.device_id+' (shown only now): '+oneTimeToken;
 await devices();
}catch(e){$('pairToken').textContent=e.message}};
$('copyToken').onclick=async()=>{if(!oneTimeToken){$('pairToken').textContent='Create a token first';return}
try{await navigator.clipboard.writeText(oneTimeToken);$('pairToken').textContent='One-time pairing token copied. Install the agent on YOUR authorized computer and clear your clipboard.'}
catch{$('pairToken').textContent='Clipboard unavailable. Select and copy the token before navigating away: '+oneTimeToken}};
 $('reissueToken').onclick=async()=>{try{
  const d=(await api('/api/customer/devices')).devices.find(x=>x.device_id===$('device').value);
  if(!d||d.mode!=='STOP'||d.last_seen_at!==null)throw Error('Only STOPPED, never-connected devices are eligible');
  if(!confirm('Reissue token for '+d.device_id+'? The previous token immediately stops working.'))return;
  const x=await api('/api/customer/devices/reissue',{agent_id:d.agent_id,confirm:'REISSUE_STOPPED_UNSEEN_DEVICE'});
  oneTimeToken=x.one_time_agent_token;
  $('pairToken').textContent='Reissued token for '+x.device_id+' (shown only now): '+oneTimeToken;
 }catch(e){$('pairToken').textContent=e.message}};
$('submit').onclick=async()=>{try{const action=$('action').value;const args=action==='system_info'?{}:{path:$('target').value};
$('result').textContent=JSON.stringify(await api('/api/customer/jobs',{device_id:$('device').value,action,arguments:args}),null,2)}
catch(e){$('result').textContent=e.message}};
$('stop').onclick=async()=>{try{const list=await api('/api/customer/devices');const device=list.devices.find(d=>d.device_id===$('device').value);
if(!device||!confirm('STOP this device and cancel pending jobs?'))return;
$('stopResult').textContent=JSON.stringify(await api('/api/customer/devices/stop',{agent_id:device.agent_id}),null,2);
await devices()}catch(e){$('stopResult').textContent=e.message}};
(async()=>{try{const me=await api('/api/customer/me');$('identity').textContent='Signed in as '+me.email+' / '+me.subscription_status}catch(e){$('identity').textContent=e.message}await devices();await jobs()})();
</script></body></html>`;
 return new Response(html,{headers:{"content-type":"text/html; charset=utf-8","cache-control":"no-store","x-frame-options":"DENY","content-security-policy":"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"}});
}
export async function handleDeviceRoute(req,env,verify){
 const path=new URL(req.url).pathname;
 if(!path.startsWith('/api/customer/')&&!path.startsWith('/api/agent/control/')&&path!=='/customer')return null;
 if(!configured(env))return deny('Customer service not provisioned',503);
 try{
  if(path.startsWith('/api/customer/')||path==='/customer')return await customer(req,env,verify,path);
  return await device(req,env,path);
 }catch{return deny('Device service unavailable',503)}
}
