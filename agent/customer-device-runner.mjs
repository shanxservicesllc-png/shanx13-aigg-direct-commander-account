// Manually supervised customer device session. Never installs a service or writes OS startup entries.
import fs from 'node:fs/promises';
import {CommercialDeviceAgent} from './cloud-agent.mjs';
const {SHANX_AGENT_TOKEN,SHANX_AGENT_MODE,SHANX_AGENT_CONFIG,SHANX_AGENT_WRITE_APPROVED}=process.env;
delete process.env.SHANX_AGENT_TOKEN;
if(!['LIMITED','GO'].includes(SHANX_AGENT_MODE)||!SHANX_AGENT_CONFIG||!/^[a-f0-9]{96}$/.test(SHANX_AGENT_TOKEN||''))throw Error('Agent not locally initialized');
const config=JSON.parse(await fs.readFile(SHANX_AGENT_CONFIG,'utf8'));
if(!config.serviceUrl?.startsWith('https://'))throw Error('Cloud must use HTTPS');
const agent=new CommercialDeviceAgent({...config,agentToken:SHANX_AGENT_TOKEN,
 approvedResume:async mode=>mode===SHANX_AGENT_MODE,
 approvedWrite:async job=>SHANX_AGENT_MODE==='GO'&&SHANX_AGENT_WRITE_APPROVED==='YES'&&job.tool==='write_file'&&/^documents\/[A-Za-z0-9 _.-]{1,120}\.txt$/.test(job.arguments.path)});
await agent.initialize();
await agent.localMode(SHANX_AGENT_MODE);
let stopRequested=false;
process.on('SIGINT',()=>{stopRequested=true;});
process.on('SIGTERM',()=>{stopRequested=true;});
try{
 console.log('ShanX13 Agent: device '+config.deviceId+', locally authorized '+SHANX_AGENT_MODE+'. No automatic background service installed.');
 for(let i=0;i<30&&!stopRequested;i++){
  const r=await agent.cycle();
  console.log('Device cycle '+(i+1)+': '+r.status+(r.requestId?' id='+r.requestId:''));
  if(r.status==='STOP')break;
  if(i<29&&!stopRequested)await new Promise(resolve=>setTimeout(resolve,2000));
 }
} finally{
 agent.dispatch.stop();
 try{await agent.request('/api/agent/control/state',{mode:'STOP',local_epoch:agent.dispatch.epoch});console.log('Cloud STOP delivered.')}
 catch{console.log('Cloud STOP not acknowledged. Local dispatcher STOP is active; verify cloud state separately.')}
}
