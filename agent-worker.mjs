// Independent machine-to-cloud transport for the SAME ShanX13 AiGG Direct Commander product.
// Public endpoint does NOT offer browser account routes; each agent is authenticated by a
// 384-bit one-time enrollment secret whose SHA-256 alone is stored in the EXISTING D1 database.
// No shell, arbitrary device control, or cross-tenant resource access.
import {handleDeviceRoute} from './customer-device-routes.mjs';
const headers={'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'};
const send=(code,error)=>new Response(JSON.stringify({error}),{status:code,headers});
export default {
 async fetch(request,env){
  const path=new URL(request.url).pathname;
  if(path==='/health'&&request.method==='GET')
   return new Response(JSON.stringify({service:'ShanX13 AiGG Direct Commander agent API',status:'reachable'}),{headers});
  if(!path.startsWith('/api/agent/control/'))return send(404,'Not found');
  if(request.method!=='POST')return send(405,'POST required');
  if(request.headers.get('origin'))return send(403,'Browser origin denied');
  return (await handleDeviceRoute(request,env,async()=>null))??send(404,'Not found');
 }
};
