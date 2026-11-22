// ShanX13 AiGG Commercial Device Agent / real operating-system handlers.
// Generic customer agent; not hardcoded to MONSTER or to Customer #1.
// Only the explicitly enrolled workspace root is accessible. No shell, no deletion.
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import {createHash} from 'node:crypto';

const LIMIT=64*1024;
const deny=code=>Object.assign(new Error(code),{code});
const validRelative=p=>typeof p==='string'&&p.length>0&&p.length<=300&&
  !path.isAbsolute(p)&&!path.win32.isAbsolute(p)&&!/[\\\0]/.test(p)&&
  p.split('/').every(part=>part!==''&&part!=='.'&&part!=='..'&&part.length<=100);
const sha=data=>createHash('sha256').update(data).digest('hex');

async function resolved(root,relative,{allowNew=false}={}){
  if(!validRelative(relative))throw deny('UNSAFE_PATH');
  const canonical=await fs.realpath(root);
  const full=path.resolve(canonical,...relative.split('/'));
  if(!full.startsWith(canonical+path.sep))throw deny('OUT_OF_SCOPE');
  const items=relative.split('/');
  let candidate=canonical;
  for(let i=0;i<items.length;i++){
    candidate=path.join(candidate,items[i]);
    try{
      const stat=await fs.lstat(candidate);
      if(stat.isSymbolicLink())throw deny('SYMLINK_DENIED');
    }catch(e){
      if(e.code==='ENOENT'&&allowNew&&i===items.length-1)break;
      throw e;
    }
  }
  return full;
}
export function createRealDeviceHandlers({workspaceRoot,now=()=>Date.now()}={}){
  if(typeof workspaceRoot!=='string'||!path.isAbsolute(workspaceRoot))throw deny('WORKSPACE_REQUIRED');
  return Object.freeze({
    async system_info(){
      return {deviceRole:'customer-agent',hostname:os.hostname(),platform:os.platform(),
        arch:os.arch(),release:os.release(),node:process.versions.node,uptimeSeconds:Math.floor(os.uptime()),
        observedAt:new Date(now()).toISOString()};
    },
    async list_dir(args){
      const target=await resolved(workspaceRoot,args?.path||'documents');
      const stat=await fs.lstat(target);
      if(!stat.isDirectory())throw deny('NOT_DIRECTORY');
      const names=await fs.readdir(target,{withFileTypes:true});
      if(names.length>200)throw deny('TOO_MANY_ENTRIES');
      return {path:args.path||'documents',entries:names.map(x=>({name:x.name,type:x.isDirectory()?'directory':x.isFile()?'file':'other'}))};
    },
    async read_file(args){
      const target=await resolved(workspaceRoot,args?.path);
      const stat=await fs.lstat(target);
      if(!stat.isFile())throw deny('NOT_REGULAR_FILE');
      if(stat.size>LIMIT)throw deny('TOO_LARGE');
      const data=await fs.readFile(target);
      if(data.byteLength>LIMIT)throw deny('TOO_LARGE');
      const decoded=new TextDecoder('utf-8',{fatal:true}).decode(data);
      return {path:args.path,content:decoded,bytes:data.byteLength,sha256:sha(data)};
    },
    async write_file(args){
      if(typeof args?.content!=='string'||Buffer.byteLength(args.content,'utf8')>LIMIT)throw deny('TOO_LARGE');
      const target=await resolved(workspaceRoot,args?.path,{allowNew:true});
      const content=Buffer.from(args.content,'utf8');
      let fd;
      try{
        fd=await fs.open(target,'wx',0o600);
        await fd.writeFile(content);
        await fd.sync();
      }finally{await fd?.close()}
      const back=await fs.readFile(target);
      if(sha(content)!==sha(back))throw deny('POST_WRITE_MISMATCH');
      return {path:args.path,bytes:back.byteLength,sha256:sha(back),verified:true,created:true};
    }
  });
}
