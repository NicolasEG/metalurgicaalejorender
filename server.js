const http=require('node:http');
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const root=__dirname, dataDir=path.join(root,'data'), uploadDir=path.join(root,'uploads');
fs.mkdirSync(dataDir,{recursive:true});fs.mkdirSync(uploadDir,{recursive:true});
const dbFile=path.join(dataDir,'content.json'), authFile=path.join(dataDir,'auth.json');
if(!fs.existsSync(dbFile))fs.copyFileSync(path.join(root,'content.json'),dbFile);
if(!fs.existsSync(authFile)){
 const password=crypto.randomBytes(12).toString('base64url'),salt=crypto.randomBytes(16).toString('hex');
 fs.writeFileSync(authFile,JSON.stringify({salt,hash:crypto.scryptSync(password,salt,64).toString('hex')}));
 fs.writeFileSync(path.join(dataDir,'acceso-inicial.txt'),'Contraseña del administrador: '+password+'\nGuardala en un lugar seguro. Podés cambiarla desde el administrador.\n');
}
const sessions=new Map(),attempts=new Map();
const publicOrigin=process.env.PUBLIC_ORIGIN?new URL(process.env.PUBLIC_ORIGIN).origin:'';
const load=()=>JSON.parse(fs.readFileSync(dbFile,'utf8'));
function save(value){const temp=dbFile+'.tmp';fs.writeFileSync(temp,JSON.stringify(value,null,2));fs.renameSync(temp,dbFile)}
const mime={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.png':'image/png','.webp':'image/webp','.jpg':'image/jpeg','.jpeg':'image/jpeg','.svg':'image/svg+xml','.mp4':'video/mp4','.webm':'video/webm','.json':'application/json; charset=utf-8','.ico':'image/x-icon','.webmanifest':'application/manifest+json'};
function json(res,status,value){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(value))}
async function body(req,limit=1024*1024){let size=0,parts=[];for await(const b of req){size+=b.length;if(size>limit)throw Object.assign(Error('El archivo supera el tamaño permitido.'),{status:413});parts.push(b)}return Buffer.concat(parts)}
function authenticated(req){const token=(req.headers.cookie||'').match(/(?:^|;\s*)alejo_session=([^;]+)/)?.[1];const s=sessions.get(token);if(!s||s<Date.now()){sessions.delete(token);return false}return token}
const str=(x,max=500)=>typeof x==='string'?x.trim().slice(0,max):'';
function clean(input){
 const old=load();
 const settings={};for(const key of ['headline','intro','about','phone','email','whatsapp','location'])settings[key]=str(input.settings?.[key],key==='about'?2000:500);
 if(!/^\d{8,15}$/.test(settings.whatsapp))throw Error('Revisá el número de WhatsApp: usá solo números con código de país.');
 if(!/^\S+@\S+\.\S+$/.test(settings.email))throw Error('Revisá el email.');
 const allowed=new Set(old.projects.flatMap(x=>x.media.map(m=>m.src)));
 for(const name of fs.readdirSync(uploadDir))allowed.add('/uploads/'+name);
 const projects=(input.projects||[]).slice(0,200).map(p=>({id:str(p.id,60)||crypto.randomUUID(),title:str(p.title,100),category:str(p.category,80),description:str(p.description,1000),published:p.published!==false,media:(p.media||[]).slice(0,30).filter(m=>allowed.has(m.src)).map(m=>({src:m.src,type:/\.(mp4|webm)$/i.test(m.src)?'video':'image',alt:str(m.alt,150)}))}));
 if(projects.some(p=>p.published&&!p.media.length))throw Error('Agregá al menos un archivo para publicar.');
 if(projects.some(p=>!p.title||!p.category))throw Error('Cada trabajo necesita un título y una categoría.');
 return {...old,settings,projects,updatedAt:new Date().toISOString()};
}
const server=http.createServer(async(req,res)=>{
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');res.setHeader('X-Frame-Options','DENY');
 try{
 const url=new URL(req.url,'http://localhost');const route=decodeURIComponent(url.pathname);
 if(req.method!=='GET'&&req.method!=='HEAD'){
  const origin=req.headers.origin;if(origin&&origin!==(publicOrigin||`${req.socket.encrypted?'https':'http'}://${req.headers.host}`))return json(res,403,{error:'Origen no permitido.'});
 }
 if(route==='/api/content'&&req.method==='GET'){const value=load();value.projects=value.projects.filter(p=>p.published);return json(res,200,value)}
 if(route==='/api/login'&&req.method==='POST'){
  const ip=req.socket.remoteAddress;const a=attempts.get(ip)||{count:0,until:Date.now()+900000};if(a.until<Date.now()){a.count=0;a.until=Date.now()+900000}if(a.count>=10)return json(res,429,{error:'Demasiados intentos. Esperá 15 minutos.'});
  const b=JSON.parse((await body(req,4096)).toString());const auth=JSON.parse(fs.readFileSync(authFile));const hash=crypto.scryptSync(typeof b.password==='string'?b.password.slice(0,200):'',auth.salt,64);if(!crypto.timingSafeEqual(hash,Buffer.from(auth.hash,'hex'))){a.count++;attempts.set(ip,a);return json(res,401,{error:'Contraseña incorrecta.'})}
  attempts.delete(ip);const token=crypto.randomBytes(32).toString('hex');sessions.set(token,Date.now()+86400000);res.setHeader('Set-Cookie',`alejo_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400${req.socket.encrypted||publicOrigin.startsWith('https:')?'; Secure':''}`);return json(res,200,{ok:true});
 }
 if(route.startsWith('/api/admin')){
  const token=authenticated(req);if(!token)return json(res,401,{error:'Ingresá para continuar.'});
  if(route==='/api/admin/content'&&req.method==='GET')return json(res,200,load());
  if(route==='/api/admin/content'&&req.method==='PUT'){const value=clean(JSON.parse((await body(req,2097152)).toString()));save(value);return json(res,200,value)}
  if(route==='/api/admin/logout'&&req.method==='POST'){sessions.delete(token);res.setHeader('Set-Cookie','alejo_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');return json(res,200,{ok:true})}
  if(route==='/api/admin/password'&&req.method==='POST'){
   const b=JSON.parse((await body(req,4096)).toString()),auth=JSON.parse(fs.readFileSync(authFile));
   if(!crypto.timingSafeEqual(crypto.scryptSync(typeof b.current==='string'?b.current.slice(0,200):'',auth.salt,64),Buffer.from(auth.hash,'hex')))return json(res,400,{error:'La contraseña actual no coincide.'});
   if(typeof b.password!=='string'||b.password.length<12||b.password.length>200)return json(res,400,{error:'Usá entre 12 y 200 caracteres.'});
   const salt=crypto.randomBytes(16).toString('hex');fs.writeFileSync(authFile,JSON.stringify({salt,hash:crypto.scryptSync(b.password,salt,64).toString('hex')}));
   if(fs.existsSync(path.join(dataDir,'acceso-inicial.txt')))fs.unlinkSync(path.join(dataDir,'acceso-inicial.txt'));for(const k of sessions.keys())if(k!==token)sessions.delete(k);return json(res,200,{ok:true});
  }
  if(route==='/api/admin/upload'&&req.method==='POST'){
   const bytes=await body(req,150*1024*1024);let ext='';
   if(bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])))ext='png';
   else if(bytes[0]===255&&bytes[1]===216&&bytes[2]===255)ext='jpg';
   else if(bytes.toString('ascii',0,4)==='RIFF'&&bytes.toString('ascii',8,12)==='WEBP')ext='webp';
   else if(bytes.toString('ascii',4,8)==='ftyp'&&['isom','iso2','mp41','mp42','avc1','M4V ','qt  '].includes(bytes.toString('ascii',8,12)))ext='mp4';
   else if(bytes.subarray(0,4).equals(Buffer.from([26,69,223,163]))&&bytes.subarray(0,4096).includes(Buffer.from('webm')))ext='webm';
   if(!ext)return json(res,400,{error:'Formato no compatible. Usá JPG, PNG, WebP, MP4 o WebM.'});
   const filename=crypto.randomUUID()+'.'+ext;fs.writeFileSync(path.join(uploadDir,filename),bytes);return json(res,201,{src:'/uploads/'+filename,type:['mp4','webm'].includes(ext)?'video':'image',alt:''});
  }
  return json(res,404,{error:'Acción no encontrada.'});
 }
 if(req.method!=='GET'&&req.method!=='HEAD')return json(res,405,{error:'Método no permitido.'});
 let file=route==='/'?'index.html':route==='/admin'?'admin.html':route.replace(/^\//,'');
 if(!/^(?:index\.html|servicios\.html|contacto\.html|admin\.html|app\.js|content-data\.js|admin\.js|styles\.css|admin\.css|manifest\.webmanifest|content\.json|assets\/[\w.-]+|assets\/videos\/[\w.-]+|uploads\/[\w.-]+)$/.test(file))return json(res,404,{error:'Página no encontrada.'});
 if(file==='content.json'){const value=load();value.projects=value.projects.filter(p=>p.published);return json(res,200,value)}
 const full=path.join(root,file);if(!fs.existsSync(full))return json(res,404,{error:'Archivo no encontrado.'});
 const stat=fs.statSync(full),range=req.headers.range;res.setHeader('Content-Type',mime[path.extname(file)]||'application/octet-stream');res.setHeader('Accept-Ranges','bytes');res.setHeader('Cache-Control',file.startsWith('uploads/')?'public, max-age=31536000, immutable':'no-cache');
 let start=0,end=stat.size-1,status=200;if(range){const m=range.match(/^bytes=(\d+)-(\d*)$/);if(!m||Number(m[1])>=stat.size){res.writeHead(416,{'Content-Range':`bytes */${stat.size}`});return res.end()}start=Number(m[1]);end=m[2]?Math.min(Number(m[2]),end):end;if(end<start){res.writeHead(416);return res.end()}status=206;res.setHeader('Content-Range',`bytes ${start}-${end}/${stat.size}`)}
 res.writeHead(status,{'Content-Length':end-start+1});if(req.method==='HEAD')return res.end();fs.createReadStream(full,{start,end}).pipe(res);
 }catch(error){json(res,error.status||400,{error:error.status===413?error.message:'No se pudo completar la acción. Revisá los datos e intentá de nuevo.'})}
});
const port=Number(process.env.PORT)||3000,host=process.env.HOST||'127.0.0.1';server.listen(port,host,()=>console.log(`Metalúrgica Alejo: http://${host}:${port}\nAdministrador: /admin\nAcceso inicial: data/acceso-inicial.txt`));
