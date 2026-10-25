interface Env { ASSETS:Fetcher; DB:D1Database; ADMIN_SETUP_TOKEN?:string; IP_SERVICE?:Fetcher; DOMAIN_SERVICE?:Fetcher; HASH_SERVICE?:Fetcher; }
const enc=new TextEncoder();
const toHex=(a:Uint8Array)=>Array.from(a).map(x=>x.toString(16).padStart(2,"0")).join("");
const random=(n:number)=>toHex(crypto.getRandomValues(new Uint8Array(n)));
async function digest(s:string){return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256",enc.encode(s))))}
async function passwordHash(password:string,salt:string,iterations=310000){
 const key=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveBits"]);
 return toHex(new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2",salt:enc.encode(salt),iterations,hash:"SHA-256"},key,256)));
}
function constant(a:string,b:string){const aa=enc.encode(a),bb=enc.encode(b);let diff=aa.length^bb.length;for(let i=0;i<Math.max(aa.length,bb.length);i++)diff|=(aa[i]??0)^(bb[i]??0);return diff===0}
const json=(obj:unknown,status=200,extra:HeadersInit={})=>new Response(JSON.stringify(obj),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store",...extra}});
const cookie=(token:string,max:number)=>"mt_session="+token+"; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age="+max;
const now=()=>Math.floor(Date.now()/1000);
async function auth(req:Request,env:Env){
 const token=req.headers.get("cookie")?.match(/(?:^|;\s*)mt_session=([a-f0-9]{64})(?:;|$)/)?.[1];if(!token)return null;
 const row=await env.DB.prepare("SELECT u.id,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id_hash=? AND s.expires_at>? AND u.active=1").bind(await digest(token),now()).first<{id:string;username:string;role:string}>();
 return row??null;
}
const body=async(req:Request)=>{if(Number(req.headers.get("content-length")??0)>4096)throw Error("Petición demasiado grande");return req.json() as Promise<any>};
const sameOrigin=(req:Request)=>{const origin=req.headers.get("origin");return !origin||origin===new URL(req.url).origin};
export default {async fetch(req:Request,env:Env):Promise<Response>{
 const url=new URL(req.url),p=url.pathname;
 if(p==="/health")return json({ok:true,service:"monkeytools-portal"});
 if(p.startsWith("/api/") && !sameOrigin(req))return json({error:"Origen no permitido"},403);
 if(p==="/api/auth/setup/status"&&req.method==="GET"){
   try{const row=await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first<{n:number}>();return json({setup_enabled:Boolean(env.ADMIN_SETUP_TOKEN),database_ready:true,admin_exists:(row?.n??0)>0});}
   catch{return json({setup_enabled:Boolean(env.ADMIN_SETUP_TOKEN),database_ready:false,admin_exists:null});}
 }
 if(p==="/api/auth/setup"&&req.method==="POST"){
   if(!env.ADMIN_SETUP_TOKEN)return json({error:"Inicialización deshabilitada"},403);
   const token=req.headers.get("x-setup-token")??"";
   if(!constant(token,env.ADMIN_SETUP_TOKEN))return json({error:"No autorizado"},403);
   const count=await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first<{n:number}>();
   if((count?.n??0)>0)return json({error:"Administrador ya creado"},409);
   let input:any;try{input=await body(req)}catch{return json({error:"JSON inválido"},400)}
   const user=String(input.username??"").trim().toLowerCase(),password=String(input.password??"");
   if(!/^[a-z0-9_.-]{3,40}$/.test(user)||password.length<16||password.length>256)return json({error:"Usuario inválido o contraseña de menos de 16 caracteres"},400);
   const salt=random(24),hash=await passwordHash(password,salt),id=crypto.randomUUID();
   await env.DB.prepare("INSERT INTO users (id,username,password_salt,password_hash,password_iterations,role,created_at) VALUES (?,?,?,?,?,'admin',?)").bind(id,user,salt,hash,310000,now()).run();
   return json({ok:true,message:"Administrador creado. Elimina ADMIN_SETUP_TOKEN de los secretos del Worker."},201);
 }
 if(p==="/api/auth/login"&&req.method==="POST"){
   let input:any;try{input=await body(req)}catch{return json({error:"Petición inválida"},400)}
   const username=String(input.username??"").trim().toLowerCase(),password=String(input.password??"");
   if(username.length>40||password.length>256)return json({error:"Credenciales incorrectas"},401);
   const user=await env.DB.prepare("SELECT id,username,password_salt,password_hash,password_iterations,active FROM users WHERE username=?").bind(username).first<{id:string;username:string;password_salt:string;password_hash:string;password_iterations:number;active:number}>();
   // Derivación también para usuarios inexistentes: evita respuestas demasiado rápidas.
   const calc=await passwordHash(password,user?.password_salt??"fallback-salt-login",user?.password_iterations??310000);
   if(!user||!user.active||!constant(calc,user.password_hash))return json({error:"Credenciales incorrectas"},401);
   const token=random(32);await env.DB.prepare("INSERT INTO sessions(id_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)").bind(await digest(token),user.id,now()+86400,now()).run();
   return json({ok:true,username:user.username},200,{"set-cookie":cookie(token,86400)});
 }
 if(p==="/api/auth/logout"&&req.method==="POST"){
   const token=req.headers.get("cookie")?.match(/(?:^|;\s*)mt_session=([a-f0-9]{64})(?:;|$)/)?.[1];
   if(token)await env.DB.prepare("DELETE FROM sessions WHERE id_hash=?").bind(await digest(token)).run();
   return json({ok:true},200,{"set-cookie":cookie("",0)});
 }
 const user=await auth(req,env);
 if(p==="/api/auth/me")return user?json({authenticated:true,username:user.username,role:user.role}):json({authenticated:false},401);
 if(!user){
   if(p==="/login/"||p==="/login")return env.ASSETS.fetch(new Request(new URL("/login/",url),req));
   if(p==="/setup/"||p==="/setup")return env.ASSETS.fetch(new Request(new URL("/setup/",url),req));
   if(p.startsWith("/api/"))return json({error:"Inicia sesión para utilizar Monkeytools"},401);
   if(p==="/favicon.ico"||p.startsWith("/assets/"))return env.ASSETS.fetch(req);
   return Response.redirect(url.origin+"/login/",302);
 }
 if(p==="/login"||p==="/login/")return Response.redirect(url.origin+"/",302);
 const binds:Record<string,Fetcher|undefined>={"/api/ip/analyze":env.IP_SERVICE,"/api/domain/analyze":env.DOMAIN_SERVICE,"/api/hash/analyze":env.HASH_SERVICE};
 if(Object.prototype.hasOwnProperty.call(binds,p)){
   if(req.method!=="POST")return json({error:"Método no permitido"},405);
   const binding=binds[p];if(!binding)return json({error:"Servicio no configurado"},503);
   const headers=new Headers(req.headers);
   // Los Workers originales restringen solicitudes a la interfaz de GitHub Pages.
   // Este valor es una aserción interna fiable únicamente mediante Service Binding.
   headers.set("Origin","https://jmarf37.github.io");
   headers.delete("cookie");
   const proxied=new Request("https://internal"+p,{method:"POST",headers,body:req.body});
   const response=await binding.fetch(proxied);
   const clean=new Headers(response.headers);
   clean.delete("access-control-allow-origin");clean.delete("access-control-allow-credentials");
   clean.set("Cache-Control","no-store");
   return new Response(response.body,{status:response.status,headers:clean});
 }
 if(p.startsWith("/api/"))return json({error:"Ruta no encontrada"},404);
 return env.ASSETS.fetch(req);
}} satisfies ExportedHandler<Env>;
