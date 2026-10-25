import {analyzeHash,validHash,type HashEnv} from "./hash";
export default {async fetch(req:Request,env:HashEnv):Promise<Response>{
 const origin=req.headers.get("Origin")??"",allowed=env.ALLOWED_ORIGIN||"https://jmarf37.github.io";
 const headers={"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store","Access-Control-Allow-Origin":allowed,"Access-Control-Allow-Methods":"POST, OPTIONS","Access-Control-Allow-Headers":"Content-Type","Vary":"Origin"};
 const reply=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers});
 const path=new URL(req.url).pathname;
 if(path==="/health")return reply({ok:true,service:"monkeytools-hash"});
 if(path!=="/api/hash/analyze")return reply({error:"Ruta no encontrada"},404);
 if(origin!==allowed)return reply({error:"Origen no permitido"},403);
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers});
 if(req.method!=="POST")return reply({error:"Método no permitido"},405);
 if(Number(req.headers.get("content-length")??0)>4096)return reply({error:"Petición demasiado grande"},413);
 let payload:unknown;try{payload=await req.json()}catch{return reply({error:"JSON inválido"},400)}
 const raw=(payload&&typeof payload==="object"&&(payload as {hashes?:unknown}).hashes)||"";
 if(typeof raw!=="string"||raw.length>1500)return reply({error:"Entrada inválida"},400);
 const hashes=[...new Set(raw.trim().split(/[,\s]+/).filter(Boolean).map(v=>v.toLowerCase()))];
 if(!hashes.length||hashes.length>15)return reply({error:"Indica entre 1 y 15 hashes"},400);
 const errors=hashes.filter(h=>!validHash(h)).map(h=>"Hash inválido: "+h);
 const results=await Promise.all(hashes.filter(validHash).map(h=>analyzeHash(h,env)));
 return reply({results,errors});
}} satisfies ExportedHandler<HashEnv>;
