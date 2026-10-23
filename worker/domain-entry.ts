import { analyzeDomain, validDomain, type DomainEnv } from "./domain";
export default {
 async fetch(request:Request,env:DomainEnv):Promise<Response>{
  const allowed="https://jmarf37.github.io";
  const origin=request.headers.get("Origin")??"";
  const headers={"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store","Access-Control-Allow-Origin":allowed,"Access-Control-Allow-Methods":"POST, OPTIONS","Access-Control-Allow-Headers":"Content-Type","Vary":"Origin"};
  const reply=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers});
  const path=new URL(request.url).pathname;
  if(path==="/health")return reply({ok:true,service:"monkeytools-domain"});
  if(path!=="/api/domain/analyze")return reply({error:"Ruta no encontrada"},404);
  if(origin!==allowed)return reply({error:"Origen no permitido"},403);
  if(request.method==="OPTIONS")return new Response(null,{status:204,headers});
  if(request.method!=="POST")return reply({error:"Método no permitido"},405);
  if(Number(request.headers.get("content-length")??0)>4096)return reply({error:"Petición demasiado grande"},413);
  let body:unknown;
  try{body=await request.json()}catch{return reply({error:"JSON inválido"},400)}
  const data=(body&&typeof body==="object"?body:{}) as {domains?:unknown};
  const raw=typeof data.domains==="string"?data.domains:"";
  if(raw.length>1000)return reply({error:"Entrada demasiado larga"},400);
  const domains=[...new Set(raw.split(/[,\s]+/).filter(Boolean).map(d=>d.toLowerCase()))];
  if(!domains.length||domains.length>5)return reply({error:"Indica entre 1 y 5 dominios"},400);
  const errors=domains.filter(d=>!validDomain(d)).map(d=>"Dominio inválido: "+d);
  const results=await Promise.all(domains.filter(validDomain).map(domain=>analyzeDomain(domain,env)));
  return reply({results,errors});
 }
} satisfies ExportedHandler<DomainEnv>;
