// Migración de dominio.py: VirusTotal, AlienVault OTX y primer resultado urlscan.io.
export interface DomainEnv { VT_API?:string; ALIEN_API?:string; URLSCAN_API?:string }
type Fields=Record<string,unknown>;
type Provider={data:Fields;error?:string};
const missing=(key:string):Provider=>({data:{},error:"Falta configurar el secreto "+key});
const guarded=async(fn:()=>Promise<Fields>):Promise<Provider>=>{try{return {data:await fn()}}catch(e){return {data:{},error:e instanceof Error?e.message:"Error del proveedor"}}};
async function json(url:string,headers:Record<string,string>):Promise<any>{
 const resp=await fetch(url,{headers,signal:AbortSignal.timeout(12000)});
 if(!resp.ok){if(resp.status===400)throw new Error("HTTP 400: el proveedor rechaza el dominio consultado; comprueba que esté escrito correctamente.");if(resp.status===404)throw new Error("HTTP 404: dominio sin registro en este proveedor.");if(resp.status===401||resp.status===403)throw new Error("HTTP "+resp.status+": acceso API rechazado; revisa la credencial o los permisos.");if(resp.status===429)throw new Error("HTTP 429: límite de consultas de la API alcanzado.");throw new Error("HTTP "+resp.status+": error del proveedor.");}
 return resp.json();
}
function asRelativeTime(timestamp:unknown):string|null {
 if(typeof timestamp!=="number")return null;
 const days=Math.max(0,Math.floor((Date.now()-timestamp*1000)/86400000));
 return days>=365?Math.floor(days/365)+" years":days>=30?Math.floor(days/30)+" months":days+" days";
}
export function validDomain(name:string):boolean{
 if(name.length>253||name.length<4||name.includes("..")||!name.includes("."))return false;
 const labels=name.split(".");
 return labels.every(l=>l.length>=1&&l.length<=63&&/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(l))&& /^[a-z]{2,63}$/i.test(labels.at(-1)??"");
}
async function virusTotal(domain:string,env:DomainEnv):Promise<Provider>{
 if(!env.VT_API)return missing("VT_API");
 return guarded(async()=>{
  const attrs=(await json("https://www.virustotal.com/api/v3/domains/"+encodeURIComponent(domain),{"x-apikey":env.VT_API!})).data?.attributes??{};
  const stats=attrs.last_analysis_stats??{};
  const malicious=Number(stats.malicious??0);
  const total=Object.values(stats).reduce<number>((sum,n)=>sum+Number(n??0),0);
  return {"Community Score":malicious+" / "+total,
   "Security Vendors Flagged":malicious>0?malicious+" security vendors flagged this domain as malicious":"No security vendors flagged this domain as malicious",
   "Domain":domain,"Registrar":attrs.registrar??null,"Creation Date":typeof attrs.creation_date==="number"?new Date(attrs.creation_date*1000).toLocaleString("es-ES",{timeZone:"UTC",year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit"}):null,
   "Categories":attrs.categories??null,"Reputation":attrs.reputation??null,
   "Last Analysis Date":asRelativeTime(attrs.last_analysis_date)};
 });
}
async function alienVault(domain:string,env:DomainEnv):Promise<Provider>{
 if(!env.ALIEN_API)return missing("ALIEN_API");
 return guarded(async()=>{
  const d=await json("https://otx.alienvault.com/api/v1/indicators/domain/"+encodeURIComponent(domain)+"/general",{"X-OTX-API-KEY":env.ALIEN_API!});
  return {"Domain":d.indicator??domain,"Pulse Info Count":d.pulse_info?.count??null,
   "Pulse Info IDs":(d.pulse_info?.pulses??[]).map((p:any)=>p.id).filter(Boolean),
   "Continent Code":d.continent_code??null,"Country Code":d.country_code2??null,
   "Latitude":d.latitude??null,"Longitude":d.longitude??null,"ASN":d.asn??null};
 });
}
async function urlscan(domain:string,env:DomainEnv):Promise<Provider>{
 if(!env.URLSCAN_API)return missing("URLSCAN_API");
 return guarded(async()=>{
  const u=new URL("https://urlscan.io/api/v1/search/");
  // Match both the URL initially submitted and the final page after redirects.
  u.searchParams.set("q","(task.domain:"+domain+" OR page.domain:"+domain+")");
  u.searchParams.set("size","100");
  const d=await json(u.toString(),{"API-Key":env.URLSCAN_API!});
  const belongs=(hostname:unknown):boolean=>{
   const actual=String(hostname??"").toLowerCase().replace(/\\.$/,"");
   return actual===domain||actual.endsWith("."+domain);
  };
  const matches=(Array.isArray(d.results)?d.results:[]).filter((item:any)=>
   belongs(item.task?.domain)||belongs(item.page?.domain)
  );
  const scans=matches.slice(0,1).map((item:any)=>{
    const task=item.task??{},page=item.page??{};
    return {"Time":task.time??null,"Domain":page.domain??null,"Url":page.url??null,
     "Redirected":page.redirected??null,"Server":page.server??null,"IP":page.ip??null,
     "ASN":page.asn??null,"ASN Name":page.asnname??null,"City":page.city??null,
     "Country":page.country??null,"Status":page.status??null,"Report URL":task.reportURL??(typeof task.uuid==="string"?"https://urlscan.io/result/"+encodeURIComponent(task.uuid)+"/":null),
     "Visibility":task.visibility??null,"UUID":task.uuid??null};
  });
  return {"URLScan Results":scans};
 });
}
function serialize(value:unknown):string{
 return value===null||value===undefined?"N/A":typeof value==="object"?JSON.stringify(value,null,2):String(value);
}
function report(domain:string,sources:Record<string,Provider>):string{
 const out=["Análisis Reputacional -> "+domain,""];
 for(const [key,title] of [["virustotal","VIRUSTOTAL"],["alienvault","AlienVault"],["urlscan","URLScan"]] as const){
  out.push("######### "+title+" #########");
  const source=sources[key];
  if(source.error)out.push("ERROR: "+source.error);
  else if(key==="urlscan"){
   const scans=source.data["URLScan Results"];
   if(Array.isArray(scans)&&scans.length){for(const scan of scans)for(const [name,value] of Object.entries(scan as Fields))out.push(name+": "+serialize(value));}
   else out.push("No hay resultados en urlscan.io.");
  }else for(const [name,value] of Object.entries(source.data))out.push(name+": "+serialize(value));
  out.push("");
 }
 const scanResults=sources.urlscan?.data["URLScan Results"];
 const firstScan=Array.isArray(scanResults)?scanResults[0] as Fields|undefined:undefined;
 const scanLink=typeof firstScan?.["Report URL"]==="string"&&String(firstScan["Report URL"]).startsWith("https://urlscan.io/")?String(firstScan["Report URL"]):null;
 out.push("######### Enlaces a los análisis #########");
 out.push("VirusTotal: https://www.virustotal.com/gui/domain/"+encodeURIComponent(domain));
 out.push("AlienVault OTX: https://otx.alienvault.com/indicator/domain/"+encodeURIComponent(domain));
 out.push("URLScan: "+(scanLink??"No disponible (sin resultados coincidentes)"));
 return out.join("\\n");
}
export async function analyzeDomain(domain:string,env:DomainEnv){
 const [vt,otx,scan]=await Promise.all([virusTotal(domain,env),alienVault(domain,env),urlscan(domain,env)]);
 const sources={virustotal:vt,alienvault:otx,urlscan:scan};
 const malicious=Number(String(vt.data["Community Score"]??"0").split("/")[0]);
 const pulses=Number(otx.data["Pulse Info Count"]??0);
 const summary={"Virustotal Community Score":vt.data["Community Score"]??null,
  "Security Vendors Flagged":vt.data["Security Vendors Flagged"]??null,
  "Registrar":vt.data.Registrar??null,"Creation Date":vt.data["Creation Date"]??null,
  "Categories":vt.data.Categories??null,"Reputation":vt.data.Reputation??null,
  "AlienVault Pulses":otx.data["Pulse Info Count"]??null,
  "URLScan Results":Array.isArray(scan.data["URLScan Results"])?scan.data["URLScan Results"].length:null};
 return {domain,summary,flags:{vt_score_red:malicious>0,vt_vendors_red:malicious>0,alien_pulses_red:pulses>0},sources,report_text:report(domain,sources)};
}
