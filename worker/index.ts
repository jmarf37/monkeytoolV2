export interface Env { VT_API?:string; ABUSE_API?:string; ALIEN_API?:string; IPQ_API?:string; BLACKLIST_URL?:string; ALLOWED_ORIGIN?:string; }
type Fields=Record<string,unknown>;
type Source={data:Fields;error?:string};
const urls={vt:"https://www.virustotal.com/api/v3/ip_addresses/",abuse:"https://api.abuseipdb.com/api/v2/check",otx:"https://otx.alienvault.com/api/v1/indicators/IPv4/",ipqs:"https://www.ipqualityscore.com/api/json/ip/",rdap:"https://rdap.org/ip/"};
const DEFAULT_BLACKLIST="https://dist.s2grupo.es/blacklist/ieoel2ganfaxpu81q2k0u5d1u0jzh3m6ogqf8xfliwpxwnocve2famnuscjf6cb0i/IP_list.txt";
function isIP(value:string):boolean {
 if (!value || value.length>45 || /[^0-9a-fA-F:.]/.test(value)) return false;
 if (value.includes(":")) {
   if (!/^[0-9a-fA-F:]+$/.test(value) || value.split("::").length>2) return false;
   const split=value.split("::"); const chunks=split.flatMap(s=>s?s.split(":"):[]);
   if(chunks.some(s=>!s||s.length>4))return false;
   return split.length===2 ? chunks.length<8 : chunks.length===8;
 }
 const p=value.split(".");return p.length===4&&p.every(x=>/^\d{1,3}$/.test(x)&&Number(x)<=255&&!(/^0\d/.test(x)));
}
async function getJSON(url:string,headers:Record<string,string>={}):Promise<any>{
 const res=await fetch(url,{headers,signal:AbortSignal.timeout(12000)});
 if(!res.ok)throw new Error("HTTP "+res.status);
 return res.json();
}
const missing=(k:string):Source=>({data:{},error:"Falta configurar el secreto "+k});
async function guarded(cb:()=>Promise<Fields>):Promise<Source>{try{return {data:await cb()}}catch(e){return {data:{},error:e instanceof Error?e.message:"Error en el proveedor"}}}
const age=(stamp:unknown)=>{if(typeof stamp!=="number")return null;const days=Math.max(0,Math.floor((Date.now()-stamp*1000)/86400000));return days>=365?Math.floor(days/365)+" years":days>=30?Math.floor(days/30)+" months":days+" days"};
async function vt(ip:string,env:Env):Promise<Source>{
 if(!env.VT_API)return missing("VT_API");
 return guarded(async()=>{const a=(await getJSON(urls.vt+encodeURIComponent(ip),{"x-apikey":env.VT_API!})).data?.attributes??{};const stats=a.last_analysis_stats??{};const malicious=Number(stats.malicious??0);return {
 "Community Score":malicious+" / "+Object.values(stats).reduce<number>((s,v)=>s+Number(v||0),0),
 "Security Vendors Flagged":malicious?malicious+" security vendors flagged this IP address as malicious":"No security vendors flagged this IP address as malicious",
 "IP":ip,"Network":a.network,"ISP": "AS "+(a.asn??"N/A")+" ("+(a.as_owner??"N/A")+")","Country":a.country,"Region":a.regional_internet_registry,"Continent":a.continent,"Jarm hash":a.jarm,"Last Analysis Date":age(a.last_analysis_date),"category":a.category,"Reputation":a.reputation};});
}
async function abuse(ip:string,env:Env):Promise<Source>{
 if(!env.ABUSE_API)return missing("ABUSE_API");
 return guarded(async()=>{const u=new URL(urls.abuse);u.searchParams.set("ipAddress",ip);u.searchParams.set("maxAgeInDays","90");const d=(await getJSON(u.toString(),{Accept:"application/json",Key:env.ABUSE_API!})).data??{};return {"Whitelist":ip+(d.isWhitelisted?" is whitelisted.":" is not whitelisted."),"Reports":"This IP ("+ip+") was reported "+(d.totalReports??"N/A")+" times.","Confidence of abuse":d.abuseConfidenceScore,"ISP":d.isp,"Usage Type":d.usageType,"Country":d.countryCode,"Hostnames":(d.hostnames??[]).join(", "),"Domain Name":d.domain,"Last Reported":d.lastReportedAt,"TOR":d.isTor};});
}
async function otx(ip:string,env:Env):Promise<Source>{
 if(ip.includes(":"))return {data:{},error:"La integración OTX original está configurada para IPv4"};
 if(!env.ALIEN_API)return missing("ALIEN_API");
 return guarded(async()=>{const d=await getJSON(urls.otx+encodeURIComponent(ip)+"/general",{"X-OTX-API-KEY":env.ALIEN_API!});return {"IP":d.indicator,"Pulse Info Count":d.pulse_info?.count,"Pulse Info IDs":(d.pulse_info?.pulses??[]).map((p:any)=>p.id).filter(Boolean),"Continent Code":d.continent_code,"Country Code":d.country_code2,"Latitude":d.latitude,"Longitude":d.longitude,"ASN":d.asn};});
}
async function ipqs(ip:string,env:Env):Promise<Source>{
 if(!env.IPQ_API)return missing("IPQ_API");
 return guarded(async()=>{const key=env.IPQ_API!.trim();if(!key)throw new Error("El secreto IPQ_API está vacío");const u=new URL(urls.ipqs+encodeURIComponent(key)+"/"+encodeURIComponent(ip));u.searchParams.set("strictness","1");u.searchParams.set("fast","true");u.searchParams.set("allow_public_access_points","true");u.searchParams.set("lighter_penalties","true");const d=await getJSON(u.toString());if(d.success===false)throw new Error("IPQS: "+String(d.message??"consulta rechazada").slice(0,200)+(typeof d.request_id==="string"?" [request_id: "+d.request_id.replace(/[^a-zA-Z0-9_-]/g,"").slice(0,64)+"]":""));return {"Fraud Score":d.fraud_score,"Proxy":d.proxy,"TOR":d.tor,"Recent Abuse":d.recent_abuse,"ISP":d.ISP,"Organization":d.organization??d.Organization,"ASN":d.ASN,"Country Code":d.country_code,"City":d.city,"Region":d.region};});
}
function contact(e:any){const fields=e.vcardArray?.[1]??[];const vals=(name:string)=>fields.filter((f:any)=>f[0]===name).map((f:any)=>Array.isArray(f[3])?f[3].filter(Boolean).join(" "):String(f[3]));return {handle:e.handle,roles:e.roles??[],name:vals("fn")[0],org:vals("org")[0],emails:vals("email"),phones:vals("tel"),addresses:vals("adr")}}
async function rdap(ip:string):Promise<Source>{
 return guarded(async()=>{const rdapHosts=[
 ["ARIN","https://rdap.arin.net/registry/ip/"],
 ["RIPE","https://rdap.db.ripe.net/ip/"],
 ["APNIC","https://rdap.apnic.net/ip/"],
 ["LACNIC","https://rdap.lacnic.net/rdap/ip/"],
 ["AFRINIC","https://rdap.afrinic.net/rdap/ip/"]
] as const;
let d:any=null;let rir="";const failures:string[]=[];
for(const [name,base] of rdapHosts){try{d=await getJSON(base+encodeURIComponent(ip),{Accept:"application/rdap+json, application/json"});rir=name;break;}catch(e){failures.push(name+": "+(e instanceof Error?e.message:"Error"));}}
if(!d)throw new Error("Ningún registro RDAP respondió: "+failures.join(" | "));
const entities=(d.entities??[]).map(contact);const owner=entities.find((e:any)=>e.roles.some((r:string)=>["registrant","administrative"].includes(r)))?.org??d.name??d.handle;const cidrs=(d.cidr0_cidrs??[]).map((c:any)=>c.v4prefix?c.v4prefix+"/"+c.length:c.v6prefix+"/"+c.length).join(", ");
 return {"RIR":rir,"Handle":d.handle,"Name":d.name,"IP Version":d.ipVersion,"Country":d.country,"Start Address":d.startAddress,"End Address":d.endAddress,"CIDR":cidrs||null,"Owner (heuristic)":owner,"Events":(d.events??[]).map((e:any)=>e.eventAction+": "+e.eventDate),"Reference":d.links?.find((x:any)=>x.rel==="self")?.href,"RDAP Contacts":{abuse:entities.filter((e:any)=>e.roles.includes("abuse")),technical:entities.filter((e:any)=>e.roles.includes("technical")),administrative:entities.filter((e:any)=>e.roles.includes("administrative")),registrant:entities.filter((e:any)=>e.roles.includes("registrant"))}};});
}
async function blacklist(ip:string,env:Env):Promise<Source>{
 return guarded(async()=>{const url=env.BLACKLIST_URL||DEFAULT_BLACKLIST;const res=await fetch(url,{signal:AbortSignal.timeout(12000)});if(!res.ok)throw new Error("HTTP "+res.status);const content=await res.text();if(content.length>8_000_000)throw new Error("Lista demasiado grande para consulta directa");const found=content.split(/\r?\n/).some(line=>line.split("#")[0].split(/[\s,;]+/).includes(ip));return {"Blacklist (S2Grupo)":found?"Sí":"No","Blacklist Fuente":"S2Grupo IP_list.txt","Blacklist Consultada":new Date().toISOString()};});
}
function format(ip:string,sources:Record<string,Source>):string{
 const order:[string,string][]=[["virustotal","Virustotal"],["abuseipdb","AbuseIPDB"],["alienvault","AlienVault OTX"],["ipqualityscore","IPQualityScore"],["rdap","Registration Data Access Protocol (RDAP)"],["blacklist","Blacklist (S2Grupo)"]];
 const data=(k:string,field:string)=>sources[k].error?"ERROR: "+sources[k].error:String(sources[k].data[field]??"N/A");
 const lines=["Análisis Reputacional ------> "+ip,"","-".repeat(88),"Resultado:", "Virustotal --> "+data("virustotal","Community Score")+" VT","AbuseIPDB --> "+data("abuseipdb","Reports")+" | Confidence "+data("abuseipdb","Confidence of abuse"),"AlienVault OTX --> "+data("alienvault","Pulse Info Count"),"IPQualityScore --> Fraud Score "+data("ipqualityscore","Fraud Score")+" | TOR "+data("ipqualityscore","TOR"),"Blacklist S2Grupo (MISP) --> "+data("blacklist","Blacklist (S2Grupo)"),"-".repeat(88)];
 for(const [key,label] of order){lines.push("","######### "+label+" #########");const x=sources[key];if(x.error)lines.push("ERROR: "+x.error);else for(const [k,v] of Object.entries(x.data))lines.push(k+": "+(typeof v==="object"&&v!==null?JSON.stringify(v,null,2):String(v??"N/A")));}
 return lines.join("\n");
}
async function analyze(ip:string,env:Env){
 const [v,a,o,q,r,b]=await Promise.all([vt(ip,env),abuse(ip,env),otx(ip,env),ipqs(ip,env),rdap(ip),blacklist(ip,env)]);
 const sources={virustotal:v,abuseipdb:a,alienvault:o,ipqualityscore:q,rdap:r,blacklist:b};
 const score=Number(String(v.data["Community Score"]??"0").split("/")[0]);const rep=Number(String(a.data.Reports??"").match(/reported (\d+) times/)?.[1]??0);
 const summary={"Virustotal Community Score":v.data["Community Score"]??null,"Security Vendors Flagged":v.data["Security Vendors Flagged"]??null,"AbuseIPDB Reports":a.data.Reports??null,"AbuseIPDB Confidence":a.data["Confidence of abuse"]??null,"AlienVault Pulses":o.data["Pulse Info Count"]??null,"IPQS TOR":q.data.TOR??null,"IPQS Fraud Score":q.data["Fraud Score"]??null,"Blacklist S2Grupo":b.data["Blacklist (S2Grupo)"]??null,"RDAP Owner (heuristic)":r.data["Owner (heuristic)"]??null,"Country":a.data.Country??null};
 const flags={vt_score_red:score>0,vt_vendors_red:score>0,abuse_reports_red:rep>10,alien_pulses_red:Number(o.data["Pulse Info Count"]??0)>0,ipqs_tor_red:q.data.TOR===true};
 return {ip,summary,flags,sources,report_text:format(ip,sources)};
}
export default {async fetch(req:Request,env:Env):Promise<Response>{
 const origin=req.headers.get("Origin")??"";const allowed=env.ALLOWED_ORIGIN||"https://jmarf37.github.io";
 const headers={"Access-Control-Allow-Origin":allowed,"Vary":"Origin","Access-Control-Allow-Methods":"POST, OPTIONS","Access-Control-Allow-Headers":"Content-Type","Cache-Control":"no-store","Content-Type":"application/json; charset=utf-8"};
 const response=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers});
 const u=new URL(req.url);if(u.pathname==="/health")return response({ok:true,service:"monkeytools-ip"});
 if(u.pathname!=="/api/ip/analyze")return response({error:"Ruta no encontrada"},404);
 if(origin!==allowed)return response({error:"Origen no permitido"},403);
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers});
 if(req.method!=="POST")return response({error:"Método no permitido"},405);
 if(Number(req.headers.get("content-length")??0)>4096)return response({error:"Petición demasiado grande"},413);
 let body:any;try{body=await req.json()}catch{return response({error:"JSON inválido"},400)}
 const input:string=typeof body.ips==="string"?body.ips:"";if(input.length>1000)return response({error:"Entrada demasiado larga"},400);
 const candidates=[...new Set(input.split(/[,\s]+/).filter(Boolean))];if(!candidates.length||candidates.length>5)return response({error:"Indica entre 1 y 5 IP por consulta"},400);
 const errors=candidates.filter(s=>!isIP(s)).map(s=>"IP inválida: "+s);
 const valid=candidates.filter(isIP);const results=[];for(const ip of valid)results.push(await analyze(ip,env));
 return response({results,errors});
}} satisfies ExportedHandler<Env>;
