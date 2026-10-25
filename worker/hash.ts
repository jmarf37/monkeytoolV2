export interface HashEnv { VT_API?:string; ALIEN_API?:string; HYBRID_API?:string; MALWAREBAZAAR_API?:string; ALLOWED_ORIGIN?:string }
type Data=Record<string,unknown>;
type Source={data:Data;error?:string};
const missing=(name:string):Source=>({data:{},error:"Falta configurar el secreto "+name});
const wrap=async(fn:()=>Promise<Data>):Promise<Source>=>{try{return {data:await fn()}}catch(e){return {data:{},error:e instanceof Error?e.message:"Error de consulta"}}};
export const validHash=(v:string)=>/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(v);
const kind=(v:string)=>v.length===32?"MD5":v.length===40?"SHA-1":"SHA-256";
const stamp=(v:unknown)=>typeof v==="number"?new Date(v*1000).toLocaleString("es-ES",{timeZone:"UTC",day:"2-digit",month:"2-digit",year:"numeric",hour:"2-digit",minute:"2-digit"} )+" UTC":null;
async function query(url:string,headers:Record<string,string>={},init:RequestInit={}):Promise<any>{
 const res=await fetch(url,{...init,headers:{...headers,...init.headers},signal:AbortSignal.timeout(14000)});
 if(!res.ok){if(res.status===404)return null;throw new Error("HTTP "+res.status+(res.status===429?" (límite de peticiones)":res.status===401||res.status===403?" (autenticación/permisos)":""))}
 return res.json();
}
async function vt(hash:string,env:HashEnv):Promise<Source>{
 if(!env.VT_API)return missing("VT_API");
 return wrap(async()=>{const response=await query("https://www.virustotal.com/api/v3/files/"+hash,{"x-apikey":env.VT_API!});
 if(!response)return {"Estado":"Sin resultados"};
 const d=response.data?.attributes??{},st=d.last_analysis_stats??{};
 return {"Community Score":Number(st.malicious??0)+" / "+Object.values(st).reduce<number>((acc,v)=>acc+Number(v??0),0),
 "Malicious":st.malicious??0,"Suspicious":st.suspicious??0,"Undetected":st.undetected??0,
 "File Name":d.meaningful_name??d.names?.[0]??null,"File Type":d.type_description??null,"Size (bytes)":d.size??null,
 "MD5":d.md5??null,"SHA-1":d.sha1??null,"SHA-256":d.sha256??null,
 "Reputation":d.reputation??null,"First Submission":stamp(d.first_submission_date),"Last Analysis":stamp(d.last_analysis_date),
 "Popular Threat Classification":d.popular_threat_classification??null};
 });
}
async function otx(hash:string,env:HashEnv):Promise<Source>{
 if(!env.ALIEN_API)return missing("ALIEN_API");
 return wrap(async()=>{const d=await query("https://otx.alienvault.com/api/v1/indicators/file/"+hash+"/general",{"X-OTX-API-KEY":env.ALIEN_API!});
 if(!d)return {"Estado":"Sin resultados"};
 return {"Hash":hash,"Pulse Info Count":d.pulse_info?.count??0,"Pulse Info IDs":(d.pulse_info?.pulses??[]).slice(0,20).map((p:any)=>p.id).filter(Boolean),"Type":d.type??null,"Sections":d.sections??null};
 });
}
async function hybrid(hash:string,env:HashEnv):Promise<Source>{
 if(!env.HYBRID_API)return missing("HYBRID_API");
 return wrap(async()=>{const url=new URL("https://www.hybrid-analysis.com/api/v2/search/hash");url.searchParams.set("hash",hash);
 const d=await query(url.toString(),{"api-key":env.HYBRID_API!,"User-Agent":"Falcon Sandbox","accept":"application/json"});
 const list=Array.isArray(d)?d:Array.isArray(d?.result)?d.result:[];
 if(!list.length)return {"Estado":"Sin resultados"};
 const latest=list[0];return {"Matches":list.length,"Verdict":latest.verdict??null,"Threat Score":latest.threat_score??null,"Threat Level":latest.threat_level??null,"AV Detections":latest.av_detect??null,"Malware Family":latest.vx_family??null,"File Name":latest.submit_name??null,"Environment":latest.environment_description??null,"Job ID":latest.job_id??null};
 });
}
async function bazaar(hash:string,env:HashEnv):Promise<Source>{
 if(!env.MALWAREBAZAAR_API)return missing("MALWAREBAZAAR_API");
 return wrap(async()=>{const body=new URLSearchParams({query:"get_info",hash});
 const d=await query("https://mb-api.abuse.ch/api/v1/",{"Auth-Key":env.MALWAREBAZAAR_API!,"Content-Type":"application/x-www-form-urlencoded"},{method:"POST",body:body.toString()});
 if(!d||d.query_status==="hash_not_found")return {"Estado":"Sin resultados"};
 if(d.query_status!=="ok")throw new Error("MalwareBazaar: "+String(d.query_status??"error").slice(0,100));
 const a=d.data?.[0]??{};
 return {"SHA-256":a.sha256_hash??null,"SHA-1":a.sha1_hash??null,"MD5":a.md5_hash??null,"File Name":a.file_name??null,"File Type":a.file_type??null,"File Size":a.file_size??null,"Signature":a.signature??null,"First Seen":a.first_seen??null,"Last Seen":a.last_seen??null,"Tags":a.tags??[],"Reporter":a.reporter??null};
 });
}
function fmt(value:unknown):string{return value==null?"N/A":typeof value==="object"?JSON.stringify(value,null,2):String(value)}
export async function analyzeHash(hash:string,env:HashEnv){
 const [v,o,h,b]=await Promise.all([vt(hash,env),otx(hash,env),hybrid(hash,env),bazaar(hash,env)]);
 const sources={virustotal:v,alienvault:o,hybridanalysis:h,malwarebazaar:b};
 const lines=["Análisis Reputacional -> "+hash,"","Tipo: "+kind(hash),""];
 for(const [key,label] of [["virustotal","VIRUSTOTAL"],["alienvault","AlienVault OTX"],["hybridanalysis","Hybrid Analysis"],["malwarebazaar","MalwareBazaar"]] as const){
 lines.push("######### "+label+" #########");
 const src=sources[key];if(src.error)lines.push("ERROR: "+src.error);else for(const [field,value] of Object.entries(src.data))lines.push(field+": "+fmt(value));lines.push("");
 }
 lines.push("######### Enlaces a los análisis #########",
 "VirusTotal: https://www.virustotal.com/gui/file/"+hash,
 "AlienVault OTX: https://otx.alienvault.com/indicator/file/"+hash,
 "Hybrid Analysis: https://www.hybrid-analysis.com/search?query="+hash,
 "MalwareBazaar: https://bazaar.abuse.ch/browse.php?search="+hash);
 return {hash,type:kind(hash),sources,report_text:lines.join("\n")};
}
