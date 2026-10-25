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
 "Threat Label":d.popular_threat_classification?.suggested_threat_label??null,
 "Popular Threat Names":(d.popular_threat_classification?.popular_threat_name??[]).map((p:any)=>p.value+" ("+p.count+")").join(", ")||"N/A",
 "Popular Threat Categories":(d.popular_threat_classification?.popular_threat_category??[]).map((p:any)=>p.value+" ("+p.count+")").join(", ")||"N/A"};
 });
}
async function otx(hash:string,env:HashEnv):Promise<Source>{
 if(!env.ALIEN_API)return missing("ALIEN_API");
 return wrap(async()=>{const d=await query("https://otx.alienvault.com/api/v1/indicators/file/"+hash+"/general",{"X-OTX-API-KEY":env.ALIEN_API!});
 if(!d)return {"Estado":"Sin resultados"};
 return {"Hash":hash,"Pulse Info Count":d.pulse_info?.count??0,"Pulse Info IDs":(d.pulse_info?.pulses??[]).slice(0,20).map((p:any)=>p.id).filter(Boolean),"Type":d.type??null,"Sections":Array.isArray(d.sections)?d.sections.join(", "):d.sections??null};
 });
}
async function hybrid(hash:string,env:HashEnv,sha256?:string):Promise<Source>{
 if(!env.HYBRID_API)return missing("HYBRID_API");
 return wrap(async()=>{
  const headers={"api-key":env.HYBRID_API!,"User-Agent":"Falcon Sandbox","Accept":"application/json"};
  const keys=[...new Set([hash,...(sha256&&sha256!==hash?[sha256]:[])])];
  const summary=(d:any,source:string):Data=>{
   const latest=Array.isArray(d)?d[0]:d;
   return {"Fuente de consulta":source,"Verdict":latest?.verdict??latest?.verdict_human??null,
   "Threat Score":typeof latest?.threat_score==="number"?latest.threat_score+" / 100":latest?.threat_score??"No disponible mediante API","Threat Level":latest?.threat_level??null,
   "AV Detections":latest?.av_detect??null,"Clasificación Hybrid Analysis":latest?.vx_family??null,
   "File Name":latest?.submit_name??latest?.file_name??null,"Environment":latest?.environment_description??null,
   "Job ID":latest?.job_id??null};
  };
  let noMatches=0;
  for(const key of keys){
   const url=new URL("https://www.hybrid-analysis.com/api/v2/search/hash");url.searchParams.set("hash",key);
   const response=await query(url.toString(),headers);
   const list=Array.isArray(response)?response:Array.isArray(response?.result)?response.result:Array.isArray(response?.data)?response.data:response&&(response.job_id||response.sha256)?[response]:[];
   if(list.length)return {"Coincidencias":list.length,"Hash consultado":key,...summary(list[0],"Search API")};
   noMatches++;
  }
  // Overview can expose static/AV intelligence even when there is no sandbox report.
  const sha=keys.find(k=>k.length===64);
  if(sha){
   const overview=await query("https://www.hybrid-analysis.com/api/v2/overview/"+sha,headers);
   if(overview&&typeof overview==="object"){
    const data=overview.result??overview;
    if(data&&typeof data==="object"&&!Array.isArray(data)){
     const obj=(x:any)=>x&&typeof x==="object"&&!Array.isArray(x)?x:{};
     const metadata=obj(data.file_metadata),info=obj(data.file_info),scan=obj(data.scanners),scannersV2=obj(data.scanners_v2),multi=obj(data.last_multi_scan),intel=obj(data.threat_intelligence);
     const first=(...values:any[])=>values.find(v=>v!==null&&v!==undefined&&v!=="")??null;
     const asDate=(v:any)=>{if(v==null||v==="")return null;const date=typeof v==="number"?new Date(v>1e12?v:v*1000):typeof v==="string"?new Date(v):null;return date&&!Number.isNaN(date.getTime())?date.toLocaleString("es-ES",{timeZone:"UTC",day:"2-digit",month:"2-digit",year:"numeric",hour:"2-digit",minute:"2-digit",second:"2-digit"})+" UTC":typeof v==="string"?v:null;};
     const score=first(data.threat_score,data.threatscore,data.score,data.malware_score,intel.threat_score);
     const scanEntries=Object.entries({...scan,...scannersV2}).filter(([,value])=>value&&typeof value==="object").map(([name,value])=>({name,...obj(value)}));
     const multiEntries=Object.entries(multi).filter(([,value])=>value&&typeof value==="object").map(([name,value])=>({name,...obj(value)}));
     const avEngines=[...scanEntries,...multiEntries];
     const metaDefender=avEngines.find(x=>/metadefender/i.test(x.name));
     const avCount=first(data.av_detect,data.av_detections,data.av_detections_count,metaDefender?.positives,metaDefender?.malicious);
     const avTotal=first(metaDefender?.total,metaDefender?.total_engines);
     const crowdstrike=avEngines.find(x=>/crowdstrike/i.test(x.name));
     const indicators=Array.isArray(data.indicators)?data.indicators:[];
     const malicious=indicators.filter((x:any)=>/malicious/i.test(String(x?.type??x?.classification??x?.severity??""))).length;
     const suspicious=indicators.filter((x:any)=>/suspicious/i.test(String(x?.type??x?.classification??x?.severity??""))).length;
     const informative=indicators.filter((x:any)=>/informative|info/i.test(String(x?.type??x?.classification??x?.severity??""))).length;
     const result:Data={"Estado":"Información del archivo disponible en Overview",
      "SHA-256":first(data.sha256,metadata.sha256),
      "SHA-1":first(data.sha1,metadata.sha1),
      "MD5":first(data.md5,metadata.md5),
      "File Type":first(data.type,data.type_short,metadata.type),
      "File Size":first(data.size,metadata.size,info.size),
      "Clasificación Hybrid Analysis":first(data.vx_family,data.malware_family),
      "Threat Score":typeof score==="number"?score+" / 100":score??"No disponible mediante API","Threat Level":first(data.threat_level,data.threat_level_human),
      "Verdict":first(data.verdict,data.verdict_human),
      "AV Detections":avCount!=null&&avTotal!=null?String(avCount)+" / "+String(avTotal):avCount&&typeof avCount==="object"?first(avCount.count,avCount.malicious):avCount,
      "CrowdStrike Falcon":first(crowdstrike?.verdict,crowdstrike?.status,crowdstrike?.result),
      "First Seen":asDate(first(data.first_seen,info.first_seen,data.first_seen_at)),
      "Last Analyzed":asDate(first(data.last_analysis,info.last_analyzed,data.last_analyzed_at)),
      "Tags":Array.isArray(data.tags)?data.tags.join(", ")||null:data.tags||null};
     if(result["First Seen"]==null)delete result["First Seen"];
     if(result["Last Analyzed"]==null)delete result["Last Analyzed"];
     if(Array.isArray(data.tags)){const tags=data.tags.map((t:any)=>String(t)).filter(Boolean);result["Tags"]=tags.length?tags.slice(0,15).join(", ")+(tags.length>15?" (15 de "+tags.length+" etiquetas)":""):null;}
     else if(typeof data.tags==="string"&&data.tags.trim()){const tags=data.tags.split(",").map((t:string)=>t.trim()).filter(Boolean);result["Tags"]=tags.slice(0,15).join(", ")+(tags.length>15?" (15 de "+tags.length+" etiquetas)":"");}
     if(indicators.length){result["Indicators Total"]=indicators.length;result["Malicious Indicators"]=malicious;result["Suspicious Indicators"]=suspicious;result["Informative Indicators"]=informative;}
     const resultEntries=avEngines.flatMap(x=>Array.isArray(x.anti_virus_results)?x.anti_virus_results:[]);
     if(resultEntries.length)result["AV detections detail"]=resultEntries.filter((x:any)=>/malicious|infected|detected/i.test(String(x?.result??x?.status??x?.verdict??""))).slice(0,15).map((x:any)=>[x?.name??x?.engine??"AV",x?.result??x?.verdict??"Detected"].join(": ")).join("; ")||"Ninguna detección detallada";
     const scanInfo=avEngines.filter(x=>x.name&&first(x.positives,x.total,x.status,x.verdict)!==null).map(x=>x.name+": "+[x.positives!==undefined?x.positives+" detecciones":null,x.total!==undefined?"/ "+x.total+" motores":null,x.status??null].filter(Boolean).join(" ")).slice(0,8);
     if(scanInfo.length)result["Escáneres disponibles"]=scanInfo.join("; ");
     const avResults=first(data.antivirus,data.av_results,data.av_scanners,data.multi_scan_result);
     if(Array.isArray(avResults))result["Antivirus Results"]=avResults.slice(0,20).map((x:any)=>[x?.name??x?.engine??"AV",x?.result??x?.verdict??x?.detection??"N/A"].join(": ")).join("; ");
     // El inventario de claves se usó para depuración; no forma parte del informe final.
     return result;
    }
   }
  }
  return {"Estado":"No existen resultados accesibles con esta clave API ("+noMatches+" consultas Search y una comprobación Overview)"};
 });
}
async function bazaar(hash:string,env:HashEnv,sha256?:string):Promise<Source>{
 if(!env.MALWAREBAZAAR_API)return missing("MALWAREBAZAAR_API");
 return wrap(async()=>{
  const keys=[hash,...(sha256&&sha256!==hash?[sha256]:[])];
  for(const key of keys){
   const body=new URLSearchParams({query:"get_info",hash:key});
   const d=await query("https://mb-api.abuse.ch/api/v1/",{"Auth-Key":env.MALWAREBAZAAR_API!,"Content-Type":"application/x-www-form-urlencoded"},{method:"POST",body:body.toString()});
   if(!d)throw new Error("MalwareBazaar no devolvió datos");
   if(d.query_status==="hash_not_found")continue;
   if(d.query_status==="illegal_hash")throw new Error("MalwareBazaar rechazó el formato de hash");
   if(d.query_status!=="ok")throw new Error("MalwareBazaar: "+String(d.query_status??"error").slice(0,100));
   const a=d.data?.[0]??{};
   return {"SHA-256":a.sha256_hash??null,"SHA-1":a.sha1_hash??null,"MD5":a.md5_hash??null,"File Name":a.file_name??null,"File Type":a.file_type??null,"File Size":a.file_size??null,"Signature":a.signature??null,"First Seen":a.first_seen??null,"Last Seen":a.last_seen??null,"Tags":Array.isArray(a.tags)?a.tags.join(", "):a.tags??null,"Reporter":a.reporter??null};
  }
  return {"Estado":"Hash no registrado en MalwareBazaar"};
 });
}
function fmt(value:unknown):string{return value==null?"N/A":typeof value==="object"?JSON.stringify(value,null,2):String(value)}
export async function analyzeHash(hash:string,env:HashEnv){
 const [v,o]=await Promise.all([vt(hash,env),otx(hash,env)]);
 const sha256=typeof v.data["SHA-256"]==="string"&&validHash(v.data["SHA-256"] as string)?v.data["SHA-256"] as string:undefined;
 const [h,b]=await Promise.all([hybrid(hash,env,sha256),bazaar(hash,env,sha256)]);
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
