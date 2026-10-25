export {};
type Result={hash:string;type:string;report_text:string;sources:Record<string,{data:Record<string,unknown>;error?:string}>};
const ENDPOINT="https://monkeytoolv2-hash.jesusmartinezferrer.workers.dev";
const form=document.querySelector<HTMLFormElement>("#hash-form");
const status=document.querySelector<HTMLElement>("#hash-status");
const output=document.querySelector<HTMLElement>("#hash-results");
const submit=form?.querySelector<HTMLButtonElement>("button[type=submit]");
const mk=<K extends keyof HTMLElementTagNameMap>(tag:K,text?:string,cls?:string)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e};
const notFound=(r:Result):boolean=>{
 const sources=r.sources;
 if(!sources||typeof sources!=="object")return false;
 const v=sources.virustotal,o=sources.alienvault,h=sources.hybridanalysis,b=sources.malwarebazaar;
 if(!v||!o||!h||!b||[v,o,h,b].some(x=>x.error))return false;
 const state=(x:{data:Record<string,unknown>})=>String(x.data?.Estado??"");
 const otxEmpty=state(o)==="Sin resultados" || (o.data?.["Pulse Info Count"]!==undefined&&Number(o.data["Pulse Info Count"])===0);
 return state(v)==="Sin resultados"&&otxEmpty&&/^(No existen resultados accesibles|No hay análisis accesibles)/.test(state(h))&&/^(Hash no registrado en MalwareBazaar|Sin resultados)$/.test(state(b));
};
function report(r:Result):string{
 if(!notFound(r))return r.report_text;
 const links=r.report_text.includes("######### Enlaces a los análisis #########")?r.report_text.slice(r.report_text.indexOf("######### Enlaces a los análisis #########")):"";
 return ["Análisis Reputacional -> "+r.hash,"","Tipo: "+r.type,"","Hash no detectado en las fuentes abiertas de análisis reputacional de VirusTotal, AlienVault OTX, Hybrid Analysis y MalwareBazaar.","",links].filter((line,i,a)=>i<a.length-1||line!=="").join("\n");
}
function render(r:Result){
 const card=mk("article",undefined,"hash-card");
 const displayedReport=report(r);
 card.append(mk("h2","Hash analizado: "+r.hash),mk("p","Algoritmo: "+r.type));
 const copy=mk("button","Copiar informe","hash-copy");copy.type="button";
 copy.addEventListener("click",async()=>{try{await navigator.clipboard.writeText(displayedReport);copy.textContent="¡Copiado!";}catch{copy.textContent="Error al copiar";}});
 card.append(copy,mk("pre",displayedReport,"hash-report"));return card;
}
form?.addEventListener("submit",async e=>{
 e.preventDefault();if(!status||!output||!submit)return;
 const raw=(document.querySelector<HTMLTextAreaElement>("#hashes")?.value??"").trim();
 const hashes=[...new Set(raw.split(/[,\s]+/).filter(Boolean))];
 if(!hashes.length||hashes.length>15){status.textContent="Indica entre 1 y 15 hashes MD5, SHA-1 o SHA-256.";return;}
 submit.disabled=true;output.replaceChildren();let completed=0,errors=0;
 try{
  for(let i=0;i<hashes.length;i+=3){
   status.textContent="Consultando hashes "+(i+1)+"–"+Math.min(i+3,hashes.length)+" de "+hashes.length+"...";
   const res=await fetch(ENDPOINT+"/api/hash/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({hashes:hashes.slice(i,i+3).join(",")})});
   const data=await res.json();if(!res.ok)throw new Error(data.error??"HTTP "+res.status);
   for(const error of (data.errors??[])){output.append(mk("p",String(error),"hash-error"));errors++;}
   for(const result of (data.results??[]) as Result[]){output.append(render(result));completed++;}
  }
  status.textContent=completed+" hashes analizados. "+errors+" entradas inválidas.";
 }catch(error){status.textContent="Completados "+completed+" hashes. "+(error instanceof Error?error.message:"Error en el Worker");}
 finally{submit.disabled=false;}
});
