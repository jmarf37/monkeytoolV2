export {};
type Result={ip:string;summary:Record<string,unknown>;flags:Record<string,boolean>;report_text:string;sources:Record<string,{data:Record<string,unknown>;error?:string}>};
const form=document.querySelector<HTMLFormElement>("#ip-form");
const output=document.querySelector<HTMLElement>("#results");
const statusElement=document.querySelector<HTMLElement>("#ip-status");
const endpointInput=document.querySelector<HTMLInputElement>("#api-endpoint");
const isPortal=location.hostname!=="jmarf37.github.io" && (location.hostname==="monkeytools.es"||location.hostname.endsWith(".workers.dev"));
const DEFAULT_WORKER_URL=isPortal?location.origin:"https://monkeytoolv2.jesusmartinezferrer.workers.dev";
if(endpointInput && !endpointInput.value) endpointInput.value=DEFAULT_WORKER_URL;
const submit=form?.querySelector<HTMLButtonElement>("button[type=submit]");
const labels=["Virustotal Community Score","Security Vendors Flagged","AbuseIPDB Reports","AbuseIPDB Confidence","AlienVault Pulses","IPQS TOR","IPQS Fraud Score","Blacklist S2Grupo","RDAP Owner (heuristic)","Country"];
const flagFor:Record<string,string>={"Virustotal Community Score":"vt_score_red","Security Vendors Flagged":"vt_vendors_red","AbuseIPDB Reports":"abuse_reports_red","AlienVault Pulses":"alien_pulses_red","IPQS TOR":"ipqs_tor_red"};
function el<K extends keyof HTMLElementTagNameMap>(tag:K,cls?:string,text?:string){const node=document.createElement(tag);if(cls)node.className=cls;if(text!==undefined)node.textContent=text;return node;}
function readable(v:unknown):string{return v===null||v===undefined?"N/A":typeof v==="object"?JSON.stringify(v):String(v)}
function render(result:Result){
 const card=el("article","report-card"),head=el("h2","","IP Analizada: "+result.ip);card.append(head,el("h3","","Resumen análisis"));
 const table=el("table","summary-table"),tbody=el("tbody");
 for(const name of labels){const tr=el("tr"),th=el("th","",name),td=el("td",result.flags[flagFor[name]]?"danger":"",readable(result.summary[name]));tr.append(th,td);tbody.append(tr)}
 table.append(tbody);card.append(table);
 const details=el("details","detail-report"),summary=el("summary","","Ver detalles completos"),copy=el("button","copy-btn","Copiar informe");
 copy.type="button";copy.addEventListener("click",async(e)=>{e.preventDefault();e.stopPropagation();try{await navigator.clipboard.writeText(result.report_text);copy.textContent="¡Copiado!";}catch{copy.textContent="No se pudo copiar";}});
 summary.append(copy);details.append(summary,el("pre","report-text",result.report_text));card.append(details);
 return card;
}
form?.addEventListener("submit",async(event)=>{
 event.preventDefault();if(!output||!statusElement||!submit)return;
 const input=(form.querySelector<HTMLTextAreaElement>("#ips")?.value??"").trim();
 const endpoint=endpointInput?.value.trim().replace(/\/+$/,"")??"";
 if(!endpoint){statusElement.textContent="Debes indicar la URL de tu Cloudflare Worker cuando esté desplegado.";return;}
 if(!/^https:\/\/[a-z0-9.-]+$/i.test(endpoint)){statusElement.textContent="La URL debe ser HTTPS y contener solo el dominio del Worker.";return;}
 const indicators=[...new Set(input.split(/[,\s]+/).filter(Boolean))];
 if(!indicators.length||indicators.length>15){statusElement.textContent="Indica entre 1 y 15 IP.";return;}
 submit.disabled=true;statusElement.textContent="Preparando "+indicators.length+" IP...";output.replaceChildren();
 let done=0,invalid=0;
 try{
  for(let i=0;i<indicators.length;i+=3){
   const part=indicators.slice(i,i+3);
   statusElement.textContent="Analizando IP "+(i+1)+"–"+Math.min(i+3,indicators.length)+" de "+indicators.length+"...";
   const res=await fetch(endpoint+"/api/ip/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ips:part.join(",")})});
   const body=await res.json();if(!res.ok)throw new Error(body.error??"HTTP "+res.status);
   const errors=Array.isArray(body.errors)?body.errors:[];invalid+=errors.length;
   for(const error of errors)output.append(el("p","danger",String(error)));
   const results=Array.isArray(body.results)?body.results as Result[]:[];
   for(const r of results)output.append(render(r));done+=results.length;
  }
  statusElement.textContent=done+" IP analizadas. "+invalid+" entradas inválidas.";
 }catch(e){statusElement.textContent=done+" IP completadas. Error en lote: "+(e instanceof Error?e.message:String(e));}
 finally{submit.disabled=false;}
});
