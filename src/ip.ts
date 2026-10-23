type Result={ip:string;summary:Record<string,unknown>;flags:Record<string,boolean>;report_text:string;sources:Record<string,{data:Record<string,unknown>;error?:string}>};
const form=document.querySelector<HTMLFormElement>("#ip-form");
const output=document.querySelector<HTMLElement>("#results");
const statusElement=document.querySelector<HTMLElement>("#ip-status");
const endpointInput=document.querySelector<HTMLInputElement>("#api-endpoint");
const DEFAULT_WORKER_URL="https://monkeytoolv2.jesusmartinezferrer.workers.dev";
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
 summary.append(copy);details.append(summary,el("pre","report-text",result.report_text));card.append(details);return card;
}
form?.addEventListener("submit",async(event)=>{
 event.preventDefault();if(!output||!statusElement||!submit)return;
 const input=(form.querySelector<HTMLTextAreaElement>("#ips")?.value??"").trim();
 const endpoint=endpointInput?.value.trim().replace(/\/+$/,"")??"";
 if(!endpoint){statusElement.textContent="Debes indicar la URL de tu Cloudflare Worker cuando esté desplegado.";return;}
 if(!/^https:\/\/[a-z0-9.-]+$/i.test(endpoint)){statusElement.textContent="La URL debe ser HTTPS y contener solo el dominio del Worker.";return;}
 submit.disabled=true;statusElement.textContent="Consultando fuentes de reputación...";output.replaceChildren();
 try{const res=await fetch(endpoint+"/api/ip/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ips:input})});const body=await res.json();if(!res.ok)throw new Error(body.error??"HTTP "+res.status);
 const errors=Array.isArray(body.errors)?body.errors:[];for(const error of errors)output.append(el("p","danger",String(error)));
 const results=Array.isArray(body.results)?body.results as Result[]:[];for(const r of results)output.append(render(r));
 statusElement.textContent=results.length+" IP analizadas. "+errors.length+" entradas inválidas.";
 }catch(e){statusElement.textContent="No se pudo consultar el Worker: "+(e instanceof Error?e.message:String(e))+". Comprueba la URL, el despliegue y CORS.";}
 finally{submit.disabled=false;}
});
