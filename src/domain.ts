type Result={domain:string;summary:Record<string,unknown>;flags:Record<string,boolean>;report_text:string;sources:Record<string,{data:Record<string,unknown>;error?:string}>};
const worker="https://monkeytoolv2-domain.TU_SUBDOMINIO.workers.dev";
const form=document.querySelector<HTMLFormElement>("#domain-form");
const resultBox=document.querySelector<HTMLElement>("#domain-results");
const status=document.querySelector<HTMLElement>("#domain-status");
const workerField=document.querySelector<HTMLInputElement>("#worker-url");
if(workerField)workerField.placeholder=worker;
const titles=["Virustotal Community Score","Security Vendors Flagged","Registrar","Creation Date","Categories","Reputation","AlienVault Pulses","URLScan Results"];
const highlights:Record<string,string>={"Virustotal Community Score":"vt_score_red","Security Vendors Flagged":"vt_vendors_red","AlienVault Pulses":"alien_pulses_red"};
const elem=<K extends keyof HTMLElementTagNameMap>(tag:K,txt?:string,cls?:string)=>{const e=document.createElement(tag);if(txt!==undefined)e.textContent=txt;if(cls)e.className=cls;return e;};
const display=(v:unknown)=>v===null||v===undefined?"N/A":typeof v==="object"?JSON.stringify(v):String(v);
function render(r:Result):HTMLElement{
 const card=elem("article",undefined,"domain-card");
 card.append(elem("h2","Dominio analizado: "+r.domain),elem("h3","Resumen análisis"));
 const table=elem("table",undefined,"domain-table");
 for(const name of titles){const tr=elem("tr");tr.append(elem("th",name),elem("td",display(r.summary[name]),r.flags[highlights[name]]?"risk":""));table.append(tr);}
 card.append(table);
 for(const [name,source] of Object.entries(r.sources)){if(source.error)card.append(elem("p",name+": "+source.error,"risk"));}
 const details=elem("details");const summary=elem("summary","Ver detalles completos");const button=elem("button","Copiar informe");button.type="button";button.className="copy-btn";
 button.addEventListener("click",async e=>{e.preventDefault();e.stopPropagation();try{await navigator.clipboard.writeText(r.report_text);button.textContent="¡Copiado!";}catch{button.textContent="No se pudo copiar";}});
 summary.append(button);details.append(summary,elem("pre",r.report_text));card.append(details);return card;
}
form?.addEventListener("submit",async event=>{
 event.preventDefault();if(!status||!resultBox)return;
 const host=workerField?.value.trim().replace(/\/+$/,"")??"";
 if(!/^https:\/\/[a-z0-9.-]+\.workers\.dev$/i.test(host)){status.textContent="Introduce la URL HTTPS del Worker de dominios.";return;}
 const domains=(document.querySelector<HTMLTextAreaElement>("#domains")?.value??"").trim();
 const button=form.querySelector<HTMLButtonElement>("button[type=submit]");if(button)button.disabled=true;
 status.textContent="Consultando fuentes de reputación...";resultBox.replaceChildren();
 try{
  const response=await fetch(host+"/api/domain/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({domains})});
  const body=await response.json();
  if(!response.ok)throw new Error(body.error??"HTTP "+response.status);
  for(const error of (body.errors??[]))resultBox.append(elem("p",String(error),"risk"));
  for(const result of (body.results??[]) as Result[])resultBox.append(render(result));
  status.textContent=(body.results?.length??0)+" dominios analizados";
 }catch(e){status.textContent="Error: "+(e instanceof Error?e.message:String(e));}
 finally{if(button)button.disabled=false;}
});
