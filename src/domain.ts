export {};
type Result={domain:string;summary:Record<string,unknown>;flags:Record<string,boolean>;report_text:string;sources:Record<string,{data:Record<string,unknown>;error?:string}>};
const isPortal=location.hostname!=="jmarf37.github.io" && (location.hostname==="monkeytools.es"||location.hostname.endsWith(".workers.dev"));
const worker=isPortal?location.origin:"https://monkeytoolv2-domain.jesusmartinezferrer.workers.dev";
const form=document.querySelector<HTMLFormElement>("#domain-form");
const resultBox=document.querySelector<HTMLElement>("#domain-results");
const domainStatus=document.querySelector<HTMLElement>("#domain-status");
const workerField=document.querySelector<HTMLInputElement>("#worker-url");
if(workerField){workerField.value=worker;workerField.placeholder=worker;}
const titles=["Virustotal Community Score","Security Vendors Flagged","Registrar","Creation Date","Categories","Reputation","AlienVault Pulses","URLScan Results"];
const highlights:Record<string,string>={"Virustotal Community Score":"vt_score_red","Security Vendors Flagged":"vt_vendors_red","AlienVault Pulses":"alien_pulses_red"};
const elem=<K extends keyof HTMLElementTagNameMap>(tag:K,txt?:string,cls?:string)=>{const e=document.createElement(tag);if(txt!==undefined)e.textContent=txt;if(cls)e.className=cls;return e;};
const display=(v:unknown)=>v===null||v===undefined?"N/A":typeof v==="object"?JSON.stringify(v):String(v);
function render(r:Result):HTMLElement{
 const card=elem("article",undefined,"domain-card");
 card.append(elem("h2","Dominio analizado: "+r.domain));
 for(const [name,source] of Object.entries(r.sources)){if(source.error)card.append(elem("p",name+": "+source.error,"risk"));}
 const details=elem("details");details.open=true;const summary=elem("summary","Informe completo");const button=elem("button","Copiar informe");button.type="button";button.className="copy-btn";
 button.addEventListener("click",async e=>{e.preventDefault();e.stopPropagation();try{await navigator.clipboard.writeText(r.report_text);button.textContent="¡Copiado!";}catch{button.textContent="No se pudo copiar";}});
 summary.append(button);details.append(summary,elem("pre",r.report_text));card.append(details);return card;
}
form?.addEventListener("submit",async event=>{
 event.preventDefault();if(!domainStatus||!resultBox)return;
 const host=workerField?.value.trim().replace(/\/+$/,"")??"";
 if(!/^https:\/\/[a-z0-9.-]+$/i.test(host)){domainStatus.textContent="Introduce la URL HTTPS del Worker de dominios.";return;}
 const domains=(document.querySelector<HTMLTextAreaElement>("#domains")?.value??"").trim();
 const candidates=[...new Set(domains.split(/[,\s]+/).filter(Boolean))];
 if(!candidates.length||candidates.length>15){domainStatus.textContent="Indica entre 1 y 15 dominios.";return;}
 const button=form.querySelector<HTMLButtonElement>("button[type=submit]");if(button)button.disabled=true;
 resultBox.replaceChildren();let count=0,invalid=0;
 try{
  for(let i=0;i<candidates.length;i+=3){
   domainStatus.textContent="Analizando dominios "+(i+1)+"–"+Math.min(i+3,candidates.length)+" de "+candidates.length+"...";
   const response=await fetch(host+"/api/domain/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({domains:candidates.slice(i,i+3).join(",")})});
   const body=await response.json();
   if(!response.ok)throw new Error(body.error??"HTTP "+response.status);
   for(const error of (body.errors??[])){resultBox.append(elem("p",String(error),"risk"));invalid++;}
   for(const result of (body.results??[]) as Result[]){resultBox.append(render(result));count++;}
  }
  domainStatus.textContent=count+" dominios analizados. "+invalid+" entradas inválidas.";
 }catch(e){domainStatus.textContent=count+" dominios completados. Error en lote: "+(e instanceof Error?e.message:String(e));}
 finally{if(button)button.disabled=false;}
});
