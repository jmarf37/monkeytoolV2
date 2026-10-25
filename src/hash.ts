export {};
type Result={hash:string;type:string;report_text:string;sources:Record<string,{data:Record<string,unknown>;error?:string}>};
const ENDPOINT="https://monkeytoolv2-hash.jesusmartinezferrer.workers.dev";
const form=document.querySelector<HTMLFormElement>("#hash-form");
const status=document.querySelector<HTMLElement>("#hash-status");
const output=document.querySelector<HTMLElement>("#hash-results");
const submit=form?.querySelector<HTMLButtonElement>("button[type=submit]");
const mk=<K extends keyof HTMLElementTagNameMap>(tag:K,text?:string,cls?:string)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e};
function render(r:Result){
 const card=mk("article",undefined,"hash-card");
 card.append(mk("h2","Hash analizado: "+r.hash),mk("p","Algoritmo: "+r.type));
 const copy=mk("button","Copiar informe","hash-copy");copy.type="button";
 copy.addEventListener("click",async()=>{try{await navigator.clipboard.writeText(r.report_text);copy.textContent="¡Copiado!";}catch{copy.textContent="Error al copiar";}});
 card.append(copy,mk("pre",r.report_text,"hash-report"));return card;
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
