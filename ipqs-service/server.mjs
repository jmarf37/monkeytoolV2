import http from "node:http";
import { timingSafeEqual } from "node:crypto";
const port=Number(process.env.PORT||10000);
const key=(process.env.IPQ_API||"").trim();
const token=process.env.IPQS_PROXY_TOKEN||"";
const verify=(provided)=>{if(!token||!provided)return false;const a=Buffer.from(provided),b=Buffer.from(token);return a.length===b.length&&timingSafeEqual(a,b)};
const reply=(res,status,body)=>{res.writeHead(status,{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"});res.end(JSON.stringify(body))};
const validIP=(ip)=>{const groups=ip.split(".");return groups.length===4&&groups.every(g=>/^(0|[1-9][0-9]{0,2})$/.test(g)&&Number(g)<=255)};
const server=http.createServer(async(req,res)=>{
 const path=new URL(req.url||"/","http://localhost").pathname;
 if(path==="/health"&&req.method==="GET")return reply(res,200,{ok:true,service:"monkeytools-ipqs"});
 if(path!=="/lookup"||req.method!=="POST")return reply(res,404,{error:"Not found"});
 if(!verify(req.headers.authorization?.startsWith("Bearer ")?req.headers.authorization.slice(7):""))return reply(res,401,{error:"Unauthorized"});
 if(!key)return reply(res,503,{error:"IPQ_API is not configured"});
 let buffer="";for await(const part of req){buffer+=part;if(buffer.length>1024)return reply(res,413,{error:"Too large"})}
 let ip;try{ip=JSON.parse(buffer).ip}catch{return reply(res,400,{error:"Invalid JSON"})}
 if(typeof ip!=="string"||!validIP(ip))return reply(res,400,{error:"Invalid IPv4"});
 try{
   const url=new URL("https://www.ipqualityscore.com/api/json/ip/"+encodeURIComponent(key)+"/"+ip);
   url.searchParams.set("strictness","1");
   url.searchParams.set("fast","true");
   url.searchParams.set("allow_public_access_points","true");
   url.searchParams.set("lighter_penalties","true");
   const upstream=await fetch(url,{signal:AbortSignal.timeout(12000)});
   const data=await upstream.json();
   // Whitelist returned fields. No credentials, raw headers or upstream URL exposed.
   if(!upstream.ok||data.success===false)return reply(res,502,{error:"IPQS: "+String(data.message||"upstream failure").slice(0,180),request_id:typeof data.request_id==="string"?data.request_id.slice(0,60):undefined});
   return reply(res,200,{data:{"Fraud Score":data.fraud_score??null,"Proxy":data.proxy??null,"TOR":data.tor??null,"Recent Abuse":data.recent_abuse??null,"ISP":data.ISP??null,"Organization":data.organization??data.Organization??null,"ASN":data.ASN??null,"Country Code":data.country_code??null,"City":data.city??null,"Region":data.region??null}});
 }catch{return reply(res,502,{error:"IPQS upstream unavailable"})}
});
server.listen(port,"0.0.0.0");
