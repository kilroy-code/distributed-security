function e({target:e=self,receiver:r=e,namespace:t=r,origin:n=e!==r&&e.location.origin,dispatcherLabel:s=t.name||r.name||r.location?.href||r,targetLabel:a=e.name||n||e.location?.href||e,log:o=(()=>null),warn:i=console.warn.bind(console),error:c=console.error.bind(console)}){let l={},g=0,m="2.0",d=e.postMessage.bind(e),p=n?e=>d(e,n):d;return r.addEventListener("message",(async function(r){o(s,"got message",r.data,"from",a,r.origin);let{id:g,method:d,params:u=[],result:f,error:y,jsonrpc:h}=r.data||{};if(r.source&&r.source!==e)return c(s,"to",a,"got message from",r.source);if(n&&n!==r.origin)return c(s,n,"mismatched origin",a,r.origin);if(h!==m)return i(`${s} ignoring non-jsonrpc message ${JSON.stringify(r.data)}.`);if(d){let e,r=null,n=Array.isArray(u)?u:[u];try{e=await t[d](...n)}catch(e){r=function(e){let{name:r,message:t}=e;return{name:r,message:t}}(e),t[d]||r.message.includes(d)?r.message||(r.message=`${r.name||r.toString()} in ${d}.`):r.message=`${d} is not defined.`}let i=r?{id:g,error:r,jsonrpc:m}:{id:g,result:e,jsonrpc:m};return o(s,"answering",g,r||e,"to",a),p(i)}let b=l[g];if(delete l[g],!b)return i(`${s} ignoring response ${r.data}.`);y?b.reject(y):b.resolve(f)})),o(`${s} will dispatch to ${a}`,e,r),function(e,...r){let t=++g,n=l[t]={};return new Promise(((i,c)=>{o(s,"request",t,e,r,"to",a),Object.assign(n,{resolve:i,reject:c}),p({id:t,method:e,params:r,jsonrpc:m})}))}}const r=self.name.split("@")[1];onmessage=t=>{if(t.source!==parent||t.origin!==new URL(document.referrer).origin)return alert(`${self.name} got ${t.data} from ${t.origin}.`);onmessage=null;const n="entry@"+r,s={sign:(e,...r)=>g("sign",e,...r),verify:(e,...r)=>g("verify",e,...r),encrypt:(e,...r)=>g("encrypt",e,...r),decrypt:(e,...r)=>g("decrypt",e,...r),create:(...e)=>g("create",...e),changeMembership:e=>g("changeMembership",e),destroy:e=>g("destroy",e),clear:e=>g("clear",e)},a=e({target:t.ports[0],targetLabel:n,dispatcherLabel:self.name,namespace:s}),o=import.meta.url,i=new URL("worker-bundle.mjs?v=54",o),c="worker@"+r,l={store:(e,r,t)=>a("store",e,r,t),retrieve:(e,r)=>a("retrieve",e,r),getUserDeviceSecret:(e,r="")=>a("getUserDeviceSecret",e,r),ready(e){t.ports[0].start(),a("ready",e)}},g=e({target:new Worker(i,{type:"module",name:c}),targetLabel:c,dispatcherLabel:self.name,namespace:l})};