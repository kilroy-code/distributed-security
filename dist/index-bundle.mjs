const e=location.origin;function t(t,r){return`${e}/db/${t}/${r}.json`}async function r(e){if(404===e.status)return"";if(!e.ok)return Promise.reject(e.statusText);let t=await e.text();return t?JSON.parse(t):t}const n={get origin(){return e},store:(e,n,o)=>fetch(t(e,n),{method:"PUT",body:JSON.stringify(o),headers:{"Content-Type":"application/json"}}).then(r),retrieve:(e,n)=>fetch(t(e,n),{cache:"default",headers:{Accept:"application/json"}}).then(r)};var o=e=>e;"undefined"!=typeof window&&(o=window.prompt);const s=new URL(import.meta.url),a=new URL("vault-bundle.mjs",s),i=document.createElement("iframe"),c=new MessageChannel,d=Object.assign({log(...e){console.log(...e)},getUserDeviceSecret:function(e,t){return t?e+o(t):e}},n),l=new Promise((e=>{d.ready=e,i.style.display="none",document.body.append(i),i.setAttribute("srcdoc",`<!DOCTYPE html><html><body><script type="module" src="${a.href}"><\/script></body></html>`),i.contentWindow.name="vault!"+s.href,c.port1.start(),i.onload=()=>i.contentWindow.postMessage("initializePort",a.origin,[c.port2])})),g=function({target:e=self,receiver:t=e,namespace:r=t,origin:n=e!==t&&e.location.origin,dispatcherLabel:o=r.name||t.name||t.location?.href||t,targetLabel:s=e.name||n||e.location?.href||e,log:a=null,info:i=console.info.bind(console),warn:c=console.warn.bind(console),error:d=console.error.bind(console)}){const l={},g="2.0",m=e.postMessage.bind(e),u=n?e=>m(e,n):m;let p=0;return t.addEventListener("message",(async function(t){a?.(o,"got message",t.data,"from",s,t.origin);let{id:i,method:m,params:p=[],result:f,error:h,jsonrpc:y}=t.data||{};if(t.source&&t.source!==e)return d?.(o,"to",s,"got message from",t.source);if(n&&n!==t.origin)return d?.(o,n,"mismatched origin",s,t.origin);if(y!==g)return c?.(`${o} ignoring non-jsonrpc message ${JSON.stringify(t.data)}.`);if(m){let e,t=null,n=Array.isArray(p)?p:[p];try{e=await r[m](...n)}catch(e){t=function(e){let{name:t,message:r,code:n,data:o}=e;return{name:t,message:r,code:n,data:o}}(e),r[m]||t.message.includes(m)?t.message||(t.message=`${t.name||t.toString()} in ${m}.`):(t.message=`${m} is not defined.`,t.code=-32601)}if(void 0===i)return;let c=t?{id:i,error:t,jsonrpc:g}:{id:i,result:e,jsonrpc:g};return a?.(o,"answering",i,t||e,"to",s),u(c)}let b=l[i];if(delete l[i],!b)return c?.(`${o} ignoring response ${t.data}.`);h?b.reject(h):b.resolve(f)})),i?.(`${o} will dispatch to ${s}`),function(e,...t){let r=++p,n=l[r]={};return new Promise(((i,c)=>{a?.(o,"request",r,e,t,"to",s),Object.assign(n,{resolve:i,reject:c}),u({id:r,method:e,params:t,jsonrpc:g})}))}}({dispatcherLabel:"entry!"+s.href,namespace:d,target:c.port1,targetLabel:i.contentWindow.name}),m={sign:(e,...t)=>g("sign",e,...t),verify:(e,...t)=>g("verify",e,...t),encrypt:(e,...t)=>g("encrypt",e,...t),decrypt:(e,...t)=>g("decrypt",e,...t),create:(...e)=>g("create",...e),changeMembership:({tag:e,add:t,remove:r}={})=>g("changeMembership",{tag:e,add:t,remove:r}),destroy:e=>g("destroy",e),clear:(e=null)=>g("clear",e),ready:l,get Storage(){return d},set Storage(e){Object.assign(d,e)},set getUserDeviceSecret(e){d.getUserDeviceSecret=e}};export{m as default};
