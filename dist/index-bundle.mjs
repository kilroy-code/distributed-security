const e=location.origin;async function t(e){if(404===e.status)return"";if(!e.ok)return Promise.reject(e.statusText);let t=await e.text();return t?JSON.parse(t):t}const r={get origin(){return e},uri:(t,r)=>`${e}/db/${t}/${r}.json`,store(e,r,n,o={}){return fetch(this.uri(e,r),{method:"PUT",body:JSON.stringify(n),headers:{"Content-Type":"application/json",...o.headers||{}}}).then(t)},retrieve(e,r,n={}){return fetch(this.uri(e,r),{cache:"default",headers:{Accept:"application/json",...n.headers||{}}}).then(t)}};var n=e=>e;"undefined"!=typeof window&&(n=window.prompt);const o=new URL(import.meta.url),s=new URL("vault-bundle.mjs",o),a=document.createElement("iframe"),i=new MessageChannel,c=Object.assign({log(...e){console.log(...e)},getUserDeviceSecret:function(e,t){return t?e+n(t):e}},r),d=new Promise((e=>{c.ready=e,a.style.display="none",document.body.append(a),a.setAttribute("srcdoc",`<!DOCTYPE html><html><body><script type="module" src="${s.href}"><\/script></body></html>`),a.contentWindow.name="vault!"+o.href,i.port1.start(),a.onload=()=>a.contentWindow.postMessage("initializePort",s.origin,[i.port2])})),l=function({target:e=self,receiver:t=e,namespace:r=t,origin:n=e!==t&&e.location.origin,dispatcherLabel:o=r.name||t.name||t.location?.href||t,targetLabel:s=e.name||n||e.location?.href||e,log:a=null,info:i=console.info.bind(console),warn:c=console.warn.bind(console),error:d=console.error.bind(console)}){const l={},g="2.0",u=e.postMessage.bind(e),m=n?e=>u(e,n):u;let p=0;return t.addEventListener("message",(async function(t){a?.(o,"got message",t.data,"from",s,t.origin);let{id:i,method:u,params:p=[],result:f,error:h,jsonrpc:y}=t.data||{};if(t.source&&t.source!==e)return d?.(o,"to",s,"got message from",t.source);if(n&&n!==t.origin)return d?.(o,n,"mismatched origin",s,t.origin);if(y!==g)return c?.(`${o} ignoring non-jsonrpc message ${JSON.stringify(t.data)}.`);if(u){let e,t=null,n=Array.isArray(p)?p:[p];try{e=await r[u](...n)}catch(e){t=function(e){let{name:t,message:r,code:n,data:o}=e;return{name:t,message:r,code:n,data:o}}(e),r[u]||t.message.includes(u)?t.message||(t.message=`${t.name||t.toString()} in ${u}.`):(t.message=`${u} is not defined.`,t.code=-32601)}if(void 0===i)return;let c=t?{id:i,error:t,jsonrpc:g}:{id:i,result:e,jsonrpc:g};return a?.(o,"answering",i,t||e,"to",s),m(c)}let b=l[i];if(delete l[i],!b)return c?.(`${o} ignoring response ${t.data}.`);h?b.reject(h):b.resolve(f)})),i?.(`${o} will dispatch to ${s}`),function(e,...t){let r=++p,n=l[r]={};return new Promise(((i,c)=>{a?.(o,"request",r,e,t,"to",s),Object.assign(n,{resolve:i,reject:c}),m({id:r,method:e,params:t,jsonrpc:g})}))}}({dispatcherLabel:"entry!"+o.href,namespace:c,target:i.port1,targetLabel:a.contentWindow.name}),g={sign:(e,...t)=>l("sign",e,...t),verify:(e,...t)=>l("verify",e,...t),encrypt:(e,...t)=>l("encrypt",e,...t),decrypt:(e,...t)=>l("decrypt",e,...t),create:(...e)=>l("create",...e),changeMembership:({tag:e,add:t,remove:r}={})=>l("changeMembership",{tag:e,add:t,remove:r}),destroy:e=>l("destroy",e),clear:(e=null)=>l("clear",e),ready:d,get Storage(){return c},set Storage(e){Object.assign(c,e)},set getUserDeviceSecret(e){c.getUserDeviceSecret=e}};export{g as default};
