const e=location.origin;function t(t,r){return`${e}/db/${t}/${r}.json`}async function r(e){if(404===e.status)return"";if(!e.ok)return Promise.reject(e.statusText);let t=await e.text();return t?JSON.parse(t):t}const n={get origin(){return e},store:(e,n,o)=>fetch(t(e,n),{method:"PUT",body:JSON.stringify(o),headers:{"Content-Type":"application/json"}}).then(r),retrieve:(e,n)=>fetch(t(e,n),{cache:"default",headers:{Accept:"application/json"}}).then(r)};var o=e=>e;"undefined"!=typeof window&&(o=window.prompt);const s=new URL(import.meta.url),a=new URL("vault-bundle.mjs",s),i=document.createElement("iframe"),c=new MessageChannel,d=Object.assign({log(...e){console.log(...e)},getUserDeviceSecret:function(e,t){return t?e+o(t):e}},n),g=new Promise((e=>{d.ready=e,i.style.display="none",document.body.append(i),i.setAttribute("srcdoc",`<!DOCTYPE html><html><body><script type="module" src="${a.href}"><\/script></body></html>`),i.contentWindow.name="vault@"+s.href,c.port1.start(),i.onload=()=>i.contentWindow.postMessage("initializePort",a.origin,[c.port2])})),l=function({target:e,receiver:t=e,namespace:r=t,origin:n=e!==t&&e.location.origin,log:o=(()=>null),warn:s=console.warn.bind(console),error:a=console.error.bind(console)}){let i={},c=0,d="2.0",g=n||e,l=e.postMessage.bind(e),m=n?e=>l(e,n):l;return o("dispatch to",g),t.addEventListener("message",(async t=>{o("message",t.data,"from",t.origin||g);let{id:c,method:l,params:u=[],result:p,error:f,jsonrpc:y}=t.data||{};if(t.source&&t.source!==e)return a("mismatched target:",e,t.source);if(n&&n!==t.origin)return a("mismatched origin",n,t.origin);if(y!==d)return s(`Ignoring non-jsonrpc message ${JSON.stringify(t.data)}.`);if(l){let e,t=null,n=Array.isArray(u)?u:[u];try{e=await r[l](...n)}catch(e){t=function(e){let{name:t,message:r}=e;return{name:t,message:r}}(e),r[l]||t.message.includes(l)?t.message||(t.message=`${t.name||t.toString()} in ${l}.`):t.message=`${l} is not defined.`}let s=t?{id:c,error:t,jsonrpc:d}:{id:c,result:e,jsonrpc:d};return o("answering",c,t||e,"to",g),m(s)}let h=i[c];if(delete i[c],!h)return console.log(`Ignoring response ${t.data}.`);f?h.reject(f):h.resolve(p)})),function(e,...t){let r=++c,n=i[r]={};return new Promise(((s,a)=>{Object.assign(n,{resolve:s,reject:a}),o("posting",r,e,t,"to",g),m({id:r,method:e,params:t,jsonrpc:d})}))}}({dispatcherLabel:"entry@"+s.href,namespace:d,target:c.port1,targetLabel:i.contentWindow.name}),m={sign:(e,...t)=>l("sign",e,...t),verify:(e,...t)=>l("verify",e,...t),encrypt:(e,...t)=>l("encrypt",e,...t),decrypt:(e,...t)=>l("decrypt",e,...t),create:(...e)=>l("create",...e),changeMembership:({tag:e,add:t,remove:r}={})=>l("changeMembership",{tag:e,add:t,remove:r}),destroy:e=>l("destroy",e),clear:(e=null)=>l("clear",e),ready:g,get Storage(){return d},set Storage(e){Object.assign(d,e)},set getUserDeviceSecret(e){d.getUserDeviceSecret=e}};export{m as default};
