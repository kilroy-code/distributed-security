import Security from "./security.mjs";

//import Storage from "./storage.mjs";
let requests = {},
    messageId = 0;

setTimeout(_ => Security.Storage = {
  store(...args) {
    return send('store', ...args);
  },
  retrieve(...args) {
    return send('retrieve', ...args);
  }
});

function send(method, ...params) {
  let id = ++messageId,
      request = requests[id] = {};
    return new Promise((resolve, reject) => {
      Object.assign(request, {resolve, reject});
      postMessage({id, method, params});
    });
}

self.addEventListener('message', async event => {
  let {id, method, params, result, error} = event.data;
  if (method) {
    let error = null,
      result = await Security[method](...params).catch(e => error = {name: e.name, message: e.message}),
      response = error ? {id, error} : {id, result};
    return postMessage(response);
  }
  let request = requests[id];
  delete requests[id];
  if (error) request.reject(error);
  else request.resolve(result);
});
