
function transferrableError(error) { // An error object that we receive on our side might not be transferrable to the other.
  let {name, message} = error;
  return {name, message};
}

function dispatch({target,
		   receiver = target,
		   namespace = receiver,
		   origin = ((target !== receiver) && target.location.origin),
		   targetLabel = origin || target.location?.href || target,
		   dispatcherLabel = receiver.location?.href || receiver,
		   log = () => null,
		   warn:logwarn = console.warn.bind(console),
		   error:logerror = console.error.bind(console)
		  }) {
  let requests = {},
      messageId = 0,
      jsonrpc = '2.0',
      capturedPost = target.postMessage.bind(target), // In case (malicious) code later changes it.
      // window.postMessage and friends takes a targetOrigin that we should supply.
      // But other forms give error rather than ignoring the extra arg. So set the right form at initialization.
      post = origin ? message => capturedPost(message, origin) : capturedPost;
  log(dispatcherLabel, 'dispatch to', targetLabel);

  receiver.addEventListener('message', async event => {
    log(dispatcherLabel, 'got message', event.data, 'from', targetLabel, event.origin);
    let {id, method, params = [], result, error, jsonrpc:version} = event.data || {};
    if (event.source && (event.source !== target)) return logerror(dispatcherLabel, 'got mismatched event from', targetLabel, event.origin);
    if (origin && (origin !== event.origin)) return logerror(dispatcherLabel, origin, 'mismatched origin', targetLabel, event.origin);
    if (version !== jsonrpc) return logwarn(`${dispatcherLabel} ignoring non-jsonrpc message ${JSON.stringify(event.data)}.`);

    if (method) { // Incoming request or notification from target.
      let error = null, result,
	  args = Array.isArray(params) ? params : [params]; // Accept either form of params.
      try { // method result might not be a promise, so we can't rely on .catch().
	result = await namespace[method](...args);
      } catch (e) {
	error = transferrableError(e);
	if (!namespace[method] && !error.message.includes(method))
	  error.message = `${method} is not defined.`; // Be more helpful than some browsers.
	else if (!error.message) // It happens. E.g., operational errors from crypto.
	  error.message = `${error.name || error.toString()} in ${method}.`;
      }
      let response = error ? {id, error, jsonrpc} : {id, result, jsonrpc};
      log(dispatcherLabel, 'answering', id, error || result, 'to', targetLabel);
      return post(response);
    }

    let request = requests[id]; // A response from target to our earlier outgoing request.
    delete requests[id];
    if (!request) return logwarn(`${dispatcherLabel} ignoring response ${event.data}.`);
    if (error) request.reject(error);
    else request.resolve(result);
  });

  // FIXME: Don't leak promises when there is no response. Timeout? Return both request and notify? special arg? Some combination?
  return function request(method, ...params) {
    let id = ++messageId,
	request = requests[id] = {};
    return new Promise((resolve, reject) => {
      Object.assign(request, {resolve, reject});
      log(dispatcherLabel, 'requesting', id, method, params, 'to', targetLabel);
      post({id, method, params, jsonrpc});
    });
  };
}

export default dispatch;
