function transferrableError(error) { // An error object that we receive on our side might not be transferrable to the other.
  let {name, message, code, data} = error;
  return {name, message, code, data};
}

// Set up bidirectional communcations with target, returning a function (methodName, ...params) that will send to target.
function dispatch({target = self,        // The window, worker, or other object to which we will postMessage.
		   receiver = target,    // The window, worker, or other object of which WE will handle 'message' events from target.
		   namespace = receiver, // An object that defines any methods that may be requested by target.

		   origin = ((target !== receiver) && target.location.origin),

		   dispatcherLabel = namespace.name || receiver.name || receiver.location?.href || receiver,
		   targetLabel = target.name || origin || target.location?.href || target,

		   log = null,
		   info:loginfo = console.info.bind(console),
		   warn:logwarn = console.warn.bind(console),
		   error:logerror = console.error.bind(console)
		  }) {
  const requests = {},
        jsonrpc = '2.0',
        capturedPost = target.postMessage.bind(target), // In case (malicious) code later changes it.
        // window.postMessage and friends takes a targetOrigin that we supply.
        // But worker.postMessage gives error rather than ignoring the extra arg. So set the right form at initialization.
        post = origin ? message => capturedPost(message, origin) : capturedPost;
  let messageId = 0; // pre-incremented id starts at 1.

  function request(method, ...params) { // Promise the result of method(...params) in target.
    // We do a target.postMessage of a jsonrpc request, and resolve the promise with the response, matched by id.
    // If the target happens to be set up by a dispatch like this one, it will respond with whatever it's
    // namespace[method](...params) resolves to. We only send jsonrpc requests (with an id), not notifications,
    // because there is no way to get errors back from a jsonrpc notification.
    let id = ++messageId,
	request = requests[id] = {};
    // It would be nice to not leak request objects if they aren't answered.
    return new Promise((resolve, reject) => {
      log?.(dispatcherLabel, 'request', id, method, params, 'to', targetLabel);
      Object.assign(request, {resolve, reject});
      post({id, method, params, jsonrpc});
    });
  }

  async function respond(event) { // Handle 'message' events that we receive from target.
    log?.(dispatcherLabel, 'got message', event.data, 'from', targetLabel, event.origin);
    let {id, method, params = [], result, error, jsonrpc:version} = event.data || {};

    // Noisily ignore messages that are not from the expect target or origin, or which are not jsonrpc.
    if (event.source && (event.source !== target)) return logerror?.(dispatcherLabel, 'to', targetLabel,  'got message from', event.source);
    if (origin && (origin !== event.origin)) return logerror?.(dispatcherLabel, origin, 'mismatched origin', targetLabel, event.origin);
    if (version !== jsonrpc) return logwarn?.(`${dispatcherLabel} ignoring non-jsonrpc message ${JSON.stringify(event.data)}.`);

    if (method) { // Incoming request or notification from target.
      let error = null, result,
          // jsonrpc request/notification can have positional args (array) or named args (a POJO).
	  args = Array.isArray(params) ? params : [params]; // Accept either.
      try { // method result might not be a promise, so we can't rely on .catch().
        result = await namespace[method](...args); // Call the method.
      } catch (e) { // Send back a clean {name, message} object.
        error = transferrableError(e);
        if (!namespace[method] && !error.message.includes(method)) {
	  error.message = `${method} is not defined.`; // Be more helpful than some browsers.
          error.code = -32601; // Defined by json-rpc spec.
        } else if (!error.message) // It happens. E.g., operational errors from crypto.
	  error.message = `${error.name || error.toString()} in ${method}.`;
      }
      if (id === undefined) return; // Don't respond to a 'notification'. null id is still sent back.
      let response = error ? {id, error, jsonrpc} : {id, result, jsonrpc};
      log?.(dispatcherLabel, 'answering', id, error || result, 'to', targetLabel);
      return post(response);
    }

    // Otherwise, it is a response from target to our earlier outgoing request.
    let request = requests[id];  // Resolve or reject the promise that an an earlier request created.
    delete requests[id];
    if (!request) return logwarn?.(`${dispatcherLabel} ignoring response ${event.data}.`);
    if (error) request.reject(error);
    else request.resolve(result);
  }

  // Now set up the handler and return the function for the caller to use to make requests.
  receiver.addEventListener("message", respond);
  loginfo?.(`${dispatcherLabel} will dispatch to ${targetLabel}`);
  return request;
}

const origin = new URL(import.meta.url).origin;

const mkdir = undefined;

const tagBreakup = /(\S{50})(\S{2})(\S{2})(\S+)/;
function tagPath(collectionName, tag, extension = 'json') { // Pathname to tag resource.
  // Used in Storage URI and file system stores. Bottlenecked here to provide consistent alternate implementations.
  // Path is .json so that static-file web servers will supply a json mime type.
  // Path is broken up so that directory reads don't get bogged down from having too much in a directory.
  //
  // NOTE: changes here must be matched by the PUT route specified in signed-cloud-server/storage.mjs and tagName.mjs
  if (!tag) return collectionName;
  let match = tag.match(tagBreakup);
  if (!match) return `${collectionName}/${tag}`;
  // eslint-disable-next-line no-unused-vars
  let [_, a, b, c, rest] = match;
  return `${collectionName}/${a}/${b}/${c}/${rest}.${extension}`;
}

async function responseHandler(response) {
  // Reject if server does, else response.text().
  if (response.status === 404) return '';
  if (!response.ok) return Promise.reject(response.statusText);
  let text = await response.text();
  if (!text) return text; // Result of store can be empty.
  return JSON.parse(text);
}

const Storage = {
  get origin() { return origin; },
  tagPath,
  mkdir,
  uri(collectionName, tag) {
    // Pathname expected by our signed-cloud-server.
    return `${origin}/db/${this.tagPath(collectionName, tag)}`;
  },
  store(collectionName, tag, signature, options = {}) {
    // Store the signed content on the signed-cloud-server, rejecting if
    // the server is unable to verify the signature following the rules of
    // https://kilroy-code.github.io/distributed-security/#storing-keys-using-the-cloud-storage-api
    return fetch(this.uri(collectionName, tag), {
      method: 'PUT',
      body: JSON.stringify(signature),
      headers: {'Content-Type': 'application/json', ...(options.headers || {})}
    }).then(responseHandler);
  },
  retrieve(collectionName, tag, options = {}) {
    // We do not verify and get the original data out here, because the caller has
    // the right to do so without trusting us.
    return fetch(this.uri(collectionName, tag), {
      cache: 'default',
      headers: {'Accept': 'application/json', ...(options.headers || {})}
    }).then(responseHandler);
  }
};

var prompter = promptString => promptString;
if (typeof(window) !== 'undefined') {
  prompter = window.prompt;
}

function getUserDeviceSecret(tag, promptString) {
  return promptString ? (tag + prompter(promptString)) : tag;
}

const entryUrl = new URL(import.meta.url),
      vaultUrl = new URL('vault.html', entryUrl),
      vaultName = 'vault!' + entryUrl.href; // Helps debugging.

// Outer layer of the vault is an iframe that establishes a browsing context separate from the app that imports us.
const iframe = document.createElement('iframe'),
      channel = new MessageChannel(),
      resourcesForIframe = Object.assign({ // What the vault can postMessage to us.
        log(...args) { console.log(...args); },
        getUserDeviceSecret
      }, Storage),
      // Set up a promise that doesn't resolve until the vault posts to us that it is ready (which in turn, won't happen until it's worker is ready).
      ready = new Promise(resolve => {
        resourcesForIframe.ready = resolve,
        iframe.style.display = 'none';
        document.body.append(iframe); // Before referencing its contentWindow.
        iframe.setAttribute('src', vaultUrl);
        iframe.contentWindow.name = vaultName;
        // Hand a private communication port to the frame.
        channel.port1.start();
        iframe.onload = () => iframe.contentWindow.postMessage(vaultName, vaultUrl.origin, [channel.port2]);
      }),
      postIframe = dispatch({  // postMessage to the vault, promising the response.
        dispatcherLabel: 'entry!' + entryUrl.href,
        namespace: resourcesForIframe,
        target: channel.port1,
        targetLabel: vaultName
      }),

      api = { // Exported for use by the application.
        sign(message, ...tags) { return postIframe('sign', message, ...tags); },
        verify(signature, ...tags) { return postIframe('verify', signature, ...tags); },
        encrypt(message, ...tags) { return postIframe('encrypt', message, ...tags); },
        decrypt(encrypted, ...tags) { return postIframe('decrypt', encrypted, ...tags); },
        create(...optionalMembers) { return postIframe('create', ...optionalMembers); },
        changeMembership({tag, add, remove} = {}) { return postIframe('changeMembership', {tag, add, remove}); },
        destroy(tagOrOptions) { return postIframe('destroy', tagOrOptions); },
        clear(tag = null) { return postIframe('clear', tag); },
        ready,

        // Application assigns these so that they can be used by the vault.
        get Storage() { return resourcesForIframe; },
        set Storage(storage) { Object.assign(resourcesForIframe, storage); },
        get getUserDeviceSecret() { return resourcesForIframe.getUserDeviceSecret; },
        set getUserDeviceSecret(functionOfTagAndPrompt) { resourcesForIframe.getUserDeviceSecret = functionOfTagAndPrompt; }
      };

export { api as default };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgtYnVuZGxlLm1qcyIsInNvdXJjZXMiOlsiLi4vbm9kZV9tb2R1bGVzL0BraTFyMHkvanNvbnJwYy9pbmRleC5tanMiLCIuLi9saWIvb3JpZ2luLWJyb3dzZXIubWpzIiwiLi4vbGliL21rZGlyLWJyb3dzZXIubWpzIiwiLi4vbGliL3RhZ1BhdGgubWpzIiwiLi4vbGliL3N0b3JhZ2UubWpzIiwiLi4vbGliL3NlY3JldC5tanMiLCIuLi9pbmRleC5tanMiXSwic291cmNlc0NvbnRlbnQiOlsiXG5mdW5jdGlvbiB0cmFuc2ZlcnJhYmxlRXJyb3IoZXJyb3IpIHsgLy8gQW4gZXJyb3Igb2JqZWN0IHRoYXQgd2UgcmVjZWl2ZSBvbiBvdXIgc2lkZSBtaWdodCBub3QgYmUgdHJhbnNmZXJyYWJsZSB0byB0aGUgb3RoZXIuXG4gIGxldCB7bmFtZSwgbWVzc2FnZSwgY29kZSwgZGF0YX0gPSBlcnJvcjtcbiAgcmV0dXJuIHtuYW1lLCBtZXNzYWdlLCBjb2RlLCBkYXRhfTtcbn1cblxuLy8gU2V0IHVwIGJpZGlyZWN0aW9uYWwgY29tbXVuY2F0aW9ucyB3aXRoIHRhcmdldCwgcmV0dXJuaW5nIGEgZnVuY3Rpb24gKG1ldGhvZE5hbWUsIC4uLnBhcmFtcykgdGhhdCB3aWxsIHNlbmQgdG8gdGFyZ2V0LlxuZnVuY3Rpb24gZGlzcGF0Y2goe3RhcmdldCA9IHNlbGYsICAgICAgICAvLyBUaGUgd2luZG93LCB3b3JrZXIsIG9yIG90aGVyIG9iamVjdCB0byB3aGljaCB3ZSB3aWxsIHBvc3RNZXNzYWdlLlxuXHRcdCAgIHJlY2VpdmVyID0gdGFyZ2V0LCAgICAvLyBUaGUgd2luZG93LCB3b3JrZXIsIG9yIG90aGVyIG9iamVjdCBvZiB3aGljaCBXRSB3aWxsIGhhbmRsZSAnbWVzc2FnZScgZXZlbnRzIGZyb20gdGFyZ2V0LlxuXHRcdCAgIG5hbWVzcGFjZSA9IHJlY2VpdmVyLCAvLyBBbiBvYmplY3QgdGhhdCBkZWZpbmVzIGFueSBtZXRob2RzIHRoYXQgbWF5IGJlIHJlcXVlc3RlZCBieSB0YXJnZXQuXG5cblx0XHQgICBvcmlnaW4gPSAoKHRhcmdldCAhPT0gcmVjZWl2ZXIpICYmIHRhcmdldC5sb2NhdGlvbi5vcmlnaW4pLFxuXG5cdFx0ICAgZGlzcGF0Y2hlckxhYmVsID0gbmFtZXNwYWNlLm5hbWUgfHwgcmVjZWl2ZXIubmFtZSB8fCByZWNlaXZlci5sb2NhdGlvbj8uaHJlZiB8fCByZWNlaXZlcixcblx0XHQgICB0YXJnZXRMYWJlbCA9IHRhcmdldC5uYW1lIHx8IG9yaWdpbiB8fCB0YXJnZXQubG9jYXRpb24/LmhyZWYgfHwgdGFyZ2V0LFxuXG5cdFx0ICAgbG9nID0gbnVsbCxcblx0XHQgICBpbmZvOmxvZ2luZm8gPSBjb25zb2xlLmluZm8uYmluZChjb25zb2xlKSxcblx0XHQgICB3YXJuOmxvZ3dhcm4gPSBjb25zb2xlLndhcm4uYmluZChjb25zb2xlKSxcblx0XHQgICBlcnJvcjpsb2dlcnJvciA9IGNvbnNvbGUuZXJyb3IuYmluZChjb25zb2xlKVxuXHRcdCAgfSkge1xuICBjb25zdCByZXF1ZXN0cyA9IHt9LFxuICAgICAgICBqc29ucnBjID0gJzIuMCcsXG4gICAgICAgIGNhcHR1cmVkUG9zdCA9IHRhcmdldC5wb3N0TWVzc2FnZS5iaW5kKHRhcmdldCksIC8vIEluIGNhc2UgKG1hbGljaW91cykgY29kZSBsYXRlciBjaGFuZ2VzIGl0LlxuICAgICAgICAvLyB3aW5kb3cucG9zdE1lc3NhZ2UgYW5kIGZyaWVuZHMgdGFrZXMgYSB0YXJnZXRPcmlnaW4gdGhhdCB3ZSBzdXBwbHkuXG4gICAgICAgIC8vIEJ1dCB3b3JrZXIucG9zdE1lc3NhZ2UgZ2l2ZXMgZXJyb3IgcmF0aGVyIHRoYW4gaWdub3JpbmcgdGhlIGV4dHJhIGFyZy4gU28gc2V0IHRoZSByaWdodCBmb3JtIGF0IGluaXRpYWxpemF0aW9uLlxuICAgICAgICBwb3N0ID0gb3JpZ2luID8gbWVzc2FnZSA9PiBjYXB0dXJlZFBvc3QobWVzc2FnZSwgb3JpZ2luKSA6IGNhcHR1cmVkUG9zdCxcbiAgICAgICAgbnVsbExvZyA9ICgpID0+IHt9O1xuICBsZXQgbWVzc2FnZUlkID0gMDsgLy8gcHJlLWluY3JlbWVudGVkIGlkIHN0YXJ0cyBhdCAxLlxuXG4gIGZ1bmN0aW9uIHJlcXVlc3QobWV0aG9kLCAuLi5wYXJhbXMpIHsgLy8gUHJvbWlzZSB0aGUgcmVzdWx0IG9mIG1ldGhvZCguLi5wYXJhbXMpIGluIHRhcmdldC5cbiAgICAvLyBXZSBkbyBhIHRhcmdldC5wb3N0TWVzc2FnZSBvZiBhIGpzb25ycGMgcmVxdWVzdCwgYW5kIHJlc29sdmUgdGhlIHByb21pc2Ugd2l0aCB0aGUgcmVzcG9uc2UsIG1hdGNoZWQgYnkgaWQuXG4gICAgLy8gSWYgdGhlIHRhcmdldCBoYXBwZW5zIHRvIGJlIHNldCB1cCBieSBhIGRpc3BhdGNoIGxpa2UgdGhpcyBvbmUsIGl0IHdpbGwgcmVzcG9uZCB3aXRoIHdoYXRldmVyIGl0J3NcbiAgICAvLyBuYW1lc3BhY2VbbWV0aG9kXSguLi5wYXJhbXMpIHJlc29sdmVzIHRvLiBXZSBvbmx5IHNlbmQganNvbnJwYyByZXF1ZXN0cyAod2l0aCBhbiBpZCksIG5vdCBub3RpZmljYXRpb25zLFxuICAgIC8vIGJlY2F1c2UgdGhlcmUgaXMgbm8gd2F5IHRvIGdldCBlcnJvcnMgYmFjayBmcm9tIGEganNvbnJwYyBub3RpZmljYXRpb24uXG4gICAgbGV0IGlkID0gKyttZXNzYWdlSWQsXG5cdHJlcXVlc3QgPSByZXF1ZXN0c1tpZF0gPSB7fTtcbiAgICAvLyBJdCB3b3VsZCBiZSBuaWNlIHRvIG5vdCBsZWFrIHJlcXVlc3Qgb2JqZWN0cyBpZiB0aGV5IGFyZW4ndCBhbnN3ZXJlZC5cbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgbG9nPy4oZGlzcGF0Y2hlckxhYmVsLCAncmVxdWVzdCcsIGlkLCBtZXRob2QsIHBhcmFtcywgJ3RvJywgdGFyZ2V0TGFiZWwpO1xuICAgICAgT2JqZWN0LmFzc2lnbihyZXF1ZXN0LCB7cmVzb2x2ZSwgcmVqZWN0fSk7XG4gICAgICBwb3N0KHtpZCwgbWV0aG9kLCBwYXJhbXMsIGpzb25ycGN9KTtcbiAgICB9KTtcbiAgfVxuXG4gIGFzeW5jIGZ1bmN0aW9uIHJlc3BvbmQoZXZlbnQpIHsgLy8gSGFuZGxlICdtZXNzYWdlJyBldmVudHMgdGhhdCB3ZSByZWNlaXZlIGZyb20gdGFyZ2V0LlxuICAgIGxvZz8uKGRpc3BhdGNoZXJMYWJlbCwgJ2dvdCBtZXNzYWdlJywgZXZlbnQuZGF0YSwgJ2Zyb20nLCB0YXJnZXRMYWJlbCwgZXZlbnQub3JpZ2luKTtcbiAgICBsZXQge2lkLCBtZXRob2QsIHBhcmFtcyA9IFtdLCByZXN1bHQsIGVycm9yLCBqc29ucnBjOnZlcnNpb259ID0gZXZlbnQuZGF0YSB8fCB7fTtcblxuICAgIC8vIE5vaXNpbHkgaWdub3JlIG1lc3NhZ2VzIHRoYXQgYXJlIG5vdCBmcm9tIHRoZSBleHBlY3QgdGFyZ2V0IG9yIG9yaWdpbiwgb3Igd2hpY2ggYXJlIG5vdCBqc29ucnBjLlxuICAgIGlmIChldmVudC5zb3VyY2UgJiYgKGV2ZW50LnNvdXJjZSAhPT0gdGFyZ2V0KSkgcmV0dXJuIGxvZ2Vycm9yPy4oZGlzcGF0Y2hlckxhYmVsLCAndG8nLCB0YXJnZXRMYWJlbCwgICdnb3QgbWVzc2FnZSBmcm9tJywgZXZlbnQuc291cmNlKTtcbiAgICBpZiAob3JpZ2luICYmIChvcmlnaW4gIT09IGV2ZW50Lm9yaWdpbikpIHJldHVybiBsb2dlcnJvcj8uKGRpc3BhdGNoZXJMYWJlbCwgb3JpZ2luLCAnbWlzbWF0Y2hlZCBvcmlnaW4nLCB0YXJnZXRMYWJlbCwgZXZlbnQub3JpZ2luKTtcbiAgICBpZiAodmVyc2lvbiAhPT0ganNvbnJwYykgcmV0dXJuIGxvZ3dhcm4/LihgJHtkaXNwYXRjaGVyTGFiZWx9IGlnbm9yaW5nIG5vbi1qc29ucnBjIG1lc3NhZ2UgJHtKU09OLnN0cmluZ2lmeShldmVudC5kYXRhKX0uYCk7XG5cbiAgICBpZiAobWV0aG9kKSB7IC8vIEluY29taW5nIHJlcXVlc3Qgb3Igbm90aWZpY2F0aW9uIGZyb20gdGFyZ2V0LlxuICAgICAgbGV0IGVycm9yID0gbnVsbCwgcmVzdWx0LFxuICAgICAgICAgIC8vIGpzb25ycGMgcmVxdWVzdC9ub3RpZmljYXRpb24gY2FuIGhhdmUgcG9zaXRpb25hbCBhcmdzIChhcnJheSkgb3IgbmFtZWQgYXJncyAoYSBQT0pPKS5cblx0ICBhcmdzID0gQXJyYXkuaXNBcnJheShwYXJhbXMpID8gcGFyYW1zIDogW3BhcmFtc107IC8vIEFjY2VwdCBlaXRoZXIuXG4gICAgICB0cnkgeyAvLyBtZXRob2QgcmVzdWx0IG1pZ2h0IG5vdCBiZSBhIHByb21pc2UsIHNvIHdlIGNhbid0IHJlbHkgb24gLmNhdGNoKCkuXG4gICAgICAgIHJlc3VsdCA9IGF3YWl0IG5hbWVzcGFjZVttZXRob2RdKC4uLmFyZ3MpOyAvLyBDYWxsIHRoZSBtZXRob2QuXG4gICAgICB9IGNhdGNoIChlKSB7IC8vIFNlbmQgYmFjayBhIGNsZWFuIHtuYW1lLCBtZXNzYWdlfSBvYmplY3QuXG4gICAgICAgIGVycm9yID0gdHJhbnNmZXJyYWJsZUVycm9yKGUpO1xuICAgICAgICBpZiAoIW5hbWVzcGFjZVttZXRob2RdICYmICFlcnJvci5tZXNzYWdlLmluY2x1ZGVzKG1ldGhvZCkpIHtcblx0ICBlcnJvci5tZXNzYWdlID0gYCR7bWV0aG9kfSBpcyBub3QgZGVmaW5lZC5gOyAvLyBCZSBtb3JlIGhlbHBmdWwgdGhhbiBzb21lIGJyb3dzZXJzLlxuICAgICAgICAgIGVycm9yLmNvZGUgPSAtMzI2MDE7IC8vIERlZmluZWQgYnkganNvbi1ycGMgc3BlYy5cbiAgICAgICAgfSBlbHNlIGlmICghZXJyb3IubWVzc2FnZSkgLy8gSXQgaGFwcGVucy4gRS5nLiwgb3BlcmF0aW9uYWwgZXJyb3JzIGZyb20gY3J5cHRvLlxuXHQgIGVycm9yLm1lc3NhZ2UgPSBgJHtlcnJvci5uYW1lIHx8IGVycm9yLnRvU3RyaW5nKCl9IGluICR7bWV0aG9kfS5gO1xuICAgICAgfVxuICAgICAgaWYgKGlkID09PSB1bmRlZmluZWQpIHJldHVybjsgLy8gRG9uJ3QgcmVzcG9uZCB0byBhICdub3RpZmljYXRpb24nLiBudWxsIGlkIGlzIHN0aWxsIHNlbnQgYmFjay5cbiAgICAgIGxldCByZXNwb25zZSA9IGVycm9yID8ge2lkLCBlcnJvciwganNvbnJwY30gOiB7aWQsIHJlc3VsdCwganNvbnJwY307XG4gICAgICBsb2c/LihkaXNwYXRjaGVyTGFiZWwsICdhbnN3ZXJpbmcnLCBpZCwgZXJyb3IgfHwgcmVzdWx0LCAndG8nLCB0YXJnZXRMYWJlbCk7XG4gICAgICByZXR1cm4gcG9zdChyZXNwb25zZSk7XG4gICAgfVxuXG4gICAgLy8gT3RoZXJ3aXNlLCBpdCBpcyBhIHJlc3BvbnNlIGZyb20gdGFyZ2V0IHRvIG91ciBlYXJsaWVyIG91dGdvaW5nIHJlcXVlc3QuXG4gICAgbGV0IHJlcXVlc3QgPSByZXF1ZXN0c1tpZF07ICAvLyBSZXNvbHZlIG9yIHJlamVjdCB0aGUgcHJvbWlzZSB0aGF0IGFuIGFuIGVhcmxpZXIgcmVxdWVzdCBjcmVhdGVkLlxuICAgIGRlbGV0ZSByZXF1ZXN0c1tpZF07XG4gICAgaWYgKCFyZXF1ZXN0KSByZXR1cm4gbG9nd2Fybj8uKGAke2Rpc3BhdGNoZXJMYWJlbH0gaWdub3JpbmcgcmVzcG9uc2UgJHtldmVudC5kYXRhfS5gKTtcbiAgICBpZiAoZXJyb3IpIHJlcXVlc3QucmVqZWN0KGVycm9yKTtcbiAgICBlbHNlIHJlcXVlc3QucmVzb2x2ZShyZXN1bHQpO1xuICB9XG5cbiAgLy8gTm93IHNldCB1cCB0aGUgaGFuZGxlciBhbmQgcmV0dXJuIHRoZSBmdW5jdGlvbiBmb3IgdGhlIGNhbGxlciB0byB1c2UgdG8gbWFrZSByZXF1ZXN0cy5cbiAgcmVjZWl2ZXIuYWRkRXZlbnRMaXN0ZW5lcihcIm1lc3NhZ2VcIiwgcmVzcG9uZCk7XG4gIGxvZ2luZm8/LihgJHtkaXNwYXRjaGVyTGFiZWx9IHdpbGwgZGlzcGF0Y2ggdG8gJHt0YXJnZXRMYWJlbH1gKTtcbiAgcmV0dXJuIHJlcXVlc3Q7XG59XG5cbmV4cG9ydCBkZWZhdWx0IGRpc3BhdGNoO1xuIiwiY29uc3Qgb3JpZ2luID0gbmV3IFVSTChpbXBvcnQubWV0YS51cmwpLm9yaWdpbjtcbmV4cG9ydCBkZWZhdWx0IG9yaWdpbjtcbiIsImV4cG9ydCBjb25zdCBta2RpciA9IHVuZGVmaW5lZDtcbiIsImNvbnN0IHRhZ0JyZWFrdXAgPSAvKFxcU3s1MH0pKFxcU3syfSkoXFxTezJ9KShcXFMrKS87XG5leHBvcnQgZnVuY3Rpb24gdGFnUGF0aChjb2xsZWN0aW9uTmFtZSwgdGFnLCBleHRlbnNpb24gPSAnanNvbicpIHsgLy8gUGF0aG5hbWUgdG8gdGFnIHJlc291cmNlLlxuICAvLyBVc2VkIGluIFN0b3JhZ2UgVVJJIGFuZCBmaWxlIHN5c3RlbSBzdG9yZXMuIEJvdHRsZW5lY2tlZCBoZXJlIHRvIHByb3ZpZGUgY29uc2lzdGVudCBhbHRlcm5hdGUgaW1wbGVtZW50YXRpb25zLlxuICAvLyBQYXRoIGlzIC5qc29uIHNvIHRoYXQgc3RhdGljLWZpbGUgd2ViIHNlcnZlcnMgd2lsbCBzdXBwbHkgYSBqc29uIG1pbWUgdHlwZS5cbiAgLy8gUGF0aCBpcyBicm9rZW4gdXAgc28gdGhhdCBkaXJlY3RvcnkgcmVhZHMgZG9uJ3QgZ2V0IGJvZ2dlZCBkb3duIGZyb20gaGF2aW5nIHRvbyBtdWNoIGluIGEgZGlyZWN0b3J5LlxuICAvL1xuICAvLyBOT1RFOiBjaGFuZ2VzIGhlcmUgbXVzdCBiZSBtYXRjaGVkIGJ5IHRoZSBQVVQgcm91dGUgc3BlY2lmaWVkIGluIHNpZ25lZC1jbG91ZC1zZXJ2ZXIvc3RvcmFnZS5tanMgYW5kIHRhZ05hbWUubWpzXG4gIGlmICghdGFnKSByZXR1cm4gY29sbGVjdGlvbk5hbWU7XG4gIGxldCBtYXRjaCA9IHRhZy5tYXRjaCh0YWdCcmVha3VwKTtcbiAgaWYgKCFtYXRjaCkgcmV0dXJuIGAke2NvbGxlY3Rpb25OYW1lfS8ke3RhZ31gO1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbm8tdW51c2VkLXZhcnNcbiAgbGV0IFtfLCBhLCBiLCBjLCByZXN0XSA9IG1hdGNoO1xuICByZXR1cm4gYCR7Y29sbGVjdGlvbk5hbWV9LyR7YX0vJHtifS8ke2N9LyR7cmVzdH0uJHtleHRlbnNpb259YDtcbn1cbiIsImltcG9ydCBvcmlnaW4gZnJvbSAnI29yaWdpbic7IC8vIFdoZW4gcnVubmluZyBpbiBhIGJyb3dzZXIsIGxvY2F0aW9uLm9yaWdpbiB3aWxsIGJlIGRlZmluZWQuIEhlcmUgd2UgYWxsb3cgZm9yIE5vZGVKUy5cbmltcG9ydCB7bWtkaXJ9IGZyb20gJyNta2Rpcic7XG5pbXBvcnQge3RhZ1BhdGh9IGZyb20gJy4vdGFnUGF0aC5tanMnO1xuXG5hc3luYyBmdW5jdGlvbiByZXNwb25zZUhhbmRsZXIocmVzcG9uc2UpIHtcbiAgLy8gUmVqZWN0IGlmIHNlcnZlciBkb2VzLCBlbHNlIHJlc3BvbnNlLnRleHQoKS5cbiAgaWYgKHJlc3BvbnNlLnN0YXR1cyA9PT0gNDA0KSByZXR1cm4gJyc7XG4gIGlmICghcmVzcG9uc2Uub2spIHJldHVybiBQcm9taXNlLnJlamVjdChyZXNwb25zZS5zdGF0dXNUZXh0KTtcbiAgbGV0IHRleHQgPSBhd2FpdCByZXNwb25zZS50ZXh0KCk7XG4gIGlmICghdGV4dCkgcmV0dXJuIHRleHQ7IC8vIFJlc3VsdCBvZiBzdG9yZSBjYW4gYmUgZW1wdHkuXG4gIHJldHVybiBKU09OLnBhcnNlKHRleHQpO1xufVxuXG5jb25zdCBTdG9yYWdlID0ge1xuICBnZXQgb3JpZ2luKCkgeyByZXR1cm4gb3JpZ2luOyB9LFxuICB0YWdQYXRoLFxuICBta2RpcixcbiAgdXJpKGNvbGxlY3Rpb25OYW1lLCB0YWcpIHtcbiAgICAvLyBQYXRobmFtZSBleHBlY3RlZCBieSBvdXIgc2lnbmVkLWNsb3VkLXNlcnZlci5cbiAgICByZXR1cm4gYCR7b3JpZ2lufS9kYi8ke3RoaXMudGFnUGF0aChjb2xsZWN0aW9uTmFtZSwgdGFnKX1gO1xuICB9LFxuICBzdG9yZShjb2xsZWN0aW9uTmFtZSwgdGFnLCBzaWduYXR1cmUsIG9wdGlvbnMgPSB7fSkge1xuICAgIC8vIFN0b3JlIHRoZSBzaWduZWQgY29udGVudCBvbiB0aGUgc2lnbmVkLWNsb3VkLXNlcnZlciwgcmVqZWN0aW5nIGlmXG4gICAgLy8gdGhlIHNlcnZlciBpcyB1bmFibGUgdG8gdmVyaWZ5IHRoZSBzaWduYXR1cmUgZm9sbG93aW5nIHRoZSBydWxlcyBvZlxuICAgIC8vIGh0dHBzOi8va2lscm95LWNvZGUuZ2l0aHViLmlvL2Rpc3RyaWJ1dGVkLXNlY3VyaXR5LyNzdG9yaW5nLWtleXMtdXNpbmctdGhlLWNsb3VkLXN0b3JhZ2UtYXBpXG4gICAgcmV0dXJuIGZldGNoKHRoaXMudXJpKGNvbGxlY3Rpb25OYW1lLCB0YWcpLCB7XG4gICAgICBtZXRob2Q6ICdQVVQnLFxuICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoc2lnbmF0dXJlKSxcbiAgICAgIGhlYWRlcnM6IHsnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nLCAuLi4ob3B0aW9ucy5oZWFkZXJzIHx8IHt9KX1cbiAgICB9KS50aGVuKHJlc3BvbnNlSGFuZGxlcik7XG4gIH0sXG4gIHJldHJpZXZlKGNvbGxlY3Rpb25OYW1lLCB0YWcsIG9wdGlvbnMgPSB7fSkge1xuICAgIC8vIFdlIGRvIG5vdCB2ZXJpZnkgYW5kIGdldCB0aGUgb3JpZ2luYWwgZGF0YSBvdXQgaGVyZSwgYmVjYXVzZSB0aGUgY2FsbGVyIGhhc1xuICAgIC8vIHRoZSByaWdodCB0byBkbyBzbyB3aXRob3V0IHRydXN0aW5nIHVzLlxuICAgIHJldHVybiBmZXRjaCh0aGlzLnVyaShjb2xsZWN0aW9uTmFtZSwgdGFnKSwge1xuICAgICAgY2FjaGU6ICdkZWZhdWx0JyxcbiAgICAgIGhlYWRlcnM6IHsnQWNjZXB0JzogJ2FwcGxpY2F0aW9uL2pzb24nLCAuLi4ob3B0aW9ucy5oZWFkZXJzIHx8IHt9KX1cbiAgICB9KS50aGVuKHJlc3BvbnNlSGFuZGxlcik7XG4gIH1cbn07XG5leHBvcnQgZGVmYXVsdCBTdG9yYWdlO1xuIiwidmFyIHByb21wdGVyID0gcHJvbXB0U3RyaW5nID0+IHByb21wdFN0cmluZztcbmlmICh0eXBlb2Yod2luZG93KSAhPT0gJ3VuZGVmaW5lZCcpIHtcbiAgcHJvbXB0ZXIgPSB3aW5kb3cucHJvbXB0O1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZ2V0VXNlckRldmljZVNlY3JldCh0YWcsIHByb21wdFN0cmluZykge1xuICByZXR1cm4gcHJvbXB0U3RyaW5nID8gKHRhZyArIHByb21wdGVyKHByb21wdFN0cmluZykpIDogdGFnO1xufVxuIiwiaW1wb3J0IGRpc3BhdGNoIGZyb20gJ0BraTFyMHkvanNvbnJwYyc7XG5pbXBvcnQgU3RvcmFnZSBmcm9tICcuL2xpYi9zdG9yYWdlLm1qcyc7XG5pbXBvcnQge2dldFVzZXJEZXZpY2VTZWNyZXR9IGZyb20gJy4vbGliL3NlY3JldC5tanMnO1xuXG5jb25zdCBlbnRyeVVybCA9IG5ldyBVUkwoaW1wb3J0Lm1ldGEudXJsKSxcbiAgICAgIHZhdWx0VXJsID0gbmV3IFVSTCgndmF1bHQuaHRtbCcsIGVudHJ5VXJsKSxcbiAgICAgIHZhdWx0TmFtZSA9ICd2YXVsdCEnICsgZW50cnlVcmwuaHJlZiAvLyBIZWxwcyBkZWJ1Z2dpbmcuXG5cbi8vIE91dGVyIGxheWVyIG9mIHRoZSB2YXVsdCBpcyBhbiBpZnJhbWUgdGhhdCBlc3RhYmxpc2hlcyBhIGJyb3dzaW5nIGNvbnRleHQgc2VwYXJhdGUgZnJvbSB0aGUgYXBwIHRoYXQgaW1wb3J0cyB1cy5cbmNvbnN0IGlmcmFtZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2lmcmFtZScpLFxuICAgICAgY2hhbm5lbCA9IG5ldyBNZXNzYWdlQ2hhbm5lbCgpLFxuICAgICAgcmVzb3VyY2VzRm9ySWZyYW1lID0gT2JqZWN0LmFzc2lnbih7IC8vIFdoYXQgdGhlIHZhdWx0IGNhbiBwb3N0TWVzc2FnZSB0byB1cy5cbiAgICAgICAgbG9nKC4uLmFyZ3MpIHsgY29uc29sZS5sb2coLi4uYXJncyk7IH0sXG4gICAgICAgIGdldFVzZXJEZXZpY2VTZWNyZXRcbiAgICAgIH0sIFN0b3JhZ2UpLFxuICAgICAgLy8gU2V0IHVwIGEgcHJvbWlzZSB0aGF0IGRvZXNuJ3QgcmVzb2x2ZSB1bnRpbCB0aGUgdmF1bHQgcG9zdHMgdG8gdXMgdGhhdCBpdCBpcyByZWFkeSAod2hpY2ggaW4gdHVybiwgd29uJ3QgaGFwcGVuIHVudGlsIGl0J3Mgd29ya2VyIGlzIHJlYWR5KS5cbiAgICAgIHJlYWR5ID0gbmV3IFByb21pc2UocmVzb2x2ZSA9PiB7XG4gICAgICAgIHJlc291cmNlc0ZvcklmcmFtZS5yZWFkeSA9IHJlc29sdmUsXG4gICAgICAgIGlmcmFtZS5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnO1xuICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZChpZnJhbWUpOyAvLyBCZWZvcmUgcmVmZXJlbmNpbmcgaXRzIGNvbnRlbnRXaW5kb3cuXG4gICAgICAgIGlmcmFtZS5zZXRBdHRyaWJ1dGUoJ3NyYycsIHZhdWx0VXJsKTtcbiAgICAgICAgaWZyYW1lLmNvbnRlbnRXaW5kb3cubmFtZSA9IHZhdWx0TmFtZTtcbiAgICAgICAgLy8gSGFuZCBhIHByaXZhdGUgY29tbXVuaWNhdGlvbiBwb3J0IHRvIHRoZSBmcmFtZS5cbiAgICAgICAgY2hhbm5lbC5wb3J0MS5zdGFydCgpO1xuICAgICAgICBpZnJhbWUub25sb2FkID0gKCkgPT4gaWZyYW1lLmNvbnRlbnRXaW5kb3cucG9zdE1lc3NhZ2UodmF1bHROYW1lLCB2YXVsdFVybC5vcmlnaW4sIFtjaGFubmVsLnBvcnQyXSk7XG4gICAgICB9KSxcbiAgICAgIHBvc3RJZnJhbWUgPSBkaXNwYXRjaCh7ICAvLyBwb3N0TWVzc2FnZSB0byB0aGUgdmF1bHQsIHByb21pc2luZyB0aGUgcmVzcG9uc2UuXG4gICAgICAgIGRpc3BhdGNoZXJMYWJlbDogJ2VudHJ5IScgKyBlbnRyeVVybC5ocmVmLFxuICAgICAgICBuYW1lc3BhY2U6IHJlc291cmNlc0ZvcklmcmFtZSxcbiAgICAgICAgdGFyZ2V0OiBjaGFubmVsLnBvcnQxLFxuICAgICAgICB0YXJnZXRMYWJlbDogdmF1bHROYW1lXG4gICAgICB9KSxcblxuICAgICAgYXBpID0geyAvLyBFeHBvcnRlZCBmb3IgdXNlIGJ5IHRoZSBhcHBsaWNhdGlvbi5cbiAgICAgICAgc2lnbihtZXNzYWdlLCAuLi50YWdzKSB7IHJldHVybiBwb3N0SWZyYW1lKCdzaWduJywgbWVzc2FnZSwgLi4udGFncyk7IH0sXG4gICAgICAgIHZlcmlmeShzaWduYXR1cmUsIC4uLnRhZ3MpIHsgcmV0dXJuIHBvc3RJZnJhbWUoJ3ZlcmlmeScsIHNpZ25hdHVyZSwgLi4udGFncyk7IH0sXG4gICAgICAgIGVuY3J5cHQobWVzc2FnZSwgLi4udGFncykgeyByZXR1cm4gcG9zdElmcmFtZSgnZW5jcnlwdCcsIG1lc3NhZ2UsIC4uLnRhZ3MpOyB9LFxuICAgICAgICBkZWNyeXB0KGVuY3J5cHRlZCwgLi4udGFncykgeyByZXR1cm4gcG9zdElmcmFtZSgnZGVjcnlwdCcsIGVuY3J5cHRlZCwgLi4udGFncyk7IH0sXG4gICAgICAgIGNyZWF0ZSguLi5vcHRpb25hbE1lbWJlcnMpIHsgcmV0dXJuIHBvc3RJZnJhbWUoJ2NyZWF0ZScsIC4uLm9wdGlvbmFsTWVtYmVycyk7IH0sXG4gICAgICAgIGNoYW5nZU1lbWJlcnNoaXAoe3RhZywgYWRkLCByZW1vdmV9ID0ge30pIHsgcmV0dXJuIHBvc3RJZnJhbWUoJ2NoYW5nZU1lbWJlcnNoaXAnLCB7dGFnLCBhZGQsIHJlbW92ZX0pOyB9LFxuICAgICAgICBkZXN0cm95KHRhZ09yT3B0aW9ucykgeyByZXR1cm4gcG9zdElmcmFtZSgnZGVzdHJveScsIHRhZ09yT3B0aW9ucyk7IH0sXG4gICAgICAgIGNsZWFyKHRhZyA9IG51bGwpIHsgcmV0dXJuIHBvc3RJZnJhbWUoJ2NsZWFyJywgdGFnKTsgfSxcbiAgICAgICAgcmVhZHksXG5cbiAgICAgICAgLy8gQXBwbGljYXRpb24gYXNzaWducyB0aGVzZSBzbyB0aGF0IHRoZXkgY2FuIGJlIHVzZWQgYnkgdGhlIHZhdWx0LlxuICAgICAgICBnZXQgU3RvcmFnZSgpIHsgcmV0dXJuIHJlc291cmNlc0ZvcklmcmFtZTsgfSxcbiAgICAgICAgc2V0IFN0b3JhZ2Uoc3RvcmFnZSkgeyBPYmplY3QuYXNzaWduKHJlc291cmNlc0ZvcklmcmFtZSwgc3RvcmFnZSk7IH0sXG4gICAgICAgIGdldCBnZXRVc2VyRGV2aWNlU2VjcmV0KCkgeyByZXR1cm4gcmVzb3VyY2VzRm9ySWZyYW1lLmdldFVzZXJEZXZpY2VTZWNyZXQ7IH0sXG4gICAgICAgIHNldCBnZXRVc2VyRGV2aWNlU2VjcmV0KGZ1bmN0aW9uT2ZUYWdBbmRQcm9tcHQpIHsgcmVzb3VyY2VzRm9ySWZyYW1lLmdldFVzZXJEZXZpY2VTZWNyZXQgPSBmdW5jdGlvbk9mVGFnQW5kUHJvbXB0OyB9XG4gICAgICB9O1xuXG5leHBvcnQgZGVmYXVsdCBhcGk7XG4iXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQ0EsU0FBUyxrQkFBa0IsQ0FBQyxLQUFLLEVBQUU7QUFDbkMsRUFBRSxJQUFJLENBQUMsSUFBSSxFQUFFLE9BQU8sRUFBRSxJQUFJLEVBQUUsSUFBSSxDQUFDLEdBQUcsS0FBSyxDQUFDO0FBQzFDLEVBQUUsT0FBTyxDQUFDLElBQUksRUFBRSxPQUFPLEVBQUUsSUFBSSxFQUFFLElBQUksQ0FBQyxDQUFDO0FBQ3JDLENBQUM7QUFDRDtBQUNBO0FBQ0EsU0FBUyxRQUFRLENBQUMsQ0FBQyxNQUFNLEdBQUcsSUFBSTtBQUNoQyxLQUFLLFFBQVEsR0FBRyxNQUFNO0FBQ3RCLEtBQUssU0FBUyxHQUFHLFFBQVE7QUFDekI7QUFDQSxLQUFLLE1BQU0sSUFBSSxDQUFDLE1BQU0sS0FBSyxRQUFRLEtBQUssTUFBTSxDQUFDLFFBQVEsQ0FBQyxNQUFNLENBQUM7QUFDL0Q7QUFDQSxLQUFLLGVBQWUsR0FBRyxTQUFTLENBQUMsSUFBSSxJQUFJLFFBQVEsQ0FBQyxJQUFJLElBQUksUUFBUSxDQUFDLFFBQVEsRUFBRSxJQUFJLElBQUksUUFBUTtBQUM3RixLQUFLLFdB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
