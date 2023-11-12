import dispatch from '../jsonrpc/index.mjs';

const vaultUrl = new URL('vault.html', import.meta.url),
      iframe = document.createElement('iframe'),
      resourcesForIframe = {
	log(...args) { console.log(...args); }
      }, // Will get handlers for messages from the iframe.
      api = {
	create(...optionalMembers) { return postIframe('create', ...optionalMembers); },
	encrypt(tag, message) { return postIframe('encrypt', tag, message); },
	decrypt(tag, encrypted) { return postIframe('decrypt', tag, encrypted); },
	sign(tag, message) { return postIframe('sign', tag, message); },
	verify(tag, signature, message) { return postIframe('verify', tag, signature, message); },
	changeMembership(tag, {add, remove} = {}) { return postIframe('changeMembership', tag, {add, remove}); },
	clear(tag = null) { return postIframe('clear', tag); },
	destroy(tag, {recursiveMembers} = {}) { return postIframe('destroy', tag, {recursiveMembers}); },

	set Storage(storage) { Object.assign(resourcesForIframe, storage); },
	set getUserDeviceSecret(thunk) { resourcesForIframe.getUserDeviceSecret = thunk; },
	ready: new Promise((resolve, reject) => {

	  // TODO: Make these css rules that the application can override.
	  iframe.setAttribute('width', '100%'); // When using a free reverse proxy service like ngrok, there may be a click through. Give enough space to read it.
	  iframe.style.display = 'none';

	  document.body.append(iframe); // Before referencing its contentWindow.
	  resourcesForIframe.ready = resolve;
	  iframe.setAttribute('src', vaultUrl);
	})
      },
      postIframe = dispatch({target: iframe.contentWindow, receiver: self, origin: vaultUrl.origin, namespace: resourcesForIframe});

export default api;
