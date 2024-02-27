import dispatch from '../jsonrpc/index.mjs';

const vaultUrl = new URL('vault.html', import.meta.url),
      iframe = document.createElement('iframe'),
      resourcesForIframe = {
	log(...args) { console.log(...args); }
      }, // Will get handlers for messages from the iframe.
      api = {
	sign(message, ...tags) { return postIframe('sign', message, ...tags); },
	verify(signature, ...tags) { return postIframe('verify', signature, ...tags); },
	encrypt(message, ...tags) { return postIframe('encrypt', message, ...tags); },
	decrypt(encrypted, tag) { return postIframe('decrypt', encrypted, tag); },
	create(...optionalMembers) { return postIframe('create', ...optionalMembers); },
	changeMembership({tag, add, remove} = {}) { return postIframe('changeMembership', {tag, add, remove}); },
	destroy(tagOrOptions) { return postIframe('destroy', tagOrOptions); },
	clear(tag = null) { return postIframe('clear', tag); },

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
