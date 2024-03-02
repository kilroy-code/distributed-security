import dispatch from './dependency/jsonrpc.mjs';

const url = import.meta.url,
      vaultUrl = new URL('vault.html', url),
      iframe = document.createElement('iframe'),
      resourcesForIframe = { // What the vault can postMessage to us.
	log(...args) { console.log(...args); }
	// Will also get store & retrieve, and getUserDeviceSecret, provided by the application,
	// and a promise resolver set by us that the vault will use to indicate that it is ready.
      },
      api = {
	sign(message, ...tags) { return postIframe('sign', message, ...tags); },
	verify(signature, ...tags) { return postIframe('verify', signature, ...tags); },
	encrypt(message, ...tags) { return postIframe('encrypt', message, ...tags); },
	decrypt(encrypted, ...tags) { return postIframe('decrypt', encrypted, ...tags); },
	create(...optionalMembers) { return postIframe('create', ...optionalMembers); },
	changeMembership({tag, add, remove} = {}) { return postIframe('changeMembership', {tag, add, remove}); },
	destroy(tagOrOptions) { return postIframe('destroy', tagOrOptions); },
	clear(tag = null) { return postIframe('clear', tag); },

	// Application assigns these so that they can be used by the vault.
	set Storage(storage) { Object.assign(resourcesForIframe, storage); },
	set getUserDeviceSecret(thunk) { resourcesForIframe.getUserDeviceSecret = thunk; },

	// Ready doesn't resolve until the vault posts to us that it is ready.
	ready: new Promise(resolve => {

	  // TODO: Make these css rules that the application can override.
	  iframe.setAttribute('width', '100%'); // When using a free reverse proxy service like ngrok, there may be a click through. Give enough space to read it.
	  iframe.style.display = 'none'; // TODO: make an overridable css rule, so that developers can show it if they want.

	  document.body.append(iframe); // Before referencing its contentWindow.
	  resourcesForIframe.ready = resolve;
	  iframe.setAttribute('src', vaultUrl);
	})
      },

      // postMessage to the vault, promising the response.
      postIframe = dispatch({
	dispatcherLabel: url,
	target: iframe.contentWindow,
	targetLabel: 'vault',
	receiver: self,
	origin: vaultUrl.origin,
	namespace: resourcesForIframe});

export default api;
