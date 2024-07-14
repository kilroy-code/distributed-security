import dispatch from '@ki1r0y/jsonrpc';
import Storage from './lib/storage.mjs';
import {getUserDeviceSecret} from './lib/secret.mjs';
import {hashBuffer, hashText, encodeBase64url, decodeBase64url} from './lib/utilities.mjs';

const entryUrl = new URL(import.meta.url),
      vaultUrl = new URL('vault.html', entryUrl),
      cloudName = entryUrl.href;

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
        // Hand a private communication port to the frame.
        channel.port1.start();
        iframe.onload = () => iframe.contentWindow.postMessage(cloudName, vaultUrl.origin, [channel.port2]);
      }),
      postIframe = dispatch({  // postMessage to the vault, promising the response.
        dispatcherLabel: 'entry!' + cloudName,
        namespace: resourcesForIframe,
        target: channel.port1,
        targetLabel: 'vault!' + cloudName
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

        // Utilities.
        hashBuffer, hashText, encodeBase64url, decodeBase64url,

        // Application assigns these so that they can be used by the vault.
        get Storage() { return resourcesForIframe; },
        set Storage(storage) { Object.assign(resourcesForIframe, storage); },
        get getUserDeviceSecret() { return resourcesForIframe.getUserDeviceSecret; },
        set getUserDeviceSecret(functionOfTagAndPrompt) { resourcesForIframe.getUserDeviceSecret = functionOfTagAndPrompt; }
      };

export default api;
