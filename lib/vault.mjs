import dispatch from '@kilroy-code/jsonrpc';

// We don't just blindly forward messages in either direction. There is a specific set of operations.
const url = import.meta.url,

      api = { // jsonrpc requests from the client are handled by these, which answers them by making requests to the worker.
        sign(message, ...tags) { return postWorker('sign', message, ...tags); },
        verify(signature, ...tags) { return postWorker('verify', signature, ...tags); },
        encrypt(message, ...tags) { return postWorker('encrypt', message, ...tags); },
        decrypt(encrypted, ...tags) { return postWorker('decrypt', encrypted, ...tags); },
        create(...optionalMembers) { return postWorker('create', ...optionalMembers); },
        changeMembership(options) { return postWorker('changeMembership', options); },
        destroy(tagOrOptions) { return postWorker('destroy', tagOrOptions); },
        clear(tag) { return postWorker('clear', tag); }
      },

      hostAPI = { // jsonrpc request from the worker are handled by thise, which answers them by make requests to the client.
        store(resourceTag, ownerTag, signature) {
          return postClient('store', resourceTag, ownerTag, signature);
        },
        retrieve(resourceTag, ownerTag) {
          return postClient('retrieve', resourceTag, ownerTag);
        },
        getUserDeviceSecret(...args) {
          return postClient('getUserDeviceSecret', ...args);
        },
        ready(label) {
          postClient('ready', label);
        }
      },

      // Sets up the jsonrpc  connection to the client (index.mjs).
      hostOrigin = document.referrer ? new URL(document.referrer).origin : '*',
      postClient = dispatch({
        dispatcherLabel: url,
        target: parent,
        targetLabel: 'entry',
        receiver: self,
        namespace: api,
        origin: hostOrigin
      }),

      // Sets up the jsonrpc connection to the worker.
      vaultOrigin = new URL('worker-bundle.mjs', url),
      worker = new Worker(vaultOrigin, {type: 'module'}),
      postWorker = dispatch({
        dispatcherLabel: url,
        target: worker,
        targetLabel: 'worker',
        namespace: hostAPI
      });

