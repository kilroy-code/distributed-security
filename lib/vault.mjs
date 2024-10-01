import dispatch from '@ki1r0y/jsonrpc';

// The vault is this code running in an iframe, which does nothing but communicate messages
// to the parent entry, and to a worker launched within the frame.

// We don't just blindly forward messages in either direction. There is a specific set of operations.

// Here is the jsonrpc connection back towards the client (index.mjs).
onmessage = event => {
  onmessage = null; // Once set, it cannot be reset.
  const cloudName = event.data, // For debugging, it help to know where we are loaded from.
        vaultName = 'vault!' + cloudName;

  const entryModuleName = 'entry!'+cloudName,
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
        postClient = dispatch({
          target: event.ports[0],
          targetLabel: entryModuleName,
          dispatcherLabel: vaultName,
          namespace: api
        });

  // Here is the jsonrpc connection to the worker.
  const url = import.meta.url,
        vaultOrigin = new URL('worker-bundle.mjs', url),
        workerName = 'worker!'+cloudName,
        worker = new Worker(vaultOrigin, {type: 'module', name: workerName}),
        hostAPI = { // jsonrpc request from the worker are handled by these, which answers them by make requests to the client.
          store(resourceTag, ownerTag, signature) {
            return postClient('store', resourceTag, ownerTag, signature);
          },
          retrieve(resourceTag, ownerTag) {
            return postClient('retrieve', resourceTag, ownerTag);
          },
          getUserDeviceSecret(tag, prompt = '') {
            return postClient('getUserDeviceSecret', tag, prompt);
          },
          ready(label) {
            event.ports[0].start();
            postClient('ready', label);
          }
        },
        postWorker = dispatch({
          target: worker,
          targetLabel: workerName,
          dispatcherLabel: vaultName,
          namespace: hostAPI
        });
};
