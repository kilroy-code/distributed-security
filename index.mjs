import Storage from './lib/storage.mjs';
import dispatch from '@kilroy-code/jsonrpc/index.mjs';
const worker = new Worker('@kilroy-code/distributed-security/lib/worker.mjs', {type: 'module'});

// Do we need this? Errors that occur in the evalution of a jsonrpc message posted to the worker will come back as a jsonrpc error,
// and thus a rejected promise from request. However, error asynchronous to that will, I think come here:
worker.onerror = error => console.error(`${error.filename}:${error.lineno} - ${error.message}`);

const VaultedSecurity = {
  request: dispatch({target: worker, namespace: Storage}),
  create(...optionalMembers) {
    return this.request('create', ...optionalMembers);
  },
  verify(tag, signature, message) { // Promise true if signature was made by tag, else false.
    return this.request('verify', tag, signature, message);
  },
  async encrypt(tag, message) { // Promise text that can only be decrypted back to message by the keypair designated by tag.
    return this.request('encrypt', tag, message);
  },
  async decrypt(tag, encrypted) { // Promise the original text given to encrypt() IFF the current user has access to the keypair designated by tag, else reject.
    return this.request('decrypt', tag, encrypted);
  },
  async sign(tag, message) { // Promise a signature for message suitable for verify() IFF the current user has access to the keypair designated by tag, else reject.
    return this.request('sign', tag, message);
  },
  async destroy(tag) { //
    return this.request('destroy', tag);
  }
};
export default VaultedSecurity;
