const VaultedSecurity = {
  worker: new Worker('/@kilroy-code/distributed-security/worker.mjs', {type: "module"}),
  requests: {},
  messageId: 0,
  send(method, ...params) {
    let id = ++this.messageId,
	request = this.requests[id] = {};
    return new Promise((resolve, reject) => {
      Object.assign(request, {resolve, reject, method});
      this.worker.postMessage({id, method, params});
    });
  },
  create(optionalMembers) {
    return this.send('create', optionalMembers);
  },
  verify(tag, signature, message) { // Promise true if signature was made by tag, else false.
    return this.send('verify', tag, signature, message);
  },
  async encrypt(tag, message) { // Promise text that can only be decrypted back to message by the keypair designated by tag.
    return this.send('encrypt', tag, message);
  },
  async decrypt(tag, encrypted) { // Promise the original text given to encrypt() IFF the current user has access to the keypair designated by tag, else reject.
    return this.send('decrypt', tag, encrypted);
  },
  async sign(tag, message) { // Promise a signature for message suitable for verify() IFF the current user has access to the keypair designated by tag, else reject.
    return this.send('sign', tag, message);
  },
  async destroy(tag) { //
    return this.send('destroy', tag);
  }
};

VaultedSecurity.worker.onmessage = event => {
  // FIXME: check event.origin. But don't we get that automatically when we switch to shared worker and ports? Also use worker-src 'self'
  let {id, result, error} = event.data,
      request = VaultedSecurity.requests[id];
  delete VaultedSecurity.requests[id];
  if (error) request.reject(error);
  else request.resolve(result);
};

export default VaultedSecurity;
