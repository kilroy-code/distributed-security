import Krypto from "./krypto.mjs";

const MultiKrypto = {
  isMultiKey(key) { // A SubtleCrypto CryptoKey is an object with a type property. Our multikeys are
    // objects with a specific type or no type property at all.
    return (key.type || 'multi') === 'multi';
  },
  mapAllTagsInParallel(from, to, operator) {
    let tags = Object.keys(from),
	wrappingPromises = tags.map(tag => {
	  if (tag === 'type') return;
	  return operator(from[tag], tag).then(result => to[tag] = result);
	}),
	promise = Promise.all(wrappingPromises);
    return promise;
  },
  async exportKey(key) {
    if (!this.isMultiKey(key)) return super.exportKey(key);
    let roster = {};
    await this.mapAllTagsInParallel(key, roster, memberKey => this.exportKey(memberKey));
    return JSON.stringify(roster);
  },
  async importKey(exported, use) {
    if (!exported.startsWith('{')) return super.importKey(exported, use);
    let roster = JSON.parse(exported),
	key = {},
	isSingleUse = typeof use === 'string';
    await this.mapAllTagsInParallel(roster, key, (exportedMember, memberTag) => this.importKey(exportedMember, isSingleUse ? use : use[memberTag]));
    return key;
  },
  async encrypt(key, message) {
    if (key.type === 'public') { // The Krypto way of encrypting with a public key will only work
      // (be decryptable) for messages up to 446 bytes! Instead, MultiKrypto always generates a symmetric
      // key to encrypt the message, and uses the public key to encrypt just the symmetric key.
      let symmetric = await this.generateSymmetricKey(),
	  wrapped = await Krypto.wrapKey(symmetric, key);
      return wrapped + '.' + await super.encrypt(symmetric, message);
    }
    if (!this.isMultiKey(key)) return super.encrypt(key, message);
    // key must be a dictionary mapping tags to encrypting keys.
    // Answer a JSON string of {roster, body}, in which
    // body is the encryption of message using one-time-use symmetric secret.
    // roster is a dictionary mapping each tag from the multikey to the secret wrapped specifically for the given tag's key.
    let secret = await this.generateSymmetricKey(),
	body = await this.encrypt(secret, message),
	roster = {},
	result = {roster, body};
    await this.mapAllTagsInParallel(key, roster, wrappingKey => this.wrapKey(secret, wrappingKey));
    return JSON.stringify(result);
  },
  async decrypt(key, encrypted) {
    if (key.type === 'private') {
      let [wrapped, body] = encrypted.split('.'),
	  symmetric = await Krypto.unwrapKey(wrapped, key, 'symmetric');
      return super.decrypt(symmetric, body);
    }
    if (!this.isMultiKey(key)) return super.decrypt(key, encrypted);
    // key must be a dictionary mapping tags to decrypting keys, and encrypted must be as produced by encrypting with a multi key.
    // If any of the decrypting keys are able to decrypt the secret, the body is decrypted with that secret.
    let {roster, body} = JSON.parse(encrypted),
	// Different from mapAllTagsInParallel in that we will decrypt with just the first one that unwraps.
	tags = Object.keys(key),
	unwrappingPromises = tags.map(tag => {
	  if (tag === 'type') return Promise.reject('skipped type tag');
	  let unwrappingKey = key[tag],
	      encryptedSecret = roster[tag];
	  if (!encryptedSecret) return Promise.reject('missing');
	  return this.unwrapKey(encryptedSecret, unwrappingKey, 'symmetric');
	});
    return Promise.any(unwrappingPromises).then(
      secret => this.decrypt(secret, body),
      fail => undefined
    );
  }
};
Object.setPrototypeOf(MultiKrypto, Krypto);
export default MultiKrypto;
