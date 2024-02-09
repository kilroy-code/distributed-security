import Krypto from "./krypto.mjs";
import * as JOSE from '../node_modules/jose/dist/browser/index.js';

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
  async exportJWK(key) {
    if (!this.isMultiKey(key)) return super.exportJWK(key);
    let names = Object.keys(key).filter(name => name !== 'type'),
	keys = await Promise.all(names.map(async name => {
	  let jwk = await this.exportJWK(key[name]);
	  jwk.kid = name;
	  return jwk;
	}));
    return {keys}; // TODO: specify kty or something?
  },
  async importJWK(jwk) {
    if (!jwk.keys) return super.importJWK(jwk);
    let key = {}; // TODO: get type from kty or some such?
    await Promise.all(jwk.keys.map(async jwk => key[jwk.kid] = await this.importJWK(jwk)));
    return key;
  },
  // async exportKey(key) {
  //   if (!this.isMultiKey(key)) return super.exportKey(key);
  //   let roster = {};
  //   await this.mapAllTagsInParallel(key, roster, memberKey => this.exportKey(memberKey));
  //   return JSON.stringify(roster);
  // },
  // async importKey(exported, use) {
  //   if (!exported.startsWith('{')) return super.importKey(exported, use);
  //   let roster = JSON.parse(exported),
  // 	key = {},
  // 	isSingleUse = typeof use === 'string';
  //   await this.mapAllTagsInParallel(roster, key, (exportedMember, memberTag) => this.importKey(exportedMember, isSingleUse ? use : use[memberTag]));
  //   return key;
  // },
  async encrypt(key, message) {
    if (!this.isMultiKey(key)) return super.encrypt(key, message);
    // key must be a dictionary mapping tags to encrypting keys.
    let jwe = new JOSE.GeneralEncrypt(new TextEncoder().encode(message)).setProtectedHeader({enc: 'A256GCM' });
    for (let tag of Object.keys(key)) { // FIXME: tag here is specifically a distributed-security tag. Use another word here/everywhere, such as key or kid
      if (tag === 'type') continue;
      let thisKey = key[tag],
	  isString = 'string' === typeof thisKey,
	  isSym = isString || this.isSymmetric(thisKey),
	  secret = isString ? new TextEncoder().encode(thisKey) : this.keySecret(thisKey),
	  alg = isString ? 'PBES2-HS512+A256KW' : (isSym ? 'A256GCMKW' : 'RSA-OAEP-256');
      // The kid and alg are per/sub-key, and so cannot be signed by all, and so cannot be protected within the signature.
      // This is ok, because the only that can happen as a result of tampering with these is that the decryption will fail,
      // which is the same result as tampering with the ciphertext or any other part of the JWE.
      jwe.addRecipient(secret).setUnprotectedHeader({kid: tag, alg});
    }
    let encrypted = await jwe.encrypt();
    return JSON.stringify(encrypted);
  },
  async decrypt(key, encrypted) {
    if (!this.isMultiKey(key)) return super.decrypt(key, encrypted);
    let jwe = JSON.parse(encrypted),
	{recipients} = jwe,
	unwrappingPromises = recipients.map(({header}) => {
	  let {kid} = header,
	      unwrappingKey = key[kid],
	      options = {};
	  if (!unwrappingKey) return Promise.reject('missing');
	  if ('string' === typeof unwrappingKey) { // TODO: only specified if allowed by secure header
	    unwrappingKey = new TextEncoder().encode(unwrappingKey);
	    options.keyManagementAlgorithms = ['PBES2-HS512+A256KW'];
	  }
	  return JOSE.generalDecrypt(jwe, this.keySecret(unwrappingKey), options)
	    .then(result => {
	      // result.unprotectedHeader is the one that was actually worked. Make sure it matches.
	      if (result.unprotectedHeader.kid !== kid) return Promise.reject('Wrong tag');
	      return result;
	    });
	}),
	// Do we really want to return undefined if everything fails? Should just allow teh rejection to propagate?
	plaintext = await Promise.any(unwrappingPromises).then(result => result.plaintext, fail => undefined);
    return plaintext && new TextDecoder().decode(plaintext);
  }
};
Object.setPrototypeOf(MultiKrypto, Krypto);
export default MultiKrypto;
