import Krypto from "./krypto.mjs";
import * as JOSE from '../node_modules/jose/dist/browser/index.js';

const signingAlgorithm = 'ES384',
      encryptingAlgorithm = 'RSA-OAEP-256',
      symmetricAlgorithm = 'A256GCM',
      symmetricWrap = 'A256GCMKW',
      secretAlgorithm = 'PBES2-HS512+A256KW';

function mismatch(kid, encodedKid) {
  let message = `Key ${kid} does not match encoded ${encodedKid}.`;
  return Promise.reject(message);
}

const MultiKrypto = {
  isMultiKey(key) { // A SubtleCrypto CryptoKey is an object with a type property. Our multikeys are
    // objects with a specific type or no type property at all.
    return (key.type || 'multi') === 'multi';
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

  // Signing is split out into steps.
  startSign(baseHeader, message) {
    let inputBuffer = this.inputBuffer(message, baseHeader),
	jws = new JOSE.GeneralSign(inputBuffer);
    return jws;
  },
  addSignature(baseHeader, tag, thisKey, jws) {
    let alg = signingAlgorithm,
	header = Object.assign({kid: tag, alg}, baseHeader);
    jws.addSignature(thisKey).setProtectedHeader(header);
  },
  async finishSignature(jws) {
    let signed = await jws.sign();
    return JSON.stringify(signed);
  },
  async sign(key, message) {
    if (!this.isMultiKey(key)) return super.sign(key, message);
    // key must be a dictionary mapping tags to signing keys, or header keys to values.
    let {type, iss, act, iat, cty, ...keys} = key,
	baseHeader = {cty, iss, act, iat},
	jws = this.startSign(baseHeader, message);
    for (let tag of Object.keys(keys)) {
      this.addSignature(baseHeader, tag, key[tag], jws);
    }
    return await this.finishSignature(jws);
  },
  async verify(key, signature) {
    if (!this.isMultiKey(key)) return super.verify(key, signature);
    // key must be a dictionary mapping tags to verifying keys, which much exactly correspond to signature kids (except for order).
    // Answer includes protectedHeaders -- which is the protected header of the first sig, without kid and alg. (We don't check for matching.)
    // Answer also includes headers -- which is an array of the kid and alg of each contained signature.
    if (!signature.startsWith('{')) return;
    let jws = JSON.parse(signature),
	{signatures} = jws,
	{type, iss, act, iat, cty, ...unmatchedSubkeys} = key,
	promises = signatures.map(async subSignature => {
	  let {kid} = JOSE.decodeProtectedHeader(subSignature),
	      subResult = await JOSE.generalVerify(jws, key[kid]),
	      resultKid = subResult.protectedHeader.kid;
	  if (resultKid !== kid) return mismatch(kid, resultKid);
	  delete unmatchedSubkeys[kid];
	  return subResult;
	}),
	result = await Promise.all(promises).catch(() => undefined),
	remainingSubkeys = Object.keys(unmatchedSubkeys);
    if (!result || remainingSubkeys.length) return undefined;
    let combined = result[0],
	header = combined.protectedHeader,
	headers = result.map(sub => ({kid: sub.protectedHeader.kid, alg: sub.protectedHeader.alg}));
    combined.headers = headers;
    delete header.kid;
    delete header.alg;
    return this.recoverDataFromContentType(combined);
  },

  async encrypt(key, message) {
    if (!this.isMultiKey(key)) return super.encrypt(key, message);
    // key must be a dictionary mapping tags to encrypting keys.
    let jwe = new JOSE.GeneralEncrypt(new TextEncoder().encode(message)).setProtectedHeader({enc: symmetricAlgorithm });
    for (let tag of Object.keys(key)) {
      if (tag === 'type') continue;
      let thisKey = key[tag],
	  isString = 'string' === typeof thisKey,
	  isSym = isString || this.isSymmetric(thisKey),
	  secret = isString ? new TextEncoder().encode(thisKey) : this.keySecret(thisKey),
	  alg = isString ? secretAlgorithm : (isSym ? symmetricWrap : encryptingAlgorithm);
      // The kid and alg are per/sub-key, and so cannot be signed by all, and so cannot be protected within the encryption.
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
	unwrappingPromises = recipients.map(async ({header}) => {
	  let {kid} = header,
	      unwrappingKey = key[kid],
	      options = {};
	  if (!unwrappingKey) return Promise.reject('missing');
	  if ('string' === typeof unwrappingKey) { // TODO: only specified if allowed by secure header
	    unwrappingKey = new TextEncoder().encode(unwrappingKey);
	    options.keyManagementAlgorithms = [secretAlgorithm];
	  }
	  let result = await JOSE.generalDecrypt(jwe, this.keySecret(unwrappingKey), options),
	      encodedKid = result.unprotectedHeader.kid;
	  if (encodedKid !== kid) return mismatch(kid, encodedKid);
	  return result;
	}),
	// Do we really want to return undefined if everything fails? Should just allow the rejection to propagate?
	plaintext = await Promise.any(unwrappingPromises).then(result => result.plaintext, fail => undefined);
    return plaintext && new TextDecoder().decode(plaintext);
  }
};
Object.setPrototypeOf(MultiKrypto, Krypto);
export default MultiKrypto;
