import Krypto from "./krypto.mjs";
import * as JOSE from "../dependency/jose.mjs";

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
    return await jws.sign();
  },
  keyTags(key) {
    return Object.keys(key).filter(key => key !== 'type');
  },
  async sign(key, message, header = {}) {
    if (!this.isMultiKey(key)) return super.sign(key, message, header);
    let jws = this.startSign(header, message);
    for (let tag of this.keyTags(key)) {
      this.addSignature(header, tag, key[tag], jws);
    }
    return await this.finishSignature(jws);
  },
  verifySubSignature(jws, signatureElement, multiKey, kids) {
    // Verify a single element of jws.signature using multiKey.
    // Always promises {protectedHeader, unprotectedHeader, kid, payload}, even if verification fails,
    // where kid is the property name within multiKey that matched (either by being specified in a header
    // or by successful verification), and payload is the decoded payload IFF there is a match.
    let protectedHeader = signatureElement.protectedHeader ?? JOSE.decodeProtectedHeader(signatureElement),
	unprotectedHeader = signatureElement.unprotectedHeader,
	kid = protectedHeader?.kid || unprotectedHeader?.kid,
	singleJWS = Object.assign({}, jws, {signatures: [signatureElement]}),
	failureResult = {protectedHeader, unprotectedHeader, kid},
	kidsToTry = kid ? [kid] : kids;
    let promise = Promise.any(kidsToTry.map(async kid => JOSE.generalVerify(singleJWS, multiKey[kid]).then(result => Object.assign({kid}, result))));
    return promise.catch(() => failureResult);
  },
  async verify(key, signature, options = {}) {
    if (!this.isMultiKey(key)) return super.verify(key, signature, options);
    if (!signature.signatures) return;

    // Comparison to panva JOSE.generalVerify.
    // JOSE takes a jws and ONE key and answers {payload, protectedHeader, unprotectedHeader} matching the one
    // jws.signature element that was verified, otherise an eror. (It tries each of the elements of the jws.signatures.)
    // It is not generally possible to know WHICH one of the jws.signatures was matched.
    // (It MAY be possible if there are unique kid elements, but that's application-dependent.)
    //
    // MultiKrypto takes a dictionary that contains named keys and recognizedHeader properties, and it returns
    // a result only if ALL the named key values verify, otherwise the value undefined. If a jws.signature element
    // has a 'kid' header (protected or not), it will only be matched by the key with that name in the dictionary.
    //
    // Additionally if a result is produced:
    // - The protectedHeader and unprotectedHeader contains only values that were common to each of the verified signature elements.
    // - An additional value is produced called signers, whose elements correspond to the signatures of the original JWS.
    //   Each signer element contains {protectedHeader, unprotectedHeader, kid, payload}, where payload is undefined
    //   if that signer was not verified.
    // It is up to the caller to decide if the result is acceptable for the application. For example, the caller might
    // want to see if there are signers or protectedHeader values that are not represented in key.
    let jws = signature,
	kids = this.keyTags(key),
	signers = await Promise.all(jws.signatures.map(signature => this.verifySubSignature(jws, signature, key, kids)));
    if (!signers.find(signer => signer.payload)) return undefined;
    // Now canonicalize the signers and build up a result.
    let [first, ...rest] = signers,
	result = {protectedHeader: {}, unprotectedHeader: {}, signers},
	// For a header value to be common to verified results, it must be in the first result.
	getUnique = categoryName => {
	  let firstHeader = first[categoryName],
	      accumulatorHeader = result[categoryName];
	  for (let label in firstHeader) {
	    let value = firstHeader[label];
	    if (rest.some(signerResult => signerResult[categoryName][label] !== value)) continue;
	    accumulatorHeader[label] = value;
	  }
	};
    getUnique('protectedHeader');
    getUnique('protectedHeader');
    // If anything verified, then set payload and allow text/json to be produced.
    // Callers can check signers[n].payload to determine if the result is what they want.
    result.payload = signers.find(signer => signer.payload).payload;
    return this.recoverDataFromContentType(result, options);
  },

  async encrypt(key, message, headers = {}) {
    if (!this.isMultiKey(key)) return super.encrypt(key, message, headers);
    // key must be a dictionary mapping tags to encrypting keys.
    let baseHeader = Object.assign({enc: symmetricAlgorithm}, headers),
	inputBuffer = this.inputBuffer(message, baseHeader),
	jwe = new JOSE.GeneralEncrypt(inputBuffer).setProtectedHeader(baseHeader);
    for (let tag of this.keyTags(key)) {
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
    return encrypted;
  },
  async decrypt(key, encrypted, options) {
    if (!this.isMultiKey(key)) return super.decrypt(key, encrypted, options);
    let jwe = encrypted,
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
	});
    // Do we really want to return undefined if everything fails? Should just allow the rejection to propagate?
    return await Promise.any(unwrappingPromises).then(
      result => {
	this.recoverDataFromContentType(result, options);
	return result;
      },
      fail => undefined);
  }
};
Object.setPrototypeOf(MultiKrypto, Krypto);
export default MultiKrypto;
