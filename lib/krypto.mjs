import * as JOSE from '../node_modules/jose/dist/browser/index.js';

// Some useful JOSE recipes for playing around.
// sk = await JOSE.generateKeyPair('ES384', {extractable: true})
// jwt = await new JOSE.SignJWT().setSubject("foo").setProtectedHeader({alg:'ES384'}).sign(sk.privateKey)
// await JOSE.jwtVerify(jwt, sk.publicKey) //.payload.sub
// 
// message = new TextEncoder().encode('some message')
// jws = await new JOSE.CompactSign(message).setProtectedHeader({alg:'ES384'}).sign(sk.privateKey) // Or FlattenedSign
// jws = await new JOSE.GeneralSign(message).addSignature(sk.privateKey).setProtectedHeader({alg:'ES384'}).sign()
// verified = await JOSE.generalVerify(jws, sk.publicKey)
// or compactVerify or flattenedVerify
// new TextDecoder().decode(verified.payload)  
//
// ek = await JOSE.generateKeyPair('RSA-OAEP-256', {extractable: true})
// jwe = await new JOSE.CompactEncrypt(message).setProtectedHeader({alg: 'RSA-OAEP-256', enc: 'A256GCM' }).encrypt(ek.publicKey)
// or FlattenedEncrypt. For symmetric secret, specify alg:'dir'.
// decrypted = await JOSE.compactDecrypt(jwe, ek.privateKey)
// new TextDecoder().decode(decrypted.plaintext)
// jwe = await new JOSE.GeneralEncrypt(message).setProtectedHeader({alg: 'RSA-OAEP-256', enc: 'A256GCM' }).addRecipient(ek.publicKey).encrypt() // with additional addRecipent() as needed
// decrypted = await JOSE.generalDecrypt(jwe, ek.privateKey)
//
// material = new TextEncoder().encode('secret')
// jwe = await new JOSE.CompactEncrypt(message).setProtectedHeader({alg: 'PBES2-HS512+A256KW', enc: 'A256GCM' }).encrypt(material)
// decrypted = await JOSE.compactDecrypt(jwe, material, {keyManagementAlgorithms: ['PBES2-HS512+A256KW'], contentEncryptionAlgorithms: ['A256GCM']})
// jwe = await new JOSE.GeneralEncrypt(message).setProtectedHeader({alg: 'PBES2-HS512+A256KW', enc: 'A256GCM' }).addRecipient(material).encrypt()
// jwe = await new JOSE.GeneralEncrypt(message).setProtectedHeader({enc: 'A256GCM' })
//   .addRecipient(ek.publicKey).setUnprotectedHeader({kid: 'foo', alg: 'RSA-OAEP-256'})
//   .addRecipient(material).setUnprotectedHeader({kid: 'secret1', alg: 'PBES2-HS512+A256KW'})
//   .addRecipient(material2).setUnprotectedHeader({kid: 'secret2', alg: 'PBES2-HS512+A256KW'})
//   .encrypt()
// decrypted = await JOSE.generalDecrypt(jwe, ek.privateKey)
// decrypted = await JOSE.generalDecrypt(jwe, material, {keyManagementAlgorithms: ['PBES2-HS512+A256KW']})

const extractable = true,  // always wrapped

      signingName = 'ECDSA',
      signingCurve = 'P-384',
      signingAlgorithm = 'ES384',

      encryptingName = 'RSA-OAEP',
      hashLength = 256,
      hashName = 'SHA-256',
      modulusLength = 4096, // panva JOSE library default is 2048
      encryptingAlgorithm = 'RSA-OAEP-256',

      symmetricName = 'AES-GCM',
      symmetricAlgorithm = 'A256GCM';

const Krypto = {
  // Krypto is an easier-to-use form of crypto.subtle, in which the various options are tuned to the type of usage we do in distributed security:
  // The main operations (covered in unit tests) are:
  // generateEncryptingKey, generateSigningKey, generateSymmetricKey,
  // encrypt, decrypt, sign, verify
  // exportKey, importKey, wrapKey, unwrapKey

  generateSigningKey() {
    return JOSE.generateKeyPair(signingAlgorithm, {extractable});
  },
  inputBuffer(data, header) { // Answers a buffer view of data and, if necessary to convert, bashes cty of header.
    if (ArrayBuffer.isView(data) && !header.cty) return data;
    let givenCty = header.cty || '';
    if (givenCty.includes('text') || ('string' === typeof data)) {
      header.cty = givenCty || 'text/plain';
    } else {
      header.cty = givenCty || 'json'; // JWS recommends leaving off the leading 'application/'.
      data = JSON.stringify(data); // Note that new String("something") will pass this way.
    }
    return new TextEncoder().encode(data);
  },
  recoverDataFromContentType(result, {cty = result?.protectedHeader?.cty} = {}) {
    // Examines result?.protectedHeader and bashes in result.text or result.json if appropriate, returning result.
    if (result && !result.hasOwnProperty('payload')) result.payload = result.plaintext;  // because JOSE uses plaintext for decrypt and payload for sign.
    if (!cty) return result; // either no cty or no result
    result.text = new TextDecoder().decode(result.payload);
    if (cty.includes('json')) result.json = JSON.parse(result.text);
    return result;
  },
  async sign(privateKey, message, {...headers} = {}) {
    let header = {alg: signingAlgorithm, ...headers},
	inputBuffer = this.inputBuffer(message, header);
    return await new JOSE.CompactSign(inputBuffer).setProtectedHeader(header).sign(privateKey);
  },
  async verify(publicKey, signature, options) {
    let result = await JOSE.compactVerify(signature, publicKey).catch(() => undefined);
    return this.recoverDataFromContentType(result, options);
  },

  async generateSymmetricKey(text) {
    let secret
    if (text) {
      let buffer = new TextEncoder().encode(text),
	  hash = await crypto.subtle.digest(hashName, buffer);
      return {type: 'secret', text: new Uint8Array(hash)};
    }
    return await JOSE.generateSecret(symmetricAlgorithm, {extractable});
  },
  isSymmetric(key) {
    return key.type === 'secret';
  },
  keySecret(key) {
    if (key.text) return key.text;
    return key;
  },
  generateEncryptingKey() {
    return JOSE.generateKeyPair(encryptingAlgorithm, {extractable, modulusLength});
  },
  async encrypt(key, message, headers = {}) {
    let alg = this.isSymmetric(key) ? 'dir' : encryptingAlgorithm,
	header = {alg, enc: symmetricAlgorithm, ...headers},
	inputBuffer = this.inputBuffer(message, header),
	secret = this.keySecret(key);
    return await new JOSE.CompactEncrypt(inputBuffer).setProtectedHeader(header).encrypt(secret);
  },
  async decrypt(key, encrypted, options) {
    let secret = this.keySecret(key),
	result = await JOSE.compactDecrypt(encrypted, secret);
    this.recoverDataFromContentType(result, options);
    if (result.hasOwnProperty('json')) return result.json;
    return result.text ?? result.payload;
  },

  async exportRaw(key) {
    let arrayBuffer = await crypto.subtle.exportKey('raw', key);
    return JOSE.base64url.encode(new Uint8Array(arrayBuffer));
  },
  async importRaw(string) {
    let algorithm = {name: signingName, namedCurve: signingCurve},
	arrayBuffer = JOSE.base64url.decode(string);
    return await crypto.subtle.importKey('raw', arrayBuffer, algorithm, extractable, ['verify']);
  },
  async exportJWK(key) {
    let exported = await JOSE.exportJWK(key),
	alg = key.algorithm;
    if (alg.name === signingName && alg.namedCurve === signingCurve) exported.alg = signingAlgorithm;
    else if (alg.name === encryptingName && alg.hash.name === hashName) exported.alg = encryptingAlgorithm;
    else if (alg.name === symmetricName && alg.length === hashLength) exported.alg = symmetricAlgorithm;
    return exported;
  },
  async importJWK(jwk) {
    jwk = Object.assign({ext: true}, jwk); // We need the result to be be able to generate a new JWK (e.g., on changeMembership)
    let imported = await JOSE.importJWK(jwk);
    if (imported instanceof Uint8Array) {
      // We depend an returning an actual key, but the JOSE library we use
      // will above produce the raw Uint8Array if the jwk is from a symmetric key.
      let algorithm = {name: symmetricName, length: hashLength}
      imported = await crypto.subtle.importKey('raw', imported, algorithm, true, ['encrypt', 'decrypt'])
    }
    return imported;
  },

  async wrapKey(key, wrappingKey) {
    let exported = await this.exportJWK(key);
    let wrapped = await this.encrypt(wrappingKey, JSON.stringify(exported));
    let wrapped2 = await this.encrypt(wrappingKey, exported);
    return wrapped;
  },
  async unwrapKey(wrappedKey, unwrappingKey) {
    let decrypted = await this.decrypt(unwrappingKey, wrappedKey);
    let decrypted2 = JSON.parse(decrypted);
    return this.importJWK(decrypted2);
  }
}

export default Krypto;
