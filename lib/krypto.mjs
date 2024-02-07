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

const hash = 'SHA-256',
      signName = 'ECDSA', // Also works with 'RSA-PSS', but comment out the use of 'raw' for 'verify' exportFormat, below.
      encryptName = 'RSA-OAEP',
      symmetricName = 'AES-GCM',
      isRSAsign = signName.startsWith('RSA');

const Krypto = {
  // Krypto is an easier-to-use form of crypto.subtle, in which the various options are tuned to the type of usage we do in distributed security:
  // The main operations (covered in unit tests) are:
  // generateEncryptingKey, generateSigningKey, generateSymmetricKey,
  // encrypt, decrypt, sign, verify
  // exportKey, importKey, wrapKey, unwrapKey
  exportable: true,  // FIXME: do we need this & extractable arg to jose?

  symmetricKeyAlgorithm: {name: symmetricName, length: 256},
  ivLength: 12,
  saltLength: 16,

  modulusLength: 4096, // panva JOSE library default is 2048
  // fixme: pull out agorithm literals to here
  asymmetricEncryptionAlgorithm: {name: encryptName},
  asymmetricEncryptionImportAlgorithm: {name: encryptName, hash},
  asymmetricEncryptionKeyAlgorithm: {name: encryptName, hash, modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]) },

  signingAlgorithm: isRSAsign ? {name: signName, saltLength: 32 } : {name: signName, hash: {name: "SHA-384"}},
  signingImportAlgorithm: isRSAsign ? {name: signName, hash} : {name: signName, namedCurve: "P-384"},
  signingKeyAlgorithm: isRSAsign ? {name: signName, hash, modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1])} : {name: signName, namedCurve: "P-384"},

  assertType(label, type, value) {
    console.assert(typeof(value) === type, "%s %o is not a %s.", label, value, type);
  },
  assertClass(label, kind, value) {
    console.assert(typeof(value) === 'object' && value instanceof kind, "%s %o is not an instance of %s.", label, value, kind.name);
  },
  assertKey(value) {
    this.assertType("Key", 'object', value);
  },

  exportFormat(use) {
    this.assertType('Use', 'string', use);
    switch (use) {

      // Public keys
    case 'verify':
      return 'raw'; // Can comment this out to use spki for ECDSA. MUST do so for RSA.
    case 'encrypt':
      return 'spki';  

      // Private keys
    case 'sign':
    case 'decrypt':
      return 'pkcs8'; 

    case 'symmetric':
      return 'raw';
    default:
      throw new Error(`Unrecognized usage '${use}'.`);
    }
  },

  generateSigningKey() {
    return JOSE.generateKeyPair('ES384', {extractable: this.exportable}); // No modulusLength for ECDSA.
  },
  async sign(privateKey, message) {
    let inputBuffer = new TextEncoder().encode(message);
    return await new JOSE.CompactSign(inputBuffer).setProtectedHeader({alg:'ES384'}).sign(privateKey);
  },
  async verify(publicKey, signature) {
    try {
      let result = await JOSE.compactVerify(signature, publicKey);
      return true; //new TextDecoder().decode(result.payload);
    } catch (e) {
      return false;  // FIXME: change unit tests an other code to expect a rejection
    }
  },

  iv(length = this.ivLength) {
    return crypto.getRandomValues(new Uint8Array(length));
  },
  salt(length = this.saltLength) {
    return crypto.getRandomValues(new Uint8Array(length));
  },
  async generateSymmetricKey(text, {salt} = {}) {
    // salt can be either an array buffer or a string (which need not be restricted to base64 characters).
    let secret, uses = ['encrypt', 'decrypt'], symmetricAlgorithm = this.symmetricKeyAlgorithm;
    if (text) {
      if (typeof(salt) === 'string') salt = this.str2ab(salt);
      else if (!salt) salt = this.salt();
      let encoder = new TextEncoder(),
	  secretName = "PBKDF2",
	  baseKey = await crypto.subtle.importKey("raw", encoder.encode(text), secretName, false, ['deriveBits', 'deriveKey']),
	  algorithm = {
	    name: secretName,
	    salt,
	    iterations: 100e3,
	    hash
	  };
      secret = await crypto.subtle.deriveKey(algorithm, baseKey, symmetricAlgorithm, this.exportable, uses);
    } else {
      secret = await JOSE.generateSecret('A256GCM', {extractable: this.exportable});
    }
    return secret;
  },
  isSymmetric(key) {
    this.assertKey(key);
    return key.type === 'secret';
  },
  keySecret(key) {
    this.assertKey(key);
    return key;
  },
  generateEncryptingKey() {
    return JOSE.generateKeyPair('RSA-OAEP-256', {extractable: this.exportable, modulusLength: this.modulusLength});
  },
  async encrypt(key, message) {
    let inputBuffer = new TextEncoder().encode(message),
	alg = this.isSymmetric(key) ? 'dir' : 'RSA-OAEP-256',
	secret = this.keySecret(key);
    return await new JOSE.CompactEncrypt(inputBuffer).setProtectedHeader({alg, enc: 'A256GCM' }).encrypt(secret);
  },
  async decrypt(key, encrypted) {
    let secret = this.keySecret(key),
	outputBuffer = await JOSE.compactDecrypt(encrypted, secret);
    return new TextDecoder().decode(outputBuffer.plaintext);
  },

  async exportRaw(key) {
    let arrayBuffer = await crypto.subtle.exportKey('raw', key);
    return this.arrayBuffer2base64string(arrayBuffer);
  },
  async importRaw(string, use) {
    let arrayBuffer = this.base64string2arrayBuffer(string);
    return await crypto.subtle.importKey('raw', arrayBuffer, this.importAlgorithm(use), this.exportable, [use]);
  },
  async exportJWK(key) {
    let exported = await JOSE.exportJWK(key),
	alg = key.algorithm;
    if (alg.name === "ECDSA" && alg.namedCurve === "P-384") exported.alg = 'ES384';
    else if (alg.name === "RSA-OAEP" && alg.hash.name === 'SHA-256') exported.alg = 'RSA-OAEP-256';
    else if (alg.name === "AES-GCM" && alg.length === 256) exported.alg = 'A256GCM';
    return exported;
  },
  async importJWK(jwk) {
    jwk = Object.assign({ext: true}, jwk); // We need the result to be be able to generate a new JWK (e.g., on changeMembership)
    let imported = await JOSE.importJWK(jwk);
    if (imported instanceof Uint8Array) {
      // We depend an returning an actual key, but the JOSE library we use
      // will above produce the raw Uint8Array if the jwk is from a symmetric key.
      imported = await crypto.subtle.importKey('raw', imported, {name: 'AES-GCM', length: 256}, true, ['encrypt', 'decrypt'])
    }
    return imported;
  },
  async exportKeyAsBuffer(key) {
    this.assertKey(key);
    let use = this.isSymmetric(key) ? 'symmetric' : key.usages?.[0],
	format = this.exportFormat(use),
	secret = this.keySecret(key),
	keyBuffer = await crypto.subtle.exportKey(format, secret),
	iv = key.iv;
    if (!iv) return keyBuffer;
    // Tack the iv onto the front.
    let ivLength = this.ivLength,
	arrayBuffer = new Uint8Array(ivLength + keyBuffer.byteLength);
    arrayBuffer.set(iv, 0);
    arrayBuffer.set(new Uint8Array(keyBuffer), ivLength);
    return arrayBuffer;
  },
  async exportKey(key) {
    this.assertKey(key);
    let arrayBuffer = await this.exportKeyAsBuffer(key),
    	b64 = this.arrayBuffer2base64string(arrayBuffer);
    return b64;
  },
  async importBuffer(arrayBuffer, use) {
    let format = this.exportFormat(use),
	algorithm = this.importAlgorithm(use),
	iv,
	uses;
    if (use === 'symmetric') {
      uses = ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    } else {
      uses = [use];
      if (use === 'encrypt') uses.push('wrapKey');
      else if (use === 'decrypt') uses.push('unwrapKey');
    }
    let secret = await crypto.subtle.importKey(format, arrayBuffer, algorithm, this.exportable, uses);
    return secret;
  },
  importAlgorithm(use) {
    this.assertType('Use', 'string', use);
    if (use === 'symmetric') return symmetricName;
    if (['encrypt', 'decrypt'].includes(use)) return this.asymmetricEncryptionImportAlgorithm;
    return this.signingImportAlgorithm;
  },
  importKey(string, use) {
    this.assertType('String to import', 'string', string);
    this.assertType('Use', 'string', use);
    let arrayBuffer = this.base64string2arrayBuffer(string);
    return this.importBuffer(arrayBuffer, use);
  },

  async wrapKey(key, wrappingKey) {
    this.assertKey(key);
    this.assertKey(wrappingKey);    
    let exported = JSON.stringify(await this.exportJWK(key));
    return this.encrypt(wrappingKey, exported);
  },
  async unwrapKey(wrappedKey, unwrappingKey, use) {
    this.assertType('String to unwrapp', 'string', wrappedKey);
    this.assertKey(unwrappingKey);
    let decrypted = await this.decrypt(unwrappingKey, wrappedKey);
    return this.importJWK(JSON.parse(decrypted), use);
  },

  // atob - base64 string => string of bytes
  // str2ab - string of bytes => array buffer
  // TextEncoder.encode - string of bytes => Uint8Array  buffer

  // TextDecoder.decode - array buffer => string of bytes 
  // ab2str - array buffer => string of bytes
  // btoa - string of bytes => base64 string

  arrayBuffer2base64string(arrayBuffer) {
    return btoa(this.ab2str(arrayBuffer));
  },
  base64string2arrayBuffer(string) {
    return this.str2ab(atob(string));
  },
  concatChar: '~',  // The character to be used for combining base64 strings. (Does not appear in standard or url-safe base64, nor is it reserved for url.)
  concatBase64(...strings) { // Return a string for which splitBase64 can recover the list of strings.
    return strings.join(this.concatChar);
  },
  splitBase64(string) { // Inverse of concatBase64.
    return string.split(this.concatChar);
  },
  str2ab(str) {
    // Convert a string into an ArrayBuffer
    // from https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  },
  ab2str(buf) {
    // Convert an ArrayBuffer into a string
    // from https://developer.chrome.com/blog/how-to-convert-arraybuffer-to-and-from-string/
    // However, the code there doesn't work on large buf:
    //    return String.fromCharCode.apply(null, new Uint8Array(buf));
    let byteArray = new Uint8Array(buf),
	byteString = '';
    for (var i = 0, bufLength = byteArray.byteLength; i < bufLength; i++) {
      byteString += String.fromCharCode(byteArray[i]);
    }
    return byteString;
  }
}

export default Krypto;
