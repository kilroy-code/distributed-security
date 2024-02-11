import {scale, makeMessage} from "./support/messageText.mjs";
import testKrypto from "./kryptoTests.mjs";

export default function testMultiKrypto(multiKrypto) {
  const slowKeyCreation = 20e3, // Android
	message = makeMessage();
  describe('falls through to krypto with single keys', function () {
    testKrypto(multiKrypto, scale);
  });

  describe('multi-way keys', function () {

    describe('multi-signature', function () {
      let signingA, signingB;
      beforeAll(async function () {
	signingA = await multiKrypto.generateSigningKey();
	signingB = await multiKrypto.generateSigningKey();
      });

      it('is a multi-signature.', async function () {
	let multiSign = {a: signingA.privateKey, b: signingB.privateKey},
	    multiVerify = {a: signingA.publicKey, b: signingB.publicKey},
	    signature = await multiKrypto.sign(multiSign, message),
	    verified = await multiKrypto.verify(multiVerify, signature);
	expect(verified).toBeTruthy();
      });
      it('can specify type:"multi" in the signing key for clarify.', async function () {
	let multiSign = {a: signingA.privateKey, b: signingB.privateKey, type:'multi'},
	    multiVerify = {a: signingA.publicKey, b: signingB.publicKey},
	    signature = await multiKrypto.sign(multiSign, message),
	    verified = await multiKrypto.verify(multiVerify, signature);
	expect(verified).toBeTruthy();
      });
      it('can specify type:"multi" in the verifying key for clarify.', async function () {
	let multiSign = {a: signingA.privateKey, b: signingB.privateKey},
	    multiVerify = {a: signingA.publicKey, b: signingB.publicKey, type:'multi'},
	    signature = await multiKrypto.sign(multiSign, message),
	    verified = await multiKrypto.verify(multiVerify, signature);
	expect(verified).toBeTruthy();
      });
      it('can specify iss, act, iat in the key, which will appear in the signature.', async function () {
	let iat = Date.now(),
	    iss = 'a',
	    act = 'b',
	    multiSign = {a: signingA.privateKey, b: signingB.privateKey,
			 iss, act, iat}, // Will appear in signature
	    multiVerify = {a: signingA.publicKey, b: signingB.publicKey},
	    signature = await multiKrypto.sign(multiSign, message),
	    verified = await multiKrypto.verify(multiVerify, signature);
	expect(verified).toBeTruthy();
	JSON.parse(signature).signatures.forEach(subSignature => {
	  let header = JOSE.decodeProtectedHeader(subSignature);
	  expect(header.iss).toBe(iss);
	  expect(header.act).toBe(act);
	  expect(header.iat).toBe(iat);
	});
      });

      it('fails fails verification if there is a mismatch between key labeling.',
	 async function () {
	   let multiSign = {a: signingA.privateKey, b: signingA.privateKey}, // Note that the value for b is not what is claimed.
	       multiVerify = {a: signingA.publicKey, b: signingB.publicKey},
	       signature = await multiKrypto.sign(multiSign, message),
	       verified = await multiKrypto.verify(multiVerify, signature);
	   expect(verified).toBeFalsy();
	 });
      it('fails fails verification if the verification sub key is missing.',
	 async function () {
	   let multiSign = {a: signingA.privateKey, b: signingB.privateKey},
	       multiVerify = {a: signingA.publicKey}, // Missing b.
	       signature = await multiKrypto.sign(multiSign, message),
	       verified = await multiKrypto.verify(multiVerify, signature);
	   expect(verified).toBeFalsy();
	 });
      it('fails fails verification if a signature sub key is missing.',
	 async function () {
	   let multiSign = {a: signingA.privateKey}, // Missing b.
	       multiVerify = {a: signingA.publicKey, b: signingB.publicKey},
	       signature = await multiKrypto.sign(multiSign, message),
	       verified = await multiKrypto.verify(multiVerify, signature);
	   expect(verified).toBeFalsy();
	 });
    });

    describe('multi-way encryption', function () {
      let encrypted, keypair, symmetric, secretText = "shh!", recipients;
      beforeAll(async function () {
	symmetric = await multiKrypto.generateSymmetricKey();
	keypair = await multiKrypto.generateEncryptingKey();
	encrypted = await multiKrypto.encrypt({a: symmetric, b: keypair.publicKey, c: secretText}, message);
	recipients = JSON.parse(encrypted).recipients;
      }, slowKeyCreation);
      it('works with symmetric members.', async function () {
	let decrypted = await multiKrypto.decrypt({a: symmetric}, encrypted);
	expect(decrypted).toBe(message);
	expect(recipients[0].header.kid).toBe('a');
	expect(recipients[0].header.alg).toBe('A256GCMKW');
      });
      it('works with keypair members.', async function () {
	let decrypted = await multiKrypto.decrypt({b: keypair.privateKey}, encrypted);
	expect(decrypted).toBe(message);
	expect(recipients[1].header.kid).toBe('b');
	expect(recipients[1].header.alg).toBe('RSA-OAEP-256');
      });
      it('works with secret text members.', async function () {
	let decrypted = await multiKrypto.decrypt({c: secretText}, encrypted);
	expect(decrypted).toBe(message);
	expect(recipients[2].header.kid).toBe('c');
	expect(recipients[2].header.alg).toBe('PBES2-HS512+A256KW');
      });

      it('produces undefined for wrong symmetric key.', async function () {
	let anotherKey = await multiKrypto.generateSymmetricKey(),
	    decrypted = await multiKrypto.decrypt({a: anotherKey}, encrypted);
	expect(decrypted).toBeUndefined();
      });
      it('produces undefined for wrong keypair.', async function () {
	let anotherKey = await multiKrypto.generateEncryptingKey(),
	    decrypted = await multiKrypto.decrypt({b: anotherKey.privateKey}, encrypted);
	expect(decrypted).toBeUndefined();
      });
      it('produces undefined for wrong secret text.', async function () {
	let decrypted = await multiKrypto.decrypt({c: "shh! "}, encrypted); // Extra whitespace
	expect(decrypted).toBeUndefined();
      });
      it('produces undefined for mislabeled key.', async function () {
	let decrypted = await multiKrypto.decrypt({a: secretText}, encrypted); // should be c
	expect(decrypted).toBeUndefined();
      });
    });
  });

  describe('export/wrap', function () {
    let encryptingMultikey, decryptingMultikey;

    beforeAll(async function () {
      let keypair1 = await multiKrypto.generateEncryptingKey(),
	  keypair2 = await multiKrypto.generateEncryptingKey(),
	  keypair3 = await multiKrypto.generateEncryptingKey();
      encryptingMultikey = {a: keypair1.publicKey, b: keypair2.publicKey};
      decryptingMultikey = {c: keypair3.privateKey, b: keypair2.privateKey};
    }, slowKeyCreation);

    it('exports homogenous member.', async function () {
      let exported = await multiKrypto.exportJWK(encryptingMultikey),
	  imported = await multiKrypto.importJWK(exported),
	  // Now prove that the imported multikey works.
	  encrypted = await multiKrypto.encrypt(imported, message),
	  decrypted = await multiKrypto.decrypt(decryptingMultikey, encrypted);
      expect(exported.keys[0].kid).toBe('a');
      expect(exported.keys[1].kid).toBe('b');
      expect(decrypted).toBe(message);
    });
    it('export heterogenous members.', async function () {
      let encryptingKeypair = await multiKrypto.generateEncryptingKey(),
	  signingKeypair = await multiKrypto.generateSigningKey(),
	  exported = await multiKrypto.exportJWK({myDecrypt: encryptingKeypair.privateKey, mySign: signingKeypair.privateKey}),
	  imported = await multiKrypto.importJWK(exported),
	  // Now prove that the imported multikey works.
	  message  = "a smaller message for asymmetric encryption", // Although JOSE always uses hybrid encryption anyway, so size isn't a problem.
	  encrypted = await multiKrypto.encrypt(encryptingKeypair.publicKey, message),
	  decrypted = await multiKrypto.decrypt(imported.myDecrypt, encrypted),
	  signed = await multiKrypto.sign(imported.mySign, message);
      expect(exported.keys[0].kid).toBe('myDecrypt');
      expect(exported.keys[1].kid).toBe('mySign');
      expect(decrypted).toBe(message);
      expect(await multiKrypto.verify(signingKeypair.publicKey, signed)).toBeTruthy();
    });

    it('can wrap/unwrap a simple key.', async function () {
      let key = await multiKrypto.generateSymmetricKey(),
	  wrapped = await multiKrypto.wrapKey(key, encryptingMultikey),
	  unwrapped = await multiKrypto.unwrapKey(wrapped, decryptingMultikey),
	  // Cool, now prove that worked.
	  encrypted = await multiKrypto.encrypt(unwrapped, message),
	  decrypted = await multiKrypto.decrypt(key, encrypted);
      expect(decrypted).toBe(message);
    });
    it('can be wrapped/unwrapped by a symmetric key with homogenous members.', async function () {
      let wrappingKey = await multiKrypto.generateSymmetricKey(),
	  wrapped = await multiKrypto.wrapKey(encryptingMultikey, wrappingKey),
	  unwrapped = await multiKrypto.unwrapKey(wrapped, wrappingKey),
	  // Cool, now prove that worked.
	  encrypted = await multiKrypto.encrypt(unwrapped, message),
	  decrypted = await multiKrypto.decrypt(decryptingMultikey, encrypted);
      expect(decrypted).toBe(message);
    });
    it('can wrap/unwrap a symmetric multikey with homogenous members.', async function () {
      let key = {x: await multiKrypto.generateSymmetricKey(), y: await multiKrypto.generateSymmetricKey()},
	  wrapped = await multiKrypto.wrapKey(key, encryptingMultikey),
	  unwrapped = await multiKrypto.unwrapKey(wrapped, decryptingMultikey),
	  // Cool, now prove that worked.
	  message = makeMessage(),
	  encrypted = await multiKrypto.encrypt(unwrapped, message),
	  decrypted = await multiKrypto.decrypt(key, encrypted);
      expect(decrypted).toBe(message);
    });
    it('can wrap/unwrap a heterogeneous multikey.', async function () {
      let encryptingKeypair = await multiKrypto.generateEncryptingKey(),
	  signingKeypair = await multiKrypto.generateSigningKey(),
	  wrapped = await multiKrypto.wrapKey({myDecrypt: encryptingKeypair.privateKey, mySign: signingKeypair.privateKey}, encryptingMultikey),
	  unwrapped = await multiKrypto.unwrapKey(wrapped, decryptingMultikey),
	  // Cool, now prove that worked.
	  message = "a shorter message",
	  encrypted = await multiKrypto.encrypt(encryptingKeypair.publicKey, message),
	  decrypted = await multiKrypto.decrypt(unwrapped.myDecrypt, encrypted),
	  signature = await multiKrypto.sign(unwrapped.mySign, message);
      expect(decrypted).toBe(message),
      expect(await multiKrypto.verify(signingKeypair.publicKey, signature)).toBeTruthy();
    }, slowKeyCreation);
  });
}
