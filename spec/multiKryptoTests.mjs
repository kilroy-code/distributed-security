import {scale, makeMessage} from "./support/messageText.mjs";
import testKrypto from "./kryptoTests.mjs";
import * as JOSE from "../dependency/jose.mjs";

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
	    // Order doesn't matter. just that they correspond as a set.
	    multiVerify = {b: signingB.publicKey, a: signingA.publicKey},
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
	    multiSign = {a: signingA.privateKey, b: signingB.privateKey},
	    multiVerify = {a: signingA.publicKey, b: signingB.publicKey},
	    signature = await multiKrypto.sign(multiSign, message, {iss, act, iat}),
	    verified = await multiKrypto.verify(multiVerify, signature);
	expect(verified).toBeTruthy();
	JSON.parse(signature).signatures.forEach(subSignature => {
	  let header = JOSE.decodeProtectedHeader(subSignature);
	  expect(header.iss).toBe(iss);
	  expect(header.act).toBe(act);
	  expect(header.iat).toBe(iat);
	});
      });
      it('can sign binary and it is recovery as binary from payload property of verfication.', async function () {
	let message = new Uint8Array([1], [2], [3]),
	    signature = await multiKrypto.sign({a: signingA.privateKey, b: signingB.privateKey}, message),
	    verified = await multiKrypto.verify({a: signingA.publicKey, b: signingB.publicKey}, signature);
	expect(verified.payload).toEqual(message);
      });
      it('can sign string type and it is recoverable as string from text property of verification.', async function () {
	let message = "a string",
	    signature = await multiKrypto.sign({a: signingA.privateKey, b: signingB.privateKey}, message),
	    verified = await multiKrypto.verify({a: signingA.publicKey, b: signingB.publicKey}, signature);
	expect(verified.text).toEqual(message);
	expect(verified.payload).toEqual(new TextEncoder().encode(message));
      });
      it('can sign a jsonable object and it is recovery as same from json property of result.', async function () {
	let message = {foo: "a string", bar: false, baz: ['a', 2, null]},
	    signature = await multiKrypto.sign({a: signingA.privateKey, b: signingB.privateKey}, message),
	    verified = await multiKrypto.verify({a: signingA.publicKey, b: signingB.publicKey}, signature);
	expect(verified.json).toEqual(message);
	expect(verified.payload).toEqual(new TextEncoder().encode(JSON.stringify(message)));
      });
      it('can specify a specific cty that will pass through to verify.', async function () {
	let message = {foo: "a string", bar: false, baz: ['a', 2, null]},
	    cty = 'application/foo+json',
	    signature = await multiKrypto.sign({a: signingA.privateKey, b: signingB.privateKey}, message, {cty}),
	    verified = await multiKrypto.verify({a: signingA.publicKey, b: signingB.publicKey}, signature);
	expect(verified.json).toEqual(message);
	expect(verified.protectedHeader.cty).toBe(cty);
	expect(verified.payload).toEqual(new TextEncoder().encode(JSON.stringify(message)));
      });

      it('fails verification if the signature is mislabeled.',
	 async function () {
	   let multiSign = {a: signingB.privateKey, b: signingA.privateKey}, // Note that the values are not what is claimed.
	       multiVerify = {a: signingA.publicKey, b: signingB.publicKey},
	       signature = await multiKrypto.sign(multiSign, message),
	       verified = await multiKrypto.verify(multiVerify, signature);
	   expect(verified).toBeUndefined();
	 });
      it('gives enough information that we can tell if a verifying sub key is missing.',
	 async function () {
	   let multiSign = {a: signingA.privateKey, b: signingB.privateKey},
	       multiVerify = {b: signingB.publicKey}, // Missing a.
	       signature = await multiKrypto.sign(multiSign, message),
	       verified = await multiKrypto.verify(multiVerify, signature);
	   // Overall, something we asked for did verify.
	   expect(verified.payload).toBeTruthy();
	   expect(verified.text).toBe(message);
	   // b is second signer in signature
	   expect(verified.signers[1].payload).toBeTruthy();
	   // but the first signer was not verified
	   expect(verified.signers[0].payload).toBeUndefined();
	 });
      it('gives enough information that we can tell if a signature sub key is missing.',
	 async function () {
	   let multiSign = {a: signingA.privateKey}, // Missing b.
	       multiVerify = {a: signingA.publicKey, b: signingB.publicKey},
	       signature = await multiKrypto.sign(multiSign, message),
	       verified = await multiKrypto.verify(multiVerify, signature);
	   // Overall, something we asked for did verify.
	   expect(verified.payload).toBeTruthy();
	   expect(verified.text).toBe(message);
	   // But only one signer
	   expect(verified.signers.length).toBe(1);
	   expect(verified.signers[0].protectedHeader.kid).toBe('a');
	   expect(verified.signers[0].payload).toBeTruthy();
	 });
    });

    describe('multi-way encryption', function () {
      let encrypted, keypair, symmetric, secretText = "shh!", recipients, encryptingMulti, decryptingMulti;
      beforeAll(async function () {
	symmetric = await multiKrypto.generateSymmetricKey();
	keypair = await multiKrypto.generateEncryptingKey();
	encrypted = await multiKrypto.encrypt({a: symmetric, b: keypair.publicKey, c: secretText}, message);
	recipients = JSON.parse(encrypted).recipients;
	let otherKeypair = await multiKrypto.generateEncryptingKey();
	encryptingMulti = {a: keypair.publicKey, b: otherKeypair.publicKey};
	decryptingMulti = {a: keypair.privateKey, b: otherKeypair.privateKey};
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

      it('handles binary, and decrypts as same.', async function () {
	let message = new Uint8Array([21, 31]),
	    encrypted = await multiKrypto.encrypt(encryptingMulti, message),
	    decrypted = await multiKrypto.decrypt(decryptingMulti, encrypted),
	    header = JOSE.decodeProtectedHeader(JSON.parse(encrypted));
	expect(header.cty).toBeUndefined();
	expect(decrypted).toEqual(message);
      });
      it('handles text, and decrypts as same.', async function () {
	let encrypted = await multiKrypto.encrypt(encryptingMulti, message),
	    decrypted = await multiKrypto.decrypt(decryptingMulti, encrypted),
	    header = JOSE.decodeProtectedHeader(JSON.parse(encrypted));
	expect(header.cty).toBe('text/plain');
	expect(decrypted).toBe(message);
      });
      it('handles json, and decrypts as same.', async function () {
	let message = {foo: 'bar'},
	    encrypted = await multiKrypto.encrypt(encryptingMulti, message);
	let header = JOSE.decodeProtectedHeader(JSON.parse(encrypted)),
	    decrypted = await multiKrypto.decrypt(decryptingMulti, encrypted);
	expect(header.cty).toBe('json');
	expect(decrypted).toEqual(message);
      });
      it('Uses specified headers if supplied, including cty.', async function () {
	let cty = 'text/html',
	    iat = Date.now(),
	    foo = 17,
	    message = "<something else>",
	    encrypted = await multiKrypto.encrypt(encryptingMulti, message, {cty, iat, foo}),
	    decrypted = await multiKrypto.decrypt(decryptingMulti, encrypted),
	    header = JOSE.decodeProtectedHeader(JSON.parse(encrypted))
	expect(header.cty).toBe(cty);
	expect(header.iat).toBe(iat);
	expect(header.foo).toBe(foo);
	expect(decrypted).toBe(message);
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
