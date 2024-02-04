import {makeMessage} from "./support/messageText.mjs";

export default function testKrypto (krypto, // Pass either Krypto or MultiKrypto
				    encryptableSize = 446) {
  const bigEncryptable = encryptableSize > 1000,
	slowKeyCreation = 10e3,
	slowHybrid = bigEncryptable ? slowKeyCreation : 5e3; // Needed on Android

  function isBase64URL(string) {
 // const regex = /^[A-Za-z0-9+\/]+(=){0,2}$/ // FIXME: not URL-safe!
    const regex = /^[A-Za-z0-9+\/~=]+$/; // FIXME: not URL-safe AND includes ~
    //const regex = /^[A-Za-z0-9_\-]+$/
    if (!regex.test(string)) console.log(string);
    expect(regex.test(string)).toBeTruthy();
  }
  describe('signing', function () {
    it('returns truthy for verified at scale with an asymmetric keypair.', async function () {
      let keypair = await krypto.generateSigningKey(),
	  message = makeMessage(),
	  signature = await krypto.sign(keypair.privateKey, message);
      isBase64URL(signature);
      expect(await krypto.verify(keypair.publicKey, signature, message)).toBeTruthy();
    });
    it('returns falsy for verify with the wrong key.', async function () {
      let keypair = await krypto.generateSigningKey(),
	  message = makeMessage(),
	  signature = await krypto.sign(keypair.privateKey, message),
	  wrongKeypair = await krypto.generateSigningKey();
      expect(await krypto.verify(wrongKeypair.publicKey, signature, message)).toBeFalsy();
    });
  });

  describe('encryption', function () {
    it(`can work up through at least ${encryptableSize} bytes with an asymmetric keypair.`, async function () {
      // Public key encrypt will work up through 446 bytes, but the result will not decrypt.
      let keypair = await krypto.generateEncryptingKey(),
	  message = makeMessage(encryptableSize),
	  encrypted = await krypto.encrypt(keypair.publicKey, message);
      isBase64URL(encrypted);
      expect(await krypto.decrypt(keypair.privateKey, encrypted)).toBe(message)
    }, slowHybrid);
    function testSymmetric(label, promise, decryptPromise = promise) {
      it(`can work on much larger data with a ${label}.`, async function () {
	let key = await promise,
	    decryptKey = await decryptPromise,
	    message = makeMessage(),
	    encrypted = await krypto.encrypt(key, message);
	isBase64URL(encrypted);
	expect(await krypto.decrypt(decryptKey, encrypted)).toBe(message);
      });
    }
    testSymmetric('fixed symmetric key',
		  krypto.generateSymmetricKey());
    testSymmetric('reproducible secret',
		  krypto.generateSymmetricKey("secret", {salt: "xyzpdq", iv: "123456789012"}),
		  krypto.generateSymmetricKey("secret", {salt: "xyzpdq", iv: "123456789012"}));
    function failsWithWrong(label, keysThunk) {
      it(`rejects wrong ${label}.`, async function() {
	let [encryptKey, decryptKey] = await keysThunk(),
	    message = makeMessage(encryptableSize),
	    encrypted = await krypto.encrypt(encryptKey, message);
	await expectAsync(krypto.decrypt(decryptKey, encrypted)).toBeRejected();
      });
    }
    failsWithWrong('asymmetric key', async () => [
      (await krypto.generateEncryptingKey()).publicKey,
      (await krypto.generateEncryptingKey()).privateKey
    ]);
    failsWithWrong('symmetric key', async () => [
      await krypto.generateSymmetricKey(),
      await krypto.generateSymmetricKey()
    ]);
    failsWithWrong('secret', async () => [
      await krypto.generateSymmetricKey("secret", {salt: "xyzpdq", iv: "123456789012"}),
      await krypto.generateSymmetricKey("secretX", {salt: "xyzpdq", iv: "123456789012"})
    ]);
    failsWithWrong('secret salt', async () => [
      await krypto.generateSymmetricKey("secret", {salt: "xyzpdq", iv: "123456789012"}),
      await krypto.generateSymmetricKey("secret", {salt: "xyzpdqX", iv: "123456789012"})
    ]);
    failsWithWrong('secret iv', async () => [
      await krypto.generateSymmetricKey("secret", {salt: "xyzpdq", iv: "123456789012"}),
      await krypto.generateSymmetricKey("secret", {salt: "xyzpdq", iv: "023456789012"})
    ]);
  });

  describe('base64 export/import', function () {
    describe(`of signing keys`, function () {
      it(`works with the private signing key as a 248 byte serialization.`, async function () {
	let keypair = await krypto.generateSigningKey(),
	    serializedPrivateKey = await krypto.exportKey(keypair.privateKey), 
	    importedPrivateKey = await krypto.importKey(serializedPrivateKey, 'sign'), 
	    message = makeMessage(),
	    signature = await krypto.sign(importedPrivateKey, message);
	isBase64URL(serializedPrivateKey);
	expect(serializedPrivateKey.length).toBe(248);
	expect(await krypto.verify(keypair.publicKey, signature, message)).toBeTruthy();
      });
      it(`works with the public verifying key as a 132 byte serialization.`, async function () {
	let keypair = await krypto.generateSigningKey(),
	    serializedPublicKey = await krypto.exportKey(keypair.publicKey), 
	    importedPublicKey = await krypto.importKey(serializedPublicKey, 'verify'), 
	    message = makeMessage(),
	    signature = await krypto.sign(keypair.privateKey, message);
	isBase64URL(serializedPublicKey);	
	expect(serializedPublicKey.length).toBe(132);
	expect(await krypto.verify(importedPublicKey, signature, message)).toBeTruthy();
      });
    });

    describe('of encryption keys', function () {
      it('works with the private key as a 3164-3168 byte serialization.', async function () {
	let keypair = await krypto.generateEncryptingKey(),
	    serializedPrivateKey = await krypto.exportKey(keypair.privateKey),
	    importedPrivateKey = await krypto.importKey(serializedPrivateKey, 'decrypt'),
	    message = makeMessage(446),
	    encrypted = await krypto.encrypt(keypair.publicKey, message);
	isBase64URL(serializedPrivateKey);	
	expect(serializedPrivateKey.length).toBeGreaterThanOrEqual(3164);	
	expect(serializedPrivateKey.length).toBeLessThanOrEqual(3168);
	expect(await krypto.decrypt(importedPrivateKey, encrypted)).toBe(message)
      });
      it('works with the public encrypting key as a serialization of no more than 736 bytes.', async function () {
	let keypair = await krypto.generateEncryptingKey(),
	    serializedPublicKey = await krypto.exportKey(keypair.publicKey),
	    importedPublicKey = await krypto.importKey(serializedPublicKey, 'encrypt'),
	    message = makeMessage(446),
	    encrypted = await krypto.encrypt(importedPublicKey, message);
	isBase64URL(serializedPublicKey);	
	expect(serializedPublicKey.length).toBe(736);
	expect(await krypto.decrypt(keypair.privateKey, encrypted)).toBe(message)
      });
    });

    describe('of symmetric key', function () {
      it('works as a 60 byte serialization (including iv).', async function () {
	let key = await await krypto.generateSymmetricKey(),
	    serializedKey = await krypto.exportKey(key),
	    importedKey = await krypto.importKey(serializedKey, 'symmetric'),
	    message = makeMessage(),
	    encrypted = await krypto.encrypt(key, message);
	isBase64URL(serializedKey);
	expect(serializedKey.length).toBe(60);	
	expect(await krypto.decrypt(importedKey, encrypted)).toBe(message);
      });
    });
  });

  it('wraps like export+encrypt.', async function () {
    // Let's "wrap" a symmetric key with an asymmetric encrypting key in two ways.
    let encryptableKey = await krypto.generateSymmetricKey(),
	wrappingKey = await krypto.generateEncryptingKey(),

	// Cycle it through export,encrypt to encrypted key, and decrypt,import to imported key.
	exported = await krypto.exportKey(encryptableKey), 
	encrypted = await krypto.encrypt(wrappingKey.publicKey, exported),
	decrypted = await krypto.decrypt(wrappingKey.privateKey, encrypted),
	imported = await krypto.importKey(decrypted, 'symmetric'),

	// Cycle it through wrap and unwrap.
	wrapped = await krypto.wrapKey(encryptableKey, wrappingKey.publicKey),
	unwrapped = await krypto.unwrapKey(wrapped, wrappingKey.privateKey, 'symmetric'),

	// Use one to encrypt a message, and the other decrypt it.
	message = "this is a message",
	encryptedMessage = await krypto.encrypt(unwrapped, message),
	decryptedMessage = await krypto.decrypt(imported, encryptedMessage);
    isBase64URL(wrapped);
    expect(decryptedMessage).toBe(message);
  }, slowKeyCreation);
}
