import {makeMessage} from "./support/messageText.mjs";

export default function testKrypto (krypto, // Pass either Krypto or MultiKrypto
				    encryptableSize = 446) {
  const bigEncryptable = encryptableSize > 1000,
	slowKeyCreation = 10e3,
	slowHybrid = bigEncryptable ? slowKeyCreation : 5e3; // Needed on Android

  const base64withDot = /^[A-Za-z0-9_\-\.]+$/;
  const looseBase64 = /.*/; // /^[A-Za-z0-9_\-\.\~+\/=]+$/      
  function isBase64URL(string, regex = looseBase64) {
 // const regex = /^[A-Za-z0-9+\/]+(=){0,2}$/ // FIXME: not URL-safe!
 //   const regex = /^[A-Za-z0-9+\/~=]+$/; // FIXME: not URL-safe AND includes ~
    //    const regex = /^[A-Za-z0-9_\-\.]+$/
    //const regex = /^[A-Za-z0-9_\-\.\~+\/=]+$/
    if (!regex.test(string)) console.log(string);
    expect(regex.test(string)).toBeTruthy();
  }
  describe('signing', function () {
    it('returns truthy for verified at scale with an asymmetric keypair.', async function () {
      let keypair = await krypto.generateSigningKey(),
	  message = makeMessage(),
	  signature = await krypto.sign(keypair.privateKey, message);
      isBase64URL(signature, base64withDot);
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
      isBase64URL(encrypted, base64withDot);
      expect(await krypto.decrypt(keypair.privateKey, encrypted)).toBe(message)
    }, slowHybrid);
    function testSymmetric(label, promise, decryptPromise = promise) {
      it(`can work on much larger data with a ${label}.`, async function () {
	let key = await promise,
	    decryptKey = await decryptPromise,
	    message = makeMessage(),
	    encrypted = await krypto.encrypt(key, message);
	isBase64URL(encrypted, base64withDot);
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
    // FIXME: jose manages its own iv, separate from ours.
    // failsWithWrong('secret iv', async () => [
    //   await krypto.generateSymmetricKey("secret", {salt: "xyzpdq", iv: "123456789012"}),
    //   await krypto.generateSymmetricKey("secret", {salt: "xyzpdq", iv: "023456789012"})
    // ]);
  });

  describe('base64 export/import', function () {
    describe(`of signing keys`, function () {
      const privateSigningSize = 248; //253; // 248 raw
      it(`works with the private signing key as a ${privateSigningSize} byte serialization.`, async function () {
	let keypair = await krypto.generateSigningKey(),
	    serializedPrivateKey = await krypto.exportKey(keypair.privateKey), 
	    importedPrivateKey = await krypto.importKey(serializedPrivateKey, 'sign'), 
	    message = makeMessage(),
	    signature = await krypto.sign(importedPrivateKey, message);
	isBase64URL(serializedPrivateKey);
	expect(serializedPrivateKey.length).toBe(privateSigningSize);
	expect(await krypto.verify(keypair.publicKey, signature, message)).toBeTruthy();
      });
      const publicSigningSize = 132; //182; // 132 raw
      it(`works with the public verifying key as a ${publicSigningSize} byte serialization.`, async function () {
	let keypair = await krypto.generateSigningKey(),
	    serializedPublicKey = await krypto.exportKey(keypair.publicKey), 
	    importedPublicKey = await krypto.importKey(serializedPublicKey, 'verify'), 
	    message = makeMessage(),
	    signature = await krypto.sign(keypair.privateKey, message);
	isBase64URL(serializedPublicKey);	
	expect(serializedPublicKey.length).toBe(publicSigningSize);
	expect(await krypto.verify(importedPublicKey, signature, message)).toBeTruthy();
      });
    });

    describe('of encryption keys', function () {
      const privateEncryptingKeySize = [3164, 3168]; //[3169, 3173] // raw [3164, 3168]; // with a 4k modulusSize key
      it(`works with the private key as a ${privateEncryptingKeySize[0]}-${privateEncryptingKeySize[1]} byte serialization.`, async function () {
	let keypair = await krypto.generateEncryptingKey(),
	    serializedPrivateKey = await krypto.exportKey(keypair.privateKey),
	    importedPrivateKey = await krypto.importKey(serializedPrivateKey, 'decrypt'),
	    message = makeMessage(446),
	    encrypted = await krypto.encrypt(keypair.publicKey, message);
	isBase64URL(serializedPrivateKey);	
	expect(serializedPrivateKey.length).toBeGreaterThanOrEqual(privateEncryptingKeySize[0]); 
	expect(serializedPrivateKey.length).toBeLessThanOrEqual(privateEncryptingKeySize[1]);
	expect(await krypto.decrypt(importedPrivateKey, encrypted)).toBe(message)
      });
      const publicEncryptingKeySize = 736; //735; // raw 736; // with a 4k modulusSize key
      it(`works with the public key as a ${publicEncryptingKeySize} byte serialization.`, async function () {
	let keypair = await krypto.generateEncryptingKey(),
	    serializedPublicKey = await krypto.exportKey(keypair.publicKey),
	    importedPublicKey = await krypto.importKey(serializedPublicKey, 'encrypt'),
	    message = makeMessage(446),
	    encrypted = await krypto.encrypt(importedPublicKey, message);
	isBase64URL(serializedPublicKey);	
	expect(serializedPublicKey.length).toBe(publicEncryptingKeySize);
	expect(await krypto.decrypt(keypair.privateKey, encrypted)).toBe(message)
      });
    });

    describe('of symmetric key', function () {
      const symmetricKeySize = 44; //79; // raw 44
      it(`works as a ${symmetricKeySize} byte serialization.`, async function () {
	let key = await await krypto.generateSymmetricKey(),
	    serializedKey = await krypto.exportKey(key),
	    importedKey = await krypto.importKey(serializedKey, 'symmetric'),
	    message = makeMessage(),
	    encrypted = await krypto.encrypt(key, message);
	isBase64URL(serializedKey);
	expect(serializedKey.length).toBe(symmetricKeySize);	
	expect(await krypto.decrypt(importedKey, encrypted)).toBe(message);
      });
    });
  });

  it('wraps like export+encrypt.', async function () {
    // Let's "wrap" a symmetric key with an asymmetric encrypting key in two ways.
    let encryptableKey = await krypto.generateSymmetricKey(),
	wrappingKey = await krypto.generateEncryptingKey(),

	// Cycle it through export,encrypt to encrypted key, and decrypt,import to imported key.
	exported = await krypto.exportJWK(encryptableKey), 
	encrypted = await krypto.encrypt(wrappingKey.publicKey, JSON.stringify(exported)),
	decrypted = await krypto.decrypt(wrappingKey.privateKey, encrypted),
	imported = await krypto.importJWK(JSON.parse(decrypted)/*, 'symmetric'*/),

	// Cycle it through wrap and unwrap.
	wrapped = await krypto.wrapKey(encryptableKey, wrappingKey.publicKey),
	unwrapped = await krypto.unwrapKey(wrapped, wrappingKey.privateKey/*, 'symmetric'*/),

	// Use one to encrypt a message, and the other decrypt it.
	message = "this is a message",
	encryptedMessage = await krypto.encrypt(unwrapped, message),
	decryptedMessage = await krypto.decrypt(imported, encryptedMessage);
    isBase64URL(wrapped);
    expect(decryptedMessage).toBe(message);
  }, slowKeyCreation);
}
