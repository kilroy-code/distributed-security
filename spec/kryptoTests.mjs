import {makeMessage, isBase64URL} from "./support/messageText.mjs";

export default function testKrypto (krypto, // Pass either Krypto or MultiKrypto
				    encryptableSize = 446) {
  const bigEncryptable = encryptableSize > 1000,
	slowKeyCreation = 10e3,
	slowHybrid = bigEncryptable ? slowKeyCreation : 5e3; // Needed on Android

  describe('signing', function () {
    let message = makeMessage();
    it('returns truthy for verified at scale with an asymmetric keypair.', async function () {
      let keypair = await krypto.generateSigningKey(),
	  signature = await krypto.sign(keypair.privateKey, message);
      isBase64URL(signature);
      expect(await krypto.verify(keypair.publicKey, signature)).toBeTruthy();
    });
    it('returns undefined for verify with the wrong key.', async function () {
      let keypair = await krypto.generateSigningKey(),
	  signature = await krypto.sign(keypair.privateKey, message),
	  wrongKeypair = await krypto.generateSigningKey();
      expect(await krypto.verify(wrongKeypair.publicKey, signature)).toBeUndefined();
    });
    it('handles text, and verifies with that as text property.', async function () {
      let keypair = await krypto.generateSigningKey(),
	  signature = await krypto.sign(keypair.privateKey, message),
	  verified = await krypto.verify(keypair.publicKey, signature);
      expect(verified.protectedHeader.cty.startsWith('text')).toBeTruthy();
      expect(verified.text).toBe(message);
    });
    it('handles json, and verifies with that as json property.', async function () {
      let keypair = await krypto.generateSigningKey(),
	  message = {foo: 'bar'},
	  signature = await krypto.sign(keypair.privateKey, message),
	  verified = await krypto.verify(keypair.publicKey, signature);
      expect(verified.protectedHeader.cty.includes('json')).toBeTruthy();
      expect(verified.json).toEqual(message);
    });
    it('handles binary, and verifies with that as payload property.', async function () {
      let keypair = await krypto.generateSigningKey(),
	  message = new Uint8Array([21, 31]),
	  signature = await krypto.sign(keypair.privateKey, message),
	  verified = await krypto.verify(keypair.publicKey, signature);
      expect(verified.cty).toBeUndefined();
      expect(verified.payload).toEqual(message);
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
		  krypto.generateSymmetricKey("secret"),
		  krypto.generateSymmetricKey("secret"));
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
      await krypto.generateSymmetricKey("secret"),
      await krypto.generateSymmetricKey("secretX")
    ]);
  });

  describe('export/import', function () {
    describe(`of signing keys`, function () {
      const privateSigningSize = 253; // 248 raw
      it(`works with the private signing key as a ${privateSigningSize} byte serialization.`, async function () {
	let keypair = await krypto.generateSigningKey(),
	    serializedPrivateKey = await krypto.exportKey(keypair.privateKey),
	    importedPrivateKey = await krypto.importKey(serializedPrivateKey),
	    message = makeMessage(),
	    signature = await krypto.sign(importedPrivateKey, message);
	expect(serializedPrivateKey.length).toBe(privateSigningSize);
	expect(await krypto.verify(keypair.publicKey, signature)).toBeTruthy();
      });
      const publicSigningSize = 182; // 132 raw
      it(`works with the public verifying key as a ${publicSigningSize} byte serialization.`, async function () {
	let keypair = await krypto.generateSigningKey(),
	    serializedPublicKey = await krypto.exportKey(keypair.publicKey),
	    importedPublicKey = await krypto.importKey(serializedPublicKey),
	    message = makeMessage(),
	    signature = await krypto.sign(keypair.privateKey, message);
	expect(serializedPublicKey.length).toBe(publicSigningSize);
	expect(await krypto.verify(importedPublicKey, signature)).toBeTruthy();
      });

      const publicSigningRawSize = 132;
      it(`works with public key as a raw verifying key as a base64URL serialization of no more that ${publicSigningRawSize} bytes`, async function () {
	let keypair = await krypto.generateSigningKey(),
	    serializedPublicKey = await krypto.exportRaw(keypair.publicKey),
	    importedPublicKey = await krypto.importRaw(serializedPublicKey),
	    message = makeMessage(),
	    signature = await krypto.sign(keypair.privateKey, message);
	isBase64URL(serializedPublicKey);
	expect(serializedPublicKey.length).toBeLessThanOrEqual(publicSigningRawSize);
	expect(await krypto.verify(importedPublicKey, signature)).toBeTruthy();
      });
    });

    describe('of encryption keys', function () {
      const privateEncryptingKeySize = [3169, 3173] // raw [3164, 3168]; // with a 4k modulusSize key
      it(`works with the private key as a ${privateEncryptingKeySize[0]}-${privateEncryptingKeySize[1]} byte serialization.`, async function () {
	let keypair = await krypto.generateEncryptingKey(),
	    serializedPrivateKey = await krypto.exportKey(keypair.privateKey),
	    importedPrivateKey = await krypto.importKey(serializedPrivateKey),
	    message = makeMessage(446),
	    encrypted = await krypto.encrypt(keypair.publicKey, message);
	expect(serializedPrivateKey.length).toBeGreaterThanOrEqual(privateEncryptingKeySize[0]);
	expect(serializedPrivateKey.length).toBeLessThanOrEqual(privateEncryptingKeySize[1]);
	expect(await krypto.decrypt(importedPrivateKey, encrypted)).toBe(message)
      });
      const publicEncryptingKeySize = 735; // raw 736; // with a 4k modulusSize key
      it(`works with the public key as a ${publicEncryptingKeySize} byte serialization.`, async function () {
	let keypair = await krypto.generateEncryptingKey(),
	    serializedPublicKey = await krypto.exportKey(keypair.publicKey),
	    importedPublicKey = await krypto.importKey(serializedPublicKey),
	    message = makeMessage(446),
	    encrypted = await krypto.encrypt(importedPublicKey, message);
	expect(serializedPublicKey.length).toBe(publicEncryptingKeySize);
	expect(await krypto.decrypt(keypair.privateKey, encrypted)).toBe(message)
      });
    });

    describe('of symmetric key', function () {
      const symmetricKeySize = 79; // raw 44
      it(`works as a ${symmetricKeySize} byte serialization.`, async function () {
	let key = await await krypto.generateSymmetricKey(),
	    serializedKey = await krypto.exportKey(key),
	    importedKey = await krypto.importKey(serializedKey),
	    message = makeMessage(),
	    encrypted = await krypto.encrypt(key, message);
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
	imported = await krypto.importJWK(JSON.parse(decrypted)),

	// Cycle it through wrap and unwrap.
	wrapped = await krypto.wrapKey(encryptableKey, wrappingKey.publicKey),
	unwrapped = await krypto.unwrapKey(wrapped, wrappingKey.privateKey),

	// Use one to encrypt a message, and the other decrypt it.
	message = "this is a message",
	encryptedMessage = await krypto.encrypt(unwrapped, message),
	decryptedMessage = await krypto.decrypt(imported, encryptedMessage);
    isBase64URL(wrapped);
    expect(decryptedMessage).toBe(message);
  }, slowKeyCreation);
}
