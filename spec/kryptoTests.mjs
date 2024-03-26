import {makeMessage, isBase64URL, sameTypedArray} from "./support/messageText.mjs";

export default function testKrypto (krypto, // Pass either Krypto or MultiKrypto
                                    encryptableSize = 446) {
  const bigEncryptable = encryptableSize > 1000,
        slowKeyCreation = 10e3,
        slowHybrid = bigEncryptable ? slowKeyCreation : 5e3, // Needed on Android
        message = makeMessage();

  describe('signing', function () {
    let keypair;
    beforeAll(async function () {
      keypair = await krypto.generateSigningKey();
    });
    it('with a private key produces a base64URL signature that verifies with the public key.', async function () {
      let signature = await krypto.sign(keypair.privateKey, message);
      isBase64URL(signature);
      expect(await krypto.verify(keypair.publicKey, signature)).toBeTruthy();
    });
    it('returns undefined for verify with the wrong key.', async function () {
      let signature = await krypto.sign(keypair.privateKey, message),
          wrongKeypair = await krypto.generateSigningKey();
      expect(await krypto.verify(wrongKeypair.publicKey, signature)).toBeUndefined();
    });
    it('handles binary, and verifies with that as payload property.', async function () {
      let message = new Uint8Array([21, 31]),
          signature = await krypto.sign(keypair.privateKey, message),
          verified = await krypto.verify(keypair.publicKey, signature);
      expect(verified.cty).toBeUndefined();
      sameTypedArray(verified, message);
    });
    it('handles text, setting cty as "text/plain", and verifies with that as the text property and an encoding of that for payload.', async function () {
      let signature = await krypto.sign(keypair.privateKey, message),
          verified = await krypto.verify(keypair.publicKey, signature);
      expect(verified.protectedHeader.cty).toBe('text/plain');
      expect(verified.text).toBe(message);
      expect(verified.payload).toEqual(new TextEncoder().encode(message));
    });
    it('handles json, setting cty as "json", and verifies with that as json property, the string of that as the text property, and the encoding of that string for payload.', async function () {
      let message = {foo: 'bar'},
          signature = await krypto.sign(keypair.privateKey, message),
          verified = await krypto.verify(keypair.publicKey, signature);
      expect(verified.protectedHeader.cty).toBe('json');
      expect(verified.json).toEqual(message);
      expect(verified.text).toBe(JSON.stringify(message));
      expect(verified.payload).toEqual(new TextEncoder().encode(JSON.stringify(message)));
    });
    it('Uses specified headers if supplied, including cty.', async function () {
      let cty = 'text/html',
          iat = Date.now(),
          foo = 17,
          message = "<something else>",
          signature = await krypto.sign(keypair.privateKey, message, {cty, iat, foo}),
          verified = await krypto.verify(keypair.publicKey, signature);
      expect(verified.protectedHeader.cty).toBe(cty);
      expect(verified.protectedHeader.iat).toBe(iat);
      expect(verified.protectedHeader.foo).toBe(foo);
      expect(verified.text).toEqual(message);
    });
  });

  describe('encryption', function () {
    let keypair;
    beforeAll(async function () {
      keypair = await krypto.generateEncryptingKey();
    });
    it(`can work up through at least ${encryptableSize} bytes with an asymmetric keypair.`, async function () {
      // Public key encrypt will work up through 446 bytes, but the result will not decrypt.
      let message = makeMessage(encryptableSize),
          encrypted = await krypto.encrypt(keypair.publicKey, message),
          decrypted = await krypto.decrypt(keypair.privateKey, encrypted);
      isBase64URL(encrypted);
      expect(decrypted.text).toBe(message)
    }, slowHybrid);
    function testSymmetric(label, promise, decryptPromise = promise) {
      it(`can work on much larger data with a ${label}.`, async function () {
        let key = await promise,
            decryptKey = await decryptPromise,
            encrypted = await krypto.encrypt(key, message),
            decrypted = await krypto.decrypt(decryptKey, encrypted);
        isBase64URL(encrypted);
        expect(decrypted.text).toBe(message);
      });
    }
    testSymmetric('fixed symmetric key',
                  krypto.generateSymmetricKey());
    testSymmetric('reproducible secret',
                  krypto.generateSymmetricKey("secret"),
                  krypto.generateSymmetricKey("secret"));

    it('handles binary, and decrypts as same.', async function () {
      let message = new Uint8Array([21, 31]),
          encrypted = await krypto.encrypt(keypair.publicKey, message),
          decrypted = await krypto.decrypt(keypair.privateKey, encrypted),
          header = krypto.decodeProtectedHeader(encrypted);
      expect(header.cty).toBeUndefined();
      sameTypedArray(decrypted, message);
    });
    it('handles text, and decrypts as same.', async function () {
      let encrypted = await krypto.encrypt(keypair.publicKey, message),
          decrypted = await krypto.decrypt(keypair.privateKey, encrypted),
          header = krypto.decodeProtectedHeader(encrypted);
      expect(header.cty).toBe('text/plain');
      expect(decrypted.text).toBe(message);
    });
    it('handles json, and decrypts as same.', async function () {
      let message = {foo: 'bar'},
          encrypted = await krypto.encrypt(keypair.publicKey, message);
      let header = krypto.decodeProtectedHeader(encrypted),
          decrypted = await krypto.decrypt(keypair.privateKey, encrypted);
      expect(header.cty).toBe('json');
      expect(decrypted.json).toEqual(message);
    });
    it('Uses specified headers if supplied, including cty.', async function () {
      let cty = 'text/html',
          iat = Date.now(),
          foo = 17,
          message = "<something else>",
          encrypted = await krypto.encrypt(keypair.publicKey, message, {cty, iat, foo}),
          decrypted = await krypto.decrypt(keypair.privateKey, encrypted),
          header = krypto.decodeProtectedHeader(encrypted)
      expect(header.cty).toBe(cty);
      expect(header.iat).toBe(iat);
      expect(header.foo).toBe(foo);
      expect(decrypted.text).toBe(message);
    });
    
    function failsWithWrong(label, keysThunk) {
      it(`rejects wrong ${label}.`, async function() {
        let [encryptKey, decryptKey] = await keysThunk(),
            message = makeMessage(encryptableSize),
            encrypted = await krypto.encrypt(encryptKey, message);
        await expectAsync(krypto.decrypt(decryptKey, encrypted)).toBeRejected();
      }, slowKeyCreation);
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
    // Handy for cycling in a size-checkable way.
    async function exportKey(key) {
      return JSON.stringify(await krypto.exportJWK(key));
    }
    function importKey(string) {
      return krypto.importJWK(JSON.parse(string));
    }

    describe(`of signing keys`, function () {
      const privateSigningSize = 253; // 248 raw
      it(`works with the private signing key as a ${privateSigningSize} byte serialization.`, async function () {
        let keypair = await krypto.generateSigningKey(),
            serializedPrivateKey = await exportKey(keypair.privateKey),
            importedPrivateKey = await importKey(serializedPrivateKey),
            signature = await krypto.sign(importedPrivateKey, message);
        expect(serializedPrivateKey.length).toBe(privateSigningSize);
        expect(await krypto.verify(keypair.publicKey, signature)).toBeTruthy();
      });
      const publicSigningSize = 182; // 132 raw
      it(`works with the public verifying key as a ${publicSigningSize} byte serialization.`, async function () {
        let keypair = await krypto.generateSigningKey(),
            serializedPublicKey = await exportKey(keypair.publicKey),
            importedPublicKey = await importKey(serializedPublicKey),
            signature = await krypto.sign(keypair.privateKey, message);
        expect(serializedPublicKey.length).toBe(publicSigningSize);
        expect(await krypto.verify(importedPublicKey, signature)).toBeTruthy();
      });

      const publicSigningRawSize = 132;
      it(`works with public key as a raw verifying key as a base64URL serialization of no more that ${publicSigningRawSize} bytes`, async function () {
        let keypair = await krypto.generateSigningKey(),
            serializedPublicKey = await krypto.exportRaw(keypair.publicKey),
            importedPublicKey = await krypto.importRaw(serializedPublicKey),
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
            serializedPrivateKey = await exportKey(keypair.privateKey),
            importedPrivateKey = await importKey(serializedPrivateKey),
            message = makeMessage(446),
            encrypted = await krypto.encrypt(keypair.publicKey, message),
            decrypted = await krypto.decrypt(importedPrivateKey, encrypted);
        expect(serializedPrivateKey.length).toBeGreaterThanOrEqual(privateEncryptingKeySize[0]);
        expect(serializedPrivateKey.length).toBeLessThanOrEqual(privateEncryptingKeySize[1]);
        expect(decrypted.text).toBe(message)
      });
      const publicEncryptingKeySize = 735; // raw 736; // with a 4k modulusSize key
      it(`works with the public key as a ${publicEncryptingKeySize} byte serialization.`, async function () {
        let keypair = await krypto.generateEncryptingKey(),
            serializedPublicKey = await exportKey(keypair.publicKey),
            importedPublicKey = await importKey(serializedPublicKey),
            message = makeMessage(446),
            encrypted = await krypto.encrypt(importedPublicKey, message),
            decrypted = await krypto.decrypt(keypair.privateKey, encrypted);
        expect(serializedPublicKey.length).toBe(publicEncryptingKeySize);
        expect(decrypted.text).toBe(message)
      });
    });

    describe('of symmetric key', function () {
      const symmetricKeySize = 79; // raw 44
      it(`works as a ${symmetricKeySize} byte serialization.`, async function () {
        let key = await krypto.generateSymmetricKey(),
            serializedKey = await exportKey(key),
            importedKey = await importKey(serializedKey),
            encrypted = await krypto.encrypt(key, message),
            decrypted = await krypto.decrypt(importedKey, encrypted);
        expect(serializedKey.length).toBe(symmetricKeySize);
        expect(decrypted.text).toBe(message);
      });
    });
  });

  it('wraps like export+encrypt.', async function () {
    // Let's "wrap" a symmetric key with an asymmetric encrypting key in two ways.
    let encryptableKey = await krypto.generateSymmetricKey(),
        wrappingKey = await krypto.generateEncryptingKey(),

        // Cycle it through export,encrypt to encrypted key, and decrypt,import to imported key.
        exported = await krypto.exportJWK(encryptableKey),
        encrypted = await krypto.encrypt(wrappingKey.publicKey, exported),
        decrypted = await krypto.decrypt(wrappingKey.privateKey, encrypted),
        imported = await krypto.importJWK(decrypted.json),

        // Cycle it through wrap and unwrap.
        wrapped = await krypto.wrapKey(encryptableKey, wrappingKey.publicKey),
        unwrapped = await krypto.unwrapKey(wrapped, wrappingKey.privateKey),

        // Use one to encrypt a message, and the other decrypt it.
        message = "this is a message",
        encryptedMessage = await krypto.encrypt(unwrapped, message),
        decryptedMessage = await krypto.decrypt(imported, encryptedMessage);
    isBase64URL(wrapped);
    expect(decryptedMessage.text).toBe(message);
  }, slowKeyCreation);
}
