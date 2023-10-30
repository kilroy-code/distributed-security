import {scale, makeMessage} from "./support/messageText.mjs";
import testKrypto from "./kryptoTests.mjs";

export default function testMultiKrypto(multiKrypto) {
  const slowKeyCreation = 20e3; // Android
  testKrypto(multiKrypto, scale);

  describe('multikey', function () {

    describe('encryption/decryption', function () {
      let message = makeMessage(),
	  encrypted, keypair, symmetric;
      beforeAll(async function () {
	symmetric = await multiKrypto.generateSymmetricKey();
	keypair = await multiKrypto.generateEncryptingKey();
	encrypted = await multiKrypto.encrypt({a: symmetric, b: keypair.publicKey}, message);
      }, slowKeyCreation);
      it('works for symmetric members.', async function () {
	let decrypted = await multiKrypto.decrypt({a: symmetric}, encrypted);
	expect(decrypted).toBe(message);
      });
      it('works for keypair members.', async function () {
	let decrypted = await multiKrypto.decrypt({b: keypair.privateKey}, encrypted);
	expect(decrypted).toBe(message);
      });
      it('produces undefined for bad/missing decryption keys.', async function () {
	let anotherKey = await multiKrypto.generateSymmetricKey(),
	    decrypted = await multiKrypto.decrypt({b: symmetric, c: anotherKey}, encrypted);
	expect(decrypted).toBeUndefined();
      });
    });

    describe('multi key', function () {
      let encryptingMultikey, decryptingMultikey, message = makeMessage();
      beforeAll(async function () {
	let keypair1 = await multiKrypto.generateEncryptingKey(),
	    keypair2 = await multiKrypto.generateEncryptingKey(),
	    keypair3 = await multiKrypto.generateEncryptingKey();
	encryptingMultikey = {a: keypair1.publicKey, b: keypair2.publicKey};
	decryptingMultikey = {c: keypair3.privateKey, b: keypair2.privateKey};
	message = makeMessage();
      }, slowKeyCreation);
      it('can be exported/imported with a single use for all members.', async function () {
	let exported = await multiKrypto.exportKey(encryptingMultikey),
	    imported = await multiKrypto.importKey(exported, 'encrypt'),
	    // Now prove that the imported multikey works.
	    encrypted = await multiKrypto.encrypt(imported, message),
	    decrypted = await multiKrypto.decrypt(decryptingMultikey, encrypted);
	expect(decrypted).toBe(message);
      });
      it('can be exported/imported with a map of use.', async function () {
	let encryptingKeypair = await multiKrypto.generateEncryptingKey(),
	    signingKeypair = await multiKrypto.generateSigningKey(),
	    exported = await multiKrypto.exportKey({myDecrypt: encryptingKeypair.privateKey, mySign: signingKeypair.privateKey}),
	    imported = await multiKrypto.importKey(exported, {myDecrypt: 'decrypt', mySign: 'sign'}),
	    // Now prove that the imported multikey works.
	    message  = "a smaller message for asymmetric encryption",
	    encrypted = await multiKrypto.encrypt(encryptingKeypair.publicKey, message),
	    decrypted = await multiKrypto.decrypt(imported.myDecrypt, encrypted),
	    signed = await multiKrypto.sign(imported.mySign, message);
	expect(decrypted).toBe(message);
	expect(await multiKrypto.verify(signingKeypair.publicKey, signed, message)).toBeTruthy();
      });
      it('can wrap/unwrap a simple key.', async function () {
	let key = await multiKrypto.generateSymmetricKey(),
	    wrapped = await multiKrypto.wrapKey(key, encryptingMultikey),
	    unwrapped = await multiKrypto.unwrapKey(wrapped, decryptingMultikey, 'symmetric'),
	    // Cool, now prove that worked.
	    message = makeMessage(),
	    encrypted = await multiKrypto.encrypt(unwrapped, message),
	    decrypted = await multiKrypto.decrypt(key, encrypted);
	expect(decrypted).toBe(message);
      });
      it('can be wrapped/unwrapped by a symmetric key with a single use for all members.', async function () {
	let wrappingKey = await multiKrypto.generateSymmetricKey(),
	    wrapped = await multiKrypto.wrapKey(encryptingMultikey, wrappingKey),
	    unwrapped = await multiKrypto.unwrapKey(wrapped, wrappingKey, 'encrypt'),
	    // Cool, now prove that worked.
	    encrypted = await multiKrypto.encrypt(unwrapped, message),
	    decrypted = await multiKrypto.decrypt(decryptingMultikey, encrypted);
	expect(decrypted).toBe(message);
      });
      it('can wrap/unwrap a symmetric multikey with a single use for all members.', async function () {
	let key = {x: await multiKrypto.generateSymmetricKey(), y: await multiKrypto.generateSymmetricKey()},
	    wrapped = await multiKrypto.wrapKey(key, encryptingMultikey),
	    unwrapped = await multiKrypto.unwrapKey(wrapped, decryptingMultikey, 'symmetric'),
	    // Cool, now prove that worked.
	    message = makeMessage(),
	    encrypted = await multiKrypto.encrypt(unwrapped, message),
	    decrypted = await multiKrypto.decrypt(key, encrypted);
	expect(decrypted).toBe(message);
      });
      it('can wrap/unwrap a diversified multikey with a map of use.', async function () {
	let encryptingKeypair = await multiKrypto.generateEncryptingKey(),
	    signingKeypair = await multiKrypto.generateSigningKey(),
	    wrapped = await multiKrypto.wrapKey({myDecrypt: encryptingKeypair.privateKey, mySign: signingKeypair.privateKey}, encryptingMultikey),
	    unwrapped = await multiKrypto.unwrapKey(wrapped, decryptingMultikey, {myDecrypt: 'decrypt', mySign: 'sign'}),
	    // Cool, now prove that worked.
	    message = "a shorter message",
	    encrypted = await multiKrypto.encrypt(encryptingKeypair.publicKey, message),
	    decrypted = await multiKrypto.decrypt(unwrapped.myDecrypt, encrypted),
	    signature = await multiKrypto.sign(unwrapped.mySign, message);
	expect(decrypted).toBe(message),
	expect(await multiKrypto.verify(signingKeypair.publicKey, signature, message)).toBeTruthy();
      }, slowKeyCreation);
    });
  });
}
