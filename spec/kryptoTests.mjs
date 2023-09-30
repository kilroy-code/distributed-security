import {makeMessage} from "./support/messageText.mjs";

export default function testKrypto (krypto, encryptableSize = 446) {

  describe('signing', function () {
    it('can be verified at scale with a keypair using RSA-PSS.', async function () {
      let keypair = await krypto.generateSigningKey(),
	  message = makeMessage(), // Public key encrypt will work up through 446 bytes, but the result will not decrypt.
	  signature = await krypto.sign(keypair.privateKey, message);
      expect(typeof signature).toBe('string');
      expect(await krypto.verify(keypair.publicKey, signature, message)).toBeTruthy();
    });
  });

  describe('encryption', function () {
    it(`can work up through ${encryptableSize} bytes with a keypair using ${encryptableSize > 1000 ? "hybrid symmetric and " : ""}RSA-OAEP.`, async function () {
      let keypair = await krypto.generateEncryptingKey(),
	  message = makeMessage(encryptableSize),
	  encrypted = await krypto.encrypt(keypair.publicKey, message);
      expect(typeof encrypted).toBe('string');
      expect(await krypto.decrypt(keypair.privateKey, encrypted)).toBe(message)
    });
    it('can work on much larger data with a symmetric key using AES-GCM.', async function () {
      let key = await await krypto.generateSymmetricKey(),
	  message = makeMessage(),
	  encrypted = await krypto.encrypt(key, message);
      expect(typeof encrypted).toBe('string');
      expect(await krypto.decrypt(key, encrypted)).toBe(message);
    });
  });

  describe('base64 export/import', function () {
    let signingAlgo = krypto.signingAlgorithm.name,
	isRSA = signingAlgo.startsWith('RSA');

    describe(`of ${signingAlgo}`, function () {
      let minPrivate = isRSA ? 3164 : 248,
	  maxPrivate = isRSA ? 3168 : 248,
	  pub = isRSA ? 736 : (krypto.exportFormat('verify') === 'raw' ? 132 : 160);
      it(`works with the private signing key as a ${minPrivate}-${maxPrivate} byte serialization.`, async function () {
	let keypair = await krypto.generateSigningKey(),
	    serializedPrivateKey = await krypto.exportKey(keypair.privateKey), 
	    importedPrivateKey = await krypto.importKey(serializedPrivateKey, 'sign'), 
	    message = makeMessage(),
	    signature = await krypto.sign(importedPrivateKey, message);
	// fixme: remove "if (signingAlgo)" throughout
	if (signingAlgo) expect(serializedPrivateKey.length).toBeGreaterThanOrEqual(minPrivate);	
	if (signingAlgo) expect(serializedPrivateKey.length).toBeLessThanOrEqual(maxPrivate);  
	expect(await krypto.verify(keypair.publicKey, signature, message)).toBeTruthy();
      });
      it(`works with the public verifying key as a ${pub} byte serialization.`, async function () {
	let keypair = await krypto.generateSigningKey(),
	    serializedPublicKey = await krypto.exportKey(keypair.publicKey), 
	    importedPublicKey = await krypto.importKey(serializedPublicKey, 'verify'), 
	    message = makeMessage(),
	    signature = await krypto.sign(keypair.privateKey, message);
	if (signingAlgo) expect(serializedPublicKey.length).toBe(pub)
	expect(await krypto.verify(importedPublicKey, signature, message)).toBeTruthy();
      });
    });

    describe('of RSA-OEP', function () {
      it('works  with the private decrypting key as a 3164-3168 byte serialization.', async function () {
	let keypair = await krypto.generateEncryptingKey(),
	    serializedPrivateKey = await krypto.exportKey(keypair.privateKey),
	    importedPrivateKey = await krypto.importKey(serializedPrivateKey, 'decrypt'),
	    message = makeMessage(446),
	    encrypted = await krypto.encrypt(keypair.publicKey, message);
	if (signingAlgo) expect(serializedPrivateKey.length).toBeGreaterThanOrEqual(3164);	
	if (signingAlgo) expect(serializedPrivateKey.length).toBeLessThanOrEqual(3168);  
	expect(await krypto.decrypt(importedPrivateKey, encrypted)).toBe(message)
      });
      it('works with the public encrypting key as a 736 byte serialization.', async function () {
	let keypair = await krypto.generateEncryptingKey(),
	    serializedPublicKey = await krypto.exportKey(keypair.publicKey),
	    importedPublicKey = await krypto.importKey(serializedPublicKey, 'encrypt'),
	    message = makeMessage(446),
	    encrypted = await krypto.encrypt(importedPublicKey, message);
	if (signingAlgo) expect(serializedPublicKey.length).toBe(736);  
	expect(await krypto.decrypt(keypair.privateKey, encrypted)).toBe(message)
      });
    });

    describe('of AES-GCM', function () {
      it('works with the symmetric key+iv as a 60 byte serialization.', async function () {
	let key = await await krypto.generateSymmetricKey(),
	    serializedKey = await krypto.exportKey(key),
	    importedKey = await krypto.importKey(serializedKey, 'symmetric'),
	    message = makeMessage(),
	    encrypted = await krypto.encrypt(key, message);
	if (signingAlgo) expect(serializedKey.length).toBe(60);
	expect(await krypto.decrypt(importedKey, encrypted)).toBe(message);
      });
    });
  });

  it('wraps like encrypt/export.', async function () {
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
    expect(decryptedMessage).toBe(message);
  });
}
