/*
  TODO:

  Use webworker

  Persistence - getWrappedKey/setWrappedKey
  The retrieved value should include the signature so that the recipient can verify. Probably the signature of the storage service, too.

  Module
  Make configurable for NodeJS

  security concerns for web workers?
  e.g., we have a team worker ask a member worker to unwrap or decrypt stuff. Is that response visible to other workers?


  Demo
  ki1r0y package with GHA
  Doc and comments

  hidden rosters - can we make it so each tag key in the roster dictionary can only be read by the members?
  Can we do this "bottom up"?
    The current implementation starts with a team publicKey and lets you try to find a path down to your device key. That has two problems:
    - It exposes member publicKeys to all (because you need to be able to read the publicKeys before you have established membership).
    - It goes down a lot of wrong paths, each with a branching set of network calls.
*/
import Krypto from "../krypto.mjs";
import MultiKrypto from "../multiKrypto.mjs";
import Security from "../security.mjs";
import {Vault, DeviceVault, TeamVault} from "../vault.mjs";

jasmine.getEnv().configure({random: false});

describe('Distributed Security', function () {
  let scale = 1024 * 1024;
  function makeMessage(length = scale) {
    return Array.from({length}, (_, index) => index & 1).join('');
  }
  function testKrypto (krypto, encryptableSize = 446) {
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
      krypto._counter = 1; // FIXME remove
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
	  decryptedMessage = await Krypto.decrypt(imported, encryptedMessage);
      expect(decryptedMessage).toBe(message);
    });
  }
  describe('Krypto', function () { testKrypto(Krypto); });
  describe('MultiKrypto', function () {
    testKrypto(MultiKrypto, scale);
    describe('multikey', function () {
      describe('encryption/decryption', function () {
	let message = makeMessage(),
	    encrypted, keypair, symmetric;
	beforeAll(async function () {
	  symmetric = await MultiKrypto.generateSymmetricKey();
	  keypair = await MultiKrypto.generateEncryptingKey();
	  encrypted = await MultiKrypto.encrypt({a: symmetric, b: keypair.publicKey}, message);
	});
	it('works for symmetric members.', async function () {
	  let decrypted = await MultiKrypto.decrypt({a: symmetric}, encrypted);
	  expect(decrypted).toBe(message);
	});
	it('works for keypair members.', async function () {
	  let decrypted = await MultiKrypto.decrypt({b: keypair.privateKey}, encrypted);
	  expect(decrypted).toBe(message);
	});
	it('produces undefined for bad/missing decryption keys.', async function () {
	  let anotherKey = await MultiKrypto.generateSymmetricKey(),
	      decrypted = await MultiKrypto.decrypt({b: symmetric, c: anotherKey}, encrypted);
	  expect(decrypted).toBeUndefined();
	});
      });
      describe('multi key', function () {
	let encryptingMultikey, decryptingMultikey, message = makeMessage();
	beforeAll(async function () {
	  let keypair1 = await MultiKrypto.generateEncryptingKey(),
	      keypair2 = await MultiKrypto.generateEncryptingKey(),
	      keypair3 = await MultiKrypto.generateEncryptingKey();
	  encryptingMultikey = {a: keypair1.publicKey, b: keypair2.publicKey};
	  decryptingMultikey = {c: keypair3.privateKey, b: keypair2.privateKey};
	  message = makeMessage();
	});
	it('can be exported/imported with a single use for all members.', async function () {
	  let exported = await MultiKrypto.exportKey(encryptingMultikey),
	      imported = await MultiKrypto.importKey(exported, 'encrypt'),
	      // Now prove that the imported multikey works.
	      encrypted = await MultiKrypto.encrypt(imported, message),
	      decrypted = await MultiKrypto.decrypt(decryptingMultikey, encrypted);
	  expect(decrypted).toBe(message);
	});
	it('can be exported/imported with a map of use.', async function () {
	  let encryptingKeypair = await MultiKrypto.generateEncryptingKey(),
	      signingKeypair = await MultiKrypto.generateSigningKey(),
	      exported = await MultiKrypto.exportKey({myDecrypt: encryptingKeypair.privateKey, mySign: signingKeypair.privateKey}),
	      imported = await MultiKrypto.importKey(exported, {myDecrypt: 'decrypt', mySign: 'sign'}),
	      // Now prove that the imported multikey works.
	      message  = "a smaller message for asymmetric encryption",
	      encrypted = await MultiKrypto.encrypt(encryptingKeypair.publicKey, message),
	      decrypted = await MultiKrypto.decrypt(imported.myDecrypt, encrypted),
	      signed = await MultiKrypto.sign(imported.mySign, message);
	  expect(decrypted).toBe(message);
	  expect(await MultiKrypto.verify(signingKeypair.publicKey, signed, message)).toBeTruthy();
	});
	it('can wrap/unwrap a simple key.', async function () {
	  let key = await MultiKrypto.generateSymmetricKey(),
	      wrapped = await MultiKrypto.wrapKey(key, encryptingMultikey),
	      unwrapped = await MultiKrypto.unwrapKey(wrapped, decryptingMultikey, 'symmetric'),
	      // Cool, now prove that worked.
	      message = makeMessage(),
	      encrypted = await MultiKrypto.encrypt(unwrapped, message),
	      decrypted = await MultiKrypto.decrypt(key, encrypted);
	  expect(decrypted).toBe(message);
	});
	it('can be wrapped/unwrapped by a symmetric key with a single use for all members.', async function () {
	  let wrappingKey = await MultiKrypto.generateSymmetricKey(),
	      wrapped = await MultiKrypto.wrapKey(encryptingMultikey, wrappingKey),
	      unwrapped = await MultiKrypto.unwrapKey(wrapped, wrappingKey, 'encrypt'),
	      // Cool, now prove that worked.
	      encrypted = await MultiKrypto.encrypt(unwrapped, message),
	      decrypted = await MultiKrypto.decrypt(decryptingMultikey, encrypted);
	  expect(decrypted).toBe(message);
	});
	it('can wrap/unwrap a symmetric multikey with a single use for all members.', async function () {
	  let key = {x: await MultiKrypto.generateSymmetricKey(), y: await MultiKrypto.generateSymmetricKey()},
	      wrapped = await MultiKrypto.wrapKey(key, encryptingMultikey),
	      unwrapped = await MultiKrypto.unwrapKey(wrapped, decryptingMultikey, 'symmetric'),
	      // Cool, now prove that worked.
	      message = makeMessage(),
	      encrypted = await MultiKrypto.encrypt(unwrapped, message),
	      decrypted = await MultiKrypto.decrypt(key, encrypted);
	  expect(decrypted).toBe(message);
	});
	it('can wrap/unwrap a diversified multikey with a map of use.', async function () {
	  let encryptingKeypair = await MultiKrypto.generateEncryptingKey(),
	      signingKeypair = await MultiKrypto.generateSigningKey(),
	      wrapped = await MultiKrypto.wrapKey({myDecrypt: encryptingKeypair.privateKey, mySign: signingKeypair.privateKey}, encryptingMultikey),
	      unwrapped = await MultiKrypto.unwrapKey(wrapped, decryptingMultikey, {myDecrypt: 'decrypt', mySign: 'sign'}),
	      // Cool, now prove that worked.
	      message = "a shorter message",
	      encrypted = await MultiKrypto.encrypt(encryptingKeypair.publicKey, message),
	      decrypted = await MultiKrypto.decrypt(unwrapped.myDecrypt, encrypted),
	      signature = await MultiKrypto.sign(unwrapped.mySign, message);
	  expect(decrypted).toBe(message),
	  expect(await MultiKrypto.verify(signingKeypair.publicKey, signature, message)).toBeTruthy();
	});
      });
    });
  });
  describe('Security', function () {
    let device, otherDevice, user, team, otherUser, otherTeam, tags;
    beforeAll(async function () {
      device = await new DeviceVault().getTag();
      otherDevice = await new DeviceVault().getTag();
      user = await TeamVault.create([device]);
      otherUser = await TeamVault.create([otherDevice]);
      team = await TeamVault.create([otherUser, user]);
      otherTeam = await TeamVault.create([otherUser, user]);   // Note: same members, but a different identity.
      tags = {device, user, otherDevice, otherUser, team, otherTeam};
      //console.log('before tests, Teams:', Security.Team, Vault.vaults);
    });
    afterAll(async function () { // Just report for debugging.
      //await Promise.all([device, /*'missing',*/ otherUser, user, team].map(async tag => console.log(tag, Vault.vaults[tag])));
      //console.log(Security.EncryptionKey)
    });
    describe('internal machinery', function () {
      function vaultTests(label, tagsKey) {
	describe(label, function () {	
	  let vault, tag;
	  beforeAll(async function () {
	    tag = tags[tagsKey];
	    vault = await Vault.ensure(tag);
	  });
	  it('vault creation results in something that be retrieved from Vault.ensure.', async function() {
	    expect(await vault.getTag()).toBe(tag);
	  });
	  it('tag is exported verify key, and vault.sign() pairs with it.', async function () {
	    let tag = vault.tag,
		verifyKey = await MultiKrypto.importKey(tag, 'verify'),
		exported = await MultiKrypto.exportKey(verifyKey);
	    expect(typeof tag).toBe('string');
	    expect(exported).toBe(tag);

	    let message = makeMessage(),
		signature = await vault.sign(message);
	    expect(await MultiKrypto.verify(verifyKey, signature, message)).toBeTruthy();
	  });
	  it('public encryption tag can be retrieved externally, and vault.decrypt() pairs with it.', async function () {
	    let tag = vault.tag,
		message = makeMessage(scale),
		retrieved = await Security.retrieve('EncryptionKey', tag),
		imported = await MultiKrypto.importKey(retrieved, 'encrypt'),
		encrypted = await MultiKrypto.encrypt(imported, message),
		decrypted = await vault.decrypt(encrypted);
	    expect(decrypted).toBe(message);
	  });
	});
      }
      vaultTests('DeviceVault', 'device');
      vaultTests('TeamVault', 'user');
    });
    describe("Usage", function () {
      function test(label, tagsKey, otherTagsKey) {
	describe(label, function () {
	  let tag, otherTag;
	  beforeAll(function () {
	    tag = tags[tagsKey];
	    otherTag = tags[otherTagsKey];
	  });
	  it('can sign and be verified.', async function () {
	    let message = makeMessage(),
		signature = await Security.sign(tag, message);
	    expect(await Security.verify(tag, signature, message)).toBeTruthy();
	  });
	  it('cannot sign for a different key.', async function () {
	    let message = makeMessage(),
		signature = await Security.sign(otherTag, message);
	    expect(await Security.verify(tag, signature, message)).toBeFalsy();
	  });
	  it('can decrypt what is encrypted for it.', async function () {
	    let message = makeMessage(scale),
		encrypted = await Security.encrypt(tag, message),
		decrypted = await Security.decrypt(tag, encrypted);
	    expect(decrypted).toBe(message);
	  });
	  it('cannot decrypt what is encrypted for a different key.', async function () {
	    let message = makeMessage(446),
		encrypted = await Security.encrypt(otherTag, message),
		decrypted = await Security.decrypt(tag, encrypted).catch(_ => null);
	    expect(decrypted).toBeFalsy();
	  });
	});
      }
      test('DeviceVault', 'device', 'otherDevice');
      test('User TeamVault', 'user', 'otherUser');
      test('Team TeamVault', 'team', 'otherTeam');      
    });
  });
});
