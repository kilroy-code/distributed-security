import dispatch from "../../jsonrpc/index.mjs";
import Storage from "./support/storage.mjs";

import Security from "../index.mjs";
//import Security from "https://kilroy-code.github.io/distributed-security/index.mjs";
import * as JOSE from '../node_modules/jose/dist/browser/index.js';
window.JOSE = JOSE;

import Krypto from "../lib/krypto.mjs";
import MultiKrypto from "../lib/multiKrypto.mjs";
import {Vault, DeviceVault, TeamVault} from "../lib/vault.mjs";
import InternalSecurity from "../lib/security.mjs";
Object.assign(window, {Krypto, MultiKrypto, Security, Storage}); // export to browser console for development/debugging experiments.

import testKrypto from "./kryptoTests.mjs";
import testMultiKrypto from "./multiKryptoTests.mjs";
import testModule from "./support/testModuleWithFoo.mjs";
import {scale, makeMessage, isBase64URL} from "./support/messageText.mjs";

//jasmine.getEnv().configure({random: false});

InternalSecurity.Storage = Security.Storage = Storage;
InternalSecurity.getUserDeviceSecret = (tag, recoveryPrompt) => recoveryPrompt ? recoveryPrompt + " is true" : "test secret";
Security.getUserDeviceSecret = (tag, recoveryPrompt) => "another secret";

describe('Distributed Security', function () {
  let message = makeMessage();
  describe('Krypto', function () {
    testKrypto(Krypto);
  });
  describe('MultiKrypto', function () {
    testMultiKrypto(MultiKrypto);
  });
  describe('Security', function () {
    const slowKeyCreation = 25e3; // e.g., Safari needs about 15 seconds. Android needs more
    async function makeVaults(scope) { // Create a standard set of test vaults through context.
      let tags = {};
      await Promise.all([
	tags.device = await scope.create(),
	tags.otherDevice = await scope.create()
      ]);
      await Promise.all([
	tags.recovery = await scope.create({prompt: "what?"}),
	tags.otherRecovery = await scope.create({prompt: "nope!"})
      ]);
      await Promise.all([
	tags.user = await scope.create(tags.device),
	tags.otherUser = await scope.create(tags.otherDevice)
      ]);
      await Promise.all([
	tags.team = await scope.create(tags.otherUser, tags.user),
	tags.otherTeam = await scope.create(tags.otherUser, tags.user)   // Note: same members, but a different identity.
      ]);
      return tags;
    }
    async function destroyVaults(scope, tags) {
      await Promise.all(Object.values(tags).map(tag => scope.destroy(tag)));
    }
    describe('internal machinery', function () {
      let tags;
      beforeAll(async function () {
	tags = await makeVaults(InternalSecurity);
      }, slowKeyCreation);
      afterAll(async function () {
	await destroyVaults(InternalSecurity, tags);
      }, slowKeyCreation);
      function vaultTests(label, tagsKey) {
	describe(label, function () {	
	  let vault, tag;
	  beforeAll(async function () {
	    tag = tags[tagsKey];
	    vault = await Vault.ensure(tag);
	  });
	  it('tag is exported verify key, and vault.sign() pairs with it.', async function () {
	    let tag = vault.tag,
		verifyKey = await MultiKrypto.importRaw(tag),
		exported = await MultiKrypto.exportRaw(verifyKey);
	    expect(typeof tag).toBe('string');
	    expect(exported).toBe(tag);

	    let signature = await vault.sign(message),
		verification = await MultiKrypto.verify(verifyKey, signature);
	    isBase64URL(signature);
	    expect(verification).toBeTruthy();
	  });
	  it('public encryption tag can be retrieved externally, and vault.decrypt() pairs with it.', async function () {
	    let tag = vault.tag,
		retrieved = await Storage.retrieve('EncryptionKey', tag),
		imported = await MultiKrypto.importJWK(JSON.parse(retrieved)),
		encrypted = await MultiKrypto.encrypt(imported, message),
		decrypted = await vault.decrypt(encrypted);
	    expect(decrypted).toBe(message);
	  });
	});
      }
      vaultTests('DeviceVault', 'device');
      vaultTests('TeamVault', 'user');
      describe('workers', function () {
	let isolatedWorker, request;
	beforeAll(function () {
	  isolatedWorker = new Worker("/@kilroy-code/distributed-security/spec/support/testWorkerWithModule.mjs", {type: 'module'});
	  request = dispatch({target: isolatedWorker});
	});
	afterAll(function () {
	  isolatedWorker.terminate();
	});
	it('do not share modules of the same name with applications.', async function () {
	  let workerInitialFoo = await request('getFoo'),
	      ourInitialFoo = testModule.foo,
	      ourNewFoo = 17;
	  expect(workerInitialFoo).toBe(ourInitialFoo);
	  expect(ourInitialFoo).not.toBe(ourNewFoo);
	  testModule.foo = ourNewFoo;
	  expect(testModule.foo).toBe(ourNewFoo);
	  expect(await request('getFoo')).toBe(workerInitialFoo);
	});
      });
    });
    describe("Usage", function () {
      let tags;
      beforeAll(async function () {
	console.log(await Security.ready);
	tags = await makeVaults(Security);
      }, slowKeyCreation);
      afterAll(async function () {
	await destroyVaults(Security, tags);
      }, slowKeyCreation);
      function test(label, tagsKey, otherTagsKey) {
	describe(label, function () {
	  let tag, otherTag;
	  beforeAll(function () {
	    tag = tags[tagsKey];
	    otherTag = tags[otherTagsKey];
	  });
	  describe('signature', function () {
	    describe('of one tag', function () {
	      it('can sign and be verified.', async function () {
		let signature = await Security.sign(message, tag);
		isBase64URL(signature);
		expect(await Security.verify(signature, tag)).toBeTruthy();
	      });
	      it('cannot sign for a different key.', async function () {
		let signature = await Security.sign(message, otherTag);
		expect(await Security.verify(signature, tag)).toBeUndefined();
	      });
	      it('distinguishes between correctly signing false and key failure.', async function () {
		let signature = await Security.sign(false, tag),
		    verified = await Security.verify(signature, tag);
		expect(verified.json).toBe(false);
	      });
	      it('can sign text and produce verified result with text property.', async function () {
		let signature = await Security.sign(message, tag),
		    verified = await Security.verify(signature, tag);
		isBase64URL(signature);
		expect(verified.text).toBe(message);
	      });
	      it('can sign json and produce verified result with json property.', async function () {
		let message = {x: 1, y: ["abc", null, false]},
		    signature = await Security.sign(message, tag),
		    verified = await Security.verify(signature, tag);
		isBase64URL(signature);
		expect(verified.json).toEqual(message);
	      });
	      it('can sign binary and produce verified result with payload property.', async function () {
		let message = new Uint8Array([1, 2, 3]),
		    signature = await Security.sign(message, tag),
		    verified = await Security.verify(signature, tag);
		isBase64URL(signature);
		expect(verified.payload).toEqual(message);
	      });
	    });
	    describe('of multiple tags', function () {
	      it('can sign and be verified.', async function () {
		let signature = await Security.sign(message, tag, otherTag);
		expect(await Security.verify(signature, otherTag, tag)).toBeTruthy(); // order does not matter
	      });
	      describe('bad verification', function () {
		let oneMore;
		beforeAll(async function () { oneMore = await Security.create(); });
		afterAll(async function () { await Security.destroy(oneMore); });
		describe('when mixing single and multi-tags', function () {
		  it('fails with extra signing tag.', async function () {
		    let signature = await Security.sign(message, otherTag);
		    expect(await Security.verify(signature, tag)).toBeUndefined();
		  });
		  it('fails with extra verifying.', async function () {
		    let signature = await Security.sign(message, tag);
		    expect(await Security.verify(signature, tag, otherTag)).toBeUndefined();
		  });
		});
		describe('when mixing multi-tag lengths', function () {
		  it('fails with extra signing tag.', async function () {
		    let signature = await Security.sign(message, otherTag, oneMore);
		    expect(await Security.verify(signature, tag, oneMore)).toBeUndefined();
		  });
		  it('fails with extra verifying tag.', async function () {
		    let signature = await Security.sign(message, tag, oneMore);
		    expect(await Security.verify(signature, tag, otherTag, oneMore)).toBeUndefined();
		  });
		});
	      });
	      it('distinguishes between correctly signing false and key failure.', async function () {
		let signature = await Security.sign(false, tag, otherTag),
		    verified = await Security.verify(signature, tag, otherTag);
		expect(verified.json).toBe(false);
	      });
	      it('can sign text and produce verified result with text property.', async function () {
		let signature = await Security.sign(message, tag, otherTag),
		    verified = await Security.verify(signature, tag, otherTag);
		expect(verified.text).toBe(message);
	      });
	      it('can sign json and produce verified result with json property.', async function () {
		let message = {x: 1, y: ["abc", null, false]},
		    signature = await Security.sign(message, tag, otherTag),
		    verified = await Security.verify(signature, tag, otherTag);
		expect(verified.json).toEqual(message);
	      });
	      it('can sign binary and produce verified result with payload property.', async function () {
		let message = new Uint8Array([1, 2, 3]),
		    signature = await Security.sign(message, tag, otherTag),
		    verified = await Security.verify(signature, tag, otherTag);
		expect(verified.payload).toEqual(message);
	      });
	    });
	  });
	  describe('encryption', function () {
	    it('can decrypt what is encrypted for it.', async function () {
	      let encrypted = await Security.encrypt(message, tag),
		  decrypted = await Security.decrypt(encrypted, tag);
	      isBase64URL(encrypted)
	      expect(decrypted).toBe(message);
	    });
	    it('cannot decrypt what is encrypted for a different key.', async function () {
	      let message = makeMessage(446),
		  encrypted = await Security.encrypt(message, otherTag),
		  errorMessage = await Security.decrypt(encrypted, tag).catch(e => e.message);
	      expect(errorMessage.toLowerCase()).toContain('operation');
	      // Some browsers supply a generic message, such as 'The operation failed for an operation-specific reason'
	      // IF there's no message at all, our jsonrpc supplies one with the jsonrpc 'method' name.
	      //expect(errorMessage).toContain('decrypt');
	    });
	  });
	});
      }
      test('DeviceVault', 'device', 'otherDevice');
      test('RecoveryVault', 'recovery', 'otherRecovery');
      test('User TeamVault', 'user', 'otherUser');
      test('Team TeamVault', 'team', 'otherTeam');
      it('can safely be used when a device is removed, but not after being entirely destroyed.', async function () {
	let [d1, d2] = await Promise.all([Security.create(), Security.create()]),
	    u = await Security.create(d1, d2),
	    t = await Security.create(u);

	let encrypted = await Security.encrypt(message, t);
	expect(await Security.decrypt(encrypted, t)).toBe(message);
	// Remove the first deep member
	await Security.changeMembership({tag: u, remove: [d1]});
	expect(await Security.decrypt(encrypted, t)).toBe(message);
	// Put it back.
	await Security.changeMembership({tag: u, add: [d1]});
	expect(await Security.decrypt(encrypted, t)).toBe(message);
	// Make the other unavailable
	await Security.destroy(d2);
	
	expect(await Security.decrypt(encrypted, t)).toBe(message);
	// Destroy it all the way down.
	await Security.destroy({tag: t, recursiveMembers: true});
	let errorMessage = await Security.decrypt(encrypted, t).then(_ => null, e => e.message);
	expect(errorMessage).toBeTruthy();
      }, slowKeyCreation);
      it('device is useable as soon as it resolves.', async function () {
	let device= await Security.create();
	expect(await Security.sign("anything", device)).toBeTruthy();
	await Security.destroy(device);
      });
      it('team is useable as soon as it resolves.', async function () {
	let team = await Security.create(tags.device); // There was a bug once: awaiting a function that did return its promise.
	expect(await Security.sign("anything", team)).toBeTruthy();
	await Security.destroy(team);
      });
      it('allows recovery prompts that contain dot.', async function () {
	let tag = await Security.create({prompt: "foo.bar"}),
	    user = await Security.create(tag),
	    message = "red.white",
	    encrypted = await Security.encrypt(message, user),
	    signed = await Security.sign(message, user);
	expect(await Security.decrypt(encrypted, user)).toBe(message);
	expect(await Security.verify(signed, user)).toBeTruthy();
	Security.destroy(user);
	Security.destroy(tag);
      });
      /*
	TODO:
	- Show that a member cannot sign or decrypt for a team that they have been removed from.
	- Show that multiple simultaneous apps can use the same tags if they use Security from the same origin and have compatible getUserDeviceSecret.
	- Show that multiple simultaneous apps cannot use the same tags if they use Security from the same origin and have incompatible getUserDeviceSecret.
       */
    });
  });
});
