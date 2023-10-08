/*
  TODO:

  prove that localStorage is not shared with workers
  use credential mechanism for device keys
  shared webworker

  Persistence - getWrappedKey/setWrappedKey
  The retrieved value should include the signature so that the recipient can verify. Probably the signature of the storage service, too.

  Module
  Clean up paths involving @kilroy-code
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
import {Vault, DeviceVault, TeamVault} from "../vault.mjs";
import Storage from "../storage.mjs";
import InternalSecurity from "../security.mjs";
import Security from "../vaultedSecurity.mjs";

import testKrypto from "./kryptoTests.mjs";
import testMultiKrypto from "./multiKryptoTests.mjs";
import testModule from "./support/testModuleWithFoo.mjs";
import dispatch from "../../jsonrpc/index.mjs";
import {scale, makeMessage} from "./support/messageText.mjs";

jasmine.getEnv().configure({random: false});

describe('Distributed Security', function () {
  describe('Krypto', function () {
    testKrypto(Krypto);
  });
  describe('MultiKrypto', function () {
    testMultiKrypto(MultiKrypto);
  });
  describe('Security', function () {
    const slowKeyCreation = 15e3; // e.g., Safari
    async function makeVaults(scope) { // Create a standard set of test vaults through context.
      let device = await scope.create(),
	  otherDevice = await scope.create(),
	  user = await scope.create([device]),
	  otherUser = await scope.create([otherDevice]),
	  team = await scope.create([otherUser, user]),
	  otherTeam = await scope.create([otherUser, user]);   // Note: same members, but a different identity.
      return {device, user, otherDevice, otherUser, team, otherTeam};
    }
    async function destroyVaults(scope, tags) {
      await Promise.all(Object.values(tags).map(tag => scope.destroy(tag)));
    }
    describe('internal machinery', function () {
      let tags;
      beforeAll(async function () {
	InternalSecurity.Storage = Storage;
	tags = await makeVaults(InternalSecurity);
      }, slowKeyCreation);
      afterAll(async function () {
	await destroyVaults(InternalSecurity, tags);
      });
      function vaultTests(label, tagsKey) {
	describe(label, function () {	
	  let vault, tag;
	  beforeAll(async function () {
	    tag = tags[tagsKey];
	    vault = await Vault.ensure(tag);
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
		retrieved = await Storage.retrieve('EncryptionKey', tag),
		imported = await MultiKrypto.importKey(retrieved, 'encrypt'),
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
	  request = dispatch(isolatedWorker);
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
	tags = await makeVaults(Security);
      }, slowKeyCreation);
      afterAll(async function () {
	await destroyVaults(Security, tags);
      });
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
      it('can safely be used when a device is removed, but not when all are removed.', async function () {
	let [d1, d2] = await Promise.all([Security.create(), Security.create()]),
	    u = await Security.create([d1, d2]),
	    t = await Security.create([u]),
	    message = makeMessage();
	let encrypted = await Security.encrypt(t, message);
	expect(await Security.decrypt(t, encrypted)).toBe(message);
	await Security.destroy(d1);
	expect(await Security.decrypt(t, encrypted)).toBe(message);
	await Security.destroy(d2);
	let errorMessage = await Security.decrypt(t, encrypted).catch(e => e.message);
	expect(errorMessage).toContain('access');
	expect(errorMessage).toContain(t);
      }, slowKeyCreation);
    });
  });
});
