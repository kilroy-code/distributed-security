import Storage from "./support/storage.mjs";
import Security from "../index.mjs";
//import Security from "https://kilroy-code.github.io/distributed-security/index.mjs";

import testKrypto from "./kryptoTests.mjs";
import testMultiKrypto from "./multiKryptoTests.mjs";
import testModule from "./support/testModuleWithFoo.mjs";
import {scale, makeMessage, isBase64URL} from "./support/messageText.mjs";

// Setup.
jasmine.getEnv().configure({random: false});
Storage.Security = Security;
Security.Storage = Storage;
let thisDeviceSecret = "secret",
    secret = thisDeviceSecret;
async function withSecret(thunk) {
  secret = "other";
  await thunk();
  secret = thisDeviceSecret;
}
function getSecret(tag, recoveryPrompt = '') {
  return recoveryPrompt + secret;
}
Security.getUserDeviceSecret = getSecret;

// For testing internals.
import * as JOSE from "../dependency/jose.mjs";
import Krypto from "../lib/krypto.mjs";
import MultiKrypto from "../lib/multiKrypto.mjs";
import InternalSecurity from "../lib/api.mjs";
import dispatch from "../dependency/jsonrpc.mjs";
InternalSecurity.Storage = Storage;
InternalSecurity.getUserDeviceSecret = getSecret;
import {Vault, DeviceVault, TeamVault} from "../lib/vault.mjs";
Object.assign(window, {Krypto, MultiKrypto, Security, Storage, InternalSecurity, JOSE}); // export to browser console for development/debugging experiments.


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
      let [device, recovery, otherRecovery] = await Promise.all([
	scope.create(),
	scope.create({prompt: "what?"}),
	scope.create({prompt: "nope!"})
      ])
      let otherDevice, otherUser;
      await withSecret(async function () {
	otherDevice = await scope.create();
	otherUser = await scope.create(otherDevice);
      });
      let user = await scope.create(device);
      // // Note: same members, but a different identity.
      let [team, otherTeam] = await Promise.all([scope.create(user, otherUser), scope.create(otherUser, user)]);
      tags.device = device;
      tags.otherDevice = otherDevice;
      tags.recovery = recovery; tags.otherRecovery = otherRecovery;
      tags.user = user; tags.otherUser = otherUser;
      tags.team = team; tags.otherTeam = otherTeam;
      return tags;
    }
    async function destroyVaults(scope, tags) {
      await scope.destroy(tags.otherTeam);
      await scope.destroy(tags.team);
      await scope.destroy(tags.user);
      await scope.destroy(tags.device);
      await scope.destroy(tags.recovery);
      await scope.destroy(tags.otherRecovery);
      await withSecret(async function () {
	await scope.destroy(tags.otherUser);
	await scope.destroy(tags.otherDevice);
      });
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
	  it('tag is exported verify key, and sign() pairs with it.', async function () {
	    let verifyKey = await MultiKrypto.importRaw(tag),
		exported = await MultiKrypto.exportRaw(verifyKey);
	    expect(typeof tag).toBe('string');
	    expect(exported).toBe(tag);

	    let vault = await Vault.ensure(tag);

	    let signature = await Vault.sign(message, {tags: [tag], signingKey: vault.signingKey}),
		verification = await MultiKrypto.verify(verifyKey, signature);
	    isBase64URL(signature);
	    expect(verification).toBeTruthy();
	  });
	  it('public encryption tag can be retrieved externally, and vault.decrypt() pairs with it.', async function () {
	    let tag = vault.tag,
		retrieved = await Storage.retrieve('EncryptionKey', tag),
		verified = await Security.verify(retrieved, tag),
		imported = await MultiKrypto.importJWK(verified.json),
		encrypted = await MultiKrypto.encrypt(imported, message),
		decrypted = await vault.decrypt(encrypted);
	    expect(decrypted.text).toBe(message);
	  });
	});
      }
      vaultTests('DeviceVault', 'device');
      vaultTests('RecoveryVault', 'recovery');
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
    describe("API", function () {
      let tags;
      beforeAll(async function () {
	console.log(await Security.ready);
	tags = await makeVaults(Security);
      }, slowKeyCreation);
      afterAll(async function () {
	await destroyVaults(Security, tags);
      }, slowKeyCreation);
      function test(label, tagsName, otherOwnedTagsName, unownedTagName) {
	describe(label, function () {
	  let tag, otherOwnedTag;
	  beforeAll(function () {
	    tag = tags[tagsName];
	    otherOwnedTag = tags[otherOwnedTagsName];
	  });
	  describe('signature', function () {
	    describe('of one tag', function () {
	      it('can sign and be verified.', async function () {
		let signature = await Security.sign(message, tag);
		isBase64URL(signature);
		expect(await Security.verify(signature, tag)).toBeTruthy();
	      });
	      it('cannot sign for a different key.', async function () {
		let signature = await Security.sign(message, otherOwnedTag);
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
	      it('uses contentType and time if supplied.', async function () {
		let contentType = 'text/html',
		    time = Date.now(),
		    message = "<something else>",
		    signature = await Security.sign(message, {tags: [tag], contentType, time}),
		    verified = await Security.verify(signature, tag);
		isBase64URL(signature);
		expect(verified.text).toEqual(message);
		expect(verified.protectedHeader.cty).toBe(contentType);
		expect(verified.protectedHeader.iat).toBe(time);
	      });
	    });
	    describe('of multiple tags', function () {
	      it('can sign and be verified.', async function () {
		let signature = await Security.sign(message, tag, otherOwnedTag);
		expect(await Security.verify(signature, otherOwnedTag, tag)).toBeTruthy(); // order does not matter
	      });
	      describe('bad verification', function () {
		let oneMore;
		beforeAll(async function () { oneMore = await Security.create(); });
		afterAll(async function () { await Security.destroy(oneMore); });
		describe('when mixing single and multi-tags', function () {
		  it('fails with extra signing tag.', async function () {
		    let signature = await Security.sign(message, otherOwnedTag);
		    expect(await Security.verify(signature, tag)).toBeUndefined();
		  });
		  it('fails with extra verifying.', async function () {
		    let signature = await Security.sign(message, tag);
		    expect(await Security.verify(signature, tag, otherOwnedTag)).toBeUndefined();
		  });
		});
		describe('when mixing multi-tag lengths', function () {
		  it('fails with mismatched signing tag.', async function () {
		    let signature = await Security.sign(message, otherOwnedTag, oneMore),
			verified = await Security.verify(signature, tag, oneMore)
		    expect(verified).toBeUndefined();
		  });
		  it('fails with extra verifying tag.', async function () {
		    let signature = await Security.sign(message, tag, oneMore);
		    expect(await Security.verify(signature, tag, otherOwnedTag, oneMore)).toBeUndefined();
		  });
		});
	      });
	      it('distinguishes between correctly signing false and key failure.', async function () {
		let signature = await Security.sign(false, tag, otherOwnedTag),
		    verified = await Security.verify(signature, tag, otherOwnedTag);
		expect(verified.json).toBe(false);
	      });
	      it('can sign text and produce verified result with text property.', async function () {
		let signature = await Security.sign(message, tag, otherOwnedTag),
		    verified = await Security.verify(signature, tag, otherOwnedTag);
		expect(verified.text).toBe(message);
	      });
	      it('can sign json and produce verified result with json property.', async function () {
		let message = {x: 1, y: ["abc", null, false]},
		    signature = await Security.sign(message, tag, otherOwnedTag),
		    verified = await Security.verify(signature, tag, otherOwnedTag);
		expect(verified.json).toEqual(message);
	      });
	      it('can sign binary and produce verified result with payload property.', async function () {
		let message = new Uint8Array([1, 2, 3]),
		    signature = await Security.sign(message, tag, otherOwnedTag),
		    verified = await Security.verify(signature, tag, otherOwnedTag);
		expect(verified.payload).toEqual(message);
	      });
	      it('uses contentType and time if supplied.', async function () {
		let contentType = 'text/html',
		    time = Date.now(),
		    message = "<something else>",
		    signature = await Security.sign(message, {tags: [tag, otherOwnedTag], contentType, time}),
		    verified = await Security.verify(signature, tag, otherOwnedTag);
		expect(verified.text).toEqual(message);
		expect(verified.protectedHeader.cty).toBe(contentType);
		expect(verified.protectedHeader.iat).toBe(time);
	      });
	    });
	  });
	  describe('encryption', function () {
	    describe('with a single tag', function () {
	      it('can decrypt what is encrypted for it.', async function () {
		let encrypted = await Security.encrypt(message, tag),
		    decrypted = await Security.decrypt(encrypted, tag);
		isBase64URL(encrypted);
		expect(decrypted.text).toBe(message);
	      });
	      it('is url-safe base64.', async function () {
		isBase64URL(await Security.encrypt(message, tag));
	      });
	      it('specifies kid.', async function () {
		let header = JOSE.decodeProtectedHeader(await Security.encrypt(message, tag));
		expect(header.kid).toBe(tag);
	      });
	      it('cannot decrypt what is encrypted for a different key.', async function () {
		let message = makeMessage(446),
		    encrypted = await Security.encrypt(message, otherOwnedTag),
		    errorMessage = await Security.decrypt(encrypted, tag).catch(e => e.message);
		expect(errorMessage.toLowerCase()).toContain('operation');
		// Some browsers supply a generic message, such as 'The operation failed for an operation-specific reason'
		// IF there's no message at all, our jsonrpc supplies one with the jsonrpc 'method' name.
		//expect(errorMessage).toContain('decrypt');
	      });
	      it('handles binary, and decrypts as same.', async function () {
		let message = new Uint8Array([21, 31]),
		    encrypted = await Security.encrypt(message, tag),
		    decrypted = await Security.decrypt(encrypted, tag),
		    header = JOSE.decodeProtectedHeader(encrypted);
		expect(header.cty).toBeUndefined();
		expect(decrypted.payload).toEqual(message);
	      });
	      it('handles text, and decrypts as same.', async function () {
		let encrypted = await Security.encrypt(message, tag),
		    decrypted = await Security.decrypt(encrypted, tag),
		    header = JOSE.decodeProtectedHeader(encrypted);
		expect(header.cty).toBe('text/plain');
		expect(decrypted.text).toBe(message);
	      });
	      it('handles json, and decrypts as same.', async function () {
		let message = {foo: 'bar'},
		    encrypted = await Security.encrypt(message, tag),
		    decrypted = await Security.decrypt(encrypted, tag),
		    header = JOSE.decodeProtectedHeader(encrypted);
		expect(header.cty).toBe('json');
		expect(decrypted.json).toEqual(message);
	      });
	      it('uses contentType and time if supplied.', async function () {
		let contentType = 'text/html',
		    time = Date.now(),
		    message = "<something else>",
		    encrypted = await Security.encrypt(message, {tags: [tag], contentType, time}),
		    decrypted = await Security.decrypt(encrypted, tag),
		    header = JOSE.decodeProtectedHeader(encrypted);
		expect(header.cty).toBe(contentType);
		expect(header.iat).toBe(time);
		expect(decrypted.text).toBe(message);
	      });
	    });
	    describe('with multiple tags', function () {
	      it('can be decrypted by any one of them.', async function () {
		let encrypted = await Security.encrypt(message, tag, otherOwnedTag),
		    decrypted1 = await Security.decrypt(encrypted, tag),
		    decrypted2 = await Security.decrypt(encrypted, otherOwnedTag);
		expect(decrypted1.text).toBe(message);
		expect(decrypted2.text).toBe(message);	      
	      });
	      it('can be be made with tags you do not own.', async function () {
		let encrypted = await Security.encrypt(message, tag, tags[unownedTagName], otherOwnedTag),
		    decrypted1 = await Security.decrypt(encrypted, tag),
		    decrypted2 = await Security.decrypt(encrypted, otherOwnedTag);
		expect(decrypted1.text).toBe(message);
		expect(decrypted2.text).toBe(message);	      
	      });
	      it('cannot be decrypted by a different tag.', async function () {
		let encrypted = await Security.encrypt(message, tag, tags[unownedTagName]),
		    decrypted = await Security.decrypt(encrypted, otherOwnedTag);
		expect(decrypted).toBeUndefined();
	      });
	      it('specifies kid in each recipient.', async function () {
		let encrypted = await Security.encrypt(message, tag, otherOwnedTag),
		    recipients = encrypted.recipients;
		expect(recipients.length).toBe(2);
		expect(recipients[0].header.kid).toBe(tag);
		expect(recipients[1].header.kid).toBe(otherOwnedTag);
	      });

	      it('handles binary, and decrypts as same.', async function () {
		let message = new Uint8Array([21, 31]),
		    encrypted = await Security.encrypt(message, tag, otherOwnedTag),
		    decrypted = await Security.decrypt(encrypted, tag),
		    header = JOSE.decodeProtectedHeader(encrypted);
		expect(header.cty).toBeUndefined();
		expect(decrypted.payload).toEqual(message);
	      });
	      it('handles text, and decrypts as same.', async function () {
		let encrypted = await Security.encrypt(message, tag, otherOwnedTag),
		    decrypted = await Security.decrypt(encrypted, tag),
		    header = JOSE.decodeProtectedHeader(encrypted);
		expect(header.cty).toBe('text/plain');
		expect(decrypted.text).toBe(message);
	      });
	      it('handles json, and decrypts as same.', async function () {
		let message = {foo: 'bar'},
		    encrypted = await Security.encrypt(message, tag, otherOwnedTag),
		    decrypted = await Security.decrypt(encrypted, tag),
		    header = JOSE.decodeProtectedHeader(encrypted);
		expect(header.cty).toBe('json');
		expect(decrypted.json).toEqual(message);
	      });
	      it('uses contentType and time if supplied.', async function () {
		let contentType = 'text/html',
		    time = Date.now(),
		    message = "<something else>",
		    encrypted = await Security.encrypt(message, {tags: [tag, otherOwnedTag], contentType, time}),
		    decrypted = await Security.decrypt(encrypted, tag),
		    header = JOSE.decodeProtectedHeader(encrypted)
		expect(header.cty).toBe(contentType);
		expect(header.iat).toBe(time);
		expect(decrypted.text).toBe(message);
	      });
	    });
	  });
	});
      }
      test('DeviceVault', 'device', 'user', 'otherDevice'); // We own user, but it isn't the same as device.
      test('RecoveryVault', 'recovery', 'otherRecovery', 'otherDevice');
      test('User TeamVault', 'user', 'device', 'otherUser'); // We ownd device, but it isn't the same as user.
      test('Team TeamVault', 'team', 'otherTeam', 'otherUser');
      describe('auditable signatures', function () {
	describe('by an explicit member', function () {
	  let signature, verification;
	  beforeAll(async function () {
	    signature = await Security.sign(message, {team: tags.team, member: tags.user});
	    verification = await Security.verify(signature, tags.team, tags.user);
	  });
	  it('recognizes a team with a member.', async function () {
	    expect(verification).toBeTruthy();
	    expect(verification.text).toBe(message);
	  });
	  it('defines iss.', function () {
	    expect(verification.protectedHeader.iss).toBe(tags.team);
	  });
	  it('defines act.', function () {
	    expect(verification.protectedHeader.act).toBe(tags.user);
	  });
	});
	describe('automatically supplies a valid member', function () {
	  it('if you have access', async function () {
	    let signature = await Security.sign(message, {team: tags.team}),
		member = JOSE.decodeProtectedHeader(signature.signatures[0]).act,
		verification = await Security.verify(signature, tags.team, member);
	    expect(verification).toBeTruthy();
	    expect(member).toBeTruthy();
	    expect(verification.protectedHeader.act).toBe(member);
	    expect(verification.protectedHeader.iat).toBeTruthy();
	  });
	});
	describe('with a valid user who is not a member', function () {
	  let nonMember;
	  beforeAll(async function () { nonMember = await Security.create(tags.device); });
	  afterAll(async function () { await Security.destroy(nonMember); });
	  it('verifies as an ordinary dual signature.', async function () {
	    let signature = await Security.sign(message, tags.team, nonMember),
		verification = await Security.verify(signature, tags.team, nonMember);
	    expect(verification.text).toBe(message);
	    expect(verification.protectedHeader.iss).toBeUndefined();
	    expect(verification.protectedHeader.act).toBeUndefined();
	  });
	  it('does not verify as a dual signature specifying team and member.', async function () {
	    let signature = await Security.sign(message, {team: tags.team, member: nonMember}),
		verification = await Security.verify(signature, tags.team, nonMember);
	    expect(verification).toBeUndefined();
	  });
	});
	describe('with a past member', function () {
	  let member, signature, time;
	  beforeAll(async function () {
	    time = Date.now() - 1;
	    member = await Security.create();
	    await Security.changeMembership({tag: tags.team, add: [member]});
	    signature = await Security.sign("message", {team: tags.team, member, time}); // while member
	    await Security.changeMembership({tag: tags.team, remove: [member]});
	  });
	  afterAll(async function () {
	    await Security.destroy(member);
	  });
	  it('fails by default.', async function () {
	    let verified = await Security.verify(signature, member);
	    expect(verified).toBeUndefined();
	  });
	  it('contains act in signature but verifies if we tell it not to check membership.', async function () {
	    let verified = await Security.verify(signature, {team: tags.team, member: false});
	    expect(verified).toBeTruthy();
	    expect(verified.text).toBe("message");
	    expect(verified.protectedHeader.act).toBe(member);
	    expect(verified.protectedHeader.iat).toBeTruthy();
	  });
	  it('fails if we tell it to check notBefore:"team", even if we tell it not to check membership.', async function () {
	    let verified = await Security.verify(signature, {team: tags.team, member: false, notBefore:'team'});
	    expect(verified).toBeUndefined();
	  });
	});
      });
      it('can safely be used when a device is removed, but not after being entirely destroyed.', async function () {
	let [d1, d2] = await Promise.all([Security.create(), Security.create()]),
	    u = await Security.create(d1, d2),
	    t = await Security.create(u);

	let encrypted = await Security.encrypt(message, t),
	    decrypted = await Security.decrypt(encrypted, t);
	expect(decrypted.text).toBe(message);
	// Remove the first deep member
	decrypted = await Security.decrypt(encrypted, t);
	await Security.changeMembership({tag: u, remove: [d1]});
	expect(decrypted.text).toBe(message);
	// Put it back.
	await Security.changeMembership({tag: u, add: [d1]});
	decrypted = await Security.decrypt(encrypted, t)
	expect(decrypted.text).toBe(message);
	// Make the other unavailable
	await Security.destroy(d2);
	decrypted = await Security.decrypt(encrypted, t);
	expect(decrypted.text).toBe(message);
	// Destroy it all the way down.
	await Security.destroy({tag: t, recursiveMembers: true});
	let errorMessage = await Security.decrypt(encrypted, t).then(_ => null, e => e.message);
	expect(errorMessage).toBeTruthy();
      }, slowKeyCreation);
      it('device is useable as soon as it resolves.', async function () {
	let device = await Security.create();
	expect(await Security.sign("anything", device)).toBeTruthy();
	await Security.destroy(device);
      });
      it('team is useable as soon as it resolves.', async function () {
	let team = await Security.create(tags.device); // There was a bug once: awaiting a function that did return its promise.
	expect(await Security.sign("anything", team)).toBeTruthy();
	await Security.destroy(team);
      });
      it('allows recovery prompts that contain dot.', async function () {
	let recovery = await Security.create({prompt: "foo.bar"}),
	    user = await Security.create(recovery),
	    message = "red.white",
	    encrypted = await Security.encrypt(message, user),
	    decrypted = await Security.decrypt(encrypted, user),
	    signed = await Security.sign(message, user);
	expect(decrypted.text).toBe(message);
	expect(await Security.verify(signed, user)).toBeTruthy();
	await Security.destroy({tag: user, recursiveMembers: true});
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
