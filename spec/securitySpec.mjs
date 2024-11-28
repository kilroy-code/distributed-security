import Storage from "./support/storage.mjs";
import Security from "@ki1r0y/distributed-security";

import testKrypto from "./kryptoTests.mjs";
import testMultiKrypto from "./multiKryptoTests.mjs";
import { makeMessage, isBase64URL, sameTypedArray} from "./support/messageText.mjs";

// Setup.
//jasmine.getEnv().configure({random: false});
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

// For testing internals.

// If THIS file is bundled, it can resolve a direct reference to the internals:
import {Krypto, MultiKrypto, InternalSecurity, KeySet, LocalCollection} from './support/internals.mjs';
//import {Krypto, MultiKrypto, InternalSecurity, KeySet, LocalCollection} from '@ki1r0y/distributed-security/dist/internal-browser-bundle.mjs';
// If this file is referenced directly, as is, in a test.html, then we'll need to have a bundle prepared,
// that gets resolved through package.json:
//import {Krypto, MultiKrypto, InternalSecurity, KeySet, LocalCollection} from '#internals';

// For testing sub hash.
import {crypto} from '../lib/utilities.mjs';
async function getHash(message) { // string to base64url, without using our own security code (which exports hashText and base64url).
  // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
  // https://developer.mozilla.org/en-US/docs/Glossary/Base64
  const messageBuffer = new TextEncoder().encode(message),
        digest = await crypto.subtle.digest("SHA-256", messageBuffer),
        hash = new Uint8Array(digest),
        asStringData = Array.from(hash, byte => String.fromCodePoint(byte)).join(''),
        base64 = btoa(asStringData);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Define some globals in a browser for debugging.
if (typeof(window) !== 'undefined') Object.assign(window, {Security, Krypto, MultiKrypto, Storage});


describe('Distributed Security', function () {
  let message = makeMessage(),
      originalStorage = Security.Storage,
      originalSecret = Security.getUserDeviceSecret;
  beforeAll(function () {
    Storage.Security = Security;
    Security.Storage = Storage;
    Security.getUserDeviceSecret = getSecret;
    InternalSecurity.Storage = Storage;
    InternalSecurity.getUserDeviceSecret = getSecret;
  });
  afterAll(function () {
    Security.Storage = originalStorage;
    Security.getUserDeviceSecret = originalSecret;
  });
  describe('Krypto', function () {
    testKrypto(Krypto);
  });
  describe('MultiKrypto', function () {
    testMultiKrypto(MultiKrypto);
  });
  describe('Security', function () {
    const slowKeyCreation = 60e3; // e.g., Safari needs about 15 seconds. Android needs more
    async function makeKeySets(scope) { // Create a standard set of test vaults through context.
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
    async function destroyKeySets(scope, tags) {
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
        tags = await makeKeySets(InternalSecurity);
      }, slowKeyCreation);
      afterAll(async function () {
        await destroyKeySets(InternalSecurity, tags);
      }, slowKeyCreation);
      function vaultTests(label, tagsKey, options = {}) {
        describe(label, function () { 
          let vault, tag;
          beforeAll(async function () {
            tag = tags[tagsKey];
            vault = await KeySet.ensure(tag, {recovery:true});
          });
          it('tag is exported verify key, and sign() pairs with it.', async function () {
            let verifyKey = await MultiKrypto.importRaw(tag),
                exported = await MultiKrypto.exportRaw(verifyKey);
            expect(typeof tag).toBe('string');
            expect(exported).toBe(tag);

            let vault = await KeySet.ensure(tag, {recovery:true});

            let signature = await KeySet.sign(message, {tags: [tag], signingKey: vault.signingKey, ...options}),
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
                decrypted = await vault.decrypt(encrypted, options);
            expect(decrypted.text).toBe(message);
          });
        });
      }
      vaultTests('DeviceKeySet', 'device');
      vaultTests('RecoveryKeySet', 'recovery', {recovery: true}); // Recovery tags are not normally used to decrypt or sign, but they can be allowed for testing.
      vaultTests('TeamKeySet', 'user');
      describe('local store', function () {
        var store; 
        beforeAll(async function () {
          store = new LocalCollection({dbName: 'testStore', collectionName: 'Foo'});
          await new Promise(resolve => setTimeout(resolve, 2e3)); // fixme remove
        });
        it('can remove without existing.', async function () {
          let tag = 'nonExistant';
          expect(await store.remove(tag)).toBe("");
        });
        it('can retrieve without existing.', async function () {
          let tag = 'nonExistant';
          expect(await store.retrieve(tag)).toBe("");
        });
        it('retrieves and can remove what is stored.', async function () {
          let tag = 'x', message = "hello";
          expect(await store.store(tag, message)).not.toBeUndefined();
          expect(await store.retrieve(tag)).toBe(message);
          expect(await store.remove(tag)).toBe("");
          expect(await store.retrieve(tag)).toBe("");
        });
        it('can write a lot without getting jumbled.', async function () {
          let count = 1000, prefix = "y", tags = [];
          for (let i = 0; i < count; i++) tags.push(prefix + i);
          let start, elapsed, per;

          start = Date.now();
          let stores = await Promise.all(tags.map((tag, index) => store.store(tag, index.toString())));
          elapsed = Date.now() - start; per = elapsed/count;
          //console.log({elapsed, per});
          expect(per).toBeLessThan(60);
          stores.forEach(storeResult => expect(storeResult).not.toBeUndefined());

          start = Date.now();
          let reads = await Promise.all(tags.map(tag => store.retrieve(tag)));
          elapsed = Date.now() - start; per = elapsed/count;
          //console.log({elapsed, per});
          expect(per).toBeLessThan(3);
          reads.forEach((readResult, index) => expect(readResult).toBe(index.toString()));

          start = Date.now();
          let removes = await Promise.all(tags.map(tag => store.remove(tag)));
          elapsed = Date.now() - start; per = elapsed/count;
          //console.log({elapsed, per});
          expect(per).toBeLessThan(8);
          removes.forEach(removeResult => expect(removeResult).toBe(""));

          start = Date.now();
          let rereads = await Promise.all(tags.map(tag => store.retrieve(tag)));
          elapsed = Date.now() - start; per = elapsed/count;
          //console.log({elapsed, per});
          expect(per).toBeLessThan(0.1);
          rereads.forEach(readResult => expect(readResult).toBe(""));
        }, 15e5)
      })
    });

    describe("API", function () {
      let tags;
      beforeAll(async function () {
        console.log(await Security.ready);
        tags = await makeKeySets(Security);
      }, slowKeyCreation);
      afterAll(async function () {
        await destroyKeySets(Security, tags);
      }, slowKeyCreation);
      function test(label, tagsName, otherOwnedTagsName, unownedTagName, options = {}) {
        describe(label, function () {
          let tag, otherOwnedTag;
          beforeAll(function () {
            tag = tags[tagsName];
            otherOwnedTag = tags[otherOwnedTagsName];
          });
          describe('signature', function () {
            describe('of one tag', function () {
              it('can sign and be verified.', async function () {
                let signature = await Security.sign(message, {tags:[tag], ...options});
                isBase64URL(signature);
                expect(await Security.verify(signature, tag)).toBeTruthy();
              });
              it('can be verified with the tag included in the signature.', async function () {
                let signature = await Security.sign(message, {tags: [tag], ...options});
                expect(await Security.verify(signature)).toBeTruthy();
              });
              it('cannot sign for a different key.', async function () {
                let signature = await Security.sign(message, {tags: [otherOwnedTag], ...options});
                expect(await Security.verify(signature, tag)).toBeUndefined();
              });
              it('cannot sign with an unowned key.', async function () {
                expect(await Security.sign("something", {tags: tags[unownedTagName], ...options}).catch(() => undefined)).toBeUndefined();
              });
              it('distinguishes between correctly signing false and key failure.', async function () {
                let signature = await Security.sign(false, {tags:[tag], ...options}),
                    verified = await Security.verify(signature, tag);
                expect(verified.json).toBe(false);
              });
              it('can sign text and produce verified result with text property.', async function () {
                let signature = await Security.sign(message, {tags:[tag], ...options}),
                    verified = await Security.verify(signature, tag);
                isBase64URL(signature);
                expect(verified.text).toBe(message);
              });
              it('can sign json and produce verified result with json property.', async function () {
                let message = {x: 1, y: ["abc", null, false]},
                    signature = await Security.sign(message, {tags: [tag], ...options}),
                    verified = await Security.verify(signature, tag);
                isBase64URL(signature);
                expect(verified.json).toEqual(message);
              });
              it('can sign binary and produce verified result with payload property.', async function () {
                let message = new Uint8Array([1, 2, 3]),
                    signature = await Security.sign(message, {tags: [tag], ...options}),
                    verified = await Security.verify(signature, tag);
                isBase64URL(signature);
                expect(verified.payload).toEqual(message);
              });
              it('uses contentType and time if supplied.', async function () {
                let contentType = 'text/html',
                    time = Date.now(),
                    message = "<something else>",
                    signature = await Security.sign(message, {tags: [tag], contentType, time, ...options}),
                    verified = await Security.verify(signature, tag);
                isBase64URL(signature);
                expect(verified.text).toEqual(message);
                expect(verified.protectedHeader.cty).toBe(contentType);
                expect(verified.protectedHeader.iat).toBe(time);
              });
              describe('includes payload hash as "sub" header', function () {
                it('by default.', async function () {
                  let message = "foo",
                      signature = await Security.sign(message, {tags: [tag], ...options}),
                      verified = await Security.verify(signature);
                  expect(verified.protectedHeader.sub).toBe(await getHash(message));
                });
                it('unless specified otherwise.', async function () {
                  let signature1 = await Security.sign('foo', {subject: "bar", tags: [tag], ...options}),
                      verified1 = await Security.verify(signature1),
                      signature2 = await Security.sign('foo', {subject: false, tags: [tag], ...options}),
                      verified2 = await Security.verify(signature2);
                  expect(verified1.protectedHeader.sub).toBe("bar");
                  expect(verified2.protectedHeader.sub).toBeUndefined();
                });
              });
            });
            describe('of multiple tags', function () {
              it('can sign and be verified.', async function () {
                let signature = await Security.sign(message, {tags: [tag, otherOwnedTag], ...options}),
                    verification = await Security.verify(signature, otherOwnedTag, tag);
                expect(verification).toBeTruthy(); // order does not matter
                expect(verification.signers[0].payload).toBeTruthy(); // All recipients listed in verify
                expect(verification.signers[1].payload).toBeTruthy();
              });
              it('does not attempt to verify unenumerated tags if any are explicit', async function () {
                let signature = await Security.sign(message, {tags: [tag, otherOwnedTag], ...options}),
                    verification = await Security.verify(signature, otherOwnedTag);
                expect(verification).toBeTruthy(); // order does not matter
                expect(verification.signers[0].payload).toBeFalsy(); // Because we explicitly verified with 1, not 0.
                expect(verification.signers[1].payload).toBeTruthy();
              });
              it('can be verified with the tag included in the signature.', async function () {
                let signature = await Security.sign(message, {tags: [tag, otherOwnedTag], ...options}),
                    verification = await Security.verify(signature);
                expect(verification).toBeTruthy();
                expect(verification.signers[0].payload).toBeTruthy(); // All are checked, and in this case, pass.
                expect(verification.signers[1].payload).toBeTruthy();
              });
              describe('bad verification', function () {
                let oneMore;
                beforeAll(async function () { oneMore = await Security.create(); });
                afterAll(async function () { await Security.destroy(oneMore); });
                describe('when mixing single and multi-tags', function () {
                  it('fails with extra signing tag.', async function () {
                    let signature = await Security.sign(message, {tags: [otherOwnedTag], ...options});
                    expect(await Security.verify(signature, tag)).toBeUndefined();
                  });
                  it('fails with extra verifying.', async function () {
                    let signature = await Security.sign(message, {tags: [tag], ...options});
                    expect(await Security.verify(signature, tag, otherOwnedTag)).toBeUndefined();
                  });
                });
                describe('when mixing multi-tag lengths', function () {
                  it('fails with mismatched signing tag.', async function () {
                    let signature = await Security.sign(message, {tags: [otherOwnedTag, oneMore], ...options}),
                        verified = await Security.verify(signature, tag, oneMore)
                    expect(verified).toBeUndefined();
                  });
                  it('fails with extra verifying tag.', async function () {
                    let signature = await Security.sign(message, {tags: [tag, oneMore], ...options});
                    expect(await Security.verify(signature, tag, otherOwnedTag, oneMore)).toBeUndefined();
                  });
                });
              });
              it('distinguishes between correctly signing false and key failure.', async function () {
                let signature = await Security.sign(false, {tags: [tag, otherOwnedTag], ...options}),
                    verified = await Security.verify(signature, tag, otherOwnedTag);
                expect(verified.json).toBe(false);
              });
              it('can sign text and produce verified result with text property.', async function () {
                let signature = await Security.sign(message, {tags: [tag, otherOwnedTag], ...options}),
                    verified = await Security.verify(signature, tag, otherOwnedTag);
                expect(verified.text).toBe(message);
              });
              it('can sign json and produce verified result with json property.', async function () {
                let message = {x: 1, y: ["abc", null, false]},
                    signature = await Security.sign(message, {tags: [tag, otherOwnedTag], ...options}),
                    verified = await Security.verify(signature, tag, otherOwnedTag);
                expect(verified.json).toEqual(message);
              });
              it('can sign binary and produce verified result with payload property.', async function () {
                let message = new Uint8Array([1, 2, 3]),
                    signature = await Security.sign(message, {tags: [tag, otherOwnedTag], ...options}),
                    verified = await Security.verify(signature, tag, otherOwnedTag);
                expect(verified.payload).toEqual(message);
              });
              it('uses contentType and time if supplied.', async function () {
                let contentType = 'text/html',
                    time = Date.now(),
                    message = "<something else>",
                    signature = await Security.sign(message, {tags: [tag, otherOwnedTag], contentType, time, ...options}),
                    verified = await Security.verify(signature, tag, otherOwnedTag);
                expect(verified.text).toEqual(message);
                expect(verified.protectedHeader.cty).toBe(contentType);
                expect(verified.protectedHeader.iat).toBe(time);
              });
              describe('includes payload hash as "sub" header', function () {
                it('by default.', async function () {
                  let message = "foo",
                      signature = await Security.sign(message, {tags: [tag, otherOwnedTag], ...options}),
                      verified = await Security.verify(signature);
                  expect(verified.protectedHeader.sub).toBe(await getHash(message));
                });
                it('unless specified otherwise.', async function () {
                  let signature1 = await Security.sign('foo', {tags: [tag, otherOwnedTag], subject: "bar", ...options}),
                      verified1 = await Security.verify(signature1),
                      signature2 = await Security.sign('foo', {tags: [tag, otherOwnedTag], subject: false, ...options}),
                      verified2 = await Security.verify(signature2);
                  expect(verified1.protectedHeader.sub).toBe("bar");
                  expect(verified2.protectedHeader.sub).toBeUndefined();
                });
              });
            });
          });
          describe('encryption', function () {
            describe('with a single tag', function () {
              it('can decrypt what is encrypted for it.', async function () {
                let encrypted = await Security.encrypt(message, tag),
                    decrypted = await Security.decrypt(encrypted, {tags: [tag], ...options});
                isBase64URL(encrypted);
                expect(decrypted.text).toBe(message);
              });
              it('can be decrypted using the tag included in the encryption.', async function () {
                let encrypted = await Security.encrypt(message, tag),
                    decrypted = await Security.decrypt(encrypted, options);
                expect(decrypted.text).toBe(message);
              });
              it('is url-safe base64.', async function () {
                isBase64URL(await Security.encrypt(message, tag));
              });
              it('specifies kid.', async function () {
                let header = Krypto.decodeProtectedHeader(await Security.encrypt(message, tag));
                expect(header.kid).toBe(tag);
              });
              it('cannot decrypt what is encrypted for a different key.', async function () {
                let message = makeMessage(446),
                    encrypted = await Security.encrypt(message, otherOwnedTag),
                    errorMessage = await Security.decrypt(encrypted, {tags: [tag], ...options}).catch(e => e.message);
                expect(errorMessage.toLowerCase()).toContain('operation');
                // Some browsers supply a generic message, such as 'The operation failed for an operation-specific reason'
                // IF there's no message at all, our jsonrpc supplies one with the jsonrpc 'method' name.
                //expect(errorMessage).toContain('decrypt');
              });
              it('handles binary, and decrypts as same.', async function () {
                let message = new Uint8Array([21, 31]),
                    encrypted = await Security.encrypt(message, tag),
                    decrypted = await Security.decrypt(encrypted, {tags: [tag], ...options}),
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBeUndefined();
                sameTypedArray(decrypted, message);
              });
              it('handles text, and decrypts as same.', async function () {
                let encrypted = await Security.encrypt(message, tag),
                    decrypted = await Security.decrypt(encrypted, {tags: [tag], ...options}),
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBe('text/plain');
                expect(decrypted.text).toBe(message);
              });
              it('handles json, and decrypts as same.', async function () {
                let message = {foo: 'bar'},
                    encrypted = await Security.encrypt(message, tag),
                    decrypted = await Security.decrypt(encrypted, {tags: [tag], ...options}),
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBe('json');
                expect(decrypted.json).toEqual(message);
              });
              it('uses contentType and time if supplied.', async function () {
                let contentType = 'text/html',
                    time = Date.now(),
                    message = "<something else>",
                    encrypted = await Security.encrypt(message, {tags: [tag], contentType, time}),
                    decrypted = await Security.decrypt(encrypted, {tags: [tag], ...options}),
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBe(contentType);
                expect(header.iat).toBe(time);
                expect(decrypted.text).toBe(message);
              });
            });
            describe('with multiple tags', function () {
              it('can be decrypted by any one of them.', async function () {
                let encrypted = await Security.encrypt(message, tag, otherOwnedTag),
                    decrypted1 = await Security.decrypt(encrypted, {tags: [tag], ...options}),
                    decrypted2 = await Security.decrypt(encrypted, {tags: [otherOwnedTag], ...options});
                expect(decrypted1.text).toBe(message);
                expect(decrypted2.text).toBe(message);        
              });
              it('can be decrypted using the tag included in the encryption.', async function () {
                let encrypted = await Security.encrypt(message, tag, otherOwnedTag),
                    decrypted = await Security.decrypt(encrypted, options);
                expect(decrypted.text).toBe(message);
              });
              it('can be be made with tags you do not own.', async function () {
                let encrypted = await Security.encrypt(message, tag, tags[unownedTagName], otherOwnedTag),
                    decrypted1 = await Security.decrypt(encrypted, {tags: [tag], ...options}),
                    decrypted2 = await Security.decrypt(encrypted, {tags: [otherOwnedTag], ...options});
                expect(decrypted1.text).toBe(message);
                expect(decrypted2.text).toBe(message);        
              });
              it('cannot be decrypted by a different tag.', async function () {
                let encrypted = await Security.encrypt(message, tag, tags[unownedTagName]),
                    decrypted = await Security.decrypt(encrypted, {tags: [otherOwnedTag], ...options});
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
                    decrypted = await Security.decrypt(encrypted, {tags: [tag], ...options}),
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBeUndefined();
                sameTypedArray(decrypted, message);
              });
              it('handles text, and decrypts as same.', async function () {
                let encrypted = await Security.encrypt(message, tag, otherOwnedTag),
                    decrypted = await Security.decrypt(encrypted, {tags: [tag], ...options}),
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBe('text/plain');
                expect(decrypted.text).toBe(message);
              });
              it('handles json, and decrypts as same.', async function () {
                let message = {foo: 'bar'},
                    encrypted = await Security.encrypt(message, tag, otherOwnedTag),
                    decrypted = await Security.decrypt(encrypted, {tags: [tag], ...options}),
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBe('json');
                expect(decrypted.json).toEqual(message);
              });
              it('uses contentType and time if supplied.', async function () {
                let contentType = 'text/html',
                    time = Date.now(),
                    message = "<something else>",
                    encrypted = await Security.encrypt(message, {tags: [tag, otherOwnedTag], contentType, time}),
                    decrypted = await Security.decrypt(encrypted, {tags: [tag], ...options}),
                    header = Krypto.decodeProtectedHeader(encrypted)
                expect(header.cty).toBe(contentType);
                expect(header.iat).toBe(time);
                expect(decrypted.text).toBe(message);
              });
            });
          });
        });
      }
      test('DeviceKeySet', 'device', 'user', 'otherDevice'); // We own user, but it isn't the same as device.
      test('RecoveryKeySet', 'recovery', 'otherRecovery', 'otherDevice', {recovery:true}); // sign/decrypt is not normally done with recovery keys, but we can force it.
      test('User TeamKeySet', 'user', 'device', 'otherUser'); // We ownd device, but it isn't the same as user.
      test('Team TeamKeySet', 'team', 'otherTeam', 'otherUser');
      describe('storage', function () {
        it('will only let a current member write new keys.', async function () {
          let testMember = await Security.create(),
              team = tags.team,
              currentEncryptedSignature = await Storage.retrieve('Team', team),
              verified = await Security.verify(currentEncryptedSignature),
              currentEncryptedKey = verified?.json;
	  console.log({team, signatures: currentEncryptedSignature.signatures, currentEncryptedSignature, verified});
          if (!verified) throw new Error(`Unable to verify '${currentEncryptedSignature?.text}'`);
          function signIt() {
            return Security.sign(currentEncryptedKey, {team, member: testMember, time: Date.now()})
          }
          await Security.changeMembership({tag: team, add: [testMember]});
          let signatureWhileMember = await signIt();
          expect(await Storage.store('Team', tags.team, signatureWhileMember)).toBeDefined(); // That's fine
          await Security.changeMembership({tag: team, remove: [testMember]});
          let signatureWhileNotAMember = await signIt();
          expect(await Storage.store('Team', team, signatureWhileNotAMember).catch(() => 'failed')).toBe('failed'); // Valid signature by an improper tag.
          expect(await Storage.store('Team', team, signatureWhileMember).catch(() => 'failed')).toBe('failed'); // Can't replay sig while member.
          expect(await Storage.store('Team', team, currentEncryptedSignature).catch(() => 'failed')).toBe('failed'); // Can't replay exact previous sig either.
          await Security.destroy(testMember);
        });
        it('will only let a current member write new public encryption key.', async function () {
          let testMember = await Security.create(),
              team = tags.team,
              currentSignature = await Storage.retrieve('EncryptionKey', team),
              currentKey = (await Security.verify(currentSignature)).json;
          function signIt() {
            return Security.sign(currentKey, {team, member: testMember, time: Date.now()})
          }
          await Security.changeMembership({tag: team, add: [testMember]});
          let signatureWhileMember = await signIt();
          expect(await Storage.store('EncryptionKey', tags.team, signatureWhileMember)).toBeDefined(); // That's fine
          await Security.changeMembership({tag: team, remove: [testMember]});
          let signatureWhileNotAMember = await signIt();
          expect(await Storage.store('EncryptionKey', team, signatureWhileNotAMember).catch(() => 'failed')).toBe('failed'); // Valid signature by an improper tag.
          expect(await Storage.store('EncryptionKey', team, signatureWhileMember).catch(() => 'failed')).toBe('failed'); // Can't replay sig while member.
          expect(await Storage.store('EncryptionKey', team, currentSignature).catch(() => 'failed')).toBe('failed'); // Can't replay exact previous sig either.
          await Security.destroy(testMember);
        }, 10e3);
        it('will only let owner of a device write new public device encryption key.', async function () {
          let testDevice = await Security.create(),
              anotherDevice = await Security.create(),
              currentSignature = await Storage.retrieve('EncryptionKey', testDevice),
              currentKey = (await Security.verify(currentSignature)).json;
          function signIt(tag) {
            return Security.sign(currentKey, {tags: [tag], time: Date.now()})
          }
          let signatureOfOwner = await signIt(testDevice);
          expect(await Storage.store('EncryptionKey', testDevice, signatureOfOwner)).toBeDefined(); // That's fine
          let signatureOfAnother = await signIt(anotherDevice);
          expect(await Storage.store('EncryptionKey', testDevice, signatureOfAnother).catch(() => 'failed')).toBe('failed'); // Valid signature by an improper tag.
          // Device owner can restore.  This is subtle:
          // There is no team key in the cloud to compare the time with. We do compare against the current value (as shown below),
          // but we do not prohibit the same timestamp from being reused.
          expect(await Storage.store('EncryptionKey', testDevice, signatureOfOwner)).toBeDefined;
          expect(await Storage.store('EncryptionKey', testDevice, currentSignature).catch(() => 'failed')).toBe('failed'); // Can't replay exact previous sig.
          await Security.destroy(testDevice);
          await Security.destroy(anotherDevice);
        }, 10e3);
      });
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
                member = Krypto.decodeProtectedHeader(signature.signatures[0]).act,
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
          }, 10e3);
          it('does not verify as a dual signature specifying team and member.', async function () {
            let signature = await Security.sign(message, {team: tags.team, member: nonMember}),
                verification = await Security.verify(signature, tags.team, nonMember);
            expect(verification).toBeUndefined();
          });
        }, 10e3);
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
      describe('miscellaneous', function () {
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
          let errorMessage = await Security.decrypt(encrypted, t).then(() => null, e => e.message);
          expect(errorMessage).toBeTruthy();
        }, slowKeyCreation);
        it('device is useable as soon as it resolves.', async function () {
          let device = await Security.create();
          expect(await Security.sign("anything", device)).toBeTruthy();
          await Security.destroy(device);
        }, 10e3);
        it('team is useable as soon as it resolves.', async function () {
          let team = await Security.create(tags.device); // There was a bug once: awaiting a function that did return its promise.
          expect(await Security.sign("anything", team)).toBeTruthy();
          await Security.destroy(team);
        });
        it('allows recovery prompts that contain dot (and confirm that a team can have a single recovery tag as member).', async function () {
          let recovery = await Security.create({prompt: "foo.bar"});
          let user = await Security.create(recovery);
          let message = "red.white";
          let encrypted = await Security.encrypt(message, user);
          let decrypted = await Security.decrypt(encrypted, user);
          let signed = await Security.sign(message, user);
          let verified = await Security.verify(signed, user);
          expect(decrypted.text).toBe(message);
          expect(verified).toBeTruthy();
          await Security.destroy({tag: user, recursiveMembers: true});
        }, 10e3);
        it('supports rotation.', async function () {
          let aliceTag = await Security.create(tags.device),
              cfoTag = await Security.create(aliceTag),
              alicePO = await Security.sign("some purchase order", {team: cfoTag, member: aliceTag}), // On Alice's computer
              cfoEyesOnly = await Security.encrypt("the other set of books", cfoTag)
          expect(await Security.verify(alicePO)).toBeTruthy();
          expect(await Security.verify(alicePO, {team: cfoTag, member: false})).toBeTruthy();
          expect(await Security.decrypt(cfoEyesOnly)).toBeTruthy(); // On Alice's computer

          // Now Alice is replace with Bob, and Carol added for the transition
          let bobTag = await Security.create(tags.device);
          let carolTag = await Security.create(tags.device);
          await Security.changeMembership({tag: cfoTag, remove: [aliceTag], add: [bobTag, carolTag]});
          await Security.destroy(aliceTag)

          expect(await Security.sign("bogus PO", {team: cfoTag, member: aliceTag}).catch(() => undefined)).toBeUndefined(); // Alice can no longer sign.
          let bobPO = await Security.sign("new PO", {team: cfoTag, member: bobTag}); // On Bob's computer
          let carolPO = await Security.sign("new PO", {team: cfoTag, member: carolTag});
          expect(await Security.verify(bobPO)).toBeTruthy();
          expect(await Security.verify(carolPO)).toBeTruthy();
          expect(await Security.verify(alicePO).catch(() => undefined)).toBeUndefined(); // Alice is no longer a member of cfoTag.
          expect(await Security.verify(alicePO, {team: cfoTag, member: false})).toBeTruthy(); // Destorying Alice's tag doesn't prevent shallow verify
          expect(await Security.decrypt(cfoEyesOnly)).toBeTruthy(); // On Bob's or Carol's computer

          // Now suppose we want to rotate the cfoTag:
          let cfoTag2 = await Security.create(bobTag); // Not Carol.
          await Security.destroy(cfoTag);

          expect(await Security.sign("bogus PO", {team: cfoTag, member: bobTag}).catch(() => undefined)).toBeUndefined(); // Fails for discontinued team.
          expect(await Security.sign("new new PO", {team: cfoTag2, member: bobTag})).toBeTruthy();
          expect(await Security.verify(alicePO, {team: cfoTag, member: false})).toBeTruthy();
          // However, some things to be aware of.
          expect(await Security.verify(bobPO)).toBeTruthy(); // works, but only because this looks like the initial check
          expect(await Security.verify(carolPO)).toBeTruthy(); // same, and confusing because Carol is not on the new team.
          expect(await Security.decrypt(cfoEyesOnly).catch(() => undefined)).toBeUndefined(); // FAILS! Bob can't sort through the mess that Alice made.
        }, 15e3);
        // TODO:
        // - Show that a member cannot sign or decrypt for a team that they have been removed from.
        // - Show that multiple simultaneous apps can use the same tags if they use Security from the same origin and have compatible getUserDeviceSecret.
        // - Show that multiple simultaneous apps cannot use the same tags if they use Security from the same origin and have incompatible getUserDeviceSecret.
      });
    });
  });
});
