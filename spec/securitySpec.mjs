import Storage from "./support/storage.mjs";
import Security from "@kilroy-code/distributed-security";
//import Security from "https://kilroy-code.github.io/distributed-security/index.mjs";

import testKrypto from "./kryptoTests.mjs";
import testMultiKrypto from "./multiKryptoTests.mjs";
import { makeMessage, isBase64URL, sameTypedArray} from "./support/messageText.mjs";

// Setup.
//jasmine.getEnv().configure({random: false});
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
import {Krypto, MultiKrypto, InternalSecurity, KeySet, LocalCollection} from '#internals';
InternalSecurity.Storage = Storage;
InternalSecurity.getUserDeviceSecret = getSecret;

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
      function vaultTests(label, tagsKey) {
        describe(label, function () { 
          let vault, tag;
          beforeAll(async function () {
            tag = tags[tagsKey];
            vault = await KeySet.ensure(tag);
          });
          it('tag is exported verify key, and sign() pairs with it.', async function () {
            let verifyKey = await MultiKrypto.importRaw(tag),
                exported = await MultiKrypto.exportRaw(verifyKey);
            expect(typeof tag).toBe('string');
            expect(exported).toBe(tag);

            let vault = await KeySet.ensure(tag);

            let signature = await KeySet.sign(message, {tags: [tag], signingKey: vault.signingKey}),
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
      vaultTests('DeviceKeySet', 'device');
      vaultTests('RecoveryKeySet', 'recovery');
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
          expect(per).toBeLessThan(5);
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
          expect(per).toBeLessThan(5);
          removes.forEach(removeResult => expect(removeResult).toBe(""));

          start = Date.now();
          let rereads = await Promise.all(tags.map(tag => store.retrieve(tag)));
          elapsed = Date.now() - start; per = elapsed/count;
          //console.log({elapsed, per});
          expect(per).toBeLessThan(0.1);
          rereads.forEach(readResult => expect(readResult).toBe(""));
        }, 10e5)
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
              it('can be verified with the tag included in the signature.', async function () {
                let signature = await Security.sign(message, tag);
                expect(await Security.verify(signature)).toBeTruthy();
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
              it('can be verified with the tag included in the signature.', async function () {
                let signature = await Security.sign(message, tag, otherOwnedTag);
                expect(await Security.verify(signature)).toBeTruthy();
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
              it('can be decrypted using the tag included in the encryption.', async function () {
                let encrypted = await Security.encrypt(message, tag),
                    decrypted = await Security.decrypt(encrypted);
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
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBeUndefined();
                sameTypedArray(decrypted, message);
              });
              it('handles text, and decrypts as same.', async function () {
                let encrypted = await Security.encrypt(message, tag),
                    decrypted = await Security.decrypt(encrypted, tag),
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBe('text/plain');
                expect(decrypted.text).toBe(message);
              });
              it('handles json, and decrypts as same.', async function () {
                let message = {foo: 'bar'},
                    encrypted = await Security.encrypt(message, tag),
                    decrypted = await Security.decrypt(encrypted, tag),
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBe('json');
                expect(decrypted.json).toEqual(message);
              });
              it('uses contentType and time if supplied.', async function () {
                let contentType = 'text/html',
                    time = Date.now(),
                    message = "<something else>",
                    encrypted = await Security.encrypt(message, {tags: [tag], contentType, time}),
                    decrypted = await Security.decrypt(encrypted, tag),
                    header = Krypto.decodeProtectedHeader(encrypted);
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
              it('can be decrypted using the tag included in the encryption.', async function () {
                let encrypted = await Security.encrypt(message, tag, otherOwnedTag),
                    decrypted = await Security.decrypt(encrypted);
                expect(decrypted.text).toBe(message);
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
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBeUndefined();
                sameTypedArray(decrypted, message);
              });
              it('handles text, and decrypts as same.', async function () {
                let encrypted = await Security.encrypt(message, tag, otherOwnedTag),
                    decrypted = await Security.decrypt(encrypted, tag),
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBe('text/plain');
                expect(decrypted.text).toBe(message);
              });
              it('handles json, and decrypts as same.', async function () {
                let message = {foo: 'bar'},
                    encrypted = await Security.encrypt(message, tag, otherOwnedTag),
                    decrypted = await Security.decrypt(encrypted, tag),
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBe('json');
                expect(decrypted.json).toEqual(message);
              });
              it('uses contentType and time if supplied.', async function () {
                let contentType = 'text/html',
                    time = Date.now(),
                    message = "<something else>",
                    encrypted = await Security.encrypt(message, {tags: [tag, otherOwnedTag], contentType, time}),
                    decrypted = await Security.decrypt(encrypted, tag),
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
      test('RecoveryKeySet', 'recovery', 'otherRecovery', 'otherDevice');
      test('User TeamKeySet', 'user', 'device', 'otherUser'); // We ownd device, but it isn't the same as user.
      test('Team TeamKeySet', 'team', 'otherTeam', 'otherUser');
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
        let errorMessage = await Security.decrypt(encrypted, t).then(() => null, e => e.message);
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
      }, 10e3);
      // TODO:
      // - Show that a member cannot sign or decrypt for a team that they have been removed from.
      // - Show that multiple simultaneous apps can use the same tags if they use Security from the same origin and have compatible getUserDeviceSecret.
      // - Show that multiple simultaneous apps cannot use the same tags if they use Security from the same origin and have incompatible getUserDeviceSecret.
    });
  });
});
