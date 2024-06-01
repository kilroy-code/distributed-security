# Advanced Use

This document describes *application use* of multiple tags for multiplarty encryption and signatures, and how to set up *multiple applications that share tag*s.

For technical information on how the library is implemented, see a guide to the [implementation](docs/implementation.md), and a description of Distributed-security [In JOSE terms](docs/in-jose-terms.md).

## Encryption with Multiple Tags and Other Encryption Options

When something is encrypted with `encrypt(message, tag)`, the only thing that will decrypt it is the private key associated with `tag`. The encryption is made with the public part of a single keypair. The encryption is a string in a standard format called "JOSE [JWE compact serialization](https://datatracker.ietf.org/doc/html/rfc7516#section-7.1)". The tag appears as the JWE *key identifier* ("kid") header, and the *content type* ("cty") header may be defined as described below. The result of a succcessful `decrypt()` is an object that includes a "payload" property containing binary data. If `text` or `json` can be produced based on content type, these are defined as additional properties. If the encryption does not decrypt, the result is falsey (undefined). 

We can also encrypt a message with multiple tags, so that any *one* of the listed tags can decrypt it. The encryption is in a standard format called "JOSE [JWE general serialization](https://datatracker.ietf.org/doc/html/rfc7516#section-7.2.1)" and includes encryptions made with each of the specified keypairs: `encrypt(message, tag1, tag2, tag3)` can be decrypted with just `decrypt(JWE)` if any *one* of tag1, tag2, or tag3 is available in your browser or device. (You can also explicitly specify which tag you want to use to decrypt.)

You can also specify options for the encryption: `encrypt(message, {tags, contentType, time})`, and for decryption: `decrypt(ciphertext, {tag, contentType}`. The `contentType` and `time` appear as "headers" within the JWE (as "cty" and "iat", respectively), which may be useful when interacting with other JOSE systems.

- A contentType that contains the substring "text" will treat the message as a string during encryption, and will produce that same string during decryption.
- A contentType that contains the substring "json" will automatically call `JSON.stringify(message)` and treat that result as a string when encrypting, and call `JSON.parse` on that same string when decrypting.
- The contentType defaults to "text/plain" during encryption if message is of type "string", and to "application/json" if message is of type "object" but not binary (an ArrayBuffer view). (We follow the JOSE standard of identifying "application/json" as just "json" in the "cty" header.) For decryption, the "contentType" defaults to whatever is specified in the JWE as the "cty" header.

> Distributed-Security uses this itself: the way that your tag's keys are available on all your devices is that Distributed-Security encrypts your keys for each member browser that you work on, and stores the encrypted keys in the cloud. Any of your browsers can then decrypt the keys, but not ayone one else who isn't a member of that team. When a Web page that uses Distributed-Security tries to sign or decrypt for your team tag, it pulls your encrypted keys' JWE, and decrypts the keys with the member key that you happen to already have in that browser (and only in that browser). The same happens recursively for more complex teams that you are a member of. 

> (There is a subtle difference between data encrypted by a team tag and a team tag's own private keys. Data encrypted by a team tag is encrypted only by the one or more tags that are explicitly given in the call to encrypt. It is NOT encrypted by the members of those tags. The team's own keys are not encrypted by the team tag -- that would be circular -- but are *instead* encrypted by the list of member tags.)

## Signatures with Multiple Tags and Other Signature Options

When something is signed with `sign(message, tag)`, the only things that will verify it is the public key assocaited with `tag`. The signature is made with the private part of a single keypair. The signature is in a standard format called "JOSE [JWS compact serialization](https://datatracker.ietf.org/doc/html/rfc7515#section-7.1)". The tag appears as the JWS *key identifier* ("kid") header. The JWS may include "cty" and "iat" headers, as defined below. The result of a succcessful `verify()` is an object that includes a "payload" property containing binary data. If `text` or `json` can be produced based on content type, these are defined as additional properties. If the signature does not verify, the result is falsey (undefined). 

We can also sign a message with multiple tags, so that any *one* of the listed tags can verify it. The signature is in a standard formated called "JOSE [JWS General serialization](https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.1)" and includes signatures made with each of the specified keypairs: `sign(message, tag1, tag2, tag3)` can be verified with just `verify(JWS, tag2)` (or tag1, or tag3, or any combination).  If any of the specified tags verify, the result additionally contains a "signers" property that has an element for each signature in the JWS. Each signer element is an object that defines "payload" if and only if the corresponding original signature was verfied, and "protectedHeader" that contains the headers attested by the signer, including the individual "kid". If no tags are specified to `verify`, the default set of tags to check is all the tags included in signature itself. All this can be used in an application-specific way to see if the JWS is what was expected.

You can also specify options: `sign(message, {tags, contentType, time, team, member})`, and `verify(ciphertext, {tags, contentType, notBefore, team, member})`. 

- The contentType and time are as for Other Encryption Options, above. 
- If a signature is made with a "team" option that has a tag as value, the JWS contains an issuer header ("iss"), and the specified tag will appear as the first of tags if not already among them. The "tags" option can be omitted.
- If a signature is made with a "member" option that has a tag as value, the JWS contains an actor header ("act"), and the specified tag will be added to the tags if not already among them. The "tags" option can be omitted. If "team" is specified as an option, "member" defaults to a member of that team that belongs to the current user in the current browser.
- If a verification is made with a "member" option that has a value of the string "team", verification will fail if the JWS does not contain "iss" and "act" headers, and if there exists a current version of the issuing team in the cloud that does not list the specfied "act" as a member. (Verification *passes* if "iss" and "act" are specified, but the "iss" team does not yet exist.) "member" defaults to "team" if the JWS contains an "act" header.
- If a verification is made with a truthy "notBefore", verification will fail if the JWS does not contain "iat", or if "iat" is earlier than the specfied "notBefore". If "notBefore" has the value "team", the "iat" cannot be earlier than the "iat" of the issuing team, if the team exists.

> This is used by Distributed-Security itself in protecting the cloud storage that holds encrypted keys. The (encrypted) keys are signed as `sign(key, {team: tag, time})` so that "iss", "act", and "iat" headers are included in the signature. The cloud `store()` operation verifies this by `verify(JWS, {team: tag, notBefore: "team"})`. See [Storing Keys using the Cloud Storage API](../README.md#storing-keys-using-the-coud-storage-api).

## Sharing Tags Across Applications

A typical application loads its application code and the distributed-security library from two different [origins](https://developer.mozilla.org/en-US/docs/Glossary/Origin), both distinct from those used by other applications. For example, the application code might come from `https:/app.example.com`, and the distributed-security library from `https:/security.example.com`. When organized this way, the keys are in a distinct [browsing context](https://developer.mozilla.org/en-US/docs/Glossary/Browsing_context) (at security.example.com) that is isolated both from the application code (running in app.example.com) and from other applications (running at, say, competitor.com). The app at app.example.com can use the tag strings returned to the app from calls to `create()`, but not any app at competitor.com.


One can have a set of cooperating applications that all share the same tags, even if the applications themselves are in different domains. For example, app.example.com and store.com could use the same tags by cooperating on a joint source named nft.org from which both applicqations load the distributes-security code. 

The loosest such cooperation requires then only requires that both applications provide the same cloud implementation when they each load distributed-security into their respective apps:

```
import * as OurCloud from "https://nft.org/cloud.mjs";
import * as Security from "https://nft.org/distributed-security/index.mjs";
Storage.Security = Security;
Security.Storage = Storage;
...
let userCreatedInOurApp = await Security.create(userDevice, userRecovery);
let userCreatedInOtherApp = await fetch("https:/otherApp.com/someUser").then(response => response.text());
let crossAppUser = await Security.create(userCreatedInOurApp, userCreatedInOtherApp);
let crossAppSignature = await Security.sign("some message", crossAppUser);
await fetch(`https://otherApp.com/doSomething?sig=${crossAppSignature}`);
```
Note that in this example, our app will not be able to decrypt or sign for userCreatedInOtherApp, but it can encrypt and verify for userCreatedInOtherApp, and it *can* do all operations (including decrypt and sign) for crossAppUser!

Even when several applications opt-in to use the same URL of the distributed-system module, no such application can copy or export keys, nor can they do any operations on a key that the user is not recursively a member of. However, any application can *use* a key (e.g., have the user sign, decrypt, or change membership of a key) that was created by any of the other applications using the same module URL IFF the user has a tag in the current app that is recursively a member. Whether this is desirable depends on the application. If you want to prevent this, you can host the distributed system module yourself. (see [Initialization](README.md#initialization)).
