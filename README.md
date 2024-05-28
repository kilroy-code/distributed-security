# Distributed Security

This is Javascript code for **browsers and Node** that makes it easy for developers to correctly and safely...

1. ... use the four standard cryptographic operations: **encrypt, decrypt, sign, and verify**.
2. ... provide simple and secure **key management** directly to users.

We take advantage of a number of separate APIs that **all modern browsers now support**, combined with a **new approach to key management**. While the benefits of cryptography have been available in some installable apps, desktop browser extensions, and in blockchain, they are now available in ordinary **desktop and mobile web pages** with **zero operating or transaction costs**, **no browser extensions**, and **no custodial wallets**.

We accomplish this by inverting the typical key-management usage where keys are used to *authenticate* an individual user, and then the user's *authority* is looked up in a database. Instead, Distributed-Security allows applications to directly define hierarchies of keys for different groups, roles, and authorities, which are proven through cryptography of enumerated members.

**For a quick "hello, world", see [@ki1r0y/signed-cloud-server](https://github.com/kilroy-code/signed-cloud-server).**

This README covers:

- [Problem Solved](#problem-solved)
- [Architectural Overview](#architectural-overview)
- [Operations](#operations) 
  - [Basic Encryption](#basic-encryption) 
  - [Basic Signatures](#basic-signatures)
  - [Creating Tags and Changing Membership](#creating-tags-and-changing-membership) 
- [Application Use](#application-use)
  - [Library Installation and Declaration](#library-installation-and-declaration)
  - [Storing Keys using the Cloud Storage API](#storing-keys-using-the-cloud-storage-api)
  - [Initialization](#initialization)


We call it "*distributed security*" because:

- It is security that powers decentralized Web applications.
- Verified information, and private information, can be securely distributed to [the cloud](https://en.wikipedia.org/wiki/Cloud_computing) and to [p2p networks](https://en.wikipedia.org/wiki/Peer-to-peer_file_sharing).
- Individuals are not represented by a single keypair that can be lost, but are rather distributed over different keypairs for each device used by that individual.
- Arbitrary teams of individuals can have their own keypairs, managed by their members in accordance with the rules of whatever app they are used in. The encrypted keypairs are stored in the cloud, rather than held by any one member of the team.  (In the blockchain community, teams are called [DAO](https://en.wikipedia.org/wiki/Decentralized_autonomous_organization)s.)

Other documents describe [advanced application usage](docs/advanced.md) and [the implementation](docs/implementation.md), and identifies [risks](docs/risks.md), the [use of the JOSE standards](docs/in-jose-terms.md), and [remaining work](docs/todo.md).

## Problem Solved

Applications can provide [wonderful benefits](docs/whycryptography.md) by using cryptography, such as:

- No passwords.
- No tracking by login or viewing of content, including private content.
- A receipt for activity that proves who authorized the activity (by pseudonym), and when.
- Secure attribution for, e.g., posts.
- Faster cloud data access.
- No theft of private content, nor risk to cloud providers that they will be forced to turn over content by threat of violence or legal action.
- All without dependendence on any centralized authority.

However, even in applications that do much of their work on powerful servers, the "last mile" of reaching users is often through their personal mobile devices. Even most mobile apps are really either wrappers around Web pages or installable web pages (aka [PWAs](https://web.dev/explore/progressive-web-apps)). To truly realize the benefits of cryptography on mobile devices, the operations must be done at the device, using keys that are on the device, aka [End-toEnd encryption](https://en.wikipedia.org/wiki/End-to-end_encryption). There are two problems that have been preventing that:

1. While the low level cryptographic operations have been available in some browsers since about 2013/2014, they are [extremely difficult to use correctly](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto#sect2). The well-developed [JOSE](https://en.wikipedia.org/wiki/JSON_Web_Encryption) standards (JWT, JWE, JWS) emerged in the following years, and the excellent [panva library](https://www.npmjs.com/package/jose) for these was first released in 2019. But that's still a lot to sort through. Distributed-security wraps these.
2. All of those standards and libraries leave key management to the application. How does a user's key get to all the user's devices? What happens when they lose the key or their whole device? A common approach is to hold the user's key pairs at the application's servers - either for the application to use there "on behalf" of the user (without End-to-End Encryption), or to be downloaded to the user's device. But this isn't safe for the users (who must trust the application and its infrastructure), or for the server operators (who are then a target for hacking and other means of being compelled to divulge the user's keys).
3. Some of the benefits of cryptography require additional infrastructure to be realized. For example, to *verify* that user A signed a document, we need user A's public key. How do we get it? From those same vulnerable and corruptible servers? And after user A proves that they are in fact, user A, how do we know that user A is authorized to perform some action, such as saving a new version of a work document? By looking them up in a database? On what server, operated by whom?

## Architectural Overview

As with most cryptographic systems, distributed-security provides an API to encrypt & decrypt messages, and to sign & verify messages. Internally to this package, the cryptography is done with the widely-used [panva library](https://www.npmjs.com/package/jose) to produce results in standard JOSE [JWE](https://www.rfc-editor.org/rfc/rfc7516) and [JWS](https://www.rfc-editor.org/rfc/rfc7515) formats, using the standard algorithms recommended for long-term key sets.

Most cryptography libraries (including panva/JOSE) expect applications to manage key creation, storage, and safety. By contrast, an application using the distributed-security library works with ordinary *tag* strings that each represent a person or a team of people in the application. For example, an application calls `encrypt(message, tag)` and the library takes care of getting the right key for the *tag* and applying it. All this happens within a separate sandbox in the browser that is isolated from the application: the application never gets to handle the keys at all. At the same time, though, no server gets to handle the raw keys either. The keys are generated in the sandbox, *encrypted* there, and the *encrypted* keys are stored in the cloud so that they are available on all the users' devices:

1. A tag can represent a team of people or other teams, like the nodes in an org-chart. The private keys of the team are *encrypted so as to be decryptable only by the members of the team*. Teams can represent a role or authority, or family, club, care team, workgroup, company, etc.
2. A tag can represent an individual human. The private keys of the individual are *encrypted so as to be decryptable only by the different browsers (on different devices) that the individual uses, or by a recovery key*.
3. A tag can represent a browser or a recovery key. The private keys of these are *encrypted by a secret supplied by the application, within the browser*:
   - The application secret for a browser is typicaly an application-specific hash of the tag, or a browser credential. The *encrypted* private browser key is stored within the sandbox on that browser. They are never put in the cloud, and are only available on that one browser.
   - The application secret for a recovery key is typically derived from a password or from the concatenated answer to a set of security questions, and then salted by an application-specific hash of the tag. The *encrypted* private recovery key is then stored in the cloud and used only when no applicable browser key is available for the current browser.

The library takes care of creating the separate sandbox within browsers, and communications with the application. It takes care of the cloud safely handling keys and messages of different types, and of security storing browser keys. The application plugs in its own cloud storage, following requirements defined [here](#storing-keys-using-the-cloud-storage-api).

## Operations

### Basic Encryption

```
let messageString = "I♥U";
let encryption = await Security.encrypt(messageString, tag); 
let decryption = await Security.decrypt(encryption);

console.log(decryption.text); // I♥U
```

The message can also be any object serializable as JSON:

```
let messageObject = {foo: 1, bar: ["x", 2.3, true], baz: "hello"};
let encryption = await Security.encrypt(messageObject, tag);
let decryption = await Security.decrypt(encryption);

// As is customary in, e.g., browser fetch responses, accessing the "json" of something
// gives the serializable object itself:
console.log(decryption.json); // {foo: 1, bar: ['x', 2.3, true], baz: 'hello'}
// And the serialized string is avaiable as text:
console.log(decryption.text); // {"foo":1,"bar":["x",2.3,true],"baz":"hello"}
```

The message can also be binary:

```
let encryption = await Security.encrypt(aUint8Array, tag);
let decryption = await Security.decrypt(encryption);
```

In all three cases, `decryption.payload` returns the Uint8Array of the underlying original message.

You can also explicitly specify the content type and timestamp, and can [**encrypt for multiple specific tags**](lib/advanced.md#encryption-with-multiple-tags-and-other-encryption-options).


### Basic Signatures

```
let signature = await Security.sign(messageString, tag);
// or
let signature = await Security.sign(messageObject, tag);
// or 
let signature = await Security.sign(aUint8Array, tag);

let verification = await Security.verify(signature);
```
and then `verification.payload`, `verification.text`, and `verifcation.json` are as above for encryption of the various types of messages. However, if the signature is not valid, `verification` holds `undefined`.

As with encryption, you can explicitly specify the content type and timestamp, and can [**sign with multiple specific tags**](lib/advanced.md#signatures-with-multiple-tags-and-other-signature-options). The latter is particularly powerful, because verification can confirm not only that a particular team member signed, but which member, and that the signing member is still on the team at the time of verification.

### Creating Tags and Changing Membership

For each new user, an application creates a tag whose "members" are the tags for the browsers or devices used by this person, and a recovery tag based on security questions:

```
let myDeviceTag = await Security.create();
let myRecoveryTag = await Security.create({prompt: "What is the air-speed velocity of an unladen swallow?"});
let myIndividualTag = await Security.create(myDeviceTag, myRecoveryTag);
```

`myIndividualTag` is what the application uses to encrypt or sign for this user. (E.g., `tag` in the examples of the previous sections.) An individual human may have many tags, e.g., for each "alt" or persona, for rotation over time, or even a new tag for each transaction. The public keys are available to everyone in the application (e.g., to encrypt for this user), and the private keys are encrypted for storage in the cloud, so that they can only be decrypted by the listed member tags (`myDeviceTag` and `myRecoveryTag` in this example).

The private keys for `myDeviceTag` are only stored directly in the browser or device on which they were created. When the library is asked to sign or decrypt for `myIndividualTag` in a new session, the library automatically uses the previously stored `myDeviceTag` to decrypt the private keys of the`myIndividualTag`. Any attempt to do this will fail on a device that does not already have the correct `myDeviceTag`. In this case, the library will attempt to use the `myRecoveryTag` as desicribed in [Initialization](#initialization), below.

The various tags returned to the application are public, and can safely be shared anywhere. For example, an application can share aliceTag with Bob, who can then send Alice a secret message using `encrypt(message, aliceTag)`.

A team composed of individuals and other teams can be created in the same way as for individuals:

```
let myTeam = await Security.create(myIndividualTag, aliceTag, anotherTeamTag);
```

The application can add or remove member tags (individuals, devices, etc.) with:

```
Security.changeMembership({
   tag: tag,
   add: [tag1, ...], 
   remove: [tag2, ...]
});
```

When no longer needed (e.g., in respect of the EU [Right to be Forgotten](https://gdpr.eu/right-to-be-forgotten/)), an application can permanently and globally destroy a tag with `destroy(tag)`.

## Application Use

### Library Installation and Declaration

The distributed-security code is available as a Javascript module:

```
# Installation in terminal:
npm install @ki1r0y/distributed-security
```

This creates a directory for the module, e.g., `node_modules/@ki1r0y/distributed-security/`. A NodeJS application can just:

```
import Security from "@ki1r0y/distributed-security";
```
and the right files will be pulled in (e.g., starting with `lib/api.mjs`).

For browsers, four important files have been provided in the `dist/` subdirectory: `index-bundle.mjs`, `vault.html`, `vault-bundle.mjs`, and `worker-bundle.mjs`. These four files must be made available on the server in the same directory, and the application must import `index-bundle.mjs`. There are several ways that this can be done.

For development and local experiments, the browser files can be served by a `locahost` or `https` domain, and it can be the same domain as the rest of the application. (Browsers require either `localhost` or `https` to enable cryptography.) The application can import `index-bundle.mjs` directly by pathname, and it will automatically pull in the other three files from the same directory on the same origin. The persisted encrypted device keys will be stored in an indexDB object store that is also accessible to the application.

For production use, it is important to keep the storage and cryptographic operations in a separate [browsing context](https://developer.mozilla.org/en-US/docs/Glossary/Browsing_context) from the rest of the application. This is accomplished by serving `index-bundle.mjs` from a separate https origin. The easiest way to do this is to use the [@ki1r0y/signed-cloud-server package](https://github.com/kilroy-code/signed-cloud-server), which also provides cloud storage. (See the next section.) In any case, the package can then be imported by URL.


### Storing Keys using the Cloud Storage API

Individuals and teams automatically work across devices because the individual or team's key is stored in the cloud by the application, and made available to everyone. However, the key is encrypted in such a way that it can be [decrypted by any member](docs/implementation.md#3-encrypting-for-members) (and only the members).

**This is the "special sauce" of distributed-security:** Instead of expecting individuals to manage copies of keys or giving unencrypted keys to centralized or third-party "custodians", we arrange things so that:

- Device keys are stored only on the device that created them, in a way that no one can read: not the application (nor by compromised application code), not the authors of distributed-security, and not even by the by the users (who might otherwise get phished).
- An individual's keys are stored in the cloud, but the vault encrypts it through a technique that allows it to be decrypted only by one of the member devices, not by the authors of distributed-security, not by the application (nor by compromised application code), and not by the cloud.
- Team keys are encrypted to be read only by their members, etc.

There are no custodial copies of device keys, and none are needed. If a device is lost, an individual can still access his individual key in the cloud using his other devices, or by a virtual device made up of security-question answers.

Security.Storage is an object with two methods: 

```
await store(collectionName, tag, signature)
await retrieve(collectionName, tag); // Resolves to the signature given to store.
```

The default implementation of these methods stores and retrieves on the same origin that the bundled files are servered from.  The easiest way to implement that is to run [@ki1r0y/signed-cloud-server package](https://github.com/kilroy-code/signed-cloud-server) - either as a stand-alone server or as middleware routes added to another server.

Alternatively, applications can supply their own implementation of the Storage API, meeting their own application-specific needs. For example, the application could limit storage to paying users. The only requirements imposed by Distributed-Security are:

1. The strings `'Team'` `'KeyRecovery'` and `'EncryptionKey'` must be allowed as the `collectionName` parameters. These are the only cloud storage collectionNames used by distributed-security. (The cloud storage may recognize other collection names, but this is not required for distributed-security to work.)
2. The `tag` parameter must support arbitrary case-sensitive strings of at least 132 ASCII characters. The tag strings are url-safe base64-encoded.
3. Arbitrarily long text and ascii jsonable payloads must be supported. Teams with N members are less than (1.2 N + 8) kbytes. (The cloud storage may support much longer payloads, and unicode text, but this this is not required for distributed-security to work.
4. `store(collectionName, tag, signature)` should verify that `Security.verify(signature, {team: tag, notBefore: "team"})` resolves to truthy. (To allow for storage to be P2P within the application, the distributed-security module is designed for such mutual co-dependency to not be an infinite loop.) store() can return anything except `undefined`. There is no security need for additional checks, such as access-control-lists or API keys. However, an application is free to make additional checks. For example, using just the minimal requirements, any member could change the composition of their team, and an application might want to either create an audit trail of which member did so, or might want to restrict such changes to a designated "administrator" member. That's up to the application.
5. Because of the way that payload text is encrypted, there is no security requirement to restrict access for the `retrieve` operation. However, applications are free to impose additional restrictions.

### Initialization

The secruity module must be initialized as follows:

```
Security.Storage = aCloudStorageImplmentationThatImplementsStoreAndRetrieve; // See above.
Security.getUserDeviceSecret = aFunctionOf(tag, optionalPrompt); // See below
await Security.ready; // Resolves to the {name, version, origin} of the package when ready to use.
```
The `getUserDeviceSecret` is used as an additional layer of defense in case an attacker is able to gain access to the device storage (perhaps through an [application or browser bug](docs/risks.md)). The string returned by this function is used as a secret to encrypt device keys within the package. At minumum, it must return the same string when given the same tag, for the same user on the same device. It is best if the string that is always returned is different for different devices, and different for different users on the same device (e.g., if  the same device is used by multiple human users). For example, it could be the hash of the concatenation of tag, username, and device tracking cookie if the cookie is reliable enough. `getUserDeviceSecret` can be gated on any facial recognition, MFA, or the Web Credential Management API to make use of hardware keys, authenticators, etc.

When the user creates a recovery tag, the application's `getUserDeviceSecret` is called with the same prompt identifier that had earlier been given to `create({prompt})`. The prompt is stored (unencrypted) with the resulting (encrypted) keys in the cloud. If the user later tries to (recursively) access the resulting recovery tag in any browser, the application's `getUserDeviceSecret(tag, prompt)` is called again, and result must be identical to what was returned when the recovery key was created.

It is recommended that the size of the string producted by getUserDeviceSecret should be between 16 and 128 characters.

`getUserDeviceSecret` can be used as a mechanism for additional distinctions. For example, suppose a group of cooperating applications want to be able to encrypt and verify a common set of tags among all uses of a shared module URL. (See [Library](#library), above.) But suppose further that, for whatever reason, they wanted each application to create a different application-specific device tag, such that no application could ask the user to sign or decrypt ultimately based solely on a different application's member device tag. In this case, an application could request an application-specific (and possibly user-specific) api-key from its own application-server, and use that api-key within the secret returned by `getUserDeviceSecret`. This would keep device keys from being used by other applications that shared the same vault. (However, it would not by itself prevent a user that has access to _both_ application's device keys from making a single "individual" key that has both application-specific keys as members. Preventing that would require additional mechanisms within the application-provided Storage API.)

[![](docs/repo-qr.png)](https://github.com/kilroy-code/distributed-security)
