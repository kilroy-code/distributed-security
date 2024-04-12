# Distributed Security

This is Javascript code for browser and Node that makes it easy for developers to correctly and safely...

1. ... use the four standard cryptographic operations: **encrypt, decrypt, sign, and verify**.
2. ... provide simple and secure **key management** directly to users.

We take advantage of a number of separate APIs that **all modern browsers now support**, combined with a **new approach to key management**. The result is that any Web applications can finally offer the long-promised [benefits of cryptography](lib/whycryptography.md), such as:

- No passwords.
- No tracking by login or viewing of content, including private content.
- A receipt for activity that proves who authorized the activity (by pseudonym), and when.
- Secure attribution for, e.g., posts.
- Faster cloud data access.
- No theft of private content, nor risk to cloud providers that they will be forced to turn over content by threat of violence or legal action.
- All without dependendence on any centralized authority.

While these benefits have been available in some installable apps, desktop browser extensions, and in blockchain, they are now available in ordinary **desktop and mobile web pages** with **zero operating or transaction costs and no browser extensions**.

We accomplish this by inverting the typical key-management usage where keys are used to *authenticate* an individual user, and then the user's *authority* is looked up in a database. Instead, Distributed-Security allows applications to directl define hierarchies of keys for different groups, roles, and authorities, which are proven through cryptography of enumerated members.

This README covers:

- [Architectural Overview](#architectural-overview)
- [Operations](#operations) 
  - [Basic Encryption](#basic-encryption) 
  - [Basic Signatures](#basic-signatures)
  - [Creating Tags and Changing Membership](#creating-tags-and-changing-membership) 
- [Application Use](#application-use)
  - [Library Installation and Declaration](#library-installation-and-declaration)
  - [Storing Keys using the Cloud Storage API](#storing-keys-using-the-cloud-storage-api)
  - [Initialization](#initialization)


We call it "distributed security" because:

- It is security that powers decentralized Web applications.
- Verified information and private information can be securely distributed to [the cloud](https://en.wikipedia.org/wiki/Cloud_computing) and to [p2p networks](https://en.wikipedia.org/wiki/Peer-to-peer_file_sharing).
- Individuals are not represented by a single keypair that can be lost, but are rather distributed over different keypairs for each device used by that individual.
- Arbitrary teams of individuals can have their own keypairs, managed by their members in accordance with the rules of whatever app they are for, with the encrypted keypairs stored in the cloud rather than by any one member of the team.  (In the blockchain community, teams are called [DAO](https://en.wikipedia.org/wiki/Decentralized_autonomous_organization)s.)

Other documents describe [advanced application usage](docs/advanced.md) and [the implementation](docs/implementation.md), and identifies [risks](docs/risks.md), the [use of JOSE](docs/in-jose-terms.md), and [remaining work](docs/todo.md).

## Architectural Overview

As with most cryptographic systems, distributed-security provides an API to encrypt & decrypt messages, and to sign & verify messages. Internally, this is done with the widely-used [panva library](https://www.npmjs.com/package/jose) to produce results in standard JOSE [JWE](https://www.rfc-editor.org/rfc/rfc7516) and [JWS](https://www.rfc-editor.org/rfc/rfc7515) formats, using the standard algorithms recommended for long-term key sets.

Most cryptography libraries (including panva) expect applications to manage key creation, storage, and safety. By contrast, an application using the distributed-security library works with ordinary *tag* strings that each represent a person or a team of people in the application. For example, an application calls `encrypt(message, tag)` and the library takes care of getting the right key for the *tag* and applying it. All this happens within a separate sandbox in the browser that is isolated from the application - the application never gets to handle the keys at all. At the same time, though, no server gets to handle the raw keys either. The keys are generated in the sandbox, encrypted there, and the *encrypted* keys are stored in the cloud so that they are available on all the users' devices:

1. A tag can represent a team of people or other teams, like the nodes in an org-chart. The private keys of the team are encrypted so as to be decryptable only by the members of the team. Teams can represent a role or authority, or family, workgroup or company.
2. A tag can represent an individual human. The private keys of the individual are encrypted so as to be decryptable only by the different browsers (on different devices) that the individual uses, or by a recovery key.
3. A tag can represent a browser or a recovery key. The private keys of these are encrypted by a secret supplied by the application:
   - The application secret for a browser is typicaly an application-specific hash of the tag, or a browser credential. The encrypted private browser key is stored within the sandbox on that browser. They are never put in the cloud, and are only available on that one browser.
   - The application secret for a recovery key is typically derived from a password or from the concatenated answer to a set of security questions, and then salted by an application-specific hash of the tag. The encrypted private recovery key is then stored in the cloud and used only when no applicable browser key is available for the current browser.

Note that *application requests* to encrypt for a tag are simple, compact, encryptions that are decrypted only by that tag. It is the private key of tag that is *internally* encrypted for each member tag. However, an application can ask that a message be encrypted or signed for multiple tags. In particular, a message can be signed for a tag *and* for the tag of the specific member that is signing. When verifying such member-signed tag, by default the system will check that the member is still a member at the time of verification.

The library takes care of creating the separate sandbox within browsers, and communications with the application. It takes care of the cloud safely handling keys and messages of different types, and of security storing browser keys. The application plugs in its own cloud storage, following requirements defined here.

## Operations

### Basic Encryption

```
let messageString = "I♥U";
let encryption = await encrypt(messageString, tag); 
let decryption = await decrypt(encryption);

console.log(decryption.text); // I♥U
```

The message can also be any object serializable as JSON:

```
let messageObject = {foo: 1, bar: ["x", 2.3, true], baz: "hello"};
let encryption = await encrypt(messageObject, tag);
let decryption = await decrypt(encryption);

// As is customary in, e.g., browser fetch responses, accessing the "json" of something
// gives the serializable object itself:
console.log(decryption.json); // {foo: 1, bar: ['x', 2.3, true], baz: 'hello'}
// And the serialized string is avaiable as text:
console.log(decryption.text); // {"foo":1,"bar":["x",2.3,true],"baz":"hello"}
```

The message can also be binary:

```
let encryption = await encrypt(aUint8Array, tag);
let decryption = await decrypt(encryption);
```

In all three cases, `decryption.payload` returns the Uint8Array of the underlying original message.

(See also  [Encryption with Multiple Tags and Other Encryption Options](lib/advanced.md#encryption-with-multiple-tags-and-other-encryption-options).)


### Basic Signatures

```
let signature = await sign(messageString, tag);
// or
let signature = await sign(messageObject, tag);
// or 
let signature = await sign(aUint8Array, tag);

let verification = await verify(signature);
```
and then `verification.payload`, `verification.text`, and `verifcation.json` are as above for encryption of the various types of messages. However, if the signature is not valid, `verification` holds `undefined`.

(See also [Signatures with Multiple Tags and Other Signature Options](lib/advanced.md#signatures-with-multiple-tags-and-other-signature-options).)

### Creating Tags and Changing Membership

For each new user, an application creates a tag whose "members" are the tags for the browsers or devices used by this person, and a recovery tag based on security questions:

```
let myDeviceTag = await create();
let myRecoveryTag = await create({prompt: "What is the air-speed velocity of an unladen swallow?"});
let myIndividualTag = await create(myeviceTag, myRecoveryTag);
```

`myIndividualTag` is what the application uses to encrypt or sign for this user. (E.g., `tag` in the examples of the previous sections.) An individual human may have many tags, e.g., for each "alt" or persona, for rotation over time, or even a new tag for each transaction. The public keys are available to everyone in the application (e.g., to encrypt for this user), and the private keys are encrypted for storage in the cloud, so that they can only be decrypted by the listed member tags (`myDeviceTag` and `myRecoveryTag` in this example).

The private keys for `myDeviceTag` are only stored directly in the browser or device on which they were created. When the library is asked to sign or decrypt for `myIndividualTag` in a new session, the library automatically uses the previously stored `myDeviceTag` to decrypt the private keys of the`myIndividualTag`. Any attempt to do this will fail on a device that does not already have the correct `myDeviceTag`. In this case, the library will attempt to use the `myRecoveryTag` as desicribed in [Initialization](#initialization), below.

The various tags returned to the application are public, and can safely be shared anywhere. For example, an application can share aliceTag with Bob, who can then send Alice a secret message using `encrypt(message, aliceTag)`.

A team composed of individuals and other teams can be created in the same way as for individuals:

```
let myTeam = await create(myIndividualTag, aliceTag, anotherTeamTag);
```

The application can add or remove member tags (individuals, devices, etc.) with:

```
changeMembership({
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
npm install @kilroy-code/distributed-security
```

For development and local experiments, this module can be imported directly into application Javascript code served at an `https` or `locahost` domain. However, for production use, distributed-security prevents keys from being copied or exported by keeping them in a "software vault" that prevents access from [phishing or XSS attacks](docs/risks.md). 

To do this, it is necessary to host the module via `https` at a *different origin* than the rest of the application. (This creates a distinct ["browsing context"](https://developer.mozilla.org/en-US/docs/Glossary/Browsing_context) that isolates the code and data.) For example, an application could be at `store.example.com`, and the distributed-security code could be hosted at `vault.example.com`:

```
import Security from "https://vault.example.com/distributed-security/index.mjs";
```

The `index.mjs` is very small. Wherever it is hosted, it must have 


### Storing Keys using the Cloud Storage API

Individuals and teams automatically work across devices because the individual or team's key is stored in the cloud by the application, and made available to everyone. However, the key is encrypted in such a way that it can be [decrypted by any member](docs/implementation.md#3-encrypting-for-members) (and only the members).

**This is the "special sauce" of distributed-security:** Instead of expecting individuals to manage copies of keys or giving unencrypted keys to centralized or third-party "custodians", we arrange things so that:

- Device keys are stored only on the device that created them, in a way that no one can read: not the application (nor by compromised application code), not the authors of distributed-security, and not even by the by the users (who might otherwise get phished).
- An individual's keys are stored in the cloud, but the vault encrypts it through a technique that allows it to be decrypted only by one of the member devices, not by the authors of distributed-security, not by the application (nor by compromised application code), and not by the cloud.
- Team keys are encrypted to be read only by their members, etc.

There are no custodial copies of device keys, and none are needed. If a device is lost, an individual can still access his individual key in the cloud using his other devices, or by a virtual device made up of security-question answers.

The application must supply a storage object with two methods: 

```
await store(collectionName, tag, signature)
let signature = await retrieve(collectionName, tag);
```

Applications must supply their own implementation of this storage API, meeting their own application-specific needs. For example, the application could limit storage to paying users. The only requirements imposed by Distributed-Security are:

1. The strings `'Team'` `'KeyRecovery'` and `'EncryptionKey'` must be allowed as the `collectionName` parameters. These are the only cloud storage collectionNames used by distributed-security. (The cloud storage may recognize other collection names, but this is not required for distributed-security to work.)
2. The `tag` parameter must support arbitrary case-sensitive strings of at least 132 ASCII characters. The tag strings are url-safe base64-encoded.
3. Arbitrarily long text and jsonable payloads must be supported. Teams with N members are less than (N + 5) kbytes. (The cloud storage may support much longer payloads, and unicode text, but this this is not required for distributed-security to work.
4. `store(collectionName, tag, signature)` should verify that `Security.verify(signature, {team: tag, notBefore: "team"})` resolves to truthy. (To allow for storage to be P2P within the application, the distributed-security module is designed for such mutual co-dependency to not be an infinite loop.) store() can return anything except `undefined`. There is no security need for additional checks, such as access-control-lists or API keys. However, an application is free to make additional checks. For example, using just the minimal requirements, any member could change the composition of their team, and an application might want to either create an audit trail of which member did so, or might want to restrict such changes to a designated "administrator" member. That's up to to the application.
5. Because of the way that payload text is encrypted, there is no security requirement to restrict access for the `retrieve` operation. However, applications are free to impose additional restrictions.

### Initialization

The secruity module must be initialized as follows:

```
Security.Storage = aCloudStorageImplmentationThatImplementsStoreAndRetrieve;
Security.getUserDeviceSecret = aFunctionOf(tag, optionalPrompt); // See below
await Security.ready; // Resolves to the {name, versIon} of the package when ready to use.
```
The `getUserDeviceSecret` is used as an additional layer of defense in case an attacker is able to gain access to the device vault storage (perhaps through an [application or browser bug](docs/risks.md)). The string returned by this function is used as a secret to encrypt device keys within the vault. At minumum, it must return the same string when given the same tag, for the same user on the same device. It is best if the string that is always returned is different for different devices, and different for different users on the same device (e.g., if  the same device is used by multiple human users). For example, it could be the hash of the concatenation of tag, username, and device tracking cookie if the cookie is reliable enough. `getUserDeviceSecret` can be gated on any facial recognition, MFA, or the Web Credential Management API to make use of hardware keys, authenticators, etc.

When the user creates a recovery tag, the application's `getUserDeviceSecret` is called with the same prompt identifier that had earlier been given to `create({prompt})`. The prompt is stored (unencrypted) with the resulting (encrypted) keys in the cloud. If the user later tries to (recursively) access the resulting recovery tag in any browser, the application's `getUserDeviceSecret(tag, prompt)` is called again, and result must be identical to what was returned when the recovery key was created.

It is recommended that the size of the string producted by getUserDeviceSecret should be between 16 and 128 characters.

`getUserDeviceSecret` can be used as a mechanism for additional distinctions. For example, suppose a group of cooperating applications want to be able to encrypt and verify a common set of tags among all uses of a shared module URL. (See [Library](#library), above.) But suppose further that, for whatever reason, they wanted each application to create a different application-specific device tag, such that no application could ask the user to sign or decrypt ultimately based solely on a different application's member device tag. In this case, an application could request an application-specific (and possibly user-specific) api-key from its own application-server, and use that api-key within the secret returned by `getUserDeviceSecret`. This would keep device keys from being used by other applications that shared the same vault. (However, it would not by itself prevent a user that has access to _both_ application's device keys from making a single "individual" key that has both application-specific keys as members. Preventing that would require additional mechanisms within the application-provided Storage API.)
