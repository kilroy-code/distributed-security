# Distributed Security

This is Javascript browser code that makes it easy for developers to correctly and safely...

1. ... use the four standard cryptographic operations: **encrypt, decrypt, sign, and verify**.
2. ... provide simple and secure **key management** directly to users.

We take advantage of a number of separate APIs that **all modern browsers now support**, combined with a **new approach to key management**. The result is that any Web applications can finally offer the long-promised benefits of cryptography:

- No site logins needed.
- A receipt for activity that proves who authorized the activity (by pseudonym), and when.
- Private data that cannot be read by anyone other than the group for which it is intended, regardless of where it is stored.
- All without dependendence on any centralized authority.

While these benefits have been available in some installable apps, desktop browser extensions, and in blockchain, they are now available in ordinary **desktop and mobile web pages** with **zero operating or transaction costs and no browser extensions**.

We call it "distributed security" because:

- It is security that powers decentralized Web applications.
- Verified information and private information can be securely distributed to [the cloud](https://en.wikipedia.org/wiki/Cloud_computing) and to [p2p networks](https://en.wikipedia.org/wiki/Peer-to-peer_file_sharing).
- Individuals are not represented by a single keypair that can be lost, but are rather distributed over different keypairs for each device used by that individual.
- Arbitrary teams of individuals can have their own keypairs, managed by their members in accordance with the rules of whatever app they are for, with the encrypted keypairs stored in the cloud rather than by any one member of the team.  (In the blockchain community, teams are called [DAO](https://en.wikipedia.org/wiki/Decentralized_autonomous_organization)s.)

**Please explore the demo at [https://howard-stearns.github.io/personal/experiments/distributed-security-demo.html](https://howard-stearns.github.io/personal/experiments/distributed-security-demo.html).**


## Operations and Tags

#### Crypto Basics

[Public-key cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography) uses a related pair of numbers called the publicKey and the privateKey. The privateKey is kept secret by the owner, but the publicKey is made available to everyone.

This allows anyone to encrypt a message so that it can _only_ be read by the holder of the privateKey:

```
mathEncrypt(publicKey, originalData) -> encryptedData
mathDecrypt(privateKey, encryptedData) -> originalData
```

And it allows the holder of a privateKey to sign a message so that anyone can verify that the message they see is unaltered from what was definitely sent by the holder of the privateKey (and absolutely not by anyone else):

```
mathSign(privateKey, data) => signature
mathVerify(publicKey, data, signature) => true if signature was from the exact same data, else false
```

Implementing this requires some pretty amazing math. Browsers now implement these operations, through an API called "SubtleCrypto", so called [because](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto):

> This API provides a number of low-level cryptographic primitives. It's very easy to misuse them, and the pitfalls involved can be very subtle.
> Even assuming you use the basic cryptographic functions correctly, secure key management and overall security system design are extremely hard to get right, and are generally the domain of specialist security experts.
> Errors in security system design and implementation can make the security of the system completely ineffective.

For example, SubtleCrypto provides a number of different kinds of keys, and of algorithms for performing each of the four operations. The keypair for encrypt/decrypt must be a different keypair than for sign/verify. Text must be converted to particular forms of binary data before it can be operated on.

#### Distributed Security Basics

**In distributed security, all the various kinds of keys are represented by a single string of characters called a tag.**  The distributed security operators work directly on tags and ordinary Javascript text strings:

```
encrypt(tag, originalClearText) -> encryptedText
decrypt(tag, encryptedText) -> originalClearText

sign(tag, someText) -> signature
verify(tag, someText, signature) -> true if signature was from someText precisely, else false
```

All distributed security operations are asynchronous - the call immediately returns a Javascript [Promise](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Using_promises) that resolves to the specified value.

That's it. The only other operations are for creating and destroying tags.

## Devices, Individuals and Teams, and Recovery

To create a new set of keypairs, an application calls `create() -> tag`.  An application will typically create just one tag for each device used by an individual, although there is nothing preventing an application from creating more.  When no longer needed (e.g., in respect of the EU [Right to be Forgotten](https://gdpr.eu/right-to-be-forgotten/)), an application can permanently and globally destroy a tag with `destroy(tag)`.

Tags are public, and can be safely shared anywhere. Text can be *encrypted* and *verified* by anyone who has the tag. It can only be *decrypted* or *signed* on the device on which this tag was created.

An individual user is simply a "team" of devices. A new team can be created with one or more constitutent tags: `create(tag1, tag2, ...) -> tag`.  The resulting tag is unique to the individual -- i.e., not the same as any of the device tags. However, the application can decrypt and sign with that tag on any of that individual's devices. Applications can add or remove a device with 

```
changeMembership(teamTag, {
   add: [tag1, ...], 
   remove: [tag2, ...]
});
```

There can also be teams of individuals (or even of other teams). A team's tag can be used to decrypt, sign, or changeMembership on any computer on which any member was created (or member of a member, etc.).

What happens if you loose access to all your devices at once? No problem! One or more of the member tags of your individual tag can be a "recovery" tag, which is encrypted using the answer to one or more security questions. By calling `createTag({prompt: "some security question"})`, an application can create one or more recovery tags that consist of answers that only you would know (or the concatenation of several answers). The recovery tags are stored in the cloud and are generally not used. But if you attempt to use your individual tag on a device that is not a member of that individual tag, the system will ask the application to ask you your security question(s). The answers will unlock your individual tag only if the answers match what was previously encrypted, allowing you to add new devices and remove the old ones.

## Application Use

### Library

The distributed security code is available as a Javascript module:

```
# Installation in terminal:
npm install @kilroy-code/distributed-security
```

For development and local experiments, this module can be imported directly into application Javascript code served at an `https` or `locahost` domain. However, for production use, distributed security prevents keys from being copied or exported by keeping them in a "software vault" that prevents access from [phishing or XSS attacks](docs/risks.md). 

To do this, it is necessary to host the module via `https` in a different domain than the rest of the application. For example, an application could be at `store.example.com`, and the distributed-security code could be hosted at `vault.example.com`:

```
import Security from "https://vault.example.com/distributed-security/index.mjs";
```

One can have a set of cooperating applications that all share the same tags, even if the applications themselves are in different domains. For example, different sites named land.metaverse.org, nfts-R-us.com, and store.com, could all use the same tags by cooperating on a joint source named ntf-keys.org that hosts the distributed-security module for each to share. 

Even when several applications opt-in to use the same URL of the distributed-system module, no such application can copy or export keys, nor can they do any operations on a key that the user is not recursively a member of. However, any application can *use* a key (e.g., have the user sign, decrypt, or change membership of a key) that was created by any of the other applications using the same module URL. Whether this is desirable depends on the application. If you want to prevent this, you can host the distributed system module yourself, _or_ make application-specific keys through `getUserDeviceSecret` (see [Initialization](#initialization), below).


### Stored Keys using the Cloud Storage API

Individuals and teams automatically work across devices because the individual or team's key is stored in the cloud by the application, and made available to everyone. However, the key is encrypted in such a way that it can be [decrypted by any member](https://github.com/kilroy-code/distributed-security/blob/main/docs/implementation.md#3-encrypting-for-members) (and only the members).

The application must supply a storage object with two methods: 

```
retrieve(collectionName, tag) -> text
store(collectionName, tag, text, textSignedByTag)
```

**This is the "secret sauce" of distributed security:** Instead of expecting individuals to manage copies of keys or giving unencrypted keys to centralized or third-party "custodians", we arrange things so that:

- Device keys are stored only on the device that created them, in a way that no one can read: not the application (nor by compromised application code), not the authors of distributed security, and not even by the by the users (who might be phished).
- An individual's keys are stored in the cloud, but the vault encrypts it through a technique that only allows it to only be read by one of the member devices, not by the authors of distributed security, and not by the application (nor by compromised application code), not by the cloud.
- Team keys are encrypted to be read only by their members, etc.

There are no custodial copies of device keys, and none are needed. If a device is lost, an individual can still access his individual key in the cloud using his other devices, or by a virtual device made up of security-question "members".

Applications must supply their own implementation of this storage API, meeting their own application-specific needs. For example, the application could limit storage to paying users. For security purposes, the only requirements are:

1. The strings `'Team'` and `'EncryptionKey'` must be allowed as the `collectionName` parameters. These are the only cloud storage collectionNames used by distributed security. (The cloud storage may recognize other collection names, but this is not required for distributed security to work.)
2. The `tag` parameter must support arbitrary case-sensitive strings of at least 132 ASCII characters. The tag strings are base64-encoded, and are _not_ URL-safe.
3. Arbitrarily long base64-encoded `text` payloads must be supported. Teams with N members are less than (N + 5) kbytes. (The cloud storage may support much longer payloads, and unicode text, but this this is not required for distributed security to work.
4. `store(collectionName, tag, text, textSignedByTag)` should verify that `Security.verify(tag, signature, text)` resolves to true for the required `collectionName`s. (To allow for storage to be P2P within the application, the distributed security module is designed for such mutual co-dependency to not be an infinite loop.) Note that this is all that is needed to ensure that only the members of a key can store it or re-store it. **[FIXME/To-Be-Implemented: we also need to include the hash of the previous value in the signature, in order to prevent replay attacks from going back to an earlier version. Do we also want to supply a signature by the member tag (for auditing)?]** Note that there is no security need for additional checks, such as access-control-lists or API keys. However, an application is free to make additional checks. For example, using just the minimal requirements, any member could change the composition of their team, and an application might want to either create an audit trail of which member did so, or might want to restrict such changes to a designated "administrator" member. That's up to to the application.
5. Because of the way that payload text is encrypted, there is no security requirement to restrict access for the `retrieve` operation. However, applications are free to impose additional restrictions.


Here is how things play out for an application using the module to sign someText.  

1. The application `sign` request goes to the vault.
2. The vault then calls the `retrieve` method of the cloud storage API. 
3. The implementation of `retrive` was supplied by the application to retrieve the opaque key, typically from a cloud-based key-value store.
4. The vault on the user's browser is the only place anywhere that has the device key D1. The vault uses this to decrypt the retrieved key I1. 
5. The vault then uses the decrypted I1 keys to sign `someText` and return it to the application.

```
     computing device D1 belonging to individual I1                                  cloud
+----------------------------------------------------+             +-------------------------+
|   vault                               app/page     |             |     key(I2, {D2, D3}    |
| +-----------+                       +------------+ |             |    is key(I2) encrypted |
| | key(D1)   |                       |            | |             |    for only D2 or D3 to |
| |           |                       |            | |             |    read                 |
| |           |   sign(I1, someText)  |            | |             |                         |
| |           |<<---------------------| 1. START   | |             |   key(I3, {D4, D5, D6}) |
| |           |                       |            | |             |                         |
| |           |  retrieve('key', I1)  |            | retrieve('key', I1)                     |
| |        2. |--------------------->>| > > > > >  |------------->>|                         |
| |           |                       |            |               |     key(I1, {D1, D7)    |       
| |           |     key(I1, {D1, D7}) |            | key(I1, {D1, D7})                       |
| |           | <<--------------------| < < < < <  |<<-------------| 3.                      |
| |           |                       |            | |             |       key(T1, {I1, I2}) |
| | 4. use key(D1)                    |            | |             |                         |
| | to decrypt|                       |            | |             |       key(T2, {I1, I3}) |
| | key(I1, {D1, D7})                 |            | |             |                         |
| |           |                       |            | |             |       key(T3, {T1, I3}) |
| | 5. sign someText                  |            | |             |                         |
| | w/ key(I1)                        |            | |             |                   etc.  |
| |           | signature(I1, someText)            | |             |                         |
| |           |---------------------->| END        | |             |                         |
| +-----------+                       +------------+ |             |                         |
+----------------------------------------------------+             +-------------------------+
```

### Initialization

The secruity module must be initialized as follows:

```
Security.Storage = aCloudStorageImplmentationThatImplementsStoreAndRetrieve;
Security.getUserDeviceSecret = aFunctionOf(tag, optionalPrompt); // See below
await Security.ready; // Resolves to the module name and version when ready to use.
```
The `getUserDeviceSecret` is used as an additional layer of defense in case an attacker is able to gain access to the device vault storage (perhaps through an [application or browser bug](docs/risk.md)). The string returned by this function is used as a secret to encrypt device keys with the vault. At minumum, it must return the same string when given the same tag, for the same user on the same device. It is best if the string that is always returned is different for different devices, and different for different users on the same device (e.g., if  the same device is used by multiple human users). For example, it could be the hash of the concatenation of tag, username, and device tracking cookie if the cookie is reliable enough. `getUserDeviceSecret' can be gated on any facial recognition, MFA, or the Web Credential Management API to make use of hardware keys, authenticators, etc.

When the user creates a recovery tag, the application's `getUserDeviceSecret` is called with the prompt identifier given to `create({prompt})`. The prompt is stored (unencrypted) with the resulting (encrypted) keys in the cloud. If user later tries to (recursively) access the resulting recovery tag, the application's `getuserDeviceSecret(tag, prompt)` is called again, and result must be identical to what was returned when the recovery key was created.

`getUserDeviceSecret` can be used as a mechanism for additional distinctions. For example, suppose a group of cooperating applications want to be able to encrypt and verify a common set of tags among all uses of a shared module URL. (See [Library](#library), above.) But suppose further that, for whatever reason, they wanted each application to create a different application-specific device tag, such that no application could ask the user to sign or decrypt ultimately based solely on a different application's member device tag. In this case, an application could request an application-specific (and possibly user-specific) api-key from its own application-server, and use that api-key within the secret returned by `getUserDeviceSecret`. This would keep device keys from being used by other applications that shared the same vault. (However, it would not by itself prevent a user that has access to _both_ application's device keys from making a single "individual" key that has both application-specific keys as members. Preventing that would require additional mechanisms within the Storage API.)

## Implementation

The above is everything one needs to know to use the distributed security operations. However, to understand the nature of what distributed security can do, it is also necessary to understand a bit about how it works. Fortunately, this is easily covered [here](docs/implementation.md), and there is no math.

Also see [risks.md](docs/risks.md) and (for now) [todo.md](docs/todo.md), and the (source)[https://github.com/howard-stearns/personal/blob/master/experiments/distributed-security-demo.html] of the [demo](https://howard-stearns.github.io/personal/experiments/distributed-security-demo.html)


