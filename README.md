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

## Devices, Individuals, and Teams

To create a new set of keypairs, an application calls `create() -> tag`.  An application will typically create just one tag for each device used by an individual, although there is nothing preventing an application from creating more.  When no longer needed (e.g., in respect of the EU [Right to be Forgotten](https://gdpr.eu/right-to-be-forgotten/)), an application can permanently and globally destroy a tag with `destroy(tag)`.

Tags are public, and can be safely shared anywhere. Text can be encrypted and verified by anyone who has the tag. It can only be decrypted or signed on the device on which this tag was created.

An individual user is simply a "team" of devices. A new team can be created with one or more constitutent device tags: `create(tag1, tag2, ...) -> tag`.  The resulting tag is unique to the individual -- i.e., not the same as any of the device tags. However, the application can decrypt and sign with that tag on any of that individual's devices. Applications can add or remove a device with _**TBD**_.

There can also be teams of individuals (or even of other teams). A team's tag can be used to decrypt or sign on any computer on which any member was created (or member of a member, etc.).

## Stored Keys

Individuals and teams automatically work across devices because the individual or team's key is stored in the cloud by the application, and made available to everyone. However, the key is encrypted in such a way that it can be [decrypted by any member](https://github.com/kilroy-code/distributed-security/blob/main/docs/implementation.md#3-encrypting-for-members) (and only the members).

The application must supply (_**TBD**_) an object with two methods: 

```
retrieve(collectionName, tag) -> text
store(collectionName, tag, text, textSignedByTag)
```

We use this to store _**encrypted**_ keys as the `text` to `retrieve`:


```
     computing device D1 belonging to individual I1                                  cloud
+----------------------------------------------------+             +-------------------------+
|   vault                               app/page     |             | key(I1, {D1, D2, D3}    |
| +-----------+                       +------------+ |             |    is key(I1) encrypted |
| | key(D1)   |                       |            | |             |    for only D1, D2, or  |
| |           |                       |            | |             |    D3 to read           |
| |           |   sign(I1, someText)  |            | |             |                         |
| |           |<<---------------------| START      | |             |       key(I2, {D4, D5}) |
| |           |                       |            | |             |                         |
| |           |  retrieve('key', I1)  |            | retrieve('key', I1)                     |
| |           |--------------------->>| > > > > >  |------------->>|           key(I3, {D6}) |
| |           |                       |            |               |                         |       
| |           | key(I1, {D1, D2, D3}) |            | key(I1, {D1, D2, D3})                   |
| |           | <<--------------------| < < < < <  |<<-------------|       key(T1, {I1, I2}) |
| |           |                       |            | |             |                         |
| | use key(D1)                       |            | |             |       key(T2, {I1, I3}) |
| | to decrypt|                       |            | |             |                         |
| | key(I1, {D1, D2, D3})             |            | |             |       key(T3, {T1, I3}) |
| |           |                       |            | |             |                         |
| | sign someText                     |            | |             |                     etc.|
| | w/ key(I1)                        |            | |             |                         |
| |           | signature(I1, M)      |            | |             |                         |
| |           |---------------------->| END        | |             |                         |
| +-----------+                       +------------+ |             |                         |
+----------------------------------------------------+             +-------------------------+
```

**This is the "secret sauce" of distributed security:** Instead of expecting individuals to manage copies of keys or giving unencrypted keys to centralized or third-party "custodians", we arrange things so that:

- Device keys are stored only the device that created them, in a way that no one can read: not the application (nor by compromised application code), not the authors of distributed security, and not even by the by the users (who might be phished).
- An individual's keys are stored in the cloud, but the vault encrypts it through a technique that only allows it to only be read by one of the member devices, not by the authors of distributed security, and not by the application (nor by compromised application code), not by the cloud.
- Team keys are encrypted to be read only by their members, etc.

There are no custodial copies of device keys, and none are needed. If a device is lost, an individual can still access his individual key in the cloud using his other devices, or by a virtual device made up of security-question "members".

## Implementation

The above is everything one needs to know to use the distributed security operations. However, to understand the nature of what distributed security can do, it is also necessary to understand a bit about how it works. Fortunately, this is easily covered [here](docs/implementation.md), and there is no math.

Also see [risks.md](docs/risks.md) and (for now) [todo.md](docs/todo.md).


