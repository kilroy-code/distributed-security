# Distributed Security

This is Javascript browser code that makes it easy for developers to correctly and safely...

1. ... use the four standard cryptographic operations: **encrypt, decrypt, sign, and verify**.
2. ... provide simple and secure **key management** directly to users.

We take advantage of a number of separate APIs that **all modern browsers now support**, combined with a **new approach to key management**. The result is that any Web applications can finally offer the long-promised benefits of cryptography:

- No passwords.
- No tracking by login or viewing of content, including private content.
- A receipt for activity that proves who authorized the activity (by pseudonym), and when.
- Faster cloud data access.
- No theft of private content, nor risk to cloud providers that they will be forced to turn over content by threat of violence or legal action.
- All without dependendence on any centralized authority.

While these benefits have been available in some installable apps, desktop browser extensions, and in blockchain, they are now available in ordinary **desktop and mobile web pages** with **zero operating or transaction costs and no browser extensions**.

This README covers:

- [Operations and Tags](#operations-and-tags) - how easy it is for Web pages to safely use basic cryptography
- [Devices, Individuals and Teams, and Recovery](#devices-individuals-and-teams) - practical key management
- [Application Use](#application-use)
  - [Library Installation and Declaration](#library-installation-and-declaration)
  - [Storing Keys using the Cloud Storage API](#storing-keys-using-the-cloud-storage-api)
  - [Initialization](#initialization)

At the end, we will revisit how this matches up with the benefits above.

We call it "distributed security" because:

- It is security that powers decentralized Web applications.
- Verified information and private information can be securely distributed to [the cloud](https://en.wikipedia.org/wiki/Cloud_computing) and to [p2p networks](https://en.wikipedia.org/wiki/Peer-to-peer_file_sharing).
- Individuals are not represented by a single keypair that can be lost, but are rather distributed over different keypairs for each device used by that individual.
- Arbitrary teams of individuals can have their own keypairs, managed by their members in accordance with the rules of whatever app they are for, with the encrypted keypairs stored in the cloud rather than by any one member of the team.  (In the blockchain community, teams are called [DAO](https://en.wikipedia.org/wiki/Decentralized_autonomous_organization)s.)

**Please explore the demo at [https://howard-stearns.github.io/personal/experiments/distributed-security-demo.html](https://howard-stearns.github.io/personal/experiments/distributed-security-demo.html).**. Other documents describe [the implementation](docs/implementation.md) and identifies [risks](docs/risks.md) and [remaining work](docs/todo.md).

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

That's it. The only other operations are for creating, changing, and destroying tags.

## Devices, Individuals and Teams, and Recovery

To create a new set of keypairs, an application calls `create() -> tag`.  An application will typically create just one tag for each browser used by an individual, although there is nothing preventing an application from creating more.  When no longer needed (e.g., in respect of the EU [Right to be Forgotten](https://gdpr.eu/right-to-be-forgotten/)), an application can permanently and globally destroy a tag with `destroy(tag)`.

Tags are public, and can be safely shared anywhere. Text can be *encrypted* and *verified* by anyone who has the tag. For tags made with `create()` (with no arguments), text can only be *decrypted* or *signed* on the browser and device on which the tag was created.

An individual user is simply a "team" of browser-specific tags. A new team tag can be created with one or more constitutent tags: `create(tag1, tag2, ...) -> tag`.  The resulting tag is unique to the individual -- i.e., not the same as any of the browser-specific tags. However, the application can decrypt and sign with that tag on any of that individual's devices. Applications can add or remove a member tag with 

```
changeMembership(teamTag, {
   add: [tag1, ...], 
   remove: [tag2, ...]
});
```

There can also be teams of individuals (or even of other teams). A team's tag can be used to decrypt, sign, or changeMembership on any computer on which any member was created (or member of a member, etc.).

What happens if you loose access to all your devices at once? No problem! One or more of the member tags of your individual tag can be a "recovery" tag, which is encrypted using the answer to one or more security questions. By calling `createTag({prompt: "some security question"})`, an application can create one or more recovery tags that consist of answers that only you would know (or the concatenation of several answers). The recovery tags are stored (encrypted) in the cloud and are generally not used. But if you attempt to use your individual tag on a device that is not a member of that individual tag, the system will ask the application to ask you your security question(s). The answers will unlock your individual tag only if the answers match what was previously encrypted, allowing you to add new devices and remove the old ones.

## Application Use

### Library Installation and Declaration

The distributed security code is available as a Javascript module:

```
# Installation in terminal:
npm install @kilroy-code/distributed-security
```

For development and local experiments, this module can be imported directly into application Javascript code served at an `https` or `locahost` domain. However, for production use, distributed security prevents keys from being copied or exported by keeping them in a "software vault" that prevents access from [phishing or XSS attacks](docs/risks.md). 

To do this, it is necessary to host the module via `https` in a different domain than the rest of the application. (This creates a distinct ["browsing context"](https://developer.mozilla.org/en-US/docs/Glossary/Browsing_context) that isolates the code and data.) For example, an application could be at `store.example.com`, and the distributed-security code could be hosted at `vault.example.com`:

```
import Security from "https://vault.example.com/distributed-security/index.mjs";
```

One can have a set of cooperating applications that all share the same tags, even if the applications themselves are in different domains. For example, different sites named land.metaverse.org, NFTs-R-us.com, and store.com, could all use the same tags by cooperating on a joint source named NFT-keys.org that hosts the distributed-security module for each to share. 

Even when several applications opt-in to use the same URL of the distributed-system module, no such application can copy or export keys, nor can they do any operations on a key that the user is not recursively a member of. However, any application can *use* a key (e.g., have the user sign, decrypt, or change membership of a key) that was created by any of the other applications using the same module URL. Whether this is desirable depends on the application. If you want to prevent this, you can host the distributed system module yourself, _or_ make application-specific keys through `getUserDeviceSecret` (see [Initialization](#initialization), below).


### Storing Keys using the Cloud Storage API

Individuals and teams automatically work across devices because the individual or team's key is stored in the cloud by the application, and made available to everyone. However, the key is encrypted in such a way that it can be [decrypted by any member](docs/implementation.md#3-encrypting-for-members) (and only the members).

**This is the "secret sauce" of distributed security:** Instead of expecting individuals to manage copies of keys or giving unencrypted keys to centralized or third-party "custodians", we arrange things so that:

- Device keys are stored only on the device that created them, in a way that no one can read: not the application (nor by compromised application code), not the authors of distributed security, and not even by the by the users (who might otherwise get phished).
- An individual's keys are stored in the cloud, but the vault encrypts it through a technique that allows it to be decrypted only by one of the member devices, not by the authors of distributed security, not by the application (nor by compromised application code), and not by the cloud.
- Team keys are encrypted to be read only by their members, etc.

There are no custodial copies of device keys, and none are needed. If a device is lost, an individual can still access his individual key in the cloud using his other devices, or by a virtual device made up of security-question answers.

The application must supply a storage object with two methods: 

```
retrieve(collectionName, tag) -> text
store(collectionName, tag, text, textSignedByTag)  (*)
```

Applications must supply their own implementation of this storage API, meeting their own application-specific needs. For example, the application could limit storage to paying users. For security purposes, the only requirements are:

1. The strings `'Team'` `'KeyRecovery'` and `'EncryptionKey'` must be allowed as the `collectionName` parameters. These are the only cloud storage collectionNames used by distributed security. (The cloud storage may recognize other collection names, but this is not required for distributed security to work.)
2. The `tag` parameter must support arbitrary case-sensitive strings of at least 132 ASCII characters. The tag strings are base64-encoded, and are _not_ URL-safe.(*)
3. Arbitrarily long base64-encoded `text` payloads must be supported. Teams with N members are less than (N + 5) kbytes. (The cloud storage may support much longer payloads, and unicode text, but this this is not required for distributed security to work.
4. `store(collectionName, tag, text, textSignedByTag)` should verify that `Security.verify(tag, textSignedByTag, text)` resolves to true for the required `collectionName`s. (To allow for storage to be P2P within the application, the distributed security module is designed for such mutual co-dependency to not be an infinite loop.) There is no security need for additional checks, such as access-control-lists or API keys. However, an application is free to make additional checks. For example, using just the minimal requirements, any member could change the composition of their team, and an application might want to either create an audit trail of which member did so, or might want to restrict such changes to a designated "administrator" member. That's up to to the application.(*)
5. Because of the way that payload text is encrypted, there is no security requirement to restrict access for the `retrieve` operation. However, applications are free to impose additional restrictions.


Here is how things play out for an application using the module to sign someText.  

1. The application `sign` request goes to the vault. 
2. The vault then calls the `retrieve` method of the cloud storage API. 
3. The implementation of `retrieve` was supplied by the application to retrieve the opaque key, typically from a cloud-based key-value store.
4. The vault on the user's browser is the only place anywhere that has the device key D1. The vault uses this to decrypt the retrieved key I1. 
5. The vault then uses the decrypted I1 keys to sign `someText` and return it to the application.

```
     computing device D1 belonging to individual I1                        cloud
+----------------------------------------------------+             +-------------------------+
|    app/page                            vault       |             |                         |                      
| store.example.com                vault.example.com |             |   key(I1, {D1, D7))     |
| +-----------+                       +------------+ |             |    is key(I1) encrypted |
| |           |                       | key(D1)    | |             |    for only D1 or D7 to |
| |           |                       |            | |             |    read                 |
| |           |   sign(I1, someText)  |            | |             |                         |
| |   1.START |--------------------->>|            | |             |                         |
| |           |                       |            | |             |                         |
| |           |                       |          2.| retrieve('key', I1)                     |
| |           |                       |            |------------->>|                         |
| |           |                       |            |               |                         |       
| |           |                       |            | key(I1, {D1, D7})  3.                   |
| |           |                       |            |<<-------------|                         |
| |           |                      4. use key(D1)| |             |                         |
| |           |                       |  to decrypt| |             |                         |
| |           |                     key(I1, {D1, D7})|             |   there are other keys  |
| |           |                       |            | |             |  here in the cloud, too |
| |           |                    5. sign someText| |             |                         |
| |           |                       |  w/ key(I1)| |             |                         |
| |           |                       |            | |             |                         |
| |     END   |signature(I1, someText)|            | |             |                         |
| |           |<<---------------------|            | |             |                         |
| +-----------+                       +------------+ |             |                         |
+----------------------------------------------------+             +-------------------------+
```

> (*) - The storage API described is what is currently implemented in the module, demo and unit tests, and it has some easily removed weaknesses (involving replay attacks and mischief by former team members). However, the API will change slightly as we develop a more general practical storage API. Using browser-side encryption and signing, it now practical to make a secure distributed storage API that can be implented as P2P if desired, cached at browser, server, and edge, secure though end-to-end-encryption, and properly attributed for both distributed accounting and sourcing. To meet these needs, it will be desirable to have a standard format (such as JWS/JSE perhaps) in which parties can verify signatures and examine team membership. See [the storage repo](https://github.com/kilroy-code/storage/blob/main/README.md).

### Initialization

The secruity module must be initialized as follows:

```
Security.Storage = aCloudStorageImplmentationThatImplementsStoreAndRetrieve;
Security.getUserDeviceSecret = aFunctionOf(tag, optionalPrompt); // See below
await Security.ready; // Resolves to the module name and version when ready to use.
```
The `getUserDeviceSecret` is used as an additional layer of defense in case an attacker is able to gain access to the device vault storage (perhaps through an [application or browser bug](docs/risks.md)). The string returned by this function is used as a secret to encrypt device keys within the vault. At minumum, it must return the same string when given the same tag, for the same user on the same device. It is best if the string that is always returned is different for different devices, and different for different users on the same device (e.g., if  the same device is used by multiple human users). For example, it could be the hash of the concatenation of tag, username, and device tracking cookie if the cookie is reliable enough. `getUserDeviceSecret` can be gated on any facial recognition, MFA, or the Web Credential Management API to make use of hardware keys, authenticators, etc.

When the user creates a recovery tag, the application's `getUserDeviceSecret` is called with the same prompt identifier that had earlier been given to `create({prompt})`. The prompt is stored (unencrypted) with the resulting (encrypted) keys in the cloud. If the user later tries to (recursively) access the resulting recovery tag, the application's `getUserDeviceSecret(tag, prompt)` is called again, and result must be identical to what was returned when the recovery key was created.

It is recommended that the size of the string producted by getUserDeviceSecret should be between 16 and 128 characters.

`getUserDeviceSecret` can be used as a mechanism for additional distinctions. For example, suppose a group of cooperating applications want to be able to encrypt and verify a common set of tags among all uses of a shared module URL. (See [Library](#library), above.) But suppose further that, for whatever reason, they wanted each application to create a different application-specific device tag, such that no application could ask the user to sign or decrypt ultimately based solely on a different application's member device tag. In this case, an application could request an application-specific (and possibly user-specific) api-key from its own application-server, and use that api-key within the secret returned by `getUserDeviceSecret`. This would keep device keys from being used by other applications that shared the same vault. (However, it would not by itself prevent a user that has access to _both_ application's device keys from making a single "individual" key that has both application-specific keys as members. Preventing that would require additional mechanisms within the Storage API.)

## Conclusion

Let's look at how Distributed Security achieves each of the benefits listed in the introduction, above.


### Privacy

- No tracking by login or viewing of content, including private content.

The general idea of a login is to confirm _who_ you are at the beginning of your session, and then use that identity to track everything you do. A lifetime ago, logins were an easy solution to the problem of accounting for time spent on early expensive multi-user computers. The name comes from ancient ships' activity records that note the speed estimate given by the time spent watching a floating log pass down the known length of the side of a ship. Eventually, the ship owners wanted the captain to note everything that happened which might be important.

Once our activities are exposed, we don't know how that information will be used, and continue to be used. Some activity, such as looking at health information or products, can be markers for things that we do not understand ourselves, which can then be used to deny or cost us. Activity can be misconstrued, and it can be used to manipulate us by presenting us with tailored content or results that use our profiled succeptabilities against us (or against someone else by someone who pretends to know us). All without us being aware.

Even if a site or app does not itself sell your activity, the site may use an outside vendor for login or other services such as usage analytics. Such vendors often provide their software for free to developers, because the vendors make their money by selling your activity patterns to advertisers. Vendors can track your activity on one site, based on the site's use of a non-login service such as analytics, and then correlate that activity with your identify from the vendor's login service used on another site. The result is that the innocent reading you are doing in one place is then put into the model provided to people that neither you nor the site are aware of.

 We can do better now.

### Verifiable Receipts

- A receipt for activity that proves who authorized the activity (by pseudonym), and when.
- No passwords.
- No transaction costs.
- No browser extensions.

For important transactions, an application might display a text confirmation that the user can save as text or a picture. Of course, these can be edited. To examine the real record, the user and any other interested parties are dependent on the integrity of the company's records: that it was legitimately created, and not modified later by the company or a hacker, and indeed that the login hadn't been stolen in the first place. Examining the transaction also requires that the database is still running, and that the company lets you examine the record. This might be practical for a company in a well-regulated industry, but not for smaller companies, organizations, or individuals running their own software.

With cryptography, software can sign the transaction record with a key that only you have. You control access to your phone or computer, and the computer controls access to the key used for signing. The software can work in milliseconds without asking you anything, or it can be written to ask you for a PIN or some such - that's up to the application. Similarly, the application server can sign the same request to show that the transaction was indeed accepted by them.

Copies of this signed record can be copied out anywhere - even to paper - and anyone with the copy and appropriate software can verify that the specified transaction was indeed authorized by the specified tag. Signatures use standardized algorithms that can be verified by software that is different from the original software that created the signature.

Note that this record does not identify you by name or account number - just by tag. In some applications, it is not necessary to know _who_ entered into the transaction, but only that you can securly redeem the result by proving that you still control the same tag. You just sign a challenge later with the same tag. 

In other cases, it may be necessary for the site to recognize the tag in order to accept the transaction in the first place. There are two ways that the application might do this:

- One is to register your tag with the site when you sign up. In this case, the site can track your transactions with them, but no one else can. You don't have to log in to merely view the site, and you only get "tagged" when you make some transaction there. This kind of behavior can be used by any cryptography system, and it makes sense when the transaction requires delivering a specific thing to a specific identifiable human.
- In other cases, it is only necessary for the application to know that the user is authorized for the activity - such as entering a private chat room or building on some specific virtual land. For this, Distributed Security allows the application to make a team that has the permission, and to add the user's tag to that team. Thereafter, it only need keep track of the team tag, and it checks for permission by asking the user's software to sign a request with this team's tag.

Outside of distributed security, the [Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API) uses cryptographic verification to confirm your identity for login without passwords. In that approach, you register your tag with the provider, and on subsequent visits the software uses that tag to sign a login challenge and they verify the result. 

It's easy to see why avoiding passwords is popular. People either forget them, or use the same password everywhere such that a theft of passwords at one company makes acccess available to all sites, or they use paper, or get locked in to a password manager or identity vendor. All this without actually being sufficient to stop breaches. Many sites now use alternatives such as magic links sent to a user's email or phone number. These require giving up your email or phone, and they send users outside the app right at the moment the user is trying to get in. They also typically require third party services (for email or messaging) that bring in extra costs, complexity, and privacy issues. 

Cryptographic signature avoid all of this for login _identity_, but unlike Web Authentication, it also allows applications to do away with login altogether by instead signing for specific activity rather than signing _browser sessions_.

The self-contained receipt is one of the application areas of blockchain, but blockchain comes with other baggage that isn't necessary for receipts by themselves. First, the algorithms used in popular blockchains are not supported in browsers. These only works in connection with either installed applications (rather than Web pages), browser extensions (which have access to your browsing activity), or "trusted" conventional Web sites that conduct your activity for you, using their own sets of conventional records. Additionally, signed receipts are not the primary purpose of blockchains, but merely one side-effect of their approach to distributed ledgers. Another side-effect of their approach to ledgers is that they _must_ charge a transaction fee to create a new entry, or else their whole model of how ledgers are reconciled falls apart. These fees are typicaly much too high for frequent everyday activity.  Distributed Security doesn't make use of these ledger-related activities, and makes provable receipts available to all browser software, for free.

### A Better Cloud

- No theft of private content, nor risk to cloud providers that they will be forced to turn over content by threat of violence or legal action.
- Faster cloud data access.
- No centralized authority.

It really isn't a good idea to store private content on a server and gating access to that server with a login. In such cases, the people operating the server have access to the content, and users are relying on the server operators to gate access properly. 
This creates a problem for the server operators as well, as it makes them a target for theft, and for violent criminals or law enforcement to compell them to provide the content. It is much better for everyone if the creator encrypts the content on their own machine, and that it stay encrypted and unreadable through transmission and at rest on the servers, and only be decrypted by the intended audience within the authorized user's browser.

Cloud access can also be faster overall when using encryption. With private content being encrypted, there is no need to check for read permission. In modern infrastructure, lookups of user permissions takes more time for database lookup than does on-the-fly decryption at the browser. The absence of an authorization step or authorization state allows a lot of implementation flexibility in the serving of the data, including caching at server, network edge, and client.

Similarly, on-the-fly verfication of self-contained signed requests or transactions is faster when there is no account lookup. Indeed, many sites are now using a signed token - e.g., a so-called [JWT](https://jwt.io/) - as a means of conveying self-contained, stateless authority. However, many sites use this to convey identity, and still need to separately lookup the signed user id to check specific authorizations! A better approach with Distributed Security is to convey each kind of authorization with it's own well-known tag, and add the user's tag as a member to this authorized team. The runtime "lookup" for membership is then done by the client when the Distributed Security vault gets access to the team key. The server needs only to verify the signature and compare test tag string against one known at startup.

There is no fixed limit to the number of members on a team. Changing team membership doesn't happen nearly as often other activities, but when it does happen, the time is proportional to the number of members. If this is a problem, large teams can be composed in a tree of teams, each with a manageable size. Checking a signature still takes just one computation for the well-known key at the top of the tree, and the client's own latency to decrypt the root key is logarithmic - proportional to the depth of the tree. (The tests of ownership of each member happens in parallel.)

Applications can allow clients to create new tags on their own, without going through any central bottleneck, as there is usually no need to record new tags in a database. The storage of encrypted keys can be a completely different service from where the main application business logic is run.