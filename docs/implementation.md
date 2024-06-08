# Distributed-Security Implementation

The source code is made to express a set of stepwise concepts in short separate pieces. This guide to the source code assumes the background knowledge of [README.md](../README.md) and [risks.md](risks.md).

Please also see [Distributed-Security in JOSE Technical Terms](in-jose-terms.md).

## Wrapping SubtleKrypto

[krypto.mjs](../lib/krypto.mjs) is a wrapper around JOSE compact serializations, or effectively a wrapper around SubtleCrypto:

### Handling inputs

SubtleCrypto provides functions for each of the four basic operations, plus [export](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/exportKey)/[import](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey) and [wrap](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/wrapKey)/[unwrap](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/unwrapKey) of keys, all taking a key object, a binary buffer, and various parameters. The methods in our Krypto module also take a key as argument, but they work on strings or objects rather than only binary buffers, and the other parameters are hardcoded to use particular algorithms.

### Symmetric Keys

Not mentioned in the README.md, is that in addition to encrypt/decrypt using a public/private keypair, SubtleCrypto can use a particular type of single key called a symmetric key for both the encrypt and decrypt operations. This isn't terribly useful at the application level because both sides must have a copy of the same key, which isn't very safe. However, we do use it in a very specific way _internally_, as will be shown below.

### Hybrid Encryption

The asymmetric algorithm used by Krypto can only encrypt messages up to 446 bytes. JOSE and Krypto uses a _hybrid_ technique, such that any request to encrypt with a public key, will instead generate a new symmetric key to encrypt the arbitrarilly sized message, and then use the public key to encrypt the symmetric key itself, and include both in the output. Decryption with a public key is the reverse.  Part of the encryption looks roughly like this (without any newlines):

```
[less than 1k bytes of a symmetric key encrypted by the given public key]
. (a separator character)
[the message encrypted by the one-time-use symmetric key]
```
(Encryption in Distributed-Security is base64 encoded, which does not include the separator character.)

The maximum result size is not limited by the algorithm this way, but only by available memory. We unit-test with 10 MB messages.

## Combining Keys

[multiKrypto.mjs](../lib/multiKrypto.mjs) is a wrapper around JOSE general serializations, extending [Krypto](#wrapping-subtlekrypto) in three ways:

### Sets of Keys
From an application standpoint, a [tag](../README.md#operations-and-tags) represents "the key". But in fact, SubtleCrypto does not let you use the same keypair for encrypt/decrypt as for sign/verify. So Distributed-Security must manage a _set_ of keys under a single tag. MultiKrypto allows a set of keys to be exported and imported as JSON. For example, a keyset of 

```
{myDecryptingKey: [a private RSA key], 
 mySigningKey: [a private ECDSA key]}
```
is exported by MultiKrypto as, effectively:

```
{"myDecryptingKey": "[about 3k bytes of exported private RSA key]",
 "mySigningKey": "[a couple hundred btyes of exported private ECDSA key]"}
```

### Encrypting for Members

Cryptographic systems regularly use the same keypair to directly represent an _identity_ such as a user or a role within an organization, regardless of what machine was used or who in that role used it. This requires the unencrypted key to be stored in multiple places for end-to-end encryption use at those machines, and to guard against loss, which if simply copied would then of course would present opportunities for the keys to be co-opted. 

Distributed-Security takes a different approach, in which a key set is only ever externally seen _encrypted_. It is encrypted in such a way that it can be read by any of the entity's constituent members, _proven by their own keypairs_. This is done in MultiKrypto by extending the above [hybrid encryption](#hybrid-encryption) with sets of member keys.

In cryptography generally, a key is "wrapped" by exporting it and then encrypting the result. Conceptually, we wrap a team key by encrypting N copies of it in the same wrapped result -- one copy for each team member. (Recall that every key set is represented by a tag string, and that the public encrypting key from each set is available to all.) Conceptually, this looks like:

```
[tag of member 1] [team key wrapped with first member's public key]
[tag of member 2] [team key wrapped with second member's public key]
...
[tag of member N] [team key wrapped with Nth member's public key]
```
This result is then publically stored. To gain access to the team key, a member obtains this wrapped team key, finds the wrapping labelled by their own tag, and unwraps just that copy using their own private decrypting key.

In fact, though, encrypting with public keys is very verbose, and _each_ `[team key wrapped with Nth members public key]` would be more than 5k bytes. Instead, we use a multiple decrypting key version of hybrid encryption, such that we generate a symmetric key, use that to wrap the team key, and then encrypt just the symmetric key N times:

```
{recipients: [
  {encrypted_key: [less than 1k bytes of a symmetric key encrypted by member 1 public key],
   header: {...[tag of member 1]...}},
  {encrypted_key: [less than 1k bytes of a symmetric key encrypted by member 2 public key],
   header: {...[tag of member 2]...}},
  ...
  {encrypted_key: [less than 1k bytes of a symmetric key encrypted by member N public key],
   header: {...[tag of member N]...}}
], ciphertext: [team key encrypted by the one-time-use symmetric key]}
```

This is roughly the same total size for one member, and each additional member adds about 4.5 kbytes less than the conceptual version above.

### Signing and Verifying with Members

Krypto and JOSE compact formats can make signatures with a single key. MultiKrypto uses JOSE general format to provide the option to sign with mutiple keys. (We use this to sign by a team and a member of the team.) Verfication provides enough information that one can see which of the signatures were verfied by the supplied keys.

## Inside The Vault

In [keySet.mjs](../lib/keySet.mjs), we define objects that manage each individual identity, using multiKrypto.

The KeySet keeps the private signing key and the private encrypting key.

The KeySet's public *encrypting* key is exported and stored in clear text in the public storage provided by the application. This allows users of the application to encrypt a message that can only be read by the corresponding KeySet. (This is subtle: to change the membership of a team, the team will be re-encrypted in the vault running on the machine of the user making the change. That vault will need the public encrypting key of each member -- it's a good thing that they are public and that other member's private keys are not necessary to do the encryption!)

The KeySet's public *signing* key is exported and used as the tag. For example, if you have a tag and a signature, any software has everything it needs to verify the message, without needing to access any application resources or anything else. Our signatures include the tag within the signature. (This is subtle, too: when the vault pulls down data from the cloud, the data is wrapped in a signature which the vault verifies before it uses it. Fortunately, the public verification key is not itself in the cloud, and is derived directly from the tag, so there's no additional cloud message involved.)

Thus copies of messages can be verified forever, even if the application is no longer providing access to storage, but new message can only be encrypted for application tags as long as the application is still providing storage. Of course, storage may be third-party storage or a p2p file sharing network.

Of the seven operations provided by [api.mjs](../lib/api.mjs), `create`, `encrypt`, and `verify` can all be done without needing to create a KeySet. However, `destroy`, `changeMembership`, `decrypt`, and `sign` all need to `ensure` a KeySet corresponding to the given tag. To do so, `ensure` either has one cached for the given key or creates one. It then verifies that the KeySet is still good:

- If the tag corresponds to the device the software is running on, there will be a locally stored multiKey that never leaves the device. (There is no reason to export it elsewhere.) The stored multiKey is then used directly, and the KeySet is ready.
- Otherwise, if there is an encrypted team multiKey in public storage for this tag, it is retrieved and Security will attempt to unwrap it by checking to see if this computer has access to any of the specified members, recursively applying this whole search down to finding either this device or failing.
- Finally, a team may specify a "recovery member". The question (or an indicator of the question) is stored (unencrypted) with the (encrypted) multiKey in the cloud, and the symmetric encrypt/decrypt key is dervied from the _answer_ to the question.  As with any other team key data, neither the application nor the authors of Distributed-Security can decrypt a recovery key. 

This search for valid keys is repeated for each new operation, because an individual may lose their membership in a team at any time. Thus each operation can involve a number of round trips corresponding to the depth of membership in the team, which is rarely more than a few levels. In fact, it is less, because of caching. (The fan out or "breadth" of a team having multiple members increases the traffic because the stored encrypted team keys are larger with more members, but the latency of access is only related to the depth of the teams because each member at the same level of a team is verified in parallel.)

There is also code here that handles deep auditable validation. A user can sign for a team and cosign as the specific member of the team. During verification, both are verified, and additionally, we (optionally) check that the member is still on the team at the time of verification. Additionally, we optionally check that signature is not made before a given time, such as the time that the team was last created. We use this internally to protect the cloud storage of wrapped keys. The code is somewhat complicated by the need to bootstrap the signing for the first version of the wrapped keys.

## Creating The Vault: Web Worker and IFrame

Everyone has access to the encrypted team keys, but no one can decrypt it other than its members. We also want to make sure that application software itself cannot read the decrypted key. (Its not just a matter of trusting the intent of the application, but also that the application has not been compromised.) To do this, the KeySets do not run in the same environment as the application, but in a separate sandbox called a [Web Worker](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API). Communication between the application and the worker is by means of messages defined by the worker, and we do not define any messages that export unencrypted keys. While desktop browser extensions generally have unfettered access to the application code and data, they do not have access to the worker data. The same is true for any malevolent code that has wormed its way into the application from dependendencies or other attacks. However, desktop users must still be vigilant to not be dupped into using various developer tools by which some browser-makers expose worker data to interactive inspection.

This is implemented by [worker.mjs](../lib/worker.mjs).

But all of this is only safe to the extent that device keys are safe. These use the browser's persistent storage, and are therefore accessible to an application running at the same origin as the worker. Browsers require workers to be in the same origin as their page, so we run the worker from a new page in an iframe. This iframe (in [vault.hml](vault.html)) should be in a different orogin from the application, so that the application cannot read the data that the worker stores.

The iframe is dynamically created by [index.mjs](../lib/index.mjs).

The communication between index.mjs and the vault.html iframe, and between vault.html and worker.mjs, are provided by postMessage carrying jsonrpc, using [@kilroy/jsonrpc](../../jsonrpc).

## Building and the Runtime Environment.

When running in NodeJS, an application just references the distributed-security package, and the package.json tells node the correct entry point. (This entry point is directly to the api.mjs and the KeySets. The dynamic iframe and Web worker is not involved.)

However, for a number of reasons, there is more involved on the Web:

- Browsers do not read package.json files, and cannot know where dependencies are located. (NodeJS packages search through a portion of the file system, but a browser `fetch` does not search the server.)
- A small portion of distributed-security, and a portion of the JOSE dependency, is specific to either NodeJS or browser environments. Distributed-security puts such dependencies in separate files, and uses package.json ["subpath imports"](https://nodejs.org/docs/latest/api/packages.html#subpath-imports) to distinguish between the two.
- Distributed-security and its dependencies is not large, but applications load faster if this can be compacted into fewer, smaller files. 

We accomplish this through a combination of the [package.json](../package.json) definitions and [Rollup](https://rollupjs.org/). The latter is configured in [rollup.config.mjs](../rollup.config.mjs).
