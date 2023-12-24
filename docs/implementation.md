# Distributed System Implementation

The source code is made to express a set of stepwise concepts in short separate pieces. This guide to the source code assumes the background knowledge of [README.md](../README.md).

## Wrapping SubtleKrypto

[krypto.mjs](../lib/krypto.mjs) is by far the longest, but it is mostly just a wrapper around SubtleCrypto:

1. SubtleCrypto provides functions for each of the four basic operations, plus [export](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/exportKey)/[import](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey) and [wrap](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/wrapKey)/[unwrap](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/unwrapKey) of keys, all taking a key object, a binary buffer, and various parameters. The methods in our Krypto module also take a key as argument, but they work on strings rather than buffers, and the other parameters are hardcoded to use particular algorithms. (For sign/verify, it uses the same ECDSA algorithm and parameters as blockchains.)
2. Not mentioned in the README.md, is that in addition to encrypt/decrypt using a public/private keypair, SubtleCrypto can use a particular type of single key called a symmetric key for both the encrypt and decrypt operations. This isn't terribly useful at the application level because both sides must have a copy of the same key, which isn't very safe. However, we do use it in a very specific way _internally_, as will be shown below. However, SubtleCrypto splits symmetric keys into two parts: a secret and buffer of random bits called an iv. Krypto combines both parts into a single key object.

The reason that SubtleCrypto separates the parts of a symmetric key is that the secret part can be used over an over again, while the iv can only safely be used for one encrypt/decrypt cycle. However, in Distributed Security, symmetric keys are only ever used for one cycle, and it is much easier to manage this when the secret and iv are packaged together. There is some extra code (_**TBD**_: do this!) in krypto to ensure that a symmetric key is only ever used through one encrypt/decrypt cylce, even through export/import. 


## Combining Keys

[multiKrypto.mjs](../lib/multiKrypto.mjs) extends [Krypto](#wrapping-subtlekrypto) in three ways:

### 1. Hybrid encryption to provide longer encrypted messages
The algorithm used by Krypto can only encrypt messages up to 446 bytes. MultiKrypto uses a _hybrid_ technique, such that any request to encrypt with a public key, will instead generate a new symmetric key to encrypt the arbitrarilly sized message, and then use the public key to encrypt the symmetric key itself, and include both in the output. Decryption with a public key is the reverse.  The encryption looks like this (without any newlines):

```
[684 bytes of a symmetric key encrypted by the given public key]
. (a dot character)
[the message encrypted by the symmetric key]
```
(Encryption in Distributed Security is base64 encoded, which does not include the dot character.)

The maximum memory size is not limited by the algorithm this way, but only by available memory. We unit-test with 10 MB messages.

### 2. Sets of Keys
From an application standpoint, a [tag](../README.md#operations-and-tags) represents _the key_. But in fact, SubtleCrypto does not let you use the same keypair for encrypt/decrypt as for sign/verify. So Distributed Security must manage a _set_ of keys under a single tag. MultiKrypto allows a set of keys to be exported and imported as JSON. For example, a keyset of 

```
{myDecryptingKey: [a private RSA algorithm key], 
 mySigningKey: [a private ECDSA algorithm key]}
```
is exported by MultiKrypto as:

```
{"myDecryptingKey": "[about 3168 bytes of exported private RSA algorithm key]",
 "mySigningKey": "[248 btyes of exported private ECDSA algorithm key]"}
```
When importing a key SubtleKrypto requires that we specify what the imported key will be used for: `'decrypt'`, `'sign'`, etc. MultiKrypt also need to specify the usage for each of the JSON property names in the export:`importKey(exportedJSON, {myDecryptingKey: 'decrypt', mySigningKey: 'sign'}`.


### 3. Encrypting for Members
Crypto systems regularly use the same keypair to directly represent an _identity_ such as a user or a role within an organization, regardless of what machine was used or who in that role used it. This requires the unencrypted key to be stored in multiple places for use and to guard against loss, which then of course presents opportunities for the keys to be co-opted. 

Distributed Security takes a different approach, in which a key set is only ever seen _encrypted_. It is encrypted in such a way that it can be read by any of the entity's constituent members, _proven by their own keypairs_. This is done by in MultiCrypto by extending the above hybrid encryption with sets of member keys.

In cryptography generally, a key is "wrapped" by exporting it and then encrypting the result. Conceptually, we wrap a team key by encrypting N copies of it in the same wrapped result -- one copy for each team member. (Recall that every key set is represented by a tag string, and that the public encrypting key from each set is available to all.) Conceptually, this looks like:

```
[tag of member 1] [team key wrapped with first member's public key]
[tag of member 2] [team key wrapped with second member's public key]
...
[tag of member N] [team key wrapped with Nth member's public key]
```
This result is then publically stored. To gain access to the team key, a member obtains this wrapped team key, finds the wrapping labelled by their own tag, and unwrap just that copy using their own private decrypting key.

In fact, though, encrypting with public keys is very verbose, and _each_ `[team key wrapped with Nth members public key]` would be more than 5k bytes. Instead, we use a multiple decrypting key version of hybrid encryption, such that we generate a symmetric key, use that to wrap the team key, and then encrypt just the symmetric key N times:

```
{"body": "[team key wrapped with a one-time-use symmetric key]",
 "roster": {
   "[tag of member 1]": "[symmetric key wrapped with first member's public key]",
   "[tag of member 2]": "[symmetric key wrapped with second member's public key]"
   ...
   "[tag of member N]": "[symmetric key wrapped with Nth member's public key]"
  }
}
```

This is roughly the same total size for one member, and about 4.5 kbytes less for each additional member.


## Vaults: Object-Oriented Keys

In [vault.mjs](../lib/vault.mjs), we define objects that manage each individual identity.

The vault keeps the private signing key and the private encrypting key.

The vault's public *encrypting* key is exported and stored in clear text in the public storage provided by the application. This allows users of the application to encrypt a message that can only be read by the corresponding vault.

The vault's public *signing* key is exported and used as the tag. For example, if you have a message, a tag, and a signature, any software has everything it needs to verify the message, without needing to access any application resources or anything else.

Thus copies of mesages can be verified forever, even if the application is no longer providing access to storage, but new message can only be encrypted for application tags as long as the application is still providing storage. Of course, storage may be third-party storage or a p2p file sharing network.

Of the seven operations provided by [security.mjs](../lib/security.mjs), `create`, `encrypt`, and `verify` can all be done without needing to create a vault. However, `destroy`, `changeMembership`, `decrypt`, and `sign` all need to `ensure` a vault corresponding to the given tag. To do so, `ensure` either has one cached for the given key or creates one. It then verifies that the vault is still good:

- If the tag corresponds to the device the software is running on, there will be a locally stored key that never leaves the device. (There is no reason to export it elsewhere.) The stored key is then used directly, and the vault is ready.
- Otherwise, if there is an encrypted team key in public storage for this tag, it is retrieve and Security will attempt to unwrap it using by checking to see if this computer has access to any of the specified members, recursively applying this whole search down to finding either this device or failing.
- Finally, a team may specify a "recovery member", that is itself a team of security questions. Each question is the tag, and the unwrapping key is a secret derived from the answer to the question. (Details are _**TBD**_.) As with any other team key data, neither the application nor the authors of Distributed Security can decrypt a recover team key. (Recovery teams can be constructed in a number of ways. This description covers the "answer 1 of N questions" case. Recovery team can also be created as, e.g., "answer q of N" by storing each of the possible _q-tupples_ of questions as tags, and the corresponding answers as secrets.)

This search for valid keys is repeated for each new operation, because an individual may lose their membership in a team at any time. Thus each operation involves a number of round trips corresponding to the depth of membership in the team, which is rarely more than a few levels. (The fan out or "breadth" of a team having multiple members increases the traffic because the stored encrypted team keys are larger with more members, but the latency of access is only related to the depth of the teams because each member at the same level of a team is verified in parallel.)

## Web Worker and IFrame.

Everyone has access to the encrypted team keys, but no one can decrypt it other than its members. We also want to make sure that application software itself cannot read the decrypted key. (Its not just a matter of trusting the intent of the application, but also that the application has not been compromised.) To do this, the [vaults](#vaults-object-oriented-keys) do not run in the same environment as the application, but in a separate sandbox called a [Web Worker](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API). Communication between the application and the worker is by means of messages defined by the worker, and we do not define any messages that export unencrypted keys. While desktop browser extensions generally have unfettered access to the application code and data, they do not have access to the worker data. The same is true for any malevolent code that has wormed its way into the application from dependendencies or other attacks. However, desktop users must still be vigilant to not be dupped into using various developer tools by which some browser-makers expose worker data to interactive inspection.

This is implemented by [worker.mjs](../lib/worker.mjs).

But all of this is only safe to the extent that device keys are safe. These use the browser's persistent storage, and are therefore accessible to an application running at the same origin as the worker. Browsers require workers to be in the same domain as their page, so we run the worker from a new page in an iframe. This iframe (in [vault.hml](vault.html)) can and should be in a different domain, so that the application cannot read the data that the worker stores.

The iframe is dynamically created by [index.mjs](../lib/index.mjs).

The communication between index.mjs and the vault.html iframe, and between vault.html and worker.mjs, are provided by postMessage/message carrying jsonrpc, using [@kilroy-code/jsonrpc](../../jsonrpc).
