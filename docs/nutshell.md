# Distributed Security, in a Nutshell

0. [Distributed Security](../README.md) is a Javascript [NPM package](../README.md#library-installation-and-declaration) that runs in any [modern browser](https://www.techopedia.com/definition/31094/evergreen-browser) and in [NodeJS](https://nodejs.org/).

This is how we achieve each of three unique capabilities:

## Recoverable, Non-Custodial Keys

1. Every key is stored in the cloud where it is available to every device. But it is encrypted in a [clever](implementation.md#encrypting-for-members) but [IETF-standard](https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.4) way, that allows any of an enumerated set of _other_ keys to decrypt it.
2. Every individual key has N member keys. These are the keys that are used to encrypt it, and any _one_ of them can decrypt it. These member keys can be:
   - A "device" key that lives only in a [secure software vault](mplementation.md#creating-the-vault-web-worker-and-iframe) on the machine on which it is created, and it never leaves that machine.
   - A "recovery" key that is securely regenerated on-the-fly from a password or passphrase known only by the user.

Thus an individual's key can be downloaded from the cloud and decrypted on any of the user's devices, or from any device using their recovery passphrase.

No one else can decyrpt it -- not even the people who operate the cloud.

3. As with all [public-key cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography), a key has a public part and a private part. The public part is what is used to encrypt a message so that only the private part can decrypt it.
4. Each key has a "tag" string that uniquely identifies it:
   - The private parts of the two key-pairs are what we encrypt and place in the cloud, identified by tag.
   - The public part is _not_ encrypted, and placed directly in the cloud, identified by tag.
   - When we encrypt a key for it's member keys, we list the tag of each member in plain text. (This is [part](https://github.com/kilroy-code/distributed-security/blob/main/docs/in-jose-terms.md) of the IETF-standard for multi-key encryption.)
   
Thus any member can decrypt their cloud-encrypted key, and can _re-encrypt_ for each of the specified member tags. This allows a member to [add or remove devices or recovery passphrases](../README.md#creating-tags-and-changing-membership) -- without the cloud host or anyone else being able to see the unencrypted key.

An app can make the recovery passphrase acceptance be dependent on harware such as a fingerprint or facial recognition or an authenticator, but there's no inherent dependency on key fobs or built-in trusted hardware.

## Private Data for Self-Managed Groups

5. Instead of trusting a server to keep data private, data is [encrypted at the client for a given tag](../README.md#basic-encryption), stored encrypted in the cloud, and decrypted only by the owner of the designated tag. Neither the cloud operator nor anyone who breaks in can read the data. (Additionally, there is no need for login or any access control lists to check for read permissions, which means that a Content Distribution Network does not need any knowledge of users or permissions, even for private data.)

6. A "team" tag can be created whose members are other indviduals or even other teams. (A team tag is no different from an individual tag. We're just using the term "team" to emphasize that the members are other cloud-stored tags rather than device-bound or passphrase-driven members.)

When content is encrypted for a team, the membership of the team can be changed by the members themselves. There is no need to re-encrypt the content because the team-tag's encrypting key-pair itself has not changed. 

Thus several institutions can manage their own teams and teams-of-teams, while sharing a cloud and private data with other institutions.

## Cross-Institutional Authority

7. Per standards, each tag internally has a public/private key-pair _for encryption/decryption_, and a _separate_ public/private key-pair for _signature/verification_. The private key in the cloud multi-encrypts _both_ private keys. 

8. The exported public verification key is used directly as the tag, so that signatures (which contain the tag) are completely self-contained and there is no need to look up the public verification key in the cloud. The tag is an ordinary string that can be publicly shared.

Thus an institution can create a team and share the tag string with a second institution just once. Any recursive member of the team can sign a request or transaction, and the other institution can verify the signature for the expected tag. The first institution does not have to update the second with new tags or new access control lists as membership changes.

9. A signature can be made that non-repudiably identifies not only the team, but the individual member of the team. (There is a [standard](https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.1).) Verification checks both signatures, and optionally confirms that the individual is in-fact a member of the team at the time of verification. (Recall that the member tags are in plain-text of the cloud-stored keys.)

This means that, e.g., the individual member's institution can track the specific member who authorized the request, while another insitution can check the overall authorization without knowing the specific membership. The two institutions don't even have to use the same cloud.

10. Instead of separate access control lists, signed documents (whether encrypted or not) contain their own authorization by being dual-signed in this way. The entire signed payload is stored, providing a self-contained, tamper-evident, attributed package. When a signed payload is to be stored, the the storage system only needs to fully verify the signature and check that the team is the same team tag that was previously stored.

This is how Distributed Security itself operates when storing keys in the cloud.

Organizational teams may be automatically produced and maintained from external directory systems. However, the cryptography directly enforcely cross-institutional authorization and privacy without relying on sharing or agreement of such external directory systems.
