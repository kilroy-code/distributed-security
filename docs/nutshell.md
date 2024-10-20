# Distributed Security, in a Nutshell

0. [Distributed Security](../README.md) is a Javascript [NPM package](../README.md#library-installation-and-declaration) that runs in any [modern browser](https://www.techopedia.com/definition/31094/evergreen-browser) and in [NodeJS](https://nodejs.org/).

This is how we achieve each of three unique capabilities:
- Recoverable, Non-Custodial Keys
- Private Data for Self-Managed Groups
- Cross-Institutional Authority

## Recoverable, Non-Custodial Keys

1. Every keypair is stored in the cloud where it is available to every device. But private keys are encrypted in a [clever](implementation.md#encrypting-for-members) but [IETF-standard](https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.4) way, that allows any of an enumerated set of _other_ keys to decrypt it.
2. Every individual keypair has N member keys. These are the keypairs that are used to encrypt it, and any _one_ of them can decrypt it. These member keypairs can be:
   - A "device" keypair that lives only in a [secure software vault](implementation.md#creating-the-vault-web-worker-and-iframe) on the machine on which it is created, and its private key never leaves that machine.
   - A "recovery" keypair that is securely regenerated on-the-fly from a password or passphrase known only by the user.

Thus an individual's keypair can be downloaded from the cloud and decrypted on any of the user's devices, or from any device using their recovery passphrase.

_No one else can decyrpt it -- not even the people who operate the cloud._

3. As with all [public-key cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography), a keypair has a public part and a private part:
   - The private part of the key-pair (used to decrypt) is what we encrypt and place in the cloud. The member key identifiers are listed in the data (per [standard](https://github.com/kilroy-code/distributed-security/blob/main/docs/in-jose-terms.md) for multi-key encryption).
   - The public part is _not_ encrypted, and placed directly in the cloud, and can be looked up by key identifier.
   
4. To [add or remove devices or passphrases](../README.md#creating-tags-and-changing-membership), the software:
   - downloads and decrypts their private key to any of their devices (or to any device using their recovery passphrase);
   - adds or removes a key identifier from the ones listed;
   - _re-encrypts_ using the public key for each of the new members.

This happens without the cloud host or anyone else being able to see the unencrypted key.

## Private Data for Self-Managed Groups

5. Instead of trusting a server to keep data private, data can be [encrypted at the client for a given key identifier](../README.md#basic-encryption), stored encrypted in the cloud, and decrypted only by the owner of the designated keypair. Neither the cloud operator nor anyone who breaks in can read the data. (This also means that the encrypted private data store can be freely replicated. Additionally, there is no need for login to check for read permissions, which means that a Content Distribution Network does not need any knowledge of users or permissions, even for private data.)

6. A "team" keypair can be created whose members are other individuals or even other teams. (A team keypair is no different from an individual keypair. We're just using the term "team" to emphasize that the members are other cloud-stored keypairs rather than device-bound or passphrase-driven members.)

When content is encrypted for a team, the membership of the team can be changed and there is no need to re-encrypt the content, because the team's encrypting key-pair itself has not changed.

Thus several institutions can manage their own teams and teams-of-teams, while sharing a cloud and private data with other institutions. There is no need to redistribute public keys when membership changes, because the stable public _team_ key is the one that is used to encrypt content for the team. To repeat: _An institution can create a team and only has to share the identifier string with a second institution once. Any changes to membership at the institution do not effect the decryption process or material at the second institution._

(In this example, any member can change the membership. Of course, the app or cloud can check authority as described next.)

## Cross-Institutional Authority

7. Per standards, each tag internally has a public/private key-pair _for encryption/decryption_, and a _separate_ public/private key-pair for _signature/verification_. The private _keyset_ in the cloud multi-encrypts _both_ private keys.

8. The exported public verification key is used directly as the key identifer, so that signatures are completely self-contained and there is no need to look up a public _verification_ key in the cloud. The key identifier is an ordinary string that can be publicly shared.

Any recursive member of the team can sign a request or transaction, and the other institution can verify the signature for the expected key identifier. The first institution does not have to update the second with new membership lists as membership changes. _The institution can manage its own internal employee / actor cryptographic operations without involving the second institution (and visa versa)._

9. A signature can be made that non-repudiably identifies not only the team, but the individual member of the team that is doing the signing. (There is a [standard](https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.1).) Verification checks both signatures, and optionally confirms that the individual is in-fact a member of the team at the time of verification. (Recall that the member tags are in plain-text of the cloud-stored keys.)

This means that, e.g., the individual member's institution can track the specific member who authorized the request, while another institution can check the overall authorization without knowing the specific membership. The two institutions don't even have to use the same cloud.

10. In addition to signing requests and transactions, content can be dual-signed this way (whether encrypted or not). The entire signed payload is stored, providing a self-contained, tamper-evident package that identifies both the owning team and the individual member that stored this version of the content. When a signed payload is to be stored, the storage system only needs to fully verify the signature and check that the key identifiers are what is expected (e.g., minimally that is team is the same as the one previously stored).

This is how Distributed Security itself operates when storing keys in the cloud.

Organizational teams may be automatically produced and maintained from external directory systems. However, the cryptography directly enforces cross-institutional authorization and privacy without relying on sharing or agreement of such external directory systems between institutions.
