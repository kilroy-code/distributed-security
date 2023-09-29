# Distributed Security


## User Benefits:

* No logins, but secured by browsers and their hardware.
* Any private information is readable ONLY be the information's owners, and not by any service provider or other party. There are no back doors.
* Users create their own teams of users, manged by the rules of their application, and not by the distributed security software nor the domain service that uses it.
* Every file, version, transaction, receipt or other result in an application can automatically have a signature (without the user taking additional action), that provides stand-alone and non-repudiable proof of:
	* who committed or authorized the result
	* when
	* what team they were acting for
	* that the result was not altered after the result was committed and stored.
* Applications can make that signature available as a securely copyable artifact, that can then be verified by any party independently of any service provider or application.


## Developer Benefits:
* It works.
* It is simple, both to use, and to understand the concepts.
* Encapsulates the various browser APIs so that application programmers can just concentrate on the application-level security concepts.
* Opportunities for broad service providers that support a support an ecosystem of third-party applications in which usera have a consistent identity across the service.
* Opportunities for storage providers and other low-level services for applications and services.

## Overview:

The various actors in the system self-organize into arbitrary teams, consisting at any given time of one or more immediate members (which may be other teams).

Every actor in the system is identified by a public key, and the private key never leaves it's software vault.

Every application action that needs to be persisted has a team that owns it, and a member that triggered the action. The result is saved as a self-contained artifact:

*   The artifact is signed by the submitter, non-redupudiably identifying the submitter's public key.
*   The artifact is signed by the owner, non-repudiably identifying the owner's public key, and that the submitter was a direct member at the time of submission.
*   The signatures verify the integrity of the saved object since the time of submission.
*   The artifact can be private, accomplished by encrypting it in way that all and only the members at the time of submission can read it.

The application's own software controls read and write access to the artifacts, but in all cases only the members of the owning team can decrypt any encrypted content. For example, in ki1r0y, the machine on which the content is saved will verify the signatures, check that the submitter is the owner or a member of the owning team, and if content already exists under this name, ki1r0y will make sure that the submitted owner is the same pubkey as the owner of the content being replaced under that name. Ki1r0y then adds its own signature to the artifact, including a timestamp. The resulting signatures and artifact - still encrypted if the submitter encrypted it - is then available for anyone to read.



## Definitions:

distributed security - a set of software tools that allows keypairs on separate devices to be organized into a new keypair. It provides an API of operations for use by a service provider.

keypair - an entity in the distributed security system, and may represent a device, a human or other indvidual "user" that has access to one or more devices, or nested collection of individuals and other teams.

service provider - the browser software that uses the distributed security api. Typically, these are different domains such as ki1r0y.com that host their set of pages whose browser-side Javascript incorporates the distributed security software. Each keypair is unique to the each service that uses it, and are not reused by other services. However, a service might provide a large set of cooperating applications that do use the same keypairs among the different applications.

operation - the basic operations supported by all levels of distributed security - encrypt, decrypt, sign, and validate. Note that there is no operation to create or copy a keypair. The distributed security browser software creates keypairs as needed, interacting with the browser's hardware, and never "exports" a private key.

application - software that does something useful or interesting for the user. A service provides one or more applications.

payload - a text string provided for an operation. The distributed security software does not specify the format of application payloads. However, the distributed security software does define internal payloads for its own use, that are also visible and available to applications through the storage provider.

payload name - a string naming a payload by which it can be retrieved from the storage provider service. It is up to the application to determine how applications payloads are named. 

private data - Any payload that is encrypted for a specifed keypair. The keypair is denoted by the public key of the pair, and only the corresponding private key can decode it.

team - a keypair for which N other keypairs are authorized for writing and, for private data, decrypting. For example, a human identity can be a keypair who uses N different devices, each with their own individual keypairs. Thus a human is a "team of devices." A family or workgroup can be a keypair that has N different human members, and thus a family or workgroup is a team.  Every stored resource is owned by a team, designated by the team's public key.

storage provider - an API for reading and writing signed payloads (whether encrypted or not). Applications must provide an implementation of storage that meets the API, as the distributed security software itself does not provide an implementation. In addition to meeting the stored property requirements of the distributed security software, applications may have their own further requirements for the storage provider, as to, e.g., durability, availability, latency, access control if any, and time service.

stored properties - metadata that are written and read by the storage provider in addition to the payload. Every resource has an owner keypair that must be a team, and an author keypair that must be a member of the owning team. When a payload is written to a storage provider, it is presented with an owner public key and the extended payload is then signed 

A request to store a resource must be signed: the storage provider must validate the signature, and must save the signature with the resource and make it available to readers of the resource. This accomplishes three things:
1. The resource is owned by the entity identified by the public key in the signature. Validating the signature ensures that the requestor has permission to write. (This can matter if the storage provider charges for storage, as the request is a non-repudiable identification of an account. It can also matter for mutable resources, which can be written several times with different payloads under the same payload name, and thus an application would want to make sure that the data is only changed by the owner. For the case of multiple authorized writers, see "team", below.)
2. For private data, the payload is encrypted by the owner before transit and storage. The storage provider never sees the unencrypted payload. 
- Readers may validate the signature on their own, without additional services from anyone, thus validating that the data has not been tampered with since signing. This allows data to be stored "in the open", either on the servers of a commerical storage provider or in a p2p distributed file system - because the resources are always signed by the keypair that requests the storage, and thus the integrity of the retrieved data can be verified with the validate operation. Additionally, if the data is private, it is encrypted so that it can only be read by the keypair that requested the storage. However, 

time service - the time stamp of a signature represents the universal time on the device that produced the signature. Of course, this is not good enough for comparisons between signatures. However, a storage provider can be designed to provide a second signature for the payload, by which the storage provider is providing an ordering of storage requests and a timestamp of some given accuracy for the storage requests.



hardware vault - a keypair on a phone or key fob that provides an API for the operations (encrypt/decrypt/sign/validate) such that the private key is stored in harware and is not available to any software outside the vault. (The distributed security sofware uses this API, which is documented at https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API.) Using a hardware valult requires physical control over the device, and typically also requires a fingerprint or other biometric second factor.

software vault - a webworker corresponding to a keypair that provides the API for the operations (encrypt/decrypt/sign/validate) such that the unenscrypted private key is not available to any software outside the vault. The distributed security software spins up a unique software vault as-needed for each team that the user tries to gain access to. The vault retrieves the 

multi-key encryption - a technique by which a private data is encrypted in a self-contained way that it can be read only by multiple authorized users, and not by any service provider or other external party. This is one of the "special sauces" of distributed security, and is used for team roster  and recovery key storage. You can think of this a N different encryptions of the same private data, packaged together for persistence in the storage provider. (If implemented exactly that way, the size of the resource would be proportional to payloadSize * numberOfMembers, which could be quite large. Instead we store it in a size proportional to just payloadSize + numberOfMembers as follows. The payload is symmetrically encrypted just once within the software vault, using a new random GUID-based secret for each encryption and never reused. Within the vault, a different encrypted copy of the secret is made for each authorized use, as specified for either the team roster storage or recovery key storage use cases, below. The final result to be stored is then the encrypted payload, and a map of each authorized use to the corresponding encrypted version of the decoding secret.)

team roster - A multi-key encryption of the private key associated with a team, readable only by the current team members. The payload is the private key associated with the team's public key, and each entry of the map records a member's public key to the member's unique encryption of the secret.

recovery keypairs - A multi-key ecnryption  ....


## Implementation:

The distributed security software is a library for browser javascript, defining four async operations.

The first two are always available, and use standard APIs built into every browser:

* verify(signature)
* encrypt(content, pubkey)

The next two will fail if the requesting user does not own the corresponding private key:

* decrypt(content, pubkey)
* sign(content, pubkey)

These operate by attempting to find a webworker in the same browser for the given pubkey, launching it if necesary. This is the locally-running vault for that individual team:

* The pubkey for the device being used will start its vault immediately, and authenticate in its own way depending on the machine's capabilities. E.g., using Web Authentication, one-time password, etc.
* Otherwise, the vault will use the storage provider to get a copy of the current team roster for the specified pubkey. The vault then recursively attempts to find a member with a valid vault on this machine. If one is found, it asks that vault to decrypt the encrypted team secret that the team roster has mapped from this member pubkey. This is used to decrypt the team's private key.

If the vault is valid, it completes the requested operation. Otherwise, it shuts down. (Team membership can change later, so it may be appropriate to retry.) Note that a private key cannot be extracted from a vault by software, but it can be pulled by a valid human team member using the browser's debugger.

The application controls changes to the team roster. In kir0y, any member can do so, and it works by simply writing a new roster (because the roster is owned by the team, and all artifacts are writeable in ki1r0y only be any member of the owning team). Note that the member pubkeys are available in plain text, and so a new secret can be encoded for each member using their public `key, such that it will only be readable by that member. Note also that the member that submitted the changed roster is non-repudiably recorded.

## Properties

There is no reason to designate someone to sign for you, or to escrow a keypair. The usual scenarios for doing this are:
- If you are part of an organization, and someone needs to sign even when you are out. A better way to do this, rather than sharing keys, is to simply define a Team that can sign. Anything that needs to be authorized is signed by a team member as the team, and also by himself. Now we have authorization by the team entity AND still know which individual actually signed.
- If there is danger of loosing access to the device with the keychain, so you want top keep a copy somewhere. Same answer here, except that the "team" is "you", and the members of the team are the individual devices. The team keys are secure in the cloud, and each member device's keypair never leaves the device. If you loose acces to a device, you can use another device to sign as "you" -- i.e., the team that represents you and all your devices -- and you can easily remove the now missing device from team, so that going forward, no one with that device (and the device's pin, your fingerprint or face, etc.) can sign as you. What's more, everything signed as you is also signed by the particular device that was used, so that you can track.

A stable tag is used to designate a keypair entity, and the keypair is used for all four operations (encrypt/decrypt, and sign/verify). There are generally two reasons to be concerned about doing so:
1. Some algorithms (e.g., raw RSA) are susceptable to attack when used in multiple ways. We do not use such algorithms.
2. Some uses have different needs as to giving multiple people access or escrow. The team concept makes that moot.

"{"1":"1[\"-3\",\"-4\"]","missing":"NaN[\"-3\",\"-4\"]"}"
"{"1":"2[\"-3\",\"-4\"]","missing":"NaN[\"-3\",\"-4\"]"}"

"{"3":"3[\"-7\",\"-8\"]","5":"5[\"-7\",\"-8\"]"}"
"{"3":"4[\"-7\",\"-8\"]","5":"6[\"-7\",\"-8\"]"}"

{tag: '3', signingKey: -3, decryptingKey: -4}
{tag: '7', signingKey: -7, decryptingKey: -8}

{1: '2', 3: '4', 5: '6', 7: '8'}
