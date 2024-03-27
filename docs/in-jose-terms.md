# Distributed-Security in JOSE Technical Terms

> This document is intended for people who are already deeply familiar with JOSE technical terms. It precisely defines *what* the library does, but not why.

1. [Distributed-Security](https://kilroy-code.github.io/distributed-security/) applications generate and decrypt [`JWE`](https://www.rfc-editor.org/rfc/rfc7516) using [`RSA-OAEP-256`](https://datatracker.ietf.org/doc/html/rfc7518#section-4.3) and they generate and verify [`JWS`](https://datatracker.ietf.org/doc/html/rfc7515) using [`ES384`](https://datatracker.ietf.org/doc/html/rfc7518#section-3.4). Except as specified below, these are in compact form.
2. Distributed-Security is an [open-source Javascript library](https://github.com/kilroy-code/distributed-security) that implements (1) using the [panva JOSE library](https://www.npmjs.com/package/jose), which in turn uses [`subtle.crypto`](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) API in browsers and the [`crypto`](https://nodejs.org/docs/latest/api/crypto.html) API in [NodeJS](https://nodejs.org/).
3. Each individual or team of individuals is identified in the application by a *tag* string, which appears as the [`kid`](https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4) property in `JWS` and `JWE`.
4. All systems (including external ones if permitted by the application) may obtain the *public keys* for a tag:
   1. The public *encrypting* [`JWK`](https://datatracker.ietf.org/doc/html/rfc7517) is freely available from the cloud, via a permissionless read operation provided by the application (and used internally by Distributed-Security).
   2. The tag itself is the Base64URL serialization of the raw public *verification* key, and so the public verification key is available directly, without reference to the cloud.

## 5. Wrapped Private Keys in the Cloud

Encryption and verification for a tag can be done anywhere using the public key from 4.1 or 4.2.

However, the private decrypting and signing keys are stored in the application-defined cloud as general JSON `JWE`, encrypted for multiple recipients using a [`A256GCMKW`](https://datatracker.ietf.org/doc/html/rfc7518#section-4.7) [`enc`](https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.2). The recipients are the *members* of the team at the time of writing the `JWE`.

To `decrypt` or `sign` for a given tag, the Distributed-Security library retrieves the `JWE` for that tag and decrypts it using whichever recipient member tag is recursively available on that browser. There is no other mechanism defined for a private key to be copied or extracted from the system.

  1. A hierarchy of teams may have individuals and other teams as `JWE`-recipient members.  
     1. Any current member of a team may use the Distributed-Security `changeMembership` or `destroy` operations on tags.  (An application may impose additional restrictions, such as restricting such operations to a particular member.) The current member test is enforced (see (7), below) without relying on any externally defined or custodial revocation protocol. 
     2. The actual keys for a tag are stable over the lifetime of the tag. As membership changes, only the multi-recipient `JWE` of the private keys change, rather than the keys themselves. There is no system protocol for recalling content that a former member had previously decrypted, nor for ensuring that a former member cannot externally `decrypt` with a private decryption key that the former member had somehow previously extracted from the system (e.g, despite the safeguards of (6), below). However, there *is* an opt-in protocol against continued verification of a `JWS` by someone who is no longer a member. (See (7), below.)
  2. An individual has member recipients that are defined by one or more additional tags that correspond to the devices on which that individual uses the app. The public keys of devices are available as in 4.1 and 4.2. The private device-specific key sets are encrypted as `JWE`.
     1. Instead of storing these in the cloud, they are persisted in [`IndexedDB`](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API) within a private browsing context that is separate from the application. (See (6), below.)
     2. The sole decrypting recipient is an application-provided unguessable string that must be unique to this user in this application on this browser. This string is used in a [`PBES2-HS512+A256KW`](https://datatracker.ietf.org/doc/html/rfc7518#section-4.8) encryption, and should be between 32 and 128 bytes. Distributed-Security asks the application for this string when encrypting the device keys, and again when decrypting them.
  3. As a backup, used only in a browser in which no previously persisted device member tags are found, a “recovery” tag can be produced as a member tag of the current individual. This is also stored as `JWE` in the manner of (5.2), however:
     1. The application-provided encrypting secret string is intended to include not only something specific to the user+application+device as for (5.2), but also the user’s concatenated, normalized responses to a set of application-defined security questions that only this user would know as a set.
     2. The application-provided prompts (or identifications of prompts) is used as the `kid` in the `JWE`, and then passed again to the application during decryption so that it may ask the user the right questions.
     3. The resulting `JWE` is not stored locally in the browser (where it could disappear), but in the application-provided cloud. The application-provided API for retrieving this will be supplied parameters that identify the request as a recovery key, so that the application may place additional restrictions on access if required (such as a OTP verification of some sort).

## 6. Sandbox

All of this (including local persistence of (5b), occurs within a unique browsing context separate from the application. (There is currently no such sandboxing in NodeJS uses of the library.)

   1. The Distributed-Security library provides the application with an object that defines methods to `encrypt`, `decrypt`, `sign`, `verify`, `create` (a tag with specified members), `changeMembership`, and `destroy` (a tag).
   2. The provided application object dynamically creates a (non-visible) iframe that loads a service worker with the real implementation of operations. The application must host the Distributed-Security module (an ES6 module) at a different origin than the main application (and the library checks this). The communication between the provided application object and the separate browsing context is via postMessage, in which both sides confirm the origin of each message. All keys are decrypted only within this browsing context and are not exported from it.
   3. The separate origin can be shared by cooperating applications, forming a shared tag-space. 
      1. Such cooperating applications do not have access to each other’s device tags or recovery tags, which are still unique to each application. However, a tag may list as member a tag created by another application, and that shared parent tag can then be used freely by a user of any of the cooperating applications, on any of that user’s devices. 
      2. Alternatively, an application may host its own copy of the Distributed-Security library at a separate origin that is uniquely hosted by the application, and which defines cross-site protections against use by other applications. This effectively defines a private tag-space unique to the application.

## 7. Auditable Signatures and Deep Verification

The `JWE` and `JWS` produced by Distributed-Security are normally defined in compact form for one tag, and do not carry additional encryptions or signatures for members. However,

- The multiple-recipient general JSON `JWE` is used internally for persisting private keys.
- An application can request a general JSON `JWS` with signatures for multiple tags, and may further request an "auditable" general JSON `JWS` identifying the specific member that signed for the team, and which contains additional secure header information:

   1. The issuing tag is identified as the [`iss`](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.1).
   2. The specific member tag is identified as the authorized actor ([`act`](https://www.rfc-editor.org/rfc/rfc8693.html#section-4.1)). The `JWS` contains a second signature for the `act`.
   3. The timestamp that the `JWS` was issued is included as the [`iat`](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.6).
   4. By default, when such additional information is present, the Distributed-Security `verify` operation checks that each supplied signature is correct, and will examine the current `JWS` specified by the `iss` (at the time of verification). If there is such a `JWS`, we confirm that the `act` is indeed a member of the `iss`, and if requested in the call, that the `iat` of the `JWS` being tested is not less than the `iat` of the current `JWS` for the `iss`. 
   5. When Distributed-Security saves anything to the cloud (on `create`, `changeMembership`, or `destroy`), it wraps the `JWE` or `JWK` in a `JWS` that has the additional secure headers and signature, and submits that `JWS` to the application for storage. The application-provided cloud storage must then `verify` the `JWS` in the manner of (7.4). This is how we guard against replay or unauthorized storage.
   6. The application *may* further restrict access to the cloud. (E.g., throttling, requiring an actor to be a member of a distinguished administrative team, etc.)
