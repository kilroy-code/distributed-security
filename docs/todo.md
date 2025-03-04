# Remaining Work for Distributed Security

## doc
- [ ] A set of short re-useable use-case examples, each describing one thing in a paragraph, a picture (e.g., of the end state), code, and optionally see-also links, arranged in a choose-your-own adventure style.
- [ ] explainer video

## code
- [ ] Require specific algorithm to verify/decrypt. Test cases to prove it.
- [ ] how do we guard against rewrite of device EncryptionKey? (since devices have no members, so signature is compact)
- [ ] Use symbols/getters/internals for internals?
- [ ] Browsers that support dynamic state paritioning will not be able to share device tags across applications from different domains, even when they share the same module domain. (They will still be able to share team tags.) Formalize this as a requirement in the doc, and store referrer with the device tag to effectively implement our own dynamic state partitioning. How do we unit-test this?  
- API - error handling
  - [ ] Give errors for at least some errors (e.g., badly formed arguments) instead of undefined. Maybe all errors?
  - [ ] Error messages should state issue up front with shortened tag at end.
  - [ ] Display an ugly warning if vault is used from same origin as application.
  - [ ] feature-detection and messaging for unsupportable browsers
  - [ ] give specialized error messages for common mistakes: not waiting for ready, passing a promise for a tag, ....
- Add to unit tests:
  - [ ] speed tests
  - [ ] Multiple apps using the same vault can use the same team tags. But this is not true for device and recovery tags.
  - [ ] storage/getUserDeviceSecret on a direct import of security.mjs does not effect that used by a properly origined index.mjs.
  - [ ] changeMembership of a device or recovery will fail
  - [ ] changeMembers will fail if not a member
  - [ ] cycles within recursive team membership is not a problem.

## dependencies
- [jsonrpc](https://github.com/kilroy-code/jsonrpc)
  - [ ] unit tests
- [signed-cloud-server](https://github.com/kilroy-code/signed-cloud-server)
  - test cache-control in browsers
  - content-security-policy ?

## release
- literature review:
  - [ ] https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
  - [ ] https://web.dev/csp/
  - [ ] https://crypto.stackexchange.com/questions/35530/where-and-how-to-store-private-keys-in-web-applications-for-private-messaging-wi and the links there.
  - see attack scenarios in:
    - [ ] https://owasp.org/www-community/attacks/Man-in-the-browser_attack
    - [ ] https://owasp.org/www-community/attacks/xss/
    - [ ] https://www.geeksforgeeks.org/clickjacking-ui-redressing/
    - [ ] https://auth0.com/blog/cross-site-scripting-xss/
- [ ] term of use to state that any distributed copies must comply with all security provisions of the software - i.e., that a modified copy that introduces a new weakness is a violation of the license, whether maliciously or unintentionally.
- [ ] quick usage section in README (or demo?) with with importmap stuff like https://thingster.app/things/ctUhszB47Wb52JgHeMV9m
- [ ] Include final license in each file, because that's what the license says to do.

## future
- Allow other apps to use cloud.ki1r0y.com, either allowing reguest origin in Access-Control-Allow-Origin, or through a registration
- Fast, self-contained membership test for removed members. (Bloom filter of removed members?)
- Support Zero-Knowledge Proofs. Specifically, allow a user to prove membership without revealing which member and without re-use. ([Semaphore](https://docs.semaphore.pse.dev/)?)
- Use Web credentials for secret, particularly public-key. (This can be done by an app now, but it would be nice to ship with "batteries included".)
- Hidden rosters - can we make it so each tag key in the roster dictionary can only be read by the members? But what about storage system checking that the submitter is a member of the team? (Maybe instead of kid, label each member by hash(tag + iat)?)
- Large membership rosters - Built-in support for partitioning.
- Is there a way to derive a public encryption key from a public verification key (i.e., from a tag), so that we don't need to store public encryption keys in the cloud? This would allow device keys to self-contained on the device, without leaving any garbage in the cloud when the device is abandoned.
- Can we verify that the code is correct? (Vault code, and particularly server code that doesn't use a vault. Browser's have subresource integrity, but not NodeJS (and someone could make a false NodeJS).) An application-provider can be sure of the code that it provides as the vault implementation, but the end-user is trusting that the application-provider is sure. It would be nice if the vault could sign its own code in memory, and make that signature available to users. (The code to securely get the live source of the module code would itself have to be signed by a trusted source.)  Such a secure execution context would be generally useful for mobile code. For example, a user-customized or even user-written search algorithm running on a server or p2p cloud could sign its results, so that the user can be sure of the recommendations. 
