# Remaining Work for Distributed Security

### Code Cleanup
- remove ad-hoc JSON.stringfy/parts 
  - [ ] Underlying krypto/multiKrypto decrypt should return whole JOSE result, which in our version already has text/json properties as appropriate. Update callers.
  - [ ] Remove various JSON.stringify in vault.mjs, and replace JSON.parse with reference to result.json.
- API - error handling
  - [ ] Good error messages for badly formatted tags, signature, encrypted. 
  - [ ] Error messages should state issue up front with shortened tag at end.
  - [ ] Display an ugly warning if vault is used from same origin as application.
  - [ ] feature-detection and messaging for unsupportable browsers
  - [ ] give specialized error messages for common mistakes: not waiting for ready, passing a promise for a tag, ....
- [ ] Browsers that support dynamic state paritioning will not be able to share device tags across applications from different domains, even when they share the same module domain. (They will still be able to share team tags.) Formalize this as a requirement in the doc, and store referrer with the device tag to effectively implement our own dynamic state partitioning. How do we unit-test this?
- [ ] Change the vault.mjs and its contients to some other name, since we are using vault.html to mean the iframe isolation mechanism.      
- [ ] Use symbols/getters/internals for internals
- [ ] Andreas' rule. (Every operation gets a one-sentence comment.)
- Add to unit tests:
  - [ ] speed tests
  - [ ] Multiple apps using the same vault can use the same team tags. But this is not true for device and recovery tags.
  - [ ] storage/getUserDeviceSecret cannot be reset once set.
  - [ ] storage/getUserDeviceSecret on a direct import of security.mjs does not effect that used by a properly origined index.mjs.
  - [ ] changeMembership of a device or recovery will fail
  - [ ] changeMembers will fail if not a member
  - [ ] device and recovery jws use a different iv each time they are encrypted
  - [ ] cycles within recursive team membership is not a problem.
  - [ ] Tests for error messages.
- [ ] Doc: the term of art for multi is "multiparty encryption". Are there places where I should use that term? Similarly for "content encryption key" (CEK) or "direct encryption".

### dependencies
- JOSE 
  - [ ] Both JOSE and Distributed-Security use E6 modules. Work out how to make our references to JOSE load, with or without an importmap and with or without a build step.
- [jsonrpc](https://github.com/kilroy-code/jsonrpc)
  - [ ] unit tests
  - [ ] make sure logging is effective but secure in "tracing"
  
### internal infrastructure
- [ ] NodeJS implementation, for use on servers and for running unit tests. (e.g., 1. When loading index.mjs outside the browser, load security.mjs directly instead of through vault. 2. lib/store and spec/support/storage to use something else under node.)
- [ ] GitHub Action to run test suite, like other parts of ki1r0y. 
- [ ] version 0.1 package release
- [ ] replace older ki1r0y storage scaffolding
- [ ] integrate into toplevel ki1r0y test suites

### release
- https://en.wikipedia.org/wiki/Security.txt and the like
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
- [ ] npm publishing, getting rid of scoped package name if necessary.
- [ ] version 1.0 release

### future
- Use Web credentials for secret, particularly public-key. (This can be done by an app now, but it would be nice to ship with "batteries included".)
- Hidden rosters - can we make it so each tag key in the roster dictionary can only be read by the members? But what about storage system checking that the submitter is a member of the team? (Maybe instead of kid, label each member by hash(tag + iat)?)
- Is there a way to derive a public encryption key from a public verification key (i.e., from a tag), so that we don't need to store public encryption keys in the cloud? This would allow device keys to self-contained on the device, without leaving any garbage in the cloud when the device is abandoned.
