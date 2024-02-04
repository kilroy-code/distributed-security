# Remaining Work for Distributed Security

### details
- API:
  - [ ] Implement caching argument to create and changeMembership.
  - [ ] Decide on the arguments to verify. The order for the parameters to verify is currently different between the doc/demo and the code. Maybe the best thing is to use JWE style, where the signature includes the message and successful verify resolves to the message.
  - [ ] Implement multi-key signatures. I think the most natural way to specify this is to reverse the order of arguments to the four basic operations, so that multiple keys can be specified by adding more arguments.
  - [ ] Provide an option (default true?) for verify to check not only the cryptographic signature, but also the additional checks for a multi-key signature (as used by store()). This provides enforcement of membership change. Do we really need this AND a cache argument?
  - [ ] Browsers that support dynamic state paritioning will not be able to share device tags across applications from different domains, even when they share the same module domain. (They will still be able to share team tags.) Formalize this as a requirement in the doc, and store referrer with the device tag to effectively implement our own dynamic state partitioning.
  - [ ] Should allow the app to get a nonce once during initialization, which it must pass during all calls? (A variation on the "hidden form field" defense against csrf.)
  - [ ] Good error messages for badly formatted tags, signature, encrypted. 
  - [ ] Error messages should state issue up front with shortened tag at end.
  - [ ] Display an ugly warning if vault is used from same origin as application.
  - [ ] Track symmetric key cycles live and through export so that they're not reused. include unit test in subsystem
  - [ ] feature-detection and messaging for unsupportable browsers
  - [ ] give specialized error messages for common mistakes: not waiting for ready, passing a promise for a tag, ....
- Code cleanup:
  - [ ] Change the vault.mjs and its contients to some other name, since we are using vault.html to mean the iframe isolation mechanism.
  - [ ] Remove iframeTrampoline.html and lib/storage distractions
  - [ ] rename lib/security.mjs -> lib/core.mjs, and unify request() to something more explicit as to target, such as requestClient()/requestWorker().
  - [ ] Demo source-code cleanup.
  - [ ] Andreas' rule. (Every operation gets a one-sentence comment.)
  - [ ] Break source files into even smaller pieces, one concept each, and update implementation.md and unit tests to match
- Add to unit tests:
  - [ ] Show how membership change is or is not caught depending on cache checkMembership options.
  - [ ] Show that multiple apps using the same vault can use the same team & recovery tags. Show that this is not true for device tags.
  - [ ] Show that cycles within recursive team membership is not a problem.
  - [ ] Deliberate failure cases: reset of storage/getUserDeviceSecret, changeMembership of a non-team, reuse of a symmetric key.
  - [ ] Tests for error messages.
- [ ] Doc: the term of art for multi is "multiparty encryption". Are there places where I should use that term? Similarly for "content encryption key" (CEK) or "direct encryption".

### dependencies
- JOSE 
  - [ ] Both JOSE and Distributed-Security use E6 modules. Work out how to make our references to JOSE load, with or without an importmap and with or without a build step.
- [jsonrpc](https://github.com/kilroy-code/jsonrpc)
  - [ ] unit tests
  - [ ] make sure logging is effective but secure in "tracing"
  
### internal infrastructure
- [ ] GitHub Action to run test suite (using puppeteer?), like other parts of ki1r0y. Include a test to make sure that the demo stays working.
- [ ] version 0.1 package release
- [ ] replace older ki1r0y storage scaffolding
- [ ] integrate into toplevel ki1r0y test suites

### release
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
- Use Web credentials for secret, particularly public-key. (This can be done by the app now, but it would be nice to ship with "batteries included".)
- Maybe provide an option in changeMembership to produce a new encryption key so that former members cannot read new documents. The option might take a list of resources to be re-encrypted with the new key.
- Hidden rosters - can we make it so each tag key in the roster dictionary can only be read by the members? But what about storage system checking that the submitter is a member of the team?
- Different signing algorithm or parameters so as to have shorter tags?
- Is there a way to derive a public encryption key from a public verification key (i.e., from a tag), so that we don't need to store public encryption keys in the cloud? This would allow device keys to self-contained on the device, without leavin any garbage in the cloud when the device is abandoned.
- Media - Currently, an app must convert media to a string, and then internally Distributed Security converts it back to binary for signing or encrypting. It would be nice to just hand it binary media directly. (However, the intention within Distributed Storage is to sign metadata about media, rather than the media itself, so this IWBNI detail is for uses other than ours.)
