# Remaining Work for Distributed Security

### critical core
- [x] device key persistence
- [x] split out distributed storage so that applications can use the module of their choice that implements the api
- [x] changing the roster
- [ ] decrypting old content after a membership change
- [x] recovery vault, using PBKDF2 derived keys

### details
- [x] device local storage leak in tests
- [ ] _**No change needed?**_ worker should be a shared worker, with indexDB storage in the worker, so that multiple pages that use the same vault can share keys.
- [ ] Change the vault.mjs and its contients to some other name, since we are using vault.html to mean the iframe isolation mechanism.
- [-] **Demo**
 - explanation
 - recovery
 - fixmes
- [ ] We currently use base64 for all serialization, including tags, which works with atob()/btoa(). But should we use url-safe base64 instead? ('+/=' => '._-') For tags only (so that they can appear in URLs), or for everything (for uniformity, including data: URLs)? 
- [ ] Good error messages for badly formatted tags, signature, encrypted. Include tests.
- [ ] Error messages should state issue up front with shortened tag at end.
- [ ] Make sure that improper operations fail, e.g., changeMembership of a device tag.
- [ ] Consider changing order of signature, message arguments to verify, on the grounds that is more important to make sense to our users than it is to match the order in crypto.subtle.
- [ ] Pass device tag to getUserDeviceSecret. Include tests.
- [ ] disallow resetting get or storage. Include tests.
- [ ] Display an ugly warning if vault is used from same origin as application.
- [ ] track symmetric key cycles live and through export so that they're not reused. include unit test in subsystem
- [ ] Andreas' rule.
- [ ] Remove iframeTrampoline.html and lib/storage distractions
- [ ] rename lib/security.mjs -> lib/core.mjs, and unify request() to something more explicit as to target, such as requestClient()/requestWorker().
- [ ] Provide a nodejs version, so that cloud storage servers can verify signature. Include in README.
- [ ] implement a defense against those browsers that do not enforce [dynamic state paritioning](https://developer.mozilla.org/en-US/docs/Web/Privacy/State_Partitioning). Store vault document.referrer alongside device keys. Refuse to act if accessed from a different document.referrer.


### dependencies
- [ ] unit tests for jsonrpc
- [ ] distributed storage unit tests, including check for replay attacks that would revert to earlier version
- [ ] distributed storage as proper package with readme

### doc
- [ ] the term of art for multi is "multiparty encryption". Are there places where I should use that term?
- [ ] break source files into even smaller pieces, one concept each, and update implementation.md and unit tests to match
- [x] write [risks.md](risks.md)
- [x] document storage requirements and usage
- [ ] document application requirements on usage - e.g., same origin, https (or localhost), browser not in private browsing or similar modes (all of which are required for the underlying technolgies), as well as any caching complications
- [ ] document application control over recovery vaults
- [x] document application control over device secrets

### internal infrastructure
- [ ] GitHub Action to run test suite (using puppeteer?), like other parts of ki1r0y. Include a test to make sure that the demo stays working.
- [ ] version 0.1 package release
- [ ] replace older ki1r0y storage scaffolding
- [ ] integrate into toplevel ki1r0y test suites

### release
- [ ] feature-detection and messaging for unsupportable browsers
- [ ] give specialized error messages for common mistakes: not waiting for ready, passing a promise for a tag, ....
- [ ] make sure logging is effective but secure in "tracing"
- [ ] quick usage section in README (or demo?) with with importmap stuff like https://thingster.app/things/ctUhszB47Wb52JgHeMV9m
- [ ] Include final license in each file, because that's what the license says to do.
- [ ] npm publishing, getting rid of scoped package name if necessary.
- [ ] version 1.0 release

### future
- [ ] Use credentials for secret, particularly public-key. (This can be done by the app now, but it would be nice to ship with "batteries included".)
- [ ] hidden rosters - can we make it so each tag key in the roster dictionary can only be read by the members? 
- [ ] jws signatures?
- [ ] different signing algorithm or parameters so as to have shorter tags?
- [ ] Is there a way to derive a public encryption key from a public verification key (i.e., from a tag), so that we don't need to store public encryption keys in the cloud? This would allow device keys to self-contained on the device, without leavin any garbage in the cloud when the device is abandoned.
- [ ] media - Currently, an app must convert media to a string, and then internally Distributed Security converts it back to binary for signing or encrypting. It would be nice to just hand it binary media directly.
