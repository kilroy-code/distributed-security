# Remaining Work for Distributed Security

- [ ] device local storage leak in tests

### critical core
- [x] device key persistence
- [x] split out distributed storage so that applications can use the module of their choice that implements the api
- [x] changing the roster
- [ ] decrypting old content after a membership change
- [x] recovery vault, using PBKDF2 derived keys

### details
- [ ] _**No change needed?**_ worker should be a shared worker, with indexDB storage in the worker, so that multiple pages that use the same vault can share keys.
- [ ] Change the vault.mjs and its contients to some other name, since we are using vault.html to mean the iframe isolation mechanism.
- [-] **Demo**:
- [ ] Pass device tag to getUserDeviceSecret, and disallow resetting get or storage.
- [ ] Display an ugly warning if vault is used from same origin as application.
- [ ] track symmetric key cycles live and through export so that they're not reused. include unit test in subsystem
- [ ] Remove iframeTrampoline.html and lib/storage distractions
- [ ] rename lib/security.mjs -> lib/core.mjs, and unify request() to something more explicit as to target, such as requestClient()/requestWorker().
- [ ] implement a defense against those browsers that do not enforce [dynamic state paritioning](https://developer.mozilla.org/en-US/docs/Web/Privacy/State_Partitioning). Store vault document.referrer alongside device keys. Refuse to act if accessed from a different document.referrer.

### dependencies
- [ ] unit tests for jsonrpc
- [ ] distributed storage unit tests, including check for replay attacks that would revert to earlier version
- [ ] distributed storage as proper package with readme

### doc
- [ ] break source files into even smaller pieces, one concept each, and update implementation.md and unit tests to match
- [x] write [risks.md](risks.md)
- [ ] document storage requirements and usage
- [ ] document application requirements on usage - e.g., same origin, https (or localhost), browser not in private browsing or similar modes (all of which are required for the underlying technolgies), as well as any caching complications
- [ ] document application control over recovery vaults
- [ ] document application control over device secrets

### internal infrastructure
- [ ] GitHub Action to run test suite (using puppeteer?), like other parts of ki1r0y
- [ ] version 0.1 package release
- [ ] replace older ki1r0y storage scaffolding
- [ ] integrate into toplevel ki1r0y test suites

### release
- [ ] feature-detection and messaging for unsupportable browsers
- [ ] give specialized error messages for common mistakes: not waiting for ready, passing a promise for a tag, ....
- [ ] make sure logging is effective but secure in "tracing"
- [ ] jsdeliver, unpkg or the like
- [ ] quick usage section in README (or demo?) with with importmap stuff like https://thingster.app/things/ctUhszB47Wb52JgHeMV9m
- [ ] Include final license in each file, because that's what the license says to do.
- [ ] version 1.0 release

### future
- [ ] hidden rosters - can we make it so each tag key in the roster dictionary can only be read by the members? 
- [ ] media - Currently, an app must convert media to a string, and then internally Distributed Security converts it back to binary for signing or encrypting. It would be nice to just hand it binary media directly.
