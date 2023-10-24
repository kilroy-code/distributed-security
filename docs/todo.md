# Remaining Work for Distributed Security

### critical core
- [ ] device key persistence
- [ ] split out distributed storage so that applications can use the module of their choice that implements the api
- [ ] changing the roster
- [ ] decrypting old content after a membership change
- [ ] recovery vault, using PBKDF2 derived keys

### details
- [ ] track symmetric key cycles live and through export so that they're not reused. include unit test in subsystem
- [ ] move request reference to module-local var in index.mjs

### dependencies
- [ ] jsonrpc as proper package with readme and unit tests
- [ ] distributed storage unit tests, including check for replay attacks that would revert to earlier version
- [ ] distributed storage as proper pacage with readme

### doc
- [ ] break source files into even smaller pieces, one concept each, and update implementation.md and unit tests to match
- [ ] write [risks.md](risks.md)
- [ ] document storage requirements and usage
- [ ] document application requirements on usage - e.g., same origin, https (or localhost), browser not in private browsing or similar modes (all of which are required for the underlying technolgies), as well as any caching complications
- [ ] document application control over recovery vaults
- [ ] document application control over device secrets

### internal infrastructure
- [ ] nodejs usage
- [ ] nodify test suite
- [ ] test suite github actions, like other parts of ki1r0y
- [ ] version 0.1 release
- [ ] separate storage package as codependency
- [ ] replace older ki1r0y storage scaffolding
- [ ] integrate into toplevel ki1r0y test suites

### release
- [ ] feature-detection and messaging for unsupportable browsers
- [ ] jsdeliver, unpkg or the like
- [ ] quick usage section in README with with importmap stuff like https://thingster.app/things/ctUhszB47Wb52JgHeMV9m
- [ ] version 1.0 release

### future
- [ ] demo, especially showing how it produces verifiable authoriship (maybe show how this is better than rostr?)
- [ ] hidden rosters - can we make it so each tag key in the roster dictionary can only be read by the members? 
