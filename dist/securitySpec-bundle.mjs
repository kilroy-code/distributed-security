const Storage$1 = {
  origin: new URL(import.meta.url).origin, // diagnostic, reported in ready
  async store(resourceTag, ownerTag, signature) {
    let verified = await this.Security.verify(signature, {team: ownerTag, notBefore: 'team'});
    if (!verified) throw new Error(`Signature ${signature} does not match owner of ${ownerTag}.`);
    if (verified.payload.length) {
      this[resourceTag][ownerTag] = signature;
    } else {
      delete this[resourceTag][ownerTag];
    }
    return null; // Must not return undefined for jsonrpc.
  },
  async retrieve(resourceTag, ownerTag) {
    // We do not verify and get the original data out here, because the caller has
    // the right to do so without trusting us.
    return this[resourceTag][ownerTag];
  },
  Team: {},
  KeyRecovery: {},
  EncryptionKey: {}
};

function transferrableError(error) { // An error object that we receive on our side might not be transferrable to the other.
  let {name, message, code, data} = error;
  return {name, message, code, data};
}

// Set up bidirectional communcations with target, returning a function (methodName, ...params) that will send to target.
function dispatch({target = self,        // The window, worker, or other object to which we will postMessage.
		   receiver = target,    // The window, worker, or other object of which WE will handle 'message' events from target.
		   namespace = receiver, // An object that defines any methods that may be requested by target.

		   origin = ((target !== receiver) && target.location.origin),

		   dispatcherLabel = namespace.name || receiver.name || receiver.location?.href || receiver,
		   targetLabel = target.name || origin || target.location?.href || target,

		   log = null,
		   info:loginfo = console.info.bind(console),
		   warn:logwarn = console.warn.bind(console),
		   error:logerror = console.error.bind(console)
		  }) {
  const requests = {},
        jsonrpc = '2.0',
        capturedPost = target.postMessage.bind(target), // In case (malicious) code later changes it.
        // window.postMessage and friends takes a targetOrigin that we supply.
        // But worker.postMessage gives error rather than ignoring the extra arg. So set the right form at initialization.
        post = origin ? message => capturedPost(message, origin) : capturedPost;
  let messageId = 0; // pre-incremented id starts at 1.

  function request(method, ...params) { // Promise the result of method(...params) in target.
    // We do a target.postMessage of a jsonrpc request, and resolve the promise with the response, matched by id.
    // If the target happens to be set up by a dispatch like this one, it will respond with whatever it's
    // namespace[method](...params) resolves to. We only send jsonrpc requests (with an id), not notifications,
    // because there is no way to get errors back from a jsonrpc notification.
    let id = ++messageId,
	request = requests[id] = {};
    // It would be nice to not leak request objects if they aren't answered.
    return new Promise((resolve, reject) => {
      log?.(dispatcherLabel, 'request', id, method, params, 'to', targetLabel);
      Object.assign(request, {resolve, reject});
      post({id, method, params, jsonrpc});
    });
  }

  async function respond(event) { // Handle 'message' events that we receive from target.
    log?.(dispatcherLabel, 'got message', event.data, 'from', targetLabel, event.origin);
    let {id, method, params = [], result, error, jsonrpc:version} = event.data || {};

    // Noisily ignore messages that are not from the expect target or origin, or which are not jsonrpc.
    if (event.source && (event.source !== target)) return logerror?.(dispatcherLabel, 'to', targetLabel,  'got message from', event.source);
    if (origin && (origin !== event.origin)) return logerror?.(dispatcherLabel, origin, 'mismatched origin', targetLabel, event.origin);
    if (version !== jsonrpc) return logwarn?.(`${dispatcherLabel} ignoring non-jsonrpc message ${JSON.stringify(event.data)}.`);

    if (method) { // Incoming request or notification from target.
      let error = null, result,
          // jsonrpc request/notification can have positional args (array) or named args (a POJO).
	  args = Array.isArray(params) ? params : [params]; // Accept either.
      try { // method result might not be a promise, so we can't rely on .catch().
        result = await namespace[method](...args); // Call the method.
      } catch (e) { // Send back a clean {name, message} object.
        error = transferrableError(e);
        if (!namespace[method] && !error.message.includes(method)) {
	  error.message = `${method} is not defined.`; // Be more helpful than some browsers.
          error.code = -32601; // Defined by json-rpc spec.
        } else if (!error.message) // It happens. E.g., operational errors from crypto.
	  error.message = `${error.name || error.toString()} in ${method}.`;
      }
      if (id === undefined) return; // Don't respond to a 'notification'. null id is still sent back.
      let response = error ? {id, error, jsonrpc} : {id, result, jsonrpc};
      log?.(dispatcherLabel, 'answering', id, error || result, 'to', targetLabel);
      return post(response);
    }

    // Otherwise, it is a response from target to our earlier outgoing request.
    let request = requests[id];  // Resolve or reject the promise that an an earlier request created.
    delete requests[id];
    if (!request) return logwarn?.(`${dispatcherLabel} ignoring response ${event.data}.`);
    if (error) request.reject(error);
    else request.resolve(result);
  }

  // Now set up the handler and return the function for the caller to use to make requests.
  receiver.addEventListener("message", respond);
  loginfo?.(`${dispatcherLabel} will dispatch to ${targetLabel}`);
  return request;
}

const origin = new URL(import.meta.url).origin;

const mkdir = undefined;

const tagBreakup = /(\S{50})(\S{2})(\S{2})(\S+)/;
function tagPath(collectionName, tag, extension = 'json') { // Pathname to tag resource.
  // Used in Storage URI and file system stores. Bottlenecked here to provide consistent alternate implementations.
  // Path is .json so that static-file web servers will supply a json mime type.
  // Path is broken up so that directory reads don't get bogged down from having too much in a directory.
  //
  // NOTE: changes here must be matched by the PUT route specified in signed-cloud-server/storage.mjs and tagName.mjs
  if (!tag) return collectionName;
  let match = tag.match(tagBreakup);
  if (!match) return `${collectionName}/${tag}`;
  // eslint-disable-next-line no-unused-vars
  let [_, a, b, c, rest] = match;
  return `${collectionName}/${a}/${b}/${c}/${rest}.${extension}`;
}

async function responseHandler(response) {
  // Reject if server does, else response.text().
  if (response.status === 404) return '';
  if (!response.ok) return Promise.reject(response.statusText);
  let text = await response.text();
  if (!text) return text; // Result of store can be empty.
  return JSON.parse(text);
}

const Storage = {
  get origin() { return origin; },
  tagPath,
  mkdir,
  uri(collectionName, tag) {
    // Pathname expected by our signed-cloud-server.
    return `${origin}/db/${this.tagPath(collectionName, tag)}`;
  },
  store(collectionName, tag, signature, options = {}) {
    // Store the signed content on the signed-cloud-server, rejecting if
    // the server is unable to verify the signature following the rules of
    // https://kilroy-code.github.io/distributed-security/#storing-keys-using-the-cloud-storage-api
    return fetch(this.uri(collectionName, tag), {
      method: 'PUT',
      body: JSON.stringify(signature),
      headers: {'Content-Type': 'application/json', ...(options.headers || {})}
    }).then(responseHandler);
  },
  retrieve(collectionName, tag, options = {}) {
    // We do not verify and get the original data out here, because the caller has
    // the right to do so without trusting us.
    return fetch(this.uri(collectionName, tag), {
      cache: 'default',
      headers: {'Accept': 'application/json', ...(options.headers || {})}
    }).then(responseHandler);
  }
};

var prompter = promptString => promptString;
if (typeof(window) !== 'undefined') {
  prompter = window.prompt;
}

function getUserDeviceSecret(tag, promptString) {
  return promptString ? (tag + prompter(promptString)) : tag;
}

const entryUrl = new URL(import.meta.url),
      vaultUrl = new URL('vault.html', entryUrl),
      vaultName = 'vault!' + entryUrl.href; // Helps debugging.

// Outer layer of the vault is an iframe that establishes a browsing context separate from the app that imports us.
const iframe = document.createElement('iframe'),
      channel = new MessageChannel(),
      resourcesForIframe = Object.assign({ // What the vault can postMessage to us.
        log(...args) { console.log(...args); },
        getUserDeviceSecret
      }, Storage),
      // Set up a promise that doesn't resolve until the vault posts to us that it is ready (which in turn, won't happen until it's worker is ready).
      ready = new Promise(resolve => {
        resourcesForIframe.ready = resolve,
        iframe.style.display = 'none';
        document.body.append(iframe); // Before referencing its contentWindow.
        iframe.setAttribute('src', vaultUrl);
        iframe.contentWindow.name = vaultName;
        // Hand a private communication port to the frame.
        channel.port1.start();
        iframe.onload = () => iframe.contentWindow.postMessage(vaultName, vaultUrl.origin, [channel.port2]);
      }),
      postIframe = dispatch({  // postMessage to the vault, promising the response.
        dispatcherLabel: 'entry!' + entryUrl.href,
        namespace: resourcesForIframe,
        target: channel.port1,
        targetLabel: vaultName
      }),

      api = { // Exported for use by the application.
        sign(message, ...tags) { return postIframe('sign', message, ...tags); },
        verify(signature, ...tags) { return postIframe('verify', signature, ...tags); },
        encrypt(message, ...tags) { return postIframe('encrypt', message, ...tags); },
        decrypt(encrypted, ...tags) { return postIframe('decrypt', encrypted, ...tags); },
        create(...optionalMembers) { return postIframe('create', ...optionalMembers); },
        changeMembership({tag, add, remove} = {}) { return postIframe('changeMembership', {tag, add, remove}); },
        destroy(tagOrOptions) { return postIframe('destroy', tagOrOptions); },
        clear(tag = null) { return postIframe('clear', tag); },
        ready,

        // Application assigns these so that they can be used by the vault.
        get Storage() { return resourcesForIframe; },
        set Storage(storage) { Object.assign(resourcesForIframe, storage); },
        get getUserDeviceSecret() { return resourcesForIframe.getUserDeviceSecret; },
        set getUserDeviceSecret(functionOfTagAndPrompt) { resourcesForIframe.getUserDeviceSecret = functionOfTagAndPrompt; }
      };

const scale = 10 * 1024 * 1024;
function makeMessage(length = scale) {
  return Array.from({length}, (_, index) => index & 1).join('');
}
const base64withDot = /^[A-Za-z0-9_\-.]+$/;
function isBase64URL(string, regex = base64withDot) {
  expect(regex.test(string)).toBeTruthy();
}

function sameTypedArray(result, message) {
  // The payload is a Uint8Array, but in NodeJS, it will be a subclass of Uint8Array,
  // which won't compare the same in Jasmine toEqual.
  expect(new Uint8Array(result.payload)).toEqual(message);
}

function testKrypto (krypto, // Pass either Krypto or MultiKrypto
                                    encryptableSize = 446) {
  const bigEncryptable = encryptableSize > 1000,
        slowKeyCreation = 15e3,
        slowHybrid = bigEncryptable ? slowKeyCreation : 5e3, // Needed on Android
        message = makeMessage();

  describe('signing', function () {
    let keypair;
    beforeAll(async function () {
      keypair = await krypto.generateSigningKey();
    });
    it('with a private key produces a base64URL signature that verifies with the public key.', async function () {
      let signature = await krypto.sign(keypair.privateKey, message);
      isBase64URL(signature);
      expect(await krypto.verify(keypair.publicKey, signature)).toBeTruthy();
    });
    it('returns undefined for verify with the wrong key.', async function () {
      let signature = await krypto.sign(keypair.privateKey, message),
          wrongKeypair = await krypto.generateSigningKey();
      expect(await krypto.verify(wrongKeypair.publicKey, signature)).toBeUndefined();
    });
    it('handles binary, and verifies with that as payload property.', async function () {
      let message = new Uint8Array([21, 31]),
          signature = await krypto.sign(keypair.privateKey, message),
          verified = await krypto.verify(keypair.publicKey, signature);
      expect(verified.cty).toBeUndefined();
      sameTypedArray(verified, message);
    });
    it('handles text, setting cty as "text/plain", and verifies with that as the text property and an encoding of that for payload.', async function () {
      let signature = await krypto.sign(keypair.privateKey, message),
          verified = await krypto.verify(keypair.publicKey, signature);
      expect(verified.protectedHeader.cty).toBe('text/plain');
      expect(verified.text).toBe(message);
      expect(verified.payload).toEqual(new TextEncoder().encode(message));
    });
    it('handles json, setting cty as "json", and verifies with that as json property, the string of that as the text property, and the encoding of that string for payload.', async function () {
      let message = {foo: 'bar'},
          signature = await krypto.sign(keypair.privateKey, message),
          verified = await krypto.verify(keypair.publicKey, signature);
      expect(verified.protectedHeader.cty).toBe('json');
      expect(verified.json).toEqual(message);
      expect(verified.text).toBe(JSON.stringify(message));
      expect(verified.payload).toEqual(new TextEncoder().encode(JSON.stringify(message)));
    });
    it('Uses specified headers if supplied, including cty.', async function () {
      let cty = 'text/html',
          iat = Date.now(),
          foo = 17,
          message = "<something else>",
          signature = await krypto.sign(keypair.privateKey, message, {cty, iat, foo}),
          verified = await krypto.verify(keypair.publicKey, signature);
      expect(verified.protectedHeader.cty).toBe(cty);
      expect(verified.protectedHeader.iat).toBe(iat);
      expect(verified.protectedHeader.foo).toBe(foo);
      expect(verified.text).toEqual(message);
    });
  });

  describe('encryption', function () {
    let keypair;
    beforeAll(async function () {
      keypair = await krypto.generateEncryptingKey();
    });
    it(`can work up through at least ${encryptableSize} bytes with an asymmetric keypair.`, async function () {
      // Public key encrypt will work up through 446 bytes, but the result will not decrypt.
      let message = makeMessage(encryptableSize),
          encrypted = await krypto.encrypt(keypair.publicKey, message),
          decrypted = await krypto.decrypt(keypair.privateKey, encrypted);
      isBase64URL(encrypted);
      expect(decrypted.text).toBe(message);
    }, slowHybrid);
    function testSymmetric(label, promise, decryptPromise = promise) {
      it(`can work on much larger data with a ${label}.`, async function () {
        let key = await promise,
            decryptKey = await decryptPromise,
            encrypted = await krypto.encrypt(key, message),
            decrypted = await krypto.decrypt(decryptKey, encrypted);
        isBase64URL(encrypted);
        expect(decrypted.text).toBe(message);
      });
    }
    testSymmetric('fixed symmetric key',
                  krypto.generateSymmetricKey());
    testSymmetric('reproducible secret',
                  krypto.generateSymmetricKey("secret"),
                  krypto.generateSymmetricKey("secret"));

    it('handles binary, and decrypts as same.', async function () {
      let message = new Uint8Array([21, 31]),
          encrypted = await krypto.encrypt(keypair.publicKey, message),
          decrypted = await krypto.decrypt(keypair.privateKey, encrypted),
          header = krypto.decodeProtectedHeader(encrypted);
      expect(header.cty).toBeUndefined();
      sameTypedArray(decrypted, message);
    });
    it('handles text, and decrypts as same.', async function () {
      let encrypted = await krypto.encrypt(keypair.publicKey, message),
          decrypted = await krypto.decrypt(keypair.privateKey, encrypted),
          header = krypto.decodeProtectedHeader(encrypted);
      expect(header.cty).toBe('text/plain');
      expect(decrypted.text).toBe(message);
    });
    it('handles json, and decrypts as same.', async function () {
      let message = {foo: 'bar'},
          encrypted = await krypto.encrypt(keypair.publicKey, message);
      let header = krypto.decodeProtectedHeader(encrypted),
          decrypted = await krypto.decrypt(keypair.privateKey, encrypted);
      expect(header.cty).toBe('json');
      expect(decrypted.json).toEqual(message);
    });
    it('Uses specified headers if supplied, including cty.', async function () {
      let cty = 'text/html',
          iat = Date.now(),
          foo = 17,
          message = "<something else>",
          encrypted = await krypto.encrypt(keypair.publicKey, message, {cty, iat, foo}),
          decrypted = await krypto.decrypt(keypair.privateKey, encrypted),
          header = krypto.decodeProtectedHeader(encrypted);
      expect(header.cty).toBe(cty);
      expect(header.iat).toBe(iat);
      expect(header.foo).toBe(foo);
      expect(decrypted.text).toBe(message);
    });
    
    function failsWithWrong(label, keysThunk) {
      it(`rejects wrong ${label}.`, async function() {
        let [encryptKey, decryptKey] = await keysThunk(),
            message = makeMessage(encryptableSize),
            encrypted = await krypto.encrypt(encryptKey, message);
        await expectAsync(krypto.decrypt(decryptKey, encrypted)).toBeRejected();
      }, slowKeyCreation);
    }
    failsWithWrong('asymmetric key', async () => [
      (await krypto.generateEncryptingKey()).publicKey,
      (await krypto.generateEncryptingKey()).privateKey
    ]);
    failsWithWrong('symmetric key', async () => [
      await krypto.generateSymmetricKey(),
      await krypto.generateSymmetricKey()
    ]);
    failsWithWrong('secret', async () => [
      await krypto.generateSymmetricKey("secret"),
      await krypto.generateSymmetricKey("secretX")
    ]);
  });

  describe('export/import', function () {
    // Handy for cycling in a size-checkable way.
    async function exportKey(key) {
      return JSON.stringify(await krypto.exportJWK(key));
    }
    function importKey(string) {
      return krypto.importJWK(JSON.parse(string));
    }

    describe(`of signing keys`, function () {
      const privateSigningSize = 253; // 248 raw
      it(`works with the private signing key as a ${privateSigningSize} byte serialization.`, async function () {
        let keypair = await krypto.generateSigningKey(),
            serializedPrivateKey = await exportKey(keypair.privateKey),
            importedPrivateKey = await importKey(serializedPrivateKey),
            signature = await krypto.sign(importedPrivateKey, message);
        expect(serializedPrivateKey.length).toBe(privateSigningSize);
        expect(await krypto.verify(keypair.publicKey, signature)).toBeTruthy();
      });
      const publicSigningSize = 182; // 132 raw
      it(`works with the public verifying key as a ${publicSigningSize} byte serialization.`, async function () {
        let keypair = await krypto.generateSigningKey(),
            serializedPublicKey = await exportKey(keypair.publicKey),
            importedPublicKey = await importKey(serializedPublicKey),
            signature = await krypto.sign(keypair.privateKey, message);
        expect(serializedPublicKey.length).toBe(publicSigningSize);
        expect(await krypto.verify(importedPublicKey, signature)).toBeTruthy();
      });

      const publicSigningRawSize = 132;
      it(`works with public key as a raw verifying key as a base64URL serialization of no more that ${publicSigningRawSize} bytes`, async function () {
        let keypair = await krypto.generateSigningKey(),
            serializedPublicKey = await krypto.exportRaw(keypair.publicKey),
            importedPublicKey = await krypto.importRaw(serializedPublicKey),
            signature = await krypto.sign(keypair.privateKey, message);
        isBase64URL(serializedPublicKey);
        expect(serializedPublicKey.length).toBeLessThanOrEqual(publicSigningRawSize);
        expect(await krypto.verify(importedPublicKey, signature)).toBeTruthy();
      });
    });

    describe('of encryption keys', function () {
      const privateEncryptingKeySize = [3169, 3173]; // raw [3164, 3168]; // with a 4k modulusSize key
      it(`works with the private key as a ${privateEncryptingKeySize[0]}-${privateEncryptingKeySize[1]} byte serialization.`, async function () {
        let keypair = await krypto.generateEncryptingKey(),
            serializedPrivateKey = await exportKey(keypair.privateKey),
            importedPrivateKey = await importKey(serializedPrivateKey),
            message = makeMessage(446),
            encrypted = await krypto.encrypt(keypair.publicKey, message),
            decrypted = await krypto.decrypt(importedPrivateKey, encrypted);
        expect(serializedPrivateKey.length).toBeGreaterThanOrEqual(privateEncryptingKeySize[0]);
        expect(serializedPrivateKey.length).toBeLessThanOrEqual(privateEncryptingKeySize[1]);
        expect(decrypted.text).toBe(message);
      });
      const publicEncryptingKeySize = 735; // raw 736; // with a 4k modulusSize key
      it(`works with the public key as a ${publicEncryptingKeySize} byte serialization.`, async function () {
        let keypair = await krypto.generateEncryptingKey(),
            serializedPublicKey = await exportKey(keypair.publicKey),
            importedPublicKey = await importKey(serializedPublicKey),
            message = makeMessage(446),
            encrypted = await krypto.encrypt(importedPublicKey, message),
            decrypted = await krypto.decrypt(keypair.privateKey, encrypted);
        expect(serializedPublicKey.length).toBe(publicEncryptingKeySize);
        expect(decrypted.text).toBe(message);
      });
    });

    describe('of symmetric key', function () {
      const symmetricKeySize = 79; // raw 44
      it(`works as a ${symmetricKeySize} byte serialization.`, async function () {
        let key = await krypto.generateSymmetricKey(),
            serializedKey = await exportKey(key),
            importedKey = await importKey(serializedKey),
            encrypted = await krypto.encrypt(key, message),
            decrypted = await krypto.decrypt(importedKey, encrypted);
        expect(serializedKey.length).toBe(symmetricKeySize);
        expect(decrypted.text).toBe(message);
      });
    });
  });

  it('wraps like export+encrypt.', async function () {
    // Let's "wrap" a symmetric key with an asymmetric encrypting key in two ways.
    let encryptableKey = await krypto.generateSymmetricKey(),
        wrappingKey = await krypto.generateEncryptingKey(),

        // Cycle it through export,encrypt to encrypted key, and decrypt,import to imported key.
        exported = await krypto.exportJWK(encryptableKey),
        encrypted = await krypto.encrypt(wrappingKey.publicKey, exported),
        decrypted = await krypto.decrypt(wrappingKey.privateKey, encrypted),
        imported = await krypto.importJWK(decrypted.json),

        // Cycle it through wrap and unwrap.
        wrapped = await krypto.wrapKey(encryptableKey, wrappingKey.publicKey),
        unwrapped = await krypto.unwrapKey(wrapped, wrappingKey.privateKey),

        // Use one to encrypt a message, and the other decrypt it.
        message = "this is a message",
        encryptedMessage = await krypto.encrypt(unwrapped, message),
        decryptedMessage = await krypto.decrypt(imported, encryptedMessage);
    isBase64URL(wrapped);
    expect(decryptedMessage.text).toBe(message);
  }, slowKeyCreation);
}

function testMultiKrypto(multiKrypto) {
  const slowKeyCreation = 20e3, // Android
        message = makeMessage();
  describe('falls through to krypto with single keys', function () {
    testKrypto(multiKrypto, scale);
  });

  describe('multi-way keys', function () {

    describe('multi-signature', function () {
      let signingA, signingB;
      beforeAll(async function () {
        signingA = await multiKrypto.generateSigningKey();
        signingB = await multiKrypto.generateSigningKey();
      });

      it('is a multi-signature.', async function () {
        let multiSign = {a: signingA.privateKey, b: signingB.privateKey},
            // Order doesn't matter. just that they correspond as a set.
            multiVerify = {b: signingB.publicKey, a: signingA.publicKey},
            signature = await multiKrypto.sign(multiSign, message),
            verified = await multiKrypto.verify(multiVerify, signature);
        expect(verified).toBeTruthy();
      });
      it('can specify type:"multi" in the signing key for clarify.', async function () {
        let multiSign = {a: signingA.privateKey, b: signingB.privateKey, type:'multi'},
            multiVerify = {a: signingA.publicKey, b: signingB.publicKey},
            signature = await multiKrypto.sign(multiSign, message),
            verified = await multiKrypto.verify(multiVerify, signature);
        expect(verified).toBeTruthy();
      });
      it('can specify type:"multi" in the verifying key for clarify.', async function () {
        let multiSign = {a: signingA.privateKey, b: signingB.privateKey},
            multiVerify = {a: signingA.publicKey, b: signingB.publicKey, type:'multi'},
            signature = await multiKrypto.sign(multiSign, message),
            verified = await multiKrypto.verify(multiVerify, signature);
        expect(verified).toBeTruthy();
      });
      it('can specify iss, act, iat in the key, which will appear in the signature.', async function () {
        let iat = Date.now(),
            iss = 'a',
            act = 'b',
            multiSign = {a: signingA.privateKey, b: signingB.privateKey},
            multiVerify = {a: signingA.publicKey, b: signingB.publicKey},
            signature = await multiKrypto.sign(multiSign, message, {iss, act, iat}),
            verified = await multiKrypto.verify(multiVerify, signature);
        expect(verified).toBeTruthy();
        signature.signatures.forEach(subSignature => {
          let header = multiKrypto.decodeProtectedHeader(subSignature);
          expect(header.iss).toBe(iss);
          expect(header.act).toBe(act);
          expect(header.iat).toBe(iat);
        });
      });
      it('can sign binary and it is recovery as binary from payload property of verfication.', async function () {
        let message = new Uint8Array([1], [2], [3]),
            signature = await multiKrypto.sign({a: signingA.privateKey, b: signingB.privateKey}, message),
            verified = await multiKrypto.verify({a: signingA.publicKey, b: signingB.publicKey}, signature);
        expect(verified.payload).toEqual(message);
      });
      it('can sign string type and it is recoverable as string from text property of verification.', async function () {
        let message = "a string",
            signature = await multiKrypto.sign({a: signingA.privateKey, b: signingB.privateKey}, message),
            verified = await multiKrypto.verify({a: signingA.publicKey, b: signingB.publicKey}, signature);
        expect(verified.text).toEqual(message);
        expect(verified.payload).toEqual(new TextEncoder().encode(message));
      });
      it('can sign a jsonable object and it is recovery as same from json property of result.', async function () {
        let message = {foo: "a string", bar: false, baz: ['a', 2, null]},
            signature = await multiKrypto.sign({a: signingA.privateKey, b: signingB.privateKey}, message),
            verified = await multiKrypto.verify({a: signingA.publicKey, b: signingB.publicKey}, signature);
        expect(verified.json).toEqual(message);
        expect(verified.payload).toEqual(new TextEncoder().encode(JSON.stringify(message)));
      });
      it('can specify a specific cty that will pass through to verify.', async function () {
        let message = {foo: "a string", bar: false, baz: ['a', 2, null]},
            cty = 'application/foo+json',
            signature = await multiKrypto.sign({a: signingA.privateKey, b: signingB.privateKey}, message, {cty}),
            verified = await multiKrypto.verify({a: signingA.publicKey, b: signingB.publicKey}, signature);
        expect(verified.json).toEqual(message);
        expect(verified.protectedHeader.cty).toBe(cty);
        expect(verified.payload).toEqual(new TextEncoder().encode(JSON.stringify(message)));
      });

      it('fails verification if the signature is mislabeled.',
         async function () {
           let multiSign = {a: signingB.privateKey, b: signingA.privateKey}, // Note that the values are not what is claimed.
               multiVerify = {a: signingA.publicKey, b: signingB.publicKey},
               signature = await multiKrypto.sign(multiSign, message),
               verified = await multiKrypto.verify(multiVerify, signature);
           expect(verified).toBeUndefined();
         });
      it('gives enough information that we can tell if a verifying sub key is missing.',
         async function () {
           let multiSign = {a: signingA.privateKey, b: signingB.privateKey},
               multiVerify = {b: signingB.publicKey}, // Missing a.
               signature = await multiKrypto.sign(multiSign, message),
               verified = await multiKrypto.verify(multiVerify, signature);
           // Overall, something we asked for did verify.
           expect(verified.payload).toBeTruthy();
           expect(verified.text).toBe(message);
           // b is second signer in signature
           expect(verified.signers[1].payload).toBeTruthy();
           // but the first signer was not verified
           expect(verified.signers[0].payload).toBeUndefined();
         });
      it('gives enough information that we can tell if a signature sub key is missing.',
         async function () {
           let multiSign = {a: signingA.privateKey}, // Missing b.
               multiVerify = {a: signingA.publicKey, b: signingB.publicKey},
               signature = await multiKrypto.sign(multiSign, message),
               verified = await multiKrypto.verify(multiVerify, signature);
           // Overall, something we asked for did verify.
           expect(verified.payload).toBeTruthy();
           expect(verified.text).toBe(message);
           // But only one signer
           expect(verified.signers.length).toBe(1);
           expect(verified.signers[0].protectedHeader.kid).toBe('a');
           expect(verified.signers[0].payload).toBeTruthy();
         });
    });

    describe('multi-way encryption', function () {
      let encrypted, keypair, symmetric, secretText = "shh!", recipients, encryptingMulti, decryptingMulti;
      beforeAll(async function () {
        symmetric = await multiKrypto.generateSymmetricKey();
        keypair = await multiKrypto.generateEncryptingKey();
        encrypted = await multiKrypto.encrypt({a: symmetric, b: keypair.publicKey, c: secretText}, message);
        recipients = encrypted.recipients;
        let otherKeypair = await multiKrypto.generateEncryptingKey();
        encryptingMulti = {a: keypair.publicKey, b: otherKeypair.publicKey};
        decryptingMulti = {a: keypair.privateKey, b: otherKeypair.privateKey};
      }, slowKeyCreation);
      it('works with symmetric members.', async function () {
        let decrypted = await multiKrypto.decrypt({a: symmetric}, encrypted);
        expect(decrypted.text).toBe(message);
        expect(recipients[0].header.kid).toBe('a');
        expect(recipients[0].header.alg).toBe('A256GCMKW');
      });
      it('works with keypair members.', async function () {
        let decrypted = await multiKrypto.decrypt({b: keypair.privateKey}, encrypted);
        expect(decrypted.text).toBe(message);
        expect(recipients[1].header.kid).toBe('b');
        expect(recipients[1].header.alg).toBe('RSA-OAEP-256');
      });
      it('works with secret text members.', async function () {
        let decrypted = await multiKrypto.decrypt({c: secretText}, encrypted);
        expect(decrypted.text).toBe(message);
        expect(recipients[2].header.kid).toBe('c');
        expect(recipients[2].header.alg).toBe('PBES2-HS512+A256KW');
      });

      it('handles binary, and decrypts as same.', async function () {
        let message = new Uint8Array([21, 31]),
            encrypted = await multiKrypto.encrypt(encryptingMulti, message),
            decrypted = await multiKrypto.decrypt(decryptingMulti, encrypted),
            header = multiKrypto.decodeProtectedHeader(encrypted);
        expect(header.cty).toBeUndefined();
        sameTypedArray(decrypted, message);
      });
      it('handles text, and decrypts as same.', async function () {
        let encrypted = await multiKrypto.encrypt(encryptingMulti, message),
            decrypted = await multiKrypto.decrypt(decryptingMulti, encrypted),
            header = multiKrypto.decodeProtectedHeader(encrypted);
        expect(header.cty).toBe('text/plain');
        expect(decrypted.text).toBe(message);
      });
      it('handles json, and decrypts as same.', async function () {
        let message = {foo: 'bar'},
            encrypted = await multiKrypto.encrypt(encryptingMulti, message);
        let header = multiKrypto.decodeProtectedHeader(encrypted),
            decrypted = await multiKrypto.decrypt(decryptingMulti, encrypted);
        expect(header.cty).toBe('json');
        expect(decrypted.json).toEqual(message);
      });
      it('Uses specified headers if supplied, including cty.', async function () {
        let cty = 'text/html',
            iat = Date.now(),
            foo = 17,
            message = "<something else>",
            encrypted = await multiKrypto.encrypt(encryptingMulti, message, {cty, iat, foo}),
            decrypted = await multiKrypto.decrypt(decryptingMulti, encrypted),
            header = multiKrypto.decodeProtectedHeader(encrypted);
        expect(header.cty).toBe(cty);
        expect(header.iat).toBe(iat);
        expect(header.foo).toBe(foo);
        expect(decrypted.text).toBe(message);
      });

      it('produces undefined for wrong symmetric key.', async function () {
        let anotherKey = await multiKrypto.generateSymmetricKey(),
            decrypted = await multiKrypto.decrypt({a: anotherKey}, encrypted);
        expect(decrypted).toBeUndefined();
      });
      it('produces undefined for wrong keypair.', async function () {
        let anotherKey = await multiKrypto.generateEncryptingKey(),
            decrypted = await multiKrypto.decrypt({b: anotherKey.privateKey}, encrypted);
        expect(decrypted).toBeUndefined();
      });
      it('produces undefined for wrong secret text.', async function () {
        let decrypted = await multiKrypto.decrypt({c: "shh! "}, encrypted); // Extra whitespace
        expect(decrypted).toBeUndefined();
      });
      it('produces undefined for mislabeled key.', async function () {
        let decrypted = await multiKrypto.decrypt({a: secretText}, encrypted); // should be c
        expect(decrypted).toBeUndefined();
      });
    });
  });

  describe('export/wrap', function () {
    let encryptingMultikey, decryptingMultikey;

    beforeAll(async function () {
      let keypair1 = await multiKrypto.generateEncryptingKey(),
          keypair2 = await multiKrypto.generateEncryptingKey(),
          keypair3 = await multiKrypto.generateEncryptingKey();
      encryptingMultikey = {a: keypair1.publicKey, b: keypair2.publicKey};
      decryptingMultikey = {c: keypair3.privateKey, b: keypair2.privateKey};
    }, slowKeyCreation);

    it('exports homogenous member.', async function () {
      let exported = await multiKrypto.exportJWK(encryptingMultikey),
          imported = await multiKrypto.importJWK(exported),
          // Now prove that the imported multikey works.
          encrypted = await multiKrypto.encrypt(imported, message),
          decrypted = await multiKrypto.decrypt(decryptingMultikey, encrypted);
      expect(exported.keys[0].kid).toBe('a');
      expect(exported.keys[1].kid).toBe('b');
      expect(decrypted.text).toBe(message);
    });
    it('export heterogenous members.', async function () {
      let encryptingKeypair = await multiKrypto.generateEncryptingKey(),
          signingKeypair = await multiKrypto.generateSigningKey(),
          exported = await multiKrypto.exportJWK({myDecrypt: encryptingKeypair.privateKey, mySign: signingKeypair.privateKey}),
          imported = await multiKrypto.importJWK(exported),
          // Now prove that the imported multikey works.
          message  = "a smaller message for asymmetric encryption", // Although JOSE always uses hybrid encryption anyway, so size isn't a problem.
          encrypted = await multiKrypto.encrypt(encryptingKeypair.publicKey, message),
          decrypted = await multiKrypto.decrypt(imported.myDecrypt, encrypted),
          signed = await multiKrypto.sign(imported.mySign, message);
      expect(exported.keys[0].kid).toBe('myDecrypt');
      expect(exported.keys[1].kid).toBe('mySign');
      expect(decrypted.text).toBe(message);
      expect(await multiKrypto.verify(signingKeypair.publicKey, signed)).toBeTruthy();
    }, 10e3);

    it('can wrap/unwrap a simple key.', async function () {
      let key = await multiKrypto.generateSymmetricKey(),
          wrapped = await multiKrypto.wrapKey(key, encryptingMultikey),
          unwrapped = await multiKrypto.unwrapKey(wrapped, decryptingMultikey),
          // Cool, now prove that worked.
          encrypted = await multiKrypto.encrypt(unwrapped, message),
          decrypted = await multiKrypto.decrypt(key, encrypted);
      expect(decrypted.text).toBe(message);
    });
    it('can be wrapped/unwrapped by a symmetric key with homogenous members.', async function () {
      let wrappingKey = await multiKrypto.generateSymmetricKey(),
          wrapped = await multiKrypto.wrapKey(encryptingMultikey, wrappingKey),
          unwrapped = await multiKrypto.unwrapKey(wrapped, wrappingKey),
          // Cool, now prove that worked.
          encrypted = await multiKrypto.encrypt(unwrapped, message),
          decrypted = await multiKrypto.decrypt(decryptingMultikey, encrypted);
      expect(decrypted.text).toBe(message);
    });
    it('can wrap/unwrap a symmetric multikey with homogenous members.', async function () {
      let key = {x: await multiKrypto.generateSymmetricKey(), y: await multiKrypto.generateSymmetricKey()},
          wrapped = await multiKrypto.wrapKey(key, encryptingMultikey),
          unwrapped = await multiKrypto.unwrapKey(wrapped, decryptingMultikey),
          // Cool, now prove that worked.
          message = makeMessage(),
          encrypted = await multiKrypto.encrypt(unwrapped, message),
          decrypted = await multiKrypto.decrypt(key, encrypted);
      expect(decrypted.text).toBe(message);
    });
    it('can wrap/unwrap a heterogeneous multikey.', async function () {
      let encryptingKeypair = await multiKrypto.generateEncryptingKey(),
          signingKeypair = await multiKrypto.generateSigningKey(),
          wrapped = await multiKrypto.wrapKey({myDecrypt: encryptingKeypair.privateKey, mySign: signingKeypair.privateKey}, encryptingMultikey),
          unwrapped = await multiKrypto.unwrapKey(wrapped, decryptingMultikey),
          // Cool, now prove that worked.
          message = "a shorter message",
          encrypted = await multiKrypto.encrypt(encryptingKeypair.publicKey, message),
          decrypted = await multiKrypto.decrypt(unwrapped.myDecrypt, encrypted),
          signature = await multiKrypto.sign(unwrapped.mySign, message);
      expect(decrypted.text).toBe(message),
      expect(await multiKrypto.verify(signingKeypair.publicKey, signature)).toBeTruthy();
    }, slowKeyCreation);
  });
}

var crypto$1 = crypto;
const isCryptoKey = (key) => key instanceof CryptoKey;

const digest$1 = async (algorithm, data) => {
    const subtleDigest = `SHA-${algorithm.slice(-3)}`;
    return new Uint8Array(await crypto$1.subtle.digest(subtleDigest, data));
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const MAX_INT32 = 2 ** 32;
function concat(...buffers) {
    const size = buffers.reduce((acc, { length }) => acc + length, 0);
    const buf = new Uint8Array(size);
    let i = 0;
    for (const buffer of buffers) {
        buf.set(buffer, i);
        i += buffer.length;
    }
    return buf;
}
function p2s(alg, p2sInput) {
    return concat(encoder.encode(alg), new Uint8Array([0]), p2sInput);
}
function writeUInt32BE(buf, value, offset) {
    if (value < 0 || value >= MAX_INT32) {
        throw new RangeError(`value must be >= 0 and <= ${MAX_INT32 - 1}. Received ${value}`);
    }
    buf.set([value >>> 24, value >>> 16, value >>> 8, value & 0xff], offset);
}
function uint64be(value) {
    const high = Math.floor(value / MAX_INT32);
    const low = value % MAX_INT32;
    const buf = new Uint8Array(8);
    writeUInt32BE(buf, high, 0);
    writeUInt32BE(buf, low, 4);
    return buf;
}
function uint32be(value) {
    const buf = new Uint8Array(4);
    writeUInt32BE(buf, value);
    return buf;
}
function lengthAndInput(input) {
    return concat(uint32be(input.length), input);
}
async function concatKdf(secret, bits, value) {
    const iterations = Math.ceil((bits >> 3) / 32);
    const res = new Uint8Array(iterations * 32);
    for (let iter = 0; iter < iterations; iter++) {
        const buf = new Uint8Array(4 + secret.length + value.length);
        buf.set(uint32be(iter + 1));
        buf.set(secret, 4);
        buf.set(value, 4 + secret.length);
        res.set(await digest$1('sha256', buf), iter * 32);
    }
    return res.slice(0, bits >> 3);
}

const encodeBase64 = (input) => {
    let unencoded = input;
    if (typeof unencoded === 'string') {
        unencoded = encoder.encode(unencoded);
    }
    const CHUNK_SIZE = 0x8000;
    const arr = [];
    for (let i = 0; i < unencoded.length; i += CHUNK_SIZE) {
        arr.push(String.fromCharCode.apply(null, unencoded.subarray(i, i + CHUNK_SIZE)));
    }
    return btoa(arr.join(''));
};
const encode$1 = (input) => {
    return encodeBase64(input).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
};
const decodeBase64 = (encoded) => {
    const binary = atob(encoded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
};
const decode$1 = (input) => {
    let encoded = input;
    if (encoded instanceof Uint8Array) {
        encoded = decoder.decode(encoded);
    }
    encoded = encoded.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
    try {
        return decodeBase64(encoded);
    }
    catch {
        throw new TypeError('The input to be decoded is not correctly encoded.');
    }
};

class JOSEError extends Error {
    static get code() {
        return 'ERR_JOSE_GENERIC';
    }
    constructor(message) {
        super(message);
        this.code = 'ERR_JOSE_GENERIC';
        this.name = this.constructor.name;
        Error.captureStackTrace?.(this, this.constructor);
    }
}
class JOSEAlgNotAllowed extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JOSE_ALG_NOT_ALLOWED';
    }
    static get code() {
        return 'ERR_JOSE_ALG_NOT_ALLOWED';
    }
}
class JOSENotSupported extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JOSE_NOT_SUPPORTED';
    }
    static get code() {
        return 'ERR_JOSE_NOT_SUPPORTED';
    }
}
class JWEDecryptionFailed extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWE_DECRYPTION_FAILED';
        this.message = 'decryption operation failed';
    }
    static get code() {
        return 'ERR_JWE_DECRYPTION_FAILED';
    }
}
class JWEInvalid extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWE_INVALID';
    }
    static get code() {
        return 'ERR_JWE_INVALID';
    }
}
class JWSInvalid extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWS_INVALID';
    }
    static get code() {
        return 'ERR_JWS_INVALID';
    }
}
class JWSSignatureVerificationFailed extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED';
        this.message = 'signature verification failed';
    }
    static get code() {
        return 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED';
    }
}

var random = crypto$1.getRandomValues.bind(crypto$1);

function bitLength$1(alg) {
    switch (alg) {
        case 'A128GCM':
        case 'A128GCMKW':
        case 'A192GCM':
        case 'A192GCMKW':
        case 'A256GCM':
        case 'A256GCMKW':
            return 96;
        case 'A128CBC-HS256':
        case 'A192CBC-HS384':
        case 'A256CBC-HS512':
            return 128;
        default:
            throw new JOSENotSupported(`Unsupported JWE Algorithm: ${alg}`);
    }
}
var generateIv = (alg) => random(new Uint8Array(bitLength$1(alg) >> 3));

const checkIvLength = (enc, iv) => {
    if (iv.length << 3 !== bitLength$1(enc)) {
        throw new JWEInvalid('Invalid Initialization Vector length');
    }
};

const checkCekLength = (cek, expected) => {
    const actual = cek.byteLength << 3;
    if (actual !== expected) {
        throw new JWEInvalid(`Invalid Content Encryption Key length. Expected ${expected} bits, got ${actual} bits`);
    }
};

const timingSafeEqual = (a, b) => {
    if (!(a instanceof Uint8Array)) {
        throw new TypeError('First argument must be a buffer');
    }
    if (!(b instanceof Uint8Array)) {
        throw new TypeError('Second argument must be a buffer');
    }
    if (a.length !== b.length) {
        throw new TypeError('Input buffers must have the same length');
    }
    const len = a.length;
    let out = 0;
    let i = -1;
    while (++i < len) {
        out |= a[i] ^ b[i];
    }
    return out === 0;
};

function unusable(name, prop = 'algorithm.name') {
    return new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
}
function isAlgorithm(algorithm, name) {
    return algorithm.name === name;
}
function getHashLength(hash) {
    return parseInt(hash.name.slice(4), 10);
}
function getNamedCurve(alg) {
    switch (alg) {
        case 'ES256':
            return 'P-256';
        case 'ES384':
            return 'P-384';
        case 'ES512':
            return 'P-521';
        default:
            throw new Error('unreachable');
    }
}
function checkUsage(key, usages) {
    if (usages.length && !usages.some((expected) => key.usages.includes(expected))) {
        let msg = 'CryptoKey does not support this operation, its usages must include ';
        if (usages.length > 2) {
            const last = usages.pop();
            msg += `one of ${usages.join(', ')}, or ${last}.`;
        }
        else if (usages.length === 2) {
            msg += `one of ${usages[0]} or ${usages[1]}.`;
        }
        else {
            msg += `${usages[0]}.`;
        }
        throw new TypeError(msg);
    }
}
function checkSigCryptoKey(key, alg, ...usages) {
    switch (alg) {
        case 'HS256':
        case 'HS384':
        case 'HS512': {
            if (!isAlgorithm(key.algorithm, 'HMAC'))
                throw unusable('HMAC');
            const expected = parseInt(alg.slice(2), 10);
            const actual = getHashLength(key.algorithm.hash);
            if (actual !== expected)
                throw unusable(`SHA-${expected}`, 'algorithm.hash');
            break;
        }
        case 'RS256':
        case 'RS384':
        case 'RS512': {
            if (!isAlgorithm(key.algorithm, 'RSASSA-PKCS1-v1_5'))
                throw unusable('RSASSA-PKCS1-v1_5');
            const expected = parseInt(alg.slice(2), 10);
            const actual = getHashLength(key.algorithm.hash);
            if (actual !== expected)
                throw unusable(`SHA-${expected}`, 'algorithm.hash');
            break;
        }
        case 'PS256':
        case 'PS384':
        case 'PS512': {
            if (!isAlgorithm(key.algorithm, 'RSA-PSS'))
                throw unusable('RSA-PSS');
            const expected = parseInt(alg.slice(2), 10);
            const actual = getHashLength(key.algorithm.hash);
            if (actual !== expected)
                throw unusable(`SHA-${expected}`, 'algorithm.hash');
            break;
        }
        case 'EdDSA': {
            if (key.algorithm.name !== 'Ed25519' && key.algorithm.name !== 'Ed448') {
                throw unusable('Ed25519 or Ed448');
            }
            break;
        }
        case 'ES256':
        case 'ES384':
        case 'ES512': {
            if (!isAlgorithm(key.algorithm, 'ECDSA'))
                throw unusable('ECDSA');
            const expected = getNamedCurve(alg);
            const actual = key.algorithm.namedCurve;
            if (actual !== expected)
                throw unusable(expected, 'algorithm.namedCurve');
            break;
        }
        default:
            throw new TypeError('CryptoKey does not support this operation');
    }
    checkUsage(key, usages);
}
function checkEncCryptoKey(key, alg, ...usages) {
    switch (alg) {
        case 'A128GCM':
        case 'A192GCM':
        case 'A256GCM': {
            if (!isAlgorithm(key.algorithm, 'AES-GCM'))
                throw unusable('AES-GCM');
            const expected = parseInt(alg.slice(1, 4), 10);
            const actual = key.algorithm.length;
            if (actual !== expected)
                throw unusable(expected, 'algorithm.length');
            break;
        }
        case 'A128KW':
        case 'A192KW':
        case 'A256KW': {
            if (!isAlgorithm(key.algorithm, 'AES-KW'))
                throw unusable('AES-KW');
            const expected = parseInt(alg.slice(1, 4), 10);
            const actual = key.algorithm.length;
            if (actual !== expected)
                throw unusable(expected, 'algorithm.length');
            break;
        }
        case 'ECDH': {
            switch (key.algorithm.name) {
                case 'ECDH':
                case 'X25519':
                case 'X448':
                    break;
                default:
                    throw unusable('ECDH, X25519, or X448');
            }
            break;
        }
        case 'PBES2-HS256+A128KW':
        case 'PBES2-HS384+A192KW':
        case 'PBES2-HS512+A256KW':
            if (!isAlgorithm(key.algorithm, 'PBKDF2'))
                throw unusable('PBKDF2');
            break;
        case 'RSA-OAEP':
        case 'RSA-OAEP-256':
        case 'RSA-OAEP-384':
        case 'RSA-OAEP-512': {
            if (!isAlgorithm(key.algorithm, 'RSA-OAEP'))
                throw unusable('RSA-OAEP');
            const expected = parseInt(alg.slice(9), 10) || 1;
            const actual = getHashLength(key.algorithm.hash);
            if (actual !== expected)
                throw unusable(`SHA-${expected}`, 'algorithm.hash');
            break;
        }
        default:
            throw new TypeError('CryptoKey does not support this operation');
    }
    checkUsage(key, usages);
}

function message(msg, actual, ...types) {
    if (types.length > 2) {
        const last = types.pop();
        msg += `one of type ${types.join(', ')}, or ${last}.`;
    }
    else if (types.length === 2) {
        msg += `one of type ${types[0]} or ${types[1]}.`;
    }
    else {
        msg += `of type ${types[0]}.`;
    }
    if (actual == null) {
        msg += ` Received ${actual}`;
    }
    else if (typeof actual === 'function' && actual.name) {
        msg += ` Received function ${actual.name}`;
    }
    else if (typeof actual === 'object' && actual != null) {
        if (actual.constructor?.name) {
            msg += ` Received an instance of ${actual.constructor.name}`;
        }
    }
    return msg;
}
var invalidKeyInput = (actual, ...types) => {
    return message('Key must be ', actual, ...types);
};
function withAlg(alg, actual, ...types) {
    return message(`Key for the ${alg} algorithm must be `, actual, ...types);
}

var isKeyLike = (key) => {
    return isCryptoKey(key);
};
const types = ['CryptoKey'];

async function cbcDecrypt(enc, cek, ciphertext, iv, tag, aad) {
    if (!(cek instanceof Uint8Array)) {
        throw new TypeError(invalidKeyInput(cek, 'Uint8Array'));
    }
    const keySize = parseInt(enc.slice(1, 4), 10);
    const encKey = await crypto$1.subtle.importKey('raw', cek.subarray(keySize >> 3), 'AES-CBC', false, ['decrypt']);
    const macKey = await crypto$1.subtle.importKey('raw', cek.subarray(0, keySize >> 3), {
        hash: `SHA-${keySize << 1}`,
        name: 'HMAC',
    }, false, ['sign']);
    const macData = concat(aad, iv, ciphertext, uint64be(aad.length << 3));
    const expectedTag = new Uint8Array((await crypto$1.subtle.sign('HMAC', macKey, macData)).slice(0, keySize >> 3));
    let macCheckPassed;
    try {
        macCheckPassed = timingSafeEqual(tag, expectedTag);
    }
    catch {
    }
    if (!macCheckPassed) {
        throw new JWEDecryptionFailed();
    }
    let plaintext;
    try {
        plaintext = new Uint8Array(await crypto$1.subtle.decrypt({ iv, name: 'AES-CBC' }, encKey, ciphertext));
    }
    catch {
    }
    if (!plaintext) {
        throw new JWEDecryptionFailed();
    }
    return plaintext;
}
async function gcmDecrypt(enc, cek, ciphertext, iv, tag, aad) {
    let encKey;
    if (cek instanceof Uint8Array) {
        encKey = await crypto$1.subtle.importKey('raw', cek, 'AES-GCM', false, ['decrypt']);
    }
    else {
        checkEncCryptoKey(cek, enc, 'decrypt');
        encKey = cek;
    }
    try {
        return new Uint8Array(await crypto$1.subtle.decrypt({
            additionalData: aad,
            iv,
            name: 'AES-GCM',
            tagLength: 128,
        }, encKey, concat(ciphertext, tag)));
    }
    catch {
        throw new JWEDecryptionFailed();
    }
}
const decrypt$2 = async (enc, cek, ciphertext, iv, tag, aad) => {
    if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
        throw new TypeError(invalidKeyInput(cek, ...types, 'Uint8Array'));
    }
    if (!iv) {
        throw new JWEInvalid('JWE Initialization Vector missing');
    }
    if (!tag) {
        throw new JWEInvalid('JWE Authentication Tag missing');
    }
    checkIvLength(enc, iv);
    switch (enc) {
        case 'A128CBC-HS256':
        case 'A192CBC-HS384':
        case 'A256CBC-HS512':
            if (cek instanceof Uint8Array)
                checkCekLength(cek, parseInt(enc.slice(-3), 10));
            return cbcDecrypt(enc, cek, ciphertext, iv, tag, aad);
        case 'A128GCM':
        case 'A192GCM':
        case 'A256GCM':
            if (cek instanceof Uint8Array)
                checkCekLength(cek, parseInt(enc.slice(1, 4), 10));
            return gcmDecrypt(enc, cek, ciphertext, iv, tag, aad);
        default:
            throw new JOSENotSupported('Unsupported JWE Content Encryption Algorithm');
    }
};

const isDisjoint = (...headers) => {
    const sources = headers.filter(Boolean);
    if (sources.length === 0 || sources.length === 1) {
        return true;
    }
    let acc;
    for (const header of sources) {
        const parameters = Object.keys(header);
        if (!acc || acc.size === 0) {
            acc = new Set(parameters);
            continue;
        }
        for (const parameter of parameters) {
            if (acc.has(parameter)) {
                return false;
            }
            acc.add(parameter);
        }
    }
    return true;
};

function isObjectLike(value) {
    return typeof value === 'object' && value !== null;
}
function isObject(input) {
    if (!isObjectLike(input) || Object.prototype.toString.call(input) !== '[object Object]') {
        return false;
    }
    if (Object.getPrototypeOf(input) === null) {
        return true;
    }
    let proto = input;
    while (Object.getPrototypeOf(proto) !== null) {
        proto = Object.getPrototypeOf(proto);
    }
    return Object.getPrototypeOf(input) === proto;
}

const bogusWebCrypto = [
    { hash: 'SHA-256', name: 'HMAC' },
    true,
    ['sign'],
];

function checkKeySize(key, alg) {
    if (key.algorithm.length !== parseInt(alg.slice(1, 4), 10)) {
        throw new TypeError(`Invalid key size for alg: ${alg}`);
    }
}
function getCryptoKey$2(key, alg, usage) {
    if (isCryptoKey(key)) {
        checkEncCryptoKey(key, alg, usage);
        return key;
    }
    if (key instanceof Uint8Array) {
        return crypto$1.subtle.importKey('raw', key, 'AES-KW', true, [usage]);
    }
    throw new TypeError(invalidKeyInput(key, ...types, 'Uint8Array'));
}
const wrap$1 = async (alg, key, cek) => {
    const cryptoKey = await getCryptoKey$2(key, alg, 'wrapKey');
    checkKeySize(cryptoKey, alg);
    const cryptoKeyCek = await crypto$1.subtle.importKey('raw', cek, ...bogusWebCrypto);
    return new Uint8Array(await crypto$1.subtle.wrapKey('raw', cryptoKeyCek, cryptoKey, 'AES-KW'));
};
const unwrap$1 = async (alg, key, encryptedKey) => {
    const cryptoKey = await getCryptoKey$2(key, alg, 'unwrapKey');
    checkKeySize(cryptoKey, alg);
    const cryptoKeyCek = await crypto$1.subtle.unwrapKey('raw', encryptedKey, cryptoKey, 'AES-KW', ...bogusWebCrypto);
    return new Uint8Array(await crypto$1.subtle.exportKey('raw', cryptoKeyCek));
};

async function deriveKey$1(publicKey, privateKey, algorithm, keyLength, apu = new Uint8Array(0), apv = new Uint8Array(0)) {
    if (!isCryptoKey(publicKey)) {
        throw new TypeError(invalidKeyInput(publicKey, ...types));
    }
    checkEncCryptoKey(publicKey, 'ECDH');
    if (!isCryptoKey(privateKey)) {
        throw new TypeError(invalidKeyInput(privateKey, ...types));
    }
    checkEncCryptoKey(privateKey, 'ECDH', 'deriveBits');
    const value = concat(lengthAndInput(encoder.encode(algorithm)), lengthAndInput(apu), lengthAndInput(apv), uint32be(keyLength));
    let length;
    if (publicKey.algorithm.name === 'X25519') {
        length = 256;
    }
    else if (publicKey.algorithm.name === 'X448') {
        length = 448;
    }
    else {
        length =
            Math.ceil(parseInt(publicKey.algorithm.namedCurve.substr(-3), 10) / 8) << 3;
    }
    const sharedSecret = new Uint8Array(await crypto$1.subtle.deriveBits({
        name: publicKey.algorithm.name,
        public: publicKey,
    }, privateKey, length));
    return concatKdf(sharedSecret, keyLength, value);
}
async function generateEpk(key) {
    if (!isCryptoKey(key)) {
        throw new TypeError(invalidKeyInput(key, ...types));
    }
    return crypto$1.subtle.generateKey(key.algorithm, true, ['deriveBits']);
}
function ecdhAllowed(key) {
    if (!isCryptoKey(key)) {
        throw new TypeError(invalidKeyInput(key, ...types));
    }
    return (['P-256', 'P-384', 'P-521'].includes(key.algorithm.namedCurve) ||
        key.algorithm.name === 'X25519' ||
        key.algorithm.name === 'X448');
}

function checkP2s(p2s) {
    if (!(p2s instanceof Uint8Array) || p2s.length < 8) {
        throw new JWEInvalid('PBES2 Salt Input must be 8 or more octets');
    }
}

function getCryptoKey$1(key, alg) {
    if (key instanceof Uint8Array) {
        return crypto$1.subtle.importKey('raw', key, 'PBKDF2', false, ['deriveBits']);
    }
    if (isCryptoKey(key)) {
        checkEncCryptoKey(key, alg, 'deriveBits', 'deriveKey');
        return key;
    }
    throw new TypeError(invalidKeyInput(key, ...types, 'Uint8Array'));
}
async function deriveKey(p2s$1, alg, p2c, key) {
    checkP2s(p2s$1);
    const salt = p2s(alg, p2s$1);
    const keylen = parseInt(alg.slice(13, 16), 10);
    const subtleAlg = {
        hash: `SHA-${alg.slice(8, 11)}`,
        iterations: p2c,
        name: 'PBKDF2',
        salt,
    };
    const wrapAlg = {
        length: keylen,
        name: 'AES-KW',
    };
    const cryptoKey = await getCryptoKey$1(key, alg);
    if (cryptoKey.usages.includes('deriveBits')) {
        return new Uint8Array(await crypto$1.subtle.deriveBits(subtleAlg, cryptoKey, keylen));
    }
    if (cryptoKey.usages.includes('deriveKey')) {
        return crypto$1.subtle.deriveKey(subtleAlg, cryptoKey, wrapAlg, false, ['wrapKey', 'unwrapKey']);
    }
    throw new TypeError('PBKDF2 key "usages" must include "deriveBits" or "deriveKey"');
}
const encrypt$2 = async (alg, key, cek, p2c = 2048, p2s = random(new Uint8Array(16))) => {
    const derived = await deriveKey(p2s, alg, p2c, key);
    const encryptedKey = await wrap$1(alg.slice(-6), derived, cek);
    return { encryptedKey, p2c, p2s: encode$1(p2s) };
};
const decrypt$1 = async (alg, key, encryptedKey, p2c, p2s) => {
    const derived = await deriveKey(p2s, alg, p2c, key);
    return unwrap$1(alg.slice(-6), derived, encryptedKey);
};

function subtleRsaEs(alg) {
    switch (alg) {
        case 'RSA-OAEP':
        case 'RSA-OAEP-256':
        case 'RSA-OAEP-384':
        case 'RSA-OAEP-512':
            return 'RSA-OAEP';
        default:
            throw new JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
    }
}

var checkKeyLength = (alg, key) => {
    if (alg.startsWith('RS') || alg.startsWith('PS')) {
        const { modulusLength } = key.algorithm;
        if (typeof modulusLength !== 'number' || modulusLength < 2048) {
            throw new TypeError(`${alg} requires key modulusLength to be 2048 bits or larger`);
        }
    }
};

const encrypt$1 = async (alg, key, cek) => {
    if (!isCryptoKey(key)) {
        throw new TypeError(invalidKeyInput(key, ...types));
    }
    checkEncCryptoKey(key, alg, 'encrypt', 'wrapKey');
    checkKeyLength(alg, key);
    if (key.usages.includes('encrypt')) {
        return new Uint8Array(await crypto$1.subtle.encrypt(subtleRsaEs(alg), key, cek));
    }
    if (key.usages.includes('wrapKey')) {
        const cryptoKeyCek = await crypto$1.subtle.importKey('raw', cek, ...bogusWebCrypto);
        return new Uint8Array(await crypto$1.subtle.wrapKey('raw', cryptoKeyCek, key, subtleRsaEs(alg)));
    }
    throw new TypeError('RSA-OAEP key "usages" must include "encrypt" or "wrapKey" for this operation');
};
const decrypt = async (alg, key, encryptedKey) => {
    if (!isCryptoKey(key)) {
        throw new TypeError(invalidKeyInput(key, ...types));
    }
    checkEncCryptoKey(key, alg, 'decrypt', 'unwrapKey');
    checkKeyLength(alg, key);
    if (key.usages.includes('decrypt')) {
        return new Uint8Array(await crypto$1.subtle.decrypt(subtleRsaEs(alg), key, encryptedKey));
    }
    if (key.usages.includes('unwrapKey')) {
        const cryptoKeyCek = await crypto$1.subtle.unwrapKey('raw', encryptedKey, key, subtleRsaEs(alg), ...bogusWebCrypto);
        return new Uint8Array(await crypto$1.subtle.exportKey('raw', cryptoKeyCek));
    }
    throw new TypeError('RSA-OAEP key "usages" must include "decrypt" or "unwrapKey" for this operation');
};

function bitLength(alg) {
    switch (alg) {
        case 'A128GCM':
            return 128;
        case 'A192GCM':
            return 192;
        case 'A256GCM':
        case 'A128CBC-HS256':
            return 256;
        case 'A192CBC-HS384':
            return 384;
        case 'A256CBC-HS512':
            return 512;
        default:
            throw new JOSENotSupported(`Unsupported JWE Algorithm: ${alg}`);
    }
}
var generateCek = (alg) => random(new Uint8Array(bitLength(alg) >> 3));

function subtleMapping(jwk) {
    let algorithm;
    let keyUsages;
    switch (jwk.kty) {
        case 'RSA': {
            switch (jwk.alg) {
                case 'PS256':
                case 'PS384':
                case 'PS512':
                    algorithm = { name: 'RSA-PSS', hash: `SHA-${jwk.alg.slice(-3)}` };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                case 'RS256':
                case 'RS384':
                case 'RS512':
                    algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: `SHA-${jwk.alg.slice(-3)}` };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                case 'RSA-OAEP':
                case 'RSA-OAEP-256':
                case 'RSA-OAEP-384':
                case 'RSA-OAEP-512':
                    algorithm = {
                        name: 'RSA-OAEP',
                        hash: `SHA-${parseInt(jwk.alg.slice(-3), 10) || 1}`,
                    };
                    keyUsages = jwk.d ? ['decrypt', 'unwrapKey'] : ['encrypt', 'wrapKey'];
                    break;
                default:
                    throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
            }
            break;
        }
        case 'EC': {
            switch (jwk.alg) {
                case 'ES256':
                    algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                case 'ES384':
                    algorithm = { name: 'ECDSA', namedCurve: 'P-384' };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                case 'ES512':
                    algorithm = { name: 'ECDSA', namedCurve: 'P-521' };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                case 'ECDH-ES':
                case 'ECDH-ES+A128KW':
                case 'ECDH-ES+A192KW':
                case 'ECDH-ES+A256KW':
                    algorithm = { name: 'ECDH', namedCurve: jwk.crv };
                    keyUsages = jwk.d ? ['deriveBits'] : [];
                    break;
                default:
                    throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
            }
            break;
        }
        case 'OKP': {
            switch (jwk.alg) {
                case 'EdDSA':
                    algorithm = { name: jwk.crv };
                    keyUsages = jwk.d ? ['sign'] : ['verify'];
                    break;
                case 'ECDH-ES':
                case 'ECDH-ES+A128KW':
                case 'ECDH-ES+A192KW':
                case 'ECDH-ES+A256KW':
                    algorithm = { name: jwk.crv };
                    keyUsages = jwk.d ? ['deriveBits'] : [];
                    break;
                default:
                    throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
            }
            break;
        }
        default:
            throw new JOSENotSupported('Invalid or unsupported JWK "kty" (Key Type) Parameter value');
    }
    return { algorithm, keyUsages };
}
const parse = async (jwk) => {
    if (!jwk.alg) {
        throw new TypeError('"alg" argument is required when "jwk.alg" is not present');
    }
    const { algorithm, keyUsages } = subtleMapping(jwk);
    const rest = [
        algorithm,
        jwk.ext ?? false,
        jwk.key_ops ?? keyUsages,
    ];
    const keyData = { ...jwk };
    delete keyData.alg;
    delete keyData.use;
    return crypto$1.subtle.importKey('jwk', keyData, ...rest);
};
var asKeyObject = parse;

async function importJWK(jwk, alg) {
    if (!isObject(jwk)) {
        throw new TypeError('JWK must be an object');
    }
    alg || (alg = jwk.alg);
    switch (jwk.kty) {
        case 'oct':
            if (typeof jwk.k !== 'string' || !jwk.k) {
                throw new TypeError('missing "k" (Key Value) Parameter value');
            }
            return decode$1(jwk.k);
        case 'RSA':
            if (jwk.oth !== undefined) {
                throw new JOSENotSupported('RSA JWK "oth" (Other Primes Info) Parameter value is not supported');
            }
        case 'EC':
        case 'OKP':
            return asKeyObject({ ...jwk, alg });
        default:
            throw new JOSENotSupported('Unsupported "kty" (Key Type) Parameter value');
    }
}

const symmetricTypeCheck = (alg, key) => {
    if (key instanceof Uint8Array)
        return;
    if (!isKeyLike(key)) {
        throw new TypeError(withAlg(alg, key, ...types, 'Uint8Array'));
    }
    if (key.type !== 'secret') {
        throw new TypeError(`${types.join(' or ')} instances for symmetric algorithms must be of type "secret"`);
    }
};
const asymmetricTypeCheck = (alg, key, usage) => {
    if (!isKeyLike(key)) {
        throw new TypeError(withAlg(alg, key, ...types));
    }
    if (key.type === 'secret') {
        throw new TypeError(`${types.join(' or ')} instances for asymmetric algorithms must not be of type "secret"`);
    }
    if (usage === 'sign' && key.type === 'public') {
        throw new TypeError(`${types.join(' or ')} instances for asymmetric algorithm signing must be of type "private"`);
    }
    if (usage === 'decrypt' && key.type === 'public') {
        throw new TypeError(`${types.join(' or ')} instances for asymmetric algorithm decryption must be of type "private"`);
    }
    if (key.algorithm && usage === 'verify' && key.type === 'private') {
        throw new TypeError(`${types.join(' or ')} instances for asymmetric algorithm verifying must be of type "public"`);
    }
    if (key.algorithm && usage === 'encrypt' && key.type === 'private') {
        throw new TypeError(`${types.join(' or ')} instances for asymmetric algorithm encryption must be of type "public"`);
    }
};
const checkKeyType = (alg, key, usage) => {
    const symmetric = alg.startsWith('HS') ||
        alg === 'dir' ||
        alg.startsWith('PBES2') ||
        /^A\d{3}(?:GCM)?KW$/.test(alg);
    if (symmetric) {
        symmetricTypeCheck(alg, key);
    }
    else {
        asymmetricTypeCheck(alg, key, usage);
    }
};

async function cbcEncrypt(enc, plaintext, cek, iv, aad) {
    if (!(cek instanceof Uint8Array)) {
        throw new TypeError(invalidKeyInput(cek, 'Uint8Array'));
    }
    const keySize = parseInt(enc.slice(1, 4), 10);
    const encKey = await crypto$1.subtle.importKey('raw', cek.subarray(keySize >> 3), 'AES-CBC', false, ['encrypt']);
    const macKey = await crypto$1.subtle.importKey('raw', cek.subarray(0, keySize >> 3), {
        hash: `SHA-${keySize << 1}`,
        name: 'HMAC',
    }, false, ['sign']);
    const ciphertext = new Uint8Array(await crypto$1.subtle.encrypt({
        iv,
        name: 'AES-CBC',
    }, encKey, plaintext));
    const macData = concat(aad, iv, ciphertext, uint64be(aad.length << 3));
    const tag = new Uint8Array((await crypto$1.subtle.sign('HMAC', macKey, macData)).slice(0, keySize >> 3));
    return { ciphertext, tag, iv };
}
async function gcmEncrypt(enc, plaintext, cek, iv, aad) {
    let encKey;
    if (cek instanceof Uint8Array) {
        encKey = await crypto$1.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
    }
    else {
        checkEncCryptoKey(cek, enc, 'encrypt');
        encKey = cek;
    }
    const encrypted = new Uint8Array(await crypto$1.subtle.encrypt({
        additionalData: aad,
        iv,
        name: 'AES-GCM',
        tagLength: 128,
    }, encKey, plaintext));
    const tag = encrypted.slice(-16);
    const ciphertext = encrypted.slice(0, -16);
    return { ciphertext, tag, iv };
}
const encrypt = async (enc, plaintext, cek, iv, aad) => {
    if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
        throw new TypeError(invalidKeyInput(cek, ...types, 'Uint8Array'));
    }
    if (iv) {
        checkIvLength(enc, iv);
    }
    else {
        iv = generateIv(enc);
    }
    switch (enc) {
        case 'A128CBC-HS256':
        case 'A192CBC-HS384':
        case 'A256CBC-HS512':
            if (cek instanceof Uint8Array) {
                checkCekLength(cek, parseInt(enc.slice(-3), 10));
            }
            return cbcEncrypt(enc, plaintext, cek, iv, aad);
        case 'A128GCM':
        case 'A192GCM':
        case 'A256GCM':
            if (cek instanceof Uint8Array) {
                checkCekLength(cek, parseInt(enc.slice(1, 4), 10));
            }
            return gcmEncrypt(enc, plaintext, cek, iv, aad);
        default:
            throw new JOSENotSupported('Unsupported JWE Content Encryption Algorithm');
    }
};

async function wrap(alg, key, cek, iv) {
    const jweAlgorithm = alg.slice(0, 7);
    const wrapped = await encrypt(jweAlgorithm, cek, key, iv, new Uint8Array(0));
    return {
        encryptedKey: wrapped.ciphertext,
        iv: encode$1(wrapped.iv),
        tag: encode$1(wrapped.tag),
    };
}
async function unwrap(alg, key, encryptedKey, iv, tag) {
    const jweAlgorithm = alg.slice(0, 7);
    return decrypt$2(jweAlgorithm, key, encryptedKey, iv, tag, new Uint8Array(0));
}

async function decryptKeyManagement(alg, key, encryptedKey, joseHeader, options) {
    checkKeyType(alg, key, 'decrypt');
    switch (alg) {
        case 'dir': {
            if (encryptedKey !== undefined)
                throw new JWEInvalid('Encountered unexpected JWE Encrypted Key');
            return key;
        }
        case 'ECDH-ES':
            if (encryptedKey !== undefined)
                throw new JWEInvalid('Encountered unexpected JWE Encrypted Key');
        case 'ECDH-ES+A128KW':
        case 'ECDH-ES+A192KW':
        case 'ECDH-ES+A256KW': {
            if (!isObject(joseHeader.epk))
                throw new JWEInvalid(`JOSE Header "epk" (Ephemeral Public Key) missing or invalid`);
            if (!ecdhAllowed(key))
                throw new JOSENotSupported('ECDH with the provided key is not allowed or not supported by your javascript runtime');
            const epk = await importJWK(joseHeader.epk, alg);
            let partyUInfo;
            let partyVInfo;
            if (joseHeader.apu !== undefined) {
                if (typeof joseHeader.apu !== 'string')
                    throw new JWEInvalid(`JOSE Header "apu" (Agreement PartyUInfo) invalid`);
                try {
                    partyUInfo = decode$1(joseHeader.apu);
                }
                catch {
                    throw new JWEInvalid('Failed to base64url decode the apu');
                }
            }
            if (joseHeader.apv !== undefined) {
                if (typeof joseHeader.apv !== 'string')
                    throw new JWEInvalid(`JOSE Header "apv" (Agreement PartyVInfo) invalid`);
                try {
                    partyVInfo = decode$1(joseHeader.apv);
                }
                catch {
                    throw new JWEInvalid('Failed to base64url decode the apv');
                }
            }
            const sharedSecret = await deriveKey$1(epk, key, alg === 'ECDH-ES' ? joseHeader.enc : alg, alg === 'ECDH-ES' ? bitLength(joseHeader.enc) : parseInt(alg.slice(-5, -2), 10), partyUInfo, partyVInfo);
            if (alg === 'ECDH-ES')
                return sharedSecret;
            if (encryptedKey === undefined)
                throw new JWEInvalid('JWE Encrypted Key missing');
            return unwrap$1(alg.slice(-6), sharedSecret, encryptedKey);
        }
        case 'RSA1_5':
        case 'RSA-OAEP':
        case 'RSA-OAEP-256':
        case 'RSA-OAEP-384':
        case 'RSA-OAEP-512': {
            if (encryptedKey === undefined)
                throw new JWEInvalid('JWE Encrypted Key missing');
            return decrypt(alg, key, encryptedKey);
        }
        case 'PBES2-HS256+A128KW':
        case 'PBES2-HS384+A192KW':
        case 'PBES2-HS512+A256KW': {
            if (encryptedKey === undefined)
                throw new JWEInvalid('JWE Encrypted Key missing');
            if (typeof joseHeader.p2c !== 'number')
                throw new JWEInvalid(`JOSE Header "p2c" (PBES2 Count) missing or invalid`);
            const p2cLimit = options?.maxPBES2Count || 10000;
            if (joseHeader.p2c > p2cLimit)
                throw new JWEInvalid(`JOSE Header "p2c" (PBES2 Count) out is of acceptable bounds`);
            if (typeof joseHeader.p2s !== 'string')
                throw new JWEInvalid(`JOSE Header "p2s" (PBES2 Salt) missing or invalid`);
            let p2s;
            try {
                p2s = decode$1(joseHeader.p2s);
            }
            catch {
                throw new JWEInvalid('Failed to base64url decode the p2s');
            }
            return decrypt$1(alg, key, encryptedKey, joseHeader.p2c, p2s);
        }
        case 'A128KW':
        case 'A192KW':
        case 'A256KW': {
            if (encryptedKey === undefined)
                throw new JWEInvalid('JWE Encrypted Key missing');
            return unwrap$1(alg, key, encryptedKey);
        }
        case 'A128GCMKW':
        case 'A192GCMKW':
        case 'A256GCMKW': {
            if (encryptedKey === undefined)
                throw new JWEInvalid('JWE Encrypted Key missing');
            if (typeof joseHeader.iv !== 'string')
                throw new JWEInvalid(`JOSE Header "iv" (Initialization Vector) missing or invalid`);
            if (typeof joseHeader.tag !== 'string')
                throw new JWEInvalid(`JOSE Header "tag" (Authentication Tag) missing or invalid`);
            let iv;
            try {
                iv = decode$1(joseHeader.iv);
            }
            catch {
                throw new JWEInvalid('Failed to base64url decode the iv');
            }
            let tag;
            try {
                tag = decode$1(joseHeader.tag);
            }
            catch {
                throw new JWEInvalid('Failed to base64url decode the tag');
            }
            return unwrap(alg, key, encryptedKey, iv, tag);
        }
        default: {
            throw new JOSENotSupported('Invalid or unsupported "alg" (JWE Algorithm) header value');
        }
    }
}

function validateCrit(Err, recognizedDefault, recognizedOption, protectedHeader, joseHeader) {
    if (joseHeader.crit !== undefined && protectedHeader?.crit === undefined) {
        throw new Err('"crit" (Critical) Header Parameter MUST be integrity protected');
    }
    if (!protectedHeader || protectedHeader.crit === undefined) {
        return new Set();
    }
    if (!Array.isArray(protectedHeader.crit) ||
        protectedHeader.crit.length === 0 ||
        protectedHeader.crit.some((input) => typeof input !== 'string' || input.length === 0)) {
        throw new Err('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
    }
    let recognized;
    if (recognizedOption !== undefined) {
        recognized = new Map([...Object.entries(recognizedOption), ...recognizedDefault.entries()]);
    }
    else {
        recognized = recognizedDefault;
    }
    for (const parameter of protectedHeader.crit) {
        if (!recognized.has(parameter)) {
            throw new JOSENotSupported(`Extension Header Parameter "${parameter}" is not recognized`);
        }
        if (joseHeader[parameter] === undefined) {
            throw new Err(`Extension Header Parameter "${parameter}" is missing`);
        }
        if (recognized.get(parameter) && protectedHeader[parameter] === undefined) {
            throw new Err(`Extension Header Parameter "${parameter}" MUST be integrity protected`);
        }
    }
    return new Set(protectedHeader.crit);
}

const validateAlgorithms = (option, algorithms) => {
    if (algorithms !== undefined &&
        (!Array.isArray(algorithms) || algorithms.some((s) => typeof s !== 'string'))) {
        throw new TypeError(`"${option}" option must be an array of strings`);
    }
    if (!algorithms) {
        return undefined;
    }
    return new Set(algorithms);
};

async function flattenedDecrypt(jwe, key, options) {
    if (!isObject(jwe)) {
        throw new JWEInvalid('Flattened JWE must be an object');
    }
    if (jwe.protected === undefined && jwe.header === undefined && jwe.unprotected === undefined) {
        throw new JWEInvalid('JOSE Header missing');
    }
    if (jwe.iv !== undefined && typeof jwe.iv !== 'string') {
        throw new JWEInvalid('JWE Initialization Vector incorrect type');
    }
    if (typeof jwe.ciphertext !== 'string') {
        throw new JWEInvalid('JWE Ciphertext missing or incorrect type');
    }
    if (jwe.tag !== undefined && typeof jwe.tag !== 'string') {
        throw new JWEInvalid('JWE Authentication Tag incorrect type');
    }
    if (jwe.protected !== undefined && typeof jwe.protected !== 'string') {
        throw new JWEInvalid('JWE Protected Header incorrect type');
    }
    if (jwe.encrypted_key !== undefined && typeof jwe.encrypted_key !== 'string') {
        throw new JWEInvalid('JWE Encrypted Key incorrect type');
    }
    if (jwe.aad !== undefined && typeof jwe.aad !== 'string') {
        throw new JWEInvalid('JWE AAD incorrect type');
    }
    if (jwe.header !== undefined && !isObject(jwe.header)) {
        throw new JWEInvalid('JWE Shared Unprotected Header incorrect type');
    }
    if (jwe.unprotected !== undefined && !isObject(jwe.unprotected)) {
        throw new JWEInvalid('JWE Per-Recipient Unprotected Header incorrect type');
    }
    let parsedProt;
    if (jwe.protected) {
        try {
            const protectedHeader = decode$1(jwe.protected);
            parsedProt = JSON.parse(decoder.decode(protectedHeader));
        }
        catch {
            throw new JWEInvalid('JWE Protected Header is invalid');
        }
    }
    if (!isDisjoint(parsedProt, jwe.header, jwe.unprotected)) {
        throw new JWEInvalid('JWE Protected, JWE Unprotected Header, and JWE Per-Recipient Unprotected Header Parameter names must be disjoint');
    }
    const joseHeader = {
        ...parsedProt,
        ...jwe.header,
        ...jwe.unprotected,
    };
    validateCrit(JWEInvalid, new Map(), options?.crit, parsedProt, joseHeader);
    if (joseHeader.zip !== undefined) {
        throw new JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported.');
    }
    const { alg, enc } = joseHeader;
    if (typeof alg !== 'string' || !alg) {
        throw new JWEInvalid('missing JWE Algorithm (alg) in JWE Header');
    }
    if (typeof enc !== 'string' || !enc) {
        throw new JWEInvalid('missing JWE Encryption Algorithm (enc) in JWE Header');
    }
    const keyManagementAlgorithms = options && validateAlgorithms('keyManagementAlgorithms', options.keyManagementAlgorithms);
    const contentEncryptionAlgorithms = options &&
        validateAlgorithms('contentEncryptionAlgorithms', options.contentEncryptionAlgorithms);
    if ((keyManagementAlgorithms && !keyManagementAlgorithms.has(alg)) ||
        (!keyManagementAlgorithms && alg.startsWith('PBES2'))) {
        throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter value not allowed');
    }
    if (contentEncryptionAlgorithms && !contentEncryptionAlgorithms.has(enc)) {
        throw new JOSEAlgNotAllowed('"enc" (Encryption Algorithm) Header Parameter value not allowed');
    }
    let encryptedKey;
    if (jwe.encrypted_key !== undefined) {
        try {
            encryptedKey = decode$1(jwe.encrypted_key);
        }
        catch {
            throw new JWEInvalid('Failed to base64url decode the encrypted_key');
        }
    }
    let resolvedKey = false;
    if (typeof key === 'function') {
        key = await key(parsedProt, jwe);
        resolvedKey = true;
    }
    let cek;
    try {
        cek = await decryptKeyManagement(alg, key, encryptedKey, joseHeader, options);
    }
    catch (err) {
        if (err instanceof TypeError || err instanceof JWEInvalid || err instanceof JOSENotSupported) {
            throw err;
        }
        cek = generateCek(enc);
    }
    let iv;
    let tag;
    if (jwe.iv !== undefined) {
        try {
            iv = decode$1(jwe.iv);
        }
        catch {
            throw new JWEInvalid('Failed to base64url decode the iv');
        }
    }
    if (jwe.tag !== undefined) {
        try {
            tag = decode$1(jwe.tag);
        }
        catch {
            throw new JWEInvalid('Failed to base64url decode the tag');
        }
    }
    const protectedHeader = encoder.encode(jwe.protected ?? '');
    let additionalData;
    if (jwe.aad !== undefined) {
        additionalData = concat(protectedHeader, encoder.encode('.'), encoder.encode(jwe.aad));
    }
    else {
        additionalData = protectedHeader;
    }
    let ciphertext;
    try {
        ciphertext = decode$1(jwe.ciphertext);
    }
    catch {
        throw new JWEInvalid('Failed to base64url decode the ciphertext');
    }
    const plaintext = await decrypt$2(enc, cek, ciphertext, iv, tag, additionalData);
    const result = { plaintext };
    if (jwe.protected !== undefined) {
        result.protectedHeader = parsedProt;
    }
    if (jwe.aad !== undefined) {
        try {
            result.additionalAuthenticatedData = decode$1(jwe.aad);
        }
        catch {
            throw new JWEInvalid('Failed to base64url decode the aad');
        }
    }
    if (jwe.unprotected !== undefined) {
        result.sharedUnprotectedHeader = jwe.unprotected;
    }
    if (jwe.header !== undefined) {
        result.unprotectedHeader = jwe.header;
    }
    if (resolvedKey) {
        return { ...result, key };
    }
    return result;
}

async function compactDecrypt(jwe, key, options) {
    if (jwe instanceof Uint8Array) {
        jwe = decoder.decode(jwe);
    }
    if (typeof jwe !== 'string') {
        throw new JWEInvalid('Compact JWE must be a string or Uint8Array');
    }
    const { 0: protectedHeader, 1: encryptedKey, 2: iv, 3: ciphertext, 4: tag, length, } = jwe.split('.');
    if (length !== 5) {
        throw new JWEInvalid('Invalid Compact JWE');
    }
    const decrypted = await flattenedDecrypt({
        ciphertext,
        iv: iv || undefined,
        protected: protectedHeader,
        tag: tag || undefined,
        encrypted_key: encryptedKey || undefined,
    }, key, options);
    const result = { plaintext: decrypted.plaintext, protectedHeader: decrypted.protectedHeader };
    if (typeof key === 'function') {
        return { ...result, key: decrypted.key };
    }
    return result;
}

async function generalDecrypt(jwe, key, options) {
    if (!isObject(jwe)) {
        throw new JWEInvalid('General JWE must be an object');
    }
    if (!Array.isArray(jwe.recipients) || !jwe.recipients.every(isObject)) {
        throw new JWEInvalid('JWE Recipients missing or incorrect type');
    }
    if (!jwe.recipients.length) {
        throw new JWEInvalid('JWE Recipients has no members');
    }
    for (const recipient of jwe.recipients) {
        try {
            return await flattenedDecrypt({
                aad: jwe.aad,
                ciphertext: jwe.ciphertext,
                encrypted_key: recipient.encrypted_key,
                header: recipient.header,
                iv: jwe.iv,
                protected: jwe.protected,
                tag: jwe.tag,
                unprotected: jwe.unprotected,
            }, key, options);
        }
        catch {
        }
    }
    throw new JWEDecryptionFailed();
}

const keyToJWK = async (key) => {
    if (key instanceof Uint8Array) {
        return {
            kty: 'oct',
            k: encode$1(key),
        };
    }
    if (!isCryptoKey(key)) {
        throw new TypeError(invalidKeyInput(key, ...types, 'Uint8Array'));
    }
    if (!key.extractable) {
        throw new TypeError('non-extractable CryptoKey cannot be exported as a JWK');
    }
    const { ext, key_ops, alg, use, ...jwk } = await crypto$1.subtle.exportKey('jwk', key);
    return jwk;
};
var keyToJWK$1 = keyToJWK;

async function exportJWK(key) {
    return keyToJWK$1(key);
}

async function encryptKeyManagement(alg, enc, key, providedCek, providedParameters = {}) {
    let encryptedKey;
    let parameters;
    let cek;
    checkKeyType(alg, key, 'encrypt');
    switch (alg) {
        case 'dir': {
            cek = key;
            break;
        }
        case 'ECDH-ES':
        case 'ECDH-ES+A128KW':
        case 'ECDH-ES+A192KW':
        case 'ECDH-ES+A256KW': {
            if (!ecdhAllowed(key)) {
                throw new JOSENotSupported('ECDH with the provided key is not allowed or not supported by your javascript runtime');
            }
            const { apu, apv } = providedParameters;
            let { epk: ephemeralKey } = providedParameters;
            ephemeralKey || (ephemeralKey = (await generateEpk(key)).privateKey);
            const { x, y, crv, kty } = await exportJWK(ephemeralKey);
            const sharedSecret = await deriveKey$1(key, ephemeralKey, alg === 'ECDH-ES' ? enc : alg, alg === 'ECDH-ES' ? bitLength(enc) : parseInt(alg.slice(-5, -2), 10), apu, apv);
            parameters = { epk: { x, crv, kty } };
            if (kty === 'EC')
                parameters.epk.y = y;
            if (apu)
                parameters.apu = encode$1(apu);
            if (apv)
                parameters.apv = encode$1(apv);
            if (alg === 'ECDH-ES') {
                cek = sharedSecret;
                break;
            }
            cek = providedCek || generateCek(enc);
            const kwAlg = alg.slice(-6);
            encryptedKey = await wrap$1(kwAlg, sharedSecret, cek);
            break;
        }
        case 'RSA1_5':
        case 'RSA-OAEP':
        case 'RSA-OAEP-256':
        case 'RSA-OAEP-384':
        case 'RSA-OAEP-512': {
            cek = providedCek || generateCek(enc);
            encryptedKey = await encrypt$1(alg, key, cek);
            break;
        }
        case 'PBES2-HS256+A128KW':
        case 'PBES2-HS384+A192KW':
        case 'PBES2-HS512+A256KW': {
            cek = providedCek || generateCek(enc);
            const { p2c, p2s } = providedParameters;
            ({ encryptedKey, ...parameters } = await encrypt$2(alg, key, cek, p2c, p2s));
            break;
        }
        case 'A128KW':
        case 'A192KW':
        case 'A256KW': {
            cek = providedCek || generateCek(enc);
            encryptedKey = await wrap$1(alg, key, cek);
            break;
        }
        case 'A128GCMKW':
        case 'A192GCMKW':
        case 'A256GCMKW': {
            cek = providedCek || generateCek(enc);
            const { iv } = providedParameters;
            ({ encryptedKey, ...parameters } = await wrap(alg, key, cek, iv));
            break;
        }
        default: {
            throw new JOSENotSupported('Invalid or unsupported "alg" (JWE Algorithm) header value');
        }
    }
    return { cek, encryptedKey, parameters };
}

const unprotected = Symbol();
class FlattenedEncrypt {
    constructor(plaintext) {
        if (!(plaintext instanceof Uint8Array)) {
            throw new TypeError('plaintext must be an instance of Uint8Array');
        }
        this._plaintext = plaintext;
    }
    setKeyManagementParameters(parameters) {
        if (this._keyManagementParameters) {
            throw new TypeError('setKeyManagementParameters can only be called once');
        }
        this._keyManagementParameters = parameters;
        return this;
    }
    setProtectedHeader(protectedHeader) {
        if (this._protectedHeader) {
            throw new TypeError('setProtectedHeader can only be called once');
        }
        this._protectedHeader = protectedHeader;
        return this;
    }
    setSharedUnprotectedHeader(sharedUnprotectedHeader) {
        if (this._sharedUnprotectedHeader) {
            throw new TypeError('setSharedUnprotectedHeader can only be called once');
        }
        this._sharedUnprotectedHeader = sharedUnprotectedHeader;
        return this;
    }
    setUnprotectedHeader(unprotectedHeader) {
        if (this._unprotectedHeader) {
            throw new TypeError('setUnprotectedHeader can only be called once');
        }
        this._unprotectedHeader = unprotectedHeader;
        return this;
    }
    setAdditionalAuthenticatedData(aad) {
        this._aad = aad;
        return this;
    }
    setContentEncryptionKey(cek) {
        if (this._cek) {
            throw new TypeError('setContentEncryptionKey can only be called once');
        }
        this._cek = cek;
        return this;
    }
    setInitializationVector(iv) {
        if (this._iv) {
            throw new TypeError('setInitializationVector can only be called once');
        }
        this._iv = iv;
        return this;
    }
    async encrypt(key, options) {
        if (!this._protectedHeader && !this._unprotectedHeader && !this._sharedUnprotectedHeader) {
            throw new JWEInvalid('either setProtectedHeader, setUnprotectedHeader, or sharedUnprotectedHeader must be called before #encrypt()');
        }
        if (!isDisjoint(this._protectedHeader, this._unprotectedHeader, this._sharedUnprotectedHeader)) {
            throw new JWEInvalid('JWE Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint');
        }
        const joseHeader = {
            ...this._protectedHeader,
            ...this._unprotectedHeader,
            ...this._sharedUnprotectedHeader,
        };
        validateCrit(JWEInvalid, new Map(), options?.crit, this._protectedHeader, joseHeader);
        if (joseHeader.zip !== undefined) {
            throw new JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported.');
        }
        const { alg, enc } = joseHeader;
        if (typeof alg !== 'string' || !alg) {
            throw new JWEInvalid('JWE "alg" (Algorithm) Header Parameter missing or invalid');
        }
        if (typeof enc !== 'string' || !enc) {
            throw new JWEInvalid('JWE "enc" (Encryption Algorithm) Header Parameter missing or invalid');
        }
        let encryptedKey;
        if (this._cek && (alg === 'dir' || alg === 'ECDH-ES')) {
            throw new TypeError(`setContentEncryptionKey cannot be called with JWE "alg" (Algorithm) Header ${alg}`);
        }
        let cek;
        {
            let parameters;
            ({ cek, encryptedKey, parameters } = await encryptKeyManagement(alg, enc, key, this._cek, this._keyManagementParameters));
            if (parameters) {
                if (options && unprotected in options) {
                    if (!this._unprotectedHeader) {
                        this.setUnprotectedHeader(parameters);
                    }
                    else {
                        this._unprotectedHeader = { ...this._unprotectedHeader, ...parameters };
                    }
                }
                else {
                    if (!this._protectedHeader) {
                        this.setProtectedHeader(parameters);
                    }
                    else {
                        this._protectedHeader = { ...this._protectedHeader, ...parameters };
                    }
                }
            }
        }
        let additionalData;
        let protectedHeader;
        let aadMember;
        if (this._protectedHeader) {
            protectedHeader = encoder.encode(encode$1(JSON.stringify(this._protectedHeader)));
        }
        else {
            protectedHeader = encoder.encode('');
        }
        if (this._aad) {
            aadMember = encode$1(this._aad);
            additionalData = concat(protectedHeader, encoder.encode('.'), encoder.encode(aadMember));
        }
        else {
            additionalData = protectedHeader;
        }
        const { ciphertext, tag, iv } = await encrypt(enc, this._plaintext, cek, this._iv, additionalData);
        const jwe = {
            ciphertext: encode$1(ciphertext),
        };
        if (iv) {
            jwe.iv = encode$1(iv);
        }
        if (tag) {
            jwe.tag = encode$1(tag);
        }
        if (encryptedKey) {
            jwe.encrypted_key = encode$1(encryptedKey);
        }
        if (aadMember) {
            jwe.aad = aadMember;
        }
        if (this._protectedHeader) {
            jwe.protected = decoder.decode(protectedHeader);
        }
        if (this._sharedUnprotectedHeader) {
            jwe.unprotected = this._sharedUnprotectedHeader;
        }
        if (this._unprotectedHeader) {
            jwe.header = this._unprotectedHeader;
        }
        return jwe;
    }
}

class IndividualRecipient {
    constructor(enc, key, options) {
        this.parent = enc;
        this.key = key;
        this.options = options;
    }
    setUnprotectedHeader(unprotectedHeader) {
        if (this.unprotectedHeader) {
            throw new TypeError('setUnprotectedHeader can only be called once');
        }
        this.unprotectedHeader = unprotectedHeader;
        return this;
    }
    addRecipient(...args) {
        return this.parent.addRecipient(...args);
    }
    encrypt(...args) {
        return this.parent.encrypt(...args);
    }
    done() {
        return this.parent;
    }
}
class GeneralEncrypt {
    constructor(plaintext) {
        this._recipients = [];
        this._plaintext = plaintext;
    }
    addRecipient(key, options) {
        const recipient = new IndividualRecipient(this, key, { crit: options?.crit });
        this._recipients.push(recipient);
        return recipient;
    }
    setProtectedHeader(protectedHeader) {
        if (this._protectedHeader) {
            throw new TypeError('setProtectedHeader can only be called once');
        }
        this._protectedHeader = protectedHeader;
        return this;
    }
    setSharedUnprotectedHeader(sharedUnprotectedHeader) {
        if (this._unprotectedHeader) {
            throw new TypeError('setSharedUnprotectedHeader can only be called once');
        }
        this._unprotectedHeader = sharedUnprotectedHeader;
        return this;
    }
    setAdditionalAuthenticatedData(aad) {
        this._aad = aad;
        return this;
    }
    async encrypt() {
        if (!this._recipients.length) {
            throw new JWEInvalid('at least one recipient must be added');
        }
        if (this._recipients.length === 1) {
            const [recipient] = this._recipients;
            const flattened = await new FlattenedEncrypt(this._plaintext)
                .setAdditionalAuthenticatedData(this._aad)
                .setProtectedHeader(this._protectedHeader)
                .setSharedUnprotectedHeader(this._unprotectedHeader)
                .setUnprotectedHeader(recipient.unprotectedHeader)
                .encrypt(recipient.key, { ...recipient.options });
            const jwe = {
                ciphertext: flattened.ciphertext,
                iv: flattened.iv,
                recipients: [{}],
                tag: flattened.tag,
            };
            if (flattened.aad)
                jwe.aad = flattened.aad;
            if (flattened.protected)
                jwe.protected = flattened.protected;
            if (flattened.unprotected)
                jwe.unprotected = flattened.unprotected;
            if (flattened.encrypted_key)
                jwe.recipients[0].encrypted_key = flattened.encrypted_key;
            if (flattened.header)
                jwe.recipients[0].header = flattened.header;
            return jwe;
        }
        let enc;
        for (let i = 0; i < this._recipients.length; i++) {
            const recipient = this._recipients[i];
            if (!isDisjoint(this._protectedHeader, this._unprotectedHeader, recipient.unprotectedHeader)) {
                throw new JWEInvalid('JWE Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint');
            }
            const joseHeader = {
                ...this._protectedHeader,
                ...this._unprotectedHeader,
                ...recipient.unprotectedHeader,
            };
            const { alg } = joseHeader;
            if (typeof alg !== 'string' || !alg) {
                throw new JWEInvalid('JWE "alg" (Algorithm) Header Parameter missing or invalid');
            }
            if (alg === 'dir' || alg === 'ECDH-ES') {
                throw new JWEInvalid('"dir" and "ECDH-ES" alg may only be used with a single recipient');
            }
            if (typeof joseHeader.enc !== 'string' || !joseHeader.enc) {
                throw new JWEInvalid('JWE "enc" (Encryption Algorithm) Header Parameter missing or invalid');
            }
            if (!enc) {
                enc = joseHeader.enc;
            }
            else if (enc !== joseHeader.enc) {
                throw new JWEInvalid('JWE "enc" (Encryption Algorithm) Header Parameter must be the same for all recipients');
            }
            validateCrit(JWEInvalid, new Map(), recipient.options.crit, this._protectedHeader, joseHeader);
            if (joseHeader.zip !== undefined) {
                throw new JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported.');
            }
        }
        const cek = generateCek(enc);
        const jwe = {
            ciphertext: '',
            iv: '',
            recipients: [],
            tag: '',
        };
        for (let i = 0; i < this._recipients.length; i++) {
            const recipient = this._recipients[i];
            const target = {};
            jwe.recipients.push(target);
            const joseHeader = {
                ...this._protectedHeader,
                ...this._unprotectedHeader,
                ...recipient.unprotectedHeader,
            };
            const p2c = joseHeader.alg.startsWith('PBES2') ? 2048 + i : undefined;
            if (i === 0) {
                const flattened = await new FlattenedEncrypt(this._plaintext)
                    .setAdditionalAuthenticatedData(this._aad)
                    .setContentEncryptionKey(cek)
                    .setProtectedHeader(this._protectedHeader)
                    .setSharedUnprotectedHeader(this._unprotectedHeader)
                    .setUnprotectedHeader(recipient.unprotectedHeader)
                    .setKeyManagementParameters({ p2c })
                    .encrypt(recipient.key, {
                    ...recipient.options,
                    [unprotected]: true,
                });
                jwe.ciphertext = flattened.ciphertext;
                jwe.iv = flattened.iv;
                jwe.tag = flattened.tag;
                if (flattened.aad)
                    jwe.aad = flattened.aad;
                if (flattened.protected)
                    jwe.protected = flattened.protected;
                if (flattened.unprotected)
                    jwe.unprotected = flattened.unprotected;
                target.encrypted_key = flattened.encrypted_key;
                if (flattened.header)
                    target.header = flattened.header;
                continue;
            }
            const { encryptedKey, parameters } = await encryptKeyManagement(recipient.unprotectedHeader?.alg ||
                this._protectedHeader?.alg ||
                this._unprotectedHeader?.alg, enc, recipient.key, cek, { p2c });
            target.encrypted_key = encode$1(encryptedKey);
            if (recipient.unprotectedHeader || parameters)
                target.header = { ...recipient.unprotectedHeader, ...parameters };
        }
        return jwe;
    }
}

function subtleDsa(alg, algorithm) {
    const hash = `SHA-${alg.slice(-3)}`;
    switch (alg) {
        case 'HS256':
        case 'HS384':
        case 'HS512':
            return { hash, name: 'HMAC' };
        case 'PS256':
        case 'PS384':
        case 'PS512':
            return { hash, name: 'RSA-PSS', saltLength: alg.slice(-3) >> 3 };
        case 'RS256':
        case 'RS384':
        case 'RS512':
            return { hash, name: 'RSASSA-PKCS1-v1_5' };
        case 'ES256':
        case 'ES384':
        case 'ES512':
            return { hash, name: 'ECDSA', namedCurve: algorithm.namedCurve };
        case 'EdDSA':
            return { name: algorithm.name };
        default:
            throw new JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
    }
}

function getCryptoKey(alg, key, usage) {
    if (isCryptoKey(key)) {
        checkSigCryptoKey(key, alg, usage);
        return key;
    }
    if (key instanceof Uint8Array) {
        if (!alg.startsWith('HS')) {
            throw new TypeError(invalidKeyInput(key, ...types));
        }
        return crypto$1.subtle.importKey('raw', key, { hash: `SHA-${alg.slice(-3)}`, name: 'HMAC' }, false, [usage]);
    }
    throw new TypeError(invalidKeyInput(key, ...types, 'Uint8Array'));
}

const verify = async (alg, key, signature, data) => {
    const cryptoKey = await getCryptoKey(alg, key, 'verify');
    checkKeyLength(alg, cryptoKey);
    const algorithm = subtleDsa(alg, cryptoKey.algorithm);
    try {
        return await crypto$1.subtle.verify(algorithm, cryptoKey, signature, data);
    }
    catch {
        return false;
    }
};

async function flattenedVerify(jws, key, options) {
    if (!isObject(jws)) {
        throw new JWSInvalid('Flattened JWS must be an object');
    }
    if (jws.protected === undefined && jws.header === undefined) {
        throw new JWSInvalid('Flattened JWS must have either of the "protected" or "header" members');
    }
    if (jws.protected !== undefined && typeof jws.protected !== 'string') {
        throw new JWSInvalid('JWS Protected Header incorrect type');
    }
    if (jws.payload === undefined) {
        throw new JWSInvalid('JWS Payload missing');
    }
    if (typeof jws.signature !== 'string') {
        throw new JWSInvalid('JWS Signature missing or incorrect type');
    }
    if (jws.header !== undefined && !isObject(jws.header)) {
        throw new JWSInvalid('JWS Unprotected Header incorrect type');
    }
    let parsedProt = {};
    if (jws.protected) {
        try {
            const protectedHeader = decode$1(jws.protected);
            parsedProt = JSON.parse(decoder.decode(protectedHeader));
        }
        catch {
            throw new JWSInvalid('JWS Protected Header is invalid');
        }
    }
    if (!isDisjoint(parsedProt, jws.header)) {
        throw new JWSInvalid('JWS Protected and JWS Unprotected Header Parameter names must be disjoint');
    }
    const joseHeader = {
        ...parsedProt,
        ...jws.header,
    };
    const extensions = validateCrit(JWSInvalid, new Map([['b64', true]]), options?.crit, parsedProt, joseHeader);
    let b64 = true;
    if (extensions.has('b64')) {
        b64 = parsedProt.b64;
        if (typeof b64 !== 'boolean') {
            throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
        }
    }
    const { alg } = joseHeader;
    if (typeof alg !== 'string' || !alg) {
        throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
    }
    const algorithms = options && validateAlgorithms('algorithms', options.algorithms);
    if (algorithms && !algorithms.has(alg)) {
        throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter value not allowed');
    }
    if (b64) {
        if (typeof jws.payload !== 'string') {
            throw new JWSInvalid('JWS Payload must be a string');
        }
    }
    else if (typeof jws.payload !== 'string' && !(jws.payload instanceof Uint8Array)) {
        throw new JWSInvalid('JWS Payload must be a string or an Uint8Array instance');
    }
    let resolvedKey = false;
    if (typeof key === 'function') {
        key = await key(parsedProt, jws);
        resolvedKey = true;
    }
    checkKeyType(alg, key, 'verify');
    const data = concat(encoder.encode(jws.protected ?? ''), encoder.encode('.'), typeof jws.payload === 'string' ? encoder.encode(jws.payload) : jws.payload);
    let signature;
    try {
        signature = decode$1(jws.signature);
    }
    catch {
        throw new JWSInvalid('Failed to base64url decode the signature');
    }
    const verified = await verify(alg, key, signature, data);
    if (!verified) {
        throw new JWSSignatureVerificationFailed();
    }
    let payload;
    if (b64) {
        try {
            payload = decode$1(jws.payload);
        }
        catch {
            throw new JWSInvalid('Failed to base64url decode the payload');
        }
    }
    else if (typeof jws.payload === 'string') {
        payload = encoder.encode(jws.payload);
    }
    else {
        payload = jws.payload;
    }
    const result = { payload };
    if (jws.protected !== undefined) {
        result.protectedHeader = parsedProt;
    }
    if (jws.header !== undefined) {
        result.unprotectedHeader = jws.header;
    }
    if (resolvedKey) {
        return { ...result, key };
    }
    return result;
}

async function compactVerify(jws, key, options) {
    if (jws instanceof Uint8Array) {
        jws = decoder.decode(jws);
    }
    if (typeof jws !== 'string') {
        throw new JWSInvalid('Compact JWS must be a string or Uint8Array');
    }
    const { 0: protectedHeader, 1: payload, 2: signature, length } = jws.split('.');
    if (length !== 3) {
        throw new JWSInvalid('Invalid Compact JWS');
    }
    const verified = await flattenedVerify({ payload, protected: protectedHeader, signature }, key, options);
    const result = { payload: verified.payload, protectedHeader: verified.protectedHeader };
    if (typeof key === 'function') {
        return { ...result, key: verified.key };
    }
    return result;
}

async function generalVerify(jws, key, options) {
    if (!isObject(jws)) {
        throw new JWSInvalid('General JWS must be an object');
    }
    if (!Array.isArray(jws.signatures) || !jws.signatures.every(isObject)) {
        throw new JWSInvalid('JWS Signatures missing or incorrect type');
    }
    for (const signature of jws.signatures) {
        try {
            return await flattenedVerify({
                header: signature.header,
                payload: jws.payload,
                protected: signature.protected,
                signature: signature.signature,
            }, key, options);
        }
        catch {
        }
    }
    throw new JWSSignatureVerificationFailed();
}

class CompactEncrypt {
    constructor(plaintext) {
        this._flattened = new FlattenedEncrypt(plaintext);
    }
    setContentEncryptionKey(cek) {
        this._flattened.setContentEncryptionKey(cek);
        return this;
    }
    setInitializationVector(iv) {
        this._flattened.setInitializationVector(iv);
        return this;
    }
    setProtectedHeader(protectedHeader) {
        this._flattened.setProtectedHeader(protectedHeader);
        return this;
    }
    setKeyManagementParameters(parameters) {
        this._flattened.setKeyManagementParameters(parameters);
        return this;
    }
    async encrypt(key, options) {
        const jwe = await this._flattened.encrypt(key, options);
        return [jwe.protected, jwe.encrypted_key, jwe.iv, jwe.ciphertext, jwe.tag].join('.');
    }
}

const sign = async (alg, key, data) => {
    const cryptoKey = await getCryptoKey(alg, key, 'sign');
    checkKeyLength(alg, cryptoKey);
    const signature = await crypto$1.subtle.sign(subtleDsa(alg, cryptoKey.algorithm), cryptoKey, data);
    return new Uint8Array(signature);
};

class FlattenedSign {
    constructor(payload) {
        if (!(payload instanceof Uint8Array)) {
            throw new TypeError('payload must be an instance of Uint8Array');
        }
        this._payload = payload;
    }
    setProtectedHeader(protectedHeader) {
        if (this._protectedHeader) {
            throw new TypeError('setProtectedHeader can only be called once');
        }
        this._protectedHeader = protectedHeader;
        return this;
    }
    setUnprotectedHeader(unprotectedHeader) {
        if (this._unprotectedHeader) {
            throw new TypeError('setUnprotectedHeader can only be called once');
        }
        this._unprotectedHeader = unprotectedHeader;
        return this;
    }
    async sign(key, options) {
        if (!this._protectedHeader && !this._unprotectedHeader) {
            throw new JWSInvalid('either setProtectedHeader or setUnprotectedHeader must be called before #sign()');
        }
        if (!isDisjoint(this._protectedHeader, this._unprotectedHeader)) {
            throw new JWSInvalid('JWS Protected and JWS Unprotected Header Parameter names must be disjoint');
        }
        const joseHeader = {
            ...this._protectedHeader,
            ...this._unprotectedHeader,
        };
        const extensions = validateCrit(JWSInvalid, new Map([['b64', true]]), options?.crit, this._protectedHeader, joseHeader);
        let b64 = true;
        if (extensions.has('b64')) {
            b64 = this._protectedHeader.b64;
            if (typeof b64 !== 'boolean') {
                throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
            }
        }
        const { alg } = joseHeader;
        if (typeof alg !== 'string' || !alg) {
            throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
        }
        checkKeyType(alg, key, 'sign');
        let payload = this._payload;
        if (b64) {
            payload = encoder.encode(encode$1(payload));
        }
        let protectedHeader;
        if (this._protectedHeader) {
            protectedHeader = encoder.encode(encode$1(JSON.stringify(this._protectedHeader)));
        }
        else {
            protectedHeader = encoder.encode('');
        }
        const data = concat(protectedHeader, encoder.encode('.'), payload);
        const signature = await sign(alg, key, data);
        const jws = {
            signature: encode$1(signature),
            payload: '',
        };
        if (b64) {
            jws.payload = decoder.decode(payload);
        }
        if (this._unprotectedHeader) {
            jws.header = this._unprotectedHeader;
        }
        if (this._protectedHeader) {
            jws.protected = decoder.decode(protectedHeader);
        }
        return jws;
    }
}

class CompactSign {
    constructor(payload) {
        this._flattened = new FlattenedSign(payload);
    }
    setProtectedHeader(protectedHeader) {
        this._flattened.setProtectedHeader(protectedHeader);
        return this;
    }
    async sign(key, options) {
        const jws = await this._flattened.sign(key, options);
        if (jws.payload === undefined) {
            throw new TypeError('use the flattened module for creating JWS with b64: false');
        }
        return `${jws.protected}.${jws.payload}.${jws.signature}`;
    }
}

class IndividualSignature {
    constructor(sig, key, options) {
        this.parent = sig;
        this.key = key;
        this.options = options;
    }
    setProtectedHeader(protectedHeader) {
        if (this.protectedHeader) {
            throw new TypeError('setProtectedHeader can only be called once');
        }
        this.protectedHeader = protectedHeader;
        return this;
    }
    setUnprotectedHeader(unprotectedHeader) {
        if (this.unprotectedHeader) {
            throw new TypeError('setUnprotectedHeader can only be called once');
        }
        this.unprotectedHeader = unprotectedHeader;
        return this;
    }
    addSignature(...args) {
        return this.parent.addSignature(...args);
    }
    sign(...args) {
        return this.parent.sign(...args);
    }
    done() {
        return this.parent;
    }
}
class GeneralSign {
    constructor(payload) {
        this._signatures = [];
        this._payload = payload;
    }
    addSignature(key, options) {
        const signature = new IndividualSignature(this, key, options);
        this._signatures.push(signature);
        return signature;
    }
    async sign() {
        if (!this._signatures.length) {
            throw new JWSInvalid('at least one signature must be added');
        }
        const jws = {
            signatures: [],
            payload: '',
        };
        for (let i = 0; i < this._signatures.length; i++) {
            const signature = this._signatures[i];
            const flattened = new FlattenedSign(this._payload);
            flattened.setProtectedHeader(signature.protectedHeader);
            flattened.setUnprotectedHeader(signature.unprotectedHeader);
            const { payload, ...rest } = await flattened.sign(signature.key, signature.options);
            if (i === 0) {
                jws.payload = payload;
            }
            else if (jws.payload !== payload) {
                throw new JWSInvalid('inconsistent use of JWS Unencoded Payload (RFC7797)');
            }
            jws.signatures.push(rest);
        }
        return jws;
    }
}

const encode = encode$1;
const decode = decode$1;

function decodeProtectedHeader(token) {
    let protectedB64u;
    if (typeof token === 'string') {
        const parts = token.split('.');
        if (parts.length === 3 || parts.length === 5) {
            [protectedB64u] = parts;
        }
    }
    else if (typeof token === 'object' && token) {
        if ('protected' in token) {
            protectedB64u = token.protected;
        }
        else {
            throw new TypeError('Token does not contain a Protected Header');
        }
    }
    try {
        if (typeof protectedB64u !== 'string' || !protectedB64u) {
            throw new Error();
        }
        const result = JSON.parse(decoder.decode(decode(protectedB64u)));
        if (!isObject(result)) {
            throw new Error();
        }
        return result;
    }
    catch {
        throw new TypeError('Invalid Token or Protected Header formatting');
    }
}

async function generateSecret$1(alg, options) {
    let length;
    let algorithm;
    let keyUsages;
    switch (alg) {
        case 'HS256':
        case 'HS384':
        case 'HS512':
            length = parseInt(alg.slice(-3), 10);
            algorithm = { name: 'HMAC', hash: `SHA-${length}`, length };
            keyUsages = ['sign', 'verify'];
            break;
        case 'A128CBC-HS256':
        case 'A192CBC-HS384':
        case 'A256CBC-HS512':
            length = parseInt(alg.slice(-3), 10);
            return random(new Uint8Array(length >> 3));
        case 'A128KW':
        case 'A192KW':
        case 'A256KW':
            length = parseInt(alg.slice(1, 4), 10);
            algorithm = { name: 'AES-KW', length };
            keyUsages = ['wrapKey', 'unwrapKey'];
            break;
        case 'A128GCMKW':
        case 'A192GCMKW':
        case 'A256GCMKW':
        case 'A128GCM':
        case 'A192GCM':
        case 'A256GCM':
            length = parseInt(alg.slice(1, 4), 10);
            algorithm = { name: 'AES-GCM', length };
            keyUsages = ['encrypt', 'decrypt'];
            break;
        default:
            throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
    }
    return crypto$1.subtle.generateKey(algorithm, options?.extractable ?? false, keyUsages);
}
function getModulusLengthOption(options) {
    const modulusLength = options?.modulusLength ?? 2048;
    if (typeof modulusLength !== 'number' || modulusLength < 2048) {
        throw new JOSENotSupported('Invalid or unsupported modulusLength option provided, 2048 bits or larger keys must be used');
    }
    return modulusLength;
}
async function generateKeyPair$1(alg, options) {
    let algorithm;
    let keyUsages;
    switch (alg) {
        case 'PS256':
        case 'PS384':
        case 'PS512':
            algorithm = {
                name: 'RSA-PSS',
                hash: `SHA-${alg.slice(-3)}`,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                modulusLength: getModulusLengthOption(options),
            };
            keyUsages = ['sign', 'verify'];
            break;
        case 'RS256':
        case 'RS384':
        case 'RS512':
            algorithm = {
                name: 'RSASSA-PKCS1-v1_5',
                hash: `SHA-${alg.slice(-3)}`,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                modulusLength: getModulusLengthOption(options),
            };
            keyUsages = ['sign', 'verify'];
            break;
        case 'RSA-OAEP':
        case 'RSA-OAEP-256':
        case 'RSA-OAEP-384':
        case 'RSA-OAEP-512':
            algorithm = {
                name: 'RSA-OAEP',
                hash: `SHA-${parseInt(alg.slice(-3), 10) || 1}`,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                modulusLength: getModulusLengthOption(options),
            };
            keyUsages = ['decrypt', 'unwrapKey', 'encrypt', 'wrapKey'];
            break;
        case 'ES256':
            algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
            keyUsages = ['sign', 'verify'];
            break;
        case 'ES384':
            algorithm = { name: 'ECDSA', namedCurve: 'P-384' };
            keyUsages = ['sign', 'verify'];
            break;
        case 'ES512':
            algorithm = { name: 'ECDSA', namedCurve: 'P-521' };
            keyUsages = ['sign', 'verify'];
            break;
        case 'EdDSA': {
            keyUsages = ['sign', 'verify'];
            const crv = options?.crv ?? 'Ed25519';
            switch (crv) {
                case 'Ed25519':
                case 'Ed448':
                    algorithm = { name: crv };
                    break;
                default:
                    throw new JOSENotSupported('Invalid or unsupported crv option provided');
            }
            break;
        }
        case 'ECDH-ES':
        case 'ECDH-ES+A128KW':
        case 'ECDH-ES+A192KW':
        case 'ECDH-ES+A256KW': {
            keyUsages = ['deriveKey', 'deriveBits'];
            const crv = options?.crv ?? 'P-256';
            switch (crv) {
                case 'P-256':
                case 'P-384':
                case 'P-521': {
                    algorithm = { name: 'ECDH', namedCurve: crv };
                    break;
                }
                case 'X25519':
                case 'X448':
                    algorithm = { name: crv };
                    break;
                default:
                    throw new JOSENotSupported('Invalid or unsupported crv option provided, supported values are P-256, P-384, P-521, X25519, and X448');
            }
            break;
        }
        default:
            throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
    }
    return (crypto$1.subtle.generateKey(algorithm, options?.extractable ?? false, keyUsages));
}

async function generateKeyPair(alg, options) {
    return generateKeyPair$1(alg, options);
}

async function generateSecret(alg, options) {
    return generateSecret$1(alg, options);
}

// One consistent algorithm for each family.
// https://datatracker.ietf.org/doc/html/rfc7518

const signingName = 'ECDSA';
const signingCurve = 'P-384';
const signingAlgorithm = 'ES384';

const encryptingName = 'RSA-OAEP';
const hashLength = 256;
const hashName = 'SHA-256';
const modulusLength = 4096; // panva JOSE library default is 2048
const encryptingAlgorithm = 'RSA-OAEP-256';

const symmetricName = 'AES-GCM';
const symmetricAlgorithm = 'A256GCM';
const symmetricWrap = 'A256GCMKW';
const secretAlgorithm = 'PBES2-HS512+A256KW';

const extractable = true;  // always wrapped

function digest(hashName, buffer) {
  return crypto.subtle.digest(hashName, buffer);
}

function exportRawKey(key) {
  return crypto.subtle.exportKey('raw', key);
}

function importRawKey(arrayBuffer) {
  const algorithm = {name: signingName, namedCurve: signingCurve};
  return crypto.subtle.importKey('raw', arrayBuffer, algorithm, extractable, ['verify']);
}

function importSecret(byteArray) {
  const algorithm = {name: symmetricName, length: hashLength};
  return crypto.subtle.importKey('raw', byteArray, algorithm, true, ['encrypt', 'decrypt'])
}

const Krypto = {
  // An inheritable singleton for compact JOSE operations.
  // See https://kilroy-code.github.io/distributed-security/docs/implementation.html#wrapping-subtlekrypto
  decodeProtectedHeader: decodeProtectedHeader,
  isEmptyJWSPayload(compactJWS) { // arg is a string
    return !compactJWS.split('.')[1];
  },

  // The cty can be specified in encrypt/sign, but defaults to a good guess.
  // The cty can be specified in decrypt/verify, but defaults to what is specified in the protected header.
  inputBuffer(data, header) { // Answers a buffer view of data and, if necessary to convert, bashes cty of header.
    if (ArrayBuffer.isView(data) && !header.cty) return data;
    let givenCty = header.cty || '';
    if (givenCty.includes('text') || ('string' === typeof data)) {
      header.cty = givenCty || 'text/plain';
    } else {
      header.cty = givenCty || 'json'; // JWS recommends leaving off the leading 'application/'.
      data = JSON.stringify(data); // Note that new String("something") will pass this way.
    }
    return new TextEncoder().encode(data);
  },
  recoverDataFromContentType(result, {cty = result?.protectedHeader?.cty} = {}) {
    // Examines result?.protectedHeader and bashes in result.text or result.json if appropriate, returning result.
    if (result && !Object.prototype.hasOwnProperty.call(result, 'payload')) result.payload = result.plaintext;  // because JOSE uses plaintext for decrypt and payload for sign.
    if (!cty || !result?.payload) return result; // either no cty or no result
    result.text = new TextDecoder().decode(result.payload);
    if (cty.includes('json')) result.json = JSON.parse(result.text);
    return result;
  },

  // Sign/Verify
  generateSigningKey() { // Promise {privateKey, publicKey} in our standard signing algorithm.
    return generateKeyPair(signingAlgorithm, {extractable});
  },
  async sign(privateKey, message, headers = {}) { // Promise a compact JWS string. Accepts headers to be protected.
    let header = {alg: signingAlgorithm, ...headers},
        inputBuffer = this.inputBuffer(message, header);
    return new CompactSign(inputBuffer).setProtectedHeader(header).sign(privateKey);
  },
  async verify(publicKey, signature, options) { // Promise {payload, text, json}, where text and json are only defined when appropriate.
    let result = await compactVerify(signature, publicKey).catch(() => undefined);
    return this.recoverDataFromContentType(result, options);
  },

  // Encrypt/Decrypt
  generateEncryptingKey() { // Promise {privateKey, publicKey} in our standard encryption algorithm.
    return generateKeyPair(encryptingAlgorithm, {extractable, modulusLength});
  },
  async encrypt(key, message, headers = {}) { // Promise a compact JWE string. Accepts headers to be protected.
    let alg = this.isSymmetric(key) ? 'dir' : encryptingAlgorithm,
        header = {alg, enc: symmetricAlgorithm, ...headers},
        inputBuffer = this.inputBuffer(message, header),
        secret = this.keySecret(key);
    return new CompactEncrypt(inputBuffer).setProtectedHeader(header).encrypt(secret);
  },
  async decrypt(key, encrypted, options = {}) { // Promise {payload, text, json}, where text and json are only defined when appropriate.
    let secret = this.keySecret(key),
        result = await compactDecrypt(encrypted, secret);
    this.recoverDataFromContentType(result, options);
    return result;
  },
  async generateSecretKey(text) { // JOSE uses a digest for PBES, but make it recognizable as a {type: 'secret'} key.
    let buffer = new TextEncoder().encode(text),
        hash = await digest(hashName, buffer);
    return {type: 'secret', text: new Uint8Array(hash)};
  },
  generateSymmetricKey(text) { // Promise a key for symmetric encryption.
    if (text) return this.generateSecretKey(text); // PBES
    return generateSecret(symmetricAlgorithm, {extractable}); // AES
  },
  isSymmetric(key) { // Either AES or PBES, but not publicKey or privateKey.
    return key.type === 'secret';
  },
  keySecret(key) { // Return what is actually used as input in JOSE library.
    if (key.text) return key.text;
    return key;
  },

  // Export/Import
  async exportRaw(key) { // base64url for public verfication keys
    let arrayBuffer = await exportRawKey(key);
    return encode(new Uint8Array(arrayBuffer));
  },
  async importRaw(string) { // Promise the verification key from base64url
    let arrayBuffer = decode(string);
    return importRawKey(arrayBuffer);
  },
  async exportJWK(key) { // Promise JWK object, with alg included.
    let exported = await exportJWK(key),
        alg = key.algorithm; // JOSE library gives algorithm, but not alg that is needed for import.
    if (alg) { // subtle.crypto underlying keys
      if (alg.name === signingName && alg.namedCurve === signingCurve) exported.alg = signingAlgorithm;
      else if (alg.name === encryptingName && alg.hash.name === hashName) exported.alg = encryptingAlgorithm;
      else if (alg.name === symmetricName && alg.length === hashLength) exported.alg = symmetricAlgorithm;
    } else switch (exported.kty) { // JOSE on NodeJS used node:crypto keys, which do not expose the precise algorithm
      case 'EC': exported.alg = signingAlgorithm; break;
      case 'RSA': exported.alg = encryptingAlgorithm; break;
      case 'oct': exported.alg = symmetricAlgorithm; break;
    }
    return exported;
  },
  async importJWK(jwk) { // Promise a key object
    jwk = {ext: true, ...jwk}; // We need the result to be be able to generate a new JWK (e.g., on changeMembership)
    let imported = await importJWK(jwk);
    if (imported instanceof Uint8Array) {
      // We depend an returning an actual key, but the JOSE library we use
      // will above produce the raw Uint8Array if the jwk is from a secret.
      imported = await importSecret(imported);
    }
    return imported;
  },

  async wrapKey(key, wrappingKey, headers = {}) { // Promise a JWE from the public wrappingKey
    let exported = await this.exportJWK(key);
    return this.encrypt(wrappingKey, exported, headers);
  },
  async unwrapKey(wrappedKey, unwrappingKey) { // Promise the key unlocked by the private unwrappingKey.
    let decrypted = await this.decrypt(unwrappingKey, wrappedKey);
    return this.importJWK(decrypted.json);
  }
};
/*
Some useful JOSE recipes for playing around.
sk = await JOSE.generateKeyPair('ES384', {extractable: true})
jwt = await new JOSE.SignJWT().setSubject("foo").setProtectedHeader({alg:'ES384'}).sign(sk.privateKey)
await JOSE.jwtVerify(jwt, sk.publicKey) //.payload.sub

message = new TextEncoder().encode('some message')
jws = await new JOSE.CompactSign(message).setProtectedHeader({alg:'ES384'}).sign(sk.privateKey) // Or FlattenedSign
jws = await new JOSE.GeneralSign(message).addSignature(sk.privateKey).setProtectedHeader({alg:'ES384'}).sign()
verified = await JOSE.generalVerify(jws, sk.publicKey)
or compactVerify or flattenedVerify
new TextDecoder().decode(verified.payload)

ek = await JOSE.generateKeyPair('RSA-OAEP-256', {extractable: true})
jwe = await new JOSE.CompactEncrypt(message).setProtectedHeader({alg: 'RSA-OAEP-256', enc: 'A256GCM' }).encrypt(ek.publicKey)
or FlattenedEncrypt. For symmetric secret, specify alg:'dir'.
decrypted = await JOSE.compactDecrypt(jwe, ek.privateKey)
new TextDecoder().decode(decrypted.plaintext)
jwe = await new JOSE.GeneralEncrypt(message).setProtectedHeader({alg: 'RSA-OAEP-256', enc: 'A256GCM' }).addRecipient(ek.publicKey).encrypt() // with additional addRecipent() as needed
decrypted = await JOSE.generalDecrypt(jwe, ek.privateKey)

material = new TextEncoder().encode('secret')
jwe = await new JOSE.CompactEncrypt(message).setProtectedHeader({alg: 'PBES2-HS512+A256KW', enc: 'A256GCM' }).encrypt(material)
decrypted = await JOSE.compactDecrypt(jwe, material, {keyManagementAlgorithms: ['PBES2-HS512+A256KW'], contentEncryptionAlgorithms: ['A256GCM']})
jwe = await new JOSE.GeneralEncrypt(message).setProtectedHeader({alg: 'PBES2-HS512+A256KW', enc: 'A256GCM' }).addRecipient(material).encrypt()
jwe = await new JOSE.GeneralEncrypt(message).setProtectedHeader({enc: 'A256GCM' })
  .addRecipient(ek.publicKey).setUnprotectedHeader({kid: 'foo', alg: 'RSA-OAEP-256'})
  .addRecipient(material).setUnprotectedHeader({kid: 'secret1', alg: 'PBES2-HS512+A256KW'})
  .addRecipient(material2).setUnprotectedHeader({kid: 'secret2', alg: 'PBES2-HS512+A256KW'})
  .encrypt()
decrypted = await JOSE.generalDecrypt(jwe, ek.privateKey)
decrypted = await JOSE.generalDecrypt(jwe, material, {keyManagementAlgorithms: ['PBES2-HS512+A256KW']})
*/

function mismatch(kid, encodedKid) { // Promise a rejection.
  let message = `Key ${kid} does not match encoded ${encodedKid}.`;
  return Promise.reject(message);
}

const MultiKrypto = {
  // Extend Krypto for general (multiple key) JOSE operations.
  // See https://kilroy-code.github.io/distributed-security/docs/implementation.html#combining-keys
  
  // Our multi keys are dictionaries of name (or kid) => keyObject.
  isMultiKey(key) { // A SubtleCrypto CryptoKey is an object with a type property. Our multikeys are
    // objects with a specific type or no type property at all.
    return (key.type || 'multi') === 'multi';
  },
  keyTags(key) { // Just the kids that are for actual keys. No 'type'.
    return Object.keys(key).filter(key => key !== 'type');
  },

  // Export/Import
  async exportJWK(key) { // Promise a JWK key set if necessary, retaining the names as kid property.
    if (!this.isMultiKey(key)) return super.exportJWK(key);
    let names = this.keyTags(key),
        keys = await Promise.all(names.map(async name => {
          let jwk = await this.exportJWK(key[name]);
          jwk.kid = name;
          return jwk;
        }));
    return {keys};
  },
  async importJWK(jwk) { // Promise a single "key" object.
    // Result will be a multi-key if JWK is a key set, in which case each must include a kid property.
    if (!jwk.keys) return super.importJWK(jwk);
    let key = {}; // TODO: get type from kty or some such?
    await Promise.all(jwk.keys.map(async jwk => key[jwk.kid] = await this.importJWK(jwk)));
    return key;
  },

  // Encrypt/Decrypt
  async encrypt(key, message, headers = {}) { // Promise a JWE, in general form if appropriate.
    if (!this.isMultiKey(key)) return super.encrypt(key, message, headers);
    // key must be a dictionary mapping tags to encrypting keys.
    let baseHeader = {enc: symmetricAlgorithm, ...headers},
        inputBuffer = this.inputBuffer(message, baseHeader),
        jwe = new GeneralEncrypt(inputBuffer).setProtectedHeader(baseHeader);
    for (let tag of this.keyTags(key)) {
      let thisKey = key[tag],
          isString = 'string' === typeof thisKey,
          isSym = isString || this.isSymmetric(thisKey),
          secret = isString ? new TextEncoder().encode(thisKey) : this.keySecret(thisKey),
          alg = isString ? secretAlgorithm : (isSym ? symmetricWrap : encryptingAlgorithm);
      // The kid and alg are per/sub-key, and so cannot be signed by all, and so cannot be protected within the encryption.
      // This is ok, because the only that can happen as a result of tampering with these is that the decryption will fail,
      // which is the same result as tampering with the ciphertext or any other part of the JWE.
      jwe.addRecipient(secret).setUnprotectedHeader({kid: tag, alg});
    }
    let encrypted = await jwe.encrypt();
    return encrypted;
  },
  async decrypt(key, encrypted, options) { // Promise {payload, text, json}, where text and json are only defined when appropriate.
    if (!this.isMultiKey(key)) return super.decrypt(key, encrypted, options);
    let jwe = encrypted,
        {recipients} = jwe,
        unwrappingPromises = recipients.map(async ({header}) => {
          let {kid} = header,
              unwrappingKey = key[kid],
              options = {};
          if (!unwrappingKey) return Promise.reject('missing');
          if ('string' === typeof unwrappingKey) { // TODO: only specified if allowed by secure header?
            unwrappingKey = new TextEncoder().encode(unwrappingKey);
            options.keyManagementAlgorithms = [secretAlgorithm];
          }
          let result = await generalDecrypt(jwe, this.keySecret(unwrappingKey), options),
              encodedKid = result.unprotectedHeader.kid;
          if (encodedKid !== kid) return mismatch(kid, encodedKid);
          return result;
        });
    // Do we really want to return undefined if everything fails? Should just allow the rejection to propagate?
    return await Promise.any(unwrappingPromises).then(
      result => {
        this.recoverDataFromContentType(result, options);
        return result;
      },
      () => undefined);
  },

  // Sign/Verify
  async sign(key, message, header = {}) { // Promise JWS, in general form with kid headers if necessary.
    if (!this.isMultiKey(key)) return super.sign(key, message, header);
    let inputBuffer = this.inputBuffer(message, header),
        jws = new GeneralSign(inputBuffer);
    for (let tag of this.keyTags(key)) {
      let thisKey = key[tag],
          thisHeader = {kid: tag, alg: signingAlgorithm, ...header};
      jws.addSignature(thisKey).setProtectedHeader(thisHeader);
    }
    return jws.sign();
  },
  verifySubSignature(jws, signatureElement, multiKey, kids) {
    // Verify a single element of jws.signature using multiKey.
    // Always promises {protectedHeader, unprotectedHeader, kid}, even if verification fails,
    // where kid is the property name within multiKey that matched (either by being specified in a header
    // or by successful verification). Also includes the decoded payload IFF there is a match.
    let protectedHeader = signatureElement.protectedHeader ?? this.decodeProtectedHeader(signatureElement),
        unprotectedHeader = signatureElement.unprotectedHeader,
        kid = protectedHeader?.kid || unprotectedHeader?.kid,
        singleJWS = {...jws, signatures: [signatureElement]},
        failureResult = {protectedHeader, unprotectedHeader, kid},
        kidsToTry = kid ? [kid] : kids;
    let promise = Promise.any(kidsToTry.map(async kid => generalVerify(singleJWS, multiKey[kid]).then(result => {return {kid, ...result};})));
    return promise.catch(() => failureResult);
  },
  async verify(key, signature, options = {}) { // Promise {payload, text, json}, where text and json are only defined when appropriate.
    // Additionally, if key is a multiKey AND signature is a general form JWS, then answer includes a signers property
    // by which caller can determine if it what they expect. The payload of each signers element is defined only that
    // signer was matched by something in key.
    
    if (!this.isMultiKey(key)) return super.verify(key, signature, options);
    if (!signature.signatures) return;

    // Comparison to panva JOSE.generalVerify.
    // JOSE takes a jws and ONE key and answers {payload, protectedHeader, unprotectedHeader} matching the one
    // jws.signature element that was verified, otherise an eror. (It tries each of the elements of the jws.signatures.)
    // It is not generally possible to know WHICH one of the jws.signatures was matched.
    // (It MAY be possible if there are unique kid elements, but that's application-dependent.)
    //
    // MultiKrypto takes a dictionary that contains named keys and recognizedHeader properties, and it returns
    // a result that has a signers array that has an element corresponding to each original signature if any
    // are matched by the multikey. (If none match, we return undefined.
    // Each element contains the kid, protectedHeader, possibly unprotectedHeader, and possibly payload (i.e. if successful).
    //
    // Additionally if a result is produced, the overall protectedHeader and unprotectedHeader contains only values
    // that were common to each of the verified signature elements.
    
    let jws = signature,
        kids = this.keyTags(key),
        signers = await Promise.all(jws.signatures.map(signature => this.verifySubSignature(jws, signature, key, kids)));
    if (!signers.find(signer => signer.payload)) return undefined;
    // Now canonicalize the signers and build up a result.
    let [first, ...rest] = signers,
        result = {protectedHeader: {}, unprotectedHeader: {}, signers},
        // For a header value to be common to verified results, it must be in the first result.
        getUnique = categoryName => {
          let firstHeader = first[categoryName],
              accumulatorHeader = result[categoryName];
          for (let label in firstHeader) {
            let value = firstHeader[label];
            if (rest.some(signerResult => signerResult[categoryName][label] !== value)) continue;
            accumulatorHeader[label] = value;
          }
        };
    getUnique('protectedHeader');
    getUnique('protectedHeader');
    // If anything verified, then set payload and allow text/json to be produced.
    // Callers can check signers[n].payload to determine if the result is what they want.
    result.payload = signers.find(signer => signer.payload).payload;
    return this.recoverDataFromContentType(result, options);
  }
};

Object.setPrototypeOf(MultiKrypto, Krypto); // Inherit from Krypto so that super.mumble() works.

class PersistedCollection {
  // Asynchronous local storage, available in web workers.
  constructor({collectionName = 'collection', dbName = 'asyncLocalStorage'} = {}) {
    // Capture the data here, but don't open the db until we need to.
    this.collectionName = collectionName;
    this.dbName = dbName;
    this.version = 1;
  }
  get db() { // Answer a promise for the database, creating it if needed.
    return this._db ??= new Promise(resolve => {
      const request = indexedDB.open(this.dbName, this.version);
      // createObjectStore can only be called from upgradeneeded, which is only called for new versions.
      request.onupgradeneeded = event => event.target.result.createObjectStore(this.collectionName);
      this.result(resolve, request);
    });
  }
  transaction(mode = 'read') { // Answer a promise for the named object store on a new transaction.
    const collectionName = this.collectionName;
    return this.db.then(db => db.transaction(collectionName, mode).objectStore(collectionName));
  }
  result(resolve, operation) {
    operation.onsuccess = event => resolve(event.target.result || ''); // Not undefined.
  }
  retrieve(tag) { // Promise to retrieve tag from collectionName.
    return new Promise(resolve => {
      this.transaction('readonly').then(store => this.result(resolve, store.get(tag)));
    });
  }
  store(tag, data) { // Promise to store data at tag in collectionName.
    return new Promise(resolve => {
      this.transaction('readwrite').then(store => this.result(resolve, store.put(data, tag)));
    });
  }
  remove(tag) { // Promise to remove tag from collectionName.
    return new Promise(resolve => {
      this.transaction('readwrite').then(store => this.result(resolve, store.delete(tag)));
    });
  }
}

function error(templateFunction, tag, cause = undefined) {
  // Formats tag (e.g., shortens it) and gives it to templateFunction(tag) to get
  // a suitable error message. Answers a rejected promise with that Error.
  let shortenedTag = tag.slice(0, 16) + "...",
      message = templateFunction(shortenedTag);
  return Promise.reject(new Error(message, {cause}));
}
function unavailable(tag) { // Do we want to distinguish between a tag being
  // unavailable at all, vs just the public encryption key being unavailable?
  // Right now we do not distinguish, and use this for both.
  return error(tag => `The tag ${tag} is not available.`, tag);
}

class KeySet {
  // A KeySet maintains two private keys: signingKey and decryptingKey.
  // See https://kilroy-code.github.io/distributed-security/docs/implementation.html#web-worker-and-iframe

  // Caching
  static keySets = {};
  static cached(tag) { // Return an already populated KeySet.
    return this.keySets[tag];
  }
  static clear(tag = null) { // Remove all KeySet instances or just the specified one, but does not destroy their storage.
    if (!tag) return KeySet.keySets = {};
    delete KeySet.keySets[tag];
  }
  constructor(tag) {
    this.tag = tag;
    this.memberTags = []; // Used when recursively destroying.
    KeySet.keySets[tag] = this; // Cache it.
  }
  // api.mjs provides the setter to changes these, and worker.mjs exercises it in browsers.
  static getUserDeviceSecret = getUserDeviceSecret;
  static Storage = Storage;

  // Principle operations.
  static async create(wrappingData) { // Create a persisted KeySet of the correct type, promising the newly created tag.
    let {time, ...keys} = await this.createKeys(wrappingData),
        {tag} = keys;
    await this.persist(tag, keys, wrappingData, time);
    return tag;
  }
  async destroy(options = {}) { // Terminates this keySet and associated storage, and same for OWNED recursiveMembers if asked.
    let {tag, memberTags, signingKey} = this,
        content = "", // Should storage have a separate operation to delete, other than storing empty?
        signature = await this.constructor.signForStorage({...options, message: content, tag, memberTags, signingKey, time: Date.now(), recovery: true});
    await this.constructor.store('EncryptionKey', tag, signature);
    await this.constructor.store(this.constructor.collection, tag, signature);
    this.constructor.clear(tag);
    if (!options.recursiveMembers) return;
    await Promise.allSettled(this.memberTags.map(async memberTag => {
      let memberKeySet = await KeySet.ensure(memberTag, {...options, recovery: true});
      await memberKeySet.destroy(options);
    }));
  }
  decrypt(encrypted, options) { // Promise {payload, text, json} as appropriate.
    let {tag, decryptingKey} = this,
        key = encrypted.recipients ? {[tag]: decryptingKey} : decryptingKey;
    return MultiKrypto.decrypt(key, encrypted, options);
  }
  // sign as either compact or multiKey general JWS.
  // There's some complexity here around being able to pass in memberTags and signingKey when the keySet is
  // being created and doesn't yet exist.
  static async sign(message, {tags = [], team:iss, member:act, time:iat = iss && Date.now(),
                              memberTags, signingKey,
                              ...options}) {
    if (iss && !act) { // Supply the value
      if (!memberTags) memberTags = (await KeySet.ensure(iss)).memberTags;
      let cachedMember = memberTags.find(tag => this.cached(tag));
      act = cachedMember || await this.ensure1(memberTags).then(keySet => keySet.tag);
    }
    if (iss && !tags.includes(iss)) tags = [iss, ...tags]; // Must be first
    if (act && !tags.includes(act)) tags = [...tags, act];

    let key = await this.produceKey(tags, async tag => {
      // Use specified signingKey (if any) for the first one.
      let key = signingKey || (await KeySet.ensure(tag, options)).signingKey;
      signingKey = null;
      return key;
    }, options);
    return MultiKrypto.sign(key, message, {iss, act, iat, ...options});
  }

  // Verify in the normal way, and then check deeply if asked.
  static async verify(signature, tags, options) {
    let isCompact = !signature.signatures,
        key = await this.produceKey(tags, tag => KeySet.verifyingKey(tag), options, isCompact),
        result = await MultiKrypto.verify(key, signature, options),
        memberTag = options.member === undefined ? result?.protectedHeader.act : options.member,
        notBefore = options.notBefore;
    function exit(label) {
      if (options.hardError) return Promise.reject(new Error(label));
    }
    if (!result) return exit('Incorrect signature.');
    if (memberTag) {
      if (options.member === 'team') {
        memberTag = result.protecteHeader.act;
        if (!memberTag) return exit('No member identified in signature.');
      }
      if (!tags.includes(memberTag)) { // Add to tags and result if not already present
        let memberKey = await KeySet.verifyingKey(memberTag),
            memberMultikey = {[memberTag]: memberKey},
            aux = await MultiKrypto.verify(memberMultikey, signature, options);
        if (!aux) return exit('Incorrect member signature.');
        tags.push(memberTag);
        result.signers.find(signer => signer.protectedHeader.kid === memberTag).payload = result.payload;
      }
    }
    if (memberTag || notBefore === 'team') {
      let teamTag = result.protectedHeader.iss || result.protectedHeader.kid, // Multi or single case.
          verifiedJWS = await this.retrieve(TeamKeySet.collection, teamTag),
          jwe = verifiedJWS?.json;
      if (memberTag && !teamTag) return exit('No team or main tag identified in signature');
      if (memberTag && jwe && !jwe.recipients.find(member => member.header.kid === memberTag)) return exit('Signer is not a member.');
      if (notBefore === 'team') notBefore = verifiedJWS?.protectedHeader.iat
        || (await this.retrieve('EncryptionKey', teamTag))?.protectedHeader.iat;
    }
    if (notBefore) {
      let {iat} = result.protectedHeader;
      if (iat < notBefore) return exit('Signature predates required timestamp.');
    }
    // Each signer should now be verified.
    if ((result.signers?.filter(signer => signer.payload).length || 1) !== tags.length) return exit('Unverified signer');
    return result;
  }

  // Key management
  static async produceKey(tags, producer, options, useSingleKey = tags.length === 1) {
    // Promise a key or multiKey, as defined by producer(tag) for each key.
    if (useSingleKey) {
      let tag = tags[0];
      options.kid = tag;   // Bashes options in the single-key case, because multiKey's have their own.
      return producer(tag);
    }
    let key = {},
        keys = await Promise.all(tags.map(tag => producer(tag)));
    // This isn't done in one step, because we'd like (for debugging and unit tests) to maintain a predictable order.
    tags.forEach((tag, index) => key[tag] = keys[index]);
    return key;
  }
  // The corresponding public keys are available publically, outside the keySet.
  static verifyingKey(tag) { // Promise the ordinary singular public key corresponding to the signing key, directly from the tag without reference to storage.
    return MultiKrypto.importRaw(tag).catch(() => unavailable(tag));
  }
  static async encryptingKey(tag) { // Promise the ordinary singular public key corresponding to the decryption key, which depends on public storage.
    let exportedPublicKey = await this.retrieve('EncryptionKey', tag);
    if (!exportedPublicKey) return unavailable(tag);
    return await MultiKrypto.importJWK(exportedPublicKey.json);
  }
  static async createKeys(memberTags) { // Promise a new tag and private keys, and store the encrypting key.
    let {publicKey:verifyingKey, privateKey:signingKey} = await MultiKrypto.generateSigningKey(),
        {publicKey:encryptingKey, privateKey:decryptingKey} = await MultiKrypto.generateEncryptingKey(),
        tag = await MultiKrypto.exportRaw(verifyingKey),
        exportedEncryptingKey = await MultiKrypto.exportJWK(encryptingKey),
        time = Date.now(),
        signature = await this.signForStorage({message: exportedEncryptingKey, tag, signingKey, memberTags, time, recovery: true});
    await this.store('EncryptionKey', tag, signature);
    return {signingKey, decryptingKey, tag, time};
  }
  static getWrapped(tag) { // Promise the wrapped key appropriate for this class.
    return this.retrieve(this.collection, tag);
  }
  static async ensure(tag, {device = true, team = true, recovery = false} = {}) { // Promise to resolve to a valid keySet, else reject.
    let keySet = this.cached(tag),
        stored = device && await DeviceKeySet.getWrapped(tag);
    if (stored) {
      keySet = new DeviceKeySet(tag);
    } else if (team && (stored = await TeamKeySet.getWrapped(tag))) {
      keySet = new TeamKeySet(tag);
    } else if (recovery && (stored = await RecoveryKeySet.getWrapped(tag))) { // Last, if at all.
      keySet = new RecoveryKeySet(tag);
    }
    // If things haven't changed, don't bother with setUnwrapped.
    if (keySet?.cached && keySet.cached === stored && keySet.decryptingKey && keySet.signingKey) return keySet;
    if (stored) keySet.cached = stored;
    else { // Not found. Could be a bogus tag, or one on another computer.
      this.clear(tag);
      return unavailable(tag);
    }
    return keySet.unwrap(keySet.cached).then(
      unwrapped => Object.assign(keySet, unwrapped),
      cause => {
        this.clear(keySet.tag);
        return error(tag => `You do not have access to the private key for ${tag}.`, keySet.tag, cause);
      });
  }
  static ensure1(tags) { // Find one valid keySet among tags, using recovery tags only if necessary.
    return Promise.any(tags.map(tag => KeySet.ensure(tag)))
      .catch(async reason => { // If we failed, try the recovery tags, if any, one at a time.
        for (let candidate of tags) {
          let keySet = await KeySet.ensure(candidate, {device: false, team: false, recovery: true}).catch(() => null);
          if (keySet) return keySet;
        }
        throw reason;
      });
  }
  static async persist(tag, keys, wrappingData, time = Date.now(), memberTags = wrappingData) { // Promise to wrap a set of keys for the wrappingData members, and persist by tag.
    let {signingKey} = keys,
        wrapped = await this.wrap(keys, wrappingData),
        signature = await this.signForStorage({message: wrapped, tag, signingKey, memberTags, time, recovery: true});
    await this.store(this.collection, tag, signature);
  }

  // Interactions with the cloud or local storage.
  static async store(collectionName, tag, signature) { // Store signature.
    if (collectionName === DeviceKeySet.collection) {
      // We called this. No need to verify here. But see retrieve().
      if (MultiKrypto.isEmptyJWSPayload(signature)) return LocalStore.remove(tag);
      return LocalStore.store(tag, signature);
    }
    return KeySet.Storage.store(collectionName, tag, signature);
  }
  static async retrieve(collectionName, tag) {  // Get back a verified result.
    let promise = (collectionName === DeviceKeySet.collection) ? LocalStore.retrieve(tag) : KeySet.Storage.retrieve(collectionName, tag),
        signature = await promise,
        key = signature && await KeySet.verifyingKey(tag);
    if (!signature) return;
    // While we rely on the Storage and LocalStore implementations to deeply check signatures during write,
    // here we still do a shallow verification check just to make sure that the data hasn't been messed with after write.
    if (signature.signatures) key = {[tag]: key}; // Prepare a multi-key
    return await MultiKrypto.verify(key, signature);
  }
}

class SecretKeySet extends KeySet { // Keys are encrypted based on a symmetric secret.
  static signForStorage({message, tag, signingKey, time}) {
    // Create a simple signature that does not specify iss or act.
    // There are no true memberTags to pass on and they are not used in simple signatures. However, the caller does
    // generically pass wrappingData as memberTags, and for RecoveryKeySets, wrappingData is the prompt. 
    // We don't store multiple times, so there's also no need for iat (which can be used to prevent replay attacks).
    return this.sign(message, {tags: [tag], signingKey, time});
  }
  static async wrappingKey(tag, prompt) { // The key used to (un)wrap the vault multi-key.
    let secret =  await this.getSecret(tag, prompt);
    // Alternatively, one could use {[wrappingData]: secret}, but that's a bit too cute, and generates a general form encryption.
    // This version generates a compact form encryption.
    return MultiKrypto.generateSecretKey(secret);
  }
  static async wrap(keys, prompt = '') { // Encrypt keyset by getUserDeviceSecret.
    let {decryptingKey, signingKey, tag} = keys,
        vaultKey = {decryptingKey, signingKey},
        wrappingKey = await this.wrappingKey(tag, prompt);
    return MultiKrypto.wrapKey(vaultKey, wrappingKey, {prompt}); // Order is backwards from encrypt.
  }
  async unwrap(wrappedKey) { // Decrypt keyset by getUserDeviceSecret.
    let parsed = wrappedKey.json || wrappedKey.text, // Handle both json and copact forms of wrappedKey.

        // The call to wrapKey, above, explicitly defines the prompt in the header of the encryption.
        protectedHeader = MultiKrypto.decodeProtectedHeader(parsed),
        prompt = protectedHeader.prompt, // In the "cute" form of wrappingKey, prompt can be pulled from parsed.recipients[0].header.kid,

        wrappingKey = await this.constructor.wrappingKey(this.tag, prompt),
        exported = (await MultiKrypto.decrypt(wrappingKey, parsed)).json;
    return await MultiKrypto.importJWK(exported, {decryptingKey: 'decrypt', signingKey: 'sign'});
  }
  static async getSecret(tag, prompt) { // getUserDeviceSecret from app.
    return KeySet.getUserDeviceSecret(tag, prompt);
  }
}

 // The user's answer(s) to a security question forms a secret, and the wrapped keys is stored in the cloude.
class RecoveryKeySet extends SecretKeySet {
  static collection = 'KeyRecovery';
}

// A KeySet corresponding to the current hardware. Wrapping secret comes from the app.
class DeviceKeySet extends SecretKeySet {
  static collection = 'Device';
}
const LocalStore = new PersistedCollection({collectionName: DeviceKeySet.collection});

class TeamKeySet extends KeySet { // A KeySet corresponding to a team of which the current user is a member (if getTag()).
  static collection = 'Team';
  static signForStorage({message, tag, ...options}) {
    return this.sign(message, {team: tag, ...options});
  }
  static async wrap(keys, members) {
    // This is used by persist, which in turn is used to create and changeMembership.
    let {decryptingKey, signingKey} = keys,
        teamKey = {decryptingKey, signingKey},
        wrappingKey = {};
    await Promise.all(members.map(memberTag => KeySet.encryptingKey(memberTag).then(key => wrappingKey[memberTag] = key)));
    let wrappedTeam = await MultiKrypto.wrapKey(teamKey, wrappingKey);
    return wrappedTeam;
  }
  async unwrap(wrapped) {
    let {recipients} = wrapped.json,
        memberTags = this.memberTags = recipients.map(recipient => recipient.header.kid);
    let keySet = await this.constructor.ensure1(memberTags); // We will use recovery tags only if we need to.
    let decrypted = await keySet.decrypt(wrapped.json);
    return await MultiKrypto.importJWK(decrypted.json);
  }
  async changeMembership({add = [], remove = []} = {}) {
    let {memberTags} = this,
        newMembers = memberTags.concat(add).filter(tag => !remove.includes(tag));
    await this.constructor.persist(this.tag, this, newMembers, Date.now(), memberTags);
    this.memberTags = newMembers;
  }
}

var name$1 = "@ki1r0y/distributed-security";
var version$1 = "1.0.2";
var description = "Signed and encrypted document infrastructure based on public key encryption and self-organizing users.";
var type = "module";
var exports = {
	node: "./lib/api.mjs",
	"default": "./index.mjs"
};
var imports = {
	"#raw": {
		node: "./lib/raw-node.mjs",
		"default": "./lib/raw-browser.mjs"
	},
	"#localStore": {
		node: "./lib/store-fs.mjs",
		"default": "./lib/store-indexed.mjs"
	},
	"#mkdir": {
		node: "./lib/mkdir-node.mjs",
		"default": "./lib/mkdir-browser.mjs"
	},
	"#origin": {
		node: "./lib/origin-node.mjs",
		"default": "./lib/origin-browser.mjs"
	},
	"#internals": {
		node: "./spec/support/internals.mjs",
		"default": "./spec/support/internal-browser-bundle.mjs"
	}
};
var scripts = {
	build: "rollup -c",
	"build-dev": "npx rollup -c --environment NODE_ENV:development",
	test: "jasmine"
};
var engines = {
	node: ">=20.0.0"
};
var repository = {
	type: "git",
	url: "git+https://github.com/kilroy-code/distributed-security.git"
};
var publishConfig = {
	registry: "https://registry.npmjs.org"
};
var keywords = [
	"encryption",
	"pki",
	"dao"
];
var author = {
	name: "Howard Stearns",
	email: "howard@ki1r0y.com"
};
var license = "MIT";
var bugs = {
	url: "https://github.com/kilroy-code/distributed-security/issues"
};
var homepage = "https://github.com/kilroy-code/distributed-security#readme";
var devDependencies = {
	"@rollup/plugin-eslint": "^9.0.5",
	"@rollup/plugin-json": "^6.1.0",
	"@rollup/plugin-node-resolve": "^15.2.3",
	"@rollup/plugin-terser": "^0.4.4",
	eslint: "^8.57.0",
	jasmine: "^4.5.0",
	"jsonc-eslint-parser": "^2.4.0",
	rollup: "^4.13.0"
};
var dependencies = {
	"@ki1r0y/jsonrpc": "^1.0.1",
	jose: "^5.2.3"
};
var _package = {
	name: name$1,
	version: version$1,
	description: description,
	type: type,
	exports: exports,
	imports: imports,
	scripts: scripts,
	engines: engines,
	repository: repository,
	publishConfig: publishConfig,
	keywords: keywords,
	author: author,
	license: license,
	bugs: bugs,
	homepage: homepage,
	devDependencies: devDependencies,
	dependencies: dependencies
};

// Because eslint doesn't recognize import assertions
const {name, version} = _package;

const Security = { // This is the api for the vault. See https://kilroy-code.github.io/distributed-security/docs/implementation.html#creating-the-vault-web-worker-and-iframe

  // Client-defined resources.
  set Storage(storage) { // Allows a node app (no vaultt) to override the default storage.
    KeySet.Storage = storage;
  },
  get Storage() { // Allows a node app (no vault) to examine storage.
    return KeySet.Storage;
  },
  set getUserDeviceSecret(functionOfTagAndPrompt) {  // Allows a node app (no vault) to override the default.
    KeySet.getUserDeviceSecret = functionOfTagAndPrompt;
  },
  get getUserDeviceSecret() {
    return KeySet.getUserDeviceSecret;
  },
  ready: {name, version, origin: KeySet.Storage.origin},

  // The four basic operations. ...rest may be one or more tags, or may be {tags, team, member, contentType, ...}
  async encrypt(message, ...rest) { // Promise a JWE.
    let options = {}, tags = this.canonicalizeParameters(rest, options),
        key = await KeySet.produceKey(tags, tag => KeySet.encryptingKey(tag), options);
    return MultiKrypto.encrypt(key, message, options);
  },
  async decrypt(encrypted, ...rest) { // Promise {payload, text, json} as appropriate.
    let options = {},
        [tag] = this.canonicalizeParameters(rest, options, encrypted),
        {recovery, ...otherOptions} = options,
        keySet = await KeySet.ensure(tag, {recovery});
    return keySet.decrypt(encrypted, otherOptions);
  },
  async sign(message, ...rest) { // Promise a JWS.
    let options = {}, tags = this.canonicalizeParameters(rest, options);
    return KeySet.sign(message, {tags, ...options});
  },
  async verify(signature, ...rest) { // Promise {payload, text, json} as appropriate.
    let options = {}, tags = this.canonicalizeParameters(rest, options, signature);
    return KeySet.verify(signature, tags, options);
  },

  // Tag maintance.
  async create(...members) { // Promise a newly-created tag with the given members. The member tags (if any) must already exist.
    if (!members.length) return await DeviceKeySet.create();
    let prompt = members[0].prompt;
    if (prompt) return await RecoveryKeySet.create(prompt);
    return await TeamKeySet.create(members);
  },
  async changeMembership({tag, recovery = false, ...options}) { // Promise to add or remove members.
    let keySet = await KeySet.ensure(tag, {recovery, ...options}); // Makes no sense to changeMembership of a recovery key.
    return keySet.changeMembership(options);
  },
  async destroy(tagOrOptions) { // Promise to remove the tag and any associated data from all storage.
    if ('string' === typeof tagOrOptions) tagOrOptions = {tag: tagOrOptions};
    let {tag, recovery = true, ...otherOptions} = tagOrOptions,
        options = {recovery, ...otherOptions},
        keySet = await KeySet.ensure(tag, options);
    return keySet.destroy(options);
  },
  clear(tag) { // Remove any locally cached KeySet for the tag, or all KeySets if not tag specified.
    KeySet.clear(tag);
  },

  decodeProtectedHeader: MultiKrypto.decodeProtectedHeader,
  canonicalizeParameters(rest, options, token) { // Return the actual list of tags, and bash options.
    // rest may be a list of tag strings
    //    or a list of one single object specifying named parameters, including either team, tags, or neither
    // token may be a JWE or JSE, or falsy, and is used to supply tags if necessary.
    if (rest.length > 1 || rest[0]?.length !== undefined) return rest;
    let {tags = [], contentType, time, ...others} = rest[0] || {},
	{team} = others; // Do not strip team from others.
    if (!tags.length) {
      if (rest.length && rest[0].length) tags = rest; // rest not empty, and its first is string-like.
      else if (token) { // get from token
        if (token.signatures) tags = token.signatures.map(sig => this.decodeProtectedHeader(sig).kid);
        else if (token.recipients) tags = token.recipients.map(rec => rec.header.kid);
        else {
          let kid = this.decodeProtectedHeader(token).kid; // compact token
          if (kid) tags = [kid];
        }
      }
    }
    if (team && !tags.includes(team)) tags = [team, ...tags];
    if (contentType) options.cty = contentType;
    if (time) options.iat = time;
    Object.assign(options, others);

    return tags;
  }
};

// Setup.
//jasmine.getEnv().configure({random: false});
let thisDeviceSecret = "secret",
    secret = thisDeviceSecret;
async function withSecret(thunk) {
  secret = "other";
  await thunk();
  secret = thisDeviceSecret;
}
function getSecret(tag, recoveryPrompt = '') {
  return recoveryPrompt + secret;
}
//import {Krypto, MultiKrypto, InternalSecurity, KeySet, LocalCollection} from '@ki1r0y/distributed-security/dist/internal-browser-bundle.mjs';
// If this file is referenced directly, as is, in a test.html, then we'll need to have a bundle prepared,
// that gets resolved through package.json:
//import {Krypto, MultiKrypto, InternalSecurity, KeySet, LocalCollection} from '#internals';

// Define some globals in a browser for debugging.
if (typeof(window) !== 'undefined') Object.assign(window, {Security: api, Krypto, MultiKrypto, Storage: Storage$1});

describe('Distributed Security', function () {
  let message = makeMessage(),
      originalStorage = api.Storage,
      originalSecret = api.getUserDeviceSecret;
  beforeAll(function () {
    Storage$1.Security = api;
    api.Storage = Storage$1;
    api.getUserDeviceSecret = getSecret;
    Security.Storage = Storage$1;
    Security.getUserDeviceSecret = getSecret;
  });
  afterAll(function () {
    api.Storage = originalStorage;
    api.getUserDeviceSecret = originalSecret;
  });
  describe('Krypto', function () {
    testKrypto(Krypto);
  });
  describe('MultiKrypto', function () {
    testMultiKrypto(MultiKrypto);
  });
  describe('Security', function () {
    const slowKeyCreation = 60e3; // e.g., Safari needs about 15 seconds. Android needs more
    async function makeKeySets(scope) { // Create a standard set of test vaults through context.
      let tags = {};
      let [device, recovery, otherRecovery] = await Promise.all([
        scope.create(),
        scope.create({prompt: "what?"}),
        scope.create({prompt: "nope!"})
      ]);
      let otherDevice, otherUser;
      await withSecret(async function () {
        otherDevice = await scope.create();
        otherUser = await scope.create(otherDevice);
      });
      let user = await scope.create(device);
      // // Note: same members, but a different identity.
      let [team, otherTeam] = await Promise.all([scope.create(user, otherUser), scope.create(otherUser, user)]);
      tags.device = device;
      tags.otherDevice = otherDevice;
      tags.recovery = recovery; tags.otherRecovery = otherRecovery;
      tags.user = user; tags.otherUser = otherUser;
      tags.team = team; tags.otherTeam = otherTeam;
      return tags;
    }
    async function destroyKeySets(scope, tags) {
      await scope.destroy(tags.otherTeam);
      await scope.destroy(tags.team);
      await scope.destroy(tags.user);
      await scope.destroy(tags.device);
      await scope.destroy(tags.recovery);
      await scope.destroy(tags.otherRecovery);
      await withSecret(async function () {
        await scope.destroy(tags.otherUser);
        await scope.destroy(tags.otherDevice);
      });
    }
    describe('internal machinery', function () {
      let tags;
      beforeAll(async function () {
        tags = await makeKeySets(Security);
      }, slowKeyCreation);
      afterAll(async function () {
        await destroyKeySets(Security, tags);
      }, slowKeyCreation);
      function vaultTests(label, tagsKey, options = {}) {
        describe(label, function () { 
          let vault, tag;
          beforeAll(async function () {
            tag = tags[tagsKey];
            vault = await KeySet.ensure(tag, {recovery:true});
          });
          it('tag is exported verify key, and sign() pairs with it.', async function () {
            let verifyKey = await MultiKrypto.importRaw(tag),
                exported = await MultiKrypto.exportRaw(verifyKey);
            expect(typeof tag).toBe('string');
            expect(exported).toBe(tag);

            let vault = await KeySet.ensure(tag, {recovery:true});

            let signature = await KeySet.sign(message, {tags: [tag], signingKey: vault.signingKey, ...options}),
                verification = await MultiKrypto.verify(verifyKey, signature);
            isBase64URL(signature);
            expect(verification).toBeTruthy();
          });
          it('public encryption tag can be retrieved externally, and vault.decrypt() pairs with it.', async function () {
            let tag = vault.tag,
                retrieved = await Storage$1.retrieve('EncryptionKey', tag),
                verified = await api.verify(retrieved, tag),
                imported = await MultiKrypto.importJWK(verified.json),
                encrypted = await MultiKrypto.encrypt(imported, message),
                decrypted = await vault.decrypt(encrypted, options);
            expect(decrypted.text).toBe(message);
          });
        });
      }
      vaultTests('DeviceKeySet', 'device');
      vaultTests('RecoveryKeySet', 'recovery', {recovery: true}); // Recovery tags are not normally used to decrypt or sign, but they can be allowed for testing.
      vaultTests('TeamKeySet', 'user');
      describe('local store', function () {
        var store; 
        beforeAll(async function () {
          store = new PersistedCollection({dbName: 'testStore', collectionName: 'Foo'});
          await new Promise(resolve => setTimeout(resolve, 2e3)); // fixme remove
        });
        it('can remove without existing.', async function () {
          let tag = 'nonExistant';
          expect(await store.remove(tag)).toBe("");
        });
        it('can retrieve without existing.', async function () {
          let tag = 'nonExistant';
          expect(await store.retrieve(tag)).toBe("");
        });
        it('retrieves and can remove what is stored.', async function () {
          let tag = 'x', message = "hello";
          expect(await store.store(tag, message)).not.toBeUndefined();
          expect(await store.retrieve(tag)).toBe(message);
          expect(await store.remove(tag)).toBe("");
          expect(await store.retrieve(tag)).toBe("");
        });
        it('can write a lot without getting jumbled.', async function () {
          let count = 1000, prefix = "y", tags = [];
          for (let i = 0; i < count; i++) tags.push(prefix + i);
          let start, elapsed, per;

          start = Date.now();
          let stores = await Promise.all(tags.map((tag, index) => store.store(tag, index.toString())));
          elapsed = Date.now() - start; per = elapsed/count;
          //console.log({elapsed, per});
          expect(per).toBeLessThan(60);
          stores.forEach(storeResult => expect(storeResult).not.toBeUndefined());

          start = Date.now();
          let reads = await Promise.all(tags.map(tag => store.retrieve(tag)));
          elapsed = Date.now() - start; per = elapsed/count;
          //console.log({elapsed, per});
          expect(per).toBeLessThan(3);
          reads.forEach((readResult, index) => expect(readResult).toBe(index.toString()));

          start = Date.now();
          let removes = await Promise.all(tags.map(tag => store.remove(tag)));
          elapsed = Date.now() - start; per = elapsed/count;
          //console.log({elapsed, per});
          expect(per).toBeLessThan(8);
          removes.forEach(removeResult => expect(removeResult).toBe(""));

          start = Date.now();
          let rereads = await Promise.all(tags.map(tag => store.retrieve(tag)));
          elapsed = Date.now() - start; per = elapsed/count;
          //console.log({elapsed, per});
          expect(per).toBeLessThan(0.1);
          rereads.forEach(readResult => expect(readResult).toBe(""));
        }, 15e5);
      });
    });

    describe("API", function () {
      let tags;
      beforeAll(async function () {
        console.log(await api.ready);
        tags = await makeKeySets(api);
      }, slowKeyCreation);
      afterAll(async function () {
        await destroyKeySets(api, tags);
      }, slowKeyCreation);
      function test(label, tagsName, otherOwnedTagsName, unownedTagName, options = {}) {
        describe(label, function () {
          let tag, otherOwnedTag;
          beforeAll(function () {
            tag = tags[tagsName];
            otherOwnedTag = tags[otherOwnedTagsName];
          });
          describe('signature', function () {
            describe('of one tag', function () {
              it('can sign and be verified.', async function () {
                let signature = await api.sign(message, {tags:[tag], ...options});
                isBase64URL(signature);
                expect(await api.verify(signature, tag)).toBeTruthy();
              });
              it('can be verified with the tag included in the signature.', async function () {
                let signature = await api.sign(message, {tags: [tag], ...options});
                expect(await api.verify(signature)).toBeTruthy();
              });
              it('cannot sign for a different key.', async function () {
                let signature = await api.sign(message, {tags: [otherOwnedTag], ...options});
                expect(await api.verify(signature, tag)).toBeUndefined();
              });
              it('cannot sign with an unowned key.', async function () {
                expect(await api.sign("something", {tags: tags[unownedTagName], ...options}).catch(() => undefined)).toBeUndefined();
              });
              it('distinguishes between correctly signing false and key failure.', async function () {
                let signature = await api.sign(false, {tags:[tag], ...options}),
                    verified = await api.verify(signature, tag);
                expect(verified.json).toBe(false);
              });
              it('can sign text and produce verified result with text property.', async function () {
                let signature = await api.sign(message, {tags:[tag], ...options}),
                    verified = await api.verify(signature, tag);
                isBase64URL(signature);
                expect(verified.text).toBe(message);
              });
              it('can sign json and produce verified result with json property.', async function () {
                let message = {x: 1, y: ["abc", null, false]},
                    signature = await api.sign(message, {tags: [tag], ...options}),
                    verified = await api.verify(signature, tag);
                isBase64URL(signature);
                expect(verified.json).toEqual(message);
              });
              it('can sign binary and produce verified result with payload property.', async function () {
                let message = new Uint8Array([1, 2, 3]),
                    signature = await api.sign(message, {tags: [tag], ...options}),
                    verified = await api.verify(signature, tag);
                isBase64URL(signature);
                expect(verified.payload).toEqual(message);
              });
              it('uses contentType and time if supplied.', async function () {
                let contentType = 'text/html',
                    time = Date.now(),
                    message = "<something else>",
                    signature = await api.sign(message, {tags: [tag], contentType, time, ...options}),
                    verified = await api.verify(signature, tag);
                isBase64URL(signature);
                expect(verified.text).toEqual(message);
                expect(verified.protectedHeader.cty).toBe(contentType);
                expect(verified.protectedHeader.iat).toBe(time);
              });
            });
            describe('of multiple tags', function () {
              it('can sign and be verified.', async function () {
                let signature = await api.sign(message, {tags: [tag, otherOwnedTag], ...options}),
                    verification = await api.verify(signature, otherOwnedTag, tag);
                expect(verification).toBeTruthy(); // order does not matter
                expect(verification.signers[0].payload).toBeTruthy(); // All recipients listed in verify
                expect(verification.signers[1].payload).toBeTruthy();
              });
              it('does not attempt to verify unenumerated tags if any are explicit', async function () {
                let signature = await api.sign(message, {tags: [tag, otherOwnedTag], ...options}),
                    verification = await api.verify(signature, otherOwnedTag);
                expect(verification).toBeTruthy(); // order does not matter
                expect(verification.signers[0].payload).toBeFalsy(); // Because we explicitly verified with 1, not 0.
                expect(verification.signers[1].payload).toBeTruthy();
              });
              it('can be verified with the tag included in the signature.', async function () {
                let signature = await api.sign(message, {tags: [tag, otherOwnedTag], ...options}),
                    verification = await api.verify(signature);
                expect(verification).toBeTruthy();
                expect(verification.signers[0].payload).toBeTruthy(); // All are checked, and in this case, pass.
                expect(verification.signers[1].payload).toBeTruthy();
              });
              describe('bad verification', function () {
                let oneMore;
                beforeAll(async function () { oneMore = await api.create(); });
                afterAll(async function () { await api.destroy(oneMore); });
                describe('when mixing single and multi-tags', function () {
                  it('fails with extra signing tag.', async function () {
                    let signature = await api.sign(message, {tags: [otherOwnedTag], ...options});
                    expect(await api.verify(signature, tag)).toBeUndefined();
                  });
                  it('fails with extra verifying.', async function () {
                    let signature = await api.sign(message, {tags: [tag], ...options});
                    expect(await api.verify(signature, tag, otherOwnedTag)).toBeUndefined();
                  });
                });
                describe('when mixing multi-tag lengths', function () {
                  it('fails with mismatched signing tag.', async function () {
                    let signature = await api.sign(message, {tags: [otherOwnedTag, oneMore], ...options}),
                        verified = await api.verify(signature, tag, oneMore);
                    expect(verified).toBeUndefined();
                  });
                  it('fails with extra verifying tag.', async function () {
                    let signature = await api.sign(message, {tags: [tag, oneMore], ...options});
                    expect(await api.verify(signature, tag, otherOwnedTag, oneMore)).toBeUndefined();
                  });
                });
              });
              it('distinguishes between correctly signing false and key failure.', async function () {
                let signature = await api.sign(false, {tags: [tag, otherOwnedTag], ...options}),
                    verified = await api.verify(signature, tag, otherOwnedTag);
                expect(verified.json).toBe(false);
              });
              it('can sign text and produce verified result with text property.', async function () {
                let signature = await api.sign(message, {tags: [tag, otherOwnedTag], ...options}),
                    verified = await api.verify(signature, tag, otherOwnedTag);
                expect(verified.text).toBe(message);
              });
              it('can sign json and produce verified result with json property.', async function () {
                let message = {x: 1, y: ["abc", null, false]},
                    signature = await api.sign(message, {tags: [tag, otherOwnedTag], ...options}),
                    verified = await api.verify(signature, tag, otherOwnedTag);
                expect(verified.json).toEqual(message);
              });
              it('can sign binary and produce verified result with payload property.', async function () {
                let message = new Uint8Array([1, 2, 3]),
                    signature = await api.sign(message, {tags: [tag, otherOwnedTag], ...options}),
                    verified = await api.verify(signature, tag, otherOwnedTag);
                expect(verified.payload).toEqual(message);
              });
              it('uses contentType and time if supplied.', async function () {
                let contentType = 'text/html',
                    time = Date.now(),
                    message = "<something else>",
                    signature = await api.sign(message, {tags: [tag, otherOwnedTag], contentType, time, ...options}),
                    verified = await api.verify(signature, tag, otherOwnedTag);
                expect(verified.text).toEqual(message);
                expect(verified.protectedHeader.cty).toBe(contentType);
                expect(verified.protectedHeader.iat).toBe(time);
              });
            });
          });
          describe('encryption', function () {
            describe('with a single tag', function () {
              it('can decrypt what is encrypted for it.', async function () {
                let encrypted = await api.encrypt(message, tag),
                    decrypted = await api.decrypt(encrypted, {tags: [tag], ...options});
                isBase64URL(encrypted);
                expect(decrypted.text).toBe(message);
              });
              it('can be decrypted using the tag included in the encryption.', async function () {
                let encrypted = await api.encrypt(message, tag),
                    decrypted = await api.decrypt(encrypted, options);
                expect(decrypted.text).toBe(message);
              });
              it('is url-safe base64.', async function () {
                isBase64URL(await api.encrypt(message, tag));
              });
              it('specifies kid.', async function () {
                let header = Krypto.decodeProtectedHeader(await api.encrypt(message, tag));
                expect(header.kid).toBe(tag);
              });
              it('cannot decrypt what is encrypted for a different key.', async function () {
                let message = makeMessage(446),
                    encrypted = await api.encrypt(message, otherOwnedTag),
                    errorMessage = await api.decrypt(encrypted, {tags: [tag], ...options}).catch(e => e.message);
                expect(errorMessage.toLowerCase()).toContain('operation');
                // Some browsers supply a generic message, such as 'The operation failed for an operation-specific reason'
                // IF there's no message at all, our jsonrpc supplies one with the jsonrpc 'method' name.
                //expect(errorMessage).toContain('decrypt');
              });
              it('handles binary, and decrypts as same.', async function () {
                let message = new Uint8Array([21, 31]),
                    encrypted = await api.encrypt(message, tag),
                    decrypted = await api.decrypt(encrypted, {tags: [tag], ...options}),
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBeUndefined();
                sameTypedArray(decrypted, message);
              });
              it('handles text, and decrypts as same.', async function () {
                let encrypted = await api.encrypt(message, tag),
                    decrypted = await api.decrypt(encrypted, {tags: [tag], ...options}),
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBe('text/plain');
                expect(decrypted.text).toBe(message);
              });
              it('handles json, and decrypts as same.', async function () {
                let message = {foo: 'bar'},
                    encrypted = await api.encrypt(message, tag),
                    decrypted = await api.decrypt(encrypted, {tags: [tag], ...options}),
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBe('json');
                expect(decrypted.json).toEqual(message);
              });
              it('uses contentType and time if supplied.', async function () {
                let contentType = 'text/html',
                    time = Date.now(),
                    message = "<something else>",
                    encrypted = await api.encrypt(message, {tags: [tag], contentType, time}),
                    decrypted = await api.decrypt(encrypted, {tags: [tag], ...options}),
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBe(contentType);
                expect(header.iat).toBe(time);
                expect(decrypted.text).toBe(message);
              });
            });
            describe('with multiple tags', function () {
              it('can be decrypted by any one of them.', async function () {
                let encrypted = await api.encrypt(message, tag, otherOwnedTag),
                    decrypted1 = await api.decrypt(encrypted, {tags: [tag], ...options}),
                    decrypted2 = await api.decrypt(encrypted, {tags: [otherOwnedTag], ...options});
                expect(decrypted1.text).toBe(message);
                expect(decrypted2.text).toBe(message);        
              });
              it('can be decrypted using the tag included in the encryption.', async function () {
                let encrypted = await api.encrypt(message, tag, otherOwnedTag),
                    decrypted = await api.decrypt(encrypted, options);
                expect(decrypted.text).toBe(message);
              });
              it('can be be made with tags you do not own.', async function () {
                let encrypted = await api.encrypt(message, tag, tags[unownedTagName], otherOwnedTag),
                    decrypted1 = await api.decrypt(encrypted, {tags: [tag], ...options}),
                    decrypted2 = await api.decrypt(encrypted, {tags: [otherOwnedTag], ...options});
                expect(decrypted1.text).toBe(message);
                expect(decrypted2.text).toBe(message);        
              });
              it('cannot be decrypted by a different tag.', async function () {
                let encrypted = await api.encrypt(message, tag, tags[unownedTagName]),
                    decrypted = await api.decrypt(encrypted, {tags: [otherOwnedTag], ...options});
                expect(decrypted).toBeUndefined();
              });
              it('specifies kid in each recipient.', async function () {
                let encrypted = await api.encrypt(message, tag, otherOwnedTag),
                    recipients = encrypted.recipients;
                expect(recipients.length).toBe(2);
                expect(recipients[0].header.kid).toBe(tag);
                expect(recipients[1].header.kid).toBe(otherOwnedTag);
              });

              it('handles binary, and decrypts as same.', async function () {
                let message = new Uint8Array([21, 31]),
                    encrypted = await api.encrypt(message, tag, otherOwnedTag),
                    decrypted = await api.decrypt(encrypted, {tags: [tag], ...options}),
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBeUndefined();
                sameTypedArray(decrypted, message);
              });
              it('handles text, and decrypts as same.', async function () {
                let encrypted = await api.encrypt(message, tag, otherOwnedTag),
                    decrypted = await api.decrypt(encrypted, {tags: [tag], ...options}),
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBe('text/plain');
                expect(decrypted.text).toBe(message);
              });
              it('handles json, and decrypts as same.', async function () {
                let message = {foo: 'bar'},
                    encrypted = await api.encrypt(message, tag, otherOwnedTag),
                    decrypted = await api.decrypt(encrypted, {tags: [tag], ...options}),
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBe('json');
                expect(decrypted.json).toEqual(message);
              });
              it('uses contentType and time if supplied.', async function () {
                let contentType = 'text/html',
                    time = Date.now(),
                    message = "<something else>",
                    encrypted = await api.encrypt(message, {tags: [tag, otherOwnedTag], contentType, time}),
                    decrypted = await api.decrypt(encrypted, {tags: [tag], ...options}),
                    header = Krypto.decodeProtectedHeader(encrypted);
                expect(header.cty).toBe(contentType);
                expect(header.iat).toBe(time);
                expect(decrypted.text).toBe(message);
              });
            });
          });
        });
      }
      test('DeviceKeySet', 'device', 'user', 'otherDevice'); // We own user, but it isn't the same as device.
      test('RecoveryKeySet', 'recovery', 'otherRecovery', 'otherDevice', {recovery:true}); // sign/decrypt is not normally done with recovery keys, but we can force it.
      test('User TeamKeySet', 'user', 'device', 'otherUser'); // We ownd device, but it isn't the same as user.
      test('Team TeamKeySet', 'team', 'otherTeam', 'otherUser');
      describe('storage', function () {
        it('will only let a current member write new keys.', async function () {
          let testMember = await api.create(),
              team = tags.team,
              currentEncryptedSignature = await Storage$1.retrieve('Team', team),
              currentEncryptedKey = (await api.verify(currentEncryptedSignature)).json;
          function signIt() {
            return api.sign(currentEncryptedKey, {team, member: testMember, time: Date.now()})
          }
          await api.changeMembership({tag: team, add: [testMember]});
          let signatureWhileMember = await signIt();
          expect(await Storage$1.store('Team', tags.team, signatureWhileMember)).toBeDefined(); // That's fine
          await api.changeMembership({tag: team, remove: [testMember]});
          let signatureWhileNotAMember = await signIt();
          expect(await Storage$1.store('Team', team, signatureWhileNotAMember).catch(() => 'failed')).toBe('failed'); // Valid signature by an improper tag.
          expect(await Storage$1.store('Team', team, signatureWhileMember).catch(() => 'failed')).toBe('failed'); // Can't replay sig while member.
          expect(await Storage$1.store('Team', team, currentEncryptedSignature).catch(() => 'failed')).toBe('failed'); // Can't replay exact previous sig either.
          await api.destroy(testMember);
        });
        it('will only let a current member write new public encryption key.', async function () {
          let testMember = await api.create(),
              team = tags.team,
              currentSignature = await Storage$1.retrieve('EncryptionKey', team),
              currentKey = (await api.verify(currentSignature)).json;
          function signIt() {
            return api.sign(currentKey, {team, member: testMember, time: Date.now()})
          }
          await api.changeMembership({tag: team, add: [testMember]});
          let signatureWhileMember = await signIt();
          expect(await Storage$1.store('EncryptionKey', tags.team, signatureWhileMember)).toBeDefined(); // That's fine
          await api.changeMembership({tag: team, remove: [testMember]});
          let signatureWhileNotAMember = await signIt();
          expect(await Storage$1.store('EncryptionKey', team, signatureWhileNotAMember).catch(() => 'failed')).toBe('failed'); // Valid signature by an improper tag.
          expect(await Storage$1.store('EncryptionKey', team, signatureWhileMember).catch(() => 'failed')).toBe('failed'); // Can't replay sig while member.
          expect(await Storage$1.store('EncryptionKey', team, currentSignature).catch(() => 'failed')).toBe('failed'); // Can't replay exact previous sig either.
          await api.destroy(testMember);
        }, 10e3);
        it('will only let owner of a device write new public device encryption key.', async function () {
          let testDevice = await api.create(),
              anotherDevice = await api.create(),
              currentSignature = await Storage$1.retrieve('EncryptionKey', testDevice),
              currentKey = (await api.verify(currentSignature)).json;
          function signIt(tag) {
            return api.sign(currentKey, {tags: [tag], time: Date.now()})
          }
          let signatureOfOwner = await signIt(testDevice);
          expect(await Storage$1.store('EncryptionKey', testDevice, signatureOfOwner)).toBeDefined(); // That's fine
          let signatureOfAnother = await signIt(anotherDevice);
          expect(await Storage$1.store('EncryptionKey', testDevice, signatureOfAnother).catch(() => 'failed')).toBe('failed'); // Valid signature by an improper tag.
          // Device owner can restore.  This is subtle:
          // There is no team key in the cloud to compare the time with. We do compare against the current value (as shown below),
          // but we do not prohibit the same timestamp from being reused.
          expect(await Storage$1.store('EncryptionKey', testDevice, signatureOfOwner)).toBeDefined;
          expect(await Storage$1.store('EncryptionKey', testDevice, currentSignature).catch(() => 'failed')).toBe('failed'); // Can't replay exact previous sig.
          await api.destroy(testDevice);
          await api.destroy(anotherDevice);
        }, 10e3);
      });
      describe('auditable signatures', function () {
        describe('by an explicit member', function () {
          let signature, verification;
          beforeAll(async function () {
            signature = await api.sign(message, {team: tags.team, member: tags.user});
            verification = await api.verify(signature, tags.team, tags.user);
          });
          it('recognizes a team with a member.', async function () {
            expect(verification).toBeTruthy();
            expect(verification.text).toBe(message);
          });
          it('defines iss.', function () {
            expect(verification.protectedHeader.iss).toBe(tags.team);
          });
          it('defines act.', function () {
            expect(verification.protectedHeader.act).toBe(tags.user);
          });
        });
        describe('automatically supplies a valid member', function () {
          it('if you have access', async function () {
            let signature = await api.sign(message, {team: tags.team}),
                member = Krypto.decodeProtectedHeader(signature.signatures[0]).act,
                verification = await api.verify(signature, tags.team, member);
            expect(verification).toBeTruthy();
            expect(member).toBeTruthy();
            expect(verification.protectedHeader.act).toBe(member);
            expect(verification.protectedHeader.iat).toBeTruthy();
          });
        });
        describe('with a valid user who is not a member', function () {
          let nonMember;
          beforeAll(async function () { nonMember = await api.create(tags.device); });
          afterAll(async function () { await api.destroy(nonMember); });
          it('verifies as an ordinary dual signature.', async function () {
            let signature = await api.sign(message, tags.team, nonMember),
                verification = await api.verify(signature, tags.team, nonMember);
            expect(verification.text).toBe(message);
            expect(verification.protectedHeader.iss).toBeUndefined();
            expect(verification.protectedHeader.act).toBeUndefined();
          }, 10e3);
          it('does not verify as a dual signature specifying team and member.', async function () {
            let signature = await api.sign(message, {team: tags.team, member: nonMember}),
                verification = await api.verify(signature, tags.team, nonMember);
            expect(verification).toBeUndefined();
          });
        }, 10e3);
        describe('with a past member', function () {
          let member, signature, time;
          beforeAll(async function () {
            time = Date.now() - 1;
            member = await api.create();
            await api.changeMembership({tag: tags.team, add: [member]});
            signature = await api.sign("message", {team: tags.team, member, time}); // while member
            await api.changeMembership({tag: tags.team, remove: [member]});
          });
          afterAll(async function () {
            await api.destroy(member);
          });
          it('fails by default.', async function () {
            let verified = await api.verify(signature, member);
            expect(verified).toBeUndefined();
          });
          it('contains act in signature but verifies if we tell it not to check membership.', async function () {
            let verified = await api.verify(signature, {team: tags.team, member: false});
            expect(verified).toBeTruthy();
            expect(verified.text).toBe("message");
            expect(verified.protectedHeader.act).toBe(member);
            expect(verified.protectedHeader.iat).toBeTruthy();
          });
          it('fails if we tell it to check notBefore:"team", even if we tell it not to check membership.', async function () {
            let verified = await api.verify(signature, {team: tags.team, member: false, notBefore:'team'});
            expect(verified).toBeUndefined();
          });
        });
      });
      describe('miscellaneous', function () {
        it('can safely be used when a device is removed, but not after being entirely destroyed.', async function () {
          let [d1, d2] = await Promise.all([api.create(), api.create()]),
              u = await api.create(d1, d2),
              t = await api.create(u);

          let encrypted = await api.encrypt(message, t),
              decrypted = await api.decrypt(encrypted, t);
          expect(decrypted.text).toBe(message);
          // Remove the first deep member
          decrypted = await api.decrypt(encrypted, t);
          await api.changeMembership({tag: u, remove: [d1]});
          expect(decrypted.text).toBe(message);
          // Put it back.
          await api.changeMembership({tag: u, add: [d1]});
          decrypted = await api.decrypt(encrypted, t);
          expect(decrypted.text).toBe(message);
          // Make the other unavailable
          await api.destroy(d2);
          decrypted = await api.decrypt(encrypted, t);
          expect(decrypted.text).toBe(message);
          // Destroy it all the way down.
          await api.destroy({tag: t, recursiveMembers: true});
          let errorMessage = await api.decrypt(encrypted, t).then(() => null, e => e.message);
          expect(errorMessage).toBeTruthy();
        }, slowKeyCreation);
        it('device is useable as soon as it resolves.', async function () {
          let device = await api.create();
          expect(await api.sign("anything", device)).toBeTruthy();
          await api.destroy(device);
        }, 10e3);
        it('team is useable as soon as it resolves.', async function () {
          let team = await api.create(tags.device); // There was a bug once: awaiting a function that did return its promise.
          expect(await api.sign("anything", team)).toBeTruthy();
          await api.destroy(team);
        });
        it('allows recovery prompts that contain dot (and confirm that a team can have a single recovery tag as member).', async function () {
          let recovery = await api.create({prompt: "foo.bar"});
          let user = await api.create(recovery);
          let message = "red.white";
          let encrypted = await api.encrypt(message, user);
          let decrypted = await api.decrypt(encrypted, user);
          let signed = await api.sign(message, user);
          let verified = await api.verify(signed, user);
          expect(decrypted.text).toBe(message);
          expect(verified).toBeTruthy();
          await api.destroy({tag: user, recursiveMembers: true});
        }, 10e3);
        it('supports rotation.', async function () {
          let aliceTag = await api.create(tags.device),
              cfoTag = await api.create(aliceTag),
              alicePO = await api.sign("some purchase order", {team: cfoTag, member: aliceTag}), // On Alice's computer
              cfoEyesOnly = await api.encrypt("the other set of books", cfoTag);
          expect(await api.verify(alicePO)).toBeTruthy();
          expect(await api.verify(alicePO, {team: cfoTag, member: false})).toBeTruthy();
          expect(await api.decrypt(cfoEyesOnly)).toBeTruthy(); // On Alice's computer

          // Now Alice is replace with Bob, and Carol added for the transition
          let bobTag = await api.create(tags.device);
          let carolTag = await api.create(tags.device);
          await api.changeMembership({tag: cfoTag, remove: [aliceTag], add: [bobTag, carolTag]});
          await api.destroy(aliceTag);

          expect(await api.sign("bogus PO", {team: cfoTag, member: aliceTag}).catch(() => undefined)).toBeUndefined(); // Alice can no longer sign.
          let bobPO = await api.sign("new PO", {team: cfoTag, member: bobTag}); // On Bob's computer
          let carolPO = await api.sign("new PO", {team: cfoTag, member: carolTag});
          expect(await api.verify(bobPO)).toBeTruthy();
          expect(await api.verify(carolPO)).toBeTruthy();
          expect(await api.verify(alicePO).catch(() => undefined)).toBeUndefined(); // Alice is no longer a member of cfoTag.
          expect(await api.verify(alicePO, {team: cfoTag, member: false})).toBeTruthy(); // Destorying Alice's tag doesn't prevent shallow verify
          expect(await api.decrypt(cfoEyesOnly)).toBeTruthy(); // On Bob's or Carol's computer

          // Now suppose we want to rotate the cfoTag:
          let cfoTag2 = await api.create(bobTag); // Not Carol.
          await api.destroy(cfoTag);

          expect(await api.sign("bogus PO", {team: cfoTag, member: bobTag}).catch(() => undefined)).toBeUndefined(); // Fails for discontinued team.
          expect(await api.sign("new new PO", {team: cfoTag2, member: bobTag})).toBeTruthy();
          expect(await api.verify(alicePO, {team: cfoTag, member: false})).toBeTruthy();
          // However, some things to be aware of.
          expect(await api.verify(bobPO)).toBeTruthy(); // works, but only because this looks like the initial check
          expect(await api.verify(carolPO)).toBeTruthy(); // same, and confusing because Carol is not on the new team.
          expect(await api.decrypt(cfoEyesOnly).catch(() => undefined)).toBeUndefined(); // FAILS! Bob can't sort through the mess that Alice made.
        }, 15e3);
        // TODO:
        // - Show that a member cannot sign or decrypt for a team that they have been removed from.
        // - Show that multiple simultaneous apps can use the same tags if they use Security from the same origin and have compatible getUserDeviceSecret.
        // - Show that multiple simultaneous apps cannot use the same tags if they use Security from the same origin and have incompatible getUserDeviceSecret.
      });
    });
  });
});
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2VjdXJpdHlTcGVjLWJ1bmRsZS5tanMiLCJzb3VyY2VzIjpbIi4uL3NwZWMvc3VwcG9ydC9zdG9yYWdlLm1qcyIsIi4uL25vZGVfbW9kdWxlcy9Aa2kxcjB5L2pzb25ycGMvaW5kZXgubWpzIiwiLi4vbGliL29yaWdpbi1icm93c2VyLm1qcyIsIi4uL2xpYi9ta2Rpci1icm93c2VyLm1qcyIsIi4uL2xpYi90YWdQYXRoLm1qcyIsIi4uL2xpYi9zdG9yYWdlLm1qcyIsIi4uL2xpYi9zZWNyZXQubWpzIiwiLi4vaW5kZXgubWpzIiwiLi4vc3BlYy9zdXBwb3J0L21lc3NhZ2VUZXh0Lm1qcyIsIi4uL3NwZWMva3J5cHRvVGVzdHMubWpzIiwiLi4vc3BlYy9tdWx0aUtyeXB0b1Rlc3RzLm1qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3dlYmNyeXB0by5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2RpZ2VzdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvYnVmZmVyX3V0aWxzLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvYmFzZTY0dXJsLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3V0aWwvZXJyb3JzLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvcmFuZG9tLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9pdi5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvY2hlY2tfaXZfbGVuZ3RoLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvY2hlY2tfY2VrX2xlbmd0aC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3RpbWluZ19zYWZlX2VxdWFsLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9jcnlwdG9fa2V5LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2lzX2tleV9saWtlLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvZGVjcnlwdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvaXNfZGlzam9pbnQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2lzX29iamVjdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2JvZ3VzLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvYWVza3cuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9lY2RoZXMuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2NoZWNrX3Aycy5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3BiZXMya3cuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9zdWJ0bGVfcnNhZXMuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9jaGVja19rZXlfbGVuZ3RoLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvcnNhZXMuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2Nlay5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2p3a190b19rZXkuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIva2V5L2ltcG9ydC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvY2hlY2tfa2V5X3R5cGUuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9lbmNyeXB0LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9hZXNnY21rdy5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvZGVjcnlwdF9rZXlfbWFuYWdlbWVudC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvdmFsaWRhdGVfY3JpdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvdmFsaWRhdGVfYWxnb3JpdGhtcy5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd2UvZmxhdHRlbmVkL2RlY3J5cHQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandlL2NvbXBhY3QvZGVjcnlwdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd2UvZ2VuZXJhbC9kZWNyeXB0LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUva2V5X3RvX2p3ay5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9rZXkvZXhwb3J0LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9lbmNyeXB0X2tleV9tYW5hZ2VtZW50LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3ZS9mbGF0dGVuZWQvZW5jcnlwdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd2UvZ2VuZXJhbC9lbmNyeXB0LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvc3VidGxlX2RzYS5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2dldF9zaWduX3ZlcmlmeV9rZXkuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS92ZXJpZnkuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandzL2ZsYXR0ZW5lZC92ZXJpZnkuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandzL2NvbXBhY3QvdmVyaWZ5LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9nZW5lcmFsL3ZlcmlmeS5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd2UvY29tcGFjdC9lbmNyeXB0LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvc2lnbi5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd3MvZmxhdHRlbmVkL3NpZ24uanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandzL2NvbXBhY3Qvc2lnbi5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd3MvZ2VuZXJhbC9zaWduLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3V0aWwvYmFzZTY0dXJsLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3V0aWwvZGVjb2RlX3Byb3RlY3RlZF9oZWFkZXIuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9nZW5lcmF0ZS5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9rZXkvZ2VuZXJhdGVfa2V5X3BhaXIuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIva2V5L2dlbmVyYXRlX3NlY3JldC5qcyIsIi4uL2xpYi9hbGdvcml0aG1zLm1qcyIsIi4uL2xpYi9yYXctYnJvd3Nlci5tanMiLCIuLi9saWIva3J5cHRvLm1qcyIsIi4uL2xpYi9tdWx0aUtyeXB0by5tanMiLCIuLi9saWIvc3RvcmUtaW5kZXhlZC5tanMiLCIuLi9saWIva2V5U2V0Lm1qcyIsIi4uL2xpYi9wYWNrYWdlLWxvYWRlci5tanMiLCIuLi9saWIvYXBpLm1qcyIsIi4uL3NwZWMvc2VjdXJpdHlTcGVjLm1qcyJdLCJzb3VyY2VzQ29udGVudCI6WyJjb25zdCBTdG9yYWdlID0ge1xuICBvcmlnaW46IG5ldyBVUkwoaW1wb3J0Lm1ldGEudXJsKS5vcmlnaW4sIC8vIGRpYWdub3N0aWMsIHJlcG9ydGVkIGluIHJlYWR5XG4gIGFzeW5jIHN0b3JlKHJlc291cmNlVGFnLCBvd25lclRhZywgc2lnbmF0dXJlKSB7XG4gICAgbGV0IHZlcmlmaWVkID0gYXdhaXQgdGhpcy5TZWN1cml0eS52ZXJpZnkoc2lnbmF0dXJlLCB7dGVhbTogb3duZXJUYWcsIG5vdEJlZm9yZTogJ3RlYW0nfSk7XG4gICAgaWYgKCF2ZXJpZmllZCkgdGhyb3cgbmV3IEVycm9yKGBTaWduYXR1cmUgJHtzaWduYXR1cmV9IGRvZXMgbm90IG1hdGNoIG93bmVyIG9mICR7b3duZXJUYWd9LmApO1xuICAgIGlmICh2ZXJpZmllZC5wYXlsb2FkLmxlbmd0aCkge1xuICAgICAgdGhpc1tyZXNvdXJjZVRhZ11bb3duZXJUYWddID0gc2lnbmF0dXJlO1xuICAgIH0gZWxzZSB7XG4gICAgICBkZWxldGUgdGhpc1tyZXNvdXJjZVRhZ11bb3duZXJUYWddO1xuICAgIH1cbiAgICByZXR1cm4gbnVsbDsgLy8gTXVzdCBub3QgcmV0dXJuIHVuZGVmaW5lZCBmb3IganNvbnJwYy5cbiAgfSxcbiAgYXN5bmMgcmV0cmlldmUocmVzb3VyY2VUYWcsIG93bmVyVGFnKSB7XG4gICAgLy8gV2UgZG8gbm90IHZlcmlmeSBhbmQgZ2V0IHRoZSBvcmlnaW5hbCBkYXRhIG91dCBoZXJlLCBiZWNhdXNlIHRoZSBjYWxsZXIgaGFzXG4gICAgLy8gdGhlIHJpZ2h0IHRvIGRvIHNvIHdpdGhvdXQgdHJ1c3RpbmcgdXMuXG4gICAgcmV0dXJuIHRoaXNbcmVzb3VyY2VUYWddW293bmVyVGFnXTtcbiAgfSxcbiAgVGVhbToge30sXG4gIEtleVJlY292ZXJ5OiB7fSxcbiAgRW5jcnlwdGlvbktleToge31cbn07XG5leHBvcnQgZGVmYXVsdCBTdG9yYWdlO1xuIiwiXG5mdW5jdGlvbiB0cmFuc2ZlcnJhYmxlRXJyb3IoZXJyb3IpIHsgLy8gQW4gZXJyb3Igb2JqZWN0IHRoYXQgd2UgcmVjZWl2ZSBvbiBvdXIgc2lkZSBtaWdodCBub3QgYmUgdHJhbnNmZXJyYWJsZSB0byB0aGUgb3RoZXIuXG4gIGxldCB7bmFtZSwgbWVzc2FnZSwgY29kZSwgZGF0YX0gPSBlcnJvcjtcbiAgcmV0dXJuIHtuYW1lLCBtZXNzYWdlLCBjb2RlLCBkYXRhfTtcbn1cblxuLy8gU2V0IHVwIGJpZGlyZWN0aW9uYWwgY29tbXVuY2F0aW9ucyB3aXRoIHRhcmdldCwgcmV0dXJuaW5nIGEgZnVuY3Rpb24gKG1ldGhvZE5hbWUsIC4uLnBhcmFtcykgdGhhdCB3aWxsIHNlbmQgdG8gdGFyZ2V0LlxuZnVuY3Rpb24gZGlzcGF0Y2goe3RhcmdldCA9IHNlbGYsICAgICAgICAvLyBUaGUgd2luZG93LCB3b3JrZXIsIG9yIG90aGVyIG9iamVjdCB0byB3aGljaCB3ZSB3aWxsIHBvc3RNZXNzYWdlLlxuXHRcdCAgIHJlY2VpdmVyID0gdGFyZ2V0LCAgICAvLyBUaGUgd2luZG93LCB3b3JrZXIsIG9yIG90aGVyIG9iamVjdCBvZiB3aGljaCBXRSB3aWxsIGhhbmRsZSAnbWVzc2FnZScgZXZlbnRzIGZyb20gdGFyZ2V0LlxuXHRcdCAgIG5hbWVzcGFjZSA9IHJlY2VpdmVyLCAvLyBBbiBvYmplY3QgdGhhdCBkZWZpbmVzIGFueSBtZXRob2RzIHRoYXQgbWF5IGJlIHJlcXVlc3RlZCBieSB0YXJnZXQuXG5cblx0XHQgICBvcmlnaW4gPSAoKHRhcmdldCAhPT0gcmVjZWl2ZXIpICYmIHRhcmdldC5sb2NhdGlvbi5vcmlnaW4pLFxuXG5cdFx0ICAgZGlzcGF0Y2hlckxhYmVsID0gbmFtZXNwYWNlLm5hbWUgfHwgcmVjZWl2ZXIubmFtZSB8fCByZWNlaXZlci5sb2NhdGlvbj8uaHJlZiB8fCByZWNlaXZlcixcblx0XHQgICB0YXJnZXRMYWJlbCA9IHRhcmdldC5uYW1lIHx8IG9yaWdpbiB8fCB0YXJnZXQubG9jYXRpb24/LmhyZWYgfHwgdGFyZ2V0LFxuXG5cdFx0ICAgbG9nID0gbnVsbCxcblx0XHQgICBpbmZvOmxvZ2luZm8gPSBjb25zb2xlLmluZm8uYmluZChjb25zb2xlKSxcblx0XHQgICB3YXJuOmxvZ3dhcm4gPSBjb25zb2xlLndhcm4uYmluZChjb25zb2xlKSxcblx0XHQgICBlcnJvcjpsb2dlcnJvciA9IGNvbnNvbGUuZXJyb3IuYmluZChjb25zb2xlKVxuXHRcdCAgfSkge1xuICBjb25zdCByZXF1ZXN0cyA9IHt9LFxuICAgICAgICBqc29ucnBjID0gJzIuMCcsXG4gICAgICAgIGNhcHR1cmVkUG9zdCA9IHRhcmdldC5wb3N0TWVzc2FnZS5iaW5kKHRhcmdldCksIC8vIEluIGNhc2UgKG1hbGljaW91cykgY29kZSBsYXRlciBjaGFuZ2VzIGl0LlxuICAgICAgICAvLyB3aW5kb3cucG9zdE1lc3NhZ2UgYW5kIGZyaWVuZHMgdGFrZXMgYSB0YXJnZXRPcmlnaW4gdGhhdCB3ZSBzdXBwbHkuXG4gICAgICAgIC8vIEJ1dCB3b3JrZXIucG9zdE1lc3NhZ2UgZ2l2ZXMgZXJyb3IgcmF0aGVyIHRoYW4gaWdub3JpbmcgdGhlIGV4dHJhIGFyZy4gU28gc2V0IHRoZSByaWdodCBmb3JtIGF0IGluaXRpYWxpemF0aW9uLlxuICAgICAgICBwb3N0ID0gb3JpZ2luID8gbWVzc2FnZSA9PiBjYXB0dXJlZFBvc3QobWVzc2FnZSwgb3JpZ2luKSA6IGNhcHR1cmVkUG9zdCxcbiAgICAgICAgbnVsbExvZyA9ICgpID0+IHt9O1xuICBsZXQgbWVzc2FnZUlkID0gMDsgLy8gcHJlLWluY3JlbWVudGVkIGlkIHN0YXJ0cyBhdCAxLlxuXG4gIGZ1bmN0aW9uIHJlcXVlc3QobWV0aG9kLCAuLi5wYXJhbXMpIHsgLy8gUHJvbWlzZSB0aGUgcmVzdWx0IG9mIG1ldGhvZCguLi5wYXJhbXMpIGluIHRhcmdldC5cbiAgICAvLyBXZSBkbyBhIHRhcmdldC5wb3N0TWVzc2FnZSBvZiBhIGpzb25ycGMgcmVxdWVzdCwgYW5kIHJlc29sdmUgdGhlIHByb21pc2Ugd2l0aCB0aGUgcmVzcG9uc2UsIG1hdGNoZWQgYnkgaWQuXG4gICAgLy8gSWYgdGhlIHRhcmdldCBoYXBwZW5zIHRvIGJlIHNldCB1cCBieSBhIGRpc3BhdGNoIGxpa2UgdGhpcyBvbmUsIGl0IHdpbGwgcmVzcG9uZCB3aXRoIHdoYXRldmVyIGl0J3NcbiAgICAvLyBuYW1lc3BhY2VbbWV0aG9kXSguLi5wYXJhbXMpIHJlc29sdmVzIHRvLiBXZSBvbmx5IHNlbmQganNvbnJwYyByZXF1ZXN0cyAod2l0aCBhbiBpZCksIG5vdCBub3RpZmljYXRpb25zLFxuICAgIC8vIGJlY2F1c2UgdGhlcmUgaXMgbm8gd2F5IHRvIGdldCBlcnJvcnMgYmFjayBmcm9tIGEganNvbnJwYyBub3RpZmljYXRpb24uXG4gICAgbGV0IGlkID0gKyttZXNzYWdlSWQsXG5cdHJlcXVlc3QgPSByZXF1ZXN0c1tpZF0gPSB7fTtcbiAgICAvLyBJdCB3b3VsZCBiZSBuaWNlIHRvIG5vdCBsZWFrIHJlcXVlc3Qgb2JqZWN0cyBpZiB0aGV5IGFyZW4ndCBhbnN3ZXJlZC5cbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgbG9nPy4oZGlzcGF0Y2hlckxhYmVsLCAncmVxdWVzdCcsIGlkLCBtZXRob2QsIHBhcmFtcywgJ3RvJywgdGFyZ2V0TGFiZWwpO1xuICAgICAgT2JqZWN0LmFzc2lnbihyZXF1ZXN0LCB7cmVzb2x2ZSwgcmVqZWN0fSk7XG4gICAgICBwb3N0KHtpZCwgbWV0aG9kLCBwYXJhbXMsIGpzb25ycGN9KTtcbiAgICB9KTtcbiAgfVxuXG4gIGFzeW5jIGZ1bmN0aW9uIHJlc3BvbmQoZXZlbnQpIHsgLy8gSGFuZGxlICdtZXNzYWdlJyBldmVudHMgdGhhdCB3ZSByZWNlaXZlIGZyb20gdGFyZ2V0LlxuICAgIGxvZz8uKGRpc3BhdGNoZXJMYWJlbCwgJ2dvdCBtZXNzYWdlJywgZXZlbnQuZGF0YSwgJ2Zyb20nLCB0YXJnZXRMYWJlbCwgZXZlbnQub3JpZ2luKTtcbiAgICBsZXQge2lkLCBtZXRob2QsIHBhcmFtcyA9IFtdLCByZXN1bHQsIGVycm9yLCBqc29ucnBjOnZlcnNpb259ID0gZXZlbnQuZGF0YSB8fCB7fTtcblxuICAgIC8vIE5vaXNpbHkgaWdub3JlIG1lc3NhZ2VzIHRoYXQgYXJlIG5vdCBmcm9tIHRoZSBleHBlY3QgdGFyZ2V0IG9yIG9yaWdpbiwgb3Igd2hpY2ggYXJlIG5vdCBqc29ucnBjLlxuICAgIGlmIChldmVudC5zb3VyY2UgJiYgKGV2ZW50LnNvdXJjZSAhPT0gdGFyZ2V0KSkgcmV0dXJuIGxvZ2Vycm9yPy4oZGlzcGF0Y2hlckxhYmVsLCAndG8nLCB0YXJnZXRMYWJlbCwgICdnb3QgbWVzc2FnZSBmcm9tJywgZXZlbnQuc291cmNlKTtcbiAgICBpZiAob3JpZ2luICYmIChvcmlnaW4gIT09IGV2ZW50Lm9yaWdpbikpIHJldHVybiBsb2dlcnJvcj8uKGRpc3BhdGNoZXJMYWJlbCwgb3JpZ2luLCAnbWlzbWF0Y2hlZCBvcmlnaW4nLCB0YXJnZXRMYWJlbCwgZXZlbnQub3JpZ2luKTtcbiAgICBpZiAodmVyc2lvbiAhPT0ganNvbnJwYykgcmV0dXJuIGxvZ3dhcm4/LihgJHtkaXNwYXRjaGVyTGFiZWx9IGlnbm9yaW5nIG5vbi1qc29ucnBjIG1lc3NhZ2UgJHtKU09OLnN0cmluZ2lmeShldmVudC5kYXRhKX0uYCk7XG5cbiAgICBpZiAobWV0aG9kKSB7IC8vIEluY29taW5nIHJlcXVlc3Qgb3Igbm90aWZpY2F0aW9uIGZyb20gdGFyZ2V0LlxuICAgICAgbGV0IGVycm9yID0gbnVsbCwgcmVzdWx0LFxuICAgICAgICAgIC8vIGpzb25ycGMgcmVxdWVzdC9ub3RpZmljYXRpb24gY2FuIGhhdmUgcG9zaXRpb25hbCBhcmdzIChhcnJheSkgb3IgbmFtZWQgYXJncyAoYSBQT0pPKS5cblx0ICBhcmdzID0gQXJyYXkuaXNBcnJheShwYXJhbXMpID8gcGFyYW1zIDogW3BhcmFtc107IC8vIEFjY2VwdCBlaXRoZXIuXG4gICAgICB0cnkgeyAvLyBtZXRob2QgcmVzdWx0IG1pZ2h0IG5vdCBiZSBhIHByb21pc2UsIHNvIHdlIGNhbid0IHJlbHkgb24gLmNhdGNoKCkuXG4gICAgICAgIHJlc3VsdCA9IGF3YWl0IG5hbWVzcGFjZVttZXRob2RdKC4uLmFyZ3MpOyAvLyBDYWxsIHRoZSBtZXRob2QuXG4gICAgICB9IGNhdGNoIChlKSB7IC8vIFNlbmQgYmFjayBhIGNsZWFuIHtuYW1lLCBtZXNzYWdlfSBvYmplY3QuXG4gICAgICAgIGVycm9yID0gdHJhbnNmZXJyYWJsZUVycm9yKGUpO1xuICAgICAgICBpZiAoIW5hbWVzcGFjZVttZXRob2RdICYmICFlcnJvci5tZXNzYWdlLmluY2x1ZGVzKG1ldGhvZCkpIHtcblx0ICBlcnJvci5tZXNzYWdlID0gYCR7bWV0aG9kfSBpcyBub3QgZGVmaW5lZC5gOyAvLyBCZSBtb3JlIGhlbHBmdWwgdGhhbiBzb21lIGJyb3dzZXJzLlxuICAgICAgICAgIGVycm9yLmNvZGUgPSAtMzI2MDE7IC8vIERlZmluZWQgYnkganNvbi1ycGMgc3BlYy5cbiAgICAgICAgfSBlbHNlIGlmICghZXJyb3IubWVzc2FnZSkgLy8gSXQgaGFwcGVucy4gRS5nLiwgb3BlcmF0aW9uYWwgZXJyb3JzIGZyb20gY3J5cHRvLlxuXHQgIGVycm9yLm1lc3NhZ2UgPSBgJHtlcnJvci5uYW1lIHx8IGVycm9yLnRvU3RyaW5nKCl9IGluICR7bWV0aG9kfS5gO1xuICAgICAgfVxuICAgICAgaWYgKGlkID09PSB1bmRlZmluZWQpIHJldHVybjsgLy8gRG9uJ3QgcmVzcG9uZCB0byBhICdub3RpZmljYXRpb24nLiBudWxsIGlkIGlzIHN0aWxsIHNlbnQgYmFjay5cbiAgICAgIGxldCByZXNwb25zZSA9IGVycm9yID8ge2lkLCBlcnJvciwganNvbnJwY30gOiB7aWQsIHJlc3VsdCwganNvbnJwY307XG4gICAgICBsb2c/LihkaXNwYXRjaGVyTGFiZWwsICdhbnN3ZXJpbmcnLCBpZCwgZXJyb3IgfHwgcmVzdWx0LCAndG8nLCB0YXJnZXRMYWJlbCk7XG4gICAgICByZXR1cm4gcG9zdChyZXNwb25zZSk7XG4gICAgfVxuXG4gICAgLy8gT3RoZXJ3aXNlLCBpdCBpcyBhIHJlc3BvbnNlIGZyb20gdGFyZ2V0IHRvIG91ciBlYXJsaWVyIG91dGdvaW5nIHJlcXVlc3QuXG4gICAgbGV0IHJlcXVlc3QgPSByZXF1ZXN0c1tpZF07ICAvLyBSZXNvbHZlIG9yIHJlamVjdCB0aGUgcHJvbWlzZSB0aGF0IGFuIGFuIGVhcmxpZXIgcmVxdWVzdCBjcmVhdGVkLlxuICAgIGRlbGV0ZSByZXF1ZXN0c1tpZF07XG4gICAgaWYgKCFyZXF1ZXN0KSByZXR1cm4gbG9nd2Fybj8uKGAke2Rpc3BhdGNoZXJMYWJlbH0gaWdub3JpbmcgcmVzcG9uc2UgJHtldmVudC5kYXRhfS5gKTtcbiAgICBpZiAoZXJyb3IpIHJlcXVlc3QucmVqZWN0KGVycm9yKTtcbiAgICBlbHNlIHJlcXVlc3QucmVzb2x2ZShyZXN1bHQpO1xuICB9XG5cbiAgLy8gTm93IHNldCB1cCB0aGUgaGFuZGxlciBhbmQgcmV0dXJuIHRoZSBmdW5jdGlvbiBmb3IgdGhlIGNhbGxlciB0byB1c2UgdG8gbWFrZSByZXF1ZXN0cy5cbiAgcmVjZWl2ZXIuYWRkRXZlbnRMaXN0ZW5lcihcIm1lc3NhZ2VcIiwgcmVzcG9uZCk7XG4gIGxvZ2luZm8/LihgJHtkaXNwYXRjaGVyTGFiZWx9IHdpbGwgZGlzcGF0Y2ggdG8gJHt0YXJnZXRMYWJlbH1gKTtcbiAgcmV0dXJuIHJlcXVlc3Q7XG59XG5cbmV4cG9ydCBkZWZhdWx0IGRpc3BhdGNoO1xuIiwiY29uc3Qgb3JpZ2luID0gbmV3IFVSTChpbXBvcnQubWV0YS51cmwpLm9yaWdpbjtcbmV4cG9ydCBkZWZhdWx0IG9yaWdpbjtcbiIsImV4cG9ydCBjb25zdCBta2RpciA9IHVuZGVmaW5lZDtcbiIsImNvbnN0IHRhZ0JyZWFrdXAgPSAvKFxcU3s1MH0pKFxcU3syfSkoXFxTezJ9KShcXFMrKS87XG5leHBvcnQgZnVuY3Rpb24gdGFnUGF0aChjb2xsZWN0aW9uTmFtZSwgdGFnLCBleHRlbnNpb24gPSAnanNvbicpIHsgLy8gUGF0aG5hbWUgdG8gdGFnIHJlc291cmNlLlxuICAvLyBVc2VkIGluIFN0b3JhZ2UgVVJJIGFuZCBmaWxlIHN5c3RlbSBzdG9yZXMuIEJvdHRsZW5lY2tlZCBoZXJlIHRvIHByb3ZpZGUgY29uc2lzdGVudCBhbHRlcm5hdGUgaW1wbGVtZW50YXRpb25zLlxuICAvLyBQYXRoIGlzIC5qc29uIHNvIHRoYXQgc3RhdGljLWZpbGUgd2ViIHNlcnZlcnMgd2lsbCBzdXBwbHkgYSBqc29uIG1pbWUgdHlwZS5cbiAgLy8gUGF0aCBpcyBicm9rZW4gdXAgc28gdGhhdCBkaXJlY3RvcnkgcmVhZHMgZG9uJ3QgZ2V0IGJvZ2dlZCBkb3duIGZyb20gaGF2aW5nIHRvbyBtdWNoIGluIGEgZGlyZWN0b3J5LlxuICAvL1xuICAvLyBOT1RFOiBjaGFuZ2VzIGhlcmUgbXVzdCBiZSBtYXRjaGVkIGJ5IHRoZSBQVVQgcm91dGUgc3BlY2lmaWVkIGluIHNpZ25lZC1jbG91ZC1zZXJ2ZXIvc3RvcmFnZS5tanMgYW5kIHRhZ05hbWUubWpzXG4gIGlmICghdGFnKSByZXR1cm4gY29sbGVjdGlvbk5hbWU7XG4gIGxldCBtYXRjaCA9IHRhZy5tYXRjaCh0YWdCcmVha3VwKTtcbiAgaWYgKCFtYXRjaCkgcmV0dXJuIGAke2NvbGxlY3Rpb25OYW1lfS8ke3RhZ31gO1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbm8tdW51c2VkLXZhcnNcbiAgbGV0IFtfLCBhLCBiLCBjLCByZXN0XSA9IG1hdGNoO1xuICByZXR1cm4gYCR7Y29sbGVjdGlvbk5hbWV9LyR7YX0vJHtifS8ke2N9LyR7cmVzdH0uJHtleHRlbnNpb259YDtcbn1cbiIsImltcG9ydCBvcmlnaW4gZnJvbSAnI29yaWdpbic7IC8vIFdoZW4gcnVubmluZyBpbiBhIGJyb3dzZXIsIGxvY2F0aW9uLm9yaWdpbiB3aWxsIGJlIGRlZmluZWQuIEhlcmUgd2UgYWxsb3cgZm9yIE5vZGVKUy5cbmltcG9ydCB7bWtkaXJ9IGZyb20gJyNta2Rpcic7XG5pbXBvcnQge3RhZ1BhdGh9IGZyb20gJy4vdGFnUGF0aC5tanMnO1xuXG5hc3luYyBmdW5jdGlvbiByZXNwb25zZUhhbmRsZXIocmVzcG9uc2UpIHtcbiAgLy8gUmVqZWN0IGlmIHNlcnZlciBkb2VzLCBlbHNlIHJlc3BvbnNlLnRleHQoKS5cbiAgaWYgKHJlc3BvbnNlLnN0YXR1cyA9PT0gNDA0KSByZXR1cm4gJyc7XG4gIGlmICghcmVzcG9uc2Uub2spIHJldHVybiBQcm9taXNlLnJlamVjdChyZXNwb25zZS5zdGF0dXNUZXh0KTtcbiAgbGV0IHRleHQgPSBhd2FpdCByZXNwb25zZS50ZXh0KCk7XG4gIGlmICghdGV4dCkgcmV0dXJuIHRleHQ7IC8vIFJlc3VsdCBvZiBzdG9yZSBjYW4gYmUgZW1wdHkuXG4gIHJldHVybiBKU09OLnBhcnNlKHRleHQpO1xufVxuXG5jb25zdCBTdG9yYWdlID0ge1xuICBnZXQgb3JpZ2luKCkgeyByZXR1cm4gb3JpZ2luOyB9LFxuICB0YWdQYXRoLFxuICBta2RpcixcbiAgdXJpKGNvbGxlY3Rpb25OYW1lLCB0YWcpIHtcbiAgICAvLyBQYXRobmFtZSBleHBlY3RlZCBieSBvdXIgc2lnbmVkLWNsb3VkLXNlcnZlci5cbiAgICByZXR1cm4gYCR7b3JpZ2lufS9kYi8ke3RoaXMudGFnUGF0aChjb2xsZWN0aW9uTmFtZSwgdGFnKX1gO1xuICB9LFxuICBzdG9yZShjb2xsZWN0aW9uTmFtZSwgdGFnLCBzaWduYXR1cmUsIG9wdGlvbnMgPSB7fSkge1xuICAgIC8vIFN0b3JlIHRoZSBzaWduZWQgY29udGVudCBvbiB0aGUgc2lnbmVkLWNsb3VkLXNlcnZlciwgcmVqZWN0aW5nIGlmXG4gICAgLy8gdGhlIHNlcnZlciBpcyB1bmFibGUgdG8gdmVyaWZ5IHRoZSBzaWduYXR1cmUgZm9sbG93aW5nIHRoZSBydWxlcyBvZlxuICAgIC8vIGh0dHBzOi8va2lscm95LWNvZGUuZ2l0aHViLmlvL2Rpc3RyaWJ1dGVkLXNlY3VyaXR5LyNzdG9yaW5nLWtleXMtdXNpbmctdGhlLWNsb3VkLXN0b3JhZ2UtYXBpXG4gICAgcmV0dXJuIGZldGNoKHRoaXMudXJpKGNvbGxlY3Rpb25OYW1lLCB0YWcpLCB7XG4gICAgICBtZXRob2Q6ICdQVVQnLFxuICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoc2lnbmF0dXJlKSxcbiAgICAgIGhlYWRlcnM6IHsnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nLCAuLi4ob3B0aW9ucy5oZWFkZXJzIHx8IHt9KX1cbiAgICB9KS50aGVuKHJlc3BvbnNlSGFuZGxlcik7XG4gIH0sXG4gIHJldHJpZXZlKGNvbGxlY3Rpb25OYW1lLCB0YWcsIG9wdGlvbnMgPSB7fSkge1xuICAgIC8vIFdlIGRvIG5vdCB2ZXJpZnkgYW5kIGdldCB0aGUgb3JpZ2luYWwgZGF0YSBvdXQgaGVyZSwgYmVjYXVzZSB0aGUgY2FsbGVyIGhhc1xuICAgIC8vIHRoZSByaWdodCB0byBkbyBzbyB3aXRob3V0IHRydXN0aW5nIHVzLlxuICAgIHJldHVybiBmZXRjaCh0aGlzLnVyaShjb2xsZWN0aW9uTmFtZSwgdGFnKSwge1xuICAgICAgY2FjaGU6ICdkZWZhdWx0JyxcbiAgICAgIGhlYWRlcnM6IHsnQWNjZXB0JzogJ2FwcGxpY2F0aW9uL2pzb24nLCAuLi4ob3B0aW9ucy5oZWFkZXJzIHx8IHt9KX1cbiAgICB9KS50aGVuKHJlc3BvbnNlSGFuZGxlcik7XG4gIH1cbn07XG5leHBvcnQgZGVmYXVsdCBTdG9yYWdlO1xuIiwidmFyIHByb21wdGVyID0gcHJvbXB0U3RyaW5nID0+IHByb21wdFN0cmluZztcbmlmICh0eXBlb2Yod2luZG93KSAhPT0gJ3VuZGVmaW5lZCcpIHtcbiAgcHJvbXB0ZXIgPSB3aW5kb3cucHJvbXB0O1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZ2V0VXNlckRldmljZVNlY3JldCh0YWcsIHByb21wdFN0cmluZykge1xuICByZXR1cm4gcHJvbXB0U3RyaW5nID8gKHRhZyArIHByb21wdGVyKHByb21wdFN0cmluZykpIDogdGFnO1xufVxuIiwiaW1wb3J0IGRpc3BhdGNoIGZyb20gJ0BraTFyMHkvanNvbnJwYyc7XG5pbXBvcnQgU3RvcmFnZSBmcm9tICcuL2xpYi9zdG9yYWdlLm1qcyc7XG5pbXBvcnQge2dldFVzZXJEZXZpY2VTZWNyZXR9IGZyb20gJy4vbGliL3NlY3JldC5tanMnO1xuXG5jb25zdCBlbnRyeVVybCA9IG5ldyBVUkwoaW1wb3J0Lm1ldGEudXJsKSxcbiAgICAgIHZhdWx0VXJsID0gbmV3IFVSTCgndmF1bHQuaHRtbCcsIGVudHJ5VXJsKSxcbiAgICAgIHZhdWx0TmFtZSA9ICd2YXVsdCEnICsgZW50cnlVcmwuaHJlZiAvLyBIZWxwcyBkZWJ1Z2dpbmcuXG5cbi8vIE91dGVyIGxheWVyIG9mIHRoZSB2YXVsdCBpcyBhbiBpZnJhbWUgdGhhdCBlc3RhYmxpc2hlcyBhIGJyb3dzaW5nIGNvbnRleHQgc2VwYXJhdGUgZnJvbSB0aGUgYXBwIHRoYXQgaW1wb3J0cyB1cy5cbmNvbnN0IGlmcmFtZSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2lmcmFtZScpLFxuICAgICAgY2hhbm5lbCA9IG5ldyBNZXNzYWdlQ2hhbm5lbCgpLFxuICAgICAgcmVzb3VyY2VzRm9ySWZyYW1lID0gT2JqZWN0LmFzc2lnbih7IC8vIFdoYXQgdGhlIHZhdWx0IGNhbiBwb3N0TWVzc2FnZSB0byB1cy5cbiAgICAgICAgbG9nKC4uLmFyZ3MpIHsgY29uc29sZS5sb2coLi4uYXJncyk7IH0sXG4gICAgICAgIGdldFVzZXJEZXZpY2VTZWNyZXRcbiAgICAgIH0sIFN0b3JhZ2UpLFxuICAgICAgLy8gU2V0IHVwIGEgcHJvbWlzZSB0aGF0IGRvZXNuJ3QgcmVzb2x2ZSB1bnRpbCB0aGUgdmF1bHQgcG9zdHMgdG8gdXMgdGhhdCBpdCBpcyByZWFkeSAod2hpY2ggaW4gdHVybiwgd29uJ3QgaGFwcGVuIHVudGlsIGl0J3Mgd29ya2VyIGlzIHJlYWR5KS5cbiAgICAgIHJlYWR5ID0gbmV3IFByb21pc2UocmVzb2x2ZSA9PiB7XG4gICAgICAgIHJlc291cmNlc0ZvcklmcmFtZS5yZWFkeSA9IHJlc29sdmUsXG4gICAgICAgIGlmcmFtZS5zdHlsZS5kaXNwbGF5ID0gJ25vbmUnO1xuICAgICAgICBkb2N1bWVudC5ib2R5LmFwcGVuZChpZnJhbWUpOyAvLyBCZWZvcmUgcmVmZXJlbmNpbmcgaXRzIGNvbnRlbnRXaW5kb3cuXG4gICAgICAgIGlmcmFtZS5zZXRBdHRyaWJ1dGUoJ3NyYycsIHZhdWx0VXJsKTtcbiAgICAgICAgaWZyYW1lLmNvbnRlbnRXaW5kb3cubmFtZSA9IHZhdWx0TmFtZTtcbiAgICAgICAgLy8gSGFuZCBhIHByaXZhdGUgY29tbXVuaWNhdGlvbiBwb3J0IHRvIHRoZSBmcmFtZS5cbiAgICAgICAgY2hhbm5lbC5wb3J0MS5zdGFydCgpO1xuICAgICAgICBpZnJhbWUub25sb2FkID0gKCkgPT4gaWZyYW1lLmNvbnRlbnRXaW5kb3cucG9zdE1lc3NhZ2UodmF1bHROYW1lLCB2YXVsdFVybC5vcmlnaW4sIFtjaGFubmVsLnBvcnQyXSk7XG4gICAgICB9KSxcbiAgICAgIHBvc3RJZnJhbWUgPSBkaXNwYXRjaCh7ICAvLyBwb3N0TWVzc2FnZSB0byB0aGUgdmF1bHQsIHByb21pc2luZyB0aGUgcmVzcG9uc2UuXG4gICAgICAgIGRpc3BhdGNoZXJMYWJlbDogJ2VudHJ5IScgKyBlbnRyeVVybC5ocmVmLFxuICAgICAgICBuYW1lc3BhY2U6IHJlc291cmNlc0ZvcklmcmFtZSxcbiAgICAgICAgdGFyZ2V0OiBjaGFubmVsLnBvcnQxLFxuICAgICAgICB0YXJnZXRMYWJlbDogdmF1bHROYW1lXG4gICAgICB9KSxcblxuICAgICAgYXBpID0geyAvLyBFeHBvcnRlZCBmb3IgdXNlIGJ5IHRoZSBhcHBsaWNhdGlvbi5cbiAgICAgICAgc2lnbihtZXNzYWdlLCAuLi50YWdzKSB7IHJldHVybiBwb3N0SWZyYW1lKCdzaWduJywgbWVzc2FnZSwgLi4udGFncyk7IH0sXG4gICAgICAgIHZlcmlmeShzaWduYXR1cmUsIC4uLnRhZ3MpIHsgcmV0dXJuIHBvc3RJZnJhbWUoJ3ZlcmlmeScsIHNpZ25hdHVyZSwgLi4udGFncyk7IH0sXG4gICAgICAgIGVuY3J5cHQobWVzc2FnZSwgLi4udGFncykgeyByZXR1cm4gcG9zdElmcmFtZSgnZW5jcnlwdCcsIG1lc3NhZ2UsIC4uLnRhZ3MpOyB9LFxuICAgICAgICBkZWNyeXB0KGVuY3J5cHRlZCwgLi4udGFncykgeyByZXR1cm4gcG9zdElmcmFtZSgnZGVjcnlwdCcsIGVuY3J5cHRlZCwgLi4udGFncyk7IH0sXG4gICAgICAgIGNyZWF0ZSguLi5vcHRpb25hbE1lbWJlcnMpIHsgcmV0dXJuIHBvc3RJZnJhbWUoJ2NyZWF0ZScsIC4uLm9wdGlvbmFsTWVtYmVycyk7IH0sXG4gICAgICAgIGNoYW5nZU1lbWJlcnNoaXAoe3RhZywgYWRkLCByZW1vdmV9ID0ge30pIHsgcmV0dXJuIHBvc3RJZnJhbWUoJ2NoYW5nZU1lbWJlcnNoaXAnLCB7dGFnLCBhZGQsIHJlbW92ZX0pOyB9LFxuICAgICAgICBkZXN0cm95KHRhZ09yT3B0aW9ucykgeyByZXR1cm4gcG9zdElmcmFtZSgnZGVzdHJveScsIHRhZ09yT3B0aW9ucyk7IH0sXG4gICAgICAgIGNsZWFyKHRhZyA9IG51bGwpIHsgcmV0dXJuIHBvc3RJZnJhbWUoJ2NsZWFyJywgdGFnKTsgfSxcbiAgICAgICAgcmVhZHksXG5cbiAgICAgICAgLy8gQXBwbGljYXRpb24gYXNzaWducyB0aGVzZSBzbyB0aGF0IHRoZXkgY2FuIGJlIHVzZWQgYnkgdGhlIHZhdWx0LlxuICAgICAgICBnZXQgU3RvcmFnZSgpIHsgcmV0dXJuIHJlc291cmNlc0ZvcklmcmFtZTsgfSxcbiAgICAgICAgc2V0IFN0b3JhZ2Uoc3RvcmFnZSkgeyBPYmplY3QuYXNzaWduKHJlc291cmNlc0ZvcklmcmFtZSwgc3RvcmFnZSk7IH0sXG4gICAgICAgIGdldCBnZXRVc2VyRGV2aWNlU2VjcmV0KCkgeyByZXR1cm4gcmVzb3VyY2VzRm9ySWZyYW1lLmdldFVzZXJEZXZpY2VTZWNyZXQ7IH0sXG4gICAgICAgIHNldCBnZXRVc2VyRGV2aWNlU2VjcmV0KGZ1bmN0aW9uT2ZUYWdBbmRQcm9tcHQpIHsgcmVzb3VyY2VzRm9ySWZyYW1lLmdldFVzZXJEZXZpY2VTZWNyZXQgPSBmdW5jdGlvbk9mVGFnQW5kUHJvbXB0OyB9XG4gICAgICB9O1xuXG5leHBvcnQgZGVmYXVsdCBhcGk7XG4iLCJleHBvcnQgY29uc3Qgc2NhbGUgPSAxMCAqIDEwMjQgKiAxMDI0O1xuZXhwb3J0IGZ1bmN0aW9uIG1ha2VNZXNzYWdlKGxlbmd0aCA9IHNjYWxlKSB7XG4gIHJldHVybiBBcnJheS5mcm9tKHtsZW5ndGh9LCAoXywgaW5kZXgpID0+IGluZGV4ICYgMSkuam9pbignJyk7XG59XG5jb25zdCBiYXNlNjR3aXRoRG90ID0gL15bQS1aYS16MC05X1xcLS5dKyQvO1xuZXhwb3J0IGZ1bmN0aW9uIGlzQmFzZTY0VVJMKHN0cmluZywgcmVnZXggPSBiYXNlNjR3aXRoRG90KSB7XG4gIGV4cGVjdChyZWdleC50ZXN0KHN0cmluZykpLnRvQmVUcnV0aHkoKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHNhbWVUeXBlZEFycmF5KHJlc3VsdCwgbWVzc2FnZSkge1xuICAvLyBUaGUgcGF5bG9hZCBpcyBhIFVpbnQ4QXJyYXksIGJ1dCBpbiBOb2RlSlMsIGl0IHdpbGwgYmUgYSBzdWJjbGFzcyBvZiBVaW50OEFycmF5LFxuICAvLyB3aGljaCB3b24ndCBjb21wYXJlIHRoZSBzYW1lIGluIEphc21pbmUgdG9FcXVhbC5cbiAgZXhwZWN0KG5ldyBVaW50OEFycmF5KHJlc3VsdC5wYXlsb2FkKSkudG9FcXVhbChtZXNzYWdlKTtcbn1cbiIsImltcG9ydCB7bWFrZU1lc3NhZ2UsIGlzQmFzZTY0VVJMLCBzYW1lVHlwZWRBcnJheX0gZnJvbSBcIi4vc3VwcG9ydC9tZXNzYWdlVGV4dC5tanNcIjtcblxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gdGVzdEtyeXB0byAoa3J5cHRvLCAvLyBQYXNzIGVpdGhlciBLcnlwdG8gb3IgTXVsdGlLcnlwdG9cbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVuY3J5cHRhYmxlU2l6ZSA9IDQ0Nikge1xuICBjb25zdCBiaWdFbmNyeXB0YWJsZSA9IGVuY3J5cHRhYmxlU2l6ZSA+IDEwMDAsXG4gICAgICAgIHNsb3dLZXlDcmVhdGlvbiA9IDE1ZTMsXG4gICAgICAgIHNsb3dIeWJyaWQgPSBiaWdFbmNyeXB0YWJsZSA/IHNsb3dLZXlDcmVhdGlvbiA6IDVlMywgLy8gTmVlZGVkIG9uIEFuZHJvaWRcbiAgICAgICAgbWVzc2FnZSA9IG1ha2VNZXNzYWdlKCk7XG5cbiAgZGVzY3JpYmUoJ3NpZ25pbmcnLCBmdW5jdGlvbiAoKSB7XG4gICAgbGV0IGtleXBhaXI7XG4gICAgYmVmb3JlQWxsKGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgIGtleXBhaXIgPSBhd2FpdCBrcnlwdG8uZ2VuZXJhdGVTaWduaW5nS2V5KCk7XG4gICAgfSk7XG4gICAgaXQoJ3dpdGggYSBwcml2YXRlIGtleSBwcm9kdWNlcyBhIGJhc2U2NFVSTCBzaWduYXR1cmUgdGhhdCB2ZXJpZmllcyB3aXRoIHRoZSBwdWJsaWMga2V5LicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgIGxldCBzaWduYXR1cmUgPSBhd2FpdCBrcnlwdG8uc2lnbihrZXlwYWlyLnByaXZhdGVLZXksIG1lc3NhZ2UpO1xuICAgICAgaXNCYXNlNjRVUkwoc2lnbmF0dXJlKTtcbiAgICAgIGV4cGVjdChhd2FpdCBrcnlwdG8udmVyaWZ5KGtleXBhaXIucHVibGljS2V5LCBzaWduYXR1cmUpKS50b0JlVHJ1dGh5KCk7XG4gICAgfSk7XG4gICAgaXQoJ3JldHVybnMgdW5kZWZpbmVkIGZvciB2ZXJpZnkgd2l0aCB0aGUgd3Jvbmcga2V5LicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgIGxldCBzaWduYXR1cmUgPSBhd2FpdCBrcnlwdG8uc2lnbihrZXlwYWlyLnByaXZhdGVLZXksIG1lc3NhZ2UpLFxuICAgICAgICAgIHdyb25nS2V5cGFpciA9IGF3YWl0IGtyeXB0by5nZW5lcmF0ZVNpZ25pbmdLZXkoKTtcbiAgICAgIGV4cGVjdChhd2FpdCBrcnlwdG8udmVyaWZ5KHdyb25nS2V5cGFpci5wdWJsaWNLZXksIHNpZ25hdHVyZSkpLnRvQmVVbmRlZmluZWQoKTtcbiAgICB9KTtcbiAgICBpdCgnaGFuZGxlcyBiaW5hcnksIGFuZCB2ZXJpZmllcyB3aXRoIHRoYXQgYXMgcGF5bG9hZCBwcm9wZXJ0eS4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICBsZXQgbWVzc2FnZSA9IG5ldyBVaW50OEFycmF5KFsyMSwgMzFdKSxcbiAgICAgICAgICBzaWduYXR1cmUgPSBhd2FpdCBrcnlwdG8uc2lnbihrZXlwYWlyLnByaXZhdGVLZXksIG1lc3NhZ2UpLFxuICAgICAgICAgIHZlcmlmaWVkID0gYXdhaXQga3J5cHRvLnZlcmlmeShrZXlwYWlyLnB1YmxpY0tleSwgc2lnbmF0dXJlKTtcbiAgICAgIGV4cGVjdCh2ZXJpZmllZC5jdHkpLnRvQmVVbmRlZmluZWQoKTtcbiAgICAgIHNhbWVUeXBlZEFycmF5KHZlcmlmaWVkLCBtZXNzYWdlKTtcbiAgICB9KTtcbiAgICBpdCgnaGFuZGxlcyB0ZXh0LCBzZXR0aW5nIGN0eSBhcyBcInRleHQvcGxhaW5cIiwgYW5kIHZlcmlmaWVzIHdpdGggdGhhdCBhcyB0aGUgdGV4dCBwcm9wZXJ0eSBhbmQgYW4gZW5jb2Rpbmcgb2YgdGhhdCBmb3IgcGF5bG9hZC4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICBsZXQgc2lnbmF0dXJlID0gYXdhaXQga3J5cHRvLnNpZ24oa2V5cGFpci5wcml2YXRlS2V5LCBtZXNzYWdlKSxcbiAgICAgICAgICB2ZXJpZmllZCA9IGF3YWl0IGtyeXB0by52ZXJpZnkoa2V5cGFpci5wdWJsaWNLZXksIHNpZ25hdHVyZSk7XG4gICAgICBleHBlY3QodmVyaWZpZWQucHJvdGVjdGVkSGVhZGVyLmN0eSkudG9CZSgndGV4dC9wbGFpbicpO1xuICAgICAgZXhwZWN0KHZlcmlmaWVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgICBleHBlY3QodmVyaWZpZWQucGF5bG9hZCkudG9FcXVhbChuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUobWVzc2FnZSkpO1xuICAgIH0pO1xuICAgIGl0KCdoYW5kbGVzIGpzb24sIHNldHRpbmcgY3R5IGFzIFwianNvblwiLCBhbmQgdmVyaWZpZXMgd2l0aCB0aGF0IGFzIGpzb24gcHJvcGVydHksIHRoZSBzdHJpbmcgb2YgdGhhdCBhcyB0aGUgdGV4dCBwcm9wZXJ0eSwgYW5kIHRoZSBlbmNvZGluZyBvZiB0aGF0IHN0cmluZyBmb3IgcGF5bG9hZC4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICBsZXQgbWVzc2FnZSA9IHtmb286ICdiYXInfSxcbiAgICAgICAgICBzaWduYXR1cmUgPSBhd2FpdCBrcnlwdG8uc2lnbihrZXlwYWlyLnByaXZhdGVLZXksIG1lc3NhZ2UpLFxuICAgICAgICAgIHZlcmlmaWVkID0gYXdhaXQga3J5cHRvLnZlcmlmeShrZXlwYWlyLnB1YmxpY0tleSwgc2lnbmF0dXJlKTtcbiAgICAgIGV4cGVjdCh2ZXJpZmllZC5wcm90ZWN0ZWRIZWFkZXIuY3R5KS50b0JlKCdqc29uJyk7XG4gICAgICBleHBlY3QodmVyaWZpZWQuanNvbikudG9FcXVhbChtZXNzYWdlKTtcbiAgICAgIGV4cGVjdCh2ZXJpZmllZC50ZXh0KS50b0JlKEpTT04uc3RyaW5naWZ5KG1lc3NhZ2UpKTtcbiAgICAgIGV4cGVjdCh2ZXJpZmllZC5wYXlsb2FkKS50b0VxdWFsKG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZShKU09OLnN0cmluZ2lmeShtZXNzYWdlKSkpO1xuICAgIH0pO1xuICAgIGl0KCdVc2VzIHNwZWNpZmllZCBoZWFkZXJzIGlmIHN1cHBsaWVkLCBpbmNsdWRpbmcgY3R5LicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgIGxldCBjdHkgPSAndGV4dC9odG1sJyxcbiAgICAgICAgICBpYXQgPSBEYXRlLm5vdygpLFxuICAgICAgICAgIGZvbyA9IDE3LFxuICAgICAgICAgIG1lc3NhZ2UgPSBcIjxzb21ldGhpbmcgZWxzZT5cIixcbiAgICAgICAgICBzaWduYXR1cmUgPSBhd2FpdCBrcnlwdG8uc2lnbihrZXlwYWlyLnByaXZhdGVLZXksIG1lc3NhZ2UsIHtjdHksIGlhdCwgZm9vfSksXG4gICAgICAgICAgdmVyaWZpZWQgPSBhd2FpdCBrcnlwdG8udmVyaWZ5KGtleXBhaXIucHVibGljS2V5LCBzaWduYXR1cmUpO1xuICAgICAgZXhwZWN0KHZlcmlmaWVkLnByb3RlY3RlZEhlYWRlci5jdHkpLnRvQmUoY3R5KTtcbiAgICAgIGV4cGVjdCh2ZXJpZmllZC5wcm90ZWN0ZWRIZWFkZXIuaWF0KS50b0JlKGlhdCk7XG4gICAgICBleHBlY3QodmVyaWZpZWQucHJvdGVjdGVkSGVhZGVyLmZvbykudG9CZShmb28pO1xuICAgICAgZXhwZWN0KHZlcmlmaWVkLnRleHQpLnRvRXF1YWwobWVzc2FnZSk7XG4gICAgfSk7XG4gIH0pO1xuXG4gIGRlc2NyaWJlKCdlbmNyeXB0aW9uJywgZnVuY3Rpb24gKCkge1xuICAgIGxldCBrZXlwYWlyO1xuICAgIGJlZm9yZUFsbChhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICBrZXlwYWlyID0gYXdhaXQga3J5cHRvLmdlbmVyYXRlRW5jcnlwdGluZ0tleSgpO1xuICAgIH0pO1xuICAgIGl0KGBjYW4gd29yayB1cCB0aHJvdWdoIGF0IGxlYXN0ICR7ZW5jcnlwdGFibGVTaXplfSBieXRlcyB3aXRoIGFuIGFzeW1tZXRyaWMga2V5cGFpci5gLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAvLyBQdWJsaWMga2V5IGVuY3J5cHQgd2lsbCB3b3JrIHVwIHRocm91Z2ggNDQ2IGJ5dGVzLCBidXQgdGhlIHJlc3VsdCB3aWxsIG5vdCBkZWNyeXB0LlxuICAgICAgbGV0IG1lc3NhZ2UgPSBtYWtlTWVzc2FnZShlbmNyeXB0YWJsZVNpemUpLFxuICAgICAgICAgIGVuY3J5cHRlZCA9IGF3YWl0IGtyeXB0by5lbmNyeXB0KGtleXBhaXIucHVibGljS2V5LCBtZXNzYWdlKSxcbiAgICAgICAgICBkZWNyeXB0ZWQgPSBhd2FpdCBrcnlwdG8uZGVjcnlwdChrZXlwYWlyLnByaXZhdGVLZXksIGVuY3J5cHRlZCk7XG4gICAgICBpc0Jhc2U2NFVSTChlbmNyeXB0ZWQpO1xuICAgICAgZXhwZWN0KGRlY3J5cHRlZC50ZXh0KS50b0JlKG1lc3NhZ2UpXG4gICAgfSwgc2xvd0h5YnJpZCk7XG4gICAgZnVuY3Rpb24gdGVzdFN5bW1ldHJpYyhsYWJlbCwgcHJvbWlzZSwgZGVjcnlwdFByb21pc2UgPSBwcm9taXNlKSB7XG4gICAgICBpdChgY2FuIHdvcmsgb24gbXVjaCBsYXJnZXIgZGF0YSB3aXRoIGEgJHtsYWJlbH0uYCwgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICBsZXQga2V5ID0gYXdhaXQgcHJvbWlzZSxcbiAgICAgICAgICAgIGRlY3J5cHRLZXkgPSBhd2FpdCBkZWNyeXB0UHJvbWlzZSxcbiAgICAgICAgICAgIGVuY3J5cHRlZCA9IGF3YWl0IGtyeXB0by5lbmNyeXB0KGtleSwgbWVzc2FnZSksXG4gICAgICAgICAgICBkZWNyeXB0ZWQgPSBhd2FpdCBrcnlwdG8uZGVjcnlwdChkZWNyeXB0S2V5LCBlbmNyeXB0ZWQpO1xuICAgICAgICBpc0Jhc2U2NFVSTChlbmNyeXB0ZWQpO1xuICAgICAgICBleHBlY3QoZGVjcnlwdGVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgICB9KTtcbiAgICB9XG4gICAgdGVzdFN5bW1ldHJpYygnZml4ZWQgc3ltbWV0cmljIGtleScsXG4gICAgICAgICAgICAgICAgICBrcnlwdG8uZ2VuZXJhdGVTeW1tZXRyaWNLZXkoKSk7XG4gICAgdGVzdFN5bW1ldHJpYygncmVwcm9kdWNpYmxlIHNlY3JldCcsXG4gICAgICAgICAgICAgICAgICBrcnlwdG8uZ2VuZXJhdGVTeW1tZXRyaWNLZXkoXCJzZWNyZXRcIiksXG4gICAgICAgICAgICAgICAgICBrcnlwdG8uZ2VuZXJhdGVTeW1tZXRyaWNLZXkoXCJzZWNyZXRcIikpO1xuXG4gICAgaXQoJ2hhbmRsZXMgYmluYXJ5LCBhbmQgZGVjcnlwdHMgYXMgc2FtZS4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICBsZXQgbWVzc2FnZSA9IG5ldyBVaW50OEFycmF5KFsyMSwgMzFdKSxcbiAgICAgICAgICBlbmNyeXB0ZWQgPSBhd2FpdCBrcnlwdG8uZW5jcnlwdChrZXlwYWlyLnB1YmxpY0tleSwgbWVzc2FnZSksXG4gICAgICAgICAgZGVjcnlwdGVkID0gYXdhaXQga3J5cHRvLmRlY3J5cHQoa2V5cGFpci5wcml2YXRlS2V5LCBlbmNyeXB0ZWQpLFxuICAgICAgICAgIGhlYWRlciA9IGtyeXB0by5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIoZW5jcnlwdGVkKTtcbiAgICAgIGV4cGVjdChoZWFkZXIuY3R5KS50b0JlVW5kZWZpbmVkKCk7XG4gICAgICBzYW1lVHlwZWRBcnJheShkZWNyeXB0ZWQsIG1lc3NhZ2UpO1xuICAgIH0pO1xuICAgIGl0KCdoYW5kbGVzIHRleHQsIGFuZCBkZWNyeXB0cyBhcyBzYW1lLicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgIGxldCBlbmNyeXB0ZWQgPSBhd2FpdCBrcnlwdG8uZW5jcnlwdChrZXlwYWlyLnB1YmxpY0tleSwgbWVzc2FnZSksXG4gICAgICAgICAgZGVjcnlwdGVkID0gYXdhaXQga3J5cHRvLmRlY3J5cHQoa2V5cGFpci5wcml2YXRlS2V5LCBlbmNyeXB0ZWQpLFxuICAgICAgICAgIGhlYWRlciA9IGtyeXB0by5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIoZW5jcnlwdGVkKTtcbiAgICAgIGV4cGVjdChoZWFkZXIuY3R5KS50b0JlKCd0ZXh0L3BsYWluJyk7XG4gICAgICBleHBlY3QoZGVjcnlwdGVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgfSk7XG4gICAgaXQoJ2hhbmRsZXMganNvbiwgYW5kIGRlY3J5cHRzIGFzIHNhbWUuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgbGV0IG1lc3NhZ2UgPSB7Zm9vOiAnYmFyJ30sXG4gICAgICAgICAgZW5jcnlwdGVkID0gYXdhaXQga3J5cHRvLmVuY3J5cHQoa2V5cGFpci5wdWJsaWNLZXksIG1lc3NhZ2UpO1xuICAgICAgbGV0IGhlYWRlciA9IGtyeXB0by5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIoZW5jcnlwdGVkKSxcbiAgICAgICAgICBkZWNyeXB0ZWQgPSBhd2FpdCBrcnlwdG8uZGVjcnlwdChrZXlwYWlyLnByaXZhdGVLZXksIGVuY3J5cHRlZCk7XG4gICAgICBleHBlY3QoaGVhZGVyLmN0eSkudG9CZSgnanNvbicpO1xuICAgICAgZXhwZWN0KGRlY3J5cHRlZC5qc29uKS50b0VxdWFsKG1lc3NhZ2UpO1xuICAgIH0pO1xuICAgIGl0KCdVc2VzIHNwZWNpZmllZCBoZWFkZXJzIGlmIHN1cHBsaWVkLCBpbmNsdWRpbmcgY3R5LicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgIGxldCBjdHkgPSAndGV4dC9odG1sJyxcbiAgICAgICAgICBpYXQgPSBEYXRlLm5vdygpLFxuICAgICAgICAgIGZvbyA9IDE3LFxuICAgICAgICAgIG1lc3NhZ2UgPSBcIjxzb21ldGhpbmcgZWxzZT5cIixcbiAgICAgICAgICBlbmNyeXB0ZWQgPSBhd2FpdCBrcnlwdG8uZW5jcnlwdChrZXlwYWlyLnB1YmxpY0tleSwgbWVzc2FnZSwge2N0eSwgaWF0LCBmb299KSxcbiAgICAgICAgICBkZWNyeXB0ZWQgPSBhd2FpdCBrcnlwdG8uZGVjcnlwdChrZXlwYWlyLnByaXZhdGVLZXksIGVuY3J5cHRlZCksXG4gICAgICAgICAgaGVhZGVyID0ga3J5cHRvLmRlY29kZVByb3RlY3RlZEhlYWRlcihlbmNyeXB0ZWQpXG4gICAgICBleHBlY3QoaGVhZGVyLmN0eSkudG9CZShjdHkpO1xuICAgICAgZXhwZWN0KGhlYWRlci5pYXQpLnRvQmUoaWF0KTtcbiAgICAgIGV4cGVjdChoZWFkZXIuZm9vKS50b0JlKGZvbyk7XG4gICAgICBleHBlY3QoZGVjcnlwdGVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgfSk7XG4gICAgXG4gICAgZnVuY3Rpb24gZmFpbHNXaXRoV3JvbmcobGFiZWwsIGtleXNUaHVuaykge1xuICAgICAgaXQoYHJlamVjdHMgd3JvbmcgJHtsYWJlbH0uYCwgYXN5bmMgZnVuY3Rpb24oKSB7XG4gICAgICAgIGxldCBbZW5jcnlwdEtleSwgZGVjcnlwdEtleV0gPSBhd2FpdCBrZXlzVGh1bmsoKSxcbiAgICAgICAgICAgIG1lc3NhZ2UgPSBtYWtlTWVzc2FnZShlbmNyeXB0YWJsZVNpemUpLFxuICAgICAgICAgICAgZW5jcnlwdGVkID0gYXdhaXQga3J5cHRvLmVuY3J5cHQoZW5jcnlwdEtleSwgbWVzc2FnZSk7XG4gICAgICAgIGF3YWl0IGV4cGVjdEFzeW5jKGtyeXB0by5kZWNyeXB0KGRlY3J5cHRLZXksIGVuY3J5cHRlZCkpLnRvQmVSZWplY3RlZCgpO1xuICAgICAgfSwgc2xvd0tleUNyZWF0aW9uKTtcbiAgICB9XG4gICAgZmFpbHNXaXRoV3JvbmcoJ2FzeW1tZXRyaWMga2V5JywgYXN5bmMgKCkgPT4gW1xuICAgICAgKGF3YWl0IGtyeXB0by5nZW5lcmF0ZUVuY3J5cHRpbmdLZXkoKSkucHVibGljS2V5LFxuICAgICAgKGF3YWl0IGtyeXB0by5nZW5lcmF0ZUVuY3J5cHRpbmdLZXkoKSkucHJpdmF0ZUtleVxuICAgIF0pO1xuICAgIGZhaWxzV2l0aFdyb25nKCdzeW1tZXRyaWMga2V5JywgYXN5bmMgKCkgPT4gW1xuICAgICAgYXdhaXQga3J5cHRvLmdlbmVyYXRlU3ltbWV0cmljS2V5KCksXG4gICAgICBhd2FpdCBrcnlwdG8uZ2VuZXJhdGVTeW1tZXRyaWNLZXkoKVxuICAgIF0pO1xuICAgIGZhaWxzV2l0aFdyb25nKCdzZWNyZXQnLCBhc3luYyAoKSA9PiBbXG4gICAgICBhd2FpdCBrcnlwdG8uZ2VuZXJhdGVTeW1tZXRyaWNLZXkoXCJzZWNyZXRcIiksXG4gICAgICBhd2FpdCBrcnlwdG8uZ2VuZXJhdGVTeW1tZXRyaWNLZXkoXCJzZWNyZXRYXCIpXG4gICAgXSk7XG4gIH0pO1xuXG4gIGRlc2NyaWJlKCdleHBvcnQvaW1wb3J0JywgZnVuY3Rpb24gKCkge1xuICAgIC8vIEhhbmR5IGZvciBjeWNsaW5nIGluIGEgc2l6ZS1jaGVja2FibGUgd2F5LlxuICAgIGFzeW5jIGZ1bmN0aW9uIGV4cG9ydEtleShrZXkpIHtcbiAgICAgIHJldHVybiBKU09OLnN0cmluZ2lmeShhd2FpdCBrcnlwdG8uZXhwb3J0SldLKGtleSkpO1xuICAgIH1cbiAgICBmdW5jdGlvbiBpbXBvcnRLZXkoc3RyaW5nKSB7XG4gICAgICByZXR1cm4ga3J5cHRvLmltcG9ydEpXSyhKU09OLnBhcnNlKHN0cmluZykpO1xuICAgIH1cblxuICAgIGRlc2NyaWJlKGBvZiBzaWduaW5nIGtleXNgLCBmdW5jdGlvbiAoKSB7XG4gICAgICBjb25zdCBwcml2YXRlU2lnbmluZ1NpemUgPSAyNTM7IC8vIDI0OCByYXdcbiAgICAgIGl0KGB3b3JrcyB3aXRoIHRoZSBwcml2YXRlIHNpZ25pbmcga2V5IGFzIGEgJHtwcml2YXRlU2lnbmluZ1NpemV9IGJ5dGUgc2VyaWFsaXphdGlvbi5gLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGxldCBrZXlwYWlyID0gYXdhaXQga3J5cHRvLmdlbmVyYXRlU2lnbmluZ0tleSgpLFxuICAgICAgICAgICAgc2VyaWFsaXplZFByaXZhdGVLZXkgPSBhd2FpdCBleHBvcnRLZXkoa2V5cGFpci5wcml2YXRlS2V5KSxcbiAgICAgICAgICAgIGltcG9ydGVkUHJpdmF0ZUtleSA9IGF3YWl0IGltcG9ydEtleShzZXJpYWxpemVkUHJpdmF0ZUtleSksXG4gICAgICAgICAgICBzaWduYXR1cmUgPSBhd2FpdCBrcnlwdG8uc2lnbihpbXBvcnRlZFByaXZhdGVLZXksIG1lc3NhZ2UpO1xuICAgICAgICBleHBlY3Qoc2VyaWFsaXplZFByaXZhdGVLZXkubGVuZ3RoKS50b0JlKHByaXZhdGVTaWduaW5nU2l6ZSk7XG4gICAgICAgIGV4cGVjdChhd2FpdCBrcnlwdG8udmVyaWZ5KGtleXBhaXIucHVibGljS2V5LCBzaWduYXR1cmUpKS50b0JlVHJ1dGh5KCk7XG4gICAgICB9KTtcbiAgICAgIGNvbnN0IHB1YmxpY1NpZ25pbmdTaXplID0gMTgyOyAvLyAxMzIgcmF3XG4gICAgICBpdChgd29ya3Mgd2l0aCB0aGUgcHVibGljIHZlcmlmeWluZyBrZXkgYXMgYSAke3B1YmxpY1NpZ25pbmdTaXplfSBieXRlIHNlcmlhbGl6YXRpb24uYCwgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICBsZXQga2V5cGFpciA9IGF3YWl0IGtyeXB0by5nZW5lcmF0ZVNpZ25pbmdLZXkoKSxcbiAgICAgICAgICAgIHNlcmlhbGl6ZWRQdWJsaWNLZXkgPSBhd2FpdCBleHBvcnRLZXkoa2V5cGFpci5wdWJsaWNLZXkpLFxuICAgICAgICAgICAgaW1wb3J0ZWRQdWJsaWNLZXkgPSBhd2FpdCBpbXBvcnRLZXkoc2VyaWFsaXplZFB1YmxpY0tleSksXG4gICAgICAgICAgICBzaWduYXR1cmUgPSBhd2FpdCBrcnlwdG8uc2lnbihrZXlwYWlyLnByaXZhdGVLZXksIG1lc3NhZ2UpO1xuICAgICAgICBleHBlY3Qoc2VyaWFsaXplZFB1YmxpY0tleS5sZW5ndGgpLnRvQmUocHVibGljU2lnbmluZ1NpemUpO1xuICAgICAgICBleHBlY3QoYXdhaXQga3J5cHRvLnZlcmlmeShpbXBvcnRlZFB1YmxpY0tleSwgc2lnbmF0dXJlKSkudG9CZVRydXRoeSgpO1xuICAgICAgfSk7XG5cbiAgICAgIGNvbnN0IHB1YmxpY1NpZ25pbmdSYXdTaXplID0gMTMyO1xuICAgICAgaXQoYHdvcmtzIHdpdGggcHVibGljIGtleSBhcyBhIHJhdyB2ZXJpZnlpbmcga2V5IGFzIGEgYmFzZTY0VVJMIHNlcmlhbGl6YXRpb24gb2Ygbm8gbW9yZSB0aGF0ICR7cHVibGljU2lnbmluZ1Jhd1NpemV9IGJ5dGVzYCwgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICBsZXQga2V5cGFpciA9IGF3YWl0IGtyeXB0by5nZW5lcmF0ZVNpZ25pbmdLZXkoKSxcbiAgICAgICAgICAgIHNlcmlhbGl6ZWRQdWJsaWNLZXkgPSBhd2FpdCBrcnlwdG8uZXhwb3J0UmF3KGtleXBhaXIucHVibGljS2V5KSxcbiAgICAgICAgICAgIGltcG9ydGVkUHVibGljS2V5ID0gYXdhaXQga3J5cHRvLmltcG9ydFJhdyhzZXJpYWxpemVkUHVibGljS2V5KSxcbiAgICAgICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IGtyeXB0by5zaWduKGtleXBhaXIucHJpdmF0ZUtleSwgbWVzc2FnZSk7XG4gICAgICAgIGlzQmFzZTY0VVJMKHNlcmlhbGl6ZWRQdWJsaWNLZXkpO1xuICAgICAgICBleHBlY3Qoc2VyaWFsaXplZFB1YmxpY0tleS5sZW5ndGgpLnRvQmVMZXNzVGhhbk9yRXF1YWwocHVibGljU2lnbmluZ1Jhd1NpemUpO1xuICAgICAgICBleHBlY3QoYXdhaXQga3J5cHRvLnZlcmlmeShpbXBvcnRlZFB1YmxpY0tleSwgc2lnbmF0dXJlKSkudG9CZVRydXRoeSgpO1xuICAgICAgfSk7XG4gICAgfSk7XG5cbiAgICBkZXNjcmliZSgnb2YgZW5jcnlwdGlvbiBrZXlzJywgZnVuY3Rpb24gKCkge1xuICAgICAgY29uc3QgcHJpdmF0ZUVuY3J5cHRpbmdLZXlTaXplID0gWzMxNjksIDMxNzNdIC8vIHJhdyBbMzE2NCwgMzE2OF07IC8vIHdpdGggYSA0ayBtb2R1bHVzU2l6ZSBrZXlcbiAgICAgIGl0KGB3b3JrcyB3aXRoIHRoZSBwcml2YXRlIGtleSBhcyBhICR7cHJpdmF0ZUVuY3J5cHRpbmdLZXlTaXplWzBdfS0ke3ByaXZhdGVFbmNyeXB0aW5nS2V5U2l6ZVsxXX0gYnl0ZSBzZXJpYWxpemF0aW9uLmAsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgbGV0IGtleXBhaXIgPSBhd2FpdCBrcnlwdG8uZ2VuZXJhdGVFbmNyeXB0aW5nS2V5KCksXG4gICAgICAgICAgICBzZXJpYWxpemVkUHJpdmF0ZUtleSA9IGF3YWl0IGV4cG9ydEtleShrZXlwYWlyLnByaXZhdGVLZXkpLFxuICAgICAgICAgICAgaW1wb3J0ZWRQcml2YXRlS2V5ID0gYXdhaXQgaW1wb3J0S2V5KHNlcmlhbGl6ZWRQcml2YXRlS2V5KSxcbiAgICAgICAgICAgIG1lc3NhZ2UgPSBtYWtlTWVzc2FnZSg0NDYpLFxuICAgICAgICAgICAgZW5jcnlwdGVkID0gYXdhaXQga3J5cHRvLmVuY3J5cHQoa2V5cGFpci5wdWJsaWNLZXksIG1lc3NhZ2UpLFxuICAgICAgICAgICAgZGVjcnlwdGVkID0gYXdhaXQga3J5cHRvLmRlY3J5cHQoaW1wb3J0ZWRQcml2YXRlS2V5LCBlbmNyeXB0ZWQpO1xuICAgICAgICBleHBlY3Qoc2VyaWFsaXplZFByaXZhdGVLZXkubGVuZ3RoKS50b0JlR3JlYXRlclRoYW5PckVxdWFsKHByaXZhdGVFbmNyeXB0aW5nS2V5U2l6ZVswXSk7XG4gICAgICAgIGV4cGVjdChzZXJpYWxpemVkUHJpdmF0ZUtleS5sZW5ndGgpLnRvQmVMZXNzVGhhbk9yRXF1YWwocHJpdmF0ZUVuY3J5cHRpbmdLZXlTaXplWzFdKTtcbiAgICAgICAgZXhwZWN0KGRlY3J5cHRlZC50ZXh0KS50b0JlKG1lc3NhZ2UpXG4gICAgICB9KTtcbiAgICAgIGNvbnN0IHB1YmxpY0VuY3J5cHRpbmdLZXlTaXplID0gNzM1OyAvLyByYXcgNzM2OyAvLyB3aXRoIGEgNGsgbW9kdWx1c1NpemUga2V5XG4gICAgICBpdChgd29ya3Mgd2l0aCB0aGUgcHVibGljIGtleSBhcyBhICR7cHVibGljRW5jcnlwdGluZ0tleVNpemV9IGJ5dGUgc2VyaWFsaXphdGlvbi5gLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGxldCBrZXlwYWlyID0gYXdhaXQga3J5cHRvLmdlbmVyYXRlRW5jcnlwdGluZ0tleSgpLFxuICAgICAgICAgICAgc2VyaWFsaXplZFB1YmxpY0tleSA9IGF3YWl0IGV4cG9ydEtleShrZXlwYWlyLnB1YmxpY0tleSksXG4gICAgICAgICAgICBpbXBvcnRlZFB1YmxpY0tleSA9IGF3YWl0IGltcG9ydEtleShzZXJpYWxpemVkUHVibGljS2V5KSxcbiAgICAgICAgICAgIG1lc3NhZ2UgPSBtYWtlTWVzc2FnZSg0NDYpLFxuICAgICAgICAgICAgZW5jcnlwdGVkID0gYXdhaXQga3J5cHRvLmVuY3J5cHQoaW1wb3J0ZWRQdWJsaWNLZXksIG1lc3NhZ2UpLFxuICAgICAgICAgICAgZGVjcnlwdGVkID0gYXdhaXQga3J5cHRvLmRlY3J5cHQoa2V5cGFpci5wcml2YXRlS2V5LCBlbmNyeXB0ZWQpO1xuICAgICAgICBleHBlY3Qoc2VyaWFsaXplZFB1YmxpY0tleS5sZW5ndGgpLnRvQmUocHVibGljRW5jcnlwdGluZ0tleVNpemUpO1xuICAgICAgICBleHBlY3QoZGVjcnlwdGVkLnRleHQpLnRvQmUobWVzc2FnZSlcbiAgICAgIH0pO1xuICAgIH0pO1xuXG4gICAgZGVzY3JpYmUoJ29mIHN5bW1ldHJpYyBrZXknLCBmdW5jdGlvbiAoKSB7XG4gICAgICBjb25zdCBzeW1tZXRyaWNLZXlTaXplID0gNzk7IC8vIHJhdyA0NFxuICAgICAgaXQoYHdvcmtzIGFzIGEgJHtzeW1tZXRyaWNLZXlTaXplfSBieXRlIHNlcmlhbGl6YXRpb24uYCwgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICBsZXQga2V5ID0gYXdhaXQga3J5cHRvLmdlbmVyYXRlU3ltbWV0cmljS2V5KCksXG4gICAgICAgICAgICBzZXJpYWxpemVkS2V5ID0gYXdhaXQgZXhwb3J0S2V5KGtleSksXG4gICAgICAgICAgICBpbXBvcnRlZEtleSA9IGF3YWl0IGltcG9ydEtleShzZXJpYWxpemVkS2V5KSxcbiAgICAgICAgICAgIGVuY3J5cHRlZCA9IGF3YWl0IGtyeXB0by5lbmNyeXB0KGtleSwgbWVzc2FnZSksXG4gICAgICAgICAgICBkZWNyeXB0ZWQgPSBhd2FpdCBrcnlwdG8uZGVjcnlwdChpbXBvcnRlZEtleSwgZW5jcnlwdGVkKTtcbiAgICAgICAgZXhwZWN0KHNlcmlhbGl6ZWRLZXkubGVuZ3RoKS50b0JlKHN5bW1ldHJpY0tleVNpemUpO1xuICAgICAgICBleHBlY3QoZGVjcnlwdGVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgICB9KTtcbiAgICB9KTtcbiAgfSk7XG5cbiAgaXQoJ3dyYXBzIGxpa2UgZXhwb3J0K2VuY3J5cHQuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgIC8vIExldCdzIFwid3JhcFwiIGEgc3ltbWV0cmljIGtleSB3aXRoIGFuIGFzeW1tZXRyaWMgZW5jcnlwdGluZyBrZXkgaW4gdHdvIHdheXMuXG4gICAgbGV0IGVuY3J5cHRhYmxlS2V5ID0gYXdhaXQga3J5cHRvLmdlbmVyYXRlU3ltbWV0cmljS2V5KCksXG4gICAgICAgIHdyYXBwaW5nS2V5ID0gYXdhaXQga3J5cHRvLmdlbmVyYXRlRW5jcnlwdGluZ0tleSgpLFxuXG4gICAgICAgIC8vIEN5Y2xlIGl0IHRocm91Z2ggZXhwb3J0LGVuY3J5cHQgdG8gZW5jcnlwdGVkIGtleSwgYW5kIGRlY3J5cHQsaW1wb3J0IHRvIGltcG9ydGVkIGtleS5cbiAgICAgICAgZXhwb3J0ZWQgPSBhd2FpdCBrcnlwdG8uZXhwb3J0SldLKGVuY3J5cHRhYmxlS2V5KSxcbiAgICAgICAgZW5jcnlwdGVkID0gYXdhaXQga3J5cHRvLmVuY3J5cHQod3JhcHBpbmdLZXkucHVibGljS2V5LCBleHBvcnRlZCksXG4gICAgICAgIGRlY3J5cHRlZCA9IGF3YWl0IGtyeXB0by5kZWNyeXB0KHdyYXBwaW5nS2V5LnByaXZhdGVLZXksIGVuY3J5cHRlZCksXG4gICAgICAgIGltcG9ydGVkID0gYXdhaXQga3J5cHRvLmltcG9ydEpXSyhkZWNyeXB0ZWQuanNvbiksXG5cbiAgICAgICAgLy8gQ3ljbGUgaXQgdGhyb3VnaCB3cmFwIGFuZCB1bndyYXAuXG4gICAgICAgIHdyYXBwZWQgPSBhd2FpdCBrcnlwdG8ud3JhcEtleShlbmNyeXB0YWJsZUtleSwgd3JhcHBpbmdLZXkucHVibGljS2V5KSxcbiAgICAgICAgdW53cmFwcGVkID0gYXdhaXQga3J5cHRvLnVud3JhcEtleSh3cmFwcGVkLCB3cmFwcGluZ0tleS5wcml2YXRlS2V5KSxcblxuICAgICAgICAvLyBVc2Ugb25lIHRvIGVuY3J5cHQgYSBtZXNzYWdlLCBhbmQgdGhlIG90aGVyIGRlY3J5cHQgaXQuXG4gICAgICAgIG1lc3NhZ2UgPSBcInRoaXMgaXMgYSBtZXNzYWdlXCIsXG4gICAgICAgIGVuY3J5cHRlZE1lc3NhZ2UgPSBhd2FpdCBrcnlwdG8uZW5jcnlwdCh1bndyYXBwZWQsIG1lc3NhZ2UpLFxuICAgICAgICBkZWNyeXB0ZWRNZXNzYWdlID0gYXdhaXQga3J5cHRvLmRlY3J5cHQoaW1wb3J0ZWQsIGVuY3J5cHRlZE1lc3NhZ2UpO1xuICAgIGlzQmFzZTY0VVJMKHdyYXBwZWQpO1xuICAgIGV4cGVjdChkZWNyeXB0ZWRNZXNzYWdlLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gIH0sIHNsb3dLZXlDcmVhdGlvbik7XG59XG4iLCJpbXBvcnQge3NjYWxlLCBtYWtlTWVzc2FnZSwgc2FtZVR5cGVkQXJyYXl9IGZyb20gXCIuL3N1cHBvcnQvbWVzc2FnZVRleHQubWpzXCI7XG5pbXBvcnQgdGVzdEtyeXB0byBmcm9tIFwiLi9rcnlwdG9UZXN0cy5tanNcIjtcblxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gdGVzdE11bHRpS3J5cHRvKG11bHRpS3J5cHRvKSB7XG4gIGNvbnN0IHNsb3dLZXlDcmVhdGlvbiA9IDIwZTMsIC8vIEFuZHJvaWRcbiAgICAgICAgbWVzc2FnZSA9IG1ha2VNZXNzYWdlKCk7XG4gIGRlc2NyaWJlKCdmYWxscyB0aHJvdWdoIHRvIGtyeXB0byB3aXRoIHNpbmdsZSBrZXlzJywgZnVuY3Rpb24gKCkge1xuICAgIHRlc3RLcnlwdG8obXVsdGlLcnlwdG8sIHNjYWxlKTtcbiAgfSk7XG5cbiAgZGVzY3JpYmUoJ211bHRpLXdheSBrZXlzJywgZnVuY3Rpb24gKCkge1xuXG4gICAgZGVzY3JpYmUoJ211bHRpLXNpZ25hdHVyZScsIGZ1bmN0aW9uICgpIHtcbiAgICAgIGxldCBzaWduaW5nQSwgc2lnbmluZ0I7XG4gICAgICBiZWZvcmVBbGwoYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICBzaWduaW5nQSA9IGF3YWl0IG11bHRpS3J5cHRvLmdlbmVyYXRlU2lnbmluZ0tleSgpO1xuICAgICAgICBzaWduaW5nQiA9IGF3YWl0IG11bHRpS3J5cHRvLmdlbmVyYXRlU2lnbmluZ0tleSgpO1xuICAgICAgfSk7XG5cbiAgICAgIGl0KCdpcyBhIG11bHRpLXNpZ25hdHVyZS4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGxldCBtdWx0aVNpZ24gPSB7YTogc2lnbmluZ0EucHJpdmF0ZUtleSwgYjogc2lnbmluZ0IucHJpdmF0ZUtleX0sXG4gICAgICAgICAgICAvLyBPcmRlciBkb2Vzbid0IG1hdHRlci4ganVzdCB0aGF0IHRoZXkgY29ycmVzcG9uZCBhcyBhIHNldC5cbiAgICAgICAgICAgIG11bHRpVmVyaWZ5ID0ge2I6IHNpZ25pbmdCLnB1YmxpY0tleSwgYTogc2lnbmluZ0EucHVibGljS2V5fSxcbiAgICAgICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IG11bHRpS3J5cHRvLnNpZ24obXVsdGlTaWduLCBtZXNzYWdlKSxcbiAgICAgICAgICAgIHZlcmlmaWVkID0gYXdhaXQgbXVsdGlLcnlwdG8udmVyaWZ5KG11bHRpVmVyaWZ5LCBzaWduYXR1cmUpO1xuICAgICAgICBleHBlY3QodmVyaWZpZWQpLnRvQmVUcnV0aHkoKTtcbiAgICAgIH0pO1xuICAgICAgaXQoJ2NhbiBzcGVjaWZ5IHR5cGU6XCJtdWx0aVwiIGluIHRoZSBzaWduaW5nIGtleSBmb3IgY2xhcmlmeS4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGxldCBtdWx0aVNpZ24gPSB7YTogc2lnbmluZ0EucHJpdmF0ZUtleSwgYjogc2lnbmluZ0IucHJpdmF0ZUtleSwgdHlwZTonbXVsdGknfSxcbiAgICAgICAgICAgIG11bHRpVmVyaWZ5ID0ge2E6IHNpZ25pbmdBLnB1YmxpY0tleSwgYjogc2lnbmluZ0IucHVibGljS2V5fSxcbiAgICAgICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IG11bHRpS3J5cHRvLnNpZ24obXVsdGlTaWduLCBtZXNzYWdlKSxcbiAgICAgICAgICAgIHZlcmlmaWVkID0gYXdhaXQgbXVsdGlLcnlwdG8udmVyaWZ5KG11bHRpVmVyaWZ5LCBzaWduYXR1cmUpO1xuICAgICAgICBleHBlY3QodmVyaWZpZWQpLnRvQmVUcnV0aHkoKTtcbiAgICAgIH0pO1xuICAgICAgaXQoJ2NhbiBzcGVjaWZ5IHR5cGU6XCJtdWx0aVwiIGluIHRoZSB2ZXJpZnlpbmcga2V5IGZvciBjbGFyaWZ5LicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgbGV0IG11bHRpU2lnbiA9IHthOiBzaWduaW5nQS5wcml2YXRlS2V5LCBiOiBzaWduaW5nQi5wcml2YXRlS2V5fSxcbiAgICAgICAgICAgIG11bHRpVmVyaWZ5ID0ge2E6IHNpZ25pbmdBLnB1YmxpY0tleSwgYjogc2lnbmluZ0IucHVibGljS2V5LCB0eXBlOidtdWx0aSd9LFxuICAgICAgICAgICAgc2lnbmF0dXJlID0gYXdhaXQgbXVsdGlLcnlwdG8uc2lnbihtdWx0aVNpZ24sIG1lc3NhZ2UpLFxuICAgICAgICAgICAgdmVyaWZpZWQgPSBhd2FpdCBtdWx0aUtyeXB0by52ZXJpZnkobXVsdGlWZXJpZnksIHNpZ25hdHVyZSk7XG4gICAgICAgIGV4cGVjdCh2ZXJpZmllZCkudG9CZVRydXRoeSgpO1xuICAgICAgfSk7XG4gICAgICBpdCgnY2FuIHNwZWNpZnkgaXNzLCBhY3QsIGlhdCBpbiB0aGUga2V5LCB3aGljaCB3aWxsIGFwcGVhciBpbiB0aGUgc2lnbmF0dXJlLicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgbGV0IGlhdCA9IERhdGUubm93KCksXG4gICAgICAgICAgICBpc3MgPSAnYScsXG4gICAgICAgICAgICBhY3QgPSAnYicsXG4gICAgICAgICAgICBtdWx0aVNpZ24gPSB7YTogc2lnbmluZ0EucHJpdmF0ZUtleSwgYjogc2lnbmluZ0IucHJpdmF0ZUtleX0sXG4gICAgICAgICAgICBtdWx0aVZlcmlmeSA9IHthOiBzaWduaW5nQS5wdWJsaWNLZXksIGI6IHNpZ25pbmdCLnB1YmxpY0tleX0sXG4gICAgICAgICAgICBzaWduYXR1cmUgPSBhd2FpdCBtdWx0aUtyeXB0by5zaWduKG11bHRpU2lnbiwgbWVzc2FnZSwge2lzcywgYWN0LCBpYXR9KSxcbiAgICAgICAgICAgIHZlcmlmaWVkID0gYXdhaXQgbXVsdGlLcnlwdG8udmVyaWZ5KG11bHRpVmVyaWZ5LCBzaWduYXR1cmUpO1xuICAgICAgICBleHBlY3QodmVyaWZpZWQpLnRvQmVUcnV0aHkoKTtcbiAgICAgICAgc2lnbmF0dXJlLnNpZ25hdHVyZXMuZm9yRWFjaChzdWJTaWduYXR1cmUgPT4ge1xuICAgICAgICAgIGxldCBoZWFkZXIgPSBtdWx0aUtyeXB0by5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIoc3ViU2lnbmF0dXJlKTtcbiAgICAgICAgICBleHBlY3QoaGVhZGVyLmlzcykudG9CZShpc3MpO1xuICAgICAgICAgIGV4cGVjdChoZWFkZXIuYWN0KS50b0JlKGFjdCk7XG4gICAgICAgICAgZXhwZWN0KGhlYWRlci5pYXQpLnRvQmUoaWF0KTtcbiAgICAgICAgfSk7XG4gICAgICB9KTtcbiAgICAgIGl0KCdjYW4gc2lnbiBiaW5hcnkgYW5kIGl0IGlzIHJlY292ZXJ5IGFzIGJpbmFyeSBmcm9tIHBheWxvYWQgcHJvcGVydHkgb2YgdmVyZmljYXRpb24uJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICBsZXQgbWVzc2FnZSA9IG5ldyBVaW50OEFycmF5KFsxXSwgWzJdLCBbM10pLFxuICAgICAgICAgICAgc2lnbmF0dXJlID0gYXdhaXQgbXVsdGlLcnlwdG8uc2lnbih7YTogc2lnbmluZ0EucHJpdmF0ZUtleSwgYjogc2lnbmluZ0IucHJpdmF0ZUtleX0sIG1lc3NhZ2UpLFxuICAgICAgICAgICAgdmVyaWZpZWQgPSBhd2FpdCBtdWx0aUtyeXB0by52ZXJpZnkoe2E6IHNpZ25pbmdBLnB1YmxpY0tleSwgYjogc2lnbmluZ0IucHVibGljS2V5fSwgc2lnbmF0dXJlKTtcbiAgICAgICAgZXhwZWN0KHZlcmlmaWVkLnBheWxvYWQpLnRvRXF1YWwobWVzc2FnZSk7XG4gICAgICB9KTtcbiAgICAgIGl0KCdjYW4gc2lnbiBzdHJpbmcgdHlwZSBhbmQgaXQgaXMgcmVjb3ZlcmFibGUgYXMgc3RyaW5nIGZyb20gdGV4dCBwcm9wZXJ0eSBvZiB2ZXJpZmljYXRpb24uJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICBsZXQgbWVzc2FnZSA9IFwiYSBzdHJpbmdcIixcbiAgICAgICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IG11bHRpS3J5cHRvLnNpZ24oe2E6IHNpZ25pbmdBLnByaXZhdGVLZXksIGI6IHNpZ25pbmdCLnByaXZhdGVLZXl9LCBtZXNzYWdlKSxcbiAgICAgICAgICAgIHZlcmlmaWVkID0gYXdhaXQgbXVsdGlLcnlwdG8udmVyaWZ5KHthOiBzaWduaW5nQS5wdWJsaWNLZXksIGI6IHNpZ25pbmdCLnB1YmxpY0tleX0sIHNpZ25hdHVyZSk7XG4gICAgICAgIGV4cGVjdCh2ZXJpZmllZC50ZXh0KS50b0VxdWFsKG1lc3NhZ2UpO1xuICAgICAgICBleHBlY3QodmVyaWZpZWQucGF5bG9hZCkudG9FcXVhbChuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUobWVzc2FnZSkpO1xuICAgICAgfSk7XG4gICAgICBpdCgnY2FuIHNpZ24gYSBqc29uYWJsZSBvYmplY3QgYW5kIGl0IGlzIHJlY292ZXJ5IGFzIHNhbWUgZnJvbSBqc29uIHByb3BlcnR5IG9mIHJlc3VsdC4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGxldCBtZXNzYWdlID0ge2ZvbzogXCJhIHN0cmluZ1wiLCBiYXI6IGZhbHNlLCBiYXo6IFsnYScsIDIsIG51bGxdfSxcbiAgICAgICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IG11bHRpS3J5cHRvLnNpZ24oe2E6IHNpZ25pbmdBLnByaXZhdGVLZXksIGI6IHNpZ25pbmdCLnByaXZhdGVLZXl9LCBtZXNzYWdlKSxcbiAgICAgICAgICAgIHZlcmlmaWVkID0gYXdhaXQgbXVsdGlLcnlwdG8udmVyaWZ5KHthOiBzaWduaW5nQS5wdWJsaWNLZXksIGI6IHNpZ25pbmdCLnB1YmxpY0tleX0sIHNpZ25hdHVyZSk7XG4gICAgICAgIGV4cGVjdCh2ZXJpZmllZC5qc29uKS50b0VxdWFsKG1lc3NhZ2UpO1xuICAgICAgICBleHBlY3QodmVyaWZpZWQucGF5bG9hZCkudG9FcXVhbChuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUoSlNPTi5zdHJpbmdpZnkobWVzc2FnZSkpKTtcbiAgICAgIH0pO1xuICAgICAgaXQoJ2NhbiBzcGVjaWZ5IGEgc3BlY2lmaWMgY3R5IHRoYXQgd2lsbCBwYXNzIHRocm91Z2ggdG8gdmVyaWZ5LicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgbGV0IG1lc3NhZ2UgPSB7Zm9vOiBcImEgc3RyaW5nXCIsIGJhcjogZmFsc2UsIGJhejogWydhJywgMiwgbnVsbF19LFxuICAgICAgICAgICAgY3R5ID0gJ2FwcGxpY2F0aW9uL2Zvbytqc29uJyxcbiAgICAgICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IG11bHRpS3J5cHRvLnNpZ24oe2E6IHNpZ25pbmdBLnByaXZhdGVLZXksIGI6IHNpZ25pbmdCLnByaXZhdGVLZXl9LCBtZXNzYWdlLCB7Y3R5fSksXG4gICAgICAgICAgICB2ZXJpZmllZCA9IGF3YWl0IG11bHRpS3J5cHRvLnZlcmlmeSh7YTogc2lnbmluZ0EucHVibGljS2V5LCBiOiBzaWduaW5nQi5wdWJsaWNLZXl9LCBzaWduYXR1cmUpO1xuICAgICAgICBleHBlY3QodmVyaWZpZWQuanNvbikudG9FcXVhbChtZXNzYWdlKTtcbiAgICAgICAgZXhwZWN0KHZlcmlmaWVkLnByb3RlY3RlZEhlYWRlci5jdHkpLnRvQmUoY3R5KTtcbiAgICAgICAgZXhwZWN0KHZlcmlmaWVkLnBheWxvYWQpLnRvRXF1YWwobmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKEpTT04uc3RyaW5naWZ5KG1lc3NhZ2UpKSk7XG4gICAgICB9KTtcblxuICAgICAgaXQoJ2ZhaWxzIHZlcmlmaWNhdGlvbiBpZiB0aGUgc2lnbmF0dXJlIGlzIG1pc2xhYmVsZWQuJyxcbiAgICAgICAgIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgbGV0IG11bHRpU2lnbiA9IHthOiBzaWduaW5nQi5wcml2YXRlS2V5LCBiOiBzaWduaW5nQS5wcml2YXRlS2V5fSwgLy8gTm90ZSB0aGF0IHRoZSB2YWx1ZXMgYXJlIG5vdCB3aGF0IGlzIGNsYWltZWQuXG4gICAgICAgICAgICAgICBtdWx0aVZlcmlmeSA9IHthOiBzaWduaW5nQS5wdWJsaWNLZXksIGI6IHNpZ25pbmdCLnB1YmxpY0tleX0sXG4gICAgICAgICAgICAgICBzaWduYXR1cmUgPSBhd2FpdCBtdWx0aUtyeXB0by5zaWduKG11bHRpU2lnbiwgbWVzc2FnZSksXG4gICAgICAgICAgICAgICB2ZXJpZmllZCA9IGF3YWl0IG11bHRpS3J5cHRvLnZlcmlmeShtdWx0aVZlcmlmeSwgc2lnbmF0dXJlKTtcbiAgICAgICAgICAgZXhwZWN0KHZlcmlmaWVkKS50b0JlVW5kZWZpbmVkKCk7XG4gICAgICAgICB9KTtcbiAgICAgIGl0KCdnaXZlcyBlbm91Z2ggaW5mb3JtYXRpb24gdGhhdCB3ZSBjYW4gdGVsbCBpZiBhIHZlcmlmeWluZyBzdWIga2V5IGlzIG1pc3NpbmcuJyxcbiAgICAgICAgIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgbGV0IG11bHRpU2lnbiA9IHthOiBzaWduaW5nQS5wcml2YXRlS2V5LCBiOiBzaWduaW5nQi5wcml2YXRlS2V5fSxcbiAgICAgICAgICAgICAgIG11bHRpVmVyaWZ5ID0ge2I6IHNpZ25pbmdCLnB1YmxpY0tleX0sIC8vIE1pc3NpbmcgYS5cbiAgICAgICAgICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IG11bHRpS3J5cHRvLnNpZ24obXVsdGlTaWduLCBtZXNzYWdlKSxcbiAgICAgICAgICAgICAgIHZlcmlmaWVkID0gYXdhaXQgbXVsdGlLcnlwdG8udmVyaWZ5KG11bHRpVmVyaWZ5LCBzaWduYXR1cmUpO1xuICAgICAgICAgICAvLyBPdmVyYWxsLCBzb21ldGhpbmcgd2UgYXNrZWQgZm9yIGRpZCB2ZXJpZnkuXG4gICAgICAgICAgIGV4cGVjdCh2ZXJpZmllZC5wYXlsb2FkKS50b0JlVHJ1dGh5KCk7XG4gICAgICAgICAgIGV4cGVjdCh2ZXJpZmllZC50ZXh0KS50b0JlKG1lc3NhZ2UpO1xuICAgICAgICAgICAvLyBiIGlzIHNlY29uZCBzaWduZXIgaW4gc2lnbmF0dXJlXG4gICAgICAgICAgIGV4cGVjdCh2ZXJpZmllZC5zaWduZXJzWzFdLnBheWxvYWQpLnRvQmVUcnV0aHkoKTtcbiAgICAgICAgICAgLy8gYnV0IHRoZSBmaXJzdCBzaWduZXIgd2FzIG5vdCB2ZXJpZmllZFxuICAgICAgICAgICBleHBlY3QodmVyaWZpZWQuc2lnbmVyc1swXS5wYXlsb2FkKS50b0JlVW5kZWZpbmVkKCk7XG4gICAgICAgICB9KTtcbiAgICAgIGl0KCdnaXZlcyBlbm91Z2ggaW5mb3JtYXRpb24gdGhhdCB3ZSBjYW4gdGVsbCBpZiBhIHNpZ25hdHVyZSBzdWIga2V5IGlzIG1pc3NpbmcuJyxcbiAgICAgICAgIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgbGV0IG11bHRpU2lnbiA9IHthOiBzaWduaW5nQS5wcml2YXRlS2V5fSwgLy8gTWlzc2luZyBiLlxuICAgICAgICAgICAgICAgbXVsdGlWZXJpZnkgPSB7YTogc2lnbmluZ0EucHVibGljS2V5LCBiOiBzaWduaW5nQi5wdWJsaWNLZXl9LFxuICAgICAgICAgICAgICAgc2lnbmF0dXJlID0gYXdhaXQgbXVsdGlLcnlwdG8uc2lnbihtdWx0aVNpZ24sIG1lc3NhZ2UpLFxuICAgICAgICAgICAgICAgdmVyaWZpZWQgPSBhd2FpdCBtdWx0aUtyeXB0by52ZXJpZnkobXVsdGlWZXJpZnksIHNpZ25hdHVyZSk7XG4gICAgICAgICAgIC8vIE92ZXJhbGwsIHNvbWV0aGluZyB3ZSBhc2tlZCBmb3IgZGlkIHZlcmlmeS5cbiAgICAgICAgICAgZXhwZWN0KHZlcmlmaWVkLnBheWxvYWQpLnRvQmVUcnV0aHkoKTtcbiAgICAgICAgICAgZXhwZWN0KHZlcmlmaWVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgICAgICAgIC8vIEJ1dCBvbmx5IG9uZSBzaWduZXJcbiAgICAgICAgICAgZXhwZWN0KHZlcmlmaWVkLnNpZ25lcnMubGVuZ3RoKS50b0JlKDEpO1xuICAgICAgICAgICBleHBlY3QodmVyaWZpZWQuc2lnbmVyc1swXS5wcm90ZWN0ZWRIZWFkZXIua2lkKS50b0JlKCdhJyk7XG4gICAgICAgICAgIGV4cGVjdCh2ZXJpZmllZC5zaWduZXJzWzBdLnBheWxvYWQpLnRvQmVUcnV0aHkoKTtcbiAgICAgICAgIH0pO1xuICAgIH0pO1xuXG4gICAgZGVzY3JpYmUoJ211bHRpLXdheSBlbmNyeXB0aW9uJywgZnVuY3Rpb24gKCkge1xuICAgICAgbGV0IGVuY3J5cHRlZCwga2V5cGFpciwgc3ltbWV0cmljLCBzZWNyZXRUZXh0ID0gXCJzaGghXCIsIHJlY2lwaWVudHMsIGVuY3J5cHRpbmdNdWx0aSwgZGVjcnlwdGluZ011bHRpO1xuICAgICAgYmVmb3JlQWxsKGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgc3ltbWV0cmljID0gYXdhaXQgbXVsdGlLcnlwdG8uZ2VuZXJhdGVTeW1tZXRyaWNLZXkoKTtcbiAgICAgICAga2V5cGFpciA9IGF3YWl0IG11bHRpS3J5cHRvLmdlbmVyYXRlRW5jcnlwdGluZ0tleSgpO1xuICAgICAgICBlbmNyeXB0ZWQgPSBhd2FpdCBtdWx0aUtyeXB0by5lbmNyeXB0KHthOiBzeW1tZXRyaWMsIGI6IGtleXBhaXIucHVibGljS2V5LCBjOiBzZWNyZXRUZXh0fSwgbWVzc2FnZSk7XG4gICAgICAgIHJlY2lwaWVudHMgPSBlbmNyeXB0ZWQucmVjaXBpZW50cztcbiAgICAgICAgbGV0IG90aGVyS2V5cGFpciA9IGF3YWl0IG11bHRpS3J5cHRvLmdlbmVyYXRlRW5jcnlwdGluZ0tleSgpO1xuICAgICAgICBlbmNyeXB0aW5nTXVsdGkgPSB7YToga2V5cGFpci5wdWJsaWNLZXksIGI6IG90aGVyS2V5cGFpci5wdWJsaWNLZXl9O1xuICAgICAgICBkZWNyeXB0aW5nTXVsdGkgPSB7YToga2V5cGFpci5wcml2YXRlS2V5LCBiOiBvdGhlcktleXBhaXIucHJpdmF0ZUtleX07XG4gICAgICB9LCBzbG93S2V5Q3JlYXRpb24pO1xuICAgICAgaXQoJ3dvcmtzIHdpdGggc3ltbWV0cmljIG1lbWJlcnMuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICBsZXQgZGVjcnlwdGVkID0gYXdhaXQgbXVsdGlLcnlwdG8uZGVjcnlwdCh7YTogc3ltbWV0cmljfSwgZW5jcnlwdGVkKTtcbiAgICAgICAgZXhwZWN0KGRlY3J5cHRlZC50ZXh0KS50b0JlKG1lc3NhZ2UpO1xuICAgICAgICBleHBlY3QocmVjaXBpZW50c1swXS5oZWFkZXIua2lkKS50b0JlKCdhJyk7XG4gICAgICAgIGV4cGVjdChyZWNpcGllbnRzWzBdLmhlYWRlci5hbGcpLnRvQmUoJ0EyNTZHQ01LVycpO1xuICAgICAgfSk7XG4gICAgICBpdCgnd29ya3Mgd2l0aCBrZXlwYWlyIG1lbWJlcnMuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICBsZXQgZGVjcnlwdGVkID0gYXdhaXQgbXVsdGlLcnlwdG8uZGVjcnlwdCh7Yjoga2V5cGFpci5wcml2YXRlS2V5fSwgZW5jcnlwdGVkKTtcbiAgICAgICAgZXhwZWN0KGRlY3J5cHRlZC50ZXh0KS50b0JlKG1lc3NhZ2UpO1xuICAgICAgICBleHBlY3QocmVjaXBpZW50c1sxXS5oZWFkZXIua2lkKS50b0JlKCdiJyk7XG4gICAgICAgIGV4cGVjdChyZWNpcGllbnRzWzFdLmhlYWRlci5hbGcpLnRvQmUoJ1JTQS1PQUVQLTI1NicpO1xuICAgICAgfSk7XG4gICAgICBpdCgnd29ya3Mgd2l0aCBzZWNyZXQgdGV4dCBtZW1iZXJzLicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgbGV0IGRlY3J5cHRlZCA9IGF3YWl0IG11bHRpS3J5cHRvLmRlY3J5cHQoe2M6IHNlY3JldFRleHR9LCBlbmNyeXB0ZWQpO1xuICAgICAgICBleHBlY3QoZGVjcnlwdGVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgICAgIGV4cGVjdChyZWNpcGllbnRzWzJdLmhlYWRlci5raWQpLnRvQmUoJ2MnKTtcbiAgICAgICAgZXhwZWN0KHJlY2lwaWVudHNbMl0uaGVhZGVyLmFsZykudG9CZSgnUEJFUzItSFM1MTIrQTI1NktXJyk7XG4gICAgICB9KTtcblxuICAgICAgaXQoJ2hhbmRsZXMgYmluYXJ5LCBhbmQgZGVjcnlwdHMgYXMgc2FtZS4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGxldCBtZXNzYWdlID0gbmV3IFVpbnQ4QXJyYXkoWzIxLCAzMV0pLFxuICAgICAgICAgICAgZW5jcnlwdGVkID0gYXdhaXQgbXVsdGlLcnlwdG8uZW5jcnlwdChlbmNyeXB0aW5nTXVsdGksIG1lc3NhZ2UpLFxuICAgICAgICAgICAgZGVjcnlwdGVkID0gYXdhaXQgbXVsdGlLcnlwdG8uZGVjcnlwdChkZWNyeXB0aW5nTXVsdGksIGVuY3J5cHRlZCksXG4gICAgICAgICAgICBoZWFkZXIgPSBtdWx0aUtyeXB0by5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIoZW5jcnlwdGVkKTtcbiAgICAgICAgZXhwZWN0KGhlYWRlci5jdHkpLnRvQmVVbmRlZmluZWQoKTtcbiAgICAgICAgc2FtZVR5cGVkQXJyYXkoZGVjcnlwdGVkLCBtZXNzYWdlKTtcbiAgICAgIH0pO1xuICAgICAgaXQoJ2hhbmRsZXMgdGV4dCwgYW5kIGRlY3J5cHRzIGFzIHNhbWUuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICBsZXQgZW5jcnlwdGVkID0gYXdhaXQgbXVsdGlLcnlwdG8uZW5jcnlwdChlbmNyeXB0aW5nTXVsdGksIG1lc3NhZ2UpLFxuICAgICAgICAgICAgZGVjcnlwdGVkID0gYXdhaXQgbXVsdGlLcnlwdG8uZGVjcnlwdChkZWNyeXB0aW5nTXVsdGksIGVuY3J5cHRlZCksXG4gICAgICAgICAgICBoZWFkZXIgPSBtdWx0aUtyeXB0by5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIoZW5jcnlwdGVkKTtcbiAgICAgICAgZXhwZWN0KGhlYWRlci5jdHkpLnRvQmUoJ3RleHQvcGxhaW4nKTtcbiAgICAgICAgZXhwZWN0KGRlY3J5cHRlZC50ZXh0KS50b0JlKG1lc3NhZ2UpO1xuICAgICAgfSk7XG4gICAgICBpdCgnaGFuZGxlcyBqc29uLCBhbmQgZGVjcnlwdHMgYXMgc2FtZS4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGxldCBtZXNzYWdlID0ge2ZvbzogJ2Jhcid9LFxuICAgICAgICAgICAgZW5jcnlwdGVkID0gYXdhaXQgbXVsdGlLcnlwdG8uZW5jcnlwdChlbmNyeXB0aW5nTXVsdGksIG1lc3NhZ2UpO1xuICAgICAgICBsZXQgaGVhZGVyID0gbXVsdGlLcnlwdG8uZGVjb2RlUHJvdGVjdGVkSGVhZGVyKGVuY3J5cHRlZCksXG4gICAgICAgICAgICBkZWNyeXB0ZWQgPSBhd2FpdCBtdWx0aUtyeXB0by5kZWNyeXB0KGRlY3J5cHRpbmdNdWx0aSwgZW5jcnlwdGVkKTtcbiAgICAgICAgZXhwZWN0KGhlYWRlci5jdHkpLnRvQmUoJ2pzb24nKTtcbiAgICAgICAgZXhwZWN0KGRlY3J5cHRlZC5qc29uKS50b0VxdWFsKG1lc3NhZ2UpO1xuICAgICAgfSk7XG4gICAgICBpdCgnVXNlcyBzcGVjaWZpZWQgaGVhZGVycyBpZiBzdXBwbGllZCwgaW5jbHVkaW5nIGN0eS4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGxldCBjdHkgPSAndGV4dC9odG1sJyxcbiAgICAgICAgICAgIGlhdCA9IERhdGUubm93KCksXG4gICAgICAgICAgICBmb28gPSAxNyxcbiAgICAgICAgICAgIG1lc3NhZ2UgPSBcIjxzb21ldGhpbmcgZWxzZT5cIixcbiAgICAgICAgICAgIGVuY3J5cHRlZCA9IGF3YWl0IG11bHRpS3J5cHRvLmVuY3J5cHQoZW5jcnlwdGluZ011bHRpLCBtZXNzYWdlLCB7Y3R5LCBpYXQsIGZvb30pLFxuICAgICAgICAgICAgZGVjcnlwdGVkID0gYXdhaXQgbXVsdGlLcnlwdG8uZGVjcnlwdChkZWNyeXB0aW5nTXVsdGksIGVuY3J5cHRlZCksXG4gICAgICAgICAgICBoZWFkZXIgPSBtdWx0aUtyeXB0by5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIoZW5jcnlwdGVkKVxuICAgICAgICBleHBlY3QoaGVhZGVyLmN0eSkudG9CZShjdHkpO1xuICAgICAgICBleHBlY3QoaGVhZGVyLmlhdCkudG9CZShpYXQpO1xuICAgICAgICBleHBlY3QoaGVhZGVyLmZvbykudG9CZShmb28pO1xuICAgICAgICBleHBlY3QoZGVjcnlwdGVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgICB9KTtcblxuICAgICAgaXQoJ3Byb2R1Y2VzIHVuZGVmaW5lZCBmb3Igd3Jvbmcgc3ltbWV0cmljIGtleS4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGxldCBhbm90aGVyS2V5ID0gYXdhaXQgbXVsdGlLcnlwdG8uZ2VuZXJhdGVTeW1tZXRyaWNLZXkoKSxcbiAgICAgICAgICAgIGRlY3J5cHRlZCA9IGF3YWl0IG11bHRpS3J5cHRvLmRlY3J5cHQoe2E6IGFub3RoZXJLZXl9LCBlbmNyeXB0ZWQpO1xuICAgICAgICBleHBlY3QoZGVjcnlwdGVkKS50b0JlVW5kZWZpbmVkKCk7XG4gICAgICB9KTtcbiAgICAgIGl0KCdwcm9kdWNlcyB1bmRlZmluZWQgZm9yIHdyb25nIGtleXBhaXIuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICBsZXQgYW5vdGhlcktleSA9IGF3YWl0IG11bHRpS3J5cHRvLmdlbmVyYXRlRW5jcnlwdGluZ0tleSgpLFxuICAgICAgICAgICAgZGVjcnlwdGVkID0gYXdhaXQgbXVsdGlLcnlwdG8uZGVjcnlwdCh7YjogYW5vdGhlcktleS5wcml2YXRlS2V5fSwgZW5jcnlwdGVkKTtcbiAgICAgICAgZXhwZWN0KGRlY3J5cHRlZCkudG9CZVVuZGVmaW5lZCgpO1xuICAgICAgfSk7XG4gICAgICBpdCgncHJvZHVjZXMgdW5kZWZpbmVkIGZvciB3cm9uZyBzZWNyZXQgdGV4dC4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGxldCBkZWNyeXB0ZWQgPSBhd2FpdCBtdWx0aUtyeXB0by5kZWNyeXB0KHtjOiBcInNoaCEgXCJ9LCBlbmNyeXB0ZWQpOyAvLyBFeHRyYSB3aGl0ZXNwYWNlXG4gICAgICAgIGV4cGVjdChkZWNyeXB0ZWQpLnRvQmVVbmRlZmluZWQoKTtcbiAgICAgIH0pO1xuICAgICAgaXQoJ3Byb2R1Y2VzIHVuZGVmaW5lZCBmb3IgbWlzbGFiZWxlZCBrZXkuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICBsZXQgZGVjcnlwdGVkID0gYXdhaXQgbXVsdGlLcnlwdG8uZGVjcnlwdCh7YTogc2VjcmV0VGV4dH0sIGVuY3J5cHRlZCk7IC8vIHNob3VsZCBiZSBjXG4gICAgICAgIGV4cGVjdChkZWNyeXB0ZWQpLnRvQmVVbmRlZmluZWQoKTtcbiAgICAgIH0pO1xuICAgIH0pO1xuICB9KTtcblxuICBkZXNjcmliZSgnZXhwb3J0L3dyYXAnLCBmdW5jdGlvbiAoKSB7XG4gICAgbGV0IGVuY3J5cHRpbmdNdWx0aWtleSwgZGVjcnlwdGluZ011bHRpa2V5O1xuXG4gICAgYmVmb3JlQWxsKGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgIGxldCBrZXlwYWlyMSA9IGF3YWl0IG11bHRpS3J5cHRvLmdlbmVyYXRlRW5jcnlwdGluZ0tleSgpLFxuICAgICAgICAgIGtleXBhaXIyID0gYXdhaXQgbXVsdGlLcnlwdG8uZ2VuZXJhdGVFbmNyeXB0aW5nS2V5KCksXG4gICAgICAgICAga2V5cGFpcjMgPSBhd2FpdCBtdWx0aUtyeXB0by5nZW5lcmF0ZUVuY3J5cHRpbmdLZXkoKTtcbiAgICAgIGVuY3J5cHRpbmdNdWx0aWtleSA9IHthOiBrZXlwYWlyMS5wdWJsaWNLZXksIGI6IGtleXBhaXIyLnB1YmxpY0tleX07XG4gICAgICBkZWNyeXB0aW5nTXVsdGlrZXkgPSB7Yzoga2V5cGFpcjMucHJpdmF0ZUtleSwgYjoga2V5cGFpcjIucHJpdmF0ZUtleX07XG4gICAgfSwgc2xvd0tleUNyZWF0aW9uKTtcblxuICAgIGl0KCdleHBvcnRzIGhvbW9nZW5vdXMgbWVtYmVyLicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgIGxldCBleHBvcnRlZCA9IGF3YWl0IG11bHRpS3J5cHRvLmV4cG9ydEpXSyhlbmNyeXB0aW5nTXVsdGlrZXkpLFxuICAgICAgICAgIGltcG9ydGVkID0gYXdhaXQgbXVsdGlLcnlwdG8uaW1wb3J0SldLKGV4cG9ydGVkKSxcbiAgICAgICAgICAvLyBOb3cgcHJvdmUgdGhhdCB0aGUgaW1wb3J0ZWQgbXVsdGlrZXkgd29ya3MuXG4gICAgICAgICAgZW5jcnlwdGVkID0gYXdhaXQgbXVsdGlLcnlwdG8uZW5jcnlwdChpbXBvcnRlZCwgbWVzc2FnZSksXG4gICAgICAgICAgZGVjcnlwdGVkID0gYXdhaXQgbXVsdGlLcnlwdG8uZGVjcnlwdChkZWNyeXB0aW5nTXVsdGlrZXksIGVuY3J5cHRlZCk7XG4gICAgICBleHBlY3QoZXhwb3J0ZWQua2V5c1swXS5raWQpLnRvQmUoJ2EnKTtcbiAgICAgIGV4cGVjdChleHBvcnRlZC5rZXlzWzFdLmtpZCkudG9CZSgnYicpO1xuICAgICAgZXhwZWN0KGRlY3J5cHRlZC50ZXh0KS50b0JlKG1lc3NhZ2UpO1xuICAgIH0pO1xuICAgIGl0KCdleHBvcnQgaGV0ZXJvZ2Vub3VzIG1lbWJlcnMuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgbGV0IGVuY3J5cHRpbmdLZXlwYWlyID0gYXdhaXQgbXVsdGlLcnlwdG8uZ2VuZXJhdGVFbmNyeXB0aW5nS2V5KCksXG4gICAgICAgICAgc2lnbmluZ0tleXBhaXIgPSBhd2FpdCBtdWx0aUtyeXB0by5nZW5lcmF0ZVNpZ25pbmdLZXkoKSxcbiAgICAgICAgICBleHBvcnRlZCA9IGF3YWl0IG11bHRpS3J5cHRvLmV4cG9ydEpXSyh7bXlEZWNyeXB0OiBlbmNyeXB0aW5nS2V5cGFpci5wcml2YXRlS2V5LCBteVNpZ246IHNpZ25pbmdLZXlwYWlyLnByaXZhdGVLZXl9KSxcbiAgICAgICAgICBpbXBvcnRlZCA9IGF3YWl0IG11bHRpS3J5cHRvLmltcG9ydEpXSyhleHBvcnRlZCksXG4gICAgICAgICAgLy8gTm93IHByb3ZlIHRoYXQgdGhlIGltcG9ydGVkIG11bHRpa2V5IHdvcmtzLlxuICAgICAgICAgIG1lc3NhZ2UgID0gXCJhIHNtYWxsZXIgbWVzc2FnZSBmb3IgYXN5bW1ldHJpYyBlbmNyeXB0aW9uXCIsIC8vIEFsdGhvdWdoIEpPU0UgYWx3YXlzIHVzZXMgaHlicmlkIGVuY3J5cHRpb24gYW55d2F5LCBzbyBzaXplIGlzbid0IGEgcHJvYmxlbS5cbiAgICAgICAgICBlbmNyeXB0ZWQgPSBhd2FpdCBtdWx0aUtyeXB0by5lbmNyeXB0KGVuY3J5cHRpbmdLZXlwYWlyLnB1YmxpY0tleSwgbWVzc2FnZSksXG4gICAgICAgICAgZGVjcnlwdGVkID0gYXdhaXQgbXVsdGlLcnlwdG8uZGVjcnlwdChpbXBvcnRlZC5teURlY3J5cHQsIGVuY3J5cHRlZCksXG4gICAgICAgICAgc2lnbmVkID0gYXdhaXQgbXVsdGlLcnlwdG8uc2lnbihpbXBvcnRlZC5teVNpZ24sIG1lc3NhZ2UpO1xuICAgICAgZXhwZWN0KGV4cG9ydGVkLmtleXNbMF0ua2lkKS50b0JlKCdteURlY3J5cHQnKTtcbiAgICAgIGV4cGVjdChleHBvcnRlZC5rZXlzWzFdLmtpZCkudG9CZSgnbXlTaWduJyk7XG4gICAgICBleHBlY3QoZGVjcnlwdGVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgICBleHBlY3QoYXdhaXQgbXVsdGlLcnlwdG8udmVyaWZ5KHNpZ25pbmdLZXlwYWlyLnB1YmxpY0tleSwgc2lnbmVkKSkudG9CZVRydXRoeSgpO1xuICAgIH0sIDEwZTMpO1xuXG4gICAgaXQoJ2NhbiB3cmFwL3Vud3JhcCBhIHNpbXBsZSBrZXkuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgbGV0IGtleSA9IGF3YWl0IG11bHRpS3J5cHRvLmdlbmVyYXRlU3ltbWV0cmljS2V5KCksXG4gICAgICAgICAgd3JhcHBlZCA9IGF3YWl0IG11bHRpS3J5cHRvLndyYXBLZXkoa2V5LCBlbmNyeXB0aW5nTXVsdGlrZXkpLFxuICAgICAgICAgIHVud3JhcHBlZCA9IGF3YWl0IG11bHRpS3J5cHRvLnVud3JhcEtleSh3cmFwcGVkLCBkZWNyeXB0aW5nTXVsdGlrZXkpLFxuICAgICAgICAgIC8vIENvb2wsIG5vdyBwcm92ZSB0aGF0IHdvcmtlZC5cbiAgICAgICAgICBlbmNyeXB0ZWQgPSBhd2FpdCBtdWx0aUtyeXB0by5lbmNyeXB0KHVud3JhcHBlZCwgbWVzc2FnZSksXG4gICAgICAgICAgZGVjcnlwdGVkID0gYXdhaXQgbXVsdGlLcnlwdG8uZGVjcnlwdChrZXksIGVuY3J5cHRlZCk7XG4gICAgICBleHBlY3QoZGVjcnlwdGVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgfSk7XG4gICAgaXQoJ2NhbiBiZSB3cmFwcGVkL3Vud3JhcHBlZCBieSBhIHN5bW1ldHJpYyBrZXkgd2l0aCBob21vZ2Vub3VzIG1lbWJlcnMuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgbGV0IHdyYXBwaW5nS2V5ID0gYXdhaXQgbXVsdGlLcnlwdG8uZ2VuZXJhdGVTeW1tZXRyaWNLZXkoKSxcbiAgICAgICAgICB3cmFwcGVkID0gYXdhaXQgbXVsdGlLcnlwdG8ud3JhcEtleShlbmNyeXB0aW5nTXVsdGlrZXksIHdyYXBwaW5nS2V5KSxcbiAgICAgICAgICB1bndyYXBwZWQgPSBhd2FpdCBtdWx0aUtyeXB0by51bndyYXBLZXkod3JhcHBlZCwgd3JhcHBpbmdLZXkpLFxuICAgICAgICAgIC8vIENvb2wsIG5vdyBwcm92ZSB0aGF0IHdvcmtlZC5cbiAgICAgICAgICBlbmNyeXB0ZWQgPSBhd2FpdCBtdWx0aUtyeXB0by5lbmNyeXB0KHVud3JhcHBlZCwgbWVzc2FnZSksXG4gICAgICAgICAgZGVjcnlwdGVkID0gYXdhaXQgbXVsdGlLcnlwdG8uZGVjcnlwdChkZWNyeXB0aW5nTXVsdGlrZXksIGVuY3J5cHRlZCk7XG4gICAgICBleHBlY3QoZGVjcnlwdGVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgfSk7XG4gICAgaXQoJ2NhbiB3cmFwL3Vud3JhcCBhIHN5bW1ldHJpYyBtdWx0aWtleSB3aXRoIGhvbW9nZW5vdXMgbWVtYmVycy4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICBsZXQga2V5ID0ge3g6IGF3YWl0IG11bHRpS3J5cHRvLmdlbmVyYXRlU3ltbWV0cmljS2V5KCksIHk6IGF3YWl0IG11bHRpS3J5cHRvLmdlbmVyYXRlU3ltbWV0cmljS2V5KCl9LFxuICAgICAgICAgIHdyYXBwZWQgPSBhd2FpdCBtdWx0aUtyeXB0by53cmFwS2V5KGtleSwgZW5jcnlwdGluZ011bHRpa2V5KSxcbiAgICAgICAgICB1bndyYXBwZWQgPSBhd2FpdCBtdWx0aUtyeXB0by51bndyYXBLZXkod3JhcHBlZCwgZGVjcnlwdGluZ011bHRpa2V5KSxcbiAgICAgICAgICAvLyBDb29sLCBub3cgcHJvdmUgdGhhdCB3b3JrZWQuXG4gICAgICAgICAgbWVzc2FnZSA9IG1ha2VNZXNzYWdlKCksXG4gICAgICAgICAgZW5jcnlwdGVkID0gYXdhaXQgbXVsdGlLcnlwdG8uZW5jcnlwdCh1bndyYXBwZWQsIG1lc3NhZ2UpLFxuICAgICAgICAgIGRlY3J5cHRlZCA9IGF3YWl0IG11bHRpS3J5cHRvLmRlY3J5cHQoa2V5LCBlbmNyeXB0ZWQpO1xuICAgICAgZXhwZWN0KGRlY3J5cHRlZC50ZXh0KS50b0JlKG1lc3NhZ2UpO1xuICAgIH0pO1xuICAgIGl0KCdjYW4gd3JhcC91bndyYXAgYSBoZXRlcm9nZW5lb3VzIG11bHRpa2V5LicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgIGxldCBlbmNyeXB0aW5nS2V5cGFpciA9IGF3YWl0IG11bHRpS3J5cHRvLmdlbmVyYXRlRW5jcnlwdGluZ0tleSgpLFxuICAgICAgICAgIHNpZ25pbmdLZXlwYWlyID0gYXdhaXQgbXVsdGlLcnlwdG8uZ2VuZXJhdGVTaWduaW5nS2V5KCksXG4gICAgICAgICAgd3JhcHBlZCA9IGF3YWl0IG11bHRpS3J5cHRvLndyYXBLZXkoe215RGVjcnlwdDogZW5jcnlwdGluZ0tleXBhaXIucHJpdmF0ZUtleSwgbXlTaWduOiBzaWduaW5nS2V5cGFpci5wcml2YXRlS2V5fSwgZW5jcnlwdGluZ011bHRpa2V5KSxcbiAgICAgICAgICB1bndyYXBwZWQgPSBhd2FpdCBtdWx0aUtyeXB0by51bndyYXBLZXkod3JhcHBlZCwgZGVjcnlwdGluZ011bHRpa2V5KSxcbiAgICAgICAgICAvLyBDb29sLCBub3cgcHJvdmUgdGhhdCB3b3JrZWQuXG4gICAgICAgICAgbWVzc2FnZSA9IFwiYSBzaG9ydGVyIG1lc3NhZ2VcIixcbiAgICAgICAgICBlbmNyeXB0ZWQgPSBhd2FpdCBtdWx0aUtyeXB0by5lbmNyeXB0KGVuY3J5cHRpbmdLZXlwYWlyLnB1YmxpY0tleSwgbWVzc2FnZSksXG4gICAgICAgICAgZGVjcnlwdGVkID0gYXdhaXQgbXVsdGlLcnlwdG8uZGVjcnlwdCh1bndyYXBwZWQubXlEZWNyeXB0LCBlbmNyeXB0ZWQpLFxuICAgICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IG11bHRpS3J5cHRvLnNpZ24odW53cmFwcGVkLm15U2lnbiwgbWVzc2FnZSk7XG4gICAgICBleHBlY3QoZGVjcnlwdGVkLnRleHQpLnRvQmUobWVzc2FnZSksXG4gICAgICBleHBlY3QoYXdhaXQgbXVsdGlLcnlwdG8udmVyaWZ5KHNpZ25pbmdLZXlwYWlyLnB1YmxpY0tleSwgc2lnbmF0dXJlKSkudG9CZVRydXRoeSgpO1xuICAgIH0sIHNsb3dLZXlDcmVhdGlvbik7XG4gIH0pO1xufVxuIiwiZXhwb3J0IGRlZmF1bHQgY3J5cHRvO1xuZXhwb3J0IGNvbnN0IGlzQ3J5cHRvS2V5ID0gKGtleSkgPT4ga2V5IGluc3RhbmNlb2YgQ3J5cHRvS2V5O1xuIiwiaW1wb3J0IGNyeXB0byBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5jb25zdCBkaWdlc3QgPSBhc3luYyAoYWxnb3JpdGhtLCBkYXRhKSA9PiB7XG4gICAgY29uc3Qgc3VidGxlRGlnZXN0ID0gYFNIQS0ke2FsZ29yaXRobS5zbGljZSgtMyl9YDtcbiAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5kaWdlc3Qoc3VidGxlRGlnZXN0LCBkYXRhKSk7XG59O1xuZXhwb3J0IGRlZmF1bHQgZGlnZXN0O1xuIiwiaW1wb3J0IGRpZ2VzdCBmcm9tICcuLi9ydW50aW1lL2RpZ2VzdC5qcyc7XG5leHBvcnQgY29uc3QgZW5jb2RlciA9IG5ldyBUZXh0RW5jb2RlcigpO1xuZXhwb3J0IGNvbnN0IGRlY29kZXIgPSBuZXcgVGV4dERlY29kZXIoKTtcbmNvbnN0IE1BWF9JTlQzMiA9IDIgKiogMzI7XG5leHBvcnQgZnVuY3Rpb24gY29uY2F0KC4uLmJ1ZmZlcnMpIHtcbiAgICBjb25zdCBzaXplID0gYnVmZmVycy5yZWR1Y2UoKGFjYywgeyBsZW5ndGggfSkgPT4gYWNjICsgbGVuZ3RoLCAwKTtcbiAgICBjb25zdCBidWYgPSBuZXcgVWludDhBcnJheShzaXplKTtcbiAgICBsZXQgaSA9IDA7XG4gICAgZm9yIChjb25zdCBidWZmZXIgb2YgYnVmZmVycykge1xuICAgICAgICBidWYuc2V0KGJ1ZmZlciwgaSk7XG4gICAgICAgIGkgKz0gYnVmZmVyLmxlbmd0aDtcbiAgICB9XG4gICAgcmV0dXJuIGJ1Zjtcbn1cbmV4cG9ydCBmdW5jdGlvbiBwMnMoYWxnLCBwMnNJbnB1dCkge1xuICAgIHJldHVybiBjb25jYXQoZW5jb2Rlci5lbmNvZGUoYWxnKSwgbmV3IFVpbnQ4QXJyYXkoWzBdKSwgcDJzSW5wdXQpO1xufVxuZnVuY3Rpb24gd3JpdGVVSW50MzJCRShidWYsIHZhbHVlLCBvZmZzZXQpIHtcbiAgICBpZiAodmFsdWUgPCAwIHx8IHZhbHVlID49IE1BWF9JTlQzMikge1xuICAgICAgICB0aHJvdyBuZXcgUmFuZ2VFcnJvcihgdmFsdWUgbXVzdCBiZSA+PSAwIGFuZCA8PSAke01BWF9JTlQzMiAtIDF9LiBSZWNlaXZlZCAke3ZhbHVlfWApO1xuICAgIH1cbiAgICBidWYuc2V0KFt2YWx1ZSA+Pj4gMjQsIHZhbHVlID4+PiAxNiwgdmFsdWUgPj4+IDgsIHZhbHVlICYgMHhmZl0sIG9mZnNldCk7XG59XG5leHBvcnQgZnVuY3Rpb24gdWludDY0YmUodmFsdWUpIHtcbiAgICBjb25zdCBoaWdoID0gTWF0aC5mbG9vcih2YWx1ZSAvIE1BWF9JTlQzMik7XG4gICAgY29uc3QgbG93ID0gdmFsdWUgJSBNQVhfSU5UMzI7XG4gICAgY29uc3QgYnVmID0gbmV3IFVpbnQ4QXJyYXkoOCk7XG4gICAgd3JpdGVVSW50MzJCRShidWYsIGhpZ2gsIDApO1xuICAgIHdyaXRlVUludDMyQkUoYnVmLCBsb3csIDQpO1xuICAgIHJldHVybiBidWY7XG59XG5leHBvcnQgZnVuY3Rpb24gdWludDMyYmUodmFsdWUpIHtcbiAgICBjb25zdCBidWYgPSBuZXcgVWludDhBcnJheSg0KTtcbiAgICB3cml0ZVVJbnQzMkJFKGJ1ZiwgdmFsdWUpO1xuICAgIHJldHVybiBidWY7XG59XG5leHBvcnQgZnVuY3Rpb24gbGVuZ3RoQW5kSW5wdXQoaW5wdXQpIHtcbiAgICByZXR1cm4gY29uY2F0KHVpbnQzMmJlKGlucHV0Lmxlbmd0aCksIGlucHV0KTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjb25jYXRLZGYoc2VjcmV0LCBiaXRzLCB2YWx1ZSkge1xuICAgIGNvbnN0IGl0ZXJhdGlvbnMgPSBNYXRoLmNlaWwoKGJpdHMgPj4gMykgLyAzMik7XG4gICAgY29uc3QgcmVzID0gbmV3IFVpbnQ4QXJyYXkoaXRlcmF0aW9ucyAqIDMyKTtcbiAgICBmb3IgKGxldCBpdGVyID0gMDsgaXRlciA8IGl0ZXJhdGlvbnM7IGl0ZXIrKykge1xuICAgICAgICBjb25zdCBidWYgPSBuZXcgVWludDhBcnJheSg0ICsgc2VjcmV0Lmxlbmd0aCArIHZhbHVlLmxlbmd0aCk7XG4gICAgICAgIGJ1Zi5zZXQodWludDMyYmUoaXRlciArIDEpKTtcbiAgICAgICAgYnVmLnNldChzZWNyZXQsIDQpO1xuICAgICAgICBidWYuc2V0KHZhbHVlLCA0ICsgc2VjcmV0Lmxlbmd0aCk7XG4gICAgICAgIHJlcy5zZXQoYXdhaXQgZGlnZXN0KCdzaGEyNTYnLCBidWYpLCBpdGVyICogMzIpO1xuICAgIH1cbiAgICByZXR1cm4gcmVzLnNsaWNlKDAsIGJpdHMgPj4gMyk7XG59XG4iLCJpbXBvcnQgeyBlbmNvZGVyLCBkZWNvZGVyIH0gZnJvbSAnLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5leHBvcnQgY29uc3QgZW5jb2RlQmFzZTY0ID0gKGlucHV0KSA9PiB7XG4gICAgbGV0IHVuZW5jb2RlZCA9IGlucHV0O1xuICAgIGlmICh0eXBlb2YgdW5lbmNvZGVkID09PSAnc3RyaW5nJykge1xuICAgICAgICB1bmVuY29kZWQgPSBlbmNvZGVyLmVuY29kZSh1bmVuY29kZWQpO1xuICAgIH1cbiAgICBjb25zdCBDSFVOS19TSVpFID0gMHg4MDAwO1xuICAgIGNvbnN0IGFyciA9IFtdO1xuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgdW5lbmNvZGVkLmxlbmd0aDsgaSArPSBDSFVOS19TSVpFKSB7XG4gICAgICAgIGFyci5wdXNoKFN0cmluZy5mcm9tQ2hhckNvZGUuYXBwbHkobnVsbCwgdW5lbmNvZGVkLnN1YmFycmF5KGksIGkgKyBDSFVOS19TSVpFKSkpO1xuICAgIH1cbiAgICByZXR1cm4gYnRvYShhcnIuam9pbignJykpO1xufTtcbmV4cG9ydCBjb25zdCBlbmNvZGUgPSAoaW5wdXQpID0+IHtcbiAgICByZXR1cm4gZW5jb2RlQmFzZTY0KGlucHV0KS5yZXBsYWNlKC89L2csICcnKS5yZXBsYWNlKC9cXCsvZywgJy0nKS5yZXBsYWNlKC9cXC8vZywgJ18nKTtcbn07XG5leHBvcnQgY29uc3QgZGVjb2RlQmFzZTY0ID0gKGVuY29kZWQpID0+IHtcbiAgICBjb25zdCBiaW5hcnkgPSBhdG9iKGVuY29kZWQpO1xuICAgIGNvbnN0IGJ5dGVzID0gbmV3IFVpbnQ4QXJyYXkoYmluYXJ5Lmxlbmd0aCk7XG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBiaW5hcnkubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgYnl0ZXNbaV0gPSBiaW5hcnkuY2hhckNvZGVBdChpKTtcbiAgICB9XG4gICAgcmV0dXJuIGJ5dGVzO1xufTtcbmV4cG9ydCBjb25zdCBkZWNvZGUgPSAoaW5wdXQpID0+IHtcbiAgICBsZXQgZW5jb2RlZCA9IGlucHV0O1xuICAgIGlmIChlbmNvZGVkIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICBlbmNvZGVkID0gZGVjb2Rlci5kZWNvZGUoZW5jb2RlZCk7XG4gICAgfVxuICAgIGVuY29kZWQgPSBlbmNvZGVkLnJlcGxhY2UoLy0vZywgJysnKS5yZXBsYWNlKC9fL2csICcvJykucmVwbGFjZSgvXFxzL2csICcnKTtcbiAgICB0cnkge1xuICAgICAgICByZXR1cm4gZGVjb2RlQmFzZTY0KGVuY29kZWQpO1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1RoZSBpbnB1dCB0byBiZSBkZWNvZGVkIGlzIG5vdCBjb3JyZWN0bHkgZW5jb2RlZC4nKTtcbiAgICB9XG59O1xuIiwiZXhwb3J0IGNsYXNzIEpPU0VFcnJvciBleHRlbmRzIEVycm9yIHtcbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pPU0VfR0VORVJJQyc7XG4gICAgfVxuICAgIGNvbnN0cnVjdG9yKG1lc3NhZ2UpIHtcbiAgICAgICAgc3VwZXIobWVzc2FnZSk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSk9TRV9HRU5FUklDJztcbiAgICAgICAgdGhpcy5uYW1lID0gdGhpcy5jb25zdHJ1Y3Rvci5uYW1lO1xuICAgICAgICBFcnJvci5jYXB0dXJlU3RhY2tUcmFjZT8uKHRoaXMsIHRoaXMuY29uc3RydWN0b3IpO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV1RDbGFpbVZhbGlkYXRpb25GYWlsZWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldUX0NMQUlNX1ZBTElEQVRJT05fRkFJTEVEJztcbiAgICB9XG4gICAgY29uc3RydWN0b3IobWVzc2FnZSwgY2xhaW0gPSAndW5zcGVjaWZpZWQnLCByZWFzb24gPSAndW5zcGVjaWZpZWQnKSB7XG4gICAgICAgIHN1cGVyKG1lc3NhZ2UpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXVF9DTEFJTV9WQUxJREFUSU9OX0ZBSUxFRCc7XG4gICAgICAgIHRoaXMuY2xhaW0gPSBjbGFpbTtcbiAgICAgICAgdGhpcy5yZWFzb24gPSByZWFzb247XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXVEV4cGlyZWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldUX0VYUElSRUQnO1xuICAgIH1cbiAgICBjb25zdHJ1Y3RvcihtZXNzYWdlLCBjbGFpbSA9ICd1bnNwZWNpZmllZCcsIHJlYXNvbiA9ICd1bnNwZWNpZmllZCcpIHtcbiAgICAgICAgc3VwZXIobWVzc2FnZSk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldUX0VYUElSRUQnO1xuICAgICAgICB0aGlzLmNsYWltID0gY2xhaW07XG4gICAgICAgIHRoaXMucmVhc29uID0gcmVhc29uO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKT1NFQWxnTm90QWxsb3dlZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSk9TRV9BTEdfTk9UX0FMTE9XRUQnO1xuICAgIH1cbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pPU0VfQUxHX05PVF9BTExPV0VEJztcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgSk9TRU5vdFN1cHBvcnRlZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSk9TRV9OT1RfU1VQUE9SVEVEJztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KT1NFX05PVF9TVVBQT1JURUQnO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV0VEZWNyeXB0aW9uRmFpbGVkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0VfREVDUllQVElPTl9GQUlMRUQnO1xuICAgICAgICB0aGlzLm1lc3NhZ2UgPSAnZGVjcnlwdGlvbiBvcGVyYXRpb24gZmFpbGVkJztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV0VfREVDUllQVElPTl9GQUlMRUQnO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV0VJbnZhbGlkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0VfSU5WQUxJRCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldFX0lOVkFMSUQnO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV1NJbnZhbGlkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV1NfSU5WQUxJRCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldTX0lOVkFMSUQnO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV1RJbnZhbGlkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV1RfSU5WQUxJRCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldUX0lOVkFMSUQnO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV0tJbnZhbGlkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0tfSU5WQUxJRCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldLX0lOVkFMSUQnO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV0tTSW52YWxpZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldLU19JTlZBTElEJztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV0tTX0lOVkFMSUQnO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV0tTTm9NYXRjaGluZ0tleSBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldLU19OT19NQVRDSElOR19LRVknO1xuICAgICAgICB0aGlzLm1lc3NhZ2UgPSAnbm8gYXBwbGljYWJsZSBrZXkgZm91bmQgaW4gdGhlIEpTT04gV2ViIEtleSBTZXQnO1xuICAgIH1cbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pXS1NfTk9fTUFUQ0hJTkdfS0VZJztcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgSldLU011bHRpcGxlTWF0Y2hpbmdLZXlzIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0tTX01VTFRJUExFX01BVENISU5HX0tFWVMnO1xuICAgICAgICB0aGlzLm1lc3NhZ2UgPSAnbXVsdGlwbGUgbWF0Y2hpbmcga2V5cyBmb3VuZCBpbiB0aGUgSlNPTiBXZWIgS2V5IFNldCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldLU19NVUxUSVBMRV9NQVRDSElOR19LRVlTJztcbiAgICB9XG59XG5TeW1ib2wuYXN5bmNJdGVyYXRvcjtcbmV4cG9ydCBjbGFzcyBKV0tTVGltZW91dCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldLU19USU1FT1VUJztcbiAgICAgICAgdGhpcy5tZXNzYWdlID0gJ3JlcXVlc3QgdGltZWQgb3V0JztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV0tTX1RJTUVPVVQnO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV1NTaWduYXR1cmVWZXJpZmljYXRpb25GYWlsZWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXU19TSUdOQVRVUkVfVkVSSUZJQ0FUSU9OX0ZBSUxFRCc7XG4gICAgICAgIHRoaXMubWVzc2FnZSA9ICdzaWduYXR1cmUgdmVyaWZpY2F0aW9uIGZhaWxlZCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldTX1NJR05BVFVSRV9WRVJJRklDQVRJT05fRkFJTEVEJztcbiAgICB9XG59XG4iLCJpbXBvcnQgY3J5cHRvIGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmV4cG9ydCBkZWZhdWx0IGNyeXB0by5nZXRSYW5kb21WYWx1ZXMuYmluZChjcnlwdG8pO1xuIiwiaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCByYW5kb20gZnJvbSAnLi4vcnVudGltZS9yYW5kb20uanMnO1xuZXhwb3J0IGZ1bmN0aW9uIGJpdExlbmd0aChhbGcpIHtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdBMTI4R0NNJzpcbiAgICAgICAgY2FzZSAnQTEyOEdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTE5MkdDTSc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ00nOlxuICAgICAgICBjYXNlICdBMjU2R0NNS1cnOlxuICAgICAgICAgICAgcmV0dXJuIDk2O1xuICAgICAgICBjYXNlICdBMTI4Q0JDLUhTMjU2JzpcbiAgICAgICAgY2FzZSAnQTE5MkNCQy1IUzM4NCc6XG4gICAgICAgIGNhc2UgJ0EyNTZDQkMtSFM1MTInOlxuICAgICAgICAgICAgcmV0dXJuIDEyODtcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKGBVbnN1cHBvcnRlZCBKV0UgQWxnb3JpdGhtOiAke2FsZ31gKTtcbiAgICB9XG59XG5leHBvcnQgZGVmYXVsdCAoYWxnKSA9PiByYW5kb20obmV3IFVpbnQ4QXJyYXkoYml0TGVuZ3RoKGFsZykgPj4gMykpO1xuIiwiaW1wb3J0IHsgSldFSW52YWxpZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IGJpdExlbmd0aCB9IGZyb20gJy4vaXYuanMnO1xuY29uc3QgY2hlY2tJdkxlbmd0aCA9IChlbmMsIGl2KSA9PiB7XG4gICAgaWYgKGl2Lmxlbmd0aCA8PCAzICE9PSBiaXRMZW5ndGgoZW5jKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSW52YWxpZCBJbml0aWFsaXphdGlvbiBWZWN0b3IgbGVuZ3RoJyk7XG4gICAgfVxufTtcbmV4cG9ydCBkZWZhdWx0IGNoZWNrSXZMZW5ndGg7XG4iLCJpbXBvcnQgeyBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuY29uc3QgY2hlY2tDZWtMZW5ndGggPSAoY2VrLCBleHBlY3RlZCkgPT4ge1xuICAgIGNvbnN0IGFjdHVhbCA9IGNlay5ieXRlTGVuZ3RoIDw8IDM7XG4gICAgaWYgKGFjdHVhbCAhPT0gZXhwZWN0ZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEludmFsaWQgQ29udGVudCBFbmNyeXB0aW9uIEtleSBsZW5ndGguIEV4cGVjdGVkICR7ZXhwZWN0ZWR9IGJpdHMsIGdvdCAke2FjdHVhbH0gYml0c2ApO1xuICAgIH1cbn07XG5leHBvcnQgZGVmYXVsdCBjaGVja0Nla0xlbmd0aDtcbiIsImNvbnN0IHRpbWluZ1NhZmVFcXVhbCA9IChhLCBiKSA9PiB7XG4gICAgaWYgKCEoYSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0ZpcnN0IGFyZ3VtZW50IG11c3QgYmUgYSBidWZmZXInKTtcbiAgICB9XG4gICAgaWYgKCEoYiBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1NlY29uZCBhcmd1bWVudCBtdXN0IGJlIGEgYnVmZmVyJyk7XG4gICAgfVxuICAgIGlmIChhLmxlbmd0aCAhPT0gYi5sZW5ndGgpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignSW5wdXQgYnVmZmVycyBtdXN0IGhhdmUgdGhlIHNhbWUgbGVuZ3RoJyk7XG4gICAgfVxuICAgIGNvbnN0IGxlbiA9IGEubGVuZ3RoO1xuICAgIGxldCBvdXQgPSAwO1xuICAgIGxldCBpID0gLTE7XG4gICAgd2hpbGUgKCsraSA8IGxlbikge1xuICAgICAgICBvdXQgfD0gYVtpXSBeIGJbaV07XG4gICAgfVxuICAgIHJldHVybiBvdXQgPT09IDA7XG59O1xuZXhwb3J0IGRlZmF1bHQgdGltaW5nU2FmZUVxdWFsO1xuIiwiZnVuY3Rpb24gdW51c2FibGUobmFtZSwgcHJvcCA9ICdhbGdvcml0aG0ubmFtZScpIHtcbiAgICByZXR1cm4gbmV3IFR5cGVFcnJvcihgQ3J5cHRvS2V5IGRvZXMgbm90IHN1cHBvcnQgdGhpcyBvcGVyYXRpb24sIGl0cyAke3Byb3B9IG11c3QgYmUgJHtuYW1lfWApO1xufVxuZnVuY3Rpb24gaXNBbGdvcml0aG0oYWxnb3JpdGhtLCBuYW1lKSB7XG4gICAgcmV0dXJuIGFsZ29yaXRobS5uYW1lID09PSBuYW1lO1xufVxuZnVuY3Rpb24gZ2V0SGFzaExlbmd0aChoYXNoKSB7XG4gICAgcmV0dXJuIHBhcnNlSW50KGhhc2gubmFtZS5zbGljZSg0KSwgMTApO1xufVxuZnVuY3Rpb24gZ2V0TmFtZWRDdXJ2ZShhbGcpIHtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdFUzI1Nic6XG4gICAgICAgICAgICByZXR1cm4gJ1AtMjU2JztcbiAgICAgICAgY2FzZSAnRVMzODQnOlxuICAgICAgICAgICAgcmV0dXJuICdQLTM4NCc7XG4gICAgICAgIGNhc2UgJ0VTNTEyJzpcbiAgICAgICAgICAgIHJldHVybiAnUC01MjEnO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCd1bnJlYWNoYWJsZScpO1xuICAgIH1cbn1cbmZ1bmN0aW9uIGNoZWNrVXNhZ2Uoa2V5LCB1c2FnZXMpIHtcbiAgICBpZiAodXNhZ2VzLmxlbmd0aCAmJiAhdXNhZ2VzLnNvbWUoKGV4cGVjdGVkKSA9PiBrZXkudXNhZ2VzLmluY2x1ZGVzKGV4cGVjdGVkKSkpIHtcbiAgICAgICAgbGV0IG1zZyA9ICdDcnlwdG9LZXkgZG9lcyBub3Qgc3VwcG9ydCB0aGlzIG9wZXJhdGlvbiwgaXRzIHVzYWdlcyBtdXN0IGluY2x1ZGUgJztcbiAgICAgICAgaWYgKHVzYWdlcy5sZW5ndGggPiAyKSB7XG4gICAgICAgICAgICBjb25zdCBsYXN0ID0gdXNhZ2VzLnBvcCgpO1xuICAgICAgICAgICAgbXNnICs9IGBvbmUgb2YgJHt1c2FnZXMuam9pbignLCAnKX0sIG9yICR7bGFzdH0uYDtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICh1c2FnZXMubGVuZ3RoID09PSAyKSB7XG4gICAgICAgICAgICBtc2cgKz0gYG9uZSBvZiAke3VzYWdlc1swXX0gb3IgJHt1c2FnZXNbMV19LmA7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBtc2cgKz0gYCR7dXNhZ2VzWzBdfS5gO1xuICAgICAgICB9XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IobXNnKTtcbiAgICB9XG59XG5leHBvcnQgZnVuY3Rpb24gY2hlY2tTaWdDcnlwdG9LZXkoa2V5LCBhbGcsIC4uLnVzYWdlcykge1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ0hTMjU2JzpcbiAgICAgICAgY2FzZSAnSFMzODQnOlxuICAgICAgICBjYXNlICdIUzUxMic6IHtcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ0hNQUMnKSlcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnSE1BQycpO1xuICAgICAgICAgICAgY29uc3QgZXhwZWN0ZWQgPSBwYXJzZUludChhbGcuc2xpY2UoMiksIDEwKTtcbiAgICAgICAgICAgIGNvbnN0IGFjdHVhbCA9IGdldEhhc2hMZW5ndGgoa2V5LmFsZ29yaXRobS5oYXNoKTtcbiAgICAgICAgICAgIGlmIChhY3R1YWwgIT09IGV4cGVjdGVkKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKGBTSEEtJHtleHBlY3RlZH1gLCAnYWxnb3JpdGhtLmhhc2gnKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ1JTMjU2JzpcbiAgICAgICAgY2FzZSAnUlMzODQnOlxuICAgICAgICBjYXNlICdSUzUxMic6IHtcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ1JTQVNTQS1QS0NTMS12MV81JykpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ1JTQVNTQS1QS0NTMS12MV81Jyk7XG4gICAgICAgICAgICBjb25zdCBleHBlY3RlZCA9IHBhcnNlSW50KGFsZy5zbGljZSgyKSwgMTApO1xuICAgICAgICAgICAgY29uc3QgYWN0dWFsID0gZ2V0SGFzaExlbmd0aChrZXkuYWxnb3JpdGhtLmhhc2gpO1xuICAgICAgICAgICAgaWYgKGFjdHVhbCAhPT0gZXhwZWN0ZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoYFNIQS0ke2V4cGVjdGVkfWAsICdhbGdvcml0aG0uaGFzaCcpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnUFMyNTYnOlxuICAgICAgICBjYXNlICdQUzM4NCc6XG4gICAgICAgIGNhc2UgJ1BTNTEyJzoge1xuICAgICAgICAgICAgaWYgKCFpc0FsZ29yaXRobShrZXkuYWxnb3JpdGhtLCAnUlNBLVBTUycpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdSU0EtUFNTJyk7XG4gICAgICAgICAgICBjb25zdCBleHBlY3RlZCA9IHBhcnNlSW50KGFsZy5zbGljZSgyKSwgMTApO1xuICAgICAgICAgICAgY29uc3QgYWN0dWFsID0gZ2V0SGFzaExlbmd0aChrZXkuYWxnb3JpdGhtLmhhc2gpO1xuICAgICAgICAgICAgaWYgKGFjdHVhbCAhPT0gZXhwZWN0ZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoYFNIQS0ke2V4cGVjdGVkfWAsICdhbGdvcml0aG0uaGFzaCcpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnRWREU0EnOiB7XG4gICAgICAgICAgICBpZiAoa2V5LmFsZ29yaXRobS5uYW1lICE9PSAnRWQyNTUxOScgJiYga2V5LmFsZ29yaXRobS5uYW1lICE9PSAnRWQ0NDgnKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ0VkMjU1MTkgb3IgRWQ0NDgnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0VTMjU2JzpcbiAgICAgICAgY2FzZSAnRVMzODQnOlxuICAgICAgICBjYXNlICdFUzUxMic6IHtcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ0VDRFNBJykpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ0VDRFNBJyk7XG4gICAgICAgICAgICBjb25zdCBleHBlY3RlZCA9IGdldE5hbWVkQ3VydmUoYWxnKTtcbiAgICAgICAgICAgIGNvbnN0IGFjdHVhbCA9IGtleS5hbGdvcml0aG0ubmFtZWRDdXJ2ZTtcbiAgICAgICAgICAgIGlmIChhY3R1YWwgIT09IGV4cGVjdGVkKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKGV4cGVjdGVkLCAnYWxnb3JpdGhtLm5hbWVkQ3VydmUnKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdDcnlwdG9LZXkgZG9lcyBub3Qgc3VwcG9ydCB0aGlzIG9wZXJhdGlvbicpO1xuICAgIH1cbiAgICBjaGVja1VzYWdlKGtleSwgdXNhZ2VzKTtcbn1cbmV4cG9ydCBmdW5jdGlvbiBjaGVja0VuY0NyeXB0b0tleShrZXksIGFsZywgLi4udXNhZ2VzKSB7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnQTEyOEdDTSc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ00nOlxuICAgICAgICBjYXNlICdBMjU2R0NNJzoge1xuICAgICAgICAgICAgaWYgKCFpc0FsZ29yaXRobShrZXkuYWxnb3JpdGhtLCAnQUVTLUdDTScpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdBRVMtR0NNJyk7XG4gICAgICAgICAgICBjb25zdCBleHBlY3RlZCA9IHBhcnNlSW50KGFsZy5zbGljZSgxLCA0KSwgMTApO1xuICAgICAgICAgICAgY29uc3QgYWN0dWFsID0ga2V5LmFsZ29yaXRobS5sZW5ndGg7XG4gICAgICAgICAgICBpZiAoYWN0dWFsICE9PSBleHBlY3RlZClcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZShleHBlY3RlZCwgJ2FsZ29yaXRobS5sZW5ndGgnKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ0FFUy1LVycpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdBRVMtS1cnKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGVjdGVkID0gcGFyc2VJbnQoYWxnLnNsaWNlKDEsIDQpLCAxMCk7XG4gICAgICAgICAgICBjb25zdCBhY3R1YWwgPSBrZXkuYWxnb3JpdGhtLmxlbmd0aDtcbiAgICAgICAgICAgIGlmIChhY3R1YWwgIT09IGV4cGVjdGVkKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKGV4cGVjdGVkLCAnYWxnb3JpdGhtLmxlbmd0aCcpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnRUNESCc6IHtcbiAgICAgICAgICAgIHN3aXRjaCAoa2V5LmFsZ29yaXRobS5uYW1lKSB7XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESCc6XG4gICAgICAgICAgICAgICAgY2FzZSAnWDI1NTE5JzpcbiAgICAgICAgICAgICAgICBjYXNlICdYNDQ4JzpcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ0VDREgsIFgyNTUxOSwgb3IgWDQ0OCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnUEJFUzItSFMyNTYrQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnUEJFUzItSFMzODQrQTE5MktXJzpcbiAgICAgICAgY2FzZSAnUEJFUzItSFM1MTIrQTI1NktXJzpcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ1BCS0RGMicpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdQQktERjInKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdSU0EtT0FFUCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTI1Nic6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTM4NCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTUxMic6IHtcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ1JTQS1PQUVQJykpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ1JTQS1PQUVQJyk7XG4gICAgICAgICAgICBjb25zdCBleHBlY3RlZCA9IHBhcnNlSW50KGFsZy5zbGljZSg5KSwgMTApIHx8IDE7XG4gICAgICAgICAgICBjb25zdCBhY3R1YWwgPSBnZXRIYXNoTGVuZ3RoKGtleS5hbGdvcml0aG0uaGFzaCk7XG4gICAgICAgICAgICBpZiAoYWN0dWFsICE9PSBleHBlY3RlZClcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZShgU0hBLSR7ZXhwZWN0ZWR9YCwgJ2FsZ29yaXRobS5oYXNoJyk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignQ3J5cHRvS2V5IGRvZXMgbm90IHN1cHBvcnQgdGhpcyBvcGVyYXRpb24nKTtcbiAgICB9XG4gICAgY2hlY2tVc2FnZShrZXksIHVzYWdlcyk7XG59XG4iLCJmdW5jdGlvbiBtZXNzYWdlKG1zZywgYWN0dWFsLCAuLi50eXBlcykge1xuICAgIGlmICh0eXBlcy5sZW5ndGggPiAyKSB7XG4gICAgICAgIGNvbnN0IGxhc3QgPSB0eXBlcy5wb3AoKTtcbiAgICAgICAgbXNnICs9IGBvbmUgb2YgdHlwZSAke3R5cGVzLmpvaW4oJywgJyl9LCBvciAke2xhc3R9LmA7XG4gICAgfVxuICAgIGVsc2UgaWYgKHR5cGVzLmxlbmd0aCA9PT0gMikge1xuICAgICAgICBtc2cgKz0gYG9uZSBvZiB0eXBlICR7dHlwZXNbMF19IG9yICR7dHlwZXNbMV19LmA7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBtc2cgKz0gYG9mIHR5cGUgJHt0eXBlc1swXX0uYDtcbiAgICB9XG4gICAgaWYgKGFjdHVhbCA9PSBudWxsKSB7XG4gICAgICAgIG1zZyArPSBgIFJlY2VpdmVkICR7YWN0dWFsfWA7XG4gICAgfVxuICAgIGVsc2UgaWYgKHR5cGVvZiBhY3R1YWwgPT09ICdmdW5jdGlvbicgJiYgYWN0dWFsLm5hbWUpIHtcbiAgICAgICAgbXNnICs9IGAgUmVjZWl2ZWQgZnVuY3Rpb24gJHthY3R1YWwubmFtZX1gO1xuICAgIH1cbiAgICBlbHNlIGlmICh0eXBlb2YgYWN0dWFsID09PSAnb2JqZWN0JyAmJiBhY3R1YWwgIT0gbnVsbCkge1xuICAgICAgICBpZiAoYWN0dWFsLmNvbnN0cnVjdG9yPy5uYW1lKSB7XG4gICAgICAgICAgICBtc2cgKz0gYCBSZWNlaXZlZCBhbiBpbnN0YW5jZSBvZiAke2FjdHVhbC5jb25zdHJ1Y3Rvci5uYW1lfWA7XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIG1zZztcbn1cbmV4cG9ydCBkZWZhdWx0IChhY3R1YWwsIC4uLnR5cGVzKSA9PiB7XG4gICAgcmV0dXJuIG1lc3NhZ2UoJ0tleSBtdXN0IGJlICcsIGFjdHVhbCwgLi4udHlwZXMpO1xufTtcbmV4cG9ydCBmdW5jdGlvbiB3aXRoQWxnKGFsZywgYWN0dWFsLCAuLi50eXBlcykge1xuICAgIHJldHVybiBtZXNzYWdlKGBLZXkgZm9yIHRoZSAke2FsZ30gYWxnb3JpdGhtIG11c3QgYmUgYCwgYWN0dWFsLCAuLi50eXBlcyk7XG59XG4iLCJpbXBvcnQgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmV4cG9ydCBkZWZhdWx0IChrZXkpID0+IHtcbiAgICByZXR1cm4gaXNDcnlwdG9LZXkoa2V5KTtcbn07XG5leHBvcnQgY29uc3QgdHlwZXMgPSBbJ0NyeXB0b0tleSddO1xuIiwiaW1wb3J0IHsgY29uY2F0LCB1aW50NjRiZSB9IGZyb20gJy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IGNoZWNrSXZMZW5ndGggZnJvbSAnLi4vbGliL2NoZWNrX2l2X2xlbmd0aC5qcyc7XG5pbXBvcnQgY2hlY2tDZWtMZW5ndGggZnJvbSAnLi9jaGVja19jZWtfbGVuZ3RoLmpzJztcbmltcG9ydCB0aW1pbmdTYWZlRXF1YWwgZnJvbSAnLi90aW1pbmdfc2FmZV9lcXVhbC5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkLCBKV0VEZWNyeXB0aW9uRmFpbGVkLCBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IGNyeXB0bywgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IGNoZWNrRW5jQ3J5cHRvS2V5IH0gZnJvbSAnLi4vbGliL2NyeXB0b19rZXkuanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmFzeW5jIGZ1bmN0aW9uIGNiY0RlY3J5cHQoZW5jLCBjZWssIGNpcGhlcnRleHQsIGl2LCB0YWcsIGFhZCkge1xuICAgIGlmICghKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGNlaywgJ1VpbnQ4QXJyYXknKSk7XG4gICAgfVxuICAgIGNvbnN0IGtleVNpemUgPSBwYXJzZUludChlbmMuc2xpY2UoMSwgNCksIDEwKTtcbiAgICBjb25zdCBlbmNLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLnN1YmFycmF5KGtleVNpemUgPj4gMyksICdBRVMtQ0JDJywgZmFsc2UsIFsnZGVjcnlwdCddKTtcbiAgICBjb25zdCBtYWNLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLnN1YmFycmF5KDAsIGtleVNpemUgPj4gMyksIHtcbiAgICAgICAgaGFzaDogYFNIQS0ke2tleVNpemUgPDwgMX1gLFxuICAgICAgICBuYW1lOiAnSE1BQycsXG4gICAgfSwgZmFsc2UsIFsnc2lnbiddKTtcbiAgICBjb25zdCBtYWNEYXRhID0gY29uY2F0KGFhZCwgaXYsIGNpcGhlcnRleHQsIHVpbnQ2NGJlKGFhZC5sZW5ndGggPDwgMykpO1xuICAgIGNvbnN0IGV4cGVjdGVkVGFnID0gbmV3IFVpbnQ4QXJyYXkoKGF3YWl0IGNyeXB0by5zdWJ0bGUuc2lnbignSE1BQycsIG1hY0tleSwgbWFjRGF0YSkpLnNsaWNlKDAsIGtleVNpemUgPj4gMykpO1xuICAgIGxldCBtYWNDaGVja1Bhc3NlZDtcbiAgICB0cnkge1xuICAgICAgICBtYWNDaGVja1Bhc3NlZCA9IHRpbWluZ1NhZmVFcXVhbCh0YWcsIGV4cGVjdGVkVGFnKTtcbiAgICB9XG4gICAgY2F0Y2gge1xuICAgIH1cbiAgICBpZiAoIW1hY0NoZWNrUGFzc2VkKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VEZWNyeXB0aW9uRmFpbGVkKCk7XG4gICAgfVxuICAgIGxldCBwbGFpbnRleHQ7XG4gICAgdHJ5IHtcbiAgICAgICAgcGxhaW50ZXh0ID0gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5kZWNyeXB0KHsgaXYsIG5hbWU6ICdBRVMtQ0JDJyB9LCBlbmNLZXksIGNpcGhlcnRleHQpKTtcbiAgICB9XG4gICAgY2F0Y2gge1xuICAgIH1cbiAgICBpZiAoIXBsYWludGV4dCkge1xuICAgICAgICB0aHJvdyBuZXcgSldFRGVjcnlwdGlvbkZhaWxlZCgpO1xuICAgIH1cbiAgICByZXR1cm4gcGxhaW50ZXh0O1xufVxuYXN5bmMgZnVuY3Rpb24gZ2NtRGVjcnlwdChlbmMsIGNlaywgY2lwaGVydGV4dCwgaXYsIHRhZywgYWFkKSB7XG4gICAgbGV0IGVuY0tleTtcbiAgICBpZiAoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICBlbmNLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLCAnQUVTLUdDTScsIGZhbHNlLCBbJ2RlY3J5cHQnXSk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBjaGVja0VuY0NyeXB0b0tleShjZWssIGVuYywgJ2RlY3J5cHQnKTtcbiAgICAgICAgZW5jS2V5ID0gY2VrO1xuICAgIH1cbiAgICB0cnkge1xuICAgICAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5kZWNyeXB0KHtcbiAgICAgICAgICAgIGFkZGl0aW9uYWxEYXRhOiBhYWQsXG4gICAgICAgICAgICBpdixcbiAgICAgICAgICAgIG5hbWU6ICdBRVMtR0NNJyxcbiAgICAgICAgICAgIHRhZ0xlbmd0aDogMTI4LFxuICAgICAgICB9LCBlbmNLZXksIGNvbmNhdChjaXBoZXJ0ZXh0LCB0YWcpKSk7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRURlY3J5cHRpb25GYWlsZWQoKTtcbiAgICB9XG59XG5jb25zdCBkZWNyeXB0ID0gYXN5bmMgKGVuYywgY2VrLCBjaXBoZXJ0ZXh0LCBpdiwgdGFnLCBhYWQpID0+IHtcbiAgICBpZiAoIWlzQ3J5cHRvS2V5KGNlaykgJiYgIShjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChjZWssIC4uLnR5cGVzLCAnVWludDhBcnJheScpKTtcbiAgICB9XG4gICAgaWYgKCFpdikge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEluaXRpYWxpemF0aW9uIFZlY3RvciBtaXNzaW5nJyk7XG4gICAgfVxuICAgIGlmICghdGFnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgQXV0aGVudGljYXRpb24gVGFnIG1pc3NpbmcnKTtcbiAgICB9XG4gICAgY2hlY2tJdkxlbmd0aChlbmMsIGl2KTtcbiAgICBzd2l0Y2ggKGVuYykge1xuICAgICAgICBjYXNlICdBMTI4Q0JDLUhTMjU2JzpcbiAgICAgICAgY2FzZSAnQTE5MkNCQy1IUzM4NCc6XG4gICAgICAgIGNhc2UgJ0EyNTZDQkMtSFM1MTInOlxuICAgICAgICAgICAgaWYgKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpXG4gICAgICAgICAgICAgICAgY2hlY2tDZWtMZW5ndGgoY2VrLCBwYXJzZUludChlbmMuc2xpY2UoLTMpLCAxMCkpO1xuICAgICAgICAgICAgcmV0dXJuIGNiY0RlY3J5cHQoZW5jLCBjZWssIGNpcGhlcnRleHQsIGl2LCB0YWcsIGFhZCk7XG4gICAgICAgIGNhc2UgJ0ExMjhHQ00nOlxuICAgICAgICBjYXNlICdBMTkyR0NNJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTSc6XG4gICAgICAgICAgICBpZiAoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSlcbiAgICAgICAgICAgICAgICBjaGVja0Nla0xlbmd0aChjZWssIHBhcnNlSW50KGVuYy5zbGljZSgxLCA0KSwgMTApKTtcbiAgICAgICAgICAgIHJldHVybiBnY21EZWNyeXB0KGVuYywgY2VrLCBjaXBoZXJ0ZXh0LCBpdiwgdGFnLCBhYWQpO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ1Vuc3VwcG9ydGVkIEpXRSBDb250ZW50IEVuY3J5cHRpb24gQWxnb3JpdGhtJyk7XG4gICAgfVxufTtcbmV4cG9ydCBkZWZhdWx0IGRlY3J5cHQ7XG4iLCJjb25zdCBpc0Rpc2pvaW50ID0gKC4uLmhlYWRlcnMpID0+IHtcbiAgICBjb25zdCBzb3VyY2VzID0gaGVhZGVycy5maWx0ZXIoQm9vbGVhbik7XG4gICAgaWYgKHNvdXJjZXMubGVuZ3RoID09PSAwIHx8IHNvdXJjZXMubGVuZ3RoID09PSAxKSB7XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cbiAgICBsZXQgYWNjO1xuICAgIGZvciAoY29uc3QgaGVhZGVyIG9mIHNvdXJjZXMpIHtcbiAgICAgICAgY29uc3QgcGFyYW1ldGVycyA9IE9iamVjdC5rZXlzKGhlYWRlcik7XG4gICAgICAgIGlmICghYWNjIHx8IGFjYy5zaXplID09PSAwKSB7XG4gICAgICAgICAgICBhY2MgPSBuZXcgU2V0KHBhcmFtZXRlcnMpO1xuICAgICAgICAgICAgY29udGludWU7XG4gICAgICAgIH1cbiAgICAgICAgZm9yIChjb25zdCBwYXJhbWV0ZXIgb2YgcGFyYW1ldGVycykge1xuICAgICAgICAgICAgaWYgKGFjYy5oYXMocGFyYW1ldGVyKSkge1xuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGFjYy5hZGQocGFyYW1ldGVyKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gdHJ1ZTtcbn07XG5leHBvcnQgZGVmYXVsdCBpc0Rpc2pvaW50O1xuIiwiZnVuY3Rpb24gaXNPYmplY3RMaWtlKHZhbHVlKSB7XG4gICAgcmV0dXJuIHR5cGVvZiB2YWx1ZSA9PT0gJ29iamVjdCcgJiYgdmFsdWUgIT09IG51bGw7XG59XG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBpc09iamVjdChpbnB1dCkge1xuICAgIGlmICghaXNPYmplY3RMaWtlKGlucHV0KSB8fCBPYmplY3QucHJvdG90eXBlLnRvU3RyaW5nLmNhbGwoaW5wdXQpICE9PSAnW29iamVjdCBPYmplY3RdJykge1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuICAgIGlmIChPYmplY3QuZ2V0UHJvdG90eXBlT2YoaW5wdXQpID09PSBudWxsKSB7XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cbiAgICBsZXQgcHJvdG8gPSBpbnB1dDtcbiAgICB3aGlsZSAoT2JqZWN0LmdldFByb3RvdHlwZU9mKHByb3RvKSAhPT0gbnVsbCkge1xuICAgICAgICBwcm90byA9IE9iamVjdC5nZXRQcm90b3R5cGVPZihwcm90byk7XG4gICAgfVxuICAgIHJldHVybiBPYmplY3QuZ2V0UHJvdG90eXBlT2YoaW5wdXQpID09PSBwcm90bztcbn1cbiIsImNvbnN0IGJvZ3VzV2ViQ3J5cHRvID0gW1xuICAgIHsgaGFzaDogJ1NIQS0yNTYnLCBuYW1lOiAnSE1BQycgfSxcbiAgICB0cnVlLFxuICAgIFsnc2lnbiddLFxuXTtcbmV4cG9ydCBkZWZhdWx0IGJvZ3VzV2ViQ3J5cHRvO1xuIiwiaW1wb3J0IGJvZ3VzV2ViQ3J5cHRvIGZyb20gJy4vYm9ndXMuanMnO1xuaW1wb3J0IGNyeXB0bywgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IGNoZWNrRW5jQ3J5cHRvS2V5IH0gZnJvbSAnLi4vbGliL2NyeXB0b19rZXkuanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmZ1bmN0aW9uIGNoZWNrS2V5U2l6ZShrZXksIGFsZykge1xuICAgIGlmIChrZXkuYWxnb3JpdGhtLmxlbmd0aCAhPT0gcGFyc2VJbnQoYWxnLnNsaWNlKDEsIDQpLCAxMCkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgSW52YWxpZCBrZXkgc2l6ZSBmb3IgYWxnOiAke2FsZ31gKTtcbiAgICB9XG59XG5mdW5jdGlvbiBnZXRDcnlwdG9LZXkoa2V5LCBhbGcsIHVzYWdlKSB7XG4gICAgaWYgKGlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgY2hlY2tFbmNDcnlwdG9LZXkoa2V5LCBhbGcsIHVzYWdlKTtcbiAgICAgICAgcmV0dXJuIGtleTtcbiAgICB9XG4gICAgaWYgKGtleSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBrZXksICdBRVMtS1cnLCB0cnVlLCBbdXNhZ2VdKTtcbiAgICB9XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcywgJ1VpbnQ4QXJyYXknKSk7XG59XG5leHBvcnQgY29uc3Qgd3JhcCA9IGFzeW5jIChhbGcsIGtleSwgY2VrKSA9PiB7XG4gICAgY29uc3QgY3J5cHRvS2V5ID0gYXdhaXQgZ2V0Q3J5cHRvS2V5KGtleSwgYWxnLCAnd3JhcEtleScpO1xuICAgIGNoZWNrS2V5U2l6ZShjcnlwdG9LZXksIGFsZyk7XG4gICAgY29uc3QgY3J5cHRvS2V5Q2VrID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGNlaywgLi4uYm9ndXNXZWJDcnlwdG8pO1xuICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLndyYXBLZXkoJ3JhdycsIGNyeXB0b0tleUNlaywgY3J5cHRvS2V5LCAnQUVTLUtXJykpO1xufTtcbmV4cG9ydCBjb25zdCB1bndyYXAgPSBhc3luYyAoYWxnLCBrZXksIGVuY3J5cHRlZEtleSkgPT4ge1xuICAgIGNvbnN0IGNyeXB0b0tleSA9IGF3YWl0IGdldENyeXB0b0tleShrZXksIGFsZywgJ3Vud3JhcEtleScpO1xuICAgIGNoZWNrS2V5U2l6ZShjcnlwdG9LZXksIGFsZyk7XG4gICAgY29uc3QgY3J5cHRvS2V5Q2VrID0gYXdhaXQgY3J5cHRvLnN1YnRsZS51bndyYXBLZXkoJ3JhdycsIGVuY3J5cHRlZEtleSwgY3J5cHRvS2V5LCAnQUVTLUtXJywgLi4uYm9ndXNXZWJDcnlwdG8pO1xuICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgncmF3JywgY3J5cHRvS2V5Q2VrKSk7XG59O1xuIiwiaW1wb3J0IHsgZW5jb2RlciwgY29uY2F0LCB1aW50MzJiZSwgbGVuZ3RoQW5kSW5wdXQsIGNvbmNhdEtkZiB9IGZyb20gJy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IGNyeXB0bywgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IGNoZWNrRW5jQ3J5cHRvS2V5IH0gZnJvbSAnLi4vbGliL2NyeXB0b19rZXkuanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZXJpdmVLZXkocHVibGljS2V5LCBwcml2YXRlS2V5LCBhbGdvcml0aG0sIGtleUxlbmd0aCwgYXB1ID0gbmV3IFVpbnQ4QXJyYXkoMCksIGFwdiA9IG5ldyBVaW50OEFycmF5KDApKSB7XG4gICAgaWYgKCFpc0NyeXB0b0tleShwdWJsaWNLZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KHB1YmxpY0tleSwgLi4udHlwZXMpKTtcbiAgICB9XG4gICAgY2hlY2tFbmNDcnlwdG9LZXkocHVibGljS2V5LCAnRUNESCcpO1xuICAgIGlmICghaXNDcnlwdG9LZXkocHJpdmF0ZUtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQocHJpdmF0ZUtleSwgLi4udHlwZXMpKTtcbiAgICB9XG4gICAgY2hlY2tFbmNDcnlwdG9LZXkocHJpdmF0ZUtleSwgJ0VDREgnLCAnZGVyaXZlQml0cycpO1xuICAgIGNvbnN0IHZhbHVlID0gY29uY2F0KGxlbmd0aEFuZElucHV0KGVuY29kZXIuZW5jb2RlKGFsZ29yaXRobSkpLCBsZW5ndGhBbmRJbnB1dChhcHUpLCBsZW5ndGhBbmRJbnB1dChhcHYpLCB1aW50MzJiZShrZXlMZW5ndGgpKTtcbiAgICBsZXQgbGVuZ3RoO1xuICAgIGlmIChwdWJsaWNLZXkuYWxnb3JpdGhtLm5hbWUgPT09ICdYMjU1MTknKSB7XG4gICAgICAgIGxlbmd0aCA9IDI1NjtcbiAgICB9XG4gICAgZWxzZSBpZiAocHVibGljS2V5LmFsZ29yaXRobS5uYW1lID09PSAnWDQ0OCcpIHtcbiAgICAgICAgbGVuZ3RoID0gNDQ4O1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgbGVuZ3RoID1cbiAgICAgICAgICAgIE1hdGguY2VpbChwYXJzZUludChwdWJsaWNLZXkuYWxnb3JpdGhtLm5hbWVkQ3VydmUuc3Vic3RyKC0zKSwgMTApIC8gOCkgPDwgMztcbiAgICB9XG4gICAgY29uc3Qgc2hhcmVkU2VjcmV0ID0gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5kZXJpdmVCaXRzKHtcbiAgICAgICAgbmFtZTogcHVibGljS2V5LmFsZ29yaXRobS5uYW1lLFxuICAgICAgICBwdWJsaWM6IHB1YmxpY0tleSxcbiAgICB9LCBwcml2YXRlS2V5LCBsZW5ndGgpKTtcbiAgICByZXR1cm4gY29uY2F0S2RmKHNoYXJlZFNlY3JldCwga2V5TGVuZ3RoLCB2YWx1ZSk7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhdGVFcGsoa2V5KSB7XG4gICAgaWYgKCFpc0NyeXB0b0tleShrZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMpKTtcbiAgICB9XG4gICAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuZ2VuZXJhdGVLZXkoa2V5LmFsZ29yaXRobSwgdHJ1ZSwgWydkZXJpdmVCaXRzJ10pO1xufVxuZXhwb3J0IGZ1bmN0aW9uIGVjZGhBbGxvd2VkKGtleSkge1xuICAgIGlmICghaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzKSk7XG4gICAgfVxuICAgIHJldHVybiAoWydQLTI1NicsICdQLTM4NCcsICdQLTUyMSddLmluY2x1ZGVzKGtleS5hbGdvcml0aG0ubmFtZWRDdXJ2ZSkgfHxcbiAgICAgICAga2V5LmFsZ29yaXRobS5uYW1lID09PSAnWDI1NTE5JyB8fFxuICAgICAgICBrZXkuYWxnb3JpdGhtLm5hbWUgPT09ICdYNDQ4Jyk7XG59XG4iLCJpbXBvcnQgeyBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gY2hlY2tQMnMocDJzKSB7XG4gICAgaWYgKCEocDJzIGluc3RhbmNlb2YgVWludDhBcnJheSkgfHwgcDJzLmxlbmd0aCA8IDgpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ1BCRVMyIFNhbHQgSW5wdXQgbXVzdCBiZSA4IG9yIG1vcmUgb2N0ZXRzJyk7XG4gICAgfVxufVxuIiwiaW1wb3J0IHJhbmRvbSBmcm9tICcuL3JhbmRvbS5qcyc7XG5pbXBvcnQgeyBwMnMgYXMgY29uY2F0U2FsdCB9IGZyb20gJy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IHsgZW5jb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4vYmFzZTY0dXJsLmpzJztcbmltcG9ydCB7IHdyYXAsIHVud3JhcCB9IGZyb20gJy4vYWVza3cuanMnO1xuaW1wb3J0IGNoZWNrUDJzIGZyb20gJy4uL2xpYi9jaGVja19wMnMuanMnO1xuaW1wb3J0IGNyeXB0bywgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IGNoZWNrRW5jQ3J5cHRvS2V5IH0gZnJvbSAnLi4vbGliL2NyeXB0b19rZXkuanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmZ1bmN0aW9uIGdldENyeXB0b0tleShrZXksIGFsZykge1xuICAgIGlmIChrZXkgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIHJldHVybiBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3Jywga2V5LCAnUEJLREYyJywgZmFsc2UsIFsnZGVyaXZlQml0cyddKTtcbiAgICB9XG4gICAgaWYgKGlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgY2hlY2tFbmNDcnlwdG9LZXkoa2V5LCBhbGcsICdkZXJpdmVCaXRzJywgJ2Rlcml2ZUtleScpO1xuICAgICAgICByZXR1cm4ga2V5O1xuICAgIH1cbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzLCAnVWludDhBcnJheScpKTtcbn1cbmFzeW5jIGZ1bmN0aW9uIGRlcml2ZUtleShwMnMsIGFsZywgcDJjLCBrZXkpIHtcbiAgICBjaGVja1AycyhwMnMpO1xuICAgIGNvbnN0IHNhbHQgPSBjb25jYXRTYWx0KGFsZywgcDJzKTtcbiAgICBjb25zdCBrZXlsZW4gPSBwYXJzZUludChhbGcuc2xpY2UoMTMsIDE2KSwgMTApO1xuICAgIGNvbnN0IHN1YnRsZUFsZyA9IHtcbiAgICAgICAgaGFzaDogYFNIQS0ke2FsZy5zbGljZSg4LCAxMSl9YCxcbiAgICAgICAgaXRlcmF0aW9uczogcDJjLFxuICAgICAgICBuYW1lOiAnUEJLREYyJyxcbiAgICAgICAgc2FsdCxcbiAgICB9O1xuICAgIGNvbnN0IHdyYXBBbGcgPSB7XG4gICAgICAgIGxlbmd0aDoga2V5bGVuLFxuICAgICAgICBuYW1lOiAnQUVTLUtXJyxcbiAgICB9O1xuICAgIGNvbnN0IGNyeXB0b0tleSA9IGF3YWl0IGdldENyeXB0b0tleShrZXksIGFsZyk7XG4gICAgaWYgKGNyeXB0b0tleS51c2FnZXMuaW5jbHVkZXMoJ2Rlcml2ZUJpdHMnKSkge1xuICAgICAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5kZXJpdmVCaXRzKHN1YnRsZUFsZywgY3J5cHRvS2V5LCBrZXlsZW4pKTtcbiAgICB9XG4gICAgaWYgKGNyeXB0b0tleS51c2FnZXMuaW5jbHVkZXMoJ2Rlcml2ZUtleScpKSB7XG4gICAgICAgIHJldHVybiBjcnlwdG8uc3VidGxlLmRlcml2ZUtleShzdWJ0bGVBbGcsIGNyeXB0b0tleSwgd3JhcEFsZywgZmFsc2UsIFsnd3JhcEtleScsICd1bndyYXBLZXknXSk7XG4gICAgfVxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1BCS0RGMiBrZXkgXCJ1c2FnZXNcIiBtdXN0IGluY2x1ZGUgXCJkZXJpdmVCaXRzXCIgb3IgXCJkZXJpdmVLZXlcIicpO1xufVxuZXhwb3J0IGNvbnN0IGVuY3J5cHQgPSBhc3luYyAoYWxnLCBrZXksIGNlaywgcDJjID0gMjA0OCwgcDJzID0gcmFuZG9tKG5ldyBVaW50OEFycmF5KDE2KSkpID0+IHtcbiAgICBjb25zdCBkZXJpdmVkID0gYXdhaXQgZGVyaXZlS2V5KHAycywgYWxnLCBwMmMsIGtleSk7XG4gICAgY29uc3QgZW5jcnlwdGVkS2V5ID0gYXdhaXQgd3JhcChhbGcuc2xpY2UoLTYpLCBkZXJpdmVkLCBjZWspO1xuICAgIHJldHVybiB7IGVuY3J5cHRlZEtleSwgcDJjLCBwMnM6IGJhc2U2NHVybChwMnMpIH07XG59O1xuZXhwb3J0IGNvbnN0IGRlY3J5cHQgPSBhc3luYyAoYWxnLCBrZXksIGVuY3J5cHRlZEtleSwgcDJjLCBwMnMpID0+IHtcbiAgICBjb25zdCBkZXJpdmVkID0gYXdhaXQgZGVyaXZlS2V5KHAycywgYWxnLCBwMmMsIGtleSk7XG4gICAgcmV0dXJuIHVud3JhcChhbGcuc2xpY2UoLTYpLCBkZXJpdmVkLCBlbmNyeXB0ZWRLZXkpO1xufTtcbiIsImltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBzdWJ0bGVSc2FFcyhhbGcpIHtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdSU0EtT0FFUCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTI1Nic6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTM4NCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTUxMic6XG4gICAgICAgICAgICByZXR1cm4gJ1JTQS1PQUVQJztcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKGBhbGcgJHthbGd9IGlzIG5vdCBzdXBwb3J0ZWQgZWl0aGVyIGJ5IEpPU0Ugb3IgeW91ciBqYXZhc2NyaXB0IHJ1bnRpbWVgKTtcbiAgICB9XG59XG4iLCJleHBvcnQgZGVmYXVsdCAoYWxnLCBrZXkpID0+IHtcbiAgICBpZiAoYWxnLnN0YXJ0c1dpdGgoJ1JTJykgfHwgYWxnLnN0YXJ0c1dpdGgoJ1BTJykpIHtcbiAgICAgICAgY29uc3QgeyBtb2R1bHVzTGVuZ3RoIH0gPSBrZXkuYWxnb3JpdGhtO1xuICAgICAgICBpZiAodHlwZW9mIG1vZHVsdXNMZW5ndGggIT09ICdudW1iZXInIHx8IG1vZHVsdXNMZW5ndGggPCAyMDQ4KSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGAke2FsZ30gcmVxdWlyZXMga2V5IG1vZHVsdXNMZW5ndGggdG8gYmUgMjA0OCBiaXRzIG9yIGxhcmdlcmApO1xuICAgICAgICB9XG4gICAgfVxufTtcbiIsImltcG9ydCBzdWJ0bGVBbGdvcml0aG0gZnJvbSAnLi9zdWJ0bGVfcnNhZXMuanMnO1xuaW1wb3J0IGJvZ3VzV2ViQ3J5cHRvIGZyb20gJy4vYm9ndXMuanMnO1xuaW1wb3J0IGNyeXB0bywgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IGNoZWNrRW5jQ3J5cHRvS2V5IH0gZnJvbSAnLi4vbGliL2NyeXB0b19rZXkuanMnO1xuaW1wb3J0IGNoZWNrS2V5TGVuZ3RoIGZyb20gJy4vY2hlY2tfa2V5X2xlbmd0aC5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuZXhwb3J0IGNvbnN0IGVuY3J5cHQgPSBhc3luYyAoYWxnLCBrZXksIGNlaykgPT4ge1xuICAgIGlmICghaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzKSk7XG4gICAgfVxuICAgIGNoZWNrRW5jQ3J5cHRvS2V5KGtleSwgYWxnLCAnZW5jcnlwdCcsICd3cmFwS2V5Jyk7XG4gICAgY2hlY2tLZXlMZW5ndGgoYWxnLCBrZXkpO1xuICAgIGlmIChrZXkudXNhZ2VzLmluY2x1ZGVzKCdlbmNyeXB0JykpIHtcbiAgICAgICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZW5jcnlwdChzdWJ0bGVBbGdvcml0aG0oYWxnKSwga2V5LCBjZWspKTtcbiAgICB9XG4gICAgaWYgKGtleS51c2FnZXMuaW5jbHVkZXMoJ3dyYXBLZXknKSkge1xuICAgICAgICBjb25zdCBjcnlwdG9LZXlDZWsgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLCAuLi5ib2d1c1dlYkNyeXB0byk7XG4gICAgICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLndyYXBLZXkoJ3JhdycsIGNyeXB0b0tleUNlaywga2V5LCBzdWJ0bGVBbGdvcml0aG0oYWxnKSkpO1xuICAgIH1cbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdSU0EtT0FFUCBrZXkgXCJ1c2FnZXNcIiBtdXN0IGluY2x1ZGUgXCJlbmNyeXB0XCIgb3IgXCJ3cmFwS2V5XCIgZm9yIHRoaXMgb3BlcmF0aW9uJyk7XG59O1xuZXhwb3J0IGNvbnN0IGRlY3J5cHQgPSBhc3luYyAoYWxnLCBrZXksIGVuY3J5cHRlZEtleSkgPT4ge1xuICAgIGlmICghaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzKSk7XG4gICAgfVxuICAgIGNoZWNrRW5jQ3J5cHRvS2V5KGtleSwgYWxnLCAnZGVjcnlwdCcsICd1bndyYXBLZXknKTtcbiAgICBjaGVja0tleUxlbmd0aChhbGcsIGtleSk7XG4gICAgaWYgKGtleS51c2FnZXMuaW5jbHVkZXMoJ2RlY3J5cHQnKSkge1xuICAgICAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5kZWNyeXB0KHN1YnRsZUFsZ29yaXRobShhbGcpLCBrZXksIGVuY3J5cHRlZEtleSkpO1xuICAgIH1cbiAgICBpZiAoa2V5LnVzYWdlcy5pbmNsdWRlcygndW53cmFwS2V5JykpIHtcbiAgICAgICAgY29uc3QgY3J5cHRvS2V5Q2VrID0gYXdhaXQgY3J5cHRvLnN1YnRsZS51bndyYXBLZXkoJ3JhdycsIGVuY3J5cHRlZEtleSwga2V5LCBzdWJ0bGVBbGdvcml0aG0oYWxnKSwgLi4uYm9ndXNXZWJDcnlwdG8pO1xuICAgICAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoJ3JhdycsIGNyeXB0b0tleUNlaykpO1xuICAgIH1cbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdSU0EtT0FFUCBrZXkgXCJ1c2FnZXNcIiBtdXN0IGluY2x1ZGUgXCJkZWNyeXB0XCIgb3IgXCJ1bndyYXBLZXlcIiBmb3IgdGhpcyBvcGVyYXRpb24nKTtcbn07XG4iLCJpbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHJhbmRvbSBmcm9tICcuLi9ydW50aW1lL3JhbmRvbS5qcyc7XG5leHBvcnQgZnVuY3Rpb24gYml0TGVuZ3RoKGFsZykge1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ0ExMjhHQ00nOlxuICAgICAgICAgICAgcmV0dXJuIDEyODtcbiAgICAgICAgY2FzZSAnQTE5MkdDTSc6XG4gICAgICAgICAgICByZXR1cm4gMTkyO1xuICAgICAgICBjYXNlICdBMjU2R0NNJzpcbiAgICAgICAgY2FzZSAnQTEyOENCQy1IUzI1Nic6XG4gICAgICAgICAgICByZXR1cm4gMjU2O1xuICAgICAgICBjYXNlICdBMTkyQ0JDLUhTMzg0JzpcbiAgICAgICAgICAgIHJldHVybiAzODQ7XG4gICAgICAgIGNhc2UgJ0EyNTZDQkMtSFM1MTInOlxuICAgICAgICAgICAgcmV0dXJuIDUxMjtcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKGBVbnN1cHBvcnRlZCBKV0UgQWxnb3JpdGhtOiAke2FsZ31gKTtcbiAgICB9XG59XG5leHBvcnQgZGVmYXVsdCAoYWxnKSA9PiByYW5kb20obmV3IFVpbnQ4QXJyYXkoYml0TGVuZ3RoKGFsZykgPj4gMykpO1xuIiwiaW1wb3J0IGNyeXB0byBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuZnVuY3Rpb24gc3VidGxlTWFwcGluZyhqd2spIHtcbiAgICBsZXQgYWxnb3JpdGhtO1xuICAgIGxldCBrZXlVc2FnZXM7XG4gICAgc3dpdGNoIChqd2sua3R5KSB7XG4gICAgICAgIGNhc2UgJ1JTQSc6IHtcbiAgICAgICAgICAgIHN3aXRjaCAoandrLmFsZykge1xuICAgICAgICAgICAgICAgIGNhc2UgJ1BTMjU2JzpcbiAgICAgICAgICAgICAgICBjYXNlICdQUzM4NCc6XG4gICAgICAgICAgICAgICAgY2FzZSAnUFM1MTInOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdSU0EtUFNTJywgaGFzaDogYFNIQS0ke2p3ay5hbGcuc2xpY2UoLTMpfWAgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ3NpZ24nXSA6IFsndmVyaWZ5J107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ1JTMjU2JzpcbiAgICAgICAgICAgICAgICBjYXNlICdSUzM4NCc6XG4gICAgICAgICAgICAgICAgY2FzZSAnUlM1MTInOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdSU0FTU0EtUEtDUzEtdjFfNScsIGhhc2g6IGBTSEEtJHtqd2suYWxnLnNsaWNlKC0zKX1gIH07XG4gICAgICAgICAgICAgICAgICAgIGtleVVzYWdlcyA9IGp3ay5kID8gWydzaWduJ10gOiBbJ3ZlcmlmeSddO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlICdSU0EtT0FFUCc6XG4gICAgICAgICAgICAgICAgY2FzZSAnUlNBLU9BRVAtMjU2JzpcbiAgICAgICAgICAgICAgICBjYXNlICdSU0EtT0FFUC0zODQnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1JTQS1PQUVQLTUxMic6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIG5hbWU6ICdSU0EtT0FFUCcsXG4gICAgICAgICAgICAgICAgICAgICAgICBoYXNoOiBgU0hBLSR7cGFyc2VJbnQoandrLmFsZy5zbGljZSgtMyksIDEwKSB8fCAxfWAsXG4gICAgICAgICAgICAgICAgICAgIH07XG4gICAgICAgICAgICAgICAgICAgIGtleVVzYWdlcyA9IGp3ay5kID8gWydkZWNyeXB0JywgJ3Vud3JhcEtleSddIDogWydlbmNyeXB0JywgJ3dyYXBLZXknXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgSldLIFwiYWxnXCIgKEFsZ29yaXRobSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdFQyc6IHtcbiAgICAgICAgICAgIHN3aXRjaCAoandrLmFsZykge1xuICAgICAgICAgICAgICAgIGNhc2UgJ0VTMjU2JzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNEU0EnLCBuYW1lZEN1cnZlOiAnUC0yNTYnIH07XG4gICAgICAgICAgICAgICAgICAgIGtleVVzYWdlcyA9IGp3ay5kID8gWydzaWduJ10gOiBbJ3ZlcmlmeSddO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlICdFUzM4NCc6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0VDRFNBJywgbmFtZWRDdXJ2ZTogJ1AtMzg0JyB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnc2lnbiddIDogWyd2ZXJpZnknXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAnRVM1MTInOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RTQScsIG5hbWVkQ3VydmU6ICdQLTUyMScgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ3NpZ24nXSA6IFsndmVyaWZ5J107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMrQTEyOEtXJzpcbiAgICAgICAgICAgICAgICBjYXNlICdFQ0RILUVTK0ExOTJLVyc6XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUytBMjU2S1cnOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RIJywgbmFtZWRDdXJ2ZTogandrLmNydiB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnZGVyaXZlQml0cyddIDogW107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIEpXSyBcImFsZ1wiIChBbGdvcml0aG0pIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnT0tQJzoge1xuICAgICAgICAgICAgc3dpdGNoIChqd2suYWxnKSB7XG4gICAgICAgICAgICAgICAgY2FzZSAnRWREU0EnOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6IGp3ay5jcnYgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ3NpZ24nXSA6IFsndmVyaWZ5J107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMrQTEyOEtXJzpcbiAgICAgICAgICAgICAgICBjYXNlICdFQ0RILUVTK0ExOTJLVyc6XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUytBMjU2S1cnOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6IGp3ay5jcnYgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ2Rlcml2ZUJpdHMnXSA6IFtdO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBKV0sgXCJhbGdcIiAoQWxnb3JpdGhtKSBQYXJhbWV0ZXIgdmFsdWUnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBKV0sgXCJrdHlcIiAoS2V5IFR5cGUpIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgIH1cbiAgICByZXR1cm4geyBhbGdvcml0aG0sIGtleVVzYWdlcyB9O1xufVxuY29uc3QgcGFyc2UgPSBhc3luYyAoandrKSA9PiB7XG4gICAgaWYgKCFqd2suYWxnKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1wiYWxnXCIgYXJndW1lbnQgaXMgcmVxdWlyZWQgd2hlbiBcImp3ay5hbGdcIiBpcyBub3QgcHJlc2VudCcpO1xuICAgIH1cbiAgICBjb25zdCB7IGFsZ29yaXRobSwga2V5VXNhZ2VzIH0gPSBzdWJ0bGVNYXBwaW5nKGp3ayk7XG4gICAgY29uc3QgcmVzdCA9IFtcbiAgICAgICAgYWxnb3JpdGhtLFxuICAgICAgICBqd2suZXh0ID8/IGZhbHNlLFxuICAgICAgICBqd2sua2V5X29wcyA/PyBrZXlVc2FnZXMsXG4gICAgXTtcbiAgICBjb25zdCBrZXlEYXRhID0geyAuLi5qd2sgfTtcbiAgICBkZWxldGUga2V5RGF0YS5hbGc7XG4gICAgZGVsZXRlIGtleURhdGEudXNlO1xuICAgIHJldHVybiBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgnandrJywga2V5RGF0YSwgLi4ucmVzdCk7XG59O1xuZXhwb3J0IGRlZmF1bHQgcGFyc2U7XG4iLCJpbXBvcnQgeyBkZWNvZGUgYXMgZGVjb2RlQmFzZTY0VVJMIH0gZnJvbSAnLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHsgZnJvbVNQS0ksIGZyb21QS0NTOCwgZnJvbVg1MDkgfSBmcm9tICcuLi9ydW50aW1lL2FzbjEuanMnO1xuaW1wb3J0IGFzS2V5T2JqZWN0IGZyb20gJy4uL3J1bnRpbWUvandrX3RvX2tleS5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4uL2xpYi9pc19vYmplY3QuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGltcG9ydFNQS0koc3BraSwgYWxnLCBvcHRpb25zKSB7XG4gICAgaWYgKHR5cGVvZiBzcGtpICE9PSAnc3RyaW5nJyB8fCBzcGtpLmluZGV4T2YoJy0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tJykgIT09IDApIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignXCJzcGtpXCIgbXVzdCBiZSBTUEtJIGZvcm1hdHRlZCBzdHJpbmcnKTtcbiAgICB9XG4gICAgcmV0dXJuIGZyb21TUEtJKHNwa2ksIGFsZywgb3B0aW9ucyk7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gaW1wb3J0WDUwOSh4NTA5LCBhbGcsIG9wdGlvbnMpIHtcbiAgICBpZiAodHlwZW9mIHg1MDkgIT09ICdzdHJpbmcnIHx8IHg1MDkuaW5kZXhPZignLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tJykgIT09IDApIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignXCJ4NTA5XCIgbXVzdCBiZSBYLjUwOSBmb3JtYXR0ZWQgc3RyaW5nJyk7XG4gICAgfVxuICAgIHJldHVybiBmcm9tWDUwOSh4NTA5LCBhbGcsIG9wdGlvbnMpO1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGltcG9ydFBLQ1M4KHBrY3M4LCBhbGcsIG9wdGlvbnMpIHtcbiAgICBpZiAodHlwZW9mIHBrY3M4ICE9PSAnc3RyaW5nJyB8fCBwa2NzOC5pbmRleE9mKCctLS0tLUJFR0lOIFBSSVZBVEUgS0VZLS0tLS0nKSAhPT0gMCkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdcInBrY3M4XCIgbXVzdCBiZSBQS0NTIzggZm9ybWF0dGVkIHN0cmluZycpO1xuICAgIH1cbiAgICByZXR1cm4gZnJvbVBLQ1M4KHBrY3M4LCBhbGcsIG9wdGlvbnMpO1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGltcG9ydEpXSyhqd2ssIGFsZykge1xuICAgIGlmICghaXNPYmplY3QoandrKSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdKV0sgbXVzdCBiZSBhbiBvYmplY3QnKTtcbiAgICB9XG4gICAgYWxnIHx8IChhbGcgPSBqd2suYWxnKTtcbiAgICBzd2l0Y2ggKGp3ay5rdHkpIHtcbiAgICAgICAgY2FzZSAnb2N0JzpcbiAgICAgICAgICAgIGlmICh0eXBlb2YgandrLmsgIT09ICdzdHJpbmcnIHx8ICFqd2suaykge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ21pc3NpbmcgXCJrXCIgKEtleSBWYWx1ZSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gZGVjb2RlQmFzZTY0VVJMKGp3ay5rKTtcbiAgICAgICAgY2FzZSAnUlNBJzpcbiAgICAgICAgICAgIGlmIChqd2sub3RoICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnUlNBIEpXSyBcIm90aFwiIChPdGhlciBQcmltZXMgSW5mbykgUGFyYW1ldGVyIHZhbHVlIGlzIG5vdCBzdXBwb3J0ZWQnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgY2FzZSAnRUMnOlxuICAgICAgICBjYXNlICdPS1AnOlxuICAgICAgICAgICAgcmV0dXJuIGFzS2V5T2JqZWN0KHsgLi4uandrLCBhbGcgfSk7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnVW5zdXBwb3J0ZWQgXCJrdHlcIiAoS2V5IFR5cGUpIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgIH1cbn1cbiIsImltcG9ydCB7IHdpdGhBbGcgYXMgaW52YWxpZEtleUlucHV0IH0gZnJvbSAnLi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgaXNLZXlMaWtlLCB7IHR5cGVzIH0gZnJvbSAnLi4vcnVudGltZS9pc19rZXlfbGlrZS5qcyc7XG5jb25zdCBzeW1tZXRyaWNUeXBlQ2hlY2sgPSAoYWxnLCBrZXkpID0+IHtcbiAgICBpZiAoa2V5IGluc3RhbmNlb2YgVWludDhBcnJheSlcbiAgICAgICAgcmV0dXJuO1xuICAgIGlmICghaXNLZXlMaWtlKGtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoYWxnLCBrZXksIC4uLnR5cGVzLCAnVWludDhBcnJheScpKTtcbiAgICB9XG4gICAgaWYgKGtleS50eXBlICE9PSAnc2VjcmV0Jykge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGAke3R5cGVzLmpvaW4oJyBvciAnKX0gaW5zdGFuY2VzIGZvciBzeW1tZXRyaWMgYWxnb3JpdGhtcyBtdXN0IGJlIG9mIHR5cGUgXCJzZWNyZXRcImApO1xuICAgIH1cbn07XG5jb25zdCBhc3ltbWV0cmljVHlwZUNoZWNrID0gKGFsZywga2V5LCB1c2FnZSkgPT4ge1xuICAgIGlmICghaXNLZXlMaWtlKGtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoYWxnLCBrZXksIC4uLnR5cGVzKSk7XG4gICAgfVxuICAgIGlmIChrZXkudHlwZSA9PT0gJ3NlY3JldCcpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHt0eXBlcy5qb2luKCcgb3IgJyl9IGluc3RhbmNlcyBmb3IgYXN5bW1ldHJpYyBhbGdvcml0aG1zIG11c3Qgbm90IGJlIG9mIHR5cGUgXCJzZWNyZXRcImApO1xuICAgIH1cbiAgICBpZiAodXNhZ2UgPT09ICdzaWduJyAmJiBrZXkudHlwZSA9PT0gJ3B1YmxpYycpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHt0eXBlcy5qb2luKCcgb3IgJyl9IGluc3RhbmNlcyBmb3IgYXN5bW1ldHJpYyBhbGdvcml0aG0gc2lnbmluZyBtdXN0IGJlIG9mIHR5cGUgXCJwcml2YXRlXCJgKTtcbiAgICB9XG4gICAgaWYgKHVzYWdlID09PSAnZGVjcnlwdCcgJiYga2V5LnR5cGUgPT09ICdwdWJsaWMnKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYCR7dHlwZXMuam9pbignIG9yICcpfSBpbnN0YW5jZXMgZm9yIGFzeW1tZXRyaWMgYWxnb3JpdGhtIGRlY3J5cHRpb24gbXVzdCBiZSBvZiB0eXBlIFwicHJpdmF0ZVwiYCk7XG4gICAgfVxuICAgIGlmIChrZXkuYWxnb3JpdGhtICYmIHVzYWdlID09PSAndmVyaWZ5JyAmJiBrZXkudHlwZSA9PT0gJ3ByaXZhdGUnKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYCR7dHlwZXMuam9pbignIG9yICcpfSBpbnN0YW5jZXMgZm9yIGFzeW1tZXRyaWMgYWxnb3JpdGhtIHZlcmlmeWluZyBtdXN0IGJlIG9mIHR5cGUgXCJwdWJsaWNcImApO1xuICAgIH1cbiAgICBpZiAoa2V5LmFsZ29yaXRobSAmJiB1c2FnZSA9PT0gJ2VuY3J5cHQnICYmIGtleS50eXBlID09PSAncHJpdmF0ZScpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHt0eXBlcy5qb2luKCcgb3IgJyl9IGluc3RhbmNlcyBmb3IgYXN5bW1ldHJpYyBhbGdvcml0aG0gZW5jcnlwdGlvbiBtdXN0IGJlIG9mIHR5cGUgXCJwdWJsaWNcImApO1xuICAgIH1cbn07XG5jb25zdCBjaGVja0tleVR5cGUgPSAoYWxnLCBrZXksIHVzYWdlKSA9PiB7XG4gICAgY29uc3Qgc3ltbWV0cmljID0gYWxnLnN0YXJ0c1dpdGgoJ0hTJykgfHxcbiAgICAgICAgYWxnID09PSAnZGlyJyB8fFxuICAgICAgICBhbGcuc3RhcnRzV2l0aCgnUEJFUzInKSB8fFxuICAgICAgICAvXkFcXGR7M30oPzpHQ00pP0tXJC8udGVzdChhbGcpO1xuICAgIGlmIChzeW1tZXRyaWMpIHtcbiAgICAgICAgc3ltbWV0cmljVHlwZUNoZWNrKGFsZywga2V5KTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIGFzeW1tZXRyaWNUeXBlQ2hlY2soYWxnLCBrZXksIHVzYWdlKTtcbiAgICB9XG59O1xuZXhwb3J0IGRlZmF1bHQgY2hlY2tLZXlUeXBlO1xuIiwiaW1wb3J0IHsgY29uY2F0LCB1aW50NjRiZSB9IGZyb20gJy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IGNoZWNrSXZMZW5ndGggZnJvbSAnLi4vbGliL2NoZWNrX2l2X2xlbmd0aC5qcyc7XG5pbXBvcnQgY2hlY2tDZWtMZW5ndGggZnJvbSAnLi9jaGVja19jZWtfbGVuZ3RoLmpzJztcbmltcG9ydCBjcnlwdG8sIHsgaXNDcnlwdG9LZXkgfSBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgeyBjaGVja0VuY0NyeXB0b0tleSB9IGZyb20gJy4uL2xpYi9jcnlwdG9fa2V5LmpzJztcbmltcG9ydCBpbnZhbGlkS2V5SW5wdXQgZnJvbSAnLi4vbGliL2ludmFsaWRfa2V5X2lucHV0LmpzJztcbmltcG9ydCBnZW5lcmF0ZUl2IGZyb20gJy4uL2xpYi9pdi5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmFzeW5jIGZ1bmN0aW9uIGNiY0VuY3J5cHQoZW5jLCBwbGFpbnRleHQsIGNlaywgaXYsIGFhZCkge1xuICAgIGlmICghKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGNlaywgJ1VpbnQ4QXJyYXknKSk7XG4gICAgfVxuICAgIGNvbnN0IGtleVNpemUgPSBwYXJzZUludChlbmMuc2xpY2UoMSwgNCksIDEwKTtcbiAgICBjb25zdCBlbmNLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLnN1YmFycmF5KGtleVNpemUgPj4gMyksICdBRVMtQ0JDJywgZmFsc2UsIFsnZW5jcnlwdCddKTtcbiAgICBjb25zdCBtYWNLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLnN1YmFycmF5KDAsIGtleVNpemUgPj4gMyksIHtcbiAgICAgICAgaGFzaDogYFNIQS0ke2tleVNpemUgPDwgMX1gLFxuICAgICAgICBuYW1lOiAnSE1BQycsXG4gICAgfSwgZmFsc2UsIFsnc2lnbiddKTtcbiAgICBjb25zdCBjaXBoZXJ0ZXh0ID0gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5lbmNyeXB0KHtcbiAgICAgICAgaXYsXG4gICAgICAgIG5hbWU6ICdBRVMtQ0JDJyxcbiAgICB9LCBlbmNLZXksIHBsYWludGV4dCkpO1xuICAgIGNvbnN0IG1hY0RhdGEgPSBjb25jYXQoYWFkLCBpdiwgY2lwaGVydGV4dCwgdWludDY0YmUoYWFkLmxlbmd0aCA8PCAzKSk7XG4gICAgY29uc3QgdGFnID0gbmV3IFVpbnQ4QXJyYXkoKGF3YWl0IGNyeXB0by5zdWJ0bGUuc2lnbignSE1BQycsIG1hY0tleSwgbWFjRGF0YSkpLnNsaWNlKDAsIGtleVNpemUgPj4gMykpO1xuICAgIHJldHVybiB7IGNpcGhlcnRleHQsIHRhZywgaXYgfTtcbn1cbmFzeW5jIGZ1bmN0aW9uIGdjbUVuY3J5cHQoZW5jLCBwbGFpbnRleHQsIGNlaywgaXYsIGFhZCkge1xuICAgIGxldCBlbmNLZXk7XG4gICAgaWYgKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgZW5jS2V5ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGNlaywgJ0FFUy1HQ00nLCBmYWxzZSwgWydlbmNyeXB0J10pO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgY2hlY2tFbmNDcnlwdG9LZXkoY2VrLCBlbmMsICdlbmNyeXB0Jyk7XG4gICAgICAgIGVuY0tleSA9IGNlaztcbiAgICB9XG4gICAgY29uc3QgZW5jcnlwdGVkID0gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5lbmNyeXB0KHtcbiAgICAgICAgYWRkaXRpb25hbERhdGE6IGFhZCxcbiAgICAgICAgaXYsXG4gICAgICAgIG5hbWU6ICdBRVMtR0NNJyxcbiAgICAgICAgdGFnTGVuZ3RoOiAxMjgsXG4gICAgfSwgZW5jS2V5LCBwbGFpbnRleHQpKTtcbiAgICBjb25zdCB0YWcgPSBlbmNyeXB0ZWQuc2xpY2UoLTE2KTtcbiAgICBjb25zdCBjaXBoZXJ0ZXh0ID0gZW5jcnlwdGVkLnNsaWNlKDAsIC0xNik7XG4gICAgcmV0dXJuIHsgY2lwaGVydGV4dCwgdGFnLCBpdiB9O1xufVxuY29uc3QgZW5jcnlwdCA9IGFzeW5jIChlbmMsIHBsYWludGV4dCwgY2VrLCBpdiwgYWFkKSA9PiB7XG4gICAgaWYgKCFpc0NyeXB0b0tleShjZWspICYmICEoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoY2VrLCAuLi50eXBlcywgJ1VpbnQ4QXJyYXknKSk7XG4gICAgfVxuICAgIGlmIChpdikge1xuICAgICAgICBjaGVja0l2TGVuZ3RoKGVuYywgaXYpO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgaXYgPSBnZW5lcmF0ZUl2KGVuYyk7XG4gICAgfVxuICAgIHN3aXRjaCAoZW5jKSB7XG4gICAgICAgIGNhc2UgJ0ExMjhDQkMtSFMyNTYnOlxuICAgICAgICBjYXNlICdBMTkyQ0JDLUhTMzg0JzpcbiAgICAgICAgY2FzZSAnQTI1NkNCQy1IUzUxMic6XG4gICAgICAgICAgICBpZiAoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICAgICAgICAgIGNoZWNrQ2VrTGVuZ3RoKGNlaywgcGFyc2VJbnQoZW5jLnNsaWNlKC0zKSwgMTApKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBjYmNFbmNyeXB0KGVuYywgcGxhaW50ZXh0LCBjZWssIGl2LCBhYWQpO1xuICAgICAgICBjYXNlICdBMTI4R0NNJzpcbiAgICAgICAgY2FzZSAnQTE5MkdDTSc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ00nOlxuICAgICAgICAgICAgaWYgKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgICAgICAgICBjaGVja0Nla0xlbmd0aChjZWssIHBhcnNlSW50KGVuYy5zbGljZSgxLCA0KSwgMTApKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBnY21FbmNyeXB0KGVuYywgcGxhaW50ZXh0LCBjZWssIGl2LCBhYWQpO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ1Vuc3VwcG9ydGVkIEpXRSBDb250ZW50IEVuY3J5cHRpb24gQWxnb3JpdGhtJyk7XG4gICAgfVxufTtcbmV4cG9ydCBkZWZhdWx0IGVuY3J5cHQ7XG4iLCJpbXBvcnQgZW5jcnlwdCBmcm9tICcuLi9ydW50aW1lL2VuY3J5cHQuanMnO1xuaW1wb3J0IGRlY3J5cHQgZnJvbSAnLi4vcnVudGltZS9kZWNyeXB0LmpzJztcbmltcG9ydCB7IGVuY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gd3JhcChhbGcsIGtleSwgY2VrLCBpdikge1xuICAgIGNvbnN0IGp3ZUFsZ29yaXRobSA9IGFsZy5zbGljZSgwLCA3KTtcbiAgICBjb25zdCB3cmFwcGVkID0gYXdhaXQgZW5jcnlwdChqd2VBbGdvcml0aG0sIGNlaywga2V5LCBpdiwgbmV3IFVpbnQ4QXJyYXkoMCkpO1xuICAgIHJldHVybiB7XG4gICAgICAgIGVuY3J5cHRlZEtleTogd3JhcHBlZC5jaXBoZXJ0ZXh0LFxuICAgICAgICBpdjogYmFzZTY0dXJsKHdyYXBwZWQuaXYpLFxuICAgICAgICB0YWc6IGJhc2U2NHVybCh3cmFwcGVkLnRhZyksXG4gICAgfTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB1bndyYXAoYWxnLCBrZXksIGVuY3J5cHRlZEtleSwgaXYsIHRhZykge1xuICAgIGNvbnN0IGp3ZUFsZ29yaXRobSA9IGFsZy5zbGljZSgwLCA3KTtcbiAgICByZXR1cm4gZGVjcnlwdChqd2VBbGdvcml0aG0sIGtleSwgZW5jcnlwdGVkS2V5LCBpdiwgdGFnLCBuZXcgVWludDhBcnJheSgwKSk7XG59XG4iLCJpbXBvcnQgeyB1bndyYXAgYXMgYWVzS3cgfSBmcm9tICcuLi9ydW50aW1lL2Flc2t3LmpzJztcbmltcG9ydCAqIGFzIEVDREggZnJvbSAnLi4vcnVudGltZS9lY2RoZXMuanMnO1xuaW1wb3J0IHsgZGVjcnlwdCBhcyBwYmVzMkt3IH0gZnJvbSAnLi4vcnVudGltZS9wYmVzMmt3LmpzJztcbmltcG9ydCB7IGRlY3J5cHQgYXMgcnNhRXMgfSBmcm9tICcuLi9ydW50aW1lL3JzYWVzLmpzJztcbmltcG9ydCB7IGRlY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkLCBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHsgYml0TGVuZ3RoIGFzIGNla0xlbmd0aCB9IGZyb20gJy4uL2xpYi9jZWsuanMnO1xuaW1wb3J0IHsgaW1wb3J0SldLIH0gZnJvbSAnLi4va2V5L2ltcG9ydC5qcyc7XG5pbXBvcnQgY2hlY2tLZXlUeXBlIGZyb20gJy4vY2hlY2tfa2V5X3R5cGUuanMnO1xuaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4vaXNfb2JqZWN0LmpzJztcbmltcG9ydCB7IHVud3JhcCBhcyBhZXNHY21LdyB9IGZyb20gJy4vYWVzZ2Nta3cuanMnO1xuYXN5bmMgZnVuY3Rpb24gZGVjcnlwdEtleU1hbmFnZW1lbnQoYWxnLCBrZXksIGVuY3J5cHRlZEtleSwgam9zZUhlYWRlciwgb3B0aW9ucykge1xuICAgIGNoZWNrS2V5VHlwZShhbGcsIGtleSwgJ2RlY3J5cHQnKTtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdkaXInOiB7XG4gICAgICAgICAgICBpZiAoZW5jcnlwdGVkS2V5ICE9PSB1bmRlZmluZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0VuY291bnRlcmVkIHVuZXhwZWN0ZWQgSldFIEVuY3J5cHRlZCBLZXknKTtcbiAgICAgICAgICAgIHJldHVybiBrZXk7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnRUNESC1FUyc6XG4gICAgICAgICAgICBpZiAoZW5jcnlwdGVkS2V5ICE9PSB1bmRlZmluZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0VuY291bnRlcmVkIHVuZXhwZWN0ZWQgSldFIEVuY3J5cHRlZCBLZXknKTtcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMTI4S1cnOlxuICAgICAgICBjYXNlICdFQ0RILUVTK0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTI1NktXJzoge1xuICAgICAgICAgICAgaWYgKCFpc09iamVjdChqb3NlSGVhZGVyLmVwaykpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwiZXBrXCIgKEVwaGVtZXJhbCBQdWJsaWMgS2V5KSBtaXNzaW5nIG9yIGludmFsaWRgKTtcbiAgICAgICAgICAgIGlmICghRUNESC5lY2RoQWxsb3dlZChrZXkpKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdFQ0RIIHdpdGggdGhlIHByb3ZpZGVkIGtleSBpcyBub3QgYWxsb3dlZCBvciBub3Qgc3VwcG9ydGVkIGJ5IHlvdXIgamF2YXNjcmlwdCBydW50aW1lJyk7XG4gICAgICAgICAgICBjb25zdCBlcGsgPSBhd2FpdCBpbXBvcnRKV0soam9zZUhlYWRlci5lcGssIGFsZyk7XG4gICAgICAgICAgICBsZXQgcGFydHlVSW5mbztcbiAgICAgICAgICAgIGxldCBwYXJ0eVZJbmZvO1xuICAgICAgICAgICAgaWYgKGpvc2VIZWFkZXIuYXB1ICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgICAgICBpZiAodHlwZW9mIGpvc2VIZWFkZXIuYXB1ICE9PSAnc3RyaW5nJylcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwiYXB1XCIgKEFncmVlbWVudCBQYXJ0eVVJbmZvKSBpbnZhbGlkYCk7XG4gICAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICAgICAgcGFydHlVSW5mbyA9IGJhc2U2NHVybChqb3NlSGVhZGVyLmFwdSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBhcHUnKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAoam9zZUhlYWRlci5hcHYgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgICAgIGlmICh0eXBlb2Ygam9zZUhlYWRlci5hcHYgIT09ICdzdHJpbmcnKVxuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSk9TRSBIZWFkZXIgXCJhcHZcIiAoQWdyZWVtZW50IFBhcnR5VkluZm8pIGludmFsaWRgKTtcbiAgICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgICAgICBwYXJ0eVZJbmZvID0gYmFzZTY0dXJsKGpvc2VIZWFkZXIuYXB2KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIGFwdicpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNvbnN0IHNoYXJlZFNlY3JldCA9IGF3YWl0IEVDREguZGVyaXZlS2V5KGVwaywga2V5LCBhbGcgPT09ICdFQ0RILUVTJyA/IGpvc2VIZWFkZXIuZW5jIDogYWxnLCBhbGcgPT09ICdFQ0RILUVTJyA/IGNla0xlbmd0aChqb3NlSGVhZGVyLmVuYykgOiBwYXJzZUludChhbGcuc2xpY2UoLTUsIC0yKSwgMTApLCBwYXJ0eVVJbmZvLCBwYXJ0eVZJbmZvKTtcbiAgICAgICAgICAgIGlmIChhbGcgPT09ICdFQ0RILUVTJylcbiAgICAgICAgICAgICAgICByZXR1cm4gc2hhcmVkU2VjcmV0O1xuICAgICAgICAgICAgaWYgKGVuY3J5cHRlZEtleSA9PT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgRW5jcnlwdGVkIEtleSBtaXNzaW5nJyk7XG4gICAgICAgICAgICByZXR1cm4gYWVzS3coYWxnLnNsaWNlKC02KSwgc2hhcmVkU2VjcmV0LCBlbmNyeXB0ZWRLZXkpO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ1JTQTFfNSc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQJzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMjU2JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMzg0JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtNTEyJzoge1xuICAgICAgICAgICAgaWYgKGVuY3J5cHRlZEtleSA9PT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgRW5jcnlwdGVkIEtleSBtaXNzaW5nJyk7XG4gICAgICAgICAgICByZXR1cm4gcnNhRXMoYWxnLCBrZXksIGVuY3J5cHRlZEtleSk7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnUEJFUzItSFMyNTYrQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnUEJFUzItSFMzODQrQTE5MktXJzpcbiAgICAgICAgY2FzZSAnUEJFUzItSFM1MTIrQTI1NktXJzoge1xuICAgICAgICAgICAgaWYgKGVuY3J5cHRlZEtleSA9PT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgRW5jcnlwdGVkIEtleSBtaXNzaW5nJyk7XG4gICAgICAgICAgICBpZiAodHlwZW9mIGpvc2VIZWFkZXIucDJjICE9PSAnbnVtYmVyJylcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSk9TRSBIZWFkZXIgXCJwMmNcIiAoUEJFUzIgQ291bnQpIG1pc3Npbmcgb3IgaW52YWxpZGApO1xuICAgICAgICAgICAgY29uc3QgcDJjTGltaXQgPSBvcHRpb25zPy5tYXhQQkVTMkNvdW50IHx8IDEwMDAwO1xuICAgICAgICAgICAgaWYgKGpvc2VIZWFkZXIucDJjID4gcDJjTGltaXQpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwicDJjXCIgKFBCRVMyIENvdW50KSBvdXQgaXMgb2YgYWNjZXB0YWJsZSBib3VuZHNgKTtcbiAgICAgICAgICAgIGlmICh0eXBlb2Ygam9zZUhlYWRlci5wMnMgIT09ICdzdHJpbmcnKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKGBKT1NFIEhlYWRlciBcInAyc1wiIChQQkVTMiBTYWx0KSBtaXNzaW5nIG9yIGludmFsaWRgKTtcbiAgICAgICAgICAgIGxldCBwMnM7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIHAycyA9IGJhc2U2NHVybChqb3NlSGVhZGVyLnAycyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBwMnMnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBwYmVzMkt3KGFsZywga2V5LCBlbmNyeXB0ZWRLZXksIGpvc2VIZWFkZXIucDJjLCBwMnMpO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGlmIChlbmNyeXB0ZWRLZXkgPT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEVuY3J5cHRlZCBLZXkgbWlzc2luZycpO1xuICAgICAgICAgICAgcmV0dXJuIGFlc0t3KGFsZywga2V5LCBlbmNyeXB0ZWRLZXkpO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0ExMjhHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ01LVyc6IHtcbiAgICAgICAgICAgIGlmIChlbmNyeXB0ZWRLZXkgPT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEVuY3J5cHRlZCBLZXkgbWlzc2luZycpO1xuICAgICAgICAgICAgaWYgKHR5cGVvZiBqb3NlSGVhZGVyLml2ICE9PSAnc3RyaW5nJylcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSk9TRSBIZWFkZXIgXCJpdlwiIChJbml0aWFsaXphdGlvbiBWZWN0b3IpIG1pc3Npbmcgb3IgaW52YWxpZGApO1xuICAgICAgICAgICAgaWYgKHR5cGVvZiBqb3NlSGVhZGVyLnRhZyAhPT0gJ3N0cmluZycpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwidGFnXCIgKEF1dGhlbnRpY2F0aW9uIFRhZykgbWlzc2luZyBvciBpbnZhbGlkYCk7XG4gICAgICAgICAgICBsZXQgaXY7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGl2ID0gYmFzZTY0dXJsKGpvc2VIZWFkZXIuaXYpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgaXYnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGxldCB0YWc7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIHRhZyA9IGJhc2U2NHVybChqb3NlSGVhZGVyLnRhZyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSB0YWcnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBhZXNHY21LdyhhbGcsIGtleSwgZW5jcnlwdGVkS2V5LCBpdiwgdGFnKTtcbiAgICAgICAgfVxuICAgICAgICBkZWZhdWx0OiB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBcImFsZ1wiIChKV0UgQWxnb3JpdGhtKSBoZWFkZXIgdmFsdWUnKTtcbiAgICAgICAgfVxuICAgIH1cbn1cbmV4cG9ydCBkZWZhdWx0IGRlY3J5cHRLZXlNYW5hZ2VtZW50O1xuIiwiaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmZ1bmN0aW9uIHZhbGlkYXRlQ3JpdChFcnIsIHJlY29nbml6ZWREZWZhdWx0LCByZWNvZ25pemVkT3B0aW9uLCBwcm90ZWN0ZWRIZWFkZXIsIGpvc2VIZWFkZXIpIHtcbiAgICBpZiAoam9zZUhlYWRlci5jcml0ICE9PSB1bmRlZmluZWQgJiYgcHJvdGVjdGVkSGVhZGVyPy5jcml0ID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycignXCJjcml0XCIgKENyaXRpY2FsKSBIZWFkZXIgUGFyYW1ldGVyIE1VU1QgYmUgaW50ZWdyaXR5IHByb3RlY3RlZCcpO1xuICAgIH1cbiAgICBpZiAoIXByb3RlY3RlZEhlYWRlciB8fCBwcm90ZWN0ZWRIZWFkZXIuY3JpdCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHJldHVybiBuZXcgU2V0KCk7XG4gICAgfVxuICAgIGlmICghQXJyYXkuaXNBcnJheShwcm90ZWN0ZWRIZWFkZXIuY3JpdCkgfHxcbiAgICAgICAgcHJvdGVjdGVkSGVhZGVyLmNyaXQubGVuZ3RoID09PSAwIHx8XG4gICAgICAgIHByb3RlY3RlZEhlYWRlci5jcml0LnNvbWUoKGlucHV0KSA9PiB0eXBlb2YgaW5wdXQgIT09ICdzdHJpbmcnIHx8IGlucHV0Lmxlbmd0aCA9PT0gMCkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycignXCJjcml0XCIgKENyaXRpY2FsKSBIZWFkZXIgUGFyYW1ldGVyIE1VU1QgYmUgYW4gYXJyYXkgb2Ygbm9uLWVtcHR5IHN0cmluZ3Mgd2hlbiBwcmVzZW50Jyk7XG4gICAgfVxuICAgIGxldCByZWNvZ25pemVkO1xuICAgIGlmIChyZWNvZ25pemVkT3B0aW9uICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmVjb2duaXplZCA9IG5ldyBNYXAoWy4uLk9iamVjdC5lbnRyaWVzKHJlY29nbml6ZWRPcHRpb24pLCAuLi5yZWNvZ25pemVkRGVmYXVsdC5lbnRyaWVzKCldKTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIHJlY29nbml6ZWQgPSByZWNvZ25pemVkRGVmYXVsdDtcbiAgICB9XG4gICAgZm9yIChjb25zdCBwYXJhbWV0ZXIgb2YgcHJvdGVjdGVkSGVhZGVyLmNyaXQpIHtcbiAgICAgICAgaWYgKCFyZWNvZ25pemVkLmhhcyhwYXJhbWV0ZXIpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZChgRXh0ZW5zaW9uIEhlYWRlciBQYXJhbWV0ZXIgXCIke3BhcmFtZXRlcn1cIiBpcyBub3QgcmVjb2duaXplZGApO1xuICAgICAgICB9XG4gICAgICAgIGlmIChqb3NlSGVhZGVyW3BhcmFtZXRlcl0gPT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycihgRXh0ZW5zaW9uIEhlYWRlciBQYXJhbWV0ZXIgXCIke3BhcmFtZXRlcn1cIiBpcyBtaXNzaW5nYCk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHJlY29nbml6ZWQuZ2V0KHBhcmFtZXRlcikgJiYgcHJvdGVjdGVkSGVhZGVyW3BhcmFtZXRlcl0gPT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycihgRXh0ZW5zaW9uIEhlYWRlciBQYXJhbWV0ZXIgXCIke3BhcmFtZXRlcn1cIiBNVVNUIGJlIGludGVncml0eSBwcm90ZWN0ZWRgKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gbmV3IFNldChwcm90ZWN0ZWRIZWFkZXIuY3JpdCk7XG59XG5leHBvcnQgZGVmYXVsdCB2YWxpZGF0ZUNyaXQ7XG4iLCJjb25zdCB2YWxpZGF0ZUFsZ29yaXRobXMgPSAob3B0aW9uLCBhbGdvcml0aG1zKSA9PiB7XG4gICAgaWYgKGFsZ29yaXRobXMgIT09IHVuZGVmaW5lZCAmJlxuICAgICAgICAoIUFycmF5LmlzQXJyYXkoYWxnb3JpdGhtcykgfHwgYWxnb3JpdGhtcy5zb21lKChzKSA9PiB0eXBlb2YgcyAhPT0gJ3N0cmluZycpKSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGBcIiR7b3B0aW9ufVwiIG9wdGlvbiBtdXN0IGJlIGFuIGFycmF5IG9mIHN0cmluZ3NgKTtcbiAgICB9XG4gICAgaWYgKCFhbGdvcml0aG1zKSB7XG4gICAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgfVxuICAgIHJldHVybiBuZXcgU2V0KGFsZ29yaXRobXMpO1xufTtcbmV4cG9ydCBkZWZhdWx0IHZhbGlkYXRlQWxnb3JpdGhtcztcbiIsImltcG9ydCB7IGRlY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi8uLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgZGVjcnlwdCBmcm9tICcuLi8uLi9ydW50aW1lL2RlY3J5cHQuanMnO1xuaW1wb3J0IHsgSk9TRUFsZ05vdEFsbG93ZWQsIEpPU0VOb3RTdXBwb3J0ZWQsIEpXRUludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgaXNEaXNqb2ludCBmcm9tICcuLi8uLi9saWIvaXNfZGlzam9pbnQuanMnO1xuaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4uLy4uL2xpYi9pc19vYmplY3QuanMnO1xuaW1wb3J0IGRlY3J5cHRLZXlNYW5hZ2VtZW50IGZyb20gJy4uLy4uL2xpYi9kZWNyeXB0X2tleV9tYW5hZ2VtZW50LmpzJztcbmltcG9ydCB7IGVuY29kZXIsIGRlY29kZXIsIGNvbmNhdCB9IGZyb20gJy4uLy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IGdlbmVyYXRlQ2VrIGZyb20gJy4uLy4uL2xpYi9jZWsuanMnO1xuaW1wb3J0IHZhbGlkYXRlQ3JpdCBmcm9tICcuLi8uLi9saWIvdmFsaWRhdGVfY3JpdC5qcyc7XG5pbXBvcnQgdmFsaWRhdGVBbGdvcml0aG1zIGZyb20gJy4uLy4uL2xpYi92YWxpZGF0ZV9hbGdvcml0aG1zLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBmbGF0dGVuZWREZWNyeXB0KGp3ZSwga2V5LCBvcHRpb25zKSB7XG4gICAgaWYgKCFpc09iamVjdChqd2UpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGbGF0dGVuZWQgSldFIG11c3QgYmUgYW4gb2JqZWN0Jyk7XG4gICAgfVxuICAgIGlmIChqd2UucHJvdGVjdGVkID09PSB1bmRlZmluZWQgJiYgandlLmhlYWRlciA9PT0gdW5kZWZpbmVkICYmIGp3ZS51bnByb3RlY3RlZCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKT1NFIEhlYWRlciBtaXNzaW5nJyk7XG4gICAgfVxuICAgIGlmIChqd2UuaXYgIT09IHVuZGVmaW5lZCAmJiB0eXBlb2YgandlLml2ICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEluaXRpYWxpemF0aW9uIFZlY3RvciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIGp3ZS5jaXBoZXJ0ZXh0ICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIENpcGhlcnRleHQgbWlzc2luZyBvciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoandlLnRhZyAhPT0gdW5kZWZpbmVkICYmIHR5cGVvZiBqd2UudGFnICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEF1dGhlbnRpY2F0aW9uIFRhZyBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoandlLnByb3RlY3RlZCAhPT0gdW5kZWZpbmVkICYmIHR5cGVvZiBqd2UucHJvdGVjdGVkICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFByb3RlY3RlZCBIZWFkZXIgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3ZS5lbmNyeXB0ZWRfa2V5ICE9PSB1bmRlZmluZWQgJiYgdHlwZW9mIGp3ZS5lbmNyeXB0ZWRfa2V5ICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEVuY3J5cHRlZCBLZXkgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3ZS5hYWQgIT09IHVuZGVmaW5lZCAmJiB0eXBlb2YgandlLmFhZCAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBBQUQgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3ZS5oZWFkZXIgIT09IHVuZGVmaW5lZCAmJiAhaXNPYmplY3QoandlLmhlYWRlcikpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBTaGFyZWQgVW5wcm90ZWN0ZWQgSGVhZGVyIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmIChqd2UudW5wcm90ZWN0ZWQgIT09IHVuZGVmaW5lZCAmJiAhaXNPYmplY3QoandlLnVucHJvdGVjdGVkKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFBlci1SZWNpcGllbnQgVW5wcm90ZWN0ZWQgSGVhZGVyIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGxldCBwYXJzZWRQcm90O1xuICAgIGlmIChqd2UucHJvdGVjdGVkKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBjb25zdCBwcm90ZWN0ZWRIZWFkZXIgPSBiYXNlNjR1cmwoandlLnByb3RlY3RlZCk7XG4gICAgICAgICAgICBwYXJzZWRQcm90ID0gSlNPTi5wYXJzZShkZWNvZGVyLmRlY29kZShwcm90ZWN0ZWRIZWFkZXIpKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFByb3RlY3RlZCBIZWFkZXIgaXMgaW52YWxpZCcpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGlmICghaXNEaXNqb2ludChwYXJzZWRQcm90LCBqd2UuaGVhZGVyLCBqd2UudW5wcm90ZWN0ZWQpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgUHJvdGVjdGVkLCBKV0UgVW5wcm90ZWN0ZWQgSGVhZGVyLCBhbmQgSldFIFBlci1SZWNpcGllbnQgVW5wcm90ZWN0ZWQgSGVhZGVyIFBhcmFtZXRlciBuYW1lcyBtdXN0IGJlIGRpc2pvaW50Jyk7XG4gICAgfVxuICAgIGNvbnN0IGpvc2VIZWFkZXIgPSB7XG4gICAgICAgIC4uLnBhcnNlZFByb3QsXG4gICAgICAgIC4uLmp3ZS5oZWFkZXIsXG4gICAgICAgIC4uLmp3ZS51bnByb3RlY3RlZCxcbiAgICB9O1xuICAgIHZhbGlkYXRlQ3JpdChKV0VJbnZhbGlkLCBuZXcgTWFwKCksIG9wdGlvbnM/LmNyaXQsIHBhcnNlZFByb3QsIGpvc2VIZWFkZXIpO1xuICAgIGlmIChqb3NlSGVhZGVyLnppcCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdKV0UgXCJ6aXBcIiAoQ29tcHJlc3Npb24gQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIGlzIG5vdCBzdXBwb3J0ZWQuJyk7XG4gICAgfVxuICAgIGNvbnN0IHsgYWxnLCBlbmMgfSA9IGpvc2VIZWFkZXI7XG4gICAgaWYgKHR5cGVvZiBhbGcgIT09ICdzdHJpbmcnIHx8ICFhbGcpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ21pc3NpbmcgSldFIEFsZ29yaXRobSAoYWxnKSBpbiBKV0UgSGVhZGVyJyk7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgZW5jICE9PSAnc3RyaW5nJyB8fCAhZW5jKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdtaXNzaW5nIEpXRSBFbmNyeXB0aW9uIEFsZ29yaXRobSAoZW5jKSBpbiBKV0UgSGVhZGVyJyk7XG4gICAgfVxuICAgIGNvbnN0IGtleU1hbmFnZW1lbnRBbGdvcml0aG1zID0gb3B0aW9ucyAmJiB2YWxpZGF0ZUFsZ29yaXRobXMoJ2tleU1hbmFnZW1lbnRBbGdvcml0aG1zJywgb3B0aW9ucy5rZXlNYW5hZ2VtZW50QWxnb3JpdGhtcyk7XG4gICAgY29uc3QgY29udGVudEVuY3J5cHRpb25BbGdvcml0aG1zID0gb3B0aW9ucyAmJlxuICAgICAgICB2YWxpZGF0ZUFsZ29yaXRobXMoJ2NvbnRlbnRFbmNyeXB0aW9uQWxnb3JpdGhtcycsIG9wdGlvbnMuY29udGVudEVuY3J5cHRpb25BbGdvcml0aG1zKTtcbiAgICBpZiAoKGtleU1hbmFnZW1lbnRBbGdvcml0aG1zICYmICFrZXlNYW5hZ2VtZW50QWxnb3JpdGhtcy5oYXMoYWxnKSkgfHxcbiAgICAgICAgKCFrZXlNYW5hZ2VtZW50QWxnb3JpdGhtcyAmJiBhbGcuc3RhcnRzV2l0aCgnUEJFUzInKSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpPU0VBbGdOb3RBbGxvd2VkKCdcImFsZ1wiIChBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgdmFsdWUgbm90IGFsbG93ZWQnKTtcbiAgICB9XG4gICAgaWYgKGNvbnRlbnRFbmNyeXB0aW9uQWxnb3JpdGhtcyAmJiAhY29udGVudEVuY3J5cHRpb25BbGdvcml0aG1zLmhhcyhlbmMpKSB7XG4gICAgICAgIHRocm93IG5ldyBKT1NFQWxnTm90QWxsb3dlZCgnXCJlbmNcIiAoRW5jcnlwdGlvbiBBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgdmFsdWUgbm90IGFsbG93ZWQnKTtcbiAgICB9XG4gICAgbGV0IGVuY3J5cHRlZEtleTtcbiAgICBpZiAoandlLmVuY3J5cHRlZF9rZXkgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgZW5jcnlwdGVkS2V5ID0gYmFzZTY0dXJsKGp3ZS5lbmNyeXB0ZWRfa2V5KTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIGVuY3J5cHRlZF9rZXknKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBsZXQgcmVzb2x2ZWRLZXkgPSBmYWxzZTtcbiAgICBpZiAodHlwZW9mIGtleSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICBrZXkgPSBhd2FpdCBrZXkocGFyc2VkUHJvdCwgandlKTtcbiAgICAgICAgcmVzb2x2ZWRLZXkgPSB0cnVlO1xuICAgIH1cbiAgICBsZXQgY2VrO1xuICAgIHRyeSB7XG4gICAgICAgIGNlayA9IGF3YWl0IGRlY3J5cHRLZXlNYW5hZ2VtZW50KGFsZywga2V5LCBlbmNyeXB0ZWRLZXksIGpvc2VIZWFkZXIsIG9wdGlvbnMpO1xuICAgIH1cbiAgICBjYXRjaCAoZXJyKSB7XG4gICAgICAgIGlmIChlcnIgaW5zdGFuY2VvZiBUeXBlRXJyb3IgfHwgZXJyIGluc3RhbmNlb2YgSldFSW52YWxpZCB8fCBlcnIgaW5zdGFuY2VvZiBKT1NFTm90U3VwcG9ydGVkKSB7XG4gICAgICAgICAgICB0aHJvdyBlcnI7XG4gICAgICAgIH1cbiAgICAgICAgY2VrID0gZ2VuZXJhdGVDZWsoZW5jKTtcbiAgICB9XG4gICAgbGV0IGl2O1xuICAgIGxldCB0YWc7XG4gICAgaWYgKGp3ZS5pdiAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBpdiA9IGJhc2U2NHVybChqd2UuaXYpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgaXYnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBpZiAoandlLnRhZyAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICB0YWcgPSBiYXNlNjR1cmwoandlLnRhZyk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSB0YWcnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBjb25zdCBwcm90ZWN0ZWRIZWFkZXIgPSBlbmNvZGVyLmVuY29kZShqd2UucHJvdGVjdGVkID8/ICcnKTtcbiAgICBsZXQgYWRkaXRpb25hbERhdGE7XG4gICAgaWYgKGp3ZS5hYWQgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICBhZGRpdGlvbmFsRGF0YSA9IGNvbmNhdChwcm90ZWN0ZWRIZWFkZXIsIGVuY29kZXIuZW5jb2RlKCcuJyksIGVuY29kZXIuZW5jb2RlKGp3ZS5hYWQpKTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIGFkZGl0aW9uYWxEYXRhID0gcHJvdGVjdGVkSGVhZGVyO1xuICAgIH1cbiAgICBsZXQgY2lwaGVydGV4dDtcbiAgICB0cnkge1xuICAgICAgICBjaXBoZXJ0ZXh0ID0gYmFzZTY0dXJsKGp3ZS5jaXBoZXJ0ZXh0KTtcbiAgICB9XG4gICAgY2F0Y2gge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIGNpcGhlcnRleHQnKTtcbiAgICB9XG4gICAgY29uc3QgcGxhaW50ZXh0ID0gYXdhaXQgZGVjcnlwdChlbmMsIGNlaywgY2lwaGVydGV4dCwgaXYsIHRhZywgYWRkaXRpb25hbERhdGEpO1xuICAgIGNvbnN0IHJlc3VsdCA9IHsgcGxhaW50ZXh0IH07XG4gICAgaWYgKGp3ZS5wcm90ZWN0ZWQgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICByZXN1bHQucHJvdGVjdGVkSGVhZGVyID0gcGFyc2VkUHJvdDtcbiAgICB9XG4gICAgaWYgKGp3ZS5hYWQgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgcmVzdWx0LmFkZGl0aW9uYWxBdXRoZW50aWNhdGVkRGF0YSA9IGJhc2U2NHVybChqd2UuYWFkKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIGFhZCcpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGlmIChqd2UudW5wcm90ZWN0ZWQgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICByZXN1bHQuc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIgPSBqd2UudW5wcm90ZWN0ZWQ7XG4gICAgfVxuICAgIGlmIChqd2UuaGVhZGVyICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmVzdWx0LnVucHJvdGVjdGVkSGVhZGVyID0gandlLmhlYWRlcjtcbiAgICB9XG4gICAgaWYgKHJlc29sdmVkS2V5KSB7XG4gICAgICAgIHJldHVybiB7IC4uLnJlc3VsdCwga2V5IH07XG4gICAgfVxuICAgIHJldHVybiByZXN1bHQ7XG59XG4iLCJpbXBvcnQgeyBmbGF0dGVuZWREZWNyeXB0IH0gZnJvbSAnLi4vZmxhdHRlbmVkL2RlY3J5cHQuanMnO1xuaW1wb3J0IHsgSldFSW52YWxpZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IGRlY29kZXIgfSBmcm9tICcuLi8uLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjb21wYWN0RGVjcnlwdChqd2UsIGtleSwgb3B0aW9ucykge1xuICAgIGlmIChqd2UgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIGp3ZSA9IGRlY29kZXIuZGVjb2RlKGp3ZSk7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgandlICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnQ29tcGFjdCBKV0UgbXVzdCBiZSBhIHN0cmluZyBvciBVaW50OEFycmF5Jyk7XG4gICAgfVxuICAgIGNvbnN0IHsgMDogcHJvdGVjdGVkSGVhZGVyLCAxOiBlbmNyeXB0ZWRLZXksIDI6IGl2LCAzOiBjaXBoZXJ0ZXh0LCA0OiB0YWcsIGxlbmd0aCwgfSA9IGp3ZS5zcGxpdCgnLicpO1xuICAgIGlmIChsZW5ndGggIT09IDUpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ludmFsaWQgQ29tcGFjdCBKV0UnKTtcbiAgICB9XG4gICAgY29uc3QgZGVjcnlwdGVkID0gYXdhaXQgZmxhdHRlbmVkRGVjcnlwdCh7XG4gICAgICAgIGNpcGhlcnRleHQsXG4gICAgICAgIGl2OiBpdiB8fCB1bmRlZmluZWQsXG4gICAgICAgIHByb3RlY3RlZDogcHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICB0YWc6IHRhZyB8fCB1bmRlZmluZWQsXG4gICAgICAgIGVuY3J5cHRlZF9rZXk6IGVuY3J5cHRlZEtleSB8fCB1bmRlZmluZWQsXG4gICAgfSwga2V5LCBvcHRpb25zKTtcbiAgICBjb25zdCByZXN1bHQgPSB7IHBsYWludGV4dDogZGVjcnlwdGVkLnBsYWludGV4dCwgcHJvdGVjdGVkSGVhZGVyOiBkZWNyeXB0ZWQucHJvdGVjdGVkSGVhZGVyIH07XG4gICAgaWYgKHR5cGVvZiBrZXkgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAgcmV0dXJuIHsgLi4ucmVzdWx0LCBrZXk6IGRlY3J5cHRlZC5rZXkgfTtcbiAgICB9XG4gICAgcmV0dXJuIHJlc3VsdDtcbn1cbiIsImltcG9ydCB7IGZsYXR0ZW5lZERlY3J5cHQgfSBmcm9tICcuLi9mbGF0dGVuZWQvZGVjcnlwdC5qcyc7XG5pbXBvcnQgeyBKV0VEZWNyeXB0aW9uRmFpbGVkLCBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4uLy4uL2xpYi9pc19vYmplY3QuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdlbmVyYWxEZWNyeXB0KGp3ZSwga2V5LCBvcHRpb25zKSB7XG4gICAgaWYgKCFpc09iamVjdChqd2UpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdHZW5lcmFsIEpXRSBtdXN0IGJlIGFuIG9iamVjdCcpO1xuICAgIH1cbiAgICBpZiAoIUFycmF5LmlzQXJyYXkoandlLnJlY2lwaWVudHMpIHx8ICFqd2UucmVjaXBpZW50cy5ldmVyeShpc09iamVjdCkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBSZWNpcGllbnRzIG1pc3Npbmcgb3IgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKCFqd2UucmVjaXBpZW50cy5sZW5ndGgpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBSZWNpcGllbnRzIGhhcyBubyBtZW1iZXJzJyk7XG4gICAgfVxuICAgIGZvciAoY29uc3QgcmVjaXBpZW50IG9mIGp3ZS5yZWNpcGllbnRzKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICByZXR1cm4gYXdhaXQgZmxhdHRlbmVkRGVjcnlwdCh7XG4gICAgICAgICAgICAgICAgYWFkOiBqd2UuYWFkLFxuICAgICAgICAgICAgICAgIGNpcGhlcnRleHQ6IGp3ZS5jaXBoZXJ0ZXh0LFxuICAgICAgICAgICAgICAgIGVuY3J5cHRlZF9rZXk6IHJlY2lwaWVudC5lbmNyeXB0ZWRfa2V5LFxuICAgICAgICAgICAgICAgIGhlYWRlcjogcmVjaXBpZW50LmhlYWRlcixcbiAgICAgICAgICAgICAgICBpdjogandlLml2LFxuICAgICAgICAgICAgICAgIHByb3RlY3RlZDogandlLnByb3RlY3RlZCxcbiAgICAgICAgICAgICAgICB0YWc6IGp3ZS50YWcsXG4gICAgICAgICAgICAgICAgdW5wcm90ZWN0ZWQ6IGp3ZS51bnByb3RlY3RlZCxcbiAgICAgICAgICAgIH0sIGtleSwgb3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICB9XG4gICAgfVxuICAgIHRocm93IG5ldyBKV0VEZWNyeXB0aW9uRmFpbGVkKCk7XG59XG4iLCJpbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IHsgZW5jb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4vYmFzZTY0dXJsLmpzJztcbmltcG9ydCB7IHR5cGVzIH0gZnJvbSAnLi9pc19rZXlfbGlrZS5qcyc7XG5jb25zdCBrZXlUb0pXSyA9IGFzeW5jIChrZXkpID0+IHtcbiAgICBpZiAoa2V5IGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAga3R5OiAnb2N0JyxcbiAgICAgICAgICAgIGs6IGJhc2U2NHVybChrZXkpLFxuICAgICAgICB9O1xuICAgIH1cbiAgICBpZiAoIWlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcywgJ1VpbnQ4QXJyYXknKSk7XG4gICAgfVxuICAgIGlmICgha2V5LmV4dHJhY3RhYmxlKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ25vbi1leHRyYWN0YWJsZSBDcnlwdG9LZXkgY2Fubm90IGJlIGV4cG9ydGVkIGFzIGEgSldLJyk7XG4gICAgfVxuICAgIGNvbnN0IHsgZXh0LCBrZXlfb3BzLCBhbGcsIHVzZSwgLi4uandrIH0gPSBhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgnandrJywga2V5KTtcbiAgICByZXR1cm4gandrO1xufTtcbmV4cG9ydCBkZWZhdWx0IGtleVRvSldLO1xuIiwiaW1wb3J0IHsgdG9TUEtJIGFzIGV4cG9ydFB1YmxpYyB9IGZyb20gJy4uL3J1bnRpbWUvYXNuMS5qcyc7XG5pbXBvcnQgeyB0b1BLQ1M4IGFzIGV4cG9ydFByaXZhdGUgfSBmcm9tICcuLi9ydW50aW1lL2FzbjEuanMnO1xuaW1wb3J0IGtleVRvSldLIGZyb20gJy4uL3J1bnRpbWUva2V5X3RvX2p3ay5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZXhwb3J0U1BLSShrZXkpIHtcbiAgICByZXR1cm4gZXhwb3J0UHVibGljKGtleSk7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZXhwb3J0UEtDUzgoa2V5KSB7XG4gICAgcmV0dXJuIGV4cG9ydFByaXZhdGUoa2V5KTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBleHBvcnRKV0soa2V5KSB7XG4gICAgcmV0dXJuIGtleVRvSldLKGtleSk7XG59XG4iLCJpbXBvcnQgeyB3cmFwIGFzIGFlc0t3IH0gZnJvbSAnLi4vcnVudGltZS9hZXNrdy5qcyc7XG5pbXBvcnQgKiBhcyBFQ0RIIGZyb20gJy4uL3J1bnRpbWUvZWNkaGVzLmpzJztcbmltcG9ydCB7IGVuY3J5cHQgYXMgcGJlczJLdyB9IGZyb20gJy4uL3J1bnRpbWUvcGJlczJrdy5qcyc7XG5pbXBvcnQgeyBlbmNyeXB0IGFzIHJzYUVzIH0gZnJvbSAnLi4vcnVudGltZS9yc2Flcy5qcyc7XG5pbXBvcnQgeyBlbmNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IGdlbmVyYXRlQ2VrLCB7IGJpdExlbmd0aCBhcyBjZWtMZW5ndGggfSBmcm9tICcuLi9saWIvY2VrLmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgeyBleHBvcnRKV0sgfSBmcm9tICcuLi9rZXkvZXhwb3J0LmpzJztcbmltcG9ydCBjaGVja0tleVR5cGUgZnJvbSAnLi9jaGVja19rZXlfdHlwZS5qcyc7XG5pbXBvcnQgeyB3cmFwIGFzIGFlc0djbUt3IH0gZnJvbSAnLi9hZXNnY21rdy5qcyc7XG5hc3luYyBmdW5jdGlvbiBlbmNyeXB0S2V5TWFuYWdlbWVudChhbGcsIGVuYywga2V5LCBwcm92aWRlZENlaywgcHJvdmlkZWRQYXJhbWV0ZXJzID0ge30pIHtcbiAgICBsZXQgZW5jcnlwdGVkS2V5O1xuICAgIGxldCBwYXJhbWV0ZXJzO1xuICAgIGxldCBjZWs7XG4gICAgY2hlY2tLZXlUeXBlKGFsZywga2V5LCAnZW5jcnlwdCcpO1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ2Rpcic6IHtcbiAgICAgICAgICAgIGNlayA9IGtleTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0VDREgtRVMnOlxuICAgICAgICBjYXNlICdFQ0RILUVTK0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTE5MktXJzpcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMjU2S1cnOiB7XG4gICAgICAgICAgICBpZiAoIUVDREguZWNkaEFsbG93ZWQoa2V5KSkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdFQ0RIIHdpdGggdGhlIHByb3ZpZGVkIGtleSBpcyBub3QgYWxsb3dlZCBvciBub3Qgc3VwcG9ydGVkIGJ5IHlvdXIgamF2YXNjcmlwdCBydW50aW1lJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjb25zdCB7IGFwdSwgYXB2IH0gPSBwcm92aWRlZFBhcmFtZXRlcnM7XG4gICAgICAgICAgICBsZXQgeyBlcGs6IGVwaGVtZXJhbEtleSB9ID0gcHJvdmlkZWRQYXJhbWV0ZXJzO1xuICAgICAgICAgICAgZXBoZW1lcmFsS2V5IHx8IChlcGhlbWVyYWxLZXkgPSAoYXdhaXQgRUNESC5nZW5lcmF0ZUVwayhrZXkpKS5wcml2YXRlS2V5KTtcbiAgICAgICAgICAgIGNvbnN0IHsgeCwgeSwgY3J2LCBrdHkgfSA9IGF3YWl0IGV4cG9ydEpXSyhlcGhlbWVyYWxLZXkpO1xuICAgICAgICAgICAgY29uc3Qgc2hhcmVkU2VjcmV0ID0gYXdhaXQgRUNESC5kZXJpdmVLZXkoa2V5LCBlcGhlbWVyYWxLZXksIGFsZyA9PT0gJ0VDREgtRVMnID8gZW5jIDogYWxnLCBhbGcgPT09ICdFQ0RILUVTJyA/IGNla0xlbmd0aChlbmMpIDogcGFyc2VJbnQoYWxnLnNsaWNlKC01LCAtMiksIDEwKSwgYXB1LCBhcHYpO1xuICAgICAgICAgICAgcGFyYW1ldGVycyA9IHsgZXBrOiB7IHgsIGNydiwga3R5IH0gfTtcbiAgICAgICAgICAgIGlmIChrdHkgPT09ICdFQycpXG4gICAgICAgICAgICAgICAgcGFyYW1ldGVycy5lcGsueSA9IHk7XG4gICAgICAgICAgICBpZiAoYXB1KVxuICAgICAgICAgICAgICAgIHBhcmFtZXRlcnMuYXB1ID0gYmFzZTY0dXJsKGFwdSk7XG4gICAgICAgICAgICBpZiAoYXB2KVxuICAgICAgICAgICAgICAgIHBhcmFtZXRlcnMuYXB2ID0gYmFzZTY0dXJsKGFwdik7XG4gICAgICAgICAgICBpZiAoYWxnID09PSAnRUNESC1FUycpIHtcbiAgICAgICAgICAgICAgICBjZWsgPSBzaGFyZWRTZWNyZXQ7XG4gICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjZWsgPSBwcm92aWRlZENlayB8fCBnZW5lcmF0ZUNlayhlbmMpO1xuICAgICAgICAgICAgY29uc3Qga3dBbGcgPSBhbGcuc2xpY2UoLTYpO1xuICAgICAgICAgICAgZW5jcnlwdGVkS2V5ID0gYXdhaXQgYWVzS3coa3dBbGcsIHNoYXJlZFNlY3JldCwgY2VrKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ1JTQTFfNSc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQJzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMjU2JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMzg0JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtNTEyJzoge1xuICAgICAgICAgICAgY2VrID0gcHJvdmlkZWRDZWsgfHwgZ2VuZXJhdGVDZWsoZW5jKTtcbiAgICAgICAgICAgIGVuY3J5cHRlZEtleSA9IGF3YWl0IHJzYUVzKGFsZywga2V5LCBjZWspO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnUEJFUzItSFMyNTYrQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnUEJFUzItSFMzODQrQTE5MktXJzpcbiAgICAgICAgY2FzZSAnUEJFUzItSFM1MTIrQTI1NktXJzoge1xuICAgICAgICAgICAgY2VrID0gcHJvdmlkZWRDZWsgfHwgZ2VuZXJhdGVDZWsoZW5jKTtcbiAgICAgICAgICAgIGNvbnN0IHsgcDJjLCBwMnMgfSA9IHByb3ZpZGVkUGFyYW1ldGVycztcbiAgICAgICAgICAgICh7IGVuY3J5cHRlZEtleSwgLi4ucGFyYW1ldGVycyB9ID0gYXdhaXQgcGJlczJLdyhhbGcsIGtleSwgY2VrLCBwMmMsIHAycykpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnQTE5MktXJzpcbiAgICAgICAgY2FzZSAnQTI1NktXJzoge1xuICAgICAgICAgICAgY2VrID0gcHJvdmlkZWRDZWsgfHwgZ2VuZXJhdGVDZWsoZW5jKTtcbiAgICAgICAgICAgIGVuY3J5cHRlZEtleSA9IGF3YWl0IGFlc0t3KGFsZywga2V5LCBjZWspO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnQTEyOEdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTE5MkdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTUtXJzoge1xuICAgICAgICAgICAgY2VrID0gcHJvdmlkZWRDZWsgfHwgZ2VuZXJhdGVDZWsoZW5jKTtcbiAgICAgICAgICAgIGNvbnN0IHsgaXYgfSA9IHByb3ZpZGVkUGFyYW1ldGVycztcbiAgICAgICAgICAgICh7IGVuY3J5cHRlZEtleSwgLi4ucGFyYW1ldGVycyB9ID0gYXdhaXQgYWVzR2NtS3coYWxnLCBrZXksIGNlaywgaXYpKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGRlZmF1bHQ6IHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIFwiYWxnXCIgKEpXRSBBbGdvcml0aG0pIGhlYWRlciB2YWx1ZScpO1xuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiB7IGNlaywgZW5jcnlwdGVkS2V5LCBwYXJhbWV0ZXJzIH07XG59XG5leHBvcnQgZGVmYXVsdCBlbmNyeXB0S2V5TWFuYWdlbWVudDtcbiIsImltcG9ydCB7IGVuY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi8uLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgZW5jcnlwdCBmcm9tICcuLi8uLi9ydW50aW1lL2VuY3J5cHQuanMnO1xuaW1wb3J0IGVuY3J5cHRLZXlNYW5hZ2VtZW50IGZyb20gJy4uLy4uL2xpYi9lbmNyeXB0X2tleV9tYW5hZ2VtZW50LmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQsIEpXRUludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgaXNEaXNqb2ludCBmcm9tICcuLi8uLi9saWIvaXNfZGlzam9pbnQuanMnO1xuaW1wb3J0IHsgZW5jb2RlciwgZGVjb2RlciwgY29uY2F0IH0gZnJvbSAnLi4vLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgdmFsaWRhdGVDcml0IGZyb20gJy4uLy4uL2xpYi92YWxpZGF0ZV9jcml0LmpzJztcbmV4cG9ydCBjb25zdCB1bnByb3RlY3RlZCA9IFN5bWJvbCgpO1xuZXhwb3J0IGNsYXNzIEZsYXR0ZW5lZEVuY3J5cHQge1xuICAgIGNvbnN0cnVjdG9yKHBsYWludGV4dCkge1xuICAgICAgICBpZiAoIShwbGFpbnRleHQgaW5zdGFuY2VvZiBVaW50OEFycmF5KSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcigncGxhaW50ZXh0IG11c3QgYmUgYW4gaW5zdGFuY2Ugb2YgVWludDhBcnJheScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3BsYWludGV4dCA9IHBsYWludGV4dDtcbiAgICB9XG4gICAgc2V0S2V5TWFuYWdlbWVudFBhcmFtZXRlcnMocGFyYW1ldGVycykge1xuICAgICAgICBpZiAodGhpcy5fa2V5TWFuYWdlbWVudFBhcmFtZXRlcnMpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldEtleU1hbmFnZW1lbnRQYXJhbWV0ZXJzIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fa2V5TWFuYWdlbWVudFBhcmFtZXRlcnMgPSBwYXJhbWV0ZXJzO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy5fcHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRQcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9wcm90ZWN0ZWRIZWFkZXIgPSBwcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRTaGFyZWRVbnByb3RlY3RlZEhlYWRlcihzaGFyZWRVbnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFNoYXJlZFVucHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIgPSBzaGFyZWRVbnByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldFVucHJvdGVjdGVkSGVhZGVyKHVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLl91bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0VW5wcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl91bnByb3RlY3RlZEhlYWRlciA9IHVucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0QWRkaXRpb25hbEF1dGhlbnRpY2F0ZWREYXRhKGFhZCkge1xuICAgICAgICB0aGlzLl9hYWQgPSBhYWQ7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRDb250ZW50RW5jcnlwdGlvbktleShjZWspIHtcbiAgICAgICAgaWYgKHRoaXMuX2Nlaykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0Q29udGVudEVuY3J5cHRpb25LZXkgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9jZWsgPSBjZWs7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRJbml0aWFsaXphdGlvblZlY3Rvcihpdikge1xuICAgICAgICBpZiAodGhpcy5faXYpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldEluaXRpYWxpemF0aW9uVmVjdG9yIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5faXYgPSBpdjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIGFzeW5jIGVuY3J5cHQoa2V5LCBvcHRpb25zKSB7XG4gICAgICAgIGlmICghdGhpcy5fcHJvdGVjdGVkSGVhZGVyICYmICF0aGlzLl91bnByb3RlY3RlZEhlYWRlciAmJiAhdGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdlaXRoZXIgc2V0UHJvdGVjdGVkSGVhZGVyLCBzZXRVbnByb3RlY3RlZEhlYWRlciwgb3Igc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIgbXVzdCBiZSBjYWxsZWQgYmVmb3JlICNlbmNyeXB0KCknKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIWlzRGlzam9pbnQodGhpcy5fcHJvdGVjdGVkSGVhZGVyLCB0aGlzLl91bnByb3RlY3RlZEhlYWRlciwgdGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFByb3RlY3RlZCwgSldFIFNoYXJlZCBVbnByb3RlY3RlZCBhbmQgSldFIFBlci1SZWNpcGllbnQgSGVhZGVyIFBhcmFtZXRlciBuYW1lcyBtdXN0IGJlIGRpc2pvaW50Jyk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3Qgam9zZUhlYWRlciA9IHtcbiAgICAgICAgICAgIC4uLnRoaXMuX3Byb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgIC4uLnRoaXMuX3VucHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgLi4udGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgIH07XG4gICAgICAgIHZhbGlkYXRlQ3JpdChKV0VJbnZhbGlkLCBuZXcgTWFwKCksIG9wdGlvbnM/LmNyaXQsIHRoaXMuX3Byb3RlY3RlZEhlYWRlciwgam9zZUhlYWRlcik7XG4gICAgICAgIGlmIChqb3NlSGVhZGVyLnppcCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSldFIFwiemlwXCIgKENvbXByZXNzaW9uIEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBpcyBub3Qgc3VwcG9ydGVkLicpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHsgYWxnLCBlbmMgfSA9IGpvc2VIZWFkZXI7XG4gICAgICAgIGlmICh0eXBlb2YgYWxnICE9PSAnc3RyaW5nJyB8fCAhYWxnKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFwiYWxnXCIgKEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBtaXNzaW5nIG9yIGludmFsaWQnKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodHlwZW9mIGVuYyAhPT0gJ3N0cmluZycgfHwgIWVuYykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBcImVuY1wiIChFbmNyeXB0aW9uIEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBtaXNzaW5nIG9yIGludmFsaWQnKTtcbiAgICAgICAgfVxuICAgICAgICBsZXQgZW5jcnlwdGVkS2V5O1xuICAgICAgICBpZiAodGhpcy5fY2VrICYmIChhbGcgPT09ICdkaXInIHx8IGFsZyA9PT0gJ0VDREgtRVMnKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgc2V0Q29udGVudEVuY3J5cHRpb25LZXkgY2Fubm90IGJlIGNhbGxlZCB3aXRoIEpXRSBcImFsZ1wiIChBbGdvcml0aG0pIEhlYWRlciAke2FsZ31gKTtcbiAgICAgICAgfVxuICAgICAgICBsZXQgY2VrO1xuICAgICAgICB7XG4gICAgICAgICAgICBsZXQgcGFyYW1ldGVycztcbiAgICAgICAgICAgICh7IGNlaywgZW5jcnlwdGVkS2V5LCBwYXJhbWV0ZXJzIH0gPSBhd2FpdCBlbmNyeXB0S2V5TWFuYWdlbWVudChhbGcsIGVuYywga2V5LCB0aGlzLl9jZWssIHRoaXMuX2tleU1hbmFnZW1lbnRQYXJhbWV0ZXJzKSk7XG4gICAgICAgICAgICBpZiAocGFyYW1ldGVycykge1xuICAgICAgICAgICAgICAgIGlmIChvcHRpb25zICYmIHVucHJvdGVjdGVkIGluIG9wdGlvbnMpIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCF0aGlzLl91bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5zZXRVbnByb3RlY3RlZEhlYWRlcihwYXJhbWV0ZXJzKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyID0geyAuLi50aGlzLl91bnByb3RlY3RlZEhlYWRlciwgLi4ucGFyYW1ldGVycyB9O1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIXRoaXMuX3Byb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5zZXRQcm90ZWN0ZWRIZWFkZXIocGFyYW1ldGVycyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9wcm90ZWN0ZWRIZWFkZXIgPSB7IC4uLnRoaXMuX3Byb3RlY3RlZEhlYWRlciwgLi4ucGFyYW1ldGVycyB9O1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIGxldCBhZGRpdGlvbmFsRGF0YTtcbiAgICAgICAgbGV0IHByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgbGV0IGFhZE1lbWJlcjtcbiAgICAgICAgaWYgKHRoaXMuX3Byb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgcHJvdGVjdGVkSGVhZGVyID0gZW5jb2Rlci5lbmNvZGUoYmFzZTY0dXJsKEpTT04uc3RyaW5naWZ5KHRoaXMuX3Byb3RlY3RlZEhlYWRlcikpKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHByb3RlY3RlZEhlYWRlciA9IGVuY29kZXIuZW5jb2RlKCcnKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5fYWFkKSB7XG4gICAgICAgICAgICBhYWRNZW1iZXIgPSBiYXNlNjR1cmwodGhpcy5fYWFkKTtcbiAgICAgICAgICAgIGFkZGl0aW9uYWxEYXRhID0gY29uY2F0KHByb3RlY3RlZEhlYWRlciwgZW5jb2Rlci5lbmNvZGUoJy4nKSwgZW5jb2Rlci5lbmNvZGUoYWFkTWVtYmVyKSk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBhZGRpdGlvbmFsRGF0YSA9IHByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCB7IGNpcGhlcnRleHQsIHRhZywgaXYgfSA9IGF3YWl0IGVuY3J5cHQoZW5jLCB0aGlzLl9wbGFpbnRleHQsIGNlaywgdGhpcy5faXYsIGFkZGl0aW9uYWxEYXRhKTtcbiAgICAgICAgY29uc3QgandlID0ge1xuICAgICAgICAgICAgY2lwaGVydGV4dDogYmFzZTY0dXJsKGNpcGhlcnRleHQpLFxuICAgICAgICB9O1xuICAgICAgICBpZiAoaXYpIHtcbiAgICAgICAgICAgIGp3ZS5pdiA9IGJhc2U2NHVybChpdik7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRhZykge1xuICAgICAgICAgICAgandlLnRhZyA9IGJhc2U2NHVybCh0YWcpO1xuICAgICAgICB9XG4gICAgICAgIGlmIChlbmNyeXB0ZWRLZXkpIHtcbiAgICAgICAgICAgIGp3ZS5lbmNyeXB0ZWRfa2V5ID0gYmFzZTY0dXJsKGVuY3J5cHRlZEtleSk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGFhZE1lbWJlcikge1xuICAgICAgICAgICAgandlLmFhZCA9IGFhZE1lbWJlcjtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5fcHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICBqd2UucHJvdGVjdGVkID0gZGVjb2Rlci5kZWNvZGUocHJvdGVjdGVkSGVhZGVyKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIGp3ZS51bnByb3RlY3RlZCA9IHRoaXMuX3NoYXJlZFVucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl91bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgandlLmhlYWRlciA9IHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBqd2U7XG4gICAgfVxufVxuIiwiaW1wb3J0IHsgRmxhdHRlbmVkRW5jcnlwdCwgdW5wcm90ZWN0ZWQgfSBmcm9tICcuLi9mbGF0dGVuZWQvZW5jcnlwdC5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkLCBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IGdlbmVyYXRlQ2VrIGZyb20gJy4uLy4uL2xpYi9jZWsuanMnO1xuaW1wb3J0IGlzRGlzam9pbnQgZnJvbSAnLi4vLi4vbGliL2lzX2Rpc2pvaW50LmpzJztcbmltcG9ydCBlbmNyeXB0S2V5TWFuYWdlbWVudCBmcm9tICcuLi8uLi9saWIvZW5jcnlwdF9rZXlfbWFuYWdlbWVudC5qcyc7XG5pbXBvcnQgeyBlbmNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi4vLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHZhbGlkYXRlQ3JpdCBmcm9tICcuLi8uLi9saWIvdmFsaWRhdGVfY3JpdC5qcyc7XG5jbGFzcyBJbmRpdmlkdWFsUmVjaXBpZW50IHtcbiAgICBjb25zdHJ1Y3RvcihlbmMsIGtleSwgb3B0aW9ucykge1xuICAgICAgICB0aGlzLnBhcmVudCA9IGVuYztcbiAgICAgICAgdGhpcy5rZXkgPSBrZXk7XG4gICAgICAgIHRoaXMub3B0aW9ucyA9IG9wdGlvbnM7XG4gICAgfVxuICAgIHNldFVucHJvdGVjdGVkSGVhZGVyKHVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLnVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRVbnByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMudW5wcm90ZWN0ZWRIZWFkZXIgPSB1bnByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIGFkZFJlY2lwaWVudCguLi5hcmdzKSB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhcmVudC5hZGRSZWNpcGllbnQoLi4uYXJncyk7XG4gICAgfVxuICAgIGVuY3J5cHQoLi4uYXJncykge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXJlbnQuZW5jcnlwdCguLi5hcmdzKTtcbiAgICB9XG4gICAgZG9uZSgpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGFyZW50O1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBHZW5lcmFsRW5jcnlwdCB7XG4gICAgY29uc3RydWN0b3IocGxhaW50ZXh0KSB7XG4gICAgICAgIHRoaXMuX3JlY2lwaWVudHMgPSBbXTtcbiAgICAgICAgdGhpcy5fcGxhaW50ZXh0ID0gcGxhaW50ZXh0O1xuICAgIH1cbiAgICBhZGRSZWNpcGllbnQoa2V5LCBvcHRpb25zKSB7XG4gICAgICAgIGNvbnN0IHJlY2lwaWVudCA9IG5ldyBJbmRpdmlkdWFsUmVjaXBpZW50KHRoaXMsIGtleSwgeyBjcml0OiBvcHRpb25zPy5jcml0IH0pO1xuICAgICAgICB0aGlzLl9yZWNpcGllbnRzLnB1c2gocmVjaXBpZW50KTtcbiAgICAgICAgcmV0dXJuIHJlY2lwaWVudDtcbiAgICB9XG4gICAgc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy5fcHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRQcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9wcm90ZWN0ZWRIZWFkZXIgPSBwcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRTaGFyZWRVbnByb3RlY3RlZEhlYWRlcihzaGFyZWRVbnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFNoYXJlZFVucHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIgPSBzaGFyZWRVbnByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldEFkZGl0aW9uYWxBdXRoZW50aWNhdGVkRGF0YShhYWQpIHtcbiAgICAgICAgdGhpcy5fYWFkID0gYWFkO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgYXN5bmMgZW5jcnlwdCgpIHtcbiAgICAgICAgaWYgKCF0aGlzLl9yZWNpcGllbnRzLmxlbmd0aCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ2F0IGxlYXN0IG9uZSByZWNpcGllbnQgbXVzdCBiZSBhZGRlZCcpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl9yZWNpcGllbnRzLmxlbmd0aCA9PT0gMSkge1xuICAgICAgICAgICAgY29uc3QgW3JlY2lwaWVudF0gPSB0aGlzLl9yZWNpcGllbnRzO1xuICAgICAgICAgICAgY29uc3QgZmxhdHRlbmVkID0gYXdhaXQgbmV3IEZsYXR0ZW5lZEVuY3J5cHQodGhpcy5fcGxhaW50ZXh0KVxuICAgICAgICAgICAgICAgIC5zZXRBZGRpdGlvbmFsQXV0aGVudGljYXRlZERhdGEodGhpcy5fYWFkKVxuICAgICAgICAgICAgICAgIC5zZXRQcm90ZWN0ZWRIZWFkZXIodGhpcy5fcHJvdGVjdGVkSGVhZGVyKVxuICAgICAgICAgICAgICAgIC5zZXRTaGFyZWRVbnByb3RlY3RlZEhlYWRlcih0aGlzLl91bnByb3RlY3RlZEhlYWRlcilcbiAgICAgICAgICAgICAgICAuc2V0VW5wcm90ZWN0ZWRIZWFkZXIocmVjaXBpZW50LnVucHJvdGVjdGVkSGVhZGVyKVxuICAgICAgICAgICAgICAgIC5lbmNyeXB0KHJlY2lwaWVudC5rZXksIHsgLi4ucmVjaXBpZW50Lm9wdGlvbnMgfSk7XG4gICAgICAgICAgICBjb25zdCBqd2UgPSB7XG4gICAgICAgICAgICAgICAgY2lwaGVydGV4dDogZmxhdHRlbmVkLmNpcGhlcnRleHQsXG4gICAgICAgICAgICAgICAgaXY6IGZsYXR0ZW5lZC5pdixcbiAgICAgICAgICAgICAgICByZWNpcGllbnRzOiBbe31dLFxuICAgICAgICAgICAgICAgIHRhZzogZmxhdHRlbmVkLnRhZyxcbiAgICAgICAgICAgIH07XG4gICAgICAgICAgICBpZiAoZmxhdHRlbmVkLmFhZClcbiAgICAgICAgICAgICAgICBqd2UuYWFkID0gZmxhdHRlbmVkLmFhZDtcbiAgICAgICAgICAgIGlmIChmbGF0dGVuZWQucHJvdGVjdGVkKVxuICAgICAgICAgICAgICAgIGp3ZS5wcm90ZWN0ZWQgPSBmbGF0dGVuZWQucHJvdGVjdGVkO1xuICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC51bnByb3RlY3RlZClcbiAgICAgICAgICAgICAgICBqd2UudW5wcm90ZWN0ZWQgPSBmbGF0dGVuZWQudW5wcm90ZWN0ZWQ7XG4gICAgICAgICAgICBpZiAoZmxhdHRlbmVkLmVuY3J5cHRlZF9rZXkpXG4gICAgICAgICAgICAgICAgandlLnJlY2lwaWVudHNbMF0uZW5jcnlwdGVkX2tleSA9IGZsYXR0ZW5lZC5lbmNyeXB0ZWRfa2V5O1xuICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC5oZWFkZXIpXG4gICAgICAgICAgICAgICAgandlLnJlY2lwaWVudHNbMF0uaGVhZGVyID0gZmxhdHRlbmVkLmhlYWRlcjtcbiAgICAgICAgICAgIHJldHVybiBqd2U7XG4gICAgICAgIH1cbiAgICAgICAgbGV0IGVuYztcbiAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCB0aGlzLl9yZWNpcGllbnRzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBjb25zdCByZWNpcGllbnQgPSB0aGlzLl9yZWNpcGllbnRzW2ldO1xuICAgICAgICAgICAgaWYgKCFpc0Rpc2pvaW50KHRoaXMuX3Byb3RlY3RlZEhlYWRlciwgdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIsIHJlY2lwaWVudC51bnByb3RlY3RlZEhlYWRlcikpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFByb3RlY3RlZCwgSldFIFNoYXJlZCBVbnByb3RlY3RlZCBhbmQgSldFIFBlci1SZWNpcGllbnQgSGVhZGVyIFBhcmFtZXRlciBuYW1lcyBtdXN0IGJlIGRpc2pvaW50Jyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjb25zdCBqb3NlSGVhZGVyID0ge1xuICAgICAgICAgICAgICAgIC4uLnRoaXMuX3Byb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgICAgICAuLi50aGlzLl91bnByb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgICAgICAuLi5yZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAgY29uc3QgeyBhbGcgfSA9IGpvc2VIZWFkZXI7XG4gICAgICAgICAgICBpZiAodHlwZW9mIGFsZyAhPT0gJ3N0cmluZycgfHwgIWFsZykge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgXCJhbGdcIiAoQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIG1pc3Npbmcgb3IgaW52YWxpZCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKGFsZyA9PT0gJ2RpcicgfHwgYWxnID09PSAnRUNESC1FUycpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnXCJkaXJcIiBhbmQgXCJFQ0RILUVTXCIgYWxnIG1heSBvbmx5IGJlIHVzZWQgd2l0aCBhIHNpbmdsZSByZWNpcGllbnQnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmICh0eXBlb2Ygam9zZUhlYWRlci5lbmMgIT09ICdzdHJpbmcnIHx8ICFqb3NlSGVhZGVyLmVuYykge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgXCJlbmNcIiAoRW5jcnlwdGlvbiBBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgbWlzc2luZyBvciBpbnZhbGlkJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAoIWVuYykge1xuICAgICAgICAgICAgICAgIGVuYyA9IGpvc2VIZWFkZXIuZW5jO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZSBpZiAoZW5jICE9PSBqb3NlSGVhZGVyLmVuYykge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgXCJlbmNcIiAoRW5jcnlwdGlvbiBBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgbXVzdCBiZSB0aGUgc2FtZSBmb3IgYWxsIHJlY2lwaWVudHMnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHZhbGlkYXRlQ3JpdChKV0VJbnZhbGlkLCBuZXcgTWFwKCksIHJlY2lwaWVudC5vcHRpb25zLmNyaXQsIHRoaXMuX3Byb3RlY3RlZEhlYWRlciwgam9zZUhlYWRlcik7XG4gICAgICAgICAgICBpZiAoam9zZUhlYWRlci56aXAgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdKV0UgXCJ6aXBcIiAoQ29tcHJlc3Npb24gQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIGlzIG5vdCBzdXBwb3J0ZWQuJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgY2VrID0gZ2VuZXJhdGVDZWsoZW5jKTtcbiAgICAgICAgY29uc3QgandlID0ge1xuICAgICAgICAgICAgY2lwaGVydGV4dDogJycsXG4gICAgICAgICAgICBpdjogJycsXG4gICAgICAgICAgICByZWNpcGllbnRzOiBbXSxcbiAgICAgICAgICAgIHRhZzogJycsXG4gICAgICAgIH07XG4gICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgdGhpcy5fcmVjaXBpZW50cy5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgY29uc3QgcmVjaXBpZW50ID0gdGhpcy5fcmVjaXBpZW50c1tpXTtcbiAgICAgICAgICAgIGNvbnN0IHRhcmdldCA9IHt9O1xuICAgICAgICAgICAgandlLnJlY2lwaWVudHMucHVzaCh0YXJnZXQpO1xuICAgICAgICAgICAgY29uc3Qgam9zZUhlYWRlciA9IHtcbiAgICAgICAgICAgICAgICAuLi50aGlzLl9wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICAgICAgLi4udGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICAgICAgLi4ucmVjaXBpZW50LnVucHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIGNvbnN0IHAyYyA9IGpvc2VIZWFkZXIuYWxnLnN0YXJ0c1dpdGgoJ1BCRVMyJykgPyAyMDQ4ICsgaSA6IHVuZGVmaW5lZDtcbiAgICAgICAgICAgIGlmIChpID09PSAwKSB7XG4gICAgICAgICAgICAgICAgY29uc3QgZmxhdHRlbmVkID0gYXdhaXQgbmV3IEZsYXR0ZW5lZEVuY3J5cHQodGhpcy5fcGxhaW50ZXh0KVxuICAgICAgICAgICAgICAgICAgICAuc2V0QWRkaXRpb25hbEF1dGhlbnRpY2F0ZWREYXRhKHRoaXMuX2FhZClcbiAgICAgICAgICAgICAgICAgICAgLnNldENvbnRlbnRFbmNyeXB0aW9uS2V5KGNlaylcbiAgICAgICAgICAgICAgICAgICAgLnNldFByb3RlY3RlZEhlYWRlcih0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpXG4gICAgICAgICAgICAgICAgICAgIC5zZXRTaGFyZWRVbnByb3RlY3RlZEhlYWRlcih0aGlzLl91bnByb3RlY3RlZEhlYWRlcilcbiAgICAgICAgICAgICAgICAgICAgLnNldFVucHJvdGVjdGVkSGVhZGVyKHJlY2lwaWVudC51bnByb3RlY3RlZEhlYWRlcilcbiAgICAgICAgICAgICAgICAgICAgLnNldEtleU1hbmFnZW1lbnRQYXJhbWV0ZXJzKHsgcDJjIH0pXG4gICAgICAgICAgICAgICAgICAgIC5lbmNyeXB0KHJlY2lwaWVudC5rZXksIHtcbiAgICAgICAgICAgICAgICAgICAgLi4ucmVjaXBpZW50Lm9wdGlvbnMsXG4gICAgICAgICAgICAgICAgICAgIFt1bnByb3RlY3RlZF06IHRydWUsXG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgandlLmNpcGhlcnRleHQgPSBmbGF0dGVuZWQuY2lwaGVydGV4dDtcbiAgICAgICAgICAgICAgICBqd2UuaXYgPSBmbGF0dGVuZWQuaXY7XG4gICAgICAgICAgICAgICAgandlLnRhZyA9IGZsYXR0ZW5lZC50YWc7XG4gICAgICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC5hYWQpXG4gICAgICAgICAgICAgICAgICAgIGp3ZS5hYWQgPSBmbGF0dGVuZWQuYWFkO1xuICAgICAgICAgICAgICAgIGlmIChmbGF0dGVuZWQucHJvdGVjdGVkKVxuICAgICAgICAgICAgICAgICAgICBqd2UucHJvdGVjdGVkID0gZmxhdHRlbmVkLnByb3RlY3RlZDtcbiAgICAgICAgICAgICAgICBpZiAoZmxhdHRlbmVkLnVucHJvdGVjdGVkKVxuICAgICAgICAgICAgICAgICAgICBqd2UudW5wcm90ZWN0ZWQgPSBmbGF0dGVuZWQudW5wcm90ZWN0ZWQ7XG4gICAgICAgICAgICAgICAgdGFyZ2V0LmVuY3J5cHRlZF9rZXkgPSBmbGF0dGVuZWQuZW5jcnlwdGVkX2tleTtcbiAgICAgICAgICAgICAgICBpZiAoZmxhdHRlbmVkLmhlYWRlcilcbiAgICAgICAgICAgICAgICAgICAgdGFyZ2V0LmhlYWRlciA9IGZsYXR0ZW5lZC5oZWFkZXI7XG4gICAgICAgICAgICAgICAgY29udGludWU7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjb25zdCB7IGVuY3J5cHRlZEtleSwgcGFyYW1ldGVycyB9ID0gYXdhaXQgZW5jcnlwdEtleU1hbmFnZW1lbnQocmVjaXBpZW50LnVucHJvdGVjdGVkSGVhZGVyPy5hbGcgfHxcbiAgICAgICAgICAgICAgICB0aGlzLl9wcm90ZWN0ZWRIZWFkZXI/LmFsZyB8fFxuICAgICAgICAgICAgICAgIHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyPy5hbGcsIGVuYywgcmVjaXBpZW50LmtleSwgY2VrLCB7IHAyYyB9KTtcbiAgICAgICAgICAgIHRhcmdldC5lbmNyeXB0ZWRfa2V5ID0gYmFzZTY0dXJsKGVuY3J5cHRlZEtleSk7XG4gICAgICAgICAgICBpZiAocmVjaXBpZW50LnVucHJvdGVjdGVkSGVhZGVyIHx8IHBhcmFtZXRlcnMpXG4gICAgICAgICAgICAgICAgdGFyZ2V0LmhlYWRlciA9IHsgLi4ucmVjaXBpZW50LnVucHJvdGVjdGVkSGVhZGVyLCAuLi5wYXJhbWV0ZXJzIH07XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGp3ZTtcbiAgICB9XG59XG4iLCJpbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gc3VidGxlRHNhKGFsZywgYWxnb3JpdGhtKSB7XG4gICAgY29uc3QgaGFzaCA9IGBTSEEtJHthbGcuc2xpY2UoLTMpfWA7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnSFMyNTYnOlxuICAgICAgICBjYXNlICdIUzM4NCc6XG4gICAgICAgIGNhc2UgJ0hTNTEyJzpcbiAgICAgICAgICAgIHJldHVybiB7IGhhc2gsIG5hbWU6ICdITUFDJyB9O1xuICAgICAgICBjYXNlICdQUzI1Nic6XG4gICAgICAgIGNhc2UgJ1BTMzg0JzpcbiAgICAgICAgY2FzZSAnUFM1MTInOlxuICAgICAgICAgICAgcmV0dXJuIHsgaGFzaCwgbmFtZTogJ1JTQS1QU1MnLCBzYWx0TGVuZ3RoOiBhbGcuc2xpY2UoLTMpID4+IDMgfTtcbiAgICAgICAgY2FzZSAnUlMyNTYnOlxuICAgICAgICBjYXNlICdSUzM4NCc6XG4gICAgICAgIGNhc2UgJ1JTNTEyJzpcbiAgICAgICAgICAgIHJldHVybiB7IGhhc2gsIG5hbWU6ICdSU0FTU0EtUEtDUzEtdjFfNScgfTtcbiAgICAgICAgY2FzZSAnRVMyNTYnOlxuICAgICAgICBjYXNlICdFUzM4NCc6XG4gICAgICAgIGNhc2UgJ0VTNTEyJzpcbiAgICAgICAgICAgIHJldHVybiB7IGhhc2gsIG5hbWU6ICdFQ0RTQScsIG5hbWVkQ3VydmU6IGFsZ29yaXRobS5uYW1lZEN1cnZlIH07XG4gICAgICAgIGNhc2UgJ0VkRFNBJzpcbiAgICAgICAgICAgIHJldHVybiB7IG5hbWU6IGFsZ29yaXRobS5uYW1lIH07XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZChgYWxnICR7YWxnfSBpcyBub3Qgc3VwcG9ydGVkIGVpdGhlciBieSBKT1NFIG9yIHlvdXIgamF2YXNjcmlwdCBydW50aW1lYCk7XG4gICAgfVxufVxuIiwiaW1wb3J0IGNyeXB0bywgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IGNoZWNrU2lnQ3J5cHRvS2V5IH0gZnJvbSAnLi4vbGliL2NyeXB0b19rZXkuanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGdldENyeXB0b0tleShhbGcsIGtleSwgdXNhZ2UpIHtcbiAgICBpZiAoaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICBjaGVja1NpZ0NyeXB0b0tleShrZXksIGFsZywgdXNhZ2UpO1xuICAgICAgICByZXR1cm4ga2V5O1xuICAgIH1cbiAgICBpZiAoa2V5IGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICBpZiAoIWFsZy5zdGFydHNXaXRoKCdIUycpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzKSk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBrZXksIHsgaGFzaDogYFNIQS0ke2FsZy5zbGljZSgtMyl9YCwgbmFtZTogJ0hNQUMnIH0sIGZhbHNlLCBbdXNhZ2VdKTtcbiAgICB9XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcywgJ1VpbnQ4QXJyYXknKSk7XG59XG4iLCJpbXBvcnQgc3VidGxlQWxnb3JpdGhtIGZyb20gJy4vc3VidGxlX2RzYS5qcyc7XG5pbXBvcnQgY3J5cHRvIGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCBjaGVja0tleUxlbmd0aCBmcm9tICcuL2NoZWNrX2tleV9sZW5ndGguanMnO1xuaW1wb3J0IGdldFZlcmlmeUtleSBmcm9tICcuL2dldF9zaWduX3ZlcmlmeV9rZXkuanMnO1xuY29uc3QgdmVyaWZ5ID0gYXN5bmMgKGFsZywga2V5LCBzaWduYXR1cmUsIGRhdGEpID0+IHtcbiAgICBjb25zdCBjcnlwdG9LZXkgPSBhd2FpdCBnZXRWZXJpZnlLZXkoYWxnLCBrZXksICd2ZXJpZnknKTtcbiAgICBjaGVja0tleUxlbmd0aChhbGcsIGNyeXB0b0tleSk7XG4gICAgY29uc3QgYWxnb3JpdGhtID0gc3VidGxlQWxnb3JpdGhtKGFsZywgY3J5cHRvS2V5LmFsZ29yaXRobSk7XG4gICAgdHJ5IHtcbiAgICAgICAgcmV0dXJuIGF3YWl0IGNyeXB0by5zdWJ0bGUudmVyaWZ5KGFsZ29yaXRobSwgY3J5cHRvS2V5LCBzaWduYXR1cmUsIGRhdGEpO1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG59O1xuZXhwb3J0IGRlZmF1bHQgdmVyaWZ5O1xuIiwiaW1wb3J0IHsgZGVjb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4uLy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmltcG9ydCB2ZXJpZnkgZnJvbSAnLi4vLi4vcnVudGltZS92ZXJpZnkuanMnO1xuaW1wb3J0IHsgSk9TRUFsZ05vdEFsbG93ZWQsIEpXU0ludmFsaWQsIEpXU1NpZ25hdHVyZVZlcmlmaWNhdGlvbkZhaWxlZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IGNvbmNhdCwgZW5jb2RlciwgZGVjb2RlciB9IGZyb20gJy4uLy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IGlzRGlzam9pbnQgZnJvbSAnLi4vLi4vbGliL2lzX2Rpc2pvaW50LmpzJztcbmltcG9ydCBpc09iamVjdCBmcm9tICcuLi8uLi9saWIvaXNfb2JqZWN0LmpzJztcbmltcG9ydCBjaGVja0tleVR5cGUgZnJvbSAnLi4vLi4vbGliL2NoZWNrX2tleV90eXBlLmpzJztcbmltcG9ydCB2YWxpZGF0ZUNyaXQgZnJvbSAnLi4vLi4vbGliL3ZhbGlkYXRlX2NyaXQuanMnO1xuaW1wb3J0IHZhbGlkYXRlQWxnb3JpdGhtcyBmcm9tICcuLi8uLi9saWIvdmFsaWRhdGVfYWxnb3JpdGhtcy5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZmxhdHRlbmVkVmVyaWZ5KGp3cywga2V5LCBvcHRpb25zKSB7XG4gICAgaWYgKCFpc09iamVjdChqd3MpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdGbGF0dGVuZWQgSldTIG11c3QgYmUgYW4gb2JqZWN0Jyk7XG4gICAgfVxuICAgIGlmIChqd3MucHJvdGVjdGVkID09PSB1bmRlZmluZWQgJiYgandzLmhlYWRlciA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdGbGF0dGVuZWQgSldTIG11c3QgaGF2ZSBlaXRoZXIgb2YgdGhlIFwicHJvdGVjdGVkXCIgb3IgXCJoZWFkZXJcIiBtZW1iZXJzJyk7XG4gICAgfVxuICAgIGlmIChqd3MucHJvdGVjdGVkICE9PSB1bmRlZmluZWQgJiYgdHlwZW9mIGp3cy5wcm90ZWN0ZWQgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgUHJvdGVjdGVkIEhlYWRlciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoandzLnBheWxvYWQgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFBheWxvYWQgbWlzc2luZycpO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIGp3cy5zaWduYXR1cmUgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgU2lnbmF0dXJlIG1pc3Npbmcgb3IgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3cy5oZWFkZXIgIT09IHVuZGVmaW5lZCAmJiAhaXNPYmplY3QoandzLmhlYWRlcikpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBVbnByb3RlY3RlZCBIZWFkZXIgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgbGV0IHBhcnNlZFByb3QgPSB7fTtcbiAgICBpZiAoandzLnByb3RlY3RlZCkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgY29uc3QgcHJvdGVjdGVkSGVhZGVyID0gYmFzZTY0dXJsKGp3cy5wcm90ZWN0ZWQpO1xuICAgICAgICAgICAgcGFyc2VkUHJvdCA9IEpTT04ucGFyc2UoZGVjb2Rlci5kZWNvZGUocHJvdGVjdGVkSGVhZGVyKSk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBQcm90ZWN0ZWQgSGVhZGVyIGlzIGludmFsaWQnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBpZiAoIWlzRGlzam9pbnQocGFyc2VkUHJvdCwgandzLmhlYWRlcikpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBQcm90ZWN0ZWQgYW5kIEpXUyBVbnByb3RlY3RlZCBIZWFkZXIgUGFyYW1ldGVyIG5hbWVzIG11c3QgYmUgZGlzam9pbnQnKTtcbiAgICB9XG4gICAgY29uc3Qgam9zZUhlYWRlciA9IHtcbiAgICAgICAgLi4ucGFyc2VkUHJvdCxcbiAgICAgICAgLi4uandzLmhlYWRlcixcbiAgICB9O1xuICAgIGNvbnN0IGV4dGVuc2lvbnMgPSB2YWxpZGF0ZUNyaXQoSldTSW52YWxpZCwgbmV3IE1hcChbWydiNjQnLCB0cnVlXV0pLCBvcHRpb25zPy5jcml0LCBwYXJzZWRQcm90LCBqb3NlSGVhZGVyKTtcbiAgICBsZXQgYjY0ID0gdHJ1ZTtcbiAgICBpZiAoZXh0ZW5zaW9ucy5oYXMoJ2I2NCcpKSB7XG4gICAgICAgIGI2NCA9IHBhcnNlZFByb3QuYjY0O1xuICAgICAgICBpZiAodHlwZW9mIGI2NCAhPT0gJ2Jvb2xlYW4nKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnVGhlIFwiYjY0XCIgKGJhc2U2NHVybC1lbmNvZGUgcGF5bG9hZCkgSGVhZGVyIFBhcmFtZXRlciBtdXN0IGJlIGEgYm9vbGVhbicpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGNvbnN0IHsgYWxnIH0gPSBqb3NlSGVhZGVyO1xuICAgIGlmICh0eXBlb2YgYWxnICE9PSAnc3RyaW5nJyB8fCAhYWxnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgXCJhbGdcIiAoQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIG1pc3Npbmcgb3IgaW52YWxpZCcpO1xuICAgIH1cbiAgICBjb25zdCBhbGdvcml0aG1zID0gb3B0aW9ucyAmJiB2YWxpZGF0ZUFsZ29yaXRobXMoJ2FsZ29yaXRobXMnLCBvcHRpb25zLmFsZ29yaXRobXMpO1xuICAgIGlmIChhbGdvcml0aG1zICYmICFhbGdvcml0aG1zLmhhcyhhbGcpKSB7XG4gICAgICAgIHRocm93IG5ldyBKT1NFQWxnTm90QWxsb3dlZCgnXCJhbGdcIiAoQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIHZhbHVlIG5vdCBhbGxvd2VkJyk7XG4gICAgfVxuICAgIGlmIChiNjQpIHtcbiAgICAgICAgaWYgKHR5cGVvZiBqd3MucGF5bG9hZCAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgUGF5bG9hZCBtdXN0IGJlIGEgc3RyaW5nJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgZWxzZSBpZiAodHlwZW9mIGp3cy5wYXlsb2FkICE9PSAnc3RyaW5nJyAmJiAhKGp3cy5wYXlsb2FkIGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBQYXlsb2FkIG11c3QgYmUgYSBzdHJpbmcgb3IgYW4gVWludDhBcnJheSBpbnN0YW5jZScpO1xuICAgIH1cbiAgICBsZXQgcmVzb2x2ZWRLZXkgPSBmYWxzZTtcbiAgICBpZiAodHlwZW9mIGtleSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICBrZXkgPSBhd2FpdCBrZXkocGFyc2VkUHJvdCwgandzKTtcbiAgICAgICAgcmVzb2x2ZWRLZXkgPSB0cnVlO1xuICAgIH1cbiAgICBjaGVja0tleVR5cGUoYWxnLCBrZXksICd2ZXJpZnknKTtcbiAgICBjb25zdCBkYXRhID0gY29uY2F0KGVuY29kZXIuZW5jb2RlKGp3cy5wcm90ZWN0ZWQgPz8gJycpLCBlbmNvZGVyLmVuY29kZSgnLicpLCB0eXBlb2YgandzLnBheWxvYWQgPT09ICdzdHJpbmcnID8gZW5jb2Rlci5lbmNvZGUoandzLnBheWxvYWQpIDogandzLnBheWxvYWQpO1xuICAgIGxldCBzaWduYXR1cmU7XG4gICAgdHJ5IHtcbiAgICAgICAgc2lnbmF0dXJlID0gYmFzZTY0dXJsKGp3cy5zaWduYXR1cmUpO1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgc2lnbmF0dXJlJyk7XG4gICAgfVxuICAgIGNvbnN0IHZlcmlmaWVkID0gYXdhaXQgdmVyaWZ5KGFsZywga2V5LCBzaWduYXR1cmUsIGRhdGEpO1xuICAgIGlmICghdmVyaWZpZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU1NpZ25hdHVyZVZlcmlmaWNhdGlvbkZhaWxlZCgpO1xuICAgIH1cbiAgICBsZXQgcGF5bG9hZDtcbiAgICBpZiAoYjY0KSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBwYXlsb2FkID0gYmFzZTY0dXJsKGp3cy5wYXlsb2FkKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIHBheWxvYWQnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBlbHNlIGlmICh0eXBlb2YgandzLnBheWxvYWQgPT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHBheWxvYWQgPSBlbmNvZGVyLmVuY29kZShqd3MucGF5bG9hZCk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBwYXlsb2FkID0gandzLnBheWxvYWQ7XG4gICAgfVxuICAgIGNvbnN0IHJlc3VsdCA9IHsgcGF5bG9hZCB9O1xuICAgIGlmIChqd3MucHJvdGVjdGVkICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmVzdWx0LnByb3RlY3RlZEhlYWRlciA9IHBhcnNlZFByb3Q7XG4gICAgfVxuICAgIGlmIChqd3MuaGVhZGVyICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmVzdWx0LnVucHJvdGVjdGVkSGVhZGVyID0gandzLmhlYWRlcjtcbiAgICB9XG4gICAgaWYgKHJlc29sdmVkS2V5KSB7XG4gICAgICAgIHJldHVybiB7IC4uLnJlc3VsdCwga2V5IH07XG4gICAgfVxuICAgIHJldHVybiByZXN1bHQ7XG59XG4iLCJpbXBvcnQgeyBmbGF0dGVuZWRWZXJpZnkgfSBmcm9tICcuLi9mbGF0dGVuZWQvdmVyaWZ5LmpzJztcbmltcG9ydCB7IEpXU0ludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgeyBkZWNvZGVyIH0gZnJvbSAnLi4vLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gY29tcGFjdFZlcmlmeShqd3MsIGtleSwgb3B0aW9ucykge1xuICAgIGlmIChqd3MgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIGp3cyA9IGRlY29kZXIuZGVjb2RlKGp3cyk7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgandzICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnQ29tcGFjdCBKV1MgbXVzdCBiZSBhIHN0cmluZyBvciBVaW50OEFycmF5Jyk7XG4gICAgfVxuICAgIGNvbnN0IHsgMDogcHJvdGVjdGVkSGVhZGVyLCAxOiBwYXlsb2FkLCAyOiBzaWduYXR1cmUsIGxlbmd0aCB9ID0gandzLnNwbGl0KCcuJyk7XG4gICAgaWYgKGxlbmd0aCAhPT0gMykge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSW52YWxpZCBDb21wYWN0IEpXUycpO1xuICAgIH1cbiAgICBjb25zdCB2ZXJpZmllZCA9IGF3YWl0IGZsYXR0ZW5lZFZlcmlmeSh7IHBheWxvYWQsIHByb3RlY3RlZDogcHJvdGVjdGVkSGVhZGVyLCBzaWduYXR1cmUgfSwga2V5LCBvcHRpb25zKTtcbiAgICBjb25zdCByZXN1bHQgPSB7IHBheWxvYWQ6IHZlcmlmaWVkLnBheWxvYWQsIHByb3RlY3RlZEhlYWRlcjogdmVyaWZpZWQucHJvdGVjdGVkSGVhZGVyIH07XG4gICAgaWYgKHR5cGVvZiBrZXkgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAgcmV0dXJuIHsgLi4ucmVzdWx0LCBrZXk6IHZlcmlmaWVkLmtleSB9O1xuICAgIH1cbiAgICByZXR1cm4gcmVzdWx0O1xufVxuIiwiaW1wb3J0IHsgZmxhdHRlbmVkVmVyaWZ5IH0gZnJvbSAnLi4vZmxhdHRlbmVkL3ZlcmlmeS5qcyc7XG5pbXBvcnQgeyBKV1NJbnZhbGlkLCBKV1NTaWduYXR1cmVWZXJpZmljYXRpb25GYWlsZWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgaXNPYmplY3QgZnJvbSAnLi4vLi4vbGliL2lzX29iamVjdC5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhbFZlcmlmeShqd3MsIGtleSwgb3B0aW9ucykge1xuICAgIGlmICghaXNPYmplY3QoandzKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnR2VuZXJhbCBKV1MgbXVzdCBiZSBhbiBvYmplY3QnKTtcbiAgICB9XG4gICAgaWYgKCFBcnJheS5pc0FycmF5KGp3cy5zaWduYXR1cmVzKSB8fCAhandzLnNpZ25hdHVyZXMuZXZlcnkoaXNPYmplY3QpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgU2lnbmF0dXJlcyBtaXNzaW5nIG9yIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGZvciAoY29uc3Qgc2lnbmF0dXJlIG9mIGp3cy5zaWduYXR1cmVzKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICByZXR1cm4gYXdhaXQgZmxhdHRlbmVkVmVyaWZ5KHtcbiAgICAgICAgICAgICAgICBoZWFkZXI6IHNpZ25hdHVyZS5oZWFkZXIsXG4gICAgICAgICAgICAgICAgcGF5bG9hZDogandzLnBheWxvYWQsXG4gICAgICAgICAgICAgICAgcHJvdGVjdGVkOiBzaWduYXR1cmUucHJvdGVjdGVkLFxuICAgICAgICAgICAgICAgIHNpZ25hdHVyZTogc2lnbmF0dXJlLnNpZ25hdHVyZSxcbiAgICAgICAgICAgIH0sIGtleSwgb3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICB9XG4gICAgfVxuICAgIHRocm93IG5ldyBKV1NTaWduYXR1cmVWZXJpZmljYXRpb25GYWlsZWQoKTtcbn1cbiIsImltcG9ydCB7IEZsYXR0ZW5lZEVuY3J5cHQgfSBmcm9tICcuLi9mbGF0dGVuZWQvZW5jcnlwdC5qcyc7XG5leHBvcnQgY2xhc3MgQ29tcGFjdEVuY3J5cHQge1xuICAgIGNvbnN0cnVjdG9yKHBsYWludGV4dCkge1xuICAgICAgICB0aGlzLl9mbGF0dGVuZWQgPSBuZXcgRmxhdHRlbmVkRW5jcnlwdChwbGFpbnRleHQpO1xuICAgIH1cbiAgICBzZXRDb250ZW50RW5jcnlwdGlvbktleShjZWspIHtcbiAgICAgICAgdGhpcy5fZmxhdHRlbmVkLnNldENvbnRlbnRFbmNyeXB0aW9uS2V5KGNlayk7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRJbml0aWFsaXphdGlvblZlY3Rvcihpdikge1xuICAgICAgICB0aGlzLl9mbGF0dGVuZWQuc2V0SW5pdGlhbGl6YXRpb25WZWN0b3IoaXYpO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICB0aGlzLl9mbGF0dGVuZWQuc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcik7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRLZXlNYW5hZ2VtZW50UGFyYW1ldGVycyhwYXJhbWV0ZXJzKSB7XG4gICAgICAgIHRoaXMuX2ZsYXR0ZW5lZC5zZXRLZXlNYW5hZ2VtZW50UGFyYW1ldGVycyhwYXJhbWV0ZXJzKTtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIGFzeW5jIGVuY3J5cHQoa2V5LCBvcHRpb25zKSB7XG4gICAgICAgIGNvbnN0IGp3ZSA9IGF3YWl0IHRoaXMuX2ZsYXR0ZW5lZC5lbmNyeXB0KGtleSwgb3B0aW9ucyk7XG4gICAgICAgIHJldHVybiBbandlLnByb3RlY3RlZCwgandlLmVuY3J5cHRlZF9rZXksIGp3ZS5pdiwgandlLmNpcGhlcnRleHQsIGp3ZS50YWddLmpvaW4oJy4nKTtcbiAgICB9XG59XG4iLCJpbXBvcnQgc3VidGxlQWxnb3JpdGhtIGZyb20gJy4vc3VidGxlX2RzYS5qcyc7XG5pbXBvcnQgY3J5cHRvIGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCBjaGVja0tleUxlbmd0aCBmcm9tICcuL2NoZWNrX2tleV9sZW5ndGguanMnO1xuaW1wb3J0IGdldFNpZ25LZXkgZnJvbSAnLi9nZXRfc2lnbl92ZXJpZnlfa2V5LmpzJztcbmNvbnN0IHNpZ24gPSBhc3luYyAoYWxnLCBrZXksIGRhdGEpID0+IHtcbiAgICBjb25zdCBjcnlwdG9LZXkgPSBhd2FpdCBnZXRTaWduS2V5KGFsZywga2V5LCAnc2lnbicpO1xuICAgIGNoZWNrS2V5TGVuZ3RoKGFsZywgY3J5cHRvS2V5KTtcbiAgICBjb25zdCBzaWduYXR1cmUgPSBhd2FpdCBjcnlwdG8uc3VidGxlLnNpZ24oc3VidGxlQWxnb3JpdGhtKGFsZywgY3J5cHRvS2V5LmFsZ29yaXRobSksIGNyeXB0b0tleSwgZGF0YSk7XG4gICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KHNpZ25hdHVyZSk7XG59O1xuZXhwb3J0IGRlZmF1bHQgc2lnbjtcbiIsImltcG9ydCB7IGVuY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi8uLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgc2lnbiBmcm9tICcuLi8uLi9ydW50aW1lL3NpZ24uanMnO1xuaW1wb3J0IGlzRGlzam9pbnQgZnJvbSAnLi4vLi4vbGliL2lzX2Rpc2pvaW50LmpzJztcbmltcG9ydCB7IEpXU0ludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgeyBlbmNvZGVyLCBkZWNvZGVyLCBjb25jYXQgfSBmcm9tICcuLi8uLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmltcG9ydCBjaGVja0tleVR5cGUgZnJvbSAnLi4vLi4vbGliL2NoZWNrX2tleV90eXBlLmpzJztcbmltcG9ydCB2YWxpZGF0ZUNyaXQgZnJvbSAnLi4vLi4vbGliL3ZhbGlkYXRlX2NyaXQuanMnO1xuZXhwb3J0IGNsYXNzIEZsYXR0ZW5lZFNpZ24ge1xuICAgIGNvbnN0cnVjdG9yKHBheWxvYWQpIHtcbiAgICAgICAgaWYgKCEocGF5bG9hZCBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdwYXlsb2FkIG11c3QgYmUgYW4gaW5zdGFuY2Ugb2YgVWludDhBcnJheScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3BheWxvYWQgPSBwYXlsb2FkO1xuICAgIH1cbiAgICBzZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3Byb3RlY3RlZEhlYWRlciA9IHByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldFVucHJvdGVjdGVkSGVhZGVyKHVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLl91bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0VW5wcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl91bnByb3RlY3RlZEhlYWRlciA9IHVucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgYXN5bmMgc2lnbihrZXksIG9wdGlvbnMpIHtcbiAgICAgICAgaWYgKCF0aGlzLl9wcm90ZWN0ZWRIZWFkZXIgJiYgIXRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnZWl0aGVyIHNldFByb3RlY3RlZEhlYWRlciBvciBzZXRVbnByb3RlY3RlZEhlYWRlciBtdXN0IGJlIGNhbGxlZCBiZWZvcmUgI3NpZ24oKScpO1xuICAgICAgICB9XG4gICAgICAgIGlmICghaXNEaXNqb2ludCh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIsIHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBQcm90ZWN0ZWQgYW5kIEpXUyBVbnByb3RlY3RlZCBIZWFkZXIgUGFyYW1ldGVyIG5hbWVzIG11c3QgYmUgZGlzam9pbnQnKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBqb3NlSGVhZGVyID0ge1xuICAgICAgICAgICAgLi4udGhpcy5fcHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgLi4udGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgIH07XG4gICAgICAgIGNvbnN0IGV4dGVuc2lvbnMgPSB2YWxpZGF0ZUNyaXQoSldTSW52YWxpZCwgbmV3IE1hcChbWydiNjQnLCB0cnVlXV0pLCBvcHRpb25zPy5jcml0LCB0aGlzLl9wcm90ZWN0ZWRIZWFkZXIsIGpvc2VIZWFkZXIpO1xuICAgICAgICBsZXQgYjY0ID0gdHJ1ZTtcbiAgICAgICAgaWYgKGV4dGVuc2lvbnMuaGFzKCdiNjQnKSkge1xuICAgICAgICAgICAgYjY0ID0gdGhpcy5fcHJvdGVjdGVkSGVhZGVyLmI2NDtcbiAgICAgICAgICAgIGlmICh0eXBlb2YgYjY0ICE9PSAnYm9vbGVhbicpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnVGhlIFwiYjY0XCIgKGJhc2U2NHVybC1lbmNvZGUgcGF5bG9hZCkgSGVhZGVyIFBhcmFtZXRlciBtdXN0IGJlIGEgYm9vbGVhbicpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHsgYWxnIH0gPSBqb3NlSGVhZGVyO1xuICAgICAgICBpZiAodHlwZW9mIGFsZyAhPT0gJ3N0cmluZycgfHwgIWFsZykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBcImFsZ1wiIChBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgbWlzc2luZyBvciBpbnZhbGlkJyk7XG4gICAgICAgIH1cbiAgICAgICAgY2hlY2tLZXlUeXBlKGFsZywga2V5LCAnc2lnbicpO1xuICAgICAgICBsZXQgcGF5bG9hZCA9IHRoaXMuX3BheWxvYWQ7XG4gICAgICAgIGlmIChiNjQpIHtcbiAgICAgICAgICAgIHBheWxvYWQgPSBlbmNvZGVyLmVuY29kZShiYXNlNjR1cmwocGF5bG9hZCkpO1xuICAgICAgICB9XG4gICAgICAgIGxldCBwcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIGlmICh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHByb3RlY3RlZEhlYWRlciA9IGVuY29kZXIuZW5jb2RlKGJhc2U2NHVybChKU09OLnN0cmluZ2lmeSh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpKSk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBwcm90ZWN0ZWRIZWFkZXIgPSBlbmNvZGVyLmVuY29kZSgnJyk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgZGF0YSA9IGNvbmNhdChwcm90ZWN0ZWRIZWFkZXIsIGVuY29kZXIuZW5jb2RlKCcuJyksIHBheWxvYWQpO1xuICAgICAgICBjb25zdCBzaWduYXR1cmUgPSBhd2FpdCBzaWduKGFsZywga2V5LCBkYXRhKTtcbiAgICAgICAgY29uc3QgandzID0ge1xuICAgICAgICAgICAgc2lnbmF0dXJlOiBiYXNlNjR1cmwoc2lnbmF0dXJlKSxcbiAgICAgICAgICAgIHBheWxvYWQ6ICcnLFxuICAgICAgICB9O1xuICAgICAgICBpZiAoYjY0KSB7XG4gICAgICAgICAgICBqd3MucGF5bG9hZCA9IGRlY29kZXIuZGVjb2RlKHBheWxvYWQpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl91bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgandzLmhlYWRlciA9IHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIGp3cy5wcm90ZWN0ZWQgPSBkZWNvZGVyLmRlY29kZShwcm90ZWN0ZWRIZWFkZXIpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBqd3M7XG4gICAgfVxufVxuIiwiaW1wb3J0IHsgRmxhdHRlbmVkU2lnbiB9IGZyb20gJy4uL2ZsYXR0ZW5lZC9zaWduLmpzJztcbmV4cG9ydCBjbGFzcyBDb21wYWN0U2lnbiB7XG4gICAgY29uc3RydWN0b3IocGF5bG9hZCkge1xuICAgICAgICB0aGlzLl9mbGF0dGVuZWQgPSBuZXcgRmxhdHRlbmVkU2lnbihwYXlsb2FkKTtcbiAgICB9XG4gICAgc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICB0aGlzLl9mbGF0dGVuZWQuc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcik7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBhc3luYyBzaWduKGtleSwgb3B0aW9ucykge1xuICAgICAgICBjb25zdCBqd3MgPSBhd2FpdCB0aGlzLl9mbGF0dGVuZWQuc2lnbihrZXksIG9wdGlvbnMpO1xuICAgICAgICBpZiAoandzLnBheWxvYWQgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcigndXNlIHRoZSBmbGF0dGVuZWQgbW9kdWxlIGZvciBjcmVhdGluZyBKV1Mgd2l0aCBiNjQ6IGZhbHNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGAke2p3cy5wcm90ZWN0ZWR9LiR7andzLnBheWxvYWR9LiR7andzLnNpZ25hdHVyZX1gO1xuICAgIH1cbn1cbiIsImltcG9ydCB7IEZsYXR0ZW5lZFNpZ24gfSBmcm9tICcuLi9mbGF0dGVuZWQvc2lnbi5qcyc7XG5pbXBvcnQgeyBKV1NJbnZhbGlkIH0gZnJvbSAnLi4vLi4vdXRpbC9lcnJvcnMuanMnO1xuY2xhc3MgSW5kaXZpZHVhbFNpZ25hdHVyZSB7XG4gICAgY29uc3RydWN0b3Ioc2lnLCBrZXksIG9wdGlvbnMpIHtcbiAgICAgICAgdGhpcy5wYXJlbnQgPSBzaWc7XG4gICAgICAgIHRoaXMua2V5ID0ga2V5O1xuICAgICAgICB0aGlzLm9wdGlvbnMgPSBvcHRpb25zO1xuICAgIH1cbiAgICBzZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0UHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5wcm90ZWN0ZWRIZWFkZXIgPSBwcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRVbnByb3RlY3RlZEhlYWRlcih1bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy51bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0VW5wcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLnVucHJvdGVjdGVkSGVhZGVyID0gdW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBhZGRTaWduYXR1cmUoLi4uYXJncykge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXJlbnQuYWRkU2lnbmF0dXJlKC4uLmFyZ3MpO1xuICAgIH1cbiAgICBzaWduKC4uLmFyZ3MpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGFyZW50LnNpZ24oLi4uYXJncyk7XG4gICAgfVxuICAgIGRvbmUoKSB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhcmVudDtcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgR2VuZXJhbFNpZ24ge1xuICAgIGNvbnN0cnVjdG9yKHBheWxvYWQpIHtcbiAgICAgICAgdGhpcy5fc2lnbmF0dXJlcyA9IFtdO1xuICAgICAgICB0aGlzLl9wYXlsb2FkID0gcGF5bG9hZDtcbiAgICB9XG4gICAgYWRkU2lnbmF0dXJlKGtleSwgb3B0aW9ucykge1xuICAgICAgICBjb25zdCBzaWduYXR1cmUgPSBuZXcgSW5kaXZpZHVhbFNpZ25hdHVyZSh0aGlzLCBrZXksIG9wdGlvbnMpO1xuICAgICAgICB0aGlzLl9zaWduYXR1cmVzLnB1c2goc2lnbmF0dXJlKTtcbiAgICAgICAgcmV0dXJuIHNpZ25hdHVyZTtcbiAgICB9XG4gICAgYXN5bmMgc2lnbigpIHtcbiAgICAgICAgaWYgKCF0aGlzLl9zaWduYXR1cmVzLmxlbmd0aCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ2F0IGxlYXN0IG9uZSBzaWduYXR1cmUgbXVzdCBiZSBhZGRlZCcpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IGp3cyA9IHtcbiAgICAgICAgICAgIHNpZ25hdHVyZXM6IFtdLFxuICAgICAgICAgICAgcGF5bG9hZDogJycsXG4gICAgICAgIH07XG4gICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgdGhpcy5fc2lnbmF0dXJlcy5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgY29uc3Qgc2lnbmF0dXJlID0gdGhpcy5fc2lnbmF0dXJlc1tpXTtcbiAgICAgICAgICAgIGNvbnN0IGZsYXR0ZW5lZCA9IG5ldyBGbGF0dGVuZWRTaWduKHRoaXMuX3BheWxvYWQpO1xuICAgICAgICAgICAgZmxhdHRlbmVkLnNldFByb3RlY3RlZEhlYWRlcihzaWduYXR1cmUucHJvdGVjdGVkSGVhZGVyKTtcbiAgICAgICAgICAgIGZsYXR0ZW5lZC5zZXRVbnByb3RlY3RlZEhlYWRlcihzaWduYXR1cmUudW5wcm90ZWN0ZWRIZWFkZXIpO1xuICAgICAgICAgICAgY29uc3QgeyBwYXlsb2FkLCAuLi5yZXN0IH0gPSBhd2FpdCBmbGF0dGVuZWQuc2lnbihzaWduYXR1cmUua2V5LCBzaWduYXR1cmUub3B0aW9ucyk7XG4gICAgICAgICAgICBpZiAoaSA9PT0gMCkge1xuICAgICAgICAgICAgICAgIGp3cy5wYXlsb2FkID0gcGF5bG9hZDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2UgaWYgKGp3cy5wYXlsb2FkICE9PSBwYXlsb2FkKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ2luY29uc2lzdGVudCB1c2Ugb2YgSldTIFVuZW5jb2RlZCBQYXlsb2FkIChSRkM3Nzk3KScpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgandzLnNpZ25hdHVyZXMucHVzaChyZXN0KTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gandzO1xuICAgIH1cbn1cbiIsImltcG9ydCAqIGFzIGJhc2U2NHVybCBmcm9tICcuLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5leHBvcnQgY29uc3QgZW5jb2RlID0gYmFzZTY0dXJsLmVuY29kZTtcbmV4cG9ydCBjb25zdCBkZWNvZGUgPSBiYXNlNjR1cmwuZGVjb2RlO1xuIiwiaW1wb3J0IHsgZGVjb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4vYmFzZTY0dXJsLmpzJztcbmltcG9ydCB7IGRlY29kZXIgfSBmcm9tICcuLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmltcG9ydCBpc09iamVjdCBmcm9tICcuLi9saWIvaXNfb2JqZWN0LmpzJztcbmV4cG9ydCBmdW5jdGlvbiBkZWNvZGVQcm90ZWN0ZWRIZWFkZXIodG9rZW4pIHtcbiAgICBsZXQgcHJvdGVjdGVkQjY0dTtcbiAgICBpZiAodHlwZW9mIHRva2VuID09PSAnc3RyaW5nJykge1xuICAgICAgICBjb25zdCBwYXJ0cyA9IHRva2VuLnNwbGl0KCcuJyk7XG4gICAgICAgIGlmIChwYXJ0cy5sZW5ndGggPT09IDMgfHwgcGFydHMubGVuZ3RoID09PSA1KSB7XG4gICAgICAgICAgICA7XG4gICAgICAgICAgICBbcHJvdGVjdGVkQjY0dV0gPSBwYXJ0cztcbiAgICAgICAgfVxuICAgIH1cbiAgICBlbHNlIGlmICh0eXBlb2YgdG9rZW4gPT09ICdvYmplY3QnICYmIHRva2VuKSB7XG4gICAgICAgIGlmICgncHJvdGVjdGVkJyBpbiB0b2tlbikge1xuICAgICAgICAgICAgcHJvdGVjdGVkQjY0dSA9IHRva2VuLnByb3RlY3RlZDtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1Rva2VuIGRvZXMgbm90IGNvbnRhaW4gYSBQcm90ZWN0ZWQgSGVhZGVyJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgdHJ5IHtcbiAgICAgICAgaWYgKHR5cGVvZiBwcm90ZWN0ZWRCNjR1ICE9PSAnc3RyaW5nJyB8fCAhcHJvdGVjdGVkQjY0dSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgcmVzdWx0ID0gSlNPTi5wYXJzZShkZWNvZGVyLmRlY29kZShiYXNlNjR1cmwocHJvdGVjdGVkQjY0dSkpKTtcbiAgICAgICAgaWYgKCFpc09iamVjdChyZXN1bHQpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0ludmFsaWQgVG9rZW4gb3IgUHJvdGVjdGVkIEhlYWRlciBmb3JtYXR0aW5nJyk7XG4gICAgfVxufVxuIiwiaW1wb3J0IGNyeXB0byBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHJhbmRvbSBmcm9tICcuL3JhbmRvbS5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhdGVTZWNyZXQoYWxnLCBvcHRpb25zKSB7XG4gICAgbGV0IGxlbmd0aDtcbiAgICBsZXQgYWxnb3JpdGhtO1xuICAgIGxldCBrZXlVc2FnZXM7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnSFMyNTYnOlxuICAgICAgICBjYXNlICdIUzM4NCc6XG4gICAgICAgIGNhc2UgJ0hTNTEyJzpcbiAgICAgICAgICAgIGxlbmd0aCA9IHBhcnNlSW50KGFsZy5zbGljZSgtMyksIDEwKTtcbiAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0hNQUMnLCBoYXNoOiBgU0hBLSR7bGVuZ3RofWAsIGxlbmd0aCB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydzaWduJywgJ3ZlcmlmeSddO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ0ExMjhDQkMtSFMyNTYnOlxuICAgICAgICBjYXNlICdBMTkyQ0JDLUhTMzg0JzpcbiAgICAgICAgY2FzZSAnQTI1NkNCQy1IUzUxMic6XG4gICAgICAgICAgICBsZW5ndGggPSBwYXJzZUludChhbGcuc2xpY2UoLTMpLCAxMCk7XG4gICAgICAgICAgICByZXR1cm4gcmFuZG9tKG5ldyBVaW50OEFycmF5KGxlbmd0aCA+PiAzKSk7XG4gICAgICAgIGNhc2UgJ0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZLVyc6XG4gICAgICAgICAgICBsZW5ndGggPSBwYXJzZUludChhbGcuc2xpY2UoMSwgNCksIDEwKTtcbiAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0FFUy1LVycsIGxlbmd0aCB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWyd3cmFwS2V5JywgJ3Vud3JhcEtleSddO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ0ExMjhHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0ExMjhHQ00nOlxuICAgICAgICBjYXNlICdBMTkyR0NNJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTSc6XG4gICAgICAgICAgICBsZW5ndGggPSBwYXJzZUludChhbGcuc2xpY2UoMSwgNCksIDEwKTtcbiAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0FFUy1HQ00nLCBsZW5ndGggfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnZW5jcnlwdCcsICdkZWNyeXB0J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIEpXSyBcImFsZ1wiIChBbGdvcml0aG0pIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgIH1cbiAgICByZXR1cm4gY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleShhbGdvcml0aG0sIG9wdGlvbnM/LmV4dHJhY3RhYmxlID8/IGZhbHNlLCBrZXlVc2FnZXMpO1xufVxuZnVuY3Rpb24gZ2V0TW9kdWx1c0xlbmd0aE9wdGlvbihvcHRpb25zKSB7XG4gICAgY29uc3QgbW9kdWx1c0xlbmd0aCA9IG9wdGlvbnM/Lm1vZHVsdXNMZW5ndGggPz8gMjA0ODtcbiAgICBpZiAodHlwZW9mIG1vZHVsdXNMZW5ndGggIT09ICdudW1iZXInIHx8IG1vZHVsdXNMZW5ndGggPCAyMDQ4KSB7XG4gICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIG1vZHVsdXNMZW5ndGggb3B0aW9uIHByb3ZpZGVkLCAyMDQ4IGJpdHMgb3IgbGFyZ2VyIGtleXMgbXVzdCBiZSB1c2VkJyk7XG4gICAgfVxuICAgIHJldHVybiBtb2R1bHVzTGVuZ3RoO1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdlbmVyYXRlS2V5UGFpcihhbGcsIG9wdGlvbnMpIHtcbiAgICBsZXQgYWxnb3JpdGhtO1xuICAgIGxldCBrZXlVc2FnZXM7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnUFMyNTYnOlxuICAgICAgICBjYXNlICdQUzM4NCc6XG4gICAgICAgIGNhc2UgJ1BTNTEyJzpcbiAgICAgICAgICAgIGFsZ29yaXRobSA9IHtcbiAgICAgICAgICAgICAgICBuYW1lOiAnUlNBLVBTUycsXG4gICAgICAgICAgICAgICAgaGFzaDogYFNIQS0ke2FsZy5zbGljZSgtMyl9YCxcbiAgICAgICAgICAgICAgICBwdWJsaWNFeHBvbmVudDogbmV3IFVpbnQ4QXJyYXkoWzB4MDEsIDB4MDAsIDB4MDFdKSxcbiAgICAgICAgICAgICAgICBtb2R1bHVzTGVuZ3RoOiBnZXRNb2R1bHVzTGVuZ3RoT3B0aW9uKG9wdGlvbnMpLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnc2lnbicsICd2ZXJpZnknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdSUzI1Nic6XG4gICAgICAgIGNhc2UgJ1JTMzg0JzpcbiAgICAgICAgY2FzZSAnUlM1MTInOlxuICAgICAgICAgICAgYWxnb3JpdGhtID0ge1xuICAgICAgICAgICAgICAgIG5hbWU6ICdSU0FTU0EtUEtDUzEtdjFfNScsXG4gICAgICAgICAgICAgICAgaGFzaDogYFNIQS0ke2FsZy5zbGljZSgtMyl9YCxcbiAgICAgICAgICAgICAgICBwdWJsaWNFeHBvbmVudDogbmV3IFVpbnQ4QXJyYXkoWzB4MDEsIDB4MDAsIDB4MDFdKSxcbiAgICAgICAgICAgICAgICBtb2R1bHVzTGVuZ3RoOiBnZXRNb2R1bHVzTGVuZ3RoT3B0aW9uKG9wdGlvbnMpLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnc2lnbicsICd2ZXJpZnknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdSU0EtT0FFUCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTI1Nic6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTM4NCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTUxMic6XG4gICAgICAgICAgICBhbGdvcml0aG0gPSB7XG4gICAgICAgICAgICAgICAgbmFtZTogJ1JTQS1PQUVQJyxcbiAgICAgICAgICAgICAgICBoYXNoOiBgU0hBLSR7cGFyc2VJbnQoYWxnLnNsaWNlKC0zKSwgMTApIHx8IDF9YCxcbiAgICAgICAgICAgICAgICBwdWJsaWNFeHBvbmVudDogbmV3IFVpbnQ4QXJyYXkoWzB4MDEsIDB4MDAsIDB4MDFdKSxcbiAgICAgICAgICAgICAgICBtb2R1bHVzTGVuZ3RoOiBnZXRNb2R1bHVzTGVuZ3RoT3B0aW9uKG9wdGlvbnMpLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnZGVjcnlwdCcsICd1bndyYXBLZXknLCAnZW5jcnlwdCcsICd3cmFwS2V5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnRVMyNTYnOlxuICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNEU0EnLCBuYW1lZEN1cnZlOiAnUC0yNTYnIH07XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3NpZ24nLCAndmVyaWZ5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnRVMzODQnOlxuICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNEU0EnLCBuYW1lZEN1cnZlOiAnUC0zODQnIH07XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3NpZ24nLCAndmVyaWZ5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnRVM1MTInOlxuICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNEU0EnLCBuYW1lZEN1cnZlOiAnUC01MjEnIH07XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3NpZ24nLCAndmVyaWZ5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnRWREU0EnOiB7XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3NpZ24nLCAndmVyaWZ5J107XG4gICAgICAgICAgICBjb25zdCBjcnYgPSBvcHRpb25zPy5jcnYgPz8gJ0VkMjU1MTknO1xuICAgICAgICAgICAgc3dpdGNoIChjcnYpIHtcbiAgICAgICAgICAgICAgICBjYXNlICdFZDI1NTE5JzpcbiAgICAgICAgICAgICAgICBjYXNlICdFZDQ0OCc6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogY3J2IH07XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIGNydiBvcHRpb24gcHJvdmlkZWQnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0VDREgtRVMnOlxuICAgICAgICBjYXNlICdFQ0RILUVTK0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTE5MktXJzpcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMjU2S1cnOiB7XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ2Rlcml2ZUtleScsICdkZXJpdmVCaXRzJ107XG4gICAgICAgICAgICBjb25zdCBjcnYgPSBvcHRpb25zPy5jcnYgPz8gJ1AtMjU2JztcbiAgICAgICAgICAgIHN3aXRjaCAoY3J2KSB7XG4gICAgICAgICAgICAgICAgY2FzZSAnUC0yNTYnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1AtMzg0JzpcbiAgICAgICAgICAgICAgICBjYXNlICdQLTUyMSc6IHtcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNESCcsIG5hbWVkQ3VydmU6IGNydiB9O1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2FzZSAnWDI1NTE5JzpcbiAgICAgICAgICAgICAgICBjYXNlICdYNDQ4JzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiBjcnYgfTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgY3J2IG9wdGlvbiBwcm92aWRlZCwgc3VwcG9ydGVkIHZhbHVlcyBhcmUgUC0yNTYsIFAtMzg0LCBQLTUyMSwgWDI1NTE5LCBhbmQgWDQ0OCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIEpXSyBcImFsZ1wiIChBbGdvcml0aG0pIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgIH1cbiAgICByZXR1cm4gKGNyeXB0by5zdWJ0bGUuZ2VuZXJhdGVLZXkoYWxnb3JpdGhtLCBvcHRpb25zPy5leHRyYWN0YWJsZSA/PyBmYWxzZSwga2V5VXNhZ2VzKSk7XG59XG4iLCJpbXBvcnQgeyBnZW5lcmF0ZUtleVBhaXIgYXMgZ2VuZXJhdGUgfSBmcm9tICcuLi9ydW50aW1lL2dlbmVyYXRlLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZUtleVBhaXIoYWxnLCBvcHRpb25zKSB7XG4gICAgcmV0dXJuIGdlbmVyYXRlKGFsZywgb3B0aW9ucyk7XG59XG4iLCJpbXBvcnQgeyBnZW5lcmF0ZVNlY3JldCBhcyBnZW5lcmF0ZSB9IGZyb20gJy4uL3J1bnRpbWUvZ2VuZXJhdGUuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdlbmVyYXRlU2VjcmV0KGFsZywgb3B0aW9ucykge1xuICAgIHJldHVybiBnZW5lcmF0ZShhbGcsIG9wdGlvbnMpO1xufVxuIiwiLy8gT25lIGNvbnNpc3RlbnQgYWxnb3JpdGhtIGZvciBlYWNoIGZhbWlseS5cbi8vIGh0dHBzOi8vZGF0YXRyYWNrZXIuaWV0Zi5vcmcvZG9jL2h0bWwvcmZjNzUxOFxuXG5leHBvcnQgY29uc3Qgc2lnbmluZ05hbWUgPSAnRUNEU0EnO1xuZXhwb3J0IGNvbnN0IHNpZ25pbmdDdXJ2ZSA9ICdQLTM4NCc7XG5leHBvcnQgY29uc3Qgc2lnbmluZ0FsZ29yaXRobSA9ICdFUzM4NCc7XG5cbmV4cG9ydCBjb25zdCBlbmNyeXB0aW5nTmFtZSA9ICdSU0EtT0FFUCc7XG5leHBvcnQgY29uc3QgaGFzaExlbmd0aCA9IDI1NjtcbmV4cG9ydCBjb25zdCBoYXNoTmFtZSA9ICdTSEEtMjU2JztcbmV4cG9ydCBjb25zdCBtb2R1bHVzTGVuZ3RoID0gNDA5NjsgLy8gcGFudmEgSk9TRSBsaWJyYXJ5IGRlZmF1bHQgaXMgMjA0OFxuZXhwb3J0IGNvbnN0IGVuY3J5cHRpbmdBbGdvcml0aG0gPSAnUlNBLU9BRVAtMjU2JztcblxuZXhwb3J0IGNvbnN0IHN5bW1ldHJpY05hbWUgPSAnQUVTLUdDTSc7XG5leHBvcnQgY29uc3Qgc3ltbWV0cmljQWxnb3JpdGhtID0gJ0EyNTZHQ00nO1xuZXhwb3J0IGNvbnN0IHN5bW1ldHJpY1dyYXAgPSAnQTI1NkdDTUtXJztcbmV4cG9ydCBjb25zdCBzZWNyZXRBbGdvcml0aG0gPSAnUEJFUzItSFM1MTIrQTI1NktXJztcblxuZXhwb3J0IGNvbnN0IGV4dHJhY3RhYmxlID0gdHJ1ZTsgIC8vIGFsd2F5cyB3cmFwcGVkXG5cbiIsImltcG9ydCB7ZXh0cmFjdGFibGUsIHNpZ25pbmdOYW1lLCBzaWduaW5nQ3VydmUsIHN5bW1ldHJpY05hbWUsIGhhc2hMZW5ndGh9IGZyb20gXCIuL2FsZ29yaXRobXMubWpzXCI7XG5cbmV4cG9ydCBmdW5jdGlvbiBkaWdlc3QoaGFzaE5hbWUsIGJ1ZmZlcikge1xuICByZXR1cm4gY3J5cHRvLnN1YnRsZS5kaWdlc3QoaGFzaE5hbWUsIGJ1ZmZlcik7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBleHBvcnRSYXdLZXkoa2V5KSB7XG4gIHJldHVybiBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgncmF3Jywga2V5KTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGltcG9ydFJhd0tleShhcnJheUJ1ZmZlcikge1xuICBjb25zdCBhbGdvcml0aG0gPSB7bmFtZTogc2lnbmluZ05hbWUsIG5hbWVkQ3VydmU6IHNpZ25pbmdDdXJ2ZX07XG4gIHJldHVybiBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgYXJyYXlCdWZmZXIsIGFsZ29yaXRobSwgZXh0cmFjdGFibGUsIFsndmVyaWZ5J10pO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gaW1wb3J0U2VjcmV0KGJ5dGVBcnJheSkge1xuICBjb25zdCBhbGdvcml0aG0gPSB7bmFtZTogc3ltbWV0cmljTmFtZSwgbGVuZ3RoOiBoYXNoTGVuZ3RofTtcbiAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBieXRlQXJyYXksIGFsZ29yaXRobSwgdHJ1ZSwgWydlbmNyeXB0JywgJ2RlY3J5cHQnXSlcbn1cbiIsImltcG9ydCAqIGFzIEpPU0UgZnJvbSBcImpvc2VcIjtcbmltcG9ydCB7ZGlnZXN0LCBleHBvcnRSYXdLZXksIGltcG9ydFJhd0tleSwgaW1wb3J0U2VjcmV0fSBmcm9tIFwiI3Jhd1wiO1xuaW1wb3J0IHtleHRyYWN0YWJsZSwgc2lnbmluZ05hbWUsIHNpZ25pbmdDdXJ2ZSwgc2lnbmluZ0FsZ29yaXRobSwgZW5jcnlwdGluZ05hbWUsIGhhc2hMZW5ndGgsIGhhc2hOYW1lLCBtb2R1bHVzTGVuZ3RoLCBlbmNyeXB0aW5nQWxnb3JpdGhtLCBzeW1tZXRyaWNOYW1lLCBzeW1tZXRyaWNBbGdvcml0aG19IGZyb20gXCIuL2FsZ29yaXRobXMubWpzXCI7XG5cbmNvbnN0IEtyeXB0byA9IHtcbiAgLy8gQW4gaW5oZXJpdGFibGUgc2luZ2xldG9uIGZvciBjb21wYWN0IEpPU0Ugb3BlcmF0aW9ucy5cbiAgLy8gU2VlIGh0dHBzOi8va2lscm95LWNvZGUuZ2l0aHViLmlvL2Rpc3RyaWJ1dGVkLXNlY3VyaXR5L2RvY3MvaW1wbGVtZW50YXRpb24uaHRtbCN3cmFwcGluZy1zdWJ0bGVrcnlwdG9cbiAgZGVjb2RlUHJvdGVjdGVkSGVhZGVyOiBKT1NFLmRlY29kZVByb3RlY3RlZEhlYWRlcixcbiAgaXNFbXB0eUpXU1BheWxvYWQoY29tcGFjdEpXUykgeyAvLyBhcmcgaXMgYSBzdHJpbmdcbiAgICByZXR1cm4gIWNvbXBhY3RKV1Muc3BsaXQoJy4nKVsxXTtcbiAgfSxcblxuICAvLyBUaGUgY3R5IGNhbiBiZSBzcGVjaWZpZWQgaW4gZW5jcnlwdC9zaWduLCBidXQgZGVmYXVsdHMgdG8gYSBnb29kIGd1ZXNzLlxuICAvLyBUaGUgY3R5IGNhbiBiZSBzcGVjaWZpZWQgaW4gZGVjcnlwdC92ZXJpZnksIGJ1dCBkZWZhdWx0cyB0byB3aGF0IGlzIHNwZWNpZmllZCBpbiB0aGUgcHJvdGVjdGVkIGhlYWRlci5cbiAgaW5wdXRCdWZmZXIoZGF0YSwgaGVhZGVyKSB7IC8vIEFuc3dlcnMgYSBidWZmZXIgdmlldyBvZiBkYXRhIGFuZCwgaWYgbmVjZXNzYXJ5IHRvIGNvbnZlcnQsIGJhc2hlcyBjdHkgb2YgaGVhZGVyLlxuICAgIGlmIChBcnJheUJ1ZmZlci5pc1ZpZXcoZGF0YSkgJiYgIWhlYWRlci5jdHkpIHJldHVybiBkYXRhO1xuICAgIGxldCBnaXZlbkN0eSA9IGhlYWRlci5jdHkgfHwgJyc7XG4gICAgaWYgKGdpdmVuQ3R5LmluY2x1ZGVzKCd0ZXh0JykgfHwgKCdzdHJpbmcnID09PSB0eXBlb2YgZGF0YSkpIHtcbiAgICAgIGhlYWRlci5jdHkgPSBnaXZlbkN0eSB8fCAndGV4dC9wbGFpbic7XG4gICAgfSBlbHNlIHtcbiAgICAgIGhlYWRlci5jdHkgPSBnaXZlbkN0eSB8fCAnanNvbic7IC8vIEpXUyByZWNvbW1lbmRzIGxlYXZpbmcgb2ZmIHRoZSBsZWFkaW5nICdhcHBsaWNhdGlvbi8nLlxuICAgICAgZGF0YSA9IEpTT04uc3RyaW5naWZ5KGRhdGEpOyAvLyBOb3RlIHRoYXQgbmV3IFN0cmluZyhcInNvbWV0aGluZ1wiKSB3aWxsIHBhc3MgdGhpcyB3YXkuXG4gICAgfVxuICAgIHJldHVybiBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUoZGF0YSk7XG4gIH0sXG4gIHJlY292ZXJEYXRhRnJvbUNvbnRlbnRUeXBlKHJlc3VsdCwge2N0eSA9IHJlc3VsdD8ucHJvdGVjdGVkSGVhZGVyPy5jdHl9ID0ge30pIHtcbiAgICAvLyBFeGFtaW5lcyByZXN1bHQ/LnByb3RlY3RlZEhlYWRlciBhbmQgYmFzaGVzIGluIHJlc3VsdC50ZXh0IG9yIHJlc3VsdC5qc29uIGlmIGFwcHJvcHJpYXRlLCByZXR1cm5pbmcgcmVzdWx0LlxuICAgIGlmIChyZXN1bHQgJiYgIU9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChyZXN1bHQsICdwYXlsb2FkJykpIHJlc3VsdC5wYXlsb2FkID0gcmVzdWx0LnBsYWludGV4dDsgIC8vIGJlY2F1c2UgSk9TRSB1c2VzIHBsYWludGV4dCBmb3IgZGVjcnlwdCBhbmQgcGF5bG9hZCBmb3Igc2lnbi5cbiAgICBpZiAoIWN0eSB8fCAhcmVzdWx0Py5wYXlsb2FkKSByZXR1cm4gcmVzdWx0OyAvLyBlaXRoZXIgbm8gY3R5IG9yIG5vIHJlc3VsdFxuICAgIHJlc3VsdC50ZXh0ID0gbmV3IFRleHREZWNvZGVyKCkuZGVjb2RlKHJlc3VsdC5wYXlsb2FkKTtcbiAgICBpZiAoY3R5LmluY2x1ZGVzKCdqc29uJykpIHJlc3VsdC5qc29uID0gSlNPTi5wYXJzZShyZXN1bHQudGV4dCk7XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfSxcblxuICAvLyBTaWduL1ZlcmlmeVxuICBnZW5lcmF0ZVNpZ25pbmdLZXkoKSB7IC8vIFByb21pc2Uge3ByaXZhdGVLZXksIHB1YmxpY0tleX0gaW4gb3VyIHN0YW5kYXJkIHNpZ25pbmcgYWxnb3JpdGhtLlxuICAgIHJldHVybiBKT1NFLmdlbmVyYXRlS2V5UGFpcihzaWduaW5nQWxnb3JpdGhtLCB7ZXh0cmFjdGFibGV9KTtcbiAgfSxcbiAgYXN5bmMgc2lnbihwcml2YXRlS2V5LCBtZXNzYWdlLCBoZWFkZXJzID0ge30pIHsgLy8gUHJvbWlzZSBhIGNvbXBhY3QgSldTIHN0cmluZy4gQWNjZXB0cyBoZWFkZXJzIHRvIGJlIHByb3RlY3RlZC5cbiAgICBsZXQgaGVhZGVyID0ge2FsZzogc2lnbmluZ0FsZ29yaXRobSwgLi4uaGVhZGVyc30sXG4gICAgICAgIGlucHV0QnVmZmVyID0gdGhpcy5pbnB1dEJ1ZmZlcihtZXNzYWdlLCBoZWFkZXIpO1xuICAgIHJldHVybiBuZXcgSk9TRS5Db21wYWN0U2lnbihpbnB1dEJ1ZmZlcikuc2V0UHJvdGVjdGVkSGVhZGVyKGhlYWRlcikuc2lnbihwcml2YXRlS2V5KTtcbiAgfSxcbiAgYXN5bmMgdmVyaWZ5KHB1YmxpY0tleSwgc2lnbmF0dXJlLCBvcHRpb25zKSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259LCB3aGVyZSB0ZXh0IGFuZCBqc29uIGFyZSBvbmx5IGRlZmluZWQgd2hlbiBhcHByb3ByaWF0ZS5cbiAgICBsZXQgcmVzdWx0ID0gYXdhaXQgSk9TRS5jb21wYWN0VmVyaWZ5KHNpZ25hdHVyZSwgcHVibGljS2V5KS5jYXRjaCgoKSA9PiB1bmRlZmluZWQpO1xuICAgIHJldHVybiB0aGlzLnJlY292ZXJEYXRhRnJvbUNvbnRlbnRUeXBlKHJlc3VsdCwgb3B0aW9ucyk7XG4gIH0sXG5cbiAgLy8gRW5jcnlwdC9EZWNyeXB0XG4gIGdlbmVyYXRlRW5jcnlwdGluZ0tleSgpIHsgLy8gUHJvbWlzZSB7cHJpdmF0ZUtleSwgcHVibGljS2V5fSBpbiBvdXIgc3RhbmRhcmQgZW5jcnlwdGlvbiBhbGdvcml0aG0uXG4gICAgcmV0dXJuIEpPU0UuZ2VuZXJhdGVLZXlQYWlyKGVuY3J5cHRpbmdBbGdvcml0aG0sIHtleHRyYWN0YWJsZSwgbW9kdWx1c0xlbmd0aH0pO1xuICB9LFxuICBhc3luYyBlbmNyeXB0KGtleSwgbWVzc2FnZSwgaGVhZGVycyA9IHt9KSB7IC8vIFByb21pc2UgYSBjb21wYWN0IEpXRSBzdHJpbmcuIEFjY2VwdHMgaGVhZGVycyB0byBiZSBwcm90ZWN0ZWQuXG4gICAgbGV0IGFsZyA9IHRoaXMuaXNTeW1tZXRyaWMoa2V5KSA/ICdkaXInIDogZW5jcnlwdGluZ0FsZ29yaXRobSxcbiAgICAgICAgaGVhZGVyID0ge2FsZywgZW5jOiBzeW1tZXRyaWNBbGdvcml0aG0sIC4uLmhlYWRlcnN9LFxuICAgICAgICBpbnB1dEJ1ZmZlciA9IHRoaXMuaW5wdXRCdWZmZXIobWVzc2FnZSwgaGVhZGVyKSxcbiAgICAgICAgc2VjcmV0ID0gdGhpcy5rZXlTZWNyZXQoa2V5KTtcbiAgICByZXR1cm4gbmV3IEpPU0UuQ29tcGFjdEVuY3J5cHQoaW5wdXRCdWZmZXIpLnNldFByb3RlY3RlZEhlYWRlcihoZWFkZXIpLmVuY3J5cHQoc2VjcmV0KTtcbiAgfSxcbiAgYXN5bmMgZGVjcnlwdChrZXksIGVuY3J5cHRlZCwgb3B0aW9ucyA9IHt9KSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259LCB3aGVyZSB0ZXh0IGFuZCBqc29uIGFyZSBvbmx5IGRlZmluZWQgd2hlbiBhcHByb3ByaWF0ZS5cbiAgICBsZXQgc2VjcmV0ID0gdGhpcy5rZXlTZWNyZXQoa2V5KSxcbiAgICAgICAgcmVzdWx0ID0gYXdhaXQgSk9TRS5jb21wYWN0RGVjcnlwdChlbmNyeXB0ZWQsIHNlY3JldCk7XG4gICAgdGhpcy5yZWNvdmVyRGF0YUZyb21Db250ZW50VHlwZShyZXN1bHQsIG9wdGlvbnMpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH0sXG4gIGFzeW5jIGdlbmVyYXRlU2VjcmV0S2V5KHRleHQpIHsgLy8gSk9TRSB1c2VzIGEgZGlnZXN0IGZvciBQQkVTLCBidXQgbWFrZSBpdCByZWNvZ25pemFibGUgYXMgYSB7dHlwZTogJ3NlY3JldCd9IGtleS5cbiAgICBsZXQgYnVmZmVyID0gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHRleHQpLFxuICAgICAgICBoYXNoID0gYXdhaXQgZGlnZXN0KGhhc2hOYW1lLCBidWZmZXIpO1xuICAgIHJldHVybiB7dHlwZTogJ3NlY3JldCcsIHRleHQ6IG5ldyBVaW50OEFycmF5KGhhc2gpfTtcbiAgfSxcbiAgZ2VuZXJhdGVTeW1tZXRyaWNLZXkodGV4dCkgeyAvLyBQcm9taXNlIGEga2V5IGZvciBzeW1tZXRyaWMgZW5jcnlwdGlvbi5cbiAgICBpZiAodGV4dCkgcmV0dXJuIHRoaXMuZ2VuZXJhdGVTZWNyZXRLZXkodGV4dCk7IC8vIFBCRVNcbiAgICByZXR1cm4gSk9TRS5nZW5lcmF0ZVNlY3JldChzeW1tZXRyaWNBbGdvcml0aG0sIHtleHRyYWN0YWJsZX0pOyAvLyBBRVNcbiAgfSxcbiAgaXNTeW1tZXRyaWMoa2V5KSB7IC8vIEVpdGhlciBBRVMgb3IgUEJFUywgYnV0IG5vdCBwdWJsaWNLZXkgb3IgcHJpdmF0ZUtleS5cbiAgICByZXR1cm4ga2V5LnR5cGUgPT09ICdzZWNyZXQnO1xuICB9LFxuICBrZXlTZWNyZXQoa2V5KSB7IC8vIFJldHVybiB3aGF0IGlzIGFjdHVhbGx5IHVzZWQgYXMgaW5wdXQgaW4gSk9TRSBsaWJyYXJ5LlxuICAgIGlmIChrZXkudGV4dCkgcmV0dXJuIGtleS50ZXh0O1xuICAgIHJldHVybiBrZXk7XG4gIH0sXG5cbiAgLy8gRXhwb3J0L0ltcG9ydFxuICBhc3luYyBleHBvcnRSYXcoa2V5KSB7IC8vIGJhc2U2NHVybCBmb3IgcHVibGljIHZlcmZpY2F0aW9uIGtleXNcbiAgICBsZXQgYXJyYXlCdWZmZXIgPSBhd2FpdCBleHBvcnRSYXdLZXkoa2V5KTtcbiAgICByZXR1cm4gSk9TRS5iYXNlNjR1cmwuZW5jb2RlKG5ldyBVaW50OEFycmF5KGFycmF5QnVmZmVyKSk7XG4gIH0sXG4gIGFzeW5jIGltcG9ydFJhdyhzdHJpbmcpIHsgLy8gUHJvbWlzZSB0aGUgdmVyaWZpY2F0aW9uIGtleSBmcm9tIGJhc2U2NHVybFxuICAgIGxldCBhcnJheUJ1ZmZlciA9IEpPU0UuYmFzZTY0dXJsLmRlY29kZShzdHJpbmcpO1xuICAgIHJldHVybiBpbXBvcnRSYXdLZXkoYXJyYXlCdWZmZXIpO1xuICB9LFxuICBhc3luYyBleHBvcnRKV0soa2V5KSB7IC8vIFByb21pc2UgSldLIG9iamVjdCwgd2l0aCBhbGcgaW5jbHVkZWQuXG4gICAgbGV0IGV4cG9ydGVkID0gYXdhaXQgSk9TRS5leHBvcnRKV0soa2V5KSxcbiAgICAgICAgYWxnID0ga2V5LmFsZ29yaXRobTsgLy8gSk9TRSBsaWJyYXJ5IGdpdmVzIGFsZ29yaXRobSwgYnV0IG5vdCBhbGcgdGhhdCBpcyBuZWVkZWQgZm9yIGltcG9ydC5cbiAgICBpZiAoYWxnKSB7IC8vIHN1YnRsZS5jcnlwdG8gdW5kZXJseWluZyBrZXlzXG4gICAgICBpZiAoYWxnLm5hbWUgPT09IHNpZ25pbmdOYW1lICYmIGFsZy5uYW1lZEN1cnZlID09PSBzaWduaW5nQ3VydmUpIGV4cG9ydGVkLmFsZyA9IHNpZ25pbmdBbGdvcml0aG07XG4gICAgICBlbHNlIGlmIChhbGcubmFtZSA9PT0gZW5jcnlwdGluZ05hbWUgJiYgYWxnLmhhc2gubmFtZSA9PT0gaGFzaE5hbWUpIGV4cG9ydGVkLmFsZyA9IGVuY3J5cHRpbmdBbGdvcml0aG07XG4gICAgICBlbHNlIGlmIChhbGcubmFtZSA9PT0gc3ltbWV0cmljTmFtZSAmJiBhbGcubGVuZ3RoID09PSBoYXNoTGVuZ3RoKSBleHBvcnRlZC5hbGcgPSBzeW1tZXRyaWNBbGdvcml0aG07XG4gICAgfSBlbHNlIHN3aXRjaCAoZXhwb3J0ZWQua3R5KSB7IC8vIEpPU0Ugb24gTm9kZUpTIHVzZWQgbm9kZTpjcnlwdG8ga2V5cywgd2hpY2ggZG8gbm90IGV4cG9zZSB0aGUgcHJlY2lzZSBhbGdvcml0aG1cbiAgICAgIGNhc2UgJ0VDJzogZXhwb3J0ZWQuYWxnID0gc2lnbmluZ0FsZ29yaXRobTsgYnJlYWs7XG4gICAgICBjYXNlICdSU0EnOiBleHBvcnRlZC5hbGcgPSBlbmNyeXB0aW5nQWxnb3JpdGhtOyBicmVhaztcbiAgICAgIGNhc2UgJ29jdCc6IGV4cG9ydGVkLmFsZyA9IHN5bW1ldHJpY0FsZ29yaXRobTsgYnJlYWs7XG4gICAgfVxuICAgIHJldHVybiBleHBvcnRlZDtcbiAgfSxcbiAgYXN5bmMgaW1wb3J0SldLKGp3aykgeyAvLyBQcm9taXNlIGEga2V5IG9iamVjdFxuICAgIGp3ayA9IHtleHQ6IHRydWUsIC4uLmp3a307IC8vIFdlIG5lZWQgdGhlIHJlc3VsdCB0byBiZSBiZSBhYmxlIHRvIGdlbmVyYXRlIGEgbmV3IEpXSyAoZS5nLiwgb24gY2hhbmdlTWVtYmVyc2hpcClcbiAgICBsZXQgaW1wb3J0ZWQgPSBhd2FpdCBKT1NFLmltcG9ydEpXSyhqd2spO1xuICAgIGlmIChpbXBvcnRlZCBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgIC8vIFdlIGRlcGVuZCBhbiByZXR1cm5pbmcgYW4gYWN0dWFsIGtleSwgYnV0IHRoZSBKT1NFIGxpYnJhcnkgd2UgdXNlXG4gICAgICAvLyB3aWxsIGFib3ZlIHByb2R1Y2UgdGhlIHJhdyBVaW50OEFycmF5IGlmIHRoZSBqd2sgaXMgZnJvbSBhIHNlY3JldC5cbiAgICAgIGltcG9ydGVkID0gYXdhaXQgaW1wb3J0U2VjcmV0KGltcG9ydGVkKTtcbiAgICB9XG4gICAgcmV0dXJuIGltcG9ydGVkO1xuICB9LFxuXG4gIGFzeW5jIHdyYXBLZXkoa2V5LCB3cmFwcGluZ0tleSwgaGVhZGVycyA9IHt9KSB7IC8vIFByb21pc2UgYSBKV0UgZnJvbSB0aGUgcHVibGljIHdyYXBwaW5nS2V5XG4gICAgbGV0IGV4cG9ydGVkID0gYXdhaXQgdGhpcy5leHBvcnRKV0soa2V5KTtcbiAgICByZXR1cm4gdGhpcy5lbmNyeXB0KHdyYXBwaW5nS2V5LCBleHBvcnRlZCwgaGVhZGVycyk7XG4gIH0sXG4gIGFzeW5jIHVud3JhcEtleSh3cmFwcGVkS2V5LCB1bndyYXBwaW5nS2V5KSB7IC8vIFByb21pc2UgdGhlIGtleSB1bmxvY2tlZCBieSB0aGUgcHJpdmF0ZSB1bndyYXBwaW5nS2V5LlxuICAgIGxldCBkZWNyeXB0ZWQgPSBhd2FpdCB0aGlzLmRlY3J5cHQodW53cmFwcGluZ0tleSwgd3JhcHBlZEtleSk7XG4gICAgcmV0dXJuIHRoaXMuaW1wb3J0SldLKGRlY3J5cHRlZC5qc29uKTtcbiAgfVxufVxuXG5leHBvcnQgZGVmYXVsdCBLcnlwdG87XG4vKlxuU29tZSB1c2VmdWwgSk9TRSByZWNpcGVzIGZvciBwbGF5aW5nIGFyb3VuZC5cbnNrID0gYXdhaXQgSk9TRS5nZW5lcmF0ZUtleVBhaXIoJ0VTMzg0Jywge2V4dHJhY3RhYmxlOiB0cnVlfSlcbmp3dCA9IGF3YWl0IG5ldyBKT1NFLlNpZ25KV1QoKS5zZXRTdWJqZWN0KFwiZm9vXCIpLnNldFByb3RlY3RlZEhlYWRlcih7YWxnOidFUzM4NCd9KS5zaWduKHNrLnByaXZhdGVLZXkpXG5hd2FpdCBKT1NFLmp3dFZlcmlmeShqd3QsIHNrLnB1YmxpY0tleSkgLy8ucGF5bG9hZC5zdWJcblxubWVzc2FnZSA9IG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZSgnc29tZSBtZXNzYWdlJylcbmp3cyA9IGF3YWl0IG5ldyBKT1NFLkNvbXBhY3RTaWduKG1lc3NhZ2UpLnNldFByb3RlY3RlZEhlYWRlcih7YWxnOidFUzM4NCd9KS5zaWduKHNrLnByaXZhdGVLZXkpIC8vIE9yIEZsYXR0ZW5lZFNpZ25cbmp3cyA9IGF3YWl0IG5ldyBKT1NFLkdlbmVyYWxTaWduKG1lc3NhZ2UpLmFkZFNpZ25hdHVyZShzay5wcml2YXRlS2V5KS5zZXRQcm90ZWN0ZWRIZWFkZXIoe2FsZzonRVMzODQnfSkuc2lnbigpXG52ZXJpZmllZCA9IGF3YWl0IEpPU0UuZ2VuZXJhbFZlcmlmeShqd3MsIHNrLnB1YmxpY0tleSlcbm9yIGNvbXBhY3RWZXJpZnkgb3IgZmxhdHRlbmVkVmVyaWZ5XG5uZXcgVGV4dERlY29kZXIoKS5kZWNvZGUodmVyaWZpZWQucGF5bG9hZClcblxuZWsgPSBhd2FpdCBKT1NFLmdlbmVyYXRlS2V5UGFpcignUlNBLU9BRVAtMjU2Jywge2V4dHJhY3RhYmxlOiB0cnVlfSlcbmp3ZSA9IGF3YWl0IG5ldyBKT1NFLkNvbXBhY3RFbmNyeXB0KG1lc3NhZ2UpLnNldFByb3RlY3RlZEhlYWRlcih7YWxnOiAnUlNBLU9BRVAtMjU2JywgZW5jOiAnQTI1NkdDTScgfSkuZW5jcnlwdChlay5wdWJsaWNLZXkpXG5vciBGbGF0dGVuZWRFbmNyeXB0LiBGb3Igc3ltbWV0cmljIHNlY3JldCwgc3BlY2lmeSBhbGc6J2RpcicuXG5kZWNyeXB0ZWQgPSBhd2FpdCBKT1NFLmNvbXBhY3REZWNyeXB0KGp3ZSwgZWsucHJpdmF0ZUtleSlcbm5ldyBUZXh0RGVjb2RlcigpLmRlY29kZShkZWNyeXB0ZWQucGxhaW50ZXh0KVxuandlID0gYXdhaXQgbmV3IEpPU0UuR2VuZXJhbEVuY3J5cHQobWVzc2FnZSkuc2V0UHJvdGVjdGVkSGVhZGVyKHthbGc6ICdSU0EtT0FFUC0yNTYnLCBlbmM6ICdBMjU2R0NNJyB9KS5hZGRSZWNpcGllbnQoZWsucHVibGljS2V5KS5lbmNyeXB0KCkgLy8gd2l0aCBhZGRpdGlvbmFsIGFkZFJlY2lwZW50KCkgYXMgbmVlZGVkXG5kZWNyeXB0ZWQgPSBhd2FpdCBKT1NFLmdlbmVyYWxEZWNyeXB0KGp3ZSwgZWsucHJpdmF0ZUtleSlcblxubWF0ZXJpYWwgPSBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUoJ3NlY3JldCcpXG5qd2UgPSBhd2FpdCBuZXcgSk9TRS5Db21wYWN0RW5jcnlwdChtZXNzYWdlKS5zZXRQcm90ZWN0ZWRIZWFkZXIoe2FsZzogJ1BCRVMyLUhTNTEyK0EyNTZLVycsIGVuYzogJ0EyNTZHQ00nIH0pLmVuY3J5cHQobWF0ZXJpYWwpXG5kZWNyeXB0ZWQgPSBhd2FpdCBKT1NFLmNvbXBhY3REZWNyeXB0KGp3ZSwgbWF0ZXJpYWwsIHtrZXlNYW5hZ2VtZW50QWxnb3JpdGhtczogWydQQkVTMi1IUzUxMitBMjU2S1cnXSwgY29udGVudEVuY3J5cHRpb25BbGdvcml0aG1zOiBbJ0EyNTZHQ00nXX0pXG5qd2UgPSBhd2FpdCBuZXcgSk9TRS5HZW5lcmFsRW5jcnlwdChtZXNzYWdlKS5zZXRQcm90ZWN0ZWRIZWFkZXIoe2FsZzogJ1BCRVMyLUhTNTEyK0EyNTZLVycsIGVuYzogJ0EyNTZHQ00nIH0pLmFkZFJlY2lwaWVudChtYXRlcmlhbCkuZW5jcnlwdCgpXG5qd2UgPSBhd2FpdCBuZXcgSk9TRS5HZW5lcmFsRW5jcnlwdChtZXNzYWdlKS5zZXRQcm90ZWN0ZWRIZWFkZXIoe2VuYzogJ0EyNTZHQ00nIH0pXG4gIC5hZGRSZWNpcGllbnQoZWsucHVibGljS2V5KS5zZXRVbnByb3RlY3RlZEhlYWRlcih7a2lkOiAnZm9vJywgYWxnOiAnUlNBLU9BRVAtMjU2J30pXG4gIC5hZGRSZWNpcGllbnQobWF0ZXJpYWwpLnNldFVucHJvdGVjdGVkSGVhZGVyKHtraWQ6ICdzZWNyZXQxJywgYWxnOiAnUEJFUzItSFM1MTIrQTI1NktXJ30pXG4gIC5hZGRSZWNpcGllbnQobWF0ZXJpYWwyKS5zZXRVbnByb3RlY3RlZEhlYWRlcih7a2lkOiAnc2VjcmV0MicsIGFsZzogJ1BCRVMyLUhTNTEyK0EyNTZLVyd9KVxuICAuZW5jcnlwdCgpXG5kZWNyeXB0ZWQgPSBhd2FpdCBKT1NFLmdlbmVyYWxEZWNyeXB0KGp3ZSwgZWsucHJpdmF0ZUtleSlcbmRlY3J5cHRlZCA9IGF3YWl0IEpPU0UuZ2VuZXJhbERlY3J5cHQoandlLCBtYXRlcmlhbCwge2tleU1hbmFnZW1lbnRBbGdvcml0aG1zOiBbJ1BCRVMyLUhTNTEyK0EyNTZLVyddfSlcbiovXG4iLCJpbXBvcnQgS3J5cHRvIGZyb20gXCIuL2tyeXB0by5tanNcIjtcbmltcG9ydCAqIGFzIEpPU0UgZnJvbSBcImpvc2VcIjtcbmltcG9ydCB7c2lnbmluZ0FsZ29yaXRobSwgZW5jcnlwdGluZ0FsZ29yaXRobSwgc3ltbWV0cmljQWxnb3JpdGhtLCBzeW1tZXRyaWNXcmFwLCBzZWNyZXRBbGdvcml0aG19IGZyb20gXCIuL2FsZ29yaXRobXMubWpzXCI7XG5cbmZ1bmN0aW9uIG1pc21hdGNoKGtpZCwgZW5jb2RlZEtpZCkgeyAvLyBQcm9taXNlIGEgcmVqZWN0aW9uLlxuICBsZXQgbWVzc2FnZSA9IGBLZXkgJHtraWR9IGRvZXMgbm90IG1hdGNoIGVuY29kZWQgJHtlbmNvZGVkS2lkfS5gO1xuICByZXR1cm4gUHJvbWlzZS5yZWplY3QobWVzc2FnZSk7XG59XG5cbmNvbnN0IE11bHRpS3J5cHRvID0ge1xuICAvLyBFeHRlbmQgS3J5cHRvIGZvciBnZW5lcmFsIChtdWx0aXBsZSBrZXkpIEpPU0Ugb3BlcmF0aW9ucy5cbiAgLy8gU2VlIGh0dHBzOi8va2lscm95LWNvZGUuZ2l0aHViLmlvL2Rpc3RyaWJ1dGVkLXNlY3VyaXR5L2RvY3MvaW1wbGVtZW50YXRpb24uaHRtbCNjb21iaW5pbmcta2V5c1xuICBcbiAgLy8gT3VyIG11bHRpIGtleXMgYXJlIGRpY3Rpb25hcmllcyBvZiBuYW1lIChvciBraWQpID0+IGtleU9iamVjdC5cbiAgaXNNdWx0aUtleShrZXkpIHsgLy8gQSBTdWJ0bGVDcnlwdG8gQ3J5cHRvS2V5IGlzIGFuIG9iamVjdCB3aXRoIGEgdHlwZSBwcm9wZXJ0eS4gT3VyIG11bHRpa2V5cyBhcmVcbiAgICAvLyBvYmplY3RzIHdpdGggYSBzcGVjaWZpYyB0eXBlIG9yIG5vIHR5cGUgcHJvcGVydHkgYXQgYWxsLlxuICAgIHJldHVybiAoa2V5LnR5cGUgfHwgJ211bHRpJykgPT09ICdtdWx0aSc7XG4gIH0sXG4gIGtleVRhZ3Moa2V5KSB7IC8vIEp1c3QgdGhlIGtpZHMgdGhhdCBhcmUgZm9yIGFjdHVhbCBrZXlzLiBObyAndHlwZScuXG4gICAgcmV0dXJuIE9iamVjdC5rZXlzKGtleSkuZmlsdGVyKGtleSA9PiBrZXkgIT09ICd0eXBlJyk7XG4gIH0sXG5cbiAgLy8gRXhwb3J0L0ltcG9ydFxuICBhc3luYyBleHBvcnRKV0soa2V5KSB7IC8vIFByb21pc2UgYSBKV0sga2V5IHNldCBpZiBuZWNlc3NhcnksIHJldGFpbmluZyB0aGUgbmFtZXMgYXMga2lkIHByb3BlcnR5LlxuICAgIGlmICghdGhpcy5pc011bHRpS2V5KGtleSkpIHJldHVybiBzdXBlci5leHBvcnRKV0soa2V5KTtcbiAgICBsZXQgbmFtZXMgPSB0aGlzLmtleVRhZ3Moa2V5KSxcbiAgICAgICAga2V5cyA9IGF3YWl0IFByb21pc2UuYWxsKG5hbWVzLm1hcChhc3luYyBuYW1lID0+IHtcbiAgICAgICAgICBsZXQgandrID0gYXdhaXQgdGhpcy5leHBvcnRKV0soa2V5W25hbWVdKTtcbiAgICAgICAgICBqd2sua2lkID0gbmFtZTtcbiAgICAgICAgICByZXR1cm4gandrO1xuICAgICAgICB9KSk7XG4gICAgcmV0dXJuIHtrZXlzfTtcbiAgfSxcbiAgYXN5bmMgaW1wb3J0SldLKGp3aykgeyAvLyBQcm9taXNlIGEgc2luZ2xlIFwia2V5XCIgb2JqZWN0LlxuICAgIC8vIFJlc3VsdCB3aWxsIGJlIGEgbXVsdGkta2V5IGlmIEpXSyBpcyBhIGtleSBzZXQsIGluIHdoaWNoIGNhc2UgZWFjaCBtdXN0IGluY2x1ZGUgYSBraWQgcHJvcGVydHkuXG4gICAgaWYgKCFqd2sua2V5cykgcmV0dXJuIHN1cGVyLmltcG9ydEpXSyhqd2spO1xuICAgIGxldCBrZXkgPSB7fTsgLy8gVE9ETzogZ2V0IHR5cGUgZnJvbSBrdHkgb3Igc29tZSBzdWNoP1xuICAgIGF3YWl0IFByb21pc2UuYWxsKGp3ay5rZXlzLm1hcChhc3luYyBqd2sgPT4ga2V5W2p3ay5raWRdID0gYXdhaXQgdGhpcy5pbXBvcnRKV0soandrKSkpO1xuICAgIHJldHVybiBrZXk7XG4gIH0sXG5cbiAgLy8gRW5jcnlwdC9EZWNyeXB0XG4gIGFzeW5jIGVuY3J5cHQoa2V5LCBtZXNzYWdlLCBoZWFkZXJzID0ge30pIHsgLy8gUHJvbWlzZSBhIEpXRSwgaW4gZ2VuZXJhbCBmb3JtIGlmIGFwcHJvcHJpYXRlLlxuICAgIGlmICghdGhpcy5pc011bHRpS2V5KGtleSkpIHJldHVybiBzdXBlci5lbmNyeXB0KGtleSwgbWVzc2FnZSwgaGVhZGVycyk7XG4gICAgLy8ga2V5IG11c3QgYmUgYSBkaWN0aW9uYXJ5IG1hcHBpbmcgdGFncyB0byBlbmNyeXB0aW5nIGtleXMuXG4gICAgbGV0IGJhc2VIZWFkZXIgPSB7ZW5jOiBzeW1tZXRyaWNBbGdvcml0aG0sIC4uLmhlYWRlcnN9LFxuICAgICAgICBpbnB1dEJ1ZmZlciA9IHRoaXMuaW5wdXRCdWZmZXIobWVzc2FnZSwgYmFzZUhlYWRlciksXG4gICAgICAgIGp3ZSA9IG5ldyBKT1NFLkdlbmVyYWxFbmNyeXB0KGlucHV0QnVmZmVyKS5zZXRQcm90ZWN0ZWRIZWFkZXIoYmFzZUhlYWRlcik7XG4gICAgZm9yIChsZXQgdGFnIG9mIHRoaXMua2V5VGFncyhrZXkpKSB7XG4gICAgICBsZXQgdGhpc0tleSA9IGtleVt0YWddLFxuICAgICAgICAgIGlzU3RyaW5nID0gJ3N0cmluZycgPT09IHR5cGVvZiB0aGlzS2V5LFxuICAgICAgICAgIGlzU3ltID0gaXNTdHJpbmcgfHwgdGhpcy5pc1N5bW1ldHJpYyh0aGlzS2V5KSxcbiAgICAgICAgICBzZWNyZXQgPSBpc1N0cmluZyA/IG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZSh0aGlzS2V5KSA6IHRoaXMua2V5U2VjcmV0KHRoaXNLZXkpLFxuICAgICAgICAgIGFsZyA9IGlzU3RyaW5nID8gc2VjcmV0QWxnb3JpdGhtIDogKGlzU3ltID8gc3ltbWV0cmljV3JhcCA6IGVuY3J5cHRpbmdBbGdvcml0aG0pO1xuICAgICAgLy8gVGhlIGtpZCBhbmQgYWxnIGFyZSBwZXIvc3ViLWtleSwgYW5kIHNvIGNhbm5vdCBiZSBzaWduZWQgYnkgYWxsLCBhbmQgc28gY2Fubm90IGJlIHByb3RlY3RlZCB3aXRoaW4gdGhlIGVuY3J5cHRpb24uXG4gICAgICAvLyBUaGlzIGlzIG9rLCBiZWNhdXNlIHRoZSBvbmx5IHRoYXQgY2FuIGhhcHBlbiBhcyBhIHJlc3VsdCBvZiB0YW1wZXJpbmcgd2l0aCB0aGVzZSBpcyB0aGF0IHRoZSBkZWNyeXB0aW9uIHdpbGwgZmFpbCxcbiAgICAgIC8vIHdoaWNoIGlzIHRoZSBzYW1lIHJlc3VsdCBhcyB0YW1wZXJpbmcgd2l0aCB0aGUgY2lwaGVydGV4dCBvciBhbnkgb3RoZXIgcGFydCBvZiB0aGUgSldFLlxuICAgICAgandlLmFkZFJlY2lwaWVudChzZWNyZXQpLnNldFVucHJvdGVjdGVkSGVhZGVyKHtraWQ6IHRhZywgYWxnfSk7XG4gICAgfVxuICAgIGxldCBlbmNyeXB0ZWQgPSBhd2FpdCBqd2UuZW5jcnlwdCgpO1xuICAgIHJldHVybiBlbmNyeXB0ZWQ7XG4gIH0sXG4gIGFzeW5jIGRlY3J5cHQoa2V5LCBlbmNyeXB0ZWQsIG9wdGlvbnMpIHsgLy8gUHJvbWlzZSB7cGF5bG9hZCwgdGV4dCwganNvbn0sIHdoZXJlIHRleHQgYW5kIGpzb24gYXJlIG9ubHkgZGVmaW5lZCB3aGVuIGFwcHJvcHJpYXRlLlxuICAgIGlmICghdGhpcy5pc011bHRpS2V5KGtleSkpIHJldHVybiBzdXBlci5kZWNyeXB0KGtleSwgZW5jcnlwdGVkLCBvcHRpb25zKTtcbiAgICBsZXQgandlID0gZW5jcnlwdGVkLFxuICAgICAgICB7cmVjaXBpZW50c30gPSBqd2UsXG4gICAgICAgIHVud3JhcHBpbmdQcm9taXNlcyA9IHJlY2lwaWVudHMubWFwKGFzeW5jICh7aGVhZGVyfSkgPT4ge1xuICAgICAgICAgIGxldCB7a2lkfSA9IGhlYWRlcixcbiAgICAgICAgICAgICAgdW53cmFwcGluZ0tleSA9IGtleVtraWRdLFxuICAgICAgICAgICAgICBvcHRpb25zID0ge307XG4gICAgICAgICAgaWYgKCF1bndyYXBwaW5nS2V5KSByZXR1cm4gUHJvbWlzZS5yZWplY3QoJ21pc3NpbmcnKTtcbiAgICAgICAgICBpZiAoJ3N0cmluZycgPT09IHR5cGVvZiB1bndyYXBwaW5nS2V5KSB7IC8vIFRPRE86IG9ubHkgc3BlY2lmaWVkIGlmIGFsbG93ZWQgYnkgc2VjdXJlIGhlYWRlcj9cbiAgICAgICAgICAgIHVud3JhcHBpbmdLZXkgPSBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUodW53cmFwcGluZ0tleSk7XG4gICAgICAgICAgICBvcHRpb25zLmtleU1hbmFnZW1lbnRBbGdvcml0aG1zID0gW3NlY3JldEFsZ29yaXRobV07XG4gICAgICAgICAgfVxuICAgICAgICAgIGxldCByZXN1bHQgPSBhd2FpdCBKT1NFLmdlbmVyYWxEZWNyeXB0KGp3ZSwgdGhpcy5rZXlTZWNyZXQodW53cmFwcGluZ0tleSksIG9wdGlvbnMpLFxuICAgICAgICAgICAgICBlbmNvZGVkS2lkID0gcmVzdWx0LnVucHJvdGVjdGVkSGVhZGVyLmtpZDtcbiAgICAgICAgICBpZiAoZW5jb2RlZEtpZCAhPT0ga2lkKSByZXR1cm4gbWlzbWF0Y2goa2lkLCBlbmNvZGVkS2lkKTtcbiAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICB9KTtcbiAgICAvLyBEbyB3ZSByZWFsbHkgd2FudCB0byByZXR1cm4gdW5kZWZpbmVkIGlmIGV2ZXJ5dGhpbmcgZmFpbHM/IFNob3VsZCBqdXN0IGFsbG93IHRoZSByZWplY3Rpb24gdG8gcHJvcGFnYXRlP1xuICAgIHJldHVybiBhd2FpdCBQcm9taXNlLmFueSh1bndyYXBwaW5nUHJvbWlzZXMpLnRoZW4oXG4gICAgICByZXN1bHQgPT4ge1xuICAgICAgICB0aGlzLnJlY292ZXJEYXRhRnJvbUNvbnRlbnRUeXBlKHJlc3VsdCwgb3B0aW9ucyk7XG4gICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICB9LFxuICAgICAgKCkgPT4gdW5kZWZpbmVkKTtcbiAgfSxcblxuICAvLyBTaWduL1ZlcmlmeVxuICBhc3luYyBzaWduKGtleSwgbWVzc2FnZSwgaGVhZGVyID0ge30pIHsgLy8gUHJvbWlzZSBKV1MsIGluIGdlbmVyYWwgZm9ybSB3aXRoIGtpZCBoZWFkZXJzIGlmIG5lY2Vzc2FyeS5cbiAgICBpZiAoIXRoaXMuaXNNdWx0aUtleShrZXkpKSByZXR1cm4gc3VwZXIuc2lnbihrZXksIG1lc3NhZ2UsIGhlYWRlcik7XG4gICAgbGV0IGlucHV0QnVmZmVyID0gdGhpcy5pbnB1dEJ1ZmZlcihtZXNzYWdlLCBoZWFkZXIpLFxuICAgICAgICBqd3MgPSBuZXcgSk9TRS5HZW5lcmFsU2lnbihpbnB1dEJ1ZmZlcik7XG4gICAgZm9yIChsZXQgdGFnIG9mIHRoaXMua2V5VGFncyhrZXkpKSB7XG4gICAgICBsZXQgdGhpc0tleSA9IGtleVt0YWddLFxuICAgICAgICAgIHRoaXNIZWFkZXIgPSB7a2lkOiB0YWcsIGFsZzogc2lnbmluZ0FsZ29yaXRobSwgLi4uaGVhZGVyfTtcbiAgICAgIGp3cy5hZGRTaWduYXR1cmUodGhpc0tleSkuc2V0UHJvdGVjdGVkSGVhZGVyKHRoaXNIZWFkZXIpO1xuICAgIH1cbiAgICByZXR1cm4gandzLnNpZ24oKTtcbiAgfSxcbiAgdmVyaWZ5U3ViU2lnbmF0dXJlKGp3cywgc2lnbmF0dXJlRWxlbWVudCwgbXVsdGlLZXksIGtpZHMpIHtcbiAgICAvLyBWZXJpZnkgYSBzaW5nbGUgZWxlbWVudCBvZiBqd3Muc2lnbmF0dXJlIHVzaW5nIG11bHRpS2V5LlxuICAgIC8vIEFsd2F5cyBwcm9taXNlcyB7cHJvdGVjdGVkSGVhZGVyLCB1bnByb3RlY3RlZEhlYWRlciwga2lkfSwgZXZlbiBpZiB2ZXJpZmljYXRpb24gZmFpbHMsXG4gICAgLy8gd2hlcmUga2lkIGlzIHRoZSBwcm9wZXJ0eSBuYW1lIHdpdGhpbiBtdWx0aUtleSB0aGF0IG1hdGNoZWQgKGVpdGhlciBieSBiZWluZyBzcGVjaWZpZWQgaW4gYSBoZWFkZXJcbiAgICAvLyBvciBieSBzdWNjZXNzZnVsIHZlcmlmaWNhdGlvbikuIEFsc28gaW5jbHVkZXMgdGhlIGRlY29kZWQgcGF5bG9hZCBJRkYgdGhlcmUgaXMgYSBtYXRjaC5cbiAgICBsZXQgcHJvdGVjdGVkSGVhZGVyID0gc2lnbmF0dXJlRWxlbWVudC5wcm90ZWN0ZWRIZWFkZXIgPz8gdGhpcy5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIoc2lnbmF0dXJlRWxlbWVudCksXG4gICAgICAgIHVucHJvdGVjdGVkSGVhZGVyID0gc2lnbmF0dXJlRWxlbWVudC51bnByb3RlY3RlZEhlYWRlcixcbiAgICAgICAga2lkID0gcHJvdGVjdGVkSGVhZGVyPy5raWQgfHwgdW5wcm90ZWN0ZWRIZWFkZXI/LmtpZCxcbiAgICAgICAgc2luZ2xlSldTID0gey4uLmp3cywgc2lnbmF0dXJlczogW3NpZ25hdHVyZUVsZW1lbnRdfSxcbiAgICAgICAgZmFpbHVyZVJlc3VsdCA9IHtwcm90ZWN0ZWRIZWFkZXIsIHVucHJvdGVjdGVkSGVhZGVyLCBraWR9LFxuICAgICAgICBraWRzVG9UcnkgPSBraWQgPyBba2lkXSA6IGtpZHM7XG4gICAgbGV0IHByb21pc2UgPSBQcm9taXNlLmFueShraWRzVG9UcnkubWFwKGFzeW5jIGtpZCA9PiBKT1NFLmdlbmVyYWxWZXJpZnkoc2luZ2xlSldTLCBtdWx0aUtleVtraWRdKS50aGVuKHJlc3VsdCA9PiB7cmV0dXJuIHtraWQsIC4uLnJlc3VsdH07fSkpKTtcbiAgICByZXR1cm4gcHJvbWlzZS5jYXRjaCgoKSA9PiBmYWlsdXJlUmVzdWx0KTtcbiAgfSxcbiAgYXN5bmMgdmVyaWZ5KGtleSwgc2lnbmF0dXJlLCBvcHRpb25zID0ge30pIHsgLy8gUHJvbWlzZSB7cGF5bG9hZCwgdGV4dCwganNvbn0sIHdoZXJlIHRleHQgYW5kIGpzb24gYXJlIG9ubHkgZGVmaW5lZCB3aGVuIGFwcHJvcHJpYXRlLlxuICAgIC8vIEFkZGl0aW9uYWxseSwgaWYga2V5IGlzIGEgbXVsdGlLZXkgQU5EIHNpZ25hdHVyZSBpcyBhIGdlbmVyYWwgZm9ybSBKV1MsIHRoZW4gYW5zd2VyIGluY2x1ZGVzIGEgc2lnbmVycyBwcm9wZXJ0eVxuICAgIC8vIGJ5IHdoaWNoIGNhbGxlciBjYW4gZGV0ZXJtaW5lIGlmIGl0IHdoYXQgdGhleSBleHBlY3QuIFRoZSBwYXlsb2FkIG9mIGVhY2ggc2lnbmVycyBlbGVtZW50IGlzIGRlZmluZWQgb25seSB0aGF0XG4gICAgLy8gc2lnbmVyIHdhcyBtYXRjaGVkIGJ5IHNvbWV0aGluZyBpbiBrZXkuXG4gICAgXG4gICAgaWYgKCF0aGlzLmlzTXVsdGlLZXkoa2V5KSkgcmV0dXJuIHN1cGVyLnZlcmlmeShrZXksIHNpZ25hdHVyZSwgb3B0aW9ucyk7XG4gICAgaWYgKCFzaWduYXR1cmUuc2lnbmF0dXJlcykgcmV0dXJuO1xuXG4gICAgLy8gQ29tcGFyaXNvbiB0byBwYW52YSBKT1NFLmdlbmVyYWxWZXJpZnkuXG4gICAgLy8gSk9TRSB0YWtlcyBhIGp3cyBhbmQgT05FIGtleSBhbmQgYW5zd2VycyB7cGF5bG9hZCwgcHJvdGVjdGVkSGVhZGVyLCB1bnByb3RlY3RlZEhlYWRlcn0gbWF0Y2hpbmcgdGhlIG9uZVxuICAgIC8vIGp3cy5zaWduYXR1cmUgZWxlbWVudCB0aGF0IHdhcyB2ZXJpZmllZCwgb3RoZXJpc2UgYW4gZXJvci4gKEl0IHRyaWVzIGVhY2ggb2YgdGhlIGVsZW1lbnRzIG9mIHRoZSBqd3Muc2lnbmF0dXJlcy4pXG4gICAgLy8gSXQgaXMgbm90IGdlbmVyYWxseSBwb3NzaWJsZSB0byBrbm93IFdISUNIIG9uZSBvZiB0aGUgandzLnNpZ25hdHVyZXMgd2FzIG1hdGNoZWQuXG4gICAgLy8gKEl0IE1BWSBiZSBwb3NzaWJsZSBpZiB0aGVyZSBhcmUgdW5pcXVlIGtpZCBlbGVtZW50cywgYnV0IHRoYXQncyBhcHBsaWNhdGlvbi1kZXBlbmRlbnQuKVxuICAgIC8vXG4gICAgLy8gTXVsdGlLcnlwdG8gdGFrZXMgYSBkaWN0aW9uYXJ5IHRoYXQgY29udGFpbnMgbmFtZWQga2V5cyBhbmQgcmVjb2duaXplZEhlYWRlciBwcm9wZXJ0aWVzLCBhbmQgaXQgcmV0dXJuc1xuICAgIC8vIGEgcmVzdWx0IHRoYXQgaGFzIGEgc2lnbmVycyBhcnJheSB0aGF0IGhhcyBhbiBlbGVtZW50IGNvcnJlc3BvbmRpbmcgdG8gZWFjaCBvcmlnaW5hbCBzaWduYXR1cmUgaWYgYW55XG4gICAgLy8gYXJlIG1hdGNoZWQgYnkgdGhlIG11bHRpa2V5LiAoSWYgbm9uZSBtYXRjaCwgd2UgcmV0dXJuIHVuZGVmaW5lZC5cbiAgICAvLyBFYWNoIGVsZW1lbnQgY29udGFpbnMgdGhlIGtpZCwgcHJvdGVjdGVkSGVhZGVyLCBwb3NzaWJseSB1bnByb3RlY3RlZEhlYWRlciwgYW5kIHBvc3NpYmx5IHBheWxvYWQgKGkuZS4gaWYgc3VjY2Vzc2Z1bCkuXG4gICAgLy9cbiAgICAvLyBBZGRpdGlvbmFsbHkgaWYgYSByZXN1bHQgaXMgcHJvZHVjZWQsIHRoZSBvdmVyYWxsIHByb3RlY3RlZEhlYWRlciBhbmQgdW5wcm90ZWN0ZWRIZWFkZXIgY29udGFpbnMgb25seSB2YWx1ZXNcbiAgICAvLyB0aGF0IHdlcmUgY29tbW9uIHRvIGVhY2ggb2YgdGhlIHZlcmlmaWVkIHNpZ25hdHVyZSBlbGVtZW50cy5cbiAgICBcbiAgICBsZXQgandzID0gc2lnbmF0dXJlLFxuICAgICAgICBraWRzID0gdGhpcy5rZXlUYWdzKGtleSksXG4gICAgICAgIHNpZ25lcnMgPSBhd2FpdCBQcm9taXNlLmFsbChqd3Muc2lnbmF0dXJlcy5tYXAoc2lnbmF0dXJlID0+IHRoaXMudmVyaWZ5U3ViU2lnbmF0dXJlKGp3cywgc2lnbmF0dXJlLCBrZXksIGtpZHMpKSk7XG4gICAgaWYgKCFzaWduZXJzLmZpbmQoc2lnbmVyID0+IHNpZ25lci5wYXlsb2FkKSkgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICAvLyBOb3cgY2Fub25pY2FsaXplIHRoZSBzaWduZXJzIGFuZCBidWlsZCB1cCBhIHJlc3VsdC5cbiAgICBsZXQgW2ZpcnN0LCAuLi5yZXN0XSA9IHNpZ25lcnMsXG4gICAgICAgIHJlc3VsdCA9IHtwcm90ZWN0ZWRIZWFkZXI6IHt9LCB1bnByb3RlY3RlZEhlYWRlcjoge30sIHNpZ25lcnN9LFxuICAgICAgICAvLyBGb3IgYSBoZWFkZXIgdmFsdWUgdG8gYmUgY29tbW9uIHRvIHZlcmlmaWVkIHJlc3VsdHMsIGl0IG11c3QgYmUgaW4gdGhlIGZpcnN0IHJlc3VsdC5cbiAgICAgICAgZ2V0VW5pcXVlID0gY2F0ZWdvcnlOYW1lID0+IHtcbiAgICAgICAgICBsZXQgZmlyc3RIZWFkZXIgPSBmaXJzdFtjYXRlZ29yeU5hbWVdLFxuICAgICAgICAgICAgICBhY2N1bXVsYXRvckhlYWRlciA9IHJlc3VsdFtjYXRlZ29yeU5hbWVdO1xuICAgICAgICAgIGZvciAobGV0IGxhYmVsIGluIGZpcnN0SGVhZGVyKSB7XG4gICAgICAgICAgICBsZXQgdmFsdWUgPSBmaXJzdEhlYWRlcltsYWJlbF07XG4gICAgICAgICAgICBpZiAocmVzdC5zb21lKHNpZ25lclJlc3VsdCA9PiBzaWduZXJSZXN1bHRbY2F0ZWdvcnlOYW1lXVtsYWJlbF0gIT09IHZhbHVlKSkgY29udGludWU7XG4gICAgICAgICAgICBhY2N1bXVsYXRvckhlYWRlcltsYWJlbF0gPSB2YWx1ZTtcbiAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgZ2V0VW5pcXVlKCdwcm90ZWN0ZWRIZWFkZXInKTtcbiAgICBnZXRVbmlxdWUoJ3Byb3RlY3RlZEhlYWRlcicpO1xuICAgIC8vIElmIGFueXRoaW5nIHZlcmlmaWVkLCB0aGVuIHNldCBwYXlsb2FkIGFuZCBhbGxvdyB0ZXh0L2pzb24gdG8gYmUgcHJvZHVjZWQuXG4gICAgLy8gQ2FsbGVycyBjYW4gY2hlY2sgc2lnbmVyc1tuXS5wYXlsb2FkIHRvIGRldGVybWluZSBpZiB0aGUgcmVzdWx0IGlzIHdoYXQgdGhleSB3YW50LlxuICAgIHJlc3VsdC5wYXlsb2FkID0gc2lnbmVycy5maW5kKHNpZ25lciA9PiBzaWduZXIucGF5bG9hZCkucGF5bG9hZDtcbiAgICByZXR1cm4gdGhpcy5yZWNvdmVyRGF0YUZyb21Db250ZW50VHlwZShyZXN1bHQsIG9wdGlvbnMpO1xuICB9XG59O1xuXG5PYmplY3Quc2V0UHJvdG90eXBlT2YoTXVsdGlLcnlwdG8sIEtyeXB0byk7IC8vIEluaGVyaXQgZnJvbSBLcnlwdG8gc28gdGhhdCBzdXBlci5tdW1ibGUoKSB3b3Jrcy5cbmV4cG9ydCBkZWZhdWx0IE11bHRpS3J5cHRvO1xuIiwiY2xhc3MgUGVyc2lzdGVkQ29sbGVjdGlvbiB7XG4gIC8vIEFzeW5jaHJvbm91cyBsb2NhbCBzdG9yYWdlLCBhdmFpbGFibGUgaW4gd2ViIHdvcmtlcnMuXG4gIGNvbnN0cnVjdG9yKHtjb2xsZWN0aW9uTmFtZSA9ICdjb2xsZWN0aW9uJywgZGJOYW1lID0gJ2FzeW5jTG9jYWxTdG9yYWdlJ30gPSB7fSkge1xuICAgIC8vIENhcHR1cmUgdGhlIGRhdGEgaGVyZSwgYnV0IGRvbid0IG9wZW4gdGhlIGRiIHVudGlsIHdlIG5lZWQgdG8uXG4gICAgdGhpcy5jb2xsZWN0aW9uTmFtZSA9IGNvbGxlY3Rpb25OYW1lO1xuICAgIHRoaXMuZGJOYW1lID0gZGJOYW1lO1xuICAgIHRoaXMudmVyc2lvbiA9IDE7XG4gIH1cbiAgZ2V0IGRiKCkgeyAvLyBBbnN3ZXIgYSBwcm9taXNlIGZvciB0aGUgZGF0YWJhc2UsIGNyZWF0aW5nIGl0IGlmIG5lZWRlZC5cbiAgICByZXR1cm4gdGhpcy5fZGIgPz89IG5ldyBQcm9taXNlKHJlc29sdmUgPT4ge1xuICAgICAgY29uc3QgcmVxdWVzdCA9IGluZGV4ZWREQi5vcGVuKHRoaXMuZGJOYW1lLCB0aGlzLnZlcnNpb24pO1xuICAgICAgLy8gY3JlYXRlT2JqZWN0U3RvcmUgY2FuIG9ubHkgYmUgY2FsbGVkIGZyb20gdXBncmFkZW5lZWRlZCwgd2hpY2ggaXMgb25seSBjYWxsZWQgZm9yIG5ldyB2ZXJzaW9ucy5cbiAgICAgIHJlcXVlc3Qub251cGdyYWRlbmVlZGVkID0gZXZlbnQgPT4gZXZlbnQudGFyZ2V0LnJlc3VsdC5jcmVhdGVPYmplY3RTdG9yZSh0aGlzLmNvbGxlY3Rpb25OYW1lKTtcbiAgICAgIHRoaXMucmVzdWx0KHJlc29sdmUsIHJlcXVlc3QpO1xuICAgIH0pO1xuICB9XG4gIHRyYW5zYWN0aW9uKG1vZGUgPSAncmVhZCcpIHsgLy8gQW5zd2VyIGEgcHJvbWlzZSBmb3IgdGhlIG5hbWVkIG9iamVjdCBzdG9yZSBvbiBhIG5ldyB0cmFuc2FjdGlvbi5cbiAgICBjb25zdCBjb2xsZWN0aW9uTmFtZSA9IHRoaXMuY29sbGVjdGlvbk5hbWU7XG4gICAgcmV0dXJuIHRoaXMuZGIudGhlbihkYiA9PiBkYi50cmFuc2FjdGlvbihjb2xsZWN0aW9uTmFtZSwgbW9kZSkub2JqZWN0U3RvcmUoY29sbGVjdGlvbk5hbWUpKTtcbiAgfVxuICByZXN1bHQocmVzb2x2ZSwgb3BlcmF0aW9uKSB7XG4gICAgb3BlcmF0aW9uLm9uc3VjY2VzcyA9IGV2ZW50ID0+IHJlc29sdmUoZXZlbnQudGFyZ2V0LnJlc3VsdCB8fCAnJyk7IC8vIE5vdCB1bmRlZmluZWQuXG4gIH1cbiAgcmV0cmlldmUodGFnKSB7IC8vIFByb21pc2UgdG8gcmV0cmlldmUgdGFnIGZyb20gY29sbGVjdGlvbk5hbWUuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKHJlc29sdmUgPT4ge1xuICAgICAgdGhpcy50cmFuc2FjdGlvbigncmVhZG9ubHknKS50aGVuKHN0b3JlID0+IHRoaXMucmVzdWx0KHJlc29sdmUsIHN0b3JlLmdldCh0YWcpKSk7XG4gICAgfSk7XG4gIH1cbiAgc3RvcmUodGFnLCBkYXRhKSB7IC8vIFByb21pc2UgdG8gc3RvcmUgZGF0YSBhdCB0YWcgaW4gY29sbGVjdGlvbk5hbWUuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKHJlc29sdmUgPT4ge1xuICAgICAgdGhpcy50cmFuc2FjdGlvbigncmVhZHdyaXRlJykudGhlbihzdG9yZSA9PiB0aGlzLnJlc3VsdChyZXNvbHZlLCBzdG9yZS5wdXQoZGF0YSwgdGFnKSkpO1xuICAgIH0pO1xuICB9XG4gIHJlbW92ZSh0YWcpIHsgLy8gUHJvbWlzZSB0byByZW1vdmUgdGFnIGZyb20gY29sbGVjdGlvbk5hbWUuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKHJlc29sdmUgPT4ge1xuICAgICAgdGhpcy50cmFuc2FjdGlvbigncmVhZHdyaXRlJykudGhlbihzdG9yZSA9PiB0aGlzLnJlc3VsdChyZXNvbHZlLCBzdG9yZS5kZWxldGUodGFnKSkpO1xuICAgIH0pO1xuICB9XG59XG5leHBvcnQgZGVmYXVsdCBQZXJzaXN0ZWRDb2xsZWN0aW9uO1xuIiwiaW1wb3J0IE11bHRpS3J5cHRvIGZyb20gJy4vbXVsdGlLcnlwdG8ubWpzJztcbmltcG9ydCBMb2NhbENvbGxlY3Rpb24gZnJvbSAnI2xvY2FsU3RvcmUnO1xuaW1wb3J0IHtnZXRVc2VyRGV2aWNlU2VjcmV0fSBmcm9tICcuL3NlY3JldC5tanMnO1xuaW1wb3J0IFN0b3JhZ2UgZnJvbSAnLi9zdG9yYWdlLm1qcyc7XG5cbmZ1bmN0aW9uIGVycm9yKHRlbXBsYXRlRnVuY3Rpb24sIHRhZywgY2F1c2UgPSB1bmRlZmluZWQpIHtcbiAgLy8gRm9ybWF0cyB0YWcgKGUuZy4sIHNob3J0ZW5zIGl0KSBhbmQgZ2l2ZXMgaXQgdG8gdGVtcGxhdGVGdW5jdGlvbih0YWcpIHRvIGdldFxuICAvLyBhIHN1aXRhYmxlIGVycm9yIG1lc3NhZ2UuIEFuc3dlcnMgYSByZWplY3RlZCBwcm9taXNlIHdpdGggdGhhdCBFcnJvci5cbiAgbGV0IHNob3J0ZW5lZFRhZyA9IHRhZy5zbGljZSgwLCAxNikgKyBcIi4uLlwiLFxuICAgICAgbWVzc2FnZSA9IHRlbXBsYXRlRnVuY3Rpb24oc2hvcnRlbmVkVGFnKTtcbiAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBFcnJvcihtZXNzYWdlLCB7Y2F1c2V9KSk7XG59XG5mdW5jdGlvbiB1bmF2YWlsYWJsZSh0YWcpIHsgLy8gRG8gd2Ugd2FudCB0byBkaXN0aW5ndWlzaCBiZXR3ZWVuIGEgdGFnIGJlaW5nXG4gIC8vIHVuYXZhaWxhYmxlIGF0IGFsbCwgdnMganVzdCB0aGUgcHVibGljIGVuY3J5cHRpb24ga2V5IGJlaW5nIHVuYXZhaWxhYmxlP1xuICAvLyBSaWdodCBub3cgd2UgZG8gbm90IGRpc3Rpbmd1aXNoLCBhbmQgdXNlIHRoaXMgZm9yIGJvdGguXG4gIHJldHVybiBlcnJvcih0YWcgPT4gYFRoZSB0YWcgJHt0YWd9IGlzIG5vdCBhdmFpbGFibGUuYCwgdGFnKTtcbn1cblxuZXhwb3J0IGNsYXNzIEtleVNldCB7XG4gIC8vIEEgS2V5U2V0IG1haW50YWlucyB0d28gcHJpdmF0ZSBrZXlzOiBzaWduaW5nS2V5IGFuZCBkZWNyeXB0aW5nS2V5LlxuICAvLyBTZWUgaHR0cHM6Ly9raWxyb3ktY29kZS5naXRodWIuaW8vZGlzdHJpYnV0ZWQtc2VjdXJpdHkvZG9jcy9pbXBsZW1lbnRhdGlvbi5odG1sI3dlYi13b3JrZXItYW5kLWlmcmFtZVxuXG4gIC8vIENhY2hpbmdcbiAgc3RhdGljIGtleVNldHMgPSB7fTtcbiAgc3RhdGljIGNhY2hlZCh0YWcpIHsgLy8gUmV0dXJuIGFuIGFscmVhZHkgcG9wdWxhdGVkIEtleVNldC5cbiAgICByZXR1cm4gdGhpcy5rZXlTZXRzW3RhZ107XG4gIH1cbiAgc3RhdGljIGNsZWFyKHRhZyA9IG51bGwpIHsgLy8gUmVtb3ZlIGFsbCBLZXlTZXQgaW5zdGFuY2VzIG9yIGp1c3QgdGhlIHNwZWNpZmllZCBvbmUsIGJ1dCBkb2VzIG5vdCBkZXN0cm95IHRoZWlyIHN0b3JhZ2UuXG4gICAgaWYgKCF0YWcpIHJldHVybiBLZXlTZXQua2V5U2V0cyA9IHt9O1xuICAgIGRlbGV0ZSBLZXlTZXQua2V5U2V0c1t0YWddXG4gIH1cbiAgY29uc3RydWN0b3IodGFnKSB7XG4gICAgdGhpcy50YWcgPSB0YWc7XG4gICAgdGhpcy5tZW1iZXJUYWdzID0gW107IC8vIFVzZWQgd2hlbiByZWN1cnNpdmVseSBkZXN0cm95aW5nLlxuICAgIEtleVNldC5rZXlTZXRzW3RhZ10gPSB0aGlzOyAvLyBDYWNoZSBpdC5cbiAgfVxuICAvLyBhcGkubWpzIHByb3ZpZGVzIHRoZSBzZXR0ZXIgdG8gY2hhbmdlcyB0aGVzZSwgYW5kIHdvcmtlci5tanMgZXhlcmNpc2VzIGl0IGluIGJyb3dzZXJzLlxuICBzdGF0aWMgZ2V0VXNlckRldmljZVNlY3JldCA9IGdldFVzZXJEZXZpY2VTZWNyZXQ7XG4gIHN0YXRpYyBTdG9yYWdlID0gU3RvcmFnZTtcblxuICAvLyBQcmluY2lwbGUgb3BlcmF0aW9ucy5cbiAgc3RhdGljIGFzeW5jIGNyZWF0ZSh3cmFwcGluZ0RhdGEpIHsgLy8gQ3JlYXRlIGEgcGVyc2lzdGVkIEtleVNldCBvZiB0aGUgY29ycmVjdCB0eXBlLCBwcm9taXNpbmcgdGhlIG5ld2x5IGNyZWF0ZWQgdGFnLlxuICAgIGxldCB7dGltZSwgLi4ua2V5c30gPSBhd2FpdCB0aGlzLmNyZWF0ZUtleXMod3JhcHBpbmdEYXRhKSxcbiAgICAgICAge3RhZ30gPSBrZXlzO1xuICAgIGF3YWl0IHRoaXMucGVyc2lzdCh0YWcsIGtleXMsIHdyYXBwaW5nRGF0YSwgdGltZSk7XG4gICAgcmV0dXJuIHRhZztcbiAgfVxuICBhc3luYyBkZXN0cm95KG9wdGlvbnMgPSB7fSkgeyAvLyBUZXJtaW5hdGVzIHRoaXMga2V5U2V0IGFuZCBhc3NvY2lhdGVkIHN0b3JhZ2UsIGFuZCBzYW1lIGZvciBPV05FRCByZWN1cnNpdmVNZW1iZXJzIGlmIGFza2VkLlxuICAgIGxldCB7dGFnLCBtZW1iZXJUYWdzLCBzaWduaW5nS2V5fSA9IHRoaXMsXG4gICAgICAgIGNvbnRlbnQgPSBcIlwiLCAvLyBTaG91bGQgc3RvcmFnZSBoYXZlIGEgc2VwYXJhdGUgb3BlcmF0aW9uIHRvIGRlbGV0ZSwgb3RoZXIgdGhhbiBzdG9yaW5nIGVtcHR5P1xuICAgICAgICBzaWduYXR1cmUgPSBhd2FpdCB0aGlzLmNvbnN0cnVjdG9yLnNpZ25Gb3JTdG9yYWdlKHsuLi5vcHRpb25zLCBtZXNzYWdlOiBjb250ZW50LCB0YWcsIG1lbWJlclRhZ3MsIHNpZ25pbmdLZXksIHRpbWU6IERhdGUubm93KCksIHJlY292ZXJ5OiB0cnVlfSk7XG4gICAgYXdhaXQgdGhpcy5jb25zdHJ1Y3Rvci5zdG9yZSgnRW5jcnlwdGlvbktleScsIHRhZywgc2lnbmF0dXJlKTtcbiAgICBhd2FpdCB0aGlzLmNvbnN0cnVjdG9yLnN0b3JlKHRoaXMuY29uc3RydWN0b3IuY29sbGVjdGlvbiwgdGFnLCBzaWduYXR1cmUpO1xuICAgIHRoaXMuY29uc3RydWN0b3IuY2xlYXIodGFnKTtcbiAgICBpZiAoIW9wdGlvbnMucmVjdXJzaXZlTWVtYmVycykgcmV0dXJuO1xuICAgIGF3YWl0IFByb21pc2UuYWxsU2V0dGxlZCh0aGlzLm1lbWJlclRhZ3MubWFwKGFzeW5jIG1lbWJlclRhZyA9PiB7XG4gICAgICBsZXQgbWVtYmVyS2V5U2V0ID0gYXdhaXQgS2V5U2V0LmVuc3VyZShtZW1iZXJUYWcsIHsuLi5vcHRpb25zLCByZWNvdmVyeTogdHJ1ZX0pO1xuICAgICAgYXdhaXQgbWVtYmVyS2V5U2V0LmRlc3Ryb3kob3B0aW9ucyk7XG4gICAgfSkpO1xuICB9XG4gIGRlY3J5cHQoZW5jcnlwdGVkLCBvcHRpb25zKSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259IGFzIGFwcHJvcHJpYXRlLlxuICAgIGxldCB7dGFnLCBkZWNyeXB0aW5nS2V5fSA9IHRoaXMsXG4gICAgICAgIGtleSA9IGVuY3J5cHRlZC5yZWNpcGllbnRzID8ge1t0YWddOiBkZWNyeXB0aW5nS2V5fSA6IGRlY3J5cHRpbmdLZXk7XG4gICAgcmV0dXJuIE11bHRpS3J5cHRvLmRlY3J5cHQoa2V5LCBlbmNyeXB0ZWQsIG9wdGlvbnMpO1xuICB9XG4gIC8vIHNpZ24gYXMgZWl0aGVyIGNvbXBhY3Qgb3IgbXVsdGlLZXkgZ2VuZXJhbCBKV1MuXG4gIC8vIFRoZXJlJ3Mgc29tZSBjb21wbGV4aXR5IGhlcmUgYXJvdW5kIGJlaW5nIGFibGUgdG8gcGFzcyBpbiBtZW1iZXJUYWdzIGFuZCBzaWduaW5nS2V5IHdoZW4gdGhlIGtleVNldCBpc1xuICAvLyBiZWluZyBjcmVhdGVkIGFuZCBkb2Vzbid0IHlldCBleGlzdC5cbiAgc3RhdGljIGFzeW5jIHNpZ24obWVzc2FnZSwge3RhZ3MgPSBbXSwgdGVhbTppc3MsIG1lbWJlcjphY3QsIHRpbWU6aWF0ID0gaXNzICYmIERhdGUubm93KCksXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtZW1iZXJUYWdzLCBzaWduaW5nS2V5LFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLi4ub3B0aW9uc30pIHtcbiAgICBpZiAoaXNzICYmICFhY3QpIHsgLy8gU3VwcGx5IHRoZSB2YWx1ZVxuICAgICAgaWYgKCFtZW1iZXJUYWdzKSBtZW1iZXJUYWdzID0gKGF3YWl0IEtleVNldC5lbnN1cmUoaXNzKSkubWVtYmVyVGFncztcbiAgICAgIGxldCBjYWNoZWRNZW1iZXIgPSBtZW1iZXJUYWdzLmZpbmQodGFnID0+IHRoaXMuY2FjaGVkKHRhZykpO1xuICAgICAgYWN0ID0gY2FjaGVkTWVtYmVyIHx8IGF3YWl0IHRoaXMuZW5zdXJlMShtZW1iZXJUYWdzKS50aGVuKGtleVNldCA9PiBrZXlTZXQudGFnKTtcbiAgICB9XG4gICAgaWYgKGlzcyAmJiAhdGFncy5pbmNsdWRlcyhpc3MpKSB0YWdzID0gW2lzcywgLi4udGFnc107IC8vIE11c3QgYmUgZmlyc3RcbiAgICBpZiAoYWN0ICYmICF0YWdzLmluY2x1ZGVzKGFjdCkpIHRhZ3MgPSBbLi4udGFncywgYWN0XTtcblxuICAgIGxldCBrZXkgPSBhd2FpdCB0aGlzLnByb2R1Y2VLZXkodGFncywgYXN5bmMgdGFnID0+IHtcbiAgICAgIC8vIFVzZSBzcGVjaWZpZWQgc2lnbmluZ0tleSAoaWYgYW55KSBmb3IgdGhlIGZpcnN0IG9uZS5cbiAgICAgIGxldCBrZXkgPSBzaWduaW5nS2V5IHx8IChhd2FpdCBLZXlTZXQuZW5zdXJlKHRhZywgb3B0aW9ucykpLnNpZ25pbmdLZXk7XG4gICAgICBzaWduaW5nS2V5ID0gbnVsbDtcbiAgICAgIHJldHVybiBrZXk7XG4gICAgfSwgb3B0aW9ucyk7XG4gICAgcmV0dXJuIE11bHRpS3J5cHRvLnNpZ24oa2V5LCBtZXNzYWdlLCB7aXNzLCBhY3QsIGlhdCwgLi4ub3B0aW9uc30pO1xuICB9XG5cbiAgLy8gVmVyaWZ5IGluIHRoZSBub3JtYWwgd2F5LCBhbmQgdGhlbiBjaGVjayBkZWVwbHkgaWYgYXNrZWQuXG4gIHN0YXRpYyBhc3luYyB2ZXJpZnkoc2lnbmF0dXJlLCB0YWdzLCBvcHRpb25zKSB7XG4gICAgbGV0IGlzQ29tcGFjdCA9ICFzaWduYXR1cmUuc2lnbmF0dXJlcyxcbiAgICAgICAga2V5ID0gYXdhaXQgdGhpcy5wcm9kdWNlS2V5KHRhZ3MsIHRhZyA9PiBLZXlTZXQudmVyaWZ5aW5nS2V5KHRhZyksIG9wdGlvbnMsIGlzQ29tcGFjdCksXG4gICAgICAgIHJlc3VsdCA9IGF3YWl0IE11bHRpS3J5cHRvLnZlcmlmeShrZXksIHNpZ25hdHVyZSwgb3B0aW9ucyksXG4gICAgICAgIG1lbWJlclRhZyA9IG9wdGlvbnMubWVtYmVyID09PSB1bmRlZmluZWQgPyByZXN1bHQ/LnByb3RlY3RlZEhlYWRlci5hY3QgOiBvcHRpb25zLm1lbWJlcixcbiAgICAgICAgbm90QmVmb3JlID0gb3B0aW9ucy5ub3RCZWZvcmU7XG4gICAgZnVuY3Rpb24gZXhpdChsYWJlbCkge1xuICAgICAgaWYgKG9wdGlvbnMuaGFyZEVycm9yKSByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IEVycm9yKGxhYmVsKSk7XG4gICAgfVxuICAgIGlmICghcmVzdWx0KSByZXR1cm4gZXhpdCgnSW5jb3JyZWN0IHNpZ25hdHVyZS4nKTtcbiAgICBpZiAobWVtYmVyVGFnKSB7XG4gICAgICBpZiAob3B0aW9ucy5tZW1iZXIgPT09ICd0ZWFtJykge1xuICAgICAgICBtZW1iZXJUYWcgPSByZXN1bHQucHJvdGVjdGVIZWFkZXIuYWN0O1xuICAgICAgICBpZiAoIW1lbWJlclRhZykgcmV0dXJuIGV4aXQoJ05vIG1lbWJlciBpZGVudGlmaWVkIGluIHNpZ25hdHVyZS4nKTtcbiAgICAgIH1cbiAgICAgIGlmICghdGFncy5pbmNsdWRlcyhtZW1iZXJUYWcpKSB7IC8vIEFkZCB0byB0YWdzIGFuZCByZXN1bHQgaWYgbm90IGFscmVhZHkgcHJlc2VudFxuICAgICAgICBsZXQgbWVtYmVyS2V5ID0gYXdhaXQgS2V5U2V0LnZlcmlmeWluZ0tleShtZW1iZXJUYWcpLFxuICAgICAgICAgICAgbWVtYmVyTXVsdGlrZXkgPSB7W21lbWJlclRhZ106IG1lbWJlcktleX0sXG4gICAgICAgICAgICBhdXggPSBhd2FpdCBNdWx0aUtyeXB0by52ZXJpZnkobWVtYmVyTXVsdGlrZXksIHNpZ25hdHVyZSwgb3B0aW9ucyk7XG4gICAgICAgIGlmICghYXV4KSByZXR1cm4gZXhpdCgnSW5jb3JyZWN0IG1lbWJlciBzaWduYXR1cmUuJyk7XG4gICAgICAgIHRhZ3MucHVzaChtZW1iZXJUYWcpO1xuICAgICAgICByZXN1bHQuc2lnbmVycy5maW5kKHNpZ25lciA9PiBzaWduZXIucHJvdGVjdGVkSGVhZGVyLmtpZCA9PT0gbWVtYmVyVGFnKS5wYXlsb2FkID0gcmVzdWx0LnBheWxvYWQ7XG4gICAgICB9XG4gICAgfVxuICAgIGlmIChtZW1iZXJUYWcgfHwgbm90QmVmb3JlID09PSAndGVhbScpIHtcbiAgICAgIGxldCB0ZWFtVGFnID0gcmVzdWx0LnByb3RlY3RlZEhlYWRlci5pc3MgfHwgcmVzdWx0LnByb3RlY3RlZEhlYWRlci5raWQsIC8vIE11bHRpIG9yIHNpbmdsZSBjYXNlLlxuICAgICAgICAgIHZlcmlmaWVkSldTID0gYXdhaXQgdGhpcy5yZXRyaWV2ZShUZWFtS2V5U2V0LmNvbGxlY3Rpb24sIHRlYW1UYWcpLFxuICAgICAgICAgIGp3ZSA9IHZlcmlmaWVkSldTPy5qc29uO1xuICAgICAgaWYgKG1lbWJlclRhZyAmJiAhdGVhbVRhZykgcmV0dXJuIGV4aXQoJ05vIHRlYW0gb3IgbWFpbiB0YWcgaWRlbnRpZmllZCBpbiBzaWduYXR1cmUnKTtcbiAgICAgIGlmIChtZW1iZXJUYWcgJiYgandlICYmICFqd2UucmVjaXBpZW50cy5maW5kKG1lbWJlciA9PiBtZW1iZXIuaGVhZGVyLmtpZCA9PT0gbWVtYmVyVGFnKSkgcmV0dXJuIGV4aXQoJ1NpZ25lciBpcyBub3QgYSBtZW1iZXIuJyk7XG4gICAgICBpZiAobm90QmVmb3JlID09PSAndGVhbScpIG5vdEJlZm9yZSA9IHZlcmlmaWVkSldTPy5wcm90ZWN0ZWRIZWFkZXIuaWF0XG4gICAgICAgIHx8IChhd2FpdCB0aGlzLnJldHJpZXZlKCdFbmNyeXB0aW9uS2V5JywgdGVhbVRhZykpPy5wcm90ZWN0ZWRIZWFkZXIuaWF0O1xuICAgIH1cbiAgICBpZiAobm90QmVmb3JlKSB7XG4gICAgICBsZXQge2lhdH0gPSByZXN1bHQucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgaWYgKGlhdCA8IG5vdEJlZm9yZSkgcmV0dXJuIGV4aXQoJ1NpZ25hdHVyZSBwcmVkYXRlcyByZXF1aXJlZCB0aW1lc3RhbXAuJyk7XG4gICAgfVxuICAgIC8vIEVhY2ggc2lnbmVyIHNob3VsZCBub3cgYmUgdmVyaWZpZWQuXG4gICAgaWYgKChyZXN1bHQuc2lnbmVycz8uZmlsdGVyKHNpZ25lciA9PiBzaWduZXIucGF5bG9hZCkubGVuZ3RoIHx8IDEpICE9PSB0YWdzLmxlbmd0aCkgcmV0dXJuIGV4aXQoJ1VudmVyaWZpZWQgc2lnbmVyJyk7XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfVxuXG4gIC8vIEtleSBtYW5hZ2VtZW50XG4gIHN0YXRpYyBhc3luYyBwcm9kdWNlS2V5KHRhZ3MsIHByb2R1Y2VyLCBvcHRpb25zLCB1c2VTaW5nbGVLZXkgPSB0YWdzLmxlbmd0aCA9PT0gMSkge1xuICAgIC8vIFByb21pc2UgYSBrZXkgb3IgbXVsdGlLZXksIGFzIGRlZmluZWQgYnkgcHJvZHVjZXIodGFnKSBmb3IgZWFjaCBrZXkuXG4gICAgaWYgKHVzZVNpbmdsZUtleSkge1xuICAgICAgbGV0IHRhZyA9IHRhZ3NbMF07XG4gICAgICBvcHRpb25zLmtpZCA9IHRhZzsgICAvLyBCYXNoZXMgb3B0aW9ucyBpbiB0aGUgc2luZ2xlLWtleSBjYXNlLCBiZWNhdXNlIG11bHRpS2V5J3MgaGF2ZSB0aGVpciBvd24uXG4gICAgICByZXR1cm4gcHJvZHVjZXIodGFnKTtcbiAgICB9XG4gICAgbGV0IGtleSA9IHt9LFxuICAgICAgICBrZXlzID0gYXdhaXQgUHJvbWlzZS5hbGwodGFncy5tYXAodGFnID0+IHByb2R1Y2VyKHRhZykpKTtcbiAgICAvLyBUaGlzIGlzbid0IGRvbmUgaW4gb25lIHN0ZXAsIGJlY2F1c2Ugd2UnZCBsaWtlIChmb3IgZGVidWdnaW5nIGFuZCB1bml0IHRlc3RzKSB0byBtYWludGFpbiBhIHByZWRpY3RhYmxlIG9yZGVyLlxuICAgIHRhZ3MuZm9yRWFjaCgodGFnLCBpbmRleCkgPT4ga2V5W3RhZ10gPSBrZXlzW2luZGV4XSk7XG4gICAgcmV0dXJuIGtleTtcbiAgfVxuICAvLyBUaGUgY29ycmVzcG9uZGluZyBwdWJsaWMga2V5cyBhcmUgYXZhaWxhYmxlIHB1YmxpY2FsbHksIG91dHNpZGUgdGhlIGtleVNldC5cbiAgc3RhdGljIHZlcmlmeWluZ0tleSh0YWcpIHsgLy8gUHJvbWlzZSB0aGUgb3JkaW5hcnkgc2luZ3VsYXIgcHVibGljIGtleSBjb3JyZXNwb25kaW5nIHRvIHRoZSBzaWduaW5nIGtleSwgZGlyZWN0bHkgZnJvbSB0aGUgdGFnIHdpdGhvdXQgcmVmZXJlbmNlIHRvIHN0b3JhZ2UuXG4gICAgcmV0dXJuIE11bHRpS3J5cHRvLmltcG9ydFJhdyh0YWcpLmNhdGNoKCgpID0+IHVuYXZhaWxhYmxlKHRhZykpO1xuICB9XG4gIHN0YXRpYyBhc3luYyBlbmNyeXB0aW5nS2V5KHRhZykgeyAvLyBQcm9taXNlIHRoZSBvcmRpbmFyeSBzaW5ndWxhciBwdWJsaWMga2V5IGNvcnJlc3BvbmRpbmcgdG8gdGhlIGRlY3J5cHRpb24ga2V5LCB3aGljaCBkZXBlbmRzIG9uIHB1YmxpYyBzdG9yYWdlLlxuICAgIGxldCBleHBvcnRlZFB1YmxpY0tleSA9IGF3YWl0IHRoaXMucmV0cmlldmUoJ0VuY3J5cHRpb25LZXknLCB0YWcpO1xuICAgIGlmICghZXhwb3J0ZWRQdWJsaWNLZXkpIHJldHVybiB1bmF2YWlsYWJsZSh0YWcpO1xuICAgIHJldHVybiBhd2FpdCBNdWx0aUtyeXB0by5pbXBvcnRKV0soZXhwb3J0ZWRQdWJsaWNLZXkuanNvbik7XG4gIH1cbiAgc3RhdGljIGFzeW5jIGNyZWF0ZUtleXMobWVtYmVyVGFncykgeyAvLyBQcm9taXNlIGEgbmV3IHRhZyBhbmQgcHJpdmF0ZSBrZXlzLCBhbmQgc3RvcmUgdGhlIGVuY3J5cHRpbmcga2V5LlxuICAgIGxldCB7cHVibGljS2V5OnZlcmlmeWluZ0tleSwgcHJpdmF0ZUtleTpzaWduaW5nS2V5fSA9IGF3YWl0IE11bHRpS3J5cHRvLmdlbmVyYXRlU2lnbmluZ0tleSgpLFxuICAgICAgICB7cHVibGljS2V5OmVuY3J5cHRpbmdLZXksIHByaXZhdGVLZXk6ZGVjcnlwdGluZ0tleX0gPSBhd2FpdCBNdWx0aUtyeXB0by5nZW5lcmF0ZUVuY3J5cHRpbmdLZXkoKSxcbiAgICAgICAgdGFnID0gYXdhaXQgTXVsdGlLcnlwdG8uZXhwb3J0UmF3KHZlcmlmeWluZ0tleSksXG4gICAgICAgIGV4cG9ydGVkRW5jcnlwdGluZ0tleSA9IGF3YWl0IE11bHRpS3J5cHRvLmV4cG9ydEpXSyhlbmNyeXB0aW5nS2V5KSxcbiAgICAgICAgdGltZSA9IERhdGUubm93KCksXG4gICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IHRoaXMuc2lnbkZvclN0b3JhZ2Uoe21lc3NhZ2U6IGV4cG9ydGVkRW5jcnlwdGluZ0tleSwgdGFnLCBzaWduaW5nS2V5LCBtZW1iZXJUYWdzLCB0aW1lLCByZWNvdmVyeTogdHJ1ZX0pO1xuICAgIGF3YWl0IHRoaXMuc3RvcmUoJ0VuY3J5cHRpb25LZXknLCB0YWcsIHNpZ25hdHVyZSk7XG4gICAgcmV0dXJuIHtzaWduaW5nS2V5LCBkZWNyeXB0aW5nS2V5LCB0YWcsIHRpbWV9O1xuICB9XG4gIHN0YXRpYyBnZXRXcmFwcGVkKHRhZykgeyAvLyBQcm9taXNlIHRoZSB3cmFwcGVkIGtleSBhcHByb3ByaWF0ZSBmb3IgdGhpcyBjbGFzcy5cbiAgICByZXR1cm4gdGhpcy5yZXRyaWV2ZSh0aGlzLmNvbGxlY3Rpb24sIHRhZyk7XG4gIH1cbiAgc3RhdGljIGFzeW5jIGVuc3VyZSh0YWcsIHtkZXZpY2UgPSB0cnVlLCB0ZWFtID0gdHJ1ZSwgcmVjb3ZlcnkgPSBmYWxzZX0gPSB7fSkgeyAvLyBQcm9taXNlIHRvIHJlc29sdmUgdG8gYSB2YWxpZCBrZXlTZXQsIGVsc2UgcmVqZWN0LlxuICAgIGxldCBrZXlTZXQgPSB0aGlzLmNhY2hlZCh0YWcpLFxuICAgICAgICBzdG9yZWQgPSBkZXZpY2UgJiYgYXdhaXQgRGV2aWNlS2V5U2V0LmdldFdyYXBwZWQodGFnKTtcbiAgICBpZiAoc3RvcmVkKSB7XG4gICAgICBrZXlTZXQgPSBuZXcgRGV2aWNlS2V5U2V0KHRhZyk7XG4gICAgfSBlbHNlIGlmICh0ZWFtICYmIChzdG9yZWQgPSBhd2FpdCBUZWFtS2V5U2V0LmdldFdyYXBwZWQodGFnKSkpIHtcbiAgICAgIGtleVNldCA9IG5ldyBUZWFtS2V5U2V0KHRhZyk7XG4gICAgfSBlbHNlIGlmIChyZWNvdmVyeSAmJiAoc3RvcmVkID0gYXdhaXQgUmVjb3ZlcnlLZXlTZXQuZ2V0V3JhcHBlZCh0YWcpKSkgeyAvLyBMYXN0LCBpZiBhdCBhbGwuXG4gICAgICBrZXlTZXQgPSBuZXcgUmVjb3ZlcnlLZXlTZXQodGFnKTtcbiAgICB9XG4gICAgLy8gSWYgdGhpbmdzIGhhdmVuJ3QgY2hhbmdlZCwgZG9uJ3QgYm90aGVyIHdpdGggc2V0VW53cmFwcGVkLlxuICAgIGlmIChrZXlTZXQ/LmNhY2hlZCAmJiBrZXlTZXQuY2FjaGVkID09PSBzdG9yZWQgJiYga2V5U2V0LmRlY3J5cHRpbmdLZXkgJiYga2V5U2V0LnNpZ25pbmdLZXkpIHJldHVybiBrZXlTZXQ7XG4gICAgaWYgKHN0b3JlZCkga2V5U2V0LmNhY2hlZCA9IHN0b3JlZDtcbiAgICBlbHNlIHsgLy8gTm90IGZvdW5kLiBDb3VsZCBiZSBhIGJvZ3VzIHRhZywgb3Igb25lIG9uIGFub3RoZXIgY29tcHV0ZXIuXG4gICAgICB0aGlzLmNsZWFyKHRhZyk7XG4gICAgICByZXR1cm4gdW5hdmFpbGFibGUodGFnKTtcbiAgICB9XG4gICAgcmV0dXJuIGtleVNldC51bndyYXAoa2V5U2V0LmNhY2hlZCkudGhlbihcbiAgICAgIHVud3JhcHBlZCA9PiBPYmplY3QuYXNzaWduKGtleVNldCwgdW53cmFwcGVkKSxcbiAgICAgIGNhdXNlID0+IHtcbiAgICAgICAgdGhpcy5jbGVhcihrZXlTZXQudGFnKVxuICAgICAgICByZXR1cm4gZXJyb3IodGFnID0+IGBZb3UgZG8gbm90IGhhdmUgYWNjZXNzIHRvIHRoZSBwcml2YXRlIGtleSBmb3IgJHt0YWd9LmAsIGtleVNldC50YWcsIGNhdXNlKTtcbiAgICAgIH0pO1xuICB9XG4gIHN0YXRpYyBlbnN1cmUxKHRhZ3MpIHsgLy8gRmluZCBvbmUgdmFsaWQga2V5U2V0IGFtb25nIHRhZ3MsIHVzaW5nIHJlY292ZXJ5IHRhZ3Mgb25seSBpZiBuZWNlc3NhcnkuXG4gICAgcmV0dXJuIFByb21pc2UuYW55KHRhZ3MubWFwKHRhZyA9PiBLZXlTZXQuZW5zdXJlKHRhZykpKVxuICAgICAgLmNhdGNoKGFzeW5jIHJlYXNvbiA9PiB7IC8vIElmIHdlIGZhaWxlZCwgdHJ5IHRoZSByZWNvdmVyeSB0YWdzLCBpZiBhbnksIG9uZSBhdCBhIHRpbWUuXG4gICAgICAgIGZvciAobGV0IGNhbmRpZGF0ZSBvZiB0YWdzKSB7XG4gICAgICAgICAgbGV0IGtleVNldCA9IGF3YWl0IEtleVNldC5lbnN1cmUoY2FuZGlkYXRlLCB7ZGV2aWNlOiBmYWxzZSwgdGVhbTogZmFsc2UsIHJlY292ZXJ5OiB0cnVlfSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgaWYgKGtleVNldCkgcmV0dXJuIGtleVNldDtcbiAgICAgICAgfVxuICAgICAgICB0aHJvdyByZWFzb247XG4gICAgICB9KTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgcGVyc2lzdCh0YWcsIGtleXMsIHdyYXBwaW5nRGF0YSwgdGltZSA9IERhdGUubm93KCksIG1lbWJlclRhZ3MgPSB3cmFwcGluZ0RhdGEpIHsgLy8gUHJvbWlzZSB0byB3cmFwIGEgc2V0IG9mIGtleXMgZm9yIHRoZSB3cmFwcGluZ0RhdGEgbWVtYmVycywgYW5kIHBlcnNpc3QgYnkgdGFnLlxuICAgIGxldCB7c2lnbmluZ0tleX0gPSBrZXlzLFxuICAgICAgICB3cmFwcGVkID0gYXdhaXQgdGhpcy53cmFwKGtleXMsIHdyYXBwaW5nRGF0YSksXG4gICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IHRoaXMuc2lnbkZvclN0b3JhZ2Uoe21lc3NhZ2U6IHdyYXBwZWQsIHRhZywgc2lnbmluZ0tleSwgbWVtYmVyVGFncywgdGltZSwgcmVjb3Zlcnk6IHRydWV9KTtcbiAgICBhd2FpdCB0aGlzLnN0b3JlKHRoaXMuY29sbGVjdGlvbiwgdGFnLCBzaWduYXR1cmUpO1xuICB9XG5cbiAgLy8gSW50ZXJhY3Rpb25zIHdpdGggdGhlIGNsb3VkIG9yIGxvY2FsIHN0b3JhZ2UuXG4gIHN0YXRpYyBhc3luYyBzdG9yZShjb2xsZWN0aW9uTmFtZSwgdGFnLCBzaWduYXR1cmUpIHsgLy8gU3RvcmUgc2lnbmF0dXJlLlxuICAgIGlmIChjb2xsZWN0aW9uTmFtZSA9PT0gRGV2aWNlS2V5U2V0LmNvbGxlY3Rpb24pIHtcbiAgICAgIC8vIFdlIGNhbGxlZCB0aGlzLiBObyBuZWVkIHRvIHZlcmlmeSBoZXJlLiBCdXQgc2VlIHJldHJpZXZlKCkuXG4gICAgICBpZiAoTXVsdGlLcnlwdG8uaXNFbXB0eUpXU1BheWxvYWQoc2lnbmF0dXJlKSkgcmV0dXJuIExvY2FsU3RvcmUucmVtb3ZlKHRhZyk7XG4gICAgICByZXR1cm4gTG9jYWxTdG9yZS5zdG9yZSh0YWcsIHNpZ25hdHVyZSk7XG4gICAgfVxuICAgIHJldHVybiBLZXlTZXQuU3RvcmFnZS5zdG9yZShjb2xsZWN0aW9uTmFtZSwgdGFnLCBzaWduYXR1cmUpO1xuICB9XG4gIHN0YXRpYyBhc3luYyByZXRyaWV2ZShjb2xsZWN0aW9uTmFtZSwgdGFnKSB7ICAvLyBHZXQgYmFjayBhIHZlcmlmaWVkIHJlc3VsdC5cbiAgICBsZXQgcHJvbWlzZSA9IChjb2xsZWN0aW9uTmFtZSA9PT0gRGV2aWNlS2V5U2V0LmNvbGxlY3Rpb24pID8gTG9jYWxTdG9yZS5yZXRyaWV2ZSh0YWcpIDogS2V5U2V0LlN0b3JhZ2UucmV0cmlldmUoY29sbGVjdGlvbk5hbWUsIHRhZyksXG4gICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IHByb21pc2UsXG4gICAgICAgIGtleSA9IHNpZ25hdHVyZSAmJiBhd2FpdCBLZXlTZXQudmVyaWZ5aW5nS2V5KHRhZyk7XG4gICAgaWYgKCFzaWduYXR1cmUpIHJldHVybjtcbiAgICAvLyBXaGlsZSB3ZSByZWx5IG9uIHRoZSBTdG9yYWdlIGFuZCBMb2NhbFN0b3JlIGltcGxlbWVudGF0aW9ucyB0byBkZWVwbHkgY2hlY2sgc2lnbmF0dXJlcyBkdXJpbmcgd3JpdGUsXG4gICAgLy8gaGVyZSB3ZSBzdGlsbCBkbyBhIHNoYWxsb3cgdmVyaWZpY2F0aW9uIGNoZWNrIGp1c3QgdG8gbWFrZSBzdXJlIHRoYXQgdGhlIGRhdGEgaGFzbid0IGJlZW4gbWVzc2VkIHdpdGggYWZ0ZXIgd3JpdGUuXG4gICAgaWYgKHNpZ25hdHVyZS5zaWduYXR1cmVzKSBrZXkgPSB7W3RhZ106IGtleX07IC8vIFByZXBhcmUgYSBtdWx0aS1rZXlcbiAgICByZXR1cm4gYXdhaXQgTXVsdGlLcnlwdG8udmVyaWZ5KGtleSwgc2lnbmF0dXJlKTtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgU2VjcmV0S2V5U2V0IGV4dGVuZHMgS2V5U2V0IHsgLy8gS2V5cyBhcmUgZW5jcnlwdGVkIGJhc2VkIG9uIGEgc3ltbWV0cmljIHNlY3JldC5cbiAgc3RhdGljIHNpZ25Gb3JTdG9yYWdlKHttZXNzYWdlLCB0YWcsIHNpZ25pbmdLZXksIHRpbWV9KSB7XG4gICAgLy8gQ3JlYXRlIGEgc2ltcGxlIHNpZ25hdHVyZSB0aGF0IGRvZXMgbm90IHNwZWNpZnkgaXNzIG9yIGFjdC5cbiAgICAvLyBUaGVyZSBhcmUgbm8gdHJ1ZSBtZW1iZXJUYWdzIHRvIHBhc3Mgb24gYW5kIHRoZXkgYXJlIG5vdCB1c2VkIGluIHNpbXBsZSBzaWduYXR1cmVzLiBIb3dldmVyLCB0aGUgY2FsbGVyIGRvZXNcbiAgICAvLyBnZW5lcmljYWxseSBwYXNzIHdyYXBwaW5nRGF0YSBhcyBtZW1iZXJUYWdzLCBhbmQgZm9yIFJlY292ZXJ5S2V5U2V0cywgd3JhcHBpbmdEYXRhIGlzIHRoZSBwcm9tcHQuIFxuICAgIC8vIFdlIGRvbid0IHN0b3JlIG11bHRpcGxlIHRpbWVzLCBzbyB0aGVyZSdzIGFsc28gbm8gbmVlZCBmb3IgaWF0ICh3aGljaCBjYW4gYmUgdXNlZCB0byBwcmV2ZW50IHJlcGxheSBhdHRhY2tzKS5cbiAgICByZXR1cm4gdGhpcy5zaWduKG1lc3NhZ2UsIHt0YWdzOiBbdGFnXSwgc2lnbmluZ0tleSwgdGltZX0pO1xuICB9XG4gIHN0YXRpYyBhc3luYyB3cmFwcGluZ0tleSh0YWcsIHByb21wdCkgeyAvLyBUaGUga2V5IHVzZWQgdG8gKHVuKXdyYXAgdGhlIHZhdWx0IG11bHRpLWtleS5cbiAgICBsZXQgc2VjcmV0ID0gIGF3YWl0IHRoaXMuZ2V0U2VjcmV0KHRhZywgcHJvbXB0KTtcbiAgICAvLyBBbHRlcm5hdGl2ZWx5LCBvbmUgY291bGQgdXNlIHtbd3JhcHBpbmdEYXRhXTogc2VjcmV0fSwgYnV0IHRoYXQncyBhIGJpdCB0b28gY3V0ZSwgYW5kIGdlbmVyYXRlcyBhIGdlbmVyYWwgZm9ybSBlbmNyeXB0aW9uLlxuICAgIC8vIFRoaXMgdmVyc2lvbiBnZW5lcmF0ZXMgYSBjb21wYWN0IGZvcm0gZW5jcnlwdGlvbi5cbiAgICByZXR1cm4gTXVsdGlLcnlwdG8uZ2VuZXJhdGVTZWNyZXRLZXkoc2VjcmV0KTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgd3JhcChrZXlzLCBwcm9tcHQgPSAnJykgeyAvLyBFbmNyeXB0IGtleXNldCBieSBnZXRVc2VyRGV2aWNlU2VjcmV0LlxuICAgIGxldCB7ZGVjcnlwdGluZ0tleSwgc2lnbmluZ0tleSwgdGFnfSA9IGtleXMsXG4gICAgICAgIHZhdWx0S2V5ID0ge2RlY3J5cHRpbmdLZXksIHNpZ25pbmdLZXl9LFxuICAgICAgICB3cmFwcGluZ0tleSA9IGF3YWl0IHRoaXMud3JhcHBpbmdLZXkodGFnLCBwcm9tcHQpO1xuICAgIHJldHVybiBNdWx0aUtyeXB0by53cmFwS2V5KHZhdWx0S2V5LCB3cmFwcGluZ0tleSwge3Byb21wdH0pOyAvLyBPcmRlciBpcyBiYWNrd2FyZHMgZnJvbSBlbmNyeXB0LlxuICB9XG4gIGFzeW5jIHVud3JhcCh3cmFwcGVkS2V5KSB7IC8vIERlY3J5cHQga2V5c2V0IGJ5IGdldFVzZXJEZXZpY2VTZWNyZXQuXG4gICAgbGV0IHBhcnNlZCA9IHdyYXBwZWRLZXkuanNvbiB8fCB3cmFwcGVkS2V5LnRleHQsIC8vIEhhbmRsZSBib3RoIGpzb24gYW5kIGNvcGFjdCBmb3JtcyBvZiB3cmFwcGVkS2V5LlxuXG4gICAgICAgIC8vIFRoZSBjYWxsIHRvIHdyYXBLZXksIGFib3ZlLCBleHBsaWNpdGx5IGRlZmluZXMgdGhlIHByb21wdCBpbiB0aGUgaGVhZGVyIG9mIHRoZSBlbmNyeXB0aW9uLlxuICAgICAgICBwcm90ZWN0ZWRIZWFkZXIgPSBNdWx0aUtyeXB0by5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIocGFyc2VkKSxcbiAgICAgICAgcHJvbXB0ID0gcHJvdGVjdGVkSGVhZGVyLnByb21wdCwgLy8gSW4gdGhlIFwiY3V0ZVwiIGZvcm0gb2Ygd3JhcHBpbmdLZXksIHByb21wdCBjYW4gYmUgcHVsbGVkIGZyb20gcGFyc2VkLnJlY2lwaWVudHNbMF0uaGVhZGVyLmtpZCxcblxuICAgICAgICB3cmFwcGluZ0tleSA9IGF3YWl0IHRoaXMuY29uc3RydWN0b3Iud3JhcHBpbmdLZXkodGhpcy50YWcsIHByb21wdCksXG4gICAgICAgIGV4cG9ydGVkID0gKGF3YWl0IE11bHRpS3J5cHRvLmRlY3J5cHQod3JhcHBpbmdLZXksIHBhcnNlZCkpLmpzb247XG4gICAgcmV0dXJuIGF3YWl0IE11bHRpS3J5cHRvLmltcG9ydEpXSyhleHBvcnRlZCwge2RlY3J5cHRpbmdLZXk6ICdkZWNyeXB0Jywgc2lnbmluZ0tleTogJ3NpZ24nfSk7XG4gIH1cbiAgc3RhdGljIGFzeW5jIGdldFNlY3JldCh0YWcsIHByb21wdCkgeyAvLyBnZXRVc2VyRGV2aWNlU2VjcmV0IGZyb20gYXBwLlxuICAgIHJldHVybiBLZXlTZXQuZ2V0VXNlckRldmljZVNlY3JldCh0YWcsIHByb21wdCk7XG4gIH1cbn1cblxuIC8vIFRoZSB1c2VyJ3MgYW5zd2VyKHMpIHRvIGEgc2VjdXJpdHkgcXVlc3Rpb24gZm9ybXMgYSBzZWNyZXQsIGFuZCB0aGUgd3JhcHBlZCBrZXlzIGlzIHN0b3JlZCBpbiB0aGUgY2xvdWRlLlxuZXhwb3J0IGNsYXNzIFJlY292ZXJ5S2V5U2V0IGV4dGVuZHMgU2VjcmV0S2V5U2V0IHtcbiAgc3RhdGljIGNvbGxlY3Rpb24gPSAnS2V5UmVjb3ZlcnknO1xufVxuXG4vLyBBIEtleVNldCBjb3JyZXNwb25kaW5nIHRvIHRoZSBjdXJyZW50IGhhcmR3YXJlLiBXcmFwcGluZyBzZWNyZXQgY29tZXMgZnJvbSB0aGUgYXBwLlxuZXhwb3J0IGNsYXNzIERldmljZUtleVNldCBleHRlbmRzIFNlY3JldEtleVNldCB7XG4gIHN0YXRpYyBjb2xsZWN0aW9uID0gJ0RldmljZSc7XG59XG5jb25zdCBMb2NhbFN0b3JlID0gbmV3IExvY2FsQ29sbGVjdGlvbih7Y29sbGVjdGlvbk5hbWU6IERldmljZUtleVNldC5jb2xsZWN0aW9ufSk7XG5cbmV4cG9ydCBjbGFzcyBUZWFtS2V5U2V0IGV4dGVuZHMgS2V5U2V0IHsgLy8gQSBLZXlTZXQgY29ycmVzcG9uZGluZyB0byBhIHRlYW0gb2Ygd2hpY2ggdGhlIGN1cnJlbnQgdXNlciBpcyBhIG1lbWJlciAoaWYgZ2V0VGFnKCkpLlxuICBzdGF0aWMgY29sbGVjdGlvbiA9ICdUZWFtJztcbiAgc3RhdGljIHNpZ25Gb3JTdG9yYWdlKHttZXNzYWdlLCB0YWcsIC4uLm9wdGlvbnN9KSB7XG4gICAgcmV0dXJuIHRoaXMuc2lnbihtZXNzYWdlLCB7dGVhbTogdGFnLCAuLi5vcHRpb25zfSk7XG4gIH1cbiAgc3RhdGljIGFzeW5jIHdyYXAoa2V5cywgbWVtYmVycykge1xuICAgIC8vIFRoaXMgaXMgdXNlZCBieSBwZXJzaXN0LCB3aGljaCBpbiB0dXJuIGlzIHVzZWQgdG8gY3JlYXRlIGFuZCBjaGFuZ2VNZW1iZXJzaGlwLlxuICAgIGxldCB7ZGVjcnlwdGluZ0tleSwgc2lnbmluZ0tleX0gPSBrZXlzLFxuICAgICAgICB0ZWFtS2V5ID0ge2RlY3J5cHRpbmdLZXksIHNpZ25pbmdLZXl9LFxuICAgICAgICB3cmFwcGluZ0tleSA9IHt9O1xuICAgIGF3YWl0IFByb21pc2UuYWxsKG1lbWJlcnMubWFwKG1lbWJlclRhZyA9PiBLZXlTZXQuZW5jcnlwdGluZ0tleShtZW1iZXJUYWcpLnRoZW4oa2V5ID0+IHdyYXBwaW5nS2V5W21lbWJlclRhZ10gPSBrZXkpKSk7XG4gICAgbGV0IHdyYXBwZWRUZWFtID0gYXdhaXQgTXVsdGlLcnlwdG8ud3JhcEtleSh0ZWFtS2V5LCB3cmFwcGluZ0tleSk7XG4gICAgcmV0dXJuIHdyYXBwZWRUZWFtO1xuICB9XG4gIGFzeW5jIHVud3JhcCh3cmFwcGVkKSB7XG4gICAgbGV0IHtyZWNpcGllbnRzfSA9IHdyYXBwZWQuanNvbixcbiAgICAgICAgbWVtYmVyVGFncyA9IHRoaXMubWVtYmVyVGFncyA9IHJlY2lwaWVudHMubWFwKHJlY2lwaWVudCA9PiByZWNpcGllbnQuaGVhZGVyLmtpZCk7XG4gICAgbGV0IGtleVNldCA9IGF3YWl0IHRoaXMuY29uc3RydWN0b3IuZW5zdXJlMShtZW1iZXJUYWdzKTsgLy8gV2Ugd2lsbCB1c2UgcmVjb3ZlcnkgdGFncyBvbmx5IGlmIHdlIG5lZWQgdG8uXG4gICAgbGV0IGRlY3J5cHRlZCA9IGF3YWl0IGtleVNldC5kZWNyeXB0KHdyYXBwZWQuanNvbik7XG4gICAgcmV0dXJuIGF3YWl0IE11bHRpS3J5cHRvLmltcG9ydEpXSyhkZWNyeXB0ZWQuanNvbik7XG4gIH1cbiAgYXN5bmMgY2hhbmdlTWVtYmVyc2hpcCh7YWRkID0gW10sIHJlbW92ZSA9IFtdfSA9IHt9KSB7XG4gICAgbGV0IHttZW1iZXJUYWdzfSA9IHRoaXMsXG4gICAgICAgIG5ld01lbWJlcnMgPSBtZW1iZXJUYWdzLmNvbmNhdChhZGQpLmZpbHRlcih0YWcgPT4gIXJlbW92ZS5pbmNsdWRlcyh0YWcpKTtcbiAgICBhd2FpdCB0aGlzLmNvbnN0cnVjdG9yLnBlcnNpc3QodGhpcy50YWcsIHRoaXMsIG5ld01lbWJlcnMsIERhdGUubm93KCksIG1lbWJlclRhZ3MpO1xuICAgIHRoaXMubWVtYmVyVGFncyA9IG5ld01lbWJlcnM7XG4gIH1cbn1cbiIsIi8vIEJlY2F1c2UgZXNsaW50IGRvZXNuJ3QgcmVjb2duaXplIGltcG9ydCBhc3NlcnRpb25zXG5pbXBvcnQgKiBhcyBwa2cgZnJvbSBcIi4uL3BhY2thZ2UuanNvblwiIHdpdGggeyB0eXBlOiAnanNvbicgfTtcbmV4cG9ydCBjb25zdCB7bmFtZSwgdmVyc2lvbn0gPSBwa2cuZGVmYXVsdDtcbiIsImltcG9ydCBNdWx0aUtyeXB0byBmcm9tIFwiLi9tdWx0aUtyeXB0by5tanNcIjtcbmltcG9ydCB7S2V5U2V0LCBEZXZpY2VLZXlTZXQsIFJlY292ZXJ5S2V5U2V0LCBUZWFtS2V5U2V0fSBmcm9tIFwiLi9rZXlTZXQubWpzXCI7XG5pbXBvcnQge25hbWUsIHZlcnNpb259IGZyb20gXCIuL3BhY2thZ2UtbG9hZGVyLm1qc1wiO1xuXG5jb25zdCBTZWN1cml0eSA9IHsgLy8gVGhpcyBpcyB0aGUgYXBpIGZvciB0aGUgdmF1bHQuIFNlZSBodHRwczovL2tpbHJveS1jb2RlLmdpdGh1Yi5pby9kaXN0cmlidXRlZC1zZWN1cml0eS9kb2NzL2ltcGxlbWVudGF0aW9uLmh0bWwjY3JlYXRpbmctdGhlLXZhdWx0LXdlYi13b3JrZXItYW5kLWlmcmFtZVxuXG4gIC8vIENsaWVudC1kZWZpbmVkIHJlc291cmNlcy5cbiAgc2V0IFN0b3JhZ2Uoc3RvcmFnZSkgeyAvLyBBbGxvd3MgYSBub2RlIGFwcCAobm8gdmF1bHR0KSB0byBvdmVycmlkZSB0aGUgZGVmYXVsdCBzdG9yYWdlLlxuICAgIEtleVNldC5TdG9yYWdlID0gc3RvcmFnZTtcbiAgfSxcbiAgZ2V0IFN0b3JhZ2UoKSB7IC8vIEFsbG93cyBhIG5vZGUgYXBwIChubyB2YXVsdCkgdG8gZXhhbWluZSBzdG9yYWdlLlxuICAgIHJldHVybiBLZXlTZXQuU3RvcmFnZTtcbiAgfSxcbiAgc2V0IGdldFVzZXJEZXZpY2VTZWNyZXQoZnVuY3Rpb25PZlRhZ0FuZFByb21wdCkgeyAgLy8gQWxsb3dzIGEgbm9kZSBhcHAgKG5vIHZhdWx0KSB0byBvdmVycmlkZSB0aGUgZGVmYXVsdC5cbiAgICBLZXlTZXQuZ2V0VXNlckRldmljZVNlY3JldCA9IGZ1bmN0aW9uT2ZUYWdBbmRQcm9tcHQ7XG4gIH0sXG4gIGdldCBnZXRVc2VyRGV2aWNlU2VjcmV0KCkge1xuICAgIHJldHVybiBLZXlTZXQuZ2V0VXNlckRldmljZVNlY3JldDtcbiAgfSxcbiAgcmVhZHk6IHtuYW1lLCB2ZXJzaW9uLCBvcmlnaW46IEtleVNldC5TdG9yYWdlLm9yaWdpbn0sXG5cbiAgLy8gVGhlIGZvdXIgYmFzaWMgb3BlcmF0aW9ucy4gLi4ucmVzdCBtYXkgYmUgb25lIG9yIG1vcmUgdGFncywgb3IgbWF5IGJlIHt0YWdzLCB0ZWFtLCBtZW1iZXIsIGNvbnRlbnRUeXBlLCAuLi59XG4gIGFzeW5jIGVuY3J5cHQobWVzc2FnZSwgLi4ucmVzdCkgeyAvLyBQcm9taXNlIGEgSldFLlxuICAgIGxldCBvcHRpb25zID0ge30sIHRhZ3MgPSB0aGlzLmNhbm9uaWNhbGl6ZVBhcmFtZXRlcnMocmVzdCwgb3B0aW9ucyksXG4gICAgICAgIGtleSA9IGF3YWl0IEtleVNldC5wcm9kdWNlS2V5KHRhZ3MsIHRhZyA9PiBLZXlTZXQuZW5jcnlwdGluZ0tleSh0YWcpLCBvcHRpb25zKTtcbiAgICByZXR1cm4gTXVsdGlLcnlwdG8uZW5jcnlwdChrZXksIG1lc3NhZ2UsIG9wdGlvbnMpO1xuICB9LFxuICBhc3luYyBkZWNyeXB0KGVuY3J5cHRlZCwgLi4ucmVzdCkgeyAvLyBQcm9taXNlIHtwYXlsb2FkLCB0ZXh0LCBqc29ufSBhcyBhcHByb3ByaWF0ZS5cbiAgICBsZXQgb3B0aW9ucyA9IHt9LFxuICAgICAgICBbdGFnXSA9IHRoaXMuY2Fub25pY2FsaXplUGFyYW1ldGVycyhyZXN0LCBvcHRpb25zLCBlbmNyeXB0ZWQpLFxuICAgICAgICB7cmVjb3ZlcnksIC4uLm90aGVyT3B0aW9uc30gPSBvcHRpb25zLFxuICAgICAgICBrZXlTZXQgPSBhd2FpdCBLZXlTZXQuZW5zdXJlKHRhZywge3JlY292ZXJ5fSk7XG4gICAgcmV0dXJuIGtleVNldC5kZWNyeXB0KGVuY3J5cHRlZCwgb3RoZXJPcHRpb25zKTtcbiAgfSxcbiAgYXN5bmMgc2lnbihtZXNzYWdlLCAuLi5yZXN0KSB7IC8vIFByb21pc2UgYSBKV1MuXG4gICAgbGV0IG9wdGlvbnMgPSB7fSwgdGFncyA9IHRoaXMuY2Fub25pY2FsaXplUGFyYW1ldGVycyhyZXN0LCBvcHRpb25zKTtcbiAgICByZXR1cm4gS2V5U2V0LnNpZ24obWVzc2FnZSwge3RhZ3MsIC4uLm9wdGlvbnN9KTtcbiAgfSxcbiAgYXN5bmMgdmVyaWZ5KHNpZ25hdHVyZSwgLi4ucmVzdCkgeyAvLyBQcm9taXNlIHtwYXlsb2FkLCB0ZXh0LCBqc29ufSBhcyBhcHByb3ByaWF0ZS5cbiAgICBsZXQgb3B0aW9ucyA9IHt9LCB0YWdzID0gdGhpcy5jYW5vbmljYWxpemVQYXJhbWV0ZXJzKHJlc3QsIG9wdGlvbnMsIHNpZ25hdHVyZSk7XG4gICAgcmV0dXJuIEtleVNldC52ZXJpZnkoc2lnbmF0dXJlLCB0YWdzLCBvcHRpb25zKTtcbiAgfSxcblxuICAvLyBUYWcgbWFpbnRhbmNlLlxuICBhc3luYyBjcmVhdGUoLi4ubWVtYmVycykgeyAvLyBQcm9taXNlIGEgbmV3bHktY3JlYXRlZCB0YWcgd2l0aCB0aGUgZ2l2ZW4gbWVtYmVycy4gVGhlIG1lbWJlciB0YWdzIChpZiBhbnkpIG11c3QgYWxyZWFkeSBleGlzdC5cbiAgICBpZiAoIW1lbWJlcnMubGVuZ3RoKSByZXR1cm4gYXdhaXQgRGV2aWNlS2V5U2V0LmNyZWF0ZSgpO1xuICAgIGxldCBwcm9tcHQgPSBtZW1iZXJzWzBdLnByb21wdDtcbiAgICBpZiAocHJvbXB0KSByZXR1cm4gYXdhaXQgUmVjb3ZlcnlLZXlTZXQuY3JlYXRlKHByb21wdCk7XG4gICAgcmV0dXJuIGF3YWl0IFRlYW1LZXlTZXQuY3JlYXRlKG1lbWJlcnMpO1xuICB9LFxuICBhc3luYyBjaGFuZ2VNZW1iZXJzaGlwKHt0YWcsIHJlY292ZXJ5ID0gZmFsc2UsIC4uLm9wdGlvbnN9KSB7IC8vIFByb21pc2UgdG8gYWRkIG9yIHJlbW92ZSBtZW1iZXJzLlxuICAgIGxldCBrZXlTZXQgPSBhd2FpdCBLZXlTZXQuZW5zdXJlKHRhZywge3JlY292ZXJ5LCAuLi5vcHRpb25zfSk7IC8vIE1ha2VzIG5vIHNlbnNlIHRvIGNoYW5nZU1lbWJlcnNoaXAgb2YgYSByZWNvdmVyeSBrZXkuXG4gICAgcmV0dXJuIGtleVNldC5jaGFuZ2VNZW1iZXJzaGlwKG9wdGlvbnMpO1xuICB9LFxuICBhc3luYyBkZXN0cm95KHRhZ09yT3B0aW9ucykgeyAvLyBQcm9taXNlIHRvIHJlbW92ZSB0aGUgdGFnIGFuZCBhbnkgYXNzb2NpYXRlZCBkYXRhIGZyb20gYWxsIHN0b3JhZ2UuXG4gICAgaWYgKCdzdHJpbmcnID09PSB0eXBlb2YgdGFnT3JPcHRpb25zKSB0YWdPck9wdGlvbnMgPSB7dGFnOiB0YWdPck9wdGlvbnN9O1xuICAgIGxldCB7dGFnLCByZWNvdmVyeSA9IHRydWUsIC4uLm90aGVyT3B0aW9uc30gPSB0YWdPck9wdGlvbnMsXG4gICAgICAgIG9wdGlvbnMgPSB7cmVjb3ZlcnksIC4uLm90aGVyT3B0aW9uc30sXG4gICAgICAgIGtleVNldCA9IGF3YWl0IEtleVNldC5lbnN1cmUodGFnLCBvcHRpb25zKTtcbiAgICByZXR1cm4ga2V5U2V0LmRlc3Ryb3kob3B0aW9ucyk7XG4gIH0sXG4gIGNsZWFyKHRhZykgeyAvLyBSZW1vdmUgYW55IGxvY2FsbHkgY2FjaGVkIEtleVNldCBmb3IgdGhlIHRhZywgb3IgYWxsIEtleVNldHMgaWYgbm90IHRhZyBzcGVjaWZpZWQuXG4gICAgS2V5U2V0LmNsZWFyKHRhZyk7XG4gIH0sXG5cbiAgZGVjb2RlUHJvdGVjdGVkSGVhZGVyOiBNdWx0aUtyeXB0by5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIsXG4gIGNhbm9uaWNhbGl6ZVBhcmFtZXRlcnMocmVzdCwgb3B0aW9ucywgdG9rZW4pIHsgLy8gUmV0dXJuIHRoZSBhY3R1YWwgbGlzdCBvZiB0YWdzLCBhbmQgYmFzaCBvcHRpb25zLlxuICAgIC8vIHJlc3QgbWF5IGJlIGEgbGlzdCBvZiB0YWcgc3RyaW5nc1xuICAgIC8vICAgIG9yIGEgbGlzdCBvZiBvbmUgc2luZ2xlIG9iamVjdCBzcGVjaWZ5aW5nIG5hbWVkIHBhcmFtZXRlcnMsIGluY2x1ZGluZyBlaXRoZXIgdGVhbSwgdGFncywgb3IgbmVpdGhlclxuICAgIC8vIHRva2VuIG1heSBiZSBhIEpXRSBvciBKU0UsIG9yIGZhbHN5LCBhbmQgaXMgdXNlZCB0byBzdXBwbHkgdGFncyBpZiBuZWNlc3NhcnkuXG4gICAgaWYgKHJlc3QubGVuZ3RoID4gMSB8fCByZXN0WzBdPy5sZW5ndGggIT09IHVuZGVmaW5lZCkgcmV0dXJuIHJlc3Q7XG4gICAgbGV0IHt0YWdzID0gW10sIGNvbnRlbnRUeXBlLCB0aW1lLCAuLi5vdGhlcnN9ID0gcmVzdFswXSB8fCB7fSxcblx0e3RlYW19ID0gb3RoZXJzOyAvLyBEbyBub3Qgc3RyaXAgdGVhbSBmcm9tIG90aGVycy5cbiAgICBpZiAoIXRhZ3MubGVuZ3RoKSB7XG4gICAgICBpZiAocmVzdC5sZW5ndGggJiYgcmVzdFswXS5sZW5ndGgpIHRhZ3MgPSByZXN0OyAvLyByZXN0IG5vdCBlbXB0eSwgYW5kIGl0cyBmaXJzdCBpcyBzdHJpbmctbGlrZS5cbiAgICAgIGVsc2UgaWYgKHRva2VuKSB7IC8vIGdldCBmcm9tIHRva2VuXG4gICAgICAgIGlmICh0b2tlbi5zaWduYXR1cmVzKSB0YWdzID0gdG9rZW4uc2lnbmF0dXJlcy5tYXAoc2lnID0+IHRoaXMuZGVjb2RlUHJvdGVjdGVkSGVhZGVyKHNpZykua2lkKTtcbiAgICAgICAgZWxzZSBpZiAodG9rZW4ucmVjaXBpZW50cykgdGFncyA9IHRva2VuLnJlY2lwaWVudHMubWFwKHJlYyA9PiByZWMuaGVhZGVyLmtpZCk7XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgIGxldCBraWQgPSB0aGlzLmRlY29kZVByb3RlY3RlZEhlYWRlcih0b2tlbikua2lkOyAvLyBjb21wYWN0IHRva2VuXG4gICAgICAgICAgaWYgKGtpZCkgdGFncyA9IFtraWRdO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICAgIGlmICh0ZWFtICYmICF0YWdzLmluY2x1ZGVzKHRlYW0pKSB0YWdzID0gW3RlYW0sIC4uLnRhZ3NdO1xuICAgIGlmIChjb250ZW50VHlwZSkgb3B0aW9ucy5jdHkgPSBjb250ZW50VHlwZTtcbiAgICBpZiAodGltZSkgb3B0aW9ucy5pYXQgPSB0aW1lO1xuICAgIE9iamVjdC5hc3NpZ24ob3B0aW9ucywgb3RoZXJzKTtcblxuICAgIHJldHVybiB0YWdzO1xuICB9XG59O1xuXG5leHBvcnQgZGVmYXVsdCBTZWN1cml0eTtcbiIsImltcG9ydCBTdG9yYWdlIGZyb20gXCIuL3N1cHBvcnQvc3RvcmFnZS5tanNcIjtcbmltcG9ydCBTZWN1cml0eSBmcm9tIFwiQGtpMXIweS9kaXN0cmlidXRlZC1zZWN1cml0eVwiO1xuXG5pbXBvcnQgdGVzdEtyeXB0byBmcm9tIFwiLi9rcnlwdG9UZXN0cy5tanNcIjtcbmltcG9ydCB0ZXN0TXVsdGlLcnlwdG8gZnJvbSBcIi4vbXVsdGlLcnlwdG9UZXN0cy5tanNcIjtcbmltcG9ydCB7IG1ha2VNZXNzYWdlLCBpc0Jhc2U2NFVSTCwgc2FtZVR5cGVkQXJyYXl9IGZyb20gXCIuL3N1cHBvcnQvbWVzc2FnZVRleHQubWpzXCI7XG5cbi8vIFNldHVwLlxuLy9qYXNtaW5lLmdldEVudigpLmNvbmZpZ3VyZSh7cmFuZG9tOiBmYWxzZX0pO1xubGV0IHRoaXNEZXZpY2VTZWNyZXQgPSBcInNlY3JldFwiLFxuICAgIHNlY3JldCA9IHRoaXNEZXZpY2VTZWNyZXQ7XG5hc3luYyBmdW5jdGlvbiB3aXRoU2VjcmV0KHRodW5rKSB7XG4gIHNlY3JldCA9IFwib3RoZXJcIjtcbiAgYXdhaXQgdGh1bmsoKTtcbiAgc2VjcmV0ID0gdGhpc0RldmljZVNlY3JldDtcbn1cbmZ1bmN0aW9uIGdldFNlY3JldCh0YWcsIHJlY292ZXJ5UHJvbXB0ID0gJycpIHtcbiAgcmV0dXJuIHJlY292ZXJ5UHJvbXB0ICsgc2VjcmV0O1xufVxuXG4vLyBGb3IgdGVzdGluZyBpbnRlcm5hbHMuXG5cbi8vIElmIFRISVMgZmlsZSBpcyBidW5kbGVkLCBpdCBjYW4gcmVzb2x2ZSBhIGRpcmVjdCByZWZlcmVuY2UgdG8gdGhlIGludGVybmFsczpcbmltcG9ydCB7S3J5cHRvLCBNdWx0aUtyeXB0bywgSW50ZXJuYWxTZWN1cml0eSwgS2V5U2V0LCBMb2NhbENvbGxlY3Rpb259IGZyb20gJy4vc3VwcG9ydC9pbnRlcm5hbHMubWpzJztcbi8vaW1wb3J0IHtLcnlwdG8sIE11bHRpS3J5cHRvLCBJbnRlcm5hbFNlY3VyaXR5LCBLZXlTZXQsIExvY2FsQ29sbGVjdGlvbn0gZnJvbSAnQGtpMXIweS9kaXN0cmlidXRlZC1zZWN1cml0eS9kaXN0L2ludGVybmFsLWJyb3dzZXItYnVuZGxlLm1qcyc7XG4vLyBJZiB0aGlzIGZpbGUgaXMgcmVmZXJlbmNlZCBkaXJlY3RseSwgYXMgaXMsIGluIGEgdGVzdC5odG1sLCB0aGVuIHdlJ2xsIG5lZWQgdG8gaGF2ZSBhIGJ1bmRsZSBwcmVwYXJlZCxcbi8vIHRoYXQgZ2V0cyByZXNvbHZlZCB0aHJvdWdoIHBhY2thZ2UuanNvbjpcbi8vaW1wb3J0IHtLcnlwdG8sIE11bHRpS3J5cHRvLCBJbnRlcm5hbFNlY3VyaXR5LCBLZXlTZXQsIExvY2FsQ29sbGVjdGlvbn0gZnJvbSAnI2ludGVybmFscyc7XG5cbi8vIERlZmluZSBzb21lIGdsb2JhbHMgaW4gYSBicm93c2VyIGZvciBkZWJ1Z2dpbmcuXG5pZiAodHlwZW9mKHdpbmRvdykgIT09ICd1bmRlZmluZWQnKSBPYmplY3QuYXNzaWduKHdpbmRvdywge1NlY3VyaXR5LCBLcnlwdG8sIE11bHRpS3J5cHRvLCBTdG9yYWdlfSk7XG5cbmRlc2NyaWJlKCdEaXN0cmlidXRlZCBTZWN1cml0eScsIGZ1bmN0aW9uICgpIHtcbiAgbGV0IG1lc3NhZ2UgPSBtYWtlTWVzc2FnZSgpLFxuICAgICAgb3JpZ2luYWxTdG9yYWdlID0gU2VjdXJpdHkuU3RvcmFnZSxcbiAgICAgIG9yaWdpbmFsU2VjcmV0ID0gU2VjdXJpdHkuZ2V0VXNlckRldmljZVNlY3JldDtcbiAgYmVmb3JlQWxsKGZ1bmN0aW9uICgpIHtcbiAgICBTdG9yYWdlLlNlY3VyaXR5ID0gU2VjdXJpdHk7XG4gICAgU2VjdXJpdHkuU3RvcmFnZSA9IFN0b3JhZ2U7XG4gICAgU2VjdXJpdHkuZ2V0VXNlckRldmljZVNlY3JldCA9IGdldFNlY3JldDtcbiAgICBJbnRlcm5hbFNlY3VyaXR5LlN0b3JhZ2UgPSBTdG9yYWdlO1xuICAgIEludGVybmFsU2VjdXJpdHkuZ2V0VXNlckRldmljZVNlY3JldCA9IGdldFNlY3JldDtcbiAgfSk7XG4gIGFmdGVyQWxsKGZ1bmN0aW9uICgpIHtcbiAgICBTZWN1cml0eS5TdG9yYWdlID0gb3JpZ2luYWxTdG9yYWdlO1xuICAgIFNlY3VyaXR5LmdldFVzZXJEZXZpY2VTZWNyZXQgPSBvcmlnaW5hbFNlY3JldDtcbiAgfSk7XG4gIGRlc2NyaWJlKCdLcnlwdG8nLCBmdW5jdGlvbiAoKSB7XG4gICAgdGVzdEtyeXB0byhLcnlwdG8pO1xuICB9KTtcbiAgZGVzY3JpYmUoJ011bHRpS3J5cHRvJywgZnVuY3Rpb24gKCkge1xuICAgIHRlc3RNdWx0aUtyeXB0byhNdWx0aUtyeXB0byk7XG4gIH0pO1xuICBkZXNjcmliZSgnU2VjdXJpdHknLCBmdW5jdGlvbiAoKSB7XG4gICAgY29uc3Qgc2xvd0tleUNyZWF0aW9uID0gNjBlMzsgLy8gZS5nLiwgU2FmYXJpIG5lZWRzIGFib3V0IDE1IHNlY29uZHMuIEFuZHJvaWQgbmVlZHMgbW9yZVxuICAgIGFzeW5jIGZ1bmN0aW9uIG1ha2VLZXlTZXRzKHNjb3BlKSB7IC8vIENyZWF0ZSBhIHN0YW5kYXJkIHNldCBvZiB0ZXN0IHZhdWx0cyB0aHJvdWdoIGNvbnRleHQuXG4gICAgICBsZXQgdGFncyA9IHt9O1xuICAgICAgbGV0IFtkZXZpY2UsIHJlY292ZXJ5LCBvdGhlclJlY292ZXJ5XSA9IGF3YWl0IFByb21pc2UuYWxsKFtcbiAgICAgICAgc2NvcGUuY3JlYXRlKCksXG4gICAgICAgIHNjb3BlLmNyZWF0ZSh7cHJvbXB0OiBcIndoYXQ/XCJ9KSxcbiAgICAgICAgc2NvcGUuY3JlYXRlKHtwcm9tcHQ6IFwibm9wZSFcIn0pXG4gICAgICBdKVxuICAgICAgbGV0IG90aGVyRGV2aWNlLCBvdGhlclVzZXI7XG4gICAgICBhd2FpdCB3aXRoU2VjcmV0KGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgb3RoZXJEZXZpY2UgPSBhd2FpdCBzY29wZS5jcmVhdGUoKTtcbiAgICAgICAgb3RoZXJVc2VyID0gYXdhaXQgc2NvcGUuY3JlYXRlKG90aGVyRGV2aWNlKTtcbiAgICAgIH0pO1xuICAgICAgbGV0IHVzZXIgPSBhd2FpdCBzY29wZS5jcmVhdGUoZGV2aWNlKTtcbiAgICAgIC8vIC8vIE5vdGU6IHNhbWUgbWVtYmVycywgYnV0IGEgZGlmZmVyZW50IGlkZW50aXR5LlxuICAgICAgbGV0IFt0ZWFtLCBvdGhlclRlYW1dID0gYXdhaXQgUHJvbWlzZS5hbGwoW3Njb3BlLmNyZWF0ZSh1c2VyLCBvdGhlclVzZXIpLCBzY29wZS5jcmVhdGUob3RoZXJVc2VyLCB1c2VyKV0pO1xuICAgICAgdGFncy5kZXZpY2UgPSBkZXZpY2U7XG4gICAgICB0YWdzLm90aGVyRGV2aWNlID0gb3RoZXJEZXZpY2U7XG4gICAgICB0YWdzLnJlY292ZXJ5ID0gcmVjb3Zlcnk7IHRhZ3Mub3RoZXJSZWNvdmVyeSA9IG90aGVyUmVjb3Zlcnk7XG4gICAgICB0YWdzLnVzZXIgPSB1c2VyOyB0YWdzLm90aGVyVXNlciA9IG90aGVyVXNlcjtcbiAgICAgIHRhZ3MudGVhbSA9IHRlYW07IHRhZ3Mub3RoZXJUZWFtID0gb3RoZXJUZWFtO1xuICAgICAgcmV0dXJuIHRhZ3M7XG4gICAgfVxuICAgIGFzeW5jIGZ1bmN0aW9uIGRlc3Ryb3lLZXlTZXRzKHNjb3BlLCB0YWdzKSB7XG4gICAgICBhd2FpdCBzY29wZS5kZXN0cm95KHRhZ3Mub3RoZXJUZWFtKTtcbiAgICAgIGF3YWl0IHNjb3BlLmRlc3Ryb3kodGFncy50ZWFtKTtcbiAgICAgIGF3YWl0IHNjb3BlLmRlc3Ryb3kodGFncy51c2VyKTtcbiAgICAgIGF3YWl0IHNjb3BlLmRlc3Ryb3kodGFncy5kZXZpY2UpO1xuICAgICAgYXdhaXQgc2NvcGUuZGVzdHJveSh0YWdzLnJlY292ZXJ5KTtcbiAgICAgIGF3YWl0IHNjb3BlLmRlc3Ryb3kodGFncy5vdGhlclJlY292ZXJ5KTtcbiAgICAgIGF3YWl0IHdpdGhTZWNyZXQoYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICBhd2FpdCBzY29wZS5kZXN0cm95KHRhZ3Mub3RoZXJVc2VyKTtcbiAgICAgICAgYXdhaXQgc2NvcGUuZGVzdHJveSh0YWdzLm90aGVyRGV2aWNlKTtcbiAgICAgIH0pO1xuICAgIH1cbiAgICBkZXNjcmliZSgnaW50ZXJuYWwgbWFjaGluZXJ5JywgZnVuY3Rpb24gKCkge1xuICAgICAgbGV0IHRhZ3M7XG4gICAgICBiZWZvcmVBbGwoYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICB0YWdzID0gYXdhaXQgbWFrZUtleVNldHMoSW50ZXJuYWxTZWN1cml0eSk7XG4gICAgICB9LCBzbG93S2V5Q3JlYXRpb24pO1xuICAgICAgYWZ0ZXJBbGwoYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICBhd2FpdCBkZXN0cm95S2V5U2V0cyhJbnRlcm5hbFNlY3VyaXR5LCB0YWdzKTtcbiAgICAgIH0sIHNsb3dLZXlDcmVhdGlvbik7XG4gICAgICBmdW5jdGlvbiB2YXVsdFRlc3RzKGxhYmVsLCB0YWdzS2V5LCBvcHRpb25zID0ge30pIHtcbiAgICAgICAgZGVzY3JpYmUobGFiZWwsIGZ1bmN0aW9uICgpIHsgXG4gICAgICAgICAgbGV0IHZhdWx0LCB0YWc7XG4gICAgICAgICAgYmVmb3JlQWxsKGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHRhZyA9IHRhZ3NbdGFnc0tleV07XG4gICAgICAgICAgICB2YXVsdCA9IGF3YWl0IEtleVNldC5lbnN1cmUodGFnLCB7cmVjb3Zlcnk6dHJ1ZX0pO1xuICAgICAgICAgIH0pO1xuICAgICAgICAgIGl0KCd0YWcgaXMgZXhwb3J0ZWQgdmVyaWZ5IGtleSwgYW5kIHNpZ24oKSBwYWlycyB3aXRoIGl0LicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIGxldCB2ZXJpZnlLZXkgPSBhd2FpdCBNdWx0aUtyeXB0by5pbXBvcnRSYXcodGFnKSxcbiAgICAgICAgICAgICAgICBleHBvcnRlZCA9IGF3YWl0IE11bHRpS3J5cHRvLmV4cG9ydFJhdyh2ZXJpZnlLZXkpO1xuICAgICAgICAgICAgZXhwZWN0KHR5cGVvZiB0YWcpLnRvQmUoJ3N0cmluZycpO1xuICAgICAgICAgICAgZXhwZWN0KGV4cG9ydGVkKS50b0JlKHRhZyk7XG5cbiAgICAgICAgICAgIGxldCB2YXVsdCA9IGF3YWl0IEtleVNldC5lbnN1cmUodGFnLCB7cmVjb3Zlcnk6dHJ1ZX0pO1xuXG4gICAgICAgICAgICBsZXQgc2lnbmF0dXJlID0gYXdhaXQgS2V5U2V0LnNpZ24obWVzc2FnZSwge3RhZ3M6IFt0YWddLCBzaWduaW5nS2V5OiB2YXVsdC5zaWduaW5nS2V5LCAuLi5vcHRpb25zfSksXG4gICAgICAgICAgICAgICAgdmVyaWZpY2F0aW9uID0gYXdhaXQgTXVsdGlLcnlwdG8udmVyaWZ5KHZlcmlmeUtleSwgc2lnbmF0dXJlKTtcbiAgICAgICAgICAgIGlzQmFzZTY0VVJMKHNpZ25hdHVyZSk7XG4gICAgICAgICAgICBleHBlY3QodmVyaWZpY2F0aW9uKS50b0JlVHJ1dGh5KCk7XG4gICAgICAgICAgfSk7XG4gICAgICAgICAgaXQoJ3B1YmxpYyBlbmNyeXB0aW9uIHRhZyBjYW4gYmUgcmV0cmlldmVkIGV4dGVybmFsbHksIGFuZCB2YXVsdC5kZWNyeXB0KCkgcGFpcnMgd2l0aCBpdC4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBsZXQgdGFnID0gdmF1bHQudGFnLFxuICAgICAgICAgICAgICAgIHJldHJpZXZlZCA9IGF3YWl0IFN0b3JhZ2UucmV0cmlldmUoJ0VuY3J5cHRpb25LZXknLCB0YWcpLFxuICAgICAgICAgICAgICAgIHZlcmlmaWVkID0gYXdhaXQgU2VjdXJpdHkudmVyaWZ5KHJldHJpZXZlZCwgdGFnKSxcbiAgICAgICAgICAgICAgICBpbXBvcnRlZCA9IGF3YWl0IE11bHRpS3J5cHRvLmltcG9ydEpXSyh2ZXJpZmllZC5qc29uKSxcbiAgICAgICAgICAgICAgICBlbmNyeXB0ZWQgPSBhd2FpdCBNdWx0aUtyeXB0by5lbmNyeXB0KGltcG9ydGVkLCBtZXNzYWdlKSxcbiAgICAgICAgICAgICAgICBkZWNyeXB0ZWQgPSBhd2FpdCB2YXVsdC5kZWNyeXB0KGVuY3J5cHRlZCwgb3B0aW9ucyk7XG4gICAgICAgICAgICBleHBlY3QoZGVjcnlwdGVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgICAgdmF1bHRUZXN0cygnRGV2aWNlS2V5U2V0JywgJ2RldmljZScpO1xuICAgICAgdmF1bHRUZXN0cygnUmVjb3ZlcnlLZXlTZXQnLCAncmVjb3ZlcnknLCB7cmVjb3Zlcnk6IHRydWV9KTsgLy8gUmVjb3ZlcnkgdGFncyBhcmUgbm90IG5vcm1hbGx5IHVzZWQgdG8gZGVjcnlwdCBvciBzaWduLCBidXQgdGhleSBjYW4gYmUgYWxsb3dlZCBmb3IgdGVzdGluZy5cbiAgICAgIHZhdWx0VGVzdHMoJ1RlYW1LZXlTZXQnLCAndXNlcicpO1xuICAgICAgZGVzY3JpYmUoJ2xvY2FsIHN0b3JlJywgZnVuY3Rpb24gKCkge1xuICAgICAgICB2YXIgc3RvcmU7IFxuICAgICAgICBiZWZvcmVBbGwoYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgIHN0b3JlID0gbmV3IExvY2FsQ29sbGVjdGlvbih7ZGJOYW1lOiAndGVzdFN0b3JlJywgY29sbGVjdGlvbk5hbWU6ICdGb28nfSk7XG4gICAgICAgICAgYXdhaXQgbmV3IFByb21pc2UocmVzb2x2ZSA9PiBzZXRUaW1lb3V0KHJlc29sdmUsIDJlMykpOyAvLyBmaXhtZSByZW1vdmVcbiAgICAgICAgfSk7XG4gICAgICAgIGl0KCdjYW4gcmVtb3ZlIHdpdGhvdXQgZXhpc3RpbmcuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGxldCB0YWcgPSAnbm9uRXhpc3RhbnQnO1xuICAgICAgICAgIGV4cGVjdChhd2FpdCBzdG9yZS5yZW1vdmUodGFnKSkudG9CZShcIlwiKTtcbiAgICAgICAgfSk7XG4gICAgICAgIGl0KCdjYW4gcmV0cmlldmUgd2l0aG91dCBleGlzdGluZy4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgbGV0IHRhZyA9ICdub25FeGlzdGFudCc7XG4gICAgICAgICAgZXhwZWN0KGF3YWl0IHN0b3JlLnJldHJpZXZlKHRhZykpLnRvQmUoXCJcIik7XG4gICAgICAgIH0pO1xuICAgICAgICBpdCgncmV0cmlldmVzIGFuZCBjYW4gcmVtb3ZlIHdoYXQgaXMgc3RvcmVkLicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBsZXQgdGFnID0gJ3gnLCBtZXNzYWdlID0gXCJoZWxsb1wiO1xuICAgICAgICAgIGV4cGVjdChhd2FpdCBzdG9yZS5zdG9yZSh0YWcsIG1lc3NhZ2UpKS5ub3QudG9CZVVuZGVmaW5lZCgpO1xuICAgICAgICAgIGV4cGVjdChhd2FpdCBzdG9yZS5yZXRyaWV2ZSh0YWcpKS50b0JlKG1lc3NhZ2UpO1xuICAgICAgICAgIGV4cGVjdChhd2FpdCBzdG9yZS5yZW1vdmUodGFnKSkudG9CZShcIlwiKTtcbiAgICAgICAgICBleHBlY3QoYXdhaXQgc3RvcmUucmV0cmlldmUodGFnKSkudG9CZShcIlwiKTtcbiAgICAgICAgfSk7XG4gICAgICAgIGl0KCdjYW4gd3JpdGUgYSBsb3Qgd2l0aG91dCBnZXR0aW5nIGp1bWJsZWQuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGxldCBjb3VudCA9IDEwMDAsIHByZWZpeCA9IFwieVwiLCB0YWdzID0gW107XG4gICAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCBjb3VudDsgaSsrKSB0YWdzLnB1c2gocHJlZml4ICsgaSk7XG4gICAgICAgICAgbGV0IHN0YXJ0LCBlbGFwc2VkLCBwZXI7XG5cbiAgICAgICAgICBzdGFydCA9IERhdGUubm93KCk7XG4gICAgICAgICAgbGV0IHN0b3JlcyA9IGF3YWl0IFByb21pc2UuYWxsKHRhZ3MubWFwKCh0YWcsIGluZGV4KSA9PiBzdG9yZS5zdG9yZSh0YWcsIGluZGV4LnRvU3RyaW5nKCkpKSk7XG4gICAgICAgICAgZWxhcHNlZCA9IERhdGUubm93KCkgLSBzdGFydDsgcGVyID0gZWxhcHNlZC9jb3VudDtcbiAgICAgICAgICAvL2NvbnNvbGUubG9nKHtlbGFwc2VkLCBwZXJ9KTtcbiAgICAgICAgICBleHBlY3QocGVyKS50b0JlTGVzc1RoYW4oNjApO1xuICAgICAgICAgIHN0b3Jlcy5mb3JFYWNoKHN0b3JlUmVzdWx0ID0+IGV4cGVjdChzdG9yZVJlc3VsdCkubm90LnRvQmVVbmRlZmluZWQoKSk7XG5cbiAgICAgICAgICBzdGFydCA9IERhdGUubm93KCk7XG4gICAgICAgICAgbGV0IHJlYWRzID0gYXdhaXQgUHJvbWlzZS5hbGwodGFncy5tYXAodGFnID0+IHN0b3JlLnJldHJpZXZlKHRhZykpKTtcbiAgICAgICAgICBlbGFwc2VkID0gRGF0ZS5ub3coKSAtIHN0YXJ0OyBwZXIgPSBlbGFwc2VkL2NvdW50O1xuICAgICAgICAgIC8vY29uc29sZS5sb2coe2VsYXBzZWQsIHBlcn0pO1xuICAgICAgICAgIGV4cGVjdChwZXIpLnRvQmVMZXNzVGhhbigzKTtcbiAgICAgICAgICByZWFkcy5mb3JFYWNoKChyZWFkUmVzdWx0LCBpbmRleCkgPT4gZXhwZWN0KHJlYWRSZXN1bHQpLnRvQmUoaW5kZXgudG9TdHJpbmcoKSkpO1xuXG4gICAgICAgICAgc3RhcnQgPSBEYXRlLm5vdygpO1xuICAgICAgICAgIGxldCByZW1vdmVzID0gYXdhaXQgUHJvbWlzZS5hbGwodGFncy5tYXAodGFnID0+IHN0b3JlLnJlbW92ZSh0YWcpKSk7XG4gICAgICAgICAgZWxhcHNlZCA9IERhdGUubm93KCkgLSBzdGFydDsgcGVyID0gZWxhcHNlZC9jb3VudDtcbiAgICAgICAgICAvL2NvbnNvbGUubG9nKHtlbGFwc2VkLCBwZXJ9KTtcbiAgICAgICAgICBleHBlY3QocGVyKS50b0JlTGVzc1RoYW4oOCk7XG4gICAgICAgICAgcmVtb3Zlcy5mb3JFYWNoKHJlbW92ZVJlc3VsdCA9PiBleHBlY3QocmVtb3ZlUmVzdWx0KS50b0JlKFwiXCIpKTtcblxuICAgICAgICAgIHN0YXJ0ID0gRGF0ZS5ub3coKTtcbiAgICAgICAgICBsZXQgcmVyZWFkcyA9IGF3YWl0IFByb21pc2UuYWxsKHRhZ3MubWFwKHRhZyA9PiBzdG9yZS5yZXRyaWV2ZSh0YWcpKSk7XG4gICAgICAgICAgZWxhcHNlZCA9IERhdGUubm93KCkgLSBzdGFydDsgcGVyID0gZWxhcHNlZC9jb3VudDtcbiAgICAgICAgICAvL2NvbnNvbGUubG9nKHtlbGFwc2VkLCBwZXJ9KTtcbiAgICAgICAgICBleHBlY3QocGVyKS50b0JlTGVzc1RoYW4oMC4xKTtcbiAgICAgICAgICByZXJlYWRzLmZvckVhY2gocmVhZFJlc3VsdCA9PiBleHBlY3QocmVhZFJlc3VsdCkudG9CZShcIlwiKSk7XG4gICAgICAgIH0sIDE1ZTUpXG4gICAgICB9KVxuICAgIH0pO1xuXG4gICAgZGVzY3JpYmUoXCJBUElcIiwgZnVuY3Rpb24gKCkge1xuICAgICAgbGV0IHRhZ3M7XG4gICAgICBiZWZvcmVBbGwoYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICBjb25zb2xlLmxvZyhhd2FpdCBTZWN1cml0eS5yZWFkeSk7XG4gICAgICAgIHRhZ3MgPSBhd2FpdCBtYWtlS2V5U2V0cyhTZWN1cml0eSk7XG4gICAgICB9LCBzbG93S2V5Q3JlYXRpb24pO1xuICAgICAgYWZ0ZXJBbGwoYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICBhd2FpdCBkZXN0cm95S2V5U2V0cyhTZWN1cml0eSwgdGFncyk7XG4gICAgICB9LCBzbG93S2V5Q3JlYXRpb24pO1xuICAgICAgZnVuY3Rpb24gdGVzdChsYWJlbCwgdGFnc05hbWUsIG90aGVyT3duZWRUYWdzTmFtZSwgdW5vd25lZFRhZ05hbWUsIG9wdGlvbnMgPSB7fSkge1xuICAgICAgICBkZXNjcmliZShsYWJlbCwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGxldCB0YWcsIG90aGVyT3duZWRUYWc7XG4gICAgICAgICAgYmVmb3JlQWxsKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHRhZyA9IHRhZ3NbdGFnc05hbWVdO1xuICAgICAgICAgICAgb3RoZXJPd25lZFRhZyA9IHRhZ3Nbb3RoZXJPd25lZFRhZ3NOYW1lXTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgICBkZXNjcmliZSgnc2lnbmF0dXJlJywgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgZGVzY3JpYmUoJ29mIG9uZSB0YWcnLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgIGl0KCdjYW4gc2lnbiBhbmQgYmUgdmVyaWZpZWQuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIGxldCBzaWduYXR1cmUgPSBhd2FpdCBTZWN1cml0eS5zaWduKG1lc3NhZ2UsIHt0YWdzOlt0YWddLCAuLi5vcHRpb25zfSk7XG4gICAgICAgICAgICAgICAgaXNCYXNlNjRVUkwoc2lnbmF0dXJlKTtcbiAgICAgICAgICAgICAgICBleHBlY3QoYXdhaXQgU2VjdXJpdHkudmVyaWZ5KHNpZ25hdHVyZSwgdGFnKSkudG9CZVRydXRoeSgpO1xuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgaXQoJ2NhbiBiZSB2ZXJpZmllZCB3aXRoIHRoZSB0YWcgaW5jbHVkZWQgaW4gdGhlIHNpZ25hdHVyZS4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgbGV0IHNpZ25hdHVyZSA9IGF3YWl0IFNlY3VyaXR5LnNpZ24obWVzc2FnZSwge3RhZ3M6IFt0YWddLCAuLi5vcHRpb25zfSk7XG4gICAgICAgICAgICAgICAgZXhwZWN0KGF3YWl0IFNlY3VyaXR5LnZlcmlmeShzaWduYXR1cmUpKS50b0JlVHJ1dGh5KCk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICBpdCgnY2Fubm90IHNpZ24gZm9yIGEgZGlmZmVyZW50IGtleS4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgbGV0IHNpZ25hdHVyZSA9IGF3YWl0IFNlY3VyaXR5LnNpZ24obWVzc2FnZSwge3RhZ3M6IFtvdGhlck93bmVkVGFnXSwgLi4ub3B0aW9uc30pO1xuICAgICAgICAgICAgICAgIGV4cGVjdChhd2FpdCBTZWN1cml0eS52ZXJpZnkoc2lnbmF0dXJlLCB0YWcpKS50b0JlVW5kZWZpbmVkKCk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICBpdCgnY2Fubm90IHNpZ24gd2l0aCBhbiB1bm93bmVkIGtleS4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgZXhwZWN0KGF3YWl0IFNlY3VyaXR5LnNpZ24oXCJzb21ldGhpbmdcIiwge3RhZ3M6IHRhZ3NbdW5vd25lZFRhZ05hbWVdLCAuLi5vcHRpb25zfSkuY2F0Y2goKCkgPT4gdW5kZWZpbmVkKSkudG9CZVVuZGVmaW5lZCgpO1xuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgaXQoJ2Rpc3Rpbmd1aXNoZXMgYmV0d2VlbiBjb3JyZWN0bHkgc2lnbmluZyBmYWxzZSBhbmQga2V5IGZhaWx1cmUuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIGxldCBzaWduYXR1cmUgPSBhd2FpdCBTZWN1cml0eS5zaWduKGZhbHNlLCB7dGFnczpbdGFnXSwgLi4ub3B0aW9uc30pLFxuICAgICAgICAgICAgICAgICAgICB2ZXJpZmllZCA9IGF3YWl0IFNlY3VyaXR5LnZlcmlmeShzaWduYXR1cmUsIHRhZyk7XG4gICAgICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWVkLmpzb24pLnRvQmUoZmFsc2UpO1xuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgaXQoJ2NhbiBzaWduIHRleHQgYW5kIHByb2R1Y2UgdmVyaWZpZWQgcmVzdWx0IHdpdGggdGV4dCBwcm9wZXJ0eS4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgbGV0IHNpZ25hdHVyZSA9IGF3YWl0IFNlY3VyaXR5LnNpZ24obWVzc2FnZSwge3RhZ3M6W3RhZ10sIC4uLm9wdGlvbnN9KSxcbiAgICAgICAgICAgICAgICAgICAgdmVyaWZpZWQgPSBhd2FpdCBTZWN1cml0eS52ZXJpZnkoc2lnbmF0dXJlLCB0YWcpO1xuICAgICAgICAgICAgICAgIGlzQmFzZTY0VVJMKHNpZ25hdHVyZSk7XG4gICAgICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICBpdCgnY2FuIHNpZ24ganNvbiBhbmQgcHJvZHVjZSB2ZXJpZmllZCByZXN1bHQgd2l0aCBqc29uIHByb3BlcnR5LicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBsZXQgbWVzc2FnZSA9IHt4OiAxLCB5OiBbXCJhYmNcIiwgbnVsbCwgZmFsc2VdfSxcbiAgICAgICAgICAgICAgICAgICAgc2lnbmF0dXJlID0gYXdhaXQgU2VjdXJpdHkuc2lnbihtZXNzYWdlLCB7dGFnczogW3RhZ10sIC4uLm9wdGlvbnN9KSxcbiAgICAgICAgICAgICAgICAgICAgdmVyaWZpZWQgPSBhd2FpdCBTZWN1cml0eS52ZXJpZnkoc2lnbmF0dXJlLCB0YWcpO1xuICAgICAgICAgICAgICAgIGlzQmFzZTY0VVJMKHNpZ25hdHVyZSk7XG4gICAgICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWVkLmpzb24pLnRvRXF1YWwobWVzc2FnZSk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICBpdCgnY2FuIHNpZ24gYmluYXJ5IGFuZCBwcm9kdWNlIHZlcmlmaWVkIHJlc3VsdCB3aXRoIHBheWxvYWQgcHJvcGVydHkuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIGxldCBtZXNzYWdlID0gbmV3IFVpbnQ4QXJyYXkoWzEsIDIsIDNdKSxcbiAgICAgICAgICAgICAgICAgICAgc2lnbmF0dXJlID0gYXdhaXQgU2VjdXJpdHkuc2lnbihtZXNzYWdlLCB7dGFnczogW3RhZ10sIC4uLm9wdGlvbnN9KSxcbiAgICAgICAgICAgICAgICAgICAgdmVyaWZpZWQgPSBhd2FpdCBTZWN1cml0eS52ZXJpZnkoc2lnbmF0dXJlLCB0YWcpO1xuICAgICAgICAgICAgICAgIGlzQmFzZTY0VVJMKHNpZ25hdHVyZSk7XG4gICAgICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWVkLnBheWxvYWQpLnRvRXF1YWwobWVzc2FnZSk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICBpdCgndXNlcyBjb250ZW50VHlwZSBhbmQgdGltZSBpZiBzdXBwbGllZC4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgbGV0IGNvbnRlbnRUeXBlID0gJ3RleHQvaHRtbCcsXG4gICAgICAgICAgICAgICAgICAgIHRpbWUgPSBEYXRlLm5vdygpLFxuICAgICAgICAgICAgICAgICAgICBtZXNzYWdlID0gXCI8c29tZXRoaW5nIGVsc2U+XCIsXG4gICAgICAgICAgICAgICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IFNlY3VyaXR5LnNpZ24obWVzc2FnZSwge3RhZ3M6IFt0YWddLCBjb250ZW50VHlwZSwgdGltZSwgLi4ub3B0aW9uc30pLFxuICAgICAgICAgICAgICAgICAgICB2ZXJpZmllZCA9IGF3YWl0IFNlY3VyaXR5LnZlcmlmeShzaWduYXR1cmUsIHRhZyk7XG4gICAgICAgICAgICAgICAgaXNCYXNlNjRVUkwoc2lnbmF0dXJlKTtcbiAgICAgICAgICAgICAgICBleHBlY3QodmVyaWZpZWQudGV4dCkudG9FcXVhbChtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICBleHBlY3QodmVyaWZpZWQucHJvdGVjdGVkSGVhZGVyLmN0eSkudG9CZShjb250ZW50VHlwZSk7XG4gICAgICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWVkLnByb3RlY3RlZEhlYWRlci5pYXQpLnRvQmUodGltZSk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICBkZXNjcmliZSgnb2YgbXVsdGlwbGUgdGFncycsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgaXQoJ2NhbiBzaWduIGFuZCBiZSB2ZXJpZmllZC4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgbGV0IHNpZ25hdHVyZSA9IGF3YWl0IFNlY3VyaXR5LnNpZ24obWVzc2FnZSwge3RhZ3M6IFt0YWcsIG90aGVyT3duZWRUYWddLCAuLi5vcHRpb25zfSksXG4gICAgICAgICAgICAgICAgICAgIHZlcmlmaWNhdGlvbiA9IGF3YWl0IFNlY3VyaXR5LnZlcmlmeShzaWduYXR1cmUsIG90aGVyT3duZWRUYWcsIHRhZyk7XG4gICAgICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWNhdGlvbikudG9CZVRydXRoeSgpOyAvLyBvcmRlciBkb2VzIG5vdCBtYXR0ZXJcbiAgICAgICAgICAgICAgICBleHBlY3QodmVyaWZpY2F0aW9uLnNpZ25lcnNbMF0ucGF5bG9hZCkudG9CZVRydXRoeSgpOyAvLyBBbGwgcmVjaXBpZW50cyBsaXN0ZWQgaW4gdmVyaWZ5XG4gICAgICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWNhdGlvbi5zaWduZXJzWzFdLnBheWxvYWQpLnRvQmVUcnV0aHkoKTtcbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgIGl0KCdkb2VzIG5vdCBhdHRlbXB0IHRvIHZlcmlmeSB1bmVudW1lcmF0ZWQgdGFncyBpZiBhbnkgYXJlIGV4cGxpY2l0JywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIGxldCBzaWduYXR1cmUgPSBhd2FpdCBTZWN1cml0eS5zaWduKG1lc3NhZ2UsIHt0YWdzOiBbdGFnLCBvdGhlck93bmVkVGFnXSwgLi4ub3B0aW9uc30pLFxuICAgICAgICAgICAgICAgICAgICB2ZXJpZmljYXRpb24gPSBhd2FpdCBTZWN1cml0eS52ZXJpZnkoc2lnbmF0dXJlLCBvdGhlck93bmVkVGFnKTtcbiAgICAgICAgICAgICAgICBleHBlY3QodmVyaWZpY2F0aW9uKS50b0JlVHJ1dGh5KCk7IC8vIG9yZGVyIGRvZXMgbm90IG1hdHRlclxuICAgICAgICAgICAgICAgIGV4cGVjdCh2ZXJpZmljYXRpb24uc2lnbmVyc1swXS5wYXlsb2FkKS50b0JlRmFsc3koKTsgLy8gQmVjYXVzZSB3ZSBleHBsaWNpdGx5IHZlcmlmaWVkIHdpdGggMSwgbm90IDAuXG4gICAgICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWNhdGlvbi5zaWduZXJzWzFdLnBheWxvYWQpLnRvQmVUcnV0aHkoKTtcbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgIGl0KCdjYW4gYmUgdmVyaWZpZWQgd2l0aCB0aGUgdGFnIGluY2x1ZGVkIGluIHRoZSBzaWduYXR1cmUuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIGxldCBzaWduYXR1cmUgPSBhd2FpdCBTZWN1cml0eS5zaWduKG1lc3NhZ2UsIHt0YWdzOiBbdGFnLCBvdGhlck93bmVkVGFnXSwgLi4ub3B0aW9uc30pLFxuICAgICAgICAgICAgICAgICAgICB2ZXJpZmljYXRpb24gPSBhd2FpdCBTZWN1cml0eS52ZXJpZnkoc2lnbmF0dXJlKTtcbiAgICAgICAgICAgICAgICBleHBlY3QodmVyaWZpY2F0aW9uKS50b0JlVHJ1dGh5KCk7XG4gICAgICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWNhdGlvbi5zaWduZXJzWzBdLnBheWxvYWQpLnRvQmVUcnV0aHkoKTsgLy8gQWxsIGFyZSBjaGVja2VkLCBhbmQgaW4gdGhpcyBjYXNlLCBwYXNzLlxuICAgICAgICAgICAgICAgIGV4cGVjdCh2ZXJpZmljYXRpb24uc2lnbmVyc1sxXS5wYXlsb2FkKS50b0JlVHJ1dGh5KCk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICBkZXNjcmliZSgnYmFkIHZlcmlmaWNhdGlvbicsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBsZXQgb25lTW9yZTtcbiAgICAgICAgICAgICAgICBiZWZvcmVBbGwoYXN5bmMgZnVuY3Rpb24gKCkgeyBvbmVNb3JlID0gYXdhaXQgU2VjdXJpdHkuY3JlYXRlKCk7IH0pO1xuICAgICAgICAgICAgICAgIGFmdGVyQWxsKGFzeW5jIGZ1bmN0aW9uICgpIHsgYXdhaXQgU2VjdXJpdHkuZGVzdHJveShvbmVNb3JlKTsgfSk7XG4gICAgICAgICAgICAgICAgZGVzY3JpYmUoJ3doZW4gbWl4aW5nIHNpbmdsZSBhbmQgbXVsdGktdGFncycsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgIGl0KCdmYWlscyB3aXRoIGV4dHJhIHNpZ25pbmcgdGFnLicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgbGV0IHNpZ25hdHVyZSA9IGF3YWl0IFNlY3VyaXR5LnNpZ24obWVzc2FnZSwge3RhZ3M6IFtvdGhlck93bmVkVGFnXSwgLi4ub3B0aW9uc30pO1xuICAgICAgICAgICAgICAgICAgICBleHBlY3QoYXdhaXQgU2VjdXJpdHkudmVyaWZ5KHNpZ25hdHVyZSwgdGFnKSkudG9CZVVuZGVmaW5lZCgpO1xuICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICBpdCgnZmFpbHMgd2l0aCBleHRyYSB2ZXJpZnlpbmcuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICBsZXQgc2lnbmF0dXJlID0gYXdhaXQgU2VjdXJpdHkuc2lnbihtZXNzYWdlLCB7dGFnczogW3RhZ10sIC4uLm9wdGlvbnN9KTtcbiAgICAgICAgICAgICAgICAgICAgZXhwZWN0KGF3YWl0IFNlY3VyaXR5LnZlcmlmeShzaWduYXR1cmUsIHRhZywgb3RoZXJPd25lZFRhZykpLnRvQmVVbmRlZmluZWQoKTtcbiAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIGRlc2NyaWJlKCd3aGVuIG1peGluZyBtdWx0aS10YWcgbGVuZ3RocycsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgIGl0KCdmYWlscyB3aXRoIG1pc21hdGNoZWQgc2lnbmluZyB0YWcuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICBsZXQgc2lnbmF0dXJlID0gYXdhaXQgU2VjdXJpdHkuc2lnbihtZXNzYWdlLCB7dGFnczogW290aGVyT3duZWRUYWcsIG9uZU1vcmVdLCAuLi5vcHRpb25zfSksXG4gICAgICAgICAgICAgICAgICAgICAgICB2ZXJpZmllZCA9IGF3YWl0IFNlY3VyaXR5LnZlcmlmeShzaWduYXR1cmUsIHRhZywgb25lTW9yZSlcbiAgICAgICAgICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWVkKS50b0JlVW5kZWZpbmVkKCk7XG4gICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgIGl0KCdmYWlscyB3aXRoIGV4dHJhIHZlcmlmeWluZyB0YWcuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgICBsZXQgc2lnbmF0dXJlID0gYXdhaXQgU2VjdXJpdHkuc2lnbihtZXNzYWdlLCB7dGFnczogW3RhZywgb25lTW9yZV0sIC4uLm9wdGlvbnN9KTtcbiAgICAgICAgICAgICAgICAgICAgZXhwZWN0KGF3YWl0IFNlY3VyaXR5LnZlcmlmeShzaWduYXR1cmUsIHRhZywgb3RoZXJPd25lZFRhZywgb25lTW9yZSkpLnRvQmVVbmRlZmluZWQoKTtcbiAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgaXQoJ2Rpc3Rpbmd1aXNoZXMgYmV0d2VlbiBjb3JyZWN0bHkgc2lnbmluZyBmYWxzZSBhbmQga2V5IGZhaWx1cmUuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIGxldCBzaWduYXR1cmUgPSBhd2FpdCBTZWN1cml0eS5zaWduKGZhbHNlLCB7dGFnczogW3RhZywgb3RoZXJPd25lZFRhZ10sIC4uLm9wdGlvbnN9KSxcbiAgICAgICAgICAgICAgICAgICAgdmVyaWZpZWQgPSBhd2FpdCBTZWN1cml0eS52ZXJpZnkoc2lnbmF0dXJlLCB0YWcsIG90aGVyT3duZWRUYWcpO1xuICAgICAgICAgICAgICAgIGV4cGVjdCh2ZXJpZmllZC5qc29uKS50b0JlKGZhbHNlKTtcbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgIGl0KCdjYW4gc2lnbiB0ZXh0IGFuZCBwcm9kdWNlIHZlcmlmaWVkIHJlc3VsdCB3aXRoIHRleHQgcHJvcGVydHkuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIGxldCBzaWduYXR1cmUgPSBhd2FpdCBTZWN1cml0eS5zaWduKG1lc3NhZ2UsIHt0YWdzOiBbdGFnLCBvdGhlck93bmVkVGFnXSwgLi4ub3B0aW9uc30pLFxuICAgICAgICAgICAgICAgICAgICB2ZXJpZmllZCA9IGF3YWl0IFNlY3VyaXR5LnZlcmlmeShzaWduYXR1cmUsIHRhZywgb3RoZXJPd25lZFRhZyk7XG4gICAgICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICBpdCgnY2FuIHNpZ24ganNvbiBhbmQgcHJvZHVjZSB2ZXJpZmllZCByZXN1bHQgd2l0aCBqc29uIHByb3BlcnR5LicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBsZXQgbWVzc2FnZSA9IHt4OiAxLCB5OiBbXCJhYmNcIiwgbnVsbCwgZmFsc2VdfSxcbiAgICAgICAgICAgICAgICAgICAgc2lnbmF0dXJlID0gYXdhaXQgU2VjdXJpdHkuc2lnbihtZXNzYWdlLCB7dGFnczogW3RhZywgb3RoZXJPd25lZFRhZ10sIC4uLm9wdGlvbnN9KSxcbiAgICAgICAgICAgICAgICAgICAgdmVyaWZpZWQgPSBhd2FpdCBTZWN1cml0eS52ZXJpZnkoc2lnbmF0dXJlLCB0YWcsIG90aGVyT3duZWRUYWcpO1xuICAgICAgICAgICAgICAgIGV4cGVjdCh2ZXJpZmllZC5qc29uKS50b0VxdWFsKG1lc3NhZ2UpO1xuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgaXQoJ2NhbiBzaWduIGJpbmFyeSBhbmQgcHJvZHVjZSB2ZXJpZmllZCByZXN1bHQgd2l0aCBwYXlsb2FkIHByb3BlcnR5LicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBsZXQgbWVzc2FnZSA9IG5ldyBVaW50OEFycmF5KFsxLCAyLCAzXSksXG4gICAgICAgICAgICAgICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IFNlY3VyaXR5LnNpZ24obWVzc2FnZSwge3RhZ3M6IFt0YWcsIG90aGVyT3duZWRUYWddLCAuLi5vcHRpb25zfSksXG4gICAgICAgICAgICAgICAgICAgIHZlcmlmaWVkID0gYXdhaXQgU2VjdXJpdHkudmVyaWZ5KHNpZ25hdHVyZSwgdGFnLCBvdGhlck93bmVkVGFnKTtcbiAgICAgICAgICAgICAgICBleHBlY3QodmVyaWZpZWQucGF5bG9hZCkudG9FcXVhbChtZXNzYWdlKTtcbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgIGl0KCd1c2VzIGNvbnRlbnRUeXBlIGFuZCB0aW1lIGlmIHN1cHBsaWVkLicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBsZXQgY29udGVudFR5cGUgPSAndGV4dC9odG1sJyxcbiAgICAgICAgICAgICAgICAgICAgdGltZSA9IERhdGUubm93KCksXG4gICAgICAgICAgICAgICAgICAgIG1lc3NhZ2UgPSBcIjxzb21ldGhpbmcgZWxzZT5cIixcbiAgICAgICAgICAgICAgICAgICAgc2lnbmF0dXJlID0gYXdhaXQgU2VjdXJpdHkuc2lnbihtZXNzYWdlLCB7dGFnczogW3RhZywgb3RoZXJPd25lZFRhZ10sIGNvbnRlbnRUeXBlLCB0aW1lLCAuLi5vcHRpb25zfSksXG4gICAgICAgICAgICAgICAgICAgIHZlcmlmaWVkID0gYXdhaXQgU2VjdXJpdHkudmVyaWZ5KHNpZ25hdHVyZSwgdGFnLCBvdGhlck93bmVkVGFnKTtcbiAgICAgICAgICAgICAgICBleHBlY3QodmVyaWZpZWQudGV4dCkudG9FcXVhbChtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICBleHBlY3QodmVyaWZpZWQucHJvdGVjdGVkSGVhZGVyLmN0eSkudG9CZShjb250ZW50VHlwZSk7XG4gICAgICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWVkLnByb3RlY3RlZEhlYWRlci5pYXQpLnRvQmUodGltZSk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfSk7XG4gICAgICAgICAgZGVzY3JpYmUoJ2VuY3J5cHRpb24nLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBkZXNjcmliZSgnd2l0aCBhIHNpbmdsZSB0YWcnLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgIGl0KCdjYW4gZGVjcnlwdCB3aGF0IGlzIGVuY3J5cHRlZCBmb3IgaXQuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIGxldCBlbmNyeXB0ZWQgPSBhd2FpdCBTZWN1cml0eS5lbmNyeXB0KG1lc3NhZ2UsIHRhZyksXG4gICAgICAgICAgICAgICAgICAgIGRlY3J5cHRlZCA9IGF3YWl0IFNlY3VyaXR5LmRlY3J5cHQoZW5jcnlwdGVkLCB7dGFnczogW3RhZ10sIC4uLm9wdGlvbnN9KTtcbiAgICAgICAgICAgICAgICBpc0Jhc2U2NFVSTChlbmNyeXB0ZWQpO1xuICAgICAgICAgICAgICAgIGV4cGVjdChkZWNyeXB0ZWQudGV4dCkudG9CZShtZXNzYWdlKTtcbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgIGl0KCdjYW4gYmUgZGVjcnlwdGVkIHVzaW5nIHRoZSB0YWcgaW5jbHVkZWQgaW4gdGhlIGVuY3J5cHRpb24uJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIGxldCBlbmNyeXB0ZWQgPSBhd2FpdCBTZWN1cml0eS5lbmNyeXB0KG1lc3NhZ2UsIHRhZyksXG4gICAgICAgICAgICAgICAgICAgIGRlY3J5cHRlZCA9IGF3YWl0IFNlY3VyaXR5LmRlY3J5cHQoZW5jcnlwdGVkLCBvcHRpb25zKTtcbiAgICAgICAgICAgICAgICBleHBlY3QoZGVjcnlwdGVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICBpdCgnaXMgdXJsLXNhZmUgYmFzZTY0LicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBpc0Jhc2U2NFVSTChhd2FpdCBTZWN1cml0eS5lbmNyeXB0KG1lc3NhZ2UsIHRhZykpO1xuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgaXQoJ3NwZWNpZmllcyBraWQuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIGxldCBoZWFkZXIgPSBLcnlwdG8uZGVjb2RlUHJvdGVjdGVkSGVhZGVyKGF3YWl0IFNlY3VyaXR5LmVuY3J5cHQobWVzc2FnZSwgdGFnKSk7XG4gICAgICAgICAgICAgICAgZXhwZWN0KGhlYWRlci5raWQpLnRvQmUodGFnKTtcbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgIGl0KCdjYW5ub3QgZGVjcnlwdCB3aGF0IGlzIGVuY3J5cHRlZCBmb3IgYSBkaWZmZXJlbnQga2V5LicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBsZXQgbWVzc2FnZSA9IG1ha2VNZXNzYWdlKDQ0NiksXG4gICAgICAgICAgICAgICAgICAgIGVuY3J5cHRlZCA9IGF3YWl0IFNlY3VyaXR5LmVuY3J5cHQobWVzc2FnZSwgb3RoZXJPd25lZFRhZyksXG4gICAgICAgICAgICAgICAgICAgIGVycm9yTWVzc2FnZSA9IGF3YWl0IFNlY3VyaXR5LmRlY3J5cHQoZW5jcnlwdGVkLCB7dGFnczogW3RhZ10sIC4uLm9wdGlvbnN9KS5jYXRjaChlID0+IGUubWVzc2FnZSk7XG4gICAgICAgICAgICAgICAgZXhwZWN0KGVycm9yTWVzc2FnZS50b0xvd2VyQ2FzZSgpKS50b0NvbnRhaW4oJ29wZXJhdGlvbicpO1xuICAgICAgICAgICAgICAgIC8vIFNvbWUgYnJvd3NlcnMgc3VwcGx5IGEgZ2VuZXJpYyBtZXNzYWdlLCBzdWNoIGFzICdUaGUgb3BlcmF0aW9uIGZhaWxlZCBmb3IgYW4gb3BlcmF0aW9uLXNwZWNpZmljIHJlYXNvbidcbiAgICAgICAgICAgICAgICAvLyBJRiB0aGVyZSdzIG5vIG1lc3NhZ2UgYXQgYWxsLCBvdXIganNvbnJwYyBzdXBwbGllcyBvbmUgd2l0aCB0aGUganNvbnJwYyAnbWV0aG9kJyBuYW1lLlxuICAgICAgICAgICAgICAgIC8vZXhwZWN0KGVycm9yTWVzc2FnZSkudG9Db250YWluKCdkZWNyeXB0Jyk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICBpdCgnaGFuZGxlcyBiaW5hcnksIGFuZCBkZWNyeXB0cyBhcyBzYW1lLicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBsZXQgbWVzc2FnZSA9IG5ldyBVaW50OEFycmF5KFsyMSwgMzFdKSxcbiAgICAgICAgICAgICAgICAgICAgZW5jcnlwdGVkID0gYXdhaXQgU2VjdXJpdHkuZW5jcnlwdChtZXNzYWdlLCB0YWcpLFxuICAgICAgICAgICAgICAgICAgICBkZWNyeXB0ZWQgPSBhd2FpdCBTZWN1cml0eS5kZWNyeXB0KGVuY3J5cHRlZCwge3RhZ3M6IFt0YWddLCAuLi5vcHRpb25zfSksXG4gICAgICAgICAgICAgICAgICAgIGhlYWRlciA9IEtyeXB0by5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIoZW5jcnlwdGVkKTtcbiAgICAgICAgICAgICAgICBleHBlY3QoaGVhZGVyLmN0eSkudG9CZVVuZGVmaW5lZCgpO1xuICAgICAgICAgICAgICAgIHNhbWVUeXBlZEFycmF5KGRlY3J5cHRlZCwgbWVzc2FnZSk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICBpdCgnaGFuZGxlcyB0ZXh0LCBhbmQgZGVjcnlwdHMgYXMgc2FtZS4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgbGV0IGVuY3J5cHRlZCA9IGF3YWl0IFNlY3VyaXR5LmVuY3J5cHQobWVzc2FnZSwgdGFnKSxcbiAgICAgICAgICAgICAgICAgICAgZGVjcnlwdGVkID0gYXdhaXQgU2VjdXJpdHkuZGVjcnlwdChlbmNyeXB0ZWQsIHt0YWdzOiBbdGFnXSwgLi4ub3B0aW9uc30pLFxuICAgICAgICAgICAgICAgICAgICBoZWFkZXIgPSBLcnlwdG8uZGVjb2RlUHJvdGVjdGVkSGVhZGVyKGVuY3J5cHRlZCk7XG4gICAgICAgICAgICAgICAgZXhwZWN0KGhlYWRlci5jdHkpLnRvQmUoJ3RleHQvcGxhaW4nKTtcbiAgICAgICAgICAgICAgICBleHBlY3QoZGVjcnlwdGVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICBpdCgnaGFuZGxlcyBqc29uLCBhbmQgZGVjcnlwdHMgYXMgc2FtZS4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgbGV0IG1lc3NhZ2UgPSB7Zm9vOiAnYmFyJ30sXG4gICAgICAgICAgICAgICAgICAgIGVuY3J5cHRlZCA9IGF3YWl0IFNlY3VyaXR5LmVuY3J5cHQobWVzc2FnZSwgdGFnKSxcbiAgICAgICAgICAgICAgICAgICAgZGVjcnlwdGVkID0gYXdhaXQgU2VjdXJpdHkuZGVjcnlwdChlbmNyeXB0ZWQsIHt0YWdzOiBbdGFnXSwgLi4ub3B0aW9uc30pLFxuICAgICAgICAgICAgICAgICAgICBoZWFkZXIgPSBLcnlwdG8uZGVjb2RlUHJvdGVjdGVkSGVhZGVyKGVuY3J5cHRlZCk7XG4gICAgICAgICAgICAgICAgZXhwZWN0KGhlYWRlci5jdHkpLnRvQmUoJ2pzb24nKTtcbiAgICAgICAgICAgICAgICBleHBlY3QoZGVjcnlwdGVkLmpzb24pLnRvRXF1YWwobWVzc2FnZSk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICBpdCgndXNlcyBjb250ZW50VHlwZSBhbmQgdGltZSBpZiBzdXBwbGllZC4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgbGV0IGNvbnRlbnRUeXBlID0gJ3RleHQvaHRtbCcsXG4gICAgICAgICAgICAgICAgICAgIHRpbWUgPSBEYXRlLm5vdygpLFxuICAgICAgICAgICAgICAgICAgICBtZXNzYWdlID0gXCI8c29tZXRoaW5nIGVsc2U+XCIsXG4gICAgICAgICAgICAgICAgICAgIGVuY3J5cHRlZCA9IGF3YWl0IFNlY3VyaXR5LmVuY3J5cHQobWVzc2FnZSwge3RhZ3M6IFt0YWddLCBjb250ZW50VHlwZSwgdGltZX0pLFxuICAgICAgICAgICAgICAgICAgICBkZWNyeXB0ZWQgPSBhd2FpdCBTZWN1cml0eS5kZWNyeXB0KGVuY3J5cHRlZCwge3RhZ3M6IFt0YWddLCAuLi5vcHRpb25zfSksXG4gICAgICAgICAgICAgICAgICAgIGhlYWRlciA9IEtyeXB0by5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIoZW5jcnlwdGVkKTtcbiAgICAgICAgICAgICAgICBleHBlY3QoaGVhZGVyLmN0eSkudG9CZShjb250ZW50VHlwZSk7XG4gICAgICAgICAgICAgICAgZXhwZWN0KGhlYWRlci5pYXQpLnRvQmUodGltZSk7XG4gICAgICAgICAgICAgICAgZXhwZWN0KGRlY3J5cHRlZC50ZXh0KS50b0JlKG1lc3NhZ2UpO1xuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgZGVzY3JpYmUoJ3dpdGggbXVsdGlwbGUgdGFncycsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgaXQoJ2NhbiBiZSBkZWNyeXB0ZWQgYnkgYW55IG9uZSBvZiB0aGVtLicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBsZXQgZW5jcnlwdGVkID0gYXdhaXQgU2VjdXJpdHkuZW5jcnlwdChtZXNzYWdlLCB0YWcsIG90aGVyT3duZWRUYWcpLFxuICAgICAgICAgICAgICAgICAgICBkZWNyeXB0ZWQxID0gYXdhaXQgU2VjdXJpdHkuZGVjcnlwdChlbmNyeXB0ZWQsIHt0YWdzOiBbdGFnXSwgLi4ub3B0aW9uc30pLFxuICAgICAgICAgICAgICAgICAgICBkZWNyeXB0ZWQyID0gYXdhaXQgU2VjdXJpdHkuZGVjcnlwdChlbmNyeXB0ZWQsIHt0YWdzOiBbb3RoZXJPd25lZFRhZ10sIC4uLm9wdGlvbnN9KTtcbiAgICAgICAgICAgICAgICBleHBlY3QoZGVjcnlwdGVkMS50ZXh0KS50b0JlKG1lc3NhZ2UpO1xuICAgICAgICAgICAgICAgIGV4cGVjdChkZWNyeXB0ZWQyLnRleHQpLnRvQmUobWVzc2FnZSk7ICAgICAgICBcbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgIGl0KCdjYW4gYmUgZGVjcnlwdGVkIHVzaW5nIHRoZSB0YWcgaW5jbHVkZWQgaW4gdGhlIGVuY3J5cHRpb24uJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIGxldCBlbmNyeXB0ZWQgPSBhd2FpdCBTZWN1cml0eS5lbmNyeXB0KG1lc3NhZ2UsIHRhZywgb3RoZXJPd25lZFRhZyksXG4gICAgICAgICAgICAgICAgICAgIGRlY3J5cHRlZCA9IGF3YWl0IFNlY3VyaXR5LmRlY3J5cHQoZW5jcnlwdGVkLCBvcHRpb25zKTtcbiAgICAgICAgICAgICAgICBleHBlY3QoZGVjcnlwdGVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICBpdCgnY2FuIGJlIGJlIG1hZGUgd2l0aCB0YWdzIHlvdSBkbyBub3Qgb3duLicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBsZXQgZW5jcnlwdGVkID0gYXdhaXQgU2VjdXJpdHkuZW5jcnlwdChtZXNzYWdlLCB0YWcsIHRhZ3NbdW5vd25lZFRhZ05hbWVdLCBvdGhlck93bmVkVGFnKSxcbiAgICAgICAgICAgICAgICAgICAgZGVjcnlwdGVkMSA9IGF3YWl0IFNlY3VyaXR5LmRlY3J5cHQoZW5jcnlwdGVkLCB7dGFnczogW3RhZ10sIC4uLm9wdGlvbnN9KSxcbiAgICAgICAgICAgICAgICAgICAgZGVjcnlwdGVkMiA9IGF3YWl0IFNlY3VyaXR5LmRlY3J5cHQoZW5jcnlwdGVkLCB7dGFnczogW290aGVyT3duZWRUYWddLCAuLi5vcHRpb25zfSk7XG4gICAgICAgICAgICAgICAgZXhwZWN0KGRlY3J5cHRlZDEudGV4dCkudG9CZShtZXNzYWdlKTtcbiAgICAgICAgICAgICAgICBleHBlY3QoZGVjcnlwdGVkMi50ZXh0KS50b0JlKG1lc3NhZ2UpOyAgICAgICAgXG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICBpdCgnY2Fubm90IGJlIGRlY3J5cHRlZCBieSBhIGRpZmZlcmVudCB0YWcuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIGxldCBlbmNyeXB0ZWQgPSBhd2FpdCBTZWN1cml0eS5lbmNyeXB0KG1lc3NhZ2UsIHRhZywgdGFnc1t1bm93bmVkVGFnTmFtZV0pLFxuICAgICAgICAgICAgICAgICAgICBkZWNyeXB0ZWQgPSBhd2FpdCBTZWN1cml0eS5kZWNyeXB0KGVuY3J5cHRlZCwge3RhZ3M6IFtvdGhlck93bmVkVGFnXSwgLi4ub3B0aW9uc30pO1xuICAgICAgICAgICAgICAgIGV4cGVjdChkZWNyeXB0ZWQpLnRvQmVVbmRlZmluZWQoKTtcbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgIGl0KCdzcGVjaWZpZXMga2lkIGluIGVhY2ggcmVjaXBpZW50LicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBsZXQgZW5jcnlwdGVkID0gYXdhaXQgU2VjdXJpdHkuZW5jcnlwdChtZXNzYWdlLCB0YWcsIG90aGVyT3duZWRUYWcpLFxuICAgICAgICAgICAgICAgICAgICByZWNpcGllbnRzID0gZW5jcnlwdGVkLnJlY2lwaWVudHM7XG4gICAgICAgICAgICAgICAgZXhwZWN0KHJlY2lwaWVudHMubGVuZ3RoKS50b0JlKDIpO1xuICAgICAgICAgICAgICAgIGV4cGVjdChyZWNpcGllbnRzWzBdLmhlYWRlci5raWQpLnRvQmUodGFnKTtcbiAgICAgICAgICAgICAgICBleHBlY3QocmVjaXBpZW50c1sxXS5oZWFkZXIua2lkKS50b0JlKG90aGVyT3duZWRUYWcpO1xuICAgICAgICAgICAgICB9KTtcblxuICAgICAgICAgICAgICBpdCgnaGFuZGxlcyBiaW5hcnksIGFuZCBkZWNyeXB0cyBhcyBzYW1lLicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBsZXQgbWVzc2FnZSA9IG5ldyBVaW50OEFycmF5KFsyMSwgMzFdKSxcbiAgICAgICAgICAgICAgICAgICAgZW5jcnlwdGVkID0gYXdhaXQgU2VjdXJpdHkuZW5jcnlwdChtZXNzYWdlLCB0YWcsIG90aGVyT3duZWRUYWcpLFxuICAgICAgICAgICAgICAgICAgICBkZWNyeXB0ZWQgPSBhd2FpdCBTZWN1cml0eS5kZWNyeXB0KGVuY3J5cHRlZCwge3RhZ3M6IFt0YWddLCAuLi5vcHRpb25zfSksXG4gICAgICAgICAgICAgICAgICAgIGhlYWRlciA9IEtyeXB0by5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIoZW5jcnlwdGVkKTtcbiAgICAgICAgICAgICAgICBleHBlY3QoaGVhZGVyLmN0eSkudG9CZVVuZGVmaW5lZCgpO1xuICAgICAgICAgICAgICAgIHNhbWVUeXBlZEFycmF5KGRlY3J5cHRlZCwgbWVzc2FnZSk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICBpdCgnaGFuZGxlcyB0ZXh0LCBhbmQgZGVjcnlwdHMgYXMgc2FtZS4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgbGV0IGVuY3J5cHRlZCA9IGF3YWl0IFNlY3VyaXR5LmVuY3J5cHQobWVzc2FnZSwgdGFnLCBvdGhlck93bmVkVGFnKSxcbiAgICAgICAgICAgICAgICAgICAgZGVjcnlwdGVkID0gYXdhaXQgU2VjdXJpdHkuZGVjcnlwdChlbmNyeXB0ZWQsIHt0YWdzOiBbdGFnXSwgLi4ub3B0aW9uc30pLFxuICAgICAgICAgICAgICAgICAgICBoZWFkZXIgPSBLcnlwdG8uZGVjb2RlUHJvdGVjdGVkSGVhZGVyKGVuY3J5cHRlZCk7XG4gICAgICAgICAgICAgICAgZXhwZWN0KGhlYWRlci5jdHkpLnRvQmUoJ3RleHQvcGxhaW4nKTtcbiAgICAgICAgICAgICAgICBleHBlY3QoZGVjcnlwdGVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICBpdCgnaGFuZGxlcyBqc29uLCBhbmQgZGVjcnlwdHMgYXMgc2FtZS4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgbGV0IG1lc3NhZ2UgPSB7Zm9vOiAnYmFyJ30sXG4gICAgICAgICAgICAgICAgICAgIGVuY3J5cHRlZCA9IGF3YWl0IFNlY3VyaXR5LmVuY3J5cHQobWVzc2FnZSwgdGFnLCBvdGhlck93bmVkVGFnKSxcbiAgICAgICAgICAgICAgICAgICAgZGVjcnlwdGVkID0gYXdhaXQgU2VjdXJpdHkuZGVjcnlwdChlbmNyeXB0ZWQsIHt0YWdzOiBbdGFnXSwgLi4ub3B0aW9uc30pLFxuICAgICAgICAgICAgICAgICAgICBoZWFkZXIgPSBLcnlwdG8uZGVjb2RlUHJvdGVjdGVkSGVhZGVyKGVuY3J5cHRlZCk7XG4gICAgICAgICAgICAgICAgZXhwZWN0KGhlYWRlci5jdHkpLnRvQmUoJ2pzb24nKTtcbiAgICAgICAgICAgICAgICBleHBlY3QoZGVjcnlwdGVkLmpzb24pLnRvRXF1YWwobWVzc2FnZSk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICBpdCgndXNlcyBjb250ZW50VHlwZSBhbmQgdGltZSBpZiBzdXBwbGllZC4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgbGV0IGNvbnRlbnRUeXBlID0gJ3RleHQvaHRtbCcsXG4gICAgICAgICAgICAgICAgICAgIHRpbWUgPSBEYXRlLm5vdygpLFxuICAgICAgICAgICAgICAgICAgICBtZXNzYWdlID0gXCI8c29tZXRoaW5nIGVsc2U+XCIsXG4gICAgICAgICAgICAgICAgICAgIGVuY3J5cHRlZCA9IGF3YWl0IFNlY3VyaXR5LmVuY3J5cHQobWVzc2FnZSwge3RhZ3M6IFt0YWcsIG90aGVyT3duZWRUYWddLCBjb250ZW50VHlwZSwgdGltZX0pLFxuICAgICAgICAgICAgICAgICAgICBkZWNyeXB0ZWQgPSBhd2FpdCBTZWN1cml0eS5kZWNyeXB0KGVuY3J5cHRlZCwge3RhZ3M6IFt0YWddLCAuLi5vcHRpb25zfSksXG4gICAgICAgICAgICAgICAgICAgIGhlYWRlciA9IEtyeXB0by5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIoZW5jcnlwdGVkKVxuICAgICAgICAgICAgICAgIGV4cGVjdChoZWFkZXIuY3R5KS50b0JlKGNvbnRlbnRUeXBlKTtcbiAgICAgICAgICAgICAgICBleHBlY3QoaGVhZGVyLmlhdCkudG9CZSh0aW1lKTtcbiAgICAgICAgICAgICAgICBleHBlY3QoZGVjcnlwdGVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgICAgdGVzdCgnRGV2aWNlS2V5U2V0JywgJ2RldmljZScsICd1c2VyJywgJ290aGVyRGV2aWNlJyk7IC8vIFdlIG93biB1c2VyLCBidXQgaXQgaXNuJ3QgdGhlIHNhbWUgYXMgZGV2aWNlLlxuICAgICAgdGVzdCgnUmVjb3ZlcnlLZXlTZXQnLCAncmVjb3ZlcnknLCAnb3RoZXJSZWNvdmVyeScsICdvdGhlckRldmljZScsIHtyZWNvdmVyeTp0cnVlfSk7IC8vIHNpZ24vZGVjcnlwdCBpcyBub3Qgbm9ybWFsbHkgZG9uZSB3aXRoIHJlY292ZXJ5IGtleXMsIGJ1dCB3ZSBjYW4gZm9yY2UgaXQuXG4gICAgICB0ZXN0KCdVc2VyIFRlYW1LZXlTZXQnLCAndXNlcicsICdkZXZpY2UnLCAnb3RoZXJVc2VyJyk7IC8vIFdlIG93bmQgZGV2aWNlLCBidXQgaXQgaXNuJ3QgdGhlIHNhbWUgYXMgdXNlci5cbiAgICAgIHRlc3QoJ1RlYW0gVGVhbUtleVNldCcsICd0ZWFtJywgJ290aGVyVGVhbScsICdvdGhlclVzZXInKTtcbiAgICAgIGRlc2NyaWJlKCdzdG9yYWdlJywgZnVuY3Rpb24gKCkge1xuICAgICAgICBpdCgnd2lsbCBvbmx5IGxldCBhIGN1cnJlbnQgbWVtYmVyIHdyaXRlIG5ldyBrZXlzLicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBsZXQgdGVzdE1lbWJlciA9IGF3YWl0IFNlY3VyaXR5LmNyZWF0ZSgpLFxuICAgICAgICAgICAgICB0ZWFtID0gdGFncy50ZWFtLFxuICAgICAgICAgICAgICBjdXJyZW50RW5jcnlwdGVkU2lnbmF0dXJlID0gYXdhaXQgU3RvcmFnZS5yZXRyaWV2ZSgnVGVhbScsIHRlYW0pLFxuICAgICAgICAgICAgICBjdXJyZW50RW5jcnlwdGVkS2V5ID0gKGF3YWl0IFNlY3VyaXR5LnZlcmlmeShjdXJyZW50RW5jcnlwdGVkU2lnbmF0dXJlKSkuanNvbjtcbiAgICAgICAgICBmdW5jdGlvbiBzaWduSXQoKSB7XG4gICAgICAgICAgICByZXR1cm4gU2VjdXJpdHkuc2lnbihjdXJyZW50RW5jcnlwdGVkS2V5LCB7dGVhbSwgbWVtYmVyOiB0ZXN0TWVtYmVyLCB0aW1lOiBEYXRlLm5vdygpfSlcbiAgICAgICAgICB9XG4gICAgICAgICAgYXdhaXQgU2VjdXJpdHkuY2hhbmdlTWVtYmVyc2hpcCh7dGFnOiB0ZWFtLCBhZGQ6IFt0ZXN0TWVtYmVyXX0pO1xuICAgICAgICAgIGxldCBzaWduYXR1cmVXaGlsZU1lbWJlciA9IGF3YWl0IHNpZ25JdCgpO1xuICAgICAgICAgIGV4cGVjdChhd2FpdCBTdG9yYWdlLnN0b3JlKCdUZWFtJywgdGFncy50ZWFtLCBzaWduYXR1cmVXaGlsZU1lbWJlcikpLnRvQmVEZWZpbmVkKCk7IC8vIFRoYXQncyBmaW5lXG4gICAgICAgICAgYXdhaXQgU2VjdXJpdHkuY2hhbmdlTWVtYmVyc2hpcCh7dGFnOiB0ZWFtLCByZW1vdmU6IFt0ZXN0TWVtYmVyXX0pO1xuICAgICAgICAgIGxldCBzaWduYXR1cmVXaGlsZU5vdEFNZW1iZXIgPSBhd2FpdCBzaWduSXQoKTtcbiAgICAgICAgICBleHBlY3QoYXdhaXQgU3RvcmFnZS5zdG9yZSgnVGVhbScsIHRlYW0sIHNpZ25hdHVyZVdoaWxlTm90QU1lbWJlcikuY2F0Y2goKCkgPT4gJ2ZhaWxlZCcpKS50b0JlKCdmYWlsZWQnKTsgLy8gVmFsaWQgc2lnbmF0dXJlIGJ5IGFuIGltcHJvcGVyIHRhZy5cbiAgICAgICAgICBleHBlY3QoYXdhaXQgU3RvcmFnZS5zdG9yZSgnVGVhbScsIHRlYW0sIHNpZ25hdHVyZVdoaWxlTWVtYmVyKS5jYXRjaCgoKSA9PiAnZmFpbGVkJykpLnRvQmUoJ2ZhaWxlZCcpOyAvLyBDYW4ndCByZXBsYXkgc2lnIHdoaWxlIG1lbWJlci5cbiAgICAgICAgICBleHBlY3QoYXdhaXQgU3RvcmFnZS5zdG9yZSgnVGVhbScsIHRlYW0sIGN1cnJlbnRFbmNyeXB0ZWRTaWduYXR1cmUpLmNhdGNoKCgpID0+ICdmYWlsZWQnKSkudG9CZSgnZmFpbGVkJyk7IC8vIENhbid0IHJlcGxheSBleGFjdCBwcmV2aW91cyBzaWcgZWl0aGVyLlxuICAgICAgICAgIGF3YWl0IFNlY3VyaXR5LmRlc3Ryb3kodGVzdE1lbWJlcik7XG4gICAgICAgIH0pO1xuICAgICAgICBpdCgnd2lsbCBvbmx5IGxldCBhIGN1cnJlbnQgbWVtYmVyIHdyaXRlIG5ldyBwdWJsaWMgZW5jcnlwdGlvbiBrZXkuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGxldCB0ZXN0TWVtYmVyID0gYXdhaXQgU2VjdXJpdHkuY3JlYXRlKCksXG4gICAgICAgICAgICAgIHRlYW0gPSB0YWdzLnRlYW0sXG4gICAgICAgICAgICAgIGN1cnJlbnRTaWduYXR1cmUgPSBhd2FpdCBTdG9yYWdlLnJldHJpZXZlKCdFbmNyeXB0aW9uS2V5JywgdGVhbSksXG4gICAgICAgICAgICAgIGN1cnJlbnRLZXkgPSAoYXdhaXQgU2VjdXJpdHkudmVyaWZ5KGN1cnJlbnRTaWduYXR1cmUpKS5qc29uO1xuICAgICAgICAgIGZ1bmN0aW9uIHNpZ25JdCgpIHtcbiAgICAgICAgICAgIHJldHVybiBTZWN1cml0eS5zaWduKGN1cnJlbnRLZXksIHt0ZWFtLCBtZW1iZXI6IHRlc3RNZW1iZXIsIHRpbWU6IERhdGUubm93KCl9KVxuICAgICAgICAgIH1cbiAgICAgICAgICBhd2FpdCBTZWN1cml0eS5jaGFuZ2VNZW1iZXJzaGlwKHt0YWc6IHRlYW0sIGFkZDogW3Rlc3RNZW1iZXJdfSk7XG4gICAgICAgICAgbGV0IHNpZ25hdHVyZVdoaWxlTWVtYmVyID0gYXdhaXQgc2lnbkl0KCk7XG4gICAgICAgICAgZXhwZWN0KGF3YWl0IFN0b3JhZ2Uuc3RvcmUoJ0VuY3J5cHRpb25LZXknLCB0YWdzLnRlYW0sIHNpZ25hdHVyZVdoaWxlTWVtYmVyKSkudG9CZURlZmluZWQoKTsgLy8gVGhhdCdzIGZpbmVcbiAgICAgICAgICBhd2FpdCBTZWN1cml0eS5jaGFuZ2VNZW1iZXJzaGlwKHt0YWc6IHRlYW0sIHJlbW92ZTogW3Rlc3RNZW1iZXJdfSk7XG4gICAgICAgICAgbGV0IHNpZ25hdHVyZVdoaWxlTm90QU1lbWJlciA9IGF3YWl0IHNpZ25JdCgpO1xuICAgICAgICAgIGV4cGVjdChhd2FpdCBTdG9yYWdlLnN0b3JlKCdFbmNyeXB0aW9uS2V5JywgdGVhbSwgc2lnbmF0dXJlV2hpbGVOb3RBTWVtYmVyKS5jYXRjaCgoKSA9PiAnZmFpbGVkJykpLnRvQmUoJ2ZhaWxlZCcpOyAvLyBWYWxpZCBzaWduYXR1cmUgYnkgYW4gaW1wcm9wZXIgdGFnLlxuICAgICAgICAgIGV4cGVjdChhd2FpdCBTdG9yYWdlLnN0b3JlKCdFbmNyeXB0aW9uS2V5JywgdGVhbSwgc2lnbmF0dXJlV2hpbGVNZW1iZXIpLmNhdGNoKCgpID0+ICdmYWlsZWQnKSkudG9CZSgnZmFpbGVkJyk7IC8vIENhbid0IHJlcGxheSBzaWcgd2hpbGUgbWVtYmVyLlxuICAgICAgICAgIGV4cGVjdChhd2FpdCBTdG9yYWdlLnN0b3JlKCdFbmNyeXB0aW9uS2V5JywgdGVhbSwgY3VycmVudFNpZ25hdHVyZSkuY2F0Y2goKCkgPT4gJ2ZhaWxlZCcpKS50b0JlKCdmYWlsZWQnKTsgLy8gQ2FuJ3QgcmVwbGF5IGV4YWN0IHByZXZpb3VzIHNpZyBlaXRoZXIuXG4gICAgICAgICAgYXdhaXQgU2VjdXJpdHkuZGVzdHJveSh0ZXN0TWVtYmVyKTtcbiAgICAgICAgfSwgMTBlMyk7XG4gICAgICAgIGl0KCd3aWxsIG9ubHkgbGV0IG93bmVyIG9mIGEgZGV2aWNlIHdyaXRlIG5ldyBwdWJsaWMgZGV2aWNlIGVuY3J5cHRpb24ga2V5LicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBsZXQgdGVzdERldmljZSA9IGF3YWl0IFNlY3VyaXR5LmNyZWF0ZSgpLFxuICAgICAgICAgICAgICBhbm90aGVyRGV2aWNlID0gYXdhaXQgU2VjdXJpdHkuY3JlYXRlKCksXG4gICAgICAgICAgICAgIGN1cnJlbnRTaWduYXR1cmUgPSBhd2FpdCBTdG9yYWdlLnJldHJpZXZlKCdFbmNyeXB0aW9uS2V5JywgdGVzdERldmljZSksXG4gICAgICAgICAgICAgIGN1cnJlbnRLZXkgPSAoYXdhaXQgU2VjdXJpdHkudmVyaWZ5KGN1cnJlbnRTaWduYXR1cmUpKS5qc29uO1xuICAgICAgICAgIGZ1bmN0aW9uIHNpZ25JdCh0YWcpIHtcbiAgICAgICAgICAgIHJldHVybiBTZWN1cml0eS5zaWduKGN1cnJlbnRLZXksIHt0YWdzOiBbdGFnXSwgdGltZTogRGF0ZS5ub3coKX0pXG4gICAgICAgICAgfVxuICAgICAgICAgIGxldCBzaWduYXR1cmVPZk93bmVyID0gYXdhaXQgc2lnbkl0KHRlc3REZXZpY2UpO1xuICAgICAgICAgIGV4cGVjdChhd2FpdCBTdG9yYWdlLnN0b3JlKCdFbmNyeXB0aW9uS2V5JywgdGVzdERldmljZSwgc2lnbmF0dXJlT2ZPd25lcikpLnRvQmVEZWZpbmVkKCk7IC8vIFRoYXQncyBmaW5lXG4gICAgICAgICAgbGV0IHNpZ25hdHVyZU9mQW5vdGhlciA9IGF3YWl0IHNpZ25JdChhbm90aGVyRGV2aWNlKTtcbiAgICAgICAgICBleHBlY3QoYXdhaXQgU3RvcmFnZS5zdG9yZSgnRW5jcnlwdGlvbktleScsIHRlc3REZXZpY2UsIHNpZ25hdHVyZU9mQW5vdGhlcikuY2F0Y2goKCkgPT4gJ2ZhaWxlZCcpKS50b0JlKCdmYWlsZWQnKTsgLy8gVmFsaWQgc2lnbmF0dXJlIGJ5IGFuIGltcHJvcGVyIHRhZy5cbiAgICAgICAgICAvLyBEZXZpY2Ugb3duZXIgY2FuIHJlc3RvcmUuICBUaGlzIGlzIHN1YnRsZTpcbiAgICAgICAgICAvLyBUaGVyZSBpcyBubyB0ZWFtIGtleSBpbiB0aGUgY2xvdWQgdG8gY29tcGFyZSB0aGUgdGltZSB3aXRoLiBXZSBkbyBjb21wYXJlIGFnYWluc3QgdGhlIGN1cnJlbnQgdmFsdWUgKGFzIHNob3duIGJlbG93KSxcbiAgICAgICAgICAvLyBidXQgd2UgZG8gbm90IHByb2hpYml0IHRoZSBzYW1lIHRpbWVzdGFtcCBmcm9tIGJlaW5nIHJldXNlZC5cbiAgICAgICAgICBleHBlY3QoYXdhaXQgU3RvcmFnZS5zdG9yZSgnRW5jcnlwdGlvbktleScsIHRlc3REZXZpY2UsIHNpZ25hdHVyZU9mT3duZXIpKS50b0JlRGVmaW5lZDtcbiAgICAgICAgICBleHBlY3QoYXdhaXQgU3RvcmFnZS5zdG9yZSgnRW5jcnlwdGlvbktleScsIHRlc3REZXZpY2UsIGN1cnJlbnRTaWduYXR1cmUpLmNhdGNoKCgpID0+ICdmYWlsZWQnKSkudG9CZSgnZmFpbGVkJyk7IC8vIENhbid0IHJlcGxheSBleGFjdCBwcmV2aW91cyBzaWcuXG4gICAgICAgICAgYXdhaXQgU2VjdXJpdHkuZGVzdHJveSh0ZXN0RGV2aWNlKTtcbiAgICAgICAgICBhd2FpdCBTZWN1cml0eS5kZXN0cm95KGFub3RoZXJEZXZpY2UpO1xuICAgICAgICB9LCAxMGUzKTtcbiAgICAgIH0pO1xuICAgICAgZGVzY3JpYmUoJ2F1ZGl0YWJsZSBzaWduYXR1cmVzJywgZnVuY3Rpb24gKCkge1xuICAgICAgICBkZXNjcmliZSgnYnkgYW4gZXhwbGljaXQgbWVtYmVyJywgZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGxldCBzaWduYXR1cmUsIHZlcmlmaWNhdGlvbjtcbiAgICAgICAgICBiZWZvcmVBbGwoYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgc2lnbmF0dXJlID0gYXdhaXQgU2VjdXJpdHkuc2lnbihtZXNzYWdlLCB7dGVhbTogdGFncy50ZWFtLCBtZW1iZXI6IHRhZ3MudXNlcn0pO1xuICAgICAgICAgICAgdmVyaWZpY2F0aW9uID0gYXdhaXQgU2VjdXJpdHkudmVyaWZ5KHNpZ25hdHVyZSwgdGFncy50ZWFtLCB0YWdzLnVzZXIpO1xuICAgICAgICAgIH0pO1xuICAgICAgICAgIGl0KCdyZWNvZ25pemVzIGEgdGVhbSB3aXRoIGEgbWVtYmVyLicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIGV4cGVjdCh2ZXJpZmljYXRpb24pLnRvQmVUcnV0aHkoKTtcbiAgICAgICAgICAgIGV4cGVjdCh2ZXJpZmljYXRpb24udGV4dCkudG9CZShtZXNzYWdlKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgICBpdCgnZGVmaW5lcyBpc3MuJywgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWNhdGlvbi5wcm90ZWN0ZWRIZWFkZXIuaXNzKS50b0JlKHRhZ3MudGVhbSk7XG4gICAgICAgICAgfSk7XG4gICAgICAgICAgaXQoJ2RlZmluZXMgYWN0LicsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIGV4cGVjdCh2ZXJpZmljYXRpb24ucHJvdGVjdGVkSGVhZGVyLmFjdCkudG9CZSh0YWdzLnVzZXIpO1xuICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICAgICAgZGVzY3JpYmUoJ2F1dG9tYXRpY2FsbHkgc3VwcGxpZXMgYSB2YWxpZCBtZW1iZXInLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgaXQoJ2lmIHlvdSBoYXZlIGFjY2VzcycsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIGxldCBzaWduYXR1cmUgPSBhd2FpdCBTZWN1cml0eS5zaWduKG1lc3NhZ2UsIHt0ZWFtOiB0YWdzLnRlYW19KSxcbiAgICAgICAgICAgICAgICBtZW1iZXIgPSBLcnlwdG8uZGVjb2RlUHJvdGVjdGVkSGVhZGVyKHNpZ25hdHVyZS5zaWduYXR1cmVzWzBdKS5hY3QsXG4gICAgICAgICAgICAgICAgdmVyaWZpY2F0aW9uID0gYXdhaXQgU2VjdXJpdHkudmVyaWZ5KHNpZ25hdHVyZSwgdGFncy50ZWFtLCBtZW1iZXIpO1xuICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWNhdGlvbikudG9CZVRydXRoeSgpO1xuICAgICAgICAgICAgZXhwZWN0KG1lbWJlcikudG9CZVRydXRoeSgpO1xuICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWNhdGlvbi5wcm90ZWN0ZWRIZWFkZXIuYWN0KS50b0JlKG1lbWJlcik7XG4gICAgICAgICAgICBleHBlY3QodmVyaWZpY2F0aW9uLnByb3RlY3RlZEhlYWRlci5pYXQpLnRvQmVUcnV0aHkoKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgfSk7XG4gICAgICAgIGRlc2NyaWJlKCd3aXRoIGEgdmFsaWQgdXNlciB3aG8gaXMgbm90IGEgbWVtYmVyJywgZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGxldCBub25NZW1iZXI7XG4gICAgICAgICAgYmVmb3JlQWxsKGFzeW5jIGZ1bmN0aW9uICgpIHsgbm9uTWVtYmVyID0gYXdhaXQgU2VjdXJpdHkuY3JlYXRlKHRhZ3MuZGV2aWNlKTsgfSk7XG4gICAgICAgICAgYWZ0ZXJBbGwoYXN5bmMgZnVuY3Rpb24gKCkgeyBhd2FpdCBTZWN1cml0eS5kZXN0cm95KG5vbk1lbWJlcik7IH0pO1xuICAgICAgICAgIGl0KCd2ZXJpZmllcyBhcyBhbiBvcmRpbmFyeSBkdWFsIHNpZ25hdHVyZS4nLCBhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBsZXQgc2lnbmF0dXJlID0gYXdhaXQgU2VjdXJpdHkuc2lnbihtZXNzYWdlLCB0YWdzLnRlYW0sIG5vbk1lbWJlciksXG4gICAgICAgICAgICAgICAgdmVyaWZpY2F0aW9uID0gYXdhaXQgU2VjdXJpdHkudmVyaWZ5KHNpZ25hdHVyZSwgdGFncy50ZWFtLCBub25NZW1iZXIpO1xuICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWNhdGlvbi50ZXh0KS50b0JlKG1lc3NhZ2UpO1xuICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWNhdGlvbi5wcm90ZWN0ZWRIZWFkZXIuaXNzKS50b0JlVW5kZWZpbmVkKCk7XG4gICAgICAgICAgICBleHBlY3QodmVyaWZpY2F0aW9uLnByb3RlY3RlZEhlYWRlci5hY3QpLnRvQmVVbmRlZmluZWQoKTtcbiAgICAgICAgICB9LCAxMGUzKTtcbiAgICAgICAgICBpdCgnZG9lcyBub3QgdmVyaWZ5IGFzIGEgZHVhbCBzaWduYXR1cmUgc3BlY2lmeWluZyB0ZWFtIGFuZCBtZW1iZXIuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgbGV0IHNpZ25hdHVyZSA9IGF3YWl0IFNlY3VyaXR5LnNpZ24obWVzc2FnZSwge3RlYW06IHRhZ3MudGVhbSwgbWVtYmVyOiBub25NZW1iZXJ9KSxcbiAgICAgICAgICAgICAgICB2ZXJpZmljYXRpb24gPSBhd2FpdCBTZWN1cml0eS52ZXJpZnkoc2lnbmF0dXJlLCB0YWdzLnRlYW0sIG5vbk1lbWJlcik7XG4gICAgICAgICAgICBleHBlY3QodmVyaWZpY2F0aW9uKS50b0JlVW5kZWZpbmVkKCk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIH0sIDEwZTMpO1xuICAgICAgICBkZXNjcmliZSgnd2l0aCBhIHBhc3QgbWVtYmVyJywgZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGxldCBtZW1iZXIsIHNpZ25hdHVyZSwgdGltZTtcbiAgICAgICAgICBiZWZvcmVBbGwoYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgdGltZSA9IERhdGUubm93KCkgLSAxO1xuICAgICAgICAgICAgbWVtYmVyID0gYXdhaXQgU2VjdXJpdHkuY3JlYXRlKCk7XG4gICAgICAgICAgICBhd2FpdCBTZWN1cml0eS5jaGFuZ2VNZW1iZXJzaGlwKHt0YWc6IHRhZ3MudGVhbSwgYWRkOiBbbWVtYmVyXX0pO1xuICAgICAgICAgICAgc2lnbmF0dXJlID0gYXdhaXQgU2VjdXJpdHkuc2lnbihcIm1lc3NhZ2VcIiwge3RlYW06IHRhZ3MudGVhbSwgbWVtYmVyLCB0aW1lfSk7IC8vIHdoaWxlIG1lbWJlclxuICAgICAgICAgICAgYXdhaXQgU2VjdXJpdHkuY2hhbmdlTWVtYmVyc2hpcCh7dGFnOiB0YWdzLnRlYW0sIHJlbW92ZTogW21lbWJlcl19KTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgICBhZnRlckFsbChhc3luYyBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBhd2FpdCBTZWN1cml0eS5kZXN0cm95KG1lbWJlcik7XG4gICAgICAgICAgfSk7XG4gICAgICAgICAgaXQoJ2ZhaWxzIGJ5IGRlZmF1bHQuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgbGV0IHZlcmlmaWVkID0gYXdhaXQgU2VjdXJpdHkudmVyaWZ5KHNpZ25hdHVyZSwgbWVtYmVyKTtcbiAgICAgICAgICAgIGV4cGVjdCh2ZXJpZmllZCkudG9CZVVuZGVmaW5lZCgpO1xuICAgICAgICAgIH0pO1xuICAgICAgICAgIGl0KCdjb250YWlucyBhY3QgaW4gc2lnbmF0dXJlIGJ1dCB2ZXJpZmllcyBpZiB3ZSB0ZWxsIGl0IG5vdCB0byBjaGVjayBtZW1iZXJzaGlwLicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIGxldCB2ZXJpZmllZCA9IGF3YWl0IFNlY3VyaXR5LnZlcmlmeShzaWduYXR1cmUsIHt0ZWFtOiB0YWdzLnRlYW0sIG1lbWJlcjogZmFsc2V9KTtcbiAgICAgICAgICAgIGV4cGVjdCh2ZXJpZmllZCkudG9CZVRydXRoeSgpO1xuICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWVkLnRleHQpLnRvQmUoXCJtZXNzYWdlXCIpO1xuICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWVkLnByb3RlY3RlZEhlYWRlci5hY3QpLnRvQmUobWVtYmVyKTtcbiAgICAgICAgICAgIGV4cGVjdCh2ZXJpZmllZC5wcm90ZWN0ZWRIZWFkZXIuaWF0KS50b0JlVHJ1dGh5KCk7XG4gICAgICAgICAgfSk7XG4gICAgICAgICAgaXQoJ2ZhaWxzIGlmIHdlIHRlbGwgaXQgdG8gY2hlY2sgbm90QmVmb3JlOlwidGVhbVwiLCBldmVuIGlmIHdlIHRlbGwgaXQgbm90IHRvIGNoZWNrIG1lbWJlcnNoaXAuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgbGV0IHZlcmlmaWVkID0gYXdhaXQgU2VjdXJpdHkudmVyaWZ5KHNpZ25hdHVyZSwge3RlYW06IHRhZ3MudGVhbSwgbWVtYmVyOiBmYWxzZSwgbm90QmVmb3JlOid0ZWFtJ30pO1xuICAgICAgICAgICAgZXhwZWN0KHZlcmlmaWVkKS50b0JlVW5kZWZpbmVkKCk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgICBkZXNjcmliZSgnbWlzY2VsbGFuZW91cycsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaXQoJ2NhbiBzYWZlbHkgYmUgdXNlZCB3aGVuIGEgZGV2aWNlIGlzIHJlbW92ZWQsIGJ1dCBub3QgYWZ0ZXIgYmVpbmcgZW50aXJlbHkgZGVzdHJveWVkLicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBsZXQgW2QxLCBkMl0gPSBhd2FpdCBQcm9taXNlLmFsbChbU2VjdXJpdHkuY3JlYXRlKCksIFNlY3VyaXR5LmNyZWF0ZSgpXSksXG4gICAgICAgICAgICAgIHUgPSBhd2FpdCBTZWN1cml0eS5jcmVhdGUoZDEsIGQyKSxcbiAgICAgICAgICAgICAgdCA9IGF3YWl0IFNlY3VyaXR5LmNyZWF0ZSh1KTtcblxuICAgICAgICAgIGxldCBlbmNyeXB0ZWQgPSBhd2FpdCBTZWN1cml0eS5lbmNyeXB0KG1lc3NhZ2UsIHQpLFxuICAgICAgICAgICAgICBkZWNyeXB0ZWQgPSBhd2FpdCBTZWN1cml0eS5kZWNyeXB0KGVuY3J5cHRlZCwgdCk7XG4gICAgICAgICAgZXhwZWN0KGRlY3J5cHRlZC50ZXh0KS50b0JlKG1lc3NhZ2UpO1xuICAgICAgICAgIC8vIFJlbW92ZSB0aGUgZmlyc3QgZGVlcCBtZW1iZXJcbiAgICAgICAgICBkZWNyeXB0ZWQgPSBhd2FpdCBTZWN1cml0eS5kZWNyeXB0KGVuY3J5cHRlZCwgdCk7XG4gICAgICAgICAgYXdhaXQgU2VjdXJpdHkuY2hhbmdlTWVtYmVyc2hpcCh7dGFnOiB1LCByZW1vdmU6IFtkMV19KTtcbiAgICAgICAgICBleHBlY3QoZGVjcnlwdGVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgICAgICAgLy8gUHV0IGl0IGJhY2suXG4gICAgICAgICAgYXdhaXQgU2VjdXJpdHkuY2hhbmdlTWVtYmVyc2hpcCh7dGFnOiB1LCBhZGQ6IFtkMV19KTtcbiAgICAgICAgICBkZWNyeXB0ZWQgPSBhd2FpdCBTZWN1cml0eS5kZWNyeXB0KGVuY3J5cHRlZCwgdClcbiAgICAgICAgICBleHBlY3QoZGVjcnlwdGVkLnRleHQpLnRvQmUobWVzc2FnZSk7XG4gICAgICAgICAgLy8gTWFrZSB0aGUgb3RoZXIgdW5hdmFpbGFibGVcbiAgICAgICAgICBhd2FpdCBTZWN1cml0eS5kZXN0cm95KGQyKTtcbiAgICAgICAgICBkZWNyeXB0ZWQgPSBhd2FpdCBTZWN1cml0eS5kZWNyeXB0KGVuY3J5cHRlZCwgdCk7XG4gICAgICAgICAgZXhwZWN0KGRlY3J5cHRlZC50ZXh0KS50b0JlKG1lc3NhZ2UpO1xuICAgICAgICAgIC8vIERlc3Ryb3kgaXQgYWxsIHRoZSB3YXkgZG93bi5cbiAgICAgICAgICBhd2FpdCBTZWN1cml0eS5kZXN0cm95KHt0YWc6IHQsIHJlY3Vyc2l2ZU1lbWJlcnM6IHRydWV9KTtcbiAgICAgICAgICBsZXQgZXJyb3JNZXNzYWdlID0gYXdhaXQgU2VjdXJpdHkuZGVjcnlwdChlbmNyeXB0ZWQsIHQpLnRoZW4oKCkgPT4gbnVsbCwgZSA9PiBlLm1lc3NhZ2UpO1xuICAgICAgICAgIGV4cGVjdChlcnJvck1lc3NhZ2UpLnRvQmVUcnV0aHkoKTtcbiAgICAgICAgfSwgc2xvd0tleUNyZWF0aW9uKTtcbiAgICAgICAgaXQoJ2RldmljZSBpcyB1c2VhYmxlIGFzIHNvb24gYXMgaXQgcmVzb2x2ZXMuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGxldCBkZXZpY2UgPSBhd2FpdCBTZWN1cml0eS5jcmVhdGUoKTtcbiAgICAgICAgICBleHBlY3QoYXdhaXQgU2VjdXJpdHkuc2lnbihcImFueXRoaW5nXCIsIGRldmljZSkpLnRvQmVUcnV0aHkoKTtcbiAgICAgICAgICBhd2FpdCBTZWN1cml0eS5kZXN0cm95KGRldmljZSk7XG4gICAgICAgIH0sIDEwZTMpO1xuICAgICAgICBpdCgndGVhbSBpcyB1c2VhYmxlIGFzIHNvb24gYXMgaXQgcmVzb2x2ZXMuJywgYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgICAgICAgIGxldCB0ZWFtID0gYXdhaXQgU2VjdXJpdHkuY3JlYXRlKHRhZ3MuZGV2aWNlKTsgLy8gVGhlcmUgd2FzIGEgYnVnIG9uY2U6IGF3YWl0aW5nIGEgZnVuY3Rpb24gdGhhdCBkaWQgcmV0dXJuIGl0cyBwcm9taXNlLlxuICAgICAgICAgIGV4cGVjdChhd2FpdCBTZWN1cml0eS5zaWduKFwiYW55dGhpbmdcIiwgdGVhbSkpLnRvQmVUcnV0aHkoKTtcbiAgICAgICAgICBhd2FpdCBTZWN1cml0eS5kZXN0cm95KHRlYW0pO1xuICAgICAgICB9KTtcbiAgICAgICAgaXQoJ2FsbG93cyByZWNvdmVyeSBwcm9tcHRzIHRoYXQgY29udGFpbiBkb3QgKGFuZCBjb25maXJtIHRoYXQgYSB0ZWFtIGNhbiBoYXZlIGEgc2luZ2xlIHJlY292ZXJ5IHRhZyBhcyBtZW1iZXIpLicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBsZXQgcmVjb3ZlcnkgPSBhd2FpdCBTZWN1cml0eS5jcmVhdGUoe3Byb21wdDogXCJmb28uYmFyXCJ9KTtcbiAgICAgICAgICBsZXQgdXNlciA9IGF3YWl0IFNlY3VyaXR5LmNyZWF0ZShyZWNvdmVyeSk7XG4gICAgICAgICAgbGV0IG1lc3NhZ2UgPSBcInJlZC53aGl0ZVwiO1xuICAgICAgICAgIGxldCBlbmNyeXB0ZWQgPSBhd2FpdCBTZWN1cml0eS5lbmNyeXB0KG1lc3NhZ2UsIHVzZXIpO1xuICAgICAgICAgIGxldCBkZWNyeXB0ZWQgPSBhd2FpdCBTZWN1cml0eS5kZWNyeXB0KGVuY3J5cHRlZCwgdXNlcik7XG4gICAgICAgICAgbGV0IHNpZ25lZCA9IGF3YWl0IFNlY3VyaXR5LnNpZ24obWVzc2FnZSwgdXNlcik7XG4gICAgICAgICAgbGV0IHZlcmlmaWVkID0gYXdhaXQgU2VjdXJpdHkudmVyaWZ5KHNpZ25lZCwgdXNlcik7XG4gICAgICAgICAgZXhwZWN0KGRlY3J5cHRlZC50ZXh0KS50b0JlKG1lc3NhZ2UpO1xuICAgICAgICAgIGV4cGVjdCh2ZXJpZmllZCkudG9CZVRydXRoeSgpO1xuICAgICAgICAgIGF3YWl0IFNlY3VyaXR5LmRlc3Ryb3koe3RhZzogdXNlciwgcmVjdXJzaXZlTWVtYmVyczogdHJ1ZX0pO1xuICAgICAgICB9LCAxMGUzKTtcbiAgICAgICAgaXQoJ3N1cHBvcnRzIHJvdGF0aW9uLicsIGFzeW5jIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICBsZXQgYWxpY2VUYWcgPSBhd2FpdCBTZWN1cml0eS5jcmVhdGUodGFncy5kZXZpY2UpLFxuICAgICAgICAgICAgICBjZm9UYWcgPSBhd2FpdCBTZWN1cml0eS5jcmVhdGUoYWxpY2VUYWcpLFxuICAgICAgICAgICAgICBhbGljZVBPID0gYXdhaXQgU2VjdXJpdHkuc2lnbihcInNvbWUgcHVyY2hhc2Ugb3JkZXJcIiwge3RlYW06IGNmb1RhZywgbWVtYmVyOiBhbGljZVRhZ30pLCAvLyBPbiBBbGljZSdzIGNvbXB1dGVyXG4gICAgICAgICAgICAgIGNmb0V5ZXNPbmx5ID0gYXdhaXQgU2VjdXJpdHkuZW5jcnlwdChcInRoZSBvdGhlciBzZXQgb2YgYm9va3NcIiwgY2ZvVGFnKVxuICAgICAgICAgIGV4cGVjdChhd2FpdCBTZWN1cml0eS52ZXJpZnkoYWxpY2VQTykpLnRvQmVUcnV0aHkoKTtcbiAgICAgICAgICBleHBlY3QoYXdhaXQgU2VjdXJpdHkudmVyaWZ5KGFsaWNlUE8sIHt0ZWFtOiBjZm9UYWcsIG1lbWJlcjogZmFsc2V9KSkudG9CZVRydXRoeSgpO1xuICAgICAgICAgIGV4cGVjdChhd2FpdCBTZWN1cml0eS5kZWNyeXB0KGNmb0V5ZXNPbmx5KSkudG9CZVRydXRoeSgpOyAvLyBPbiBBbGljZSdzIGNvbXB1dGVyXG5cbiAgICAgICAgICAvLyBOb3cgQWxpY2UgaXMgcmVwbGFjZSB3aXRoIEJvYiwgYW5kIENhcm9sIGFkZGVkIGZvciB0aGUgdHJhbnNpdGlvblxuICAgICAgICAgIGxldCBib2JUYWcgPSBhd2FpdCBTZWN1cml0eS5jcmVhdGUodGFncy5kZXZpY2UpO1xuICAgICAgICAgIGxldCBjYXJvbFRhZyA9IGF3YWl0IFNlY3VyaXR5LmNyZWF0ZSh0YWdzLmRldmljZSk7XG4gICAgICAgICAgYXdhaXQgU2VjdXJpdHkuY2hhbmdlTWVtYmVyc2hpcCh7dGFnOiBjZm9UYWcsIHJlbW92ZTogW2FsaWNlVGFnXSwgYWRkOiBbYm9iVGFnLCBjYXJvbFRhZ119KTtcbiAgICAgICAgICBhd2FpdCBTZWN1cml0eS5kZXN0cm95KGFsaWNlVGFnKVxuXG4gICAgICAgICAgZXhwZWN0KGF3YWl0IFNlY3VyaXR5LnNpZ24oXCJib2d1cyBQT1wiLCB7dGVhbTogY2ZvVGFnLCBtZW1iZXI6IGFsaWNlVGFnfSkuY2F0Y2goKCkgPT4gdW5kZWZpbmVkKSkudG9CZVVuZGVmaW5lZCgpOyAvLyBBbGljZSBjYW4gbm8gbG9uZ2VyIHNpZ24uXG4gICAgICAgICAgbGV0IGJvYlBPID0gYXdhaXQgU2VjdXJpdHkuc2lnbihcIm5ldyBQT1wiLCB7dGVhbTogY2ZvVGFnLCBtZW1iZXI6IGJvYlRhZ30pOyAvLyBPbiBCb2IncyBjb21wdXRlclxuICAgICAgICAgIGxldCBjYXJvbFBPID0gYXdhaXQgU2VjdXJpdHkuc2lnbihcIm5ldyBQT1wiLCB7dGVhbTogY2ZvVGFnLCBtZW1iZXI6IGNhcm9sVGFnfSk7XG4gICAgICAgICAgZXhwZWN0KGF3YWl0IFNlY3VyaXR5LnZlcmlmeShib2JQTykpLnRvQmVUcnV0aHkoKTtcbiAgICAgICAgICBleHBlY3QoYXdhaXQgU2VjdXJpdHkudmVyaWZ5KGNhcm9sUE8pKS50b0JlVHJ1dGh5KCk7XG4gICAgICAgICAgZXhwZWN0KGF3YWl0IFNlY3VyaXR5LnZlcmlmeShhbGljZVBPKS5jYXRjaCgoKSA9PiB1bmRlZmluZWQpKS50b0JlVW5kZWZpbmVkKCk7IC8vIEFsaWNlIGlzIG5vIGxvbmdlciBhIG1lbWJlciBvZiBjZm9UYWcuXG4gICAgICAgICAgZXhwZWN0KGF3YWl0IFNlY3VyaXR5LnZlcmlmeShhbGljZVBPLCB7dGVhbTogY2ZvVGFnLCBtZW1iZXI6IGZhbHNlfSkpLnRvQmVUcnV0aHkoKTsgLy8gRGVzdG9yeWluZyBBbGljZSdzIHRhZyBkb2Vzbid0IHByZXZlbnQgc2hhbGxvdyB2ZXJpZnlcbiAgICAgICAgICBleHBlY3QoYXdhaXQgU2VjdXJpdHkuZGVjcnlwdChjZm9FeWVzT25seSkpLnRvQmVUcnV0aHkoKTsgLy8gT24gQm9iJ3Mgb3IgQ2Fyb2wncyBjb21wdXRlclxuXG4gICAgICAgICAgLy8gTm93IHN1cHBvc2Ugd2Ugd2FudCB0byByb3RhdGUgdGhlIGNmb1RhZzpcbiAgICAgICAgICBsZXQgY2ZvVGFnMiA9IGF3YWl0IFNlY3VyaXR5LmNyZWF0ZShib2JUYWcpOyAvLyBOb3QgQ2Fyb2wuXG4gICAgICAgICAgYXdhaXQgU2VjdXJpdHkuZGVzdHJveShjZm9UYWcpO1xuXG4gICAgICAgICAgZXhwZWN0KGF3YWl0IFNlY3VyaXR5LnNpZ24oXCJib2d1cyBQT1wiLCB7dGVhbTogY2ZvVGFnLCBtZW1iZXI6IGJvYlRhZ30pLmNhdGNoKCgpID0+IHVuZGVmaW5lZCkpLnRvQmVVbmRlZmluZWQoKTsgLy8gRmFpbHMgZm9yIGRpc2NvbnRpbnVlZCB0ZWFtLlxuICAgICAgICAgIGV4cGVjdChhd2FpdCBTZWN1cml0eS5zaWduKFwibmV3IG5ldyBQT1wiLCB7dGVhbTogY2ZvVGFnMiwgbWVtYmVyOiBib2JUYWd9KSkudG9CZVRydXRoeSgpO1xuICAgICAgICAgIGV4cGVjdChhd2FpdCBTZWN1cml0eS52ZXJpZnkoYWxpY2VQTywge3RlYW06IGNmb1RhZywgbWVtYmVyOiBmYWxzZX0pKS50b0JlVHJ1dGh5KCk7XG4gICAgICAgICAgLy8gSG93ZXZlciwgc29tZSB0aGluZ3MgdG8gYmUgYXdhcmUgb2YuXG4gICAgICAgICAgZXhwZWN0KGF3YWl0IFNlY3VyaXR5LnZlcmlmeShib2JQTykpLnRvQmVUcnV0aHkoKTsgLy8gd29ya3MsIGJ1dCBvbmx5IGJlY2F1c2UgdGhpcyBsb29rcyBsaWtlIHRoZSBpbml0aWFsIGNoZWNrXG4gICAgICAgICAgZXhwZWN0KGF3YWl0IFNlY3VyaXR5LnZlcmlmeShjYXJvbFBPKSkudG9CZVRydXRoeSgpOyAvLyBzYW1lLCBhbmQgY29uZnVzaW5nIGJlY2F1c2UgQ2Fyb2wgaXMgbm90IG9uIHRoZSBuZXcgdGVhbS5cbiAgICAgICAgICBleHBlY3QoYXdhaXQgU2VjdXJpdHkuZGVjcnlwdChjZm9FeWVzT25seSkuY2F0Y2goKCkgPT4gdW5kZWZpbmVkKSkudG9CZVVuZGVmaW5lZCgpOyAvLyBGQUlMUyEgQm9iIGNhbid0IHNvcnQgdGhyb3VnaCB0aGUgbWVzcyB0aGF0IEFsaWNlIG1hZGUuXG4gICAgICAgIH0sIDE1ZTMpO1xuICAgICAgICAvLyBUT0RPOlxuICAgICAgICAvLyAtIFNob3cgdGhhdCBhIG1lbWJlciBjYW5ub3Qgc2lnbiBvciBkZWNyeXB0IGZvciBhIHRlYW0gdGhhdCB0aGV5IGhhdmUgYmVlbiByZW1vdmVkIGZyb20uXG4gICAgICAgIC8vIC0gU2hvdyB0aGF0IG11bHRpcGxlIHNpbXVsdGFuZW91cyBhcHBzIGNhbiB1c2UgdGhlIHNhbWUgdGFncyBpZiB0aGV5IHVzZSBTZWN1cml0eSBmcm9tIHRoZSBzYW1lIG9yaWdpbiBhbmQgaGF2ZSBjb21wYXRpYmxlIGdldFVzZXJEZXZpY2VTZWNyZXQuXG4gICAgICAgIC8vIC0gU2hvdyB0aGF0IG11bHRpcGxlIHNpbXVsdGFuZW91cyBhcHBzIGNhbm5vdCB1c2UgdGhlIHNhbWUgdGFncyBpZiB0aGV5IHVzZSBTZWN1cml0eSBmcm9tIHRoZSBzYW1lIG9yaWdpbiBhbmQgaGF2ZSBpbmNvbXBhdGlibGUgZ2V0VXNlckRldmljZVNlY3JldC5cbiAgICAgIH0pO1xuICAgIH0pO1xuICB9KTtcbn0pO1xuIl0sIm5hbWVzIjpbIlN0b3JhZ2UiLCJkaWdlc3QiLCJjcnlwdG8iLCJlbmNvZGUiLCJkZWNvZGUiLCJiaXRMZW5ndGgiLCJkZWNyeXB0IiwiZ2V0Q3J5cHRvS2V5Iiwid3JhcCIsInVud3JhcCIsImRlcml2ZUtleSIsInAycyIsImNvbmNhdFNhbHQiLCJlbmNyeXB0IiwiYmFzZTY0dXJsIiwic3VidGxlQWxnb3JpdGhtIiwiZGVjb2RlQmFzZTY0VVJMIiwiaW52YWxpZEtleUlucHV0IiwiRUNESC5lY2RoQWxsb3dlZCIsIkVDREguZGVyaXZlS2V5IiwiY2VrTGVuZ3RoIiwiYWVzS3ciLCJyc2FFcyIsInBiZXMyS3ciLCJhZXNHY21LdyIsImtleVRvSldLIiwiRUNESC5nZW5lcmF0ZUVwayIsImdldFZlcmlmeUtleSIsImdldFNpZ25LZXkiLCJiYXNlNjR1cmwuZW5jb2RlIiwiYmFzZTY0dXJsLmRlY29kZSIsImdlbmVyYXRlU2VjcmV0IiwiZ2VuZXJhdGVLZXlQYWlyIiwiZ2VuZXJhdGUiLCJKT1NFLmRlY29kZVByb3RlY3RlZEhlYWRlciIsIkpPU0UuZ2VuZXJhdGVLZXlQYWlyIiwiSk9TRS5Db21wYWN0U2lnbiIsIkpPU0UuY29tcGFjdFZlcmlmeSIsIkpPU0UuQ29tcGFjdEVuY3J5cHQiLCJKT1NFLmNvbXBhY3REZWNyeXB0IiwiSk9TRS5nZW5lcmF0ZVNlY3JldCIsIkpPU0UuYmFzZTY0dXJsLmVuY29kZSIsIkpPU0UuYmFzZTY0dXJsLmRlY29kZSIsIkpPU0UuZXhwb3J0SldLIiwiSk9TRS5pbXBvcnRKV0siLCJKT1NFLkdlbmVyYWxFbmNyeXB0IiwiSk9TRS5nZW5lcmFsRGVjcnlwdCIsIkpPU0UuR2VuZXJhbFNpZ24iLCJKT1NFLmdlbmVyYWxWZXJpZnkiLCJMb2NhbENvbGxlY3Rpb24iLCJwa2cuZGVmYXVsdCIsIlNlY3VyaXR5IiwiSW50ZXJuYWxTZWN1cml0eSJdLCJtYXBwaW5ncyI6IkFBQUEsTUFBTUEsU0FBTyxHQUFHO0FBQ2hCLEVBQUUsTUFBTSxFQUFFLElBQUksR0FBRyxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUMsTUFBTTtBQUN6QyxFQUFFLE1BQU0sS0FBSyxDQUFDLFdBQVcsRUFBRSxRQUFRLEVBQUUsU0FBUyxFQUFFO0FBQ2hELElBQUksSUFBSSxRQUFRLEdBQUcsTUFBTSxJQUFJLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQyxTQUFTLEVBQUUsQ0FBQyxJQUFJLEVBQUUsUUFBUSxFQUFFLFNBQVMsRUFBRSxNQUFNLENBQUMsQ0FBQyxDQUFDO0FBQzlGLElBQUksSUFBSSxDQUFDLFFBQVEsRUFBRSxNQUFNLElBQUksS0FBSyxDQUFDLENBQUMsVUFBVSxFQUFFLFNBQVMsQ0FBQyx5QkFBeUIsRUFBRSxRQUFRLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztBQUNsRyxJQUFJLElBQUksUUFBUSxDQUFDLE9BQU8sQ0FBQyxNQUFNLEVBQUU7QUFDakMsTUFBTSxJQUFJLENBQUMsV0FBVyxDQUFDLENBQUMsUUFBUSxDQUFDLEdBQUcsU0FBUyxDQUFDO0FBQzlDLEtBQUssTUFBTTtBQUNYLE1BQU0sT0FBTyxJQUFJLENBQUMsV0FBVyxDQUFDLENBQUMsUUFBUSxDQUFDLENBQUM7QUFDekMsS0FBSztBQUNMLElBQUksT0FBTyxJQUFJLENBQUM7QUFDaEIsR0FBRztBQUNILEVBQUUsTUFBTSxRQUFRLENBQUMsV0FBVyxFQUFFLFFBQVEsRUFBRTtBQUN4QztBQUNBO0FBQ0EsSUFBSSxPQUFPLElBQUksQ0FBQyxXQUFXLENBQUMsQ0FBQyxRQUFRLENBQUMsQ0FBQztBQUN2QyxHQUFHO0FBQ0gsRUFBRSxJQUFJLEVBQUUsRUFBRTtBQUNWLEVBQUUsV0FBVyxFQUFFLEVBQUU7QUFDakIsRUFBRSxhQUFhLEVBQUUsRUFBRTtBQUNuQixDQUFDOztBQ25CRCxTQUFTLGtCQUFrQixDQUFDLEtBQUssRUFBRTtBQUNuQyxFQUFFLElBQUksQ0FBQyxJQUFJLEVBQUUsT0FBTyxFQUFFLElBQUksRUFBRSxJQUFJLENBQUMsR0FBRyxLQUFLLENBQUM7QUFDMUMsRUFBRSxPQUFPLENBQUMsSUFBSSxFQUFFLE9BQU8sRUFBRSxJQUFJLEVBQUUsSUFBSSxDQUFDLENBQUM7QUFDckMsQ0FBQztBQUNEO0FBQ0E7QUFDQSxTQUFTLFFBQVEsQ0FBQyxDQUFDLE1BQU0sR0FBRyxJQUFJO0FBQ2hDLEtBQUssUUFBUSxHQUFHLE1BQU07QUFDdEIsS0FBSyxTQUFTLEdBQUcsUUFBUTtBQUN6QjtBQUNBLEtBQUssTUFBTSxJQUFJLENBQUMsTUFBTSxLQUFLLFFBQVEsS0FBSyxNQUFNLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQztBQUMvRDtBQUNBLEtBQUssZUFBZSxHQUFHLFNBQVMsQ0FBQyxJQUFJLElBQUksUUFBUSxDQUFDLElBQUksSUFBSSxRQUFRLENBQUMsUUFBUSxFQUFFLElBQUksSUFBSSxRQUFRO0FBQzdGLEtBQUssV0FBVyxHQUFHLE1BQU0sQ0FBQyxJQUFJLElBQUksTUFBTSxJQUFJLE1BQU0sQ0FBQyxRQUFRLEVBQUUsSUFBSSxJQUFJLE1BQU07QUFDM0U7QUFDQSxLQUFLLEdBQUcsR0FBRyxJQUFJO0FBQ2YsS0FBSyxJQUFJLENBQUMsT0FBTyxHQUFHLE9BQU8sQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQztBQUM5QyxLQUFLLElBQUksQ0FBQyxPQUFPLEdBQUcsT0FBTyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDO0FBQzlDLEtBQUssS0FBSyxDQUFDLFFBQVEsR0FBRyxPQUFPLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUM7QUFDakQsS0FBSyxFQUFFO0FBQ1AsRUFBTyxNQUFDLFFBQVEsR0FBRyxFQUFFLENBQUM7QUFDdEIsUUFBUSxPQUFPLEdBQUcsS0FBSyxDQUFDO0FBQ3hCLFFBQVEsWUFBWSxHQUFHLE1BQU0sQ0FBQyxXQUFXLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDO0FBQ3ZELFFBQVE7QUFDUjtBQUNBLFFBQVEsSUFBSSxHQUFHLE1BQU0sR0FBRyxPQUFPLElBQUksWUFBWSxDQUFDLE9BQU8sRUFBRSxNQUFNLENBQUMsR0FBRyxZQUFZLENBQ3BEO0FBQzNCLEVBQUUsSUFBSSxTQUFTLEdBQUcsQ0FBQyxDQUFDO0FBQ3BCO0FBQ0EsRUFBRSxTQUFTLE9BQU8sQ0FBQyxNQUFNLEVBQUUsR0FBRyxNQUFNLEVBQUU7QUFDdEM7QUFDQTtBQUNBO0FBQ0E7QUFDQSxJQUFJLElBQUksRUFBRSxHQUFHLEVBQUUsU0FBUztBQUN4QixDQUFDLE9BQU8sR0FBRyxRQUFRLENBQUMsRUFBRSxDQUFDLEdBQUcsRUFBRSxDQUFDO0FBQzdCO0FBQ0EsSUFBSSxPQUFPLElBQUksT0FBTyxDQUFDLENBQUMsT0FBTyxFQUFFLE1BQU0sS0FBSztBQUM1QyxNQUFNLEdBQUcsR0FBRyxlQUFlLEVBQUUsU0FBUyxFQUFFLEVBQUUsRUFBRSxNQUFNLEVBQUUsTUFBTSxFQUFFLElBQUksRUFBRSxXQUFXLENBQUMsQ0FBQztBQUMvRSxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsT0FBTyxFQUFFLENBQUMsT0FBTyxFQUFFLE1BQU0sQ0FBQyxDQUFDLENBQUM7QUFDaEQsTUFBTSxJQUFJLENBQUMsQ0FBQyxFQUFFLEVBQUUsTUFBTSxFQUFFLE1BQU0sRUFBRSxPQUFPLENBQUMsQ0FBQyxDQUFDO0FBQzFDLEtBQUssQ0FBQyxDQUFDO0FBQ1AsR0FBRztBQUNIO0FBQ0EsRUFBRSxlQUFlLE9BQU8sQ0FBQyxLQUFLLEVBQUU7QUFDaEMsSUFBSSxHQUFHLEdBQUcsZUFBZSxFQUFFLGFBQWEsRUFBRSxLQUFLLENBQUMsSUFBSSxFQUFFLE1BQU0sRUFBRSxXQUFXLEVBQUUsS0FBSyxDQUFDLE1BQU0sQ0FBQyxDQUFDO0FBQ3pGLElBQUksSUFBSSxDQUFDLEVBQUUsRUFBRSxNQUFNLEVBQUUsTUFBTSxHQUFHLEVBQUUsRUFBRSxNQUFNLEVBQUUsS0FBSyxFQUFFLE9BQU8sQ0FBQyxPQUFPLENBQUMsR0FBRyxLQUFLLENBQUMsSUFBSSxJQUFJLEVBQUUsQ0FBQztBQUNyRjtBQUNBO0FBQ0EsSUFBSSxJQUFJLEtBQUssQ0FBQyxNQUFNLEtBQUssS0FBSyxDQUFDLE1BQU0sS0FBSyxNQUFNLENBQUMsRUFBRSxPQUFPLFFBQVEsR0FBRyxlQUFlLEVBQUUsSUFBSSxFQUFFLFdBQVcsR0FBRyxrQkFBa0IsRUFBRSxLQUFLLENBQUMsTUFBTSxDQUFDLENBQUM7QUFDNUksSUFBSSxJQUFJLE1BQU0sS0FBSyxNQUFNLEtBQUssS0FBSyxDQUFDLE1BQU0sQ0FBQyxFQUFFLE9BQU8sUUFBUSxHQUFHLGVBQWUsRUFBRSxNQUFNLEVBQUUsbUJBQW1CLEVBQUUsV0FBVyxFQUFFLEtBQUssQ0FBQyxNQUFNLENBQUMsQ0FBQztBQUN4SSxJQUFJLElBQUksT0FBTyxLQUFLLE9BQU8sRUFBRSxPQUFPLE9BQU8sR0FBRyxDQUFDLEVBQUUsZUFBZSxDQUFDLDhCQUE4QixFQUFFLElBQUksQ0FBQyxTQUFTLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7QUFDaEk7QUFDQSxJQUFJLElBQUksTUFBTSxFQUFFO0FBQ2hCLE1BQU0sSUFBSSxLQUFLLEdBQUcsSUFBSSxFQUFFLE1BQU07QUFDOUI7QUFDQSxHQUFHLElBQUksR0FBRyxLQUFLLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxHQUFHLE1BQU0sR0FBRyxDQUFDLE1BQU0sQ0FBQyxDQUFDO0FBQ3BELE1BQU0sSUFBSTtBQUNWLFFBQVEsTUFBTSxHQUFHLE1BQU0sU0FBUyxDQUFDLE1BQU0sQ0FBQyxDQUFDLEdBQUcsSUFBSSxDQUFDLENBQUM7QUFDbEQsT0FBTyxDQUFDLE9BQU8sQ0FBQyxFQUFFO0FBQ2xCLFFBQVEsS0FBSyxHQUFHLGtCQUFrQixDQUFDLENBQUMsQ0FBQyxDQUFDO0FBQ3RDLFFBQVEsSUFBSSxDQUFDLFNBQVMsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxPQUFPLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQyxFQUFFO0FBQ25FLEdBQUcsS0FBSyxDQUFDLE9BQU8sR0FBRyxDQUFDLEVBQUUsTUFBTSxDQUFDLGdCQUFnQixDQUFDLENBQUM7QUFDL0MsVUFBVSxLQUFLLENBQUMsSUFBSSxHQUFHLENBQUMsS0FBSyxDQUFDO0FBQzlCLFNBQVMsTUFBTSxJQUFJLENBQUMsS0FBSyxDQUFDLE9BQU87QUFDakMsR0FBRyxLQUFLLENBQUMsT0FBTyxHQUFHLENBQUMsRUFBRSxLQUFLLENBQUMsSUFBSSxJQUFJLEtBQUssQ0FBQyxRQUFRLEVBQUUsQ0FBQyxJQUFJLEVBQUUsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDO0FBQ3JFLE9BQU87QUFDUCxNQUFNLElBQUksRUFBRSxLQUFLLFNBQVMsRUFBRSxPQUFPO0FBQ25DLE1BQU0sSUFBSSxRQUFRLEdBQUcsS0FBSyxHQUFHLENBQUMsRUFBRSxFQUFFLEtBQUssRUFBRSxPQUFPLENBQUMsR0FBRyxDQUFDLEVBQUUsRUFBRSxNQUFNLEVBQUUsT0FBTyxDQUFDLENBQUM7QUFDMUUsTUFBTSxHQUFHLEdBQUcsZUFBZSxFQUFFLFdBQVcsRUFBRSxFQUFFLEVBQUUsS0FBSyxJQUFJLE1BQU0sRUFBRSxJQUFJLEVBQUUsV0FBVyxDQUFDLENBQUM7QUFDbEYsTUFBTSxPQUFPLElBQUksQ0FBQyxRQUFRLENBQUMsQ0FBQztBQUM1QixLQUFLO0FBQ0w7QUFDQTtBQUNBLElBQUksSUFBSSxPQUFPLEdBQUcsUUFBUSxDQUFDLEVBQUUsQ0FBQyxDQUFDO0FBQy9CLElBQUksT0FBTyxRQUFRLENBQUMsRUFBRSxDQUFDLENBQUM7QUFDeEIsSUFBSSxJQUFJLENBQUMsT0FBTyxFQUFFLE9BQU8sT0FBTyxHQUFHLENBQUMsRUFBRSxlQUFlLENBQUMsbUJBQW1CLEVBQUUsS0FBSyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0FBQzFGLElBQUksSUFBSSxLQUFLLEVBQUUsT0FBTyxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQztBQUNyQyxTQUFTLE9BQU8sQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLENBQUM7QUFDakMsR0FBRztBQUNIO0FBQ0E7QUFDQSxFQUFFLFFBQVEsQ0FBQyxnQkFBZ0IsQ0FBQyxTQUFTLEVBQUUsT0FBTyxDQUFDLENBQUM7QUFDaEQsRUFBRSxPQUFPLEdBQUcsQ0FBQyxFQUFFLGVBQWUsQ0FBQyxrQkFBa0IsRUFBRSxXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUM7QUFDbEUsRUFBRSxPQUFPLE9BQU8sQ0FBQztBQUNqQjs7QUN0RkEsTUFBTSxNQUFNLEdBQUcsSUFBSSxHQUFHLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxNQUFNOztBQ0F2QyxNQUFNLEtBQUssR0FBRyxTQUFTOztBQ0E5QixNQUFNLFVBQVUsR0FBRyw2QkFBNkIsQ0FBQztBQUMxQyxTQUFTLE9BQU8sQ0FBQyxjQUFjLEVBQUUsR0FBRyxFQUFFLFNBQVMsR0FBRyxNQUFNLEVBQUU7QUFDakU7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEVBQUUsSUFBSSxDQUFDLEdBQUcsRUFBRSxPQUFPLGNBQWMsQ0FBQztBQUNsQyxFQUFFLElBQUksS0FBSyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsVUFBVSxDQUFDLENBQUM7QUFDcEMsRUFBRSxJQUFJLENBQUMsS0FBSyxFQUFFLE9BQU8sQ0FBQyxFQUFFLGNBQWMsQ0FBQyxDQUFDLEVBQUUsR0FBRyxDQUFDLENBQUMsQ0FBQztBQUNoRDtBQUNBLEVBQUUsSUFBSSxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxJQUFJLENBQUMsR0FBRyxLQUFLLENBQUM7QUFDakMsRUFBRSxPQUFPLENBQUMsRUFBRSxjQUFjLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxFQUFFLElBQUksQ0FBQyxDQUFDLEVBQUUsU0FBUyxDQUFDLENBQUMsQ0FBQztBQUNqRTs7QUNUQSxlQUFlLGVBQWUsQ0FBQyxRQUFRLEVBQUU7QUFDekM7QUFDQSxFQUFFLElBQUksUUFBUSxDQUFDLE1BQU0sS0FBSyxHQUFHLEVBQUUsT0FBTyxFQUFFLENBQUM7QUFDekMsRUFBRSxJQUFJLENBQUMsUUFBUSxDQUFDLEVBQUUsRUFBRSxPQUFPLE9BQU8sQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLFVBQVUsQ0FBQyxDQUFDO0FBQy9ELEVBQUUsSUFBSSxJQUFJLEdBQUcsTUFBTSxRQUFRLENBQUMsSUFBSSxFQUFFLENBQUM7QUFDbkMsRUFBRSxJQUFJLENBQUMsSUFBSSxFQUFFLE9BQU8sSUFBSSxDQUFDO0FBQ3pCLEVBQUUsT0FBTyxJQUFJLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxDQUFDO0FBQzFCLENBQUM7QUFDRDtBQUNBLE1BQU0sT0FBTyxHQUFHO0FBQ2hCLEVBQUUsSUFBSSxNQUFNLEdBQUcsRUFBRSxPQUFPLE1BQU0sQ0FBQyxFQUFFO0FBQ2pDLEVBQUUsT0FBTztBQUNULEVBQUUsS0FBSztBQUNQLEVBQUUsR0FBRyxDQUFDLGNBQWMsRUFBRSxHQUFHLEVBQUU7QUFDM0I7QUFDQSxJQUFJLE9BQU8sQ0FBQyxFQUFFLE1BQU0sQ0FBQyxJQUFJLEVBQUUsSUFBSSxDQUFDLE9BQU8sQ0FBQyxjQUFjLEVBQUUsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDO0FBQy9ELEdBQUc7QUFDSCxFQUFFLEtBQUssQ0FBQyxjQUFjLEVBQUUsR0FBRyxFQUFFLFNBQVMsRUFBRSxPQUFPLEdBQUcsRUFBRSxFQUFFO0FBQ3REO0FBQ0E7QUFDQTtBQUNBLElBQUksT0FBTyxLQUFLLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxjQUFjLEVBQUUsR0FBRyxDQUFDLEVBQUU7QUFDaEQsTUFBTSxNQUFNLEVBQUUsS0FBSztBQUNuQixNQUFNLElBQUksRUFBRSxJQUFJLENBQUMsU0FBUyxDQUFDLFNBQVMsQ0FBQztBQUNyQyxNQUFNLE9BQU8sRUFBRSxDQUFDLGNBQWMsRUFBRSxrQkFBa0IsRUFBRSxJQUFJLE9BQU8sQ0FBQyxPQUFPLElBQUksRUFBRSxFQUFFO0FBQy9FLEtBQUssQ0FBQyxDQUFDLElBQUksQ0FBQyxlQUFlLENBQUMsQ0FBQztBQUM3QixHQUFHO0FBQ0gsRUFBRSxRQUFRLENBQUMsY0FBYyxFQUFFLEdBQUcsRUFBRSxPQUFPLEdBQUcsRUFBRSxFQUFFO0FBQzlDO0FBQ0E7QUFDQSxJQUFJLE9BQU8sS0FBSyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsY0FBYyxFQUFFLEdBQUcsQ0FBQyxFQUFFO0FBQ2hELE1BQU0sS0FBSyxFQUFFLFNBQVM7QUFDdEIsTUFBTSxPQUFPLEVBQUUsQ0FBQyxRQUFRLEVBQUUsa0JBQWtCLEVBQUUsSUFBSSxPQUFPLENBQUMsT0FBTyxJQUFJLEVBQUUsRUFBRTtBQUN6RSxLQUFLLENBQUMsQ0FBQyxJQUFJLENBQUMsZUFBZSxDQUFDLENBQUM7QUFDN0IsR0FBRztBQUNILENBQUM7O0FDdkNELElBQUksUUFBUSxHQUFHLFlBQVksSUFBSSxZQUFZLENBQUM7QUFDNUMsSUFBSSxPQUFPLE1BQU0sQ0FBQyxLQUFLLFdBQVcsRUFBRTtBQUNwQyxFQUFFLFFBQVEsR0FBRyxNQUFNLENBQUMsTUFBTSxDQUFDO0FBQzNCLENBQUM7QUFDRDtBQUNPLFNBQVMsbUJBQW1CLENBQUMsR0FBRyxFQUFFLFlBQVksRUFBRTtBQUN2RCxFQUFFLE9BQU8sWUFBWSxJQUFJLEdBQUcsR0FBRyxRQUFRLENBQUMsWUFBWSxDQUFDLElBQUksR0FBRyxDQUFDO0FBQzdEOztBQ0hBLE1BQU0sUUFBUSxHQUFHLElBQUksR0FBRyxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDO0FBQ3pDLE1BQU0sUUFBUSxHQUFHLElBQUksR0FBRyxDQUFDLFlBQVksRUFBRSxRQUFRLENBQUM7QUFDaEQsTUFBTSxTQUFTLEdBQUcsUUFBUSxHQUFHLFFBQVEsQ0FBQyxLQUFJO0FBQzFDO0FBQ0E7QUFDQSxNQUFNLE1BQU0sR0FBRyxRQUFRLENBQUMsYUFBYSxDQUFDLFFBQVEsQ0FBQztBQUMvQyxNQUFNLE9BQU8sR0FBRyxJQUFJLGNBQWMsRUFBRTtBQUNwQyxNQUFNLGtCQUFrQixHQUFHLE1BQU0sQ0FBQyxNQUFNLENBQUM7QUFDekMsUUFBUSxHQUFHLENBQUMsR0FBRyxJQUFJLEVBQUUsRUFBRSxPQUFPLENBQUMsR0FBRyxDQUFDLEdBQUcsSUFBSSxDQUFDLENBQUMsRUFBRTtBQUM5QyxRQUFRLG1CQUFtQjtBQUMzQixPQUFPLEVBQUUsT0FBTyxDQUFDO0FBQ2pCO0FBQ0EsTUFBTSxLQUFLLEdBQUcsSUFBSSxPQUFPLENBQUMsT0FBTyxJQUFJO0FBQ3JDLFFBQVEsa0JBQWtCLENBQUMsS0FBSyxHQUFHLE9BQU87QUFDMUMsUUFBUSxNQUFNLENBQUMsS0FBSyxDQUFDLE9BQU8sR0FBRyxNQUFNLENBQUM7QUFDdEMsUUFBUSxRQUFRLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsQ0FBQztBQUNyQyxRQUFRLE1BQU0sQ0FBQyxZQUFZLENBQUMsS0FBSyxFQUFFLFFBQVEsQ0FBQyxDQUFDO0FBQzdDLFFBQVEsTUFBTSxDQUFDLGFBQWEsQ0FBQyxJQUFJLEdBQUcsU0FBUyxDQUFDO0FBQzlDO0FBQ0EsUUFBUSxPQUFPLENBQUMsS0FBSyxDQUFDLEtBQUssRUFBRSxDQUFDO0FBQzlCLFFBQVEsTUFBTSxDQUFDLE1BQU0sR0FBRyxNQUFNLE1BQU0sQ0FBQyxhQUFhLENBQUMsV0FBVyxDQUFDLFNBQVMsRUFBRSxRQUFRLENBQUMsTUFBTSxFQUFFLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUM7QUFDNUcsT0FBTyxDQUFDO0FBQ1IsTUFBTSxVQUFVLEdBQUcsUUFBUSxDQUFDO0FBQzVCLFFBQVEsZUFBZSxFQUFFLFFBQVEsR0FBRyxRQUFRLENBQUMsSUFBSTtBQUNqRCxRQUFRLFNBQVMsRUFBRSxrQkFBa0I7QUFDckMsUUFBUSxNQUFNLEVBQUUsT0FBTyxDQUFDLEtBQUs7QUFDN0IsUUFBUSxXQUFXLEVBQUUsU0FBUztBQUM5QixPQUFPLENBQUM7QUFDUjtBQUNBLE1BQU0sR0FBRyxHQUFHO0FBQ1osUUFBUSxJQUFJLENBQUMsT0FBTyxFQUFFLEdBQUcsSUFBSSxFQUFFLEVBQUUsT0FBTyxVQUFVLENBQUMsTUFBTSxFQUFFLE9BQU8sRUFBRSxHQUFHLElBQUksQ0FBQyxDQUFDLEVBQUU7QUFDL0UsUUFBUSxNQUFNLENBQUMsU0FBUyxFQUFFLEdBQUcsSUFBSSxFQUFFLEVBQUUsT0FBTyxVQUFVLENBQUMsUUFBUSxFQUFFLFNBQVMsRUFBRSxHQUFHLElBQUksQ0FBQyxDQUFDLEVBQUU7QUFDdkYsUUFBUSxPQUFPLENBQUMsT0FBTyxFQUFFLEdBQUcsSUFBSSxFQUFFLEVBQUUsT0FBTyxVQUFVLENBQUMsU0FBUyxFQUFFLE9BQU8sRUFBRSxHQUFHLElBQUksQ0FBQyxDQUFDLEVBQUU7QUFDckYsUUFBUSxPQUFPLENBQUMsU0FBUyxFQUFFLEdBQUcsSUFBSSxFQUFFLEVBQUUsT0FBTyxVQUFVLENBQUMsU0FBUyxFQUFFLFNBQVMsRUFBRSxHQUFHLElBQUksQ0FBQyxDQUFDLEVBQUU7QUFDekYsUUFBUSxNQUFNLENBQUMsR0FBRyxlQUFlLEVBQUUsRUFBRSxPQUFPLFVBQVUsQ0FBQyxRQUFRLEVBQUUsR0FBRyxlQUFlLENBQUMsQ0FBQyxFQUFFO0FBQ3ZGLFFBQVEsZ0JBQWdCLENBQUMsQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFLE1BQU0sQ0FBQyxHQUFHLEVBQUUsRUFBRSxFQUFFLE9BQU8sVUFBVSxDQUFDLGtCQUFrQixFQUFFLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxNQUFNLENBQUMsQ0FBQyxDQUFDLEVBQUU7QUFDaEgsUUFBUSxPQUFPLENBQUMsWUFBWSxFQUFFLEVBQUUsT0FBTyxVQUFVLENBQUMsU0FBUyxFQUFFLFlBQVksQ0FBQyxDQUFDLEVBQUU7QUFDN0UsUUFBUSxLQUFLLENBQUMsR0FBRyxHQUFHLElBQUksRUFBRSxFQUFFLE9BQU8sVUFBVSxDQUFDLE9BQU8sRUFBRSxHQUFHLENBQUMsQ0FBQyxFQUFFO0FBQzlELFFBQVEsS0FBSztBQUNiO0FBQ0E7QUFDQSxRQUFRLElBQUksT0FBTyxHQUFHLEVBQUUsT0FBTyxrQkFBa0IsQ0FBQyxFQUFFO0FBQ3BELFFBQVEsSUFBSSxPQUFPLENBQUMsT0FBTyxFQUFFLEVBQUUsTUFBTSxDQUFDLE1BQU0sQ0FBQyxrQkFBa0IsRUFBRSxPQUFPLENBQUMsQ0FBQyxFQUFFO0FBQzVFLFFBQVEsSUFBSSxtQkFBbUIsR0FBRyxFQUFFLE9BQU8sa0JBQWtCLENBQUMsbUJBQW1CLENBQUMsRUFBRTtBQUNwRixRQUFRLElBQUksbUJBQW1CLENBQUMsc0JBQXNCLEVBQUUsRUFBRSxrQkFBa0IsQ0FBQyxtQkFBbUIsR0FBRyxzQkFBc0IsQ0FBQyxFQUFFO0FBQzVILE9BQU87O0FDakRBLE1BQU0sS0FBSyxHQUFHLEVBQUUsR0FBRyxJQUFJLEdBQUcsSUFBSSxDQUFDO0FBQy9CLFNBQVMsV0FBVyxDQUFDLE1BQU0sR0FBRyxLQUFLLEVBQUU7QUFDNUMsRUFBRSxPQUFPLEtBQUssQ0FBQyxJQUFJLENBQUMsQ0FBQyxNQUFNLENBQUMsRUFBRSxDQUFDLENBQUMsRUFBRSxLQUFLLEtBQUssS0FBSyxHQUFHLENBQUMsQ0FBQyxDQUFDLElBQUksQ0FBQyxFQUFFLENBQUMsQ0FBQztBQUNoRSxDQUFDO0FBQ0QsTUFBTSxhQUFhLEdBQUcsb0JBQW9CLENBQUM7QUFDcEMsU0FBUyxXQUFXLENBQUMsTUFBTSxFQUFFLEtBQUssR0FBRyxhQUFhLEVBQUU7QUFDM0QsRUFBRSxNQUFNLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLFVBQVUsRUFBRSxDQUFDO0FBQzFDLENBQUM7QUFDRDtBQUNPLFNBQVMsY0FBYyxDQUFDLE1BQU0sRUFBRSxPQUFPLEVBQUU7QUFDaEQ7QUFDQTtBQUNBLEVBQUUsTUFBTSxDQUFDLElBQUksVUFBVSxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUMsQ0FBQztBQUMxRDs7QUNYZSxTQUFTLFVBQVUsRUFBRSxNQUFNO0FBQzFDLG9DQUFvQyxlQUFlLEdBQUcsR0FBRyxFQUFFO0FBQzNELEVBQUUsTUFBTSxjQUFjLEdBQUcsZUFBZSxHQUFHLElBQUk7QUFDL0MsUUFBUSxlQUFlLEdBQUcsSUFBSTtBQUM5QixRQUFRLFVBQVUsR0FBRyxjQUFjLEdBQUcsZUFBZSxHQUFHLEdBQUc7QUFDM0QsUUFBUSxPQUFPLEdBQUcsV0FBVyxFQUFFLENBQUM7QUFDaEM7QUFDQSxFQUFFLFFBQVEsQ0FBQyxTQUFTLEVBQUUsWUFBWTtBQUNsQyxJQUFJLElBQUksT0FBTyxDQUFDO0FBQ2hCLElBQUksU0FBUyxDQUFDLGtCQUFrQjtBQUNoQyxNQUFNLE9BQU8sR0FBRyxNQUFNLE1BQU0sQ0FBQyxrQkFBa0IsRUFBRSxDQUFDO0FBQ2xELEtBQUssQ0FBQyxDQUFDO0FBQ1AsSUFBSSxFQUFFLENBQUMsc0ZBQXNGLEVBQUUsa0JBQWtCO0FBQ2pILE1BQU0sSUFBSSxTQUFTLEdBQUcsTUFBTSxNQUFNLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxVQUFVLEVBQUUsT0FBTyxDQUFDLENBQUM7QUFDckUsTUFBTSxXQUFXLENBQUMsU0FBUyxDQUFDLENBQUM7QUFDN0IsTUFBTSxNQUFNLENBQUMsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQyxTQUFTLEVBQUUsU0FBUyxDQUFDLENBQUMsQ0FBQyxVQUFVLEVBQUUsQ0FBQztBQUM3RSxLQUFLLENBQUMsQ0FBQztBQUNQLElBQUksRUFBRSxDQUFDLGtEQUFrRCxFQUFFLGtCQUFrQjtBQUM3RSxNQUFNLElBQUksU0FBUyxHQUFHLE1BQU0sTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsVUFBVSxFQUFFLE9BQU8sQ0FBQztBQUNwRSxVQUFVLFlBQVksR0FBRyxNQUFNLE1BQU0sQ0FBQyxrQkFBa0IsRUFBRSxDQUFDO0FBQzNELE1BQU0sTUFBTSxDQUFDLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxZQUFZLENBQUMsU0FBUyxFQUFFLFNBQVMsQ0FBQyxDQUFDLENBQUMsYUFBYSxFQUFFLENBQUM7QUFDckYsS0FBSyxDQUFDLENBQUM7QUFDUCxJQUFJLEVBQUUsQ0FBQyw2REFBNkQsRUFBRSxrQkFBa0I7QUFDeEYsTUFBTSxJQUFJLE9BQU8sR0FBRyxJQUFJLFVBQVUsQ0FBQyxDQUFDLEVBQUUsRUFBRSxFQUFFLENBQUMsQ0FBQztBQUM1QyxVQUFVLFNBQVMsR0FBRyxNQUFNLE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLFVBQVUsRUFBRSxPQUFPLENBQUM7QUFDcEUsVUFBVSxRQUFRLEdBQUcsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQyxTQUFTLEVBQUUsU0FBUyxDQUFDLENBQUM7QUFDdkUsTUFBTSxNQUFNLENBQUMsUUFBUSxDQUFDLEdBQUcsQ0FBQyxDQUFDLGFBQWEsRUFBRSxDQUFDO0FBQzNDLE1BQU0sY0FBYyxDQUFDLFFBQVEsRUFBRSxPQUFPLENBQUMsQ0FBQztBQUN4QyxLQUFLLENBQUMsQ0FBQztBQUNQLElBQUksRUFBRSxDQUFDLDZIQUE2SCxFQUFFLGtCQUFrQjtBQUN4SixNQUFNLElBQUksU0FBUyxHQUFHLE1BQU0sTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsVUFBVSxFQUFFLE9BQU8sQ0FBQztBQUNwRSxVQUFVLFFBQVEsR0FBRyxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLFNBQVMsRUFBRSxTQUFTLENBQUMsQ0FBQztBQUN2RSxNQUFNLE1BQU0sQ0FBQyxRQUFRLENBQUMsZUFBZSxDQUFDLEdBQUcsQ0FBQyxDQUFDLElBQUksQ0FBQyxZQUFZLENBQUMsQ0FBQztBQUM5RCxNQUFNLE1BQU0sQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxDQUFDO0FBQzFDLE1BQU0sTUFBTSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsQ0FBQyxPQUFPLENBQUMsSUFBSSxXQUFXLEVBQUUsQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQztBQUMxRSxLQUFLLENBQUMsQ0FBQztBQUNQLElBQUksRUFBRSxDQUFDLHFLQUFxSyxFQUFFLGtCQUFrQjtBQUNoTSxNQUFNLElBQUksT0FBTyxHQUFHLENBQUMsR0FBRyxFQUFFLEtBQUssQ0FBQztBQUNoQyxVQUFVLFNBQVMsR0FBRyxNQUFNLE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLFVBQVUsRUFBRSxPQUFPLENBQUM7QUFDcEUsVUFBVSxRQUFRLEdBQUcsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQyxTQUFTLEVBQUUsU0FBUyxDQUFDLENBQUM7QUFDdkUsTUFBTSxNQUFNLENBQUMsUUFBUSxDQUFDLGVBQWUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUM7QUFDeEQsTUFBTSxNQUFNLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUMsQ0FBQztBQUM3QyxNQUFNLE1BQU0sQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQztBQUMxRCxNQUFNLE1BQU0sQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLENBQUMsT0FBTyxDQUFDLElBQUksV0FBVyxFQUFFLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxDQUFDO0FBQzFGLEtBQUssQ0FBQyxDQUFDO0FBQ1AsSUFBSSxFQUFFLENBQUMsb0RBQW9ELEVBQUUsa0JBQWtCO0FBQy9FLE1BQU0sSUFBSSxHQUFHLEdBQUcsV0FBVztBQUMzQixVQUFVLEdBQUcsR0FBRyxJQUFJLENBQUMsR0FBRyxFQUFFO0FBQzFCLFVBQVUsR0FBRyxHQUFHLEVBQUU7QUFDbEIsVUFBVSxPQUFPLEdBQUcsa0JBQWtCO0FBQ3RDLFVBQVUsU0FBUyxHQUFHLE1BQU0sTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsVUFBVSxFQUFFLE9BQU8sRUFBRSxDQUFDLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxDQUFDLENBQUM7QUFDckYsVUFBVSxRQUFRLEdBQUcsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQyxTQUFTLEVBQUUsU0FBUyxDQUFDLENBQUM7QUFDdkUsTUFBTSxNQUFNLENBQUMsUUFBUSxDQUFDLGVBQWUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUM7QUFDckQsTUFBTSxNQUFNLENBQUMsUUFBUSxDQUFDLGVBQWUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUM7QUFDckQsTUFBTSxNQUFNLENBQUMsUUFBUSxDQUFDLGVBQWUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUM7QUFDckQsTUFBTSxNQUFNLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUMsQ0FBQztBQUM3QyxLQUFLLENBQUMsQ0FBQztBQUNQLEdBQUcsQ0FBQyxDQUFDO0FBQ0w7QUFDQSxFQUFFLFFBQVEsQ0FBQyxZQUFZLEVBQUUsWUFBWTtBQUNyQyxJQUFJLElBQUksT0FBTyxDQUFDO0FBQ2hCLElBQUksU0FBUyxDQUFDLGtCQUFrQjtBQUNoQyxNQUFNLE9BQU8sR0FBRyxNQUFNLE1BQU0sQ0FBQyxxQkFBcUIsRUFBRSxDQUFDO0FBQ3JELEtBQUssQ0FBQyxDQUFDO0FBQ1AsSUFBSSxFQUFFLENBQUMsQ0FBQyw2QkFBNkIsRUFBRSxlQUFlLENBQUMsa0NBQWtDLENBQUMsRUFBRSxrQkFBa0I7QUFDOUc7QUFDQSxNQUFNLElBQUksT0FBTyxHQUFHLFdBQVcsQ0FBQyxlQUFlLENBQUM7QUFDaEQsVUFBVSxTQUFTLEdBQUcsTUFBTSxNQUFNLENBQUMsT0FBTyxDQUFDLE9BQU8sQ0FBQyxTQUFTLEVBQUUsT0FBTyxDQUFDO0FBQ3RFLFVBQVUsU0FBUyxHQUFHLE1BQU0sTUFBTSxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUMsVUFBVSxFQUFFLFNBQVMsQ0FBQyxDQUFDO0FBQzFFLE1BQU0sV0FBVyxDQUFDLFNBQVMsQ0FBQyxDQUFDO0FBQzdCLE1BQU0sTUFBTSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxJQUFJLENBQUMsT0FBTyxFQUFDO0FBQzFDLEtBQUssRUFBRSxVQUFVLENBQUMsQ0FBQztBQUNuQixJQUFJLFNBQVMsYUFBYSxDQUFDLEtBQUssRUFBRSxPQUFPLEVBQUUsY0FBYyxHQUFHLE9BQU8sRUFBRTtBQUNyRSxNQUFNLEVBQUUsQ0FBQyxDQUFDLG9DQUFvQyxFQUFFLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxrQkFBa0I7QUFDNUUsUUFBUSxJQUFJLEdBQUcsR0FBRyxNQUFNLE9BQU87QUFDL0IsWUFBWSxVQUFVLEdBQUcsTUFBTSxjQUFjO0FBQzdDLFlBQVksU0FBUyxHQUFHLE1BQU0sTUFBTSxDQUFDLE9BQU8sQ0FBQyxHQUFHLEVBQUUsT0FBTyxDQUFDO0FBQzFELFlBQVksU0FBUyxHQUFHLE1BQU0sTUFBTSxDQUFDLE9BQU8sQ0FBQyxVQUFVLEVBQUUsU0FBUyxDQUFDLENBQUM7QUFDcEUsUUFBUSxXQUFXLENBQUMsU0FBUyxDQUFDLENBQUM7QUFDL0IsUUFBUSxNQUFNLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQyxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQztBQUM3QyxPQUFPLENBQUMsQ0FBQztBQUNULEtBQUs7QUFDTCxJQUFJLGFBQWEsQ0FBQyxxQkFBcUI7QUFDdkMsa0JBQWtCLE1BQU0sQ0FBQyxvQkFBb0IsRUFBRSxDQUFDLENBQUM7QUFDakQsSUFBSSxhQUFhLENBQUMscUJBQXFCO0FBQ3ZDLGtCQUFrQixNQUFNLENBQUMsb0JBQW9CLENBQUMsUUFBUSxDQUFDO0FBQ3ZELGtCQUFrQixNQUFNLENBQUMsb0JBQW9CLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQztBQUN6RDtBQUNBLElBQUksRUFBRSxDQUFDLHVDQUF1QyxFQUFFLGtCQUFrQjtBQUNsRSxNQUFNLElBQUksT0FBTyxHQUFHLElBQUksVUFBVSxDQUFDLENBQUMsRUFBRSxFQUFFLEVBQUUsQ0FBQyxDQUFDO0FBQzVDLFVBQVUsU0FBUyxHQUFHLE1BQU0sTUFBTSxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUMsU0FBUyxFQUFFLE9BQU8sQ0FBQztBQUN0RSxVQUFVLFNBQVMsR0FBRyxNQUFNLE1BQU0sQ0FBQyxPQUFPLENBQUMsT0FBTyxDQUFDLFVBQVUsRUFBRSxTQUFTLENBQUM7QUFDekUsVUFBVSxNQUFNLEdBQUcsTUFBTSxDQUFDLHFCQUFxQixDQUFDLFNBQVMsQ0FBQyxDQUFDO0FBQzNELE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQyxhQUFhLEVBQUUsQ0FBQztBQUN6QyxNQUFNLGNBQWMsQ0FBQyxTQUFTLEVBQUUsT0FBTyxDQUFDLENBQUM7QUFDekMsS0FBSyxDQUFDLENBQUM7QUFDUCxJQUFJLEVBQUUsQ0FBQyxxQ0FBcUMsRUFBRSxrQkFBa0I7QUFDaEUsTUFBTSxJQUFJLFNBQVMsR0FBRyxNQUFNLE1BQU0sQ0FBQyxPQUFPLENBQUMsT0FBTyxDQUFDLFNBQVMsRUFBRSxPQUFPLENBQUM7QUFDdEUsVUFBVSxTQUFTLEdBQUcsTUFBTSxNQUFNLENBQUMsT0FBTyxDQUFDLE9BQU8sQ0FBQyxVQUFVLEVBQUUsU0FBUyxDQUFDO0FBQ3pFLFVBQVUsTUFBTSxHQUFHLE1BQU0sQ0FBQyxxQkFBcUIsQ0FBQyxTQUFTLENBQUMsQ0FBQztBQUMzRCxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUMsSUFBSSxDQUFDLFlBQVksQ0FBQyxDQUFDO0FBQzVDLE1BQU0sTUFBTSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUM7QUFDM0MsS0FBSyxDQUFDLENBQUM7QUFDUCxJQUFJLEVBQUUsQ0FBQyxxQ0FBcUMsRUFBRSxrQkFBa0I7QUFDaEUsTUFBTSxJQUFJLE9BQU8sR0FBRyxDQUFDLEdBQUcsRUFBRSxLQUFLLENBQUM7QUFDaEMsVUFBVSxTQUFTLEdBQUcsTUFBTSxNQUFNLENBQUMsT0FBTyxDQUFDLE9BQU8sQ0FBQyxTQUFTLEVBQUUsT0FBTyxDQUFDLENBQUM7QUFDdkUsTUFBTSxJQUFJLE1BQU0sR0FBRyxNQUFNLENBQUMscUJBQXFCLENBQUMsU0FBUyxDQUFDO0FBQzFELFVBQVUsU0FBUyxHQUFHLE1BQU0sTUFBTSxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUMsVUFBVSxFQUFFLFNBQVMsQ0FBQyxDQUFDO0FBQzFFLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUM7QUFDdEMsTUFBTSxNQUFNLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQyxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUMsQ0FBQztBQUM5QyxLQUFLLENBQUMsQ0FBQztBQUNQLElBQUksRUFBRSxDQUFDLG9EQUFvRCxFQUFFLGtCQUFrQjtBQUMvRSxNQUFNLElBQUksR0FBRyxHQUFHLFdBQVc7QUFDM0IsVUFBVSxHQUFHLEdBQUcsSUFBSSxDQUFDLEdBQUcsRUFBRTtBQUMxQixVQUFVLEdBQUcsR0FBRyxFQUFFO0FBQ2xCLFVBQVUsT0FBTyxHQUFHLGtCQUFrQjtBQUN0QyxVQUFVLFNBQVMsR0FBRyxNQUFNLE1BQU0sQ0FBQyxPQUFPLENBQUMsT0FBTyxDQUFDLFNBQVMsRUFBRSxPQUFPLEVBQUUsQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUcsQ0FBQyxDQUFDO0FBQ3ZGLFVBQVUsU0FBUyxHQUFHLE1BQU0sTUFBTSxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUMsVUFBVSxFQUFFLFNBQVMsQ0FBQztBQUN6RSxVQUFVLE1BQU0sR0FBRyxNQUFNLENBQUMscUJBQXFCLENBQUMsU0FBUyxFQUFDO0FBQzFELE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUM7QUFDbkMsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQztBQUNuQyxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDO0FBQ25DLE1BQU0sTUFBTSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUM7QUFDM0MsS0FBSyxDQUFDLENBQUM7QUFDUDtBQUNBLElBQUksU0FBUyxjQUFjLENBQUMsS0FBSyxFQUFFLFNBQVMsRUFBRTtBQUM5QyxNQUFNLEVBQUUsQ0FBQyxDQUFDLGNBQWMsRUFBRSxLQUFLLENBQUMsQ0FBQyxDQUFDLEVBQUUsaUJBQWlCO0FBQ3JELFFBQVEsSUFBSSxDQUFDLFVBQVUsRUFBRSxVQUFVLENBQUMsR0FBRyxNQUFNLFNBQVMsRUFBRTtBQUN4RCxZQUFZLE9BQU8sR0FBRyxXQUFXLENBQUMsZUFBZSxDQUFDO0FBQ2xELFlBQVksU0FBUyxHQUFHLE1BQU0sTUFBTSxDQUFDLE9BQU8sQ0FBQyxVQUFVLEVBQUUsT0FBTyxDQUFDLENBQUM7QUFDbEUsUUFBUSxNQUFNLFdBQVcsQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLFVBQVUsRUFBRSxTQUFTLENBQUMsQ0FBQyxDQUFDLFlBQVksRUFBRSxDQUFDO0FBQ2hGLE9BQU8sRUFBRSxlQUFlLENBQUMsQ0FBQztBQUMxQixLQUFLO0FBQ0wsSUFBSSxjQUFjLENBQUMsZ0JBQWdCLEVBQUUsWUFBWTtBQUNqRCxNQUFNLENBQUMsTUFBTSxNQUFNLENBQUMscUJBQXFCLEVBQUUsRUFBRSxTQUFTO0FBQ3RELE1BQU0sQ0FBQyxNQUFNLE1BQU0sQ0FBQyxxQkFBcUIsRUFBRSxFQUFFLFVBQVU7QUFDdkQsS0FBSyxDQUFDLENBQUM7QUFDUCxJQUFJLGNBQWMsQ0FBQyxlQUFlLEVBQUUsWUFBWTtBQUNoRCxNQUFNLE1BQU0sTUFBTSxDQUFDLG9CQUFvQixFQUFFO0FBQ3pDLE1BQU0sTUFBTSxNQUFNLENBQUMsb0JBQW9CLEVBQUU7QUFDekMsS0FBSyxDQUFDLENBQUM7QUFDUCxJQUFJLGNBQWMsQ0FBQyxRQUFRLEVBQUUsWUFBWTtBQUN6QyxNQUFNLE1BQU0sTUFBTSxDQUFDLG9CQUFvQixDQUFDLFFBQVEsQ0FBQztBQUNqRCxNQUFNLE1BQU0sTUFBTSxDQUFDLG9CQUFvQixDQUFDLFNBQVMsQ0FBQztBQUNsRCxLQUFLLENBQUMsQ0FBQztBQUNQLEdBQUcsQ0FBQyxDQUFDO0FBQ0w7QUFDQSxFQUFFLFFBQVEsQ0FBQyxlQUFlLEVBQUUsWUFBWTtBQUN4QztBQUNBLElBQUksZUFBZSxTQUFTLENBQUMsR0FBRyxFQUFFO0FBQ2xDLE1BQU0sT0FBTyxJQUFJLENBQUMsU0FBUyxDQUFDLE1BQU0sTUFBTSxDQUFDLFNBQVMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDO0FBQ3pELEtBQUs7QUFDTCxJQUFJLFNBQVMsU0FBUyxDQUFDLE1BQU0sRUFBRTtBQUMvQixNQUFNLE9BQU8sTUFBTSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUM7QUFDbEQsS0FBSztBQUNMO0FBQ0EsSUFBSSxRQUFRLENBQUMsQ0FBQyxlQUFlLENBQUMsRUFBRSxZQUFZO0FBQzVDLE1BQU0sTUFBTSxrQkFBa0IsR0FBRyxHQUFHLENBQUM7QUFDckMsTUFBTSxFQUFFLENBQUMsQ0FBQyx3Q0FBd0MsRUFBRSxrQkFBa0IsQ0FBQyxvQkFBb0IsQ0FBQyxFQUFFLGtCQUFrQjtBQUNoSCxRQUFRLElBQUksT0FBTyxHQUFHLE1BQU0sTUFBTSxDQUFDLGtCQUFrQixFQUFFO0FBQ3ZELFlBQVksb0JBQW9CLEdBQUcsTUFBTSxTQUFTLENBQUMsT0FBTyxDQUFDLFVBQVUsQ0FBQztBQUN0RSxZQUFZLGtCQUFrQixHQUFHLE1BQU0sU0FBUyxDQUFDLG9CQUFvQixDQUFDO0FBQ3RFLFlBQVksU0FBUyxHQUFHLE1BQU0sTUFBTSxDQUFDLElBQUksQ0FBQyxrQkFBa0IsRUFBRSxPQUFPLENBQUMsQ0FBQztBQUN2RSxRQUFRLE1BQU0sQ0FBQyxvQkFBb0IsQ0FBQyxNQUFNLENBQUMsQ0FBQyxJQUFJLENBQUMsa0JBQWtCLENBQUMsQ0FBQztBQUNyRSxRQUFRLE1BQU0sQ0FBQyxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLFNBQVMsRUFBRSxTQUFTLENBQUMsQ0FBQyxDQUFDLFVBQVUsRUFBRSxDQUFDO0FBQy9FLE9BQU8sQ0FBQyxDQUFDO0FBQ1QsTUFBTSxNQUFNLGlCQUFpQixHQUFHLEdBQUcsQ0FBQztBQUNwQyxNQUFNLEVBQUUsQ0FBQyxDQUFDLHlDQUF5QyxFQUFFLGlCQUFpQixDQUFDLG9CQUFvQixDQUFDLEVBQUUsa0JBQWtCO0FBQ2hILFFBQVEsSUFBSSxPQUFPLEdBQUcsTUFBTSxNQUFNLENBQUMsa0JBQWtCLEVBQUU7QUFDdkQsWUFBWSxtQkFBbUIsR0FBRyxNQUFNLFNBQVMsQ0FBQyxPQUFPLENBQUMsU0FBUyxDQUFDO0FBQ3BFLFlBQVksaUJBQWlCLEdBQUcsTUFBTSxTQUFTLENBQUMsbUJBQW1CLENBQUM7QUFDcEUsWUFBWSxTQUFTLEdBQUcsTUFBTSxNQUFNLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxVQUFVLEVBQUUsT0FBTyxDQUFDLENBQUM7QUFDdkUsUUFBUSxNQUFNLENBQUMsbUJBQW1CLENBQUMsTUFBTSxDQUFDLENBQUMsSUFBSSxDQUFDLGlCQUFpQixDQUFDLENBQUM7QUFDbkUsUUFBUSxNQUFNLENBQUMsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLGlCQUFpQixFQUFFLFNBQVMsQ0FBQyxDQUFDLENBQUMsVUFBVSxFQUFFLENBQUM7QUFDL0UsT0FBTyxDQUFDLENBQUM7QUFDVDtBQUNBLE1BQU0sTUFBTSxvQkFBb0IsR0FBRyxHQUFHLENBQUM7QUFDdkMsTUFBTSxFQUFFLENBQUMsQ0FBQywwRkFBMEYsRUFBRSxvQkFBb0IsQ0FBQyxNQUFNLENBQUMsRUFBRSxrQkFBa0I7QUFDdEosUUFBUSxJQUFJLE9BQU8sR0FBRyxNQUFNLE1BQU0sQ0FBQyxrQkFBa0IsRUFBRTtBQUN2RCxZQUFZLG1CQUFtQixHQUFHLE1BQU0sTUFBTSxDQUFDLFNBQVMsQ0FBQyxPQUFPLENBQUMsU0FBUyxDQUFDO0FBQzNFLFlBQVksaUJBQWlCLEdBQUcsTUFBTSxNQUFNLENBQUMsU0FBUyxDQUFDLG1CQUFtQixDQUFDO0FBQzNFLFlBQVksU0FBUyxHQUFHLE1BQU0sTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsVUFBVSxFQUFFLE9BQU8sQ0FBQyxDQUFDO0FBQ3ZFLFFBQVEsV0FBVyxDQUFDLG1CQUFtQixDQUFDLENBQUM7QUFDekMsUUFBUSxNQUFNLENBQUMsbUJBQW1CLENBQUMsTUFBTSxDQUFDLENBQUMsbUJBQW1CLENBQUMsb0JBQW9CLENBQUMsQ0FBQztBQUNyRixRQUFRLE1BQU0sQ0FBQyxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsaUJBQWlCLEVBQUUsU0FBUyxDQUFDLENBQUMsQ0FBQyxVQUFVLEVBQUUsQ0FBQztBQUMvRSxPQUFPLENBQUMsQ0FBQztBQUNULEtBQUssQ0FBQyxDQUFDO0FBQ1A7QUFDQSxJQUFJLFFBQVEsQ0FBQyxvQkFBb0IsRUFBRSxZQUFZO0FBQy9DLE1BQU0sTUFBTSx3QkFBd0IsR0FBRyxDQUFDLElBQUksRUFBRSxJQUFJLEVBQUM7QUFDbkQsTUFBTSxFQUFFLENBQUMsQ0FBQyxnQ0FBZ0MsRUFBRSx3QkFBd0IsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLEVBQUUsd0JBQXdCLENBQUMsQ0FBQyxDQUFDLENBQUMsb0JBQW9CLENBQUMsRUFBRSxrQkFBa0I7QUFDaEosUUFBUSxJQUFJLE9BQU8sR0FBRyxNQUFNLE1BQU0sQ0FBQyxxQkFBcUIsRUFBRTtBQUMxRCxZQUFZLG9CQUFvQixHQUFHLE1BQU0sU0FBUyxDQUFDLE9BQU8sQ0FBQyxVQUFVLENBQUM7QUFDdEUsWUFBWSxrQkFBa0IsR0FBRyxNQUFNLFNBQVMsQ0FBQyxvQkFBb0IsQ0FBQztBQUN0RSxZQUFZLE9BQU8sR0FBRyxXQUFXLENBQUMsR0FBRyxDQUFDO0FBQ3RDLFlBQVksU0FBUyxHQUFHLE1BQU0sTUFBTSxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUMsU0FBUyxFQUFFLE9BQU8sQ0FBQztBQUN4RSxZQUFZLFNBQVMsR0FBRyxNQUFNLE1BQU0sQ0FBQyxPQUFPLENBQUMsa0JBQWtCLEVBQUUsU0FBUyxDQUFDLENBQUM7QUFDNUUsUUFBUSxNQUFNLENBQUMsb0JBQW9CLENBQUMsTUFBTSxDQUFDLENBQUMsc0JBQXNCLENBQUMsd0JBQXdCLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztBQUNoRyxRQUFRLE1BQU0sQ0FBQyxvQkFBb0IsQ0FBQyxNQUFNLENBQUMsQ0FBQyxtQkFBbUIsQ0FBQyx3QkFBd0IsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0FBQzdGLFFBQVEsTUFBTSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxJQUFJLENBQUMsT0FBTyxFQUFDO0FBQzVDLE9BQU8sQ0FBQyxDQUFDO0FBQ1QsTUFBTSxNQUFNLHVCQUF1QixHQUFHLEdBQUcsQ0FBQztBQUMxQyxNQUFNLEVBQUUsQ0FBQyxDQUFDLCtCQUErQixFQUFFLHVCQUF1QixDQUFDLG9CQUFvQixDQUFDLEVBQUUsa0JBQWtCO0FBQzVHLFFBQVEsSUFBSSxPQUFPLEdBQUcsTUFBTSxNQUFNLENBQUMscUJBQXFCLEVBQUU7QUFDMUQsWUFBWSxtQkFBbUIsR0FBRyxNQUFNLFNBQVMsQ0FBQyxPQUFPLENBQUMsU0FBUyxDQUFDO0FBQ3BFLFlBQVksaUJBQWlCLEdBQUcsTUFBTSxTQUFTLENBQUMsbUJBQW1CLENBQUM7QUFDcEUsWUFBWSxPQUFPLEdBQUcsV0FBVyxDQUFDLEdBQUcsQ0FBQztBQUN0QyxZQUFZLFNBQVMsR0FBRyxNQUFNLE1BQU0sQ0FBQyxPQUFPLENBQUMsaUJBQWlCLEVBQUUsT0FBTyxDQUFDO0FBQ3hFLFlBQVksU0FBUyxHQUFHLE1BQU0sTUFBTSxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUMsVUFBVSxFQUFFLFNBQVMsQ0FBQyxDQUFDO0FBQzVFLFFBQVEsTUFBTSxDQUFDLG1CQUFtQixDQUFDLE1BQU0sQ0FBQyxDQUFDLElBQUksQ0FBQyx1QkFBdUIsQ0FBQyxDQUFDO0FBQ3pFLFFBQVEsTUFBTSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxJQUFJLENBQUMsT0FBTyxFQUFDO0FBQzVDLE9BQU8sQ0FBQyxDQUFDO0FBQ1QsS0FBSyxDQUFDLENBQUM7QUFDUDtBQUNBLElBQUksUUFBUSxDQUFDLGtCQUFrQixFQUFFLFlBQVk7QUFDN0MsTUFBTSxNQUFNLGdCQUFnQixHQUFHLEVBQUUsQ0FBQztBQUNsQyxNQUFNLEVBQUUsQ0FBQyxDQUFDLFdBQVcsRUFBRSxnQkFBZ0IsQ0FBQyxvQkFBb0IsQ0FBQyxFQUFFLGtCQUFrQjtBQUNqRixRQUFRLElBQUksR0FBRyxHQUFHLE1BQU0sTUFBTSxDQUFDLG9CQUFvQixFQUFFO0FBQ3JELFlBQVksYUFBYSxHQUFHLE1BQU0sU0FBUyxDQUFDLEdBQUcsQ0FBQztBQUNoRCxZQUFZLFdBQVcsR0FBRyxNQUFNLFNBQVMsQ0FBQyxhQUFhLENBQUM7QUFDeEQsWUFBWSxTQUFTLEdBQUcsTUFBTSxNQUFNLENBQUMsT0FBTyxDQUFDLEdBQUcsRUFBRSxPQUFPLENBQUM7QUFDMUQsWUFBWSxTQUFTLEdBQUcsTUFBTSxNQUFNLENBQUMsT0FBTyxDQUFDLFdBQVcsRUFBRSxTQUFTLENBQUMsQ0FBQztBQUNyRSxRQUFRLE1BQU0sQ0FBQyxhQUFhLENBQUMsTUFBTSxDQUFDLENBQUMsSUFBSSxDQUFDLGdCQUFnQixDQUFDLENBQUM7QUFDNUQsUUFBUSxNQUFNLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQyxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQztBQUM3QyxPQUFPLENBQUMsQ0FBQztBQUNULEtBQUssQ0FBQyxDQUFDO0FBQ1AsR0FBRyxDQUFDLENBQUM7QUFDTDtBQUNBLEVBQUUsRUFBRSxDQUFDLDRCQUE0QixFQUFFLGtCQUFrQjtBQUNyRDtBQUNBLElBQUksSUFBSSxjQUFjLEdBQUcsTUFBTSxNQUFNLENBQUMsb0JBQW9CLEVBQUU7QUFDNUQsUUFBUSxXQUFXLEdBQUcsTUFBTSxNQUFNLENBQUMscUJBQXFCLEVBQUU7QUFDMUQ7QUFDQTtBQUNBLFFBQVEsUUFBUSxHQUFHLE1BQU0sTUFBTSxDQUFDLFNBQVMsQ0FBQyxjQUFjLENBQUM7QUFDekQsUUFBUSxTQUFTLEdBQUcsTUFBTSxNQUFNLENBQUMsT0FBTyxDQUFDLFdBQVcsQ0FBQyxTQUFTLEVBQUUsUUFBUSxDQUFDO0FBQ3pFLFFBQVEsU0FBUyxHQUFHLE1BQU0sTUFBTSxDQUFDLE9BQU8sQ0FBQyxXQUFXLENBQUMsVUFBVSxFQUFFLFNBQVMsQ0FBQztBQUMzRSxRQUFRLFFBQVEsR0FBRyxNQUFNLE1BQU0sQ0FBQyxTQUFTLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQztBQUN6RDtBQUNBO0FBQ0EsUUFBUSxPQUFPLEdBQUcsTUFBTSxNQUFNLENBQUMsT0FBTyxDQUFDLGNBQWMsRUFBRSxXQUFXLENBQUMsU0FBUyxDQUFDO0FBQzdFLFFBQVEsU0FBUyxHQUFHLE1BQU0sTUFBTSxDQUFDLFNBQVMsQ0FBQyxPQUFPLEVBQUUsV0FBVyxDQUFDLFVBQVUsQ0FBQztBQUMzRTtBQUNBO0FBQ0EsUUFBUSxPQUFPLEdBQUcsbUJBQW1CO0FBQ3JDLFFBQVEsZ0JBQWdCLEdBQUcsTUFBTSxNQUFNLENBQUMsT0FBTyxDQUFDLFNBQVMsRUFBRSxPQUFPLENBQUM7QUFDbkUsUUFBUSxnQkFBZ0IsR0FBRyxNQUFNLE1BQU0sQ0FBQyxPQUFPLENBQUMsUUFBUSxFQUFFLGdCQUFnQixDQUFDLENBQUM7QUFDNUUsSUFBSSxXQUFXLENBQUMsT0FBTyxDQUFDLENBQUM7QUFDekIsSUFBSSxNQUFNLENBQUMsZ0JBQWdCLENBQUMsSUFBSSxDQUFDLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxDQUFDO0FBQ2hELEdBQUcsRUFBRSxlQUFlLENBQUMsQ0FBQztBQUN0Qjs7QUN6UGUsU0FBUyxlQUFlLENBQUMsV0FBVyxFQUFFO0FBQ3JELEVBQUUsTUFBTSxlQUFlLEdBQUcsSUFBSTtBQUM5QixRQUFRLE9BQU8sR0FBRyxXQUFXLEVBQUUsQ0FBQztBQUNoQyxFQUFFLFFBQVEsQ0FBQywwQ0FBMEMsRUFBRSxZQUFZO0FBQ25FLElBQUksVUFBVSxDQUFDLFdBQVcsRUFBRSxLQUFLLENBQUMsQ0FBQztBQUNuQyxHQUFHLENBQUMsQ0FBQztBQUNMO0FBQ0EsRUFBRSxRQUFRLENBQUMsZ0JBQWdCLEVBQUUsWUFBWTtBQUN6QztBQUNBLElBQUksUUFBUSxDQUFDLGlCQUFpQixFQUFFLFlBQVk7QUFDNUMsTUFBTSxJQUFJLFFBQVEsRUFBRSxRQUFRLENBQUM7QUFDN0IsTUFBTSxTQUFTLENBQUMsa0JBQWtCO0FBQ2xDLFFBQVEsUUFBUSxHQUFHLE1BQU0sV0FBVyxDQUFDLGtCQUFrQixFQUFFLENBQUM7QUFDMUQsUUFBUSxRQUFRLEdBQUcsTUFBTSxXQUFXLENBQUMsa0JBQWtCLEVBQUUsQ0FBQztBQUMxRCxPQUFPLENBQUMsQ0FBQztBQUNUO0FBQ0EsTUFBTSxFQUFFLENBQUMsdUJBQXVCLEVBQUUsa0JBQWtCO0FBQ3BELFFBQVEsSUFBSSxTQUFTLEdBQUcsQ0FBQyxDQUFDLEVBQUUsUUFBUSxDQUFDLFVBQVUsRUFBRSxDQUFDLEVBQUUsUUFBUSxDQUFDLFVBQVUsQ0FBQztBQUN4RTtBQUNBLFlBQVksV0FBVyxHQUFHLENBQUMsQ0FBQyxFQUFFLFFBQVEsQ0FBQyxTQUFTLEVBQUUsQ0FBQyxFQUFFLFFBQVEsQ0FBQyxTQUFTLENBQUM7QUFDeEUsWUFBWSxTQUFTLEdBQUcsTUFBTSxXQUFXLENBQUMsSUFBSSxDQUFDLFNBQVMsRUFBRSxPQUFPLENBQUM7QUFDbEUsWUFBWSxRQUFRLEdBQUcsTUFBTSxXQUFXLENBQUMsTUFBTSxDQUFDLFdBQVcsRUFBRSxTQUFTLENBQUMsQ0FBQztBQUN4RSxRQUFRLE1BQU0sQ0FBQyxRQUFRLENBQUMsQ0FBQyxVQUFVLEVBQUUsQ0FBQztBQUN0QyxPQUFPLENBQUMsQ0FBQztBQUNULE1BQU0sRUFBRSxDQUFDLDBEQUEwRCxFQUFFLGtCQUFrQjtBQUN2RixRQUFRLElBQUksU0FBUyxHQUFHLENBQUMsQ0FBQyxFQUFFLFFBQVEsQ0FBQyxVQUFVLEVBQUUsQ0FBQyxFQUFFLFFBQVEsQ0FBQyxVQUFVLEVBQUUsSUFBSSxDQUFDLE9BQU8sQ0FBQztBQUN0RixZQUFZLFdBQVcsR0FBRyxDQUFDLENBQUMsRUFBRSxRQUFRLENBQUMsU0FBUyxFQUFFLENBQUMsRUFBRSxRQUFRLENBQUMsU0FBUyxDQUFDO0FBQ3hFLFlBQVksU0FBUyxHQUFHLE1BQU0sV0FBVyxDQUFDLElBQUksQ0FBQyxTQUFTLEVBQUUsT0FBTyxDQUFDO0FBQ2xFLFlBQVksUUFBUSxHQUFHLE1BQU0sV0FBVyxDQUFDLE1BQU0sQ0FBQyxXQUFXLEVBQUUsU0FBUyxDQUFDLENBQUM7QUFDeEUsUUFBUSxNQUFNLENBQUMsUUFBUSxDQUFDLENBQUMsVUFBVSxFQUFFLENBQUM7QUFDdEMsT0FBTyxDQUFDLENBQUM7QUFDVCxNQUFNLEVBQUUsQ0FBQyw0REFBNEQsRUFBRSxrQkFBa0I7QUFDekYsUUFBUSxJQUFJLFNBQVMsR0FBRyxDQUFDLENBQUMsRUFBRSxRQUFRLENBQUMsVUFBVSxFQUFFLENBQUMsRUFBRSxRQUFRLENBQUMsVUFBVSxDQUFDO0FBQ3hFLFlBQVksV0FBVyxHQUFHLENBQUMsQ0FBQyxFQUFFLFFBQVEsQ0FBQyxTQUFTLEVBQUUsQ0FBQyxFQUFFLFFBQVEsQ0FBQyxTQUFTLEVBQUUsSUFBSSxDQUFDLE9BQU8sQ0FBQztBQUN0RixZQUFZLFNBQVMsR0FBRyxNQUFNLFdBQVcsQ0FBQyxJQUFJLENBQUMsU0FBUyxFQUFFLE9BQU8sQ0FBQztBQUNsRSxZQUFZLFFBQVEsR0FBRyxNQUFNLFdBQVcsQ0FBQyxNQUFNLENBQUMsV0FBVyxFQUFFLFNBQVMsQ0FBQyxDQUFDO0FBQ3hFLFFBQVEsTUFBTSxDQUFDLFFBQVEsQ0FBQyxDQUFDLFVBQVUsRUFBRSxDQUFDO0FBQ3RDLE9BQU8sQ0FBQyxDQUFDO0FBQ1QsTUFBTSxFQUFFLENBQUMsMkVBQTJFLEVBQUUsa0JBQWtCO0FBQ3hHLFFBQVEsSUFBSSxHQUFHLEdBQUcsSUFBSSxDQUFDLEdBQUcsRUFBRTtBQUM1QixZQUFZLEdBQUcsR0FBRyxHQUFHO0FBQ3JCLFlBQVksR0FBRyxHQUFHLEdBQUc7QUFDckIsWUFBWSxTQUFTLEdBQUcsQ0FBQyxDQUFDLEVBQUUsUUFBUSxDQUFDLFVBQVUsRUFBRSxDQUFDLEVBQUUsUUFBUSxDQUFDLFVBQVUsQ0FBQztBQUN4RSxZQUFZLFdBQVcsR0FBRyxDQUFDLENBQUMsRUFBRSxRQUFRLENBQUMsU0FBUyxFQUFFLENBQUMsRUFBRSxRQUFRLENBQUMsU0FBUyxDQUFDO0FBQ3hFLFlBQVksU0FBUyxHQUFHLE1BQU0sV0FBVyxDQUFDLElBQUksQ0FBQyxTQUFTLEVBQUUsT0FBTyxFQUFFLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLENBQUMsQ0FBQztBQUNuRixZQUFZLFFBQVEsR0FBRyxNQUFNLFdBQVcsQ0FBQyxNQUFNLENBQUMsV0FBVyxFQUFFLFNBQVMsQ0FBQyxDQUFDO0FBQ3hFLFFBQVEsTUFBTSxDQUFDLFFBQVEsQ0FBQyxDQUFDLFVBQVUsRUFBRSxDQUFDO0FBQ3RDLFFBQVEsU0FBUyxDQUFDLFVBQVUsQ0FBQyxPQUFPLENBQUMsWUFBWSxJQUFJO0FBQ3JELFVBQVUsSUFBSSxNQUFNLEdBQUcsV0FBVyxDQUFDLHFCQUFxQixDQUFDLFlBQVksQ0FBQyxDQUFDO0FBQ3ZFLFVBQVUsTUFBTSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUM7QUFDdkMsVUFBVSxNQUFNLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQztBQUN2QyxVQUFVLE1BQU0sQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDO0FBQ3ZDLFNBQVMsQ0FBQyxDQUFDO0FBQ1gsT0FBTyxDQUFDLENBQUM7QUFDVCxNQUFNLEVBQUUsQ0FBQyxvRkFBb0YsRUFBRSxrQkFBa0I7QUFDakgsUUFBUSxJQUFJLE9BQU8sR0FBRyxJQUFJLFVBQVUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsQ0FBQztBQUNuRCxZQUFZLFNBQVMsR0FBRyxNQUFNLFdBQVcsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLEVBQUUsUUFBUSxDQUFDLFVBQVUsRUFBRSxDQUFDLEVBQUUsUUFBUSxDQUFDLFVBQVUsQ0FBQyxFQUFFLE9BQU8sQ0FBQztBQUN6RyxZQUFZLFFBQVEsR0FBRyxNQUFNLFdBQVcsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLEVBQUUsUUFBUSxDQUFDLFNBQVMsRUFBRSxDQUFDLEVBQUUsUUFBUSxDQUFDLFNBQVMsQ0FBQyxFQUFFLFNBQVMsQ0FBQyxDQUFDO0FBQzNHLFFBQVEsTUFBTSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsQ0FBQyxPQUFPLENBQUMsT0FBTyxDQUFDLENBQUM7QUFDbEQsT0FBTyxDQUFDLENBQUM7QUFDVCxNQUFNLEVBQUUsQ0FBQywwRkFBMEYsRUFBRSxrQkFBa0I7QUFDdkgsUUFBUSxJQUFJLE9BQU8sR0FBRyxVQUFVO0FBQ2hDLFlBQVksU0FBUyxHQUFHLE1BQU0sV0FBVyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsRUFBRSxRQUFRLENBQUMsVUFBVSxFQUFFLENBQUMsRUFBRSxRQUFRLENBQUMsVUFBVSxDQUFDLEVBQUUsT0FBTyxDQUFDO0FBQ3pHLFlBQVksUUFBUSxHQUFHLE1BQU0sV0FBVyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsRUFBRSxRQUFRLENBQUMsU0FBUyxFQUFFLENBQUMsRUFBRSxRQUFRLENBQUMsU0FBUyxDQUFDLEVBQUUsU0FBUyxDQUFDLENBQUM7QUFDM0csUUFBUSxNQUFNLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUMsQ0FBQztBQUMvQyxRQUFRLE1BQU0sQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLENBQUMsT0FBTyxDQUFDLElBQUksV0FBVyxFQUFFLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUM7QUFDNUUsT0FBTyxDQUFDLENBQUM7QUFDVCxNQUFNLEVBQUUsQ0FBQyxxRkFBcUYsRUFBRSxrQkFBa0I7QUFDbEgsUUFBUSxJQUFJLE9BQU8sR0FBRyxDQUFDLEdBQUcsRUFBRSxVQUFVLEVBQUUsR0FBRyxFQUFFLEtBQUssRUFBRSxHQUFHLEVBQUUsQ0FBQyxHQUFHLEVBQUUsQ0FBQyxFQUFFLElBQUksQ0FBQyxDQUFDO0FBQ3hFLFlBQVksU0FBUyxHQUFHLE1BQU0sV0FBVyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsRUFBRSxRQUFRLENBQUMsVUFBVSxFQUFFLENBQUMsRUFBRSxRQUFRLENBQUMsVUFBVSxDQUFDLEVBQUUsT0FBTyxDQUFDO0FBQ3pHLFlBQVksUUFBUSxHQUFHLE1BQU0sV0FBVyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsRUFBRSxRQUFRLENBQUMsU0FBUyxFQUFFLENBQUMsRUFBRSxRQUFRLENBQUMsU0FBUyxDQUFDLEVBQUUsU0FBUyxDQUFDLENBQUM7QUFDM0csUUFBUSxNQUFNLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUMsQ0FBQztBQUMvQyxRQUFRLE1BQU0sQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLENBQUMsT0FBTyxDQUFDLElBQUksV0FBVyxFQUFFLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxDQUFDO0FBQzVGLE9BQU8sQ0FBQyxDQUFDO0FBQ1QsTUFBTSxFQUFFLENBQUMsOERBQThELEVBQUUsa0JBQWtCO0FBQzNGLFFBQVEsSUFBSSxPQUFPLEdBQUcsQ0FBQyxHQUFHLEVBQUUsVUFBVSxFQUFFLEdBQUcsRUFBRSxLQUFLLEVBQUUsR0FBRyxFQUFFLENBQUMsR0FBRyxFQUFFLENBQUMsRUFBRSxJQUFJLENBQUMsQ0FBQztBQUN4RSxZQUFZLEdBQUcsR0FBRyxzQkFBc0I7QUFDeEMsWUFBWSxTQUFTLEdBQUcsTUFBTSxXQUFXLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxFQUFFLFFBQVEsQ0FBQyxVQUFVLEVBQUUsQ0FBQyxFQUFFLFFBQVEsQ0FBQyxVQUFVLENBQUMsRUFBRSxPQUFPLEVBQUUsQ0FBQyxHQUFHLENBQUMsQ0FBQztBQUNoSCxZQUFZLFFBQVEsR0FBRyxNQUFNLFdBQVcsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLEVBQUUsUUFBUSxDQUFDLFNBQVMsRUFBRSxDQUFDLEVBQUUsUUFBUSxDQUFDLFNBQVMsQ0FBQyxFQUFFLFNBQVMsQ0FBQyxDQUFDO0FBQzNHLFFBQVEsTUFBTSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsQ0FBQyxPQUFPLENBQUMsT0FBTyxDQUFDLENBQUM7QUFDL0MsUUFBUSxNQUFNLENBQUMsUUFBUSxDQUFDLGVBQWUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUM7QUFDdkQsUUFBUSxNQUFNLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQyxDQUFDLE9BQU8sQ0FBQyxJQUFJLFdBQVcsRUFBRSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsQ0FBQztBQUM1RixPQUFPLENBQUMsQ0FBQztBQUNUO0FBQ0EsTUFBTSxFQUFFLENBQUMsb0RBQW9EO0FBQzdELFNBQVMsa0JBQWtCO0FBQzNCLFdBQVcsSUFBSSxTQUFTLEdBQUcsQ0FBQyxDQUFDLEVBQUUsUUFBUSxDQUFDLFVBQVUsRUFBRSxDQUFDLEVBQUUsUUFBUSxDQUFDLFVBQVUsQ0FBQztBQUMzRSxlQUFlLFdBQVcsR0FBRyxDQUFDLENBQUMsRUFBRSxRQUFRLENBQUMsU0FBUyxFQUFFLENBQUMsRUFBRSxRQUFRLENBQUMsU0FBUyxDQUFDO0FBQzNFLGVBQWUsU0FBUyxHQUFHLE1BQU0sV0FBVyxDQUFDLElBQUksQ0FBQyxTQUFTLEVBQUUsT0FBTyxDQUFDO0FBQ3JFLGVBQWUsUUFBUSxHQUFHLE1BQU0sV0FBVyxDQUFDLE1BQU0sQ0FBQyxXQUFXLEVBQUUsU0FBUyxDQUFDLENBQUM7QUFDM0UsV0FBVyxNQUFNLENBQUMsUUFBUSxDQUFDLENBQUMsYUFBYSxFQUFFLENBQUM7QUFDNUMsVUFBVSxDQUFDLENBQUM7QUFDWixNQUFNLEVBQUUsQ0FBQyw4RUFBOEU7QUFDdkYsU0FBUyxrQkFBa0I7QUFDM0IsV0FBVyxJQUFJLFNBQVMsR0FBRyxDQUFDLENBQUMsRUFBRSxRQUFRLENBQUMsVUFBVSxFQUFFLENBQUMsRUFBRSxRQUFRLENBQUMsVUFBVSxDQUFDO0FBQzNFLGVBQWUsV0FBVyxHQUFHLENBQUMsQ0FBQyxFQUFFLFFBQVEsQ0FBQyxTQUFTLENBQUM7QUFDcEQsZUFBZSxTQUFTLEdBQUcsTUFBTSxXQUFXLENBQUMsSUFBSSxDQUFDLFNBQVMsRUFBRSxPQUFPLENBQUM7QUFDckUsZUFBZSxRQUFRLEdBQUcsTUFBTSxXQUFXLENBQUMsTUFBTSxDQUFDLFdBQVcsRUFBRSxTQUFTLENBQUMsQ0FBQztBQUMzRTtBQUNBLFdBQVcsTUFBTSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsQ0FBQyxVQUFVLEVBQUUsQ0FBQztBQUNqRCxXQUFXLE1BQU0sQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxDQUFDO0FBQy9DO0FBQ0EsV0FBVyxNQUFNLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsQ0FBQyxVQUFVLEVBQUUsQ0FBQztBQUM1RDtBQUNBLFdBQVcsTUFBTSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLENBQUMsYUFBYSxFQUFFLENBQUM7QUFDL0QsVUFBVSxDQUFDLENBQUM7QUFDWixNQUFNLEVBQUUsQ0FBQyw4RUFBOEU7QUFDdkYsU0FBUyxrQkFBa0I7QUFDM0IsV0FBVyxJQUFJLFNBQVMsR0FBRyxDQUFDLENBQUMsRUFBRSxRQUFRLENBQUMsVUFBVSxDQUFDO0FBQ25ELGVBQWUsV0FBVyxHQUFHLENBQUMsQ0FBQyxFQUFFLFFBQVEsQ0FBQyxTQUFTLEVBQUUsQ0FBQyxFQUFFLFFBQVEsQ0FBQyxTQUFTLENBQUM7QUFDM0UsZUFBZSxTQUFTLEdBQUcsTUFBTSxXQUFXLENBQUMsSUFBSSxDQUFDLFNBQVMsRUFBRSxPQUFPLENBQUM7QUFDckUsZUFBZSxRQUFRLEdBQUcsTUFBTSxXQUFXLENBQUMsTUFBTSxDQUFDLFdBQVcsRUFBRSxTQUFTLENBQUMsQ0FBQztBQUMzRTtBQUNBLFdBQVcsTUFBTSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsQ0FBQyxVQUFVLEVBQUUsQ0FBQztBQUNqRCxXQUFXLE1BQU0sQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxDQUFDO0FBQy9DO0FBQ0EsV0FBVyxNQUFNLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUM7QUFDbkQsV0FBVyxNQUFNLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsQ0FBQyxlQUFlLENBQUMsR0FBRyxDQUFDLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDO0FBQ3JFLFdBQVcsTUFBTSxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLENBQUMsVUFBVSxFQUFFLENBQUM7QUFDNUQsVUFBVSxDQUFDLENBQUM7QUFDWixLQUFLLENBQUMsQ0FBQztBQUNQO0FBQ0EsSUFBSSxRQUFRLENBQUMsc0JBQXNCLEVBQUUsWUFBWTtBQUNqRCxNQUFNLElBQUksU0FBUyxFQUFFLE9BQU8sRUFBRSxTQUFTLEVBQUUsVUFBVSxHQUFHLE1BQU0sRUFBRSxVQUFVLEVBQUUsZUFBZSxFQUFFLGVBQWUsQ0FBQztBQUMzRyxNQUFNLFNBQVMsQ0FBQyxrQkFBa0I7QUFDbEMsUUFBUSxTQUFTLEdBQUcsTUFBTSxXQUFXLENBQUMsb0JBQW9CLEVBQUUsQ0FBQztBQUM3RCxRQUFRLE9BQU8sR0FBRyxNQUFNLFdBQVcsQ0FBQyxxQkFBcUIsRUFBRSxDQUFDO0FBQzVELFFBQVEsU0FBUyxHQUFHLE1BQU0sV0FBVyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsRUFBRSxTQUFTLEVBQUUsQ0FBQyxFQUFFLE9BQU8sQ0FBQyxTQUFTLEVBQUUsQ0FBQyxFQUFFLFVBQVUsQ0FBQyxFQUFFLE9BQU8sQ0FBQyxDQUFDO0FBQzVHLFFBQVEsVUFBVSxHQUFHLFNBQVMsQ0FBQyxVQUFVLENBQUM7QUFDMUMsUUFBUSxJQUFJLFlBQVksR0FBRyxNQUFNLFdBQVcsQ0FBQyxxQkFBcUIsRUFBRSxDQUFDO0FBQ3JFLFFBQVEsZUFBZSxHQUFHLENBQUMsQ0FBQyxFQUFFLE9BQU8sQ0FBQyxTQUFTLEVBQUUsQ0FBQyxFQUFFLFlBQVksQ0FBQyxTQUFTLENBQUMsQ0FBQztBQUM1RSxRQUFRLGVBQWUsR0FBRyxDQUFDLENBQUMsRUFBRSxPQUFPLENBQUMsVUFBVSxFQUFFLENBQUMsRUFBRSxZQUFZLENBQUMsVUFBVSxDQUFDLENBQUM7QUFDOUUsT0FBTyxFQUFFLGVBQWUsQ0FBQyxDQUFDO0FBQzFCLE1BQU0sRUFBRSxDQUFDLCtCQUErQixFQUFFLGtCQUFrQjtBQUM1RCxRQUFRLElBQUksU0FBUyxHQUFHLE1BQU0sV0FBVyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsRUFBRSxTQUFTLENBQUMsRUFBRSxTQUFTLENBQUMsQ0FBQztBQUM3RSxRQUFRLE1BQU0sQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxDQUFDO0FBQzdDLFFBQVEsTUFBTSxDQUFDLFVBQVUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDO0FBQ25ELFFBQVEsTUFBTSxDQUFDLFVBQVUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUMsSUFBSSxDQUFDLFdBQVcsQ0FBQyxDQUFDO0FBQzNELE9BQU8sQ0FBQyxDQUFDO0FBQ1QsTUFBTSxFQUFFLENBQUMsNkJBQTZCLEVBQUUsa0JBQWtCO0FBQzFELFFBQVEsSUFBSSxTQUFTLEdBQUcsTUFBTSxXQUFXLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxFQUFFLE9BQU8sQ0FBQyxVQUFVLENBQUMsRUFBRSxTQUFTLENBQUMsQ0FBQztBQUN0RixRQUFRLE1BQU0sQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxDQUFDO0FBQzdDLFFBQVEsTUFBTSxDQUFDLFVBQVUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDO0FBQ25ELFFBQVEsTUFBTSxDQUFDLFVBQVUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUMsSUFBSSxDQUFDLGNBQWMsQ0FBQyxDQUFDO0FBQzlELE9BQU8sQ0FBQyxDQUFDO0FBQ1QsTUFBTSxFQUFFLENBQUMsaUNBQWlDLEVBQUUsa0JBQWtCO0FBQzlELFFBQVEsSUFBSSxTQUFTLEdBQUcsTUFBTSxXQUFXLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxFQUFFLFVBQVUsQ0FBQyxFQUFFLFNBQVMsQ0FBQyxDQUFDO0FBQzlFLFFBQVEsTUFBTSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUM7QUFDN0MsUUFBUSxNQUFNLENBQUMsVUFBVSxDQUFDLENBQUMsQ0FBQyxDQUFD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QUFFLE1BQU0sRUFBRSxNQUFNLENBQUMsQ0FBQyxDQUFDO0FBQ3BGLFVBQVUsSUFBSSxPQUFPLEdBQUcsTUFBTUEsR0FBUSxDQUFDLElBQUksQ0FBQyxRQUFRLEVBQUUsQ0FBQyxJQUFJLEVBQUUsTUFBTSxFQUFFLE1BQU0sRUFBRSxRQUFRLENBQUMsQ0FBQyxDQUFDO0FBQ3hGLFVBQVUsTUFBTSxDQUFDLE1BQU1BLEdBQVEsQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxVQUFVLEVBQUUsQ0FBQztBQUM1RCxVQUFVLE1BQU0sQ0FBQyxNQUFNQSxHQUFRLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsVUFBVSxFQUFFLENBQUM7QUFDOUQsVUFBVSxNQUFNLENBQUMsTUFBTUEsR0FBUSxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUMsQ0FBQyxLQUFLLENBQUMsTUFBTSxTQUFTLENBQUMsQ0FBQyxDQUFDLGFBQWEsRUFBRSxDQUFDO0FBQ3hGLFVBQVUsTUFBTSxDQUFDLE1BQU1BLEdBQVEsQ0FBQyxNQUFNLENBQUMsT0FBTyxFQUFFLENBQUMsSUFBSSxFQUFFLE1BQU0sRUFBRSxNQUFNLEVBQUUsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDLFVBQVUsRUFBRSxDQUFDO0FBQzdGLFVBQVUsTUFBTSxDQUFDLE1BQU1BLEdBQVEsQ0FBQyxPQUFPLENBQUMsV0FBVyxDQUFDLENBQUMsQ0FBQyxVQUFVLEVBQUUsQ0FBQztBQUNuRTtBQUNBO0FBQ0EsVUFBVSxJQUFJLE9BQU8sR0FBRyxNQUFNQSxHQUFRLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxDQUFDO0FBQ3RELFVBQVUsTUFBTUEsR0FBUSxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQztBQUN6QztBQUNBLFVBQVUsTUFBTSxDQUFDLE1BQU1BLEdBQVEsQ0FBQyxJQUFJLENBQUMsVUFBVSxFQUFFLENBQUMsSUFBSSxFQUFFLE1BQU0sRUFBRSxNQUFNLEVBQUUsTUFBTSxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsTUFBTSxTQUFTLENBQUMsQ0FBQyxDQUFDLGFBQWEsRUFBRSxDQUFDO0FBQ3pILFVBQVUsTUFBTSxDQUFDLE1BQU1BLEdBQVEsQ0FBQyxJQUFJLENBQUMsWUFBWSxFQUFFLENBQUMsSUFBSSxFQUFFLE9BQU8sRUFBRSxNQUFNLEVBQUUsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDLFVBQVUsRUFBRSxDQUFDO0FBQ2xHLFVBQVUsTUFBTSxDQUFDLE1BQU1BLEdBQVEsQ0FBQyxNQUFNLENBQUMsT0FBTyxFQUFFLENBQUMsSUFBSSxFQUFFLE1BQU0sRUFBRSxNQUFNLEVBQUUsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDLFVBQVUsRUFBRSxDQUFDO0FBQzdGO0FBQ0EsVUFBVSxNQUFNLENBQUMsTUFBTUEsR0FBUSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLFVBQVUsRUFBRSxDQUFDO0FBQzVELFVBQVUsTUFBTSxDQUFDLE1BQU1BLEdBQVEsQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxVQUFVLEVBQUUsQ0FBQztBQUM5RCxVQUFVLE1BQU0sQ0FBQyxNQUFNQSxHQUFRLENBQUMsT0FBTyxDQUFDLFdBQVcsQ0FBQyxDQUFDLEtBQUssQ0FBQyxNQUFNLFNBQVMsQ0FBQyxDQUFDLENBQUMsYUFBYSxFQUFFLENBQUM7QUFDN0YsU0FBUyxFQUFFLElBQUksQ0FBQyxDQUFDO0FBQ2pCO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsT0FBTyxDQUFDLENBQUM7QUFDVCxLQUFLLENBQUMsQ0FBQztBQUNQLEdBQUcsQ0FBQyxDQUFDO0FBQ0wsQ0FBQyxDQUFDIiwieF9nb29nbGVfaWdub3JlTGlzdCI6WzEsMTEsMTIsMTMsMTQsMTUsMTYsMTcsMTgsMTksMjAsMjEsMjIsMjMsMjQsMjUsMjYsMjcsMjgsMjksMzAsMzEsMzIsMzMsMzQsMzUsMzYsMzcsMzgsMzksNDAsNDEsNDIsNDMsNDQsNDUsNDYsNDcsNDgsNDksNTAsNTEsNTIsNTMsNTQsNTUsNTYsNTcsNTgsNTksNjAsNjEsNjIsNjMsNjQsNjUsNjYsNjddfQ==
