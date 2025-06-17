var crypto$2 = crypto;

var crypto$1 = crypto;
const isCryptoKey = (key) => key instanceof CryptoKey;

const digest = async (algorithm, data) => {
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
        res.set(await digest('sha256', buf), iter * 32);
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
    constructor(message, options) {
        super(message, options);
        this.code = 'ERR_JOSE_GENERIC';
        this.name = this.constructor.name;
        Error.captureStackTrace?.(this, this.constructor);
    }
}
JOSEError.code = 'ERR_JOSE_GENERIC';
class JWTClaimValidationFailed extends JOSEError {
    constructor(message, payload, claim = 'unspecified', reason = 'unspecified') {
        super(message, { cause: { claim, reason, payload } });
        this.code = 'ERR_JWT_CLAIM_VALIDATION_FAILED';
        this.claim = claim;
        this.reason = reason;
        this.payload = payload;
    }
}
JWTClaimValidationFailed.code = 'ERR_JWT_CLAIM_VALIDATION_FAILED';
class JWTExpired extends JOSEError {
    constructor(message, payload, claim = 'unspecified', reason = 'unspecified') {
        super(message, { cause: { claim, reason, payload } });
        this.code = 'ERR_JWT_EXPIRED';
        this.claim = claim;
        this.reason = reason;
        this.payload = payload;
    }
}
JWTExpired.code = 'ERR_JWT_EXPIRED';
class JOSEAlgNotAllowed extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JOSE_ALG_NOT_ALLOWED';
    }
}
JOSEAlgNotAllowed.code = 'ERR_JOSE_ALG_NOT_ALLOWED';
class JOSENotSupported extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JOSE_NOT_SUPPORTED';
    }
}
JOSENotSupported.code = 'ERR_JOSE_NOT_SUPPORTED';
class JWEDecryptionFailed extends JOSEError {
    constructor(message = 'decryption operation failed', options) {
        super(message, options);
        this.code = 'ERR_JWE_DECRYPTION_FAILED';
    }
}
JWEDecryptionFailed.code = 'ERR_JWE_DECRYPTION_FAILED';
class JWEInvalid extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWE_INVALID';
    }
}
JWEInvalid.code = 'ERR_JWE_INVALID';
class JWSInvalid extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWS_INVALID';
    }
}
JWSInvalid.code = 'ERR_JWS_INVALID';
class JWTInvalid extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWT_INVALID';
    }
}
JWTInvalid.code = 'ERR_JWT_INVALID';
class JWKInvalid extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWK_INVALID';
    }
}
JWKInvalid.code = 'ERR_JWK_INVALID';
class JWKSInvalid extends JOSEError {
    constructor() {
        super(...arguments);
        this.code = 'ERR_JWKS_INVALID';
    }
}
JWKSInvalid.code = 'ERR_JWKS_INVALID';
class JWKSNoMatchingKey extends JOSEError {
    constructor(message = 'no applicable key found in the JSON Web Key Set', options) {
        super(message, options);
        this.code = 'ERR_JWKS_NO_MATCHING_KEY';
    }
}
JWKSNoMatchingKey.code = 'ERR_JWKS_NO_MATCHING_KEY';
class JWKSMultipleMatchingKeys extends JOSEError {
    constructor(message = 'multiple matching keys found in the JSON Web Key Set', options) {
        super(message, options);
        this.code = 'ERR_JWKS_MULTIPLE_MATCHING_KEYS';
    }
}
JWKSMultipleMatchingKeys.code = 'ERR_JWKS_MULTIPLE_MATCHING_KEYS';
class JWKSTimeout extends JOSEError {
    constructor(message = 'request timed out', options) {
        super(message, options);
        this.code = 'ERR_JWKS_TIMEOUT';
    }
}
JWKSTimeout.code = 'ERR_JWKS_TIMEOUT';
class JWSSignatureVerificationFailed extends JOSEError {
    constructor(message = 'signature verification failed', options) {
        super(message, options);
        this.code = 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED';
    }
}
JWSSignatureVerificationFailed.code = 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED';

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
    types = types.filter(Boolean);
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
    if (isCryptoKey(key)) {
        return true;
    }
    return key?.[Symbol.toStringTag] === 'KeyObject';
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
            Math.ceil(parseInt(publicKey.algorithm.namedCurve.substr(-3), 10) / 8) <<
                3;
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

function isJWK(key) {
    return isObject(key) && typeof key.kty === 'string';
}
function isPrivateJWK(key) {
    return key.kty !== 'oct' && typeof key.d === 'string';
}
function isPublicJWK(key) {
    return key.kty !== 'oct' && typeof key.d === 'undefined';
}
function isSecretJWK(key) {
    return isJWK(key) && key.kty === 'oct' && typeof key.k === 'string';
}

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

const exportKeyValue = (k) => decode$1(k);
let privCache;
let pubCache;
const isKeyObject = (key) => {
    return key?.[Symbol.toStringTag] === 'KeyObject';
};
const importAndCache = async (cache, key, jwk, alg, freeze = false) => {
    let cached = cache.get(key);
    if (cached?.[alg]) {
        return cached[alg];
    }
    const cryptoKey = await parse({ ...jwk, alg });
    if (freeze)
        Object.freeze(key);
    if (!cached) {
        cache.set(key, { [alg]: cryptoKey });
    }
    else {
        cached[alg] = cryptoKey;
    }
    return cryptoKey;
};
const normalizePublicKey = (key, alg) => {
    if (isKeyObject(key)) {
        let jwk = key.export({ format: 'jwk' });
        delete jwk.d;
        delete jwk.dp;
        delete jwk.dq;
        delete jwk.p;
        delete jwk.q;
        delete jwk.qi;
        if (jwk.k) {
            return exportKeyValue(jwk.k);
        }
        pubCache || (pubCache = new WeakMap());
        return importAndCache(pubCache, key, jwk, alg);
    }
    if (isJWK(key)) {
        if (key.k)
            return decode$1(key.k);
        pubCache || (pubCache = new WeakMap());
        const cryptoKey = importAndCache(pubCache, key, key, alg, true);
        return cryptoKey;
    }
    return key;
};
const normalizePrivateKey = (key, alg) => {
    if (isKeyObject(key)) {
        let jwk = key.export({ format: 'jwk' });
        if (jwk.k) {
            return exportKeyValue(jwk.k);
        }
        privCache || (privCache = new WeakMap());
        return importAndCache(privCache, key, jwk, alg);
    }
    if (isJWK(key)) {
        if (key.k)
            return decode$1(key.k);
        privCache || (privCache = new WeakMap());
        const cryptoKey = importAndCache(privCache, key, key, alg, true);
        return cryptoKey;
    }
    return key;
};
var normalize = { normalizePublicKey, normalizePrivateKey };

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
            return parse({ ...jwk, alg });
        default:
            throw new JOSENotSupported('Unsupported "kty" (Key Type) Parameter value');
    }
}

const tag = (key) => key?.[Symbol.toStringTag];
const jwkMatchesOp = (alg, key, usage) => {
    if (key.use !== undefined && key.use !== 'sig') {
        throw new TypeError('Invalid key for this operation, when present its use must be sig');
    }
    if (key.key_ops !== undefined && key.key_ops.includes?.(usage) !== true) {
        throw new TypeError(`Invalid key for this operation, when present its key_ops must include ${usage}`);
    }
    if (key.alg !== undefined && key.alg !== alg) {
        throw new TypeError(`Invalid key for this operation, when present its alg must be ${alg}`);
    }
    return true;
};
const symmetricTypeCheck = (alg, key, usage, allowJwk) => {
    if (key instanceof Uint8Array)
        return;
    if (allowJwk && isJWK(key)) {
        if (isSecretJWK(key) && jwkMatchesOp(alg, key, usage))
            return;
        throw new TypeError(`JSON Web Key for symmetric algorithms must have JWK "kty" (Key Type) equal to "oct" and the JWK "k" (Key Value) present`);
    }
    if (!isKeyLike(key)) {
        throw new TypeError(withAlg(alg, key, ...types, 'Uint8Array', allowJwk ? 'JSON Web Key' : null));
    }
    if (key.type !== 'secret') {
        throw new TypeError(`${tag(key)} instances for symmetric algorithms must be of type "secret"`);
    }
};
const asymmetricTypeCheck = (alg, key, usage, allowJwk) => {
    if (allowJwk && isJWK(key)) {
        switch (usage) {
            case 'sign':
                if (isPrivateJWK(key) && jwkMatchesOp(alg, key, usage))
                    return;
                throw new TypeError(`JSON Web Key for this operation be a private JWK`);
            case 'verify':
                if (isPublicJWK(key) && jwkMatchesOp(alg, key, usage))
                    return;
                throw new TypeError(`JSON Web Key for this operation be a public JWK`);
        }
    }
    if (!isKeyLike(key)) {
        throw new TypeError(withAlg(alg, key, ...types, allowJwk ? 'JSON Web Key' : null));
    }
    if (key.type === 'secret') {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithms must not be of type "secret"`);
    }
    if (usage === 'sign' && key.type === 'public') {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm signing must be of type "private"`);
    }
    if (usage === 'decrypt' && key.type === 'public') {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm decryption must be of type "private"`);
    }
    if (key.algorithm && usage === 'verify' && key.type === 'private') {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm verifying must be of type "public"`);
    }
    if (key.algorithm && usage === 'encrypt' && key.type === 'private') {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm encryption must be of type "public"`);
    }
};
function checkKeyType(allowJwk, alg, key, usage) {
    const symmetric = alg.startsWith('HS') ||
        alg === 'dir' ||
        alg.startsWith('PBES2') ||
        /^A\d{3}(?:GCM)?KW$/.test(alg);
    if (symmetric) {
        symmetricTypeCheck(alg, key, usage, allowJwk);
    }
    else {
        asymmetricTypeCheck(alg, key, usage, allowJwk);
    }
}
var checkKeyType$1 = checkKeyType.bind(undefined, false);
const checkKeyTypeWithJwk = checkKeyType.bind(undefined, true);

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
    checkKeyType$1(alg, key, 'decrypt');
    key = (await normalize.normalizePrivateKey?.(key, alg)) || key;
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

const unprotected = Symbol();

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

async function exportJWK(key) {
    return keyToJWK(key);
}

async function encryptKeyManagement(alg, enc, key, providedCek, providedParameters = {}) {
    let encryptedKey;
    let parameters;
    let cek;
    checkKeyType$1(alg, key, 'encrypt');
    key = (await normalize.normalizePublicKey?.(key, alg)) || key;
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
                else if (!this._protectedHeader) {
                    this.setProtectedHeader(parameters);
                }
                else {
                    this._protectedHeader = { ...this._protectedHeader, ...parameters };
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

async function getCryptoKey(alg, key, usage) {
    if (usage === 'sign') {
        key = await normalize.normalizePrivateKey(key, alg);
    }
    if (usage === 'verify') {
        key = await normalize.normalizePublicKey(key, alg);
    }
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
    throw new TypeError(invalidKeyInput(key, ...types, 'Uint8Array', 'JSON Web Key'));
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
        checkKeyTypeWithJwk(alg, key, 'verify');
        if (isJWK(key)) {
            key = await importJWK(key, alg);
        }
    }
    else {
        checkKeyTypeWithJwk(alg, key, 'verify');
    }
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
        checkKeyTypeWithJwk(alg, key, 'sign');
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
    return crypto$1.subtle.generateKey(algorithm, options?.extractable, keyUsages);
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
    return crypto$1.subtle.generateKey(algorithm, options?.extractable ?? false, keyUsages);
}

async function generateKeyPair(alg, options) {
    return generateKeyPair$1(alg, options);
}

async function generateSecret(alg, options) {
    return generateSecret$1(alg, options);
}

// One consistent algorithm for each family.
// https://datatracker.ietf.org/doc/html/rfc7518

const signingName = 'EdDSA';
const signingCurve = 'Ed25519';
const signingAlgorithm = 'EdDSA';

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

async function hashBuffer(buffer) { // Promise a Uint8Array digest of buffer.
  let hash = await crypto$2.subtle.digest(hashName, buffer);
  return new Uint8Array(hash);
}
function hashText(text) { // Promise a Uint8Array digest of text string.
  let buffer = new TextEncoder().encode(text);
  return hashBuffer(buffer);
}
function encodeBase64url(uint8Array) { // Answer base64url encoded string of array.
  return encode(uint8Array);
}
function decodeBase64url(string) { // Answer the decoded Uint8Array of the base64url string.
  return decode(string);
}
function decodeClaims(jwSomething, index = 0) { // Answer an object whose keys are the decoded protected header of the JWS or JWE (using signatures[index] of a general-form JWS).
  return decodeProtectedHeader(jwSomething.signatures?.[index] || jwSomething);
}

function exportRawKey(key) {
  return crypto$2.subtle.exportKey('raw', key);
}

function importRawKey(arrayBuffer) {
  const algorithm = {name: signingCurve};
  return crypto$2.subtle.importKey('raw', arrayBuffer, algorithm, extractable, ['verify']);
}

function importSecret(byteArray) {
  const algorithm = {name: symmetricName, length: hashLength};
  return crypto$2.subtle.importKey('raw', byteArray, algorithm, true, ['encrypt', 'decrypt']);
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
    if (ArrayBuffer.isView(data)) return data;
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
    let hash = await hashText(text);
    return {type: 'secret', text: hash};
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
    return encodeBase64url(new Uint8Array(arrayBuffer));
  },
  async importRaw(string) { // Promise the verification key from base64url
    let arrayBuffer = decodeBase64url(string);
    return importRawKey(arrayBuffer);
  },
  async exportJWK(key) { // Promise JWK object, with alg included.
    let exported = await exportJWK(key),
        alg = key.algorithm; // JOSE library gives algorithm, but not alg that is needed for import.
    if (alg) { // subtle.crypto underlying keys
      if (alg.name === signingName && alg.namedCurve === signingCurve) exported.alg = signingAlgorithm;
      else if (alg.name === signingCurve) exported.alg = signingAlgorithm;
      else if (alg.name === encryptingName && alg.hash.name === hashName) exported.alg = encryptingAlgorithm;
      else if (alg.name === symmetricName && alg.length === hashLength) exported.alg = symmetricAlgorithm;
    } else switch (exported.kty) { // JOSE on NodeJS used node:crypto keys, which do not expose the precise algorithm
      case 'EC': exported.alg = signingAlgorithm; break;
      case 'OKP': exported.alg = signingAlgorithm; break;
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

let Cache$1 = class Cache extends Map {
  constructor(maxSize, defaultTimeToLive = 0) {
    super();
    this.maxSize = maxSize;
    this.defaultTimeToLive = defaultTimeToLive;
    this._nextWriteIndex = 0;
    this._keyList = Array(maxSize);
    this._timers = new Map();
  }
  set(key, value, ttl = this.defaultTimeToLive) {
    let nextWriteIndex = this._nextWriteIndex;

    // least-recently-SET bookkeeping:
    //   keyList is an array of keys that have been set.
    //   nextWriteIndex is where the next key is to be written in that array, wrapping around.
    // As it wraps, the key at keyList[nextWriteIndex] is the oldest that has been set.
    // However, that key and others may have already been deleted.
    // This implementation maximizes read speed first, write speed second, and simplicity/correctness third.
    // It does NOT try to keep the maximum number of values present. So as keys get manually deleted, the keyList
    // is not adjusted, and so there will keys present in the array that do not have entries in the values
    // map. The array is maxSize long, but the meaningful entries in it may be less.
    this.delete(this._keyList[nextWriteIndex]); // Regardless of current size.
    this._keyList[nextWriteIndex] = key;
    this._nextWriteIndex = (nextWriteIndex + 1) % this.maxSize;

    if (this._timers.has(key)) clearTimeout(this._timers.get(key));
    super.set(key, value);

    if (!ttl) return;  // Set timeout if required.
    this._timers.set(key, setTimeout(() => this.delete(key), ttl));
  }
  delete(key) {
    if (this._timers.has(key)) clearTimeout(this._timers.get(key));
    this._timers.delete(key);
    return super.delete(key);
  }
  clear(newMaxSize = this.maxSize) {
    this.maxSize = newMaxSize;
    this._keyList = Array(newMaxSize);
    this._nextWriteIndex = 0;
    super.clear();
    for (const timer of this._timers.values()) clearTimeout(timer);
    this._timers.clear();
  }
};

class Cache extends Map{constructor(e,t=0){super(),this.maxSize=e,this.defaultTimeToLive=t,this._nextWriteIndex=0,this._keyList=Array(e),this._timers=new Map;}set(e,t,s=this.defaultTimeToLive){let i=this._nextWriteIndex;this.delete(this._keyList[i]),this._keyList[i]=e,this._nextWriteIndex=(i+1)%this.maxSize,this._timers.has(e)&&clearTimeout(this._timers.get(e)),super.set(e,t),s&&this._timers.set(e,setTimeout((()=>this.delete(e)),s));}delete(e){return this._timers.has(e)&&clearTimeout(this._timers.get(e)),this._timers.delete(e),super.delete(e)}clear(e=this.maxSize){this.maxSize=e,this._keyList=Array(e),this._nextWriteIndex=0,super.clear();for(const e of this._timers.values())clearTimeout(e);this._timers.clear();}}class StorageBase{constructor({name:e,baseName:t="Storage",maxSerializerSize:s=1e3,debug:i=false}){const a=`${t}/${e}`,r=new Cache(s);Object.assign(this,{name:e,baseName:t,fullName:a,debug:i,serializer:r});}async list(){return this.serialize("",((e,t)=>this.listInternal(t,e)))}async get(e){return this.serialize(e,((e,t)=>this.getInternal(t,e)))}async delete(e){return this.serialize(e,((e,t)=>this.deleteInternal(t,e)))}async put(e,t){return this.serialize(e,((e,s)=>this.putInternal(s,t,e)))}log(...e){this.debug&&console.log(this.name,...e);}async serialize(e,t){const{serializer:s,ready:i}=this;let a=s.get(e)||i;return a=a.then((async()=>t(await this.ready,this.path(e)))),s.set(e,a),await a}}const{Response:e,URL:t}=globalThis;class StorageCache extends StorageBase{constructor(...e){super(...e),this.stripper=new RegExp(`^/${this.fullName}/`),this.ready=caches.open(this.fullName);}async listInternal(e,t){return (await t.keys()||[]).map((e=>this.tag(e.url)))}async getInternal(e,t){const s=await t.match(e);return s?.json()}deleteInternal(e,t){return t.delete(e)}putInternal(t,s,i){return i.put(t,e.json(s))}path(e){return `/${this.fullName}/${e}`}tag(e){return new t(e).pathname.replace(this.stripper,"")}destroy(){return caches.delete(this.fullName)}}

var prompter = promptString => promptString;
if (typeof(window) !== 'undefined') {
  prompter = window.prompt;
}

function getUserDeviceSecret(tag, promptString) {
  return promptString ? (tag + prompter(promptString)) : tag;
}

const origin = new URL(import.meta.url).origin;

function tagPath(collectionName, tag, extension = 'json') { // Pathname to tag resource.
  // Used in Storage URI. Bottlenecked here to provide consistent alternate implementations.
  // Path is .json so that static-file web servers will supply a json mime type.
  //
  // NOTE: changes here must be matched by the PUT route specified in signed-cloud-server/storage.mjs and tagName.mjs
  if (!tag) return collectionName;
  return `${collectionName}/${tag}.${extension}`;
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
  uri(collectionName, tag) {
    // Pathname expected by our signed-cloud-server.
    return `${origin}/Storage/${this.tagPath(collectionName, tag)}`;
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

function error(templateFunction, tag, cause = undefined) {
  // Formats tag (e.g., shortens it) and gives it to templateFunction(tag) to get
  // a suitable error message. Answers a rejected promise with that Error.
  let shortenedTag = tag ? tag.slice(0, 16) + "..." : '<empty tag>',
      message = templateFunction(shortenedTag);
  return Promise.reject(new Error(message, {cause}));
}
function unavailable(tag, operation) {
  return error(tag => `The ${operation} tag ${tag} is not available.`, tag);
}

class KeySet {
  // A KeySet maintains two private keys: signingKey and decryptingKey.
  // See https://kilroy-code.github.io/distributed-security/docs/implementation.html#web-worker-and-iframe

  // Caching
  static keySets = new Cache$1(500, 60 * 60 * 1e3);
  static cached(tag) { // Return an already populated KeySet.
    return KeySet.keySets.get(tag);
  }
  static cache(tag, keySet) { // Keep track of recent keySets.
    KeySet.keySets.set(tag, keySet);
  }
  static clear(tag = null) { // Remove all KeySet instances or just the specified one, but does not destroy their storage.
    if (!tag) return KeySet.keySets.clear();
    return KeySet.keySets.delete(tag);
  }
  constructor(tag) {
    this.tag = tag;
    this.memberTags = []; // Used when recursively destroying.
    KeySet.cache(tag, this);
  }
  // api.mjs provides the setter to changes these, and worker.mjs exercises it in browsers.
  static getUserDeviceSecret = getUserDeviceSecret;
  static Storage = Storage;

  // Principle operations.
  static async create(wrappingData) { // Create a persisted KeySet of the correct type, promising the newly created tag.
    // Note that creating a KeySet does not instantiate it.
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
  static async sign(message, {tags = [],
                              team:iss, member:act,
                              subject:sub = 'hash',
                              time:iat = iss && Date.now(),
                              memberTags, signingKey, recovery,
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
      let key = signingKey || (await KeySet.ensure(tag, {recovery, ...options})).signingKey;
      signingKey = null;
      return key;
    }, options),
        messageBuffer = MultiKrypto.inputBuffer(message, options);
    if (sub === 'hash') {
      const hash = await hashBuffer(messageBuffer);
      sub = await encodeBase64url(hash);
    } else if (!sub) {
      sub = undefined;
    }
    return MultiKrypto.sign(key, messageBuffer, {iss, act, iat, sub, ...options});
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
        memberTag = result.protectedHeader.act;
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
        || (await this.retrieve('EncryptionKey', teamTag, 'force'))?.protectedHeader.iat;
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
    return MultiKrypto.importRaw(tag).catch(() => unavailable(tag, 'verification'));
  }
  static async encryptingKey(tag) { // Promise the ordinary singular public key corresponding to the decryption key, which depends on public storage.
    let exportedPublicKey = await this.retrieve('EncryptionKey', tag);
    if (!exportedPublicKey) return unavailable(tag, 'encryption');
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
      keySet ||= new DeviceKeySet(tag);
    } else if (team && (stored = await TeamKeySet.getWrapped(tag))) {
      keySet ||= new TeamKeySet(tag);
    } else if (recovery && (stored = await RecoveryKeySet.getWrapped(tag))) { // Last, if at all.
      keySet ||= new RecoveryKeySet(tag);
    }
    // If things haven't changed, don't bother with setUnwrapped.
    if (keySet?.cached && // cached and stored are verified signatures
        keySet.cached.protectedHeader.iat === stored?.protectedHeader.iat &&
        keySet.cached.text === stored?.text &&
        keySet.decryptingKey && keySet.signingKey) return keySet;
    if (stored) keySet.cached = stored;
    else { // Not found. Could be a bogus tag, or one on another computer.
      this.clear(tag);
      return unavailable(tag, 'private');
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
      if (MultiKrypto.isEmptyJWSPayload(signature)) return LocalStore.delete(tag);
      return LocalStore.put(tag, signature);
    }
    return KeySet.Storage.store(collectionName, tag, signature);
  }
  static async retrieve(collectionName, tag, forceFresh = false) {  // Get back a verified result.
    // Some collections don't change content. No need to re-fetch/re-verify if it exists.
    let existing = !forceFresh && this.cached(tag);
    if (existing?.constructor.collection === collectionName) return existing.cached;
    let promise = (collectionName === DeviceKeySet.collection) ? LocalStore.get(tag) : KeySet.Storage.retrieve(collectionName, tag),
        signature = await promise,
        key = signature && await KeySet.verifyingKey(tag);
    if (!signature) return;
    // While we rely on the Storage implementations to deeply check signatures during write,
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
  static wipe() {
    return LocalStore.destroy();
  }
}
const LocalStore = new StorageCache({name: DeviceKeySet.collection});

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
    this.constructor.clear(this.tag);
  }
}

var name$1 = "@ki1r0y/distributed-security";
var version$1 = "1.2.4";
var _package = {
	name: name$1,
	version: version$1};

const {name, version} = _package;

const Security = { // This is the api for the vault. See https://kilroy-code.github.io/distributed-security/docs/implementation.html#creating-the-vault-web-worker-and-iframe

  get KeySet() { return KeySet; },// FIXME: do not leave this here
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
  wipeDeviceKeys() {
    return DeviceKeySet.wipe();
  },

  // Utlities
  hashBuffer, hashText, encodeBase64url, decodeBase64url, decodeClaims,

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
        if (token.signatures) tags = token.signatures.map(sig => MultiKrypto.decodeProtectedHeader(sig).kid);
        else if (token.recipients) tags = token.recipients.map(rec => rec.header.kid);
        else {
          let kid = MultiKrypto.decodeProtectedHeader(token).kid; // compact token
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

export { Security as default };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXBpLWJyb3dzZXItYnVuZGxlLm1qcyIsInNvdXJjZXMiOlsiLi4vbGliL2NyeXB0by1icm93c2VyLm1qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3dlYmNyeXB0by5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2RpZ2VzdC5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvYnVmZmVyX3V0aWxzLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvYmFzZTY0dXJsLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3V0aWwvZXJyb3JzLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvcmFuZG9tLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9pdi5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvY2hlY2tfaXZfbGVuZ3RoLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvY2hlY2tfY2VrX2xlbmd0aC5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3RpbWluZ19zYWZlX2VxdWFsLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9jcnlwdG9fa2V5LmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2lzX2tleV9saWtlLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvZGVjcnlwdC5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvaXNfZGlzam9pbnQuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2lzX29iamVjdC5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2JvZ3VzLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvYWVza3cuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9lY2RoZXMuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2NoZWNrX3Aycy5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3BiZXMya3cuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9zdWJ0bGVfcnNhZXMuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9jaGVja19rZXlfbGVuZ3RoLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvcnNhZXMuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2lzX2p3ay5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2p3a190b19rZXkuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9ub3JtYWxpemVfa2V5LmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9jZWsuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIva2V5L2ltcG9ydC5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvY2hlY2tfa2V5X3R5cGUuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9lbmNyeXB0LmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9hZXNnY21rdy5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvZGVjcnlwdF9rZXlfbWFuYWdlbWVudC5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvdmFsaWRhdGVfY3JpdC5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvdmFsaWRhdGVfYWxnb3JpdGhtcy5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd2UvZmxhdHRlbmVkL2RlY3J5cHQuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandlL2NvbXBhY3QvZGVjcnlwdC5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd2UvZ2VuZXJhbC9kZWNyeXB0LmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9wcml2YXRlX3N5bWJvbHMuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9rZXlfdG9fandrLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2tleS9leHBvcnQuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2VuY3J5cHRfa2V5X21hbmFnZW1lbnQuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandlL2ZsYXR0ZW5lZC9lbmNyeXB0LmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3ZS9nZW5lcmFsL2VuY3J5cHQuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9zdWJ0bGVfZHNhLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvZ2V0X3NpZ25fdmVyaWZ5X2tleS5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3ZlcmlmeS5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd3MvZmxhdHRlbmVkL3ZlcmlmeS5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd3MvY29tcGFjdC92ZXJpZnkuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandzL2dlbmVyYWwvdmVyaWZ5LmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3ZS9jb21wYWN0L2VuY3J5cHQuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9zaWduLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9mbGF0dGVuZWQvc2lnbi5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd3MvY29tcGFjdC9zaWduLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9nZW5lcmFsL3NpZ24uanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvdXRpbC9iYXNlNjR1cmwuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvdXRpbC9kZWNvZGVfcHJvdGVjdGVkX2hlYWRlci5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2dlbmVyYXRlLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2tleS9nZW5lcmF0ZV9rZXlfcGFpci5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9rZXkvZ2VuZXJhdGVfc2VjcmV0LmpzIiwiLi4vbGliL2FsZ29yaXRobXMubWpzIiwiLi4vbGliL3V0aWxpdGllcy5tanMiLCIuLi9saWIvcmF3LWJyb3dzZXIubWpzIiwiLi4vbGliL2tyeXB0by5tanMiLCIuLi9saWIvbXVsdGlLcnlwdG8ubWpzIiwiLi4vLi4vY2FjaGUvaW5kZXgubWpzIiwiLi4vLi4vc3RvcmFnZS9idW5kbGUubWpzIiwiLi4vbGliL3NlY3JldC5tanMiLCIuLi9saWIvb3JpZ2luLWJyb3dzZXIubWpzIiwiLi4vbGliL3RhZ1BhdGgubWpzIiwiLi4vbGliL3N0b3JhZ2UubWpzIiwiLi4vbGliL2tleVNldC5tanMiLCIuLi9saWIvcGFja2FnZS1sb2FkZXIubWpzIiwiLi4vbGliL2FwaS5tanMiXSwic291cmNlc0NvbnRlbnQiOlsiZXhwb3J0IGRlZmF1bHQgY3J5cHRvO1xuIiwiZXhwb3J0IGRlZmF1bHQgY3J5cHRvO1xuZXhwb3J0IGNvbnN0IGlzQ3J5cHRvS2V5ID0gKGtleSkgPT4ga2V5IGluc3RhbmNlb2YgQ3J5cHRvS2V5O1xuIiwiaW1wb3J0IGNyeXB0byBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5jb25zdCBkaWdlc3QgPSBhc3luYyAoYWxnb3JpdGhtLCBkYXRhKSA9PiB7XG4gICAgY29uc3Qgc3VidGxlRGlnZXN0ID0gYFNIQS0ke2FsZ29yaXRobS5zbGljZSgtMyl9YDtcbiAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5kaWdlc3Qoc3VidGxlRGlnZXN0LCBkYXRhKSk7XG59O1xuZXhwb3J0IGRlZmF1bHQgZGlnZXN0O1xuIiwiaW1wb3J0IGRpZ2VzdCBmcm9tICcuLi9ydW50aW1lL2RpZ2VzdC5qcyc7XG5leHBvcnQgY29uc3QgZW5jb2RlciA9IG5ldyBUZXh0RW5jb2RlcigpO1xuZXhwb3J0IGNvbnN0IGRlY29kZXIgPSBuZXcgVGV4dERlY29kZXIoKTtcbmNvbnN0IE1BWF9JTlQzMiA9IDIgKiogMzI7XG5leHBvcnQgZnVuY3Rpb24gY29uY2F0KC4uLmJ1ZmZlcnMpIHtcbiAgICBjb25zdCBzaXplID0gYnVmZmVycy5yZWR1Y2UoKGFjYywgeyBsZW5ndGggfSkgPT4gYWNjICsgbGVuZ3RoLCAwKTtcbiAgICBjb25zdCBidWYgPSBuZXcgVWludDhBcnJheShzaXplKTtcbiAgICBsZXQgaSA9IDA7XG4gICAgZm9yIChjb25zdCBidWZmZXIgb2YgYnVmZmVycykge1xuICAgICAgICBidWYuc2V0KGJ1ZmZlciwgaSk7XG4gICAgICAgIGkgKz0gYnVmZmVyLmxlbmd0aDtcbiAgICB9XG4gICAgcmV0dXJuIGJ1Zjtcbn1cbmV4cG9ydCBmdW5jdGlvbiBwMnMoYWxnLCBwMnNJbnB1dCkge1xuICAgIHJldHVybiBjb25jYXQoZW5jb2Rlci5lbmNvZGUoYWxnKSwgbmV3IFVpbnQ4QXJyYXkoWzBdKSwgcDJzSW5wdXQpO1xufVxuZnVuY3Rpb24gd3JpdGVVSW50MzJCRShidWYsIHZhbHVlLCBvZmZzZXQpIHtcbiAgICBpZiAodmFsdWUgPCAwIHx8IHZhbHVlID49IE1BWF9JTlQzMikge1xuICAgICAgICB0aHJvdyBuZXcgUmFuZ2VFcnJvcihgdmFsdWUgbXVzdCBiZSA+PSAwIGFuZCA8PSAke01BWF9JTlQzMiAtIDF9LiBSZWNlaXZlZCAke3ZhbHVlfWApO1xuICAgIH1cbiAgICBidWYuc2V0KFt2YWx1ZSA+Pj4gMjQsIHZhbHVlID4+PiAxNiwgdmFsdWUgPj4+IDgsIHZhbHVlICYgMHhmZl0sIG9mZnNldCk7XG59XG5leHBvcnQgZnVuY3Rpb24gdWludDY0YmUodmFsdWUpIHtcbiAgICBjb25zdCBoaWdoID0gTWF0aC5mbG9vcih2YWx1ZSAvIE1BWF9JTlQzMik7XG4gICAgY29uc3QgbG93ID0gdmFsdWUgJSBNQVhfSU5UMzI7XG4gICAgY29uc3QgYnVmID0gbmV3IFVpbnQ4QXJyYXkoOCk7XG4gICAgd3JpdGVVSW50MzJCRShidWYsIGhpZ2gsIDApO1xuICAgIHdyaXRlVUludDMyQkUoYnVmLCBsb3csIDQpO1xuICAgIHJldHVybiBidWY7XG59XG5leHBvcnQgZnVuY3Rpb24gdWludDMyYmUodmFsdWUpIHtcbiAgICBjb25zdCBidWYgPSBuZXcgVWludDhBcnJheSg0KTtcbiAgICB3cml0ZVVJbnQzMkJFKGJ1ZiwgdmFsdWUpO1xuICAgIHJldHVybiBidWY7XG59XG5leHBvcnQgZnVuY3Rpb24gbGVuZ3RoQW5kSW5wdXQoaW5wdXQpIHtcbiAgICByZXR1cm4gY29uY2F0KHVpbnQzMmJlKGlucHV0Lmxlbmd0aCksIGlucHV0KTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjb25jYXRLZGYoc2VjcmV0LCBiaXRzLCB2YWx1ZSkge1xuICAgIGNvbnN0IGl0ZXJhdGlvbnMgPSBNYXRoLmNlaWwoKGJpdHMgPj4gMykgLyAzMik7XG4gICAgY29uc3QgcmVzID0gbmV3IFVpbnQ4QXJyYXkoaXRlcmF0aW9ucyAqIDMyKTtcbiAgICBmb3IgKGxldCBpdGVyID0gMDsgaXRlciA8IGl0ZXJhdGlvbnM7IGl0ZXIrKykge1xuICAgICAgICBjb25zdCBidWYgPSBuZXcgVWludDhBcnJheSg0ICsgc2VjcmV0Lmxlbmd0aCArIHZhbHVlLmxlbmd0aCk7XG4gICAgICAgIGJ1Zi5zZXQodWludDMyYmUoaXRlciArIDEpKTtcbiAgICAgICAgYnVmLnNldChzZWNyZXQsIDQpO1xuICAgICAgICBidWYuc2V0KHZhbHVlLCA0ICsgc2VjcmV0Lmxlbmd0aCk7XG4gICAgICAgIHJlcy5zZXQoYXdhaXQgZGlnZXN0KCdzaGEyNTYnLCBidWYpLCBpdGVyICogMzIpO1xuICAgIH1cbiAgICByZXR1cm4gcmVzLnNsaWNlKDAsIGJpdHMgPj4gMyk7XG59XG4iLCJpbXBvcnQgeyBlbmNvZGVyLCBkZWNvZGVyIH0gZnJvbSAnLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5leHBvcnQgY29uc3QgZW5jb2RlQmFzZTY0ID0gKGlucHV0KSA9PiB7XG4gICAgbGV0IHVuZW5jb2RlZCA9IGlucHV0O1xuICAgIGlmICh0eXBlb2YgdW5lbmNvZGVkID09PSAnc3RyaW5nJykge1xuICAgICAgICB1bmVuY29kZWQgPSBlbmNvZGVyLmVuY29kZSh1bmVuY29kZWQpO1xuICAgIH1cbiAgICBjb25zdCBDSFVOS19TSVpFID0gMHg4MDAwO1xuICAgIGNvbnN0IGFyciA9IFtdO1xuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgdW5lbmNvZGVkLmxlbmd0aDsgaSArPSBDSFVOS19TSVpFKSB7XG4gICAgICAgIGFyci5wdXNoKFN0cmluZy5mcm9tQ2hhckNvZGUuYXBwbHkobnVsbCwgdW5lbmNvZGVkLnN1YmFycmF5KGksIGkgKyBDSFVOS19TSVpFKSkpO1xuICAgIH1cbiAgICByZXR1cm4gYnRvYShhcnIuam9pbignJykpO1xufTtcbmV4cG9ydCBjb25zdCBlbmNvZGUgPSAoaW5wdXQpID0+IHtcbiAgICByZXR1cm4gZW5jb2RlQmFzZTY0KGlucHV0KS5yZXBsYWNlKC89L2csICcnKS5yZXBsYWNlKC9cXCsvZywgJy0nKS5yZXBsYWNlKC9cXC8vZywgJ18nKTtcbn07XG5leHBvcnQgY29uc3QgZGVjb2RlQmFzZTY0ID0gKGVuY29kZWQpID0+IHtcbiAgICBjb25zdCBiaW5hcnkgPSBhdG9iKGVuY29kZWQpO1xuICAgIGNvbnN0IGJ5dGVzID0gbmV3IFVpbnQ4QXJyYXkoYmluYXJ5Lmxlbmd0aCk7XG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBiaW5hcnkubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgYnl0ZXNbaV0gPSBiaW5hcnkuY2hhckNvZGVBdChpKTtcbiAgICB9XG4gICAgcmV0dXJuIGJ5dGVzO1xufTtcbmV4cG9ydCBjb25zdCBkZWNvZGUgPSAoaW5wdXQpID0+IHtcbiAgICBsZXQgZW5jb2RlZCA9IGlucHV0O1xuICAgIGlmIChlbmNvZGVkIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICBlbmNvZGVkID0gZGVjb2Rlci5kZWNvZGUoZW5jb2RlZCk7XG4gICAgfVxuICAgIGVuY29kZWQgPSBlbmNvZGVkLnJlcGxhY2UoLy0vZywgJysnKS5yZXBsYWNlKC9fL2csICcvJykucmVwbGFjZSgvXFxzL2csICcnKTtcbiAgICB0cnkge1xuICAgICAgICByZXR1cm4gZGVjb2RlQmFzZTY0KGVuY29kZWQpO1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1RoZSBpbnB1dCB0byBiZSBkZWNvZGVkIGlzIG5vdCBjb3JyZWN0bHkgZW5jb2RlZC4nKTtcbiAgICB9XG59O1xuIiwiZXhwb3J0IGNsYXNzIEpPU0VFcnJvciBleHRlbmRzIEVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcihtZXNzYWdlLCBvcHRpb25zKSB7XG4gICAgICAgIHN1cGVyKG1lc3NhZ2UsIG9wdGlvbnMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pPU0VfR0VORVJJQyc7XG4gICAgICAgIHRoaXMubmFtZSA9IHRoaXMuY29uc3RydWN0b3IubmFtZTtcbiAgICAgICAgRXJyb3IuY2FwdHVyZVN0YWNrVHJhY2U/Lih0aGlzLCB0aGlzLmNvbnN0cnVjdG9yKTtcbiAgICB9XG59XG5KT1NFRXJyb3IuY29kZSA9ICdFUlJfSk9TRV9HRU5FUklDJztcbmV4cG9ydCBjbGFzcyBKV1RDbGFpbVZhbGlkYXRpb25GYWlsZWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKG1lc3NhZ2UsIHBheWxvYWQsIGNsYWltID0gJ3Vuc3BlY2lmaWVkJywgcmVhc29uID0gJ3Vuc3BlY2lmaWVkJykge1xuICAgICAgICBzdXBlcihtZXNzYWdlLCB7IGNhdXNlOiB7IGNsYWltLCByZWFzb24sIHBheWxvYWQgfSB9KTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV1RfQ0xBSU1fVkFMSURBVElPTl9GQUlMRUQnO1xuICAgICAgICB0aGlzLmNsYWltID0gY2xhaW07XG4gICAgICAgIHRoaXMucmVhc29uID0gcmVhc29uO1xuICAgICAgICB0aGlzLnBheWxvYWQgPSBwYXlsb2FkO1xuICAgIH1cbn1cbkpXVENsYWltVmFsaWRhdGlvbkZhaWxlZC5jb2RlID0gJ0VSUl9KV1RfQ0xBSU1fVkFMSURBVElPTl9GQUlMRUQnO1xuZXhwb3J0IGNsYXNzIEpXVEV4cGlyZWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKG1lc3NhZ2UsIHBheWxvYWQsIGNsYWltID0gJ3Vuc3BlY2lmaWVkJywgcmVhc29uID0gJ3Vuc3BlY2lmaWVkJykge1xuICAgICAgICBzdXBlcihtZXNzYWdlLCB7IGNhdXNlOiB7IGNsYWltLCByZWFzb24sIHBheWxvYWQgfSB9KTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV1RfRVhQSVJFRCc7XG4gICAgICAgIHRoaXMuY2xhaW0gPSBjbGFpbTtcbiAgICAgICAgdGhpcy5yZWFzb24gPSByZWFzb247XG4gICAgICAgIHRoaXMucGF5bG9hZCA9IHBheWxvYWQ7XG4gICAgfVxufVxuSldURXhwaXJlZC5jb2RlID0gJ0VSUl9KV1RfRVhQSVJFRCc7XG5leHBvcnQgY2xhc3MgSk9TRUFsZ05vdEFsbG93ZWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pPU0VfQUxHX05PVF9BTExPV0VEJztcbiAgICB9XG59XG5KT1NFQWxnTm90QWxsb3dlZC5jb2RlID0gJ0VSUl9KT1NFX0FMR19OT1RfQUxMT1dFRCc7XG5leHBvcnQgY2xhc3MgSk9TRU5vdFN1cHBvcnRlZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSk9TRV9OT1RfU1VQUE9SVEVEJztcbiAgICB9XG59XG5KT1NFTm90U3VwcG9ydGVkLmNvZGUgPSAnRVJSX0pPU0VfTk9UX1NVUFBPUlRFRCc7XG5leHBvcnQgY2xhc3MgSldFRGVjcnlwdGlvbkZhaWxlZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IobWVzc2FnZSA9ICdkZWNyeXB0aW9uIG9wZXJhdGlvbiBmYWlsZWQnLCBvcHRpb25zKSB7XG4gICAgICAgIHN1cGVyKG1lc3NhZ2UsIG9wdGlvbnMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXRV9ERUNSWVBUSU9OX0ZBSUxFRCc7XG4gICAgfVxufVxuSldFRGVjcnlwdGlvbkZhaWxlZC5jb2RlID0gJ0VSUl9KV0VfREVDUllQVElPTl9GQUlMRUQnO1xuZXhwb3J0IGNsYXNzIEpXRUludmFsaWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXRV9JTlZBTElEJztcbiAgICB9XG59XG5KV0VJbnZhbGlkLmNvZGUgPSAnRVJSX0pXRV9JTlZBTElEJztcbmV4cG9ydCBjbGFzcyBKV1NJbnZhbGlkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV1NfSU5WQUxJRCc7XG4gICAgfVxufVxuSldTSW52YWxpZC5jb2RlID0gJ0VSUl9KV1NfSU5WQUxJRCc7XG5leHBvcnQgY2xhc3MgSldUSW52YWxpZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldUX0lOVkFMSUQnO1xuICAgIH1cbn1cbkpXVEludmFsaWQuY29kZSA9ICdFUlJfSldUX0lOVkFMSUQnO1xuZXhwb3J0IGNsYXNzIEpXS0ludmFsaWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXS19JTlZBTElEJztcbiAgICB9XG59XG5KV0tJbnZhbGlkLmNvZGUgPSAnRVJSX0pXS19JTlZBTElEJztcbmV4cG9ydCBjbGFzcyBKV0tTSW52YWxpZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldLU19JTlZBTElEJztcbiAgICB9XG59XG5KV0tTSW52YWxpZC5jb2RlID0gJ0VSUl9KV0tTX0lOVkFMSUQnO1xuZXhwb3J0IGNsYXNzIEpXS1NOb01hdGNoaW5nS2V5IGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcihtZXNzYWdlID0gJ25vIGFwcGxpY2FibGUga2V5IGZvdW5kIGluIHRoZSBKU09OIFdlYiBLZXkgU2V0Jywgb3B0aW9ucykge1xuICAgICAgICBzdXBlcihtZXNzYWdlLCBvcHRpb25zKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0tTX05PX01BVENISU5HX0tFWSc7XG4gICAgfVxufVxuSldLU05vTWF0Y2hpbmdLZXkuY29kZSA9ICdFUlJfSldLU19OT19NQVRDSElOR19LRVknO1xuZXhwb3J0IGNsYXNzIEpXS1NNdWx0aXBsZU1hdGNoaW5nS2V5cyBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IobWVzc2FnZSA9ICdtdWx0aXBsZSBtYXRjaGluZyBrZXlzIGZvdW5kIGluIHRoZSBKU09OIFdlYiBLZXkgU2V0Jywgb3B0aW9ucykge1xuICAgICAgICBzdXBlcihtZXNzYWdlLCBvcHRpb25zKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0tTX01VTFRJUExFX01BVENISU5HX0tFWVMnO1xuICAgIH1cbn1cblN5bWJvbC5hc3luY0l0ZXJhdG9yO1xuSldLU011bHRpcGxlTWF0Y2hpbmdLZXlzLmNvZGUgPSAnRVJSX0pXS1NfTVVMVElQTEVfTUFUQ0hJTkdfS0VZUyc7XG5leHBvcnQgY2xhc3MgSldLU1RpbWVvdXQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKG1lc3NhZ2UgPSAncmVxdWVzdCB0aW1lZCBvdXQnLCBvcHRpb25zKSB7XG4gICAgICAgIHN1cGVyKG1lc3NhZ2UsIG9wdGlvbnMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXS1NfVElNRU9VVCc7XG4gICAgfVxufVxuSldLU1RpbWVvdXQuY29kZSA9ICdFUlJfSldLU19USU1FT1VUJztcbmV4cG9ydCBjbGFzcyBKV1NTaWduYXR1cmVWZXJpZmljYXRpb25GYWlsZWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKG1lc3NhZ2UgPSAnc2lnbmF0dXJlIHZlcmlmaWNhdGlvbiBmYWlsZWQnLCBvcHRpb25zKSB7XG4gICAgICAgIHN1cGVyKG1lc3NhZ2UsIG9wdGlvbnMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXU19TSUdOQVRVUkVfVkVSSUZJQ0FUSU9OX0ZBSUxFRCc7XG4gICAgfVxufVxuSldTU2lnbmF0dXJlVmVyaWZpY2F0aW9uRmFpbGVkLmNvZGUgPSAnRVJSX0pXU19TSUdOQVRVUkVfVkVSSUZJQ0FUSU9OX0ZBSUxFRCc7XG4iLCJpbXBvcnQgY3J5cHRvIGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmV4cG9ydCBkZWZhdWx0IGNyeXB0by5nZXRSYW5kb21WYWx1ZXMuYmluZChjcnlwdG8pO1xuIiwiaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCByYW5kb20gZnJvbSAnLi4vcnVudGltZS9yYW5kb20uanMnO1xuZXhwb3J0IGZ1bmN0aW9uIGJpdExlbmd0aChhbGcpIHtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdBMTI4R0NNJzpcbiAgICAgICAgY2FzZSAnQTEyOEdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTE5MkdDTSc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ00nOlxuICAgICAgICBjYXNlICdBMjU2R0NNS1cnOlxuICAgICAgICAgICAgcmV0dXJuIDk2O1xuICAgICAgICBjYXNlICdBMTI4Q0JDLUhTMjU2JzpcbiAgICAgICAgY2FzZSAnQTE5MkNCQy1IUzM4NCc6XG4gICAgICAgIGNhc2UgJ0EyNTZDQkMtSFM1MTInOlxuICAgICAgICAgICAgcmV0dXJuIDEyODtcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKGBVbnN1cHBvcnRlZCBKV0UgQWxnb3JpdGhtOiAke2FsZ31gKTtcbiAgICB9XG59XG5leHBvcnQgZGVmYXVsdCAoYWxnKSA9PiByYW5kb20obmV3IFVpbnQ4QXJyYXkoYml0TGVuZ3RoKGFsZykgPj4gMykpO1xuIiwiaW1wb3J0IHsgSldFSW52YWxpZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IGJpdExlbmd0aCB9IGZyb20gJy4vaXYuanMnO1xuY29uc3QgY2hlY2tJdkxlbmd0aCA9IChlbmMsIGl2KSA9PiB7XG4gICAgaWYgKGl2Lmxlbmd0aCA8PCAzICE9PSBiaXRMZW5ndGgoZW5jKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSW52YWxpZCBJbml0aWFsaXphdGlvbiBWZWN0b3IgbGVuZ3RoJyk7XG4gICAgfVxufTtcbmV4cG9ydCBkZWZhdWx0IGNoZWNrSXZMZW5ndGg7XG4iLCJpbXBvcnQgeyBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuY29uc3QgY2hlY2tDZWtMZW5ndGggPSAoY2VrLCBleHBlY3RlZCkgPT4ge1xuICAgIGNvbnN0IGFjdHVhbCA9IGNlay5ieXRlTGVuZ3RoIDw8IDM7XG4gICAgaWYgKGFjdHVhbCAhPT0gZXhwZWN0ZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEludmFsaWQgQ29udGVudCBFbmNyeXB0aW9uIEtleSBsZW5ndGguIEV4cGVjdGVkICR7ZXhwZWN0ZWR9IGJpdHMsIGdvdCAke2FjdHVhbH0gYml0c2ApO1xuICAgIH1cbn07XG5leHBvcnQgZGVmYXVsdCBjaGVja0Nla0xlbmd0aDtcbiIsImNvbnN0IHRpbWluZ1NhZmVFcXVhbCA9IChhLCBiKSA9PiB7XG4gICAgaWYgKCEoYSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0ZpcnN0IGFyZ3VtZW50IG11c3QgYmUgYSBidWZmZXInKTtcbiAgICB9XG4gICAgaWYgKCEoYiBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1NlY29uZCBhcmd1bWVudCBtdXN0IGJlIGEgYnVmZmVyJyk7XG4gICAgfVxuICAgIGlmIChhLmxlbmd0aCAhPT0gYi5sZW5ndGgpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignSW5wdXQgYnVmZmVycyBtdXN0IGhhdmUgdGhlIHNhbWUgbGVuZ3RoJyk7XG4gICAgfVxuICAgIGNvbnN0IGxlbiA9IGEubGVuZ3RoO1xuICAgIGxldCBvdXQgPSAwO1xuICAgIGxldCBpID0gLTE7XG4gICAgd2hpbGUgKCsraSA8IGxlbikge1xuICAgICAgICBvdXQgfD0gYVtpXSBeIGJbaV07XG4gICAgfVxuICAgIHJldHVybiBvdXQgPT09IDA7XG59O1xuZXhwb3J0IGRlZmF1bHQgdGltaW5nU2FmZUVxdWFsO1xuIiwiZnVuY3Rpb24gdW51c2FibGUobmFtZSwgcHJvcCA9ICdhbGdvcml0aG0ubmFtZScpIHtcbiAgICByZXR1cm4gbmV3IFR5cGVFcnJvcihgQ3J5cHRvS2V5IGRvZXMgbm90IHN1cHBvcnQgdGhpcyBvcGVyYXRpb24sIGl0cyAke3Byb3B9IG11c3QgYmUgJHtuYW1lfWApO1xufVxuZnVuY3Rpb24gaXNBbGdvcml0aG0oYWxnb3JpdGhtLCBuYW1lKSB7XG4gICAgcmV0dXJuIGFsZ29yaXRobS5uYW1lID09PSBuYW1lO1xufVxuZnVuY3Rpb24gZ2V0SGFzaExlbmd0aChoYXNoKSB7XG4gICAgcmV0dXJuIHBhcnNlSW50KGhhc2gubmFtZS5zbGljZSg0KSwgMTApO1xufVxuZnVuY3Rpb24gZ2V0TmFtZWRDdXJ2ZShhbGcpIHtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdFUzI1Nic6XG4gICAgICAgICAgICByZXR1cm4gJ1AtMjU2JztcbiAgICAgICAgY2FzZSAnRVMzODQnOlxuICAgICAgICAgICAgcmV0dXJuICdQLTM4NCc7XG4gICAgICAgIGNhc2UgJ0VTNTEyJzpcbiAgICAgICAgICAgIHJldHVybiAnUC01MjEnO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCd1bnJlYWNoYWJsZScpO1xuICAgIH1cbn1cbmZ1bmN0aW9uIGNoZWNrVXNhZ2Uoa2V5LCB1c2FnZXMpIHtcbiAgICBpZiAodXNhZ2VzLmxlbmd0aCAmJiAhdXNhZ2VzLnNvbWUoKGV4cGVjdGVkKSA9PiBrZXkudXNhZ2VzLmluY2x1ZGVzKGV4cGVjdGVkKSkpIHtcbiAgICAgICAgbGV0IG1zZyA9ICdDcnlwdG9LZXkgZG9lcyBub3Qgc3VwcG9ydCB0aGlzIG9wZXJhdGlvbiwgaXRzIHVzYWdlcyBtdXN0IGluY2x1ZGUgJztcbiAgICAgICAgaWYgKHVzYWdlcy5sZW5ndGggPiAyKSB7XG4gICAgICAgICAgICBjb25zdCBsYXN0ID0gdXNhZ2VzLnBvcCgpO1xuICAgICAgICAgICAgbXNnICs9IGBvbmUgb2YgJHt1c2FnZXMuam9pbignLCAnKX0sIG9yICR7bGFzdH0uYDtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICh1c2FnZXMubGVuZ3RoID09PSAyKSB7XG4gICAgICAgICAgICBtc2cgKz0gYG9uZSBvZiAke3VzYWdlc1swXX0gb3IgJHt1c2FnZXNbMV19LmA7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBtc2cgKz0gYCR7dXNhZ2VzWzBdfS5gO1xuICAgICAgICB9XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IobXNnKTtcbiAgICB9XG59XG5leHBvcnQgZnVuY3Rpb24gY2hlY2tTaWdDcnlwdG9LZXkoa2V5LCBhbGcsIC4uLnVzYWdlcykge1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ0hTMjU2JzpcbiAgICAgICAgY2FzZSAnSFMzODQnOlxuICAgICAgICBjYXNlICdIUzUxMic6IHtcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ0hNQUMnKSlcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnSE1BQycpO1xuICAgICAgICAgICAgY29uc3QgZXhwZWN0ZWQgPSBwYXJzZUludChhbGcuc2xpY2UoMiksIDEwKTtcbiAgICAgICAgICAgIGNvbnN0IGFjdHVhbCA9IGdldEhhc2hMZW5ndGgoa2V5LmFsZ29yaXRobS5oYXNoKTtcbiAgICAgICAgICAgIGlmIChhY3R1YWwgIT09IGV4cGVjdGVkKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKGBTSEEtJHtleHBlY3RlZH1gLCAnYWxnb3JpdGhtLmhhc2gnKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ1JTMjU2JzpcbiAgICAgICAgY2FzZSAnUlMzODQnOlxuICAgICAgICBjYXNlICdSUzUxMic6IHtcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ1JTQVNTQS1QS0NTMS12MV81JykpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ1JTQVNTQS1QS0NTMS12MV81Jyk7XG4gICAgICAgICAgICBjb25zdCBleHBlY3RlZCA9IHBhcnNlSW50KGFsZy5zbGljZSgyKSwgMTApO1xuICAgICAgICAgICAgY29uc3QgYWN0dWFsID0gZ2V0SGFzaExlbmd0aChrZXkuYWxnb3JpdGhtLmhhc2gpO1xuICAgICAgICAgICAgaWYgKGFjdHVhbCAhPT0gZXhwZWN0ZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoYFNIQS0ke2V4cGVjdGVkfWAsICdhbGdvcml0aG0uaGFzaCcpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnUFMyNTYnOlxuICAgICAgICBjYXNlICdQUzM4NCc6XG4gICAgICAgIGNhc2UgJ1BTNTEyJzoge1xuICAgICAgICAgICAgaWYgKCFpc0FsZ29yaXRobShrZXkuYWxnb3JpdGhtLCAnUlNBLVBTUycpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdSU0EtUFNTJyk7XG4gICAgICAgICAgICBjb25zdCBleHBlY3RlZCA9IHBhcnNlSW50KGFsZy5zbGljZSgyKSwgMTApO1xuICAgICAgICAgICAgY29uc3QgYWN0dWFsID0gZ2V0SGFzaExlbmd0aChrZXkuYWxnb3JpdGhtLmhhc2gpO1xuICAgICAgICAgICAgaWYgKGFjdHVhbCAhPT0gZXhwZWN0ZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoYFNIQS0ke2V4cGVjdGVkfWAsICdhbGdvcml0aG0uaGFzaCcpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnRWREU0EnOiB7XG4gICAgICAgICAgICBpZiAoa2V5LmFsZ29yaXRobS5uYW1lICE9PSAnRWQyNTUxOScgJiYga2V5LmFsZ29yaXRobS5uYW1lICE9PSAnRWQ0NDgnKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ0VkMjU1MTkgb3IgRWQ0NDgnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0VTMjU2JzpcbiAgICAgICAgY2FzZSAnRVMzODQnOlxuICAgICAgICBjYXNlICdFUzUxMic6IHtcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ0VDRFNBJykpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ0VDRFNBJyk7XG4gICAgICAgICAgICBjb25zdCBleHBlY3RlZCA9IGdldE5hbWVkQ3VydmUoYWxnKTtcbiAgICAgICAgICAgIGNvbnN0IGFjdHVhbCA9IGtleS5hbGdvcml0aG0ubmFtZWRDdXJ2ZTtcbiAgICAgICAgICAgIGlmIChhY3R1YWwgIT09IGV4cGVjdGVkKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKGV4cGVjdGVkLCAnYWxnb3JpdGhtLm5hbWVkQ3VydmUnKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdDcnlwdG9LZXkgZG9lcyBub3Qgc3VwcG9ydCB0aGlzIG9wZXJhdGlvbicpO1xuICAgIH1cbiAgICBjaGVja1VzYWdlKGtleSwgdXNhZ2VzKTtcbn1cbmV4cG9ydCBmdW5jdGlvbiBjaGVja0VuY0NyeXB0b0tleShrZXksIGFsZywgLi4udXNhZ2VzKSB7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnQTEyOEdDTSc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ00nOlxuICAgICAgICBjYXNlICdBMjU2R0NNJzoge1xuICAgICAgICAgICAgaWYgKCFpc0FsZ29yaXRobShrZXkuYWxnb3JpdGhtLCAnQUVTLUdDTScpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdBRVMtR0NNJyk7XG4gICAgICAgICAgICBjb25zdCBleHBlY3RlZCA9IHBhcnNlSW50KGFsZy5zbGljZSgxLCA0KSwgMTApO1xuICAgICAgICAgICAgY29uc3QgYWN0dWFsID0ga2V5LmFsZ29yaXRobS5sZW5ndGg7XG4gICAgICAgICAgICBpZiAoYWN0dWFsICE9PSBleHBlY3RlZClcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZShleHBlY3RlZCwgJ2FsZ29yaXRobS5sZW5ndGgnKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ0FFUy1LVycpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdBRVMtS1cnKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGVjdGVkID0gcGFyc2VJbnQoYWxnLnNsaWNlKDEsIDQpLCAxMCk7XG4gICAgICAgICAgICBjb25zdCBhY3R1YWwgPSBrZXkuYWxnb3JpdGhtLmxlbmd0aDtcbiAgICAgICAgICAgIGlmIChhY3R1YWwgIT09IGV4cGVjdGVkKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKGV4cGVjdGVkLCAnYWxnb3JpdGhtLmxlbmd0aCcpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnRUNESCc6IHtcbiAgICAgICAgICAgIHN3aXRjaCAoa2V5LmFsZ29yaXRobS5uYW1lKSB7XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESCc6XG4gICAgICAgICAgICAgICAgY2FzZSAnWDI1NTE5JzpcbiAgICAgICAgICAgICAgICBjYXNlICdYNDQ4JzpcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ0VDREgsIFgyNTUxOSwgb3IgWDQ0OCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnUEJFUzItSFMyNTYrQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnUEJFUzItSFMzODQrQTE5MktXJzpcbiAgICAgICAgY2FzZSAnUEJFUzItSFM1MTIrQTI1NktXJzpcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ1BCS0RGMicpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdQQktERjInKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdSU0EtT0FFUCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTI1Nic6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTM4NCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTUxMic6IHtcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ1JTQS1PQUVQJykpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ1JTQS1PQUVQJyk7XG4gICAgICAgICAgICBjb25zdCBleHBlY3RlZCA9IHBhcnNlSW50KGFsZy5zbGljZSg5KSwgMTApIHx8IDE7XG4gICAgICAgICAgICBjb25zdCBhY3R1YWwgPSBnZXRIYXNoTGVuZ3RoKGtleS5hbGdvcml0aG0uaGFzaCk7XG4gICAgICAgICAgICBpZiAoYWN0dWFsICE9PSBleHBlY3RlZClcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZShgU0hBLSR7ZXhwZWN0ZWR9YCwgJ2FsZ29yaXRobS5oYXNoJyk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignQ3J5cHRvS2V5IGRvZXMgbm90IHN1cHBvcnQgdGhpcyBvcGVyYXRpb24nKTtcbiAgICB9XG4gICAgY2hlY2tVc2FnZShrZXksIHVzYWdlcyk7XG59XG4iLCJmdW5jdGlvbiBtZXNzYWdlKG1zZywgYWN0dWFsLCAuLi50eXBlcykge1xuICAgIHR5cGVzID0gdHlwZXMuZmlsdGVyKEJvb2xlYW4pO1xuICAgIGlmICh0eXBlcy5sZW5ndGggPiAyKSB7XG4gICAgICAgIGNvbnN0IGxhc3QgPSB0eXBlcy5wb3AoKTtcbiAgICAgICAgbXNnICs9IGBvbmUgb2YgdHlwZSAke3R5cGVzLmpvaW4oJywgJyl9LCBvciAke2xhc3R9LmA7XG4gICAgfVxuICAgIGVsc2UgaWYgKHR5cGVzLmxlbmd0aCA9PT0gMikge1xuICAgICAgICBtc2cgKz0gYG9uZSBvZiB0eXBlICR7dHlwZXNbMF19IG9yICR7dHlwZXNbMV19LmA7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBtc2cgKz0gYG9mIHR5cGUgJHt0eXBlc1swXX0uYDtcbiAgICB9XG4gICAgaWYgKGFjdHVhbCA9PSBudWxsKSB7XG4gICAgICAgIG1zZyArPSBgIFJlY2VpdmVkICR7YWN0dWFsfWA7XG4gICAgfVxuICAgIGVsc2UgaWYgKHR5cGVvZiBhY3R1YWwgPT09ICdmdW5jdGlvbicgJiYgYWN0dWFsLm5hbWUpIHtcbiAgICAgICAgbXNnICs9IGAgUmVjZWl2ZWQgZnVuY3Rpb24gJHthY3R1YWwubmFtZX1gO1xuICAgIH1cbiAgICBlbHNlIGlmICh0eXBlb2YgYWN0dWFsID09PSAnb2JqZWN0JyAmJiBhY3R1YWwgIT0gbnVsbCkge1xuICAgICAgICBpZiAoYWN0dWFsLmNvbnN0cnVjdG9yPy5uYW1lKSB7XG4gICAgICAgICAgICBtc2cgKz0gYCBSZWNlaXZlZCBhbiBpbnN0YW5jZSBvZiAke2FjdHVhbC5jb25zdHJ1Y3Rvci5uYW1lfWA7XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIG1zZztcbn1cbmV4cG9ydCBkZWZhdWx0IChhY3R1YWwsIC4uLnR5cGVzKSA9PiB7XG4gICAgcmV0dXJuIG1lc3NhZ2UoJ0tleSBtdXN0IGJlICcsIGFjdHVhbCwgLi4udHlwZXMpO1xufTtcbmV4cG9ydCBmdW5jdGlvbiB3aXRoQWxnKGFsZywgYWN0dWFsLCAuLi50eXBlcykge1xuICAgIHJldHVybiBtZXNzYWdlKGBLZXkgZm9yIHRoZSAke2FsZ30gYWxnb3JpdGhtIG11c3QgYmUgYCwgYWN0dWFsLCAuLi50eXBlcyk7XG59XG4iLCJpbXBvcnQgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmV4cG9ydCBkZWZhdWx0IChrZXkpID0+IHtcbiAgICBpZiAoaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG4gICAgcmV0dXJuIGtleT8uW1N5bWJvbC50b1N0cmluZ1RhZ10gPT09ICdLZXlPYmplY3QnO1xufTtcbmV4cG9ydCBjb25zdCB0eXBlcyA9IFsnQ3J5cHRvS2V5J107XG4iLCJpbXBvcnQgeyBjb25jYXQsIHVpbnQ2NGJlIH0gZnJvbSAnLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgY2hlY2tJdkxlbmd0aCBmcm9tICcuLi9saWIvY2hlY2tfaXZfbGVuZ3RoLmpzJztcbmltcG9ydCBjaGVja0Nla0xlbmd0aCBmcm9tICcuL2NoZWNrX2Nla19sZW5ndGguanMnO1xuaW1wb3J0IHRpbWluZ1NhZmVFcXVhbCBmcm9tICcuL3RpbWluZ19zYWZlX2VxdWFsLmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQsIEpXRURlY3J5cHRpb25GYWlsZWQsIEpXRUludmFsaWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tFbmNDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuYXN5bmMgZnVuY3Rpb24gY2JjRGVjcnlwdChlbmMsIGNlaywgY2lwaGVydGV4dCwgaXYsIHRhZywgYWFkKSB7XG4gICAgaWYgKCEoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoY2VrLCAnVWludDhBcnJheScpKTtcbiAgICB9XG4gICAgY29uc3Qga2V5U2l6ZSA9IHBhcnNlSW50KGVuYy5zbGljZSgxLCA0KSwgMTApO1xuICAgIGNvbnN0IGVuY0tleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBjZWsuc3ViYXJyYXkoa2V5U2l6ZSA+PiAzKSwgJ0FFUy1DQkMnLCBmYWxzZSwgWydkZWNyeXB0J10pO1xuICAgIGNvbnN0IG1hY0tleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBjZWsuc3ViYXJyYXkoMCwga2V5U2l6ZSA+PiAzKSwge1xuICAgICAgICBoYXNoOiBgU0hBLSR7a2V5U2l6ZSA8PCAxfWAsXG4gICAgICAgIG5hbWU6ICdITUFDJyxcbiAgICB9LCBmYWxzZSwgWydzaWduJ10pO1xuICAgIGNvbnN0IG1hY0RhdGEgPSBjb25jYXQoYWFkLCBpdiwgY2lwaGVydGV4dCwgdWludDY0YmUoYWFkLmxlbmd0aCA8PCAzKSk7XG4gICAgY29uc3QgZXhwZWN0ZWRUYWcgPSBuZXcgVWludDhBcnJheSgoYXdhaXQgY3J5cHRvLnN1YnRsZS5zaWduKCdITUFDJywgbWFjS2V5LCBtYWNEYXRhKSkuc2xpY2UoMCwga2V5U2l6ZSA+PiAzKSk7XG4gICAgbGV0IG1hY0NoZWNrUGFzc2VkO1xuICAgIHRyeSB7XG4gICAgICAgIG1hY0NoZWNrUGFzc2VkID0gdGltaW5nU2FmZUVxdWFsKHRhZywgZXhwZWN0ZWRUYWcpO1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgfVxuICAgIGlmICghbWFjQ2hlY2tQYXNzZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRURlY3J5cHRpb25GYWlsZWQoKTtcbiAgICB9XG4gICAgbGV0IHBsYWludGV4dDtcbiAgICB0cnkge1xuICAgICAgICBwbGFpbnRleHQgPSBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmRlY3J5cHQoeyBpdiwgbmFtZTogJ0FFUy1DQkMnIH0sIGVuY0tleSwgY2lwaGVydGV4dCkpO1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgfVxuICAgIGlmICghcGxhaW50ZXh0KSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VEZWNyeXB0aW9uRmFpbGVkKCk7XG4gICAgfVxuICAgIHJldHVybiBwbGFpbnRleHQ7XG59XG5hc3luYyBmdW5jdGlvbiBnY21EZWNyeXB0KGVuYywgY2VrLCBjaXBoZXJ0ZXh0LCBpdiwgdGFnLCBhYWQpIHtcbiAgICBsZXQgZW5jS2V5O1xuICAgIGlmIChjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIGVuY0tleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBjZWssICdBRVMtR0NNJywgZmFsc2UsIFsnZGVjcnlwdCddKTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIGNoZWNrRW5jQ3J5cHRvS2V5KGNlaywgZW5jLCAnZGVjcnlwdCcpO1xuICAgICAgICBlbmNLZXkgPSBjZWs7XG4gICAgfVxuICAgIHRyeSB7XG4gICAgICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmRlY3J5cHQoe1xuICAgICAgICAgICAgYWRkaXRpb25hbERhdGE6IGFhZCxcbiAgICAgICAgICAgIGl2LFxuICAgICAgICAgICAgbmFtZTogJ0FFUy1HQ00nLFxuICAgICAgICAgICAgdGFnTGVuZ3RoOiAxMjgsXG4gICAgICAgIH0sIGVuY0tleSwgY29uY2F0KGNpcGhlcnRleHQsIHRhZykpKTtcbiAgICB9XG4gICAgY2F0Y2gge1xuICAgICAgICB0aHJvdyBuZXcgSldFRGVjcnlwdGlvbkZhaWxlZCgpO1xuICAgIH1cbn1cbmNvbnN0IGRlY3J5cHQgPSBhc3luYyAoZW5jLCBjZWssIGNpcGhlcnRleHQsIGl2LCB0YWcsIGFhZCkgPT4ge1xuICAgIGlmICghaXNDcnlwdG9LZXkoY2VrKSAmJiAhKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGNlaywgLi4udHlwZXMsICdVaW50OEFycmF5JykpO1xuICAgIH1cbiAgICBpZiAoIWl2KSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgSW5pdGlhbGl6YXRpb24gVmVjdG9yIG1pc3NpbmcnKTtcbiAgICB9XG4gICAgaWYgKCF0YWcpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBBdXRoZW50aWNhdGlvbiBUYWcgbWlzc2luZycpO1xuICAgIH1cbiAgICBjaGVja0l2TGVuZ3RoKGVuYywgaXYpO1xuICAgIHN3aXRjaCAoZW5jKSB7XG4gICAgICAgIGNhc2UgJ0ExMjhDQkMtSFMyNTYnOlxuICAgICAgICBjYXNlICdBMTkyQ0JDLUhTMzg0JzpcbiAgICAgICAgY2FzZSAnQTI1NkNCQy1IUzUxMic6XG4gICAgICAgICAgICBpZiAoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSlcbiAgICAgICAgICAgICAgICBjaGVja0Nla0xlbmd0aChjZWssIHBhcnNlSW50KGVuYy5zbGljZSgtMyksIDEwKSk7XG4gICAgICAgICAgICByZXR1cm4gY2JjRGVjcnlwdChlbmMsIGNlaywgY2lwaGVydGV4dCwgaXYsIHRhZywgYWFkKTtcbiAgICAgICAgY2FzZSAnQTEyOEdDTSc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ00nOlxuICAgICAgICBjYXNlICdBMjU2R0NNJzpcbiAgICAgICAgICAgIGlmIChjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KVxuICAgICAgICAgICAgICAgIGNoZWNrQ2VrTGVuZ3RoKGNlaywgcGFyc2VJbnQoZW5jLnNsaWNlKDEsIDQpLCAxMCkpO1xuICAgICAgICAgICAgcmV0dXJuIGdjbURlY3J5cHQoZW5jLCBjZWssIGNpcGhlcnRleHQsIGl2LCB0YWcsIGFhZCk7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnVW5zdXBwb3J0ZWQgSldFIENvbnRlbnQgRW5jcnlwdGlvbiBBbGdvcml0aG0nKTtcbiAgICB9XG59O1xuZXhwb3J0IGRlZmF1bHQgZGVjcnlwdDtcbiIsImNvbnN0IGlzRGlzam9pbnQgPSAoLi4uaGVhZGVycykgPT4ge1xuICAgIGNvbnN0IHNvdXJjZXMgPSBoZWFkZXJzLmZpbHRlcihCb29sZWFuKTtcbiAgICBpZiAoc291cmNlcy5sZW5ndGggPT09IDAgfHwgc291cmNlcy5sZW5ndGggPT09IDEpIHtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIGxldCBhY2M7XG4gICAgZm9yIChjb25zdCBoZWFkZXIgb2Ygc291cmNlcykge1xuICAgICAgICBjb25zdCBwYXJhbWV0ZXJzID0gT2JqZWN0LmtleXMoaGVhZGVyKTtcbiAgICAgICAgaWYgKCFhY2MgfHwgYWNjLnNpemUgPT09IDApIHtcbiAgICAgICAgICAgIGFjYyA9IG5ldyBTZXQocGFyYW1ldGVycyk7XG4gICAgICAgICAgICBjb250aW51ZTtcbiAgICAgICAgfVxuICAgICAgICBmb3IgKGNvbnN0IHBhcmFtZXRlciBvZiBwYXJhbWV0ZXJzKSB7XG4gICAgICAgICAgICBpZiAoYWNjLmhhcyhwYXJhbWV0ZXIpKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYWNjLmFkZChwYXJhbWV0ZXIpO1xuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiB0cnVlO1xufTtcbmV4cG9ydCBkZWZhdWx0IGlzRGlzam9pbnQ7XG4iLCJmdW5jdGlvbiBpc09iamVjdExpa2UodmFsdWUpIHtcbiAgICByZXR1cm4gdHlwZW9mIHZhbHVlID09PSAnb2JqZWN0JyAmJiB2YWx1ZSAhPT0gbnVsbDtcbn1cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGlzT2JqZWN0KGlucHV0KSB7XG4gICAgaWYgKCFpc09iamVjdExpa2UoaW5wdXQpIHx8IE9iamVjdC5wcm90b3R5cGUudG9TdHJpbmcuY2FsbChpbnB1dCkgIT09ICdbb2JqZWN0IE9iamVjdF0nKSB7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gICAgaWYgKE9iamVjdC5nZXRQcm90b3R5cGVPZihpbnB1dCkgPT09IG51bGwpIHtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIGxldCBwcm90byA9IGlucHV0O1xuICAgIHdoaWxlIChPYmplY3QuZ2V0UHJvdG90eXBlT2YocHJvdG8pICE9PSBudWxsKSB7XG4gICAgICAgIHByb3RvID0gT2JqZWN0LmdldFByb3RvdHlwZU9mKHByb3RvKTtcbiAgICB9XG4gICAgcmV0dXJuIE9iamVjdC5nZXRQcm90b3R5cGVPZihpbnB1dCkgPT09IHByb3RvO1xufVxuIiwiY29uc3QgYm9ndXNXZWJDcnlwdG8gPSBbXG4gICAgeyBoYXNoOiAnU0hBLTI1NicsIG5hbWU6ICdITUFDJyB9LFxuICAgIHRydWUsXG4gICAgWydzaWduJ10sXG5dO1xuZXhwb3J0IGRlZmF1bHQgYm9ndXNXZWJDcnlwdG87XG4iLCJpbXBvcnQgYm9ndXNXZWJDcnlwdG8gZnJvbSAnLi9ib2d1cy5qcyc7XG5pbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tFbmNDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuZnVuY3Rpb24gY2hlY2tLZXlTaXplKGtleSwgYWxnKSB7XG4gICAgaWYgKGtleS5hbGdvcml0aG0ubGVuZ3RoICE9PSBwYXJzZUludChhbGcuc2xpY2UoMSwgNCksIDEwKSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGBJbnZhbGlkIGtleSBzaXplIGZvciBhbGc6ICR7YWxnfWApO1xuICAgIH1cbn1cbmZ1bmN0aW9uIGdldENyeXB0b0tleShrZXksIGFsZywgdXNhZ2UpIHtcbiAgICBpZiAoaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICBjaGVja0VuY0NyeXB0b0tleShrZXksIGFsZywgdXNhZ2UpO1xuICAgICAgICByZXR1cm4ga2V5O1xuICAgIH1cbiAgICBpZiAoa2V5IGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICByZXR1cm4gY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGtleSwgJ0FFUy1LVycsIHRydWUsIFt1c2FnZV0pO1xuICAgIH1cbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzLCAnVWludDhBcnJheScpKTtcbn1cbmV4cG9ydCBjb25zdCB3cmFwID0gYXN5bmMgKGFsZywga2V5LCBjZWspID0+IHtcbiAgICBjb25zdCBjcnlwdG9LZXkgPSBhd2FpdCBnZXRDcnlwdG9LZXkoa2V5LCBhbGcsICd3cmFwS2V5Jyk7XG4gICAgY2hlY2tLZXlTaXplKGNyeXB0b0tleSwgYWxnKTtcbiAgICBjb25zdCBjcnlwdG9LZXlDZWsgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLCAuLi5ib2d1c1dlYkNyeXB0byk7XG4gICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUud3JhcEtleSgncmF3JywgY3J5cHRvS2V5Q2VrLCBjcnlwdG9LZXksICdBRVMtS1cnKSk7XG59O1xuZXhwb3J0IGNvbnN0IHVud3JhcCA9IGFzeW5jIChhbGcsIGtleSwgZW5jcnlwdGVkS2V5KSA9PiB7XG4gICAgY29uc3QgY3J5cHRvS2V5ID0gYXdhaXQgZ2V0Q3J5cHRvS2V5KGtleSwgYWxnLCAndW53cmFwS2V5Jyk7XG4gICAgY2hlY2tLZXlTaXplKGNyeXB0b0tleSwgYWxnKTtcbiAgICBjb25zdCBjcnlwdG9LZXlDZWsgPSBhd2FpdCBjcnlwdG8uc3VidGxlLnVud3JhcEtleSgncmF3JywgZW5jcnlwdGVkS2V5LCBjcnlwdG9LZXksICdBRVMtS1cnLCAuLi5ib2d1c1dlYkNyeXB0byk7XG4gICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdyYXcnLCBjcnlwdG9LZXlDZWspKTtcbn07XG4iLCJpbXBvcnQgeyBlbmNvZGVyLCBjb25jYXQsIHVpbnQzMmJlLCBsZW5ndGhBbmRJbnB1dCwgY29uY2F0S2RmIH0gZnJvbSAnLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tFbmNDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGRlcml2ZUtleShwdWJsaWNLZXksIHByaXZhdGVLZXksIGFsZ29yaXRobSwga2V5TGVuZ3RoLCBhcHUgPSBuZXcgVWludDhBcnJheSgwKSwgYXB2ID0gbmV3IFVpbnQ4QXJyYXkoMCkpIHtcbiAgICBpZiAoIWlzQ3J5cHRvS2V5KHB1YmxpY0tleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQocHVibGljS2V5LCAuLi50eXBlcykpO1xuICAgIH1cbiAgICBjaGVja0VuY0NyeXB0b0tleShwdWJsaWNLZXksICdFQ0RIJyk7XG4gICAgaWYgKCFpc0NyeXB0b0tleShwcml2YXRlS2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChwcml2YXRlS2V5LCAuLi50eXBlcykpO1xuICAgIH1cbiAgICBjaGVja0VuY0NyeXB0b0tleShwcml2YXRlS2V5LCAnRUNESCcsICdkZXJpdmVCaXRzJyk7XG4gICAgY29uc3QgdmFsdWUgPSBjb25jYXQobGVuZ3RoQW5kSW5wdXQoZW5jb2Rlci5lbmNvZGUoYWxnb3JpdGhtKSksIGxlbmd0aEFuZElucHV0KGFwdSksIGxlbmd0aEFuZElucHV0KGFwdiksIHVpbnQzMmJlKGtleUxlbmd0aCkpO1xuICAgIGxldCBsZW5ndGg7XG4gICAgaWYgKHB1YmxpY0tleS5hbGdvcml0aG0ubmFtZSA9PT0gJ1gyNTUxOScpIHtcbiAgICAgICAgbGVuZ3RoID0gMjU2O1xuICAgIH1cbiAgICBlbHNlIGlmIChwdWJsaWNLZXkuYWxnb3JpdGhtLm5hbWUgPT09ICdYNDQ4Jykge1xuICAgICAgICBsZW5ndGggPSA0NDg7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBsZW5ndGggPVxuICAgICAgICAgICAgTWF0aC5jZWlsKHBhcnNlSW50KHB1YmxpY0tleS5hbGdvcml0aG0ubmFtZWRDdXJ2ZS5zdWJzdHIoLTMpLCAxMCkgLyA4KSA8PFxuICAgICAgICAgICAgICAgIDM7XG4gICAgfVxuICAgIGNvbnN0IHNoYXJlZFNlY3JldCA9IG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZGVyaXZlQml0cyh7XG4gICAgICAgIG5hbWU6IHB1YmxpY0tleS5hbGdvcml0aG0ubmFtZSxcbiAgICAgICAgcHVibGljOiBwdWJsaWNLZXksXG4gICAgfSwgcHJpdmF0ZUtleSwgbGVuZ3RoKSk7XG4gICAgcmV0dXJuIGNvbmNhdEtkZihzaGFyZWRTZWNyZXQsIGtleUxlbmd0aCwgdmFsdWUpO1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdlbmVyYXRlRXBrKGtleSkge1xuICAgIGlmICghaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzKSk7XG4gICAgfVxuICAgIHJldHVybiBjcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KGtleS5hbGdvcml0aG0sIHRydWUsIFsnZGVyaXZlQml0cyddKTtcbn1cbmV4cG9ydCBmdW5jdGlvbiBlY2RoQWxsb3dlZChrZXkpIHtcbiAgICBpZiAoIWlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcykpO1xuICAgIH1cbiAgICByZXR1cm4gKFsnUC0yNTYnLCAnUC0zODQnLCAnUC01MjEnXS5pbmNsdWRlcyhrZXkuYWxnb3JpdGhtLm5hbWVkQ3VydmUpIHx8XG4gICAgICAgIGtleS5hbGdvcml0aG0ubmFtZSA9PT0gJ1gyNTUxOScgfHxcbiAgICAgICAga2V5LmFsZ29yaXRobS5uYW1lID09PSAnWDQ0OCcpO1xufVxuIiwiaW1wb3J0IHsgSldFSW52YWxpZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNoZWNrUDJzKHAycykge1xuICAgIGlmICghKHAycyBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHx8IHAycy5sZW5ndGggPCA4KSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdQQkVTMiBTYWx0IElucHV0IG11c3QgYmUgOCBvciBtb3JlIG9jdGV0cycpO1xuICAgIH1cbn1cbiIsImltcG9ydCByYW5kb20gZnJvbSAnLi9yYW5kb20uanMnO1xuaW1wb3J0IHsgcDJzIGFzIGNvbmNhdFNhbHQgfSBmcm9tICcuLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmltcG9ydCB7IGVuY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgeyB3cmFwLCB1bndyYXAgfSBmcm9tICcuL2Flc2t3LmpzJztcbmltcG9ydCBjaGVja1AycyBmcm9tICcuLi9saWIvY2hlY2tfcDJzLmpzJztcbmltcG9ydCBjcnlwdG8sIHsgaXNDcnlwdG9LZXkgfSBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgeyBjaGVja0VuY0NyeXB0b0tleSB9IGZyb20gJy4uL2xpYi9jcnlwdG9fa2V5LmpzJztcbmltcG9ydCBpbnZhbGlkS2V5SW5wdXQgZnJvbSAnLi4vbGliL2ludmFsaWRfa2V5X2lucHV0LmpzJztcbmltcG9ydCB7IHR5cGVzIH0gZnJvbSAnLi9pc19rZXlfbGlrZS5qcyc7XG5mdW5jdGlvbiBnZXRDcnlwdG9LZXkoa2V5LCBhbGcpIHtcbiAgICBpZiAoa2V5IGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICByZXR1cm4gY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGtleSwgJ1BCS0RGMicsIGZhbHNlLCBbJ2Rlcml2ZUJpdHMnXSk7XG4gICAgfVxuICAgIGlmIChpc0NyeXB0b0tleShrZXkpKSB7XG4gICAgICAgIGNoZWNrRW5jQ3J5cHRvS2V5KGtleSwgYWxnLCAnZGVyaXZlQml0cycsICdkZXJpdmVLZXknKTtcbiAgICAgICAgcmV0dXJuIGtleTtcbiAgICB9XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcywgJ1VpbnQ4QXJyYXknKSk7XG59XG5hc3luYyBmdW5jdGlvbiBkZXJpdmVLZXkocDJzLCBhbGcsIHAyYywga2V5KSB7XG4gICAgY2hlY2tQMnMocDJzKTtcbiAgICBjb25zdCBzYWx0ID0gY29uY2F0U2FsdChhbGcsIHAycyk7XG4gICAgY29uc3Qga2V5bGVuID0gcGFyc2VJbnQoYWxnLnNsaWNlKDEzLCAxNiksIDEwKTtcbiAgICBjb25zdCBzdWJ0bGVBbGcgPSB7XG4gICAgICAgIGhhc2g6IGBTSEEtJHthbGcuc2xpY2UoOCwgMTEpfWAsXG4gICAgICAgIGl0ZXJhdGlvbnM6IHAyYyxcbiAgICAgICAgbmFtZTogJ1BCS0RGMicsXG4gICAgICAgIHNhbHQsXG4gICAgfTtcbiAgICBjb25zdCB3cmFwQWxnID0ge1xuICAgICAgICBsZW5ndGg6IGtleWxlbixcbiAgICAgICAgbmFtZTogJ0FFUy1LVycsXG4gICAgfTtcbiAgICBjb25zdCBjcnlwdG9LZXkgPSBhd2FpdCBnZXRDcnlwdG9LZXkoa2V5LCBhbGcpO1xuICAgIGlmIChjcnlwdG9LZXkudXNhZ2VzLmluY2x1ZGVzKCdkZXJpdmVCaXRzJykpIHtcbiAgICAgICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZGVyaXZlQml0cyhzdWJ0bGVBbGcsIGNyeXB0b0tleSwga2V5bGVuKSk7XG4gICAgfVxuICAgIGlmIChjcnlwdG9LZXkudXNhZ2VzLmluY2x1ZGVzKCdkZXJpdmVLZXknKSkge1xuICAgICAgICByZXR1cm4gY3J5cHRvLnN1YnRsZS5kZXJpdmVLZXkoc3VidGxlQWxnLCBjcnlwdG9LZXksIHdyYXBBbGcsIGZhbHNlLCBbJ3dyYXBLZXknLCAndW53cmFwS2V5J10pO1xuICAgIH1cbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdQQktERjIga2V5IFwidXNhZ2VzXCIgbXVzdCBpbmNsdWRlIFwiZGVyaXZlQml0c1wiIG9yIFwiZGVyaXZlS2V5XCInKTtcbn1cbmV4cG9ydCBjb25zdCBlbmNyeXB0ID0gYXN5bmMgKGFsZywga2V5LCBjZWssIHAyYyA9IDIwNDgsIHAycyA9IHJhbmRvbShuZXcgVWludDhBcnJheSgxNikpKSA9PiB7XG4gICAgY29uc3QgZGVyaXZlZCA9IGF3YWl0IGRlcml2ZUtleShwMnMsIGFsZywgcDJjLCBrZXkpO1xuICAgIGNvbnN0IGVuY3J5cHRlZEtleSA9IGF3YWl0IHdyYXAoYWxnLnNsaWNlKC02KSwgZGVyaXZlZCwgY2VrKTtcbiAgICByZXR1cm4geyBlbmNyeXB0ZWRLZXksIHAyYywgcDJzOiBiYXNlNjR1cmwocDJzKSB9O1xufTtcbmV4cG9ydCBjb25zdCBkZWNyeXB0ID0gYXN5bmMgKGFsZywga2V5LCBlbmNyeXB0ZWRLZXksIHAyYywgcDJzKSA9PiB7XG4gICAgY29uc3QgZGVyaXZlZCA9IGF3YWl0IGRlcml2ZUtleShwMnMsIGFsZywgcDJjLCBrZXkpO1xuICAgIHJldHVybiB1bndyYXAoYWxnLnNsaWNlKC02KSwgZGVyaXZlZCwgZW5jcnlwdGVkS2V5KTtcbn07XG4iLCJpbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gc3VidGxlUnNhRXMoYWxnKSB7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0yNTYnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0zODQnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC01MTInOlxuICAgICAgICAgICAgcmV0dXJuICdSU0EtT0FFUCc7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZChgYWxnICR7YWxnfSBpcyBub3Qgc3VwcG9ydGVkIGVpdGhlciBieSBKT1NFIG9yIHlvdXIgamF2YXNjcmlwdCBydW50aW1lYCk7XG4gICAgfVxufVxuIiwiZXhwb3J0IGRlZmF1bHQgKGFsZywga2V5KSA9PiB7XG4gICAgaWYgKGFsZy5zdGFydHNXaXRoKCdSUycpIHx8IGFsZy5zdGFydHNXaXRoKCdQUycpKSB7XG4gICAgICAgIGNvbnN0IHsgbW9kdWx1c0xlbmd0aCB9ID0ga2V5LmFsZ29yaXRobTtcbiAgICAgICAgaWYgKHR5cGVvZiBtb2R1bHVzTGVuZ3RoICE9PSAnbnVtYmVyJyB8fCBtb2R1bHVzTGVuZ3RoIDwgMjA0OCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHthbGd9IHJlcXVpcmVzIGtleSBtb2R1bHVzTGVuZ3RoIHRvIGJlIDIwNDggYml0cyBvciBsYXJnZXJgKTtcbiAgICAgICAgfVxuICAgIH1cbn07XG4iLCJpbXBvcnQgc3VidGxlQWxnb3JpdGhtIGZyb20gJy4vc3VidGxlX3JzYWVzLmpzJztcbmltcG9ydCBib2d1c1dlYkNyeXB0byBmcm9tICcuL2JvZ3VzLmpzJztcbmltcG9ydCBjcnlwdG8sIHsgaXNDcnlwdG9LZXkgfSBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgeyBjaGVja0VuY0NyeXB0b0tleSB9IGZyb20gJy4uL2xpYi9jcnlwdG9fa2V5LmpzJztcbmltcG9ydCBjaGVja0tleUxlbmd0aCBmcm9tICcuL2NoZWNrX2tleV9sZW5ndGguanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmV4cG9ydCBjb25zdCBlbmNyeXB0ID0gYXN5bmMgKGFsZywga2V5LCBjZWspID0+IHtcbiAgICBpZiAoIWlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcykpO1xuICAgIH1cbiAgICBjaGVja0VuY0NyeXB0b0tleShrZXksIGFsZywgJ2VuY3J5cHQnLCAnd3JhcEtleScpO1xuICAgIGNoZWNrS2V5TGVuZ3RoKGFsZywga2V5KTtcbiAgICBpZiAoa2V5LnVzYWdlcy5pbmNsdWRlcygnZW5jcnlwdCcpKSB7XG4gICAgICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmVuY3J5cHQoc3VidGxlQWxnb3JpdGhtKGFsZyksIGtleSwgY2VrKSk7XG4gICAgfVxuICAgIGlmIChrZXkudXNhZ2VzLmluY2x1ZGVzKCd3cmFwS2V5JykpIHtcbiAgICAgICAgY29uc3QgY3J5cHRvS2V5Q2VrID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGNlaywgLi4uYm9ndXNXZWJDcnlwdG8pO1xuICAgICAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS53cmFwS2V5KCdyYXcnLCBjcnlwdG9LZXlDZWssIGtleSwgc3VidGxlQWxnb3JpdGhtKGFsZykpKTtcbiAgICB9XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcignUlNBLU9BRVAga2V5IFwidXNhZ2VzXCIgbXVzdCBpbmNsdWRlIFwiZW5jcnlwdFwiIG9yIFwid3JhcEtleVwiIGZvciB0aGlzIG9wZXJhdGlvbicpO1xufTtcbmV4cG9ydCBjb25zdCBkZWNyeXB0ID0gYXN5bmMgKGFsZywga2V5LCBlbmNyeXB0ZWRLZXkpID0+IHtcbiAgICBpZiAoIWlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcykpO1xuICAgIH1cbiAgICBjaGVja0VuY0NyeXB0b0tleShrZXksIGFsZywgJ2RlY3J5cHQnLCAndW53cmFwS2V5Jyk7XG4gICAgY2hlY2tLZXlMZW5ndGgoYWxnLCBrZXkpO1xuICAgIGlmIChrZXkudXNhZ2VzLmluY2x1ZGVzKCdkZWNyeXB0JykpIHtcbiAgICAgICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZGVjcnlwdChzdWJ0bGVBbGdvcml0aG0oYWxnKSwga2V5LCBlbmNyeXB0ZWRLZXkpKTtcbiAgICB9XG4gICAgaWYgKGtleS51c2FnZXMuaW5jbHVkZXMoJ3Vud3JhcEtleScpKSB7XG4gICAgICAgIGNvbnN0IGNyeXB0b0tleUNlayA9IGF3YWl0IGNyeXB0by5zdWJ0bGUudW53cmFwS2V5KCdyYXcnLCBlbmNyeXB0ZWRLZXksIGtleSwgc3VidGxlQWxnb3JpdGhtKGFsZyksIC4uLmJvZ3VzV2ViQ3J5cHRvKTtcbiAgICAgICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdyYXcnLCBjcnlwdG9LZXlDZWspKTtcbiAgICB9XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcignUlNBLU9BRVAga2V5IFwidXNhZ2VzXCIgbXVzdCBpbmNsdWRlIFwiZGVjcnlwdFwiIG9yIFwidW53cmFwS2V5XCIgZm9yIHRoaXMgb3BlcmF0aW9uJyk7XG59O1xuIiwiaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4vaXNfb2JqZWN0LmpzJztcbmV4cG9ydCBmdW5jdGlvbiBpc0pXSyhrZXkpIHtcbiAgICByZXR1cm4gaXNPYmplY3Qoa2V5KSAmJiB0eXBlb2Yga2V5Lmt0eSA9PT0gJ3N0cmluZyc7XG59XG5leHBvcnQgZnVuY3Rpb24gaXNQcml2YXRlSldLKGtleSkge1xuICAgIHJldHVybiBrZXkua3R5ICE9PSAnb2N0JyAmJiB0eXBlb2Yga2V5LmQgPT09ICdzdHJpbmcnO1xufVxuZXhwb3J0IGZ1bmN0aW9uIGlzUHVibGljSldLKGtleSkge1xuICAgIHJldHVybiBrZXkua3R5ICE9PSAnb2N0JyAmJiB0eXBlb2Yga2V5LmQgPT09ICd1bmRlZmluZWQnO1xufVxuZXhwb3J0IGZ1bmN0aW9uIGlzU2VjcmV0SldLKGtleSkge1xuICAgIHJldHVybiBpc0pXSyhrZXkpICYmIGtleS5rdHkgPT09ICdvY3QnICYmIHR5cGVvZiBrZXkuayA9PT0gJ3N0cmluZyc7XG59XG4iLCJpbXBvcnQgY3J5cHRvIGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5mdW5jdGlvbiBzdWJ0bGVNYXBwaW5nKGp3aykge1xuICAgIGxldCBhbGdvcml0aG07XG4gICAgbGV0IGtleVVzYWdlcztcbiAgICBzd2l0Y2ggKGp3ay5rdHkpIHtcbiAgICAgICAgY2FzZSAnUlNBJzoge1xuICAgICAgICAgICAgc3dpdGNoIChqd2suYWxnKSB7XG4gICAgICAgICAgICAgICAgY2FzZSAnUFMyNTYnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1BTMzg0JzpcbiAgICAgICAgICAgICAgICBjYXNlICdQUzUxMic6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ1JTQS1QU1MnLCBoYXNoOiBgU0hBLSR7andrLmFsZy5zbGljZSgtMyl9YCB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnc2lnbiddIDogWyd2ZXJpZnknXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAnUlMyNTYnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1JTMzg0JzpcbiAgICAgICAgICAgICAgICBjYXNlICdSUzUxMic6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ1JTQVNTQS1QS0NTMS12MV81JywgaGFzaDogYFNIQS0ke2p3ay5hbGcuc2xpY2UoLTMpfWAgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ3NpZ24nXSA6IFsndmVyaWZ5J107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ1JTQS1PQUVQJzpcbiAgICAgICAgICAgICAgICBjYXNlICdSU0EtT0FFUC0yNTYnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1JTQS1PQUVQLTM4NCc6XG4gICAgICAgICAgICAgICAgY2FzZSAnUlNBLU9BRVAtNTEyJzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0ge1xuICAgICAgICAgICAgICAgICAgICAgICAgbmFtZTogJ1JTQS1PQUVQJyxcbiAgICAgICAgICAgICAgICAgICAgICAgIGhhc2g6IGBTSEEtJHtwYXJzZUludChqd2suYWxnLnNsaWNlKC0zKSwgMTApIHx8IDF9YCxcbiAgICAgICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ2RlY3J5cHQnLCAndW53cmFwS2V5J10gOiBbJ2VuY3J5cHQnLCAnd3JhcEtleSddO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBKV0sgXCJhbGdcIiAoQWxnb3JpdGhtKSBQYXJhbWV0ZXIgdmFsdWUnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0VDJzoge1xuICAgICAgICAgICAgc3dpdGNoIChqd2suYWxnKSB7XG4gICAgICAgICAgICAgICAgY2FzZSAnRVMyNTYnOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RTQScsIG5hbWVkQ3VydmU6ICdQLTI1NicgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ3NpZ24nXSA6IFsndmVyaWZ5J107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ0VTMzg0JzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNEU0EnLCBuYW1lZEN1cnZlOiAnUC0zODQnIH07XG4gICAgICAgICAgICAgICAgICAgIGtleVVzYWdlcyA9IGp3ay5kID8gWydzaWduJ10gOiBbJ3ZlcmlmeSddO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlICdFUzUxMic6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0VDRFNBJywgbmFtZWRDdXJ2ZTogJ1AtNTIxJyB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnc2lnbiddIDogWyd2ZXJpZnknXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUyc6XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUytBMTI4S1cnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMrQTE5MktXJzpcbiAgICAgICAgICAgICAgICBjYXNlICdFQ0RILUVTK0EyNTZLVyc6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0VDREgnLCBuYW1lZEN1cnZlOiBqd2suY3J2IH07XG4gICAgICAgICAgICAgICAgICAgIGtleVVzYWdlcyA9IGp3ay5kID8gWydkZXJpdmVCaXRzJ10gOiBbXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgSldLIFwiYWxnXCIgKEFsZ29yaXRobSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdPS1AnOiB7XG4gICAgICAgICAgICBzd2l0Y2ggKGp3ay5hbGcpIHtcbiAgICAgICAgICAgICAgICBjYXNlICdFZERTQSc6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogandrLmNydiB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnc2lnbiddIDogWyd2ZXJpZnknXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUyc6XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUytBMTI4S1cnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMrQTE5MktXJzpcbiAgICAgICAgICAgICAgICBjYXNlICdFQ0RILUVTK0EyNTZLVyc6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogandrLmNydiB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnZGVyaXZlQml0cyddIDogW107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIEpXSyBcImFsZ1wiIChBbGdvcml0aG0pIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIEpXSyBcImt0eVwiIChLZXkgVHlwZSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgfVxuICAgIHJldHVybiB7IGFsZ29yaXRobSwga2V5VXNhZ2VzIH07XG59XG5jb25zdCBwYXJzZSA9IGFzeW5jIChqd2spID0+IHtcbiAgICBpZiAoIWp3ay5hbGcpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignXCJhbGdcIiBhcmd1bWVudCBpcyByZXF1aXJlZCB3aGVuIFwiandrLmFsZ1wiIGlzIG5vdCBwcmVzZW50Jyk7XG4gICAgfVxuICAgIGNvbnN0IHsgYWxnb3JpdGhtLCBrZXlVc2FnZXMgfSA9IHN1YnRsZU1hcHBpbmcoandrKTtcbiAgICBjb25zdCByZXN0ID0gW1xuICAgICAgICBhbGdvcml0aG0sXG4gICAgICAgIGp3ay5leHQgPz8gZmFsc2UsXG4gICAgICAgIGp3ay5rZXlfb3BzID8/IGtleVVzYWdlcyxcbiAgICBdO1xuICAgIGNvbnN0IGtleURhdGEgPSB7IC4uLmp3ayB9O1xuICAgIGRlbGV0ZSBrZXlEYXRhLmFsZztcbiAgICBkZWxldGUga2V5RGF0YS51c2U7XG4gICAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdqd2snLCBrZXlEYXRhLCAuLi5yZXN0KTtcbn07XG5leHBvcnQgZGVmYXVsdCBwYXJzZTtcbiIsImltcG9ydCB7IGlzSldLIH0gZnJvbSAnLi4vbGliL2lzX2p3ay5qcyc7XG5pbXBvcnQgeyBkZWNvZGUgfSBmcm9tICcuL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgaW1wb3J0SldLIGZyb20gJy4vandrX3RvX2tleS5qcyc7XG5jb25zdCBleHBvcnRLZXlWYWx1ZSA9IChrKSA9PiBkZWNvZGUoayk7XG5sZXQgcHJpdkNhY2hlO1xubGV0IHB1YkNhY2hlO1xuY29uc3QgaXNLZXlPYmplY3QgPSAoa2V5KSA9PiB7XG4gICAgcmV0dXJuIGtleT8uW1N5bWJvbC50b1N0cmluZ1RhZ10gPT09ICdLZXlPYmplY3QnO1xufTtcbmNvbnN0IGltcG9ydEFuZENhY2hlID0gYXN5bmMgKGNhY2hlLCBrZXksIGp3aywgYWxnLCBmcmVlemUgPSBmYWxzZSkgPT4ge1xuICAgIGxldCBjYWNoZWQgPSBjYWNoZS5nZXQoa2V5KTtcbiAgICBpZiAoY2FjaGVkPy5bYWxnXSkge1xuICAgICAgICByZXR1cm4gY2FjaGVkW2FsZ107XG4gICAgfVxuICAgIGNvbnN0IGNyeXB0b0tleSA9IGF3YWl0IGltcG9ydEpXSyh7IC4uLmp3aywgYWxnIH0pO1xuICAgIGlmIChmcmVlemUpXG4gICAgICAgIE9iamVjdC5mcmVlemUoa2V5KTtcbiAgICBpZiAoIWNhY2hlZCkge1xuICAgICAgICBjYWNoZS5zZXQoa2V5LCB7IFthbGddOiBjcnlwdG9LZXkgfSk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBjYWNoZWRbYWxnXSA9IGNyeXB0b0tleTtcbiAgICB9XG4gICAgcmV0dXJuIGNyeXB0b0tleTtcbn07XG5jb25zdCBub3JtYWxpemVQdWJsaWNLZXkgPSAoa2V5LCBhbGcpID0+IHtcbiAgICBpZiAoaXNLZXlPYmplY3Qoa2V5KSkge1xuICAgICAgICBsZXQgandrID0ga2V5LmV4cG9ydCh7IGZvcm1hdDogJ2p3aycgfSk7XG4gICAgICAgIGRlbGV0ZSBqd2suZDtcbiAgICAgICAgZGVsZXRlIGp3ay5kcDtcbiAgICAgICAgZGVsZXRlIGp3ay5kcTtcbiAgICAgICAgZGVsZXRlIGp3ay5wO1xuICAgICAgICBkZWxldGUgandrLnE7XG4gICAgICAgIGRlbGV0ZSBqd2sucWk7XG4gICAgICAgIGlmIChqd2suaykge1xuICAgICAgICAgICAgcmV0dXJuIGV4cG9ydEtleVZhbHVlKGp3ay5rKTtcbiAgICAgICAgfVxuICAgICAgICBwdWJDYWNoZSB8fCAocHViQ2FjaGUgPSBuZXcgV2Vha01hcCgpKTtcbiAgICAgICAgcmV0dXJuIGltcG9ydEFuZENhY2hlKHB1YkNhY2hlLCBrZXksIGp3aywgYWxnKTtcbiAgICB9XG4gICAgaWYgKGlzSldLKGtleSkpIHtcbiAgICAgICAgaWYgKGtleS5rKVxuICAgICAgICAgICAgcmV0dXJuIGRlY29kZShrZXkuayk7XG4gICAgICAgIHB1YkNhY2hlIHx8IChwdWJDYWNoZSA9IG5ldyBXZWFrTWFwKCkpO1xuICAgICAgICBjb25zdCBjcnlwdG9LZXkgPSBpbXBvcnRBbmRDYWNoZShwdWJDYWNoZSwga2V5LCBrZXksIGFsZywgdHJ1ZSk7XG4gICAgICAgIHJldHVybiBjcnlwdG9LZXk7XG4gICAgfVxuICAgIHJldHVybiBrZXk7XG59O1xuY29uc3Qgbm9ybWFsaXplUHJpdmF0ZUtleSA9IChrZXksIGFsZykgPT4ge1xuICAgIGlmIChpc0tleU9iamVjdChrZXkpKSB7XG4gICAgICAgIGxldCBqd2sgPSBrZXkuZXhwb3J0KHsgZm9ybWF0OiAnandrJyB9KTtcbiAgICAgICAgaWYgKGp3ay5rKSB7XG4gICAgICAgICAgICByZXR1cm4gZXhwb3J0S2V5VmFsdWUoandrLmspO1xuICAgICAgICB9XG4gICAgICAgIHByaXZDYWNoZSB8fCAocHJpdkNhY2hlID0gbmV3IFdlYWtNYXAoKSk7XG4gICAgICAgIHJldHVybiBpbXBvcnRBbmRDYWNoZShwcml2Q2FjaGUsIGtleSwgandrLCBhbGcpO1xuICAgIH1cbiAgICBpZiAoaXNKV0soa2V5KSkge1xuICAgICAgICBpZiAoa2V5LmspXG4gICAgICAgICAgICByZXR1cm4gZGVjb2RlKGtleS5rKTtcbiAgICAgICAgcHJpdkNhY2hlIHx8IChwcml2Q2FjaGUgPSBuZXcgV2Vha01hcCgpKTtcbiAgICAgICAgY29uc3QgY3J5cHRvS2V5ID0gaW1wb3J0QW5kQ2FjaGUocHJpdkNhY2hlLCBrZXksIGtleSwgYWxnLCB0cnVlKTtcbiAgICAgICAgcmV0dXJuIGNyeXB0b0tleTtcbiAgICB9XG4gICAgcmV0dXJuIGtleTtcbn07XG5leHBvcnQgZGVmYXVsdCB7IG5vcm1hbGl6ZVB1YmxpY0tleSwgbm9ybWFsaXplUHJpdmF0ZUtleSB9O1xuIiwiaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCByYW5kb20gZnJvbSAnLi4vcnVudGltZS9yYW5kb20uanMnO1xuZXhwb3J0IGZ1bmN0aW9uIGJpdExlbmd0aChhbGcpIHtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdBMTI4R0NNJzpcbiAgICAgICAgICAgIHJldHVybiAxMjg7XG4gICAgICAgIGNhc2UgJ0ExOTJHQ00nOlxuICAgICAgICAgICAgcmV0dXJuIDE5MjtcbiAgICAgICAgY2FzZSAnQTI1NkdDTSc6XG4gICAgICAgIGNhc2UgJ0ExMjhDQkMtSFMyNTYnOlxuICAgICAgICAgICAgcmV0dXJuIDI1NjtcbiAgICAgICAgY2FzZSAnQTE5MkNCQy1IUzM4NCc6XG4gICAgICAgICAgICByZXR1cm4gMzg0O1xuICAgICAgICBjYXNlICdBMjU2Q0JDLUhTNTEyJzpcbiAgICAgICAgICAgIHJldHVybiA1MTI7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZChgVW5zdXBwb3J0ZWQgSldFIEFsZ29yaXRobTogJHthbGd9YCk7XG4gICAgfVxufVxuZXhwb3J0IGRlZmF1bHQgKGFsZykgPT4gcmFuZG9tKG5ldyBVaW50OEFycmF5KGJpdExlbmd0aChhbGcpID4+IDMpKTtcbiIsImltcG9ydCB7IGRlY29kZSBhcyBkZWNvZGVCYXNlNjRVUkwgfSBmcm9tICcuLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgeyBmcm9tU1BLSSwgZnJvbVBLQ1M4LCBmcm9tWDUwOSB9IGZyb20gJy4uL3J1bnRpbWUvYXNuMS5qcyc7XG5pbXBvcnQgYXNLZXlPYmplY3QgZnJvbSAnLi4vcnVudGltZS9qd2tfdG9fa2V5LmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgaXNPYmplY3QgZnJvbSAnLi4vbGliL2lzX29iamVjdC5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gaW1wb3J0U1BLSShzcGtpLCBhbGcsIG9wdGlvbnMpIHtcbiAgICBpZiAodHlwZW9mIHNwa2kgIT09ICdzdHJpbmcnIHx8IHNwa2kuaW5kZXhPZignLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0nKSAhPT0gMCkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdcInNwa2lcIiBtdXN0IGJlIFNQS0kgZm9ybWF0dGVkIHN0cmluZycpO1xuICAgIH1cbiAgICByZXR1cm4gZnJvbVNQS0koc3BraSwgYWxnLCBvcHRpb25zKTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBpbXBvcnRYNTA5KHg1MDksIGFsZywgb3B0aW9ucykge1xuICAgIGlmICh0eXBlb2YgeDUwOSAhPT0gJ3N0cmluZycgfHwgeDUwOS5pbmRleE9mKCctLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0nKSAhPT0gMCkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdcIng1MDlcIiBtdXN0IGJlIFguNTA5IGZvcm1hdHRlZCBzdHJpbmcnKTtcbiAgICB9XG4gICAgcmV0dXJuIGZyb21YNTA5KHg1MDksIGFsZywgb3B0aW9ucyk7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gaW1wb3J0UEtDUzgocGtjczgsIGFsZywgb3B0aW9ucykge1xuICAgIGlmICh0eXBlb2YgcGtjczggIT09ICdzdHJpbmcnIHx8IHBrY3M4LmluZGV4T2YoJy0tLS0tQkVHSU4gUFJJVkFURSBLRVktLS0tLScpICE9PSAwKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1wicGtjczhcIiBtdXN0IGJlIFBLQ1MjOCBmb3JtYXR0ZWQgc3RyaW5nJyk7XG4gICAgfVxuICAgIHJldHVybiBmcm9tUEtDUzgocGtjczgsIGFsZywgb3B0aW9ucyk7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gaW1wb3J0SldLKGp3aywgYWxnKSB7XG4gICAgaWYgKCFpc09iamVjdChqd2spKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0pXSyBtdXN0IGJlIGFuIG9iamVjdCcpO1xuICAgIH1cbiAgICBhbGcgfHwgKGFsZyA9IGp3ay5hbGcpO1xuICAgIHN3aXRjaCAoandrLmt0eSkge1xuICAgICAgICBjYXNlICdvY3QnOlxuICAgICAgICAgICAgaWYgKHR5cGVvZiBqd2suayAhPT0gJ3N0cmluZycgfHwgIWp3ay5rKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignbWlzc2luZyBcImtcIiAoS2V5IFZhbHVlKSBQYXJhbWV0ZXIgdmFsdWUnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBkZWNvZGVCYXNlNjRVUkwoandrLmspO1xuICAgICAgICBjYXNlICdSU0EnOlxuICAgICAgICAgICAgaWYgKGp3ay5vdGggIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdSU0EgSldLIFwib3RoXCIgKE90aGVyIFByaW1lcyBJbmZvKSBQYXJhbWV0ZXIgdmFsdWUgaXMgbm90IHN1cHBvcnRlZCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICBjYXNlICdFQyc6XG4gICAgICAgIGNhc2UgJ09LUCc6XG4gICAgICAgICAgICByZXR1cm4gYXNLZXlPYmplY3QoeyAuLi5qd2ssIGFsZyB9KTtcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdVbnN1cHBvcnRlZCBcImt0eVwiIChLZXkgVHlwZSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgfVxufVxuIiwiaW1wb3J0IHsgd2l0aEFsZyBhcyBpbnZhbGlkS2V5SW5wdXQgfSBmcm9tICcuL2ludmFsaWRfa2V5X2lucHV0LmpzJztcbmltcG9ydCBpc0tleUxpa2UsIHsgdHlwZXMgfSBmcm9tICcuLi9ydW50aW1lL2lzX2tleV9saWtlLmpzJztcbmltcG9ydCAqIGFzIGp3ayBmcm9tICcuL2lzX2p3ay5qcyc7XG5jb25zdCB0YWcgPSAoa2V5KSA9PiBrZXk/LltTeW1ib2wudG9TdHJpbmdUYWddO1xuY29uc3QgandrTWF0Y2hlc09wID0gKGFsZywga2V5LCB1c2FnZSkgPT4ge1xuICAgIGlmIChrZXkudXNlICE9PSB1bmRlZmluZWQgJiYga2V5LnVzZSAhPT0gJ3NpZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignSW52YWxpZCBrZXkgZm9yIHRoaXMgb3BlcmF0aW9uLCB3aGVuIHByZXNlbnQgaXRzIHVzZSBtdXN0IGJlIHNpZycpO1xuICAgIH1cbiAgICBpZiAoa2V5LmtleV9vcHMgIT09IHVuZGVmaW5lZCAmJiBrZXkua2V5X29wcy5pbmNsdWRlcz8uKHVzYWdlKSAhPT0gdHJ1ZSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGBJbnZhbGlkIGtleSBmb3IgdGhpcyBvcGVyYXRpb24sIHdoZW4gcHJlc2VudCBpdHMga2V5X29wcyBtdXN0IGluY2x1ZGUgJHt1c2FnZX1gKTtcbiAgICB9XG4gICAgaWYgKGtleS5hbGcgIT09IHVuZGVmaW5lZCAmJiBrZXkuYWxnICE9PSBhbGcpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgSW52YWxpZCBrZXkgZm9yIHRoaXMgb3BlcmF0aW9uLCB3aGVuIHByZXNlbnQgaXRzIGFsZyBtdXN0IGJlICR7YWxnfWApO1xuICAgIH1cbiAgICByZXR1cm4gdHJ1ZTtcbn07XG5jb25zdCBzeW1tZXRyaWNUeXBlQ2hlY2sgPSAoYWxnLCBrZXksIHVzYWdlLCBhbGxvd0p3aykgPT4ge1xuICAgIGlmIChrZXkgaW5zdGFuY2VvZiBVaW50OEFycmF5KVxuICAgICAgICByZXR1cm47XG4gICAgaWYgKGFsbG93SndrICYmIGp3ay5pc0pXSyhrZXkpKSB7XG4gICAgICAgIGlmIChqd2suaXNTZWNyZXRKV0soa2V5KSAmJiBqd2tNYXRjaGVzT3AoYWxnLCBrZXksIHVzYWdlKSlcbiAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgSlNPTiBXZWIgS2V5IGZvciBzeW1tZXRyaWMgYWxnb3JpdGhtcyBtdXN0IGhhdmUgSldLIFwia3R5XCIgKEtleSBUeXBlKSBlcXVhbCB0byBcIm9jdFwiIGFuZCB0aGUgSldLIFwia1wiIChLZXkgVmFsdWUpIHByZXNlbnRgKTtcbiAgICB9XG4gICAgaWYgKCFpc0tleUxpa2Uoa2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChhbGcsIGtleSwgLi4udHlwZXMsICdVaW50OEFycmF5JywgYWxsb3dKd2sgPyAnSlNPTiBXZWIgS2V5JyA6IG51bGwpKTtcbiAgICB9XG4gICAgaWYgKGtleS50eXBlICE9PSAnc2VjcmV0Jykge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGAke3RhZyhrZXkpfSBpbnN0YW5jZXMgZm9yIHN5bW1ldHJpYyBhbGdvcml0aG1zIG11c3QgYmUgb2YgdHlwZSBcInNlY3JldFwiYCk7XG4gICAgfVxufTtcbmNvbnN0IGFzeW1tZXRyaWNUeXBlQ2hlY2sgPSAoYWxnLCBrZXksIHVzYWdlLCBhbGxvd0p3aykgPT4ge1xuICAgIGlmIChhbGxvd0p3ayAmJiBqd2suaXNKV0soa2V5KSkge1xuICAgICAgICBzd2l0Y2ggKHVzYWdlKSB7XG4gICAgICAgICAgICBjYXNlICdzaWduJzpcbiAgICAgICAgICAgICAgICBpZiAoandrLmlzUHJpdmF0ZUpXSyhrZXkpICYmIGp3a01hdGNoZXNPcChhbGcsIGtleSwgdXNhZ2UpKVxuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgSlNPTiBXZWIgS2V5IGZvciB0aGlzIG9wZXJhdGlvbiBiZSBhIHByaXZhdGUgSldLYCk7XG4gICAgICAgICAgICBjYXNlICd2ZXJpZnknOlxuICAgICAgICAgICAgICAgIGlmIChqd2suaXNQdWJsaWNKV0soa2V5KSAmJiBqd2tNYXRjaGVzT3AoYWxnLCBrZXksIHVzYWdlKSlcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYEpTT04gV2ViIEtleSBmb3IgdGhpcyBvcGVyYXRpb24gYmUgYSBwdWJsaWMgSldLYCk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgaWYgKCFpc0tleUxpa2Uoa2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChhbGcsIGtleSwgLi4udHlwZXMsIGFsbG93SndrID8gJ0pTT04gV2ViIEtleScgOiBudWxsKSk7XG4gICAgfVxuICAgIGlmIChrZXkudHlwZSA9PT0gJ3NlY3JldCcpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHt0YWcoa2V5KX0gaW5zdGFuY2VzIGZvciBhc3ltbWV0cmljIGFsZ29yaXRobXMgbXVzdCBub3QgYmUgb2YgdHlwZSBcInNlY3JldFwiYCk7XG4gICAgfVxuICAgIGlmICh1c2FnZSA9PT0gJ3NpZ24nICYmIGtleS50eXBlID09PSAncHVibGljJykge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGAke3RhZyhrZXkpfSBpbnN0YW5jZXMgZm9yIGFzeW1tZXRyaWMgYWxnb3JpdGhtIHNpZ25pbmcgbXVzdCBiZSBvZiB0eXBlIFwicHJpdmF0ZVwiYCk7XG4gICAgfVxuICAgIGlmICh1c2FnZSA9PT0gJ2RlY3J5cHQnICYmIGtleS50eXBlID09PSAncHVibGljJykge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGAke3RhZyhrZXkpfSBpbnN0YW5jZXMgZm9yIGFzeW1tZXRyaWMgYWxnb3JpdGhtIGRlY3J5cHRpb24gbXVzdCBiZSBvZiB0eXBlIFwicHJpdmF0ZVwiYCk7XG4gICAgfVxuICAgIGlmIChrZXkuYWxnb3JpdGhtICYmIHVzYWdlID09PSAndmVyaWZ5JyAmJiBrZXkudHlwZSA9PT0gJ3ByaXZhdGUnKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYCR7dGFnKGtleSl9IGluc3RhbmNlcyBmb3IgYXN5bW1ldHJpYyBhbGdvcml0aG0gdmVyaWZ5aW5nIG11c3QgYmUgb2YgdHlwZSBcInB1YmxpY1wiYCk7XG4gICAgfVxuICAgIGlmIChrZXkuYWxnb3JpdGhtICYmIHVzYWdlID09PSAnZW5jcnlwdCcgJiYga2V5LnR5cGUgPT09ICdwcml2YXRlJykge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGAke3RhZyhrZXkpfSBpbnN0YW5jZXMgZm9yIGFzeW1tZXRyaWMgYWxnb3JpdGhtIGVuY3J5cHRpb24gbXVzdCBiZSBvZiB0eXBlIFwicHVibGljXCJgKTtcbiAgICB9XG59O1xuZnVuY3Rpb24gY2hlY2tLZXlUeXBlKGFsbG93SndrLCBhbGcsIGtleSwgdXNhZ2UpIHtcbiAgICBjb25zdCBzeW1tZXRyaWMgPSBhbGcuc3RhcnRzV2l0aCgnSFMnKSB8fFxuICAgICAgICBhbGcgPT09ICdkaXInIHx8XG4gICAgICAgIGFsZy5zdGFydHNXaXRoKCdQQkVTMicpIHx8XG4gICAgICAgIC9eQVxcZHszfSg/OkdDTSk/S1ckLy50ZXN0KGFsZyk7XG4gICAgaWYgKHN5bW1ldHJpYykge1xuICAgICAgICBzeW1tZXRyaWNUeXBlQ2hlY2soYWxnLCBrZXksIHVzYWdlLCBhbGxvd0p3ayk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBhc3ltbWV0cmljVHlwZUNoZWNrKGFsZywga2V5LCB1c2FnZSwgYWxsb3dKd2spO1xuICAgIH1cbn1cbmV4cG9ydCBkZWZhdWx0IGNoZWNrS2V5VHlwZS5iaW5kKHVuZGVmaW5lZCwgZmFsc2UpO1xuZXhwb3J0IGNvbnN0IGNoZWNrS2V5VHlwZVdpdGhKd2sgPSBjaGVja0tleVR5cGUuYmluZCh1bmRlZmluZWQsIHRydWUpO1xuIiwiaW1wb3J0IHsgY29uY2F0LCB1aW50NjRiZSB9IGZyb20gJy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IGNoZWNrSXZMZW5ndGggZnJvbSAnLi4vbGliL2NoZWNrX2l2X2xlbmd0aC5qcyc7XG5pbXBvcnQgY2hlY2tDZWtMZW5ndGggZnJvbSAnLi9jaGVja19jZWtfbGVuZ3RoLmpzJztcbmltcG9ydCBjcnlwdG8sIHsgaXNDcnlwdG9LZXkgfSBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgeyBjaGVja0VuY0NyeXB0b0tleSB9IGZyb20gJy4uL2xpYi9jcnlwdG9fa2V5LmpzJztcbmltcG9ydCBpbnZhbGlkS2V5SW5wdXQgZnJvbSAnLi4vbGliL2ludmFsaWRfa2V5X2lucHV0LmpzJztcbmltcG9ydCBnZW5lcmF0ZUl2IGZyb20gJy4uL2xpYi9pdi5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmFzeW5jIGZ1bmN0aW9uIGNiY0VuY3J5cHQoZW5jLCBwbGFpbnRleHQsIGNlaywgaXYsIGFhZCkge1xuICAgIGlmICghKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGNlaywgJ1VpbnQ4QXJyYXknKSk7XG4gICAgfVxuICAgIGNvbnN0IGtleVNpemUgPSBwYXJzZUludChlbmMuc2xpY2UoMSwgNCksIDEwKTtcbiAgICBjb25zdCBlbmNLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLnN1YmFycmF5KGtleVNpemUgPj4gMyksICdBRVMtQ0JDJywgZmFsc2UsIFsnZW5jcnlwdCddKTtcbiAgICBjb25zdCBtYWNLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLnN1YmFycmF5KDAsIGtleVNpemUgPj4gMyksIHtcbiAgICAgICAgaGFzaDogYFNIQS0ke2tleVNpemUgPDwgMX1gLFxuICAgICAgICBuYW1lOiAnSE1BQycsXG4gICAgfSwgZmFsc2UsIFsnc2lnbiddKTtcbiAgICBjb25zdCBjaXBoZXJ0ZXh0ID0gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5lbmNyeXB0KHtcbiAgICAgICAgaXYsXG4gICAgICAgIG5hbWU6ICdBRVMtQ0JDJyxcbiAgICB9LCBlbmNLZXksIHBsYWludGV4dCkpO1xuICAgIGNvbnN0IG1hY0RhdGEgPSBjb25jYXQoYWFkLCBpdiwgY2lwaGVydGV4dCwgdWludDY0YmUoYWFkLmxlbmd0aCA8PCAzKSk7XG4gICAgY29uc3QgdGFnID0gbmV3IFVpbnQ4QXJyYXkoKGF3YWl0IGNyeXB0by5zdWJ0bGUuc2lnbignSE1BQycsIG1hY0tleSwgbWFjRGF0YSkpLnNsaWNlKDAsIGtleVNpemUgPj4gMykpO1xuICAgIHJldHVybiB7IGNpcGhlcnRleHQsIHRhZywgaXYgfTtcbn1cbmFzeW5jIGZ1bmN0aW9uIGdjbUVuY3J5cHQoZW5jLCBwbGFpbnRleHQsIGNlaywgaXYsIGFhZCkge1xuICAgIGxldCBlbmNLZXk7XG4gICAgaWYgKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgZW5jS2V5ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGNlaywgJ0FFUy1HQ00nLCBmYWxzZSwgWydlbmNyeXB0J10pO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgY2hlY2tFbmNDcnlwdG9LZXkoY2VrLCBlbmMsICdlbmNyeXB0Jyk7XG4gICAgICAgIGVuY0tleSA9IGNlaztcbiAgICB9XG4gICAgY29uc3QgZW5jcnlwdGVkID0gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5lbmNyeXB0KHtcbiAgICAgICAgYWRkaXRpb25hbERhdGE6IGFhZCxcbiAgICAgICAgaXYsXG4gICAgICAgIG5hbWU6ICdBRVMtR0NNJyxcbiAgICAgICAgdGFnTGVuZ3RoOiAxMjgsXG4gICAgfSwgZW5jS2V5LCBwbGFpbnRleHQpKTtcbiAgICBjb25zdCB0YWcgPSBlbmNyeXB0ZWQuc2xpY2UoLTE2KTtcbiAgICBjb25zdCBjaXBoZXJ0ZXh0ID0gZW5jcnlwdGVkLnNsaWNlKDAsIC0xNik7XG4gICAgcmV0dXJuIHsgY2lwaGVydGV4dCwgdGFnLCBpdiB9O1xufVxuY29uc3QgZW5jcnlwdCA9IGFzeW5jIChlbmMsIHBsYWludGV4dCwgY2VrLCBpdiwgYWFkKSA9PiB7XG4gICAgaWYgKCFpc0NyeXB0b0tleShjZWspICYmICEoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoY2VrLCAuLi50eXBlcywgJ1VpbnQ4QXJyYXknKSk7XG4gICAgfVxuICAgIGlmIChpdikge1xuICAgICAgICBjaGVja0l2TGVuZ3RoKGVuYywgaXYpO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgaXYgPSBnZW5lcmF0ZUl2KGVuYyk7XG4gICAgfVxuICAgIHN3aXRjaCAoZW5jKSB7XG4gICAgICAgIGNhc2UgJ0ExMjhDQkMtSFMyNTYnOlxuICAgICAgICBjYXNlICdBMTkyQ0JDLUhTMzg0JzpcbiAgICAgICAgY2FzZSAnQTI1NkNCQy1IUzUxMic6XG4gICAgICAgICAgICBpZiAoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICAgICAgICAgIGNoZWNrQ2VrTGVuZ3RoKGNlaywgcGFyc2VJbnQoZW5jLnNsaWNlKC0zKSwgMTApKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBjYmNFbmNyeXB0KGVuYywgcGxhaW50ZXh0LCBjZWssIGl2LCBhYWQpO1xuICAgICAgICBjYXNlICdBMTI4R0NNJzpcbiAgICAgICAgY2FzZSAnQTE5MkdDTSc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ00nOlxuICAgICAgICAgICAgaWYgKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgICAgICAgICBjaGVja0Nla0xlbmd0aChjZWssIHBhcnNlSW50KGVuYy5zbGljZSgxLCA0KSwgMTApKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBnY21FbmNyeXB0KGVuYywgcGxhaW50ZXh0LCBjZWssIGl2LCBhYWQpO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ1Vuc3VwcG9ydGVkIEpXRSBDb250ZW50IEVuY3J5cHRpb24gQWxnb3JpdGhtJyk7XG4gICAgfVxufTtcbmV4cG9ydCBkZWZhdWx0IGVuY3J5cHQ7XG4iLCJpbXBvcnQgZW5jcnlwdCBmcm9tICcuLi9ydW50aW1lL2VuY3J5cHQuanMnO1xuaW1wb3J0IGRlY3J5cHQgZnJvbSAnLi4vcnVudGltZS9kZWNyeXB0LmpzJztcbmltcG9ydCB7IGVuY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gd3JhcChhbGcsIGtleSwgY2VrLCBpdikge1xuICAgIGNvbnN0IGp3ZUFsZ29yaXRobSA9IGFsZy5zbGljZSgwLCA3KTtcbiAgICBjb25zdCB3cmFwcGVkID0gYXdhaXQgZW5jcnlwdChqd2VBbGdvcml0aG0sIGNlaywga2V5LCBpdiwgbmV3IFVpbnQ4QXJyYXkoMCkpO1xuICAgIHJldHVybiB7XG4gICAgICAgIGVuY3J5cHRlZEtleTogd3JhcHBlZC5jaXBoZXJ0ZXh0LFxuICAgICAgICBpdjogYmFzZTY0dXJsKHdyYXBwZWQuaXYpLFxuICAgICAgICB0YWc6IGJhc2U2NHVybCh3cmFwcGVkLnRhZyksXG4gICAgfTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB1bndyYXAoYWxnLCBrZXksIGVuY3J5cHRlZEtleSwgaXYsIHRhZykge1xuICAgIGNvbnN0IGp3ZUFsZ29yaXRobSA9IGFsZy5zbGljZSgwLCA3KTtcbiAgICByZXR1cm4gZGVjcnlwdChqd2VBbGdvcml0aG0sIGtleSwgZW5jcnlwdGVkS2V5LCBpdiwgdGFnLCBuZXcgVWludDhBcnJheSgwKSk7XG59XG4iLCJpbXBvcnQgeyB1bndyYXAgYXMgYWVzS3cgfSBmcm9tICcuLi9ydW50aW1lL2Flc2t3LmpzJztcbmltcG9ydCAqIGFzIEVDREggZnJvbSAnLi4vcnVudGltZS9lY2RoZXMuanMnO1xuaW1wb3J0IHsgZGVjcnlwdCBhcyBwYmVzMkt3IH0gZnJvbSAnLi4vcnVudGltZS9wYmVzMmt3LmpzJztcbmltcG9ydCB7IGRlY3J5cHQgYXMgcnNhRXMgfSBmcm9tICcuLi9ydW50aW1lL3JzYWVzLmpzJztcbmltcG9ydCB7IGRlY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgbm9ybWFsaXplIGZyb20gJy4uL3J1bnRpbWUvbm9ybWFsaXplX2tleS5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkLCBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHsgYml0TGVuZ3RoIGFzIGNla0xlbmd0aCB9IGZyb20gJy4uL2xpYi9jZWsuanMnO1xuaW1wb3J0IHsgaW1wb3J0SldLIH0gZnJvbSAnLi4va2V5L2ltcG9ydC5qcyc7XG5pbXBvcnQgY2hlY2tLZXlUeXBlIGZyb20gJy4vY2hlY2tfa2V5X3R5cGUuanMnO1xuaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4vaXNfb2JqZWN0LmpzJztcbmltcG9ydCB7IHVud3JhcCBhcyBhZXNHY21LdyB9IGZyb20gJy4vYWVzZ2Nta3cuanMnO1xuYXN5bmMgZnVuY3Rpb24gZGVjcnlwdEtleU1hbmFnZW1lbnQoYWxnLCBrZXksIGVuY3J5cHRlZEtleSwgam9zZUhlYWRlciwgb3B0aW9ucykge1xuICAgIGNoZWNrS2V5VHlwZShhbGcsIGtleSwgJ2RlY3J5cHQnKTtcbiAgICBrZXkgPSAoYXdhaXQgbm9ybWFsaXplLm5vcm1hbGl6ZVByaXZhdGVLZXk/LihrZXksIGFsZykpIHx8IGtleTtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdkaXInOiB7XG4gICAgICAgICAgICBpZiAoZW5jcnlwdGVkS2V5ICE9PSB1bmRlZmluZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0VuY291bnRlcmVkIHVuZXhwZWN0ZWQgSldFIEVuY3J5cHRlZCBLZXknKTtcbiAgICAgICAgICAgIHJldHVybiBrZXk7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnRUNESC1FUyc6XG4gICAgICAgICAgICBpZiAoZW5jcnlwdGVkS2V5ICE9PSB1bmRlZmluZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0VuY291bnRlcmVkIHVuZXhwZWN0ZWQgSldFIEVuY3J5cHRlZCBLZXknKTtcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMTI4S1cnOlxuICAgICAgICBjYXNlICdFQ0RILUVTK0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTI1NktXJzoge1xuICAgICAgICAgICAgaWYgKCFpc09iamVjdChqb3NlSGVhZGVyLmVwaykpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwiZXBrXCIgKEVwaGVtZXJhbCBQdWJsaWMgS2V5KSBtaXNzaW5nIG9yIGludmFsaWRgKTtcbiAgICAgICAgICAgIGlmICghRUNESC5lY2RoQWxsb3dlZChrZXkpKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdFQ0RIIHdpdGggdGhlIHByb3ZpZGVkIGtleSBpcyBub3QgYWxsb3dlZCBvciBub3Qgc3VwcG9ydGVkIGJ5IHlvdXIgamF2YXNjcmlwdCBydW50aW1lJyk7XG4gICAgICAgICAgICBjb25zdCBlcGsgPSBhd2FpdCBpbXBvcnRKV0soam9zZUhlYWRlci5lcGssIGFsZyk7XG4gICAgICAgICAgICBsZXQgcGFydHlVSW5mbztcbiAgICAgICAgICAgIGxldCBwYXJ0eVZJbmZvO1xuICAgICAgICAgICAgaWYgKGpvc2VIZWFkZXIuYXB1ICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgICAgICBpZiAodHlwZW9mIGpvc2VIZWFkZXIuYXB1ICE9PSAnc3RyaW5nJylcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwiYXB1XCIgKEFncmVlbWVudCBQYXJ0eVVJbmZvKSBpbnZhbGlkYCk7XG4gICAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICAgICAgcGFydHlVSW5mbyA9IGJhc2U2NHVybChqb3NlSGVhZGVyLmFwdSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBhcHUnKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAoam9zZUhlYWRlci5hcHYgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgICAgIGlmICh0eXBlb2Ygam9zZUhlYWRlci5hcHYgIT09ICdzdHJpbmcnKVxuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSk9TRSBIZWFkZXIgXCJhcHZcIiAoQWdyZWVtZW50IFBhcnR5VkluZm8pIGludmFsaWRgKTtcbiAgICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgICAgICBwYXJ0eVZJbmZvID0gYmFzZTY0dXJsKGpvc2VIZWFkZXIuYXB2KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIGFwdicpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNvbnN0IHNoYXJlZFNlY3JldCA9IGF3YWl0IEVDREguZGVyaXZlS2V5KGVwaywga2V5LCBhbGcgPT09ICdFQ0RILUVTJyA/IGpvc2VIZWFkZXIuZW5jIDogYWxnLCBhbGcgPT09ICdFQ0RILUVTJyA/IGNla0xlbmd0aChqb3NlSGVhZGVyLmVuYykgOiBwYXJzZUludChhbGcuc2xpY2UoLTUsIC0yKSwgMTApLCBwYXJ0eVVJbmZvLCBwYXJ0eVZJbmZvKTtcbiAgICAgICAgICAgIGlmIChhbGcgPT09ICdFQ0RILUVTJylcbiAgICAgICAgICAgICAgICByZXR1cm4gc2hhcmVkU2VjcmV0O1xuICAgICAgICAgICAgaWYgKGVuY3J5cHRlZEtleSA9PT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgRW5jcnlwdGVkIEtleSBtaXNzaW5nJyk7XG4gICAgICAgICAgICByZXR1cm4gYWVzS3coYWxnLnNsaWNlKC02KSwgc2hhcmVkU2VjcmV0LCBlbmNyeXB0ZWRLZXkpO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ1JTQTFfNSc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQJzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMjU2JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMzg0JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtNTEyJzoge1xuICAgICAgICAgICAgaWYgKGVuY3J5cHRlZEtleSA9PT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgRW5jcnlwdGVkIEtleSBtaXNzaW5nJyk7XG4gICAgICAgICAgICByZXR1cm4gcnNhRXMoYWxnLCBrZXksIGVuY3J5cHRlZEtleSk7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnUEJFUzItSFMyNTYrQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnUEJFUzItSFMzODQrQTE5MktXJzpcbiAgICAgICAgY2FzZSAnUEJFUzItSFM1MTIrQTI1NktXJzoge1xuICAgICAgICAgICAgaWYgKGVuY3J5cHRlZEtleSA9PT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgRW5jcnlwdGVkIEtleSBtaXNzaW5nJyk7XG4gICAgICAgICAgICBpZiAodHlwZW9mIGpvc2VIZWFkZXIucDJjICE9PSAnbnVtYmVyJylcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSk9TRSBIZWFkZXIgXCJwMmNcIiAoUEJFUzIgQ291bnQpIG1pc3Npbmcgb3IgaW52YWxpZGApO1xuICAgICAgICAgICAgY29uc3QgcDJjTGltaXQgPSBvcHRpb25zPy5tYXhQQkVTMkNvdW50IHx8IDEwMDAwO1xuICAgICAgICAgICAgaWYgKGpvc2VIZWFkZXIucDJjID4gcDJjTGltaXQpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwicDJjXCIgKFBCRVMyIENvdW50KSBvdXQgaXMgb2YgYWNjZXB0YWJsZSBib3VuZHNgKTtcbiAgICAgICAgICAgIGlmICh0eXBlb2Ygam9zZUhlYWRlci5wMnMgIT09ICdzdHJpbmcnKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKGBKT1NFIEhlYWRlciBcInAyc1wiIChQQkVTMiBTYWx0KSBtaXNzaW5nIG9yIGludmFsaWRgKTtcbiAgICAgICAgICAgIGxldCBwMnM7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIHAycyA9IGJhc2U2NHVybChqb3NlSGVhZGVyLnAycyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBwMnMnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBwYmVzMkt3KGFsZywga2V5LCBlbmNyeXB0ZWRLZXksIGpvc2VIZWFkZXIucDJjLCBwMnMpO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGlmIChlbmNyeXB0ZWRLZXkgPT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEVuY3J5cHRlZCBLZXkgbWlzc2luZycpO1xuICAgICAgICAgICAgcmV0dXJuIGFlc0t3KGFsZywga2V5LCBlbmNyeXB0ZWRLZXkpO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0ExMjhHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ01LVyc6IHtcbiAgICAgICAgICAgIGlmIChlbmNyeXB0ZWRLZXkgPT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEVuY3J5cHRlZCBLZXkgbWlzc2luZycpO1xuICAgICAgICAgICAgaWYgKHR5cGVvZiBqb3NlSGVhZGVyLml2ICE9PSAnc3RyaW5nJylcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSk9TRSBIZWFkZXIgXCJpdlwiIChJbml0aWFsaXphdGlvbiBWZWN0b3IpIG1pc3Npbmcgb3IgaW52YWxpZGApO1xuICAgICAgICAgICAgaWYgKHR5cGVvZiBqb3NlSGVhZGVyLnRhZyAhPT0gJ3N0cmluZycpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwidGFnXCIgKEF1dGhlbnRpY2F0aW9uIFRhZykgbWlzc2luZyBvciBpbnZhbGlkYCk7XG4gICAgICAgICAgICBsZXQgaXY7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGl2ID0gYmFzZTY0dXJsKGpvc2VIZWFkZXIuaXYpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgaXYnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGxldCB0YWc7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIHRhZyA9IGJhc2U2NHVybChqb3NlSGVhZGVyLnRhZyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSB0YWcnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBhZXNHY21LdyhhbGcsIGtleSwgZW5jcnlwdGVkS2V5LCBpdiwgdGFnKTtcbiAgICAgICAgfVxuICAgICAgICBkZWZhdWx0OiB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBcImFsZ1wiIChKV0UgQWxnb3JpdGhtKSBoZWFkZXIgdmFsdWUnKTtcbiAgICAgICAgfVxuICAgIH1cbn1cbmV4cG9ydCBkZWZhdWx0IGRlY3J5cHRLZXlNYW5hZ2VtZW50O1xuIiwiaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmZ1bmN0aW9uIHZhbGlkYXRlQ3JpdChFcnIsIHJlY29nbml6ZWREZWZhdWx0LCByZWNvZ25pemVkT3B0aW9uLCBwcm90ZWN0ZWRIZWFkZXIsIGpvc2VIZWFkZXIpIHtcbiAgICBpZiAoam9zZUhlYWRlci5jcml0ICE9PSB1bmRlZmluZWQgJiYgcHJvdGVjdGVkSGVhZGVyPy5jcml0ID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycignXCJjcml0XCIgKENyaXRpY2FsKSBIZWFkZXIgUGFyYW1ldGVyIE1VU1QgYmUgaW50ZWdyaXR5IHByb3RlY3RlZCcpO1xuICAgIH1cbiAgICBpZiAoIXByb3RlY3RlZEhlYWRlciB8fCBwcm90ZWN0ZWRIZWFkZXIuY3JpdCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHJldHVybiBuZXcgU2V0KCk7XG4gICAgfVxuICAgIGlmICghQXJyYXkuaXNBcnJheShwcm90ZWN0ZWRIZWFkZXIuY3JpdCkgfHxcbiAgICAgICAgcHJvdGVjdGVkSGVhZGVyLmNyaXQubGVuZ3RoID09PSAwIHx8XG4gICAgICAgIHByb3RlY3RlZEhlYWRlci5jcml0LnNvbWUoKGlucHV0KSA9PiB0eXBlb2YgaW5wdXQgIT09ICdzdHJpbmcnIHx8IGlucHV0Lmxlbmd0aCA9PT0gMCkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycignXCJjcml0XCIgKENyaXRpY2FsKSBIZWFkZXIgUGFyYW1ldGVyIE1VU1QgYmUgYW4gYXJyYXkgb2Ygbm9uLWVtcHR5IHN0cmluZ3Mgd2hlbiBwcmVzZW50Jyk7XG4gICAgfVxuICAgIGxldCByZWNvZ25pemVkO1xuICAgIGlmIChyZWNvZ25pemVkT3B0aW9uICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmVjb2duaXplZCA9IG5ldyBNYXAoWy4uLk9iamVjdC5lbnRyaWVzKHJlY29nbml6ZWRPcHRpb24pLCAuLi5yZWNvZ25pemVkRGVmYXVsdC5lbnRyaWVzKCldKTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIHJlY29nbml6ZWQgPSByZWNvZ25pemVkRGVmYXVsdDtcbiAgICB9XG4gICAgZm9yIChjb25zdCBwYXJhbWV0ZXIgb2YgcHJvdGVjdGVkSGVhZGVyLmNyaXQpIHtcbiAgICAgICAgaWYgKCFyZWNvZ25pemVkLmhhcyhwYXJhbWV0ZXIpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZChgRXh0ZW5zaW9uIEhlYWRlciBQYXJhbWV0ZXIgXCIke3BhcmFtZXRlcn1cIiBpcyBub3QgcmVjb2duaXplZGApO1xuICAgICAgICB9XG4gICAgICAgIGlmIChqb3NlSGVhZGVyW3BhcmFtZXRlcl0gPT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycihgRXh0ZW5zaW9uIEhlYWRlciBQYXJhbWV0ZXIgXCIke3BhcmFtZXRlcn1cIiBpcyBtaXNzaW5nYCk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHJlY29nbml6ZWQuZ2V0KHBhcmFtZXRlcikgJiYgcHJvdGVjdGVkSGVhZGVyW3BhcmFtZXRlcl0gPT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycihgRXh0ZW5zaW9uIEhlYWRlciBQYXJhbWV0ZXIgXCIke3BhcmFtZXRlcn1cIiBNVVNUIGJlIGludGVncml0eSBwcm90ZWN0ZWRgKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gbmV3IFNldChwcm90ZWN0ZWRIZWFkZXIuY3JpdCk7XG59XG5leHBvcnQgZGVmYXVsdCB2YWxpZGF0ZUNyaXQ7XG4iLCJjb25zdCB2YWxpZGF0ZUFsZ29yaXRobXMgPSAob3B0aW9uLCBhbGdvcml0aG1zKSA9PiB7XG4gICAgaWYgKGFsZ29yaXRobXMgIT09IHVuZGVmaW5lZCAmJlxuICAgICAgICAoIUFycmF5LmlzQXJyYXkoYWxnb3JpdGhtcykgfHwgYWxnb3JpdGhtcy5zb21lKChzKSA9PiB0eXBlb2YgcyAhPT0gJ3N0cmluZycpKSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGBcIiR7b3B0aW9ufVwiIG9wdGlvbiBtdXN0IGJlIGFuIGFycmF5IG9mIHN0cmluZ3NgKTtcbiAgICB9XG4gICAgaWYgKCFhbGdvcml0aG1zKSB7XG4gICAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgfVxuICAgIHJldHVybiBuZXcgU2V0KGFsZ29yaXRobXMpO1xufTtcbmV4cG9ydCBkZWZhdWx0IHZhbGlkYXRlQWxnb3JpdGhtcztcbiIsImltcG9ydCB7IGRlY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi8uLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgZGVjcnlwdCBmcm9tICcuLi8uLi9ydW50aW1lL2RlY3J5cHQuanMnO1xuaW1wb3J0IHsgSk9TRUFsZ05vdEFsbG93ZWQsIEpPU0VOb3RTdXBwb3J0ZWQsIEpXRUludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgaXNEaXNqb2ludCBmcm9tICcuLi8uLi9saWIvaXNfZGlzam9pbnQuanMnO1xuaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4uLy4uL2xpYi9pc19vYmplY3QuanMnO1xuaW1wb3J0IGRlY3J5cHRLZXlNYW5hZ2VtZW50IGZyb20gJy4uLy4uL2xpYi9kZWNyeXB0X2tleV9tYW5hZ2VtZW50LmpzJztcbmltcG9ydCB7IGVuY29kZXIsIGRlY29kZXIsIGNvbmNhdCB9IGZyb20gJy4uLy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IGdlbmVyYXRlQ2VrIGZyb20gJy4uLy4uL2xpYi9jZWsuanMnO1xuaW1wb3J0IHZhbGlkYXRlQ3JpdCBmcm9tICcuLi8uLi9saWIvdmFsaWRhdGVfY3JpdC5qcyc7XG5pbXBvcnQgdmFsaWRhdGVBbGdvcml0aG1zIGZyb20gJy4uLy4uL2xpYi92YWxpZGF0ZV9hbGdvcml0aG1zLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBmbGF0dGVuZWREZWNyeXB0KGp3ZSwga2V5LCBvcHRpb25zKSB7XG4gICAgaWYgKCFpc09iamVjdChqd2UpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGbGF0dGVuZWQgSldFIG11c3QgYmUgYW4gb2JqZWN0Jyk7XG4gICAgfVxuICAgIGlmIChqd2UucHJvdGVjdGVkID09PSB1bmRlZmluZWQgJiYgandlLmhlYWRlciA9PT0gdW5kZWZpbmVkICYmIGp3ZS51bnByb3RlY3RlZCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKT1NFIEhlYWRlciBtaXNzaW5nJyk7XG4gICAgfVxuICAgIGlmIChqd2UuaXYgIT09IHVuZGVmaW5lZCAmJiB0eXBlb2YgandlLml2ICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEluaXRpYWxpemF0aW9uIFZlY3RvciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIGp3ZS5jaXBoZXJ0ZXh0ICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIENpcGhlcnRleHQgbWlzc2luZyBvciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoandlLnRhZyAhPT0gdW5kZWZpbmVkICYmIHR5cGVvZiBqd2UudGFnICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEF1dGhlbnRpY2F0aW9uIFRhZyBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoandlLnByb3RlY3RlZCAhPT0gdW5kZWZpbmVkICYmIHR5cGVvZiBqd2UucHJvdGVjdGVkICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFByb3RlY3RlZCBIZWFkZXIgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3ZS5lbmNyeXB0ZWRfa2V5ICE9PSB1bmRlZmluZWQgJiYgdHlwZW9mIGp3ZS5lbmNyeXB0ZWRfa2V5ICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEVuY3J5cHRlZCBLZXkgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3ZS5hYWQgIT09IHVuZGVmaW5lZCAmJiB0eXBlb2YgandlLmFhZCAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBBQUQgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3ZS5oZWFkZXIgIT09IHVuZGVmaW5lZCAmJiAhaXNPYmplY3QoandlLmhlYWRlcikpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBTaGFyZWQgVW5wcm90ZWN0ZWQgSGVhZGVyIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmIChqd2UudW5wcm90ZWN0ZWQgIT09IHVuZGVmaW5lZCAmJiAhaXNPYmplY3QoandlLnVucHJvdGVjdGVkKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFBlci1SZWNpcGllbnQgVW5wcm90ZWN0ZWQgSGVhZGVyIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGxldCBwYXJzZWRQcm90O1xuICAgIGlmIChqd2UucHJvdGVjdGVkKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBjb25zdCBwcm90ZWN0ZWRIZWFkZXIgPSBiYXNlNjR1cmwoandlLnByb3RlY3RlZCk7XG4gICAgICAgICAgICBwYXJzZWRQcm90ID0gSlNPTi5wYXJzZShkZWNvZGVyLmRlY29kZShwcm90ZWN0ZWRIZWFkZXIpKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFByb3RlY3RlZCBIZWFkZXIgaXMgaW52YWxpZCcpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGlmICghaXNEaXNqb2ludChwYXJzZWRQcm90LCBqd2UuaGVhZGVyLCBqd2UudW5wcm90ZWN0ZWQpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgUHJvdGVjdGVkLCBKV0UgVW5wcm90ZWN0ZWQgSGVhZGVyLCBhbmQgSldFIFBlci1SZWNpcGllbnQgVW5wcm90ZWN0ZWQgSGVhZGVyIFBhcmFtZXRlciBuYW1lcyBtdXN0IGJlIGRpc2pvaW50Jyk7XG4gICAgfVxuICAgIGNvbnN0IGpvc2VIZWFkZXIgPSB7XG4gICAgICAgIC4uLnBhcnNlZFByb3QsXG4gICAgICAgIC4uLmp3ZS5oZWFkZXIsXG4gICAgICAgIC4uLmp3ZS51bnByb3RlY3RlZCxcbiAgICB9O1xuICAgIHZhbGlkYXRlQ3JpdChKV0VJbnZhbGlkLCBuZXcgTWFwKCksIG9wdGlvbnM/LmNyaXQsIHBhcnNlZFByb3QsIGpvc2VIZWFkZXIpO1xuICAgIGlmIChqb3NlSGVhZGVyLnppcCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdKV0UgXCJ6aXBcIiAoQ29tcHJlc3Npb24gQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIGlzIG5vdCBzdXBwb3J0ZWQuJyk7XG4gICAgfVxuICAgIGNvbnN0IHsgYWxnLCBlbmMgfSA9IGpvc2VIZWFkZXI7XG4gICAgaWYgKHR5cGVvZiBhbGcgIT09ICdzdHJpbmcnIHx8ICFhbGcpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ21pc3NpbmcgSldFIEFsZ29yaXRobSAoYWxnKSBpbiBKV0UgSGVhZGVyJyk7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgZW5jICE9PSAnc3RyaW5nJyB8fCAhZW5jKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdtaXNzaW5nIEpXRSBFbmNyeXB0aW9uIEFsZ29yaXRobSAoZW5jKSBpbiBKV0UgSGVhZGVyJyk7XG4gICAgfVxuICAgIGNvbnN0IGtleU1hbmFnZW1lbnRBbGdvcml0aG1zID0gb3B0aW9ucyAmJiB2YWxpZGF0ZUFsZ29yaXRobXMoJ2tleU1hbmFnZW1lbnRBbGdvcml0aG1zJywgb3B0aW9ucy5rZXlNYW5hZ2VtZW50QWxnb3JpdGhtcyk7XG4gICAgY29uc3QgY29udGVudEVuY3J5cHRpb25BbGdvcml0aG1zID0gb3B0aW9ucyAmJlxuICAgICAgICB2YWxpZGF0ZUFsZ29yaXRobXMoJ2NvbnRlbnRFbmNyeXB0aW9uQWxnb3JpdGhtcycsIG9wdGlvbnMuY29udGVudEVuY3J5cHRpb25BbGdvcml0aG1zKTtcbiAgICBpZiAoKGtleU1hbmFnZW1lbnRBbGdvcml0aG1zICYmICFrZXlNYW5hZ2VtZW50QWxnb3JpdGhtcy5oYXMoYWxnKSkgfHxcbiAgICAgICAgKCFrZXlNYW5hZ2VtZW50QWxnb3JpdGhtcyAmJiBhbGcuc3RhcnRzV2l0aCgnUEJFUzInKSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpPU0VBbGdOb3RBbGxvd2VkKCdcImFsZ1wiIChBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgdmFsdWUgbm90IGFsbG93ZWQnKTtcbiAgICB9XG4gICAgaWYgKGNvbnRlbnRFbmNyeXB0aW9uQWxnb3JpdGhtcyAmJiAhY29udGVudEVuY3J5cHRpb25BbGdvcml0aG1zLmhhcyhlbmMpKSB7XG4gICAgICAgIHRocm93IG5ldyBKT1NFQWxnTm90QWxsb3dlZCgnXCJlbmNcIiAoRW5jcnlwdGlvbiBBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgdmFsdWUgbm90IGFsbG93ZWQnKTtcbiAgICB9XG4gICAgbGV0IGVuY3J5cHRlZEtleTtcbiAgICBpZiAoandlLmVuY3J5cHRlZF9rZXkgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgZW5jcnlwdGVkS2V5ID0gYmFzZTY0dXJsKGp3ZS5lbmNyeXB0ZWRfa2V5KTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIGVuY3J5cHRlZF9rZXknKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBsZXQgcmVzb2x2ZWRLZXkgPSBmYWxzZTtcbiAgICBpZiAodHlwZW9mIGtleSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICBrZXkgPSBhd2FpdCBrZXkocGFyc2VkUHJvdCwgandlKTtcbiAgICAgICAgcmVzb2x2ZWRLZXkgPSB0cnVlO1xuICAgIH1cbiAgICBsZXQgY2VrO1xuICAgIHRyeSB7XG4gICAgICAgIGNlayA9IGF3YWl0IGRlY3J5cHRLZXlNYW5hZ2VtZW50KGFsZywga2V5LCBlbmNyeXB0ZWRLZXksIGpvc2VIZWFkZXIsIG9wdGlvbnMpO1xuICAgIH1cbiAgICBjYXRjaCAoZXJyKSB7XG4gICAgICAgIGlmIChlcnIgaW5zdGFuY2VvZiBUeXBlRXJyb3IgfHwgZXJyIGluc3RhbmNlb2YgSldFSW52YWxpZCB8fCBlcnIgaW5zdGFuY2VvZiBKT1NFTm90U3VwcG9ydGVkKSB7XG4gICAgICAgICAgICB0aHJvdyBlcnI7XG4gICAgICAgIH1cbiAgICAgICAgY2VrID0gZ2VuZXJhdGVDZWsoZW5jKTtcbiAgICB9XG4gICAgbGV0IGl2O1xuICAgIGxldCB0YWc7XG4gICAgaWYgKGp3ZS5pdiAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBpdiA9IGJhc2U2NHVybChqd2UuaXYpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgaXYnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBpZiAoandlLnRhZyAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICB0YWcgPSBiYXNlNjR1cmwoandlLnRhZyk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSB0YWcnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBjb25zdCBwcm90ZWN0ZWRIZWFkZXIgPSBlbmNvZGVyLmVuY29kZShqd2UucHJvdGVjdGVkID8/ICcnKTtcbiAgICBsZXQgYWRkaXRpb25hbERhdGE7XG4gICAgaWYgKGp3ZS5hYWQgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICBhZGRpdGlvbmFsRGF0YSA9IGNvbmNhdChwcm90ZWN0ZWRIZWFkZXIsIGVuY29kZXIuZW5jb2RlKCcuJyksIGVuY29kZXIuZW5jb2RlKGp3ZS5hYWQpKTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIGFkZGl0aW9uYWxEYXRhID0gcHJvdGVjdGVkSGVhZGVyO1xuICAgIH1cbiAgICBsZXQgY2lwaGVydGV4dDtcbiAgICB0cnkge1xuICAgICAgICBjaXBoZXJ0ZXh0ID0gYmFzZTY0dXJsKGp3ZS5jaXBoZXJ0ZXh0KTtcbiAgICB9XG4gICAgY2F0Y2gge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIGNpcGhlcnRleHQnKTtcbiAgICB9XG4gICAgY29uc3QgcGxhaW50ZXh0ID0gYXdhaXQgZGVjcnlwdChlbmMsIGNlaywgY2lwaGVydGV4dCwgaXYsIHRhZywgYWRkaXRpb25hbERhdGEpO1xuICAgIGNvbnN0IHJlc3VsdCA9IHsgcGxhaW50ZXh0IH07XG4gICAgaWYgKGp3ZS5wcm90ZWN0ZWQgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICByZXN1bHQucHJvdGVjdGVkSGVhZGVyID0gcGFyc2VkUHJvdDtcbiAgICB9XG4gICAgaWYgKGp3ZS5hYWQgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgcmVzdWx0LmFkZGl0aW9uYWxBdXRoZW50aWNhdGVkRGF0YSA9IGJhc2U2NHVybChqd2UuYWFkKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIGFhZCcpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGlmIChqd2UudW5wcm90ZWN0ZWQgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICByZXN1bHQuc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIgPSBqd2UudW5wcm90ZWN0ZWQ7XG4gICAgfVxuICAgIGlmIChqd2UuaGVhZGVyICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmVzdWx0LnVucHJvdGVjdGVkSGVhZGVyID0gandlLmhlYWRlcjtcbiAgICB9XG4gICAgaWYgKHJlc29sdmVkS2V5KSB7XG4gICAgICAgIHJldHVybiB7IC4uLnJlc3VsdCwga2V5IH07XG4gICAgfVxuICAgIHJldHVybiByZXN1bHQ7XG59XG4iLCJpbXBvcnQgeyBmbGF0dGVuZWREZWNyeXB0IH0gZnJvbSAnLi4vZmxhdHRlbmVkL2RlY3J5cHQuanMnO1xuaW1wb3J0IHsgSldFSW52YWxpZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IGRlY29kZXIgfSBmcm9tICcuLi8uLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjb21wYWN0RGVjcnlwdChqd2UsIGtleSwgb3B0aW9ucykge1xuICAgIGlmIChqd2UgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIGp3ZSA9IGRlY29kZXIuZGVjb2RlKGp3ZSk7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgandlICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnQ29tcGFjdCBKV0UgbXVzdCBiZSBhIHN0cmluZyBvciBVaW50OEFycmF5Jyk7XG4gICAgfVxuICAgIGNvbnN0IHsgMDogcHJvdGVjdGVkSGVhZGVyLCAxOiBlbmNyeXB0ZWRLZXksIDI6IGl2LCAzOiBjaXBoZXJ0ZXh0LCA0OiB0YWcsIGxlbmd0aCwgfSA9IGp3ZS5zcGxpdCgnLicpO1xuICAgIGlmIChsZW5ndGggIT09IDUpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ludmFsaWQgQ29tcGFjdCBKV0UnKTtcbiAgICB9XG4gICAgY29uc3QgZGVjcnlwdGVkID0gYXdhaXQgZmxhdHRlbmVkRGVjcnlwdCh7XG4gICAgICAgIGNpcGhlcnRleHQsXG4gICAgICAgIGl2OiBpdiB8fCB1bmRlZmluZWQsXG4gICAgICAgIHByb3RlY3RlZDogcHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICB0YWc6IHRhZyB8fCB1bmRlZmluZWQsXG4gICAgICAgIGVuY3J5cHRlZF9rZXk6IGVuY3J5cHRlZEtleSB8fCB1bmRlZmluZWQsXG4gICAgfSwga2V5LCBvcHRpb25zKTtcbiAgICBjb25zdCByZXN1bHQgPSB7IHBsYWludGV4dDogZGVjcnlwdGVkLnBsYWludGV4dCwgcHJvdGVjdGVkSGVhZGVyOiBkZWNyeXB0ZWQucHJvdGVjdGVkSGVhZGVyIH07XG4gICAgaWYgKHR5cGVvZiBrZXkgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAgcmV0dXJuIHsgLi4ucmVzdWx0LCBrZXk6IGRlY3J5cHRlZC5rZXkgfTtcbiAgICB9XG4gICAgcmV0dXJuIHJlc3VsdDtcbn1cbiIsImltcG9ydCB7IGZsYXR0ZW5lZERlY3J5cHQgfSBmcm9tICcuLi9mbGF0dGVuZWQvZGVjcnlwdC5qcyc7XG5pbXBvcnQgeyBKV0VEZWNyeXB0aW9uRmFpbGVkLCBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4uLy4uL2xpYi9pc19vYmplY3QuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdlbmVyYWxEZWNyeXB0KGp3ZSwga2V5LCBvcHRpb25zKSB7XG4gICAgaWYgKCFpc09iamVjdChqd2UpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdHZW5lcmFsIEpXRSBtdXN0IGJlIGFuIG9iamVjdCcpO1xuICAgIH1cbiAgICBpZiAoIUFycmF5LmlzQXJyYXkoandlLnJlY2lwaWVudHMpIHx8ICFqd2UucmVjaXBpZW50cy5ldmVyeShpc09iamVjdCkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBSZWNpcGllbnRzIG1pc3Npbmcgb3IgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKCFqd2UucmVjaXBpZW50cy5sZW5ndGgpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBSZWNpcGllbnRzIGhhcyBubyBtZW1iZXJzJyk7XG4gICAgfVxuICAgIGZvciAoY29uc3QgcmVjaXBpZW50IG9mIGp3ZS5yZWNpcGllbnRzKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICByZXR1cm4gYXdhaXQgZmxhdHRlbmVkRGVjcnlwdCh7XG4gICAgICAgICAgICAgICAgYWFkOiBqd2UuYWFkLFxuICAgICAgICAgICAgICAgIGNpcGhlcnRleHQ6IGp3ZS5jaXBoZXJ0ZXh0LFxuICAgICAgICAgICAgICAgIGVuY3J5cHRlZF9rZXk6IHJlY2lwaWVudC5lbmNyeXB0ZWRfa2V5LFxuICAgICAgICAgICAgICAgIGhlYWRlcjogcmVjaXBpZW50LmhlYWRlcixcbiAgICAgICAgICAgICAgICBpdjogandlLml2LFxuICAgICAgICAgICAgICAgIHByb3RlY3RlZDogandlLnByb3RlY3RlZCxcbiAgICAgICAgICAgICAgICB0YWc6IGp3ZS50YWcsXG4gICAgICAgICAgICAgICAgdW5wcm90ZWN0ZWQ6IGp3ZS51bnByb3RlY3RlZCxcbiAgICAgICAgICAgIH0sIGtleSwgb3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICB9XG4gICAgfVxuICAgIHRocm93IG5ldyBKV0VEZWNyeXB0aW9uRmFpbGVkKCk7XG59XG4iLCJleHBvcnQgY29uc3QgdW5wcm90ZWN0ZWQgPSBTeW1ib2woKTtcbiIsImltcG9ydCBjcnlwdG8sIHsgaXNDcnlwdG9LZXkgfSBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyBlbmNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmNvbnN0IGtleVRvSldLID0gYXN5bmMgKGtleSkgPT4ge1xuICAgIGlmIChrZXkgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBrdHk6ICdvY3QnLFxuICAgICAgICAgICAgazogYmFzZTY0dXJsKGtleSksXG4gICAgICAgIH07XG4gICAgfVxuICAgIGlmICghaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzLCAnVWludDhBcnJheScpKTtcbiAgICB9XG4gICAgaWYgKCFrZXkuZXh0cmFjdGFibGUpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignbm9uLWV4dHJhY3RhYmxlIENyeXB0b0tleSBjYW5ub3QgYmUgZXhwb3J0ZWQgYXMgYSBKV0snKTtcbiAgICB9XG4gICAgY29uc3QgeyBleHQsIGtleV9vcHMsIGFsZywgdXNlLCAuLi5qd2sgfSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdqd2snLCBrZXkpO1xuICAgIHJldHVybiBqd2s7XG59O1xuZXhwb3J0IGRlZmF1bHQga2V5VG9KV0s7XG4iLCJpbXBvcnQgeyB0b1NQS0kgYXMgZXhwb3J0UHVibGljIH0gZnJvbSAnLi4vcnVudGltZS9hc24xLmpzJztcbmltcG9ydCB7IHRvUEtDUzggYXMgZXhwb3J0UHJpdmF0ZSB9IGZyb20gJy4uL3J1bnRpbWUvYXNuMS5qcyc7XG5pbXBvcnQga2V5VG9KV0sgZnJvbSAnLi4vcnVudGltZS9rZXlfdG9fandrLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBleHBvcnRTUEtJKGtleSkge1xuICAgIHJldHVybiBleHBvcnRQdWJsaWMoa2V5KTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBleHBvcnRQS0NTOChrZXkpIHtcbiAgICByZXR1cm4gZXhwb3J0UHJpdmF0ZShrZXkpO1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGV4cG9ydEpXSyhrZXkpIHtcbiAgICByZXR1cm4ga2V5VG9KV0soa2V5KTtcbn1cbiIsImltcG9ydCB7IHdyYXAgYXMgYWVzS3cgfSBmcm9tICcuLi9ydW50aW1lL2Flc2t3LmpzJztcbmltcG9ydCAqIGFzIEVDREggZnJvbSAnLi4vcnVudGltZS9lY2RoZXMuanMnO1xuaW1wb3J0IHsgZW5jcnlwdCBhcyBwYmVzMkt3IH0gZnJvbSAnLi4vcnVudGltZS9wYmVzMmt3LmpzJztcbmltcG9ydCB7IGVuY3J5cHQgYXMgcnNhRXMgfSBmcm9tICcuLi9ydW50aW1lL3JzYWVzLmpzJztcbmltcG9ydCB7IGVuY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgbm9ybWFsaXplIGZyb20gJy4uL3J1bnRpbWUvbm9ybWFsaXplX2tleS5qcyc7XG5pbXBvcnQgZ2VuZXJhdGVDZWssIHsgYml0TGVuZ3RoIGFzIGNla0xlbmd0aCB9IGZyb20gJy4uL2xpYi9jZWsuanMnO1xuaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IGV4cG9ydEpXSyB9IGZyb20gJy4uL2tleS9leHBvcnQuanMnO1xuaW1wb3J0IGNoZWNrS2V5VHlwZSBmcm9tICcuL2NoZWNrX2tleV90eXBlLmpzJztcbmltcG9ydCB7IHdyYXAgYXMgYWVzR2NtS3cgfSBmcm9tICcuL2Flc2djbWt3LmpzJztcbmFzeW5jIGZ1bmN0aW9uIGVuY3J5cHRLZXlNYW5hZ2VtZW50KGFsZywgZW5jLCBrZXksIHByb3ZpZGVkQ2VrLCBwcm92aWRlZFBhcmFtZXRlcnMgPSB7fSkge1xuICAgIGxldCBlbmNyeXB0ZWRLZXk7XG4gICAgbGV0IHBhcmFtZXRlcnM7XG4gICAgbGV0IGNlaztcbiAgICBjaGVja0tleVR5cGUoYWxnLCBrZXksICdlbmNyeXB0Jyk7XG4gICAga2V5ID0gKGF3YWl0IG5vcm1hbGl6ZS5ub3JtYWxpemVQdWJsaWNLZXk/LihrZXksIGFsZykpIHx8IGtleTtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdkaXInOiB7XG4gICAgICAgICAgICBjZWsgPSBrZXk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdFQ0RILUVTJzpcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMTI4S1cnOlxuICAgICAgICBjYXNlICdFQ0RILUVTK0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTI1NktXJzoge1xuICAgICAgICAgICAgaWYgKCFFQ0RILmVjZGhBbGxvd2VkKGtleSkpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnRUNESCB3aXRoIHRoZSBwcm92aWRlZCBrZXkgaXMgbm90IGFsbG93ZWQgb3Igbm90IHN1cHBvcnRlZCBieSB5b3VyIGphdmFzY3JpcHQgcnVudGltZScpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY29uc3QgeyBhcHUsIGFwdiB9ID0gcHJvdmlkZWRQYXJhbWV0ZXJzO1xuICAgICAgICAgICAgbGV0IHsgZXBrOiBlcGhlbWVyYWxLZXkgfSA9IHByb3ZpZGVkUGFyYW1ldGVycztcbiAgICAgICAgICAgIGVwaGVtZXJhbEtleSB8fCAoZXBoZW1lcmFsS2V5ID0gKGF3YWl0IEVDREguZ2VuZXJhdGVFcGsoa2V5KSkucHJpdmF0ZUtleSk7XG4gICAgICAgICAgICBjb25zdCB7IHgsIHksIGNydiwga3R5IH0gPSBhd2FpdCBleHBvcnRKV0soZXBoZW1lcmFsS2V5KTtcbiAgICAgICAgICAgIGNvbnN0IHNoYXJlZFNlY3JldCA9IGF3YWl0IEVDREguZGVyaXZlS2V5KGtleSwgZXBoZW1lcmFsS2V5LCBhbGcgPT09ICdFQ0RILUVTJyA/IGVuYyA6IGFsZywgYWxnID09PSAnRUNESC1FUycgPyBjZWtMZW5ndGgoZW5jKSA6IHBhcnNlSW50KGFsZy5zbGljZSgtNSwgLTIpLCAxMCksIGFwdSwgYXB2KTtcbiAgICAgICAgICAgIHBhcmFtZXRlcnMgPSB7IGVwazogeyB4LCBjcnYsIGt0eSB9IH07XG4gICAgICAgICAgICBpZiAoa3R5ID09PSAnRUMnKVxuICAgICAgICAgICAgICAgIHBhcmFtZXRlcnMuZXBrLnkgPSB5O1xuICAgICAgICAgICAgaWYgKGFwdSlcbiAgICAgICAgICAgICAgICBwYXJhbWV0ZXJzLmFwdSA9IGJhc2U2NHVybChhcHUpO1xuICAgICAgICAgICAgaWYgKGFwdilcbiAgICAgICAgICAgICAgICBwYXJhbWV0ZXJzLmFwdiA9IGJhc2U2NHVybChhcHYpO1xuICAgICAgICAgICAgaWYgKGFsZyA9PT0gJ0VDREgtRVMnKSB7XG4gICAgICAgICAgICAgICAgY2VrID0gc2hhcmVkU2VjcmV0O1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY2VrID0gcHJvdmlkZWRDZWsgfHwgZ2VuZXJhdGVDZWsoZW5jKTtcbiAgICAgICAgICAgIGNvbnN0IGt3QWxnID0gYWxnLnNsaWNlKC02KTtcbiAgICAgICAgICAgIGVuY3J5cHRlZEtleSA9IGF3YWl0IGFlc0t3KGt3QWxnLCBzaGFyZWRTZWNyZXQsIGNlayk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdSU0ExXzUnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTI1Nic6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTM4NCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTUxMic6IHtcbiAgICAgICAgICAgIGNlayA9IHByb3ZpZGVkQ2VrIHx8IGdlbmVyYXRlQ2VrKGVuYyk7XG4gICAgICAgICAgICBlbmNyeXB0ZWRLZXkgPSBhd2FpdCByc2FFcyhhbGcsIGtleSwgY2VrKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ1BCRVMyLUhTMjU2K0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ1BCRVMyLUhTMzg0K0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ1BCRVMyLUhTNTEyK0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGNlayA9IHByb3ZpZGVkQ2VrIHx8IGdlbmVyYXRlQ2VrKGVuYyk7XG4gICAgICAgICAgICBjb25zdCB7IHAyYywgcDJzIH0gPSBwcm92aWRlZFBhcmFtZXRlcnM7XG4gICAgICAgICAgICAoeyBlbmNyeXB0ZWRLZXksIC4uLnBhcmFtZXRlcnMgfSA9IGF3YWl0IHBiZXMyS3coYWxnLCBrZXksIGNlaywgcDJjLCBwMnMpKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGNlayA9IHByb3ZpZGVkQ2VrIHx8IGdlbmVyYXRlQ2VrKGVuYyk7XG4gICAgICAgICAgICBlbmNyeXB0ZWRLZXkgPSBhd2FpdCBhZXNLdyhhbGcsIGtleSwgY2VrKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0ExMjhHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ01LVyc6IHtcbiAgICAgICAgICAgIGNlayA9IHByb3ZpZGVkQ2VrIHx8IGdlbmVyYXRlQ2VrKGVuYyk7XG4gICAgICAgICAgICBjb25zdCB7IGl2IH0gPSBwcm92aWRlZFBhcmFtZXRlcnM7XG4gICAgICAgICAgICAoeyBlbmNyeXB0ZWRLZXksIC4uLnBhcmFtZXRlcnMgfSA9IGF3YWl0IGFlc0djbUt3KGFsZywga2V5LCBjZWssIGl2KSk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBkZWZhdWx0OiB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBcImFsZ1wiIChKV0UgQWxnb3JpdGhtKSBoZWFkZXIgdmFsdWUnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4geyBjZWssIGVuY3J5cHRlZEtleSwgcGFyYW1ldGVycyB9O1xufVxuZXhwb3J0IGRlZmF1bHQgZW5jcnlwdEtleU1hbmFnZW1lbnQ7XG4iLCJpbXBvcnQgeyBlbmNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi4vLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHsgdW5wcm90ZWN0ZWQgfSBmcm9tICcuLi8uLi9saWIvcHJpdmF0ZV9zeW1ib2xzLmpzJztcbmltcG9ydCBlbmNyeXB0IGZyb20gJy4uLy4uL3J1bnRpbWUvZW5jcnlwdC5qcyc7XG5pbXBvcnQgZW5jcnlwdEtleU1hbmFnZW1lbnQgZnJvbSAnLi4vLi4vbGliL2VuY3J5cHRfa2V5X21hbmFnZW1lbnQuanMnO1xuaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCwgSldFSW52YWxpZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCBpc0Rpc2pvaW50IGZyb20gJy4uLy4uL2xpYi9pc19kaXNqb2ludC5qcyc7XG5pbXBvcnQgeyBlbmNvZGVyLCBkZWNvZGVyLCBjb25jYXQgfSBmcm9tICcuLi8uLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmltcG9ydCB2YWxpZGF0ZUNyaXQgZnJvbSAnLi4vLi4vbGliL3ZhbGlkYXRlX2NyaXQuanMnO1xuZXhwb3J0IGNsYXNzIEZsYXR0ZW5lZEVuY3J5cHQge1xuICAgIGNvbnN0cnVjdG9yKHBsYWludGV4dCkge1xuICAgICAgICBpZiAoIShwbGFpbnRleHQgaW5zdGFuY2VvZiBVaW50OEFycmF5KSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcigncGxhaW50ZXh0IG11c3QgYmUgYW4gaW5zdGFuY2Ugb2YgVWludDhBcnJheScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3BsYWludGV4dCA9IHBsYWludGV4dDtcbiAgICB9XG4gICAgc2V0S2V5TWFuYWdlbWVudFBhcmFtZXRlcnMocGFyYW1ldGVycykge1xuICAgICAgICBpZiAodGhpcy5fa2V5TWFuYWdlbWVudFBhcmFtZXRlcnMpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldEtleU1hbmFnZW1lbnRQYXJhbWV0ZXJzIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fa2V5TWFuYWdlbWVudFBhcmFtZXRlcnMgPSBwYXJhbWV0ZXJzO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy5fcHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRQcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9wcm90ZWN0ZWRIZWFkZXIgPSBwcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRTaGFyZWRVbnByb3RlY3RlZEhlYWRlcihzaGFyZWRVbnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFNoYXJlZFVucHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIgPSBzaGFyZWRVbnByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldFVucHJvdGVjdGVkSGVhZGVyKHVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLl91bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0VW5wcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl91bnByb3RlY3RlZEhlYWRlciA9IHVucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0QWRkaXRpb25hbEF1dGhlbnRpY2F0ZWREYXRhKGFhZCkge1xuICAgICAgICB0aGlzLl9hYWQgPSBhYWQ7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRDb250ZW50RW5jcnlwdGlvbktleShjZWspIHtcbiAgICAgICAgaWYgKHRoaXMuX2Nlaykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0Q29udGVudEVuY3J5cHRpb25LZXkgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9jZWsgPSBjZWs7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRJbml0aWFsaXphdGlvblZlY3Rvcihpdikge1xuICAgICAgICBpZiAodGhpcy5faXYpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldEluaXRpYWxpemF0aW9uVmVjdG9yIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5faXYgPSBpdjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIGFzeW5jIGVuY3J5cHQoa2V5LCBvcHRpb25zKSB7XG4gICAgICAgIGlmICghdGhpcy5fcHJvdGVjdGVkSGVhZGVyICYmICF0aGlzLl91bnByb3RlY3RlZEhlYWRlciAmJiAhdGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdlaXRoZXIgc2V0UHJvdGVjdGVkSGVhZGVyLCBzZXRVbnByb3RlY3RlZEhlYWRlciwgb3Igc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIgbXVzdCBiZSBjYWxsZWQgYmVmb3JlICNlbmNyeXB0KCknKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIWlzRGlzam9pbnQodGhpcy5fcHJvdGVjdGVkSGVhZGVyLCB0aGlzLl91bnByb3RlY3RlZEhlYWRlciwgdGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFByb3RlY3RlZCwgSldFIFNoYXJlZCBVbnByb3RlY3RlZCBhbmQgSldFIFBlci1SZWNpcGllbnQgSGVhZGVyIFBhcmFtZXRlciBuYW1lcyBtdXN0IGJlIGRpc2pvaW50Jyk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3Qgam9zZUhlYWRlciA9IHtcbiAgICAgICAgICAgIC4uLnRoaXMuX3Byb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgIC4uLnRoaXMuX3VucHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgLi4udGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgIH07XG4gICAgICAgIHZhbGlkYXRlQ3JpdChKV0VJbnZhbGlkLCBuZXcgTWFwKCksIG9wdGlvbnM/LmNyaXQsIHRoaXMuX3Byb3RlY3RlZEhlYWRlciwgam9zZUhlYWRlcik7XG4gICAgICAgIGlmIChqb3NlSGVhZGVyLnppcCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSldFIFwiemlwXCIgKENvbXByZXNzaW9uIEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBpcyBub3Qgc3VwcG9ydGVkLicpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHsgYWxnLCBlbmMgfSA9IGpvc2VIZWFkZXI7XG4gICAgICAgIGlmICh0eXBlb2YgYWxnICE9PSAnc3RyaW5nJyB8fCAhYWxnKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFwiYWxnXCIgKEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBtaXNzaW5nIG9yIGludmFsaWQnKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodHlwZW9mIGVuYyAhPT0gJ3N0cmluZycgfHwgIWVuYykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBcImVuY1wiIChFbmNyeXB0aW9uIEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBtaXNzaW5nIG9yIGludmFsaWQnKTtcbiAgICAgICAgfVxuICAgICAgICBsZXQgZW5jcnlwdGVkS2V5O1xuICAgICAgICBpZiAodGhpcy5fY2VrICYmIChhbGcgPT09ICdkaXInIHx8IGFsZyA9PT0gJ0VDREgtRVMnKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgc2V0Q29udGVudEVuY3J5cHRpb25LZXkgY2Fubm90IGJlIGNhbGxlZCB3aXRoIEpXRSBcImFsZ1wiIChBbGdvcml0aG0pIEhlYWRlciAke2FsZ31gKTtcbiAgICAgICAgfVxuICAgICAgICBsZXQgY2VrO1xuICAgICAgICB7XG4gICAgICAgICAgICBsZXQgcGFyYW1ldGVycztcbiAgICAgICAgICAgICh7IGNlaywgZW5jcnlwdGVkS2V5LCBwYXJhbWV0ZXJzIH0gPSBhd2FpdCBlbmNyeXB0S2V5TWFuYWdlbWVudChhbGcsIGVuYywga2V5LCB0aGlzLl9jZWssIHRoaXMuX2tleU1hbmFnZW1lbnRQYXJhbWV0ZXJzKSk7XG4gICAgICAgICAgICBpZiAocGFyYW1ldGVycykge1xuICAgICAgICAgICAgICAgIGlmIChvcHRpb25zICYmIHVucHJvdGVjdGVkIGluIG9wdGlvbnMpIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCF0aGlzLl91bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5zZXRVbnByb3RlY3RlZEhlYWRlcihwYXJhbWV0ZXJzKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyID0geyAuLi50aGlzLl91bnByb3RlY3RlZEhlYWRlciwgLi4ucGFyYW1ldGVycyB9O1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2UgaWYgKCF0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5zZXRQcm90ZWN0ZWRIZWFkZXIocGFyYW1ldGVycyk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICB0aGlzLl9wcm90ZWN0ZWRIZWFkZXIgPSB7IC4uLnRoaXMuX3Byb3RlY3RlZEhlYWRlciwgLi4ucGFyYW1ldGVycyB9O1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBsZXQgYWRkaXRpb25hbERhdGE7XG4gICAgICAgIGxldCBwcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIGxldCBhYWRNZW1iZXI7XG4gICAgICAgIGlmICh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHByb3RlY3RlZEhlYWRlciA9IGVuY29kZXIuZW5jb2RlKGJhc2U2NHVybChKU09OLnN0cmluZ2lmeSh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpKSk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBwcm90ZWN0ZWRIZWFkZXIgPSBlbmNvZGVyLmVuY29kZSgnJyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX2FhZCkge1xuICAgICAgICAgICAgYWFkTWVtYmVyID0gYmFzZTY0dXJsKHRoaXMuX2FhZCk7XG4gICAgICAgICAgICBhZGRpdGlvbmFsRGF0YSA9IGNvbmNhdChwcm90ZWN0ZWRIZWFkZXIsIGVuY29kZXIuZW5jb2RlKCcuJyksIGVuY29kZXIuZW5jb2RlKGFhZE1lbWJlcikpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgYWRkaXRpb25hbERhdGEgPSBwcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgeyBjaXBoZXJ0ZXh0LCB0YWcsIGl2IH0gPSBhd2FpdCBlbmNyeXB0KGVuYywgdGhpcy5fcGxhaW50ZXh0LCBjZWssIHRoaXMuX2l2LCBhZGRpdGlvbmFsRGF0YSk7XG4gICAgICAgIGNvbnN0IGp3ZSA9IHtcbiAgICAgICAgICAgIGNpcGhlcnRleHQ6IGJhc2U2NHVybChjaXBoZXJ0ZXh0KSxcbiAgICAgICAgfTtcbiAgICAgICAgaWYgKGl2KSB7XG4gICAgICAgICAgICBqd2UuaXYgPSBiYXNlNjR1cmwoaXYpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0YWcpIHtcbiAgICAgICAgICAgIGp3ZS50YWcgPSBiYXNlNjR1cmwodGFnKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoZW5jcnlwdGVkS2V5KSB7XG4gICAgICAgICAgICBqd2UuZW5jcnlwdGVkX2tleSA9IGJhc2U2NHVybChlbmNyeXB0ZWRLZXkpO1xuICAgICAgICB9XG4gICAgICAgIGlmIChhYWRNZW1iZXIpIHtcbiAgICAgICAgICAgIGp3ZS5hYWQgPSBhYWRNZW1iZXI7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX3Byb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgandlLnByb3RlY3RlZCA9IGRlY29kZXIuZGVjb2RlKHByb3RlY3RlZEhlYWRlcik7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX3NoYXJlZFVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICBqd2UudW5wcm90ZWN0ZWQgPSB0aGlzLl9zaGFyZWRVbnByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIGp3ZS5oZWFkZXIgPSB0aGlzLl91bnByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gandlO1xuICAgIH1cbn1cbiIsImltcG9ydCB7IEZsYXR0ZW5lZEVuY3J5cHQgfSBmcm9tICcuLi9mbGF0dGVuZWQvZW5jcnlwdC5qcyc7XG5pbXBvcnQgeyB1bnByb3RlY3RlZCB9IGZyb20gJy4uLy4uL2xpYi9wcml2YXRlX3N5bWJvbHMuanMnO1xuaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCwgSldFSW52YWxpZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCBnZW5lcmF0ZUNlayBmcm9tICcuLi8uLi9saWIvY2VrLmpzJztcbmltcG9ydCBpc0Rpc2pvaW50IGZyb20gJy4uLy4uL2xpYi9pc19kaXNqb2ludC5qcyc7XG5pbXBvcnQgZW5jcnlwdEtleU1hbmFnZW1lbnQgZnJvbSAnLi4vLi4vbGliL2VuY3J5cHRfa2V5X21hbmFnZW1lbnQuanMnO1xuaW1wb3J0IHsgZW5jb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4uLy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmltcG9ydCB2YWxpZGF0ZUNyaXQgZnJvbSAnLi4vLi4vbGliL3ZhbGlkYXRlX2NyaXQuanMnO1xuY2xhc3MgSW5kaXZpZHVhbFJlY2lwaWVudCB7XG4gICAgY29uc3RydWN0b3IoZW5jLCBrZXksIG9wdGlvbnMpIHtcbiAgICAgICAgdGhpcy5wYXJlbnQgPSBlbmM7XG4gICAgICAgIHRoaXMua2V5ID0ga2V5O1xuICAgICAgICB0aGlzLm9wdGlvbnMgPSBvcHRpb25zO1xuICAgIH1cbiAgICBzZXRVbnByb3RlY3RlZEhlYWRlcih1bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy51bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0VW5wcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLnVucHJvdGVjdGVkSGVhZGVyID0gdW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBhZGRSZWNpcGllbnQoLi4uYXJncykge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXJlbnQuYWRkUmVjaXBpZW50KC4uLmFyZ3MpO1xuICAgIH1cbiAgICBlbmNyeXB0KC4uLmFyZ3MpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGFyZW50LmVuY3J5cHQoLi4uYXJncyk7XG4gICAgfVxuICAgIGRvbmUoKSB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhcmVudDtcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgR2VuZXJhbEVuY3J5cHQge1xuICAgIGNvbnN0cnVjdG9yKHBsYWludGV4dCkge1xuICAgICAgICB0aGlzLl9yZWNpcGllbnRzID0gW107XG4gICAgICAgIHRoaXMuX3BsYWludGV4dCA9IHBsYWludGV4dDtcbiAgICB9XG4gICAgYWRkUmVjaXBpZW50KGtleSwgb3B0aW9ucykge1xuICAgICAgICBjb25zdCByZWNpcGllbnQgPSBuZXcgSW5kaXZpZHVhbFJlY2lwaWVudCh0aGlzLCBrZXksIHsgY3JpdDogb3B0aW9ucz8uY3JpdCB9KTtcbiAgICAgICAgdGhpcy5fcmVjaXBpZW50cy5wdXNoKHJlY2lwaWVudCk7XG4gICAgICAgIHJldHVybiByZWNpcGllbnQ7XG4gICAgfVxuICAgIHNldFByb3RlY3RlZEhlYWRlcihwcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMuX3Byb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0UHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fcHJvdGVjdGVkSGVhZGVyID0gcHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0U2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIoc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRTaGFyZWRVbnByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyID0gc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRBZGRpdGlvbmFsQXV0aGVudGljYXRlZERhdGEoYWFkKSB7XG4gICAgICAgIHRoaXMuX2FhZCA9IGFhZDtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIGFzeW5jIGVuY3J5cHQoKSB7XG4gICAgICAgIGlmICghdGhpcy5fcmVjaXBpZW50cy5sZW5ndGgpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdhdCBsZWFzdCBvbmUgcmVjaXBpZW50IG11c3QgYmUgYWRkZWQnKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5fcmVjaXBpZW50cy5sZW5ndGggPT09IDEpIHtcbiAgICAgICAgICAgIGNvbnN0IFtyZWNpcGllbnRdID0gdGhpcy5fcmVjaXBpZW50cztcbiAgICAgICAgICAgIGNvbnN0IGZsYXR0ZW5lZCA9IGF3YWl0IG5ldyBGbGF0dGVuZWRFbmNyeXB0KHRoaXMuX3BsYWludGV4dClcbiAgICAgICAgICAgICAgICAuc2V0QWRkaXRpb25hbEF1dGhlbnRpY2F0ZWREYXRhKHRoaXMuX2FhZClcbiAgICAgICAgICAgICAgICAuc2V0UHJvdGVjdGVkSGVhZGVyKHRoaXMuX3Byb3RlY3RlZEhlYWRlcilcbiAgICAgICAgICAgICAgICAuc2V0U2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIodGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpXG4gICAgICAgICAgICAgICAgLnNldFVucHJvdGVjdGVkSGVhZGVyKHJlY2lwaWVudC51bnByb3RlY3RlZEhlYWRlcilcbiAgICAgICAgICAgICAgICAuZW5jcnlwdChyZWNpcGllbnQua2V5LCB7IC4uLnJlY2lwaWVudC5vcHRpb25zIH0pO1xuICAgICAgICAgICAgY29uc3QgandlID0ge1xuICAgICAgICAgICAgICAgIGNpcGhlcnRleHQ6IGZsYXR0ZW5lZC5jaXBoZXJ0ZXh0LFxuICAgICAgICAgICAgICAgIGl2OiBmbGF0dGVuZWQuaXYsXG4gICAgICAgICAgICAgICAgcmVjaXBpZW50czogW3t9XSxcbiAgICAgICAgICAgICAgICB0YWc6IGZsYXR0ZW5lZC50YWcsXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC5hYWQpXG4gICAgICAgICAgICAgICAgandlLmFhZCA9IGZsYXR0ZW5lZC5hYWQ7XG4gICAgICAgICAgICBpZiAoZmxhdHRlbmVkLnByb3RlY3RlZClcbiAgICAgICAgICAgICAgICBqd2UucHJvdGVjdGVkID0gZmxhdHRlbmVkLnByb3RlY3RlZDtcbiAgICAgICAgICAgIGlmIChmbGF0dGVuZWQudW5wcm90ZWN0ZWQpXG4gICAgICAgICAgICAgICAgandlLnVucHJvdGVjdGVkID0gZmxhdHRlbmVkLnVucHJvdGVjdGVkO1xuICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC5lbmNyeXB0ZWRfa2V5KVxuICAgICAgICAgICAgICAgIGp3ZS5yZWNpcGllbnRzWzBdLmVuY3J5cHRlZF9rZXkgPSBmbGF0dGVuZWQuZW5jcnlwdGVkX2tleTtcbiAgICAgICAgICAgIGlmIChmbGF0dGVuZWQuaGVhZGVyKVxuICAgICAgICAgICAgICAgIGp3ZS5yZWNpcGllbnRzWzBdLmhlYWRlciA9IGZsYXR0ZW5lZC5oZWFkZXI7XG4gICAgICAgICAgICByZXR1cm4gandlO1xuICAgICAgICB9XG4gICAgICAgIGxldCBlbmM7XG4gICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgdGhpcy5fcmVjaXBpZW50cy5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgY29uc3QgcmVjaXBpZW50ID0gdGhpcy5fcmVjaXBpZW50c1tpXTtcbiAgICAgICAgICAgIGlmICghaXNEaXNqb2ludCh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIsIHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyLCByZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXIpKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBQcm90ZWN0ZWQsIEpXRSBTaGFyZWQgVW5wcm90ZWN0ZWQgYW5kIEpXRSBQZXItUmVjaXBpZW50IEhlYWRlciBQYXJhbWV0ZXIgbmFtZXMgbXVzdCBiZSBkaXNqb2ludCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY29uc3Qgam9zZUhlYWRlciA9IHtcbiAgICAgICAgICAgICAgICAuLi50aGlzLl9wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICAgICAgLi4udGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICAgICAgLi4ucmVjaXBpZW50LnVucHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIGNvbnN0IHsgYWxnIH0gPSBqb3NlSGVhZGVyO1xuICAgICAgICAgICAgaWYgKHR5cGVvZiBhbGcgIT09ICdzdHJpbmcnIHx8ICFhbGcpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFwiYWxnXCIgKEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBtaXNzaW5nIG9yIGludmFsaWQnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmIChhbGcgPT09ICdkaXInIHx8IGFsZyA9PT0gJ0VDREgtRVMnKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ1wiZGlyXCIgYW5kIFwiRUNESC1FU1wiIGFsZyBtYXkgb25seSBiZSB1c2VkIHdpdGggYSBzaW5nbGUgcmVjaXBpZW50Jyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAodHlwZW9mIGpvc2VIZWFkZXIuZW5jICE9PSAnc3RyaW5nJyB8fCAham9zZUhlYWRlci5lbmMpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFwiZW5jXCIgKEVuY3J5cHRpb24gQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIG1pc3Npbmcgb3IgaW52YWxpZCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKCFlbmMpIHtcbiAgICAgICAgICAgICAgICBlbmMgPSBqb3NlSGVhZGVyLmVuYztcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2UgaWYgKGVuYyAhPT0gam9zZUhlYWRlci5lbmMpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFwiZW5jXCIgKEVuY3J5cHRpb24gQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIG11c3QgYmUgdGhlIHNhbWUgZm9yIGFsbCByZWNpcGllbnRzJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICB2YWxpZGF0ZUNyaXQoSldFSW52YWxpZCwgbmV3IE1hcCgpLCByZWNpcGllbnQub3B0aW9ucy5jcml0LCB0aGlzLl9wcm90ZWN0ZWRIZWFkZXIsIGpvc2VIZWFkZXIpO1xuICAgICAgICAgICAgaWYgKGpvc2VIZWFkZXIuemlwICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSldFIFwiemlwXCIgKENvbXByZXNzaW9uIEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBpcyBub3Qgc3VwcG9ydGVkLicpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIGNvbnN0IGNlayA9IGdlbmVyYXRlQ2VrKGVuYyk7XG4gICAgICAgIGNvbnN0IGp3ZSA9IHtcbiAgICAgICAgICAgIGNpcGhlcnRleHQ6ICcnLFxuICAgICAgICAgICAgaXY6ICcnLFxuICAgICAgICAgICAgcmVjaXBpZW50czogW10sXG4gICAgICAgICAgICB0YWc6ICcnLFxuICAgICAgICB9O1xuICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHRoaXMuX3JlY2lwaWVudHMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIGNvbnN0IHJlY2lwaWVudCA9IHRoaXMuX3JlY2lwaWVudHNbaV07XG4gICAgICAgICAgICBjb25zdCB0YXJnZXQgPSB7fTtcbiAgICAgICAgICAgIGp3ZS5yZWNpcGllbnRzLnB1c2godGFyZ2V0KTtcbiAgICAgICAgICAgIGNvbnN0IGpvc2VIZWFkZXIgPSB7XG4gICAgICAgICAgICAgICAgLi4udGhpcy5fcHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgICAgIC4uLnRoaXMuX3VucHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgICAgIC4uLnJlY2lwaWVudC51bnByb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgIH07XG4gICAgICAgICAgICBjb25zdCBwMmMgPSBqb3NlSGVhZGVyLmFsZy5zdGFydHNXaXRoKCdQQkVTMicpID8gMjA0OCArIGkgOiB1bmRlZmluZWQ7XG4gICAgICAgICAgICBpZiAoaSA9PT0gMCkge1xuICAgICAgICAgICAgICAgIGNvbnN0IGZsYXR0ZW5lZCA9IGF3YWl0IG5ldyBGbGF0dGVuZWRFbmNyeXB0KHRoaXMuX3BsYWludGV4dClcbiAgICAgICAgICAgICAgICAgICAgLnNldEFkZGl0aW9uYWxBdXRoZW50aWNhdGVkRGF0YSh0aGlzLl9hYWQpXG4gICAgICAgICAgICAgICAgICAgIC5zZXRDb250ZW50RW5jcnlwdGlvbktleShjZWspXG4gICAgICAgICAgICAgICAgICAgIC5zZXRQcm90ZWN0ZWRIZWFkZXIodGhpcy5fcHJvdGVjdGVkSGVhZGVyKVxuICAgICAgICAgICAgICAgICAgICAuc2V0U2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIodGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpXG4gICAgICAgICAgICAgICAgICAgIC5zZXRVbnByb3RlY3RlZEhlYWRlcihyZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXIpXG4gICAgICAgICAgICAgICAgICAgIC5zZXRLZXlNYW5hZ2VtZW50UGFyYW1ldGVycyh7IHAyYyB9KVxuICAgICAgICAgICAgICAgICAgICAuZW5jcnlwdChyZWNpcGllbnQua2V5LCB7XG4gICAgICAgICAgICAgICAgICAgIC4uLnJlY2lwaWVudC5vcHRpb25zLFxuICAgICAgICAgICAgICAgICAgICBbdW5wcm90ZWN0ZWRdOiB0cnVlLFxuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIGp3ZS5jaXBoZXJ0ZXh0ID0gZmxhdHRlbmVkLmNpcGhlcnRleHQ7XG4gICAgICAgICAgICAgICAgandlLml2ID0gZmxhdHRlbmVkLml2O1xuICAgICAgICAgICAgICAgIGp3ZS50YWcgPSBmbGF0dGVuZWQudGFnO1xuICAgICAgICAgICAgICAgIGlmIChmbGF0dGVuZWQuYWFkKVxuICAgICAgICAgICAgICAgICAgICBqd2UuYWFkID0gZmxhdHRlbmVkLmFhZDtcbiAgICAgICAgICAgICAgICBpZiAoZmxhdHRlbmVkLnByb3RlY3RlZClcbiAgICAgICAgICAgICAgICAgICAgandlLnByb3RlY3RlZCA9IGZsYXR0ZW5lZC5wcm90ZWN0ZWQ7XG4gICAgICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC51bnByb3RlY3RlZClcbiAgICAgICAgICAgICAgICAgICAgandlLnVucHJvdGVjdGVkID0gZmxhdHRlbmVkLnVucHJvdGVjdGVkO1xuICAgICAgICAgICAgICAgIHRhcmdldC5lbmNyeXB0ZWRfa2V5ID0gZmxhdHRlbmVkLmVuY3J5cHRlZF9rZXk7XG4gICAgICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC5oZWFkZXIpXG4gICAgICAgICAgICAgICAgICAgIHRhcmdldC5oZWFkZXIgPSBmbGF0dGVuZWQuaGVhZGVyO1xuICAgICAgICAgICAgICAgIGNvbnRpbnVlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY29uc3QgeyBlbmNyeXB0ZWRLZXksIHBhcmFtZXRlcnMgfSA9IGF3YWl0IGVuY3J5cHRLZXlNYW5hZ2VtZW50KHJlY2lwaWVudC51bnByb3RlY3RlZEhlYWRlcj8uYWxnIHx8XG4gICAgICAgICAgICAgICAgdGhpcy5fcHJvdGVjdGVkSGVhZGVyPy5hbGcgfHxcbiAgICAgICAgICAgICAgICB0aGlzLl91bnByb3RlY3RlZEhlYWRlcj8uYWxnLCBlbmMsIHJlY2lwaWVudC5rZXksIGNlaywgeyBwMmMgfSk7XG4gICAgICAgICAgICB0YXJnZXQuZW5jcnlwdGVkX2tleSA9IGJhc2U2NHVybChlbmNyeXB0ZWRLZXkpO1xuICAgICAgICAgICAgaWYgKHJlY2lwaWVudC51bnByb3RlY3RlZEhlYWRlciB8fCBwYXJhbWV0ZXJzKVxuICAgICAgICAgICAgICAgIHRhcmdldC5oZWFkZXIgPSB7IC4uLnJlY2lwaWVudC51bnByb3RlY3RlZEhlYWRlciwgLi4ucGFyYW1ldGVycyB9O1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBqd2U7XG4gICAgfVxufVxuIiwiaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIHN1YnRsZURzYShhbGcsIGFsZ29yaXRobSkge1xuICAgIGNvbnN0IGhhc2ggPSBgU0hBLSR7YWxnLnNsaWNlKC0zKX1gO1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ0hTMjU2JzpcbiAgICAgICAgY2FzZSAnSFMzODQnOlxuICAgICAgICBjYXNlICdIUzUxMic6XG4gICAgICAgICAgICByZXR1cm4geyBoYXNoLCBuYW1lOiAnSE1BQycgfTtcbiAgICAgICAgY2FzZSAnUFMyNTYnOlxuICAgICAgICBjYXNlICdQUzM4NCc6XG4gICAgICAgIGNhc2UgJ1BTNTEyJzpcbiAgICAgICAgICAgIHJldHVybiB7IGhhc2gsIG5hbWU6ICdSU0EtUFNTJywgc2FsdExlbmd0aDogYWxnLnNsaWNlKC0zKSA+PiAzIH07XG4gICAgICAgIGNhc2UgJ1JTMjU2JzpcbiAgICAgICAgY2FzZSAnUlMzODQnOlxuICAgICAgICBjYXNlICdSUzUxMic6XG4gICAgICAgICAgICByZXR1cm4geyBoYXNoLCBuYW1lOiAnUlNBU1NBLVBLQ1MxLXYxXzUnIH07XG4gICAgICAgIGNhc2UgJ0VTMjU2JzpcbiAgICAgICAgY2FzZSAnRVMzODQnOlxuICAgICAgICBjYXNlICdFUzUxMic6XG4gICAgICAgICAgICByZXR1cm4geyBoYXNoLCBuYW1lOiAnRUNEU0EnLCBuYW1lZEN1cnZlOiBhbGdvcml0aG0ubmFtZWRDdXJ2ZSB9O1xuICAgICAgICBjYXNlICdFZERTQSc6XG4gICAgICAgICAgICByZXR1cm4geyBuYW1lOiBhbGdvcml0aG0ubmFtZSB9O1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoYGFsZyAke2FsZ30gaXMgbm90IHN1cHBvcnRlZCBlaXRoZXIgYnkgSk9TRSBvciB5b3VyIGphdmFzY3JpcHQgcnVudGltZWApO1xuICAgIH1cbn1cbiIsImltcG9ydCBjcnlwdG8sIHsgaXNDcnlwdG9LZXkgfSBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgeyBjaGVja1NpZ0NyeXB0b0tleSB9IGZyb20gJy4uL2xpYi9jcnlwdG9fa2V5LmpzJztcbmltcG9ydCBpbnZhbGlkS2V5SW5wdXQgZnJvbSAnLi4vbGliL2ludmFsaWRfa2V5X2lucHV0LmpzJztcbmltcG9ydCB7IHR5cGVzIH0gZnJvbSAnLi9pc19rZXlfbGlrZS5qcyc7XG5pbXBvcnQgbm9ybWFsaXplIGZyb20gJy4vbm9ybWFsaXplX2tleS5qcyc7XG5leHBvcnQgZGVmYXVsdCBhc3luYyBmdW5jdGlvbiBnZXRDcnlwdG9LZXkoYWxnLCBrZXksIHVzYWdlKSB7XG4gICAgaWYgKHVzYWdlID09PSAnc2lnbicpIHtcbiAgICAgICAga2V5ID0gYXdhaXQgbm9ybWFsaXplLm5vcm1hbGl6ZVByaXZhdGVLZXkoa2V5LCBhbGcpO1xuICAgIH1cbiAgICBpZiAodXNhZ2UgPT09ICd2ZXJpZnknKSB7XG4gICAgICAgIGtleSA9IGF3YWl0IG5vcm1hbGl6ZS5ub3JtYWxpemVQdWJsaWNLZXkoa2V5LCBhbGcpO1xuICAgIH1cbiAgICBpZiAoaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICBjaGVja1NpZ0NyeXB0b0tleShrZXksIGFsZywgdXNhZ2UpO1xuICAgICAgICByZXR1cm4ga2V5O1xuICAgIH1cbiAgICBpZiAoa2V5IGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICBpZiAoIWFsZy5zdGFydHNXaXRoKCdIUycpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzKSk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBrZXksIHsgaGFzaDogYFNIQS0ke2FsZy5zbGljZSgtMyl9YCwgbmFtZTogJ0hNQUMnIH0sIGZhbHNlLCBbdXNhZ2VdKTtcbiAgICB9XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcywgJ1VpbnQ4QXJyYXknLCAnSlNPTiBXZWIgS2V5JykpO1xufVxuIiwiaW1wb3J0IHN1YnRsZUFsZ29yaXRobSBmcm9tICcuL3N1YnRsZV9kc2EuanMnO1xuaW1wb3J0IGNyeXB0byBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgY2hlY2tLZXlMZW5ndGggZnJvbSAnLi9jaGVja19rZXlfbGVuZ3RoLmpzJztcbmltcG9ydCBnZXRWZXJpZnlLZXkgZnJvbSAnLi9nZXRfc2lnbl92ZXJpZnlfa2V5LmpzJztcbmNvbnN0IHZlcmlmeSA9IGFzeW5jIChhbGcsIGtleSwgc2lnbmF0dXJlLCBkYXRhKSA9PiB7XG4gICAgY29uc3QgY3J5cHRvS2V5ID0gYXdhaXQgZ2V0VmVyaWZ5S2V5KGFsZywga2V5LCAndmVyaWZ5Jyk7XG4gICAgY2hlY2tLZXlMZW5ndGgoYWxnLCBjcnlwdG9LZXkpO1xuICAgIGNvbnN0IGFsZ29yaXRobSA9IHN1YnRsZUFsZ29yaXRobShhbGcsIGNyeXB0b0tleS5hbGdvcml0aG0pO1xuICAgIHRyeSB7XG4gICAgICAgIHJldHVybiBhd2FpdCBjcnlwdG8uc3VidGxlLnZlcmlmeShhbGdvcml0aG0sIGNyeXB0b0tleSwgc2lnbmF0dXJlLCBkYXRhKTtcbiAgICB9XG4gICAgY2F0Y2gge1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxufTtcbmV4cG9ydCBkZWZhdWx0IHZlcmlmeTtcbiIsImltcG9ydCB7IGRlY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi8uLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgdmVyaWZ5IGZyb20gJy4uLy4uL3J1bnRpbWUvdmVyaWZ5LmpzJztcbmltcG9ydCB7IEpPU0VBbGdOb3RBbGxvd2VkLCBKV1NJbnZhbGlkLCBKV1NTaWduYXR1cmVWZXJpZmljYXRpb25GYWlsZWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgeyBjb25jYXQsIGVuY29kZXIsIGRlY29kZXIgfSBmcm9tICcuLi8uLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmltcG9ydCBpc0Rpc2pvaW50IGZyb20gJy4uLy4uL2xpYi9pc19kaXNqb2ludC5qcyc7XG5pbXBvcnQgaXNPYmplY3QgZnJvbSAnLi4vLi4vbGliL2lzX29iamVjdC5qcyc7XG5pbXBvcnQgeyBjaGVja0tleVR5cGVXaXRoSndrIH0gZnJvbSAnLi4vLi4vbGliL2NoZWNrX2tleV90eXBlLmpzJztcbmltcG9ydCB2YWxpZGF0ZUNyaXQgZnJvbSAnLi4vLi4vbGliL3ZhbGlkYXRlX2NyaXQuanMnO1xuaW1wb3J0IHZhbGlkYXRlQWxnb3JpdGhtcyBmcm9tICcuLi8uLi9saWIvdmFsaWRhdGVfYWxnb3JpdGhtcy5qcyc7XG5pbXBvcnQgeyBpc0pXSyB9IGZyb20gJy4uLy4uL2xpYi9pc19qd2suanMnO1xuaW1wb3J0IHsgaW1wb3J0SldLIH0gZnJvbSAnLi4vLi4va2V5L2ltcG9ydC5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZmxhdHRlbmVkVmVyaWZ5KGp3cywga2V5LCBvcHRpb25zKSB7XG4gICAgaWYgKCFpc09iamVjdChqd3MpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdGbGF0dGVuZWQgSldTIG11c3QgYmUgYW4gb2JqZWN0Jyk7XG4gICAgfVxuICAgIGlmIChqd3MucHJvdGVjdGVkID09PSB1bmRlZmluZWQgJiYgandzLmhlYWRlciA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdGbGF0dGVuZWQgSldTIG11c3QgaGF2ZSBlaXRoZXIgb2YgdGhlIFwicHJvdGVjdGVkXCIgb3IgXCJoZWFkZXJcIiBtZW1iZXJzJyk7XG4gICAgfVxuICAgIGlmIChqd3MucHJvdGVjdGVkICE9PSB1bmRlZmluZWQgJiYgdHlwZW9mIGp3cy5wcm90ZWN0ZWQgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgUHJvdGVjdGVkIEhlYWRlciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoandzLnBheWxvYWQgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFBheWxvYWQgbWlzc2luZycpO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIGp3cy5zaWduYXR1cmUgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgU2lnbmF0dXJlIG1pc3Npbmcgb3IgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3cy5oZWFkZXIgIT09IHVuZGVmaW5lZCAmJiAhaXNPYmplY3QoandzLmhlYWRlcikpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBVbnByb3RlY3RlZCBIZWFkZXIgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgbGV0IHBhcnNlZFByb3QgPSB7fTtcbiAgICBpZiAoandzLnByb3RlY3RlZCkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgY29uc3QgcHJvdGVjdGVkSGVhZGVyID0gYmFzZTY0dXJsKGp3cy5wcm90ZWN0ZWQpO1xuICAgICAgICAgICAgcGFyc2VkUHJvdCA9IEpTT04ucGFyc2UoZGVjb2Rlci5kZWNvZGUocHJvdGVjdGVkSGVhZGVyKSk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBQcm90ZWN0ZWQgSGVhZGVyIGlzIGludmFsaWQnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBpZiAoIWlzRGlzam9pbnQocGFyc2VkUHJvdCwgandzLmhlYWRlcikpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBQcm90ZWN0ZWQgYW5kIEpXUyBVbnByb3RlY3RlZCBIZWFkZXIgUGFyYW1ldGVyIG5hbWVzIG11c3QgYmUgZGlzam9pbnQnKTtcbiAgICB9XG4gICAgY29uc3Qgam9zZUhlYWRlciA9IHtcbiAgICAgICAgLi4ucGFyc2VkUHJvdCxcbiAgICAgICAgLi4uandzLmhlYWRlcixcbiAgICB9O1xuICAgIGNvbnN0IGV4dGVuc2lvbnMgPSB2YWxpZGF0ZUNyaXQoSldTSW52YWxpZCwgbmV3IE1hcChbWydiNjQnLCB0cnVlXV0pLCBvcHRpb25zPy5jcml0LCBwYXJzZWRQcm90LCBqb3NlSGVhZGVyKTtcbiAgICBsZXQgYjY0ID0gdHJ1ZTtcbiAgICBpZiAoZXh0ZW5zaW9ucy5oYXMoJ2I2NCcpKSB7XG4gICAgICAgIGI2NCA9IHBhcnNlZFByb3QuYjY0O1xuICAgICAgICBpZiAodHlwZW9mIGI2NCAhPT0gJ2Jvb2xlYW4nKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnVGhlIFwiYjY0XCIgKGJhc2U2NHVybC1lbmNvZGUgcGF5bG9hZCkgSGVhZGVyIFBhcmFtZXRlciBtdXN0IGJlIGEgYm9vbGVhbicpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGNvbnN0IHsgYWxnIH0gPSBqb3NlSGVhZGVyO1xuICAgIGlmICh0eXBlb2YgYWxnICE9PSAnc3RyaW5nJyB8fCAhYWxnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgXCJhbGdcIiAoQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIG1pc3Npbmcgb3IgaW52YWxpZCcpO1xuICAgIH1cbiAgICBjb25zdCBhbGdvcml0aG1zID0gb3B0aW9ucyAmJiB2YWxpZGF0ZUFsZ29yaXRobXMoJ2FsZ29yaXRobXMnLCBvcHRpb25zLmFsZ29yaXRobXMpO1xuICAgIGlmIChhbGdvcml0aG1zICYmICFhbGdvcml0aG1zLmhhcyhhbGcpKSB7XG4gICAgICAgIHRocm93IG5ldyBKT1NFQWxnTm90QWxsb3dlZCgnXCJhbGdcIiAoQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIHZhbHVlIG5vdCBhbGxvd2VkJyk7XG4gICAgfVxuICAgIGlmIChiNjQpIHtcbiAgICAgICAgaWYgKHR5cGVvZiBqd3MucGF5bG9hZCAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgUGF5bG9hZCBtdXN0IGJlIGEgc3RyaW5nJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgZWxzZSBpZiAodHlwZW9mIGp3cy5wYXlsb2FkICE9PSAnc3RyaW5nJyAmJiAhKGp3cy5wYXlsb2FkIGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBQYXlsb2FkIG11c3QgYmUgYSBzdHJpbmcgb3IgYW4gVWludDhBcnJheSBpbnN0YW5jZScpO1xuICAgIH1cbiAgICBsZXQgcmVzb2x2ZWRLZXkgPSBmYWxzZTtcbiAgICBpZiAodHlwZW9mIGtleSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICBrZXkgPSBhd2FpdCBrZXkocGFyc2VkUHJvdCwgandzKTtcbiAgICAgICAgcmVzb2x2ZWRLZXkgPSB0cnVlO1xuICAgICAgICBjaGVja0tleVR5cGVXaXRoSndrKGFsZywga2V5LCAndmVyaWZ5Jyk7XG4gICAgICAgIGlmIChpc0pXSyhrZXkpKSB7XG4gICAgICAgICAgICBrZXkgPSBhd2FpdCBpbXBvcnRKV0soa2V5LCBhbGcpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBjaGVja0tleVR5cGVXaXRoSndrKGFsZywga2V5LCAndmVyaWZ5Jyk7XG4gICAgfVxuICAgIGNvbnN0IGRhdGEgPSBjb25jYXQoZW5jb2Rlci5lbmNvZGUoandzLnByb3RlY3RlZCA/PyAnJyksIGVuY29kZXIuZW5jb2RlKCcuJyksIHR5cGVvZiBqd3MucGF5bG9hZCA9PT0gJ3N0cmluZycgPyBlbmNvZGVyLmVuY29kZShqd3MucGF5bG9hZCkgOiBqd3MucGF5bG9hZCk7XG4gICAgbGV0IHNpZ25hdHVyZTtcbiAgICB0cnkge1xuICAgICAgICBzaWduYXR1cmUgPSBiYXNlNjR1cmwoandzLnNpZ25hdHVyZSk7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBzaWduYXR1cmUnKTtcbiAgICB9XG4gICAgY29uc3QgdmVyaWZpZWQgPSBhd2FpdCB2ZXJpZnkoYWxnLCBrZXksIHNpZ25hdHVyZSwgZGF0YSk7XG4gICAgaWYgKCF2ZXJpZmllZCkge1xuICAgICAgICB0aHJvdyBuZXcgSldTU2lnbmF0dXJlVmVyaWZpY2F0aW9uRmFpbGVkKCk7XG4gICAgfVxuICAgIGxldCBwYXlsb2FkO1xuICAgIGlmIChiNjQpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHBheWxvYWQgPSBiYXNlNjR1cmwoandzLnBheWxvYWQpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgcGF5bG9hZCcpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGVsc2UgaWYgKHR5cGVvZiBqd3MucGF5bG9hZCA9PT0gJ3N0cmluZycpIHtcbiAgICAgICAgcGF5bG9hZCA9IGVuY29kZXIuZW5jb2RlKGp3cy5wYXlsb2FkKTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIHBheWxvYWQgPSBqd3MucGF5bG9hZDtcbiAgICB9XG4gICAgY29uc3QgcmVzdWx0ID0geyBwYXlsb2FkIH07XG4gICAgaWYgKGp3cy5wcm90ZWN0ZWQgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICByZXN1bHQucHJvdGVjdGVkSGVhZGVyID0gcGFyc2VkUHJvdDtcbiAgICB9XG4gICAgaWYgKGp3cy5oZWFkZXIgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICByZXN1bHQudW5wcm90ZWN0ZWRIZWFkZXIgPSBqd3MuaGVhZGVyO1xuICAgIH1cbiAgICBpZiAocmVzb2x2ZWRLZXkpIHtcbiAgICAgICAgcmV0dXJuIHsgLi4ucmVzdWx0LCBrZXkgfTtcbiAgICB9XG4gICAgcmV0dXJuIHJlc3VsdDtcbn1cbiIsImltcG9ydCB7IGZsYXR0ZW5lZFZlcmlmeSB9IGZyb20gJy4uL2ZsYXR0ZW5lZC92ZXJpZnkuanMnO1xuaW1wb3J0IHsgSldTSW52YWxpZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IGRlY29kZXIgfSBmcm9tICcuLi8uLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjb21wYWN0VmVyaWZ5KGp3cywga2V5LCBvcHRpb25zKSB7XG4gICAgaWYgKGp3cyBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgandzID0gZGVjb2Rlci5kZWNvZGUoandzKTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBqd3MgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdDb21wYWN0IEpXUyBtdXN0IGJlIGEgc3RyaW5nIG9yIFVpbnQ4QXJyYXknKTtcbiAgICB9XG4gICAgY29uc3QgeyAwOiBwcm90ZWN0ZWRIZWFkZXIsIDE6IHBheWxvYWQsIDI6IHNpZ25hdHVyZSwgbGVuZ3RoIH0gPSBqd3Muc3BsaXQoJy4nKTtcbiAgICBpZiAobGVuZ3RoICE9PSAzKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdJbnZhbGlkIENvbXBhY3QgSldTJyk7XG4gICAgfVxuICAgIGNvbnN0IHZlcmlmaWVkID0gYXdhaXQgZmxhdHRlbmVkVmVyaWZ5KHsgcGF5bG9hZCwgcHJvdGVjdGVkOiBwcm90ZWN0ZWRIZWFkZXIsIHNpZ25hdHVyZSB9LCBrZXksIG9wdGlvbnMpO1xuICAgIGNvbnN0IHJlc3VsdCA9IHsgcGF5bG9hZDogdmVyaWZpZWQucGF5bG9hZCwgcHJvdGVjdGVkSGVhZGVyOiB2ZXJpZmllZC5wcm90ZWN0ZWRIZWFkZXIgfTtcbiAgICBpZiAodHlwZW9mIGtleSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICByZXR1cm4geyAuLi5yZXN1bHQsIGtleTogdmVyaWZpZWQua2V5IH07XG4gICAgfVxuICAgIHJldHVybiByZXN1bHQ7XG59XG4iLCJpbXBvcnQgeyBmbGF0dGVuZWRWZXJpZnkgfSBmcm9tICcuLi9mbGF0dGVuZWQvdmVyaWZ5LmpzJztcbmltcG9ydCB7IEpXU0ludmFsaWQsIEpXU1NpZ25hdHVyZVZlcmlmaWNhdGlvbkZhaWxlZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCBpc09iamVjdCBmcm9tICcuLi8uLi9saWIvaXNfb2JqZWN0LmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmFsVmVyaWZ5KGp3cywga2V5LCBvcHRpb25zKSB7XG4gICAgaWYgKCFpc09iamVjdChqd3MpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdHZW5lcmFsIEpXUyBtdXN0IGJlIGFuIG9iamVjdCcpO1xuICAgIH1cbiAgICBpZiAoIUFycmF5LmlzQXJyYXkoandzLnNpZ25hdHVyZXMpIHx8ICFqd3Muc2lnbmF0dXJlcy5ldmVyeShpc09iamVjdCkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBTaWduYXR1cmVzIG1pc3Npbmcgb3IgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgZm9yIChjb25zdCBzaWduYXR1cmUgb2YgandzLnNpZ25hdHVyZXMpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHJldHVybiBhd2FpdCBmbGF0dGVuZWRWZXJpZnkoe1xuICAgICAgICAgICAgICAgIGhlYWRlcjogc2lnbmF0dXJlLmhlYWRlcixcbiAgICAgICAgICAgICAgICBwYXlsb2FkOiBqd3MucGF5bG9hZCxcbiAgICAgICAgICAgICAgICBwcm90ZWN0ZWQ6IHNpZ25hdHVyZS5wcm90ZWN0ZWQsXG4gICAgICAgICAgICAgICAgc2lnbmF0dXJlOiBzaWduYXR1cmUuc2lnbmF0dXJlLFxuICAgICAgICAgICAgfSwga2V5LCBvcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgIH1cbiAgICB9XG4gICAgdGhyb3cgbmV3IEpXU1NpZ25hdHVyZVZlcmlmaWNhdGlvbkZhaWxlZCgpO1xufVxuIiwiaW1wb3J0IHsgRmxhdHRlbmVkRW5jcnlwdCB9IGZyb20gJy4uL2ZsYXR0ZW5lZC9lbmNyeXB0LmpzJztcbmV4cG9ydCBjbGFzcyBDb21wYWN0RW5jcnlwdCB7XG4gICAgY29uc3RydWN0b3IocGxhaW50ZXh0KSB7XG4gICAgICAgIHRoaXMuX2ZsYXR0ZW5lZCA9IG5ldyBGbGF0dGVuZWRFbmNyeXB0KHBsYWludGV4dCk7XG4gICAgfVxuICAgIHNldENvbnRlbnRFbmNyeXB0aW9uS2V5KGNlaykge1xuICAgICAgICB0aGlzLl9mbGF0dGVuZWQuc2V0Q29udGVudEVuY3J5cHRpb25LZXkoY2VrKTtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldEluaXRpYWxpemF0aW9uVmVjdG9yKGl2KSB7XG4gICAgICAgIHRoaXMuX2ZsYXR0ZW5lZC5zZXRJbml0aWFsaXphdGlvblZlY3Rvcihpdik7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIHRoaXMuX2ZsYXR0ZW5lZC5zZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKTtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldEtleU1hbmFnZW1lbnRQYXJhbWV0ZXJzKHBhcmFtZXRlcnMpIHtcbiAgICAgICAgdGhpcy5fZmxhdHRlbmVkLnNldEtleU1hbmFnZW1lbnRQYXJhbWV0ZXJzKHBhcmFtZXRlcnMpO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgYXN5bmMgZW5jcnlwdChrZXksIG9wdGlvbnMpIHtcbiAgICAgICAgY29uc3QgandlID0gYXdhaXQgdGhpcy5fZmxhdHRlbmVkLmVuY3J5cHQoa2V5LCBvcHRpb25zKTtcbiAgICAgICAgcmV0dXJuIFtqd2UucHJvdGVjdGVkLCBqd2UuZW5jcnlwdGVkX2tleSwgandlLml2LCBqd2UuY2lwaGVydGV4dCwgandlLnRhZ10uam9pbignLicpO1xuICAgIH1cbn1cbiIsImltcG9ydCBzdWJ0bGVBbGdvcml0aG0gZnJvbSAnLi9zdWJ0bGVfZHNhLmpzJztcbmltcG9ydCBjcnlwdG8gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IGNoZWNrS2V5TGVuZ3RoIGZyb20gJy4vY2hlY2tfa2V5X2xlbmd0aC5qcyc7XG5pbXBvcnQgZ2V0U2lnbktleSBmcm9tICcuL2dldF9zaWduX3ZlcmlmeV9rZXkuanMnO1xuY29uc3Qgc2lnbiA9IGFzeW5jIChhbGcsIGtleSwgZGF0YSkgPT4ge1xuICAgIGNvbnN0IGNyeXB0b0tleSA9IGF3YWl0IGdldFNpZ25LZXkoYWxnLCBrZXksICdzaWduJyk7XG4gICAgY2hlY2tLZXlMZW5ndGgoYWxnLCBjcnlwdG9LZXkpO1xuICAgIGNvbnN0IHNpZ25hdHVyZSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuc2lnbihzdWJ0bGVBbGdvcml0aG0oYWxnLCBjcnlwdG9LZXkuYWxnb3JpdGhtKSwgY3J5cHRvS2V5LCBkYXRhKTtcbiAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoc2lnbmF0dXJlKTtcbn07XG5leHBvcnQgZGVmYXVsdCBzaWduO1xuIiwiaW1wb3J0IHsgZW5jb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4uLy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmltcG9ydCBzaWduIGZyb20gJy4uLy4uL3J1bnRpbWUvc2lnbi5qcyc7XG5pbXBvcnQgaXNEaXNqb2ludCBmcm9tICcuLi8uLi9saWIvaXNfZGlzam9pbnQuanMnO1xuaW1wb3J0IHsgSldTSW52YWxpZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IGVuY29kZXIsIGRlY29kZXIsIGNvbmNhdCB9IGZyb20gJy4uLy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IHsgY2hlY2tLZXlUeXBlV2l0aEp3ayB9IGZyb20gJy4uLy4uL2xpYi9jaGVja19rZXlfdHlwZS5qcyc7XG5pbXBvcnQgdmFsaWRhdGVDcml0IGZyb20gJy4uLy4uL2xpYi92YWxpZGF0ZV9jcml0LmpzJztcbmV4cG9ydCBjbGFzcyBGbGF0dGVuZWRTaWduIHtcbiAgICBjb25zdHJ1Y3RvcihwYXlsb2FkKSB7XG4gICAgICAgIGlmICghKHBheWxvYWQgaW5zdGFuY2VvZiBVaW50OEFycmF5KSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcigncGF5bG9hZCBtdXN0IGJlIGFuIGluc3RhbmNlIG9mIFVpbnQ4QXJyYXknKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9wYXlsb2FkID0gcGF5bG9hZDtcbiAgICB9XG4gICAgc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy5fcHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRQcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9wcm90ZWN0ZWRIZWFkZXIgPSBwcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRVbnByb3RlY3RlZEhlYWRlcih1bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFVucHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIgPSB1bnByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIGFzeW5jIHNpZ24oa2V5LCBvcHRpb25zKSB7XG4gICAgICAgIGlmICghdGhpcy5fcHJvdGVjdGVkSGVhZGVyICYmICF0aGlzLl91bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ2VpdGhlciBzZXRQcm90ZWN0ZWRIZWFkZXIgb3Igc2V0VW5wcm90ZWN0ZWRIZWFkZXIgbXVzdCBiZSBjYWxsZWQgYmVmb3JlICNzaWduKCknKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIWlzRGlzam9pbnQodGhpcy5fcHJvdGVjdGVkSGVhZGVyLCB0aGlzLl91bnByb3RlY3RlZEhlYWRlcikpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgUHJvdGVjdGVkIGFuZCBKV1MgVW5wcm90ZWN0ZWQgSGVhZGVyIFBhcmFtZXRlciBuYW1lcyBtdXN0IGJlIGRpc2pvaW50Jyk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3Qgam9zZUhlYWRlciA9IHtcbiAgICAgICAgICAgIC4uLnRoaXMuX3Byb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgIC4uLnRoaXMuX3VucHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICB9O1xuICAgICAgICBjb25zdCBleHRlbnNpb25zID0gdmFsaWRhdGVDcml0KEpXU0ludmFsaWQsIG5ldyBNYXAoW1snYjY0JywgdHJ1ZV1dKSwgb3B0aW9ucz8uY3JpdCwgdGhpcy5fcHJvdGVjdGVkSGVhZGVyLCBqb3NlSGVhZGVyKTtcbiAgICAgICAgbGV0IGI2NCA9IHRydWU7XG4gICAgICAgIGlmIChleHRlbnNpb25zLmhhcygnYjY0JykpIHtcbiAgICAgICAgICAgIGI2NCA9IHRoaXMuX3Byb3RlY3RlZEhlYWRlci5iNjQ7XG4gICAgICAgICAgICBpZiAodHlwZW9mIGI2NCAhPT0gJ2Jvb2xlYW4nKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ1RoZSBcImI2NFwiIChiYXNlNjR1cmwtZW5jb2RlIHBheWxvYWQpIEhlYWRlciBQYXJhbWV0ZXIgbXVzdCBiZSBhIGJvb2xlYW4nKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBjb25zdCB7IGFsZyB9ID0gam9zZUhlYWRlcjtcbiAgICAgICAgaWYgKHR5cGVvZiBhbGcgIT09ICdzdHJpbmcnIHx8ICFhbGcpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgXCJhbGdcIiAoQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIG1pc3Npbmcgb3IgaW52YWxpZCcpO1xuICAgICAgICB9XG4gICAgICAgIGNoZWNrS2V5VHlwZVdpdGhKd2soYWxnLCBrZXksICdzaWduJyk7XG4gICAgICAgIGxldCBwYXlsb2FkID0gdGhpcy5fcGF5bG9hZDtcbiAgICAgICAgaWYgKGI2NCkge1xuICAgICAgICAgICAgcGF5bG9hZCA9IGVuY29kZXIuZW5jb2RlKGJhc2U2NHVybChwYXlsb2FkKSk7XG4gICAgICAgIH1cbiAgICAgICAgbGV0IHByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgaWYgKHRoaXMuX3Byb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgcHJvdGVjdGVkSGVhZGVyID0gZW5jb2Rlci5lbmNvZGUoYmFzZTY0dXJsKEpTT04uc3RyaW5naWZ5KHRoaXMuX3Byb3RlY3RlZEhlYWRlcikpKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHByb3RlY3RlZEhlYWRlciA9IGVuY29kZXIuZW5jb2RlKCcnKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBkYXRhID0gY29uY2F0KHByb3RlY3RlZEhlYWRlciwgZW5jb2Rlci5lbmNvZGUoJy4nKSwgcGF5bG9hZCk7XG4gICAgICAgIGNvbnN0IHNpZ25hdHVyZSA9IGF3YWl0IHNpZ24oYWxnLCBrZXksIGRhdGEpO1xuICAgICAgICBjb25zdCBqd3MgPSB7XG4gICAgICAgICAgICBzaWduYXR1cmU6IGJhc2U2NHVybChzaWduYXR1cmUpLFxuICAgICAgICAgICAgcGF5bG9hZDogJycsXG4gICAgICAgIH07XG4gICAgICAgIGlmIChiNjQpIHtcbiAgICAgICAgICAgIGp3cy5wYXlsb2FkID0gZGVjb2Rlci5kZWNvZGUocGF5bG9hZCk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICBqd3MuaGVhZGVyID0gdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX3Byb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgandzLnByb3RlY3RlZCA9IGRlY29kZXIuZGVjb2RlKHByb3RlY3RlZEhlYWRlcik7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGp3cztcbiAgICB9XG59XG4iLCJpbXBvcnQgeyBGbGF0dGVuZWRTaWduIH0gZnJvbSAnLi4vZmxhdHRlbmVkL3NpZ24uanMnO1xuZXhwb3J0IGNsYXNzIENvbXBhY3RTaWduIHtcbiAgICBjb25zdHJ1Y3RvcihwYXlsb2FkKSB7XG4gICAgICAgIHRoaXMuX2ZsYXR0ZW5lZCA9IG5ldyBGbGF0dGVuZWRTaWduKHBheWxvYWQpO1xuICAgIH1cbiAgICBzZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIHRoaXMuX2ZsYXR0ZW5lZC5zZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKTtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIGFzeW5jIHNpZ24oa2V5LCBvcHRpb25zKSB7XG4gICAgICAgIGNvbnN0IGp3cyA9IGF3YWl0IHRoaXMuX2ZsYXR0ZW5lZC5zaWduKGtleSwgb3B0aW9ucyk7XG4gICAgICAgIGlmIChqd3MucGF5bG9hZCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCd1c2UgdGhlIGZsYXR0ZW5lZCBtb2R1bGUgZm9yIGNyZWF0aW5nIEpXUyB3aXRoIGI2NDogZmFsc2UnKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gYCR7andzLnByb3RlY3RlZH0uJHtqd3MucGF5bG9hZH0uJHtqd3Muc2lnbmF0dXJlfWA7XG4gICAgfVxufVxuIiwiaW1wb3J0IHsgRmxhdHRlbmVkU2lnbiB9IGZyb20gJy4uL2ZsYXR0ZW5lZC9zaWduLmpzJztcbmltcG9ydCB7IEpXU0ludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5jbGFzcyBJbmRpdmlkdWFsU2lnbmF0dXJlIHtcbiAgICBjb25zdHJ1Y3RvcihzaWcsIGtleSwgb3B0aW9ucykge1xuICAgICAgICB0aGlzLnBhcmVudCA9IHNpZztcbiAgICAgICAgdGhpcy5rZXkgPSBrZXk7XG4gICAgICAgIHRoaXMub3B0aW9ucyA9IG9wdGlvbnM7XG4gICAgfVxuICAgIHNldFByb3RlY3RlZEhlYWRlcihwcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRQcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLnByb3RlY3RlZEhlYWRlciA9IHByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldFVucHJvdGVjdGVkSGVhZGVyKHVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLnVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRVbnByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMudW5wcm90ZWN0ZWRIZWFkZXIgPSB1bnByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIGFkZFNpZ25hdHVyZSguLi5hcmdzKSB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhcmVudC5hZGRTaWduYXR1cmUoLi4uYXJncyk7XG4gICAgfVxuICAgIHNpZ24oLi4uYXJncykge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXJlbnQuc2lnbiguLi5hcmdzKTtcbiAgICB9XG4gICAgZG9uZSgpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGFyZW50O1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBHZW5lcmFsU2lnbiB7XG4gICAgY29uc3RydWN0b3IocGF5bG9hZCkge1xuICAgICAgICB0aGlzLl9zaWduYXR1cmVzID0gW107XG4gICAgICAgIHRoaXMuX3BheWxvYWQgPSBwYXlsb2FkO1xuICAgIH1cbiAgICBhZGRTaWduYXR1cmUoa2V5LCBvcHRpb25zKSB7XG4gICAgICAgIGNvbnN0IHNpZ25hdHVyZSA9IG5ldyBJbmRpdmlkdWFsU2lnbmF0dXJlKHRoaXMsIGtleSwgb3B0aW9ucyk7XG4gICAgICAgIHRoaXMuX3NpZ25hdHVyZXMucHVzaChzaWduYXR1cmUpO1xuICAgICAgICByZXR1cm4gc2lnbmF0dXJlO1xuICAgIH1cbiAgICBhc3luYyBzaWduKCkge1xuICAgICAgICBpZiAoIXRoaXMuX3NpZ25hdHVyZXMubGVuZ3RoKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnYXQgbGVhc3Qgb25lIHNpZ25hdHVyZSBtdXN0IGJlIGFkZGVkJyk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgandzID0ge1xuICAgICAgICAgICAgc2lnbmF0dXJlczogW10sXG4gICAgICAgICAgICBwYXlsb2FkOiAnJyxcbiAgICAgICAgfTtcbiAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCB0aGlzLl9zaWduYXR1cmVzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBjb25zdCBzaWduYXR1cmUgPSB0aGlzLl9zaWduYXR1cmVzW2ldO1xuICAgICAgICAgICAgY29uc3QgZmxhdHRlbmVkID0gbmV3IEZsYXR0ZW5lZFNpZ24odGhpcy5fcGF5bG9hZCk7XG4gICAgICAgICAgICBmbGF0dGVuZWQuc2V0UHJvdGVjdGVkSGVhZGVyKHNpZ25hdHVyZS5wcm90ZWN0ZWRIZWFkZXIpO1xuICAgICAgICAgICAgZmxhdHRlbmVkLnNldFVucHJvdGVjdGVkSGVhZGVyKHNpZ25hdHVyZS51bnByb3RlY3RlZEhlYWRlcik7XG4gICAgICAgICAgICBjb25zdCB7IHBheWxvYWQsIC4uLnJlc3QgfSA9IGF3YWl0IGZsYXR0ZW5lZC5zaWduKHNpZ25hdHVyZS5rZXksIHNpZ25hdHVyZS5vcHRpb25zKTtcbiAgICAgICAgICAgIGlmIChpID09PSAwKSB7XG4gICAgICAgICAgICAgICAgandzLnBheWxvYWQgPSBwYXlsb2FkO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZSBpZiAoandzLnBheWxvYWQgIT09IHBheWxvYWQpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnaW5jb25zaXN0ZW50IHVzZSBvZiBKV1MgVW5lbmNvZGVkIFBheWxvYWQgKFJGQzc3OTcpJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBqd3Muc2lnbmF0dXJlcy5wdXNoKHJlc3QpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBqd3M7XG4gICAgfVxufVxuIiwiaW1wb3J0ICogYXMgYmFzZTY0dXJsIGZyb20gJy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmV4cG9ydCBjb25zdCBlbmNvZGUgPSBiYXNlNjR1cmwuZW5jb2RlO1xuZXhwb3J0IGNvbnN0IGRlY29kZSA9IGJhc2U2NHVybC5kZWNvZGU7XG4iLCJpbXBvcnQgeyBkZWNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHsgZGVjb2RlciB9IGZyb20gJy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4uL2xpYi9pc19vYmplY3QuanMnO1xuZXhwb3J0IGZ1bmN0aW9uIGRlY29kZVByb3RlY3RlZEhlYWRlcih0b2tlbikge1xuICAgIGxldCBwcm90ZWN0ZWRCNjR1O1xuICAgIGlmICh0eXBlb2YgdG9rZW4gPT09ICdzdHJpbmcnKSB7XG4gICAgICAgIGNvbnN0IHBhcnRzID0gdG9rZW4uc3BsaXQoJy4nKTtcbiAgICAgICAgaWYgKHBhcnRzLmxlbmd0aCA9PT0gMyB8fCBwYXJ0cy5sZW5ndGggPT09IDUpIHtcbiAgICAgICAgICAgIDtcbiAgICAgICAgICAgIFtwcm90ZWN0ZWRCNjR1XSA9IHBhcnRzO1xuICAgICAgICB9XG4gICAgfVxuICAgIGVsc2UgaWYgKHR5cGVvZiB0b2tlbiA9PT0gJ29iamVjdCcgJiYgdG9rZW4pIHtcbiAgICAgICAgaWYgKCdwcm90ZWN0ZWQnIGluIHRva2VuKSB7XG4gICAgICAgICAgICBwcm90ZWN0ZWRCNjR1ID0gdG9rZW4ucHJvdGVjdGVkO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignVG9rZW4gZG9lcyBub3QgY29udGFpbiBhIFByb3RlY3RlZCBIZWFkZXInKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICB0cnkge1xuICAgICAgICBpZiAodHlwZW9mIHByb3RlY3RlZEI2NHUgIT09ICdzdHJpbmcnIHx8ICFwcm90ZWN0ZWRCNjR1KSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCByZXN1bHQgPSBKU09OLnBhcnNlKGRlY29kZXIuZGVjb2RlKGJhc2U2NHVybChwcm90ZWN0ZWRCNjR1KSkpO1xuICAgICAgICBpZiAoIWlzT2JqZWN0KHJlc3VsdCkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcigpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignSW52YWxpZCBUb2tlbiBvciBQcm90ZWN0ZWQgSGVhZGVyIGZvcm1hdHRpbmcnKTtcbiAgICB9XG59XG4iLCJpbXBvcnQgY3J5cHRvIGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgcmFuZG9tIGZyb20gJy4vcmFuZG9tLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZVNlY3JldChhbGcsIG9wdGlvbnMpIHtcbiAgICBsZXQgbGVuZ3RoO1xuICAgIGxldCBhbGdvcml0aG07XG4gICAgbGV0IGtleVVzYWdlcztcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdIUzI1Nic6XG4gICAgICAgIGNhc2UgJ0hTMzg0JzpcbiAgICAgICAgY2FzZSAnSFM1MTInOlxuICAgICAgICAgICAgbGVuZ3RoID0gcGFyc2VJbnQoYWxnLnNsaWNlKC0zKSwgMTApO1xuICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnSE1BQycsIGhhc2g6IGBTSEEtJHtsZW5ndGh9YCwgbGVuZ3RoIH07XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3NpZ24nLCAndmVyaWZ5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnQTEyOENCQy1IUzI1Nic6XG4gICAgICAgIGNhc2UgJ0ExOTJDQkMtSFMzODQnOlxuICAgICAgICBjYXNlICdBMjU2Q0JDLUhTNTEyJzpcbiAgICAgICAgICAgIGxlbmd0aCA9IHBhcnNlSW50KGFsZy5zbGljZSgtMyksIDEwKTtcbiAgICAgICAgICAgIHJldHVybiByYW5kb20obmV3IFVpbnQ4QXJyYXkobGVuZ3RoID4+IDMpKTtcbiAgICAgICAgY2FzZSAnQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnQTE5MktXJzpcbiAgICAgICAgY2FzZSAnQTI1NktXJzpcbiAgICAgICAgICAgIGxlbmd0aCA9IHBhcnNlSW50KGFsZy5zbGljZSgxLCA0KSwgMTApO1xuICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnQUVTLUtXJywgbGVuZ3RoIH07XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3dyYXBLZXknLCAndW53cmFwS2V5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnQTEyOEdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTE5MkdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTEyOEdDTSc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ00nOlxuICAgICAgICBjYXNlICdBMjU2R0NNJzpcbiAgICAgICAgICAgIGxlbmd0aCA9IHBhcnNlSW50KGFsZy5zbGljZSgxLCA0KSwgMTApO1xuICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnQUVTLUdDTScsIGxlbmd0aCB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydlbmNyeXB0JywgJ2RlY3J5cHQnXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgSldLIFwiYWxnXCIgKEFsZ29yaXRobSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgfVxuICAgIHJldHVybiBjcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KGFsZ29yaXRobSwgb3B0aW9ucz8uZXh0cmFjdGFibGUgPz8gZmFsc2UsIGtleVVzYWdlcyk7XG59XG5mdW5jdGlvbiBnZXRNb2R1bHVzTGVuZ3RoT3B0aW9uKG9wdGlvbnMpIHtcbiAgICBjb25zdCBtb2R1bHVzTGVuZ3RoID0gb3B0aW9ucz8ubW9kdWx1c0xlbmd0aCA/PyAyMDQ4O1xuICAgIGlmICh0eXBlb2YgbW9kdWx1c0xlbmd0aCAhPT0gJ251bWJlcicgfHwgbW9kdWx1c0xlbmd0aCA8IDIwNDgpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgbW9kdWx1c0xlbmd0aCBvcHRpb24gcHJvdmlkZWQsIDIwNDggYml0cyBvciBsYXJnZXIga2V5cyBtdXN0IGJlIHVzZWQnKTtcbiAgICB9XG4gICAgcmV0dXJuIG1vZHVsdXNMZW5ndGg7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhdGVLZXlQYWlyKGFsZywgb3B0aW9ucykge1xuICAgIGxldCBhbGdvcml0aG07XG4gICAgbGV0IGtleVVzYWdlcztcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdQUzI1Nic6XG4gICAgICAgIGNhc2UgJ1BTMzg0JzpcbiAgICAgICAgY2FzZSAnUFM1MTInOlxuICAgICAgICAgICAgYWxnb3JpdGhtID0ge1xuICAgICAgICAgICAgICAgIG5hbWU6ICdSU0EtUFNTJyxcbiAgICAgICAgICAgICAgICBoYXNoOiBgU0hBLSR7YWxnLnNsaWNlKC0zKX1gLFxuICAgICAgICAgICAgICAgIHB1YmxpY0V4cG9uZW50OiBuZXcgVWludDhBcnJheShbMHgwMSwgMHgwMCwgMHgwMV0pLFxuICAgICAgICAgICAgICAgIG1vZHVsdXNMZW5ndGg6IGdldE1vZHVsdXNMZW5ndGhPcHRpb24ob3B0aW9ucyksXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydzaWduJywgJ3ZlcmlmeSddO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ1JTMjU2JzpcbiAgICAgICAgY2FzZSAnUlMzODQnOlxuICAgICAgICBjYXNlICdSUzUxMic6XG4gICAgICAgICAgICBhbGdvcml0aG0gPSB7XG4gICAgICAgICAgICAgICAgbmFtZTogJ1JTQVNTQS1QS0NTMS12MV81JyxcbiAgICAgICAgICAgICAgICBoYXNoOiBgU0hBLSR7YWxnLnNsaWNlKC0zKX1gLFxuICAgICAgICAgICAgICAgIHB1YmxpY0V4cG9uZW50OiBuZXcgVWludDhBcnJheShbMHgwMSwgMHgwMCwgMHgwMV0pLFxuICAgICAgICAgICAgICAgIG1vZHVsdXNMZW5ndGg6IGdldE1vZHVsdXNMZW5ndGhPcHRpb24ob3B0aW9ucyksXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydzaWduJywgJ3ZlcmlmeSddO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQJzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMjU2JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMzg0JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtNTEyJzpcbiAgICAgICAgICAgIGFsZ29yaXRobSA9IHtcbiAgICAgICAgICAgICAgICBuYW1lOiAnUlNBLU9BRVAnLFxuICAgICAgICAgICAgICAgIGhhc2g6IGBTSEEtJHtwYXJzZUludChhbGcuc2xpY2UoLTMpLCAxMCkgfHwgMX1gLFxuICAgICAgICAgICAgICAgIHB1YmxpY0V4cG9uZW50OiBuZXcgVWludDhBcnJheShbMHgwMSwgMHgwMCwgMHgwMV0pLFxuICAgICAgICAgICAgICAgIG1vZHVsdXNMZW5ndGg6IGdldE1vZHVsdXNMZW5ndGhPcHRpb24ob3B0aW9ucyksXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydkZWNyeXB0JywgJ3Vud3JhcEtleScsICdlbmNyeXB0JywgJ3dyYXBLZXknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdFUzI1Nic6XG4gICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RTQScsIG5hbWVkQ3VydmU6ICdQLTI1NicgfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnc2lnbicsICd2ZXJpZnknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdFUzM4NCc6XG4gICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RTQScsIG5hbWVkQ3VydmU6ICdQLTM4NCcgfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnc2lnbicsICd2ZXJpZnknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdFUzUxMic6XG4gICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RTQScsIG5hbWVkQ3VydmU6ICdQLTUyMScgfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnc2lnbicsICd2ZXJpZnknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdFZERTQSc6IHtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnc2lnbicsICd2ZXJpZnknXTtcbiAgICAgICAgICAgIGNvbnN0IGNydiA9IG9wdGlvbnM/LmNydiA/PyAnRWQyNTUxOSc7XG4gICAgICAgICAgICBzd2l0Y2ggKGNydikge1xuICAgICAgICAgICAgICAgIGNhc2UgJ0VkMjU1MTknOlxuICAgICAgICAgICAgICAgIGNhc2UgJ0VkNDQ4JzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiBjcnYgfTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgY3J2IG9wdGlvbiBwcm92aWRlZCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnRUNESC1FUyc6XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMTkyS1cnOlxuICAgICAgICBjYXNlICdFQ0RILUVTK0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnZGVyaXZlS2V5JywgJ2Rlcml2ZUJpdHMnXTtcbiAgICAgICAgICAgIGNvbnN0IGNydiA9IG9wdGlvbnM/LmNydiA/PyAnUC0yNTYnO1xuICAgICAgICAgICAgc3dpdGNoIChjcnYpIHtcbiAgICAgICAgICAgICAgICBjYXNlICdQLTI1Nic6XG4gICAgICAgICAgICAgICAgY2FzZSAnUC0zODQnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1AtNTIxJzoge1xuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RIJywgbmFtZWRDdXJ2ZTogY3J2IH07XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXNlICdYMjU1MTknOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1g0NDgnOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6IGNydiB9O1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBjcnYgb3B0aW9uIHByb3ZpZGVkLCBzdXBwb3J0ZWQgdmFsdWVzIGFyZSBQLTI1NiwgUC0zODQsIFAtNTIxLCBYMjU1MTksIGFuZCBYNDQ4Jyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgSldLIFwiYWxnXCIgKEFsZ29yaXRobSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgfVxuICAgIHJldHVybiBjcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KGFsZ29yaXRobSwgb3B0aW9ucz8uZXh0cmFjdGFibGUgPz8gZmFsc2UsIGtleVVzYWdlcyk7XG59XG4iLCJpbXBvcnQgeyBnZW5lcmF0ZUtleVBhaXIgYXMgZ2VuZXJhdGUgfSBmcm9tICcuLi9ydW50aW1lL2dlbmVyYXRlLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZUtleVBhaXIoYWxnLCBvcHRpb25zKSB7XG4gICAgcmV0dXJuIGdlbmVyYXRlKGFsZywgb3B0aW9ucyk7XG59XG4iLCJpbXBvcnQgeyBnZW5lcmF0ZVNlY3JldCBhcyBnZW5lcmF0ZSB9IGZyb20gJy4uL3J1bnRpbWUvZ2VuZXJhdGUuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdlbmVyYXRlU2VjcmV0KGFsZywgb3B0aW9ucykge1xuICAgIHJldHVybiBnZW5lcmF0ZShhbGcsIG9wdGlvbnMpO1xufVxuIiwiLy8gT25lIGNvbnNpc3RlbnQgYWxnb3JpdGhtIGZvciBlYWNoIGZhbWlseS5cbi8vIGh0dHBzOi8vZGF0YXRyYWNrZXIuaWV0Zi5vcmcvZG9jL2h0bWwvcmZjNzUxOFxuXG5leHBvcnQgY29uc3Qgc2lnbmluZ05hbWUgPSAnRWREU0EnO1xuZXhwb3J0IGNvbnN0IHNpZ25pbmdDdXJ2ZSA9ICdFZDI1NTE5JztcbmV4cG9ydCBjb25zdCBzaWduaW5nQWxnb3JpdGhtID0gJ0VkRFNBJztcblxuZXhwb3J0IGNvbnN0IGVuY3J5cHRpbmdOYW1lID0gJ1JTQS1PQUVQJztcbmV4cG9ydCBjb25zdCBoYXNoTGVuZ3RoID0gMjU2O1xuZXhwb3J0IGNvbnN0IGhhc2hOYW1lID0gJ1NIQS0yNTYnO1xuZXhwb3J0IGNvbnN0IG1vZHVsdXNMZW5ndGggPSA0MDk2OyAvLyBwYW52YSBKT1NFIGxpYnJhcnkgZGVmYXVsdCBpcyAyMDQ4XG5leHBvcnQgY29uc3QgZW5jcnlwdGluZ0FsZ29yaXRobSA9ICdSU0EtT0FFUC0yNTYnO1xuXG5leHBvcnQgY29uc3Qgc3ltbWV0cmljTmFtZSA9ICdBRVMtR0NNJztcbmV4cG9ydCBjb25zdCBzeW1tZXRyaWNBbGdvcml0aG0gPSAnQTI1NkdDTSc7XG5leHBvcnQgY29uc3Qgc3ltbWV0cmljV3JhcCA9ICdBMjU2R0NNS1cnO1xuZXhwb3J0IGNvbnN0IHNlY3JldEFsZ29yaXRobSA9ICdQQkVTMi1IUzUxMitBMjU2S1cnO1xuXG5leHBvcnQgY29uc3QgZXh0cmFjdGFibGUgPSB0cnVlOyAgLy8gYWx3YXlzIHdyYXBwZWRcblxuIiwiaW1wb3J0IGNyeXB0byBmcm9tICcjY3J5cHRvJztcbmltcG9ydCAqIGFzIEpPU0UgZnJvbSAnam9zZSc7XG5pbXBvcnQge2hhc2hOYW1lfSBmcm9tICcuL2FsZ29yaXRobXMubWpzJztcbmV4cG9ydCB7Y3J5cHRvLCBKT1NFfTtcblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGhhc2hCdWZmZXIoYnVmZmVyKSB7IC8vIFByb21pc2UgYSBVaW50OEFycmF5IGRpZ2VzdCBvZiBidWZmZXIuXG4gIGxldCBoYXNoID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5kaWdlc3QoaGFzaE5hbWUsIGJ1ZmZlcik7XG4gIHJldHVybiBuZXcgVWludDhBcnJheShoYXNoKTtcbn1cbmV4cG9ydCBmdW5jdGlvbiBoYXNoVGV4dCh0ZXh0KSB7IC8vIFByb21pc2UgYSBVaW50OEFycmF5IGRpZ2VzdCBvZiB0ZXh0IHN0cmluZy5cbiAgbGV0IGJ1ZmZlciA9IG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZSh0ZXh0KTtcbiAgcmV0dXJuIGhhc2hCdWZmZXIoYnVmZmVyKTtcbn1cbmV4cG9ydCBmdW5jdGlvbiBlbmNvZGVCYXNlNjR1cmwodWludDhBcnJheSkgeyAvLyBBbnN3ZXIgYmFzZTY0dXJsIGVuY29kZWQgc3RyaW5nIG9mIGFycmF5LlxuICByZXR1cm4gSk9TRS5iYXNlNjR1cmwuZW5jb2RlKHVpbnQ4QXJyYXkpO1xufVxuZXhwb3J0IGZ1bmN0aW9uIGRlY29kZUJhc2U2NHVybChzdHJpbmcpIHsgLy8gQW5zd2VyIHRoZSBkZWNvZGVkIFVpbnQ4QXJyYXkgb2YgdGhlIGJhc2U2NHVybCBzdHJpbmcuXG4gIHJldHVybiBKT1NFLmJhc2U2NHVybC5kZWNvZGUoc3RyaW5nKTtcbn1cbmV4cG9ydCBmdW5jdGlvbiBkZWNvZGVDbGFpbXMoandTb21ldGhpbmcsIGluZGV4ID0gMCkgeyAvLyBBbnN3ZXIgYW4gb2JqZWN0IHdob3NlIGtleXMgYXJlIHRoZSBkZWNvZGVkIHByb3RlY3RlZCBoZWFkZXIgb2YgdGhlIEpXUyBvciBKV0UgKHVzaW5nIHNpZ25hdHVyZXNbaW5kZXhdIG9mIGEgZ2VuZXJhbC1mb3JtIEpXUykuXG4gIHJldHVybiBKT1NFLmRlY29kZVByb3RlY3RlZEhlYWRlcihqd1NvbWV0aGluZy5zaWduYXR1cmVzPy5baW5kZXhdIHx8IGp3U29tZXRoaW5nKTtcbn1cbiAgICBcbiIsImltcG9ydCB7ZXh0cmFjdGFibGUsIHNpZ25pbmdOYW1lLCBzaWduaW5nQ3VydmUsIHN5bW1ldHJpY05hbWUsIGhhc2hMZW5ndGh9IGZyb20gXCIuL2FsZ29yaXRobXMubWpzXCI7XG5pbXBvcnQgY3J5cHRvIGZyb20gJyNjcnlwdG8nO1xuXG5leHBvcnQgZnVuY3Rpb24gZXhwb3J0UmF3S2V5KGtleSkge1xuICByZXR1cm4gY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoJ3JhdycsIGtleSk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBpbXBvcnRSYXdLZXkoYXJyYXlCdWZmZXIpIHtcbiAgY29uc3QgYWxnb3JpdGhtID0ge25hbWU6IHNpZ25pbmdDdXJ2ZX07XG4gIHJldHVybiBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgYXJyYXlCdWZmZXIsIGFsZ29yaXRobSwgZXh0cmFjdGFibGUsIFsndmVyaWZ5J10pO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gaW1wb3J0U2VjcmV0KGJ5dGVBcnJheSkge1xuICBjb25zdCBhbGdvcml0aG0gPSB7bmFtZTogc3ltbWV0cmljTmFtZSwgbGVuZ3RoOiBoYXNoTGVuZ3RofTtcbiAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBieXRlQXJyYXksIGFsZ29yaXRobSwgdHJ1ZSwgWydlbmNyeXB0JywgJ2RlY3J5cHQnXSk7XG59XG4iLCJpbXBvcnQge0pPU0UsIGhhc2hUZXh0LCBlbmNvZGVCYXNlNjR1cmwsIGRlY29kZUJhc2U2NHVybH0gZnJvbSAnLi91dGlsaXRpZXMubWpzJztcbmltcG9ydCB7ZXhwb3J0UmF3S2V5LCBpbXBvcnRSYXdLZXksIGltcG9ydFNlY3JldH0gZnJvbSAnI3Jhdyc7XG5pbXBvcnQge2V4dHJhY3RhYmxlLCBzaWduaW5nTmFtZSwgc2lnbmluZ0N1cnZlLCBzaWduaW5nQWxnb3JpdGhtLCBlbmNyeXB0aW5nTmFtZSwgaGFzaExlbmd0aCwgaGFzaE5hbWUsIG1vZHVsdXNMZW5ndGgsIGVuY3J5cHRpbmdBbGdvcml0aG0sIHN5bW1ldHJpY05hbWUsIHN5bW1ldHJpY0FsZ29yaXRobX0gZnJvbSAnLi9hbGdvcml0aG1zLm1qcyc7XG5cbmNvbnN0IEtyeXB0byA9IHtcbiAgLy8gQW4gaW5oZXJpdGFibGUgc2luZ2xldG9uIGZvciBjb21wYWN0IEpPU0Ugb3BlcmF0aW9ucy5cbiAgLy8gU2VlIGh0dHBzOi8va2lscm95LWNvZGUuZ2l0aHViLmlvL2Rpc3RyaWJ1dGVkLXNlY3VyaXR5L2RvY3MvaW1wbGVtZW50YXRpb24uaHRtbCN3cmFwcGluZy1zdWJ0bGVrcnlwdG9cbiAgZGVjb2RlUHJvdGVjdGVkSGVhZGVyOiBKT1NFLmRlY29kZVByb3RlY3RlZEhlYWRlcixcbiAgaXNFbXB0eUpXU1BheWxvYWQoY29tcGFjdEpXUykgeyAvLyBhcmcgaXMgYSBzdHJpbmdcbiAgICByZXR1cm4gIWNvbXBhY3RKV1Muc3BsaXQoJy4nKVsxXTtcbiAgfSxcblxuXG4gIC8vIFRoZSBjdHkgY2FuIGJlIHNwZWNpZmllZCBpbiBlbmNyeXB0L3NpZ24sIGJ1dCBkZWZhdWx0cyB0byBhIGdvb2QgZ3Vlc3MuXG4gIC8vIFRoZSBjdHkgY2FuIGJlIHNwZWNpZmllZCBpbiBkZWNyeXB0L3ZlcmlmeSwgYnV0IGRlZmF1bHRzIHRvIHdoYXQgaXMgc3BlY2lmaWVkIGluIHRoZSBwcm90ZWN0ZWQgaGVhZGVyLlxuICBpbnB1dEJ1ZmZlcihkYXRhLCBoZWFkZXIpIHsgLy8gQW5zd2VycyBhIGJ1ZmZlciB2aWV3IG9mIGRhdGEgYW5kLCBpZiBuZWNlc3NhcnkgdG8gY29udmVydCwgYmFzaGVzIGN0eSBvZiBoZWFkZXIuXG4gICAgaWYgKEFycmF5QnVmZmVyLmlzVmlldyhkYXRhKSkgcmV0dXJuIGRhdGE7XG4gICAgbGV0IGdpdmVuQ3R5ID0gaGVhZGVyLmN0eSB8fCAnJztcbiAgICBpZiAoZ2l2ZW5DdHkuaW5jbHVkZXMoJ3RleHQnKSB8fCAoJ3N0cmluZycgPT09IHR5cGVvZiBkYXRhKSkge1xuICAgICAgaGVhZGVyLmN0eSA9IGdpdmVuQ3R5IHx8ICd0ZXh0L3BsYWluJztcbiAgICB9IGVsc2Uge1xuICAgICAgaGVhZGVyLmN0eSA9IGdpdmVuQ3R5IHx8ICdqc29uJzsgLy8gSldTIHJlY29tbWVuZHMgbGVhdmluZyBvZmYgdGhlIGxlYWRpbmcgJ2FwcGxpY2F0aW9uLycuXG4gICAgICBkYXRhID0gSlNPTi5zdHJpbmdpZnkoZGF0YSk7IC8vIE5vdGUgdGhhdCBuZXcgU3RyaW5nKFwic29tZXRoaW5nXCIpIHdpbGwgcGFzcyB0aGlzIHdheS5cbiAgICB9XG4gICAgcmV0dXJuIG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZShkYXRhKTtcbiAgfSxcbiAgcmVjb3ZlckRhdGFGcm9tQ29udGVudFR5cGUocmVzdWx0LCB7Y3R5ID0gcmVzdWx0Py5wcm90ZWN0ZWRIZWFkZXI/LmN0eX0gPSB7fSkge1xuICAgIC8vIEV4YW1pbmVzIHJlc3VsdD8ucHJvdGVjdGVkSGVhZGVyIGFuZCBiYXNoZXMgaW4gcmVzdWx0LnRleHQgb3IgcmVzdWx0Lmpzb24gaWYgYXBwcm9wcmlhdGUsIHJldHVybmluZyByZXN1bHQuXG4gICAgaWYgKHJlc3VsdCAmJiAhT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHJlc3VsdCwgJ3BheWxvYWQnKSkgcmVzdWx0LnBheWxvYWQgPSByZXN1bHQucGxhaW50ZXh0OyAgLy8gYmVjYXVzZSBKT1NFIHVzZXMgcGxhaW50ZXh0IGZvciBkZWNyeXB0IGFuZCBwYXlsb2FkIGZvciBzaWduLlxuICAgIGlmICghY3R5IHx8ICFyZXN1bHQ/LnBheWxvYWQpIHJldHVybiByZXN1bHQ7IC8vIGVpdGhlciBubyBjdHkgb3Igbm8gcmVzdWx0XG4gICAgcmVzdWx0LnRleHQgPSBuZXcgVGV4dERlY29kZXIoKS5kZWNvZGUocmVzdWx0LnBheWxvYWQpO1xuICAgIGlmIChjdHkuaW5jbHVkZXMoJ2pzb24nKSkgcmVzdWx0Lmpzb24gPSBKU09OLnBhcnNlKHJlc3VsdC50ZXh0KTtcbiAgICByZXR1cm4gcmVzdWx0O1xuICB9LFxuXG4gIC8vIFNpZ24vVmVyaWZ5XG4gIGdlbmVyYXRlU2lnbmluZ0tleSgpIHsgLy8gUHJvbWlzZSB7cHJpdmF0ZUtleSwgcHVibGljS2V5fSBpbiBvdXIgc3RhbmRhcmQgc2lnbmluZyBhbGdvcml0aG0uXG4gICAgcmV0dXJuIEpPU0UuZ2VuZXJhdGVLZXlQYWlyKHNpZ25pbmdBbGdvcml0aG0sIHtleHRyYWN0YWJsZX0pO1xuICB9LFxuICBhc3luYyBzaWduKHByaXZhdGVLZXksIG1lc3NhZ2UsIGhlYWRlcnMgPSB7fSkgeyAvLyBQcm9taXNlIGEgY29tcGFjdCBKV1Mgc3RyaW5nLiBBY2NlcHRzIGhlYWRlcnMgdG8gYmUgcHJvdGVjdGVkLlxuICAgIGxldCBoZWFkZXIgPSB7YWxnOiBzaWduaW5nQWxnb3JpdGhtLCAuLi5oZWFkZXJzfSxcbiAgICAgICAgaW5wdXRCdWZmZXIgPSB0aGlzLmlucHV0QnVmZmVyKG1lc3NhZ2UsIGhlYWRlcik7XG4gICAgcmV0dXJuIG5ldyBKT1NFLkNvbXBhY3RTaWduKGlucHV0QnVmZmVyKS5zZXRQcm90ZWN0ZWRIZWFkZXIoaGVhZGVyKS5zaWduKHByaXZhdGVLZXkpO1xuICB9LFxuICBhc3luYyB2ZXJpZnkocHVibGljS2V5LCBzaWduYXR1cmUsIG9wdGlvbnMpIHsgLy8gUHJvbWlzZSB7cGF5bG9hZCwgdGV4dCwganNvbn0sIHdoZXJlIHRleHQgYW5kIGpzb24gYXJlIG9ubHkgZGVmaW5lZCB3aGVuIGFwcHJvcHJpYXRlLlxuICAgIGxldCByZXN1bHQgPSBhd2FpdCBKT1NFLmNvbXBhY3RWZXJpZnkoc2lnbmF0dXJlLCBwdWJsaWNLZXkpLmNhdGNoKCgpID0+IHVuZGVmaW5lZCk7XG4gICAgcmV0dXJuIHRoaXMucmVjb3ZlckRhdGFGcm9tQ29udGVudFR5cGUocmVzdWx0LCBvcHRpb25zKTtcbiAgfSxcblxuICAvLyBFbmNyeXB0L0RlY3J5cHRcbiAgZ2VuZXJhdGVFbmNyeXB0aW5nS2V5KCkgeyAvLyBQcm9taXNlIHtwcml2YXRlS2V5LCBwdWJsaWNLZXl9IGluIG91ciBzdGFuZGFyZCBlbmNyeXB0aW9uIGFsZ29yaXRobS5cbiAgICByZXR1cm4gSk9TRS5nZW5lcmF0ZUtleVBhaXIoZW5jcnlwdGluZ0FsZ29yaXRobSwge2V4dHJhY3RhYmxlLCBtb2R1bHVzTGVuZ3RofSk7XG4gIH0sXG4gIGFzeW5jIGVuY3J5cHQoa2V5LCBtZXNzYWdlLCBoZWFkZXJzID0ge30pIHsgLy8gUHJvbWlzZSBhIGNvbXBhY3QgSldFIHN0cmluZy4gQWNjZXB0cyBoZWFkZXJzIHRvIGJlIHByb3RlY3RlZC5cbiAgICBsZXQgYWxnID0gdGhpcy5pc1N5bW1ldHJpYyhrZXkpID8gJ2RpcicgOiBlbmNyeXB0aW5nQWxnb3JpdGhtLFxuICAgICAgICBoZWFkZXIgPSB7YWxnLCBlbmM6IHN5bW1ldHJpY0FsZ29yaXRobSwgLi4uaGVhZGVyc30sXG4gICAgICAgIGlucHV0QnVmZmVyID0gdGhpcy5pbnB1dEJ1ZmZlcihtZXNzYWdlLCBoZWFkZXIpLFxuICAgICAgICBzZWNyZXQgPSB0aGlzLmtleVNlY3JldChrZXkpO1xuICAgIHJldHVybiBuZXcgSk9TRS5Db21wYWN0RW5jcnlwdChpbnB1dEJ1ZmZlcikuc2V0UHJvdGVjdGVkSGVhZGVyKGhlYWRlcikuZW5jcnlwdChzZWNyZXQpO1xuICB9LFxuICBhc3luYyBkZWNyeXB0KGtleSwgZW5jcnlwdGVkLCBvcHRpb25zID0ge30pIHsgLy8gUHJvbWlzZSB7cGF5bG9hZCwgdGV4dCwganNvbn0sIHdoZXJlIHRleHQgYW5kIGpzb24gYXJlIG9ubHkgZGVmaW5lZCB3aGVuIGFwcHJvcHJpYXRlLlxuICAgIGxldCBzZWNyZXQgPSB0aGlzLmtleVNlY3JldChrZXkpLFxuICAgICAgICByZXN1bHQgPSBhd2FpdCBKT1NFLmNvbXBhY3REZWNyeXB0KGVuY3J5cHRlZCwgc2VjcmV0KTtcbiAgICB0aGlzLnJlY292ZXJEYXRhRnJvbUNvbnRlbnRUeXBlKHJlc3VsdCwgb3B0aW9ucyk7XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfSxcbiAgYXN5bmMgZ2VuZXJhdGVTZWNyZXRLZXkodGV4dCkgeyAvLyBKT1NFIHVzZXMgYSBkaWdlc3QgZm9yIFBCRVMsIGJ1dCBtYWtlIGl0IHJlY29nbml6YWJsZSBhcyBhIHt0eXBlOiAnc2VjcmV0J30ga2V5LlxuICAgIGxldCBoYXNoID0gYXdhaXQgaGFzaFRleHQodGV4dCk7XG4gICAgcmV0dXJuIHt0eXBlOiAnc2VjcmV0JywgdGV4dDogaGFzaH07XG4gIH0sXG4gIGdlbmVyYXRlU3ltbWV0cmljS2V5KHRleHQpIHsgLy8gUHJvbWlzZSBhIGtleSBmb3Igc3ltbWV0cmljIGVuY3J5cHRpb24uXG4gICAgaWYgKHRleHQpIHJldHVybiB0aGlzLmdlbmVyYXRlU2VjcmV0S2V5KHRleHQpOyAvLyBQQkVTXG4gICAgcmV0dXJuIEpPU0UuZ2VuZXJhdGVTZWNyZXQoc3ltbWV0cmljQWxnb3JpdGhtLCB7ZXh0cmFjdGFibGV9KTsgLy8gQUVTXG4gIH0sXG4gIGlzU3ltbWV0cmljKGtleSkgeyAvLyBFaXRoZXIgQUVTIG9yIFBCRVMsIGJ1dCBub3QgcHVibGljS2V5IG9yIHByaXZhdGVLZXkuXG4gICAgcmV0dXJuIGtleS50eXBlID09PSAnc2VjcmV0JztcbiAgfSxcbiAga2V5U2VjcmV0KGtleSkgeyAvLyBSZXR1cm4gd2hhdCBpcyBhY3R1YWxseSB1c2VkIGFzIGlucHV0IGluIEpPU0UgbGlicmFyeS5cbiAgICBpZiAoa2V5LnRleHQpIHJldHVybiBrZXkudGV4dDtcbiAgICByZXR1cm4ga2V5O1xuICB9LFxuXG4gIC8vIEV4cG9ydC9JbXBvcnRcbiAgYXN5bmMgZXhwb3J0UmF3KGtleSkgeyAvLyBiYXNlNjR1cmwgZm9yIHB1YmxpYyB2ZXJmaWNhdGlvbiBrZXlzXG4gICAgbGV0IGFycmF5QnVmZmVyID0gYXdhaXQgZXhwb3J0UmF3S2V5KGtleSk7XG4gICAgcmV0dXJuIGVuY29kZUJhc2U2NHVybChuZXcgVWludDhBcnJheShhcnJheUJ1ZmZlcikpO1xuICB9LFxuICBhc3luYyBpbXBvcnRSYXcoc3RyaW5nKSB7IC8vIFByb21pc2UgdGhlIHZlcmlmaWNhdGlvbiBrZXkgZnJvbSBiYXNlNjR1cmxcbiAgICBsZXQgYXJyYXlCdWZmZXIgPSBkZWNvZGVCYXNlNjR1cmwoc3RyaW5nKTtcbiAgICByZXR1cm4gaW1wb3J0UmF3S2V5KGFycmF5QnVmZmVyKTtcbiAgfSxcbiAgYXN5bmMgZXhwb3J0SldLKGtleSkgeyAvLyBQcm9taXNlIEpXSyBvYmplY3QsIHdpdGggYWxnIGluY2x1ZGVkLlxuICAgIGxldCBleHBvcnRlZCA9IGF3YWl0IEpPU0UuZXhwb3J0SldLKGtleSksXG4gICAgICAgIGFsZyA9IGtleS5hbGdvcml0aG07IC8vIEpPU0UgbGlicmFyeSBnaXZlcyBhbGdvcml0aG0sIGJ1dCBub3QgYWxnIHRoYXQgaXMgbmVlZGVkIGZvciBpbXBvcnQuXG4gICAgaWYgKGFsZykgeyAvLyBzdWJ0bGUuY3J5cHRvIHVuZGVybHlpbmcga2V5c1xuICAgICAgaWYgKGFsZy5uYW1lID09PSBzaWduaW5nTmFtZSAmJiBhbGcubmFtZWRDdXJ2ZSA9PT0gc2lnbmluZ0N1cnZlKSBleHBvcnRlZC5hbGcgPSBzaWduaW5nQWxnb3JpdGhtO1xuICAgICAgZWxzZSBpZiAoYWxnLm5hbWUgPT09IHNpZ25pbmdDdXJ2ZSkgZXhwb3J0ZWQuYWxnID0gc2lnbmluZ0FsZ29yaXRobTtcbiAgICAgIGVsc2UgaWYgKGFsZy5uYW1lID09PSBlbmNyeXB0aW5nTmFtZSAmJiBhbGcuaGFzaC5uYW1lID09PSBoYXNoTmFtZSkgZXhwb3J0ZWQuYWxnID0gZW5jcnlwdGluZ0FsZ29yaXRobTtcbiAgICAgIGVsc2UgaWYgKGFsZy5uYW1lID09PSBzeW1tZXRyaWNOYW1lICYmIGFsZy5sZW5ndGggPT09IGhhc2hMZW5ndGgpIGV4cG9ydGVkLmFsZyA9IHN5bW1ldHJpY0FsZ29yaXRobTtcbiAgICB9IGVsc2Ugc3dpdGNoIChleHBvcnRlZC5rdHkpIHsgLy8gSk9TRSBvbiBOb2RlSlMgdXNlZCBub2RlOmNyeXB0byBrZXlzLCB3aGljaCBkbyBub3QgZXhwb3NlIHRoZSBwcmVjaXNlIGFsZ29yaXRobVxuICAgICAgY2FzZSAnRUMnOiBleHBvcnRlZC5hbGcgPSBzaWduaW5nQWxnb3JpdGhtOyBicmVhaztcbiAgICAgIGNhc2UgJ09LUCc6IGV4cG9ydGVkLmFsZyA9IHNpZ25pbmdBbGdvcml0aG07IGJyZWFrO1xuICAgICAgY2FzZSAnUlNBJzogZXhwb3J0ZWQuYWxnID0gZW5jcnlwdGluZ0FsZ29yaXRobTsgYnJlYWs7XG4gICAgICBjYXNlICdvY3QnOiBleHBvcnRlZC5hbGcgPSBzeW1tZXRyaWNBbGdvcml0aG07IGJyZWFrO1xuICAgIH1cbiAgICByZXR1cm4gZXhwb3J0ZWQ7XG4gIH0sXG4gIGFzeW5jIGltcG9ydEpXSyhqd2spIHsgLy8gUHJvbWlzZSBhIGtleSBvYmplY3RcbiAgICBqd2sgPSB7ZXh0OiB0cnVlLCAuLi5qd2t9OyAvLyBXZSBuZWVkIHRoZSByZXN1bHQgdG8gYmUgYmUgYWJsZSB0byBnZW5lcmF0ZSBhIG5ldyBKV0sgKGUuZy4sIG9uIGNoYW5nZU1lbWJlcnNoaXApXG4gICAgbGV0IGltcG9ydGVkID0gYXdhaXQgSk9TRS5pbXBvcnRKV0soandrKTtcbiAgICBpZiAoaW1wb3J0ZWQgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAvLyBXZSBkZXBlbmQgYW4gcmV0dXJuaW5nIGFuIGFjdHVhbCBrZXksIGJ1dCB0aGUgSk9TRSBsaWJyYXJ5IHdlIHVzZVxuICAgICAgLy8gd2lsbCBhYm92ZSBwcm9kdWNlIHRoZSByYXcgVWludDhBcnJheSBpZiB0aGUgandrIGlzIGZyb20gYSBzZWNyZXQuXG4gICAgICBpbXBvcnRlZCA9IGF3YWl0IGltcG9ydFNlY3JldChpbXBvcnRlZCk7XG4gICAgfVxuICAgIHJldHVybiBpbXBvcnRlZDtcbiAgfSxcblxuICBhc3luYyB3cmFwS2V5KGtleSwgd3JhcHBpbmdLZXksIGhlYWRlcnMgPSB7fSkgeyAvLyBQcm9taXNlIGEgSldFIGZyb20gdGhlIHB1YmxpYyB3cmFwcGluZ0tleVxuICAgIGxldCBleHBvcnRlZCA9IGF3YWl0IHRoaXMuZXhwb3J0SldLKGtleSk7XG4gICAgcmV0dXJuIHRoaXMuZW5jcnlwdCh3cmFwcGluZ0tleSwgZXhwb3J0ZWQsIGhlYWRlcnMpO1xuICB9LFxuICBhc3luYyB1bndyYXBLZXkod3JhcHBlZEtleSwgdW53cmFwcGluZ0tleSkgeyAvLyBQcm9taXNlIHRoZSBrZXkgdW5sb2NrZWQgYnkgdGhlIHByaXZhdGUgdW53cmFwcGluZ0tleS5cbiAgICBsZXQgZGVjcnlwdGVkID0gYXdhaXQgdGhpcy5kZWNyeXB0KHVud3JhcHBpbmdLZXksIHdyYXBwZWRLZXkpO1xuICAgIHJldHVybiB0aGlzLmltcG9ydEpXSyhkZWNyeXB0ZWQuanNvbik7XG4gIH1cbn1cblxuZXhwb3J0IGRlZmF1bHQgS3J5cHRvO1xuLypcblNvbWUgdXNlZnVsIEpPU0UgcmVjaXBlcyBmb3IgcGxheWluZyBhcm91bmQuXG5zayA9IGF3YWl0IEpPU0UuZ2VuZXJhdGVLZXlQYWlyKCdFUzM4NCcsIHtleHRyYWN0YWJsZTogdHJ1ZX0pXG5qd3QgPSBhd2FpdCBuZXcgSk9TRS5TaWduSldUKCkuc2V0U3ViamVjdChcImZvb1wiKS5zZXRQcm90ZWN0ZWRIZWFkZXIoe2FsZzonRVMzODQnfSkuc2lnbihzay5wcml2YXRlS2V5KVxuYXdhaXQgSk9TRS5qd3RWZXJpZnkoand0LCBzay5wdWJsaWNLZXkpIC8vLnBheWxvYWQuc3ViXG5cbm1lc3NhZ2UgPSBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUoJ3NvbWUgbWVzc2FnZScpXG5qd3MgPSBhd2FpdCBuZXcgSk9TRS5Db21wYWN0U2lnbihtZXNzYWdlKS5zZXRQcm90ZWN0ZWRIZWFkZXIoe2FsZzonRVMzODQnfSkuc2lnbihzay5wcml2YXRlS2V5KSAvLyBPciBGbGF0dGVuZWRTaWduXG5qd3MgPSBhd2FpdCBuZXcgSk9TRS5HZW5lcmFsU2lnbihtZXNzYWdlKS5hZGRTaWduYXR1cmUoc2sucHJpdmF0ZUtleSkuc2V0UHJvdGVjdGVkSGVhZGVyKHthbGc6J0VTMzg0J30pLnNpZ24oKVxudmVyaWZpZWQgPSBhd2FpdCBKT1NFLmdlbmVyYWxWZXJpZnkoandzLCBzay5wdWJsaWNLZXkpXG5vciBjb21wYWN0VmVyaWZ5IG9yIGZsYXR0ZW5lZFZlcmlmeVxubmV3IFRleHREZWNvZGVyKCkuZGVjb2RlKHZlcmlmaWVkLnBheWxvYWQpXG5cbmVrID0gYXdhaXQgSk9TRS5nZW5lcmF0ZUtleVBhaXIoJ1JTQS1PQUVQLTI1NicsIHtleHRyYWN0YWJsZTogdHJ1ZX0pXG5qd2UgPSBhd2FpdCBuZXcgSk9TRS5Db21wYWN0RW5jcnlwdChtZXNzYWdlKS5zZXRQcm90ZWN0ZWRIZWFkZXIoe2FsZzogJ1JTQS1PQUVQLTI1NicsIGVuYzogJ0EyNTZHQ00nIH0pLmVuY3J5cHQoZWsucHVibGljS2V5KVxub3IgRmxhdHRlbmVkRW5jcnlwdC4gRm9yIHN5bW1ldHJpYyBzZWNyZXQsIHNwZWNpZnkgYWxnOidkaXInLlxuZGVjcnlwdGVkID0gYXdhaXQgSk9TRS5jb21wYWN0RGVjcnlwdChqd2UsIGVrLnByaXZhdGVLZXkpXG5uZXcgVGV4dERlY29kZXIoKS5kZWNvZGUoZGVjcnlwdGVkLnBsYWludGV4dClcbmp3ZSA9IGF3YWl0IG5ldyBKT1NFLkdlbmVyYWxFbmNyeXB0KG1lc3NhZ2UpLnNldFByb3RlY3RlZEhlYWRlcih7YWxnOiAnUlNBLU9BRVAtMjU2JywgZW5jOiAnQTI1NkdDTScgfSkuYWRkUmVjaXBpZW50KGVrLnB1YmxpY0tleSkuZW5jcnlwdCgpIC8vIHdpdGggYWRkaXRpb25hbCBhZGRSZWNpcGVudCgpIGFzIG5lZWRlZFxuZGVjcnlwdGVkID0gYXdhaXQgSk9TRS5nZW5lcmFsRGVjcnlwdChqd2UsIGVrLnByaXZhdGVLZXkpXG5cbm1hdGVyaWFsID0gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKCdzZWNyZXQnKVxuandlID0gYXdhaXQgbmV3IEpPU0UuQ29tcGFjdEVuY3J5cHQobWVzc2FnZSkuc2V0UHJvdGVjdGVkSGVhZGVyKHthbGc6ICdQQkVTMi1IUzUxMitBMjU2S1cnLCBlbmM6ICdBMjU2R0NNJyB9KS5lbmNyeXB0KG1hdGVyaWFsKVxuZGVjcnlwdGVkID0gYXdhaXQgSk9TRS5jb21wYWN0RGVjcnlwdChqd2UsIG1hdGVyaWFsLCB7a2V5TWFuYWdlbWVudEFsZ29yaXRobXM6IFsnUEJFUzItSFM1MTIrQTI1NktXJ10sIGNvbnRlbnRFbmNyeXB0aW9uQWxnb3JpdGhtczogWydBMjU2R0NNJ119KVxuandlID0gYXdhaXQgbmV3IEpPU0UuR2VuZXJhbEVuY3J5cHQobWVzc2FnZSkuc2V0UHJvdGVjdGVkSGVhZGVyKHthbGc6ICdQQkVTMi1IUzUxMitBMjU2S1cnLCBlbmM6ICdBMjU2R0NNJyB9KS5hZGRSZWNpcGllbnQobWF0ZXJpYWwpLmVuY3J5cHQoKVxuandlID0gYXdhaXQgbmV3IEpPU0UuR2VuZXJhbEVuY3J5cHQobWVzc2FnZSkuc2V0UHJvdGVjdGVkSGVhZGVyKHtlbmM6ICdBMjU2R0NNJyB9KVxuICAuYWRkUmVjaXBpZW50KGVrLnB1YmxpY0tleSkuc2V0VW5wcm90ZWN0ZWRIZWFkZXIoe2tpZDogJ2ZvbycsIGFsZzogJ1JTQS1PQUVQLTI1Nid9KVxuICAuYWRkUmVjaXBpZW50KG1hdGVyaWFsKS5zZXRVbnByb3RlY3RlZEhlYWRlcih7a2lkOiAnc2VjcmV0MScsIGFsZzogJ1BCRVMyLUhTNTEyK0EyNTZLVyd9KVxuICAuYWRkUmVjaXBpZW50KG1hdGVyaWFsMikuc2V0VW5wcm90ZWN0ZWRIZWFkZXIoe2tpZDogJ3NlY3JldDInLCBhbGc6ICdQQkVTMi1IUzUxMitBMjU2S1cnfSlcbiAgLmVuY3J5cHQoKVxuZGVjcnlwdGVkID0gYXdhaXQgSk9TRS5nZW5lcmFsRGVjcnlwdChqd2UsIGVrLnByaXZhdGVLZXkpXG5kZWNyeXB0ZWQgPSBhd2FpdCBKT1NFLmdlbmVyYWxEZWNyeXB0KGp3ZSwgbWF0ZXJpYWwsIHtrZXlNYW5hZ2VtZW50QWxnb3JpdGhtczogWydQQkVTMi1IUzUxMitBMjU2S1cnXX0pXG4qL1xuIiwiaW1wb3J0IEtyeXB0byBmcm9tIFwiLi9rcnlwdG8ubWpzXCI7XG5pbXBvcnQgKiBhcyBKT1NFIGZyb20gXCJqb3NlXCI7XG5pbXBvcnQge3NpZ25pbmdBbGdvcml0aG0sIGVuY3J5cHRpbmdBbGdvcml0aG0sIHN5bW1ldHJpY0FsZ29yaXRobSwgc3ltbWV0cmljV3JhcCwgc2VjcmV0QWxnb3JpdGhtfSBmcm9tIFwiLi9hbGdvcml0aG1zLm1qc1wiO1xuXG5mdW5jdGlvbiBtaXNtYXRjaChraWQsIGVuY29kZWRLaWQpIHsgLy8gUHJvbWlzZSBhIHJlamVjdGlvbi5cbiAgbGV0IG1lc3NhZ2UgPSBgS2V5ICR7a2lkfSBkb2VzIG5vdCBtYXRjaCBlbmNvZGVkICR7ZW5jb2RlZEtpZH0uYDtcbiAgcmV0dXJuIFByb21pc2UucmVqZWN0KG1lc3NhZ2UpO1xufVxuXG5jb25zdCBNdWx0aUtyeXB0byA9IHtcbiAgLy8gRXh0ZW5kIEtyeXB0byBmb3IgZ2VuZXJhbCAobXVsdGlwbGUga2V5KSBKT1NFIG9wZXJhdGlvbnMuXG4gIC8vIFNlZSBodHRwczovL2tpbHJveS1jb2RlLmdpdGh1Yi5pby9kaXN0cmlidXRlZC1zZWN1cml0eS9kb2NzL2ltcGxlbWVudGF0aW9uLmh0bWwjY29tYmluaW5nLWtleXNcbiAgXG4gIC8vIE91ciBtdWx0aSBrZXlzIGFyZSBkaWN0aW9uYXJpZXMgb2YgbmFtZSAob3Iga2lkKSA9PiBrZXlPYmplY3QuXG4gIGlzTXVsdGlLZXkoa2V5KSB7IC8vIEEgU3VidGxlQ3J5cHRvIENyeXB0b0tleSBpcyBhbiBvYmplY3Qgd2l0aCBhIHR5cGUgcHJvcGVydHkuIE91ciBtdWx0aWtleXMgYXJlXG4gICAgLy8gb2JqZWN0cyB3aXRoIGEgc3BlY2lmaWMgdHlwZSBvciBubyB0eXBlIHByb3BlcnR5IGF0IGFsbC5cbiAgICByZXR1cm4gKGtleS50eXBlIHx8ICdtdWx0aScpID09PSAnbXVsdGknO1xuICB9LFxuICBrZXlUYWdzKGtleSkgeyAvLyBKdXN0IHRoZSBraWRzIHRoYXQgYXJlIGZvciBhY3R1YWwga2V5cy4gTm8gJ3R5cGUnLlxuICAgIHJldHVybiBPYmplY3Qua2V5cyhrZXkpLmZpbHRlcihrZXkgPT4ga2V5ICE9PSAndHlwZScpO1xuICB9LFxuXG4gIC8vIEV4cG9ydC9JbXBvcnRcbiAgYXN5bmMgZXhwb3J0SldLKGtleSkgeyAvLyBQcm9taXNlIGEgSldLIGtleSBzZXQgaWYgbmVjZXNzYXJ5LCByZXRhaW5pbmcgdGhlIG5hbWVzIGFzIGtpZCBwcm9wZXJ0eS5cbiAgICBpZiAoIXRoaXMuaXNNdWx0aUtleShrZXkpKSByZXR1cm4gc3VwZXIuZXhwb3J0SldLKGtleSk7XG4gICAgbGV0IG5hbWVzID0gdGhpcy5rZXlUYWdzKGtleSksXG4gICAgICAgIGtleXMgPSBhd2FpdCBQcm9taXNlLmFsbChuYW1lcy5tYXAoYXN5bmMgbmFtZSA9PiB7XG4gICAgICAgICAgbGV0IGp3ayA9IGF3YWl0IHRoaXMuZXhwb3J0SldLKGtleVtuYW1lXSk7XG4gICAgICAgICAgandrLmtpZCA9IG5hbWU7XG4gICAgICAgICAgcmV0dXJuIGp3aztcbiAgICAgICAgfSkpO1xuICAgIHJldHVybiB7a2V5c307XG4gIH0sXG4gIGFzeW5jIGltcG9ydEpXSyhqd2spIHsgLy8gUHJvbWlzZSBhIHNpbmdsZSBcImtleVwiIG9iamVjdC5cbiAgICAvLyBSZXN1bHQgd2lsbCBiZSBhIG11bHRpLWtleSBpZiBKV0sgaXMgYSBrZXkgc2V0LCBpbiB3aGljaCBjYXNlIGVhY2ggbXVzdCBpbmNsdWRlIGEga2lkIHByb3BlcnR5LlxuICAgIGlmICghandrLmtleXMpIHJldHVybiBzdXBlci5pbXBvcnRKV0soandrKTtcbiAgICBsZXQga2V5ID0ge307IC8vIFRPRE86IGdldCB0eXBlIGZyb20ga3R5IG9yIHNvbWUgc3VjaD9cbiAgICBhd2FpdCBQcm9taXNlLmFsbChqd2sua2V5cy5tYXAoYXN5bmMgandrID0+IGtleVtqd2sua2lkXSA9IGF3YWl0IHRoaXMuaW1wb3J0SldLKGp3aykpKTtcbiAgICByZXR1cm4ga2V5O1xuICB9LFxuXG4gIC8vIEVuY3J5cHQvRGVjcnlwdFxuICBhc3luYyBlbmNyeXB0KGtleSwgbWVzc2FnZSwgaGVhZGVycyA9IHt9KSB7IC8vIFByb21pc2UgYSBKV0UsIGluIGdlbmVyYWwgZm9ybSBpZiBhcHByb3ByaWF0ZS5cbiAgICBpZiAoIXRoaXMuaXNNdWx0aUtleShrZXkpKSByZXR1cm4gc3VwZXIuZW5jcnlwdChrZXksIG1lc3NhZ2UsIGhlYWRlcnMpO1xuICAgIC8vIGtleSBtdXN0IGJlIGEgZGljdGlvbmFyeSBtYXBwaW5nIHRhZ3MgdG8gZW5jcnlwdGluZyBrZXlzLlxuICAgIGxldCBiYXNlSGVhZGVyID0ge2VuYzogc3ltbWV0cmljQWxnb3JpdGhtLCAuLi5oZWFkZXJzfSxcbiAgICAgICAgaW5wdXRCdWZmZXIgPSB0aGlzLmlucHV0QnVmZmVyKG1lc3NhZ2UsIGJhc2VIZWFkZXIpLFxuICAgICAgICBqd2UgPSBuZXcgSk9TRS5HZW5lcmFsRW5jcnlwdChpbnB1dEJ1ZmZlcikuc2V0UHJvdGVjdGVkSGVhZGVyKGJhc2VIZWFkZXIpO1xuICAgIGZvciAobGV0IHRhZyBvZiB0aGlzLmtleVRhZ3Moa2V5KSkge1xuICAgICAgbGV0IHRoaXNLZXkgPSBrZXlbdGFnXSxcbiAgICAgICAgICBpc1N0cmluZyA9ICdzdHJpbmcnID09PSB0eXBlb2YgdGhpc0tleSxcbiAgICAgICAgICBpc1N5bSA9IGlzU3RyaW5nIHx8IHRoaXMuaXNTeW1tZXRyaWModGhpc0tleSksXG4gICAgICAgICAgc2VjcmV0ID0gaXNTdHJpbmcgPyBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUodGhpc0tleSkgOiB0aGlzLmtleVNlY3JldCh0aGlzS2V5KSxcbiAgICAgICAgICBhbGcgPSBpc1N0cmluZyA/IHNlY3JldEFsZ29yaXRobSA6IChpc1N5bSA/IHN5bW1ldHJpY1dyYXAgOiBlbmNyeXB0aW5nQWxnb3JpdGhtKTtcbiAgICAgIC8vIFRoZSBraWQgYW5kIGFsZyBhcmUgcGVyL3N1Yi1rZXksIGFuZCBzbyBjYW5ub3QgYmUgc2lnbmVkIGJ5IGFsbCwgYW5kIHNvIGNhbm5vdCBiZSBwcm90ZWN0ZWQgd2l0aGluIHRoZSBlbmNyeXB0aW9uLlxuICAgICAgLy8gVGhpcyBpcyBvaywgYmVjYXVzZSB0aGUgb25seSB0aGF0IGNhbiBoYXBwZW4gYXMgYSByZXN1bHQgb2YgdGFtcGVyaW5nIHdpdGggdGhlc2UgaXMgdGhhdCB0aGUgZGVjcnlwdGlvbiB3aWxsIGZhaWwsXG4gICAgICAvLyB3aGljaCBpcyB0aGUgc2FtZSByZXN1bHQgYXMgdGFtcGVyaW5nIHdpdGggdGhlIGNpcGhlcnRleHQgb3IgYW55IG90aGVyIHBhcnQgb2YgdGhlIEpXRS5cbiAgICAgIGp3ZS5hZGRSZWNpcGllbnQoc2VjcmV0KS5zZXRVbnByb3RlY3RlZEhlYWRlcih7a2lkOiB0YWcsIGFsZ30pO1xuICAgIH1cbiAgICBsZXQgZW5jcnlwdGVkID0gYXdhaXQgandlLmVuY3J5cHQoKTtcbiAgICByZXR1cm4gZW5jcnlwdGVkO1xuICB9LFxuICBhc3luYyBkZWNyeXB0KGtleSwgZW5jcnlwdGVkLCBvcHRpb25zKSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259LCB3aGVyZSB0ZXh0IGFuZCBqc29uIGFyZSBvbmx5IGRlZmluZWQgd2hlbiBhcHByb3ByaWF0ZS5cbiAgICBpZiAoIXRoaXMuaXNNdWx0aUtleShrZXkpKSByZXR1cm4gc3VwZXIuZGVjcnlwdChrZXksIGVuY3J5cHRlZCwgb3B0aW9ucyk7XG4gICAgbGV0IGp3ZSA9IGVuY3J5cHRlZCxcbiAgICAgICAge3JlY2lwaWVudHN9ID0gandlLFxuICAgICAgICB1bndyYXBwaW5nUHJvbWlzZXMgPSByZWNpcGllbnRzLm1hcChhc3luYyAoe2hlYWRlcn0pID0+IHtcbiAgICAgICAgICBsZXQge2tpZH0gPSBoZWFkZXIsXG4gICAgICAgICAgICAgIHVud3JhcHBpbmdLZXkgPSBrZXlba2lkXSxcbiAgICAgICAgICAgICAgb3B0aW9ucyA9IHt9O1xuICAgICAgICAgIGlmICghdW53cmFwcGluZ0tleSkgcmV0dXJuIFByb21pc2UucmVqZWN0KCdtaXNzaW5nJyk7XG4gICAgICAgICAgaWYgKCdzdHJpbmcnID09PSB0eXBlb2YgdW53cmFwcGluZ0tleSkgeyAvLyBUT0RPOiBvbmx5IHNwZWNpZmllZCBpZiBhbGxvd2VkIGJ5IHNlY3VyZSBoZWFkZXI/XG4gICAgICAgICAgICB1bndyYXBwaW5nS2V5ID0gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHVud3JhcHBpbmdLZXkpO1xuICAgICAgICAgICAgb3B0aW9ucy5rZXlNYW5hZ2VtZW50QWxnb3JpdGhtcyA9IFtzZWNyZXRBbGdvcml0aG1dO1xuICAgICAgICAgIH1cbiAgICAgICAgICBsZXQgcmVzdWx0ID0gYXdhaXQgSk9TRS5nZW5lcmFsRGVjcnlwdChqd2UsIHRoaXMua2V5U2VjcmV0KHVud3JhcHBpbmdLZXkpLCBvcHRpb25zKSxcbiAgICAgICAgICAgICAgZW5jb2RlZEtpZCA9IHJlc3VsdC51bnByb3RlY3RlZEhlYWRlci5raWQ7XG4gICAgICAgICAgaWYgKGVuY29kZWRLaWQgIT09IGtpZCkgcmV0dXJuIG1pc21hdGNoKGtpZCwgZW5jb2RlZEtpZCk7XG4gICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgfSk7XG4gICAgLy8gRG8gd2UgcmVhbGx5IHdhbnQgdG8gcmV0dXJuIHVuZGVmaW5lZCBpZiBldmVyeXRoaW5nIGZhaWxzPyBTaG91bGQganVzdCBhbGxvdyB0aGUgcmVqZWN0aW9uIHRvIHByb3BhZ2F0ZT9cbiAgICByZXR1cm4gYXdhaXQgUHJvbWlzZS5hbnkodW53cmFwcGluZ1Byb21pc2VzKS50aGVuKFxuICAgICAgcmVzdWx0ID0+IHtcbiAgICAgICAgdGhpcy5yZWNvdmVyRGF0YUZyb21Db250ZW50VHlwZShyZXN1bHQsIG9wdGlvbnMpO1xuICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgfSxcbiAgICAgICgpID0+IHVuZGVmaW5lZCk7XG4gIH0sXG5cbiAgLy8gU2lnbi9WZXJpZnlcbiAgYXN5bmMgc2lnbihrZXksIG1lc3NhZ2UsIGhlYWRlciA9IHt9KSB7IC8vIFByb21pc2UgSldTLCBpbiBnZW5lcmFsIGZvcm0gd2l0aCBraWQgaGVhZGVycyBpZiBuZWNlc3NhcnkuXG4gICAgaWYgKCF0aGlzLmlzTXVsdGlLZXkoa2V5KSkgcmV0dXJuIHN1cGVyLnNpZ24oa2V5LCBtZXNzYWdlLCBoZWFkZXIpO1xuICAgIGxldCBpbnB1dEJ1ZmZlciA9IHRoaXMuaW5wdXRCdWZmZXIobWVzc2FnZSwgaGVhZGVyKSxcbiAgICAgICAgandzID0gbmV3IEpPU0UuR2VuZXJhbFNpZ24oaW5wdXRCdWZmZXIpO1xuICAgIGZvciAobGV0IHRhZyBvZiB0aGlzLmtleVRhZ3Moa2V5KSkge1xuICAgICAgbGV0IHRoaXNLZXkgPSBrZXlbdGFnXSxcbiAgICAgICAgICB0aGlzSGVhZGVyID0ge2tpZDogdGFnLCBhbGc6IHNpZ25pbmdBbGdvcml0aG0sIC4uLmhlYWRlcn07XG4gICAgICBqd3MuYWRkU2lnbmF0dXJlKHRoaXNLZXkpLnNldFByb3RlY3RlZEhlYWRlcih0aGlzSGVhZGVyKTtcbiAgICB9XG4gICAgcmV0dXJuIGp3cy5zaWduKCk7XG4gIH0sXG4gIHZlcmlmeVN1YlNpZ25hdHVyZShqd3MsIHNpZ25hdHVyZUVsZW1lbnQsIG11bHRpS2V5LCBraWRzKSB7XG4gICAgLy8gVmVyaWZ5IGEgc2luZ2xlIGVsZW1lbnQgb2YgandzLnNpZ25hdHVyZSB1c2luZyBtdWx0aUtleS5cbiAgICAvLyBBbHdheXMgcHJvbWlzZXMge3Byb3RlY3RlZEhlYWRlciwgdW5wcm90ZWN0ZWRIZWFkZXIsIGtpZH0sIGV2ZW4gaWYgdmVyaWZpY2F0aW9uIGZhaWxzLFxuICAgIC8vIHdoZXJlIGtpZCBpcyB0aGUgcHJvcGVydHkgbmFtZSB3aXRoaW4gbXVsdGlLZXkgdGhhdCBtYXRjaGVkIChlaXRoZXIgYnkgYmVpbmcgc3BlY2lmaWVkIGluIGEgaGVhZGVyXG4gICAgLy8gb3IgYnkgc3VjY2Vzc2Z1bCB2ZXJpZmljYXRpb24pLiBBbHNvIGluY2x1ZGVzIHRoZSBkZWNvZGVkIHBheWxvYWQgSUZGIHRoZXJlIGlzIGEgbWF0Y2guXG4gICAgbGV0IHByb3RlY3RlZEhlYWRlciA9IHNpZ25hdHVyZUVsZW1lbnQucHJvdGVjdGVkSGVhZGVyID8/IHRoaXMuZGVjb2RlUHJvdGVjdGVkSGVhZGVyKHNpZ25hdHVyZUVsZW1lbnQpLFxuICAgICAgICB1bnByb3RlY3RlZEhlYWRlciA9IHNpZ25hdHVyZUVsZW1lbnQudW5wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgIGtpZCA9IHByb3RlY3RlZEhlYWRlcj8ua2lkIHx8IHVucHJvdGVjdGVkSGVhZGVyPy5raWQsXG4gICAgICAgIHNpbmdsZUpXUyA9IHsuLi5qd3MsIHNpZ25hdHVyZXM6IFtzaWduYXR1cmVFbGVtZW50XX0sXG4gICAgICAgIGZhaWx1cmVSZXN1bHQgPSB7cHJvdGVjdGVkSGVhZGVyLCB1bnByb3RlY3RlZEhlYWRlciwga2lkfSxcbiAgICAgICAga2lkc1RvVHJ5ID0ga2lkID8gW2tpZF0gOiBraWRzO1xuICAgIGxldCBwcm9taXNlID0gUHJvbWlzZS5hbnkoa2lkc1RvVHJ5Lm1hcChhc3luYyBraWQgPT4gSk9TRS5nZW5lcmFsVmVyaWZ5KHNpbmdsZUpXUywgbXVsdGlLZXlba2lkXSkudGhlbihyZXN1bHQgPT4ge3JldHVybiB7a2lkLCAuLi5yZXN1bHR9O30pKSk7XG4gICAgcmV0dXJuIHByb21pc2UuY2F0Y2goKCkgPT4gZmFpbHVyZVJlc3VsdCk7XG4gIH0sXG4gIGFzeW5jIHZlcmlmeShrZXksIHNpZ25hdHVyZSwgb3B0aW9ucyA9IHt9KSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259LCB3aGVyZSB0ZXh0IGFuZCBqc29uIGFyZSBvbmx5IGRlZmluZWQgd2hlbiBhcHByb3ByaWF0ZS5cbiAgICAvLyBBZGRpdGlvbmFsbHksIGlmIGtleSBpcyBhIG11bHRpS2V5IEFORCBzaWduYXR1cmUgaXMgYSBnZW5lcmFsIGZvcm0gSldTLCB0aGVuIGFuc3dlciBpbmNsdWRlcyBhIHNpZ25lcnMgcHJvcGVydHlcbiAgICAvLyBieSB3aGljaCBjYWxsZXIgY2FuIGRldGVybWluZSBpZiBpdCB3aGF0IHRoZXkgZXhwZWN0LiBUaGUgcGF5bG9hZCBvZiBlYWNoIHNpZ25lcnMgZWxlbWVudCBpcyBkZWZpbmVkIG9ubHkgdGhhdFxuICAgIC8vIHNpZ25lciB3YXMgbWF0Y2hlZCBieSBzb21ldGhpbmcgaW4ga2V5LlxuICAgIFxuICAgIGlmICghdGhpcy5pc011bHRpS2V5KGtleSkpIHJldHVybiBzdXBlci52ZXJpZnkoa2V5LCBzaWduYXR1cmUsIG9wdGlvbnMpO1xuICAgIGlmICghc2lnbmF0dXJlLnNpZ25hdHVyZXMpIHJldHVybjtcblxuICAgIC8vIENvbXBhcmlzb24gdG8gcGFudmEgSk9TRS5nZW5lcmFsVmVyaWZ5LlxuICAgIC8vIEpPU0UgdGFrZXMgYSBqd3MgYW5kIE9ORSBrZXkgYW5kIGFuc3dlcnMge3BheWxvYWQsIHByb3RlY3RlZEhlYWRlciwgdW5wcm90ZWN0ZWRIZWFkZXJ9IG1hdGNoaW5nIHRoZSBvbmVcbiAgICAvLyBqd3Muc2lnbmF0dXJlIGVsZW1lbnQgdGhhdCB3YXMgdmVyaWZpZWQsIG90aGVyaXNlIGFuIGVyb3IuIChJdCB0cmllcyBlYWNoIG9mIHRoZSBlbGVtZW50cyBvZiB0aGUgandzLnNpZ25hdHVyZXMuKVxuICAgIC8vIEl0IGlzIG5vdCBnZW5lcmFsbHkgcG9zc2libGUgdG8ga25vdyBXSElDSCBvbmUgb2YgdGhlIGp3cy5zaWduYXR1cmVzIHdhcyBtYXRjaGVkLlxuICAgIC8vIChJdCBNQVkgYmUgcG9zc2libGUgaWYgdGhlcmUgYXJlIHVuaXF1ZSBraWQgZWxlbWVudHMsIGJ1dCB0aGF0J3MgYXBwbGljYXRpb24tZGVwZW5kZW50LilcbiAgICAvL1xuICAgIC8vIE11bHRpS3J5cHRvIHRha2VzIGEgZGljdGlvbmFyeSB0aGF0IGNvbnRhaW5zIG5hbWVkIGtleXMgYW5kIHJlY29nbml6ZWRIZWFkZXIgcHJvcGVydGllcywgYW5kIGl0IHJldHVybnNcbiAgICAvLyBhIHJlc3VsdCB0aGF0IGhhcyBhIHNpZ25lcnMgYXJyYXkgdGhhdCBoYXMgYW4gZWxlbWVudCBjb3JyZXNwb25kaW5nIHRvIGVhY2ggb3JpZ2luYWwgc2lnbmF0dXJlIGlmIGFueVxuICAgIC8vIGFyZSBtYXRjaGVkIGJ5IHRoZSBtdWx0aWtleS4gKElmIG5vbmUgbWF0Y2gsIHdlIHJldHVybiB1bmRlZmluZWQuXG4gICAgLy8gRWFjaCBlbGVtZW50IGNvbnRhaW5zIHRoZSBraWQsIHByb3RlY3RlZEhlYWRlciwgcG9zc2libHkgdW5wcm90ZWN0ZWRIZWFkZXIsIGFuZCBwb3NzaWJseSBwYXlsb2FkIChpLmUuIGlmIHN1Y2Nlc3NmdWwpLlxuICAgIC8vXG4gICAgLy8gQWRkaXRpb25hbGx5IGlmIGEgcmVzdWx0IGlzIHByb2R1Y2VkLCB0aGUgb3ZlcmFsbCBwcm90ZWN0ZWRIZWFkZXIgYW5kIHVucHJvdGVjdGVkSGVhZGVyIGNvbnRhaW5zIG9ubHkgdmFsdWVzXG4gICAgLy8gdGhhdCB3ZXJlIGNvbW1vbiB0byBlYWNoIG9mIHRoZSB2ZXJpZmllZCBzaWduYXR1cmUgZWxlbWVudHMuXG4gICAgXG4gICAgbGV0IGp3cyA9IHNpZ25hdHVyZSxcbiAgICAgICAga2lkcyA9IHRoaXMua2V5VGFncyhrZXkpLFxuICAgICAgICBzaWduZXJzID0gYXdhaXQgUHJvbWlzZS5hbGwoandzLnNpZ25hdHVyZXMubWFwKHNpZ25hdHVyZSA9PiB0aGlzLnZlcmlmeVN1YlNpZ25hdHVyZShqd3MsIHNpZ25hdHVyZSwga2V5LCBraWRzKSkpO1xuICAgIGlmICghc2lnbmVycy5maW5kKHNpZ25lciA9PiBzaWduZXIucGF5bG9hZCkpIHJldHVybiB1bmRlZmluZWQ7XG4gICAgLy8gTm93IGNhbm9uaWNhbGl6ZSB0aGUgc2lnbmVycyBhbmQgYnVpbGQgdXAgYSByZXN1bHQuXG4gICAgbGV0IFtmaXJzdCwgLi4ucmVzdF0gPSBzaWduZXJzLFxuICAgICAgICByZXN1bHQgPSB7cHJvdGVjdGVkSGVhZGVyOiB7fSwgdW5wcm90ZWN0ZWRIZWFkZXI6IHt9LCBzaWduZXJzfSxcbiAgICAgICAgLy8gRm9yIGEgaGVhZGVyIHZhbHVlIHRvIGJlIGNvbW1vbiB0byB2ZXJpZmllZCByZXN1bHRzLCBpdCBtdXN0IGJlIGluIHRoZSBmaXJzdCByZXN1bHQuXG4gICAgICAgIGdldFVuaXF1ZSA9IGNhdGVnb3J5TmFtZSA9PiB7XG4gICAgICAgICAgbGV0IGZpcnN0SGVhZGVyID0gZmlyc3RbY2F0ZWdvcnlOYW1lXSxcbiAgICAgICAgICAgICAgYWNjdW11bGF0b3JIZWFkZXIgPSByZXN1bHRbY2F0ZWdvcnlOYW1lXTtcbiAgICAgICAgICBmb3IgKGxldCBsYWJlbCBpbiBmaXJzdEhlYWRlcikge1xuICAgICAgICAgICAgbGV0IHZhbHVlID0gZmlyc3RIZWFkZXJbbGFiZWxdO1xuICAgICAgICAgICAgaWYgKHJlc3Quc29tZShzaWduZXJSZXN1bHQgPT4gc2lnbmVyUmVzdWx0W2NhdGVnb3J5TmFtZV1bbGFiZWxdICE9PSB2YWx1ZSkpIGNvbnRpbnVlO1xuICAgICAgICAgICAgYWNjdW11bGF0b3JIZWFkZXJbbGFiZWxdID0gdmFsdWU7XG4gICAgICAgICAgfVxuICAgICAgICB9O1xuICAgIGdldFVuaXF1ZSgncHJvdGVjdGVkSGVhZGVyJyk7XG4gICAgZ2V0VW5pcXVlKCdwcm90ZWN0ZWRIZWFkZXInKTtcbiAgICAvLyBJZiBhbnl0aGluZyB2ZXJpZmllZCwgdGhlbiBzZXQgcGF5bG9hZCBhbmQgYWxsb3cgdGV4dC9qc29uIHRvIGJlIHByb2R1Y2VkLlxuICAgIC8vIENhbGxlcnMgY2FuIGNoZWNrIHNpZ25lcnNbbl0ucGF5bG9hZCB0byBkZXRlcm1pbmUgaWYgdGhlIHJlc3VsdCBpcyB3aGF0IHRoZXkgd2FudC5cbiAgICByZXN1bHQucGF5bG9hZCA9IHNpZ25lcnMuZmluZChzaWduZXIgPT4gc2lnbmVyLnBheWxvYWQpLnBheWxvYWQ7XG4gICAgcmV0dXJuIHRoaXMucmVjb3ZlckRhdGFGcm9tQ29udGVudFR5cGUocmVzdWx0LCBvcHRpb25zKTtcbiAgfVxufTtcblxuT2JqZWN0LnNldFByb3RvdHlwZU9mKE11bHRpS3J5cHRvLCBLcnlwdG8pOyAvLyBJbmhlcml0IGZyb20gS3J5cHRvIHNvIHRoYXQgc3VwZXIubXVtYmxlKCkgd29ya3MuXG5leHBvcnQgZGVmYXVsdCBNdWx0aUtyeXB0bztcbiIsImNvbnN0IGRlZmF1bHRNYXhTaXplID0gNTAwO1xuZXhwb3J0IGNsYXNzIENhY2hlIGV4dGVuZHMgTWFwIHtcbiAgY29uc3RydWN0b3IobWF4U2l6ZSwgZGVmYXVsdFRpbWVUb0xpdmUgPSAwKSB7XG4gICAgc3VwZXIoKTtcbiAgICB0aGlzLm1heFNpemUgPSBtYXhTaXplO1xuICAgIHRoaXMuZGVmYXVsdFRpbWVUb0xpdmUgPSBkZWZhdWx0VGltZVRvTGl2ZTtcbiAgICB0aGlzLl9uZXh0V3JpdGVJbmRleCA9IDA7XG4gICAgdGhpcy5fa2V5TGlzdCA9IEFycmF5KG1heFNpemUpO1xuICAgIHRoaXMuX3RpbWVycyA9IG5ldyBNYXAoKTtcbiAgfVxuICBzZXQoa2V5LCB2YWx1ZSwgdHRsID0gdGhpcy5kZWZhdWx0VGltZVRvTGl2ZSkge1xuICAgIGxldCBuZXh0V3JpdGVJbmRleCA9IHRoaXMuX25leHRXcml0ZUluZGV4O1xuXG4gICAgLy8gbGVhc3QtcmVjZW50bHktU0VUIGJvb2trZWVwaW5nOlxuICAgIC8vICAga2V5TGlzdCBpcyBhbiBhcnJheSBvZiBrZXlzIHRoYXQgaGF2ZSBiZWVuIHNldC5cbiAgICAvLyAgIG5leHRXcml0ZUluZGV4IGlzIHdoZXJlIHRoZSBuZXh0IGtleSBpcyB0byBiZSB3cml0dGVuIGluIHRoYXQgYXJyYXksIHdyYXBwaW5nIGFyb3VuZC5cbiAgICAvLyBBcyBpdCB3cmFwcywgdGhlIGtleSBhdCBrZXlMaXN0W25leHRXcml0ZUluZGV4XSBpcyB0aGUgb2xkZXN0IHRoYXQgaGFzIGJlZW4gc2V0LlxuICAgIC8vIEhvd2V2ZXIsIHRoYXQga2V5IGFuZCBvdGhlcnMgbWF5IGhhdmUgYWxyZWFkeSBiZWVuIGRlbGV0ZWQuXG4gICAgLy8gVGhpcyBpbXBsZW1lbnRhdGlvbiBtYXhpbWl6ZXMgcmVhZCBzcGVlZCBmaXJzdCwgd3JpdGUgc3BlZWQgc2Vjb25kLCBhbmQgc2ltcGxpY2l0eS9jb3JyZWN0bmVzcyB0aGlyZC5cbiAgICAvLyBJdCBkb2VzIE5PVCB0cnkgdG8ga2VlcCB0aGUgbWF4aW11bSBudW1iZXIgb2YgdmFsdWVzIHByZXNlbnQuIFNvIGFzIGtleXMgZ2V0IG1hbnVhbGx5IGRlbGV0ZWQsIHRoZSBrZXlMaXN0XG4gICAgLy8gaXMgbm90IGFkanVzdGVkLCBhbmQgc28gdGhlcmUgd2lsbCBrZXlzIHByZXNlbnQgaW4gdGhlIGFycmF5IHRoYXQgZG8gbm90IGhhdmUgZW50cmllcyBpbiB0aGUgdmFsdWVzXG4gICAgLy8gbWFwLiBUaGUgYXJyYXkgaXMgbWF4U2l6ZSBsb25nLCBidXQgdGhlIG1lYW5pbmdmdWwgZW50cmllcyBpbiBpdCBtYXkgYmUgbGVzcy5cbiAgICB0aGlzLmRlbGV0ZSh0aGlzLl9rZXlMaXN0W25leHRXcml0ZUluZGV4XSk7IC8vIFJlZ2FyZGxlc3Mgb2YgY3VycmVudCBzaXplLlxuICAgIHRoaXMuX2tleUxpc3RbbmV4dFdyaXRlSW5kZXhdID0ga2V5O1xuICAgIHRoaXMuX25leHRXcml0ZUluZGV4ID0gKG5leHRXcml0ZUluZGV4ICsgMSkgJSB0aGlzLm1heFNpemU7XG5cbiAgICBpZiAodGhpcy5fdGltZXJzLmhhcyhrZXkpKSBjbGVhclRpbWVvdXQodGhpcy5fdGltZXJzLmdldChrZXkpKTtcbiAgICBzdXBlci5zZXQoa2V5LCB2YWx1ZSk7XG5cbiAgICBpZiAoIXR0bCkgcmV0dXJuOyAgLy8gU2V0IHRpbWVvdXQgaWYgcmVxdWlyZWQuXG4gICAgdGhpcy5fdGltZXJzLnNldChrZXksIHNldFRpbWVvdXQoKCkgPT4gdGhpcy5kZWxldGUoa2V5KSwgdHRsKSk7XG4gIH1cbiAgZGVsZXRlKGtleSkge1xuICAgIGlmICh0aGlzLl90aW1lcnMuaGFzKGtleSkpIGNsZWFyVGltZW91dCh0aGlzLl90aW1lcnMuZ2V0KGtleSkpO1xuICAgIHRoaXMuX3RpbWVycy5kZWxldGUoa2V5KTtcbiAgICByZXR1cm4gc3VwZXIuZGVsZXRlKGtleSk7XG4gIH1cbiAgY2xlYXIobmV3TWF4U2l6ZSA9IHRoaXMubWF4U2l6ZSkge1xuICAgIHRoaXMubWF4U2l6ZSA9IG5ld01heFNpemU7XG4gICAgdGhpcy5fa2V5TGlzdCA9IEFycmF5KG5ld01heFNpemUpO1xuICAgIHRoaXMuX25leHRXcml0ZUluZGV4ID0gMDtcbiAgICBzdXBlci5jbGVhcigpO1xuICAgIGZvciAoY29uc3QgdGltZXIgb2YgdGhpcy5fdGltZXJzLnZhbHVlcygpKSBjbGVhclRpbWVvdXQodGltZXIpXG4gICAgdGhpcy5fdGltZXJzLmNsZWFyKCk7XG4gIH1cbn07XG5leHBvcnQgZGVmYXVsdCBDYWNoZTtcbiIsImNsYXNzIENhY2hlIGV4dGVuZHMgTWFwe2NvbnN0cnVjdG9yKGUsdD0wKXtzdXBlcigpLHRoaXMubWF4U2l6ZT1lLHRoaXMuZGVmYXVsdFRpbWVUb0xpdmU9dCx0aGlzLl9uZXh0V3JpdGVJbmRleD0wLHRoaXMuX2tleUxpc3Q9QXJyYXkoZSksdGhpcy5fdGltZXJzPW5ldyBNYXB9c2V0KGUsdCxzPXRoaXMuZGVmYXVsdFRpbWVUb0xpdmUpe2xldCBpPXRoaXMuX25leHRXcml0ZUluZGV4O3RoaXMuZGVsZXRlKHRoaXMuX2tleUxpc3RbaV0pLHRoaXMuX2tleUxpc3RbaV09ZSx0aGlzLl9uZXh0V3JpdGVJbmRleD0oaSsxKSV0aGlzLm1heFNpemUsdGhpcy5fdGltZXJzLmhhcyhlKSYmY2xlYXJUaW1lb3V0KHRoaXMuX3RpbWVycy5nZXQoZSkpLHN1cGVyLnNldChlLHQpLHMmJnRoaXMuX3RpbWVycy5zZXQoZSxzZXRUaW1lb3V0KCgoKT0+dGhpcy5kZWxldGUoZSkpLHMpKX1kZWxldGUoZSl7cmV0dXJuIHRoaXMuX3RpbWVycy5oYXMoZSkmJmNsZWFyVGltZW91dCh0aGlzLl90aW1lcnMuZ2V0KGUpKSx0aGlzLl90aW1lcnMuZGVsZXRlKGUpLHN1cGVyLmRlbGV0ZShlKX1jbGVhcihlPXRoaXMubWF4U2l6ZSl7dGhpcy5tYXhTaXplPWUsdGhpcy5fa2V5TGlzdD1BcnJheShlKSx0aGlzLl9uZXh0V3JpdGVJbmRleD0wLHN1cGVyLmNsZWFyKCk7Zm9yKGNvbnN0IGUgb2YgdGhpcy5fdGltZXJzLnZhbHVlcygpKWNsZWFyVGltZW91dChlKTt0aGlzLl90aW1lcnMuY2xlYXIoKX19Y2xhc3MgU3RvcmFnZUJhc2V7Y29uc3RydWN0b3Ioe25hbWU6ZSxiYXNlTmFtZTp0PVwiU3RvcmFnZVwiLG1heFNlcmlhbGl6ZXJTaXplOnM9MWUzLGRlYnVnOmk9ITF9KXtjb25zdCBhPWAke3R9LyR7ZX1gLHI9bmV3IENhY2hlKHMpO09iamVjdC5hc3NpZ24odGhpcyx7bmFtZTplLGJhc2VOYW1lOnQsZnVsbE5hbWU6YSxkZWJ1ZzppLHNlcmlhbGl6ZXI6cn0pfWFzeW5jIGxpc3QoKXtyZXR1cm4gdGhpcy5zZXJpYWxpemUoXCJcIiwoKGUsdCk9PnRoaXMubGlzdEludGVybmFsKHQsZSkpKX1hc3luYyBnZXQoZSl7cmV0dXJuIHRoaXMuc2VyaWFsaXplKGUsKChlLHQpPT50aGlzLmdldEludGVybmFsKHQsZSkpKX1hc3luYyBkZWxldGUoZSl7cmV0dXJuIHRoaXMuc2VyaWFsaXplKGUsKChlLHQpPT50aGlzLmRlbGV0ZUludGVybmFsKHQsZSkpKX1hc3luYyBwdXQoZSx0KXtyZXR1cm4gdGhpcy5zZXJpYWxpemUoZSwoKGUscyk9PnRoaXMucHV0SW50ZXJuYWwocyx0LGUpKSl9bG9nKC4uLmUpe3RoaXMuZGVidWcmJmNvbnNvbGUubG9nKHRoaXMubmFtZSwuLi5lKX1hc3luYyBzZXJpYWxpemUoZSx0KXtjb25zdHtzZXJpYWxpemVyOnMscmVhZHk6aX09dGhpcztsZXQgYT1zLmdldChlKXx8aTtyZXR1cm4gYT1hLnRoZW4oKGFzeW5jKCk9PnQoYXdhaXQgdGhpcy5yZWFkeSx0aGlzLnBhdGgoZSkpKSkscy5zZXQoZSxhKSxhd2FpdCBhfX1jb25zdHtSZXNwb25zZTplLFVSTDp0fT1nbG9iYWxUaGlzO2NsYXNzIFN0b3JhZ2VDYWNoZSBleHRlbmRzIFN0b3JhZ2VCYXNle2NvbnN0cnVjdG9yKC4uLmUpe3N1cGVyKC4uLmUpLHRoaXMuc3RyaXBwZXI9bmV3IFJlZ0V4cChgXi8ke3RoaXMuZnVsbE5hbWV9L2ApLHRoaXMucmVhZHk9Y2FjaGVzLm9wZW4odGhpcy5mdWxsTmFtZSl9YXN5bmMgbGlzdEludGVybmFsKGUsdCl7cmV0dXJuKGF3YWl0IHQua2V5cygpfHxbXSkubWFwKChlPT50aGlzLnRhZyhlLnVybCkpKX1hc3luYyBnZXRJbnRlcm5hbChlLHQpe2NvbnN0IHM9YXdhaXQgdC5tYXRjaChlKTtyZXR1cm4gcz8uanNvbigpfWRlbGV0ZUludGVybmFsKGUsdCl7cmV0dXJuIHQuZGVsZXRlKGUpfXB1dEludGVybmFsKHQscyxpKXtyZXR1cm4gaS5wdXQodCxlLmpzb24ocykpfXBhdGgoZSl7cmV0dXJuYC8ke3RoaXMuZnVsbE5hbWV9LyR7ZX1gfXRhZyhlKXtyZXR1cm4gbmV3IHQoZSkucGF0aG5hbWUucmVwbGFjZSh0aGlzLnN0cmlwcGVyLFwiXCIpfWRlc3Ryb3koKXtyZXR1cm4gY2FjaGVzLmRlbGV0ZSh0aGlzLmZ1bGxOYW1lKX19ZXhwb3J0e1N0b3JhZ2VDYWNoZSBhcyBTdG9yYWdlTG9jYWwsU3RvcmFnZUNhY2hlIGFzIGRlZmF1bHR9O1xuIiwidmFyIHByb21wdGVyID0gcHJvbXB0U3RyaW5nID0+IHByb21wdFN0cmluZztcbmlmICh0eXBlb2Yod2luZG93KSAhPT0gJ3VuZGVmaW5lZCcpIHtcbiAgcHJvbXB0ZXIgPSB3aW5kb3cucHJvbXB0O1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZ2V0VXNlckRldmljZVNlY3JldCh0YWcsIHByb21wdFN0cmluZykge1xuICByZXR1cm4gcHJvbXB0U3RyaW5nID8gKHRhZyArIHByb21wdGVyKHByb21wdFN0cmluZykpIDogdGFnO1xufVxuIiwiY29uc3Qgb3JpZ2luID0gbmV3IFVSTChpbXBvcnQubWV0YS51cmwpLm9yaWdpbjtcbmV4cG9ydCBkZWZhdWx0IG9yaWdpbjtcbiIsImV4cG9ydCBmdW5jdGlvbiB0YWdQYXRoKGNvbGxlY3Rpb25OYW1lLCB0YWcsIGV4dGVuc2lvbiA9ICdqc29uJykgeyAvLyBQYXRobmFtZSB0byB0YWcgcmVzb3VyY2UuXG4gIC8vIFVzZWQgaW4gU3RvcmFnZSBVUkkuIEJvdHRsZW5lY2tlZCBoZXJlIHRvIHByb3ZpZGUgY29uc2lzdGVudCBhbHRlcm5hdGUgaW1wbGVtZW50YXRpb25zLlxuICAvLyBQYXRoIGlzIC5qc29uIHNvIHRoYXQgc3RhdGljLWZpbGUgd2ViIHNlcnZlcnMgd2lsbCBzdXBwbHkgYSBqc29uIG1pbWUgdHlwZS5cbiAgLy9cbiAgLy8gTk9URTogY2hhbmdlcyBoZXJlIG11c3QgYmUgbWF0Y2hlZCBieSB0aGUgUFVUIHJvdXRlIHNwZWNpZmllZCBpbiBzaWduZWQtY2xvdWQtc2VydmVyL3N0b3JhZ2UubWpzIGFuZCB0YWdOYW1lLm1qc1xuICBpZiAoIXRhZykgcmV0dXJuIGNvbGxlY3Rpb25OYW1lO1xuICByZXR1cm4gYCR7Y29sbGVjdGlvbk5hbWV9LyR7dGFnfS4ke2V4dGVuc2lvbn1gO1xufVxuIiwiaW1wb3J0IG9yaWdpbiBmcm9tICcjb3JpZ2luJzsgLy8gV2hlbiBydW5uaW5nIGluIGEgYnJvd3NlciwgbG9jYXRpb24ub3JpZ2luIHdpbGwgYmUgZGVmaW5lZC4gSGVyZSB3ZSBhbGxvdyBmb3IgTm9kZUpTLlxuaW1wb3J0IHt0YWdQYXRofSBmcm9tICcuL3RhZ1BhdGgubWpzJztcblxuYXN5bmMgZnVuY3Rpb24gcmVzcG9uc2VIYW5kbGVyKHJlc3BvbnNlKSB7XG4gIC8vIFJlamVjdCBpZiBzZXJ2ZXIgZG9lcywgZWxzZSByZXNwb25zZS50ZXh0KCkuXG4gIGlmIChyZXNwb25zZS5zdGF0dXMgPT09IDQwNCkgcmV0dXJuICcnO1xuICBpZiAoIXJlc3BvbnNlLm9rKSByZXR1cm4gUHJvbWlzZS5yZWplY3QocmVzcG9uc2Uuc3RhdHVzVGV4dCk7XG4gIGxldCB0ZXh0ID0gYXdhaXQgcmVzcG9uc2UudGV4dCgpO1xuICBpZiAoIXRleHQpIHJldHVybiB0ZXh0OyAvLyBSZXN1bHQgb2Ygc3RvcmUgY2FuIGJlIGVtcHR5LlxuICByZXR1cm4gSlNPTi5wYXJzZSh0ZXh0KTtcbn1cblxuY29uc3QgU3RvcmFnZSA9IHtcbiAgZ2V0IG9yaWdpbigpIHsgcmV0dXJuIG9yaWdpbjsgfSxcbiAgdGFnUGF0aCxcbiAgdXJpKGNvbGxlY3Rpb25OYW1lLCB0YWcpIHtcbiAgICAvLyBQYXRobmFtZSBleHBlY3RlZCBieSBvdXIgc2lnbmVkLWNsb3VkLXNlcnZlci5cbiAgICByZXR1cm4gYCR7b3JpZ2lufS9TdG9yYWdlLyR7dGhpcy50YWdQYXRoKGNvbGxlY3Rpb25OYW1lLCB0YWcpfWA7XG4gIH0sXG4gIHN0b3JlKGNvbGxlY3Rpb25OYW1lLCB0YWcsIHNpZ25hdHVyZSwgb3B0aW9ucyA9IHt9KSB7XG4gICAgLy8gU3RvcmUgdGhlIHNpZ25lZCBjb250ZW50IG9uIHRoZSBzaWduZWQtY2xvdWQtc2VydmVyLCByZWplY3RpbmcgaWZcbiAgICAvLyB0aGUgc2VydmVyIGlzIHVuYWJsZSB0byB2ZXJpZnkgdGhlIHNpZ25hdHVyZSBmb2xsb3dpbmcgdGhlIHJ1bGVzIG9mXG4gICAgLy8gaHR0cHM6Ly9raWxyb3ktY29kZS5naXRodWIuaW8vZGlzdHJpYnV0ZWQtc2VjdXJpdHkvI3N0b3Jpbmcta2V5cy11c2luZy10aGUtY2xvdWQtc3RvcmFnZS1hcGlcbiAgICByZXR1cm4gZmV0Y2godGhpcy51cmkoY29sbGVjdGlvbk5hbWUsIHRhZyksIHtcbiAgICAgIG1ldGhvZDogJ1BVVCcsXG4gICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShzaWduYXR1cmUpLFxuICAgICAgaGVhZGVyczogeydDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsIC4uLihvcHRpb25zLmhlYWRlcnMgfHwge30pfVxuICAgIH0pLnRoZW4ocmVzcG9uc2VIYW5kbGVyKTtcbiAgfSxcbiAgcmV0cmlldmUoY29sbGVjdGlvbk5hbWUsIHRhZywgb3B0aW9ucyA9IHt9KSB7XG4gICAgLy8gV2UgZG8gbm90IHZlcmlmeSBhbmQgZ2V0IHRoZSBvcmlnaW5hbCBkYXRhIG91dCBoZXJlLCBiZWNhdXNlIHRoZSBjYWxsZXIgaGFzXG4gICAgLy8gdGhlIHJpZ2h0IHRvIGRvIHNvIHdpdGhvdXQgdHJ1c3RpbmcgdXMuXG4gICAgcmV0dXJuIGZldGNoKHRoaXMudXJpKGNvbGxlY3Rpb25OYW1lLCB0YWcpLCB7XG4gICAgICBjYWNoZTogJ2RlZmF1bHQnLFxuICAgICAgaGVhZGVyczogeydBY2NlcHQnOiAnYXBwbGljYXRpb24vanNvbicsIC4uLihvcHRpb25zLmhlYWRlcnMgfHwge30pfVxuICAgIH0pLnRoZW4ocmVzcG9uc2VIYW5kbGVyKTtcbiAgfVxufTtcbmV4cG9ydCBkZWZhdWx0IFN0b3JhZ2U7XG4iLCJpbXBvcnQgQ2FjaGUgZnJvbSAnQGtpMXIweS9jYWNoZSc7XG5pbXBvcnQgU3RvcmFnZUxvY2FsIGZyb20gJ0BraTFyMHkvc3RvcmFnZSc7XG5pbXBvcnQge2hhc2hCdWZmZXIsIGVuY29kZUJhc2U2NHVybH0gZnJvbSAnLi91dGlsaXRpZXMubWpzJztcbmltcG9ydCBNdWx0aUtyeXB0byBmcm9tICcuL211bHRpS3J5cHRvLm1qcyc7XG5pbXBvcnQge2dldFVzZXJEZXZpY2VTZWNyZXR9IGZyb20gJy4vc2VjcmV0Lm1qcyc7XG5pbXBvcnQgU3RvcmFnZSBmcm9tICcuL3N0b3JhZ2UubWpzJztcblxuZnVuY3Rpb24gZXJyb3IodGVtcGxhdGVGdW5jdGlvbiwgdGFnLCBjYXVzZSA9IHVuZGVmaW5lZCkge1xuICAvLyBGb3JtYXRzIHRhZyAoZS5nLiwgc2hvcnRlbnMgaXQpIGFuZCBnaXZlcyBpdCB0byB0ZW1wbGF0ZUZ1bmN0aW9uKHRhZykgdG8gZ2V0XG4gIC8vIGEgc3VpdGFibGUgZXJyb3IgbWVzc2FnZS4gQW5zd2VycyBhIHJlamVjdGVkIHByb21pc2Ugd2l0aCB0aGF0IEVycm9yLlxuICBsZXQgc2hvcnRlbmVkVGFnID0gdGFnID8gdGFnLnNsaWNlKDAsIDE2KSArIFwiLi4uXCIgOiAnPGVtcHR5IHRhZz4nLFxuICAgICAgbWVzc2FnZSA9IHRlbXBsYXRlRnVuY3Rpb24oc2hvcnRlbmVkVGFnKTtcbiAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBFcnJvcihtZXNzYWdlLCB7Y2F1c2V9KSk7XG59XG5mdW5jdGlvbiB1bmF2YWlsYWJsZSh0YWcsIG9wZXJhdGlvbikge1xuICByZXR1cm4gZXJyb3IodGFnID0+IGBUaGUgJHtvcGVyYXRpb259IHRhZyAke3RhZ30gaXMgbm90IGF2YWlsYWJsZS5gLCB0YWcpO1xufVxuXG5leHBvcnQgY2xhc3MgS2V5U2V0IHtcbiAgLy8gQSBLZXlTZXQgbWFpbnRhaW5zIHR3byBwcml2YXRlIGtleXM6IHNpZ25pbmdLZXkgYW5kIGRlY3J5cHRpbmdLZXkuXG4gIC8vIFNlZSBodHRwczovL2tpbHJveS1jb2RlLmdpdGh1Yi5pby9kaXN0cmlidXRlZC1zZWN1cml0eS9kb2NzL2ltcGxlbWVudGF0aW9uLmh0bWwjd2ViLXdvcmtlci1hbmQtaWZyYW1lXG5cbiAgLy8gQ2FjaGluZ1xuICBzdGF0aWMga2V5U2V0cyA9IG5ldyBDYWNoZSg1MDAsIDYwICogNjAgKiAxZTMpO1xuICBzdGF0aWMgY2FjaGVkKHRhZykgeyAvLyBSZXR1cm4gYW4gYWxyZWFkeSBwb3B1bGF0ZWQgS2V5U2V0LlxuICAgIHJldHVybiBLZXlTZXQua2V5U2V0cy5nZXQodGFnKTtcbiAgfVxuICBzdGF0aWMgY2FjaGUodGFnLCBrZXlTZXQpIHsgLy8gS2VlcCB0cmFjayBvZiByZWNlbnQga2V5U2V0cy5cbiAgICBLZXlTZXQua2V5U2V0cy5zZXQodGFnLCBrZXlTZXQpO1xuICB9XG4gIHN0YXRpYyBjbGVhcih0YWcgPSBudWxsKSB7IC8vIFJlbW92ZSBhbGwgS2V5U2V0IGluc3RhbmNlcyBvciBqdXN0IHRoZSBzcGVjaWZpZWQgb25lLCBidXQgZG9lcyBub3QgZGVzdHJveSB0aGVpciBzdG9yYWdlLlxuICAgIGlmICghdGFnKSByZXR1cm4gS2V5U2V0LmtleVNldHMuY2xlYXIoKTtcbiAgICByZXR1cm4gS2V5U2V0LmtleVNldHMuZGVsZXRlKHRhZyk7XG4gIH1cbiAgY29uc3RydWN0b3IodGFnKSB7XG4gICAgdGhpcy50YWcgPSB0YWc7XG4gICAgdGhpcy5tZW1iZXJUYWdzID0gW107IC8vIFVzZWQgd2hlbiByZWN1cnNpdmVseSBkZXN0cm95aW5nLlxuICAgIEtleVNldC5jYWNoZSh0YWcsIHRoaXMpO1xuICB9XG4gIC8vIGFwaS5tanMgcHJvdmlkZXMgdGhlIHNldHRlciB0byBjaGFuZ2VzIHRoZXNlLCBhbmQgd29ya2VyLm1qcyBleGVyY2lzZXMgaXQgaW4gYnJvd3NlcnMuXG4gIHN0YXRpYyBnZXRVc2VyRGV2aWNlU2VjcmV0ID0gZ2V0VXNlckRldmljZVNlY3JldDtcbiAgc3RhdGljIFN0b3JhZ2UgPSBTdG9yYWdlO1xuXG4gIC8vIFByaW5jaXBsZSBvcGVyYXRpb25zLlxuICBzdGF0aWMgYXN5bmMgY3JlYXRlKHdyYXBwaW5nRGF0YSkgeyAvLyBDcmVhdGUgYSBwZXJzaXN0ZWQgS2V5U2V0IG9mIHRoZSBjb3JyZWN0IHR5cGUsIHByb21pc2luZyB0aGUgbmV3bHkgY3JlYXRlZCB0YWcuXG4gICAgLy8gTm90ZSB0aGF0IGNyZWF0aW5nIGEgS2V5U2V0IGRvZXMgbm90IGluc3RhbnRpYXRlIGl0LlxuICAgIGxldCB7dGltZSwgLi4ua2V5c30gPSBhd2FpdCB0aGlzLmNyZWF0ZUtleXMod3JhcHBpbmdEYXRhKSxcbiAgICAgICAge3RhZ30gPSBrZXlzO1xuICAgIGF3YWl0IHRoaXMucGVyc2lzdCh0YWcsIGtleXMsIHdyYXBwaW5nRGF0YSwgdGltZSk7XG4gICAgcmV0dXJuIHRhZztcbiAgfVxuICBhc3luYyBkZXN0cm95KG9wdGlvbnMgPSB7fSkgeyAvLyBUZXJtaW5hdGVzIHRoaXMga2V5U2V0IGFuZCBhc3NvY2lhdGVkIHN0b3JhZ2UsIGFuZCBzYW1lIGZvciBPV05FRCByZWN1cnNpdmVNZW1iZXJzIGlmIGFza2VkLlxuICAgIGxldCB7dGFnLCBtZW1iZXJUYWdzLCBzaWduaW5nS2V5fSA9IHRoaXMsXG4gICAgICAgIGNvbnRlbnQgPSBcIlwiLCAvLyBTaG91bGQgc3RvcmFnZSBoYXZlIGEgc2VwYXJhdGUgb3BlcmF0aW9uIHRvIGRlbGV0ZSwgb3RoZXIgdGhhbiBzdG9yaW5nIGVtcHR5P1xuICAgICAgICBzaWduYXR1cmUgPSBhd2FpdCB0aGlzLmNvbnN0cnVjdG9yLnNpZ25Gb3JTdG9yYWdlKHsuLi5vcHRpb25zLCBtZXNzYWdlOiBjb250ZW50LCB0YWcsIG1lbWJlclRhZ3MsIHNpZ25pbmdLZXksIHRpbWU6IERhdGUubm93KCksIHJlY292ZXJ5OiB0cnVlfSk7XG4gICAgYXdhaXQgdGhpcy5jb25zdHJ1Y3Rvci5zdG9yZSgnRW5jcnlwdGlvbktleScsIHRhZywgc2lnbmF0dXJlKTtcbiAgICBhd2FpdCB0aGlzLmNvbnN0cnVjdG9yLnN0b3JlKHRoaXMuY29uc3RydWN0b3IuY29sbGVjdGlvbiwgdGFnLCBzaWduYXR1cmUpO1xuICAgIHRoaXMuY29uc3RydWN0b3IuY2xlYXIodGFnKTtcbiAgICBpZiAoIW9wdGlvbnMucmVjdXJzaXZlTWVtYmVycykgcmV0dXJuO1xuICAgIGF3YWl0IFByb21pc2UuYWxsU2V0dGxlZCh0aGlzLm1lbWJlclRhZ3MubWFwKGFzeW5jIG1lbWJlclRhZyA9PiB7XG4gICAgICBsZXQgbWVtYmVyS2V5U2V0ID0gYXdhaXQgS2V5U2V0LmVuc3VyZShtZW1iZXJUYWcsIHsuLi5vcHRpb25zLCByZWNvdmVyeTogdHJ1ZX0pO1xuICAgICAgYXdhaXQgbWVtYmVyS2V5U2V0LmRlc3Ryb3kob3B0aW9ucyk7XG4gICAgfSkpO1xuICB9XG4gIGRlY3J5cHQoZW5jcnlwdGVkLCBvcHRpb25zKSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259IGFzIGFwcHJvcHJpYXRlLlxuICAgIGxldCB7dGFnLCBkZWNyeXB0aW5nS2V5fSA9IHRoaXMsXG4gICAgICAgIGtleSA9IGVuY3J5cHRlZC5yZWNpcGllbnRzID8ge1t0YWddOiBkZWNyeXB0aW5nS2V5fSA6IGRlY3J5cHRpbmdLZXk7XG4gICAgcmV0dXJuIE11bHRpS3J5cHRvLmRlY3J5cHQoa2V5LCBlbmNyeXB0ZWQsIG9wdGlvbnMpO1xuICB9XG4gIC8vIHNpZ24gYXMgZWl0aGVyIGNvbXBhY3Qgb3IgbXVsdGlLZXkgZ2VuZXJhbCBKV1MuXG4gIC8vIFRoZXJlJ3Mgc29tZSBjb21wbGV4aXR5IGhlcmUgYXJvdW5kIGJlaW5nIGFibGUgdG8gcGFzcyBpbiBtZW1iZXJUYWdzIGFuZCBzaWduaW5nS2V5IHdoZW4gdGhlIGtleVNldCBpc1xuICAvLyBiZWluZyBjcmVhdGVkIGFuZCBkb2Vzbid0IHlldCBleGlzdC5cbiAgc3RhdGljIGFzeW5jIHNpZ24obWVzc2FnZSwge3RhZ3MgPSBbXSxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHRlYW06aXNzLCBtZW1iZXI6YWN0LFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3ViamVjdDpzdWIgPSAnaGFzaCcsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0aW1lOmlhdCA9IGlzcyAmJiBEYXRlLm5vdygpLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbWVtYmVyVGFncywgc2lnbmluZ0tleSwgcmVjb3ZlcnksXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAuLi5vcHRpb25zfSkge1xuICAgIGlmIChpc3MgJiYgIWFjdCkgeyAvLyBTdXBwbHkgdGhlIHZhbHVlXG4gICAgICBpZiAoIW1lbWJlclRhZ3MpIG1lbWJlclRhZ3MgPSAoYXdhaXQgS2V5U2V0LmVuc3VyZShpc3MpKS5tZW1iZXJUYWdzO1xuICAgICAgbGV0IGNhY2hlZE1lbWJlciA9IG1lbWJlclRhZ3MuZmluZCh0YWcgPT4gdGhpcy5jYWNoZWQodGFnKSk7XG4gICAgICBhY3QgPSBjYWNoZWRNZW1iZXIgfHwgYXdhaXQgdGhpcy5lbnN1cmUxKG1lbWJlclRhZ3MpLnRoZW4oa2V5U2V0ID0+IGtleVNldC50YWcpO1xuICAgIH1cbiAgICBpZiAoaXNzICYmICF0YWdzLmluY2x1ZGVzKGlzcykpIHRhZ3MgPSBbaXNzLCAuLi50YWdzXTsgLy8gTXVzdCBiZSBmaXJzdFxuICAgIGlmIChhY3QgJiYgIXRhZ3MuaW5jbHVkZXMoYWN0KSkgdGFncyA9IFsuLi50YWdzLCBhY3RdO1xuXG4gICAgbGV0IGtleSA9IGF3YWl0IHRoaXMucHJvZHVjZUtleSh0YWdzLCBhc3luYyB0YWcgPT4ge1xuICAgICAgLy8gVXNlIHNwZWNpZmllZCBzaWduaW5nS2V5IChpZiBhbnkpIGZvciB0aGUgZmlyc3Qgb25lLlxuICAgICAgbGV0IGtleSA9IHNpZ25pbmdLZXkgfHwgKGF3YWl0IEtleVNldC5lbnN1cmUodGFnLCB7cmVjb3ZlcnksIC4uLm9wdGlvbnN9KSkuc2lnbmluZ0tleTtcbiAgICAgIHNpZ25pbmdLZXkgPSBudWxsO1xuICAgICAgcmV0dXJuIGtleTtcbiAgICB9LCBvcHRpb25zKSxcbiAgICAgICAgbWVzc2FnZUJ1ZmZlciA9IE11bHRpS3J5cHRvLmlucHV0QnVmZmVyKG1lc3NhZ2UsIG9wdGlvbnMpO1xuICAgIGlmIChzdWIgPT09ICdoYXNoJykge1xuICAgICAgY29uc3QgaGFzaCA9IGF3YWl0IGhhc2hCdWZmZXIobWVzc2FnZUJ1ZmZlcik7XG4gICAgICBzdWIgPSBhd2FpdCBlbmNvZGVCYXNlNjR1cmwoaGFzaCk7XG4gICAgfSBlbHNlIGlmICghc3ViKSB7XG4gICAgICBzdWIgPSB1bmRlZmluZWQ7XG4gICAgfVxuICAgIHJldHVybiBNdWx0aUtyeXB0by5zaWduKGtleSwgbWVzc2FnZUJ1ZmZlciwge2lzcywgYWN0LCBpYXQsIHN1YiwgLi4ub3B0aW9uc30pO1xuICB9XG5cbiAgLy8gVmVyaWZ5IGluIHRoZSBub3JtYWwgd2F5LCBhbmQgdGhlbiBjaGVjayBkZWVwbHkgaWYgYXNrZWQuXG4gIHN0YXRpYyBhc3luYyB2ZXJpZnkoc2lnbmF0dXJlLCB0YWdzLCBvcHRpb25zKSB7XG4gICAgbGV0IGlzQ29tcGFjdCA9ICFzaWduYXR1cmUuc2lnbmF0dXJlcyxcbiAgICAgICAga2V5ID0gYXdhaXQgdGhpcy5wcm9kdWNlS2V5KHRhZ3MsIHRhZyA9PiBLZXlTZXQudmVyaWZ5aW5nS2V5KHRhZyksIG9wdGlvbnMsIGlzQ29tcGFjdCksXG4gICAgICAgIHJlc3VsdCA9IGF3YWl0IE11bHRpS3J5cHRvLnZlcmlmeShrZXksIHNpZ25hdHVyZSwgb3B0aW9ucyksXG4gICAgICAgIG1lbWJlclRhZyA9IG9wdGlvbnMubWVtYmVyID09PSB1bmRlZmluZWQgPyByZXN1bHQ/LnByb3RlY3RlZEhlYWRlci5hY3QgOiBvcHRpb25zLm1lbWJlcixcbiAgICAgICAgbm90QmVmb3JlID0gb3B0aW9ucy5ub3RCZWZvcmU7XG4gICAgZnVuY3Rpb24gZXhpdChsYWJlbCkge1xuICAgICAgaWYgKG9wdGlvbnMuaGFyZEVycm9yKSByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IEVycm9yKGxhYmVsKSk7XG4gICAgfVxuICAgIGlmICghcmVzdWx0KSByZXR1cm4gZXhpdCgnSW5jb3JyZWN0IHNpZ25hdHVyZS4nKTtcbiAgICBpZiAobWVtYmVyVGFnKSB7XG4gICAgICBpZiAob3B0aW9ucy5tZW1iZXIgPT09ICd0ZWFtJykge1xuICAgICAgICBtZW1iZXJUYWcgPSByZXN1bHQucHJvdGVjdGVkSGVhZGVyLmFjdDtcbiAgICAgICAgaWYgKCFtZW1iZXJUYWcpIHJldHVybiBleGl0KCdObyBtZW1iZXIgaWRlbnRpZmllZCBpbiBzaWduYXR1cmUuJyk7XG4gICAgICB9XG4gICAgICBpZiAoIXRhZ3MuaW5jbHVkZXMobWVtYmVyVGFnKSkgeyAvLyBBZGQgdG8gdGFncyBhbmQgcmVzdWx0IGlmIG5vdCBhbHJlYWR5IHByZXNlbnRcbiAgICAgICAgbGV0IG1lbWJlcktleSA9IGF3YWl0IEtleVNldC52ZXJpZnlpbmdLZXkobWVtYmVyVGFnKSxcbiAgICAgICAgICAgIG1lbWJlck11bHRpa2V5ID0ge1ttZW1iZXJUYWddOiBtZW1iZXJLZXl9LFxuICAgICAgICAgICAgYXV4ID0gYXdhaXQgTXVsdGlLcnlwdG8udmVyaWZ5KG1lbWJlck11bHRpa2V5LCBzaWduYXR1cmUsIG9wdGlvbnMpO1xuICAgICAgICBpZiAoIWF1eCkgcmV0dXJuIGV4aXQoJ0luY29ycmVjdCBtZW1iZXIgc2lnbmF0dXJlLicpO1xuICAgICAgICB0YWdzLnB1c2gobWVtYmVyVGFnKTtcbiAgICAgICAgcmVzdWx0LnNpZ25lcnMuZmluZChzaWduZXIgPT4gc2lnbmVyLnByb3RlY3RlZEhlYWRlci5raWQgPT09IG1lbWJlclRhZykucGF5bG9hZCA9IHJlc3VsdC5wYXlsb2FkO1xuICAgICAgfVxuICAgIH1cbiAgICBpZiAobWVtYmVyVGFnIHx8IG5vdEJlZm9yZSA9PT0gJ3RlYW0nKSB7XG4gICAgICBsZXQgdGVhbVRhZyA9IHJlc3VsdC5wcm90ZWN0ZWRIZWFkZXIuaXNzIHx8IHJlc3VsdC5wcm90ZWN0ZWRIZWFkZXIua2lkLCAvLyBNdWx0aSBvciBzaW5nbGUgY2FzZS5cbiAgICAgICAgICB2ZXJpZmllZEpXUyA9IGF3YWl0IHRoaXMucmV0cmlldmUoVGVhbUtleVNldC5jb2xsZWN0aW9uLCB0ZWFtVGFnKSxcbiAgICAgICAgICBqd2UgPSB2ZXJpZmllZEpXUz8uanNvbjtcbiAgICAgIGlmIChtZW1iZXJUYWcgJiYgIXRlYW1UYWcpIHJldHVybiBleGl0KCdObyB0ZWFtIG9yIG1haW4gdGFnIGlkZW50aWZpZWQgaW4gc2lnbmF0dXJlJyk7XG4gICAgICBpZiAobWVtYmVyVGFnICYmIGp3ZSAmJiAhandlLnJlY2lwaWVudHMuZmluZChtZW1iZXIgPT4gbWVtYmVyLmhlYWRlci5raWQgPT09IG1lbWJlclRhZykpIHJldHVybiBleGl0KCdTaWduZXIgaXMgbm90IGEgbWVtYmVyLicpO1xuICAgICAgaWYgKG5vdEJlZm9yZSA9PT0gJ3RlYW0nKSBub3RCZWZvcmUgPSB2ZXJpZmllZEpXUz8ucHJvdGVjdGVkSGVhZGVyLmlhdFxuICAgICAgICB8fCAoYXdhaXQgdGhpcy5yZXRyaWV2ZSgnRW5jcnlwdGlvbktleScsIHRlYW1UYWcsICdmb3JjZScpKT8ucHJvdGVjdGVkSGVhZGVyLmlhdDtcbiAgICB9XG4gICAgaWYgKG5vdEJlZm9yZSkge1xuICAgICAgbGV0IHtpYXR9ID0gcmVzdWx0LnByb3RlY3RlZEhlYWRlcjtcbiAgICAgIGlmIChpYXQgPCBub3RCZWZvcmUpIHJldHVybiBleGl0KCdTaWduYXR1cmUgcHJlZGF0ZXMgcmVxdWlyZWQgdGltZXN0YW1wLicpO1xuICAgIH1cbiAgICAvLyBFYWNoIHNpZ25lciBzaG91bGQgbm93IGJlIHZlcmlmaWVkLlxuICAgIGlmICgocmVzdWx0LnNpZ25lcnM/LmZpbHRlcihzaWduZXIgPT4gc2lnbmVyLnBheWxvYWQpLmxlbmd0aCB8fCAxKSAhPT0gdGFncy5sZW5ndGgpIHJldHVybiBleGl0KCdVbnZlcmlmaWVkIHNpZ25lcicpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICAvLyBLZXkgbWFuYWdlbWVudFxuICBzdGF0aWMgYXN5bmMgcHJvZHVjZUtleSh0YWdzLCBwcm9kdWNlciwgb3B0aW9ucywgdXNlU2luZ2xlS2V5ID0gdGFncy5sZW5ndGggPT09IDEpIHtcbiAgICAvLyBQcm9taXNlIGEga2V5IG9yIG11bHRpS2V5LCBhcyBkZWZpbmVkIGJ5IHByb2R1Y2VyKHRhZykgZm9yIGVhY2gga2V5LlxuICAgIGlmICh1c2VTaW5nbGVLZXkpIHtcbiAgICAgIGxldCB0YWcgPSB0YWdzWzBdO1xuICAgICAgb3B0aW9ucy5raWQgPSB0YWc7ICAgLy8gQmFzaGVzIG9wdGlvbnMgaW4gdGhlIHNpbmdsZS1rZXkgY2FzZSwgYmVjYXVzZSBtdWx0aUtleSdzIGhhdmUgdGhlaXIgb3duLlxuICAgICAgcmV0dXJuIHByb2R1Y2VyKHRhZyk7XG4gICAgfVxuICAgIGxldCBrZXkgPSB7fSxcbiAgICAgICAga2V5cyA9IGF3YWl0IFByb21pc2UuYWxsKHRhZ3MubWFwKHRhZyA9PiBwcm9kdWNlcih0YWcpKSk7XG4gICAgLy8gVGhpcyBpc24ndCBkb25lIGluIG9uZSBzdGVwLCBiZWNhdXNlIHdlJ2QgbGlrZSAoZm9yIGRlYnVnZ2luZyBhbmQgdW5pdCB0ZXN0cykgdG8gbWFpbnRhaW4gYSBwcmVkaWN0YWJsZSBvcmRlci5cbiAgICB0YWdzLmZvckVhY2goKHRhZywgaW5kZXgpID0+IGtleVt0YWddID0ga2V5c1tpbmRleF0pO1xuICAgIHJldHVybiBrZXk7XG4gIH1cbiAgLy8gVGhlIGNvcnJlc3BvbmRpbmcgcHVibGljIGtleXMgYXJlIGF2YWlsYWJsZSBwdWJsaWNhbGx5LCBvdXRzaWRlIHRoZSBrZXlTZXQuXG4gIHN0YXRpYyB2ZXJpZnlpbmdLZXkodGFnKSB7IC8vIFByb21pc2UgdGhlIG9yZGluYXJ5IHNpbmd1bGFyIHB1YmxpYyBrZXkgY29ycmVzcG9uZGluZyB0byB0aGUgc2lnbmluZyBrZXksIGRpcmVjdGx5IGZyb20gdGhlIHRhZyB3aXRob3V0IHJlZmVyZW5jZSB0byBzdG9yYWdlLlxuICAgIHJldHVybiBNdWx0aUtyeXB0by5pbXBvcnRSYXcodGFnKS5jYXRjaCgoKSA9PiB1bmF2YWlsYWJsZSh0YWcsICd2ZXJpZmljYXRpb24nKSk7XG4gIH1cbiAgc3RhdGljIGFzeW5jIGVuY3J5cHRpbmdLZXkodGFnKSB7IC8vIFByb21pc2UgdGhlIG9yZGluYXJ5IHNpbmd1bGFyIHB1YmxpYyBrZXkgY29ycmVzcG9uZGluZyB0byB0aGUgZGVjcnlwdGlvbiBrZXksIHdoaWNoIGRlcGVuZHMgb24gcHVibGljIHN0b3JhZ2UuXG4gICAgbGV0IGV4cG9ydGVkUHVibGljS2V5ID0gYXdhaXQgdGhpcy5yZXRyaWV2ZSgnRW5jcnlwdGlvbktleScsIHRhZyk7XG4gICAgaWYgKCFleHBvcnRlZFB1YmxpY0tleSkgcmV0dXJuIHVuYXZhaWxhYmxlKHRhZywgJ2VuY3J5cHRpb24nKTtcbiAgICByZXR1cm4gYXdhaXQgTXVsdGlLcnlwdG8uaW1wb3J0SldLKGV4cG9ydGVkUHVibGljS2V5Lmpzb24pO1xuICB9XG4gIHN0YXRpYyBhc3luYyBjcmVhdGVLZXlzKG1lbWJlclRhZ3MpIHsgLy8gUHJvbWlzZSBhIG5ldyB0YWcgYW5kIHByaXZhdGUga2V5cywgYW5kIHN0b3JlIHRoZSBlbmNyeXB0aW5nIGtleS5cbiAgICBsZXQge3B1YmxpY0tleTp2ZXJpZnlpbmdLZXksIHByaXZhdGVLZXk6c2lnbmluZ0tleX0gPSBhd2FpdCBNdWx0aUtyeXB0by5nZW5lcmF0ZVNpZ25pbmdLZXkoKSxcbiAgICAgICAge3B1YmxpY0tleTplbmNyeXB0aW5nS2V5LCBwcml2YXRlS2V5OmRlY3J5cHRpbmdLZXl9ID0gYXdhaXQgTXVsdGlLcnlwdG8uZ2VuZXJhdGVFbmNyeXB0aW5nS2V5KCksXG4gICAgICAgIHRhZyA9IGF3YWl0IE11bHRpS3J5cHRvLmV4cG9ydFJhdyh2ZXJpZnlpbmdLZXkpLFxuICAgICAgICBleHBvcnRlZEVuY3J5cHRpbmdLZXkgPSBhd2FpdCBNdWx0aUtyeXB0by5leHBvcnRKV0soZW5jcnlwdGluZ0tleSksXG4gICAgICAgIHRpbWUgPSBEYXRlLm5vdygpLFxuICAgICAgICBzaWduYXR1cmUgPSBhd2FpdCB0aGlzLnNpZ25Gb3JTdG9yYWdlKHttZXNzYWdlOiBleHBvcnRlZEVuY3J5cHRpbmdLZXksIHRhZywgc2lnbmluZ0tleSwgbWVtYmVyVGFncywgdGltZSwgcmVjb3Zlcnk6IHRydWV9KTtcbiAgICBhd2FpdCB0aGlzLnN0b3JlKCdFbmNyeXB0aW9uS2V5JywgdGFnLCBzaWduYXR1cmUpO1xuICAgIHJldHVybiB7c2lnbmluZ0tleSwgZGVjcnlwdGluZ0tleSwgdGFnLCB0aW1lfTtcbiAgfVxuICBzdGF0aWMgZ2V0V3JhcHBlZCh0YWcpIHsgLy8gUHJvbWlzZSB0aGUgd3JhcHBlZCBrZXkgYXBwcm9wcmlhdGUgZm9yIHRoaXMgY2xhc3MuXG4gICAgcmV0dXJuIHRoaXMucmV0cmlldmUodGhpcy5jb2xsZWN0aW9uLCB0YWcpO1xuICB9XG4gIHN0YXRpYyBhc3luYyBlbnN1cmUodGFnLCB7ZGV2aWNlID0gdHJ1ZSwgdGVhbSA9IHRydWUsIHJlY292ZXJ5ID0gZmFsc2V9ID0ge30pIHsgLy8gUHJvbWlzZSB0byByZXNvbHZlIHRvIGEgdmFsaWQga2V5U2V0LCBlbHNlIHJlamVjdC5cbiAgICBsZXQga2V5U2V0ID0gdGhpcy5jYWNoZWQodGFnKSxcbiAgICAgICAgc3RvcmVkID0gZGV2aWNlICYmIGF3YWl0IERldmljZUtleVNldC5nZXRXcmFwcGVkKHRhZyk7XG4gICAgaWYgKHN0b3JlZCkge1xuICAgICAga2V5U2V0IHx8PSBuZXcgRGV2aWNlS2V5U2V0KHRhZyk7XG4gICAgfSBlbHNlIGlmICh0ZWFtICYmIChzdG9yZWQgPSBhd2FpdCBUZWFtS2V5U2V0LmdldFdyYXBwZWQodGFnKSkpIHtcbiAgICAgIGtleVNldCB8fD0gbmV3IFRlYW1LZXlTZXQodGFnKTtcbiAgICB9IGVsc2UgaWYgKHJlY292ZXJ5ICYmIChzdG9yZWQgPSBhd2FpdCBSZWNvdmVyeUtleVNldC5nZXRXcmFwcGVkKHRhZykpKSB7IC8vIExhc3QsIGlmIGF0IGFsbC5cbiAgICAgIGtleVNldCB8fD0gbmV3IFJlY292ZXJ5S2V5U2V0KHRhZyk7XG4gICAgfVxuICAgIC8vIElmIHRoaW5ncyBoYXZlbid0IGNoYW5nZWQsIGRvbid0IGJvdGhlciB3aXRoIHNldFVud3JhcHBlZC5cbiAgICBpZiAoa2V5U2V0Py5jYWNoZWQgJiYgLy8gY2FjaGVkIGFuZCBzdG9yZWQgYXJlIHZlcmlmaWVkIHNpZ25hdHVyZXNcbiAgICAgICAga2V5U2V0LmNhY2hlZC5wcm90ZWN0ZWRIZWFkZXIuaWF0ID09PSBzdG9yZWQ/LnByb3RlY3RlZEhlYWRlci5pYXQgJiZcbiAgICAgICAga2V5U2V0LmNhY2hlZC50ZXh0ID09PSBzdG9yZWQ/LnRleHQgJiZcbiAgICAgICAga2V5U2V0LmRlY3J5cHRpbmdLZXkgJiYga2V5U2V0LnNpZ25pbmdLZXkpIHJldHVybiBrZXlTZXQ7XG4gICAgaWYgKHN0b3JlZCkga2V5U2V0LmNhY2hlZCA9IHN0b3JlZDtcbiAgICBlbHNlIHsgLy8gTm90IGZvdW5kLiBDb3VsZCBiZSBhIGJvZ3VzIHRhZywgb3Igb25lIG9uIGFub3RoZXIgY29tcHV0ZXIuXG4gICAgICB0aGlzLmNsZWFyKHRhZyk7XG4gICAgICByZXR1cm4gdW5hdmFpbGFibGUodGFnLCAncHJpdmF0ZScpO1xuICAgIH1cbiAgICByZXR1cm4ga2V5U2V0LnVud3JhcChrZXlTZXQuY2FjaGVkKS50aGVuKFxuICAgICAgdW53cmFwcGVkID0+IE9iamVjdC5hc3NpZ24oa2V5U2V0LCB1bndyYXBwZWQpLFxuICAgICAgY2F1c2UgPT4ge1xuICAgICAgICB0aGlzLmNsZWFyKGtleVNldC50YWcpXG4gICAgICAgIHJldHVybiBlcnJvcih0YWcgPT4gYFlvdSBkbyBub3QgaGF2ZSBhY2Nlc3MgdG8gdGhlIHByaXZhdGUga2V5IGZvciAke3RhZ30uYCwga2V5U2V0LnRhZywgY2F1c2UpO1xuICAgICAgfSk7XG4gIH1cbiAgc3RhdGljIGVuc3VyZTEodGFncykgeyAvLyBGaW5kIG9uZSB2YWxpZCBrZXlTZXQgYW1vbmcgdGFncywgdXNpbmcgcmVjb3ZlcnkgdGFncyBvbmx5IGlmIG5lY2Vzc2FyeS5cbiAgICByZXR1cm4gUHJvbWlzZS5hbnkodGFncy5tYXAodGFnID0+IEtleVNldC5lbnN1cmUodGFnKSkpXG4gICAgICAuY2F0Y2goYXN5bmMgcmVhc29uID0+IHsgLy8gSWYgd2UgZmFpbGVkLCB0cnkgdGhlIHJlY292ZXJ5IHRhZ3MsIGlmIGFueSwgb25lIGF0IGEgdGltZS5cbiAgICAgICAgZm9yIChsZXQgY2FuZGlkYXRlIG9mIHRhZ3MpIHtcbiAgICAgICAgICBsZXQga2V5U2V0ID0gYXdhaXQgS2V5U2V0LmVuc3VyZShjYW5kaWRhdGUsIHtkZXZpY2U6IGZhbHNlLCB0ZWFtOiBmYWxzZSwgcmVjb3Zlcnk6IHRydWV9KS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICBpZiAoa2V5U2V0KSByZXR1cm4ga2V5U2V0O1xuICAgICAgICB9XG4gICAgICAgIHRocm93IHJlYXNvbjtcbiAgICAgIH0pO1xuICB9XG4gIHN0YXRpYyBhc3luYyBwZXJzaXN0KHRhZywga2V5cywgd3JhcHBpbmdEYXRhLCB0aW1lID0gRGF0ZS5ub3coKSwgbWVtYmVyVGFncyA9IHdyYXBwaW5nRGF0YSkgeyAvLyBQcm9taXNlIHRvIHdyYXAgYSBzZXQgb2Yga2V5cyBmb3IgdGhlIHdyYXBwaW5nRGF0YSBtZW1iZXJzLCBhbmQgcGVyc2lzdCBieSB0YWcuXG4gICAgbGV0IHtzaWduaW5nS2V5fSA9IGtleXMsXG4gICAgICAgIHdyYXBwZWQgPSBhd2FpdCB0aGlzLndyYXAoa2V5cywgd3JhcHBpbmdEYXRhKSxcbiAgICAgICAgc2lnbmF0dXJlID0gYXdhaXQgdGhpcy5zaWduRm9yU3RvcmFnZSh7bWVzc2FnZTogd3JhcHBlZCwgdGFnLCBzaWduaW5nS2V5LCBtZW1iZXJUYWdzLCB0aW1lLCByZWNvdmVyeTogdHJ1ZX0pO1xuICAgIGF3YWl0IHRoaXMuc3RvcmUodGhpcy5jb2xsZWN0aW9uLCB0YWcsIHNpZ25hdHVyZSk7XG4gIH1cblxuICAvLyBJbnRlcmFjdGlvbnMgd2l0aCB0aGUgY2xvdWQgb3IgbG9jYWwgc3RvcmFnZS5cbiAgc3RhdGljIGFzeW5jIHN0b3JlKGNvbGxlY3Rpb25OYW1lLCB0YWcsIHNpZ25hdHVyZSkgeyAvLyBTdG9yZSBzaWduYXR1cmUuXG4gICAgaWYgKGNvbGxlY3Rpb25OYW1lID09PSBEZXZpY2VLZXlTZXQuY29sbGVjdGlvbikge1xuICAgICAgLy8gV2UgY2FsbGVkIHRoaXMuIE5vIG5lZWQgdG8gdmVyaWZ5IGhlcmUuIEJ1dCBzZWUgcmV0cmlldmUoKS5cbiAgICAgIGlmIChNdWx0aUtyeXB0by5pc0VtcHR5SldTUGF5bG9hZChzaWduYXR1cmUpKSByZXR1cm4gTG9jYWxTdG9yZS5kZWxldGUodGFnKTtcbiAgICAgIHJldHVybiBMb2NhbFN0b3JlLnB1dCh0YWcsIHNpZ25hdHVyZSk7XG4gICAgfVxuICAgIHJldHVybiBLZXlTZXQuU3RvcmFnZS5zdG9yZShjb2xsZWN0aW9uTmFtZSwgdGFnLCBzaWduYXR1cmUpO1xuICB9XG4gIHN0YXRpYyBhc3luYyByZXRyaWV2ZShjb2xsZWN0aW9uTmFtZSwgdGFnLCBmb3JjZUZyZXNoID0gZmFsc2UpIHsgIC8vIEdldCBiYWNrIGEgdmVyaWZpZWQgcmVzdWx0LlxuICAgIC8vIFNvbWUgY29sbGVjdGlvbnMgZG9uJ3QgY2hhbmdlIGNvbnRlbnQuIE5vIG5lZWQgdG8gcmUtZmV0Y2gvcmUtdmVyaWZ5IGlmIGl0IGV4aXN0cy5cbiAgICBsZXQgZXhpc3RpbmcgPSAhZm9yY2VGcmVzaCAmJiB0aGlzLmNhY2hlZCh0YWcpO1xuICAgIGlmIChleGlzdGluZz8uY29uc3RydWN0b3IuY29sbGVjdGlvbiA9PT0gY29sbGVjdGlvbk5hbWUpIHJldHVybiBleGlzdGluZy5jYWNoZWQ7XG4gICAgbGV0IHByb21pc2UgPSAoY29sbGVjdGlvbk5hbWUgPT09IERldmljZUtleVNldC5jb2xsZWN0aW9uKSA/IExvY2FsU3RvcmUuZ2V0KHRhZykgOiBLZXlTZXQuU3RvcmFnZS5yZXRyaWV2ZShjb2xsZWN0aW9uTmFtZSwgdGFnKSxcbiAgICAgICAgc2lnbmF0dXJlID0gYXdhaXQgcHJvbWlzZSxcbiAgICAgICAga2V5ID0gc2lnbmF0dXJlICYmIGF3YWl0IEtleVNldC52ZXJpZnlpbmdLZXkodGFnKTtcbiAgICBpZiAoIXNpZ25hdHVyZSkgcmV0dXJuO1xuICAgIC8vIFdoaWxlIHdlIHJlbHkgb24gdGhlIFN0b3JhZ2UgaW1wbGVtZW50YXRpb25zIHRvIGRlZXBseSBjaGVjayBzaWduYXR1cmVzIGR1cmluZyB3cml0ZSxcbiAgICAvLyBoZXJlIHdlIHN0aWxsIGRvIGEgc2hhbGxvdyB2ZXJpZmljYXRpb24gY2hlY2sganVzdCB0byBtYWtlIHN1cmUgdGhhdCB0aGUgZGF0YSBoYXNuJ3QgYmVlbiBtZXNzZWQgd2l0aCBhZnRlciB3cml0ZS5cbiAgICBpZiAoc2lnbmF0dXJlLnNpZ25hdHVyZXMpIGtleSA9IHtbdGFnXToga2V5fTsgLy8gUHJlcGFyZSBhIG11bHRpLWtleVxuICAgIHJldHVybiBhd2FpdCBNdWx0aUtyeXB0by52ZXJpZnkoa2V5LCBzaWduYXR1cmUpO1xuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBTZWNyZXRLZXlTZXQgZXh0ZW5kcyBLZXlTZXQgeyAvLyBLZXlzIGFyZSBlbmNyeXB0ZWQgYmFzZWQgb24gYSBzeW1tZXRyaWMgc2VjcmV0LlxuICBzdGF0aWMgc2lnbkZvclN0b3JhZ2Uoe21lc3NhZ2UsIHRhZywgc2lnbmluZ0tleSwgdGltZX0pIHtcbiAgICAvLyBDcmVhdGUgYSBzaW1wbGUgc2lnbmF0dXJlIHRoYXQgZG9lcyBub3Qgc3BlY2lmeSBpc3Mgb3IgYWN0LlxuICAgIC8vIFRoZXJlIGFyZSBubyB0cnVlIG1lbWJlclRhZ3MgdG8gcGFzcyBvbiBhbmQgdGhleSBhcmUgbm90IHVzZWQgaW4gc2ltcGxlIHNpZ25hdHVyZXMuIEhvd2V2ZXIsIHRoZSBjYWxsZXIgZG9lc1xuICAgIC8vIGdlbmVyaWNhbGx5IHBhc3Mgd3JhcHBpbmdEYXRhIGFzIG1lbWJlclRhZ3MsIGFuZCBmb3IgUmVjb3ZlcnlLZXlTZXRzLCB3cmFwcGluZ0RhdGEgaXMgdGhlIHByb21wdC4gXG4gICAgLy8gV2UgZG9uJ3Qgc3RvcmUgbXVsdGlwbGUgdGltZXMsIHNvIHRoZXJlJ3MgYWxzbyBubyBuZWVkIGZvciBpYXQgKHdoaWNoIGNhbiBiZSB1c2VkIHRvIHByZXZlbnQgcmVwbGF5IGF0dGFja3MpLlxuICAgIHJldHVybiB0aGlzLnNpZ24obWVzc2FnZSwge3RhZ3M6IFt0YWddLCBzaWduaW5nS2V5LCB0aW1lfSk7XG4gIH1cbiAgc3RhdGljIGFzeW5jIHdyYXBwaW5nS2V5KHRhZywgcHJvbXB0KSB7IC8vIFRoZSBrZXkgdXNlZCB0byAodW4pd3JhcCB0aGUgdmF1bHQgbXVsdGkta2V5LlxuICAgIGxldCBzZWNyZXQgPSAgYXdhaXQgdGhpcy5nZXRTZWNyZXQodGFnLCBwcm9tcHQpO1xuICAgIC8vIEFsdGVybmF0aXZlbHksIG9uZSBjb3VsZCB1c2Uge1t3cmFwcGluZ0RhdGFdOiBzZWNyZXR9LCBidXQgdGhhdCdzIGEgYml0IHRvbyBjdXRlLCBhbmQgZ2VuZXJhdGVzIGEgZ2VuZXJhbCBmb3JtIGVuY3J5cHRpb24uXG4gICAgLy8gVGhpcyB2ZXJzaW9uIGdlbmVyYXRlcyBhIGNvbXBhY3QgZm9ybSBlbmNyeXB0aW9uLlxuICAgIHJldHVybiBNdWx0aUtyeXB0by5nZW5lcmF0ZVNlY3JldEtleShzZWNyZXQpO1xuICB9XG4gIHN0YXRpYyBhc3luYyB3cmFwKGtleXMsIHByb21wdCA9ICcnKSB7IC8vIEVuY3J5cHQga2V5c2V0IGJ5IGdldFVzZXJEZXZpY2VTZWNyZXQuXG4gICAgbGV0IHtkZWNyeXB0aW5nS2V5LCBzaWduaW5nS2V5LCB0YWd9ID0ga2V5cyxcbiAgICAgICAgdmF1bHRLZXkgPSB7ZGVjcnlwdGluZ0tleSwgc2lnbmluZ0tleX0sXG4gICAgICAgIHdyYXBwaW5nS2V5ID0gYXdhaXQgdGhpcy53cmFwcGluZ0tleSh0YWcsIHByb21wdCk7XG4gICAgcmV0dXJuIE11bHRpS3J5cHRvLndyYXBLZXkodmF1bHRLZXksIHdyYXBwaW5nS2V5LCB7cHJvbXB0fSk7IC8vIE9yZGVyIGlzIGJhY2t3YXJkcyBmcm9tIGVuY3J5cHQuXG4gIH1cbiAgYXN5bmMgdW53cmFwKHdyYXBwZWRLZXkpIHsgLy8gRGVjcnlwdCBrZXlzZXQgYnkgZ2V0VXNlckRldmljZVNlY3JldC5cbiAgICBsZXQgcGFyc2VkID0gd3JhcHBlZEtleS5qc29uIHx8IHdyYXBwZWRLZXkudGV4dCwgLy8gSGFuZGxlIGJvdGgganNvbiBhbmQgY29wYWN0IGZvcm1zIG9mIHdyYXBwZWRLZXkuXG5cbiAgICAgICAgLy8gVGhlIGNhbGwgdG8gd3JhcEtleSwgYWJvdmUsIGV4cGxpY2l0bHkgZGVmaW5lcyB0aGUgcHJvbXB0IGluIHRoZSBoZWFkZXIgb2YgdGhlIGVuY3J5cHRpb24uXG4gICAgICAgIHByb3RlY3RlZEhlYWRlciA9IE11bHRpS3J5cHRvLmRlY29kZVByb3RlY3RlZEhlYWRlcihwYXJzZWQpLFxuICAgICAgICBwcm9tcHQgPSBwcm90ZWN0ZWRIZWFkZXIucHJvbXB0LCAvLyBJbiB0aGUgXCJjdXRlXCIgZm9ybSBvZiB3cmFwcGluZ0tleSwgcHJvbXB0IGNhbiBiZSBwdWxsZWQgZnJvbSBwYXJzZWQucmVjaXBpZW50c1swXS5oZWFkZXIua2lkLFxuXG4gICAgICAgIHdyYXBwaW5nS2V5ID0gYXdhaXQgdGhpcy5jb25zdHJ1Y3Rvci53cmFwcGluZ0tleSh0aGlzLnRhZywgcHJvbXB0KSxcbiAgICAgICAgZXhwb3J0ZWQgPSAoYXdhaXQgTXVsdGlLcnlwdG8uZGVjcnlwdCh3cmFwcGluZ0tleSwgcGFyc2VkKSkuanNvbjtcbiAgICByZXR1cm4gYXdhaXQgTXVsdGlLcnlwdG8uaW1wb3J0SldLKGV4cG9ydGVkLCB7ZGVjcnlwdGluZ0tleTogJ2RlY3J5cHQnLCBzaWduaW5nS2V5OiAnc2lnbid9KTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgZ2V0U2VjcmV0KHRhZywgcHJvbXB0KSB7IC8vIGdldFVzZXJEZXZpY2VTZWNyZXQgZnJvbSBhcHAuXG4gICAgcmV0dXJuIEtleVNldC5nZXRVc2VyRGV2aWNlU2VjcmV0KHRhZywgcHJvbXB0KTtcbiAgfVxufVxuXG4gLy8gVGhlIHVzZXIncyBhbnN3ZXIocykgdG8gYSBzZWN1cml0eSBxdWVzdGlvbiBmb3JtcyBhIHNlY3JldCwgYW5kIHRoZSB3cmFwcGVkIGtleXMgaXMgc3RvcmVkIGluIHRoZSBjbG91ZGUuXG5leHBvcnQgY2xhc3MgUmVjb3ZlcnlLZXlTZXQgZXh0ZW5kcyBTZWNyZXRLZXlTZXQge1xuICBzdGF0aWMgY29sbGVjdGlvbiA9ICdLZXlSZWNvdmVyeSc7XG59XG5cbi8vIEEgS2V5U2V0IGNvcnJlc3BvbmRpbmcgdG8gdGhlIGN1cnJlbnQgaGFyZHdhcmUuIFdyYXBwaW5nIHNlY3JldCBjb21lcyBmcm9tIHRoZSBhcHAuXG5leHBvcnQgY2xhc3MgRGV2aWNlS2V5U2V0IGV4dGVuZHMgU2VjcmV0S2V5U2V0IHtcbiAgc3RhdGljIGNvbGxlY3Rpb24gPSAnRGV2aWNlJztcbiAgc3RhdGljIHdpcGUoKSB7XG4gICAgcmV0dXJuIExvY2FsU3RvcmUuZGVzdHJveSgpO1xuICB9XG59XG5jb25zdCBMb2NhbFN0b3JlID0gbmV3IFN0b3JhZ2VMb2NhbCh7bmFtZTogRGV2aWNlS2V5U2V0LmNvbGxlY3Rpb259KTtcblxuZXhwb3J0IGNsYXNzIFRlYW1LZXlTZXQgZXh0ZW5kcyBLZXlTZXQgeyAvLyBBIEtleVNldCBjb3JyZXNwb25kaW5nIHRvIGEgdGVhbSBvZiB3aGljaCB0aGUgY3VycmVudCB1c2VyIGlzIGEgbWVtYmVyIChpZiBnZXRUYWcoKSkuXG4gIHN0YXRpYyBjb2xsZWN0aW9uID0gJ1RlYW0nO1xuICBzdGF0aWMgc2lnbkZvclN0b3JhZ2Uoe21lc3NhZ2UsIHRhZywgLi4ub3B0aW9uc30pIHtcbiAgICByZXR1cm4gdGhpcy5zaWduKG1lc3NhZ2UsIHt0ZWFtOiB0YWcsIC4uLm9wdGlvbnN9KTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgd3JhcChrZXlzLCBtZW1iZXJzKSB7XG4gICAgLy8gVGhpcyBpcyB1c2VkIGJ5IHBlcnNpc3QsIHdoaWNoIGluIHR1cm4gaXMgdXNlZCB0byBjcmVhdGUgYW5kIGNoYW5nZU1lbWJlcnNoaXAuXG4gICAgbGV0IHtkZWNyeXB0aW5nS2V5LCBzaWduaW5nS2V5fSA9IGtleXMsXG4gICAgICAgIHRlYW1LZXkgPSB7ZGVjcnlwdGluZ0tleSwgc2lnbmluZ0tleX0sXG4gICAgICAgIHdyYXBwaW5nS2V5ID0ge307XG4gICAgYXdhaXQgUHJvbWlzZS5hbGwobWVtYmVycy5tYXAobWVtYmVyVGFnID0+IEtleVNldC5lbmNyeXB0aW5nS2V5KG1lbWJlclRhZykudGhlbihrZXkgPT4gd3JhcHBpbmdLZXlbbWVtYmVyVGFnXSA9IGtleSkpKTtcbiAgICBsZXQgd3JhcHBlZFRlYW0gPSBhd2FpdCBNdWx0aUtyeXB0by53cmFwS2V5KHRlYW1LZXksIHdyYXBwaW5nS2V5KTtcbiAgICByZXR1cm4gd3JhcHBlZFRlYW07XG4gIH1cbiAgYXN5bmMgdW53cmFwKHdyYXBwZWQpIHtcbiAgICBsZXQge3JlY2lwaWVudHN9ID0gd3JhcHBlZC5qc29uLFxuICAgICAgICBtZW1iZXJUYWdzID0gdGhpcy5tZW1iZXJUYWdzID0gcmVjaXBpZW50cy5tYXAocmVjaXBpZW50ID0+IHJlY2lwaWVudC5oZWFkZXIua2lkKTtcbiAgICBsZXQga2V5U2V0ID0gYXdhaXQgdGhpcy5jb25zdHJ1Y3Rvci5lbnN1cmUxKG1lbWJlclRhZ3MpOyAvLyBXZSB3aWxsIHVzZSByZWNvdmVyeSB0YWdzIG9ubHkgaWYgd2UgbmVlZCB0by5cbiAgICBsZXQgZGVjcnlwdGVkID0gYXdhaXQga2V5U2V0LmRlY3J5cHQod3JhcHBlZC5qc29uKTtcbiAgICByZXR1cm4gYXdhaXQgTXVsdGlLcnlwdG8uaW1wb3J0SldLKGRlY3J5cHRlZC5qc29uKTtcbiAgfVxuICBhc3luYyBjaGFuZ2VNZW1iZXJzaGlwKHthZGQgPSBbXSwgcmVtb3ZlID0gW119ID0ge30pIHtcbiAgICBsZXQge21lbWJlclRhZ3N9ID0gdGhpcyxcbiAgICAgICAgbmV3TWVtYmVycyA9IG1lbWJlclRhZ3MuY29uY2F0KGFkZCkuZmlsdGVyKHRhZyA9PiAhcmVtb3ZlLmluY2x1ZGVzKHRhZykpO1xuICAgIGF3YWl0IHRoaXMuY29uc3RydWN0b3IucGVyc2lzdCh0aGlzLnRhZywgdGhpcywgbmV3TWVtYmVycywgRGF0ZS5ub3coKSwgbWVtYmVyVGFncyk7XG4gICAgdGhpcy5tZW1iZXJUYWdzID0gbmV3TWVtYmVycztcbiAgICB0aGlzLmNvbnN0cnVjdG9yLmNsZWFyKHRoaXMudGFnKTtcbiAgfVxufVxuIiwiaW1wb3J0ICogYXMgcGtnIGZyb20gXCIuLi9wYWNrYWdlLmpzb25cIiB3aXRoIHsgdHlwZTogJ2pzb24nIH07XG5leHBvcnQgY29uc3Qge25hbWUsIHZlcnNpb259ID0gcGtnLmRlZmF1bHQ7XG4iLCJpbXBvcnQge2hhc2hCdWZmZXIsIGhhc2hUZXh0LCBlbmNvZGVCYXNlNjR1cmwsIGRlY29kZUJhc2U2NHVybCwgZGVjb2RlQ2xhaW1zfSBmcm9tICcuL3V0aWxpdGllcy5tanMnO1xuaW1wb3J0IE11bHRpS3J5cHRvIGZyb20gXCIuL211bHRpS3J5cHRvLm1qc1wiO1xuaW1wb3J0IHtLZXlTZXQsIERldmljZUtleVNldCwgUmVjb3ZlcnlLZXlTZXQsIFRlYW1LZXlTZXR9IGZyb20gXCIuL2tleVNldC5tanNcIjtcbmltcG9ydCB7bmFtZSwgdmVyc2lvbn0gZnJvbSBcIi4vcGFja2FnZS1sb2FkZXIubWpzXCI7XG5cbmNvbnN0IFNlY3VyaXR5ID0geyAvLyBUaGlzIGlzIHRoZSBhcGkgZm9yIHRoZSB2YXVsdC4gU2VlIGh0dHBzOi8va2lscm95LWNvZGUuZ2l0aHViLmlvL2Rpc3RyaWJ1dGVkLXNlY3VyaXR5L2RvY3MvaW1wbGVtZW50YXRpb24uaHRtbCNjcmVhdGluZy10aGUtdmF1bHQtd2ViLXdvcmtlci1hbmQtaWZyYW1lXG5cbiAgZ2V0IEtleVNldCgpIHsgcmV0dXJuIEtleVNldDsgfSwvLyBGSVhNRTogZG8gbm90IGxlYXZlIHRoaXMgaGVyZVxuICAvLyBDbGllbnQtZGVmaW5lZCByZXNvdXJjZXMuXG4gIHNldCBTdG9yYWdlKHN0b3JhZ2UpIHsgLy8gQWxsb3dzIGEgbm9kZSBhcHAgKG5vIHZhdWx0dCkgdG8gb3ZlcnJpZGUgdGhlIGRlZmF1bHQgc3RvcmFnZS5cbiAgICBLZXlTZXQuU3RvcmFnZSA9IHN0b3JhZ2U7XG4gIH0sXG4gIGdldCBTdG9yYWdlKCkgeyAvLyBBbGxvd3MgYSBub2RlIGFwcCAobm8gdmF1bHQpIHRvIGV4YW1pbmUgc3RvcmFnZS5cbiAgICByZXR1cm4gS2V5U2V0LlN0b3JhZ2U7XG4gIH0sXG4gIHNldCBnZXRVc2VyRGV2aWNlU2VjcmV0KGZ1bmN0aW9uT2ZUYWdBbmRQcm9tcHQpIHsgIC8vIEFsbG93cyBhIG5vZGUgYXBwIChubyB2YXVsdCkgdG8gb3ZlcnJpZGUgdGhlIGRlZmF1bHQuXG4gICAgS2V5U2V0LmdldFVzZXJEZXZpY2VTZWNyZXQgPSBmdW5jdGlvbk9mVGFnQW5kUHJvbXB0O1xuICB9LFxuICBnZXQgZ2V0VXNlckRldmljZVNlY3JldCgpIHtcbiAgICByZXR1cm4gS2V5U2V0LmdldFVzZXJEZXZpY2VTZWNyZXQ7XG4gIH0sXG4gIHJlYWR5OiB7bmFtZSwgdmVyc2lvbiwgb3JpZ2luOiBLZXlTZXQuU3RvcmFnZS5vcmlnaW59LFxuXG4gIC8vIFRoZSBmb3VyIGJhc2ljIG9wZXJhdGlvbnMuIC4uLnJlc3QgbWF5IGJlIG9uZSBvciBtb3JlIHRhZ3MsIG9yIG1heSBiZSB7dGFncywgdGVhbSwgbWVtYmVyLCBjb250ZW50VHlwZSwgLi4ufVxuICBhc3luYyBlbmNyeXB0KG1lc3NhZ2UsIC4uLnJlc3QpIHsgLy8gUHJvbWlzZSBhIEpXRS5cbiAgICBsZXQgb3B0aW9ucyA9IHt9LCB0YWdzID0gdGhpcy5jYW5vbmljYWxpemVQYXJhbWV0ZXJzKHJlc3QsIG9wdGlvbnMpLFxuICAgICAgICBrZXkgPSBhd2FpdCBLZXlTZXQucHJvZHVjZUtleSh0YWdzLCB0YWcgPT4gS2V5U2V0LmVuY3J5cHRpbmdLZXkodGFnKSwgb3B0aW9ucyk7XG4gICAgcmV0dXJuIE11bHRpS3J5cHRvLmVuY3J5cHQoa2V5LCBtZXNzYWdlLCBvcHRpb25zKTtcbiAgfSxcbiAgYXN5bmMgZGVjcnlwdChlbmNyeXB0ZWQsIC4uLnJlc3QpIHsgLy8gUHJvbWlzZSB7cGF5bG9hZCwgdGV4dCwganNvbn0gYXMgYXBwcm9wcmlhdGUuXG4gICAgbGV0IG9wdGlvbnMgPSB7fSxcbiAgICAgICAgW3RhZ10gPSB0aGlzLmNhbm9uaWNhbGl6ZVBhcmFtZXRlcnMocmVzdCwgb3B0aW9ucywgZW5jcnlwdGVkKSxcbiAgICAgICAge3JlY292ZXJ5LCAuLi5vdGhlck9wdGlvbnN9ID0gb3B0aW9ucyxcbiAgICAgICAga2V5U2V0ID0gYXdhaXQgS2V5U2V0LmVuc3VyZSh0YWcsIHtyZWNvdmVyeX0pO1xuICAgIHJldHVybiBrZXlTZXQuZGVjcnlwdChlbmNyeXB0ZWQsIG90aGVyT3B0aW9ucyk7XG4gIH0sXG4gIGFzeW5jIHNpZ24obWVzc2FnZSwgLi4ucmVzdCkgeyAvLyBQcm9taXNlIGEgSldTLlxuICAgIGxldCBvcHRpb25zID0ge30sIHRhZ3MgPSB0aGlzLmNhbm9uaWNhbGl6ZVBhcmFtZXRlcnMocmVzdCwgb3B0aW9ucyk7XG4gICAgcmV0dXJuIEtleVNldC5zaWduKG1lc3NhZ2UsIHt0YWdzLCAuLi5vcHRpb25zfSk7XG4gIH0sXG4gIGFzeW5jIHZlcmlmeShzaWduYXR1cmUsIC4uLnJlc3QpIHsgLy8gUHJvbWlzZSB7cGF5bG9hZCwgdGV4dCwganNvbn0gYXMgYXBwcm9wcmlhdGUuXG4gICAgbGV0IG9wdGlvbnMgPSB7fSwgdGFncyA9IHRoaXMuY2Fub25pY2FsaXplUGFyYW1ldGVycyhyZXN0LCBvcHRpb25zLCBzaWduYXR1cmUpO1xuICAgIHJldHVybiBLZXlTZXQudmVyaWZ5KHNpZ25hdHVyZSwgdGFncywgb3B0aW9ucyk7XG4gIH0sXG5cbiAgLy8gVGFnIG1haW50YW5jZS5cbiAgYXN5bmMgY3JlYXRlKC4uLm1lbWJlcnMpIHsgLy8gUHJvbWlzZSBhIG5ld2x5LWNyZWF0ZWQgdGFnIHdpdGggdGhlIGdpdmVuIG1lbWJlcnMuIFRoZSBtZW1iZXIgdGFncyAoaWYgYW55KSBtdXN0IGFscmVhZHkgZXhpc3QuXG4gICAgaWYgKCFtZW1iZXJzLmxlbmd0aCkgcmV0dXJuIGF3YWl0IERldmljZUtleVNldC5jcmVhdGUoKTtcbiAgICBsZXQgcHJvbXB0ID0gbWVtYmVyc1swXS5wcm9tcHQ7XG4gICAgaWYgKHByb21wdCkgcmV0dXJuIGF3YWl0IFJlY292ZXJ5S2V5U2V0LmNyZWF0ZShwcm9tcHQpO1xuICAgIHJldHVybiBhd2FpdCBUZWFtS2V5U2V0LmNyZWF0ZShtZW1iZXJzKTtcbiAgfSxcbiAgYXN5bmMgY2hhbmdlTWVtYmVyc2hpcCh7dGFnLCByZWNvdmVyeSA9IGZhbHNlLCAuLi5vcHRpb25zfSkgeyAvLyBQcm9taXNlIHRvIGFkZCBvciByZW1vdmUgbWVtYmVycy5cbiAgICBsZXQga2V5U2V0ID0gYXdhaXQgS2V5U2V0LmVuc3VyZSh0YWcsIHtyZWNvdmVyeSwgLi4ub3B0aW9uc30pOyAvLyBNYWtlcyBubyBzZW5zZSB0byBjaGFuZ2VNZW1iZXJzaGlwIG9mIGEgcmVjb3Zlcnkga2V5LlxuICAgIHJldHVybiBrZXlTZXQuY2hhbmdlTWVtYmVyc2hpcChvcHRpb25zKTtcbiAgfSxcbiAgYXN5bmMgZGVzdHJveSh0YWdPck9wdGlvbnMpIHsgLy8gUHJvbWlzZSB0byByZW1vdmUgdGhlIHRhZyBhbmQgYW55IGFzc29jaWF0ZWQgZGF0YSBmcm9tIGFsbCBzdG9yYWdlLlxuICAgIGlmICgnc3RyaW5nJyA9PT0gdHlwZW9mIHRhZ09yT3B0aW9ucykgdGFnT3JPcHRpb25zID0ge3RhZzogdGFnT3JPcHRpb25zfTtcbiAgICBsZXQge3RhZywgcmVjb3ZlcnkgPSB0cnVlLCAuLi5vdGhlck9wdGlvbnN9ID0gdGFnT3JPcHRpb25zLFxuICAgICAgICBvcHRpb25zID0ge3JlY292ZXJ5LCAuLi5vdGhlck9wdGlvbnN9LFxuICAgICAgICBrZXlTZXQgPSBhd2FpdCBLZXlTZXQuZW5zdXJlKHRhZywgb3B0aW9ucyk7XG4gICAgcmV0dXJuIGtleVNldC5kZXN0cm95KG9wdGlvbnMpO1xuICB9LFxuICBjbGVhcih0YWcpIHsgLy8gUmVtb3ZlIGFueSBsb2NhbGx5IGNhY2hlZCBLZXlTZXQgZm9yIHRoZSB0YWcsIG9yIGFsbCBLZXlTZXRzIGlmIG5vdCB0YWcgc3BlY2lmaWVkLlxuICAgIEtleVNldC5jbGVhcih0YWcpO1xuICB9LFxuICB3aXBlRGV2aWNlS2V5cygpIHtcbiAgICByZXR1cm4gRGV2aWNlS2V5U2V0LndpcGUoKTtcbiAgfSxcblxuICAvLyBVdGxpdGllc1xuICBoYXNoQnVmZmVyLCBoYXNoVGV4dCwgZW5jb2RlQmFzZTY0dXJsLCBkZWNvZGVCYXNlNjR1cmwsIGRlY29kZUNsYWltcyxcblxuICBjYW5vbmljYWxpemVQYXJhbWV0ZXJzKHJlc3QsIG9wdGlvbnMsIHRva2VuKSB7IC8vIFJldHVybiB0aGUgYWN0dWFsIGxpc3Qgb2YgdGFncywgYW5kIGJhc2ggb3B0aW9ucy5cbiAgICAvLyByZXN0IG1heSBiZSBhIGxpc3Qgb2YgdGFnIHN0cmluZ3NcbiAgICAvLyAgICBvciBhIGxpc3Qgb2Ygb25lIHNpbmdsZSBvYmplY3Qgc3BlY2lmeWluZyBuYW1lZCBwYXJhbWV0ZXJzLCBpbmNsdWRpbmcgZWl0aGVyIHRlYW0sIHRhZ3MsIG9yIG5laXRoZXJcbiAgICAvLyB0b2tlbiBtYXkgYmUgYSBKV0Ugb3IgSlNFLCBvciBmYWxzeSwgYW5kIGlzIHVzZWQgdG8gc3VwcGx5IHRhZ3MgaWYgbmVjZXNzYXJ5LlxuICAgIGlmIChyZXN0Lmxlbmd0aCA+IDEgfHwgcmVzdFswXT8ubGVuZ3RoICE9PSB1bmRlZmluZWQpIHJldHVybiByZXN0O1xuICAgIGxldCB7dGFncyA9IFtdLCBjb250ZW50VHlwZSwgdGltZSwgLi4ub3RoZXJzfSA9IHJlc3RbMF0gfHwge30sXG5cdHt0ZWFtfSA9IG90aGVyczsgLy8gRG8gbm90IHN0cmlwIHRlYW0gZnJvbSBvdGhlcnMuXG4gICAgaWYgKCF0YWdzLmxlbmd0aCkge1xuICAgICAgaWYgKHJlc3QubGVuZ3RoICYmIHJlc3RbMF0ubGVuZ3RoKSB0YWdzID0gcmVzdDsgLy8gcmVzdCBub3QgZW1wdHksIGFuZCBpdHMgZmlyc3QgaXMgc3RyaW5nLWxpa2UuXG4gICAgICBlbHNlIGlmICh0b2tlbikgeyAvLyBnZXQgZnJvbSB0b2tlblxuICAgICAgICBpZiAodG9rZW4uc2lnbmF0dXJlcykgdGFncyA9IHRva2VuLnNpZ25hdHVyZXMubWFwKHNpZyA9PiBNdWx0aUtyeXB0by5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIoc2lnKS5raWQpO1xuICAgICAgICBlbHNlIGlmICh0b2tlbi5yZWNpcGllbnRzKSB0YWdzID0gdG9rZW4ucmVjaXBpZW50cy5tYXAocmVjID0+IHJlYy5oZWFkZXIua2lkKTtcbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgbGV0IGtpZCA9IE11bHRpS3J5cHRvLmRlY29kZVByb3RlY3RlZEhlYWRlcih0b2tlbikua2lkOyAvLyBjb21wYWN0IHRva2VuXG4gICAgICAgICAgaWYgKGtpZCkgdGFncyA9IFtraWRdO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICAgIGlmICh0ZWFtICYmICF0YWdzLmluY2x1ZGVzKHRlYW0pKSB0YWdzID0gW3RlYW0sIC4uLnRhZ3NdO1xuICAgIGlmIChjb250ZW50VHlwZSkgb3B0aW9ucy5jdHkgPSBjb250ZW50VHlwZTtcbiAgICBpZiAodGltZSkgb3B0aW9ucy5pYXQgPSB0aW1lO1xuICAgIE9iamVjdC5hc3NpZ24ob3B0aW9ucywgb3RoZXJzKTtcblxuICAgIHJldHVybiB0YWdzO1xuICB9XG59O1xuXG5leHBvcnQgZGVmYXVsdCBTZWN1cml0eTtcbiJdLCJuYW1lcyI6WyJjcnlwdG8iLCJlbmNvZGUiLCJkZWNvZGUiLCJiaXRMZW5ndGgiLCJkZWNyeXB0IiwiZ2V0Q3J5cHRvS2V5Iiwid3JhcCIsInVud3JhcCIsImRlcml2ZUtleSIsInAycyIsImNvbmNhdFNhbHQiLCJlbmNyeXB0IiwiYmFzZTY0dXJsIiwic3VidGxlQWxnb3JpdGhtIiwiaW1wb3J0SldLIiwiZGVjb2RlQmFzZTY0VVJMIiwiYXNLZXlPYmplY3QiLCJqd2suaXNKV0siLCJqd2suaXNTZWNyZXRKV0siLCJpbnZhbGlkS2V5SW5wdXQiLCJqd2suaXNQcml2YXRlSldLIiwiandrLmlzUHVibGljSldLIiwiY2hlY2tLZXlUeXBlIiwiRUNESC5lY2RoQWxsb3dlZCIsIkVDREguZGVyaXZlS2V5IiwiY2VrTGVuZ3RoIiwiYWVzS3ciLCJyc2FFcyIsInBiZXMyS3ciLCJhZXNHY21LdyIsIkVDREguZ2VuZXJhdGVFcGsiLCJnZXRWZXJpZnlLZXkiLCJnZXRTaWduS2V5IiwiYmFzZTY0dXJsLmVuY29kZSIsImJhc2U2NHVybC5kZWNvZGUiLCJnZW5lcmF0ZVNlY3JldCIsImdlbmVyYXRlS2V5UGFpciIsImdlbmVyYXRlIiwiSk9TRS5iYXNlNjR1cmwuZW5jb2RlIiwiSk9TRS5iYXNlNjR1cmwuZGVjb2RlIiwiSk9TRS5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIiLCJKT1NFLmdlbmVyYXRlS2V5UGFpciIsIkpPU0UuQ29tcGFjdFNpZ24iLCJKT1NFLmNvbXBhY3RWZXJpZnkiLCJKT1NFLkNvbXBhY3RFbmNyeXB0IiwiSk9TRS5jb21wYWN0RGVjcnlwdCIsIkpPU0UuZ2VuZXJhdGVTZWNyZXQiLCJKT1NFLmV4cG9ydEpXSyIsIkpPU0UuaW1wb3J0SldLIiwiSk9TRS5HZW5lcmFsRW5jcnlwdCIsIkpPU0UuZ2VuZXJhbERlY3J5cHQiLCJKT1NFLkdlbmVyYWxTaWduIiwiSk9TRS5nZW5lcmFsVmVyaWZ5IiwiQ2FjaGUiLCJTdG9yYWdlTG9jYWwiLCJwa2cuZGVmYXVsdCJdLCJtYXBwaW5ncyI6IkFBQUEsZUFBZSxNQUFNOztBQ0FyQixlQUFlLE1BQU07QUFDZCxNQUFNLFdBQVcsR0FBRyxDQUFDLEdBQUcsS0FBSyxHQUFHLFlBQVksU0FBUzs7QUNBNUQsTUFBTSxNQUFNLEdBQUcsT0FBTyxTQUFTLEVBQUUsSUFBSSxLQUFLO0FBQzFDLElBQUksTUFBTSxZQUFZLEdBQUcsQ0FBQyxJQUFJLEVBQUUsU0FBUyxDQUFDLEtBQUssQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDO0FBQ3JELElBQUksT0FBTyxJQUFJLFVBQVUsQ0FBQyxNQUFNQSxRQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxZQUFZLEVBQUUsSUFBSSxDQUFDLENBQUM7QUFDekUsQ0FBQzs7QUNITSxNQUFNLE9BQU8sR0FBRyxJQUFJLFdBQVcsRUFBRTtBQUNqQyxNQUFNLE9BQU8sR0FBRyxJQUFJLFdBQVcsRUFBRTtBQUN4QyxNQUFNLFNBQVMsR0FBRyxDQUFDLElBQUksRUFBRTtBQUNsQixTQUFTLE1BQU0sQ0FBQyxHQUFHLE9BQU8sRUFBRTtBQUNuQyxJQUFJLE1BQU0sSUFBSSxHQUFHLE9BQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQyxHQUFHLEVBQUUsRUFBRSxNQUFNLEVBQUUsS0FBSyxHQUFHLEdBQUcsTUFBTSxFQUFFLENBQUMsQ0FBQztBQUNyRSxJQUFJLE1BQU0sR0FBRyxHQUFHLElBQUksVUFBVSxDQUFDLElBQUksQ0FBQztBQUNwQyxJQUFJLElBQUksQ0FBQyxHQUFHLENBQUM7QUFDYixJQUFJLEtBQUssTUFBTSxNQUFNLElBQUksT0FBTyxFQUFFO0FBQ2xDLFFBQVEsR0FBRyxDQUFDLEdBQUcsQ0FBQyxNQUFNLEVBQUUsQ0FBQyxDQUFDO0FBQzFCLFFBQVEsQ0FBQyxJQUFJLE1BQU0sQ0FBQyxNQUFNO0FB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QUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLEVBQUMsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsRUFBRSxZQUFZLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDLElBQUksQ0FBQyxlQUFlLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxLQUFLLEVBQUUsQ0FBQyxJQUFJLE1BQU0sQ0FBQyxJQUFJLElBQUksQ0FBQyxPQUFPLENBQUMsTUFBTSxFQUFFLENBQUMsWUFBWSxDQUFDLENBQUMsQ0FBQyxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsS0FBSyxHQUFFLENBQUMsQ0FBQyxNQUFNLFdBQVcsQ0FBQyxXQUFXLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLFFBQVEsQ0FBQyxDQUFDLENBQUMsU0FBUyxDQUFDLGlCQUFpQixDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxLQUFFLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLElBQUksS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxRQUFRLENBQUMsQ0FBQyxDQUFDLFFBQVEsQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxVQUFVLENBQUMsQ0FBQyxDQUFDLEVBQUMsQ0FBQyxNQUFNLElBQUksRUFBRSxDQUFDLE9BQU8sSUFBSSxDQUFDLFNBQVMsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxHQUFHLElBQUksQ0FBQyxZQUFZLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsTUFBTSxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxJQUFJLENBQUMsU0FBUyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxDQUFDLEdBQUcsSUFBSSxDQUFDLFdBQVcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxNQUFNLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFPLElBQUksQ0FBQyxTQUFTLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLENBQUMsR0FBRyxJQUFJLENBQUMsY0FBYyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLE1BQU0sR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFPLElBQUksQ0FBQyxTQUFTLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLENBQUMsR0FBRyxJQUFJLENBQUMsV0FBVyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsS0FBSyxFQUFFLE9BQU8sQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsRUFBQyxDQUFDLE1BQU0sU0FBUyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsVUFBVSxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsQ0FBQyxJQUFJLEVBQUUsU0FBUyxDQUFDLENBQUMsTUFBTSxJQUFJLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLFFBQVEsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDLFVBQVUsQ0FBQyxNQUFNLFlBQVksU0FBUyxXQUFXLENBQUMsV0FBVyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxJQUFJLE1BQU0sQ0FBQyxDQUFDLEVBQUUsRUFBRSxJQUFJLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxRQUFRLEVBQUMsQ0FBQyxNQUFNLFlBQVksQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTSxDQUFDLE1BQU0sQ0FBQyxDQUFDLElBQUksRUFBRSxFQUFFLEVBQUUsRUFBRSxHQUFHLEVBQUUsQ0FBQyxFQUFFLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsTUFBTSxXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxDQUFDLE1BQU0sQ0FBQyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsRUFBRSxJQUFJLEVBQUUsQ0FBQyxjQUFjLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTSxDQUFDLENBQUMsRUFBRSxJQUFJLENBQUMsUUFBUSxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFPLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLFFBQVEsQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxFQUFFLENBQUMsQ0FBQyxPQUFPLEVBQUUsQ0FBQyxPQUFPLE1BQU0sQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFDOztBQ0FwN0QsSUFBSSxRQUFRLEdBQUcsWUFBWSxJQUFJLFlBQVk7QUFDM0MsSUFBSSxPQUFPLE1BQU0sQ0FBQyxLQUFLLFdBQVcsRUFBRTtBQUNwQyxFQUFFLFFBQVEsR0FBRyxNQUFNLENBQUMsTUFBTTtBQUMxQjs7QUFFTyxTQUFTLG1CQUFtQixDQUFDLEdBQUcsRUFBRSxZQUFZLEVBQUU7QUFDdkQsRUFBRSxPQUFPLFlBQVksSUFBSSxHQUFHLEdBQUcsUUFBUSxDQUFDLFlBQVksQ0FBQyxJQUFJLEdBQUc7QUFDNUQ7O0FDUEEsTUFBTSxNQUFNLEdBQUcsSUFBSSxHQUFHLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxNQUFNOztBQ0F2QyxTQUFTLE9BQU8sQ0FBQyxjQUFjLEVBQUUsR0FBRyxFQUFFLFNBQVMsR0FBRyxNQUFNLEVBQUU7QUFDakU7QUFDQTtBQUNBO0FBQ0E7QUFDQSxFQUFFLElBQUksQ0FBQyxHQUFHLEVBQUUsT0FBTyxjQUFjO0FBQ2pDLEVBQUUsT0FBTyxDQUFDLEVBQUUsY0FBYyxDQUFDLENBQUMsRUFBRSxHQUFHLENBQUMsQ0FBQyxFQUFFLFNBQVMsQ0FBQyxDQUFDO0FBQ2hEOztBQ0pBLGVBQWUsZUFBZSxDQUFDLFFBQVEsRUFBRTtBQUN6QztBQUNBLEVBQUUsSUFBSSxRQUFRLENBQUMsTUFBTSxLQUFLLEdBQUcsRUFBRSxPQUFPLEVBQUU7QUFDeEMsRUFBRSxJQUFJLENBQUMsUUFBUSxDQUFDLEVBQUUsRUFBRSxPQUFPLE9BQU8sQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLFVBQVUsQ0FBQztBQUM5RCxFQUFFLElBQUksSUFBSSxHQUFHLE1BQU0sUUFBUSxDQUFDLElBQUksRUFBRTtBQUNsQyxFQUFFLElBQUksQ0FBQyxJQUFJLEVBQUUsT0FBTyxJQUFJLENBQUM7QUFDekIsRUFBRSxPQUFPLElBQUksQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDO0FBQ3pCOztBQUVBLE1BQU0sT0FBTyxHQUFHO0FBQ2hCLEVBQUUsSUFBSSxNQUFNLEdBQUcsRUFBRSxPQUFPLE1BQU0sQ0FBQyxFQUFFO0FBQ2pDLEVBQUUsT0FBTztBQUNULEVBQUUsR0FBRyxDQUFDLGNBQWMsRUFBRSxHQUFHLEVBQUU7QUFDM0I7QUFDQSxJQUFJLE9BQU8sQ0FBQyxFQUFFLE1BQU0sQ0FBQyxTQUFTLEVBQUUsSUFBSSxDQUFDLE9BQU8sQ0FBQyxjQUFjLEVBQUUsR0FBRyxDQUFDLENBQUMsQ0FBQztBQUNuRSxHQUFHO0FBQ0gsRUFBRSxLQUFLLENBQUMsY0FBYyxFQUFFLEdBQUcsRUFBRSxTQUFTLEVBQUUsT0FBTyxHQUFHLEVBQUUsRUFBRTtBQUN0RDtBQUNBO0FBQ0E7QUFDQSxJQUFJLE9BQU8sS0FBSyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsY0FBYyxFQUFFLEdBQUcsQ0FBQyxFQUFFO0FBQ2hELE1BQU0sTUFBTSxFQUFFLEtBQUs7QUFDbkIsTUFBTSxJQUFJLEVBQUUsSUFBSSxDQUFDLFNBQVMsQ0FBQyxTQUFTLENBQUM7QUFDckMsTUFBTSxPQUFPLEVBQUUsQ0FBQyxjQUFjLEVBQUUsa0JBQWtCLEVBQUUsSUFBSSxPQUFPLENBQUMsT0FBTyxJQUFJLEVBQUUsQ0FBQztBQUM5RSxLQUFLLENBQUMsQ0FBQyxJQUFJLENBQUMsZUFBZSxDQUFDO0FBQzVCLEdBQUc7QUFDSCxFQUFFLFFBQVEsQ0FBQyxjQUFjLEVBQUUsR0FBRyxFQUFFLE9BQU8sR0FBRyxFQUFFLEVBQUU7QUFDOUM7QUFDQTtBQUNBLElBQUksT0FBTyxLQUFLLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxjQUFjLEVBQUUsR0FBRyxDQUFDLEVBQUU7QUFDaEQsTUFBTSxLQUFLLEVBQUUsU0FBUztBQUN0QixNQUFNLE9BQU8sRUFBRSxDQUFDLFFBQVEsRUFBRSxrQkFBa0IsRUFBRSxJQUFJLE9BQU8sQ0FBQyxPQUFPLElBQUksRUFBRSxDQUFDO0FBQ3hFLEtBQUssQ0FBQyxDQUFDLElBQUksQ0FBQyxlQUFlLENBQUM7QUFDNUI7QUFDQSxDQUFDOztBQzlCRCxTQUFTLEtBQUssQ0FBQyxnQkFBZ0IsRUFBRSxHQUFHLEVBQUUsS0FBSyxHQUFHLFNBQVMsRUFBRTtBQUN6RDtBQUNBO0FBQ0EsRUFBRSxJQUFJLFlBQVksR0FBRyxHQUFHLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsRUFBRSxDQUFDLEdBQUcsS0FBSyxHQUFHLGFBQWE7QUFDbkUsTUFBTSxPQUFPLEdBQUcsZ0JBQWdCLENBQUMsWUFBWSxDQUFDO0FBQzlDLEVBQUUsT0FBTyxPQUFPLENBQUMsTUFBTSxDQUFDLElBQUksS0FBSyxDQUFDLE9BQU8sRUFBRSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUM7QUFDcEQ7QUFDQSxTQUFTLFdBQVcsQ0FBQyxHQUFHLEVBQUUsU0FBUyxFQUFFO0FBQ3JDLEVBQUUsT0FBTyxLQUFLLENBQUMsR0FBRyxJQUFJLENBQUMsSUFBSSxFQUFFLFNBQVMsQ0FBQyxLQUFLLEVBQUUsR0FBRyxDQUFDLGtCQUFrQixDQUFDLEVBQUUsR0FBRyxDQUFDO0FBQzNFOztBQUVPLE1BQU0sTUFBTSxDQUFDO0FBQ3BCO0FBQ0E7O0FBRUE7QUFDQSxFQUFFLE9BQU8sT0FBTyxHQUFHLElBQUlDLE9BQUssQ0FBQyxHQUFHLEVBQUUsRUFBRSxHQUFHLEVBQUUsR0FBRyxHQUFHLENBQUM7QUFDaEQsRUFBRSxPQUFPLE1BQU0sQ0FBQyxHQUFHLEVBQUU7QUFDckIsSUFBSSxPQUFPLE1BQU0sQ0FBQyxPQUFPLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQztBQUNsQztBQUNBLEVBQUUsT0FBTyxLQUFLLENBQUMsR0FBRyxFQUFFLE1BQU0sRUFBRTtBQUM1QixJQUFJLE1BQU0sQ0FBQyxPQUFPLENBQUMsR0FBRyxDQUFDLEdBQUcsRUFBRSxNQUFNLENBQUM7QUFDbkM7QUFDQSxFQUFFLE9BQU8sS0FBSyxDQUFDLEdBQUcsR0FBRyxJQUFJLEVBQUU7QUFDM0IsSUFBSSxJQUFJLENBQUMsR0FBRyxFQUFFLE9BQU8sTUFBTSxDQUFDLE9BQU8sQ0FBQyxLQUFLLEVBQUU7QUFDM0MsSUFBSSxPQUFPLE1BQU0sQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQztBQUNyQztBQUNBLEVBQUUsV0FBVyxDQUFDLEdBQUcsRUFBRTtBQUNuQixJQUFJLElBQUksQ0FBQyxHQUFHLEdBQUcsR0FBRztBQUNsQixJQUFJLElBQUksQ0FBQyxVQUFVLEdBQUcsRUFBRSxDQUFDO0FBQ3pCLElBQUksTUFBTSxDQUFDLEtBQUssQ0FBQyxHQUFHLEVBQUUsSUFBSSxDQUFDO0FBQzNCO0FBQ0E7QUFDQSxFQUFFLE9BQU8sbUJBQW1CLEdBQUcsbUJBQW1CO0FBQ2xELEVBQUUsT0FBTyxPQUFPLEdBQUcsT0FBTzs7QUFFMUI7QUFDQSxFQUFFLGFBQWEsTUFBTSxDQUFDLFlBQVksRUFBRTtBQUNwQztBQUNBLElBQUksSUFBSSxDQUFDLElBQUksRUFBRSxHQUFHLElBQUksQ0FBQyxHQUFHLE1BQU0sSUFBSSxDQUFDLFVBQVUsQ0FBQyxZQUFZLENBQUM7QUFDN0QsUUFBUSxDQUFDLEdBQUcsQ0FBQyxHQUFHLElBQUk7QUFDcEIsSUFBSSxNQUFNLElBQUksQ0FBQyxPQUFPLENBQUMsR0FBRyxFQUFFLElBQUksRUFBRSxZQUFZLEVBQUUsSUFBSSxDQUFDO0FBQ3JELElBQUksT0FBTyxHQUFHO0FBQ2Q7QUFDQSxFQUFFLE1BQU0sT0FBTyxDQUFDLE9BQU8sR0FBRyxFQUFFLEVBQUU7QUFDOUIsSUFBSSxJQUFJLENBQUMsR0FBRyxFQUFFLFVBQVUsRUFBRSxVQUFVLENBQUMsR0FBRyxJQUFJO0FBQzVDLFFBQVEsT0FBTyxHQUFHLEVBQUU7QUFDcEIsUUFBUSxTQUFTLEdBQUcsTUFBTSxJQUFJLENBQUMsV0FBVyxDQUFDLGNBQWMsQ0FBQyxDQUFDLEdBQUcsT0FBTyxFQUFFLE9BQU8sRUFBRSxPQUFPLEVBQUUsR0FBRyxFQUFFLFVBQVUsRUFBRSxVQUFVLEVBQUUsSUFBSSxFQUFFLElBQUksQ0FBQyxHQUFHLEVBQUUsRUFBRSxRQUFRLEVBQUUsSUFBSSxDQUFDLENBQUM7QUFDeEosSUFBSSxNQUFNLElBQUksQ0FBQyxXQUFXLENBQUMsS0FBSyxDQUFDLGVBQWUsRUFBRSxHQUFHLEVBQUUsU0FBUyxDQUFDO0FBQ2pFLElBQUksTUFBTSxJQUFJLENBQUMsV0FBVyxDQUFDLEtBQUssQ0FBQyxJQUFJLENBQUMsV0FBVyxDQUFDLFVBQVUsRUFBRSxHQUFHLEVBQUUsU0FBUyxDQUFDO0FBQzdFLElBQUksSUFBSSxDQUFDLFdBQVcsQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDO0FBQy9CLElBQUksSUFBSSxDQUFDLE9BQU8sQ0FBQyxnQkFBZ0IsRUFBRTtBQUNuQyxJQUFJLE1BQU0sT0FBTyxDQUFDLFVBQVUsQ0FBQyxJQUFJLENBQUMsVUFBVSxDQUFDLEdBQUcsQ0FBQyxNQUFNLFNBQVMsSUFBSTtBQUNwRSxNQUFNLElBQUksWUFBWSxHQUFHLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxTQUFTLEVBQUUsQ0FBQyxHQUFHLE9BQU8sRUFBRSxRQUFRLEVBQUUsSUFBSSxDQUFDLENBQUM7QUFDckYsTUFBTSxNQUFNLFlBQVksQ0FBQyxPQUFPLENBQUMsT0FBTyxDQUFDO0FBQ3pDLEtBQUssQ0FBQyxDQUFDO0FBQ1A7QUFDQSxFQUFFLE9BQU8sQ0FBQyxTQUFTLEVBQUUsT0FBTyxFQUFFO0FBQzlCLElBQUksSUFBSSxDQUFDLEdBQUcsRUFBRSxhQUFhLENBQUMsR0FBRyxJQUFJO0FBQ25DLFFBQVEsR0FBRyxHQUFHLFNBQVMsQ0FBQyxVQUFVLEdBQUcsQ0FBQyxDQUFDLEdBQUcsR0FBRyxhQUFhLENBQUMsR0FBRyxhQUFhO0FBQzNFLElBQUksT0FBTyxXQUFXLENBQUMsT0FBTyxDQUFDLEdBQUcsRUFBRSxTQUFTLEVBQUUsT0FBTyxDQUFDO0FBQ3ZEO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsRUFBRSxhQUFhLElBQUksQ0FBQyxPQUFPLEVBQUUsQ0FBQyxJQUFJLEdBQUcsRUFBRTtBQUN2Qyw4QkFBOEIsSUFBSSxDQUFDLEdBQUcsRUFBRSxNQUFNLENBQUMsR0FBRztBQUNsRCw4QkFBOEIsT0FBTyxDQUFDLEdBQUcsR0FBRyxNQUFNO0FBQ2xELDhCQUE4QixJQUFJLENBQUMsR0FBRyxHQUFHLEdBQUcsSUFBSSxJQUFJLENBQUMsR0FBRyxFQUFFO0FBQzFELDhCQUE4QixVQUFVLEVBQUUsVUFBVSxFQUFFLFFBQVE7QUFDOUQsOEJBQThCLEdBQUcsT0FBTyxDQUFDLEVBQUU7QUFDM0MsSUFBSSxJQUFJLEdBQUcsSUFBSSxDQUFDLEdBQUcsRUFBRTtBQUNyQixNQUFNLElBQUksQ0FBQyxVQUFVLEVBQUUsVUFBVSxHQUFHLENBQUMsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxFQUFFLFVBQVU7QUFDekUsTUFBTSxJQUFJLFlBQVksR0FBRyxVQUFVLENBQUMsSUFBSSxDQUFDLEdBQUcsSUFBSSxJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDO0FBQ2pFLE1BQU0sR0FBRyxHQUFHLFlBQVksSUFBSSxNQUFNLElBQUksQ0FBQyxPQUFPLENBQUMsVUFBVSxDQUFDLENBQUMsSUFBSSxDQUFDLE1BQU0sSUFBSSxNQUFNLENBQUMsR0FBRyxDQUFDO0FBQ3JGO0FBQ0EsSUFBSSxJQUFJLEdBQUcsSUFBSSxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsR0FBRyxDQUFDLEVBQUUsSUFBSSxHQUFHLENBQUMsR0FBRyxFQUFFLEdBQUcsSUFBSSxDQUFDLENBQUM7QUFDMUQsSUFBSSxJQUFJLEdBQUcsSUFBSSxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsR0FBRyxDQUFDLEVBQUUsSUFBSSxHQUFHLENBQUMsR0FBRyxJQUFJLEVBQUUsR0FBRyxDQUFDOztBQUV6RCxJQUFJLElBQUksR0FBRyxHQUFHLE1BQU0sSUFBSSxDQUFDLFVBQVUsQ0FBQyxJQUFJLEVBQUUsTUFBTSxHQUFHLElBQUk7QUFDdkQ7QUFDQSxNQUFNLElBQUksR0FBRyxHQUFHLFVBQVUsSUFBSSxDQUFDLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxHQUFHLEVBQUUsQ0FBQyxRQUFRLEVBQUUsR0FBRyxPQUFPLENBQUMsQ0FBQyxFQUFFLFVBQVU7QUFDM0YsTUFBTSxVQUFVLEdBQUcsSUFBSTtBQUN2QixNQUFNLE9BQU8sR0FBRztBQUNoQixLQUFLLEVBQUUsT0FBTyxDQUFDO0FBQ2YsUUFBUSxhQUFhLEdBQUcsV0FBVyxDQUFDLFdBQVcsQ0FBQyxPQUFPLEVBQUUsT0FBTyxDQUFDO0FBQ2pFLElBQUksSUFBSSxHQUFHLEtBQUssTUFBTSxFQUFFO0FBQ3hCLE1BQU0sTUFBTSxJQUFJLEdBQUcsTUFBTSxVQUFVLENBQUMsYUFBYSxDQUFDO0FBQ2xELE1BQU0sR0FBRyxHQUFHLE1BQU0sZUFBZSxDQUFDLElBQUksQ0FBQztBQUN2QyxLQUFLLE1BQU0sSUFBSSxDQUFDLEdBQUcsRUFBRTtBQUNyQixNQUFNLEdBQUcsR0FBRyxTQUFTO0FBQ3JCO0FBQ0EsSUFBSSxPQUFPLFdBQVcsQ0FBQyxJQUFJLENBQUMsR0FBRyxFQUFFLGFBQWEsRUFBRSxDQUFDLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLE9BQU8sQ0FBQyxDQUFDO0FBQ2pGOztBQUVBO0FBQ0EsRUFBRSxhQUFhLE1BQU0sQ0FBQyxTQUFTLEVBQUUsSUFBSSxFQUFFLE9BQU8sRUFBRTtBQUNoRCxJQUFJLElBQUksU0FBUyxHQUFHLENBQUMsU0FBUyxDQUFDLFVBQVU7QUFDekMsUUFBUSxHQUFHLEdBQUcsTUFBTSxJQUFJLENBQUMsVUFBVSxDQUFDLElBQUksRUFBRSxHQUFHLElBQUksTUFBTSxDQUFDLFlBQVksQ0FBQyxHQUFHLENBQUMsRUFBRSxPQUFPLEVBQUUsU0FBUyxDQUFDO0FBQzlGLFFBQVEsTUFBTSxHQUFHLE1BQU0sV0FBVyxDQUFDLE1BQU0sQ0FBQyxHQUFHLEVBQUUsU0FBUyxFQUFFLE9BQU8sQ0FBQztBQUNsRSxRQUFRLFNBQVMsR0FBRyxPQUFPLENBQUMsTUFBTSxLQUFLLFNBQVMsR0FBRyxNQUFNLEVBQUUsZUFBZSxDQUFDLEdBQUcsR0FBRyxPQUFPLENBQUMsTUFBTTtBQUMvRixRQUFRLFNBQVMsR0FBRyxPQUFPLENBQUMsU0FBUztBQUNyQyxJQUFJLFNBQVMsSUFBSSxDQUFDLEtBQUssRUFBRTtBQUN6QixNQUFNLElBQUksT0FBTyxDQUFDLFNBQVMsRUFBRSxPQUFPLE9BQU8sQ0FBQyxNQUFNLENBQUMsSUFBSSxLQUFLLENBQUMsS0FBSyxDQUFDLENBQUM7QUFDcEU7QUFDQSxJQUFJLElBQUksQ0FBQyxNQUFNLEVBQUUsT0FBTyxJQUFJLENBQUMsc0JBQXNCLENBQUM7QUFDcEQsSUFBSSxJQUFJLFNBQVMsRUFBRTtBQUNuQixNQUFNLElBQUksT0FBTyxDQUFDLE1BQU0sS0FBSyxNQUFNLEVBQUU7QUFDckMsUUFBUSxTQUFTLEdBQUcsTUFBTSxDQUFDLGVBQWUsQ0FBQyxHQUFHO0FBQzlDLFFBQVEsSUFBSSxDQUFDLFNBQVMsRUFBRSxPQUFPLElBQUksQ0FBQyxvQ0FBb0MsQ0FBQztBQUN6RTtBQUNBLE1BQU0sSUFBSSxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsU0FBUyxDQUFDLEVBQUU7QUFDckMsUUFBUSxJQUFJLFNBQVMsR0FBRyxNQUFNLE1BQU0sQ0FBQyxZQUFZLENBQUMsU0FBUyxDQUFDO0FBQzVELFlBQVksY0FBYyxHQUFHLENBQUMsQ0FBQyxTQUFTLEdBQUcsU0FBUyxDQUFDO0FBQ3JELFlBQVksR0FBRyxHQUFHLE1BQU0sV0FBVyxDQUFDLE1BQU0sQ0FBQyxjQUFjLEVBQUUsU0FBUyxFQUFFLE9BQU8sQ0FBQztBQUM5RSxRQUFRLElBQUksQ0FBQyxHQUFHLEVBQUUsT0FBTyxJQUFJLENBQUMsNkJBQTZCLENBQUM7QUFDNUQsUUFBUSxJQUFJLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQztBQUM1QixRQUFRLE1BQU0sQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLE1BQU0sSUFBSSxNQUFNLENBQUMsZUFBZSxDQUFDLEdBQUcsS0FBSyxTQUFTLENBQUMsQ0FBQyxPQUFPLEdBQUcsTUFBTSxDQUFDLE9BQU87QUFDeEc7QUFDQTtBQUNBLElBQUksSUFBSSxTQUFTLElBQUksU0FBUyxLQUFLLE1BQU0sRUFBRTtBQUMzQyxNQUFNLElBQUksT0FBTyxHQUFHLE1BQU0sQ0FBQyxlQUFlLENBQUMsR0FBRyxJQUFJLE1BQU0sQ0FBQyxlQUFlLENBQUMsR0FBRztBQUM1RSxVQUFVLFdBQVcsR0FBRyxNQUFNLElBQUksQ0FBQyxRQUFRLENBQUMsVUFBVSxDQUFDLFVBQVUsRUFBRSxPQUFPLENBQUM7QUFDM0UsVUFBVSxHQUFHLEdBQUcsV0FBVyxFQUFFLElBQUk7QUFDakMsTUFBTSxJQUFJLFNBQVMsSUFBSSxDQUFDLE9BQU8sRUFBRSxPQUFPLElBQUksQ0FBQyw2Q0FBNkMsQ0FBQztBQUMzRixNQUFNLElBQUksU0FBUyxJQUFJLEdBQUcsSUFBSSxDQUFDLEdBQUcsQ0FBQyxVQUFVLENBQUMsSUFBSSxDQUFDLE1BQU0sSUFBSSxNQUFNLENBQUMsTUFBTSxDQUFDLEdBQUcsS0FBSyxTQUFTLENBQUMsRUFBRSxPQUFPLElBQUksQ0FBQyx5QkFBeUIsQ0FBQztBQUNySSxNQUFNLElBQUksU0FBUyxLQUFLLE1BQU0sRUFBRSxTQUFTLEdBQUcsV0FBVyxFQUFFLGVBQWUsQ0FBQztBQUN6RSxXQUFXLENBQUMsTUFBTSxJQUFJLENBQUMsUUFBUSxDQUFDLGVBQWUsRUFBRSxPQUFPLEVBQUUsT0FBTyxDQUFDLEdBQUcsZUFBZSxDQUFDLEdBQUc7QUFDeEY7QUFDQSxJQUFJLElBQUksU0FBUyxFQUFFO0FBQ25CLE1BQU0sSUFBSSxDQUFDLEdBQUcsQ0FBQyxHQUFHLE1BQU0sQ0FBQyxlQUFlO0FBQ3hDLE1BQU0sSUFBSSxHQUFHLEdBQUcsU0FBUyxFQUFFLE9BQU8sSUFBSSxDQUFDLHdDQUF3QyxDQUFDO0FBQ2hGO0FBQ0E7QUFDQSxJQUFJLElBQUksQ0FBQyxNQUFNLENBQUMsT0FBTyxFQUFFLE1BQU0sQ0FBQyxNQUFNLElBQUksTUFBTSxDQUFDLE9BQU8sQ0FBQyxDQUFDLE1BQU0sSUFBSSxDQUFDLE1BQU0sSUFBSSxDQUFDLE1BQU0sRUFBRSxPQUFPLElBQUksQ0FBQyxtQkFBbUIsQ0FBQztBQUN4SCxJQUFJLE9BQU8sTUFBTTtBQUNqQjs7QUFFQTtBQUNBLEVBQUUsYUFBYSxVQUFVLENBQUMsSUFBSSxFQUFFLFFBQVEsRUFBRSxPQUFPLEVBQUUsWUFBWSxHQUFHLElBQUksQ0FBQyxNQUFNLEtBQUssQ0FBQyxFQUFFO0FBQ3JGO0FBQ0EsSUFBSSxJQUFJLFlBQVksRUFBRTtBQUN0QixNQUFNLElBQUksR0FBRyxHQUFHLElBQUksQ0FBQyxDQUFDLENBQUM7QUFDdkIsTUFBTSxPQUFPLENBQUMsR0FBRyxHQUFHLEdBQUcsQ0FBQztBQUN4QixNQUFNLE9BQU8sUUFBUSxDQUFDLEdBQUcsQ0FBQztBQUMxQjtBQUNBLElBQUksSUFBSSxHQUFHLEdBQUcsRUFBRTtBQUNoQixRQUFRLElBQUksR0FBRyxNQUFNLE9BQU8sQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxHQUFHLElBQUksUUFBUSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7QUFDaEU7QUFDQSxJQUFJLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQyxHQUFHLEVBQUUsS0FBSyxLQUFLLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLENBQUM7QUFDeEQsSUFBSSxPQUFPLEdBQUc7QUFDZDtBQUNBO0FBQ0EsRUFBRSxPQUFPLFlBQVksQ0FBQyxHQUFHLEVBQUU7QUFDM0IsSUFBSSxPQUFPLFdBQVcsQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLENBQUMsS0FBSyxDQUFDLE1BQU0sV0FBVyxDQUFDLEdBQUcsRUFBRSxjQUFjLENBQUMsQ0FBQztBQUNuRjtBQUNBLEVBQUUsYUFBYSxhQUFhLENBQUMsR0FBRyxFQUFFO0FBQ2xDLElBQUksSUFBSSxpQkFBaUIsR0FBRyxNQUFNLElBQUksQ0FBQyxRQUFRLENBQUMsZUFBZSxFQUFFLEdBQUcsQ0FBQztBQUNyRSxJQUFJLElBQUksQ0FBQyxpQkFBaUIsRUFBRSxPQUFPLFdBQVcsQ0FBQyxHQUFHLEVBQUUsWUFBWSxDQUFDO0FBQ2pFLElBQUksT0FBTyxNQUFNLFdBQVcsQ0FBQyxTQUFTLENBQUMsaUJBQWlCLENBQUMsSUFBSSxDQUFDO0FBQzlEO0FBQ0EsRUFBRSxhQUFhLFVBQVUsQ0FBQyxVQUFVLEVBQUU7QUFDdEMsSUFBSSxJQUFJLENBQUMsU0FBUyxDQUFDLFlBQVksRUFBRSxVQUFVLENBQUMsVUFBVSxDQUFDLEdBQUcsTUFBTSxXQUFXLENBQUMsa0JBQWtCLEVBQUU7QUFDaEcsUUFBUSxDQUFDLFNBQVMsQ0FBQyxhQUFhLEVBQUUsVUFBVSxDQUFDLGFBQWEsQ0FBQyxHQUFHLE1BQU0sV0FBVyxDQUFDLHFCQUFxQixFQUFFO0FBQ3ZHLFFBQVEsR0FBRyxHQUFHLE1BQU0sV0FBVyxDQUFDLFNBQVMsQ0FBQyxZQUFZLENBQUM7QUFDdkQsUUFBUSxxQkFBcUIsR0FBRyxNQUFNLFdBQVcsQ0FBQyxTQUFTLENBQUMsYUFBYSxDQUFDO0FBQzFFLFFBQVEsSUFBSSxHQUFHLElBQUksQ0FBQyxHQUFHLEVBQUU7QUFDekIsUUFBUSxTQUFTLEdBQUcsTUFBTSxJQUFJLENBQUMsY0FBYyxDQUFDLENBQUMsT0FBTyxFQUFFLHFCQUFxQixFQUFFLEdBQUcsRUFBRSxVQUFVLEVBQUUsVUFBVSxFQUFFLElBQUksRUFBRSxRQUFRLEVBQUUsSUFBSSxDQUFDLENBQUM7QUFDbEksSUFBSSxNQUFNLElBQUksQ0FBQyxLQUFLLENBQUMsZUFBZSxFQUFFLEdBQUcsRUFBRSxTQUFTLENBQUM7QUFDckQsSUFBSSxPQUFPLENBQUMsVUFBVSxFQUFFLGFBQWEsRUFBRSxHQUFHLEVBQUUsSUFBSSxDQUFDO0FBQ2pEO0FBQ0EsRUFBRSxPQUFPLFVBQVUsQ0FBQyxHQUFHLEVBQUU7QUFDekIsSUFBSSxPQUFPLElBQUksQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLFVBQVUsRUFBRSxHQUFHLENBQUM7QUFDOUM7QUFDQSxFQUFFLGFBQWEsTUFBTSxDQUFDLEdBQUcsRUFBRSxDQUFDLE1BQU0sR0FBRyxJQUFJLEVBQUUsSUFBSSxHQUFHLElBQUksRUFBRSxRQUFRLEdBQUcsS0FBSyxDQUFDLEdBQUcsRUFBRSxFQUFFO0FBQ2hGLElBQUksSUFBSSxNQUFNLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUM7QUFDakMsUUFBUSxNQUFNLEdBQUcsTUFBTSxJQUFJLE1BQU0sWUFBWSxDQUFDLFVBQVUsQ0FBQyxHQUFHLENBQUM7QUFDN0QsSUFBSSxJQUFJLE1BQU0sRUFBRTtBQUNoQixNQUFNLE1BQU0sS0FBSyxJQUFJLFlBQVksQ0FBQyxHQUFHLENBQUM7QUFDdEMsS0FBSyxNQUFNLElBQUksSUFBSSxLQUFLLE1BQU0sR0FBRyxNQUFNLFVBQVUsQ0FBQyxVQUFVLENBQUMsR0FBRyxDQUFDLENBQUMsRUFBRTtBQUNwRSxNQUFNLE1BQU0sS0FBSyxJQUFJLFVBQVUsQ0FBQyxHQUFHLENBQUM7QUFDcEMsS0FBSyxNQUFNLElBQUksUUFBUSxLQUFLLE1BQU0sR0FBRyxNQUFNLGNBQWMsQ0FBQyxVQUFVLENBQUMsR0FBRyxDQUFDLENBQUMsRUFBRTtBQUM1RSxNQUFNLE1BQU0sS0FBSyxJQUFJLGNBQWMsQ0FBQyxHQUFHLENBQUM7QUFDeEM7QUFDQTtBQUNBLElBQUksSUFBSSxNQUFNLEVBQUUsTUFBTTtBQUN0QixRQUFRLE1BQU0sQ0FBQyxNQUFNLENBQUMsZUFBZSxDQUFDLEdBQUcsS0FBSyxNQUFNLEVBQUUsZUFBZSxDQUFDLEdBQUc7QUFDekUsUUFBUSxNQUFNLENBQUMsTUFBTSxDQUFDLElBQUksS0FBSyxNQUFNLEVBQUUsSUFBSTtBQUMzQyxRQUFRLE1BQU0sQ0FBQyxhQUFhLElBQUksTUFBTSxDQUFDLFVBQVUsRUFBRSxPQUFPLE1BQU07QUFDaEUsSUFBSSxJQUFJLE1BQU0sRUFBRSxNQUFNLENBQUMsTUFBTSxHQUFHLE1BQU07QUFDdEMsU0FBUztBQUNULE1BQU0sSUFBSSxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUM7QUFDckIsTUFBTSxPQUFPLFdBQVcsQ0FBQyxHQUFHLEVBQUUsU0FBUyxDQUFDO0FBQ3hDO0FBQ0EsSUFBSSxPQUFPLE1BQU0sQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxDQUFDLElBQUk7QUFDNUMsTUFBTSxTQUFTLElBQUksTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLEVBQUUsU0FBUyxDQUFDO0FBQ25ELE1BQU0sS0FBSyxJQUFJO0FBQ2YsUUFBUSxJQUFJLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxHQUFHO0FBQzdCLFFBQVEsT0FBTyxLQUFLLENBQUMsR0FBRyxJQUFJLENBQUMsOENBQThDLEVBQUUsR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFLE1BQU0sQ0FBQyxHQUFHLEVBQUUsS0FBSyxDQUFDO0FBQ3ZHLE9BQU8sQ0FBQztBQUNSO0FBQ0EsRUFBRSxPQUFPLE9BQU8sQ0FBQyxJQUFJLEVBQUU7QUFDdkIsSUFBSSxPQUFPLE9BQU8sQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxHQUFHLElBQUksTUFBTSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQztBQUMxRCxPQUFPLEtBQUssQ0FBQyxNQUFNLE1BQU0sSUFBSTtBQUM3QixRQUFRLEtBQUssSUFBSSxTQUFTLElBQUksSUFBSSxFQUFFO0FBQ3BDLFVBQVUsSUFBSSxNQUFNLEdBQUcsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLFNBQVMsRUFBRSxDQUFDLE1BQU0sRUFBRSxLQUFLLEVBQUUsSUFBSSxFQUFFLEtBQUssRUFBRSxRQUFRLEVBQUUsSUFBSSxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsTUFBTSxJQUFJLENBQUM7QUFDckgsVUFBVSxJQUFJLE1BQU0sRUFBRSxPQUFPLE1BQU07QUFDbkM7QUFDQSxRQUFRLE1BQU0sTUFBTTtBQUNwQixPQUFPLENBQUM7QUFDUjtBQUNBLEVBQUUsYUFBYSxPQUFPLENBQUMsR0FBRyxFQUFFLElBQUksRUFBRSxZQUFZLEVBQUUsSUFBSSxHQUFHLElBQUksQ0FBQyxHQUFHLEVBQUUsRUFBRSxVQUFVLEdBQUcsWUFBWSxFQUFFO0FBQzlGLElBQUksSUFBSSxDQUFDLFVBQVUsQ0FBQyxHQUFHLElBQUk7QUFDM0IsUUFBUSxPQUFPLEdBQUcsTUFBTSxJQUFJLENBQUMsSUFBSSxDQUFDLElBQUksRUFBRSxZQUFZLENBQUM7QUFDckQsUUFBUSxTQUFTLEdBQUcsTUFBTSxJQUFJLENBQUMsY0FBYyxDQUFDLENBQUMsT0FBTyxFQUFFLE9BQU8sRUFBRSxHQUFHLEVBQUUsVUFBVSxFQUFFLFVBQVUsRUFBRSxJQUFJLEVBQUUsUUFBUSxFQUFFLElBQUksQ0FBQyxDQUFDO0FBQ3BILElBQUksTUFBTSxJQUFJLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxVQUFVLEVBQUUsR0FBRyxFQUFFLFNBQVMsQ0FBQztBQUNyRDs7QUFFQTtBQUNBLEVBQUUsYUFBYSxLQUFLLENBQUMsY0FBYyxFQUFFLEdBQUcsRUFBRSxTQUFTLEVBQUU7QUFDckQsSUFBSSxJQUFJLGNBQWMsS0FBSyxZQUFZLENBQUMsVUFBVSxFQUFFO0FBQ3BEO0FBQ0EsTUFBTSxJQUFJLFdBQVcsQ0FBQyxpQkFBaUIsQ0FBQyxTQUFTLENBQUMsRUFBRSxPQUFPLFVBQVUsQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDO0FBQ2pGLE1BQU0sT0FBTyxVQUFVLENBQUMsR0FBRyxDQUFDLEdBQUcsRUFBRSxTQUFTLENBQUM7QUFDM0M7QUFDQSxJQUFJLE9BQU8sTUFBTSxDQUFDLE9BQU8sQ0FBQyxLQUFLLENBQUMsY0FBYyxFQUFFLEdBQUcsRUFBRSxTQUFTLENBQUM7QUFDL0Q7QUFDQSxFQUFFLGFBQWEsUUFBUSxDQUFDLGNBQWMsRUFBRSxHQUFHLEVBQUUsVUFBVSxHQUFHLEtBQUssRUFBRTtBQUNqRTtBQUNBLElBQUksSUFBSSxRQUFRLEdBQUcsQ0FBQyxVQUFVLElBQUksSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUM7QUFDbEQsSUFBSSxJQUFJLFFBQVEsRUFBRSxXQUFXLENBQUMsVUFBVSxLQUFLLGNBQWMsRUFBRSxPQUFPLFFBQVEsQ0FBQyxNQUFNO0FBQ25GLElBQUksSUFBSSxPQUFPLEdBQUcsQ0FBQyxjQUFjLEtBQUssWUFBWSxDQUFDLFVBQVUsSUFBSSxVQUFVLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFHLE1BQU0sQ0FBQyxPQUFPLENBQUMsUUFBUSxDQUFDLGNBQWMsRUFBRSxHQUFHLENBQUM7QUFDbkksUUFBUSxTQUFTLEdBQUcsTUFBTSxPQUFPO0FBQ2pDLFFBQVEsR0FBRyxHQUFHLFNBQVMsSUFBSSxNQUFNLE1BQU0sQ0FBQyxZQUFZLENBQUMsR0FBRyxDQUFDO0FBQ3pELElBQUksSUFBSSxDQUFDLFNBQVMsRUFBRTtBQUNwQjtBQUNBO0FBQ0EsSUFBSSxJQUFJLFNBQVMsQ0FBQyxVQUFVLEVBQUUsR0FBRyxHQUFHLENBQUMsQ0FBQyxHQUFHLEdBQUcsR0FBRyxDQUFDLENBQUM7QUFDakQsSUFBSSxPQUFPLE1BQU0sV0FBVyxDQUFDLE1BQU0sQ0FBQyxHQUFHLEVBQUUsU0FBUyxDQUFDO0FBQ25EO0FBQ0E7O0FBRU8sTUFBTSxZQUFZLFNBQVMsTUFBTSxDQUFDO0FBQ3pDLEVBQUUsT0FBTyxjQUFjLENBQUMsQ0FBQyxPQUFPLEVBQUUsR0FBRyxFQUFFLFVBQVUsRUFBRSxJQUFJLENBQUMsRUFBRTtBQUMxRDtBQUNBO0FBQ0E7QUFDQTtBQUNBLElBQUksT0FBTyxJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sRUFBRSxDQUFDLElBQUksRUFBRSxDQUFDLEdBQUcsQ0FBQyxFQUFFLFVBQVUsRUFBRSxJQUFJLENBQUMsQ0FBQztBQUM5RDtBQUNBLEVBQUUsYUFBYSxXQUFXLENBQUMsR0FBRyxFQUFFLE1BQU0sRUFBRTtBQUN4QyxJQUFJLElBQUksTUFBTSxJQUFJLE1BQU0sSUFBSSxDQUFDLFNBQVMsQ0FBQyxHQUFHLEVBQUUsTUFBTSxDQUFDO0FBQ25EO0FBQ0E7QUFDQSxJQUFJLE9BQU8sV0FBVyxDQUFDLGlCQUFpQixDQUFDLE1BQU0sQ0FBQztBQUNoRDtBQUNBLEVBQUUsYUFBYSxJQUFJLENBQUMsSUFBSSxFQUFFLE1BQU0sR0FBRyxFQUFFLEVBQUU7QUFDdkMsSUFBSSxJQUFJLENBQUMsYUFBYSxFQUFFLFVBQVUsRUFBRSxHQUFHLENBQUMsR0FBRyxJQUFJO0FBQy9DLFFBQVEsUUFBUSxHQUFHLENBQUMsYUFBYSxFQUFFLFVBQVUsQ0FBQztBQUM5QyxRQUFRLFdBQVcsR0FBRyxNQUFNLElBQUksQ0FBQyxXQUFXLENBQUMsR0FBRyxFQUFFLE1BQU0sQ0FBQztBQUN6RCxJQUFJLE9BQU8sV0FBVyxDQUFDLE9BQU8sQ0FBQyxRQUFRLEVBQUUsV0FBVyxFQUFFLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQztBQUNoRTtBQUNBLEVBQUUsTUFBTSxNQUFNLENBQUMsVUFBVSxFQUFFO0FBQzNCLElBQUksSUFBSSxNQUFNLEdBQUcsVUFBVSxDQUFDLElBQUksSUFBSSxVQUFVLENBQUMsSUFBSTs7QUFFbkQ7QUFDQSxRQUFRLGVBQWUsR0FBRyxXQUFXLENBQUMscUJBQXFCLENBQUMsTUFBTSxDQUFDO0FBQ25FLFFBQVEsTUFBTSxHQUFHLGVBQWUsQ0FBQyxNQUFNOztBQUV2QyxRQUFRLFdBQVcsR0FBRyxNQUFNLElBQUksQ0FBQyxXQUFXLENBQUMsV0FBVyxDQUFDLElBQUksQ0FBQyxHQUFHLEVBQUUsTUFBTSxDQUFDO0FBQzFFLFFBQVEsUUFBUSxHQUFHLENBQUMsTUFBTSxXQUFXLENBQUMsT0FBTyxDQUFDLFdBQVcsRUFBRSxNQUFNLENBQUMsRUFBRSxJQUFJO0FBQ3hFLElBQUksT0FBTyxNQUFNLFdBQVcsQ0FBQyxTQUFTLENBQUMsUUFBUSxFQUFFLENBQUMsYUFBYSxFQUFFLFNBQVMsRUFBRSxVQUFVLEVBQUUsTUFBTSxDQUFDLENBQUM7QUFDaEc7QUFDQSxFQUFFLGFBQWEsU0FBUyxDQUFDLEdBQUcsRUFBRSxNQUFNLEVBQUU7QUFDdEMsSUFBSSxPQUFPLE1BQU0sQ0FBQyxtQkFBbUIsQ0FBQyxHQUFHLEVBQUUsTUFBTSxDQUFDO0FBQ2xEO0FBQ0E7O0FBRUE7QUFDTyxNQUFNLGNBQWMsU0FBUyxZQUFZLENBQUM7QUFDakQsRUFBRSxPQUFPLFVBQVUsR0FBRyxhQUFhO0FBQ25DOztBQUVBO0FBQ08sTUFBTSxZQUFZLFNBQVMsWUFBWSxDQUFDO0FBQy9DLEVBQUUsT0FBTyxVQUFVLEdBQUcsUUFBUTtBQUM5QixFQUFFLE9BQU8sSUFBSSxHQUFHO0FBQ2hCLElBQUksT0FBTyxVQUFVLENBQUMsT0FBTyxFQUFFO0FBQy9CO0FBQ0E7QUFDQSxNQUFNLFVBQVUsR0FBRyxJQUFJQyxZQUFZLENBQUMsQ0FBQyxJQUFJLEVBQUUsWUFBWSxDQUFDLFVBQVUsQ0FBQyxDQUFDOztBQUU3RCxNQUFNLFVBQVUsU0FBUyxNQUFNLENBQUM7QUFDdkMsRUFBRSxPQUFPLFVBQVUsR0FBRyxNQUFNO0FBQzVCLEVBQUUsT0FBTyxjQUFjLENBQUMsQ0FBQyxPQUFPLEVBQUUsR0FBRyxFQUFFLEdBQUcsT0FBTyxDQUFDLEVBQUU7QUFDcEQsSUFBSSxPQUFPLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxFQUFFLENBQUMsSUFBSSxFQUFFLEdBQUcsRUFBRSxHQUFHLE9BQU8sQ0FBQyxDQUFDO0FBQ3REO0FBQ0EsRUFBRSxhQUFhLElBQUksQ0FBQyxJQUFJLEVBQUUsT0FBTyxFQUFFO0FBQ25DO0FBQ0EsSUFBSSxJQUFJLENBQUMsYUFBYSxFQUFFLFVBQVUsQ0FBQyxHQUFHLElBQUk7QUFDMUMsUUFBUSxPQUFPLEdBQUcsQ0FBQyxhQUFhLEVBQUUsVUFBVSxDQUFDO0FBQzdDLFFBQVEsV0FBVyxHQUFHLEVBQUU7QUFDeEIsSUFBSSxNQUFNLE9BQU8sQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxTQUFTLElBQUksTUFBTSxDQUFDLGFBQWEsQ0FBQyxTQUFTLENBQUMsQ0FBQyxJQUFJLENBQUMsR0FBRyxJQUFJLFdBQVcsQ0FBQyxTQUFTLENBQUMsR0FBRyxHQUFHLENBQUMsQ0FBQyxDQUFDO0FBQzFILElBQUksSUFBSSxXQUFXLEdBQUcsTUFBTSxXQUFXLENBQUMsT0FBTyxDQUFDLE9BQU8sRUFBRSxXQUFXLENBQUM7QUFDckUsSUFBSSxPQUFPLFdBQVc7QUFDdEI7QUFDQSxFQUFFLE1BQU0sTUFBTSxDQUFDLE9BQU8sRUFBRTtBQUN4QixJQUFJLElBQUksQ0FBQyxVQUFVLENBQUMsR0FBRyxPQUFPLENBQUMsSUFBSTtBQUNuQyxRQUFRLFVBQVUsR0FBRyxJQUFJLENBQUMsVUFBVSxHQUFHLFVBQVUsQ0FBQyxHQUFHLENBQUMsU0FBUyxJQUFJLFNBQVMsQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDO0FBQ3hGLElBQUksSUFBSSxNQUFNLEdBQUcsTUFBTSxJQUFJLENBQUMsV0FBVyxDQUFDLE9BQU8sQ0FBQyxVQUFVLENBQUMsQ0FBQztBQUM1RCxJQUFJLElBQUksU0FBUyxHQUFHLE1BQU0sTUFBTSxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDO0FBQ3RELElBQUksT0FBTyxNQUFNLFdBQVcsQ0FBQyxTQUFTLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQztBQUN0RDtBQUNBLEVBQUUsTUFBTSxnQkFBZ0IsQ0FBQyxDQUFDLEdBQUcsR0FBRyxFQUFFLEVBQUUsTUFBTSxHQUFHLEVBQUUsQ0FBQyxHQUFHLEVBQUUsRUFBRTtBQUN2RCxJQUFJLElBQUksQ0FBQyxVQUFVLENBQUMsR0FBRyxJQUFJO0FBQzNCLFFBQVEsVUFBVSxHQUFHLFVBQVUsQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUMsTUFBTSxDQUFDLEdBQUcsSUFBSSxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsR0FBRyxDQUFDLENBQUM7QUFDaEYsSUFBSSxNQUFNLElBQUksQ0FBQyxXQUFXLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQyxHQUFHLEVBQUUsSUFBSSxFQUFFLFVBQVUsRUFBRSxJQUFJLENBQUMsR0FBRyxFQUFFLEVBQUUsVUFBVSxDQUFDO0FBQ3RGLElBQUksSUFBSSxDQUFDLFVBQVUsR0FBRyxVQUFVO0FBQ2hDLElBQUksSUFBSSxDQUFDLFdBQVcsQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQztBQUNwQztBQUNBOzs7Ozs7OztBQ3RVTyxNQUFNLENBQUMsSUFBSSxFQUFFLE9BQU8sQ0FBQyxHQUFHQyxRQUFXOztBQ0lyQyxNQUFDLFFBQVEsR0FBRzs7QUFFakIsRUFBRSxJQUFJLE1BQU0sR0FBRyxFQUFFLE9BQU8sTUFBTSxDQUFDLEVBQUU7QUFDakM7QUFDQSxFQUFFLElBQUksT0FBTyxDQUFDLE9BQU8sRUFBRTtBQUN2QixJQUFJLE1BQU0sQ0FBQyxPQUFPLEdBQUcsT0FBTztBQUM1QixHQUFHO0FBQ0gsRUFBRSxJQUFJLE9BQU8sR0FBRztBQUNoQixJQUFJLE9BQU8sTUFBTSxDQUFDLE9BQU87QUFDekIsR0FBRztBQUNILEVBQUUsSUFBSSxtQkFBbUIsQ0FBQyxzQkFBc0IsRUFBRTtBQUNsRCxJQUFJLE1BQU0sQ0FBQyxtQkFBbUIsR0FBRyxzQkFBc0I7QUFDdkQsR0FBRztBQUNILEVBQUUsSUFBSSxtQkFBbUIsR0FBRztBQUM1QixJQUFJLE9BQU8sTUFBTSxDQUFDLG1CQUFtQjtBQUNyQyxHQUFHO0FBQ0gsRUFBRSxLQUFLLEVBQUUsQ0FBQyxJQUFJLEVBQUUsT0FBTyxFQUFFLE1BQU0sRUFBRSxNQUFNLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQzs7QUFFdkQ7QUFDQSxFQUFFLE1BQU0sT0FBTyxDQUFDLE9BQU8sRUFBRSxHQUFHLElBQUksRUFBRTtBQUNsQyxJQUFJLElBQUksT0FBTyxHQUFHLEVBQUUsRUFBRSxJQUFJLEdBQUcsSUFBSSxDQUFDLHNCQUFzQixDQUFDLElBQUksRUFBRSxPQUFPLENBQUM7QUFDdkUsUUFBUSxHQUFHLEdBQUcsTUFBTSxNQUFNLENBQUMsVUFBVSxDQUFDLElBQUksRUFBRSxHQUFHLElBQUksTUFBTSxDQUFDLGFBQWEsQ0FBQyxHQUFHLENBQUMsRUFBRSxPQUFPLENBQUM7QUFDdEYsSUFBSSxPQUFPLFdBQVcsQ0FBQyxPQUFPLENBQUMsR0FBRyxFQUFFLE9BQU8sRUFBRSxPQUFPLENBQUM7QUFDckQsR0FBRztBQUNILEVBQUUsTUFBTSxPQUFPLENBQUMsU0FBUyxFQUFFLEdBQUcsSUFBSSxFQUFFO0FBQ3BDLElBQUksSUFBSSxPQUFPLEdBQUcsRUFBRTtBQUNwQixRQUFRLENBQUMsR0FBRyxDQUFDLEdBQUcsSUFBSSxDQUFDLHNCQUFzQixDQUFDLElBQUksRUFBRSxPQUFPLEVBQUUsU0FBUyxDQUFDO0FBQ3JFLFFBQVEsQ0FBQyxRQUFRLEVBQUUsR0FBRyxZQUFZLENBQUMsR0FBRyxPQUFPO0FBQzdDLFFBQVEsTUFBTSxHQUFHLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxHQUFHLEVBQUUsQ0FBQyxRQUFRLENBQUMsQ0FBQztBQUNyRCxJQUFJLE9BQU8sTUFBTSxDQUFDLE9BQU8sQ0FBQyxTQUFTLEVBQUUsWUFBWSxDQUFDO0FBQ2xELEdBQUc7QUFDSCxFQUFFLE1BQU0sSUFBSSxDQUFDLE9BQU8sRUFBRSxHQUFHLElBQUksRUFBRTtBQUMvQixJQUFJLElBQUksT0FBTyxHQUFHLEVBQUUsRUFBRSxJQUFJLEdBQUcsSUFBSSxDQUFDLHNCQUFzQixDQUFDLElBQUksRUFBRSxPQUFPLENBQUM7QUFDdkUsSUFBSSxPQUFPLE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxFQUFFLENBQUMsSUFBSSxFQUFFLEdBQUcsT0FBTyxDQUFDLENBQUM7QUFDbkQsR0FBRztBQUNILEVBQUUsTUFBTSxNQUFNLENBQUMsU0FBUyxFQUFFLEdBQUcsSUFBSSxFQUFFO0FBQ25DLElBQUksSUFBSSxPQUFPLEdBQUcsRUFBRSxFQUFFLElBQUksR0FBRyxJQUFJLENBQUMsc0JBQXNCLENBQUMsSUFBSSxFQUFFLE9BQU8sRUFBRSxTQUFTLENBQUM7QUFDbEYsSUFBSSxPQUFPLE1BQU0sQ0FBQyxNQUFNLENBQUMsU0FBUyxFQUFFLElBQUksRUFBRSxPQUFPLENBQUM7QUFDbEQsR0FBRzs7QUFFSDtBQUNBLEVBQUUsTUFBTSxNQUFNLENBQUMsR0FBRyxPQUFPLEVBQUU7QUFDM0IsSUFBSSxJQUFJLENBQUMsT0FBTyxDQUFDLE1BQU0sRUFBRSxPQUFPLE1BQU0sWUFBWSxDQUFDLE1BQU0sRUFBRTtBQUMzRCxJQUFJLElBQUksTUFBTSxHQUFHLE9BQU8sQ0FBQyxDQUFDLENBQUMsQ0FBQyxNQUFNO0FBQ2xDLElBQUksSUFBSSxNQUFNLEVBQUUsT0FBTyxNQUFNLGNBQWMsQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDO0FBQzFELElBQUksT0FBTyxNQUFNLFVBQVUsQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDO0FBQzNDLEdBQUc7QUFDSCxFQUFFLE1BQU0sZ0JBQWdCLENBQUMsQ0FBQyxHQUFHLEVBQUUsUUFBUSxHQUFHLEtBQUssRUFBRSxHQUFHLE9BQU8sQ0FBQyxFQUFFO0FBQzlELElBQUksSUFBSSxNQUFNLEdBQUcsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLEdBQUcsRUFBRSxDQUFDLFFBQVEsRUFBRSxHQUFHLE9BQU8sQ0FBQyxDQUFDLENBQUM7QUFDbEUsSUFBSSxPQUFPLE1BQU0sQ0FBQyxnQkFBZ0IsQ0FBQyxPQUFPLENBQUM7QUFDM0MsR0FBRztBQUNILEVBQUUsTUFBTSxPQUFPLENBQUMsWUFBWSxFQUFFO0FBQzlCLElBQUksSUFBSSxRQUFRLEtBQUssT0FBTyxZQUFZLEVBQUUsWUFBWSxHQUFHLENBQUMsR0FBRyxFQUFFLFlBQVksQ0FBQztBQUM1RSxJQUFJLElBQUksQ0FBQyxHQUFHLEVBQUUsUUFBUSxHQUFHLElBQUksRUFBRSxHQUFHLFlBQVksQ0FBQyxHQUFHLFlBQVk7QUFDOUQsUUFBUSxPQUFPLEdBQUcsQ0FBQyxRQUFRLEVBQUUsR0FBRyxZQUFZLENBQUM7QUFDN0MsUUFBUSxNQUFNLEdBQUcsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLEdBQUcsRUFBRSxPQUFPLENBQUM7QUFDbEQsSUFBSSxPQUFPLE1BQU0sQ0FBQyxPQUFPLENBQUMsT0FBTyxDQUFDO0FBQ2xDLEdBQUc7QUFDSCxFQUFFLEtBQUssQ0FBQyxHQUFHLEVBQUU7QUFDYixJQUFJLE1BQU0sQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDO0FBQ3JCLEdBQUc7QUFDSCxFQUFFLGNBQWMsR0FBRztBQUNuQixJQUFJLE9BQU8sWUFBWSxDQUFDLElBQUksRUFBRTtBQUM5QixHQUFHOztBQUVIO0FBQ0EsRUFBRSxVQUFVLEVBQUUsUUFBUSxFQUFFLGVBQWUsRUFBRSxlQUFlLEVBQUUsWUFBWTs7QUFFdEUsRUFBRSxzQkFBc0IsQ0FBQyxJQUFJLEVBQUUsT0FBTyxFQUFFLEtBQUssRUFBRTtBQUMvQztBQUNBO0FBQ0E7QUFDQSxJQUFJLElBQUksSUFBSSxDQUFDLE1BQU0sR0FBRyxDQUFDLElBQUksSUFBSSxDQUFDLENBQUMsQ0FBQyxFQUFFLE1BQU0sS0FBSyxTQUFTLEVBQUUsT0FBTyxJQUFJO0FBQ3JFLElBQUksSUFBSSxDQUFDLElBQUksR0FBRyxFQUFFLEVBQUUsV0FBVyxFQUFFLElBQUksRUFBRSxHQUFHLE1BQU0sQ0FBQyxHQUFHLElBQUksQ0FBQyxDQUFDLENBQUMsSUFBSSxFQUFFO0FBQ2pFLENBQUMsQ0FBQyxJQUFJLENBQUMsR0FBRyxNQUFNLENBQUM7QUFDakIsSUFBSSxJQUFJLENBQUMsSUFBSSxDQUFDLE1BQU0sRUFBRTtBQUN0QixNQUFNLElBQUksSUFBSSxDQUFDLE1BQU0sSUFBSSxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUMsTUFBTSxFQUFFLElBQUksR0FBRyxJQUFJLENBQUM7QUFDckQsV0FBVyxJQUFJLEtBQUssRUFBRTtBQUN0QixRQUFRLElBQUksS0FBSyxDQUFDLFVBQVUsRUFBRSxJQUFJLEdBQUcsS0FBSyxDQUFDLFVBQVUsQ0FBQyxHQUFHLENBQUMsR0FBRyxJQUFJLFdBQVcsQ0FBQyxxQkFBcUIsQ0FBQyxHQUFHLENBQUMsQ0FBQyxHQUFHLENBQUM7QUFDNUcsYUFBYSxJQUFJLEtBQUssQ0FBQyxVQUFVLEVBQUUsSUFBSSxHQUFHLEtBQUssQ0FBQyxVQUFVLENBQUMsR0FBRyxDQUFDLEdBQUcsSUFBSSxHQUFHLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQztBQUNyRixhQUFhO0FBQ2IsVUFBVSxJQUFJLEdBQUcsR0FBRyxXQUFXLENBQUMscUJBQXFCLENBQUMsS0FBSyxDQUFDLENBQUMsR0FBRyxDQUFDO0FBQ2pFLFVBQVUsSUFBSSxHQUFHLEVBQUUsSUFBSSxHQUFHLENBQUMsR0FBRyxDQUFDO0FBQy9CO0FBQ0E7QUFDQTtBQUNBLElBQUksSUFBSSxJQUFJLElBQUksQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxFQUFFLElBQUksR0FBRyxDQUFDLElBQUksRUFBRSxHQUFHLElBQUksQ0FBQztBQUM1RCxJQUFJLElBQUksV0FBVyxFQUFFLE9BQU8sQ0FBQyxHQUFHLEdBQUcsV0FBVztBQUM5QyxJQUFJLElBQUksSUFBSSxFQUFFLE9BQU8sQ0FBQyxHQUFHLEdBQUcsSUFBSTtBQUNoQyxJQUFJLE1BQU0sQ0FBQyxNQUFNLENBQUMsT0FBTyxFQUFFLE1BQU0sQ0FBQzs7QUFFbEMsSUFBSSxPQUFPLElBQUk7QUFDZjtBQUNBOzs7OyIsInhfZ29vZ2xlX2lnbm9yZUxpc3QiOlsxLDIsMyw0LDUsNiw3LDgsOSwxMCwxMSwxMiwxMywxNCwxNSwxNiwxNywxOCwxOSwyMCwyMSwyMiwyMywyNCwyNSwyNiwyNywyOCwyOSwzMCwzMSwzMiwzMywzNCwzNSwzNiwzNywzOCwzOSw0MCw0MSw0Miw0Myw0NCw0NSw0Niw0Nyw0OCw0OSw1MCw1MSw1Miw1Myw1NCw1NSw1Niw1Nyw1OCw1OSw2MF19
