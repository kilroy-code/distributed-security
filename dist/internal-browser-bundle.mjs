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

export { DeviceKeySet, Security as InternalSecurity, KeySet, Krypto, StorageCache as LocalCollection, MultiKrypto, TeamKeySet, dispatch };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW50ZXJuYWwtYnJvd3Nlci1idW5kbGUubWpzIiwic291cmNlcyI6WyIuLi9saWIvY3J5cHRvLWJyb3dzZXIubWpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvd2ViY3J5cHRvLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvZGlnZXN0LmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9idWZmZXJfdXRpbHMuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9iYXNlNjR1cmwuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvdXRpbC9lcnJvcnMuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9yYW5kb20uanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2l2LmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9jaGVja19pdl9sZW5ndGguanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9jaGVja19jZWtfbGVuZ3RoLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvdGltaW5nX3NhZmVfZXF1YWwuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2NyeXB0b19rZXkuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2ludmFsaWRfa2V5X2lucHV0LmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvaXNfa2V5X2xpa2UuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9kZWNyeXB0LmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9pc19kaXNqb2ludC5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvaXNfb2JqZWN0LmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvYm9ndXMuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9hZXNrdy5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2VjZGhlcy5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvY2hlY2tfcDJzLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvcGJlczJrdy5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3N1YnRsZV9yc2Flcy5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2NoZWNrX2tleV9sZW5ndGguanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9yc2Flcy5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvaXNfandrLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvandrX3RvX2tleS5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL25vcm1hbGl6ZV9rZXkuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2Nlay5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9rZXkvaW1wb3J0LmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9jaGVja19rZXlfdHlwZS5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2VuY3J5cHQuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2Flc2djbWt3LmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9kZWNyeXB0X2tleV9tYW5hZ2VtZW50LmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi92YWxpZGF0ZV9jcml0LmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi92YWxpZGF0ZV9hbGdvcml0aG1zLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3ZS9mbGF0dGVuZWQvZGVjcnlwdC5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd2UvY29tcGFjdC9kZWNyeXB0LmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3ZS9nZW5lcmFsL2RlY3J5cHQuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL3ByaXZhdGVfc3ltYm9scy5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2tleV90b19qd2suanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIva2V5L2V4cG9ydC5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvZW5jcnlwdF9rZXlfbWFuYWdlbWVudC5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd2UvZmxhdHRlbmVkL2VuY3J5cHQuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandlL2dlbmVyYWwvZW5jcnlwdC5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3N1YnRsZV9kc2EuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9nZXRfc2lnbl92ZXJpZnlfa2V5LmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvdmVyaWZ5LmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9mbGF0dGVuZWQvdmVyaWZ5LmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9jb21wYWN0L3ZlcmlmeS5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd3MvZ2VuZXJhbC92ZXJpZnkuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandlL2NvbXBhY3QvZW5jcnlwdC5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3NpZ24uanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandzL2ZsYXR0ZW5lZC9zaWduLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9jb21wYWN0L3NpZ24uanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandzL2dlbmVyYWwvc2lnbi5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci91dGlsL2Jhc2U2NHVybC5qcyIsIi4uLy4uLy4uLy4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci91dGlsL2RlY29kZV9wcm90ZWN0ZWRfaGVhZGVyLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvZ2VuZXJhdGUuanMiLCIuLi8uLi8uLi8uLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIva2V5L2dlbmVyYXRlX2tleV9wYWlyLmpzIiwiLi4vLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2tleS9nZW5lcmF0ZV9zZWNyZXQuanMiLCIuLi9saWIvYWxnb3JpdGhtcy5tanMiLCIuLi9saWIvdXRpbGl0aWVzLm1qcyIsIi4uL2xpYi9yYXctYnJvd3Nlci5tanMiLCIuLi9saWIva3J5cHRvLm1qcyIsIi4uL2xpYi9tdWx0aUtyeXB0by5tanMiLCIuLi8uLi9jYWNoZS9pbmRleC5tanMiLCIuLi8uLi9zdG9yYWdlL2J1bmRsZS5tanMiLCIuLi9saWIvc2VjcmV0Lm1qcyIsIi4uL2xpYi9vcmlnaW4tYnJvd3Nlci5tanMiLCIuLi9saWIvdGFnUGF0aC5tanMiLCIuLi9saWIvc3RvcmFnZS5tanMiLCIuLi9saWIva2V5U2V0Lm1qcyIsIi4uL2xpYi9wYWNrYWdlLWxvYWRlci5tanMiLCIuLi9saWIvYXBpLm1qcyIsIi4uLy4uL2pzb25ycGMvaW5kZXgubWpzIl0sInNvdXJjZXNDb250ZW50IjpbImV4cG9ydCBkZWZhdWx0IGNyeXB0bztcbiIsImV4cG9ydCBkZWZhdWx0IGNyeXB0bztcbmV4cG9ydCBjb25zdCBpc0NyeXB0b0tleSA9IChrZXkpID0+IGtleSBpbnN0YW5jZW9mIENyeXB0b0tleTtcbiIsImltcG9ydCBjcnlwdG8gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuY29uc3QgZGlnZXN0ID0gYXN5bmMgKGFsZ29yaXRobSwgZGF0YSkgPT4ge1xuICAgIGNvbnN0IHN1YnRsZURpZ2VzdCA9IGBTSEEtJHthbGdvcml0aG0uc2xpY2UoLTMpfWA7XG4gICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZGlnZXN0KHN1YnRsZURpZ2VzdCwgZGF0YSkpO1xufTtcbmV4cG9ydCBkZWZhdWx0IGRpZ2VzdDtcbiIsImltcG9ydCBkaWdlc3QgZnJvbSAnLi4vcnVudGltZS9kaWdlc3QuanMnO1xuZXhwb3J0IGNvbnN0IGVuY29kZXIgPSBuZXcgVGV4dEVuY29kZXIoKTtcbmV4cG9ydCBjb25zdCBkZWNvZGVyID0gbmV3IFRleHREZWNvZGVyKCk7XG5jb25zdCBNQVhfSU5UMzIgPSAyICoqIDMyO1xuZXhwb3J0IGZ1bmN0aW9uIGNvbmNhdCguLi5idWZmZXJzKSB7XG4gICAgY29uc3Qgc2l6ZSA9IGJ1ZmZlcnMucmVkdWNlKChhY2MsIHsgbGVuZ3RoIH0pID0+IGFjYyArIGxlbmd0aCwgMCk7XG4gICAgY29uc3QgYnVmID0gbmV3IFVpbnQ4QXJyYXkoc2l6ZSk7XG4gICAgbGV0IGkgPSAwO1xuICAgIGZvciAoY29uc3QgYnVmZmVyIG9mIGJ1ZmZlcnMpIHtcbiAgICAgICAgYnVmLnNldChidWZmZXIsIGkpO1xuICAgICAgICBpICs9IGJ1ZmZlci5sZW5ndGg7XG4gICAgfVxuICAgIHJldHVybiBidWY7XG59XG5leHBvcnQgZnVuY3Rpb24gcDJzKGFsZywgcDJzSW5wdXQpIHtcbiAgICByZXR1cm4gY29uY2F0KGVuY29kZXIuZW5jb2RlKGFsZyksIG5ldyBVaW50OEFycmF5KFswXSksIHAyc0lucHV0KTtcbn1cbmZ1bmN0aW9uIHdyaXRlVUludDMyQkUoYnVmLCB2YWx1ZSwgb2Zmc2V0KSB7XG4gICAgaWYgKHZhbHVlIDwgMCB8fCB2YWx1ZSA+PSBNQVhfSU5UMzIpIHtcbiAgICAgICAgdGhyb3cgbmV3IFJhbmdlRXJyb3IoYHZhbHVlIG11c3QgYmUgPj0gMCBhbmQgPD0gJHtNQVhfSU5UMzIgLSAxfS4gUmVjZWl2ZWQgJHt2YWx1ZX1gKTtcbiAgICB9XG4gICAgYnVmLnNldChbdmFsdWUgPj4+IDI0LCB2YWx1ZSA+Pj4gMTYsIHZhbHVlID4+PiA4LCB2YWx1ZSAmIDB4ZmZdLCBvZmZzZXQpO1xufVxuZXhwb3J0IGZ1bmN0aW9uIHVpbnQ2NGJlKHZhbHVlKSB7XG4gICAgY29uc3QgaGlnaCA9IE1hdGguZmxvb3IodmFsdWUgLyBNQVhfSU5UMzIpO1xuICAgIGNvbnN0IGxvdyA9IHZhbHVlICUgTUFYX0lOVDMyO1xuICAgIGNvbnN0IGJ1ZiA9IG5ldyBVaW50OEFycmF5KDgpO1xuICAgIHdyaXRlVUludDMyQkUoYnVmLCBoaWdoLCAwKTtcbiAgICB3cml0ZVVJbnQzMkJFKGJ1ZiwgbG93LCA0KTtcbiAgICByZXR1cm4gYnVmO1xufVxuZXhwb3J0IGZ1bmN0aW9uIHVpbnQzMmJlKHZhbHVlKSB7XG4gICAgY29uc3QgYnVmID0gbmV3IFVpbnQ4QXJyYXkoNCk7XG4gICAgd3JpdGVVSW50MzJCRShidWYsIHZhbHVlKTtcbiAgICByZXR1cm4gYnVmO1xufVxuZXhwb3J0IGZ1bmN0aW9uIGxlbmd0aEFuZElucHV0KGlucHV0KSB7XG4gICAgcmV0dXJuIGNvbmNhdCh1aW50MzJiZShpbnB1dC5sZW5ndGgpLCBpbnB1dCk7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gY29uY2F0S2RmKHNlY3JldCwgYml0cywgdmFsdWUpIHtcbiAgICBjb25zdCBpdGVyYXRpb25zID0gTWF0aC5jZWlsKChiaXRzID4+IDMpIC8gMzIpO1xuICAgIGNvbnN0IHJlcyA9IG5ldyBVaW50OEFycmF5KGl0ZXJhdGlvbnMgKiAzMik7XG4gICAgZm9yIChsZXQgaXRlciA9IDA7IGl0ZXIgPCBpdGVyYXRpb25zOyBpdGVyKyspIHtcbiAgICAgICAgY29uc3QgYnVmID0gbmV3IFVpbnQ4QXJyYXkoNCArIHNlY3JldC5sZW5ndGggKyB2YWx1ZS5sZW5ndGgpO1xuICAgICAgICBidWYuc2V0KHVpbnQzMmJlKGl0ZXIgKyAxKSk7XG4gICAgICAgIGJ1Zi5zZXQoc2VjcmV0LCA0KTtcbiAgICAgICAgYnVmLnNldCh2YWx1ZSwgNCArIHNlY3JldC5sZW5ndGgpO1xuICAgICAgICByZXMuc2V0KGF3YWl0IGRpZ2VzdCgnc2hhMjU2JywgYnVmKSwgaXRlciAqIDMyKTtcbiAgICB9XG4gICAgcmV0dXJuIHJlcy5zbGljZSgwLCBiaXRzID4+IDMpO1xufVxuIiwiaW1wb3J0IHsgZW5jb2RlciwgZGVjb2RlciB9IGZyb20gJy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuZXhwb3J0IGNvbnN0IGVuY29kZUJhc2U2NCA9IChpbnB1dCkgPT4ge1xuICAgIGxldCB1bmVuY29kZWQgPSBpbnB1dDtcbiAgICBpZiAodHlwZW9mIHVuZW5jb2RlZCA9PT0gJ3N0cmluZycpIHtcbiAgICAgICAgdW5lbmNvZGVkID0gZW5jb2Rlci5lbmNvZGUodW5lbmNvZGVkKTtcbiAgICB9XG4gICAgY29uc3QgQ0hVTktfU0laRSA9IDB4ODAwMDtcbiAgICBjb25zdCBhcnIgPSBbXTtcbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IHVuZW5jb2RlZC5sZW5ndGg7IGkgKz0gQ0hVTktfU0laRSkge1xuICAgICAgICBhcnIucHVzaChTdHJpbmcuZnJvbUNoYXJDb2RlLmFwcGx5KG51bGwsIHVuZW5jb2RlZC5zdWJhcnJheShpLCBpICsgQ0hVTktfU0laRSkpKTtcbiAgICB9XG4gICAgcmV0dXJuIGJ0b2EoYXJyLmpvaW4oJycpKTtcbn07XG5leHBvcnQgY29uc3QgZW5jb2RlID0gKGlucHV0KSA9PiB7XG4gICAgcmV0dXJuIGVuY29kZUJhc2U2NChpbnB1dCkucmVwbGFjZSgvPS9nLCAnJykucmVwbGFjZSgvXFwrL2csICctJykucmVwbGFjZSgvXFwvL2csICdfJyk7XG59O1xuZXhwb3J0IGNvbnN0IGRlY29kZUJhc2U2NCA9IChlbmNvZGVkKSA9PiB7XG4gICAgY29uc3QgYmluYXJ5ID0gYXRvYihlbmNvZGVkKTtcbiAgICBjb25zdCBieXRlcyA9IG5ldyBVaW50OEFycmF5KGJpbmFyeS5sZW5ndGgpO1xuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgYmluYXJ5Lmxlbmd0aDsgaSsrKSB7XG4gICAgICAgIGJ5dGVzW2ldID0gYmluYXJ5LmNoYXJDb2RlQXQoaSk7XG4gICAgfVxuICAgIHJldHVybiBieXRlcztcbn07XG5leHBvcnQgY29uc3QgZGVjb2RlID0gKGlucHV0KSA9PiB7XG4gICAgbGV0IGVuY29kZWQgPSBpbnB1dDtcbiAgICBpZiAoZW5jb2RlZCBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgZW5jb2RlZCA9IGRlY29kZXIuZGVjb2RlKGVuY29kZWQpO1xuICAgIH1cbiAgICBlbmNvZGVkID0gZW5jb2RlZC5yZXBsYWNlKC8tL2csICcrJykucmVwbGFjZSgvXy9nLCAnLycpLnJlcGxhY2UoL1xccy9nLCAnJyk7XG4gICAgdHJ5IHtcbiAgICAgICAgcmV0dXJuIGRlY29kZUJhc2U2NChlbmNvZGVkKTtcbiAgICB9XG4gICAgY2F0Y2gge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdUaGUgaW5wdXQgdG8gYmUgZGVjb2RlZCBpcyBub3QgY29ycmVjdGx5IGVuY29kZWQuJyk7XG4gICAgfVxufTtcbiIsImV4cG9ydCBjbGFzcyBKT1NFRXJyb3IgZXh0ZW5kcyBFcnJvciB7XG4gICAgY29uc3RydWN0b3IobWVzc2FnZSwgb3B0aW9ucykge1xuICAgICAgICBzdXBlcihtZXNzYWdlLCBvcHRpb25zKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KT1NFX0dFTkVSSUMnO1xuICAgICAgICB0aGlzLm5hbWUgPSB0aGlzLmNvbnN0cnVjdG9yLm5hbWU7XG4gICAgICAgIEVycm9yLmNhcHR1cmVTdGFja1RyYWNlPy4odGhpcywgdGhpcy5jb25zdHJ1Y3Rvcik7XG4gICAgfVxufVxuSk9TRUVycm9yLmNvZGUgPSAnRVJSX0pPU0VfR0VORVJJQyc7XG5leHBvcnQgY2xhc3MgSldUQ2xhaW1WYWxpZGF0aW9uRmFpbGVkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcihtZXNzYWdlLCBwYXlsb2FkLCBjbGFpbSA9ICd1bnNwZWNpZmllZCcsIHJlYXNvbiA9ICd1bnNwZWNpZmllZCcpIHtcbiAgICAgICAgc3VwZXIobWVzc2FnZSwgeyBjYXVzZTogeyBjbGFpbSwgcmVhc29uLCBwYXlsb2FkIH0gfSk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldUX0NMQUlNX1ZBTElEQVRJT05fRkFJTEVEJztcbiAgICAgICAgdGhpcy5jbGFpbSA9IGNsYWltO1xuICAgICAgICB0aGlzLnJlYXNvbiA9IHJlYXNvbjtcbiAgICAgICAgdGhpcy5wYXlsb2FkID0gcGF5bG9hZDtcbiAgICB9XG59XG5KV1RDbGFpbVZhbGlkYXRpb25GYWlsZWQuY29kZSA9ICdFUlJfSldUX0NMQUlNX1ZBTElEQVRJT05fRkFJTEVEJztcbmV4cG9ydCBjbGFzcyBKV1RFeHBpcmVkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcihtZXNzYWdlLCBwYXlsb2FkLCBjbGFpbSA9ICd1bnNwZWNpZmllZCcsIHJlYXNvbiA9ICd1bnNwZWNpZmllZCcpIHtcbiAgICAgICAgc3VwZXIobWVzc2FnZSwgeyBjYXVzZTogeyBjbGFpbSwgcmVhc29uLCBwYXlsb2FkIH0gfSk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldUX0VYUElSRUQnO1xuICAgICAgICB0aGlzLmNsYWltID0gY2xhaW07XG4gICAgICAgIHRoaXMucmVhc29uID0gcmVhc29uO1xuICAgICAgICB0aGlzLnBheWxvYWQgPSBwYXlsb2FkO1xuICAgIH1cbn1cbkpXVEV4cGlyZWQuY29kZSA9ICdFUlJfSldUX0VYUElSRUQnO1xuZXhwb3J0IGNsYXNzIEpPU0VBbGdOb3RBbGxvd2VkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KT1NFX0FMR19OT1RfQUxMT1dFRCc7XG4gICAgfVxufVxuSk9TRUFsZ05vdEFsbG93ZWQuY29kZSA9ICdFUlJfSk9TRV9BTEdfTk9UX0FMTE9XRUQnO1xuZXhwb3J0IGNsYXNzIEpPU0VOb3RTdXBwb3J0ZWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pPU0VfTk9UX1NVUFBPUlRFRCc7XG4gICAgfVxufVxuSk9TRU5vdFN1cHBvcnRlZC5jb2RlID0gJ0VSUl9KT1NFX05PVF9TVVBQT1JURUQnO1xuZXhwb3J0IGNsYXNzIEpXRURlY3J5cHRpb25GYWlsZWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKG1lc3NhZ2UgPSAnZGVjcnlwdGlvbiBvcGVyYXRpb24gZmFpbGVkJywgb3B0aW9ucykge1xuICAgICAgICBzdXBlcihtZXNzYWdlLCBvcHRpb25zKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0VfREVDUllQVElPTl9GQUlMRUQnO1xuICAgIH1cbn1cbkpXRURlY3J5cHRpb25GYWlsZWQuY29kZSA9ICdFUlJfSldFX0RFQ1JZUFRJT05fRkFJTEVEJztcbmV4cG9ydCBjbGFzcyBKV0VJbnZhbGlkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0VfSU5WQUxJRCc7XG4gICAgfVxufVxuSldFSW52YWxpZC5jb2RlID0gJ0VSUl9KV0VfSU5WQUxJRCc7XG5leHBvcnQgY2xhc3MgSldTSW52YWxpZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldTX0lOVkFMSUQnO1xuICAgIH1cbn1cbkpXU0ludmFsaWQuY29kZSA9ICdFUlJfSldTX0lOVkFMSUQnO1xuZXhwb3J0IGNsYXNzIEpXVEludmFsaWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXVF9JTlZBTElEJztcbiAgICB9XG59XG5KV1RJbnZhbGlkLmNvZGUgPSAnRVJSX0pXVF9JTlZBTElEJztcbmV4cG9ydCBjbGFzcyBKV0tJbnZhbGlkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0tfSU5WQUxJRCc7XG4gICAgfVxufVxuSldLSW52YWxpZC5jb2RlID0gJ0VSUl9KV0tfSU5WQUxJRCc7XG5leHBvcnQgY2xhc3MgSldLU0ludmFsaWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXS1NfSU5WQUxJRCc7XG4gICAgfVxufVxuSldLU0ludmFsaWQuY29kZSA9ICdFUlJfSldLU19JTlZBTElEJztcbmV4cG9ydCBjbGFzcyBKV0tTTm9NYXRjaGluZ0tleSBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IobWVzc2FnZSA9ICdubyBhcHBsaWNhYmxlIGtleSBmb3VuZCBpbiB0aGUgSlNPTiBXZWIgS2V5IFNldCcsIG9wdGlvbnMpIHtcbiAgICAgICAgc3VwZXIobWVzc2FnZSwgb3B0aW9ucyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldLU19OT19NQVRDSElOR19LRVknO1xuICAgIH1cbn1cbkpXS1NOb01hdGNoaW5nS2V5LmNvZGUgPSAnRVJSX0pXS1NfTk9fTUFUQ0hJTkdfS0VZJztcbmV4cG9ydCBjbGFzcyBKV0tTTXVsdGlwbGVNYXRjaGluZ0tleXMgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKG1lc3NhZ2UgPSAnbXVsdGlwbGUgbWF0Y2hpbmcga2V5cyBmb3VuZCBpbiB0aGUgSlNPTiBXZWIgS2V5IFNldCcsIG9wdGlvbnMpIHtcbiAgICAgICAgc3VwZXIobWVzc2FnZSwgb3B0aW9ucyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldLU19NVUxUSVBMRV9NQVRDSElOR19LRVlTJztcbiAgICB9XG59XG5TeW1ib2wuYXN5bmNJdGVyYXRvcjtcbkpXS1NNdWx0aXBsZU1hdGNoaW5nS2V5cy5jb2RlID0gJ0VSUl9KV0tTX01VTFRJUExFX01BVENISU5HX0tFWVMnO1xuZXhwb3J0IGNsYXNzIEpXS1NUaW1lb3V0IGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcihtZXNzYWdlID0gJ3JlcXVlc3QgdGltZWQgb3V0Jywgb3B0aW9ucykge1xuICAgICAgICBzdXBlcihtZXNzYWdlLCBvcHRpb25zKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0tTX1RJTUVPVVQnO1xuICAgIH1cbn1cbkpXS1NUaW1lb3V0LmNvZGUgPSAnRVJSX0pXS1NfVElNRU9VVCc7XG5leHBvcnQgY2xhc3MgSldTU2lnbmF0dXJlVmVyaWZpY2F0aW9uRmFpbGVkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcihtZXNzYWdlID0gJ3NpZ25hdHVyZSB2ZXJpZmljYXRpb24gZmFpbGVkJywgb3B0aW9ucykge1xuICAgICAgICBzdXBlcihtZXNzYWdlLCBvcHRpb25zKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV1NfU0lHTkFUVVJFX1ZFUklGSUNBVElPTl9GQUlMRUQnO1xuICAgIH1cbn1cbkpXU1NpZ25hdHVyZVZlcmlmaWNhdGlvbkZhaWxlZC5jb2RlID0gJ0VSUl9KV1NfU0lHTkFUVVJFX1ZFUklGSUNBVElPTl9GQUlMRUQnO1xuIiwiaW1wb3J0IGNyeXB0byBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5leHBvcnQgZGVmYXVsdCBjcnlwdG8uZ2V0UmFuZG9tVmFsdWVzLmJpbmQoY3J5cHRvKTtcbiIsImltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgcmFuZG9tIGZyb20gJy4uL3J1bnRpbWUvcmFuZG9tLmpzJztcbmV4cG9ydCBmdW5jdGlvbiBiaXRMZW5ndGgoYWxnKSB7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnQTEyOEdDTSc6XG4gICAgICAgIGNhc2UgJ0ExMjhHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ00nOlxuICAgICAgICBjYXNlICdBMTkyR0NNS1cnOlxuICAgICAgICBjYXNlICdBMjU2R0NNJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTUtXJzpcbiAgICAgICAgICAgIHJldHVybiA5NjtcbiAgICAgICAgY2FzZSAnQTEyOENCQy1IUzI1Nic6XG4gICAgICAgIGNhc2UgJ0ExOTJDQkMtSFMzODQnOlxuICAgICAgICBjYXNlICdBMjU2Q0JDLUhTNTEyJzpcbiAgICAgICAgICAgIHJldHVybiAxMjg7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZChgVW5zdXBwb3J0ZWQgSldFIEFsZ29yaXRobTogJHthbGd9YCk7XG4gICAgfVxufVxuZXhwb3J0IGRlZmF1bHQgKGFsZykgPT4gcmFuZG9tKG5ldyBVaW50OEFycmF5KGJpdExlbmd0aChhbGcpID4+IDMpKTtcbiIsImltcG9ydCB7IEpXRUludmFsaWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgeyBiaXRMZW5ndGggfSBmcm9tICcuL2l2LmpzJztcbmNvbnN0IGNoZWNrSXZMZW5ndGggPSAoZW5jLCBpdikgPT4ge1xuICAgIGlmIChpdi5sZW5ndGggPDwgMyAhPT0gYml0TGVuZ3RoKGVuYykpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ludmFsaWQgSW5pdGlhbGl6YXRpb24gVmVjdG9yIGxlbmd0aCcpO1xuICAgIH1cbn07XG5leHBvcnQgZGVmYXVsdCBjaGVja0l2TGVuZ3RoO1xuIiwiaW1wb3J0IHsgSldFSW52YWxpZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmNvbnN0IGNoZWNrQ2VrTGVuZ3RoID0gKGNlaywgZXhwZWN0ZWQpID0+IHtcbiAgICBjb25zdCBhY3R1YWwgPSBjZWsuYnl0ZUxlbmd0aCA8PCAzO1xuICAgIGlmIChhY3R1YWwgIT09IGV4cGVjdGVkKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKGBJbnZhbGlkIENvbnRlbnQgRW5jcnlwdGlvbiBLZXkgbGVuZ3RoLiBFeHBlY3RlZCAke2V4cGVjdGVkfSBiaXRzLCBnb3QgJHthY3R1YWx9IGJpdHNgKTtcbiAgICB9XG59O1xuZXhwb3J0IGRlZmF1bHQgY2hlY2tDZWtMZW5ndGg7XG4iLCJjb25zdCB0aW1pbmdTYWZlRXF1YWwgPSAoYSwgYikgPT4ge1xuICAgIGlmICghKGEgaW5zdGFuY2VvZiBVaW50OEFycmF5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdGaXJzdCBhcmd1bWVudCBtdXN0IGJlIGEgYnVmZmVyJyk7XG4gICAgfVxuICAgIGlmICghKGIgaW5zdGFuY2VvZiBVaW50OEFycmF5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdTZWNvbmQgYXJndW1lbnQgbXVzdCBiZSBhIGJ1ZmZlcicpO1xuICAgIH1cbiAgICBpZiAoYS5sZW5ndGggIT09IGIubGVuZ3RoKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0lucHV0IGJ1ZmZlcnMgbXVzdCBoYXZlIHRoZSBzYW1lIGxlbmd0aCcpO1xuICAgIH1cbiAgICBjb25zdCBsZW4gPSBhLmxlbmd0aDtcbiAgICBsZXQgb3V0ID0gMDtcbiAgICBsZXQgaSA9IC0xO1xuICAgIHdoaWxlICgrK2kgPCBsZW4pIHtcbiAgICAgICAgb3V0IHw9IGFbaV0gXiBiW2ldO1xuICAgIH1cbiAgICByZXR1cm4gb3V0ID09PSAwO1xufTtcbmV4cG9ydCBkZWZhdWx0IHRpbWluZ1NhZmVFcXVhbDtcbiIsImZ1bmN0aW9uIHVudXNhYmxlKG5hbWUsIHByb3AgPSAnYWxnb3JpdGhtLm5hbWUnKSB7XG4gICAgcmV0dXJuIG5ldyBUeXBlRXJyb3IoYENyeXB0b0tleSBkb2VzIG5vdCBzdXBwb3J0IHRoaXMgb3BlcmF0aW9uLCBpdHMgJHtwcm9wfSBtdXN0IGJlICR7bmFtZX1gKTtcbn1cbmZ1bmN0aW9uIGlzQWxnb3JpdGhtKGFsZ29yaXRobSwgbmFtZSkge1xuICAgIHJldHVybiBhbGdvcml0aG0ubmFtZSA9PT0gbmFtZTtcbn1cbmZ1bmN0aW9uIGdldEhhc2hMZW5ndGgoaGFzaCkge1xuICAgIHJldHVybiBwYXJzZUludChoYXNoLm5hbWUuc2xpY2UoNCksIDEwKTtcbn1cbmZ1bmN0aW9uIGdldE5hbWVkQ3VydmUoYWxnKSB7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnRVMyNTYnOlxuICAgICAgICAgICAgcmV0dXJuICdQLTI1Nic7XG4gICAgICAgIGNhc2UgJ0VTMzg0JzpcbiAgICAgICAgICAgIHJldHVybiAnUC0zODQnO1xuICAgICAgICBjYXNlICdFUzUxMic6XG4gICAgICAgICAgICByZXR1cm4gJ1AtNTIxJztcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcigndW5yZWFjaGFibGUnKTtcbiAgICB9XG59XG5mdW5jdGlvbiBjaGVja1VzYWdlKGtleSwgdXNhZ2VzKSB7XG4gICAgaWYgKHVzYWdlcy5sZW5ndGggJiYgIXVzYWdlcy5zb21lKChleHBlY3RlZCkgPT4ga2V5LnVzYWdlcy5pbmNsdWRlcyhleHBlY3RlZCkpKSB7XG4gICAgICAgIGxldCBtc2cgPSAnQ3J5cHRvS2V5IGRvZXMgbm90IHN1cHBvcnQgdGhpcyBvcGVyYXRpb24sIGl0cyB1c2FnZXMgbXVzdCBpbmNsdWRlICc7XG4gICAgICAgIGlmICh1c2FnZXMubGVuZ3RoID4gMikge1xuICAgICAgICAgICAgY29uc3QgbGFzdCA9IHVzYWdlcy5wb3AoKTtcbiAgICAgICAgICAgIG1zZyArPSBgb25lIG9mICR7dXNhZ2VzLmpvaW4oJywgJyl9LCBvciAke2xhc3R9LmA7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAodXNhZ2VzLmxlbmd0aCA9PT0gMikge1xuICAgICAgICAgICAgbXNnICs9IGBvbmUgb2YgJHt1c2FnZXNbMF19IG9yICR7dXNhZ2VzWzFdfS5gO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgbXNnICs9IGAke3VzYWdlc1swXX0uYDtcbiAgICAgICAgfVxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKG1zZyk7XG4gICAgfVxufVxuZXhwb3J0IGZ1bmN0aW9uIGNoZWNrU2lnQ3J5cHRvS2V5KGtleSwgYWxnLCAuLi51c2FnZXMpIHtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdIUzI1Nic6XG4gICAgICAgIGNhc2UgJ0hTMzg0JzpcbiAgICAgICAgY2FzZSAnSFM1MTInOiB7XG4gICAgICAgICAgICBpZiAoIWlzQWxnb3JpdGhtKGtleS5hbGdvcml0aG0sICdITUFDJykpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ0hNQUMnKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGVjdGVkID0gcGFyc2VJbnQoYWxnLnNsaWNlKDIpLCAxMCk7XG4gICAgICAgICAgICBjb25zdCBhY3R1YWwgPSBnZXRIYXNoTGVuZ3RoKGtleS5hbGdvcml0aG0uaGFzaCk7XG4gICAgICAgICAgICBpZiAoYWN0dWFsICE9PSBleHBlY3RlZClcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZShgU0hBLSR7ZXhwZWN0ZWR9YCwgJ2FsZ29yaXRobS5oYXNoJyk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdSUzI1Nic6XG4gICAgICAgIGNhc2UgJ1JTMzg0JzpcbiAgICAgICAgY2FzZSAnUlM1MTInOiB7XG4gICAgICAgICAgICBpZiAoIWlzQWxnb3JpdGhtKGtleS5hbGdvcml0aG0sICdSU0FTU0EtUEtDUzEtdjFfNScpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdSU0FTU0EtUEtDUzEtdjFfNScpO1xuICAgICAgICAgICAgY29uc3QgZXhwZWN0ZWQgPSBwYXJzZUludChhbGcuc2xpY2UoMiksIDEwKTtcbiAgICAgICAgICAgIGNvbnN0IGFjdHVhbCA9IGdldEhhc2hMZW5ndGgoa2V5LmFsZ29yaXRobS5oYXNoKTtcbiAgICAgICAgICAgIGlmIChhY3R1YWwgIT09IGV4cGVjdGVkKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKGBTSEEtJHtleHBlY3RlZH1gLCAnYWxnb3JpdGhtLmhhc2gnKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ1BTMjU2JzpcbiAgICAgICAgY2FzZSAnUFMzODQnOlxuICAgICAgICBjYXNlICdQUzUxMic6IHtcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ1JTQS1QU1MnKSlcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnUlNBLVBTUycpO1xuICAgICAgICAgICAgY29uc3QgZXhwZWN0ZWQgPSBwYXJzZUludChhbGcuc2xpY2UoMiksIDEwKTtcbiAgICAgICAgICAgIGNvbnN0IGFjdHVhbCA9IGdldEhhc2hMZW5ndGgoa2V5LmFsZ29yaXRobS5oYXNoKTtcbiAgICAgICAgICAgIGlmIChhY3R1YWwgIT09IGV4cGVjdGVkKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKGBTSEEtJHtleHBlY3RlZH1gLCAnYWxnb3JpdGhtLmhhc2gnKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0VkRFNBJzoge1xuICAgICAgICAgICAgaWYgKGtleS5hbGdvcml0aG0ubmFtZSAhPT0gJ0VkMjU1MTknICYmIGtleS5hbGdvcml0aG0ubmFtZSAhPT0gJ0VkNDQ4Jykge1xuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdFZDI1NTE5IG9yIEVkNDQ4Jyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdFUzI1Nic6XG4gICAgICAgIGNhc2UgJ0VTMzg0JzpcbiAgICAgICAgY2FzZSAnRVM1MTInOiB7XG4gICAgICAgICAgICBpZiAoIWlzQWxnb3JpdGhtKGtleS5hbGdvcml0aG0sICdFQ0RTQScpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdFQ0RTQScpO1xuICAgICAgICAgICAgY29uc3QgZXhwZWN0ZWQgPSBnZXROYW1lZEN1cnZlKGFsZyk7XG4gICAgICAgICAgICBjb25zdCBhY3R1YWwgPSBrZXkuYWxnb3JpdGhtLm5hbWVkQ3VydmU7XG4gICAgICAgICAgICBpZiAoYWN0dWFsICE9PSBleHBlY3RlZClcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZShleHBlY3RlZCwgJ2FsZ29yaXRobS5uYW1lZEN1cnZlJyk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignQ3J5cHRvS2V5IGRvZXMgbm90IHN1cHBvcnQgdGhpcyBvcGVyYXRpb24nKTtcbiAgICB9XG4gICAgY2hlY2tVc2FnZShrZXksIHVzYWdlcyk7XG59XG5leHBvcnQgZnVuY3Rpb24gY2hlY2tFbmNDcnlwdG9LZXkoa2V5LCBhbGcsIC4uLnVzYWdlcykge1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ0ExMjhHQ00nOlxuICAgICAgICBjYXNlICdBMTkyR0NNJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTSc6IHtcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ0FFUy1HQ00nKSlcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnQUVTLUdDTScpO1xuICAgICAgICAgICAgY29uc3QgZXhwZWN0ZWQgPSBwYXJzZUludChhbGcuc2xpY2UoMSwgNCksIDEwKTtcbiAgICAgICAgICAgIGNvbnN0IGFjdHVhbCA9IGtleS5hbGdvcml0aG0ubGVuZ3RoO1xuICAgICAgICAgICAgaWYgKGFjdHVhbCAhPT0gZXhwZWN0ZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoZXhwZWN0ZWQsICdhbGdvcml0aG0ubGVuZ3RoJyk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdBMTI4S1cnOlxuICAgICAgICBjYXNlICdBMTkyS1cnOlxuICAgICAgICBjYXNlICdBMjU2S1cnOiB7XG4gICAgICAgICAgICBpZiAoIWlzQWxnb3JpdGhtKGtleS5hbGdvcml0aG0sICdBRVMtS1cnKSlcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnQUVTLUtXJyk7XG4gICAgICAgICAgICBjb25zdCBleHBlY3RlZCA9IHBhcnNlSW50KGFsZy5zbGljZSgxLCA0KSwgMTApO1xuICAgICAgICAgICAgY29uc3QgYWN0dWFsID0ga2V5LmFsZ29yaXRobS5sZW5ndGg7XG4gICAgICAgICAgICBpZiAoYWN0dWFsICE9PSBleHBlY3RlZClcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZShleHBlY3RlZCwgJ2FsZ29yaXRobS5sZW5ndGgnKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0VDREgnOiB7XG4gICAgICAgICAgICBzd2l0Y2ggKGtleS5hbGdvcml0aG0ubmFtZSkge1xuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1gyNTUxOSc6XG4gICAgICAgICAgICAgICAgY2FzZSAnWDQ0OCc6XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdFQ0RILCBYMjU1MTksIG9yIFg0NDgnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ1BCRVMyLUhTMjU2K0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ1BCRVMyLUhTMzg0K0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ1BCRVMyLUhTNTEyK0EyNTZLVyc6XG4gICAgICAgICAgICBpZiAoIWlzQWxnb3JpdGhtKGtleS5hbGdvcml0aG0sICdQQktERjInKSlcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnUEJLREYyJyk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0yNTYnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0zODQnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC01MTInOiB7XG4gICAgICAgICAgICBpZiAoIWlzQWxnb3JpdGhtKGtleS5hbGdvcml0aG0sICdSU0EtT0FFUCcpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdSU0EtT0FFUCcpO1xuICAgICAgICAgICAgY29uc3QgZXhwZWN0ZWQgPSBwYXJzZUludChhbGcuc2xpY2UoOSksIDEwKSB8fCAxO1xuICAgICAgICAgICAgY29uc3QgYWN0dWFsID0gZ2V0SGFzaExlbmd0aChrZXkuYWxnb3JpdGhtLmhhc2gpO1xuICAgICAgICAgICAgaWYgKGFjdHVhbCAhPT0gZXhwZWN0ZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoYFNIQS0ke2V4cGVjdGVkfWAsICdhbGdvcml0aG0uaGFzaCcpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0NyeXB0b0tleSBkb2VzIG5vdCBzdXBwb3J0IHRoaXMgb3BlcmF0aW9uJyk7XG4gICAgfVxuICAgIGNoZWNrVXNhZ2Uoa2V5LCB1c2FnZXMpO1xufVxuIiwiZnVuY3Rpb24gbWVzc2FnZShtc2csIGFjdHVhbCwgLi4udHlwZXMpIHtcbiAgICB0eXBlcyA9IHR5cGVzLmZpbHRlcihCb29sZWFuKTtcbiAgICBpZiAodHlwZXMubGVuZ3RoID4gMikge1xuICAgICAgICBjb25zdCBsYXN0ID0gdHlwZXMucG9wKCk7XG4gICAgICAgIG1zZyArPSBgb25lIG9mIHR5cGUgJHt0eXBlcy5qb2luKCcsICcpfSwgb3IgJHtsYXN0fS5gO1xuICAgIH1cbiAgICBlbHNlIGlmICh0eXBlcy5sZW5ndGggPT09IDIpIHtcbiAgICAgICAgbXNnICs9IGBvbmUgb2YgdHlwZSAke3R5cGVzWzBdfSBvciAke3R5cGVzWzFdfS5gO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgbXNnICs9IGBvZiB0eXBlICR7dHlwZXNbMF19LmA7XG4gICAgfVxuICAgIGlmIChhY3R1YWwgPT0gbnVsbCkge1xuICAgICAgICBtc2cgKz0gYCBSZWNlaXZlZCAke2FjdHVhbH1gO1xuICAgIH1cbiAgICBlbHNlIGlmICh0eXBlb2YgYWN0dWFsID09PSAnZnVuY3Rpb24nICYmIGFjdHVhbC5uYW1lKSB7XG4gICAgICAgIG1zZyArPSBgIFJlY2VpdmVkIGZ1bmN0aW9uICR7YWN0dWFsLm5hbWV9YDtcbiAgICB9XG4gICAgZWxzZSBpZiAodHlwZW9mIGFjdHVhbCA9PT0gJ29iamVjdCcgJiYgYWN0dWFsICE9IG51bGwpIHtcbiAgICAgICAgaWYgKGFjdHVhbC5jb25zdHJ1Y3Rvcj8ubmFtZSkge1xuICAgICAgICAgICAgbXNnICs9IGAgUmVjZWl2ZWQgYW4gaW5zdGFuY2Ugb2YgJHthY3R1YWwuY29uc3RydWN0b3IubmFtZX1gO1xuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiBtc2c7XG59XG5leHBvcnQgZGVmYXVsdCAoYWN0dWFsLCAuLi50eXBlcykgPT4ge1xuICAgIHJldHVybiBtZXNzYWdlKCdLZXkgbXVzdCBiZSAnLCBhY3R1YWwsIC4uLnR5cGVzKTtcbn07XG5leHBvcnQgZnVuY3Rpb24gd2l0aEFsZyhhbGcsIGFjdHVhbCwgLi4udHlwZXMpIHtcbiAgICByZXR1cm4gbWVzc2FnZShgS2V5IGZvciB0aGUgJHthbGd9IGFsZ29yaXRobSBtdXN0IGJlIGAsIGFjdHVhbCwgLi4udHlwZXMpO1xufVxuIiwiaW1wb3J0IHsgaXNDcnlwdG9LZXkgfSBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5leHBvcnQgZGVmYXVsdCAoa2V5KSA9PiB7XG4gICAgaWYgKGlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIHJldHVybiBrZXk/LltTeW1ib2wudG9TdHJpbmdUYWddID09PSAnS2V5T2JqZWN0Jztcbn07XG5leHBvcnQgY29uc3QgdHlwZXMgPSBbJ0NyeXB0b0tleSddO1xuIiwiaW1wb3J0IHsgY29uY2F0LCB1aW50NjRiZSB9IGZyb20gJy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IGNoZWNrSXZMZW5ndGggZnJvbSAnLi4vbGliL2NoZWNrX2l2X2xlbmd0aC5qcyc7XG5pbXBvcnQgY2hlY2tDZWtMZW5ndGggZnJvbSAnLi9jaGVja19jZWtfbGVuZ3RoLmpzJztcbmltcG9ydCB0aW1pbmdTYWZlRXF1YWwgZnJvbSAnLi90aW1pbmdfc2FmZV9lcXVhbC5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkLCBKV0VEZWNyeXB0aW9uRmFpbGVkLCBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IGNyeXB0bywgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IGNoZWNrRW5jQ3J5cHRvS2V5IH0gZnJvbSAnLi4vbGliL2NyeXB0b19rZXkuanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmFzeW5jIGZ1bmN0aW9uIGNiY0RlY3J5cHQoZW5jLCBjZWssIGNpcGhlcnRleHQsIGl2LCB0YWcsIGFhZCkge1xuICAgIGlmICghKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGNlaywgJ1VpbnQ4QXJyYXknKSk7XG4gICAgfVxuICAgIGNvbnN0IGtleVNpemUgPSBwYXJzZUludChlbmMuc2xpY2UoMSwgNCksIDEwKTtcbiAgICBjb25zdCBlbmNLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLnN1YmFycmF5KGtleVNpemUgPj4gMyksICdBRVMtQ0JDJywgZmFsc2UsIFsnZGVjcnlwdCddKTtcbiAgICBjb25zdCBtYWNLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLnN1YmFycmF5KDAsIGtleVNpemUgPj4gMyksIHtcbiAgICAgICAgaGFzaDogYFNIQS0ke2tleVNpemUgPDwgMX1gLFxuICAgICAgICBuYW1lOiAnSE1BQycsXG4gICAgfSwgZmFsc2UsIFsnc2lnbiddKTtcbiAgICBjb25zdCBtYWNEYXRhID0gY29uY2F0KGFhZCwgaXYsIGNpcGhlcnRleHQsIHVpbnQ2NGJlKGFhZC5sZW5ndGggPDwgMykpO1xuICAgIGNvbnN0IGV4cGVjdGVkVGFnID0gbmV3IFVpbnQ4QXJyYXkoKGF3YWl0IGNyeXB0by5zdWJ0bGUuc2lnbignSE1BQycsIG1hY0tleSwgbWFjRGF0YSkpLnNsaWNlKDAsIGtleVNpemUgPj4gMykpO1xuICAgIGxldCBtYWNDaGVja1Bhc3NlZDtcbiAgICB0cnkge1xuICAgICAgICBtYWNDaGVja1Bhc3NlZCA9IHRpbWluZ1NhZmVFcXVhbCh0YWcsIGV4cGVjdGVkVGFnKTtcbiAgICB9XG4gICAgY2F0Y2gge1xuICAgIH1cbiAgICBpZiAoIW1hY0NoZWNrUGFzc2VkKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VEZWNyeXB0aW9uRmFpbGVkKCk7XG4gICAgfVxuICAgIGxldCBwbGFpbnRleHQ7XG4gICAgdHJ5IHtcbiAgICAgICAgcGxhaW50ZXh0ID0gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5kZWNyeXB0KHsgaXYsIG5hbWU6ICdBRVMtQ0JDJyB9LCBlbmNLZXksIGNpcGhlcnRleHQpKTtcbiAgICB9XG4gICAgY2F0Y2gge1xuICAgIH1cbiAgICBpZiAoIXBsYWludGV4dCkge1xuICAgICAgICB0aHJvdyBuZXcgSldFRGVjcnlwdGlvbkZhaWxlZCgpO1xuICAgIH1cbiAgICByZXR1cm4gcGxhaW50ZXh0O1xufVxuYXN5bmMgZnVuY3Rpb24gZ2NtRGVjcnlwdChlbmMsIGNlaywgY2lwaGVydGV4dCwgaXYsIHRhZywgYWFkKSB7XG4gICAgbGV0IGVuY0tleTtcbiAgICBpZiAoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICBlbmNLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLCAnQUVTLUdDTScsIGZhbHNlLCBbJ2RlY3J5cHQnXSk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBjaGVja0VuY0NyeXB0b0tleShjZWssIGVuYywgJ2RlY3J5cHQnKTtcbiAgICAgICAgZW5jS2V5ID0gY2VrO1xuICAgIH1cbiAgICB0cnkge1xuICAgICAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5kZWNyeXB0KHtcbiAgICAgICAgICAgIGFkZGl0aW9uYWxEYXRhOiBhYWQsXG4gICAgICAgICAgICBpdixcbiAgICAgICAgICAgIG5hbWU6ICdBRVMtR0NNJyxcbiAgICAgICAgICAgIHRhZ0xlbmd0aDogMTI4LFxuICAgICAgICB9LCBlbmNLZXksIGNvbmNhdChjaXBoZXJ0ZXh0LCB0YWcpKSk7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRURlY3J5cHRpb25GYWlsZWQoKTtcbiAgICB9XG59XG5jb25zdCBkZWNyeXB0ID0gYXN5bmMgKGVuYywgY2VrLCBjaXBoZXJ0ZXh0LCBpdiwgdGFnLCBhYWQpID0+IHtcbiAgICBpZiAoIWlzQ3J5cHRvS2V5KGNlaykgJiYgIShjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChjZWssIC4uLnR5cGVzLCAnVWludDhBcnJheScpKTtcbiAgICB9XG4gICAgaWYgKCFpdikge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEluaXRpYWxpemF0aW9uIFZlY3RvciBtaXNzaW5nJyk7XG4gICAgfVxuICAgIGlmICghdGFnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgQXV0aGVudGljYXRpb24gVGFnIG1pc3NpbmcnKTtcbiAgICB9XG4gICAgY2hlY2tJdkxlbmd0aChlbmMsIGl2KTtcbiAgICBzd2l0Y2ggKGVuYykge1xuICAgICAgICBjYXNlICdBMTI4Q0JDLUhTMjU2JzpcbiAgICAgICAgY2FzZSAnQTE5MkNCQy1IUzM4NCc6XG4gICAgICAgIGNhc2UgJ0EyNTZDQkMtSFM1MTInOlxuICAgICAgICAgICAgaWYgKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpXG4gICAgICAgICAgICAgICAgY2hlY2tDZWtMZW5ndGgoY2VrLCBwYXJzZUludChlbmMuc2xpY2UoLTMpLCAxMCkpO1xuICAgICAgICAgICAgcmV0dXJuIGNiY0RlY3J5cHQoZW5jLCBjZWssIGNpcGhlcnRleHQsIGl2LCB0YWcsIGFhZCk7XG4gICAgICAgIGNhc2UgJ0ExMjhHQ00nOlxuICAgICAgICBjYXNlICdBMTkyR0NNJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTSc6XG4gICAgICAgICAgICBpZiAoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSlcbiAgICAgICAgICAgICAgICBjaGVja0Nla0xlbmd0aChjZWssIHBhcnNlSW50KGVuYy5zbGljZSgxLCA0KSwgMTApKTtcbiAgICAgICAgICAgIHJldHVybiBnY21EZWNyeXB0KGVuYywgY2VrLCBjaXBoZXJ0ZXh0LCBpdiwgdGFnLCBhYWQpO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ1Vuc3VwcG9ydGVkIEpXRSBDb250ZW50IEVuY3J5cHRpb24gQWxnb3JpdGhtJyk7XG4gICAgfVxufTtcbmV4cG9ydCBkZWZhdWx0IGRlY3J5cHQ7XG4iLCJjb25zdCBpc0Rpc2pvaW50ID0gKC4uLmhlYWRlcnMpID0+IHtcbiAgICBjb25zdCBzb3VyY2VzID0gaGVhZGVycy5maWx0ZXIoQm9vbGVhbik7XG4gICAgaWYgKHNvdXJjZXMubGVuZ3RoID09PSAwIHx8IHNvdXJjZXMubGVuZ3RoID09PSAxKSB7XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cbiAgICBsZXQgYWNjO1xuICAgIGZvciAoY29uc3QgaGVhZGVyIG9mIHNvdXJjZXMpIHtcbiAgICAgICAgY29uc3QgcGFyYW1ldGVycyA9IE9iamVjdC5rZXlzKGhlYWRlcik7XG4gICAgICAgIGlmICghYWNjIHx8IGFjYy5zaXplID09PSAwKSB7XG4gICAgICAgICAgICBhY2MgPSBuZXcgU2V0KHBhcmFtZXRlcnMpO1xuICAgICAgICAgICAgY29udGludWU7XG4gICAgICAgIH1cbiAgICAgICAgZm9yIChjb25zdCBwYXJhbWV0ZXIgb2YgcGFyYW1ldGVycykge1xuICAgICAgICAgICAgaWYgKGFjYy5oYXMocGFyYW1ldGVyKSkge1xuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGFjYy5hZGQocGFyYW1ldGVyKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gdHJ1ZTtcbn07XG5leHBvcnQgZGVmYXVsdCBpc0Rpc2pvaW50O1xuIiwiZnVuY3Rpb24gaXNPYmplY3RMaWtlKHZhbHVlKSB7XG4gICAgcmV0dXJuIHR5cGVvZiB2YWx1ZSA9PT0gJ29iamVjdCcgJiYgdmFsdWUgIT09IG51bGw7XG59XG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBpc09iamVjdChpbnB1dCkge1xuICAgIGlmICghaXNPYmplY3RMaWtlKGlucHV0KSB8fCBPYmplY3QucHJvdG90eXBlLnRvU3RyaW5nLmNhbGwoaW5wdXQpICE9PSAnW29iamVjdCBPYmplY3RdJykge1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuICAgIGlmIChPYmplY3QuZ2V0UHJvdG90eXBlT2YoaW5wdXQpID09PSBudWxsKSB7XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cbiAgICBsZXQgcHJvdG8gPSBpbnB1dDtcbiAgICB3aGlsZSAoT2JqZWN0LmdldFByb3RvdHlwZU9mKHByb3RvKSAhPT0gbnVsbCkge1xuICAgICAgICBwcm90byA9IE9iamVjdC5nZXRQcm90b3R5cGVPZihwcm90byk7XG4gICAgfVxuICAgIHJldHVybiBPYmplY3QuZ2V0UHJvdG90eXBlT2YoaW5wdXQpID09PSBwcm90bztcbn1cbiIsImNvbnN0IGJvZ3VzV2ViQ3J5cHRvID0gW1xuICAgIHsgaGFzaDogJ1NIQS0yNTYnLCBuYW1lOiAnSE1BQycgfSxcbiAgICB0cnVlLFxuICAgIFsnc2lnbiddLFxuXTtcbmV4cG9ydCBkZWZhdWx0IGJvZ3VzV2ViQ3J5cHRvO1xuIiwiaW1wb3J0IGJvZ3VzV2ViQ3J5cHRvIGZyb20gJy4vYm9ndXMuanMnO1xuaW1wb3J0IGNyeXB0bywgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IGNoZWNrRW5jQ3J5cHRvS2V5IH0gZnJvbSAnLi4vbGliL2NyeXB0b19rZXkuanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmZ1bmN0aW9uIGNoZWNrS2V5U2l6ZShrZXksIGFsZykge1xuICAgIGlmIChrZXkuYWxnb3JpdGhtLmxlbmd0aCAhPT0gcGFyc2VJbnQoYWxnLnNsaWNlKDEsIDQpLCAxMCkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgSW52YWxpZCBrZXkgc2l6ZSBmb3IgYWxnOiAke2FsZ31gKTtcbiAgICB9XG59XG5mdW5jdGlvbiBnZXRDcnlwdG9LZXkoa2V5LCBhbGcsIHVzYWdlKSB7XG4gICAgaWYgKGlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgY2hlY2tFbmNDcnlwdG9LZXkoa2V5LCBhbGcsIHVzYWdlKTtcbiAgICAgICAgcmV0dXJuIGtleTtcbiAgICB9XG4gICAgaWYgKGtleSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBrZXksICdBRVMtS1cnLCB0cnVlLCBbdXNhZ2VdKTtcbiAgICB9XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcywgJ1VpbnQ4QXJyYXknKSk7XG59XG5leHBvcnQgY29uc3Qgd3JhcCA9IGFzeW5jIChhbGcsIGtleSwgY2VrKSA9PiB7XG4gICAgY29uc3QgY3J5cHRvS2V5ID0gYXdhaXQgZ2V0Q3J5cHRvS2V5KGtleSwgYWxnLCAnd3JhcEtleScpO1xuICAgIGNoZWNrS2V5U2l6ZShjcnlwdG9LZXksIGFsZyk7XG4gICAgY29uc3QgY3J5cHRvS2V5Q2VrID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGNlaywgLi4uYm9ndXNXZWJDcnlwdG8pO1xuICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLndyYXBLZXkoJ3JhdycsIGNyeXB0b0tleUNlaywgY3J5cHRvS2V5LCAnQUVTLUtXJykpO1xufTtcbmV4cG9ydCBjb25zdCB1bndyYXAgPSBhc3luYyAoYWxnLCBrZXksIGVuY3J5cHRlZEtleSkgPT4ge1xuICAgIGNvbnN0IGNyeXB0b0tleSA9IGF3YWl0IGdldENyeXB0b0tleShrZXksIGFsZywgJ3Vud3JhcEtleScpO1xuICAgIGNoZWNrS2V5U2l6ZShjcnlwdG9LZXksIGFsZyk7XG4gICAgY29uc3QgY3J5cHRvS2V5Q2VrID0gYXdhaXQgY3J5cHRvLnN1YnRsZS51bndyYXBLZXkoJ3JhdycsIGVuY3J5cHRlZEtleSwgY3J5cHRvS2V5LCAnQUVTLUtXJywgLi4uYm9ndXNXZWJDcnlwdG8pO1xuICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgncmF3JywgY3J5cHRvS2V5Q2VrKSk7XG59O1xuIiwiaW1wb3J0IHsgZW5jb2RlciwgY29uY2F0LCB1aW50MzJiZSwgbGVuZ3RoQW5kSW5wdXQsIGNvbmNhdEtkZiB9IGZyb20gJy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IGNyeXB0bywgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IGNoZWNrRW5jQ3J5cHRvS2V5IH0gZnJvbSAnLi4vbGliL2NyeXB0b19rZXkuanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZXJpdmVLZXkocHVibGljS2V5LCBwcml2YXRlS2V5LCBhbGdvcml0aG0sIGtleUxlbmd0aCwgYXB1ID0gbmV3IFVpbnQ4QXJyYXkoMCksIGFwdiA9IG5ldyBVaW50OEFycmF5KDApKSB7XG4gICAgaWYgKCFpc0NyeXB0b0tleShwdWJsaWNLZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KHB1YmxpY0tleSwgLi4udHlwZXMpKTtcbiAgICB9XG4gICAgY2hlY2tFbmNDcnlwdG9LZXkocHVibGljS2V5LCAnRUNESCcpO1xuICAgIGlmICghaXNDcnlwdG9LZXkocHJpdmF0ZUtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQocHJpdmF0ZUtleSwgLi4udHlwZXMpKTtcbiAgICB9XG4gICAgY2hlY2tFbmNDcnlwdG9LZXkocHJpdmF0ZUtleSwgJ0VDREgnLCAnZGVyaXZlQml0cycpO1xuICAgIGNvbnN0IHZhbHVlID0gY29uY2F0KGxlbmd0aEFuZElucHV0KGVuY29kZXIuZW5jb2RlKGFsZ29yaXRobSkpLCBsZW5ndGhBbmRJbnB1dChhcHUpLCBsZW5ndGhBbmRJbnB1dChhcHYpLCB1aW50MzJiZShrZXlMZW5ndGgpKTtcbiAgICBsZXQgbGVuZ3RoO1xuICAgIGlmIChwdWJsaWNLZXkuYWxnb3JpdGhtLm5hbWUgPT09ICdYMjU1MTknKSB7XG4gICAgICAgIGxlbmd0aCA9IDI1NjtcbiAgICB9XG4gICAgZWxzZSBpZiAocHVibGljS2V5LmFsZ29yaXRobS5uYW1lID09PSAnWDQ0OCcpIHtcbiAgICAgICAgbGVuZ3RoID0gNDQ4O1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgbGVuZ3RoID1cbiAgICAgICAgICAgIE1hdGguY2VpbChwYXJzZUludChwdWJsaWNLZXkuYWxnb3JpdGhtLm5hbWVkQ3VydmUuc3Vic3RyKC0zKSwgMTApIC8gOCkgPDxcbiAgICAgICAgICAgICAgICAzO1xuICAgIH1cbiAgICBjb25zdCBzaGFyZWRTZWNyZXQgPSBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmRlcml2ZUJpdHMoe1xuICAgICAgICBuYW1lOiBwdWJsaWNLZXkuYWxnb3JpdGhtLm5hbWUsXG4gICAgICAgIHB1YmxpYzogcHVibGljS2V5LFxuICAgIH0sIHByaXZhdGVLZXksIGxlbmd0aCkpO1xuICAgIHJldHVybiBjb25jYXRLZGYoc2hhcmVkU2VjcmV0LCBrZXlMZW5ndGgsIHZhbHVlKTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZUVwayhrZXkpIHtcbiAgICBpZiAoIWlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcykpO1xuICAgIH1cbiAgICByZXR1cm4gY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleShrZXkuYWxnb3JpdGhtLCB0cnVlLCBbJ2Rlcml2ZUJpdHMnXSk7XG59XG5leHBvcnQgZnVuY3Rpb24gZWNkaEFsbG93ZWQoa2V5KSB7XG4gICAgaWYgKCFpc0NyeXB0b0tleShrZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMpKTtcbiAgICB9XG4gICAgcmV0dXJuIChbJ1AtMjU2JywgJ1AtMzg0JywgJ1AtNTIxJ10uaW5jbHVkZXMoa2V5LmFsZ29yaXRobS5uYW1lZEN1cnZlKSB8fFxuICAgICAgICBrZXkuYWxnb3JpdGhtLm5hbWUgPT09ICdYMjU1MTknIHx8XG4gICAgICAgIGtleS5hbGdvcml0aG0ubmFtZSA9PT0gJ1g0NDgnKTtcbn1cbiIsImltcG9ydCB7IEpXRUludmFsaWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBjaGVja1AycyhwMnMpIHtcbiAgICBpZiAoIShwMnMgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB8fCBwMnMubGVuZ3RoIDwgOCkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnUEJFUzIgU2FsdCBJbnB1dCBtdXN0IGJlIDggb3IgbW9yZSBvY3RldHMnKTtcbiAgICB9XG59XG4iLCJpbXBvcnQgcmFuZG9tIGZyb20gJy4vcmFuZG9tLmpzJztcbmltcG9ydCB7IHAycyBhcyBjb25jYXRTYWx0IH0gZnJvbSAnLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgeyBlbmNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHsgd3JhcCwgdW53cmFwIH0gZnJvbSAnLi9hZXNrdy5qcyc7XG5pbXBvcnQgY2hlY2tQMnMgZnJvbSAnLi4vbGliL2NoZWNrX3Aycy5qcyc7XG5pbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tFbmNDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuZnVuY3Rpb24gZ2V0Q3J5cHRvS2V5KGtleSwgYWxnKSB7XG4gICAgaWYgKGtleSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBrZXksICdQQktERjInLCBmYWxzZSwgWydkZXJpdmVCaXRzJ10pO1xuICAgIH1cbiAgICBpZiAoaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICBjaGVja0VuY0NyeXB0b0tleShrZXksIGFsZywgJ2Rlcml2ZUJpdHMnLCAnZGVyaXZlS2V5Jyk7XG4gICAgICAgIHJldHVybiBrZXk7XG4gICAgfVxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMsICdVaW50OEFycmF5JykpO1xufVxuYXN5bmMgZnVuY3Rpb24gZGVyaXZlS2V5KHAycywgYWxnLCBwMmMsIGtleSkge1xuICAgIGNoZWNrUDJzKHAycyk7XG4gICAgY29uc3Qgc2FsdCA9IGNvbmNhdFNhbHQoYWxnLCBwMnMpO1xuICAgIGNvbnN0IGtleWxlbiA9IHBhcnNlSW50KGFsZy5zbGljZSgxMywgMTYpLCAxMCk7XG4gICAgY29uc3Qgc3VidGxlQWxnID0ge1xuICAgICAgICBoYXNoOiBgU0hBLSR7YWxnLnNsaWNlKDgsIDExKX1gLFxuICAgICAgICBpdGVyYXRpb25zOiBwMmMsXG4gICAgICAgIG5hbWU6ICdQQktERjInLFxuICAgICAgICBzYWx0LFxuICAgIH07XG4gICAgY29uc3Qgd3JhcEFsZyA9IHtcbiAgICAgICAgbGVuZ3RoOiBrZXlsZW4sXG4gICAgICAgIG5hbWU6ICdBRVMtS1cnLFxuICAgIH07XG4gICAgY29uc3QgY3J5cHRvS2V5ID0gYXdhaXQgZ2V0Q3J5cHRvS2V5KGtleSwgYWxnKTtcbiAgICBpZiAoY3J5cHRvS2V5LnVzYWdlcy5pbmNsdWRlcygnZGVyaXZlQml0cycpKSB7XG4gICAgICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmRlcml2ZUJpdHMoc3VidGxlQWxnLCBjcnlwdG9LZXksIGtleWxlbikpO1xuICAgIH1cbiAgICBpZiAoY3J5cHRvS2V5LnVzYWdlcy5pbmNsdWRlcygnZGVyaXZlS2V5JykpIHtcbiAgICAgICAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuZGVyaXZlS2V5KHN1YnRsZUFsZywgY3J5cHRvS2V5LCB3cmFwQWxnLCBmYWxzZSwgWyd3cmFwS2V5JywgJ3Vud3JhcEtleSddKTtcbiAgICB9XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcignUEJLREYyIGtleSBcInVzYWdlc1wiIG11c3QgaW5jbHVkZSBcImRlcml2ZUJpdHNcIiBvciBcImRlcml2ZUtleVwiJyk7XG59XG5leHBvcnQgY29uc3QgZW5jcnlwdCA9IGFzeW5jIChhbGcsIGtleSwgY2VrLCBwMmMgPSAyMDQ4LCBwMnMgPSByYW5kb20obmV3IFVpbnQ4QXJyYXkoMTYpKSkgPT4ge1xuICAgIGNvbnN0IGRlcml2ZWQgPSBhd2FpdCBkZXJpdmVLZXkocDJzLCBhbGcsIHAyYywga2V5KTtcbiAgICBjb25zdCBlbmNyeXB0ZWRLZXkgPSBhd2FpdCB3cmFwKGFsZy5zbGljZSgtNiksIGRlcml2ZWQsIGNlayk7XG4gICAgcmV0dXJuIHsgZW5jcnlwdGVkS2V5LCBwMmMsIHAyczogYmFzZTY0dXJsKHAycykgfTtcbn07XG5leHBvcnQgY29uc3QgZGVjcnlwdCA9IGFzeW5jIChhbGcsIGtleSwgZW5jcnlwdGVkS2V5LCBwMmMsIHAycykgPT4ge1xuICAgIGNvbnN0IGRlcml2ZWQgPSBhd2FpdCBkZXJpdmVLZXkocDJzLCBhbGcsIHAyYywga2V5KTtcbiAgICByZXR1cm4gdW53cmFwKGFsZy5zbGljZSgtNiksIGRlcml2ZWQsIGVuY3J5cHRlZEtleSk7XG59O1xuIiwiaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIHN1YnRsZVJzYUVzKGFsZykge1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQJzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMjU2JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMzg0JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtNTEyJzpcbiAgICAgICAgICAgIHJldHVybiAnUlNBLU9BRVAnO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoYGFsZyAke2FsZ30gaXMgbm90IHN1cHBvcnRlZCBlaXRoZXIgYnkgSk9TRSBvciB5b3VyIGphdmFzY3JpcHQgcnVudGltZWApO1xuICAgIH1cbn1cbiIsImV4cG9ydCBkZWZhdWx0IChhbGcsIGtleSkgPT4ge1xuICAgIGlmIChhbGcuc3RhcnRzV2l0aCgnUlMnKSB8fCBhbGcuc3RhcnRzV2l0aCgnUFMnKSkge1xuICAgICAgICBjb25zdCB7IG1vZHVsdXNMZW5ndGggfSA9IGtleS5hbGdvcml0aG07XG4gICAgICAgIGlmICh0eXBlb2YgbW9kdWx1c0xlbmd0aCAhPT0gJ251bWJlcicgfHwgbW9kdWx1c0xlbmd0aCA8IDIwNDgpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYCR7YWxnfSByZXF1aXJlcyBrZXkgbW9kdWx1c0xlbmd0aCB0byBiZSAyMDQ4IGJpdHMgb3IgbGFyZ2VyYCk7XG4gICAgICAgIH1cbiAgICB9XG59O1xuIiwiaW1wb3J0IHN1YnRsZUFsZ29yaXRobSBmcm9tICcuL3N1YnRsZV9yc2Flcy5qcyc7XG5pbXBvcnQgYm9ndXNXZWJDcnlwdG8gZnJvbSAnLi9ib2d1cy5qcyc7XG5pbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tFbmNDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgY2hlY2tLZXlMZW5ndGggZnJvbSAnLi9jaGVja19rZXlfbGVuZ3RoLmpzJztcbmltcG9ydCBpbnZhbGlkS2V5SW5wdXQgZnJvbSAnLi4vbGliL2ludmFsaWRfa2V5X2lucHV0LmpzJztcbmltcG9ydCB7IHR5cGVzIH0gZnJvbSAnLi9pc19rZXlfbGlrZS5qcyc7XG5leHBvcnQgY29uc3QgZW5jcnlwdCA9IGFzeW5jIChhbGcsIGtleSwgY2VrKSA9PiB7XG4gICAgaWYgKCFpc0NyeXB0b0tleShrZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMpKTtcbiAgICB9XG4gICAgY2hlY2tFbmNDcnlwdG9LZXkoa2V5LCBhbGcsICdlbmNyeXB0JywgJ3dyYXBLZXknKTtcbiAgICBjaGVja0tleUxlbmd0aChhbGcsIGtleSk7XG4gICAgaWYgKGtleS51c2FnZXMuaW5jbHVkZXMoJ2VuY3J5cHQnKSkge1xuICAgICAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5lbmNyeXB0KHN1YnRsZUFsZ29yaXRobShhbGcpLCBrZXksIGNlaykpO1xuICAgIH1cbiAgICBpZiAoa2V5LnVzYWdlcy5pbmNsdWRlcygnd3JhcEtleScpKSB7XG4gICAgICAgIGNvbnN0IGNyeXB0b0tleUNlayA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBjZWssIC4uLmJvZ3VzV2ViQ3J5cHRvKTtcbiAgICAgICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUud3JhcEtleSgncmF3JywgY3J5cHRvS2V5Q2VrLCBrZXksIHN1YnRsZUFsZ29yaXRobShhbGcpKSk7XG4gICAgfVxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1JTQS1PQUVQIGtleSBcInVzYWdlc1wiIG11c3QgaW5jbHVkZSBcImVuY3J5cHRcIiBvciBcIndyYXBLZXlcIiBmb3IgdGhpcyBvcGVyYXRpb24nKTtcbn07XG5leHBvcnQgY29uc3QgZGVjcnlwdCA9IGFzeW5jIChhbGcsIGtleSwgZW5jcnlwdGVkS2V5KSA9PiB7XG4gICAgaWYgKCFpc0NyeXB0b0tleShrZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMpKTtcbiAgICB9XG4gICAgY2hlY2tFbmNDcnlwdG9LZXkoa2V5LCBhbGcsICdkZWNyeXB0JywgJ3Vud3JhcEtleScpO1xuICAgIGNoZWNrS2V5TGVuZ3RoKGFsZywga2V5KTtcbiAgICBpZiAoa2V5LnVzYWdlcy5pbmNsdWRlcygnZGVjcnlwdCcpKSB7XG4gICAgICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmRlY3J5cHQoc3VidGxlQWxnb3JpdGhtKGFsZyksIGtleSwgZW5jcnlwdGVkS2V5KSk7XG4gICAgfVxuICAgIGlmIChrZXkudXNhZ2VzLmluY2x1ZGVzKCd1bndyYXBLZXknKSkge1xuICAgICAgICBjb25zdCBjcnlwdG9LZXlDZWsgPSBhd2FpdCBjcnlwdG8uc3VidGxlLnVud3JhcEtleSgncmF3JywgZW5jcnlwdGVkS2V5LCBrZXksIHN1YnRsZUFsZ29yaXRobShhbGcpLCAuLi5ib2d1c1dlYkNyeXB0byk7XG4gICAgICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgncmF3JywgY3J5cHRvS2V5Q2VrKSk7XG4gICAgfVxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1JTQS1PQUVQIGtleSBcInVzYWdlc1wiIG11c3QgaW5jbHVkZSBcImRlY3J5cHRcIiBvciBcInVud3JhcEtleVwiIGZvciB0aGlzIG9wZXJhdGlvbicpO1xufTtcbiIsImltcG9ydCBpc09iamVjdCBmcm9tICcuL2lzX29iamVjdC5qcyc7XG5leHBvcnQgZnVuY3Rpb24gaXNKV0soa2V5KSB7XG4gICAgcmV0dXJuIGlzT2JqZWN0KGtleSkgJiYgdHlwZW9mIGtleS5rdHkgPT09ICdzdHJpbmcnO1xufVxuZXhwb3J0IGZ1bmN0aW9uIGlzUHJpdmF0ZUpXSyhrZXkpIHtcbiAgICByZXR1cm4ga2V5Lmt0eSAhPT0gJ29jdCcgJiYgdHlwZW9mIGtleS5kID09PSAnc3RyaW5nJztcbn1cbmV4cG9ydCBmdW5jdGlvbiBpc1B1YmxpY0pXSyhrZXkpIHtcbiAgICByZXR1cm4ga2V5Lmt0eSAhPT0gJ29jdCcgJiYgdHlwZW9mIGtleS5kID09PSAndW5kZWZpbmVkJztcbn1cbmV4cG9ydCBmdW5jdGlvbiBpc1NlY3JldEpXSyhrZXkpIHtcbiAgICByZXR1cm4gaXNKV0soa2V5KSAmJiBrZXkua3R5ID09PSAnb2N0JyAmJiB0eXBlb2Yga2V5LmsgPT09ICdzdHJpbmcnO1xufVxuIiwiaW1wb3J0IGNyeXB0byBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuZnVuY3Rpb24gc3VidGxlTWFwcGluZyhqd2spIHtcbiAgICBsZXQgYWxnb3JpdGhtO1xuICAgIGxldCBrZXlVc2FnZXM7XG4gICAgc3dpdGNoIChqd2sua3R5KSB7XG4gICAgICAgIGNhc2UgJ1JTQSc6IHtcbiAgICAgICAgICAgIHN3aXRjaCAoandrLmFsZykge1xuICAgICAgICAgICAgICAgIGNhc2UgJ1BTMjU2JzpcbiAgICAgICAgICAgICAgICBjYXNlICdQUzM4NCc6XG4gICAgICAgICAgICAgICAgY2FzZSAnUFM1MTInOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdSU0EtUFNTJywgaGFzaDogYFNIQS0ke2p3ay5hbGcuc2xpY2UoLTMpfWAgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ3NpZ24nXSA6IFsndmVyaWZ5J107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ1JTMjU2JzpcbiAgICAgICAgICAgICAgICBjYXNlICdSUzM4NCc6XG4gICAgICAgICAgICAgICAgY2FzZSAnUlM1MTInOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdSU0FTU0EtUEtDUzEtdjFfNScsIGhhc2g6IGBTSEEtJHtqd2suYWxnLnNsaWNlKC0zKX1gIH07XG4gICAgICAgICAgICAgICAgICAgIGtleVVzYWdlcyA9IGp3ay5kID8gWydzaWduJ10gOiBbJ3ZlcmlmeSddO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlICdSU0EtT0FFUCc6XG4gICAgICAgICAgICAgICAgY2FzZSAnUlNBLU9BRVAtMjU2JzpcbiAgICAgICAgICAgICAgICBjYXNlICdSU0EtT0FFUC0zODQnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1JTQS1PQUVQLTUxMic6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIG5hbWU6ICdSU0EtT0FFUCcsXG4gICAgICAgICAgICAgICAgICAgICAgICBoYXNoOiBgU0hBLSR7cGFyc2VJbnQoandrLmFsZy5zbGljZSgtMyksIDEwKSB8fCAxfWAsXG4gICAgICAgICAgICAgICAgICAgIH07XG4gICAgICAgICAgICAgICAgICAgIGtleVVzYWdlcyA9IGp3ay5kID8gWydkZWNyeXB0JywgJ3Vud3JhcEtleSddIDogWydlbmNyeXB0JywgJ3dyYXBLZXknXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgSldLIFwiYWxnXCIgKEFsZ29yaXRobSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdFQyc6IHtcbiAgICAgICAgICAgIHN3aXRjaCAoandrLmFsZykge1xuICAgICAgICAgICAgICAgIGNhc2UgJ0VTMjU2JzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNEU0EnLCBuYW1lZEN1cnZlOiAnUC0yNTYnIH07XG4gICAgICAgICAgICAgICAgICAgIGtleVVzYWdlcyA9IGp3ay5kID8gWydzaWduJ10gOiBbJ3ZlcmlmeSddO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlICdFUzM4NCc6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0VDRFNBJywgbmFtZWRDdXJ2ZTogJ1AtMzg0JyB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnc2lnbiddIDogWyd2ZXJpZnknXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAnRVM1MTInOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RTQScsIG5hbWVkQ3VydmU6ICdQLTUyMScgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ3NpZ24nXSA6IFsndmVyaWZ5J107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMrQTEyOEtXJzpcbiAgICAgICAgICAgICAgICBjYXNlICdFQ0RILUVTK0ExOTJLVyc6XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUytBMjU2S1cnOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RIJywgbmFtZWRDdXJ2ZTogandrLmNydiB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnZGVyaXZlQml0cyddIDogW107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIEpXSyBcImFsZ1wiIChBbGdvcml0aG0pIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnT0tQJzoge1xuICAgICAgICAgICAgc3dpdGNoIChqd2suYWxnKSB7XG4gICAgICAgICAgICAgICAgY2FzZSAnRWREU0EnOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6IGp3ay5jcnYgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ3NpZ24nXSA6IFsndmVyaWZ5J107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMrQTEyOEtXJzpcbiAgICAgICAgICAgICAgICBjYXNlICdFQ0RILUVTK0ExOTJLVyc6XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUytBMjU2S1cnOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6IGp3ay5jcnYgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ2Rlcml2ZUJpdHMnXSA6IFtdO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBKV0sgXCJhbGdcIiAoQWxnb3JpdGhtKSBQYXJhbWV0ZXIgdmFsdWUnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBKV0sgXCJrdHlcIiAoS2V5IFR5cGUpIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgIH1cbiAgICByZXR1cm4geyBhbGdvcml0aG0sIGtleVVzYWdlcyB9O1xufVxuY29uc3QgcGFyc2UgPSBhc3luYyAoandrKSA9PiB7XG4gICAgaWYgKCFqd2suYWxnKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1wiYWxnXCIgYXJndW1lbnQgaXMgcmVxdWlyZWQgd2hlbiBcImp3ay5hbGdcIiBpcyBub3QgcHJlc2VudCcpO1xuICAgIH1cbiAgICBjb25zdCB7IGFsZ29yaXRobSwga2V5VXNhZ2VzIH0gPSBzdWJ0bGVNYXBwaW5nKGp3ayk7XG4gICAgY29uc3QgcmVzdCA9IFtcbiAgICAgICAgYWxnb3JpdGhtLFxuICAgICAgICBqd2suZXh0ID8/IGZhbHNlLFxuICAgICAgICBqd2sua2V5X29wcyA/PyBrZXlVc2FnZXMsXG4gICAgXTtcbiAgICBjb25zdCBrZXlEYXRhID0geyAuLi5qd2sgfTtcbiAgICBkZWxldGUga2V5RGF0YS5hbGc7XG4gICAgZGVsZXRlIGtleURhdGEudXNlO1xuICAgIHJldHVybiBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgnandrJywga2V5RGF0YSwgLi4ucmVzdCk7XG59O1xuZXhwb3J0IGRlZmF1bHQgcGFyc2U7XG4iLCJpbXBvcnQgeyBpc0pXSyB9IGZyb20gJy4uL2xpYi9pc19qd2suanMnO1xuaW1wb3J0IHsgZGVjb2RlIH0gZnJvbSAnLi9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IGltcG9ydEpXSyBmcm9tICcuL2p3a190b19rZXkuanMnO1xuY29uc3QgZXhwb3J0S2V5VmFsdWUgPSAoaykgPT4gZGVjb2RlKGspO1xubGV0IHByaXZDYWNoZTtcbmxldCBwdWJDYWNoZTtcbmNvbnN0IGlzS2V5T2JqZWN0ID0gKGtleSkgPT4ge1xuICAgIHJldHVybiBrZXk/LltTeW1ib2wudG9TdHJpbmdUYWddID09PSAnS2V5T2JqZWN0Jztcbn07XG5jb25zdCBpbXBvcnRBbmRDYWNoZSA9IGFzeW5jIChjYWNoZSwga2V5LCBqd2ssIGFsZywgZnJlZXplID0gZmFsc2UpID0+IHtcbiAgICBsZXQgY2FjaGVkID0gY2FjaGUuZ2V0KGtleSk7XG4gICAgaWYgKGNhY2hlZD8uW2FsZ10pIHtcbiAgICAgICAgcmV0dXJuIGNhY2hlZFthbGddO1xuICAgIH1cbiAgICBjb25zdCBjcnlwdG9LZXkgPSBhd2FpdCBpbXBvcnRKV0soeyAuLi5qd2ssIGFsZyB9KTtcbiAgICBpZiAoZnJlZXplKVxuICAgICAgICBPYmplY3QuZnJlZXplKGtleSk7XG4gICAgaWYgKCFjYWNoZWQpIHtcbiAgICAgICAgY2FjaGUuc2V0KGtleSwgeyBbYWxnXTogY3J5cHRvS2V5IH0pO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgY2FjaGVkW2FsZ10gPSBjcnlwdG9LZXk7XG4gICAgfVxuICAgIHJldHVybiBjcnlwdG9LZXk7XG59O1xuY29uc3Qgbm9ybWFsaXplUHVibGljS2V5ID0gKGtleSwgYWxnKSA9PiB7XG4gICAgaWYgKGlzS2V5T2JqZWN0KGtleSkpIHtcbiAgICAgICAgbGV0IGp3ayA9IGtleS5leHBvcnQoeyBmb3JtYXQ6ICdqd2snIH0pO1xuICAgICAgICBkZWxldGUgandrLmQ7XG4gICAgICAgIGRlbGV0ZSBqd2suZHA7XG4gICAgICAgIGRlbGV0ZSBqd2suZHE7XG4gICAgICAgIGRlbGV0ZSBqd2sucDtcbiAgICAgICAgZGVsZXRlIGp3ay5xO1xuICAgICAgICBkZWxldGUgandrLnFpO1xuICAgICAgICBpZiAoandrLmspIHtcbiAgICAgICAgICAgIHJldHVybiBleHBvcnRLZXlWYWx1ZShqd2suayk7XG4gICAgICAgIH1cbiAgICAgICAgcHViQ2FjaGUgfHwgKHB1YkNhY2hlID0gbmV3IFdlYWtNYXAoKSk7XG4gICAgICAgIHJldHVybiBpbXBvcnRBbmRDYWNoZShwdWJDYWNoZSwga2V5LCBqd2ssIGFsZyk7XG4gICAgfVxuICAgIGlmIChpc0pXSyhrZXkpKSB7XG4gICAgICAgIGlmIChrZXkuaylcbiAgICAgICAgICAgIHJldHVybiBkZWNvZGUoa2V5LmspO1xuICAgICAgICBwdWJDYWNoZSB8fCAocHViQ2FjaGUgPSBuZXcgV2Vha01hcCgpKTtcbiAgICAgICAgY29uc3QgY3J5cHRvS2V5ID0gaW1wb3J0QW5kQ2FjaGUocHViQ2FjaGUsIGtleSwga2V5LCBhbGcsIHRydWUpO1xuICAgICAgICByZXR1cm4gY3J5cHRvS2V5O1xuICAgIH1cbiAgICByZXR1cm4ga2V5O1xufTtcbmNvbnN0IG5vcm1hbGl6ZVByaXZhdGVLZXkgPSAoa2V5LCBhbGcpID0+IHtcbiAgICBpZiAoaXNLZXlPYmplY3Qoa2V5KSkge1xuICAgICAgICBsZXQgandrID0ga2V5LmV4cG9ydCh7IGZvcm1hdDogJ2p3aycgfSk7XG4gICAgICAgIGlmIChqd2suaykge1xuICAgICAgICAgICAgcmV0dXJuIGV4cG9ydEtleVZhbHVlKGp3ay5rKTtcbiAgICAgICAgfVxuICAgICAgICBwcml2Q2FjaGUgfHwgKHByaXZDYWNoZSA9IG5ldyBXZWFrTWFwKCkpO1xuICAgICAgICByZXR1cm4gaW1wb3J0QW5kQ2FjaGUocHJpdkNhY2hlLCBrZXksIGp3aywgYWxnKTtcbiAgICB9XG4gICAgaWYgKGlzSldLKGtleSkpIHtcbiAgICAgICAgaWYgKGtleS5rKVxuICAgICAgICAgICAgcmV0dXJuIGRlY29kZShrZXkuayk7XG4gICAgICAgIHByaXZDYWNoZSB8fCAocHJpdkNhY2hlID0gbmV3IFdlYWtNYXAoKSk7XG4gICAgICAgIGNvbnN0IGNyeXB0b0tleSA9IGltcG9ydEFuZENhY2hlKHByaXZDYWNoZSwga2V5LCBrZXksIGFsZywgdHJ1ZSk7XG4gICAgICAgIHJldHVybiBjcnlwdG9LZXk7XG4gICAgfVxuICAgIHJldHVybiBrZXk7XG59O1xuZXhwb3J0IGRlZmF1bHQgeyBub3JtYWxpemVQdWJsaWNLZXksIG5vcm1hbGl6ZVByaXZhdGVLZXkgfTtcbiIsImltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgcmFuZG9tIGZyb20gJy4uL3J1bnRpbWUvcmFuZG9tLmpzJztcbmV4cG9ydCBmdW5jdGlvbiBiaXRMZW5ndGgoYWxnKSB7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnQTEyOEdDTSc6XG4gICAgICAgICAgICByZXR1cm4gMTI4O1xuICAgICAgICBjYXNlICdBMTkyR0NNJzpcbiAgICAgICAgICAgIHJldHVybiAxOTI7XG4gICAgICAgIGNhc2UgJ0EyNTZHQ00nOlxuICAgICAgICBjYXNlICdBMTI4Q0JDLUhTMjU2JzpcbiAgICAgICAgICAgIHJldHVybiAyNTY7XG4gICAgICAgIGNhc2UgJ0ExOTJDQkMtSFMzODQnOlxuICAgICAgICAgICAgcmV0dXJuIDM4NDtcbiAgICAgICAgY2FzZSAnQTI1NkNCQy1IUzUxMic6XG4gICAgICAgICAgICByZXR1cm4gNTEyO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoYFVuc3VwcG9ydGVkIEpXRSBBbGdvcml0aG06ICR7YWxnfWApO1xuICAgIH1cbn1cbmV4cG9ydCBkZWZhdWx0IChhbGcpID0+IHJhbmRvbShuZXcgVWludDhBcnJheShiaXRMZW5ndGgoYWxnKSA+PiAzKSk7XG4iLCJpbXBvcnQgeyBkZWNvZGUgYXMgZGVjb2RlQmFzZTY0VVJMIH0gZnJvbSAnLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHsgZnJvbVNQS0ksIGZyb21QS0NTOCwgZnJvbVg1MDkgfSBmcm9tICcuLi9ydW50aW1lL2FzbjEuanMnO1xuaW1wb3J0IGFzS2V5T2JqZWN0IGZyb20gJy4uL3J1bnRpbWUvandrX3RvX2tleS5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4uL2xpYi9pc19vYmplY3QuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGltcG9ydFNQS0koc3BraSwgYWxnLCBvcHRpb25zKSB7XG4gICAgaWYgKHR5cGVvZiBzcGtpICE9PSAnc3RyaW5nJyB8fCBzcGtpLmluZGV4T2YoJy0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tJykgIT09IDApIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignXCJzcGtpXCIgbXVzdCBiZSBTUEtJIGZvcm1hdHRlZCBzdHJpbmcnKTtcbiAgICB9XG4gICAgcmV0dXJuIGZyb21TUEtJKHNwa2ksIGFsZywgb3B0aW9ucyk7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gaW1wb3J0WDUwOSh4NTA5LCBhbGcsIG9wdGlvbnMpIHtcbiAgICBpZiAodHlwZW9mIHg1MDkgIT09ICdzdHJpbmcnIHx8IHg1MDkuaW5kZXhPZignLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tJykgIT09IDApIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignXCJ4NTA5XCIgbXVzdCBiZSBYLjUwOSBmb3JtYXR0ZWQgc3RyaW5nJyk7XG4gICAgfVxuICAgIHJldHVybiBmcm9tWDUwOSh4NTA5LCBhbGcsIG9wdGlvbnMpO1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGltcG9ydFBLQ1M4KHBrY3M4LCBhbGcsIG9wdGlvbnMpIHtcbiAgICBpZiAodHlwZW9mIHBrY3M4ICE9PSAnc3RyaW5nJyB8fCBwa2NzOC5pbmRleE9mKCctLS0tLUJFR0lOIFBSSVZBVEUgS0VZLS0tLS0nKSAhPT0gMCkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdcInBrY3M4XCIgbXVzdCBiZSBQS0NTIzggZm9ybWF0dGVkIHN0cmluZycpO1xuICAgIH1cbiAgICByZXR1cm4gZnJvbVBLQ1M4KHBrY3M4LCBhbGcsIG9wdGlvbnMpO1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGltcG9ydEpXSyhqd2ssIGFsZykge1xuICAgIGlmICghaXNPYmplY3QoandrKSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdKV0sgbXVzdCBiZSBhbiBvYmplY3QnKTtcbiAgICB9XG4gICAgYWxnIHx8IChhbGcgPSBqd2suYWxnKTtcbiAgICBzd2l0Y2ggKGp3ay5rdHkpIHtcbiAgICAgICAgY2FzZSAnb2N0JzpcbiAgICAgICAgICAgIGlmICh0eXBlb2YgandrLmsgIT09ICdzdHJpbmcnIHx8ICFqd2suaykge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ21pc3NpbmcgXCJrXCIgKEtleSBWYWx1ZSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gZGVjb2RlQmFzZTY0VVJMKGp3ay5rKTtcbiAgICAgICAgY2FzZSAnUlNBJzpcbiAgICAgICAgICAgIGlmIChqd2sub3RoICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnUlNBIEpXSyBcIm90aFwiIChPdGhlciBQcmltZXMgSW5mbykgUGFyYW1ldGVyIHZhbHVlIGlzIG5vdCBzdXBwb3J0ZWQnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgY2FzZSAnRUMnOlxuICAgICAgICBjYXNlICdPS1AnOlxuICAgICAgICAgICAgcmV0dXJuIGFzS2V5T2JqZWN0KHsgLi4uandrLCBhbGcgfSk7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnVW5zdXBwb3J0ZWQgXCJrdHlcIiAoS2V5IFR5cGUpIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgIH1cbn1cbiIsImltcG9ydCB7IHdpdGhBbGcgYXMgaW52YWxpZEtleUlucHV0IH0gZnJvbSAnLi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgaXNLZXlMaWtlLCB7IHR5cGVzIH0gZnJvbSAnLi4vcnVudGltZS9pc19rZXlfbGlrZS5qcyc7XG5pbXBvcnQgKiBhcyBqd2sgZnJvbSAnLi9pc19qd2suanMnO1xuY29uc3QgdGFnID0gKGtleSkgPT4ga2V5Py5bU3ltYm9sLnRvU3RyaW5nVGFnXTtcbmNvbnN0IGp3a01hdGNoZXNPcCA9IChhbGcsIGtleSwgdXNhZ2UpID0+IHtcbiAgICBpZiAoa2V5LnVzZSAhPT0gdW5kZWZpbmVkICYmIGtleS51c2UgIT09ICdzaWcnKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0ludmFsaWQga2V5IGZvciB0aGlzIG9wZXJhdGlvbiwgd2hlbiBwcmVzZW50IGl0cyB1c2UgbXVzdCBiZSBzaWcnKTtcbiAgICB9XG4gICAgaWYgKGtleS5rZXlfb3BzICE9PSB1bmRlZmluZWQgJiYga2V5LmtleV9vcHMuaW5jbHVkZXM/Lih1c2FnZSkgIT09IHRydWUpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgSW52YWxpZCBrZXkgZm9yIHRoaXMgb3BlcmF0aW9uLCB3aGVuIHByZXNlbnQgaXRzIGtleV9vcHMgbXVzdCBpbmNsdWRlICR7dXNhZ2V9YCk7XG4gICAgfVxuICAgIGlmIChrZXkuYWxnICE9PSB1bmRlZmluZWQgJiYga2V5LmFsZyAhPT0gYWxnKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYEludmFsaWQga2V5IGZvciB0aGlzIG9wZXJhdGlvbiwgd2hlbiBwcmVzZW50IGl0cyBhbGcgbXVzdCBiZSAke2FsZ31gKTtcbiAgICB9XG4gICAgcmV0dXJuIHRydWU7XG59O1xuY29uc3Qgc3ltbWV0cmljVHlwZUNoZWNrID0gKGFsZywga2V5LCB1c2FnZSwgYWxsb3dKd2spID0+IHtcbiAgICBpZiAoa2V5IGluc3RhbmNlb2YgVWludDhBcnJheSlcbiAgICAgICAgcmV0dXJuO1xuICAgIGlmIChhbGxvd0p3ayAmJiBqd2suaXNKV0soa2V5KSkge1xuICAgICAgICBpZiAoandrLmlzU2VjcmV0SldLKGtleSkgJiYgandrTWF0Y2hlc09wKGFsZywga2V5LCB1c2FnZSkpXG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYEpTT04gV2ViIEtleSBmb3Igc3ltbWV0cmljIGFsZ29yaXRobXMgbXVzdCBoYXZlIEpXSyBcImt0eVwiIChLZXkgVHlwZSkgZXF1YWwgdG8gXCJvY3RcIiBhbmQgdGhlIEpXSyBcImtcIiAoS2V5IFZhbHVlKSBwcmVzZW50YCk7XG4gICAgfVxuICAgIGlmICghaXNLZXlMaWtlKGtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoYWxnLCBrZXksIC4uLnR5cGVzLCAnVWludDhBcnJheScsIGFsbG93SndrID8gJ0pTT04gV2ViIEtleScgOiBudWxsKSk7XG4gICAgfVxuICAgIGlmIChrZXkudHlwZSAhPT0gJ3NlY3JldCcpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHt0YWcoa2V5KX0gaW5zdGFuY2VzIGZvciBzeW1tZXRyaWMgYWxnb3JpdGhtcyBtdXN0IGJlIG9mIHR5cGUgXCJzZWNyZXRcImApO1xuICAgIH1cbn07XG5jb25zdCBhc3ltbWV0cmljVHlwZUNoZWNrID0gKGFsZywga2V5LCB1c2FnZSwgYWxsb3dKd2spID0+IHtcbiAgICBpZiAoYWxsb3dKd2sgJiYgandrLmlzSldLKGtleSkpIHtcbiAgICAgICAgc3dpdGNoICh1c2FnZSkge1xuICAgICAgICAgICAgY2FzZSAnc2lnbic6XG4gICAgICAgICAgICAgICAgaWYgKGp3ay5pc1ByaXZhdGVKV0soa2V5KSAmJiBqd2tNYXRjaGVzT3AoYWxnLCBrZXksIHVzYWdlKSlcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYEpTT04gV2ViIEtleSBmb3IgdGhpcyBvcGVyYXRpb24gYmUgYSBwcml2YXRlIEpXS2ApO1xuICAgICAgICAgICAgY2FzZSAndmVyaWZ5JzpcbiAgICAgICAgICAgICAgICBpZiAoandrLmlzUHVibGljSldLKGtleSkgJiYgandrTWF0Y2hlc09wKGFsZywga2V5LCB1c2FnZSkpXG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGBKU09OIFdlYiBLZXkgZm9yIHRoaXMgb3BlcmF0aW9uIGJlIGEgcHVibGljIEpXS2ApO1xuICAgICAgICB9XG4gICAgfVxuICAgIGlmICghaXNLZXlMaWtlKGtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoYWxnLCBrZXksIC4uLnR5cGVzLCBhbGxvd0p3ayA/ICdKU09OIFdlYiBLZXknIDogbnVsbCkpO1xuICAgIH1cbiAgICBpZiAoa2V5LnR5cGUgPT09ICdzZWNyZXQnKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYCR7dGFnKGtleSl9IGluc3RhbmNlcyBmb3IgYXN5bW1ldHJpYyBhbGdvcml0aG1zIG11c3Qgbm90IGJlIG9mIHR5cGUgXCJzZWNyZXRcImApO1xuICAgIH1cbiAgICBpZiAodXNhZ2UgPT09ICdzaWduJyAmJiBrZXkudHlwZSA9PT0gJ3B1YmxpYycpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHt0YWcoa2V5KX0gaW5zdGFuY2VzIGZvciBhc3ltbWV0cmljIGFsZ29yaXRobSBzaWduaW5nIG11c3QgYmUgb2YgdHlwZSBcInByaXZhdGVcImApO1xuICAgIH1cbiAgICBpZiAodXNhZ2UgPT09ICdkZWNyeXB0JyAmJiBrZXkudHlwZSA9PT0gJ3B1YmxpYycpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHt0YWcoa2V5KX0gaW5zdGFuY2VzIGZvciBhc3ltbWV0cmljIGFsZ29yaXRobSBkZWNyeXB0aW9uIG11c3QgYmUgb2YgdHlwZSBcInByaXZhdGVcImApO1xuICAgIH1cbiAgICBpZiAoa2V5LmFsZ29yaXRobSAmJiB1c2FnZSA9PT0gJ3ZlcmlmeScgJiYga2V5LnR5cGUgPT09ICdwcml2YXRlJykge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGAke3RhZyhrZXkpfSBpbnN0YW5jZXMgZm9yIGFzeW1tZXRyaWMgYWxnb3JpdGhtIHZlcmlmeWluZyBtdXN0IGJlIG9mIHR5cGUgXCJwdWJsaWNcImApO1xuICAgIH1cbiAgICBpZiAoa2V5LmFsZ29yaXRobSAmJiB1c2FnZSA9PT0gJ2VuY3J5cHQnICYmIGtleS50eXBlID09PSAncHJpdmF0ZScpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHt0YWcoa2V5KX0gaW5zdGFuY2VzIGZvciBhc3ltbWV0cmljIGFsZ29yaXRobSBlbmNyeXB0aW9uIG11c3QgYmUgb2YgdHlwZSBcInB1YmxpY1wiYCk7XG4gICAgfVxufTtcbmZ1bmN0aW9uIGNoZWNrS2V5VHlwZShhbGxvd0p3aywgYWxnLCBrZXksIHVzYWdlKSB7XG4gICAgY29uc3Qgc3ltbWV0cmljID0gYWxnLnN0YXJ0c1dpdGgoJ0hTJykgfHxcbiAgICAgICAgYWxnID09PSAnZGlyJyB8fFxuICAgICAgICBhbGcuc3RhcnRzV2l0aCgnUEJFUzInKSB8fFxuICAgICAgICAvXkFcXGR7M30oPzpHQ00pP0tXJC8udGVzdChhbGcpO1xuICAgIGlmIChzeW1tZXRyaWMpIHtcbiAgICAgICAgc3ltbWV0cmljVHlwZUNoZWNrKGFsZywga2V5LCB1c2FnZSwgYWxsb3dKd2spO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgYXN5bW1ldHJpY1R5cGVDaGVjayhhbGcsIGtleSwgdXNhZ2UsIGFsbG93SndrKTtcbiAgICB9XG59XG5leHBvcnQgZGVmYXVsdCBjaGVja0tleVR5cGUuYmluZCh1bmRlZmluZWQsIGZhbHNlKTtcbmV4cG9ydCBjb25zdCBjaGVja0tleVR5cGVXaXRoSndrID0gY2hlY2tLZXlUeXBlLmJpbmQodW5kZWZpbmVkLCB0cnVlKTtcbiIsImltcG9ydCB7IGNvbmNhdCwgdWludDY0YmUgfSBmcm9tICcuLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmltcG9ydCBjaGVja0l2TGVuZ3RoIGZyb20gJy4uL2xpYi9jaGVja19pdl9sZW5ndGguanMnO1xuaW1wb3J0IGNoZWNrQ2VrTGVuZ3RoIGZyb20gJy4vY2hlY2tfY2VrX2xlbmd0aC5qcyc7XG5pbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tFbmNDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgZ2VuZXJhdGVJdiBmcm9tICcuLi9saWIvaXYuanMnO1xuaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IHR5cGVzIH0gZnJvbSAnLi9pc19rZXlfbGlrZS5qcyc7XG5hc3luYyBmdW5jdGlvbiBjYmNFbmNyeXB0KGVuYywgcGxhaW50ZXh0LCBjZWssIGl2LCBhYWQpIHtcbiAgICBpZiAoIShjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChjZWssICdVaW50OEFycmF5JykpO1xuICAgIH1cbiAgICBjb25zdCBrZXlTaXplID0gcGFyc2VJbnQoZW5jLnNsaWNlKDEsIDQpLCAxMCk7XG4gICAgY29uc3QgZW5jS2V5ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGNlay5zdWJhcnJheShrZXlTaXplID4+IDMpLCAnQUVTLUNCQycsIGZhbHNlLCBbJ2VuY3J5cHQnXSk7XG4gICAgY29uc3QgbWFjS2V5ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGNlay5zdWJhcnJheSgwLCBrZXlTaXplID4+IDMpLCB7XG4gICAgICAgIGhhc2g6IGBTSEEtJHtrZXlTaXplIDw8IDF9YCxcbiAgICAgICAgbmFtZTogJ0hNQUMnLFxuICAgIH0sIGZhbHNlLCBbJ3NpZ24nXSk7XG4gICAgY29uc3QgY2lwaGVydGV4dCA9IG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZW5jcnlwdCh7XG4gICAgICAgIGl2LFxuICAgICAgICBuYW1lOiAnQUVTLUNCQycsXG4gICAgfSwgZW5jS2V5LCBwbGFpbnRleHQpKTtcbiAgICBjb25zdCBtYWNEYXRhID0gY29uY2F0KGFhZCwgaXYsIGNpcGhlcnRleHQsIHVpbnQ2NGJlKGFhZC5sZW5ndGggPDwgMykpO1xuICAgIGNvbnN0IHRhZyA9IG5ldyBVaW50OEFycmF5KChhd2FpdCBjcnlwdG8uc3VidGxlLnNpZ24oJ0hNQUMnLCBtYWNLZXksIG1hY0RhdGEpKS5zbGljZSgwLCBrZXlTaXplID4+IDMpKTtcbiAgICByZXR1cm4geyBjaXBoZXJ0ZXh0LCB0YWcsIGl2IH07XG59XG5hc3luYyBmdW5jdGlvbiBnY21FbmNyeXB0KGVuYywgcGxhaW50ZXh0LCBjZWssIGl2LCBhYWQpIHtcbiAgICBsZXQgZW5jS2V5O1xuICAgIGlmIChjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIGVuY0tleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBjZWssICdBRVMtR0NNJywgZmFsc2UsIFsnZW5jcnlwdCddKTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIGNoZWNrRW5jQ3J5cHRvS2V5KGNlaywgZW5jLCAnZW5jcnlwdCcpO1xuICAgICAgICBlbmNLZXkgPSBjZWs7XG4gICAgfVxuICAgIGNvbnN0IGVuY3J5cHRlZCA9IG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZW5jcnlwdCh7XG4gICAgICAgIGFkZGl0aW9uYWxEYXRhOiBhYWQsXG4gICAgICAgIGl2LFxuICAgICAgICBuYW1lOiAnQUVTLUdDTScsXG4gICAgICAgIHRhZ0xlbmd0aDogMTI4LFxuICAgIH0sIGVuY0tleSwgcGxhaW50ZXh0KSk7XG4gICAgY29uc3QgdGFnID0gZW5jcnlwdGVkLnNsaWNlKC0xNik7XG4gICAgY29uc3QgY2lwaGVydGV4dCA9IGVuY3J5cHRlZC5zbGljZSgwLCAtMTYpO1xuICAgIHJldHVybiB7IGNpcGhlcnRleHQsIHRhZywgaXYgfTtcbn1cbmNvbnN0IGVuY3J5cHQgPSBhc3luYyAoZW5jLCBwbGFpbnRleHQsIGNlaywgaXYsIGFhZCkgPT4ge1xuICAgIGlmICghaXNDcnlwdG9LZXkoY2VrKSAmJiAhKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGNlaywgLi4udHlwZXMsICdVaW50OEFycmF5JykpO1xuICAgIH1cbiAgICBpZiAoaXYpIHtcbiAgICAgICAgY2hlY2tJdkxlbmd0aChlbmMsIGl2KTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIGl2ID0gZ2VuZXJhdGVJdihlbmMpO1xuICAgIH1cbiAgICBzd2l0Y2ggKGVuYykge1xuICAgICAgICBjYXNlICdBMTI4Q0JDLUhTMjU2JzpcbiAgICAgICAgY2FzZSAnQTE5MkNCQy1IUzM4NCc6XG4gICAgICAgIGNhc2UgJ0EyNTZDQkMtSFM1MTInOlxuICAgICAgICAgICAgaWYgKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgICAgICAgICBjaGVja0Nla0xlbmd0aChjZWssIHBhcnNlSW50KGVuYy5zbGljZSgtMyksIDEwKSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gY2JjRW5jcnlwdChlbmMsIHBsYWludGV4dCwgY2VrLCBpdiwgYWFkKTtcbiAgICAgICAgY2FzZSAnQTEyOEdDTSc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ00nOlxuICAgICAgICBjYXNlICdBMjU2R0NNJzpcbiAgICAgICAgICAgIGlmIChjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgICAgICAgICAgY2hlY2tDZWtMZW5ndGgoY2VrLCBwYXJzZUludChlbmMuc2xpY2UoMSwgNCksIDEwKSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gZ2NtRW5jcnlwdChlbmMsIHBsYWludGV4dCwgY2VrLCBpdiwgYWFkKTtcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdVbnN1cHBvcnRlZCBKV0UgQ29udGVudCBFbmNyeXB0aW9uIEFsZ29yaXRobScpO1xuICAgIH1cbn07XG5leHBvcnQgZGVmYXVsdCBlbmNyeXB0O1xuIiwiaW1wb3J0IGVuY3J5cHQgZnJvbSAnLi4vcnVudGltZS9lbmNyeXB0LmpzJztcbmltcG9ydCBkZWNyeXB0IGZyb20gJy4uL3J1bnRpbWUvZGVjcnlwdC5qcyc7XG5pbXBvcnQgeyBlbmNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHdyYXAoYWxnLCBrZXksIGNlaywgaXYpIHtcbiAgICBjb25zdCBqd2VBbGdvcml0aG0gPSBhbGcuc2xpY2UoMCwgNyk7XG4gICAgY29uc3Qgd3JhcHBlZCA9IGF3YWl0IGVuY3J5cHQoandlQWxnb3JpdGhtLCBjZWssIGtleSwgaXYsIG5ldyBVaW50OEFycmF5KDApKTtcbiAgICByZXR1cm4ge1xuICAgICAgICBlbmNyeXB0ZWRLZXk6IHdyYXBwZWQuY2lwaGVydGV4dCxcbiAgICAgICAgaXY6IGJhc2U2NHVybCh3cmFwcGVkLml2KSxcbiAgICAgICAgdGFnOiBiYXNlNjR1cmwod3JhcHBlZC50YWcpLFxuICAgIH07XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdW53cmFwKGFsZywga2V5LCBlbmNyeXB0ZWRLZXksIGl2LCB0YWcpIHtcbiAgICBjb25zdCBqd2VBbGdvcml0aG0gPSBhbGcuc2xpY2UoMCwgNyk7XG4gICAgcmV0dXJuIGRlY3J5cHQoandlQWxnb3JpdGhtLCBrZXksIGVuY3J5cHRlZEtleSwgaXYsIHRhZywgbmV3IFVpbnQ4QXJyYXkoMCkpO1xufVxuIiwiaW1wb3J0IHsgdW53cmFwIGFzIGFlc0t3IH0gZnJvbSAnLi4vcnVudGltZS9hZXNrdy5qcyc7XG5pbXBvcnQgKiBhcyBFQ0RIIGZyb20gJy4uL3J1bnRpbWUvZWNkaGVzLmpzJztcbmltcG9ydCB7IGRlY3J5cHQgYXMgcGJlczJLdyB9IGZyb20gJy4uL3J1bnRpbWUvcGJlczJrdy5qcyc7XG5pbXBvcnQgeyBkZWNyeXB0IGFzIHJzYUVzIH0gZnJvbSAnLi4vcnVudGltZS9yc2Flcy5qcyc7XG5pbXBvcnQgeyBkZWNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IG5vcm1hbGl6ZSBmcm9tICcuLi9ydW50aW1lL25vcm1hbGl6ZV9rZXkuanMnO1xuaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCwgSldFSW52YWxpZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IGJpdExlbmd0aCBhcyBjZWtMZW5ndGggfSBmcm9tICcuLi9saWIvY2VrLmpzJztcbmltcG9ydCB7IGltcG9ydEpXSyB9IGZyb20gJy4uL2tleS9pbXBvcnQuanMnO1xuaW1wb3J0IGNoZWNrS2V5VHlwZSBmcm9tICcuL2NoZWNrX2tleV90eXBlLmpzJztcbmltcG9ydCBpc09iamVjdCBmcm9tICcuL2lzX29iamVjdC5qcyc7XG5pbXBvcnQgeyB1bndyYXAgYXMgYWVzR2NtS3cgfSBmcm9tICcuL2Flc2djbWt3LmpzJztcbmFzeW5jIGZ1bmN0aW9uIGRlY3J5cHRLZXlNYW5hZ2VtZW50KGFsZywga2V5LCBlbmNyeXB0ZWRLZXksIGpvc2VIZWFkZXIsIG9wdGlvbnMpIHtcbiAgICBjaGVja0tleVR5cGUoYWxnLCBrZXksICdkZWNyeXB0Jyk7XG4gICAga2V5ID0gKGF3YWl0IG5vcm1hbGl6ZS5ub3JtYWxpemVQcml2YXRlS2V5Py4oa2V5LCBhbGcpKSB8fCBrZXk7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnZGlyJzoge1xuICAgICAgICAgICAgaWYgKGVuY3J5cHRlZEtleSAhPT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdFbmNvdW50ZXJlZCB1bmV4cGVjdGVkIEpXRSBFbmNyeXB0ZWQgS2V5Jyk7XG4gICAgICAgICAgICByZXR1cm4ga2V5O1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0VDREgtRVMnOlxuICAgICAgICAgICAgaWYgKGVuY3J5cHRlZEtleSAhPT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdFbmNvdW50ZXJlZCB1bmV4cGVjdGVkIEpXRSBFbmNyeXB0ZWQgS2V5Jyk7XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMTkyS1cnOlxuICAgICAgICBjYXNlICdFQ0RILUVTK0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGlmICghaXNPYmplY3Qoam9zZUhlYWRlci5lcGspKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKGBKT1NFIEhlYWRlciBcImVwa1wiIChFcGhlbWVyYWwgUHVibGljIEtleSkgbWlzc2luZyBvciBpbnZhbGlkYCk7XG4gICAgICAgICAgICBpZiAoIUVDREguZWNkaEFsbG93ZWQoa2V5KSlcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnRUNESCB3aXRoIHRoZSBwcm92aWRlZCBrZXkgaXMgbm90IGFsbG93ZWQgb3Igbm90IHN1cHBvcnRlZCBieSB5b3VyIGphdmFzY3JpcHQgcnVudGltZScpO1xuICAgICAgICAgICAgY29uc3QgZXBrID0gYXdhaXQgaW1wb3J0SldLKGpvc2VIZWFkZXIuZXBrLCBhbGcpO1xuICAgICAgICAgICAgbGV0IHBhcnR5VUluZm87XG4gICAgICAgICAgICBsZXQgcGFydHlWSW5mbztcbiAgICAgICAgICAgIGlmIChqb3NlSGVhZGVyLmFwdSAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICAgICAgaWYgKHR5cGVvZiBqb3NlSGVhZGVyLmFwdSAhPT0gJ3N0cmluZycpXG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKGBKT1NFIEhlYWRlciBcImFwdVwiIChBZ3JlZW1lbnQgUGFydHlVSW5mbykgaW52YWxpZGApO1xuICAgICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgICAgIHBhcnR5VUluZm8gPSBiYXNlNjR1cmwoam9zZUhlYWRlci5hcHUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgYXB1Jyk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKGpvc2VIZWFkZXIuYXB2ICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgICAgICBpZiAodHlwZW9mIGpvc2VIZWFkZXIuYXB2ICE9PSAnc3RyaW5nJylcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwiYXB2XCIgKEFncmVlbWVudCBQYXJ0eVZJbmZvKSBpbnZhbGlkYCk7XG4gICAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICAgICAgcGFydHlWSW5mbyA9IGJhc2U2NHVybChqb3NlSGVhZGVyLmFwdik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBhcHYnKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjb25zdCBzaGFyZWRTZWNyZXQgPSBhd2FpdCBFQ0RILmRlcml2ZUtleShlcGssIGtleSwgYWxnID09PSAnRUNESC1FUycgPyBqb3NlSGVhZGVyLmVuYyA6IGFsZywgYWxnID09PSAnRUNESC1FUycgPyBjZWtMZW5ndGgoam9zZUhlYWRlci5lbmMpIDogcGFyc2VJbnQoYWxnLnNsaWNlKC01LCAtMiksIDEwKSwgcGFydHlVSW5mbywgcGFydHlWSW5mbyk7XG4gICAgICAgICAgICBpZiAoYWxnID09PSAnRUNESC1FUycpXG4gICAgICAgICAgICAgICAgcmV0dXJuIHNoYXJlZFNlY3JldDtcbiAgICAgICAgICAgIGlmIChlbmNyeXB0ZWRLZXkgPT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEVuY3J5cHRlZCBLZXkgbWlzc2luZycpO1xuICAgICAgICAgICAgcmV0dXJuIGFlc0t3KGFsZy5zbGljZSgtNiksIHNoYXJlZFNlY3JldCwgZW5jcnlwdGVkS2V5KTtcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdSU0ExXzUnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTI1Nic6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTM4NCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTUxMic6IHtcbiAgICAgICAgICAgIGlmIChlbmNyeXB0ZWRLZXkgPT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEVuY3J5cHRlZCBLZXkgbWlzc2luZycpO1xuICAgICAgICAgICAgcmV0dXJuIHJzYUVzKGFsZywga2V5LCBlbmNyeXB0ZWRLZXkpO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ1BCRVMyLUhTMjU2K0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ1BCRVMyLUhTMzg0K0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ1BCRVMyLUhTNTEyK0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGlmIChlbmNyeXB0ZWRLZXkgPT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEVuY3J5cHRlZCBLZXkgbWlzc2luZycpO1xuICAgICAgICAgICAgaWYgKHR5cGVvZiBqb3NlSGVhZGVyLnAyYyAhPT0gJ251bWJlcicpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwicDJjXCIgKFBCRVMyIENvdW50KSBtaXNzaW5nIG9yIGludmFsaWRgKTtcbiAgICAgICAgICAgIGNvbnN0IHAyY0xpbWl0ID0gb3B0aW9ucz8ubWF4UEJFUzJDb3VudCB8fCAxMDAwMDtcbiAgICAgICAgICAgIGlmIChqb3NlSGVhZGVyLnAyYyA+IHAyY0xpbWl0KVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKGBKT1NFIEhlYWRlciBcInAyY1wiIChQQkVTMiBDb3VudCkgb3V0IGlzIG9mIGFjY2VwdGFibGUgYm91bmRzYCk7XG4gICAgICAgICAgICBpZiAodHlwZW9mIGpvc2VIZWFkZXIucDJzICE9PSAnc3RyaW5nJylcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSk9TRSBIZWFkZXIgXCJwMnNcIiAoUEJFUzIgU2FsdCkgbWlzc2luZyBvciBpbnZhbGlkYCk7XG4gICAgICAgICAgICBsZXQgcDJzO1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBwMnMgPSBiYXNlNjR1cmwoam9zZUhlYWRlci5wMnMpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgcDJzJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gcGJlczJLdyhhbGcsIGtleSwgZW5jcnlwdGVkS2V5LCBqb3NlSGVhZGVyLnAyYywgcDJzKTtcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdBMTI4S1cnOlxuICAgICAgICBjYXNlICdBMTkyS1cnOlxuICAgICAgICBjYXNlICdBMjU2S1cnOiB7XG4gICAgICAgICAgICBpZiAoZW5jcnlwdGVkS2V5ID09PSB1bmRlZmluZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBFbmNyeXB0ZWQgS2V5IG1pc3NpbmcnKTtcbiAgICAgICAgICAgIHJldHVybiBhZXNLdyhhbGcsIGtleSwgZW5jcnlwdGVkS2V5KTtcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdBMTI4R0NNS1cnOlxuICAgICAgICBjYXNlICdBMTkyR0NNS1cnOlxuICAgICAgICBjYXNlICdBMjU2R0NNS1cnOiB7XG4gICAgICAgICAgICBpZiAoZW5jcnlwdGVkS2V5ID09PSB1bmRlZmluZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBFbmNyeXB0ZWQgS2V5IG1pc3NpbmcnKTtcbiAgICAgICAgICAgIGlmICh0eXBlb2Ygam9zZUhlYWRlci5pdiAhPT0gJ3N0cmluZycpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwiaXZcIiAoSW5pdGlhbGl6YXRpb24gVmVjdG9yKSBtaXNzaW5nIG9yIGludmFsaWRgKTtcbiAgICAgICAgICAgIGlmICh0eXBlb2Ygam9zZUhlYWRlci50YWcgIT09ICdzdHJpbmcnKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKGBKT1NFIEhlYWRlciBcInRhZ1wiIChBdXRoZW50aWNhdGlvbiBUYWcpIG1pc3Npbmcgb3IgaW52YWxpZGApO1xuICAgICAgICAgICAgbGV0IGl2O1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBpdiA9IGJhc2U2NHVybChqb3NlSGVhZGVyLml2KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIGl2Jyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBsZXQgdGFnO1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICB0YWcgPSBiYXNlNjR1cmwoam9zZUhlYWRlci50YWcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgdGFnJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gYWVzR2NtS3coYWxnLCBrZXksIGVuY3J5cHRlZEtleSwgaXYsIHRhZyk7XG4gICAgICAgIH1cbiAgICAgICAgZGVmYXVsdDoge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgXCJhbGdcIiAoSldFIEFsZ29yaXRobSkgaGVhZGVyIHZhbHVlJyk7XG4gICAgICAgIH1cbiAgICB9XG59XG5leHBvcnQgZGVmYXVsdCBkZWNyeXB0S2V5TWFuYWdlbWVudDtcbiIsImltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5mdW5jdGlvbiB2YWxpZGF0ZUNyaXQoRXJyLCByZWNvZ25pemVkRGVmYXVsdCwgcmVjb2duaXplZE9wdGlvbiwgcHJvdGVjdGVkSGVhZGVyLCBqb3NlSGVhZGVyKSB7XG4gICAgaWYgKGpvc2VIZWFkZXIuY3JpdCAhPT0gdW5kZWZpbmVkICYmIHByb3RlY3RlZEhlYWRlcj8uY3JpdCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnIoJ1wiY3JpdFwiIChDcml0aWNhbCkgSGVhZGVyIFBhcmFtZXRlciBNVVNUIGJlIGludGVncml0eSBwcm90ZWN0ZWQnKTtcbiAgICB9XG4gICAgaWYgKCFwcm90ZWN0ZWRIZWFkZXIgfHwgcHJvdGVjdGVkSGVhZGVyLmNyaXQgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICByZXR1cm4gbmV3IFNldCgpO1xuICAgIH1cbiAgICBpZiAoIUFycmF5LmlzQXJyYXkocHJvdGVjdGVkSGVhZGVyLmNyaXQpIHx8XG4gICAgICAgIHByb3RlY3RlZEhlYWRlci5jcml0Lmxlbmd0aCA9PT0gMCB8fFxuICAgICAgICBwcm90ZWN0ZWRIZWFkZXIuY3JpdC5zb21lKChpbnB1dCkgPT4gdHlwZW9mIGlucHV0ICE9PSAnc3RyaW5nJyB8fCBpbnB1dC5sZW5ndGggPT09IDApKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnIoJ1wiY3JpdFwiIChDcml0aWNhbCkgSGVhZGVyIFBhcmFtZXRlciBNVVNUIGJlIGFuIGFycmF5IG9mIG5vbi1lbXB0eSBzdHJpbmdzIHdoZW4gcHJlc2VudCcpO1xuICAgIH1cbiAgICBsZXQgcmVjb2duaXplZDtcbiAgICBpZiAocmVjb2duaXplZE9wdGlvbiAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHJlY29nbml6ZWQgPSBuZXcgTWFwKFsuLi5PYmplY3QuZW50cmllcyhyZWNvZ25pemVkT3B0aW9uKSwgLi4ucmVjb2duaXplZERlZmF1bHQuZW50cmllcygpXSk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICByZWNvZ25pemVkID0gcmVjb2duaXplZERlZmF1bHQ7XG4gICAgfVxuICAgIGZvciAoY29uc3QgcGFyYW1ldGVyIG9mIHByb3RlY3RlZEhlYWRlci5jcml0KSB7XG4gICAgICAgIGlmICghcmVjb2duaXplZC5oYXMocGFyYW1ldGVyKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoYEV4dGVuc2lvbiBIZWFkZXIgUGFyYW1ldGVyIFwiJHtwYXJhbWV0ZXJ9XCIgaXMgbm90IHJlY29nbml6ZWRgKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoam9zZUhlYWRlcltwYXJhbWV0ZXJdID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnIoYEV4dGVuc2lvbiBIZWFkZXIgUGFyYW1ldGVyIFwiJHtwYXJhbWV0ZXJ9XCIgaXMgbWlzc2luZ2ApO1xuICAgICAgICB9XG4gICAgICAgIGlmIChyZWNvZ25pemVkLmdldChwYXJhbWV0ZXIpICYmIHByb3RlY3RlZEhlYWRlcltwYXJhbWV0ZXJdID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnIoYEV4dGVuc2lvbiBIZWFkZXIgUGFyYW1ldGVyIFwiJHtwYXJhbWV0ZXJ9XCIgTVVTVCBiZSBpbnRlZ3JpdHkgcHJvdGVjdGVkYCk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIG5ldyBTZXQocHJvdGVjdGVkSGVhZGVyLmNyaXQpO1xufVxuZXhwb3J0IGRlZmF1bHQgdmFsaWRhdGVDcml0O1xuIiwiY29uc3QgdmFsaWRhdGVBbGdvcml0aG1zID0gKG9wdGlvbiwgYWxnb3JpdGhtcykgPT4ge1xuICAgIGlmIChhbGdvcml0aG1zICE9PSB1bmRlZmluZWQgJiZcbiAgICAgICAgKCFBcnJheS5pc0FycmF5KGFsZ29yaXRobXMpIHx8IGFsZ29yaXRobXMuc29tZSgocykgPT4gdHlwZW9mIHMgIT09ICdzdHJpbmcnKSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgXCIke29wdGlvbn1cIiBvcHRpb24gbXVzdCBiZSBhbiBhcnJheSBvZiBzdHJpbmdzYCk7XG4gICAgfVxuICAgIGlmICghYWxnb3JpdGhtcykge1xuICAgICAgICByZXR1cm4gdW5kZWZpbmVkO1xuICAgIH1cbiAgICByZXR1cm4gbmV3IFNldChhbGdvcml0aG1zKTtcbn07XG5leHBvcnQgZGVmYXVsdCB2YWxpZGF0ZUFsZ29yaXRobXM7XG4iLCJpbXBvcnQgeyBkZWNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi4vLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IGRlY3J5cHQgZnJvbSAnLi4vLi4vcnVudGltZS9kZWNyeXB0LmpzJztcbmltcG9ydCB7IEpPU0VBbGdOb3RBbGxvd2VkLCBKT1NFTm90U3VwcG9ydGVkLCBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IGlzRGlzam9pbnQgZnJvbSAnLi4vLi4vbGliL2lzX2Rpc2pvaW50LmpzJztcbmltcG9ydCBpc09iamVjdCBmcm9tICcuLi8uLi9saWIvaXNfb2JqZWN0LmpzJztcbmltcG9ydCBkZWNyeXB0S2V5TWFuYWdlbWVudCBmcm9tICcuLi8uLi9saWIvZGVjcnlwdF9rZXlfbWFuYWdlbWVudC5qcyc7XG5pbXBvcnQgeyBlbmNvZGVyLCBkZWNvZGVyLCBjb25jYXQgfSBmcm9tICcuLi8uLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmltcG9ydCBnZW5lcmF0ZUNlayBmcm9tICcuLi8uLi9saWIvY2VrLmpzJztcbmltcG9ydCB2YWxpZGF0ZUNyaXQgZnJvbSAnLi4vLi4vbGliL3ZhbGlkYXRlX2NyaXQuanMnO1xuaW1wb3J0IHZhbGlkYXRlQWxnb3JpdGhtcyBmcm9tICcuLi8uLi9saWIvdmFsaWRhdGVfYWxnb3JpdGhtcy5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZmxhdHRlbmVkRGVjcnlwdChqd2UsIGtleSwgb3B0aW9ucykge1xuICAgIGlmICghaXNPYmplY3QoandlKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmxhdHRlbmVkIEpXRSBtdXN0IGJlIGFuIG9iamVjdCcpO1xuICAgIH1cbiAgICBpZiAoandlLnByb3RlY3RlZCA9PT0gdW5kZWZpbmVkICYmIGp3ZS5oZWFkZXIgPT09IHVuZGVmaW5lZCAmJiBqd2UudW5wcm90ZWN0ZWQgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSk9TRSBIZWFkZXIgbWlzc2luZycpO1xuICAgIH1cbiAgICBpZiAoandlLml2ICE9PSB1bmRlZmluZWQgJiYgdHlwZW9mIGp3ZS5pdiAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBJbml0aWFsaXphdGlvbiBWZWN0b3IgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBqd2UuY2lwaGVydGV4dCAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBDaXBoZXJ0ZXh0IG1pc3Npbmcgb3IgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3ZS50YWcgIT09IHVuZGVmaW5lZCAmJiB0eXBlb2YgandlLnRhZyAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBBdXRoZW50aWNhdGlvbiBUYWcgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3ZS5wcm90ZWN0ZWQgIT09IHVuZGVmaW5lZCAmJiB0eXBlb2YgandlLnByb3RlY3RlZCAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBQcm90ZWN0ZWQgSGVhZGVyIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmIChqd2UuZW5jcnlwdGVkX2tleSAhPT0gdW5kZWZpbmVkICYmIHR5cGVvZiBqd2UuZW5jcnlwdGVkX2tleSAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBFbmNyeXB0ZWQgS2V5IGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmIChqd2UuYWFkICE9PSB1bmRlZmluZWQgJiYgdHlwZW9mIGp3ZS5hYWQgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgQUFEIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmIChqd2UuaGVhZGVyICE9PSB1bmRlZmluZWQgJiYgIWlzT2JqZWN0KGp3ZS5oZWFkZXIpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgU2hhcmVkIFVucHJvdGVjdGVkIEhlYWRlciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoandlLnVucHJvdGVjdGVkICE9PSB1bmRlZmluZWQgJiYgIWlzT2JqZWN0KGp3ZS51bnByb3RlY3RlZCkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBQZXItUmVjaXBpZW50IFVucHJvdGVjdGVkIEhlYWRlciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBsZXQgcGFyc2VkUHJvdDtcbiAgICBpZiAoandlLnByb3RlY3RlZCkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgY29uc3QgcHJvdGVjdGVkSGVhZGVyID0gYmFzZTY0dXJsKGp3ZS5wcm90ZWN0ZWQpO1xuICAgICAgICAgICAgcGFyc2VkUHJvdCA9IEpTT04ucGFyc2UoZGVjb2Rlci5kZWNvZGUocHJvdGVjdGVkSGVhZGVyKSk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBQcm90ZWN0ZWQgSGVhZGVyIGlzIGludmFsaWQnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBpZiAoIWlzRGlzam9pbnQocGFyc2VkUHJvdCwgandlLmhlYWRlciwgandlLnVucHJvdGVjdGVkKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFByb3RlY3RlZCwgSldFIFVucHJvdGVjdGVkIEhlYWRlciwgYW5kIEpXRSBQZXItUmVjaXBpZW50IFVucHJvdGVjdGVkIEhlYWRlciBQYXJhbWV0ZXIgbmFtZXMgbXVzdCBiZSBkaXNqb2ludCcpO1xuICAgIH1cbiAgICBjb25zdCBqb3NlSGVhZGVyID0ge1xuICAgICAgICAuLi5wYXJzZWRQcm90LFxuICAgICAgICAuLi5qd2UuaGVhZGVyLFxuICAgICAgICAuLi5qd2UudW5wcm90ZWN0ZWQsXG4gICAgfTtcbiAgICB2YWxpZGF0ZUNyaXQoSldFSW52YWxpZCwgbmV3IE1hcCgpLCBvcHRpb25zPy5jcml0LCBwYXJzZWRQcm90LCBqb3NlSGVhZGVyKTtcbiAgICBpZiAoam9zZUhlYWRlci56aXAgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSldFIFwiemlwXCIgKENvbXByZXNzaW9uIEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBpcyBub3Qgc3VwcG9ydGVkLicpO1xuICAgIH1cbiAgICBjb25zdCB7IGFsZywgZW5jIH0gPSBqb3NlSGVhZGVyO1xuICAgIGlmICh0eXBlb2YgYWxnICE9PSAnc3RyaW5nJyB8fCAhYWxnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdtaXNzaW5nIEpXRSBBbGdvcml0aG0gKGFsZykgaW4gSldFIEhlYWRlcicpO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIGVuYyAhPT0gJ3N0cmluZycgfHwgIWVuYykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnbWlzc2luZyBKV0UgRW5jcnlwdGlvbiBBbGdvcml0aG0gKGVuYykgaW4gSldFIEhlYWRlcicpO1xuICAgIH1cbiAgICBjb25zdCBrZXlNYW5hZ2VtZW50QWxnb3JpdGhtcyA9IG9wdGlvbnMgJiYgdmFsaWRhdGVBbGdvcml0aG1zKCdrZXlNYW5hZ2VtZW50QWxnb3JpdGhtcycsIG9wdGlvbnMua2V5TWFuYWdlbWVudEFsZ29yaXRobXMpO1xuICAgIGNvbnN0IGNvbnRlbnRFbmNyeXB0aW9uQWxnb3JpdGhtcyA9IG9wdGlvbnMgJiZcbiAgICAgICAgdmFsaWRhdGVBbGdvcml0aG1zKCdjb250ZW50RW5jcnlwdGlvbkFsZ29yaXRobXMnLCBvcHRpb25zLmNvbnRlbnRFbmNyeXB0aW9uQWxnb3JpdGhtcyk7XG4gICAgaWYgKChrZXlNYW5hZ2VtZW50QWxnb3JpdGhtcyAmJiAha2V5TWFuYWdlbWVudEFsZ29yaXRobXMuaGFzKGFsZykpIHx8XG4gICAgICAgICgha2V5TWFuYWdlbWVudEFsZ29yaXRobXMgJiYgYWxnLnN0YXJ0c1dpdGgoJ1BCRVMyJykpKSB7XG4gICAgICAgIHRocm93IG5ldyBKT1NFQWxnTm90QWxsb3dlZCgnXCJhbGdcIiAoQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIHZhbHVlIG5vdCBhbGxvd2VkJyk7XG4gICAgfVxuICAgIGlmIChjb250ZW50RW5jcnlwdGlvbkFsZ29yaXRobXMgJiYgIWNvbnRlbnRFbmNyeXB0aW9uQWxnb3JpdGhtcy5oYXMoZW5jKSkge1xuICAgICAgICB0aHJvdyBuZXcgSk9TRUFsZ05vdEFsbG93ZWQoJ1wiZW5jXCIgKEVuY3J5cHRpb24gQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIHZhbHVlIG5vdCBhbGxvd2VkJyk7XG4gICAgfVxuICAgIGxldCBlbmNyeXB0ZWRLZXk7XG4gICAgaWYgKGp3ZS5lbmNyeXB0ZWRfa2V5ICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIGVuY3J5cHRlZEtleSA9IGJhc2U2NHVybChqd2UuZW5jcnlwdGVkX2tleSk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBlbmNyeXB0ZWRfa2V5Jyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgbGV0IHJlc29sdmVkS2V5ID0gZmFsc2U7XG4gICAgaWYgKHR5cGVvZiBrZXkgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAga2V5ID0gYXdhaXQga2V5KHBhcnNlZFByb3QsIGp3ZSk7XG4gICAgICAgIHJlc29sdmVkS2V5ID0gdHJ1ZTtcbiAgICB9XG4gICAgbGV0IGNlaztcbiAgICB0cnkge1xuICAgICAgICBjZWsgPSBhd2FpdCBkZWNyeXB0S2V5TWFuYWdlbWVudChhbGcsIGtleSwgZW5jcnlwdGVkS2V5LCBqb3NlSGVhZGVyLCBvcHRpb25zKTtcbiAgICB9XG4gICAgY2F0Y2ggKGVycikge1xuICAgICAgICBpZiAoZXJyIGluc3RhbmNlb2YgVHlwZUVycm9yIHx8IGVyciBpbnN0YW5jZW9mIEpXRUludmFsaWQgfHwgZXJyIGluc3RhbmNlb2YgSk9TRU5vdFN1cHBvcnRlZCkge1xuICAgICAgICAgICAgdGhyb3cgZXJyO1xuICAgICAgICB9XG4gICAgICAgIGNlayA9IGdlbmVyYXRlQ2VrKGVuYyk7XG4gICAgfVxuICAgIGxldCBpdjtcbiAgICBsZXQgdGFnO1xuICAgIGlmIChqd2UuaXYgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgaXYgPSBiYXNlNjR1cmwoandlLml2KTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIGl2Jyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgaWYgKGp3ZS50YWcgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgdGFnID0gYmFzZTY0dXJsKGp3ZS50YWcpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgdGFnJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgY29uc3QgcHJvdGVjdGVkSGVhZGVyID0gZW5jb2Rlci5lbmNvZGUoandlLnByb3RlY3RlZCA/PyAnJyk7XG4gICAgbGV0IGFkZGl0aW9uYWxEYXRhO1xuICAgIGlmIChqd2UuYWFkICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgYWRkaXRpb25hbERhdGEgPSBjb25jYXQocHJvdGVjdGVkSGVhZGVyLCBlbmNvZGVyLmVuY29kZSgnLicpLCBlbmNvZGVyLmVuY29kZShqd2UuYWFkKSk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBhZGRpdGlvbmFsRGF0YSA9IHByb3RlY3RlZEhlYWRlcjtcbiAgICB9XG4gICAgbGV0IGNpcGhlcnRleHQ7XG4gICAgdHJ5IHtcbiAgICAgICAgY2lwaGVydGV4dCA9IGJhc2U2NHVybChqd2UuY2lwaGVydGV4dCk7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBjaXBoZXJ0ZXh0Jyk7XG4gICAgfVxuICAgIGNvbnN0IHBsYWludGV4dCA9IGF3YWl0IGRlY3J5cHQoZW5jLCBjZWssIGNpcGhlcnRleHQsIGl2LCB0YWcsIGFkZGl0aW9uYWxEYXRhKTtcbiAgICBjb25zdCByZXN1bHQgPSB7IHBsYWludGV4dCB9O1xuICAgIGlmIChqd2UucHJvdGVjdGVkICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmVzdWx0LnByb3RlY3RlZEhlYWRlciA9IHBhcnNlZFByb3Q7XG4gICAgfVxuICAgIGlmIChqd2UuYWFkICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHJlc3VsdC5hZGRpdGlvbmFsQXV0aGVudGljYXRlZERhdGEgPSBiYXNlNjR1cmwoandlLmFhZCk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBhYWQnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBpZiAoandlLnVucHJvdGVjdGVkICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmVzdWx0LnNoYXJlZFVucHJvdGVjdGVkSGVhZGVyID0gandlLnVucHJvdGVjdGVkO1xuICAgIH1cbiAgICBpZiAoandlLmhlYWRlciAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHJlc3VsdC51bnByb3RlY3RlZEhlYWRlciA9IGp3ZS5oZWFkZXI7XG4gICAgfVxuICAgIGlmIChyZXNvbHZlZEtleSkge1xuICAgICAgICByZXR1cm4geyAuLi5yZXN1bHQsIGtleSB9O1xuICAgIH1cbiAgICByZXR1cm4gcmVzdWx0O1xufVxuIiwiaW1wb3J0IHsgZmxhdHRlbmVkRGVjcnlwdCB9IGZyb20gJy4uL2ZsYXR0ZW5lZC9kZWNyeXB0LmpzJztcbmltcG9ydCB7IEpXRUludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgeyBkZWNvZGVyIH0gZnJvbSAnLi4vLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gY29tcGFjdERlY3J5cHQoandlLCBrZXksIG9wdGlvbnMpIHtcbiAgICBpZiAoandlIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICBqd2UgPSBkZWNvZGVyLmRlY29kZShqd2UpO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIGp3ZSAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0NvbXBhY3QgSldFIG11c3QgYmUgYSBzdHJpbmcgb3IgVWludDhBcnJheScpO1xuICAgIH1cbiAgICBjb25zdCB7IDA6IHByb3RlY3RlZEhlYWRlciwgMTogZW5jcnlwdGVkS2V5LCAyOiBpdiwgMzogY2lwaGVydGV4dCwgNDogdGFnLCBsZW5ndGgsIH0gPSBqd2Uuc3BsaXQoJy4nKTtcbiAgICBpZiAobGVuZ3RoICE9PSA1KSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdJbnZhbGlkIENvbXBhY3QgSldFJyk7XG4gICAgfVxuICAgIGNvbnN0IGRlY3J5cHRlZCA9IGF3YWl0IGZsYXR0ZW5lZERlY3J5cHQoe1xuICAgICAgICBjaXBoZXJ0ZXh0LFxuICAgICAgICBpdjogaXYgfHwgdW5kZWZpbmVkLFxuICAgICAgICBwcm90ZWN0ZWQ6IHByb3RlY3RlZEhlYWRlcixcbiAgICAgICAgdGFnOiB0YWcgfHwgdW5kZWZpbmVkLFxuICAgICAgICBlbmNyeXB0ZWRfa2V5OiBlbmNyeXB0ZWRLZXkgfHwgdW5kZWZpbmVkLFxuICAgIH0sIGtleSwgb3B0aW9ucyk7XG4gICAgY29uc3QgcmVzdWx0ID0geyBwbGFpbnRleHQ6IGRlY3J5cHRlZC5wbGFpbnRleHQsIHByb3RlY3RlZEhlYWRlcjogZGVjcnlwdGVkLnByb3RlY3RlZEhlYWRlciB9O1xuICAgIGlmICh0eXBlb2Yga2V5ID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgIHJldHVybiB7IC4uLnJlc3VsdCwga2V5OiBkZWNyeXB0ZWQua2V5IH07XG4gICAgfVxuICAgIHJldHVybiByZXN1bHQ7XG59XG4iLCJpbXBvcnQgeyBmbGF0dGVuZWREZWNyeXB0IH0gZnJvbSAnLi4vZmxhdHRlbmVkL2RlY3J5cHQuanMnO1xuaW1wb3J0IHsgSldFRGVjcnlwdGlvbkZhaWxlZCwgSldFSW52YWxpZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCBpc09iamVjdCBmcm9tICcuLi8uLi9saWIvaXNfb2JqZWN0LmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmFsRGVjcnlwdChqd2UsIGtleSwgb3B0aW9ucykge1xuICAgIGlmICghaXNPYmplY3QoandlKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnR2VuZXJhbCBKV0UgbXVzdCBiZSBhbiBvYmplY3QnKTtcbiAgICB9XG4gICAgaWYgKCFBcnJheS5pc0FycmF5KGp3ZS5yZWNpcGllbnRzKSB8fCAhandlLnJlY2lwaWVudHMuZXZlcnkoaXNPYmplY3QpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgUmVjaXBpZW50cyBtaXNzaW5nIG9yIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmICghandlLnJlY2lwaWVudHMubGVuZ3RoKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgUmVjaXBpZW50cyBoYXMgbm8gbWVtYmVycycpO1xuICAgIH1cbiAgICBmb3IgKGNvbnN0IHJlY2lwaWVudCBvZiBqd2UucmVjaXBpZW50cykge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgcmV0dXJuIGF3YWl0IGZsYXR0ZW5lZERlY3J5cHQoe1xuICAgICAgICAgICAgICAgIGFhZDogandlLmFhZCxcbiAgICAgICAgICAgICAgICBjaXBoZXJ0ZXh0OiBqd2UuY2lwaGVydGV4dCxcbiAgICAgICAgICAgICAgICBlbmNyeXB0ZWRfa2V5OiByZWNpcGllbnQuZW5jcnlwdGVkX2tleSxcbiAgICAgICAgICAgICAgICBoZWFkZXI6IHJlY2lwaWVudC5oZWFkZXIsXG4gICAgICAgICAgICAgICAgaXY6IGp3ZS5pdixcbiAgICAgICAgICAgICAgICBwcm90ZWN0ZWQ6IGp3ZS5wcm90ZWN0ZWQsXG4gICAgICAgICAgICAgICAgdGFnOiBqd2UudGFnLFxuICAgICAgICAgICAgICAgIHVucHJvdGVjdGVkOiBqd2UudW5wcm90ZWN0ZWQsXG4gICAgICAgICAgICB9LCBrZXksIG9wdGlvbnMpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIHtcbiAgICAgICAgfVxuICAgIH1cbiAgICB0aHJvdyBuZXcgSldFRGVjcnlwdGlvbkZhaWxlZCgpO1xufVxuIiwiZXhwb3J0IGNvbnN0IHVucHJvdGVjdGVkID0gU3ltYm9sKCk7XG4iLCJpbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IHsgZW5jb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4vYmFzZTY0dXJsLmpzJztcbmltcG9ydCB7IHR5cGVzIH0gZnJvbSAnLi9pc19rZXlfbGlrZS5qcyc7XG5jb25zdCBrZXlUb0pXSyA9IGFzeW5jIChrZXkpID0+IHtcbiAgICBpZiAoa2V5IGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAga3R5OiAnb2N0JyxcbiAgICAgICAgICAgIGs6IGJhc2U2NHVybChrZXkpLFxuICAgICAgICB9O1xuICAgIH1cbiAgICBpZiAoIWlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcywgJ1VpbnQ4QXJyYXknKSk7XG4gICAgfVxuICAgIGlmICgha2V5LmV4dHJhY3RhYmxlKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ25vbi1leHRyYWN0YWJsZSBDcnlwdG9LZXkgY2Fubm90IGJlIGV4cG9ydGVkIGFzIGEgSldLJyk7XG4gICAgfVxuICAgIGNvbnN0IHsgZXh0LCBrZXlfb3BzLCBhbGcsIHVzZSwgLi4uandrIH0gPSBhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgnandrJywga2V5KTtcbiAgICByZXR1cm4gandrO1xufTtcbmV4cG9ydCBkZWZhdWx0IGtleVRvSldLO1xuIiwiaW1wb3J0IHsgdG9TUEtJIGFzIGV4cG9ydFB1YmxpYyB9IGZyb20gJy4uL3J1bnRpbWUvYXNuMS5qcyc7XG5pbXBvcnQgeyB0b1BLQ1M4IGFzIGV4cG9ydFByaXZhdGUgfSBmcm9tICcuLi9ydW50aW1lL2FzbjEuanMnO1xuaW1wb3J0IGtleVRvSldLIGZyb20gJy4uL3J1bnRpbWUva2V5X3RvX2p3ay5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZXhwb3J0U1BLSShrZXkpIHtcbiAgICByZXR1cm4gZXhwb3J0UHVibGljKGtleSk7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZXhwb3J0UEtDUzgoa2V5KSB7XG4gICAgcmV0dXJuIGV4cG9ydFByaXZhdGUoa2V5KTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBleHBvcnRKV0soa2V5KSB7XG4gICAgcmV0dXJuIGtleVRvSldLKGtleSk7XG59XG4iLCJpbXBvcnQgeyB3cmFwIGFzIGFlc0t3IH0gZnJvbSAnLi4vcnVudGltZS9hZXNrdy5qcyc7XG5pbXBvcnQgKiBhcyBFQ0RIIGZyb20gJy4uL3J1bnRpbWUvZWNkaGVzLmpzJztcbmltcG9ydCB7IGVuY3J5cHQgYXMgcGJlczJLdyB9IGZyb20gJy4uL3J1bnRpbWUvcGJlczJrdy5qcyc7XG5pbXBvcnQgeyBlbmNyeXB0IGFzIHJzYUVzIH0gZnJvbSAnLi4vcnVudGltZS9yc2Flcy5qcyc7XG5pbXBvcnQgeyBlbmNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IG5vcm1hbGl6ZSBmcm9tICcuLi9ydW50aW1lL25vcm1hbGl6ZV9rZXkuanMnO1xuaW1wb3J0IGdlbmVyYXRlQ2VrLCB7IGJpdExlbmd0aCBhcyBjZWtMZW5ndGggfSBmcm9tICcuLi9saWIvY2VrLmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgeyBleHBvcnRKV0sgfSBmcm9tICcuLi9rZXkvZXhwb3J0LmpzJztcbmltcG9ydCBjaGVja0tleVR5cGUgZnJvbSAnLi9jaGVja19rZXlfdHlwZS5qcyc7XG5pbXBvcnQgeyB3cmFwIGFzIGFlc0djbUt3IH0gZnJvbSAnLi9hZXNnY21rdy5qcyc7XG5hc3luYyBmdW5jdGlvbiBlbmNyeXB0S2V5TWFuYWdlbWVudChhbGcsIGVuYywga2V5LCBwcm92aWRlZENlaywgcHJvdmlkZWRQYXJhbWV0ZXJzID0ge30pIHtcbiAgICBsZXQgZW5jcnlwdGVkS2V5O1xuICAgIGxldCBwYXJhbWV0ZXJzO1xuICAgIGxldCBjZWs7XG4gICAgY2hlY2tLZXlUeXBlKGFsZywga2V5LCAnZW5jcnlwdCcpO1xuICAgIGtleSA9IChhd2FpdCBub3JtYWxpemUubm9ybWFsaXplUHVibGljS2V5Py4oa2V5LCBhbGcpKSB8fCBrZXk7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnZGlyJzoge1xuICAgICAgICAgICAgY2VrID0ga2V5O1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnRUNESC1FUyc6XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMTkyS1cnOlxuICAgICAgICBjYXNlICdFQ0RILUVTK0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGlmICghRUNESC5lY2RoQWxsb3dlZChrZXkpKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0VDREggd2l0aCB0aGUgcHJvdmlkZWQga2V5IGlzIG5vdCBhbGxvd2VkIG9yIG5vdCBzdXBwb3J0ZWQgYnkgeW91ciBqYXZhc2NyaXB0IHJ1bnRpbWUnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNvbnN0IHsgYXB1LCBhcHYgfSA9IHByb3ZpZGVkUGFyYW1ldGVycztcbiAgICAgICAgICAgIGxldCB7IGVwazogZXBoZW1lcmFsS2V5IH0gPSBwcm92aWRlZFBhcmFtZXRlcnM7XG4gICAgICAgICAgICBlcGhlbWVyYWxLZXkgfHwgKGVwaGVtZXJhbEtleSA9IChhd2FpdCBFQ0RILmdlbmVyYXRlRXBrKGtleSkpLnByaXZhdGVLZXkpO1xuICAgICAgICAgICAgY29uc3QgeyB4LCB5LCBjcnYsIGt0eSB9ID0gYXdhaXQgZXhwb3J0SldLKGVwaGVtZXJhbEtleSk7XG4gICAgICAgICAgICBjb25zdCBzaGFyZWRTZWNyZXQgPSBhd2FpdCBFQ0RILmRlcml2ZUtleShrZXksIGVwaGVtZXJhbEtleSwgYWxnID09PSAnRUNESC1FUycgPyBlbmMgOiBhbGcsIGFsZyA9PT0gJ0VDREgtRVMnID8gY2VrTGVuZ3RoKGVuYykgOiBwYXJzZUludChhbGcuc2xpY2UoLTUsIC0yKSwgMTApLCBhcHUsIGFwdik7XG4gICAgICAgICAgICBwYXJhbWV0ZXJzID0geyBlcGs6IHsgeCwgY3J2LCBrdHkgfSB9O1xuICAgICAgICAgICAgaWYgKGt0eSA9PT0gJ0VDJylcbiAgICAgICAgICAgICAgICBwYXJhbWV0ZXJzLmVway55ID0geTtcbiAgICAgICAgICAgIGlmIChhcHUpXG4gICAgICAgICAgICAgICAgcGFyYW1ldGVycy5hcHUgPSBiYXNlNjR1cmwoYXB1KTtcbiAgICAgICAgICAgIGlmIChhcHYpXG4gICAgICAgICAgICAgICAgcGFyYW1ldGVycy5hcHYgPSBiYXNlNjR1cmwoYXB2KTtcbiAgICAgICAgICAgIGlmIChhbGcgPT09ICdFQ0RILUVTJykge1xuICAgICAgICAgICAgICAgIGNlayA9IHNoYXJlZFNlY3JldDtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNlayA9IHByb3ZpZGVkQ2VrIHx8IGdlbmVyYXRlQ2VrKGVuYyk7XG4gICAgICAgICAgICBjb25zdCBrd0FsZyA9IGFsZy5zbGljZSgtNik7XG4gICAgICAgICAgICBlbmNyeXB0ZWRLZXkgPSBhd2FpdCBhZXNLdyhrd0FsZywgc2hhcmVkU2VjcmV0LCBjZWspO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnUlNBMV81JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0yNTYnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0zODQnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC01MTInOiB7XG4gICAgICAgICAgICBjZWsgPSBwcm92aWRlZENlayB8fCBnZW5lcmF0ZUNlayhlbmMpO1xuICAgICAgICAgICAgZW5jcnlwdGVkS2V5ID0gYXdhaXQgcnNhRXMoYWxnLCBrZXksIGNlayk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdQQkVTMi1IUzI1NitBMTI4S1cnOlxuICAgICAgICBjYXNlICdQQkVTMi1IUzM4NCtBMTkyS1cnOlxuICAgICAgICBjYXNlICdQQkVTMi1IUzUxMitBMjU2S1cnOiB7XG4gICAgICAgICAgICBjZWsgPSBwcm92aWRlZENlayB8fCBnZW5lcmF0ZUNlayhlbmMpO1xuICAgICAgICAgICAgY29uc3QgeyBwMmMsIHAycyB9ID0gcHJvdmlkZWRQYXJhbWV0ZXJzO1xuICAgICAgICAgICAgKHsgZW5jcnlwdGVkS2V5LCAuLi5wYXJhbWV0ZXJzIH0gPSBhd2FpdCBwYmVzMkt3KGFsZywga2V5LCBjZWssIHAyYywgcDJzKSk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdBMTI4S1cnOlxuICAgICAgICBjYXNlICdBMTkyS1cnOlxuICAgICAgICBjYXNlICdBMjU2S1cnOiB7XG4gICAgICAgICAgICBjZWsgPSBwcm92aWRlZENlayB8fCBnZW5lcmF0ZUNlayhlbmMpO1xuICAgICAgICAgICAgZW5jcnlwdGVkS2V5ID0gYXdhaXQgYWVzS3coYWxnLCBrZXksIGNlayk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdBMTI4R0NNS1cnOlxuICAgICAgICBjYXNlICdBMTkyR0NNS1cnOlxuICAgICAgICBjYXNlICdBMjU2R0NNS1cnOiB7XG4gICAgICAgICAgICBjZWsgPSBwcm92aWRlZENlayB8fCBnZW5lcmF0ZUNlayhlbmMpO1xuICAgICAgICAgICAgY29uc3QgeyBpdiB9ID0gcHJvdmlkZWRQYXJhbWV0ZXJzO1xuICAgICAgICAgICAgKHsgZW5jcnlwdGVkS2V5LCAuLi5wYXJhbWV0ZXJzIH0gPSBhd2FpdCBhZXNHY21LdyhhbGcsIGtleSwgY2VrLCBpdikpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgZGVmYXVsdDoge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgXCJhbGdcIiAoSldFIEFsZ29yaXRobSkgaGVhZGVyIHZhbHVlJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHsgY2VrLCBlbmNyeXB0ZWRLZXksIHBhcmFtZXRlcnMgfTtcbn1cbmV4cG9ydCBkZWZhdWx0IGVuY3J5cHRLZXlNYW5hZ2VtZW50O1xuIiwiaW1wb3J0IHsgZW5jb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4uLy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmltcG9ydCB7IHVucHJvdGVjdGVkIH0gZnJvbSAnLi4vLi4vbGliL3ByaXZhdGVfc3ltYm9scy5qcyc7XG5pbXBvcnQgZW5jcnlwdCBmcm9tICcuLi8uLi9ydW50aW1lL2VuY3J5cHQuanMnO1xuaW1wb3J0IGVuY3J5cHRLZXlNYW5hZ2VtZW50IGZyb20gJy4uLy4uL2xpYi9lbmNyeXB0X2tleV9tYW5hZ2VtZW50LmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQsIEpXRUludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgaXNEaXNqb2ludCBmcm9tICcuLi8uLi9saWIvaXNfZGlzam9pbnQuanMnO1xuaW1wb3J0IHsgZW5jb2RlciwgZGVjb2RlciwgY29uY2F0IH0gZnJvbSAnLi4vLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgdmFsaWRhdGVDcml0IGZyb20gJy4uLy4uL2xpYi92YWxpZGF0ZV9jcml0LmpzJztcbmV4cG9ydCBjbGFzcyBGbGF0dGVuZWRFbmNyeXB0IHtcbiAgICBjb25zdHJ1Y3RvcihwbGFpbnRleHQpIHtcbiAgICAgICAgaWYgKCEocGxhaW50ZXh0IGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3BsYWludGV4dCBtdXN0IGJlIGFuIGluc3RhbmNlIG9mIFVpbnQ4QXJyYXknKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9wbGFpbnRleHQgPSBwbGFpbnRleHQ7XG4gICAgfVxuICAgIHNldEtleU1hbmFnZW1lbnRQYXJhbWV0ZXJzKHBhcmFtZXRlcnMpIHtcbiAgICAgICAgaWYgKHRoaXMuX2tleU1hbmFnZW1lbnRQYXJhbWV0ZXJzKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRLZXlNYW5hZ2VtZW50UGFyYW1ldGVycyBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX2tleU1hbmFnZW1lbnRQYXJhbWV0ZXJzID0gcGFyYW1ldGVycztcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldFByb3RlY3RlZEhlYWRlcihwcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMuX3Byb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0UHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fcHJvdGVjdGVkSGVhZGVyID0gcHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0U2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIoc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMuX3NoYXJlZFVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRTaGFyZWRVbnByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3NoYXJlZFVucHJvdGVjdGVkSGVhZGVyID0gc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRVbnByb3RlY3RlZEhlYWRlcih1bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFVucHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIgPSB1bnByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldEFkZGl0aW9uYWxBdXRoZW50aWNhdGVkRGF0YShhYWQpIHtcbiAgICAgICAgdGhpcy5fYWFkID0gYWFkO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0Q29udGVudEVuY3J5cHRpb25LZXkoY2VrKSB7XG4gICAgICAgIGlmICh0aGlzLl9jZWspIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldENvbnRlbnRFbmNyeXB0aW9uS2V5IGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fY2VrID0gY2VrO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0SW5pdGlhbGl6YXRpb25WZWN0b3IoaXYpIHtcbiAgICAgICAgaWYgKHRoaXMuX2l2KSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRJbml0aWFsaXphdGlvblZlY3RvciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX2l2ID0gaXY7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBhc3luYyBlbmNyeXB0KGtleSwgb3B0aW9ucykge1xuICAgICAgICBpZiAoIXRoaXMuX3Byb3RlY3RlZEhlYWRlciAmJiAhdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIgJiYgIXRoaXMuX3NoYXJlZFVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnZWl0aGVyIHNldFByb3RlY3RlZEhlYWRlciwgc2V0VW5wcm90ZWN0ZWRIZWFkZXIsIG9yIHNoYXJlZFVucHJvdGVjdGVkSGVhZGVyIG11c3QgYmUgY2FsbGVkIGJlZm9yZSAjZW5jcnlwdCgpJyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCFpc0Rpc2pvaW50KHRoaXMuX3Byb3RlY3RlZEhlYWRlciwgdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIsIHRoaXMuX3NoYXJlZFVucHJvdGVjdGVkSGVhZGVyKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBQcm90ZWN0ZWQsIEpXRSBTaGFyZWQgVW5wcm90ZWN0ZWQgYW5kIEpXRSBQZXItUmVjaXBpZW50IEhlYWRlciBQYXJhbWV0ZXIgbmFtZXMgbXVzdCBiZSBkaXNqb2ludCcpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IGpvc2VIZWFkZXIgPSB7XG4gICAgICAgICAgICAuLi50aGlzLl9wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICAuLi50aGlzLl91bnByb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgIC4uLnRoaXMuX3NoYXJlZFVucHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICB9O1xuICAgICAgICB2YWxpZGF0ZUNyaXQoSldFSW52YWxpZCwgbmV3IE1hcCgpLCBvcHRpb25zPy5jcml0LCB0aGlzLl9wcm90ZWN0ZWRIZWFkZXIsIGpvc2VIZWFkZXIpO1xuICAgICAgICBpZiAoam9zZUhlYWRlci56aXAgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0pXRSBcInppcFwiIChDb21wcmVzc2lvbiBBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgaXMgbm90IHN1cHBvcnRlZC4nKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCB7IGFsZywgZW5jIH0gPSBqb3NlSGVhZGVyO1xuICAgICAgICBpZiAodHlwZW9mIGFsZyAhPT0gJ3N0cmluZycgfHwgIWFsZykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBcImFsZ1wiIChBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgbWlzc2luZyBvciBpbnZhbGlkJyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHR5cGVvZiBlbmMgIT09ICdzdHJpbmcnIHx8ICFlbmMpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgXCJlbmNcIiAoRW5jcnlwdGlvbiBBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgbWlzc2luZyBvciBpbnZhbGlkJyk7XG4gICAgICAgIH1cbiAgICAgICAgbGV0IGVuY3J5cHRlZEtleTtcbiAgICAgICAgaWYgKHRoaXMuX2NlayAmJiAoYWxnID09PSAnZGlyJyB8fCBhbGcgPT09ICdFQ0RILUVTJykpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYHNldENvbnRlbnRFbmNyeXB0aW9uS2V5IGNhbm5vdCBiZSBjYWxsZWQgd2l0aCBKV0UgXCJhbGdcIiAoQWxnb3JpdGhtKSBIZWFkZXIgJHthbGd9YCk7XG4gICAgICAgIH1cbiAgICAgICAgbGV0IGNlaztcbiAgICAgICAge1xuICAgICAgICAgICAgbGV0IHBhcmFtZXRlcnM7XG4gICAgICAgICAgICAoeyBjZWssIGVuY3J5cHRlZEtleSwgcGFyYW1ldGVycyB9ID0gYXdhaXQgZW5jcnlwdEtleU1hbmFnZW1lbnQoYWxnLCBlbmMsIGtleSwgdGhpcy5fY2VrLCB0aGlzLl9rZXlNYW5hZ2VtZW50UGFyYW1ldGVycykpO1xuICAgICAgICAgICAgaWYgKHBhcmFtZXRlcnMpIHtcbiAgICAgICAgICAgICAgICBpZiAob3B0aW9ucyAmJiB1bnByb3RlY3RlZCBpbiBvcHRpb25zKSB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuc2V0VW5wcm90ZWN0ZWRIZWFkZXIocGFyYW1ldGVycyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl91bnByb3RlY3RlZEhlYWRlciA9IHsgLi4udGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIsIC4uLnBhcmFtZXRlcnMgfTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIGlmICghdGhpcy5fcHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICAgICAgICAgIHRoaXMuc2V0UHJvdGVjdGVkSGVhZGVyKHBhcmFtZXRlcnMpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgdGhpcy5fcHJvdGVjdGVkSGVhZGVyID0geyAuLi50aGlzLl9wcm90ZWN0ZWRIZWFkZXIsIC4uLnBhcmFtZXRlcnMgfTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgbGV0IGFkZGl0aW9uYWxEYXRhO1xuICAgICAgICBsZXQgcHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICBsZXQgYWFkTWVtYmVyO1xuICAgICAgICBpZiAodGhpcy5fcHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICBwcm90ZWN0ZWRIZWFkZXIgPSBlbmNvZGVyLmVuY29kZShiYXNlNjR1cmwoSlNPTi5zdHJpbmdpZnkodGhpcy5fcHJvdGVjdGVkSGVhZGVyKSkpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgcHJvdGVjdGVkSGVhZGVyID0gZW5jb2Rlci5lbmNvZGUoJycpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl9hYWQpIHtcbiAgICAgICAgICAgIGFhZE1lbWJlciA9IGJhc2U2NHVybCh0aGlzLl9hYWQpO1xuICAgICAgICAgICAgYWRkaXRpb25hbERhdGEgPSBjb25jYXQocHJvdGVjdGVkSGVhZGVyLCBlbmNvZGVyLmVuY29kZSgnLicpLCBlbmNvZGVyLmVuY29kZShhYWRNZW1iZXIpKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIGFkZGl0aW9uYWxEYXRhID0gcHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHsgY2lwaGVydGV4dCwgdGFnLCBpdiB9ID0gYXdhaXQgZW5jcnlwdChlbmMsIHRoaXMuX3BsYWludGV4dCwgY2VrLCB0aGlzLl9pdiwgYWRkaXRpb25hbERhdGEpO1xuICAgICAgICBjb25zdCBqd2UgPSB7XG4gICAgICAgICAgICBjaXBoZXJ0ZXh0OiBiYXNlNjR1cmwoY2lwaGVydGV4dCksXG4gICAgICAgIH07XG4gICAgICAgIGlmIChpdikge1xuICAgICAgICAgICAgandlLml2ID0gYmFzZTY0dXJsKGl2KTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGFnKSB7XG4gICAgICAgICAgICBqd2UudGFnID0gYmFzZTY0dXJsKHRhZyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGVuY3J5cHRlZEtleSkge1xuICAgICAgICAgICAgandlLmVuY3J5cHRlZF9rZXkgPSBiYXNlNjR1cmwoZW5jcnlwdGVkS2V5KTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoYWFkTWVtYmVyKSB7XG4gICAgICAgICAgICBqd2UuYWFkID0gYWFkTWVtYmVyO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIGp3ZS5wcm90ZWN0ZWQgPSBkZWNvZGVyLmRlY29kZShwcm90ZWN0ZWRIZWFkZXIpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl9zaGFyZWRVbnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgandlLnVucHJvdGVjdGVkID0gdGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICBqd2UuaGVhZGVyID0gdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGp3ZTtcbiAgICB9XG59XG4iLCJpbXBvcnQgeyBGbGF0dGVuZWRFbmNyeXB0IH0gZnJvbSAnLi4vZmxhdHRlbmVkL2VuY3J5cHQuanMnO1xuaW1wb3J0IHsgdW5wcm90ZWN0ZWQgfSBmcm9tICcuLi8uLi9saWIvcHJpdmF0ZV9zeW1ib2xzLmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQsIEpXRUludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgZ2VuZXJhdGVDZWsgZnJvbSAnLi4vLi4vbGliL2Nlay5qcyc7XG5pbXBvcnQgaXNEaXNqb2ludCBmcm9tICcuLi8uLi9saWIvaXNfZGlzam9pbnQuanMnO1xuaW1wb3J0IGVuY3J5cHRLZXlNYW5hZ2VtZW50IGZyb20gJy4uLy4uL2xpYi9lbmNyeXB0X2tleV9tYW5hZ2VtZW50LmpzJztcbmltcG9ydCB7IGVuY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi8uLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgdmFsaWRhdGVDcml0IGZyb20gJy4uLy4uL2xpYi92YWxpZGF0ZV9jcml0LmpzJztcbmNsYXNzIEluZGl2aWR1YWxSZWNpcGllbnQge1xuICAgIGNvbnN0cnVjdG9yKGVuYywga2V5LCBvcHRpb25zKSB7XG4gICAgICAgIHRoaXMucGFyZW50ID0gZW5jO1xuICAgICAgICB0aGlzLmtleSA9IGtleTtcbiAgICAgICAgdGhpcy5vcHRpb25zID0gb3B0aW9ucztcbiAgICB9XG4gICAgc2V0VW5wcm90ZWN0ZWRIZWFkZXIodW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMudW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFVucHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy51bnByb3RlY3RlZEhlYWRlciA9IHVucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgYWRkUmVjaXBpZW50KC4uLmFyZ3MpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGFyZW50LmFkZFJlY2lwaWVudCguLi5hcmdzKTtcbiAgICB9XG4gICAgZW5jcnlwdCguLi5hcmdzKSB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhcmVudC5lbmNyeXB0KC4uLmFyZ3MpO1xuICAgIH1cbiAgICBkb25lKCkge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXJlbnQ7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEdlbmVyYWxFbmNyeXB0IHtcbiAgICBjb25zdHJ1Y3RvcihwbGFpbnRleHQpIHtcbiAgICAgICAgdGhpcy5fcmVjaXBpZW50cyA9IFtdO1xuICAgICAgICB0aGlzLl9wbGFpbnRleHQgPSBwbGFpbnRleHQ7XG4gICAgfVxuICAgIGFkZFJlY2lwaWVudChrZXksIG9wdGlvbnMpIHtcbiAgICAgICAgY29uc3QgcmVjaXBpZW50ID0gbmV3IEluZGl2aWR1YWxSZWNpcGllbnQodGhpcywga2V5LCB7IGNyaXQ6IG9wdGlvbnM/LmNyaXQgfSk7XG4gICAgICAgIHRoaXMuX3JlY2lwaWVudHMucHVzaChyZWNpcGllbnQpO1xuICAgICAgICByZXR1cm4gcmVjaXBpZW50O1xuICAgIH1cbiAgICBzZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3Byb3RlY3RlZEhlYWRlciA9IHByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldFNoYXJlZFVucHJvdGVjdGVkSGVhZGVyKHNoYXJlZFVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLl91bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0U2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl91bnByb3RlY3RlZEhlYWRlciA9IHNoYXJlZFVucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0QWRkaXRpb25hbEF1dGhlbnRpY2F0ZWREYXRhKGFhZCkge1xuICAgICAgICB0aGlzLl9hYWQgPSBhYWQ7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBhc3luYyBlbmNyeXB0KCkge1xuICAgICAgICBpZiAoIXRoaXMuX3JlY2lwaWVudHMubGVuZ3RoKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnYXQgbGVhc3Qgb25lIHJlY2lwaWVudCBtdXN0IGJlIGFkZGVkJyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX3JlY2lwaWVudHMubGVuZ3RoID09PSAxKSB7XG4gICAgICAgICAgICBjb25zdCBbcmVjaXBpZW50XSA9IHRoaXMuX3JlY2lwaWVudHM7XG4gICAgICAgICAgICBjb25zdCBmbGF0dGVuZWQgPSBhd2FpdCBuZXcgRmxhdHRlbmVkRW5jcnlwdCh0aGlzLl9wbGFpbnRleHQpXG4gICAgICAgICAgICAgICAgLnNldEFkZGl0aW9uYWxBdXRoZW50aWNhdGVkRGF0YSh0aGlzLl9hYWQpXG4gICAgICAgICAgICAgICAgLnNldFByb3RlY3RlZEhlYWRlcih0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpXG4gICAgICAgICAgICAgICAgLnNldFNoYXJlZFVucHJvdGVjdGVkSGVhZGVyKHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKVxuICAgICAgICAgICAgICAgIC5zZXRVbnByb3RlY3RlZEhlYWRlcihyZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXIpXG4gICAgICAgICAgICAgICAgLmVuY3J5cHQocmVjaXBpZW50LmtleSwgeyAuLi5yZWNpcGllbnQub3B0aW9ucyB9KTtcbiAgICAgICAgICAgIGNvbnN0IGp3ZSA9IHtcbiAgICAgICAgICAgICAgICBjaXBoZXJ0ZXh0OiBmbGF0dGVuZWQuY2lwaGVydGV4dCxcbiAgICAgICAgICAgICAgICBpdjogZmxhdHRlbmVkLml2LFxuICAgICAgICAgICAgICAgIHJlY2lwaWVudHM6IFt7fV0sXG4gICAgICAgICAgICAgICAgdGFnOiBmbGF0dGVuZWQudGFnLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIGlmIChmbGF0dGVuZWQuYWFkKVxuICAgICAgICAgICAgICAgIGp3ZS5hYWQgPSBmbGF0dGVuZWQuYWFkO1xuICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC5wcm90ZWN0ZWQpXG4gICAgICAgICAgICAgICAgandlLnByb3RlY3RlZCA9IGZsYXR0ZW5lZC5wcm90ZWN0ZWQ7XG4gICAgICAgICAgICBpZiAoZmxhdHRlbmVkLnVucHJvdGVjdGVkKVxuICAgICAgICAgICAgICAgIGp3ZS51bnByb3RlY3RlZCA9IGZsYXR0ZW5lZC51bnByb3RlY3RlZDtcbiAgICAgICAgICAgIGlmIChmbGF0dGVuZWQuZW5jcnlwdGVkX2tleSlcbiAgICAgICAgICAgICAgICBqd2UucmVjaXBpZW50c1swXS5lbmNyeXB0ZWRfa2V5ID0gZmxhdHRlbmVkLmVuY3J5cHRlZF9rZXk7XG4gICAgICAgICAgICBpZiAoZmxhdHRlbmVkLmhlYWRlcilcbiAgICAgICAgICAgICAgICBqd2UucmVjaXBpZW50c1swXS5oZWFkZXIgPSBmbGF0dGVuZWQuaGVhZGVyO1xuICAgICAgICAgICAgcmV0dXJuIGp3ZTtcbiAgICAgICAgfVxuICAgICAgICBsZXQgZW5jO1xuICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHRoaXMuX3JlY2lwaWVudHMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIGNvbnN0IHJlY2lwaWVudCA9IHRoaXMuX3JlY2lwaWVudHNbaV07XG4gICAgICAgICAgICBpZiAoIWlzRGlzam9pbnQodGhpcy5fcHJvdGVjdGVkSGVhZGVyLCB0aGlzLl91bnByb3RlY3RlZEhlYWRlciwgcmVjaXBpZW50LnVucHJvdGVjdGVkSGVhZGVyKSkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgUHJvdGVjdGVkLCBKV0UgU2hhcmVkIFVucHJvdGVjdGVkIGFuZCBKV0UgUGVyLVJlY2lwaWVudCBIZWFkZXIgUGFyYW1ldGVyIG5hbWVzIG11c3QgYmUgZGlzam9pbnQnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNvbnN0IGpvc2VIZWFkZXIgPSB7XG4gICAgICAgICAgICAgICAgLi4udGhpcy5fcHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgICAgIC4uLnRoaXMuX3VucHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgICAgIC4uLnJlY2lwaWVudC51bnByb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgIH07XG4gICAgICAgICAgICBjb25zdCB7IGFsZyB9ID0gam9zZUhlYWRlcjtcbiAgICAgICAgICAgIGlmICh0eXBlb2YgYWxnICE9PSAnc3RyaW5nJyB8fCAhYWxnKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBcImFsZ1wiIChBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgbWlzc2luZyBvciBpbnZhbGlkJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAoYWxnID09PSAnZGlyJyB8fCBhbGcgPT09ICdFQ0RILUVTJykge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdcImRpclwiIGFuZCBcIkVDREgtRVNcIiBhbGcgbWF5IG9ubHkgYmUgdXNlZCB3aXRoIGEgc2luZ2xlIHJlY2lwaWVudCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKHR5cGVvZiBqb3NlSGVhZGVyLmVuYyAhPT0gJ3N0cmluZycgfHwgIWpvc2VIZWFkZXIuZW5jKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBcImVuY1wiIChFbmNyeXB0aW9uIEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBtaXNzaW5nIG9yIGludmFsaWQnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmICghZW5jKSB7XG4gICAgICAgICAgICAgICAgZW5jID0gam9zZUhlYWRlci5lbmM7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIGlmIChlbmMgIT09IGpvc2VIZWFkZXIuZW5jKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBcImVuY1wiIChFbmNyeXB0aW9uIEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBtdXN0IGJlIHRoZSBzYW1lIGZvciBhbGwgcmVjaXBpZW50cycpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgdmFsaWRhdGVDcml0KEpXRUludmFsaWQsIG5ldyBNYXAoKSwgcmVjaXBpZW50Lm9wdGlvbnMuY3JpdCwgdGhpcy5fcHJvdGVjdGVkSGVhZGVyLCBqb3NlSGVhZGVyKTtcbiAgICAgICAgICAgIGlmIChqb3NlSGVhZGVyLnppcCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0pXRSBcInppcFwiIChDb21wcmVzc2lvbiBBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgaXMgbm90IHN1cHBvcnRlZC4nKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBjb25zdCBjZWsgPSBnZW5lcmF0ZUNlayhlbmMpO1xuICAgICAgICBjb25zdCBqd2UgPSB7XG4gICAgICAgICAgICBjaXBoZXJ0ZXh0OiAnJyxcbiAgICAgICAgICAgIGl2OiAnJyxcbiAgICAgICAgICAgIHJlY2lwaWVudHM6IFtdLFxuICAgICAgICAgICAgdGFnOiAnJyxcbiAgICAgICAgfTtcbiAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCB0aGlzLl9yZWNpcGllbnRzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBjb25zdCByZWNpcGllbnQgPSB0aGlzLl9yZWNpcGllbnRzW2ldO1xuICAgICAgICAgICAgY29uc3QgdGFyZ2V0ID0ge307XG4gICAgICAgICAgICBqd2UucmVjaXBpZW50cy5wdXNoKHRhcmdldCk7XG4gICAgICAgICAgICBjb25zdCBqb3NlSGVhZGVyID0ge1xuICAgICAgICAgICAgICAgIC4uLnRoaXMuX3Byb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgICAgICAuLi50aGlzLl91bnByb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgICAgICAuLi5yZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAgY29uc3QgcDJjID0gam9zZUhlYWRlci5hbGcuc3RhcnRzV2l0aCgnUEJFUzInKSA/IDIwNDggKyBpIDogdW5kZWZpbmVkO1xuICAgICAgICAgICAgaWYgKGkgPT09IDApIHtcbiAgICAgICAgICAgICAgICBjb25zdCBmbGF0dGVuZWQgPSBhd2FpdCBuZXcgRmxhdHRlbmVkRW5jcnlwdCh0aGlzLl9wbGFpbnRleHQpXG4gICAgICAgICAgICAgICAgICAgIC5zZXRBZGRpdGlvbmFsQXV0aGVudGljYXRlZERhdGEodGhpcy5fYWFkKVxuICAgICAgICAgICAgICAgICAgICAuc2V0Q29udGVudEVuY3J5cHRpb25LZXkoY2VrKVxuICAgICAgICAgICAgICAgICAgICAuc2V0UHJvdGVjdGVkSGVhZGVyKHRoaXMuX3Byb3RlY3RlZEhlYWRlcilcbiAgICAgICAgICAgICAgICAgICAgLnNldFNoYXJlZFVucHJvdGVjdGVkSGVhZGVyKHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKVxuICAgICAgICAgICAgICAgICAgICAuc2V0VW5wcm90ZWN0ZWRIZWFkZXIocmVjaXBpZW50LnVucHJvdGVjdGVkSGVhZGVyKVxuICAgICAgICAgICAgICAgICAgICAuc2V0S2V5TWFuYWdlbWVudFBhcmFtZXRlcnMoeyBwMmMgfSlcbiAgICAgICAgICAgICAgICAgICAgLmVuY3J5cHQocmVjaXBpZW50LmtleSwge1xuICAgICAgICAgICAgICAgICAgICAuLi5yZWNpcGllbnQub3B0aW9ucyxcbiAgICAgICAgICAgICAgICAgICAgW3VucHJvdGVjdGVkXTogdHJ1ZSxcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICBqd2UuY2lwaGVydGV4dCA9IGZsYXR0ZW5lZC5jaXBoZXJ0ZXh0O1xuICAgICAgICAgICAgICAgIGp3ZS5pdiA9IGZsYXR0ZW5lZC5pdjtcbiAgICAgICAgICAgICAgICBqd2UudGFnID0gZmxhdHRlbmVkLnRhZztcbiAgICAgICAgICAgICAgICBpZiAoZmxhdHRlbmVkLmFhZClcbiAgICAgICAgICAgICAgICAgICAgandlLmFhZCA9IGZsYXR0ZW5lZC5hYWQ7XG4gICAgICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC5wcm90ZWN0ZWQpXG4gICAgICAgICAgICAgICAgICAgIGp3ZS5wcm90ZWN0ZWQgPSBmbGF0dGVuZWQucHJvdGVjdGVkO1xuICAgICAgICAgICAgICAgIGlmIChmbGF0dGVuZWQudW5wcm90ZWN0ZWQpXG4gICAgICAgICAgICAgICAgICAgIGp3ZS51bnByb3RlY3RlZCA9IGZsYXR0ZW5lZC51bnByb3RlY3RlZDtcbiAgICAgICAgICAgICAgICB0YXJnZXQuZW5jcnlwdGVkX2tleSA9IGZsYXR0ZW5lZC5lbmNyeXB0ZWRfa2V5O1xuICAgICAgICAgICAgICAgIGlmIChmbGF0dGVuZWQuaGVhZGVyKVxuICAgICAgICAgICAgICAgICAgICB0YXJnZXQuaGVhZGVyID0gZmxhdHRlbmVkLmhlYWRlcjtcbiAgICAgICAgICAgICAgICBjb250aW51ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNvbnN0IHsgZW5jcnlwdGVkS2V5LCBwYXJhbWV0ZXJzIH0gPSBhd2FpdCBlbmNyeXB0S2V5TWFuYWdlbWVudChyZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXI/LmFsZyB8fFxuICAgICAgICAgICAgICAgIHRoaXMuX3Byb3RlY3RlZEhlYWRlcj8uYWxnIHx8XG4gICAgICAgICAgICAgICAgdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXI/LmFsZywgZW5jLCByZWNpcGllbnQua2V5LCBjZWssIHsgcDJjIH0pO1xuICAgICAgICAgICAgdGFyZ2V0LmVuY3J5cHRlZF9rZXkgPSBiYXNlNjR1cmwoZW5jcnlwdGVkS2V5KTtcbiAgICAgICAgICAgIGlmIChyZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXIgfHwgcGFyYW1ldGVycylcbiAgICAgICAgICAgICAgICB0YXJnZXQuaGVhZGVyID0geyAuLi5yZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXIsIC4uLnBhcmFtZXRlcnMgfTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gandlO1xuICAgIH1cbn1cbiIsImltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBzdWJ0bGVEc2EoYWxnLCBhbGdvcml0aG0pIHtcbiAgICBjb25zdCBoYXNoID0gYFNIQS0ke2FsZy5zbGljZSgtMyl9YDtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdIUzI1Nic6XG4gICAgICAgIGNhc2UgJ0hTMzg0JzpcbiAgICAgICAgY2FzZSAnSFM1MTInOlxuICAgICAgICAgICAgcmV0dXJuIHsgaGFzaCwgbmFtZTogJ0hNQUMnIH07XG4gICAgICAgIGNhc2UgJ1BTMjU2JzpcbiAgICAgICAgY2FzZSAnUFMzODQnOlxuICAgICAgICBjYXNlICdQUzUxMic6XG4gICAgICAgICAgICByZXR1cm4geyBoYXNoLCBuYW1lOiAnUlNBLVBTUycsIHNhbHRMZW5ndGg6IGFsZy5zbGljZSgtMykgPj4gMyB9O1xuICAgICAgICBjYXNlICdSUzI1Nic6XG4gICAgICAgIGNhc2UgJ1JTMzg0JzpcbiAgICAgICAgY2FzZSAnUlM1MTInOlxuICAgICAgICAgICAgcmV0dXJuIHsgaGFzaCwgbmFtZTogJ1JTQVNTQS1QS0NTMS12MV81JyB9O1xuICAgICAgICBjYXNlICdFUzI1Nic6XG4gICAgICAgIGNhc2UgJ0VTMzg0JzpcbiAgICAgICAgY2FzZSAnRVM1MTInOlxuICAgICAgICAgICAgcmV0dXJuIHsgaGFzaCwgbmFtZTogJ0VDRFNBJywgbmFtZWRDdXJ2ZTogYWxnb3JpdGhtLm5hbWVkQ3VydmUgfTtcbiAgICAgICAgY2FzZSAnRWREU0EnOlxuICAgICAgICAgICAgcmV0dXJuIHsgbmFtZTogYWxnb3JpdGhtLm5hbWUgfTtcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKGBhbGcgJHthbGd9IGlzIG5vdCBzdXBwb3J0ZWQgZWl0aGVyIGJ5IEpPU0Ugb3IgeW91ciBqYXZhc2NyaXB0IHJ1bnRpbWVgKTtcbiAgICB9XG59XG4iLCJpbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tTaWdDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuaW1wb3J0IG5vcm1hbGl6ZSBmcm9tICcuL25vcm1hbGl6ZV9rZXkuanMnO1xuZXhwb3J0IGRlZmF1bHQgYXN5bmMgZnVuY3Rpb24gZ2V0Q3J5cHRvS2V5KGFsZywga2V5LCB1c2FnZSkge1xuICAgIGlmICh1c2FnZSA9PT0gJ3NpZ24nKSB7XG4gICAgICAgIGtleSA9IGF3YWl0IG5vcm1hbGl6ZS5ub3JtYWxpemVQcml2YXRlS2V5KGtleSwgYWxnKTtcbiAgICB9XG4gICAgaWYgKHVzYWdlID09PSAndmVyaWZ5Jykge1xuICAgICAgICBrZXkgPSBhd2FpdCBub3JtYWxpemUubm9ybWFsaXplUHVibGljS2V5KGtleSwgYWxnKTtcbiAgICB9XG4gICAgaWYgKGlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgY2hlY2tTaWdDcnlwdG9LZXkoa2V5LCBhbGcsIHVzYWdlKTtcbiAgICAgICAgcmV0dXJuIGtleTtcbiAgICB9XG4gICAgaWYgKGtleSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgaWYgKCFhbGcuc3RhcnRzV2l0aCgnSFMnKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcykpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3Jywga2V5LCB7IGhhc2g6IGBTSEEtJHthbGcuc2xpY2UoLTMpfWAsIG5hbWU6ICdITUFDJyB9LCBmYWxzZSwgW3VzYWdlXSk7XG4gICAgfVxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMsICdVaW50OEFycmF5JywgJ0pTT04gV2ViIEtleScpKTtcbn1cbiIsImltcG9ydCBzdWJ0bGVBbGdvcml0aG0gZnJvbSAnLi9zdWJ0bGVfZHNhLmpzJztcbmltcG9ydCBjcnlwdG8gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IGNoZWNrS2V5TGVuZ3RoIGZyb20gJy4vY2hlY2tfa2V5X2xlbmd0aC5qcyc7XG5pbXBvcnQgZ2V0VmVyaWZ5S2V5IGZyb20gJy4vZ2V0X3NpZ25fdmVyaWZ5X2tleS5qcyc7XG5jb25zdCB2ZXJpZnkgPSBhc3luYyAoYWxnLCBrZXksIHNpZ25hdHVyZSwgZGF0YSkgPT4ge1xuICAgIGNvbnN0IGNyeXB0b0tleSA9IGF3YWl0IGdldFZlcmlmeUtleShhbGcsIGtleSwgJ3ZlcmlmeScpO1xuICAgIGNoZWNrS2V5TGVuZ3RoKGFsZywgY3J5cHRvS2V5KTtcbiAgICBjb25zdCBhbGdvcml0aG0gPSBzdWJ0bGVBbGdvcml0aG0oYWxnLCBjcnlwdG9LZXkuYWxnb3JpdGhtKTtcbiAgICB0cnkge1xuICAgICAgICByZXR1cm4gYXdhaXQgY3J5cHRvLnN1YnRsZS52ZXJpZnkoYWxnb3JpdGhtLCBjcnlwdG9LZXksIHNpZ25hdHVyZSwgZGF0YSk7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbn07XG5leHBvcnQgZGVmYXVsdCB2ZXJpZnk7XG4iLCJpbXBvcnQgeyBkZWNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi4vLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHZlcmlmeSBmcm9tICcuLi8uLi9ydW50aW1lL3ZlcmlmeS5qcyc7XG5pbXBvcnQgeyBKT1NFQWxnTm90QWxsb3dlZCwgSldTSW52YWxpZCwgSldTU2lnbmF0dXJlVmVyaWZpY2F0aW9uRmFpbGVkIH0gZnJvbSAnLi4vLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHsgY29uY2F0LCBlbmNvZGVyLCBkZWNvZGVyIH0gZnJvbSAnLi4vLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgaXNEaXNqb2ludCBmcm9tICcuLi8uLi9saWIvaXNfZGlzam9pbnQuanMnO1xuaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4uLy4uL2xpYi9pc19vYmplY3QuanMnO1xuaW1wb3J0IHsgY2hlY2tLZXlUeXBlV2l0aEp3ayB9IGZyb20gJy4uLy4uL2xpYi9jaGVja19rZXlfdHlwZS5qcyc7XG5pbXBvcnQgdmFsaWRhdGVDcml0IGZyb20gJy4uLy4uL2xpYi92YWxpZGF0ZV9jcml0LmpzJztcbmltcG9ydCB2YWxpZGF0ZUFsZ29yaXRobXMgZnJvbSAnLi4vLi4vbGliL3ZhbGlkYXRlX2FsZ29yaXRobXMuanMnO1xuaW1wb3J0IHsgaXNKV0sgfSBmcm9tICcuLi8uLi9saWIvaXNfandrLmpzJztcbmltcG9ydCB7IGltcG9ydEpXSyB9IGZyb20gJy4uLy4uL2tleS9pbXBvcnQuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGZsYXR0ZW5lZFZlcmlmeShqd3MsIGtleSwgb3B0aW9ucykge1xuICAgIGlmICghaXNPYmplY3QoandzKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnRmxhdHRlbmVkIEpXUyBtdXN0IGJlIGFuIG9iamVjdCcpO1xuICAgIH1cbiAgICBpZiAoandzLnByb3RlY3RlZCA9PT0gdW5kZWZpbmVkICYmIGp3cy5oZWFkZXIgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnRmxhdHRlbmVkIEpXUyBtdXN0IGhhdmUgZWl0aGVyIG9mIHRoZSBcInByb3RlY3RlZFwiIG9yIFwiaGVhZGVyXCIgbWVtYmVycycpO1xuICAgIH1cbiAgICBpZiAoandzLnByb3RlY3RlZCAhPT0gdW5kZWZpbmVkICYmIHR5cGVvZiBqd3MucHJvdGVjdGVkICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFByb3RlY3RlZCBIZWFkZXIgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3cy5wYXlsb2FkID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBQYXlsb2FkIG1pc3NpbmcnKTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBqd3Muc2lnbmF0dXJlICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFNpZ25hdHVyZSBtaXNzaW5nIG9yIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmIChqd3MuaGVhZGVyICE9PSB1bmRlZmluZWQgJiYgIWlzT2JqZWN0KGp3cy5oZWFkZXIpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgVW5wcm90ZWN0ZWQgSGVhZGVyIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGxldCBwYXJzZWRQcm90ID0ge307XG4gICAgaWYgKGp3cy5wcm90ZWN0ZWQpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIGNvbnN0IHByb3RlY3RlZEhlYWRlciA9IGJhc2U2NHVybChqd3MucHJvdGVjdGVkKTtcbiAgICAgICAgICAgIHBhcnNlZFByb3QgPSBKU09OLnBhcnNlKGRlY29kZXIuZGVjb2RlKHByb3RlY3RlZEhlYWRlcikpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgUHJvdGVjdGVkIEhlYWRlciBpcyBpbnZhbGlkJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgaWYgKCFpc0Rpc2pvaW50KHBhcnNlZFByb3QsIGp3cy5oZWFkZXIpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgUHJvdGVjdGVkIGFuZCBKV1MgVW5wcm90ZWN0ZWQgSGVhZGVyIFBhcmFtZXRlciBuYW1lcyBtdXN0IGJlIGRpc2pvaW50Jyk7XG4gICAgfVxuICAgIGNvbnN0IGpvc2VIZWFkZXIgPSB7XG4gICAgICAgIC4uLnBhcnNlZFByb3QsXG4gICAgICAgIC4uLmp3cy5oZWFkZXIsXG4gICAgfTtcbiAgICBjb25zdCBleHRlbnNpb25zID0gdmFsaWRhdGVDcml0KEpXU0ludmFsaWQsIG5ldyBNYXAoW1snYjY0JywgdHJ1ZV1dKSwgb3B0aW9ucz8uY3JpdCwgcGFyc2VkUHJvdCwgam9zZUhlYWRlcik7XG4gICAgbGV0IGI2NCA9IHRydWU7XG4gICAgaWYgKGV4dGVuc2lvbnMuaGFzKCdiNjQnKSkge1xuICAgICAgICBiNjQgPSBwYXJzZWRQcm90LmI2NDtcbiAgICAgICAgaWYgKHR5cGVvZiBiNjQgIT09ICdib29sZWFuJykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ1RoZSBcImI2NFwiIChiYXNlNjR1cmwtZW5jb2RlIHBheWxvYWQpIEhlYWRlciBQYXJhbWV0ZXIgbXVzdCBiZSBhIGJvb2xlYW4nKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBjb25zdCB7IGFsZyB9ID0gam9zZUhlYWRlcjtcbiAgICBpZiAodHlwZW9mIGFsZyAhPT0gJ3N0cmluZycgfHwgIWFsZykge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFwiYWxnXCIgKEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBtaXNzaW5nIG9yIGludmFsaWQnKTtcbiAgICB9XG4gICAgY29uc3QgYWxnb3JpdGhtcyA9IG9wdGlvbnMgJiYgdmFsaWRhdGVBbGdvcml0aG1zKCdhbGdvcml0aG1zJywgb3B0aW9ucy5hbGdvcml0aG1zKTtcbiAgICBpZiAoYWxnb3JpdGhtcyAmJiAhYWxnb3JpdGhtcy5oYXMoYWxnKSkge1xuICAgICAgICB0aHJvdyBuZXcgSk9TRUFsZ05vdEFsbG93ZWQoJ1wiYWxnXCIgKEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciB2YWx1ZSBub3QgYWxsb3dlZCcpO1xuICAgIH1cbiAgICBpZiAoYjY0KSB7XG4gICAgICAgIGlmICh0eXBlb2YgandzLnBheWxvYWQgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFBheWxvYWQgbXVzdCBiZSBhIHN0cmluZycpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGVsc2UgaWYgKHR5cGVvZiBqd3MucGF5bG9hZCAhPT0gJ3N0cmluZycgJiYgIShqd3MucGF5bG9hZCBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgUGF5bG9hZCBtdXN0IGJlIGEgc3RyaW5nIG9yIGFuIFVpbnQ4QXJyYXkgaW5zdGFuY2UnKTtcbiAgICB9XG4gICAgbGV0IHJlc29sdmVkS2V5ID0gZmFsc2U7XG4gICAgaWYgKHR5cGVvZiBrZXkgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAga2V5ID0gYXdhaXQga2V5KHBhcnNlZFByb3QsIGp3cyk7XG4gICAgICAgIHJlc29sdmVkS2V5ID0gdHJ1ZTtcbiAgICAgICAgY2hlY2tLZXlUeXBlV2l0aEp3ayhhbGcsIGtleSwgJ3ZlcmlmeScpO1xuICAgICAgICBpZiAoaXNKV0soa2V5KSkge1xuICAgICAgICAgICAga2V5ID0gYXdhaXQgaW1wb3J0SldLKGtleSwgYWxnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgY2hlY2tLZXlUeXBlV2l0aEp3ayhhbGcsIGtleSwgJ3ZlcmlmeScpO1xuICAgIH1cbiAgICBjb25zdCBkYXRhID0gY29uY2F0KGVuY29kZXIuZW5jb2RlKGp3cy5wcm90ZWN0ZWQgPz8gJycpLCBlbmNvZGVyLmVuY29kZSgnLicpLCB0eXBlb2YgandzLnBheWxvYWQgPT09ICdzdHJpbmcnID8gZW5jb2Rlci5lbmNvZGUoandzLnBheWxvYWQpIDogandzLnBheWxvYWQpO1xuICAgIGxldCBzaWduYXR1cmU7XG4gICAgdHJ5IHtcbiAgICAgICAgc2lnbmF0dXJlID0gYmFzZTY0dXJsKGp3cy5zaWduYXR1cmUpO1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgc2lnbmF0dXJlJyk7XG4gICAgfVxuICAgIGNvbnN0IHZlcmlmaWVkID0gYXdhaXQgdmVyaWZ5KGFsZywga2V5LCBzaWduYXR1cmUsIGRhdGEpO1xuICAgIGlmICghdmVyaWZpZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU1NpZ25hdHVyZVZlcmlmaWNhdGlvbkZhaWxlZCgpO1xuICAgIH1cbiAgICBsZXQgcGF5bG9hZDtcbiAgICBpZiAoYjY0KSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBwYXlsb2FkID0gYmFzZTY0dXJsKGp3cy5wYXlsb2FkKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIHBheWxvYWQnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBlbHNlIGlmICh0eXBlb2YgandzLnBheWxvYWQgPT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHBheWxvYWQgPSBlbmNvZGVyLmVuY29kZShqd3MucGF5bG9hZCk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBwYXlsb2FkID0gandzLnBheWxvYWQ7XG4gICAgfVxuICAgIGNvbnN0IHJlc3VsdCA9IHsgcGF5bG9hZCB9O1xuICAgIGlmIChqd3MucHJvdGVjdGVkICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmVzdWx0LnByb3RlY3RlZEhlYWRlciA9IHBhcnNlZFByb3Q7XG4gICAgfVxuICAgIGlmIChqd3MuaGVhZGVyICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmVzdWx0LnVucHJvdGVjdGVkSGVhZGVyID0gandzLmhlYWRlcjtcbiAgICB9XG4gICAgaWYgKHJlc29sdmVkS2V5KSB7XG4gICAgICAgIHJldHVybiB7IC4uLnJlc3VsdCwga2V5IH07XG4gICAgfVxuICAgIHJldHVybiByZXN1bHQ7XG59XG4iLCJpbXBvcnQgeyBmbGF0dGVuZWRWZXJpZnkgfSBmcm9tICcuLi9mbGF0dGVuZWQvdmVyaWZ5LmpzJztcbmltcG9ydCB7IEpXU0ludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgeyBkZWNvZGVyIH0gZnJvbSAnLi4vLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gY29tcGFjdFZlcmlmeShqd3MsIGtleSwgb3B0aW9ucykge1xuICAgIGlmIChqd3MgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIGp3cyA9IGRlY29kZXIuZGVjb2RlKGp3cyk7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgandzICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnQ29tcGFjdCBKV1MgbXVzdCBiZSBhIHN0cmluZyBvciBVaW50OEFycmF5Jyk7XG4gICAgfVxuICAgIGNvbnN0IHsgMDogcHJvdGVjdGVkSGVhZGVyLCAxOiBwYXlsb2FkLCAyOiBzaWduYXR1cmUsIGxlbmd0aCB9ID0gandzLnNwbGl0KCcuJyk7XG4gICAgaWYgKGxlbmd0aCAhPT0gMykge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSW52YWxpZCBDb21wYWN0IEpXUycpO1xuICAgIH1cbiAgICBjb25zdCB2ZXJpZmllZCA9IGF3YWl0IGZsYXR0ZW5lZFZlcmlmeSh7IHBheWxvYWQsIHByb3RlY3RlZDogcHJvdGVjdGVkSGVhZGVyLCBzaWduYXR1cmUgfSwga2V5LCBvcHRpb25zKTtcbiAgICBjb25zdCByZXN1bHQgPSB7IHBheWxvYWQ6IHZlcmlmaWVkLnBheWxvYWQsIHByb3RlY3RlZEhlYWRlcjogdmVyaWZpZWQucHJvdGVjdGVkSGVhZGVyIH07XG4gICAgaWYgKHR5cGVvZiBrZXkgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAgcmV0dXJuIHsgLi4ucmVzdWx0LCBrZXk6IHZlcmlmaWVkLmtleSB9O1xuICAgIH1cbiAgICByZXR1cm4gcmVzdWx0O1xufVxuIiwiaW1wb3J0IHsgZmxhdHRlbmVkVmVyaWZ5IH0gZnJvbSAnLi4vZmxhdHRlbmVkL3ZlcmlmeS5qcyc7XG5pbXBvcnQgeyBKV1NJbnZhbGlkLCBKV1NTaWduYXR1cmVWZXJpZmljYXRpb25GYWlsZWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgaXNPYmplY3QgZnJvbSAnLi4vLi4vbGliL2lzX29iamVjdC5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhbFZlcmlmeShqd3MsIGtleSwgb3B0aW9ucykge1xuICAgIGlmICghaXNPYmplY3QoandzKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnR2VuZXJhbCBKV1MgbXVzdCBiZSBhbiBvYmplY3QnKTtcbiAgICB9XG4gICAgaWYgKCFBcnJheS5pc0FycmF5KGp3cy5zaWduYXR1cmVzKSB8fCAhandzLnNpZ25hdHVyZXMuZXZlcnkoaXNPYmplY3QpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgU2lnbmF0dXJlcyBtaXNzaW5nIG9yIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGZvciAoY29uc3Qgc2lnbmF0dXJlIG9mIGp3cy5zaWduYXR1cmVzKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICByZXR1cm4gYXdhaXQgZmxhdHRlbmVkVmVyaWZ5KHtcbiAgICAgICAgICAgICAgICBoZWFkZXI6IHNpZ25hdHVyZS5oZWFkZXIsXG4gICAgICAgICAgICAgICAgcGF5bG9hZDogandzLnBheWxvYWQsXG4gICAgICAgICAgICAgICAgcHJvdGVjdGVkOiBzaWduYXR1cmUucHJvdGVjdGVkLFxuICAgICAgICAgICAgICAgIHNpZ25hdHVyZTogc2lnbmF0dXJlLnNpZ25hdHVyZSxcbiAgICAgICAgICAgIH0sIGtleSwgb3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICB9XG4gICAgfVxuICAgIHRocm93IG5ldyBKV1NTaWduYXR1cmVWZXJpZmljYXRpb25GYWlsZWQoKTtcbn1cbiIsImltcG9ydCB7IEZsYXR0ZW5lZEVuY3J5cHQgfSBmcm9tICcuLi9mbGF0dGVuZWQvZW5jcnlwdC5qcyc7XG5leHBvcnQgY2xhc3MgQ29tcGFjdEVuY3J5cHQge1xuICAgIGNvbnN0cnVjdG9yKHBsYWludGV4dCkge1xuICAgICAgICB0aGlzLl9mbGF0dGVuZWQgPSBuZXcgRmxhdHRlbmVkRW5jcnlwdChwbGFpbnRleHQpO1xuICAgIH1cbiAgICBzZXRDb250ZW50RW5jcnlwdGlvbktleShjZWspIHtcbiAgICAgICAgdGhpcy5fZmxhdHRlbmVkLnNldENvbnRlbnRFbmNyeXB0aW9uS2V5KGNlayk7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRJbml0aWFsaXphdGlvblZlY3Rvcihpdikge1xuICAgICAgICB0aGlzLl9mbGF0dGVuZWQuc2V0SW5pdGlhbGl6YXRpb25WZWN0b3IoaXYpO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICB0aGlzLl9mbGF0dGVuZWQuc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcik7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRLZXlNYW5hZ2VtZW50UGFyYW1ldGVycyhwYXJhbWV0ZXJzKSB7XG4gICAgICAgIHRoaXMuX2ZsYXR0ZW5lZC5zZXRLZXlNYW5hZ2VtZW50UGFyYW1ldGVycyhwYXJhbWV0ZXJzKTtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIGFzeW5jIGVuY3J5cHQoa2V5LCBvcHRpb25zKSB7XG4gICAgICAgIGNvbnN0IGp3ZSA9IGF3YWl0IHRoaXMuX2ZsYXR0ZW5lZC5lbmNyeXB0KGtleSwgb3B0aW9ucyk7XG4gICAgICAgIHJldHVybiBbandlLnByb3RlY3RlZCwgandlLmVuY3J5cHRlZF9rZXksIGp3ZS5pdiwgandlLmNpcGhlcnRleHQsIGp3ZS50YWddLmpvaW4oJy4nKTtcbiAgICB9XG59XG4iLCJpbXBvcnQgc3VidGxlQWxnb3JpdGhtIGZyb20gJy4vc3VidGxlX2RzYS5qcyc7XG5pbXBvcnQgY3J5cHRvIGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCBjaGVja0tleUxlbmd0aCBmcm9tICcuL2NoZWNrX2tleV9sZW5ndGguanMnO1xuaW1wb3J0IGdldFNpZ25LZXkgZnJvbSAnLi9nZXRfc2lnbl92ZXJpZnlfa2V5LmpzJztcbmNvbnN0IHNpZ24gPSBhc3luYyAoYWxnLCBrZXksIGRhdGEpID0+IHtcbiAgICBjb25zdCBjcnlwdG9LZXkgPSBhd2FpdCBnZXRTaWduS2V5KGFsZywga2V5LCAnc2lnbicpO1xuICAgIGNoZWNrS2V5TGVuZ3RoKGFsZywgY3J5cHRvS2V5KTtcbiAgICBjb25zdCBzaWduYXR1cmUgPSBhd2FpdCBjcnlwdG8uc3VidGxlLnNpZ24oc3VidGxlQWxnb3JpdGhtKGFsZywgY3J5cHRvS2V5LmFsZ29yaXRobSksIGNyeXB0b0tleSwgZGF0YSk7XG4gICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KHNpZ25hdHVyZSk7XG59O1xuZXhwb3J0IGRlZmF1bHQgc2lnbjtcbiIsImltcG9ydCB7IGVuY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi8uLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgc2lnbiBmcm9tICcuLi8uLi9ydW50aW1lL3NpZ24uanMnO1xuaW1wb3J0IGlzRGlzam9pbnQgZnJvbSAnLi4vLi4vbGliL2lzX2Rpc2pvaW50LmpzJztcbmltcG9ydCB7IEpXU0ludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgeyBlbmNvZGVyLCBkZWNvZGVyLCBjb25jYXQgfSBmcm9tICcuLi8uLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmltcG9ydCB7IGNoZWNrS2V5VHlwZVdpdGhKd2sgfSBmcm9tICcuLi8uLi9saWIvY2hlY2tfa2V5X3R5cGUuanMnO1xuaW1wb3J0IHZhbGlkYXRlQ3JpdCBmcm9tICcuLi8uLi9saWIvdmFsaWRhdGVfY3JpdC5qcyc7XG5leHBvcnQgY2xhc3MgRmxhdHRlbmVkU2lnbiB7XG4gICAgY29uc3RydWN0b3IocGF5bG9hZCkge1xuICAgICAgICBpZiAoIShwYXlsb2FkIGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3BheWxvYWQgbXVzdCBiZSBhbiBpbnN0YW5jZSBvZiBVaW50OEFycmF5Jyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fcGF5bG9hZCA9IHBheWxvYWQ7XG4gICAgfVxuICAgIHNldFByb3RlY3RlZEhlYWRlcihwcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMuX3Byb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0UHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fcHJvdGVjdGVkSGVhZGVyID0gcHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0VW5wcm90ZWN0ZWRIZWFkZXIodW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRVbnByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyID0gdW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBhc3luYyBzaWduKGtleSwgb3B0aW9ucykge1xuICAgICAgICBpZiAoIXRoaXMuX3Byb3RlY3RlZEhlYWRlciAmJiAhdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdlaXRoZXIgc2V0UHJvdGVjdGVkSGVhZGVyIG9yIHNldFVucHJvdGVjdGVkSGVhZGVyIG11c3QgYmUgY2FsbGVkIGJlZm9yZSAjc2lnbigpJyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCFpc0Rpc2pvaW50KHRoaXMuX3Byb3RlY3RlZEhlYWRlciwgdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFByb3RlY3RlZCBhbmQgSldTIFVucHJvdGVjdGVkIEhlYWRlciBQYXJhbWV0ZXIgbmFtZXMgbXVzdCBiZSBkaXNqb2ludCcpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IGpvc2VIZWFkZXIgPSB7XG4gICAgICAgICAgICAuLi50aGlzLl9wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICAuLi50aGlzLl91bnByb3RlY3RlZEhlYWRlcixcbiAgICAgICAgfTtcbiAgICAgICAgY29uc3QgZXh0ZW5zaW9ucyA9IHZhbGlkYXRlQ3JpdChKV1NJbnZhbGlkLCBuZXcgTWFwKFtbJ2I2NCcsIHRydWVdXSksIG9wdGlvbnM/LmNyaXQsIHRoaXMuX3Byb3RlY3RlZEhlYWRlciwgam9zZUhlYWRlcik7XG4gICAgICAgIGxldCBiNjQgPSB0cnVlO1xuICAgICAgICBpZiAoZXh0ZW5zaW9ucy5oYXMoJ2I2NCcpKSB7XG4gICAgICAgICAgICBiNjQgPSB0aGlzLl9wcm90ZWN0ZWRIZWFkZXIuYjY0O1xuICAgICAgICAgICAgaWYgKHR5cGVvZiBiNjQgIT09ICdib29sZWFuJykge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdUaGUgXCJiNjRcIiAoYmFzZTY0dXJsLWVuY29kZSBwYXlsb2FkKSBIZWFkZXIgUGFyYW1ldGVyIG11c3QgYmUgYSBib29sZWFuJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgeyBhbGcgfSA9IGpvc2VIZWFkZXI7XG4gICAgICAgIGlmICh0eXBlb2YgYWxnICE9PSAnc3RyaW5nJyB8fCAhYWxnKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFwiYWxnXCIgKEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBtaXNzaW5nIG9yIGludmFsaWQnKTtcbiAgICAgICAgfVxuICAgICAgICBjaGVja0tleVR5cGVXaXRoSndrKGFsZywga2V5LCAnc2lnbicpO1xuICAgICAgICBsZXQgcGF5bG9hZCA9IHRoaXMuX3BheWxvYWQ7XG4gICAgICAgIGlmIChiNjQpIHtcbiAgICAgICAgICAgIHBheWxvYWQgPSBlbmNvZGVyLmVuY29kZShiYXNlNjR1cmwocGF5bG9hZCkpO1xuICAgICAgICB9XG4gICAgICAgIGxldCBwcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIGlmICh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHByb3RlY3RlZEhlYWRlciA9IGVuY29kZXIuZW5jb2RlKGJhc2U2NHVybChKU09OLnN0cmluZ2lmeSh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpKSk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBwcm90ZWN0ZWRIZWFkZXIgPSBlbmNvZGVyLmVuY29kZSgnJyk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgZGF0YSA9IGNvbmNhdChwcm90ZWN0ZWRIZWFkZXIsIGVuY29kZXIuZW5jb2RlKCcuJyksIHBheWxvYWQpO1xuICAgICAgICBjb25zdCBzaWduYXR1cmUgPSBhd2FpdCBzaWduKGFsZywga2V5LCBkYXRhKTtcbiAgICAgICAgY29uc3QgandzID0ge1xuICAgICAgICAgICAgc2lnbmF0dXJlOiBiYXNlNjR1cmwoc2lnbmF0dXJlKSxcbiAgICAgICAgICAgIHBheWxvYWQ6ICcnLFxuICAgICAgICB9O1xuICAgICAgICBpZiAoYjY0KSB7XG4gICAgICAgICAgICBqd3MucGF5bG9hZCA9IGRlY29kZXIuZGVjb2RlKHBheWxvYWQpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl91bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgandzLmhlYWRlciA9IHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIGp3cy5wcm90ZWN0ZWQgPSBkZWNvZGVyLmRlY29kZShwcm90ZWN0ZWRIZWFkZXIpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBqd3M7XG4gICAgfVxufVxuIiwiaW1wb3J0IHsgRmxhdHRlbmVkU2lnbiB9IGZyb20gJy4uL2ZsYXR0ZW5lZC9zaWduLmpzJztcbmV4cG9ydCBjbGFzcyBDb21wYWN0U2lnbiB7XG4gICAgY29uc3RydWN0b3IocGF5bG9hZCkge1xuICAgICAgICB0aGlzLl9mbGF0dGVuZWQgPSBuZXcgRmxhdHRlbmVkU2lnbihwYXlsb2FkKTtcbiAgICB9XG4gICAgc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICB0aGlzLl9mbGF0dGVuZWQuc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcik7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBhc3luYyBzaWduKGtleSwgb3B0aW9ucykge1xuICAgICAgICBjb25zdCBqd3MgPSBhd2FpdCB0aGlzLl9mbGF0dGVuZWQuc2lnbihrZXksIG9wdGlvbnMpO1xuICAgICAgICBpZiAoandzLnBheWxvYWQgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcigndXNlIHRoZSBmbGF0dGVuZWQgbW9kdWxlIGZvciBjcmVhdGluZyBKV1Mgd2l0aCBiNjQ6IGZhbHNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGAke2p3cy5wcm90ZWN0ZWR9LiR7andzLnBheWxvYWR9LiR7andzLnNpZ25hdHVyZX1gO1xuICAgIH1cbn1cbiIsImltcG9ydCB7IEZsYXR0ZW5lZFNpZ24gfSBmcm9tICcuLi9mbGF0dGVuZWQvc2lnbi5qcyc7XG5pbXBvcnQgeyBKV1NJbnZhbGlkIH0gZnJvbSAnLi4vLi4vdXRpbC9lcnJvcnMuanMnO1xuY2xhc3MgSW5kaXZpZHVhbFNpZ25hdHVyZSB7XG4gICAgY29uc3RydWN0b3Ioc2lnLCBrZXksIG9wdGlvbnMpIHtcbiAgICAgICAgdGhpcy5wYXJlbnQgPSBzaWc7XG4gICAgICAgIHRoaXMua2V5ID0ga2V5O1xuICAgICAgICB0aGlzLm9wdGlvbnMgPSBvcHRpb25zO1xuICAgIH1cbiAgICBzZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0UHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5wcm90ZWN0ZWRIZWFkZXIgPSBwcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRVbnByb3RlY3RlZEhlYWRlcih1bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy51bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0VW5wcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLnVucHJvdGVjdGVkSGVhZGVyID0gdW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBhZGRTaWduYXR1cmUoLi4uYXJncykge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXJlbnQuYWRkU2lnbmF0dXJlKC4uLmFyZ3MpO1xuICAgIH1cbiAgICBzaWduKC4uLmFyZ3MpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGFyZW50LnNpZ24oLi4uYXJncyk7XG4gICAgfVxuICAgIGRvbmUoKSB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhcmVudDtcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgR2VuZXJhbFNpZ24ge1xuICAgIGNvbnN0cnVjdG9yKHBheWxvYWQpIHtcbiAgICAgICAgdGhpcy5fc2lnbmF0dXJlcyA9IFtdO1xuICAgICAgICB0aGlzLl9wYXlsb2FkID0gcGF5bG9hZDtcbiAgICB9XG4gICAgYWRkU2lnbmF0dXJlKGtleSwgb3B0aW9ucykge1xuICAgICAgICBjb25zdCBzaWduYXR1cmUgPSBuZXcgSW5kaXZpZHVhbFNpZ25hdHVyZSh0aGlzLCBrZXksIG9wdGlvbnMpO1xuICAgICAgICB0aGlzLl9zaWduYXR1cmVzLnB1c2goc2lnbmF0dXJlKTtcbiAgICAgICAgcmV0dXJuIHNpZ25hdHVyZTtcbiAgICB9XG4gICAgYXN5bmMgc2lnbigpIHtcbiAgICAgICAgaWYgKCF0aGlzLl9zaWduYXR1cmVzLmxlbmd0aCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ2F0IGxlYXN0IG9uZSBzaWduYXR1cmUgbXVzdCBiZSBhZGRlZCcpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IGp3cyA9IHtcbiAgICAgICAgICAgIHNpZ25hdHVyZXM6IFtdLFxuICAgICAgICAgICAgcGF5bG9hZDogJycsXG4gICAgICAgIH07XG4gICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgdGhpcy5fc2lnbmF0dXJlcy5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgY29uc3Qgc2lnbmF0dXJlID0gdGhpcy5fc2lnbmF0dXJlc1tpXTtcbiAgICAgICAgICAgIGNvbnN0IGZsYXR0ZW5lZCA9IG5ldyBGbGF0dGVuZWRTaWduKHRoaXMuX3BheWxvYWQpO1xuICAgICAgICAgICAgZmxhdHRlbmVkLnNldFByb3RlY3RlZEhlYWRlcihzaWduYXR1cmUucHJvdGVjdGVkSGVhZGVyKTtcbiAgICAgICAgICAgIGZsYXR0ZW5lZC5zZXRVbnByb3RlY3RlZEhlYWRlcihzaWduYXR1cmUudW5wcm90ZWN0ZWRIZWFkZXIpO1xuICAgICAgICAgICAgY29uc3QgeyBwYXlsb2FkLCAuLi5yZXN0IH0gPSBhd2FpdCBmbGF0dGVuZWQuc2lnbihzaWduYXR1cmUua2V5LCBzaWduYXR1cmUub3B0aW9ucyk7XG4gICAgICAgICAgICBpZiAoaSA9PT0gMCkge1xuICAgICAgICAgICAgICAgIGp3cy5wYXlsb2FkID0gcGF5bG9hZDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2UgaWYgKGp3cy5wYXlsb2FkICE9PSBwYXlsb2FkKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ2luY29uc2lzdGVudCB1c2Ugb2YgSldTIFVuZW5jb2RlZCBQYXlsb2FkIChSRkM3Nzk3KScpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgandzLnNpZ25hdHVyZXMucHVzaChyZXN0KTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gandzO1xuICAgIH1cbn1cbiIsImltcG9ydCAqIGFzIGJhc2U2NHVybCBmcm9tICcuLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5leHBvcnQgY29uc3QgZW5jb2RlID0gYmFzZTY0dXJsLmVuY29kZTtcbmV4cG9ydCBjb25zdCBkZWNvZGUgPSBiYXNlNjR1cmwuZGVjb2RlO1xuIiwiaW1wb3J0IHsgZGVjb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4vYmFzZTY0dXJsLmpzJztcbmltcG9ydCB7IGRlY29kZXIgfSBmcm9tICcuLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmltcG9ydCBpc09iamVjdCBmcm9tICcuLi9saWIvaXNfb2JqZWN0LmpzJztcbmV4cG9ydCBmdW5jdGlvbiBkZWNvZGVQcm90ZWN0ZWRIZWFkZXIodG9rZW4pIHtcbiAgICBsZXQgcHJvdGVjdGVkQjY0dTtcbiAgICBpZiAodHlwZW9mIHRva2VuID09PSAnc3RyaW5nJykge1xuICAgICAgICBjb25zdCBwYXJ0cyA9IHRva2VuLnNwbGl0KCcuJyk7XG4gICAgICAgIGlmIChwYXJ0cy5sZW5ndGggPT09IDMgfHwgcGFydHMubGVuZ3RoID09PSA1KSB7XG4gICAgICAgICAgICA7XG4gICAgICAgICAgICBbcHJvdGVjdGVkQjY0dV0gPSBwYXJ0cztcbiAgICAgICAgfVxuICAgIH1cbiAgICBlbHNlIGlmICh0eXBlb2YgdG9rZW4gPT09ICdvYmplY3QnICYmIHRva2VuKSB7XG4gICAgICAgIGlmICgncHJvdGVjdGVkJyBpbiB0b2tlbikge1xuICAgICAgICAgICAgcHJvdGVjdGVkQjY0dSA9IHRva2VuLnByb3RlY3RlZDtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1Rva2VuIGRvZXMgbm90IGNvbnRhaW4gYSBQcm90ZWN0ZWQgSGVhZGVyJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgdHJ5IHtcbiAgICAgICAgaWYgKHR5cGVvZiBwcm90ZWN0ZWRCNjR1ICE9PSAnc3RyaW5nJyB8fCAhcHJvdGVjdGVkQjY0dSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgcmVzdWx0ID0gSlNPTi5wYXJzZShkZWNvZGVyLmRlY29kZShiYXNlNjR1cmwocHJvdGVjdGVkQjY0dSkpKTtcbiAgICAgICAgaWYgKCFpc09iamVjdChyZXN1bHQpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0ludmFsaWQgVG9rZW4gb3IgUHJvdGVjdGVkIEhlYWRlciBmb3JtYXR0aW5nJyk7XG4gICAgfVxufVxuIiwiaW1wb3J0IGNyeXB0byBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHJhbmRvbSBmcm9tICcuL3JhbmRvbS5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhdGVTZWNyZXQoYWxnLCBvcHRpb25zKSB7XG4gICAgbGV0IGxlbmd0aDtcbiAgICBsZXQgYWxnb3JpdGhtO1xuICAgIGxldCBrZXlVc2FnZXM7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnSFMyNTYnOlxuICAgICAgICBjYXNlICdIUzM4NCc6XG4gICAgICAgIGNhc2UgJ0hTNTEyJzpcbiAgICAgICAgICAgIGxlbmd0aCA9IHBhcnNlSW50KGFsZy5zbGljZSgtMyksIDEwKTtcbiAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0hNQUMnLCBoYXNoOiBgU0hBLSR7bGVuZ3RofWAsIGxlbmd0aCB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydzaWduJywgJ3ZlcmlmeSddO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ0ExMjhDQkMtSFMyNTYnOlxuICAgICAgICBjYXNlICdBMTkyQ0JDLUhTMzg0JzpcbiAgICAgICAgY2FzZSAnQTI1NkNCQy1IUzUxMic6XG4gICAgICAgICAgICBsZW5ndGggPSBwYXJzZUludChhbGcuc2xpY2UoLTMpLCAxMCk7XG4gICAgICAgICAgICByZXR1cm4gcmFuZG9tKG5ldyBVaW50OEFycmF5KGxlbmd0aCA+PiAzKSk7XG4gICAgICAgIGNhc2UgJ0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZLVyc6XG4gICAgICAgICAgICBsZW5ndGggPSBwYXJzZUludChhbGcuc2xpY2UoMSwgNCksIDEwKTtcbiAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0FFUy1LVycsIGxlbmd0aCB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWyd3cmFwS2V5JywgJ3Vud3JhcEtleSddO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ0ExMjhHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0ExMjhHQ00nOlxuICAgICAgICBjYXNlICdBMTkyR0NNJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTSc6XG4gICAgICAgICAgICBsZW5ndGggPSBwYXJzZUludChhbGcuc2xpY2UoMSwgNCksIDEwKTtcbiAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0FFUy1HQ00nLCBsZW5ndGggfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnZW5jcnlwdCcsICdkZWNyeXB0J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIEpXSyBcImFsZ1wiIChBbGdvcml0aG0pIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgIH1cbiAgICByZXR1cm4gY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleShhbGdvcml0aG0sIG9wdGlvbnM/LmV4dHJhY3RhYmxlID8/IGZhbHNlLCBrZXlVc2FnZXMpO1xufVxuZnVuY3Rpb24gZ2V0TW9kdWx1c0xlbmd0aE9wdGlvbihvcHRpb25zKSB7XG4gICAgY29uc3QgbW9kdWx1c0xlbmd0aCA9IG9wdGlvbnM/Lm1vZHVsdXNMZW5ndGggPz8gMjA0ODtcbiAgICBpZiAodHlwZW9mIG1vZHVsdXNMZW5ndGggIT09ICdudW1iZXInIHx8IG1vZHVsdXNMZW5ndGggPCAyMDQ4KSB7XG4gICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIG1vZHVsdXNMZW5ndGggb3B0aW9uIHByb3ZpZGVkLCAyMDQ4IGJpdHMgb3IgbGFyZ2VyIGtleXMgbXVzdCBiZSB1c2VkJyk7XG4gICAgfVxuICAgIHJldHVybiBtb2R1bHVzTGVuZ3RoO1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdlbmVyYXRlS2V5UGFpcihhbGcsIG9wdGlvbnMpIHtcbiAgICBsZXQgYWxnb3JpdGhtO1xuICAgIGxldCBrZXlVc2FnZXM7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnUFMyNTYnOlxuICAgICAgICBjYXNlICdQUzM4NCc6XG4gICAgICAgIGNhc2UgJ1BTNTEyJzpcbiAgICAgICAgICAgIGFsZ29yaXRobSA9IHtcbiAgICAgICAgICAgICAgICBuYW1lOiAnUlNBLVBTUycsXG4gICAgICAgICAgICAgICAgaGFzaDogYFNIQS0ke2FsZy5zbGljZSgtMyl9YCxcbiAgICAgICAgICAgICAgICBwdWJsaWNFeHBvbmVudDogbmV3IFVpbnQ4QXJyYXkoWzB4MDEsIDB4MDAsIDB4MDFdKSxcbiAgICAgICAgICAgICAgICBtb2R1bHVzTGVuZ3RoOiBnZXRNb2R1bHVzTGVuZ3RoT3B0aW9uKG9wdGlvbnMpLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnc2lnbicsICd2ZXJpZnknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdSUzI1Nic6XG4gICAgICAgIGNhc2UgJ1JTMzg0JzpcbiAgICAgICAgY2FzZSAnUlM1MTInOlxuICAgICAgICAgICAgYWxnb3JpdGhtID0ge1xuICAgICAgICAgICAgICAgIG5hbWU6ICdSU0FTU0EtUEtDUzEtdjFfNScsXG4gICAgICAgICAgICAgICAgaGFzaDogYFNIQS0ke2FsZy5zbGljZSgtMyl9YCxcbiAgICAgICAgICAgICAgICBwdWJsaWNFeHBvbmVudDogbmV3IFVpbnQ4QXJyYXkoWzB4MDEsIDB4MDAsIDB4MDFdKSxcbiAgICAgICAgICAgICAgICBtb2R1bHVzTGVuZ3RoOiBnZXRNb2R1bHVzTGVuZ3RoT3B0aW9uKG9wdGlvbnMpLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnc2lnbicsICd2ZXJpZnknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdSU0EtT0FFUCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTI1Nic6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTM4NCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTUxMic6XG4gICAgICAgICAgICBhbGdvcml0aG0gPSB7XG4gICAgICAgICAgICAgICAgbmFtZTogJ1JTQS1PQUVQJyxcbiAgICAgICAgICAgICAgICBoYXNoOiBgU0hBLSR7cGFyc2VJbnQoYWxnLnNsaWNlKC0zKSwgMTApIHx8IDF9YCxcbiAgICAgICAgICAgICAgICBwdWJsaWNFeHBvbmVudDogbmV3IFVpbnQ4QXJyYXkoWzB4MDEsIDB4MDAsIDB4MDFdKSxcbiAgICAgICAgICAgICAgICBtb2R1bHVzTGVuZ3RoOiBnZXRNb2R1bHVzTGVuZ3RoT3B0aW9uKG9wdGlvbnMpLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnZGVjcnlwdCcsICd1bndyYXBLZXknLCAnZW5jcnlwdCcsICd3cmFwS2V5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnRVMyNTYnOlxuICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNEU0EnLCBuYW1lZEN1cnZlOiAnUC0yNTYnIH07XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3NpZ24nLCAndmVyaWZ5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnRVMzODQnOlxuICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNEU0EnLCBuYW1lZEN1cnZlOiAnUC0zODQnIH07XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3NpZ24nLCAndmVyaWZ5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnRVM1MTInOlxuICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNEU0EnLCBuYW1lZEN1cnZlOiAnUC01MjEnIH07XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3NpZ24nLCAndmVyaWZ5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnRWREU0EnOiB7XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3NpZ24nLCAndmVyaWZ5J107XG4gICAgICAgICAgICBjb25zdCBjcnYgPSBvcHRpb25zPy5jcnYgPz8gJ0VkMjU1MTknO1xuICAgICAgICAgICAgc3dpdGNoIChjcnYpIHtcbiAgICAgICAgICAgICAgICBjYXNlICdFZDI1NTE5JzpcbiAgICAgICAgICAgICAgICBjYXNlICdFZDQ0OCc6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogY3J2IH07XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIGNydiBvcHRpb24gcHJvdmlkZWQnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0VDREgtRVMnOlxuICAgICAgICBjYXNlICdFQ0RILUVTK0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTE5MktXJzpcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMjU2S1cnOiB7XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ2Rlcml2ZUtleScsICdkZXJpdmVCaXRzJ107XG4gICAgICAgICAgICBjb25zdCBjcnYgPSBvcHRpb25zPy5jcnYgPz8gJ1AtMjU2JztcbiAgICAgICAgICAgIHN3aXRjaCAoY3J2KSB7XG4gICAgICAgICAgICAgICAgY2FzZSAnUC0yNTYnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1AtMzg0JzpcbiAgICAgICAgICAgICAgICBjYXNlICdQLTUyMSc6IHtcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNESCcsIG5hbWVkQ3VydmU6IGNydiB9O1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2FzZSAnWDI1NTE5JzpcbiAgICAgICAgICAgICAgICBjYXNlICdYNDQ4JzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiBjcnYgfTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgY3J2IG9wdGlvbiBwcm92aWRlZCwgc3VwcG9ydGVkIHZhbHVlcyBhcmUgUC0yNTYsIFAtMzg0LCBQLTUyMSwgWDI1NTE5LCBhbmQgWDQ0OCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIEpXSyBcImFsZ1wiIChBbGdvcml0aG0pIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgIH1cbiAgICByZXR1cm4gY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleShhbGdvcml0aG0sIG9wdGlvbnM/LmV4dHJhY3RhYmxlID8/IGZhbHNlLCBrZXlVc2FnZXMpO1xufVxuIiwiaW1wb3J0IHsgZ2VuZXJhdGVLZXlQYWlyIGFzIGdlbmVyYXRlIH0gZnJvbSAnLi4vcnVudGltZS9nZW5lcmF0ZS5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhdGVLZXlQYWlyKGFsZywgb3B0aW9ucykge1xuICAgIHJldHVybiBnZW5lcmF0ZShhbGcsIG9wdGlvbnMpO1xufVxuIiwiaW1wb3J0IHsgZ2VuZXJhdGVTZWNyZXQgYXMgZ2VuZXJhdGUgfSBmcm9tICcuLi9ydW50aW1lL2dlbmVyYXRlLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZVNlY3JldChhbGcsIG9wdGlvbnMpIHtcbiAgICByZXR1cm4gZ2VuZXJhdGUoYWxnLCBvcHRpb25zKTtcbn1cbiIsIi8vIE9uZSBjb25zaXN0ZW50IGFsZ29yaXRobSBmb3IgZWFjaCBmYW1pbHkuXG4vLyBodHRwczovL2RhdGF0cmFja2VyLmlldGYub3JnL2RvYy9odG1sL3JmYzc1MThcblxuZXhwb3J0IGNvbnN0IHNpZ25pbmdOYW1lID0gJ0VkRFNBJztcbmV4cG9ydCBjb25zdCBzaWduaW5nQ3VydmUgPSAnRWQyNTUxOSc7XG5leHBvcnQgY29uc3Qgc2lnbmluZ0FsZ29yaXRobSA9ICdFZERTQSc7XG5cbmV4cG9ydCBjb25zdCBlbmNyeXB0aW5nTmFtZSA9ICdSU0EtT0FFUCc7XG5leHBvcnQgY29uc3QgaGFzaExlbmd0aCA9IDI1NjtcbmV4cG9ydCBjb25zdCBoYXNoTmFtZSA9ICdTSEEtMjU2JztcbmV4cG9ydCBjb25zdCBtb2R1bHVzTGVuZ3RoID0gNDA5NjsgLy8gcGFudmEgSk9TRSBsaWJyYXJ5IGRlZmF1bHQgaXMgMjA0OFxuZXhwb3J0IGNvbnN0IGVuY3J5cHRpbmdBbGdvcml0aG0gPSAnUlNBLU9BRVAtMjU2JztcblxuZXhwb3J0IGNvbnN0IHN5bW1ldHJpY05hbWUgPSAnQUVTLUdDTSc7XG5leHBvcnQgY29uc3Qgc3ltbWV0cmljQWxnb3JpdGhtID0gJ0EyNTZHQ00nO1xuZXhwb3J0IGNvbnN0IHN5bW1ldHJpY1dyYXAgPSAnQTI1NkdDTUtXJztcbmV4cG9ydCBjb25zdCBzZWNyZXRBbGdvcml0aG0gPSAnUEJFUzItSFM1MTIrQTI1NktXJztcblxuZXhwb3J0IGNvbnN0IGV4dHJhY3RhYmxlID0gdHJ1ZTsgIC8vIGFsd2F5cyB3cmFwcGVkXG5cbiIsImltcG9ydCBjcnlwdG8gZnJvbSAnI2NyeXB0byc7XG5pbXBvcnQgKiBhcyBKT1NFIGZyb20gJ2pvc2UnO1xuaW1wb3J0IHtoYXNoTmFtZX0gZnJvbSAnLi9hbGdvcml0aG1zLm1qcyc7XG5leHBvcnQge2NyeXB0bywgSk9TRX07XG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBoYXNoQnVmZmVyKGJ1ZmZlcikgeyAvLyBQcm9taXNlIGEgVWludDhBcnJheSBkaWdlc3Qgb2YgYnVmZmVyLlxuICBsZXQgaGFzaCA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZGlnZXN0KGhhc2hOYW1lLCBidWZmZXIpO1xuICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoaGFzaCk7XG59XG5leHBvcnQgZnVuY3Rpb24gaGFzaFRleHQodGV4dCkgeyAvLyBQcm9taXNlIGEgVWludDhBcnJheSBkaWdlc3Qgb2YgdGV4dCBzdHJpbmcuXG4gIGxldCBidWZmZXIgPSBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUodGV4dCk7XG4gIHJldHVybiBoYXNoQnVmZmVyKGJ1ZmZlcik7XG59XG5leHBvcnQgZnVuY3Rpb24gZW5jb2RlQmFzZTY0dXJsKHVpbnQ4QXJyYXkpIHsgLy8gQW5zd2VyIGJhc2U2NHVybCBlbmNvZGVkIHN0cmluZyBvZiBhcnJheS5cbiAgcmV0dXJuIEpPU0UuYmFzZTY0dXJsLmVuY29kZSh1aW50OEFycmF5KTtcbn1cbmV4cG9ydCBmdW5jdGlvbiBkZWNvZGVCYXNlNjR1cmwoc3RyaW5nKSB7IC8vIEFuc3dlciB0aGUgZGVjb2RlZCBVaW50OEFycmF5IG9mIHRoZSBiYXNlNjR1cmwgc3RyaW5nLlxuICByZXR1cm4gSk9TRS5iYXNlNjR1cmwuZGVjb2RlKHN0cmluZyk7XG59XG5leHBvcnQgZnVuY3Rpb24gZGVjb2RlQ2xhaW1zKGp3U29tZXRoaW5nLCBpbmRleCA9IDApIHsgLy8gQW5zd2VyIGFuIG9iamVjdCB3aG9zZSBrZXlzIGFyZSB0aGUgZGVjb2RlZCBwcm90ZWN0ZWQgaGVhZGVyIG9mIHRoZSBKV1Mgb3IgSldFICh1c2luZyBzaWduYXR1cmVzW2luZGV4XSBvZiBhIGdlbmVyYWwtZm9ybSBKV1MpLlxuICByZXR1cm4gSk9TRS5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIoandTb21ldGhpbmcuc2lnbmF0dXJlcz8uW2luZGV4XSB8fCBqd1NvbWV0aGluZyk7XG59XG4gICAgXG4iLCJpbXBvcnQge2V4dHJhY3RhYmxlLCBzaWduaW5nTmFtZSwgc2lnbmluZ0N1cnZlLCBzeW1tZXRyaWNOYW1lLCBoYXNoTGVuZ3RofSBmcm9tIFwiLi9hbGdvcml0aG1zLm1qc1wiO1xuaW1wb3J0IGNyeXB0byBmcm9tICcjY3J5cHRvJztcblxuZXhwb3J0IGZ1bmN0aW9uIGV4cG9ydFJhd0tleShrZXkpIHtcbiAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdyYXcnLCBrZXkpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gaW1wb3J0UmF3S2V5KGFycmF5QnVmZmVyKSB7XG4gIGNvbnN0IGFsZ29yaXRobSA9IHtuYW1lOiBzaWduaW5nQ3VydmV9O1xuICByZXR1cm4gY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGFycmF5QnVmZmVyLCBhbGdvcml0aG0sIGV4dHJhY3RhYmxlLCBbJ3ZlcmlmeSddKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGltcG9ydFNlY3JldChieXRlQXJyYXkpIHtcbiAgY29uc3QgYWxnb3JpdGhtID0ge25hbWU6IHN5bW1ldHJpY05hbWUsIGxlbmd0aDogaGFzaExlbmd0aH07XG4gIHJldHVybiBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgYnl0ZUFycmF5LCBhbGdvcml0aG0sIHRydWUsIFsnZW5jcnlwdCcsICdkZWNyeXB0J10pO1xufVxuIiwiaW1wb3J0IHtKT1NFLCBoYXNoVGV4dCwgZW5jb2RlQmFzZTY0dXJsLCBkZWNvZGVCYXNlNjR1cmx9IGZyb20gJy4vdXRpbGl0aWVzLm1qcyc7XG5pbXBvcnQge2V4cG9ydFJhd0tleSwgaW1wb3J0UmF3S2V5LCBpbXBvcnRTZWNyZXR9IGZyb20gJyNyYXcnO1xuaW1wb3J0IHtleHRyYWN0YWJsZSwgc2lnbmluZ05hbWUsIHNpZ25pbmdDdXJ2ZSwgc2lnbmluZ0FsZ29yaXRobSwgZW5jcnlwdGluZ05hbWUsIGhhc2hMZW5ndGgsIGhhc2hOYW1lLCBtb2R1bHVzTGVuZ3RoLCBlbmNyeXB0aW5nQWxnb3JpdGhtLCBzeW1tZXRyaWNOYW1lLCBzeW1tZXRyaWNBbGdvcml0aG19IGZyb20gJy4vYWxnb3JpdGhtcy5tanMnO1xuXG5jb25zdCBLcnlwdG8gPSB7XG4gIC8vIEFuIGluaGVyaXRhYmxlIHNpbmdsZXRvbiBmb3IgY29tcGFjdCBKT1NFIG9wZXJhdGlvbnMuXG4gIC8vIFNlZSBodHRwczovL2tpbHJveS1jb2RlLmdpdGh1Yi5pby9kaXN0cmlidXRlZC1zZWN1cml0eS9kb2NzL2ltcGxlbWVudGF0aW9uLmh0bWwjd3JhcHBpbmctc3VidGxla3J5cHRvXG4gIGRlY29kZVByb3RlY3RlZEhlYWRlcjogSk9TRS5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIsXG4gIGlzRW1wdHlKV1NQYXlsb2FkKGNvbXBhY3RKV1MpIHsgLy8gYXJnIGlzIGEgc3RyaW5nXG4gICAgcmV0dXJuICFjb21wYWN0SldTLnNwbGl0KCcuJylbMV07XG4gIH0sXG5cblxuICAvLyBUaGUgY3R5IGNhbiBiZSBzcGVjaWZpZWQgaW4gZW5jcnlwdC9zaWduLCBidXQgZGVmYXVsdHMgdG8gYSBnb29kIGd1ZXNzLlxuICAvLyBUaGUgY3R5IGNhbiBiZSBzcGVjaWZpZWQgaW4gZGVjcnlwdC92ZXJpZnksIGJ1dCBkZWZhdWx0cyB0byB3aGF0IGlzIHNwZWNpZmllZCBpbiB0aGUgcHJvdGVjdGVkIGhlYWRlci5cbiAgaW5wdXRCdWZmZXIoZGF0YSwgaGVhZGVyKSB7IC8vIEFuc3dlcnMgYSBidWZmZXIgdmlldyBvZiBkYXRhIGFuZCwgaWYgbmVjZXNzYXJ5IHRvIGNvbnZlcnQsIGJhc2hlcyBjdHkgb2YgaGVhZGVyLlxuICAgIGlmIChBcnJheUJ1ZmZlci5pc1ZpZXcoZGF0YSkpIHJldHVybiBkYXRhO1xuICAgIGxldCBnaXZlbkN0eSA9IGhlYWRlci5jdHkgfHwgJyc7XG4gICAgaWYgKGdpdmVuQ3R5LmluY2x1ZGVzKCd0ZXh0JykgfHwgKCdzdHJpbmcnID09PSB0eXBlb2YgZGF0YSkpIHtcbiAgICAgIGhlYWRlci5jdHkgPSBnaXZlbkN0eSB8fCAndGV4dC9wbGFpbic7XG4gICAgfSBlbHNlIHtcbiAgICAgIGhlYWRlci5jdHkgPSBnaXZlbkN0eSB8fCAnanNvbic7IC8vIEpXUyByZWNvbW1lbmRzIGxlYXZpbmcgb2ZmIHRoZSBsZWFkaW5nICdhcHBsaWNhdGlvbi8nLlxuICAgICAgZGF0YSA9IEpTT04uc3RyaW5naWZ5KGRhdGEpOyAvLyBOb3RlIHRoYXQgbmV3IFN0cmluZyhcInNvbWV0aGluZ1wiKSB3aWxsIHBhc3MgdGhpcyB3YXkuXG4gICAgfVxuICAgIHJldHVybiBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUoZGF0YSk7XG4gIH0sXG4gIHJlY292ZXJEYXRhRnJvbUNvbnRlbnRUeXBlKHJlc3VsdCwge2N0eSA9IHJlc3VsdD8ucHJvdGVjdGVkSGVhZGVyPy5jdHl9ID0ge30pIHtcbiAgICAvLyBFeGFtaW5lcyByZXN1bHQ/LnByb3RlY3RlZEhlYWRlciBhbmQgYmFzaGVzIGluIHJlc3VsdC50ZXh0IG9yIHJlc3VsdC5qc29uIGlmIGFwcHJvcHJpYXRlLCByZXR1cm5pbmcgcmVzdWx0LlxuICAgIGlmIChyZXN1bHQgJiYgIU9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChyZXN1bHQsICdwYXlsb2FkJykpIHJlc3VsdC5wYXlsb2FkID0gcmVzdWx0LnBsYWludGV4dDsgIC8vIGJlY2F1c2UgSk9TRSB1c2VzIHBsYWludGV4dCBmb3IgZGVjcnlwdCBhbmQgcGF5bG9hZCBmb3Igc2lnbi5cbiAgICBpZiAoIWN0eSB8fCAhcmVzdWx0Py5wYXlsb2FkKSByZXR1cm4gcmVzdWx0OyAvLyBlaXRoZXIgbm8gY3R5IG9yIG5vIHJlc3VsdFxuICAgIHJlc3VsdC50ZXh0ID0gbmV3IFRleHREZWNvZGVyKCkuZGVjb2RlKHJlc3VsdC5wYXlsb2FkKTtcbiAgICBpZiAoY3R5LmluY2x1ZGVzKCdqc29uJykpIHJlc3VsdC5qc29uID0gSlNPTi5wYXJzZShyZXN1bHQudGV4dCk7XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfSxcblxuICAvLyBTaWduL1ZlcmlmeVxuICBnZW5lcmF0ZVNpZ25pbmdLZXkoKSB7IC8vIFByb21pc2Uge3ByaXZhdGVLZXksIHB1YmxpY0tleX0gaW4gb3VyIHN0YW5kYXJkIHNpZ25pbmcgYWxnb3JpdGhtLlxuICAgIHJldHVybiBKT1NFLmdlbmVyYXRlS2V5UGFpcihzaWduaW5nQWxnb3JpdGhtLCB7ZXh0cmFjdGFibGV9KTtcbiAgfSxcbiAgYXN5bmMgc2lnbihwcml2YXRlS2V5LCBtZXNzYWdlLCBoZWFkZXJzID0ge30pIHsgLy8gUHJvbWlzZSBhIGNvbXBhY3QgSldTIHN0cmluZy4gQWNjZXB0cyBoZWFkZXJzIHRvIGJlIHByb3RlY3RlZC5cbiAgICBsZXQgaGVhZGVyID0ge2FsZzogc2lnbmluZ0FsZ29yaXRobSwgLi4uaGVhZGVyc30sXG4gICAgICAgIGlucHV0QnVmZmVyID0gdGhpcy5pbnB1dEJ1ZmZlcihtZXNzYWdlLCBoZWFkZXIpO1xuICAgIHJldHVybiBuZXcgSk9TRS5Db21wYWN0U2lnbihpbnB1dEJ1ZmZlcikuc2V0UHJvdGVjdGVkSGVhZGVyKGhlYWRlcikuc2lnbihwcml2YXRlS2V5KTtcbiAgfSxcbiAgYXN5bmMgdmVyaWZ5KHB1YmxpY0tleSwgc2lnbmF0dXJlLCBvcHRpb25zKSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259LCB3aGVyZSB0ZXh0IGFuZCBqc29uIGFyZSBvbmx5IGRlZmluZWQgd2hlbiBhcHByb3ByaWF0ZS5cbiAgICBsZXQgcmVzdWx0ID0gYXdhaXQgSk9TRS5jb21wYWN0VmVyaWZ5KHNpZ25hdHVyZSwgcHVibGljS2V5KS5jYXRjaCgoKSA9PiB1bmRlZmluZWQpO1xuICAgIHJldHVybiB0aGlzLnJlY292ZXJEYXRhRnJvbUNvbnRlbnRUeXBlKHJlc3VsdCwgb3B0aW9ucyk7XG4gIH0sXG5cbiAgLy8gRW5jcnlwdC9EZWNyeXB0XG4gIGdlbmVyYXRlRW5jcnlwdGluZ0tleSgpIHsgLy8gUHJvbWlzZSB7cHJpdmF0ZUtleSwgcHVibGljS2V5fSBpbiBvdXIgc3RhbmRhcmQgZW5jcnlwdGlvbiBhbGdvcml0aG0uXG4gICAgcmV0dXJuIEpPU0UuZ2VuZXJhdGVLZXlQYWlyKGVuY3J5cHRpbmdBbGdvcml0aG0sIHtleHRyYWN0YWJsZSwgbW9kdWx1c0xlbmd0aH0pO1xuICB9LFxuICBhc3luYyBlbmNyeXB0KGtleSwgbWVzc2FnZSwgaGVhZGVycyA9IHt9KSB7IC8vIFByb21pc2UgYSBjb21wYWN0IEpXRSBzdHJpbmcuIEFjY2VwdHMgaGVhZGVycyB0byBiZSBwcm90ZWN0ZWQuXG4gICAgbGV0IGFsZyA9IHRoaXMuaXNTeW1tZXRyaWMoa2V5KSA/ICdkaXInIDogZW5jcnlwdGluZ0FsZ29yaXRobSxcbiAgICAgICAgaGVhZGVyID0ge2FsZywgZW5jOiBzeW1tZXRyaWNBbGdvcml0aG0sIC4uLmhlYWRlcnN9LFxuICAgICAgICBpbnB1dEJ1ZmZlciA9IHRoaXMuaW5wdXRCdWZmZXIobWVzc2FnZSwgaGVhZGVyKSxcbiAgICAgICAgc2VjcmV0ID0gdGhpcy5rZXlTZWNyZXQoa2V5KTtcbiAgICByZXR1cm4gbmV3IEpPU0UuQ29tcGFjdEVuY3J5cHQoaW5wdXRCdWZmZXIpLnNldFByb3RlY3RlZEhlYWRlcihoZWFkZXIpLmVuY3J5cHQoc2VjcmV0KTtcbiAgfSxcbiAgYXN5bmMgZGVjcnlwdChrZXksIGVuY3J5cHRlZCwgb3B0aW9ucyA9IHt9KSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259LCB3aGVyZSB0ZXh0IGFuZCBqc29uIGFyZSBvbmx5IGRlZmluZWQgd2hlbiBhcHByb3ByaWF0ZS5cbiAgICBsZXQgc2VjcmV0ID0gdGhpcy5rZXlTZWNyZXQoa2V5KSxcbiAgICAgICAgcmVzdWx0ID0gYXdhaXQgSk9TRS5jb21wYWN0RGVjcnlwdChlbmNyeXB0ZWQsIHNlY3JldCk7XG4gICAgdGhpcy5yZWNvdmVyRGF0YUZyb21Db250ZW50VHlwZShyZXN1bHQsIG9wdGlvbnMpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH0sXG4gIGFzeW5jIGdlbmVyYXRlU2VjcmV0S2V5KHRleHQpIHsgLy8gSk9TRSB1c2VzIGEgZGlnZXN0IGZvciBQQkVTLCBidXQgbWFrZSBpdCByZWNvZ25pemFibGUgYXMgYSB7dHlwZTogJ3NlY3JldCd9IGtleS5cbiAgICBsZXQgaGFzaCA9IGF3YWl0IGhhc2hUZXh0KHRleHQpO1xuICAgIHJldHVybiB7dHlwZTogJ3NlY3JldCcsIHRleHQ6IGhhc2h9O1xuICB9LFxuICBnZW5lcmF0ZVN5bW1ldHJpY0tleSh0ZXh0KSB7IC8vIFByb21pc2UgYSBrZXkgZm9yIHN5bW1ldHJpYyBlbmNyeXB0aW9uLlxuICAgIGlmICh0ZXh0KSByZXR1cm4gdGhpcy5nZW5lcmF0ZVNlY3JldEtleSh0ZXh0KTsgLy8gUEJFU1xuICAgIHJldHVybiBKT1NFLmdlbmVyYXRlU2VjcmV0KHN5bW1ldHJpY0FsZ29yaXRobSwge2V4dHJhY3RhYmxlfSk7IC8vIEFFU1xuICB9LFxuICBpc1N5bW1ldHJpYyhrZXkpIHsgLy8gRWl0aGVyIEFFUyBvciBQQkVTLCBidXQgbm90IHB1YmxpY0tleSBvciBwcml2YXRlS2V5LlxuICAgIHJldHVybiBrZXkudHlwZSA9PT0gJ3NlY3JldCc7XG4gIH0sXG4gIGtleVNlY3JldChrZXkpIHsgLy8gUmV0dXJuIHdoYXQgaXMgYWN0dWFsbHkgdXNlZCBhcyBpbnB1dCBpbiBKT1NFIGxpYnJhcnkuXG4gICAgaWYgKGtleS50ZXh0KSByZXR1cm4ga2V5LnRleHQ7XG4gICAgcmV0dXJuIGtleTtcbiAgfSxcblxuICAvLyBFeHBvcnQvSW1wb3J0XG4gIGFzeW5jIGV4cG9ydFJhdyhrZXkpIHsgLy8gYmFzZTY0dXJsIGZvciBwdWJsaWMgdmVyZmljYXRpb24ga2V5c1xuICAgIGxldCBhcnJheUJ1ZmZlciA9IGF3YWl0IGV4cG9ydFJhd0tleShrZXkpO1xuICAgIHJldHVybiBlbmNvZGVCYXNlNjR1cmwobmV3IFVpbnQ4QXJyYXkoYXJyYXlCdWZmZXIpKTtcbiAgfSxcbiAgYXN5bmMgaW1wb3J0UmF3KHN0cmluZykgeyAvLyBQcm9taXNlIHRoZSB2ZXJpZmljYXRpb24ga2V5IGZyb20gYmFzZTY0dXJsXG4gICAgbGV0IGFycmF5QnVmZmVyID0gZGVjb2RlQmFzZTY0dXJsKHN0cmluZyk7XG4gICAgcmV0dXJuIGltcG9ydFJhd0tleShhcnJheUJ1ZmZlcik7XG4gIH0sXG4gIGFzeW5jIGV4cG9ydEpXSyhrZXkpIHsgLy8gUHJvbWlzZSBKV0sgb2JqZWN0LCB3aXRoIGFsZyBpbmNsdWRlZC5cbiAgICBsZXQgZXhwb3J0ZWQgPSBhd2FpdCBKT1NFLmV4cG9ydEpXSyhrZXkpLFxuICAgICAgICBhbGcgPSBrZXkuYWxnb3JpdGhtOyAvLyBKT1NFIGxpYnJhcnkgZ2l2ZXMgYWxnb3JpdGhtLCBidXQgbm90IGFsZyB0aGF0IGlzIG5lZWRlZCBmb3IgaW1wb3J0LlxuICAgIGlmIChhbGcpIHsgLy8gc3VidGxlLmNyeXB0byB1bmRlcmx5aW5nIGtleXNcbiAgICAgIGlmIChhbGcubmFtZSA9PT0gc2lnbmluZ05hbWUgJiYgYWxnLm5hbWVkQ3VydmUgPT09IHNpZ25pbmdDdXJ2ZSkgZXhwb3J0ZWQuYWxnID0gc2lnbmluZ0FsZ29yaXRobTtcbiAgICAgIGVsc2UgaWYgKGFsZy5uYW1lID09PSBzaWduaW5nQ3VydmUpIGV4cG9ydGVkLmFsZyA9IHNpZ25pbmdBbGdvcml0aG07XG4gICAgICBlbHNlIGlmIChhbGcubmFtZSA9PT0gZW5jcnlwdGluZ05hbWUgJiYgYWxnLmhhc2gubmFtZSA9PT0gaGFzaE5hbWUpIGV4cG9ydGVkLmFsZyA9IGVuY3J5cHRpbmdBbGdvcml0aG07XG4gICAgICBlbHNlIGlmIChhbGcubmFtZSA9PT0gc3ltbWV0cmljTmFtZSAmJiBhbGcubGVuZ3RoID09PSBoYXNoTGVuZ3RoKSBleHBvcnRlZC5hbGcgPSBzeW1tZXRyaWNBbGdvcml0aG07XG4gICAgfSBlbHNlIHN3aXRjaCAoZXhwb3J0ZWQua3R5KSB7IC8vIEpPU0Ugb24gTm9kZUpTIHVzZWQgbm9kZTpjcnlwdG8ga2V5cywgd2hpY2ggZG8gbm90IGV4cG9zZSB0aGUgcHJlY2lzZSBhbGdvcml0aG1cbiAgICAgIGNhc2UgJ0VDJzogZXhwb3J0ZWQuYWxnID0gc2lnbmluZ0FsZ29yaXRobTsgYnJlYWs7XG4gICAgICBjYXNlICdPS1AnOiBleHBvcnRlZC5hbGcgPSBzaWduaW5nQWxnb3JpdGhtOyBicmVhaztcbiAgICAgIGNhc2UgJ1JTQSc6IGV4cG9ydGVkLmFsZyA9IGVuY3J5cHRpbmdBbGdvcml0aG07IGJyZWFrO1xuICAgICAgY2FzZSAnb2N0JzogZXhwb3J0ZWQuYWxnID0gc3ltbWV0cmljQWxnb3JpdGhtOyBicmVhaztcbiAgICB9XG4gICAgcmV0dXJuIGV4cG9ydGVkO1xuICB9LFxuICBhc3luYyBpbXBvcnRKV0soandrKSB7IC8vIFByb21pc2UgYSBrZXkgb2JqZWN0XG4gICAgandrID0ge2V4dDogdHJ1ZSwgLi4uandrfTsgLy8gV2UgbmVlZCB0aGUgcmVzdWx0IHRvIGJlIGJlIGFibGUgdG8gZ2VuZXJhdGUgYSBuZXcgSldLIChlLmcuLCBvbiBjaGFuZ2VNZW1iZXJzaGlwKVxuICAgIGxldCBpbXBvcnRlZCA9IGF3YWl0IEpPU0UuaW1wb3J0SldLKGp3ayk7XG4gICAgaWYgKGltcG9ydGVkIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgLy8gV2UgZGVwZW5kIGFuIHJldHVybmluZyBhbiBhY3R1YWwga2V5LCBidXQgdGhlIEpPU0UgbGlicmFyeSB3ZSB1c2VcbiAgICAgIC8vIHdpbGwgYWJvdmUgcHJvZHVjZSB0aGUgcmF3IFVpbnQ4QXJyYXkgaWYgdGhlIGp3ayBpcyBmcm9tIGEgc2VjcmV0LlxuICAgICAgaW1wb3J0ZWQgPSBhd2FpdCBpbXBvcnRTZWNyZXQoaW1wb3J0ZWQpO1xuICAgIH1cbiAgICByZXR1cm4gaW1wb3J0ZWQ7XG4gIH0sXG5cbiAgYXN5bmMgd3JhcEtleShrZXksIHdyYXBwaW5nS2V5LCBoZWFkZXJzID0ge30pIHsgLy8gUHJvbWlzZSBhIEpXRSBmcm9tIHRoZSBwdWJsaWMgd3JhcHBpbmdLZXlcbiAgICBsZXQgZXhwb3J0ZWQgPSBhd2FpdCB0aGlzLmV4cG9ydEpXSyhrZXkpO1xuICAgIHJldHVybiB0aGlzLmVuY3J5cHQod3JhcHBpbmdLZXksIGV4cG9ydGVkLCBoZWFkZXJzKTtcbiAgfSxcbiAgYXN5bmMgdW53cmFwS2V5KHdyYXBwZWRLZXksIHVud3JhcHBpbmdLZXkpIHsgLy8gUHJvbWlzZSB0aGUga2V5IHVubG9ja2VkIGJ5IHRoZSBwcml2YXRlIHVud3JhcHBpbmdLZXkuXG4gICAgbGV0IGRlY3J5cHRlZCA9IGF3YWl0IHRoaXMuZGVjcnlwdCh1bndyYXBwaW5nS2V5LCB3cmFwcGVkS2V5KTtcbiAgICByZXR1cm4gdGhpcy5pbXBvcnRKV0soZGVjcnlwdGVkLmpzb24pO1xuICB9XG59XG5cbmV4cG9ydCBkZWZhdWx0IEtyeXB0bztcbi8qXG5Tb21lIHVzZWZ1bCBKT1NFIHJlY2lwZXMgZm9yIHBsYXlpbmcgYXJvdW5kLlxuc2sgPSBhd2FpdCBKT1NFLmdlbmVyYXRlS2V5UGFpcignRVMzODQnLCB7ZXh0cmFjdGFibGU6IHRydWV9KVxuand0ID0gYXdhaXQgbmV3IEpPU0UuU2lnbkpXVCgpLnNldFN1YmplY3QoXCJmb29cIikuc2V0UHJvdGVjdGVkSGVhZGVyKHthbGc6J0VTMzg0J30pLnNpZ24oc2sucHJpdmF0ZUtleSlcbmF3YWl0IEpPU0Uuand0VmVyaWZ5KGp3dCwgc2sucHVibGljS2V5KSAvLy5wYXlsb2FkLnN1YlxuXG5tZXNzYWdlID0gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKCdzb21lIG1lc3NhZ2UnKVxuandzID0gYXdhaXQgbmV3IEpPU0UuQ29tcGFjdFNpZ24obWVzc2FnZSkuc2V0UHJvdGVjdGVkSGVhZGVyKHthbGc6J0VTMzg0J30pLnNpZ24oc2sucHJpdmF0ZUtleSkgLy8gT3IgRmxhdHRlbmVkU2lnblxuandzID0gYXdhaXQgbmV3IEpPU0UuR2VuZXJhbFNpZ24obWVzc2FnZSkuYWRkU2lnbmF0dXJlKHNrLnByaXZhdGVLZXkpLnNldFByb3RlY3RlZEhlYWRlcih7YWxnOidFUzM4NCd9KS5zaWduKClcbnZlcmlmaWVkID0gYXdhaXQgSk9TRS5nZW5lcmFsVmVyaWZ5KGp3cywgc2sucHVibGljS2V5KVxub3IgY29tcGFjdFZlcmlmeSBvciBmbGF0dGVuZWRWZXJpZnlcbm5ldyBUZXh0RGVjb2RlcigpLmRlY29kZSh2ZXJpZmllZC5wYXlsb2FkKVxuXG5layA9IGF3YWl0IEpPU0UuZ2VuZXJhdGVLZXlQYWlyKCdSU0EtT0FFUC0yNTYnLCB7ZXh0cmFjdGFibGU6IHRydWV9KVxuandlID0gYXdhaXQgbmV3IEpPU0UuQ29tcGFjdEVuY3J5cHQobWVzc2FnZSkuc2V0UHJvdGVjdGVkSGVhZGVyKHthbGc6ICdSU0EtT0FFUC0yNTYnLCBlbmM6ICdBMjU2R0NNJyB9KS5lbmNyeXB0KGVrLnB1YmxpY0tleSlcbm9yIEZsYXR0ZW5lZEVuY3J5cHQuIEZvciBzeW1tZXRyaWMgc2VjcmV0LCBzcGVjaWZ5IGFsZzonZGlyJy5cbmRlY3J5cHRlZCA9IGF3YWl0IEpPU0UuY29tcGFjdERlY3J5cHQoandlLCBlay5wcml2YXRlS2V5KVxubmV3IFRleHREZWNvZGVyKCkuZGVjb2RlKGRlY3J5cHRlZC5wbGFpbnRleHQpXG5qd2UgPSBhd2FpdCBuZXcgSk9TRS5HZW5lcmFsRW5jcnlwdChtZXNzYWdlKS5zZXRQcm90ZWN0ZWRIZWFkZXIoe2FsZzogJ1JTQS1PQUVQLTI1NicsIGVuYzogJ0EyNTZHQ00nIH0pLmFkZFJlY2lwaWVudChlay5wdWJsaWNLZXkpLmVuY3J5cHQoKSAvLyB3aXRoIGFkZGl0aW9uYWwgYWRkUmVjaXBlbnQoKSBhcyBuZWVkZWRcbmRlY3J5cHRlZCA9IGF3YWl0IEpPU0UuZ2VuZXJhbERlY3J5cHQoandlLCBlay5wcml2YXRlS2V5KVxuXG5tYXRlcmlhbCA9IG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZSgnc2VjcmV0Jylcbmp3ZSA9IGF3YWl0IG5ldyBKT1NFLkNvbXBhY3RFbmNyeXB0KG1lc3NhZ2UpLnNldFByb3RlY3RlZEhlYWRlcih7YWxnOiAnUEJFUzItSFM1MTIrQTI1NktXJywgZW5jOiAnQTI1NkdDTScgfSkuZW5jcnlwdChtYXRlcmlhbClcbmRlY3J5cHRlZCA9IGF3YWl0IEpPU0UuY29tcGFjdERlY3J5cHQoandlLCBtYXRlcmlhbCwge2tleU1hbmFnZW1lbnRBbGdvcml0aG1zOiBbJ1BCRVMyLUhTNTEyK0EyNTZLVyddLCBjb250ZW50RW5jcnlwdGlvbkFsZ29yaXRobXM6IFsnQTI1NkdDTSddfSlcbmp3ZSA9IGF3YWl0IG5ldyBKT1NFLkdlbmVyYWxFbmNyeXB0KG1lc3NhZ2UpLnNldFByb3RlY3RlZEhlYWRlcih7YWxnOiAnUEJFUzItSFM1MTIrQTI1NktXJywgZW5jOiAnQTI1NkdDTScgfSkuYWRkUmVjaXBpZW50KG1hdGVyaWFsKS5lbmNyeXB0KClcbmp3ZSA9IGF3YWl0IG5ldyBKT1NFLkdlbmVyYWxFbmNyeXB0KG1lc3NhZ2UpLnNldFByb3RlY3RlZEhlYWRlcih7ZW5jOiAnQTI1NkdDTScgfSlcbiAgLmFkZFJlY2lwaWVudChlay5wdWJsaWNLZXkpLnNldFVucHJvdGVjdGVkSGVhZGVyKHtraWQ6ICdmb28nLCBhbGc6ICdSU0EtT0FFUC0yNTYnfSlcbiAgLmFkZFJlY2lwaWVudChtYXRlcmlhbCkuc2V0VW5wcm90ZWN0ZWRIZWFkZXIoe2tpZDogJ3NlY3JldDEnLCBhbGc6ICdQQkVTMi1IUzUxMitBMjU2S1cnfSlcbiAgLmFkZFJlY2lwaWVudChtYXRlcmlhbDIpLnNldFVucHJvdGVjdGVkSGVhZGVyKHtraWQ6ICdzZWNyZXQyJywgYWxnOiAnUEJFUzItSFM1MTIrQTI1NktXJ30pXG4gIC5lbmNyeXB0KClcbmRlY3J5cHRlZCA9IGF3YWl0IEpPU0UuZ2VuZXJhbERlY3J5cHQoandlLCBlay5wcml2YXRlS2V5KVxuZGVjcnlwdGVkID0gYXdhaXQgSk9TRS5nZW5lcmFsRGVjcnlwdChqd2UsIG1hdGVyaWFsLCB7a2V5TWFuYWdlbWVudEFsZ29yaXRobXM6IFsnUEJFUzItSFM1MTIrQTI1NktXJ119KVxuKi9cbiIsImltcG9ydCBLcnlwdG8gZnJvbSBcIi4va3J5cHRvLm1qc1wiO1xuaW1wb3J0ICogYXMgSk9TRSBmcm9tIFwiam9zZVwiO1xuaW1wb3J0IHtzaWduaW5nQWxnb3JpdGhtLCBlbmNyeXB0aW5nQWxnb3JpdGhtLCBzeW1tZXRyaWNBbGdvcml0aG0sIHN5bW1ldHJpY1dyYXAsIHNlY3JldEFsZ29yaXRobX0gZnJvbSBcIi4vYWxnb3JpdGhtcy5tanNcIjtcblxuZnVuY3Rpb24gbWlzbWF0Y2goa2lkLCBlbmNvZGVkS2lkKSB7IC8vIFByb21pc2UgYSByZWplY3Rpb24uXG4gIGxldCBtZXNzYWdlID0gYEtleSAke2tpZH0gZG9lcyBub3QgbWF0Y2ggZW5jb2RlZCAke2VuY29kZWRLaWR9LmA7XG4gIHJldHVybiBQcm9taXNlLnJlamVjdChtZXNzYWdlKTtcbn1cblxuY29uc3QgTXVsdGlLcnlwdG8gPSB7XG4gIC8vIEV4dGVuZCBLcnlwdG8gZm9yIGdlbmVyYWwgKG11bHRpcGxlIGtleSkgSk9TRSBvcGVyYXRpb25zLlxuICAvLyBTZWUgaHR0cHM6Ly9raWxyb3ktY29kZS5naXRodWIuaW8vZGlzdHJpYnV0ZWQtc2VjdXJpdHkvZG9jcy9pbXBsZW1lbnRhdGlvbi5odG1sI2NvbWJpbmluZy1rZXlzXG4gIFxuICAvLyBPdXIgbXVsdGkga2V5cyBhcmUgZGljdGlvbmFyaWVzIG9mIG5hbWUgKG9yIGtpZCkgPT4ga2V5T2JqZWN0LlxuICBpc011bHRpS2V5KGtleSkgeyAvLyBBIFN1YnRsZUNyeXB0byBDcnlwdG9LZXkgaXMgYW4gb2JqZWN0IHdpdGggYSB0eXBlIHByb3BlcnR5LiBPdXIgbXVsdGlrZXlzIGFyZVxuICAgIC8vIG9iamVjdHMgd2l0aCBhIHNwZWNpZmljIHR5cGUgb3Igbm8gdHlwZSBwcm9wZXJ0eSBhdCBhbGwuXG4gICAgcmV0dXJuIChrZXkudHlwZSB8fCAnbXVsdGknKSA9PT0gJ211bHRpJztcbiAgfSxcbiAga2V5VGFncyhrZXkpIHsgLy8gSnVzdCB0aGUga2lkcyB0aGF0IGFyZSBmb3IgYWN0dWFsIGtleXMuIE5vICd0eXBlJy5cbiAgICByZXR1cm4gT2JqZWN0LmtleXMoa2V5KS5maWx0ZXIoa2V5ID0+IGtleSAhPT0gJ3R5cGUnKTtcbiAgfSxcblxuICAvLyBFeHBvcnQvSW1wb3J0XG4gIGFzeW5jIGV4cG9ydEpXSyhrZXkpIHsgLy8gUHJvbWlzZSBhIEpXSyBrZXkgc2V0IGlmIG5lY2Vzc2FyeSwgcmV0YWluaW5nIHRoZSBuYW1lcyBhcyBraWQgcHJvcGVydHkuXG4gICAgaWYgKCF0aGlzLmlzTXVsdGlLZXkoa2V5KSkgcmV0dXJuIHN1cGVyLmV4cG9ydEpXSyhrZXkpO1xuICAgIGxldCBuYW1lcyA9IHRoaXMua2V5VGFncyhrZXkpLFxuICAgICAgICBrZXlzID0gYXdhaXQgUHJvbWlzZS5hbGwobmFtZXMubWFwKGFzeW5jIG5hbWUgPT4ge1xuICAgICAgICAgIGxldCBqd2sgPSBhd2FpdCB0aGlzLmV4cG9ydEpXSyhrZXlbbmFtZV0pO1xuICAgICAgICAgIGp3ay5raWQgPSBuYW1lO1xuICAgICAgICAgIHJldHVybiBqd2s7XG4gICAgICAgIH0pKTtcbiAgICByZXR1cm4ge2tleXN9O1xuICB9LFxuICBhc3luYyBpbXBvcnRKV0soandrKSB7IC8vIFByb21pc2UgYSBzaW5nbGUgXCJrZXlcIiBvYmplY3QuXG4gICAgLy8gUmVzdWx0IHdpbGwgYmUgYSBtdWx0aS1rZXkgaWYgSldLIGlzIGEga2V5IHNldCwgaW4gd2hpY2ggY2FzZSBlYWNoIG11c3QgaW5jbHVkZSBhIGtpZCBwcm9wZXJ0eS5cbiAgICBpZiAoIWp3ay5rZXlzKSByZXR1cm4gc3VwZXIuaW1wb3J0SldLKGp3ayk7XG4gICAgbGV0IGtleSA9IHt9OyAvLyBUT0RPOiBnZXQgdHlwZSBmcm9tIGt0eSBvciBzb21lIHN1Y2g/XG4gICAgYXdhaXQgUHJvbWlzZS5hbGwoandrLmtleXMubWFwKGFzeW5jIGp3ayA9PiBrZXlbandrLmtpZF0gPSBhd2FpdCB0aGlzLmltcG9ydEpXSyhqd2spKSk7XG4gICAgcmV0dXJuIGtleTtcbiAgfSxcblxuICAvLyBFbmNyeXB0L0RlY3J5cHRcbiAgYXN5bmMgZW5jcnlwdChrZXksIG1lc3NhZ2UsIGhlYWRlcnMgPSB7fSkgeyAvLyBQcm9taXNlIGEgSldFLCBpbiBnZW5lcmFsIGZvcm0gaWYgYXBwcm9wcmlhdGUuXG4gICAgaWYgKCF0aGlzLmlzTXVsdGlLZXkoa2V5KSkgcmV0dXJuIHN1cGVyLmVuY3J5cHQoa2V5LCBtZXNzYWdlLCBoZWFkZXJzKTtcbiAgICAvLyBrZXkgbXVzdCBiZSBhIGRpY3Rpb25hcnkgbWFwcGluZyB0YWdzIHRvIGVuY3J5cHRpbmcga2V5cy5cbiAgICBsZXQgYmFzZUhlYWRlciA9IHtlbmM6IHN5bW1ldHJpY0FsZ29yaXRobSwgLi4uaGVhZGVyc30sXG4gICAgICAgIGlucHV0QnVmZmVyID0gdGhpcy5pbnB1dEJ1ZmZlcihtZXNzYWdlLCBiYXNlSGVhZGVyKSxcbiAgICAgICAgandlID0gbmV3IEpPU0UuR2VuZXJhbEVuY3J5cHQoaW5wdXRCdWZmZXIpLnNldFByb3RlY3RlZEhlYWRlcihiYXNlSGVhZGVyKTtcbiAgICBmb3IgKGxldCB0YWcgb2YgdGhpcy5rZXlUYWdzKGtleSkpIHtcbiAgICAgIGxldCB0aGlzS2V5ID0ga2V5W3RhZ10sXG4gICAgICAgICAgaXNTdHJpbmcgPSAnc3RyaW5nJyA9PT0gdHlwZW9mIHRoaXNLZXksXG4gICAgICAgICAgaXNTeW0gPSBpc1N0cmluZyB8fCB0aGlzLmlzU3ltbWV0cmljKHRoaXNLZXkpLFxuICAgICAgICAgIHNlY3JldCA9IGlzU3RyaW5nID8gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHRoaXNLZXkpIDogdGhpcy5rZXlTZWNyZXQodGhpc0tleSksXG4gICAgICAgICAgYWxnID0gaXNTdHJpbmcgPyBzZWNyZXRBbGdvcml0aG0gOiAoaXNTeW0gPyBzeW1tZXRyaWNXcmFwIDogZW5jcnlwdGluZ0FsZ29yaXRobSk7XG4gICAgICAvLyBUaGUga2lkIGFuZCBhbGcgYXJlIHBlci9zdWIta2V5LCBhbmQgc28gY2Fubm90IGJlIHNpZ25lZCBieSBhbGwsIGFuZCBzbyBjYW5ub3QgYmUgcHJvdGVjdGVkIHdpdGhpbiB0aGUgZW5jcnlwdGlvbi5cbiAgICAgIC8vIFRoaXMgaXMgb2ssIGJlY2F1c2UgdGhlIG9ubHkgdGhhdCBjYW4gaGFwcGVuIGFzIGEgcmVzdWx0IG9mIHRhbXBlcmluZyB3aXRoIHRoZXNlIGlzIHRoYXQgdGhlIGRlY3J5cHRpb24gd2lsbCBmYWlsLFxuICAgICAgLy8gd2hpY2ggaXMgdGhlIHNhbWUgcmVzdWx0IGFzIHRhbXBlcmluZyB3aXRoIHRoZSBjaXBoZXJ0ZXh0IG9yIGFueSBvdGhlciBwYXJ0IG9mIHRoZSBKV0UuXG4gICAgICBqd2UuYWRkUmVjaXBpZW50KHNlY3JldCkuc2V0VW5wcm90ZWN0ZWRIZWFkZXIoe2tpZDogdGFnLCBhbGd9KTtcbiAgICB9XG4gICAgbGV0IGVuY3J5cHRlZCA9IGF3YWl0IGp3ZS5lbmNyeXB0KCk7XG4gICAgcmV0dXJuIGVuY3J5cHRlZDtcbiAgfSxcbiAgYXN5bmMgZGVjcnlwdChrZXksIGVuY3J5cHRlZCwgb3B0aW9ucykgeyAvLyBQcm9taXNlIHtwYXlsb2FkLCB0ZXh0LCBqc29ufSwgd2hlcmUgdGV4dCBhbmQganNvbiBhcmUgb25seSBkZWZpbmVkIHdoZW4gYXBwcm9wcmlhdGUuXG4gICAgaWYgKCF0aGlzLmlzTXVsdGlLZXkoa2V5KSkgcmV0dXJuIHN1cGVyLmRlY3J5cHQoa2V5LCBlbmNyeXB0ZWQsIG9wdGlvbnMpO1xuICAgIGxldCBqd2UgPSBlbmNyeXB0ZWQsXG4gICAgICAgIHtyZWNpcGllbnRzfSA9IGp3ZSxcbiAgICAgICAgdW53cmFwcGluZ1Byb21pc2VzID0gcmVjaXBpZW50cy5tYXAoYXN5bmMgKHtoZWFkZXJ9KSA9PiB7XG4gICAgICAgICAgbGV0IHtraWR9ID0gaGVhZGVyLFxuICAgICAgICAgICAgICB1bndyYXBwaW5nS2V5ID0ga2V5W2tpZF0sXG4gICAgICAgICAgICAgIG9wdGlvbnMgPSB7fTtcbiAgICAgICAgICBpZiAoIXVud3JhcHBpbmdLZXkpIHJldHVybiBQcm9taXNlLnJlamVjdCgnbWlzc2luZycpO1xuICAgICAgICAgIGlmICgnc3RyaW5nJyA9PT0gdHlwZW9mIHVud3JhcHBpbmdLZXkpIHsgLy8gVE9ETzogb25seSBzcGVjaWZpZWQgaWYgYWxsb3dlZCBieSBzZWN1cmUgaGVhZGVyP1xuICAgICAgICAgICAgdW53cmFwcGluZ0tleSA9IG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZSh1bndyYXBwaW5nS2V5KTtcbiAgICAgICAgICAgIG9wdGlvbnMua2V5TWFuYWdlbWVudEFsZ29yaXRobXMgPSBbc2VjcmV0QWxnb3JpdGhtXTtcbiAgICAgICAgICB9XG4gICAgICAgICAgbGV0IHJlc3VsdCA9IGF3YWl0IEpPU0UuZ2VuZXJhbERlY3J5cHQoandlLCB0aGlzLmtleVNlY3JldCh1bndyYXBwaW5nS2V5KSwgb3B0aW9ucyksXG4gICAgICAgICAgICAgIGVuY29kZWRLaWQgPSByZXN1bHQudW5wcm90ZWN0ZWRIZWFkZXIua2lkO1xuICAgICAgICAgIGlmIChlbmNvZGVkS2lkICE9PSBraWQpIHJldHVybiBtaXNtYXRjaChraWQsIGVuY29kZWRLaWQpO1xuICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgIH0pO1xuICAgIC8vIERvIHdlIHJlYWxseSB3YW50IHRvIHJldHVybiB1bmRlZmluZWQgaWYgZXZlcnl0aGluZyBmYWlscz8gU2hvdWxkIGp1c3QgYWxsb3cgdGhlIHJlamVjdGlvbiB0byBwcm9wYWdhdGU/XG4gICAgcmV0dXJuIGF3YWl0IFByb21pc2UuYW55KHVud3JhcHBpbmdQcm9taXNlcykudGhlbihcbiAgICAgIHJlc3VsdCA9PiB7XG4gICAgICAgIHRoaXMucmVjb3ZlckRhdGFGcm9tQ29udGVudFR5cGUocmVzdWx0LCBvcHRpb25zKTtcbiAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgIH0sXG4gICAgICAoKSA9PiB1bmRlZmluZWQpO1xuICB9LFxuXG4gIC8vIFNpZ24vVmVyaWZ5XG4gIGFzeW5jIHNpZ24oa2V5LCBtZXNzYWdlLCBoZWFkZXIgPSB7fSkgeyAvLyBQcm9taXNlIEpXUywgaW4gZ2VuZXJhbCBmb3JtIHdpdGgga2lkIGhlYWRlcnMgaWYgbmVjZXNzYXJ5LlxuICAgIGlmICghdGhpcy5pc011bHRpS2V5KGtleSkpIHJldHVybiBzdXBlci5zaWduKGtleSwgbWVzc2FnZSwgaGVhZGVyKTtcbiAgICBsZXQgaW5wdXRCdWZmZXIgPSB0aGlzLmlucHV0QnVmZmVyKG1lc3NhZ2UsIGhlYWRlciksXG4gICAgICAgIGp3cyA9IG5ldyBKT1NFLkdlbmVyYWxTaWduKGlucHV0QnVmZmVyKTtcbiAgICBmb3IgKGxldCB0YWcgb2YgdGhpcy5rZXlUYWdzKGtleSkpIHtcbiAgICAgIGxldCB0aGlzS2V5ID0ga2V5W3RhZ10sXG4gICAgICAgICAgdGhpc0hlYWRlciA9IHtraWQ6IHRhZywgYWxnOiBzaWduaW5nQWxnb3JpdGhtLCAuLi5oZWFkZXJ9O1xuICAgICAgandzLmFkZFNpZ25hdHVyZSh0aGlzS2V5KS5zZXRQcm90ZWN0ZWRIZWFkZXIodGhpc0hlYWRlcik7XG4gICAgfVxuICAgIHJldHVybiBqd3Muc2lnbigpO1xuICB9LFxuICB2ZXJpZnlTdWJTaWduYXR1cmUoandzLCBzaWduYXR1cmVFbGVtZW50LCBtdWx0aUtleSwga2lkcykge1xuICAgIC8vIFZlcmlmeSBhIHNpbmdsZSBlbGVtZW50IG9mIGp3cy5zaWduYXR1cmUgdXNpbmcgbXVsdGlLZXkuXG4gICAgLy8gQWx3YXlzIHByb21pc2VzIHtwcm90ZWN0ZWRIZWFkZXIsIHVucHJvdGVjdGVkSGVhZGVyLCBraWR9LCBldmVuIGlmIHZlcmlmaWNhdGlvbiBmYWlscyxcbiAgICAvLyB3aGVyZSBraWQgaXMgdGhlIHByb3BlcnR5IG5hbWUgd2l0aGluIG11bHRpS2V5IHRoYXQgbWF0Y2hlZCAoZWl0aGVyIGJ5IGJlaW5nIHNwZWNpZmllZCBpbiBhIGhlYWRlclxuICAgIC8vIG9yIGJ5IHN1Y2Nlc3NmdWwgdmVyaWZpY2F0aW9uKS4gQWxzbyBpbmNsdWRlcyB0aGUgZGVjb2RlZCBwYXlsb2FkIElGRiB0aGVyZSBpcyBhIG1hdGNoLlxuICAgIGxldCBwcm90ZWN0ZWRIZWFkZXIgPSBzaWduYXR1cmVFbGVtZW50LnByb3RlY3RlZEhlYWRlciA/PyB0aGlzLmRlY29kZVByb3RlY3RlZEhlYWRlcihzaWduYXR1cmVFbGVtZW50KSxcbiAgICAgICAgdW5wcm90ZWN0ZWRIZWFkZXIgPSBzaWduYXR1cmVFbGVtZW50LnVucHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICBraWQgPSBwcm90ZWN0ZWRIZWFkZXI/LmtpZCB8fCB1bnByb3RlY3RlZEhlYWRlcj8ua2lkLFxuICAgICAgICBzaW5nbGVKV1MgPSB7Li4uandzLCBzaWduYXR1cmVzOiBbc2lnbmF0dXJlRWxlbWVudF19LFxuICAgICAgICBmYWlsdXJlUmVzdWx0ID0ge3Byb3RlY3RlZEhlYWRlciwgdW5wcm90ZWN0ZWRIZWFkZXIsIGtpZH0sXG4gICAgICAgIGtpZHNUb1RyeSA9IGtpZCA/IFtraWRdIDoga2lkcztcbiAgICBsZXQgcHJvbWlzZSA9IFByb21pc2UuYW55KGtpZHNUb1RyeS5tYXAoYXN5bmMga2lkID0+IEpPU0UuZ2VuZXJhbFZlcmlmeShzaW5nbGVKV1MsIG11bHRpS2V5W2tpZF0pLnRoZW4ocmVzdWx0ID0+IHtyZXR1cm4ge2tpZCwgLi4ucmVzdWx0fTt9KSkpO1xuICAgIHJldHVybiBwcm9taXNlLmNhdGNoKCgpID0+IGZhaWx1cmVSZXN1bHQpO1xuICB9LFxuICBhc3luYyB2ZXJpZnkoa2V5LCBzaWduYXR1cmUsIG9wdGlvbnMgPSB7fSkgeyAvLyBQcm9taXNlIHtwYXlsb2FkLCB0ZXh0LCBqc29ufSwgd2hlcmUgdGV4dCBhbmQganNvbiBhcmUgb25seSBkZWZpbmVkIHdoZW4gYXBwcm9wcmlhdGUuXG4gICAgLy8gQWRkaXRpb25hbGx5LCBpZiBrZXkgaXMgYSBtdWx0aUtleSBBTkQgc2lnbmF0dXJlIGlzIGEgZ2VuZXJhbCBmb3JtIEpXUywgdGhlbiBhbnN3ZXIgaW5jbHVkZXMgYSBzaWduZXJzIHByb3BlcnR5XG4gICAgLy8gYnkgd2hpY2ggY2FsbGVyIGNhbiBkZXRlcm1pbmUgaWYgaXQgd2hhdCB0aGV5IGV4cGVjdC4gVGhlIHBheWxvYWQgb2YgZWFjaCBzaWduZXJzIGVsZW1lbnQgaXMgZGVmaW5lZCBvbmx5IHRoYXRcbiAgICAvLyBzaWduZXIgd2FzIG1hdGNoZWQgYnkgc29tZXRoaW5nIGluIGtleS5cbiAgICBcbiAgICBpZiAoIXRoaXMuaXNNdWx0aUtleShrZXkpKSByZXR1cm4gc3VwZXIudmVyaWZ5KGtleSwgc2lnbmF0dXJlLCBvcHRpb25zKTtcbiAgICBpZiAoIXNpZ25hdHVyZS5zaWduYXR1cmVzKSByZXR1cm47XG5cbiAgICAvLyBDb21wYXJpc29uIHRvIHBhbnZhIEpPU0UuZ2VuZXJhbFZlcmlmeS5cbiAgICAvLyBKT1NFIHRha2VzIGEgandzIGFuZCBPTkUga2V5IGFuZCBhbnN3ZXJzIHtwYXlsb2FkLCBwcm90ZWN0ZWRIZWFkZXIsIHVucHJvdGVjdGVkSGVhZGVyfSBtYXRjaGluZyB0aGUgb25lXG4gICAgLy8gandzLnNpZ25hdHVyZSBlbGVtZW50IHRoYXQgd2FzIHZlcmlmaWVkLCBvdGhlcmlzZSBhbiBlcm9yLiAoSXQgdHJpZXMgZWFjaCBvZiB0aGUgZWxlbWVudHMgb2YgdGhlIGp3cy5zaWduYXR1cmVzLilcbiAgICAvLyBJdCBpcyBub3QgZ2VuZXJhbGx5IHBvc3NpYmxlIHRvIGtub3cgV0hJQ0ggb25lIG9mIHRoZSBqd3Muc2lnbmF0dXJlcyB3YXMgbWF0Y2hlZC5cbiAgICAvLyAoSXQgTUFZIGJlIHBvc3NpYmxlIGlmIHRoZXJlIGFyZSB1bmlxdWUga2lkIGVsZW1lbnRzLCBidXQgdGhhdCdzIGFwcGxpY2F0aW9uLWRlcGVuZGVudC4pXG4gICAgLy9cbiAgICAvLyBNdWx0aUtyeXB0byB0YWtlcyBhIGRpY3Rpb25hcnkgdGhhdCBjb250YWlucyBuYW1lZCBrZXlzIGFuZCByZWNvZ25pemVkSGVhZGVyIHByb3BlcnRpZXMsIGFuZCBpdCByZXR1cm5zXG4gICAgLy8gYSByZXN1bHQgdGhhdCBoYXMgYSBzaWduZXJzIGFycmF5IHRoYXQgaGFzIGFuIGVsZW1lbnQgY29ycmVzcG9uZGluZyB0byBlYWNoIG9yaWdpbmFsIHNpZ25hdHVyZSBpZiBhbnlcbiAgICAvLyBhcmUgbWF0Y2hlZCBieSB0aGUgbXVsdGlrZXkuIChJZiBub25lIG1hdGNoLCB3ZSByZXR1cm4gdW5kZWZpbmVkLlxuICAgIC8vIEVhY2ggZWxlbWVudCBjb250YWlucyB0aGUga2lkLCBwcm90ZWN0ZWRIZWFkZXIsIHBvc3NpYmx5IHVucHJvdGVjdGVkSGVhZGVyLCBhbmQgcG9zc2libHkgcGF5bG9hZCAoaS5lLiBpZiBzdWNjZXNzZnVsKS5cbiAgICAvL1xuICAgIC8vIEFkZGl0aW9uYWxseSBpZiBhIHJlc3VsdCBpcyBwcm9kdWNlZCwgdGhlIG92ZXJhbGwgcHJvdGVjdGVkSGVhZGVyIGFuZCB1bnByb3RlY3RlZEhlYWRlciBjb250YWlucyBvbmx5IHZhbHVlc1xuICAgIC8vIHRoYXQgd2VyZSBjb21tb24gdG8gZWFjaCBvZiB0aGUgdmVyaWZpZWQgc2lnbmF0dXJlIGVsZW1lbnRzLlxuICAgIFxuICAgIGxldCBqd3MgPSBzaWduYXR1cmUsXG4gICAgICAgIGtpZHMgPSB0aGlzLmtleVRhZ3Moa2V5KSxcbiAgICAgICAgc2lnbmVycyA9IGF3YWl0IFByb21pc2UuYWxsKGp3cy5zaWduYXR1cmVzLm1hcChzaWduYXR1cmUgPT4gdGhpcy52ZXJpZnlTdWJTaWduYXR1cmUoandzLCBzaWduYXR1cmUsIGtleSwga2lkcykpKTtcbiAgICBpZiAoIXNpZ25lcnMuZmluZChzaWduZXIgPT4gc2lnbmVyLnBheWxvYWQpKSByZXR1cm4gdW5kZWZpbmVkO1xuICAgIC8vIE5vdyBjYW5vbmljYWxpemUgdGhlIHNpZ25lcnMgYW5kIGJ1aWxkIHVwIGEgcmVzdWx0LlxuICAgIGxldCBbZmlyc3QsIC4uLnJlc3RdID0gc2lnbmVycyxcbiAgICAgICAgcmVzdWx0ID0ge3Byb3RlY3RlZEhlYWRlcjoge30sIHVucHJvdGVjdGVkSGVhZGVyOiB7fSwgc2lnbmVyc30sXG4gICAgICAgIC8vIEZvciBhIGhlYWRlciB2YWx1ZSB0byBiZSBjb21tb24gdG8gdmVyaWZpZWQgcmVzdWx0cywgaXQgbXVzdCBiZSBpbiB0aGUgZmlyc3QgcmVzdWx0LlxuICAgICAgICBnZXRVbmlxdWUgPSBjYXRlZ29yeU5hbWUgPT4ge1xuICAgICAgICAgIGxldCBmaXJzdEhlYWRlciA9IGZpcnN0W2NhdGVnb3J5TmFtZV0sXG4gICAgICAgICAgICAgIGFjY3VtdWxhdG9ySGVhZGVyID0gcmVzdWx0W2NhdGVnb3J5TmFtZV07XG4gICAgICAgICAgZm9yIChsZXQgbGFiZWwgaW4gZmlyc3RIZWFkZXIpIHtcbiAgICAgICAgICAgIGxldCB2YWx1ZSA9IGZpcnN0SGVhZGVyW2xhYmVsXTtcbiAgICAgICAgICAgIGlmIChyZXN0LnNvbWUoc2lnbmVyUmVzdWx0ID0+IHNpZ25lclJlc3VsdFtjYXRlZ29yeU5hbWVdW2xhYmVsXSAhPT0gdmFsdWUpKSBjb250aW51ZTtcbiAgICAgICAgICAgIGFjY3VtdWxhdG9ySGVhZGVyW2xhYmVsXSA9IHZhbHVlO1xuICAgICAgICAgIH1cbiAgICAgICAgfTtcbiAgICBnZXRVbmlxdWUoJ3Byb3RlY3RlZEhlYWRlcicpO1xuICAgIGdldFVuaXF1ZSgncHJvdGVjdGVkSGVhZGVyJyk7XG4gICAgLy8gSWYgYW55dGhpbmcgdmVyaWZpZWQsIHRoZW4gc2V0IHBheWxvYWQgYW5kIGFsbG93IHRleHQvanNvbiB0byBiZSBwcm9kdWNlZC5cbiAgICAvLyBDYWxsZXJzIGNhbiBjaGVjayBzaWduZXJzW25dLnBheWxvYWQgdG8gZGV0ZXJtaW5lIGlmIHRoZSByZXN1bHQgaXMgd2hhdCB0aGV5IHdhbnQuXG4gICAgcmVzdWx0LnBheWxvYWQgPSBzaWduZXJzLmZpbmQoc2lnbmVyID0+IHNpZ25lci5wYXlsb2FkKS5wYXlsb2FkO1xuICAgIHJldHVybiB0aGlzLnJlY292ZXJEYXRhRnJvbUNvbnRlbnRUeXBlKHJlc3VsdCwgb3B0aW9ucyk7XG4gIH1cbn07XG5cbk9iamVjdC5zZXRQcm90b3R5cGVPZihNdWx0aUtyeXB0bywgS3J5cHRvKTsgLy8gSW5oZXJpdCBmcm9tIEtyeXB0byBzbyB0aGF0IHN1cGVyLm11bWJsZSgpIHdvcmtzLlxuZXhwb3J0IGRlZmF1bHQgTXVsdGlLcnlwdG87XG4iLCJjb25zdCBkZWZhdWx0TWF4U2l6ZSA9IDUwMDtcbmV4cG9ydCBjbGFzcyBDYWNoZSBleHRlbmRzIE1hcCB7XG4gIGNvbnN0cnVjdG9yKG1heFNpemUsIGRlZmF1bHRUaW1lVG9MaXZlID0gMCkge1xuICAgIHN1cGVyKCk7XG4gICAgdGhpcy5tYXhTaXplID0gbWF4U2l6ZTtcbiAgICB0aGlzLmRlZmF1bHRUaW1lVG9MaXZlID0gZGVmYXVsdFRpbWVUb0xpdmU7XG4gICAgdGhpcy5fbmV4dFdyaXRlSW5kZXggPSAwO1xuICAgIHRoaXMuX2tleUxpc3QgPSBBcnJheShtYXhTaXplKTtcbiAgICB0aGlzLl90aW1lcnMgPSBuZXcgTWFwKCk7XG4gIH1cbiAgc2V0KGtleSwgdmFsdWUsIHR0bCA9IHRoaXMuZGVmYXVsdFRpbWVUb0xpdmUpIHtcbiAgICBsZXQgbmV4dFdyaXRlSW5kZXggPSB0aGlzLl9uZXh0V3JpdGVJbmRleDtcblxuICAgIC8vIGxlYXN0LXJlY2VudGx5LVNFVCBib29ra2VlcGluZzpcbiAgICAvLyAgIGtleUxpc3QgaXMgYW4gYXJyYXkgb2Yga2V5cyB0aGF0IGhhdmUgYmVlbiBzZXQuXG4gICAgLy8gICBuZXh0V3JpdGVJbmRleCBpcyB3aGVyZSB0aGUgbmV4dCBrZXkgaXMgdG8gYmUgd3JpdHRlbiBpbiB0aGF0IGFycmF5LCB3cmFwcGluZyBhcm91bmQuXG4gICAgLy8gQXMgaXQgd3JhcHMsIHRoZSBrZXkgYXQga2V5TGlzdFtuZXh0V3JpdGVJbmRleF0gaXMgdGhlIG9sZGVzdCB0aGF0IGhhcyBiZWVuIHNldC5cbiAgICAvLyBIb3dldmVyLCB0aGF0IGtleSBhbmQgb3RoZXJzIG1heSBoYXZlIGFscmVhZHkgYmVlbiBkZWxldGVkLlxuICAgIC8vIFRoaXMgaW1wbGVtZW50YXRpb24gbWF4aW1pemVzIHJlYWQgc3BlZWQgZmlyc3QsIHdyaXRlIHNwZWVkIHNlY29uZCwgYW5kIHNpbXBsaWNpdHkvY29ycmVjdG5lc3MgdGhpcmQuXG4gICAgLy8gSXQgZG9lcyBOT1QgdHJ5IHRvIGtlZXAgdGhlIG1heGltdW0gbnVtYmVyIG9mIHZhbHVlcyBwcmVzZW50LiBTbyBhcyBrZXlzIGdldCBtYW51YWxseSBkZWxldGVkLCB0aGUga2V5TGlzdFxuICAgIC8vIGlzIG5vdCBhZGp1c3RlZCwgYW5kIHNvIHRoZXJlIHdpbGwga2V5cyBwcmVzZW50IGluIHRoZSBhcnJheSB0aGF0IGRvIG5vdCBoYXZlIGVudHJpZXMgaW4gdGhlIHZhbHVlc1xuICAgIC8vIG1hcC4gVGhlIGFycmF5IGlzIG1heFNpemUgbG9uZywgYnV0IHRoZSBtZWFuaW5nZnVsIGVudHJpZXMgaW4gaXQgbWF5IGJlIGxlc3MuXG4gICAgdGhpcy5kZWxldGUodGhpcy5fa2V5TGlzdFtuZXh0V3JpdGVJbmRleF0pOyAvLyBSZWdhcmRsZXNzIG9mIGN1cnJlbnQgc2l6ZS5cbiAgICB0aGlzLl9rZXlMaXN0W25leHRXcml0ZUluZGV4XSA9IGtleTtcbiAgICB0aGlzLl9uZXh0V3JpdGVJbmRleCA9IChuZXh0V3JpdGVJbmRleCArIDEpICUgdGhpcy5tYXhTaXplO1xuXG4gICAgaWYgKHRoaXMuX3RpbWVycy5oYXMoa2V5KSkgY2xlYXJUaW1lb3V0KHRoaXMuX3RpbWVycy5nZXQoa2V5KSk7XG4gICAgc3VwZXIuc2V0KGtleSwgdmFsdWUpO1xuXG4gICAgaWYgKCF0dGwpIHJldHVybjsgIC8vIFNldCB0aW1lb3V0IGlmIHJlcXVpcmVkLlxuICAgIHRoaXMuX3RpbWVycy5zZXQoa2V5LCBzZXRUaW1lb3V0KCgpID0+IHRoaXMuZGVsZXRlKGtleSksIHR0bCkpO1xuICB9XG4gIGRlbGV0ZShrZXkpIHtcbiAgICBpZiAodGhpcy5fdGltZXJzLmhhcyhrZXkpKSBjbGVhclRpbWVvdXQodGhpcy5fdGltZXJzLmdldChrZXkpKTtcbiAgICB0aGlzLl90aW1lcnMuZGVsZXRlKGtleSk7XG4gICAgcmV0dXJuIHN1cGVyLmRlbGV0ZShrZXkpO1xuICB9XG4gIGNsZWFyKG5ld01heFNpemUgPSB0aGlzLm1heFNpemUpIHtcbiAgICB0aGlzLm1heFNpemUgPSBuZXdNYXhTaXplO1xuICAgIHRoaXMuX2tleUxpc3QgPSBBcnJheShuZXdNYXhTaXplKTtcbiAgICB0aGlzLl9uZXh0V3JpdGVJbmRleCA9IDA7XG4gICAgc3VwZXIuY2xlYXIoKTtcbiAgICBmb3IgKGNvbnN0IHRpbWVyIG9mIHRoaXMuX3RpbWVycy52YWx1ZXMoKSkgY2xlYXJUaW1lb3V0KHRpbWVyKVxuICAgIHRoaXMuX3RpbWVycy5jbGVhcigpO1xuICB9XG59O1xuZXhwb3J0IGRlZmF1bHQgQ2FjaGU7XG4iLCJjbGFzcyBDYWNoZSBleHRlbmRzIE1hcHtjb25zdHJ1Y3RvcihlLHQ9MCl7c3VwZXIoKSx0aGlzLm1heFNpemU9ZSx0aGlzLmRlZmF1bHRUaW1lVG9MaXZlPXQsdGhpcy5fbmV4dFdyaXRlSW5kZXg9MCx0aGlzLl9rZXlMaXN0PUFycmF5KGUpLHRoaXMuX3RpbWVycz1uZXcgTWFwfXNldChlLHQscz10aGlzLmRlZmF1bHRUaW1lVG9MaXZlKXtsZXQgaT10aGlzLl9uZXh0V3JpdGVJbmRleDt0aGlzLmRlbGV0ZSh0aGlzLl9rZXlMaXN0W2ldKSx0aGlzLl9rZXlMaXN0W2ldPWUsdGhpcy5fbmV4dFdyaXRlSW5kZXg9KGkrMSkldGhpcy5tYXhTaXplLHRoaXMuX3RpbWVycy5oYXMoZSkmJmNsZWFyVGltZW91dCh0aGlzLl90aW1lcnMuZ2V0KGUpKSxzdXBlci5zZXQoZSx0KSxzJiZ0aGlzLl90aW1lcnMuc2V0KGUsc2V0VGltZW91dCgoKCk9PnRoaXMuZGVsZXRlKGUpKSxzKSl9ZGVsZXRlKGUpe3JldHVybiB0aGlzLl90aW1lcnMuaGFzKGUpJiZjbGVhclRpbWVvdXQodGhpcy5fdGltZXJzLmdldChlKSksdGhpcy5fdGltZXJzLmRlbGV0ZShlKSxzdXBlci5kZWxldGUoZSl9Y2xlYXIoZT10aGlzLm1heFNpemUpe3RoaXMubWF4U2l6ZT1lLHRoaXMuX2tleUxpc3Q9QXJyYXkoZSksdGhpcy5fbmV4dFdyaXRlSW5kZXg9MCxzdXBlci5jbGVhcigpO2Zvcihjb25zdCBlIG9mIHRoaXMuX3RpbWVycy52YWx1ZXMoKSljbGVhclRpbWVvdXQoZSk7dGhpcy5fdGltZXJzLmNsZWFyKCl9fWNsYXNzIFN0b3JhZ2VCYXNle2NvbnN0cnVjdG9yKHtuYW1lOmUsYmFzZU5hbWU6dD1cIlN0b3JhZ2VcIixtYXhTZXJpYWxpemVyU2l6ZTpzPTFlMyxkZWJ1ZzppPSExfSl7Y29uc3QgYT1gJHt0fS8ke2V9YCxyPW5ldyBDYWNoZShzKTtPYmplY3QuYXNzaWduKHRoaXMse25hbWU6ZSxiYXNlTmFtZTp0LGZ1bGxOYW1lOmEsZGVidWc6aSxzZXJpYWxpemVyOnJ9KX1hc3luYyBsaXN0KCl7cmV0dXJuIHRoaXMuc2VyaWFsaXplKFwiXCIsKChlLHQpPT50aGlzLmxpc3RJbnRlcm5hbCh0LGUpKSl9YXN5bmMgZ2V0KGUpe3JldHVybiB0aGlzLnNlcmlhbGl6ZShlLCgoZSx0KT0+dGhpcy5nZXRJbnRlcm5hbCh0LGUpKSl9YXN5bmMgZGVsZXRlKGUpe3JldHVybiB0aGlzLnNlcmlhbGl6ZShlLCgoZSx0KT0+dGhpcy5kZWxldGVJbnRlcm5hbCh0LGUpKSl9YXN5bmMgcHV0KGUsdCl7cmV0dXJuIHRoaXMuc2VyaWFsaXplKGUsKChlLHMpPT50aGlzLnB1dEludGVybmFsKHMsdCxlKSkpfWxvZyguLi5lKXt0aGlzLmRlYnVnJiZjb25zb2xlLmxvZyh0aGlzLm5hbWUsLi4uZSl9YXN5bmMgc2VyaWFsaXplKGUsdCl7Y29uc3R7c2VyaWFsaXplcjpzLHJlYWR5Oml9PXRoaXM7bGV0IGE9cy5nZXQoZSl8fGk7cmV0dXJuIGE9YS50aGVuKChhc3luYygpPT50KGF3YWl0IHRoaXMucmVhZHksdGhpcy5wYXRoKGUpKSkpLHMuc2V0KGUsYSksYXdhaXQgYX19Y29uc3R7UmVzcG9uc2U6ZSxVUkw6dH09Z2xvYmFsVGhpcztjbGFzcyBTdG9yYWdlQ2FjaGUgZXh0ZW5kcyBTdG9yYWdlQmFzZXtjb25zdHJ1Y3RvciguLi5lKXtzdXBlciguLi5lKSx0aGlzLnN0cmlwcGVyPW5ldyBSZWdFeHAoYF4vJHt0aGlzLmZ1bGxOYW1lfS9gKSx0aGlzLnJlYWR5PWNhY2hlcy5vcGVuKHRoaXMuZnVsbE5hbWUpfWFzeW5jIGxpc3RJbnRlcm5hbChlLHQpe3JldHVybihhd2FpdCB0LmtleXMoKXx8W10pLm1hcCgoZT0+dGhpcy50YWcoZS51cmwpKSl9YXN5bmMgZ2V0SW50ZXJuYWwoZSx0KXtjb25zdCBzPWF3YWl0IHQubWF0Y2goZSk7cmV0dXJuIHM/Lmpzb24oKX1kZWxldGVJbnRlcm5hbChlLHQpe3JldHVybiB0LmRlbGV0ZShlKX1wdXRJbnRlcm5hbCh0LHMsaSl7cmV0dXJuIGkucHV0KHQsZS5qc29uKHMpKX1wYXRoKGUpe3JldHVybmAvJHt0aGlzLmZ1bGxOYW1lfS8ke2V9YH10YWcoZSl7cmV0dXJuIG5ldyB0KGUpLnBhdGhuYW1lLnJlcGxhY2UodGhpcy5zdHJpcHBlcixcIlwiKX1kZXN0cm95KCl7cmV0dXJuIGNhY2hlcy5kZWxldGUodGhpcy5mdWxsTmFtZSl9fWV4cG9ydHtTdG9yYWdlQ2FjaGUgYXMgU3RvcmFnZUxvY2FsLFN0b3JhZ2VDYWNoZSBhcyBkZWZhdWx0fTtcbiIsInZhciBwcm9tcHRlciA9IHByb21wdFN0cmluZyA9PiBwcm9tcHRTdHJpbmc7XG5pZiAodHlwZW9mKHdpbmRvdykgIT09ICd1bmRlZmluZWQnKSB7XG4gIHByb21wdGVyID0gd2luZG93LnByb21wdDtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGdldFVzZXJEZXZpY2VTZWNyZXQodGFnLCBwcm9tcHRTdHJpbmcpIHtcbiAgcmV0dXJuIHByb21wdFN0cmluZyA/ICh0YWcgKyBwcm9tcHRlcihwcm9tcHRTdHJpbmcpKSA6IHRhZztcbn1cbiIsImNvbnN0IG9yaWdpbiA9IG5ldyBVUkwoaW1wb3J0Lm1ldGEudXJsKS5vcmlnaW47XG5leHBvcnQgZGVmYXVsdCBvcmlnaW47XG4iLCJleHBvcnQgZnVuY3Rpb24gdGFnUGF0aChjb2xsZWN0aW9uTmFtZSwgdGFnLCBleHRlbnNpb24gPSAnanNvbicpIHsgLy8gUGF0aG5hbWUgdG8gdGFnIHJlc291cmNlLlxuICAvLyBVc2VkIGluIFN0b3JhZ2UgVVJJLiBCb3R0bGVuZWNrZWQgaGVyZSB0byBwcm92aWRlIGNvbnNpc3RlbnQgYWx0ZXJuYXRlIGltcGxlbWVudGF0aW9ucy5cbiAgLy8gUGF0aCBpcyAuanNvbiBzbyB0aGF0IHN0YXRpYy1maWxlIHdlYiBzZXJ2ZXJzIHdpbGwgc3VwcGx5IGEganNvbiBtaW1lIHR5cGUuXG4gIC8vXG4gIC8vIE5PVEU6IGNoYW5nZXMgaGVyZSBtdXN0IGJlIG1hdGNoZWQgYnkgdGhlIFBVVCByb3V0ZSBzcGVjaWZpZWQgaW4gc2lnbmVkLWNsb3VkLXNlcnZlci9zdG9yYWdlLm1qcyBhbmQgdGFnTmFtZS5tanNcbiAgaWYgKCF0YWcpIHJldHVybiBjb2xsZWN0aW9uTmFtZTtcbiAgcmV0dXJuIGAke2NvbGxlY3Rpb25OYW1lfS8ke3RhZ30uJHtleHRlbnNpb259YDtcbn1cbiIsImltcG9ydCBvcmlnaW4gZnJvbSAnI29yaWdpbic7IC8vIFdoZW4gcnVubmluZyBpbiBhIGJyb3dzZXIsIGxvY2F0aW9uLm9yaWdpbiB3aWxsIGJlIGRlZmluZWQuIEhlcmUgd2UgYWxsb3cgZm9yIE5vZGVKUy5cbmltcG9ydCB7dGFnUGF0aH0gZnJvbSAnLi90YWdQYXRoLm1qcyc7XG5cbmFzeW5jIGZ1bmN0aW9uIHJlc3BvbnNlSGFuZGxlcihyZXNwb25zZSkge1xuICAvLyBSZWplY3QgaWYgc2VydmVyIGRvZXMsIGVsc2UgcmVzcG9uc2UudGV4dCgpLlxuICBpZiAocmVzcG9uc2Uuc3RhdHVzID09PSA0MDQpIHJldHVybiAnJztcbiAgaWYgKCFyZXNwb25zZS5vaykgcmV0dXJuIFByb21pc2UucmVqZWN0KHJlc3BvbnNlLnN0YXR1c1RleHQpO1xuICBsZXQgdGV4dCA9IGF3YWl0IHJlc3BvbnNlLnRleHQoKTtcbiAgaWYgKCF0ZXh0KSByZXR1cm4gdGV4dDsgLy8gUmVzdWx0IG9mIHN0b3JlIGNhbiBiZSBlbXB0eS5cbiAgcmV0dXJuIEpTT04ucGFyc2UodGV4dCk7XG59XG5cbmNvbnN0IFN0b3JhZ2UgPSB7XG4gIGdldCBvcmlnaW4oKSB7IHJldHVybiBvcmlnaW47IH0sXG4gIHRhZ1BhdGgsXG4gIHVyaShjb2xsZWN0aW9uTmFtZSwgdGFnKSB7XG4gICAgLy8gUGF0aG5hbWUgZXhwZWN0ZWQgYnkgb3VyIHNpZ25lZC1jbG91ZC1zZXJ2ZXIuXG4gICAgcmV0dXJuIGAke29yaWdpbn0vU3RvcmFnZS8ke3RoaXMudGFnUGF0aChjb2xsZWN0aW9uTmFtZSwgdGFnKX1gO1xuICB9LFxuICBzdG9yZShjb2xsZWN0aW9uTmFtZSwgdGFnLCBzaWduYXR1cmUsIG9wdGlvbnMgPSB7fSkge1xuICAgIC8vIFN0b3JlIHRoZSBzaWduZWQgY29udGVudCBvbiB0aGUgc2lnbmVkLWNsb3VkLXNlcnZlciwgcmVqZWN0aW5nIGlmXG4gICAgLy8gdGhlIHNlcnZlciBpcyB1bmFibGUgdG8gdmVyaWZ5IHRoZSBzaWduYXR1cmUgZm9sbG93aW5nIHRoZSBydWxlcyBvZlxuICAgIC8vIGh0dHBzOi8va2lscm95LWNvZGUuZ2l0aHViLmlvL2Rpc3RyaWJ1dGVkLXNlY3VyaXR5LyNzdG9yaW5nLWtleXMtdXNpbmctdGhlLWNsb3VkLXN0b3JhZ2UtYXBpXG4gICAgcmV0dXJuIGZldGNoKHRoaXMudXJpKGNvbGxlY3Rpb25OYW1lLCB0YWcpLCB7XG4gICAgICBtZXRob2Q6ICdQVVQnLFxuICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoc2lnbmF0dXJlKSxcbiAgICAgIGhlYWRlcnM6IHsnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nLCAuLi4ob3B0aW9ucy5oZWFkZXJzIHx8IHt9KX1cbiAgICB9KS50aGVuKHJlc3BvbnNlSGFuZGxlcik7XG4gIH0sXG4gIHJldHJpZXZlKGNvbGxlY3Rpb25OYW1lLCB0YWcsIG9wdGlvbnMgPSB7fSkge1xuICAgIC8vIFdlIGRvIG5vdCB2ZXJpZnkgYW5kIGdldCB0aGUgb3JpZ2luYWwgZGF0YSBvdXQgaGVyZSwgYmVjYXVzZSB0aGUgY2FsbGVyIGhhc1xuICAgIC8vIHRoZSByaWdodCB0byBkbyBzbyB3aXRob3V0IHRydXN0aW5nIHVzLlxuICAgIHJldHVybiBmZXRjaCh0aGlzLnVyaShjb2xsZWN0aW9uTmFtZSwgdGFnKSwge1xuICAgICAgY2FjaGU6ICdkZWZhdWx0JyxcbiAgICAgIGhlYWRlcnM6IHsnQWNjZXB0JzogJ2FwcGxpY2F0aW9uL2pzb24nLCAuLi4ob3B0aW9ucy5oZWFkZXJzIHx8IHt9KX1cbiAgICB9KS50aGVuKHJlc3BvbnNlSGFuZGxlcik7XG4gIH1cbn07XG5leHBvcnQgZGVmYXVsdCBTdG9yYWdlO1xuIiwiaW1wb3J0IENhY2hlIGZyb20gJ0BraTFyMHkvY2FjaGUnO1xuaW1wb3J0IFN0b3JhZ2VMb2NhbCBmcm9tICdAa2kxcjB5L3N0b3JhZ2UnO1xuaW1wb3J0IHtoYXNoQnVmZmVyLCBlbmNvZGVCYXNlNjR1cmx9IGZyb20gJy4vdXRpbGl0aWVzLm1qcyc7XG5pbXBvcnQgTXVsdGlLcnlwdG8gZnJvbSAnLi9tdWx0aUtyeXB0by5tanMnO1xuaW1wb3J0IHtnZXRVc2VyRGV2aWNlU2VjcmV0fSBmcm9tICcuL3NlY3JldC5tanMnO1xuaW1wb3J0IFN0b3JhZ2UgZnJvbSAnLi9zdG9yYWdlLm1qcyc7XG5cbmZ1bmN0aW9uIGVycm9yKHRlbXBsYXRlRnVuY3Rpb24sIHRhZywgY2F1c2UgPSB1bmRlZmluZWQpIHtcbiAgLy8gRm9ybWF0cyB0YWcgKGUuZy4sIHNob3J0ZW5zIGl0KSBhbmQgZ2l2ZXMgaXQgdG8gdGVtcGxhdGVGdW5jdGlvbih0YWcpIHRvIGdldFxuICAvLyBhIHN1aXRhYmxlIGVycm9yIG1lc3NhZ2UuIEFuc3dlcnMgYSByZWplY3RlZCBwcm9taXNlIHdpdGggdGhhdCBFcnJvci5cbiAgbGV0IHNob3J0ZW5lZFRhZyA9IHRhZyA/IHRhZy5zbGljZSgwLCAxNikgKyBcIi4uLlwiIDogJzxlbXB0eSB0YWc+JyxcbiAgICAgIG1lc3NhZ2UgPSB0ZW1wbGF0ZUZ1bmN0aW9uKHNob3J0ZW5lZFRhZyk7XG4gIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgRXJyb3IobWVzc2FnZSwge2NhdXNlfSkpO1xufVxuZnVuY3Rpb24gdW5hdmFpbGFibGUodGFnLCBvcGVyYXRpb24pIHtcbiAgcmV0dXJuIGVycm9yKHRhZyA9PiBgVGhlICR7b3BlcmF0aW9ufSB0YWcgJHt0YWd9IGlzIG5vdCBhdmFpbGFibGUuYCwgdGFnKTtcbn1cblxuZXhwb3J0IGNsYXNzIEtleVNldCB7XG4gIC8vIEEgS2V5U2V0IG1haW50YWlucyB0d28gcHJpdmF0ZSBrZXlzOiBzaWduaW5nS2V5IGFuZCBkZWNyeXB0aW5nS2V5LlxuICAvLyBTZWUgaHR0cHM6Ly9raWxyb3ktY29kZS5naXRodWIuaW8vZGlzdHJpYnV0ZWQtc2VjdXJpdHkvZG9jcy9pbXBsZW1lbnRhdGlvbi5odG1sI3dlYi13b3JrZXItYW5kLWlmcmFtZVxuXG4gIC8vIENhY2hpbmdcbiAgc3RhdGljIGtleVNldHMgPSBuZXcgQ2FjaGUoNTAwLCA2MCAqIDYwICogMWUzKTtcbiAgc3RhdGljIGNhY2hlZCh0YWcpIHsgLy8gUmV0dXJuIGFuIGFscmVhZHkgcG9wdWxhdGVkIEtleVNldC5cbiAgICByZXR1cm4gS2V5U2V0LmtleVNldHMuZ2V0KHRhZyk7XG4gIH1cbiAgc3RhdGljIGNhY2hlKHRhZywga2V5U2V0KSB7IC8vIEtlZXAgdHJhY2sgb2YgcmVjZW50IGtleVNldHMuXG4gICAgS2V5U2V0LmtleVNldHMuc2V0KHRhZywga2V5U2V0KTtcbiAgfVxuICBzdGF0aWMgY2xlYXIodGFnID0gbnVsbCkgeyAvLyBSZW1vdmUgYWxsIEtleVNldCBpbnN0YW5jZXMgb3IganVzdCB0aGUgc3BlY2lmaWVkIG9uZSwgYnV0IGRvZXMgbm90IGRlc3Ryb3kgdGhlaXIgc3RvcmFnZS5cbiAgICBpZiAoIXRhZykgcmV0dXJuIEtleVNldC5rZXlTZXRzLmNsZWFyKCk7XG4gICAgcmV0dXJuIEtleVNldC5rZXlTZXRzLmRlbGV0ZSh0YWcpO1xuICB9XG4gIGNvbnN0cnVjdG9yKHRhZykge1xuICAgIHRoaXMudGFnID0gdGFnO1xuICAgIHRoaXMubWVtYmVyVGFncyA9IFtdOyAvLyBVc2VkIHdoZW4gcmVjdXJzaXZlbHkgZGVzdHJveWluZy5cbiAgICBLZXlTZXQuY2FjaGUodGFnLCB0aGlzKTtcbiAgfVxuICAvLyBhcGkubWpzIHByb3ZpZGVzIHRoZSBzZXR0ZXIgdG8gY2hhbmdlcyB0aGVzZSwgYW5kIHdvcmtlci5tanMgZXhlcmNpc2VzIGl0IGluIGJyb3dzZXJzLlxuICBzdGF0aWMgZ2V0VXNlckRldmljZVNlY3JldCA9IGdldFVzZXJEZXZpY2VTZWNyZXQ7XG4gIHN0YXRpYyBTdG9yYWdlID0gU3RvcmFnZTtcblxuICAvLyBQcmluY2lwbGUgb3BlcmF0aW9ucy5cbiAgc3RhdGljIGFzeW5jIGNyZWF0ZSh3cmFwcGluZ0RhdGEpIHsgLy8gQ3JlYXRlIGEgcGVyc2lzdGVkIEtleVNldCBvZiB0aGUgY29ycmVjdCB0eXBlLCBwcm9taXNpbmcgdGhlIG5ld2x5IGNyZWF0ZWQgdGFnLlxuICAgIC8vIE5vdGUgdGhhdCBjcmVhdGluZyBhIEtleVNldCBkb2VzIG5vdCBpbnN0YW50aWF0ZSBpdC5cbiAgICBsZXQge3RpbWUsIC4uLmtleXN9ID0gYXdhaXQgdGhpcy5jcmVhdGVLZXlzKHdyYXBwaW5nRGF0YSksXG4gICAgICAgIHt0YWd9ID0ga2V5cztcbiAgICBhd2FpdCB0aGlzLnBlcnNpc3QodGFnLCBrZXlzLCB3cmFwcGluZ0RhdGEsIHRpbWUpO1xuICAgIHJldHVybiB0YWc7XG4gIH1cbiAgYXN5bmMgZGVzdHJveShvcHRpb25zID0ge30pIHsgLy8gVGVybWluYXRlcyB0aGlzIGtleVNldCBhbmQgYXNzb2NpYXRlZCBzdG9yYWdlLCBhbmQgc2FtZSBmb3IgT1dORUQgcmVjdXJzaXZlTWVtYmVycyBpZiBhc2tlZC5cbiAgICBsZXQge3RhZywgbWVtYmVyVGFncywgc2lnbmluZ0tleX0gPSB0aGlzLFxuICAgICAgICBjb250ZW50ID0gXCJcIiwgLy8gU2hvdWxkIHN0b3JhZ2UgaGF2ZSBhIHNlcGFyYXRlIG9wZXJhdGlvbiB0byBkZWxldGUsIG90aGVyIHRoYW4gc3RvcmluZyBlbXB0eT9cbiAgICAgICAgc2lnbmF0dXJlID0gYXdhaXQgdGhpcy5jb25zdHJ1Y3Rvci5zaWduRm9yU3RvcmFnZSh7Li4ub3B0aW9ucywgbWVzc2FnZTogY29udGVudCwgdGFnLCBtZW1iZXJUYWdzLCBzaWduaW5nS2V5LCB0aW1lOiBEYXRlLm5vdygpLCByZWNvdmVyeTogdHJ1ZX0pO1xuICAgIGF3YWl0IHRoaXMuY29uc3RydWN0b3Iuc3RvcmUoJ0VuY3J5cHRpb25LZXknLCB0YWcsIHNpZ25hdHVyZSk7XG4gICAgYXdhaXQgdGhpcy5jb25zdHJ1Y3Rvci5zdG9yZSh0aGlzLmNvbnN0cnVjdG9yLmNvbGxlY3Rpb24sIHRhZywgc2lnbmF0dXJlKTtcbiAgICB0aGlzLmNvbnN0cnVjdG9yLmNsZWFyKHRhZyk7XG4gICAgaWYgKCFvcHRpb25zLnJlY3Vyc2l2ZU1lbWJlcnMpIHJldHVybjtcbiAgICBhd2FpdCBQcm9taXNlLmFsbFNldHRsZWQodGhpcy5tZW1iZXJUYWdzLm1hcChhc3luYyBtZW1iZXJUYWcgPT4ge1xuICAgICAgbGV0IG1lbWJlcktleVNldCA9IGF3YWl0IEtleVNldC5lbnN1cmUobWVtYmVyVGFnLCB7Li4ub3B0aW9ucywgcmVjb3Zlcnk6IHRydWV9KTtcbiAgICAgIGF3YWl0IG1lbWJlcktleVNldC5kZXN0cm95KG9wdGlvbnMpO1xuICAgIH0pKTtcbiAgfVxuICBkZWNyeXB0KGVuY3J5cHRlZCwgb3B0aW9ucykgeyAvLyBQcm9taXNlIHtwYXlsb2FkLCB0ZXh0LCBqc29ufSBhcyBhcHByb3ByaWF0ZS5cbiAgICBsZXQge3RhZywgZGVjcnlwdGluZ0tleX0gPSB0aGlzLFxuICAgICAgICBrZXkgPSBlbmNyeXB0ZWQucmVjaXBpZW50cyA/IHtbdGFnXTogZGVjcnlwdGluZ0tleX0gOiBkZWNyeXB0aW5nS2V5O1xuICAgIHJldHVybiBNdWx0aUtyeXB0by5kZWNyeXB0KGtleSwgZW5jcnlwdGVkLCBvcHRpb25zKTtcbiAgfVxuICAvLyBzaWduIGFzIGVpdGhlciBjb21wYWN0IG9yIG11bHRpS2V5IGdlbmVyYWwgSldTLlxuICAvLyBUaGVyZSdzIHNvbWUgY29tcGxleGl0eSBoZXJlIGFyb3VuZCBiZWluZyBhYmxlIHRvIHBhc3MgaW4gbWVtYmVyVGFncyBhbmQgc2lnbmluZ0tleSB3aGVuIHRoZSBrZXlTZXQgaXNcbiAgLy8gYmVpbmcgY3JlYXRlZCBhbmQgZG9lc24ndCB5ZXQgZXhpc3QuXG4gIHN0YXRpYyBhc3luYyBzaWduKG1lc3NhZ2UsIHt0YWdzID0gW10sXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICB0ZWFtOmlzcywgbWVtYmVyOmFjdCxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHN1YmplY3Q6c3ViID0gJ2hhc2gnLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGltZTppYXQgPSBpc3MgJiYgRGF0ZS5ub3coKSxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1lbWJlclRhZ3MsIHNpZ25pbmdLZXksIHJlY292ZXJ5LFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLi4ub3B0aW9uc30pIHtcbiAgICBpZiAoaXNzICYmICFhY3QpIHsgLy8gU3VwcGx5IHRoZSB2YWx1ZVxuICAgICAgaWYgKCFtZW1iZXJUYWdzKSBtZW1iZXJUYWdzID0gKGF3YWl0IEtleVNldC5lbnN1cmUoaXNzKSkubWVtYmVyVGFncztcbiAgICAgIGxldCBjYWNoZWRNZW1iZXIgPSBtZW1iZXJUYWdzLmZpbmQodGFnID0+IHRoaXMuY2FjaGVkKHRhZykpO1xuICAgICAgYWN0ID0gY2FjaGVkTWVtYmVyIHx8IGF3YWl0IHRoaXMuZW5zdXJlMShtZW1iZXJUYWdzKS50aGVuKGtleVNldCA9PiBrZXlTZXQudGFnKTtcbiAgICB9XG4gICAgaWYgKGlzcyAmJiAhdGFncy5pbmNsdWRlcyhpc3MpKSB0YWdzID0gW2lzcywgLi4udGFnc107IC8vIE11c3QgYmUgZmlyc3RcbiAgICBpZiAoYWN0ICYmICF0YWdzLmluY2x1ZGVzKGFjdCkpIHRhZ3MgPSBbLi4udGFncywgYWN0XTtcblxuICAgIGxldCBrZXkgPSBhd2FpdCB0aGlzLnByb2R1Y2VLZXkodGFncywgYXN5bmMgdGFnID0+IHtcbiAgICAgIC8vIFVzZSBzcGVjaWZpZWQgc2lnbmluZ0tleSAoaWYgYW55KSBmb3IgdGhlIGZpcnN0IG9uZS5cbiAgICAgIGxldCBrZXkgPSBzaWduaW5nS2V5IHx8IChhd2FpdCBLZXlTZXQuZW5zdXJlKHRhZywge3JlY292ZXJ5LCAuLi5vcHRpb25zfSkpLnNpZ25pbmdLZXk7XG4gICAgICBzaWduaW5nS2V5ID0gbnVsbDtcbiAgICAgIHJldHVybiBrZXk7XG4gICAgfSwgb3B0aW9ucyksXG4gICAgICAgIG1lc3NhZ2VCdWZmZXIgPSBNdWx0aUtyeXB0by5pbnB1dEJ1ZmZlcihtZXNzYWdlLCBvcHRpb25zKTtcbiAgICBpZiAoc3ViID09PSAnaGFzaCcpIHtcbiAgICAgIGNvbnN0IGhhc2ggPSBhd2FpdCBoYXNoQnVmZmVyKG1lc3NhZ2VCdWZmZXIpO1xuICAgICAgc3ViID0gYXdhaXQgZW5jb2RlQmFzZTY0dXJsKGhhc2gpO1xuICAgIH0gZWxzZSBpZiAoIXN1Yikge1xuICAgICAgc3ViID0gdW5kZWZpbmVkO1xuICAgIH1cbiAgICByZXR1cm4gTXVsdGlLcnlwdG8uc2lnbihrZXksIG1lc3NhZ2VCdWZmZXIsIHtpc3MsIGFjdCwgaWF0LCBzdWIsIC4uLm9wdGlvbnN9KTtcbiAgfVxuXG4gIC8vIFZlcmlmeSBpbiB0aGUgbm9ybWFsIHdheSwgYW5kIHRoZW4gY2hlY2sgZGVlcGx5IGlmIGFza2VkLlxuICBzdGF0aWMgYXN5bmMgdmVyaWZ5KHNpZ25hdHVyZSwgdGFncywgb3B0aW9ucykge1xuICAgIGxldCBpc0NvbXBhY3QgPSAhc2lnbmF0dXJlLnNpZ25hdHVyZXMsXG4gICAgICAgIGtleSA9IGF3YWl0IHRoaXMucHJvZHVjZUtleSh0YWdzLCB0YWcgPT4gS2V5U2V0LnZlcmlmeWluZ0tleSh0YWcpLCBvcHRpb25zLCBpc0NvbXBhY3QpLFxuICAgICAgICByZXN1bHQgPSBhd2FpdCBNdWx0aUtyeXB0by52ZXJpZnkoa2V5LCBzaWduYXR1cmUsIG9wdGlvbnMpLFxuICAgICAgICBtZW1iZXJUYWcgPSBvcHRpb25zLm1lbWJlciA9PT0gdW5kZWZpbmVkID8gcmVzdWx0Py5wcm90ZWN0ZWRIZWFkZXIuYWN0IDogb3B0aW9ucy5tZW1iZXIsXG4gICAgICAgIG5vdEJlZm9yZSA9IG9wdGlvbnMubm90QmVmb3JlO1xuICAgIGZ1bmN0aW9uIGV4aXQobGFiZWwpIHtcbiAgICAgIGlmIChvcHRpb25zLmhhcmRFcnJvcikgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBFcnJvcihsYWJlbCkpO1xuICAgIH1cbiAgICBpZiAoIXJlc3VsdCkgcmV0dXJuIGV4aXQoJ0luY29ycmVjdCBzaWduYXR1cmUuJyk7XG4gICAgaWYgKG1lbWJlclRhZykge1xuICAgICAgaWYgKG9wdGlvbnMubWVtYmVyID09PSAndGVhbScpIHtcbiAgICAgICAgbWVtYmVyVGFnID0gcmVzdWx0LnByb3RlY3RlZEhlYWRlci5hY3Q7XG4gICAgICAgIGlmICghbWVtYmVyVGFnKSByZXR1cm4gZXhpdCgnTm8gbWVtYmVyIGlkZW50aWZpZWQgaW4gc2lnbmF0dXJlLicpO1xuICAgICAgfVxuICAgICAgaWYgKCF0YWdzLmluY2x1ZGVzKG1lbWJlclRhZykpIHsgLy8gQWRkIHRvIHRhZ3MgYW5kIHJlc3VsdCBpZiBub3QgYWxyZWFkeSBwcmVzZW50XG4gICAgICAgIGxldCBtZW1iZXJLZXkgPSBhd2FpdCBLZXlTZXQudmVyaWZ5aW5nS2V5KG1lbWJlclRhZyksXG4gICAgICAgICAgICBtZW1iZXJNdWx0aWtleSA9IHtbbWVtYmVyVGFnXTogbWVtYmVyS2V5fSxcbiAgICAgICAgICAgIGF1eCA9IGF3YWl0IE11bHRpS3J5cHRvLnZlcmlmeShtZW1iZXJNdWx0aWtleSwgc2lnbmF0dXJlLCBvcHRpb25zKTtcbiAgICAgICAgaWYgKCFhdXgpIHJldHVybiBleGl0KCdJbmNvcnJlY3QgbWVtYmVyIHNpZ25hdHVyZS4nKTtcbiAgICAgICAgdGFncy5wdXNoKG1lbWJlclRhZyk7XG4gICAgICAgIHJlc3VsdC5zaWduZXJzLmZpbmQoc2lnbmVyID0+IHNpZ25lci5wcm90ZWN0ZWRIZWFkZXIua2lkID09PSBtZW1iZXJUYWcpLnBheWxvYWQgPSByZXN1bHQucGF5bG9hZDtcbiAgICAgIH1cbiAgICB9XG4gICAgaWYgKG1lbWJlclRhZyB8fCBub3RCZWZvcmUgPT09ICd0ZWFtJykge1xuICAgICAgbGV0IHRlYW1UYWcgPSByZXN1bHQucHJvdGVjdGVkSGVhZGVyLmlzcyB8fCByZXN1bHQucHJvdGVjdGVkSGVhZGVyLmtpZCwgLy8gTXVsdGkgb3Igc2luZ2xlIGNhc2UuXG4gICAgICAgICAgdmVyaWZpZWRKV1MgPSBhd2FpdCB0aGlzLnJldHJpZXZlKFRlYW1LZXlTZXQuY29sbGVjdGlvbiwgdGVhbVRhZyksXG4gICAgICAgICAgandlID0gdmVyaWZpZWRKV1M/Lmpzb247XG4gICAgICBpZiAobWVtYmVyVGFnICYmICF0ZWFtVGFnKSByZXR1cm4gZXhpdCgnTm8gdGVhbSBvciBtYWluIHRhZyBpZGVudGlmaWVkIGluIHNpZ25hdHVyZScpO1xuICAgICAgaWYgKG1lbWJlclRhZyAmJiBqd2UgJiYgIWp3ZS5yZWNpcGllbnRzLmZpbmQobWVtYmVyID0+IG1lbWJlci5oZWFkZXIua2lkID09PSBtZW1iZXJUYWcpKSByZXR1cm4gZXhpdCgnU2lnbmVyIGlzIG5vdCBhIG1lbWJlci4nKTtcbiAgICAgIGlmIChub3RCZWZvcmUgPT09ICd0ZWFtJykgbm90QmVmb3JlID0gdmVyaWZpZWRKV1M/LnByb3RlY3RlZEhlYWRlci5pYXRcbiAgICAgICAgfHwgKGF3YWl0IHRoaXMucmV0cmlldmUoJ0VuY3J5cHRpb25LZXknLCB0ZWFtVGFnLCAnZm9yY2UnKSk/LnByb3RlY3RlZEhlYWRlci5pYXQ7XG4gICAgfVxuICAgIGlmIChub3RCZWZvcmUpIHtcbiAgICAgIGxldCB7aWF0fSA9IHJlc3VsdC5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICBpZiAoaWF0IDwgbm90QmVmb3JlKSByZXR1cm4gZXhpdCgnU2lnbmF0dXJlIHByZWRhdGVzIHJlcXVpcmVkIHRpbWVzdGFtcC4nKTtcbiAgICB9XG4gICAgLy8gRWFjaCBzaWduZXIgc2hvdWxkIG5vdyBiZSB2ZXJpZmllZC5cbiAgICBpZiAoKHJlc3VsdC5zaWduZXJzPy5maWx0ZXIoc2lnbmVyID0+IHNpZ25lci5wYXlsb2FkKS5sZW5ndGggfHwgMSkgIT09IHRhZ3MubGVuZ3RoKSByZXR1cm4gZXhpdCgnVW52ZXJpZmllZCBzaWduZXInKTtcbiAgICByZXR1cm4gcmVzdWx0O1xuICB9XG5cbiAgLy8gS2V5IG1hbmFnZW1lbnRcbiAgc3RhdGljIGFzeW5jIHByb2R1Y2VLZXkodGFncywgcHJvZHVjZXIsIG9wdGlvbnMsIHVzZVNpbmdsZUtleSA9IHRhZ3MubGVuZ3RoID09PSAxKSB7XG4gICAgLy8gUHJvbWlzZSBhIGtleSBvciBtdWx0aUtleSwgYXMgZGVmaW5lZCBieSBwcm9kdWNlcih0YWcpIGZvciBlYWNoIGtleS5cbiAgICBpZiAodXNlU2luZ2xlS2V5KSB7XG4gICAgICBsZXQgdGFnID0gdGFnc1swXTtcbiAgICAgIG9wdGlvbnMua2lkID0gdGFnOyAgIC8vIEJhc2hlcyBvcHRpb25zIGluIHRoZSBzaW5nbGUta2V5IGNhc2UsIGJlY2F1c2UgbXVsdGlLZXkncyBoYXZlIHRoZWlyIG93bi5cbiAgICAgIHJldHVybiBwcm9kdWNlcih0YWcpO1xuICAgIH1cbiAgICBsZXQga2V5ID0ge30sXG4gICAgICAgIGtleXMgPSBhd2FpdCBQcm9taXNlLmFsbCh0YWdzLm1hcCh0YWcgPT4gcHJvZHVjZXIodGFnKSkpO1xuICAgIC8vIFRoaXMgaXNuJ3QgZG9uZSBpbiBvbmUgc3RlcCwgYmVjYXVzZSB3ZSdkIGxpa2UgKGZvciBkZWJ1Z2dpbmcgYW5kIHVuaXQgdGVzdHMpIHRvIG1haW50YWluIGEgcHJlZGljdGFibGUgb3JkZXIuXG4gICAgdGFncy5mb3JFYWNoKCh0YWcsIGluZGV4KSA9PiBrZXlbdGFnXSA9IGtleXNbaW5kZXhdKTtcbiAgICByZXR1cm4ga2V5O1xuICB9XG4gIC8vIFRoZSBjb3JyZXNwb25kaW5nIHB1YmxpYyBrZXlzIGFyZSBhdmFpbGFibGUgcHVibGljYWxseSwgb3V0c2lkZSB0aGUga2V5U2V0LlxuICBzdGF0aWMgdmVyaWZ5aW5nS2V5KHRhZykgeyAvLyBQcm9taXNlIHRoZSBvcmRpbmFyeSBzaW5ndWxhciBwdWJsaWMga2V5IGNvcnJlc3BvbmRpbmcgdG8gdGhlIHNpZ25pbmcga2V5LCBkaXJlY3RseSBmcm9tIHRoZSB0YWcgd2l0aG91dCByZWZlcmVuY2UgdG8gc3RvcmFnZS5cbiAgICByZXR1cm4gTXVsdGlLcnlwdG8uaW1wb3J0UmF3KHRhZykuY2F0Y2goKCkgPT4gdW5hdmFpbGFibGUodGFnLCAndmVyaWZpY2F0aW9uJykpO1xuICB9XG4gIHN0YXRpYyBhc3luYyBlbmNyeXB0aW5nS2V5KHRhZykgeyAvLyBQcm9taXNlIHRoZSBvcmRpbmFyeSBzaW5ndWxhciBwdWJsaWMga2V5IGNvcnJlc3BvbmRpbmcgdG8gdGhlIGRlY3J5cHRpb24ga2V5LCB3aGljaCBkZXBlbmRzIG9uIHB1YmxpYyBzdG9yYWdlLlxuICAgIGxldCBleHBvcnRlZFB1YmxpY0tleSA9IGF3YWl0IHRoaXMucmV0cmlldmUoJ0VuY3J5cHRpb25LZXknLCB0YWcpO1xuICAgIGlmICghZXhwb3J0ZWRQdWJsaWNLZXkpIHJldHVybiB1bmF2YWlsYWJsZSh0YWcsICdlbmNyeXB0aW9uJyk7XG4gICAgcmV0dXJuIGF3YWl0IE11bHRpS3J5cHRvLmltcG9ydEpXSyhleHBvcnRlZFB1YmxpY0tleS5qc29uKTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgY3JlYXRlS2V5cyhtZW1iZXJUYWdzKSB7IC8vIFByb21pc2UgYSBuZXcgdGFnIGFuZCBwcml2YXRlIGtleXMsIGFuZCBzdG9yZSB0aGUgZW5jcnlwdGluZyBrZXkuXG4gICAgbGV0IHtwdWJsaWNLZXk6dmVyaWZ5aW5nS2V5LCBwcml2YXRlS2V5OnNpZ25pbmdLZXl9ID0gYXdhaXQgTXVsdGlLcnlwdG8uZ2VuZXJhdGVTaWduaW5nS2V5KCksXG4gICAgICAgIHtwdWJsaWNLZXk6ZW5jcnlwdGluZ0tleSwgcHJpdmF0ZUtleTpkZWNyeXB0aW5nS2V5fSA9IGF3YWl0IE11bHRpS3J5cHRvLmdlbmVyYXRlRW5jcnlwdGluZ0tleSgpLFxuICAgICAgICB0YWcgPSBhd2FpdCBNdWx0aUtyeXB0by5leHBvcnRSYXcodmVyaWZ5aW5nS2V5KSxcbiAgICAgICAgZXhwb3J0ZWRFbmNyeXB0aW5nS2V5ID0gYXdhaXQgTXVsdGlLcnlwdG8uZXhwb3J0SldLKGVuY3J5cHRpbmdLZXkpLFxuICAgICAgICB0aW1lID0gRGF0ZS5ub3coKSxcbiAgICAgICAgc2lnbmF0dXJlID0gYXdhaXQgdGhpcy5zaWduRm9yU3RvcmFnZSh7bWVzc2FnZTogZXhwb3J0ZWRFbmNyeXB0aW5nS2V5LCB0YWcsIHNpZ25pbmdLZXksIG1lbWJlclRhZ3MsIHRpbWUsIHJlY292ZXJ5OiB0cnVlfSk7XG4gICAgYXdhaXQgdGhpcy5zdG9yZSgnRW5jcnlwdGlvbktleScsIHRhZywgc2lnbmF0dXJlKTtcbiAgICByZXR1cm4ge3NpZ25pbmdLZXksIGRlY3J5cHRpbmdLZXksIHRhZywgdGltZX07XG4gIH1cbiAgc3RhdGljIGdldFdyYXBwZWQodGFnKSB7IC8vIFByb21pc2UgdGhlIHdyYXBwZWQga2V5IGFwcHJvcHJpYXRlIGZvciB0aGlzIGNsYXNzLlxuICAgIHJldHVybiB0aGlzLnJldHJpZXZlKHRoaXMuY29sbGVjdGlvbiwgdGFnKTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgZW5zdXJlKHRhZywge2RldmljZSA9IHRydWUsIHRlYW0gPSB0cnVlLCByZWNvdmVyeSA9IGZhbHNlfSA9IHt9KSB7IC8vIFByb21pc2UgdG8gcmVzb2x2ZSB0byBhIHZhbGlkIGtleVNldCwgZWxzZSByZWplY3QuXG4gICAgbGV0IGtleVNldCA9IHRoaXMuY2FjaGVkKHRhZyksXG4gICAgICAgIHN0b3JlZCA9IGRldmljZSAmJiBhd2FpdCBEZXZpY2VLZXlTZXQuZ2V0V3JhcHBlZCh0YWcpO1xuICAgIGlmIChzdG9yZWQpIHtcbiAgICAgIGtleVNldCB8fD0gbmV3IERldmljZUtleVNldCh0YWcpO1xuICAgIH0gZWxzZSBpZiAodGVhbSAmJiAoc3RvcmVkID0gYXdhaXQgVGVhbUtleVNldC5nZXRXcmFwcGVkKHRhZykpKSB7XG4gICAgICBrZXlTZXQgfHw9IG5ldyBUZWFtS2V5U2V0KHRhZyk7XG4gICAgfSBlbHNlIGlmIChyZWNvdmVyeSAmJiAoc3RvcmVkID0gYXdhaXQgUmVjb3ZlcnlLZXlTZXQuZ2V0V3JhcHBlZCh0YWcpKSkgeyAvLyBMYXN0LCBpZiBhdCBhbGwuXG4gICAgICBrZXlTZXQgfHw9IG5ldyBSZWNvdmVyeUtleVNldCh0YWcpO1xuICAgIH1cbiAgICAvLyBJZiB0aGluZ3MgaGF2ZW4ndCBjaGFuZ2VkLCBkb24ndCBib3RoZXIgd2l0aCBzZXRVbndyYXBwZWQuXG4gICAgaWYgKGtleVNldD8uY2FjaGVkICYmIC8vIGNhY2hlZCBhbmQgc3RvcmVkIGFyZSB2ZXJpZmllZCBzaWduYXR1cmVzXG4gICAgICAgIGtleVNldC5jYWNoZWQucHJvdGVjdGVkSGVhZGVyLmlhdCA9PT0gc3RvcmVkPy5wcm90ZWN0ZWRIZWFkZXIuaWF0ICYmXG4gICAgICAgIGtleVNldC5jYWNoZWQudGV4dCA9PT0gc3RvcmVkPy50ZXh0ICYmXG4gICAgICAgIGtleVNldC5kZWNyeXB0aW5nS2V5ICYmIGtleVNldC5zaWduaW5nS2V5KSByZXR1cm4ga2V5U2V0O1xuICAgIGlmIChzdG9yZWQpIGtleVNldC5jYWNoZWQgPSBzdG9yZWQ7XG4gICAgZWxzZSB7IC8vIE5vdCBmb3VuZC4gQ291bGQgYmUgYSBib2d1cyB0YWcsIG9yIG9uZSBvbiBhbm90aGVyIGNvbXB1dGVyLlxuICAgICAgdGhpcy5jbGVhcih0YWcpO1xuICAgICAgcmV0dXJuIHVuYXZhaWxhYmxlKHRhZywgJ3ByaXZhdGUnKTtcbiAgICB9XG4gICAgcmV0dXJuIGtleVNldC51bndyYXAoa2V5U2V0LmNhY2hlZCkudGhlbihcbiAgICAgIHVud3JhcHBlZCA9PiBPYmplY3QuYXNzaWduKGtleVNldCwgdW53cmFwcGVkKSxcbiAgICAgIGNhdXNlID0+IHtcbiAgICAgICAgdGhpcy5jbGVhcihrZXlTZXQudGFnKVxuICAgICAgICByZXR1cm4gZXJyb3IodGFnID0+IGBZb3UgZG8gbm90IGhhdmUgYWNjZXNzIHRvIHRoZSBwcml2YXRlIGtleSBmb3IgJHt0YWd9LmAsIGtleVNldC50YWcsIGNhdXNlKTtcbiAgICAgIH0pO1xuICB9XG4gIHN0YXRpYyBlbnN1cmUxKHRhZ3MpIHsgLy8gRmluZCBvbmUgdmFsaWQga2V5U2V0IGFtb25nIHRhZ3MsIHVzaW5nIHJlY292ZXJ5IHRhZ3Mgb25seSBpZiBuZWNlc3NhcnkuXG4gICAgcmV0dXJuIFByb21pc2UuYW55KHRhZ3MubWFwKHRhZyA9PiBLZXlTZXQuZW5zdXJlKHRhZykpKVxuICAgICAgLmNhdGNoKGFzeW5jIHJlYXNvbiA9PiB7IC8vIElmIHdlIGZhaWxlZCwgdHJ5IHRoZSByZWNvdmVyeSB0YWdzLCBpZiBhbnksIG9uZSBhdCBhIHRpbWUuXG4gICAgICAgIGZvciAobGV0IGNhbmRpZGF0ZSBvZiB0YWdzKSB7XG4gICAgICAgICAgbGV0IGtleVNldCA9IGF3YWl0IEtleVNldC5lbnN1cmUoY2FuZGlkYXRlLCB7ZGV2aWNlOiBmYWxzZSwgdGVhbTogZmFsc2UsIHJlY292ZXJ5OiB0cnVlfSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgaWYgKGtleVNldCkgcmV0dXJuIGtleVNldDtcbiAgICAgICAgfVxuICAgICAgICB0aHJvdyByZWFzb247XG4gICAgICB9KTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgcGVyc2lzdCh0YWcsIGtleXMsIHdyYXBwaW5nRGF0YSwgdGltZSA9IERhdGUubm93KCksIG1lbWJlclRhZ3MgPSB3cmFwcGluZ0RhdGEpIHsgLy8gUHJvbWlzZSB0byB3cmFwIGEgc2V0IG9mIGtleXMgZm9yIHRoZSB3cmFwcGluZ0RhdGEgbWVtYmVycywgYW5kIHBlcnNpc3QgYnkgdGFnLlxuICAgIGxldCB7c2lnbmluZ0tleX0gPSBrZXlzLFxuICAgICAgICB3cmFwcGVkID0gYXdhaXQgdGhpcy53cmFwKGtleXMsIHdyYXBwaW5nRGF0YSksXG4gICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IHRoaXMuc2lnbkZvclN0b3JhZ2Uoe21lc3NhZ2U6IHdyYXBwZWQsIHRhZywgc2lnbmluZ0tleSwgbWVtYmVyVGFncywgdGltZSwgcmVjb3Zlcnk6IHRydWV9KTtcbiAgICBhd2FpdCB0aGlzLnN0b3JlKHRoaXMuY29sbGVjdGlvbiwgdGFnLCBzaWduYXR1cmUpO1xuICB9XG5cbiAgLy8gSW50ZXJhY3Rpb25zIHdpdGggdGhlIGNsb3VkIG9yIGxvY2FsIHN0b3JhZ2UuXG4gIHN0YXRpYyBhc3luYyBzdG9yZShjb2xsZWN0aW9uTmFtZSwgdGFnLCBzaWduYXR1cmUpIHsgLy8gU3RvcmUgc2lnbmF0dXJlLlxuICAgIGlmIChjb2xsZWN0aW9uTmFtZSA9PT0gRGV2aWNlS2V5U2V0LmNvbGxlY3Rpb24pIHtcbiAgICAgIC8vIFdlIGNhbGxlZCB0aGlzLiBObyBuZWVkIHRvIHZlcmlmeSBoZXJlLiBCdXQgc2VlIHJldHJpZXZlKCkuXG4gICAgICBpZiAoTXVsdGlLcnlwdG8uaXNFbXB0eUpXU1BheWxvYWQoc2lnbmF0dXJlKSkgcmV0dXJuIExvY2FsU3RvcmUuZGVsZXRlKHRhZyk7XG4gICAgICByZXR1cm4gTG9jYWxTdG9yZS5wdXQodGFnLCBzaWduYXR1cmUpO1xuICAgIH1cbiAgICByZXR1cm4gS2V5U2V0LlN0b3JhZ2Uuc3RvcmUoY29sbGVjdGlvbk5hbWUsIHRhZywgc2lnbmF0dXJlKTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgcmV0cmlldmUoY29sbGVjdGlvbk5hbWUsIHRhZywgZm9yY2VGcmVzaCA9IGZhbHNlKSB7ICAvLyBHZXQgYmFjayBhIHZlcmlmaWVkIHJlc3VsdC5cbiAgICAvLyBTb21lIGNvbGxlY3Rpb25zIGRvbid0IGNoYW5nZSBjb250ZW50LiBObyBuZWVkIHRvIHJlLWZldGNoL3JlLXZlcmlmeSBpZiBpdCBleGlzdHMuXG4gICAgbGV0IGV4aXN0aW5nID0gIWZvcmNlRnJlc2ggJiYgdGhpcy5jYWNoZWQodGFnKTtcbiAgICBpZiAoZXhpc3Rpbmc/LmNvbnN0cnVjdG9yLmNvbGxlY3Rpb24gPT09IGNvbGxlY3Rpb25OYW1lKSByZXR1cm4gZXhpc3RpbmcuY2FjaGVkO1xuICAgIGxldCBwcm9taXNlID0gKGNvbGxlY3Rpb25OYW1lID09PSBEZXZpY2VLZXlTZXQuY29sbGVjdGlvbikgPyBMb2NhbFN0b3JlLmdldCh0YWcpIDogS2V5U2V0LlN0b3JhZ2UucmV0cmlldmUoY29sbGVjdGlvbk5hbWUsIHRhZyksXG4gICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IHByb21pc2UsXG4gICAgICAgIGtleSA9IHNpZ25hdHVyZSAmJiBhd2FpdCBLZXlTZXQudmVyaWZ5aW5nS2V5KHRhZyk7XG4gICAgaWYgKCFzaWduYXR1cmUpIHJldHVybjtcbiAgICAvLyBXaGlsZSB3ZSByZWx5IG9uIHRoZSBTdG9yYWdlIGltcGxlbWVudGF0aW9ucyB0byBkZWVwbHkgY2hlY2sgc2lnbmF0dXJlcyBkdXJpbmcgd3JpdGUsXG4gICAgLy8gaGVyZSB3ZSBzdGlsbCBkbyBhIHNoYWxsb3cgdmVyaWZpY2F0aW9uIGNoZWNrIGp1c3QgdG8gbWFrZSBzdXJlIHRoYXQgdGhlIGRhdGEgaGFzbid0IGJlZW4gbWVzc2VkIHdpdGggYWZ0ZXIgd3JpdGUuXG4gICAgaWYgKHNpZ25hdHVyZS5zaWduYXR1cmVzKSBrZXkgPSB7W3RhZ106IGtleX07IC8vIFByZXBhcmUgYSBtdWx0aS1rZXlcbiAgICByZXR1cm4gYXdhaXQgTXVsdGlLcnlwdG8udmVyaWZ5KGtleSwgc2lnbmF0dXJlKTtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgU2VjcmV0S2V5U2V0IGV4dGVuZHMgS2V5U2V0IHsgLy8gS2V5cyBhcmUgZW5jcnlwdGVkIGJhc2VkIG9uIGEgc3ltbWV0cmljIHNlY3JldC5cbiAgc3RhdGljIHNpZ25Gb3JTdG9yYWdlKHttZXNzYWdlLCB0YWcsIHNpZ25pbmdLZXksIHRpbWV9KSB7XG4gICAgLy8gQ3JlYXRlIGEgc2ltcGxlIHNpZ25hdHVyZSB0aGF0IGRvZXMgbm90IHNwZWNpZnkgaXNzIG9yIGFjdC5cbiAgICAvLyBUaGVyZSBhcmUgbm8gdHJ1ZSBtZW1iZXJUYWdzIHRvIHBhc3Mgb24gYW5kIHRoZXkgYXJlIG5vdCB1c2VkIGluIHNpbXBsZSBzaWduYXR1cmVzLiBIb3dldmVyLCB0aGUgY2FsbGVyIGRvZXNcbiAgICAvLyBnZW5lcmljYWxseSBwYXNzIHdyYXBwaW5nRGF0YSBhcyBtZW1iZXJUYWdzLCBhbmQgZm9yIFJlY292ZXJ5S2V5U2V0cywgd3JhcHBpbmdEYXRhIGlzIHRoZSBwcm9tcHQuIFxuICAgIC8vIFdlIGRvbid0IHN0b3JlIG11bHRpcGxlIHRpbWVzLCBzbyB0aGVyZSdzIGFsc28gbm8gbmVlZCBmb3IgaWF0ICh3aGljaCBjYW4gYmUgdXNlZCB0byBwcmV2ZW50IHJlcGxheSBhdHRhY2tzKS5cbiAgICByZXR1cm4gdGhpcy5zaWduKG1lc3NhZ2UsIHt0YWdzOiBbdGFnXSwgc2lnbmluZ0tleSwgdGltZX0pO1xuICB9XG4gIHN0YXRpYyBhc3luYyB3cmFwcGluZ0tleSh0YWcsIHByb21wdCkgeyAvLyBUaGUga2V5IHVzZWQgdG8gKHVuKXdyYXAgdGhlIHZhdWx0IG11bHRpLWtleS5cbiAgICBsZXQgc2VjcmV0ID0gIGF3YWl0IHRoaXMuZ2V0U2VjcmV0KHRhZywgcHJvbXB0KTtcbiAgICAvLyBBbHRlcm5hdGl2ZWx5LCBvbmUgY291bGQgdXNlIHtbd3JhcHBpbmdEYXRhXTogc2VjcmV0fSwgYnV0IHRoYXQncyBhIGJpdCB0b28gY3V0ZSwgYW5kIGdlbmVyYXRlcyBhIGdlbmVyYWwgZm9ybSBlbmNyeXB0aW9uLlxuICAgIC8vIFRoaXMgdmVyc2lvbiBnZW5lcmF0ZXMgYSBjb21wYWN0IGZvcm0gZW5jcnlwdGlvbi5cbiAgICByZXR1cm4gTXVsdGlLcnlwdG8uZ2VuZXJhdGVTZWNyZXRLZXkoc2VjcmV0KTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgd3JhcChrZXlzLCBwcm9tcHQgPSAnJykgeyAvLyBFbmNyeXB0IGtleXNldCBieSBnZXRVc2VyRGV2aWNlU2VjcmV0LlxuICAgIGxldCB7ZGVjcnlwdGluZ0tleSwgc2lnbmluZ0tleSwgdGFnfSA9IGtleXMsXG4gICAgICAgIHZhdWx0S2V5ID0ge2RlY3J5cHRpbmdLZXksIHNpZ25pbmdLZXl9LFxuICAgICAgICB3cmFwcGluZ0tleSA9IGF3YWl0IHRoaXMud3JhcHBpbmdLZXkodGFnLCBwcm9tcHQpO1xuICAgIHJldHVybiBNdWx0aUtyeXB0by53cmFwS2V5KHZhdWx0S2V5LCB3cmFwcGluZ0tleSwge3Byb21wdH0pOyAvLyBPcmRlciBpcyBiYWNrd2FyZHMgZnJvbSBlbmNyeXB0LlxuICB9XG4gIGFzeW5jIHVud3JhcCh3cmFwcGVkS2V5KSB7IC8vIERlY3J5cHQga2V5c2V0IGJ5IGdldFVzZXJEZXZpY2VTZWNyZXQuXG4gICAgbGV0IHBhcnNlZCA9IHdyYXBwZWRLZXkuanNvbiB8fCB3cmFwcGVkS2V5LnRleHQsIC8vIEhhbmRsZSBib3RoIGpzb24gYW5kIGNvcGFjdCBmb3JtcyBvZiB3cmFwcGVkS2V5LlxuXG4gICAgICAgIC8vIFRoZSBjYWxsIHRvIHdyYXBLZXksIGFib3ZlLCBleHBsaWNpdGx5IGRlZmluZXMgdGhlIHByb21wdCBpbiB0aGUgaGVhZGVyIG9mIHRoZSBlbmNyeXB0aW9uLlxuICAgICAgICBwcm90ZWN0ZWRIZWFkZXIgPSBNdWx0aUtyeXB0by5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIocGFyc2VkKSxcbiAgICAgICAgcHJvbXB0ID0gcHJvdGVjdGVkSGVhZGVyLnByb21wdCwgLy8gSW4gdGhlIFwiY3V0ZVwiIGZvcm0gb2Ygd3JhcHBpbmdLZXksIHByb21wdCBjYW4gYmUgcHVsbGVkIGZyb20gcGFyc2VkLnJlY2lwaWVudHNbMF0uaGVhZGVyLmtpZCxcblxuICAgICAgICB3cmFwcGluZ0tleSA9IGF3YWl0IHRoaXMuY29uc3RydWN0b3Iud3JhcHBpbmdLZXkodGhpcy50YWcsIHByb21wdCksXG4gICAgICAgIGV4cG9ydGVkID0gKGF3YWl0IE11bHRpS3J5cHRvLmRlY3J5cHQod3JhcHBpbmdLZXksIHBhcnNlZCkpLmpzb247XG4gICAgcmV0dXJuIGF3YWl0IE11bHRpS3J5cHRvLmltcG9ydEpXSyhleHBvcnRlZCwge2RlY3J5cHRpbmdLZXk6ICdkZWNyeXB0Jywgc2lnbmluZ0tleTogJ3NpZ24nfSk7XG4gIH1cbiAgc3RhdGljIGFzeW5jIGdldFNlY3JldCh0YWcsIHByb21wdCkgeyAvLyBnZXRVc2VyRGV2aWNlU2VjcmV0IGZyb20gYXBwLlxuICAgIHJldHVybiBLZXlTZXQuZ2V0VXNlckRldmljZVNlY3JldCh0YWcsIHByb21wdCk7XG4gIH1cbn1cblxuIC8vIFRoZSB1c2VyJ3MgYW5zd2VyKHMpIHRvIGEgc2VjdXJpdHkgcXVlc3Rpb24gZm9ybXMgYSBzZWNyZXQsIGFuZCB0aGUgd3JhcHBlZCBrZXlzIGlzIHN0b3JlZCBpbiB0aGUgY2xvdWRlLlxuZXhwb3J0IGNsYXNzIFJlY292ZXJ5S2V5U2V0IGV4dGVuZHMgU2VjcmV0S2V5U2V0IHtcbiAgc3RhdGljIGNvbGxlY3Rpb24gPSAnS2V5UmVjb3ZlcnknO1xufVxuXG4vLyBBIEtleVNldCBjb3JyZXNwb25kaW5nIHRvIHRoZSBjdXJyZW50IGhhcmR3YXJlLiBXcmFwcGluZyBzZWNyZXQgY29tZXMgZnJvbSB0aGUgYXBwLlxuZXhwb3J0IGNsYXNzIERldmljZUtleVNldCBleHRlbmRzIFNlY3JldEtleVNldCB7XG4gIHN0YXRpYyBjb2xsZWN0aW9uID0gJ0RldmljZSc7XG4gIHN0YXRpYyB3aXBlKCkge1xuICAgIHJldHVybiBMb2NhbFN0b3JlLmRlc3Ryb3koKTtcbiAgfVxufVxuY29uc3QgTG9jYWxTdG9yZSA9IG5ldyBTdG9yYWdlTG9jYWwoe25hbWU6IERldmljZUtleVNldC5jb2xsZWN0aW9ufSk7XG5cbmV4cG9ydCBjbGFzcyBUZWFtS2V5U2V0IGV4dGVuZHMgS2V5U2V0IHsgLy8gQSBLZXlTZXQgY29ycmVzcG9uZGluZyB0byBhIHRlYW0gb2Ygd2hpY2ggdGhlIGN1cnJlbnQgdXNlciBpcyBhIG1lbWJlciAoaWYgZ2V0VGFnKCkpLlxuICBzdGF0aWMgY29sbGVjdGlvbiA9ICdUZWFtJztcbiAgc3RhdGljIHNpZ25Gb3JTdG9yYWdlKHttZXNzYWdlLCB0YWcsIC4uLm9wdGlvbnN9KSB7XG4gICAgcmV0dXJuIHRoaXMuc2lnbihtZXNzYWdlLCB7dGVhbTogdGFnLCAuLi5vcHRpb25zfSk7XG4gIH1cbiAgc3RhdGljIGFzeW5jIHdyYXAoa2V5cywgbWVtYmVycykge1xuICAgIC8vIFRoaXMgaXMgdXNlZCBieSBwZXJzaXN0LCB3aGljaCBpbiB0dXJuIGlzIHVzZWQgdG8gY3JlYXRlIGFuZCBjaGFuZ2VNZW1iZXJzaGlwLlxuICAgIGxldCB7ZGVjcnlwdGluZ0tleSwgc2lnbmluZ0tleX0gPSBrZXlzLFxuICAgICAgICB0ZWFtS2V5ID0ge2RlY3J5cHRpbmdLZXksIHNpZ25pbmdLZXl9LFxuICAgICAgICB3cmFwcGluZ0tleSA9IHt9O1xuICAgIGF3YWl0IFByb21pc2UuYWxsKG1lbWJlcnMubWFwKG1lbWJlclRhZyA9PiBLZXlTZXQuZW5jcnlwdGluZ0tleShtZW1iZXJUYWcpLnRoZW4oa2V5ID0+IHdyYXBwaW5nS2V5W21lbWJlclRhZ10gPSBrZXkpKSk7XG4gICAgbGV0IHdyYXBwZWRUZWFtID0gYXdhaXQgTXVsdGlLcnlwdG8ud3JhcEtleSh0ZWFtS2V5LCB3cmFwcGluZ0tleSk7XG4gICAgcmV0dXJuIHdyYXBwZWRUZWFtO1xuICB9XG4gIGFzeW5jIHVud3JhcCh3cmFwcGVkKSB7XG4gICAgbGV0IHtyZWNpcGllbnRzfSA9IHdyYXBwZWQuanNvbixcbiAgICAgICAgbWVtYmVyVGFncyA9IHRoaXMubWVtYmVyVGFncyA9IHJlY2lwaWVudHMubWFwKHJlY2lwaWVudCA9PiByZWNpcGllbnQuaGVhZGVyLmtpZCk7XG4gICAgbGV0IGtleVNldCA9IGF3YWl0IHRoaXMuY29uc3RydWN0b3IuZW5zdXJlMShtZW1iZXJUYWdzKTsgLy8gV2Ugd2lsbCB1c2UgcmVjb3ZlcnkgdGFncyBvbmx5IGlmIHdlIG5lZWQgdG8uXG4gICAgbGV0IGRlY3J5cHRlZCA9IGF3YWl0IGtleVNldC5kZWNyeXB0KHdyYXBwZWQuanNvbik7XG4gICAgcmV0dXJuIGF3YWl0IE11bHRpS3J5cHRvLmltcG9ydEpXSyhkZWNyeXB0ZWQuanNvbik7XG4gIH1cbiAgYXN5bmMgY2hhbmdlTWVtYmVyc2hpcCh7YWRkID0gW10sIHJlbW92ZSA9IFtdfSA9IHt9KSB7XG4gICAgbGV0IHttZW1iZXJUYWdzfSA9IHRoaXMsXG4gICAgICAgIG5ld01lbWJlcnMgPSBtZW1iZXJUYWdzLmNvbmNhdChhZGQpLmZpbHRlcih0YWcgPT4gIXJlbW92ZS5pbmNsdWRlcyh0YWcpKTtcbiAgICBhd2FpdCB0aGlzLmNvbnN0cnVjdG9yLnBlcnNpc3QodGhpcy50YWcsIHRoaXMsIG5ld01lbWJlcnMsIERhdGUubm93KCksIG1lbWJlclRhZ3MpO1xuICAgIHRoaXMubWVtYmVyVGFncyA9IG5ld01lbWJlcnM7XG4gICAgdGhpcy5jb25zdHJ1Y3Rvci5jbGVhcih0aGlzLnRhZyk7XG4gIH1cbn1cbiIsImltcG9ydCAqIGFzIHBrZyBmcm9tIFwiLi4vcGFja2FnZS5qc29uXCIgd2l0aCB7IHR5cGU6ICdqc29uJyB9O1xuZXhwb3J0IGNvbnN0IHtuYW1lLCB2ZXJzaW9ufSA9IHBrZy5kZWZhdWx0O1xuIiwiaW1wb3J0IHtoYXNoQnVmZmVyLCBoYXNoVGV4dCwgZW5jb2RlQmFzZTY0dXJsLCBkZWNvZGVCYXNlNjR1cmwsIGRlY29kZUNsYWltc30gZnJvbSAnLi91dGlsaXRpZXMubWpzJztcbmltcG9ydCBNdWx0aUtyeXB0byBmcm9tIFwiLi9tdWx0aUtyeXB0by5tanNcIjtcbmltcG9ydCB7S2V5U2V0LCBEZXZpY2VLZXlTZXQsIFJlY292ZXJ5S2V5U2V0LCBUZWFtS2V5U2V0fSBmcm9tIFwiLi9rZXlTZXQubWpzXCI7XG5pbXBvcnQge25hbWUsIHZlcnNpb259IGZyb20gXCIuL3BhY2thZ2UtbG9hZGVyLm1qc1wiO1xuXG5jb25zdCBTZWN1cml0eSA9IHsgLy8gVGhpcyBpcyB0aGUgYXBpIGZvciB0aGUgdmF1bHQuIFNlZSBodHRwczovL2tpbHJveS1jb2RlLmdpdGh1Yi5pby9kaXN0cmlidXRlZC1zZWN1cml0eS9kb2NzL2ltcGxlbWVudGF0aW9uLmh0bWwjY3JlYXRpbmctdGhlLXZhdWx0LXdlYi13b3JrZXItYW5kLWlmcmFtZVxuXG4gIGdldCBLZXlTZXQoKSB7IHJldHVybiBLZXlTZXQ7IH0sLy8gRklYTUU6IGRvIG5vdCBsZWF2ZSB0aGlzIGhlcmVcbiAgLy8gQ2xpZW50LWRlZmluZWQgcmVzb3VyY2VzLlxuICBzZXQgU3RvcmFnZShzdG9yYWdlKSB7IC8vIEFsbG93cyBhIG5vZGUgYXBwIChubyB2YXVsdHQpIHRvIG92ZXJyaWRlIHRoZSBkZWZhdWx0IHN0b3JhZ2UuXG4gICAgS2V5U2V0LlN0b3JhZ2UgPSBzdG9yYWdlO1xuICB9LFxuICBnZXQgU3RvcmFnZSgpIHsgLy8gQWxsb3dzIGEgbm9kZSBhcHAgKG5vIHZhdWx0KSB0byBleGFtaW5lIHN0b3JhZ2UuXG4gICAgcmV0dXJuIEtleVNldC5TdG9yYWdlO1xuICB9LFxuICBzZXQgZ2V0VXNlckRldmljZVNlY3JldChmdW5jdGlvbk9mVGFnQW5kUHJvbXB0KSB7ICAvLyBBbGxvd3MgYSBub2RlIGFwcCAobm8gdmF1bHQpIHRvIG92ZXJyaWRlIHRoZSBkZWZhdWx0LlxuICAgIEtleVNldC5nZXRVc2VyRGV2aWNlU2VjcmV0ID0gZnVuY3Rpb25PZlRhZ0FuZFByb21wdDtcbiAgfSxcbiAgZ2V0IGdldFVzZXJEZXZpY2VTZWNyZXQoKSB7XG4gICAgcmV0dXJuIEtleVNldC5nZXRVc2VyRGV2aWNlU2VjcmV0O1xuICB9LFxuICByZWFkeToge25hbWUsIHZlcnNpb24sIG9yaWdpbjogS2V5U2V0LlN0b3JhZ2Uub3JpZ2lufSxcblxuICAvLyBUaGUgZm91ciBiYXNpYyBvcGVyYXRpb25zLiAuLi5yZXN0IG1heSBiZSBvbmUgb3IgbW9yZSB0YWdzLCBvciBtYXkgYmUge3RhZ3MsIHRlYW0sIG1lbWJlciwgY29udGVudFR5cGUsIC4uLn1cbiAgYXN5bmMgZW5jcnlwdChtZXNzYWdlLCAuLi5yZXN0KSB7IC8vIFByb21pc2UgYSBKV0UuXG4gICAgbGV0IG9wdGlvbnMgPSB7fSwgdGFncyA9IHRoaXMuY2Fub25pY2FsaXplUGFyYW1ldGVycyhyZXN0LCBvcHRpb25zKSxcbiAgICAgICAga2V5ID0gYXdhaXQgS2V5U2V0LnByb2R1Y2VLZXkodGFncywgdGFnID0+IEtleVNldC5lbmNyeXB0aW5nS2V5KHRhZyksIG9wdGlvbnMpO1xuICAgIHJldHVybiBNdWx0aUtyeXB0by5lbmNyeXB0KGtleSwgbWVzc2FnZSwgb3B0aW9ucyk7XG4gIH0sXG4gIGFzeW5jIGRlY3J5cHQoZW5jcnlwdGVkLCAuLi5yZXN0KSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259IGFzIGFwcHJvcHJpYXRlLlxuICAgIGxldCBvcHRpb25zID0ge30sXG4gICAgICAgIFt0YWddID0gdGhpcy5jYW5vbmljYWxpemVQYXJhbWV0ZXJzKHJlc3QsIG9wdGlvbnMsIGVuY3J5cHRlZCksXG4gICAgICAgIHtyZWNvdmVyeSwgLi4ub3RoZXJPcHRpb25zfSA9IG9wdGlvbnMsXG4gICAgICAgIGtleVNldCA9IGF3YWl0IEtleVNldC5lbnN1cmUodGFnLCB7cmVjb3Zlcnl9KTtcbiAgICByZXR1cm4ga2V5U2V0LmRlY3J5cHQoZW5jcnlwdGVkLCBvdGhlck9wdGlvbnMpO1xuICB9LFxuICBhc3luYyBzaWduKG1lc3NhZ2UsIC4uLnJlc3QpIHsgLy8gUHJvbWlzZSBhIEpXUy5cbiAgICBsZXQgb3B0aW9ucyA9IHt9LCB0YWdzID0gdGhpcy5jYW5vbmljYWxpemVQYXJhbWV0ZXJzKHJlc3QsIG9wdGlvbnMpO1xuICAgIHJldHVybiBLZXlTZXQuc2lnbihtZXNzYWdlLCB7dGFncywgLi4ub3B0aW9uc30pO1xuICB9LFxuICBhc3luYyB2ZXJpZnkoc2lnbmF0dXJlLCAuLi5yZXN0KSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259IGFzIGFwcHJvcHJpYXRlLlxuICAgIGxldCBvcHRpb25zID0ge30sIHRhZ3MgPSB0aGlzLmNhbm9uaWNhbGl6ZVBhcmFtZXRlcnMocmVzdCwgb3B0aW9ucywgc2lnbmF0dXJlKTtcbiAgICByZXR1cm4gS2V5U2V0LnZlcmlmeShzaWduYXR1cmUsIHRhZ3MsIG9wdGlvbnMpO1xuICB9LFxuXG4gIC8vIFRhZyBtYWludGFuY2UuXG4gIGFzeW5jIGNyZWF0ZSguLi5tZW1iZXJzKSB7IC8vIFByb21pc2UgYSBuZXdseS1jcmVhdGVkIHRhZyB3aXRoIHRoZSBnaXZlbiBtZW1iZXJzLiBUaGUgbWVtYmVyIHRhZ3MgKGlmIGFueSkgbXVzdCBhbHJlYWR5IGV4aXN0LlxuICAgIGlmICghbWVtYmVycy5sZW5ndGgpIHJldHVybiBhd2FpdCBEZXZpY2VLZXlTZXQuY3JlYXRlKCk7XG4gICAgbGV0IHByb21wdCA9IG1lbWJlcnNbMF0ucHJvbXB0O1xuICAgIGlmIChwcm9tcHQpIHJldHVybiBhd2FpdCBSZWNvdmVyeUtleVNldC5jcmVhdGUocHJvbXB0KTtcbiAgICByZXR1cm4gYXdhaXQgVGVhbUtleVNldC5jcmVhdGUobWVtYmVycyk7XG4gIH0sXG4gIGFzeW5jIGNoYW5nZU1lbWJlcnNoaXAoe3RhZywgcmVjb3ZlcnkgPSBmYWxzZSwgLi4ub3B0aW9uc30pIHsgLy8gUHJvbWlzZSB0byBhZGQgb3IgcmVtb3ZlIG1lbWJlcnMuXG4gICAgbGV0IGtleVNldCA9IGF3YWl0IEtleVNldC5lbnN1cmUodGFnLCB7cmVjb3ZlcnksIC4uLm9wdGlvbnN9KTsgLy8gTWFrZXMgbm8gc2Vuc2UgdG8gY2hhbmdlTWVtYmVyc2hpcCBvZiBhIHJlY292ZXJ5IGtleS5cbiAgICByZXR1cm4ga2V5U2V0LmNoYW5nZU1lbWJlcnNoaXAob3B0aW9ucyk7XG4gIH0sXG4gIGFzeW5jIGRlc3Ryb3kodGFnT3JPcHRpb25zKSB7IC8vIFByb21pc2UgdG8gcmVtb3ZlIHRoZSB0YWcgYW5kIGFueSBhc3NvY2lhdGVkIGRhdGEgZnJvbSBhbGwgc3RvcmFnZS5cbiAgICBpZiAoJ3N0cmluZycgPT09IHR5cGVvZiB0YWdPck9wdGlvbnMpIHRhZ09yT3B0aW9ucyA9IHt0YWc6IHRhZ09yT3B0aW9uc307XG4gICAgbGV0IHt0YWcsIHJlY292ZXJ5ID0gdHJ1ZSwgLi4ub3RoZXJPcHRpb25zfSA9IHRhZ09yT3B0aW9ucyxcbiAgICAgICAgb3B0aW9ucyA9IHtyZWNvdmVyeSwgLi4ub3RoZXJPcHRpb25zfSxcbiAgICAgICAga2V5U2V0ID0gYXdhaXQgS2V5U2V0LmVuc3VyZSh0YWcsIG9wdGlvbnMpO1xuICAgIHJldHVybiBrZXlTZXQuZGVzdHJveShvcHRpb25zKTtcbiAgfSxcbiAgY2xlYXIodGFnKSB7IC8vIFJlbW92ZSBhbnkgbG9jYWxseSBjYWNoZWQgS2V5U2V0IGZvciB0aGUgdGFnLCBvciBhbGwgS2V5U2V0cyBpZiBub3QgdGFnIHNwZWNpZmllZC5cbiAgICBLZXlTZXQuY2xlYXIodGFnKTtcbiAgfSxcbiAgd2lwZURldmljZUtleXMoKSB7XG4gICAgcmV0dXJuIERldmljZUtleVNldC53aXBlKCk7XG4gIH0sXG5cbiAgLy8gVXRsaXRpZXNcbiAgaGFzaEJ1ZmZlciwgaGFzaFRleHQsIGVuY29kZUJhc2U2NHVybCwgZGVjb2RlQmFzZTY0dXJsLCBkZWNvZGVDbGFpbXMsXG5cbiAgY2Fub25pY2FsaXplUGFyYW1ldGVycyhyZXN0LCBvcHRpb25zLCB0b2tlbikgeyAvLyBSZXR1cm4gdGhlIGFjdHVhbCBsaXN0IG9mIHRhZ3MsIGFuZCBiYXNoIG9wdGlvbnMuXG4gICAgLy8gcmVzdCBtYXkgYmUgYSBsaXN0IG9mIHRhZyBzdHJpbmdzXG4gICAgLy8gICAgb3IgYSBsaXN0IG9mIG9uZSBzaW5nbGUgb2JqZWN0IHNwZWNpZnlpbmcgbmFtZWQgcGFyYW1ldGVycywgaW5jbHVkaW5nIGVpdGhlciB0ZWFtLCB0YWdzLCBvciBuZWl0aGVyXG4gICAgLy8gdG9rZW4gbWF5IGJlIGEgSldFIG9yIEpTRSwgb3IgZmFsc3ksIGFuZCBpcyB1c2VkIHRvIHN1cHBseSB0YWdzIGlmIG5lY2Vzc2FyeS5cbiAgICBpZiAocmVzdC5sZW5ndGggPiAxIHx8IHJlc3RbMF0/Lmxlbmd0aCAhPT0gdW5kZWZpbmVkKSByZXR1cm4gcmVzdDtcbiAgICBsZXQge3RhZ3MgPSBbXSwgY29udGVudFR5cGUsIHRpbWUsIC4uLm90aGVyc30gPSByZXN0WzBdIHx8IHt9LFxuXHR7dGVhbX0gPSBvdGhlcnM7IC8vIERvIG5vdCBzdHJpcCB0ZWFtIGZyb20gb3RoZXJzLlxuICAgIGlmICghdGFncy5sZW5ndGgpIHtcbiAgICAgIGlmIChyZXN0Lmxlbmd0aCAmJiByZXN0WzBdLmxlbmd0aCkgdGFncyA9IHJlc3Q7IC8vIHJlc3Qgbm90IGVtcHR5LCBhbmQgaXRzIGZpcnN0IGlzIHN0cmluZy1saWtlLlxuICAgICAgZWxzZSBpZiAodG9rZW4pIHsgLy8gZ2V0IGZyb20gdG9rZW5cbiAgICAgICAgaWYgKHRva2VuLnNpZ25hdHVyZXMpIHRhZ3MgPSB0b2tlbi5zaWduYXR1cmVzLm1hcChzaWcgPT4gTXVsdGlLcnlwdG8uZGVjb2RlUHJvdGVjdGVkSGVhZGVyKHNpZykua2lkKTtcbiAgICAgICAgZWxzZSBpZiAodG9rZW4ucmVjaXBpZW50cykgdGFncyA9IHRva2VuLnJlY2lwaWVudHMubWFwKHJlYyA9PiByZWMuaGVhZGVyLmtpZCk7XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgIGxldCBraWQgPSBNdWx0aUtyeXB0by5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIodG9rZW4pLmtpZDsgLy8gY29tcGFjdCB0b2tlblxuICAgICAgICAgIGlmIChraWQpIHRhZ3MgPSBba2lkXTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgICBpZiAodGVhbSAmJiAhdGFncy5pbmNsdWRlcyh0ZWFtKSkgdGFncyA9IFt0ZWFtLCAuLi50YWdzXTtcbiAgICBpZiAoY29udGVudFR5cGUpIG9wdGlvbnMuY3R5ID0gY29udGVudFR5cGU7XG4gICAgaWYgKHRpbWUpIG9wdGlvbnMuaWF0ID0gdGltZTtcbiAgICBPYmplY3QuYXNzaWduKG9wdGlvbnMsIG90aGVycyk7XG5cbiAgICByZXR1cm4gdGFncztcbiAgfVxufTtcblxuZXhwb3J0IGRlZmF1bHQgU2VjdXJpdHk7XG4iLCJcbmZ1bmN0aW9uIHRyYW5zZmVycmFibGVFcnJvcihlcnJvcikgeyAvLyBBbiBlcnJvciBvYmplY3QgdGhhdCB3ZSByZWNlaXZlIG9uIG91ciBzaWRlIG1pZ2h0IG5vdCBiZSB0cmFuc2ZlcnJhYmxlIHRvIHRoZSBvdGhlci5cbiAgbGV0IHtuYW1lLCBtZXNzYWdlLCBjb2RlLCBkYXRhfSA9IGVycm9yO1xuICByZXR1cm4ge25hbWUsIG1lc3NhZ2UsIGNvZGUsIGRhdGF9O1xufVxuXG4vLyBTZXQgdXAgYmlkaXJlY3Rpb25hbCBjb21tdW5jYXRpb25zIHdpdGggdGFyZ2V0LCByZXR1cm5pbmcgYSBmdW5jdGlvbiAobWV0aG9kTmFtZSwgLi4ucGFyYW1zKSB0aGF0IHdpbGwgc2VuZCB0byB0YXJnZXQuXG5mdW5jdGlvbiBkaXNwYXRjaCh7dGFyZ2V0ID0gc2VsZiwgICAgICAgIC8vIFRoZSB3aW5kb3csIHdvcmtlciwgb3Igb3RoZXIgb2JqZWN0IHRvIHdoaWNoIHdlIHdpbGwgcG9zdE1lc3NhZ2UuXG5cdFx0ICAgcmVjZWl2ZXIgPSB0YXJnZXQsICAgIC8vIFRoZSB3aW5kb3csIHdvcmtlciwgb3Igb3RoZXIgb2JqZWN0IG9mIHdoaWNoIFdFIHdpbGwgaGFuZGxlICdtZXNzYWdlJyBldmVudHMgZnJvbSB0YXJnZXQuXG5cdFx0ICAgbmFtZXNwYWNlID0gcmVjZWl2ZXIsIC8vIEFuIG9iamVjdCB0aGF0IGRlZmluZXMgYW55IG1ldGhvZHMgdGhhdCBtYXkgYmUgcmVxdWVzdGVkIGJ5IHRhcmdldC5cblxuXHRcdCAgIG9yaWdpbiA9ICgodGFyZ2V0ICE9PSByZWNlaXZlcikgJiYgdGFyZ2V0LmxvY2F0aW9uLm9yaWdpbiksXG5cblx0XHQgICBkaXNwYXRjaGVyTGFiZWwgPSBuYW1lc3BhY2UubmFtZSB8fCByZWNlaXZlci5uYW1lIHx8IHJlY2VpdmVyLmxvY2F0aW9uPy5ocmVmIHx8IHJlY2VpdmVyLFxuXHRcdCAgIHRhcmdldExhYmVsID0gdGFyZ2V0Lm5hbWUgfHwgb3JpZ2luIHx8IHRhcmdldC5sb2NhdGlvbj8uaHJlZiB8fCB0YXJnZXQsXG5cblx0XHQgICBsb2cgPSBudWxsLFxuXHRcdCAgIGluZm86bG9naW5mbyA9IGNvbnNvbGUuaW5mby5iaW5kKGNvbnNvbGUpLFxuXHRcdCAgIHdhcm46bG9nd2FybiA9IGNvbnNvbGUud2Fybi5iaW5kKGNvbnNvbGUpLFxuXHRcdCAgIGVycm9yOmxvZ2Vycm9yID0gY29uc29sZS5lcnJvci5iaW5kKGNvbnNvbGUpXG5cdFx0ICB9KSB7XG4gIGNvbnN0IHJlcXVlc3RzID0ge30sXG4gICAgICAgIGpzb25ycGMgPSAnMi4wJyxcbiAgICAgICAgY2FwdHVyZWRQb3N0ID0gdGFyZ2V0LnBvc3RNZXNzYWdlLmJpbmQodGFyZ2V0KSwgLy8gSW4gY2FzZSAobWFsaWNpb3VzKSBjb2RlIGxhdGVyIGNoYW5nZXMgaXQuXG4gICAgICAgIC8vIHdpbmRvdy5wb3N0TWVzc2FnZSBhbmQgZnJpZW5kcyB0YWtlcyBhIHRhcmdldE9yaWdpbiB0aGF0IHdlIHN1cHBseS5cbiAgICAgICAgLy8gQnV0IHdvcmtlci5wb3N0TWVzc2FnZSBnaXZlcyBlcnJvciByYXRoZXIgdGhhbiBpZ25vcmluZyB0aGUgZXh0cmEgYXJnLiBTbyBzZXQgdGhlIHJpZ2h0IGZvcm0gYXQgaW5pdGlhbGl6YXRpb24uXG4gICAgICAgIHBvc3QgPSBvcmlnaW4gPyBtZXNzYWdlID0+IGNhcHR1cmVkUG9zdChtZXNzYWdlLCBvcmlnaW4pIDogY2FwdHVyZWRQb3N0LFxuICAgICAgICBudWxsTG9nID0gKCkgPT4ge307XG4gIGxldCBtZXNzYWdlSWQgPSAwOyAvLyBwcmUtaW5jcmVtZW50ZWQgaWQgc3RhcnRzIGF0IDEuXG5cbiAgZnVuY3Rpb24gcmVxdWVzdChtZXRob2QsIC4uLnBhcmFtcykgeyAvLyBQcm9taXNlIHRoZSByZXN1bHQgb2YgbWV0aG9kKC4uLnBhcmFtcykgaW4gdGFyZ2V0LlxuICAgIC8vIFdlIGRvIGEgdGFyZ2V0LnBvc3RNZXNzYWdlIG9mIGEganNvbnJwYyByZXF1ZXN0LCBhbmQgcmVzb2x2ZSB0aGUgcHJvbWlzZSB3aXRoIHRoZSByZXNwb25zZSwgbWF0Y2hlZCBieSBpZC5cbiAgICAvLyBJZiB0aGUgdGFyZ2V0IGhhcHBlbnMgdG8gYmUgc2V0IHVwIGJ5IGEgZGlzcGF0Y2ggbGlrZSB0aGlzIG9uZSwgaXQgd2lsbCByZXNwb25kIHdpdGggd2hhdGV2ZXIgaXQnc1xuICAgIC8vIG5hbWVzcGFjZVttZXRob2RdKC4uLnBhcmFtcykgcmVzb2x2ZXMgdG8uIFdlIG9ubHkgc2VuZCBqc29ucnBjIHJlcXVlc3RzICh3aXRoIGFuIGlkKSwgbm90IG5vdGlmaWNhdGlvbnMsXG4gICAgLy8gYmVjYXVzZSB0aGVyZSBpcyBubyB3YXkgdG8gZ2V0IGVycm9ycyBiYWNrIGZyb20gYSBqc29ucnBjIG5vdGlmaWNhdGlvbi5cbiAgICBsZXQgaWQgPSArK21lc3NhZ2VJZCxcblx0cmVxdWVzdCA9IHJlcXVlc3RzW2lkXSA9IHt9O1xuICAgIC8vIEl0IHdvdWxkIGJlIG5pY2UgdG8gbm90IGxlYWsgcmVxdWVzdCBvYmplY3RzIGlmIHRoZXkgYXJlbid0IGFuc3dlcmVkLlxuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBsb2c/LihkaXNwYXRjaGVyTGFiZWwsICdyZXF1ZXN0JywgaWQsIG1ldGhvZCwgcGFyYW1zLCAndG8nLCB0YXJnZXRMYWJlbCk7XG4gICAgICBPYmplY3QuYXNzaWduKHJlcXVlc3QsIHtyZXNvbHZlLCByZWplY3R9KTtcbiAgICAgIHBvc3Qoe2lkLCBtZXRob2QsIHBhcmFtcywganNvbnJwY30pO1xuICAgIH0pO1xuICB9XG5cbiAgYXN5bmMgZnVuY3Rpb24gcmVzcG9uZChldmVudCkgeyAvLyBIYW5kbGUgJ21lc3NhZ2UnIGV2ZW50cyB0aGF0IHdlIHJlY2VpdmUgZnJvbSB0YXJnZXQuXG4gICAgbG9nPy4oZGlzcGF0Y2hlckxhYmVsLCAnZ290IG1lc3NhZ2UnLCBldmVudC5kYXRhLCAnZnJvbScsIHRhcmdldExhYmVsLCBldmVudC5vcmlnaW4pO1xuICAgIGxldCB7aWQsIG1ldGhvZCwgcGFyYW1zID0gW10sIHJlc3VsdCwgZXJyb3IsIGpzb25ycGM6dmVyc2lvbn0gPSBldmVudC5kYXRhIHx8IHt9O1xuXG4gICAgLy8gTm9pc2lseSBpZ25vcmUgbWVzc2FnZXMgdGhhdCBhcmUgbm90IGZyb20gdGhlIGV4cGVjdCB0YXJnZXQgb3Igb3JpZ2luLCBvciB3aGljaCBhcmUgbm90IGpzb25ycGMuXG4gICAgaWYgKGV2ZW50LnNvdXJjZSAmJiAoZXZlbnQuc291cmNlICE9PSB0YXJnZXQpKSByZXR1cm4gbG9nZXJyb3I/LihkaXNwYXRjaGVyTGFiZWwsICd0bycsIHRhcmdldExhYmVsLCAgJ2dvdCBtZXNzYWdlIGZyb20nLCBldmVudC5zb3VyY2UpO1xuICAgIGlmIChvcmlnaW4gJiYgKG9yaWdpbiAhPT0gZXZlbnQub3JpZ2luKSkgcmV0dXJuIGxvZ2Vycm9yPy4oZGlzcGF0Y2hlckxhYmVsLCBvcmlnaW4sICdtaXNtYXRjaGVkIG9yaWdpbicsIHRhcmdldExhYmVsLCBldmVudC5vcmlnaW4pO1xuICAgIGlmICh2ZXJzaW9uICE9PSBqc29ucnBjKSByZXR1cm4gbG9nd2Fybj8uKGAke2Rpc3BhdGNoZXJMYWJlbH0gaWdub3Jpbmcgbm9uLWpzb25ycGMgbWVzc2FnZSAke0pTT04uc3RyaW5naWZ5KGV2ZW50LmRhdGEpfS5gKTtcblxuICAgIGlmIChtZXRob2QpIHsgLy8gSW5jb21pbmcgcmVxdWVzdCBvciBub3RpZmljYXRpb24gZnJvbSB0YXJnZXQuXG4gICAgICBsZXQgZXJyb3IgPSBudWxsLCByZXN1bHQsXG4gICAgICAgICAgLy8ganNvbnJwYyByZXF1ZXN0L25vdGlmaWNhdGlvbiBjYW4gaGF2ZSBwb3NpdGlvbmFsIGFyZ3MgKGFycmF5KSBvciBuYW1lZCBhcmdzIChhIFBPSk8pLlxuXHQgIGFyZ3MgPSBBcnJheS5pc0FycmF5KHBhcmFtcykgPyBwYXJhbXMgOiBbcGFyYW1zXTsgLy8gQWNjZXB0IGVpdGhlci5cbiAgICAgIHRyeSB7IC8vIG1ldGhvZCByZXN1bHQgbWlnaHQgbm90IGJlIGEgcHJvbWlzZSwgc28gd2UgY2FuJ3QgcmVseSBvbiAuY2F0Y2goKS5cbiAgICAgICAgcmVzdWx0ID0gYXdhaXQgbmFtZXNwYWNlW21ldGhvZF0oLi4uYXJncyk7IC8vIENhbGwgdGhlIG1ldGhvZC5cbiAgICAgIH0gY2F0Y2ggKGUpIHsgLy8gU2VuZCBiYWNrIGEgY2xlYW4ge25hbWUsIG1lc3NhZ2V9IG9iamVjdC5cbiAgICAgICAgZXJyb3IgPSB0cmFuc2ZlcnJhYmxlRXJyb3IoZSk7XG4gICAgICAgIGlmICghbmFtZXNwYWNlW21ldGhvZF0gJiYgIWVycm9yLm1lc3NhZ2UuaW5jbHVkZXMobWV0aG9kKSkge1xuXHQgIGVycm9yLm1lc3NhZ2UgPSBgJHttZXRob2R9IGlzIG5vdCBkZWZpbmVkLmA7IC8vIEJlIG1vcmUgaGVscGZ1bCB0aGFuIHNvbWUgYnJvd3NlcnMuXG4gICAgICAgICAgZXJyb3IuY29kZSA9IC0zMjYwMTsgLy8gRGVmaW5lZCBieSBqc29uLXJwYyBzcGVjLlxuICAgICAgICB9IGVsc2UgaWYgKCFlcnJvci5tZXNzYWdlKSAvLyBJdCBoYXBwZW5zLiBFLmcuLCBvcGVyYXRpb25hbCBlcnJvcnMgZnJvbSBjcnlwdG8uXG5cdCAgZXJyb3IubWVzc2FnZSA9IGAke2Vycm9yLm5hbWUgfHwgZXJyb3IudG9TdHJpbmcoKX0gaW4gJHttZXRob2R9LmA7XG4gICAgICB9XG4gICAgICBpZiAoaWQgPT09IHVuZGVmaW5lZCkgcmV0dXJuOyAvLyBEb24ndCByZXNwb25kIHRvIGEgJ25vdGlmaWNhdGlvbicuIG51bGwgaWQgaXMgc3RpbGwgc2VudCBiYWNrLlxuICAgICAgbGV0IHJlc3BvbnNlID0gZXJyb3IgPyB7aWQsIGVycm9yLCBqc29ucnBjfSA6IHtpZCwgcmVzdWx0LCBqc29ucnBjfTtcbiAgICAgIGxvZz8uKGRpc3BhdGNoZXJMYWJlbCwgJ2Fuc3dlcmluZycsIGlkLCBlcnJvciB8fCByZXN1bHQsICd0bycsIHRhcmdldExhYmVsKTtcbiAgICAgIHJldHVybiBwb3N0KHJlc3BvbnNlKTtcbiAgICB9XG5cbiAgICAvLyBPdGhlcndpc2UsIGl0IGlzIGEgcmVzcG9uc2UgZnJvbSB0YXJnZXQgdG8gb3VyIGVhcmxpZXIgb3V0Z29pbmcgcmVxdWVzdC5cbiAgICBsZXQgcmVxdWVzdCA9IHJlcXVlc3RzW2lkXTsgIC8vIFJlc29sdmUgb3IgcmVqZWN0IHRoZSBwcm9taXNlIHRoYXQgYW4gYW4gZWFybGllciByZXF1ZXN0IGNyZWF0ZWQuXG4gICAgZGVsZXRlIHJlcXVlc3RzW2lkXTtcbiAgICBpZiAoIXJlcXVlc3QpIHJldHVybiBsb2d3YXJuPy4oYCR7ZGlzcGF0Y2hlckxhYmVsfSBpZ25vcmluZyByZXNwb25zZSAke2V2ZW50LmRhdGF9LmApO1xuICAgIGlmIChlcnJvcikgcmVxdWVzdC5yZWplY3QoZXJyb3IpO1xuICAgIGVsc2UgcmVxdWVzdC5yZXNvbHZlKHJlc3VsdCk7XG4gIH1cblxuICAvLyBOb3cgc2V0IHVwIHRoZSBoYW5kbGVyIGFuZCByZXR1cm4gdGhlIGZ1bmN0aW9uIGZvciB0aGUgY2FsbGVyIHRvIHVzZSB0byBtYWtlIHJlcXVlc3RzLlxuICByZWNlaXZlci5hZGRFdmVudExpc3RlbmVyKFwibWVzc2FnZVwiLCByZXNwb25kKTtcbiAgbG9naW5mbz8uKGAke2Rpc3BhdGNoZXJMYWJlbH0gd2lsbCBkaXNwYXRjaCB0byAke3RhcmdldExhYmVsfWApO1xuICByZXR1cm4gcmVxdWVzdDtcbn1cblxuZXhwb3J0IGRlZmF1bHQgZGlzcGF0Y2g7XG4iXSwibmFtZXMiOlsiY3J5cHRvIiwiZW5jb2RlIiwiZGVjb2RlIiwiYml0TGVuZ3RoIiwiZGVjcnlwdCIsImdldENyeXB0b0tleSIsIndyYXAiLCJ1bndyYXAiLCJkZXJpdmVLZXkiLCJwMnMiLCJjb25jYXRTYWx0IiwiZW5jcnlwdCIsImJhc2U2NHVybCIsInN1YnRsZUFsZ29yaXRobSIsImltcG9ydEpXSyIsImRlY29kZUJhc2U2NFVSTCIsImFzS2V5T2JqZWN0IiwiandrLmlzSldLIiwiandrLmlzU2VjcmV0SldLIiwiaW52YWxpZEtleUlucHV0IiwiandrLmlzUHJpdmF0ZUpXSyIsImp3ay5pc1B1YmxpY0pXSyIsImNoZWNrS2V5VHlwZSIsIkVDREguZWNkaEFsbG93ZWQiLCJFQ0RILmRlcml2ZUtleSIsImNla0xlbmd0aCIsImFlc0t3IiwicnNhRXMiLCJwYmVzMkt3IiwiYWVzR2NtS3ciLCJFQ0RILmdlbmVyYXRlRXBrIiwiZ2V0VmVyaWZ5S2V5IiwiZ2V0U2lnbktleSIsImJhc2U2NHVybC5lbmNvZGUiLCJiYXNlNjR1cmwuZGVjb2RlIiwiZ2VuZXJhdGVTZWNyZXQiLCJnZW5lcmF0ZUtleVBhaXIiLCJnZW5lcmF0ZSIsIkpPU0UuYmFzZTY0dXJsLmVuY29kZSIsIkpPU0UuYmFzZTY0dXJsLmRlY29kZSIsIkpPU0UuZGVjb2RlUHJvdGVjdGVkSGVhZGVyIiwiSk9TRS5nZW5lcmF0ZUtleVBhaXIiLCJKT1NFLkNvbXBhY3RTaWduIiwiSk9TRS5jb21wYWN0VmVyaWZ5IiwiSk9TRS5Db21wYWN0RW5jcnlwdCIsIkpPU0UuY29tcGFjdERlY3J5cHQiLCJKT1NFLmdlbmVyYXRlU2VjcmV0IiwiSk9TRS5leHBvcnRKV0siLCJKT1NFLmltcG9ydEpXSyIsIkpPU0UuR2VuZXJhbEVuY3J5cHQiLCJKT1NFLmdlbmVyYWxEZWNyeXB0IiwiSk9TRS5HZW5lcmFsU2lnbiIsIkpPU0UuZ2VuZXJhbFZlcmlmeSIsIkNhY2hlIiwiU3RvcmFnZUxvY2FsIiwicGtnLmRlZmF1bHQiXSwibWFwcGluZ3MiOiJBQUFBLGVBQWUsTUFBTTs7QUNBckIsZUFBZSxNQUFNO0FBQ2QsTUFBTSxXQUFXLEdBQUcsQ0FBQyxHQUFHLEtBQUssR0FBRyxZQUFZLFNBQVM7O0FDQTVELE1BQU0sTUFBTSxHQUFHLE9BQU8sU0FBUyxFQUFFLElBQUksS0FBSztBQUMxQyxJQUFJLE1BQU0sWUFBWSxHQUFHLENBQUMsSUFBSSxFQUFFLFNBQVMsQ0FBQyxLQUFLLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQztBQUNyRCxJQUFJLE9BQU8sSUFBSSxVQUFVLENBQUMsTUFBTUEsUUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsWUFBWSxFQUFFLElBQUksQ0FBQyxDQUFDO0FBQ3pFLENBQUM7O0FDSE0sTUFBTSxPQUFPLEdBQUcsSUFBSSxXQUFXLEVBQUU7QUFDakMsTUFBTSxPQUFPLEdBQUcsSUFBSSxXQUFXLEVBQUU7QUFDeEMsTUFBTSxTQUFTLEdBQUcsQ0FBQyxJQUFJLEVBQUU7QUFDbEIsU0FBUyxNQUFNLENBQUMsR0FBRyxPQUFPLEVBQUU7QUFDbkMsSUFBSSxNQUFNLElBQUksR0FBRyxPQUFPLENBQUMsTUFBTSxDQUFDLENBQUMsR0FBRyxFQUFFLEVBQUUsTUFBTSxFQUFFLEtBQUssR0FBRyxHQUFHLE1BQU0sRUFBRSxDQUFDLENBQUM7QUFDckUsSUFBSSxNQUFNLEdBQUcsR0FBRyxJQUFJLFVBQVUsQ0FBQyxJQUFJLENBQUM7QUFDcEMsSUFBSSxJQUFJLENBQUMsR0FBRyxDQUFDO0FBQ2IsSUFBSSxLQUFLLE1BQU0sTUFBTSxJQUFJLE9BQU8sRUFBRTtBQUNsQyxRQUFRLEdBQUcsQ0FBQyxHQUFHLENBQUMsTUFBTSxFQUFFLENBQUMsQ0FBQztBQUMxQixRQUFRLENBQUMsSUFBSSxNQUFNLENBQUMsTUFBTTtBQUMxQjtBQUNBLElBQUksT0FBTyxHQUFHO0FBQ2Q7QUFDTyxTQUFTLEdBQUcsQ0FBQyxHQUFHLEVBQUUsUUFBUSxFQUFFO0FBQ25DLElBQUksT0FBTyxNQUFNLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsRUFBRSxJQUFJLFVBQVUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLEVBQUUsUUFBUSxDQUFDO0FBQ3JFO0FBQ0EsU0FBUyxhQUFhLENBQUMsR0FBRyxFQUFFLEtBQUssRUFBRSxNQUFNLEVBQUU7QUFDM0MsSUFBSSxJQUFJLEtBQUssR0FBRyxDQUFDLElBQUksS0FBSyxJQUFJLFNBQVMsRUFBRTtBQUN6QyxRQUFRLE1BQU0sSUFBSSxVQUFVLENBQUMsQ0FBQywwQkFBMEIsRUFBRSxTQUFTLEdBQUcsQ0FBQyxDQUFDLFdBQVcsRUFBRSxLQUFLLENBQUMsQ0FBQyxDQUFDO0FBQzdGO0FBQ0EsSUFBSSxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUMsS0FBSyxLQUFLLEVBQUUsRUFBRSxLQUFLLEtBQUssRUFBRSxFQUFFLEtBQUssS0FBSyxDQUFDLEVBQUUsS0FBSyxHQUFHLElBQUksQ0FBQyxFQUFFLE1BQU0sQ0FBQztBQUM1RTtBQUNPLFNBQVMsUUFBUSxDQUFDLEtBQUssRUFBRTtBQUNoQyxJQUFJLE1BQU0sSUFBSSxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsS0FBSyxHQUFHLFNBQVMsQ0FBQztBQUM5QyxJQUFJLE1BQU0sR0FBRyxHQUFHLEtBQUssR0FBRyxTQUFTO0FBQ2pDLElBQUksTUFBTSxHQUFHLEdBQUcsSUFBSSxVQUFVLENBQUMsQ0FBQyxDQUFDO0FBQ2pDLElBQUksYUFBYSxDQUFDLEdBQUcsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO0FBQy9CLElBQUksYUFBYSxDQUFDLEdBQUcsRUFBRSxHQUFHLEVBQUUsQ0FBQyxDQUFDO0FBQzlCLElBQUksT0FBTyxHQUFHO0FBQ2Q7QUFDTyxTQUFTLFFBQVEsQ0FBQyxLQUFLLEVBQUU7QUFDaEMsSUFBSSxNQUFNLEdBQUcsR0FBRyxJQUFJLFVBQVUsQ0FBQyxDQUFDLENBQUM7QUFDakMsSUFBSSxhQUFhLENBQUMsR0FBRyxFQUFFLEtBQUssQ0FBQztBQUM3QixJQUFJLE9BQU8sR0FBRztBQUNkO0FBQ08sU0FBUyxjQUFjLENBQUMsS0FBSyxFQUFFO0FBQ3RDLElBQUksT0FBTyxNQUFNLENBQUMsUUFBUSxDQUFDLEtBQUssQ0FBQyxNQUFNLENBQUMsRUFBRSxLQUFLLENBQUM7QUFDaEQ7QUFDTyxlQUFlLFNBQVMsQ0FBQyxNQUFNLEVBQUUsSUFBSSxFQUFFLEtBQUssRUFBRTtBQUNyRCxJQUFJLE1BQU0sVUFBVSxHQUFHLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQyxJQUFJLElBQUksQ0FBQyxJQUFJLEVBQUUsQ0FBQztBQUNsRCxJQUFJLE1BQU0sR0FBRyxHQUFHLElBQUksVUFBVSxDQUFDLFVBQVUsR0FBRyxFQUFFLENBQUM7QUFDL0MsSUFBSSxLQUFLLElBQUksSUFBSSxHQUFHLENBQUMsRUFBRSxJQUFJLEdBQUcsVUFBVSxFQUFFLElBQUksRUFBRSxFQUFFO0FBQ2xELFFBQVEsTUFBTSxHQUFHLEdBQUcsSUFBSSxVQUFVLENBQUMsQ0FBQyxHQUFHLE1BQU0sQ0FBQyxNQUFNLEdBQUcsS0FBSyxDQUFDLE1BQU0sQ0FBQztBQUNwRSxRQUFRLEdBQUcsQ0FBQyxHQUFHLENBQUMsUUFBUSxDQUFDLElBQUksR0FBRyxDQUFDLENBQUMsQ0FBQztBQUNuQyxRQUFRLEdBQUcsQ0FBQyxHQUFHLENBQUMsTUFBTSxFQUFFLENBQUMsQ0FBQztBQUMxQixRQUFRLEdBQUcsQ0FBQyxHQUFHLENBQUMsS0FBSyxFQUFFLENBQUMsR0FBRyxNQUFNLENBQUMsTUFBTSxDQUFDO0FBQ3pDLFFBQVEsR0FBRyxDQUFDLEdBQUcsQ0FBQyxNQUFNLE1BQU0sQ0FBQyxRQUFRLEVBQUUsR0FBRyxDQUFDLEVBQUUsSUFBSSxHQUFHLEVBQUUsQ0FBQztBQUN2RDtBQUNBLElBQUksT0FBTyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxJQUFJLElBQUksQ0FBQyxDQUFDO0FBQ2xDOztBQ2pETyxNQUFNLFlBQVksR0FBRyxDQUFDLEtBQUssS0FBSztBQUN2QyxJQUFJLElBQUksU0FBUyxHQUFHLEtBQUs7QUFDekIsSUFBSSxJQUFJLE9BQU8sU0FBUyxLQUFLLFFBQVEsRUFBRTtBQUN2QyxRQUFRLFNBQVMsR0FBRyxPQUFPLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FBQztBQUM3QztBQUNBLElBQUksTUFBTSxVQUFVLEdBQUcsTUFBTTtBQUM3QixJQUFJLE1BQU0sR0FBRyxHQUFHLEVBQUU7QUFDbEIsSUFBSSxLQUFLLElBQUksQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDLEdBQUcsU0FBUyxDQUFDLE1BQU0sRUFBRSxDQUFDLElBQUksVUFBVSxFQUFFO0FBQzNELFFBQVEsR0FBRyxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsWUFBWSxDQUFDLEtBQUssQ0FBQyxJQUFJLEVBQUUsU0FBUyxDQUFDLFFBQVEsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxHQUFHLFVBQVUsQ0FBQyxDQUFDLENBQUM7QUFDeEY7QUFDQSxJQUFJLE9BQU8sSUFBSSxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsRUFBRSxDQUFDLENBQUM7QUFDN0IsQ0FBQztBQUNNLE1BQU1DLFFBQU0sR0FBRyxDQUFDLEtBQUssS0FBSztBQUNqQyxJQUFJLE9BQU8sWUFBWSxDQUFDLEtBQUssQ0FBQyxDQUFDLE9BQU8sQ0FBQyxJQUFJLEVBQUUsRUFBRSxDQUFDLENBQUMsT0FBTyxDQUFDLEtBQUssRUFBRSxHQUFHLENBQUMsQ0FBQyxPQUFPLENBQUMsS0FBSyxFQUFFLEdBQUcsQ0FBQztBQUN4RixDQUFDO0FBQ00sTUFBTSxZQUFZLEdBQUcsQ0FBQyxPQUFPLEtBQUs7QUFDekMsSUFBSSxNQUFNLE1BQU0sR0FBRyxJQUFJLENBQUMsT0FBTyxDQUFDO0FBQ2hDLElBQUksTUFBTSxLQUFLLEdBQUcsSUFBSSxVQUFVLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQztBQUMvQyxJQUFJLEtBQUssSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsR0FBRyxNQUFNLENBQUMsTUFBTSxFQUFFLENBQUMsRUFBRSxFQUFFO0FBQzVDLFFBQVEsS0FBSyxDQUFDLENBQUMsQ0FBQyxHQUFHLE1BQU0sQ0FBQyxVQUFVLENBQUMsQ0FBQyxDQUFDO0FBQ3ZDO0FBQ0EsSUFBSSxPQUFPLEtBQUs7QUFDaEIsQ0FBQztBQUNNLE1BQU1DLFFBQU0sR0FBRyxDQUFDLEtBQUssS0FBSztBQUNqQyxJQUFJLElBQUksT0FBTyxHQUFHLEtBQUs7QUFDdkIsSUFBSSxJQUFJLE9BQU8sWUFBWSxVQUFVLEVBQUU7QUFDdkMsUUFBUSxPQUFPLEdBQUcsT0FBTyxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUM7QUFDekM7QUFDQSxJQUFJLE9BQU8sR0FBRyxPQUFPLENBQUMsT0FBTyxDQUFDLElBQUksRUFBRSxHQUFHLENBQUMsQ0FBQyxPQUFPLENBQUMsSUFBSSxFQUFFLEdBQUcsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxLQUFLLEVBQUUsRUFBRSxDQUFDO0FBQzlFLElBQUksSUFBSTtBQUNSLFFBQVEsT0FBTyxZQUFZLENBQUMsT0FBTyxDQUFDO0FBQ3BDO0FBQ0EsSUFBSSxNQUFNO0FBQ1YsUUFBUSxNQUFNLElBQUksU0FBUyxDQUFDLG1EQUFtRCxDQUFDO0FBQ2hGO0FBQ0EsQ0FBQzs7QUNwQ00sTUFBTSxTQUFTLFNBQVMsS0FBSyxDQUFDO0FBQ3JDLElBQUksV0FBVyxDQUFDLE9BQU8sRUFBRSxPQUFPLEVBQUU7QUFDbEMsUUFBUSxLQUFLLENBQUMsT0FBTyxFQUFFLE9BQU8sQ0FBQztBQUMvQixRQUFRLElBQUksQ0FBQyxJQUFJLEdBQUcsa0JBQWtCO0FBQ3RDLFFBQVEsSUFBSSxDQUFDLElBQUksR0FBRyxJQUFJLENBQUMsV0FBVyxDQUFDLElBQUk7QUFDekMsUUFBUSxLQUFLLENBQUMsaUJBQWlCLEdBQUcsSUFBSSxFQUFFLElBQUksQ0FBQyxXQUFXLENBQUM7QUFDekQ7QUFDQTtBQUNBLFNBQVMsQ0FBQyxJQUFJLEdBQUcsa0JBQWtCO0FBQzVCLE1BQU0sd0JBQXdCLFNBQVMsU0FBUyxDQUFDO0FBQ3hELElBQUksV0FBVyxDQUFDLE9BQU8sRUFBRSxPQUFPLEVBQUUsS0FBSyxHQUFHLGFBQWEsRUFBRSxNQUFNLEdBQUcsYUFBYSxFQUFFO0FBQ2pGLFFBQVEsS0FBSyxDQUFDLE9BQU8sRUFBRSxFQUFFLEtBQUssRUFBRSxFQUFFLEtBQUssRUFBRSxNQUFNLEVBQUUsT0FBTyxFQUFFLEVBQUUsQ0FBQztBQUM3RCxRQUFRLElBQUksQ0FBQyxJQUFJLEdBQUcsaUNBQWlDO0FBQ3JELFFBQVEsSUFBSSxDQUFDLEtBQUssR0FBRyxLQUFLO0FBQzFCLFFBQVEsSUFBSSxDQUFDLE1BQU0sR0FBRyxNQUFNO0FBQzVCLFFBQVEsSUFBSSxDQUFDLE9BQU8sR0FBRyxPQUFPO0FBQzlCO0FBQ0E7QUFDQSx3QkFBd0IsQ0FBQyxJQUFJLEdBQUcsaUNBQWlDO0FBQzFELE1BQU0sVUFBVSxTQUFTLFNBQVMsQ0FBQztBQUMxQyxJQUFJLFdBQVcsQ0FBQyxPQUFPLEVBQUUsT0FBTyxFQUFFLEtBQUssR0FBRyxhQUFhLEVBQUUsTUFBTSxHQUFHLGFBQWEsRUFBRTtBQUNqRixRQUFRLEtBQUssQ0FBQyxPQUFPLEVBQUUsRUFBRSxLQUFLLEVBQUUsRUFBRSxLQUFLLEVBQUUsTUFBTSxFQUFFLE9BQU8sRUFBRSxFQUFFLENBQUM7QUFDN0QsUUFBUSxJQUFJLENBQUMsSUFBSSxHQUFHLGlCQUFpQjtBQUNyQyxRQUFRLElBQUksQ0FBQyxLQUFLLEdBQUcsS0FBSztBQUMxQixRQUFRLElBQUksQ0FBQyxNQUFNLEdBQUcsTUFBTTtBQUM1QixRQUFRLElBQUksQ0FBQyxPQUFPLEdBQUcsT0FBTztBQUM5QjtBQUNBO0FBQ0EsVUFBVSxDQUFDLElBQUksR0FBRyxpQkFBaUI7QUFDNUIsTUFBTSxpQkFBaUIsU0FBUyxTQUFTLENBQUM7QUFDakQsSUFBSSxXQUFXLEdBQUc7QUFDbEIsUUFBUSxLQUFLLENBQUMsR0FBRyxTQUFTLENBQUM7QUFDM0IsUUFBUSxJQUFJLENBQUMsSUFBSSxHQUFHLDBCQUEwQjtBQUM5QztBQUNBO0FBQ0EsaUJBQWlCLENBQUMsSUFBSSxHQUFHLDBCQUEwQjtBQUM1QyxNQUFNLGdCQUFnQixTQUFTLFNBQVMsQ0FBQztBQUNoRCxJQUFJLFdBQVcsR0FBRztBQUNsQixRQUFRLEtBQUssQ0FBQyxHQUFHLFNBQVMsQ0FBQztBQUMzQixRQUFRLElBQUksQ0FBQyxJQUFJLEdBQUcsd0JBQXdCO0FBQzVDO0FBQ0E7QUFDQSxnQkFBZ0IsQ0FBQyxJQUFJLEdBQUcsd0JBQXdCO0FBQ3pDLE1BQU0sbUJBQW1CLFNBQVMsU0FBUyxDQUFDO0FBQ25ELElBQUksV0FBVyxDQUFDLE9BQU8sR0FBRyw2QkFBNkIsRUFBRSxPQUFPLEVBQUU7QUFDbEUsUUFBUSxLQUFLLENBQUMsT0FBTyxFQUFFLE9BQU8sQ0FBQztBQUMvQixRQUFRLElBQUksQ0FBQyxJQUFJLEdBQUcsMkJBQTJCO0FBQy9DO0FBQ0E7QUFDQSxtQkFBbUIsQ0FBQyxJQUFJLEdBQUcsMkJBQTJCO0FBQy9DLE1BQU0sVUFBVSxTQUFTLFNBQVMsQ0FBQztBQUMxQyxJQUFJLFdBQVcsR0FBRztBQUNsQixRQUFRLEtBQUssQ0FBQyxHQUFHLFNBQVMsQ0FBQztBQUMzQixRQUFRLElBQUksQ0FBQyxJQUFJLEdBQUcsaUJBQWlCO0FBQ3JDO0FBQ0E7QUFDQSxVQUFVLENBQUMsSUFBSSxHQUFHLGlCQUFpQjtBQUM1QixNQUFNLFVBQVUsU0FBUyxTQUFTLENBQUM7QUFDMUMsSUFBSSxXQUFXLEdBQUc7QUFDbEIsUUFBUSxLQUFLLENBQUMsR0FBRyxTQUFTLENBQUM7QUFDM0IsUUFBUSxJQUFJLENBQUMsSUFBSSxHQUFHLGlCQUFpQjtBQUNyQztBQUNBO0FBQ0EsVUFBVSxDQUFDLElBQUksR0FBRyxpQkFBaUI7QUFDNUIsTUFBTSxVQUFVLFNBQVMsU0FBUyxDQUFDO0FBQzFDLElBQUksV0FBVyxHQUFHO0FBQ2xCLFFBQVEsS0FBSyxDQUFDLEdBQUcsU0FBUyxDQUFDO0FBQzNCLFFBQVEsSUFBSSxDQUFDLElBQUksR0FBRyxpQkFBaUI7QUFDckM7QUFDQTtBQUNBLFVBQVUsQ0FBQyxJQUFJLEdBQUcsaUJBQWlCO0FBQzVCLE1BQU0sVUFBVSxTQUFTLFNBQVMsQ0FBQztBQUMxQyxJQUFJLFdBQVcsR0FBRztBQUNsQixRQUFRLEtBQUssQ0FBQyxHQUFHLFNBQVMsQ0FBQztBQUMzQixRQUFRLElBQUksQ0FBQyxJQUFJLEdBQUcsaUJBQWlCO0FBQ3JDO0FBQ0E7QUFDQSxVQUFVLENBQUMsSUFBSSxHQUFHLGlCQUFpQjtBQUM1QixNQUFNLFdBQVcsU0FBUyxTQUFTLENBQUM7QUFDM0MsSUFBSSxXQUFXLEdBQUc7QUFDbEIsUUFBUSxLQUFLLENBQUMsR0FBRyxTQUFTLENBQUM7QUFDM0IsUUFBUSxJQUFJLENBQUMsSUFBSSxHQUFHLGtCQUFrQjtBQUN0QztBQUNBO0FBQ0EsV0FBVyxDQUFDLElBQUksR0FBRyxrQkFBa0I7QUFDOUIsTUFBTSxpQkFBaUIsU0FBUyxTQUFTLENBQUM7QUFDakQsSUFBSSxXQUFXLENBQUMsT0FBTyxHQUFHLGlEQUFpRCxFQUFFLE9BQU8sRUFBRTtBQUN0RixRQUFRLEtBQUssQ0FBQyxPQUFPLEVBQUUsT0FBTyxDQUFDO0FBQy9CLFFBQVEsSUFBSSxDQUFDLElBQUksR0FBRywwQkFBMEI7QUFDOUM7QUFDQTtBQUNBLGlCQUFpQixDQUFDLElBQUksR0FBRywwQkFBMEI7QUFDNUMsTUFBTSx3QkFBd0IsU0FBUyxTQUFTLENBQUM7QUFDeEQsSUFBSSxXQUFXLENBQUMsT0FBTyxHQUFHLHNEQUFzRCxFQUFFLE9BQU8sRUFBRTtBQUMzRixRQUFRLEtBQUssQ0FBQyxPQUFPLEVBQUUsT0FBTyxDQUFDO0FBQy9CLFFBQVEsSUFBSSxDQUFDLElBQUksR0FBRyxpQ0FBaUM7QUFDckQ7QUFDQTtBQUVBLHdCQUF3QixDQUFDLElBQUksR0FBRyxpQ0FBaUM7QUFDMUQsTUFBTSxXQUFXLFNBQVMsU0FBUyxDQUFDO0FBQzNDLElBQUksV0FBVyxDQUFDLE9BQU8sR0FBRyxtQkFBbUIsRUFBRSxPQUFPLEVBQUU7QUFDeEQsUUFBUSxLQUFLLENBQUMsT0FBTyxFQUFFLE9BQU8sQ0FBQztBQUMvQixRQUFRLElBQUksQ0FBQyxJQUFJLEdBQUcsa0JBQWtCO0FBQ3RDO0FBQ0E7QUFDQSxXQUFXLENBQUMsSUFBSSxHQUFHLGtCQUFrQjtBQUM5QixNQUFNLDhCQUE4QixTQUFTLFNBQVMsQ0FBQztBQUM5RCxJQUFJLFdBQVcsQ0FBQyxPQUFPLEdBQUcsK0JBQStCLEVBQUUsT0FBTyxFQUFFO0FBQ3BFLFFBQVEsS0FBSyxDQUFDLE9BQU8sRUFBRSxPQUFPLENBQUM7QUFDL0IsUUFBUSxJQUFJLENBQUMsSUFBSSxHQUFHLHVDQUF1QztBQUMzRDtBQUNBO0FBQ0EsOEJBQThCLENBQUMsSUFBSSxHQUFHLHVDQUF1Qzs7QUNoSDdFLGFBQWVGLFFBQU0sQ0FBQyxlQUFlLENBQUMsSUFBSSxDQUFDQSxRQUFNLENBQUM7O0FDQzNDLFNBQVNHLFdBQVMsQ0FBQyxHQUFHLEVBQUU7QUFDL0IsSUFBSSxRQUFRLEdBQUc7QUFDZixRQUFRLEtBQUssU0FBUztBQUN0QixRQUFRLEtBQUssV0FBVztBQUN4QixRQUFRLEtBQUssU0FBUztBQUN0QixRQUFRLEtBQUssV0FBVztBQUN4QixRQUFRLEtBQUssU0FBUztBQUN0QixRQUFRLEtBQUssV0FBVztBQUN4QixZQUFZLE9BQU8sRUFBRTtBQUNyQixRQUFRLEtBQUssZUFBZTtBQUM1QixRQUFRLEtBQUssZUFBZTtBQUM1QixRQUFRLEtBQUssZUFBZTtBQUM1QixZQUFZLE9BQU8sR0FBRztBQUN0QixRQUFRO0FBQ1IsWUFBWSxNQUFNLElBQUksZ0JBQWdCLENBQUMsQ0FBQywyQkFBMkIsRUFBRSxHQUFHLENBQUMsQ0FBQyxDQUFDO0FBQzNFO0FBQ0E7QUFDQSxpQkFBZSxDQUFDLEdBQUcsS0FBSyxNQUFNLENBQUMsSUFBSSxVQUFVLENBQUNBLFdBQVMsQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQzs7QUNqQm5FLE1BQU0sYUFBYSxHQUFHLENBQUMsR0FBRyxFQUFFLEVBQUUsS0FBSztBQUNuQyxJQUFJLElBQUksRUFBRSxDQUFDLE1BQU0sSUFBSSxDQUFDLEtBQUtBLFdBQVMsQ0FBQyxHQUFHLENBQUMsRUFBRTtBQUMzQyxRQUFRLE1BQU0sSUFBSSxVQUFVLENBQUMsc0NBQXNDLENBQUM7QUFDcEU7QUFDQSxDQUFDOztBQ0xELE1BQU0sY0FBYyxHQUFHLENBQUMsR0FBRyxFQUFFLFFBQVEsS0FBSztBQUMxQyxJQUFJLE1BQU0sTUFBTSxHQUFHLEdBQUcsQ0FBQyxVQUFVLElBQUksQ0FBQztBQUN0QyxJQUFJLElBQUksTUFBTSxLQUFLLFFBQVEsRUFBRTtBQUM3QixRQUFRLE1BQU0sSUFBSSxVQUFVLENBQUMsQ0FBQyxnREFBZ0QsRUFBRSxRQUFRLENBQUMsV0FBVyxFQUFFLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQztBQUNwSDtBQUNBLENBQUM7O0FDTkQsTUFBTSxlQUFlLEdBQUcsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxLQUFLO0FBQ2xDLElBQUksSUFBSSxFQUFFLENBQUMsWUFBWSxVQUFVLENBQUMsRUFBRTtBQUNwQyxRQUFRLE1BQU0sSUFBSSxTQUFTLENBQUMsaUNBQWlDLENBQUM7QUFDOUQ7QUFDQSxJQUFJLElBQUksRUFBRSxDQUFDLFlBQVksVUFBVSxDQUFDLEVBQUU7QUFDcEMsUUFBUSxNQUFNLElBQUksU0FBUyxDQUFDLGtDQUFrQyxDQUFDO0FBQy9EO0FBQ0EsSUFBSSxJQUFJLENBQUMsQ0FBQyxNQUFNLEtBQUssQ0FBQyxDQUFDLE1BQU0sRUFBRTtBQUMvQixRQUFRLE1BQU0sSUFBSSxTQUFTLENBQUMseUNBQXlDLENBQUM7QUFDdEU7QUFDQSxJQUFJLE1BQU0sR0FBRyxHQUFHLENBQUMsQ0FBQyxNQUFNO0FBQ3hCLElBQUksSUFBSSxHQUFHLEdBQUcsQ0FBQztBQUNmLElBQUksSUFBSSxDQUFDLEdBQUcsRUFBRTtBQUNkLElBQUksT0FBTyxFQUFFLENBQUMsR0FBRyxHQUFHLEVBQUU7QUFDdEIsUUFBUSxHQUFHLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUM7QUFDMUI7QUFDQSxJQUFJLE9BQU8sR0FBRyxLQUFLLENBQUM7QUFDcEIsQ0FBQzs7QUNqQkQsU0FBUyxRQUFRLENBQUMsSUFBSSxFQUFFLElBQUksR0FBRyxnQkFBZ0IsRUFBRTtBQUNqRCxJQUFJLE9BQU8sSUFBSSxTQUFTLENBQUMsQ0FBQywrQ0FBK0MsRUFBRSxJQUFJLENBQUMsU0FBUyxFQUFFLElBQUksQ0FBQyxDQUFDLENBQUM7QUFDbEc7QUFDQSxTQUFTLFdBQVcsQ0FBQyxTQUFTLEVBQUUsSUFBSSxFQUFFO0FBQ3RDLElBQUksT0FBTyxTQUFTLENBQUMsSUFBSSxLQUFLLElBQUk7QUFDbEM7QUFDQSxTQUFTLGFBQWEsQ0FBQyxJQUFJLEVBQUU7QUFDN0IsSUFBSSxPQUFPLFFBQVEsQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxFQUFFLENBQUM7QUFDM0M7QUFDQSxTQUFTLGFBQWEsQ0FBQyxHQUFHLEVBQUU7QUFDNUIsSUFBSSxRQUFRLEdBQUc7QUFDZixRQUFRLEtBQUssT0FBTztBQUNwQixZQUFZLE9BQU8sT0FBTztBQUMxQixRQUFRLEtBQUssT0FBTztBQUNwQixZQUFZLE9BQU8sT0FBTztBQUMxQixRQUFRLEtBQUssT0FBTztBQUNwQixZQUFZLE9BQU8sT0FBTztBQUMxQixRQUFRO0FBQ1IsWUFBWSxNQUFNLElBQUksS0FBSyxDQUFDLGFBQWEsQ0FBQztBQUMxQztBQUNBO0FBQ0EsU0FBUyxVQUFVLENBQUMsR0FBRyxFQUFFLE1BQU0sRUFBRTtBQUNqQyxJQUFJLElBQUksTUFBTSxDQUFDLE1BQU0sSUFBSSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsQ0FBQyxRQUFRLEtBQUssR0FBRyxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsUUFBUSxDQUFDLENBQUMsRUFBRTtBQUNwRixRQUFRLElBQUksR0FBRyxHQUFHLHFFQUFxRTtBQUN2RixRQUFRLElBQUksTUFBTSxDQUFDLE1BQU0sR0FBRyxDQUFDLEVBQUU7QUFDL0IsWUFBWSxNQUFNLElBQUksR0FBRyxNQUFNLENBQUMsR0FBRyxFQUFFO0FBQ3JDLFlBQVksR0FBRyxJQUFJLENBQUMsT0FBTyxFQUFFLE1BQU0sQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUMsS0FBSyxFQUFFLElBQUksQ0FBQyxDQUFDLENBQUM7QUFDN0Q7QUFDQSxhQUFhLElBQUksTUFBTSxDQUFDLE1BQU0sS0FBSyxDQUFDLEVBQUU7QUFDdEMsWUFBWSxHQUFHLElBQUksQ0FBQyxPQUFPLEVBQUUsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDLElBQUksRUFBRSxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0FBQ3pEO0FBQ0EsYUFBYTtBQUNiLFlBQVksR0FBRyxJQUFJLENBQUMsRUFBRSxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0FBQ2xDO0FBQ0EsUUFBUSxNQUFNLElBQUksU0FBUyxDQUFDLEdBQUcsQ0FBQztBQUNoQztBQUNBO0FBQ08sU0FBUyxpQkFBaUIsQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUcsTUFBTSxFQUFFO0FBQ3ZELElBQUksUUFBUSxHQUFHO0FBQ2YsUUFBUSxLQUFLLE9BQU87QUFDcEIsUUFBUSxLQUFLLE9BQU87QUFDcEIsUUFBUSxLQUFLLE9BQU8sRUFBRTtBQUN0QixZQUFZLElBQUksQ0FBQyxXQUFXLENBQUMsR0FBRyxDQUFDLFNBQVMsRUFBRSxNQUFNLENBQUM7QUFDbkQsZ0JBQWdCLE1BQU0sUUFBUSxDQUFDLE1BQU0sQ0FBQztBQUN0QyxZQUFZLE1BQU0sUUFBUSxHQUFHLFFBQVEsQ0FBQyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUUsQ0FBQztBQUN2RCxZQUFZLE1BQU0sTUFBTSxHQUFHLGFBQWEsQ0FBQyxHQUFHLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQztBQUM1RCxZQUFZLElBQUksTUFBTSxLQUFLLFFBQVE7QUFDbkMsZ0JBQWdCLE1BQU0sUUFBUSxDQUFDLENBQUMsSUFBSSxFQUFFLFFBQVEsQ0FBQyxDQUFDLEVBQUUsZ0JBQWdCLENBQUM7QUFDbkUsWUFBWTtBQUNaO0FBQ0EsUUFBUSxLQUFLLE9BQU87QUFDcEIsUUFBUSxLQUFLLE9BQU87QUFDcEIsUUFBUSxLQUFLLE9BQU8sRUFBRTtBQUN0QixZQUFZLElBQUksQ0FBQyxXQUFXLENBQUMsR0FBRyxDQUFDLFNBQVMsRUFBRSxtQkFBbUIsQ0FBQztBQUNoRSxnQkFBZ0IsTUFBTSxRQUFRLENBQUMsbUJBQW1CLENBQUM7QUFDbkQsWUFBWSxNQUFNLFFBQVEsR0FBRyxRQUFRLENBQUMsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxFQUFFLENBQUM7QUFDdkQsWUFBWSxNQUFNLE1BQU0sR0FBRyxhQUFhLENBQUMsR0FBRyxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUM7QUFDNUQsWUFBWSxJQUFJLE1BQU0sS0FBSyxRQUFRO0FBQ25DLGdCQUFnQixNQUFNLFFBQVEsQ0FBQyxDQUFDLElBQUksRUFBRSxRQUFRLENBQUMsQ0FBQyxFQUFFLGdCQUFnQixDQUFDO0FBQ25FLFlBQVk7QUFDWjtBQUNBLFFBQVEsS0FBSyxPQUFPO0FBQ3BCLFFBQVEsS0FBSyxPQUFPO0FBQ3BCLFFBQVEsS0FBSyxPQUFPLEVBQUU7QUFDdEIsWUFBWSxJQUFJLENBQUMsV0FBVyxDQUFDLEdBQUcsQ0FBQyxTQUFTLEVBQUUsU0FBUyxDQUFDO0FBQ3RELGdCQUFnQixNQUFNLFFBQVEsQ0FBQyxTQUFTLENBQUM7QUFDekMsWUFBWSxNQUFNLFFBQVEsR0FBRyxRQUFRLENBQUMsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxFQUFFLENBQUM7QUFDdkQsWUFBWSxNQUFNLE1BQU0sR0FBRyxhQUFhLENBQUMsR0FBRyxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUM7QUFDNUQsWUFBWSxJQUFJLE1BQU0sS0FBSyxRQUFRO0FBQ25DLGdCQUFnQixNQUFNLFFBQVEsQ0FBQyxDQUFDLElBQUksRUFBRSxRQUFRLENBQUMsQ0FBQyxFQUFFLGdCQUFnQixDQUFDO0FBQ25FLFlBQVk7QUFDWjtBQUNBLFFBQVEsS0FBSyxPQUFPLEVBQUU7QUFDdEIsWUFBWSxJQUFJLEdBQUcsQ0FBQyxTQUFTLENBQUMsSUFBSSxLQUFLLFNBQVMsSUFBSSxHQUFHLENBQUMsU0FBUyxDQUFDLElBQUksS0FBSyxPQUFPLEVBQUU7QUFDcEYsZ0JBQWdCLE1BQU0sUUFBUSxDQUFDLGtCQUFrQixDQUFDO0FBQ2xEO0FBQ0EsWUFBWTtBQUNaO0FBQ0EsUUFBUSxLQUFLLE9BQU87QUFDcEIsUUFBUSxLQUFLLE9BQU87QUFDcEIsUUFBUSxLQUFLLE9BQU8sRUFBRTtBQUN0QixZQUFZLElBQUksQ0FBQyxXQUFXLENBQUMsR0FBRyxDQUFDLFNBQVMsRUFBRSxPQUFPLENBQUM7QUFDcEQsZ0JBQWdCLE1BQU0sUUFBUSxDQUFDLE9BQU8sQ0FBQztBQUN2QyxZQUFZLE1BQU0sUUFBUSxHQUFHLGFBQWEsQ0FBQyxHQUFHLENBQUM7QUFDL0MsWUFBWSxNQUFNLE1BQU0sR0FBRyxHQUFHLENBQUMsU0FBUyxDQUFDLFVBQVU7QUFDbkQsWUFBWSxJQUFJLE1BQU0sS0FBSyxRQUFRO0FBQ25DLGdCQUFnQixNQUFNLFFBQVEsQ0FBQyxRQUFRLEVBQUUsc0JBQXNCLENBQUM7QUFDaEUsWUFBWTtBQUNaO0FBQ0EsUUFBUTtBQUNSLFlBQVksTUFBTSxJQUFJLFNBQVMsQ0FBQywyQ0FBMkMsQ0FBQztBQUM1RTtBQUNBLElBQUksVUFBVSxDQUFDLEdBQUcsRUFBRSxNQUFNLENBQUM7QUFDM0I7QUFDTyxTQUFTLGlCQUFpQixDQUFDLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxNQUFNLEVBQUU7QUFDdkQsSUFBSSxRQUFRLEdBQUc7QUFDZixRQUFRLEtBQUssU0FBUztBQUN0QixRQUFRLEtBQUssU0FBUztBQUN0QixRQUFRLEtBQUssU0FBUyxFQUFFO0FBQ3hCLFlBQVksSUFBSSxDQUFDLFdBQVcsQ0FBQyxHQUFHLENBQUMsU0FBUyxFQUFFLFNBQVMsQ0FBQztBQUN0RCxnQkFBZ0IsTUFBTSxRQUFRLENBQUMsU0FBUyxDQUFDO0FBQ3pDLFlBQVksTUFBTSxRQUFRLEdBQUcsUUFBUSxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxFQUFFLEVBQUUsQ0FBQztBQUMxRCxZQUFZLE1BQU0sTUFBTSxHQUFHLEdBQUcsQ0FBQyxTQUFTLENBQUMsTUFBTTtBQUMvQyxZQUFZLElBQUksTUFBTSxLQUFLLFFBQVE7QUFDbkMsZ0JBQWdCLE1BQU0sUUFBUSxDQUFDLFFBQVEsRUFBRSxrQkFBa0IsQ0FBQztBQUM1RCxZQUFZO0FBQ1o7QUFDQSxRQUFRLEtBQUssUUFBUTtBQUNyQixRQUFRLEtBQUssUUFBUTtBQUNyQixRQUFRLEtBQUssUUFBUSxFQUFFO0FBQ3ZCLFlBQVksSUFBSSxDQUFDLFdBQVcsQ0FBQyxHQUFHLENBQUMsU0FBUyxFQUFFLFFBQVEsQ0FBQztBQUNyRCxnQkFBZ0IsTUFBTSxRQUFRLENBQUMsUUFBUSxDQUFDO0FBQ3hDLFlBQVksTUFBTSxRQUFRLEdBQUcsUUFBUSxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxFQUFFLEVBQUUsQ0FBQztBQUMxRCxZQUFZLE1BQU0sTUFBTSxHQUFHLEdBQUcsQ0FBQyxTQUFTLENBQUMsTUFBTTtBQUMvQyxZQUFZLElBQUksTUFBTSxLQUFLLFFBQVE7QUFDbkMsZ0JBQWdCLE1BQU0sUUFBUSxDQUFDLFFBQVEsRUFBRSxrQkFBa0IsQ0FBQztBQUM1RCxZQUFZO0FBQ1o7QUFDQSxRQUFRLEtBQUssTUFBTSxFQUFFO0FBQ3JCLFlBQVksUUFBUSxHQUFHLENBQUMsU0FBUyxDQUFDLElBQUk7QUFDdEMsZ0JBQWdCLEtBQUssTUFBTTtBQUMzQixnQkFBZ0IsS0FBSyxRQUFRO0FBQzdCLGdCQUFnQixLQUFLLE1BQU07QUFDM0Isb0JBQW9CO0FBQ3BCLGdCQUFnQjtBQUNoQixvQkFBb0IsTUFBTSxRQUFRLENBQUMsdUJBQXVCLENBQUM7QUFDM0Q7QUFDQSxZQUFZO0FBQ1o7QUFDQSxRQUFRLEtBQUssb0JBQW9CO0FBQ2pDLFFBQVEsS0FBSyxvQkFBb0I7QUFDakMsUUFBUSxLQUFLLG9CQUFvQjtBQUNqQyxZQUFZLElBQUksQ0FBQyxXQUFXLENBQUMsR0FBRyxDQUFDLFNBQVMsRUFBRSxRQUFRLENBQUM7QUFDckQsZ0JBQWdCLE1BQU0sUUFBUSxDQUFDLFFBQVEsQ0FBQztBQUN4QyxZQUFZO0FBQ1osUUFBUSxLQUFLLFVBQVU7QUFDdkIsUUFBUSxLQUFLLGNBQWM7QUFDM0IsUUFBUSxLQUFLLGNBQWM7QUFDM0IsUUFBUSxLQUFLLGNBQWMsRUFBRTtBQUM3QixZQUFZLElBQUksQ0FBQyxXQUFXLENBQUMsR0FBRyxDQUFDLFNBQVMsRUFBRSxVQUFVLENBQUM7QUFDdkQsZ0JBQWdCLE1BQU0sUUFBUSxDQUFDLFVBQVUsQ0FBQztBQUMxQyxZQUFZLE1BQU0sUUFBUSxHQUFHLFFBQVEsQ0FBQyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxJQUFJLENBQUM7QUFDNUQsWUFBWSxNQUFNLE1BQU0sR0FBRyxhQUFhLENBQUMsR0FBRyxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUM7QUFDNUQsWUFBWSxJQUFJLE1BQU0sS0FBSyxRQUFRO0FBQ25DLGdCQUFnQixNQUFNLFFBQVEsQ0FBQyxDQUFDLElBQUksRUFBRSxRQUFRLENBQUMsQ0FBQyxFQUFFLGdCQUFnQixDQUFDO0FBQ25FLFlBQVk7QUFDWjtBQUNBLFFBQVE7QUFDUixZQUFZLE1BQU0sSUFBSSxTQUFTLENBQUMsMkNBQTJDLENBQUM7QUFDNUU7QUFDQSxJQUFJLFVBQVUsQ0FBQyxHQUFHLEVBQUUsTUFBTSxDQUFDO0FBQzNCOztBQ3ZKQSxTQUFTLE9BQU8sQ0FBQyxHQUFHLEVBQUUsTUFBTSxFQUFFLEdBQUcsS0FBSyxFQUFFO0FBQ3hDLElBQUksS0FBSyxHQUFHLEtBQUssQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDO0FBQ2pDLElBQUksSUFBSSxLQUFLLENBQUMsTUFBTSxHQUFHLENBQUMsRUFBRTtBQUMxQixRQUFRLE1BQU0sSUFBSSxHQUFHLEtBQUssQ0FBQyxHQUFHLEVBQUU7QUFDaEMsUUFBUSxHQUFHLElBQUksQ0FBQyxZQUFZLEVBQUUsS0FBSyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQyxLQUFLLEVBQUUsSUFBSSxDQUFDLENBQUMsQ0FBQztBQUM3RDtBQUNBLFNBQVMsSUFBSSxLQUFLLENBQUMsTUFBTSxLQUFLLENBQUMsRUFBRTtBQUNqQyxRQUFRLEdBQUcsSUFBSSxDQUFDLFlBQVksRUFBRSxLQUFLLENBQUMsQ0FBQyxDQUFDLENBQUMsSUFBSSxFQUFFLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7QUFDeEQ7QUFDQSxTQUFTO0FBQ1QsUUFBUSxHQUFHLElBQUksQ0FBQyxRQUFRLEVBQUUsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztBQUNyQztBQUNBLElBQUksSUFBSSxNQUFNLElBQUksSUFBSSxFQUFFO0FBQ3hCLFFBQVEsR0FBRyxJQUFJLENBQUMsVUFBVSxFQUFFLE1BQU0sQ0FBQyxDQUFDO0FBQ3BDO0FBQ0EsU0FBUyxJQUFJLE9BQU8sTUFBTSxLQUFLLFVBQVUsSUFBSSxNQUFNLENBQUMsSUFBSSxFQUFFO0FBQzFELFFBQVEsR0FBRyxJQUFJLENBQUMsbUJBQW1CLEVBQUUsTUFBTSxDQUFDLElBQUksQ0FBQyxDQUFDO0FBQ2xEO0FBQ0EsU0FBUyxJQUFJLE9BQU8sTUFBTSxLQUFLLFFBQVEsSUFBSSxNQUFNLElBQUksSUFBSSxFQUFFO0FBQzNELFFBQVEsSUFBSSxNQUFNLENBQUMsV0FBVyxFQUFFLElBQUksRUFBRTtBQUN0QyxZQUFZLEdBQUcsSUFBSSxDQUFDLHlCQUF5QixFQUFFLE1BQU0sQ0FBQyxXQUFXLENBQUMsSUFBSSxDQUFDLENBQUM7QUFDeEU7QUFDQTtBQUNBLElBQUksT0FBTyxHQUFHO0FBQ2Q7QUFDQSxzQkFBZSxDQUFDLE1BQU0sRUFBRSxHQUFHLEtBQUssS0FBSztBQUNyQyxJQUFJLE9BQU8sT0FBTyxDQUFDLGNBQWMsRUFBRSxNQUFNLEVBQUUsR0FBRyxLQUFLLENBQUM7QUFDcEQsQ0FBQztBQUNNLFNBQVMsT0FBTyxDQUFDLEdBQUcsRUFBRSxNQUFNLEVBQUUsR0FBRyxLQUFLLEVBQUU7QUFDL0MsSUFBSSxPQUFPLE9BQU8sQ0FBQyxDQUFDLFlBQVksRUFBRSxHQUFHLENBQUMsbUJBQW1CLENBQUMsRUFBRSxNQUFNLEVBQUUsR0FBRyxLQUFLLENBQUM7QUFDN0U7O0FDN0JBLGdCQUFlLENBQUMsR0FBRyxLQUFLO0FBQ3hCLElBQUksSUFBSSxXQUFXLENBQUMsR0FBRyxDQUFDLEVBQUU7QUFDMUIsUUFBUSxPQUFPLElBQUk7QUFDbkI7QUFDQSxJQUFJLE9BQU8sR0FBRyxHQUFHLE1BQU0sQ0FBQyxXQUFXLENBQUMsS0FBSyxXQUFXO0FBQ3BELENBQUM7QUFDTSxNQUFNLEtBQUssR0FBRyxDQUFDLFdBQVcsQ0FBQzs7QUNFbEMsZUFBZSxVQUFVLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxVQUFVLEVBQUUsRUFBRSxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUU7QUFDOUQsSUFBSSxJQUFJLEVBQUUsR0FBRyxZQUFZLFVBQVUsQ0FBQyxFQUFFO0FBQ3RDLFFBQVEsTUFBTSxJQUFJLFNBQVMsQ0FBQyxlQUFlLENBQUMsR0FBRyxFQUFFLFlBQVksQ0FBQyxDQUFDO0FBQy9EO0FBQ0EsSUFBSSxNQUFNLE9BQU8sR0FBRyxRQUFRLENBQUMsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLEVBQUUsRUFBRSxDQUFDO0FBQ2pELElBQUksTUFBTSxNQUFNLEdBQUcsTUFBTUgsUUFBTSxDQUFDLE1BQU0sQ0FBQyxTQUFTLENBQUMsS0FBSyxFQUFFLEdBQUcsQ0FBQyxRQUFRLENBQUMsT0FBTyxJQUFJLENBQUMsQ0FBQyxFQUFFLFNBQVMsRUFBRSxLQUFLLEVBQUUsQ0FBQyxTQUFTLENBQUMsQ0FBQztBQUNsSCxJQUFJLE1BQU0sTUFBTSxHQUFHLE1BQU1BLFFBQU0sQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUFDLEtBQUssRUFBRSxHQUFHLENBQUMsUUFBUSxDQUFDLENBQUMsRUFBRSxPQUFPLElBQUksQ0FBQyxDQUFDLEVBQUU7QUFDdkYsUUFBUSxJQUFJLEVBQUUsQ0FBQyxJQUFJLEVBQUUsT0FBTyxJQUFJLENBQUMsQ0FBQyxDQUFDO0FBQ25DLFFBQVEsSUFBSSxFQUFFLE1BQU07QUFDcEIsS0FBSyxFQUFFLEtBQUssRUFBRSxDQUFDLE1BQU0sQ0FBQyxDQUFDO0FBQ3ZCLElBQUksTUFBTSxPQUFPLEdBQUcsTUFBTSxDQUFDLEdBQUcsRUFBRSxFQUFFLEVBQUUsVUFBVSxFQUFFLFFBQVEsQ0FBQyxHQUFHLENBQUMsTUFBTSxJQUFJLENBQUMsQ0FBQyxDQUFDO0FBQzFFLElBQUksTUFBTSxXQUFXLEdBQUcsSUFBSSxVQUFVLENBQUMsQ0FBQyxNQUFNQSxRQUFNLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLEVBQUUsTUFBTSxFQUFFLE9BQU8sQ0FBQyxFQUFFLEtBQUssQ0FBQyxDQUFDLEVBQUUsT0FBTyxJQUFJLENBQUMsQ0FBQyxDQUFDO0FBQ2xILElBQUksSUFBSSxjQUFjO0FBQ3RCLElBQUksSUFBSTtBQUNSLFFBQVEsY0FBYyxHQUFHLGVBQWUsQ0FBQyxHQUFHLEVBQUUsV0FBVyxDQUFDO0FBQzFEO0FBQ0EsSUFBSSxNQUFNO0FBQ1Y7QUFDQSxJQUFJLElBQUksQ0FBQyxjQUFjLEVBQUU7QUFDekIsUUFBUSxNQUFNLElBQUksbUJBQW1CLEVBQUU7QUFDdkM7QUFDQSxJQUFJLElBQUksU0FBUztBQUNqQixJQUFJLElBQUk7QUFDUixRQUFRLFNBQVMsR0FBRyxJQUFJLFVBQVUsQ0FBQyxNQUFNQSxRQUFNLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQyxFQUFFLEVBQUUsRUFBRSxJQUFJLEVBQUUsU0FBUyxFQUFFLEVBQUUsTUFBTSxFQUFFLFVBQVUsQ0FBQyxDQUFDO0FBQzVHO0FBQ0EsSUFBSSxNQUFNO0FBQ1Y7QUFDQSxJQUFJLElBQUksQ0FBQyxTQUFTLEVBQUU7QUFDcEIsUUFBUSxNQUFNLElBQUksbUJBQW1CLEVBQUU7QUFDdkM7QUFDQSxJQUFJLE9BQU8sU0FBUztBQUNwQjtBQUNBLGVBQWUsVUFBVSxDQUFDLEdBQUcsRUFBRSxHQUFHLEVBQUUsVUFBVSxFQUFFLEVBQUUsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFO0FBQzlELElBQUksSUFBSSxNQUFNO0FBQ2QsSUFBSSxJQUFJLEdBQUcsWUFBWSxVQUFVLEVBQUU7QUFDbkMsUUFBUSxNQUFNLEdBQUcsTUFBTUEsUUFBTSxDQUFDLE1BQU0sQ0FBQyxTQUFTLENBQUMsS0FBSyxFQUFFLEdBQUcsRUFBRSxTQUFTLEVBQUUsS0FBSyxFQUFFLENBQUMsU0FBUyxDQUFDLENBQUM7QUFDekY7QUFDQSxTQUFTO0FBQ1QsUUFBUSxpQkFBaUIsQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFLFNBQVMsQ0FBQztBQUM5QyxRQUFRLE1BQU0sR0FBRyxHQUFHO0FBQ3BCO0FBQ0EsSUFBSSxJQUFJO0FBQ1IsUUFBUSxPQUFPLElBQUksVUFBVSxDQUFDLE1BQU1BLFFBQU0sQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDO0FBQzFELFlBQVksY0FBYyxFQUFFLEdBQUc7QUFDL0IsWUFBWSxFQUFFO0FBQ2QsWUFBWSxJQUFJLEVBQUUsU0FBUztBQUMzQixZQUFZLFNBQVMsRUFBRSxHQUFHO0FBQzFCLFNBQVMsRUFBRSxNQUFNLEVBQUUsTUFBTSxDQUFDLFVBQVUsRUFBRSxHQUFHLENBQUMsQ0FBQyxDQUFDO0FBQzVDO0FBQ0EsSUFBSSxNQUFNO0FBQ1YsUUFBUSxNQUFNLElBQUksbUJBQW1CLEVBQUU7QUFDdkM7QUFDQTtBQUNBLE1BQU1JLFNBQU8sR0FBRyxPQUFPLEdBQUcsRUFBRSxHQUFHLEVBQUUsVUFBVSxFQUFFLEVBQUUsRUFBRSxHQUFHLEVBQUUsR0FBRyxLQUFLO0FBQzlELElBQUksSUFBSSxDQUFDLFdBQVcsQ0FBQyxHQUFHLENBQUMsSUFBSSxFQUFFLEdBQUcsWUFBWSxVQUFVLENBQUMsRUFBRTtBQUMzRCxRQUFRLE1BQU0sSUFBSSxTQUFTLENBQUMsZUFBZSxDQUFDLEdBQUcsRUFBRSxHQUFHLEtBQUssRUFBRSxZQUFZLENBQUMsQ0FBQztBQUN6RTtBQUNBLElBQUksSUFBSSxDQUFDLEVBQUUsRUFBRTtBQUNiLFFBQVEsTUFBTSxJQUFJLFVBQVUsQ0FBQyxtQ0FBbUMsQ0FBQztBQUNqRTtBQUNBLElBQUksSUFBSSxDQUFDLEdBQUcsRUFBRTtBQUNkLFFBQVEsTUFBTSxJQUFJLFVBQVUsQ0FBQyxnQ0FBZ0MsQ0FBQztBQUM5RDtBQUNBLElBQUksYUFBYSxDQUFDLEdBQUcsRUFBRSxFQUFFLENBQUM7QUFDMUIsSUFBSSxRQUFRLEdBQUc7QUFDZixRQUFRLEtBQUssZUFBZTtBQUM1QixRQUFRLEtBQUssZUFBZTtBQUM1QixRQUFRLEtBQUssZUFBZTtBQUM1QixZQUFZLElBQUksR0FBRyxZQUFZLFVBQVU7QUFDekMsZ0JBQWdCLGNBQWMsQ0FBQyxHQUFHLEVBQUUsUUFBUSxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsRUFBRSxDQUFDLEVBQUUsRUFBRSxDQUFDLENBQUM7QUFDaEUsWUFBWSxPQUFPLFVBQVUsQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFLFVBQVUsRUFBRSxFQUFFLEVBQUUsR0FBRyxFQUFFLEdBQUcsQ0FBQztBQUNqRSxRQUFRLEtBQUssU0FBUztBQUN0QixRQUFRLEtBQUssU0FBUztBQUN0QixRQUFRLEtBQUssU0FBUztBQUN0QixZQUFZLElBQUksR0FBRyxZQUFZLFVBQVU7QUFDekMsZ0JBQWdCLGNBQWMsQ0FBQyxHQUFHLEVBQUUsUUFBUSxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxDQUFDO0FBQ2xFLFlBQVksT0FBTyxVQUFVLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxVQUFVLEVBQUUsRUFBRSxFQUFFLEdBQUcsRUFBRSxHQUFHLENBQUM7QUFDakUsUUFBUTtBQUNSLFlBQVksTUFBTSxJQUFJLGdCQUFnQixDQUFDLDhDQUE4QyxDQUFDO0FBQ3RGO0FBQ0EsQ0FBQzs7QUN6RkQsTUFBTSxVQUFVLEdBQUcsQ0FBQyxHQUFHLE9BQU8sS0FBSztBQUNuQyxJQUFJLE1BQU0sT0FBTyxHQUFHLE9BQU8sQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDO0FBQzNDLElBQUksSUFBSSxPQUFPLENBQUMsTUFBTSxLQUFLLENBQUMsSUFBSSxPQUFPLENBQUMsTUFBTSxLQUFLLENBQUMsRUFBRTtBQUN0RCxRQUFRLE9BQU8sSUFBSTtBQUNuQjtBQUNBLElBQUksSUFBSSxHQUFHO0FBQ1gsSUFBSSxLQUFLLE1BQU0sTUFBTSxJQUFJLE9BQU8sRUFBRTtBQUNsQyxRQUFRLE1BQU0sVUFBVSxHQUFHLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDO0FBQzlDLFFBQVEsSUFBSSxDQUFDLEdBQUcsSUFBSSxHQUFHLENBQUMsSUFBSSxLQUFLLENBQUMsRUFBRTtBQUNwQyxZQUFZLEdBQUcsR0FBRyxJQUFJLEdBQUcsQ0FBQyxVQUFVLENBQUM7QUFDckMsWUFBWTtBQUNaO0FBQ0EsUUFBUSxLQUFLLE1BQU0sU0FBUyxJQUFJLFVBQVUsRUFBRTtBQUM1QyxZQUFZLElBQUksR0FBRyxDQUFDLEdBQUcsQ0FBQyxTQUFTLENBQUMsRUFBRTtBQUNwQyxnQkFBZ0IsT0FBTyxLQUFLO0FBQzVCO0FBQ0EsWUFBWSxHQUFHLENBQUMsR0FBRyxDQUFDLFNBQVMsQ0FBQztBQUM5QjtBQUNBO0FBQ0EsSUFBSSxPQUFPLElBQUk7QUFDZixDQUFDOztBQ3BCRCxTQUFTLFlBQVksQ0FBQyxLQUFLLEVBQUU7QUFDN0IsSUFBSSxPQUFPLE9BQU8sS0FBSyxLQUFLLFFBQVEsSUFBSSxLQUFLLEtBQUssSUFBSTtBQUN0RDtBQUNlLFNBQVMsUUFBUSxDQUFDLEtBQUssRUFBRTtBQUN4QyxJQUFJLElBQUksQ0FBQyxZQUFZLENBQUMsS0FBSyxDQUFDLElBQUksTUFBTSxDQUFDLFNBQVMsQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxLQUFLLGlCQUFpQixFQUFFO0FBQzdGLFFBQVEsT0FBTyxLQUFLO0FBQ3BCO0FBQ0EsSUFBSSxJQUFJLE1BQU0sQ0FBQyxjQUFjLENBQUMsS0FBSyxDQUFDLEtBQUssSUFBSSxFQUFFO0FBQy9DLFFBQVEsT0FBTyxJQUFJO0FBQ25CO0FBQ0EsSUFBSSxJQUFJLEtBQUssR0FBRyxLQUFLO0FBQ3JCLElBQUksT0FBTyxNQUFNLENBQUMsY0FBYyxDQUFDLEtBQUssQ0FBQyxLQUFLLElBQUksRUFBRTtBQUNsRCxRQUFRLEtBQUssR0FBRyxNQUFNLENBQUMsY0FBYyxDQUFDLEtBQUssQ0FBQztBQUM1QztBQUNBLElBQUksT0FBTyxNQUFNLENBQUMsY0FBYyxDQUFDLEtBQUssQ0FBQyxLQUFLLEtBQUs7QUFDakQ7O0FDZkEsTUFBTSxjQUFjLEdBQUc7QUFDdkIsSUFBSSxFQUFFLElBQUksRUFBRSxTQUFTLEVBQUUsSUFBSSxFQUFFLE1BQU0sRUFBRTtBQUNyQyxJQUFJLElBQUk7QUFDUixJQUFJLENBQUMsTUFBTSxDQUFDO0FBQ1osQ0FBQzs7QUNDRCxTQUFTLFlBQVksQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFO0FBQ2hDLElBQUksSUFBSSxHQUFHLENBQUMsU0FBUyxDQUFDLE1BQU0sS0FBSyxRQUFRLENBQUMsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLEVBQUUsRUFBRSxDQUFDLEVBQUU7QUFDaEUsUUFBUSxNQUFNLElBQUksU0FBUyxDQUFDLENBQUMsMEJBQTBCLEVBQUUsR0FBRyxDQUFDLENBQUMsQ0FBQztBQUMvRDtBQUNBO0FBQ0EsU0FBU0MsY0FBWSxDQUFDLEdBQUcsRUFBRSxHQUFHLEVBQUUsS0FBSyxFQUFFO0FBQ3ZDLElBQUksSUFBSSxXQUFXLENBQUMsR0FBRyxDQUFDLEVBQUU7QUFDMUIsUUFBUSxpQkFBaUIsQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFLEtBQUssQ0FBQztBQUMxQyxRQUFRLE9BQU8sR0FBRztBQUNsQjtBQUNBLElBQUksSUFBSSxHQUFHLFlBQVksVUFBVSxFQUFFO0FBQ25DLFFBQVEsT0FBT0wsUUFBTSxDQUFDLE1BQU0sQ0FBQyxTQUFTLENBQUMsS0FBSyxFQUFFLEdBQUcsRUFBRSxRQUFRLEVBQUUsSUFBSSxFQUFFLENBQUMsS0FBSyxDQUFDLENBQUM7QUFDM0U7QUFDQSxJQUFJLE1BQU0sSUFBSSxTQUFTLENBQUMsZUFBZSxDQUFDLEdBQUcsRUFBRSxHQUFHLEtBQUssRUFBRSxZQUFZLENBQUMsQ0FBQztBQUNyRTtBQUNPLE1BQU1NLE1BQUksR0FBRyxPQUFPLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxLQUFLO0FBQzdDLElBQUksTUFBTSxTQUFTLEdBQUcsTUFBTUQsY0FBWSxDQUFDLEdBQUcsRUFBRSxHQUFHLEVBQUUsU0FBUyxDQUFDO0FBQzdELElBQUksWUFBWSxDQUFDLFNBQVMsRUFBRSxHQUFHLENBQUM7QUFDaEMsSUFBSSxNQUFNLFlBQVksR0FBRyxNQUFNTCxRQUFNLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FBQyxLQUFLLEVBQUUsR0FBRyxFQUFFLEdBQUcsY0FBYyxDQUFDO0FBQ3JGLElBQUksT0FBTyxJQUFJLFVBQVUsQ0FBQyxNQUFNQSxRQUFNLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQyxLQUFLLEVBQUUsWUFBWSxFQUFFLFNBQVMsRUFBRSxRQUFRLENBQUMsQ0FBQztBQUNoRyxDQUFDO0FBQ00sTUFBTU8sUUFBTSxHQUFHLE9BQU8sR0FBRyxFQUFFLEdBQUcsRUFBRSxZQUFZLEtBQUs7QUFDeEQsSUFBSSxNQUFNLFNBQVMsR0FBRyxNQUFNRixjQUFZLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxXQUFXLENBQUM7QUFDL0QsSUFBSSxZQUFZLENBQUMsU0FBUyxFQUFFLEdBQUcsQ0FBQztBQUNoQyxJQUFJLE1BQU0sWUFBWSxHQUFHLE1BQU1MLFFBQU0sQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUFDLEtBQUssRUFBRSxZQUFZLEVBQUUsU0FBUyxFQUFFLFFBQVEsRUFBRSxHQUFHLGNBQWMsQ0FBQztBQUNuSCxJQUFJLE9BQU8sSUFBSSxVQUFVLENBQUMsTUFBTUEsUUFBTSxDQUFDLE1BQU0sQ0FBQyxTQUFTLENBQUMsS0FBSyxFQUFFLFlBQVksQ0FBQyxDQUFDO0FBQzdFLENBQUM7O0FDMUJNLGVBQWVRLFdBQVMsQ0FBQyxTQUFTLEVBQUUsVUFBVSxFQUFFLFNBQVMsRUFBRSxTQUFTLEVBQUUsR0FBRyxHQUFHLElBQUksVUFBVSxDQUFDLENBQUMsQ0FBQyxFQUFFLEdBQUcsR0FBRyxJQUFJLFVBQVUsQ0FBQyxDQUFDLENBQUMsRUFBRTtBQUMvSCxJQUFJLElBQUksQ0FBQyxXQUFXLENBQUMsU0FBUyxDQUFDLEVBQUU7QUFDakMsUUFBUSxNQUFNLElBQUksU0FBUyxDQUFDLGVBQWUsQ0FBQyxTQUFTLEVBQUUsR0FBRyxLQUFLLENBQUMsQ0FBQztBQUNqRTtBQUNBLElBQUksaUJBQWlCLENBQUMsU0FBUyxFQUFFLE1BQU0sQ0FBQztBQUN4QyxJQUFJLElBQUksQ0FBQyxXQUFXLENBQUMsVUFBVSxDQUFDLEVBQUU7QUFDbEMsUUFBUSxNQUFNLElBQUksU0FBUyxDQUFDLGVBQWUsQ0FBQyxVQUFVLEVBQUUsR0FBRyxLQUFLLENBQUMsQ0FBQztBQUNsRTtBQUNBLElBQUksaUJBQWlCLENBQUMsVUFBVSxFQUFFLE1BQU0sRUFBRSxZQUFZLENBQUM7QUFDdkQsSUFBSSxNQUFNLEtBQUssR0FBRyxNQUFNLENBQUMsY0FBYyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUFDLENBQUMsRUFBRSxjQUFjLENBQUMsR0FBRyxDQUFDLEVBQUUsY0FBYyxDQUFDLEdBQUcsQ0FBQyxFQUFFLFFBQVEsQ0FBQyxTQUFTLENBQUMsQ0FBQztBQUNsSSxJQUFJLElBQUksTUFBTTtBQUNkLElBQUksSUFBSSxTQUFTLENBQUMsU0FBUyxDQUFDLElBQUksS0FBSyxRQUFRLEVBQUU7QUFDL0MsUUFBUSxNQUFNLEdBQUcsR0FBRztBQUNwQjtBQUNBLFNBQVMsSUFBSSxTQUFTLENBQUMsU0FBUyxDQUFDLElBQUksS0FBSyxNQUFNLEVBQUU7QUFDbEQsUUFBUSxNQUFNLEdBQUcsR0FBRztBQUNwQjtBQUNBLFNBQVM7QUFDVCxRQUFRLE1BQU07QUFDZCxZQUFZLElBQUksQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLFNBQVMsQ0FBQyxTQUFTLENBQUMsVUFBVSxDQUFDLE1BQU0sQ0FBQyxFQUFFLENBQUMsRUFBRSxFQUFFLENBQUMsR0FBRyxDQUFDLENBQUM7QUFDbEYsZ0JBQWdCLENBQUM7QUFDakI7QUFDQSxJQUFJLE1BQU0sWUFBWSxHQUFHLElBQUksVUFBVSxDQUFDLE1BQU1SLFFBQU0sQ0FBQyxNQUFNLENBQUMsVUFBVSxDQUFDO0FBQ3ZFLFFBQVEsSUFBSSxFQUFFLFNBQVMsQ0FBQyxTQUFTLENBQUMsSUFBSTtBQUN0QyxRQUFRLE1BQU0sRUFBRSxTQUFTO0FBQ3pCLEtBQUssRUFBRSxVQUFVLEVBQUUsTUFBTSxDQUFDLENBQUM7QUFDM0IsSUFBSSxPQUFPLFNBQVMsQ0FBQyxZQUFZLEVBQUUsU0FBUyxFQUFFLEtBQUssQ0FBQztBQUNwRDtBQUNPLGVBQWUsV0FBVyxDQUFDLEdBQUcsRUFBRTtBQUN2QyxJQUFJLElBQUksQ0FBQyxXQUFXLENBQUMsR0FBRyxDQUFDLEVBQUU7QUFDM0IsUUFBUSxNQUFNLElBQUksU0FBUyxDQUFDLGVBQWUsQ0FBQyxHQUFHLEVBQUUsR0FBRyxLQUFLLENBQUMsQ0FBQztBQUMzRDtBQUNBLElBQUksT0FBT0EsUUFBTSxDQUFDLE1BQU0sQ0FBQyxXQUFXLENBQUMsR0FBRyxDQUFDLFNBQVMsRUFBRSxJQUFJLEVBQUUsQ0FBQyxZQUFZLENBQUMsQ0FBQztBQUN6RTtBQUNPLFNBQVMsV0FBVyxDQUFDLEdBQUcsRUFBRTtBQUNqQyxJQUFJLElBQUksQ0FBQyxXQUFXLENBQUMsR0FBRyxDQUFDLEVBQUU7QUFDM0IsUUFBUSxNQUFNLElBQUksU0FBUyxDQUFDLGVBQWUsQ0FBQyxHQUFHLEVBQUUsR0FBRyxLQUFLLENBQUMsQ0FBQztBQUMzRDtBQUNBLElBQUksUUFBUSxDQUFDLE9BQU8sRUFBRSxPQUFPLEVBQUUsT0FBTyxDQUFDLENBQUMsUUFBUSxDQUFDLEdBQUcsQ0FBQyxTQUFTLENBQUMsVUFBVSxDQUFDO0FBQzFFLFFBQVEsR0FBRyxDQUFDLFNBQVMsQ0FBQyxJQUFJLEtBQUssUUFBUTtBQUN2QyxRQUFRLEdBQUcsQ0FBQyxTQUFTLENBQUMsSUFBSSxLQUFLLE1BQU07QUFDckM7O0FDN0NlLFNBQVMsUUFBUSxDQUFDLEdBQUcsRUFBRTtBQUN0QyxJQUFJLElBQUksRUFBRSxHQUFHLFlBQVksVUFBVSxDQUFDLElBQUksR0FBRyxDQUFDLE1BQU0sR0FBRyxDQUFDLEVBQUU7QUFDeEQsUUFBUSxNQUFNLElBQUksVUFBVSxDQUFDLDJDQUEyQyxDQUFDO0FBQ3pFO0FBQ0E7O0FDSUEsU0FBU0ssY0FBWSxDQUFDLEdBQUcsRUFBRSxHQUFHLEVBQUU7QUFDaEMsSUFBSSxJQUFJLEdBQUcsWUFBWSxVQUFVLEVBQUU7QUFDbkMsUUFBUSxPQUFPTCxRQUFNLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FBQyxLQUFLLEVBQUUsR0FBRyxFQUFFLFFBQVEsRUFBRSxLQUFLLEVBQUUsQ0FBQyxZQUFZLENBQUMsQ0FBQztBQUNuRjtBQUNBLElBQUksSUFBSSxXQUFXLENBQUMsR0FBRyxDQUFDLEVBQUU7QUFDMUIsUUFBUSxpQkFBaUIsQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFLFlBQVksRUFBRSxXQUFXLENBQUM7QUFDOUQsUUFBUSxPQUFPLEdBQUc7QUFDbEI7QUFDQSxJQUFJLE1BQU0sSUFBSSxTQUFTLENBQUMsZUFBZSxDQUFDLEdBQUcsRUFBRSxHQUFHLEtBQUssRUFBRSxZQUFZLENBQUMsQ0FBQztBQUNyRTtBQUNBLGVBQWUsU0FBUyxDQUFDUyxLQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUU7QUFDN0MsSUFBSSxRQUFRLENBQUNBLEtBQUcsQ0FBQztBQUNqQixJQUFJLE1BQU0sSUFBSSxHQUFHQyxHQUFVLENBQUMsR0FBRyxFQUFFRCxLQUFHLENBQUM7QUFDckMsSUFBSSxNQUFNLE1BQU0sR0FBRyxRQUFRLENBQUMsR0FBRyxDQUFDLEtBQUssQ0FBQyxFQUFFLEVBQUUsRUFBRSxDQUFDLEVBQUUsRUFBRSxDQUFDO0FBQ2xELElBQUksTUFBTSxTQUFTLEdBQUc7QUFDdEIsUUFBUSxJQUFJLEVBQUUsQ0FBQyxJQUFJLEVBQUUsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsRUFBRSxDQUFDLENBQUMsQ0FBQztBQUN2QyxRQUFRLFVBQVUsRUFBRSxHQUFHO0FBQ3ZCLFFBQVEsSUFBSSxFQUFFLFFBQVE7QUFDdEIsUUFBUSxJQUFJO0FBQ1osS0FBSztBQUNMLElBQUksTUFBTSxPQUFPLEdBQUc7QUFDcEIsUUFBUSxNQUFNLEVBQUUsTUFBTTtBQUN0QixRQUFRLElBQUksRUFBRSxRQUFRO0FBQ3RCLEtBQUs7QUFDTCxJQUFJLE1BQU0sU0FBUyxHQUFHLE1BQU1KLGNBQVksQ0FBQyxHQUFHLEVBQUUsR0FBRyxDQUFDO0FBQ2xELElBQUksSUFBSSxTQUFTLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxZQUFZLENBQUMsRUFBRTtBQUNqRCxRQUFRLE9BQU8sSUFBSSxVQUFVLENBQUMsTUFBTUwsUUFBTSxDQUFDLE1BQU0sQ0FBQyxVQUFVLENBQUMsU0FBUyxFQUFFLFNBQVMsRUFBRSxNQUFNLENBQUMsQ0FBQztBQUMzRjtBQUNBLElBQUksSUFBSSxTQUFTLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxXQUFXLENBQUMsRUFBRTtBQUNoRCxRQUFRLE9BQU9BLFFBQU0sQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUFDLFNBQVMsRUFBRSxTQUFTLEVBQUUsT0FBTyxFQUFFLEtBQUssRUFBRSxDQUFDLFNBQVMsRUFBRSxXQUFXLENBQUMsQ0FBQztBQUN0RztBQUNBLElBQUksTUFBTSxJQUFJLFNBQVMsQ0FBQyw4REFBOEQsQ0FBQztBQUN2RjtBQUNPLE1BQU1XLFNBQU8sR0FBRyxPQUFPLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUcsR0FBRyxJQUFJLEVBQUUsR0FBRyxHQUFHLE1BQU0sQ0FBQyxJQUFJLFVBQVUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxLQUFLO0FBQzlGLElBQUksTUFBTSxPQUFPLEdBQUcsTUFBTSxTQUFTLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxDQUFDO0FBQ3ZELElBQUksTUFBTSxZQUFZLEdBQUcsTUFBTUwsTUFBSSxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsRUFBRSxDQUFDLEVBQUUsT0FBTyxFQUFFLEdBQUcsQ0FBQztBQUNoRSxJQUFJLE9BQU8sRUFBRSxZQUFZLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRU0sUUFBUyxDQUFDLEdBQUcsQ0FBQyxFQUFFO0FBQ3JELENBQUM7QUFDTSxNQUFNUixTQUFPLEdBQUcsT0FBTyxHQUFHLEVBQUUsR0FBRyxFQUFFLFlBQVksRUFBRSxHQUFHLEVBQUUsR0FBRyxLQUFLO0FBQ25FLElBQUksTUFBTSxPQUFPLEdBQUcsTUFBTSxTQUFTLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxDQUFDO0FBQ3ZELElBQUksT0FBT0csUUFBTSxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsRUFBRSxDQUFDLEVBQUUsT0FBTyxFQUFFLFlBQVksQ0FBQztBQUN2RCxDQUFDOztBQ2pEYyxTQUFTLFdBQVcsQ0FBQyxHQUFHLEVBQUU7QUFDekMsSUFBSSxRQUFRLEdBQUc7QUFDZixRQUFRLEtBQUssVUFBVTtBQUN2QixRQUFRLEtBQUssY0FBYztBQUMzQixRQUFRLEtBQUssY0FBYztBQUMzQixRQUFRLEtBQUssY0FBYztBQUMzQixZQUFZLE9BQU8sVUFBVTtBQUM3QixRQUFRO0FBQ1IsWUFBWSxNQUFNLElBQUksZ0JBQWdCLENBQUMsQ0FBQyxJQUFJLEVBQUUsR0FBRyxDQUFDLDJEQUEyRCxDQUFDLENBQUM7QUFDL0c7QUFDQTs7QUNYQSxxQkFBZSxDQUFDLEdBQUcsRUFBRSxHQUFHLEtBQUs7QUFDN0IsSUFBSSxJQUFJLEdBQUcsQ0FBQyxVQUFVLENBQUMsSUFBSSxDQUFDLElBQUksR0FBRyxDQUFDLFVBQVUsQ0FBQyxJQUFJLENBQUMsRUFBRTtBQUN0RCxRQUFRLE1BQU0sRUFBRSxhQUFhLEVBQUUsR0FBRyxHQUFHLENBQUMsU0FBUztBQUMvQyxRQUFRLElBQUksT0FBTyxhQUFhLEtBQUssUUFBUSxJQUFJLGFBQWEsR0FBRyxJQUFJLEVBQUU7QUFDdkUsWUFBWSxNQUFNLElBQUksU0FBUyxDQUFDLENBQUMsRUFBRSxHQUFHLENBQUMscURBQXFELENBQUMsQ0FBQztBQUM5RjtBQUNBO0FBQ0EsQ0FBQzs7QUNBTSxNQUFNSSxTQUFPLEdBQUcsT0FBTyxHQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUcsS0FBSztBQUNoRCxJQUFJLElBQUksQ0FBQyxXQUFXLENBQUMsR0FBRyxDQUFDLEVBQUU7QUFDM0IsUUFBUSxNQUFNLElBQUksU0FBUyxDQUFDLGVBQWUsQ0FBQyxHQUFHLEVBQUUsR0FBRyxLQUFLLENBQUMsQ0FBQztBQUMzRDtBQUNBLElBQUksaUJBQWlCLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxTQUFTLEVBQUUsU0FBUyxDQUFDO0FBQ3JELElBQUksY0FBYyxDQUFDLEdBQUcsRUFBRSxHQUFHLENBQUM7QUFDNUIsSUFBSSxJQUFJLEdBQUcsQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLFNBQVMsQ0FBQyxFQUFFO0FBQ3hDLFFBQVEsT0FBTyxJQUFJLFVBQVUsQ0FBQyxNQUFNWCxRQUFNLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQ2EsV0FBZSxDQUFDLEdBQUcsQ0FBQyxFQUFFLEdBQUcsRUFBRSxHQUFHLENBQUMsQ0FBQztBQUMxRjtBQUNBLElBQUksSUFBSSxHQUFHLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxTQUFTLENBQUMsRUFBRTtBQUN4QyxRQUFRLE1BQU0sWUFBWSxHQUFHLE1BQU1iLFFBQU0sQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUFDLEtBQUssRUFBRSxHQUFHLEVBQUUsR0FBRyxjQUFjLENBQUM7QUFDekYsUUFBUSxPQUFPLElBQUksVUFBVSxDQUFDLE1BQU1BLFFBQU0sQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLEtBQUssRUFBRSxZQUFZLEVBQUUsR0FBRyxFQUFFYSxXQUFlLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQztBQUMxRztBQUNBLElBQUksTUFBTSxJQUFJLFNBQVMsQ0FBQyw4RUFBOEUsQ0FBQztBQUN2RyxDQUFDO0FBQ00sTUFBTSxPQUFPLEdBQUcsT0FBTyxHQUFHLEVBQUUsR0FBRyxFQUFFLFlBQVksS0FBSztBQUN6RCxJQUFJLElBQUksQ0FBQyxXQUFXLENBQUMsR0FBRyxDQUFDLEVBQUU7QUFDM0IsUUFBUSxNQUFNLElBQUksU0FBUyxDQUFDLGVBQWUsQ0FBQyxHQUFHLEVBQUUsR0FBRyxLQUFLLENBQUMsQ0FBQztBQUMzRDtBQUNBLElBQUksaUJBQWlCLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxTQUFTLEVBQUUsV0FBVyxDQUFDO0FBQ3ZELElBQUksY0FBYyxDQUFDLEdBQUcsRUFBRSxHQUFHLENBQUM7QUFDNUIsSUFBSSxJQUFJLEdBQUcsQ0FBQyxNQUFNLENBQUMsUUFBUSxDQUFDLFNBQVMsQ0FBQyxFQUFFO0FBQ3hDLFFBQVEsT0FBTyxJQUFJLFVBQVUsQ0FBQyxNQUFNYixRQUFNLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQ2EsV0FBZSxDQUFDLEdBQUcsQ0FBQyxFQUFFLEdBQUcsRUFBRSxZQUFZLENBQUMsQ0FBQztBQUNuRztBQUNBLElBQUksSUFBSSxHQUFHLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxXQUFXLENBQUMsRUFBRTtBQUMxQyxRQUFRLE1BQU0sWUFBWSxHQUFHLE1BQU1iLFFBQU0sQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUFDLEtBQUssRUFBRSxZQUFZLEVBQUUsR0FBRyxFQUFFYSxXQUFlLENBQUMsR0FBRyxDQUFDLEVBQUUsR0FBRyxjQUFjLENBQUM7QUFDN0gsUUFBUSxPQUFPLElBQUksVUFBVSxDQUFDLE1BQU1iLFFBQU0sQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUFDLEtBQUssRUFBRSxZQUFZLENBQUMsQ0FBQztBQUNqRjtBQUNBLElBQUksTUFBTSxJQUFJLFNBQVMsQ0FBQyxnRkFBZ0YsQ0FBQztBQUN6RyxDQUFDOztBQ25DTSxTQUFTLEtBQUssQ0FBQyxHQUFHLEVBQUU7QUFDM0IsSUFBSSxPQUFPLFFBQVEsQ0FBQyxHQUFHLENBQUMsSUFBSSxPQUFPLEdBQUcsQ0FBQyxHQUFHLEtBQUssUUFBUTtBQUN2RDtBQUNPLFNBQVMsWUFBWSxDQUFDLEdBQUcsRUFBRTtBQUNsQyxJQUFJLE9BQU8sR0FBRyxDQUFDLEdBQUcsS0FBSyxLQUFLLElBQUksT0FBTyxHQUFHLENBQUMsQ0FBQyxLQUFLLFFBQVE7QUFDekQ7QUFDTyxTQUFTLFdBQVcsQ0FBQyxHQUFHLEVBQUU7QUFDakMsSUFBSSxPQUFPLEdBQUcsQ0FBQyxHQUFHLEtBQUssS0FBSyxJQUFJLE9BQU8sR0FBRyxDQUFDLENBQUMsS0FBSyxXQUFXO0FBQzVEO0FBQ08sU0FBUyxXQUFXLENBQUMsR0FBRyxFQUFFO0FBQ2pDLElBQUksT0FBTyxLQUFLLENBQUMsR0FBRyxDQUFDLElBQUksR0FBRyxDQUFDLEdBQUcsS0FBSyxLQUFLLElBQUksT0FBTyxHQUFHLENBQUMsQ0FBQyxLQUFLLFFBQVE7QUFDdkU7O0FDVkEsU0FBUyxhQUFhLENBQUMsR0FBRyxFQUFFO0FBQzVCLElBQUksSUFBSSxTQUFTO0FBQ2pCLElBQUksSUFBSSxTQUFTO0FBQ2pCLElBQUksUUFBUSxHQUFHLENBQUMsR0FBRztBQUNuQixRQUFRLEtBQUssS0FBSyxFQUFFO0FBQ3BCLFlBQVksUUFBUSxHQUFHLENBQUMsR0FBRztBQUMzQixnQkFBZ0IsS0FBSyxPQUFPO0FBQzVCLGdCQUFnQixLQUFLLE9BQU87QUFDNUIsZ0JBQWdCLEtBQUssT0FBTztBQUM1QixvQkFBb0IsU0FBUyxHQUFHLEVBQUUsSUFBSSxFQUFFLFNBQVMsRUFBRSxJQUFJLEVBQUUsQ0FBQyxJQUFJLEVBQUUsR0FBRyxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxFQUFFO0FBQ3JGLG9CQUFvQixTQUFTLEdBQUcsR0FBRyxDQUFDLENBQUMsR0FBRyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsUUFBUSxDQUFDO0FBQzdELG9CQUFvQjtBQUNwQixnQkFBZ0IsS0FBSyxPQUFPO0FBQzVCLGdCQUFnQixLQUFLLE9BQU87QUFDNUIsZ0JBQWdCLEtBQUssT0FBTztBQUM1QixvQkFBb0IsU0FBUyxHQUFHLEVBQUUsSUFBSSxFQUFFLG1CQUFtQixFQUFFLElBQUksRUFBRSxDQUFDLElBQUksRUFBRSxHQUFHLENBQUMsR0FBRyxDQUFDLEtBQUssQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEVBQUU7QUFDL0Ysb0JBQW9CLFNBQVMsR0FBRyxHQUFHLENBQUMsQ0FBQyxHQUFHLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxRQUFRLENBQUM7QUFDN0Qsb0JBQW9CO0FBQ3BCLGdCQUFnQixLQUFLLFVBQVU7QUFDL0IsZ0JBQWdCLEtBQUssY0FBYztBQUNuQyxnQkFBZ0IsS0FBSyxjQUFjO0FBQ25DLGdCQUFnQixLQUFLLGNBQWM7QUFDbkMsb0JBQW9CLFNBQVMsR0FBRztBQUNoQyx3QkFBd0IsSUFBSSxFQUFFLFVBQVU7QUFDeEMsd0JBQXdCLElBQUksRUFBRSxDQUFDLElBQUksRUFBRSxRQUFRLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsRUFBRSxDQUFDLEVBQUUsRUFBRSxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUM7QUFDM0UscUJBQXFCO0FBQ3JCLG9CQUFvQixTQUFTLEdBQUcsR0FBRyxDQUFDLENBQUMsR0FBRyxDQUFDLFNBQVMsRUFBRSxXQUFXLENBQUMsR0FBRyxDQUFDLFNBQVMsRUFBRSxTQUFTLENBQUM7QUFDekYsb0JBQW9CO0FBQ3BCLGdCQUFnQjtBQUNoQixvQkFBb0IsTUFBTSxJQUFJLGdCQUFnQixDQUFDLDhEQUE4RCxDQUFDO0FBQzlHO0FBQ0EsWUFBWTtBQUNaO0FBQ0EsUUFBUSxLQUFLLElBQUksRUFBRTtBQUNuQixZQUFZLFFBQVEsR0FBRyxDQUFDLEdBQUc7QUFDM0IsZ0JBQWdCLEtBQUssT0FBTztBQUM1QixvQkFBb0IsU0FBUyxHQUFHLEVBQUUsSUFBSSxFQUFFLE9BQU8sRUFBRSxVQUFVLEVBQUUsT0FBTyxFQUFFO0FBQ3RFLG9CQUFvQixTQUFTLEdBQUcsR0FBRyxDQUFDLENBQUMsR0FBRyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsUUFBUSxDQUFDO0FBQzdELG9CQUFvQjtBQUNwQixnQkFBZ0IsS0FBSyxPQUFPO0FBQzVCLG9CQUFvQixTQUFTLEdBQUcsRUFBRSxJQUFJLEVBQUUsT0FBTyxFQUFFLFVBQVUsRUFBRSxPQUFPLEVBQUU7QUFDdEUsb0JBQW9CLFNBQVMsR0FBRyxHQUFHLENBQUMsQ0FBQyxHQUFHLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxRQUFRLENBQUM7QUFDN0Qsb0JBQW9CO0FBQ3BCLGdCQUFnQixLQUFLLE9BQU87QUFDNUIsb0JBQW9CLFNBQVMsR0FBRyxFQUFFLElBQUksRUFBRSxPQUFPLEVBQUUsVUFBVSxFQUFFLE9BQU8sRUFBRTtBQUN0RSxvQkFBb0IsU0FBUyxHQUFHLEdBQUcsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLFFBQVEsQ0FBQztBQUM3RCxvQkFBb0I7QUFDcEIsZ0JBQWdCLEtBQUssU0FBUztBQUM5QixnQkFBZ0IsS0FBSyxnQkFBZ0I7QUFDckMsZ0JBQWdCLEtBQUssZ0JBQWdCO0FBQ3JDLGdCQUFnQixLQUFLLGdCQUFnQjtBQUNyQyxvQkFBb0IsU0FBUyxHQUFHLEVBQUUsSUFBSSxFQUFFLE1BQU0sRUFBRSxVQUFVLEVBQUUsR0FBRyxDQUFDLEdBQUcsRUFBRTtBQUNyRSxvQkFBb0IsU0FBUyxHQUFHLEdBQUcsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxZQUFZLENBQUMsR0FBRyxFQUFFO0FBQzNELG9CQUFvQjtBQUNwQixnQkFBZ0I7QUFDaEIsb0JBQW9CLE1BQU0sSUFBSSxnQkFBZ0IsQ0FBQyw4REFBOEQsQ0FBQztBQUM5RztBQUNBLFlBQVk7QUFDWjtBQUNBLFFBQVEsS0FBSyxLQUFLLEVBQUU7QUFDcEIsWUFBWSxRQUFRLEdBQUcsQ0FBQyxHQUFHO0FBQzNCLGdCQUFnQixLQUFLLE9BQU87QUFDNUIsb0JBQW9CLFNBQVMsR0FBRyxFQUFFLElBQUksRUFBRSxHQUFHLENBQUMsR0FBRyxFQUFFO0FBQ2pELG9CQUFvQixTQUFTLEdBQUcsR0FBRyxDQUFDLENBQUMsR0FBRyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsUUFBUSxDQUFDO0FBQzdELG9CQUFvQjtBQUNwQixnQkFBZ0IsS0FBSyxTQUFTO0FBQzlCLGdCQUFnQixLQUFLLGdCQUFnQjtBQUNyQyxnQkFBZ0IsS0FBSyxnQkFBZ0I7QUFDckMsZ0JBQWdCLEtBQUssZ0JBQWdCO0FBQ3JDLG9CQUFvQixTQUFTLEdBQUcsRUFBRSxJQUFJLEVBQUUsR0FBRyxDQUFDLEdBQUcsRUFBRTtBQUNqRCxvQkFBb0IsU0FBUyxHQUFHLEdBQUcsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxZQUFZLENBQUMsR0FBRyxFQUFFO0FBQzNELG9CQUFvQjtBQUNwQixnQkFBZ0I7QUFDaEIsb0JBQW9CLE1BQU0sSUFBSSxnQkFBZ0IsQ0FBQyw4REFBOEQsQ0FBQztBQUM5RztBQUNBLFlBQVk7QUFDWjtBQUNBLFFBQVE7QUFDUixZQUFZLE1BQU0sSUFBSSxnQkFBZ0IsQ0FBQyw2REFBNkQsQ0FBQztBQUNyRztBQUNBLElBQUksT0FBTyxFQUFFLFNBQVMsRUFBRSxTQUFTLEVBQUU7QUFDbkM7QUFDQSxNQUFNLEtBQUssR0FBRyxPQUFPLEdBQUcsS0FBSztBQUM3QixJQUFJLElBQUksQ0FBQyxHQUFHLENBQUMsR0FBRyxFQUFFO0FBQ2xCLFFBQVEsTUFBTSxJQUFJLFNBQVMsQ0FBQywwREFBMEQsQ0FBQztBQUN2RjtBQUNBLElBQUksTUFBTSxFQUFFLFNBQVMsRUFBRSxTQUFTLEVBQUUsR0FBRyxhQUFhLENBQUMsR0FBRyxDQUFDO0FBQ3ZELElBQUksTUFBTSxJQUFJLEdBQUc7QUFDakIsUUFBUSxTQUFTO0FBQ2pCLFFBQVEsR0FBRyxDQUFDLEdBQUcsSUFBSSxLQUFLO0FBQ3hCLFFBQVEsR0FBRyxDQUFDLE9BQU8sSUFBSSxTQUFTO0FBQ2hDLEtBQUs7QUFDTCxJQUFJLE1BQU0sT0FBTyxHQUFHLEVBQUUsR0FBRyxHQUFHLEVBQUU7QUFDOUIsSUFBSSxPQUFPLE9BQU8sQ0FBQyxHQUFHO0FBQ3RCLElBQUksT0FBTyxPQUFPLENBQUMsR0FBRztBQUN0QixJQUFJLE9BQU9BLFFBQU0sQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUFDLEtBQUssRUFBRSxPQUFPLEVBQUUsR0FBRyxJQUFJLENBQUM7QUFDM0QsQ0FBQzs7QUMvRkQsTUFBTSxjQUFjLEdBQUcsQ0FBQyxDQUFDLEtBQUtFLFFBQU0sQ0FBQyxDQUFDLENBQUM7QUFDdkMsSUFBSSxTQUFTO0FBQ2IsSUFBSSxRQUFRO0FBQ1osTUFBTSxXQUFXLEdBQUcsQ0FBQyxHQUFHLEtBQUs7QUFDN0IsSUFBSSxPQUFPLEdBQUcsR0FBRyxNQUFNLENBQUMsV0FBVyxDQUFDLEtBQUssV0FBVztBQUNwRCxDQUFDO0FBQ0QsTUFBTSxjQUFjLEdBQUcsT0FBTyxLQUFLLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsTUFBTSxHQUFHLEtBQUssS0FBSztBQUN2RSxJQUFJLElBQUksTUFBTSxHQUFHLEtBQUssQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDO0FBQy9CLElBQUksSUFBSSxNQUFNLEdBQUcsR0FBRyxDQUFDLEVBQUU7QUFDdkIsUUFBUSxPQUFPLE1BQU0sQ0FBQyxHQUFHLENBQUM7QUFDMUI7QUFDQSxJQUFJLE1BQU0sU0FBUyxHQUFHLE1BQU1ZLEtBQVMsQ0FBQyxFQUFFLEdBQUcsR0FBRyxFQUFFLEdBQUcsRUFBRSxDQUFDO0FBQ3RELElBQUksSUFBSSxNQUFNO0FBQ2QsUUFBUSxNQUFNLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQztBQUMxQixJQUFJLElBQUksQ0FBQyxNQUFNLEVBQUU7QUFDakIsUUFBUSxLQUFLLENBQUMsR0FBRyxDQUFDLEdBQUcsRUFBRSxFQUFFLENBQUMsR0FBRyxHQUFHLFNBQVMsRUFBRSxDQUFDO0FBQzVDO0FBQ0EsU0FBUztBQUNULFFBQVEsTUFBTSxDQUFDLEdBQUcsQ0FBQyxHQUFHLFNBQVM7QUFDL0I7QUFDQSxJQUFJLE9BQU8sU0FBUztBQUNwQixDQUFDO0FBQ0QsTUFBTSxrQkFBa0IsR0FBRyxDQUFDLEdBQUcsRUFBRSxHQUFHLEtBQUs7QUFDekMsSUFBSSxJQUFJLFdBQVcsQ0FBQyxHQUFHLENBQUMsRUFBRTtBQUMxQixRQUFRLElBQUksR0FBRyxHQUFHLEdBQUcsQ0FBQyxNQUFNLENBQUMsRUFBRSxNQUFNLEVBQUUsS0FBSyxFQUFFLENBQUM7QUFDL0MsUUFBUSxPQUFPLEdBQUcsQ0FBQyxDQUFDO0FBQ3BCLFFBQVEsT0FBTyxHQUFHLENBQUMsRUFBRTtBQUNyQixRQUFRLE9BQU8sR0FBRyxDQUFDLEVBQUU7QUFDckIsUUFBUSxPQUFPLEdBQUcsQ0FBQyxDQUFDO0FBQ3BCLFFBQVEsT0FBTyxHQUFHLENBQUMsQ0FBQztBQUNwQixRQUFRLE9BQU8sR0FBRyxDQUFDLEVBQUU7QUFDckIsUUFBUSxJQUFJLEdBQUcsQ0FBQyxDQUFDLEVBQUU7QUFDbkIsWUFBWSxPQUFPLGNBQWMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDO0FBQ3hDO0FBQ0EsUUFBUSxRQUFRLEtBQUssUUFBUSxHQUFHLElBQUksT0FBTyxFQUFFLENBQUM7QUFDOUMsUUFBUSxPQUFPLGNBQWMsQ0FBQyxRQUFRLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLENBQUM7QUFDdEQ7QUFDQSxJQUFJLElBQUksS0FBSyxDQUFDLEdBQUcsQ0FBQyxFQUFFO0FBQ3BCLFFBQVEsSUFBSSxHQUFHLENBQUMsQ0FBQztBQUNqQixZQUFZLE9BQU9aLFFBQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDO0FBQ2hDLFFBQVEsUUFBUSxLQUFLLFFBQVEsR0FBRyxJQUFJLE9BQU8sRUFBRSxDQUFDO0FBQzlDLFFBQVEsTUFBTSxTQUFTLEdBQUcsY0FBYyxDQUFDLFFBQVEsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxJQUFJLENBQUM7QUFDdkUsUUFBUSxPQUFPLFNBQVM7QUFDeEI7QUFDQSxJQUFJLE9BQU8sR0FBRztBQUNkLENBQUM7QUFDRCxNQUFNLG1CQUFtQixHQUFHLENBQUMsR0FBRyxFQUFFLEdBQUcsS0FBSztBQUMxQyxJQUFJLElBQUksV0FBVyxDQUFDLEdBQUcsQ0FBQyxFQUFFO0FBQzFCLFFBQVEsSUFBSSxHQUFHLEdBQUcsR0FBRyxDQUFDLE1BQU0sQ0FBQyxFQUFFLE1BQU0sRUFBRSxLQUFLLEVBQUUsQ0FBQztBQUMvQyxRQUFRLElBQUksR0FBRyxDQUFDLENBQUMsRUFBRTtBQUNuQixZQUFZLE9BQU8sY0FBYyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7QUFDeEM7QUFDQSxRQUFRLFNBQVMsS0FBSyxTQUFTLEdBQUcsSUFBSSxPQUFPLEVBQUUsQ0FBQztBQUNoRCxRQUFRLE9BQU8sY0FBYyxDQUFDLFNBQVMsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUcsQ0FBQztBQUN2RDtBQUNBLElBQUksSUFBSSxLQUFLLENBQUMsR0FBRyxDQUFDLEVBQUU7QUFDcEIsUUFBUSxJQUFJLEdBQUcsQ0FBQyxDQUFDO0FBQ2pCLFlBQVksT0FBT0EsUUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7QUFDaEMsUUFBUSxTQUFTLEtBQUssU0FBUyxHQUFHLElBQUksT0FBTyxFQUFFLENBQUM7QUFDaEQsUUFBUSxNQUFNLFNBQVMsR0FBRyxjQUFjLENBQUMsU0FBUyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLElBQUksQ0FBQztBQUN4RSxRQUFRLE9BQU8sU0FBUztBQUN4QjtBQUNBLElBQUksT0FBTyxHQUFHO0FBQ2QsQ0FBQztBQUNELGdCQUFlLEVBQUUsa0JBQWtCLEVBQUUsbUJBQW1CLEVBQUU7O0FDakVuRCxTQUFTLFNBQVMsQ0FBQyxHQUFHLEVBQUU7QUFDL0IsSUFBSSxRQUFRLEdBQUc7QUFDZixRQUFRLEtBQUssU0FBUztBQUN0QixZQUFZLE9BQU8sR0FBRztBQUN0QixRQUFRLEtBQUssU0FBUztBQUN0QixZQUFZLE9BQU8sR0FBRztBQUN0QixRQUFRLEtBQUssU0FBUztBQUN0QixRQUFRLEtBQUssZUFBZTtBQUM1QixZQUFZLE9BQU8sR0FBRztBQUN0QixRQUFRLEtBQUssZUFBZTtBQUM1QixZQUFZLE9BQU8sR0FBRztBQUN0QixRQUFRLEtBQUssZUFBZTtBQUM1QixZQUFZLE9BQU8sR0FBRztBQUN0QixRQUFRO0FBQ1IsWUFBWSxNQUFNLElBQUksZ0JBQWdCLENBQUMsQ0FBQywyQkFBMkIsRUFBRSxHQUFHLENBQUMsQ0FBQyxDQUFDO0FBQzNFO0FBQ0E7QUFDQSxrQkFBZSxDQUFDLEdBQUcsS0FBSyxNQUFNLENBQUMsSUFBSSxVQUFVLENBQUMsU0FBUyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDOztBQ0k1RCxlQUFlLFNBQVMsQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFO0FBQzFDLElBQUksSUFBSSxDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUMsRUFBRTtBQUN4QixRQUFRLE1BQU0sSUFBSSxTQUFTLENBQUMsdUJBQXVCLENBQUM7QUFDcEQ7QUFDQSxJQUFJLEdBQUcsS0FBSyxHQUFHLEdBQUcsR0FBRyxDQUFDLEdBQUcsQ0FBQztBQUMxQixJQUFJLFFBQVEsR0FBRyxDQUFDLEdBQUc7QUFDbkIsUUFBUSxLQUFLLEtBQUs7QUFDbEIsWUFBWSxJQUFJLE9BQU8sR0FBRyxDQUFDLENBQUMsS0FBSyxRQUFRLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFO0FBQ3JELGdCQUFnQixNQUFNLElBQUksU0FBUyxDQUFDLHlDQUF5QyxDQUFDO0FBQzlFO0FBQ0EsWUFBWSxPQUFPYSxRQUFlLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQztBQUN6QyxRQUFRLEtBQUssS0FBSztBQUNsQixZQUFZLElBQUksR0FBRyxDQUFDLEdBQUcsS0FBSyxTQUFTLEVBQUU7QUFDdkMsZ0JBQWdCLE1BQU0sSUFBSSxnQkFBZ0IsQ0FBQyxvRUFBb0UsQ0FBQztBQUNoSDtBQUNBLFFBQVEsS0FBSyxJQUFJO0FBQ2pCLFFBQVEsS0FBSyxLQUFLO0FBQ2xCLFlBQVksT0FBT0MsS0FBVyxDQUFDLEVBQUUsR0FBRyxHQUFHLEVBQUUsR0FBRyxFQUFFLENBQUM7QUFDL0MsUUFBUTtBQUNSLFlBQVksTUFBTSxJQUFJLGdCQUFnQixDQUFDLDhDQUE4QyxDQUFDO0FBQ3RGO0FBQ0E7O0FDekNBLE1BQU0sR0FBRyxHQUFHLENBQUMsR0FBRyxLQUFLLEdBQUcsR0FBRyxNQUFNLENBQUMsV0FBVyxDQUFDO0FBQzlDLE1BQU0sWUFBWSxHQUFHLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxLQUFLLEtBQUs7QUFDMUMsSUFBSSxJQUFJLEdBQUcsQ0FBQyxHQUFHLEtBQUssU0FBUyxJQUFJLEdBQUcsQ0FBQyxHQUFHLEtBQUssS0FBSyxFQUFFO0FBQ3BELFFBQVEsTUFBTSxJQUFJLFNBQVMsQ0FBQyxrRUFBa0UsQ0FBQztBQUMvRjtBQUNBLElBQUksSUFBSSxHQUFHLENBQUMsT0FBTyxLQUFLLFNBQVMsSUFBSSxHQUFHLENBQUMsT0FBTyxDQUFDLFFBQVEsR0FBRyxLQUFLLENBQUMsS0FBSyxJQUFJLEVBQUU7QUFDN0UsUUFBUSxNQUFNLElBQUksU0FBUyxDQUFDLENBQUMsc0VBQXNFLEVBQUUsS0FBSyxDQUFDLENBQUMsQ0FBQztBQUM3RztBQUNBLElBQUksSUFBSSxHQUFHLENBQUMsR0FBRyxLQUFLLFNBQVMsSUFBSSxHQUFHLENBQUMsR0FBRyxLQUFLLEdBQUcsRUFBRTtBQUNsRCxRQUFRLE1BQU0sSUFBSSxTQUFTLENBQUMsQ0FBQyw2REFBNkQsRUFBRSxHQUFHLENBQUMsQ0FBQyxDQUFDO0FBQ2xHO0FBQ0EsSUFBSSxPQUFPLElBQUk7QUFDZixDQUFDO0FBQ0QsTUFBTSxrQkFBa0IsR0FBRyxDQUFDLEdBQUcsRUFBRSxHQUFHLEVBQUUsS0FBSyxFQUFFLFFBQVEsS0FBSztBQUMxRCxJQUFJLElBQUksR0FBRyxZQUFZLFVBQVU7QUFDakMsUUFBUTtBQUNSLElBQUksSUFBSSxRQUFRLElBQUlDLEtBQVMsQ0FBQyxHQUFHLENBQUMsRUFBRTtBQUNwQyxRQUFRLElBQUlDLFdBQWUsQ0FBQyxHQUFHLENBQUMsSUFBSSxZQUFZLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxLQUFLLENBQUM7QUFDakUsWUFBWTtBQUNaLFFBQVEsTUFBTSxJQUFJLFNBQVMsQ0FBQyxDQUFDLHVIQUF1SCxDQUFDLENBQUM7QUFDdEo7QUFDQSxJQUFJLElBQUksQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLEVBQUU7QUFDekIsUUFBUSxNQUFNLElBQUksU0FBUyxDQUFDQyxPQUFlLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLEtBQUssRUFBRSxZQUFZLEVBQUUsUUFBUSxHQUFHLGNBQWMsR0FBRyxJQUFJLENBQUMsQ0FBQztBQUNoSDtBQUNBLElBQUksSUFBSSxHQUFHLENBQUMsSUFBSSxLQUFLLFFBQVEsRUFBRTtBQUMvQixRQUFRLE1BQU0sSUFBSSxTQUFTLENBQUMsQ0FBQyxFQUFFLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQyw0REFBNEQsQ0FBQyxDQUFDO0FBQ3RHO0FBQ0EsQ0FBQztBQUNELE1BQU0sbUJBQW1CLEdBQUcsQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFLEtBQUssRUFBRSxRQUFRLEtBQUs7QUFDM0QsSUFBSSxJQUFJLFFBQVEsSUFBSUYsS0FBUyxDQUFDLEdBQUcsQ0FBQyxFQUFFO0FBQ3BDLFFBQVEsUUFBUSxLQUFLO0FBQ3JCLFlBQVksS0FBSyxNQUFNO0FBQ3ZCLGdCQUFnQixJQUFJRyxZQUFnQixDQUFDLEdBQUcsQ0FBQyxJQUFJLFlBQVksQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFLEtBQUssQ0FBQztBQUMxRSxvQkFBb0I7QUFDcEIsZ0JBQWdCLE1BQU0sSUFBSSxTQUFTLENBQUMsQ0FBQyxnREFBZ0QsQ0FBQyxDQUFDO0FBQ3ZGLFlBQVksS0FBSyxRQUFRO0FBQ3pCLGdCQUFnQixJQUFJQyxXQUFlLENBQUMsR0FBRyxDQUFDLElBQUksWUFBWSxDQUFDLEdBQUcsRUFBRSxHQUFHLEVBQUUsS0FBSyxDQUFDO0FBQ3pFLG9CQUFvQjtBQUNwQixnQkFBZ0IsTUFBTSxJQUFJLFNBQVMsQ0FBQyxDQUFDLCtDQUErQyxDQUFDLENBQUM7QUFDdEY7QUFDQTtBQUNBLElBQUksSUFBSSxDQUFDLFNBQVMsQ0FBQyxHQUFHLENBQUMsRUFBRTtBQUN6QixRQUFRLE1BQU0sSUFBSSxTQUFTLENBQUNGLE9BQWUsQ0FBQyxHQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUcsS0FBSyxFQUFFLFFBQVEsR0FBRyxjQUFjLEdBQUcsSUFBSSxDQUFDLENBQUM7QUFDbEc7QUFDQSxJQUFJLElBQUksR0FBRyxDQUFDLElBQUksS0FBSyxRQUFRLEVBQUU7QUFDL0IsUUFBUSxNQUFNLElBQUksU0FBUyxDQUFDLENBQUMsRUFBRSxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUMsaUVBQWlFLENBQUMsQ0FBQztBQUMzRztBQUNBLElBQUksSUFBSSxLQUFLLEtBQUssTUFBTSxJQUFJLEdBQUcsQ0FBQyxJQUFJLEtBQUssUUFBUSxFQUFFO0FBQ25ELFFBQVEsTUFBTSxJQUFJLFNBQVMsQ0FBQyxDQUFDLEVBQUUsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFDLHFFQUFxRSxDQUFDLENBQUM7QUFDL0c7QUFDQSxJQUFJLElBQUksS0FBSyxLQUFLLFNBQVMsSUFBSSxHQUFHLENBQUMsSUFBSSxLQUFLLFFBQVEsRUFBRTtBQUN0RCxRQUFRLE1BQU0sSUFBSSxTQUFTLENBQUMsQ0FBQyxFQUFFLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQyx3RUFBd0UsQ0FBQyxDQUFDO0FBQ2xIO0FBQ0EsSUFBSSxJQUFJLEdBQUcsQ0FBQyxTQUFTLElBQUksS0FBSyxLQUFLLFFBQVEsSUFBSSxHQUFHLENBQUMsSUFBSSxLQUFLLFNBQVMsRUFBRTtBQUN2RSxRQUFRLE1BQU0sSUFBSSxTQUFTLENBQUMsQ0FBQyxFQUFFLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQyxzRUFBc0UsQ0FBQyxDQUFDO0FBQ2hIO0FBQ0EsSUFBSSxJQUFJLEdBQUcsQ0FBQyxTQUFTLElBQUksS0FBSyxLQUFLLFNBQVMsSUFBSSxHQUFHLENBQUMsSUFBSSxLQUFLLFNBQVMsRUFBRTtBQUN4RSxRQUFRLE1BQU0sSUFBSSxTQUFTLENBQUMsQ0FBQyxFQUFFLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQyx1RUFBdUUsQ0FBQyxDQUFDO0FBQ2pIO0FBQ0EsQ0FBQztBQUNELFNBQVMsWUFBWSxDQUFDLFFBQVEsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEtBQUssRUFBRTtBQUNqRCxJQUFJLE1BQU0sU0FBUyxHQUFHLEdBQUcsQ0FBQyxVQUFV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QVMsSUFBSSxHQUFHLENBQUMsV0FBVyxLQUFLLFNBQVMsRUFBRTtBQUNsRyxRQUFRLE1BQU0sSUFBSSxVQUFVLENBQUMscUJBQXFCLENBQUM7QUFDbkQ7QUFDQSxJQUFJLElBQUksR0FBRyxDQUFDLEVBQUUsS0FBSyxTQUFTLElBQUksT0FBTyxHQUFHLENBQUMsRUFBRSxLQUFLLFFBQVEsRUFBRTtBQUM1RCxRQUFRLE1BQU0sSUFBSSxVQUFVLENBQUMsMENBQTBDLENBQUM7QUFDeEU7QUFDQSxJQUFJLElBQUksT0FBTyxHQUFHLENBQUMsVUFBVSxLQUFLLFFBQVEsRUFBRTtBQUM1QyxRQUFRLE1BQU0sSUFBSSxVQUFVLENBQUMsMENBQTBDLENBQUM7QUFDeEU7QUFDQSxJQUFJLElBQUksR0FBRyxDQUFDLEdBQUcsS0FBSyxTQUFTLElBQUksT0FBTyxHQUFHLENBQUMsR0FBRyxLQUFLLFFBQVEsRUFBRTtBQUM5RCxRQUFRLE1BQU0sSUFBSSxVQUFVLENBQUMsdUNBQXVDLENBQUM7QUFDckU7QUFDQSxJQUFJLElBQUksR0FBRyxDQUFDLFNBQVMsS0FBSyxTQUFTLElBQUksT0FBTyxHQUFHLENBQUMsU0FBUyxLQUFLLFFBQVEsRUFBRTtBQUMxRSxRQUFRLE1BQU0sSUFBSSxVQUFVLENBQUMscUNBQXFDLENBQUM7QUFDbkU7QUFDQSxJQUFJLElBQUksR0FBRyxDQUFDLGFBQWEsS0FBSyxTQUFTLElBQUksT0FBTyxHQUFHLENBQUMsYUFBYSxLQUFLLFFBQVEsRUFBRTtBQUNsRixRQUFRLE1BQU0sSUFBSSxVQUFVLENBQUMsa0NBQWtDLENBQUM7QUFDaEU7QUFDQSxJQUFJLElBQUksR0FBRyxDQUFDLEdBQUcsS0FBSyxTQUFTLElBQUksT0FBTyxHQUFHLENBQUMsR0FBRyxLQUFLLFFBQVEsRUFBRTtBQUM5RCxRQUFRLE1BQU0sSUFBSSxVQUFVLENBQUMsd0JBQXdCLENBQUM7QUFDdEQ7QUFDQSxJQUFJLElBQUksR0FBRyxDQUFDLE1BQU0sS0FBSyxTQUFTLElBQUksQ0FBQyxRQUFRLENBQUMsR0FBRyxDQUFD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QUcsQ0FBQyxFQUFFLFlBQVksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQztBQUNsRSxJQUFJLEtBQUssQ0FBQyxHQUFHLENBQUMsR0FBRyxFQUFFLEtBQUssQ0FBQzs7QUFFekIsSUFBSSxJQUFJLENBQUMsR0FBRyxFQUFFLE9BQU87QUFDckIsSUFBSSxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLEVBQUUsVUFBVSxDQUFDLE1BQU0sSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsRUFBRSxHQUFHLENBQUMsQ0FBQztBQUNsRTtBQUNBLEVBQUUsTUFBTSxDQUFDLEdBQUcsRUFBRTtBQUNkLElBQUksSUFBSSxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsRUFBRSxZQUFZLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUM7QUFDbEUsSUFBSSxJQUFJLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUM7QUFDNUIsSUFBSSxPQUFPLEtBQUssQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDO0FBQzVCO0FBQ0EsRUFBRSxLQUFLLENBQUMsVUFBVSxHQUFHLElBQUksQ0FBQyxPQUFPLEVBQUU7QUFDbkMsSUFBSSxJQUFJLENBQUMsT0FBTyxHQUFHLFVBQVU7QUFDN0IsSUFBSSxJQUFJLENBQUMsUUFBUSxHQUFHLEtBQUssQ0FBQyxVQUFVLENBQUM7QUFDckMsSUFBSSxJQUFJLENBQUMsZUFBZSxHQUFHLENBQUM7QUFDNUIsSUFBSSxLQUFLLENBQUMsS0FBSyxFQUFFO0FBQ2pCLElBQUksS0FBSyxNQUFNLEtBQUssSUFBSSxJQUFJLENBQUMsT0FBTyxDQUFDLE1BQU0sRUFBRSxFQUFFLFlBQVksQ0FBQyxLQUFLO0FBQ2pFLElBQUksSUFBSSxDQUFDLE9BQU8sQ0FBQyxLQUFLLEVBQUU7QUFDeEI7QUFDQTs7QUM3Q0EsTUFBTSxLQUFLLFNBQVMsR0FBRyxDQUFDLFdBQVcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLEtBQUssRUFBRSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLGVBQWUsQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxJQUFJLElBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLGlCQUFpQixDQUFDLENBQUMsSUFBSSxDQUFDLENBQUMsSUFBSSxDQUFDLGVBQWUsQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsZUFBZSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsRUFBRSxJQUFJLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFLFlBQVksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsRUFBRSxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsVUFBVSxFQUFFLElBQUksSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsRUFBQyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFPLElBQUksQ0FBQyxPQUFPLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFLFlBQVksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLGVBQWUsQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLEtBQUssRUFBRSxDQUFDLElBQUksTUFBTSxDQUFDLElBQUksSUFBSSxDQUFDLE9BQU8sQ0FBQyxNQUFNLEVBQUUsQ0FBQyxZQUFZLENBQUMsQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxLQUFLLEdBQUUsQ0FBQyxDQUFDLE1BQU0sV0FBVyxDQUFDLFdBQVcsQ0FBQyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQyxTQUFTLENBQUMsaUJBQWlCLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLEtBQUUsQ0FBQyxDQUFDLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsSUFBSSxLQUFLLENBQUMsQ0FBQyxDQUFDLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLFFBQVEsQ0FBQyxDQUFDLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLFVBQVUsQ0FBQyxDQUFDLENBQUMsRUFBQyxDQUFDLE1BQU0sSUFBSSxFQUFFLENBQUMsT0FBTyxJQUFJLENBQUMsU0FBUyxDQUFDLEVBQUUsRUFBRSxDQUFDLENBQUMsQ0FBQyxDQUFDLEdBQUcsSUFBSSxDQUFDLFlBQVksQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxNQUFNLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFPLElBQUksQ0FBQyxTQUFTLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLENBQUMsR0FBRyxJQUFJLENBQUMsV0FBVyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLE1BQU0sTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDLE9BQU8sSUFBSSxDQUFDLFNBQVMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxHQUFHLElBQUksQ0FBQyxjQUFjLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsTUFBTSxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLE9BQU8sSUFBSSxDQUFDLFNBQVMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxHQUFHLElBQUksQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLElBQUksQ0FBQyxLQUFLLEVBQUUsT0FBTyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFDLENBQUMsTUFBTSxTQUFTLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxVQUFVLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxDQUFDLElBQUksRUFBRSxTQUFTLENBQUMsQ0FBQyxNQUFNLElBQUksQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsVUFBVSxDQUFDLE1BQU0sWUFBWSxTQUFTLFdBQVcsQ0FBQyxXQUFXLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLElBQUksTUFBTSxDQUFDLENBQUMsRUFBRSxFQUFFLElBQUksQ0FBQyxRQUFRLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLFFBQVEsRUFBQyxDQUFDLE1BQU0sWUFBWSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFNLENBQUMsTUFBTSxDQUFDLENBQUMsSUFBSSxFQUFFLEVBQUUsRUFBRSxFQUFFLEdBQUcsRUFBRSxDQUFDLEVBQUUsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDLEVBQUUsQ0FBQyxNQUFNLFdBQVcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsTUFBTSxDQUFDLENBQUMsTUFBTSxDQUFDLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxFQUFFLElBQUksRUFBRSxDQUFDLGNBQWMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDLFdBQVcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQyxPQUFNLENBQUMsQ0FBQyxFQUFFLElBQUksQ0FBQyxRQUFRLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDLE9BQU8sSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLEVBQUUsQ0FBQyxDQUFDLE9BQU8sRUFBRSxDQUFDLE9BQU8sTUFBTSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLENBQUM7O0FDQXA3RCxJQUFJLFFBQVEsR0FBRyxZQUFZLElBQUksWUFBWTtBQUMzQyxJQUFJLE9BQU8sTUFBTSxDQUFDLEtBQUssV0FBVyxFQUFFO0FBQ3BDLEVBQUUsUUFBUSxHQUFHLE1BQU0sQ0FBQyxNQUFNO0FBQzFCOztBQUVPLFNBQVMsbUJBQW1CLENBQUMsR0FBRyxFQUFFLFlBQVksRUFBRTtBQUN2RCxFQUFFLE9BQU8sWUFBWSxJQUFJLEdBQUcsR0FBRyxRQUFRLENBQUMsWUFBWSxDQUFDLElBQUksR0FBRztBQUM1RDs7QUNQQSxNQUFNLE1BQU0sR0FBRyxJQUFJLEdBQUcsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDLE1BQU07O0FDQXZDLFNBQVMsT0FBTyxDQUFDLGNBQWMsRUFBRSxHQUFHLEVBQUUsU0FBUyxHQUFHLE1BQU0sRUFBRTtBQUNqRTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEVBQUUsSUFBSSxDQUFDLEdBQUcsRUFBRSxPQUFPLGNBQWM7QUFDakMsRUFBRSxPQUFPLENBQUMsRUFBRSxjQUFjLENBQUMsQ0FBQyxFQUFFLEdBQUcsQ0FBQyxDQUFDLEVBQUUsU0FBUyxDQUFDLENBQUM7QUFDaEQ7O0FDSkEsZUFBZSxlQUFlLENBQUMsUUFBUSxFQUFFO0FBQ3pDO0FBQ0EsRUFBRSxJQUFJLFFBQVEsQ0FBQyxNQUFNLEtBQUssR0FBRyxFQUFFLE9BQU8sRUFBRTtBQUN4QyxFQUFFLElBQUksQ0FBQyxRQUFRLENBQUMsRUFBRSxFQUFFLE9BQU8sT0FBTyxDQUFDLE1BQU0sQ0FBQyxRQUFRLENBQUMsVUFBVSxDQUFDO0FBQzlELEVBQUUsSUFBSSxJQUFJLEdBQUcsTUFBTSxRQUFRLENBQUMsSUFBSSxFQUFFO0FBQ2xDLEVBQUUsSUFBSSxDQUFDLElBQUksRUFBRSxPQUFPLElBQUksQ0FBQztBQUN6QixFQUFFLE9BQU8sSUFBSSxDQUFDLEtBQUssQ0FBQyxJQUFJLENBQUM7QUFDekI7O0FBRUEsTUFBTSxPQUFPLEdBQUc7QUFDaEIsRUFBRSxJQUFJLE1BQU0sR0FBRyxFQUFFLE9BQU8sTUFBTSxDQUFDLEVBQUU7QUFDakMsRUFBRSxPQUFPO0FBQ1QsRUFBRSxHQUFHLENBQUMsY0FBYyxFQUFFLEdBQUcsRUFBRTtBQUMzQjtBQUNBLElBQUksT0FBTyxDQUFDLEVBQUUsTUFBTSxDQUFDLFNBQVMsRUFBRSxJQUFJLENBQUMsT0FBTyxDQUFDLGNBQWMsRUFBRSxHQUFHLENBQUMsQ0FBQyxDQUFDO0FBQ25FLEdBQUc7QUFDSCxFQUFFLEtBQUssQ0FBQyxjQUFjLEVBQUUsR0FBRyxFQUFFLFNBQVMsRUFBRSxPQUFPLEdBQUcsRUFBRSxFQUFFO0FBQ3REO0FBQ0E7QUFDQTtBQUNBLElBQUksT0FBTyxLQUFLLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxjQUFjLEVBQUUsR0FBRyxDQUFDLEVBQUU7QUFDaEQsTUFBTSxNQUFNLEVBQUUsS0FBSztBQUNuQixNQUFNLElBQUksRUFBRSxJQUFJLENBQUMsU0FBUyxDQUFDLFNBQVMsQ0FBQztBQUNyQyxNQUFNLE9BQU8sRUFBRSxDQUFDLGNBQWMsRUFBRSxrQkFBa0IsRUFBRSxJQUFJLE9BQU8sQ0FBQyxPQUFPLElBQUksRUFBRSxDQUFDO0FBQzlFLEtBQUssQ0FBQyxDQUFDLElBQUksQ0FBQyxlQUFlLENBQUM7QUFDNUIsR0FBRztBQUNILEVBQUUsUUFBUSxDQUFDLGNBQWMsRUFBRSxHQUFHLEVBQUUsT0FBTyxHQUFHLEVBQUUsRUFBRTtBQUM5QztBQUNBO0FBQ0EsSUFBSSxPQUFPLEtBQUssQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLGNBQWMsRUFBRSxHQUFHLENBQUMsRUFBRTtBQUNoRCxNQUFNLEtBQUssRUFBRSxTQUFTO0FBQ3RCLE1BQU0sT0FBTyxFQUFFLENBQUMsUUFBUSxFQUFFLGtCQUFrQixFQUFFLElBQUksT0FBTyxDQUFDLE9BQU8sSUFBSSxFQUFFLENBQUM7QUFDeEUsS0FBSyxDQUFDLENBQUMsSUFBSSxDQUFDLGVBQWUsQ0FBQztBQUM1QjtBQUNBLENBQUM7O0FDOUJELFNBQVMsS0FBSyxDQUFDLGdCQUFnQixFQUFFLEdBQUcsRUFBRSxLQUFLLEdBQUcsU0FBUyxFQUFFO0FBQ3pEO0FBQ0E7QUFDQSxFQUFFLElBQUksWUFBWSxHQUFHLEdBQUcsR0FBRyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxFQUFFLENBQUMsR0FBRyxLQUFLLEdBQUcsYUFBYTtBQUNuRSxNQUFNLE9BQU8sR0FBRyxnQkFBZ0IsQ0FBQyxZQUFZLENBQUM7QUFDOUMsRUFBRSxPQUFPLE9BQU8sQ0FBQyxNQUFNLENBQUMsSUFBSSxLQUFLLENBQUMsT0FBTyxFQUFFLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQztBQUNwRDtBQUNBLFNBQVMsV0FBVyxDQUFDLEdBQUcsRUFBRSxTQUFTLEVBQUU7QUFDckMsRUFBRSxPQUFPLEtBQUssQ0FBQyxHQUFHLElBQUksQ0FBQyxJQUFJLEVBQUUsU0FBUyxDQUFDLEtBQUssRUFBRSxHQUFHLENBQUMsa0JBQWtCLENBQUMsRUFBRSxHQUFHLENBQUM7QUFDM0U7O0FBRU8sTUFBTSxNQUFNLENBQUM7QUFDcEI7QUFDQTs7QUFFQTtBQUNBLEVBQUUsT0FBTyxPQUFPLEdBQUcsSUFBSUMsT0FBSyxDQUFDLEdBQUcsRUFBRSxFQUFFLEdBQUcsRUFBRSxHQUFHLEdBQUcsQ0FBQztBQUNoRCxFQUFFLE9BQU8sTUFBTSxDQUFDLEdBQUcsRUFBRTtBQUNyQixJQUFJLE9BQU8sTUFBTSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDO0FBQ2xDO0FBQ0EsRUFBRSxPQUFPLEtBQUssQ0FBQyxHQUFHLEVBQUUsTUFBTSxFQUFFO0FBQzVCLElBQUksTUFBTSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsR0FBRyxFQUFFLE1BQU0sQ0FBQztBQUNuQztBQUNBLEVBQUUsT0FBTyxLQUFLLENBQUMsR0FBRyxHQUFHLElBQUksRUFBRTtBQUMzQixJQUFJLElBQUksQ0FBQyxHQUFHLEVBQUUsT0FBTyxNQUFNLENBQUMsT0FBTyxDQUFDLEtBQUssRUFBRTtBQUMzQyxJQUFJLE9BQU8sTUFBTSxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDO0FBQ3JDO0FBQ0EsRUFBRSxXQUFXLENBQUMsR0FBRyxFQUFFO0FBQ25CLElBQUksSUFBSSxDQUFDLEdBQUcsR0FBRyxHQUFHO0FBQ2xCLElBQUksSUFBSSxDQUFDLFVBQVUsR0FBRyxFQUFFLENBQUM7QUFDekIsSUFBSSxNQUFNLENBQUMsS0FBSyxDQUFDLEdBQUcsRUFBRSxJQUFJLENBQUM7QUFDM0I7QUFDQTtBQUNBLEVBQUUsT0FBTyxtQkFBbUIsR0FBRyxtQkFBbUI7QUFDbEQsRUFBRSxPQUFPLE9BQU8sR0FBRyxPQUFPOztBQUUxQjtBQUNBLEVBQUUsYUFBYSxNQUFNLENBQUMsWUFBWSxFQUFFO0FBQ3BDO0FBQ0EsSUFBSSxJQUFJLENBQUMsSUFBSSxFQUFFLEdBQUcsSUFBSSxDQUFDLEdBQUcsTUFBTSxJQUFJLENBQUMsVUFBVSxDQUFDLFlBQVksQ0FBQztBQUM3RCxRQUFRLENBQUMsR0FBRyxDQUFDLEdBQUcsSUFBSTtBQUNwQixJQUFJLE1BQU0sSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLEVBQUUsSUFBSSxFQUFFLFlBQVksRUFBRSxJQUFJLENBQUM7QUFDckQsSUFBSSxPQUFPLEdBQUc7QUFDZDtBQUNBLEVBQUUsTUFBTSxPQUFPLENBQUMsT0FBTyxHQUFHLEVBQUUsRUFBRTtBQUM5QixJQUFJLElBQUksQ0FBQyxHQUFHLEVBQUUsVUFBVSxFQUFFLFVBQVUsQ0FBQyxHQUFHLElBQUk7QUFDNUMsUUFBUSxPQUFPLEdBQUcsRUFBRTtBQUNwQixRQUFRLFNBQVMsR0FBRyxNQUFNLElBQUksQ0FBQyxXQUFXLENBQUMsY0FBYyxDQUFDLENBQUMsR0FBRyxPQUFPLEVBQUUsT0FBTyxFQUFFLE9BQU8sRUFBRSxHQUFHLEVBQUUsVUFBVSxFQUFFLFVBQVUsRUFBRSxJQUFJLEVBQUUsSUFBSSxDQUFDLEdBQUcsRUFBRSxFQUFFLFFBQVEsRUFBRSxJQUFJLENBQUMsQ0FBQztBQUN4SixJQUFJLE1BQU0sSUFBSSxDQUFDLFdBQVcsQ0FBQyxLQUFLLENBQUMsZUFBZSxFQUFFLEdBQUcsRUFBRSxTQUFTLENBQUM7QUFDakUsSUFBSSxNQUFNLElBQUksQ0FBQyxXQUFXLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxXQUFXLENBQUMsVUFBVSxFQUFFLEdBQUcsRUFBRSxTQUFTLENBQUM7QUFDN0UsSUFBSSxJQUFJLENBQUMsV0FBVyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUM7QUFDL0IsSUFBSSxJQUFJLENBQUMsT0FBTyxDQUFDLGdCQUFnQixFQUFFO0FBQ25DLElBQUksTUFBTSxPQUFPLENBQUMsVUFBVSxDQUFDLElBQUksQ0FBQyxVQUFVLENBQUMsR0FBRyxDQUFDLE1BQU0sU0FBUyxJQUFJO0FBQ3BFLE1BQU0sSUFBSSxZQUFZLEdBQUcsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLFNBQVMsRUFBRSxDQUFDLEdBQUcsT0FBTyxFQUFFLFFBQVEsRUFBRSxJQUFJLENBQUMsQ0FBQztBQUNyRixNQUFNLE1BQU0sWUFBWSxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUM7QUFDekMsS0FBSyxDQUFDLENBQUM7QUFDUDtBQUNBLEVBQUUsT0FBTyxDQUFDLFNBQVMsRUFBRSxPQUFPLEVBQUU7QUFDOUIsSUFBSSxJQUFJLENBQUMsR0FBRyxFQUFFLGFBQWEsQ0FBQyxHQUFHLElBQUk7QUFDbkMsUUFBUSxHQUFHLEdBQUcsU0FBUyxDQUFDLFVBQVUsR0FBRyxDQUFDLENBQUMsR0FBRyxHQUFHLGFBQWEsQ0FBQyxHQUFHLGFBQWE7QUFDM0UsSUFBSSxPQUFPLFdBQVcsQ0FBQyxPQUFPLENBQUMsR0FBRyxFQUFFLFNBQVMsRUFBRSxPQUFPLENBQUM7QUFDdkQ7QUFDQTtBQUNBO0FBQ0E7QUFDQSxFQUFFLGFBQWEsSUFBSSxDQUFDLE9BQU8sRUFBRSxDQUFDLElBQUksR0FBRyxFQUFFO0FBQ3ZDLDhCQUE4QixJQUFJLENBQUMsR0FBRyxFQUFFLE1BQU0sQ0FBQyxHQUFHO0FBQ2xELDhCQUE4QixPQUFPLENBQUMsR0FBRyxHQUFHLE1BQU07QUFDbEQsOEJBQThCLElBQUksQ0FBQyxHQUFHLEdBQUcsR0FBRyxJQUFJLElBQUksQ0FBQyxHQUFHLEVBQUU7QUFDMUQsOEJBQThCLFVBQVUsRUFBRSxVQUFVLEVBQUUsUUFBUTtBQUM5RCw4QkFBOEIsR0FBRyxPQUFPLENBQUMsRUFBRTtBQUMzQyxJQUFJLElBQUksR0FBRyxJQUFJLENBQUMsR0FBRyxFQUFFO0FBQ3JCLE1BQU0sSUFBSSxDQUFDLFVBQVUsRUFBRSxVQUFVLEdBQUcsQ0FBQyxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLEVBQUUsVUFBVTtBQUN6RSxNQUFNLElBQUksWUFBWSxHQUFHLFVBQVUsQ0FBQyxJQUFJLENBQUMsR0FBRyxJQUFJLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7QUFDakUsTUFBTSxHQUFHLEdBQUcsWUFBWSxJQUFJLE1BQU0sSUFBSSxDQUFDLE9BQU8sQ0FBQyxVQUFVLENBQUMsQ0FBQyxJQUFJLENBQUMsTUFBTSxJQUFJLE1BQU0sQ0FBQyxHQUFHLENBQUM7QUFDckY7QUFDQSxJQUFJLElBQUksR0FBRyxJQUFJLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUMsRUFBRSxJQUFJLEdBQUcsQ0FBQyxHQUFHLEVBQUUsR0FBRyxJQUFJLENBQUMsQ0FBQztBQUMxRCxJQUFJLElBQUksR0FBRyxJQUFJLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUMsRUFBRSxJQUFJLEdBQUcsQ0FBQyxHQUFHLElBQUksRUFBRSxHQUFHLENBQUM7O0FBRXpELElBQUksSUFBSSxHQUFHLEdBQUcsTUFBTSxJQUFJLENBQUMsVUFBVSxDQUFDLElBQUksRUFBRSxNQUFNLEdBQUcsSUFBSTtBQUN2RDtBQUNBLE1BQU0sSUFBSSxHQUFHLEdBQUcsVUFBVSxJQUFJLENBQUMsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLEdBQUcsRUFBRSxDQUFDLFFBQVEsRUFBRSxHQUFHLE9BQU8sQ0FBQyxDQUFDLEVBQUUsVUFBVTtBQUMzRixNQUFNLFVBQVUsR0FBRyxJQUFJO0FBQ3ZCLE1BQU0sT0FBTyxHQUFHO0FBQ2hCLEtBQUssRUFBRSxPQUFPLENBQUM7QUFDZixRQUFRLGFBQWEsR0FBRyxXQUFXLENBQUMsV0FBVyxDQUFDLE9BQU8sRUFBRSxPQUFPLENBQUM7QUFDakUsSUFBSSxJQUFJLEdBQUcsS0FBSyxNQUFNLEVBQUU7QUFDeEIsTUFBTSxNQUFNLElBQUksR0FBRyxNQUFNLFVBQVUsQ0FBQyxhQUFhLENBQUM7QUFDbEQsTUFBTSxHQUFHLEdBQUcsTUFBTSxlQUFlLENBQUMsSUFBSSxDQUFDO0FBQ3ZDLEtBQUssTUFBTSxJQUFJLENBQUMsR0FBRyxFQUFFO0FBQ3JCLE1BQU0sR0FBRyxHQUFHLFNBQVM7QUFDckI7QUFDQSxJQUFJLE9BQU8sV0FBVyxDQUFDLElBQUksQ0FBQyxHQUFHLEVBQUUsYUFBYSxFQUFFLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUcsT0FBTyxDQUFDLENBQUM7QUFDakY7O0FBRUE7QUFDQSxFQUFFLGFBQWEsTUFBTSxDQUFDLFNBQVMsRUFBRSxJQUFJLEVBQUUsT0FBTyxFQUFFO0FBQ2hELElBQUksSUFBSSxTQUFTLEdBQUcsQ0FBQyxTQUFTLENBQUMsVUFBVTtBQUN6QyxRQUFRLEdBQUcsR0FBRyxNQUFNLElBQUksQ0FBQyxVQUFVLENBQUMsSUFBSSxFQUFFLEdBQUcsSUFBSSxNQUFNLENBQUMsWUFBWSxDQUFDLEdBQUcsQ0FBQyxFQUFFLE9BQU8sRUFBRSxTQUFTLENBQUM7QUFDOUYsUUFBUSxNQUFNLEdBQUcsTUFBTSxXQUFXLENBQUMsTUFBTSxDQUFDLEdBQUcsRUFBRSxTQUFTLEVBQUUsT0FBTyxDQUFDO0FBQ2xFLFFBQVEsU0FBUyxHQUFHLE9BQU8sQ0FBQyxNQUFNLEtBQUssU0FBUyxHQUFHLE1BQU0sRUFBRSxlQUFlLENBQUMsR0FBRyxHQUFHLE9BQU8sQ0FBQyxNQUFNO0FBQy9GLFFBQVEsU0FBUyxHQUFHLE9BQU8sQ0FBQyxTQUFTO0FBQ3JDLElBQUksU0FBUyxJQUFJLENBQUMsS0FBSyxFQUFFO0FBQ3pCLE1BQU0sSUFBSSxPQUFPLENBQUMsU0FBUyxFQUFFLE9BQU8sT0FBTyxDQUFDLE1BQU0sQ0FBQyxJQUFJLEtBQUssQ0FBQyxLQUFLLENBQUMsQ0FBQztBQUNwRTtBQUNBLElBQUksSUFBSSxDQUFDLE1BQU0sRUFBRSxPQUFPLElBQUksQ0FBQyxzQkFBc0IsQ0FBQztBQUNwRCxJQUFJLElBQUksU0FBUyxFQUFFO0FBQ25CLE1BQU0sSUFBSSxPQUFPLENBQUMsTUFBTSxLQUFLLE1BQU0sRUFBRTtBQUNyQyxRQUFRLFNBQVMsR0FBRyxNQUFNLENBQUMsZUFBZSxDQUFDLEdBQUc7QUFDOUMsUUFBUSxJQUFJLENBQUMsU0FBUyxFQUFFLE9BQU8sSUFBSSxDQUFDLG9DQUFvQyxDQUFDO0FBQ3pFO0FBQ0EsTUFBTSxJQUFJLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxTQUFTLENBQUMsRUFBRTtBQUNyQyxRQUFRLElBQUksU0FBUyxHQUFHLE1BQU0sTUFBTSxDQUFDLFlBQVksQ0FBQyxTQUFTLENBQUM7QUFDNUQsWUFBWSxjQUFjLEdBQUcsQ0FBQyxDQUFDLFNBQVMsR0FBRyxTQUFTLENBQUM7QUFDckQsWUFBWSxHQUFHLEdBQUcsTUFBTSxXQUFXLENBQUMsTUFBTSxDQUFDLGNBQWMsRUFBRSxTQUFTLEVBQUUsT0FBTyxDQUFDO0FBQzlFLFFBQVEsSUFBSSxDQUFDLEdBQUcsRUFBRSxPQUFPLElBQUksQ0FBQyw2QkFBNkIsQ0FBQztBQUM1RCxRQUFRLElBQUksQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDO0FBQzVCLFFBQVEsTUFBTSxDQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUMsTUFBTSxJQUFJLE1BQU0sQ0FBQyxlQUFlLENBQUMsR0FBRyxLQUFLLFNBQVMsQ0FBQyxDQUFDLE9BQU8sR0FBRyxNQUFNLENBQUMsT0FBTztBQUN4RztBQUNBO0FBQ0EsSUFBSSxJQUFJLFNBQVMsSUFBSSxTQUFTLEtBQUssTUFBTSxFQUFFO0FBQzNDLE1BQU0sSUFBSSxPQUFPLEdBQUcsTUFBTSxDQUFDLGVBQWUsQ0FBQyxHQUFHLElBQUksTUFBTSxDQUFDLGVBQWUsQ0FBQyxHQUFHO0FBQzVFLFVBQVUsV0FBVyxHQUFHLE1BQU0sSUFBSSxDQUFDLFFBQVEsQ0FBQyxVQUFVLENBQUMsVUFBVSxFQUFFLE9BQU8sQ0FBQztBQUMzRSxVQUFVLEdBQUcsR0FBRyxXQUFXLEVBQUUsSUFBSTtBQUNqQyxNQUFNLElBQUksU0FBUyxJQUFJLENBQUMsT0FBTyxFQUFFLE9BQU8sSUFBSSxDQUFDLDZDQUE2QyxDQUFDO0FBQzNGLE1BQU0sSUFBSSxTQUFTLElBQUksR0FBRyxJQUFJLENBQUMsR0FBRyxDQUFDLFVBQVUsQ0FBQyxJQUFJLENBQUMsTUFBTSxJQUFJLE1BQU0sQ0FBQyxNQUFNLENBQUMsR0FBRyxLQUFLLFNBQVMsQ0FBQyxFQUFFLE9BQU8sSUFBSSxDQUFDLHlCQUF5QixDQUFDO0FBQ3JJLE1BQU0sSUFBSSxTQUFTLEtBQUssTUFBTSxFQUFFLFNBQVMsR0FBRyxXQUFXLEVBQUUsZUFBZSxDQUFDO0FBQ3pFLFdBQVcsQ0FBQyxNQUFNLElBQUksQ0FBQyxRQUFRLENBQUMsZUFBZSxFQUFFLE9BQU8sRUFBRSxPQUFPLENBQUMsR0FBRyxlQUFlLENBQUMsR0FBRztBQUN4RjtBQUNBLElBQUksSUFBSSxTQUFTLEVBQUU7QUFDbkIsTUFBTSxJQUFJLENBQUMsR0FBRyxDQUFDLEdBQUcsTUFBTSxDQUFDLGVBQWU7QUFDeEMsTUFBTSxJQUFJLEdBQUcsR0FBRyxTQUFTLEVBQUUsT0FBTyxJQUFJLENBQUMsd0NBQXdDLENBQUM7QUFDaEY7QUFDQTtBQUNBLElBQUksSUFBSSxDQUFDLE1BQU0sQ0FBQyxPQUFPLEVBQUUsTUFBTSxDQUFDLE1BQU0sSUFBSSxNQUFNLENBQUMsT0FBTyxDQUFDLENBQUMsTUFBTSxJQUFJLENBQUMsTUFBTSxJQUFJLENBQUMsTUFBTSxFQUFFLE9BQU8sSUFBSSxDQUFDLG1CQUFtQixDQUFDO0FBQ3hILElBQUksT0FBTyxNQUFNO0FBQ2pCOztBQUVBO0FBQ0EsRUFBRSxhQUFhLFVBQVUsQ0FBQyxJQUFJLEVBQUUsUUFBUSxFQUFFLE9BQU8sRUFBRSxZQUFZLEdBQUcsSUFBSSxDQUFDLE1BQU0sS0FBSyxDQUFDLEVBQUU7QUFDckY7QUFDQSxJQUFJLElBQUksWUFBWSxFQUFFO0FBQ3RCLE1BQU0sSUFBSSxHQUFHLEdBQUcsSUFBSSxDQUFDLENBQUMsQ0FBQztBQUN2QixNQUFNLE9BQU8sQ0FBQyxHQUFHLEdBQUcsR0FBRyxDQUFDO0FBQ3hCLE1BQU0sT0FBTyxRQUFRLENBQUMsR0FBRyxDQUFDO0FBQzFCO0FBQ0EsSUFBSSxJQUFJLEdBQUcsR0FBRyxFQUFFO0FBQ2hCLFFBQVEsSUFBSSxHQUFHLE1BQU0sT0FBTyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLEdBQUcsSUFBSSxRQUFRLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQztBQUNoRTtBQUNBLElBQUksSUFBSSxDQUFDLE9BQU8sQ0FBQyxDQUFDLEdBQUcsRUFBRSxLQUFLLEtBQUssR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsQ0FBQztBQUN4RCxJQUFJLE9BQU8sR0FBRztBQUNkO0FBQ0E7QUFDQSxFQUFFLE9BQU8sWUFBWSxDQUFDLEdBQUcsRUFBRTtBQUMzQixJQUFJLE9BQU8sV0FBVyxDQUFDLFNBQVMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxLQUFLLENBQUMsTUFBTSxXQUFXLENBQUMsR0FBRyxFQUFFLGNBQWMsQ0FBQyxDQUFDO0FBQ25GO0FBQ0EsRUFBRSxhQUFhLGFBQWEsQ0FBQyxHQUFHLEVBQUU7QUFDbEMsSUFBSSxJQUFJLGlCQUFpQixHQUFHLE1BQU0sSUFBSSxDQUFDLFFBQVEsQ0FBQyxlQUFlLEVBQUUsR0FBRyxDQUFDO0FBQ3JFLElBQUksSUFBSSxDQUFDLGlCQUFpQixFQUFFLE9BQU8sV0FBVyxDQUFDLEdBQUcsRUFBRSxZQUFZLENBQUM7QUFDakUsSUFBSSxPQUFPLE1BQU0sV0FBVyxDQUFDLFNBQVMsQ0FBQyxpQkFBaUIsQ0FBQyxJQUFJLENBQUM7QUFDOUQ7QUFDQSxFQUFFLGFBQWEsVUFBVSxDQUFDLFVBQVUsRUFBRTtBQUN0QyxJQUFJLElBQUksQ0FBQyxTQUFTLENBQUMsWUFBWSxFQUFFLFVBQVUsQ0FBQyxVQUFVLENBQUMsR0FBRyxNQUFNLFdBQVcsQ0FBQyxrQkFBa0IsRUFBRTtBQUNoRyxRQUFRLENBQUMsU0FBUyxDQUFDLGFBQWEsRUFBRSxVQUFVLENBQUMsYUFBYSxDQUFDLEdBQUcsTUFBTSxXQUFXLENBQUMscUJBQXFCLEVBQUU7QUFDdkcsUUFBUSxHQUFHLEdBQUcsTUFBTSxXQUFXLENBQUMsU0FBUyxDQUFDLFlBQVksQ0FBQztBQUN2RCxRQUFRLHFCQUFxQixHQUFHLE1BQU0sV0FBVyxDQUFDLFNBQVMsQ0FBQyxhQUFhLENBQUM7QUFDMUUsUUFBUSxJQUFJLEdBQUcsSUFBSSxDQUFDLEdBQUcsRUFBRTtBQUN6QixRQUFRLFNBQVMsR0FBRyxNQUFNLElBQUksQ0FBQyxjQUFjLENBQUMsQ0FBQyxPQUFPLEVBQUUscUJBQXFCLEVBQUUsR0FBRyxFQUFFLFVBQVUsRUFBRSxVQUFVLEVBQUUsSUFBSSxFQUFFLFFBQVEsRUFBRSxJQUFJLENBQUMsQ0FBQztBQUNsSSxJQUFJLE1BQU0sSUFBSSxDQUFDLEtBQUssQ0FBQyxlQUFlLEVBQUUsR0FBRyxFQUFFLFNBQVMsQ0FBQztBQUNyRCxJQUFJLE9BQU8sQ0FBQyxVQUFVLEVBQUUsYUFBYSxFQUFFLEdBQUcsRUFBRSxJQUFJLENBQUM7QUFDakQ7QUFDQSxFQUFFLE9BQU8sVUFBVSxDQUFDLEdBQUcsRUFBRTtBQUN6QixJQUFJLE9BQU8sSUFBSSxDQUFDLFFBQVEsQ0FBQyxJQUFJLENBQUMsVUFBVSxFQUFFLEdBQUcsQ0FBQztBQUM5QztBQUNBLEVBQUUsYUFBYSxNQUFNLENBQUMsR0FBRyxFQUFFLENBQUMsTUFBTSxHQUFHLElBQUksRUFBRSxJQUFJLEdBQUcsSUFBSSxFQUFFLFFBQVEsR0FBRyxLQUFLLENBQUMsR0FBRyxFQUFFLEVBQUU7QUFDaEYsSUFBSSxJQUFJLE1BQU0sR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQztBQUNqQyxRQUFRLE1BQU0sR0FBRyxNQUFNLElBQUksTUFBTSxZQUFZLENBQUMsVUFBVSxDQUFDLEdBQUcsQ0FBQztBQUM3RCxJQUFJLElBQUksTUFBTSxFQUFFO0FBQ2hCLE1BQU0sTUFBTSxLQUFLLElBQUksWUFBWSxDQUFDLEdBQUcsQ0FBQztBQUN0QyxLQUFLLE1BQU0sSUFBSSxJQUFJLEtBQUssTUFBTSxHQUFHLE1BQU0sVUFBVSxDQUFDLFVBQVUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFO0FBQ3BFLE1BQU0sTUFBTSxLQUFLLElBQUksVUFBVSxDQUFDLEdBQUcsQ0FBQztBQUNwQyxLQUFLLE1BQU0sSUFBSSxRQUFRLEtBQUssTUFBTSxHQUFHLE1BQU0sY0FBYyxDQUFDLFVBQVUsQ0FBQyxHQUFHLENBQUMsQ0FBQyxFQUFFO0FBQzVFLE1BQU0sTUFBTSxLQUFLLElBQUksY0FBYyxDQUFDLEdBQUcsQ0FBQztBQUN4QztBQUNBO0FBQ0EsSUFBSSxJQUFJLE1BQU0sRUFBRSxNQUFNO0FBQ3RCLFFBQVEsTUFBTSxDQUFDLE1BQU0sQ0FBQyxlQUFlLENBQUMsR0FBRyxLQUFLLE1BQU0sRUFBRSxlQUFlLENBQUMsR0FBRztBQUN6RSxRQUFRLE1BQU0sQ0FBQyxNQUFNLENBQUMsSUFBSSxLQUFLLE1BQU0sRUFBRSxJQUFJO0FBQzNDLFFBQVEsTUFBTSxDQUFDLGFBQWEsSUFBSSxNQUFNLENBQUMsVUFBVSxFQUFFLE9BQU8sTUFBTTtBQUNoRSxJQUFJLElBQUksTUFBTSxFQUFFLE1BQU0sQ0FBQyxNQUFNLEdBQUcsTUFBTTtBQUN0QyxTQUFTO0FBQ1QsTUFBTSxJQUFJLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQztBQUNyQixNQUFNLE9BQU8sV0FBVyxDQUFDLEdBQUcsRUFBRSxTQUFTLENBQUM7QUFDeEM7QUFDQSxJQUFJLE9BQU8sTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLENBQUMsSUFBSTtBQUM1QyxNQUFNLFNBQVMsSUFBSSxNQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sRUFBRSxTQUFTLENBQUM7QUFDbkQsTUFBTSxLQUFLLElBQUk7QUFDZixRQUFRLElBQUksQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLEdBQUc7QUFDN0IsUUFBUSxPQUFPLEtBQUssQ0FBQyxHQUFHLElBQUksQ0FBQyw4Q0FBOEMsRUFBRSxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUUsTUFBTSxDQUFDLEdBQUcsRUFBRSxLQUFLLENBQUM7QUFDdkcsT0FBTyxDQUFDO0FBQ1I7QUFDQSxFQUFFLE9BQU8sT0FBTyxDQUFDLElBQUksRUFBRTtBQUN2QixJQUFJLE9BQU8sT0FBTyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLEdBQUcsSUFBSSxNQUFNLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFDO0FBQzFELE9BQU8sS0FBSyxDQUFDLE1BQU0sTUFBTSxJQUFJO0FBQzdCLFFBQVEsS0FBSyxJQUFJLFNBQVMsSUFBSSxJQUFJLEVBQUU7QUFDcEMsVUFBVSxJQUFJLE1BQU0sR0FBRyxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsU0FBUyxFQUFFLENBQUMsTUFBTSxFQUFFLEtBQUssRUFBRSxJQUFJLEVBQUUsS0FBSyxFQUFFLFFBQVEsRUFBRSxJQUFJLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxNQUFNLElBQUksQ0FBQztBQUNySCxVQUFVLElBQUksTUFBTSxFQUFFLE9BQU8sTUFBTTtBQUNuQztBQUNBLFFBQVEsTUFBTSxNQUFNO0FBQ3BCLE9BQU8sQ0FBQztBQUNSO0FBQ0EsRUFBRSxhQUFhLE9BQU8sQ0FBQyxHQUFHLEVBQUUsSUFBSSxFQUFFLFlBQVksRUFBRSxJQUFJLEdBQUcsSUFBSSxDQUFDLEdBQUcsRUFBRSxFQUFFLFVBQVUsR0FBRyxZQUFZLEVBQUU7QUFDOUYsSUFBSSxJQUFJLENBQUMsVUFBVSxDQUFDLEdBQUcsSUFBSTtBQUMzQixRQUFRLE9BQU8sR0FBRyxNQUFNLElBQUksQ0FBQyxJQUFJLENBQUMsSUFBSSxFQUFFLFlBQVksQ0FBQztBQUNyRCxRQUFRLFNBQVMsR0FBRyxNQUFNLElBQUksQ0FBQyxjQUFjLENBQUMsQ0FBQyxPQUFPLEVBQUUsT0FBTyxFQUFFLEdBQUcsRUFBRSxVQUFVLEVBQUUsVUFBVSxFQUFFLElBQUksRUFBRSxRQUFRLEVBQUUsSUFBSSxDQUFDLENBQUM7QUFDcEgsSUFBSSxNQUFNLElBQUksQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDLFVBQVUsRUFBRSxHQUFHLEVBQUUsU0FBUyxDQUFDO0FBQ3JEOztBQUVBO0FBQ0EsRUFBRSxhQUFhLEtBQUssQ0FBQyxjQUFjLEVBQUUsR0FBRyxFQUFFLFNBQVMsRUFBRTtBQUNyRCxJQUFJLElBQUksY0FBYyxLQUFLLFlBQVksQ0FBQyxVQUFVLEVBQUU7QUFDcEQ7QUFDQSxNQUFNLElBQUksV0FBVyxDQUFDLGlCQUFpQixDQUFDLFNBQVMsQ0FBQyxFQUFFLE9BQU8sVUFBVSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUM7QUFDakYsTUFBTSxPQUFPLFVBQVUsQ0FBQyxHQUFHLENBQUMsR0FBRyxFQUFFLFNBQVMsQ0FBQztBQUMzQztBQUNBLElBQUksT0FBTyxNQUFNLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxjQUFjLEVBQUUsR0FBRyxFQUFFLFNBQVMsQ0FBQztBQUMvRDtBQUNBLEVBQUUsYUFBYSxRQUFRLENBQUMsY0FBYyxFQUFFLEdBQUcsRUFBRSxVQUFVLEdBQUcsS0FBSyxFQUFFO0FBQ2pFO0FBQ0EsSUFBSSxJQUFJLFFBQVEsR0FBRyxDQUFDLFVBQVUsSUFBSSxJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQztBQUNsRCxJQUFJLElBQUksUUFBUSxFQUFFLFdBQVcsQ0FBQyxVQUFVLEtBQUssY0FBYyxFQUFFLE9BQU8sUUFBUSxDQUFDLE1BQU07QUFDbkYsSUFBSSxJQUFJLE9BQU8sR0FBRyxDQUFDLGNBQWMsS0FBSyxZQUFZLENBQUMsVUFBVSxJQUFJLFVBQVUsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUcsTUFBTSxDQUFDLE9BQU8sQ0FBQyxRQUFRLENBQUMsY0FBYyxFQUFFLEdBQUcsQ0FBQztBQUNuSSxRQUFRLFNBQVMsR0FBRyxNQUFNLE9BQU87QUFDakMsUUFBUSxHQUFHLEdBQUcsU0FBUyxJQUFJLE1BQU0sTUFBTSxDQUFDLFlBQVksQ0FBQyxHQUFHLENBQUM7QUFDekQsSUFBSSxJQUFJLENBQUMsU0FBUyxFQUFFO0FBQ3BCO0FBQ0E7QUFDQSxJQUFJLElBQUksU0FBUyxDQUFDLFVBQVUsRUFBRSxHQUFHLEdBQUcsQ0FBQyxDQUFDLEdBQUcsR0FBRyxHQUFHLENBQUMsQ0FBQztBQUNqRCxJQUFJLE9BQU8sTUFBTSxXQUFXLENBQUMsTUFBTSxDQUFDLEdBQUcsRUFBRSxTQUFTLENBQUM7QUFDbkQ7QUFDQTs7QUFFTyxNQUFNLFlBQVksU0FBUyxNQUFNLENBQUM7QUFDekMsRUFBRSxPQUFPLGNBQWMsQ0FBQyxDQUFDLE9BQU8sRUFBRSxHQUFHLEVBQUUsVUFBVSxFQUFFLElBQUksQ0FBQyxFQUFFO0FBQzFEO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsSUFBSSxPQUFPLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxFQUFFLENBQUMsSUFBSSxFQUFFLENBQUMsR0FBRyxDQUFDLEVBQUUsVUFBVSxFQUFFLElBQUksQ0FBQyxDQUFDO0FBQzlEO0FBQ0EsRUFBRSxhQUFhLFdBQVcsQ0FBQyxHQUFHLEVBQUUsTUFBTSxFQUFFO0FBQ3hDLElBQUksSUFBSSxNQUFNLElBQUksTUFBTSxJQUFJLENBQUMsU0FBUyxDQUFDLEdBQUcsRUFBRSxNQUFNLENBQUM7QUFDbkQ7QUFDQTtBQUNBLElBQUksT0FBTyxXQUFXLENBQUMsaUJBQWlCLENBQUMsTUFBTSxDQUFDO0FBQ2hEO0FBQ0EsRUFBRSxhQUFhLElBQUksQ0FBQyxJQUFJLEVBQUUsTUFBTSxHQUFHLEVBQUUsRUFBRTtBQUN2QyxJQUFJLElBQUksQ0FBQyxhQUFhLEVBQUUsVUFBVSxFQUFFLEdBQUcsQ0FBQyxHQUFHLElBQUk7QUFDL0MsUUFBUSxRQUFRLEdBQUcsQ0FBQyxhQUFhLEVBQUUsVUFBVSxDQUFDO0FBQzlDLFFBQVEsV0FBVyxHQUFHLE1BQU0sSUFBSSxDQUFDLFdBQVcsQ0FBQyxHQUFHLEVBQUUsTUFBTSxDQUFDO0FBQ3pELElBQUksT0FBTyxXQUFXLENBQUMsT0FBTyxDQUFDLFFBQVEsRUFBRSxXQUFXLEVBQUUsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDO0FBQ2hFO0FBQ0EsRUFBRSxNQUFNLE1BQU0sQ0FBQyxVQUFVLEVBQUU7QUFDM0IsSUFBSSxJQUFJLE1BQU0sR0FBRyxVQUFVLENBQUMsSUFBSSxJQUFJLFVBQVUsQ0FBQyxJQUFJOztBQUVuRDtBQUNBLFFBQVEsZUFBZSxHQUFHLFdBQVcsQ0FBQyxxQkFBcUIsQ0FBQyxNQUFNLENBQUM7QUFDbkUsUUFBUSxNQUFNLEdBQUcsZUFBZSxDQUFDLE1BQU07O0FBRXZDLFFBQVEsV0FBVyxHQUFHLE1BQU0sSUFBSSxDQUFDLFdBQVcsQ0FBQyxXQUFXLENBQUMsSUFBSSxDQUFDLEdBQUcsRUFBRSxNQUFNLENBQUM7QUFDMUUsUUFBUSxRQUFRLEdBQUcsQ0FBQyxNQUFNLFdBQVcsQ0FBQyxPQUFPLENBQUMsV0FBVyxFQUFFLE1BQU0sQ0FBQyxFQUFFLElBQUk7QUFDeEUsSUFBSSxPQUFPLE1BQU0sV0FBVyxDQUFDLFNBQVMsQ0FBQyxRQUFRLEVBQUUsQ0FBQyxhQUFhLEVBQUUsU0FBUyxFQUFFLFVBQVUsRUFBRSxNQUFNLENBQUMsQ0FBQztBQUNoRztBQUNBLEVBQUUsYUFBYSxTQUFTLENBQUMsR0FBRyxFQUFFLE1BQU0sRUFBRTtBQUN0QyxJQUFJLE9BQU8sTUFBTSxDQUFDLG1CQUFtQixDQUFDLEdBQUcsRUFBRSxNQUFNLENBQUM7QUFDbEQ7QUFDQTs7QUFFQTtBQUNPLE1BQU0sY0FBYyxTQUFTLFlBQVksQ0FBQztBQUNqRCxFQUFFLE9BQU8sVUFBVSxHQUFHLGFBQWE7QUFDbkM7O0FBRUE7QUFDTyxNQUFNLFlBQVksU0FBUyxZQUFZLENBQUM7QUFDL0MsRUFBRSxPQUFPLFVBQVUsR0FBRyxRQUFRO0FBQzlCLEVBQUUsT0FBTyxJQUFJLEdBQUc7QUFDaEIsSUFBSSxPQUFPLFVBQVUsQ0FBQyxPQUFPLEVBQUU7QUFDL0I7QUFDQTtBQUNBLE1BQU0sVUFBVSxHQUFHLElBQUlDLFlBQVksQ0FBQyxDQUFDLElBQUksRUFBRSxZQUFZLENBQUMsVUFBVSxDQUFDLENBQUM7O0FBRTdELE1BQU0sVUFBVSxTQUFTLE1BQU0sQ0FBQztBQUN2QyxFQUFFLE9BQU8sVUFBVSxHQUFHLE1BQU07QUFDNUIsRUFBRSxPQUFPLGNBQWMsQ0FBQyxDQUFDLE9BQU8sRUFBRSxHQUFHLEVBQUUsR0FBRyxPQUFPLENBQUMsRUFBRTtBQUNwRCxJQUFJLE9BQU8sSUFBSSxDQUFDLElBQUksQ0FBQyxPQUFPLEVBQUUsQ0FBQyxJQUFJLEVBQUUsR0FBRyxFQUFFLEdBQUcsT0FBTyxDQUFDLENBQUM7QUFDdEQ7QUFDQSxFQUFFLGFBQWEsSUFBSSxDQUFDLElBQUksRUFBRSxPQUFPLEVBQUU7QUFDbkM7QUFDQSxJQUFJLElBQUksQ0FBQyxhQUFhLEVBQUUsVUFBVSxDQUFDLEdBQUcsSUFBSTtBQUMxQyxRQUFRLE9BQU8sR0FBRyxDQUFDLGFBQWEsRUFBRSxVQUFVLENBQUM7QUFDN0MsUUFBUSxXQUFXLEdBQUcsRUFBRTtBQUN4QixJQUFJLE1BQU0sT0FBTyxDQUFDLEdBQUcsQ0FBQyxPQUFPLENBQUMsR0FBRyxDQUFDLFNBQVMsSUFBSSxNQUFNLENBQUMsYUFBYSxDQUFDLFNBQVMsQ0FBQyxDQUFDLElBQUksQ0FBQyxHQUFHLElBQUksV0FBVyxDQUFDLFNBQVMsQ0FBQyxHQUFHLEdBQUcsQ0FBQyxDQUFDLENBQUM7QUFDMUgsSUFBSSxJQUFJLFdBQVcsR0FBRyxNQUFNLFdBQVcsQ0FBQyxPQUFPLENBQUMsT0FBTyxFQUFFLFdBQVcsQ0FBQztBQUNyRSxJQUFJLE9BQU8sV0FBVztBQUN0QjtBQUNBLEVBQUUsTUFBTSxNQUFNLENBQUMsT0FBTyxFQUFFO0FBQ3hCLElBQUksSUFBSSxDQUFDLFVBQVUsQ0FBQyxHQUFHLE9BQU8sQ0FBQyxJQUFJO0FBQ25DLFFBQVEsVUFBVSxHQUFHLElBQUksQ0FBQyxVQUFVLEdBQUcsVUFBVSxDQUFDLEdBQUcsQ0FBQyxTQUFTLElBQUksU0FBUyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUM7QUFDeEYsSUFBSSxJQUFJLE1BQU0sR0FBRyxNQUFNLElBQUksQ0FBQyxXQUFXLENBQUMsT0FBTyxDQUFDLFVBQVUsQ0FBQyxDQUFDO0FBQzVELElBQUksSUFBSSxTQUFTLEdBQUcsTUFBTSxNQUFNLENBQUMsT0FBTyxDQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUM7QUFDdEQsSUFBSSxPQUFPLE1BQU0sV0FBVyxDQUFDLFNBQVMsQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDO0FBQ3REO0FBQ0EsRUFBRSxNQUFNLGdCQUFnQixDQUFDLENBQUMsR0FBRyxHQUFHLEVBQUUsRUFBRSxNQUFNLEdBQUcsRUFBRSxDQUFDLEdBQUcsRUFBRSxFQUFFO0FBQ3ZELElBQUksSUFBSSxDQUFDLFVBQVUsQ0FBQyxHQUFHLElBQUk7QUFDM0IsUUFBUSxVQUFVLEdBQUcsVUFBVSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQyxNQUFNLENBQUMsR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUMsQ0FBQztBQUNoRixJQUFJLE1BQU0sSUFBSSxDQUFDLFdBQVcsQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLEdBQUcsRUFBRSxJQUFJLEVBQUUsVUFBVSxFQUFFLElBQUksQ0FBQyxHQUFHLEVBQUUsRUFBRSxVQUFVLENBQUM7QUFDdEYsSUFBSSxJQUFJLENBQUMsVUFBVSxHQUFHLFVBQVU7QUFDaEMsSUFBSSxJQUFJLENBQUMsV0FBVyxDQUFDLEtBQUssQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDO0FBQ3BDO0FBQ0E7Ozs7Ozs7O0FDdFVPLE1BQU0sQ0FBQyxJQUFJLEVBQUUsT0FBTyxDQUFDLEdBQUdDLFFBQVc7O0FDSXJDLE1BQUMsUUFBUSxHQUFHOztBQUVqQixFQUFFLElBQUksTUFBTSxHQUFHLEVBQUUsT0FBTyxNQUFNLENBQUMsRUFBRTtBQUNqQztBQUNBLEVBQUUsSUFBSSxPQUFPLENBQUMsT0FBTyxFQUFFO0FBQ3ZCLElBQUksTUFBTSxDQUFDLE9BQU8sR0FBRyxPQUFPO0FBQzVCLEdBQUc7QUFDSCxFQUFFLElBQUksT0FBTyxHQUFHO0FBQ2hCLElBQUksT0FBTyxNQUFNLENBQUMsT0FBTztBQUN6QixHQUFHO0FBQ0gsRUFBRSxJQUFJLG1CQUFtQixDQUFDLHNCQUFzQixFQUFFO0FBQ2xELElBQUksTUFBTSxDQUFDLG1CQUFtQixHQUFHLHNCQUFzQjtBQUN2RCxHQUFHO0FBQ0gsRUFBRSxJQUFJLG1CQUFtQixHQUFHO0FBQzVCLElBQUksT0FBTyxNQUFNLENBQUMsbUJBQW1CO0FBQ3JDLEdBQUc7QUFDSCxFQUFFLEtBQUssRUFBRSxDQUFDLElBQUksRUFBRSxPQUFPLEVBQUUsTUFBTSxFQUFFLE1BQU0sQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDOztBQUV2RDtBQUNBLEVBQUUsTUFBTSxPQUFPLENBQUMsT0FBTyxFQUFFLEdBQUcsSUFBSSxFQUFFO0FBQ2xDLElBQUksSUFBSSxPQUFPLEdBQUcsRUFBRSxFQUFFLElBQUksR0FBRyxJQUFJLENBQUMsc0JBQXNCLENBQUMsSUFBSSxFQUFFLE9BQU8sQ0FBQztBQUN2RSxRQUFRLEdBQUcsR0FBRyxNQUFNLE1BQU0sQ0FBQyxVQUFVLENBQUMsSUFBSSxFQUFFLEdBQUcsSUFBSSxNQUFNLENBQUMsYUFBYSxDQUFDLEdBQUcsQ0FBQyxFQUFFLE9BQU8sQ0FBQztBQUN0RixJQUFJLE9BQU8sV0FBVyxDQUFDLE9BQU8sQ0FBQyxHQUFHLEVBQUUsT0FBTyxFQUFFLE9BQU8sQ0FBQztBQUNyRCxHQUFHO0FBQ0gsRUFBRSxNQUFNLE9BQU8sQ0FBQyxTQUFTLEVBQUUsR0FBRyxJQUFJLEVBQUU7QUFDcEMsSUFBSSxJQUFJLE9BQU8sR0FBRyxFQUFFO0FBQ3BCLFFBQVEsQ0FBQyxHQUFHLENBQUMsR0FBRyxJQUFJLENBQUMsc0JBQXNCLENBQUMsSUFBSSxFQUFFLE9BQU8sRUFBRSxTQUFTLENBQUM7QUFDckUsUUFBUSxDQUFDLFFBQVEsRUFBRSxHQUFHLFlBQVksQ0FBQyxHQUFHLE9BQU87QUFDN0MsUUFBUSxNQUFNLEdBQUcsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLEdBQUcsRUFBRSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0FBQ3JELElBQUksT0FBTyxNQUFNLENBQUMsT0FBTyxDQUFDLFNBQVMsRUFBRSxZQUFZLENBQUM7QUFDbEQsR0FBRztBQUNILEVBQUUsTUFBTSxJQUFJLENBQUMsT0FBTyxFQUFFLEdBQUcsSUFBSSxFQUFFO0FBQy9CLElBQUksSUFBSSxPQUFPLEdBQUcsRUFBRSxFQUFFLElBQUksR0FBRyxJQUFJLENBQUMsc0JBQXNCLENBQUMsSUFBSSxFQUFFLE9BQU8sQ0FBQztBQUN2RSxJQUFJLE9BQU8sTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLEVBQUUsQ0FBQyxJQUFJLEVBQUUsR0FBRyxPQUFPLENBQUMsQ0FBQztBQUNuRCxHQUFHO0FBQ0gsRUFBRSxNQUFNLE1BQU0sQ0FBQyxTQUFTLEVBQUUsR0FBRyxJQUFJLEVBQUU7QUFDbkMsSUFBSSxJQUFJLE9BQU8sR0FBRyxFQUFFLEVBQUUsSUFBSSxHQUFHLElBQUksQ0FBQyxzQkFBc0IsQ0FBQyxJQUFJLEVBQUUsT0FBTyxFQUFFLFNBQVMsQ0FBQztBQUNsRixJQUFJLE9BQU8sTUFBTSxDQUFDLE1BQU0sQ0FBQyxTQUFTLEVBQUUsSUFBSSxFQUFFLE9BQU8sQ0FBQztBQUNsRCxHQUFHOztBQUVIO0FBQ0EsRUFBRSxNQUFNLE1BQU0sQ0FBQyxHQUFHLE9BQU8sRUFBRTtBQUMzQixJQUFJLElBQUksQ0FBQyxPQUFPLENBQUMsTUFBTSxFQUFFLE9BQU8sTUFBTSxZQUFZLENBQUMsTUFBTSxFQUFFO0FBQzNELElBQUksSUFBSSxNQUFNLEdBQUcsT0FBTyxDQUFDLENBQUMsQ0FBQyxDQUFDLE1BQU07QUFDbEMsSUFBSSxJQUFJLE1BQU0sRUFBRSxPQUFPLE1BQU0sY0FBYyxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUM7QUFDMUQsSUFBSSxPQUFPLE1BQU0sVUFBVSxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUM7QUFDM0MsR0FBRztBQUNILEVBQUUsTUFBTSxnQkFBZ0IsQ0FBQyxDQUFDLEdBQUcsRUFBRSxRQUFRLEdBQUcsS0FBSyxFQUFFLEdBQUcsT0FBTyxDQUFDLEVBQUU7QUFDOUQsSUFBSSxJQUFJLE1BQU0sR0FBRyxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsR0FBRyxFQUFFLENBQUMsUUFBUSxFQUFFLEdBQUcsT0FBTyxDQUFDLENBQUMsQ0FBQztBQUNsRSxJQUFJLE9BQU8sTUFBTSxDQUFDLGdCQUFnQixDQUFDLE9BQU8sQ0FBQztBQUMzQyxHQUFHO0FBQ0gsRUFBRSxNQUFNLE9BQU8sQ0FBQyxZQUFZLEVBQUU7QUFDOUIsSUFBSSxJQUFJLFFBQVEsS0FBSyxPQUFPLFlBQVksRUFBRSxZQUFZLEdBQUcsQ0FBQyxHQUFHLEVBQUUsWUFBWSxDQUFDO0FBQzVFLElBQUksSUFBSSxDQUFDLEdBQUcsRUFBRSxRQUFRLEdBQUcsSUFBSSxFQUFFLEdBQUcsWUFBWSxDQUFDLEdBQUcsWUFBWTtBQUM5RCxRQUFRLE9BQU8sR0FBRyxDQUFDLFFBQVEsRUFBRSxHQUFHLFlBQVksQ0FBQztBQUM3QyxRQUFRLE1BQU0sR0FBRyxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsR0FBRyxFQUFFLE9BQU8sQ0FBQztBQUNsRCxJQUFJLE9BQU8sTUFBTSxDQUFDLE9BQU8sQ0FBQyxPQUFPLENBQUM7QUFDbEMsR0FBRztBQUNILEVBQUUsS0FBSyxDQUFDLEdBQUcsRUFBRTtBQUNiLElBQUksTUFBTSxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUM7QUFDckIsR0FBRztBQUNILEVBQUUsY0FBYyxHQUFHO0FBQ25CLElBQUksT0FBTyxZQUFZLENBQUMsSUFBSSxFQUFFO0FBQzlCLEdBQUc7O0FBRUg7QUFDQSxFQUFFLFVBQVUsRUFBRSxRQUFRLEVBQUUsZUFBZSxFQUFFLGVBQWUsRUFBRSxZQUFZOztBQUV0RSxFQUFFLHNCQUFzQixDQUFDLElBQUksRUFBRSxPQUFPLEVBQUUsS0FBSyxFQUFFO0FBQy9DO0FBQ0E7QUFDQTtBQUNBLElBQUksSUFBSSxJQUFJLENBQUMsTUFBTSxHQUFHLENBQUMsSUFBSSxJQUFJLENBQUMsQ0FBQyxDQUFDLEVBQUUsTUFBTSxLQUFLLFNBQVMsRUFBRSxPQUFPLElBQUk7QUFDckUsSUFBSSxJQUFJLENBQUMsSUFBSSxHQUFHLEVBQUUsRUFBRSxXQUFXLEVBQUUsSUFBSSxFQUFFLEdBQUcsTUFBTSxDQUFDLEdBQUcsSUFBSSxDQUFDLENBQUMsQ0FBQyxJQUFJLEVBQUU7QUFDakUsQ0FBQyxDQUFDLElBQUksQ0FBQyxHQUFHLE1BQU0sQ0FBQztBQUNqQixJQUFJLElBQUksQ0FBQyxJQUFJLENBQUMsTUFBTSxFQUFFO0FBQ3RCLE1BQU0sSUFBSSxJQUFJLENBQUMsTUFBTSxJQUFJLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQyxNQUFNLEVBQUUsSUFBSSxHQUFHLElBQUksQ0FBQztBQUNyRCxXQUFXLElBQUksS0FBSyxFQUFFO0FBQ3RCLFFBQVEsSUFBSSxLQUFLLENBQUMsVUFBVSxFQUFFLElBQUksR0FBRyxLQUFLLENBQUMsVUFBVSxDQUFDLEdBQUcsQ0FBQyxHQUFHLElBQUksV0FBVyxDQUFDLHFCQUFxQixDQUFDLEdBQUcsQ0FBQyxDQUFDLEdBQUcsQ0FBQztBQUM1RyxhQUFhLElBQUksS0FBSyxDQUFDLFVBQVUsRUFBRSxJQUFJLEdBQUcsS0FBSyxDQUFDLFVBQVUsQ0FBQyxHQUFHLENBQUMsR0FBRyxJQUFJLEdBQUcsQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDO0FBQ3JGLGFBQWE7QUFDYixVQUFVLElBQUksR0FBRyxHQUFHLFdBQVcsQ0FBQyxxQkFBcUIsQ0FBQyxLQUFLLENBQUMsQ0FBQyxHQUFHLENBQUM7QUFDakUsVUFBVSxJQUFJLEdBQUcsRUFBRSxJQUFJLEdBQUcsQ0FBQyxHQUFHLENBQUM7QUFDL0I7QUFDQTtBQUNBO0FBQ0EsSUFBSSxJQUFJLElBQUksSUFBSSxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLEVBQUUsSUFBSSxHQUFHLENBQUMsSUFBSSxFQUFFLEdBQUcsSUFBSSxDQUFDO0FBQzVELElBQUksSUFBSSxXQUFXLEVBQUUsT0FBTyxDQUFDLEdBQUcsR0FBRyxXQUFXO0FBQzlDLElBQUksSUFBSSxJQUFJLEVBQUUsT0FBTyxDQUFDLEdBQUcsR0FBRyxJQUFJO0FBQ2hDLElBQUksTUFBTSxDQUFDLE1BQU0sQ0FBQyxPQUFPLEVBQUUsTUFBTSxDQUFDOztBQUVsQyxJQUFJLE9BQU8sSUFBSTtBQUNmO0FBQ0E7O0FDakdBLFNBQVMsa0JBQWtCLENBQUMsS0FBSyxFQUFFO0FBQ25DLEVBQUUsSUFBSSxDQUFDLElBQUksRUFBRSxPQUFPLEVBQUUsSUFBSSxFQUFFLElBQUksQ0FBQyxHQUFHLEtBQUs7QUFDekMsRUFBRSxPQUFPLENBQUMsSUFBSSxFQUFFLE9BQU8sRUFBRSxJQUFJLEVBQUUsSUFBSSxDQUFDO0FBQ3BDOztBQUVBO0FBQ0EsU0FBUyxRQUFRLENBQUMsQ0FBQyxNQUFNLEdBQUcsSUFBSTtBQUNoQyxLQUFLLFFBQVEsR0FBRyxNQUFNO0FBQ3RCLEtBQUssU0FBUyxHQUFHLFFBQVE7O0FBRXpCLEtBQUssTUFBTSxJQUFJLENBQUMsTUFBTSxLQUFLLFFBQVEsS0FBSyxNQUFNLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQzs7QUFFL0QsS0FBSyxlQUFlLEdBQUcsU0FBUyxDQUFDLElBQUksSUFBSSxRQUFRLENBQUMsSUFBSSxJQUFJLFFBQVEsQ0FBQyxRQUFRLEVBQUUsSUFBSSxJQUFJLFFBQVE7QUFDN0YsS0FBSyxXQUFXLEdBQUcsTUFBTSxDQUFDLElBQUksSUFBSSxNQUFNLElBQUksTUFBTSxDQUFDLFFBQVEsRUFBRSxJQUFJLElBQUksTUFBTTs7QUFFM0UsS0FBSyxHQUFHLEdBQUcsSUFBSTtBQUNmLEtBQUssSUFBSSxDQUFDLE9BQU8sR0FBRyxPQUFPLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUM7QUFDOUMsS0FBSyxJQUFJLENBQUMsT0FBTyxHQUFHLE9BQU8sQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQztBQUM5QyxLQUFLLEtBQUssQ0FBQyxRQUFRLEdBQUcsT0FBTyxDQUFDLEtBQUssQ0FBQyxJQUFJLENBQUMsT0FBTztBQUNoRCxLQUFLLEVBQUU7QUFDUCxFQUFPLE1BQUMsUUFBUSxHQUFHLEVBQUU7QUFDckIsUUFBUSxPQUFPLEdBQUcsS0FBSztBQUN2QixRQUFRLFlBQVksR0FBRyxNQUFNLENBQUMsV0FBVyxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQztBQUN2RCxRQUFRO0FBQ1I7QUFDQSxRQUFRLElBQUksR0FBRyxNQUFNLEdBQUcsT0FBTyxJQUFJLFlBQVksQ0FBQyxPQUFPLEVBQUUsTUFBTSxDQUFDLEdBQUcsWUFBWTtBQUUvRSxFQUFFLElBQUksU0FBUyxHQUFHLENBQUMsQ0FBQzs7QUFFcEIsRUFBRSxTQUFTLE9BQU8sQ0FBQyxNQUFNLEVBQUUsR0FBRyxNQUFNLEVBQUU7QUFDdEM7QUFDQTtBQUNBO0FBQ0E7QUFDQSxJQUFJLElBQUksRUFBRSxHQUFHLEVBQUUsU0FBUztBQUN4QixDQUFDLE9BQU8sR0FBRyxRQUFRLENBQUMsRUFBRSxDQUFDLEdBQUcsRUFBRTtBQUM1QjtBQUNBLElBQUksT0FBTyxJQUFJLE9BQU8sQ0FBQyxDQUFDLE9BQU8sRUFBRSxNQUFNLEtBQUs7QUFDNUMsTUFBTSxHQUFHLEdBQUcsZUFBZSxFQUFFLFNBQVMsRUFBRSxFQUFFLEVBQUUsTUFBTSxFQUFFLE1BQU0sRUFBRSxJQUFJLEVBQUUsV0FBVyxDQUFDO0FBQzlFLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxPQUFPLEVBQUUsQ0FBQyxPQUFPLEVBQUUsTUFBTSxDQUFDLENBQUM7QUFDL0MsTUFBTSxJQUFJLENBQUMsQ0FBQyxFQUFFLEVBQUUsTUFBTSxFQUFFLE1BQU0sRUFBRSxPQUFPLENBQUMsQ0FBQztBQUN6QyxLQUFLLENBQUM7QUFDTjs7QUFFQSxFQUFFLGVBQWUsT0FBTyxDQUFDLEtBQUssRUFBRTtBQUNoQyxJQUFJLEdBQUcsR0FBRyxlQUFlLEVBQUUsYUFBYSxFQUFFLEtBQUssQ0FBQyxJQUFJLEVBQUUsTUFBTSxFQUFFLFdBQVcsRUFBRSxLQUFLLENBQUMsTUFBTSxDQUFDO0FBQ3hGLElBQUksSUFBSSxDQUFDLEVBQUUsRUFBRSxNQUFNLEVBQUUsTUFBTSxHQUFHLEVBQUUsRUFBRSxNQUFNLEVBQUUsS0FBSyxFQUFFLE9BQU8sQ0FBQyxPQUFPLENBQUMsR0FBRyxLQUFLLENBQUMsSUFBSSxJQUFJLEVBQUU7O0FBRXBGO0FBQ0EsSUFBSSxJQUFJLEtBQUssQ0FBQyxNQUFNLEtBQUssS0FBSyxDQUFDLE1BQU0sS0FBSyxNQUFNLENBQUMsRUFBRSxPQUFPLFFBQVEsR0FBRyxlQUFlLEVBQUUsSUFBSSxFQUFFLFdBQVcsR0FBRyxrQkFBa0IsRUFBRSxLQUFLLENBQUMsTUFBTSxDQUFDO0FBQzNJLElBQUksSUFBSSxNQUFNLEtBQUssTUFBTSxLQUFLLEtBQUssQ0FBQyxNQUFNLENBQUMsRUFBRSxPQUFPLFFBQVEsR0FBRyxlQUFlLEVBQUUsTUFBTSxFQUFFLG1CQUFtQixFQUFFLFdBQVcsRUFBRSxLQUFLLENBQUMsTUFBTSxDQUFDO0FBQ3ZJLElBQUksSUFBSSxPQUFPLEtBQUssT0FBTyxFQUFFLE9BQU8sT0FBTyxHQUFHLENBQUMsRUFBRSxlQUFlLENBQUMsOEJBQThCLEVBQUUsSUFBSSxDQUFDLFNBQVMsQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7O0FBRS9ILElBQUksSUFBSSxNQUFNLEVBQUU7QUFDaEIsTUFBTSxJQUFJLEtBQUssR0FBRyxJQUFJLEVBQUUsTUFBTTtBQUM5QjtBQUNBLEdBQUcsSUFBSSxHQUFHLEtBQUssQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLEdBQUcsTUFBTSxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUM7QUFDcEQsTUFBTSxJQUFJO0FBQ1YsUUFBUSxNQUFNLEdBQUcsTUFBTSxTQUFTLENBQUMsTUFBTSxDQUFDLENBQUMsR0FBRyxJQUFJLENBQUMsQ0FBQztBQUNsRCxPQUFPLENBQUMsT0FBTyxDQUFDLEVBQUU7QUFDbEIsUUFBUSxLQUFLLEdBQUcsa0JBQWtCLENBQUMsQ0FBQyxDQUFDO0FBQ3JDLFFBQVEsSUFBSSxDQUFDLFNBQVMsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxPQUFPLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQyxFQUFFO0FBQ25FLEdBQUcsS0FBSyxDQUFDLE9BQU8sR0FBRyxDQUFDLEVBQUUsTUFBTSxDQUFDLGdCQUFnQixDQUFDLENBQUM7QUFDL0MsVUFBVSxLQUFLLENBQUMsSUFBSSxHQUFHLE1BQU0sQ0FBQztBQUM5QixTQUFTLE1BQU0sSUFBSSxDQUFDLEtBQUssQ0FBQyxPQUFPO0FBQ2pDLEdBQUcsS0FBSyxDQUFDLE9BQU8sR0FBRyxDQUFDLEVBQUUsS0FBSyxDQUFDLElBQUksSUFBSSxLQUFLLENBQUMsUUFBUSxFQUFFLENBQUMsSUFBSSxFQUFFLE1BQU0sQ0FBQyxDQUFDLENBQUM7QUFDcEU7QUFDQSxNQUFNLElBQUksRUFBRSxLQUFLLFNBQVMsRUFBRSxPQUFPO0FBQ25DLE1BQU0sSUFBSSxRQUFRLEdBQUcsS0FBSyxHQUFHLENBQUMsRUFBRSxFQUFFLEtBQUssRUFBRSxPQUFPLENBQUMsR0FBRyxDQUFDLEVBQUUsRUFBRSxNQUFNLEVBQUUsT0FBTyxDQUFDO0FBQ3pFLE1BQU0sR0FBRyxHQUFHLGVBQWUsRUFBRSxXQUFXLEVBQUUsRUFBRSxFQUFFLEtBQUssSUFBSSxNQUFNLEVBQUUsSUFBSSxFQUFFLFdBQVcsQ0FBQztBQUNqRixNQUFNLE9BQU8sSUFBSSxDQUFDLFFBQVEsQ0FBQztBQUMzQjs7QUFFQTtBQUNBLElBQUksSUFBSSxPQUFPLEdBQUcsUUFBUSxDQUFDLEVBQUUsQ0FBQyxDQUFDO0FBQy9CLElBQUksT0FBTyxRQUFRLENBQUMsRUFBRSxDQUFDO0FBQ3ZCLElBQUksSUFBSSxDQUFDLE9BQU8sRUFBRSxPQUFPLE9BQU8sR0FBRyxDQUFDLEVBQUUsZUFBZSxDQUFDLG1CQUFtQixFQUFFLEtBQUssQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUM7QUFDekYsSUFBSSxJQUFJLEtBQUssRUFBRSxPQUFPLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQztBQUNwQyxTQUFTLE9BQU8sQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDO0FBQ2hDOztBQUVBO0FBQ0EsRUFBRSxRQUFRLENBQUMsZ0JBQWdCLENBQUMsU0FBUyxFQUFFLE9BQU8sQ0FBQztBQUMvQyxFQUFFLE9BQU8sR0FBRyxDQUFDLEVBQUUsZUFBZSxDQUFDLGtCQUFrQixFQUFFLFdBQVcsQ0FBQyxDQUFDLENBQUM7QUFDakUsRUFBRSxPQUFPLE9BQU87QUFDaEI7Ozs7IiwieF9nb29nbGVfaWdub3JlTGlzdCI6WzEsMiwzLDQsNSw2LDcsOCw5LDEwLDExLDEyLDEzLDE0LDE1LDE2LDE3LDE4LDE5LDIwLDIxLDIyLDIzLDI0LDI1LDI2LDI3LDI4LDI5LDMwLDMxLDMyLDMzLDM0LDM1LDM2LDM3LDM4LDM5LDQwLDQxLDQyLDQzLDQ0LDQ1LDQ2LDQ3LDQ4LDQ5LDUwLDUxLDUyLDUzLDU0LDU1LDU2LDU3LDU4LDU5LDYwXX0=
