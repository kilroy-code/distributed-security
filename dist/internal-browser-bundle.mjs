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

var prompter = promptString => promptString;
if (typeof(window) !== 'undefined') {
  prompter = window.prompt;
}

function getUserDeviceSecret(tag, promptString) {
  return promptString ? (tag + prompter(promptString)) : tag;
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
        signature = await this.constructor.signForStorage({message: content, tag, memberTags, signingKey, time: Date.now()});
    await this.constructor.store('EncryptionKey', tag, signature);
    await this.constructor.store(this.constructor.collection, tag, signature);
    this.constructor.clear(tag);
    if (!options.recursiveMembers) return;
    await Promise.allSettled(this.memberTags.map(async memberTag => {
      let memberKeySet = await KeySet.ensure(memberTag);
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
      act = cachedMember || await Promise.any(memberTags.map(tag => KeySet.ensure(tag))).then(keySet => keySet.tag);
    }
    if (iss && !tags.includes(iss)) tags = [iss, ...tags]; // Must be first
    if (act && !tags.includes(act)) tags = [...tags, act];

    let key = await this.produceKey(tags, async tag => {
      // Use specified signingKey (if any) for the first one.
      let key = signingKey || (await KeySet.ensure(tag)).signingKey;
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
        signature = await this.signForStorage({message: exportedEncryptingKey, tag, signingKey, memberTags, time});
    await this.store('EncryptionKey', tag, signature);
    return {signingKey, decryptingKey, tag, time};
  }
  static getWrapped(tag) { // Promise the wrapped key appropriate for this class.
    return this.retrieve(this.collection, tag);
  }
  static async ensure(tag) { // Promise to resolve to a valid keySet, else reject.
    let keySet = this.cached(tag),
        stored = await DeviceKeySet.getWrapped(tag);
    if (stored) {
      keySet = new DeviceKeySet(tag);
    } else if ((stored = await TeamKeySet.getWrapped(tag))) {
      keySet = new TeamKeySet(tag);
    } else if ((stored = await RecoveryKeySet.getWrapped(tag))) {
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
  static async persist(tag, keys, wrappingData, time = Date.now(), memberTags = wrappingData) { // Promise to wrap a set of keys for the wrappingData members, and persist by tag.
    let {signingKey} = keys,
        wrapped = await this.wrap(keys, wrappingData),
        signature = await this.signForStorage({message: wrapped, tag, signingKey, memberTags, time});
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
        memberTags = this.memberTags = recipients.map(recipient => recipient.header.kid),
        // We will use recovery tags only if we need to. First step is to identify them.
        // TODO: optimize this. E.g., determine recovery tags at creation and identify them in wrapped.
        recoveryWraps = await Promise.all(memberTags.map(tag => RecoveryKeySet.getWrapped(tag).catch(() => null))),
        recoveryTags = memberTags.filter((tag, index) => recoveryWraps[index]),
        nonRecoveryTags = memberTags.filter(tag => !recoveryTags.includes(tag));
    let keySet = await Promise.any(nonRecoveryTags.map(memberTag => KeySet.ensure(memberTag)))
        .catch(async reason => { // If we failed, use the recovery tags, if any, one at a time.
          for (let recovery of recoveryTags) {
            let keySet = await KeySet.ensure(recovery).catch(() => null);
            if (keySet) return keySet;
          }
          throw reason;
        });
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
var version$1 = "1.0.1";
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
	"@ki1r0y/jsonrpc": "^1.0.0",
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
  set Storage(storage) { // Allows a node app (no vault) to override the default storage.
    KeySet.Storage = storage;
  },
  get Storage() { // Allows a node app (no vault) to examine storage.
    return KeySet.Storage;
  },
  set getUserDeviceSecret(functionOfTagAndPrompt) {  // Allows a node app (no vault) to override the default.
    KeySet.getUserDeviceSecret = functionOfTagAndPrompt;
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
        vault = await KeySet.ensure(tag);
    return vault.decrypt(encrypted, options);
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
  async changeMembership({tag, ...options}) { // Promise to add or remove members.
    let vault = await KeySet.ensure(tag);
    return vault.changeMembership(options);
  },
  async destroy(tagOrOptions) { // Promise to remove the tag and any associated data from all storage.
    if ('string' === typeof tagOrOptions) tagOrOptions = {tag: tagOrOptions};
    let {tag, ...options} = tagOrOptions;
    let vault = await KeySet.ensure(tag);
    return vault.destroy(options);
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

export { DeviceKeySet, Security as InternalSecurity, KeySet, Krypto, PersistedCollection as LocalCollection, MultiKrypto, TeamKeySet, dispatch };
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW50ZXJuYWwtYnJvd3Nlci1idW5kbGUubWpzIiwic291cmNlcyI6WyIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS93ZWJjcnlwdG8uanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9kaWdlc3QuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2J1ZmZlcl91dGlscy5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2Jhc2U2NHVybC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci91dGlsL2Vycm9ycy5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3JhbmRvbS5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvaXYuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2NoZWNrX2l2X2xlbmd0aC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2NoZWNrX2Nla19sZW5ndGguanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS90aW1pbmdfc2FmZV9lcXVhbC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvY3J5cHRvX2tleS5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9pc19rZXlfbGlrZS5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2RlY3J5cHQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2lzX2Rpc2pvaW50LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9pc19vYmplY3QuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9ib2d1cy5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2Flc2t3LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvZWNkaGVzLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9jaGVja19wMnMuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9wYmVzMmt3LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvc3VidGxlX3JzYWVzLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvY2hlY2tfa2V5X2xlbmd0aC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3JzYWVzLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9jZWsuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9qd2tfdG9fa2V5LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2tleS9pbXBvcnQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2NoZWNrX2tleV90eXBlLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvZW5jcnlwdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvYWVzZ2Nta3cuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2RlY3J5cHRfa2V5X21hbmFnZW1lbnQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL3ZhbGlkYXRlX2NyaXQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL3ZhbGlkYXRlX2FsZ29yaXRobXMuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandlL2ZsYXR0ZW5lZC9kZWNyeXB0LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3ZS9jb21wYWN0L2RlY3J5cHQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandlL2dlbmVyYWwvZGVjcnlwdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2tleV90b19qd2suanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIva2V5L2V4cG9ydC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvZW5jcnlwdF9rZXlfbWFuYWdlbWVudC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd2UvZmxhdHRlbmVkL2VuY3J5cHQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandlL2dlbmVyYWwvZW5jcnlwdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3N1YnRsZV9kc2EuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9nZXRfc2lnbl92ZXJpZnlfa2V5LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvdmVyaWZ5LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9mbGF0dGVuZWQvdmVyaWZ5LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9jb21wYWN0L3ZlcmlmeS5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd3MvZ2VuZXJhbC92ZXJpZnkuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandlL2NvbXBhY3QvZW5jcnlwdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3NpZ24uanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandzL2ZsYXR0ZW5lZC9zaWduLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9jb21wYWN0L3NpZ24uanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandzL2dlbmVyYWwvc2lnbi5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci91dGlsL2Jhc2U2NHVybC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci91dGlsL2RlY29kZV9wcm90ZWN0ZWRfaGVhZGVyLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvZ2VuZXJhdGUuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIva2V5L2dlbmVyYXRlX2tleV9wYWlyLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2tleS9nZW5lcmF0ZV9zZWNyZXQuanMiLCIuLi9saWIvYWxnb3JpdGhtcy5tanMiLCIuLi9saWIvcmF3LWJyb3dzZXIubWpzIiwiLi4vbGliL2tyeXB0by5tanMiLCIuLi9saWIvbXVsdGlLcnlwdG8ubWpzIiwiLi4vbGliL3N0b3JlLWluZGV4ZWQubWpzIiwiLi4vbGliL3NlY3JldC5tanMiLCIuLi9saWIvb3JpZ2luLWJyb3dzZXIubWpzIiwiLi4vbGliL21rZGlyLWJyb3dzZXIubWpzIiwiLi4vbGliL3RhZ1BhdGgubWpzIiwiLi4vbGliL3N0b3JhZ2UubWpzIiwiLi4vbGliL2tleVNldC5tanMiLCIuLi9saWIvcGFja2FnZS1sb2FkZXIubWpzIiwiLi4vbGliL2FwaS5tanMiLCIuLi9ub2RlX21vZHVsZXMvQGtpMXIweS9qc29ucnBjL2luZGV4Lm1qcyJdLCJzb3VyY2VzQ29udGVudCI6WyJleHBvcnQgZGVmYXVsdCBjcnlwdG87XG5leHBvcnQgY29uc3QgaXNDcnlwdG9LZXkgPSAoa2V5KSA9PiBrZXkgaW5zdGFuY2VvZiBDcnlwdG9LZXk7XG4iLCJpbXBvcnQgY3J5cHRvIGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmNvbnN0IGRpZ2VzdCA9IGFzeW5jIChhbGdvcml0aG0sIGRhdGEpID0+IHtcbiAgICBjb25zdCBzdWJ0bGVEaWdlc3QgPSBgU0hBLSR7YWxnb3JpdGhtLnNsaWNlKC0zKX1gO1xuICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmRpZ2VzdChzdWJ0bGVEaWdlc3QsIGRhdGEpKTtcbn07XG5leHBvcnQgZGVmYXVsdCBkaWdlc3Q7XG4iLCJpbXBvcnQgZGlnZXN0IGZyb20gJy4uL3J1bnRpbWUvZGlnZXN0LmpzJztcbmV4cG9ydCBjb25zdCBlbmNvZGVyID0gbmV3IFRleHRFbmNvZGVyKCk7XG5leHBvcnQgY29uc3QgZGVjb2RlciA9IG5ldyBUZXh0RGVjb2RlcigpO1xuY29uc3QgTUFYX0lOVDMyID0gMiAqKiAzMjtcbmV4cG9ydCBmdW5jdGlvbiBjb25jYXQoLi4uYnVmZmVycykge1xuICAgIGNvbnN0IHNpemUgPSBidWZmZXJzLnJlZHVjZSgoYWNjLCB7IGxlbmd0aCB9KSA9PiBhY2MgKyBsZW5ndGgsIDApO1xuICAgIGNvbnN0IGJ1ZiA9IG5ldyBVaW50OEFycmF5KHNpemUpO1xuICAgIGxldCBpID0gMDtcbiAgICBmb3IgKGNvbnN0IGJ1ZmZlciBvZiBidWZmZXJzKSB7XG4gICAgICAgIGJ1Zi5zZXQoYnVmZmVyLCBpKTtcbiAgICAgICAgaSArPSBidWZmZXIubGVuZ3RoO1xuICAgIH1cbiAgICByZXR1cm4gYnVmO1xufVxuZXhwb3J0IGZ1bmN0aW9uIHAycyhhbGcsIHAyc0lucHV0KSB7XG4gICAgcmV0dXJuIGNvbmNhdChlbmNvZGVyLmVuY29kZShhbGcpLCBuZXcgVWludDhBcnJheShbMF0pLCBwMnNJbnB1dCk7XG59XG5mdW5jdGlvbiB3cml0ZVVJbnQzMkJFKGJ1ZiwgdmFsdWUsIG9mZnNldCkge1xuICAgIGlmICh2YWx1ZSA8IDAgfHwgdmFsdWUgPj0gTUFYX0lOVDMyKSB7XG4gICAgICAgIHRocm93IG5ldyBSYW5nZUVycm9yKGB2YWx1ZSBtdXN0IGJlID49IDAgYW5kIDw9ICR7TUFYX0lOVDMyIC0gMX0uIFJlY2VpdmVkICR7dmFsdWV9YCk7XG4gICAgfVxuICAgIGJ1Zi5zZXQoW3ZhbHVlID4+PiAyNCwgdmFsdWUgPj4+IDE2LCB2YWx1ZSA+Pj4gOCwgdmFsdWUgJiAweGZmXSwgb2Zmc2V0KTtcbn1cbmV4cG9ydCBmdW5jdGlvbiB1aW50NjRiZSh2YWx1ZSkge1xuICAgIGNvbnN0IGhpZ2ggPSBNYXRoLmZsb29yKHZhbHVlIC8gTUFYX0lOVDMyKTtcbiAgICBjb25zdCBsb3cgPSB2YWx1ZSAlIE1BWF9JTlQzMjtcbiAgICBjb25zdCBidWYgPSBuZXcgVWludDhBcnJheSg4KTtcbiAgICB3cml0ZVVJbnQzMkJFKGJ1ZiwgaGlnaCwgMCk7XG4gICAgd3JpdGVVSW50MzJCRShidWYsIGxvdywgNCk7XG4gICAgcmV0dXJuIGJ1Zjtcbn1cbmV4cG9ydCBmdW5jdGlvbiB1aW50MzJiZSh2YWx1ZSkge1xuICAgIGNvbnN0IGJ1ZiA9IG5ldyBVaW50OEFycmF5KDQpO1xuICAgIHdyaXRlVUludDMyQkUoYnVmLCB2YWx1ZSk7XG4gICAgcmV0dXJuIGJ1Zjtcbn1cbmV4cG9ydCBmdW5jdGlvbiBsZW5ndGhBbmRJbnB1dChpbnB1dCkge1xuICAgIHJldHVybiBjb25jYXQodWludDMyYmUoaW5wdXQubGVuZ3RoKSwgaW5wdXQpO1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGNvbmNhdEtkZihzZWNyZXQsIGJpdHMsIHZhbHVlKSB7XG4gICAgY29uc3QgaXRlcmF0aW9ucyA9IE1hdGguY2VpbCgoYml0cyA+PiAzKSAvIDMyKTtcbiAgICBjb25zdCByZXMgPSBuZXcgVWludDhBcnJheShpdGVyYXRpb25zICogMzIpO1xuICAgIGZvciAobGV0IGl0ZXIgPSAwOyBpdGVyIDwgaXRlcmF0aW9uczsgaXRlcisrKSB7XG4gICAgICAgIGNvbnN0IGJ1ZiA9IG5ldyBVaW50OEFycmF5KDQgKyBzZWNyZXQubGVuZ3RoICsgdmFsdWUubGVuZ3RoKTtcbiAgICAgICAgYnVmLnNldCh1aW50MzJiZShpdGVyICsgMSkpO1xuICAgICAgICBidWYuc2V0KHNlY3JldCwgNCk7XG4gICAgICAgIGJ1Zi5zZXQodmFsdWUsIDQgKyBzZWNyZXQubGVuZ3RoKTtcbiAgICAgICAgcmVzLnNldChhd2FpdCBkaWdlc3QoJ3NoYTI1NicsIGJ1ZiksIGl0ZXIgKiAzMik7XG4gICAgfVxuICAgIHJldHVybiByZXMuc2xpY2UoMCwgYml0cyA+PiAzKTtcbn1cbiIsImltcG9ydCB7IGVuY29kZXIsIGRlY29kZXIgfSBmcm9tICcuLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmV4cG9ydCBjb25zdCBlbmNvZGVCYXNlNjQgPSAoaW5wdXQpID0+IHtcbiAgICBsZXQgdW5lbmNvZGVkID0gaW5wdXQ7XG4gICAgaWYgKHR5cGVvZiB1bmVuY29kZWQgPT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHVuZW5jb2RlZCA9IGVuY29kZXIuZW5jb2RlKHVuZW5jb2RlZCk7XG4gICAgfVxuICAgIGNvbnN0IENIVU5LX1NJWkUgPSAweDgwMDA7XG4gICAgY29uc3QgYXJyID0gW107XG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCB1bmVuY29kZWQubGVuZ3RoOyBpICs9IENIVU5LX1NJWkUpIHtcbiAgICAgICAgYXJyLnB1c2goU3RyaW5nLmZyb21DaGFyQ29kZS5hcHBseShudWxsLCB1bmVuY29kZWQuc3ViYXJyYXkoaSwgaSArIENIVU5LX1NJWkUpKSk7XG4gICAgfVxuICAgIHJldHVybiBidG9hKGFyci5qb2luKCcnKSk7XG59O1xuZXhwb3J0IGNvbnN0IGVuY29kZSA9IChpbnB1dCkgPT4ge1xuICAgIHJldHVybiBlbmNvZGVCYXNlNjQoaW5wdXQpLnJlcGxhY2UoLz0vZywgJycpLnJlcGxhY2UoL1xcKy9nLCAnLScpLnJlcGxhY2UoL1xcLy9nLCAnXycpO1xufTtcbmV4cG9ydCBjb25zdCBkZWNvZGVCYXNlNjQgPSAoZW5jb2RlZCkgPT4ge1xuICAgIGNvbnN0IGJpbmFyeSA9IGF0b2IoZW5jb2RlZCk7XG4gICAgY29uc3QgYnl0ZXMgPSBuZXcgVWludDhBcnJheShiaW5hcnkubGVuZ3RoKTtcbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IGJpbmFyeS5sZW5ndGg7IGkrKykge1xuICAgICAgICBieXRlc1tpXSA9IGJpbmFyeS5jaGFyQ29kZUF0KGkpO1xuICAgIH1cbiAgICByZXR1cm4gYnl0ZXM7XG59O1xuZXhwb3J0IGNvbnN0IGRlY29kZSA9IChpbnB1dCkgPT4ge1xuICAgIGxldCBlbmNvZGVkID0gaW5wdXQ7XG4gICAgaWYgKGVuY29kZWQgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIGVuY29kZWQgPSBkZWNvZGVyLmRlY29kZShlbmNvZGVkKTtcbiAgICB9XG4gICAgZW5jb2RlZCA9IGVuY29kZWQucmVwbGFjZSgvLS9nLCAnKycpLnJlcGxhY2UoL18vZywgJy8nKS5yZXBsYWNlKC9cXHMvZywgJycpO1xuICAgIHRyeSB7XG4gICAgICAgIHJldHVybiBkZWNvZGVCYXNlNjQoZW5jb2RlZCk7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignVGhlIGlucHV0IHRvIGJlIGRlY29kZWQgaXMgbm90IGNvcnJlY3RseSBlbmNvZGVkLicpO1xuICAgIH1cbn07XG4iLCJleHBvcnQgY2xhc3MgSk9TRUVycm9yIGV4dGVuZHMgRXJyb3Ige1xuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSk9TRV9HRU5FUklDJztcbiAgICB9XG4gICAgY29uc3RydWN0b3IobWVzc2FnZSkge1xuICAgICAgICBzdXBlcihtZXNzYWdlKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KT1NFX0dFTkVSSUMnO1xuICAgICAgICB0aGlzLm5hbWUgPSB0aGlzLmNvbnN0cnVjdG9yLm5hbWU7XG4gICAgICAgIEVycm9yLmNhcHR1cmVTdGFja1RyYWNlPy4odGhpcywgdGhpcy5jb25zdHJ1Y3Rvcik7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXVENsYWltVmFsaWRhdGlvbkZhaWxlZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV1RfQ0xBSU1fVkFMSURBVElPTl9GQUlMRUQnO1xuICAgIH1cbiAgICBjb25zdHJ1Y3RvcihtZXNzYWdlLCBjbGFpbSA9ICd1bnNwZWNpZmllZCcsIHJlYXNvbiA9ICd1bnNwZWNpZmllZCcpIHtcbiAgICAgICAgc3VwZXIobWVzc2FnZSk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldUX0NMQUlNX1ZBTElEQVRJT05fRkFJTEVEJztcbiAgICAgICAgdGhpcy5jbGFpbSA9IGNsYWltO1xuICAgICAgICB0aGlzLnJlYXNvbiA9IHJlYXNvbjtcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgSldURXhwaXJlZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV1RfRVhQSVJFRCc7XG4gICAgfVxuICAgIGNvbnN0cnVjdG9yKG1lc3NhZ2UsIGNsYWltID0gJ3Vuc3BlY2lmaWVkJywgcmVhc29uID0gJ3Vuc3BlY2lmaWVkJykge1xuICAgICAgICBzdXBlcihtZXNzYWdlKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV1RfRVhQSVJFRCc7XG4gICAgICAgIHRoaXMuY2xhaW0gPSBjbGFpbTtcbiAgICAgICAgdGhpcy5yZWFzb24gPSByZWFzb247XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpPU0VBbGdOb3RBbGxvd2VkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KT1NFX0FMR19OT1RfQUxMT1dFRCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSk9TRV9BTEdfTk9UX0FMTE9XRUQnO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKT1NFTm90U3VwcG9ydGVkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KT1NFX05PVF9TVVBQT1JURUQnO1xuICAgIH1cbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pPU0VfTk9UX1NVUFBPUlRFRCc7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXRURlY3J5cHRpb25GYWlsZWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXRV9ERUNSWVBUSU9OX0ZBSUxFRCc7XG4gICAgICAgIHRoaXMubWVzc2FnZSA9ICdkZWNyeXB0aW9uIG9wZXJhdGlvbiBmYWlsZWQnO1xuICAgIH1cbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pXRV9ERUNSWVBUSU9OX0ZBSUxFRCc7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXRUludmFsaWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXRV9JTlZBTElEJztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV0VfSU5WQUxJRCc7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXU0ludmFsaWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXU19JTlZBTElEJztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV1NfSU5WQUxJRCc7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXVEludmFsaWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXVF9JTlZBTElEJztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV1RfSU5WQUxJRCc7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXS0ludmFsaWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXS19JTlZBTElEJztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV0tfSU5WQUxJRCc7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXS1NJbnZhbGlkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0tTX0lOVkFMSUQnO1xuICAgIH1cbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pXS1NfSU5WQUxJRCc7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXS1NOb01hdGNoaW5nS2V5IGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0tTX05PX01BVENISU5HX0tFWSc7XG4gICAgICAgIHRoaXMubWVzc2FnZSA9ICdubyBhcHBsaWNhYmxlIGtleSBmb3VuZCBpbiB0aGUgSlNPTiBXZWIgS2V5IFNldCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldLU19OT19NQVRDSElOR19LRVknO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV0tTTXVsdGlwbGVNYXRjaGluZ0tleXMgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXS1NfTVVMVElQTEVfTUFUQ0hJTkdfS0VZUyc7XG4gICAgICAgIHRoaXMubWVzc2FnZSA9ICdtdWx0aXBsZSBtYXRjaGluZyBrZXlzIGZvdW5kIGluIHRoZSBKU09OIFdlYiBLZXkgU2V0JztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV0tTX01VTFRJUExFX01BVENISU5HX0tFWVMnO1xuICAgIH1cbn1cblN5bWJvbC5hc3luY0l0ZXJhdG9yO1xuZXhwb3J0IGNsYXNzIEpXS1NUaW1lb3V0IGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0tTX1RJTUVPVVQnO1xuICAgICAgICB0aGlzLm1lc3NhZ2UgPSAncmVxdWVzdCB0aW1lZCBvdXQnO1xuICAgIH1cbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pXS1NfVElNRU9VVCc7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXU1NpZ25hdHVyZVZlcmlmaWNhdGlvbkZhaWxlZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldTX1NJR05BVFVSRV9WRVJJRklDQVRJT05fRkFJTEVEJztcbiAgICAgICAgdGhpcy5tZXNzYWdlID0gJ3NpZ25hdHVyZSB2ZXJpZmljYXRpb24gZmFpbGVkJztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV1NfU0lHTkFUVVJFX1ZFUklGSUNBVElPTl9GQUlMRUQnO1xuICAgIH1cbn1cbiIsImltcG9ydCBjcnlwdG8gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuZXhwb3J0IGRlZmF1bHQgY3J5cHRvLmdldFJhbmRvbVZhbHVlcy5iaW5kKGNyeXB0byk7XG4iLCJpbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHJhbmRvbSBmcm9tICcuLi9ydW50aW1lL3JhbmRvbS5qcyc7XG5leHBvcnQgZnVuY3Rpb24gYml0TGVuZ3RoKGFsZykge1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ0ExMjhHQ00nOlxuICAgICAgICBjYXNlICdBMTI4R0NNS1cnOlxuICAgICAgICBjYXNlICdBMTkyR0NNJzpcbiAgICAgICAgY2FzZSAnQTE5MkdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTSc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ01LVyc6XG4gICAgICAgICAgICByZXR1cm4gOTY7XG4gICAgICAgIGNhc2UgJ0ExMjhDQkMtSFMyNTYnOlxuICAgICAgICBjYXNlICdBMTkyQ0JDLUhTMzg0JzpcbiAgICAgICAgY2FzZSAnQTI1NkNCQy1IUzUxMic6XG4gICAgICAgICAgICByZXR1cm4gMTI4O1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoYFVuc3VwcG9ydGVkIEpXRSBBbGdvcml0aG06ICR7YWxnfWApO1xuICAgIH1cbn1cbmV4cG9ydCBkZWZhdWx0IChhbGcpID0+IHJhbmRvbShuZXcgVWludDhBcnJheShiaXRMZW5ndGgoYWxnKSA+PiAzKSk7XG4iLCJpbXBvcnQgeyBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHsgYml0TGVuZ3RoIH0gZnJvbSAnLi9pdi5qcyc7XG5jb25zdCBjaGVja0l2TGVuZ3RoID0gKGVuYywgaXYpID0+IHtcbiAgICBpZiAoaXYubGVuZ3RoIDw8IDMgIT09IGJpdExlbmd0aChlbmMpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdJbnZhbGlkIEluaXRpYWxpemF0aW9uIFZlY3RvciBsZW5ndGgnKTtcbiAgICB9XG59O1xuZXhwb3J0IGRlZmF1bHQgY2hlY2tJdkxlbmd0aDtcbiIsImltcG9ydCB7IEpXRUludmFsaWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5jb25zdCBjaGVja0Nla0xlbmd0aCA9IChjZWssIGV4cGVjdGVkKSA9PiB7XG4gICAgY29uc3QgYWN0dWFsID0gY2VrLmJ5dGVMZW5ndGggPDwgMztcbiAgICBpZiAoYWN0dWFsICE9PSBleHBlY3RlZCkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSW52YWxpZCBDb250ZW50IEVuY3J5cHRpb24gS2V5IGxlbmd0aC4gRXhwZWN0ZWQgJHtleHBlY3RlZH0gYml0cywgZ290ICR7YWN0dWFsfSBiaXRzYCk7XG4gICAgfVxufTtcbmV4cG9ydCBkZWZhdWx0IGNoZWNrQ2VrTGVuZ3RoO1xuIiwiY29uc3QgdGltaW5nU2FmZUVxdWFsID0gKGEsIGIpID0+IHtcbiAgICBpZiAoIShhIGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignRmlyc3QgYXJndW1lbnQgbXVzdCBiZSBhIGJ1ZmZlcicpO1xuICAgIH1cbiAgICBpZiAoIShiIGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignU2Vjb25kIGFyZ3VtZW50IG11c3QgYmUgYSBidWZmZXInKTtcbiAgICB9XG4gICAgaWYgKGEubGVuZ3RoICE9PSBiLmxlbmd0aCkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdJbnB1dCBidWZmZXJzIG11c3QgaGF2ZSB0aGUgc2FtZSBsZW5ndGgnKTtcbiAgICB9XG4gICAgY29uc3QgbGVuID0gYS5sZW5ndGg7XG4gICAgbGV0IG91dCA9IDA7XG4gICAgbGV0IGkgPSAtMTtcbiAgICB3aGlsZSAoKytpIDwgbGVuKSB7XG4gICAgICAgIG91dCB8PSBhW2ldIF4gYltpXTtcbiAgICB9XG4gICAgcmV0dXJuIG91dCA9PT0gMDtcbn07XG5leHBvcnQgZGVmYXVsdCB0aW1pbmdTYWZlRXF1YWw7XG4iLCJmdW5jdGlvbiB1bnVzYWJsZShuYW1lLCBwcm9wID0gJ2FsZ29yaXRobS5uYW1lJykge1xuICAgIHJldHVybiBuZXcgVHlwZUVycm9yKGBDcnlwdG9LZXkgZG9lcyBub3Qgc3VwcG9ydCB0aGlzIG9wZXJhdGlvbiwgaXRzICR7cHJvcH0gbXVzdCBiZSAke25hbWV9YCk7XG59XG5mdW5jdGlvbiBpc0FsZ29yaXRobShhbGdvcml0aG0sIG5hbWUpIHtcbiAgICByZXR1cm4gYWxnb3JpdGhtLm5hbWUgPT09IG5hbWU7XG59XG5mdW5jdGlvbiBnZXRIYXNoTGVuZ3RoKGhhc2gpIHtcbiAgICByZXR1cm4gcGFyc2VJbnQoaGFzaC5uYW1lLnNsaWNlKDQpLCAxMCk7XG59XG5mdW5jdGlvbiBnZXROYW1lZEN1cnZlKGFsZykge1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ0VTMjU2JzpcbiAgICAgICAgICAgIHJldHVybiAnUC0yNTYnO1xuICAgICAgICBjYXNlICdFUzM4NCc6XG4gICAgICAgICAgICByZXR1cm4gJ1AtMzg0JztcbiAgICAgICAgY2FzZSAnRVM1MTInOlxuICAgICAgICAgICAgcmV0dXJuICdQLTUyMSc7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ3VucmVhY2hhYmxlJyk7XG4gICAgfVxufVxuZnVuY3Rpb24gY2hlY2tVc2FnZShrZXksIHVzYWdlcykge1xuICAgIGlmICh1c2FnZXMubGVuZ3RoICYmICF1c2FnZXMuc29tZSgoZXhwZWN0ZWQpID0+IGtleS51c2FnZXMuaW5jbHVkZXMoZXhwZWN0ZWQpKSkge1xuICAgICAgICBsZXQgbXNnID0gJ0NyeXB0b0tleSBkb2VzIG5vdCBzdXBwb3J0IHRoaXMgb3BlcmF0aW9uLCBpdHMgdXNhZ2VzIG11c3QgaW5jbHVkZSAnO1xuICAgICAgICBpZiAodXNhZ2VzLmxlbmd0aCA+IDIpIHtcbiAgICAgICAgICAgIGNvbnN0IGxhc3QgPSB1c2FnZXMucG9wKCk7XG4gICAgICAgICAgICBtc2cgKz0gYG9uZSBvZiAke3VzYWdlcy5qb2luKCcsICcpfSwgb3IgJHtsYXN0fS5gO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKHVzYWdlcy5sZW5ndGggPT09IDIpIHtcbiAgICAgICAgICAgIG1zZyArPSBgb25lIG9mICR7dXNhZ2VzWzBdfSBvciAke3VzYWdlc1sxXX0uYDtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIG1zZyArPSBgJHt1c2FnZXNbMF19LmA7XG4gICAgICAgIH1cbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihtc2cpO1xuICAgIH1cbn1cbmV4cG9ydCBmdW5jdGlvbiBjaGVja1NpZ0NyeXB0b0tleShrZXksIGFsZywgLi4udXNhZ2VzKSB7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnSFMyNTYnOlxuICAgICAgICBjYXNlICdIUzM4NCc6XG4gICAgICAgIGNhc2UgJ0hTNTEyJzoge1xuICAgICAgICAgICAgaWYgKCFpc0FsZ29yaXRobShrZXkuYWxnb3JpdGhtLCAnSE1BQycpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdITUFDJyk7XG4gICAgICAgICAgICBjb25zdCBleHBlY3RlZCA9IHBhcnNlSW50KGFsZy5zbGljZSgyKSwgMTApO1xuICAgICAgICAgICAgY29uc3QgYWN0dWFsID0gZ2V0SGFzaExlbmd0aChrZXkuYWxnb3JpdGhtLmhhc2gpO1xuICAgICAgICAgICAgaWYgKGFjdHVhbCAhPT0gZXhwZWN0ZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoYFNIQS0ke2V4cGVjdGVkfWAsICdhbGdvcml0aG0uaGFzaCcpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnUlMyNTYnOlxuICAgICAgICBjYXNlICdSUzM4NCc6XG4gICAgICAgIGNhc2UgJ1JTNTEyJzoge1xuICAgICAgICAgICAgaWYgKCFpc0FsZ29yaXRobShrZXkuYWxnb3JpdGhtLCAnUlNBU1NBLVBLQ1MxLXYxXzUnKSlcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnUlNBU1NBLVBLQ1MxLXYxXzUnKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGVjdGVkID0gcGFyc2VJbnQoYWxnLnNsaWNlKDIpLCAxMCk7XG4gICAgICAgICAgICBjb25zdCBhY3R1YWwgPSBnZXRIYXNoTGVuZ3RoKGtleS5hbGdvcml0aG0uaGFzaCk7XG4gICAgICAgICAgICBpZiAoYWN0dWFsICE9PSBleHBlY3RlZClcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZShgU0hBLSR7ZXhwZWN0ZWR9YCwgJ2FsZ29yaXRobS5oYXNoJyk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdQUzI1Nic6XG4gICAgICAgIGNhc2UgJ1BTMzg0JzpcbiAgICAgICAgY2FzZSAnUFM1MTInOiB7XG4gICAgICAgICAgICBpZiAoIWlzQWxnb3JpdGhtKGtleS5hbGdvcml0aG0sICdSU0EtUFNTJykpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ1JTQS1QU1MnKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGVjdGVkID0gcGFyc2VJbnQoYWxnLnNsaWNlKDIpLCAxMCk7XG4gICAgICAgICAgICBjb25zdCBhY3R1YWwgPSBnZXRIYXNoTGVuZ3RoKGtleS5hbGdvcml0aG0uaGFzaCk7XG4gICAgICAgICAgICBpZiAoYWN0dWFsICE9PSBleHBlY3RlZClcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZShgU0hBLSR7ZXhwZWN0ZWR9YCwgJ2FsZ29yaXRobS5oYXNoJyk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdFZERTQSc6IHtcbiAgICAgICAgICAgIGlmIChrZXkuYWxnb3JpdGhtLm5hbWUgIT09ICdFZDI1NTE5JyAmJiBrZXkuYWxnb3JpdGhtLm5hbWUgIT09ICdFZDQ0OCcpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnRWQyNTUxOSBvciBFZDQ0OCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnRVMyNTYnOlxuICAgICAgICBjYXNlICdFUzM4NCc6XG4gICAgICAgIGNhc2UgJ0VTNTEyJzoge1xuICAgICAgICAgICAgaWYgKCFpc0FsZ29yaXRobShrZXkuYWxnb3JpdGhtLCAnRUNEU0EnKSlcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnRUNEU0EnKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGVjdGVkID0gZ2V0TmFtZWRDdXJ2ZShhbGcpO1xuICAgICAgICAgICAgY29uc3QgYWN0dWFsID0ga2V5LmFsZ29yaXRobS5uYW1lZEN1cnZlO1xuICAgICAgICAgICAgaWYgKGFjdHVhbCAhPT0gZXhwZWN0ZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoZXhwZWN0ZWQsICdhbGdvcml0aG0ubmFtZWRDdXJ2ZScpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0NyeXB0b0tleSBkb2VzIG5vdCBzdXBwb3J0IHRoaXMgb3BlcmF0aW9uJyk7XG4gICAgfVxuICAgIGNoZWNrVXNhZ2Uoa2V5LCB1c2FnZXMpO1xufVxuZXhwb3J0IGZ1bmN0aW9uIGNoZWNrRW5jQ3J5cHRvS2V5KGtleSwgYWxnLCAuLi51c2FnZXMpIHtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdBMTI4R0NNJzpcbiAgICAgICAgY2FzZSAnQTE5MkdDTSc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ00nOiB7XG4gICAgICAgICAgICBpZiAoIWlzQWxnb3JpdGhtKGtleS5hbGdvcml0aG0sICdBRVMtR0NNJykpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ0FFUy1HQ00nKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGVjdGVkID0gcGFyc2VJbnQoYWxnLnNsaWNlKDEsIDQpLCAxMCk7XG4gICAgICAgICAgICBjb25zdCBhY3R1YWwgPSBrZXkuYWxnb3JpdGhtLmxlbmd0aDtcbiAgICAgICAgICAgIGlmIChhY3R1YWwgIT09IGV4cGVjdGVkKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKGV4cGVjdGVkLCAnYWxnb3JpdGhtLmxlbmd0aCcpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnQTE5MktXJzpcbiAgICAgICAgY2FzZSAnQTI1NktXJzoge1xuICAgICAgICAgICAgaWYgKCFpc0FsZ29yaXRobShrZXkuYWxnb3JpdGhtLCAnQUVTLUtXJykpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ0FFUy1LVycpO1xuICAgICAgICAgICAgY29uc3QgZXhwZWN0ZWQgPSBwYXJzZUludChhbGcuc2xpY2UoMSwgNCksIDEwKTtcbiAgICAgICAgICAgIGNvbnN0IGFjdHVhbCA9IGtleS5hbGdvcml0aG0ubGVuZ3RoO1xuICAgICAgICAgICAgaWYgKGFjdHVhbCAhPT0gZXhwZWN0ZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoZXhwZWN0ZWQsICdhbGdvcml0aG0ubGVuZ3RoJyk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdFQ0RIJzoge1xuICAgICAgICAgICAgc3dpdGNoIChrZXkuYWxnb3JpdGhtLm5hbWUpIHtcbiAgICAgICAgICAgICAgICBjYXNlICdFQ0RIJzpcbiAgICAgICAgICAgICAgICBjYXNlICdYMjU1MTknOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1g0NDgnOlxuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnRUNESCwgWDI1NTE5LCBvciBYNDQ4Jyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdQQkVTMi1IUzI1NitBMTI4S1cnOlxuICAgICAgICBjYXNlICdQQkVTMi1IUzM4NCtBMTkyS1cnOlxuICAgICAgICBjYXNlICdQQkVTMi1IUzUxMitBMjU2S1cnOlxuICAgICAgICAgICAgaWYgKCFpc0FsZ29yaXRobShrZXkuYWxnb3JpdGhtLCAnUEJLREYyJykpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ1BCS0RGMicpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQJzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMjU2JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMzg0JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtNTEyJzoge1xuICAgICAgICAgICAgaWYgKCFpc0FsZ29yaXRobShrZXkuYWxnb3JpdGhtLCAnUlNBLU9BRVAnKSlcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnUlNBLU9BRVAnKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGVjdGVkID0gcGFyc2VJbnQoYWxnLnNsaWNlKDkpLCAxMCkgfHwgMTtcbiAgICAgICAgICAgIGNvbnN0IGFjdHVhbCA9IGdldEhhc2hMZW5ndGgoa2V5LmFsZ29yaXRobS5oYXNoKTtcbiAgICAgICAgICAgIGlmIChhY3R1YWwgIT09IGV4cGVjdGVkKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKGBTSEEtJHtleHBlY3RlZH1gLCAnYWxnb3JpdGhtLmhhc2gnKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdDcnlwdG9LZXkgZG9lcyBub3Qgc3VwcG9ydCB0aGlzIG9wZXJhdGlvbicpO1xuICAgIH1cbiAgICBjaGVja1VzYWdlKGtleSwgdXNhZ2VzKTtcbn1cbiIsImZ1bmN0aW9uIG1lc3NhZ2UobXNnLCBhY3R1YWwsIC4uLnR5cGVzKSB7XG4gICAgaWYgKHR5cGVzLmxlbmd0aCA+IDIpIHtcbiAgICAgICAgY29uc3QgbGFzdCA9IHR5cGVzLnBvcCgpO1xuICAgICAgICBtc2cgKz0gYG9uZSBvZiB0eXBlICR7dHlwZXMuam9pbignLCAnKX0sIG9yICR7bGFzdH0uYDtcbiAgICB9XG4gICAgZWxzZSBpZiAodHlwZXMubGVuZ3RoID09PSAyKSB7XG4gICAgICAgIG1zZyArPSBgb25lIG9mIHR5cGUgJHt0eXBlc1swXX0gb3IgJHt0eXBlc1sxXX0uYDtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIG1zZyArPSBgb2YgdHlwZSAke3R5cGVzWzBdfS5gO1xuICAgIH1cbiAgICBpZiAoYWN0dWFsID09IG51bGwpIHtcbiAgICAgICAgbXNnICs9IGAgUmVjZWl2ZWQgJHthY3R1YWx9YDtcbiAgICB9XG4gICAgZWxzZSBpZiAodHlwZW9mIGFjdHVhbCA9PT0gJ2Z1bmN0aW9uJyAmJiBhY3R1YWwubmFtZSkge1xuICAgICAgICBtc2cgKz0gYCBSZWNlaXZlZCBmdW5jdGlvbiAke2FjdHVhbC5uYW1lfWA7XG4gICAgfVxuICAgIGVsc2UgaWYgKHR5cGVvZiBhY3R1YWwgPT09ICdvYmplY3QnICYmIGFjdHVhbCAhPSBudWxsKSB7XG4gICAgICAgIGlmIChhY3R1YWwuY29uc3RydWN0b3I/Lm5hbWUpIHtcbiAgICAgICAgICAgIG1zZyArPSBgIFJlY2VpdmVkIGFuIGluc3RhbmNlIG9mICR7YWN0dWFsLmNvbnN0cnVjdG9yLm5hbWV9YDtcbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gbXNnO1xufVxuZXhwb3J0IGRlZmF1bHQgKGFjdHVhbCwgLi4udHlwZXMpID0+IHtcbiAgICByZXR1cm4gbWVzc2FnZSgnS2V5IG11c3QgYmUgJywgYWN0dWFsLCAuLi50eXBlcyk7XG59O1xuZXhwb3J0IGZ1bmN0aW9uIHdpdGhBbGcoYWxnLCBhY3R1YWwsIC4uLnR5cGVzKSB7XG4gICAgcmV0dXJuIG1lc3NhZ2UoYEtleSBmb3IgdGhlICR7YWxnfSBhbGdvcml0aG0gbXVzdCBiZSBgLCBhY3R1YWwsIC4uLnR5cGVzKTtcbn1cbiIsImltcG9ydCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuZXhwb3J0IGRlZmF1bHQgKGtleSkgPT4ge1xuICAgIHJldHVybiBpc0NyeXB0b0tleShrZXkpO1xufTtcbmV4cG9ydCBjb25zdCB0eXBlcyA9IFsnQ3J5cHRvS2V5J107XG4iLCJpbXBvcnQgeyBjb25jYXQsIHVpbnQ2NGJlIH0gZnJvbSAnLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgY2hlY2tJdkxlbmd0aCBmcm9tICcuLi9saWIvY2hlY2tfaXZfbGVuZ3RoLmpzJztcbmltcG9ydCBjaGVja0Nla0xlbmd0aCBmcm9tICcuL2NoZWNrX2Nla19sZW5ndGguanMnO1xuaW1wb3J0IHRpbWluZ1NhZmVFcXVhbCBmcm9tICcuL3RpbWluZ19zYWZlX2VxdWFsLmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQsIEpXRURlY3J5cHRpb25GYWlsZWQsIEpXRUludmFsaWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tFbmNDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuYXN5bmMgZnVuY3Rpb24gY2JjRGVjcnlwdChlbmMsIGNlaywgY2lwaGVydGV4dCwgaXYsIHRhZywgYWFkKSB7XG4gICAgaWYgKCEoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoY2VrLCAnVWludDhBcnJheScpKTtcbiAgICB9XG4gICAgY29uc3Qga2V5U2l6ZSA9IHBhcnNlSW50KGVuYy5zbGljZSgxLCA0KSwgMTApO1xuICAgIGNvbnN0IGVuY0tleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBjZWsuc3ViYXJyYXkoa2V5U2l6ZSA+PiAzKSwgJ0FFUy1DQkMnLCBmYWxzZSwgWydkZWNyeXB0J10pO1xuICAgIGNvbnN0IG1hY0tleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBjZWsuc3ViYXJyYXkoMCwga2V5U2l6ZSA+PiAzKSwge1xuICAgICAgICBoYXNoOiBgU0hBLSR7a2V5U2l6ZSA8PCAxfWAsXG4gICAgICAgIG5hbWU6ICdITUFDJyxcbiAgICB9LCBmYWxzZSwgWydzaWduJ10pO1xuICAgIGNvbnN0IG1hY0RhdGEgPSBjb25jYXQoYWFkLCBpdiwgY2lwaGVydGV4dCwgdWludDY0YmUoYWFkLmxlbmd0aCA8PCAzKSk7XG4gICAgY29uc3QgZXhwZWN0ZWRUYWcgPSBuZXcgVWludDhBcnJheSgoYXdhaXQgY3J5cHRvLnN1YnRsZS5zaWduKCdITUFDJywgbWFjS2V5LCBtYWNEYXRhKSkuc2xpY2UoMCwga2V5U2l6ZSA+PiAzKSk7XG4gICAgbGV0IG1hY0NoZWNrUGFzc2VkO1xuICAgIHRyeSB7XG4gICAgICAgIG1hY0NoZWNrUGFzc2VkID0gdGltaW5nU2FmZUVxdWFsKHRhZywgZXhwZWN0ZWRUYWcpO1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgfVxuICAgIGlmICghbWFjQ2hlY2tQYXNzZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRURlY3J5cHRpb25GYWlsZWQoKTtcbiAgICB9XG4gICAgbGV0IHBsYWludGV4dDtcbiAgICB0cnkge1xuICAgICAgICBwbGFpbnRleHQgPSBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmRlY3J5cHQoeyBpdiwgbmFtZTogJ0FFUy1DQkMnIH0sIGVuY0tleSwgY2lwaGVydGV4dCkpO1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgfVxuICAgIGlmICghcGxhaW50ZXh0KSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VEZWNyeXB0aW9uRmFpbGVkKCk7XG4gICAgfVxuICAgIHJldHVybiBwbGFpbnRleHQ7XG59XG5hc3luYyBmdW5jdGlvbiBnY21EZWNyeXB0KGVuYywgY2VrLCBjaXBoZXJ0ZXh0LCBpdiwgdGFnLCBhYWQpIHtcbiAgICBsZXQgZW5jS2V5O1xuICAgIGlmIChjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIGVuY0tleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBjZWssICdBRVMtR0NNJywgZmFsc2UsIFsnZGVjcnlwdCddKTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIGNoZWNrRW5jQ3J5cHRvS2V5KGNlaywgZW5jLCAnZGVjcnlwdCcpO1xuICAgICAgICBlbmNLZXkgPSBjZWs7XG4gICAgfVxuICAgIHRyeSB7XG4gICAgICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmRlY3J5cHQoe1xuICAgICAgICAgICAgYWRkaXRpb25hbERhdGE6IGFhZCxcbiAgICAgICAgICAgIGl2LFxuICAgICAgICAgICAgbmFtZTogJ0FFUy1HQ00nLFxuICAgICAgICAgICAgdGFnTGVuZ3RoOiAxMjgsXG4gICAgICAgIH0sIGVuY0tleSwgY29uY2F0KGNpcGhlcnRleHQsIHRhZykpKTtcbiAgICB9XG4gICAgY2F0Y2gge1xuICAgICAgICB0aHJvdyBuZXcgSldFRGVjcnlwdGlvbkZhaWxlZCgpO1xuICAgIH1cbn1cbmNvbnN0IGRlY3J5cHQgPSBhc3luYyAoZW5jLCBjZWssIGNpcGhlcnRleHQsIGl2LCB0YWcsIGFhZCkgPT4ge1xuICAgIGlmICghaXNDcnlwdG9LZXkoY2VrKSAmJiAhKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGNlaywgLi4udHlwZXMsICdVaW50OEFycmF5JykpO1xuICAgIH1cbiAgICBpZiAoIWl2KSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgSW5pdGlhbGl6YXRpb24gVmVjdG9yIG1pc3NpbmcnKTtcbiAgICB9XG4gICAgaWYgKCF0YWcpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBBdXRoZW50aWNhdGlvbiBUYWcgbWlzc2luZycpO1xuICAgIH1cbiAgICBjaGVja0l2TGVuZ3RoKGVuYywgaXYpO1xuICAgIHN3aXRjaCAoZW5jKSB7XG4gICAgICAgIGNhc2UgJ0ExMjhDQkMtSFMyNTYnOlxuICAgICAgICBjYXNlICdBMTkyQ0JDLUhTMzg0JzpcbiAgICAgICAgY2FzZSAnQTI1NkNCQy1IUzUxMic6XG4gICAgICAgICAgICBpZiAoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSlcbiAgICAgICAgICAgICAgICBjaGVja0Nla0xlbmd0aChjZWssIHBhcnNlSW50KGVuYy5zbGljZSgtMyksIDEwKSk7XG4gICAgICAgICAgICByZXR1cm4gY2JjRGVjcnlwdChlbmMsIGNlaywgY2lwaGVydGV4dCwgaXYsIHRhZywgYWFkKTtcbiAgICAgICAgY2FzZSAnQTEyOEdDTSc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ00nOlxuICAgICAgICBjYXNlICdBMjU2R0NNJzpcbiAgICAgICAgICAgIGlmIChjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KVxuICAgICAgICAgICAgICAgIGNoZWNrQ2VrTGVuZ3RoKGNlaywgcGFyc2VJbnQoZW5jLnNsaWNlKDEsIDQpLCAxMCkpO1xuICAgICAgICAgICAgcmV0dXJuIGdjbURlY3J5cHQoZW5jLCBjZWssIGNpcGhlcnRleHQsIGl2LCB0YWcsIGFhZCk7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnVW5zdXBwb3J0ZWQgSldFIENvbnRlbnQgRW5jcnlwdGlvbiBBbGdvcml0aG0nKTtcbiAgICB9XG59O1xuZXhwb3J0IGRlZmF1bHQgZGVjcnlwdDtcbiIsImNvbnN0IGlzRGlzam9pbnQgPSAoLi4uaGVhZGVycykgPT4ge1xuICAgIGNvbnN0IHNvdXJjZXMgPSBoZWFkZXJzLmZpbHRlcihCb29sZWFuKTtcbiAgICBpZiAoc291cmNlcy5sZW5ndGggPT09IDAgfHwgc291cmNlcy5sZW5ndGggPT09IDEpIHtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIGxldCBhY2M7XG4gICAgZm9yIChjb25zdCBoZWFkZXIgb2Ygc291cmNlcykge1xuICAgICAgICBjb25zdCBwYXJhbWV0ZXJzID0gT2JqZWN0LmtleXMoaGVhZGVyKTtcbiAgICAgICAgaWYgKCFhY2MgfHwgYWNjLnNpemUgPT09IDApIHtcbiAgICAgICAgICAgIGFjYyA9IG5ldyBTZXQocGFyYW1ldGVycyk7XG4gICAgICAgICAgICBjb250aW51ZTtcbiAgICAgICAgfVxuICAgICAgICBmb3IgKGNvbnN0IHBhcmFtZXRlciBvZiBwYXJhbWV0ZXJzKSB7XG4gICAgICAgICAgICBpZiAoYWNjLmhhcyhwYXJhbWV0ZXIpKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYWNjLmFkZChwYXJhbWV0ZXIpO1xuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiB0cnVlO1xufTtcbmV4cG9ydCBkZWZhdWx0IGlzRGlzam9pbnQ7XG4iLCJmdW5jdGlvbiBpc09iamVjdExpa2UodmFsdWUpIHtcbiAgICByZXR1cm4gdHlwZW9mIHZhbHVlID09PSAnb2JqZWN0JyAmJiB2YWx1ZSAhPT0gbnVsbDtcbn1cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGlzT2JqZWN0KGlucHV0KSB7XG4gICAgaWYgKCFpc09iamVjdExpa2UoaW5wdXQpIHx8IE9iamVjdC5wcm90b3R5cGUudG9TdHJpbmcuY2FsbChpbnB1dCkgIT09ICdbb2JqZWN0IE9iamVjdF0nKSB7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gICAgaWYgKE9iamVjdC5nZXRQcm90b3R5cGVPZihpbnB1dCkgPT09IG51bGwpIHtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIGxldCBwcm90byA9IGlucHV0O1xuICAgIHdoaWxlIChPYmplY3QuZ2V0UHJvdG90eXBlT2YocHJvdG8pICE9PSBudWxsKSB7XG4gICAgICAgIHByb3RvID0gT2JqZWN0LmdldFByb3RvdHlwZU9mKHByb3RvKTtcbiAgICB9XG4gICAgcmV0dXJuIE9iamVjdC5nZXRQcm90b3R5cGVPZihpbnB1dCkgPT09IHByb3RvO1xufVxuIiwiY29uc3QgYm9ndXNXZWJDcnlwdG8gPSBbXG4gICAgeyBoYXNoOiAnU0hBLTI1NicsIG5hbWU6ICdITUFDJyB9LFxuICAgIHRydWUsXG4gICAgWydzaWduJ10sXG5dO1xuZXhwb3J0IGRlZmF1bHQgYm9ndXNXZWJDcnlwdG87XG4iLCJpbXBvcnQgYm9ndXNXZWJDcnlwdG8gZnJvbSAnLi9ib2d1cy5qcyc7XG5pbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tFbmNDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuZnVuY3Rpb24gY2hlY2tLZXlTaXplKGtleSwgYWxnKSB7XG4gICAgaWYgKGtleS5hbGdvcml0aG0ubGVuZ3RoICE9PSBwYXJzZUludChhbGcuc2xpY2UoMSwgNCksIDEwKSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGBJbnZhbGlkIGtleSBzaXplIGZvciBhbGc6ICR7YWxnfWApO1xuICAgIH1cbn1cbmZ1bmN0aW9uIGdldENyeXB0b0tleShrZXksIGFsZywgdXNhZ2UpIHtcbiAgICBpZiAoaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICBjaGVja0VuY0NyeXB0b0tleShrZXksIGFsZywgdXNhZ2UpO1xuICAgICAgICByZXR1cm4ga2V5O1xuICAgIH1cbiAgICBpZiAoa2V5IGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICByZXR1cm4gY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGtleSwgJ0FFUy1LVycsIHRydWUsIFt1c2FnZV0pO1xuICAgIH1cbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzLCAnVWludDhBcnJheScpKTtcbn1cbmV4cG9ydCBjb25zdCB3cmFwID0gYXN5bmMgKGFsZywga2V5LCBjZWspID0+IHtcbiAgICBjb25zdCBjcnlwdG9LZXkgPSBhd2FpdCBnZXRDcnlwdG9LZXkoa2V5LCBhbGcsICd3cmFwS2V5Jyk7XG4gICAgY2hlY2tLZXlTaXplKGNyeXB0b0tleSwgYWxnKTtcbiAgICBjb25zdCBjcnlwdG9LZXlDZWsgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLCAuLi5ib2d1c1dlYkNyeXB0byk7XG4gICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUud3JhcEtleSgncmF3JywgY3J5cHRvS2V5Q2VrLCBjcnlwdG9LZXksICdBRVMtS1cnKSk7XG59O1xuZXhwb3J0IGNvbnN0IHVud3JhcCA9IGFzeW5jIChhbGcsIGtleSwgZW5jcnlwdGVkS2V5KSA9PiB7XG4gICAgY29uc3QgY3J5cHRvS2V5ID0gYXdhaXQgZ2V0Q3J5cHRvS2V5KGtleSwgYWxnLCAndW53cmFwS2V5Jyk7XG4gICAgY2hlY2tLZXlTaXplKGNyeXB0b0tleSwgYWxnKTtcbiAgICBjb25zdCBjcnlwdG9LZXlDZWsgPSBhd2FpdCBjcnlwdG8uc3VidGxlLnVud3JhcEtleSgncmF3JywgZW5jcnlwdGVkS2V5LCBjcnlwdG9LZXksICdBRVMtS1cnLCAuLi5ib2d1c1dlYkNyeXB0byk7XG4gICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdyYXcnLCBjcnlwdG9LZXlDZWspKTtcbn07XG4iLCJpbXBvcnQgeyBlbmNvZGVyLCBjb25jYXQsIHVpbnQzMmJlLCBsZW5ndGhBbmRJbnB1dCwgY29uY2F0S2RmIH0gZnJvbSAnLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tFbmNDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGRlcml2ZUtleShwdWJsaWNLZXksIHByaXZhdGVLZXksIGFsZ29yaXRobSwga2V5TGVuZ3RoLCBhcHUgPSBuZXcgVWludDhBcnJheSgwKSwgYXB2ID0gbmV3IFVpbnQ4QXJyYXkoMCkpIHtcbiAgICBpZiAoIWlzQ3J5cHRvS2V5KHB1YmxpY0tleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQocHVibGljS2V5LCAuLi50eXBlcykpO1xuICAgIH1cbiAgICBjaGVja0VuY0NyeXB0b0tleShwdWJsaWNLZXksICdFQ0RIJyk7XG4gICAgaWYgKCFpc0NyeXB0b0tleShwcml2YXRlS2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChwcml2YXRlS2V5LCAuLi50eXBlcykpO1xuICAgIH1cbiAgICBjaGVja0VuY0NyeXB0b0tleShwcml2YXRlS2V5LCAnRUNESCcsICdkZXJpdmVCaXRzJyk7XG4gICAgY29uc3QgdmFsdWUgPSBjb25jYXQobGVuZ3RoQW5kSW5wdXQoZW5jb2Rlci5lbmNvZGUoYWxnb3JpdGhtKSksIGxlbmd0aEFuZElucHV0KGFwdSksIGxlbmd0aEFuZElucHV0KGFwdiksIHVpbnQzMmJlKGtleUxlbmd0aCkpO1xuICAgIGxldCBsZW5ndGg7XG4gICAgaWYgKHB1YmxpY0tleS5hbGdvcml0aG0ubmFtZSA9PT0gJ1gyNTUxOScpIHtcbiAgICAgICAgbGVuZ3RoID0gMjU2O1xuICAgIH1cbiAgICBlbHNlIGlmIChwdWJsaWNLZXkuYWxnb3JpdGhtLm5hbWUgPT09ICdYNDQ4Jykge1xuICAgICAgICBsZW5ndGggPSA0NDg7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBsZW5ndGggPVxuICAgICAgICAgICAgTWF0aC5jZWlsKHBhcnNlSW50KHB1YmxpY0tleS5hbGdvcml0aG0ubmFtZWRDdXJ2ZS5zdWJzdHIoLTMpLCAxMCkgLyA4KSA8PCAzO1xuICAgIH1cbiAgICBjb25zdCBzaGFyZWRTZWNyZXQgPSBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmRlcml2ZUJpdHMoe1xuICAgICAgICBuYW1lOiBwdWJsaWNLZXkuYWxnb3JpdGhtLm5hbWUsXG4gICAgICAgIHB1YmxpYzogcHVibGljS2V5LFxuICAgIH0sIHByaXZhdGVLZXksIGxlbmd0aCkpO1xuICAgIHJldHVybiBjb25jYXRLZGYoc2hhcmVkU2VjcmV0LCBrZXlMZW5ndGgsIHZhbHVlKTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZUVwayhrZXkpIHtcbiAgICBpZiAoIWlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcykpO1xuICAgIH1cbiAgICByZXR1cm4gY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleShrZXkuYWxnb3JpdGhtLCB0cnVlLCBbJ2Rlcml2ZUJpdHMnXSk7XG59XG5leHBvcnQgZnVuY3Rpb24gZWNkaEFsbG93ZWQoa2V5KSB7XG4gICAgaWYgKCFpc0NyeXB0b0tleShrZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMpKTtcbiAgICB9XG4gICAgcmV0dXJuIChbJ1AtMjU2JywgJ1AtMzg0JywgJ1AtNTIxJ10uaW5jbHVkZXMoa2V5LmFsZ29yaXRobS5uYW1lZEN1cnZlKSB8fFxuICAgICAgICBrZXkuYWxnb3JpdGhtLm5hbWUgPT09ICdYMjU1MTknIHx8XG4gICAgICAgIGtleS5hbGdvcml0aG0ubmFtZSA9PT0gJ1g0NDgnKTtcbn1cbiIsImltcG9ydCB7IEpXRUludmFsaWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBjaGVja1AycyhwMnMpIHtcbiAgICBpZiAoIShwMnMgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB8fCBwMnMubGVuZ3RoIDwgOCkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnUEJFUzIgU2FsdCBJbnB1dCBtdXN0IGJlIDggb3IgbW9yZSBvY3RldHMnKTtcbiAgICB9XG59XG4iLCJpbXBvcnQgcmFuZG9tIGZyb20gJy4vcmFuZG9tLmpzJztcbmltcG9ydCB7IHAycyBhcyBjb25jYXRTYWx0IH0gZnJvbSAnLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgeyBlbmNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHsgd3JhcCwgdW53cmFwIH0gZnJvbSAnLi9hZXNrdy5qcyc7XG5pbXBvcnQgY2hlY2tQMnMgZnJvbSAnLi4vbGliL2NoZWNrX3Aycy5qcyc7XG5pbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tFbmNDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuZnVuY3Rpb24gZ2V0Q3J5cHRvS2V5KGtleSwgYWxnKSB7XG4gICAgaWYgKGtleSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBrZXksICdQQktERjInLCBmYWxzZSwgWydkZXJpdmVCaXRzJ10pO1xuICAgIH1cbiAgICBpZiAoaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICBjaGVja0VuY0NyeXB0b0tleShrZXksIGFsZywgJ2Rlcml2ZUJpdHMnLCAnZGVyaXZlS2V5Jyk7XG4gICAgICAgIHJldHVybiBrZXk7XG4gICAgfVxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMsICdVaW50OEFycmF5JykpO1xufVxuYXN5bmMgZnVuY3Rpb24gZGVyaXZlS2V5KHAycywgYWxnLCBwMmMsIGtleSkge1xuICAgIGNoZWNrUDJzKHAycyk7XG4gICAgY29uc3Qgc2FsdCA9IGNvbmNhdFNhbHQoYWxnLCBwMnMpO1xuICAgIGNvbnN0IGtleWxlbiA9IHBhcnNlSW50KGFsZy5zbGljZSgxMywgMTYpLCAxMCk7XG4gICAgY29uc3Qgc3VidGxlQWxnID0ge1xuICAgICAgICBoYXNoOiBgU0hBLSR7YWxnLnNsaWNlKDgsIDExKX1gLFxuICAgICAgICBpdGVyYXRpb25zOiBwMmMsXG4gICAgICAgIG5hbWU6ICdQQktERjInLFxuICAgICAgICBzYWx0LFxuICAgIH07XG4gICAgY29uc3Qgd3JhcEFsZyA9IHtcbiAgICAgICAgbGVuZ3RoOiBrZXlsZW4sXG4gICAgICAgIG5hbWU6ICdBRVMtS1cnLFxuICAgIH07XG4gICAgY29uc3QgY3J5cHRvS2V5ID0gYXdhaXQgZ2V0Q3J5cHRvS2V5KGtleSwgYWxnKTtcbiAgICBpZiAoY3J5cHRvS2V5LnVzYWdlcy5pbmNsdWRlcygnZGVyaXZlQml0cycpKSB7XG4gICAgICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmRlcml2ZUJpdHMoc3VidGxlQWxnLCBjcnlwdG9LZXksIGtleWxlbikpO1xuICAgIH1cbiAgICBpZiAoY3J5cHRvS2V5LnVzYWdlcy5pbmNsdWRlcygnZGVyaXZlS2V5JykpIHtcbiAgICAgICAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuZGVyaXZlS2V5KHN1YnRsZUFsZywgY3J5cHRvS2V5LCB3cmFwQWxnLCBmYWxzZSwgWyd3cmFwS2V5JywgJ3Vud3JhcEtleSddKTtcbiAgICB9XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcignUEJLREYyIGtleSBcInVzYWdlc1wiIG11c3QgaW5jbHVkZSBcImRlcml2ZUJpdHNcIiBvciBcImRlcml2ZUtleVwiJyk7XG59XG5leHBvcnQgY29uc3QgZW5jcnlwdCA9IGFzeW5jIChhbGcsIGtleSwgY2VrLCBwMmMgPSAyMDQ4LCBwMnMgPSByYW5kb20obmV3IFVpbnQ4QXJyYXkoMTYpKSkgPT4ge1xuICAgIGNvbnN0IGRlcml2ZWQgPSBhd2FpdCBkZXJpdmVLZXkocDJzLCBhbGcsIHAyYywga2V5KTtcbiAgICBjb25zdCBlbmNyeXB0ZWRLZXkgPSBhd2FpdCB3cmFwKGFsZy5zbGljZSgtNiksIGRlcml2ZWQsIGNlayk7XG4gICAgcmV0dXJuIHsgZW5jcnlwdGVkS2V5LCBwMmMsIHAyczogYmFzZTY0dXJsKHAycykgfTtcbn07XG5leHBvcnQgY29uc3QgZGVjcnlwdCA9IGFzeW5jIChhbGcsIGtleSwgZW5jcnlwdGVkS2V5LCBwMmMsIHAycykgPT4ge1xuICAgIGNvbnN0IGRlcml2ZWQgPSBhd2FpdCBkZXJpdmVLZXkocDJzLCBhbGcsIHAyYywga2V5KTtcbiAgICByZXR1cm4gdW53cmFwKGFsZy5zbGljZSgtNiksIGRlcml2ZWQsIGVuY3J5cHRlZEtleSk7XG59O1xuIiwiaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIHN1YnRsZVJzYUVzKGFsZykge1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQJzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMjU2JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMzg0JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtNTEyJzpcbiAgICAgICAgICAgIHJldHVybiAnUlNBLU9BRVAnO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoYGFsZyAke2FsZ30gaXMgbm90IHN1cHBvcnRlZCBlaXRoZXIgYnkgSk9TRSBvciB5b3VyIGphdmFzY3JpcHQgcnVudGltZWApO1xuICAgIH1cbn1cbiIsImV4cG9ydCBkZWZhdWx0IChhbGcsIGtleSkgPT4ge1xuICAgIGlmIChhbGcuc3RhcnRzV2l0aCgnUlMnKSB8fCBhbGcuc3RhcnRzV2l0aCgnUFMnKSkge1xuICAgICAgICBjb25zdCB7IG1vZHVsdXNMZW5ndGggfSA9IGtleS5hbGdvcml0aG07XG4gICAgICAgIGlmICh0eXBlb2YgbW9kdWx1c0xlbmd0aCAhPT0gJ251bWJlcicgfHwgbW9kdWx1c0xlbmd0aCA8IDIwNDgpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYCR7YWxnfSByZXF1aXJlcyBrZXkgbW9kdWx1c0xlbmd0aCB0byBiZSAyMDQ4IGJpdHMgb3IgbGFyZ2VyYCk7XG4gICAgICAgIH1cbiAgICB9XG59O1xuIiwiaW1wb3J0IHN1YnRsZUFsZ29yaXRobSBmcm9tICcuL3N1YnRsZV9yc2Flcy5qcyc7XG5pbXBvcnQgYm9ndXNXZWJDcnlwdG8gZnJvbSAnLi9ib2d1cy5qcyc7XG5pbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tFbmNDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgY2hlY2tLZXlMZW5ndGggZnJvbSAnLi9jaGVja19rZXlfbGVuZ3RoLmpzJztcbmltcG9ydCBpbnZhbGlkS2V5SW5wdXQgZnJvbSAnLi4vbGliL2ludmFsaWRfa2V5X2lucHV0LmpzJztcbmltcG9ydCB7IHR5cGVzIH0gZnJvbSAnLi9pc19rZXlfbGlrZS5qcyc7XG5leHBvcnQgY29uc3QgZW5jcnlwdCA9IGFzeW5jIChhbGcsIGtleSwgY2VrKSA9PiB7XG4gICAgaWYgKCFpc0NyeXB0b0tleShrZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMpKTtcbiAgICB9XG4gICAgY2hlY2tFbmNDcnlwdG9LZXkoa2V5LCBhbGcsICdlbmNyeXB0JywgJ3dyYXBLZXknKTtcbiAgICBjaGVja0tleUxlbmd0aChhbGcsIGtleSk7XG4gICAgaWYgKGtleS51c2FnZXMuaW5jbHVkZXMoJ2VuY3J5cHQnKSkge1xuICAgICAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5lbmNyeXB0KHN1YnRsZUFsZ29yaXRobShhbGcpLCBrZXksIGNlaykpO1xuICAgIH1cbiAgICBpZiAoa2V5LnVzYWdlcy5pbmNsdWRlcygnd3JhcEtleScpKSB7XG4gICAgICAgIGNvbnN0IGNyeXB0b0tleUNlayA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBjZWssIC4uLmJvZ3VzV2ViQ3J5cHRvKTtcbiAgICAgICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUud3JhcEtleSgncmF3JywgY3J5cHRvS2V5Q2VrLCBrZXksIHN1YnRsZUFsZ29yaXRobShhbGcpKSk7XG4gICAgfVxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1JTQS1PQUVQIGtleSBcInVzYWdlc1wiIG11c3QgaW5jbHVkZSBcImVuY3J5cHRcIiBvciBcIndyYXBLZXlcIiBmb3IgdGhpcyBvcGVyYXRpb24nKTtcbn07XG5leHBvcnQgY29uc3QgZGVjcnlwdCA9IGFzeW5jIChhbGcsIGtleSwgZW5jcnlwdGVkS2V5KSA9PiB7XG4gICAgaWYgKCFpc0NyeXB0b0tleShrZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMpKTtcbiAgICB9XG4gICAgY2hlY2tFbmNDcnlwdG9LZXkoa2V5LCBhbGcsICdkZWNyeXB0JywgJ3Vud3JhcEtleScpO1xuICAgIGNoZWNrS2V5TGVuZ3RoKGFsZywga2V5KTtcbiAgICBpZiAoa2V5LnVzYWdlcy5pbmNsdWRlcygnZGVjcnlwdCcpKSB7XG4gICAgICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmRlY3J5cHQoc3VidGxlQWxnb3JpdGhtKGFsZyksIGtleSwgZW5jcnlwdGVkS2V5KSk7XG4gICAgfVxuICAgIGlmIChrZXkudXNhZ2VzLmluY2x1ZGVzKCd1bndyYXBLZXknKSkge1xuICAgICAgICBjb25zdCBjcnlwdG9LZXlDZWsgPSBhd2FpdCBjcnlwdG8uc3VidGxlLnVud3JhcEtleSgncmF3JywgZW5jcnlwdGVkS2V5LCBrZXksIHN1YnRsZUFsZ29yaXRobShhbGcpLCAuLi5ib2d1c1dlYkNyeXB0byk7XG4gICAgICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgncmF3JywgY3J5cHRvS2V5Q2VrKSk7XG4gICAgfVxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1JTQS1PQUVQIGtleSBcInVzYWdlc1wiIG11c3QgaW5jbHVkZSBcImRlY3J5cHRcIiBvciBcInVud3JhcEtleVwiIGZvciB0aGlzIG9wZXJhdGlvbicpO1xufTtcbiIsImltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgcmFuZG9tIGZyb20gJy4uL3J1bnRpbWUvcmFuZG9tLmpzJztcbmV4cG9ydCBmdW5jdGlvbiBiaXRMZW5ndGgoYWxnKSB7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnQTEyOEdDTSc6XG4gICAgICAgICAgICByZXR1cm4gMTI4O1xuICAgICAgICBjYXNlICdBMTkyR0NNJzpcbiAgICAgICAgICAgIHJldHVybiAxOTI7XG4gICAgICAgIGNhc2UgJ0EyNTZHQ00nOlxuICAgICAgICBjYXNlICdBMTI4Q0JDLUhTMjU2JzpcbiAgICAgICAgICAgIHJldHVybiAyNTY7XG4gICAgICAgIGNhc2UgJ0ExOTJDQkMtSFMzODQnOlxuICAgICAgICAgICAgcmV0dXJuIDM4NDtcbiAgICAgICAgY2FzZSAnQTI1NkNCQy1IUzUxMic6XG4gICAgICAgICAgICByZXR1cm4gNTEyO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoYFVuc3VwcG9ydGVkIEpXRSBBbGdvcml0aG06ICR7YWxnfWApO1xuICAgIH1cbn1cbmV4cG9ydCBkZWZhdWx0IChhbGcpID0+IHJhbmRvbShuZXcgVWludDhBcnJheShiaXRMZW5ndGgoYWxnKSA+PiAzKSk7XG4iLCJpbXBvcnQgY3J5cHRvIGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5mdW5jdGlvbiBzdWJ0bGVNYXBwaW5nKGp3aykge1xuICAgIGxldCBhbGdvcml0aG07XG4gICAgbGV0IGtleVVzYWdlcztcbiAgICBzd2l0Y2ggKGp3ay5rdHkpIHtcbiAgICAgICAgY2FzZSAnUlNBJzoge1xuICAgICAgICAgICAgc3dpdGNoIChqd2suYWxnKSB7XG4gICAgICAgICAgICAgICAgY2FzZSAnUFMyNTYnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1BTMzg0JzpcbiAgICAgICAgICAgICAgICBjYXNlICdQUzUxMic6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ1JTQS1QU1MnLCBoYXNoOiBgU0hBLSR7andrLmFsZy5zbGljZSgtMyl9YCB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnc2lnbiddIDogWyd2ZXJpZnknXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAnUlMyNTYnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1JTMzg0JzpcbiAgICAgICAgICAgICAgICBjYXNlICdSUzUxMic6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ1JTQVNTQS1QS0NTMS12MV81JywgaGFzaDogYFNIQS0ke2p3ay5hbGcuc2xpY2UoLTMpfWAgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ3NpZ24nXSA6IFsndmVyaWZ5J107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ1JTQS1PQUVQJzpcbiAgICAgICAgICAgICAgICBjYXNlICdSU0EtT0FFUC0yNTYnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1JTQS1PQUVQLTM4NCc6XG4gICAgICAgICAgICAgICAgY2FzZSAnUlNBLU9BRVAtNTEyJzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0ge1xuICAgICAgICAgICAgICAgICAgICAgICAgbmFtZTogJ1JTQS1PQUVQJyxcbiAgICAgICAgICAgICAgICAgICAgICAgIGhhc2g6IGBTSEEtJHtwYXJzZUludChqd2suYWxnLnNsaWNlKC0zKSwgMTApIHx8IDF9YCxcbiAgICAgICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ2RlY3J5cHQnLCAndW53cmFwS2V5J10gOiBbJ2VuY3J5cHQnLCAnd3JhcEtleSddO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBKV0sgXCJhbGdcIiAoQWxnb3JpdGhtKSBQYXJhbWV0ZXIgdmFsdWUnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0VDJzoge1xuICAgICAgICAgICAgc3dpdGNoIChqd2suYWxnKSB7XG4gICAgICAgICAgICAgICAgY2FzZSAnRVMyNTYnOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RTQScsIG5hbWVkQ3VydmU6ICdQLTI1NicgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ3NpZ24nXSA6IFsndmVyaWZ5J107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ0VTMzg0JzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNEU0EnLCBuYW1lZEN1cnZlOiAnUC0zODQnIH07XG4gICAgICAgICAgICAgICAgICAgIGtleVVzYWdlcyA9IGp3ay5kID8gWydzaWduJ10gOiBbJ3ZlcmlmeSddO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlICdFUzUxMic6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0VDRFNBJywgbmFtZWRDdXJ2ZTogJ1AtNTIxJyB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnc2lnbiddIDogWyd2ZXJpZnknXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUyc6XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUytBMTI4S1cnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMrQTE5MktXJzpcbiAgICAgICAgICAgICAgICBjYXNlICdFQ0RILUVTK0EyNTZLVyc6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0VDREgnLCBuYW1lZEN1cnZlOiBqd2suY3J2IH07XG4gICAgICAgICAgICAgICAgICAgIGtleVVzYWdlcyA9IGp3ay5kID8gWydkZXJpdmVCaXRzJ10gOiBbXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgSldLIFwiYWxnXCIgKEFsZ29yaXRobSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdPS1AnOiB7XG4gICAgICAgICAgICBzd2l0Y2ggKGp3ay5hbGcpIHtcbiAgICAgICAgICAgICAgICBjYXNlICdFZERTQSc6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogandrLmNydiB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnc2lnbiddIDogWyd2ZXJpZnknXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUyc6XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUytBMTI4S1cnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMrQTE5MktXJzpcbiAgICAgICAgICAgICAgICBjYXNlICdFQ0RILUVTK0EyNTZLVyc6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogandrLmNydiB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnZGVyaXZlQml0cyddIDogW107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIEpXSyBcImFsZ1wiIChBbGdvcml0aG0pIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIEpXSyBcImt0eVwiIChLZXkgVHlwZSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgfVxuICAgIHJldHVybiB7IGFsZ29yaXRobSwga2V5VXNhZ2VzIH07XG59XG5jb25zdCBwYXJzZSA9IGFzeW5jIChqd2spID0+IHtcbiAgICBpZiAoIWp3ay5hbGcpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignXCJhbGdcIiBhcmd1bWVudCBpcyByZXF1aXJlZCB3aGVuIFwiandrLmFsZ1wiIGlzIG5vdCBwcmVzZW50Jyk7XG4gICAgfVxuICAgIGNvbnN0IHsgYWxnb3JpdGhtLCBrZXlVc2FnZXMgfSA9IHN1YnRsZU1hcHBpbmcoandrKTtcbiAgICBjb25zdCByZXN0ID0gW1xuICAgICAgICBhbGdvcml0aG0sXG4gICAgICAgIGp3ay5leHQgPz8gZmFsc2UsXG4gICAgICAgIGp3ay5rZXlfb3BzID8/IGtleVVzYWdlcyxcbiAgICBdO1xuICAgIGNvbnN0IGtleURhdGEgPSB7IC4uLmp3ayB9O1xuICAgIGRlbGV0ZSBrZXlEYXRhLmFsZztcbiAgICBkZWxldGUga2V5RGF0YS51c2U7XG4gICAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdqd2snLCBrZXlEYXRhLCAuLi5yZXN0KTtcbn07XG5leHBvcnQgZGVmYXVsdCBwYXJzZTtcbiIsImltcG9ydCB7IGRlY29kZSBhcyBkZWNvZGVCYXNlNjRVUkwgfSBmcm9tICcuLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgeyBmcm9tU1BLSSwgZnJvbVBLQ1M4LCBmcm9tWDUwOSB9IGZyb20gJy4uL3J1bnRpbWUvYXNuMS5qcyc7XG5pbXBvcnQgYXNLZXlPYmplY3QgZnJvbSAnLi4vcnVudGltZS9qd2tfdG9fa2V5LmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgaXNPYmplY3QgZnJvbSAnLi4vbGliL2lzX29iamVjdC5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gaW1wb3J0U1BLSShzcGtpLCBhbGcsIG9wdGlvbnMpIHtcbiAgICBpZiAodHlwZW9mIHNwa2kgIT09ICdzdHJpbmcnIHx8IHNwa2kuaW5kZXhPZignLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0nKSAhPT0gMCkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdcInNwa2lcIiBtdXN0IGJlIFNQS0kgZm9ybWF0dGVkIHN0cmluZycpO1xuICAgIH1cbiAgICByZXR1cm4gZnJvbVNQS0koc3BraSwgYWxnLCBvcHRpb25zKTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBpbXBvcnRYNTA5KHg1MDksIGFsZywgb3B0aW9ucykge1xuICAgIGlmICh0eXBlb2YgeDUwOSAhPT0gJ3N0cmluZycgfHwgeDUwOS5pbmRleE9mKCctLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0nKSAhPT0gMCkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdcIng1MDlcIiBtdXN0IGJlIFguNTA5IGZvcm1hdHRlZCBzdHJpbmcnKTtcbiAgICB9XG4gICAgcmV0dXJuIGZyb21YNTA5KHg1MDksIGFsZywgb3B0aW9ucyk7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gaW1wb3J0UEtDUzgocGtjczgsIGFsZywgb3B0aW9ucykge1xuICAgIGlmICh0eXBlb2YgcGtjczggIT09ICdzdHJpbmcnIHx8IHBrY3M4LmluZGV4T2YoJy0tLS0tQkVHSU4gUFJJVkFURSBLRVktLS0tLScpICE9PSAwKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1wicGtjczhcIiBtdXN0IGJlIFBLQ1MjOCBmb3JtYXR0ZWQgc3RyaW5nJyk7XG4gICAgfVxuICAgIHJldHVybiBmcm9tUEtDUzgocGtjczgsIGFsZywgb3B0aW9ucyk7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gaW1wb3J0SldLKGp3aywgYWxnKSB7XG4gICAgaWYgKCFpc09iamVjdChqd2spKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0pXSyBtdXN0IGJlIGFuIG9iamVjdCcpO1xuICAgIH1cbiAgICBhbGcgfHwgKGFsZyA9IGp3ay5hbGcpO1xuICAgIHN3aXRjaCAoandrLmt0eSkge1xuICAgICAgICBjYXNlICdvY3QnOlxuICAgICAgICAgICAgaWYgKHR5cGVvZiBqd2suayAhPT0gJ3N0cmluZycgfHwgIWp3ay5rKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignbWlzc2luZyBcImtcIiAoS2V5IFZhbHVlKSBQYXJhbWV0ZXIgdmFsdWUnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBkZWNvZGVCYXNlNjRVUkwoandrLmspO1xuICAgICAgICBjYXNlICdSU0EnOlxuICAgICAgICAgICAgaWYgKGp3ay5vdGggIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdSU0EgSldLIFwib3RoXCIgKE90aGVyIFByaW1lcyBJbmZvKSBQYXJhbWV0ZXIgdmFsdWUgaXMgbm90IHN1cHBvcnRlZCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICBjYXNlICdFQyc6XG4gICAgICAgIGNhc2UgJ09LUCc6XG4gICAgICAgICAgICByZXR1cm4gYXNLZXlPYmplY3QoeyAuLi5qd2ssIGFsZyB9KTtcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdVbnN1cHBvcnRlZCBcImt0eVwiIChLZXkgVHlwZSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgfVxufVxuIiwiaW1wb3J0IHsgd2l0aEFsZyBhcyBpbnZhbGlkS2V5SW5wdXQgfSBmcm9tICcuL2ludmFsaWRfa2V5X2lucHV0LmpzJztcbmltcG9ydCBpc0tleUxpa2UsIHsgdHlwZXMgfSBmcm9tICcuLi9ydW50aW1lL2lzX2tleV9saWtlLmpzJztcbmNvbnN0IHN5bW1ldHJpY1R5cGVDaGVjayA9IChhbGcsIGtleSkgPT4ge1xuICAgIGlmIChrZXkgaW5zdGFuY2VvZiBVaW50OEFycmF5KVxuICAgICAgICByZXR1cm47XG4gICAgaWYgKCFpc0tleUxpa2Uoa2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChhbGcsIGtleSwgLi4udHlwZXMsICdVaW50OEFycmF5JykpO1xuICAgIH1cbiAgICBpZiAoa2V5LnR5cGUgIT09ICdzZWNyZXQnKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYCR7dHlwZXMuam9pbignIG9yICcpfSBpbnN0YW5jZXMgZm9yIHN5bW1ldHJpYyBhbGdvcml0aG1zIG11c3QgYmUgb2YgdHlwZSBcInNlY3JldFwiYCk7XG4gICAgfVxufTtcbmNvbnN0IGFzeW1tZXRyaWNUeXBlQ2hlY2sgPSAoYWxnLCBrZXksIHVzYWdlKSA9PiB7XG4gICAgaWYgKCFpc0tleUxpa2Uoa2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChhbGcsIGtleSwgLi4udHlwZXMpKTtcbiAgICB9XG4gICAgaWYgKGtleS50eXBlID09PSAnc2VjcmV0Jykge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGAke3R5cGVzLmpvaW4oJyBvciAnKX0gaW5zdGFuY2VzIGZvciBhc3ltbWV0cmljIGFsZ29yaXRobXMgbXVzdCBub3QgYmUgb2YgdHlwZSBcInNlY3JldFwiYCk7XG4gICAgfVxuICAgIGlmICh1c2FnZSA9PT0gJ3NpZ24nICYmIGtleS50eXBlID09PSAncHVibGljJykge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGAke3R5cGVzLmpvaW4oJyBvciAnKX0gaW5zdGFuY2VzIGZvciBhc3ltbWV0cmljIGFsZ29yaXRobSBzaWduaW5nIG11c3QgYmUgb2YgdHlwZSBcInByaXZhdGVcImApO1xuICAgIH1cbiAgICBpZiAodXNhZ2UgPT09ICdkZWNyeXB0JyAmJiBrZXkudHlwZSA9PT0gJ3B1YmxpYycpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHt0eXBlcy5qb2luKCcgb3IgJyl9IGluc3RhbmNlcyBmb3IgYXN5bW1ldHJpYyBhbGdvcml0aG0gZGVjcnlwdGlvbiBtdXN0IGJlIG9mIHR5cGUgXCJwcml2YXRlXCJgKTtcbiAgICB9XG4gICAgaWYgKGtleS5hbGdvcml0aG0gJiYgdXNhZ2UgPT09ICd2ZXJpZnknICYmIGtleS50eXBlID09PSAncHJpdmF0ZScpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHt0eXBlcy5qb2luKCcgb3IgJyl9IGluc3RhbmNlcyBmb3IgYXN5bW1ldHJpYyBhbGdvcml0aG0gdmVyaWZ5aW5nIG11c3QgYmUgb2YgdHlwZSBcInB1YmxpY1wiYCk7XG4gICAgfVxuICAgIGlmIChrZXkuYWxnb3JpdGhtICYmIHVzYWdlID09PSAnZW5jcnlwdCcgJiYga2V5LnR5cGUgPT09ICdwcml2YXRlJykge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGAke3R5cGVzLmpvaW4oJyBvciAnKX0gaW5zdGFuY2VzIGZvciBhc3ltbWV0cmljIGFsZ29yaXRobSBlbmNyeXB0aW9uIG11c3QgYmUgb2YgdHlwZSBcInB1YmxpY1wiYCk7XG4gICAgfVxufTtcbmNvbnN0IGNoZWNrS2V5VHlwZSA9IChhbGcsIGtleSwgdXNhZ2UpID0+IHtcbiAgICBjb25zdCBzeW1tZXRyaWMgPSBhbGcuc3RhcnRzV2l0aCgnSFMnKSB8fFxuICAgICAgICBhbGcgPT09ICdkaXInIHx8XG4gICAgICAgIGFsZy5zdGFydHNXaXRoKCdQQkVTMicpIHx8XG4gICAgICAgIC9eQVxcZHszfSg/OkdDTSk/S1ckLy50ZXN0KGFsZyk7XG4gICAgaWYgKHN5bW1ldHJpYykge1xuICAgICAgICBzeW1tZXRyaWNUeXBlQ2hlY2soYWxnLCBrZXkpO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgYXN5bW1ldHJpY1R5cGVDaGVjayhhbGcsIGtleSwgdXNhZ2UpO1xuICAgIH1cbn07XG5leHBvcnQgZGVmYXVsdCBjaGVja0tleVR5cGU7XG4iLCJpbXBvcnQgeyBjb25jYXQsIHVpbnQ2NGJlIH0gZnJvbSAnLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgY2hlY2tJdkxlbmd0aCBmcm9tICcuLi9saWIvY2hlY2tfaXZfbGVuZ3RoLmpzJztcbmltcG9ydCBjaGVja0Nla0xlbmd0aCBmcm9tICcuL2NoZWNrX2Nla19sZW5ndGguanMnO1xuaW1wb3J0IGNyeXB0bywgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IGNoZWNrRW5jQ3J5cHRvS2V5IH0gZnJvbSAnLi4vbGliL2NyeXB0b19rZXkuanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IGdlbmVyYXRlSXYgZnJvbSAnLi4vbGliL2l2LmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuYXN5bmMgZnVuY3Rpb24gY2JjRW5jcnlwdChlbmMsIHBsYWludGV4dCwgY2VrLCBpdiwgYWFkKSB7XG4gICAgaWYgKCEoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoY2VrLCAnVWludDhBcnJheScpKTtcbiAgICB9XG4gICAgY29uc3Qga2V5U2l6ZSA9IHBhcnNlSW50KGVuYy5zbGljZSgxLCA0KSwgMTApO1xuICAgIGNvbnN0IGVuY0tleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBjZWsuc3ViYXJyYXkoa2V5U2l6ZSA+PiAzKSwgJ0FFUy1DQkMnLCBmYWxzZSwgWydlbmNyeXB0J10pO1xuICAgIGNvbnN0IG1hY0tleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBjZWsuc3ViYXJyYXkoMCwga2V5U2l6ZSA+PiAzKSwge1xuICAgICAgICBoYXNoOiBgU0hBLSR7a2V5U2l6ZSA8PCAxfWAsXG4gICAgICAgIG5hbWU6ICdITUFDJyxcbiAgICB9LCBmYWxzZSwgWydzaWduJ10pO1xuICAgIGNvbnN0IGNpcGhlcnRleHQgPSBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmVuY3J5cHQoe1xuICAgICAgICBpdixcbiAgICAgICAgbmFtZTogJ0FFUy1DQkMnLFxuICAgIH0sIGVuY0tleSwgcGxhaW50ZXh0KSk7XG4gICAgY29uc3QgbWFjRGF0YSA9IGNvbmNhdChhYWQsIGl2LCBjaXBoZXJ0ZXh0LCB1aW50NjRiZShhYWQubGVuZ3RoIDw8IDMpKTtcbiAgICBjb25zdCB0YWcgPSBuZXcgVWludDhBcnJheSgoYXdhaXQgY3J5cHRvLnN1YnRsZS5zaWduKCdITUFDJywgbWFjS2V5LCBtYWNEYXRhKSkuc2xpY2UoMCwga2V5U2l6ZSA+PiAzKSk7XG4gICAgcmV0dXJuIHsgY2lwaGVydGV4dCwgdGFnLCBpdiB9O1xufVxuYXN5bmMgZnVuY3Rpb24gZ2NtRW5jcnlwdChlbmMsIHBsYWludGV4dCwgY2VrLCBpdiwgYWFkKSB7XG4gICAgbGV0IGVuY0tleTtcbiAgICBpZiAoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICBlbmNLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLCAnQUVTLUdDTScsIGZhbHNlLCBbJ2VuY3J5cHQnXSk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBjaGVja0VuY0NyeXB0b0tleShjZWssIGVuYywgJ2VuY3J5cHQnKTtcbiAgICAgICAgZW5jS2V5ID0gY2VrO1xuICAgIH1cbiAgICBjb25zdCBlbmNyeXB0ZWQgPSBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmVuY3J5cHQoe1xuICAgICAgICBhZGRpdGlvbmFsRGF0YTogYWFkLFxuICAgICAgICBpdixcbiAgICAgICAgbmFtZTogJ0FFUy1HQ00nLFxuICAgICAgICB0YWdMZW5ndGg6IDEyOCxcbiAgICB9LCBlbmNLZXksIHBsYWludGV4dCkpO1xuICAgIGNvbnN0IHRhZyA9IGVuY3J5cHRlZC5zbGljZSgtMTYpO1xuICAgIGNvbnN0IGNpcGhlcnRleHQgPSBlbmNyeXB0ZWQuc2xpY2UoMCwgLTE2KTtcbiAgICByZXR1cm4geyBjaXBoZXJ0ZXh0LCB0YWcsIGl2IH07XG59XG5jb25zdCBlbmNyeXB0ID0gYXN5bmMgKGVuYywgcGxhaW50ZXh0LCBjZWssIGl2LCBhYWQpID0+IHtcbiAgICBpZiAoIWlzQ3J5cHRvS2V5KGNlaykgJiYgIShjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChjZWssIC4uLnR5cGVzLCAnVWludDhBcnJheScpKTtcbiAgICB9XG4gICAgaWYgKGl2KSB7XG4gICAgICAgIGNoZWNrSXZMZW5ndGgoZW5jLCBpdik7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBpdiA9IGdlbmVyYXRlSXYoZW5jKTtcbiAgICB9XG4gICAgc3dpdGNoIChlbmMpIHtcbiAgICAgICAgY2FzZSAnQTEyOENCQy1IUzI1Nic6XG4gICAgICAgIGNhc2UgJ0ExOTJDQkMtSFMzODQnOlxuICAgICAgICBjYXNlICdBMjU2Q0JDLUhTNTEyJzpcbiAgICAgICAgICAgIGlmIChjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgICAgICAgICAgY2hlY2tDZWtMZW5ndGgoY2VrLCBwYXJzZUludChlbmMuc2xpY2UoLTMpLCAxMCkpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIGNiY0VuY3J5cHQoZW5jLCBwbGFpbnRleHQsIGNlaywgaXYsIGFhZCk7XG4gICAgICAgIGNhc2UgJ0ExMjhHQ00nOlxuICAgICAgICBjYXNlICdBMTkyR0NNJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTSc6XG4gICAgICAgICAgICBpZiAoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICAgICAgICAgIGNoZWNrQ2VrTGVuZ3RoKGNlaywgcGFyc2VJbnQoZW5jLnNsaWNlKDEsIDQpLCAxMCkpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIGdjbUVuY3J5cHQoZW5jLCBwbGFpbnRleHQsIGNlaywgaXYsIGFhZCk7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnVW5zdXBwb3J0ZWQgSldFIENvbnRlbnQgRW5jcnlwdGlvbiBBbGdvcml0aG0nKTtcbiAgICB9XG59O1xuZXhwb3J0IGRlZmF1bHQgZW5jcnlwdDtcbiIsImltcG9ydCBlbmNyeXB0IGZyb20gJy4uL3J1bnRpbWUvZW5jcnlwdC5qcyc7XG5pbXBvcnQgZGVjcnlwdCBmcm9tICcuLi9ydW50aW1lL2RlY3J5cHQuanMnO1xuaW1wb3J0IHsgZW5jb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB3cmFwKGFsZywga2V5LCBjZWssIGl2KSB7XG4gICAgY29uc3QgandlQWxnb3JpdGhtID0gYWxnLnNsaWNlKDAsIDcpO1xuICAgIGNvbnN0IHdyYXBwZWQgPSBhd2FpdCBlbmNyeXB0KGp3ZUFsZ29yaXRobSwgY2VrLCBrZXksIGl2LCBuZXcgVWludDhBcnJheSgwKSk7XG4gICAgcmV0dXJuIHtcbiAgICAgICAgZW5jcnlwdGVkS2V5OiB3cmFwcGVkLmNpcGhlcnRleHQsXG4gICAgICAgIGl2OiBiYXNlNjR1cmwod3JhcHBlZC5pdiksXG4gICAgICAgIHRhZzogYmFzZTY0dXJsKHdyYXBwZWQudGFnKSxcbiAgICB9O1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHVud3JhcChhbGcsIGtleSwgZW5jcnlwdGVkS2V5LCBpdiwgdGFnKSB7XG4gICAgY29uc3QgandlQWxnb3JpdGhtID0gYWxnLnNsaWNlKDAsIDcpO1xuICAgIHJldHVybiBkZWNyeXB0KGp3ZUFsZ29yaXRobSwga2V5LCBlbmNyeXB0ZWRLZXksIGl2LCB0YWcsIG5ldyBVaW50OEFycmF5KDApKTtcbn1cbiIsImltcG9ydCB7IHVud3JhcCBhcyBhZXNLdyB9IGZyb20gJy4uL3J1bnRpbWUvYWVza3cuanMnO1xuaW1wb3J0ICogYXMgRUNESCBmcm9tICcuLi9ydW50aW1lL2VjZGhlcy5qcyc7XG5pbXBvcnQgeyBkZWNyeXB0IGFzIHBiZXMyS3cgfSBmcm9tICcuLi9ydW50aW1lL3BiZXMya3cuanMnO1xuaW1wb3J0IHsgZGVjcnlwdCBhcyByc2FFcyB9IGZyb20gJy4uL3J1bnRpbWUvcnNhZXMuanMnO1xuaW1wb3J0IHsgZGVjb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQsIEpXRUludmFsaWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgeyBiaXRMZW5ndGggYXMgY2VrTGVuZ3RoIH0gZnJvbSAnLi4vbGliL2Nlay5qcyc7XG5pbXBvcnQgeyBpbXBvcnRKV0sgfSBmcm9tICcuLi9rZXkvaW1wb3J0LmpzJztcbmltcG9ydCBjaGVja0tleVR5cGUgZnJvbSAnLi9jaGVja19rZXlfdHlwZS5qcyc7XG5pbXBvcnQgaXNPYmplY3QgZnJvbSAnLi9pc19vYmplY3QuanMnO1xuaW1wb3J0IHsgdW53cmFwIGFzIGFlc0djbUt3IH0gZnJvbSAnLi9hZXNnY21rdy5qcyc7XG5hc3luYyBmdW5jdGlvbiBkZWNyeXB0S2V5TWFuYWdlbWVudChhbGcsIGtleSwgZW5jcnlwdGVkS2V5LCBqb3NlSGVhZGVyLCBvcHRpb25zKSB7XG4gICAgY2hlY2tLZXlUeXBlKGFsZywga2V5LCAnZGVjcnlwdCcpO1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ2Rpcic6IHtcbiAgICAgICAgICAgIGlmIChlbmNyeXB0ZWRLZXkgIT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRW5jb3VudGVyZWQgdW5leHBlY3RlZCBKV0UgRW5jcnlwdGVkIEtleScpO1xuICAgICAgICAgICAgcmV0dXJuIGtleTtcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdFQ0RILUVTJzpcbiAgICAgICAgICAgIGlmIChlbmNyeXB0ZWRLZXkgIT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRW5jb3VudGVyZWQgdW5leHBlY3RlZCBKV0UgRW5jcnlwdGVkIEtleScpO1xuICAgICAgICBjYXNlICdFQ0RILUVTK0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTE5MktXJzpcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMjU2S1cnOiB7XG4gICAgICAgICAgICBpZiAoIWlzT2JqZWN0KGpvc2VIZWFkZXIuZXBrKSlcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSk9TRSBIZWFkZXIgXCJlcGtcIiAoRXBoZW1lcmFsIFB1YmxpYyBLZXkpIG1pc3Npbmcgb3IgaW52YWxpZGApO1xuICAgICAgICAgICAgaWYgKCFFQ0RILmVjZGhBbGxvd2VkKGtleSkpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0VDREggd2l0aCB0aGUgcHJvdmlkZWQga2V5IGlzIG5vdCBhbGxvd2VkIG9yIG5vdCBzdXBwb3J0ZWQgYnkgeW91ciBqYXZhc2NyaXB0IHJ1bnRpbWUnKTtcbiAgICAgICAgICAgIGNvbnN0IGVwayA9IGF3YWl0IGltcG9ydEpXSyhqb3NlSGVhZGVyLmVwaywgYWxnKTtcbiAgICAgICAgICAgIGxldCBwYXJ0eVVJbmZvO1xuICAgICAgICAgICAgbGV0IHBhcnR5VkluZm87XG4gICAgICAgICAgICBpZiAoam9zZUhlYWRlci5hcHUgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgICAgIGlmICh0eXBlb2Ygam9zZUhlYWRlci5hcHUgIT09ICdzdHJpbmcnKVxuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSk9TRSBIZWFkZXIgXCJhcHVcIiAoQWdyZWVtZW50IFBhcnR5VUluZm8pIGludmFsaWRgKTtcbiAgICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgICAgICBwYXJ0eVVJbmZvID0gYmFzZTY0dXJsKGpvc2VIZWFkZXIuYXB1KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIGFwdScpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmIChqb3NlSGVhZGVyLmFwdiAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICAgICAgaWYgKHR5cGVvZiBqb3NlSGVhZGVyLmFwdiAhPT0gJ3N0cmluZycpXG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKGBKT1NFIEhlYWRlciBcImFwdlwiIChBZ3JlZW1lbnQgUGFydHlWSW5mbykgaW52YWxpZGApO1xuICAgICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgICAgIHBhcnR5VkluZm8gPSBiYXNlNjR1cmwoam9zZUhlYWRlci5hcHYpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgYXB2Jyk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY29uc3Qgc2hhcmVkU2VjcmV0ID0gYXdhaXQgRUNESC5kZXJpdmVLZXkoZXBrLCBrZXksIGFsZyA9PT0gJ0VDREgtRVMnID8gam9zZUhlYWRlci5lbmMgOiBhbGcsIGFsZyA9PT0gJ0VDREgtRVMnID8gY2VrTGVuZ3RoKGpvc2VIZWFkZXIuZW5jKSA6IHBhcnNlSW50KGFsZy5zbGljZSgtNSwgLTIpLCAxMCksIHBhcnR5VUluZm8sIHBhcnR5VkluZm8pO1xuICAgICAgICAgICAgaWYgKGFsZyA9PT0gJ0VDREgtRVMnKVxuICAgICAgICAgICAgICAgIHJldHVybiBzaGFyZWRTZWNyZXQ7XG4gICAgICAgICAgICBpZiAoZW5jcnlwdGVkS2V5ID09PSB1bmRlZmluZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBFbmNyeXB0ZWQgS2V5IG1pc3NpbmcnKTtcbiAgICAgICAgICAgIHJldHVybiBhZXNLdyhhbGcuc2xpY2UoLTYpLCBzaGFyZWRTZWNyZXQsIGVuY3J5cHRlZEtleSk7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnUlNBMV81JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0yNTYnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0zODQnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC01MTInOiB7XG4gICAgICAgICAgICBpZiAoZW5jcnlwdGVkS2V5ID09PSB1bmRlZmluZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBFbmNyeXB0ZWQgS2V5IG1pc3NpbmcnKTtcbiAgICAgICAgICAgIHJldHVybiByc2FFcyhhbGcsIGtleSwgZW5jcnlwdGVkS2V5KTtcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdQQkVTMi1IUzI1NitBMTI4S1cnOlxuICAgICAgICBjYXNlICdQQkVTMi1IUzM4NCtBMTkyS1cnOlxuICAgICAgICBjYXNlICdQQkVTMi1IUzUxMitBMjU2S1cnOiB7XG4gICAgICAgICAgICBpZiAoZW5jcnlwdGVkS2V5ID09PSB1bmRlZmluZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBFbmNyeXB0ZWQgS2V5IG1pc3NpbmcnKTtcbiAgICAgICAgICAgIGlmICh0eXBlb2Ygam9zZUhlYWRlci5wMmMgIT09ICdudW1iZXInKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKGBKT1NFIEhlYWRlciBcInAyY1wiIChQQkVTMiBDb3VudCkgbWlzc2luZyBvciBpbnZhbGlkYCk7XG4gICAgICAgICAgICBjb25zdCBwMmNMaW1pdCA9IG9wdGlvbnM/Lm1heFBCRVMyQ291bnQgfHwgMTAwMDA7XG4gICAgICAgICAgICBpZiAoam9zZUhlYWRlci5wMmMgPiBwMmNMaW1pdClcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSk9TRSBIZWFkZXIgXCJwMmNcIiAoUEJFUzIgQ291bnQpIG91dCBpcyBvZiBhY2NlcHRhYmxlIGJvdW5kc2ApO1xuICAgICAgICAgICAgaWYgKHR5cGVvZiBqb3NlSGVhZGVyLnAycyAhPT0gJ3N0cmluZycpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwicDJzXCIgKFBCRVMyIFNhbHQpIG1pc3Npbmcgb3IgaW52YWxpZGApO1xuICAgICAgICAgICAgbGV0IHAycztcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgcDJzID0gYmFzZTY0dXJsKGpvc2VIZWFkZXIucDJzKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIHAycycpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIHBiZXMyS3coYWxnLCBrZXksIGVuY3J5cHRlZEtleSwgam9zZUhlYWRlci5wMmMsIHAycyk7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnQTE5MktXJzpcbiAgICAgICAgY2FzZSAnQTI1NktXJzoge1xuICAgICAgICAgICAgaWYgKGVuY3J5cHRlZEtleSA9PT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgRW5jcnlwdGVkIEtleSBtaXNzaW5nJyk7XG4gICAgICAgICAgICByZXR1cm4gYWVzS3coYWxnLCBrZXksIGVuY3J5cHRlZEtleSk7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnQTEyOEdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTE5MkdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTUtXJzoge1xuICAgICAgICAgICAgaWYgKGVuY3J5cHRlZEtleSA9PT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgRW5jcnlwdGVkIEtleSBtaXNzaW5nJyk7XG4gICAgICAgICAgICBpZiAodHlwZW9mIGpvc2VIZWFkZXIuaXYgIT09ICdzdHJpbmcnKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKGBKT1NFIEhlYWRlciBcIml2XCIgKEluaXRpYWxpemF0aW9uIFZlY3RvcikgbWlzc2luZyBvciBpbnZhbGlkYCk7XG4gICAgICAgICAgICBpZiAodHlwZW9mIGpvc2VIZWFkZXIudGFnICE9PSAnc3RyaW5nJylcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSk9TRSBIZWFkZXIgXCJ0YWdcIiAoQXV0aGVudGljYXRpb24gVGFnKSBtaXNzaW5nIG9yIGludmFsaWRgKTtcbiAgICAgICAgICAgIGxldCBpdjtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgaXYgPSBiYXNlNjR1cmwoam9zZUhlYWRlci5pdik7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBpdicpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgbGV0IHRhZztcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgdGFnID0gYmFzZTY0dXJsKGpvc2VIZWFkZXIudGFnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIHRhZycpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIGFlc0djbUt3KGFsZywga2V5LCBlbmNyeXB0ZWRLZXksIGl2LCB0YWcpO1xuICAgICAgICB9XG4gICAgICAgIGRlZmF1bHQ6IHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIFwiYWxnXCIgKEpXRSBBbGdvcml0aG0pIGhlYWRlciB2YWx1ZScpO1xuICAgICAgICB9XG4gICAgfVxufVxuZXhwb3J0IGRlZmF1bHQgZGVjcnlwdEtleU1hbmFnZW1lbnQ7XG4iLCJpbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuZnVuY3Rpb24gdmFsaWRhdGVDcml0KEVyciwgcmVjb2duaXplZERlZmF1bHQsIHJlY29nbml6ZWRPcHRpb24sIHByb3RlY3RlZEhlYWRlciwgam9zZUhlYWRlcikge1xuICAgIGlmIChqb3NlSGVhZGVyLmNyaXQgIT09IHVuZGVmaW5lZCAmJiBwcm90ZWN0ZWRIZWFkZXI/LmNyaXQgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyKCdcImNyaXRcIiAoQ3JpdGljYWwpIEhlYWRlciBQYXJhbWV0ZXIgTVVTVCBiZSBpbnRlZ3JpdHkgcHJvdGVjdGVkJyk7XG4gICAgfVxuICAgIGlmICghcHJvdGVjdGVkSGVhZGVyIHx8IHByb3RlY3RlZEhlYWRlci5jcml0ID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmV0dXJuIG5ldyBTZXQoKTtcbiAgICB9XG4gICAgaWYgKCFBcnJheS5pc0FycmF5KHByb3RlY3RlZEhlYWRlci5jcml0KSB8fFxuICAgICAgICBwcm90ZWN0ZWRIZWFkZXIuY3JpdC5sZW5ndGggPT09IDAgfHxcbiAgICAgICAgcHJvdGVjdGVkSGVhZGVyLmNyaXQuc29tZSgoaW5wdXQpID0+IHR5cGVvZiBpbnB1dCAhPT0gJ3N0cmluZycgfHwgaW5wdXQubGVuZ3RoID09PSAwKSkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyKCdcImNyaXRcIiAoQ3JpdGljYWwpIEhlYWRlciBQYXJhbWV0ZXIgTVVTVCBiZSBhbiBhcnJheSBvZiBub24tZW1wdHkgc3RyaW5ncyB3aGVuIHByZXNlbnQnKTtcbiAgICB9XG4gICAgbGV0IHJlY29nbml6ZWQ7XG4gICAgaWYgKHJlY29nbml6ZWRPcHRpb24gIT09IHVuZGVmaW5lZCkge1xuICAgICAgICByZWNvZ25pemVkID0gbmV3IE1hcChbLi4uT2JqZWN0LmVudHJpZXMocmVjb2duaXplZE9wdGlvbiksIC4uLnJlY29nbml6ZWREZWZhdWx0LmVudHJpZXMoKV0pO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgcmVjb2duaXplZCA9IHJlY29nbml6ZWREZWZhdWx0O1xuICAgIH1cbiAgICBmb3IgKGNvbnN0IHBhcmFtZXRlciBvZiBwcm90ZWN0ZWRIZWFkZXIuY3JpdCkge1xuICAgICAgICBpZiAoIXJlY29nbml6ZWQuaGFzKHBhcmFtZXRlcikpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKGBFeHRlbnNpb24gSGVhZGVyIFBhcmFtZXRlciBcIiR7cGFyYW1ldGVyfVwiIGlzIG5vdCByZWNvZ25pemVkYCk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGpvc2VIZWFkZXJbcGFyYW1ldGVyXSA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyKGBFeHRlbnNpb24gSGVhZGVyIFBhcmFtZXRlciBcIiR7cGFyYW1ldGVyfVwiIGlzIG1pc3NpbmdgKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAocmVjb2duaXplZC5nZXQocGFyYW1ldGVyKSAmJiBwcm90ZWN0ZWRIZWFkZXJbcGFyYW1ldGVyXSA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyKGBFeHRlbnNpb24gSGVhZGVyIFBhcmFtZXRlciBcIiR7cGFyYW1ldGVyfVwiIE1VU1QgYmUgaW50ZWdyaXR5IHByb3RlY3RlZGApO1xuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiBuZXcgU2V0KHByb3RlY3RlZEhlYWRlci5jcml0KTtcbn1cbmV4cG9ydCBkZWZhdWx0IHZhbGlkYXRlQ3JpdDtcbiIsImNvbnN0IHZhbGlkYXRlQWxnb3JpdGhtcyA9IChvcHRpb24sIGFsZ29yaXRobXMpID0+IHtcbiAgICBpZiAoYWxnb3JpdGhtcyAhPT0gdW5kZWZpbmVkICYmXG4gICAgICAgICghQXJyYXkuaXNBcnJheShhbGdvcml0aG1zKSB8fCBhbGdvcml0aG1zLnNvbWUoKHMpID0+IHR5cGVvZiBzICE9PSAnc3RyaW5nJykpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYFwiJHtvcHRpb259XCIgb3B0aW9uIG11c3QgYmUgYW4gYXJyYXkgb2Ygc3RyaW5nc2ApO1xuICAgIH1cbiAgICBpZiAoIWFsZ29yaXRobXMpIHtcbiAgICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICB9XG4gICAgcmV0dXJuIG5ldyBTZXQoYWxnb3JpdGhtcyk7XG59O1xuZXhwb3J0IGRlZmF1bHQgdmFsaWRhdGVBbGdvcml0aG1zO1xuIiwiaW1wb3J0IHsgZGVjb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4uLy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmltcG9ydCBkZWNyeXB0IGZyb20gJy4uLy4uL3J1bnRpbWUvZGVjcnlwdC5qcyc7XG5pbXBvcnQgeyBKT1NFQWxnTm90QWxsb3dlZCwgSk9TRU5vdFN1cHBvcnRlZCwgSldFSW52YWxpZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCBpc0Rpc2pvaW50IGZyb20gJy4uLy4uL2xpYi9pc19kaXNqb2ludC5qcyc7XG5pbXBvcnQgaXNPYmplY3QgZnJvbSAnLi4vLi4vbGliL2lzX29iamVjdC5qcyc7XG5pbXBvcnQgZGVjcnlwdEtleU1hbmFnZW1lbnQgZnJvbSAnLi4vLi4vbGliL2RlY3J5cHRfa2V5X21hbmFnZW1lbnQuanMnO1xuaW1wb3J0IHsgZW5jb2RlciwgZGVjb2RlciwgY29uY2F0IH0gZnJvbSAnLi4vLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgZ2VuZXJhdGVDZWsgZnJvbSAnLi4vLi4vbGliL2Nlay5qcyc7XG5pbXBvcnQgdmFsaWRhdGVDcml0IGZyb20gJy4uLy4uL2xpYi92YWxpZGF0ZV9jcml0LmpzJztcbmltcG9ydCB2YWxpZGF0ZUFsZ29yaXRobXMgZnJvbSAnLi4vLi4vbGliL3ZhbGlkYXRlX2FsZ29yaXRobXMuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGZsYXR0ZW5lZERlY3J5cHQoandlLCBrZXksIG9wdGlvbnMpIHtcbiAgICBpZiAoIWlzT2JqZWN0KGp3ZSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZsYXR0ZW5lZCBKV0UgbXVzdCBiZSBhbiBvYmplY3QnKTtcbiAgICB9XG4gICAgaWYgKGp3ZS5wcm90ZWN0ZWQgPT09IHVuZGVmaW5lZCAmJiBqd2UuaGVhZGVyID09PSB1bmRlZmluZWQgJiYgandlLnVucHJvdGVjdGVkID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pPU0UgSGVhZGVyIG1pc3NpbmcnKTtcbiAgICB9XG4gICAgaWYgKGp3ZS5pdiAhPT0gdW5kZWZpbmVkICYmIHR5cGVvZiBqd2UuaXYgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgSW5pdGlhbGl6YXRpb24gVmVjdG9yIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgandlLmNpcGhlcnRleHQgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgQ2lwaGVydGV4dCBtaXNzaW5nIG9yIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmIChqd2UudGFnICE9PSB1bmRlZmluZWQgJiYgdHlwZW9mIGp3ZS50YWcgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgQXV0aGVudGljYXRpb24gVGFnIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmIChqd2UucHJvdGVjdGVkICE9PSB1bmRlZmluZWQgJiYgdHlwZW9mIGp3ZS5wcm90ZWN0ZWQgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgUHJvdGVjdGVkIEhlYWRlciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoandlLmVuY3J5cHRlZF9rZXkgIT09IHVuZGVmaW5lZCAmJiB0eXBlb2YgandlLmVuY3J5cHRlZF9rZXkgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgRW5jcnlwdGVkIEtleSBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoandlLmFhZCAhPT0gdW5kZWZpbmVkICYmIHR5cGVvZiBqd2UuYWFkICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEFBRCBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoandlLmhlYWRlciAhPT0gdW5kZWZpbmVkICYmICFpc09iamVjdChqd2UuaGVhZGVyKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFNoYXJlZCBVbnByb3RlY3RlZCBIZWFkZXIgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3ZS51bnByb3RlY3RlZCAhPT0gdW5kZWZpbmVkICYmICFpc09iamVjdChqd2UudW5wcm90ZWN0ZWQpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgUGVyLVJlY2lwaWVudCBVbnByb3RlY3RlZCBIZWFkZXIgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgbGV0IHBhcnNlZFByb3Q7XG4gICAgaWYgKGp3ZS5wcm90ZWN0ZWQpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIGNvbnN0IHByb3RlY3RlZEhlYWRlciA9IGJhc2U2NHVybChqd2UucHJvdGVjdGVkKTtcbiAgICAgICAgICAgIHBhcnNlZFByb3QgPSBKU09OLnBhcnNlKGRlY29kZXIuZGVjb2RlKHByb3RlY3RlZEhlYWRlcikpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgUHJvdGVjdGVkIEhlYWRlciBpcyBpbnZhbGlkJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgaWYgKCFpc0Rpc2pvaW50KHBhcnNlZFByb3QsIGp3ZS5oZWFkZXIsIGp3ZS51bnByb3RlY3RlZCkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBQcm90ZWN0ZWQsIEpXRSBVbnByb3RlY3RlZCBIZWFkZXIsIGFuZCBKV0UgUGVyLVJlY2lwaWVudCBVbnByb3RlY3RlZCBIZWFkZXIgUGFyYW1ldGVyIG5hbWVzIG11c3QgYmUgZGlzam9pbnQnKTtcbiAgICB9XG4gICAgY29uc3Qgam9zZUhlYWRlciA9IHtcbiAgICAgICAgLi4ucGFyc2VkUHJvdCxcbiAgICAgICAgLi4uandlLmhlYWRlcixcbiAgICAgICAgLi4uandlLnVucHJvdGVjdGVkLFxuICAgIH07XG4gICAgdmFsaWRhdGVDcml0KEpXRUludmFsaWQsIG5ldyBNYXAoKSwgb3B0aW9ucz8uY3JpdCwgcGFyc2VkUHJvdCwgam9zZUhlYWRlcik7XG4gICAgaWYgKGpvc2VIZWFkZXIuemlwICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0pXRSBcInppcFwiIChDb21wcmVzc2lvbiBBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgaXMgbm90IHN1cHBvcnRlZC4nKTtcbiAgICB9XG4gICAgY29uc3QgeyBhbGcsIGVuYyB9ID0gam9zZUhlYWRlcjtcbiAgICBpZiAodHlwZW9mIGFsZyAhPT0gJ3N0cmluZycgfHwgIWFsZykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnbWlzc2luZyBKV0UgQWxnb3JpdGhtIChhbGcpIGluIEpXRSBIZWFkZXInKTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBlbmMgIT09ICdzdHJpbmcnIHx8ICFlbmMpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ21pc3NpbmcgSldFIEVuY3J5cHRpb24gQWxnb3JpdGhtIChlbmMpIGluIEpXRSBIZWFkZXInKTtcbiAgICB9XG4gICAgY29uc3Qga2V5TWFuYWdlbWVudEFsZ29yaXRobXMgPSBvcHRpb25zICYmIHZhbGlkYXRlQWxnb3JpdGhtcygna2V5TWFuYWdlbWVudEFsZ29yaXRobXMnLCBvcHRpb25zLmtleU1hbmFnZW1lbnRBbGdvcml0aG1zKTtcbiAgICBjb25zdCBjb250ZW50RW5jcnlwdGlvbkFsZ29yaXRobXMgPSBvcHRpb25zICYmXG4gICAgICAgIHZhbGlkYXRlQWxnb3JpdGhtcygnY29udGVudEVuY3J5cHRpb25BbGdvcml0aG1zJywgb3B0aW9ucy5jb250ZW50RW5jcnlwdGlvbkFsZ29yaXRobXMpO1xuICAgIGlmICgoa2V5TWFuYWdlbWVudEFsZ29yaXRobXMgJiYgIWtleU1hbmFnZW1lbnRBbGdvcml0aG1zLmhhcyhhbGcpKSB8fFxuICAgICAgICAoIWtleU1hbmFnZW1lbnRBbGdvcml0aG1zICYmIGFsZy5zdGFydHNXaXRoKCdQQkVTMicpKSkge1xuICAgICAgICB0aHJvdyBuZXcgSk9TRUFsZ05vdEFsbG93ZWQoJ1wiYWxnXCIgKEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciB2YWx1ZSBub3QgYWxsb3dlZCcpO1xuICAgIH1cbiAgICBpZiAoY29udGVudEVuY3J5cHRpb25BbGdvcml0aG1zICYmICFjb250ZW50RW5jcnlwdGlvbkFsZ29yaXRobXMuaGFzKGVuYykpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpPU0VBbGdOb3RBbGxvd2VkKCdcImVuY1wiIChFbmNyeXB0aW9uIEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciB2YWx1ZSBub3QgYWxsb3dlZCcpO1xuICAgIH1cbiAgICBsZXQgZW5jcnlwdGVkS2V5O1xuICAgIGlmIChqd2UuZW5jcnlwdGVkX2tleSAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBlbmNyeXB0ZWRLZXkgPSBiYXNlNjR1cmwoandlLmVuY3J5cHRlZF9rZXkpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgZW5jcnlwdGVkX2tleScpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGxldCByZXNvbHZlZEtleSA9IGZhbHNlO1xuICAgIGlmICh0eXBlb2Yga2V5ID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgIGtleSA9IGF3YWl0IGtleShwYXJzZWRQcm90LCBqd2UpO1xuICAgICAgICByZXNvbHZlZEtleSA9IHRydWU7XG4gICAgfVxuICAgIGxldCBjZWs7XG4gICAgdHJ5IHtcbiAgICAgICAgY2VrID0gYXdhaXQgZGVjcnlwdEtleU1hbmFnZW1lbnQoYWxnLCBrZXksIGVuY3J5cHRlZEtleSwgam9zZUhlYWRlciwgb3B0aW9ucyk7XG4gICAgfVxuICAgIGNhdGNoIChlcnIpIHtcbiAgICAgICAgaWYgKGVyciBpbnN0YW5jZW9mIFR5cGVFcnJvciB8fCBlcnIgaW5zdGFuY2VvZiBKV0VJbnZhbGlkIHx8IGVyciBpbnN0YW5jZW9mIEpPU0VOb3RTdXBwb3J0ZWQpIHtcbiAgICAgICAgICAgIHRocm93IGVycjtcbiAgICAgICAgfVxuICAgICAgICBjZWsgPSBnZW5lcmF0ZUNlayhlbmMpO1xuICAgIH1cbiAgICBsZXQgaXY7XG4gICAgbGV0IHRhZztcbiAgICBpZiAoandlLml2ICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIGl2ID0gYmFzZTY0dXJsKGp3ZS5pdik7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBpdicpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGlmIChqd2UudGFnICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHRhZyA9IGJhc2U2NHVybChqd2UudGFnKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIHRhZycpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGNvbnN0IHByb3RlY3RlZEhlYWRlciA9IGVuY29kZXIuZW5jb2RlKGp3ZS5wcm90ZWN0ZWQgPz8gJycpO1xuICAgIGxldCBhZGRpdGlvbmFsRGF0YTtcbiAgICBpZiAoandlLmFhZCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIGFkZGl0aW9uYWxEYXRhID0gY29uY2F0KHByb3RlY3RlZEhlYWRlciwgZW5jb2Rlci5lbmNvZGUoJy4nKSwgZW5jb2Rlci5lbmNvZGUoandlLmFhZCkpO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgYWRkaXRpb25hbERhdGEgPSBwcm90ZWN0ZWRIZWFkZXI7XG4gICAgfVxuICAgIGxldCBjaXBoZXJ0ZXh0O1xuICAgIHRyeSB7XG4gICAgICAgIGNpcGhlcnRleHQgPSBiYXNlNjR1cmwoandlLmNpcGhlcnRleHQpO1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgY2lwaGVydGV4dCcpO1xuICAgIH1cbiAgICBjb25zdCBwbGFpbnRleHQgPSBhd2FpdCBkZWNyeXB0KGVuYywgY2VrLCBjaXBoZXJ0ZXh0LCBpdiwgdGFnLCBhZGRpdGlvbmFsRGF0YSk7XG4gICAgY29uc3QgcmVzdWx0ID0geyBwbGFpbnRleHQgfTtcbiAgICBpZiAoandlLnByb3RlY3RlZCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHJlc3VsdC5wcm90ZWN0ZWRIZWFkZXIgPSBwYXJzZWRQcm90O1xuICAgIH1cbiAgICBpZiAoandlLmFhZCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICByZXN1bHQuYWRkaXRpb25hbEF1dGhlbnRpY2F0ZWREYXRhID0gYmFzZTY0dXJsKGp3ZS5hYWQpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgYWFkJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgaWYgKGp3ZS51bnByb3RlY3RlZCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHJlc3VsdC5zaGFyZWRVbnByb3RlY3RlZEhlYWRlciA9IGp3ZS51bnByb3RlY3RlZDtcbiAgICB9XG4gICAgaWYgKGp3ZS5oZWFkZXIgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICByZXN1bHQudW5wcm90ZWN0ZWRIZWFkZXIgPSBqd2UuaGVhZGVyO1xuICAgIH1cbiAgICBpZiAocmVzb2x2ZWRLZXkpIHtcbiAgICAgICAgcmV0dXJuIHsgLi4ucmVzdWx0LCBrZXkgfTtcbiAgICB9XG4gICAgcmV0dXJuIHJlc3VsdDtcbn1cbiIsImltcG9ydCB7IGZsYXR0ZW5lZERlY3J5cHQgfSBmcm9tICcuLi9mbGF0dGVuZWQvZGVjcnlwdC5qcyc7XG5pbXBvcnQgeyBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHsgZGVjb2RlciB9IGZyb20gJy4uLy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGNvbXBhY3REZWNyeXB0KGp3ZSwga2V5LCBvcHRpb25zKSB7XG4gICAgaWYgKGp3ZSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgandlID0gZGVjb2Rlci5kZWNvZGUoandlKTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBqd2UgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdDb21wYWN0IEpXRSBtdXN0IGJlIGEgc3RyaW5nIG9yIFVpbnQ4QXJyYXknKTtcbiAgICB9XG4gICAgY29uc3QgeyAwOiBwcm90ZWN0ZWRIZWFkZXIsIDE6IGVuY3J5cHRlZEtleSwgMjogaXYsIDM6IGNpcGhlcnRleHQsIDQ6IHRhZywgbGVuZ3RoLCB9ID0gandlLnNwbGl0KCcuJyk7XG4gICAgaWYgKGxlbmd0aCAhPT0gNSkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSW52YWxpZCBDb21wYWN0IEpXRScpO1xuICAgIH1cbiAgICBjb25zdCBkZWNyeXB0ZWQgPSBhd2FpdCBmbGF0dGVuZWREZWNyeXB0KHtcbiAgICAgICAgY2lwaGVydGV4dCxcbiAgICAgICAgaXY6IGl2IHx8IHVuZGVmaW5lZCxcbiAgICAgICAgcHJvdGVjdGVkOiBwcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgIHRhZzogdGFnIHx8IHVuZGVmaW5lZCxcbiAgICAgICAgZW5jcnlwdGVkX2tleTogZW5jcnlwdGVkS2V5IHx8IHVuZGVmaW5lZCxcbiAgICB9LCBrZXksIG9wdGlvbnMpO1xuICAgIGNvbnN0IHJlc3VsdCA9IHsgcGxhaW50ZXh0OiBkZWNyeXB0ZWQucGxhaW50ZXh0LCBwcm90ZWN0ZWRIZWFkZXI6IGRlY3J5cHRlZC5wcm90ZWN0ZWRIZWFkZXIgfTtcbiAgICBpZiAodHlwZW9mIGtleSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICByZXR1cm4geyAuLi5yZXN1bHQsIGtleTogZGVjcnlwdGVkLmtleSB9O1xuICAgIH1cbiAgICByZXR1cm4gcmVzdWx0O1xufVxuIiwiaW1wb3J0IHsgZmxhdHRlbmVkRGVjcnlwdCB9IGZyb20gJy4uL2ZsYXR0ZW5lZC9kZWNyeXB0LmpzJztcbmltcG9ydCB7IEpXRURlY3J5cHRpb25GYWlsZWQsIEpXRUludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgaXNPYmplY3QgZnJvbSAnLi4vLi4vbGliL2lzX29iamVjdC5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhbERlY3J5cHQoandlLCBrZXksIG9wdGlvbnMpIHtcbiAgICBpZiAoIWlzT2JqZWN0KGp3ZSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0dlbmVyYWwgSldFIG11c3QgYmUgYW4gb2JqZWN0Jyk7XG4gICAgfVxuICAgIGlmICghQXJyYXkuaXNBcnJheShqd2UucmVjaXBpZW50cykgfHwgIWp3ZS5yZWNpcGllbnRzLmV2ZXJ5KGlzT2JqZWN0KSkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFJlY2lwaWVudHMgbWlzc2luZyBvciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoIWp3ZS5yZWNpcGllbnRzLmxlbmd0aCkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFJlY2lwaWVudHMgaGFzIG5vIG1lbWJlcnMnKTtcbiAgICB9XG4gICAgZm9yIChjb25zdCByZWNpcGllbnQgb2YgandlLnJlY2lwaWVudHMpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHJldHVybiBhd2FpdCBmbGF0dGVuZWREZWNyeXB0KHtcbiAgICAgICAgICAgICAgICBhYWQ6IGp3ZS5hYWQsXG4gICAgICAgICAgICAgICAgY2lwaGVydGV4dDogandlLmNpcGhlcnRleHQsXG4gICAgICAgICAgICAgICAgZW5jcnlwdGVkX2tleTogcmVjaXBpZW50LmVuY3J5cHRlZF9rZXksXG4gICAgICAgICAgICAgICAgaGVhZGVyOiByZWNpcGllbnQuaGVhZGVyLFxuICAgICAgICAgICAgICAgIGl2OiBqd2UuaXYsXG4gICAgICAgICAgICAgICAgcHJvdGVjdGVkOiBqd2UucHJvdGVjdGVkLFxuICAgICAgICAgICAgICAgIHRhZzogandlLnRhZyxcbiAgICAgICAgICAgICAgICB1bnByb3RlY3RlZDogandlLnVucHJvdGVjdGVkLFxuICAgICAgICAgICAgfSwga2V5LCBvcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgIH1cbiAgICB9XG4gICAgdGhyb3cgbmV3IEpXRURlY3J5cHRpb25GYWlsZWQoKTtcbn1cbiIsImltcG9ydCBjcnlwdG8sIHsgaXNDcnlwdG9LZXkgfSBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyBlbmNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmNvbnN0IGtleVRvSldLID0gYXN5bmMgKGtleSkgPT4ge1xuICAgIGlmIChrZXkgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBrdHk6ICdvY3QnLFxuICAgICAgICAgICAgazogYmFzZTY0dXJsKGtleSksXG4gICAgICAgIH07XG4gICAgfVxuICAgIGlmICghaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzLCAnVWludDhBcnJheScpKTtcbiAgICB9XG4gICAgaWYgKCFrZXkuZXh0cmFjdGFibGUpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignbm9uLWV4dHJhY3RhYmxlIENyeXB0b0tleSBjYW5ub3QgYmUgZXhwb3J0ZWQgYXMgYSBKV0snKTtcbiAgICB9XG4gICAgY29uc3QgeyBleHQsIGtleV9vcHMsIGFsZywgdXNlLCAuLi5qd2sgfSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdqd2snLCBrZXkpO1xuICAgIHJldHVybiBqd2s7XG59O1xuZXhwb3J0IGRlZmF1bHQga2V5VG9KV0s7XG4iLCJpbXBvcnQgeyB0b1NQS0kgYXMgZXhwb3J0UHVibGljIH0gZnJvbSAnLi4vcnVudGltZS9hc24xLmpzJztcbmltcG9ydCB7IHRvUEtDUzggYXMgZXhwb3J0UHJpdmF0ZSB9IGZyb20gJy4uL3J1bnRpbWUvYXNuMS5qcyc7XG5pbXBvcnQga2V5VG9KV0sgZnJvbSAnLi4vcnVudGltZS9rZXlfdG9fandrLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBleHBvcnRTUEtJKGtleSkge1xuICAgIHJldHVybiBleHBvcnRQdWJsaWMoa2V5KTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBleHBvcnRQS0NTOChrZXkpIHtcbiAgICByZXR1cm4gZXhwb3J0UHJpdmF0ZShrZXkpO1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGV4cG9ydEpXSyhrZXkpIHtcbiAgICByZXR1cm4ga2V5VG9KV0soa2V5KTtcbn1cbiIsImltcG9ydCB7IHdyYXAgYXMgYWVzS3cgfSBmcm9tICcuLi9ydW50aW1lL2Flc2t3LmpzJztcbmltcG9ydCAqIGFzIEVDREggZnJvbSAnLi4vcnVudGltZS9lY2RoZXMuanMnO1xuaW1wb3J0IHsgZW5jcnlwdCBhcyBwYmVzMkt3IH0gZnJvbSAnLi4vcnVudGltZS9wYmVzMmt3LmpzJztcbmltcG9ydCB7IGVuY3J5cHQgYXMgcnNhRXMgfSBmcm9tICcuLi9ydW50aW1lL3JzYWVzLmpzJztcbmltcG9ydCB7IGVuY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgZ2VuZXJhdGVDZWssIHsgYml0TGVuZ3RoIGFzIGNla0xlbmd0aCB9IGZyb20gJy4uL2xpYi9jZWsuanMnO1xuaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IGV4cG9ydEpXSyB9IGZyb20gJy4uL2tleS9leHBvcnQuanMnO1xuaW1wb3J0IGNoZWNrS2V5VHlwZSBmcm9tICcuL2NoZWNrX2tleV90eXBlLmpzJztcbmltcG9ydCB7IHdyYXAgYXMgYWVzR2NtS3cgfSBmcm9tICcuL2Flc2djbWt3LmpzJztcbmFzeW5jIGZ1bmN0aW9uIGVuY3J5cHRLZXlNYW5hZ2VtZW50KGFsZywgZW5jLCBrZXksIHByb3ZpZGVkQ2VrLCBwcm92aWRlZFBhcmFtZXRlcnMgPSB7fSkge1xuICAgIGxldCBlbmNyeXB0ZWRLZXk7XG4gICAgbGV0IHBhcmFtZXRlcnM7XG4gICAgbGV0IGNlaztcbiAgICBjaGVja0tleVR5cGUoYWxnLCBrZXksICdlbmNyeXB0Jyk7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnZGlyJzoge1xuICAgICAgICAgICAgY2VrID0ga2V5O1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnRUNESC1FUyc6XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMTkyS1cnOlxuICAgICAgICBjYXNlICdFQ0RILUVTK0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGlmICghRUNESC5lY2RoQWxsb3dlZChrZXkpKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0VDREggd2l0aCB0aGUgcHJvdmlkZWQga2V5IGlzIG5vdCBhbGxvd2VkIG9yIG5vdCBzdXBwb3J0ZWQgYnkgeW91ciBqYXZhc2NyaXB0IHJ1bnRpbWUnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNvbnN0IHsgYXB1LCBhcHYgfSA9IHByb3ZpZGVkUGFyYW1ldGVycztcbiAgICAgICAgICAgIGxldCB7IGVwazogZXBoZW1lcmFsS2V5IH0gPSBwcm92aWRlZFBhcmFtZXRlcnM7XG4gICAgICAgICAgICBlcGhlbWVyYWxLZXkgfHwgKGVwaGVtZXJhbEtleSA9IChhd2FpdCBFQ0RILmdlbmVyYXRlRXBrKGtleSkpLnByaXZhdGVLZXkpO1xuICAgICAgICAgICAgY29uc3QgeyB4LCB5LCBjcnYsIGt0eSB9ID0gYXdhaXQgZXhwb3J0SldLKGVwaGVtZXJhbEtleSk7XG4gICAgICAgICAgICBjb25zdCBzaGFyZWRTZWNyZXQgPSBhd2FpdCBFQ0RILmRlcml2ZUtleShrZXksIGVwaGVtZXJhbEtleSwgYWxnID09PSAnRUNESC1FUycgPyBlbmMgOiBhbGcsIGFsZyA9PT0gJ0VDREgtRVMnID8gY2VrTGVuZ3RoKGVuYykgOiBwYXJzZUludChhbGcuc2xpY2UoLTUsIC0yKSwgMTApLCBhcHUsIGFwdik7XG4gICAgICAgICAgICBwYXJhbWV0ZXJzID0geyBlcGs6IHsgeCwgY3J2LCBrdHkgfSB9O1xuICAgICAgICAgICAgaWYgKGt0eSA9PT0gJ0VDJylcbiAgICAgICAgICAgICAgICBwYXJhbWV0ZXJzLmVway55ID0geTtcbiAgICAgICAgICAgIGlmIChhcHUpXG4gICAgICAgICAgICAgICAgcGFyYW1ldGVycy5hcHUgPSBiYXNlNjR1cmwoYXB1KTtcbiAgICAgICAgICAgIGlmIChhcHYpXG4gICAgICAgICAgICAgICAgcGFyYW1ldGVycy5hcHYgPSBiYXNlNjR1cmwoYXB2KTtcbiAgICAgICAgICAgIGlmIChhbGcgPT09ICdFQ0RILUVTJykge1xuICAgICAgICAgICAgICAgIGNlayA9IHNoYXJlZFNlY3JldDtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNlayA9IHByb3ZpZGVkQ2VrIHx8IGdlbmVyYXRlQ2VrKGVuYyk7XG4gICAgICAgICAgICBjb25zdCBrd0FsZyA9IGFsZy5zbGljZSgtNik7XG4gICAgICAgICAgICBlbmNyeXB0ZWRLZXkgPSBhd2FpdCBhZXNLdyhrd0FsZywgc2hhcmVkU2VjcmV0LCBjZWspO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnUlNBMV81JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0yNTYnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0zODQnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC01MTInOiB7XG4gICAgICAgICAgICBjZWsgPSBwcm92aWRlZENlayB8fCBnZW5lcmF0ZUNlayhlbmMpO1xuICAgICAgICAgICAgZW5jcnlwdGVkS2V5ID0gYXdhaXQgcnNhRXMoYWxnLCBrZXksIGNlayk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdQQkVTMi1IUzI1NitBMTI4S1cnOlxuICAgICAgICBjYXNlICdQQkVTMi1IUzM4NCtBMTkyS1cnOlxuICAgICAgICBjYXNlICdQQkVTMi1IUzUxMitBMjU2S1cnOiB7XG4gICAgICAgICAgICBjZWsgPSBwcm92aWRlZENlayB8fCBnZW5lcmF0ZUNlayhlbmMpO1xuICAgICAgICAgICAgY29uc3QgeyBwMmMsIHAycyB9ID0gcHJvdmlkZWRQYXJhbWV0ZXJzO1xuICAgICAgICAgICAgKHsgZW5jcnlwdGVkS2V5LCAuLi5wYXJhbWV0ZXJzIH0gPSBhd2FpdCBwYmVzMkt3KGFsZywga2V5LCBjZWssIHAyYywgcDJzKSk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdBMTI4S1cnOlxuICAgICAgICBjYXNlICdBMTkyS1cnOlxuICAgICAgICBjYXNlICdBMjU2S1cnOiB7XG4gICAgICAgICAgICBjZWsgPSBwcm92aWRlZENlayB8fCBnZW5lcmF0ZUNlayhlbmMpO1xuICAgICAgICAgICAgZW5jcnlwdGVkS2V5ID0gYXdhaXQgYWVzS3coYWxnLCBrZXksIGNlayk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdBMTI4R0NNS1cnOlxuICAgICAgICBjYXNlICdBMTkyR0NNS1cnOlxuICAgICAgICBjYXNlICdBMjU2R0NNS1cnOiB7XG4gICAgICAgICAgICBjZWsgPSBwcm92aWRlZENlayB8fCBnZW5lcmF0ZUNlayhlbmMpO1xuICAgICAgICAgICAgY29uc3QgeyBpdiB9ID0gcHJvdmlkZWRQYXJhbWV0ZXJzO1xuICAgICAgICAgICAgKHsgZW5jcnlwdGVkS2V5LCAuLi5wYXJhbWV0ZXJzIH0gPSBhd2FpdCBhZXNHY21LdyhhbGcsIGtleSwgY2VrLCBpdikpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgZGVmYXVsdDoge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgXCJhbGdcIiAoSldFIEFsZ29yaXRobSkgaGVhZGVyIHZhbHVlJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHsgY2VrLCBlbmNyeXB0ZWRLZXksIHBhcmFtZXRlcnMgfTtcbn1cbmV4cG9ydCBkZWZhdWx0IGVuY3J5cHRLZXlNYW5hZ2VtZW50O1xuIiwiaW1wb3J0IHsgZW5jb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4uLy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmltcG9ydCBlbmNyeXB0IGZyb20gJy4uLy4uL3J1bnRpbWUvZW5jcnlwdC5qcyc7XG5pbXBvcnQgZW5jcnlwdEtleU1hbmFnZW1lbnQgZnJvbSAnLi4vLi4vbGliL2VuY3J5cHRfa2V5X21hbmFnZW1lbnQuanMnO1xuaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCwgSldFSW52YWxpZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCBpc0Rpc2pvaW50IGZyb20gJy4uLy4uL2xpYi9pc19kaXNqb2ludC5qcyc7XG5pbXBvcnQgeyBlbmNvZGVyLCBkZWNvZGVyLCBjb25jYXQgfSBmcm9tICcuLi8uLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmltcG9ydCB2YWxpZGF0ZUNyaXQgZnJvbSAnLi4vLi4vbGliL3ZhbGlkYXRlX2NyaXQuanMnO1xuZXhwb3J0IGNvbnN0IHVucHJvdGVjdGVkID0gU3ltYm9sKCk7XG5leHBvcnQgY2xhc3MgRmxhdHRlbmVkRW5jcnlwdCB7XG4gICAgY29uc3RydWN0b3IocGxhaW50ZXh0KSB7XG4gICAgICAgIGlmICghKHBsYWludGV4dCBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdwbGFpbnRleHQgbXVzdCBiZSBhbiBpbnN0YW5jZSBvZiBVaW50OEFycmF5Jyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fcGxhaW50ZXh0ID0gcGxhaW50ZXh0O1xuICAgIH1cbiAgICBzZXRLZXlNYW5hZ2VtZW50UGFyYW1ldGVycyhwYXJhbWV0ZXJzKSB7XG4gICAgICAgIGlmICh0aGlzLl9rZXlNYW5hZ2VtZW50UGFyYW1ldGVycykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0S2V5TWFuYWdlbWVudFBhcmFtZXRlcnMgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9rZXlNYW5hZ2VtZW50UGFyYW1ldGVycyA9IHBhcmFtZXRlcnM7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3Byb3RlY3RlZEhlYWRlciA9IHByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldFNoYXJlZFVucHJvdGVjdGVkSGVhZGVyKHNoYXJlZFVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLl9zaGFyZWRVbnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0U2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9zaGFyZWRVbnByb3RlY3RlZEhlYWRlciA9IHNoYXJlZFVucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0VW5wcm90ZWN0ZWRIZWFkZXIodW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRVbnByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyID0gdW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRBZGRpdGlvbmFsQXV0aGVudGljYXRlZERhdGEoYWFkKSB7XG4gICAgICAgIHRoaXMuX2FhZCA9IGFhZDtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldENvbnRlbnRFbmNyeXB0aW9uS2V5KGNlaykge1xuICAgICAgICBpZiAodGhpcy5fY2VrKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRDb250ZW50RW5jcnlwdGlvbktleSBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX2NlayA9IGNlaztcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldEluaXRpYWxpemF0aW9uVmVjdG9yKGl2KSB7XG4gICAgICAgIGlmICh0aGlzLl9pdikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0SW5pdGlhbGl6YXRpb25WZWN0b3IgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9pdiA9IGl2O1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgYXN5bmMgZW5jcnlwdChrZXksIG9wdGlvbnMpIHtcbiAgICAgICAgaWYgKCF0aGlzLl9wcm90ZWN0ZWRIZWFkZXIgJiYgIXRoaXMuX3VucHJvdGVjdGVkSGVhZGVyICYmICF0aGlzLl9zaGFyZWRVbnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ2VpdGhlciBzZXRQcm90ZWN0ZWRIZWFkZXIsIHNldFVucHJvdGVjdGVkSGVhZGVyLCBvciBzaGFyZWRVbnByb3RlY3RlZEhlYWRlciBtdXN0IGJlIGNhbGxlZCBiZWZvcmUgI2VuY3J5cHQoKScpO1xuICAgICAgICB9XG4gICAgICAgIGlmICghaXNEaXNqb2ludCh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIsIHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyLCB0aGlzLl9zaGFyZWRVbnByb3RlY3RlZEhlYWRlcikpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgUHJvdGVjdGVkLCBKV0UgU2hhcmVkIFVucHJvdGVjdGVkIGFuZCBKV0UgUGVyLVJlY2lwaWVudCBIZWFkZXIgUGFyYW1ldGVyIG5hbWVzIG11c3QgYmUgZGlzam9pbnQnKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBqb3NlSGVhZGVyID0ge1xuICAgICAgICAgICAgLi4udGhpcy5fcHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgLi4udGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICAuLi50aGlzLl9zaGFyZWRVbnByb3RlY3RlZEhlYWRlcixcbiAgICAgICAgfTtcbiAgICAgICAgdmFsaWRhdGVDcml0KEpXRUludmFsaWQsIG5ldyBNYXAoKSwgb3B0aW9ucz8uY3JpdCwgdGhpcy5fcHJvdGVjdGVkSGVhZGVyLCBqb3NlSGVhZGVyKTtcbiAgICAgICAgaWYgKGpvc2VIZWFkZXIuemlwICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdKV0UgXCJ6aXBcIiAoQ29tcHJlc3Npb24gQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIGlzIG5vdCBzdXBwb3J0ZWQuJyk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgeyBhbGcsIGVuYyB9ID0gam9zZUhlYWRlcjtcbiAgICAgICAgaWYgKHR5cGVvZiBhbGcgIT09ICdzdHJpbmcnIHx8ICFhbGcpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgXCJhbGdcIiAoQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIG1pc3Npbmcgb3IgaW52YWxpZCcpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0eXBlb2YgZW5jICE9PSAnc3RyaW5nJyB8fCAhZW5jKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFwiZW5jXCIgKEVuY3J5cHRpb24gQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIG1pc3Npbmcgb3IgaW52YWxpZCcpO1xuICAgICAgICB9XG4gICAgICAgIGxldCBlbmNyeXB0ZWRLZXk7XG4gICAgICAgIGlmICh0aGlzLl9jZWsgJiYgKGFsZyA9PT0gJ2RpcicgfHwgYWxnID09PSAnRUNESC1FUycpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGBzZXRDb250ZW50RW5jcnlwdGlvbktleSBjYW5ub3QgYmUgY2FsbGVkIHdpdGggSldFIFwiYWxnXCIgKEFsZ29yaXRobSkgSGVhZGVyICR7YWxnfWApO1xuICAgICAgICB9XG4gICAgICAgIGxldCBjZWs7XG4gICAgICAgIHtcbiAgICAgICAgICAgIGxldCBwYXJhbWV0ZXJzO1xuICAgICAgICAgICAgKHsgY2VrLCBlbmNyeXB0ZWRLZXksIHBhcmFtZXRlcnMgfSA9IGF3YWl0IGVuY3J5cHRLZXlNYW5hZ2VtZW50KGFsZywgZW5jLCBrZXksIHRoaXMuX2NlaywgdGhpcy5fa2V5TWFuYWdlbWVudFBhcmFtZXRlcnMpKTtcbiAgICAgICAgICAgIGlmIChwYXJhbWV0ZXJzKSB7XG4gICAgICAgICAgICAgICAgaWYgKG9wdGlvbnMgJiYgdW5wcm90ZWN0ZWQgaW4gb3B0aW9ucykge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIXRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnNldFVucHJvdGVjdGVkSGVhZGVyKHBhcmFtZXRlcnMpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIgPSB7IC4uLnRoaXMuX3VucHJvdGVjdGVkSGVhZGVyLCAuLi5wYXJhbWV0ZXJzIH07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghdGhpcy5fcHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnNldFByb3RlY3RlZEhlYWRlcihwYXJhbWV0ZXJzKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX3Byb3RlY3RlZEhlYWRlciA9IHsgLi4udGhpcy5fcHJvdGVjdGVkSGVhZGVyLCAuLi5wYXJhbWV0ZXJzIH07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgbGV0IGFkZGl0aW9uYWxEYXRhO1xuICAgICAgICBsZXQgcHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICBsZXQgYWFkTWVtYmVyO1xuICAgICAgICBpZiAodGhpcy5fcHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICBwcm90ZWN0ZWRIZWFkZXIgPSBlbmNvZGVyLmVuY29kZShiYXNlNjR1cmwoSlNPTi5zdHJpbmdpZnkodGhpcy5fcHJvdGVjdGVkSGVhZGVyKSkpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgcHJvdGVjdGVkSGVhZGVyID0gZW5jb2Rlci5lbmNvZGUoJycpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl9hYWQpIHtcbiAgICAgICAgICAgIGFhZE1lbWJlciA9IGJhc2U2NHVybCh0aGlzLl9hYWQpO1xuICAgICAgICAgICAgYWRkaXRpb25hbERhdGEgPSBjb25jYXQocHJvdGVjdGVkSGVhZGVyLCBlbmNvZGVyLmVuY29kZSgnLicpLCBlbmNvZGVyLmVuY29kZShhYWRNZW1iZXIpKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIGFkZGl0aW9uYWxEYXRhID0gcHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHsgY2lwaGVydGV4dCwgdGFnLCBpdiB9ID0gYXdhaXQgZW5jcnlwdChlbmMsIHRoaXMuX3BsYWludGV4dCwgY2VrLCB0aGlzLl9pdiwgYWRkaXRpb25hbERhdGEpO1xuICAgICAgICBjb25zdCBqd2UgPSB7XG4gICAgICAgICAgICBjaXBoZXJ0ZXh0OiBiYXNlNjR1cmwoY2lwaGVydGV4dCksXG4gICAgICAgIH07XG4gICAgICAgIGlmIChpdikge1xuICAgICAgICAgICAgandlLml2ID0gYmFzZTY0dXJsKGl2KTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGFnKSB7XG4gICAgICAgICAgICBqd2UudGFnID0gYmFzZTY0dXJsKHRhZyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGVuY3J5cHRlZEtleSkge1xuICAgICAgICAgICAgandlLmVuY3J5cHRlZF9rZXkgPSBiYXNlNjR1cmwoZW5jcnlwdGVkS2V5KTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoYWFkTWVtYmVyKSB7XG4gICAgICAgICAgICBqd2UuYWFkID0gYWFkTWVtYmVyO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIGp3ZS5wcm90ZWN0ZWQgPSBkZWNvZGVyLmRlY29kZShwcm90ZWN0ZWRIZWFkZXIpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl9zaGFyZWRVbnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgandlLnVucHJvdGVjdGVkID0gdGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICBqd2UuaGVhZGVyID0gdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGp3ZTtcbiAgICB9XG59XG4iLCJpbXBvcnQgeyBGbGF0dGVuZWRFbmNyeXB0LCB1bnByb3RlY3RlZCB9IGZyb20gJy4uL2ZsYXR0ZW5lZC9lbmNyeXB0LmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQsIEpXRUludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgZ2VuZXJhdGVDZWsgZnJvbSAnLi4vLi4vbGliL2Nlay5qcyc7XG5pbXBvcnQgaXNEaXNqb2ludCBmcm9tICcuLi8uLi9saWIvaXNfZGlzam9pbnQuanMnO1xuaW1wb3J0IGVuY3J5cHRLZXlNYW5hZ2VtZW50IGZyb20gJy4uLy4uL2xpYi9lbmNyeXB0X2tleV9tYW5hZ2VtZW50LmpzJztcbmltcG9ydCB7IGVuY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi8uLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgdmFsaWRhdGVDcml0IGZyb20gJy4uLy4uL2xpYi92YWxpZGF0ZV9jcml0LmpzJztcbmNsYXNzIEluZGl2aWR1YWxSZWNpcGllbnQge1xuICAgIGNvbnN0cnVjdG9yKGVuYywga2V5LCBvcHRpb25zKSB7XG4gICAgICAgIHRoaXMucGFyZW50ID0gZW5jO1xuICAgICAgICB0aGlzLmtleSA9IGtleTtcbiAgICAgICAgdGhpcy5vcHRpb25zID0gb3B0aW9ucztcbiAgICB9XG4gICAgc2V0VW5wcm90ZWN0ZWRIZWFkZXIodW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMudW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFVucHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy51bnByb3RlY3RlZEhlYWRlciA9IHVucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgYWRkUmVjaXBpZW50KC4uLmFyZ3MpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGFyZW50LmFkZFJlY2lwaWVudCguLi5hcmdzKTtcbiAgICB9XG4gICAgZW5jcnlwdCguLi5hcmdzKSB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhcmVudC5lbmNyeXB0KC4uLmFyZ3MpO1xuICAgIH1cbiAgICBkb25lKCkge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXJlbnQ7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEdlbmVyYWxFbmNyeXB0IHtcbiAgICBjb25zdHJ1Y3RvcihwbGFpbnRleHQpIHtcbiAgICAgICAgdGhpcy5fcmVjaXBpZW50cyA9IFtdO1xuICAgICAgICB0aGlzLl9wbGFpbnRleHQgPSBwbGFpbnRleHQ7XG4gICAgfVxuICAgIGFkZFJlY2lwaWVudChrZXksIG9wdGlvbnMpIHtcbiAgICAgICAgY29uc3QgcmVjaXBpZW50ID0gbmV3IEluZGl2aWR1YWxSZWNpcGllbnQodGhpcywga2V5LCB7IGNyaXQ6IG9wdGlvbnM/LmNyaXQgfSk7XG4gICAgICAgIHRoaXMuX3JlY2lwaWVudHMucHVzaChyZWNpcGllbnQpO1xuICAgICAgICByZXR1cm4gcmVjaXBpZW50O1xuICAgIH1cbiAgICBzZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3Byb3RlY3RlZEhlYWRlciA9IHByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldFNoYXJlZFVucHJvdGVjdGVkSGVhZGVyKHNoYXJlZFVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLl91bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0U2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl91bnByb3RlY3RlZEhlYWRlciA9IHNoYXJlZFVucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0QWRkaXRpb25hbEF1dGhlbnRpY2F0ZWREYXRhKGFhZCkge1xuICAgICAgICB0aGlzLl9hYWQgPSBhYWQ7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBhc3luYyBlbmNyeXB0KCkge1xuICAgICAgICBpZiAoIXRoaXMuX3JlY2lwaWVudHMubGVuZ3RoKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnYXQgbGVhc3Qgb25lIHJlY2lwaWVudCBtdXN0IGJlIGFkZGVkJyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX3JlY2lwaWVudHMubGVuZ3RoID09PSAxKSB7XG4gICAgICAgICAgICBjb25zdCBbcmVjaXBpZW50XSA9IHRoaXMuX3JlY2lwaWVudHM7XG4gICAgICAgICAgICBjb25zdCBmbGF0dGVuZWQgPSBhd2FpdCBuZXcgRmxhdHRlbmVkRW5jcnlwdCh0aGlzLl9wbGFpbnRleHQpXG4gICAgICAgICAgICAgICAgLnNldEFkZGl0aW9uYWxBdXRoZW50aWNhdGVkRGF0YSh0aGlzLl9hYWQpXG4gICAgICAgICAgICAgICAgLnNldFByb3RlY3RlZEhlYWRlcih0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpXG4gICAgICAgICAgICAgICAgLnNldFNoYXJlZFVucHJvdGVjdGVkSGVhZGVyKHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKVxuICAgICAgICAgICAgICAgIC5zZXRVbnByb3RlY3RlZEhlYWRlcihyZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXIpXG4gICAgICAgICAgICAgICAgLmVuY3J5cHQocmVjaXBpZW50LmtleSwgeyAuLi5yZWNpcGllbnQub3B0aW9ucyB9KTtcbiAgICAgICAgICAgIGNvbnN0IGp3ZSA9IHtcbiAgICAgICAgICAgICAgICBjaXBoZXJ0ZXh0OiBmbGF0dGVuZWQuY2lwaGVydGV4dCxcbiAgICAgICAgICAgICAgICBpdjogZmxhdHRlbmVkLml2LFxuICAgICAgICAgICAgICAgIHJlY2lwaWVudHM6IFt7fV0sXG4gICAgICAgICAgICAgICAgdGFnOiBmbGF0dGVuZWQudGFnLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIGlmIChmbGF0dGVuZWQuYWFkKVxuICAgICAgICAgICAgICAgIGp3ZS5hYWQgPSBmbGF0dGVuZWQuYWFkO1xuICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC5wcm90ZWN0ZWQpXG4gICAgICAgICAgICAgICAgandlLnByb3RlY3RlZCA9IGZsYXR0ZW5lZC5wcm90ZWN0ZWQ7XG4gICAgICAgICAgICBpZiAoZmxhdHRlbmVkLnVucHJvdGVjdGVkKVxuICAgICAgICAgICAgICAgIGp3ZS51bnByb3RlY3RlZCA9IGZsYXR0ZW5lZC51bnByb3RlY3RlZDtcbiAgICAgICAgICAgIGlmIChmbGF0dGVuZWQuZW5jcnlwdGVkX2tleSlcbiAgICAgICAgICAgICAgICBqd2UucmVjaXBpZW50c1swXS5lbmNyeXB0ZWRfa2V5ID0gZmxhdHRlbmVkLmVuY3J5cHRlZF9rZXk7XG4gICAgICAgICAgICBpZiAoZmxhdHRlbmVkLmhlYWRlcilcbiAgICAgICAgICAgICAgICBqd2UucmVjaXBpZW50c1swXS5oZWFkZXIgPSBmbGF0dGVuZWQuaGVhZGVyO1xuICAgICAgICAgICAgcmV0dXJuIGp3ZTtcbiAgICAgICAgfVxuICAgICAgICBsZXQgZW5jO1xuICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHRoaXMuX3JlY2lwaWVudHMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIGNvbnN0IHJlY2lwaWVudCA9IHRoaXMuX3JlY2lwaWVudHNbaV07XG4gICAgICAgICAgICBpZiAoIWlzRGlzam9pbnQodGhpcy5fcHJvdGVjdGVkSGVhZGVyLCB0aGlzLl91bnByb3RlY3RlZEhlYWRlciwgcmVjaXBpZW50LnVucHJvdGVjdGVkSGVhZGVyKSkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgUHJvdGVjdGVkLCBKV0UgU2hhcmVkIFVucHJvdGVjdGVkIGFuZCBKV0UgUGVyLVJlY2lwaWVudCBIZWFkZXIgUGFyYW1ldGVyIG5hbWVzIG11c3QgYmUgZGlzam9pbnQnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNvbnN0IGpvc2VIZWFkZXIgPSB7XG4gICAgICAgICAgICAgICAgLi4udGhpcy5fcHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgICAgIC4uLnRoaXMuX3VucHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgICAgIC4uLnJlY2lwaWVudC51bnByb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgIH07XG4gICAgICAgICAgICBjb25zdCB7IGFsZyB9ID0gam9zZUhlYWRlcjtcbiAgICAgICAgICAgIGlmICh0eXBlb2YgYWxnICE9PSAnc3RyaW5nJyB8fCAhYWxnKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBcImFsZ1wiIChBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgbWlzc2luZyBvciBpbnZhbGlkJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAoYWxnID09PSAnZGlyJyB8fCBhbGcgPT09ICdFQ0RILUVTJykge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdcImRpclwiIGFuZCBcIkVDREgtRVNcIiBhbGcgbWF5IG9ubHkgYmUgdXNlZCB3aXRoIGEgc2luZ2xlIHJlY2lwaWVudCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKHR5cGVvZiBqb3NlSGVhZGVyLmVuYyAhPT0gJ3N0cmluZycgfHwgIWpvc2VIZWFkZXIuZW5jKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBcImVuY1wiIChFbmNyeXB0aW9uIEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBtaXNzaW5nIG9yIGludmFsaWQnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmICghZW5jKSB7XG4gICAgICAgICAgICAgICAgZW5jID0gam9zZUhlYWRlci5lbmM7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIGlmIChlbmMgIT09IGpvc2VIZWFkZXIuZW5jKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBcImVuY1wiIChFbmNyeXB0aW9uIEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBtdXN0IGJlIHRoZSBzYW1lIGZvciBhbGwgcmVjaXBpZW50cycpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgdmFsaWRhdGVDcml0KEpXRUludmFsaWQsIG5ldyBNYXAoKSwgcmVjaXBpZW50Lm9wdGlvbnMuY3JpdCwgdGhpcy5fcHJvdGVjdGVkSGVhZGVyLCBqb3NlSGVhZGVyKTtcbiAgICAgICAgICAgIGlmIChqb3NlSGVhZGVyLnppcCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0pXRSBcInppcFwiIChDb21wcmVzc2lvbiBBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgaXMgbm90IHN1cHBvcnRlZC4nKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBjb25zdCBjZWsgPSBnZW5lcmF0ZUNlayhlbmMpO1xuICAgICAgICBjb25zdCBqd2UgPSB7XG4gICAgICAgICAgICBjaXBoZXJ0ZXh0OiAnJyxcbiAgICAgICAgICAgIGl2OiAnJyxcbiAgICAgICAgICAgIHJlY2lwaWVudHM6IFtdLFxuICAgICAgICAgICAgdGFnOiAnJyxcbiAgICAgICAgfTtcbiAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCB0aGlzLl9yZWNpcGllbnRzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBjb25zdCByZWNpcGllbnQgPSB0aGlzLl9yZWNpcGllbnRzW2ldO1xuICAgICAgICAgICAgY29uc3QgdGFyZ2V0ID0ge307XG4gICAgICAgICAgICBqd2UucmVjaXBpZW50cy5wdXNoKHRhcmdldCk7XG4gICAgICAgICAgICBjb25zdCBqb3NlSGVhZGVyID0ge1xuICAgICAgICAgICAgICAgIC4uLnRoaXMuX3Byb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgICAgICAuLi50aGlzLl91bnByb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgICAgICAuLi5yZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAgY29uc3QgcDJjID0gam9zZUhlYWRlci5hbGcuc3RhcnRzV2l0aCgnUEJFUzInKSA/IDIwNDggKyBpIDogdW5kZWZpbmVkO1xuICAgICAgICAgICAgaWYgKGkgPT09IDApIHtcbiAgICAgICAgICAgICAgICBjb25zdCBmbGF0dGVuZWQgPSBhd2FpdCBuZXcgRmxhdHRlbmVkRW5jcnlwdCh0aGlzLl9wbGFpbnRleHQpXG4gICAgICAgICAgICAgICAgICAgIC5zZXRBZGRpdGlvbmFsQXV0aGVudGljYXRlZERhdGEodGhpcy5fYWFkKVxuICAgICAgICAgICAgICAgICAgICAuc2V0Q29udGVudEVuY3J5cHRpb25LZXkoY2VrKVxuICAgICAgICAgICAgICAgICAgICAuc2V0UHJvdGVjdGVkSGVhZGVyKHRoaXMuX3Byb3RlY3RlZEhlYWRlcilcbiAgICAgICAgICAgICAgICAgICAgLnNldFNoYXJlZFVucHJvdGVjdGVkSGVhZGVyKHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKVxuICAgICAgICAgICAgICAgICAgICAuc2V0VW5wcm90ZWN0ZWRIZWFkZXIocmVjaXBpZW50LnVucHJvdGVjdGVkSGVhZGVyKVxuICAgICAgICAgICAgICAgICAgICAuc2V0S2V5TWFuYWdlbWVudFBhcmFtZXRlcnMoeyBwMmMgfSlcbiAgICAgICAgICAgICAgICAgICAgLmVuY3J5cHQocmVjaXBpZW50LmtleSwge1xuICAgICAgICAgICAgICAgICAgICAuLi5yZWNpcGllbnQub3B0aW9ucyxcbiAgICAgICAgICAgICAgICAgICAgW3VucHJvdGVjdGVkXTogdHJ1ZSxcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICBqd2UuY2lwaGVydGV4dCA9IGZsYXR0ZW5lZC5jaXBoZXJ0ZXh0O1xuICAgICAgICAgICAgICAgIGp3ZS5pdiA9IGZsYXR0ZW5lZC5pdjtcbiAgICAgICAgICAgICAgICBqd2UudGFnID0gZmxhdHRlbmVkLnRhZztcbiAgICAgICAgICAgICAgICBpZiAoZmxhdHRlbmVkLmFhZClcbiAgICAgICAgICAgICAgICAgICAgandlLmFhZCA9IGZsYXR0ZW5lZC5hYWQ7XG4gICAgICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC5wcm90ZWN0ZWQpXG4gICAgICAgICAgICAgICAgICAgIGp3ZS5wcm90ZWN0ZWQgPSBmbGF0dGVuZWQucHJvdGVjdGVkO1xuICAgICAgICAgICAgICAgIGlmIChmbGF0dGVuZWQudW5wcm90ZWN0ZWQpXG4gICAgICAgICAgICAgICAgICAgIGp3ZS51bnByb3RlY3RlZCA9IGZsYXR0ZW5lZC51bnByb3RlY3RlZDtcbiAgICAgICAgICAgICAgICB0YXJnZXQuZW5jcnlwdGVkX2tleSA9IGZsYXR0ZW5lZC5lbmNyeXB0ZWRfa2V5O1xuICAgICAgICAgICAgICAgIGlmIChmbGF0dGVuZWQuaGVhZGVyKVxuICAgICAgICAgICAgICAgICAgICB0YXJnZXQuaGVhZGVyID0gZmxhdHRlbmVkLmhlYWRlcjtcbiAgICAgICAgICAgICAgICBjb250aW51ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNvbnN0IHsgZW5jcnlwdGVkS2V5LCBwYXJhbWV0ZXJzIH0gPSBhd2FpdCBlbmNyeXB0S2V5TWFuYWdlbWVudChyZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXI/LmFsZyB8fFxuICAgICAgICAgICAgICAgIHRoaXMuX3Byb3RlY3RlZEhlYWRlcj8uYWxnIHx8XG4gICAgICAgICAgICAgICAgdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXI/LmFsZywgZW5jLCByZWNpcGllbnQua2V5LCBjZWssIHsgcDJjIH0pO1xuICAgICAgICAgICAgdGFyZ2V0LmVuY3J5cHRlZF9rZXkgPSBiYXNlNjR1cmwoZW5jcnlwdGVkS2V5KTtcbiAgICAgICAgICAgIGlmIChyZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXIgfHwgcGFyYW1ldGVycylcbiAgICAgICAgICAgICAgICB0YXJnZXQuaGVhZGVyID0geyAuLi5yZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXIsIC4uLnBhcmFtZXRlcnMgfTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gandlO1xuICAgIH1cbn1cbiIsImltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBzdWJ0bGVEc2EoYWxnLCBhbGdvcml0aG0pIHtcbiAgICBjb25zdCBoYXNoID0gYFNIQS0ke2FsZy5zbGljZSgtMyl9YDtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdIUzI1Nic6XG4gICAgICAgIGNhc2UgJ0hTMzg0JzpcbiAgICAgICAgY2FzZSAnSFM1MTInOlxuICAgICAgICAgICAgcmV0dXJuIHsgaGFzaCwgbmFtZTogJ0hNQUMnIH07XG4gICAgICAgIGNhc2UgJ1BTMjU2JzpcbiAgICAgICAgY2FzZSAnUFMzODQnOlxuICAgICAgICBjYXNlICdQUzUxMic6XG4gICAgICAgICAgICByZXR1cm4geyBoYXNoLCBuYW1lOiAnUlNBLVBTUycsIHNhbHRMZW5ndGg6IGFsZy5zbGljZSgtMykgPj4gMyB9O1xuICAgICAgICBjYXNlICdSUzI1Nic6XG4gICAgICAgIGNhc2UgJ1JTMzg0JzpcbiAgICAgICAgY2FzZSAnUlM1MTInOlxuICAgICAgICAgICAgcmV0dXJuIHsgaGFzaCwgbmFtZTogJ1JTQVNTQS1QS0NTMS12MV81JyB9O1xuICAgICAgICBjYXNlICdFUzI1Nic6XG4gICAgICAgIGNhc2UgJ0VTMzg0JzpcbiAgICAgICAgY2FzZSAnRVM1MTInOlxuICAgICAgICAgICAgcmV0dXJuIHsgaGFzaCwgbmFtZTogJ0VDRFNBJywgbmFtZWRDdXJ2ZTogYWxnb3JpdGhtLm5hbWVkQ3VydmUgfTtcbiAgICAgICAgY2FzZSAnRWREU0EnOlxuICAgICAgICAgICAgcmV0dXJuIHsgbmFtZTogYWxnb3JpdGhtLm5hbWUgfTtcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKGBhbGcgJHthbGd9IGlzIG5vdCBzdXBwb3J0ZWQgZWl0aGVyIGJ5IEpPU0Ugb3IgeW91ciBqYXZhc2NyaXB0IHJ1bnRpbWVgKTtcbiAgICB9XG59XG4iLCJpbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tTaWdDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gZ2V0Q3J5cHRvS2V5KGFsZywga2V5LCB1c2FnZSkge1xuICAgIGlmIChpc0NyeXB0b0tleShrZXkpKSB7XG4gICAgICAgIGNoZWNrU2lnQ3J5cHRvS2V5KGtleSwgYWxnLCB1c2FnZSk7XG4gICAgICAgIHJldHVybiBrZXk7XG4gICAgfVxuICAgIGlmIChrZXkgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIGlmICghYWxnLnN0YXJ0c1dpdGgoJ0hTJykpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMpKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGtleSwgeyBoYXNoOiBgU0hBLSR7YWxnLnNsaWNlKC0zKX1gLCBuYW1lOiAnSE1BQycgfSwgZmFsc2UsIFt1c2FnZV0pO1xuICAgIH1cbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzLCAnVWludDhBcnJheScpKTtcbn1cbiIsImltcG9ydCBzdWJ0bGVBbGdvcml0aG0gZnJvbSAnLi9zdWJ0bGVfZHNhLmpzJztcbmltcG9ydCBjcnlwdG8gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IGNoZWNrS2V5TGVuZ3RoIGZyb20gJy4vY2hlY2tfa2V5X2xlbmd0aC5qcyc7XG5pbXBvcnQgZ2V0VmVyaWZ5S2V5IGZyb20gJy4vZ2V0X3NpZ25fdmVyaWZ5X2tleS5qcyc7XG5jb25zdCB2ZXJpZnkgPSBhc3luYyAoYWxnLCBrZXksIHNpZ25hdHVyZSwgZGF0YSkgPT4ge1xuICAgIGNvbnN0IGNyeXB0b0tleSA9IGF3YWl0IGdldFZlcmlmeUtleShhbGcsIGtleSwgJ3ZlcmlmeScpO1xuICAgIGNoZWNrS2V5TGVuZ3RoKGFsZywgY3J5cHRvS2V5KTtcbiAgICBjb25zdCBhbGdvcml0aG0gPSBzdWJ0bGVBbGdvcml0aG0oYWxnLCBjcnlwdG9LZXkuYWxnb3JpdGhtKTtcbiAgICB0cnkge1xuICAgICAgICByZXR1cm4gYXdhaXQgY3J5cHRvLnN1YnRsZS52ZXJpZnkoYWxnb3JpdGhtLCBjcnlwdG9LZXksIHNpZ25hdHVyZSwgZGF0YSk7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbn07XG5leHBvcnQgZGVmYXVsdCB2ZXJpZnk7XG4iLCJpbXBvcnQgeyBkZWNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi4vLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHZlcmlmeSBmcm9tICcuLi8uLi9ydW50aW1lL3ZlcmlmeS5qcyc7XG5pbXBvcnQgeyBKT1NFQWxnTm90QWxsb3dlZCwgSldTSW52YWxpZCwgSldTU2lnbmF0dXJlVmVyaWZpY2F0aW9uRmFpbGVkIH0gZnJvbSAnLi4vLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHsgY29uY2F0LCBlbmNvZGVyLCBkZWNvZGVyIH0gZnJvbSAnLi4vLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgaXNEaXNqb2ludCBmcm9tICcuLi8uLi9saWIvaXNfZGlzam9pbnQuanMnO1xuaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4uLy4uL2xpYi9pc19vYmplY3QuanMnO1xuaW1wb3J0IGNoZWNrS2V5VHlwZSBmcm9tICcuLi8uLi9saWIvY2hlY2tfa2V5X3R5cGUuanMnO1xuaW1wb3J0IHZhbGlkYXRlQ3JpdCBmcm9tICcuLi8uLi9saWIvdmFsaWRhdGVfY3JpdC5qcyc7XG5pbXBvcnQgdmFsaWRhdGVBbGdvcml0aG1zIGZyb20gJy4uLy4uL2xpYi92YWxpZGF0ZV9hbGdvcml0aG1zLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBmbGF0dGVuZWRWZXJpZnkoandzLCBrZXksIG9wdGlvbnMpIHtcbiAgICBpZiAoIWlzT2JqZWN0KGp3cykpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0ZsYXR0ZW5lZCBKV1MgbXVzdCBiZSBhbiBvYmplY3QnKTtcbiAgICB9XG4gICAgaWYgKGp3cy5wcm90ZWN0ZWQgPT09IHVuZGVmaW5lZCAmJiBqd3MuaGVhZGVyID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0ZsYXR0ZW5lZCBKV1MgbXVzdCBoYXZlIGVpdGhlciBvZiB0aGUgXCJwcm90ZWN0ZWRcIiBvciBcImhlYWRlclwiIG1lbWJlcnMnKTtcbiAgICB9XG4gICAgaWYgKGp3cy5wcm90ZWN0ZWQgIT09IHVuZGVmaW5lZCAmJiB0eXBlb2YgandzLnByb3RlY3RlZCAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBQcm90ZWN0ZWQgSGVhZGVyIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmIChqd3MucGF5bG9hZCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgUGF5bG9hZCBtaXNzaW5nJyk7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgandzLnNpZ25hdHVyZSAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBTaWduYXR1cmUgbWlzc2luZyBvciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoandzLmhlYWRlciAhPT0gdW5kZWZpbmVkICYmICFpc09iamVjdChqd3MuaGVhZGVyKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFVucHJvdGVjdGVkIEhlYWRlciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBsZXQgcGFyc2VkUHJvdCA9IHt9O1xuICAgIGlmIChqd3MucHJvdGVjdGVkKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBjb25zdCBwcm90ZWN0ZWRIZWFkZXIgPSBiYXNlNjR1cmwoandzLnByb3RlY3RlZCk7XG4gICAgICAgICAgICBwYXJzZWRQcm90ID0gSlNPTi5wYXJzZShkZWNvZGVyLmRlY29kZShwcm90ZWN0ZWRIZWFkZXIpKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFByb3RlY3RlZCBIZWFkZXIgaXMgaW52YWxpZCcpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGlmICghaXNEaXNqb2ludChwYXJzZWRQcm90LCBqd3MuaGVhZGVyKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFByb3RlY3RlZCBhbmQgSldTIFVucHJvdGVjdGVkIEhlYWRlciBQYXJhbWV0ZXIgbmFtZXMgbXVzdCBiZSBkaXNqb2ludCcpO1xuICAgIH1cbiAgICBjb25zdCBqb3NlSGVhZGVyID0ge1xuICAgICAgICAuLi5wYXJzZWRQcm90LFxuICAgICAgICAuLi5qd3MuaGVhZGVyLFxuICAgIH07XG4gICAgY29uc3QgZXh0ZW5zaW9ucyA9IHZhbGlkYXRlQ3JpdChKV1NJbnZhbGlkLCBuZXcgTWFwKFtbJ2I2NCcsIHRydWVdXSksIG9wdGlvbnM/LmNyaXQsIHBhcnNlZFByb3QsIGpvc2VIZWFkZXIpO1xuICAgIGxldCBiNjQgPSB0cnVlO1xuICAgIGlmIChleHRlbnNpb25zLmhhcygnYjY0JykpIHtcbiAgICAgICAgYjY0ID0gcGFyc2VkUHJvdC5iNjQ7XG4gICAgICAgIGlmICh0eXBlb2YgYjY0ICE9PSAnYm9vbGVhbicpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdUaGUgXCJiNjRcIiAoYmFzZTY0dXJsLWVuY29kZSBwYXlsb2FkKSBIZWFkZXIgUGFyYW1ldGVyIG11c3QgYmUgYSBib29sZWFuJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgY29uc3QgeyBhbGcgfSA9IGpvc2VIZWFkZXI7XG4gICAgaWYgKHR5cGVvZiBhbGcgIT09ICdzdHJpbmcnIHx8ICFhbGcpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBcImFsZ1wiIChBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgbWlzc2luZyBvciBpbnZhbGlkJyk7XG4gICAgfVxuICAgIGNvbnN0IGFsZ29yaXRobXMgPSBvcHRpb25zICYmIHZhbGlkYXRlQWxnb3JpdGhtcygnYWxnb3JpdGhtcycsIG9wdGlvbnMuYWxnb3JpdGhtcyk7XG4gICAgaWYgKGFsZ29yaXRobXMgJiYgIWFsZ29yaXRobXMuaGFzKGFsZykpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpPU0VBbGdOb3RBbGxvd2VkKCdcImFsZ1wiIChBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgdmFsdWUgbm90IGFsbG93ZWQnKTtcbiAgICB9XG4gICAgaWYgKGI2NCkge1xuICAgICAgICBpZiAodHlwZW9mIGp3cy5wYXlsb2FkICE9PSAnc3RyaW5nJykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBQYXlsb2FkIG11c3QgYmUgYSBzdHJpbmcnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBlbHNlIGlmICh0eXBlb2YgandzLnBheWxvYWQgIT09ICdzdHJpbmcnICYmICEoandzLnBheWxvYWQgaW5zdGFuY2VvZiBVaW50OEFycmF5KSkge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFBheWxvYWQgbXVzdCBiZSBhIHN0cmluZyBvciBhbiBVaW50OEFycmF5IGluc3RhbmNlJyk7XG4gICAgfVxuICAgIGxldCByZXNvbHZlZEtleSA9IGZhbHNlO1xuICAgIGlmICh0eXBlb2Yga2V5ID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgIGtleSA9IGF3YWl0IGtleShwYXJzZWRQcm90LCBqd3MpO1xuICAgICAgICByZXNvbHZlZEtleSA9IHRydWU7XG4gICAgfVxuICAgIGNoZWNrS2V5VHlwZShhbGcsIGtleSwgJ3ZlcmlmeScpO1xuICAgIGNvbnN0IGRhdGEgPSBjb25jYXQoZW5jb2Rlci5lbmNvZGUoandzLnByb3RlY3RlZCA/PyAnJyksIGVuY29kZXIuZW5jb2RlKCcuJyksIHR5cGVvZiBqd3MucGF5bG9hZCA9PT0gJ3N0cmluZycgPyBlbmNvZGVyLmVuY29kZShqd3MucGF5bG9hZCkgOiBqd3MucGF5bG9hZCk7XG4gICAgbGV0IHNpZ25hdHVyZTtcbiAgICB0cnkge1xuICAgICAgICBzaWduYXR1cmUgPSBiYXNlNjR1cmwoandzLnNpZ25hdHVyZSk7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBzaWduYXR1cmUnKTtcbiAgICB9XG4gICAgY29uc3QgdmVyaWZpZWQgPSBhd2FpdCB2ZXJpZnkoYWxnLCBrZXksIHNpZ25hdHVyZSwgZGF0YSk7XG4gICAgaWYgKCF2ZXJpZmllZCkge1xuICAgICAgICB0aHJvdyBuZXcgSldTU2lnbmF0dXJlVmVyaWZpY2F0aW9uRmFpbGVkKCk7XG4gICAgfVxuICAgIGxldCBwYXlsb2FkO1xuICAgIGlmIChiNjQpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHBheWxvYWQgPSBiYXNlNjR1cmwoandzLnBheWxvYWQpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgcGF5bG9hZCcpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGVsc2UgaWYgKHR5cGVvZiBqd3MucGF5bG9hZCA9PT0gJ3N0cmluZycpIHtcbiAgICAgICAgcGF5bG9hZCA9IGVuY29kZXIuZW5jb2RlKGp3cy5wYXlsb2FkKTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIHBheWxvYWQgPSBqd3MucGF5bG9hZDtcbiAgICB9XG4gICAgY29uc3QgcmVzdWx0ID0geyBwYXlsb2FkIH07XG4gICAgaWYgKGp3cy5wcm90ZWN0ZWQgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICByZXN1bHQucHJvdGVjdGVkSGVhZGVyID0gcGFyc2VkUHJvdDtcbiAgICB9XG4gICAgaWYgKGp3cy5oZWFkZXIgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICByZXN1bHQudW5wcm90ZWN0ZWRIZWFkZXIgPSBqd3MuaGVhZGVyO1xuICAgIH1cbiAgICBpZiAocmVzb2x2ZWRLZXkpIHtcbiAgICAgICAgcmV0dXJuIHsgLi4ucmVzdWx0LCBrZXkgfTtcbiAgICB9XG4gICAgcmV0dXJuIHJlc3VsdDtcbn1cbiIsImltcG9ydCB7IGZsYXR0ZW5lZFZlcmlmeSB9IGZyb20gJy4uL2ZsYXR0ZW5lZC92ZXJpZnkuanMnO1xuaW1wb3J0IHsgSldTSW52YWxpZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IGRlY29kZXIgfSBmcm9tICcuLi8uLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjb21wYWN0VmVyaWZ5KGp3cywga2V5LCBvcHRpb25zKSB7XG4gICAgaWYgKGp3cyBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgandzID0gZGVjb2Rlci5kZWNvZGUoandzKTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBqd3MgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdDb21wYWN0IEpXUyBtdXN0IGJlIGEgc3RyaW5nIG9yIFVpbnQ4QXJyYXknKTtcbiAgICB9XG4gICAgY29uc3QgeyAwOiBwcm90ZWN0ZWRIZWFkZXIsIDE6IHBheWxvYWQsIDI6IHNpZ25hdHVyZSwgbGVuZ3RoIH0gPSBqd3Muc3BsaXQoJy4nKTtcbiAgICBpZiAobGVuZ3RoICE9PSAzKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdJbnZhbGlkIENvbXBhY3QgSldTJyk7XG4gICAgfVxuICAgIGNvbnN0IHZlcmlmaWVkID0gYXdhaXQgZmxhdHRlbmVkVmVyaWZ5KHsgcGF5bG9hZCwgcHJvdGVjdGVkOiBwcm90ZWN0ZWRIZWFkZXIsIHNpZ25hdHVyZSB9LCBrZXksIG9wdGlvbnMpO1xuICAgIGNvbnN0IHJlc3VsdCA9IHsgcGF5bG9hZDogdmVyaWZpZWQucGF5bG9hZCwgcHJvdGVjdGVkSGVhZGVyOiB2ZXJpZmllZC5wcm90ZWN0ZWRIZWFkZXIgfTtcbiAgICBpZiAodHlwZW9mIGtleSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICByZXR1cm4geyAuLi5yZXN1bHQsIGtleTogdmVyaWZpZWQua2V5IH07XG4gICAgfVxuICAgIHJldHVybiByZXN1bHQ7XG59XG4iLCJpbXBvcnQgeyBmbGF0dGVuZWRWZXJpZnkgfSBmcm9tICcuLi9mbGF0dGVuZWQvdmVyaWZ5LmpzJztcbmltcG9ydCB7IEpXU0ludmFsaWQsIEpXU1NpZ25hdHVyZVZlcmlmaWNhdGlvbkZhaWxlZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCBpc09iamVjdCBmcm9tICcuLi8uLi9saWIvaXNfb2JqZWN0LmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmFsVmVyaWZ5KGp3cywga2V5LCBvcHRpb25zKSB7XG4gICAgaWYgKCFpc09iamVjdChqd3MpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdHZW5lcmFsIEpXUyBtdXN0IGJlIGFuIG9iamVjdCcpO1xuICAgIH1cbiAgICBpZiAoIUFycmF5LmlzQXJyYXkoandzLnNpZ25hdHVyZXMpIHx8ICFqd3Muc2lnbmF0dXJlcy5ldmVyeShpc09iamVjdCkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBTaWduYXR1cmVzIG1pc3Npbmcgb3IgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgZm9yIChjb25zdCBzaWduYXR1cmUgb2YgandzLnNpZ25hdHVyZXMpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHJldHVybiBhd2FpdCBmbGF0dGVuZWRWZXJpZnkoe1xuICAgICAgICAgICAgICAgIGhlYWRlcjogc2lnbmF0dXJlLmhlYWRlcixcbiAgICAgICAgICAgICAgICBwYXlsb2FkOiBqd3MucGF5bG9hZCxcbiAgICAgICAgICAgICAgICBwcm90ZWN0ZWQ6IHNpZ25hdHVyZS5wcm90ZWN0ZWQsXG4gICAgICAgICAgICAgICAgc2lnbmF0dXJlOiBzaWduYXR1cmUuc2lnbmF0dXJlLFxuICAgICAgICAgICAgfSwga2V5LCBvcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgIH1cbiAgICB9XG4gICAgdGhyb3cgbmV3IEpXU1NpZ25hdHVyZVZlcmlmaWNhdGlvbkZhaWxlZCgpO1xufVxuIiwiaW1wb3J0IHsgRmxhdHRlbmVkRW5jcnlwdCB9IGZyb20gJy4uL2ZsYXR0ZW5lZC9lbmNyeXB0LmpzJztcbmV4cG9ydCBjbGFzcyBDb21wYWN0RW5jcnlwdCB7XG4gICAgY29uc3RydWN0b3IocGxhaW50ZXh0KSB7XG4gICAgICAgIHRoaXMuX2ZsYXR0ZW5lZCA9IG5ldyBGbGF0dGVuZWRFbmNyeXB0KHBsYWludGV4dCk7XG4gICAgfVxuICAgIHNldENvbnRlbnRFbmNyeXB0aW9uS2V5KGNlaykge1xuICAgICAgICB0aGlzLl9mbGF0dGVuZWQuc2V0Q29udGVudEVuY3J5cHRpb25LZXkoY2VrKTtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldEluaXRpYWxpemF0aW9uVmVjdG9yKGl2KSB7XG4gICAgICAgIHRoaXMuX2ZsYXR0ZW5lZC5zZXRJbml0aWFsaXphdGlvblZlY3Rvcihpdik7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIHRoaXMuX2ZsYXR0ZW5lZC5zZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKTtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldEtleU1hbmFnZW1lbnRQYXJhbWV0ZXJzKHBhcmFtZXRlcnMpIHtcbiAgICAgICAgdGhpcy5fZmxhdHRlbmVkLnNldEtleU1hbmFnZW1lbnRQYXJhbWV0ZXJzKHBhcmFtZXRlcnMpO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgYXN5bmMgZW5jcnlwdChrZXksIG9wdGlvbnMpIHtcbiAgICAgICAgY29uc3QgandlID0gYXdhaXQgdGhpcy5fZmxhdHRlbmVkLmVuY3J5cHQoa2V5LCBvcHRpb25zKTtcbiAgICAgICAgcmV0dXJuIFtqd2UucHJvdGVjdGVkLCBqd2UuZW5jcnlwdGVkX2tleSwgandlLml2LCBqd2UuY2lwaGVydGV4dCwgandlLnRhZ10uam9pbignLicpO1xuICAgIH1cbn1cbiIsImltcG9ydCBzdWJ0bGVBbGdvcml0aG0gZnJvbSAnLi9zdWJ0bGVfZHNhLmpzJztcbmltcG9ydCBjcnlwdG8gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IGNoZWNrS2V5TGVuZ3RoIGZyb20gJy4vY2hlY2tfa2V5X2xlbmd0aC5qcyc7XG5pbXBvcnQgZ2V0U2lnbktleSBmcm9tICcuL2dldF9zaWduX3ZlcmlmeV9rZXkuanMnO1xuY29uc3Qgc2lnbiA9IGFzeW5jIChhbGcsIGtleSwgZGF0YSkgPT4ge1xuICAgIGNvbnN0IGNyeXB0b0tleSA9IGF3YWl0IGdldFNpZ25LZXkoYWxnLCBrZXksICdzaWduJyk7XG4gICAgY2hlY2tLZXlMZW5ndGgoYWxnLCBjcnlwdG9LZXkpO1xuICAgIGNvbnN0IHNpZ25hdHVyZSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuc2lnbihzdWJ0bGVBbGdvcml0aG0oYWxnLCBjcnlwdG9LZXkuYWxnb3JpdGhtKSwgY3J5cHRvS2V5LCBkYXRhKTtcbiAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoc2lnbmF0dXJlKTtcbn07XG5leHBvcnQgZGVmYXVsdCBzaWduO1xuIiwiaW1wb3J0IHsgZW5jb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4uLy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmltcG9ydCBzaWduIGZyb20gJy4uLy4uL3J1bnRpbWUvc2lnbi5qcyc7XG5pbXBvcnQgaXNEaXNqb2ludCBmcm9tICcuLi8uLi9saWIvaXNfZGlzam9pbnQuanMnO1xuaW1wb3J0IHsgSldTSW52YWxpZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IGVuY29kZXIsIGRlY29kZXIsIGNvbmNhdCB9IGZyb20gJy4uLy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IGNoZWNrS2V5VHlwZSBmcm9tICcuLi8uLi9saWIvY2hlY2tfa2V5X3R5cGUuanMnO1xuaW1wb3J0IHZhbGlkYXRlQ3JpdCBmcm9tICcuLi8uLi9saWIvdmFsaWRhdGVfY3JpdC5qcyc7XG5leHBvcnQgY2xhc3MgRmxhdHRlbmVkU2lnbiB7XG4gICAgY29uc3RydWN0b3IocGF5bG9hZCkge1xuICAgICAgICBpZiAoIShwYXlsb2FkIGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3BheWxvYWQgbXVzdCBiZSBhbiBpbnN0YW5jZSBvZiBVaW50OEFycmF5Jyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fcGF5bG9hZCA9IHBheWxvYWQ7XG4gICAgfVxuICAgIHNldFByb3RlY3RlZEhlYWRlcihwcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMuX3Byb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0UHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fcHJvdGVjdGVkSGVhZGVyID0gcHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0VW5wcm90ZWN0ZWRIZWFkZXIodW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRVbnByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyID0gdW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBhc3luYyBzaWduKGtleSwgb3B0aW9ucykge1xuICAgICAgICBpZiAoIXRoaXMuX3Byb3RlY3RlZEhlYWRlciAmJiAhdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdlaXRoZXIgc2V0UHJvdGVjdGVkSGVhZGVyIG9yIHNldFVucHJvdGVjdGVkSGVhZGVyIG11c3QgYmUgY2FsbGVkIGJlZm9yZSAjc2lnbigpJyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCFpc0Rpc2pvaW50KHRoaXMuX3Byb3RlY3RlZEhlYWRlciwgdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFByb3RlY3RlZCBhbmQgSldTIFVucHJvdGVjdGVkIEhlYWRlciBQYXJhbWV0ZXIgbmFtZXMgbXVzdCBiZSBkaXNqb2ludCcpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IGpvc2VIZWFkZXIgPSB7XG4gICAgICAgICAgICAuLi50aGlzLl9wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICAuLi50aGlzLl91bnByb3RlY3RlZEhlYWRlcixcbiAgICAgICAgfTtcbiAgICAgICAgY29uc3QgZXh0ZW5zaW9ucyA9IHZhbGlkYXRlQ3JpdChKV1NJbnZhbGlkLCBuZXcgTWFwKFtbJ2I2NCcsIHRydWVdXSksIG9wdGlvbnM/LmNyaXQsIHRoaXMuX3Byb3RlY3RlZEhlYWRlciwgam9zZUhlYWRlcik7XG4gICAgICAgIGxldCBiNjQgPSB0cnVlO1xuICAgICAgICBpZiAoZXh0ZW5zaW9ucy5oYXMoJ2I2NCcpKSB7XG4gICAgICAgICAgICBiNjQgPSB0aGlzLl9wcm90ZWN0ZWRIZWFkZXIuYjY0O1xuICAgICAgICAgICAgaWYgKHR5cGVvZiBiNjQgIT09ICdib29sZWFuJykge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdUaGUgXCJiNjRcIiAoYmFzZTY0dXJsLWVuY29kZSBwYXlsb2FkKSBIZWFkZXIgUGFyYW1ldGVyIG11c3QgYmUgYSBib29sZWFuJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgeyBhbGcgfSA9IGpvc2VIZWFkZXI7XG4gICAgICAgIGlmICh0eXBlb2YgYWxnICE9PSAnc3RyaW5nJyB8fCAhYWxnKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFwiYWxnXCIgKEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBtaXNzaW5nIG9yIGludmFsaWQnKTtcbiAgICAgICAgfVxuICAgICAgICBjaGVja0tleVR5cGUoYWxnLCBrZXksICdzaWduJyk7XG4gICAgICAgIGxldCBwYXlsb2FkID0gdGhpcy5fcGF5bG9hZDtcbiAgICAgICAgaWYgKGI2NCkge1xuICAgICAgICAgICAgcGF5bG9hZCA9IGVuY29kZXIuZW5jb2RlKGJhc2U2NHVybChwYXlsb2FkKSk7XG4gICAgICAgIH1cbiAgICAgICAgbGV0IHByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgaWYgKHRoaXMuX3Byb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgcHJvdGVjdGVkSGVhZGVyID0gZW5jb2Rlci5lbmNvZGUoYmFzZTY0dXJsKEpTT04uc3RyaW5naWZ5KHRoaXMuX3Byb3RlY3RlZEhlYWRlcikpKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHByb3RlY3RlZEhlYWRlciA9IGVuY29kZXIuZW5jb2RlKCcnKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBkYXRhID0gY29uY2F0KHByb3RlY3RlZEhlYWRlciwgZW5jb2Rlci5lbmNvZGUoJy4nKSwgcGF5bG9hZCk7XG4gICAgICAgIGNvbnN0IHNpZ25hdHVyZSA9IGF3YWl0IHNpZ24oYWxnLCBrZXksIGRhdGEpO1xuICAgICAgICBjb25zdCBqd3MgPSB7XG4gICAgICAgICAgICBzaWduYXR1cmU6IGJhc2U2NHVybChzaWduYXR1cmUpLFxuICAgICAgICAgICAgcGF5bG9hZDogJycsXG4gICAgICAgIH07XG4gICAgICAgIGlmIChiNjQpIHtcbiAgICAgICAgICAgIGp3cy5wYXlsb2FkID0gZGVjb2Rlci5kZWNvZGUocGF5bG9hZCk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICBqd3MuaGVhZGVyID0gdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX3Byb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgandzLnByb3RlY3RlZCA9IGRlY29kZXIuZGVjb2RlKHByb3RlY3RlZEhlYWRlcik7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGp3cztcbiAgICB9XG59XG4iLCJpbXBvcnQgeyBGbGF0dGVuZWRTaWduIH0gZnJvbSAnLi4vZmxhdHRlbmVkL3NpZ24uanMnO1xuZXhwb3J0IGNsYXNzIENvbXBhY3RTaWduIHtcbiAgICBjb25zdHJ1Y3RvcihwYXlsb2FkKSB7XG4gICAgICAgIHRoaXMuX2ZsYXR0ZW5lZCA9IG5ldyBGbGF0dGVuZWRTaWduKHBheWxvYWQpO1xuICAgIH1cbiAgICBzZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIHRoaXMuX2ZsYXR0ZW5lZC5zZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKTtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIGFzeW5jIHNpZ24oa2V5LCBvcHRpb25zKSB7XG4gICAgICAgIGNvbnN0IGp3cyA9IGF3YWl0IHRoaXMuX2ZsYXR0ZW5lZC5zaWduKGtleSwgb3B0aW9ucyk7XG4gICAgICAgIGlmIChqd3MucGF5bG9hZCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCd1c2UgdGhlIGZsYXR0ZW5lZCBtb2R1bGUgZm9yIGNyZWF0aW5nIEpXUyB3aXRoIGI2NDogZmFsc2UnKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gYCR7andzLnByb3RlY3RlZH0uJHtqd3MucGF5bG9hZH0uJHtqd3Muc2lnbmF0dXJlfWA7XG4gICAgfVxufVxuIiwiaW1wb3J0IHsgRmxhdHRlbmVkU2lnbiB9IGZyb20gJy4uL2ZsYXR0ZW5lZC9zaWduLmpzJztcbmltcG9ydCB7IEpXU0ludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5jbGFzcyBJbmRpdmlkdWFsU2lnbmF0dXJlIHtcbiAgICBjb25zdHJ1Y3RvcihzaWcsIGtleSwgb3B0aW9ucykge1xuICAgICAgICB0aGlzLnBhcmVudCA9IHNpZztcbiAgICAgICAgdGhpcy5rZXkgPSBrZXk7XG4gICAgICAgIHRoaXMub3B0aW9ucyA9IG9wdGlvbnM7XG4gICAgfVxuICAgIHNldFByb3RlY3RlZEhlYWRlcihwcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRQcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLnByb3RlY3RlZEhlYWRlciA9IHByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldFVucHJvdGVjdGVkSGVhZGVyKHVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLnVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRVbnByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMudW5wcm90ZWN0ZWRIZWFkZXIgPSB1bnByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIGFkZFNpZ25hdHVyZSguLi5hcmdzKSB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhcmVudC5hZGRTaWduYXR1cmUoLi4uYXJncyk7XG4gICAgfVxuICAgIHNpZ24oLi4uYXJncykge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXJlbnQuc2lnbiguLi5hcmdzKTtcbiAgICB9XG4gICAgZG9uZSgpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGFyZW50O1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBHZW5lcmFsU2lnbiB7XG4gICAgY29uc3RydWN0b3IocGF5bG9hZCkge1xuICAgICAgICB0aGlzLl9zaWduYXR1cmVzID0gW107XG4gICAgICAgIHRoaXMuX3BheWxvYWQgPSBwYXlsb2FkO1xuICAgIH1cbiAgICBhZGRTaWduYXR1cmUoa2V5LCBvcHRpb25zKSB7XG4gICAgICAgIGNvbnN0IHNpZ25hdHVyZSA9IG5ldyBJbmRpdmlkdWFsU2lnbmF0dXJlKHRoaXMsIGtleSwgb3B0aW9ucyk7XG4gICAgICAgIHRoaXMuX3NpZ25hdHVyZXMucHVzaChzaWduYXR1cmUpO1xuICAgICAgICByZXR1cm4gc2lnbmF0dXJlO1xuICAgIH1cbiAgICBhc3luYyBzaWduKCkge1xuICAgICAgICBpZiAoIXRoaXMuX3NpZ25hdHVyZXMubGVuZ3RoKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnYXQgbGVhc3Qgb25lIHNpZ25hdHVyZSBtdXN0IGJlIGFkZGVkJyk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgandzID0ge1xuICAgICAgICAgICAgc2lnbmF0dXJlczogW10sXG4gICAgICAgICAgICBwYXlsb2FkOiAnJyxcbiAgICAgICAgfTtcbiAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCB0aGlzLl9zaWduYXR1cmVzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBjb25zdCBzaWduYXR1cmUgPSB0aGlzLl9zaWduYXR1cmVzW2ldO1xuICAgICAgICAgICAgY29uc3QgZmxhdHRlbmVkID0gbmV3IEZsYXR0ZW5lZFNpZ24odGhpcy5fcGF5bG9hZCk7XG4gICAgICAgICAgICBmbGF0dGVuZWQuc2V0UHJvdGVjdGVkSGVhZGVyKHNpZ25hdHVyZS5wcm90ZWN0ZWRIZWFkZXIpO1xuICAgICAgICAgICAgZmxhdHRlbmVkLnNldFVucHJvdGVjdGVkSGVhZGVyKHNpZ25hdHVyZS51bnByb3RlY3RlZEhlYWRlcik7XG4gICAgICAgICAgICBjb25zdCB7IHBheWxvYWQsIC4uLnJlc3QgfSA9IGF3YWl0IGZsYXR0ZW5lZC5zaWduKHNpZ25hdHVyZS5rZXksIHNpZ25hdHVyZS5vcHRpb25zKTtcbiAgICAgICAgICAgIGlmIChpID09PSAwKSB7XG4gICAgICAgICAgICAgICAgandzLnBheWxvYWQgPSBwYXlsb2FkO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZSBpZiAoandzLnBheWxvYWQgIT09IHBheWxvYWQpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnaW5jb25zaXN0ZW50IHVzZSBvZiBKV1MgVW5lbmNvZGVkIFBheWxvYWQgKFJGQzc3OTcpJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBqd3Muc2lnbmF0dXJlcy5wdXNoKHJlc3QpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBqd3M7XG4gICAgfVxufVxuIiwiaW1wb3J0ICogYXMgYmFzZTY0dXJsIGZyb20gJy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmV4cG9ydCBjb25zdCBlbmNvZGUgPSBiYXNlNjR1cmwuZW5jb2RlO1xuZXhwb3J0IGNvbnN0IGRlY29kZSA9IGJhc2U2NHVybC5kZWNvZGU7XG4iLCJpbXBvcnQgeyBkZWNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHsgZGVjb2RlciB9IGZyb20gJy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4uL2xpYi9pc19vYmplY3QuanMnO1xuZXhwb3J0IGZ1bmN0aW9uIGRlY29kZVByb3RlY3RlZEhlYWRlcih0b2tlbikge1xuICAgIGxldCBwcm90ZWN0ZWRCNjR1O1xuICAgIGlmICh0eXBlb2YgdG9rZW4gPT09ICdzdHJpbmcnKSB7XG4gICAgICAgIGNvbnN0IHBhcnRzID0gdG9rZW4uc3BsaXQoJy4nKTtcbiAgICAgICAgaWYgKHBhcnRzLmxlbmd0aCA9PT0gMyB8fCBwYXJ0cy5sZW5ndGggPT09IDUpIHtcbiAgICAgICAgICAgIDtcbiAgICAgICAgICAgIFtwcm90ZWN0ZWRCNjR1XSA9IHBhcnRzO1xuICAgICAgICB9XG4gICAgfVxuICAgIGVsc2UgaWYgKHR5cGVvZiB0b2tlbiA9PT0gJ29iamVjdCcgJiYgdG9rZW4pIHtcbiAgICAgICAgaWYgKCdwcm90ZWN0ZWQnIGluIHRva2VuKSB7XG4gICAgICAgICAgICBwcm90ZWN0ZWRCNjR1ID0gdG9rZW4ucHJvdGVjdGVkO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignVG9rZW4gZG9lcyBub3QgY29udGFpbiBhIFByb3RlY3RlZCBIZWFkZXInKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICB0cnkge1xuICAgICAgICBpZiAodHlwZW9mIHByb3RlY3RlZEI2NHUgIT09ICdzdHJpbmcnIHx8ICFwcm90ZWN0ZWRCNjR1KSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCByZXN1bHQgPSBKU09OLnBhcnNlKGRlY29kZXIuZGVjb2RlKGJhc2U2NHVybChwcm90ZWN0ZWRCNjR1KSkpO1xuICAgICAgICBpZiAoIWlzT2JqZWN0KHJlc3VsdCkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcigpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignSW52YWxpZCBUb2tlbiBvciBQcm90ZWN0ZWQgSGVhZGVyIGZvcm1hdHRpbmcnKTtcbiAgICB9XG59XG4iLCJpbXBvcnQgY3J5cHRvIGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgcmFuZG9tIGZyb20gJy4vcmFuZG9tLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZVNlY3JldChhbGcsIG9wdGlvbnMpIHtcbiAgICBsZXQgbGVuZ3RoO1xuICAgIGxldCBhbGdvcml0aG07XG4gICAgbGV0IGtleVVzYWdlcztcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdIUzI1Nic6XG4gICAgICAgIGNhc2UgJ0hTMzg0JzpcbiAgICAgICAgY2FzZSAnSFM1MTInOlxuICAgICAgICAgICAgbGVuZ3RoID0gcGFyc2VJbnQoYWxnLnNsaWNlKC0zKSwgMTApO1xuICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnSE1BQycsIGhhc2g6IGBTSEEtJHtsZW5ndGh9YCwgbGVuZ3RoIH07XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3NpZ24nLCAndmVyaWZ5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnQTEyOENCQy1IUzI1Nic6XG4gICAgICAgIGNhc2UgJ0ExOTJDQkMtSFMzODQnOlxuICAgICAgICBjYXNlICdBMjU2Q0JDLUhTNTEyJzpcbiAgICAgICAgICAgIGxlbmd0aCA9IHBhcnNlSW50KGFsZy5zbGljZSgtMyksIDEwKTtcbiAgICAgICAgICAgIHJldHVybiByYW5kb20obmV3IFVpbnQ4QXJyYXkobGVuZ3RoID4+IDMpKTtcbiAgICAgICAgY2FzZSAnQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnQTE5MktXJzpcbiAgICAgICAgY2FzZSAnQTI1NktXJzpcbiAgICAgICAgICAgIGxlbmd0aCA9IHBhcnNlSW50KGFsZy5zbGljZSgxLCA0KSwgMTApO1xuICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnQUVTLUtXJywgbGVuZ3RoIH07XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3dyYXBLZXknLCAndW53cmFwS2V5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnQTEyOEdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTE5MkdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTEyOEdDTSc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ00nOlxuICAgICAgICBjYXNlICdBMjU2R0NNJzpcbiAgICAgICAgICAgIGxlbmd0aCA9IHBhcnNlSW50KGFsZy5zbGljZSgxLCA0KSwgMTApO1xuICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnQUVTLUdDTScsIGxlbmd0aCB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydlbmNyeXB0JywgJ2RlY3J5cHQnXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgSldLIFwiYWxnXCIgKEFsZ29yaXRobSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgfVxuICAgIHJldHVybiBjcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KGFsZ29yaXRobSwgb3B0aW9ucz8uZXh0cmFjdGFibGUgPz8gZmFsc2UsIGtleVVzYWdlcyk7XG59XG5mdW5jdGlvbiBnZXRNb2R1bHVzTGVuZ3RoT3B0aW9uKG9wdGlvbnMpIHtcbiAgICBjb25zdCBtb2R1bHVzTGVuZ3RoID0gb3B0aW9ucz8ubW9kdWx1c0xlbmd0aCA/PyAyMDQ4O1xuICAgIGlmICh0eXBlb2YgbW9kdWx1c0xlbmd0aCAhPT0gJ251bWJlcicgfHwgbW9kdWx1c0xlbmd0aCA8IDIwNDgpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgbW9kdWx1c0xlbmd0aCBvcHRpb24gcHJvdmlkZWQsIDIwNDggYml0cyBvciBsYXJnZXIga2V5cyBtdXN0IGJlIHVzZWQnKTtcbiAgICB9XG4gICAgcmV0dXJuIG1vZHVsdXNMZW5ndGg7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhdGVLZXlQYWlyKGFsZywgb3B0aW9ucykge1xuICAgIGxldCBhbGdvcml0aG07XG4gICAgbGV0IGtleVVzYWdlcztcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdQUzI1Nic6XG4gICAgICAgIGNhc2UgJ1BTMzg0JzpcbiAgICAgICAgY2FzZSAnUFM1MTInOlxuICAgICAgICAgICAgYWxnb3JpdGhtID0ge1xuICAgICAgICAgICAgICAgIG5hbWU6ICdSU0EtUFNTJyxcbiAgICAgICAgICAgICAgICBoYXNoOiBgU0hBLSR7YWxnLnNsaWNlKC0zKX1gLFxuICAgICAgICAgICAgICAgIHB1YmxpY0V4cG9uZW50OiBuZXcgVWludDhBcnJheShbMHgwMSwgMHgwMCwgMHgwMV0pLFxuICAgICAgICAgICAgICAgIG1vZHVsdXNMZW5ndGg6IGdldE1vZHVsdXNMZW5ndGhPcHRpb24ob3B0aW9ucyksXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydzaWduJywgJ3ZlcmlmeSddO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ1JTMjU2JzpcbiAgICAgICAgY2FzZSAnUlMzODQnOlxuICAgICAgICBjYXNlICdSUzUxMic6XG4gICAgICAgICAgICBhbGdvcml0aG0gPSB7XG4gICAgICAgICAgICAgICAgbmFtZTogJ1JTQVNTQS1QS0NTMS12MV81JyxcbiAgICAgICAgICAgICAgICBoYXNoOiBgU0hBLSR7YWxnLnNsaWNlKC0zKX1gLFxuICAgICAgICAgICAgICAgIHB1YmxpY0V4cG9uZW50OiBuZXcgVWludDhBcnJheShbMHgwMSwgMHgwMCwgMHgwMV0pLFxuICAgICAgICAgICAgICAgIG1vZHVsdXNMZW5ndGg6IGdldE1vZHVsdXNMZW5ndGhPcHRpb24ob3B0aW9ucyksXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydzaWduJywgJ3ZlcmlmeSddO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQJzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMjU2JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMzg0JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtNTEyJzpcbiAgICAgICAgICAgIGFsZ29yaXRobSA9IHtcbiAgICAgICAgICAgICAgICBuYW1lOiAnUlNBLU9BRVAnLFxuICAgICAgICAgICAgICAgIGhhc2g6IGBTSEEtJHtwYXJzZUludChhbGcuc2xpY2UoLTMpLCAxMCkgfHwgMX1gLFxuICAgICAgICAgICAgICAgIHB1YmxpY0V4cG9uZW50OiBuZXcgVWludDhBcnJheShbMHgwMSwgMHgwMCwgMHgwMV0pLFxuICAgICAgICAgICAgICAgIG1vZHVsdXNMZW5ndGg6IGdldE1vZHVsdXNMZW5ndGhPcHRpb24ob3B0aW9ucyksXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydkZWNyeXB0JywgJ3Vud3JhcEtleScsICdlbmNyeXB0JywgJ3dyYXBLZXknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdFUzI1Nic6XG4gICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RTQScsIG5hbWVkQ3VydmU6ICdQLTI1NicgfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnc2lnbicsICd2ZXJpZnknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdFUzM4NCc6XG4gICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RTQScsIG5hbWVkQ3VydmU6ICdQLTM4NCcgfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnc2lnbicsICd2ZXJpZnknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdFUzUxMic6XG4gICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RTQScsIG5hbWVkQ3VydmU6ICdQLTUyMScgfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnc2lnbicsICd2ZXJpZnknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdFZERTQSc6IHtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnc2lnbicsICd2ZXJpZnknXTtcbiAgICAgICAgICAgIGNvbnN0IGNydiA9IG9wdGlvbnM/LmNydiA/PyAnRWQyNTUxOSc7XG4gICAgICAgICAgICBzd2l0Y2ggKGNydikge1xuICAgICAgICAgICAgICAgIGNhc2UgJ0VkMjU1MTknOlxuICAgICAgICAgICAgICAgIGNhc2UgJ0VkNDQ4JzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiBjcnYgfTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgY3J2IG9wdGlvbiBwcm92aWRlZCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnRUNESC1FUyc6XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMTkyS1cnOlxuICAgICAgICBjYXNlICdFQ0RILUVTK0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnZGVyaXZlS2V5JywgJ2Rlcml2ZUJpdHMnXTtcbiAgICAgICAgICAgIGNvbnN0IGNydiA9IG9wdGlvbnM/LmNydiA/PyAnUC0yNTYnO1xuICAgICAgICAgICAgc3dpdGNoIChjcnYpIHtcbiAgICAgICAgICAgICAgICBjYXNlICdQLTI1Nic6XG4gICAgICAgICAgICAgICAgY2FzZSAnUC0zODQnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1AtNTIxJzoge1xuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RIJywgbmFtZWRDdXJ2ZTogY3J2IH07XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXNlICdYMjU1MTknOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1g0NDgnOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6IGNydiB9O1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBjcnYgb3B0aW9uIHByb3ZpZGVkLCBzdXBwb3J0ZWQgdmFsdWVzIGFyZSBQLTI1NiwgUC0zODQsIFAtNTIxLCBYMjU1MTksIGFuZCBYNDQ4Jyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgSldLIFwiYWxnXCIgKEFsZ29yaXRobSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgfVxuICAgIHJldHVybiAoY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleShhbGdvcml0aG0sIG9wdGlvbnM/LmV4dHJhY3RhYmxlID8/IGZhbHNlLCBrZXlVc2FnZXMpKTtcbn1cbiIsImltcG9ydCB7IGdlbmVyYXRlS2V5UGFpciBhcyBnZW5lcmF0ZSB9IGZyb20gJy4uL3J1bnRpbWUvZ2VuZXJhdGUuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdlbmVyYXRlS2V5UGFpcihhbGcsIG9wdGlvbnMpIHtcbiAgICByZXR1cm4gZ2VuZXJhdGUoYWxnLCBvcHRpb25zKTtcbn1cbiIsImltcG9ydCB7IGdlbmVyYXRlU2VjcmV0IGFzIGdlbmVyYXRlIH0gZnJvbSAnLi4vcnVudGltZS9nZW5lcmF0ZS5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhdGVTZWNyZXQoYWxnLCBvcHRpb25zKSB7XG4gICAgcmV0dXJuIGdlbmVyYXRlKGFsZywgb3B0aW9ucyk7XG59XG4iLCIvLyBPbmUgY29uc2lzdGVudCBhbGdvcml0aG0gZm9yIGVhY2ggZmFtaWx5LlxuLy8gaHR0cHM6Ly9kYXRhdHJhY2tlci5pZXRmLm9yZy9kb2MvaHRtbC9yZmM3NTE4XG5cbmV4cG9ydCBjb25zdCBzaWduaW5nTmFtZSA9ICdFQ0RTQSc7XG5leHBvcnQgY29uc3Qgc2lnbmluZ0N1cnZlID0gJ1AtMzg0JztcbmV4cG9ydCBjb25zdCBzaWduaW5nQWxnb3JpdGhtID0gJ0VTMzg0JztcblxuZXhwb3J0IGNvbnN0IGVuY3J5cHRpbmdOYW1lID0gJ1JTQS1PQUVQJztcbmV4cG9ydCBjb25zdCBoYXNoTGVuZ3RoID0gMjU2O1xuZXhwb3J0IGNvbnN0IGhhc2hOYW1lID0gJ1NIQS0yNTYnO1xuZXhwb3J0IGNvbnN0IG1vZHVsdXNMZW5ndGggPSA0MDk2OyAvLyBwYW52YSBKT1NFIGxpYnJhcnkgZGVmYXVsdCBpcyAyMDQ4XG5leHBvcnQgY29uc3QgZW5jcnlwdGluZ0FsZ29yaXRobSA9ICdSU0EtT0FFUC0yNTYnO1xuXG5leHBvcnQgY29uc3Qgc3ltbWV0cmljTmFtZSA9ICdBRVMtR0NNJztcbmV4cG9ydCBjb25zdCBzeW1tZXRyaWNBbGdvcml0aG0gPSAnQTI1NkdDTSc7XG5leHBvcnQgY29uc3Qgc3ltbWV0cmljV3JhcCA9ICdBMjU2R0NNS1cnO1xuZXhwb3J0IGNvbnN0IHNlY3JldEFsZ29yaXRobSA9ICdQQkVTMi1IUzUxMitBMjU2S1cnO1xuXG5leHBvcnQgY29uc3QgZXh0cmFjdGFibGUgPSB0cnVlOyAgLy8gYWx3YXlzIHdyYXBwZWRcblxuIiwiaW1wb3J0IHtleHRyYWN0YWJsZSwgc2lnbmluZ05hbWUsIHNpZ25pbmdDdXJ2ZSwgc3ltbWV0cmljTmFtZSwgaGFzaExlbmd0aH0gZnJvbSBcIi4vYWxnb3JpdGhtcy5tanNcIjtcblxuZXhwb3J0IGZ1bmN0aW9uIGRpZ2VzdChoYXNoTmFtZSwgYnVmZmVyKSB7XG4gIHJldHVybiBjcnlwdG8uc3VidGxlLmRpZ2VzdChoYXNoTmFtZSwgYnVmZmVyKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGV4cG9ydFJhd0tleShrZXkpIHtcbiAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdyYXcnLCBrZXkpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gaW1wb3J0UmF3S2V5KGFycmF5QnVmZmVyKSB7XG4gIGNvbnN0IGFsZ29yaXRobSA9IHtuYW1lOiBzaWduaW5nTmFtZSwgbmFtZWRDdXJ2ZTogc2lnbmluZ0N1cnZlfTtcbiAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBhcnJheUJ1ZmZlciwgYWxnb3JpdGhtLCBleHRyYWN0YWJsZSwgWyd2ZXJpZnknXSk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBpbXBvcnRTZWNyZXQoYnl0ZUFycmF5KSB7XG4gIGNvbnN0IGFsZ29yaXRobSA9IHtuYW1lOiBzeW1tZXRyaWNOYW1lLCBsZW5ndGg6IGhhc2hMZW5ndGh9O1xuICByZXR1cm4gY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGJ5dGVBcnJheSwgYWxnb3JpdGhtLCB0cnVlLCBbJ2VuY3J5cHQnLCAnZGVjcnlwdCddKVxufVxuIiwiaW1wb3J0ICogYXMgSk9TRSBmcm9tIFwiam9zZVwiO1xuaW1wb3J0IHtkaWdlc3QsIGV4cG9ydFJhd0tleSwgaW1wb3J0UmF3S2V5LCBpbXBvcnRTZWNyZXR9IGZyb20gXCIjcmF3XCI7XG5pbXBvcnQge2V4dHJhY3RhYmxlLCBzaWduaW5nTmFtZSwgc2lnbmluZ0N1cnZlLCBzaWduaW5nQWxnb3JpdGhtLCBlbmNyeXB0aW5nTmFtZSwgaGFzaExlbmd0aCwgaGFzaE5hbWUsIG1vZHVsdXNMZW5ndGgsIGVuY3J5cHRpbmdBbGdvcml0aG0sIHN5bW1ldHJpY05hbWUsIHN5bW1ldHJpY0FsZ29yaXRobX0gZnJvbSBcIi4vYWxnb3JpdGhtcy5tanNcIjtcblxuY29uc3QgS3J5cHRvID0ge1xuICAvLyBBbiBpbmhlcml0YWJsZSBzaW5nbGV0b24gZm9yIGNvbXBhY3QgSk9TRSBvcGVyYXRpb25zLlxuICAvLyBTZWUgaHR0cHM6Ly9raWxyb3ktY29kZS5naXRodWIuaW8vZGlzdHJpYnV0ZWQtc2VjdXJpdHkvZG9jcy9pbXBsZW1lbnRhdGlvbi5odG1sI3dyYXBwaW5nLXN1YnRsZWtyeXB0b1xuICBkZWNvZGVQcm90ZWN0ZWRIZWFkZXI6IEpPU0UuZGVjb2RlUHJvdGVjdGVkSGVhZGVyLFxuICBpc0VtcHR5SldTUGF5bG9hZChjb21wYWN0SldTKSB7IC8vIGFyZyBpcyBhIHN0cmluZ1xuICAgIHJldHVybiAhY29tcGFjdEpXUy5zcGxpdCgnLicpWzFdO1xuICB9LFxuXG4gIC8vIFRoZSBjdHkgY2FuIGJlIHNwZWNpZmllZCBpbiBlbmNyeXB0L3NpZ24sIGJ1dCBkZWZhdWx0cyB0byBhIGdvb2QgZ3Vlc3MuXG4gIC8vIFRoZSBjdHkgY2FuIGJlIHNwZWNpZmllZCBpbiBkZWNyeXB0L3ZlcmlmeSwgYnV0IGRlZmF1bHRzIHRvIHdoYXQgaXMgc3BlY2lmaWVkIGluIHRoZSBwcm90ZWN0ZWQgaGVhZGVyLlxuICBpbnB1dEJ1ZmZlcihkYXRhLCBoZWFkZXIpIHsgLy8gQW5zd2VycyBhIGJ1ZmZlciB2aWV3IG9mIGRhdGEgYW5kLCBpZiBuZWNlc3NhcnkgdG8gY29udmVydCwgYmFzaGVzIGN0eSBvZiBoZWFkZXIuXG4gICAgaWYgKEFycmF5QnVmZmVyLmlzVmlldyhkYXRhKSAmJiAhaGVhZGVyLmN0eSkgcmV0dXJuIGRhdGE7XG4gICAgbGV0IGdpdmVuQ3R5ID0gaGVhZGVyLmN0eSB8fCAnJztcbiAgICBpZiAoZ2l2ZW5DdHkuaW5jbHVkZXMoJ3RleHQnKSB8fCAoJ3N0cmluZycgPT09IHR5cGVvZiBkYXRhKSkge1xuICAgICAgaGVhZGVyLmN0eSA9IGdpdmVuQ3R5IHx8ICd0ZXh0L3BsYWluJztcbiAgICB9IGVsc2Uge1xuICAgICAgaGVhZGVyLmN0eSA9IGdpdmVuQ3R5IHx8ICdqc29uJzsgLy8gSldTIHJlY29tbWVuZHMgbGVhdmluZyBvZmYgdGhlIGxlYWRpbmcgJ2FwcGxpY2F0aW9uLycuXG4gICAgICBkYXRhID0gSlNPTi5zdHJpbmdpZnkoZGF0YSk7IC8vIE5vdGUgdGhhdCBuZXcgU3RyaW5nKFwic29tZXRoaW5nXCIpIHdpbGwgcGFzcyB0aGlzIHdheS5cbiAgICB9XG4gICAgcmV0dXJuIG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZShkYXRhKTtcbiAgfSxcbiAgcmVjb3ZlckRhdGFGcm9tQ29udGVudFR5cGUocmVzdWx0LCB7Y3R5ID0gcmVzdWx0Py5wcm90ZWN0ZWRIZWFkZXI/LmN0eX0gPSB7fSkge1xuICAgIC8vIEV4YW1pbmVzIHJlc3VsdD8ucHJvdGVjdGVkSGVhZGVyIGFuZCBiYXNoZXMgaW4gcmVzdWx0LnRleHQgb3IgcmVzdWx0Lmpzb24gaWYgYXBwcm9wcmlhdGUsIHJldHVybmluZyByZXN1bHQuXG4gICAgaWYgKHJlc3VsdCAmJiAhT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHJlc3VsdCwgJ3BheWxvYWQnKSkgcmVzdWx0LnBheWxvYWQgPSByZXN1bHQucGxhaW50ZXh0OyAgLy8gYmVjYXVzZSBKT1NFIHVzZXMgcGxhaW50ZXh0IGZvciBkZWNyeXB0IGFuZCBwYXlsb2FkIGZvciBzaWduLlxuICAgIGlmICghY3R5IHx8ICFyZXN1bHQ/LnBheWxvYWQpIHJldHVybiByZXN1bHQ7IC8vIGVpdGhlciBubyBjdHkgb3Igbm8gcmVzdWx0XG4gICAgcmVzdWx0LnRleHQgPSBuZXcgVGV4dERlY29kZXIoKS5kZWNvZGUocmVzdWx0LnBheWxvYWQpO1xuICAgIGlmIChjdHkuaW5jbHVkZXMoJ2pzb24nKSkgcmVzdWx0Lmpzb24gPSBKU09OLnBhcnNlKHJlc3VsdC50ZXh0KTtcbiAgICByZXR1cm4gcmVzdWx0O1xuICB9LFxuXG4gIC8vIFNpZ24vVmVyaWZ5XG4gIGdlbmVyYXRlU2lnbmluZ0tleSgpIHsgLy8gUHJvbWlzZSB7cHJpdmF0ZUtleSwgcHVibGljS2V5fSBpbiBvdXIgc3RhbmRhcmQgc2lnbmluZyBhbGdvcml0aG0uXG4gICAgcmV0dXJuIEpPU0UuZ2VuZXJhdGVLZXlQYWlyKHNpZ25pbmdBbGdvcml0aG0sIHtleHRyYWN0YWJsZX0pO1xuICB9LFxuICBhc3luYyBzaWduKHByaXZhdGVLZXksIG1lc3NhZ2UsIGhlYWRlcnMgPSB7fSkgeyAvLyBQcm9taXNlIGEgY29tcGFjdCBKV1Mgc3RyaW5nLiBBY2NlcHRzIGhlYWRlcnMgdG8gYmUgcHJvdGVjdGVkLlxuICAgIGxldCBoZWFkZXIgPSB7YWxnOiBzaWduaW5nQWxnb3JpdGhtLCAuLi5oZWFkZXJzfSxcbiAgICAgICAgaW5wdXRCdWZmZXIgPSB0aGlzLmlucHV0QnVmZmVyKG1lc3NhZ2UsIGhlYWRlcik7XG4gICAgcmV0dXJuIG5ldyBKT1NFLkNvbXBhY3RTaWduKGlucHV0QnVmZmVyKS5zZXRQcm90ZWN0ZWRIZWFkZXIoaGVhZGVyKS5zaWduKHByaXZhdGVLZXkpO1xuICB9LFxuICBhc3luYyB2ZXJpZnkocHVibGljS2V5LCBzaWduYXR1cmUsIG9wdGlvbnMpIHsgLy8gUHJvbWlzZSB7cGF5bG9hZCwgdGV4dCwganNvbn0sIHdoZXJlIHRleHQgYW5kIGpzb24gYXJlIG9ubHkgZGVmaW5lZCB3aGVuIGFwcHJvcHJpYXRlLlxuICAgIGxldCByZXN1bHQgPSBhd2FpdCBKT1NFLmNvbXBhY3RWZXJpZnkoc2lnbmF0dXJlLCBwdWJsaWNLZXkpLmNhdGNoKCgpID0+IHVuZGVmaW5lZCk7XG4gICAgcmV0dXJuIHRoaXMucmVjb3ZlckRhdGFGcm9tQ29udGVudFR5cGUocmVzdWx0LCBvcHRpb25zKTtcbiAgfSxcblxuICAvLyBFbmNyeXB0L0RlY3J5cHRcbiAgZ2VuZXJhdGVFbmNyeXB0aW5nS2V5KCkgeyAvLyBQcm9taXNlIHtwcml2YXRlS2V5LCBwdWJsaWNLZXl9IGluIG91ciBzdGFuZGFyZCBlbmNyeXB0aW9uIGFsZ29yaXRobS5cbiAgICByZXR1cm4gSk9TRS5nZW5lcmF0ZUtleVBhaXIoZW5jcnlwdGluZ0FsZ29yaXRobSwge2V4dHJhY3RhYmxlLCBtb2R1bHVzTGVuZ3RofSk7XG4gIH0sXG4gIGFzeW5jIGVuY3J5cHQoa2V5LCBtZXNzYWdlLCBoZWFkZXJzID0ge30pIHsgLy8gUHJvbWlzZSBhIGNvbXBhY3QgSldFIHN0cmluZy4gQWNjZXB0cyBoZWFkZXJzIHRvIGJlIHByb3RlY3RlZC5cbiAgICBsZXQgYWxnID0gdGhpcy5pc1N5bW1ldHJpYyhrZXkpID8gJ2RpcicgOiBlbmNyeXB0aW5nQWxnb3JpdGhtLFxuICAgICAgICBoZWFkZXIgPSB7YWxnLCBlbmM6IHN5bW1ldHJpY0FsZ29yaXRobSwgLi4uaGVhZGVyc30sXG4gICAgICAgIGlucHV0QnVmZmVyID0gdGhpcy5pbnB1dEJ1ZmZlcihtZXNzYWdlLCBoZWFkZXIpLFxuICAgICAgICBzZWNyZXQgPSB0aGlzLmtleVNlY3JldChrZXkpO1xuICAgIHJldHVybiBuZXcgSk9TRS5Db21wYWN0RW5jcnlwdChpbnB1dEJ1ZmZlcikuc2V0UHJvdGVjdGVkSGVhZGVyKGhlYWRlcikuZW5jcnlwdChzZWNyZXQpO1xuICB9LFxuICBhc3luYyBkZWNyeXB0KGtleSwgZW5jcnlwdGVkLCBvcHRpb25zID0ge30pIHsgLy8gUHJvbWlzZSB7cGF5bG9hZCwgdGV4dCwganNvbn0sIHdoZXJlIHRleHQgYW5kIGpzb24gYXJlIG9ubHkgZGVmaW5lZCB3aGVuIGFwcHJvcHJpYXRlLlxuICAgIGxldCBzZWNyZXQgPSB0aGlzLmtleVNlY3JldChrZXkpLFxuICAgICAgICByZXN1bHQgPSBhd2FpdCBKT1NFLmNvbXBhY3REZWNyeXB0KGVuY3J5cHRlZCwgc2VjcmV0KTtcbiAgICB0aGlzLnJlY292ZXJEYXRhRnJvbUNvbnRlbnRUeXBlKHJlc3VsdCwgb3B0aW9ucyk7XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfSxcbiAgYXN5bmMgZ2VuZXJhdGVTZWNyZXRLZXkodGV4dCkgeyAvLyBKT1NFIHVzZXMgYSBkaWdlc3QgZm9yIFBCRVMsIGJ1dCBtYWtlIGl0IHJlY29nbml6YWJsZSBhcyBhIHt0eXBlOiAnc2VjcmV0J30ga2V5LlxuICAgIGxldCBidWZmZXIgPSBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUodGV4dCksXG4gICAgICAgIGhhc2ggPSBhd2FpdCBkaWdlc3QoaGFzaE5hbWUsIGJ1ZmZlcik7XG4gICAgcmV0dXJuIHt0eXBlOiAnc2VjcmV0JywgdGV4dDogbmV3IFVpbnQ4QXJyYXkoaGFzaCl9O1xuICB9LFxuICBnZW5lcmF0ZVN5bW1ldHJpY0tleSh0ZXh0KSB7IC8vIFByb21pc2UgYSBrZXkgZm9yIHN5bW1ldHJpYyBlbmNyeXB0aW9uLlxuICAgIGlmICh0ZXh0KSByZXR1cm4gdGhpcy5nZW5lcmF0ZVNlY3JldEtleSh0ZXh0KTsgLy8gUEJFU1xuICAgIHJldHVybiBKT1NFLmdlbmVyYXRlU2VjcmV0KHN5bW1ldHJpY0FsZ29yaXRobSwge2V4dHJhY3RhYmxlfSk7IC8vIEFFU1xuICB9LFxuICBpc1N5bW1ldHJpYyhrZXkpIHsgLy8gRWl0aGVyIEFFUyBvciBQQkVTLCBidXQgbm90IHB1YmxpY0tleSBvciBwcml2YXRlS2V5LlxuICAgIHJldHVybiBrZXkudHlwZSA9PT0gJ3NlY3JldCc7XG4gIH0sXG4gIGtleVNlY3JldChrZXkpIHsgLy8gUmV0dXJuIHdoYXQgaXMgYWN0dWFsbHkgdXNlZCBhcyBpbnB1dCBpbiBKT1NFIGxpYnJhcnkuXG4gICAgaWYgKGtleS50ZXh0KSByZXR1cm4ga2V5LnRleHQ7XG4gICAgcmV0dXJuIGtleTtcbiAgfSxcblxuICAvLyBFeHBvcnQvSW1wb3J0XG4gIGFzeW5jIGV4cG9ydFJhdyhrZXkpIHsgLy8gYmFzZTY0dXJsIGZvciBwdWJsaWMgdmVyZmljYXRpb24ga2V5c1xuICAgIGxldCBhcnJheUJ1ZmZlciA9IGF3YWl0IGV4cG9ydFJhd0tleShrZXkpO1xuICAgIHJldHVybiBKT1NFLmJhc2U2NHVybC5lbmNvZGUobmV3IFVpbnQ4QXJyYXkoYXJyYXlCdWZmZXIpKTtcbiAgfSxcbiAgYXN5bmMgaW1wb3J0UmF3KHN0cmluZykgeyAvLyBQcm9taXNlIHRoZSB2ZXJpZmljYXRpb24ga2V5IGZyb20gYmFzZTY0dXJsXG4gICAgbGV0IGFycmF5QnVmZmVyID0gSk9TRS5iYXNlNjR1cmwuZGVjb2RlKHN0cmluZyk7XG4gICAgcmV0dXJuIGltcG9ydFJhd0tleShhcnJheUJ1ZmZlcik7XG4gIH0sXG4gIGFzeW5jIGV4cG9ydEpXSyhrZXkpIHsgLy8gUHJvbWlzZSBKV0sgb2JqZWN0LCB3aXRoIGFsZyBpbmNsdWRlZC5cbiAgICBsZXQgZXhwb3J0ZWQgPSBhd2FpdCBKT1NFLmV4cG9ydEpXSyhrZXkpLFxuICAgICAgICBhbGcgPSBrZXkuYWxnb3JpdGhtOyAvLyBKT1NFIGxpYnJhcnkgZ2l2ZXMgYWxnb3JpdGhtLCBidXQgbm90IGFsZyB0aGF0IGlzIG5lZWRlZCBmb3IgaW1wb3J0LlxuICAgIGlmIChhbGcpIHsgLy8gc3VidGxlLmNyeXB0byB1bmRlcmx5aW5nIGtleXNcbiAgICAgIGlmIChhbGcubmFtZSA9PT0gc2lnbmluZ05hbWUgJiYgYWxnLm5hbWVkQ3VydmUgPT09IHNpZ25pbmdDdXJ2ZSkgZXhwb3J0ZWQuYWxnID0gc2lnbmluZ0FsZ29yaXRobTtcbiAgICAgIGVsc2UgaWYgKGFsZy5uYW1lID09PSBlbmNyeXB0aW5nTmFtZSAmJiBhbGcuaGFzaC5uYW1lID09PSBoYXNoTmFtZSkgZXhwb3J0ZWQuYWxnID0gZW5jcnlwdGluZ0FsZ29yaXRobTtcbiAgICAgIGVsc2UgaWYgKGFsZy5uYW1lID09PSBzeW1tZXRyaWNOYW1lICYmIGFsZy5sZW5ndGggPT09IGhhc2hMZW5ndGgpIGV4cG9ydGVkLmFsZyA9IHN5bW1ldHJpY0FsZ29yaXRobTtcbiAgICB9IGVsc2Ugc3dpdGNoIChleHBvcnRlZC5rdHkpIHsgLy8gSk9TRSBvbiBOb2RlSlMgdXNlZCBub2RlOmNyeXB0byBrZXlzLCB3aGljaCBkbyBub3QgZXhwb3NlIHRoZSBwcmVjaXNlIGFsZ29yaXRobVxuICAgICAgY2FzZSAnRUMnOiBleHBvcnRlZC5hbGcgPSBzaWduaW5nQWxnb3JpdGhtOyBicmVhaztcbiAgICAgIGNhc2UgJ1JTQSc6IGV4cG9ydGVkLmFsZyA9IGVuY3J5cHRpbmdBbGdvcml0aG07IGJyZWFrO1xuICAgICAgY2FzZSAnb2N0JzogZXhwb3J0ZWQuYWxnID0gc3ltbWV0cmljQWxnb3JpdGhtOyBicmVhaztcbiAgICB9XG4gICAgcmV0dXJuIGV4cG9ydGVkO1xuICB9LFxuICBhc3luYyBpbXBvcnRKV0soandrKSB7IC8vIFByb21pc2UgYSBrZXkgb2JqZWN0XG4gICAgandrID0ge2V4dDogdHJ1ZSwgLi4uandrfTsgLy8gV2UgbmVlZCB0aGUgcmVzdWx0IHRvIGJlIGJlIGFibGUgdG8gZ2VuZXJhdGUgYSBuZXcgSldLIChlLmcuLCBvbiBjaGFuZ2VNZW1iZXJzaGlwKVxuICAgIGxldCBpbXBvcnRlZCA9IGF3YWl0IEpPU0UuaW1wb3J0SldLKGp3ayk7XG4gICAgaWYgKGltcG9ydGVkIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgLy8gV2UgZGVwZW5kIGFuIHJldHVybmluZyBhbiBhY3R1YWwga2V5LCBidXQgdGhlIEpPU0UgbGlicmFyeSB3ZSB1c2VcbiAgICAgIC8vIHdpbGwgYWJvdmUgcHJvZHVjZSB0aGUgcmF3IFVpbnQ4QXJyYXkgaWYgdGhlIGp3ayBpcyBmcm9tIGEgc2VjcmV0LlxuICAgICAgaW1wb3J0ZWQgPSBhd2FpdCBpbXBvcnRTZWNyZXQoaW1wb3J0ZWQpO1xuICAgIH1cbiAgICByZXR1cm4gaW1wb3J0ZWQ7XG4gIH0sXG5cbiAgYXN5bmMgd3JhcEtleShrZXksIHdyYXBwaW5nS2V5LCBoZWFkZXJzID0ge30pIHsgLy8gUHJvbWlzZSBhIEpXRSBmcm9tIHRoZSBwdWJsaWMgd3JhcHBpbmdLZXlcbiAgICBsZXQgZXhwb3J0ZWQgPSBhd2FpdCB0aGlzLmV4cG9ydEpXSyhrZXkpO1xuICAgIHJldHVybiB0aGlzLmVuY3J5cHQod3JhcHBpbmdLZXksIGV4cG9ydGVkLCBoZWFkZXJzKTtcbiAgfSxcbiAgYXN5bmMgdW53cmFwS2V5KHdyYXBwZWRLZXksIHVud3JhcHBpbmdLZXkpIHsgLy8gUHJvbWlzZSB0aGUga2V5IHVubG9ja2VkIGJ5IHRoZSBwcml2YXRlIHVud3JhcHBpbmdLZXkuXG4gICAgbGV0IGRlY3J5cHRlZCA9IGF3YWl0IHRoaXMuZGVjcnlwdCh1bndyYXBwaW5nS2V5LCB3cmFwcGVkS2V5KTtcbiAgICByZXR1cm4gdGhpcy5pbXBvcnRKV0soZGVjcnlwdGVkLmpzb24pO1xuICB9XG59XG5cbmV4cG9ydCBkZWZhdWx0IEtyeXB0bztcbi8qXG5Tb21lIHVzZWZ1bCBKT1NFIHJlY2lwZXMgZm9yIHBsYXlpbmcgYXJvdW5kLlxuc2sgPSBhd2FpdCBKT1NFLmdlbmVyYXRlS2V5UGFpcignRVMzODQnLCB7ZXh0cmFjdGFibGU6IHRydWV9KVxuand0ID0gYXdhaXQgbmV3IEpPU0UuU2lnbkpXVCgpLnNldFN1YmplY3QoXCJmb29cIikuc2V0UHJvdGVjdGVkSGVhZGVyKHthbGc6J0VTMzg0J30pLnNpZ24oc2sucHJpdmF0ZUtleSlcbmF3YWl0IEpPU0Uuand0VmVyaWZ5KGp3dCwgc2sucHVibGljS2V5KSAvLy5wYXlsb2FkLnN1YlxuXG5tZXNzYWdlID0gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKCdzb21lIG1lc3NhZ2UnKVxuandzID0gYXdhaXQgbmV3IEpPU0UuQ29tcGFjdFNpZ24obWVzc2FnZSkuc2V0UHJvdGVjdGVkSGVhZGVyKHthbGc6J0VTMzg0J30pLnNpZ24oc2sucHJpdmF0ZUtleSkgLy8gT3IgRmxhdHRlbmVkU2lnblxuandzID0gYXdhaXQgbmV3IEpPU0UuR2VuZXJhbFNpZ24obWVzc2FnZSkuYWRkU2lnbmF0dXJlKHNrLnByaXZhdGVLZXkpLnNldFByb3RlY3RlZEhlYWRlcih7YWxnOidFUzM4NCd9KS5zaWduKClcbnZlcmlmaWVkID0gYXdhaXQgSk9TRS5nZW5lcmFsVmVyaWZ5KGp3cywgc2sucHVibGljS2V5KVxub3IgY29tcGFjdFZlcmlmeSBvciBmbGF0dGVuZWRWZXJpZnlcbm5ldyBUZXh0RGVjb2RlcigpLmRlY29kZSh2ZXJpZmllZC5wYXlsb2FkKVxuXG5layA9IGF3YWl0IEpPU0UuZ2VuZXJhdGVLZXlQYWlyKCdSU0EtT0FFUC0yNTYnLCB7ZXh0cmFjdGFibGU6IHRydWV9KVxuandlID0gYXdhaXQgbmV3IEpPU0UuQ29tcGFjdEVuY3J5cHQobWVzc2FnZSkuc2V0UHJvdGVjdGVkSGVhZGVyKHthbGc6ICdSU0EtT0FFUC0yNTYnLCBlbmM6ICdBMjU2R0NNJyB9KS5lbmNyeXB0KGVrLnB1YmxpY0tleSlcbm9yIEZsYXR0ZW5lZEVuY3J5cHQuIEZvciBzeW1tZXRyaWMgc2VjcmV0LCBzcGVjaWZ5IGFsZzonZGlyJy5cbmRlY3J5cHRlZCA9IGF3YWl0IEpPU0UuY29tcGFjdERlY3J5cHQoandlLCBlay5wcml2YXRlS2V5KVxubmV3IFRleHREZWNvZGVyKCkuZGVjb2RlKGRlY3J5cHRlZC5wbGFpbnRleHQpXG5qd2UgPSBhd2FpdCBuZXcgSk9TRS5HZW5lcmFsRW5jcnlwdChtZXNzYWdlKS5zZXRQcm90ZWN0ZWRIZWFkZXIoe2FsZzogJ1JTQS1PQUVQLTI1NicsIGVuYzogJ0EyNTZHQ00nIH0pLmFkZFJlY2lwaWVudChlay5wdWJsaWNLZXkpLmVuY3J5cHQoKSAvLyB3aXRoIGFkZGl0aW9uYWwgYWRkUmVjaXBlbnQoKSBhcyBuZWVkZWRcbmRlY3J5cHRlZCA9IGF3YWl0IEpPU0UuZ2VuZXJhbERlY3J5cHQoandlLCBlay5wcml2YXRlS2V5KVxuXG5tYXRlcmlhbCA9IG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZSgnc2VjcmV0Jylcbmp3ZSA9IGF3YWl0IG5ldyBKT1NFLkNvbXBhY3RFbmNyeXB0KG1lc3NhZ2UpLnNldFByb3RlY3RlZEhlYWRlcih7YWxnOiAnUEJFUzItSFM1MTIrQTI1NktXJywgZW5jOiAnQTI1NkdDTScgfSkuZW5jcnlwdChtYXRlcmlhbClcbmRlY3J5cHRlZCA9IGF3YWl0IEpPU0UuY29tcGFjdERlY3J5cHQoandlLCBtYXRlcmlhbCwge2tleU1hbmFnZW1lbnRBbGdvcml0aG1zOiBbJ1BCRVMyLUhTNTEyK0EyNTZLVyddLCBjb250ZW50RW5jcnlwdGlvbkFsZ29yaXRobXM6IFsnQTI1NkdDTSddfSlcbmp3ZSA9IGF3YWl0IG5ldyBKT1NFLkdlbmVyYWxFbmNyeXB0KG1lc3NhZ2UpLnNldFByb3RlY3RlZEhlYWRlcih7YWxnOiAnUEJFUzItSFM1MTIrQTI1NktXJywgZW5jOiAnQTI1NkdDTScgfSkuYWRkUmVjaXBpZW50KG1hdGVyaWFsKS5lbmNyeXB0KClcbmp3ZSA9IGF3YWl0IG5ldyBKT1NFLkdlbmVyYWxFbmNyeXB0KG1lc3NhZ2UpLnNldFByb3RlY3RlZEhlYWRlcih7ZW5jOiAnQTI1NkdDTScgfSlcbiAgLmFkZFJlY2lwaWVudChlay5wdWJsaWNLZXkpLnNldFVucHJvdGVjdGVkSGVhZGVyKHtraWQ6ICdmb28nLCBhbGc6ICdSU0EtT0FFUC0yNTYnfSlcbiAgLmFkZFJlY2lwaWVudChtYXRlcmlhbCkuc2V0VW5wcm90ZWN0ZWRIZWFkZXIoe2tpZDogJ3NlY3JldDEnLCBhbGc6ICdQQkVTMi1IUzUxMitBMjU2S1cnfSlcbiAgLmFkZFJlY2lwaWVudChtYXRlcmlhbDIpLnNldFVucHJvdGVjdGVkSGVhZGVyKHtraWQ6ICdzZWNyZXQyJywgYWxnOiAnUEJFUzItSFM1MTIrQTI1NktXJ30pXG4gIC5lbmNyeXB0KClcbmRlY3J5cHRlZCA9IGF3YWl0IEpPU0UuZ2VuZXJhbERlY3J5cHQoandlLCBlay5wcml2YXRlS2V5KVxuZGVjcnlwdGVkID0gYXdhaXQgSk9TRS5nZW5lcmFsRGVjcnlwdChqd2UsIG1hdGVyaWFsLCB7a2V5TWFuYWdlbWVudEFsZ29yaXRobXM6IFsnUEJFUzItSFM1MTIrQTI1NktXJ119KVxuKi9cbiIsImltcG9ydCBLcnlwdG8gZnJvbSBcIi4va3J5cHRvLm1qc1wiO1xuaW1wb3J0ICogYXMgSk9TRSBmcm9tIFwiam9zZVwiO1xuaW1wb3J0IHtzaWduaW5nQWxnb3JpdGhtLCBlbmNyeXB0aW5nQWxnb3JpdGhtLCBzeW1tZXRyaWNBbGdvcml0aG0sIHN5bW1ldHJpY1dyYXAsIHNlY3JldEFsZ29yaXRobX0gZnJvbSBcIi4vYWxnb3JpdGhtcy5tanNcIjtcblxuZnVuY3Rpb24gbWlzbWF0Y2goa2lkLCBlbmNvZGVkS2lkKSB7IC8vIFByb21pc2UgYSByZWplY3Rpb24uXG4gIGxldCBtZXNzYWdlID0gYEtleSAke2tpZH0gZG9lcyBub3QgbWF0Y2ggZW5jb2RlZCAke2VuY29kZWRLaWR9LmA7XG4gIHJldHVybiBQcm9taXNlLnJlamVjdChtZXNzYWdlKTtcbn1cblxuY29uc3QgTXVsdGlLcnlwdG8gPSB7XG4gIC8vIEV4dGVuZCBLcnlwdG8gZm9yIGdlbmVyYWwgKG11bHRpcGxlIGtleSkgSk9TRSBvcGVyYXRpb25zLlxuICAvLyBTZWUgaHR0cHM6Ly9raWxyb3ktY29kZS5naXRodWIuaW8vZGlzdHJpYnV0ZWQtc2VjdXJpdHkvZG9jcy9pbXBsZW1lbnRhdGlvbi5odG1sI2NvbWJpbmluZy1rZXlzXG4gIFxuICAvLyBPdXIgbXVsdGkga2V5cyBhcmUgZGljdGlvbmFyaWVzIG9mIG5hbWUgKG9yIGtpZCkgPT4ga2V5T2JqZWN0LlxuICBpc011bHRpS2V5KGtleSkgeyAvLyBBIFN1YnRsZUNyeXB0byBDcnlwdG9LZXkgaXMgYW4gb2JqZWN0IHdpdGggYSB0eXBlIHByb3BlcnR5LiBPdXIgbXVsdGlrZXlzIGFyZVxuICAgIC8vIG9iamVjdHMgd2l0aCBhIHNwZWNpZmljIHR5cGUgb3Igbm8gdHlwZSBwcm9wZXJ0eSBhdCBhbGwuXG4gICAgcmV0dXJuIChrZXkudHlwZSB8fCAnbXVsdGknKSA9PT0gJ211bHRpJztcbiAgfSxcbiAga2V5VGFncyhrZXkpIHsgLy8gSnVzdCB0aGUga2lkcyB0aGF0IGFyZSBmb3IgYWN0dWFsIGtleXMuIE5vICd0eXBlJy5cbiAgICByZXR1cm4gT2JqZWN0LmtleXMoa2V5KS5maWx0ZXIoa2V5ID0+IGtleSAhPT0gJ3R5cGUnKTtcbiAgfSxcblxuICAvLyBFeHBvcnQvSW1wb3J0XG4gIGFzeW5jIGV4cG9ydEpXSyhrZXkpIHsgLy8gUHJvbWlzZSBhIEpXSyBrZXkgc2V0IGlmIG5lY2Vzc2FyeSwgcmV0YWluaW5nIHRoZSBuYW1lcyBhcyBraWQgcHJvcGVydHkuXG4gICAgaWYgKCF0aGlzLmlzTXVsdGlLZXkoa2V5KSkgcmV0dXJuIHN1cGVyLmV4cG9ydEpXSyhrZXkpO1xuICAgIGxldCBuYW1lcyA9IHRoaXMua2V5VGFncyhrZXkpLFxuICAgICAgICBrZXlzID0gYXdhaXQgUHJvbWlzZS5hbGwobmFtZXMubWFwKGFzeW5jIG5hbWUgPT4ge1xuICAgICAgICAgIGxldCBqd2sgPSBhd2FpdCB0aGlzLmV4cG9ydEpXSyhrZXlbbmFtZV0pO1xuICAgICAgICAgIGp3ay5raWQgPSBuYW1lO1xuICAgICAgICAgIHJldHVybiBqd2s7XG4gICAgICAgIH0pKTtcbiAgICByZXR1cm4ge2tleXN9O1xuICB9LFxuICBhc3luYyBpbXBvcnRKV0soandrKSB7IC8vIFByb21pc2UgYSBzaW5nbGUgXCJrZXlcIiBvYmplY3QuXG4gICAgLy8gUmVzdWx0IHdpbGwgYmUgYSBtdWx0aS1rZXkgaWYgSldLIGlzIGEga2V5IHNldCwgaW4gd2hpY2ggY2FzZSBlYWNoIG11c3QgaW5jbHVkZSBhIGtpZCBwcm9wZXJ0eS5cbiAgICBpZiAoIWp3ay5rZXlzKSByZXR1cm4gc3VwZXIuaW1wb3J0SldLKGp3ayk7XG4gICAgbGV0IGtleSA9IHt9OyAvLyBUT0RPOiBnZXQgdHlwZSBmcm9tIGt0eSBvciBzb21lIHN1Y2g/XG4gICAgYXdhaXQgUHJvbWlzZS5hbGwoandrLmtleXMubWFwKGFzeW5jIGp3ayA9PiBrZXlbandrLmtpZF0gPSBhd2FpdCB0aGlzLmltcG9ydEpXSyhqd2spKSk7XG4gICAgcmV0dXJuIGtleTtcbiAgfSxcblxuICAvLyBFbmNyeXB0L0RlY3J5cHRcbiAgYXN5bmMgZW5jcnlwdChrZXksIG1lc3NhZ2UsIGhlYWRlcnMgPSB7fSkgeyAvLyBQcm9taXNlIGEgSldFLCBpbiBnZW5lcmFsIGZvcm0gaWYgYXBwcm9wcmlhdGUuXG4gICAgaWYgKCF0aGlzLmlzTXVsdGlLZXkoa2V5KSkgcmV0dXJuIHN1cGVyLmVuY3J5cHQoa2V5LCBtZXNzYWdlLCBoZWFkZXJzKTtcbiAgICAvLyBrZXkgbXVzdCBiZSBhIGRpY3Rpb25hcnkgbWFwcGluZyB0YWdzIHRvIGVuY3J5cHRpbmcga2V5cy5cbiAgICBsZXQgYmFzZUhlYWRlciA9IHtlbmM6IHN5bW1ldHJpY0FsZ29yaXRobSwgLi4uaGVhZGVyc30sXG4gICAgICAgIGlucHV0QnVmZmVyID0gdGhpcy5pbnB1dEJ1ZmZlcihtZXNzYWdlLCBiYXNlSGVhZGVyKSxcbiAgICAgICAgandlID0gbmV3IEpPU0UuR2VuZXJhbEVuY3J5cHQoaW5wdXRCdWZmZXIpLnNldFByb3RlY3RlZEhlYWRlcihiYXNlSGVhZGVyKTtcbiAgICBmb3IgKGxldCB0YWcgb2YgdGhpcy5rZXlUYWdzKGtleSkpIHtcbiAgICAgIGxldCB0aGlzS2V5ID0ga2V5W3RhZ10sXG4gICAgICAgICAgaXNTdHJpbmcgPSAnc3RyaW5nJyA9PT0gdHlwZW9mIHRoaXNLZXksXG4gICAgICAgICAgaXNTeW0gPSBpc1N0cmluZyB8fCB0aGlzLmlzU3ltbWV0cmljKHRoaXNLZXkpLFxuICAgICAgICAgIHNlY3JldCA9IGlzU3RyaW5nID8gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHRoaXNLZXkpIDogdGhpcy5rZXlTZWNyZXQodGhpc0tleSksXG4gICAgICAgICAgYWxnID0gaXNTdHJpbmcgPyBzZWNyZXRBbGdvcml0aG0gOiAoaXNTeW0gPyBzeW1tZXRyaWNXcmFwIDogZW5jcnlwdGluZ0FsZ29yaXRobSk7XG4gICAgICAvLyBUaGUga2lkIGFuZCBhbGcgYXJlIHBlci9zdWIta2V5LCBhbmQgc28gY2Fubm90IGJlIHNpZ25lZCBieSBhbGwsIGFuZCBzbyBjYW5ub3QgYmUgcHJvdGVjdGVkIHdpdGhpbiB0aGUgZW5jcnlwdGlvbi5cbiAgICAgIC8vIFRoaXMgaXMgb2ssIGJlY2F1c2UgdGhlIG9ubHkgdGhhdCBjYW4gaGFwcGVuIGFzIGEgcmVzdWx0IG9mIHRhbXBlcmluZyB3aXRoIHRoZXNlIGlzIHRoYXQgdGhlIGRlY3J5cHRpb24gd2lsbCBmYWlsLFxuICAgICAgLy8gd2hpY2ggaXMgdGhlIHNhbWUgcmVzdWx0IGFzIHRhbXBlcmluZyB3aXRoIHRoZSBjaXBoZXJ0ZXh0IG9yIGFueSBvdGhlciBwYXJ0IG9mIHRoZSBKV0UuXG4gICAgICBqd2UuYWRkUmVjaXBpZW50KHNlY3JldCkuc2V0VW5wcm90ZWN0ZWRIZWFkZXIoe2tpZDogdGFnLCBhbGd9KTtcbiAgICB9XG4gICAgbGV0IGVuY3J5cHRlZCA9IGF3YWl0IGp3ZS5lbmNyeXB0KCk7XG4gICAgcmV0dXJuIGVuY3J5cHRlZDtcbiAgfSxcbiAgYXN5bmMgZGVjcnlwdChrZXksIGVuY3J5cHRlZCwgb3B0aW9ucykgeyAvLyBQcm9taXNlIHtwYXlsb2FkLCB0ZXh0LCBqc29ufSwgd2hlcmUgdGV4dCBhbmQganNvbiBhcmUgb25seSBkZWZpbmVkIHdoZW4gYXBwcm9wcmlhdGUuXG4gICAgaWYgKCF0aGlzLmlzTXVsdGlLZXkoa2V5KSkgcmV0dXJuIHN1cGVyLmRlY3J5cHQoa2V5LCBlbmNyeXB0ZWQsIG9wdGlvbnMpO1xuICAgIGxldCBqd2UgPSBlbmNyeXB0ZWQsXG4gICAgICAgIHtyZWNpcGllbnRzfSA9IGp3ZSxcbiAgICAgICAgdW53cmFwcGluZ1Byb21pc2VzID0gcmVjaXBpZW50cy5tYXAoYXN5bmMgKHtoZWFkZXJ9KSA9PiB7XG4gICAgICAgICAgbGV0IHtraWR9ID0gaGVhZGVyLFxuICAgICAgICAgICAgICB1bndyYXBwaW5nS2V5ID0ga2V5W2tpZF0sXG4gICAgICAgICAgICAgIG9wdGlvbnMgPSB7fTtcbiAgICAgICAgICBpZiAoIXVud3JhcHBpbmdLZXkpIHJldHVybiBQcm9taXNlLnJlamVjdCgnbWlzc2luZycpO1xuICAgICAgICAgIGlmICgnc3RyaW5nJyA9PT0gdHlwZW9mIHVud3JhcHBpbmdLZXkpIHsgLy8gVE9ETzogb25seSBzcGVjaWZpZWQgaWYgYWxsb3dlZCBieSBzZWN1cmUgaGVhZGVyP1xuICAgICAgICAgICAgdW53cmFwcGluZ0tleSA9IG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZSh1bndyYXBwaW5nS2V5KTtcbiAgICAgICAgICAgIG9wdGlvbnMua2V5TWFuYWdlbWVudEFsZ29yaXRobXMgPSBbc2VjcmV0QWxnb3JpdGhtXTtcbiAgICAgICAgICB9XG4gICAgICAgICAgbGV0IHJlc3VsdCA9IGF3YWl0IEpPU0UuZ2VuZXJhbERlY3J5cHQoandlLCB0aGlzLmtleVNlY3JldCh1bndyYXBwaW5nS2V5KSwgb3B0aW9ucyksXG4gICAgICAgICAgICAgIGVuY29kZWRLaWQgPSByZXN1bHQudW5wcm90ZWN0ZWRIZWFkZXIua2lkO1xuICAgICAgICAgIGlmIChlbmNvZGVkS2lkICE9PSBraWQpIHJldHVybiBtaXNtYXRjaChraWQsIGVuY29kZWRLaWQpO1xuICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgIH0pO1xuICAgIC8vIERvIHdlIHJlYWxseSB3YW50IHRvIHJldHVybiB1bmRlZmluZWQgaWYgZXZlcnl0aGluZyBmYWlscz8gU2hvdWxkIGp1c3QgYWxsb3cgdGhlIHJlamVjdGlvbiB0byBwcm9wYWdhdGU/XG4gICAgcmV0dXJuIGF3YWl0IFByb21pc2UuYW55KHVud3JhcHBpbmdQcm9taXNlcykudGhlbihcbiAgICAgIHJlc3VsdCA9PiB7XG4gICAgICAgIHRoaXMucmVjb3ZlckRhdGFGcm9tQ29udGVudFR5cGUocmVzdWx0LCBvcHRpb25zKTtcbiAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgIH0sXG4gICAgICAoKSA9PiB1bmRlZmluZWQpO1xuICB9LFxuXG4gIC8vIFNpZ24vVmVyaWZ5XG4gIGFzeW5jIHNpZ24oa2V5LCBtZXNzYWdlLCBoZWFkZXIgPSB7fSkgeyAvLyBQcm9taXNlIEpXUywgaW4gZ2VuZXJhbCBmb3JtIHdpdGgga2lkIGhlYWRlcnMgaWYgbmVjZXNzYXJ5LlxuICAgIGlmICghdGhpcy5pc011bHRpS2V5KGtleSkpIHJldHVybiBzdXBlci5zaWduKGtleSwgbWVzc2FnZSwgaGVhZGVyKTtcbiAgICBsZXQgaW5wdXRCdWZmZXIgPSB0aGlzLmlucHV0QnVmZmVyKG1lc3NhZ2UsIGhlYWRlciksXG4gICAgICAgIGp3cyA9IG5ldyBKT1NFLkdlbmVyYWxTaWduKGlucHV0QnVmZmVyKTtcbiAgICBmb3IgKGxldCB0YWcgb2YgdGhpcy5rZXlUYWdzKGtleSkpIHtcbiAgICAgIGxldCB0aGlzS2V5ID0ga2V5W3RhZ10sXG4gICAgICAgICAgdGhpc0hlYWRlciA9IHtraWQ6IHRhZywgYWxnOiBzaWduaW5nQWxnb3JpdGhtLCAuLi5oZWFkZXJ9O1xuICAgICAgandzLmFkZFNpZ25hdHVyZSh0aGlzS2V5KS5zZXRQcm90ZWN0ZWRIZWFkZXIodGhpc0hlYWRlcik7XG4gICAgfVxuICAgIHJldHVybiBqd3Muc2lnbigpO1xuICB9LFxuICB2ZXJpZnlTdWJTaWduYXR1cmUoandzLCBzaWduYXR1cmVFbGVtZW50LCBtdWx0aUtleSwga2lkcykge1xuICAgIC8vIFZlcmlmeSBhIHNpbmdsZSBlbGVtZW50IG9mIGp3cy5zaWduYXR1cmUgdXNpbmcgbXVsdGlLZXkuXG4gICAgLy8gQWx3YXlzIHByb21pc2VzIHtwcm90ZWN0ZWRIZWFkZXIsIHVucHJvdGVjdGVkSGVhZGVyLCBraWR9LCBldmVuIGlmIHZlcmlmaWNhdGlvbiBmYWlscyxcbiAgICAvLyB3aGVyZSBraWQgaXMgdGhlIHByb3BlcnR5IG5hbWUgd2l0aGluIG11bHRpS2V5IHRoYXQgbWF0Y2hlZCAoZWl0aGVyIGJ5IGJlaW5nIHNwZWNpZmllZCBpbiBhIGhlYWRlclxuICAgIC8vIG9yIGJ5IHN1Y2Nlc3NmdWwgdmVyaWZpY2F0aW9uKS4gQWxzbyBpbmNsdWRlcyB0aGUgZGVjb2RlZCBwYXlsb2FkIElGRiB0aGVyZSBpcyBhIG1hdGNoLlxuICAgIGxldCBwcm90ZWN0ZWRIZWFkZXIgPSBzaWduYXR1cmVFbGVtZW50LnByb3RlY3RlZEhlYWRlciA/PyB0aGlzLmRlY29kZVByb3RlY3RlZEhlYWRlcihzaWduYXR1cmVFbGVtZW50KSxcbiAgICAgICAgdW5wcm90ZWN0ZWRIZWFkZXIgPSBzaWduYXR1cmVFbGVtZW50LnVucHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICBraWQgPSBwcm90ZWN0ZWRIZWFkZXI/LmtpZCB8fCB1bnByb3RlY3RlZEhlYWRlcj8ua2lkLFxuICAgICAgICBzaW5nbGVKV1MgPSB7Li4uandzLCBzaWduYXR1cmVzOiBbc2lnbmF0dXJlRWxlbWVudF19LFxuICAgICAgICBmYWlsdXJlUmVzdWx0ID0ge3Byb3RlY3RlZEhlYWRlciwgdW5wcm90ZWN0ZWRIZWFkZXIsIGtpZH0sXG4gICAgICAgIGtpZHNUb1RyeSA9IGtpZCA/IFtraWRdIDoga2lkcztcbiAgICBsZXQgcHJvbWlzZSA9IFByb21pc2UuYW55KGtpZHNUb1RyeS5tYXAoYXN5bmMga2lkID0+IEpPU0UuZ2VuZXJhbFZlcmlmeShzaW5nbGVKV1MsIG11bHRpS2V5W2tpZF0pLnRoZW4ocmVzdWx0ID0+IHtyZXR1cm4ge2tpZCwgLi4ucmVzdWx0fTt9KSkpO1xuICAgIHJldHVybiBwcm9taXNlLmNhdGNoKCgpID0+IGZhaWx1cmVSZXN1bHQpO1xuICB9LFxuICBhc3luYyB2ZXJpZnkoa2V5LCBzaWduYXR1cmUsIG9wdGlvbnMgPSB7fSkgeyAvLyBQcm9taXNlIHtwYXlsb2FkLCB0ZXh0LCBqc29ufSwgd2hlcmUgdGV4dCBhbmQganNvbiBhcmUgb25seSBkZWZpbmVkIHdoZW4gYXBwcm9wcmlhdGUuXG4gICAgLy8gQWRkaXRpb25hbGx5LCBpZiBrZXkgaXMgYSBtdWx0aUtleSBBTkQgc2lnbmF0dXJlIGlzIGEgZ2VuZXJhbCBmb3JtIEpXUywgdGhlbiBhbnN3ZXIgaW5jbHVkZXMgYSBzaWduZXJzIHByb3BlcnR5XG4gICAgLy8gYnkgd2hpY2ggY2FsbGVyIGNhbiBkZXRlcm1pbmUgaWYgaXQgd2hhdCB0aGV5IGV4cGVjdC4gVGhlIHBheWxvYWQgb2YgZWFjaCBzaWduZXJzIGVsZW1lbnQgaXMgZGVmaW5lZCBvbmx5IHRoYXRcbiAgICAvLyBzaWduZXIgd2FzIG1hdGNoZWQgYnkgc29tZXRoaW5nIGluIGtleS5cbiAgICBcbiAgICBpZiAoIXRoaXMuaXNNdWx0aUtleShrZXkpKSByZXR1cm4gc3VwZXIudmVyaWZ5KGtleSwgc2lnbmF0dXJlLCBvcHRpb25zKTtcbiAgICBpZiAoIXNpZ25hdHVyZS5zaWduYXR1cmVzKSByZXR1cm47XG5cbiAgICAvLyBDb21wYXJpc29uIHRvIHBhbnZhIEpPU0UuZ2VuZXJhbFZlcmlmeS5cbiAgICAvLyBKT1NFIHRha2VzIGEgandzIGFuZCBPTkUga2V5IGFuZCBhbnN3ZXJzIHtwYXlsb2FkLCBwcm90ZWN0ZWRIZWFkZXIsIHVucHJvdGVjdGVkSGVhZGVyfSBtYXRjaGluZyB0aGUgb25lXG4gICAgLy8gandzLnNpZ25hdHVyZSBlbGVtZW50IHRoYXQgd2FzIHZlcmlmaWVkLCBvdGhlcmlzZSBhbiBlcm9yLiAoSXQgdHJpZXMgZWFjaCBvZiB0aGUgZWxlbWVudHMgb2YgdGhlIGp3cy5zaWduYXR1cmVzLilcbiAgICAvLyBJdCBpcyBub3QgZ2VuZXJhbGx5IHBvc3NpYmxlIHRvIGtub3cgV0hJQ0ggb25lIG9mIHRoZSBqd3Muc2lnbmF0dXJlcyB3YXMgbWF0Y2hlZC5cbiAgICAvLyAoSXQgTUFZIGJlIHBvc3NpYmxlIGlmIHRoZXJlIGFyZSB1bmlxdWUga2lkIGVsZW1lbnRzLCBidXQgdGhhdCdzIGFwcGxpY2F0aW9uLWRlcGVuZGVudC4pXG4gICAgLy9cbiAgICAvLyBNdWx0aUtyeXB0byB0YWtlcyBhIGRpY3Rpb25hcnkgdGhhdCBjb250YWlucyBuYW1lZCBrZXlzIGFuZCByZWNvZ25pemVkSGVhZGVyIHByb3BlcnRpZXMsIGFuZCBpdCByZXR1cm5zXG4gICAgLy8gYSByZXN1bHQgdGhhdCBoYXMgYSBzaWduZXJzIGFycmF5IHRoYXQgaGFzIGFuIGVsZW1lbnQgY29ycmVzcG9uZGluZyB0byBlYWNoIG9yaWdpbmFsIHNpZ25hdHVyZSBpZiBhbnlcbiAgICAvLyBhcmUgbWF0Y2hlZCBieSB0aGUgbXVsdGlrZXkuIChJZiBub25lIG1hdGNoLCB3ZSByZXR1cm4gdW5kZWZpbmVkLlxuICAgIC8vIEVhY2ggZWxlbWVudCBjb250YWlucyB0aGUga2lkLCBwcm90ZWN0ZWRIZWFkZXIsIHBvc3NpYmx5IHVucHJvdGVjdGVkSGVhZGVyLCBhbmQgcG9zc2libHkgcGF5bG9hZCAoaS5lLiBpZiBzdWNjZXNzZnVsKS5cbiAgICAvL1xuICAgIC8vIEFkZGl0aW9uYWxseSBpZiBhIHJlc3VsdCBpcyBwcm9kdWNlZCwgdGhlIG92ZXJhbGwgcHJvdGVjdGVkSGVhZGVyIGFuZCB1bnByb3RlY3RlZEhlYWRlciBjb250YWlucyBvbmx5IHZhbHVlc1xuICAgIC8vIHRoYXQgd2VyZSBjb21tb24gdG8gZWFjaCBvZiB0aGUgdmVyaWZpZWQgc2lnbmF0dXJlIGVsZW1lbnRzLlxuICAgIFxuICAgIGxldCBqd3MgPSBzaWduYXR1cmUsXG4gICAgICAgIGtpZHMgPSB0aGlzLmtleVRhZ3Moa2V5KSxcbiAgICAgICAgc2lnbmVycyA9IGF3YWl0IFByb21pc2UuYWxsKGp3cy5zaWduYXR1cmVzLm1hcChzaWduYXR1cmUgPT4gdGhpcy52ZXJpZnlTdWJTaWduYXR1cmUoandzLCBzaWduYXR1cmUsIGtleSwga2lkcykpKTtcbiAgICBpZiAoIXNpZ25lcnMuZmluZChzaWduZXIgPT4gc2lnbmVyLnBheWxvYWQpKSByZXR1cm4gdW5kZWZpbmVkO1xuICAgIC8vIE5vdyBjYW5vbmljYWxpemUgdGhlIHNpZ25lcnMgYW5kIGJ1aWxkIHVwIGEgcmVzdWx0LlxuICAgIGxldCBbZmlyc3QsIC4uLnJlc3RdID0gc2lnbmVycyxcbiAgICAgICAgcmVzdWx0ID0ge3Byb3RlY3RlZEhlYWRlcjoge30sIHVucHJvdGVjdGVkSGVhZGVyOiB7fSwgc2lnbmVyc30sXG4gICAgICAgIC8vIEZvciBhIGhlYWRlciB2YWx1ZSB0byBiZSBjb21tb24gdG8gdmVyaWZpZWQgcmVzdWx0cywgaXQgbXVzdCBiZSBpbiB0aGUgZmlyc3QgcmVzdWx0LlxuICAgICAgICBnZXRVbmlxdWUgPSBjYXRlZ29yeU5hbWUgPT4ge1xuICAgICAgICAgIGxldCBmaXJzdEhlYWRlciA9IGZpcnN0W2NhdGVnb3J5TmFtZV0sXG4gICAgICAgICAgICAgIGFjY3VtdWxhdG9ySGVhZGVyID0gcmVzdWx0W2NhdGVnb3J5TmFtZV07XG4gICAgICAgICAgZm9yIChsZXQgbGFiZWwgaW4gZmlyc3RIZWFkZXIpIHtcbiAgICAgICAgICAgIGxldCB2YWx1ZSA9IGZpcnN0SGVhZGVyW2xhYmVsXTtcbiAgICAgICAgICAgIGlmIChyZXN0LnNvbWUoc2lnbmVyUmVzdWx0ID0+IHNpZ25lclJlc3VsdFtjYXRlZ29yeU5hbWVdW2xhYmVsXSAhPT0gdmFsdWUpKSBjb250aW51ZTtcbiAgICAgICAgICAgIGFjY3VtdWxhdG9ySGVhZGVyW2xhYmVsXSA9IHZhbHVlO1xuICAgICAgICAgIH1cbiAgICAgICAgfTtcbiAgICBnZXRVbmlxdWUoJ3Byb3RlY3RlZEhlYWRlcicpO1xuICAgIGdldFVuaXF1ZSgncHJvdGVjdGVkSGVhZGVyJyk7XG4gICAgLy8gSWYgYW55dGhpbmcgdmVyaWZpZWQsIHRoZW4gc2V0IHBheWxvYWQgYW5kIGFsbG93IHRleHQvanNvbiB0byBiZSBwcm9kdWNlZC5cbiAgICAvLyBDYWxsZXJzIGNhbiBjaGVjayBzaWduZXJzW25dLnBheWxvYWQgdG8gZGV0ZXJtaW5lIGlmIHRoZSByZXN1bHQgaXMgd2hhdCB0aGV5IHdhbnQuXG4gICAgcmVzdWx0LnBheWxvYWQgPSBzaWduZXJzLmZpbmQoc2lnbmVyID0+IHNpZ25lci5wYXlsb2FkKS5wYXlsb2FkO1xuICAgIHJldHVybiB0aGlzLnJlY292ZXJEYXRhRnJvbUNvbnRlbnRUeXBlKHJlc3VsdCwgb3B0aW9ucyk7XG4gIH1cbn07XG5cbk9iamVjdC5zZXRQcm90b3R5cGVPZihNdWx0aUtyeXB0bywgS3J5cHRvKTsgLy8gSW5oZXJpdCBmcm9tIEtyeXB0byBzbyB0aGF0IHN1cGVyLm11bWJsZSgpIHdvcmtzLlxuZXhwb3J0IGRlZmF1bHQgTXVsdGlLcnlwdG87XG4iLCJjbGFzcyBQZXJzaXN0ZWRDb2xsZWN0aW9uIHtcbiAgLy8gQXN5bmNocm9ub3VzIGxvY2FsIHN0b3JhZ2UsIGF2YWlsYWJsZSBpbiB3ZWIgd29ya2Vycy5cbiAgY29uc3RydWN0b3Ioe2NvbGxlY3Rpb25OYW1lID0gJ2NvbGxlY3Rpb24nLCBkYk5hbWUgPSAnYXN5bmNMb2NhbFN0b3JhZ2UnfSA9IHt9KSB7XG4gICAgLy8gQ2FwdHVyZSB0aGUgZGF0YSBoZXJlLCBidXQgZG9uJ3Qgb3BlbiB0aGUgZGIgdW50aWwgd2UgbmVlZCB0by5cbiAgICB0aGlzLmNvbGxlY3Rpb25OYW1lID0gY29sbGVjdGlvbk5hbWU7XG4gICAgdGhpcy5kYk5hbWUgPSBkYk5hbWU7XG4gICAgdGhpcy52ZXJzaW9uID0gMTtcbiAgfVxuICBnZXQgZGIoKSB7IC8vIEFuc3dlciBhIHByb21pc2UgZm9yIHRoZSBkYXRhYmFzZSwgY3JlYXRpbmcgaXQgaWYgbmVlZGVkLlxuICAgIHJldHVybiB0aGlzLl9kYiA/Pz0gbmV3IFByb21pc2UocmVzb2x2ZSA9PiB7XG4gICAgICBjb25zdCByZXF1ZXN0ID0gaW5kZXhlZERCLm9wZW4odGhpcy5kYk5hbWUsIHRoaXMudmVyc2lvbik7XG4gICAgICAvLyBjcmVhdGVPYmplY3RTdG9yZSBjYW4gb25seSBiZSBjYWxsZWQgZnJvbSB1cGdyYWRlbmVlZGVkLCB3aGljaCBpcyBvbmx5IGNhbGxlZCBmb3IgbmV3IHZlcnNpb25zLlxuICAgICAgcmVxdWVzdC5vbnVwZ3JhZGVuZWVkZWQgPSBldmVudCA9PiBldmVudC50YXJnZXQucmVzdWx0LmNyZWF0ZU9iamVjdFN0b3JlKHRoaXMuY29sbGVjdGlvbk5hbWUpO1xuICAgICAgdGhpcy5yZXN1bHQocmVzb2x2ZSwgcmVxdWVzdCk7XG4gICAgfSk7XG4gIH1cbiAgdHJhbnNhY3Rpb24obW9kZSA9ICdyZWFkJykgeyAvLyBBbnN3ZXIgYSBwcm9taXNlIGZvciB0aGUgbmFtZWQgb2JqZWN0IHN0b3JlIG9uIGEgbmV3IHRyYW5zYWN0aW9uLlxuICAgIGNvbnN0IGNvbGxlY3Rpb25OYW1lID0gdGhpcy5jb2xsZWN0aW9uTmFtZTtcbiAgICByZXR1cm4gdGhpcy5kYi50aGVuKGRiID0+IGRiLnRyYW5zYWN0aW9uKGNvbGxlY3Rpb25OYW1lLCBtb2RlKS5vYmplY3RTdG9yZShjb2xsZWN0aW9uTmFtZSkpO1xuICB9XG4gIHJlc3VsdChyZXNvbHZlLCBvcGVyYXRpb24pIHtcbiAgICBvcGVyYXRpb24ub25zdWNjZXNzID0gZXZlbnQgPT4gcmVzb2x2ZShldmVudC50YXJnZXQucmVzdWx0IHx8ICcnKTsgLy8gTm90IHVuZGVmaW5lZC5cbiAgfVxuICByZXRyaWV2ZSh0YWcpIHsgLy8gUHJvbWlzZSB0byByZXRyaWV2ZSB0YWcgZnJvbSBjb2xsZWN0aW9uTmFtZS5cbiAgICByZXR1cm4gbmV3IFByb21pc2UocmVzb2x2ZSA9PiB7XG4gICAgICB0aGlzLnRyYW5zYWN0aW9uKCdyZWFkb25seScpLnRoZW4oc3RvcmUgPT4gdGhpcy5yZXN1bHQocmVzb2x2ZSwgc3RvcmUuZ2V0KHRhZykpKTtcbiAgICB9KTtcbiAgfVxuICBzdG9yZSh0YWcsIGRhdGEpIHsgLy8gUHJvbWlzZSB0byBzdG9yZSBkYXRhIGF0IHRhZyBpbiBjb2xsZWN0aW9uTmFtZS5cbiAgICByZXR1cm4gbmV3IFByb21pc2UocmVzb2x2ZSA9PiB7XG4gICAgICB0aGlzLnRyYW5zYWN0aW9uKCdyZWFkd3JpdGUnKS50aGVuKHN0b3JlID0+IHRoaXMucmVzdWx0KHJlc29sdmUsIHN0b3JlLnB1dChkYXRhLCB0YWcpKSk7XG4gICAgfSk7XG4gIH1cbiAgcmVtb3ZlKHRhZykgeyAvLyBQcm9taXNlIHRvIHJlbW92ZSB0YWcgZnJvbSBjb2xsZWN0aW9uTmFtZS5cbiAgICByZXR1cm4gbmV3IFByb21pc2UocmVzb2x2ZSA9PiB7XG4gICAgICB0aGlzLnRyYW5zYWN0aW9uKCdyZWFkd3JpdGUnKS50aGVuKHN0b3JlID0+IHRoaXMucmVzdWx0KHJlc29sdmUsIHN0b3JlLmRlbGV0ZSh0YWcpKSk7XG4gICAgfSk7XG4gIH1cbn1cbmV4cG9ydCBkZWZhdWx0IFBlcnNpc3RlZENvbGxlY3Rpb247XG4iLCJ2YXIgcHJvbXB0ZXIgPSBwcm9tcHRTdHJpbmcgPT4gcHJvbXB0U3RyaW5nO1xuaWYgKHR5cGVvZih3aW5kb3cpICE9PSAndW5kZWZpbmVkJykge1xuICBwcm9tcHRlciA9IHdpbmRvdy5wcm9tcHQ7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXRVc2VyRGV2aWNlU2VjcmV0KHRhZywgcHJvbXB0U3RyaW5nKSB7XG4gIHJldHVybiBwcm9tcHRTdHJpbmcgPyAodGFnICsgcHJvbXB0ZXIocHJvbXB0U3RyaW5nKSkgOiB0YWc7XG59XG4iLCJjb25zdCBvcmlnaW4gPSBuZXcgVVJMKGltcG9ydC5tZXRhLnVybCkub3JpZ2luO1xuZXhwb3J0IGRlZmF1bHQgb3JpZ2luO1xuIiwiZXhwb3J0IGNvbnN0IG1rZGlyID0gdW5kZWZpbmVkO1xuIiwiY29uc3QgdGFnQnJlYWt1cCA9IC8oXFxTezUwfSkoXFxTezJ9KShcXFN7Mn0pKFxcUyspLztcbmV4cG9ydCBmdW5jdGlvbiB0YWdQYXRoKGNvbGxlY3Rpb25OYW1lLCB0YWcsIGV4dGVuc2lvbiA9ICdqc29uJykgeyAvLyBQYXRobmFtZSB0byB0YWcgcmVzb3VyY2UuXG4gIC8vIFVzZWQgaW4gU3RvcmFnZSBVUkkgYW5kIGZpbGUgc3lzdGVtIHN0b3Jlcy4gQm90dGxlbmVja2VkIGhlcmUgdG8gcHJvdmlkZSBjb25zaXN0ZW50IGFsdGVybmF0ZSBpbXBsZW1lbnRhdGlvbnMuXG4gIC8vIFBhdGggaXMgLmpzb24gc28gdGhhdCBzdGF0aWMtZmlsZSB3ZWIgc2VydmVycyB3aWxsIHN1cHBseSBhIGpzb24gbWltZSB0eXBlLlxuICAvLyBQYXRoIGlzIGJyb2tlbiB1cCBzbyB0aGF0IGRpcmVjdG9yeSByZWFkcyBkb24ndCBnZXQgYm9nZ2VkIGRvd24gZnJvbSBoYXZpbmcgdG9vIG11Y2ggaW4gYSBkaXJlY3RvcnkuXG4gIC8vXG4gIC8vIE5PVEU6IGNoYW5nZXMgaGVyZSBtdXN0IGJlIG1hdGNoZWQgYnkgdGhlIFBVVCByb3V0ZSBzcGVjaWZpZWQgaW4gc2lnbmVkLWNsb3VkLXNlcnZlci9zdG9yYWdlLm1qcyBhbmQgdGFnTmFtZS5tanNcbiAgaWYgKCF0YWcpIHJldHVybiBjb2xsZWN0aW9uTmFtZTtcbiAgbGV0IG1hdGNoID0gdGFnLm1hdGNoKHRhZ0JyZWFrdXApO1xuICBpZiAoIW1hdGNoKSByZXR1cm4gYCR7Y29sbGVjdGlvbk5hbWV9LyR7dGFnfWA7XG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuby11bnVzZWQtdmFyc1xuICBsZXQgW18sIGEsIGIsIGMsIHJlc3RdID0gbWF0Y2g7XG4gIHJldHVybiBgJHtjb2xsZWN0aW9uTmFtZX0vJHthfS8ke2J9LyR7Y30vJHtyZXN0fS4ke2V4dGVuc2lvbn1gO1xufVxuIiwiaW1wb3J0IG9yaWdpbiBmcm9tICcjb3JpZ2luJzsgLy8gV2hlbiBydW5uaW5nIGluIGEgYnJvd3NlciwgbG9jYXRpb24ub3JpZ2luIHdpbGwgYmUgZGVmaW5lZC4gSGVyZSB3ZSBhbGxvdyBmb3IgTm9kZUpTLlxuaW1wb3J0IHtta2Rpcn0gZnJvbSAnI21rZGlyJztcbmltcG9ydCB7dGFnUGF0aH0gZnJvbSAnLi90YWdQYXRoLm1qcyc7XG5cbmFzeW5jIGZ1bmN0aW9uIHJlc3BvbnNlSGFuZGxlcihyZXNwb25zZSkge1xuICAvLyBSZWplY3QgaWYgc2VydmVyIGRvZXMsIGVsc2UgcmVzcG9uc2UudGV4dCgpLlxuICBpZiAocmVzcG9uc2Uuc3RhdHVzID09PSA0MDQpIHJldHVybiAnJztcbiAgaWYgKCFyZXNwb25zZS5vaykgcmV0dXJuIFByb21pc2UucmVqZWN0KHJlc3BvbnNlLnN0YXR1c1RleHQpO1xuICBsZXQgdGV4dCA9IGF3YWl0IHJlc3BvbnNlLnRleHQoKTtcbiAgaWYgKCF0ZXh0KSByZXR1cm4gdGV4dDsgLy8gUmVzdWx0IG9mIHN0b3JlIGNhbiBiZSBlbXB0eS5cbiAgcmV0dXJuIEpTT04ucGFyc2UodGV4dCk7XG59XG5cbmNvbnN0IFN0b3JhZ2UgPSB7XG4gIGdldCBvcmlnaW4oKSB7IHJldHVybiBvcmlnaW47IH0sXG4gIHRhZ1BhdGgsXG4gIG1rZGlyLFxuICB1cmkoY29sbGVjdGlvbk5hbWUsIHRhZykge1xuICAgIC8vIFBhdGhuYW1lIGV4cGVjdGVkIGJ5IG91ciBzaWduZWQtY2xvdWQtc2VydmVyLlxuICAgIHJldHVybiBgJHtvcmlnaW59L2RiLyR7dGhpcy50YWdQYXRoKGNvbGxlY3Rpb25OYW1lLCB0YWcpfWA7XG4gIH0sXG4gIHN0b3JlKGNvbGxlY3Rpb25OYW1lLCB0YWcsIHNpZ25hdHVyZSwgb3B0aW9ucyA9IHt9KSB7XG4gICAgLy8gU3RvcmUgdGhlIHNpZ25lZCBjb250ZW50IG9uIHRoZSBzaWduZWQtY2xvdWQtc2VydmVyLCByZWplY3RpbmcgaWZcbiAgICAvLyB0aGUgc2VydmVyIGlzIHVuYWJsZSB0byB2ZXJpZnkgdGhlIHNpZ25hdHVyZSBmb2xsb3dpbmcgdGhlIHJ1bGVzIG9mXG4gICAgLy8gaHR0cHM6Ly9raWxyb3ktY29kZS5naXRodWIuaW8vZGlzdHJpYnV0ZWQtc2VjdXJpdHkvI3N0b3Jpbmcta2V5cy11c2luZy10aGUtY2xvdWQtc3RvcmFnZS1hcGlcbiAgICByZXR1cm4gZmV0Y2godGhpcy51cmkoY29sbGVjdGlvbk5hbWUsIHRhZyksIHtcbiAgICAgIG1ldGhvZDogJ1BVVCcsXG4gICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShzaWduYXR1cmUpLFxuICAgICAgaGVhZGVyczogeydDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsIC4uLihvcHRpb25zLmhlYWRlcnMgfHwge30pfVxuICAgIH0pLnRoZW4ocmVzcG9uc2VIYW5kbGVyKTtcbiAgfSxcbiAgcmV0cmlldmUoY29sbGVjdGlvbk5hbWUsIHRhZywgb3B0aW9ucyA9IHt9KSB7XG4gICAgLy8gV2UgZG8gbm90IHZlcmlmeSBhbmQgZ2V0IHRoZSBvcmlnaW5hbCBkYXRhIG91dCBoZXJlLCBiZWNhdXNlIHRoZSBjYWxsZXIgaGFzXG4gICAgLy8gdGhlIHJpZ2h0IHRvIGRvIHNvIHdpdGhvdXQgdHJ1c3RpbmcgdXMuXG4gICAgcmV0dXJuIGZldGNoKHRoaXMudXJpKGNvbGxlY3Rpb25OYW1lLCB0YWcpLCB7XG4gICAgICBjYWNoZTogJ2RlZmF1bHQnLFxuICAgICAgaGVhZGVyczogeydBY2NlcHQnOiAnYXBwbGljYXRpb24vanNvbicsIC4uLihvcHRpb25zLmhlYWRlcnMgfHwge30pfVxuICAgIH0pLnRoZW4ocmVzcG9uc2VIYW5kbGVyKTtcbiAgfVxufTtcbmV4cG9ydCBkZWZhdWx0IFN0b3JhZ2U7XG4iLCJpbXBvcnQgTXVsdGlLcnlwdG8gZnJvbSAnLi9tdWx0aUtyeXB0by5tanMnO1xuaW1wb3J0IExvY2FsQ29sbGVjdGlvbiBmcm9tICcjbG9jYWxTdG9yZSc7XG5pbXBvcnQge2dldFVzZXJEZXZpY2VTZWNyZXR9IGZyb20gJy4vc2VjcmV0Lm1qcyc7XG5pbXBvcnQgU3RvcmFnZSBmcm9tICcuL3N0b3JhZ2UubWpzJztcblxuZnVuY3Rpb24gZXJyb3IodGVtcGxhdGVGdW5jdGlvbiwgdGFnLCBjYXVzZSA9IHVuZGVmaW5lZCkge1xuICAvLyBGb3JtYXRzIHRhZyAoZS5nLiwgc2hvcnRlbnMgaXQpIGFuZCBnaXZlcyBpdCB0byB0ZW1wbGF0ZUZ1bmN0aW9uKHRhZykgdG8gZ2V0XG4gIC8vIGEgc3VpdGFibGUgZXJyb3IgbWVzc2FnZS4gQW5zd2VycyBhIHJlamVjdGVkIHByb21pc2Ugd2l0aCB0aGF0IEVycm9yLlxuICBsZXQgc2hvcnRlbmVkVGFnID0gdGFnLnNsaWNlKDAsIDE2KSArIFwiLi4uXCIsXG4gICAgICBtZXNzYWdlID0gdGVtcGxhdGVGdW5jdGlvbihzaG9ydGVuZWRUYWcpO1xuICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IEVycm9yKG1lc3NhZ2UsIHtjYXVzZX0pKTtcbn1cbmZ1bmN0aW9uIHVuYXZhaWxhYmxlKHRhZykgeyAvLyBEbyB3ZSB3YW50IHRvIGRpc3Rpbmd1aXNoIGJldHdlZW4gYSB0YWcgYmVpbmdcbiAgLy8gdW5hdmFpbGFibGUgYXQgYWxsLCB2cyBqdXN0IHRoZSBwdWJsaWMgZW5jcnlwdGlvbiBrZXkgYmVpbmcgdW5hdmFpbGFibGU/XG4gIC8vIFJpZ2h0IG5vdyB3ZSBkbyBub3QgZGlzdGluZ3Vpc2gsIGFuZCB1c2UgdGhpcyBmb3IgYm90aC5cbiAgcmV0dXJuIGVycm9yKHRhZyA9PiBgVGhlIHRhZyAke3RhZ30gaXMgbm90IGF2YWlsYWJsZS5gLCB0YWcpO1xufVxuXG5leHBvcnQgY2xhc3MgS2V5U2V0IHtcbiAgLy8gQSBLZXlTZXQgbWFpbnRhaW5zIHR3byBwcml2YXRlIGtleXM6IHNpZ25pbmdLZXkgYW5kIGRlY3J5cHRpbmdLZXkuXG4gIC8vIFNlZSBodHRwczovL2tpbHJveS1jb2RlLmdpdGh1Yi5pby9kaXN0cmlidXRlZC1zZWN1cml0eS9kb2NzL2ltcGxlbWVudGF0aW9uLmh0bWwjd2ViLXdvcmtlci1hbmQtaWZyYW1lXG5cbiAgLy8gQ2FjaGluZ1xuICBzdGF0aWMga2V5U2V0cyA9IHt9O1xuICBzdGF0aWMgY2FjaGVkKHRhZykgeyAvLyBSZXR1cm4gYW4gYWxyZWFkeSBwb3B1bGF0ZWQgS2V5U2V0LlxuICAgIHJldHVybiB0aGlzLmtleVNldHNbdGFnXTtcbiAgfVxuICBzdGF0aWMgY2xlYXIodGFnID0gbnVsbCkgeyAvLyBSZW1vdmUgYWxsIEtleVNldCBpbnN0YW5jZXMgb3IganVzdCB0aGUgc3BlY2lmaWVkIG9uZSwgYnV0IGRvZXMgbm90IGRlc3Ryb3kgdGhlaXIgc3RvcmFnZS5cbiAgICBpZiAoIXRhZykgcmV0dXJuIEtleVNldC5rZXlTZXRzID0ge307XG4gICAgZGVsZXRlIEtleVNldC5rZXlTZXRzW3RhZ11cbiAgfVxuICBjb25zdHJ1Y3Rvcih0YWcpIHtcbiAgICB0aGlzLnRhZyA9IHRhZztcbiAgICB0aGlzLm1lbWJlclRhZ3MgPSBbXTsgLy8gVXNlZCB3aGVuIHJlY3Vyc2l2ZWx5IGRlc3Ryb3lpbmcuXG4gICAgS2V5U2V0LmtleVNldHNbdGFnXSA9IHRoaXM7IC8vIENhY2hlIGl0LlxuICB9XG4gIC8vIGFwaS5tanMgcHJvdmlkZXMgdGhlIHNldHRlciB0byBjaGFuZ2VzIHRoZXNlLCBhbmQgd29ya2VyLm1qcyBleGVyY2lzZXMgaXQgaW4gYnJvd3NlcnMuXG4gIHN0YXRpYyBnZXRVc2VyRGV2aWNlU2VjcmV0ID0gZ2V0VXNlckRldmljZVNlY3JldDtcbiAgc3RhdGljIFN0b3JhZ2UgPSBTdG9yYWdlO1xuXG4gIC8vIFByaW5jaXBsZSBvcGVyYXRpb25zLlxuICBzdGF0aWMgYXN5bmMgY3JlYXRlKHdyYXBwaW5nRGF0YSkgeyAvLyBDcmVhdGUgYSBwZXJzaXN0ZWQgS2V5U2V0IG9mIHRoZSBjb3JyZWN0IHR5cGUsIHByb21pc2luZyB0aGUgbmV3bHkgY3JlYXRlZCB0YWcuXG4gICAgbGV0IHt0aW1lLCAuLi5rZXlzfSA9IGF3YWl0IHRoaXMuY3JlYXRlS2V5cyh3cmFwcGluZ0RhdGEpLFxuICAgICAgICB7dGFnfSA9IGtleXM7XG4gICAgYXdhaXQgdGhpcy5wZXJzaXN0KHRhZywga2V5cywgd3JhcHBpbmdEYXRhLCB0aW1lKTtcbiAgICByZXR1cm4gdGFnO1xuICB9XG4gIGFzeW5jIGRlc3Ryb3kob3B0aW9ucyA9IHt9KSB7IC8vIFRlcm1pbmF0ZXMgdGhpcyBrZXlTZXQgYW5kIGFzc29jaWF0ZWQgc3RvcmFnZSwgYW5kIHNhbWUgZm9yIE9XTkVEIHJlY3Vyc2l2ZU1lbWJlcnMgaWYgYXNrZWQuXG4gICAgbGV0IHt0YWcsIG1lbWJlclRhZ3MsIHNpZ25pbmdLZXl9ID0gdGhpcyxcbiAgICAgICAgY29udGVudCA9IFwiXCIsIC8vIFNob3VsZCBzdG9yYWdlIGhhdmUgYSBzZXBhcmF0ZSBvcGVyYXRpb24gdG8gZGVsZXRlLCBvdGhlciB0aGFuIHN0b3JpbmcgZW1wdHk/XG4gICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IHRoaXMuY29uc3RydWN0b3Iuc2lnbkZvclN0b3JhZ2Uoe21lc3NhZ2U6IGNvbnRlbnQsIHRhZywgbWVtYmVyVGFncywgc2lnbmluZ0tleSwgdGltZTogRGF0ZS5ub3coKX0pO1xuICAgIGF3YWl0IHRoaXMuY29uc3RydWN0b3Iuc3RvcmUoJ0VuY3J5cHRpb25LZXknLCB0YWcsIHNpZ25hdHVyZSk7XG4gICAgYXdhaXQgdGhpcy5jb25zdHJ1Y3Rvci5zdG9yZSh0aGlzLmNvbnN0cnVjdG9yLmNvbGxlY3Rpb24sIHRhZywgc2lnbmF0dXJlKTtcbiAgICB0aGlzLmNvbnN0cnVjdG9yLmNsZWFyKHRhZyk7XG4gICAgaWYgKCFvcHRpb25zLnJlY3Vyc2l2ZU1lbWJlcnMpIHJldHVybjtcbiAgICBhd2FpdCBQcm9taXNlLmFsbFNldHRsZWQodGhpcy5tZW1iZXJUYWdzLm1hcChhc3luYyBtZW1iZXJUYWcgPT4ge1xuICAgICAgbGV0IG1lbWJlcktleVNldCA9IGF3YWl0IEtleVNldC5lbnN1cmUobWVtYmVyVGFnKTtcbiAgICAgIGF3YWl0IG1lbWJlcktleVNldC5kZXN0cm95KG9wdGlvbnMpO1xuICAgIH0pKTtcbiAgfVxuICBkZWNyeXB0KGVuY3J5cHRlZCwgb3B0aW9ucykgeyAvLyBQcm9taXNlIHtwYXlsb2FkLCB0ZXh0LCBqc29ufSBhcyBhcHByb3ByaWF0ZS5cbiAgICBsZXQge3RhZywgZGVjcnlwdGluZ0tleX0gPSB0aGlzLFxuICAgICAgICBrZXkgPSBlbmNyeXB0ZWQucmVjaXBpZW50cyA/IHtbdGFnXTogZGVjcnlwdGluZ0tleX0gOiBkZWNyeXB0aW5nS2V5O1xuICAgIHJldHVybiBNdWx0aUtyeXB0by5kZWNyeXB0KGtleSwgZW5jcnlwdGVkLCBvcHRpb25zKTtcbiAgfVxuICAvLyBzaWduIGFzIGVpdGhlciBjb21wYWN0IG9yIG11bHRpS2V5IGdlbmVyYWwgSldTLlxuICAvLyBUaGVyZSdzIHNvbWUgY29tcGxleGl0eSBoZXJlIGFyb3VuZCBiZWluZyBhYmxlIHRvIHBhc3MgaW4gbWVtYmVyVGFncyBhbmQgc2lnbmluZ0tleSB3aGVuIHRoZSBrZXlTZXQgaXNcbiAgLy8gYmVpbmcgY3JlYXRlZCBhbmQgZG9lc24ndCB5ZXQgZXhpc3QuXG4gIHN0YXRpYyBhc3luYyBzaWduKG1lc3NhZ2UsIHt0YWdzID0gW10sIHRlYW06aXNzLCBtZW1iZXI6YWN0LCB0aW1lOmlhdCA9IGlzcyAmJiBEYXRlLm5vdygpLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgbWVtYmVyVGFncywgc2lnbmluZ0tleSxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC4uLm9wdGlvbnN9KSB7XG4gICAgaWYgKGlzcyAmJiAhYWN0KSB7IC8vIFN1cHBseSB0aGUgdmFsdWVcbiAgICAgIGlmICghbWVtYmVyVGFncykgbWVtYmVyVGFncyA9IChhd2FpdCBLZXlTZXQuZW5zdXJlKGlzcykpLm1lbWJlclRhZ3M7XG4gICAgICBsZXQgY2FjaGVkTWVtYmVyID0gbWVtYmVyVGFncy5maW5kKHRhZyA9PiB0aGlzLmNhY2hlZCh0YWcpKTtcbiAgICAgIGFjdCA9IGNhY2hlZE1lbWJlciB8fCBhd2FpdCBQcm9taXNlLmFueShtZW1iZXJUYWdzLm1hcCh0YWcgPT4gS2V5U2V0LmVuc3VyZSh0YWcpKSkudGhlbihrZXlTZXQgPT4ga2V5U2V0LnRhZylcbiAgICB9XG4gICAgaWYgKGlzcyAmJiAhdGFncy5pbmNsdWRlcyhpc3MpKSB0YWdzID0gW2lzcywgLi4udGFnc107IC8vIE11c3QgYmUgZmlyc3RcbiAgICBpZiAoYWN0ICYmICF0YWdzLmluY2x1ZGVzKGFjdCkpIHRhZ3MgPSBbLi4udGFncywgYWN0XTtcblxuICAgIGxldCBrZXkgPSBhd2FpdCB0aGlzLnByb2R1Y2VLZXkodGFncywgYXN5bmMgdGFnID0+IHtcbiAgICAgIC8vIFVzZSBzcGVjaWZpZWQgc2lnbmluZ0tleSAoaWYgYW55KSBmb3IgdGhlIGZpcnN0IG9uZS5cbiAgICAgIGxldCBrZXkgPSBzaWduaW5nS2V5IHx8IChhd2FpdCBLZXlTZXQuZW5zdXJlKHRhZykpLnNpZ25pbmdLZXk7XG4gICAgICBzaWduaW5nS2V5ID0gbnVsbDtcbiAgICAgIHJldHVybiBrZXk7XG4gICAgfSwgb3B0aW9ucyk7XG4gICAgcmV0dXJuIE11bHRpS3J5cHRvLnNpZ24oa2V5LCBtZXNzYWdlLCB7aXNzLCBhY3QsIGlhdCwgLi4ub3B0aW9uc30pO1xuICB9XG5cbiAgLy8gVmVyaWZ5IGluIHRoZSBub3JtYWwgd2F5LCBhbmQgdGhlbiBjaGVjayBkZWVwbHkgaWYgYXNrZWQuXG4gIHN0YXRpYyBhc3luYyB2ZXJpZnkoc2lnbmF0dXJlLCB0YWdzLCBvcHRpb25zKSB7XG4gICAgbGV0IGlzQ29tcGFjdCA9ICFzaWduYXR1cmUuc2lnbmF0dXJlcyxcbiAgICAgICAga2V5ID0gYXdhaXQgdGhpcy5wcm9kdWNlS2V5KHRhZ3MsIHRhZyA9PiBLZXlTZXQudmVyaWZ5aW5nS2V5KHRhZyksIG9wdGlvbnMsIGlzQ29tcGFjdCksXG4gICAgICAgIHJlc3VsdCA9IGF3YWl0IE11bHRpS3J5cHRvLnZlcmlmeShrZXksIHNpZ25hdHVyZSwgb3B0aW9ucyksXG4gICAgICAgIG1lbWJlclRhZyA9IG9wdGlvbnMubWVtYmVyID09PSB1bmRlZmluZWQgPyByZXN1bHQ/LnByb3RlY3RlZEhlYWRlci5hY3QgOiBvcHRpb25zLm1lbWJlcixcbiAgICAgICAgbm90QmVmb3JlID0gb3B0aW9ucy5ub3RCZWZvcmU7XG4gICAgZnVuY3Rpb24gZXhpdChsYWJlbCkge1xuICAgICAgaWYgKG9wdGlvbnMuaGFyZEVycm9yKSByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IEVycm9yKGxhYmVsKSk7XG4gICAgfVxuICAgIGlmICghcmVzdWx0KSByZXR1cm4gZXhpdCgnSW5jb3JyZWN0IHNpZ25hdHVyZS4nKTtcbiAgICBpZiAobWVtYmVyVGFnKSB7XG4gICAgICBpZiAob3B0aW9ucy5tZW1iZXIgPT09ICd0ZWFtJykge1xuICAgICAgICBtZW1iZXJUYWcgPSByZXN1bHQucHJvdGVjdGVIZWFkZXIuYWN0O1xuICAgICAgICBpZiAoIW1lbWJlclRhZykgcmV0dXJuIGV4aXQoJ05vIG1lbWJlciBpZGVudGlmaWVkIGluIHNpZ25hdHVyZS4nKTtcbiAgICAgIH1cbiAgICAgIGlmICghdGFncy5pbmNsdWRlcyhtZW1iZXJUYWcpKSB7IC8vIEFkZCB0byB0YWdzIGFuZCByZXN1bHQgaWYgbm90IGFscmVhZHkgcHJlc2VudFxuICAgICAgICBsZXQgbWVtYmVyS2V5ID0gYXdhaXQgS2V5U2V0LnZlcmlmeWluZ0tleShtZW1iZXJUYWcpLFxuICAgICAgICAgICAgbWVtYmVyTXVsdGlrZXkgPSB7W21lbWJlclRhZ106IG1lbWJlcktleX0sXG4gICAgICAgICAgICBhdXggPSBhd2FpdCBNdWx0aUtyeXB0by52ZXJpZnkobWVtYmVyTXVsdGlrZXksIHNpZ25hdHVyZSwgb3B0aW9ucyk7XG4gICAgICAgIGlmICghYXV4KSByZXR1cm4gZXhpdCgnSW5jb3JyZWN0IG1lbWJlciBzaWduYXR1cmUuJyk7XG4gICAgICAgIHRhZ3MucHVzaChtZW1iZXJUYWcpO1xuICAgICAgICByZXN1bHQuc2lnbmVycy5maW5kKHNpZ25lciA9PiBzaWduZXIucHJvdGVjdGVkSGVhZGVyLmtpZCA9PT0gbWVtYmVyVGFnKS5wYXlsb2FkID0gcmVzdWx0LnBheWxvYWQ7XG4gICAgICB9XG4gICAgfVxuICAgIGlmIChtZW1iZXJUYWcgfHwgbm90QmVmb3JlID09PSAndGVhbScpIHtcbiAgICAgIGxldCB0ZWFtVGFnID0gcmVzdWx0LnByb3RlY3RlZEhlYWRlci5pc3MgfHwgcmVzdWx0LnByb3RlY3RlZEhlYWRlci5raWQsIC8vIE11bHRpIG9yIHNpbmdsZSBjYXNlLlxuICAgICAgICAgIHZlcmlmaWVkSldTID0gYXdhaXQgdGhpcy5yZXRyaWV2ZShUZWFtS2V5U2V0LmNvbGxlY3Rpb24sIHRlYW1UYWcpLFxuICAgICAgICAgIGp3ZSA9IHZlcmlmaWVkSldTPy5qc29uO1xuICAgICAgaWYgKG1lbWJlclRhZyAmJiAhdGVhbVRhZykgcmV0dXJuIGV4aXQoJ05vIHRlYW0gb3IgbWFpbiB0YWcgaWRlbnRpZmllZCBpbiBzaWduYXR1cmUnKTtcbiAgICAgIGlmIChtZW1iZXJUYWcgJiYgandlICYmICFqd2UucmVjaXBpZW50cy5maW5kKG1lbWJlciA9PiBtZW1iZXIuaGVhZGVyLmtpZCA9PT0gbWVtYmVyVGFnKSkgcmV0dXJuIGV4aXQoJ1NpZ25lciBpcyBub3QgYSBtZW1iZXIuJyk7XG4gICAgICBpZiAobm90QmVmb3JlID09PSAndGVhbScpIG5vdEJlZm9yZSA9IHZlcmlmaWVkSldTPy5wcm90ZWN0ZWRIZWFkZXIuaWF0XG4gICAgICAgIHx8IChhd2FpdCB0aGlzLnJldHJpZXZlKCdFbmNyeXB0aW9uS2V5JywgdGVhbVRhZykpPy5wcm90ZWN0ZWRIZWFkZXIuaWF0O1xuICAgIH1cbiAgICBpZiAobm90QmVmb3JlKSB7XG4gICAgICBsZXQge2lhdH0gPSByZXN1bHQucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgaWYgKGlhdCA8IG5vdEJlZm9yZSkgcmV0dXJuIGV4aXQoJ1NpZ25hdHVyZSBwcmVkYXRlcyByZXF1aXJlZCB0aW1lc3RhbXAuJyk7XG4gICAgfVxuICAgIC8vIEVhY2ggc2lnbmVyIHNob3VsZCBub3cgYmUgdmVyaWZpZWQuXG4gICAgaWYgKChyZXN1bHQuc2lnbmVycz8uZmlsdGVyKHNpZ25lciA9PiBzaWduZXIucGF5bG9hZCkubGVuZ3RoIHx8IDEpICE9PSB0YWdzLmxlbmd0aCkgcmV0dXJuIGV4aXQoJ1VudmVyaWZpZWQgc2lnbmVyJyk7XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfVxuXG4gIC8vIEtleSBtYW5hZ2VtZW50XG4gIHN0YXRpYyBhc3luYyBwcm9kdWNlS2V5KHRhZ3MsIHByb2R1Y2VyLCBvcHRpb25zLCB1c2VTaW5nbGVLZXkgPSB0YWdzLmxlbmd0aCA9PT0gMSkge1xuICAgIC8vIFByb21pc2UgYSBrZXkgb3IgbXVsdGlLZXksIGFzIGRlZmluZWQgYnkgcHJvZHVjZXIodGFnKSBmb3IgZWFjaCBrZXkuXG4gICAgaWYgKHVzZVNpbmdsZUtleSkge1xuICAgICAgbGV0IHRhZyA9IHRhZ3NbMF07XG4gICAgICBvcHRpb25zLmtpZCA9IHRhZzsgICAvLyBCYXNoZXMgb3B0aW9ucyBpbiB0aGUgc2luZ2xlLWtleSBjYXNlLCBiZWNhdXNlIG11bHRpS2V5J3MgaGF2ZSB0aGVpciBvd24uXG4gICAgICByZXR1cm4gcHJvZHVjZXIodGFnKTtcbiAgICB9XG4gICAgbGV0IGtleSA9IHt9LFxuICAgICAgICBrZXlzID0gYXdhaXQgUHJvbWlzZS5hbGwodGFncy5tYXAodGFnID0+IHByb2R1Y2VyKHRhZykpKTtcbiAgICAvLyBUaGlzIGlzbid0IGRvbmUgaW4gb25lIHN0ZXAsIGJlY2F1c2Ugd2UnZCBsaWtlIChmb3IgZGVidWdnaW5nIGFuZCB1bml0IHRlc3RzKSB0byBtYWludGFpbiBhIHByZWRpY3RhYmxlIG9yZGVyLlxuICAgIHRhZ3MuZm9yRWFjaCgodGFnLCBpbmRleCkgPT4ga2V5W3RhZ10gPSBrZXlzW2luZGV4XSk7XG4gICAgcmV0dXJuIGtleTtcbiAgfVxuICAvLyBUaGUgY29ycmVzcG9uZGluZyBwdWJsaWMga2V5cyBhcmUgYXZhaWxhYmxlIHB1YmxpY2FsbHksIG91dHNpZGUgdGhlIGtleVNldC5cbiAgc3RhdGljIHZlcmlmeWluZ0tleSh0YWcpIHsgLy8gUHJvbWlzZSB0aGUgb3JkaW5hcnkgc2luZ3VsYXIgcHVibGljIGtleSBjb3JyZXNwb25kaW5nIHRvIHRoZSBzaWduaW5nIGtleSwgZGlyZWN0bHkgZnJvbSB0aGUgdGFnIHdpdGhvdXQgcmVmZXJlbmNlIHRvIHN0b3JhZ2UuXG4gICAgcmV0dXJuIE11bHRpS3J5cHRvLmltcG9ydFJhdyh0YWcpLmNhdGNoKCgpID0+IHVuYXZhaWxhYmxlKHRhZykpO1xuICB9XG4gIHN0YXRpYyBhc3luYyBlbmNyeXB0aW5nS2V5KHRhZykgeyAvLyBQcm9taXNlIHRoZSBvcmRpbmFyeSBzaW5ndWxhciBwdWJsaWMga2V5IGNvcnJlc3BvbmRpbmcgdG8gdGhlIGRlY3J5cHRpb24ga2V5LCB3aGljaCBkZXBlbmRzIG9uIHB1YmxpYyBzdG9yYWdlLlxuICAgIGxldCBleHBvcnRlZFB1YmxpY0tleSA9IGF3YWl0IHRoaXMucmV0cmlldmUoJ0VuY3J5cHRpb25LZXknLCB0YWcpO1xuICAgIGlmICghZXhwb3J0ZWRQdWJsaWNLZXkpIHJldHVybiB1bmF2YWlsYWJsZSh0YWcpO1xuICAgIHJldHVybiBhd2FpdCBNdWx0aUtyeXB0by5pbXBvcnRKV0soZXhwb3J0ZWRQdWJsaWNLZXkuanNvbik7XG4gIH1cbiAgc3RhdGljIGFzeW5jIGNyZWF0ZUtleXMobWVtYmVyVGFncykgeyAvLyBQcm9taXNlIGEgbmV3IHRhZyBhbmQgcHJpdmF0ZSBrZXlzLCBhbmQgc3RvcmUgdGhlIGVuY3J5cHRpbmcga2V5LlxuICAgIGxldCB7cHVibGljS2V5OnZlcmlmeWluZ0tleSwgcHJpdmF0ZUtleTpzaWduaW5nS2V5fSA9IGF3YWl0IE11bHRpS3J5cHRvLmdlbmVyYXRlU2lnbmluZ0tleSgpLFxuICAgICAgICB7cHVibGljS2V5OmVuY3J5cHRpbmdLZXksIHByaXZhdGVLZXk6ZGVjcnlwdGluZ0tleX0gPSBhd2FpdCBNdWx0aUtyeXB0by5nZW5lcmF0ZUVuY3J5cHRpbmdLZXkoKSxcbiAgICAgICAgdGFnID0gYXdhaXQgTXVsdGlLcnlwdG8uZXhwb3J0UmF3KHZlcmlmeWluZ0tleSksXG4gICAgICAgIGV4cG9ydGVkRW5jcnlwdGluZ0tleSA9IGF3YWl0IE11bHRpS3J5cHRvLmV4cG9ydEpXSyhlbmNyeXB0aW5nS2V5KSxcbiAgICAgICAgdGltZSA9IERhdGUubm93KCksXG4gICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IHRoaXMuc2lnbkZvclN0b3JhZ2Uoe21lc3NhZ2U6IGV4cG9ydGVkRW5jcnlwdGluZ0tleSwgdGFnLCBzaWduaW5nS2V5LCBtZW1iZXJUYWdzLCB0aW1lfSk7XG4gICAgYXdhaXQgdGhpcy5zdG9yZSgnRW5jcnlwdGlvbktleScsIHRhZywgc2lnbmF0dXJlKTtcbiAgICByZXR1cm4ge3NpZ25pbmdLZXksIGRlY3J5cHRpbmdLZXksIHRhZywgdGltZX07XG4gIH1cbiAgc3RhdGljIGdldFdyYXBwZWQodGFnKSB7IC8vIFByb21pc2UgdGhlIHdyYXBwZWQga2V5IGFwcHJvcHJpYXRlIGZvciB0aGlzIGNsYXNzLlxuICAgIHJldHVybiB0aGlzLnJldHJpZXZlKHRoaXMuY29sbGVjdGlvbiwgdGFnKTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgZW5zdXJlKHRhZykgeyAvLyBQcm9taXNlIHRvIHJlc29sdmUgdG8gYSB2YWxpZCBrZXlTZXQsIGVsc2UgcmVqZWN0LlxuICAgIGxldCBrZXlTZXQgPSB0aGlzLmNhY2hlZCh0YWcpLFxuICAgICAgICBzdG9yZWQgPSBhd2FpdCBEZXZpY2VLZXlTZXQuZ2V0V3JhcHBlZCh0YWcpO1xuICAgIGlmIChzdG9yZWQpIHtcbiAgICAgIGtleVNldCA9IG5ldyBEZXZpY2VLZXlTZXQodGFnKTtcbiAgICB9IGVsc2UgaWYgKChzdG9yZWQgPSBhd2FpdCBUZWFtS2V5U2V0LmdldFdyYXBwZWQodGFnKSkpIHtcbiAgICAgIGtleVNldCA9IG5ldyBUZWFtS2V5U2V0KHRhZyk7XG4gICAgfSBlbHNlIGlmICgoc3RvcmVkID0gYXdhaXQgUmVjb3ZlcnlLZXlTZXQuZ2V0V3JhcHBlZCh0YWcpKSkge1xuICAgICAga2V5U2V0ID0gbmV3IFJlY292ZXJ5S2V5U2V0KHRhZyk7XG4gICAgfVxuICAgIC8vIElmIHRoaW5ncyBoYXZlbid0IGNoYW5nZWQsIGRvbid0IGJvdGhlciB3aXRoIHNldFVud3JhcHBlZC5cbiAgICBpZiAoa2V5U2V0Py5jYWNoZWQgJiYga2V5U2V0LmNhY2hlZCA9PT0gc3RvcmVkICYmIGtleVNldC5kZWNyeXB0aW5nS2V5ICYmIGtleVNldC5zaWduaW5nS2V5KSByZXR1cm4ga2V5U2V0O1xuICAgIGlmIChzdG9yZWQpIGtleVNldC5jYWNoZWQgPSBzdG9yZWQ7XG4gICAgZWxzZSB7IC8vIE5vdCBmb3VuZC4gQ291bGQgYmUgYSBib2d1cyB0YWcsIG9yIG9uZSBvbiBhbm90aGVyIGNvbXB1dGVyLlxuICAgICAgdGhpcy5jbGVhcih0YWcpO1xuICAgICAgcmV0dXJuIHVuYXZhaWxhYmxlKHRhZyk7XG4gICAgfVxuICAgIHJldHVybiBrZXlTZXQudW53cmFwKGtleVNldC5jYWNoZWQpLnRoZW4oXG4gICAgICB1bndyYXBwZWQgPT4gT2JqZWN0LmFzc2lnbihrZXlTZXQsIHVud3JhcHBlZCksXG4gICAgICBjYXVzZSA9PiB7XG4gICAgICAgIHRoaXMuY2xlYXIoa2V5U2V0LnRhZylcbiAgICAgICAgcmV0dXJuIGVycm9yKHRhZyA9PiBgWW91IGRvIG5vdCBoYXZlIGFjY2VzcyB0byB0aGUgcHJpdmF0ZSBrZXkgZm9yICR7dGFnfS5gLCBrZXlTZXQudGFnLCBjYXVzZSk7XG4gICAgICB9KTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgcGVyc2lzdCh0YWcsIGtleXMsIHdyYXBwaW5nRGF0YSwgdGltZSA9IERhdGUubm93KCksIG1lbWJlclRhZ3MgPSB3cmFwcGluZ0RhdGEpIHsgLy8gUHJvbWlzZSB0byB3cmFwIGEgc2V0IG9mIGtleXMgZm9yIHRoZSB3cmFwcGluZ0RhdGEgbWVtYmVycywgYW5kIHBlcnNpc3QgYnkgdGFnLlxuICAgIGxldCB7c2lnbmluZ0tleX0gPSBrZXlzLFxuICAgICAgICB3cmFwcGVkID0gYXdhaXQgdGhpcy53cmFwKGtleXMsIHdyYXBwaW5nRGF0YSksXG4gICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IHRoaXMuc2lnbkZvclN0b3JhZ2Uoe21lc3NhZ2U6IHdyYXBwZWQsIHRhZywgc2lnbmluZ0tleSwgbWVtYmVyVGFncywgdGltZX0pO1xuICAgIGF3YWl0IHRoaXMuc3RvcmUodGhpcy5jb2xsZWN0aW9uLCB0YWcsIHNpZ25hdHVyZSk7XG4gIH1cblxuICAvLyBJbnRlcmFjdGlvbnMgd2l0aCB0aGUgY2xvdWQgb3IgbG9jYWwgc3RvcmFnZS5cbiAgc3RhdGljIGFzeW5jIHN0b3JlKGNvbGxlY3Rpb25OYW1lLCB0YWcsIHNpZ25hdHVyZSkgeyAvLyBTdG9yZSBzaWduYXR1cmUuXG4gICAgaWYgKGNvbGxlY3Rpb25OYW1lID09PSBEZXZpY2VLZXlTZXQuY29sbGVjdGlvbikge1xuICAgICAgLy8gV2UgY2FsbGVkIHRoaXMuIE5vIG5lZWQgdG8gdmVyaWZ5IGhlcmUuIEJ1dCBzZWUgcmV0cmlldmUoKS5cbiAgICAgIGlmIChNdWx0aUtyeXB0by5pc0VtcHR5SldTUGF5bG9hZChzaWduYXR1cmUpKSByZXR1cm4gTG9jYWxTdG9yZS5yZW1vdmUodGFnKTtcbiAgICAgIHJldHVybiBMb2NhbFN0b3JlLnN0b3JlKHRhZywgc2lnbmF0dXJlKTtcbiAgICB9XG4gICAgcmV0dXJuIEtleVNldC5TdG9yYWdlLnN0b3JlKGNvbGxlY3Rpb25OYW1lLCB0YWcsIHNpZ25hdHVyZSk7XG4gIH1cbiAgc3RhdGljIGFzeW5jIHJldHJpZXZlKGNvbGxlY3Rpb25OYW1lLCB0YWcpIHsgIC8vIEdldCBiYWNrIGEgdmVyaWZpZWQgcmVzdWx0LlxuICAgIGxldCBwcm9taXNlID0gKGNvbGxlY3Rpb25OYW1lID09PSBEZXZpY2VLZXlTZXQuY29sbGVjdGlvbikgPyBMb2NhbFN0b3JlLnJldHJpZXZlKHRhZykgOiBLZXlTZXQuU3RvcmFnZS5yZXRyaWV2ZShjb2xsZWN0aW9uTmFtZSwgdGFnKSxcbiAgICAgICAgc2lnbmF0dXJlID0gYXdhaXQgcHJvbWlzZSxcbiAgICAgICAga2V5ID0gc2lnbmF0dXJlICYmIGF3YWl0IEtleVNldC52ZXJpZnlpbmdLZXkodGFnKTtcbiAgICBpZiAoIXNpZ25hdHVyZSkgcmV0dXJuO1xuICAgIC8vIFdoaWxlIHdlIHJlbHkgb24gdGhlIFN0b3JhZ2UgYW5kIExvY2FsU3RvcmUgaW1wbGVtZW50YXRpb25zIHRvIGRlZXBseSBjaGVjayBzaWduYXR1cmVzIGR1cmluZyB3cml0ZSxcbiAgICAvLyBoZXJlIHdlIHN0aWxsIGRvIGEgc2hhbGxvdyB2ZXJpZmljYXRpb24gY2hlY2sganVzdCB0byBtYWtlIHN1cmUgdGhhdCB0aGUgZGF0YSBoYXNuJ3QgYmVlbiBtZXNzZWQgd2l0aCBhZnRlciB3cml0ZS5cbiAgICBpZiAoc2lnbmF0dXJlLnNpZ25hdHVyZXMpIGtleSA9IHtbdGFnXToga2V5fTsgLy8gUHJlcGFyZSBhIG11bHRpLWtleVxuICAgIHJldHVybiBhd2FpdCBNdWx0aUtyeXB0by52ZXJpZnkoa2V5LCBzaWduYXR1cmUpO1xuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBTZWNyZXRLZXlTZXQgZXh0ZW5kcyBLZXlTZXQgeyAvLyBLZXlzIGFyZSBlbmNyeXB0ZWQgYmFzZWQgb24gYSBzeW1tZXRyaWMgc2VjcmV0LlxuICBzdGF0aWMgc2lnbkZvclN0b3JhZ2Uoe21lc3NhZ2UsIHRhZywgc2lnbmluZ0tleSwgdGltZX0pIHtcbiAgICAvLyBDcmVhdGUgYSBzaW1wbGUgc2lnbmF0dXJlIHRoYXQgZG9lcyBub3Qgc3BlY2lmeSBpc3Mgb3IgYWN0LlxuICAgIC8vIFRoZXJlIGFyZSBubyB0cnVlIG1lbWJlclRhZ3MgdG8gcGFzcyBvbiBhbmQgdGhleSBhcmUgbm90IHVzZWQgaW4gc2ltcGxlIHNpZ25hdHVyZXMuIEhvd2V2ZXIsIHRoZSBjYWxsZXIgZG9lc1xuICAgIC8vIGdlbmVyaWNhbGx5IHBhc3Mgd3JhcHBpbmdEYXRhIGFzIG1lbWJlclRhZ3MsIGFuZCBmb3IgUmVjb3ZlcnlLZXlTZXRzLCB3cmFwcGluZ0RhdGEgaXMgdGhlIHByb21wdC4gXG4gICAgLy8gV2UgZG9uJ3Qgc3RvcmUgbXVsdGlwbGUgdGltZXMsIHNvIHRoZXJlJ3MgYWxzbyBubyBuZWVkIGZvciBpYXQgKHdoaWNoIGNhbiBiZSB1c2VkIHRvIHByZXZlbnQgcmVwbGF5IGF0dGFja3MpLlxuICAgIHJldHVybiB0aGlzLnNpZ24obWVzc2FnZSwge3RhZ3M6IFt0YWddLCBzaWduaW5nS2V5LCB0aW1lfSk7XG4gIH1cbiAgc3RhdGljIGFzeW5jIHdyYXBwaW5nS2V5KHRhZywgcHJvbXB0KSB7IC8vIFRoZSBrZXkgdXNlZCB0byAodW4pd3JhcCB0aGUgdmF1bHQgbXVsdGkta2V5LlxuICAgIGxldCBzZWNyZXQgPSAgYXdhaXQgdGhpcy5nZXRTZWNyZXQodGFnLCBwcm9tcHQpO1xuICAgIC8vIEFsdGVybmF0aXZlbHksIG9uZSBjb3VsZCB1c2Uge1t3cmFwcGluZ0RhdGFdOiBzZWNyZXR9LCBidXQgdGhhdCdzIGEgYml0IHRvbyBjdXRlLCBhbmQgZ2VuZXJhdGVzIGEgZ2VuZXJhbCBmb3JtIGVuY3J5cHRpb24uXG4gICAgLy8gVGhpcyB2ZXJzaW9uIGdlbmVyYXRlcyBhIGNvbXBhY3QgZm9ybSBlbmNyeXB0aW9uLlxuICAgIHJldHVybiBNdWx0aUtyeXB0by5nZW5lcmF0ZVNlY3JldEtleShzZWNyZXQpO1xuICB9XG4gIHN0YXRpYyBhc3luYyB3cmFwKGtleXMsIHByb21wdCA9ICcnKSB7IC8vIEVuY3J5cHQga2V5c2V0IGJ5IGdldFVzZXJEZXZpY2VTZWNyZXQuXG4gICAgbGV0IHtkZWNyeXB0aW5nS2V5LCBzaWduaW5nS2V5LCB0YWd9ID0ga2V5cyxcbiAgICAgICAgdmF1bHRLZXkgPSB7ZGVjcnlwdGluZ0tleSwgc2lnbmluZ0tleX0sXG4gICAgICAgIHdyYXBwaW5nS2V5ID0gYXdhaXQgdGhpcy53cmFwcGluZ0tleSh0YWcsIHByb21wdCk7XG4gICAgcmV0dXJuIE11bHRpS3J5cHRvLndyYXBLZXkodmF1bHRLZXksIHdyYXBwaW5nS2V5LCB7cHJvbXB0fSk7IC8vIE9yZGVyIGlzIGJhY2t3YXJkcyBmcm9tIGVuY3J5cHQuXG4gIH1cbiAgYXN5bmMgdW53cmFwKHdyYXBwZWRLZXkpIHsgLy8gRGVjcnlwdCBrZXlzZXQgYnkgZ2V0VXNlckRldmljZVNlY3JldC5cbiAgICBsZXQgcGFyc2VkID0gd3JhcHBlZEtleS5qc29uIHx8IHdyYXBwZWRLZXkudGV4dCwgLy8gSGFuZGxlIGJvdGgganNvbiBhbmQgY29wYWN0IGZvcm1zIG9mIHdyYXBwZWRLZXkuXG5cbiAgICAgICAgLy8gVGhlIGNhbGwgdG8gd3JhcEtleSwgYWJvdmUsIGV4cGxpY2l0bHkgZGVmaW5lcyB0aGUgcHJvbXB0IGluIHRoZSBoZWFkZXIgb2YgdGhlIGVuY3J5cHRpb24uXG4gICAgICAgIHByb3RlY3RlZEhlYWRlciA9IE11bHRpS3J5cHRvLmRlY29kZVByb3RlY3RlZEhlYWRlcihwYXJzZWQpLFxuICAgICAgICBwcm9tcHQgPSBwcm90ZWN0ZWRIZWFkZXIucHJvbXB0LCAvLyBJbiB0aGUgXCJjdXRlXCIgZm9ybSBvZiB3cmFwcGluZ0tleSwgcHJvbXB0IGNhbiBiZSBwdWxsZWQgZnJvbSBwYXJzZWQucmVjaXBpZW50c1swXS5oZWFkZXIua2lkLFxuXG4gICAgICAgIHdyYXBwaW5nS2V5ID0gYXdhaXQgdGhpcy5jb25zdHJ1Y3Rvci53cmFwcGluZ0tleSh0aGlzLnRhZywgcHJvbXB0KSxcbiAgICAgICAgZXhwb3J0ZWQgPSAoYXdhaXQgTXVsdGlLcnlwdG8uZGVjcnlwdCh3cmFwcGluZ0tleSwgcGFyc2VkKSkuanNvbjtcbiAgICByZXR1cm4gYXdhaXQgTXVsdGlLcnlwdG8uaW1wb3J0SldLKGV4cG9ydGVkLCB7ZGVjcnlwdGluZ0tleTogJ2RlY3J5cHQnLCBzaWduaW5nS2V5OiAnc2lnbid9KTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgZ2V0U2VjcmV0KHRhZywgcHJvbXB0KSB7IC8vIGdldFVzZXJEZXZpY2VTZWNyZXQgZnJvbSBhcHAuXG4gICAgcmV0dXJuIEtleVNldC5nZXRVc2VyRGV2aWNlU2VjcmV0KHRhZywgcHJvbXB0KTtcbiAgfVxufVxuXG4gLy8gVGhlIHVzZXIncyBhbnN3ZXIocykgdG8gYSBzZWN1cml0eSBxdWVzdGlvbiBmb3JtcyBhIHNlY3JldCwgYW5kIHRoZSB3cmFwcGVkIGtleXMgaXMgc3RvcmVkIGluIHRoZSBjbG91ZGUuXG5leHBvcnQgY2xhc3MgUmVjb3ZlcnlLZXlTZXQgZXh0ZW5kcyBTZWNyZXRLZXlTZXQge1xuICBzdGF0aWMgY29sbGVjdGlvbiA9ICdLZXlSZWNvdmVyeSc7XG59XG5cbi8vIEEgS2V5U2V0IGNvcnJlc3BvbmRpbmcgdG8gdGhlIGN1cnJlbnQgaGFyZHdhcmUuIFdyYXBwaW5nIHNlY3JldCBjb21lcyBmcm9tIHRoZSBhcHAuXG5leHBvcnQgY2xhc3MgRGV2aWNlS2V5U2V0IGV4dGVuZHMgU2VjcmV0S2V5U2V0IHtcbiAgc3RhdGljIGNvbGxlY3Rpb24gPSAnRGV2aWNlJztcbn1cbmNvbnN0IExvY2FsU3RvcmUgPSBuZXcgTG9jYWxDb2xsZWN0aW9uKHtjb2xsZWN0aW9uTmFtZTogRGV2aWNlS2V5U2V0LmNvbGxlY3Rpb259KTtcblxuZXhwb3J0IGNsYXNzIFRlYW1LZXlTZXQgZXh0ZW5kcyBLZXlTZXQgeyAvLyBBIEtleVNldCBjb3JyZXNwb25kaW5nIHRvIGEgdGVhbSBvZiB3aGljaCB0aGUgY3VycmVudCB1c2VyIGlzIGEgbWVtYmVyIChpZiBnZXRUYWcoKSkuXG4gIHN0YXRpYyBjb2xsZWN0aW9uID0gJ1RlYW0nO1xuICBzdGF0aWMgc2lnbkZvclN0b3JhZ2Uoe21lc3NhZ2UsIHRhZywgLi4ub3B0aW9uc30pIHtcbiAgICByZXR1cm4gdGhpcy5zaWduKG1lc3NhZ2UsIHt0ZWFtOiB0YWcsIC4uLm9wdGlvbnN9KTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgd3JhcChrZXlzLCBtZW1iZXJzKSB7XG4gICAgLy8gVGhpcyBpcyB1c2VkIGJ5IHBlcnNpc3QsIHdoaWNoIGluIHR1cm4gaXMgdXNlZCB0byBjcmVhdGUgYW5kIGNoYW5nZU1lbWJlcnNoaXAuXG4gICAgbGV0IHtkZWNyeXB0aW5nS2V5LCBzaWduaW5nS2V5fSA9IGtleXMsXG4gICAgICAgIHRlYW1LZXkgPSB7ZGVjcnlwdGluZ0tleSwgc2lnbmluZ0tleX0sXG4gICAgICAgIHdyYXBwaW5nS2V5ID0ge307XG4gICAgYXdhaXQgUHJvbWlzZS5hbGwobWVtYmVycy5tYXAobWVtYmVyVGFnID0+IEtleVNldC5lbmNyeXB0aW5nS2V5KG1lbWJlclRhZykudGhlbihrZXkgPT4gd3JhcHBpbmdLZXlbbWVtYmVyVGFnXSA9IGtleSkpKTtcbiAgICBsZXQgd3JhcHBlZFRlYW0gPSBhd2FpdCBNdWx0aUtyeXB0by53cmFwS2V5KHRlYW1LZXksIHdyYXBwaW5nS2V5KTtcbiAgICByZXR1cm4gd3JhcHBlZFRlYW07XG4gIH1cbiAgYXN5bmMgdW53cmFwKHdyYXBwZWQpIHtcbiAgICBsZXQge3JlY2lwaWVudHN9ID0gd3JhcHBlZC5qc29uLFxuICAgICAgICBtZW1iZXJUYWdzID0gdGhpcy5tZW1iZXJUYWdzID0gcmVjaXBpZW50cy5tYXAocmVjaXBpZW50ID0+IHJlY2lwaWVudC5oZWFkZXIua2lkKSxcbiAgICAgICAgLy8gV2Ugd2lsbCB1c2UgcmVjb3ZlcnkgdGFncyBvbmx5IGlmIHdlIG5lZWQgdG8uIEZpcnN0IHN0ZXAgaXMgdG8gaWRlbnRpZnkgdGhlbS5cbiAgICAgICAgLy8gVE9ETzogb3B0aW1pemUgdGhpcy4gRS5nLiwgZGV0ZXJtaW5lIHJlY292ZXJ5IHRhZ3MgYXQgY3JlYXRpb24gYW5kIGlkZW50aWZ5IHRoZW0gaW4gd3JhcHBlZC5cbiAgICAgICAgcmVjb3ZlcnlXcmFwcyA9IGF3YWl0IFByb21pc2UuYWxsKG1lbWJlclRhZ3MubWFwKHRhZyA9PiBSZWNvdmVyeUtleVNldC5nZXRXcmFwcGVkKHRhZykuY2F0Y2goKCkgPT4gbnVsbCkpKSxcbiAgICAgICAgcmVjb3ZlcnlUYWdzID0gbWVtYmVyVGFncy5maWx0ZXIoKHRhZywgaW5kZXgpID0+IHJlY292ZXJ5V3JhcHNbaW5kZXhdKSxcbiAgICAgICAgbm9uUmVjb3ZlcnlUYWdzID0gbWVtYmVyVGFncy5maWx0ZXIodGFnID0+ICFyZWNvdmVyeVRhZ3MuaW5jbHVkZXModGFnKSk7XG4gICAgbGV0IGtleVNldCA9IGF3YWl0IFByb21pc2UuYW55KG5vblJlY292ZXJ5VGFncy5tYXAobWVtYmVyVGFnID0+IEtleVNldC5lbnN1cmUobWVtYmVyVGFnKSkpXG4gICAgICAgIC5jYXRjaChhc3luYyByZWFzb24gPT4geyAvLyBJZiB3ZSBmYWlsZWQsIHVzZSB0aGUgcmVjb3ZlcnkgdGFncywgaWYgYW55LCBvbmUgYXQgYSB0aW1lLlxuICAgICAgICAgIGZvciAobGV0IHJlY292ZXJ5IG9mIHJlY292ZXJ5VGFncykge1xuICAgICAgICAgICAgbGV0IGtleVNldCA9IGF3YWl0IEtleVNldC5lbnN1cmUocmVjb3ZlcnkpLmNhdGNoKCgpID0+IG51bGwpO1xuICAgICAgICAgICAgaWYgKGtleVNldCkgcmV0dXJuIGtleVNldDtcbiAgICAgICAgICB9XG4gICAgICAgICAgdGhyb3cgcmVhc29uO1xuICAgICAgICB9KTtcbiAgICBsZXQgZGVjcnlwdGVkID0gYXdhaXQga2V5U2V0LmRlY3J5cHQod3JhcHBlZC5qc29uKTtcbiAgICByZXR1cm4gYXdhaXQgTXVsdGlLcnlwdG8uaW1wb3J0SldLKGRlY3J5cHRlZC5qc29uKTtcbiAgfVxuICBhc3luYyBjaGFuZ2VNZW1iZXJzaGlwKHthZGQgPSBbXSwgcmVtb3ZlID0gW119ID0ge30pIHtcbiAgICBsZXQge21lbWJlclRhZ3N9ID0gdGhpcyxcbiAgICAgICAgbmV3TWVtYmVycyA9IG1lbWJlclRhZ3MuY29uY2F0KGFkZCkuZmlsdGVyKHRhZyA9PiAhcmVtb3ZlLmluY2x1ZGVzKHRhZykpO1xuICAgIGF3YWl0IHRoaXMuY29uc3RydWN0b3IucGVyc2lzdCh0aGlzLnRhZywgdGhpcywgbmV3TWVtYmVycywgRGF0ZS5ub3coKSwgbWVtYmVyVGFncyk7XG4gICAgdGhpcy5tZW1iZXJUYWdzID0gbmV3TWVtYmVycztcbiAgfVxufVxuIiwiLy8gQmVjYXVzZSBlc2xpbnQgZG9lc24ndCByZWNvZ25pemUgaW1wb3J0IGFzc2VydGlvbnNcbmltcG9ydCAqIGFzIHBrZyBmcm9tIFwiLi4vcGFja2FnZS5qc29uXCIgd2l0aCB7IHR5cGU6ICdqc29uJyB9O1xuZXhwb3J0IGNvbnN0IHtuYW1lLCB2ZXJzaW9ufSA9IHBrZy5kZWZhdWx0O1xuIiwiaW1wb3J0IE11bHRpS3J5cHRvIGZyb20gXCIuL211bHRpS3J5cHRvLm1qc1wiO1xuaW1wb3J0IHtLZXlTZXQsIERldmljZUtleVNldCwgUmVjb3ZlcnlLZXlTZXQsIFRlYW1LZXlTZXR9IGZyb20gXCIuL2tleVNldC5tanNcIjtcbmltcG9ydCB7bmFtZSwgdmVyc2lvbn0gZnJvbSBcIi4vcGFja2FnZS1sb2FkZXIubWpzXCI7XG5cbmNvbnN0IFNlY3VyaXR5ID0geyAvLyBUaGlzIGlzIHRoZSBhcGkgZm9yIHRoZSB2YXVsdC4gU2VlIGh0dHBzOi8va2lscm95LWNvZGUuZ2l0aHViLmlvL2Rpc3RyaWJ1dGVkLXNlY3VyaXR5L2RvY3MvaW1wbGVtZW50YXRpb24uaHRtbCNjcmVhdGluZy10aGUtdmF1bHQtd2ViLXdvcmtlci1hbmQtaWZyYW1lXG5cbiAgLy8gQ2xpZW50LWRlZmluZWQgcmVzb3VyY2VzLlxuICBzZXQgU3RvcmFnZShzdG9yYWdlKSB7IC8vIEFsbG93cyBhIG5vZGUgYXBwIChubyB2YXVsdCkgdG8gb3ZlcnJpZGUgdGhlIGRlZmF1bHQgc3RvcmFnZS5cbiAgICBLZXlTZXQuU3RvcmFnZSA9IHN0b3JhZ2U7XG4gIH0sXG4gIGdldCBTdG9yYWdlKCkgeyAvLyBBbGxvd3MgYSBub2RlIGFwcCAobm8gdmF1bHQpIHRvIGV4YW1pbmUgc3RvcmFnZS5cbiAgICByZXR1cm4gS2V5U2V0LlN0b3JhZ2U7XG4gIH0sXG4gIHNldCBnZXRVc2VyRGV2aWNlU2VjcmV0KGZ1bmN0aW9uT2ZUYWdBbmRQcm9tcHQpIHsgIC8vIEFsbG93cyBhIG5vZGUgYXBwIChubyB2YXVsdCkgdG8gb3ZlcnJpZGUgdGhlIGRlZmF1bHQuXG4gICAgS2V5U2V0LmdldFVzZXJEZXZpY2VTZWNyZXQgPSBmdW5jdGlvbk9mVGFnQW5kUHJvbXB0O1xuICB9LFxuICByZWFkeToge25hbWUsIHZlcnNpb24sIG9yaWdpbjogS2V5U2V0LlN0b3JhZ2Uub3JpZ2lufSxcblxuICAvLyBUaGUgZm91ciBiYXNpYyBvcGVyYXRpb25zLiAuLi5yZXN0IG1heSBiZSBvbmUgb3IgbW9yZSB0YWdzLCBvciBtYXkgYmUge3RhZ3MsIHRlYW0sIG1lbWJlciwgY29udGVudFR5cGUsIC4uLn1cbiAgYXN5bmMgZW5jcnlwdChtZXNzYWdlLCAuLi5yZXN0KSB7IC8vIFByb21pc2UgYSBKV0UuXG4gICAgbGV0IG9wdGlvbnMgPSB7fSwgdGFncyA9IHRoaXMuY2Fub25pY2FsaXplUGFyYW1ldGVycyhyZXN0LCBvcHRpb25zKSxcbiAgICAgICAga2V5ID0gYXdhaXQgS2V5U2V0LnByb2R1Y2VLZXkodGFncywgdGFnID0+IEtleVNldC5lbmNyeXB0aW5nS2V5KHRhZyksIG9wdGlvbnMpO1xuICAgIHJldHVybiBNdWx0aUtyeXB0by5lbmNyeXB0KGtleSwgbWVzc2FnZSwgb3B0aW9ucyk7XG4gIH0sXG4gIGFzeW5jIGRlY3J5cHQoZW5jcnlwdGVkLCAuLi5yZXN0KSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259IGFzIGFwcHJvcHJpYXRlLlxuICAgIGxldCBvcHRpb25zID0ge30sXG4gICAgICAgIFt0YWddID0gdGhpcy5jYW5vbmljYWxpemVQYXJhbWV0ZXJzKHJlc3QsIG9wdGlvbnMsIGVuY3J5cHRlZCksXG4gICAgICAgIHZhdWx0ID0gYXdhaXQgS2V5U2V0LmVuc3VyZSh0YWcpO1xuICAgIHJldHVybiB2YXVsdC5kZWNyeXB0KGVuY3J5cHRlZCwgb3B0aW9ucyk7XG4gIH0sXG4gIGFzeW5jIHNpZ24obWVzc2FnZSwgLi4ucmVzdCkgeyAvLyBQcm9taXNlIGEgSldTLlxuICAgIGxldCBvcHRpb25zID0ge30sIHRhZ3MgPSB0aGlzLmNhbm9uaWNhbGl6ZVBhcmFtZXRlcnMocmVzdCwgb3B0aW9ucyk7XG4gICAgcmV0dXJuIEtleVNldC5zaWduKG1lc3NhZ2UsIHt0YWdzLCAuLi5vcHRpb25zfSk7XG4gIH0sXG4gIGFzeW5jIHZlcmlmeShzaWduYXR1cmUsIC4uLnJlc3QpIHsgLy8gUHJvbWlzZSB7cGF5bG9hZCwgdGV4dCwganNvbn0gYXMgYXBwcm9wcmlhdGUuXG4gICAgbGV0IG9wdGlvbnMgPSB7fSwgdGFncyA9IHRoaXMuY2Fub25pY2FsaXplUGFyYW1ldGVycyhyZXN0LCBvcHRpb25zLCBzaWduYXR1cmUpO1xuICAgIHJldHVybiBLZXlTZXQudmVyaWZ5KHNpZ25hdHVyZSwgdGFncywgb3B0aW9ucyk7XG4gIH0sXG5cbiAgLy8gVGFnIG1haW50YW5jZS5cbiAgYXN5bmMgY3JlYXRlKC4uLm1lbWJlcnMpIHsgLy8gUHJvbWlzZSBhIG5ld2x5LWNyZWF0ZWQgdGFnIHdpdGggdGhlIGdpdmVuIG1lbWJlcnMuIFRoZSBtZW1iZXIgdGFncyAoaWYgYW55KSBtdXN0IGFscmVhZHkgZXhpc3QuXG4gICAgaWYgKCFtZW1iZXJzLmxlbmd0aCkgcmV0dXJuIGF3YWl0IERldmljZUtleVNldC5jcmVhdGUoKTtcbiAgICBsZXQgcHJvbXB0ID0gbWVtYmVyc1swXS5wcm9tcHQ7XG4gICAgaWYgKHByb21wdCkgcmV0dXJuIGF3YWl0IFJlY292ZXJ5S2V5U2V0LmNyZWF0ZShwcm9tcHQpO1xuICAgIHJldHVybiBhd2FpdCBUZWFtS2V5U2V0LmNyZWF0ZShtZW1iZXJzKTtcbiAgfSxcbiAgYXN5bmMgY2hhbmdlTWVtYmVyc2hpcCh7dGFnLCAuLi5vcHRpb25zfSkgeyAvLyBQcm9taXNlIHRvIGFkZCBvciByZW1vdmUgbWVtYmVycy5cbiAgICBsZXQgdmF1bHQgPSBhd2FpdCBLZXlTZXQuZW5zdXJlKHRhZyk7XG4gICAgcmV0dXJuIHZhdWx0LmNoYW5nZU1lbWJlcnNoaXAob3B0aW9ucyk7XG4gIH0sXG4gIGFzeW5jIGRlc3Ryb3kodGFnT3JPcHRpb25zKSB7IC8vIFByb21pc2UgdG8gcmVtb3ZlIHRoZSB0YWcgYW5kIGFueSBhc3NvY2lhdGVkIGRhdGEgZnJvbSBhbGwgc3RvcmFnZS5cbiAgICBpZiAoJ3N0cmluZycgPT09IHR5cGVvZiB0YWdPck9wdGlvbnMpIHRhZ09yT3B0aW9ucyA9IHt0YWc6IHRhZ09yT3B0aW9uc307XG4gICAgbGV0IHt0YWcsIC4uLm9wdGlvbnN9ID0gdGFnT3JPcHRpb25zO1xuICAgIGxldCB2YXVsdCA9IGF3YWl0IEtleVNldC5lbnN1cmUodGFnKTtcbiAgICByZXR1cm4gdmF1bHQuZGVzdHJveShvcHRpb25zKTtcbiAgfSxcbiAgY2xlYXIodGFnKSB7IC8vIFJlbW92ZSBhbnkgbG9jYWxseSBjYWNoZWQgS2V5U2V0IGZvciB0aGUgdGFnLCBvciBhbGwgS2V5U2V0cyBpZiBub3QgdGFnIHNwZWNpZmllZC5cbiAgICBLZXlTZXQuY2xlYXIodGFnKTtcbiAgfSxcblxuICBkZWNvZGVQcm90ZWN0ZWRIZWFkZXI6IE11bHRpS3J5cHRvLmRlY29kZVByb3RlY3RlZEhlYWRlcixcbiAgY2Fub25pY2FsaXplUGFyYW1ldGVycyhyZXN0LCBvcHRpb25zLCB0b2tlbikgeyAvLyBSZXR1cm4gdGhlIGFjdHVhbCBsaXN0IG9mIHRhZ3MsIGFuZCBiYXNoIG9wdGlvbnMuXG4gICAgLy8gcmVzdCBtYXkgYmUgYSBsaXN0IG9mIHRhZyBzdHJpbmdzXG4gICAgLy8gICAgb3IgYSBsaXN0IG9mIG9uZSBzaW5nbGUgb2JqZWN0IHNwZWNpZnlpbmcgbmFtZWQgcGFyYW1ldGVycywgaW5jbHVkaW5nIGVpdGhlciB0ZWFtLCB0YWdzLCBvciBuZWl0aGVyXG4gICAgLy8gdG9rZW4gbWF5IGJlIGEgSldFIG9yIEpTRSwgb3IgZmFsc3ksIGFuZCBpcyB1c2VkIHRvIHN1cHBseSB0YWdzIGlmIG5lY2Vzc2FyeS5cbiAgICBpZiAocmVzdC5sZW5ndGggPiAxIHx8IHJlc3RbMF0/Lmxlbmd0aCAhPT0gdW5kZWZpbmVkKSByZXR1cm4gcmVzdDtcbiAgICBsZXQge3RhZ3MgPSBbXSwgY29udGVudFR5cGUsIHRpbWUsIC4uLm90aGVyc30gPSByZXN0WzBdIHx8IHt9LFxuXHR7dGVhbX0gPSBvdGhlcnM7IC8vIERvIG5vdCBzdHJpcCB0ZWFtIGZyb20gb3RoZXJzLlxuICAgIGlmICghdGFncy5sZW5ndGgpIHtcbiAgICAgIGlmIChyZXN0Lmxlbmd0aCAmJiByZXN0WzBdLmxlbmd0aCkgdGFncyA9IHJlc3Q7IC8vIHJlc3Qgbm90IGVtcHR5LCBhbmQgaXRzIGZpcnN0IGlzIHN0cmluZy1saWtlLlxuICAgICAgZWxzZSBpZiAodG9rZW4pIHsgLy8gZ2V0IGZyb20gdG9rZW5cbiAgICAgICAgaWYgKHRva2VuLnNpZ25hdHVyZXMpIHRhZ3MgPSB0b2tlbi5zaWduYXR1cmVzLm1hcChzaWcgPT4gdGhpcy5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIoc2lnKS5raWQpO1xuICAgICAgICBlbHNlIGlmICh0b2tlbi5yZWNpcGllbnRzKSB0YWdzID0gdG9rZW4ucmVjaXBpZW50cy5tYXAocmVjID0+IHJlYy5oZWFkZXIua2lkKTtcbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgbGV0IGtpZCA9IHRoaXMuZGVjb2RlUHJvdGVjdGVkSGVhZGVyKHRva2VuKS5raWQ7IC8vIGNvbXBhY3QgdG9rZW5cbiAgICAgICAgICBpZiAoa2lkKSB0YWdzID0gW2tpZF07XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gICAgaWYgKHRlYW0gJiYgIXRhZ3MuaW5jbHVkZXModGVhbSkpIHRhZ3MgPSBbdGVhbSwgLi4udGFnc107XG4gICAgaWYgKGNvbnRlbnRUeXBlKSBvcHRpb25zLmN0eSA9IGNvbnRlbnRUeXBlO1xuICAgIGlmICh0aW1lKSBvcHRpb25zLmlhdCA9IHRpbWU7XG4gICAgT2JqZWN0LmFzc2lnbihvcHRpb25zLCBvdGhlcnMpO1xuXG4gICAgcmV0dXJuIHRhZ3M7XG4gIH1cbn07XG5cbmV4cG9ydCBkZWZhdWx0IFNlY3VyaXR5O1xuIiwiXG5mdW5jdGlvbiB0cmFuc2ZlcnJhYmxlRXJyb3IoZXJyb3IpIHsgLy8gQW4gZXJyb3Igb2JqZWN0IHRoYXQgd2UgcmVjZWl2ZSBvbiBvdXIgc2lkZSBtaWdodCBub3QgYmUgdHJhbnNmZXJyYWJsZSB0byB0aGUgb3RoZXIuXG4gIGxldCB7bmFtZSwgbWVzc2FnZSwgY29kZSwgZGF0YX0gPSBlcnJvcjtcbiAgcmV0dXJuIHtuYW1lLCBtZXNzYWdlLCBjb2RlLCBkYXRhfTtcbn1cblxuLy8gU2V0IHVwIGJpZGlyZWN0aW9uYWwgY29tbXVuY2F0aW9ucyB3aXRoIHRhcmdldCwgcmV0dXJuaW5nIGEgZnVuY3Rpb24gKG1ldGhvZE5hbWUsIC4uLnBhcmFtcykgdGhhdCB3aWxsIHNlbmQgdG8gdGFyZ2V0LlxuZnVuY3Rpb24gZGlzcGF0Y2goe3RhcmdldCA9IHNlbGYsICAgICAgICAvLyBUaGUgd2luZG93LCB3b3JrZXIsIG9yIG90aGVyIG9iamVjdCB0byB3aGljaCB3ZSB3aWxsIHBvc3RNZXNzYWdlLlxuXHRcdCAgIHJlY2VpdmVyID0gdGFyZ2V0LCAgICAvLyBUaGUgd2luZG93LCB3b3JrZXIsIG9yIG90aGVyIG9iamVjdCBvZiB3aGljaCBXRSB3aWxsIGhhbmRsZSAnbWVzc2FnZScgZXZlbnRzIGZyb20gdGFyZ2V0LlxuXHRcdCAgIG5hbWVzcGFjZSA9IHJlY2VpdmVyLCAvLyBBbiBvYmplY3QgdGhhdCBkZWZpbmVzIGFueSBtZXRob2RzIHRoYXQgbWF5IGJlIHJlcXVlc3RlZCBieSB0YXJnZXQuXG5cblx0XHQgICBvcmlnaW4gPSAoKHRhcmdldCAhPT0gcmVjZWl2ZXIpICYmIHRhcmdldC5sb2NhdGlvbi5vcmlnaW4pLFxuXG5cdFx0ICAgZGlzcGF0Y2hlckxhYmVsID0gbmFtZXNwYWNlLm5hbWUgfHwgcmVjZWl2ZXIubmFtZSB8fCByZWNlaXZlci5sb2NhdGlvbj8uaHJlZiB8fCByZWNlaXZlcixcblx0XHQgICB0YXJnZXRMYWJlbCA9IHRhcmdldC5uYW1lIHx8IG9yaWdpbiB8fCB0YXJnZXQubG9jYXRpb24/LmhyZWYgfHwgdGFyZ2V0LFxuXG5cdFx0ICAgbG9nID0gbnVsbCxcblx0XHQgICBpbmZvOmxvZ2luZm8gPSBjb25zb2xlLmluZm8uYmluZChjb25zb2xlKSxcblx0XHQgICB3YXJuOmxvZ3dhcm4gPSBjb25zb2xlLndhcm4uYmluZChjb25zb2xlKSxcblx0XHQgICBlcnJvcjpsb2dlcnJvciA9IGNvbnNvbGUuZXJyb3IuYmluZChjb25zb2xlKVxuXHRcdCAgfSkge1xuICBjb25zdCByZXF1ZXN0cyA9IHt9LFxuICAgICAgICBqc29ucnBjID0gJzIuMCcsXG4gICAgICAgIGNhcHR1cmVkUG9zdCA9IHRhcmdldC5wb3N0TWVzc2FnZS5iaW5kKHRhcmdldCksIC8vIEluIGNhc2UgKG1hbGljaW91cykgY29kZSBsYXRlciBjaGFuZ2VzIGl0LlxuICAgICAgICAvLyB3aW5kb3cucG9zdE1lc3NhZ2UgYW5kIGZyaWVuZHMgdGFrZXMgYSB0YXJnZXRPcmlnaW4gdGhhdCB3ZSBzdXBwbHkuXG4gICAgICAgIC8vIEJ1dCB3b3JrZXIucG9zdE1lc3NhZ2UgZ2l2ZXMgZXJyb3IgcmF0aGVyIHRoYW4gaWdub3JpbmcgdGhlIGV4dHJhIGFyZy4gU28gc2V0IHRoZSByaWdodCBmb3JtIGF0IGluaXRpYWxpemF0aW9uLlxuICAgICAgICBwb3N0ID0gb3JpZ2luID8gbWVzc2FnZSA9PiBjYXB0dXJlZFBvc3QobWVzc2FnZSwgb3JpZ2luKSA6IGNhcHR1cmVkUG9zdCxcbiAgICAgICAgbnVsbExvZyA9ICgpID0+IHt9O1xuICBsZXQgbWVzc2FnZUlkID0gMDsgLy8gcHJlLWluY3JlbWVudGVkIGlkIHN0YXJ0cyBhdCAxLlxuXG4gIGZ1bmN0aW9uIHJlcXVlc3QobWV0aG9kLCAuLi5wYXJhbXMpIHsgLy8gUHJvbWlzZSB0aGUgcmVzdWx0IG9mIG1ldGhvZCguLi5wYXJhbXMpIGluIHRhcmdldC5cbiAgICAvLyBXZSBkbyBhIHRhcmdldC5wb3N0TWVzc2FnZSBvZiBhIGpzb25ycGMgcmVxdWVzdCwgYW5kIHJlc29sdmUgdGhlIHByb21pc2Ugd2l0aCB0aGUgcmVzcG9uc2UsIG1hdGNoZWQgYnkgaWQuXG4gICAgLy8gSWYgdGhlIHRhcmdldCBoYXBwZW5zIHRvIGJlIHNldCB1cCBieSBhIGRpc3BhdGNoIGxpa2UgdGhpcyBvbmUsIGl0IHdpbGwgcmVzcG9uZCB3aXRoIHdoYXRldmVyIGl0J3NcbiAgICAvLyBuYW1lc3BhY2VbbWV0aG9kXSguLi5wYXJhbXMpIHJlc29sdmVzIHRvLiBXZSBvbmx5IHNlbmQganNvbnJwYyByZXF1ZXN0cyAod2l0aCBhbiBpZCksIG5vdCBub3RpZmljYXRpb25zLFxuICAgIC8vIGJlY2F1c2UgdGhlcmUgaXMgbm8gd2F5IHRvIGdldCBlcnJvcnMgYmFjayBmcm9tIGEganNvbnJwYyBub3RpZmljYXRpb24uXG4gICAgbGV0IGlkID0gKyttZXNzYWdlSWQsXG5cdHJlcXVlc3QgPSByZXF1ZXN0c1tpZF0gPSB7fTtcbiAgICAvLyBJdCB3b3VsZCBiZSBuaWNlIHRvIG5vdCBsZWFrIHJlcXVlc3Qgb2JqZWN0cyBpZiB0aGV5IGFyZW4ndCBhbnN3ZXJlZC5cbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgbG9nPy4oZGlzcGF0Y2hlckxhYmVsLCAncmVxdWVzdCcsIGlkLCBtZXRob2QsIHBhcmFtcywgJ3RvJywgdGFyZ2V0TGFiZWwpO1xuICAgICAgT2JqZWN0LmFzc2lnbihyZXF1ZXN0LCB7cmVzb2x2ZSwgcmVqZWN0fSk7XG4gICAgICBwb3N0KHtpZCwgbWV0aG9kLCBwYXJhbXMsIGpzb25ycGN9KTtcbiAgICB9KTtcbiAgfVxuXG4gIGFzeW5jIGZ1bmN0aW9uIHJlc3BvbmQoZXZlbnQpIHsgLy8gSGFuZGxlICdtZXNzYWdlJyBldmVudHMgdGhhdCB3ZSByZWNlaXZlIGZyb20gdGFyZ2V0LlxuICAgIGxvZz8uKGRpc3BhdGNoZXJMYWJlbCwgJ2dvdCBtZXNzYWdlJywgZXZlbnQuZGF0YSwgJ2Zyb20nLCB0YXJnZXRMYWJlbCwgZXZlbnQub3JpZ2luKTtcbiAgICBsZXQge2lkLCBtZXRob2QsIHBhcmFtcyA9IFtdLCByZXN1bHQsIGVycm9yLCBqc29ucnBjOnZlcnNpb259ID0gZXZlbnQuZGF0YSB8fCB7fTtcblxuICAgIC8vIE5vaXNpbHkgaWdub3JlIG1lc3NhZ2VzIHRoYXQgYXJlIG5vdCBmcm9tIHRoZSBleHBlY3QgdGFyZ2V0IG9yIG9yaWdpbiwgb3Igd2hpY2ggYXJlIG5vdCBqc29ucnBjLlxuICAgIGlmIChldmVudC5zb3VyY2UgJiYgKGV2ZW50LnNvdXJjZSAhPT0gdGFyZ2V0KSkgcmV0dXJuIGxvZ2Vycm9yPy4oZGlzcGF0Y2hlckxhYmVsLCAndG8nLCB0YXJnZXRMYWJlbCwgICdnb3QgbWVzc2FnZSBmcm9tJywgZXZlbnQuc291cmNlKTtcbiAgICBpZiAob3JpZ2luICYmIChvcmlnaW4gIT09IGV2ZW50Lm9yaWdpbikpIHJldHVybiBsb2dlcnJvcj8uKGRpc3BhdGNoZXJMYWJlbCwgb3JpZ2luLCAnbWlzbWF0Y2hlZCBvcmlnaW4nLCB0YXJnZXRMYWJlbCwgZXZlbnQub3JpZ2luKTtcbiAgICBpZiAodmVyc2lvbiAhPT0ganNvbnJwYykgcmV0dXJuIGxvZ3dhcm4/LihgJHtkaXNwYXRjaGVyTGFiZWx9IGlnbm9yaW5nIG5vbi1qc29ucnBjIG1lc3NhZ2UgJHtKU09OLnN0cmluZ2lmeShldmVudC5kYXRhKX0uYCk7XG5cbiAgICBpZiAobWV0aG9kKSB7IC8vIEluY29taW5nIHJlcXVlc3Qgb3Igbm90aWZpY2F0aW9uIGZyb20gdGFyZ2V0LlxuICAgICAgbGV0IGVycm9yID0gbnVsbCwgcmVzdWx0LFxuICAgICAgICAgIC8vIGpzb25ycGMgcmVxdWVzdC9ub3RpZmljYXRpb24gY2FuIGhhdmUgcG9zaXRpb25hbCBhcmdzIChhcnJheSkgb3IgbmFtZWQgYXJncyAoYSBQT0pPKS5cblx0ICBhcmdzID0gQXJyYXkuaXNBcnJheShwYXJhbXMpID8gcGFyYW1zIDogW3BhcmFtc107IC8vIEFjY2VwdCBlaXRoZXIuXG4gICAgICB0cnkgeyAvLyBtZXRob2QgcmVzdWx0IG1pZ2h0IG5vdCBiZSBhIHByb21pc2UsIHNvIHdlIGNhbid0IHJlbHkgb24gLmNhdGNoKCkuXG4gICAgICAgIHJlc3VsdCA9IGF3YWl0IG5hbWVzcGFjZVttZXRob2RdKC4uLmFyZ3MpOyAvLyBDYWxsIHRoZSBtZXRob2QuXG4gICAgICB9IGNhdGNoIChlKSB7IC8vIFNlbmQgYmFjayBhIGNsZWFuIHtuYW1lLCBtZXNzYWdlfSBvYmplY3QuXG4gICAgICAgIGVycm9yID0gdHJhbnNmZXJyYWJsZUVycm9yKGUpO1xuICAgICAgICBpZiAoIW5hbWVzcGFjZVttZXRob2RdICYmICFlcnJvci5tZXNzYWdlLmluY2x1ZGVzKG1ldGhvZCkpIHtcblx0ICBlcnJvci5tZXNzYWdlID0gYCR7bWV0aG9kfSBpcyBub3QgZGVmaW5lZC5gOyAvLyBCZSBtb3JlIGhlbHBmdWwgdGhhbiBzb21lIGJyb3dzZXJzLlxuICAgICAgICAgIGVycm9yLmNvZGUgPSAtMzI2MDE7IC8vIERlZmluZWQgYnkganNvbi1ycGMgc3BlYy5cbiAgICAgICAgfSBlbHNlIGlmICghZXJyb3IubWVzc2FnZSkgLy8gSXQgaGFwcGVucy4gRS5nLiwgb3BlcmF0aW9uYWwgZXJyb3JzIGZyb20gY3J5cHRvLlxuXHQgIGVycm9yLm1lc3NhZ2UgPSBgJHtlcnJvci5uYW1lIHx8IGVycm9yLnRvU3RyaW5nKCl9IGluICR7bWV0aG9kfS5gO1xuICAgICAgfVxuICAgICAgaWYgKGlkID09PSB1bmRlZmluZWQpIHJldHVybjsgLy8gRG9uJ3QgcmVzcG9uZCB0byBhICdub3RpZmljYXRpb24nLiBudWxsIGlkIGlzIHN0aWxsIHNlbnQgYmFjay5cbiAgICAgIGxldCByZXNwb25zZSA9IGVycm9yID8ge2lkLCBlcnJvciwganNvbnJwY30gOiB7aWQsIHJlc3VsdCwganNvbnJwY307XG4gICAgICBsb2c/LihkaXNwYXRjaGVyTGFiZWwsICdhbnN3ZXJpbmcnLCBpZCwgZXJyb3IgfHwgcmVzdWx0LCAndG8nLCB0YXJnZXRMYWJlbCk7XG4gICAgICByZXR1cm4gcG9zdChyZXNwb25zZSk7XG4gICAgfVxuXG4gICAgLy8gT3RoZXJ3aXNlLCBpdCBpcyBhIHJlc3BvbnNlIGZyb20gdGFyZ2V0IHRvIG91ciBlYXJsaWVyIG91dGdvaW5nIHJlcXVlc3QuXG4gICAgbGV0IHJlcXVlc3QgPSByZXF1ZXN0c1tpZF07ICAvLyBSZXNvbHZlIG9yIHJlamVjdCB0aGUgcHJvbWlzZSB0aGF0IGFuIGFuIGVhcmxpZXIgcmVxdWVzdCBjcmVhdGVkLlxuICAgIGRlbGV0ZSByZXF1ZXN0c1tpZF07XG4gICAgaWYgKCFyZXF1ZXN0KSByZXR1cm4gbG9nd2Fybj8uKGAke2Rpc3BhdGNoZXJMYWJlbH0gaWdub3JpbmcgcmVzcG9uc2UgJHtldmVudC5kYXRhfS5gKTtcbiAgICBpZiAoZXJyb3IpIHJlcXVlc3QucmVqZWN0KGVycm9yKTtcbiAgICBlbHNlIHJlcXVlc3QucmVzb2x2ZShyZXN1bHQpO1xuICB9XG5cbiAgLy8gTm93IHNldCB1cCB0aGUgaGFuZGxlciBhbmQgcmV0dXJuIHRoZSBmdW5jdGlvbiBmb3IgdGhlIGNhbGxlciB0byB1c2UgdG8gbWFrZSByZXF1ZXN0cy5cbiAgcmVjZWl2ZXIuYWRkRXZlbnRMaXN0ZW5lcihcIm1lc3NhZ2VcIiwgcmVzcG9uZCk7XG4gIGxvZ2luZm8/LihgJHtkaXNwYXRjaGVyTGFiZWx9IHdpbGwgZGlzcGF0Y2ggdG8gJHt0YXJnZXRMYWJlbH1gKTtcbiAgcmV0dXJuIHJlcXVlc3Q7XG59XG5cbmV4cG9ydCBkZWZhdWx0IGRpc3BhdGNoO1xuIl0sIm5hbWVzIjpbImRpZ2VzdCIsImNyeXB0byIsImVuY29kZSIsImRlY29kZSIsImJpdExlbmd0aCIsImRlY3J5cHQiLCJnZXRDcnlwdG9LZXkiLCJ3cmFwIiwidW53cmFwIiwiZGVyaXZlS2V5IiwicDJzIiwiY29uY2F0U2FsdCIsImVuY3J5cHQiLCJiYXNlNjR1cmwiLCJzdWJ0bGVBbGdvcml0aG0iLCJkZWNvZGVCYXNlNjRVUkwiLCJpbnZhbGlkS2V5SW5wdXQiLCJFQ0RILmVjZGhBbGxvd2VkIiwiRUNESC5kZXJpdmVLZXkiLCJjZWtMZW5ndGgiLCJhZXNLdyIsInJzYUVzIiwicGJlczJLdyIsImFlc0djbUt3Iiwia2V5VG9KV0siLCJFQ0RILmdlbmVyYXRlRXBrIiwiZ2V0VmVyaWZ5S2V5IiwiZ2V0U2lnbktleSIsImJhc2U2NHVybC5lbmNvZGUiLCJiYXNlNjR1cmwuZGVjb2RlIiwiZ2VuZXJhdGVTZWNyZXQiLCJnZW5lcmF0ZUtleVBhaXIiLCJnZW5lcmF0ZSIsIkpPU0UuZGVjb2RlUHJvdGVjdGVkSGVhZGVyIiwiSk9TRS5nZW5lcmF0ZUtleVBhaXIiLCJKT1NFLkNvbXBhY3RTaWduIiwiSk9TRS5jb21wYWN0VmVyaWZ5IiwiSk9TRS5Db21wYWN0RW5jcnlwdCIsIkpPU0UuY29tcGFjdERlY3J5cHQiLCJKT1NFLmdlbmVyYXRlU2VjcmV0IiwiSk9TRS5iYXNlNjR1cmwuZW5jb2RlIiwiSk9TRS5iYXNlNjR1cmwuZGVjb2RlIiwiSk9TRS5leHBvcnRKV0siLCJKT1NFLmltcG9ydEpXSyIsIkpPU0UuR2VuZXJhbEVuY3J5cHQiLCJKT1NFLmdlbmVyYWxEZWNyeXB0IiwiSk9TRS5HZW5lcmFsU2lnbiIsIkpPU0UuZ2VuZXJhbFZlcmlmeSIsIkxvY2FsQ29sbGVjdGlvbiIsInBrZy5kZWZhdWx0Il0sIm1hcHBpbmdzIjoiQUFBQSxlQUFlLE1BQU0sQ0FBQztBQUNmLE1BQU0sV0FBVyxHQUFHLENBQUMsR0FBRyxLQUFLLEdBQUcsWUFBWSxTQUFTOztBQ0E1RCxNQUFNQSxRQUFNLEdBQUcsT0FBTyxTQUFTLEVBQUUsSUFBSSxLQUFLO0FBQzFDLElBQUksTUFBTSxZQUFZLEdBQUcsQ0FBQyxJQUFJLEVBQUUsU0FBUyxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztBQUN0RCxJQUFJLE9BQU8sSUFBSSxVQUFVLENBQUMsTUFBTUMsUUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsWUFBWSxFQUFFLElBQUksQ0FBQyxDQUFDLENBQUM7QUFDMUUsQ0FBQzs7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TCxJQUFJLElBQUksR0FBRyxDQUFDLElBQUksS0FBSyxRQUFRLEVBQUU7QUFDL0IsUUFBUSxNQUFNLElBQUksU0FBUyxDQUFDLENBQUMsRUFBRSxLQUFLLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLGlFQUFpRSxDQUFDLENBQUMsQ0FBQztBQUN0SCxLQUFLO0FBQ0wsSUFBSSxJQUFJLEtBQUssS0FBSyxNQUFNLElBQUksR0FBRyxDQUFDLElBQUksS0FBSyxRQUFRLEVBQUU7QUFDbkQsUUFBUSxNQUFNLElBQUksU0FBUyxDQUFDLENBQUMsRUFBRSxLQUFLLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLHFFQUFxRSxDQUFDLENBQUMsQ0FBQztBQUMxSCxLQUFLO0FBQ0wsSUFBSSxJQUFJLEtBQUssS0FBSyxTQUFTLElBQUksR0FBRyxDQUFDLElBQUksS0FBSyxRQUFRLEVBQUU7QUFDdEQsUUFBUSxNQUFNLElBQUksU0FBUyxDQUFDLENBQUMsRUFBRSxLQUFLLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLHdFQUF3RSxDQUFDLENBQUMsQ0FBQztBQUM3SCxLQUFLO0FBQ0wsSUFBSSxJQUFJLEdBQUcsQ0FBQyxTQUFTLElBQUksS0FBSyxLQUFLLFFBQVEsSUFBSSxHQUFHLENBQUMsSUFBSSxLQUFLLFNBQVMsRUFBRTtBQUN2RSxRQUFRLE1BQU0sSUFBSSxTQUFTLENBQUMsQ0FBQyxFQUFFLEtBQUssQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUMsc0VBQXNFLENBQUMsQ0FBQyxDQUFDO0FBQzNILEtBQUs7QUFDTCxJQUFJLElBQUksR0FBRyxDQUFDLFNBQVMsSUFBSSxLQUFLLEtBQUssU0FBUyxJQUFJLEdBQUcsQ0FBQyxJQUFJLEtBQUssU0FBUyxFQUFFO0FBQ3hFLFFBQVEsTUFBTSxJQUFJLFNBQVMsQ0FBQyxDQUFDLEVBQUUsS0FBSyxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyx1RUFBdUUsQ0FBQyxDQUFDLENBQUM7QUFDNUgsS0FBSztBQUNMLENBQUMsQ0FB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QyxHQUFHLENBQUMsRUFBRSxFQUFFLE1BQU0sRUFBRSxPQUFPLENBQUMsQ0FBQztBQUMxRSxNQUFNLEdBQUcsR0FBRyxlQUFlLEVBQUUsV0FBVyxFQUFFLEVBQUUsRUFBRSxLQUFLLElBQUksTUFBTSxFQUFFLElBQUksRUFBRSxXQUFXLENBQUMsQ0FBQztBQUNsRixNQUFNLE9BQU8sSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0FBQzVCLEtBQUs7QUFDTDtBQUNBO0FBQ0EsSUFBSSxJQUFJLE9BQU8sR0FBRyxRQUFRLENBQUMsRUFBRSxDQUFDLENBQUM7QUFDL0IsSUFBSSxPQUFPLFFBQVEsQ0FBQyxFQUFFLENBQUMsQ0FBQztBQUN4QixJQUFJLElBQUksQ0FBQyxPQUFPLEVBQUUsT0FBTyxPQUFPLEdBQUcsQ0FBQyxFQUFFLGVBQWUsQ0FBQyxtQkFBbUIsRUFBRSxLQUFLLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7QUFDMUYsSUFBSSxJQUFJLEtBQUssRUFBRSxPQUFPLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDO0FBQ3JDLFNBQVMsT0FBTyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQztBQUNqQyxHQUFHO0FBQ0g7QUFDQTtBQUNBLEVBQUUsUUFBUSxDQUFDLGdCQUFnQixDQUFDLFNBQVMsRUFBRSxPQUFPLENBQUMsQ0FBQztBQUNoRCxFQUFFLE9BQU8sR0FBRyxDQUFDLEVBQUUsZUFBZSxDQUFDLGtCQUFrQixFQUFFLFdBQVcsQ0FBQyxDQUFDLENBQUMsQ0FBQztBQUNsRSxFQUFFLE9BQU8sT0FBTyxDQUFDO0FBQ2pCOzs7OyIsInhfZ29vZ2xlX2lnbm9yZUxpc3QiOlswLDEsMiwzLDQsNSw2LDcsOCw5LDEwLDExLDEyLDEzLDE0LDE1LDE2LDE3LDE4LDE5LDIwLDIxLDIyLDIzLDI0LDI1LDI2LDI3LDI4LDI5LDMwLDMxLDMyLDMzLDM0LDM1LDM2LDM3LDM4LDM5LDQwLDQxLDQyLDQzLDQ0LDQ1LDQ2LDQ3LDQ4LDQ5LDUwLDUxLDUyLDUzLDU0LDU1LDU2LDcwXX0=
