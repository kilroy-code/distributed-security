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
    return  new CompactEncrypt(inputBuffer).setProtectedHeader(header).encrypt(secret);
  },
  async decrypt(key, encrypted, options) { // Promise {payload, text, json}, where text and json are only defined when appropriate.
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

  async wrapKey(key, wrappingKey) { // Promise a JWE from the public wrappingKey
    let exported = await this.exportJWK(key);
    return this.encrypt(wrappingKey, exported);
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

const origin = location.origin;

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
  uri(collectionName, tag) {
    // Pathname expected by our signed-cloud-server.
    return `${origin}/db/${collectionName}/${tag}.json`; // fixme origin
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
  static async wrap(keys, wrappingData = '') { // Encrypt keyset by getUserDeviceSecret.
    let {decryptingKey, signingKey, tag} = keys,
        vaultKey = {decryptingKey, signingKey},
        wrappingKey = {[wrappingData]: await this.getSecret(tag, wrappingData)};
    return MultiKrypto.wrapKey(vaultKey, wrappingKey);
  }
  async unwrap(wrappedKey) { // Decrypt keyset by getUserDeviceSecret.
    let parsed = wrappedKey.json,
        prompt = parsed.recipients[0].header.kid,
        secret = {[prompt]: await this.constructor.getSecret(this.tag, prompt)},
        exported = (await MultiKrypto.decrypt(secret, wrappedKey.json)).json;
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
          return reason;
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

var name$1 = "@kilroy-code/distributed-security";
var version$1 = "0.0.9";
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
var repository = {
	type: "git",
	url: "git+https://github.com/kilroy-code/distributed-security.git"
};
var publishConfig = {
	registry: "https://npm.pkg.github.com"
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
	"@kilroy-code/jsonrpc": "^0.0.3",
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
    if (rest.length > 1) return rest;
    let {tags = [], contentType, time, ...others} = rest[0] || {},
	{team} = others; // Do not strip team from others.
    if (!tags.length) {
      if (rest.length && rest[0].length) tags = rest; // rest not empty, and its first is string-like.
      else if (token) { // get from token
        if (token.signatures) tags = token.signatures.map(sig => this.decodeProtectedHeader(sig).kid);
        else if (token.recipients) tags = token.recipients.map(rec => rec.header.kid);
        else {
          try {
            let kid = this.decodeProtectedHeader(token).kid; // compact token
            if (kid) tags = [kid];
          } catch (e) {
            console.error('failure with', {rest, token, team, tags, e});
          }
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW50ZXJuYWwtYnJvd3Nlci1idW5kbGUubWpzIiwic291cmNlcyI6WyIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS93ZWJjcnlwdG8uanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9kaWdlc3QuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2J1ZmZlcl91dGlscy5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2Jhc2U2NHVybC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci91dGlsL2Vycm9ycy5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3JhbmRvbS5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvaXYuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2NoZWNrX2l2X2xlbmd0aC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2NoZWNrX2Nla19sZW5ndGguanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS90aW1pbmdfc2FmZV9lcXVhbC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvY3J5cHRvX2tleS5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9pc19rZXlfbGlrZS5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2RlY3J5cHQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2lzX2Rpc2pvaW50LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9pc19vYmplY3QuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9ib2d1cy5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2Flc2t3LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvZWNkaGVzLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9jaGVja19wMnMuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9wYmVzMmt3LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvc3VidGxlX3JzYWVzLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvY2hlY2tfa2V5X2xlbmd0aC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3JzYWVzLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9jZWsuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9qd2tfdG9fa2V5LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2tleS9pbXBvcnQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2NoZWNrX2tleV90eXBlLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvZW5jcnlwdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvYWVzZ2Nta3cuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2RlY3J5cHRfa2V5X21hbmFnZW1lbnQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL3ZhbGlkYXRlX2NyaXQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL3ZhbGlkYXRlX2FsZ29yaXRobXMuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandlL2ZsYXR0ZW5lZC9kZWNyeXB0LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3ZS9jb21wYWN0L2RlY3J5cHQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandlL2dlbmVyYWwvZGVjcnlwdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2tleV90b19qd2suanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIva2V5L2V4cG9ydC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvZW5jcnlwdF9rZXlfbWFuYWdlbWVudC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd2UvZmxhdHRlbmVkL2VuY3J5cHQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandlL2dlbmVyYWwvZW5jcnlwdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3N1YnRsZV9kc2EuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9nZXRfc2lnbl92ZXJpZnlfa2V5LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvdmVyaWZ5LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9mbGF0dGVuZWQvdmVyaWZ5LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9jb21wYWN0L3ZlcmlmeS5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd3MvZ2VuZXJhbC92ZXJpZnkuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandlL2NvbXBhY3QvZW5jcnlwdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3NpZ24uanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandzL2ZsYXR0ZW5lZC9zaWduLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9jb21wYWN0L3NpZ24uanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandzL2dlbmVyYWwvc2lnbi5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci91dGlsL2Jhc2U2NHVybC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci91dGlsL2RlY29kZV9wcm90ZWN0ZWRfaGVhZGVyLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvZ2VuZXJhdGUuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIva2V5L2dlbmVyYXRlX2tleV9wYWlyLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2tleS9nZW5lcmF0ZV9zZWNyZXQuanMiLCIuLi9saWIvYWxnb3JpdGhtcy5tanMiLCIuLi9saWIvcmF3LWJyb3dzZXIubWpzIiwiLi4vbGliL2tyeXB0by5tanMiLCIuLi9saWIvbXVsdGlLcnlwdG8ubWpzIiwiLi4vbGliL3N0b3JlLWluZGV4ZWQubWpzIiwiLi4vbGliL3NlY3JldC5tanMiLCIuLi9saWIvb3JpZ2luLWJyb3dzZXIubWpzIiwiLi4vbGliL3N0b3JhZ2UubWpzIiwiLi4vbGliL2tleVNldC5tanMiLCIuLi9saWIvcGFja2FnZS1sb2FkZXIubWpzIiwiLi4vbGliL2FwaS5tanMiLCIuLi9ub2RlX21vZHVsZXMvQGtpbHJveS1jb2RlL2pzb25ycGMvaW5kZXgubWpzIl0sInNvdXJjZXNDb250ZW50IjpbImV4cG9ydCBkZWZhdWx0IGNyeXB0bztcbmV4cG9ydCBjb25zdCBpc0NyeXB0b0tleSA9IChrZXkpID0+IGtleSBpbnN0YW5jZW9mIENyeXB0b0tleTtcbiIsImltcG9ydCBjcnlwdG8gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuY29uc3QgZGlnZXN0ID0gYXN5bmMgKGFsZ29yaXRobSwgZGF0YSkgPT4ge1xuICAgIGNvbnN0IHN1YnRsZURpZ2VzdCA9IGBTSEEtJHthbGdvcml0aG0uc2xpY2UoLTMpfWA7XG4gICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZGlnZXN0KHN1YnRsZURpZ2VzdCwgZGF0YSkpO1xufTtcbmV4cG9ydCBkZWZhdWx0IGRpZ2VzdDtcbiIsImltcG9ydCBkaWdlc3QgZnJvbSAnLi4vcnVudGltZS9kaWdlc3QuanMnO1xuZXhwb3J0IGNvbnN0IGVuY29kZXIgPSBuZXcgVGV4dEVuY29kZXIoKTtcbmV4cG9ydCBjb25zdCBkZWNvZGVyID0gbmV3IFRleHREZWNvZGVyKCk7XG5jb25zdCBNQVhfSU5UMzIgPSAyICoqIDMyO1xuZXhwb3J0IGZ1bmN0aW9uIGNvbmNhdCguLi5idWZmZXJzKSB7XG4gICAgY29uc3Qgc2l6ZSA9IGJ1ZmZlcnMucmVkdWNlKChhY2MsIHsgbGVuZ3RoIH0pID0+IGFjYyArIGxlbmd0aCwgMCk7XG4gICAgY29uc3QgYnVmID0gbmV3IFVpbnQ4QXJyYXkoc2l6ZSk7XG4gICAgbGV0IGkgPSAwO1xuICAgIGZvciAoY29uc3QgYnVmZmVyIG9mIGJ1ZmZlcnMpIHtcbiAgICAgICAgYnVmLnNldChidWZmZXIsIGkpO1xuICAgICAgICBpICs9IGJ1ZmZlci5sZW5ndGg7XG4gICAgfVxuICAgIHJldHVybiBidWY7XG59XG5leHBvcnQgZnVuY3Rpb24gcDJzKGFsZywgcDJzSW5wdXQpIHtcbiAgICByZXR1cm4gY29uY2F0KGVuY29kZXIuZW5jb2RlKGFsZyksIG5ldyBVaW50OEFycmF5KFswXSksIHAyc0lucHV0KTtcbn1cbmZ1bmN0aW9uIHdyaXRlVUludDMyQkUoYnVmLCB2YWx1ZSwgb2Zmc2V0KSB7XG4gICAgaWYgKHZhbHVlIDwgMCB8fCB2YWx1ZSA+PSBNQVhfSU5UMzIpIHtcbiAgICAgICAgdGhyb3cgbmV3IFJhbmdlRXJyb3IoYHZhbHVlIG11c3QgYmUgPj0gMCBhbmQgPD0gJHtNQVhfSU5UMzIgLSAxfS4gUmVjZWl2ZWQgJHt2YWx1ZX1gKTtcbiAgICB9XG4gICAgYnVmLnNldChbdmFsdWUgPj4+IDI0LCB2YWx1ZSA+Pj4gMTYsIHZhbHVlID4+PiA4LCB2YWx1ZSAmIDB4ZmZdLCBvZmZzZXQpO1xufVxuZXhwb3J0IGZ1bmN0aW9uIHVpbnQ2NGJlKHZhbHVlKSB7XG4gICAgY29uc3QgaGlnaCA9IE1hdGguZmxvb3IodmFsdWUgLyBNQVhfSU5UMzIpO1xuICAgIGNvbnN0IGxvdyA9IHZhbHVlICUgTUFYX0lOVDMyO1xuICAgIGNvbnN0IGJ1ZiA9IG5ldyBVaW50OEFycmF5KDgpO1xuICAgIHdyaXRlVUludDMyQkUoYnVmLCBoaWdoLCAwKTtcbiAgICB3cml0ZVVJbnQzMkJFKGJ1ZiwgbG93LCA0KTtcbiAgICByZXR1cm4gYnVmO1xufVxuZXhwb3J0IGZ1bmN0aW9uIHVpbnQzMmJlKHZhbHVlKSB7XG4gICAgY29uc3QgYnVmID0gbmV3IFVpbnQ4QXJyYXkoNCk7XG4gICAgd3JpdGVVSW50MzJCRShidWYsIHZhbHVlKTtcbiAgICByZXR1cm4gYnVmO1xufVxuZXhwb3J0IGZ1bmN0aW9uIGxlbmd0aEFuZElucHV0KGlucHV0KSB7XG4gICAgcmV0dXJuIGNvbmNhdCh1aW50MzJiZShpbnB1dC5sZW5ndGgpLCBpbnB1dCk7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gY29uY2F0S2RmKHNlY3JldCwgYml0cywgdmFsdWUpIHtcbiAgICBjb25zdCBpdGVyYXRpb25zID0gTWF0aC5jZWlsKChiaXRzID4+IDMpIC8gMzIpO1xuICAgIGNvbnN0IHJlcyA9IG5ldyBVaW50OEFycmF5KGl0ZXJhdGlvbnMgKiAzMik7XG4gICAgZm9yIChsZXQgaXRlciA9IDA7IGl0ZXIgPCBpdGVyYXRpb25zOyBpdGVyKyspIHtcbiAgICAgICAgY29uc3QgYnVmID0gbmV3IFVpbnQ4QXJyYXkoNCArIHNlY3JldC5sZW5ndGggKyB2YWx1ZS5sZW5ndGgpO1xuICAgICAgICBidWYuc2V0KHVpbnQzMmJlKGl0ZXIgKyAxKSk7XG4gICAgICAgIGJ1Zi5zZXQoc2VjcmV0LCA0KTtcbiAgICAgICAgYnVmLnNldCh2YWx1ZSwgNCArIHNlY3JldC5sZW5ndGgpO1xuICAgICAgICByZXMuc2V0KGF3YWl0IGRpZ2VzdCgnc2hhMjU2JywgYnVmKSwgaXRlciAqIDMyKTtcbiAgICB9XG4gICAgcmV0dXJuIHJlcy5zbGljZSgwLCBiaXRzID4+IDMpO1xufVxuIiwiaW1wb3J0IHsgZW5jb2RlciwgZGVjb2RlciB9IGZyb20gJy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuZXhwb3J0IGNvbnN0IGVuY29kZUJhc2U2NCA9IChpbnB1dCkgPT4ge1xuICAgIGxldCB1bmVuY29kZWQgPSBpbnB1dDtcbiAgICBpZiAodHlwZW9mIHVuZW5jb2RlZCA9PT0gJ3N0cmluZycpIHtcbiAgICAgICAgdW5lbmNvZGVkID0gZW5jb2Rlci5lbmNvZGUodW5lbmNvZGVkKTtcbiAgICB9XG4gICAgY29uc3QgQ0hVTktfU0laRSA9IDB4ODAwMDtcbiAgICBjb25zdCBhcnIgPSBbXTtcbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IHVuZW5jb2RlZC5sZW5ndGg7IGkgKz0gQ0hVTktfU0laRSkge1xuICAgICAgICBhcnIucHVzaChTdHJpbmcuZnJvbUNoYXJDb2RlLmFwcGx5KG51bGwsIHVuZW5jb2RlZC5zdWJhcnJheShpLCBpICsgQ0hVTktfU0laRSkpKTtcbiAgICB9XG4gICAgcmV0dXJuIGJ0b2EoYXJyLmpvaW4oJycpKTtcbn07XG5leHBvcnQgY29uc3QgZW5jb2RlID0gKGlucHV0KSA9PiB7XG4gICAgcmV0dXJuIGVuY29kZUJhc2U2NChpbnB1dCkucmVwbGFjZSgvPS9nLCAnJykucmVwbGFjZSgvXFwrL2csICctJykucmVwbGFjZSgvXFwvL2csICdfJyk7XG59O1xuZXhwb3J0IGNvbnN0IGRlY29kZUJhc2U2NCA9IChlbmNvZGVkKSA9PiB7XG4gICAgY29uc3QgYmluYXJ5ID0gYXRvYihlbmNvZGVkKTtcbiAgICBjb25zdCBieXRlcyA9IG5ldyBVaW50OEFycmF5KGJpbmFyeS5sZW5ndGgpO1xuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgYmluYXJ5Lmxlbmd0aDsgaSsrKSB7XG4gICAgICAgIGJ5dGVzW2ldID0gYmluYXJ5LmNoYXJDb2RlQXQoaSk7XG4gICAgfVxuICAgIHJldHVybiBieXRlcztcbn07XG5leHBvcnQgY29uc3QgZGVjb2RlID0gKGlucHV0KSA9PiB7XG4gICAgbGV0IGVuY29kZWQgPSBpbnB1dDtcbiAgICBpZiAoZW5jb2RlZCBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgZW5jb2RlZCA9IGRlY29kZXIuZGVjb2RlKGVuY29kZWQpO1xuICAgIH1cbiAgICBlbmNvZGVkID0gZW5jb2RlZC5yZXBsYWNlKC8tL2csICcrJykucmVwbGFjZSgvXy9nLCAnLycpLnJlcGxhY2UoL1xccy9nLCAnJyk7XG4gICAgdHJ5IHtcbiAgICAgICAgcmV0dXJuIGRlY29kZUJhc2U2NChlbmNvZGVkKTtcbiAgICB9XG4gICAgY2F0Y2gge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdUaGUgaW5wdXQgdG8gYmUgZGVjb2RlZCBpcyBub3QgY29ycmVjdGx5IGVuY29kZWQuJyk7XG4gICAgfVxufTtcbiIsImV4cG9ydCBjbGFzcyBKT1NFRXJyb3IgZXh0ZW5kcyBFcnJvciB7XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KT1NFX0dFTkVSSUMnO1xuICAgIH1cbiAgICBjb25zdHJ1Y3RvcihtZXNzYWdlKSB7XG4gICAgICAgIHN1cGVyKG1lc3NhZ2UpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pPU0VfR0VORVJJQyc7XG4gICAgICAgIHRoaXMubmFtZSA9IHRoaXMuY29uc3RydWN0b3IubmFtZTtcbiAgICAgICAgRXJyb3IuY2FwdHVyZVN0YWNrVHJhY2U/Lih0aGlzLCB0aGlzLmNvbnN0cnVjdG9yKTtcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgSldUQ2xhaW1WYWxpZGF0aW9uRmFpbGVkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pXVF9DTEFJTV9WQUxJREFUSU9OX0ZBSUxFRCc7XG4gICAgfVxuICAgIGNvbnN0cnVjdG9yKG1lc3NhZ2UsIGNsYWltID0gJ3Vuc3BlY2lmaWVkJywgcmVhc29uID0gJ3Vuc3BlY2lmaWVkJykge1xuICAgICAgICBzdXBlcihtZXNzYWdlKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV1RfQ0xBSU1fVkFMSURBVElPTl9GQUlMRUQnO1xuICAgICAgICB0aGlzLmNsYWltID0gY2xhaW07XG4gICAgICAgIHRoaXMucmVhc29uID0gcmVhc29uO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV1RFeHBpcmVkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pXVF9FWFBJUkVEJztcbiAgICB9XG4gICAgY29uc3RydWN0b3IobWVzc2FnZSwgY2xhaW0gPSAndW5zcGVjaWZpZWQnLCByZWFzb24gPSAndW5zcGVjaWZpZWQnKSB7XG4gICAgICAgIHN1cGVyKG1lc3NhZ2UpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXVF9FWFBJUkVEJztcbiAgICAgICAgdGhpcy5jbGFpbSA9IGNsYWltO1xuICAgICAgICB0aGlzLnJlYXNvbiA9IHJlYXNvbjtcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgSk9TRUFsZ05vdEFsbG93ZWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pPU0VfQUxHX05PVF9BTExPV0VEJztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KT1NFX0FMR19OT1RfQUxMT1dFRCc7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpPU0VOb3RTdXBwb3J0ZWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pPU0VfTk9UX1NVUFBPUlRFRCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSk9TRV9OT1RfU1VQUE9SVEVEJztcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgSldFRGVjcnlwdGlvbkZhaWxlZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldFX0RFQ1JZUFRJT05fRkFJTEVEJztcbiAgICAgICAgdGhpcy5tZXNzYWdlID0gJ2RlY3J5cHRpb24gb3BlcmF0aW9uIGZhaWxlZCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldFX0RFQ1JZUFRJT05fRkFJTEVEJztcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgSldFSW52YWxpZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldFX0lOVkFMSUQnO1xuICAgIH1cbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pXRV9JTlZBTElEJztcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgSldTSW52YWxpZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldTX0lOVkFMSUQnO1xuICAgIH1cbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pXU19JTlZBTElEJztcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgSldUSW52YWxpZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldUX0lOVkFMSUQnO1xuICAgIH1cbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pXVF9JTlZBTElEJztcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgSldLSW52YWxpZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldLX0lOVkFMSUQnO1xuICAgIH1cbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pXS19JTlZBTElEJztcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgSldLU0ludmFsaWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXS1NfSU5WQUxJRCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldLU19JTlZBTElEJztcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgSldLU05vTWF0Y2hpbmdLZXkgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXS1NfTk9fTUFUQ0hJTkdfS0VZJztcbiAgICAgICAgdGhpcy5tZXNzYWdlID0gJ25vIGFwcGxpY2FibGUga2V5IGZvdW5kIGluIHRoZSBKU09OIFdlYiBLZXkgU2V0JztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV0tTX05PX01BVENISU5HX0tFWSc7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXS1NNdWx0aXBsZU1hdGNoaW5nS2V5cyBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldLU19NVUxUSVBMRV9NQVRDSElOR19LRVlTJztcbiAgICAgICAgdGhpcy5tZXNzYWdlID0gJ211bHRpcGxlIG1hdGNoaW5nIGtleXMgZm91bmQgaW4gdGhlIEpTT04gV2ViIEtleSBTZXQnO1xuICAgIH1cbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pXS1NfTVVMVElQTEVfTUFUQ0hJTkdfS0VZUyc7XG4gICAgfVxufVxuU3ltYm9sLmFzeW5jSXRlcmF0b3I7XG5leHBvcnQgY2xhc3MgSldLU1RpbWVvdXQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXS1NfVElNRU9VVCc7XG4gICAgICAgIHRoaXMubWVzc2FnZSA9ICdyZXF1ZXN0IHRpbWVkIG91dCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldLU19USU1FT1VUJztcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgSldTU2lnbmF0dXJlVmVyaWZpY2F0aW9uRmFpbGVkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV1NfU0lHTkFUVVJFX1ZFUklGSUNBVElPTl9GQUlMRUQnO1xuICAgICAgICB0aGlzLm1lc3NhZ2UgPSAnc2lnbmF0dXJlIHZlcmlmaWNhdGlvbiBmYWlsZWQnO1xuICAgIH1cbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pXU19TSUdOQVRVUkVfVkVSSUZJQ0FUSU9OX0ZBSUxFRCc7XG4gICAgfVxufVxuIiwiaW1wb3J0IGNyeXB0byBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5leHBvcnQgZGVmYXVsdCBjcnlwdG8uZ2V0UmFuZG9tVmFsdWVzLmJpbmQoY3J5cHRvKTtcbiIsImltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgcmFuZG9tIGZyb20gJy4uL3J1bnRpbWUvcmFuZG9tLmpzJztcbmV4cG9ydCBmdW5jdGlvbiBiaXRMZW5ndGgoYWxnKSB7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnQTEyOEdDTSc6XG4gICAgICAgIGNhc2UgJ0ExMjhHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ00nOlxuICAgICAgICBjYXNlICdBMTkyR0NNS1cnOlxuICAgICAgICBjYXNlICdBMjU2R0NNJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTUtXJzpcbiAgICAgICAgICAgIHJldHVybiA5NjtcbiAgICAgICAgY2FzZSAnQTEyOENCQy1IUzI1Nic6XG4gICAgICAgIGNhc2UgJ0ExOTJDQkMtSFMzODQnOlxuICAgICAgICBjYXNlICdBMjU2Q0JDLUhTNTEyJzpcbiAgICAgICAgICAgIHJldHVybiAxMjg7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZChgVW5zdXBwb3J0ZWQgSldFIEFsZ29yaXRobTogJHthbGd9YCk7XG4gICAgfVxufVxuZXhwb3J0IGRlZmF1bHQgKGFsZykgPT4gcmFuZG9tKG5ldyBVaW50OEFycmF5KGJpdExlbmd0aChhbGcpID4+IDMpKTtcbiIsImltcG9ydCB7IEpXRUludmFsaWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgeyBiaXRMZW5ndGggfSBmcm9tICcuL2l2LmpzJztcbmNvbnN0IGNoZWNrSXZMZW5ndGggPSAoZW5jLCBpdikgPT4ge1xuICAgIGlmIChpdi5sZW5ndGggPDwgMyAhPT0gYml0TGVuZ3RoKGVuYykpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ludmFsaWQgSW5pdGlhbGl6YXRpb24gVmVjdG9yIGxlbmd0aCcpO1xuICAgIH1cbn07XG5leHBvcnQgZGVmYXVsdCBjaGVja0l2TGVuZ3RoO1xuIiwiaW1wb3J0IHsgSldFSW52YWxpZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmNvbnN0IGNoZWNrQ2VrTGVuZ3RoID0gKGNlaywgZXhwZWN0ZWQpID0+IHtcbiAgICBjb25zdCBhY3R1YWwgPSBjZWsuYnl0ZUxlbmd0aCA8PCAzO1xuICAgIGlmIChhY3R1YWwgIT09IGV4cGVjdGVkKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKGBJbnZhbGlkIENvbnRlbnQgRW5jcnlwdGlvbiBLZXkgbGVuZ3RoLiBFeHBlY3RlZCAke2V4cGVjdGVkfSBiaXRzLCBnb3QgJHthY3R1YWx9IGJpdHNgKTtcbiAgICB9XG59O1xuZXhwb3J0IGRlZmF1bHQgY2hlY2tDZWtMZW5ndGg7XG4iLCJjb25zdCB0aW1pbmdTYWZlRXF1YWwgPSAoYSwgYikgPT4ge1xuICAgIGlmICghKGEgaW5zdGFuY2VvZiBVaW50OEFycmF5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdGaXJzdCBhcmd1bWVudCBtdXN0IGJlIGEgYnVmZmVyJyk7XG4gICAgfVxuICAgIGlmICghKGIgaW5zdGFuY2VvZiBVaW50OEFycmF5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdTZWNvbmQgYXJndW1lbnQgbXVzdCBiZSBhIGJ1ZmZlcicpO1xuICAgIH1cbiAgICBpZiAoYS5sZW5ndGggIT09IGIubGVuZ3RoKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0lucHV0IGJ1ZmZlcnMgbXVzdCBoYXZlIHRoZSBzYW1lIGxlbmd0aCcpO1xuICAgIH1cbiAgICBjb25zdCBsZW4gPSBhLmxlbmd0aDtcbiAgICBsZXQgb3V0ID0gMDtcbiAgICBsZXQgaSA9IC0xO1xuICAgIHdoaWxlICgrK2kgPCBsZW4pIHtcbiAgICAgICAgb3V0IHw9IGFbaV0gXiBiW2ldO1xuICAgIH1cbiAgICByZXR1cm4gb3V0ID09PSAwO1xufTtcbmV4cG9ydCBkZWZhdWx0IHRpbWluZ1NhZmVFcXVhbDtcbiIsImZ1bmN0aW9uIHVudXNhYmxlKG5hbWUsIHByb3AgPSAnYWxnb3JpdGhtLm5hbWUnKSB7XG4gICAgcmV0dXJuIG5ldyBUeXBlRXJyb3IoYENyeXB0b0tleSBkb2VzIG5vdCBzdXBwb3J0IHRoaXMgb3BlcmF0aW9uLCBpdHMgJHtwcm9wfSBtdXN0IGJlICR7bmFtZX1gKTtcbn1cbmZ1bmN0aW9uIGlzQWxnb3JpdGhtKGFsZ29yaXRobSwgbmFtZSkge1xuICAgIHJldHVybiBhbGdvcml0aG0ubmFtZSA9PT0gbmFtZTtcbn1cbmZ1bmN0aW9uIGdldEhhc2hMZW5ndGgoaGFzaCkge1xuICAgIHJldHVybiBwYXJzZUludChoYXNoLm5hbWUuc2xpY2UoNCksIDEwKTtcbn1cbmZ1bmN0aW9uIGdldE5hbWVkQ3VydmUoYWxnKSB7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnRVMyNTYnOlxuICAgICAgICAgICAgcmV0dXJuICdQLTI1Nic7XG4gICAgICAgIGNhc2UgJ0VTMzg0JzpcbiAgICAgICAgICAgIHJldHVybiAnUC0zODQnO1xuICAgICAgICBjYXNlICdFUzUxMic6XG4gICAgICAgICAgICByZXR1cm4gJ1AtNTIxJztcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcigndW5yZWFjaGFibGUnKTtcbiAgICB9XG59XG5mdW5jdGlvbiBjaGVja1VzYWdlKGtleSwgdXNhZ2VzKSB7XG4gICAgaWYgKHVzYWdlcy5sZW5ndGggJiYgIXVzYWdlcy5zb21lKChleHBlY3RlZCkgPT4ga2V5LnVzYWdlcy5pbmNsdWRlcyhleHBlY3RlZCkpKSB7XG4gICAgICAgIGxldCBtc2cgPSAnQ3J5cHRvS2V5IGRvZXMgbm90IHN1cHBvcnQgdGhpcyBvcGVyYXRpb24sIGl0cyB1c2FnZXMgbXVzdCBpbmNsdWRlICc7XG4gICAgICAgIGlmICh1c2FnZXMubGVuZ3RoID4gMikge1xuICAgICAgICAgICAgY29uc3QgbGFzdCA9IHVzYWdlcy5wb3AoKTtcbiAgICAgICAgICAgIG1zZyArPSBgb25lIG9mICR7dXNhZ2VzLmpvaW4oJywgJyl9LCBvciAke2xhc3R9LmA7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSBpZiAodXNhZ2VzLmxlbmd0aCA9PT0gMikge1xuICAgICAgICAgICAgbXNnICs9IGBvbmUgb2YgJHt1c2FnZXNbMF19IG9yICR7dXNhZ2VzWzFdfS5gO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgbXNnICs9IGAke3VzYWdlc1swXX0uYDtcbiAgICAgICAgfVxuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKG1zZyk7XG4gICAgfVxufVxuZXhwb3J0IGZ1bmN0aW9uIGNoZWNrU2lnQ3J5cHRvS2V5KGtleSwgYWxnLCAuLi51c2FnZXMpIHtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdIUzI1Nic6XG4gICAgICAgIGNhc2UgJ0hTMzg0JzpcbiAgICAgICAgY2FzZSAnSFM1MTInOiB7XG4gICAgICAgICAgICBpZiAoIWlzQWxnb3JpdGhtKGtleS5hbGdvcml0aG0sICdITUFDJykpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ0hNQUMnKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGVjdGVkID0gcGFyc2VJbnQoYWxnLnNsaWNlKDIpLCAxMCk7XG4gICAgICAgICAgICBjb25zdCBhY3R1YWwgPSBnZXRIYXNoTGVuZ3RoKGtleS5hbGdvcml0aG0uaGFzaCk7XG4gICAgICAgICAgICBpZiAoYWN0dWFsICE9PSBleHBlY3RlZClcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZShgU0hBLSR7ZXhwZWN0ZWR9YCwgJ2FsZ29yaXRobS5oYXNoJyk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdSUzI1Nic6XG4gICAgICAgIGNhc2UgJ1JTMzg0JzpcbiAgICAgICAgY2FzZSAnUlM1MTInOiB7XG4gICAgICAgICAgICBpZiAoIWlzQWxnb3JpdGhtKGtleS5hbGdvcml0aG0sICdSU0FTU0EtUEtDUzEtdjFfNScpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdSU0FTU0EtUEtDUzEtdjFfNScpO1xuICAgICAgICAgICAgY29uc3QgZXhwZWN0ZWQgPSBwYXJzZUludChhbGcuc2xpY2UoMiksIDEwKTtcbiAgICAgICAgICAgIGNvbnN0IGFjdHVhbCA9IGdldEhhc2hMZW5ndGgoa2V5LmFsZ29yaXRobS5oYXNoKTtcbiAgICAgICAgICAgIGlmIChhY3R1YWwgIT09IGV4cGVjdGVkKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKGBTSEEtJHtleHBlY3RlZH1gLCAnYWxnb3JpdGhtLmhhc2gnKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ1BTMjU2JzpcbiAgICAgICAgY2FzZSAnUFMzODQnOlxuICAgICAgICBjYXNlICdQUzUxMic6IHtcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ1JTQS1QU1MnKSlcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnUlNBLVBTUycpO1xuICAgICAgICAgICAgY29uc3QgZXhwZWN0ZWQgPSBwYXJzZUludChhbGcuc2xpY2UoMiksIDEwKTtcbiAgICAgICAgICAgIGNvbnN0IGFjdHVhbCA9IGdldEhhc2hMZW5ndGgoa2V5LmFsZ29yaXRobS5oYXNoKTtcbiAgICAgICAgICAgIGlmIChhY3R1YWwgIT09IGV4cGVjdGVkKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKGBTSEEtJHtleHBlY3RlZH1gLCAnYWxnb3JpdGhtLmhhc2gnKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0VkRFNBJzoge1xuICAgICAgICAgICAgaWYgKGtleS5hbGdvcml0aG0ubmFtZSAhPT0gJ0VkMjU1MTknICYmIGtleS5hbGdvcml0aG0ubmFtZSAhPT0gJ0VkNDQ4Jykge1xuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdFZDI1NTE5IG9yIEVkNDQ4Jyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdFUzI1Nic6XG4gICAgICAgIGNhc2UgJ0VTMzg0JzpcbiAgICAgICAgY2FzZSAnRVM1MTInOiB7XG4gICAgICAgICAgICBpZiAoIWlzQWxnb3JpdGhtKGtleS5hbGdvcml0aG0sICdFQ0RTQScpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdFQ0RTQScpO1xuICAgICAgICAgICAgY29uc3QgZXhwZWN0ZWQgPSBnZXROYW1lZEN1cnZlKGFsZyk7XG4gICAgICAgICAgICBjb25zdCBhY3R1YWwgPSBrZXkuYWxnb3JpdGhtLm5hbWVkQ3VydmU7XG4gICAgICAgICAgICBpZiAoYWN0dWFsICE9PSBleHBlY3RlZClcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZShleHBlY3RlZCwgJ2FsZ29yaXRobS5uYW1lZEN1cnZlJyk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignQ3J5cHRvS2V5IGRvZXMgbm90IHN1cHBvcnQgdGhpcyBvcGVyYXRpb24nKTtcbiAgICB9XG4gICAgY2hlY2tVc2FnZShrZXksIHVzYWdlcyk7XG59XG5leHBvcnQgZnVuY3Rpb24gY2hlY2tFbmNDcnlwdG9LZXkoa2V5LCBhbGcsIC4uLnVzYWdlcykge1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ0ExMjhHQ00nOlxuICAgICAgICBjYXNlICdBMTkyR0NNJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTSc6IHtcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ0FFUy1HQ00nKSlcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnQUVTLUdDTScpO1xuICAgICAgICAgICAgY29uc3QgZXhwZWN0ZWQgPSBwYXJzZUludChhbGcuc2xpY2UoMSwgNCksIDEwKTtcbiAgICAgICAgICAgIGNvbnN0IGFjdHVhbCA9IGtleS5hbGdvcml0aG0ubGVuZ3RoO1xuICAgICAgICAgICAgaWYgKGFjdHVhbCAhPT0gZXhwZWN0ZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoZXhwZWN0ZWQsICdhbGdvcml0aG0ubGVuZ3RoJyk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdBMTI4S1cnOlxuICAgICAgICBjYXNlICdBMTkyS1cnOlxuICAgICAgICBjYXNlICdBMjU2S1cnOiB7XG4gICAgICAgICAgICBpZiAoIWlzQWxnb3JpdGhtKGtleS5hbGdvcml0aG0sICdBRVMtS1cnKSlcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnQUVTLUtXJyk7XG4gICAgICAgICAgICBjb25zdCBleHBlY3RlZCA9IHBhcnNlSW50KGFsZy5zbGljZSgxLCA0KSwgMTApO1xuICAgICAgICAgICAgY29uc3QgYWN0dWFsID0ga2V5LmFsZ29yaXRobS5sZW5ndGg7XG4gICAgICAgICAgICBpZiAoYWN0dWFsICE9PSBleHBlY3RlZClcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZShleHBlY3RlZCwgJ2FsZ29yaXRobS5sZW5ndGgnKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0VDREgnOiB7XG4gICAgICAgICAgICBzd2l0Y2ggKGtleS5hbGdvcml0aG0ubmFtZSkge1xuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1gyNTUxOSc6XG4gICAgICAgICAgICAgICAgY2FzZSAnWDQ0OCc6XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdFQ0RILCBYMjU1MTksIG9yIFg0NDgnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ1BCRVMyLUhTMjU2K0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ1BCRVMyLUhTMzg0K0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ1BCRVMyLUhTNTEyK0EyNTZLVyc6XG4gICAgICAgICAgICBpZiAoIWlzQWxnb3JpdGhtKGtleS5hbGdvcml0aG0sICdQQktERjInKSlcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnUEJLREYyJyk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0yNTYnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0zODQnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC01MTInOiB7XG4gICAgICAgICAgICBpZiAoIWlzQWxnb3JpdGhtKGtleS5hbGdvcml0aG0sICdSU0EtT0FFUCcpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdSU0EtT0FFUCcpO1xuICAgICAgICAgICAgY29uc3QgZXhwZWN0ZWQgPSBwYXJzZUludChhbGcuc2xpY2UoOSksIDEwKSB8fCAxO1xuICAgICAgICAgICAgY29uc3QgYWN0dWFsID0gZ2V0SGFzaExlbmd0aChrZXkuYWxnb3JpdGhtLmhhc2gpO1xuICAgICAgICAgICAgaWYgKGFjdHVhbCAhPT0gZXhwZWN0ZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoYFNIQS0ke2V4cGVjdGVkfWAsICdhbGdvcml0aG0uaGFzaCcpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0NyeXB0b0tleSBkb2VzIG5vdCBzdXBwb3J0IHRoaXMgb3BlcmF0aW9uJyk7XG4gICAgfVxuICAgIGNoZWNrVXNhZ2Uoa2V5LCB1c2FnZXMpO1xufVxuIiwiZnVuY3Rpb24gbWVzc2FnZShtc2csIGFjdHVhbCwgLi4udHlwZXMpIHtcbiAgICBpZiAodHlwZXMubGVuZ3RoID4gMikge1xuICAgICAgICBjb25zdCBsYXN0ID0gdHlwZXMucG9wKCk7XG4gICAgICAgIG1zZyArPSBgb25lIG9mIHR5cGUgJHt0eXBlcy5qb2luKCcsICcpfSwgb3IgJHtsYXN0fS5gO1xuICAgIH1cbiAgICBlbHNlIGlmICh0eXBlcy5sZW5ndGggPT09IDIpIHtcbiAgICAgICAgbXNnICs9IGBvbmUgb2YgdHlwZSAke3R5cGVzWzBdfSBvciAke3R5cGVzWzFdfS5gO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgbXNnICs9IGBvZiB0eXBlICR7dHlwZXNbMF19LmA7XG4gICAgfVxuICAgIGlmIChhY3R1YWwgPT0gbnVsbCkge1xuICAgICAgICBtc2cgKz0gYCBSZWNlaXZlZCAke2FjdHVhbH1gO1xuICAgIH1cbiAgICBlbHNlIGlmICh0eXBlb2YgYWN0dWFsID09PSAnZnVuY3Rpb24nICYmIGFjdHVhbC5uYW1lKSB7XG4gICAgICAgIG1zZyArPSBgIFJlY2VpdmVkIGZ1bmN0aW9uICR7YWN0dWFsLm5hbWV9YDtcbiAgICB9XG4gICAgZWxzZSBpZiAodHlwZW9mIGFjdHVhbCA9PT0gJ29iamVjdCcgJiYgYWN0dWFsICE9IG51bGwpIHtcbiAgICAgICAgaWYgKGFjdHVhbC5jb25zdHJ1Y3Rvcj8ubmFtZSkge1xuICAgICAgICAgICAgbXNnICs9IGAgUmVjZWl2ZWQgYW4gaW5zdGFuY2Ugb2YgJHthY3R1YWwuY29uc3RydWN0b3IubmFtZX1gO1xuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiBtc2c7XG59XG5leHBvcnQgZGVmYXVsdCAoYWN0dWFsLCAuLi50eXBlcykgPT4ge1xuICAgIHJldHVybiBtZXNzYWdlKCdLZXkgbXVzdCBiZSAnLCBhY3R1YWwsIC4uLnR5cGVzKTtcbn07XG5leHBvcnQgZnVuY3Rpb24gd2l0aEFsZyhhbGcsIGFjdHVhbCwgLi4udHlwZXMpIHtcbiAgICByZXR1cm4gbWVzc2FnZShgS2V5IGZvciB0aGUgJHthbGd9IGFsZ29yaXRobSBtdXN0IGJlIGAsIGFjdHVhbCwgLi4udHlwZXMpO1xufVxuIiwiaW1wb3J0IHsgaXNDcnlwdG9LZXkgfSBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5leHBvcnQgZGVmYXVsdCAoa2V5KSA9PiB7XG4gICAgcmV0dXJuIGlzQ3J5cHRvS2V5KGtleSk7XG59O1xuZXhwb3J0IGNvbnN0IHR5cGVzID0gWydDcnlwdG9LZXknXTtcbiIsImltcG9ydCB7IGNvbmNhdCwgdWludDY0YmUgfSBmcm9tICcuLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmltcG9ydCBjaGVja0l2TGVuZ3RoIGZyb20gJy4uL2xpYi9jaGVja19pdl9sZW5ndGguanMnO1xuaW1wb3J0IGNoZWNrQ2VrTGVuZ3RoIGZyb20gJy4vY2hlY2tfY2VrX2xlbmd0aC5qcyc7XG5pbXBvcnQgdGltaW5nU2FmZUVxdWFsIGZyb20gJy4vdGltaW5nX3NhZmVfZXF1YWwuanMnO1xuaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCwgSldFRGVjcnlwdGlvbkZhaWxlZCwgSldFSW52YWxpZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCBjcnlwdG8sIHsgaXNDcnlwdG9LZXkgfSBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgeyBjaGVja0VuY0NyeXB0b0tleSB9IGZyb20gJy4uL2xpYi9jcnlwdG9fa2V5LmpzJztcbmltcG9ydCBpbnZhbGlkS2V5SW5wdXQgZnJvbSAnLi4vbGliL2ludmFsaWRfa2V5X2lucHV0LmpzJztcbmltcG9ydCB7IHR5cGVzIH0gZnJvbSAnLi9pc19rZXlfbGlrZS5qcyc7XG5hc3luYyBmdW5jdGlvbiBjYmNEZWNyeXB0KGVuYywgY2VrLCBjaXBoZXJ0ZXh0LCBpdiwgdGFnLCBhYWQpIHtcbiAgICBpZiAoIShjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChjZWssICdVaW50OEFycmF5JykpO1xuICAgIH1cbiAgICBjb25zdCBrZXlTaXplID0gcGFyc2VJbnQoZW5jLnNsaWNlKDEsIDQpLCAxMCk7XG4gICAgY29uc3QgZW5jS2V5ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGNlay5zdWJhcnJheShrZXlTaXplID4+IDMpLCAnQUVTLUNCQycsIGZhbHNlLCBbJ2RlY3J5cHQnXSk7XG4gICAgY29uc3QgbWFjS2V5ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGNlay5zdWJhcnJheSgwLCBrZXlTaXplID4+IDMpLCB7XG4gICAgICAgIGhhc2g6IGBTSEEtJHtrZXlTaXplIDw8IDF9YCxcbiAgICAgICAgbmFtZTogJ0hNQUMnLFxuICAgIH0sIGZhbHNlLCBbJ3NpZ24nXSk7XG4gICAgY29uc3QgbWFjRGF0YSA9IGNvbmNhdChhYWQsIGl2LCBjaXBoZXJ0ZXh0LCB1aW50NjRiZShhYWQubGVuZ3RoIDw8IDMpKTtcbiAgICBjb25zdCBleHBlY3RlZFRhZyA9IG5ldyBVaW50OEFycmF5KChhd2FpdCBjcnlwdG8uc3VidGxlLnNpZ24oJ0hNQUMnLCBtYWNLZXksIG1hY0RhdGEpKS5zbGljZSgwLCBrZXlTaXplID4+IDMpKTtcbiAgICBsZXQgbWFjQ2hlY2tQYXNzZWQ7XG4gICAgdHJ5IHtcbiAgICAgICAgbWFjQ2hlY2tQYXNzZWQgPSB0aW1pbmdTYWZlRXF1YWwodGFnLCBleHBlY3RlZFRhZyk7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICB9XG4gICAgaWYgKCFtYWNDaGVja1Bhc3NlZCkge1xuICAgICAgICB0aHJvdyBuZXcgSldFRGVjcnlwdGlvbkZhaWxlZCgpO1xuICAgIH1cbiAgICBsZXQgcGxhaW50ZXh0O1xuICAgIHRyeSB7XG4gICAgICAgIHBsYWludGV4dCA9IG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZGVjcnlwdCh7IGl2LCBuYW1lOiAnQUVTLUNCQycgfSwgZW5jS2V5LCBjaXBoZXJ0ZXh0KSk7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICB9XG4gICAgaWYgKCFwbGFpbnRleHQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRURlY3J5cHRpb25GYWlsZWQoKTtcbiAgICB9XG4gICAgcmV0dXJuIHBsYWludGV4dDtcbn1cbmFzeW5jIGZ1bmN0aW9uIGdjbURlY3J5cHQoZW5jLCBjZWssIGNpcGhlcnRleHQsIGl2LCB0YWcsIGFhZCkge1xuICAgIGxldCBlbmNLZXk7XG4gICAgaWYgKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgZW5jS2V5ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGNlaywgJ0FFUy1HQ00nLCBmYWxzZSwgWydkZWNyeXB0J10pO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgY2hlY2tFbmNDcnlwdG9LZXkoY2VrLCBlbmMsICdkZWNyeXB0Jyk7XG4gICAgICAgIGVuY0tleSA9IGNlaztcbiAgICB9XG4gICAgdHJ5IHtcbiAgICAgICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZGVjcnlwdCh7XG4gICAgICAgICAgICBhZGRpdGlvbmFsRGF0YTogYWFkLFxuICAgICAgICAgICAgaXYsXG4gICAgICAgICAgICBuYW1lOiAnQUVTLUdDTScsXG4gICAgICAgICAgICB0YWdMZW5ndGg6IDEyOCxcbiAgICAgICAgfSwgZW5jS2V5LCBjb25jYXQoY2lwaGVydGV4dCwgdGFnKSkpO1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgICAgIHRocm93IG5ldyBKV0VEZWNyeXB0aW9uRmFpbGVkKCk7XG4gICAgfVxufVxuY29uc3QgZGVjcnlwdCA9IGFzeW5jIChlbmMsIGNlaywgY2lwaGVydGV4dCwgaXYsIHRhZywgYWFkKSA9PiB7XG4gICAgaWYgKCFpc0NyeXB0b0tleShjZWspICYmICEoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoY2VrLCAuLi50eXBlcywgJ1VpbnQ4QXJyYXknKSk7XG4gICAgfVxuICAgIGlmICghaXYpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBJbml0aWFsaXphdGlvbiBWZWN0b3IgbWlzc2luZycpO1xuICAgIH1cbiAgICBpZiAoIXRhZykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEF1dGhlbnRpY2F0aW9uIFRhZyBtaXNzaW5nJyk7XG4gICAgfVxuICAgIGNoZWNrSXZMZW5ndGgoZW5jLCBpdik7XG4gICAgc3dpdGNoIChlbmMpIHtcbiAgICAgICAgY2FzZSAnQTEyOENCQy1IUzI1Nic6XG4gICAgICAgIGNhc2UgJ0ExOTJDQkMtSFMzODQnOlxuICAgICAgICBjYXNlICdBMjU2Q0JDLUhTNTEyJzpcbiAgICAgICAgICAgIGlmIChjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KVxuICAgICAgICAgICAgICAgIGNoZWNrQ2VrTGVuZ3RoKGNlaywgcGFyc2VJbnQoZW5jLnNsaWNlKC0zKSwgMTApKTtcbiAgICAgICAgICAgIHJldHVybiBjYmNEZWNyeXB0KGVuYywgY2VrLCBjaXBoZXJ0ZXh0LCBpdiwgdGFnLCBhYWQpO1xuICAgICAgICBjYXNlICdBMTI4R0NNJzpcbiAgICAgICAgY2FzZSAnQTE5MkdDTSc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ00nOlxuICAgICAgICAgICAgaWYgKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpXG4gICAgICAgICAgICAgICAgY2hlY2tDZWtMZW5ndGgoY2VrLCBwYXJzZUludChlbmMuc2xpY2UoMSwgNCksIDEwKSk7XG4gICAgICAgICAgICByZXR1cm4gZ2NtRGVjcnlwdChlbmMsIGNlaywgY2lwaGVydGV4dCwgaXYsIHRhZywgYWFkKTtcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdVbnN1cHBvcnRlZCBKV0UgQ29udGVudCBFbmNyeXB0aW9uIEFsZ29yaXRobScpO1xuICAgIH1cbn07XG5leHBvcnQgZGVmYXVsdCBkZWNyeXB0O1xuIiwiY29uc3QgaXNEaXNqb2ludCA9ICguLi5oZWFkZXJzKSA9PiB7XG4gICAgY29uc3Qgc291cmNlcyA9IGhlYWRlcnMuZmlsdGVyKEJvb2xlYW4pO1xuICAgIGlmIChzb3VyY2VzLmxlbmd0aCA9PT0gMCB8fCBzb3VyY2VzLmxlbmd0aCA9PT0gMSkge1xuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG4gICAgbGV0IGFjYztcbiAgICBmb3IgKGNvbnN0IGhlYWRlciBvZiBzb3VyY2VzKSB7XG4gICAgICAgIGNvbnN0IHBhcmFtZXRlcnMgPSBPYmplY3Qua2V5cyhoZWFkZXIpO1xuICAgICAgICBpZiAoIWFjYyB8fCBhY2Muc2l6ZSA9PT0gMCkge1xuICAgICAgICAgICAgYWNjID0gbmV3IFNldChwYXJhbWV0ZXJzKTtcbiAgICAgICAgICAgIGNvbnRpbnVlO1xuICAgICAgICB9XG4gICAgICAgIGZvciAoY29uc3QgcGFyYW1ldGVyIG9mIHBhcmFtZXRlcnMpIHtcbiAgICAgICAgICAgIGlmIChhY2MuaGFzKHBhcmFtZXRlcikpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBhY2MuYWRkKHBhcmFtZXRlcik7XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHRydWU7XG59O1xuZXhwb3J0IGRlZmF1bHQgaXNEaXNqb2ludDtcbiIsImZ1bmN0aW9uIGlzT2JqZWN0TGlrZSh2YWx1ZSkge1xuICAgIHJldHVybiB0eXBlb2YgdmFsdWUgPT09ICdvYmplY3QnICYmIHZhbHVlICE9PSBudWxsO1xufVxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gaXNPYmplY3QoaW5wdXQpIHtcbiAgICBpZiAoIWlzT2JqZWN0TGlrZShpbnB1dCkgfHwgT2JqZWN0LnByb3RvdHlwZS50b1N0cmluZy5jYWxsKGlucHV0KSAhPT0gJ1tvYmplY3QgT2JqZWN0XScpIHtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgICBpZiAoT2JqZWN0LmdldFByb3RvdHlwZU9mKGlucHV0KSA9PT0gbnVsbCkge1xuICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG4gICAgbGV0IHByb3RvID0gaW5wdXQ7XG4gICAgd2hpbGUgKE9iamVjdC5nZXRQcm90b3R5cGVPZihwcm90bykgIT09IG51bGwpIHtcbiAgICAgICAgcHJvdG8gPSBPYmplY3QuZ2V0UHJvdG90eXBlT2YocHJvdG8pO1xuICAgIH1cbiAgICByZXR1cm4gT2JqZWN0LmdldFByb3RvdHlwZU9mKGlucHV0KSA9PT0gcHJvdG87XG59XG4iLCJjb25zdCBib2d1c1dlYkNyeXB0byA9IFtcbiAgICB7IGhhc2g6ICdTSEEtMjU2JywgbmFtZTogJ0hNQUMnIH0sXG4gICAgdHJ1ZSxcbiAgICBbJ3NpZ24nXSxcbl07XG5leHBvcnQgZGVmYXVsdCBib2d1c1dlYkNyeXB0bztcbiIsImltcG9ydCBib2d1c1dlYkNyeXB0byBmcm9tICcuL2JvZ3VzLmpzJztcbmltcG9ydCBjcnlwdG8sIHsgaXNDcnlwdG9LZXkgfSBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgeyBjaGVja0VuY0NyeXB0b0tleSB9IGZyb20gJy4uL2xpYi9jcnlwdG9fa2V5LmpzJztcbmltcG9ydCBpbnZhbGlkS2V5SW5wdXQgZnJvbSAnLi4vbGliL2ludmFsaWRfa2V5X2lucHV0LmpzJztcbmltcG9ydCB7IHR5cGVzIH0gZnJvbSAnLi9pc19rZXlfbGlrZS5qcyc7XG5mdW5jdGlvbiBjaGVja0tleVNpemUoa2V5LCBhbGcpIHtcbiAgICBpZiAoa2V5LmFsZ29yaXRobS5sZW5ndGggIT09IHBhcnNlSW50KGFsZy5zbGljZSgxLCA0KSwgMTApKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYEludmFsaWQga2V5IHNpemUgZm9yIGFsZzogJHthbGd9YCk7XG4gICAgfVxufVxuZnVuY3Rpb24gZ2V0Q3J5cHRvS2V5KGtleSwgYWxnLCB1c2FnZSkge1xuICAgIGlmIChpc0NyeXB0b0tleShrZXkpKSB7XG4gICAgICAgIGNoZWNrRW5jQ3J5cHRvS2V5KGtleSwgYWxnLCB1c2FnZSk7XG4gICAgICAgIHJldHVybiBrZXk7XG4gICAgfVxuICAgIGlmIChrZXkgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIHJldHVybiBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3Jywga2V5LCAnQUVTLUtXJywgdHJ1ZSwgW3VzYWdlXSk7XG4gICAgfVxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMsICdVaW50OEFycmF5JykpO1xufVxuZXhwb3J0IGNvbnN0IHdyYXAgPSBhc3luYyAoYWxnLCBrZXksIGNlaykgPT4ge1xuICAgIGNvbnN0IGNyeXB0b0tleSA9IGF3YWl0IGdldENyeXB0b0tleShrZXksIGFsZywgJ3dyYXBLZXknKTtcbiAgICBjaGVja0tleVNpemUoY3J5cHRvS2V5LCBhbGcpO1xuICAgIGNvbnN0IGNyeXB0b0tleUNlayA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBjZWssIC4uLmJvZ3VzV2ViQ3J5cHRvKTtcbiAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS53cmFwS2V5KCdyYXcnLCBjcnlwdG9LZXlDZWssIGNyeXB0b0tleSwgJ0FFUy1LVycpKTtcbn07XG5leHBvcnQgY29uc3QgdW53cmFwID0gYXN5bmMgKGFsZywga2V5LCBlbmNyeXB0ZWRLZXkpID0+IHtcbiAgICBjb25zdCBjcnlwdG9LZXkgPSBhd2FpdCBnZXRDcnlwdG9LZXkoa2V5LCBhbGcsICd1bndyYXBLZXknKTtcbiAgICBjaGVja0tleVNpemUoY3J5cHRvS2V5LCBhbGcpO1xuICAgIGNvbnN0IGNyeXB0b0tleUNlayA9IGF3YWl0IGNyeXB0by5zdWJ0bGUudW53cmFwS2V5KCdyYXcnLCBlbmNyeXB0ZWRLZXksIGNyeXB0b0tleSwgJ0FFUy1LVycsIC4uLmJvZ3VzV2ViQ3J5cHRvKTtcbiAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoJ3JhdycsIGNyeXB0b0tleUNlaykpO1xufTtcbiIsImltcG9ydCB7IGVuY29kZXIsIGNvbmNhdCwgdWludDMyYmUsIGxlbmd0aEFuZElucHV0LCBjb25jYXRLZGYgfSBmcm9tICcuLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmltcG9ydCBjcnlwdG8sIHsgaXNDcnlwdG9LZXkgfSBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgeyBjaGVja0VuY0NyeXB0b0tleSB9IGZyb20gJy4uL2xpYi9jcnlwdG9fa2V5LmpzJztcbmltcG9ydCBpbnZhbGlkS2V5SW5wdXQgZnJvbSAnLi4vbGliL2ludmFsaWRfa2V5X2lucHV0LmpzJztcbmltcG9ydCB7IHR5cGVzIH0gZnJvbSAnLi9pc19rZXlfbGlrZS5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZGVyaXZlS2V5KHB1YmxpY0tleSwgcHJpdmF0ZUtleSwgYWxnb3JpdGhtLCBrZXlMZW5ndGgsIGFwdSA9IG5ldyBVaW50OEFycmF5KDApLCBhcHYgPSBuZXcgVWludDhBcnJheSgwKSkge1xuICAgIGlmICghaXNDcnlwdG9LZXkocHVibGljS2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChwdWJsaWNLZXksIC4uLnR5cGVzKSk7XG4gICAgfVxuICAgIGNoZWNrRW5jQ3J5cHRvS2V5KHB1YmxpY0tleSwgJ0VDREgnKTtcbiAgICBpZiAoIWlzQ3J5cHRvS2V5KHByaXZhdGVLZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KHByaXZhdGVLZXksIC4uLnR5cGVzKSk7XG4gICAgfVxuICAgIGNoZWNrRW5jQ3J5cHRvS2V5KHByaXZhdGVLZXksICdFQ0RIJywgJ2Rlcml2ZUJpdHMnKTtcbiAgICBjb25zdCB2YWx1ZSA9IGNvbmNhdChsZW5ndGhBbmRJbnB1dChlbmNvZGVyLmVuY29kZShhbGdvcml0aG0pKSwgbGVuZ3RoQW5kSW5wdXQoYXB1KSwgbGVuZ3RoQW5kSW5wdXQoYXB2KSwgdWludDMyYmUoa2V5TGVuZ3RoKSk7XG4gICAgbGV0IGxlbmd0aDtcbiAgICBpZiAocHVibGljS2V5LmFsZ29yaXRobS5uYW1lID09PSAnWDI1NTE5Jykge1xuICAgICAgICBsZW5ndGggPSAyNTY7XG4gICAgfVxuICAgIGVsc2UgaWYgKHB1YmxpY0tleS5hbGdvcml0aG0ubmFtZSA9PT0gJ1g0NDgnKSB7XG4gICAgICAgIGxlbmd0aCA9IDQ0ODtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIGxlbmd0aCA9XG4gICAgICAgICAgICBNYXRoLmNlaWwocGFyc2VJbnQocHVibGljS2V5LmFsZ29yaXRobS5uYW1lZEN1cnZlLnN1YnN0cigtMyksIDEwKSAvIDgpIDw8IDM7XG4gICAgfVxuICAgIGNvbnN0IHNoYXJlZFNlY3JldCA9IG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZGVyaXZlQml0cyh7XG4gICAgICAgIG5hbWU6IHB1YmxpY0tleS5hbGdvcml0aG0ubmFtZSxcbiAgICAgICAgcHVibGljOiBwdWJsaWNLZXksXG4gICAgfSwgcHJpdmF0ZUtleSwgbGVuZ3RoKSk7XG4gICAgcmV0dXJuIGNvbmNhdEtkZihzaGFyZWRTZWNyZXQsIGtleUxlbmd0aCwgdmFsdWUpO1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdlbmVyYXRlRXBrKGtleSkge1xuICAgIGlmICghaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzKSk7XG4gICAgfVxuICAgIHJldHVybiBjcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KGtleS5hbGdvcml0aG0sIHRydWUsIFsnZGVyaXZlQml0cyddKTtcbn1cbmV4cG9ydCBmdW5jdGlvbiBlY2RoQWxsb3dlZChrZXkpIHtcbiAgICBpZiAoIWlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcykpO1xuICAgIH1cbiAgICByZXR1cm4gKFsnUC0yNTYnLCAnUC0zODQnLCAnUC01MjEnXS5pbmNsdWRlcyhrZXkuYWxnb3JpdGhtLm5hbWVkQ3VydmUpIHx8XG4gICAgICAgIGtleS5hbGdvcml0aG0ubmFtZSA9PT0gJ1gyNTUxOScgfHxcbiAgICAgICAga2V5LmFsZ29yaXRobS5uYW1lID09PSAnWDQ0OCcpO1xufVxuIiwiaW1wb3J0IHsgSldFSW52YWxpZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGNoZWNrUDJzKHAycykge1xuICAgIGlmICghKHAycyBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHx8IHAycy5sZW5ndGggPCA4KSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdQQkVTMiBTYWx0IElucHV0IG11c3QgYmUgOCBvciBtb3JlIG9jdGV0cycpO1xuICAgIH1cbn1cbiIsImltcG9ydCByYW5kb20gZnJvbSAnLi9yYW5kb20uanMnO1xuaW1wb3J0IHsgcDJzIGFzIGNvbmNhdFNhbHQgfSBmcm9tICcuLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmltcG9ydCB7IGVuY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgeyB3cmFwLCB1bndyYXAgfSBmcm9tICcuL2Flc2t3LmpzJztcbmltcG9ydCBjaGVja1AycyBmcm9tICcuLi9saWIvY2hlY2tfcDJzLmpzJztcbmltcG9ydCBjcnlwdG8sIHsgaXNDcnlwdG9LZXkgfSBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgeyBjaGVja0VuY0NyeXB0b0tleSB9IGZyb20gJy4uL2xpYi9jcnlwdG9fa2V5LmpzJztcbmltcG9ydCBpbnZhbGlkS2V5SW5wdXQgZnJvbSAnLi4vbGliL2ludmFsaWRfa2V5X2lucHV0LmpzJztcbmltcG9ydCB7IHR5cGVzIH0gZnJvbSAnLi9pc19rZXlfbGlrZS5qcyc7XG5mdW5jdGlvbiBnZXRDcnlwdG9LZXkoa2V5LCBhbGcpIHtcbiAgICBpZiAoa2V5IGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICByZXR1cm4gY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGtleSwgJ1BCS0RGMicsIGZhbHNlLCBbJ2Rlcml2ZUJpdHMnXSk7XG4gICAgfVxuICAgIGlmIChpc0NyeXB0b0tleShrZXkpKSB7XG4gICAgICAgIGNoZWNrRW5jQ3J5cHRvS2V5KGtleSwgYWxnLCAnZGVyaXZlQml0cycsICdkZXJpdmVLZXknKTtcbiAgICAgICAgcmV0dXJuIGtleTtcbiAgICB9XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcywgJ1VpbnQ4QXJyYXknKSk7XG59XG5hc3luYyBmdW5jdGlvbiBkZXJpdmVLZXkocDJzLCBhbGcsIHAyYywga2V5KSB7XG4gICAgY2hlY2tQMnMocDJzKTtcbiAgICBjb25zdCBzYWx0ID0gY29uY2F0U2FsdChhbGcsIHAycyk7XG4gICAgY29uc3Qga2V5bGVuID0gcGFyc2VJbnQoYWxnLnNsaWNlKDEzLCAxNiksIDEwKTtcbiAgICBjb25zdCBzdWJ0bGVBbGcgPSB7XG4gICAgICAgIGhhc2g6IGBTSEEtJHthbGcuc2xpY2UoOCwgMTEpfWAsXG4gICAgICAgIGl0ZXJhdGlvbnM6IHAyYyxcbiAgICAgICAgbmFtZTogJ1BCS0RGMicsXG4gICAgICAgIHNhbHQsXG4gICAgfTtcbiAgICBjb25zdCB3cmFwQWxnID0ge1xuICAgICAgICBsZW5ndGg6IGtleWxlbixcbiAgICAgICAgbmFtZTogJ0FFUy1LVycsXG4gICAgfTtcbiAgICBjb25zdCBjcnlwdG9LZXkgPSBhd2FpdCBnZXRDcnlwdG9LZXkoa2V5LCBhbGcpO1xuICAgIGlmIChjcnlwdG9LZXkudXNhZ2VzLmluY2x1ZGVzKCdkZXJpdmVCaXRzJykpIHtcbiAgICAgICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZGVyaXZlQml0cyhzdWJ0bGVBbGcsIGNyeXB0b0tleSwga2V5bGVuKSk7XG4gICAgfVxuICAgIGlmIChjcnlwdG9LZXkudXNhZ2VzLmluY2x1ZGVzKCdkZXJpdmVLZXknKSkge1xuICAgICAgICByZXR1cm4gY3J5cHRvLnN1YnRsZS5kZXJpdmVLZXkoc3VidGxlQWxnLCBjcnlwdG9LZXksIHdyYXBBbGcsIGZhbHNlLCBbJ3dyYXBLZXknLCAndW53cmFwS2V5J10pO1xuICAgIH1cbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdQQktERjIga2V5IFwidXNhZ2VzXCIgbXVzdCBpbmNsdWRlIFwiZGVyaXZlQml0c1wiIG9yIFwiZGVyaXZlS2V5XCInKTtcbn1cbmV4cG9ydCBjb25zdCBlbmNyeXB0ID0gYXN5bmMgKGFsZywga2V5LCBjZWssIHAyYyA9IDIwNDgsIHAycyA9IHJhbmRvbShuZXcgVWludDhBcnJheSgxNikpKSA9PiB7XG4gICAgY29uc3QgZGVyaXZlZCA9IGF3YWl0IGRlcml2ZUtleShwMnMsIGFsZywgcDJjLCBrZXkpO1xuICAgIGNvbnN0IGVuY3J5cHRlZEtleSA9IGF3YWl0IHdyYXAoYWxnLnNsaWNlKC02KSwgZGVyaXZlZCwgY2VrKTtcbiAgICByZXR1cm4geyBlbmNyeXB0ZWRLZXksIHAyYywgcDJzOiBiYXNlNjR1cmwocDJzKSB9O1xufTtcbmV4cG9ydCBjb25zdCBkZWNyeXB0ID0gYXN5bmMgKGFsZywga2V5LCBlbmNyeXB0ZWRLZXksIHAyYywgcDJzKSA9PiB7XG4gICAgY29uc3QgZGVyaXZlZCA9IGF3YWl0IGRlcml2ZUtleShwMnMsIGFsZywgcDJjLCBrZXkpO1xuICAgIHJldHVybiB1bndyYXAoYWxnLnNsaWNlKC02KSwgZGVyaXZlZCwgZW5jcnlwdGVkS2V5KTtcbn07XG4iLCJpbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gc3VidGxlUnNhRXMoYWxnKSB7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0yNTYnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0zODQnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC01MTInOlxuICAgICAgICAgICAgcmV0dXJuICdSU0EtT0FFUCc7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZChgYWxnICR7YWxnfSBpcyBub3Qgc3VwcG9ydGVkIGVpdGhlciBieSBKT1NFIG9yIHlvdXIgamF2YXNjcmlwdCBydW50aW1lYCk7XG4gICAgfVxufVxuIiwiZXhwb3J0IGRlZmF1bHQgKGFsZywga2V5KSA9PiB7XG4gICAgaWYgKGFsZy5zdGFydHNXaXRoKCdSUycpIHx8IGFsZy5zdGFydHNXaXRoKCdQUycpKSB7XG4gICAgICAgIGNvbnN0IHsgbW9kdWx1c0xlbmd0aCB9ID0ga2V5LmFsZ29yaXRobTtcbiAgICAgICAgaWYgKHR5cGVvZiBtb2R1bHVzTGVuZ3RoICE9PSAnbnVtYmVyJyB8fCBtb2R1bHVzTGVuZ3RoIDwgMjA0OCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHthbGd9IHJlcXVpcmVzIGtleSBtb2R1bHVzTGVuZ3RoIHRvIGJlIDIwNDggYml0cyBvciBsYXJnZXJgKTtcbiAgICAgICAgfVxuICAgIH1cbn07XG4iLCJpbXBvcnQgc3VidGxlQWxnb3JpdGhtIGZyb20gJy4vc3VidGxlX3JzYWVzLmpzJztcbmltcG9ydCBib2d1c1dlYkNyeXB0byBmcm9tICcuL2JvZ3VzLmpzJztcbmltcG9ydCBjcnlwdG8sIHsgaXNDcnlwdG9LZXkgfSBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgeyBjaGVja0VuY0NyeXB0b0tleSB9IGZyb20gJy4uL2xpYi9jcnlwdG9fa2V5LmpzJztcbmltcG9ydCBjaGVja0tleUxlbmd0aCBmcm9tICcuL2NoZWNrX2tleV9sZW5ndGguanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmV4cG9ydCBjb25zdCBlbmNyeXB0ID0gYXN5bmMgKGFsZywga2V5LCBjZWspID0+IHtcbiAgICBpZiAoIWlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcykpO1xuICAgIH1cbiAgICBjaGVja0VuY0NyeXB0b0tleShrZXksIGFsZywgJ2VuY3J5cHQnLCAnd3JhcEtleScpO1xuICAgIGNoZWNrS2V5TGVuZ3RoKGFsZywga2V5KTtcbiAgICBpZiAoa2V5LnVzYWdlcy5pbmNsdWRlcygnZW5jcnlwdCcpKSB7XG4gICAgICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmVuY3J5cHQoc3VidGxlQWxnb3JpdGhtKGFsZyksIGtleSwgY2VrKSk7XG4gICAgfVxuICAgIGlmIChrZXkudXNhZ2VzLmluY2x1ZGVzKCd3cmFwS2V5JykpIHtcbiAgICAgICAgY29uc3QgY3J5cHRvS2V5Q2VrID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGNlaywgLi4uYm9ndXNXZWJDcnlwdG8pO1xuICAgICAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS53cmFwS2V5KCdyYXcnLCBjcnlwdG9LZXlDZWssIGtleSwgc3VidGxlQWxnb3JpdGhtKGFsZykpKTtcbiAgICB9XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcignUlNBLU9BRVAga2V5IFwidXNhZ2VzXCIgbXVzdCBpbmNsdWRlIFwiZW5jcnlwdFwiIG9yIFwid3JhcEtleVwiIGZvciB0aGlzIG9wZXJhdGlvbicpO1xufTtcbmV4cG9ydCBjb25zdCBkZWNyeXB0ID0gYXN5bmMgKGFsZywga2V5LCBlbmNyeXB0ZWRLZXkpID0+IHtcbiAgICBpZiAoIWlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcykpO1xuICAgIH1cbiAgICBjaGVja0VuY0NyeXB0b0tleShrZXksIGFsZywgJ2RlY3J5cHQnLCAndW53cmFwS2V5Jyk7XG4gICAgY2hlY2tLZXlMZW5ndGgoYWxnLCBrZXkpO1xuICAgIGlmIChrZXkudXNhZ2VzLmluY2x1ZGVzKCdkZWNyeXB0JykpIHtcbiAgICAgICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZGVjcnlwdChzdWJ0bGVBbGdvcml0aG0oYWxnKSwga2V5LCBlbmNyeXB0ZWRLZXkpKTtcbiAgICB9XG4gICAgaWYgKGtleS51c2FnZXMuaW5jbHVkZXMoJ3Vud3JhcEtleScpKSB7XG4gICAgICAgIGNvbnN0IGNyeXB0b0tleUNlayA9IGF3YWl0IGNyeXB0by5zdWJ0bGUudW53cmFwS2V5KCdyYXcnLCBlbmNyeXB0ZWRLZXksIGtleSwgc3VidGxlQWxnb3JpdGhtKGFsZyksIC4uLmJvZ3VzV2ViQ3J5cHRvKTtcbiAgICAgICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdyYXcnLCBjcnlwdG9LZXlDZWspKTtcbiAgICB9XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcignUlNBLU9BRVAga2V5IFwidXNhZ2VzXCIgbXVzdCBpbmNsdWRlIFwiZGVjcnlwdFwiIG9yIFwidW53cmFwS2V5XCIgZm9yIHRoaXMgb3BlcmF0aW9uJyk7XG59O1xuIiwiaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCByYW5kb20gZnJvbSAnLi4vcnVudGltZS9yYW5kb20uanMnO1xuZXhwb3J0IGZ1bmN0aW9uIGJpdExlbmd0aChhbGcpIHtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdBMTI4R0NNJzpcbiAgICAgICAgICAgIHJldHVybiAxMjg7XG4gICAgICAgIGNhc2UgJ0ExOTJHQ00nOlxuICAgICAgICAgICAgcmV0dXJuIDE5MjtcbiAgICAgICAgY2FzZSAnQTI1NkdDTSc6XG4gICAgICAgIGNhc2UgJ0ExMjhDQkMtSFMyNTYnOlxuICAgICAgICAgICAgcmV0dXJuIDI1NjtcbiAgICAgICAgY2FzZSAnQTE5MkNCQy1IUzM4NCc6XG4gICAgICAgICAgICByZXR1cm4gMzg0O1xuICAgICAgICBjYXNlICdBMjU2Q0JDLUhTNTEyJzpcbiAgICAgICAgICAgIHJldHVybiA1MTI7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZChgVW5zdXBwb3J0ZWQgSldFIEFsZ29yaXRobTogJHthbGd9YCk7XG4gICAgfVxufVxuZXhwb3J0IGRlZmF1bHQgKGFsZykgPT4gcmFuZG9tKG5ldyBVaW50OEFycmF5KGJpdExlbmd0aChhbGcpID4+IDMpKTtcbiIsImltcG9ydCBjcnlwdG8gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmZ1bmN0aW9uIHN1YnRsZU1hcHBpbmcoandrKSB7XG4gICAgbGV0IGFsZ29yaXRobTtcbiAgICBsZXQga2V5VXNhZ2VzO1xuICAgIHN3aXRjaCAoandrLmt0eSkge1xuICAgICAgICBjYXNlICdSU0EnOiB7XG4gICAgICAgICAgICBzd2l0Y2ggKGp3ay5hbGcpIHtcbiAgICAgICAgICAgICAgICBjYXNlICdQUzI1Nic6XG4gICAgICAgICAgICAgICAgY2FzZSAnUFMzODQnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1BTNTEyJzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnUlNBLVBTUycsIGhhc2g6IGBTSEEtJHtqd2suYWxnLnNsaWNlKC0zKX1gIH07XG4gICAgICAgICAgICAgICAgICAgIGtleVVzYWdlcyA9IGp3ay5kID8gWydzaWduJ10gOiBbJ3ZlcmlmeSddO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlICdSUzI1Nic6XG4gICAgICAgICAgICAgICAgY2FzZSAnUlMzODQnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1JTNTEyJzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnUlNBU1NBLVBLQ1MxLXYxXzUnLCBoYXNoOiBgU0hBLSR7andrLmFsZy5zbGljZSgtMyl9YCB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnc2lnbiddIDogWyd2ZXJpZnknXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAnUlNBLU9BRVAnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1JTQS1PQUVQLTI1Nic6XG4gICAgICAgICAgICAgICAgY2FzZSAnUlNBLU9BRVAtMzg0JzpcbiAgICAgICAgICAgICAgICBjYXNlICdSU0EtT0FFUC01MTInOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBuYW1lOiAnUlNBLU9BRVAnLFxuICAgICAgICAgICAgICAgICAgICAgICAgaGFzaDogYFNIQS0ke3BhcnNlSW50KGp3ay5hbGcuc2xpY2UoLTMpLCAxMCkgfHwgMX1gLFxuICAgICAgICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnZGVjcnlwdCcsICd1bndyYXBLZXknXSA6IFsnZW5jcnlwdCcsICd3cmFwS2V5J107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIEpXSyBcImFsZ1wiIChBbGdvcml0aG0pIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnRUMnOiB7XG4gICAgICAgICAgICBzd2l0Y2ggKGp3ay5hbGcpIHtcbiAgICAgICAgICAgICAgICBjYXNlICdFUzI1Nic6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0VDRFNBJywgbmFtZWRDdXJ2ZTogJ1AtMjU2JyB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnc2lnbiddIDogWyd2ZXJpZnknXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAnRVMzODQnOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RTQScsIG5hbWVkQ3VydmU6ICdQLTM4NCcgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ3NpZ24nXSA6IFsndmVyaWZ5J107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ0VTNTEyJzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNEU0EnLCBuYW1lZEN1cnZlOiAnUC01MjEnIH07XG4gICAgICAgICAgICAgICAgICAgIGtleVVzYWdlcyA9IGp3ay5kID8gWydzaWduJ10gOiBbJ3ZlcmlmeSddO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlICdFQ0RILUVTJzpcbiAgICAgICAgICAgICAgICBjYXNlICdFQ0RILUVTK0ExMjhLVyc6XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUytBMTkyS1cnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMrQTI1NktXJzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNESCcsIG5hbWVkQ3VydmU6IGp3ay5jcnYgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ2Rlcml2ZUJpdHMnXSA6IFtdO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBKV0sgXCJhbGdcIiAoQWxnb3JpdGhtKSBQYXJhbWV0ZXIgdmFsdWUnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ09LUCc6IHtcbiAgICAgICAgICAgIHN3aXRjaCAoandrLmFsZykge1xuICAgICAgICAgICAgICAgIGNhc2UgJ0VkRFNBJzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiBqd2suY3J2IH07XG4gICAgICAgICAgICAgICAgICAgIGtleVVzYWdlcyA9IGp3ay5kID8gWydzaWduJ10gOiBbJ3ZlcmlmeSddO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlICdFQ0RILUVTJzpcbiAgICAgICAgICAgICAgICBjYXNlICdFQ0RILUVTK0ExMjhLVyc6XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUytBMTkyS1cnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMrQTI1NktXJzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiBqd2suY3J2IH07XG4gICAgICAgICAgICAgICAgICAgIGtleVVzYWdlcyA9IGp3ay5kID8gWydkZXJpdmVCaXRzJ10gOiBbXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgSldLIFwiYWxnXCIgKEFsZ29yaXRobSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgSldLIFwia3R5XCIgKEtleSBUeXBlKSBQYXJhbWV0ZXIgdmFsdWUnKTtcbiAgICB9XG4gICAgcmV0dXJuIHsgYWxnb3JpdGhtLCBrZXlVc2FnZXMgfTtcbn1cbmNvbnN0IHBhcnNlID0gYXN5bmMgKGp3aykgPT4ge1xuICAgIGlmICghandrLmFsZykge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdcImFsZ1wiIGFyZ3VtZW50IGlzIHJlcXVpcmVkIHdoZW4gXCJqd2suYWxnXCIgaXMgbm90IHByZXNlbnQnKTtcbiAgICB9XG4gICAgY29uc3QgeyBhbGdvcml0aG0sIGtleVVzYWdlcyB9ID0gc3VidGxlTWFwcGluZyhqd2spO1xuICAgIGNvbnN0IHJlc3QgPSBbXG4gICAgICAgIGFsZ29yaXRobSxcbiAgICAgICAgandrLmV4dCA/PyBmYWxzZSxcbiAgICAgICAgandrLmtleV9vcHMgPz8ga2V5VXNhZ2VzLFxuICAgIF07XG4gICAgY29uc3Qga2V5RGF0YSA9IHsgLi4uandrIH07XG4gICAgZGVsZXRlIGtleURhdGEuYWxnO1xuICAgIGRlbGV0ZSBrZXlEYXRhLnVzZTtcbiAgICByZXR1cm4gY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ2p3aycsIGtleURhdGEsIC4uLnJlc3QpO1xufTtcbmV4cG9ydCBkZWZhdWx0IHBhcnNlO1xuIiwiaW1wb3J0IHsgZGVjb2RlIGFzIGRlY29kZUJhc2U2NFVSTCB9IGZyb20gJy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmltcG9ydCB7IGZyb21TUEtJLCBmcm9tUEtDUzgsIGZyb21YNTA5IH0gZnJvbSAnLi4vcnVudGltZS9hc24xLmpzJztcbmltcG9ydCBhc0tleU9iamVjdCBmcm9tICcuLi9ydW50aW1lL2p3a190b19rZXkuanMnO1xuaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCBpc09iamVjdCBmcm9tICcuLi9saWIvaXNfb2JqZWN0LmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBpbXBvcnRTUEtJKHNwa2ksIGFsZywgb3B0aW9ucykge1xuICAgIGlmICh0eXBlb2Ygc3BraSAhPT0gJ3N0cmluZycgfHwgc3BraS5pbmRleE9mKCctLS0tLUJFR0lOIFBVQkxJQyBLRVktLS0tLScpICE9PSAwKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1wic3BraVwiIG11c3QgYmUgU1BLSSBmb3JtYXR0ZWQgc3RyaW5nJyk7XG4gICAgfVxuICAgIHJldHVybiBmcm9tU1BLSShzcGtpLCBhbGcsIG9wdGlvbnMpO1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGltcG9ydFg1MDkoeDUwOSwgYWxnLCBvcHRpb25zKSB7XG4gICAgaWYgKHR5cGVvZiB4NTA5ICE9PSAnc3RyaW5nJyB8fCB4NTA5LmluZGV4T2YoJy0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLScpICE9PSAwKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1wieDUwOVwiIG11c3QgYmUgWC41MDkgZm9ybWF0dGVkIHN0cmluZycpO1xuICAgIH1cbiAgICByZXR1cm4gZnJvbVg1MDkoeDUwOSwgYWxnLCBvcHRpb25zKTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBpbXBvcnRQS0NTOChwa2NzOCwgYWxnLCBvcHRpb25zKSB7XG4gICAgaWYgKHR5cGVvZiBwa2NzOCAhPT0gJ3N0cmluZycgfHwgcGtjczguaW5kZXhPZignLS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tJykgIT09IDApIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignXCJwa2NzOFwiIG11c3QgYmUgUEtDUyM4IGZvcm1hdHRlZCBzdHJpbmcnKTtcbiAgICB9XG4gICAgcmV0dXJuIGZyb21QS0NTOChwa2NzOCwgYWxnLCBvcHRpb25zKTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBpbXBvcnRKV0soandrLCBhbGcpIHtcbiAgICBpZiAoIWlzT2JqZWN0KGp3aykpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignSldLIG11c3QgYmUgYW4gb2JqZWN0Jyk7XG4gICAgfVxuICAgIGFsZyB8fCAoYWxnID0gandrLmFsZyk7XG4gICAgc3dpdGNoIChqd2sua3R5KSB7XG4gICAgICAgIGNhc2UgJ29jdCc6XG4gICAgICAgICAgICBpZiAodHlwZW9mIGp3ay5rICE9PSAnc3RyaW5nJyB8fCAhandrLmspIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdtaXNzaW5nIFwia1wiIChLZXkgVmFsdWUpIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIGRlY29kZUJhc2U2NFVSTChqd2suayk7XG4gICAgICAgIGNhc2UgJ1JTQSc6XG4gICAgICAgICAgICBpZiAoandrLm90aCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ1JTQSBKV0sgXCJvdGhcIiAoT3RoZXIgUHJpbWVzIEluZm8pIFBhcmFtZXRlciB2YWx1ZSBpcyBub3Qgc3VwcG9ydGVkJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0VDJzpcbiAgICAgICAgY2FzZSAnT0tQJzpcbiAgICAgICAgICAgIHJldHVybiBhc0tleU9iamVjdCh7IC4uLmp3aywgYWxnIH0pO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ1Vuc3VwcG9ydGVkIFwia3R5XCIgKEtleSBUeXBlKSBQYXJhbWV0ZXIgdmFsdWUnKTtcbiAgICB9XG59XG4iLCJpbXBvcnQgeyB3aXRoQWxnIGFzIGludmFsaWRLZXlJbnB1dCB9IGZyb20gJy4vaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IGlzS2V5TGlrZSwgeyB0eXBlcyB9IGZyb20gJy4uL3J1bnRpbWUvaXNfa2V5X2xpa2UuanMnO1xuY29uc3Qgc3ltbWV0cmljVHlwZUNoZWNrID0gKGFsZywga2V5KSA9PiB7XG4gICAgaWYgKGtleSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpXG4gICAgICAgIHJldHVybjtcbiAgICBpZiAoIWlzS2V5TGlrZShrZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGFsZywga2V5LCAuLi50eXBlcywgJ1VpbnQ4QXJyYXknKSk7XG4gICAgfVxuICAgIGlmIChrZXkudHlwZSAhPT0gJ3NlY3JldCcpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHt0eXBlcy5qb2luKCcgb3IgJyl9IGluc3RhbmNlcyBmb3Igc3ltbWV0cmljIGFsZ29yaXRobXMgbXVzdCBiZSBvZiB0eXBlIFwic2VjcmV0XCJgKTtcbiAgICB9XG59O1xuY29uc3QgYXN5bW1ldHJpY1R5cGVDaGVjayA9IChhbGcsIGtleSwgdXNhZ2UpID0+IHtcbiAgICBpZiAoIWlzS2V5TGlrZShrZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGFsZywga2V5LCAuLi50eXBlcykpO1xuICAgIH1cbiAgICBpZiAoa2V5LnR5cGUgPT09ICdzZWNyZXQnKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYCR7dHlwZXMuam9pbignIG9yICcpfSBpbnN0YW5jZXMgZm9yIGFzeW1tZXRyaWMgYWxnb3JpdGhtcyBtdXN0IG5vdCBiZSBvZiB0eXBlIFwic2VjcmV0XCJgKTtcbiAgICB9XG4gICAgaWYgKHVzYWdlID09PSAnc2lnbicgJiYga2V5LnR5cGUgPT09ICdwdWJsaWMnKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYCR7dHlwZXMuam9pbignIG9yICcpfSBpbnN0YW5jZXMgZm9yIGFzeW1tZXRyaWMgYWxnb3JpdGhtIHNpZ25pbmcgbXVzdCBiZSBvZiB0eXBlIFwicHJpdmF0ZVwiYCk7XG4gICAgfVxuICAgIGlmICh1c2FnZSA9PT0gJ2RlY3J5cHQnICYmIGtleS50eXBlID09PSAncHVibGljJykge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGAke3R5cGVzLmpvaW4oJyBvciAnKX0gaW5zdGFuY2VzIGZvciBhc3ltbWV0cmljIGFsZ29yaXRobSBkZWNyeXB0aW9uIG11c3QgYmUgb2YgdHlwZSBcInByaXZhdGVcImApO1xuICAgIH1cbiAgICBpZiAoa2V5LmFsZ29yaXRobSAmJiB1c2FnZSA9PT0gJ3ZlcmlmeScgJiYga2V5LnR5cGUgPT09ICdwcml2YXRlJykge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGAke3R5cGVzLmpvaW4oJyBvciAnKX0gaW5zdGFuY2VzIGZvciBhc3ltbWV0cmljIGFsZ29yaXRobSB2ZXJpZnlpbmcgbXVzdCBiZSBvZiB0eXBlIFwicHVibGljXCJgKTtcbiAgICB9XG4gICAgaWYgKGtleS5hbGdvcml0aG0gJiYgdXNhZ2UgPT09ICdlbmNyeXB0JyAmJiBrZXkudHlwZSA9PT0gJ3ByaXZhdGUnKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYCR7dHlwZXMuam9pbignIG9yICcpfSBpbnN0YW5jZXMgZm9yIGFzeW1tZXRyaWMgYWxnb3JpdGhtIGVuY3J5cHRpb24gbXVzdCBiZSBvZiB0eXBlIFwicHVibGljXCJgKTtcbiAgICB9XG59O1xuY29uc3QgY2hlY2tLZXlUeXBlID0gKGFsZywga2V5LCB1c2FnZSkgPT4ge1xuICAgIGNvbnN0IHN5bW1ldHJpYyA9IGFsZy5zdGFydHNXaXRoKCdIUycpIHx8XG4gICAgICAgIGFsZyA9PT0gJ2RpcicgfHxcbiAgICAgICAgYWxnLnN0YXJ0c1dpdGgoJ1BCRVMyJykgfHxcbiAgICAgICAgL15BXFxkezN9KD86R0NNKT9LVyQvLnRlc3QoYWxnKTtcbiAgICBpZiAoc3ltbWV0cmljKSB7XG4gICAgICAgIHN5bW1ldHJpY1R5cGVDaGVjayhhbGcsIGtleSk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBhc3ltbWV0cmljVHlwZUNoZWNrKGFsZywga2V5LCB1c2FnZSk7XG4gICAgfVxufTtcbmV4cG9ydCBkZWZhdWx0IGNoZWNrS2V5VHlwZTtcbiIsImltcG9ydCB7IGNvbmNhdCwgdWludDY0YmUgfSBmcm9tICcuLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmltcG9ydCBjaGVja0l2TGVuZ3RoIGZyb20gJy4uL2xpYi9jaGVja19pdl9sZW5ndGguanMnO1xuaW1wb3J0IGNoZWNrQ2VrTGVuZ3RoIGZyb20gJy4vY2hlY2tfY2VrX2xlbmd0aC5qcyc7XG5pbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tFbmNDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgZ2VuZXJhdGVJdiBmcm9tICcuLi9saWIvaXYuanMnO1xuaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IHR5cGVzIH0gZnJvbSAnLi9pc19rZXlfbGlrZS5qcyc7XG5hc3luYyBmdW5jdGlvbiBjYmNFbmNyeXB0KGVuYywgcGxhaW50ZXh0LCBjZWssIGl2LCBhYWQpIHtcbiAgICBpZiAoIShjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChjZWssICdVaW50OEFycmF5JykpO1xuICAgIH1cbiAgICBjb25zdCBrZXlTaXplID0gcGFyc2VJbnQoZW5jLnNsaWNlKDEsIDQpLCAxMCk7XG4gICAgY29uc3QgZW5jS2V5ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGNlay5zdWJhcnJheShrZXlTaXplID4+IDMpLCAnQUVTLUNCQycsIGZhbHNlLCBbJ2VuY3J5cHQnXSk7XG4gICAgY29uc3QgbWFjS2V5ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGNlay5zdWJhcnJheSgwLCBrZXlTaXplID4+IDMpLCB7XG4gICAgICAgIGhhc2g6IGBTSEEtJHtrZXlTaXplIDw8IDF9YCxcbiAgICAgICAgbmFtZTogJ0hNQUMnLFxuICAgIH0sIGZhbHNlLCBbJ3NpZ24nXSk7XG4gICAgY29uc3QgY2lwaGVydGV4dCA9IG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZW5jcnlwdCh7XG4gICAgICAgIGl2LFxuICAgICAgICBuYW1lOiAnQUVTLUNCQycsXG4gICAgfSwgZW5jS2V5LCBwbGFpbnRleHQpKTtcbiAgICBjb25zdCBtYWNEYXRhID0gY29uY2F0KGFhZCwgaXYsIGNpcGhlcnRleHQsIHVpbnQ2NGJlKGFhZC5sZW5ndGggPDwgMykpO1xuICAgIGNvbnN0IHRhZyA9IG5ldyBVaW50OEFycmF5KChhd2FpdCBjcnlwdG8uc3VidGxlLnNpZ24oJ0hNQUMnLCBtYWNLZXksIG1hY0RhdGEpKS5zbGljZSgwLCBrZXlTaXplID4+IDMpKTtcbiAgICByZXR1cm4geyBjaXBoZXJ0ZXh0LCB0YWcsIGl2IH07XG59XG5hc3luYyBmdW5jdGlvbiBnY21FbmNyeXB0KGVuYywgcGxhaW50ZXh0LCBjZWssIGl2LCBhYWQpIHtcbiAgICBsZXQgZW5jS2V5O1xuICAgIGlmIChjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIGVuY0tleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBjZWssICdBRVMtR0NNJywgZmFsc2UsIFsnZW5jcnlwdCddKTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIGNoZWNrRW5jQ3J5cHRvS2V5KGNlaywgZW5jLCAnZW5jcnlwdCcpO1xuICAgICAgICBlbmNLZXkgPSBjZWs7XG4gICAgfVxuICAgIGNvbnN0IGVuY3J5cHRlZCA9IG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZW5jcnlwdCh7XG4gICAgICAgIGFkZGl0aW9uYWxEYXRhOiBhYWQsXG4gICAgICAgIGl2LFxuICAgICAgICBuYW1lOiAnQUVTLUdDTScsXG4gICAgICAgIHRhZ0xlbmd0aDogMTI4LFxuICAgIH0sIGVuY0tleSwgcGxhaW50ZXh0KSk7XG4gICAgY29uc3QgdGFnID0gZW5jcnlwdGVkLnNsaWNlKC0xNik7XG4gICAgY29uc3QgY2lwaGVydGV4dCA9IGVuY3J5cHRlZC5zbGljZSgwLCAtMTYpO1xuICAgIHJldHVybiB7IGNpcGhlcnRleHQsIHRhZywgaXYgfTtcbn1cbmNvbnN0IGVuY3J5cHQgPSBhc3luYyAoZW5jLCBwbGFpbnRleHQsIGNlaywgaXYsIGFhZCkgPT4ge1xuICAgIGlmICghaXNDcnlwdG9LZXkoY2VrKSAmJiAhKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGNlaywgLi4udHlwZXMsICdVaW50OEFycmF5JykpO1xuICAgIH1cbiAgICBpZiAoaXYpIHtcbiAgICAgICAgY2hlY2tJdkxlbmd0aChlbmMsIGl2KTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIGl2ID0gZ2VuZXJhdGVJdihlbmMpO1xuICAgIH1cbiAgICBzd2l0Y2ggKGVuYykge1xuICAgICAgICBjYXNlICdBMTI4Q0JDLUhTMjU2JzpcbiAgICAgICAgY2FzZSAnQTE5MkNCQy1IUzM4NCc6XG4gICAgICAgIGNhc2UgJ0EyNTZDQkMtSFM1MTInOlxuICAgICAgICAgICAgaWYgKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgICAgICAgICBjaGVja0Nla0xlbmd0aChjZWssIHBhcnNlSW50KGVuYy5zbGljZSgtMyksIDEwKSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gY2JjRW5jcnlwdChlbmMsIHBsYWludGV4dCwgY2VrLCBpdiwgYWFkKTtcbiAgICAgICAgY2FzZSAnQTEyOEdDTSc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ00nOlxuICAgICAgICBjYXNlICdBMjU2R0NNJzpcbiAgICAgICAgICAgIGlmIChjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgICAgICAgICAgY2hlY2tDZWtMZW5ndGgoY2VrLCBwYXJzZUludChlbmMuc2xpY2UoMSwgNCksIDEwKSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gZ2NtRW5jcnlwdChlbmMsIHBsYWludGV4dCwgY2VrLCBpdiwgYWFkKTtcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdVbnN1cHBvcnRlZCBKV0UgQ29udGVudCBFbmNyeXB0aW9uIEFsZ29yaXRobScpO1xuICAgIH1cbn07XG5leHBvcnQgZGVmYXVsdCBlbmNyeXB0O1xuIiwiaW1wb3J0IGVuY3J5cHQgZnJvbSAnLi4vcnVudGltZS9lbmNyeXB0LmpzJztcbmltcG9ydCBkZWNyeXB0IGZyb20gJy4uL3J1bnRpbWUvZGVjcnlwdC5qcyc7XG5pbXBvcnQgeyBlbmNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHdyYXAoYWxnLCBrZXksIGNlaywgaXYpIHtcbiAgICBjb25zdCBqd2VBbGdvcml0aG0gPSBhbGcuc2xpY2UoMCwgNyk7XG4gICAgY29uc3Qgd3JhcHBlZCA9IGF3YWl0IGVuY3J5cHQoandlQWxnb3JpdGhtLCBjZWssIGtleSwgaXYsIG5ldyBVaW50OEFycmF5KDApKTtcbiAgICByZXR1cm4ge1xuICAgICAgICBlbmNyeXB0ZWRLZXk6IHdyYXBwZWQuY2lwaGVydGV4dCxcbiAgICAgICAgaXY6IGJhc2U2NHVybCh3cmFwcGVkLml2KSxcbiAgICAgICAgdGFnOiBiYXNlNjR1cmwod3JhcHBlZC50YWcpLFxuICAgIH07XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdW53cmFwKGFsZywga2V5LCBlbmNyeXB0ZWRLZXksIGl2LCB0YWcpIHtcbiAgICBjb25zdCBqd2VBbGdvcml0aG0gPSBhbGcuc2xpY2UoMCwgNyk7XG4gICAgcmV0dXJuIGRlY3J5cHQoandlQWxnb3JpdGhtLCBrZXksIGVuY3J5cHRlZEtleSwgaXYsIHRhZywgbmV3IFVpbnQ4QXJyYXkoMCkpO1xufVxuIiwiaW1wb3J0IHsgdW53cmFwIGFzIGFlc0t3IH0gZnJvbSAnLi4vcnVudGltZS9hZXNrdy5qcyc7XG5pbXBvcnQgKiBhcyBFQ0RIIGZyb20gJy4uL3J1bnRpbWUvZWNkaGVzLmpzJztcbmltcG9ydCB7IGRlY3J5cHQgYXMgcGJlczJLdyB9IGZyb20gJy4uL3J1bnRpbWUvcGJlczJrdy5qcyc7XG5pbXBvcnQgeyBkZWNyeXB0IGFzIHJzYUVzIH0gZnJvbSAnLi4vcnVudGltZS9yc2Flcy5qcyc7XG5pbXBvcnQgeyBkZWNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCwgSldFSW52YWxpZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IGJpdExlbmd0aCBhcyBjZWtMZW5ndGggfSBmcm9tICcuLi9saWIvY2VrLmpzJztcbmltcG9ydCB7IGltcG9ydEpXSyB9IGZyb20gJy4uL2tleS9pbXBvcnQuanMnO1xuaW1wb3J0IGNoZWNrS2V5VHlwZSBmcm9tICcuL2NoZWNrX2tleV90eXBlLmpzJztcbmltcG9ydCBpc09iamVjdCBmcm9tICcuL2lzX29iamVjdC5qcyc7XG5pbXBvcnQgeyB1bndyYXAgYXMgYWVzR2NtS3cgfSBmcm9tICcuL2Flc2djbWt3LmpzJztcbmFzeW5jIGZ1bmN0aW9uIGRlY3J5cHRLZXlNYW5hZ2VtZW50KGFsZywga2V5LCBlbmNyeXB0ZWRLZXksIGpvc2VIZWFkZXIsIG9wdGlvbnMpIHtcbiAgICBjaGVja0tleVR5cGUoYWxnLCBrZXksICdkZWNyeXB0Jyk7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnZGlyJzoge1xuICAgICAgICAgICAgaWYgKGVuY3J5cHRlZEtleSAhPT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdFbmNvdW50ZXJlZCB1bmV4cGVjdGVkIEpXRSBFbmNyeXB0ZWQgS2V5Jyk7XG4gICAgICAgICAgICByZXR1cm4ga2V5O1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0VDREgtRVMnOlxuICAgICAgICAgICAgaWYgKGVuY3J5cHRlZEtleSAhPT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdFbmNvdW50ZXJlZCB1bmV4cGVjdGVkIEpXRSBFbmNyeXB0ZWQgS2V5Jyk7XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMTkyS1cnOlxuICAgICAgICBjYXNlICdFQ0RILUVTK0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGlmICghaXNPYmplY3Qoam9zZUhlYWRlci5lcGspKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKGBKT1NFIEhlYWRlciBcImVwa1wiIChFcGhlbWVyYWwgUHVibGljIEtleSkgbWlzc2luZyBvciBpbnZhbGlkYCk7XG4gICAgICAgICAgICBpZiAoIUVDREguZWNkaEFsbG93ZWQoa2V5KSlcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnRUNESCB3aXRoIHRoZSBwcm92aWRlZCBrZXkgaXMgbm90IGFsbG93ZWQgb3Igbm90IHN1cHBvcnRlZCBieSB5b3VyIGphdmFzY3JpcHQgcnVudGltZScpO1xuICAgICAgICAgICAgY29uc3QgZXBrID0gYXdhaXQgaW1wb3J0SldLKGpvc2VIZWFkZXIuZXBrLCBhbGcpO1xuICAgICAgICAgICAgbGV0IHBhcnR5VUluZm87XG4gICAgICAgICAgICBsZXQgcGFydHlWSW5mbztcbiAgICAgICAgICAgIGlmIChqb3NlSGVhZGVyLmFwdSAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICAgICAgaWYgKHR5cGVvZiBqb3NlSGVhZGVyLmFwdSAhPT0gJ3N0cmluZycpXG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKGBKT1NFIEhlYWRlciBcImFwdVwiIChBZ3JlZW1lbnQgUGFydHlVSW5mbykgaW52YWxpZGApO1xuICAgICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgICAgIHBhcnR5VUluZm8gPSBiYXNlNjR1cmwoam9zZUhlYWRlci5hcHUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgYXB1Jyk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKGpvc2VIZWFkZXIuYXB2ICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgICAgICBpZiAodHlwZW9mIGpvc2VIZWFkZXIuYXB2ICE9PSAnc3RyaW5nJylcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwiYXB2XCIgKEFncmVlbWVudCBQYXJ0eVZJbmZvKSBpbnZhbGlkYCk7XG4gICAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICAgICAgcGFydHlWSW5mbyA9IGJhc2U2NHVybChqb3NlSGVhZGVyLmFwdik7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBhcHYnKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjb25zdCBzaGFyZWRTZWNyZXQgPSBhd2FpdCBFQ0RILmRlcml2ZUtleShlcGssIGtleSwgYWxnID09PSAnRUNESC1FUycgPyBqb3NlSGVhZGVyLmVuYyA6IGFsZywgYWxnID09PSAnRUNESC1FUycgPyBjZWtMZW5ndGgoam9zZUhlYWRlci5lbmMpIDogcGFyc2VJbnQoYWxnLnNsaWNlKC01LCAtMiksIDEwKSwgcGFydHlVSW5mbywgcGFydHlWSW5mbyk7XG4gICAgICAgICAgICBpZiAoYWxnID09PSAnRUNESC1FUycpXG4gICAgICAgICAgICAgICAgcmV0dXJuIHNoYXJlZFNlY3JldDtcbiAgICAgICAgICAgIGlmIChlbmNyeXB0ZWRLZXkgPT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEVuY3J5cHRlZCBLZXkgbWlzc2luZycpO1xuICAgICAgICAgICAgcmV0dXJuIGFlc0t3KGFsZy5zbGljZSgtNiksIHNoYXJlZFNlY3JldCwgZW5jcnlwdGVkS2V5KTtcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdSU0ExXzUnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTI1Nic6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTM4NCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTUxMic6IHtcbiAgICAgICAgICAgIGlmIChlbmNyeXB0ZWRLZXkgPT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEVuY3J5cHRlZCBLZXkgbWlzc2luZycpO1xuICAgICAgICAgICAgcmV0dXJuIHJzYUVzKGFsZywga2V5LCBlbmNyeXB0ZWRLZXkpO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ1BCRVMyLUhTMjU2K0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ1BCRVMyLUhTMzg0K0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ1BCRVMyLUhTNTEyK0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGlmIChlbmNyeXB0ZWRLZXkgPT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEVuY3J5cHRlZCBLZXkgbWlzc2luZycpO1xuICAgICAgICAgICAgaWYgKHR5cGVvZiBqb3NlSGVhZGVyLnAyYyAhPT0gJ251bWJlcicpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwicDJjXCIgKFBCRVMyIENvdW50KSBtaXNzaW5nIG9yIGludmFsaWRgKTtcbiAgICAgICAgICAgIGNvbnN0IHAyY0xpbWl0ID0gb3B0aW9ucz8ubWF4UEJFUzJDb3VudCB8fCAxMDAwMDtcbiAgICAgICAgICAgIGlmIChqb3NlSGVhZGVyLnAyYyA+IHAyY0xpbWl0KVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKGBKT1NFIEhlYWRlciBcInAyY1wiIChQQkVTMiBDb3VudCkgb3V0IGlzIG9mIGFjY2VwdGFibGUgYm91bmRzYCk7XG4gICAgICAgICAgICBpZiAodHlwZW9mIGpvc2VIZWFkZXIucDJzICE9PSAnc3RyaW5nJylcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSk9TRSBIZWFkZXIgXCJwMnNcIiAoUEJFUzIgU2FsdCkgbWlzc2luZyBvciBpbnZhbGlkYCk7XG4gICAgICAgICAgICBsZXQgcDJzO1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBwMnMgPSBiYXNlNjR1cmwoam9zZUhlYWRlci5wMnMpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgcDJzJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gcGJlczJLdyhhbGcsIGtleSwgZW5jcnlwdGVkS2V5LCBqb3NlSGVhZGVyLnAyYywgcDJzKTtcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdBMTI4S1cnOlxuICAgICAgICBjYXNlICdBMTkyS1cnOlxuICAgICAgICBjYXNlICdBMjU2S1cnOiB7XG4gICAgICAgICAgICBpZiAoZW5jcnlwdGVkS2V5ID09PSB1bmRlZmluZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBFbmNyeXB0ZWQgS2V5IG1pc3NpbmcnKTtcbiAgICAgICAgICAgIHJldHVybiBhZXNLdyhhbGcsIGtleSwgZW5jcnlwdGVkS2V5KTtcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdBMTI4R0NNS1cnOlxuICAgICAgICBjYXNlICdBMTkyR0NNS1cnOlxuICAgICAgICBjYXNlICdBMjU2R0NNS1cnOiB7XG4gICAgICAgICAgICBpZiAoZW5jcnlwdGVkS2V5ID09PSB1bmRlZmluZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBFbmNyeXB0ZWQgS2V5IG1pc3NpbmcnKTtcbiAgICAgICAgICAgIGlmICh0eXBlb2Ygam9zZUhlYWRlci5pdiAhPT0gJ3N0cmluZycpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwiaXZcIiAoSW5pdGlhbGl6YXRpb24gVmVjdG9yKSBtaXNzaW5nIG9yIGludmFsaWRgKTtcbiAgICAgICAgICAgIGlmICh0eXBlb2Ygam9zZUhlYWRlci50YWcgIT09ICdzdHJpbmcnKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKGBKT1NFIEhlYWRlciBcInRhZ1wiIChBdXRoZW50aWNhdGlvbiBUYWcpIG1pc3Npbmcgb3IgaW52YWxpZGApO1xuICAgICAgICAgICAgbGV0IGl2O1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICBpdiA9IGJhc2U2NHVybChqb3NlSGVhZGVyLml2KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIGl2Jyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBsZXQgdGFnO1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICB0YWcgPSBiYXNlNjR1cmwoam9zZUhlYWRlci50YWcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgdGFnJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gYWVzR2NtS3coYWxnLCBrZXksIGVuY3J5cHRlZEtleSwgaXYsIHRhZyk7XG4gICAgICAgIH1cbiAgICAgICAgZGVmYXVsdDoge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgXCJhbGdcIiAoSldFIEFsZ29yaXRobSkgaGVhZGVyIHZhbHVlJyk7XG4gICAgICAgIH1cbiAgICB9XG59XG5leHBvcnQgZGVmYXVsdCBkZWNyeXB0S2V5TWFuYWdlbWVudDtcbiIsImltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5mdW5jdGlvbiB2YWxpZGF0ZUNyaXQoRXJyLCByZWNvZ25pemVkRGVmYXVsdCwgcmVjb2duaXplZE9wdGlvbiwgcHJvdGVjdGVkSGVhZGVyLCBqb3NlSGVhZGVyKSB7XG4gICAgaWYgKGpvc2VIZWFkZXIuY3JpdCAhPT0gdW5kZWZpbmVkICYmIHByb3RlY3RlZEhlYWRlcj8uY3JpdCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnIoJ1wiY3JpdFwiIChDcml0aWNhbCkgSGVhZGVyIFBhcmFtZXRlciBNVVNUIGJlIGludGVncml0eSBwcm90ZWN0ZWQnKTtcbiAgICB9XG4gICAgaWYgKCFwcm90ZWN0ZWRIZWFkZXIgfHwgcHJvdGVjdGVkSGVhZGVyLmNyaXQgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICByZXR1cm4gbmV3IFNldCgpO1xuICAgIH1cbiAgICBpZiAoIUFycmF5LmlzQXJyYXkocHJvdGVjdGVkSGVhZGVyLmNyaXQpIHx8XG4gICAgICAgIHByb3RlY3RlZEhlYWRlci5jcml0Lmxlbmd0aCA9PT0gMCB8fFxuICAgICAgICBwcm90ZWN0ZWRIZWFkZXIuY3JpdC5zb21lKChpbnB1dCkgPT4gdHlwZW9mIGlucHV0ICE9PSAnc3RyaW5nJyB8fCBpbnB1dC5sZW5ndGggPT09IDApKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnIoJ1wiY3JpdFwiIChDcml0aWNhbCkgSGVhZGVyIFBhcmFtZXRlciBNVVNUIGJlIGFuIGFycmF5IG9mIG5vbi1lbXB0eSBzdHJpbmdzIHdoZW4gcHJlc2VudCcpO1xuICAgIH1cbiAgICBsZXQgcmVjb2duaXplZDtcbiAgICBpZiAocmVjb2duaXplZE9wdGlvbiAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHJlY29nbml6ZWQgPSBuZXcgTWFwKFsuLi5PYmplY3QuZW50cmllcyhyZWNvZ25pemVkT3B0aW9uKSwgLi4ucmVjb2duaXplZERlZmF1bHQuZW50cmllcygpXSk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICByZWNvZ25pemVkID0gcmVjb2duaXplZERlZmF1bHQ7XG4gICAgfVxuICAgIGZvciAoY29uc3QgcGFyYW1ldGVyIG9mIHByb3RlY3RlZEhlYWRlci5jcml0KSB7XG4gICAgICAgIGlmICghcmVjb2duaXplZC5oYXMocGFyYW1ldGVyKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoYEV4dGVuc2lvbiBIZWFkZXIgUGFyYW1ldGVyIFwiJHtwYXJhbWV0ZXJ9XCIgaXMgbm90IHJlY29nbml6ZWRgKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoam9zZUhlYWRlcltwYXJhbWV0ZXJdID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnIoYEV4dGVuc2lvbiBIZWFkZXIgUGFyYW1ldGVyIFwiJHtwYXJhbWV0ZXJ9XCIgaXMgbWlzc2luZ2ApO1xuICAgICAgICB9XG4gICAgICAgIGlmIChyZWNvZ25pemVkLmdldChwYXJhbWV0ZXIpICYmIHByb3RlY3RlZEhlYWRlcltwYXJhbWV0ZXJdID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnIoYEV4dGVuc2lvbiBIZWFkZXIgUGFyYW1ldGVyIFwiJHtwYXJhbWV0ZXJ9XCIgTVVTVCBiZSBpbnRlZ3JpdHkgcHJvdGVjdGVkYCk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIG5ldyBTZXQocHJvdGVjdGVkSGVhZGVyLmNyaXQpO1xufVxuZXhwb3J0IGRlZmF1bHQgdmFsaWRhdGVDcml0O1xuIiwiY29uc3QgdmFsaWRhdGVBbGdvcml0aG1zID0gKG9wdGlvbiwgYWxnb3JpdGhtcykgPT4ge1xuICAgIGlmIChhbGdvcml0aG1zICE9PSB1bmRlZmluZWQgJiZcbiAgICAgICAgKCFBcnJheS5pc0FycmF5KGFsZ29yaXRobXMpIHx8IGFsZ29yaXRobXMuc29tZSgocykgPT4gdHlwZW9mIHMgIT09ICdzdHJpbmcnKSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgXCIke29wdGlvbn1cIiBvcHRpb24gbXVzdCBiZSBhbiBhcnJheSBvZiBzdHJpbmdzYCk7XG4gICAgfVxuICAgIGlmICghYWxnb3JpdGhtcykge1xuICAgICAgICByZXR1cm4gdW5kZWZpbmVkO1xuICAgIH1cbiAgICByZXR1cm4gbmV3IFNldChhbGdvcml0aG1zKTtcbn07XG5leHBvcnQgZGVmYXVsdCB2YWxpZGF0ZUFsZ29yaXRobXM7XG4iLCJpbXBvcnQgeyBkZWNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi4vLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IGRlY3J5cHQgZnJvbSAnLi4vLi4vcnVudGltZS9kZWNyeXB0LmpzJztcbmltcG9ydCB7IEpPU0VBbGdOb3RBbGxvd2VkLCBKT1NFTm90U3VwcG9ydGVkLCBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IGlzRGlzam9pbnQgZnJvbSAnLi4vLi4vbGliL2lzX2Rpc2pvaW50LmpzJztcbmltcG9ydCBpc09iamVjdCBmcm9tICcuLi8uLi9saWIvaXNfb2JqZWN0LmpzJztcbmltcG9ydCBkZWNyeXB0S2V5TWFuYWdlbWVudCBmcm9tICcuLi8uLi9saWIvZGVjcnlwdF9rZXlfbWFuYWdlbWVudC5qcyc7XG5pbXBvcnQgeyBlbmNvZGVyLCBkZWNvZGVyLCBjb25jYXQgfSBmcm9tICcuLi8uLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmltcG9ydCBnZW5lcmF0ZUNlayBmcm9tICcuLi8uLi9saWIvY2VrLmpzJztcbmltcG9ydCB2YWxpZGF0ZUNyaXQgZnJvbSAnLi4vLi4vbGliL3ZhbGlkYXRlX2NyaXQuanMnO1xuaW1wb3J0IHZhbGlkYXRlQWxnb3JpdGhtcyBmcm9tICcuLi8uLi9saWIvdmFsaWRhdGVfYWxnb3JpdGhtcy5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZmxhdHRlbmVkRGVjcnlwdChqd2UsIGtleSwgb3B0aW9ucykge1xuICAgIGlmICghaXNPYmplY3QoandlKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmxhdHRlbmVkIEpXRSBtdXN0IGJlIGFuIG9iamVjdCcpO1xuICAgIH1cbiAgICBpZiAoandlLnByb3RlY3RlZCA9PT0gdW5kZWZpbmVkICYmIGp3ZS5oZWFkZXIgPT09IHVuZGVmaW5lZCAmJiBqd2UudW5wcm90ZWN0ZWQgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSk9TRSBIZWFkZXIgbWlzc2luZycpO1xuICAgIH1cbiAgICBpZiAoandlLml2ICE9PSB1bmRlZmluZWQgJiYgdHlwZW9mIGp3ZS5pdiAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBJbml0aWFsaXphdGlvbiBWZWN0b3IgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBqd2UuY2lwaGVydGV4dCAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBDaXBoZXJ0ZXh0IG1pc3Npbmcgb3IgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3ZS50YWcgIT09IHVuZGVmaW5lZCAmJiB0eXBlb2YgandlLnRhZyAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBBdXRoZW50aWNhdGlvbiBUYWcgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3ZS5wcm90ZWN0ZWQgIT09IHVuZGVmaW5lZCAmJiB0eXBlb2YgandlLnByb3RlY3RlZCAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBQcm90ZWN0ZWQgSGVhZGVyIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmIChqd2UuZW5jcnlwdGVkX2tleSAhPT0gdW5kZWZpbmVkICYmIHR5cGVvZiBqd2UuZW5jcnlwdGVkX2tleSAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBFbmNyeXB0ZWQgS2V5IGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmIChqd2UuYWFkICE9PSB1bmRlZmluZWQgJiYgdHlwZW9mIGp3ZS5hYWQgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgQUFEIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmIChqd2UuaGVhZGVyICE9PSB1bmRlZmluZWQgJiYgIWlzT2JqZWN0KGp3ZS5oZWFkZXIpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgU2hhcmVkIFVucHJvdGVjdGVkIEhlYWRlciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoandlLnVucHJvdGVjdGVkICE9PSB1bmRlZmluZWQgJiYgIWlzT2JqZWN0KGp3ZS51bnByb3RlY3RlZCkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBQZXItUmVjaXBpZW50IFVucHJvdGVjdGVkIEhlYWRlciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBsZXQgcGFyc2VkUHJvdDtcbiAgICBpZiAoandlLnByb3RlY3RlZCkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgY29uc3QgcHJvdGVjdGVkSGVhZGVyID0gYmFzZTY0dXJsKGp3ZS5wcm90ZWN0ZWQpO1xuICAgICAgICAgICAgcGFyc2VkUHJvdCA9IEpTT04ucGFyc2UoZGVjb2Rlci5kZWNvZGUocHJvdGVjdGVkSGVhZGVyKSk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBQcm90ZWN0ZWQgSGVhZGVyIGlzIGludmFsaWQnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBpZiAoIWlzRGlzam9pbnQocGFyc2VkUHJvdCwgandlLmhlYWRlciwgandlLnVucHJvdGVjdGVkKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFByb3RlY3RlZCwgSldFIFVucHJvdGVjdGVkIEhlYWRlciwgYW5kIEpXRSBQZXItUmVjaXBpZW50IFVucHJvdGVjdGVkIEhlYWRlciBQYXJhbWV0ZXIgbmFtZXMgbXVzdCBiZSBkaXNqb2ludCcpO1xuICAgIH1cbiAgICBjb25zdCBqb3NlSGVhZGVyID0ge1xuICAgICAgICAuLi5wYXJzZWRQcm90LFxuICAgICAgICAuLi5qd2UuaGVhZGVyLFxuICAgICAgICAuLi5qd2UudW5wcm90ZWN0ZWQsXG4gICAgfTtcbiAgICB2YWxpZGF0ZUNyaXQoSldFSW52YWxpZCwgbmV3IE1hcCgpLCBvcHRpb25zPy5jcml0LCBwYXJzZWRQcm90LCBqb3NlSGVhZGVyKTtcbiAgICBpZiAoam9zZUhlYWRlci56aXAgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSldFIFwiemlwXCIgKENvbXByZXNzaW9uIEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBpcyBub3Qgc3VwcG9ydGVkLicpO1xuICAgIH1cbiAgICBjb25zdCB7IGFsZywgZW5jIH0gPSBqb3NlSGVhZGVyO1xuICAgIGlmICh0eXBlb2YgYWxnICE9PSAnc3RyaW5nJyB8fCAhYWxnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdtaXNzaW5nIEpXRSBBbGdvcml0aG0gKGFsZykgaW4gSldFIEhlYWRlcicpO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIGVuYyAhPT0gJ3N0cmluZycgfHwgIWVuYykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnbWlzc2luZyBKV0UgRW5jcnlwdGlvbiBBbGdvcml0aG0gKGVuYykgaW4gSldFIEhlYWRlcicpO1xuICAgIH1cbiAgICBjb25zdCBrZXlNYW5hZ2VtZW50QWxnb3JpdGhtcyA9IG9wdGlvbnMgJiYgdmFsaWRhdGVBbGdvcml0aG1zKCdrZXlNYW5hZ2VtZW50QWxnb3JpdGhtcycsIG9wdGlvbnMua2V5TWFuYWdlbWVudEFsZ29yaXRobXMpO1xuICAgIGNvbnN0IGNvbnRlbnRFbmNyeXB0aW9uQWxnb3JpdGhtcyA9IG9wdGlvbnMgJiZcbiAgICAgICAgdmFsaWRhdGVBbGdvcml0aG1zKCdjb250ZW50RW5jcnlwdGlvbkFsZ29yaXRobXMnLCBvcHRpb25zLmNvbnRlbnRFbmNyeXB0aW9uQWxnb3JpdGhtcyk7XG4gICAgaWYgKChrZXlNYW5hZ2VtZW50QWxnb3JpdGhtcyAmJiAha2V5TWFuYWdlbWVudEFsZ29yaXRobXMuaGFzKGFsZykpIHx8XG4gICAgICAgICgha2V5TWFuYWdlbWVudEFsZ29yaXRobXMgJiYgYWxnLnN0YXJ0c1dpdGgoJ1BCRVMyJykpKSB7XG4gICAgICAgIHRocm93IG5ldyBKT1NFQWxnTm90QWxsb3dlZCgnXCJhbGdcIiAoQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIHZhbHVlIG5vdCBhbGxvd2VkJyk7XG4gICAgfVxuICAgIGlmIChjb250ZW50RW5jcnlwdGlvbkFsZ29yaXRobXMgJiYgIWNvbnRlbnRFbmNyeXB0aW9uQWxnb3JpdGhtcy5oYXMoZW5jKSkge1xuICAgICAgICB0aHJvdyBuZXcgSk9TRUFsZ05vdEFsbG93ZWQoJ1wiZW5jXCIgKEVuY3J5cHRpb24gQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIHZhbHVlIG5vdCBhbGxvd2VkJyk7XG4gICAgfVxuICAgIGxldCBlbmNyeXB0ZWRLZXk7XG4gICAgaWYgKGp3ZS5lbmNyeXB0ZWRfa2V5ICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIGVuY3J5cHRlZEtleSA9IGJhc2U2NHVybChqd2UuZW5jcnlwdGVkX2tleSk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBlbmNyeXB0ZWRfa2V5Jyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgbGV0IHJlc29sdmVkS2V5ID0gZmFsc2U7XG4gICAgaWYgKHR5cGVvZiBrZXkgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAga2V5ID0gYXdhaXQga2V5KHBhcnNlZFByb3QsIGp3ZSk7XG4gICAgICAgIHJlc29sdmVkS2V5ID0gdHJ1ZTtcbiAgICB9XG4gICAgbGV0IGNlaztcbiAgICB0cnkge1xuICAgICAgICBjZWsgPSBhd2FpdCBkZWNyeXB0S2V5TWFuYWdlbWVudChhbGcsIGtleSwgZW5jcnlwdGVkS2V5LCBqb3NlSGVhZGVyLCBvcHRpb25zKTtcbiAgICB9XG4gICAgY2F0Y2ggKGVycikge1xuICAgICAgICBpZiAoZXJyIGluc3RhbmNlb2YgVHlwZUVycm9yIHx8IGVyciBpbnN0YW5jZW9mIEpXRUludmFsaWQgfHwgZXJyIGluc3RhbmNlb2YgSk9TRU5vdFN1cHBvcnRlZCkge1xuICAgICAgICAgICAgdGhyb3cgZXJyO1xuICAgICAgICB9XG4gICAgICAgIGNlayA9IGdlbmVyYXRlQ2VrKGVuYyk7XG4gICAgfVxuICAgIGxldCBpdjtcbiAgICBsZXQgdGFnO1xuICAgIGlmIChqd2UuaXYgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgaXYgPSBiYXNlNjR1cmwoandlLml2KTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIGl2Jyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgaWYgKGp3ZS50YWcgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgdGFnID0gYmFzZTY0dXJsKGp3ZS50YWcpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgdGFnJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgY29uc3QgcHJvdGVjdGVkSGVhZGVyID0gZW5jb2Rlci5lbmNvZGUoandlLnByb3RlY3RlZCA/PyAnJyk7XG4gICAgbGV0IGFkZGl0aW9uYWxEYXRhO1xuICAgIGlmIChqd2UuYWFkICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgYWRkaXRpb25hbERhdGEgPSBjb25jYXQocHJvdGVjdGVkSGVhZGVyLCBlbmNvZGVyLmVuY29kZSgnLicpLCBlbmNvZGVyLmVuY29kZShqd2UuYWFkKSk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBhZGRpdGlvbmFsRGF0YSA9IHByb3RlY3RlZEhlYWRlcjtcbiAgICB9XG4gICAgbGV0IGNpcGhlcnRleHQ7XG4gICAgdHJ5IHtcbiAgICAgICAgY2lwaGVydGV4dCA9IGJhc2U2NHVybChqd2UuY2lwaGVydGV4dCk7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBjaXBoZXJ0ZXh0Jyk7XG4gICAgfVxuICAgIGNvbnN0IHBsYWludGV4dCA9IGF3YWl0IGRlY3J5cHQoZW5jLCBjZWssIGNpcGhlcnRleHQsIGl2LCB0YWcsIGFkZGl0aW9uYWxEYXRhKTtcbiAgICBjb25zdCByZXN1bHQgPSB7IHBsYWludGV4dCB9O1xuICAgIGlmIChqd2UucHJvdGVjdGVkICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmVzdWx0LnByb3RlY3RlZEhlYWRlciA9IHBhcnNlZFByb3Q7XG4gICAgfVxuICAgIGlmIChqd2UuYWFkICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHJlc3VsdC5hZGRpdGlvbmFsQXV0aGVudGljYXRlZERhdGEgPSBiYXNlNjR1cmwoandlLmFhZCk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBhYWQnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBpZiAoandlLnVucHJvdGVjdGVkICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmVzdWx0LnNoYXJlZFVucHJvdGVjdGVkSGVhZGVyID0gandlLnVucHJvdGVjdGVkO1xuICAgIH1cbiAgICBpZiAoandlLmhlYWRlciAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHJlc3VsdC51bnByb3RlY3RlZEhlYWRlciA9IGp3ZS5oZWFkZXI7XG4gICAgfVxuICAgIGlmIChyZXNvbHZlZEtleSkge1xuICAgICAgICByZXR1cm4geyAuLi5yZXN1bHQsIGtleSB9O1xuICAgIH1cbiAgICByZXR1cm4gcmVzdWx0O1xufVxuIiwiaW1wb3J0IHsgZmxhdHRlbmVkRGVjcnlwdCB9IGZyb20gJy4uL2ZsYXR0ZW5lZC9kZWNyeXB0LmpzJztcbmltcG9ydCB7IEpXRUludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgeyBkZWNvZGVyIH0gZnJvbSAnLi4vLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gY29tcGFjdERlY3J5cHQoandlLCBrZXksIG9wdGlvbnMpIHtcbiAgICBpZiAoandlIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICBqd2UgPSBkZWNvZGVyLmRlY29kZShqd2UpO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIGp3ZSAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0NvbXBhY3QgSldFIG11c3QgYmUgYSBzdHJpbmcgb3IgVWludDhBcnJheScpO1xuICAgIH1cbiAgICBjb25zdCB7IDA6IHByb3RlY3RlZEhlYWRlciwgMTogZW5jcnlwdGVkS2V5LCAyOiBpdiwgMzogY2lwaGVydGV4dCwgNDogdGFnLCBsZW5ndGgsIH0gPSBqd2Uuc3BsaXQoJy4nKTtcbiAgICBpZiAobGVuZ3RoICE9PSA1KSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdJbnZhbGlkIENvbXBhY3QgSldFJyk7XG4gICAgfVxuICAgIGNvbnN0IGRlY3J5cHRlZCA9IGF3YWl0IGZsYXR0ZW5lZERlY3J5cHQoe1xuICAgICAgICBjaXBoZXJ0ZXh0LFxuICAgICAgICBpdjogaXYgfHwgdW5kZWZpbmVkLFxuICAgICAgICBwcm90ZWN0ZWQ6IHByb3RlY3RlZEhlYWRlcixcbiAgICAgICAgdGFnOiB0YWcgfHwgdW5kZWZpbmVkLFxuICAgICAgICBlbmNyeXB0ZWRfa2V5OiBlbmNyeXB0ZWRLZXkgfHwgdW5kZWZpbmVkLFxuICAgIH0sIGtleSwgb3B0aW9ucyk7XG4gICAgY29uc3QgcmVzdWx0ID0geyBwbGFpbnRleHQ6IGRlY3J5cHRlZC5wbGFpbnRleHQsIHByb3RlY3RlZEhlYWRlcjogZGVjcnlwdGVkLnByb3RlY3RlZEhlYWRlciB9O1xuICAgIGlmICh0eXBlb2Yga2V5ID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgIHJldHVybiB7IC4uLnJlc3VsdCwga2V5OiBkZWNyeXB0ZWQua2V5IH07XG4gICAgfVxuICAgIHJldHVybiByZXN1bHQ7XG59XG4iLCJpbXBvcnQgeyBmbGF0dGVuZWREZWNyeXB0IH0gZnJvbSAnLi4vZmxhdHRlbmVkL2RlY3J5cHQuanMnO1xuaW1wb3J0IHsgSldFRGVjcnlwdGlvbkZhaWxlZCwgSldFSW52YWxpZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCBpc09iamVjdCBmcm9tICcuLi8uLi9saWIvaXNfb2JqZWN0LmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmFsRGVjcnlwdChqd2UsIGtleSwgb3B0aW9ucykge1xuICAgIGlmICghaXNPYmplY3QoandlKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnR2VuZXJhbCBKV0UgbXVzdCBiZSBhbiBvYmplY3QnKTtcbiAgICB9XG4gICAgaWYgKCFBcnJheS5pc0FycmF5KGp3ZS5yZWNpcGllbnRzKSB8fCAhandlLnJlY2lwaWVudHMuZXZlcnkoaXNPYmplY3QpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgUmVjaXBpZW50cyBtaXNzaW5nIG9yIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmICghandlLnJlY2lwaWVudHMubGVuZ3RoKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgUmVjaXBpZW50cyBoYXMgbm8gbWVtYmVycycpO1xuICAgIH1cbiAgICBmb3IgKGNvbnN0IHJlY2lwaWVudCBvZiBqd2UucmVjaXBpZW50cykge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgcmV0dXJuIGF3YWl0IGZsYXR0ZW5lZERlY3J5cHQoe1xuICAgICAgICAgICAgICAgIGFhZDogandlLmFhZCxcbiAgICAgICAgICAgICAgICBjaXBoZXJ0ZXh0OiBqd2UuY2lwaGVydGV4dCxcbiAgICAgICAgICAgICAgICBlbmNyeXB0ZWRfa2V5OiByZWNpcGllbnQuZW5jcnlwdGVkX2tleSxcbiAgICAgICAgICAgICAgICBoZWFkZXI6IHJlY2lwaWVudC5oZWFkZXIsXG4gICAgICAgICAgICAgICAgaXY6IGp3ZS5pdixcbiAgICAgICAgICAgICAgICBwcm90ZWN0ZWQ6IGp3ZS5wcm90ZWN0ZWQsXG4gICAgICAgICAgICAgICAgdGFnOiBqd2UudGFnLFxuICAgICAgICAgICAgICAgIHVucHJvdGVjdGVkOiBqd2UudW5wcm90ZWN0ZWQsXG4gICAgICAgICAgICB9LCBrZXksIG9wdGlvbnMpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIHtcbiAgICAgICAgfVxuICAgIH1cbiAgICB0aHJvdyBuZXcgSldFRGVjcnlwdGlvbkZhaWxlZCgpO1xufVxuIiwiaW1wb3J0IGNyeXB0bywgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCBpbnZhbGlkS2V5SW5wdXQgZnJvbSAnLi4vbGliL2ludmFsaWRfa2V5X2lucHV0LmpzJztcbmltcG9ydCB7IGVuY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuY29uc3Qga2V5VG9KV0sgPSBhc3luYyAoa2V5KSA9PiB7XG4gICAgaWYgKGtleSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgIGt0eTogJ29jdCcsXG4gICAgICAgICAgICBrOiBiYXNlNjR1cmwoa2V5KSxcbiAgICAgICAgfTtcbiAgICB9XG4gICAgaWYgKCFpc0NyeXB0b0tleShrZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMsICdVaW50OEFycmF5JykpO1xuICAgIH1cbiAgICBpZiAoIWtleS5leHRyYWN0YWJsZSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdub24tZXh0cmFjdGFibGUgQ3J5cHRvS2V5IGNhbm5vdCBiZSBleHBvcnRlZCBhcyBhIEpXSycpO1xuICAgIH1cbiAgICBjb25zdCB7IGV4dCwga2V5X29wcywgYWxnLCB1c2UsIC4uLmp3ayB9ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoJ2p3aycsIGtleSk7XG4gICAgcmV0dXJuIGp3aztcbn07XG5leHBvcnQgZGVmYXVsdCBrZXlUb0pXSztcbiIsImltcG9ydCB7IHRvU1BLSSBhcyBleHBvcnRQdWJsaWMgfSBmcm9tICcuLi9ydW50aW1lL2FzbjEuanMnO1xuaW1wb3J0IHsgdG9QS0NTOCBhcyBleHBvcnRQcml2YXRlIH0gZnJvbSAnLi4vcnVudGltZS9hc24xLmpzJztcbmltcG9ydCBrZXlUb0pXSyBmcm9tICcuLi9ydW50aW1lL2tleV90b19qd2suanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGV4cG9ydFNQS0koa2V5KSB7XG4gICAgcmV0dXJuIGV4cG9ydFB1YmxpYyhrZXkpO1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGV4cG9ydFBLQ1M4KGtleSkge1xuICAgIHJldHVybiBleHBvcnRQcml2YXRlKGtleSk7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZXhwb3J0SldLKGtleSkge1xuICAgIHJldHVybiBrZXlUb0pXSyhrZXkpO1xufVxuIiwiaW1wb3J0IHsgd3JhcCBhcyBhZXNLdyB9IGZyb20gJy4uL3J1bnRpbWUvYWVza3cuanMnO1xuaW1wb3J0ICogYXMgRUNESCBmcm9tICcuLi9ydW50aW1lL2VjZGhlcy5qcyc7XG5pbXBvcnQgeyBlbmNyeXB0IGFzIHBiZXMyS3cgfSBmcm9tICcuLi9ydW50aW1lL3BiZXMya3cuanMnO1xuaW1wb3J0IHsgZW5jcnlwdCBhcyByc2FFcyB9IGZyb20gJy4uL3J1bnRpbWUvcnNhZXMuanMnO1xuaW1wb3J0IHsgZW5jb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmltcG9ydCBnZW5lcmF0ZUNlaywgeyBiaXRMZW5ndGggYXMgY2VrTGVuZ3RoIH0gZnJvbSAnLi4vbGliL2Nlay5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHsgZXhwb3J0SldLIH0gZnJvbSAnLi4va2V5L2V4cG9ydC5qcyc7XG5pbXBvcnQgY2hlY2tLZXlUeXBlIGZyb20gJy4vY2hlY2tfa2V5X3R5cGUuanMnO1xuaW1wb3J0IHsgd3JhcCBhcyBhZXNHY21LdyB9IGZyb20gJy4vYWVzZ2Nta3cuanMnO1xuYXN5bmMgZnVuY3Rpb24gZW5jcnlwdEtleU1hbmFnZW1lbnQoYWxnLCBlbmMsIGtleSwgcHJvdmlkZWRDZWssIHByb3ZpZGVkUGFyYW1ldGVycyA9IHt9KSB7XG4gICAgbGV0IGVuY3J5cHRlZEtleTtcbiAgICBsZXQgcGFyYW1ldGVycztcbiAgICBsZXQgY2VrO1xuICAgIGNoZWNrS2V5VHlwZShhbGcsIGtleSwgJ2VuY3J5cHQnKTtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdkaXInOiB7XG4gICAgICAgICAgICBjZWsgPSBrZXk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdFQ0RILUVTJzpcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMTI4S1cnOlxuICAgICAgICBjYXNlICdFQ0RILUVTK0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTI1NktXJzoge1xuICAgICAgICAgICAgaWYgKCFFQ0RILmVjZGhBbGxvd2VkKGtleSkpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnRUNESCB3aXRoIHRoZSBwcm92aWRlZCBrZXkgaXMgbm90IGFsbG93ZWQgb3Igbm90IHN1cHBvcnRlZCBieSB5b3VyIGphdmFzY3JpcHQgcnVudGltZScpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY29uc3QgeyBhcHUsIGFwdiB9ID0gcHJvdmlkZWRQYXJhbWV0ZXJzO1xuICAgICAgICAgICAgbGV0IHsgZXBrOiBlcGhlbWVyYWxLZXkgfSA9IHByb3ZpZGVkUGFyYW1ldGVycztcbiAgICAgICAgICAgIGVwaGVtZXJhbEtleSB8fCAoZXBoZW1lcmFsS2V5ID0gKGF3YWl0IEVDREguZ2VuZXJhdGVFcGsoa2V5KSkucHJpdmF0ZUtleSk7XG4gICAgICAgICAgICBjb25zdCB7IHgsIHksIGNydiwga3R5IH0gPSBhd2FpdCBleHBvcnRKV0soZXBoZW1lcmFsS2V5KTtcbiAgICAgICAgICAgIGNvbnN0IHNoYXJlZFNlY3JldCA9IGF3YWl0IEVDREguZGVyaXZlS2V5KGtleSwgZXBoZW1lcmFsS2V5LCBhbGcgPT09ICdFQ0RILUVTJyA/IGVuYyA6IGFsZywgYWxnID09PSAnRUNESC1FUycgPyBjZWtMZW5ndGgoZW5jKSA6IHBhcnNlSW50KGFsZy5zbGljZSgtNSwgLTIpLCAxMCksIGFwdSwgYXB2KTtcbiAgICAgICAgICAgIHBhcmFtZXRlcnMgPSB7IGVwazogeyB4LCBjcnYsIGt0eSB9IH07XG4gICAgICAgICAgICBpZiAoa3R5ID09PSAnRUMnKVxuICAgICAgICAgICAgICAgIHBhcmFtZXRlcnMuZXBrLnkgPSB5O1xuICAgICAgICAgICAgaWYgKGFwdSlcbiAgICAgICAgICAgICAgICBwYXJhbWV0ZXJzLmFwdSA9IGJhc2U2NHVybChhcHUpO1xuICAgICAgICAgICAgaWYgKGFwdilcbiAgICAgICAgICAgICAgICBwYXJhbWV0ZXJzLmFwdiA9IGJhc2U2NHVybChhcHYpO1xuICAgICAgICAgICAgaWYgKGFsZyA9PT0gJ0VDREgtRVMnKSB7XG4gICAgICAgICAgICAgICAgY2VrID0gc2hhcmVkU2VjcmV0O1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY2VrID0gcHJvdmlkZWRDZWsgfHwgZ2VuZXJhdGVDZWsoZW5jKTtcbiAgICAgICAgICAgIGNvbnN0IGt3QWxnID0gYWxnLnNsaWNlKC02KTtcbiAgICAgICAgICAgIGVuY3J5cHRlZEtleSA9IGF3YWl0IGFlc0t3KGt3QWxnLCBzaGFyZWRTZWNyZXQsIGNlayk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdSU0ExXzUnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTI1Nic6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTM4NCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTUxMic6IHtcbiAgICAgICAgICAgIGNlayA9IHByb3ZpZGVkQ2VrIHx8IGdlbmVyYXRlQ2VrKGVuYyk7XG4gICAgICAgICAgICBlbmNyeXB0ZWRLZXkgPSBhd2FpdCByc2FFcyhhbGcsIGtleSwgY2VrKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ1BCRVMyLUhTMjU2K0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ1BCRVMyLUhTMzg0K0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ1BCRVMyLUhTNTEyK0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGNlayA9IHByb3ZpZGVkQ2VrIHx8IGdlbmVyYXRlQ2VrKGVuYyk7XG4gICAgICAgICAgICBjb25zdCB7IHAyYywgcDJzIH0gPSBwcm92aWRlZFBhcmFtZXRlcnM7XG4gICAgICAgICAgICAoeyBlbmNyeXB0ZWRLZXksIC4uLnBhcmFtZXRlcnMgfSA9IGF3YWl0IHBiZXMyS3coYWxnLCBrZXksIGNlaywgcDJjLCBwMnMpKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGNlayA9IHByb3ZpZGVkQ2VrIHx8IGdlbmVyYXRlQ2VrKGVuYyk7XG4gICAgICAgICAgICBlbmNyeXB0ZWRLZXkgPSBhd2FpdCBhZXNLdyhhbGcsIGtleSwgY2VrKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0ExMjhHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ01LVyc6IHtcbiAgICAgICAgICAgIGNlayA9IHByb3ZpZGVkQ2VrIHx8IGdlbmVyYXRlQ2VrKGVuYyk7XG4gICAgICAgICAgICBjb25zdCB7IGl2IH0gPSBwcm92aWRlZFBhcmFtZXRlcnM7XG4gICAgICAgICAgICAoeyBlbmNyeXB0ZWRLZXksIC4uLnBhcmFtZXRlcnMgfSA9IGF3YWl0IGFlc0djbUt3KGFsZywga2V5LCBjZWssIGl2KSk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBkZWZhdWx0OiB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBcImFsZ1wiIChKV0UgQWxnb3JpdGhtKSBoZWFkZXIgdmFsdWUnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4geyBjZWssIGVuY3J5cHRlZEtleSwgcGFyYW1ldGVycyB9O1xufVxuZXhwb3J0IGRlZmF1bHQgZW5jcnlwdEtleU1hbmFnZW1lbnQ7XG4iLCJpbXBvcnQgeyBlbmNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi4vLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IGVuY3J5cHQgZnJvbSAnLi4vLi4vcnVudGltZS9lbmNyeXB0LmpzJztcbmltcG9ydCBlbmNyeXB0S2V5TWFuYWdlbWVudCBmcm9tICcuLi8uLi9saWIvZW5jcnlwdF9rZXlfbWFuYWdlbWVudC5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkLCBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IGlzRGlzam9pbnQgZnJvbSAnLi4vLi4vbGliL2lzX2Rpc2pvaW50LmpzJztcbmltcG9ydCB7IGVuY29kZXIsIGRlY29kZXIsIGNvbmNhdCB9IGZyb20gJy4uLy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IHZhbGlkYXRlQ3JpdCBmcm9tICcuLi8uLi9saWIvdmFsaWRhdGVfY3JpdC5qcyc7XG5leHBvcnQgY29uc3QgdW5wcm90ZWN0ZWQgPSBTeW1ib2woKTtcbmV4cG9ydCBjbGFzcyBGbGF0dGVuZWRFbmNyeXB0IHtcbiAgICBjb25zdHJ1Y3RvcihwbGFpbnRleHQpIHtcbiAgICAgICAgaWYgKCEocGxhaW50ZXh0IGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3BsYWludGV4dCBtdXN0IGJlIGFuIGluc3RhbmNlIG9mIFVpbnQ4QXJyYXknKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9wbGFpbnRleHQgPSBwbGFpbnRleHQ7XG4gICAgfVxuICAgIHNldEtleU1hbmFnZW1lbnRQYXJhbWV0ZXJzKHBhcmFtZXRlcnMpIHtcbiAgICAgICAgaWYgKHRoaXMuX2tleU1hbmFnZW1lbnRQYXJhbWV0ZXJzKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRLZXlNYW5hZ2VtZW50UGFyYW1ldGVycyBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX2tleU1hbmFnZW1lbnRQYXJhbWV0ZXJzID0gcGFyYW1ldGVycztcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldFByb3RlY3RlZEhlYWRlcihwcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMuX3Byb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0UHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fcHJvdGVjdGVkSGVhZGVyID0gcHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0U2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIoc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMuX3NoYXJlZFVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRTaGFyZWRVbnByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3NoYXJlZFVucHJvdGVjdGVkSGVhZGVyID0gc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRVbnByb3RlY3RlZEhlYWRlcih1bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFVucHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIgPSB1bnByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldEFkZGl0aW9uYWxBdXRoZW50aWNhdGVkRGF0YShhYWQpIHtcbiAgICAgICAgdGhpcy5fYWFkID0gYWFkO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0Q29udGVudEVuY3J5cHRpb25LZXkoY2VrKSB7XG4gICAgICAgIGlmICh0aGlzLl9jZWspIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldENvbnRlbnRFbmNyeXB0aW9uS2V5IGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fY2VrID0gY2VrO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0SW5pdGlhbGl6YXRpb25WZWN0b3IoaXYpIHtcbiAgICAgICAgaWYgKHRoaXMuX2l2KSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRJbml0aWFsaXphdGlvblZlY3RvciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX2l2ID0gaXY7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBhc3luYyBlbmNyeXB0KGtleSwgb3B0aW9ucykge1xuICAgICAgICBpZiAoIXRoaXMuX3Byb3RlY3RlZEhlYWRlciAmJiAhdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIgJiYgIXRoaXMuX3NoYXJlZFVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnZWl0aGVyIHNldFByb3RlY3RlZEhlYWRlciwgc2V0VW5wcm90ZWN0ZWRIZWFkZXIsIG9yIHNoYXJlZFVucHJvdGVjdGVkSGVhZGVyIG11c3QgYmUgY2FsbGVkIGJlZm9yZSAjZW5jcnlwdCgpJyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCFpc0Rpc2pvaW50KHRoaXMuX3Byb3RlY3RlZEhlYWRlciwgdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIsIHRoaXMuX3NoYXJlZFVucHJvdGVjdGVkSGVhZGVyKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBQcm90ZWN0ZWQsIEpXRSBTaGFyZWQgVW5wcm90ZWN0ZWQgYW5kIEpXRSBQZXItUmVjaXBpZW50IEhlYWRlciBQYXJhbWV0ZXIgbmFtZXMgbXVzdCBiZSBkaXNqb2ludCcpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IGpvc2VIZWFkZXIgPSB7XG4gICAgICAgICAgICAuLi50aGlzLl9wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICAuLi50aGlzLl91bnByb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgIC4uLnRoaXMuX3NoYXJlZFVucHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICB9O1xuICAgICAgICB2YWxpZGF0ZUNyaXQoSldFSW52YWxpZCwgbmV3IE1hcCgpLCBvcHRpb25zPy5jcml0LCB0aGlzLl9wcm90ZWN0ZWRIZWFkZXIsIGpvc2VIZWFkZXIpO1xuICAgICAgICBpZiAoam9zZUhlYWRlci56aXAgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0pXRSBcInppcFwiIChDb21wcmVzc2lvbiBBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgaXMgbm90IHN1cHBvcnRlZC4nKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCB7IGFsZywgZW5jIH0gPSBqb3NlSGVhZGVyO1xuICAgICAgICBpZiAodHlwZW9mIGFsZyAhPT0gJ3N0cmluZycgfHwgIWFsZykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBcImFsZ1wiIChBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgbWlzc2luZyBvciBpbnZhbGlkJyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHR5cGVvZiBlbmMgIT09ICdzdHJpbmcnIHx8ICFlbmMpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgXCJlbmNcIiAoRW5jcnlwdGlvbiBBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgbWlzc2luZyBvciBpbnZhbGlkJyk7XG4gICAgICAgIH1cbiAgICAgICAgbGV0IGVuY3J5cHRlZEtleTtcbiAgICAgICAgaWYgKHRoaXMuX2NlayAmJiAoYWxnID09PSAnZGlyJyB8fCBhbGcgPT09ICdFQ0RILUVTJykpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYHNldENvbnRlbnRFbmNyeXB0aW9uS2V5IGNhbm5vdCBiZSBjYWxsZWQgd2l0aCBKV0UgXCJhbGdcIiAoQWxnb3JpdGhtKSBIZWFkZXIgJHthbGd9YCk7XG4gICAgICAgIH1cbiAgICAgICAgbGV0IGNlaztcbiAgICAgICAge1xuICAgICAgICAgICAgbGV0IHBhcmFtZXRlcnM7XG4gICAgICAgICAgICAoeyBjZWssIGVuY3J5cHRlZEtleSwgcGFyYW1ldGVycyB9ID0gYXdhaXQgZW5jcnlwdEtleU1hbmFnZW1lbnQoYWxnLCBlbmMsIGtleSwgdGhpcy5fY2VrLCB0aGlzLl9rZXlNYW5hZ2VtZW50UGFyYW1ldGVycykpO1xuICAgICAgICAgICAgaWYgKHBhcmFtZXRlcnMpIHtcbiAgICAgICAgICAgICAgICBpZiAob3B0aW9ucyAmJiB1bnByb3RlY3RlZCBpbiBvcHRpb25zKSB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuc2V0VW5wcm90ZWN0ZWRIZWFkZXIocGFyYW1ldGVycyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl91bnByb3RlY3RlZEhlYWRlciA9IHsgLi4udGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIsIC4uLnBhcmFtZXRlcnMgfTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCF0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuc2V0UHJvdGVjdGVkSGVhZGVyKHBhcmFtZXRlcnMpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fcHJvdGVjdGVkSGVhZGVyID0geyAuLi50aGlzLl9wcm90ZWN0ZWRIZWFkZXIsIC4uLnBhcmFtZXRlcnMgfTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBsZXQgYWRkaXRpb25hbERhdGE7XG4gICAgICAgIGxldCBwcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIGxldCBhYWRNZW1iZXI7XG4gICAgICAgIGlmICh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHByb3RlY3RlZEhlYWRlciA9IGVuY29kZXIuZW5jb2RlKGJhc2U2NHVybChKU09OLnN0cmluZ2lmeSh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpKSk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBwcm90ZWN0ZWRIZWFkZXIgPSBlbmNvZGVyLmVuY29kZSgnJyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX2FhZCkge1xuICAgICAgICAgICAgYWFkTWVtYmVyID0gYmFzZTY0dXJsKHRoaXMuX2FhZCk7XG4gICAgICAgICAgICBhZGRpdGlvbmFsRGF0YSA9IGNvbmNhdChwcm90ZWN0ZWRIZWFkZXIsIGVuY29kZXIuZW5jb2RlKCcuJyksIGVuY29kZXIuZW5jb2RlKGFhZE1lbWJlcikpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgYWRkaXRpb25hbERhdGEgPSBwcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgeyBjaXBoZXJ0ZXh0LCB0YWcsIGl2IH0gPSBhd2FpdCBlbmNyeXB0KGVuYywgdGhpcy5fcGxhaW50ZXh0LCBjZWssIHRoaXMuX2l2LCBhZGRpdGlvbmFsRGF0YSk7XG4gICAgICAgIGNvbnN0IGp3ZSA9IHtcbiAgICAgICAgICAgIGNpcGhlcnRleHQ6IGJhc2U2NHVybChjaXBoZXJ0ZXh0KSxcbiAgICAgICAgfTtcbiAgICAgICAgaWYgKGl2KSB7XG4gICAgICAgICAgICBqd2UuaXYgPSBiYXNlNjR1cmwoaXYpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0YWcpIHtcbiAgICAgICAgICAgIGp3ZS50YWcgPSBiYXNlNjR1cmwodGFnKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoZW5jcnlwdGVkS2V5KSB7XG4gICAgICAgICAgICBqd2UuZW5jcnlwdGVkX2tleSA9IGJhc2U2NHVybChlbmNyeXB0ZWRLZXkpO1xuICAgICAgICB9XG4gICAgICAgIGlmIChhYWRNZW1iZXIpIHtcbiAgICAgICAgICAgIGp3ZS5hYWQgPSBhYWRNZW1iZXI7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX3Byb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgandlLnByb3RlY3RlZCA9IGRlY29kZXIuZGVjb2RlKHByb3RlY3RlZEhlYWRlcik7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX3NoYXJlZFVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICBqd2UudW5wcm90ZWN0ZWQgPSB0aGlzLl9zaGFyZWRVbnByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIGp3ZS5oZWFkZXIgPSB0aGlzLl91bnByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gandlO1xuICAgIH1cbn1cbiIsImltcG9ydCB7IEZsYXR0ZW5lZEVuY3J5cHQsIHVucHJvdGVjdGVkIH0gZnJvbSAnLi4vZmxhdHRlbmVkL2VuY3J5cHQuanMnO1xuaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCwgSldFSW52YWxpZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCBnZW5lcmF0ZUNlayBmcm9tICcuLi8uLi9saWIvY2VrLmpzJztcbmltcG9ydCBpc0Rpc2pvaW50IGZyb20gJy4uLy4uL2xpYi9pc19kaXNqb2ludC5qcyc7XG5pbXBvcnQgZW5jcnlwdEtleU1hbmFnZW1lbnQgZnJvbSAnLi4vLi4vbGliL2VuY3J5cHRfa2V5X21hbmFnZW1lbnQuanMnO1xuaW1wb3J0IHsgZW5jb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4uLy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmltcG9ydCB2YWxpZGF0ZUNyaXQgZnJvbSAnLi4vLi4vbGliL3ZhbGlkYXRlX2NyaXQuanMnO1xuY2xhc3MgSW5kaXZpZHVhbFJlY2lwaWVudCB7XG4gICAgY29uc3RydWN0b3IoZW5jLCBrZXksIG9wdGlvbnMpIHtcbiAgICAgICAgdGhpcy5wYXJlbnQgPSBlbmM7XG4gICAgICAgIHRoaXMua2V5ID0ga2V5O1xuICAgICAgICB0aGlzLm9wdGlvbnMgPSBvcHRpb25zO1xuICAgIH1cbiAgICBzZXRVbnByb3RlY3RlZEhlYWRlcih1bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy51bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0VW5wcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLnVucHJvdGVjdGVkSGVhZGVyID0gdW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBhZGRSZWNpcGllbnQoLi4uYXJncykge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXJlbnQuYWRkUmVjaXBpZW50KC4uLmFyZ3MpO1xuICAgIH1cbiAgICBlbmNyeXB0KC4uLmFyZ3MpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGFyZW50LmVuY3J5cHQoLi4uYXJncyk7XG4gICAgfVxuICAgIGRvbmUoKSB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhcmVudDtcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgR2VuZXJhbEVuY3J5cHQge1xuICAgIGNvbnN0cnVjdG9yKHBsYWludGV4dCkge1xuICAgICAgICB0aGlzLl9yZWNpcGllbnRzID0gW107XG4gICAgICAgIHRoaXMuX3BsYWludGV4dCA9IHBsYWludGV4dDtcbiAgICB9XG4gICAgYWRkUmVjaXBpZW50KGtleSwgb3B0aW9ucykge1xuICAgICAgICBjb25zdCByZWNpcGllbnQgPSBuZXcgSW5kaXZpZHVhbFJlY2lwaWVudCh0aGlzLCBrZXksIHsgY3JpdDogb3B0aW9ucz8uY3JpdCB9KTtcbiAgICAgICAgdGhpcy5fcmVjaXBpZW50cy5wdXNoKHJlY2lwaWVudCk7XG4gICAgICAgIHJldHVybiByZWNpcGllbnQ7XG4gICAgfVxuICAgIHNldFByb3RlY3RlZEhlYWRlcihwcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMuX3Byb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0UHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fcHJvdGVjdGVkSGVhZGVyID0gcHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0U2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIoc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRTaGFyZWRVbnByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyID0gc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRBZGRpdGlvbmFsQXV0aGVudGljYXRlZERhdGEoYWFkKSB7XG4gICAgICAgIHRoaXMuX2FhZCA9IGFhZDtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIGFzeW5jIGVuY3J5cHQoKSB7XG4gICAgICAgIGlmICghdGhpcy5fcmVjaXBpZW50cy5sZW5ndGgpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdhdCBsZWFzdCBvbmUgcmVjaXBpZW50IG11c3QgYmUgYWRkZWQnKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5fcmVjaXBpZW50cy5sZW5ndGggPT09IDEpIHtcbiAgICAgICAgICAgIGNvbnN0IFtyZWNpcGllbnRdID0gdGhpcy5fcmVjaXBpZW50cztcbiAgICAgICAgICAgIGNvbnN0IGZsYXR0ZW5lZCA9IGF3YWl0IG5ldyBGbGF0dGVuZWRFbmNyeXB0KHRoaXMuX3BsYWludGV4dClcbiAgICAgICAgICAgICAgICAuc2V0QWRkaXRpb25hbEF1dGhlbnRpY2F0ZWREYXRhKHRoaXMuX2FhZClcbiAgICAgICAgICAgICAgICAuc2V0UHJvdGVjdGVkSGVhZGVyKHRoaXMuX3Byb3RlY3RlZEhlYWRlcilcbiAgICAgICAgICAgICAgICAuc2V0U2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIodGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpXG4gICAgICAgICAgICAgICAgLnNldFVucHJvdGVjdGVkSGVhZGVyKHJlY2lwaWVudC51bnByb3RlY3RlZEhlYWRlcilcbiAgICAgICAgICAgICAgICAuZW5jcnlwdChyZWNpcGllbnQua2V5LCB7IC4uLnJlY2lwaWVudC5vcHRpb25zIH0pO1xuICAgICAgICAgICAgY29uc3QgandlID0ge1xuICAgICAgICAgICAgICAgIGNpcGhlcnRleHQ6IGZsYXR0ZW5lZC5jaXBoZXJ0ZXh0LFxuICAgICAgICAgICAgICAgIGl2OiBmbGF0dGVuZWQuaXYsXG4gICAgICAgICAgICAgICAgcmVjaXBpZW50czogW3t9XSxcbiAgICAgICAgICAgICAgICB0YWc6IGZsYXR0ZW5lZC50YWcsXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC5hYWQpXG4gICAgICAgICAgICAgICAgandlLmFhZCA9IGZsYXR0ZW5lZC5hYWQ7XG4gICAgICAgICAgICBpZiAoZmxhdHRlbmVkLnByb3RlY3RlZClcbiAgICAgICAgICAgICAgICBqd2UucHJvdGVjdGVkID0gZmxhdHRlbmVkLnByb3RlY3RlZDtcbiAgICAgICAgICAgIGlmIChmbGF0dGVuZWQudW5wcm90ZWN0ZWQpXG4gICAgICAgICAgICAgICAgandlLnVucHJvdGVjdGVkID0gZmxhdHRlbmVkLnVucHJvdGVjdGVkO1xuICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC5lbmNyeXB0ZWRfa2V5KVxuICAgICAgICAgICAgICAgIGp3ZS5yZWNpcGllbnRzWzBdLmVuY3J5cHRlZF9rZXkgPSBmbGF0dGVuZWQuZW5jcnlwdGVkX2tleTtcbiAgICAgICAgICAgIGlmIChmbGF0dGVuZWQuaGVhZGVyKVxuICAgICAgICAgICAgICAgIGp3ZS5yZWNpcGllbnRzWzBdLmhlYWRlciA9IGZsYXR0ZW5lZC5oZWFkZXI7XG4gICAgICAgICAgICByZXR1cm4gandlO1xuICAgICAgICB9XG4gICAgICAgIGxldCBlbmM7XG4gICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgdGhpcy5fcmVjaXBpZW50cy5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgY29uc3QgcmVjaXBpZW50ID0gdGhpcy5fcmVjaXBpZW50c1tpXTtcbiAgICAgICAgICAgIGlmICghaXNEaXNqb2ludCh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIsIHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyLCByZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXIpKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBQcm90ZWN0ZWQsIEpXRSBTaGFyZWQgVW5wcm90ZWN0ZWQgYW5kIEpXRSBQZXItUmVjaXBpZW50IEhlYWRlciBQYXJhbWV0ZXIgbmFtZXMgbXVzdCBiZSBkaXNqb2ludCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY29uc3Qgam9zZUhlYWRlciA9IHtcbiAgICAgICAgICAgICAgICAuLi50aGlzLl9wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICAgICAgLi4udGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICAgICAgLi4ucmVjaXBpZW50LnVucHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIGNvbnN0IHsgYWxnIH0gPSBqb3NlSGVhZGVyO1xuICAgICAgICAgICAgaWYgKHR5cGVvZiBhbGcgIT09ICdzdHJpbmcnIHx8ICFhbGcpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFwiYWxnXCIgKEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBtaXNzaW5nIG9yIGludmFsaWQnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmIChhbGcgPT09ICdkaXInIHx8IGFsZyA9PT0gJ0VDREgtRVMnKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ1wiZGlyXCIgYW5kIFwiRUNESC1FU1wiIGFsZyBtYXkgb25seSBiZSB1c2VkIHdpdGggYSBzaW5nbGUgcmVjaXBpZW50Jyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAodHlwZW9mIGpvc2VIZWFkZXIuZW5jICE9PSAnc3RyaW5nJyB8fCAham9zZUhlYWRlci5lbmMpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFwiZW5jXCIgKEVuY3J5cHRpb24gQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIG1pc3Npbmcgb3IgaW52YWxpZCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKCFlbmMpIHtcbiAgICAgICAgICAgICAgICBlbmMgPSBqb3NlSGVhZGVyLmVuYztcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2UgaWYgKGVuYyAhPT0gam9zZUhlYWRlci5lbmMpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFwiZW5jXCIgKEVuY3J5cHRpb24gQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIG11c3QgYmUgdGhlIHNhbWUgZm9yIGFsbCByZWNpcGllbnRzJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICB2YWxpZGF0ZUNyaXQoSldFSW52YWxpZCwgbmV3IE1hcCgpLCByZWNpcGllbnQub3B0aW9ucy5jcml0LCB0aGlzLl9wcm90ZWN0ZWRIZWFkZXIsIGpvc2VIZWFkZXIpO1xuICAgICAgICAgICAgaWYgKGpvc2VIZWFkZXIuemlwICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSldFIFwiemlwXCIgKENvbXByZXNzaW9uIEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBpcyBub3Qgc3VwcG9ydGVkLicpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIGNvbnN0IGNlayA9IGdlbmVyYXRlQ2VrKGVuYyk7XG4gICAgICAgIGNvbnN0IGp3ZSA9IHtcbiAgICAgICAgICAgIGNpcGhlcnRleHQ6ICcnLFxuICAgICAgICAgICAgaXY6ICcnLFxuICAgICAgICAgICAgcmVjaXBpZW50czogW10sXG4gICAgICAgICAgICB0YWc6ICcnLFxuICAgICAgICB9O1xuICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHRoaXMuX3JlY2lwaWVudHMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIGNvbnN0IHJlY2lwaWVudCA9IHRoaXMuX3JlY2lwaWVudHNbaV07XG4gICAgICAgICAgICBjb25zdCB0YXJnZXQgPSB7fTtcbiAgICAgICAgICAgIGp3ZS5yZWNpcGllbnRzLnB1c2godGFyZ2V0KTtcbiAgICAgICAgICAgIGNvbnN0IGpvc2VIZWFkZXIgPSB7XG4gICAgICAgICAgICAgICAgLi4udGhpcy5fcHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgICAgIC4uLnRoaXMuX3VucHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgICAgIC4uLnJlY2lwaWVudC51bnByb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgIH07XG4gICAgICAgICAgICBjb25zdCBwMmMgPSBqb3NlSGVhZGVyLmFsZy5zdGFydHNXaXRoKCdQQkVTMicpID8gMjA0OCArIGkgOiB1bmRlZmluZWQ7XG4gICAgICAgICAgICBpZiAoaSA9PT0gMCkge1xuICAgICAgICAgICAgICAgIGNvbnN0IGZsYXR0ZW5lZCA9IGF3YWl0IG5ldyBGbGF0dGVuZWRFbmNyeXB0KHRoaXMuX3BsYWludGV4dClcbiAgICAgICAgICAgICAgICAgICAgLnNldEFkZGl0aW9uYWxBdXRoZW50aWNhdGVkRGF0YSh0aGlzLl9hYWQpXG4gICAgICAgICAgICAgICAgICAgIC5zZXRDb250ZW50RW5jcnlwdGlvbktleShjZWspXG4gICAgICAgICAgICAgICAgICAgIC5zZXRQcm90ZWN0ZWRIZWFkZXIodGhpcy5fcHJvdGVjdGVkSGVhZGVyKVxuICAgICAgICAgICAgICAgICAgICAuc2V0U2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIodGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpXG4gICAgICAgICAgICAgICAgICAgIC5zZXRVbnByb3RlY3RlZEhlYWRlcihyZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXIpXG4gICAgICAgICAgICAgICAgICAgIC5zZXRLZXlNYW5hZ2VtZW50UGFyYW1ldGVycyh7IHAyYyB9KVxuICAgICAgICAgICAgICAgICAgICAuZW5jcnlwdChyZWNpcGllbnQua2V5LCB7XG4gICAgICAgICAgICAgICAgICAgIC4uLnJlY2lwaWVudC5vcHRpb25zLFxuICAgICAgICAgICAgICAgICAgICBbdW5wcm90ZWN0ZWRdOiB0cnVlLFxuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIGp3ZS5jaXBoZXJ0ZXh0ID0gZmxhdHRlbmVkLmNpcGhlcnRleHQ7XG4gICAgICAgICAgICAgICAgandlLml2ID0gZmxhdHRlbmVkLml2O1xuICAgICAgICAgICAgICAgIGp3ZS50YWcgPSBmbGF0dGVuZWQudGFnO1xuICAgICAgICAgICAgICAgIGlmIChmbGF0dGVuZWQuYWFkKVxuICAgICAgICAgICAgICAgICAgICBqd2UuYWFkID0gZmxhdHRlbmVkLmFhZDtcbiAgICAgICAgICAgICAgICBpZiAoZmxhdHRlbmVkLnByb3RlY3RlZClcbiAgICAgICAgICAgICAgICAgICAgandlLnByb3RlY3RlZCA9IGZsYXR0ZW5lZC5wcm90ZWN0ZWQ7XG4gICAgICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC51bnByb3RlY3RlZClcbiAgICAgICAgICAgICAgICAgICAgandlLnVucHJvdGVjdGVkID0gZmxhdHRlbmVkLnVucHJvdGVjdGVkO1xuICAgICAgICAgICAgICAgIHRhcmdldC5lbmNyeXB0ZWRfa2V5ID0gZmxhdHRlbmVkLmVuY3J5cHRlZF9rZXk7XG4gICAgICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC5oZWFkZXIpXG4gICAgICAgICAgICAgICAgICAgIHRhcmdldC5oZWFkZXIgPSBmbGF0dGVuZWQuaGVhZGVyO1xuICAgICAgICAgICAgICAgIGNvbnRpbnVlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY29uc3QgeyBlbmNyeXB0ZWRLZXksIHBhcmFtZXRlcnMgfSA9IGF3YWl0IGVuY3J5cHRLZXlNYW5hZ2VtZW50KHJlY2lwaWVudC51bnByb3RlY3RlZEhlYWRlcj8uYWxnIHx8XG4gICAgICAgICAgICAgICAgdGhpcy5fcHJvdGVjdGVkSGVhZGVyPy5hbGcgfHxcbiAgICAgICAgICAgICAgICB0aGlzLl91bnByb3RlY3RlZEhlYWRlcj8uYWxnLCBlbmMsIHJlY2lwaWVudC5rZXksIGNlaywgeyBwMmMgfSk7XG4gICAgICAgICAgICB0YXJnZXQuZW5jcnlwdGVkX2tleSA9IGJhc2U2NHVybChlbmNyeXB0ZWRLZXkpO1xuICAgICAgICAgICAgaWYgKHJlY2lwaWVudC51bnByb3RlY3RlZEhlYWRlciB8fCBwYXJhbWV0ZXJzKVxuICAgICAgICAgICAgICAgIHRhcmdldC5oZWFkZXIgPSB7IC4uLnJlY2lwaWVudC51bnByb3RlY3RlZEhlYWRlciwgLi4ucGFyYW1ldGVycyB9O1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBqd2U7XG4gICAgfVxufVxuIiwiaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIHN1YnRsZURzYShhbGcsIGFsZ29yaXRobSkge1xuICAgIGNvbnN0IGhhc2ggPSBgU0hBLSR7YWxnLnNsaWNlKC0zKX1gO1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ0hTMjU2JzpcbiAgICAgICAgY2FzZSAnSFMzODQnOlxuICAgICAgICBjYXNlICdIUzUxMic6XG4gICAgICAgICAgICByZXR1cm4geyBoYXNoLCBuYW1lOiAnSE1BQycgfTtcbiAgICAgICAgY2FzZSAnUFMyNTYnOlxuICAgICAgICBjYXNlICdQUzM4NCc6XG4gICAgICAgIGNhc2UgJ1BTNTEyJzpcbiAgICAgICAgICAgIHJldHVybiB7IGhhc2gsIG5hbWU6ICdSU0EtUFNTJywgc2FsdExlbmd0aDogYWxnLnNsaWNlKC0zKSA+PiAzIH07XG4gICAgICAgIGNhc2UgJ1JTMjU2JzpcbiAgICAgICAgY2FzZSAnUlMzODQnOlxuICAgICAgICBjYXNlICdSUzUxMic6XG4gICAgICAgICAgICByZXR1cm4geyBoYXNoLCBuYW1lOiAnUlNBU1NBLVBLQ1MxLXYxXzUnIH07XG4gICAgICAgIGNhc2UgJ0VTMjU2JzpcbiAgICAgICAgY2FzZSAnRVMzODQnOlxuICAgICAgICBjYXNlICdFUzUxMic6XG4gICAgICAgICAgICByZXR1cm4geyBoYXNoLCBuYW1lOiAnRUNEU0EnLCBuYW1lZEN1cnZlOiBhbGdvcml0aG0ubmFtZWRDdXJ2ZSB9O1xuICAgICAgICBjYXNlICdFZERTQSc6XG4gICAgICAgICAgICByZXR1cm4geyBuYW1lOiBhbGdvcml0aG0ubmFtZSB9O1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoYGFsZyAke2FsZ30gaXMgbm90IHN1cHBvcnRlZCBlaXRoZXIgYnkgSk9TRSBvciB5b3VyIGphdmFzY3JpcHQgcnVudGltZWApO1xuICAgIH1cbn1cbiIsImltcG9ydCBjcnlwdG8sIHsgaXNDcnlwdG9LZXkgfSBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgeyBjaGVja1NpZ0NyeXB0b0tleSB9IGZyb20gJy4uL2xpYi9jcnlwdG9fa2V5LmpzJztcbmltcG9ydCBpbnZhbGlkS2V5SW5wdXQgZnJvbSAnLi4vbGliL2ludmFsaWRfa2V5X2lucHV0LmpzJztcbmltcG9ydCB7IHR5cGVzIH0gZnJvbSAnLi9pc19rZXlfbGlrZS5qcyc7XG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBnZXRDcnlwdG9LZXkoYWxnLCBrZXksIHVzYWdlKSB7XG4gICAgaWYgKGlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgY2hlY2tTaWdDcnlwdG9LZXkoa2V5LCBhbGcsIHVzYWdlKTtcbiAgICAgICAgcmV0dXJuIGtleTtcbiAgICB9XG4gICAgaWYgKGtleSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgaWYgKCFhbGcuc3RhcnRzV2l0aCgnSFMnKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcykpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3Jywga2V5LCB7IGhhc2g6IGBTSEEtJHthbGcuc2xpY2UoLTMpfWAsIG5hbWU6ICdITUFDJyB9LCBmYWxzZSwgW3VzYWdlXSk7XG4gICAgfVxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMsICdVaW50OEFycmF5JykpO1xufVxuIiwiaW1wb3J0IHN1YnRsZUFsZ29yaXRobSBmcm9tICcuL3N1YnRsZV9kc2EuanMnO1xuaW1wb3J0IGNyeXB0byBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgY2hlY2tLZXlMZW5ndGggZnJvbSAnLi9jaGVja19rZXlfbGVuZ3RoLmpzJztcbmltcG9ydCBnZXRWZXJpZnlLZXkgZnJvbSAnLi9nZXRfc2lnbl92ZXJpZnlfa2V5LmpzJztcbmNvbnN0IHZlcmlmeSA9IGFzeW5jIChhbGcsIGtleSwgc2lnbmF0dXJlLCBkYXRhKSA9PiB7XG4gICAgY29uc3QgY3J5cHRvS2V5ID0gYXdhaXQgZ2V0VmVyaWZ5S2V5KGFsZywga2V5LCAndmVyaWZ5Jyk7XG4gICAgY2hlY2tLZXlMZW5ndGgoYWxnLCBjcnlwdG9LZXkpO1xuICAgIGNvbnN0IGFsZ29yaXRobSA9IHN1YnRsZUFsZ29yaXRobShhbGcsIGNyeXB0b0tleS5hbGdvcml0aG0pO1xuICAgIHRyeSB7XG4gICAgICAgIHJldHVybiBhd2FpdCBjcnlwdG8uc3VidGxlLnZlcmlmeShhbGdvcml0aG0sIGNyeXB0b0tleSwgc2lnbmF0dXJlLCBkYXRhKTtcbiAgICB9XG4gICAgY2F0Y2gge1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxufTtcbmV4cG9ydCBkZWZhdWx0IHZlcmlmeTtcbiIsImltcG9ydCB7IGRlY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi8uLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgdmVyaWZ5IGZyb20gJy4uLy4uL3J1bnRpbWUvdmVyaWZ5LmpzJztcbmltcG9ydCB7IEpPU0VBbGdOb3RBbGxvd2VkLCBKV1NJbnZhbGlkLCBKV1NTaWduYXR1cmVWZXJpZmljYXRpb25GYWlsZWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgeyBjb25jYXQsIGVuY29kZXIsIGRlY29kZXIgfSBmcm9tICcuLi8uLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmltcG9ydCBpc0Rpc2pvaW50IGZyb20gJy4uLy4uL2xpYi9pc19kaXNqb2ludC5qcyc7XG5pbXBvcnQgaXNPYmplY3QgZnJvbSAnLi4vLi4vbGliL2lzX29iamVjdC5qcyc7XG5pbXBvcnQgY2hlY2tLZXlUeXBlIGZyb20gJy4uLy4uL2xpYi9jaGVja19rZXlfdHlwZS5qcyc7XG5pbXBvcnQgdmFsaWRhdGVDcml0IGZyb20gJy4uLy4uL2xpYi92YWxpZGF0ZV9jcml0LmpzJztcbmltcG9ydCB2YWxpZGF0ZUFsZ29yaXRobXMgZnJvbSAnLi4vLi4vbGliL3ZhbGlkYXRlX2FsZ29yaXRobXMuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGZsYXR0ZW5lZFZlcmlmeShqd3MsIGtleSwgb3B0aW9ucykge1xuICAgIGlmICghaXNPYmplY3QoandzKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnRmxhdHRlbmVkIEpXUyBtdXN0IGJlIGFuIG9iamVjdCcpO1xuICAgIH1cbiAgICBpZiAoandzLnByb3RlY3RlZCA9PT0gdW5kZWZpbmVkICYmIGp3cy5oZWFkZXIgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnRmxhdHRlbmVkIEpXUyBtdXN0IGhhdmUgZWl0aGVyIG9mIHRoZSBcInByb3RlY3RlZFwiIG9yIFwiaGVhZGVyXCIgbWVtYmVycycpO1xuICAgIH1cbiAgICBpZiAoandzLnByb3RlY3RlZCAhPT0gdW5kZWZpbmVkICYmIHR5cGVvZiBqd3MucHJvdGVjdGVkICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFByb3RlY3RlZCBIZWFkZXIgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3cy5wYXlsb2FkID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBQYXlsb2FkIG1pc3NpbmcnKTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBqd3Muc2lnbmF0dXJlICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFNpZ25hdHVyZSBtaXNzaW5nIG9yIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmIChqd3MuaGVhZGVyICE9PSB1bmRlZmluZWQgJiYgIWlzT2JqZWN0KGp3cy5oZWFkZXIpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgVW5wcm90ZWN0ZWQgSGVhZGVyIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGxldCBwYXJzZWRQcm90ID0ge307XG4gICAgaWYgKGp3cy5wcm90ZWN0ZWQpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIGNvbnN0IHByb3RlY3RlZEhlYWRlciA9IGJhc2U2NHVybChqd3MucHJvdGVjdGVkKTtcbiAgICAgICAgICAgIHBhcnNlZFByb3QgPSBKU09OLnBhcnNlKGRlY29kZXIuZGVjb2RlKHByb3RlY3RlZEhlYWRlcikpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgUHJvdGVjdGVkIEhlYWRlciBpcyBpbnZhbGlkJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgaWYgKCFpc0Rpc2pvaW50KHBhcnNlZFByb3QsIGp3cy5oZWFkZXIpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgUHJvdGVjdGVkIGFuZCBKV1MgVW5wcm90ZWN0ZWQgSGVhZGVyIFBhcmFtZXRlciBuYW1lcyBtdXN0IGJlIGRpc2pvaW50Jyk7XG4gICAgfVxuICAgIGNvbnN0IGpvc2VIZWFkZXIgPSB7XG4gICAgICAgIC4uLnBhcnNlZFByb3QsXG4gICAgICAgIC4uLmp3cy5oZWFkZXIsXG4gICAgfTtcbiAgICBjb25zdCBleHRlbnNpb25zID0gdmFsaWRhdGVDcml0KEpXU0ludmFsaWQsIG5ldyBNYXAoW1snYjY0JywgdHJ1ZV1dKSwgb3B0aW9ucz8uY3JpdCwgcGFyc2VkUHJvdCwgam9zZUhlYWRlcik7XG4gICAgbGV0IGI2NCA9IHRydWU7XG4gICAgaWYgKGV4dGVuc2lvbnMuaGFzKCdiNjQnKSkge1xuICAgICAgICBiNjQgPSBwYXJzZWRQcm90LmI2NDtcbiAgICAgICAgaWYgKHR5cGVvZiBiNjQgIT09ICdib29sZWFuJykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ1RoZSBcImI2NFwiIChiYXNlNjR1cmwtZW5jb2RlIHBheWxvYWQpIEhlYWRlciBQYXJhbWV0ZXIgbXVzdCBiZSBhIGJvb2xlYW4nKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBjb25zdCB7IGFsZyB9ID0gam9zZUhlYWRlcjtcbiAgICBpZiAodHlwZW9mIGFsZyAhPT0gJ3N0cmluZycgfHwgIWFsZykge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFwiYWxnXCIgKEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBtaXNzaW5nIG9yIGludmFsaWQnKTtcbiAgICB9XG4gICAgY29uc3QgYWxnb3JpdGhtcyA9IG9wdGlvbnMgJiYgdmFsaWRhdGVBbGdvcml0aG1zKCdhbGdvcml0aG1zJywgb3B0aW9ucy5hbGdvcml0aG1zKTtcbiAgICBpZiAoYWxnb3JpdGhtcyAmJiAhYWxnb3JpdGhtcy5oYXMoYWxnKSkge1xuICAgICAgICB0aHJvdyBuZXcgSk9TRUFsZ05vdEFsbG93ZWQoJ1wiYWxnXCIgKEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciB2YWx1ZSBub3QgYWxsb3dlZCcpO1xuICAgIH1cbiAgICBpZiAoYjY0KSB7XG4gICAgICAgIGlmICh0eXBlb2YgandzLnBheWxvYWQgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFBheWxvYWQgbXVzdCBiZSBhIHN0cmluZycpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGVsc2UgaWYgKHR5cGVvZiBqd3MucGF5bG9hZCAhPT0gJ3N0cmluZycgJiYgIShqd3MucGF5bG9hZCBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgUGF5bG9hZCBtdXN0IGJlIGEgc3RyaW5nIG9yIGFuIFVpbnQ4QXJyYXkgaW5zdGFuY2UnKTtcbiAgICB9XG4gICAgbGV0IHJlc29sdmVkS2V5ID0gZmFsc2U7XG4gICAgaWYgKHR5cGVvZiBrZXkgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAga2V5ID0gYXdhaXQga2V5KHBhcnNlZFByb3QsIGp3cyk7XG4gICAgICAgIHJlc29sdmVkS2V5ID0gdHJ1ZTtcbiAgICB9XG4gICAgY2hlY2tLZXlUeXBlKGFsZywga2V5LCAndmVyaWZ5Jyk7XG4gICAgY29uc3QgZGF0YSA9IGNvbmNhdChlbmNvZGVyLmVuY29kZShqd3MucHJvdGVjdGVkID8/ICcnKSwgZW5jb2Rlci5lbmNvZGUoJy4nKSwgdHlwZW9mIGp3cy5wYXlsb2FkID09PSAnc3RyaW5nJyA/IGVuY29kZXIuZW5jb2RlKGp3cy5wYXlsb2FkKSA6IGp3cy5wYXlsb2FkKTtcbiAgICBsZXQgc2lnbmF0dXJlO1xuICAgIHRyeSB7XG4gICAgICAgIHNpZ25hdHVyZSA9IGJhc2U2NHVybChqd3Muc2lnbmF0dXJlKTtcbiAgICB9XG4gICAgY2F0Y2gge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIHNpZ25hdHVyZScpO1xuICAgIH1cbiAgICBjb25zdCB2ZXJpZmllZCA9IGF3YWl0IHZlcmlmeShhbGcsIGtleSwgc2lnbmF0dXJlLCBkYXRhKTtcbiAgICBpZiAoIXZlcmlmaWVkKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NTaWduYXR1cmVWZXJpZmljYXRpb25GYWlsZWQoKTtcbiAgICB9XG4gICAgbGV0IHBheWxvYWQ7XG4gICAgaWYgKGI2NCkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgcGF5bG9hZCA9IGJhc2U2NHVybChqd3MucGF5bG9hZCk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBwYXlsb2FkJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgZWxzZSBpZiAodHlwZW9mIGp3cy5wYXlsb2FkID09PSAnc3RyaW5nJykge1xuICAgICAgICBwYXlsb2FkID0gZW5jb2Rlci5lbmNvZGUoandzLnBheWxvYWQpO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgcGF5bG9hZCA9IGp3cy5wYXlsb2FkO1xuICAgIH1cbiAgICBjb25zdCByZXN1bHQgPSB7IHBheWxvYWQgfTtcbiAgICBpZiAoandzLnByb3RlY3RlZCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHJlc3VsdC5wcm90ZWN0ZWRIZWFkZXIgPSBwYXJzZWRQcm90O1xuICAgIH1cbiAgICBpZiAoandzLmhlYWRlciAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHJlc3VsdC51bnByb3RlY3RlZEhlYWRlciA9IGp3cy5oZWFkZXI7XG4gICAgfVxuICAgIGlmIChyZXNvbHZlZEtleSkge1xuICAgICAgICByZXR1cm4geyAuLi5yZXN1bHQsIGtleSB9O1xuICAgIH1cbiAgICByZXR1cm4gcmVzdWx0O1xufVxuIiwiaW1wb3J0IHsgZmxhdHRlbmVkVmVyaWZ5IH0gZnJvbSAnLi4vZmxhdHRlbmVkL3ZlcmlmeS5qcyc7XG5pbXBvcnQgeyBKV1NJbnZhbGlkIH0gZnJvbSAnLi4vLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHsgZGVjb2RlciB9IGZyb20gJy4uLy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGNvbXBhY3RWZXJpZnkoandzLCBrZXksIG9wdGlvbnMpIHtcbiAgICBpZiAoandzIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICBqd3MgPSBkZWNvZGVyLmRlY29kZShqd3MpO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIGp3cyAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0NvbXBhY3QgSldTIG11c3QgYmUgYSBzdHJpbmcgb3IgVWludDhBcnJheScpO1xuICAgIH1cbiAgICBjb25zdCB7IDA6IHByb3RlY3RlZEhlYWRlciwgMTogcGF5bG9hZCwgMjogc2lnbmF0dXJlLCBsZW5ndGggfSA9IGp3cy5zcGxpdCgnLicpO1xuICAgIGlmIChsZW5ndGggIT09IDMpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0ludmFsaWQgQ29tcGFjdCBKV1MnKTtcbiAgICB9XG4gICAgY29uc3QgdmVyaWZpZWQgPSBhd2FpdCBmbGF0dGVuZWRWZXJpZnkoeyBwYXlsb2FkLCBwcm90ZWN0ZWQ6IHByb3RlY3RlZEhlYWRlciwgc2lnbmF0dXJlIH0sIGtleSwgb3B0aW9ucyk7XG4gICAgY29uc3QgcmVzdWx0ID0geyBwYXlsb2FkOiB2ZXJpZmllZC5wYXlsb2FkLCBwcm90ZWN0ZWRIZWFkZXI6IHZlcmlmaWVkLnByb3RlY3RlZEhlYWRlciB9O1xuICAgIGlmICh0eXBlb2Yga2V5ID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgIHJldHVybiB7IC4uLnJlc3VsdCwga2V5OiB2ZXJpZmllZC5rZXkgfTtcbiAgICB9XG4gICAgcmV0dXJuIHJlc3VsdDtcbn1cbiIsImltcG9ydCB7IGZsYXR0ZW5lZFZlcmlmeSB9IGZyb20gJy4uL2ZsYXR0ZW5lZC92ZXJpZnkuanMnO1xuaW1wb3J0IHsgSldTSW52YWxpZCwgSldTU2lnbmF0dXJlVmVyaWZpY2F0aW9uRmFpbGVkIH0gZnJvbSAnLi4vLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4uLy4uL2xpYi9pc19vYmplY3QuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdlbmVyYWxWZXJpZnkoandzLCBrZXksIG9wdGlvbnMpIHtcbiAgICBpZiAoIWlzT2JqZWN0KGp3cykpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0dlbmVyYWwgSldTIG11c3QgYmUgYW4gb2JqZWN0Jyk7XG4gICAgfVxuICAgIGlmICghQXJyYXkuaXNBcnJheShqd3Muc2lnbmF0dXJlcykgfHwgIWp3cy5zaWduYXR1cmVzLmV2ZXJ5KGlzT2JqZWN0KSkge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFNpZ25hdHVyZXMgbWlzc2luZyBvciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBmb3IgKGNvbnN0IHNpZ25hdHVyZSBvZiBqd3Muc2lnbmF0dXJlcykge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgcmV0dXJuIGF3YWl0IGZsYXR0ZW5lZFZlcmlmeSh7XG4gICAgICAgICAgICAgICAgaGVhZGVyOiBzaWduYXR1cmUuaGVhZGVyLFxuICAgICAgICAgICAgICAgIHBheWxvYWQ6IGp3cy5wYXlsb2FkLFxuICAgICAgICAgICAgICAgIHByb3RlY3RlZDogc2lnbmF0dXJlLnByb3RlY3RlZCxcbiAgICAgICAgICAgICAgICBzaWduYXR1cmU6IHNpZ25hdHVyZS5zaWduYXR1cmUsXG4gICAgICAgICAgICB9LCBrZXksIG9wdGlvbnMpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIHtcbiAgICAgICAgfVxuICAgIH1cbiAgICB0aHJvdyBuZXcgSldTU2lnbmF0dXJlVmVyaWZpY2F0aW9uRmFpbGVkKCk7XG59XG4iLCJpbXBvcnQgeyBGbGF0dGVuZWRFbmNyeXB0IH0gZnJvbSAnLi4vZmxhdHRlbmVkL2VuY3J5cHQuanMnO1xuZXhwb3J0IGNsYXNzIENvbXBhY3RFbmNyeXB0IHtcbiAgICBjb25zdHJ1Y3RvcihwbGFpbnRleHQpIHtcbiAgICAgICAgdGhpcy5fZmxhdHRlbmVkID0gbmV3IEZsYXR0ZW5lZEVuY3J5cHQocGxhaW50ZXh0KTtcbiAgICB9XG4gICAgc2V0Q29udGVudEVuY3J5cHRpb25LZXkoY2VrKSB7XG4gICAgICAgIHRoaXMuX2ZsYXR0ZW5lZC5zZXRDb250ZW50RW5jcnlwdGlvbktleShjZWspO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0SW5pdGlhbGl6YXRpb25WZWN0b3IoaXYpIHtcbiAgICAgICAgdGhpcy5fZmxhdHRlbmVkLnNldEluaXRpYWxpemF0aW9uVmVjdG9yKGl2KTtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldFByb3RlY3RlZEhlYWRlcihwcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgdGhpcy5fZmxhdHRlbmVkLnNldFByb3RlY3RlZEhlYWRlcihwcm90ZWN0ZWRIZWFkZXIpO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0S2V5TWFuYWdlbWVudFBhcmFtZXRlcnMocGFyYW1ldGVycykge1xuICAgICAgICB0aGlzLl9mbGF0dGVuZWQuc2V0S2V5TWFuYWdlbWVudFBhcmFtZXRlcnMocGFyYW1ldGVycyk7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBhc3luYyBlbmNyeXB0KGtleSwgb3B0aW9ucykge1xuICAgICAgICBjb25zdCBqd2UgPSBhd2FpdCB0aGlzLl9mbGF0dGVuZWQuZW5jcnlwdChrZXksIG9wdGlvbnMpO1xuICAgICAgICByZXR1cm4gW2p3ZS5wcm90ZWN0ZWQsIGp3ZS5lbmNyeXB0ZWRfa2V5LCBqd2UuaXYsIGp3ZS5jaXBoZXJ0ZXh0LCBqd2UudGFnXS5qb2luKCcuJyk7XG4gICAgfVxufVxuIiwiaW1wb3J0IHN1YnRsZUFsZ29yaXRobSBmcm9tICcuL3N1YnRsZV9kc2EuanMnO1xuaW1wb3J0IGNyeXB0byBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgY2hlY2tLZXlMZW5ndGggZnJvbSAnLi9jaGVja19rZXlfbGVuZ3RoLmpzJztcbmltcG9ydCBnZXRTaWduS2V5IGZyb20gJy4vZ2V0X3NpZ25fdmVyaWZ5X2tleS5qcyc7XG5jb25zdCBzaWduID0gYXN5bmMgKGFsZywga2V5LCBkYXRhKSA9PiB7XG4gICAgY29uc3QgY3J5cHRvS2V5ID0gYXdhaXQgZ2V0U2lnbktleShhbGcsIGtleSwgJ3NpZ24nKTtcbiAgICBjaGVja0tleUxlbmd0aChhbGcsIGNyeXB0b0tleSk7XG4gICAgY29uc3Qgc2lnbmF0dXJlID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5zaWduKHN1YnRsZUFsZ29yaXRobShhbGcsIGNyeXB0b0tleS5hbGdvcml0aG0pLCBjcnlwdG9LZXksIGRhdGEpO1xuICAgIHJldHVybiBuZXcgVWludDhBcnJheShzaWduYXR1cmUpO1xufTtcbmV4cG9ydCBkZWZhdWx0IHNpZ247XG4iLCJpbXBvcnQgeyBlbmNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi4vLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHNpZ24gZnJvbSAnLi4vLi4vcnVudGltZS9zaWduLmpzJztcbmltcG9ydCBpc0Rpc2pvaW50IGZyb20gJy4uLy4uL2xpYi9pc19kaXNqb2ludC5qcyc7XG5pbXBvcnQgeyBKV1NJbnZhbGlkIH0gZnJvbSAnLi4vLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHsgZW5jb2RlciwgZGVjb2RlciwgY29uY2F0IH0gZnJvbSAnLi4vLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgY2hlY2tLZXlUeXBlIGZyb20gJy4uLy4uL2xpYi9jaGVja19rZXlfdHlwZS5qcyc7XG5pbXBvcnQgdmFsaWRhdGVDcml0IGZyb20gJy4uLy4uL2xpYi92YWxpZGF0ZV9jcml0LmpzJztcbmV4cG9ydCBjbGFzcyBGbGF0dGVuZWRTaWduIHtcbiAgICBjb25zdHJ1Y3RvcihwYXlsb2FkKSB7XG4gICAgICAgIGlmICghKHBheWxvYWQgaW5zdGFuY2VvZiBVaW50OEFycmF5KSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcigncGF5bG9hZCBtdXN0IGJlIGFuIGluc3RhbmNlIG9mIFVpbnQ4QXJyYXknKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9wYXlsb2FkID0gcGF5bG9hZDtcbiAgICB9XG4gICAgc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy5fcHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRQcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9wcm90ZWN0ZWRIZWFkZXIgPSBwcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRVbnByb3RlY3RlZEhlYWRlcih1bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFVucHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIgPSB1bnByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIGFzeW5jIHNpZ24oa2V5LCBvcHRpb25zKSB7XG4gICAgICAgIGlmICghdGhpcy5fcHJvdGVjdGVkSGVhZGVyICYmICF0aGlzLl91bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ2VpdGhlciBzZXRQcm90ZWN0ZWRIZWFkZXIgb3Igc2V0VW5wcm90ZWN0ZWRIZWFkZXIgbXVzdCBiZSBjYWxsZWQgYmVmb3JlICNzaWduKCknKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIWlzRGlzam9pbnQodGhpcy5fcHJvdGVjdGVkSGVhZGVyLCB0aGlzLl91bnByb3RlY3RlZEhlYWRlcikpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgUHJvdGVjdGVkIGFuZCBKV1MgVW5wcm90ZWN0ZWQgSGVhZGVyIFBhcmFtZXRlciBuYW1lcyBtdXN0IGJlIGRpc2pvaW50Jyk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3Qgam9zZUhlYWRlciA9IHtcbiAgICAgICAgICAgIC4uLnRoaXMuX3Byb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgIC4uLnRoaXMuX3VucHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICB9O1xuICAgICAgICBjb25zdCBleHRlbnNpb25zID0gdmFsaWRhdGVDcml0KEpXU0ludmFsaWQsIG5ldyBNYXAoW1snYjY0JywgdHJ1ZV1dKSwgb3B0aW9ucz8uY3JpdCwgdGhpcy5fcHJvdGVjdGVkSGVhZGVyLCBqb3NlSGVhZGVyKTtcbiAgICAgICAgbGV0IGI2NCA9IHRydWU7XG4gICAgICAgIGlmIChleHRlbnNpb25zLmhhcygnYjY0JykpIHtcbiAgICAgICAgICAgIGI2NCA9IHRoaXMuX3Byb3RlY3RlZEhlYWRlci5iNjQ7XG4gICAgICAgICAgICBpZiAodHlwZW9mIGI2NCAhPT0gJ2Jvb2xlYW4nKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ1RoZSBcImI2NFwiIChiYXNlNjR1cmwtZW5jb2RlIHBheWxvYWQpIEhlYWRlciBQYXJhbWV0ZXIgbXVzdCBiZSBhIGJvb2xlYW4nKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBjb25zdCB7IGFsZyB9ID0gam9zZUhlYWRlcjtcbiAgICAgICAgaWYgKHR5cGVvZiBhbGcgIT09ICdzdHJpbmcnIHx8ICFhbGcpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgXCJhbGdcIiAoQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIG1pc3Npbmcgb3IgaW52YWxpZCcpO1xuICAgICAgICB9XG4gICAgICAgIGNoZWNrS2V5VHlwZShhbGcsIGtleSwgJ3NpZ24nKTtcbiAgICAgICAgbGV0IHBheWxvYWQgPSB0aGlzLl9wYXlsb2FkO1xuICAgICAgICBpZiAoYjY0KSB7XG4gICAgICAgICAgICBwYXlsb2FkID0gZW5jb2Rlci5lbmNvZGUoYmFzZTY0dXJsKHBheWxvYWQpKTtcbiAgICAgICAgfVxuICAgICAgICBsZXQgcHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICBpZiAodGhpcy5fcHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICBwcm90ZWN0ZWRIZWFkZXIgPSBlbmNvZGVyLmVuY29kZShiYXNlNjR1cmwoSlNPTi5zdHJpbmdpZnkodGhpcy5fcHJvdGVjdGVkSGVhZGVyKSkpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgcHJvdGVjdGVkSGVhZGVyID0gZW5jb2Rlci5lbmNvZGUoJycpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IGRhdGEgPSBjb25jYXQocHJvdGVjdGVkSGVhZGVyLCBlbmNvZGVyLmVuY29kZSgnLicpLCBwYXlsb2FkKTtcbiAgICAgICAgY29uc3Qgc2lnbmF0dXJlID0gYXdhaXQgc2lnbihhbGcsIGtleSwgZGF0YSk7XG4gICAgICAgIGNvbnN0IGp3cyA9IHtcbiAgICAgICAgICAgIHNpZ25hdHVyZTogYmFzZTY0dXJsKHNpZ25hdHVyZSksXG4gICAgICAgICAgICBwYXlsb2FkOiAnJyxcbiAgICAgICAgfTtcbiAgICAgICAgaWYgKGI2NCkge1xuICAgICAgICAgICAgandzLnBheWxvYWQgPSBkZWNvZGVyLmRlY29kZShwYXlsb2FkKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIGp3cy5oZWFkZXIgPSB0aGlzLl91bnByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5fcHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICBqd3MucHJvdGVjdGVkID0gZGVjb2Rlci5kZWNvZGUocHJvdGVjdGVkSGVhZGVyKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gandzO1xuICAgIH1cbn1cbiIsImltcG9ydCB7IEZsYXR0ZW5lZFNpZ24gfSBmcm9tICcuLi9mbGF0dGVuZWQvc2lnbi5qcyc7XG5leHBvcnQgY2xhc3MgQ29tcGFjdFNpZ24ge1xuICAgIGNvbnN0cnVjdG9yKHBheWxvYWQpIHtcbiAgICAgICAgdGhpcy5fZmxhdHRlbmVkID0gbmV3IEZsYXR0ZW5lZFNpZ24ocGF5bG9hZCk7XG4gICAgfVxuICAgIHNldFByb3RlY3RlZEhlYWRlcihwcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgdGhpcy5fZmxhdHRlbmVkLnNldFByb3RlY3RlZEhlYWRlcihwcm90ZWN0ZWRIZWFkZXIpO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgYXN5bmMgc2lnbihrZXksIG9wdGlvbnMpIHtcbiAgICAgICAgY29uc3QgandzID0gYXdhaXQgdGhpcy5fZmxhdHRlbmVkLnNpZ24oa2V5LCBvcHRpb25zKTtcbiAgICAgICAgaWYgKGp3cy5wYXlsb2FkID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3VzZSB0aGUgZmxhdHRlbmVkIG1vZHVsZSBmb3IgY3JlYXRpbmcgSldTIHdpdGggYjY0OiBmYWxzZScpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBgJHtqd3MucHJvdGVjdGVkfS4ke2p3cy5wYXlsb2FkfS4ke2p3cy5zaWduYXR1cmV9YDtcbiAgICB9XG59XG4iLCJpbXBvcnQgeyBGbGF0dGVuZWRTaWduIH0gZnJvbSAnLi4vZmxhdHRlbmVkL3NpZ24uanMnO1xuaW1wb3J0IHsgSldTSW52YWxpZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmNsYXNzIEluZGl2aWR1YWxTaWduYXR1cmUge1xuICAgIGNvbnN0cnVjdG9yKHNpZywga2V5LCBvcHRpb25zKSB7XG4gICAgICAgIHRoaXMucGFyZW50ID0gc2lnO1xuICAgICAgICB0aGlzLmtleSA9IGtleTtcbiAgICAgICAgdGhpcy5vcHRpb25zID0gb3B0aW9ucztcbiAgICB9XG4gICAgc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMucHJvdGVjdGVkSGVhZGVyID0gcHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0VW5wcm90ZWN0ZWRIZWFkZXIodW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMudW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFVucHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy51bnByb3RlY3RlZEhlYWRlciA9IHVucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgYWRkU2lnbmF0dXJlKC4uLmFyZ3MpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGFyZW50LmFkZFNpZ25hdHVyZSguLi5hcmdzKTtcbiAgICB9XG4gICAgc2lnbiguLi5hcmdzKSB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhcmVudC5zaWduKC4uLmFyZ3MpO1xuICAgIH1cbiAgICBkb25lKCkge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXJlbnQ7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEdlbmVyYWxTaWduIHtcbiAgICBjb25zdHJ1Y3RvcihwYXlsb2FkKSB7XG4gICAgICAgIHRoaXMuX3NpZ25hdHVyZXMgPSBbXTtcbiAgICAgICAgdGhpcy5fcGF5bG9hZCA9IHBheWxvYWQ7XG4gICAgfVxuICAgIGFkZFNpZ25hdHVyZShrZXksIG9wdGlvbnMpIHtcbiAgICAgICAgY29uc3Qgc2lnbmF0dXJlID0gbmV3IEluZGl2aWR1YWxTaWduYXR1cmUodGhpcywga2V5LCBvcHRpb25zKTtcbiAgICAgICAgdGhpcy5fc2lnbmF0dXJlcy5wdXNoKHNpZ25hdHVyZSk7XG4gICAgICAgIHJldHVybiBzaWduYXR1cmU7XG4gICAgfVxuICAgIGFzeW5jIHNpZ24oKSB7XG4gICAgICAgIGlmICghdGhpcy5fc2lnbmF0dXJlcy5sZW5ndGgpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdhdCBsZWFzdCBvbmUgc2lnbmF0dXJlIG11c3QgYmUgYWRkZWQnKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBqd3MgPSB7XG4gICAgICAgICAgICBzaWduYXR1cmVzOiBbXSxcbiAgICAgICAgICAgIHBheWxvYWQ6ICcnLFxuICAgICAgICB9O1xuICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHRoaXMuX3NpZ25hdHVyZXMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIGNvbnN0IHNpZ25hdHVyZSA9IHRoaXMuX3NpZ25hdHVyZXNbaV07XG4gICAgICAgICAgICBjb25zdCBmbGF0dGVuZWQgPSBuZXcgRmxhdHRlbmVkU2lnbih0aGlzLl9wYXlsb2FkKTtcbiAgICAgICAgICAgIGZsYXR0ZW5lZC5zZXRQcm90ZWN0ZWRIZWFkZXIoc2lnbmF0dXJlLnByb3RlY3RlZEhlYWRlcik7XG4gICAgICAgICAgICBmbGF0dGVuZWQuc2V0VW5wcm90ZWN0ZWRIZWFkZXIoc2lnbmF0dXJlLnVucHJvdGVjdGVkSGVhZGVyKTtcbiAgICAgICAgICAgIGNvbnN0IHsgcGF5bG9hZCwgLi4ucmVzdCB9ID0gYXdhaXQgZmxhdHRlbmVkLnNpZ24oc2lnbmF0dXJlLmtleSwgc2lnbmF0dXJlLm9wdGlvbnMpO1xuICAgICAgICAgICAgaWYgKGkgPT09IDApIHtcbiAgICAgICAgICAgICAgICBqd3MucGF5bG9hZCA9IHBheWxvYWQ7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIGlmIChqd3MucGF5bG9hZCAhPT0gcGF5bG9hZCkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdpbmNvbnNpc3RlbnQgdXNlIG9mIEpXUyBVbmVuY29kZWQgUGF5bG9hZCAoUkZDNzc5NyknKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGp3cy5zaWduYXR1cmVzLnB1c2gocmVzdCk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGp3cztcbiAgICB9XG59XG4iLCJpbXBvcnQgKiBhcyBiYXNlNjR1cmwgZnJvbSAnLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuZXhwb3J0IGNvbnN0IGVuY29kZSA9IGJhc2U2NHVybC5lbmNvZGU7XG5leHBvcnQgY29uc3QgZGVjb2RlID0gYmFzZTY0dXJsLmRlY29kZTtcbiIsImltcG9ydCB7IGRlY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgeyBkZWNvZGVyIH0gZnJvbSAnLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgaXNPYmplY3QgZnJvbSAnLi4vbGliL2lzX29iamVjdC5qcyc7XG5leHBvcnQgZnVuY3Rpb24gZGVjb2RlUHJvdGVjdGVkSGVhZGVyKHRva2VuKSB7XG4gICAgbGV0IHByb3RlY3RlZEI2NHU7XG4gICAgaWYgKHR5cGVvZiB0b2tlbiA9PT0gJ3N0cmluZycpIHtcbiAgICAgICAgY29uc3QgcGFydHMgPSB0b2tlbi5zcGxpdCgnLicpO1xuICAgICAgICBpZiAocGFydHMubGVuZ3RoID09PSAzIHx8IHBhcnRzLmxlbmd0aCA9PT0gNSkge1xuICAgICAgICAgICAgO1xuICAgICAgICAgICAgW3Byb3RlY3RlZEI2NHVdID0gcGFydHM7XG4gICAgICAgIH1cbiAgICB9XG4gICAgZWxzZSBpZiAodHlwZW9mIHRva2VuID09PSAnb2JqZWN0JyAmJiB0b2tlbikge1xuICAgICAgICBpZiAoJ3Byb3RlY3RlZCcgaW4gdG9rZW4pIHtcbiAgICAgICAgICAgIHByb3RlY3RlZEI2NHUgPSB0b2tlbi5wcm90ZWN0ZWQ7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdUb2tlbiBkb2VzIG5vdCBjb250YWluIGEgUHJvdGVjdGVkIEhlYWRlcicpO1xuICAgICAgICB9XG4gICAgfVxuICAgIHRyeSB7XG4gICAgICAgIGlmICh0eXBlb2YgcHJvdGVjdGVkQjY0dSAhPT0gJ3N0cmluZycgfHwgIXByb3RlY3RlZEI2NHUpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcigpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHJlc3VsdCA9IEpTT04ucGFyc2UoZGVjb2Rlci5kZWNvZGUoYmFzZTY0dXJsKHByb3RlY3RlZEI2NHUpKSk7XG4gICAgICAgIGlmICghaXNPYmplY3QocmVzdWx0KSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICB9XG4gICAgY2F0Y2gge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdJbnZhbGlkIFRva2VuIG9yIFByb3RlY3RlZCBIZWFkZXIgZm9ybWF0dGluZycpO1xuICAgIH1cbn1cbiIsImltcG9ydCBjcnlwdG8gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCByYW5kb20gZnJvbSAnLi9yYW5kb20uanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdlbmVyYXRlU2VjcmV0KGFsZywgb3B0aW9ucykge1xuICAgIGxldCBsZW5ndGg7XG4gICAgbGV0IGFsZ29yaXRobTtcbiAgICBsZXQga2V5VXNhZ2VzO1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ0hTMjU2JzpcbiAgICAgICAgY2FzZSAnSFMzODQnOlxuICAgICAgICBjYXNlICdIUzUxMic6XG4gICAgICAgICAgICBsZW5ndGggPSBwYXJzZUludChhbGcuc2xpY2UoLTMpLCAxMCk7XG4gICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdITUFDJywgaGFzaDogYFNIQS0ke2xlbmd0aH1gLCBsZW5ndGggfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnc2lnbicsICd2ZXJpZnknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdBMTI4Q0JDLUhTMjU2JzpcbiAgICAgICAgY2FzZSAnQTE5MkNCQy1IUzM4NCc6XG4gICAgICAgIGNhc2UgJ0EyNTZDQkMtSFM1MTInOlxuICAgICAgICAgICAgbGVuZ3RoID0gcGFyc2VJbnQoYWxnLnNsaWNlKC0zKSwgMTApO1xuICAgICAgICAgICAgcmV0dXJuIHJhbmRvbShuZXcgVWludDhBcnJheShsZW5ndGggPj4gMykpO1xuICAgICAgICBjYXNlICdBMTI4S1cnOlxuICAgICAgICBjYXNlICdBMTkyS1cnOlxuICAgICAgICBjYXNlICdBMjU2S1cnOlxuICAgICAgICAgICAgbGVuZ3RoID0gcGFyc2VJbnQoYWxnLnNsaWNlKDEsIDQpLCAxMCk7XG4gICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdBRVMtS1cnLCBsZW5ndGggfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnd3JhcEtleScsICd1bndyYXBLZXknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdBMTI4R0NNS1cnOlxuICAgICAgICBjYXNlICdBMTkyR0NNS1cnOlxuICAgICAgICBjYXNlICdBMjU2R0NNS1cnOlxuICAgICAgICBjYXNlICdBMTI4R0NNJzpcbiAgICAgICAgY2FzZSAnQTE5MkdDTSc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ00nOlxuICAgICAgICAgICAgbGVuZ3RoID0gcGFyc2VJbnQoYWxnLnNsaWNlKDEsIDQpLCAxMCk7XG4gICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdBRVMtR0NNJywgbGVuZ3RoIH07XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ2VuY3J5cHQnLCAnZGVjcnlwdCddO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBKV0sgXCJhbGdcIiAoQWxnb3JpdGhtKSBQYXJhbWV0ZXIgdmFsdWUnKTtcbiAgICB9XG4gICAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuZ2VuZXJhdGVLZXkoYWxnb3JpdGhtLCBvcHRpb25zPy5leHRyYWN0YWJsZSA/PyBmYWxzZSwga2V5VXNhZ2VzKTtcbn1cbmZ1bmN0aW9uIGdldE1vZHVsdXNMZW5ndGhPcHRpb24ob3B0aW9ucykge1xuICAgIGNvbnN0IG1vZHVsdXNMZW5ndGggPSBvcHRpb25zPy5tb2R1bHVzTGVuZ3RoID8/IDIwNDg7XG4gICAgaWYgKHR5cGVvZiBtb2R1bHVzTGVuZ3RoICE9PSAnbnVtYmVyJyB8fCBtb2R1bHVzTGVuZ3RoIDwgMjA0OCkge1xuICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBtb2R1bHVzTGVuZ3RoIG9wdGlvbiBwcm92aWRlZCwgMjA0OCBiaXRzIG9yIGxhcmdlciBrZXlzIG11c3QgYmUgdXNlZCcpO1xuICAgIH1cbiAgICByZXR1cm4gbW9kdWx1c0xlbmd0aDtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZUtleVBhaXIoYWxnLCBvcHRpb25zKSB7XG4gICAgbGV0IGFsZ29yaXRobTtcbiAgICBsZXQga2V5VXNhZ2VzO1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ1BTMjU2JzpcbiAgICAgICAgY2FzZSAnUFMzODQnOlxuICAgICAgICBjYXNlICdQUzUxMic6XG4gICAgICAgICAgICBhbGdvcml0aG0gPSB7XG4gICAgICAgICAgICAgICAgbmFtZTogJ1JTQS1QU1MnLFxuICAgICAgICAgICAgICAgIGhhc2g6IGBTSEEtJHthbGcuc2xpY2UoLTMpfWAsXG4gICAgICAgICAgICAgICAgcHVibGljRXhwb25lbnQ6IG5ldyBVaW50OEFycmF5KFsweDAxLCAweDAwLCAweDAxXSksXG4gICAgICAgICAgICAgICAgbW9kdWx1c0xlbmd0aDogZ2V0TW9kdWx1c0xlbmd0aE9wdGlvbihvcHRpb25zKSxcbiAgICAgICAgICAgIH07XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3NpZ24nLCAndmVyaWZ5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnUlMyNTYnOlxuICAgICAgICBjYXNlICdSUzM4NCc6XG4gICAgICAgIGNhc2UgJ1JTNTEyJzpcbiAgICAgICAgICAgIGFsZ29yaXRobSA9IHtcbiAgICAgICAgICAgICAgICBuYW1lOiAnUlNBU1NBLVBLQ1MxLXYxXzUnLFxuICAgICAgICAgICAgICAgIGhhc2g6IGBTSEEtJHthbGcuc2xpY2UoLTMpfWAsXG4gICAgICAgICAgICAgICAgcHVibGljRXhwb25lbnQ6IG5ldyBVaW50OEFycmF5KFsweDAxLCAweDAwLCAweDAxXSksXG4gICAgICAgICAgICAgICAgbW9kdWx1c0xlbmd0aDogZ2V0TW9kdWx1c0xlbmd0aE9wdGlvbihvcHRpb25zKSxcbiAgICAgICAgICAgIH07XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3NpZ24nLCAndmVyaWZ5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0yNTYnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0zODQnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC01MTInOlxuICAgICAgICAgICAgYWxnb3JpdGhtID0ge1xuICAgICAgICAgICAgICAgIG5hbWU6ICdSU0EtT0FFUCcsXG4gICAgICAgICAgICAgICAgaGFzaDogYFNIQS0ke3BhcnNlSW50KGFsZy5zbGljZSgtMyksIDEwKSB8fCAxfWAsXG4gICAgICAgICAgICAgICAgcHVibGljRXhwb25lbnQ6IG5ldyBVaW50OEFycmF5KFsweDAxLCAweDAwLCAweDAxXSksXG4gICAgICAgICAgICAgICAgbW9kdWx1c0xlbmd0aDogZ2V0TW9kdWx1c0xlbmd0aE9wdGlvbihvcHRpb25zKSxcbiAgICAgICAgICAgIH07XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ2RlY3J5cHQnLCAndW53cmFwS2V5JywgJ2VuY3J5cHQnLCAnd3JhcEtleSddO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ0VTMjU2JzpcbiAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0VDRFNBJywgbmFtZWRDdXJ2ZTogJ1AtMjU2JyB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydzaWduJywgJ3ZlcmlmeSddO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ0VTMzg0JzpcbiAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0VDRFNBJywgbmFtZWRDdXJ2ZTogJ1AtMzg0JyB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydzaWduJywgJ3ZlcmlmeSddO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ0VTNTEyJzpcbiAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0VDRFNBJywgbmFtZWRDdXJ2ZTogJ1AtNTIxJyB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydzaWduJywgJ3ZlcmlmeSddO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ0VkRFNBJzoge1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydzaWduJywgJ3ZlcmlmeSddO1xuICAgICAgICAgICAgY29uc3QgY3J2ID0gb3B0aW9ucz8uY3J2ID8/ICdFZDI1NTE5JztcbiAgICAgICAgICAgIHN3aXRjaCAoY3J2KSB7XG4gICAgICAgICAgICAgICAgY2FzZSAnRWQyNTUxOSc6XG4gICAgICAgICAgICAgICAgY2FzZSAnRWQ0NDgnOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6IGNydiB9O1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBjcnYgb3B0aW9uIHByb3ZpZGVkJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdFQ0RILUVTJzpcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMTI4S1cnOlxuICAgICAgICBjYXNlICdFQ0RILUVTK0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTI1NktXJzoge1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydkZXJpdmVLZXknLCAnZGVyaXZlQml0cyddO1xuICAgICAgICAgICAgY29uc3QgY3J2ID0gb3B0aW9ucz8uY3J2ID8/ICdQLTI1Nic7XG4gICAgICAgICAgICBzd2l0Y2ggKGNydikge1xuICAgICAgICAgICAgICAgIGNhc2UgJ1AtMjU2JzpcbiAgICAgICAgICAgICAgICBjYXNlICdQLTM4NCc6XG4gICAgICAgICAgICAgICAgY2FzZSAnUC01MjEnOiB7XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0VDREgnLCBuYW1lZEN1cnZlOiBjcnYgfTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhc2UgJ1gyNTUxOSc6XG4gICAgICAgICAgICAgICAgY2FzZSAnWDQ0OCc6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogY3J2IH07XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIGNydiBvcHRpb24gcHJvdmlkZWQsIHN1cHBvcnRlZCB2YWx1ZXMgYXJlIFAtMjU2LCBQLTM4NCwgUC01MjEsIFgyNTUxOSwgYW5kIFg0NDgnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBKV0sgXCJhbGdcIiAoQWxnb3JpdGhtKSBQYXJhbWV0ZXIgdmFsdWUnKTtcbiAgICB9XG4gICAgcmV0dXJuIChjcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KGFsZ29yaXRobSwgb3B0aW9ucz8uZXh0cmFjdGFibGUgPz8gZmFsc2UsIGtleVVzYWdlcykpO1xufVxuIiwiaW1wb3J0IHsgZ2VuZXJhdGVLZXlQYWlyIGFzIGdlbmVyYXRlIH0gZnJvbSAnLi4vcnVudGltZS9nZW5lcmF0ZS5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhdGVLZXlQYWlyKGFsZywgb3B0aW9ucykge1xuICAgIHJldHVybiBnZW5lcmF0ZShhbGcsIG9wdGlvbnMpO1xufVxuIiwiaW1wb3J0IHsgZ2VuZXJhdGVTZWNyZXQgYXMgZ2VuZXJhdGUgfSBmcm9tICcuLi9ydW50aW1lL2dlbmVyYXRlLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZVNlY3JldChhbGcsIG9wdGlvbnMpIHtcbiAgICByZXR1cm4gZ2VuZXJhdGUoYWxnLCBvcHRpb25zKTtcbn1cbiIsIi8vIE9uZSBjb25zaXN0ZW50IGFsZ29yaXRobSBmb3IgZWFjaCBmYW1pbHkuXG4vLyBodHRwczovL2RhdGF0cmFja2VyLmlldGYub3JnL2RvYy9odG1sL3JmYzc1MThcblxuZXhwb3J0IGNvbnN0IHNpZ25pbmdOYW1lID0gJ0VDRFNBJztcbmV4cG9ydCBjb25zdCBzaWduaW5nQ3VydmUgPSAnUC0zODQnO1xuZXhwb3J0IGNvbnN0IHNpZ25pbmdBbGdvcml0aG0gPSAnRVMzODQnO1xuXG5leHBvcnQgY29uc3QgZW5jcnlwdGluZ05hbWUgPSAnUlNBLU9BRVAnO1xuZXhwb3J0IGNvbnN0IGhhc2hMZW5ndGggPSAyNTY7XG5leHBvcnQgY29uc3QgaGFzaE5hbWUgPSAnU0hBLTI1Nic7XG5leHBvcnQgY29uc3QgbW9kdWx1c0xlbmd0aCA9IDQwOTY7IC8vIHBhbnZhIEpPU0UgbGlicmFyeSBkZWZhdWx0IGlzIDIwNDhcbmV4cG9ydCBjb25zdCBlbmNyeXB0aW5nQWxnb3JpdGhtID0gJ1JTQS1PQUVQLTI1Nic7XG5cbmV4cG9ydCBjb25zdCBzeW1tZXRyaWNOYW1lID0gJ0FFUy1HQ00nO1xuZXhwb3J0IGNvbnN0IHN5bW1ldHJpY0FsZ29yaXRobSA9ICdBMjU2R0NNJztcbmV4cG9ydCBjb25zdCBzeW1tZXRyaWNXcmFwID0gJ0EyNTZHQ01LVyc7XG5leHBvcnQgY29uc3Qgc2VjcmV0QWxnb3JpdGhtID0gJ1BCRVMyLUhTNTEyK0EyNTZLVyc7XG5cbmV4cG9ydCBjb25zdCBleHRyYWN0YWJsZSA9IHRydWU7ICAvLyBhbHdheXMgd3JhcHBlZFxuXG4iLCJpbXBvcnQge2V4dHJhY3RhYmxlLCBzaWduaW5nTmFtZSwgc2lnbmluZ0N1cnZlLCBzeW1tZXRyaWNOYW1lLCBoYXNoTGVuZ3RofSBmcm9tIFwiLi9hbGdvcml0aG1zLm1qc1wiO1xuXG5leHBvcnQgZnVuY3Rpb24gZGlnZXN0KGhhc2hOYW1lLCBidWZmZXIpIHtcbiAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuZGlnZXN0KGhhc2hOYW1lLCBidWZmZXIpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZXhwb3J0UmF3S2V5KGtleSkge1xuICByZXR1cm4gY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoJ3JhdycsIGtleSk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBpbXBvcnRSYXdLZXkoYXJyYXlCdWZmZXIpIHtcbiAgY29uc3QgYWxnb3JpdGhtID0ge25hbWU6IHNpZ25pbmdOYW1lLCBuYW1lZEN1cnZlOiBzaWduaW5nQ3VydmV9O1xuICByZXR1cm4gY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGFycmF5QnVmZmVyLCBhbGdvcml0aG0sIGV4dHJhY3RhYmxlLCBbJ3ZlcmlmeSddKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGltcG9ydFNlY3JldChieXRlQXJyYXkpIHtcbiAgY29uc3QgYWxnb3JpdGhtID0ge25hbWU6IHN5bW1ldHJpY05hbWUsIGxlbmd0aDogaGFzaExlbmd0aH07XG4gIHJldHVybiBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgYnl0ZUFycmF5LCBhbGdvcml0aG0sIHRydWUsIFsnZW5jcnlwdCcsICdkZWNyeXB0J10pXG59XG4iLCJpbXBvcnQgKiBhcyBKT1NFIGZyb20gXCJqb3NlXCI7XG5pbXBvcnQge2RpZ2VzdCwgZXhwb3J0UmF3S2V5LCBpbXBvcnRSYXdLZXksIGltcG9ydFNlY3JldH0gZnJvbSBcIiNyYXdcIjtcbmltcG9ydCB7ZXh0cmFjdGFibGUsIHNpZ25pbmdOYW1lLCBzaWduaW5nQ3VydmUsIHNpZ25pbmdBbGdvcml0aG0sIGVuY3J5cHRpbmdOYW1lLCBoYXNoTGVuZ3RoLCBoYXNoTmFtZSwgbW9kdWx1c0xlbmd0aCwgZW5jcnlwdGluZ0FsZ29yaXRobSwgc3ltbWV0cmljTmFtZSwgc3ltbWV0cmljQWxnb3JpdGhtfSBmcm9tIFwiLi9hbGdvcml0aG1zLm1qc1wiO1xuXG5jb25zdCBLcnlwdG8gPSB7XG4gIC8vIEFuIGluaGVyaXRhYmxlIHNpbmdsZXRvbiBmb3IgY29tcGFjdCBKT1NFIG9wZXJhdGlvbnMuXG4gIC8vIFNlZSBodHRwczovL2tpbHJveS1jb2RlLmdpdGh1Yi5pby9kaXN0cmlidXRlZC1zZWN1cml0eS9kb2NzL2ltcGxlbWVudGF0aW9uLmh0bWwjd3JhcHBpbmctc3VidGxla3J5cHRvXG4gIGRlY29kZVByb3RlY3RlZEhlYWRlcjogSk9TRS5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIsXG4gIGlzRW1wdHlKV1NQYXlsb2FkKGNvbXBhY3RKV1MpIHsgLy8gYXJnIGlzIGEgc3RyaW5nXG4gICAgcmV0dXJuICFjb21wYWN0SldTLnNwbGl0KCcuJylbMV07XG4gIH0sXG5cbiAgLy8gVGhlIGN0eSBjYW4gYmUgc3BlY2lmaWVkIGluIGVuY3J5cHQvc2lnbiwgYnV0IGRlZmF1bHRzIHRvIGEgZ29vZCBndWVzcy5cbiAgLy8gVGhlIGN0eSBjYW4gYmUgc3BlY2lmaWVkIGluIGRlY3J5cHQvdmVyaWZ5LCBidXQgZGVmYXVsdHMgdG8gd2hhdCBpcyBzcGVjaWZpZWQgaW4gdGhlIHByb3RlY3RlZCBoZWFkZXIuXG4gIGlucHV0QnVmZmVyKGRhdGEsIGhlYWRlcikgeyAvLyBBbnN3ZXJzIGEgYnVmZmVyIHZpZXcgb2YgZGF0YSBhbmQsIGlmIG5lY2Vzc2FyeSB0byBjb252ZXJ0LCBiYXNoZXMgY3R5IG9mIGhlYWRlci5cbiAgICBpZiAoQXJyYXlCdWZmZXIuaXNWaWV3KGRhdGEpICYmICFoZWFkZXIuY3R5KSByZXR1cm4gZGF0YTtcbiAgICBsZXQgZ2l2ZW5DdHkgPSBoZWFkZXIuY3R5IHx8ICcnO1xuICAgIGlmIChnaXZlbkN0eS5pbmNsdWRlcygndGV4dCcpIHx8ICgnc3RyaW5nJyA9PT0gdHlwZW9mIGRhdGEpKSB7XG4gICAgICBoZWFkZXIuY3R5ID0gZ2l2ZW5DdHkgfHwgJ3RleHQvcGxhaW4nO1xuICAgIH0gZWxzZSB7XG4gICAgICBoZWFkZXIuY3R5ID0gZ2l2ZW5DdHkgfHwgJ2pzb24nOyAvLyBKV1MgcmVjb21tZW5kcyBsZWF2aW5nIG9mZiB0aGUgbGVhZGluZyAnYXBwbGljYXRpb24vJy5cbiAgICAgIGRhdGEgPSBKU09OLnN0cmluZ2lmeShkYXRhKTsgLy8gTm90ZSB0aGF0IG5ldyBTdHJpbmcoXCJzb21ldGhpbmdcIikgd2lsbCBwYXNzIHRoaXMgd2F5LlxuICAgIH1cbiAgICByZXR1cm4gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKGRhdGEpO1xuICB9LFxuICByZWNvdmVyRGF0YUZyb21Db250ZW50VHlwZShyZXN1bHQsIHtjdHkgPSByZXN1bHQ/LnByb3RlY3RlZEhlYWRlcj8uY3R5fSA9IHt9KSB7XG4gICAgLy8gRXhhbWluZXMgcmVzdWx0Py5wcm90ZWN0ZWRIZWFkZXIgYW5kIGJhc2hlcyBpbiByZXN1bHQudGV4dCBvciByZXN1bHQuanNvbiBpZiBhcHByb3ByaWF0ZSwgcmV0dXJuaW5nIHJlc3VsdC5cbiAgICBpZiAocmVzdWx0ICYmICFPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocmVzdWx0LCAncGF5bG9hZCcpKSByZXN1bHQucGF5bG9hZCA9IHJlc3VsdC5wbGFpbnRleHQ7ICAvLyBiZWNhdXNlIEpPU0UgdXNlcyBwbGFpbnRleHQgZm9yIGRlY3J5cHQgYW5kIHBheWxvYWQgZm9yIHNpZ24uXG4gICAgaWYgKCFjdHkgfHwgIXJlc3VsdD8ucGF5bG9hZCkgcmV0dXJuIHJlc3VsdDsgLy8gZWl0aGVyIG5vIGN0eSBvciBubyByZXN1bHRcbiAgICByZXN1bHQudGV4dCA9IG5ldyBUZXh0RGVjb2RlcigpLmRlY29kZShyZXN1bHQucGF5bG9hZCk7XG4gICAgaWYgKGN0eS5pbmNsdWRlcygnanNvbicpKSByZXN1bHQuanNvbiA9IEpTT04ucGFyc2UocmVzdWx0LnRleHQpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH0sXG5cbiAgLy8gU2lnbi9WZXJpZnlcbiAgZ2VuZXJhdGVTaWduaW5nS2V5KCkgeyAvLyBQcm9taXNlIHtwcml2YXRlS2V5LCBwdWJsaWNLZXl9IGluIG91ciBzdGFuZGFyZCBzaWduaW5nIGFsZ29yaXRobS5cbiAgICByZXR1cm4gSk9TRS5nZW5lcmF0ZUtleVBhaXIoc2lnbmluZ0FsZ29yaXRobSwge2V4dHJhY3RhYmxlfSk7XG4gIH0sXG4gIGFzeW5jIHNpZ24ocHJpdmF0ZUtleSwgbWVzc2FnZSwgaGVhZGVycyA9IHt9KSB7IC8vIFByb21pc2UgYSBjb21wYWN0IEpXUyBzdHJpbmcuIEFjY2VwdHMgaGVhZGVycyB0byBiZSBwcm90ZWN0ZWQuXG4gICAgbGV0IGhlYWRlciA9IHthbGc6IHNpZ25pbmdBbGdvcml0aG0sIC4uLmhlYWRlcnN9LFxuICAgICAgICBpbnB1dEJ1ZmZlciA9IHRoaXMuaW5wdXRCdWZmZXIobWVzc2FnZSwgaGVhZGVyKTtcbiAgICByZXR1cm4gbmV3IEpPU0UuQ29tcGFjdFNpZ24oaW5wdXRCdWZmZXIpLnNldFByb3RlY3RlZEhlYWRlcihoZWFkZXIpLnNpZ24ocHJpdmF0ZUtleSk7XG4gIH0sXG4gIGFzeW5jIHZlcmlmeShwdWJsaWNLZXksIHNpZ25hdHVyZSwgb3B0aW9ucykgeyAvLyBQcm9taXNlIHtwYXlsb2FkLCB0ZXh0LCBqc29ufSwgd2hlcmUgdGV4dCBhbmQganNvbiBhcmUgb25seSBkZWZpbmVkIHdoZW4gYXBwcm9wcmlhdGUuXG4gICAgbGV0IHJlc3VsdCA9IGF3YWl0IEpPU0UuY29tcGFjdFZlcmlmeShzaWduYXR1cmUsIHB1YmxpY0tleSkuY2F0Y2goKCkgPT4gdW5kZWZpbmVkKTtcbiAgICByZXR1cm4gdGhpcy5yZWNvdmVyRGF0YUZyb21Db250ZW50VHlwZShyZXN1bHQsIG9wdGlvbnMpO1xuICB9LFxuXG4gIC8vIEVuY3J5cHQvRGVjcnlwdFxuICBnZW5lcmF0ZUVuY3J5cHRpbmdLZXkoKSB7IC8vIFByb21pc2Uge3ByaXZhdGVLZXksIHB1YmxpY0tleX0gaW4gb3VyIHN0YW5kYXJkIGVuY3J5cHRpb24gYWxnb3JpdGhtLlxuICAgIHJldHVybiBKT1NFLmdlbmVyYXRlS2V5UGFpcihlbmNyeXB0aW5nQWxnb3JpdGhtLCB7ZXh0cmFjdGFibGUsIG1vZHVsdXNMZW5ndGh9KTtcbiAgfSxcbiAgYXN5bmMgZW5jcnlwdChrZXksIG1lc3NhZ2UsIGhlYWRlcnMgPSB7fSkgeyAvLyBQcm9taXNlIGEgY29tcGFjdCBKV0Ugc3RyaW5nLiBBY2NlcHRzIGhlYWRlcnMgdG8gYmUgcHJvdGVjdGVkLlxuICAgIGxldCBhbGcgPSB0aGlzLmlzU3ltbWV0cmljKGtleSkgPyAnZGlyJyA6IGVuY3J5cHRpbmdBbGdvcml0aG0sXG4gICAgICAgIGhlYWRlciA9IHthbGcsIGVuYzogc3ltbWV0cmljQWxnb3JpdGhtLCAuLi5oZWFkZXJzfSxcbiAgICAgICAgaW5wdXRCdWZmZXIgPSB0aGlzLmlucHV0QnVmZmVyKG1lc3NhZ2UsIGhlYWRlciksXG4gICAgICAgIHNlY3JldCA9IHRoaXMua2V5U2VjcmV0KGtleSk7XG4gICAgcmV0dXJuICBuZXcgSk9TRS5Db21wYWN0RW5jcnlwdChpbnB1dEJ1ZmZlcikuc2V0UHJvdGVjdGVkSGVhZGVyKGhlYWRlcikuZW5jcnlwdChzZWNyZXQpO1xuICB9LFxuICBhc3luYyBkZWNyeXB0KGtleSwgZW5jcnlwdGVkLCBvcHRpb25zKSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259LCB3aGVyZSB0ZXh0IGFuZCBqc29uIGFyZSBvbmx5IGRlZmluZWQgd2hlbiBhcHByb3ByaWF0ZS5cbiAgICBsZXQgc2VjcmV0ID0gdGhpcy5rZXlTZWNyZXQoa2V5KSxcbiAgICAgICAgcmVzdWx0ID0gYXdhaXQgSk9TRS5jb21wYWN0RGVjcnlwdChlbmNyeXB0ZWQsIHNlY3JldCk7XG4gICAgdGhpcy5yZWNvdmVyRGF0YUZyb21Db250ZW50VHlwZShyZXN1bHQsIG9wdGlvbnMpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH0sXG4gIGFzeW5jIGdlbmVyYXRlU2VjcmV0S2V5KHRleHQpIHsgLy8gSk9TRSB1c2VzIGEgZGlnZXN0IGZvciBQQkVTLCBidXQgbWFrZSBpdCByZWNvZ25pemFibGUgYXMgYSB7dHlwZTogJ3NlY3JldCd9IGtleS5cbiAgICBsZXQgYnVmZmVyID0gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHRleHQpLFxuICAgICAgICBoYXNoID0gYXdhaXQgZGlnZXN0KGhhc2hOYW1lLCBidWZmZXIpO1xuICAgIHJldHVybiB7dHlwZTogJ3NlY3JldCcsIHRleHQ6IG5ldyBVaW50OEFycmF5KGhhc2gpfTtcbiAgfSxcbiAgZ2VuZXJhdGVTeW1tZXRyaWNLZXkodGV4dCkgeyAvLyBQcm9taXNlIGEga2V5IGZvciBzeW1tZXRyaWMgZW5jcnlwdGlvbi5cbiAgICBpZiAodGV4dCkgcmV0dXJuIHRoaXMuZ2VuZXJhdGVTZWNyZXRLZXkodGV4dCk7IC8vIFBCRVNcbiAgICByZXR1cm4gSk9TRS5nZW5lcmF0ZVNlY3JldChzeW1tZXRyaWNBbGdvcml0aG0sIHtleHRyYWN0YWJsZX0pOyAvLyBBRVNcbiAgfSxcbiAgaXNTeW1tZXRyaWMoa2V5KSB7IC8vIEVpdGhlciBBRVMgb3IgUEJFUywgYnV0IG5vdCBwdWJsaWNLZXkgb3IgcHJpdmF0ZUtleS5cbiAgICByZXR1cm4ga2V5LnR5cGUgPT09ICdzZWNyZXQnO1xuICB9LFxuICBrZXlTZWNyZXQoa2V5KSB7IC8vIFJldHVybiB3aGF0IGlzIGFjdHVhbGx5IHVzZWQgYXMgaW5wdXQgaW4gSk9TRSBsaWJyYXJ5LlxuICAgIGlmIChrZXkudGV4dCkgcmV0dXJuIGtleS50ZXh0O1xuICAgIHJldHVybiBrZXk7XG4gIH0sXG5cbiAgLy8gRXhwb3J0L0ltcG9ydFxuICBhc3luYyBleHBvcnRSYXcoa2V5KSB7IC8vIGJhc2U2NHVybCBmb3IgcHVibGljIHZlcmZpY2F0aW9uIGtleXNcbiAgICBsZXQgYXJyYXlCdWZmZXIgPSBhd2FpdCBleHBvcnRSYXdLZXkoa2V5KTtcbiAgICByZXR1cm4gSk9TRS5iYXNlNjR1cmwuZW5jb2RlKG5ldyBVaW50OEFycmF5KGFycmF5QnVmZmVyKSk7XG4gIH0sXG4gIGFzeW5jIGltcG9ydFJhdyhzdHJpbmcpIHsgLy8gUHJvbWlzZSB0aGUgdmVyaWZpY2F0aW9uIGtleSBmcm9tIGJhc2U2NHVybFxuICAgIGxldCBhcnJheUJ1ZmZlciA9IEpPU0UuYmFzZTY0dXJsLmRlY29kZShzdHJpbmcpO1xuICAgIHJldHVybiBpbXBvcnRSYXdLZXkoYXJyYXlCdWZmZXIpO1xuICB9LFxuICBhc3luYyBleHBvcnRKV0soa2V5KSB7IC8vIFByb21pc2UgSldLIG9iamVjdCwgd2l0aCBhbGcgaW5jbHVkZWQuXG4gICAgbGV0IGV4cG9ydGVkID0gYXdhaXQgSk9TRS5leHBvcnRKV0soa2V5KSxcbiAgICAgICAgYWxnID0ga2V5LmFsZ29yaXRobTsgLy8gSk9TRSBsaWJyYXJ5IGdpdmVzIGFsZ29yaXRobSwgYnV0IG5vdCBhbGcgdGhhdCBpcyBuZWVkZWQgZm9yIGltcG9ydC5cbiAgICBpZiAoYWxnKSB7IC8vIHN1YnRsZS5jcnlwdG8gdW5kZXJseWluZyBrZXlzXG4gICAgICBpZiAoYWxnLm5hbWUgPT09IHNpZ25pbmdOYW1lICYmIGFsZy5uYW1lZEN1cnZlID09PSBzaWduaW5nQ3VydmUpIGV4cG9ydGVkLmFsZyA9IHNpZ25pbmdBbGdvcml0aG07XG4gICAgICBlbHNlIGlmIChhbGcubmFtZSA9PT0gZW5jcnlwdGluZ05hbWUgJiYgYWxnLmhhc2gubmFtZSA9PT0gaGFzaE5hbWUpIGV4cG9ydGVkLmFsZyA9IGVuY3J5cHRpbmdBbGdvcml0aG07XG4gICAgICBlbHNlIGlmIChhbGcubmFtZSA9PT0gc3ltbWV0cmljTmFtZSAmJiBhbGcubGVuZ3RoID09PSBoYXNoTGVuZ3RoKSBleHBvcnRlZC5hbGcgPSBzeW1tZXRyaWNBbGdvcml0aG07XG4gICAgfSBlbHNlIHN3aXRjaCAoZXhwb3J0ZWQua3R5KSB7IC8vIEpPU0Ugb24gTm9kZUpTIHVzZWQgbm9kZTpjcnlwdG8ga2V5cywgd2hpY2ggZG8gbm90IGV4cG9zZSB0aGUgcHJlY2lzZSBhbGdvcml0aG1cbiAgICAgIGNhc2UgJ0VDJzogZXhwb3J0ZWQuYWxnID0gc2lnbmluZ0FsZ29yaXRobTsgYnJlYWs7XG4gICAgICBjYXNlICdSU0EnOiBleHBvcnRlZC5hbGcgPSBlbmNyeXB0aW5nQWxnb3JpdGhtOyBicmVhaztcbiAgICAgIGNhc2UgJ29jdCc6IGV4cG9ydGVkLmFsZyA9IHN5bW1ldHJpY0FsZ29yaXRobTsgYnJlYWs7XG4gICAgfVxuICAgIHJldHVybiBleHBvcnRlZDtcbiAgfSxcbiAgYXN5bmMgaW1wb3J0SldLKGp3aykgeyAvLyBQcm9taXNlIGEga2V5IG9iamVjdFxuICAgIGp3ayA9IHtleHQ6IHRydWUsIC4uLmp3a307IC8vIFdlIG5lZWQgdGhlIHJlc3VsdCB0byBiZSBiZSBhYmxlIHRvIGdlbmVyYXRlIGEgbmV3IEpXSyAoZS5nLiwgb24gY2hhbmdlTWVtYmVyc2hpcClcbiAgICBsZXQgaW1wb3J0ZWQgPSBhd2FpdCBKT1NFLmltcG9ydEpXSyhqd2spO1xuICAgIGlmIChpbXBvcnRlZCBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgIC8vIFdlIGRlcGVuZCBhbiByZXR1cm5pbmcgYW4gYWN0dWFsIGtleSwgYnV0IHRoZSBKT1NFIGxpYnJhcnkgd2UgdXNlXG4gICAgICAvLyB3aWxsIGFib3ZlIHByb2R1Y2UgdGhlIHJhdyBVaW50OEFycmF5IGlmIHRoZSBqd2sgaXMgZnJvbSBhIHNlY3JldC5cbiAgICAgIGltcG9ydGVkID0gYXdhaXQgaW1wb3J0U2VjcmV0KGltcG9ydGVkKTtcbiAgICB9XG4gICAgcmV0dXJuIGltcG9ydGVkO1xuICB9LFxuXG4gIGFzeW5jIHdyYXBLZXkoa2V5LCB3cmFwcGluZ0tleSkgeyAvLyBQcm9taXNlIGEgSldFIGZyb20gdGhlIHB1YmxpYyB3cmFwcGluZ0tleVxuICAgIGxldCBleHBvcnRlZCA9IGF3YWl0IHRoaXMuZXhwb3J0SldLKGtleSk7XG4gICAgcmV0dXJuIHRoaXMuZW5jcnlwdCh3cmFwcGluZ0tleSwgZXhwb3J0ZWQpO1xuICB9LFxuICBhc3luYyB1bndyYXBLZXkod3JhcHBlZEtleSwgdW53cmFwcGluZ0tleSkgeyAvLyBQcm9taXNlIHRoZSBrZXkgdW5sb2NrZWQgYnkgdGhlIHByaXZhdGUgdW53cmFwcGluZ0tleS5cbiAgICBsZXQgZGVjcnlwdGVkID0gYXdhaXQgdGhpcy5kZWNyeXB0KHVud3JhcHBpbmdLZXksIHdyYXBwZWRLZXkpO1xuICAgIHJldHVybiB0aGlzLmltcG9ydEpXSyhkZWNyeXB0ZWQuanNvbik7XG4gIH1cbn1cblxuZXhwb3J0IGRlZmF1bHQgS3J5cHRvO1xuLypcblNvbWUgdXNlZnVsIEpPU0UgcmVjaXBlcyBmb3IgcGxheWluZyBhcm91bmQuXG5zayA9IGF3YWl0IEpPU0UuZ2VuZXJhdGVLZXlQYWlyKCdFUzM4NCcsIHtleHRyYWN0YWJsZTogdHJ1ZX0pXG5qd3QgPSBhd2FpdCBuZXcgSk9TRS5TaWduSldUKCkuc2V0U3ViamVjdChcImZvb1wiKS5zZXRQcm90ZWN0ZWRIZWFkZXIoe2FsZzonRVMzODQnfSkuc2lnbihzay5wcml2YXRlS2V5KVxuYXdhaXQgSk9TRS5qd3RWZXJpZnkoand0LCBzay5wdWJsaWNLZXkpIC8vLnBheWxvYWQuc3ViXG5cbm1lc3NhZ2UgPSBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUoJ3NvbWUgbWVzc2FnZScpXG5qd3MgPSBhd2FpdCBuZXcgSk9TRS5Db21wYWN0U2lnbihtZXNzYWdlKS5zZXRQcm90ZWN0ZWRIZWFkZXIoe2FsZzonRVMzODQnfSkuc2lnbihzay5wcml2YXRlS2V5KSAvLyBPciBGbGF0dGVuZWRTaWduXG5qd3MgPSBhd2FpdCBuZXcgSk9TRS5HZW5lcmFsU2lnbihtZXNzYWdlKS5hZGRTaWduYXR1cmUoc2sucHJpdmF0ZUtleSkuc2V0UHJvdGVjdGVkSGVhZGVyKHthbGc6J0VTMzg0J30pLnNpZ24oKVxudmVyaWZpZWQgPSBhd2FpdCBKT1NFLmdlbmVyYWxWZXJpZnkoandzLCBzay5wdWJsaWNLZXkpXG5vciBjb21wYWN0VmVyaWZ5IG9yIGZsYXR0ZW5lZFZlcmlmeVxubmV3IFRleHREZWNvZGVyKCkuZGVjb2RlKHZlcmlmaWVkLnBheWxvYWQpXG5cbmVrID0gYXdhaXQgSk9TRS5nZW5lcmF0ZUtleVBhaXIoJ1JTQS1PQUVQLTI1NicsIHtleHRyYWN0YWJsZTogdHJ1ZX0pXG5qd2UgPSBhd2FpdCBuZXcgSk9TRS5Db21wYWN0RW5jcnlwdChtZXNzYWdlKS5zZXRQcm90ZWN0ZWRIZWFkZXIoe2FsZzogJ1JTQS1PQUVQLTI1NicsIGVuYzogJ0EyNTZHQ00nIH0pLmVuY3J5cHQoZWsucHVibGljS2V5KVxub3IgRmxhdHRlbmVkRW5jcnlwdC4gRm9yIHN5bW1ldHJpYyBzZWNyZXQsIHNwZWNpZnkgYWxnOidkaXInLlxuZGVjcnlwdGVkID0gYXdhaXQgSk9TRS5jb21wYWN0RGVjcnlwdChqd2UsIGVrLnByaXZhdGVLZXkpXG5uZXcgVGV4dERlY29kZXIoKS5kZWNvZGUoZGVjcnlwdGVkLnBsYWludGV4dClcbmp3ZSA9IGF3YWl0IG5ldyBKT1NFLkdlbmVyYWxFbmNyeXB0KG1lc3NhZ2UpLnNldFByb3RlY3RlZEhlYWRlcih7YWxnOiAnUlNBLU9BRVAtMjU2JywgZW5jOiAnQTI1NkdDTScgfSkuYWRkUmVjaXBpZW50KGVrLnB1YmxpY0tleSkuZW5jcnlwdCgpIC8vIHdpdGggYWRkaXRpb25hbCBhZGRSZWNpcGVudCgpIGFzIG5lZWRlZFxuZGVjcnlwdGVkID0gYXdhaXQgSk9TRS5nZW5lcmFsRGVjcnlwdChqd2UsIGVrLnByaXZhdGVLZXkpXG5cbm1hdGVyaWFsID0gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKCdzZWNyZXQnKVxuandlID0gYXdhaXQgbmV3IEpPU0UuQ29tcGFjdEVuY3J5cHQobWVzc2FnZSkuc2V0UHJvdGVjdGVkSGVhZGVyKHthbGc6ICdQQkVTMi1IUzUxMitBMjU2S1cnLCBlbmM6ICdBMjU2R0NNJyB9KS5lbmNyeXB0KG1hdGVyaWFsKVxuZGVjcnlwdGVkID0gYXdhaXQgSk9TRS5jb21wYWN0RGVjcnlwdChqd2UsIG1hdGVyaWFsLCB7a2V5TWFuYWdlbWVudEFsZ29yaXRobXM6IFsnUEJFUzItSFM1MTIrQTI1NktXJ10sIGNvbnRlbnRFbmNyeXB0aW9uQWxnb3JpdGhtczogWydBMjU2R0NNJ119KVxuandlID0gYXdhaXQgbmV3IEpPU0UuR2VuZXJhbEVuY3J5cHQobWVzc2FnZSkuc2V0UHJvdGVjdGVkSGVhZGVyKHthbGc6ICdQQkVTMi1IUzUxMitBMjU2S1cnLCBlbmM6ICdBMjU2R0NNJyB9KS5hZGRSZWNpcGllbnQobWF0ZXJpYWwpLmVuY3J5cHQoKVxuandlID0gYXdhaXQgbmV3IEpPU0UuR2VuZXJhbEVuY3J5cHQobWVzc2FnZSkuc2V0UHJvdGVjdGVkSGVhZGVyKHtlbmM6ICdBMjU2R0NNJyB9KVxuICAuYWRkUmVjaXBpZW50KGVrLnB1YmxpY0tleSkuc2V0VW5wcm90ZWN0ZWRIZWFkZXIoe2tpZDogJ2ZvbycsIGFsZzogJ1JTQS1PQUVQLTI1Nid9KVxuICAuYWRkUmVjaXBpZW50KG1hdGVyaWFsKS5zZXRVbnByb3RlY3RlZEhlYWRlcih7a2lkOiAnc2VjcmV0MScsIGFsZzogJ1BCRVMyLUhTNTEyK0EyNTZLVyd9KVxuICAuYWRkUmVjaXBpZW50KG1hdGVyaWFsMikuc2V0VW5wcm90ZWN0ZWRIZWFkZXIoe2tpZDogJ3NlY3JldDInLCBhbGc6ICdQQkVTMi1IUzUxMitBMjU2S1cnfSlcbiAgLmVuY3J5cHQoKVxuZGVjcnlwdGVkID0gYXdhaXQgSk9TRS5nZW5lcmFsRGVjcnlwdChqd2UsIGVrLnByaXZhdGVLZXkpXG5kZWNyeXB0ZWQgPSBhd2FpdCBKT1NFLmdlbmVyYWxEZWNyeXB0KGp3ZSwgbWF0ZXJpYWwsIHtrZXlNYW5hZ2VtZW50QWxnb3JpdGhtczogWydQQkVTMi1IUzUxMitBMjU2S1cnXX0pXG4qL1xuIiwiaW1wb3J0IEtyeXB0byBmcm9tIFwiLi9rcnlwdG8ubWpzXCI7XG5pbXBvcnQgKiBhcyBKT1NFIGZyb20gXCJqb3NlXCI7XG5pbXBvcnQge3NpZ25pbmdBbGdvcml0aG0sIGVuY3J5cHRpbmdBbGdvcml0aG0sIHN5bW1ldHJpY0FsZ29yaXRobSwgc3ltbWV0cmljV3JhcCwgc2VjcmV0QWxnb3JpdGhtfSBmcm9tIFwiLi9hbGdvcml0aG1zLm1qc1wiO1xuXG5mdW5jdGlvbiBtaXNtYXRjaChraWQsIGVuY29kZWRLaWQpIHsgLy8gUHJvbWlzZSBhIHJlamVjdGlvbi5cbiAgbGV0IG1lc3NhZ2UgPSBgS2V5ICR7a2lkfSBkb2VzIG5vdCBtYXRjaCBlbmNvZGVkICR7ZW5jb2RlZEtpZH0uYDtcbiAgcmV0dXJuIFByb21pc2UucmVqZWN0KG1lc3NhZ2UpO1xufVxuXG5jb25zdCBNdWx0aUtyeXB0byA9IHtcbiAgLy8gRXh0ZW5kIEtyeXB0byBmb3IgZ2VuZXJhbCAobXVsdGlwbGUga2V5KSBKT1NFIG9wZXJhdGlvbnMuXG4gIC8vIFNlZSBodHRwczovL2tpbHJveS1jb2RlLmdpdGh1Yi5pby9kaXN0cmlidXRlZC1zZWN1cml0eS9kb2NzL2ltcGxlbWVudGF0aW9uLmh0bWwjY29tYmluaW5nLWtleXNcbiAgXG4gIC8vIE91ciBtdWx0aSBrZXlzIGFyZSBkaWN0aW9uYXJpZXMgb2YgbmFtZSAob3Iga2lkKSA9PiBrZXlPYmplY3QuXG4gIGlzTXVsdGlLZXkoa2V5KSB7IC8vIEEgU3VidGxlQ3J5cHRvIENyeXB0b0tleSBpcyBhbiBvYmplY3Qgd2l0aCBhIHR5cGUgcHJvcGVydHkuIE91ciBtdWx0aWtleXMgYXJlXG4gICAgLy8gb2JqZWN0cyB3aXRoIGEgc3BlY2lmaWMgdHlwZSBvciBubyB0eXBlIHByb3BlcnR5IGF0IGFsbC5cbiAgICByZXR1cm4gKGtleS50eXBlIHx8ICdtdWx0aScpID09PSAnbXVsdGknO1xuICB9LFxuICBrZXlUYWdzKGtleSkgeyAvLyBKdXN0IHRoZSBraWRzIHRoYXQgYXJlIGZvciBhY3R1YWwga2V5cy4gTm8gJ3R5cGUnLlxuICAgIHJldHVybiBPYmplY3Qua2V5cyhrZXkpLmZpbHRlcihrZXkgPT4ga2V5ICE9PSAndHlwZScpO1xuICB9LFxuXG4gIC8vIEV4cG9ydC9JbXBvcnRcbiAgYXN5bmMgZXhwb3J0SldLKGtleSkgeyAvLyBQcm9taXNlIGEgSldLIGtleSBzZXQgaWYgbmVjZXNzYXJ5LCByZXRhaW5pbmcgdGhlIG5hbWVzIGFzIGtpZCBwcm9wZXJ0eS5cbiAgICBpZiAoIXRoaXMuaXNNdWx0aUtleShrZXkpKSByZXR1cm4gc3VwZXIuZXhwb3J0SldLKGtleSk7XG4gICAgbGV0IG5hbWVzID0gdGhpcy5rZXlUYWdzKGtleSksXG4gICAgICAgIGtleXMgPSBhd2FpdCBQcm9taXNlLmFsbChuYW1lcy5tYXAoYXN5bmMgbmFtZSA9PiB7XG4gICAgICAgICAgbGV0IGp3ayA9IGF3YWl0IHRoaXMuZXhwb3J0SldLKGtleVtuYW1lXSk7XG4gICAgICAgICAgandrLmtpZCA9IG5hbWU7XG4gICAgICAgICAgcmV0dXJuIGp3aztcbiAgICAgICAgfSkpO1xuICAgIHJldHVybiB7a2V5c307XG4gIH0sXG4gIGFzeW5jIGltcG9ydEpXSyhqd2spIHsgLy8gUHJvbWlzZSBhIHNpbmdsZSBcImtleVwiIG9iamVjdC5cbiAgICAvLyBSZXN1bHQgd2lsbCBiZSBhIG11bHRpLWtleSBpZiBKV0sgaXMgYSBrZXkgc2V0LCBpbiB3aGljaCBjYXNlIGVhY2ggbXVzdCBpbmNsdWRlIGEga2lkIHByb3BlcnR5LlxuICAgIGlmICghandrLmtleXMpIHJldHVybiBzdXBlci5pbXBvcnRKV0soandrKTtcbiAgICBsZXQga2V5ID0ge307IC8vIFRPRE86IGdldCB0eXBlIGZyb20ga3R5IG9yIHNvbWUgc3VjaD9cbiAgICBhd2FpdCBQcm9taXNlLmFsbChqd2sua2V5cy5tYXAoYXN5bmMgandrID0+IGtleVtqd2sua2lkXSA9IGF3YWl0IHRoaXMuaW1wb3J0SldLKGp3aykpKTtcbiAgICByZXR1cm4ga2V5O1xuICB9LFxuXG4gIC8vIEVuY3J5cHQvRGVjcnlwdFxuICBhc3luYyBlbmNyeXB0KGtleSwgbWVzc2FnZSwgaGVhZGVycyA9IHt9KSB7IC8vIFByb21pc2UgYSBKV0UsIGluIGdlbmVyYWwgZm9ybSBpZiBhcHByb3ByaWF0ZS5cbiAgICBpZiAoIXRoaXMuaXNNdWx0aUtleShrZXkpKSByZXR1cm4gc3VwZXIuZW5jcnlwdChrZXksIG1lc3NhZ2UsIGhlYWRlcnMpO1xuICAgIC8vIGtleSBtdXN0IGJlIGEgZGljdGlvbmFyeSBtYXBwaW5nIHRhZ3MgdG8gZW5jcnlwdGluZyBrZXlzLlxuICAgIGxldCBiYXNlSGVhZGVyID0ge2VuYzogc3ltbWV0cmljQWxnb3JpdGhtLCAuLi5oZWFkZXJzfSxcbiAgICAgICAgaW5wdXRCdWZmZXIgPSB0aGlzLmlucHV0QnVmZmVyKG1lc3NhZ2UsIGJhc2VIZWFkZXIpLFxuICAgICAgICBqd2UgPSBuZXcgSk9TRS5HZW5lcmFsRW5jcnlwdChpbnB1dEJ1ZmZlcikuc2V0UHJvdGVjdGVkSGVhZGVyKGJhc2VIZWFkZXIpO1xuICAgIGZvciAobGV0IHRhZyBvZiB0aGlzLmtleVRhZ3Moa2V5KSkge1xuICAgICAgbGV0IHRoaXNLZXkgPSBrZXlbdGFnXSxcbiAgICAgICAgICBpc1N0cmluZyA9ICdzdHJpbmcnID09PSB0eXBlb2YgdGhpc0tleSxcbiAgICAgICAgICBpc1N5bSA9IGlzU3RyaW5nIHx8IHRoaXMuaXNTeW1tZXRyaWModGhpc0tleSksXG4gICAgICAgICAgc2VjcmV0ID0gaXNTdHJpbmcgPyBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUodGhpc0tleSkgOiB0aGlzLmtleVNlY3JldCh0aGlzS2V5KSxcbiAgICAgICAgICBhbGcgPSBpc1N0cmluZyA/IHNlY3JldEFsZ29yaXRobSA6IChpc1N5bSA/IHN5bW1ldHJpY1dyYXAgOiBlbmNyeXB0aW5nQWxnb3JpdGhtKTtcbiAgICAgIC8vIFRoZSBraWQgYW5kIGFsZyBhcmUgcGVyL3N1Yi1rZXksIGFuZCBzbyBjYW5ub3QgYmUgc2lnbmVkIGJ5IGFsbCwgYW5kIHNvIGNhbm5vdCBiZSBwcm90ZWN0ZWQgd2l0aGluIHRoZSBlbmNyeXB0aW9uLlxuICAgICAgLy8gVGhpcyBpcyBvaywgYmVjYXVzZSB0aGUgb25seSB0aGF0IGNhbiBoYXBwZW4gYXMgYSByZXN1bHQgb2YgdGFtcGVyaW5nIHdpdGggdGhlc2UgaXMgdGhhdCB0aGUgZGVjcnlwdGlvbiB3aWxsIGZhaWwsXG4gICAgICAvLyB3aGljaCBpcyB0aGUgc2FtZSByZXN1bHQgYXMgdGFtcGVyaW5nIHdpdGggdGhlIGNpcGhlcnRleHQgb3IgYW55IG90aGVyIHBhcnQgb2YgdGhlIEpXRS5cbiAgICAgIGp3ZS5hZGRSZWNpcGllbnQoc2VjcmV0KS5zZXRVbnByb3RlY3RlZEhlYWRlcih7a2lkOiB0YWcsIGFsZ30pO1xuICAgIH1cbiAgICBsZXQgZW5jcnlwdGVkID0gYXdhaXQgandlLmVuY3J5cHQoKTtcbiAgICByZXR1cm4gZW5jcnlwdGVkO1xuICB9LFxuICBhc3luYyBkZWNyeXB0KGtleSwgZW5jcnlwdGVkLCBvcHRpb25zKSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259LCB3aGVyZSB0ZXh0IGFuZCBqc29uIGFyZSBvbmx5IGRlZmluZWQgd2hlbiBhcHByb3ByaWF0ZS5cbiAgICBpZiAoIXRoaXMuaXNNdWx0aUtleShrZXkpKSByZXR1cm4gc3VwZXIuZGVjcnlwdChrZXksIGVuY3J5cHRlZCwgb3B0aW9ucyk7XG4gICAgbGV0IGp3ZSA9IGVuY3J5cHRlZCxcbiAgICAgICAge3JlY2lwaWVudHN9ID0gandlLFxuICAgICAgICB1bndyYXBwaW5nUHJvbWlzZXMgPSByZWNpcGllbnRzLm1hcChhc3luYyAoe2hlYWRlcn0pID0+IHtcbiAgICAgICAgICBsZXQge2tpZH0gPSBoZWFkZXIsXG4gICAgICAgICAgICAgIHVud3JhcHBpbmdLZXkgPSBrZXlba2lkXSxcbiAgICAgICAgICAgICAgb3B0aW9ucyA9IHt9O1xuICAgICAgICAgIGlmICghdW53cmFwcGluZ0tleSkgcmV0dXJuIFByb21pc2UucmVqZWN0KCdtaXNzaW5nJyk7XG4gICAgICAgICAgaWYgKCdzdHJpbmcnID09PSB0eXBlb2YgdW53cmFwcGluZ0tleSkgeyAvLyBUT0RPOiBvbmx5IHNwZWNpZmllZCBpZiBhbGxvd2VkIGJ5IHNlY3VyZSBoZWFkZXI/XG4gICAgICAgICAgICB1bndyYXBwaW5nS2V5ID0gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHVud3JhcHBpbmdLZXkpO1xuICAgICAgICAgICAgb3B0aW9ucy5rZXlNYW5hZ2VtZW50QWxnb3JpdGhtcyA9IFtzZWNyZXRBbGdvcml0aG1dO1xuICAgICAgICAgIH1cbiAgICAgICAgICBsZXQgcmVzdWx0ID0gYXdhaXQgSk9TRS5nZW5lcmFsRGVjcnlwdChqd2UsIHRoaXMua2V5U2VjcmV0KHVud3JhcHBpbmdLZXkpLCBvcHRpb25zKSxcbiAgICAgICAgICAgICAgZW5jb2RlZEtpZCA9IHJlc3VsdC51bnByb3RlY3RlZEhlYWRlci5raWQ7XG4gICAgICAgICAgaWYgKGVuY29kZWRLaWQgIT09IGtpZCkgcmV0dXJuIG1pc21hdGNoKGtpZCwgZW5jb2RlZEtpZCk7XG4gICAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgICAgfSk7XG4gICAgLy8gRG8gd2UgcmVhbGx5IHdhbnQgdG8gcmV0dXJuIHVuZGVmaW5lZCBpZiBldmVyeXRoaW5nIGZhaWxzPyBTaG91bGQganVzdCBhbGxvdyB0aGUgcmVqZWN0aW9uIHRvIHByb3BhZ2F0ZT9cbiAgICByZXR1cm4gYXdhaXQgUHJvbWlzZS5hbnkodW53cmFwcGluZ1Byb21pc2VzKS50aGVuKFxuICAgICAgcmVzdWx0ID0+IHtcbiAgICAgICAgdGhpcy5yZWNvdmVyRGF0YUZyb21Db250ZW50VHlwZShyZXN1bHQsIG9wdGlvbnMpO1xuICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgfSxcbiAgICAgICgpID0+IHVuZGVmaW5lZCk7XG4gIH0sXG5cbiAgLy8gU2lnbi9WZXJpZnlcbiAgYXN5bmMgc2lnbihrZXksIG1lc3NhZ2UsIGhlYWRlciA9IHt9KSB7IC8vIFByb21pc2UgSldTLCBpbiBnZW5lcmFsIGZvcm0gd2l0aCBraWQgaGVhZGVycyBpZiBuZWNlc3NhcnkuXG4gICAgaWYgKCF0aGlzLmlzTXVsdGlLZXkoa2V5KSkgcmV0dXJuIHN1cGVyLnNpZ24oa2V5LCBtZXNzYWdlLCBoZWFkZXIpO1xuICAgIGxldCBpbnB1dEJ1ZmZlciA9IHRoaXMuaW5wdXRCdWZmZXIobWVzc2FnZSwgaGVhZGVyKSxcbiAgICAgICAgandzID0gbmV3IEpPU0UuR2VuZXJhbFNpZ24oaW5wdXRCdWZmZXIpO1xuICAgIGZvciAobGV0IHRhZyBvZiB0aGlzLmtleVRhZ3Moa2V5KSkge1xuICAgICAgbGV0IHRoaXNLZXkgPSBrZXlbdGFnXSxcbiAgICAgICAgICB0aGlzSGVhZGVyID0ge2tpZDogdGFnLCBhbGc6IHNpZ25pbmdBbGdvcml0aG0sIC4uLmhlYWRlcn07XG4gICAgICBqd3MuYWRkU2lnbmF0dXJlKHRoaXNLZXkpLnNldFByb3RlY3RlZEhlYWRlcih0aGlzSGVhZGVyKTtcbiAgICB9XG4gICAgcmV0dXJuIGp3cy5zaWduKCk7XG4gIH0sXG4gIHZlcmlmeVN1YlNpZ25hdHVyZShqd3MsIHNpZ25hdHVyZUVsZW1lbnQsIG11bHRpS2V5LCBraWRzKSB7XG4gICAgLy8gVmVyaWZ5IGEgc2luZ2xlIGVsZW1lbnQgb2YgandzLnNpZ25hdHVyZSB1c2luZyBtdWx0aUtleS5cbiAgICAvLyBBbHdheXMgcHJvbWlzZXMge3Byb3RlY3RlZEhlYWRlciwgdW5wcm90ZWN0ZWRIZWFkZXIsIGtpZH0sIGV2ZW4gaWYgdmVyaWZpY2F0aW9uIGZhaWxzLFxuICAgIC8vIHdoZXJlIGtpZCBpcyB0aGUgcHJvcGVydHkgbmFtZSB3aXRoaW4gbXVsdGlLZXkgdGhhdCBtYXRjaGVkIChlaXRoZXIgYnkgYmVpbmcgc3BlY2lmaWVkIGluIGEgaGVhZGVyXG4gICAgLy8gb3IgYnkgc3VjY2Vzc2Z1bCB2ZXJpZmljYXRpb24pLiBBbHNvIGluY2x1ZGVzIHRoZSBkZWNvZGVkIHBheWxvYWQgSUZGIHRoZXJlIGlzIGEgbWF0Y2guXG4gICAgbGV0IHByb3RlY3RlZEhlYWRlciA9IHNpZ25hdHVyZUVsZW1lbnQucHJvdGVjdGVkSGVhZGVyID8/IHRoaXMuZGVjb2RlUHJvdGVjdGVkSGVhZGVyKHNpZ25hdHVyZUVsZW1lbnQpLFxuICAgICAgICB1bnByb3RlY3RlZEhlYWRlciA9IHNpZ25hdHVyZUVsZW1lbnQudW5wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgIGtpZCA9IHByb3RlY3RlZEhlYWRlcj8ua2lkIHx8IHVucHJvdGVjdGVkSGVhZGVyPy5raWQsXG4gICAgICAgIHNpbmdsZUpXUyA9IHsuLi5qd3MsIHNpZ25hdHVyZXM6IFtzaWduYXR1cmVFbGVtZW50XX0sXG4gICAgICAgIGZhaWx1cmVSZXN1bHQgPSB7cHJvdGVjdGVkSGVhZGVyLCB1bnByb3RlY3RlZEhlYWRlciwga2lkfSxcbiAgICAgICAga2lkc1RvVHJ5ID0ga2lkID8gW2tpZF0gOiBraWRzO1xuICAgIGxldCBwcm9taXNlID0gUHJvbWlzZS5hbnkoa2lkc1RvVHJ5Lm1hcChhc3luYyBraWQgPT4gSk9TRS5nZW5lcmFsVmVyaWZ5KHNpbmdsZUpXUywgbXVsdGlLZXlba2lkXSkudGhlbihyZXN1bHQgPT4ge3JldHVybiB7a2lkLCAuLi5yZXN1bHR9O30pKSk7XG4gICAgcmV0dXJuIHByb21pc2UuY2F0Y2goKCkgPT4gZmFpbHVyZVJlc3VsdCk7XG4gIH0sXG4gIGFzeW5jIHZlcmlmeShrZXksIHNpZ25hdHVyZSwgb3B0aW9ucyA9IHt9KSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259LCB3aGVyZSB0ZXh0IGFuZCBqc29uIGFyZSBvbmx5IGRlZmluZWQgd2hlbiBhcHByb3ByaWF0ZS5cbiAgICAvLyBBZGRpdGlvbmFsbHksIGlmIGtleSBpcyBhIG11bHRpS2V5IEFORCBzaWduYXR1cmUgaXMgYSBnZW5lcmFsIGZvcm0gSldTLCB0aGVuIGFuc3dlciBpbmNsdWRlcyBhIHNpZ25lcnMgcHJvcGVydHlcbiAgICAvLyBieSB3aGljaCBjYWxsZXIgY2FuIGRldGVybWluZSBpZiBpdCB3aGF0IHRoZXkgZXhwZWN0LiBUaGUgcGF5bG9hZCBvZiBlYWNoIHNpZ25lcnMgZWxlbWVudCBpcyBkZWZpbmVkIG9ubHkgdGhhdFxuICAgIC8vIHNpZ25lciB3YXMgbWF0Y2hlZCBieSBzb21ldGhpbmcgaW4ga2V5LlxuICAgIFxuICAgIGlmICghdGhpcy5pc011bHRpS2V5KGtleSkpIHJldHVybiBzdXBlci52ZXJpZnkoa2V5LCBzaWduYXR1cmUsIG9wdGlvbnMpO1xuICAgIGlmICghc2lnbmF0dXJlLnNpZ25hdHVyZXMpIHJldHVybjtcblxuICAgIC8vIENvbXBhcmlzb24gdG8gcGFudmEgSk9TRS5nZW5lcmFsVmVyaWZ5LlxuICAgIC8vIEpPU0UgdGFrZXMgYSBqd3MgYW5kIE9ORSBrZXkgYW5kIGFuc3dlcnMge3BheWxvYWQsIHByb3RlY3RlZEhlYWRlciwgdW5wcm90ZWN0ZWRIZWFkZXJ9IG1hdGNoaW5nIHRoZSBvbmVcbiAgICAvLyBqd3Muc2lnbmF0dXJlIGVsZW1lbnQgdGhhdCB3YXMgdmVyaWZpZWQsIG90aGVyaXNlIGFuIGVyb3IuIChJdCB0cmllcyBlYWNoIG9mIHRoZSBlbGVtZW50cyBvZiB0aGUgandzLnNpZ25hdHVyZXMuKVxuICAgIC8vIEl0IGlzIG5vdCBnZW5lcmFsbHkgcG9zc2libGUgdG8ga25vdyBXSElDSCBvbmUgb2YgdGhlIGp3cy5zaWduYXR1cmVzIHdhcyBtYXRjaGVkLlxuICAgIC8vIChJdCBNQVkgYmUgcG9zc2libGUgaWYgdGhlcmUgYXJlIHVuaXF1ZSBraWQgZWxlbWVudHMsIGJ1dCB0aGF0J3MgYXBwbGljYXRpb24tZGVwZW5kZW50LilcbiAgICAvL1xuICAgIC8vIE11bHRpS3J5cHRvIHRha2VzIGEgZGljdGlvbmFyeSB0aGF0IGNvbnRhaW5zIG5hbWVkIGtleXMgYW5kIHJlY29nbml6ZWRIZWFkZXIgcHJvcGVydGllcywgYW5kIGl0IHJldHVybnNcbiAgICAvLyBhIHJlc3VsdCB0aGF0IGhhcyBhIHNpZ25lcnMgYXJyYXkgdGhhdCBoYXMgYW4gZWxlbWVudCBjb3JyZXNwb25kaW5nIHRvIGVhY2ggb3JpZ2luYWwgc2lnbmF0dXJlIGlmIGFueVxuICAgIC8vIGFyZSBtYXRjaGVkIGJ5IHRoZSBtdWx0aWtleS4gKElmIG5vbmUgbWF0Y2gsIHdlIHJldHVybiB1bmRlZmluZWQuXG4gICAgLy8gRWFjaCBlbGVtZW50IGNvbnRhaW5zIHRoZSBraWQsIHByb3RlY3RlZEhlYWRlciwgcG9zc2libHkgdW5wcm90ZWN0ZWRIZWFkZXIsIGFuZCBwb3NzaWJseSBwYXlsb2FkIChpLmUuIGlmIHN1Y2Nlc3NmdWwpLlxuICAgIC8vXG4gICAgLy8gQWRkaXRpb25hbGx5IGlmIGEgcmVzdWx0IGlzIHByb2R1Y2VkLCB0aGUgb3ZlcmFsbCBwcm90ZWN0ZWRIZWFkZXIgYW5kIHVucHJvdGVjdGVkSGVhZGVyIGNvbnRhaW5zIG9ubHkgdmFsdWVzXG4gICAgLy8gdGhhdCB3ZXJlIGNvbW1vbiB0byBlYWNoIG9mIHRoZSB2ZXJpZmllZCBzaWduYXR1cmUgZWxlbWVudHMuXG4gICAgXG4gICAgbGV0IGp3cyA9IHNpZ25hdHVyZSxcbiAgICAgICAga2lkcyA9IHRoaXMua2V5VGFncyhrZXkpLFxuICAgICAgICBzaWduZXJzID0gYXdhaXQgUHJvbWlzZS5hbGwoandzLnNpZ25hdHVyZXMubWFwKHNpZ25hdHVyZSA9PiB0aGlzLnZlcmlmeVN1YlNpZ25hdHVyZShqd3MsIHNpZ25hdHVyZSwga2V5LCBraWRzKSkpO1xuICAgIGlmICghc2lnbmVycy5maW5kKHNpZ25lciA9PiBzaWduZXIucGF5bG9hZCkpIHJldHVybiB1bmRlZmluZWQ7XG4gICAgLy8gTm93IGNhbm9uaWNhbGl6ZSB0aGUgc2lnbmVycyBhbmQgYnVpbGQgdXAgYSByZXN1bHQuXG4gICAgbGV0IFtmaXJzdCwgLi4ucmVzdF0gPSBzaWduZXJzLFxuICAgICAgICByZXN1bHQgPSB7cHJvdGVjdGVkSGVhZGVyOiB7fSwgdW5wcm90ZWN0ZWRIZWFkZXI6IHt9LCBzaWduZXJzfSxcbiAgICAgICAgLy8gRm9yIGEgaGVhZGVyIHZhbHVlIHRvIGJlIGNvbW1vbiB0byB2ZXJpZmllZCByZXN1bHRzLCBpdCBtdXN0IGJlIGluIHRoZSBmaXJzdCByZXN1bHQuXG4gICAgICAgIGdldFVuaXF1ZSA9IGNhdGVnb3J5TmFtZSA9PiB7XG4gICAgICAgICAgbGV0IGZpcnN0SGVhZGVyID0gZmlyc3RbY2F0ZWdvcnlOYW1lXSxcbiAgICAgICAgICAgICAgYWNjdW11bGF0b3JIZWFkZXIgPSByZXN1bHRbY2F0ZWdvcnlOYW1lXTtcbiAgICAgICAgICBmb3IgKGxldCBsYWJlbCBpbiBmaXJzdEhlYWRlcikge1xuICAgICAgICAgICAgbGV0IHZhbHVlID0gZmlyc3RIZWFkZXJbbGFiZWxdO1xuICAgICAgICAgICAgaWYgKHJlc3Quc29tZShzaWduZXJSZXN1bHQgPT4gc2lnbmVyUmVzdWx0W2NhdGVnb3J5TmFtZV1bbGFiZWxdICE9PSB2YWx1ZSkpIGNvbnRpbnVlO1xuICAgICAgICAgICAgYWNjdW11bGF0b3JIZWFkZXJbbGFiZWxdID0gdmFsdWU7XG4gICAgICAgICAgfVxuICAgICAgICB9O1xuICAgIGdldFVuaXF1ZSgncHJvdGVjdGVkSGVhZGVyJyk7XG4gICAgZ2V0VW5pcXVlKCdwcm90ZWN0ZWRIZWFkZXInKTtcbiAgICAvLyBJZiBhbnl0aGluZyB2ZXJpZmllZCwgdGhlbiBzZXQgcGF5bG9hZCBhbmQgYWxsb3cgdGV4dC9qc29uIHRvIGJlIHByb2R1Y2VkLlxuICAgIC8vIENhbGxlcnMgY2FuIGNoZWNrIHNpZ25lcnNbbl0ucGF5bG9hZCB0byBkZXRlcm1pbmUgaWYgdGhlIHJlc3VsdCBpcyB3aGF0IHRoZXkgd2FudC5cbiAgICByZXN1bHQucGF5bG9hZCA9IHNpZ25lcnMuZmluZChzaWduZXIgPT4gc2lnbmVyLnBheWxvYWQpLnBheWxvYWQ7XG4gICAgcmV0dXJuIHRoaXMucmVjb3ZlckRhdGFGcm9tQ29udGVudFR5cGUocmVzdWx0LCBvcHRpb25zKTtcbiAgfVxufTtcblxuT2JqZWN0LnNldFByb3RvdHlwZU9mKE11bHRpS3J5cHRvLCBLcnlwdG8pOyAvLyBJbmhlcml0IGZyb20gS3J5cHRvIHNvIHRoYXQgc3VwZXIubXVtYmxlKCkgd29ya3MuXG5leHBvcnQgZGVmYXVsdCBNdWx0aUtyeXB0bztcbiIsImNsYXNzIFBlcnNpc3RlZENvbGxlY3Rpb24ge1xuICAvLyBBc3luY2hyb25vdXMgbG9jYWwgc3RvcmFnZSwgYXZhaWxhYmxlIGluIHdlYiB3b3JrZXJzLlxuICBjb25zdHJ1Y3Rvcih7Y29sbGVjdGlvbk5hbWUgPSAnY29sbGVjdGlvbicsIGRiTmFtZSA9ICdhc3luY0xvY2FsU3RvcmFnZSd9ID0ge30pIHtcbiAgICAvLyBDYXB0dXJlIHRoZSBkYXRhIGhlcmUsIGJ1dCBkb24ndCBvcGVuIHRoZSBkYiB1bnRpbCB3ZSBuZWVkIHRvLlxuICAgIHRoaXMuY29sbGVjdGlvbk5hbWUgPSBjb2xsZWN0aW9uTmFtZTtcbiAgICB0aGlzLmRiTmFtZSA9IGRiTmFtZTtcbiAgICB0aGlzLnZlcnNpb24gPSAxO1xuICB9XG4gIGdldCBkYigpIHsgLy8gQW5zd2VyIGEgcHJvbWlzZSBmb3IgdGhlIGRhdGFiYXNlLCBjcmVhdGluZyBpdCBpZiBuZWVkZWQuXG4gICAgcmV0dXJuIHRoaXMuX2RiID8/PSBuZXcgUHJvbWlzZShyZXNvbHZlID0+IHtcbiAgICAgIGNvbnN0IHJlcXVlc3QgPSBpbmRleGVkREIub3Blbih0aGlzLmRiTmFtZSwgdGhpcy52ZXJzaW9uKTtcbiAgICAgIC8vIGNyZWF0ZU9iamVjdFN0b3JlIGNhbiBvbmx5IGJlIGNhbGxlZCBmcm9tIHVwZ3JhZGVuZWVkZWQsIHdoaWNoIGlzIG9ubHkgY2FsbGVkIGZvciBuZXcgdmVyc2lvbnMuXG4gICAgICByZXF1ZXN0Lm9udXBncmFkZW5lZWRlZCA9IGV2ZW50ID0+IGV2ZW50LnRhcmdldC5yZXN1bHQuY3JlYXRlT2JqZWN0U3RvcmUodGhpcy5jb2xsZWN0aW9uTmFtZSk7XG4gICAgICB0aGlzLnJlc3VsdChyZXNvbHZlLCByZXF1ZXN0KTtcbiAgICB9KTtcbiAgfVxuICB0cmFuc2FjdGlvbihtb2RlID0gJ3JlYWQnKSB7IC8vIEFuc3dlciBhIHByb21pc2UgZm9yIHRoZSBuYW1lZCBvYmplY3Qgc3RvcmUgb24gYSBuZXcgdHJhbnNhY3Rpb24uXG4gICAgY29uc3QgY29sbGVjdGlvbk5hbWUgPSB0aGlzLmNvbGxlY3Rpb25OYW1lO1xuICAgIHJldHVybiB0aGlzLmRiLnRoZW4oZGIgPT4gZGIudHJhbnNhY3Rpb24oY29sbGVjdGlvbk5hbWUsIG1vZGUpLm9iamVjdFN0b3JlKGNvbGxlY3Rpb25OYW1lKSk7XG4gIH1cbiAgcmVzdWx0KHJlc29sdmUsIG9wZXJhdGlvbikge1xuICAgIG9wZXJhdGlvbi5vbnN1Y2Nlc3MgPSBldmVudCA9PiByZXNvbHZlKGV2ZW50LnRhcmdldC5yZXN1bHQgfHwgJycpOyAvLyBOb3QgdW5kZWZpbmVkLlxuICB9XG4gIHJldHJpZXZlKHRhZykgeyAvLyBQcm9taXNlIHRvIHJldHJpZXZlIHRhZyBmcm9tIGNvbGxlY3Rpb25OYW1lLlxuICAgIHJldHVybiBuZXcgUHJvbWlzZShyZXNvbHZlID0+IHtcbiAgICAgIHRoaXMudHJhbnNhY3Rpb24oJ3JlYWRvbmx5JykudGhlbihzdG9yZSA9PiB0aGlzLnJlc3VsdChyZXNvbHZlLCBzdG9yZS5nZXQodGFnKSkpO1xuICAgIH0pO1xuICB9XG4gIHN0b3JlKHRhZywgZGF0YSkgeyAvLyBQcm9taXNlIHRvIHN0b3JlIGRhdGEgYXQgdGFnIGluIGNvbGxlY3Rpb25OYW1lLlxuICAgIHJldHVybiBuZXcgUHJvbWlzZShyZXNvbHZlID0+IHtcbiAgICAgIHRoaXMudHJhbnNhY3Rpb24oJ3JlYWR3cml0ZScpLnRoZW4oc3RvcmUgPT4gdGhpcy5yZXN1bHQocmVzb2x2ZSwgc3RvcmUucHV0KGRhdGEsIHRhZykpKTtcbiAgICB9KTtcbiAgfVxuICByZW1vdmUodGFnKSB7IC8vIFByb21pc2UgdG8gcmVtb3ZlIHRhZyBmcm9tIGNvbGxlY3Rpb25OYW1lLlxuICAgIHJldHVybiBuZXcgUHJvbWlzZShyZXNvbHZlID0+IHtcbiAgICAgIHRoaXMudHJhbnNhY3Rpb24oJ3JlYWR3cml0ZScpLnRoZW4oc3RvcmUgPT4gdGhpcy5yZXN1bHQocmVzb2x2ZSwgc3RvcmUuZGVsZXRlKHRhZykpKTtcbiAgICB9KTtcbiAgfVxufVxuZXhwb3J0IGRlZmF1bHQgUGVyc2lzdGVkQ29sbGVjdGlvbjtcbiIsInZhciBwcm9tcHRlciA9IHByb21wdFN0cmluZyA9PiBwcm9tcHRTdHJpbmc7XG5pZiAodHlwZW9mKHdpbmRvdykgIT09ICd1bmRlZmluZWQnKSB7XG4gIHByb21wdGVyID0gd2luZG93LnByb21wdDtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGdldFVzZXJEZXZpY2VTZWNyZXQodGFnLCBwcm9tcHRTdHJpbmcpIHtcbiAgcmV0dXJuIHByb21wdFN0cmluZyA/ICh0YWcgKyBwcm9tcHRlcihwcm9tcHRTdHJpbmcpKSA6IHRhZztcbn1cbiIsImNvbnN0IG9yaWdpbiA9IGxvY2F0aW9uLm9yaWdpbjtcbmV4cG9ydCBkZWZhdWx0IG9yaWdpbjtcbiIsImltcG9ydCBvcmlnaW4gZnJvbSAnI29yaWdpbic7IC8vIFdoZW4gcnVubmluZyBpbiBhIGJyb3dzZXIsIGxvY2F0aW9uLm9yaWdpbiB3aWxsIGJlIGRlZmluZWQuIEhlcmUgd2UgYWxsb3cgZm9yIE5vZGVKUy5cblxuYXN5bmMgZnVuY3Rpb24gcmVzcG9uc2VIYW5kbGVyKHJlc3BvbnNlKSB7XG4gIC8vIFJlamVjdCBpZiBzZXJ2ZXIgZG9lcywgZWxzZSByZXNwb25zZS50ZXh0KCkuXG4gIGlmIChyZXNwb25zZS5zdGF0dXMgPT09IDQwNCkgcmV0dXJuICcnO1xuICBpZiAoIXJlc3BvbnNlLm9rKSByZXR1cm4gUHJvbWlzZS5yZWplY3QocmVzcG9uc2Uuc3RhdHVzVGV4dCk7XG4gIGxldCB0ZXh0ID0gYXdhaXQgcmVzcG9uc2UudGV4dCgpO1xuICBpZiAoIXRleHQpIHJldHVybiB0ZXh0OyAvLyBSZXN1bHQgb2Ygc3RvcmUgY2FuIGJlIGVtcHR5LlxuICByZXR1cm4gSlNPTi5wYXJzZSh0ZXh0KTtcbn1cblxuY29uc3QgU3RvcmFnZSA9IHtcbiAgZ2V0IG9yaWdpbigpIHsgcmV0dXJuIG9yaWdpbjsgfSxcbiAgdXJpKGNvbGxlY3Rpb25OYW1lLCB0YWcpIHtcbiAgICAvLyBQYXRobmFtZSBleHBlY3RlZCBieSBvdXIgc2lnbmVkLWNsb3VkLXNlcnZlci5cbiAgICByZXR1cm4gYCR7b3JpZ2lufS9kYi8ke2NvbGxlY3Rpb25OYW1lfS8ke3RhZ30uanNvbmA7IC8vIGZpeG1lIG9yaWdpblxuICB9LFxuICBzdG9yZShjb2xsZWN0aW9uTmFtZSwgdGFnLCBzaWduYXR1cmUsIG9wdGlvbnMgPSB7fSkge1xuICAgIC8vIFN0b3JlIHRoZSBzaWduZWQgY29udGVudCBvbiB0aGUgc2lnbmVkLWNsb3VkLXNlcnZlciwgcmVqZWN0aW5nIGlmXG4gICAgLy8gdGhlIHNlcnZlciBpcyB1bmFibGUgdG8gdmVyaWZ5IHRoZSBzaWduYXR1cmUgZm9sbG93aW5nIHRoZSBydWxlcyBvZlxuICAgIC8vIGh0dHBzOi8va2lscm95LWNvZGUuZ2l0aHViLmlvL2Rpc3RyaWJ1dGVkLXNlY3VyaXR5LyNzdG9yaW5nLWtleXMtdXNpbmctdGhlLWNsb3VkLXN0b3JhZ2UtYXBpXG4gICAgcmV0dXJuIGZldGNoKHRoaXMudXJpKGNvbGxlY3Rpb25OYW1lLCB0YWcpLCB7XG4gICAgICBtZXRob2Q6ICdQVVQnLFxuICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoc2lnbmF0dXJlKSxcbiAgICAgIGhlYWRlcnM6IHsnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nLCAuLi4ob3B0aW9ucy5oZWFkZXJzIHx8IHt9KX1cbiAgICB9KS50aGVuKHJlc3BvbnNlSGFuZGxlcik7XG4gIH0sXG4gIHJldHJpZXZlKGNvbGxlY3Rpb25OYW1lLCB0YWcsIG9wdGlvbnMgPSB7fSkge1xuICAgIC8vIFdlIGRvIG5vdCB2ZXJpZnkgYW5kIGdldCB0aGUgb3JpZ2luYWwgZGF0YSBvdXQgaGVyZSwgYmVjYXVzZSB0aGUgY2FsbGVyIGhhc1xuICAgIC8vIHRoZSByaWdodCB0byBkbyBzbyB3aXRob3V0IHRydXN0aW5nIHVzLlxuICAgIHJldHVybiBmZXRjaCh0aGlzLnVyaShjb2xsZWN0aW9uTmFtZSwgdGFnKSwge1xuICAgICAgY2FjaGU6ICdkZWZhdWx0JyxcbiAgICAgIGhlYWRlcnM6IHsnQWNjZXB0JzogJ2FwcGxpY2F0aW9uL2pzb24nLCAuLi4ob3B0aW9ucy5oZWFkZXJzIHx8IHt9KX1cbiAgICB9KS50aGVuKHJlc3BvbnNlSGFuZGxlcik7XG4gIH1cbn07XG5leHBvcnQgZGVmYXVsdCBTdG9yYWdlO1xuIiwiaW1wb3J0IE11bHRpS3J5cHRvIGZyb20gJy4vbXVsdGlLcnlwdG8ubWpzJztcbmltcG9ydCBMb2NhbENvbGxlY3Rpb24gZnJvbSAnI2xvY2FsU3RvcmUnO1xuaW1wb3J0IHtnZXRVc2VyRGV2aWNlU2VjcmV0fSBmcm9tICcuL3NlY3JldC5tanMnO1xuaW1wb3J0IFN0b3JhZ2UgZnJvbSAnLi9zdG9yYWdlLm1qcyc7XG5cbmZ1bmN0aW9uIGVycm9yKHRlbXBsYXRlRnVuY3Rpb24sIHRhZywgY2F1c2UgPSB1bmRlZmluZWQpIHtcbiAgLy8gRm9ybWF0cyB0YWcgKGUuZy4sIHNob3J0ZW5zIGl0KSBhbmQgZ2l2ZXMgaXQgdG8gdGVtcGxhdGVGdW5jdGlvbih0YWcpIHRvIGdldFxuICAvLyBhIHN1aXRhYmxlIGVycm9yIG1lc3NhZ2UuIEFuc3dlcnMgYSByZWplY3RlZCBwcm9taXNlIHdpdGggdGhhdCBFcnJvci5cbiAgbGV0IHNob3J0ZW5lZFRhZyA9IHRhZy5zbGljZSgwLCAxNikgKyBcIi4uLlwiLFxuICAgICAgbWVzc2FnZSA9IHRlbXBsYXRlRnVuY3Rpb24oc2hvcnRlbmVkVGFnKTtcbiAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBFcnJvcihtZXNzYWdlLCB7Y2F1c2V9KSk7XG59XG5mdW5jdGlvbiB1bmF2YWlsYWJsZSh0YWcpIHsgLy8gRG8gd2Ugd2FudCB0byBkaXN0aW5ndWlzaCBiZXR3ZWVuIGEgdGFnIGJlaW5nXG4gIC8vIHVuYXZhaWxhYmxlIGF0IGFsbCwgdnMganVzdCB0aGUgcHVibGljIGVuY3J5cHRpb24ga2V5IGJlaW5nIHVuYXZhaWxhYmxlP1xuICAvLyBSaWdodCBub3cgd2UgZG8gbm90IGRpc3Rpbmd1aXNoLCBhbmQgdXNlIHRoaXMgZm9yIGJvdGguXG4gIHJldHVybiBlcnJvcih0YWcgPT4gYFRoZSB0YWcgJHt0YWd9IGlzIG5vdCBhdmFpbGFibGUuYCwgdGFnKTtcbn1cblxuZXhwb3J0IGNsYXNzIEtleVNldCB7XG4gIC8vIEEgS2V5U2V0IG1haW50YWlucyB0d28gcHJpdmF0ZSBrZXlzOiBzaWduaW5nS2V5IGFuZCBkZWNyeXB0aW5nS2V5LlxuICAvLyBTZWUgaHR0cHM6Ly9raWxyb3ktY29kZS5naXRodWIuaW8vZGlzdHJpYnV0ZWQtc2VjdXJpdHkvZG9jcy9pbXBsZW1lbnRhdGlvbi5odG1sI3dlYi13b3JrZXItYW5kLWlmcmFtZVxuXG4gIC8vIENhY2hpbmdcbiAgc3RhdGljIGtleVNldHMgPSB7fTtcbiAgc3RhdGljIGNhY2hlZCh0YWcpIHsgLy8gUmV0dXJuIGFuIGFscmVhZHkgcG9wdWxhdGVkIEtleVNldC5cbiAgICByZXR1cm4gdGhpcy5rZXlTZXRzW3RhZ107XG4gIH1cbiAgc3RhdGljIGNsZWFyKHRhZyA9IG51bGwpIHsgLy8gUmVtb3ZlIGFsbCBLZXlTZXQgaW5zdGFuY2VzIG9yIGp1c3QgdGhlIHNwZWNpZmllZCBvbmUsIGJ1dCBkb2VzIG5vdCBkZXN0cm95IHRoZWlyIHN0b3JhZ2UuXG4gICAgaWYgKCF0YWcpIHJldHVybiBLZXlTZXQua2V5U2V0cyA9IHt9O1xuICAgIGRlbGV0ZSBLZXlTZXQua2V5U2V0c1t0YWddXG4gIH1cbiAgY29uc3RydWN0b3IodGFnKSB7XG4gICAgdGhpcy50YWcgPSB0YWc7XG4gICAgdGhpcy5tZW1iZXJUYWdzID0gW107IC8vIFVzZWQgd2hlbiByZWN1cnNpdmVseSBkZXN0cm95aW5nLlxuICAgIEtleVNldC5rZXlTZXRzW3RhZ10gPSB0aGlzOyAvLyBDYWNoZSBpdC5cbiAgfVxuICAvLyBhcGkubWpzIHByb3ZpZGVzIHRoZSBzZXR0ZXIgdG8gY2hhbmdlcyB0aGVzZSwgYW5kIHdvcmtlci5tanMgZXhlcmNpc2VzIGl0IGluIGJyb3dzZXJzLlxuICBzdGF0aWMgZ2V0VXNlckRldmljZVNlY3JldCA9IGdldFVzZXJEZXZpY2VTZWNyZXQ7XG4gIHN0YXRpYyBTdG9yYWdlID0gU3RvcmFnZTtcblxuICAvLyBQcmluY2lwbGUgb3BlcmF0aW9ucy5cbiAgc3RhdGljIGFzeW5jIGNyZWF0ZSh3cmFwcGluZ0RhdGEpIHsgLy8gQ3JlYXRlIGEgcGVyc2lzdGVkIEtleVNldCBvZiB0aGUgY29ycmVjdCB0eXBlLCBwcm9taXNpbmcgdGhlIG5ld2x5IGNyZWF0ZWQgdGFnLlxuICAgIGxldCB7dGltZSwgLi4ua2V5c30gPSBhd2FpdCB0aGlzLmNyZWF0ZUtleXMod3JhcHBpbmdEYXRhKSxcbiAgICAgICAge3RhZ30gPSBrZXlzO1xuICAgIGF3YWl0IHRoaXMucGVyc2lzdCh0YWcsIGtleXMsIHdyYXBwaW5nRGF0YSwgdGltZSk7XG4gICAgcmV0dXJuIHRhZztcbiAgfVxuICBhc3luYyBkZXN0cm95KG9wdGlvbnMgPSB7fSkgeyAvLyBUZXJtaW5hdGVzIHRoaXMga2V5U2V0IGFuZCBhc3NvY2lhdGVkIHN0b3JhZ2UsIGFuZCBzYW1lIGZvciBPV05FRCByZWN1cnNpdmVNZW1iZXJzIGlmIGFza2VkLlxuICAgIGxldCB7dGFnLCBtZW1iZXJUYWdzLCBzaWduaW5nS2V5fSA9IHRoaXMsXG4gICAgICAgIGNvbnRlbnQgPSBcIlwiLCAvLyBTaG91bGQgc3RvcmFnZSBoYXZlIGEgc2VwYXJhdGUgb3BlcmF0aW9uIHRvIGRlbGV0ZSwgb3RoZXIgdGhhbiBzdG9yaW5nIGVtcHR5P1xuICAgICAgICBzaWduYXR1cmUgPSBhd2FpdCB0aGlzLmNvbnN0cnVjdG9yLnNpZ25Gb3JTdG9yYWdlKHttZXNzYWdlOiBjb250ZW50LCB0YWcsIG1lbWJlclRhZ3MsIHNpZ25pbmdLZXksIHRpbWU6IERhdGUubm93KCl9KTtcbiAgICBhd2FpdCB0aGlzLmNvbnN0cnVjdG9yLnN0b3JlKCdFbmNyeXB0aW9uS2V5JywgdGFnLCBzaWduYXR1cmUpO1xuICAgIGF3YWl0IHRoaXMuY29uc3RydWN0b3Iuc3RvcmUodGhpcy5jb25zdHJ1Y3Rvci5jb2xsZWN0aW9uLCB0YWcsIHNpZ25hdHVyZSk7XG4gICAgdGhpcy5jb25zdHJ1Y3Rvci5jbGVhcih0YWcpO1xuICAgIGlmICghb3B0aW9ucy5yZWN1cnNpdmVNZW1iZXJzKSByZXR1cm47XG4gICAgYXdhaXQgUHJvbWlzZS5hbGxTZXR0bGVkKHRoaXMubWVtYmVyVGFncy5tYXAoYXN5bmMgbWVtYmVyVGFnID0+IHtcbiAgICAgIGxldCBtZW1iZXJLZXlTZXQgPSBhd2FpdCBLZXlTZXQuZW5zdXJlKG1lbWJlclRhZyk7XG4gICAgICBhd2FpdCBtZW1iZXJLZXlTZXQuZGVzdHJveShvcHRpb25zKTtcbiAgICB9KSk7XG4gIH1cbiAgZGVjcnlwdChlbmNyeXB0ZWQsIG9wdGlvbnMpIHsgLy8gUHJvbWlzZSB7cGF5bG9hZCwgdGV4dCwganNvbn0gYXMgYXBwcm9wcmlhdGUuXG4gICAgbGV0IHt0YWcsIGRlY3J5cHRpbmdLZXl9ID0gdGhpcyxcbiAgICAgICAga2V5ID0gZW5jcnlwdGVkLnJlY2lwaWVudHMgPyB7W3RhZ106IGRlY3J5cHRpbmdLZXl9IDogZGVjcnlwdGluZ0tleTtcbiAgICByZXR1cm4gTXVsdGlLcnlwdG8uZGVjcnlwdChrZXksIGVuY3J5cHRlZCwgb3B0aW9ucyk7XG4gIH1cbiAgLy8gc2lnbiBhcyBlaXRoZXIgY29tcGFjdCBvciBtdWx0aUtleSBnZW5lcmFsIEpXUy5cbiAgLy8gVGhlcmUncyBzb21lIGNvbXBsZXhpdHkgaGVyZSBhcm91bmQgYmVpbmcgYWJsZSB0byBwYXNzIGluIG1lbWJlclRhZ3MgYW5kIHNpZ25pbmdLZXkgd2hlbiB0aGUga2V5U2V0IGlzXG4gIC8vIGJlaW5nIGNyZWF0ZWQgYW5kIGRvZXNuJ3QgeWV0IGV4aXN0LlxuICBzdGF0aWMgYXN5bmMgc2lnbihtZXNzYWdlLCB7dGFncyA9IFtdLCB0ZWFtOmlzcywgbWVtYmVyOmFjdCwgdGltZTppYXQgPSBpc3MgJiYgRGF0ZS5ub3coKSxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1lbWJlclRhZ3MsIHNpZ25pbmdLZXksXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAuLi5vcHRpb25zfSkge1xuICAgIGlmIChpc3MgJiYgIWFjdCkgeyAvLyBTdXBwbHkgdGhlIHZhbHVlXG4gICAgICBpZiAoIW1lbWJlclRhZ3MpIG1lbWJlclRhZ3MgPSAoYXdhaXQgS2V5U2V0LmVuc3VyZShpc3MpKS5tZW1iZXJUYWdzO1xuICAgICAgbGV0IGNhY2hlZE1lbWJlciA9IG1lbWJlclRhZ3MuZmluZCh0YWcgPT4gdGhpcy5jYWNoZWQodGFnKSk7XG4gICAgICBhY3QgPSBjYWNoZWRNZW1iZXIgfHwgYXdhaXQgUHJvbWlzZS5hbnkobWVtYmVyVGFncy5tYXAodGFnID0+IEtleVNldC5lbnN1cmUodGFnKSkpLnRoZW4oa2V5U2V0ID0+IGtleVNldC50YWcpXG4gICAgfVxuICAgIGlmIChpc3MgJiYgIXRhZ3MuaW5jbHVkZXMoaXNzKSkgdGFncyA9IFtpc3MsIC4uLnRhZ3NdOyAvLyBNdXN0IGJlIGZpcnN0XG4gICAgaWYgKGFjdCAmJiAhdGFncy5pbmNsdWRlcyhhY3QpKSB0YWdzID0gWy4uLnRhZ3MsIGFjdF07XG5cbiAgICBsZXQga2V5ID0gYXdhaXQgdGhpcy5wcm9kdWNlS2V5KHRhZ3MsIGFzeW5jIHRhZyA9PiB7XG4gICAgICAvLyBVc2Ugc3BlY2lmaWVkIHNpZ25pbmdLZXkgKGlmIGFueSkgZm9yIHRoZSBmaXJzdCBvbmUuXG4gICAgICBsZXQga2V5ID0gc2lnbmluZ0tleSB8fCAoYXdhaXQgS2V5U2V0LmVuc3VyZSh0YWcpKS5zaWduaW5nS2V5O1xuICAgICAgc2lnbmluZ0tleSA9IG51bGw7XG4gICAgICByZXR1cm4ga2V5O1xuICAgIH0sIG9wdGlvbnMpO1xuICAgIHJldHVybiBNdWx0aUtyeXB0by5zaWduKGtleSwgbWVzc2FnZSwge2lzcywgYWN0LCBpYXQsIC4uLm9wdGlvbnN9KTtcbiAgfVxuXG4gIC8vIFZlcmlmeSBpbiB0aGUgbm9ybWFsIHdheSwgYW5kIHRoZW4gY2hlY2sgZGVlcGx5IGlmIGFza2VkLlxuICBzdGF0aWMgYXN5bmMgdmVyaWZ5KHNpZ25hdHVyZSwgdGFncywgb3B0aW9ucykge1xuICAgIGxldCBpc0NvbXBhY3QgPSAhc2lnbmF0dXJlLnNpZ25hdHVyZXMsXG4gICAgICAgIGtleSA9IGF3YWl0IHRoaXMucHJvZHVjZUtleSh0YWdzLCB0YWcgPT4gS2V5U2V0LnZlcmlmeWluZ0tleSh0YWcpLCBvcHRpb25zLCBpc0NvbXBhY3QpLFxuICAgICAgICByZXN1bHQgPSBhd2FpdCBNdWx0aUtyeXB0by52ZXJpZnkoa2V5LCBzaWduYXR1cmUsIG9wdGlvbnMpLFxuICAgICAgICBtZW1iZXJUYWcgPSBvcHRpb25zLm1lbWJlciA9PT0gdW5kZWZpbmVkID8gcmVzdWx0Py5wcm90ZWN0ZWRIZWFkZXIuYWN0IDogb3B0aW9ucy5tZW1iZXIsXG4gICAgICAgIG5vdEJlZm9yZSA9IG9wdGlvbnMubm90QmVmb3JlO1xuICAgIGZ1bmN0aW9uIGV4aXQobGFiZWwpIHtcbiAgICAgIGlmIChvcHRpb25zLmhhcmRFcnJvcikgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBFcnJvcihsYWJlbCkpO1xuICAgIH1cbiAgICBpZiAoIXJlc3VsdCkgcmV0dXJuIGV4aXQoJ0luY29ycmVjdCBzaWduYXR1cmUuJyk7XG4gICAgaWYgKG1lbWJlclRhZykge1xuICAgICAgaWYgKG9wdGlvbnMubWVtYmVyID09PSAndGVhbScpIHtcbiAgICAgICAgbWVtYmVyVGFnID0gcmVzdWx0LnByb3RlY3RlSGVhZGVyLmFjdDtcbiAgICAgICAgaWYgKCFtZW1iZXJUYWcpIHJldHVybiBleGl0KCdObyBtZW1iZXIgaWRlbnRpZmllZCBpbiBzaWduYXR1cmUuJyk7XG4gICAgICB9XG4gICAgICBpZiAoIXRhZ3MuaW5jbHVkZXMobWVtYmVyVGFnKSkgeyAvLyBBZGQgdG8gdGFncyBhbmQgcmVzdWx0IGlmIG5vdCBhbHJlYWR5IHByZXNlbnRcbiAgICAgICAgbGV0IG1lbWJlcktleSA9IGF3YWl0IEtleVNldC52ZXJpZnlpbmdLZXkobWVtYmVyVGFnKSxcbiAgICAgICAgICAgIG1lbWJlck11bHRpa2V5ID0ge1ttZW1iZXJUYWddOiBtZW1iZXJLZXl9LFxuICAgICAgICAgICAgYXV4ID0gYXdhaXQgTXVsdGlLcnlwdG8udmVyaWZ5KG1lbWJlck11bHRpa2V5LCBzaWduYXR1cmUsIG9wdGlvbnMpO1xuICAgICAgICBpZiAoIWF1eCkgcmV0dXJuIGV4aXQoJ0luY29ycmVjdCBtZW1iZXIgc2lnbmF0dXJlLicpO1xuICAgICAgICB0YWdzLnB1c2gobWVtYmVyVGFnKTtcbiAgICAgICAgcmVzdWx0LnNpZ25lcnMuZmluZChzaWduZXIgPT4gc2lnbmVyLnByb3RlY3RlZEhlYWRlci5raWQgPT09IG1lbWJlclRhZykucGF5bG9hZCA9IHJlc3VsdC5wYXlsb2FkO1xuICAgICAgfVxuICAgIH1cbiAgICBpZiAobWVtYmVyVGFnIHx8IG5vdEJlZm9yZSA9PT0gJ3RlYW0nKSB7XG4gICAgICBsZXQgdGVhbVRhZyA9IHJlc3VsdC5wcm90ZWN0ZWRIZWFkZXIuaXNzIHx8IHJlc3VsdC5wcm90ZWN0ZWRIZWFkZXIua2lkLCAvLyBNdWx0aSBvciBzaW5nbGUgY2FzZS5cbiAgICAgICAgICB2ZXJpZmllZEpXUyA9IGF3YWl0IHRoaXMucmV0cmlldmUoVGVhbUtleVNldC5jb2xsZWN0aW9uLCB0ZWFtVGFnKSxcbiAgICAgICAgICBqd2UgPSB2ZXJpZmllZEpXUz8uanNvbjtcbiAgICAgIGlmIChtZW1iZXJUYWcgJiYgIXRlYW1UYWcpIHJldHVybiBleGl0KCdObyB0ZWFtIG9yIG1haW4gdGFnIGlkZW50aWZpZWQgaW4gc2lnbmF0dXJlJyk7XG4gICAgICBpZiAobWVtYmVyVGFnICYmIGp3ZSAmJiAhandlLnJlY2lwaWVudHMuZmluZChtZW1iZXIgPT4gbWVtYmVyLmhlYWRlci5raWQgPT09IG1lbWJlclRhZykpIHJldHVybiBleGl0KCdTaWduZXIgaXMgbm90IGEgbWVtYmVyLicpO1xuICAgICAgaWYgKG5vdEJlZm9yZSA9PT0gJ3RlYW0nKSBub3RCZWZvcmUgPSB2ZXJpZmllZEpXUz8ucHJvdGVjdGVkSGVhZGVyLmlhdFxuICAgICAgICB8fCAoYXdhaXQgdGhpcy5yZXRyaWV2ZSgnRW5jcnlwdGlvbktleScsIHRlYW1UYWcpKT8ucHJvdGVjdGVkSGVhZGVyLmlhdDtcbiAgICB9XG4gICAgaWYgKG5vdEJlZm9yZSkge1xuICAgICAgbGV0IHtpYXR9ID0gcmVzdWx0LnByb3RlY3RlZEhlYWRlcjtcbiAgICAgIGlmIChpYXQgPCBub3RCZWZvcmUpIHJldHVybiBleGl0KCdTaWduYXR1cmUgcHJlZGF0ZXMgcmVxdWlyZWQgdGltZXN0YW1wLicpO1xuICAgIH1cbiAgICAvLyBFYWNoIHNpZ25lciBzaG91bGQgbm93IGJlIHZlcmlmaWVkLlxuICAgIGlmICgocmVzdWx0LnNpZ25lcnM/LmZpbHRlcihzaWduZXIgPT4gc2lnbmVyLnBheWxvYWQpLmxlbmd0aCB8fCAxKSAhPT0gdGFncy5sZW5ndGgpIHJldHVybiBleGl0KCdVbnZlcmlmaWVkIHNpZ25lcicpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICAvLyBLZXkgbWFuYWdlbWVudFxuICBzdGF0aWMgYXN5bmMgcHJvZHVjZUtleSh0YWdzLCBwcm9kdWNlciwgb3B0aW9ucywgdXNlU2luZ2xlS2V5ID0gdGFncy5sZW5ndGggPT09IDEpIHtcbiAgICAvLyBQcm9taXNlIGEga2V5IG9yIG11bHRpS2V5LCBhcyBkZWZpbmVkIGJ5IHByb2R1Y2VyKHRhZykgZm9yIGVhY2gga2V5LlxuICAgIGlmICh1c2VTaW5nbGVLZXkpIHtcbiAgICAgIGxldCB0YWcgPSB0YWdzWzBdO1xuICAgICAgb3B0aW9ucy5raWQgPSB0YWc7ICAgLy8gQmFzaGVzIG9wdGlvbnMgaW4gdGhlIHNpbmdsZS1rZXkgY2FzZSwgYmVjYXVzZSBtdWx0aUtleSdzIGhhdmUgdGhlaXIgb3duLlxuICAgICAgcmV0dXJuIHByb2R1Y2VyKHRhZyk7XG4gICAgfVxuICAgIGxldCBrZXkgPSB7fSxcbiAgICAgICAga2V5cyA9IGF3YWl0IFByb21pc2UuYWxsKHRhZ3MubWFwKHRhZyA9PiBwcm9kdWNlcih0YWcpKSk7XG4gICAgLy8gVGhpcyBpc24ndCBkb25lIGluIG9uZSBzdGVwLCBiZWNhdXNlIHdlJ2QgbGlrZSAoZm9yIGRlYnVnZ2luZyBhbmQgdW5pdCB0ZXN0cykgdG8gbWFpbnRhaW4gYSBwcmVkaWN0YWJsZSBvcmRlci5cbiAgICB0YWdzLmZvckVhY2goKHRhZywgaW5kZXgpID0+IGtleVt0YWddID0ga2V5c1tpbmRleF0pO1xuICAgIHJldHVybiBrZXk7XG4gIH1cbiAgLy8gVGhlIGNvcnJlc3BvbmRpbmcgcHVibGljIGtleXMgYXJlIGF2YWlsYWJsZSBwdWJsaWNhbGx5LCBvdXRzaWRlIHRoZSBrZXlTZXQuXG4gIHN0YXRpYyB2ZXJpZnlpbmdLZXkodGFnKSB7IC8vIFByb21pc2UgdGhlIG9yZGluYXJ5IHNpbmd1bGFyIHB1YmxpYyBrZXkgY29ycmVzcG9uZGluZyB0byB0aGUgc2lnbmluZyBrZXksIGRpcmVjdGx5IGZyb20gdGhlIHRhZyB3aXRob3V0IHJlZmVyZW5jZSB0byBzdG9yYWdlLlxuICAgIHJldHVybiBNdWx0aUtyeXB0by5pbXBvcnRSYXcodGFnKS5jYXRjaCgoKSA9PiB1bmF2YWlsYWJsZSh0YWcpKTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgZW5jcnlwdGluZ0tleSh0YWcpIHsgLy8gUHJvbWlzZSB0aGUgb3JkaW5hcnkgc2luZ3VsYXIgcHVibGljIGtleSBjb3JyZXNwb25kaW5nIHRvIHRoZSBkZWNyeXB0aW9uIGtleSwgd2hpY2ggZGVwZW5kcyBvbiBwdWJsaWMgc3RvcmFnZS5cbiAgICBsZXQgZXhwb3J0ZWRQdWJsaWNLZXkgPSBhd2FpdCB0aGlzLnJldHJpZXZlKCdFbmNyeXB0aW9uS2V5JywgdGFnKTtcbiAgICBpZiAoIWV4cG9ydGVkUHVibGljS2V5KSByZXR1cm4gdW5hdmFpbGFibGUodGFnKTtcbiAgICByZXR1cm4gYXdhaXQgTXVsdGlLcnlwdG8uaW1wb3J0SldLKGV4cG9ydGVkUHVibGljS2V5Lmpzb24pO1xuICB9XG4gIHN0YXRpYyBhc3luYyBjcmVhdGVLZXlzKG1lbWJlclRhZ3MpIHsgLy8gUHJvbWlzZSBhIG5ldyB0YWcgYW5kIHByaXZhdGUga2V5cywgYW5kIHN0b3JlIHRoZSBlbmNyeXB0aW5nIGtleS5cbiAgICBsZXQge3B1YmxpY0tleTp2ZXJpZnlpbmdLZXksIHByaXZhdGVLZXk6c2lnbmluZ0tleX0gPSBhd2FpdCBNdWx0aUtyeXB0by5nZW5lcmF0ZVNpZ25pbmdLZXkoKSxcbiAgICAgICAge3B1YmxpY0tleTplbmNyeXB0aW5nS2V5LCBwcml2YXRlS2V5OmRlY3J5cHRpbmdLZXl9ID0gYXdhaXQgTXVsdGlLcnlwdG8uZ2VuZXJhdGVFbmNyeXB0aW5nS2V5KCksXG4gICAgICAgIHRhZyA9IGF3YWl0IE11bHRpS3J5cHRvLmV4cG9ydFJhdyh2ZXJpZnlpbmdLZXkpLFxuICAgICAgICBleHBvcnRlZEVuY3J5cHRpbmdLZXkgPSBhd2FpdCBNdWx0aUtyeXB0by5leHBvcnRKV0soZW5jcnlwdGluZ0tleSksXG4gICAgICAgIHRpbWUgPSBEYXRlLm5vdygpLFxuICAgICAgICBzaWduYXR1cmUgPSBhd2FpdCB0aGlzLnNpZ25Gb3JTdG9yYWdlKHttZXNzYWdlOiBleHBvcnRlZEVuY3J5cHRpbmdLZXksIHRhZywgc2lnbmluZ0tleSwgbWVtYmVyVGFncywgdGltZX0pO1xuICAgIGF3YWl0IHRoaXMuc3RvcmUoJ0VuY3J5cHRpb25LZXknLCB0YWcsIHNpZ25hdHVyZSk7XG4gICAgcmV0dXJuIHtzaWduaW5nS2V5LCBkZWNyeXB0aW5nS2V5LCB0YWcsIHRpbWV9O1xuICB9XG4gIHN0YXRpYyBnZXRXcmFwcGVkKHRhZykgeyAvLyBQcm9taXNlIHRoZSB3cmFwcGVkIGtleSBhcHByb3ByaWF0ZSBmb3IgdGhpcyBjbGFzcy5cbiAgICByZXR1cm4gdGhpcy5yZXRyaWV2ZSh0aGlzLmNvbGxlY3Rpb24sIHRhZyk7XG4gIH1cbiAgc3RhdGljIGFzeW5jIGVuc3VyZSh0YWcpIHsgLy8gUHJvbWlzZSB0byByZXNvbHZlIHRvIGEgdmFsaWQga2V5U2V0LCBlbHNlIHJlamVjdC5cbiAgICBsZXQga2V5U2V0ID0gdGhpcy5jYWNoZWQodGFnKSxcbiAgICAgICAgc3RvcmVkID0gYXdhaXQgRGV2aWNlS2V5U2V0LmdldFdyYXBwZWQodGFnKTtcbiAgICBpZiAoc3RvcmVkKSB7XG4gICAgICBrZXlTZXQgPSBuZXcgRGV2aWNlS2V5U2V0KHRhZyk7XG4gICAgfSBlbHNlIGlmICgoc3RvcmVkID0gYXdhaXQgVGVhbUtleVNldC5nZXRXcmFwcGVkKHRhZykpKSB7XG4gICAgICBrZXlTZXQgPSBuZXcgVGVhbUtleVNldCh0YWcpO1xuICAgIH0gZWxzZSBpZiAoKHN0b3JlZCA9IGF3YWl0IFJlY292ZXJ5S2V5U2V0LmdldFdyYXBwZWQodGFnKSkpIHtcbiAgICAgIGtleVNldCA9IG5ldyBSZWNvdmVyeUtleVNldCh0YWcpO1xuICAgIH1cbiAgICAvLyBJZiB0aGluZ3MgaGF2ZW4ndCBjaGFuZ2VkLCBkb24ndCBib3RoZXIgd2l0aCBzZXRVbndyYXBwZWQuXG4gICAgaWYgKGtleVNldD8uY2FjaGVkICYmIGtleVNldC5jYWNoZWQgPT09IHN0b3JlZCAmJiBrZXlTZXQuZGVjcnlwdGluZ0tleSAmJiBrZXlTZXQuc2lnbmluZ0tleSkgcmV0dXJuIGtleVNldDtcbiAgICBpZiAoc3RvcmVkKSBrZXlTZXQuY2FjaGVkID0gc3RvcmVkO1xuICAgIGVsc2UgeyAvLyBOb3QgZm91bmQuIENvdWxkIGJlIGEgYm9ndXMgdGFnLCBvciBvbmUgb24gYW5vdGhlciBjb21wdXRlci5cbiAgICAgIHRoaXMuY2xlYXIodGFnKTtcbiAgICAgIHJldHVybiB1bmF2YWlsYWJsZSh0YWcpO1xuICAgIH1cbiAgICByZXR1cm4ga2V5U2V0LnVud3JhcChrZXlTZXQuY2FjaGVkKS50aGVuKFxuICAgICAgdW53cmFwcGVkID0+IE9iamVjdC5hc3NpZ24oa2V5U2V0LCB1bndyYXBwZWQpLFxuICAgICAgY2F1c2UgPT4ge1xuICAgICAgICB0aGlzLmNsZWFyKGtleVNldC50YWcpXG4gICAgICAgIHJldHVybiBlcnJvcih0YWcgPT4gYFlvdSBkbyBub3QgaGF2ZSBhY2Nlc3MgdG8gdGhlIHByaXZhdGUga2V5IGZvciAke3RhZ30uYCwga2V5U2V0LnRhZywgY2F1c2UpO1xuICAgICAgfSk7XG4gIH1cbiAgc3RhdGljIGFzeW5jIHBlcnNpc3QodGFnLCBrZXlzLCB3cmFwcGluZ0RhdGEsIHRpbWUgPSBEYXRlLm5vdygpLCBtZW1iZXJUYWdzID0gd3JhcHBpbmdEYXRhKSB7IC8vIFByb21pc2UgdG8gd3JhcCBhIHNldCBvZiBrZXlzIGZvciB0aGUgd3JhcHBpbmdEYXRhIG1lbWJlcnMsIGFuZCBwZXJzaXN0IGJ5IHRhZy5cbiAgICBsZXQge3NpZ25pbmdLZXl9ID0ga2V5cyxcbiAgICAgICAgd3JhcHBlZCA9IGF3YWl0IHRoaXMud3JhcChrZXlzLCB3cmFwcGluZ0RhdGEpLFxuICAgICAgICBzaWduYXR1cmUgPSBhd2FpdCB0aGlzLnNpZ25Gb3JTdG9yYWdlKHttZXNzYWdlOiB3cmFwcGVkLCB0YWcsIHNpZ25pbmdLZXksIG1lbWJlclRhZ3MsIHRpbWV9KTtcbiAgICBhd2FpdCB0aGlzLnN0b3JlKHRoaXMuY29sbGVjdGlvbiwgdGFnLCBzaWduYXR1cmUpO1xuICB9XG5cbiAgLy8gSW50ZXJhY3Rpb25zIHdpdGggdGhlIGNsb3VkIG9yIGxvY2FsIHN0b3JhZ2UuXG4gIHN0YXRpYyBhc3luYyBzdG9yZShjb2xsZWN0aW9uTmFtZSwgdGFnLCBzaWduYXR1cmUpIHsgLy8gU3RvcmUgc2lnbmF0dXJlLlxuICAgIGlmIChjb2xsZWN0aW9uTmFtZSA9PT0gRGV2aWNlS2V5U2V0LmNvbGxlY3Rpb24pIHtcbiAgICAgIC8vIFdlIGNhbGxlZCB0aGlzLiBObyBuZWVkIHRvIHZlcmlmeSBoZXJlLiBCdXQgc2VlIHJldHJpZXZlKCkuXG4gICAgICBpZiAoTXVsdGlLcnlwdG8uaXNFbXB0eUpXU1BheWxvYWQoc2lnbmF0dXJlKSkgcmV0dXJuIExvY2FsU3RvcmUucmVtb3ZlKHRhZyk7XG4gICAgICByZXR1cm4gTG9jYWxTdG9yZS5zdG9yZSh0YWcsIHNpZ25hdHVyZSk7XG4gICAgfVxuICAgIHJldHVybiBLZXlTZXQuU3RvcmFnZS5zdG9yZShjb2xsZWN0aW9uTmFtZSwgdGFnLCBzaWduYXR1cmUpO1xuICB9XG4gIHN0YXRpYyBhc3luYyByZXRyaWV2ZShjb2xsZWN0aW9uTmFtZSwgdGFnKSB7ICAvLyBHZXQgYmFjayBhIHZlcmlmaWVkIHJlc3VsdC5cbiAgICBsZXQgcHJvbWlzZSA9IChjb2xsZWN0aW9uTmFtZSA9PT0gRGV2aWNlS2V5U2V0LmNvbGxlY3Rpb24pID8gTG9jYWxTdG9yZS5yZXRyaWV2ZSh0YWcpIDogS2V5U2V0LlN0b3JhZ2UucmV0cmlldmUoY29sbGVjdGlvbk5hbWUsIHRhZyksXG4gICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IHByb21pc2UsXG4gICAgICAgIGtleSA9IHNpZ25hdHVyZSAmJiBhd2FpdCBLZXlTZXQudmVyaWZ5aW5nS2V5KHRhZyk7XG4gICAgaWYgKCFzaWduYXR1cmUpIHJldHVybjtcbiAgICAvLyBXaGlsZSB3ZSByZWx5IG9uIHRoZSBTdG9yYWdlIGFuZCBMb2NhbFN0b3JlIGltcGxlbWVudGF0aW9ucyB0byBkZWVwbHkgY2hlY2sgc2lnbmF0dXJlcyBkdXJpbmcgd3JpdGUsXG4gICAgLy8gaGVyZSB3ZSBzdGlsbCBkbyBhIHNoYWxsb3cgdmVyaWZpY2F0aW9uIGNoZWNrIGp1c3QgdG8gbWFrZSBzdXJlIHRoYXQgdGhlIGRhdGEgaGFzbid0IGJlZW4gbWVzc2VkIHdpdGggYWZ0ZXIgd3JpdGUuXG4gICAgaWYgKHNpZ25hdHVyZS5zaWduYXR1cmVzKSBrZXkgPSB7W3RhZ106IGtleX07IC8vIFByZXBhcmUgYSBtdWx0aS1rZXlcbiAgICByZXR1cm4gYXdhaXQgTXVsdGlLcnlwdG8udmVyaWZ5KGtleSwgc2lnbmF0dXJlKTtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgU2VjcmV0S2V5U2V0IGV4dGVuZHMgS2V5U2V0IHsgLy8gS2V5cyBhcmUgZW5jcnlwdGVkIGJhc2VkIG9uIGEgc3ltbWV0cmljIHNlY3JldC5cbiAgc3RhdGljIHNpZ25Gb3JTdG9yYWdlKHttZXNzYWdlLCB0YWcsIHNpZ25pbmdLZXksIHRpbWV9KSB7XG4gICAgLy8gQ3JlYXRlIGEgc2ltcGxlIHNpZ25hdHVyZSB0aGF0IGRvZXMgbm90IHNwZWNpZnkgaXNzIG9yIGFjdC5cbiAgICAvLyBUaGVyZSBhcmUgbm8gdHJ1ZSBtZW1iZXJUYWdzIHRvIHBhc3Mgb24gYW5kIHRoZXkgYXJlIG5vdCB1c2VkIGluIHNpbXBsZSBzaWduYXR1cmVzLiBIb3dldmVyLCB0aGUgY2FsbGVyIGRvZXNcbiAgICAvLyBnZW5lcmljYWxseSBwYXNzIHdyYXBwaW5nRGF0YSBhcyBtZW1iZXJUYWdzLCBhbmQgZm9yIFJlY292ZXJ5S2V5U2V0cywgd3JhcHBpbmdEYXRhIGlzIHRoZSBwcm9tcHQuIFxuICAgIC8vIFdlIGRvbid0IHN0b3JlIG11bHRpcGxlIHRpbWVzLCBzbyB0aGVyZSdzIGFsc28gbm8gbmVlZCBmb3IgaWF0ICh3aGljaCBjYW4gYmUgdXNlZCB0byBwcmV2ZW50IHJlcGxheSBhdHRhY2tzKS5cbiAgICByZXR1cm4gdGhpcy5zaWduKG1lc3NhZ2UsIHt0YWdzOiBbdGFnXSwgc2lnbmluZ0tleSwgdGltZX0pO1xuICB9XG4gIHN0YXRpYyBhc3luYyB3cmFwKGtleXMsIHdyYXBwaW5nRGF0YSA9ICcnKSB7IC8vIEVuY3J5cHQga2V5c2V0IGJ5IGdldFVzZXJEZXZpY2VTZWNyZXQuXG4gICAgbGV0IHtkZWNyeXB0aW5nS2V5LCBzaWduaW5nS2V5LCB0YWd9ID0ga2V5cyxcbiAgICAgICAgdmF1bHRLZXkgPSB7ZGVjcnlwdGluZ0tleSwgc2lnbmluZ0tleX0sXG4gICAgICAgIHdyYXBwaW5nS2V5ID0ge1t3cmFwcGluZ0RhdGFdOiBhd2FpdCB0aGlzLmdldFNlY3JldCh0YWcsIHdyYXBwaW5nRGF0YSl9O1xuICAgIHJldHVybiBNdWx0aUtyeXB0by53cmFwS2V5KHZhdWx0S2V5LCB3cmFwcGluZ0tleSk7XG4gIH1cbiAgYXN5bmMgdW53cmFwKHdyYXBwZWRLZXkpIHsgLy8gRGVjcnlwdCBrZXlzZXQgYnkgZ2V0VXNlckRldmljZVNlY3JldC5cbiAgICBsZXQgcGFyc2VkID0gd3JhcHBlZEtleS5qc29uLFxuICAgICAgICBwcm9tcHQgPSBwYXJzZWQucmVjaXBpZW50c1swXS5oZWFkZXIua2lkLFxuICAgICAgICBzZWNyZXQgPSB7W3Byb21wdF06IGF3YWl0IHRoaXMuY29uc3RydWN0b3IuZ2V0U2VjcmV0KHRoaXMudGFnLCBwcm9tcHQpfSxcbiAgICAgICAgZXhwb3J0ZWQgPSAoYXdhaXQgTXVsdGlLcnlwdG8uZGVjcnlwdChzZWNyZXQsIHdyYXBwZWRLZXkuanNvbikpLmpzb247XG4gICAgcmV0dXJuIGF3YWl0IE11bHRpS3J5cHRvLmltcG9ydEpXSyhleHBvcnRlZCwge2RlY3J5cHRpbmdLZXk6ICdkZWNyeXB0Jywgc2lnbmluZ0tleTogJ3NpZ24nfSk7XG4gIH1cbiAgc3RhdGljIGFzeW5jIGdldFNlY3JldCh0YWcsIHByb21wdCkgeyAvLyBnZXRVc2VyRGV2aWNlU2VjcmV0IGZyb20gYXBwLlxuICAgIHJldHVybiBLZXlTZXQuZ2V0VXNlckRldmljZVNlY3JldCh0YWcsIHByb21wdCk7XG4gIH1cbn1cblxuIC8vIFRoZSB1c2VyJ3MgYW5zd2VyKHMpIHRvIGEgc2VjdXJpdHkgcXVlc3Rpb24gZm9ybXMgYSBzZWNyZXQsIGFuZCB0aGUgd3JhcHBlZCBrZXlzIGlzIHN0b3JlZCBpbiB0aGUgY2xvdWRlLlxuZXhwb3J0IGNsYXNzIFJlY292ZXJ5S2V5U2V0IGV4dGVuZHMgU2VjcmV0S2V5U2V0IHtcbiAgc3RhdGljIGNvbGxlY3Rpb24gPSAnS2V5UmVjb3ZlcnknO1xufVxuXG4vLyBBIEtleVNldCBjb3JyZXNwb25kaW5nIHRvIHRoZSBjdXJyZW50IGhhcmR3YXJlLiBXcmFwcGluZyBzZWNyZXQgY29tZXMgZnJvbSB0aGUgYXBwLlxuZXhwb3J0IGNsYXNzIERldmljZUtleVNldCBleHRlbmRzIFNlY3JldEtleVNldCB7XG4gIHN0YXRpYyBjb2xsZWN0aW9uID0gJ0RldmljZSc7XG59XG5jb25zdCBMb2NhbFN0b3JlID0gbmV3IExvY2FsQ29sbGVjdGlvbih7Y29sbGVjdGlvbk5hbWU6IERldmljZUtleVNldC5jb2xsZWN0aW9ufSk7XG5cbmV4cG9ydCBjbGFzcyBUZWFtS2V5U2V0IGV4dGVuZHMgS2V5U2V0IHsgLy8gQSBLZXlTZXQgY29ycmVzcG9uZGluZyB0byBhIHRlYW0gb2Ygd2hpY2ggdGhlIGN1cnJlbnQgdXNlciBpcyBhIG1lbWJlciAoaWYgZ2V0VGFnKCkpLlxuICBzdGF0aWMgY29sbGVjdGlvbiA9ICdUZWFtJztcbiAgc3RhdGljIHNpZ25Gb3JTdG9yYWdlKHttZXNzYWdlLCB0YWcsIC4uLm9wdGlvbnN9KSB7XG4gICAgcmV0dXJuIHRoaXMuc2lnbihtZXNzYWdlLCB7dGVhbTogdGFnLCAuLi5vcHRpb25zfSk7XG4gIH1cbiAgc3RhdGljIGFzeW5jIHdyYXAoa2V5cywgbWVtYmVycykge1xuICAgIC8vIFRoaXMgaXMgdXNlZCBieSBwZXJzaXN0LCB3aGljaCBpbiB0dXJuIGlzIHVzZWQgdG8gY3JlYXRlIGFuZCBjaGFuZ2VNZW1iZXJzaGlwLlxuICAgIGxldCB7ZGVjcnlwdGluZ0tleSwgc2lnbmluZ0tleX0gPSBrZXlzLFxuICB0ZWFtS2V5ID0ge2RlY3J5cHRpbmdLZXksIHNpZ25pbmdLZXl9LFxuICB3cmFwcGluZ0tleSA9IHt9O1xuICAgIGF3YWl0IFByb21pc2UuYWxsKG1lbWJlcnMubWFwKG1lbWJlclRhZyA9PiBLZXlTZXQuZW5jcnlwdGluZ0tleShtZW1iZXJUYWcpLnRoZW4oa2V5ID0+IHdyYXBwaW5nS2V5W21lbWJlclRhZ10gPSBrZXkpKSk7XG4gICAgbGV0IHdyYXBwZWRUZWFtID0gYXdhaXQgTXVsdGlLcnlwdG8ud3JhcEtleSh0ZWFtS2V5LCB3cmFwcGluZ0tleSk7XG4gICAgcmV0dXJuIHdyYXBwZWRUZWFtO1xuICB9XG4gIGFzeW5jIHVud3JhcCh3cmFwcGVkKSB7XG4gICAgbGV0IHtyZWNpcGllbnRzfSA9IHdyYXBwZWQuanNvbixcbiAgICAgICAgbWVtYmVyVGFncyA9IHRoaXMubWVtYmVyVGFncyA9IHJlY2lwaWVudHMubWFwKHJlY2lwaWVudCA9PiByZWNpcGllbnQuaGVhZGVyLmtpZCksXG4gICAgICAgIC8vIFdlIHdpbGwgdXNlIHJlY292ZXJ5IHRhZ3Mgb25seSBpZiB3ZSBuZWVkIHRvLiBGaXJzdCBzdGVwIGlzIHRvIGlkZW50aWZ5IHRoZW0uXG4gICAgICAgIC8vIFRPRE86IG9wdGltaXplIHRoaXMuIEUuZy4sIGRldGVybWluZSByZWNvdmVyeSB0YWdzIGF0IGNyZWF0aW9uIGFuZCBpZGVudGlmeSB0aGVtIGluIHdyYXBwZWQuXG4gICAgICAgIHJlY292ZXJ5V3JhcHMgPSBhd2FpdCBQcm9taXNlLmFsbChtZW1iZXJUYWdzLm1hcCh0YWcgPT4gUmVjb3ZlcnlLZXlTZXQuZ2V0V3JhcHBlZCh0YWcpLmNhdGNoKCgpID0+IG51bGwpKSksXG4gICAgICAgIHJlY292ZXJ5VGFncyA9IG1lbWJlclRhZ3MuZmlsdGVyKCh0YWcsIGluZGV4KSA9PiByZWNvdmVyeVdyYXBzW2luZGV4XSksXG4gICAgICAgIG5vblJlY292ZXJ5VGFncyA9IG1lbWJlclRhZ3MuZmlsdGVyKHRhZyA9PiAhcmVjb3ZlcnlUYWdzLmluY2x1ZGVzKHRhZykpO1xuICAgIGxldCBrZXlTZXQgPSBhd2FpdCBQcm9taXNlLmFueShub25SZWNvdmVyeVRhZ3MubWFwKG1lbWJlclRhZyA9PiBLZXlTZXQuZW5zdXJlKG1lbWJlclRhZykpKVxuICAgICAgICAuY2F0Y2goYXN5bmMgcmVhc29uID0+IHsgLy8gSWYgd2UgZmFpbGVkLCB1c2UgdGhlIHJlY292ZXJ5IHRhZ3MsIGlmIGFueSwgb25lIGF0IGEgdGltZS5cbiAgICAgICAgICBmb3IgKGxldCByZWNvdmVyeSBvZiByZWNvdmVyeVRhZ3MpIHtcbiAgICAgICAgICAgIGxldCBrZXlTZXQgPSBhd2FpdCBLZXlTZXQuZW5zdXJlKHJlY292ZXJ5KS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICAgIGlmIChrZXlTZXQpIHJldHVybiBrZXlTZXQ7XG4gICAgICAgICAgfVxuICAgICAgICAgIHJldHVybiByZWFzb247XG4gICAgICAgIH0pO1xuICAgIGxldCBkZWNyeXB0ZWQgPSBhd2FpdCBrZXlTZXQuZGVjcnlwdCh3cmFwcGVkLmpzb24pO1xuICAgIHJldHVybiBhd2FpdCBNdWx0aUtyeXB0by5pbXBvcnRKV0soZGVjcnlwdGVkLmpzb24pO1xuICB9XG4gIGFzeW5jIGNoYW5nZU1lbWJlcnNoaXAoe2FkZCA9IFtdLCByZW1vdmUgPSBbXX0gPSB7fSkge1xuICAgIGxldCB7bWVtYmVyVGFnc30gPSB0aGlzLFxuICAgICAgICBuZXdNZW1iZXJzID0gbWVtYmVyVGFncy5jb25jYXQoYWRkKS5maWx0ZXIodGFnID0+ICFyZW1vdmUuaW5jbHVkZXModGFnKSk7XG4gICAgYXdhaXQgdGhpcy5jb25zdHJ1Y3Rvci5wZXJzaXN0KHRoaXMudGFnLCB0aGlzLCBuZXdNZW1iZXJzLCBEYXRlLm5vdygpLCBtZW1iZXJUYWdzKTtcbiAgICB0aGlzLm1lbWJlclRhZ3MgPSBuZXdNZW1iZXJzO1xuICB9XG59XG4iLCIvLyBCZWNhdXNlIGVzbGludCBkb2Vzbid0IHJlY29nbml6ZSBpbXBvcnQgYXNzZXJ0aW9uc1xuaW1wb3J0ICogYXMgcGtnIGZyb20gXCIuLi9wYWNrYWdlLmpzb25cIiBhc3NlcnQgeyB0eXBlOiAnanNvbicgfTtcbmV4cG9ydCBjb25zdCB7bmFtZSwgdmVyc2lvbn0gPSBwa2cuZGVmYXVsdDtcbiIsImltcG9ydCBNdWx0aUtyeXB0byBmcm9tIFwiLi9tdWx0aUtyeXB0by5tanNcIjtcbmltcG9ydCB7S2V5U2V0LCBEZXZpY2VLZXlTZXQsIFJlY292ZXJ5S2V5U2V0LCBUZWFtS2V5U2V0fSBmcm9tIFwiLi9rZXlTZXQubWpzXCI7XG5pbXBvcnQge25hbWUsIHZlcnNpb259IGZyb20gXCIuL3BhY2thZ2UtbG9hZGVyLm1qc1wiO1xuXG5jb25zdCBTZWN1cml0eSA9IHsgLy8gVGhpcyBpcyB0aGUgYXBpIGZvciB0aGUgdmF1bHQuIFNlZSBodHRwczovL2tpbHJveS1jb2RlLmdpdGh1Yi5pby9kaXN0cmlidXRlZC1zZWN1cml0eS9kb2NzL2ltcGxlbWVudGF0aW9uLmh0bWwjY3JlYXRpbmctdGhlLXZhdWx0LXdlYi13b3JrZXItYW5kLWlmcmFtZVxuXG4gIC8vIENsaWVudC1kZWZpbmVkIHJlc291cmNlcy5cbiAgc2V0IFN0b3JhZ2Uoc3RvcmFnZSkgeyAvLyBBbGxvd3MgYSBub2RlIGFwcCAobm8gdmF1bHQpIHRvIG92ZXJyaWRlIHRoZSBkZWZhdWx0IHN0b3JhZ2UuXG4gICAgS2V5U2V0LlN0b3JhZ2UgPSBzdG9yYWdlO1xuICB9LFxuICBnZXQgU3RvcmFnZSgpIHsgLy8gQWxsb3dzIGEgbm9kZSBhcHAgKG5vIHZhdWx0KSB0byBleGFtaW5lIHN0b3JhZ2UuXG4gICAgcmV0dXJuIEtleVNldC5TdG9yYWdlO1xuICB9LFxuICBzZXQgZ2V0VXNlckRldmljZVNlY3JldChmdW5jdGlvbk9mVGFnQW5kUHJvbXB0KSB7ICAvLyBBbGxvd3MgYSBub2RlIGFwcCAobm8gdmF1bHQpIHRvIG92ZXJyaWRlIHRoZSBkZWZhdWx0LlxuICAgIEtleVNldC5nZXRVc2VyRGV2aWNlU2VjcmV0ID0gZnVuY3Rpb25PZlRhZ0FuZFByb21wdDtcbiAgfSxcbiAgcmVhZHk6IHtuYW1lLCB2ZXJzaW9uLCBvcmlnaW46IEtleVNldC5TdG9yYWdlLm9yaWdpbn0sXG5cbiAgLy8gVGhlIGZvdXIgYmFzaWMgb3BlcmF0aW9ucy4gLi4ucmVzdCBtYXkgYmUgb25lIG9yIG1vcmUgdGFncywgb3IgbWF5IGJlIHt0YWdzLCB0ZWFtLCBtZW1iZXIsIGNvbnRlbnRUeXBlLCAuLi59XG4gIGFzeW5jIGVuY3J5cHQobWVzc2FnZSwgLi4ucmVzdCkgeyAvLyBQcm9taXNlIGEgSldFLlxuICAgIGxldCBvcHRpb25zID0ge30sIHRhZ3MgPSB0aGlzLmNhbm9uaWNhbGl6ZVBhcmFtZXRlcnMocmVzdCwgb3B0aW9ucyksXG4gICAgICAgIGtleSA9IGF3YWl0IEtleVNldC5wcm9kdWNlS2V5KHRhZ3MsIHRhZyA9PiBLZXlTZXQuZW5jcnlwdGluZ0tleSh0YWcpLCBvcHRpb25zKTtcbiAgICByZXR1cm4gTXVsdGlLcnlwdG8uZW5jcnlwdChrZXksIG1lc3NhZ2UsIG9wdGlvbnMpO1xuICB9LFxuICBhc3luYyBkZWNyeXB0KGVuY3J5cHRlZCwgLi4ucmVzdCkgeyAvLyBQcm9taXNlIHtwYXlsb2FkLCB0ZXh0LCBqc29ufSBhcyBhcHByb3ByaWF0ZS5cbiAgICBsZXQgb3B0aW9ucyA9IHt9LFxuICAgICAgICBbdGFnXSA9IHRoaXMuY2Fub25pY2FsaXplUGFyYW1ldGVycyhyZXN0LCBvcHRpb25zLCBlbmNyeXB0ZWQpLFxuICAgICAgICB2YXVsdCA9IGF3YWl0IEtleVNldC5lbnN1cmUodGFnKTtcbiAgICByZXR1cm4gdmF1bHQuZGVjcnlwdChlbmNyeXB0ZWQsIG9wdGlvbnMpO1xuICB9LFxuICBhc3luYyBzaWduKG1lc3NhZ2UsIC4uLnJlc3QpIHsgLy8gUHJvbWlzZSBhIEpXUy5cbiAgICBsZXQgb3B0aW9ucyA9IHt9LCB0YWdzID0gdGhpcy5jYW5vbmljYWxpemVQYXJhbWV0ZXJzKHJlc3QsIG9wdGlvbnMpO1xuICAgIHJldHVybiBLZXlTZXQuc2lnbihtZXNzYWdlLCB7dGFncywgLi4ub3B0aW9uc30pO1xuICB9LFxuICBhc3luYyB2ZXJpZnkoc2lnbmF0dXJlLCAuLi5yZXN0KSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259IGFzIGFwcHJvcHJpYXRlLlxuICAgIGxldCBvcHRpb25zID0ge30sIHRhZ3MgPSB0aGlzLmNhbm9uaWNhbGl6ZVBhcmFtZXRlcnMocmVzdCwgb3B0aW9ucywgc2lnbmF0dXJlKTtcbiAgICByZXR1cm4gS2V5U2V0LnZlcmlmeShzaWduYXR1cmUsIHRhZ3MsIG9wdGlvbnMpO1xuICB9LFxuXG4gIC8vIFRhZyBtYWludGFuY2UuXG4gIGFzeW5jIGNyZWF0ZSguLi5tZW1iZXJzKSB7IC8vIFByb21pc2UgYSBuZXdseS1jcmVhdGVkIHRhZyB3aXRoIHRoZSBnaXZlbiBtZW1iZXJzLiBUaGUgbWVtYmVyIHRhZ3MgKGlmIGFueSkgbXVzdCBhbHJlYWR5IGV4aXN0LlxuICAgIGlmICghbWVtYmVycy5sZW5ndGgpIHJldHVybiBhd2FpdCBEZXZpY2VLZXlTZXQuY3JlYXRlKCk7XG4gICAgbGV0IHByb21wdCA9IG1lbWJlcnNbMF0ucHJvbXB0O1xuICAgIGlmIChwcm9tcHQpIHJldHVybiBhd2FpdCBSZWNvdmVyeUtleVNldC5jcmVhdGUocHJvbXB0KTtcbiAgICByZXR1cm4gYXdhaXQgVGVhbUtleVNldC5jcmVhdGUobWVtYmVycyk7XG4gIH0sXG4gIGFzeW5jIGNoYW5nZU1lbWJlcnNoaXAoe3RhZywgLi4ub3B0aW9uc30pIHsgLy8gUHJvbWlzZSB0byBhZGQgb3IgcmVtb3ZlIG1lbWJlcnMuXG4gICAgbGV0IHZhdWx0ID0gYXdhaXQgS2V5U2V0LmVuc3VyZSh0YWcpO1xuICAgIHJldHVybiB2YXVsdC5jaGFuZ2VNZW1iZXJzaGlwKG9wdGlvbnMpO1xuICB9LFxuICBhc3luYyBkZXN0cm95KHRhZ09yT3B0aW9ucykgeyAvLyBQcm9taXNlIHRvIHJlbW92ZSB0aGUgdGFnIGFuZCBhbnkgYXNzb2NpYXRlZCBkYXRhIGZyb20gYWxsIHN0b3JhZ2UuXG4gICAgaWYgKCdzdHJpbmcnID09PSB0eXBlb2YgdGFnT3JPcHRpb25zKSB0YWdPck9wdGlvbnMgPSB7dGFnOiB0YWdPck9wdGlvbnN9O1xuICAgIGxldCB7dGFnLCAuLi5vcHRpb25zfSA9IHRhZ09yT3B0aW9ucztcbiAgICBsZXQgdmF1bHQgPSBhd2FpdCBLZXlTZXQuZW5zdXJlKHRhZyk7XG4gICAgcmV0dXJuIHZhdWx0LmRlc3Ryb3kob3B0aW9ucyk7XG4gIH0sXG4gIGNsZWFyKHRhZykgeyAvLyBSZW1vdmUgYW55IGxvY2FsbHkgY2FjaGVkIEtleVNldCBmb3IgdGhlIHRhZywgb3IgYWxsIEtleVNldHMgaWYgbm90IHRhZyBzcGVjaWZpZWQuXG4gICAgS2V5U2V0LmNsZWFyKHRhZyk7XG4gIH0sXG5cbiAgZGVjb2RlUHJvdGVjdGVkSGVhZGVyOiBNdWx0aUtyeXB0by5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIsXG4gIGNhbm9uaWNhbGl6ZVBhcmFtZXRlcnMocmVzdCwgb3B0aW9ucywgdG9rZW4pIHsgLy8gUmV0dXJuIHRoZSBhY3R1YWwgbGlzdCBvZiB0YWdzLCBhbmQgYmFzaCBvcHRpb25zLlxuICAgIC8vIHJlc3QgbWF5IGJlIGEgbGlzdCBvZiB0YWcgc3RyaW5nc1xuICAgIC8vICAgIG9yIGEgbGlzdCBvZiBvbmUgc2luZ2xlIG9iamVjdCBzcGVjaWZ5aW5nIG5hbWVkIHBhcmFtZXRlcnMsIGluY2x1ZGluZyBlaXRoZXIgdGVhbSwgdGFncywgb3IgbmVpdGhlclxuICAgIC8vIHRva2VuIG1heSBiZSBhIEpXRSBvciBKU0UsIG9yIGZhbHN5LCBhbmQgaXMgdXNlZCB0byBzdXBwbHkgdGFncyBpZiBuZWNlc3NhcnkuXG4gICAgaWYgKHJlc3QubGVuZ3RoID4gMSkgcmV0dXJuIHJlc3Q7XG4gICAgbGV0IHt0YWdzID0gW10sIGNvbnRlbnRUeXBlLCB0aW1lLCAuLi5vdGhlcnN9ID0gcmVzdFswXSB8fCB7fSxcblx0e3RlYW19ID0gb3RoZXJzOyAvLyBEbyBub3Qgc3RyaXAgdGVhbSBmcm9tIG90aGVycy5cbiAgICBpZiAoIXRhZ3MubGVuZ3RoKSB7XG4gICAgICBpZiAocmVzdC5sZW5ndGggJiYgcmVzdFswXS5sZW5ndGgpIHRhZ3MgPSByZXN0OyAvLyByZXN0IG5vdCBlbXB0eSwgYW5kIGl0cyBmaXJzdCBpcyBzdHJpbmctbGlrZS5cbiAgICAgIGVsc2UgaWYgKHRva2VuKSB7IC8vIGdldCBmcm9tIHRva2VuXG4gICAgICAgIGlmICh0b2tlbi5zaWduYXR1cmVzKSB0YWdzID0gdG9rZW4uc2lnbmF0dXJlcy5tYXAoc2lnID0+IHRoaXMuZGVjb2RlUHJvdGVjdGVkSGVhZGVyKHNpZykua2lkKTtcbiAgICAgICAgZWxzZSBpZiAodG9rZW4ucmVjaXBpZW50cykgdGFncyA9IHRva2VuLnJlY2lwaWVudHMubWFwKHJlYyA9PiByZWMuaGVhZGVyLmtpZCk7XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICBsZXQga2lkID0gdGhpcy5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIodG9rZW4pLmtpZDsgLy8gY29tcGFjdCB0b2tlblxuICAgICAgICAgICAgaWYgKGtpZCkgdGFncyA9IFtraWRdO1xuICAgICAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ2ZhaWx1cmUgd2l0aCcsIHtyZXN0LCB0b2tlbiwgdGVhbSwgdGFncywgZX0pO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgICBpZiAodGVhbSAmJiAhdGFncy5pbmNsdWRlcyh0ZWFtKSkgdGFncyA9IFt0ZWFtLCAuLi50YWdzXTtcbiAgICBpZiAoY29udGVudFR5cGUpIG9wdGlvbnMuY3R5ID0gY29udGVudFR5cGU7XG4gICAgaWYgKHRpbWUpIG9wdGlvbnMuaWF0ID0gdGltZTtcbiAgICBPYmplY3QuYXNzaWduKG9wdGlvbnMsIG90aGVycyk7XG5cbiAgICByZXR1cm4gdGFncztcbiAgfVxufTtcblxuZXhwb3J0IGRlZmF1bHQgU2VjdXJpdHk7XG4iLCJcbmZ1bmN0aW9uIHRyYW5zZmVycmFibGVFcnJvcihlcnJvcikgeyAvLyBBbiBlcnJvciBvYmplY3QgdGhhdCB3ZSByZWNlaXZlIG9uIG91ciBzaWRlIG1pZ2h0IG5vdCBiZSB0cmFuc2ZlcnJhYmxlIHRvIHRoZSBvdGhlci5cbiAgbGV0IHtuYW1lLCBtZXNzYWdlLCBjb2RlLCBkYXRhfSA9IGVycm9yO1xuICByZXR1cm4ge25hbWUsIG1lc3NhZ2UsIGNvZGUsIGRhdGF9O1xufVxuXG4vLyBTZXQgdXAgYmlkaXJlY3Rpb25hbCBjb21tdW5jYXRpb25zIHdpdGggdGFyZ2V0LCByZXR1cm5pbmcgYSBmdW5jdGlvbiAobWV0aG9kTmFtZSwgLi4ucGFyYW1zKSB0aGF0IHdpbGwgc2VuZCB0byB0YXJnZXQuXG5mdW5jdGlvbiBkaXNwYXRjaCh7dGFyZ2V0ID0gc2VsZiwgICAgICAgIC8vIFRoZSB3aW5kb3csIHdvcmtlciwgb3Igb3RoZXIgb2JqZWN0IHRvIHdoaWNoIHdlIHdpbGwgcG9zdE1lc3NhZ2UuXG5cdFx0ICAgcmVjZWl2ZXIgPSB0YXJnZXQsICAgIC8vIFRoZSB3aW5kb3csIHdvcmtlciwgb3Igb3RoZXIgb2JqZWN0IG9mIHdoaWNoIFdFIHdpbGwgaGFuZGxlICdtZXNzYWdlJyBldmVudHMgZnJvbSB0YXJnZXQuXG5cdFx0ICAgbmFtZXNwYWNlID0gcmVjZWl2ZXIsIC8vIEFuIG9iamVjdCB0aGF0IGRlZmluZXMgYW55IG1ldGhvZHMgdGhhdCBtYXkgYmUgcmVxdWVzdGVkIGJ5IHRhcmdldC5cblxuXHRcdCAgIG9yaWdpbiA9ICgodGFyZ2V0ICE9PSByZWNlaXZlcikgJiYgdGFyZ2V0LmxvY2F0aW9uLm9yaWdpbiksXG5cblx0XHQgICBkaXNwYXRjaGVyTGFiZWwgPSBuYW1lc3BhY2UubmFtZSB8fCByZWNlaXZlci5uYW1lIHx8IHJlY2VpdmVyLmxvY2F0aW9uPy5ocmVmIHx8IHJlY2VpdmVyLFxuXHRcdCAgIHRhcmdldExhYmVsID0gdGFyZ2V0Lm5hbWUgfHwgb3JpZ2luIHx8IHRhcmdldC5sb2NhdGlvbj8uaHJlZiB8fCB0YXJnZXQsXG5cblx0XHQgICBsb2cgPSBudWxsLFxuXHRcdCAgIGluZm86bG9naW5mbyA9IGNvbnNvbGUuaW5mby5iaW5kKGNvbnNvbGUpLFxuXHRcdCAgIHdhcm46bG9nd2FybiA9IGNvbnNvbGUud2Fybi5iaW5kKGNvbnNvbGUpLFxuXHRcdCAgIGVycm9yOmxvZ2Vycm9yID0gY29uc29sZS5lcnJvci5iaW5kKGNvbnNvbGUpXG5cdFx0ICB9KSB7XG4gIGNvbnN0IHJlcXVlc3RzID0ge30sXG4gICAgICAgIGpzb25ycGMgPSAnMi4wJyxcbiAgICAgICAgY2FwdHVyZWRQb3N0ID0gdGFyZ2V0LnBvc3RNZXNzYWdlLmJpbmQodGFyZ2V0KSwgLy8gSW4gY2FzZSAobWFsaWNpb3VzKSBjb2RlIGxhdGVyIGNoYW5nZXMgaXQuXG4gICAgICAgIC8vIHdpbmRvdy5wb3N0TWVzc2FnZSBhbmQgZnJpZW5kcyB0YWtlcyBhIHRhcmdldE9yaWdpbiB0aGF0IHdlIHN1cHBseS5cbiAgICAgICAgLy8gQnV0IHdvcmtlci5wb3N0TWVzc2FnZSBnaXZlcyBlcnJvciByYXRoZXIgdGhhbiBpZ25vcmluZyB0aGUgZXh0cmEgYXJnLiBTbyBzZXQgdGhlIHJpZ2h0IGZvcm0gYXQgaW5pdGlhbGl6YXRpb24uXG4gICAgICAgIHBvc3QgPSBvcmlnaW4gPyBtZXNzYWdlID0+IGNhcHR1cmVkUG9zdChtZXNzYWdlLCBvcmlnaW4pIDogY2FwdHVyZWRQb3N0LFxuICAgICAgICBudWxsTG9nID0gKCkgPT4ge307XG4gIGxldCBtZXNzYWdlSWQgPSAwOyAvLyBwcmUtaW5jcmVtZW50ZWQgaWQgc3RhcnRzIGF0IDEuXG5cbiAgZnVuY3Rpb24gcmVxdWVzdChtZXRob2QsIC4uLnBhcmFtcykgeyAvLyBQcm9taXNlIHRoZSByZXN1bHQgb2YgbWV0aG9kKC4uLnBhcmFtcykgaW4gdGFyZ2V0LlxuICAgIC8vIFdlIGRvIGEgdGFyZ2V0LnBvc3RNZXNzYWdlIG9mIGEganNvbnJwYyByZXF1ZXN0LCBhbmQgcmVzb2x2ZSB0aGUgcHJvbWlzZSB3aXRoIHRoZSByZXNwb25zZSwgbWF0Y2hlZCBieSBpZC5cbiAgICAvLyBJZiB0aGUgdGFyZ2V0IGhhcHBlbnMgdG8gYmUgc2V0IHVwIGJ5IGEgZGlzcGF0Y2ggbGlrZSB0aGlzIG9uZSwgaXQgd2lsbCByZXNwb25kIHdpdGggd2hhdGV2ZXIgaXQnc1xuICAgIC8vIG5hbWVzcGFjZVttZXRob2RdKC4uLnBhcmFtcykgcmVzb2x2ZXMgdG8uIFdlIG9ubHkgc2VuZCBqc29ucnBjIHJlcXVlc3RzICh3aXRoIGFuIGlkKSwgbm90IG5vdGlmaWNhdGlvbnMsXG4gICAgLy8gYmVjYXVzZSB0aGVyZSBpcyBubyB3YXkgdG8gZ2V0IGVycm9ycyBiYWNrIGZyb20gYSBqc29ucnBjIG5vdGlmaWNhdGlvbi5cbiAgICBsZXQgaWQgPSArK21lc3NhZ2VJZCxcblx0cmVxdWVzdCA9IHJlcXVlc3RzW2lkXSA9IHt9O1xuICAgIC8vIEl0IHdvdWxkIGJlIG5pY2UgdG8gbm90IGxlYWsgcmVxdWVzdCBvYmplY3RzIGlmIHRoZXkgYXJlbid0IGFuc3dlcmVkLlxuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgICBsb2c/LihkaXNwYXRjaGVyTGFiZWwsICdyZXF1ZXN0JywgaWQsIG1ldGhvZCwgcGFyYW1zLCAndG8nLCB0YXJnZXRMYWJlbCk7XG4gICAgICBPYmplY3QuYXNzaWduKHJlcXVlc3QsIHtyZXNvbHZlLCByZWplY3R9KTtcbiAgICAgIHBvc3Qoe2lkLCBtZXRob2QsIHBhcmFtcywganNvbnJwY30pO1xuICAgIH0pO1xuICB9XG5cbiAgYXN5bmMgZnVuY3Rpb24gcmVzcG9uZChldmVudCkgeyAvLyBIYW5kbGUgJ21lc3NhZ2UnIGV2ZW50cyB0aGF0IHdlIHJlY2VpdmUgZnJvbSB0YXJnZXQuXG4gICAgbG9nPy4oZGlzcGF0Y2hlckxhYmVsLCAnZ290IG1lc3NhZ2UnLCBldmVudC5kYXRhLCAnZnJvbScsIHRhcmdldExhYmVsLCBldmVudC5vcmlnaW4pO1xuICAgIGxldCB7aWQsIG1ldGhvZCwgcGFyYW1zID0gW10sIHJlc3VsdCwgZXJyb3IsIGpzb25ycGM6dmVyc2lvbn0gPSBldmVudC5kYXRhIHx8IHt9O1xuXG4gICAgLy8gTm9pc2lseSBpZ25vcmUgbWVzc2FnZXMgdGhhdCBhcmUgbm90IGZyb20gdGhlIGV4cGVjdCB0YXJnZXQgb3Igb3JpZ2luLCBvciB3aGljaCBhcmUgbm90IGpzb25ycGMuXG4gICAgaWYgKGV2ZW50LnNvdXJjZSAmJiAoZXZlbnQuc291cmNlICE9PSB0YXJnZXQpKSByZXR1cm4gbG9nZXJyb3I/LihkaXNwYXRjaGVyTGFiZWwsICd0bycsIHRhcmdldExhYmVsLCAgJ2dvdCBtZXNzYWdlIGZyb20nLCBldmVudC5zb3VyY2UpO1xuICAgIGlmIChvcmlnaW4gJiYgKG9yaWdpbiAhPT0gZXZlbnQub3JpZ2luKSkgcmV0dXJuIGxvZ2Vycm9yPy4oZGlzcGF0Y2hlckxhYmVsLCBvcmlnaW4sICdtaXNtYXRjaGVkIG9yaWdpbicsIHRhcmdldExhYmVsLCBldmVudC5vcmlnaW4pO1xuICAgIGlmICh2ZXJzaW9uICE9PSBqc29ucnBjKSByZXR1cm4gbG9nd2Fybj8uKGAke2Rpc3BhdGNoZXJMYWJlbH0gaWdub3Jpbmcgbm9uLWpzb25ycGMgbWVzc2FnZSAke0pTT04uc3RyaW5naWZ5KGV2ZW50LmRhdGEpfS5gKTtcblxuICAgIGlmIChtZXRob2QpIHsgLy8gSW5jb21pbmcgcmVxdWVzdCBvciBub3RpZmljYXRpb24gZnJvbSB0YXJnZXQuXG4gICAgICBsZXQgZXJyb3IgPSBudWxsLCByZXN1bHQsXG4gICAgICAgICAgLy8ganNvbnJwYyByZXF1ZXN0L25vdGlmaWNhdGlvbiBjYW4gaGF2ZSBwb3NpdGlvbmFsIGFyZ3MgKGFycmF5KSBvciBuYW1lZCBhcmdzIChhIFBPSk8pLlxuXHQgIGFyZ3MgPSBBcnJheS5pc0FycmF5KHBhcmFtcykgPyBwYXJhbXMgOiBbcGFyYW1zXTsgLy8gQWNjZXB0IGVpdGhlci5cbiAgICAgIHRyeSB7IC8vIG1ldGhvZCByZXN1bHQgbWlnaHQgbm90IGJlIGEgcHJvbWlzZSwgc28gd2UgY2FuJ3QgcmVseSBvbiAuY2F0Y2goKS5cbiAgICAgICAgcmVzdWx0ID0gYXdhaXQgbmFtZXNwYWNlW21ldGhvZF0oLi4uYXJncyk7IC8vIENhbGwgdGhlIG1ldGhvZC5cbiAgICAgIH0gY2F0Y2ggKGUpIHsgLy8gU2VuZCBiYWNrIGEgY2xlYW4ge25hbWUsIG1lc3NhZ2V9IG9iamVjdC5cbiAgICAgICAgZXJyb3IgPSB0cmFuc2ZlcnJhYmxlRXJyb3IoZSk7XG4gICAgICAgIGlmICghbmFtZXNwYWNlW21ldGhvZF0gJiYgIWVycm9yLm1lc3NhZ2UuaW5jbHVkZXMobWV0aG9kKSkge1xuXHQgIGVycm9yLm1lc3NhZ2UgPSBgJHttZXRob2R9IGlzIG5vdCBkZWZpbmVkLmA7IC8vIEJlIG1vcmUgaGVscGZ1bCB0aGFuIHNvbWUgYnJvd3NlcnMuXG4gICAgICAgICAgZXJyb3IuY29kZSA9IC0zMjYwMTsgLy8gRGVmaW5lZCBieSBqc29uLXJwYyBzcGVjLlxuICAgICAgICB9IGVsc2UgaWYgKCFlcnJvci5tZXNzYWdlKSAvLyBJdCBoYXBwZW5zLiBFLmcuLCBvcGVyYXRpb25hbCBlcnJvcnMgZnJvbSBjcnlwdG8uXG5cdCAgZXJyb3IubWVzc2FnZSA9IGAke2Vycm9yLm5hbWUgfHwgZXJyb3IudG9TdHJpbmcoKX0gaW4gJHttZXRob2R9LmA7XG4gICAgICB9XG4gICAgICBpZiAoaWQgPT09IHVuZGVmaW5lZCkgcmV0dXJuOyAvLyBEb24ndCByZXNwb25kIHRvIGEgJ25vdGlmaWNhdGlvbicuIG51bGwgaWQgaXMgc3RpbGwgc2VudCBiYWNrLlxuICAgICAgbGV0IHJlc3BvbnNlID0gZXJyb3IgPyB7aWQsIGVycm9yLCBqc29ucnBjfSA6IHtpZCwgcmVzdWx0LCBqc29ucnBjfTtcbiAgICAgIGxvZz8uKGRpc3BhdGNoZXJMYWJlbCwgJ2Fuc3dlcmluZycsIGlkLCBlcnJvciB8fCByZXN1bHQsICd0bycsIHRhcmdldExhYmVsKTtcbiAgICAgIHJldHVybiBwb3N0KHJlc3BvbnNlKTtcbiAgICB9XG5cbiAgICAvLyBPdGhlcndpc2UsIGl0IGlzIGEgcmVzcG9uc2UgZnJvbSB0YXJnZXQgdG8gb3VyIGVhcmxpZXIgb3V0Z29pbmcgcmVxdWVzdC5cbiAgICBsZXQgcmVxdWVzdCA9IHJlcXVlc3RzW2lkXTsgIC8vIFJlc29sdmUgb3IgcmVqZWN0IHRoZSBwcm9taXNlIHRoYXQgYW4gYW4gZWFybGllciByZXF1ZXN0IGNyZWF0ZWQuXG4gICAgZGVsZXRlIHJlcXVlc3RzW2lkXTtcbiAgICBpZiAoIXJlcXVlc3QpIHJldHVybiBsb2d3YXJuPy4oYCR7ZGlzcGF0Y2hlckxhYmVsfSBpZ25vcmluZyByZXNwb25zZSAke2V2ZW50LmRhdGF9LmApO1xuICAgIGlmIChlcnJvcikgcmVxdWVzdC5yZWplY3QoZXJyb3IpO1xuICAgIGVsc2UgcmVxdWVzdC5yZXNvbHZlKHJlc3VsdCk7XG4gIH1cblxuICAvLyBOb3cgc2V0IHVwIHRoZSBoYW5kbGVyIGFuZCByZXR1cm4gdGhlIGZ1bmN0aW9uIGZvciB0aGUgY2FsbGVyIHRvIHVzZSB0byBtYWtlIHJlcXVlc3RzLlxuICByZWNlaXZlci5hZGRFdmVudExpc3RlbmVyKFwibWVzc2FnZVwiLCByZXNwb25kKTtcbiAgbG9naW5mbz8uKGAke2Rpc3BhdGNoZXJMYWJlbH0gd2lsbCBkaXNwYXRjaCB0byAke3RhcmdldExhYmVsfWApO1xuICByZXR1cm4gcmVxdWVzdDtcbn1cblxuZXhwb3J0IGRlZmF1bHQgZGlzcGF0Y2g7XG4iXSwibmFtZXMiOlsiZGlnZXN0IiwiY3J5cHRvIiwiZW5jb2RlIiwiZGVjb2RlIiwiYml0TGVuZ3RoIiwiZGVjcnlwdCIsImdldENyeXB0b0tleSIsIndyYXAiLCJ1bndyYXAiLCJkZXJpdmVLZXkiLCJwMnMiLCJjb25jYXRTYWx0IiwiZW5jcnlwdCIsImJhc2U2NHVybCIsInN1YnRsZUFsZ29yaXRobSIsImRlY29kZUJhc2U2NFVSTCIsImludmFsaWRLZXlJbnB1dCIsIkVDREguZWNkaEFsbG93ZWQiLCJFQ0RILmRlcml2ZUtleSIsImNla0xlbmd0aCIsImFlc0t3IiwicnNhRXMiLCJwYmVzMkt3IiwiYWVzR2NtS3ciLCJrZXlUb0pXSyIsIkVDREguZ2VuZXJhdGVFcGsiLCJnZXRWZXJpZnlLZXkiLCJnZXRTaWduS2V5IiwiYmFzZTY0dXJsLmVuY29kZSIsImJhc2U2NHVybC5kZWNvZGUiLCJnZW5lcmF0ZVNlY3JldCIsImdlbmVyYXRlS2V5UGFpciIsImdlbmVyYXRlIiwiSk9TRS5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIiLCJKT1NFLmdlbmVyYXRlS2V5UGFpciIsIkpPU0UuQ29tcGFjdFNpZ24iLCJKT1NFLmNvbXBhY3RWZXJpZnkiLCJKT1NFLkNvbXBhY3RFbmNyeXB0IiwiSk9TRS5jb21wYWN0RGVjcnlwdCIsIkpPU0UuZ2VuZXJhdGVTZWNyZXQiLCJKT1NFLmJhc2U2NHVybC5lbmNvZGUiLCJKT1NFLmJhc2U2NHVybC5kZWNvZGUiLCJKT1NFLmV4cG9ydEpXSyIsIkpPU0UuaW1wb3J0SldLIiwiSk9TRS5HZW5lcmFsRW5jcnlwdCIsIkpPU0UuZ2VuZXJhbERlY3J5cHQiLCJKT1NFLkdlbmVyYWxTaWduIiwiSk9TRS5nZW5lcmFsVmVyaWZ5IiwiTG9jYWxDb2xsZWN0aW9uIiwicGtnLmRlZmF1bHQiXSwibWFwcGluZ3MiOiJBQUFBLGVBQWUsTUFBTSxDQUFDO0FBQ2YsTUFBTSxXQUFXLEdBQUcsQ0FBQyxHQUFHLEtBQUssR0FBRyxZQUFZLFNBQVM7O0FDQTVELE1BQU1BLFFBQU0sR0FBRyxPQUFPLFNBQVMsRUFBRSxJQUFJLEtBQUs7QUFDMUMsSUFBSSxNQUFNLFlBQVksR0FBRyxDQUFDLElBQUksRUFBRSxTQUFTLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0FBQ3RELElBQUksT0FBTyxJQUFJLFVB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QUFDO0FBQ00sZUFBZSxTQUFTLENBQUMsTUFBTSxFQUFFLElBQUksRUFBRSxLQUFLLEVBQUU7QUFDckQsSUFBSSxNQUFNLFVBQVUsR0FBRyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUMsSUFBSSxJQUFJLENBQUMsSUFBSSxFQUFFLENBQUMsQ0FBQztBQUNuRCxJQUFJLE1BQU0sR0FBRyxHQUFHLElBQUksVUFBVSxDQUFDLFVBQVUsR0FBRyxFQUFFLENBQUMsQ0FBQztBQUNoRCxJQUFJLEtBQUssSUFBSSxJQUFJLEdBQUcsQ0FBQyxFQUFFLElBQUksR0FBRyxVQUFVLEVBQUUsSUFBSSxFQUFFLEVBQUU7QUFDbEQsUUFBUSxNQUFNLEdBQUcsR0FBRyxJQUFJLFVBQVUsQ0FBQyxDQUFDLEdBQUcsTUFBTSxDQUFDLE1BQU0sR0FBRyxLQUFLLENBQUMsTUFBTSxDQUFDLENBQUM7QUFDckUsUUFBUSxHQUFHLENBQUMsR0FBRyxDQUFDLFFBQVEsQ0FBQyxJQUFJLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQztBQUNwQyxRQUFRLEdBQUcsQ0FBQyxHQUFHLENBQUMsTUFBTSxFQUFFLENBQUMsQ0FBQyxDQUFDO0FBQzNCLFFBQVEsR0FBRyxDQUFDLEdBQUcsQ0FBQyxLQUFLLEVBQUUsQ0FBQyxHQUFHLE1BQU0sQ0FBQyxNQUFNLENBQUMsQ0FBQztBQUMxQyxRQUFRLEdBQUcsQ0FBQyxHQUFHLENBQUMsTUFBTUQsUUFBTSxDQUFDLFFBQVEsRUFBRSxHQUFHLENBQUMsRUFBRSxJQUFJLEdBQUcsRUFBRSxDQUFDLENBQUM7QUFDeEQsS0FBSztBQUNMLElBQUksT0FBTyxHQUFHLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxJQUFJLElBQUksQ0FBQyxDQUFDLENBQUM7QUFDbkM7O0FDakRPLE1BQU0sWUFBWSxHQUFHLENBQUMsS0FBSyxLQUFLO0FBQ3ZDLElBQUksSUFBSSxTQUFTLEdBQUcsS0FBSyxDQUFDO0FBQzFCLElBQUksSUFBSSxPQUFPLFNBQVMsS0FBSyxRQUFRLEVBQUU7QUFDdkMsUUFBUSxTQUFTLEdBQUcs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SUFBSSxLQUFLLENBQUMsUUFBUSxFQUFFLENBQUMsSUFBSSxFQUFFLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQztBQUNyRSxPQUFPO0FBQ1AsTUFBTSxJQUFJLEVBQUUsS0FBSyxTQUFTLEVBQUUsT0FBTztBQUNuQyxNQUFNLElBQUksUUFBUSxHQUFHLEtBQUssR0FBRyxDQUFDLEVBQUUsRUFBRSxLQUFLLEVBQUUsT0FBTyxDQUFDLEdBQUcsQ0FBQyxFQUFFLEVBQUUsTUFBTSxFQUFFLE9BQU8sQ0FBQyxDQUFDO0FBQzFFLE1BQU0sR0FBRyxHQUFHLGVBQWUsRUFBRSxXQUFXLEVBQUUsRUFBRSxFQUFFLEtBQUssSUFBSSxNQUFNLEVBQUUsSUFBSSxFQUFFLFdBQVcsQ0FBQyxDQUFDO0FBQ2xGLE1BQU0sT0FBTyxJQUFJLENBQUMsUUFBUSxDQUFDLENBQUM7QUFDNUIsS0FBSztBQUNMO0FBQ0E7QUFDQSxJQUFJLElBQUksT0FBTyxHQUFHLFFBQVEsQ0FBQyxFQUFFLENBQUMsQ0FBQztBQUMvQixJQUFJLE9BQU8sUUFBUSxDQUFDLEVBQUUsQ0FBQyxDQUFDO0FBQ3hCLElBQUksSUFBSSxDQUFDLE9BQU8sRUFBRSxPQUFPLE9BQU8sR0FBRyxDQUFDLEVBQUUsZUFBZSxDQUFDLG1CQUFtQixFQUFFLEtBQUssQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztBQUMxRixJQUFJLElBQUksS0FBSyxFQUFFLE9BQU8sQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLENBQUM7QUFDckMsU0FBUyxPQUFPLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFDO0FBQ2pDLEdBQUc7QUFDSDtBQUNBO0FBQ0EsRUFBRSxRQUFRLENBQUMsZ0JBQWdCLENBQUMsU0FBUyxFQUFFLE9BQU8sQ0FBQyxDQUFDO0FBQ2hELEVBQUUsT0FBTyxHQUFHLENBQUMsRUFBRSxlQUFlLENBQUMsa0JBQWtCLEVBQUUsV0FBVyxDQUFDLENBQUMsQ0FBQyxDQUFDO0FBQ2xFLEVBQUUsT0FBTyxPQUFPLENBQUM7QUFDakI7Ozs7IiwieF9nb29nbGVfaWdub3JlTGlzdCI6WzAsMSwyLDMsNCw1LDYsNyw4LDksMTAsMTEsMTIsMTMsMTQsMTUsMTYsMTcsMTgsMTksMjAsMjEsMjIsMjMsMjQsMjUsMjYsMjcsMjgsMjksMzAsMzEsMzIsMzMsMzQsMzUsMzYsMzcsMzgsMzksNDAsNDEsNDIsNDMsNDQsNDUsNDYsNDcsNDgsNDksNTAsNTEsNTIsNTMsNTQsNTUsNTYsNjhdfQ==
