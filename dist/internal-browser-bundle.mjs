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
  return `${collectionName}/${b}/${c}/${a}/${rest}.${extension}`;
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

// I'd love to use this, but it isn't supported across enough Node and eslint versions.
// import * as pkg from "../package.json" with { type: 'json' };
// export const {name, version} = pkg.default;

// So just hardcode and keep updating. Sigh.
const name = '@ki1r0y/distributed-security';
const version = '1.0.3';

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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW50ZXJuYWwtYnJvd3Nlci1idW5kbGUubWpzIiwic291cmNlcyI6WyIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS93ZWJjcnlwdG8uanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9kaWdlc3QuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2J1ZmZlcl91dGlscy5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2Jhc2U2NHVybC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci91dGlsL2Vycm9ycy5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3JhbmRvbS5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvaXYuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2NoZWNrX2l2X2xlbmd0aC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2NoZWNrX2Nla19sZW5ndGguanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS90aW1pbmdfc2FmZV9lcXVhbC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvY3J5cHRvX2tleS5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9pc19rZXlfbGlrZS5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2RlY3J5cHQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2lzX2Rpc2pvaW50LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9pc19vYmplY3QuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9ib2d1cy5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2Flc2t3LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvZWNkaGVzLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9jaGVja19wMnMuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9wYmVzMmt3LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvc3VidGxlX3JzYWVzLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvY2hlY2tfa2V5X2xlbmd0aC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3JzYWVzLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9jZWsuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9qd2tfdG9fa2V5LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2tleS9pbXBvcnQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2NoZWNrX2tleV90eXBlLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvZW5jcnlwdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvYWVzZ2Nta3cuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2RlY3J5cHRfa2V5X21hbmFnZW1lbnQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL3ZhbGlkYXRlX2NyaXQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL3ZhbGlkYXRlX2FsZ29yaXRobXMuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandlL2ZsYXR0ZW5lZC9kZWNyeXB0LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3ZS9jb21wYWN0L2RlY3J5cHQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandlL2dlbmVyYWwvZGVjcnlwdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2tleV90b19qd2suanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIva2V5L2V4cG9ydC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvZW5jcnlwdF9rZXlfbWFuYWdlbWVudC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd2UvZmxhdHRlbmVkL2VuY3J5cHQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandlL2dlbmVyYWwvZW5jcnlwdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3N1YnRsZV9kc2EuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9nZXRfc2lnbl92ZXJpZnlfa2V5LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvdmVyaWZ5LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9mbGF0dGVuZWQvdmVyaWZ5LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9jb21wYWN0L3ZlcmlmeS5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd3MvZ2VuZXJhbC92ZXJpZnkuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandlL2NvbXBhY3QvZW5jcnlwdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3NpZ24uanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandzL2ZsYXR0ZW5lZC9zaWduLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9jb21wYWN0L3NpZ24uanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandzL2dlbmVyYWwvc2lnbi5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci91dGlsL2Jhc2U2NHVybC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci91dGlsL2RlY29kZV9wcm90ZWN0ZWRfaGVhZGVyLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvZ2VuZXJhdGUuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIva2V5L2dlbmVyYXRlX2tleV9wYWlyLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2tleS9nZW5lcmF0ZV9zZWNyZXQuanMiLCIuLi9saWIvYWxnb3JpdGhtcy5tanMiLCIuLi9saWIvcmF3LWJyb3dzZXIubWpzIiwiLi4vbGliL2tyeXB0by5tanMiLCIuLi9saWIvbXVsdGlLcnlwdG8ubWpzIiwiLi4vbGliL3N0b3JlLWluZGV4ZWQubWpzIiwiLi4vbGliL3NlY3JldC5tanMiLCIuLi9saWIvb3JpZ2luLWJyb3dzZXIubWpzIiwiLi4vbGliL21rZGlyLWJyb3dzZXIubWpzIiwiLi4vbGliL3RhZ1BhdGgubWpzIiwiLi4vbGliL3N0b3JhZ2UubWpzIiwiLi4vbGliL2tleVNldC5tanMiLCIuLi9saWIvcGFja2FnZS1sb2FkZXIubWpzIiwiLi4vbGliL2FwaS5tanMiLCIuLi9ub2RlX21vZHVsZXMvQGtpMXIweS9qc29ucnBjL2luZGV4Lm1qcyJdLCJzb3VyY2VzQ29udGVudCI6WyJleHBvcnQgZGVmYXVsdCBjcnlwdG87XG5leHBvcnQgY29uc3QgaXNDcnlwdG9LZXkgPSAoa2V5KSA9PiBrZXkgaW5zdGFuY2VvZiBDcnlwdG9LZXk7XG4iLCJpbXBvcnQgY3J5cHRvIGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmNvbnN0IGRpZ2VzdCA9IGFzeW5jIChhbGdvcml0aG0sIGRhdGEpID0+IHtcbiAgICBjb25zdCBzdWJ0bGVEaWdlc3QgPSBgU0hBLSR7YWxnb3JpdGhtLnNsaWNlKC0zKX1gO1xuICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmRpZ2VzdChzdWJ0bGVEaWdlc3QsIGRhdGEpKTtcbn07XG5leHBvcnQgZGVmYXVsdCBkaWdlc3Q7XG4iLCJpbXBvcnQgZGlnZXN0IGZyb20gJy4uL3J1bnRpbWUvZGlnZXN0LmpzJztcbmV4cG9ydCBjb25zdCBlbmNvZGVyID0gbmV3IFRleHRFbmNvZGVyKCk7XG5leHBvcnQgY29uc3QgZGVjb2RlciA9IG5ldyBUZXh0RGVjb2RlcigpO1xuY29uc3QgTUFYX0lOVDMyID0gMiAqKiAzMjtcbmV4cG9ydCBmdW5jdGlvbiBjb25jYXQoLi4uYnVmZmVycykge1xuICAgIGNvbnN0IHNpemUgPSBidWZmZXJzLnJlZHVjZSgoYWNjLCB7IGxlbmd0aCB9KSA9PiBhY2MgKyBsZW5ndGgsIDApO1xuICAgIGNvbnN0IGJ1ZiA9IG5ldyBVaW50OEFycmF5KHNpemUpO1xuICAgIGxldCBpID0gMDtcbiAgICBmb3IgKGNvbnN0IGJ1ZmZlciBvZiBidWZmZXJzKSB7XG4gICAgICAgIGJ1Zi5zZXQoYnVmZmVyLCBpKTtcbiAgICAgICAgaSArPSBidWZmZXIubGVuZ3RoO1xuICAgIH1cbiAgICByZXR1cm4gYnVmO1xufVxuZXhwb3J0IGZ1bmN0aW9uIHAycyhhbGcsIHAyc0lucHV0KSB7XG4gICAgcmV0dXJuIGNvbmNhdChlbmNvZGVyLmVuY29kZShhbGcpLCBuZXcgVWludDhBcnJheShbMF0pLCBwMnNJbnB1dCk7XG59XG5mdW5jdGlvbiB3cml0ZVVJbnQzMkJFKGJ1ZiwgdmFsdWUsIG9mZnNldCkge1xuICAgIGlmICh2YWx1ZSA8IDAgfHwgdmFsdWUgPj0gTUFYX0lOVDMyKSB7XG4gICAgICAgIHRocm93IG5ldyBSYW5nZUVycm9yKGB2YWx1ZSBtdXN0IGJlID49IDAgYW5kIDw9ICR7TUFYX0lOVDMyIC0gMX0uIFJlY2VpdmVkICR7dmFsdWV9YCk7XG4gICAgfVxuICAgIGJ1Zi5zZXQoW3ZhbHVlID4+PiAyNCwgdmFsdWUgPj4+IDE2LCB2YWx1ZSA+Pj4gOCwgdmFsdWUgJiAweGZmXSwgb2Zmc2V0KTtcbn1cbmV4cG9ydCBmdW5jdGlvbiB1aW50NjRiZSh2YWx1ZSkge1xuICAgIGNvbnN0IGhpZ2ggPSBNYXRoLmZsb29yKHZhbHVlIC8gTUFYX0lOVDMyKTtcbiAgICBjb25zdCBsb3cgPSB2YWx1ZSAlIE1BWF9JTlQzMjtcbiAgICBjb25zdCBidWYgPSBuZXcgVWludDhBcnJheSg4KTtcbiAgICB3cml0ZVVJbnQzMkJFKGJ1ZiwgaGlnaCwgMCk7XG4gICAgd3JpdGVVSW50MzJCRShidWYsIGxvdywgNCk7XG4gICAgcmV0dXJuIGJ1Zjtcbn1cbmV4cG9ydCBmdW5jdGlvbiB1aW50MzJiZSh2YWx1ZSkge1xuICAgIGNvbnN0IGJ1ZiA9IG5ldyBVaW50OEFycmF5KDQpO1xuICAgIHdyaXRlVUludDMyQkUoYnVmLCB2YWx1ZSk7XG4gICAgcmV0dXJuIGJ1Zjtcbn1cbmV4cG9ydCBmdW5jdGlvbiBsZW5ndGhBbmRJbnB1dChpbnB1dCkge1xuICAgIHJldHVybiBjb25jYXQodWludDMyYmUoaW5wdXQubGVuZ3RoKSwgaW5wdXQpO1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGNvbmNhdEtkZihzZWNyZXQsIGJpdHMsIHZhbHVlKSB7XG4gICAgY29uc3QgaXRlcmF0aW9ucyA9IE1hdGguY2VpbCgoYml0cyA+PiAzKSAvIDMyKTtcbiAgICBjb25zdCByZXMgPSBuZXcgVWludDhBcnJheShpdGVyYXRpb25zICogMzIpO1xuICAgIGZvciAobGV0IGl0ZXIgPSAwOyBpdGVyIDwgaXRlcmF0aW9uczsgaXRlcisrKSB7XG4gICAgICAgIGNvbnN0IGJ1ZiA9IG5ldyBVaW50OEFycmF5KDQgKyBzZWNyZXQubGVuZ3RoICsgdmFsdWUubGVuZ3RoKTtcbiAgICAgICAgYnVmLnNldCh1aW50MzJiZShpdGVyICsgMSkpO1xuICAgICAgICBidWYuc2V0KHNlY3JldCwgNCk7XG4gICAgICAgIGJ1Zi5zZXQodmFsdWUsIDQgKyBzZWNyZXQubGVuZ3RoKTtcbiAgICAgICAgcmVzLnNldChhd2FpdCBkaWdlc3QoJ3NoYTI1NicsIGJ1ZiksIGl0ZXIgKiAzMik7XG4gICAgfVxuICAgIHJldHVybiByZXMuc2xpY2UoMCwgYml0cyA+PiAzKTtcbn1cbiIsImltcG9ydCB7IGVuY29kZXIsIGRlY29kZXIgfSBmcm9tICcuLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmV4cG9ydCBjb25zdCBlbmNvZGVCYXNlNjQgPSAoaW5wdXQpID0+IHtcbiAgICBsZXQgdW5lbmNvZGVkID0gaW5wdXQ7XG4gICAgaWYgKHR5cGVvZiB1bmVuY29kZWQgPT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHVuZW5jb2RlZCA9IGVuY29kZXIuZW5jb2RlKHVuZW5jb2RlZCk7XG4gICAgfVxuICAgIGNvbnN0IENIVU5LX1NJWkUgPSAweDgwMDA7XG4gICAgY29uc3QgYXJyID0gW107XG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCB1bmVuY29kZWQubGVuZ3RoOyBpICs9IENIVU5LX1NJWkUpIHtcbiAgICAgICAgYXJyLnB1c2goU3RyaW5nLmZyb21DaGFyQ29kZS5hcHBseShudWxsLCB1bmVuY29kZWQuc3ViYXJyYXkoaSwgaSArIENIVU5LX1NJWkUpKSk7XG4gICAgfVxuICAgIHJldHVybiBidG9hKGFyci5qb2luKCcnKSk7XG59O1xuZXhwb3J0IGNvbnN0IGVuY29kZSA9IChpbnB1dCkgPT4ge1xuICAgIHJldHVybiBlbmNvZGVCYXNlNjQoaW5wdXQpLnJlcGxhY2UoLz0vZywgJycpLnJlcGxhY2UoL1xcKy9nLCAnLScpLnJlcGxhY2UoL1xcLy9nLCAnXycpO1xufTtcbmV4cG9ydCBjb25zdCBkZWNvZGVCYXNlNjQgPSAoZW5jb2RlZCkgPT4ge1xuICAgIGNvbnN0IGJpbmFyeSA9IGF0b2IoZW5jb2RlZCk7XG4gICAgY29uc3QgYnl0ZXMgPSBuZXcgVWludDhBcnJheShiaW5hcnkubGVuZ3RoKTtcbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IGJpbmFyeS5sZW5ndGg7IGkrKykge1xuICAgICAgICBieXRlc1tpXSA9IGJpbmFyeS5jaGFyQ29kZUF0KGkpO1xuICAgIH1cbiAgICByZXR1cm4gYnl0ZXM7XG59O1xuZXhwb3J0IGNvbnN0IGRlY29kZSA9IChpbnB1dCkgPT4ge1xuICAgIGxldCBlbmNvZGVkID0gaW5wdXQ7XG4gICAgaWYgKGVuY29kZWQgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIGVuY29kZWQgPSBkZWNvZGVyLmRlY29kZShlbmNvZGVkKTtcbiAgICB9XG4gICAgZW5jb2RlZCA9IGVuY29kZWQucmVwbGFjZSgvLS9nLCAnKycpLnJlcGxhY2UoL18vZywgJy8nKS5yZXBsYWNlKC9cXHMvZywgJycpO1xuICAgIHRyeSB7XG4gICAgICAgIHJldHVybiBkZWNvZGVCYXNlNjQoZW5jb2RlZCk7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignVGhlIGlucHV0IHRvIGJlIGRlY29kZWQgaXMgbm90IGNvcnJlY3RseSBlbmNvZGVkLicpO1xuICAgIH1cbn07XG4iLCJleHBvcnQgY2xhc3MgSk9TRUVycm9yIGV4dGVuZHMgRXJyb3Ige1xuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSk9TRV9HRU5FUklDJztcbiAgICB9XG4gICAgY29uc3RydWN0b3IobWVzc2FnZSkge1xuICAgICAgICBzdXBlcihtZXNzYWdlKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KT1NFX0dFTkVSSUMnO1xuICAgICAgICB0aGlzLm5hbWUgPSB0aGlzLmNvbnN0cnVjdG9yLm5hbWU7XG4gICAgICAgIEVycm9yLmNhcHR1cmVTdGFja1RyYWNlPy4odGhpcywgdGhpcy5jb25zdHJ1Y3Rvcik7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXVENsYWltVmFsaWRhdGlvbkZhaWxlZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV1RfQ0xBSU1fVkFMSURBVElPTl9GQUlMRUQnO1xuICAgIH1cbiAgICBjb25zdHJ1Y3RvcihtZXNzYWdlLCBjbGFpbSA9ICd1bnNwZWNpZmllZCcsIHJlYXNvbiA9ICd1bnNwZWNpZmllZCcpIHtcbiAgICAgICAgc3VwZXIobWVzc2FnZSk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldUX0NMQUlNX1ZBTElEQVRJT05fRkFJTEVEJztcbiAgICAgICAgdGhpcy5jbGFpbSA9IGNsYWltO1xuICAgICAgICB0aGlzLnJlYXNvbiA9IHJlYXNvbjtcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgSldURXhwaXJlZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV1RfRVhQSVJFRCc7XG4gICAgfVxuICAgIGNvbnN0cnVjdG9yKG1lc3NhZ2UsIGNsYWltID0gJ3Vuc3BlY2lmaWVkJywgcmVhc29uID0gJ3Vuc3BlY2lmaWVkJykge1xuICAgICAgICBzdXBlcihtZXNzYWdlKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV1RfRVhQSVJFRCc7XG4gICAgICAgIHRoaXMuY2xhaW0gPSBjbGFpbTtcbiAgICAgICAgdGhpcy5yZWFzb24gPSByZWFzb247XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpPU0VBbGdOb3RBbGxvd2VkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KT1NFX0FMR19OT1RfQUxMT1dFRCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSk9TRV9BTEdfTk9UX0FMTE9XRUQnO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKT1NFTm90U3VwcG9ydGVkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KT1NFX05PVF9TVVBQT1JURUQnO1xuICAgIH1cbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pPU0VfTk9UX1NVUFBPUlRFRCc7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXRURlY3J5cHRpb25GYWlsZWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXRV9ERUNSWVBUSU9OX0ZBSUxFRCc7XG4gICAgICAgIHRoaXMubWVzc2FnZSA9ICdkZWNyeXB0aW9uIG9wZXJhdGlvbiBmYWlsZWQnO1xuICAgIH1cbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pXRV9ERUNSWVBUSU9OX0ZBSUxFRCc7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXRUludmFsaWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXRV9JTlZBTElEJztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV0VfSU5WQUxJRCc7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXU0ludmFsaWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXU19JTlZBTElEJztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV1NfSU5WQUxJRCc7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXVEludmFsaWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXVF9JTlZBTElEJztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV1RfSU5WQUxJRCc7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXS0ludmFsaWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXS19JTlZBTElEJztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV0tfSU5WQUxJRCc7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXS1NJbnZhbGlkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0tTX0lOVkFMSUQnO1xuICAgIH1cbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pXS1NfSU5WQUxJRCc7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXS1NOb01hdGNoaW5nS2V5IGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0tTX05PX01BVENISU5HX0tFWSc7XG4gICAgICAgIHRoaXMubWVzc2FnZSA9ICdubyBhcHBsaWNhYmxlIGtleSBmb3VuZCBpbiB0aGUgSlNPTiBXZWIgS2V5IFNldCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldLU19OT19NQVRDSElOR19LRVknO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV0tTTXVsdGlwbGVNYXRjaGluZ0tleXMgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXS1NfTVVMVElQTEVfTUFUQ0hJTkdfS0VZUyc7XG4gICAgICAgIHRoaXMubWVzc2FnZSA9ICdtdWx0aXBsZSBtYXRjaGluZyBrZXlzIGZvdW5kIGluIHRoZSBKU09OIFdlYiBLZXkgU2V0JztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV0tTX01VTFRJUExFX01BVENISU5HX0tFWVMnO1xuICAgIH1cbn1cblN5bWJvbC5hc3luY0l0ZXJhdG9yO1xuZXhwb3J0IGNsYXNzIEpXS1NUaW1lb3V0IGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0tTX1RJTUVPVVQnO1xuICAgICAgICB0aGlzLm1lc3NhZ2UgPSAncmVxdWVzdCB0aW1lZCBvdXQnO1xuICAgIH1cbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pXS1NfVElNRU9VVCc7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXU1NpZ25hdHVyZVZlcmlmaWNhdGlvbkZhaWxlZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldTX1NJR05BVFVSRV9WRVJJRklDQVRJT05fRkFJTEVEJztcbiAgICAgICAgdGhpcy5tZXNzYWdlID0gJ3NpZ25hdHVyZSB2ZXJpZmljYXRpb24gZmFpbGVkJztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV1NfU0lHTkFUVVJFX1ZFUklGSUNBVElPTl9GQUlMRUQnO1xuICAgIH1cbn1cbiIsImltcG9ydCBjcnlwdG8gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuZXhwb3J0IGRlZmF1bHQgY3J5cHRvLmdldFJhbmRvbVZhbHVlcy5iaW5kKGNyeXB0byk7XG4iLCJpbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHJhbmRvbSBmcm9tICcuLi9ydW50aW1lL3JhbmRvbS5qcyc7XG5leHBvcnQgZnVuY3Rpb24gYml0TGVuZ3RoKGFsZykge1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ0ExMjhHQ00nOlxuICAgICAgICBjYXNlICdBMTI4R0NNS1cnOlxuICAgICAgICBjYXNlICdBMTkyR0NNJzpcbiAgICAgICAgY2FzZSAnQTE5MkdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTSc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ01LVyc6XG4gICAgICAgICAgICByZXR1cm4gOTY7XG4gICAgICAgIGNhc2UgJ0ExMjhDQkMtSFMyNTYnOlxuICAgICAgICBjYXNlICdBMTkyQ0JDLUhTMzg0JzpcbiAgICAgICAgY2FzZSAnQTI1NkNCQy1IUzUxMic6XG4gICAgICAgICAgICByZXR1cm4gMTI4O1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoYFVuc3VwcG9ydGVkIEpXRSBBbGdvcml0aG06ICR7YWxnfWApO1xuICAgIH1cbn1cbmV4cG9ydCBkZWZhdWx0IChhbGcpID0+IHJhbmRvbShuZXcgVWludDhBcnJheShiaXRMZW5ndGgoYWxnKSA+PiAzKSk7XG4iLCJpbXBvcnQgeyBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHsgYml0TGVuZ3RoIH0gZnJvbSAnLi9pdi5qcyc7XG5jb25zdCBjaGVja0l2TGVuZ3RoID0gKGVuYywgaXYpID0+IHtcbiAgICBpZiAoaXYubGVuZ3RoIDw8IDMgIT09IGJpdExlbmd0aChlbmMpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdJbnZhbGlkIEluaXRpYWxpemF0aW9uIFZlY3RvciBsZW5ndGgnKTtcbiAgICB9XG59O1xuZXhwb3J0IGRlZmF1bHQgY2hlY2tJdkxlbmd0aDtcbiIsImltcG9ydCB7IEpXRUludmFsaWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5jb25zdCBjaGVja0Nla0xlbmd0aCA9IChjZWssIGV4cGVjdGVkKSA9PiB7XG4gICAgY29uc3QgYWN0dWFsID0gY2VrLmJ5dGVMZW5ndGggPDwgMztcbiAgICBpZiAoYWN0dWFsICE9PSBleHBlY3RlZCkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSW52YWxpZCBDb250ZW50IEVuY3J5cHRpb24gS2V5IGxlbmd0aC4gRXhwZWN0ZWQgJHtleHBlY3RlZH0gYml0cywgZ290ICR7YWN0dWFsfSBiaXRzYCk7XG4gICAgfVxufTtcbmV4cG9ydCBkZWZhdWx0IGNoZWNrQ2VrTGVuZ3RoO1xuIiwiY29uc3QgdGltaW5nU2FmZUVxdWFsID0gKGEsIGIpID0+IHtcbiAgICBpZiAoIShhIGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignRmlyc3QgYXJndW1lbnQgbXVzdCBiZSBhIGJ1ZmZlcicpO1xuICAgIH1cbiAgICBpZiAoIShiIGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignU2Vjb25kIGFyZ3VtZW50IG11c3QgYmUgYSBidWZmZXInKTtcbiAgICB9XG4gICAgaWYgKGEubGVuZ3RoICE9PSBiLmxlbmd0aCkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdJbnB1dCBidWZmZXJzIG11c3QgaGF2ZSB0aGUgc2FtZSBsZW5ndGgnKTtcbiAgICB9XG4gICAgY29uc3QgbGVuID0gYS5sZW5ndGg7XG4gICAgbGV0IG91dCA9IDA7XG4gICAgbGV0IGkgPSAtMTtcbiAgICB3aGlsZSAoKytpIDwgbGVuKSB7XG4gICAgICAgIG91dCB8PSBhW2ldIF4gYltpXTtcbiAgICB9XG4gICAgcmV0dXJuIG91dCA9PT0gMDtcbn07XG5leHBvcnQgZGVmYXVsdCB0aW1pbmdTYWZlRXF1YWw7XG4iLCJmdW5jdGlvbiB1bnVzYWJsZShuYW1lLCBwcm9wID0gJ2FsZ29yaXRobS5uYW1lJykge1xuICAgIHJldHVybiBuZXcgVHlwZUVycm9yKGBDcnlwdG9LZXkgZG9lcyBub3Qgc3VwcG9ydCB0aGlzIG9wZXJhdGlvbiwgaXRzICR7cHJvcH0gbXVzdCBiZSAke25hbWV9YCk7XG59XG5mdW5jdGlvbiBpc0FsZ29yaXRobShhbGdvcml0aG0sIG5hbWUpIHtcbiAgICByZXR1cm4gYWxnb3JpdGhtLm5hbWUgPT09IG5hbWU7XG59XG5mdW5jdGlvbiBnZXRIYXNoTGVuZ3RoKGhhc2gpIHtcbiAgICByZXR1cm4gcGFyc2VJbnQoaGFzaC5uYW1lLnNsaWNlKDQpLCAxMCk7XG59XG5mdW5jdGlvbiBnZXROYW1lZEN1cnZlKGFsZykge1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ0VTMjU2JzpcbiAgICAgICAgICAgIHJldHVybiAnUC0yNTYnO1xuICAgICAgICBjYXNlICdFUzM4NCc6XG4gICAgICAgICAgICByZXR1cm4gJ1AtMzg0JztcbiAgICAgICAgY2FzZSAnRVM1MTInOlxuICAgICAgICAgICAgcmV0dXJuICdQLTUyMSc7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ3VucmVhY2hhYmxlJyk7XG4gICAgfVxufVxuZnVuY3Rpb24gY2hlY2tVc2FnZShrZXksIHVzYWdlcykge1xuICAgIGlmICh1c2FnZXMubGVuZ3RoICYmICF1c2FnZXMuc29tZSgoZXhwZWN0ZWQpID0+IGtleS51c2FnZXMuaW5jbHVkZXMoZXhwZWN0ZWQpKSkge1xuICAgICAgICBsZXQgbXNnID0gJ0NyeXB0b0tleSBkb2VzIG5vdCBzdXBwb3J0IHRoaXMgb3BlcmF0aW9uLCBpdHMgdXNhZ2VzIG11c3QgaW5jbHVkZSAnO1xuICAgICAgICBpZiAodXNhZ2VzLmxlbmd0aCA+IDIpIHtcbiAgICAgICAgICAgIGNvbnN0IGxhc3QgPSB1c2FnZXMucG9wKCk7XG4gICAgICAgICAgICBtc2cgKz0gYG9uZSBvZiAke3VzYWdlcy5qb2luKCcsICcpfSwgb3IgJHtsYXN0fS5gO1xuICAgICAgICB9XG4gICAgICAgIGVsc2UgaWYgKHVzYWdlcy5sZW5ndGggPT09IDIpIHtcbiAgICAgICAgICAgIG1zZyArPSBgb25lIG9mICR7dXNhZ2VzWzBdfSBvciAke3VzYWdlc1sxXX0uYDtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIG1zZyArPSBgJHt1c2FnZXNbMF19LmA7XG4gICAgICAgIH1cbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihtc2cpO1xuICAgIH1cbn1cbmV4cG9ydCBmdW5jdGlvbiBjaGVja1NpZ0NyeXB0b0tleShrZXksIGFsZywgLi4udXNhZ2VzKSB7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnSFMyNTYnOlxuICAgICAgICBjYXNlICdIUzM4NCc6XG4gICAgICAgIGNhc2UgJ0hTNTEyJzoge1xuICAgICAgICAgICAgaWYgKCFpc0FsZ29yaXRobShrZXkuYWxnb3JpdGhtLCAnSE1BQycpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdITUFDJyk7XG4gICAgICAgICAgICBjb25zdCBleHBlY3RlZCA9IHBhcnNlSW50KGFsZy5zbGljZSgyKSwgMTApO1xuICAgICAgICAgICAgY29uc3QgYWN0dWFsID0gZ2V0SGFzaExlbmd0aChrZXkuYWxnb3JpdGhtLmhhc2gpO1xuICAgICAgICAgICAgaWYgKGFjdHVhbCAhPT0gZXhwZWN0ZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoYFNIQS0ke2V4cGVjdGVkfWAsICdhbGdvcml0aG0uaGFzaCcpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnUlMyNTYnOlxuICAgICAgICBjYXNlICdSUzM4NCc6XG4gICAgICAgIGNhc2UgJ1JTNTEyJzoge1xuICAgICAgICAgICAgaWYgKCFpc0FsZ29yaXRobShrZXkuYWxnb3JpdGhtLCAnUlNBU1NBLVBLQ1MxLXYxXzUnKSlcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnUlNBU1NBLVBLQ1MxLXYxXzUnKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGVjdGVkID0gcGFyc2VJbnQoYWxnLnNsaWNlKDIpLCAxMCk7XG4gICAgICAgICAgICBjb25zdCBhY3R1YWwgPSBnZXRIYXNoTGVuZ3RoKGtleS5hbGdvcml0aG0uaGFzaCk7XG4gICAgICAgICAgICBpZiAoYWN0dWFsICE9PSBleHBlY3RlZClcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZShgU0hBLSR7ZXhwZWN0ZWR9YCwgJ2FsZ29yaXRobS5oYXNoJyk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdQUzI1Nic6XG4gICAgICAgIGNhc2UgJ1BTMzg0JzpcbiAgICAgICAgY2FzZSAnUFM1MTInOiB7XG4gICAgICAgICAgICBpZiAoIWlzQWxnb3JpdGhtKGtleS5hbGdvcml0aG0sICdSU0EtUFNTJykpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ1JTQS1QU1MnKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGVjdGVkID0gcGFyc2VJbnQoYWxnLnNsaWNlKDIpLCAxMCk7XG4gICAgICAgICAgICBjb25zdCBhY3R1YWwgPSBnZXRIYXNoTGVuZ3RoKGtleS5hbGdvcml0aG0uaGFzaCk7XG4gICAgICAgICAgICBpZiAoYWN0dWFsICE9PSBleHBlY3RlZClcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZShgU0hBLSR7ZXhwZWN0ZWR9YCwgJ2FsZ29yaXRobS5oYXNoJyk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdFZERTQSc6IHtcbiAgICAgICAgICAgIGlmIChrZXkuYWxnb3JpdGhtLm5hbWUgIT09ICdFZDI1NTE5JyAmJiBrZXkuYWxnb3JpdGhtLm5hbWUgIT09ICdFZDQ0OCcpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnRWQyNTUxOSBvciBFZDQ0OCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnRVMyNTYnOlxuICAgICAgICBjYXNlICdFUzM4NCc6XG4gICAgICAgIGNhc2UgJ0VTNTEyJzoge1xuICAgICAgICAgICAgaWYgKCFpc0FsZ29yaXRobShrZXkuYWxnb3JpdGhtLCAnRUNEU0EnKSlcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnRUNEU0EnKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGVjdGVkID0gZ2V0TmFtZWRDdXJ2ZShhbGcpO1xuICAgICAgICAgICAgY29uc3QgYWN0dWFsID0ga2V5LmFsZ29yaXRobS5uYW1lZEN1cnZlO1xuICAgICAgICAgICAgaWYgKGFjdHVhbCAhPT0gZXhwZWN0ZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoZXhwZWN0ZWQsICdhbGdvcml0aG0ubmFtZWRDdXJ2ZScpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0NyeXB0b0tleSBkb2VzIG5vdCBzdXBwb3J0IHRoaXMgb3BlcmF0aW9uJyk7XG4gICAgfVxuICAgIGNoZWNrVXNhZ2Uoa2V5LCB1c2FnZXMpO1xufVxuZXhwb3J0IGZ1bmN0aW9uIGNoZWNrRW5jQ3J5cHRvS2V5KGtleSwgYWxnLCAuLi51c2FnZXMpIHtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdBMTI4R0NNJzpcbiAgICAgICAgY2FzZSAnQTE5MkdDTSc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ00nOiB7XG4gICAgICAgICAgICBpZiAoIWlzQWxnb3JpdGhtKGtleS5hbGdvcml0aG0sICdBRVMtR0NNJykpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ0FFUy1HQ00nKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGVjdGVkID0gcGFyc2VJbnQoYWxnLnNsaWNlKDEsIDQpLCAxMCk7XG4gICAgICAgICAgICBjb25zdCBhY3R1YWwgPSBrZXkuYWxnb3JpdGhtLmxlbmd0aDtcbiAgICAgICAgICAgIGlmIChhY3R1YWwgIT09IGV4cGVjdGVkKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKGV4cGVjdGVkLCAnYWxnb3JpdGhtLmxlbmd0aCcpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnQTE5MktXJzpcbiAgICAgICAgY2FzZSAnQTI1NktXJzoge1xuICAgICAgICAgICAgaWYgKCFpc0FsZ29yaXRobShrZXkuYWxnb3JpdGhtLCAnQUVTLUtXJykpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ0FFUy1LVycpO1xuICAgICAgICAgICAgY29uc3QgZXhwZWN0ZWQgPSBwYXJzZUludChhbGcuc2xpY2UoMSwgNCksIDEwKTtcbiAgICAgICAgICAgIGNvbnN0IGFjdHVhbCA9IGtleS5hbGdvcml0aG0ubGVuZ3RoO1xuICAgICAgICAgICAgaWYgKGFjdHVhbCAhPT0gZXhwZWN0ZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoZXhwZWN0ZWQsICdhbGdvcml0aG0ubGVuZ3RoJyk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdFQ0RIJzoge1xuICAgICAgICAgICAgc3dpdGNoIChrZXkuYWxnb3JpdGhtLm5hbWUpIHtcbiAgICAgICAgICAgICAgICBjYXNlICdFQ0RIJzpcbiAgICAgICAgICAgICAgICBjYXNlICdYMjU1MTknOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1g0NDgnOlxuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnRUNESCwgWDI1NTE5LCBvciBYNDQ4Jyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdQQkVTMi1IUzI1NitBMTI4S1cnOlxuICAgICAgICBjYXNlICdQQkVTMi1IUzM4NCtBMTkyS1cnOlxuICAgICAgICBjYXNlICdQQkVTMi1IUzUxMitBMjU2S1cnOlxuICAgICAgICAgICAgaWYgKCFpc0FsZ29yaXRobShrZXkuYWxnb3JpdGhtLCAnUEJLREYyJykpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ1BCS0RGMicpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQJzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMjU2JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMzg0JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtNTEyJzoge1xuICAgICAgICAgICAgaWYgKCFpc0FsZ29yaXRobShrZXkuYWxnb3JpdGhtLCAnUlNBLU9BRVAnKSlcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnUlNBLU9BRVAnKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGVjdGVkID0gcGFyc2VJbnQoYWxnLnNsaWNlKDkpLCAxMCkgfHwgMTtcbiAgICAgICAgICAgIGNvbnN0IGFjdHVhbCA9IGdldEhhc2hMZW5ndGgoa2V5LmFsZ29yaXRobS5oYXNoKTtcbiAgICAgICAgICAgIGlmIChhY3R1YWwgIT09IGV4cGVjdGVkKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKGBTSEEtJHtleHBlY3RlZH1gLCAnYWxnb3JpdGhtLmhhc2gnKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdDcnlwdG9LZXkgZG9lcyBub3Qgc3VwcG9ydCB0aGlzIG9wZXJhdGlvbicpO1xuICAgIH1cbiAgICBjaGVja1VzYWdlKGtleSwgdXNhZ2VzKTtcbn1cbiIsImZ1bmN0aW9uIG1lc3NhZ2UobXNnLCBhY3R1YWwsIC4uLnR5cGVzKSB7XG4gICAgaWYgKHR5cGVzLmxlbmd0aCA+IDIpIHtcbiAgICAgICAgY29uc3QgbGFzdCA9IHR5cGVzLnBvcCgpO1xuICAgICAgICBtc2cgKz0gYG9uZSBvZiB0eXBlICR7dHlwZXMuam9pbignLCAnKX0sIG9yICR7bGFzdH0uYDtcbiAgICB9XG4gICAgZWxzZSBpZiAodHlwZXMubGVuZ3RoID09PSAyKSB7XG4gICAgICAgIG1zZyArPSBgb25lIG9mIHR5cGUgJHt0eXBlc1swXX0gb3IgJHt0eXBlc1sxXX0uYDtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIG1zZyArPSBgb2YgdHlwZSAke3R5cGVzWzBdfS5gO1xuICAgIH1cbiAgICBpZiAoYWN0dWFsID09IG51bGwpIHtcbiAgICAgICAgbXNnICs9IGAgUmVjZWl2ZWQgJHthY3R1YWx9YDtcbiAgICB9XG4gICAgZWxzZSBpZiAodHlwZW9mIGFjdHVhbCA9PT0gJ2Z1bmN0aW9uJyAmJiBhY3R1YWwubmFtZSkge1xuICAgICAgICBtc2cgKz0gYCBSZWNlaXZlZCBmdW5jdGlvbiAke2FjdHVhbC5uYW1lfWA7XG4gICAgfVxuICAgIGVsc2UgaWYgKHR5cGVvZiBhY3R1YWwgPT09ICdvYmplY3QnICYmIGFjdHVhbCAhPSBudWxsKSB7XG4gICAgICAgIGlmIChhY3R1YWwuY29uc3RydWN0b3I/Lm5hbWUpIHtcbiAgICAgICAgICAgIG1zZyArPSBgIFJlY2VpdmVkIGFuIGluc3RhbmNlIG9mICR7YWN0dWFsLmNvbnN0cnVjdG9yLm5hbWV9YDtcbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gbXNnO1xufVxuZXhwb3J0IGRlZmF1bHQgKGFjdHVhbCwgLi4udHlwZXMpID0+IHtcbiAgICByZXR1cm4gbWVzc2FnZSgnS2V5IG11c3QgYmUgJywgYWN0dWFsLCAuLi50eXBlcyk7XG59O1xuZXhwb3J0IGZ1bmN0aW9uIHdpdGhBbGcoYWxnLCBhY3R1YWwsIC4uLnR5cGVzKSB7XG4gICAgcmV0dXJuIG1lc3NhZ2UoYEtleSBmb3IgdGhlICR7YWxnfSBhbGdvcml0aG0gbXVzdCBiZSBgLCBhY3R1YWwsIC4uLnR5cGVzKTtcbn1cbiIsImltcG9ydCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuZXhwb3J0IGRlZmF1bHQgKGtleSkgPT4ge1xuICAgIHJldHVybiBpc0NyeXB0b0tleShrZXkpO1xufTtcbmV4cG9ydCBjb25zdCB0eXBlcyA9IFsnQ3J5cHRvS2V5J107XG4iLCJpbXBvcnQgeyBjb25jYXQsIHVpbnQ2NGJlIH0gZnJvbSAnLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgY2hlY2tJdkxlbmd0aCBmcm9tICcuLi9saWIvY2hlY2tfaXZfbGVuZ3RoLmpzJztcbmltcG9ydCBjaGVja0Nla0xlbmd0aCBmcm9tICcuL2NoZWNrX2Nla19sZW5ndGguanMnO1xuaW1wb3J0IHRpbWluZ1NhZmVFcXVhbCBmcm9tICcuL3RpbWluZ19zYWZlX2VxdWFsLmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQsIEpXRURlY3J5cHRpb25GYWlsZWQsIEpXRUludmFsaWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tFbmNDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuYXN5bmMgZnVuY3Rpb24gY2JjRGVjcnlwdChlbmMsIGNlaywgY2lwaGVydGV4dCwgaXYsIHRhZywgYWFkKSB7XG4gICAgaWYgKCEoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoY2VrLCAnVWludDhBcnJheScpKTtcbiAgICB9XG4gICAgY29uc3Qga2V5U2l6ZSA9IHBhcnNlSW50KGVuYy5zbGljZSgxLCA0KSwgMTApO1xuICAgIGNvbnN0IGVuY0tleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBjZWsuc3ViYXJyYXkoa2V5U2l6ZSA+PiAzKSwgJ0FFUy1DQkMnLCBmYWxzZSwgWydkZWNyeXB0J10pO1xuICAgIGNvbnN0IG1hY0tleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBjZWsuc3ViYXJyYXkoMCwga2V5U2l6ZSA+PiAzKSwge1xuICAgICAgICBoYXNoOiBgU0hBLSR7a2V5U2l6ZSA8PCAxfWAsXG4gICAgICAgIG5hbWU6ICdITUFDJyxcbiAgICB9LCBmYWxzZSwgWydzaWduJ10pO1xuICAgIGNvbnN0IG1hY0RhdGEgPSBjb25jYXQoYWFkLCBpdiwgY2lwaGVydGV4dCwgdWludDY0YmUoYWFkLmxlbmd0aCA8PCAzKSk7XG4gICAgY29uc3QgZXhwZWN0ZWRUYWcgPSBuZXcgVWludDhBcnJheSgoYXdhaXQgY3J5cHRvLnN1YnRsZS5zaWduKCdITUFDJywgbWFjS2V5LCBtYWNEYXRhKSkuc2xpY2UoMCwga2V5U2l6ZSA+PiAzKSk7XG4gICAgbGV0IG1hY0NoZWNrUGFzc2VkO1xuICAgIHRyeSB7XG4gICAgICAgIG1hY0NoZWNrUGFzc2VkID0gdGltaW5nU2FmZUVxdWFsKHRhZywgZXhwZWN0ZWRUYWcpO1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgfVxuICAgIGlmICghbWFjQ2hlY2tQYXNzZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRURlY3J5cHRpb25GYWlsZWQoKTtcbiAgICB9XG4gICAgbGV0IHBsYWludGV4dDtcbiAgICB0cnkge1xuICAgICAgICBwbGFpbnRleHQgPSBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmRlY3J5cHQoeyBpdiwgbmFtZTogJ0FFUy1DQkMnIH0sIGVuY0tleSwgY2lwaGVydGV4dCkpO1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgfVxuICAgIGlmICghcGxhaW50ZXh0KSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VEZWNyeXB0aW9uRmFpbGVkKCk7XG4gICAgfVxuICAgIHJldHVybiBwbGFpbnRleHQ7XG59XG5hc3luYyBmdW5jdGlvbiBnY21EZWNyeXB0KGVuYywgY2VrLCBjaXBoZXJ0ZXh0LCBpdiwgdGFnLCBhYWQpIHtcbiAgICBsZXQgZW5jS2V5O1xuICAgIGlmIChjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIGVuY0tleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBjZWssICdBRVMtR0NNJywgZmFsc2UsIFsnZGVjcnlwdCddKTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIGNoZWNrRW5jQ3J5cHRvS2V5KGNlaywgZW5jLCAnZGVjcnlwdCcpO1xuICAgICAgICBlbmNLZXkgPSBjZWs7XG4gICAgfVxuICAgIHRyeSB7XG4gICAgICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmRlY3J5cHQoe1xuICAgICAgICAgICAgYWRkaXRpb25hbERhdGE6IGFhZCxcbiAgICAgICAgICAgIGl2LFxuICAgICAgICAgICAgbmFtZTogJ0FFUy1HQ00nLFxuICAgICAgICAgICAgdGFnTGVuZ3RoOiAxMjgsXG4gICAgICAgIH0sIGVuY0tleSwgY29uY2F0KGNpcGhlcnRleHQsIHRhZykpKTtcbiAgICB9XG4gICAgY2F0Y2gge1xuICAgICAgICB0aHJvdyBuZXcgSldFRGVjcnlwdGlvbkZhaWxlZCgpO1xuICAgIH1cbn1cbmNvbnN0IGRlY3J5cHQgPSBhc3luYyAoZW5jLCBjZWssIGNpcGhlcnRleHQsIGl2LCB0YWcsIGFhZCkgPT4ge1xuICAgIGlmICghaXNDcnlwdG9LZXkoY2VrKSAmJiAhKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGNlaywgLi4udHlwZXMsICdVaW50OEFycmF5JykpO1xuICAgIH1cbiAgICBpZiAoIWl2KSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgSW5pdGlhbGl6YXRpb24gVmVjdG9yIG1pc3NpbmcnKTtcbiAgICB9XG4gICAgaWYgKCF0YWcpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBBdXRoZW50aWNhdGlvbiBUYWcgbWlzc2luZycpO1xuICAgIH1cbiAgICBjaGVja0l2TGVuZ3RoKGVuYywgaXYpO1xuICAgIHN3aXRjaCAoZW5jKSB7XG4gICAgICAgIGNhc2UgJ0ExMjhDQkMtSFMyNTYnOlxuICAgICAgICBjYXNlICdBMTkyQ0JDLUhTMzg0JzpcbiAgICAgICAgY2FzZSAnQTI1NkNCQy1IUzUxMic6XG4gICAgICAgICAgICBpZiAoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSlcbiAgICAgICAgICAgICAgICBjaGVja0Nla0xlbmd0aChjZWssIHBhcnNlSW50KGVuYy5zbGljZSgtMyksIDEwKSk7XG4gICAgICAgICAgICByZXR1cm4gY2JjRGVjcnlwdChlbmMsIGNlaywgY2lwaGVydGV4dCwgaXYsIHRhZywgYWFkKTtcbiAgICAgICAgY2FzZSAnQTEyOEdDTSc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ00nOlxuICAgICAgICBjYXNlICdBMjU2R0NNJzpcbiAgICAgICAgICAgIGlmIChjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KVxuICAgICAgICAgICAgICAgIGNoZWNrQ2VrTGVuZ3RoKGNlaywgcGFyc2VJbnQoZW5jLnNsaWNlKDEsIDQpLCAxMCkpO1xuICAgICAgICAgICAgcmV0dXJuIGdjbURlY3J5cHQoZW5jLCBjZWssIGNpcGhlcnRleHQsIGl2LCB0YWcsIGFhZCk7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnVW5zdXBwb3J0ZWQgSldFIENvbnRlbnQgRW5jcnlwdGlvbiBBbGdvcml0aG0nKTtcbiAgICB9XG59O1xuZXhwb3J0IGRlZmF1bHQgZGVjcnlwdDtcbiIsImNvbnN0IGlzRGlzam9pbnQgPSAoLi4uaGVhZGVycykgPT4ge1xuICAgIGNvbnN0IHNvdXJjZXMgPSBoZWFkZXJzLmZpbHRlcihCb29sZWFuKTtcbiAgICBpZiAoc291cmNlcy5sZW5ndGggPT09IDAgfHwgc291cmNlcy5sZW5ndGggPT09IDEpIHtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIGxldCBhY2M7XG4gICAgZm9yIChjb25zdCBoZWFkZXIgb2Ygc291cmNlcykge1xuICAgICAgICBjb25zdCBwYXJhbWV0ZXJzID0gT2JqZWN0LmtleXMoaGVhZGVyKTtcbiAgICAgICAgaWYgKCFhY2MgfHwgYWNjLnNpemUgPT09IDApIHtcbiAgICAgICAgICAgIGFjYyA9IG5ldyBTZXQocGFyYW1ldGVycyk7XG4gICAgICAgICAgICBjb250aW51ZTtcbiAgICAgICAgfVxuICAgICAgICBmb3IgKGNvbnN0IHBhcmFtZXRlciBvZiBwYXJhbWV0ZXJzKSB7XG4gICAgICAgICAgICBpZiAoYWNjLmhhcyhwYXJhbWV0ZXIpKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYWNjLmFkZChwYXJhbWV0ZXIpO1xuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiB0cnVlO1xufTtcbmV4cG9ydCBkZWZhdWx0IGlzRGlzam9pbnQ7XG4iLCJmdW5jdGlvbiBpc09iamVjdExpa2UodmFsdWUpIHtcbiAgICByZXR1cm4gdHlwZW9mIHZhbHVlID09PSAnb2JqZWN0JyAmJiB2YWx1ZSAhPT0gbnVsbDtcbn1cbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGlzT2JqZWN0KGlucHV0KSB7XG4gICAgaWYgKCFpc09iamVjdExpa2UoaW5wdXQpIHx8IE9iamVjdC5wcm90b3R5cGUudG9TdHJpbmcuY2FsbChpbnB1dCkgIT09ICdbb2JqZWN0IE9iamVjdF0nKSB7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gICAgaWYgKE9iamVjdC5nZXRQcm90b3R5cGVPZihpbnB1dCkgPT09IG51bGwpIHtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIGxldCBwcm90byA9IGlucHV0O1xuICAgIHdoaWxlIChPYmplY3QuZ2V0UHJvdG90eXBlT2YocHJvdG8pICE9PSBudWxsKSB7XG4gICAgICAgIHByb3RvID0gT2JqZWN0LmdldFByb3RvdHlwZU9mKHByb3RvKTtcbiAgICB9XG4gICAgcmV0dXJuIE9iamVjdC5nZXRQcm90b3R5cGVPZihpbnB1dCkgPT09IHByb3RvO1xufVxuIiwiY29uc3QgYm9ndXNXZWJDcnlwdG8gPSBbXG4gICAgeyBoYXNoOiAnU0hBLTI1NicsIG5hbWU6ICdITUFDJyB9LFxuICAgIHRydWUsXG4gICAgWydzaWduJ10sXG5dO1xuZXhwb3J0IGRlZmF1bHQgYm9ndXNXZWJDcnlwdG87XG4iLCJpbXBvcnQgYm9ndXNXZWJDcnlwdG8gZnJvbSAnLi9ib2d1cy5qcyc7XG5pbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tFbmNDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuZnVuY3Rpb24gY2hlY2tLZXlTaXplKGtleSwgYWxnKSB7XG4gICAgaWYgKGtleS5hbGdvcml0aG0ubGVuZ3RoICE9PSBwYXJzZUludChhbGcuc2xpY2UoMSwgNCksIDEwKSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGBJbnZhbGlkIGtleSBzaXplIGZvciBhbGc6ICR7YWxnfWApO1xuICAgIH1cbn1cbmZ1bmN0aW9uIGdldENyeXB0b0tleShrZXksIGFsZywgdXNhZ2UpIHtcbiAgICBpZiAoaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICBjaGVja0VuY0NyeXB0b0tleShrZXksIGFsZywgdXNhZ2UpO1xuICAgICAgICByZXR1cm4ga2V5O1xuICAgIH1cbiAgICBpZiAoa2V5IGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICByZXR1cm4gY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGtleSwgJ0FFUy1LVycsIHRydWUsIFt1c2FnZV0pO1xuICAgIH1cbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzLCAnVWludDhBcnJheScpKTtcbn1cbmV4cG9ydCBjb25zdCB3cmFwID0gYXN5bmMgKGFsZywga2V5LCBjZWspID0+IHtcbiAgICBjb25zdCBjcnlwdG9LZXkgPSBhd2FpdCBnZXRDcnlwdG9LZXkoa2V5LCBhbGcsICd3cmFwS2V5Jyk7XG4gICAgY2hlY2tLZXlTaXplKGNyeXB0b0tleSwgYWxnKTtcbiAgICBjb25zdCBjcnlwdG9LZXlDZWsgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLCAuLi5ib2d1c1dlYkNyeXB0byk7XG4gICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUud3JhcEtleSgncmF3JywgY3J5cHRvS2V5Q2VrLCBjcnlwdG9LZXksICdBRVMtS1cnKSk7XG59O1xuZXhwb3J0IGNvbnN0IHVud3JhcCA9IGFzeW5jIChhbGcsIGtleSwgZW5jcnlwdGVkS2V5KSA9PiB7XG4gICAgY29uc3QgY3J5cHRvS2V5ID0gYXdhaXQgZ2V0Q3J5cHRvS2V5KGtleSwgYWxnLCAndW53cmFwS2V5Jyk7XG4gICAgY2hlY2tLZXlTaXplKGNyeXB0b0tleSwgYWxnKTtcbiAgICBjb25zdCBjcnlwdG9LZXlDZWsgPSBhd2FpdCBjcnlwdG8uc3VidGxlLnVud3JhcEtleSgncmF3JywgZW5jcnlwdGVkS2V5LCBjcnlwdG9LZXksICdBRVMtS1cnLCAuLi5ib2d1c1dlYkNyeXB0byk7XG4gICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdyYXcnLCBjcnlwdG9LZXlDZWspKTtcbn07XG4iLCJpbXBvcnQgeyBlbmNvZGVyLCBjb25jYXQsIHVpbnQzMmJlLCBsZW5ndGhBbmRJbnB1dCwgY29uY2F0S2RmIH0gZnJvbSAnLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tFbmNDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGRlcml2ZUtleShwdWJsaWNLZXksIHByaXZhdGVLZXksIGFsZ29yaXRobSwga2V5TGVuZ3RoLCBhcHUgPSBuZXcgVWludDhBcnJheSgwKSwgYXB2ID0gbmV3IFVpbnQ4QXJyYXkoMCkpIHtcbiAgICBpZiAoIWlzQ3J5cHRvS2V5KHB1YmxpY0tleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQocHVibGljS2V5LCAuLi50eXBlcykpO1xuICAgIH1cbiAgICBjaGVja0VuY0NyeXB0b0tleShwdWJsaWNLZXksICdFQ0RIJyk7XG4gICAgaWYgKCFpc0NyeXB0b0tleShwcml2YXRlS2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChwcml2YXRlS2V5LCAuLi50eXBlcykpO1xuICAgIH1cbiAgICBjaGVja0VuY0NyeXB0b0tleShwcml2YXRlS2V5LCAnRUNESCcsICdkZXJpdmVCaXRzJyk7XG4gICAgY29uc3QgdmFsdWUgPSBjb25jYXQobGVuZ3RoQW5kSW5wdXQoZW5jb2Rlci5lbmNvZGUoYWxnb3JpdGhtKSksIGxlbmd0aEFuZElucHV0KGFwdSksIGxlbmd0aEFuZElucHV0KGFwdiksIHVpbnQzMmJlKGtleUxlbmd0aCkpO1xuICAgIGxldCBsZW5ndGg7XG4gICAgaWYgKHB1YmxpY0tleS5hbGdvcml0aG0ubmFtZSA9PT0gJ1gyNTUxOScpIHtcbiAgICAgICAgbGVuZ3RoID0gMjU2O1xuICAgIH1cbiAgICBlbHNlIGlmIChwdWJsaWNLZXkuYWxnb3JpdGhtLm5hbWUgPT09ICdYNDQ4Jykge1xuICAgICAgICBsZW5ndGggPSA0NDg7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBsZW5ndGggPVxuICAgICAgICAgICAgTWF0aC5jZWlsKHBhcnNlSW50KHB1YmxpY0tleS5hbGdvcml0aG0ubmFtZWRDdXJ2ZS5zdWJzdHIoLTMpLCAxMCkgLyA4KSA8PCAzO1xuICAgIH1cbiAgICBjb25zdCBzaGFyZWRTZWNyZXQgPSBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmRlcml2ZUJpdHMoe1xuICAgICAgICBuYW1lOiBwdWJsaWNLZXkuYWxnb3JpdGhtLm5hbWUsXG4gICAgICAgIHB1YmxpYzogcHVibGljS2V5LFxuICAgIH0sIHByaXZhdGVLZXksIGxlbmd0aCkpO1xuICAgIHJldHVybiBjb25jYXRLZGYoc2hhcmVkU2VjcmV0LCBrZXlMZW5ndGgsIHZhbHVlKTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZUVwayhrZXkpIHtcbiAgICBpZiAoIWlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcykpO1xuICAgIH1cbiAgICByZXR1cm4gY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleShrZXkuYWxnb3JpdGhtLCB0cnVlLCBbJ2Rlcml2ZUJpdHMnXSk7XG59XG5leHBvcnQgZnVuY3Rpb24gZWNkaEFsbG93ZWQoa2V5KSB7XG4gICAgaWYgKCFpc0NyeXB0b0tleShrZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMpKTtcbiAgICB9XG4gICAgcmV0dXJuIChbJ1AtMjU2JywgJ1AtMzg0JywgJ1AtNTIxJ10uaW5jbHVkZXMoa2V5LmFsZ29yaXRobS5uYW1lZEN1cnZlKSB8fFxuICAgICAgICBrZXkuYWxnb3JpdGhtLm5hbWUgPT09ICdYMjU1MTknIHx8XG4gICAgICAgIGtleS5hbGdvcml0aG0ubmFtZSA9PT0gJ1g0NDgnKTtcbn1cbiIsImltcG9ydCB7IEpXRUludmFsaWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBjaGVja1AycyhwMnMpIHtcbiAgICBpZiAoIShwMnMgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB8fCBwMnMubGVuZ3RoIDwgOCkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnUEJFUzIgU2FsdCBJbnB1dCBtdXN0IGJlIDggb3IgbW9yZSBvY3RldHMnKTtcbiAgICB9XG59XG4iLCJpbXBvcnQgcmFuZG9tIGZyb20gJy4vcmFuZG9tLmpzJztcbmltcG9ydCB7IHAycyBhcyBjb25jYXRTYWx0IH0gZnJvbSAnLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgeyBlbmNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHsgd3JhcCwgdW53cmFwIH0gZnJvbSAnLi9hZXNrdy5qcyc7XG5pbXBvcnQgY2hlY2tQMnMgZnJvbSAnLi4vbGliL2NoZWNrX3Aycy5qcyc7XG5pbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tFbmNDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuZnVuY3Rpb24gZ2V0Q3J5cHRvS2V5KGtleSwgYWxnKSB7XG4gICAgaWYgKGtleSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBrZXksICdQQktERjInLCBmYWxzZSwgWydkZXJpdmVCaXRzJ10pO1xuICAgIH1cbiAgICBpZiAoaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICBjaGVja0VuY0NyeXB0b0tleShrZXksIGFsZywgJ2Rlcml2ZUJpdHMnLCAnZGVyaXZlS2V5Jyk7XG4gICAgICAgIHJldHVybiBrZXk7XG4gICAgfVxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMsICdVaW50OEFycmF5JykpO1xufVxuYXN5bmMgZnVuY3Rpb24gZGVyaXZlS2V5KHAycywgYWxnLCBwMmMsIGtleSkge1xuICAgIGNoZWNrUDJzKHAycyk7XG4gICAgY29uc3Qgc2FsdCA9IGNvbmNhdFNhbHQoYWxnLCBwMnMpO1xuICAgIGNvbnN0IGtleWxlbiA9IHBhcnNlSW50KGFsZy5zbGljZSgxMywgMTYpLCAxMCk7XG4gICAgY29uc3Qgc3VidGxlQWxnID0ge1xuICAgICAgICBoYXNoOiBgU0hBLSR7YWxnLnNsaWNlKDgsIDExKX1gLFxuICAgICAgICBpdGVyYXRpb25zOiBwMmMsXG4gICAgICAgIG5hbWU6ICdQQktERjInLFxuICAgICAgICBzYWx0LFxuICAgIH07XG4gICAgY29uc3Qgd3JhcEFsZyA9IHtcbiAgICAgICAgbGVuZ3RoOiBrZXlsZW4sXG4gICAgICAgIG5hbWU6ICdBRVMtS1cnLFxuICAgIH07XG4gICAgY29uc3QgY3J5cHRvS2V5ID0gYXdhaXQgZ2V0Q3J5cHRvS2V5KGtleSwgYWxnKTtcbiAgICBpZiAoY3J5cHRvS2V5LnVzYWdlcy5pbmNsdWRlcygnZGVyaXZlQml0cycpKSB7XG4gICAgICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmRlcml2ZUJpdHMoc3VidGxlQWxnLCBjcnlwdG9LZXksIGtleWxlbikpO1xuICAgIH1cbiAgICBpZiAoY3J5cHRvS2V5LnVzYWdlcy5pbmNsdWRlcygnZGVyaXZlS2V5JykpIHtcbiAgICAgICAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuZGVyaXZlS2V5KHN1YnRsZUFsZywgY3J5cHRvS2V5LCB3cmFwQWxnLCBmYWxzZSwgWyd3cmFwS2V5JywgJ3Vud3JhcEtleSddKTtcbiAgICB9XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcignUEJLREYyIGtleSBcInVzYWdlc1wiIG11c3QgaW5jbHVkZSBcImRlcml2ZUJpdHNcIiBvciBcImRlcml2ZUtleVwiJyk7XG59XG5leHBvcnQgY29uc3QgZW5jcnlwdCA9IGFzeW5jIChhbGcsIGtleSwgY2VrLCBwMmMgPSAyMDQ4LCBwMnMgPSByYW5kb20obmV3IFVpbnQ4QXJyYXkoMTYpKSkgPT4ge1xuICAgIGNvbnN0IGRlcml2ZWQgPSBhd2FpdCBkZXJpdmVLZXkocDJzLCBhbGcsIHAyYywga2V5KTtcbiAgICBjb25zdCBlbmNyeXB0ZWRLZXkgPSBhd2FpdCB3cmFwKGFsZy5zbGljZSgtNiksIGRlcml2ZWQsIGNlayk7XG4gICAgcmV0dXJuIHsgZW5jcnlwdGVkS2V5LCBwMmMsIHAyczogYmFzZTY0dXJsKHAycykgfTtcbn07XG5leHBvcnQgY29uc3QgZGVjcnlwdCA9IGFzeW5jIChhbGcsIGtleSwgZW5jcnlwdGVkS2V5LCBwMmMsIHAycykgPT4ge1xuICAgIGNvbnN0IGRlcml2ZWQgPSBhd2FpdCBkZXJpdmVLZXkocDJzLCBhbGcsIHAyYywga2V5KTtcbiAgICByZXR1cm4gdW53cmFwKGFsZy5zbGljZSgtNiksIGRlcml2ZWQsIGVuY3J5cHRlZEtleSk7XG59O1xuIiwiaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIHN1YnRsZVJzYUVzKGFsZykge1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQJzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMjU2JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMzg0JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtNTEyJzpcbiAgICAgICAgICAgIHJldHVybiAnUlNBLU9BRVAnO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoYGFsZyAke2FsZ30gaXMgbm90IHN1cHBvcnRlZCBlaXRoZXIgYnkgSk9TRSBvciB5b3VyIGphdmFzY3JpcHQgcnVudGltZWApO1xuICAgIH1cbn1cbiIsImV4cG9ydCBkZWZhdWx0IChhbGcsIGtleSkgPT4ge1xuICAgIGlmIChhbGcuc3RhcnRzV2l0aCgnUlMnKSB8fCBhbGcuc3RhcnRzV2l0aCgnUFMnKSkge1xuICAgICAgICBjb25zdCB7IG1vZHVsdXNMZW5ndGggfSA9IGtleS5hbGdvcml0aG07XG4gICAgICAgIGlmICh0eXBlb2YgbW9kdWx1c0xlbmd0aCAhPT0gJ251bWJlcicgfHwgbW9kdWx1c0xlbmd0aCA8IDIwNDgpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYCR7YWxnfSByZXF1aXJlcyBrZXkgbW9kdWx1c0xlbmd0aCB0byBiZSAyMDQ4IGJpdHMgb3IgbGFyZ2VyYCk7XG4gICAgICAgIH1cbiAgICB9XG59O1xuIiwiaW1wb3J0IHN1YnRsZUFsZ29yaXRobSBmcm9tICcuL3N1YnRsZV9yc2Flcy5qcyc7XG5pbXBvcnQgYm9ndXNXZWJDcnlwdG8gZnJvbSAnLi9ib2d1cy5qcyc7XG5pbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tFbmNDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgY2hlY2tLZXlMZW5ndGggZnJvbSAnLi9jaGVja19rZXlfbGVuZ3RoLmpzJztcbmltcG9ydCBpbnZhbGlkS2V5SW5wdXQgZnJvbSAnLi4vbGliL2ludmFsaWRfa2V5X2lucHV0LmpzJztcbmltcG9ydCB7IHR5cGVzIH0gZnJvbSAnLi9pc19rZXlfbGlrZS5qcyc7XG5leHBvcnQgY29uc3QgZW5jcnlwdCA9IGFzeW5jIChhbGcsIGtleSwgY2VrKSA9PiB7XG4gICAgaWYgKCFpc0NyeXB0b0tleShrZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMpKTtcbiAgICB9XG4gICAgY2hlY2tFbmNDcnlwdG9LZXkoa2V5LCBhbGcsICdlbmNyeXB0JywgJ3dyYXBLZXknKTtcbiAgICBjaGVja0tleUxlbmd0aChhbGcsIGtleSk7XG4gICAgaWYgKGtleS51c2FnZXMuaW5jbHVkZXMoJ2VuY3J5cHQnKSkge1xuICAgICAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5lbmNyeXB0KHN1YnRsZUFsZ29yaXRobShhbGcpLCBrZXksIGNlaykpO1xuICAgIH1cbiAgICBpZiAoa2V5LnVzYWdlcy5pbmNsdWRlcygnd3JhcEtleScpKSB7XG4gICAgICAgIGNvbnN0IGNyeXB0b0tleUNlayA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBjZWssIC4uLmJvZ3VzV2ViQ3J5cHRvKTtcbiAgICAgICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUud3JhcEtleSgncmF3JywgY3J5cHRvS2V5Q2VrLCBrZXksIHN1YnRsZUFsZ29yaXRobShhbGcpKSk7XG4gICAgfVxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1JTQS1PQUVQIGtleSBcInVzYWdlc1wiIG11c3QgaW5jbHVkZSBcImVuY3J5cHRcIiBvciBcIndyYXBLZXlcIiBmb3IgdGhpcyBvcGVyYXRpb24nKTtcbn07XG5leHBvcnQgY29uc3QgZGVjcnlwdCA9IGFzeW5jIChhbGcsIGtleSwgZW5jcnlwdGVkS2V5KSA9PiB7XG4gICAgaWYgKCFpc0NyeXB0b0tleShrZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMpKTtcbiAgICB9XG4gICAgY2hlY2tFbmNDcnlwdG9LZXkoa2V5LCBhbGcsICdkZWNyeXB0JywgJ3Vud3JhcEtleScpO1xuICAgIGNoZWNrS2V5TGVuZ3RoKGFsZywga2V5KTtcbiAgICBpZiAoa2V5LnVzYWdlcy5pbmNsdWRlcygnZGVjcnlwdCcpKSB7XG4gICAgICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmRlY3J5cHQoc3VidGxlQWxnb3JpdGhtKGFsZyksIGtleSwgZW5jcnlwdGVkS2V5KSk7XG4gICAgfVxuICAgIGlmIChrZXkudXNhZ2VzLmluY2x1ZGVzKCd1bndyYXBLZXknKSkge1xuICAgICAgICBjb25zdCBjcnlwdG9LZXlDZWsgPSBhd2FpdCBjcnlwdG8uc3VidGxlLnVud3JhcEtleSgncmF3JywgZW5jcnlwdGVkS2V5LCBrZXksIHN1YnRsZUFsZ29yaXRobShhbGcpLCAuLi5ib2d1c1dlYkNyeXB0byk7XG4gICAgICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgncmF3JywgY3J5cHRvS2V5Q2VrKSk7XG4gICAgfVxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1JTQS1PQUVQIGtleSBcInVzYWdlc1wiIG11c3QgaW5jbHVkZSBcImRlY3J5cHRcIiBvciBcInVud3JhcEtleVwiIGZvciB0aGlzIG9wZXJhdGlvbicpO1xufTtcbiIsImltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgcmFuZG9tIGZyb20gJy4uL3J1bnRpbWUvcmFuZG9tLmpzJztcbmV4cG9ydCBmdW5jdGlvbiBiaXRMZW5ndGgoYWxnKSB7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnQTEyOEdDTSc6XG4gICAgICAgICAgICByZXR1cm4gMTI4O1xuICAgICAgICBjYXNlICdBMTkyR0NNJzpcbiAgICAgICAgICAgIHJldHVybiAxOTI7XG4gICAgICAgIGNhc2UgJ0EyNTZHQ00nOlxuICAgICAgICBjYXNlICdBMTI4Q0JDLUhTMjU2JzpcbiAgICAgICAgICAgIHJldHVybiAyNTY7XG4gICAgICAgIGNhc2UgJ0ExOTJDQkMtSFMzODQnOlxuICAgICAgICAgICAgcmV0dXJuIDM4NDtcbiAgICAgICAgY2FzZSAnQTI1NkNCQy1IUzUxMic6XG4gICAgICAgICAgICByZXR1cm4gNTEyO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoYFVuc3VwcG9ydGVkIEpXRSBBbGdvcml0aG06ICR7YWxnfWApO1xuICAgIH1cbn1cbmV4cG9ydCBkZWZhdWx0IChhbGcpID0+IHJhbmRvbShuZXcgVWludDhBcnJheShiaXRMZW5ndGgoYWxnKSA+PiAzKSk7XG4iLCJpbXBvcnQgY3J5cHRvIGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5mdW5jdGlvbiBzdWJ0bGVNYXBwaW5nKGp3aykge1xuICAgIGxldCBhbGdvcml0aG07XG4gICAgbGV0IGtleVVzYWdlcztcbiAgICBzd2l0Y2ggKGp3ay5rdHkpIHtcbiAgICAgICAgY2FzZSAnUlNBJzoge1xuICAgICAgICAgICAgc3dpdGNoIChqd2suYWxnKSB7XG4gICAgICAgICAgICAgICAgY2FzZSAnUFMyNTYnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1BTMzg0JzpcbiAgICAgICAgICAgICAgICBjYXNlICdQUzUxMic6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ1JTQS1QU1MnLCBoYXNoOiBgU0hBLSR7andrLmFsZy5zbGljZSgtMyl9YCB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnc2lnbiddIDogWyd2ZXJpZnknXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAnUlMyNTYnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1JTMzg0JzpcbiAgICAgICAgICAgICAgICBjYXNlICdSUzUxMic6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ1JTQVNTQS1QS0NTMS12MV81JywgaGFzaDogYFNIQS0ke2p3ay5hbGcuc2xpY2UoLTMpfWAgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ3NpZ24nXSA6IFsndmVyaWZ5J107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ1JTQS1PQUVQJzpcbiAgICAgICAgICAgICAgICBjYXNlICdSU0EtT0FFUC0yNTYnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1JTQS1PQUVQLTM4NCc6XG4gICAgICAgICAgICAgICAgY2FzZSAnUlNBLU9BRVAtNTEyJzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0ge1xuICAgICAgICAgICAgICAgICAgICAgICAgbmFtZTogJ1JTQS1PQUVQJyxcbiAgICAgICAgICAgICAgICAgICAgICAgIGhhc2g6IGBTSEEtJHtwYXJzZUludChqd2suYWxnLnNsaWNlKC0zKSwgMTApIHx8IDF9YCxcbiAgICAgICAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ2RlY3J5cHQnLCAndW53cmFwS2V5J10gOiBbJ2VuY3J5cHQnLCAnd3JhcEtleSddO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBKV0sgXCJhbGdcIiAoQWxnb3JpdGhtKSBQYXJhbWV0ZXIgdmFsdWUnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0VDJzoge1xuICAgICAgICAgICAgc3dpdGNoIChqd2suYWxnKSB7XG4gICAgICAgICAgICAgICAgY2FzZSAnRVMyNTYnOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RTQScsIG5hbWVkQ3VydmU6ICdQLTI1NicgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ3NpZ24nXSA6IFsndmVyaWZ5J107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ0VTMzg0JzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNEU0EnLCBuYW1lZEN1cnZlOiAnUC0zODQnIH07XG4gICAgICAgICAgICAgICAgICAgIGtleVVzYWdlcyA9IGp3ay5kID8gWydzaWduJ10gOiBbJ3ZlcmlmeSddO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlICdFUzUxMic6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0VDRFNBJywgbmFtZWRDdXJ2ZTogJ1AtNTIxJyB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnc2lnbiddIDogWyd2ZXJpZnknXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUyc6XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUytBMTI4S1cnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMrQTE5MktXJzpcbiAgICAgICAgICAgICAgICBjYXNlICdFQ0RILUVTK0EyNTZLVyc6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0VDREgnLCBuYW1lZEN1cnZlOiBqd2suY3J2IH07XG4gICAgICAgICAgICAgICAgICAgIGtleVVzYWdlcyA9IGp3ay5kID8gWydkZXJpdmVCaXRzJ10gOiBbXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgSldLIFwiYWxnXCIgKEFsZ29yaXRobSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdPS1AnOiB7XG4gICAgICAgICAgICBzd2l0Y2ggKGp3ay5hbGcpIHtcbiAgICAgICAgICAgICAgICBjYXNlICdFZERTQSc6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogandrLmNydiB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnc2lnbiddIDogWyd2ZXJpZnknXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUyc6XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUytBMTI4S1cnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMrQTE5MktXJzpcbiAgICAgICAgICAgICAgICBjYXNlICdFQ0RILUVTK0EyNTZLVyc6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogandrLmNydiB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnZGVyaXZlQml0cyddIDogW107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIEpXSyBcImFsZ1wiIChBbGdvcml0aG0pIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIEpXSyBcImt0eVwiIChLZXkgVHlwZSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgfVxuICAgIHJldHVybiB7IGFsZ29yaXRobSwga2V5VXNhZ2VzIH07XG59XG5jb25zdCBwYXJzZSA9IGFzeW5jIChqd2spID0+IHtcbiAgICBpZiAoIWp3ay5hbGcpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignXCJhbGdcIiBhcmd1bWVudCBpcyByZXF1aXJlZCB3aGVuIFwiandrLmFsZ1wiIGlzIG5vdCBwcmVzZW50Jyk7XG4gICAgfVxuICAgIGNvbnN0IHsgYWxnb3JpdGhtLCBrZXlVc2FnZXMgfSA9IHN1YnRsZU1hcHBpbmcoandrKTtcbiAgICBjb25zdCByZXN0ID0gW1xuICAgICAgICBhbGdvcml0aG0sXG4gICAgICAgIGp3ay5leHQgPz8gZmFsc2UsXG4gICAgICAgIGp3ay5rZXlfb3BzID8/IGtleVVzYWdlcyxcbiAgICBdO1xuICAgIGNvbnN0IGtleURhdGEgPSB7IC4uLmp3ayB9O1xuICAgIGRlbGV0ZSBrZXlEYXRhLmFsZztcbiAgICBkZWxldGUga2V5RGF0YS51c2U7XG4gICAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdqd2snLCBrZXlEYXRhLCAuLi5yZXN0KTtcbn07XG5leHBvcnQgZGVmYXVsdCBwYXJzZTtcbiIsImltcG9ydCB7IGRlY29kZSBhcyBkZWNvZGVCYXNlNjRVUkwgfSBmcm9tICcuLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgeyBmcm9tU1BLSSwgZnJvbVBLQ1M4LCBmcm9tWDUwOSB9IGZyb20gJy4uL3J1bnRpbWUvYXNuMS5qcyc7XG5pbXBvcnQgYXNLZXlPYmplY3QgZnJvbSAnLi4vcnVudGltZS9qd2tfdG9fa2V5LmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgaXNPYmplY3QgZnJvbSAnLi4vbGliL2lzX29iamVjdC5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gaW1wb3J0U1BLSShzcGtpLCBhbGcsIG9wdGlvbnMpIHtcbiAgICBpZiAodHlwZW9mIHNwa2kgIT09ICdzdHJpbmcnIHx8IHNwa2kuaW5kZXhPZignLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0nKSAhPT0gMCkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdcInNwa2lcIiBtdXN0IGJlIFNQS0kgZm9ybWF0dGVkIHN0cmluZycpO1xuICAgIH1cbiAgICByZXR1cm4gZnJvbVNQS0koc3BraSwgYWxnLCBvcHRpb25zKTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBpbXBvcnRYNTA5KHg1MDksIGFsZywgb3B0aW9ucykge1xuICAgIGlmICh0eXBlb2YgeDUwOSAhPT0gJ3N0cmluZycgfHwgeDUwOS5pbmRleE9mKCctLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0nKSAhPT0gMCkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdcIng1MDlcIiBtdXN0IGJlIFguNTA5IGZvcm1hdHRlZCBzdHJpbmcnKTtcbiAgICB9XG4gICAgcmV0dXJuIGZyb21YNTA5KHg1MDksIGFsZywgb3B0aW9ucyk7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gaW1wb3J0UEtDUzgocGtjczgsIGFsZywgb3B0aW9ucykge1xuICAgIGlmICh0eXBlb2YgcGtjczggIT09ICdzdHJpbmcnIHx8IHBrY3M4LmluZGV4T2YoJy0tLS0tQkVHSU4gUFJJVkFURSBLRVktLS0tLScpICE9PSAwKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1wicGtjczhcIiBtdXN0IGJlIFBLQ1MjOCBmb3JtYXR0ZWQgc3RyaW5nJyk7XG4gICAgfVxuICAgIHJldHVybiBmcm9tUEtDUzgocGtjczgsIGFsZywgb3B0aW9ucyk7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gaW1wb3J0SldLKGp3aywgYWxnKSB7XG4gICAgaWYgKCFpc09iamVjdChqd2spKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0pXSyBtdXN0IGJlIGFuIG9iamVjdCcpO1xuICAgIH1cbiAgICBhbGcgfHwgKGFsZyA9IGp3ay5hbGcpO1xuICAgIHN3aXRjaCAoandrLmt0eSkge1xuICAgICAgICBjYXNlICdvY3QnOlxuICAgICAgICAgICAgaWYgKHR5cGVvZiBqd2suayAhPT0gJ3N0cmluZycgfHwgIWp3ay5rKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignbWlzc2luZyBcImtcIiAoS2V5IFZhbHVlKSBQYXJhbWV0ZXIgdmFsdWUnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBkZWNvZGVCYXNlNjRVUkwoandrLmspO1xuICAgICAgICBjYXNlICdSU0EnOlxuICAgICAgICAgICAgaWYgKGp3ay5vdGggIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdSU0EgSldLIFwib3RoXCIgKE90aGVyIFByaW1lcyBJbmZvKSBQYXJhbWV0ZXIgdmFsdWUgaXMgbm90IHN1cHBvcnRlZCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICBjYXNlICdFQyc6XG4gICAgICAgIGNhc2UgJ09LUCc6XG4gICAgICAgICAgICByZXR1cm4gYXNLZXlPYmplY3QoeyAuLi5qd2ssIGFsZyB9KTtcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdVbnN1cHBvcnRlZCBcImt0eVwiIChLZXkgVHlwZSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgfVxufVxuIiwiaW1wb3J0IHsgd2l0aEFsZyBhcyBpbnZhbGlkS2V5SW5wdXQgfSBmcm9tICcuL2ludmFsaWRfa2V5X2lucHV0LmpzJztcbmltcG9ydCBpc0tleUxpa2UsIHsgdHlwZXMgfSBmcm9tICcuLi9ydW50aW1lL2lzX2tleV9saWtlLmpzJztcbmNvbnN0IHN5bW1ldHJpY1R5cGVDaGVjayA9IChhbGcsIGtleSkgPT4ge1xuICAgIGlmIChrZXkgaW5zdGFuY2VvZiBVaW50OEFycmF5KVxuICAgICAgICByZXR1cm47XG4gICAgaWYgKCFpc0tleUxpa2Uoa2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChhbGcsIGtleSwgLi4udHlwZXMsICdVaW50OEFycmF5JykpO1xuICAgIH1cbiAgICBpZiAoa2V5LnR5cGUgIT09ICdzZWNyZXQnKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYCR7dHlwZXMuam9pbignIG9yICcpfSBpbnN0YW5jZXMgZm9yIHN5bW1ldHJpYyBhbGdvcml0aG1zIG11c3QgYmUgb2YgdHlwZSBcInNlY3JldFwiYCk7XG4gICAgfVxufTtcbmNvbnN0IGFzeW1tZXRyaWNUeXBlQ2hlY2sgPSAoYWxnLCBrZXksIHVzYWdlKSA9PiB7XG4gICAgaWYgKCFpc0tleUxpa2Uoa2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChhbGcsIGtleSwgLi4udHlwZXMpKTtcbiAgICB9XG4gICAgaWYgKGtleS50eXBlID09PSAnc2VjcmV0Jykge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGAke3R5cGVzLmpvaW4oJyBvciAnKX0gaW5zdGFuY2VzIGZvciBhc3ltbWV0cmljIGFsZ29yaXRobXMgbXVzdCBub3QgYmUgb2YgdHlwZSBcInNlY3JldFwiYCk7XG4gICAgfVxuICAgIGlmICh1c2FnZSA9PT0gJ3NpZ24nICYmIGtleS50eXBlID09PSAncHVibGljJykge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGAke3R5cGVzLmpvaW4oJyBvciAnKX0gaW5zdGFuY2VzIGZvciBhc3ltbWV0cmljIGFsZ29yaXRobSBzaWduaW5nIG11c3QgYmUgb2YgdHlwZSBcInByaXZhdGVcImApO1xuICAgIH1cbiAgICBpZiAodXNhZ2UgPT09ICdkZWNyeXB0JyAmJiBrZXkudHlwZSA9PT0gJ3B1YmxpYycpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHt0eXBlcy5qb2luKCcgb3IgJyl9IGluc3RhbmNlcyBmb3IgYXN5bW1ldHJpYyBhbGdvcml0aG0gZGVjcnlwdGlvbiBtdXN0IGJlIG9mIHR5cGUgXCJwcml2YXRlXCJgKTtcbiAgICB9XG4gICAgaWYgKGtleS5hbGdvcml0aG0gJiYgdXNhZ2UgPT09ICd2ZXJpZnknICYmIGtleS50eXBlID09PSAncHJpdmF0ZScpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHt0eXBlcy5qb2luKCcgb3IgJyl9IGluc3RhbmNlcyBmb3IgYXN5bW1ldHJpYyBhbGdvcml0aG0gdmVyaWZ5aW5nIG11c3QgYmUgb2YgdHlwZSBcInB1YmxpY1wiYCk7XG4gICAgfVxuICAgIGlmIChrZXkuYWxnb3JpdGhtICYmIHVzYWdlID09PSAnZW5jcnlwdCcgJiYga2V5LnR5cGUgPT09ICdwcml2YXRlJykge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGAke3R5cGVzLmpvaW4oJyBvciAnKX0gaW5zdGFuY2VzIGZvciBhc3ltbWV0cmljIGFsZ29yaXRobSBlbmNyeXB0aW9uIG11c3QgYmUgb2YgdHlwZSBcInB1YmxpY1wiYCk7XG4gICAgfVxufTtcbmNvbnN0IGNoZWNrS2V5VHlwZSA9IChhbGcsIGtleSwgdXNhZ2UpID0+IHtcbiAgICBjb25zdCBzeW1tZXRyaWMgPSBhbGcuc3RhcnRzV2l0aCgnSFMnKSB8fFxuICAgICAgICBhbGcgPT09ICdkaXInIHx8XG4gICAgICAgIGFsZy5zdGFydHNXaXRoKCdQQkVTMicpIHx8XG4gICAgICAgIC9eQVxcZHszfSg/OkdDTSk/S1ckLy50ZXN0KGFsZyk7XG4gICAgaWYgKHN5bW1ldHJpYykge1xuICAgICAgICBzeW1tZXRyaWNUeXBlQ2hlY2soYWxnLCBrZXkpO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgYXN5bW1ldHJpY1R5cGVDaGVjayhhbGcsIGtleSwgdXNhZ2UpO1xuICAgIH1cbn07XG5leHBvcnQgZGVmYXVsdCBjaGVja0tleVR5cGU7XG4iLCJpbXBvcnQgeyBjb25jYXQsIHVpbnQ2NGJlIH0gZnJvbSAnLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgY2hlY2tJdkxlbmd0aCBmcm9tICcuLi9saWIvY2hlY2tfaXZfbGVuZ3RoLmpzJztcbmltcG9ydCBjaGVja0Nla0xlbmd0aCBmcm9tICcuL2NoZWNrX2Nla19sZW5ndGguanMnO1xuaW1wb3J0IGNyeXB0bywgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IGNoZWNrRW5jQ3J5cHRvS2V5IH0gZnJvbSAnLi4vbGliL2NyeXB0b19rZXkuanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IGdlbmVyYXRlSXYgZnJvbSAnLi4vbGliL2l2LmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuYXN5bmMgZnVuY3Rpb24gY2JjRW5jcnlwdChlbmMsIHBsYWludGV4dCwgY2VrLCBpdiwgYWFkKSB7XG4gICAgaWYgKCEoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoY2VrLCAnVWludDhBcnJheScpKTtcbiAgICB9XG4gICAgY29uc3Qga2V5U2l6ZSA9IHBhcnNlSW50KGVuYy5zbGljZSgxLCA0KSwgMTApO1xuICAgIGNvbnN0IGVuY0tleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBjZWsuc3ViYXJyYXkoa2V5U2l6ZSA+PiAzKSwgJ0FFUy1DQkMnLCBmYWxzZSwgWydlbmNyeXB0J10pO1xuICAgIGNvbnN0IG1hY0tleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBjZWsuc3ViYXJyYXkoMCwga2V5U2l6ZSA+PiAzKSwge1xuICAgICAgICBoYXNoOiBgU0hBLSR7a2V5U2l6ZSA8PCAxfWAsXG4gICAgICAgIG5hbWU6ICdITUFDJyxcbiAgICB9LCBmYWxzZSwgWydzaWduJ10pO1xuICAgIGNvbnN0IGNpcGhlcnRleHQgPSBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmVuY3J5cHQoe1xuICAgICAgICBpdixcbiAgICAgICAgbmFtZTogJ0FFUy1DQkMnLFxuICAgIH0sIGVuY0tleSwgcGxhaW50ZXh0KSk7XG4gICAgY29uc3QgbWFjRGF0YSA9IGNvbmNhdChhYWQsIGl2LCBjaXBoZXJ0ZXh0LCB1aW50NjRiZShhYWQubGVuZ3RoIDw8IDMpKTtcbiAgICBjb25zdCB0YWcgPSBuZXcgVWludDhBcnJheSgoYXdhaXQgY3J5cHRvLnN1YnRsZS5zaWduKCdITUFDJywgbWFjS2V5LCBtYWNEYXRhKSkuc2xpY2UoMCwga2V5U2l6ZSA+PiAzKSk7XG4gICAgcmV0dXJuIHsgY2lwaGVydGV4dCwgdGFnLCBpdiB9O1xufVxuYXN5bmMgZnVuY3Rpb24gZ2NtRW5jcnlwdChlbmMsIHBsYWludGV4dCwgY2VrLCBpdiwgYWFkKSB7XG4gICAgbGV0IGVuY0tleTtcbiAgICBpZiAoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICBlbmNLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLCAnQUVTLUdDTScsIGZhbHNlLCBbJ2VuY3J5cHQnXSk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBjaGVja0VuY0NyeXB0b0tleShjZWssIGVuYywgJ2VuY3J5cHQnKTtcbiAgICAgICAgZW5jS2V5ID0gY2VrO1xuICAgIH1cbiAgICBjb25zdCBlbmNyeXB0ZWQgPSBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmVuY3J5cHQoe1xuICAgICAgICBhZGRpdGlvbmFsRGF0YTogYWFkLFxuICAgICAgICBpdixcbiAgICAgICAgbmFtZTogJ0FFUy1HQ00nLFxuICAgICAgICB0YWdMZW5ndGg6IDEyOCxcbiAgICB9LCBlbmNLZXksIHBsYWludGV4dCkpO1xuICAgIGNvbnN0IHRhZyA9IGVuY3J5cHRlZC5zbGljZSgtMTYpO1xuICAgIGNvbnN0IGNpcGhlcnRleHQgPSBlbmNyeXB0ZWQuc2xpY2UoMCwgLTE2KTtcbiAgICByZXR1cm4geyBjaXBoZXJ0ZXh0LCB0YWcsIGl2IH07XG59XG5jb25zdCBlbmNyeXB0ID0gYXN5bmMgKGVuYywgcGxhaW50ZXh0LCBjZWssIGl2LCBhYWQpID0+IHtcbiAgICBpZiAoIWlzQ3J5cHRvS2V5KGNlaykgJiYgIShjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChjZWssIC4uLnR5cGVzLCAnVWludDhBcnJheScpKTtcbiAgICB9XG4gICAgaWYgKGl2KSB7XG4gICAgICAgIGNoZWNrSXZMZW5ndGgoZW5jLCBpdik7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBpdiA9IGdlbmVyYXRlSXYoZW5jKTtcbiAgICB9XG4gICAgc3dpdGNoIChlbmMpIHtcbiAgICAgICAgY2FzZSAnQTEyOENCQy1IUzI1Nic6XG4gICAgICAgIGNhc2UgJ0ExOTJDQkMtSFMzODQnOlxuICAgICAgICBjYXNlICdBMjU2Q0JDLUhTNTEyJzpcbiAgICAgICAgICAgIGlmIChjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgICAgICAgICAgY2hlY2tDZWtMZW5ndGgoY2VrLCBwYXJzZUludChlbmMuc2xpY2UoLTMpLCAxMCkpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIGNiY0VuY3J5cHQoZW5jLCBwbGFpbnRleHQsIGNlaywgaXYsIGFhZCk7XG4gICAgICAgIGNhc2UgJ0ExMjhHQ00nOlxuICAgICAgICBjYXNlICdBMTkyR0NNJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTSc6XG4gICAgICAgICAgICBpZiAoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICAgICAgICAgIGNoZWNrQ2VrTGVuZ3RoKGNlaywgcGFyc2VJbnQoZW5jLnNsaWNlKDEsIDQpLCAxMCkpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIGdjbUVuY3J5cHQoZW5jLCBwbGFpbnRleHQsIGNlaywgaXYsIGFhZCk7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnVW5zdXBwb3J0ZWQgSldFIENvbnRlbnQgRW5jcnlwdGlvbiBBbGdvcml0aG0nKTtcbiAgICB9XG59O1xuZXhwb3J0IGRlZmF1bHQgZW5jcnlwdDtcbiIsImltcG9ydCBlbmNyeXB0IGZyb20gJy4uL3J1bnRpbWUvZW5jcnlwdC5qcyc7XG5pbXBvcnQgZGVjcnlwdCBmcm9tICcuLi9ydW50aW1lL2RlY3J5cHQuanMnO1xuaW1wb3J0IHsgZW5jb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB3cmFwKGFsZywga2V5LCBjZWssIGl2KSB7XG4gICAgY29uc3QgandlQWxnb3JpdGhtID0gYWxnLnNsaWNlKDAsIDcpO1xuICAgIGNvbnN0IHdyYXBwZWQgPSBhd2FpdCBlbmNyeXB0KGp3ZUFsZ29yaXRobSwgY2VrLCBrZXksIGl2LCBuZXcgVWludDhBcnJheSgwKSk7XG4gICAgcmV0dXJuIHtcbiAgICAgICAgZW5jcnlwdGVkS2V5OiB3cmFwcGVkLmNpcGhlcnRleHQsXG4gICAgICAgIGl2OiBiYXNlNjR1cmwod3JhcHBlZC5pdiksXG4gICAgICAgIHRhZzogYmFzZTY0dXJsKHdyYXBwZWQudGFnKSxcbiAgICB9O1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHVud3JhcChhbGcsIGtleSwgZW5jcnlwdGVkS2V5LCBpdiwgdGFnKSB7XG4gICAgY29uc3QgandlQWxnb3JpdGhtID0gYWxnLnNsaWNlKDAsIDcpO1xuICAgIHJldHVybiBkZWNyeXB0KGp3ZUFsZ29yaXRobSwga2V5LCBlbmNyeXB0ZWRLZXksIGl2LCB0YWcsIG5ldyBVaW50OEFycmF5KDApKTtcbn1cbiIsImltcG9ydCB7IHVud3JhcCBhcyBhZXNLdyB9IGZyb20gJy4uL3J1bnRpbWUvYWVza3cuanMnO1xuaW1wb3J0ICogYXMgRUNESCBmcm9tICcuLi9ydW50aW1lL2VjZGhlcy5qcyc7XG5pbXBvcnQgeyBkZWNyeXB0IGFzIHBiZXMyS3cgfSBmcm9tICcuLi9ydW50aW1lL3BiZXMya3cuanMnO1xuaW1wb3J0IHsgZGVjcnlwdCBhcyByc2FFcyB9IGZyb20gJy4uL3J1bnRpbWUvcnNhZXMuanMnO1xuaW1wb3J0IHsgZGVjb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQsIEpXRUludmFsaWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgeyBiaXRMZW5ndGggYXMgY2VrTGVuZ3RoIH0gZnJvbSAnLi4vbGliL2Nlay5qcyc7XG5pbXBvcnQgeyBpbXBvcnRKV0sgfSBmcm9tICcuLi9rZXkvaW1wb3J0LmpzJztcbmltcG9ydCBjaGVja0tleVR5cGUgZnJvbSAnLi9jaGVja19rZXlfdHlwZS5qcyc7XG5pbXBvcnQgaXNPYmplY3QgZnJvbSAnLi9pc19vYmplY3QuanMnO1xuaW1wb3J0IHsgdW53cmFwIGFzIGFlc0djbUt3IH0gZnJvbSAnLi9hZXNnY21rdy5qcyc7XG5hc3luYyBmdW5jdGlvbiBkZWNyeXB0S2V5TWFuYWdlbWVudChhbGcsIGtleSwgZW5jcnlwdGVkS2V5LCBqb3NlSGVhZGVyLCBvcHRpb25zKSB7XG4gICAgY2hlY2tLZXlUeXBlKGFsZywga2V5LCAnZGVjcnlwdCcpO1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ2Rpcic6IHtcbiAgICAgICAgICAgIGlmIChlbmNyeXB0ZWRLZXkgIT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRW5jb3VudGVyZWQgdW5leHBlY3RlZCBKV0UgRW5jcnlwdGVkIEtleScpO1xuICAgICAgICAgICAgcmV0dXJuIGtleTtcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdFQ0RILUVTJzpcbiAgICAgICAgICAgIGlmIChlbmNyeXB0ZWRLZXkgIT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRW5jb3VudGVyZWQgdW5leHBlY3RlZCBKV0UgRW5jcnlwdGVkIEtleScpO1xuICAgICAgICBjYXNlICdFQ0RILUVTK0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTE5MktXJzpcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMjU2S1cnOiB7XG4gICAgICAgICAgICBpZiAoIWlzT2JqZWN0KGpvc2VIZWFkZXIuZXBrKSlcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSk9TRSBIZWFkZXIgXCJlcGtcIiAoRXBoZW1lcmFsIFB1YmxpYyBLZXkpIG1pc3Npbmcgb3IgaW52YWxpZGApO1xuICAgICAgICAgICAgaWYgKCFFQ0RILmVjZGhBbGxvd2VkKGtleSkpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0VDREggd2l0aCB0aGUgcHJvdmlkZWQga2V5IGlzIG5vdCBhbGxvd2VkIG9yIG5vdCBzdXBwb3J0ZWQgYnkgeW91ciBqYXZhc2NyaXB0IHJ1bnRpbWUnKTtcbiAgICAgICAgICAgIGNvbnN0IGVwayA9IGF3YWl0IGltcG9ydEpXSyhqb3NlSGVhZGVyLmVwaywgYWxnKTtcbiAgICAgICAgICAgIGxldCBwYXJ0eVVJbmZvO1xuICAgICAgICAgICAgbGV0IHBhcnR5VkluZm87XG4gICAgICAgICAgICBpZiAoam9zZUhlYWRlci5hcHUgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgICAgIGlmICh0eXBlb2Ygam9zZUhlYWRlci5hcHUgIT09ICdzdHJpbmcnKVxuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSk9TRSBIZWFkZXIgXCJhcHVcIiAoQWdyZWVtZW50IFBhcnR5VUluZm8pIGludmFsaWRgKTtcbiAgICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgICAgICBwYXJ0eVVJbmZvID0gYmFzZTY0dXJsKGpvc2VIZWFkZXIuYXB1KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIGFwdScpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmIChqb3NlSGVhZGVyLmFwdiAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICAgICAgaWYgKHR5cGVvZiBqb3NlSGVhZGVyLmFwdiAhPT0gJ3N0cmluZycpXG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKGBKT1NFIEhlYWRlciBcImFwdlwiIChBZ3JlZW1lbnQgUGFydHlWSW5mbykgaW52YWxpZGApO1xuICAgICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgICAgIHBhcnR5VkluZm8gPSBiYXNlNjR1cmwoam9zZUhlYWRlci5hcHYpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgYXB2Jyk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY29uc3Qgc2hhcmVkU2VjcmV0ID0gYXdhaXQgRUNESC5kZXJpdmVLZXkoZXBrLCBrZXksIGFsZyA9PT0gJ0VDREgtRVMnID8gam9zZUhlYWRlci5lbmMgOiBhbGcsIGFsZyA9PT0gJ0VDREgtRVMnID8gY2VrTGVuZ3RoKGpvc2VIZWFkZXIuZW5jKSA6IHBhcnNlSW50KGFsZy5zbGljZSgtNSwgLTIpLCAxMCksIHBhcnR5VUluZm8sIHBhcnR5VkluZm8pO1xuICAgICAgICAgICAgaWYgKGFsZyA9PT0gJ0VDREgtRVMnKVxuICAgICAgICAgICAgICAgIHJldHVybiBzaGFyZWRTZWNyZXQ7XG4gICAgICAgICAgICBpZiAoZW5jcnlwdGVkS2V5ID09PSB1bmRlZmluZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBFbmNyeXB0ZWQgS2V5IG1pc3NpbmcnKTtcbiAgICAgICAgICAgIHJldHVybiBhZXNLdyhhbGcuc2xpY2UoLTYpLCBzaGFyZWRTZWNyZXQsIGVuY3J5cHRlZEtleSk7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnUlNBMV81JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0yNTYnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0zODQnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC01MTInOiB7XG4gICAgICAgICAgICBpZiAoZW5jcnlwdGVkS2V5ID09PSB1bmRlZmluZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBFbmNyeXB0ZWQgS2V5IG1pc3NpbmcnKTtcbiAgICAgICAgICAgIHJldHVybiByc2FFcyhhbGcsIGtleSwgZW5jcnlwdGVkS2V5KTtcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdQQkVTMi1IUzI1NitBMTI4S1cnOlxuICAgICAgICBjYXNlICdQQkVTMi1IUzM4NCtBMTkyS1cnOlxuICAgICAgICBjYXNlICdQQkVTMi1IUzUxMitBMjU2S1cnOiB7XG4gICAgICAgICAgICBpZiAoZW5jcnlwdGVkS2V5ID09PSB1bmRlZmluZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBFbmNyeXB0ZWQgS2V5IG1pc3NpbmcnKTtcbiAgICAgICAgICAgIGlmICh0eXBlb2Ygam9zZUhlYWRlci5wMmMgIT09ICdudW1iZXInKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKGBKT1NFIEhlYWRlciBcInAyY1wiIChQQkVTMiBDb3VudCkgbWlzc2luZyBvciBpbnZhbGlkYCk7XG4gICAgICAgICAgICBjb25zdCBwMmNMaW1pdCA9IG9wdGlvbnM/Lm1heFBCRVMyQ291bnQgfHwgMTAwMDA7XG4gICAgICAgICAgICBpZiAoam9zZUhlYWRlci5wMmMgPiBwMmNMaW1pdClcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSk9TRSBIZWFkZXIgXCJwMmNcIiAoUEJFUzIgQ291bnQpIG91dCBpcyBvZiBhY2NlcHRhYmxlIGJvdW5kc2ApO1xuICAgICAgICAgICAgaWYgKHR5cGVvZiBqb3NlSGVhZGVyLnAycyAhPT0gJ3N0cmluZycpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwicDJzXCIgKFBCRVMyIFNhbHQpIG1pc3Npbmcgb3IgaW52YWxpZGApO1xuICAgICAgICAgICAgbGV0IHAycztcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgcDJzID0gYmFzZTY0dXJsKGpvc2VIZWFkZXIucDJzKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIHAycycpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIHBiZXMyS3coYWxnLCBrZXksIGVuY3J5cHRlZEtleSwgam9zZUhlYWRlci5wMmMsIHAycyk7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnQTE5MktXJzpcbiAgICAgICAgY2FzZSAnQTI1NktXJzoge1xuICAgICAgICAgICAgaWYgKGVuY3J5cHRlZEtleSA9PT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgRW5jcnlwdGVkIEtleSBtaXNzaW5nJyk7XG4gICAgICAgICAgICByZXR1cm4gYWVzS3coYWxnLCBrZXksIGVuY3J5cHRlZEtleSk7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnQTEyOEdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTE5MkdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTUtXJzoge1xuICAgICAgICAgICAgaWYgKGVuY3J5cHRlZEtleSA9PT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgRW5jcnlwdGVkIEtleSBtaXNzaW5nJyk7XG4gICAgICAgICAgICBpZiAodHlwZW9mIGpvc2VIZWFkZXIuaXYgIT09ICdzdHJpbmcnKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKGBKT1NFIEhlYWRlciBcIml2XCIgKEluaXRpYWxpemF0aW9uIFZlY3RvcikgbWlzc2luZyBvciBpbnZhbGlkYCk7XG4gICAgICAgICAgICBpZiAodHlwZW9mIGpvc2VIZWFkZXIudGFnICE9PSAnc3RyaW5nJylcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSk9TRSBIZWFkZXIgXCJ0YWdcIiAoQXV0aGVudGljYXRpb24gVGFnKSBtaXNzaW5nIG9yIGludmFsaWRgKTtcbiAgICAgICAgICAgIGxldCBpdjtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgaXYgPSBiYXNlNjR1cmwoam9zZUhlYWRlci5pdik7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBpdicpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgbGV0IHRhZztcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgdGFnID0gYmFzZTY0dXJsKGpvc2VIZWFkZXIudGFnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIHRhZycpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIGFlc0djbUt3KGFsZywga2V5LCBlbmNyeXB0ZWRLZXksIGl2LCB0YWcpO1xuICAgICAgICB9XG4gICAgICAgIGRlZmF1bHQ6IHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIFwiYWxnXCIgKEpXRSBBbGdvcml0aG0pIGhlYWRlciB2YWx1ZScpO1xuICAgICAgICB9XG4gICAgfVxufVxuZXhwb3J0IGRlZmF1bHQgZGVjcnlwdEtleU1hbmFnZW1lbnQ7XG4iLCJpbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuZnVuY3Rpb24gdmFsaWRhdGVDcml0KEVyciwgcmVjb2duaXplZERlZmF1bHQsIHJlY29nbml6ZWRPcHRpb24sIHByb3RlY3RlZEhlYWRlciwgam9zZUhlYWRlcikge1xuICAgIGlmIChqb3NlSGVhZGVyLmNyaXQgIT09IHVuZGVmaW5lZCAmJiBwcm90ZWN0ZWRIZWFkZXI/LmNyaXQgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyKCdcImNyaXRcIiAoQ3JpdGljYWwpIEhlYWRlciBQYXJhbWV0ZXIgTVVTVCBiZSBpbnRlZ3JpdHkgcHJvdGVjdGVkJyk7XG4gICAgfVxuICAgIGlmICghcHJvdGVjdGVkSGVhZGVyIHx8IHByb3RlY3RlZEhlYWRlci5jcml0ID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmV0dXJuIG5ldyBTZXQoKTtcbiAgICB9XG4gICAgaWYgKCFBcnJheS5pc0FycmF5KHByb3RlY3RlZEhlYWRlci5jcml0KSB8fFxuICAgICAgICBwcm90ZWN0ZWRIZWFkZXIuY3JpdC5sZW5ndGggPT09IDAgfHxcbiAgICAgICAgcHJvdGVjdGVkSGVhZGVyLmNyaXQuc29tZSgoaW5wdXQpID0+IHR5cGVvZiBpbnB1dCAhPT0gJ3N0cmluZycgfHwgaW5wdXQubGVuZ3RoID09PSAwKSkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyKCdcImNyaXRcIiAoQ3JpdGljYWwpIEhlYWRlciBQYXJhbWV0ZXIgTVVTVCBiZSBhbiBhcnJheSBvZiBub24tZW1wdHkgc3RyaW5ncyB3aGVuIHByZXNlbnQnKTtcbiAgICB9XG4gICAgbGV0IHJlY29nbml6ZWQ7XG4gICAgaWYgKHJlY29nbml6ZWRPcHRpb24gIT09IHVuZGVmaW5lZCkge1xuICAgICAgICByZWNvZ25pemVkID0gbmV3IE1hcChbLi4uT2JqZWN0LmVudHJpZXMocmVjb2duaXplZE9wdGlvbiksIC4uLnJlY29nbml6ZWREZWZhdWx0LmVudHJpZXMoKV0pO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgcmVjb2duaXplZCA9IHJlY29nbml6ZWREZWZhdWx0O1xuICAgIH1cbiAgICBmb3IgKGNvbnN0IHBhcmFtZXRlciBvZiBwcm90ZWN0ZWRIZWFkZXIuY3JpdCkge1xuICAgICAgICBpZiAoIXJlY29nbml6ZWQuaGFzKHBhcmFtZXRlcikpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKGBFeHRlbnNpb24gSGVhZGVyIFBhcmFtZXRlciBcIiR7cGFyYW1ldGVyfVwiIGlzIG5vdCByZWNvZ25pemVkYCk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGpvc2VIZWFkZXJbcGFyYW1ldGVyXSA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyKGBFeHRlbnNpb24gSGVhZGVyIFBhcmFtZXRlciBcIiR7cGFyYW1ldGVyfVwiIGlzIG1pc3NpbmdgKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAocmVjb2duaXplZC5nZXQocGFyYW1ldGVyKSAmJiBwcm90ZWN0ZWRIZWFkZXJbcGFyYW1ldGVyXSA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyKGBFeHRlbnNpb24gSGVhZGVyIFBhcmFtZXRlciBcIiR7cGFyYW1ldGVyfVwiIE1VU1QgYmUgaW50ZWdyaXR5IHByb3RlY3RlZGApO1xuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiBuZXcgU2V0KHByb3RlY3RlZEhlYWRlci5jcml0KTtcbn1cbmV4cG9ydCBkZWZhdWx0IHZhbGlkYXRlQ3JpdDtcbiIsImNvbnN0IHZhbGlkYXRlQWxnb3JpdGhtcyA9IChvcHRpb24sIGFsZ29yaXRobXMpID0+IHtcbiAgICBpZiAoYWxnb3JpdGhtcyAhPT0gdW5kZWZpbmVkICYmXG4gICAgICAgICghQXJyYXkuaXNBcnJheShhbGdvcml0aG1zKSB8fCBhbGdvcml0aG1zLnNvbWUoKHMpID0+IHR5cGVvZiBzICE9PSAnc3RyaW5nJykpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYFwiJHtvcHRpb259XCIgb3B0aW9uIG11c3QgYmUgYW4gYXJyYXkgb2Ygc3RyaW5nc2ApO1xuICAgIH1cbiAgICBpZiAoIWFsZ29yaXRobXMpIHtcbiAgICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICB9XG4gICAgcmV0dXJuIG5ldyBTZXQoYWxnb3JpdGhtcyk7XG59O1xuZXhwb3J0IGRlZmF1bHQgdmFsaWRhdGVBbGdvcml0aG1zO1xuIiwiaW1wb3J0IHsgZGVjb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4uLy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmltcG9ydCBkZWNyeXB0IGZyb20gJy4uLy4uL3J1bnRpbWUvZGVjcnlwdC5qcyc7XG5pbXBvcnQgeyBKT1NFQWxnTm90QWxsb3dlZCwgSk9TRU5vdFN1cHBvcnRlZCwgSldFSW52YWxpZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCBpc0Rpc2pvaW50IGZyb20gJy4uLy4uL2xpYi9pc19kaXNqb2ludC5qcyc7XG5pbXBvcnQgaXNPYmplY3QgZnJvbSAnLi4vLi4vbGliL2lzX29iamVjdC5qcyc7XG5pbXBvcnQgZGVjcnlwdEtleU1hbmFnZW1lbnQgZnJvbSAnLi4vLi4vbGliL2RlY3J5cHRfa2V5X21hbmFnZW1lbnQuanMnO1xuaW1wb3J0IHsgZW5jb2RlciwgZGVjb2RlciwgY29uY2F0IH0gZnJvbSAnLi4vLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgZ2VuZXJhdGVDZWsgZnJvbSAnLi4vLi4vbGliL2Nlay5qcyc7XG5pbXBvcnQgdmFsaWRhdGVDcml0IGZyb20gJy4uLy4uL2xpYi92YWxpZGF0ZV9jcml0LmpzJztcbmltcG9ydCB2YWxpZGF0ZUFsZ29yaXRobXMgZnJvbSAnLi4vLi4vbGliL3ZhbGlkYXRlX2FsZ29yaXRobXMuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGZsYXR0ZW5lZERlY3J5cHQoandlLCBrZXksIG9wdGlvbnMpIHtcbiAgICBpZiAoIWlzT2JqZWN0KGp3ZSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZsYXR0ZW5lZCBKV0UgbXVzdCBiZSBhbiBvYmplY3QnKTtcbiAgICB9XG4gICAgaWYgKGp3ZS5wcm90ZWN0ZWQgPT09IHVuZGVmaW5lZCAmJiBqd2UuaGVhZGVyID09PSB1bmRlZmluZWQgJiYgandlLnVucHJvdGVjdGVkID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pPU0UgSGVhZGVyIG1pc3NpbmcnKTtcbiAgICB9XG4gICAgaWYgKGp3ZS5pdiAhPT0gdW5kZWZpbmVkICYmIHR5cGVvZiBqd2UuaXYgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgSW5pdGlhbGl6YXRpb24gVmVjdG9yIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgandlLmNpcGhlcnRleHQgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgQ2lwaGVydGV4dCBtaXNzaW5nIG9yIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmIChqd2UudGFnICE9PSB1bmRlZmluZWQgJiYgdHlwZW9mIGp3ZS50YWcgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgQXV0aGVudGljYXRpb24gVGFnIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmIChqd2UucHJvdGVjdGVkICE9PSB1bmRlZmluZWQgJiYgdHlwZW9mIGp3ZS5wcm90ZWN0ZWQgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgUHJvdGVjdGVkIEhlYWRlciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoandlLmVuY3J5cHRlZF9rZXkgIT09IHVuZGVmaW5lZCAmJiB0eXBlb2YgandlLmVuY3J5cHRlZF9rZXkgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgRW5jcnlwdGVkIEtleSBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoandlLmFhZCAhPT0gdW5kZWZpbmVkICYmIHR5cGVvZiBqd2UuYWFkICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEFBRCBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoandlLmhlYWRlciAhPT0gdW5kZWZpbmVkICYmICFpc09iamVjdChqd2UuaGVhZGVyKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFNoYXJlZCBVbnByb3RlY3RlZCBIZWFkZXIgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3ZS51bnByb3RlY3RlZCAhPT0gdW5kZWZpbmVkICYmICFpc09iamVjdChqd2UudW5wcm90ZWN0ZWQpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgUGVyLVJlY2lwaWVudCBVbnByb3RlY3RlZCBIZWFkZXIgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgbGV0IHBhcnNlZFByb3Q7XG4gICAgaWYgKGp3ZS5wcm90ZWN0ZWQpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIGNvbnN0IHByb3RlY3RlZEhlYWRlciA9IGJhc2U2NHVybChqd2UucHJvdGVjdGVkKTtcbiAgICAgICAgICAgIHBhcnNlZFByb3QgPSBKU09OLnBhcnNlKGRlY29kZXIuZGVjb2RlKHByb3RlY3RlZEhlYWRlcikpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgUHJvdGVjdGVkIEhlYWRlciBpcyBpbnZhbGlkJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgaWYgKCFpc0Rpc2pvaW50KHBhcnNlZFByb3QsIGp3ZS5oZWFkZXIsIGp3ZS51bnByb3RlY3RlZCkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBQcm90ZWN0ZWQsIEpXRSBVbnByb3RlY3RlZCBIZWFkZXIsIGFuZCBKV0UgUGVyLVJlY2lwaWVudCBVbnByb3RlY3RlZCBIZWFkZXIgUGFyYW1ldGVyIG5hbWVzIG11c3QgYmUgZGlzam9pbnQnKTtcbiAgICB9XG4gICAgY29uc3Qgam9zZUhlYWRlciA9IHtcbiAgICAgICAgLi4ucGFyc2VkUHJvdCxcbiAgICAgICAgLi4uandlLmhlYWRlcixcbiAgICAgICAgLi4uandlLnVucHJvdGVjdGVkLFxuICAgIH07XG4gICAgdmFsaWRhdGVDcml0KEpXRUludmFsaWQsIG5ldyBNYXAoKSwgb3B0aW9ucz8uY3JpdCwgcGFyc2VkUHJvdCwgam9zZUhlYWRlcik7XG4gICAgaWYgKGpvc2VIZWFkZXIuemlwICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0pXRSBcInppcFwiIChDb21wcmVzc2lvbiBBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgaXMgbm90IHN1cHBvcnRlZC4nKTtcbiAgICB9XG4gICAgY29uc3QgeyBhbGcsIGVuYyB9ID0gam9zZUhlYWRlcjtcbiAgICBpZiAodHlwZW9mIGFsZyAhPT0gJ3N0cmluZycgfHwgIWFsZykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnbWlzc2luZyBKV0UgQWxnb3JpdGhtIChhbGcpIGluIEpXRSBIZWFkZXInKTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBlbmMgIT09ICdzdHJpbmcnIHx8ICFlbmMpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ21pc3NpbmcgSldFIEVuY3J5cHRpb24gQWxnb3JpdGhtIChlbmMpIGluIEpXRSBIZWFkZXInKTtcbiAgICB9XG4gICAgY29uc3Qga2V5TWFuYWdlbWVudEFsZ29yaXRobXMgPSBvcHRpb25zICYmIHZhbGlkYXRlQWxnb3JpdGhtcygna2V5TWFuYWdlbWVudEFsZ29yaXRobXMnLCBvcHRpb25zLmtleU1hbmFnZW1lbnRBbGdvcml0aG1zKTtcbiAgICBjb25zdCBjb250ZW50RW5jcnlwdGlvbkFsZ29yaXRobXMgPSBvcHRpb25zICYmXG4gICAgICAgIHZhbGlkYXRlQWxnb3JpdGhtcygnY29udGVudEVuY3J5cHRpb25BbGdvcml0aG1zJywgb3B0aW9ucy5jb250ZW50RW5jcnlwdGlvbkFsZ29yaXRobXMpO1xuICAgIGlmICgoa2V5TWFuYWdlbWVudEFsZ29yaXRobXMgJiYgIWtleU1hbmFnZW1lbnRBbGdvcml0aG1zLmhhcyhhbGcpKSB8fFxuICAgICAgICAoIWtleU1hbmFnZW1lbnRBbGdvcml0aG1zICYmIGFsZy5zdGFydHNXaXRoKCdQQkVTMicpKSkge1xuICAgICAgICB0aHJvdyBuZXcgSk9TRUFsZ05vdEFsbG93ZWQoJ1wiYWxnXCIgKEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciB2YWx1ZSBub3QgYWxsb3dlZCcpO1xuICAgIH1cbiAgICBpZiAoY29udGVudEVuY3J5cHRpb25BbGdvcml0aG1zICYmICFjb250ZW50RW5jcnlwdGlvbkFsZ29yaXRobXMuaGFzKGVuYykpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpPU0VBbGdOb3RBbGxvd2VkKCdcImVuY1wiIChFbmNyeXB0aW9uIEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciB2YWx1ZSBub3QgYWxsb3dlZCcpO1xuICAgIH1cbiAgICBsZXQgZW5jcnlwdGVkS2V5O1xuICAgIGlmIChqd2UuZW5jcnlwdGVkX2tleSAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBlbmNyeXB0ZWRLZXkgPSBiYXNlNjR1cmwoandlLmVuY3J5cHRlZF9rZXkpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgZW5jcnlwdGVkX2tleScpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGxldCByZXNvbHZlZEtleSA9IGZhbHNlO1xuICAgIGlmICh0eXBlb2Yga2V5ID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgIGtleSA9IGF3YWl0IGtleShwYXJzZWRQcm90LCBqd2UpO1xuICAgICAgICByZXNvbHZlZEtleSA9IHRydWU7XG4gICAgfVxuICAgIGxldCBjZWs7XG4gICAgdHJ5IHtcbiAgICAgICAgY2VrID0gYXdhaXQgZGVjcnlwdEtleU1hbmFnZW1lbnQoYWxnLCBrZXksIGVuY3J5cHRlZEtleSwgam9zZUhlYWRlciwgb3B0aW9ucyk7XG4gICAgfVxuICAgIGNhdGNoIChlcnIpIHtcbiAgICAgICAgaWYgKGVyciBpbnN0YW5jZW9mIFR5cGVFcnJvciB8fCBlcnIgaW5zdGFuY2VvZiBKV0VJbnZhbGlkIHx8IGVyciBpbnN0YW5jZW9mIEpPU0VOb3RTdXBwb3J0ZWQpIHtcbiAgICAgICAgICAgIHRocm93IGVycjtcbiAgICAgICAgfVxuICAgICAgICBjZWsgPSBnZW5lcmF0ZUNlayhlbmMpO1xuICAgIH1cbiAgICBsZXQgaXY7XG4gICAgbGV0IHRhZztcbiAgICBpZiAoandlLml2ICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIGl2ID0gYmFzZTY0dXJsKGp3ZS5pdik7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBpdicpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGlmIChqd2UudGFnICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHRhZyA9IGJhc2U2NHVybChqd2UudGFnKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIHRhZycpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGNvbnN0IHByb3RlY3RlZEhlYWRlciA9IGVuY29kZXIuZW5jb2RlKGp3ZS5wcm90ZWN0ZWQgPz8gJycpO1xuICAgIGxldCBhZGRpdGlvbmFsRGF0YTtcbiAgICBpZiAoandlLmFhZCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIGFkZGl0aW9uYWxEYXRhID0gY29uY2F0KHByb3RlY3RlZEhlYWRlciwgZW5jb2Rlci5lbmNvZGUoJy4nKSwgZW5jb2Rlci5lbmNvZGUoandlLmFhZCkpO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgYWRkaXRpb25hbERhdGEgPSBwcm90ZWN0ZWRIZWFkZXI7XG4gICAgfVxuICAgIGxldCBjaXBoZXJ0ZXh0O1xuICAgIHRyeSB7XG4gICAgICAgIGNpcGhlcnRleHQgPSBiYXNlNjR1cmwoandlLmNpcGhlcnRleHQpO1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgY2lwaGVydGV4dCcpO1xuICAgIH1cbiAgICBjb25zdCBwbGFpbnRleHQgPSBhd2FpdCBkZWNyeXB0KGVuYywgY2VrLCBjaXBoZXJ0ZXh0LCBpdiwgdGFnLCBhZGRpdGlvbmFsRGF0YSk7XG4gICAgY29uc3QgcmVzdWx0ID0geyBwbGFpbnRleHQgfTtcbiAgICBpZiAoandlLnByb3RlY3RlZCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHJlc3VsdC5wcm90ZWN0ZWRIZWFkZXIgPSBwYXJzZWRQcm90O1xuICAgIH1cbiAgICBpZiAoandlLmFhZCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICByZXN1bHQuYWRkaXRpb25hbEF1dGhlbnRpY2F0ZWREYXRhID0gYmFzZTY0dXJsKGp3ZS5hYWQpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgYWFkJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgaWYgKGp3ZS51bnByb3RlY3RlZCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHJlc3VsdC5zaGFyZWRVbnByb3RlY3RlZEhlYWRlciA9IGp3ZS51bnByb3RlY3RlZDtcbiAgICB9XG4gICAgaWYgKGp3ZS5oZWFkZXIgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICByZXN1bHQudW5wcm90ZWN0ZWRIZWFkZXIgPSBqd2UuaGVhZGVyO1xuICAgIH1cbiAgICBpZiAocmVzb2x2ZWRLZXkpIHtcbiAgICAgICAgcmV0dXJuIHsgLi4ucmVzdWx0LCBrZXkgfTtcbiAgICB9XG4gICAgcmV0dXJuIHJlc3VsdDtcbn1cbiIsImltcG9ydCB7IGZsYXR0ZW5lZERlY3J5cHQgfSBmcm9tICcuLi9mbGF0dGVuZWQvZGVjcnlwdC5qcyc7XG5pbXBvcnQgeyBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHsgZGVjb2RlciB9IGZyb20gJy4uLy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGNvbXBhY3REZWNyeXB0KGp3ZSwga2V5LCBvcHRpb25zKSB7XG4gICAgaWYgKGp3ZSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgandlID0gZGVjb2Rlci5kZWNvZGUoandlKTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBqd2UgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdDb21wYWN0IEpXRSBtdXN0IGJlIGEgc3RyaW5nIG9yIFVpbnQ4QXJyYXknKTtcbiAgICB9XG4gICAgY29uc3QgeyAwOiBwcm90ZWN0ZWRIZWFkZXIsIDE6IGVuY3J5cHRlZEtleSwgMjogaXYsIDM6IGNpcGhlcnRleHQsIDQ6IHRhZywgbGVuZ3RoLCB9ID0gandlLnNwbGl0KCcuJyk7XG4gICAgaWYgKGxlbmd0aCAhPT0gNSkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSW52YWxpZCBDb21wYWN0IEpXRScpO1xuICAgIH1cbiAgICBjb25zdCBkZWNyeXB0ZWQgPSBhd2FpdCBmbGF0dGVuZWREZWNyeXB0KHtcbiAgICAgICAgY2lwaGVydGV4dCxcbiAgICAgICAgaXY6IGl2IHx8IHVuZGVmaW5lZCxcbiAgICAgICAgcHJvdGVjdGVkOiBwcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgIHRhZzogdGFnIHx8IHVuZGVmaW5lZCxcbiAgICAgICAgZW5jcnlwdGVkX2tleTogZW5jcnlwdGVkS2V5IHx8IHVuZGVmaW5lZCxcbiAgICB9LCBrZXksIG9wdGlvbnMpO1xuICAgIGNvbnN0IHJlc3VsdCA9IHsgcGxhaW50ZXh0OiBkZWNyeXB0ZWQucGxhaW50ZXh0LCBwcm90ZWN0ZWRIZWFkZXI6IGRlY3J5cHRlZC5wcm90ZWN0ZWRIZWFkZXIgfTtcbiAgICBpZiAodHlwZW9mIGtleSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICByZXR1cm4geyAuLi5yZXN1bHQsIGtleTogZGVjcnlwdGVkLmtleSB9O1xuICAgIH1cbiAgICByZXR1cm4gcmVzdWx0O1xufVxuIiwiaW1wb3J0IHsgZmxhdHRlbmVkRGVjcnlwdCB9IGZyb20gJy4uL2ZsYXR0ZW5lZC9kZWNyeXB0LmpzJztcbmltcG9ydCB7IEpXRURlY3J5cHRpb25GYWlsZWQsIEpXRUludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgaXNPYmplY3QgZnJvbSAnLi4vLi4vbGliL2lzX29iamVjdC5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhbERlY3J5cHQoandlLCBrZXksIG9wdGlvbnMpIHtcbiAgICBpZiAoIWlzT2JqZWN0KGp3ZSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0dlbmVyYWwgSldFIG11c3QgYmUgYW4gb2JqZWN0Jyk7XG4gICAgfVxuICAgIGlmICghQXJyYXkuaXNBcnJheShqd2UucmVjaXBpZW50cykgfHwgIWp3ZS5yZWNpcGllbnRzLmV2ZXJ5KGlzT2JqZWN0KSkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFJlY2lwaWVudHMgbWlzc2luZyBvciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoIWp3ZS5yZWNpcGllbnRzLmxlbmd0aCkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFJlY2lwaWVudHMgaGFzIG5vIG1lbWJlcnMnKTtcbiAgICB9XG4gICAgZm9yIChjb25zdCByZWNpcGllbnQgb2YgandlLnJlY2lwaWVudHMpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHJldHVybiBhd2FpdCBmbGF0dGVuZWREZWNyeXB0KHtcbiAgICAgICAgICAgICAgICBhYWQ6IGp3ZS5hYWQsXG4gICAgICAgICAgICAgICAgY2lwaGVydGV4dDogandlLmNpcGhlcnRleHQsXG4gICAgICAgICAgICAgICAgZW5jcnlwdGVkX2tleTogcmVjaXBpZW50LmVuY3J5cHRlZF9rZXksXG4gICAgICAgICAgICAgICAgaGVhZGVyOiByZWNpcGllbnQuaGVhZGVyLFxuICAgICAgICAgICAgICAgIGl2OiBqd2UuaXYsXG4gICAgICAgICAgICAgICAgcHJvdGVjdGVkOiBqd2UucHJvdGVjdGVkLFxuICAgICAgICAgICAgICAgIHRhZzogandlLnRhZyxcbiAgICAgICAgICAgICAgICB1bnByb3RlY3RlZDogandlLnVucHJvdGVjdGVkLFxuICAgICAgICAgICAgfSwga2V5LCBvcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgIH1cbiAgICB9XG4gICAgdGhyb3cgbmV3IEpXRURlY3J5cHRpb25GYWlsZWQoKTtcbn1cbiIsImltcG9ydCBjcnlwdG8sIHsgaXNDcnlwdG9LZXkgfSBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyBlbmNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmNvbnN0IGtleVRvSldLID0gYXN5bmMgKGtleSkgPT4ge1xuICAgIGlmIChrZXkgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBrdHk6ICdvY3QnLFxuICAgICAgICAgICAgazogYmFzZTY0dXJsKGtleSksXG4gICAgICAgIH07XG4gICAgfVxuICAgIGlmICghaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzLCAnVWludDhBcnJheScpKTtcbiAgICB9XG4gICAgaWYgKCFrZXkuZXh0cmFjdGFibGUpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignbm9uLWV4dHJhY3RhYmxlIENyeXB0b0tleSBjYW5ub3QgYmUgZXhwb3J0ZWQgYXMgYSBKV0snKTtcbiAgICB9XG4gICAgY29uc3QgeyBleHQsIGtleV9vcHMsIGFsZywgdXNlLCAuLi5qd2sgfSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdqd2snLCBrZXkpO1xuICAgIHJldHVybiBqd2s7XG59O1xuZXhwb3J0IGRlZmF1bHQga2V5VG9KV0s7XG4iLCJpbXBvcnQgeyB0b1NQS0kgYXMgZXhwb3J0UHVibGljIH0gZnJvbSAnLi4vcnVudGltZS9hc24xLmpzJztcbmltcG9ydCB7IHRvUEtDUzggYXMgZXhwb3J0UHJpdmF0ZSB9IGZyb20gJy4uL3J1bnRpbWUvYXNuMS5qcyc7XG5pbXBvcnQga2V5VG9KV0sgZnJvbSAnLi4vcnVudGltZS9rZXlfdG9fandrLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBleHBvcnRTUEtJKGtleSkge1xuICAgIHJldHVybiBleHBvcnRQdWJsaWMoa2V5KTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBleHBvcnRQS0NTOChrZXkpIHtcbiAgICByZXR1cm4gZXhwb3J0UHJpdmF0ZShrZXkpO1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGV4cG9ydEpXSyhrZXkpIHtcbiAgICByZXR1cm4ga2V5VG9KV0soa2V5KTtcbn1cbiIsImltcG9ydCB7IHdyYXAgYXMgYWVzS3cgfSBmcm9tICcuLi9ydW50aW1lL2Flc2t3LmpzJztcbmltcG9ydCAqIGFzIEVDREggZnJvbSAnLi4vcnVudGltZS9lY2RoZXMuanMnO1xuaW1wb3J0IHsgZW5jcnlwdCBhcyBwYmVzMkt3IH0gZnJvbSAnLi4vcnVudGltZS9wYmVzMmt3LmpzJztcbmltcG9ydCB7IGVuY3J5cHQgYXMgcnNhRXMgfSBmcm9tICcuLi9ydW50aW1lL3JzYWVzLmpzJztcbmltcG9ydCB7IGVuY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgZ2VuZXJhdGVDZWssIHsgYml0TGVuZ3RoIGFzIGNla0xlbmd0aCB9IGZyb20gJy4uL2xpYi9jZWsuanMnO1xuaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IGV4cG9ydEpXSyB9IGZyb20gJy4uL2tleS9leHBvcnQuanMnO1xuaW1wb3J0IGNoZWNrS2V5VHlwZSBmcm9tICcuL2NoZWNrX2tleV90eXBlLmpzJztcbmltcG9ydCB7IHdyYXAgYXMgYWVzR2NtS3cgfSBmcm9tICcuL2Flc2djbWt3LmpzJztcbmFzeW5jIGZ1bmN0aW9uIGVuY3J5cHRLZXlNYW5hZ2VtZW50KGFsZywgZW5jLCBrZXksIHByb3ZpZGVkQ2VrLCBwcm92aWRlZFBhcmFtZXRlcnMgPSB7fSkge1xuICAgIGxldCBlbmNyeXB0ZWRLZXk7XG4gICAgbGV0IHBhcmFtZXRlcnM7XG4gICAgbGV0IGNlaztcbiAgICBjaGVja0tleVR5cGUoYWxnLCBrZXksICdlbmNyeXB0Jyk7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnZGlyJzoge1xuICAgICAgICAgICAgY2VrID0ga2V5O1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnRUNESC1FUyc6XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMTkyS1cnOlxuICAgICAgICBjYXNlICdFQ0RILUVTK0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGlmICghRUNESC5lY2RoQWxsb3dlZChrZXkpKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0VDREggd2l0aCB0aGUgcHJvdmlkZWQga2V5IGlzIG5vdCBhbGxvd2VkIG9yIG5vdCBzdXBwb3J0ZWQgYnkgeW91ciBqYXZhc2NyaXB0IHJ1bnRpbWUnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNvbnN0IHsgYXB1LCBhcHYgfSA9IHByb3ZpZGVkUGFyYW1ldGVycztcbiAgICAgICAgICAgIGxldCB7IGVwazogZXBoZW1lcmFsS2V5IH0gPSBwcm92aWRlZFBhcmFtZXRlcnM7XG4gICAgICAgICAgICBlcGhlbWVyYWxLZXkgfHwgKGVwaGVtZXJhbEtleSA9IChhd2FpdCBFQ0RILmdlbmVyYXRlRXBrKGtleSkpLnByaXZhdGVLZXkpO1xuICAgICAgICAgICAgY29uc3QgeyB4LCB5LCBjcnYsIGt0eSB9ID0gYXdhaXQgZXhwb3J0SldLKGVwaGVtZXJhbEtleSk7XG4gICAgICAgICAgICBjb25zdCBzaGFyZWRTZWNyZXQgPSBhd2FpdCBFQ0RILmRlcml2ZUtleShrZXksIGVwaGVtZXJhbEtleSwgYWxnID09PSAnRUNESC1FUycgPyBlbmMgOiBhbGcsIGFsZyA9PT0gJ0VDREgtRVMnID8gY2VrTGVuZ3RoKGVuYykgOiBwYXJzZUludChhbGcuc2xpY2UoLTUsIC0yKSwgMTApLCBhcHUsIGFwdik7XG4gICAgICAgICAgICBwYXJhbWV0ZXJzID0geyBlcGs6IHsgeCwgY3J2LCBrdHkgfSB9O1xuICAgICAgICAgICAgaWYgKGt0eSA9PT0gJ0VDJylcbiAgICAgICAgICAgICAgICBwYXJhbWV0ZXJzLmVway55ID0geTtcbiAgICAgICAgICAgIGlmIChhcHUpXG4gICAgICAgICAgICAgICAgcGFyYW1ldGVycy5hcHUgPSBiYXNlNjR1cmwoYXB1KTtcbiAgICAgICAgICAgIGlmIChhcHYpXG4gICAgICAgICAgICAgICAgcGFyYW1ldGVycy5hcHYgPSBiYXNlNjR1cmwoYXB2KTtcbiAgICAgICAgICAgIGlmIChhbGcgPT09ICdFQ0RILUVTJykge1xuICAgICAgICAgICAgICAgIGNlayA9IHNoYXJlZFNlY3JldDtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNlayA9IHByb3ZpZGVkQ2VrIHx8IGdlbmVyYXRlQ2VrKGVuYyk7XG4gICAgICAgICAgICBjb25zdCBrd0FsZyA9IGFsZy5zbGljZSgtNik7XG4gICAgICAgICAgICBlbmNyeXB0ZWRLZXkgPSBhd2FpdCBhZXNLdyhrd0FsZywgc2hhcmVkU2VjcmV0LCBjZWspO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnUlNBMV81JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0yNTYnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC0zODQnOlxuICAgICAgICBjYXNlICdSU0EtT0FFUC01MTInOiB7XG4gICAgICAgICAgICBjZWsgPSBwcm92aWRlZENlayB8fCBnZW5lcmF0ZUNlayhlbmMpO1xuICAgICAgICAgICAgZW5jcnlwdGVkS2V5ID0gYXdhaXQgcnNhRXMoYWxnLCBrZXksIGNlayk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdQQkVTMi1IUzI1NitBMTI4S1cnOlxuICAgICAgICBjYXNlICdQQkVTMi1IUzM4NCtBMTkyS1cnOlxuICAgICAgICBjYXNlICdQQkVTMi1IUzUxMitBMjU2S1cnOiB7XG4gICAgICAgICAgICBjZWsgPSBwcm92aWRlZENlayB8fCBnZW5lcmF0ZUNlayhlbmMpO1xuICAgICAgICAgICAgY29uc3QgeyBwMmMsIHAycyB9ID0gcHJvdmlkZWRQYXJhbWV0ZXJzO1xuICAgICAgICAgICAgKHsgZW5jcnlwdGVkS2V5LCAuLi5wYXJhbWV0ZXJzIH0gPSBhd2FpdCBwYmVzMkt3KGFsZywga2V5LCBjZWssIHAyYywgcDJzKSk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdBMTI4S1cnOlxuICAgICAgICBjYXNlICdBMTkyS1cnOlxuICAgICAgICBjYXNlICdBMjU2S1cnOiB7XG4gICAgICAgICAgICBjZWsgPSBwcm92aWRlZENlayB8fCBnZW5lcmF0ZUNlayhlbmMpO1xuICAgICAgICAgICAgZW5jcnlwdGVkS2V5ID0gYXdhaXQgYWVzS3coYWxnLCBrZXksIGNlayk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdBMTI4R0NNS1cnOlxuICAgICAgICBjYXNlICdBMTkyR0NNS1cnOlxuICAgICAgICBjYXNlICdBMjU2R0NNS1cnOiB7XG4gICAgICAgICAgICBjZWsgPSBwcm92aWRlZENlayB8fCBnZW5lcmF0ZUNlayhlbmMpO1xuICAgICAgICAgICAgY29uc3QgeyBpdiB9ID0gcHJvdmlkZWRQYXJhbWV0ZXJzO1xuICAgICAgICAgICAgKHsgZW5jcnlwdGVkS2V5LCAuLi5wYXJhbWV0ZXJzIH0gPSBhd2FpdCBhZXNHY21LdyhhbGcsIGtleSwgY2VrLCBpdikpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgZGVmYXVsdDoge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgXCJhbGdcIiAoSldFIEFsZ29yaXRobSkgaGVhZGVyIHZhbHVlJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHsgY2VrLCBlbmNyeXB0ZWRLZXksIHBhcmFtZXRlcnMgfTtcbn1cbmV4cG9ydCBkZWZhdWx0IGVuY3J5cHRLZXlNYW5hZ2VtZW50O1xuIiwiaW1wb3J0IHsgZW5jb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4uLy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmltcG9ydCBlbmNyeXB0IGZyb20gJy4uLy4uL3J1bnRpbWUvZW5jcnlwdC5qcyc7XG5pbXBvcnQgZW5jcnlwdEtleU1hbmFnZW1lbnQgZnJvbSAnLi4vLi4vbGliL2VuY3J5cHRfa2V5X21hbmFnZW1lbnQuanMnO1xuaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCwgSldFSW52YWxpZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCBpc0Rpc2pvaW50IGZyb20gJy4uLy4uL2xpYi9pc19kaXNqb2ludC5qcyc7XG5pbXBvcnQgeyBlbmNvZGVyLCBkZWNvZGVyLCBjb25jYXQgfSBmcm9tICcuLi8uLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmltcG9ydCB2YWxpZGF0ZUNyaXQgZnJvbSAnLi4vLi4vbGliL3ZhbGlkYXRlX2NyaXQuanMnO1xuZXhwb3J0IGNvbnN0IHVucHJvdGVjdGVkID0gU3ltYm9sKCk7XG5leHBvcnQgY2xhc3MgRmxhdHRlbmVkRW5jcnlwdCB7XG4gICAgY29uc3RydWN0b3IocGxhaW50ZXh0KSB7XG4gICAgICAgIGlmICghKHBsYWludGV4dCBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdwbGFpbnRleHQgbXVzdCBiZSBhbiBpbnN0YW5jZSBvZiBVaW50OEFycmF5Jyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fcGxhaW50ZXh0ID0gcGxhaW50ZXh0O1xuICAgIH1cbiAgICBzZXRLZXlNYW5hZ2VtZW50UGFyYW1ldGVycyhwYXJhbWV0ZXJzKSB7XG4gICAgICAgIGlmICh0aGlzLl9rZXlNYW5hZ2VtZW50UGFyYW1ldGVycykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0S2V5TWFuYWdlbWVudFBhcmFtZXRlcnMgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9rZXlNYW5hZ2VtZW50UGFyYW1ldGVycyA9IHBhcmFtZXRlcnM7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3Byb3RlY3RlZEhlYWRlciA9IHByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldFNoYXJlZFVucHJvdGVjdGVkSGVhZGVyKHNoYXJlZFVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLl9zaGFyZWRVbnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0U2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9zaGFyZWRVbnByb3RlY3RlZEhlYWRlciA9IHNoYXJlZFVucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0VW5wcm90ZWN0ZWRIZWFkZXIodW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRVbnByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyID0gdW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRBZGRpdGlvbmFsQXV0aGVudGljYXRlZERhdGEoYWFkKSB7XG4gICAgICAgIHRoaXMuX2FhZCA9IGFhZDtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldENvbnRlbnRFbmNyeXB0aW9uS2V5KGNlaykge1xuICAgICAgICBpZiAodGhpcy5fY2VrKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRDb250ZW50RW5jcnlwdGlvbktleSBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX2NlayA9IGNlaztcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldEluaXRpYWxpemF0aW9uVmVjdG9yKGl2KSB7XG4gICAgICAgIGlmICh0aGlzLl9pdikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0SW5pdGlhbGl6YXRpb25WZWN0b3IgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9pdiA9IGl2O1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgYXN5bmMgZW5jcnlwdChrZXksIG9wdGlvbnMpIHtcbiAgICAgICAgaWYgKCF0aGlzLl9wcm90ZWN0ZWRIZWFkZXIgJiYgIXRoaXMuX3VucHJvdGVjdGVkSGVhZGVyICYmICF0aGlzLl9zaGFyZWRVbnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ2VpdGhlciBzZXRQcm90ZWN0ZWRIZWFkZXIsIHNldFVucHJvdGVjdGVkSGVhZGVyLCBvciBzaGFyZWRVbnByb3RlY3RlZEhlYWRlciBtdXN0IGJlIGNhbGxlZCBiZWZvcmUgI2VuY3J5cHQoKScpO1xuICAgICAgICB9XG4gICAgICAgIGlmICghaXNEaXNqb2ludCh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIsIHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyLCB0aGlzLl9zaGFyZWRVbnByb3RlY3RlZEhlYWRlcikpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgUHJvdGVjdGVkLCBKV0UgU2hhcmVkIFVucHJvdGVjdGVkIGFuZCBKV0UgUGVyLVJlY2lwaWVudCBIZWFkZXIgUGFyYW1ldGVyIG5hbWVzIG11c3QgYmUgZGlzam9pbnQnKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBqb3NlSGVhZGVyID0ge1xuICAgICAgICAgICAgLi4udGhpcy5fcHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgLi4udGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICAuLi50aGlzLl9zaGFyZWRVbnByb3RlY3RlZEhlYWRlcixcbiAgICAgICAgfTtcbiAgICAgICAgdmFsaWRhdGVDcml0KEpXRUludmFsaWQsIG5ldyBNYXAoKSwgb3B0aW9ucz8uY3JpdCwgdGhpcy5fcHJvdGVjdGVkSGVhZGVyLCBqb3NlSGVhZGVyKTtcbiAgICAgICAgaWYgKGpvc2VIZWFkZXIuemlwICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdKV0UgXCJ6aXBcIiAoQ29tcHJlc3Npb24gQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIGlzIG5vdCBzdXBwb3J0ZWQuJyk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgeyBhbGcsIGVuYyB9ID0gam9zZUhlYWRlcjtcbiAgICAgICAgaWYgKHR5cGVvZiBhbGcgIT09ICdzdHJpbmcnIHx8ICFhbGcpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgXCJhbGdcIiAoQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIG1pc3Npbmcgb3IgaW52YWxpZCcpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0eXBlb2YgZW5jICE9PSAnc3RyaW5nJyB8fCAhZW5jKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFwiZW5jXCIgKEVuY3J5cHRpb24gQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIG1pc3Npbmcgb3IgaW52YWxpZCcpO1xuICAgICAgICB9XG4gICAgICAgIGxldCBlbmNyeXB0ZWRLZXk7XG4gICAgICAgIGlmICh0aGlzLl9jZWsgJiYgKGFsZyA9PT0gJ2RpcicgfHwgYWxnID09PSAnRUNESC1FUycpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGBzZXRDb250ZW50RW5jcnlwdGlvbktleSBjYW5ub3QgYmUgY2FsbGVkIHdpdGggSldFIFwiYWxnXCIgKEFsZ29yaXRobSkgSGVhZGVyICR7YWxnfWApO1xuICAgICAgICB9XG4gICAgICAgIGxldCBjZWs7XG4gICAgICAgIHtcbiAgICAgICAgICAgIGxldCBwYXJhbWV0ZXJzO1xuICAgICAgICAgICAgKHsgY2VrLCBlbmNyeXB0ZWRLZXksIHBhcmFtZXRlcnMgfSA9IGF3YWl0IGVuY3J5cHRLZXlNYW5hZ2VtZW50KGFsZywgZW5jLCBrZXksIHRoaXMuX2NlaywgdGhpcy5fa2V5TWFuYWdlbWVudFBhcmFtZXRlcnMpKTtcbiAgICAgICAgICAgIGlmIChwYXJhbWV0ZXJzKSB7XG4gICAgICAgICAgICAgICAgaWYgKG9wdGlvbnMgJiYgdW5wcm90ZWN0ZWQgaW4gb3B0aW9ucykge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIXRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnNldFVucHJvdGVjdGVkSGVhZGVyKHBhcmFtZXRlcnMpO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIgPSB7IC4uLnRoaXMuX3VucHJvdGVjdGVkSGVhZGVyLCAuLi5wYXJhbWV0ZXJzIH07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIGlmICghdGhpcy5fcHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLnNldFByb3RlY3RlZEhlYWRlcihwYXJhbWV0ZXJzKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX3Byb3RlY3RlZEhlYWRlciA9IHsgLi4udGhpcy5fcHJvdGVjdGVkSGVhZGVyLCAuLi5wYXJhbWV0ZXJzIH07XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgbGV0IGFkZGl0aW9uYWxEYXRhO1xuICAgICAgICBsZXQgcHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICBsZXQgYWFkTWVtYmVyO1xuICAgICAgICBpZiAodGhpcy5fcHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICBwcm90ZWN0ZWRIZWFkZXIgPSBlbmNvZGVyLmVuY29kZShiYXNlNjR1cmwoSlNPTi5zdHJpbmdpZnkodGhpcy5fcHJvdGVjdGVkSGVhZGVyKSkpO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgcHJvdGVjdGVkSGVhZGVyID0gZW5jb2Rlci5lbmNvZGUoJycpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl9hYWQpIHtcbiAgICAgICAgICAgIGFhZE1lbWJlciA9IGJhc2U2NHVybCh0aGlzLl9hYWQpO1xuICAgICAgICAgICAgYWRkaXRpb25hbERhdGEgPSBjb25jYXQocHJvdGVjdGVkSGVhZGVyLCBlbmNvZGVyLmVuY29kZSgnLicpLCBlbmNvZGVyLmVuY29kZShhYWRNZW1iZXIpKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIGFkZGl0aW9uYWxEYXRhID0gcHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHsgY2lwaGVydGV4dCwgdGFnLCBpdiB9ID0gYXdhaXQgZW5jcnlwdChlbmMsIHRoaXMuX3BsYWludGV4dCwgY2VrLCB0aGlzLl9pdiwgYWRkaXRpb25hbERhdGEpO1xuICAgICAgICBjb25zdCBqd2UgPSB7XG4gICAgICAgICAgICBjaXBoZXJ0ZXh0OiBiYXNlNjR1cmwoY2lwaGVydGV4dCksXG4gICAgICAgIH07XG4gICAgICAgIGlmIChpdikge1xuICAgICAgICAgICAgandlLml2ID0gYmFzZTY0dXJsKGl2KTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGFnKSB7XG4gICAgICAgICAgICBqd2UudGFnID0gYmFzZTY0dXJsKHRhZyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGVuY3J5cHRlZEtleSkge1xuICAgICAgICAgICAgandlLmVuY3J5cHRlZF9rZXkgPSBiYXNlNjR1cmwoZW5jcnlwdGVkS2V5KTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoYWFkTWVtYmVyKSB7XG4gICAgICAgICAgICBqd2UuYWFkID0gYWFkTWVtYmVyO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIGp3ZS5wcm90ZWN0ZWQgPSBkZWNvZGVyLmRlY29kZShwcm90ZWN0ZWRIZWFkZXIpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl9zaGFyZWRVbnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgandlLnVucHJvdGVjdGVkID0gdGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICBqd2UuaGVhZGVyID0gdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGp3ZTtcbiAgICB9XG59XG4iLCJpbXBvcnQgeyBGbGF0dGVuZWRFbmNyeXB0LCB1bnByb3RlY3RlZCB9IGZyb20gJy4uL2ZsYXR0ZW5lZC9lbmNyeXB0LmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQsIEpXRUludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgZ2VuZXJhdGVDZWsgZnJvbSAnLi4vLi4vbGliL2Nlay5qcyc7XG5pbXBvcnQgaXNEaXNqb2ludCBmcm9tICcuLi8uLi9saWIvaXNfZGlzam9pbnQuanMnO1xuaW1wb3J0IGVuY3J5cHRLZXlNYW5hZ2VtZW50IGZyb20gJy4uLy4uL2xpYi9lbmNyeXB0X2tleV9tYW5hZ2VtZW50LmpzJztcbmltcG9ydCB7IGVuY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi8uLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgdmFsaWRhdGVDcml0IGZyb20gJy4uLy4uL2xpYi92YWxpZGF0ZV9jcml0LmpzJztcbmNsYXNzIEluZGl2aWR1YWxSZWNpcGllbnQge1xuICAgIGNvbnN0cnVjdG9yKGVuYywga2V5LCBvcHRpb25zKSB7XG4gICAgICAgIHRoaXMucGFyZW50ID0gZW5jO1xuICAgICAgICB0aGlzLmtleSA9IGtleTtcbiAgICAgICAgdGhpcy5vcHRpb25zID0gb3B0aW9ucztcbiAgICB9XG4gICAgc2V0VW5wcm90ZWN0ZWRIZWFkZXIodW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMudW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFVucHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy51bnByb3RlY3RlZEhlYWRlciA9IHVucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgYWRkUmVjaXBpZW50KC4uLmFyZ3MpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGFyZW50LmFkZFJlY2lwaWVudCguLi5hcmdzKTtcbiAgICB9XG4gICAgZW5jcnlwdCguLi5hcmdzKSB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhcmVudC5lbmNyeXB0KC4uLmFyZ3MpO1xuICAgIH1cbiAgICBkb25lKCkge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXJlbnQ7XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEdlbmVyYWxFbmNyeXB0IHtcbiAgICBjb25zdHJ1Y3RvcihwbGFpbnRleHQpIHtcbiAgICAgICAgdGhpcy5fcmVjaXBpZW50cyA9IFtdO1xuICAgICAgICB0aGlzLl9wbGFpbnRleHQgPSBwbGFpbnRleHQ7XG4gICAgfVxuICAgIGFkZFJlY2lwaWVudChrZXksIG9wdGlvbnMpIHtcbiAgICAgICAgY29uc3QgcmVjaXBpZW50ID0gbmV3IEluZGl2aWR1YWxSZWNpcGllbnQodGhpcywga2V5LCB7IGNyaXQ6IG9wdGlvbnM/LmNyaXQgfSk7XG4gICAgICAgIHRoaXMuX3JlY2lwaWVudHMucHVzaChyZWNpcGllbnQpO1xuICAgICAgICByZXR1cm4gcmVjaXBpZW50O1xuICAgIH1cbiAgICBzZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3Byb3RlY3RlZEhlYWRlciA9IHByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldFNoYXJlZFVucHJvdGVjdGVkSGVhZGVyKHNoYXJlZFVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLl91bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0U2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl91bnByb3RlY3RlZEhlYWRlciA9IHNoYXJlZFVucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0QWRkaXRpb25hbEF1dGhlbnRpY2F0ZWREYXRhKGFhZCkge1xuICAgICAgICB0aGlzLl9hYWQgPSBhYWQ7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBhc3luYyBlbmNyeXB0KCkge1xuICAgICAgICBpZiAoIXRoaXMuX3JlY2lwaWVudHMubGVuZ3RoKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnYXQgbGVhc3Qgb25lIHJlY2lwaWVudCBtdXN0IGJlIGFkZGVkJyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX3JlY2lwaWVudHMubGVuZ3RoID09PSAxKSB7XG4gICAgICAgICAgICBjb25zdCBbcmVjaXBpZW50XSA9IHRoaXMuX3JlY2lwaWVudHM7XG4gICAgICAgICAgICBjb25zdCBmbGF0dGVuZWQgPSBhd2FpdCBuZXcgRmxhdHRlbmVkRW5jcnlwdCh0aGlzLl9wbGFpbnRleHQpXG4gICAgICAgICAgICAgICAgLnNldEFkZGl0aW9uYWxBdXRoZW50aWNhdGVkRGF0YSh0aGlzLl9hYWQpXG4gICAgICAgICAgICAgICAgLnNldFByb3RlY3RlZEhlYWRlcih0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpXG4gICAgICAgICAgICAgICAgLnNldFNoYXJlZFVucHJvdGVjdGVkSGVhZGVyKHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKVxuICAgICAgICAgICAgICAgIC5zZXRVbnByb3RlY3RlZEhlYWRlcihyZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXIpXG4gICAgICAgICAgICAgICAgLmVuY3J5cHQocmVjaXBpZW50LmtleSwgeyAuLi5yZWNpcGllbnQub3B0aW9ucyB9KTtcbiAgICAgICAgICAgIGNvbnN0IGp3ZSA9IHtcbiAgICAgICAgICAgICAgICBjaXBoZXJ0ZXh0OiBmbGF0dGVuZWQuY2lwaGVydGV4dCxcbiAgICAgICAgICAgICAgICBpdjogZmxhdHRlbmVkLml2LFxuICAgICAgICAgICAgICAgIHJlY2lwaWVudHM6IFt7fV0sXG4gICAgICAgICAgICAgICAgdGFnOiBmbGF0dGVuZWQudGFnLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIGlmIChmbGF0dGVuZWQuYWFkKVxuICAgICAgICAgICAgICAgIGp3ZS5hYWQgPSBmbGF0dGVuZWQuYWFkO1xuICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC5wcm90ZWN0ZWQpXG4gICAgICAgICAgICAgICAgandlLnByb3RlY3RlZCA9IGZsYXR0ZW5lZC5wcm90ZWN0ZWQ7XG4gICAgICAgICAgICBpZiAoZmxhdHRlbmVkLnVucHJvdGVjdGVkKVxuICAgICAgICAgICAgICAgIGp3ZS51bnByb3RlY3RlZCA9IGZsYXR0ZW5lZC51bnByb3RlY3RlZDtcbiAgICAgICAgICAgIGlmIChmbGF0dGVuZWQuZW5jcnlwdGVkX2tleSlcbiAgICAgICAgICAgICAgICBqd2UucmVjaXBpZW50c1swXS5lbmNyeXB0ZWRfa2V5ID0gZmxhdHRlbmVkLmVuY3J5cHRlZF9rZXk7XG4gICAgICAgICAgICBpZiAoZmxhdHRlbmVkLmhlYWRlcilcbiAgICAgICAgICAgICAgICBqd2UucmVjaXBpZW50c1swXS5oZWFkZXIgPSBmbGF0dGVuZWQuaGVhZGVyO1xuICAgICAgICAgICAgcmV0dXJuIGp3ZTtcbiAgICAgICAgfVxuICAgICAgICBsZXQgZW5jO1xuICAgICAgICBmb3IgKGxldCBpID0gMDsgaSA8IHRoaXMuX3JlY2lwaWVudHMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIGNvbnN0IHJlY2lwaWVudCA9IHRoaXMuX3JlY2lwaWVudHNbaV07XG4gICAgICAgICAgICBpZiAoIWlzRGlzam9pbnQodGhpcy5fcHJvdGVjdGVkSGVhZGVyLCB0aGlzLl91bnByb3RlY3RlZEhlYWRlciwgcmVjaXBpZW50LnVucHJvdGVjdGVkSGVhZGVyKSkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgUHJvdGVjdGVkLCBKV0UgU2hhcmVkIFVucHJvdGVjdGVkIGFuZCBKV0UgUGVyLVJlY2lwaWVudCBIZWFkZXIgUGFyYW1ldGVyIG5hbWVzIG11c3QgYmUgZGlzam9pbnQnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNvbnN0IGpvc2VIZWFkZXIgPSB7XG4gICAgICAgICAgICAgICAgLi4udGhpcy5fcHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgICAgIC4uLnRoaXMuX3VucHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgICAgIC4uLnJlY2lwaWVudC51bnByb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgIH07XG4gICAgICAgICAgICBjb25zdCB7IGFsZyB9ID0gam9zZUhlYWRlcjtcbiAgICAgICAgICAgIGlmICh0eXBlb2YgYWxnICE9PSAnc3RyaW5nJyB8fCAhYWxnKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBcImFsZ1wiIChBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgbWlzc2luZyBvciBpbnZhbGlkJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAoYWxnID09PSAnZGlyJyB8fCBhbGcgPT09ICdFQ0RILUVTJykge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdcImRpclwiIGFuZCBcIkVDREgtRVNcIiBhbGcgbWF5IG9ubHkgYmUgdXNlZCB3aXRoIGEgc2luZ2xlIHJlY2lwaWVudCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKHR5cGVvZiBqb3NlSGVhZGVyLmVuYyAhPT0gJ3N0cmluZycgfHwgIWpvc2VIZWFkZXIuZW5jKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBcImVuY1wiIChFbmNyeXB0aW9uIEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBtaXNzaW5nIG9yIGludmFsaWQnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmICghZW5jKSB7XG4gICAgICAgICAgICAgICAgZW5jID0gam9zZUhlYWRlci5lbmM7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBlbHNlIGlmIChlbmMgIT09IGpvc2VIZWFkZXIuZW5jKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBcImVuY1wiIChFbmNyeXB0aW9uIEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBtdXN0IGJlIHRoZSBzYW1lIGZvciBhbGwgcmVjaXBpZW50cycpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgdmFsaWRhdGVDcml0KEpXRUludmFsaWQsIG5ldyBNYXAoKSwgcmVjaXBpZW50Lm9wdGlvbnMuY3JpdCwgdGhpcy5fcHJvdGVjdGVkSGVhZGVyLCBqb3NlSGVhZGVyKTtcbiAgICAgICAgICAgIGlmIChqb3NlSGVhZGVyLnppcCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0pXRSBcInppcFwiIChDb21wcmVzc2lvbiBBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgaXMgbm90IHN1cHBvcnRlZC4nKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBjb25zdCBjZWsgPSBnZW5lcmF0ZUNlayhlbmMpO1xuICAgICAgICBjb25zdCBqd2UgPSB7XG4gICAgICAgICAgICBjaXBoZXJ0ZXh0OiAnJyxcbiAgICAgICAgICAgIGl2OiAnJyxcbiAgICAgICAgICAgIHJlY2lwaWVudHM6IFtdLFxuICAgICAgICAgICAgdGFnOiAnJyxcbiAgICAgICAgfTtcbiAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCB0aGlzLl9yZWNpcGllbnRzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBjb25zdCByZWNpcGllbnQgPSB0aGlzLl9yZWNpcGllbnRzW2ldO1xuICAgICAgICAgICAgY29uc3QgdGFyZ2V0ID0ge307XG4gICAgICAgICAgICBqd2UucmVjaXBpZW50cy5wdXNoKHRhcmdldCk7XG4gICAgICAgICAgICBjb25zdCBqb3NlSGVhZGVyID0ge1xuICAgICAgICAgICAgICAgIC4uLnRoaXMuX3Byb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgICAgICAuLi50aGlzLl91bnByb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgICAgICAuLi5yZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAgY29uc3QgcDJjID0gam9zZUhlYWRlci5hbGcuc3RhcnRzV2l0aCgnUEJFUzInKSA/IDIwNDggKyBpIDogdW5kZWZpbmVkO1xuICAgICAgICAgICAgaWYgKGkgPT09IDApIHtcbiAgICAgICAgICAgICAgICBjb25zdCBmbGF0dGVuZWQgPSBhd2FpdCBuZXcgRmxhdHRlbmVkRW5jcnlwdCh0aGlzLl9wbGFpbnRleHQpXG4gICAgICAgICAgICAgICAgICAgIC5zZXRBZGRpdGlvbmFsQXV0aGVudGljYXRlZERhdGEodGhpcy5fYWFkKVxuICAgICAgICAgICAgICAgICAgICAuc2V0Q29udGVudEVuY3J5cHRpb25LZXkoY2VrKVxuICAgICAgICAgICAgICAgICAgICAuc2V0UHJvdGVjdGVkSGVhZGVyKHRoaXMuX3Byb3RlY3RlZEhlYWRlcilcbiAgICAgICAgICAgICAgICAgICAgLnNldFNoYXJlZFVucHJvdGVjdGVkSGVhZGVyKHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKVxuICAgICAgICAgICAgICAgICAgICAuc2V0VW5wcm90ZWN0ZWRIZWFkZXIocmVjaXBpZW50LnVucHJvdGVjdGVkSGVhZGVyKVxuICAgICAgICAgICAgICAgICAgICAuc2V0S2V5TWFuYWdlbWVudFBhcmFtZXRlcnMoeyBwMmMgfSlcbiAgICAgICAgICAgICAgICAgICAgLmVuY3J5cHQocmVjaXBpZW50LmtleSwge1xuICAgICAgICAgICAgICAgICAgICAuLi5yZWNpcGllbnQub3B0aW9ucyxcbiAgICAgICAgICAgICAgICAgICAgW3VucHJvdGVjdGVkXTogdHJ1ZSxcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICBqd2UuY2lwaGVydGV4dCA9IGZsYXR0ZW5lZC5jaXBoZXJ0ZXh0O1xuICAgICAgICAgICAgICAgIGp3ZS5pdiA9IGZsYXR0ZW5lZC5pdjtcbiAgICAgICAgICAgICAgICBqd2UudGFnID0gZmxhdHRlbmVkLnRhZztcbiAgICAgICAgICAgICAgICBpZiAoZmxhdHRlbmVkLmFhZClcbiAgICAgICAgICAgICAgICAgICAgandlLmFhZCA9IGZsYXR0ZW5lZC5hYWQ7XG4gICAgICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC5wcm90ZWN0ZWQpXG4gICAgICAgICAgICAgICAgICAgIGp3ZS5wcm90ZWN0ZWQgPSBmbGF0dGVuZWQucHJvdGVjdGVkO1xuICAgICAgICAgICAgICAgIGlmIChmbGF0dGVuZWQudW5wcm90ZWN0ZWQpXG4gICAgICAgICAgICAgICAgICAgIGp3ZS51bnByb3RlY3RlZCA9IGZsYXR0ZW5lZC51bnByb3RlY3RlZDtcbiAgICAgICAgICAgICAgICB0YXJnZXQuZW5jcnlwdGVkX2tleSA9IGZsYXR0ZW5lZC5lbmNyeXB0ZWRfa2V5O1xuICAgICAgICAgICAgICAgIGlmIChmbGF0dGVuZWQuaGVhZGVyKVxuICAgICAgICAgICAgICAgICAgICB0YXJnZXQuaGVhZGVyID0gZmxhdHRlbmVkLmhlYWRlcjtcbiAgICAgICAgICAgICAgICBjb250aW51ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNvbnN0IHsgZW5jcnlwdGVkS2V5LCBwYXJhbWV0ZXJzIH0gPSBhd2FpdCBlbmNyeXB0S2V5TWFuYWdlbWVudChyZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXI/LmFsZyB8fFxuICAgICAgICAgICAgICAgIHRoaXMuX3Byb3RlY3RlZEhlYWRlcj8uYWxnIHx8XG4gICAgICAgICAgICAgICAgdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXI/LmFsZywgZW5jLCByZWNpcGllbnQua2V5LCBjZWssIHsgcDJjIH0pO1xuICAgICAgICAgICAgdGFyZ2V0LmVuY3J5cHRlZF9rZXkgPSBiYXNlNjR1cmwoZW5jcnlwdGVkS2V5KTtcbiAgICAgICAgICAgIGlmIChyZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXIgfHwgcGFyYW1ldGVycylcbiAgICAgICAgICAgICAgICB0YXJnZXQuaGVhZGVyID0geyAuLi5yZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXIsIC4uLnBhcmFtZXRlcnMgfTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gandlO1xuICAgIH1cbn1cbiIsImltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBzdWJ0bGVEc2EoYWxnLCBhbGdvcml0aG0pIHtcbiAgICBjb25zdCBoYXNoID0gYFNIQS0ke2FsZy5zbGljZSgtMyl9YDtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdIUzI1Nic6XG4gICAgICAgIGNhc2UgJ0hTMzg0JzpcbiAgICAgICAgY2FzZSAnSFM1MTInOlxuICAgICAgICAgICAgcmV0dXJuIHsgaGFzaCwgbmFtZTogJ0hNQUMnIH07XG4gICAgICAgIGNhc2UgJ1BTMjU2JzpcbiAgICAgICAgY2FzZSAnUFMzODQnOlxuICAgICAgICBjYXNlICdQUzUxMic6XG4gICAgICAgICAgICByZXR1cm4geyBoYXNoLCBuYW1lOiAnUlNBLVBTUycsIHNhbHRMZW5ndGg6IGFsZy5zbGljZSgtMykgPj4gMyB9O1xuICAgICAgICBjYXNlICdSUzI1Nic6XG4gICAgICAgIGNhc2UgJ1JTMzg0JzpcbiAgICAgICAgY2FzZSAnUlM1MTInOlxuICAgICAgICAgICAgcmV0dXJuIHsgaGFzaCwgbmFtZTogJ1JTQVNTQS1QS0NTMS12MV81JyB9O1xuICAgICAgICBjYXNlICdFUzI1Nic6XG4gICAgICAgIGNhc2UgJ0VTMzg0JzpcbiAgICAgICAgY2FzZSAnRVM1MTInOlxuICAgICAgICAgICAgcmV0dXJuIHsgaGFzaCwgbmFtZTogJ0VDRFNBJywgbmFtZWRDdXJ2ZTogYWxnb3JpdGhtLm5hbWVkQ3VydmUgfTtcbiAgICAgICAgY2FzZSAnRWREU0EnOlxuICAgICAgICAgICAgcmV0dXJuIHsgbmFtZTogYWxnb3JpdGhtLm5hbWUgfTtcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKGBhbGcgJHthbGd9IGlzIG5vdCBzdXBwb3J0ZWQgZWl0aGVyIGJ5IEpPU0Ugb3IgeW91ciBqYXZhc2NyaXB0IHJ1bnRpbWVgKTtcbiAgICB9XG59XG4iLCJpbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IHsgY2hlY2tTaWdDcnlwdG9LZXkgfSBmcm9tICcuLi9saWIvY3J5cHRvX2tleS5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gZ2V0Q3J5cHRvS2V5KGFsZywga2V5LCB1c2FnZSkge1xuICAgIGlmIChpc0NyeXB0b0tleShrZXkpKSB7XG4gICAgICAgIGNoZWNrU2lnQ3J5cHRvS2V5KGtleSwgYWxnLCB1c2FnZSk7XG4gICAgICAgIHJldHVybiBrZXk7XG4gICAgfVxuICAgIGlmIChrZXkgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIGlmICghYWxnLnN0YXJ0c1dpdGgoJ0hTJykpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMpKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGtleSwgeyBoYXNoOiBgU0hBLSR7YWxnLnNsaWNlKC0zKX1gLCBuYW1lOiAnSE1BQycgfSwgZmFsc2UsIFt1c2FnZV0pO1xuICAgIH1cbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzLCAnVWludDhBcnJheScpKTtcbn1cbiIsImltcG9ydCBzdWJ0bGVBbGdvcml0aG0gZnJvbSAnLi9zdWJ0bGVfZHNhLmpzJztcbmltcG9ydCBjcnlwdG8gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IGNoZWNrS2V5TGVuZ3RoIGZyb20gJy4vY2hlY2tfa2V5X2xlbmd0aC5qcyc7XG5pbXBvcnQgZ2V0VmVyaWZ5S2V5IGZyb20gJy4vZ2V0X3NpZ25fdmVyaWZ5X2tleS5qcyc7XG5jb25zdCB2ZXJpZnkgPSBhc3luYyAoYWxnLCBrZXksIHNpZ25hdHVyZSwgZGF0YSkgPT4ge1xuICAgIGNvbnN0IGNyeXB0b0tleSA9IGF3YWl0IGdldFZlcmlmeUtleShhbGcsIGtleSwgJ3ZlcmlmeScpO1xuICAgIGNoZWNrS2V5TGVuZ3RoKGFsZywgY3J5cHRvS2V5KTtcbiAgICBjb25zdCBhbGdvcml0aG0gPSBzdWJ0bGVBbGdvcml0aG0oYWxnLCBjcnlwdG9LZXkuYWxnb3JpdGhtKTtcbiAgICB0cnkge1xuICAgICAgICByZXR1cm4gYXdhaXQgY3J5cHRvLnN1YnRsZS52ZXJpZnkoYWxnb3JpdGhtLCBjcnlwdG9LZXksIHNpZ25hdHVyZSwgZGF0YSk7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbn07XG5leHBvcnQgZGVmYXVsdCB2ZXJpZnk7XG4iLCJpbXBvcnQgeyBkZWNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi4vLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHZlcmlmeSBmcm9tICcuLi8uLi9ydW50aW1lL3ZlcmlmeS5qcyc7XG5pbXBvcnQgeyBKT1NFQWxnTm90QWxsb3dlZCwgSldTSW52YWxpZCwgSldTU2lnbmF0dXJlVmVyaWZpY2F0aW9uRmFpbGVkIH0gZnJvbSAnLi4vLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHsgY29uY2F0LCBlbmNvZGVyLCBkZWNvZGVyIH0gZnJvbSAnLi4vLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgaXNEaXNqb2ludCBmcm9tICcuLi8uLi9saWIvaXNfZGlzam9pbnQuanMnO1xuaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4uLy4uL2xpYi9pc19vYmplY3QuanMnO1xuaW1wb3J0IGNoZWNrS2V5VHlwZSBmcm9tICcuLi8uLi9saWIvY2hlY2tfa2V5X3R5cGUuanMnO1xuaW1wb3J0IHZhbGlkYXRlQ3JpdCBmcm9tICcuLi8uLi9saWIvdmFsaWRhdGVfY3JpdC5qcyc7XG5pbXBvcnQgdmFsaWRhdGVBbGdvcml0aG1zIGZyb20gJy4uLy4uL2xpYi92YWxpZGF0ZV9hbGdvcml0aG1zLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBmbGF0dGVuZWRWZXJpZnkoandzLCBrZXksIG9wdGlvbnMpIHtcbiAgICBpZiAoIWlzT2JqZWN0KGp3cykpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0ZsYXR0ZW5lZCBKV1MgbXVzdCBiZSBhbiBvYmplY3QnKTtcbiAgICB9XG4gICAgaWYgKGp3cy5wcm90ZWN0ZWQgPT09IHVuZGVmaW5lZCAmJiBqd3MuaGVhZGVyID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0ZsYXR0ZW5lZCBKV1MgbXVzdCBoYXZlIGVpdGhlciBvZiB0aGUgXCJwcm90ZWN0ZWRcIiBvciBcImhlYWRlclwiIG1lbWJlcnMnKTtcbiAgICB9XG4gICAgaWYgKGp3cy5wcm90ZWN0ZWQgIT09IHVuZGVmaW5lZCAmJiB0eXBlb2YgandzLnByb3RlY3RlZCAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBQcm90ZWN0ZWQgSGVhZGVyIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmIChqd3MucGF5bG9hZCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgUGF5bG9hZCBtaXNzaW5nJyk7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgandzLnNpZ25hdHVyZSAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBTaWduYXR1cmUgbWlzc2luZyBvciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoandzLmhlYWRlciAhPT0gdW5kZWZpbmVkICYmICFpc09iamVjdChqd3MuaGVhZGVyKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFVucHJvdGVjdGVkIEhlYWRlciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBsZXQgcGFyc2VkUHJvdCA9IHt9O1xuICAgIGlmIChqd3MucHJvdGVjdGVkKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBjb25zdCBwcm90ZWN0ZWRIZWFkZXIgPSBiYXNlNjR1cmwoandzLnByb3RlY3RlZCk7XG4gICAgICAgICAgICBwYXJzZWRQcm90ID0gSlNPTi5wYXJzZShkZWNvZGVyLmRlY29kZShwcm90ZWN0ZWRIZWFkZXIpKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFByb3RlY3RlZCBIZWFkZXIgaXMgaW52YWxpZCcpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGlmICghaXNEaXNqb2ludChwYXJzZWRQcm90LCBqd3MuaGVhZGVyKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFByb3RlY3RlZCBhbmQgSldTIFVucHJvdGVjdGVkIEhlYWRlciBQYXJhbWV0ZXIgbmFtZXMgbXVzdCBiZSBkaXNqb2ludCcpO1xuICAgIH1cbiAgICBjb25zdCBqb3NlSGVhZGVyID0ge1xuICAgICAgICAuLi5wYXJzZWRQcm90LFxuICAgICAgICAuLi5qd3MuaGVhZGVyLFxuICAgIH07XG4gICAgY29uc3QgZXh0ZW5zaW9ucyA9IHZhbGlkYXRlQ3JpdChKV1NJbnZhbGlkLCBuZXcgTWFwKFtbJ2I2NCcsIHRydWVdXSksIG9wdGlvbnM/LmNyaXQsIHBhcnNlZFByb3QsIGpvc2VIZWFkZXIpO1xuICAgIGxldCBiNjQgPSB0cnVlO1xuICAgIGlmIChleHRlbnNpb25zLmhhcygnYjY0JykpIHtcbiAgICAgICAgYjY0ID0gcGFyc2VkUHJvdC5iNjQ7XG4gICAgICAgIGlmICh0eXBlb2YgYjY0ICE9PSAnYm9vbGVhbicpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdUaGUgXCJiNjRcIiAoYmFzZTY0dXJsLWVuY29kZSBwYXlsb2FkKSBIZWFkZXIgUGFyYW1ldGVyIG11c3QgYmUgYSBib29sZWFuJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgY29uc3QgeyBhbGcgfSA9IGpvc2VIZWFkZXI7XG4gICAgaWYgKHR5cGVvZiBhbGcgIT09ICdzdHJpbmcnIHx8ICFhbGcpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBcImFsZ1wiIChBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgbWlzc2luZyBvciBpbnZhbGlkJyk7XG4gICAgfVxuICAgIGNvbnN0IGFsZ29yaXRobXMgPSBvcHRpb25zICYmIHZhbGlkYXRlQWxnb3JpdGhtcygnYWxnb3JpdGhtcycsIG9wdGlvbnMuYWxnb3JpdGhtcyk7XG4gICAgaWYgKGFsZ29yaXRobXMgJiYgIWFsZ29yaXRobXMuaGFzKGFsZykpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpPU0VBbGdOb3RBbGxvd2VkKCdcImFsZ1wiIChBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgdmFsdWUgbm90IGFsbG93ZWQnKTtcbiAgICB9XG4gICAgaWYgKGI2NCkge1xuICAgICAgICBpZiAodHlwZW9mIGp3cy5wYXlsb2FkICE9PSAnc3RyaW5nJykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBQYXlsb2FkIG11c3QgYmUgYSBzdHJpbmcnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBlbHNlIGlmICh0eXBlb2YgandzLnBheWxvYWQgIT09ICdzdHJpbmcnICYmICEoandzLnBheWxvYWQgaW5zdGFuY2VvZiBVaW50OEFycmF5KSkge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFBheWxvYWQgbXVzdCBiZSBhIHN0cmluZyBvciBhbiBVaW50OEFycmF5IGluc3RhbmNlJyk7XG4gICAgfVxuICAgIGxldCByZXNvbHZlZEtleSA9IGZhbHNlO1xuICAgIGlmICh0eXBlb2Yga2V5ID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgIGtleSA9IGF3YWl0IGtleShwYXJzZWRQcm90LCBqd3MpO1xuICAgICAgICByZXNvbHZlZEtleSA9IHRydWU7XG4gICAgfVxuICAgIGNoZWNrS2V5VHlwZShhbGcsIGtleSwgJ3ZlcmlmeScpO1xuICAgIGNvbnN0IGRhdGEgPSBjb25jYXQoZW5jb2Rlci5lbmNvZGUoandzLnByb3RlY3RlZCA/PyAnJyksIGVuY29kZXIuZW5jb2RlKCcuJyksIHR5cGVvZiBqd3MucGF5bG9hZCA9PT0gJ3N0cmluZycgPyBlbmNvZGVyLmVuY29kZShqd3MucGF5bG9hZCkgOiBqd3MucGF5bG9hZCk7XG4gICAgbGV0IHNpZ25hdHVyZTtcbiAgICB0cnkge1xuICAgICAgICBzaWduYXR1cmUgPSBiYXNlNjR1cmwoandzLnNpZ25hdHVyZSk7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBzaWduYXR1cmUnKTtcbiAgICB9XG4gICAgY29uc3QgdmVyaWZpZWQgPSBhd2FpdCB2ZXJpZnkoYWxnLCBrZXksIHNpZ25hdHVyZSwgZGF0YSk7XG4gICAgaWYgKCF2ZXJpZmllZCkge1xuICAgICAgICB0aHJvdyBuZXcgSldTU2lnbmF0dXJlVmVyaWZpY2F0aW9uRmFpbGVkKCk7XG4gICAgfVxuICAgIGxldCBwYXlsb2FkO1xuICAgIGlmIChiNjQpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHBheWxvYWQgPSBiYXNlNjR1cmwoandzLnBheWxvYWQpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgcGF5bG9hZCcpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGVsc2UgaWYgKHR5cGVvZiBqd3MucGF5bG9hZCA9PT0gJ3N0cmluZycpIHtcbiAgICAgICAgcGF5bG9hZCA9IGVuY29kZXIuZW5jb2RlKGp3cy5wYXlsb2FkKTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIHBheWxvYWQgPSBqd3MucGF5bG9hZDtcbiAgICB9XG4gICAgY29uc3QgcmVzdWx0ID0geyBwYXlsb2FkIH07XG4gICAgaWYgKGp3cy5wcm90ZWN0ZWQgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICByZXN1bHQucHJvdGVjdGVkSGVhZGVyID0gcGFyc2VkUHJvdDtcbiAgICB9XG4gICAgaWYgKGp3cy5oZWFkZXIgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICByZXN1bHQudW5wcm90ZWN0ZWRIZWFkZXIgPSBqd3MuaGVhZGVyO1xuICAgIH1cbiAgICBpZiAocmVzb2x2ZWRLZXkpIHtcbiAgICAgICAgcmV0dXJuIHsgLi4ucmVzdWx0LCBrZXkgfTtcbiAgICB9XG4gICAgcmV0dXJuIHJlc3VsdDtcbn1cbiIsImltcG9ydCB7IGZsYXR0ZW5lZFZlcmlmeSB9IGZyb20gJy4uL2ZsYXR0ZW5lZC92ZXJpZnkuanMnO1xuaW1wb3J0IHsgSldTSW52YWxpZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IGRlY29kZXIgfSBmcm9tICcuLi8uLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjb21wYWN0VmVyaWZ5KGp3cywga2V5LCBvcHRpb25zKSB7XG4gICAgaWYgKGp3cyBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgandzID0gZGVjb2Rlci5kZWNvZGUoandzKTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBqd3MgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdDb21wYWN0IEpXUyBtdXN0IGJlIGEgc3RyaW5nIG9yIFVpbnQ4QXJyYXknKTtcbiAgICB9XG4gICAgY29uc3QgeyAwOiBwcm90ZWN0ZWRIZWFkZXIsIDE6IHBheWxvYWQsIDI6IHNpZ25hdHVyZSwgbGVuZ3RoIH0gPSBqd3Muc3BsaXQoJy4nKTtcbiAgICBpZiAobGVuZ3RoICE9PSAzKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdJbnZhbGlkIENvbXBhY3QgSldTJyk7XG4gICAgfVxuICAgIGNvbnN0IHZlcmlmaWVkID0gYXdhaXQgZmxhdHRlbmVkVmVyaWZ5KHsgcGF5bG9hZCwgcHJvdGVjdGVkOiBwcm90ZWN0ZWRIZWFkZXIsIHNpZ25hdHVyZSB9LCBrZXksIG9wdGlvbnMpO1xuICAgIGNvbnN0IHJlc3VsdCA9IHsgcGF5bG9hZDogdmVyaWZpZWQucGF5bG9hZCwgcHJvdGVjdGVkSGVhZGVyOiB2ZXJpZmllZC5wcm90ZWN0ZWRIZWFkZXIgfTtcbiAgICBpZiAodHlwZW9mIGtleSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICByZXR1cm4geyAuLi5yZXN1bHQsIGtleTogdmVyaWZpZWQua2V5IH07XG4gICAgfVxuICAgIHJldHVybiByZXN1bHQ7XG59XG4iLCJpbXBvcnQgeyBmbGF0dGVuZWRWZXJpZnkgfSBmcm9tICcuLi9mbGF0dGVuZWQvdmVyaWZ5LmpzJztcbmltcG9ydCB7IEpXU0ludmFsaWQsIEpXU1NpZ25hdHVyZVZlcmlmaWNhdGlvbkZhaWxlZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCBpc09iamVjdCBmcm9tICcuLi8uLi9saWIvaXNfb2JqZWN0LmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmFsVmVyaWZ5KGp3cywga2V5LCBvcHRpb25zKSB7XG4gICAgaWYgKCFpc09iamVjdChqd3MpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdHZW5lcmFsIEpXUyBtdXN0IGJlIGFuIG9iamVjdCcpO1xuICAgIH1cbiAgICBpZiAoIUFycmF5LmlzQXJyYXkoandzLnNpZ25hdHVyZXMpIHx8ICFqd3Muc2lnbmF0dXJlcy5ldmVyeShpc09iamVjdCkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBTaWduYXR1cmVzIG1pc3Npbmcgb3IgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgZm9yIChjb25zdCBzaWduYXR1cmUgb2YgandzLnNpZ25hdHVyZXMpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgIHJldHVybiBhd2FpdCBmbGF0dGVuZWRWZXJpZnkoe1xuICAgICAgICAgICAgICAgIGhlYWRlcjogc2lnbmF0dXJlLmhlYWRlcixcbiAgICAgICAgICAgICAgICBwYXlsb2FkOiBqd3MucGF5bG9hZCxcbiAgICAgICAgICAgICAgICBwcm90ZWN0ZWQ6IHNpZ25hdHVyZS5wcm90ZWN0ZWQsXG4gICAgICAgICAgICAgICAgc2lnbmF0dXJlOiBzaWduYXR1cmUuc2lnbmF0dXJlLFxuICAgICAgICAgICAgfSwga2V5LCBvcHRpb25zKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgIH1cbiAgICB9XG4gICAgdGhyb3cgbmV3IEpXU1NpZ25hdHVyZVZlcmlmaWNhdGlvbkZhaWxlZCgpO1xufVxuIiwiaW1wb3J0IHsgRmxhdHRlbmVkRW5jcnlwdCB9IGZyb20gJy4uL2ZsYXR0ZW5lZC9lbmNyeXB0LmpzJztcbmV4cG9ydCBjbGFzcyBDb21wYWN0RW5jcnlwdCB7XG4gICAgY29uc3RydWN0b3IocGxhaW50ZXh0KSB7XG4gICAgICAgIHRoaXMuX2ZsYXR0ZW5lZCA9IG5ldyBGbGF0dGVuZWRFbmNyeXB0KHBsYWludGV4dCk7XG4gICAgfVxuICAgIHNldENvbnRlbnRFbmNyeXB0aW9uS2V5KGNlaykge1xuICAgICAgICB0aGlzLl9mbGF0dGVuZWQuc2V0Q29udGVudEVuY3J5cHRpb25LZXkoY2VrKTtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldEluaXRpYWxpemF0aW9uVmVjdG9yKGl2KSB7XG4gICAgICAgIHRoaXMuX2ZsYXR0ZW5lZC5zZXRJbml0aWFsaXphdGlvblZlY3Rvcihpdik7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIHRoaXMuX2ZsYXR0ZW5lZC5zZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKTtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldEtleU1hbmFnZW1lbnRQYXJhbWV0ZXJzKHBhcmFtZXRlcnMpIHtcbiAgICAgICAgdGhpcy5fZmxhdHRlbmVkLnNldEtleU1hbmFnZW1lbnRQYXJhbWV0ZXJzKHBhcmFtZXRlcnMpO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgYXN5bmMgZW5jcnlwdChrZXksIG9wdGlvbnMpIHtcbiAgICAgICAgY29uc3QgandlID0gYXdhaXQgdGhpcy5fZmxhdHRlbmVkLmVuY3J5cHQoa2V5LCBvcHRpb25zKTtcbiAgICAgICAgcmV0dXJuIFtqd2UucHJvdGVjdGVkLCBqd2UuZW5jcnlwdGVkX2tleSwgandlLml2LCBqd2UuY2lwaGVydGV4dCwgandlLnRhZ10uam9pbignLicpO1xuICAgIH1cbn1cbiIsImltcG9ydCBzdWJ0bGVBbGdvcml0aG0gZnJvbSAnLi9zdWJ0bGVfZHNhLmpzJztcbmltcG9ydCBjcnlwdG8gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IGNoZWNrS2V5TGVuZ3RoIGZyb20gJy4vY2hlY2tfa2V5X2xlbmd0aC5qcyc7XG5pbXBvcnQgZ2V0U2lnbktleSBmcm9tICcuL2dldF9zaWduX3ZlcmlmeV9rZXkuanMnO1xuY29uc3Qgc2lnbiA9IGFzeW5jIChhbGcsIGtleSwgZGF0YSkgPT4ge1xuICAgIGNvbnN0IGNyeXB0b0tleSA9IGF3YWl0IGdldFNpZ25LZXkoYWxnLCBrZXksICdzaWduJyk7XG4gICAgY2hlY2tLZXlMZW5ndGgoYWxnLCBjcnlwdG9LZXkpO1xuICAgIGNvbnN0IHNpZ25hdHVyZSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuc2lnbihzdWJ0bGVBbGdvcml0aG0oYWxnLCBjcnlwdG9LZXkuYWxnb3JpdGhtKSwgY3J5cHRvS2V5LCBkYXRhKTtcbiAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoc2lnbmF0dXJlKTtcbn07XG5leHBvcnQgZGVmYXVsdCBzaWduO1xuIiwiaW1wb3J0IHsgZW5jb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4uLy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmltcG9ydCBzaWduIGZyb20gJy4uLy4uL3J1bnRpbWUvc2lnbi5qcyc7XG5pbXBvcnQgaXNEaXNqb2ludCBmcm9tICcuLi8uLi9saWIvaXNfZGlzam9pbnQuanMnO1xuaW1wb3J0IHsgSldTSW52YWxpZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IGVuY29kZXIsIGRlY29kZXIsIGNvbmNhdCB9IGZyb20gJy4uLy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IGNoZWNrS2V5VHlwZSBmcm9tICcuLi8uLi9saWIvY2hlY2tfa2V5X3R5cGUuanMnO1xuaW1wb3J0IHZhbGlkYXRlQ3JpdCBmcm9tICcuLi8uLi9saWIvdmFsaWRhdGVfY3JpdC5qcyc7XG5leHBvcnQgY2xhc3MgRmxhdHRlbmVkU2lnbiB7XG4gICAgY29uc3RydWN0b3IocGF5bG9hZCkge1xuICAgICAgICBpZiAoIShwYXlsb2FkIGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3BheWxvYWQgbXVzdCBiZSBhbiBpbnN0YW5jZSBvZiBVaW50OEFycmF5Jyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fcGF5bG9hZCA9IHBheWxvYWQ7XG4gICAgfVxuICAgIHNldFByb3RlY3RlZEhlYWRlcihwcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMuX3Byb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0UHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fcHJvdGVjdGVkSGVhZGVyID0gcHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0VW5wcm90ZWN0ZWRIZWFkZXIodW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRVbnByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyID0gdW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBhc3luYyBzaWduKGtleSwgb3B0aW9ucykge1xuICAgICAgICBpZiAoIXRoaXMuX3Byb3RlY3RlZEhlYWRlciAmJiAhdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdlaXRoZXIgc2V0UHJvdGVjdGVkSGVhZGVyIG9yIHNldFVucHJvdGVjdGVkSGVhZGVyIG11c3QgYmUgY2FsbGVkIGJlZm9yZSAjc2lnbigpJyk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKCFpc0Rpc2pvaW50KHRoaXMuX3Byb3RlY3RlZEhlYWRlciwgdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFByb3RlY3RlZCBhbmQgSldTIFVucHJvdGVjdGVkIEhlYWRlciBQYXJhbWV0ZXIgbmFtZXMgbXVzdCBiZSBkaXNqb2ludCcpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IGpvc2VIZWFkZXIgPSB7XG4gICAgICAgICAgICAuLi50aGlzLl9wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICAuLi50aGlzLl91bnByb3RlY3RlZEhlYWRlcixcbiAgICAgICAgfTtcbiAgICAgICAgY29uc3QgZXh0ZW5zaW9ucyA9IHZhbGlkYXRlQ3JpdChKV1NJbnZhbGlkLCBuZXcgTWFwKFtbJ2I2NCcsIHRydWVdXSksIG9wdGlvbnM/LmNyaXQsIHRoaXMuX3Byb3RlY3RlZEhlYWRlciwgam9zZUhlYWRlcik7XG4gICAgICAgIGxldCBiNjQgPSB0cnVlO1xuICAgICAgICBpZiAoZXh0ZW5zaW9ucy5oYXMoJ2I2NCcpKSB7XG4gICAgICAgICAgICBiNjQgPSB0aGlzLl9wcm90ZWN0ZWRIZWFkZXIuYjY0O1xuICAgICAgICAgICAgaWYgKHR5cGVvZiBiNjQgIT09ICdib29sZWFuJykge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdUaGUgXCJiNjRcIiAoYmFzZTY0dXJsLWVuY29kZSBwYXlsb2FkKSBIZWFkZXIgUGFyYW1ldGVyIG11c3QgYmUgYSBib29sZWFuJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgeyBhbGcgfSA9IGpvc2VIZWFkZXI7XG4gICAgICAgIGlmICh0eXBlb2YgYWxnICE9PSAnc3RyaW5nJyB8fCAhYWxnKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFwiYWxnXCIgKEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBtaXNzaW5nIG9yIGludmFsaWQnKTtcbiAgICAgICAgfVxuICAgICAgICBjaGVja0tleVR5cGUoYWxnLCBrZXksICdzaWduJyk7XG4gICAgICAgIGxldCBwYXlsb2FkID0gdGhpcy5fcGF5bG9hZDtcbiAgICAgICAgaWYgKGI2NCkge1xuICAgICAgICAgICAgcGF5bG9hZCA9IGVuY29kZXIuZW5jb2RlKGJhc2U2NHVybChwYXlsb2FkKSk7XG4gICAgICAgIH1cbiAgICAgICAgbGV0IHByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgaWYgKHRoaXMuX3Byb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgcHJvdGVjdGVkSGVhZGVyID0gZW5jb2Rlci5lbmNvZGUoYmFzZTY0dXJsKEpTT04uc3RyaW5naWZ5KHRoaXMuX3Byb3RlY3RlZEhlYWRlcikpKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHByb3RlY3RlZEhlYWRlciA9IGVuY29kZXIuZW5jb2RlKCcnKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBkYXRhID0gY29uY2F0KHByb3RlY3RlZEhlYWRlciwgZW5jb2Rlci5lbmNvZGUoJy4nKSwgcGF5bG9hZCk7XG4gICAgICAgIGNvbnN0IHNpZ25hdHVyZSA9IGF3YWl0IHNpZ24oYWxnLCBrZXksIGRhdGEpO1xuICAgICAgICBjb25zdCBqd3MgPSB7XG4gICAgICAgICAgICBzaWduYXR1cmU6IGJhc2U2NHVybChzaWduYXR1cmUpLFxuICAgICAgICAgICAgcGF5bG9hZDogJycsXG4gICAgICAgIH07XG4gICAgICAgIGlmIChiNjQpIHtcbiAgICAgICAgICAgIGp3cy5wYXlsb2FkID0gZGVjb2Rlci5kZWNvZGUocGF5bG9hZCk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICBqd3MuaGVhZGVyID0gdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuX3Byb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgandzLnByb3RlY3RlZCA9IGRlY29kZXIuZGVjb2RlKHByb3RlY3RlZEhlYWRlcik7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGp3cztcbiAgICB9XG59XG4iLCJpbXBvcnQgeyBGbGF0dGVuZWRTaWduIH0gZnJvbSAnLi4vZmxhdHRlbmVkL3NpZ24uanMnO1xuZXhwb3J0IGNsYXNzIENvbXBhY3RTaWduIHtcbiAgICBjb25zdHJ1Y3RvcihwYXlsb2FkKSB7XG4gICAgICAgIHRoaXMuX2ZsYXR0ZW5lZCA9IG5ldyBGbGF0dGVuZWRTaWduKHBheWxvYWQpO1xuICAgIH1cbiAgICBzZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIHRoaXMuX2ZsYXR0ZW5lZC5zZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKTtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIGFzeW5jIHNpZ24oa2V5LCBvcHRpb25zKSB7XG4gICAgICAgIGNvbnN0IGp3cyA9IGF3YWl0IHRoaXMuX2ZsYXR0ZW5lZC5zaWduKGtleSwgb3B0aW9ucyk7XG4gICAgICAgIGlmIChqd3MucGF5bG9hZCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCd1c2UgdGhlIGZsYXR0ZW5lZCBtb2R1bGUgZm9yIGNyZWF0aW5nIEpXUyB3aXRoIGI2NDogZmFsc2UnKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gYCR7andzLnByb3RlY3RlZH0uJHtqd3MucGF5bG9hZH0uJHtqd3Muc2lnbmF0dXJlfWA7XG4gICAgfVxufVxuIiwiaW1wb3J0IHsgRmxhdHRlbmVkU2lnbiB9IGZyb20gJy4uL2ZsYXR0ZW5lZC9zaWduLmpzJztcbmltcG9ydCB7IEpXU0ludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5jbGFzcyBJbmRpdmlkdWFsU2lnbmF0dXJlIHtcbiAgICBjb25zdHJ1Y3RvcihzaWcsIGtleSwgb3B0aW9ucykge1xuICAgICAgICB0aGlzLnBhcmVudCA9IHNpZztcbiAgICAgICAgdGhpcy5rZXkgPSBrZXk7XG4gICAgICAgIHRoaXMub3B0aW9ucyA9IG9wdGlvbnM7XG4gICAgfVxuICAgIHNldFByb3RlY3RlZEhlYWRlcihwcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgaWYgKHRoaXMucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRQcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLnByb3RlY3RlZEhlYWRlciA9IHByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldFVucHJvdGVjdGVkSGVhZGVyKHVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLnVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRVbnByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMudW5wcm90ZWN0ZWRIZWFkZXIgPSB1bnByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIGFkZFNpZ25hdHVyZSguLi5hcmdzKSB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhcmVudC5hZGRTaWduYXR1cmUoLi4uYXJncyk7XG4gICAgfVxuICAgIHNpZ24oLi4uYXJncykge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXJlbnQuc2lnbiguLi5hcmdzKTtcbiAgICB9XG4gICAgZG9uZSgpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGFyZW50O1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBHZW5lcmFsU2lnbiB7XG4gICAgY29uc3RydWN0b3IocGF5bG9hZCkge1xuICAgICAgICB0aGlzLl9zaWduYXR1cmVzID0gW107XG4gICAgICAgIHRoaXMuX3BheWxvYWQgPSBwYXlsb2FkO1xuICAgIH1cbiAgICBhZGRTaWduYXR1cmUoa2V5LCBvcHRpb25zKSB7XG4gICAgICAgIGNvbnN0IHNpZ25hdHVyZSA9IG5ldyBJbmRpdmlkdWFsU2lnbmF0dXJlKHRoaXMsIGtleSwgb3B0aW9ucyk7XG4gICAgICAgIHRoaXMuX3NpZ25hdHVyZXMucHVzaChzaWduYXR1cmUpO1xuICAgICAgICByZXR1cm4gc2lnbmF0dXJlO1xuICAgIH1cbiAgICBhc3luYyBzaWduKCkge1xuICAgICAgICBpZiAoIXRoaXMuX3NpZ25hdHVyZXMubGVuZ3RoKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnYXQgbGVhc3Qgb25lIHNpZ25hdHVyZSBtdXN0IGJlIGFkZGVkJyk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgandzID0ge1xuICAgICAgICAgICAgc2lnbmF0dXJlczogW10sXG4gICAgICAgICAgICBwYXlsb2FkOiAnJyxcbiAgICAgICAgfTtcbiAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCB0aGlzLl9zaWduYXR1cmVzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBjb25zdCBzaWduYXR1cmUgPSB0aGlzLl9zaWduYXR1cmVzW2ldO1xuICAgICAgICAgICAgY29uc3QgZmxhdHRlbmVkID0gbmV3IEZsYXR0ZW5lZFNpZ24odGhpcy5fcGF5bG9hZCk7XG4gICAgICAgICAgICBmbGF0dGVuZWQuc2V0UHJvdGVjdGVkSGVhZGVyKHNpZ25hdHVyZS5wcm90ZWN0ZWRIZWFkZXIpO1xuICAgICAgICAgICAgZmxhdHRlbmVkLnNldFVucHJvdGVjdGVkSGVhZGVyKHNpZ25hdHVyZS51bnByb3RlY3RlZEhlYWRlcik7XG4gICAgICAgICAgICBjb25zdCB7IHBheWxvYWQsIC4uLnJlc3QgfSA9IGF3YWl0IGZsYXR0ZW5lZC5zaWduKHNpZ25hdHVyZS5rZXksIHNpZ25hdHVyZS5vcHRpb25zKTtcbiAgICAgICAgICAgIGlmIChpID09PSAwKSB7XG4gICAgICAgICAgICAgICAgandzLnBheWxvYWQgPSBwYXlsb2FkO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZSBpZiAoandzLnBheWxvYWQgIT09IHBheWxvYWQpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnaW5jb25zaXN0ZW50IHVzZSBvZiBKV1MgVW5lbmNvZGVkIFBheWxvYWQgKFJGQzc3OTcpJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBqd3Muc2lnbmF0dXJlcy5wdXNoKHJlc3QpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBqd3M7XG4gICAgfVxufVxuIiwiaW1wb3J0ICogYXMgYmFzZTY0dXJsIGZyb20gJy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmV4cG9ydCBjb25zdCBlbmNvZGUgPSBiYXNlNjR1cmwuZW5jb2RlO1xuZXhwb3J0IGNvbnN0IGRlY29kZSA9IGJhc2U2NHVybC5kZWNvZGU7XG4iLCJpbXBvcnQgeyBkZWNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHsgZGVjb2RlciB9IGZyb20gJy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4uL2xpYi9pc19vYmplY3QuanMnO1xuZXhwb3J0IGZ1bmN0aW9uIGRlY29kZVByb3RlY3RlZEhlYWRlcih0b2tlbikge1xuICAgIGxldCBwcm90ZWN0ZWRCNjR1O1xuICAgIGlmICh0eXBlb2YgdG9rZW4gPT09ICdzdHJpbmcnKSB7XG4gICAgICAgIGNvbnN0IHBhcnRzID0gdG9rZW4uc3BsaXQoJy4nKTtcbiAgICAgICAgaWYgKHBhcnRzLmxlbmd0aCA9PT0gMyB8fCBwYXJ0cy5sZW5ndGggPT09IDUpIHtcbiAgICAgICAgICAgIDtcbiAgICAgICAgICAgIFtwcm90ZWN0ZWRCNjR1XSA9IHBhcnRzO1xuICAgICAgICB9XG4gICAgfVxuICAgIGVsc2UgaWYgKHR5cGVvZiB0b2tlbiA9PT0gJ29iamVjdCcgJiYgdG9rZW4pIHtcbiAgICAgICAgaWYgKCdwcm90ZWN0ZWQnIGluIHRva2VuKSB7XG4gICAgICAgICAgICBwcm90ZWN0ZWRCNjR1ID0gdG9rZW4ucHJvdGVjdGVkO1xuICAgICAgICB9XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignVG9rZW4gZG9lcyBub3QgY29udGFpbiBhIFByb3RlY3RlZCBIZWFkZXInKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICB0cnkge1xuICAgICAgICBpZiAodHlwZW9mIHByb3RlY3RlZEI2NHUgIT09ICdzdHJpbmcnIHx8ICFwcm90ZWN0ZWRCNjR1KSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCByZXN1bHQgPSBKU09OLnBhcnNlKGRlY29kZXIuZGVjb2RlKGJhc2U2NHVybChwcm90ZWN0ZWRCNjR1KSkpO1xuICAgICAgICBpZiAoIWlzT2JqZWN0KHJlc3VsdCkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcigpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignSW52YWxpZCBUb2tlbiBvciBQcm90ZWN0ZWQgSGVhZGVyIGZvcm1hdHRpbmcnKTtcbiAgICB9XG59XG4iLCJpbXBvcnQgY3J5cHRvIGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgcmFuZG9tIGZyb20gJy4vcmFuZG9tLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZVNlY3JldChhbGcsIG9wdGlvbnMpIHtcbiAgICBsZXQgbGVuZ3RoO1xuICAgIGxldCBhbGdvcml0aG07XG4gICAgbGV0IGtleVVzYWdlcztcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdIUzI1Nic6XG4gICAgICAgIGNhc2UgJ0hTMzg0JzpcbiAgICAgICAgY2FzZSAnSFM1MTInOlxuICAgICAgICAgICAgbGVuZ3RoID0gcGFyc2VJbnQoYWxnLnNsaWNlKC0zKSwgMTApO1xuICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnSE1BQycsIGhhc2g6IGBTSEEtJHtsZW5ndGh9YCwgbGVuZ3RoIH07XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3NpZ24nLCAndmVyaWZ5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnQTEyOENCQy1IUzI1Nic6XG4gICAgICAgIGNhc2UgJ0ExOTJDQkMtSFMzODQnOlxuICAgICAgICBjYXNlICdBMjU2Q0JDLUhTNTEyJzpcbiAgICAgICAgICAgIGxlbmd0aCA9IHBhcnNlSW50KGFsZy5zbGljZSgtMyksIDEwKTtcbiAgICAgICAgICAgIHJldHVybiByYW5kb20obmV3IFVpbnQ4QXJyYXkobGVuZ3RoID4+IDMpKTtcbiAgICAgICAgY2FzZSAnQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnQTE5MktXJzpcbiAgICAgICAgY2FzZSAnQTI1NktXJzpcbiAgICAgICAgICAgIGxlbmd0aCA9IHBhcnNlSW50KGFsZy5zbGljZSgxLCA0KSwgMTApO1xuICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnQUVTLUtXJywgbGVuZ3RoIH07XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3dyYXBLZXknLCAndW53cmFwS2V5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnQTEyOEdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTE5MkdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTEyOEdDTSc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ00nOlxuICAgICAgICBjYXNlICdBMjU2R0NNJzpcbiAgICAgICAgICAgIGxlbmd0aCA9IHBhcnNlSW50KGFsZy5zbGljZSgxLCA0KSwgMTApO1xuICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnQUVTLUdDTScsIGxlbmd0aCB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydlbmNyeXB0JywgJ2RlY3J5cHQnXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgSldLIFwiYWxnXCIgKEFsZ29yaXRobSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgfVxuICAgIHJldHVybiBjcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KGFsZ29yaXRobSwgb3B0aW9ucz8uZXh0cmFjdGFibGUgPz8gZmFsc2UsIGtleVVzYWdlcyk7XG59XG5mdW5jdGlvbiBnZXRNb2R1bHVzTGVuZ3RoT3B0aW9uKG9wdGlvbnMpIHtcbiAgICBjb25zdCBtb2R1bHVzTGVuZ3RoID0gb3B0aW9ucz8ubW9kdWx1c0xlbmd0aCA/PyAyMDQ4O1xuICAgIGlmICh0eXBlb2YgbW9kdWx1c0xlbmd0aCAhPT0gJ251bWJlcicgfHwgbW9kdWx1c0xlbmd0aCA8IDIwNDgpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgbW9kdWx1c0xlbmd0aCBvcHRpb24gcHJvdmlkZWQsIDIwNDggYml0cyBvciBsYXJnZXIga2V5cyBtdXN0IGJlIHVzZWQnKTtcbiAgICB9XG4gICAgcmV0dXJuIG1vZHVsdXNMZW5ndGg7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhdGVLZXlQYWlyKGFsZywgb3B0aW9ucykge1xuICAgIGxldCBhbGdvcml0aG07XG4gICAgbGV0IGtleVVzYWdlcztcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdQUzI1Nic6XG4gICAgICAgIGNhc2UgJ1BTMzg0JzpcbiAgICAgICAgY2FzZSAnUFM1MTInOlxuICAgICAgICAgICAgYWxnb3JpdGhtID0ge1xuICAgICAgICAgICAgICAgIG5hbWU6ICdSU0EtUFNTJyxcbiAgICAgICAgICAgICAgICBoYXNoOiBgU0hBLSR7YWxnLnNsaWNlKC0zKX1gLFxuICAgICAgICAgICAgICAgIHB1YmxpY0V4cG9uZW50OiBuZXcgVWludDhBcnJheShbMHgwMSwgMHgwMCwgMHgwMV0pLFxuICAgICAgICAgICAgICAgIG1vZHVsdXNMZW5ndGg6IGdldE1vZHVsdXNMZW5ndGhPcHRpb24ob3B0aW9ucyksXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydzaWduJywgJ3ZlcmlmeSddO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ1JTMjU2JzpcbiAgICAgICAgY2FzZSAnUlMzODQnOlxuICAgICAgICBjYXNlICdSUzUxMic6XG4gICAgICAgICAgICBhbGdvcml0aG0gPSB7XG4gICAgICAgICAgICAgICAgbmFtZTogJ1JTQVNTQS1QS0NTMS12MV81JyxcbiAgICAgICAgICAgICAgICBoYXNoOiBgU0hBLSR7YWxnLnNsaWNlKC0zKX1gLFxuICAgICAgICAgICAgICAgIHB1YmxpY0V4cG9uZW50OiBuZXcgVWludDhBcnJheShbMHgwMSwgMHgwMCwgMHgwMV0pLFxuICAgICAgICAgICAgICAgIG1vZHVsdXNMZW5ndGg6IGdldE1vZHVsdXNMZW5ndGhPcHRpb24ob3B0aW9ucyksXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydzaWduJywgJ3ZlcmlmeSddO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQJzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMjU2JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMzg0JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtNTEyJzpcbiAgICAgICAgICAgIGFsZ29yaXRobSA9IHtcbiAgICAgICAgICAgICAgICBuYW1lOiAnUlNBLU9BRVAnLFxuICAgICAgICAgICAgICAgIGhhc2g6IGBTSEEtJHtwYXJzZUludChhbGcuc2xpY2UoLTMpLCAxMCkgfHwgMX1gLFxuICAgICAgICAgICAgICAgIHB1YmxpY0V4cG9uZW50OiBuZXcgVWludDhBcnJheShbMHgwMSwgMHgwMCwgMHgwMV0pLFxuICAgICAgICAgICAgICAgIG1vZHVsdXNMZW5ndGg6IGdldE1vZHVsdXNMZW5ndGhPcHRpb24ob3B0aW9ucyksXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydkZWNyeXB0JywgJ3Vud3JhcEtleScsICdlbmNyeXB0JywgJ3dyYXBLZXknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdFUzI1Nic6XG4gICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RTQScsIG5hbWVkQ3VydmU6ICdQLTI1NicgfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnc2lnbicsICd2ZXJpZnknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdFUzM4NCc6XG4gICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RTQScsIG5hbWVkQ3VydmU6ICdQLTM4NCcgfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnc2lnbicsICd2ZXJpZnknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdFUzUxMic6XG4gICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RTQScsIG5hbWVkQ3VydmU6ICdQLTUyMScgfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnc2lnbicsICd2ZXJpZnknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdFZERTQSc6IHtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnc2lnbicsICd2ZXJpZnknXTtcbiAgICAgICAgICAgIGNvbnN0IGNydiA9IG9wdGlvbnM/LmNydiA/PyAnRWQyNTUxOSc7XG4gICAgICAgICAgICBzd2l0Y2ggKGNydikge1xuICAgICAgICAgICAgICAgIGNhc2UgJ0VkMjU1MTknOlxuICAgICAgICAgICAgICAgIGNhc2UgJ0VkNDQ4JzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiBjcnYgfTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgY3J2IG9wdGlvbiBwcm92aWRlZCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnRUNESC1FUyc6XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMTkyS1cnOlxuICAgICAgICBjYXNlICdFQ0RILUVTK0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnZGVyaXZlS2V5JywgJ2Rlcml2ZUJpdHMnXTtcbiAgICAgICAgICAgIGNvbnN0IGNydiA9IG9wdGlvbnM/LmNydiA/PyAnUC0yNTYnO1xuICAgICAgICAgICAgc3dpdGNoIChjcnYpIHtcbiAgICAgICAgICAgICAgICBjYXNlICdQLTI1Nic6XG4gICAgICAgICAgICAgICAgY2FzZSAnUC0zODQnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1AtNTIxJzoge1xuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RIJywgbmFtZWRDdXJ2ZTogY3J2IH07XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBjYXNlICdYMjU1MTknOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1g0NDgnOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6IGNydiB9O1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBjcnYgb3B0aW9uIHByb3ZpZGVkLCBzdXBwb3J0ZWQgdmFsdWVzIGFyZSBQLTI1NiwgUC0zODQsIFAtNTIxLCBYMjU1MTksIGFuZCBYNDQ4Jyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgSldLIFwiYWxnXCIgKEFsZ29yaXRobSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgfVxuICAgIHJldHVybiAoY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleShhbGdvcml0aG0sIG9wdGlvbnM/LmV4dHJhY3RhYmxlID8/IGZhbHNlLCBrZXlVc2FnZXMpKTtcbn1cbiIsImltcG9ydCB7IGdlbmVyYXRlS2V5UGFpciBhcyBnZW5lcmF0ZSB9IGZyb20gJy4uL3J1bnRpbWUvZ2VuZXJhdGUuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdlbmVyYXRlS2V5UGFpcihhbGcsIG9wdGlvbnMpIHtcbiAgICByZXR1cm4gZ2VuZXJhdGUoYWxnLCBvcHRpb25zKTtcbn1cbiIsImltcG9ydCB7IGdlbmVyYXRlU2VjcmV0IGFzIGdlbmVyYXRlIH0gZnJvbSAnLi4vcnVudGltZS9nZW5lcmF0ZS5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhdGVTZWNyZXQoYWxnLCBvcHRpb25zKSB7XG4gICAgcmV0dXJuIGdlbmVyYXRlKGFsZywgb3B0aW9ucyk7XG59XG4iLCIvLyBPbmUgY29uc2lzdGVudCBhbGdvcml0aG0gZm9yIGVhY2ggZmFtaWx5LlxuLy8gaHR0cHM6Ly9kYXRhdHJhY2tlci5pZXRmLm9yZy9kb2MvaHRtbC9yZmM3NTE4XG5cbmV4cG9ydCBjb25zdCBzaWduaW5nTmFtZSA9ICdFQ0RTQSc7XG5leHBvcnQgY29uc3Qgc2lnbmluZ0N1cnZlID0gJ1AtMzg0JztcbmV4cG9ydCBjb25zdCBzaWduaW5nQWxnb3JpdGhtID0gJ0VTMzg0JztcblxuZXhwb3J0IGNvbnN0IGVuY3J5cHRpbmdOYW1lID0gJ1JTQS1PQUVQJztcbmV4cG9ydCBjb25zdCBoYXNoTGVuZ3RoID0gMjU2O1xuZXhwb3J0IGNvbnN0IGhhc2hOYW1lID0gJ1NIQS0yNTYnO1xuZXhwb3J0IGNvbnN0IG1vZHVsdXNMZW5ndGggPSA0MDk2OyAvLyBwYW52YSBKT1NFIGxpYnJhcnkgZGVmYXVsdCBpcyAyMDQ4XG5leHBvcnQgY29uc3QgZW5jcnlwdGluZ0FsZ29yaXRobSA9ICdSU0EtT0FFUC0yNTYnO1xuXG5leHBvcnQgY29uc3Qgc3ltbWV0cmljTmFtZSA9ICdBRVMtR0NNJztcbmV4cG9ydCBjb25zdCBzeW1tZXRyaWNBbGdvcml0aG0gPSAnQTI1NkdDTSc7XG5leHBvcnQgY29uc3Qgc3ltbWV0cmljV3JhcCA9ICdBMjU2R0NNS1cnO1xuZXhwb3J0IGNvbnN0IHNlY3JldEFsZ29yaXRobSA9ICdQQkVTMi1IUzUxMitBMjU2S1cnO1xuXG5leHBvcnQgY29uc3QgZXh0cmFjdGFibGUgPSB0cnVlOyAgLy8gYWx3YXlzIHdyYXBwZWRcblxuIiwiaW1wb3J0IHtleHRyYWN0YWJsZSwgc2lnbmluZ05hbWUsIHNpZ25pbmdDdXJ2ZSwgc3ltbWV0cmljTmFtZSwgaGFzaExlbmd0aH0gZnJvbSBcIi4vYWxnb3JpdGhtcy5tanNcIjtcblxuZXhwb3J0IGZ1bmN0aW9uIGRpZ2VzdChoYXNoTmFtZSwgYnVmZmVyKSB7XG4gIHJldHVybiBjcnlwdG8uc3VidGxlLmRpZ2VzdChoYXNoTmFtZSwgYnVmZmVyKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGV4cG9ydFJhd0tleShrZXkpIHtcbiAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCdyYXcnLCBrZXkpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gaW1wb3J0UmF3S2V5KGFycmF5QnVmZmVyKSB7XG4gIGNvbnN0IGFsZ29yaXRobSA9IHtuYW1lOiBzaWduaW5nTmFtZSwgbmFtZWRDdXJ2ZTogc2lnbmluZ0N1cnZlfTtcbiAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBhcnJheUJ1ZmZlciwgYWxnb3JpdGhtLCBleHRyYWN0YWJsZSwgWyd2ZXJpZnknXSk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBpbXBvcnRTZWNyZXQoYnl0ZUFycmF5KSB7XG4gIGNvbnN0IGFsZ29yaXRobSA9IHtuYW1lOiBzeW1tZXRyaWNOYW1lLCBsZW5ndGg6IGhhc2hMZW5ndGh9O1xuICByZXR1cm4gY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGJ5dGVBcnJheSwgYWxnb3JpdGhtLCB0cnVlLCBbJ2VuY3J5cHQnLCAnZGVjcnlwdCddKVxufVxuIiwiaW1wb3J0ICogYXMgSk9TRSBmcm9tIFwiam9zZVwiO1xuaW1wb3J0IHtkaWdlc3QsIGV4cG9ydFJhd0tleSwgaW1wb3J0UmF3S2V5LCBpbXBvcnRTZWNyZXR9IGZyb20gXCIjcmF3XCI7XG5pbXBvcnQge2V4dHJhY3RhYmxlLCBzaWduaW5nTmFtZSwgc2lnbmluZ0N1cnZlLCBzaWduaW5nQWxnb3JpdGhtLCBlbmNyeXB0aW5nTmFtZSwgaGFzaExlbmd0aCwgaGFzaE5hbWUsIG1vZHVsdXNMZW5ndGgsIGVuY3J5cHRpbmdBbGdvcml0aG0sIHN5bW1ldHJpY05hbWUsIHN5bW1ldHJpY0FsZ29yaXRobX0gZnJvbSBcIi4vYWxnb3JpdGhtcy5tanNcIjtcblxuY29uc3QgS3J5cHRvID0ge1xuICAvLyBBbiBpbmhlcml0YWJsZSBzaW5nbGV0b24gZm9yIGNvbXBhY3QgSk9TRSBvcGVyYXRpb25zLlxuICAvLyBTZWUgaHR0cHM6Ly9raWxyb3ktY29kZS5naXRodWIuaW8vZGlzdHJpYnV0ZWQtc2VjdXJpdHkvZG9jcy9pbXBsZW1lbnRhdGlvbi5odG1sI3dyYXBwaW5nLXN1YnRsZWtyeXB0b1xuICBkZWNvZGVQcm90ZWN0ZWRIZWFkZXI6IEpPU0UuZGVjb2RlUHJvdGVjdGVkSGVhZGVyLFxuICBpc0VtcHR5SldTUGF5bG9hZChjb21wYWN0SldTKSB7IC8vIGFyZyBpcyBhIHN0cmluZ1xuICAgIHJldHVybiAhY29tcGFjdEpXUy5zcGxpdCgnLicpWzFdO1xuICB9LFxuXG4gIC8vIFRoZSBjdHkgY2FuIGJlIHNwZWNpZmllZCBpbiBlbmNyeXB0L3NpZ24sIGJ1dCBkZWZhdWx0cyB0byBhIGdvb2QgZ3Vlc3MuXG4gIC8vIFRoZSBjdHkgY2FuIGJlIHNwZWNpZmllZCBpbiBkZWNyeXB0L3ZlcmlmeSwgYnV0IGRlZmF1bHRzIHRvIHdoYXQgaXMgc3BlY2lmaWVkIGluIHRoZSBwcm90ZWN0ZWQgaGVhZGVyLlxuICBpbnB1dEJ1ZmZlcihkYXRhLCBoZWFkZXIpIHsgLy8gQW5zd2VycyBhIGJ1ZmZlciB2aWV3IG9mIGRhdGEgYW5kLCBpZiBuZWNlc3NhcnkgdG8gY29udmVydCwgYmFzaGVzIGN0eSBvZiBoZWFkZXIuXG4gICAgaWYgKEFycmF5QnVmZmVyLmlzVmlldyhkYXRhKSAmJiAhaGVhZGVyLmN0eSkgcmV0dXJuIGRhdGE7XG4gICAgbGV0IGdpdmVuQ3R5ID0gaGVhZGVyLmN0eSB8fCAnJztcbiAgICBpZiAoZ2l2ZW5DdHkuaW5jbHVkZXMoJ3RleHQnKSB8fCAoJ3N0cmluZycgPT09IHR5cGVvZiBkYXRhKSkge1xuICAgICAgaGVhZGVyLmN0eSA9IGdpdmVuQ3R5IHx8ICd0ZXh0L3BsYWluJztcbiAgICB9IGVsc2Uge1xuICAgICAgaGVhZGVyLmN0eSA9IGdpdmVuQ3R5IHx8ICdqc29uJzsgLy8gSldTIHJlY29tbWVuZHMgbGVhdmluZyBvZmYgdGhlIGxlYWRpbmcgJ2FwcGxpY2F0aW9uLycuXG4gICAgICBkYXRhID0gSlNPTi5zdHJpbmdpZnkoZGF0YSk7IC8vIE5vdGUgdGhhdCBuZXcgU3RyaW5nKFwic29tZXRoaW5nXCIpIHdpbGwgcGFzcyB0aGlzIHdheS5cbiAgICB9XG4gICAgcmV0dXJuIG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZShkYXRhKTtcbiAgfSxcbiAgcmVjb3ZlckRhdGFGcm9tQ29udGVudFR5cGUocmVzdWx0LCB7Y3R5ID0gcmVzdWx0Py5wcm90ZWN0ZWRIZWFkZXI/LmN0eX0gPSB7fSkge1xuICAgIC8vIEV4YW1pbmVzIHJlc3VsdD8ucHJvdGVjdGVkSGVhZGVyIGFuZCBiYXNoZXMgaW4gcmVzdWx0LnRleHQgb3IgcmVzdWx0Lmpzb24gaWYgYXBwcm9wcmlhdGUsIHJldHVybmluZyByZXN1bHQuXG4gICAgaWYgKHJlc3VsdCAmJiAhT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHJlc3VsdCwgJ3BheWxvYWQnKSkgcmVzdWx0LnBheWxvYWQgPSByZXN1bHQucGxhaW50ZXh0OyAgLy8gYmVjYXVzZSBKT1NFIHVzZXMgcGxhaW50ZXh0IGZvciBkZWNyeXB0IGFuZCBwYXlsb2FkIGZvciBzaWduLlxuICAgIGlmICghY3R5IHx8ICFyZXN1bHQ/LnBheWxvYWQpIHJldHVybiByZXN1bHQ7IC8vIGVpdGhlciBubyBjdHkgb3Igbm8gcmVzdWx0XG4gICAgcmVzdWx0LnRleHQgPSBuZXcgVGV4dERlY29kZXIoKS5kZWNvZGUocmVzdWx0LnBheWxvYWQpO1xuICAgIGlmIChjdHkuaW5jbHVkZXMoJ2pzb24nKSkgcmVzdWx0Lmpzb24gPSBKU09OLnBhcnNlKHJlc3VsdC50ZXh0KTtcbiAgICByZXR1cm4gcmVzdWx0O1xuICB9LFxuXG4gIC8vIFNpZ24vVmVyaWZ5XG4gIGdlbmVyYXRlU2lnbmluZ0tleSgpIHsgLy8gUHJvbWlzZSB7cHJpdmF0ZUtleSwgcHVibGljS2V5fSBpbiBvdXIgc3RhbmRhcmQgc2lnbmluZyBhbGdvcml0aG0uXG4gICAgcmV0dXJuIEpPU0UuZ2VuZXJhdGVLZXlQYWlyKHNpZ25pbmdBbGdvcml0aG0sIHtleHRyYWN0YWJsZX0pO1xuICB9LFxuICBhc3luYyBzaWduKHByaXZhdGVLZXksIG1lc3NhZ2UsIGhlYWRlcnMgPSB7fSkgeyAvLyBQcm9taXNlIGEgY29tcGFjdCBKV1Mgc3RyaW5nLiBBY2NlcHRzIGhlYWRlcnMgdG8gYmUgcHJvdGVjdGVkLlxuICAgIGxldCBoZWFkZXIgPSB7YWxnOiBzaWduaW5nQWxnb3JpdGhtLCAuLi5oZWFkZXJzfSxcbiAgICAgICAgaW5wdXRCdWZmZXIgPSB0aGlzLmlucHV0QnVmZmVyKG1lc3NhZ2UsIGhlYWRlcik7XG4gICAgcmV0dXJuIG5ldyBKT1NFLkNvbXBhY3RTaWduKGlucHV0QnVmZmVyKS5zZXRQcm90ZWN0ZWRIZWFkZXIoaGVhZGVyKS5zaWduKHByaXZhdGVLZXkpO1xuICB9LFxuICBhc3luYyB2ZXJpZnkocHVibGljS2V5LCBzaWduYXR1cmUsIG9wdGlvbnMpIHsgLy8gUHJvbWlzZSB7cGF5bG9hZCwgdGV4dCwganNvbn0sIHdoZXJlIHRleHQgYW5kIGpzb24gYXJlIG9ubHkgZGVmaW5lZCB3aGVuIGFwcHJvcHJpYXRlLlxuICAgIGxldCByZXN1bHQgPSBhd2FpdCBKT1NFLmNvbXBhY3RWZXJpZnkoc2lnbmF0dXJlLCBwdWJsaWNLZXkpLmNhdGNoKCgpID0+IHVuZGVmaW5lZCk7XG4gICAgcmV0dXJuIHRoaXMucmVjb3ZlckRhdGFGcm9tQ29udGVudFR5cGUocmVzdWx0LCBvcHRpb25zKTtcbiAgfSxcblxuICAvLyBFbmNyeXB0L0RlY3J5cHRcbiAgZ2VuZXJhdGVFbmNyeXB0aW5nS2V5KCkgeyAvLyBQcm9taXNlIHtwcml2YXRlS2V5LCBwdWJsaWNLZXl9IGluIG91ciBzdGFuZGFyZCBlbmNyeXB0aW9uIGFsZ29yaXRobS5cbiAgICByZXR1cm4gSk9TRS5nZW5lcmF0ZUtleVBhaXIoZW5jcnlwdGluZ0FsZ29yaXRobSwge2V4dHJhY3RhYmxlLCBtb2R1bHVzTGVuZ3RofSk7XG4gIH0sXG4gIGFzeW5jIGVuY3J5cHQoa2V5LCBtZXNzYWdlLCBoZWFkZXJzID0ge30pIHsgLy8gUHJvbWlzZSBhIGNvbXBhY3QgSldFIHN0cmluZy4gQWNjZXB0cyBoZWFkZXJzIHRvIGJlIHByb3RlY3RlZC5cbiAgICBsZXQgYWxnID0gdGhpcy5pc1N5bW1ldHJpYyhrZXkpID8gJ2RpcicgOiBlbmNyeXB0aW5nQWxnb3JpdGhtLFxuICAgICAgICBoZWFkZXIgPSB7YWxnLCBlbmM6IHN5bW1ldHJpY0FsZ29yaXRobSwgLi4uaGVhZGVyc30sXG4gICAgICAgIGlucHV0QnVmZmVyID0gdGhpcy5pbnB1dEJ1ZmZlcihtZXNzYWdlLCBoZWFkZXIpLFxuICAgICAgICBzZWNyZXQgPSB0aGlzLmtleVNlY3JldChrZXkpO1xuICAgIHJldHVybiBuZXcgSk9TRS5Db21wYWN0RW5jcnlwdChpbnB1dEJ1ZmZlcikuc2V0UHJvdGVjdGVkSGVhZGVyKGhlYWRlcikuZW5jcnlwdChzZWNyZXQpO1xuICB9LFxuICBhc3luYyBkZWNyeXB0KGtleSwgZW5jcnlwdGVkLCBvcHRpb25zID0ge30pIHsgLy8gUHJvbWlzZSB7cGF5bG9hZCwgdGV4dCwganNvbn0sIHdoZXJlIHRleHQgYW5kIGpzb24gYXJlIG9ubHkgZGVmaW5lZCB3aGVuIGFwcHJvcHJpYXRlLlxuICAgIGxldCBzZWNyZXQgPSB0aGlzLmtleVNlY3JldChrZXkpLFxuICAgICAgICByZXN1bHQgPSBhd2FpdCBKT1NFLmNvbXBhY3REZWNyeXB0KGVuY3J5cHRlZCwgc2VjcmV0KTtcbiAgICB0aGlzLnJlY292ZXJEYXRhRnJvbUNvbnRlbnRUeXBlKHJlc3VsdCwgb3B0aW9ucyk7XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfSxcbiAgYXN5bmMgZ2VuZXJhdGVTZWNyZXRLZXkodGV4dCkgeyAvLyBKT1NFIHVzZXMgYSBkaWdlc3QgZm9yIFBCRVMsIGJ1dCBtYWtlIGl0IHJlY29nbml6YWJsZSBhcyBhIHt0eXBlOiAnc2VjcmV0J30ga2V5LlxuICAgIGxldCBidWZmZXIgPSBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUodGV4dCksXG4gICAgICAgIGhhc2ggPSBhd2FpdCBkaWdlc3QoaGFzaE5hbWUsIGJ1ZmZlcik7XG4gICAgcmV0dXJuIHt0eXBlOiAnc2VjcmV0JywgdGV4dDogbmV3IFVpbnQ4QXJyYXkoaGFzaCl9O1xuICB9LFxuICBnZW5lcmF0ZVN5bW1ldHJpY0tleSh0ZXh0KSB7IC8vIFByb21pc2UgYSBrZXkgZm9yIHN5bW1ldHJpYyBlbmNyeXB0aW9uLlxuICAgIGlmICh0ZXh0KSByZXR1cm4gdGhpcy5nZW5lcmF0ZVNlY3JldEtleSh0ZXh0KTsgLy8gUEJFU1xuICAgIHJldHVybiBKT1NFLmdlbmVyYXRlU2VjcmV0KHN5bW1ldHJpY0FsZ29yaXRobSwge2V4dHJhY3RhYmxlfSk7IC8vIEFFU1xuICB9LFxuICBpc1N5bW1ldHJpYyhrZXkpIHsgLy8gRWl0aGVyIEFFUyBvciBQQkVTLCBidXQgbm90IHB1YmxpY0tleSBvciBwcml2YXRlS2V5LlxuICAgIHJldHVybiBrZXkudHlwZSA9PT0gJ3NlY3JldCc7XG4gIH0sXG4gIGtleVNlY3JldChrZXkpIHsgLy8gUmV0dXJuIHdoYXQgaXMgYWN0dWFsbHkgdXNlZCBhcyBpbnB1dCBpbiBKT1NFIGxpYnJhcnkuXG4gICAgaWYgKGtleS50ZXh0KSByZXR1cm4ga2V5LnRleHQ7XG4gICAgcmV0dXJuIGtleTtcbiAgfSxcblxuICAvLyBFeHBvcnQvSW1wb3J0XG4gIGFzeW5jIGV4cG9ydFJhdyhrZXkpIHsgLy8gYmFzZTY0dXJsIGZvciBwdWJsaWMgdmVyZmljYXRpb24ga2V5c1xuICAgIGxldCBhcnJheUJ1ZmZlciA9IGF3YWl0IGV4cG9ydFJhd0tleShrZXkpO1xuICAgIHJldHVybiBKT1NFLmJhc2U2NHVybC5lbmNvZGUobmV3IFVpbnQ4QXJyYXkoYXJyYXlCdWZmZXIpKTtcbiAgfSxcbiAgYXN5bmMgaW1wb3J0UmF3KHN0cmluZykgeyAvLyBQcm9taXNlIHRoZSB2ZXJpZmljYXRpb24ga2V5IGZyb20gYmFzZTY0dXJsXG4gICAgbGV0IGFycmF5QnVmZmVyID0gSk9TRS5iYXNlNjR1cmwuZGVjb2RlKHN0cmluZyk7XG4gICAgcmV0dXJuIGltcG9ydFJhd0tleShhcnJheUJ1ZmZlcik7XG4gIH0sXG4gIGFzeW5jIGV4cG9ydEpXSyhrZXkpIHsgLy8gUHJvbWlzZSBKV0sgb2JqZWN0LCB3aXRoIGFsZyBpbmNsdWRlZC5cbiAgICBsZXQgZXhwb3J0ZWQgPSBhd2FpdCBKT1NFLmV4cG9ydEpXSyhrZXkpLFxuICAgICAgICBhbGcgPSBrZXkuYWxnb3JpdGhtOyAvLyBKT1NFIGxpYnJhcnkgZ2l2ZXMgYWxnb3JpdGhtLCBidXQgbm90IGFsZyB0aGF0IGlzIG5lZWRlZCBmb3IgaW1wb3J0LlxuICAgIGlmIChhbGcpIHsgLy8gc3VidGxlLmNyeXB0byB1bmRlcmx5aW5nIGtleXNcbiAgICAgIGlmIChhbGcubmFtZSA9PT0gc2lnbmluZ05hbWUgJiYgYWxnLm5hbWVkQ3VydmUgPT09IHNpZ25pbmdDdXJ2ZSkgZXhwb3J0ZWQuYWxnID0gc2lnbmluZ0FsZ29yaXRobTtcbiAgICAgIGVsc2UgaWYgKGFsZy5uYW1lID09PSBlbmNyeXB0aW5nTmFtZSAmJiBhbGcuaGFzaC5uYW1lID09PSBoYXNoTmFtZSkgZXhwb3J0ZWQuYWxnID0gZW5jcnlwdGluZ0FsZ29yaXRobTtcbiAgICAgIGVsc2UgaWYgKGFsZy5uYW1lID09PSBzeW1tZXRyaWNOYW1lICYmIGFsZy5sZW5ndGggPT09IGhhc2hMZW5ndGgpIGV4cG9ydGVkLmFsZyA9IHN5bW1ldHJpY0FsZ29yaXRobTtcbiAgICB9IGVsc2Ugc3dpdGNoIChleHBvcnRlZC5rdHkpIHsgLy8gSk9TRSBvbiBOb2RlSlMgdXNlZCBub2RlOmNyeXB0byBrZXlzLCB3aGljaCBkbyBub3QgZXhwb3NlIHRoZSBwcmVjaXNlIGFsZ29yaXRobVxuICAgICAgY2FzZSAnRUMnOiBleHBvcnRlZC5hbGcgPSBzaWduaW5nQWxnb3JpdGhtOyBicmVhaztcbiAgICAgIGNhc2UgJ1JTQSc6IGV4cG9ydGVkLmFsZyA9IGVuY3J5cHRpbmdBbGdvcml0aG07IGJyZWFrO1xuICAgICAgY2FzZSAnb2N0JzogZXhwb3J0ZWQuYWxnID0gc3ltbWV0cmljQWxnb3JpdGhtOyBicmVhaztcbiAgICB9XG4gICAgcmV0dXJuIGV4cG9ydGVkO1xuICB9LFxuICBhc3luYyBpbXBvcnRKV0soandrKSB7IC8vIFByb21pc2UgYSBrZXkgb2JqZWN0XG4gICAgandrID0ge2V4dDogdHJ1ZSwgLi4uandrfTsgLy8gV2UgbmVlZCB0aGUgcmVzdWx0IHRvIGJlIGJlIGFibGUgdG8gZ2VuZXJhdGUgYSBuZXcgSldLIChlLmcuLCBvbiBjaGFuZ2VNZW1iZXJzaGlwKVxuICAgIGxldCBpbXBvcnRlZCA9IGF3YWl0IEpPU0UuaW1wb3J0SldLKGp3ayk7XG4gICAgaWYgKGltcG9ydGVkIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgLy8gV2UgZGVwZW5kIGFuIHJldHVybmluZyBhbiBhY3R1YWwga2V5LCBidXQgdGhlIEpPU0UgbGlicmFyeSB3ZSB1c2VcbiAgICAgIC8vIHdpbGwgYWJvdmUgcHJvZHVjZSB0aGUgcmF3IFVpbnQ4QXJyYXkgaWYgdGhlIGp3ayBpcyBmcm9tIGEgc2VjcmV0LlxuICAgICAgaW1wb3J0ZWQgPSBhd2FpdCBpbXBvcnRTZWNyZXQoaW1wb3J0ZWQpO1xuICAgIH1cbiAgICByZXR1cm4gaW1wb3J0ZWQ7XG4gIH0sXG5cbiAgYXN5bmMgd3JhcEtleShrZXksIHdyYXBwaW5nS2V5LCBoZWFkZXJzID0ge30pIHsgLy8gUHJvbWlzZSBhIEpXRSBmcm9tIHRoZSBwdWJsaWMgd3JhcHBpbmdLZXlcbiAgICBsZXQgZXhwb3J0ZWQgPSBhd2FpdCB0aGlzLmV4cG9ydEpXSyhrZXkpO1xuICAgIHJldHVybiB0aGlzLmVuY3J5cHQod3JhcHBpbmdLZXksIGV4cG9ydGVkLCBoZWFkZXJzKTtcbiAgfSxcbiAgYXN5bmMgdW53cmFwS2V5KHdyYXBwZWRLZXksIHVud3JhcHBpbmdLZXkpIHsgLy8gUHJvbWlzZSB0aGUga2V5IHVubG9ja2VkIGJ5IHRoZSBwcml2YXRlIHVud3JhcHBpbmdLZXkuXG4gICAgbGV0IGRlY3J5cHRlZCA9IGF3YWl0IHRoaXMuZGVjcnlwdCh1bndyYXBwaW5nS2V5LCB3cmFwcGVkS2V5KTtcbiAgICByZXR1cm4gdGhpcy5pbXBvcnRKV0soZGVjcnlwdGVkLmpzb24pO1xuICB9XG59XG5cbmV4cG9ydCBkZWZhdWx0IEtyeXB0bztcbi8qXG5Tb21lIHVzZWZ1bCBKT1NFIHJlY2lwZXMgZm9yIHBsYXlpbmcgYXJvdW5kLlxuc2sgPSBhd2FpdCBKT1NFLmdlbmVyYXRlS2V5UGFpcignRVMzODQnLCB7ZXh0cmFjdGFibGU6IHRydWV9KVxuand0ID0gYXdhaXQgbmV3IEpPU0UuU2lnbkpXVCgpLnNldFN1YmplY3QoXCJmb29cIikuc2V0UHJvdGVjdGVkSGVhZGVyKHthbGc6J0VTMzg0J30pLnNpZ24oc2sucHJpdmF0ZUtleSlcbmF3YWl0IEpPU0Uuand0VmVyaWZ5KGp3dCwgc2sucHVibGljS2V5KSAvLy5wYXlsb2FkLnN1YlxuXG5tZXNzYWdlID0gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKCdzb21lIG1lc3NhZ2UnKVxuandzID0gYXdhaXQgbmV3IEpPU0UuQ29tcGFjdFNpZ24obWVzc2FnZSkuc2V0UHJvdGVjdGVkSGVhZGVyKHthbGc6J0VTMzg0J30pLnNpZ24oc2sucHJpdmF0ZUtleSkgLy8gT3IgRmxhdHRlbmVkU2lnblxuandzID0gYXdhaXQgbmV3IEpPU0UuR2VuZXJhbFNpZ24obWVzc2FnZSkuYWRkU2lnbmF0dXJlKHNrLnByaXZhdGVLZXkpLnNldFByb3RlY3RlZEhlYWRlcih7YWxnOidFUzM4NCd9KS5zaWduKClcbnZlcmlmaWVkID0gYXdhaXQgSk9TRS5nZW5lcmFsVmVyaWZ5KGp3cywgc2sucHVibGljS2V5KVxub3IgY29tcGFjdFZlcmlmeSBvciBmbGF0dGVuZWRWZXJpZnlcbm5ldyBUZXh0RGVjb2RlcigpLmRlY29kZSh2ZXJpZmllZC5wYXlsb2FkKVxuXG5layA9IGF3YWl0IEpPU0UuZ2VuZXJhdGVLZXlQYWlyKCdSU0EtT0FFUC0yNTYnLCB7ZXh0cmFjdGFibGU6IHRydWV9KVxuandlID0gYXdhaXQgbmV3IEpPU0UuQ29tcGFjdEVuY3J5cHQobWVzc2FnZSkuc2V0UHJvdGVjdGVkSGVhZGVyKHthbGc6ICdSU0EtT0FFUC0yNTYnLCBlbmM6ICdBMjU2R0NNJyB9KS5lbmNyeXB0KGVrLnB1YmxpY0tleSlcbm9yIEZsYXR0ZW5lZEVuY3J5cHQuIEZvciBzeW1tZXRyaWMgc2VjcmV0LCBzcGVjaWZ5IGFsZzonZGlyJy5cbmRlY3J5cHRlZCA9IGF3YWl0IEpPU0UuY29tcGFjdERlY3J5cHQoandlLCBlay5wcml2YXRlS2V5KVxubmV3IFRleHREZWNvZGVyKCkuZGVjb2RlKGRlY3J5cHRlZC5wbGFpbnRleHQpXG5qd2UgPSBhd2FpdCBuZXcgSk9TRS5HZW5lcmFsRW5jcnlwdChtZXNzYWdlKS5zZXRQcm90ZWN0ZWRIZWFkZXIoe2FsZzogJ1JTQS1PQUVQLTI1NicsIGVuYzogJ0EyNTZHQ00nIH0pLmFkZFJlY2lwaWVudChlay5wdWJsaWNLZXkpLmVuY3J5cHQoKSAvLyB3aXRoIGFkZGl0aW9uYWwgYWRkUmVjaXBlbnQoKSBhcyBuZWVkZWRcbmRlY3J5cHRlZCA9IGF3YWl0IEpPU0UuZ2VuZXJhbERlY3J5cHQoandlLCBlay5wcml2YXRlS2V5KVxuXG5tYXRlcmlhbCA9IG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZSgnc2VjcmV0Jylcbmp3ZSA9IGF3YWl0IG5ldyBKT1NFLkNvbXBhY3RFbmNyeXB0KG1lc3NhZ2UpLnNldFByb3RlY3RlZEhlYWRlcih7YWxnOiAnUEJFUzItSFM1MTIrQTI1NktXJywgZW5jOiAnQTI1NkdDTScgfSkuZW5jcnlwdChtYXRlcmlhbClcbmRlY3J5cHRlZCA9IGF3YWl0IEpPU0UuY29tcGFjdERlY3J5cHQoandlLCBtYXRlcmlhbCwge2tleU1hbmFnZW1lbnRBbGdvcml0aG1zOiBbJ1BCRVMyLUhTNTEyK0EyNTZLVyddLCBjb250ZW50RW5jcnlwdGlvbkFsZ29yaXRobXM6IFsnQTI1NkdDTSddfSlcbmp3ZSA9IGF3YWl0IG5ldyBKT1NFLkdlbmVyYWxFbmNyeXB0KG1lc3NhZ2UpLnNldFByb3RlY3RlZEhlYWRlcih7YWxnOiAnUEJFUzItSFM1MTIrQTI1NktXJywgZW5jOiAnQTI1NkdDTScgfSkuYWRkUmVjaXBpZW50KG1hdGVyaWFsKS5lbmNyeXB0KClcbmp3ZSA9IGF3YWl0IG5ldyBKT1NFLkdlbmVyYWxFbmNyeXB0KG1lc3NhZ2UpLnNldFByb3RlY3RlZEhlYWRlcih7ZW5jOiAnQTI1NkdDTScgfSlcbiAgLmFkZFJlY2lwaWVudChlay5wdWJsaWNLZXkpLnNldFVucHJvdGVjdGVkSGVhZGVyKHtraWQ6ICdmb28nLCBhbGc6ICdSU0EtT0FFUC0yNTYnfSlcbiAgLmFkZFJlY2lwaWVudChtYXRlcmlhbCkuc2V0VW5wcm90ZWN0ZWRIZWFkZXIoe2tpZDogJ3NlY3JldDEnLCBhbGc6ICdQQkVTMi1IUzUxMitBMjU2S1cnfSlcbiAgLmFkZFJlY2lwaWVudChtYXRlcmlhbDIpLnNldFVucHJvdGVjdGVkSGVhZGVyKHtraWQ6ICdzZWNyZXQyJywgYWxnOiAnUEJFUzItSFM1MTIrQTI1NktXJ30pXG4gIC5lbmNyeXB0KClcbmRlY3J5cHRlZCA9IGF3YWl0IEpPU0UuZ2VuZXJhbERlY3J5cHQoandlLCBlay5wcml2YXRlS2V5KVxuZGVjcnlwdGVkID0gYXdhaXQgSk9TRS5nZW5lcmFsRGVjcnlwdChqd2UsIG1hdGVyaWFsLCB7a2V5TWFuYWdlbWVudEFsZ29yaXRobXM6IFsnUEJFUzItSFM1MTIrQTI1NktXJ119KVxuKi9cbiIsImltcG9ydCBLcnlwdG8gZnJvbSBcIi4va3J5cHRvLm1qc1wiO1xuaW1wb3J0ICogYXMgSk9TRSBmcm9tIFwiam9zZVwiO1xuaW1wb3J0IHtzaWduaW5nQWxnb3JpdGhtLCBlbmNyeXB0aW5nQWxnb3JpdGhtLCBzeW1tZXRyaWNBbGdvcml0aG0sIHN5bW1ldHJpY1dyYXAsIHNlY3JldEFsZ29yaXRobX0gZnJvbSBcIi4vYWxnb3JpdGhtcy5tanNcIjtcblxuZnVuY3Rpb24gbWlzbWF0Y2goa2lkLCBlbmNvZGVkS2lkKSB7IC8vIFByb21pc2UgYSByZWplY3Rpb24uXG4gIGxldCBtZXNzYWdlID0gYEtleSAke2tpZH0gZG9lcyBub3QgbWF0Y2ggZW5jb2RlZCAke2VuY29kZWRLaWR9LmA7XG4gIHJldHVybiBQcm9taXNlLnJlamVjdChtZXNzYWdlKTtcbn1cblxuY29uc3QgTXVsdGlLcnlwdG8gPSB7XG4gIC8vIEV4dGVuZCBLcnlwdG8gZm9yIGdlbmVyYWwgKG11bHRpcGxlIGtleSkgSk9TRSBvcGVyYXRpb25zLlxuICAvLyBTZWUgaHR0cHM6Ly9raWxyb3ktY29kZS5naXRodWIuaW8vZGlzdHJpYnV0ZWQtc2VjdXJpdHkvZG9jcy9pbXBsZW1lbnRhdGlvbi5odG1sI2NvbWJpbmluZy1rZXlzXG4gIFxuICAvLyBPdXIgbXVsdGkga2V5cyBhcmUgZGljdGlvbmFyaWVzIG9mIG5hbWUgKG9yIGtpZCkgPT4ga2V5T2JqZWN0LlxuICBpc011bHRpS2V5KGtleSkgeyAvLyBBIFN1YnRsZUNyeXB0byBDcnlwdG9LZXkgaXMgYW4gb2JqZWN0IHdpdGggYSB0eXBlIHByb3BlcnR5LiBPdXIgbXVsdGlrZXlzIGFyZVxuICAgIC8vIG9iamVjdHMgd2l0aCBhIHNwZWNpZmljIHR5cGUgb3Igbm8gdHlwZSBwcm9wZXJ0eSBhdCBhbGwuXG4gICAgcmV0dXJuIChrZXkudHlwZSB8fCAnbXVsdGknKSA9PT0gJ211bHRpJztcbiAgfSxcbiAga2V5VGFncyhrZXkpIHsgLy8gSnVzdCB0aGUga2lkcyB0aGF0IGFyZSBmb3IgYWN0dWFsIGtleXMuIE5vICd0eXBlJy5cbiAgICByZXR1cm4gT2JqZWN0LmtleXMoa2V5KS5maWx0ZXIoa2V5ID0+IGtleSAhPT0gJ3R5cGUnKTtcbiAgfSxcblxuICAvLyBFeHBvcnQvSW1wb3J0XG4gIGFzeW5jIGV4cG9ydEpXSyhrZXkpIHsgLy8gUHJvbWlzZSBhIEpXSyBrZXkgc2V0IGlmIG5lY2Vzc2FyeSwgcmV0YWluaW5nIHRoZSBuYW1lcyBhcyBraWQgcHJvcGVydHkuXG4gICAgaWYgKCF0aGlzLmlzTXVsdGlLZXkoa2V5KSkgcmV0dXJuIHN1cGVyLmV4cG9ydEpXSyhrZXkpO1xuICAgIGxldCBuYW1lcyA9IHRoaXMua2V5VGFncyhrZXkpLFxuICAgICAgICBrZXlzID0gYXdhaXQgUHJvbWlzZS5hbGwobmFtZXMubWFwKGFzeW5jIG5hbWUgPT4ge1xuICAgICAgICAgIGxldCBqd2sgPSBhd2FpdCB0aGlzLmV4cG9ydEpXSyhrZXlbbmFtZV0pO1xuICAgICAgICAgIGp3ay5raWQgPSBuYW1lO1xuICAgICAgICAgIHJldHVybiBqd2s7XG4gICAgICAgIH0pKTtcbiAgICByZXR1cm4ge2tleXN9O1xuICB9LFxuICBhc3luYyBpbXBvcnRKV0soandrKSB7IC8vIFByb21pc2UgYSBzaW5nbGUgXCJrZXlcIiBvYmplY3QuXG4gICAgLy8gUmVzdWx0IHdpbGwgYmUgYSBtdWx0aS1rZXkgaWYgSldLIGlzIGEga2V5IHNldCwgaW4gd2hpY2ggY2FzZSBlYWNoIG11c3QgaW5jbHVkZSBhIGtpZCBwcm9wZXJ0eS5cbiAgICBpZiAoIWp3ay5rZXlzKSByZXR1cm4gc3VwZXIuaW1wb3J0SldLKGp3ayk7XG4gICAgbGV0IGtleSA9IHt9OyAvLyBUT0RPOiBnZXQgdHlwZSBmcm9tIGt0eSBvciBzb21lIHN1Y2g/XG4gICAgYXdhaXQgUHJvbWlzZS5hbGwoandrLmtleXMubWFwKGFzeW5jIGp3ayA9PiBrZXlbandrLmtpZF0gPSBhd2FpdCB0aGlzLmltcG9ydEpXSyhqd2spKSk7XG4gICAgcmV0dXJuIGtleTtcbiAgfSxcblxuICAvLyBFbmNyeXB0L0RlY3J5cHRcbiAgYXN5bmMgZW5jcnlwdChrZXksIG1lc3NhZ2UsIGhlYWRlcnMgPSB7fSkgeyAvLyBQcm9taXNlIGEgSldFLCBpbiBnZW5lcmFsIGZvcm0gaWYgYXBwcm9wcmlhdGUuXG4gICAgaWYgKCF0aGlzLmlzTXVsdGlLZXkoa2V5KSkgcmV0dXJuIHN1cGVyLmVuY3J5cHQoa2V5LCBtZXNzYWdlLCBoZWFkZXJzKTtcbiAgICAvLyBrZXkgbXVzdCBiZSBhIGRpY3Rpb25hcnkgbWFwcGluZyB0YWdzIHRvIGVuY3J5cHRpbmcga2V5cy5cbiAgICBsZXQgYmFzZUhlYWRlciA9IHtlbmM6IHN5bW1ldHJpY0FsZ29yaXRobSwgLi4uaGVhZGVyc30sXG4gICAgICAgIGlucHV0QnVmZmVyID0gdGhpcy5pbnB1dEJ1ZmZlcihtZXNzYWdlLCBiYXNlSGVhZGVyKSxcbiAgICAgICAgandlID0gbmV3IEpPU0UuR2VuZXJhbEVuY3J5cHQoaW5wdXRCdWZmZXIpLnNldFByb3RlY3RlZEhlYWRlcihiYXNlSGVhZGVyKTtcbiAgICBmb3IgKGxldCB0YWcgb2YgdGhpcy5rZXlUYWdzKGtleSkpIHtcbiAgICAgIGxldCB0aGlzS2V5ID0ga2V5W3RhZ10sXG4gICAgICAgICAgaXNTdHJpbmcgPSAnc3RyaW5nJyA9PT0gdHlwZW9mIHRoaXNLZXksXG4gICAgICAgICAgaXNTeW0gPSBpc1N0cmluZyB8fCB0aGlzLmlzU3ltbWV0cmljKHRoaXNLZXkpLFxuICAgICAgICAgIHNlY3JldCA9IGlzU3RyaW5nID8gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHRoaXNLZXkpIDogdGhpcy5rZXlTZWNyZXQodGhpc0tleSksXG4gICAgICAgICAgYWxnID0gaXNTdHJpbmcgPyBzZWNyZXRBbGdvcml0aG0gOiAoaXNTeW0gPyBzeW1tZXRyaWNXcmFwIDogZW5jcnlwdGluZ0FsZ29yaXRobSk7XG4gICAgICAvLyBUaGUga2lkIGFuZCBhbGcgYXJlIHBlci9zdWIta2V5LCBhbmQgc28gY2Fubm90IGJlIHNpZ25lZCBieSBhbGwsIGFuZCBzbyBjYW5ub3QgYmUgcHJvdGVjdGVkIHdpdGhpbiB0aGUgZW5jcnlwdGlvbi5cbiAgICAgIC8vIFRoaXMgaXMgb2ssIGJlY2F1c2UgdGhlIG9ubHkgdGhhdCBjYW4gaGFwcGVuIGFzIGEgcmVzdWx0IG9mIHRhbXBlcmluZyB3aXRoIHRoZXNlIGlzIHRoYXQgdGhlIGRlY3J5cHRpb24gd2lsbCBmYWlsLFxuICAgICAgLy8gd2hpY2ggaXMgdGhlIHNhbWUgcmVzdWx0IGFzIHRhbXBlcmluZyB3aXRoIHRoZSBjaXBoZXJ0ZXh0IG9yIGFueSBvdGhlciBwYXJ0IG9mIHRoZSBKV0UuXG4gICAgICBqd2UuYWRkUmVjaXBpZW50KHNlY3JldCkuc2V0VW5wcm90ZWN0ZWRIZWFkZXIoe2tpZDogdGFnLCBhbGd9KTtcbiAgICB9XG4gICAgbGV0IGVuY3J5cHRlZCA9IGF3YWl0IGp3ZS5lbmNyeXB0KCk7XG4gICAgcmV0dXJuIGVuY3J5cHRlZDtcbiAgfSxcbiAgYXN5bmMgZGVjcnlwdChrZXksIGVuY3J5cHRlZCwgb3B0aW9ucykgeyAvLyBQcm9taXNlIHtwYXlsb2FkLCB0ZXh0LCBqc29ufSwgd2hlcmUgdGV4dCBhbmQganNvbiBhcmUgb25seSBkZWZpbmVkIHdoZW4gYXBwcm9wcmlhdGUuXG4gICAgaWYgKCF0aGlzLmlzTXVsdGlLZXkoa2V5KSkgcmV0dXJuIHN1cGVyLmRlY3J5cHQoa2V5LCBlbmNyeXB0ZWQsIG9wdGlvbnMpO1xuICAgIGxldCBqd2UgPSBlbmNyeXB0ZWQsXG4gICAgICAgIHtyZWNpcGllbnRzfSA9IGp3ZSxcbiAgICAgICAgdW53cmFwcGluZ1Byb21pc2VzID0gcmVjaXBpZW50cy5tYXAoYXN5bmMgKHtoZWFkZXJ9KSA9PiB7XG4gICAgICAgICAgbGV0IHtraWR9ID0gaGVhZGVyLFxuICAgICAgICAgICAgICB1bndyYXBwaW5nS2V5ID0ga2V5W2tpZF0sXG4gICAgICAgICAgICAgIG9wdGlvbnMgPSB7fTtcbiAgICAgICAgICBpZiAoIXVud3JhcHBpbmdLZXkpIHJldHVybiBQcm9taXNlLnJlamVjdCgnbWlzc2luZycpO1xuICAgICAgICAgIGlmICgnc3RyaW5nJyA9PT0gdHlwZW9mIHVud3JhcHBpbmdLZXkpIHsgLy8gVE9ETzogb25seSBzcGVjaWZpZWQgaWYgYWxsb3dlZCBieSBzZWN1cmUgaGVhZGVyP1xuICAgICAgICAgICAgdW53cmFwcGluZ0tleSA9IG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZSh1bndyYXBwaW5nS2V5KTtcbiAgICAgICAgICAgIG9wdGlvbnMua2V5TWFuYWdlbWVudEFsZ29yaXRobXMgPSBbc2VjcmV0QWxnb3JpdGhtXTtcbiAgICAgICAgICB9XG4gICAgICAgICAgbGV0IHJlc3VsdCA9IGF3YWl0IEpPU0UuZ2VuZXJhbERlY3J5cHQoandlLCB0aGlzLmtleVNlY3JldCh1bndyYXBwaW5nS2V5KSwgb3B0aW9ucyksXG4gICAgICAgICAgICAgIGVuY29kZWRLaWQgPSByZXN1bHQudW5wcm90ZWN0ZWRIZWFkZXIua2lkO1xuICAgICAgICAgIGlmIChlbmNvZGVkS2lkICE9PSBraWQpIHJldHVybiBtaXNtYXRjaChraWQsIGVuY29kZWRLaWQpO1xuICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgIH0pO1xuICAgIC8vIERvIHdlIHJlYWxseSB3YW50IHRvIHJldHVybiB1bmRlZmluZWQgaWYgZXZlcnl0aGluZyBmYWlscz8gU2hvdWxkIGp1c3QgYWxsb3cgdGhlIHJlamVjdGlvbiB0byBwcm9wYWdhdGU/XG4gICAgcmV0dXJuIGF3YWl0IFByb21pc2UuYW55KHVud3JhcHBpbmdQcm9taXNlcykudGhlbihcbiAgICAgIHJlc3VsdCA9PiB7XG4gICAgICAgIHRoaXMucmVjb3ZlckRhdGFGcm9tQ29udGVudFR5cGUocmVzdWx0LCBvcHRpb25zKTtcbiAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgIH0sXG4gICAgICAoKSA9PiB1bmRlZmluZWQpO1xuICB9LFxuXG4gIC8vIFNpZ24vVmVyaWZ5XG4gIGFzeW5jIHNpZ24oa2V5LCBtZXNzYWdlLCBoZWFkZXIgPSB7fSkgeyAvLyBQcm9taXNlIEpXUywgaW4gZ2VuZXJhbCBmb3JtIHdpdGgga2lkIGhlYWRlcnMgaWYgbmVjZXNzYXJ5LlxuICAgIGlmICghdGhpcy5pc011bHRpS2V5KGtleSkpIHJldHVybiBzdXBlci5zaWduKGtleSwgbWVzc2FnZSwgaGVhZGVyKTtcbiAgICBsZXQgaW5wdXRCdWZmZXIgPSB0aGlzLmlucHV0QnVmZmVyKG1lc3NhZ2UsIGhlYWRlciksXG4gICAgICAgIGp3cyA9IG5ldyBKT1NFLkdlbmVyYWxTaWduKGlucHV0QnVmZmVyKTtcbiAgICBmb3IgKGxldCB0YWcgb2YgdGhpcy5rZXlUYWdzKGtleSkpIHtcbiAgICAgIGxldCB0aGlzS2V5ID0ga2V5W3RhZ10sXG4gICAgICAgICAgdGhpc0hlYWRlciA9IHtraWQ6IHRhZywgYWxnOiBzaWduaW5nQWxnb3JpdGhtLCAuLi5oZWFkZXJ9O1xuICAgICAgandzLmFkZFNpZ25hdHVyZSh0aGlzS2V5KS5zZXRQcm90ZWN0ZWRIZWFkZXIodGhpc0hlYWRlcik7XG4gICAgfVxuICAgIHJldHVybiBqd3Muc2lnbigpO1xuICB9LFxuICB2ZXJpZnlTdWJTaWduYXR1cmUoandzLCBzaWduYXR1cmVFbGVtZW50LCBtdWx0aUtleSwga2lkcykge1xuICAgIC8vIFZlcmlmeSBhIHNpbmdsZSBlbGVtZW50IG9mIGp3cy5zaWduYXR1cmUgdXNpbmcgbXVsdGlLZXkuXG4gICAgLy8gQWx3YXlzIHByb21pc2VzIHtwcm90ZWN0ZWRIZWFkZXIsIHVucHJvdGVjdGVkSGVhZGVyLCBraWR9LCBldmVuIGlmIHZlcmlmaWNhdGlvbiBmYWlscyxcbiAgICAvLyB3aGVyZSBraWQgaXMgdGhlIHByb3BlcnR5IG5hbWUgd2l0aGluIG11bHRpS2V5IHRoYXQgbWF0Y2hlZCAoZWl0aGVyIGJ5IGJlaW5nIHNwZWNpZmllZCBpbiBhIGhlYWRlclxuICAgIC8vIG9yIGJ5IHN1Y2Nlc3NmdWwgdmVyaWZpY2F0aW9uKS4gQWxzbyBpbmNsdWRlcyB0aGUgZGVjb2RlZCBwYXlsb2FkIElGRiB0aGVyZSBpcyBhIG1hdGNoLlxuICAgIGxldCBwcm90ZWN0ZWRIZWFkZXIgPSBzaWduYXR1cmVFbGVtZW50LnByb3RlY3RlZEhlYWRlciA/PyB0aGlzLmRlY29kZVByb3RlY3RlZEhlYWRlcihzaWduYXR1cmVFbGVtZW50KSxcbiAgICAgICAgdW5wcm90ZWN0ZWRIZWFkZXIgPSBzaWduYXR1cmVFbGVtZW50LnVucHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICBraWQgPSBwcm90ZWN0ZWRIZWFkZXI/LmtpZCB8fCB1bnByb3RlY3RlZEhlYWRlcj8ua2lkLFxuICAgICAgICBzaW5nbGVKV1MgPSB7Li4uandzLCBzaWduYXR1cmVzOiBbc2lnbmF0dXJlRWxlbWVudF19LFxuICAgICAgICBmYWlsdXJlUmVzdWx0ID0ge3Byb3RlY3RlZEhlYWRlciwgdW5wcm90ZWN0ZWRIZWFkZXIsIGtpZH0sXG4gICAgICAgIGtpZHNUb1RyeSA9IGtpZCA/IFtraWRdIDoga2lkcztcbiAgICBsZXQgcHJvbWlzZSA9IFByb21pc2UuYW55KGtpZHNUb1RyeS5tYXAoYXN5bmMga2lkID0+IEpPU0UuZ2VuZXJhbFZlcmlmeShzaW5nbGVKV1MsIG11bHRpS2V5W2tpZF0pLnRoZW4ocmVzdWx0ID0+IHtyZXR1cm4ge2tpZCwgLi4ucmVzdWx0fTt9KSkpO1xuICAgIHJldHVybiBwcm9taXNlLmNhdGNoKCgpID0+IGZhaWx1cmVSZXN1bHQpO1xuICB9LFxuICBhc3luYyB2ZXJpZnkoa2V5LCBzaWduYXR1cmUsIG9wdGlvbnMgPSB7fSkgeyAvLyBQcm9taXNlIHtwYXlsb2FkLCB0ZXh0LCBqc29ufSwgd2hlcmUgdGV4dCBhbmQganNvbiBhcmUgb25seSBkZWZpbmVkIHdoZW4gYXBwcm9wcmlhdGUuXG4gICAgLy8gQWRkaXRpb25hbGx5LCBpZiBrZXkgaXMgYSBtdWx0aUtleSBBTkQgc2lnbmF0dXJlIGlzIGEgZ2VuZXJhbCBmb3JtIEpXUywgdGhlbiBhbnN3ZXIgaW5jbHVkZXMgYSBzaWduZXJzIHByb3BlcnR5XG4gICAgLy8gYnkgd2hpY2ggY2FsbGVyIGNhbiBkZXRlcm1pbmUgaWYgaXQgd2hhdCB0aGV5IGV4cGVjdC4gVGhlIHBheWxvYWQgb2YgZWFjaCBzaWduZXJzIGVsZW1lbnQgaXMgZGVmaW5lZCBvbmx5IHRoYXRcbiAgICAvLyBzaWduZXIgd2FzIG1hdGNoZWQgYnkgc29tZXRoaW5nIGluIGtleS5cbiAgICBcbiAgICBpZiAoIXRoaXMuaXNNdWx0aUtleShrZXkpKSByZXR1cm4gc3VwZXIudmVyaWZ5KGtleSwgc2lnbmF0dXJlLCBvcHRpb25zKTtcbiAgICBpZiAoIXNpZ25hdHVyZS5zaWduYXR1cmVzKSByZXR1cm47XG5cbiAgICAvLyBDb21wYXJpc29uIHRvIHBhbnZhIEpPU0UuZ2VuZXJhbFZlcmlmeS5cbiAgICAvLyBKT1NFIHRha2VzIGEgandzIGFuZCBPTkUga2V5IGFuZCBhbnN3ZXJzIHtwYXlsb2FkLCBwcm90ZWN0ZWRIZWFkZXIsIHVucHJvdGVjdGVkSGVhZGVyfSBtYXRjaGluZyB0aGUgb25lXG4gICAgLy8gandzLnNpZ25hdHVyZSBlbGVtZW50IHRoYXQgd2FzIHZlcmlmaWVkLCBvdGhlcmlzZSBhbiBlcm9yLiAoSXQgdHJpZXMgZWFjaCBvZiB0aGUgZWxlbWVudHMgb2YgdGhlIGp3cy5zaWduYXR1cmVzLilcbiAgICAvLyBJdCBpcyBub3QgZ2VuZXJhbGx5IHBvc3NpYmxlIHRvIGtub3cgV0hJQ0ggb25lIG9mIHRoZSBqd3Muc2lnbmF0dXJlcyB3YXMgbWF0Y2hlZC5cbiAgICAvLyAoSXQgTUFZIGJlIHBvc3NpYmxlIGlmIHRoZXJlIGFyZSB1bmlxdWUga2lkIGVsZW1lbnRzLCBidXQgdGhhdCdzIGFwcGxpY2F0aW9uLWRlcGVuZGVudC4pXG4gICAgLy9cbiAgICAvLyBNdWx0aUtyeXB0byB0YWtlcyBhIGRpY3Rpb25hcnkgdGhhdCBjb250YWlucyBuYW1lZCBrZXlzIGFuZCByZWNvZ25pemVkSGVhZGVyIHByb3BlcnRpZXMsIGFuZCBpdCByZXR1cm5zXG4gICAgLy8gYSByZXN1bHQgdGhhdCBoYXMgYSBzaWduZXJzIGFycmF5IHRoYXQgaGFzIGFuIGVsZW1lbnQgY29ycmVzcG9uZGluZyB0byBlYWNoIG9yaWdpbmFsIHNpZ25hdHVyZSBpZiBhbnlcbiAgICAvLyBhcmUgbWF0Y2hlZCBieSB0aGUgbXVsdGlrZXkuIChJZiBub25lIG1hdGNoLCB3ZSByZXR1cm4gdW5kZWZpbmVkLlxuICAgIC8vIEVhY2ggZWxlbWVudCBjb250YWlucyB0aGUga2lkLCBwcm90ZWN0ZWRIZWFkZXIsIHBvc3NpYmx5IHVucHJvdGVjdGVkSGVhZGVyLCBhbmQgcG9zc2libHkgcGF5bG9hZCAoaS5lLiBpZiBzdWNjZXNzZnVsKS5cbiAgICAvL1xuICAgIC8vIEFkZGl0aW9uYWxseSBpZiBhIHJlc3VsdCBpcyBwcm9kdWNlZCwgdGhlIG92ZXJhbGwgcHJvdGVjdGVkSGVhZGVyIGFuZCB1bnByb3RlY3RlZEhlYWRlciBjb250YWlucyBvbmx5IHZhbHVlc1xuICAgIC8vIHRoYXQgd2VyZSBjb21tb24gdG8gZWFjaCBvZiB0aGUgdmVyaWZpZWQgc2lnbmF0dXJlIGVsZW1lbnRzLlxuICAgIFxuICAgIGxldCBqd3MgPSBzaWduYXR1cmUsXG4gICAgICAgIGtpZHMgPSB0aGlzLmtleVRhZ3Moa2V5KSxcbiAgICAgICAgc2lnbmVycyA9IGF3YWl0IFByb21pc2UuYWxsKGp3cy5zaWduYXR1cmVzLm1hcChzaWduYXR1cmUgPT4gdGhpcy52ZXJpZnlTdWJTaWduYXR1cmUoandzLCBzaWduYXR1cmUsIGtleSwga2lkcykpKTtcbiAgICBpZiAoIXNpZ25lcnMuZmluZChzaWduZXIgPT4gc2lnbmVyLnBheWxvYWQpKSByZXR1cm4gdW5kZWZpbmVkO1xuICAgIC8vIE5vdyBjYW5vbmljYWxpemUgdGhlIHNpZ25lcnMgYW5kIGJ1aWxkIHVwIGEgcmVzdWx0LlxuICAgIGxldCBbZmlyc3QsIC4uLnJlc3RdID0gc2lnbmVycyxcbiAgICAgICAgcmVzdWx0ID0ge3Byb3RlY3RlZEhlYWRlcjoge30sIHVucHJvdGVjdGVkSGVhZGVyOiB7fSwgc2lnbmVyc30sXG4gICAgICAgIC8vIEZvciBhIGhlYWRlciB2YWx1ZSB0byBiZSBjb21tb24gdG8gdmVyaWZpZWQgcmVzdWx0cywgaXQgbXVzdCBiZSBpbiB0aGUgZmlyc3QgcmVzdWx0LlxuICAgICAgICBnZXRVbmlxdWUgPSBjYXRlZ29yeU5hbWUgPT4ge1xuICAgICAgICAgIGxldCBmaXJzdEhlYWRlciA9IGZpcnN0W2NhdGVnb3J5TmFtZV0sXG4gICAgICAgICAgICAgIGFjY3VtdWxhdG9ySGVhZGVyID0gcmVzdWx0W2NhdGVnb3J5TmFtZV07XG4gICAgICAgICAgZm9yIChsZXQgbGFiZWwgaW4gZmlyc3RIZWFkZXIpIHtcbiAgICAgICAgICAgIGxldCB2YWx1ZSA9IGZpcnN0SGVhZGVyW2xhYmVsXTtcbiAgICAgICAgICAgIGlmIChyZXN0LnNvbWUoc2lnbmVyUmVzdWx0ID0+IHNpZ25lclJlc3VsdFtjYXRlZ29yeU5hbWVdW2xhYmVsXSAhPT0gdmFsdWUpKSBjb250aW51ZTtcbiAgICAgICAgICAgIGFjY3VtdWxhdG9ySGVhZGVyW2xhYmVsXSA9IHZhbHVlO1xuICAgICAgICAgIH1cbiAgICAgICAgfTtcbiAgICBnZXRVbmlxdWUoJ3Byb3RlY3RlZEhlYWRlcicpO1xuICAgIGdldFVuaXF1ZSgncHJvdGVjdGVkSGVhZGVyJyk7XG4gICAgLy8gSWYgYW55dGhpbmcgdmVyaWZpZWQsIHRoZW4gc2V0IHBheWxvYWQgYW5kIGFsbG93IHRleHQvanNvbiB0byBiZSBwcm9kdWNlZC5cbiAgICAvLyBDYWxsZXJzIGNhbiBjaGVjayBzaWduZXJzW25dLnBheWxvYWQgdG8gZGV0ZXJtaW5lIGlmIHRoZSByZXN1bHQgaXMgd2hhdCB0aGV5IHdhbnQuXG4gICAgcmVzdWx0LnBheWxvYWQgPSBzaWduZXJzLmZpbmQoc2lnbmVyID0+IHNpZ25lci5wYXlsb2FkKS5wYXlsb2FkO1xuICAgIHJldHVybiB0aGlzLnJlY292ZXJEYXRhRnJvbUNvbnRlbnRUeXBlKHJlc3VsdCwgb3B0aW9ucyk7XG4gIH1cbn07XG5cbk9iamVjdC5zZXRQcm90b3R5cGVPZihNdWx0aUtyeXB0bywgS3J5cHRvKTsgLy8gSW5oZXJpdCBmcm9tIEtyeXB0byBzbyB0aGF0IHN1cGVyLm11bWJsZSgpIHdvcmtzLlxuZXhwb3J0IGRlZmF1bHQgTXVsdGlLcnlwdG87XG4iLCJjbGFzcyBQZXJzaXN0ZWRDb2xsZWN0aW9uIHtcbiAgLy8gQXN5bmNocm9ub3VzIGxvY2FsIHN0b3JhZ2UsIGF2YWlsYWJsZSBpbiB3ZWIgd29ya2Vycy5cbiAgY29uc3RydWN0b3Ioe2NvbGxlY3Rpb25OYW1lID0gJ2NvbGxlY3Rpb24nLCBkYk5hbWUgPSAnYXN5bmNMb2NhbFN0b3JhZ2UnfSA9IHt9KSB7XG4gICAgLy8gQ2FwdHVyZSB0aGUgZGF0YSBoZXJlLCBidXQgZG9uJ3Qgb3BlbiB0aGUgZGIgdW50aWwgd2UgbmVlZCB0by5cbiAgICB0aGlzLmNvbGxlY3Rpb25OYW1lID0gY29sbGVjdGlvbk5hbWU7XG4gICAgdGhpcy5kYk5hbWUgPSBkYk5hbWU7XG4gICAgdGhpcy52ZXJzaW9uID0gMTtcbiAgfVxuICBnZXQgZGIoKSB7IC8vIEFuc3dlciBhIHByb21pc2UgZm9yIHRoZSBkYXRhYmFzZSwgY3JlYXRpbmcgaXQgaWYgbmVlZGVkLlxuICAgIHJldHVybiB0aGlzLl9kYiA/Pz0gbmV3IFByb21pc2UocmVzb2x2ZSA9PiB7XG4gICAgICBjb25zdCByZXF1ZXN0ID0gaW5kZXhlZERCLm9wZW4odGhpcy5kYk5hbWUsIHRoaXMudmVyc2lvbik7XG4gICAgICAvLyBjcmVhdGVPYmplY3RTdG9yZSBjYW4gb25seSBiZSBjYWxsZWQgZnJvbSB1cGdyYWRlbmVlZGVkLCB3aGljaCBpcyBvbmx5IGNhbGxlZCBmb3IgbmV3IHZlcnNpb25zLlxuICAgICAgcmVxdWVzdC5vbnVwZ3JhZGVuZWVkZWQgPSBldmVudCA9PiBldmVudC50YXJnZXQucmVzdWx0LmNyZWF0ZU9iamVjdFN0b3JlKHRoaXMuY29sbGVjdGlvbk5hbWUpO1xuICAgICAgdGhpcy5yZXN1bHQocmVzb2x2ZSwgcmVxdWVzdCk7XG4gICAgfSk7XG4gIH1cbiAgdHJhbnNhY3Rpb24obW9kZSA9ICdyZWFkJykgeyAvLyBBbnN3ZXIgYSBwcm9taXNlIGZvciB0aGUgbmFtZWQgb2JqZWN0IHN0b3JlIG9uIGEgbmV3IHRyYW5zYWN0aW9uLlxuICAgIGNvbnN0IGNvbGxlY3Rpb25OYW1lID0gdGhpcy5jb2xsZWN0aW9uTmFtZTtcbiAgICByZXR1cm4gdGhpcy5kYi50aGVuKGRiID0+IGRiLnRyYW5zYWN0aW9uKGNvbGxlY3Rpb25OYW1lLCBtb2RlKS5vYmplY3RTdG9yZShjb2xsZWN0aW9uTmFtZSkpO1xuICB9XG4gIHJlc3VsdChyZXNvbHZlLCBvcGVyYXRpb24pIHtcbiAgICBvcGVyYXRpb24ub25zdWNjZXNzID0gZXZlbnQgPT4gcmVzb2x2ZShldmVudC50YXJnZXQucmVzdWx0IHx8ICcnKTsgLy8gTm90IHVuZGVmaW5lZC5cbiAgfVxuICByZXRyaWV2ZSh0YWcpIHsgLy8gUHJvbWlzZSB0byByZXRyaWV2ZSB0YWcgZnJvbSBjb2xsZWN0aW9uTmFtZS5cbiAgICByZXR1cm4gbmV3IFByb21pc2UocmVzb2x2ZSA9PiB7XG4gICAgICB0aGlzLnRyYW5zYWN0aW9uKCdyZWFkb25seScpLnRoZW4oc3RvcmUgPT4gdGhpcy5yZXN1bHQocmVzb2x2ZSwgc3RvcmUuZ2V0KHRhZykpKTtcbiAgICB9KTtcbiAgfVxuICBzdG9yZSh0YWcsIGRhdGEpIHsgLy8gUHJvbWlzZSB0byBzdG9yZSBkYXRhIGF0IHRhZyBpbiBjb2xsZWN0aW9uTmFtZS5cbiAgICByZXR1cm4gbmV3IFByb21pc2UocmVzb2x2ZSA9PiB7XG4gICAgICB0aGlzLnRyYW5zYWN0aW9uKCdyZWFkd3JpdGUnKS50aGVuKHN0b3JlID0+IHRoaXMucmVzdWx0KHJlc29sdmUsIHN0b3JlLnB1dChkYXRhLCB0YWcpKSk7XG4gICAgfSk7XG4gIH1cbiAgcmVtb3ZlKHRhZykgeyAvLyBQcm9taXNlIHRvIHJlbW92ZSB0YWcgZnJvbSBjb2xsZWN0aW9uTmFtZS5cbiAgICByZXR1cm4gbmV3IFByb21pc2UocmVzb2x2ZSA9PiB7XG4gICAgICB0aGlzLnRyYW5zYWN0aW9uKCdyZWFkd3JpdGUnKS50aGVuKHN0b3JlID0+IHRoaXMucmVzdWx0KHJlc29sdmUsIHN0b3JlLmRlbGV0ZSh0YWcpKSk7XG4gICAgfSk7XG4gIH1cbn1cbmV4cG9ydCBkZWZhdWx0IFBlcnNpc3RlZENvbGxlY3Rpb247XG4iLCJ2YXIgcHJvbXB0ZXIgPSBwcm9tcHRTdHJpbmcgPT4gcHJvbXB0U3RyaW5nO1xuaWYgKHR5cGVvZih3aW5kb3cpICE9PSAndW5kZWZpbmVkJykge1xuICBwcm9tcHRlciA9IHdpbmRvdy5wcm9tcHQ7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXRVc2VyRGV2aWNlU2VjcmV0KHRhZywgcHJvbXB0U3RyaW5nKSB7XG4gIHJldHVybiBwcm9tcHRTdHJpbmcgPyAodGFnICsgcHJvbXB0ZXIocHJvbXB0U3RyaW5nKSkgOiB0YWc7XG59XG4iLCJjb25zdCBvcmlnaW4gPSBuZXcgVVJMKGltcG9ydC5tZXRhLnVybCkub3JpZ2luO1xuZXhwb3J0IGRlZmF1bHQgb3JpZ2luO1xuIiwiZXhwb3J0IGNvbnN0IG1rZGlyID0gdW5kZWZpbmVkO1xuIiwiY29uc3QgdGFnQnJlYWt1cCA9IC8oXFxTezUwfSkoXFxTezJ9KShcXFN7Mn0pKFxcUyspLztcbmV4cG9ydCBmdW5jdGlvbiB0YWdQYXRoKGNvbGxlY3Rpb25OYW1lLCB0YWcsIGV4dGVuc2lvbiA9ICdqc29uJykgeyAvLyBQYXRobmFtZSB0byB0YWcgcmVzb3VyY2UuXG4gIC8vIFVzZWQgaW4gU3RvcmFnZSBVUkkgYW5kIGZpbGUgc3lzdGVtIHN0b3Jlcy4gQm90dGxlbmVja2VkIGhlcmUgdG8gcHJvdmlkZSBjb25zaXN0ZW50IGFsdGVybmF0ZSBpbXBsZW1lbnRhdGlvbnMuXG4gIC8vIFBhdGggaXMgLmpzb24gc28gdGhhdCBzdGF0aWMtZmlsZSB3ZWIgc2VydmVycyB3aWxsIHN1cHBseSBhIGpzb24gbWltZSB0eXBlLlxuICAvLyBQYXRoIGlzIGJyb2tlbiB1cCBzbyB0aGF0IGRpcmVjdG9yeSByZWFkcyBkb24ndCBnZXQgYm9nZ2VkIGRvd24gZnJvbSBoYXZpbmcgdG9vIG11Y2ggaW4gYSBkaXJlY3RvcnkuXG4gIC8vXG4gIC8vIE5PVEU6IGNoYW5nZXMgaGVyZSBtdXN0IGJlIG1hdGNoZWQgYnkgdGhlIFBVVCByb3V0ZSBzcGVjaWZpZWQgaW4gc2lnbmVkLWNsb3VkLXNlcnZlci9zdG9yYWdlLm1qcyBhbmQgdGFnTmFtZS5tanNcbiAgaWYgKCF0YWcpIHJldHVybiBjb2xsZWN0aW9uTmFtZTtcbiAgbGV0IG1hdGNoID0gdGFnLm1hdGNoKHRhZ0JyZWFrdXApO1xuICBpZiAoIW1hdGNoKSByZXR1cm4gYCR7Y29sbGVjdGlvbk5hbWV9LyR7dGFnfWA7XG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuby11bnVzZWQtdmFyc1xuICBsZXQgW18sIGEsIGIsIGMsIHJlc3RdID0gbWF0Y2g7XG4gIHJldHVybiBgJHtjb2xsZWN0aW9uTmFtZX0vJHtifS8ke2N9LyR7YX0vJHtyZXN0fS4ke2V4dGVuc2lvbn1gO1xufVxuIiwiaW1wb3J0IG9yaWdpbiBmcm9tICcjb3JpZ2luJzsgLy8gV2hlbiBydW5uaW5nIGluIGEgYnJvd3NlciwgbG9jYXRpb24ub3JpZ2luIHdpbGwgYmUgZGVmaW5lZC4gSGVyZSB3ZSBhbGxvdyBmb3IgTm9kZUpTLlxuaW1wb3J0IHtta2Rpcn0gZnJvbSAnI21rZGlyJztcbmltcG9ydCB7dGFnUGF0aH0gZnJvbSAnLi90YWdQYXRoLm1qcyc7XG5cbmFzeW5jIGZ1bmN0aW9uIHJlc3BvbnNlSGFuZGxlcihyZXNwb25zZSkge1xuICAvLyBSZWplY3QgaWYgc2VydmVyIGRvZXMsIGVsc2UgcmVzcG9uc2UudGV4dCgpLlxuICBpZiAocmVzcG9uc2Uuc3RhdHVzID09PSA0MDQpIHJldHVybiAnJztcbiAgaWYgKCFyZXNwb25zZS5vaykgcmV0dXJuIFByb21pc2UucmVqZWN0KHJlc3BvbnNlLnN0YXR1c1RleHQpO1xuICBsZXQgdGV4dCA9IGF3YWl0IHJlc3BvbnNlLnRleHQoKTtcbiAgaWYgKCF0ZXh0KSByZXR1cm4gdGV4dDsgLy8gUmVzdWx0IG9mIHN0b3JlIGNhbiBiZSBlbXB0eS5cbiAgcmV0dXJuIEpTT04ucGFyc2UodGV4dCk7XG59XG5cbmNvbnN0IFN0b3JhZ2UgPSB7XG4gIGdldCBvcmlnaW4oKSB7IHJldHVybiBvcmlnaW47IH0sXG4gIHRhZ1BhdGgsXG4gIG1rZGlyLFxuICB1cmkoY29sbGVjdGlvbk5hbWUsIHRhZykge1xuICAgIC8vIFBhdGhuYW1lIGV4cGVjdGVkIGJ5IG91ciBzaWduZWQtY2xvdWQtc2VydmVyLlxuICAgIHJldHVybiBgJHtvcmlnaW59L2RiLyR7dGhpcy50YWdQYXRoKGNvbGxlY3Rpb25OYW1lLCB0YWcpfWA7XG4gIH0sXG4gIHN0b3JlKGNvbGxlY3Rpb25OYW1lLCB0YWcsIHNpZ25hdHVyZSwgb3B0aW9ucyA9IHt9KSB7XG4gICAgLy8gU3RvcmUgdGhlIHNpZ25lZCBjb250ZW50IG9uIHRoZSBzaWduZWQtY2xvdWQtc2VydmVyLCByZWplY3RpbmcgaWZcbiAgICAvLyB0aGUgc2VydmVyIGlzIHVuYWJsZSB0byB2ZXJpZnkgdGhlIHNpZ25hdHVyZSBmb2xsb3dpbmcgdGhlIHJ1bGVzIG9mXG4gICAgLy8gaHR0cHM6Ly9raWxyb3ktY29kZS5naXRodWIuaW8vZGlzdHJpYnV0ZWQtc2VjdXJpdHkvI3N0b3Jpbmcta2V5cy11c2luZy10aGUtY2xvdWQtc3RvcmFnZS1hcGlcbiAgICByZXR1cm4gZmV0Y2godGhpcy51cmkoY29sbGVjdGlvbk5hbWUsIHRhZyksIHtcbiAgICAgIG1ldGhvZDogJ1BVVCcsXG4gICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShzaWduYXR1cmUpLFxuICAgICAgaGVhZGVyczogeydDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicsIC4uLihvcHRpb25zLmhlYWRlcnMgfHwge30pfVxuICAgIH0pLnRoZW4ocmVzcG9uc2VIYW5kbGVyKTtcbiAgfSxcbiAgcmV0cmlldmUoY29sbGVjdGlvbk5hbWUsIHRhZywgb3B0aW9ucyA9IHt9KSB7XG4gICAgLy8gV2UgZG8gbm90IHZlcmlmeSBhbmQgZ2V0IHRoZSBvcmlnaW5hbCBkYXRhIG91dCBoZXJlLCBiZWNhdXNlIHRoZSBjYWxsZXIgaGFzXG4gICAgLy8gdGhlIHJpZ2h0IHRvIGRvIHNvIHdpdGhvdXQgdHJ1c3RpbmcgdXMuXG4gICAgcmV0dXJuIGZldGNoKHRoaXMudXJpKGNvbGxlY3Rpb25OYW1lLCB0YWcpLCB7XG4gICAgICBjYWNoZTogJ2RlZmF1bHQnLFxuICAgICAgaGVhZGVyczogeydBY2NlcHQnOiAnYXBwbGljYXRpb24vanNvbicsIC4uLihvcHRpb25zLmhlYWRlcnMgfHwge30pfVxuICAgIH0pLnRoZW4ocmVzcG9uc2VIYW5kbGVyKTtcbiAgfVxufTtcbmV4cG9ydCBkZWZhdWx0IFN0b3JhZ2U7XG4iLCJpbXBvcnQgTXVsdGlLcnlwdG8gZnJvbSAnLi9tdWx0aUtyeXB0by5tanMnO1xuaW1wb3J0IExvY2FsQ29sbGVjdGlvbiBmcm9tICcjbG9jYWxTdG9yZSc7XG5pbXBvcnQge2dldFVzZXJEZXZpY2VTZWNyZXR9IGZyb20gJy4vc2VjcmV0Lm1qcyc7XG5pbXBvcnQgU3RvcmFnZSBmcm9tICcuL3N0b3JhZ2UubWpzJztcblxuZnVuY3Rpb24gZXJyb3IodGVtcGxhdGVGdW5jdGlvbiwgdGFnLCBjYXVzZSA9IHVuZGVmaW5lZCkge1xuICAvLyBGb3JtYXRzIHRhZyAoZS5nLiwgc2hvcnRlbnMgaXQpIGFuZCBnaXZlcyBpdCB0byB0ZW1wbGF0ZUZ1bmN0aW9uKHRhZykgdG8gZ2V0XG4gIC8vIGEgc3VpdGFibGUgZXJyb3IgbWVzc2FnZS4gQW5zd2VycyBhIHJlamVjdGVkIHByb21pc2Ugd2l0aCB0aGF0IEVycm9yLlxuICBsZXQgc2hvcnRlbmVkVGFnID0gdGFnLnNsaWNlKDAsIDE2KSArIFwiLi4uXCIsXG4gICAgICBtZXNzYWdlID0gdGVtcGxhdGVGdW5jdGlvbihzaG9ydGVuZWRUYWcpO1xuICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IEVycm9yKG1lc3NhZ2UsIHtjYXVzZX0pKTtcbn1cbmZ1bmN0aW9uIHVuYXZhaWxhYmxlKHRhZykgeyAvLyBEbyB3ZSB3YW50IHRvIGRpc3Rpbmd1aXNoIGJldHdlZW4gYSB0YWcgYmVpbmdcbiAgLy8gdW5hdmFpbGFibGUgYXQgYWxsLCB2cyBqdXN0IHRoZSBwdWJsaWMgZW5jcnlwdGlvbiBrZXkgYmVpbmcgdW5hdmFpbGFibGU/XG4gIC8vIFJpZ2h0IG5vdyB3ZSBkbyBub3QgZGlzdGluZ3Vpc2gsIGFuZCB1c2UgdGhpcyBmb3IgYm90aC5cbiAgcmV0dXJuIGVycm9yKHRhZyA9PiBgVGhlIHRhZyAke3RhZ30gaXMgbm90IGF2YWlsYWJsZS5gLCB0YWcpO1xufVxuXG5leHBvcnQgY2xhc3MgS2V5U2V0IHtcbiAgLy8gQSBLZXlTZXQgbWFpbnRhaW5zIHR3byBwcml2YXRlIGtleXM6IHNpZ25pbmdLZXkgYW5kIGRlY3J5cHRpbmdLZXkuXG4gIC8vIFNlZSBodHRwczovL2tpbHJveS1jb2RlLmdpdGh1Yi5pby9kaXN0cmlidXRlZC1zZWN1cml0eS9kb2NzL2ltcGxlbWVudGF0aW9uLmh0bWwjd2ViLXdvcmtlci1hbmQtaWZyYW1lXG5cbiAgLy8gQ2FjaGluZ1xuICBzdGF0aWMga2V5U2V0cyA9IHt9O1xuICBzdGF0aWMgY2FjaGVkKHRhZykgeyAvLyBSZXR1cm4gYW4gYWxyZWFkeSBwb3B1bGF0ZWQgS2V5U2V0LlxuICAgIHJldHVybiB0aGlzLmtleVNldHNbdGFnXTtcbiAgfVxuICBzdGF0aWMgY2xlYXIodGFnID0gbnVsbCkgeyAvLyBSZW1vdmUgYWxsIEtleVNldCBpbnN0YW5jZXMgb3IganVzdCB0aGUgc3BlY2lmaWVkIG9uZSwgYnV0IGRvZXMgbm90IGRlc3Ryb3kgdGhlaXIgc3RvcmFnZS5cbiAgICBpZiAoIXRhZykgcmV0dXJuIEtleVNldC5rZXlTZXRzID0ge307XG4gICAgZGVsZXRlIEtleVNldC5rZXlTZXRzW3RhZ11cbiAgfVxuICBjb25zdHJ1Y3Rvcih0YWcpIHtcbiAgICB0aGlzLnRhZyA9IHRhZztcbiAgICB0aGlzLm1lbWJlclRhZ3MgPSBbXTsgLy8gVXNlZCB3aGVuIHJlY3Vyc2l2ZWx5IGRlc3Ryb3lpbmcuXG4gICAgS2V5U2V0LmtleVNldHNbdGFnXSA9IHRoaXM7IC8vIENhY2hlIGl0LlxuICB9XG4gIC8vIGFwaS5tanMgcHJvdmlkZXMgdGhlIHNldHRlciB0byBjaGFuZ2VzIHRoZXNlLCBhbmQgd29ya2VyLm1qcyBleGVyY2lzZXMgaXQgaW4gYnJvd3NlcnMuXG4gIHN0YXRpYyBnZXRVc2VyRGV2aWNlU2VjcmV0ID0gZ2V0VXNlckRldmljZVNlY3JldDtcbiAgc3RhdGljIFN0b3JhZ2UgPSBTdG9yYWdlO1xuXG4gIC8vIFByaW5jaXBsZSBvcGVyYXRpb25zLlxuICBzdGF0aWMgYXN5bmMgY3JlYXRlKHdyYXBwaW5nRGF0YSkgeyAvLyBDcmVhdGUgYSBwZXJzaXN0ZWQgS2V5U2V0IG9mIHRoZSBjb3JyZWN0IHR5cGUsIHByb21pc2luZyB0aGUgbmV3bHkgY3JlYXRlZCB0YWcuXG4gICAgbGV0IHt0aW1lLCAuLi5rZXlzfSA9IGF3YWl0IHRoaXMuY3JlYXRlS2V5cyh3cmFwcGluZ0RhdGEpLFxuICAgICAgICB7dGFnfSA9IGtleXM7XG4gICAgYXdhaXQgdGhpcy5wZXJzaXN0KHRhZywga2V5cywgd3JhcHBpbmdEYXRhLCB0aW1lKTtcbiAgICByZXR1cm4gdGFnO1xuICB9XG4gIGFzeW5jIGRlc3Ryb3kob3B0aW9ucyA9IHt9KSB7IC8vIFRlcm1pbmF0ZXMgdGhpcyBrZXlTZXQgYW5kIGFzc29jaWF0ZWQgc3RvcmFnZSwgYW5kIHNhbWUgZm9yIE9XTkVEIHJlY3Vyc2l2ZU1lbWJlcnMgaWYgYXNrZWQuXG4gICAgbGV0IHt0YWcsIG1lbWJlclRhZ3MsIHNpZ25pbmdLZXl9ID0gdGhpcyxcbiAgICAgICAgY29udGVudCA9IFwiXCIsIC8vIFNob3VsZCBzdG9yYWdlIGhhdmUgYSBzZXBhcmF0ZSBvcGVyYXRpb24gdG8gZGVsZXRlLCBvdGhlciB0aGFuIHN0b3JpbmcgZW1wdHk/XG4gICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IHRoaXMuY29uc3RydWN0b3Iuc2lnbkZvclN0b3JhZ2Uoey4uLm9wdGlvbnMsIG1lc3NhZ2U6IGNvbnRlbnQsIHRhZywgbWVtYmVyVGFncywgc2lnbmluZ0tleSwgdGltZTogRGF0ZS5ub3coKSwgcmVjb3Zlcnk6IHRydWV9KTtcbiAgICBhd2FpdCB0aGlzLmNvbnN0cnVjdG9yLnN0b3JlKCdFbmNyeXB0aW9uS2V5JywgdGFnLCBzaWduYXR1cmUpO1xuICAgIGF3YWl0IHRoaXMuY29uc3RydWN0b3Iuc3RvcmUodGhpcy5jb25zdHJ1Y3Rvci5jb2xsZWN0aW9uLCB0YWcsIHNpZ25hdHVyZSk7XG4gICAgdGhpcy5jb25zdHJ1Y3Rvci5jbGVhcih0YWcpO1xuICAgIGlmICghb3B0aW9ucy5yZWN1cnNpdmVNZW1iZXJzKSByZXR1cm47XG4gICAgYXdhaXQgUHJvbWlzZS5hbGxTZXR0bGVkKHRoaXMubWVtYmVyVGFncy5tYXAoYXN5bmMgbWVtYmVyVGFnID0+IHtcbiAgICAgIGxldCBtZW1iZXJLZXlTZXQgPSBhd2FpdCBLZXlTZXQuZW5zdXJlKG1lbWJlclRhZywgey4uLm9wdGlvbnMsIHJlY292ZXJ5OiB0cnVlfSk7XG4gICAgICBhd2FpdCBtZW1iZXJLZXlTZXQuZGVzdHJveShvcHRpb25zKTtcbiAgICB9KSk7XG4gIH1cbiAgZGVjcnlwdChlbmNyeXB0ZWQsIG9wdGlvbnMpIHsgLy8gUHJvbWlzZSB7cGF5bG9hZCwgdGV4dCwganNvbn0gYXMgYXBwcm9wcmlhdGUuXG4gICAgbGV0IHt0YWcsIGRlY3J5cHRpbmdLZXl9ID0gdGhpcyxcbiAgICAgICAga2V5ID0gZW5jcnlwdGVkLnJlY2lwaWVudHMgPyB7W3RhZ106IGRlY3J5cHRpbmdLZXl9IDogZGVjcnlwdGluZ0tleTtcbiAgICByZXR1cm4gTXVsdGlLcnlwdG8uZGVjcnlwdChrZXksIGVuY3J5cHRlZCwgb3B0aW9ucyk7XG4gIH1cbiAgLy8gc2lnbiBhcyBlaXRoZXIgY29tcGFjdCBvciBtdWx0aUtleSBnZW5lcmFsIEpXUy5cbiAgLy8gVGhlcmUncyBzb21lIGNvbXBsZXhpdHkgaGVyZSBhcm91bmQgYmVpbmcgYWJsZSB0byBwYXNzIGluIG1lbWJlclRhZ3MgYW5kIHNpZ25pbmdLZXkgd2hlbiB0aGUga2V5U2V0IGlzXG4gIC8vIGJlaW5nIGNyZWF0ZWQgYW5kIGRvZXNuJ3QgeWV0IGV4aXN0LlxuICBzdGF0aWMgYXN5bmMgc2lnbihtZXNzYWdlLCB7dGFncyA9IFtdLCB0ZWFtOmlzcywgbWVtYmVyOmFjdCwgdGltZTppYXQgPSBpc3MgJiYgRGF0ZS5ub3coKSxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1lbWJlclRhZ3MsIHNpZ25pbmdLZXksXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAuLi5vcHRpb25zfSkge1xuICAgIGlmIChpc3MgJiYgIWFjdCkgeyAvLyBTdXBwbHkgdGhlIHZhbHVlXG4gICAgICBpZiAoIW1lbWJlclRhZ3MpIG1lbWJlclRhZ3MgPSAoYXdhaXQgS2V5U2V0LmVuc3VyZShpc3MpKS5tZW1iZXJUYWdzO1xuICAgICAgbGV0IGNhY2hlZE1lbWJlciA9IG1lbWJlclRhZ3MuZmluZCh0YWcgPT4gdGhpcy5jYWNoZWQodGFnKSk7XG4gICAgICBhY3QgPSBjYWNoZWRNZW1iZXIgfHwgYXdhaXQgdGhpcy5lbnN1cmUxKG1lbWJlclRhZ3MpLnRoZW4oa2V5U2V0ID0+IGtleVNldC50YWcpO1xuICAgIH1cbiAgICBpZiAoaXNzICYmICF0YWdzLmluY2x1ZGVzKGlzcykpIHRhZ3MgPSBbaXNzLCAuLi50YWdzXTsgLy8gTXVzdCBiZSBmaXJzdFxuICAgIGlmIChhY3QgJiYgIXRhZ3MuaW5jbHVkZXMoYWN0KSkgdGFncyA9IFsuLi50YWdzLCBhY3RdO1xuXG4gICAgbGV0IGtleSA9IGF3YWl0IHRoaXMucHJvZHVjZUtleSh0YWdzLCBhc3luYyB0YWcgPT4ge1xuICAgICAgLy8gVXNlIHNwZWNpZmllZCBzaWduaW5nS2V5IChpZiBhbnkpIGZvciB0aGUgZmlyc3Qgb25lLlxuICAgICAgbGV0IGtleSA9IHNpZ25pbmdLZXkgfHwgKGF3YWl0IEtleVNldC5lbnN1cmUodGFnLCBvcHRpb25zKSkuc2lnbmluZ0tleTtcbiAgICAgIHNpZ25pbmdLZXkgPSBudWxsO1xuICAgICAgcmV0dXJuIGtleTtcbiAgICB9LCBvcHRpb25zKTtcbiAgICByZXR1cm4gTXVsdGlLcnlwdG8uc2lnbihrZXksIG1lc3NhZ2UsIHtpc3MsIGFjdCwgaWF0LCAuLi5vcHRpb25zfSk7XG4gIH1cblxuICAvLyBWZXJpZnkgaW4gdGhlIG5vcm1hbCB3YXksIGFuZCB0aGVuIGNoZWNrIGRlZXBseSBpZiBhc2tlZC5cbiAgc3RhdGljIGFzeW5jIHZlcmlmeShzaWduYXR1cmUsIHRhZ3MsIG9wdGlvbnMpIHtcbiAgICBsZXQgaXNDb21wYWN0ID0gIXNpZ25hdHVyZS5zaWduYXR1cmVzLFxuICAgICAgICBrZXkgPSBhd2FpdCB0aGlzLnByb2R1Y2VLZXkodGFncywgdGFnID0+IEtleVNldC52ZXJpZnlpbmdLZXkodGFnKSwgb3B0aW9ucywgaXNDb21wYWN0KSxcbiAgICAgICAgcmVzdWx0ID0gYXdhaXQgTXVsdGlLcnlwdG8udmVyaWZ5KGtleSwgc2lnbmF0dXJlLCBvcHRpb25zKSxcbiAgICAgICAgbWVtYmVyVGFnID0gb3B0aW9ucy5tZW1iZXIgPT09IHVuZGVmaW5lZCA/IHJlc3VsdD8ucHJvdGVjdGVkSGVhZGVyLmFjdCA6IG9wdGlvbnMubWVtYmVyLFxuICAgICAgICBub3RCZWZvcmUgPSBvcHRpb25zLm5vdEJlZm9yZTtcbiAgICBmdW5jdGlvbiBleGl0KGxhYmVsKSB7XG4gICAgICBpZiAob3B0aW9ucy5oYXJkRXJyb3IpIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgRXJyb3IobGFiZWwpKTtcbiAgICB9XG4gICAgaWYgKCFyZXN1bHQpIHJldHVybiBleGl0KCdJbmNvcnJlY3Qgc2lnbmF0dXJlLicpO1xuICAgIGlmIChtZW1iZXJUYWcpIHtcbiAgICAgIGlmIChvcHRpb25zLm1lbWJlciA9PT0gJ3RlYW0nKSB7XG4gICAgICAgIG1lbWJlclRhZyA9IHJlc3VsdC5wcm90ZWN0ZUhlYWRlci5hY3Q7XG4gICAgICAgIGlmICghbWVtYmVyVGFnKSByZXR1cm4gZXhpdCgnTm8gbWVtYmVyIGlkZW50aWZpZWQgaW4gc2lnbmF0dXJlLicpO1xuICAgICAgfVxuICAgICAgaWYgKCF0YWdzLmluY2x1ZGVzKG1lbWJlclRhZykpIHsgLy8gQWRkIHRvIHRhZ3MgYW5kIHJlc3VsdCBpZiBub3QgYWxyZWFkeSBwcmVzZW50XG4gICAgICAgIGxldCBtZW1iZXJLZXkgPSBhd2FpdCBLZXlTZXQudmVyaWZ5aW5nS2V5KG1lbWJlclRhZyksXG4gICAgICAgICAgICBtZW1iZXJNdWx0aWtleSA9IHtbbWVtYmVyVGFnXTogbWVtYmVyS2V5fSxcbiAgICAgICAgICAgIGF1eCA9IGF3YWl0IE11bHRpS3J5cHRvLnZlcmlmeShtZW1iZXJNdWx0aWtleSwgc2lnbmF0dXJlLCBvcHRpb25zKTtcbiAgICAgICAgaWYgKCFhdXgpIHJldHVybiBleGl0KCdJbmNvcnJlY3QgbWVtYmVyIHNpZ25hdHVyZS4nKTtcbiAgICAgICAgdGFncy5wdXNoKG1lbWJlclRhZyk7XG4gICAgICAgIHJlc3VsdC5zaWduZXJzLmZpbmQoc2lnbmVyID0+IHNpZ25lci5wcm90ZWN0ZWRIZWFkZXIua2lkID09PSBtZW1iZXJUYWcpLnBheWxvYWQgPSByZXN1bHQucGF5bG9hZDtcbiAgICAgIH1cbiAgICB9XG4gICAgaWYgKG1lbWJlclRhZyB8fCBub3RCZWZvcmUgPT09ICd0ZWFtJykge1xuICAgICAgbGV0IHRlYW1UYWcgPSByZXN1bHQucHJvdGVjdGVkSGVhZGVyLmlzcyB8fCByZXN1bHQucHJvdGVjdGVkSGVhZGVyLmtpZCwgLy8gTXVsdGkgb3Igc2luZ2xlIGNhc2UuXG4gICAgICAgICAgdmVyaWZpZWRKV1MgPSBhd2FpdCB0aGlzLnJldHJpZXZlKFRlYW1LZXlTZXQuY29sbGVjdGlvbiwgdGVhbVRhZyksXG4gICAgICAgICAgandlID0gdmVyaWZpZWRKV1M/Lmpzb247XG4gICAgICBpZiAobWVtYmVyVGFnICYmICF0ZWFtVGFnKSByZXR1cm4gZXhpdCgnTm8gdGVhbSBvciBtYWluIHRhZyBpZGVudGlmaWVkIGluIHNpZ25hdHVyZScpO1xuICAgICAgaWYgKG1lbWJlclRhZyAmJiBqd2UgJiYgIWp3ZS5yZWNpcGllbnRzLmZpbmQobWVtYmVyID0+IG1lbWJlci5oZWFkZXIua2lkID09PSBtZW1iZXJUYWcpKSByZXR1cm4gZXhpdCgnU2lnbmVyIGlzIG5vdCBhIG1lbWJlci4nKTtcbiAgICAgIGlmIChub3RCZWZvcmUgPT09ICd0ZWFtJykgbm90QmVmb3JlID0gdmVyaWZpZWRKV1M/LnByb3RlY3RlZEhlYWRlci5pYXRcbiAgICAgICAgfHwgKGF3YWl0IHRoaXMucmV0cmlldmUoJ0VuY3J5cHRpb25LZXknLCB0ZWFtVGFnKSk/LnByb3RlY3RlZEhlYWRlci5pYXQ7XG4gICAgfVxuICAgIGlmIChub3RCZWZvcmUpIHtcbiAgICAgIGxldCB7aWF0fSA9IHJlc3VsdC5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICBpZiAoaWF0IDwgbm90QmVmb3JlKSByZXR1cm4gZXhpdCgnU2lnbmF0dXJlIHByZWRhdGVzIHJlcXVpcmVkIHRpbWVzdGFtcC4nKTtcbiAgICB9XG4gICAgLy8gRWFjaCBzaWduZXIgc2hvdWxkIG5vdyBiZSB2ZXJpZmllZC5cbiAgICBpZiAoKHJlc3VsdC5zaWduZXJzPy5maWx0ZXIoc2lnbmVyID0+IHNpZ25lci5wYXlsb2FkKS5sZW5ndGggfHwgMSkgIT09IHRhZ3MubGVuZ3RoKSByZXR1cm4gZXhpdCgnVW52ZXJpZmllZCBzaWduZXInKTtcbiAgICByZXR1cm4gcmVzdWx0O1xuICB9XG5cbiAgLy8gS2V5IG1hbmFnZW1lbnRcbiAgc3RhdGljIGFzeW5jIHByb2R1Y2VLZXkodGFncywgcHJvZHVjZXIsIG9wdGlvbnMsIHVzZVNpbmdsZUtleSA9IHRhZ3MubGVuZ3RoID09PSAxKSB7XG4gICAgLy8gUHJvbWlzZSBhIGtleSBvciBtdWx0aUtleSwgYXMgZGVmaW5lZCBieSBwcm9kdWNlcih0YWcpIGZvciBlYWNoIGtleS5cbiAgICBpZiAodXNlU2luZ2xlS2V5KSB7XG4gICAgICBsZXQgdGFnID0gdGFnc1swXTtcbiAgICAgIG9wdGlvbnMua2lkID0gdGFnOyAgIC8vIEJhc2hlcyBvcHRpb25zIGluIHRoZSBzaW5nbGUta2V5IGNhc2UsIGJlY2F1c2UgbXVsdGlLZXkncyBoYXZlIHRoZWlyIG93bi5cbiAgICAgIHJldHVybiBwcm9kdWNlcih0YWcpO1xuICAgIH1cbiAgICBsZXQga2V5ID0ge30sXG4gICAgICAgIGtleXMgPSBhd2FpdCBQcm9taXNlLmFsbCh0YWdzLm1hcCh0YWcgPT4gcHJvZHVjZXIodGFnKSkpO1xuICAgIC8vIFRoaXMgaXNuJ3QgZG9uZSBpbiBvbmUgc3RlcCwgYmVjYXVzZSB3ZSdkIGxpa2UgKGZvciBkZWJ1Z2dpbmcgYW5kIHVuaXQgdGVzdHMpIHRvIG1haW50YWluIGEgcHJlZGljdGFibGUgb3JkZXIuXG4gICAgdGFncy5mb3JFYWNoKCh0YWcsIGluZGV4KSA9PiBrZXlbdGFnXSA9IGtleXNbaW5kZXhdKTtcbiAgICByZXR1cm4ga2V5O1xuICB9XG4gIC8vIFRoZSBjb3JyZXNwb25kaW5nIHB1YmxpYyBrZXlzIGFyZSBhdmFpbGFibGUgcHVibGljYWxseSwgb3V0c2lkZSB0aGUga2V5U2V0LlxuICBzdGF0aWMgdmVyaWZ5aW5nS2V5KHRhZykgeyAvLyBQcm9taXNlIHRoZSBvcmRpbmFyeSBzaW5ndWxhciBwdWJsaWMga2V5IGNvcnJlc3BvbmRpbmcgdG8gdGhlIHNpZ25pbmcga2V5LCBkaXJlY3RseSBmcm9tIHRoZSB0YWcgd2l0aG91dCByZWZlcmVuY2UgdG8gc3RvcmFnZS5cbiAgICByZXR1cm4gTXVsdGlLcnlwdG8uaW1wb3J0UmF3KHRhZykuY2F0Y2goKCkgPT4gdW5hdmFpbGFibGUodGFnKSk7XG4gIH1cbiAgc3RhdGljIGFzeW5jIGVuY3J5cHRpbmdLZXkodGFnKSB7IC8vIFByb21pc2UgdGhlIG9yZGluYXJ5IHNpbmd1bGFyIHB1YmxpYyBrZXkgY29ycmVzcG9uZGluZyB0byB0aGUgZGVjcnlwdGlvbiBrZXksIHdoaWNoIGRlcGVuZHMgb24gcHVibGljIHN0b3JhZ2UuXG4gICAgbGV0IGV4cG9ydGVkUHVibGljS2V5ID0gYXdhaXQgdGhpcy5yZXRyaWV2ZSgnRW5jcnlwdGlvbktleScsIHRhZyk7XG4gICAgaWYgKCFleHBvcnRlZFB1YmxpY0tleSkgcmV0dXJuIHVuYXZhaWxhYmxlKHRhZyk7XG4gICAgcmV0dXJuIGF3YWl0IE11bHRpS3J5cHRvLmltcG9ydEpXSyhleHBvcnRlZFB1YmxpY0tleS5qc29uKTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgY3JlYXRlS2V5cyhtZW1iZXJUYWdzKSB7IC8vIFByb21pc2UgYSBuZXcgdGFnIGFuZCBwcml2YXRlIGtleXMsIGFuZCBzdG9yZSB0aGUgZW5jcnlwdGluZyBrZXkuXG4gICAgbGV0IHtwdWJsaWNLZXk6dmVyaWZ5aW5nS2V5LCBwcml2YXRlS2V5OnNpZ25pbmdLZXl9ID0gYXdhaXQgTXVsdGlLcnlwdG8uZ2VuZXJhdGVTaWduaW5nS2V5KCksXG4gICAgICAgIHtwdWJsaWNLZXk6ZW5jcnlwdGluZ0tleSwgcHJpdmF0ZUtleTpkZWNyeXB0aW5nS2V5fSA9IGF3YWl0IE11bHRpS3J5cHRvLmdlbmVyYXRlRW5jcnlwdGluZ0tleSgpLFxuICAgICAgICB0YWcgPSBhd2FpdCBNdWx0aUtyeXB0by5leHBvcnRSYXcodmVyaWZ5aW5nS2V5KSxcbiAgICAgICAgZXhwb3J0ZWRFbmNyeXB0aW5nS2V5ID0gYXdhaXQgTXVsdGlLcnlwdG8uZXhwb3J0SldLKGVuY3J5cHRpbmdLZXkpLFxuICAgICAgICB0aW1lID0gRGF0ZS5ub3coKSxcbiAgICAgICAgc2lnbmF0dXJlID0gYXdhaXQgdGhpcy5zaWduRm9yU3RvcmFnZSh7bWVzc2FnZTogZXhwb3J0ZWRFbmNyeXB0aW5nS2V5LCB0YWcsIHNpZ25pbmdLZXksIG1lbWJlclRhZ3MsIHRpbWUsIHJlY292ZXJ5OiB0cnVlfSk7XG4gICAgYXdhaXQgdGhpcy5zdG9yZSgnRW5jcnlwdGlvbktleScsIHRhZywgc2lnbmF0dXJlKTtcbiAgICByZXR1cm4ge3NpZ25pbmdLZXksIGRlY3J5cHRpbmdLZXksIHRhZywgdGltZX07XG4gIH1cbiAgc3RhdGljIGdldFdyYXBwZWQodGFnKSB7IC8vIFByb21pc2UgdGhlIHdyYXBwZWQga2V5IGFwcHJvcHJpYXRlIGZvciB0aGlzIGNsYXNzLlxuICAgIHJldHVybiB0aGlzLnJldHJpZXZlKHRoaXMuY29sbGVjdGlvbiwgdGFnKTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgZW5zdXJlKHRhZywge2RldmljZSA9IHRydWUsIHRlYW0gPSB0cnVlLCByZWNvdmVyeSA9IGZhbHNlfSA9IHt9KSB7IC8vIFByb21pc2UgdG8gcmVzb2x2ZSB0byBhIHZhbGlkIGtleVNldCwgZWxzZSByZWplY3QuXG4gICAgbGV0IGtleVNldCA9IHRoaXMuY2FjaGVkKHRhZyksXG4gICAgICAgIHN0b3JlZCA9IGRldmljZSAmJiBhd2FpdCBEZXZpY2VLZXlTZXQuZ2V0V3JhcHBlZCh0YWcpO1xuICAgIGlmIChzdG9yZWQpIHtcbiAgICAgIGtleVNldCA9IG5ldyBEZXZpY2VLZXlTZXQodGFnKTtcbiAgICB9IGVsc2UgaWYgKHRlYW0gJiYgKHN0b3JlZCA9IGF3YWl0IFRlYW1LZXlTZXQuZ2V0V3JhcHBlZCh0YWcpKSkge1xuICAgICAga2V5U2V0ID0gbmV3IFRlYW1LZXlTZXQodGFnKTtcbiAgICB9IGVsc2UgaWYgKHJlY292ZXJ5ICYmIChzdG9yZWQgPSBhd2FpdCBSZWNvdmVyeUtleVNldC5nZXRXcmFwcGVkKHRhZykpKSB7IC8vIExhc3QsIGlmIGF0IGFsbC5cbiAgICAgIGtleVNldCA9IG5ldyBSZWNvdmVyeUtleVNldCh0YWcpO1xuICAgIH1cbiAgICAvLyBJZiB0aGluZ3MgaGF2ZW4ndCBjaGFuZ2VkLCBkb24ndCBib3RoZXIgd2l0aCBzZXRVbndyYXBwZWQuXG4gICAgaWYgKGtleVNldD8uY2FjaGVkICYmIGtleVNldC5jYWNoZWQgPT09IHN0b3JlZCAmJiBrZXlTZXQuZGVjcnlwdGluZ0tleSAmJiBrZXlTZXQuc2lnbmluZ0tleSkgcmV0dXJuIGtleVNldDtcbiAgICBpZiAoc3RvcmVkKSBrZXlTZXQuY2FjaGVkID0gc3RvcmVkO1xuICAgIGVsc2UgeyAvLyBOb3QgZm91bmQuIENvdWxkIGJlIGEgYm9ndXMgdGFnLCBvciBvbmUgb24gYW5vdGhlciBjb21wdXRlci5cbiAgICAgIHRoaXMuY2xlYXIodGFnKTtcbiAgICAgIHJldHVybiB1bmF2YWlsYWJsZSh0YWcpO1xuICAgIH1cbiAgICByZXR1cm4ga2V5U2V0LnVud3JhcChrZXlTZXQuY2FjaGVkKS50aGVuKFxuICAgICAgdW53cmFwcGVkID0+IE9iamVjdC5hc3NpZ24oa2V5U2V0LCB1bndyYXBwZWQpLFxuICAgICAgY2F1c2UgPT4ge1xuICAgICAgICB0aGlzLmNsZWFyKGtleVNldC50YWcpXG4gICAgICAgIHJldHVybiBlcnJvcih0YWcgPT4gYFlvdSBkbyBub3QgaGF2ZSBhY2Nlc3MgdG8gdGhlIHByaXZhdGUga2V5IGZvciAke3RhZ30uYCwga2V5U2V0LnRhZywgY2F1c2UpO1xuICAgICAgfSk7XG4gIH1cbiAgc3RhdGljIGVuc3VyZTEodGFncykgeyAvLyBGaW5kIG9uZSB2YWxpZCBrZXlTZXQgYW1vbmcgdGFncywgdXNpbmcgcmVjb3ZlcnkgdGFncyBvbmx5IGlmIG5lY2Vzc2FyeS5cbiAgICByZXR1cm4gUHJvbWlzZS5hbnkodGFncy5tYXAodGFnID0+IEtleVNldC5lbnN1cmUodGFnKSkpXG4gICAgICAuY2F0Y2goYXN5bmMgcmVhc29uID0+IHsgLy8gSWYgd2UgZmFpbGVkLCB0cnkgdGhlIHJlY292ZXJ5IHRhZ3MsIGlmIGFueSwgb25lIGF0IGEgdGltZS5cbiAgICAgICAgZm9yIChsZXQgY2FuZGlkYXRlIG9mIHRhZ3MpIHtcbiAgICAgICAgICBsZXQga2V5U2V0ID0gYXdhaXQgS2V5U2V0LmVuc3VyZShjYW5kaWRhdGUsIHtkZXZpY2U6IGZhbHNlLCB0ZWFtOiBmYWxzZSwgcmVjb3Zlcnk6IHRydWV9KS5jYXRjaCgoKSA9PiBudWxsKTtcbiAgICAgICAgICBpZiAoa2V5U2V0KSByZXR1cm4ga2V5U2V0O1xuICAgICAgICB9XG4gICAgICAgIHRocm93IHJlYXNvbjtcbiAgICAgIH0pO1xuICB9XG4gIHN0YXRpYyBhc3luYyBwZXJzaXN0KHRhZywga2V5cywgd3JhcHBpbmdEYXRhLCB0aW1lID0gRGF0ZS5ub3coKSwgbWVtYmVyVGFncyA9IHdyYXBwaW5nRGF0YSkgeyAvLyBQcm9taXNlIHRvIHdyYXAgYSBzZXQgb2Yga2V5cyBmb3IgdGhlIHdyYXBwaW5nRGF0YSBtZW1iZXJzLCBhbmQgcGVyc2lzdCBieSB0YWcuXG4gICAgbGV0IHtzaWduaW5nS2V5fSA9IGtleXMsXG4gICAgICAgIHdyYXBwZWQgPSBhd2FpdCB0aGlzLndyYXAoa2V5cywgd3JhcHBpbmdEYXRhKSxcbiAgICAgICAgc2lnbmF0dXJlID0gYXdhaXQgdGhpcy5zaWduRm9yU3RvcmFnZSh7bWVzc2FnZTogd3JhcHBlZCwgdGFnLCBzaWduaW5nS2V5LCBtZW1iZXJUYWdzLCB0aW1lLCByZWNvdmVyeTogdHJ1ZX0pO1xuICAgIGF3YWl0IHRoaXMuc3RvcmUodGhpcy5jb2xsZWN0aW9uLCB0YWcsIHNpZ25hdHVyZSk7XG4gIH1cblxuICAvLyBJbnRlcmFjdGlvbnMgd2l0aCB0aGUgY2xvdWQgb3IgbG9jYWwgc3RvcmFnZS5cbiAgc3RhdGljIGFzeW5jIHN0b3JlKGNvbGxlY3Rpb25OYW1lLCB0YWcsIHNpZ25hdHVyZSkgeyAvLyBTdG9yZSBzaWduYXR1cmUuXG4gICAgaWYgKGNvbGxlY3Rpb25OYW1lID09PSBEZXZpY2VLZXlTZXQuY29sbGVjdGlvbikge1xuICAgICAgLy8gV2UgY2FsbGVkIHRoaXMuIE5vIG5lZWQgdG8gdmVyaWZ5IGhlcmUuIEJ1dCBzZWUgcmV0cmlldmUoKS5cbiAgICAgIGlmIChNdWx0aUtyeXB0by5pc0VtcHR5SldTUGF5bG9hZChzaWduYXR1cmUpKSByZXR1cm4gTG9jYWxTdG9yZS5yZW1vdmUodGFnKTtcbiAgICAgIHJldHVybiBMb2NhbFN0b3JlLnN0b3JlKHRhZywgc2lnbmF0dXJlKTtcbiAgICB9XG4gICAgcmV0dXJuIEtleVNldC5TdG9yYWdlLnN0b3JlKGNvbGxlY3Rpb25OYW1lLCB0YWcsIHNpZ25hdHVyZSk7XG4gIH1cbiAgc3RhdGljIGFzeW5jIHJldHJpZXZlKGNvbGxlY3Rpb25OYW1lLCB0YWcpIHsgIC8vIEdldCBiYWNrIGEgdmVyaWZpZWQgcmVzdWx0LlxuICAgIGxldCBwcm9taXNlID0gKGNvbGxlY3Rpb25OYW1lID09PSBEZXZpY2VLZXlTZXQuY29sbGVjdGlvbikgPyBMb2NhbFN0b3JlLnJldHJpZXZlKHRhZykgOiBLZXlTZXQuU3RvcmFnZS5yZXRyaWV2ZShjb2xsZWN0aW9uTmFtZSwgdGFnKSxcbiAgICAgICAgc2lnbmF0dXJlID0gYXdhaXQgcHJvbWlzZSxcbiAgICAgICAga2V5ID0gc2lnbmF0dXJlICYmIGF3YWl0IEtleVNldC52ZXJpZnlpbmdLZXkodGFnKTtcbiAgICBpZiAoIXNpZ25hdHVyZSkgcmV0dXJuO1xuICAgIC8vIFdoaWxlIHdlIHJlbHkgb24gdGhlIFN0b3JhZ2UgYW5kIExvY2FsU3RvcmUgaW1wbGVtZW50YXRpb25zIHRvIGRlZXBseSBjaGVjayBzaWduYXR1cmVzIGR1cmluZyB3cml0ZSxcbiAgICAvLyBoZXJlIHdlIHN0aWxsIGRvIGEgc2hhbGxvdyB2ZXJpZmljYXRpb24gY2hlY2sganVzdCB0byBtYWtlIHN1cmUgdGhhdCB0aGUgZGF0YSBoYXNuJ3QgYmVlbiBtZXNzZWQgd2l0aCBhZnRlciB3cml0ZS5cbiAgICBpZiAoc2lnbmF0dXJlLnNpZ25hdHVyZXMpIGtleSA9IHtbdGFnXToga2V5fTsgLy8gUHJlcGFyZSBhIG11bHRpLWtleVxuICAgIHJldHVybiBhd2FpdCBNdWx0aUtyeXB0by52ZXJpZnkoa2V5LCBzaWduYXR1cmUpO1xuICB9XG59XG5cbmV4cG9ydCBjbGFzcyBTZWNyZXRLZXlTZXQgZXh0ZW5kcyBLZXlTZXQgeyAvLyBLZXlzIGFyZSBlbmNyeXB0ZWQgYmFzZWQgb24gYSBzeW1tZXRyaWMgc2VjcmV0LlxuICBzdGF0aWMgc2lnbkZvclN0b3JhZ2Uoe21lc3NhZ2UsIHRhZywgc2lnbmluZ0tleSwgdGltZX0pIHtcbiAgICAvLyBDcmVhdGUgYSBzaW1wbGUgc2lnbmF0dXJlIHRoYXQgZG9lcyBub3Qgc3BlY2lmeSBpc3Mgb3IgYWN0LlxuICAgIC8vIFRoZXJlIGFyZSBubyB0cnVlIG1lbWJlclRhZ3MgdG8gcGFzcyBvbiBhbmQgdGhleSBhcmUgbm90IHVzZWQgaW4gc2ltcGxlIHNpZ25hdHVyZXMuIEhvd2V2ZXIsIHRoZSBjYWxsZXIgZG9lc1xuICAgIC8vIGdlbmVyaWNhbGx5IHBhc3Mgd3JhcHBpbmdEYXRhIGFzIG1lbWJlclRhZ3MsIGFuZCBmb3IgUmVjb3ZlcnlLZXlTZXRzLCB3cmFwcGluZ0RhdGEgaXMgdGhlIHByb21wdC4gXG4gICAgLy8gV2UgZG9uJ3Qgc3RvcmUgbXVsdGlwbGUgdGltZXMsIHNvIHRoZXJlJ3MgYWxzbyBubyBuZWVkIGZvciBpYXQgKHdoaWNoIGNhbiBiZSB1c2VkIHRvIHByZXZlbnQgcmVwbGF5IGF0dGFja3MpLlxuICAgIHJldHVybiB0aGlzLnNpZ24obWVzc2FnZSwge3RhZ3M6IFt0YWddLCBzaWduaW5nS2V5LCB0aW1lfSk7XG4gIH1cbiAgc3RhdGljIGFzeW5jIHdyYXBwaW5nS2V5KHRhZywgcHJvbXB0KSB7IC8vIFRoZSBrZXkgdXNlZCB0byAodW4pd3JhcCB0aGUgdmF1bHQgbXVsdGkta2V5LlxuICAgIGxldCBzZWNyZXQgPSAgYXdhaXQgdGhpcy5nZXRTZWNyZXQodGFnLCBwcm9tcHQpO1xuICAgIC8vIEFsdGVybmF0aXZlbHksIG9uZSBjb3VsZCB1c2Uge1t3cmFwcGluZ0RhdGFdOiBzZWNyZXR9LCBidXQgdGhhdCdzIGEgYml0IHRvbyBjdXRlLCBhbmQgZ2VuZXJhdGVzIGEgZ2VuZXJhbCBmb3JtIGVuY3J5cHRpb24uXG4gICAgLy8gVGhpcyB2ZXJzaW9uIGdlbmVyYXRlcyBhIGNvbXBhY3QgZm9ybSBlbmNyeXB0aW9uLlxuICAgIHJldHVybiBNdWx0aUtyeXB0by5nZW5lcmF0ZVNlY3JldEtleShzZWNyZXQpO1xuICB9XG4gIHN0YXRpYyBhc3luYyB3cmFwKGtleXMsIHByb21wdCA9ICcnKSB7IC8vIEVuY3J5cHQga2V5c2V0IGJ5IGdldFVzZXJEZXZpY2VTZWNyZXQuXG4gICAgbGV0IHtkZWNyeXB0aW5nS2V5LCBzaWduaW5nS2V5LCB0YWd9ID0ga2V5cyxcbiAgICAgICAgdmF1bHRLZXkgPSB7ZGVjcnlwdGluZ0tleSwgc2lnbmluZ0tleX0sXG4gICAgICAgIHdyYXBwaW5nS2V5ID0gYXdhaXQgdGhpcy53cmFwcGluZ0tleSh0YWcsIHByb21wdCk7XG4gICAgcmV0dXJuIE11bHRpS3J5cHRvLndyYXBLZXkodmF1bHRLZXksIHdyYXBwaW5nS2V5LCB7cHJvbXB0fSk7IC8vIE9yZGVyIGlzIGJhY2t3YXJkcyBmcm9tIGVuY3J5cHQuXG4gIH1cbiAgYXN5bmMgdW53cmFwKHdyYXBwZWRLZXkpIHsgLy8gRGVjcnlwdCBrZXlzZXQgYnkgZ2V0VXNlckRldmljZVNlY3JldC5cbiAgICBsZXQgcGFyc2VkID0gd3JhcHBlZEtleS5qc29uIHx8IHdyYXBwZWRLZXkudGV4dCwgLy8gSGFuZGxlIGJvdGgganNvbiBhbmQgY29wYWN0IGZvcm1zIG9mIHdyYXBwZWRLZXkuXG5cbiAgICAgICAgLy8gVGhlIGNhbGwgdG8gd3JhcEtleSwgYWJvdmUsIGV4cGxpY2l0bHkgZGVmaW5lcyB0aGUgcHJvbXB0IGluIHRoZSBoZWFkZXIgb2YgdGhlIGVuY3J5cHRpb24uXG4gICAgICAgIHByb3RlY3RlZEhlYWRlciA9IE11bHRpS3J5cHRvLmRlY29kZVByb3RlY3RlZEhlYWRlcihwYXJzZWQpLFxuICAgICAgICBwcm9tcHQgPSBwcm90ZWN0ZWRIZWFkZXIucHJvbXB0LCAvLyBJbiB0aGUgXCJjdXRlXCIgZm9ybSBvZiB3cmFwcGluZ0tleSwgcHJvbXB0IGNhbiBiZSBwdWxsZWQgZnJvbSBwYXJzZWQucmVjaXBpZW50c1swXS5oZWFkZXIua2lkLFxuXG4gICAgICAgIHdyYXBwaW5nS2V5ID0gYXdhaXQgdGhpcy5jb25zdHJ1Y3Rvci53cmFwcGluZ0tleSh0aGlzLnRhZywgcHJvbXB0KSxcbiAgICAgICAgZXhwb3J0ZWQgPSAoYXdhaXQgTXVsdGlLcnlwdG8uZGVjcnlwdCh3cmFwcGluZ0tleSwgcGFyc2VkKSkuanNvbjtcbiAgICByZXR1cm4gYXdhaXQgTXVsdGlLcnlwdG8uaW1wb3J0SldLKGV4cG9ydGVkLCB7ZGVjcnlwdGluZ0tleTogJ2RlY3J5cHQnLCBzaWduaW5nS2V5OiAnc2lnbid9KTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgZ2V0U2VjcmV0KHRhZywgcHJvbXB0KSB7IC8vIGdldFVzZXJEZXZpY2VTZWNyZXQgZnJvbSBhcHAuXG4gICAgcmV0dXJuIEtleVNldC5nZXRVc2VyRGV2aWNlU2VjcmV0KHRhZywgcHJvbXB0KTtcbiAgfVxufVxuXG4gLy8gVGhlIHVzZXIncyBhbnN3ZXIocykgdG8gYSBzZWN1cml0eSBxdWVzdGlvbiBmb3JtcyBhIHNlY3JldCwgYW5kIHRoZSB3cmFwcGVkIGtleXMgaXMgc3RvcmVkIGluIHRoZSBjbG91ZGUuXG5leHBvcnQgY2xhc3MgUmVjb3ZlcnlLZXlTZXQgZXh0ZW5kcyBTZWNyZXRLZXlTZXQge1xuICBzdGF0aWMgY29sbGVjdGlvbiA9ICdLZXlSZWNvdmVyeSc7XG59XG5cbi8vIEEgS2V5U2V0IGNvcnJlc3BvbmRpbmcgdG8gdGhlIGN1cnJlbnQgaGFyZHdhcmUuIFdyYXBwaW5nIHNlY3JldCBjb21lcyBmcm9tIHRoZSBhcHAuXG5leHBvcnQgY2xhc3MgRGV2aWNlS2V5U2V0IGV4dGVuZHMgU2VjcmV0S2V5U2V0IHtcbiAgc3RhdGljIGNvbGxlY3Rpb24gPSAnRGV2aWNlJztcbn1cbmNvbnN0IExvY2FsU3RvcmUgPSBuZXcgTG9jYWxDb2xsZWN0aW9uKHtjb2xsZWN0aW9uTmFtZTogRGV2aWNlS2V5U2V0LmNvbGxlY3Rpb259KTtcblxuZXhwb3J0IGNsYXNzIFRlYW1LZXlTZXQgZXh0ZW5kcyBLZXlTZXQgeyAvLyBBIEtleVNldCBjb3JyZXNwb25kaW5nIHRvIGEgdGVhbSBvZiB3aGljaCB0aGUgY3VycmVudCB1c2VyIGlzIGEgbWVtYmVyIChpZiBnZXRUYWcoKSkuXG4gIHN0YXRpYyBjb2xsZWN0aW9uID0gJ1RlYW0nO1xuICBzdGF0aWMgc2lnbkZvclN0b3JhZ2Uoe21lc3NhZ2UsIHRhZywgLi4ub3B0aW9uc30pIHtcbiAgICByZXR1cm4gdGhpcy5zaWduKG1lc3NhZ2UsIHt0ZWFtOiB0YWcsIC4uLm9wdGlvbnN9KTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgd3JhcChrZXlzLCBtZW1iZXJzKSB7XG4gICAgLy8gVGhpcyBpcyB1c2VkIGJ5IHBlcnNpc3QsIHdoaWNoIGluIHR1cm4gaXMgdXNlZCB0byBjcmVhdGUgYW5kIGNoYW5nZU1lbWJlcnNoaXAuXG4gICAgbGV0IHtkZWNyeXB0aW5nS2V5LCBzaWduaW5nS2V5fSA9IGtleXMsXG4gICAgICAgIHRlYW1LZXkgPSB7ZGVjcnlwdGluZ0tleSwgc2lnbmluZ0tleX0sXG4gICAgICAgIHdyYXBwaW5nS2V5ID0ge307XG4gICAgYXdhaXQgUHJvbWlzZS5hbGwobWVtYmVycy5tYXAobWVtYmVyVGFnID0+IEtleVNldC5lbmNyeXB0aW5nS2V5KG1lbWJlclRhZykudGhlbihrZXkgPT4gd3JhcHBpbmdLZXlbbWVtYmVyVGFnXSA9IGtleSkpKTtcbiAgICBsZXQgd3JhcHBlZFRlYW0gPSBhd2FpdCBNdWx0aUtyeXB0by53cmFwS2V5KHRlYW1LZXksIHdyYXBwaW5nS2V5KTtcbiAgICByZXR1cm4gd3JhcHBlZFRlYW07XG4gIH1cbiAgYXN5bmMgdW53cmFwKHdyYXBwZWQpIHtcbiAgICBsZXQge3JlY2lwaWVudHN9ID0gd3JhcHBlZC5qc29uLFxuICAgICAgICBtZW1iZXJUYWdzID0gdGhpcy5tZW1iZXJUYWdzID0gcmVjaXBpZW50cy5tYXAocmVjaXBpZW50ID0+IHJlY2lwaWVudC5oZWFkZXIua2lkKTtcbiAgICBsZXQga2V5U2V0ID0gYXdhaXQgdGhpcy5jb25zdHJ1Y3Rvci5lbnN1cmUxKG1lbWJlclRhZ3MpOyAvLyBXZSB3aWxsIHVzZSByZWNvdmVyeSB0YWdzIG9ubHkgaWYgd2UgbmVlZCB0by5cbiAgICBsZXQgZGVjcnlwdGVkID0gYXdhaXQga2V5U2V0LmRlY3J5cHQod3JhcHBlZC5qc29uKTtcbiAgICByZXR1cm4gYXdhaXQgTXVsdGlLcnlwdG8uaW1wb3J0SldLKGRlY3J5cHRlZC5qc29uKTtcbiAgfVxuICBhc3luYyBjaGFuZ2VNZW1iZXJzaGlwKHthZGQgPSBbXSwgcmVtb3ZlID0gW119ID0ge30pIHtcbiAgICBsZXQge21lbWJlclRhZ3N9ID0gdGhpcyxcbiAgICAgICAgbmV3TWVtYmVycyA9IG1lbWJlclRhZ3MuY29uY2F0KGFkZCkuZmlsdGVyKHRhZyA9PiAhcmVtb3ZlLmluY2x1ZGVzKHRhZykpO1xuICAgIGF3YWl0IHRoaXMuY29uc3RydWN0b3IucGVyc2lzdCh0aGlzLnRhZywgdGhpcywgbmV3TWVtYmVycywgRGF0ZS5ub3coKSwgbWVtYmVyVGFncyk7XG4gICAgdGhpcy5tZW1iZXJUYWdzID0gbmV3TWVtYmVycztcbiAgfVxufVxuIiwiLy8gSSdkIGxvdmUgdG8gdXNlIHRoaXMsIGJ1dCBpdCBpc24ndCBzdXBwb3J0ZWQgYWNyb3NzIGVub3VnaCBOb2RlIGFuZCBlc2xpbnQgdmVyc2lvbnMuXG4vLyBpbXBvcnQgKiBhcyBwa2cgZnJvbSBcIi4uL3BhY2thZ2UuanNvblwiIHdpdGggeyB0eXBlOiAnanNvbicgfTtcbi8vIGV4cG9ydCBjb25zdCB7bmFtZSwgdmVyc2lvbn0gPSBwa2cuZGVmYXVsdDtcblxuLy8gU28ganVzdCBoYXJkY29kZSBhbmQga2VlcCB1cGRhdGluZy4gU2lnaC5cbmV4cG9ydCBjb25zdCBuYW1lID0gJ0BraTFyMHkvZGlzdHJpYnV0ZWQtc2VjdXJpdHknO1xuZXhwb3J0IGNvbnN0IHZlcnNpb24gPSAnMS4wLjMnO1xuIiwiaW1wb3J0IE11bHRpS3J5cHRvIGZyb20gXCIuL211bHRpS3J5cHRvLm1qc1wiO1xuaW1wb3J0IHtLZXlTZXQsIERldmljZUtleVNldCwgUmVjb3ZlcnlLZXlTZXQsIFRlYW1LZXlTZXR9IGZyb20gXCIuL2tleVNldC5tanNcIjtcbmltcG9ydCB7bmFtZSwgdmVyc2lvbn0gZnJvbSBcIi4vcGFja2FnZS1sb2FkZXIubWpzXCI7XG5cbmNvbnN0IFNlY3VyaXR5ID0geyAvLyBUaGlzIGlzIHRoZSBhcGkgZm9yIHRoZSB2YXVsdC4gU2VlIGh0dHBzOi8va2lscm95LWNvZGUuZ2l0aHViLmlvL2Rpc3RyaWJ1dGVkLXNlY3VyaXR5L2RvY3MvaW1wbGVtZW50YXRpb24uaHRtbCNjcmVhdGluZy10aGUtdmF1bHQtd2ViLXdvcmtlci1hbmQtaWZyYW1lXG5cbiAgLy8gQ2xpZW50LWRlZmluZWQgcmVzb3VyY2VzLlxuICBzZXQgU3RvcmFnZShzdG9yYWdlKSB7IC8vIEFsbG93cyBhIG5vZGUgYXBwIChubyB2YXVsdHQpIHRvIG92ZXJyaWRlIHRoZSBkZWZhdWx0IHN0b3JhZ2UuXG4gICAgS2V5U2V0LlN0b3JhZ2UgPSBzdG9yYWdlO1xuICB9LFxuICBnZXQgU3RvcmFnZSgpIHsgLy8gQWxsb3dzIGEgbm9kZSBhcHAgKG5vIHZhdWx0KSB0byBleGFtaW5lIHN0b3JhZ2UuXG4gICAgcmV0dXJuIEtleVNldC5TdG9yYWdlO1xuICB9LFxuICBzZXQgZ2V0VXNlckRldmljZVNlY3JldChmdW5jdGlvbk9mVGFnQW5kUHJvbXB0KSB7ICAvLyBBbGxvd3MgYSBub2RlIGFwcCAobm8gdmF1bHQpIHRvIG92ZXJyaWRlIHRoZSBkZWZhdWx0LlxuICAgIEtleVNldC5nZXRVc2VyRGV2aWNlU2VjcmV0ID0gZnVuY3Rpb25PZlRhZ0FuZFByb21wdDtcbiAgfSxcbiAgZ2V0IGdldFVzZXJEZXZpY2VTZWNyZXQoKSB7XG4gICAgcmV0dXJuIEtleVNldC5nZXRVc2VyRGV2aWNlU2VjcmV0O1xuICB9LFxuICByZWFkeToge25hbWUsIHZlcnNpb24sIG9yaWdpbjogS2V5U2V0LlN0b3JhZ2Uub3JpZ2lufSxcblxuICAvLyBUaGUgZm91ciBiYXNpYyBvcGVyYXRpb25zLiAuLi5yZXN0IG1heSBiZSBvbmUgb3IgbW9yZSB0YWdzLCBvciBtYXkgYmUge3RhZ3MsIHRlYW0sIG1lbWJlciwgY29udGVudFR5cGUsIC4uLn1cbiAgYXN5bmMgZW5jcnlwdChtZXNzYWdlLCAuLi5yZXN0KSB7IC8vIFByb21pc2UgYSBKV0UuXG4gICAgbGV0IG9wdGlvbnMgPSB7fSwgdGFncyA9IHRoaXMuY2Fub25pY2FsaXplUGFyYW1ldGVycyhyZXN0LCBvcHRpb25zKSxcbiAgICAgICAga2V5ID0gYXdhaXQgS2V5U2V0LnByb2R1Y2VLZXkodGFncywgdGFnID0+IEtleVNldC5lbmNyeXB0aW5nS2V5KHRhZyksIG9wdGlvbnMpO1xuICAgIHJldHVybiBNdWx0aUtyeXB0by5lbmNyeXB0KGtleSwgbWVzc2FnZSwgb3B0aW9ucyk7XG4gIH0sXG4gIGFzeW5jIGRlY3J5cHQoZW5jcnlwdGVkLCAuLi5yZXN0KSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259IGFzIGFwcHJvcHJpYXRlLlxuICAgIGxldCBvcHRpb25zID0ge30sXG4gICAgICAgIFt0YWddID0gdGhpcy5jYW5vbmljYWxpemVQYXJhbWV0ZXJzKHJlc3QsIG9wdGlvbnMsIGVuY3J5cHRlZCksXG4gICAgICAgIHtyZWNvdmVyeSwgLi4ub3RoZXJPcHRpb25zfSA9IG9wdGlvbnMsXG4gICAgICAgIGtleVNldCA9IGF3YWl0IEtleVNldC5lbnN1cmUodGFnLCB7cmVjb3Zlcnl9KTtcbiAgICByZXR1cm4ga2V5U2V0LmRlY3J5cHQoZW5jcnlwdGVkLCBvdGhlck9wdGlvbnMpO1xuICB9LFxuICBhc3luYyBzaWduKG1lc3NhZ2UsIC4uLnJlc3QpIHsgLy8gUHJvbWlzZSBhIEpXUy5cbiAgICBsZXQgb3B0aW9ucyA9IHt9LCB0YWdzID0gdGhpcy5jYW5vbmljYWxpemVQYXJhbWV0ZXJzKHJlc3QsIG9wdGlvbnMpO1xuICAgIHJldHVybiBLZXlTZXQuc2lnbihtZXNzYWdlLCB7dGFncywgLi4ub3B0aW9uc30pO1xuICB9LFxuICBhc3luYyB2ZXJpZnkoc2lnbmF0dXJlLCAuLi5yZXN0KSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259IGFzIGFwcHJvcHJpYXRlLlxuICAgIGxldCBvcHRpb25zID0ge30sIHRhZ3MgPSB0aGlzLmNhbm9uaWNhbGl6ZVBhcmFtZXRlcnMocmVzdCwgb3B0aW9ucywgc2lnbmF0dXJlKTtcbiAgICByZXR1cm4gS2V5U2V0LnZlcmlmeShzaWduYXR1cmUsIHRhZ3MsIG9wdGlvbnMpO1xuICB9LFxuXG4gIC8vIFRhZyBtYWludGFuY2UuXG4gIGFzeW5jIGNyZWF0ZSguLi5tZW1iZXJzKSB7IC8vIFByb21pc2UgYSBuZXdseS1jcmVhdGVkIHRhZyB3aXRoIHRoZSBnaXZlbiBtZW1iZXJzLiBUaGUgbWVtYmVyIHRhZ3MgKGlmIGFueSkgbXVzdCBhbHJlYWR5IGV4aXN0LlxuICAgIGlmICghbWVtYmVycy5sZW5ndGgpIHJldHVybiBhd2FpdCBEZXZpY2VLZXlTZXQuY3JlYXRlKCk7XG4gICAgbGV0IHByb21wdCA9IG1lbWJlcnNbMF0ucHJvbXB0O1xuICAgIGlmIChwcm9tcHQpIHJldHVybiBhd2FpdCBSZWNvdmVyeUtleVNldC5jcmVhdGUocHJvbXB0KTtcbiAgICByZXR1cm4gYXdhaXQgVGVhbUtleVNldC5jcmVhdGUobWVtYmVycyk7XG4gIH0sXG4gIGFzeW5jIGNoYW5nZU1lbWJlcnNoaXAoe3RhZywgcmVjb3ZlcnkgPSBmYWxzZSwgLi4ub3B0aW9uc30pIHsgLy8gUHJvbWlzZSB0byBhZGQgb3IgcmVtb3ZlIG1lbWJlcnMuXG4gICAgbGV0IGtleVNldCA9IGF3YWl0IEtleVNldC5lbnN1cmUodGFnLCB7cmVjb3ZlcnksIC4uLm9wdGlvbnN9KTsgLy8gTWFrZXMgbm8gc2Vuc2UgdG8gY2hhbmdlTWVtYmVyc2hpcCBvZiBhIHJlY292ZXJ5IGtleS5cbiAgICByZXR1cm4ga2V5U2V0LmNoYW5nZU1lbWJlcnNoaXAob3B0aW9ucyk7XG4gIH0sXG4gIGFzeW5jIGRlc3Ryb3kodGFnT3JPcHRpb25zKSB7IC8vIFByb21pc2UgdG8gcmVtb3ZlIHRoZSB0YWcgYW5kIGFueSBhc3NvY2lhdGVkIGRhdGEgZnJvbSBhbGwgc3RvcmFnZS5cbiAgICBpZiAoJ3N0cmluZycgPT09IHR5cGVvZiB0YWdPck9wdGlvbnMpIHRhZ09yT3B0aW9ucyA9IHt0YWc6IHRhZ09yT3B0aW9uc307XG4gICAgbGV0IHt0YWcsIHJlY292ZXJ5ID0gdHJ1ZSwgLi4ub3RoZXJPcHRpb25zfSA9IHRhZ09yT3B0aW9ucyxcbiAgICAgICAgb3B0aW9ucyA9IHtyZWNvdmVyeSwgLi4ub3RoZXJPcHRpb25zfSxcbiAgICAgICAga2V5U2V0ID0gYXdhaXQgS2V5U2V0LmVuc3VyZSh0YWcsIG9wdGlvbnMpO1xuICAgIHJldHVybiBrZXlTZXQuZGVzdHJveShvcHRpb25zKTtcbiAgfSxcbiAgY2xlYXIodGFnKSB7IC8vIFJlbW92ZSBhbnkgbG9jYWxseSBjYWNoZWQgS2V5U2V0IGZvciB0aGUgdGFnLCBvciBhbGwgS2V5U2V0cyBpZiBub3QgdGFnIHNwZWNpZmllZC5cbiAgICBLZXlTZXQuY2xlYXIodGFnKTtcbiAgfSxcblxuICBkZWNvZGVQcm90ZWN0ZWRIZWFkZXI6IE11bHRpS3J5cHRvLmRlY29kZVByb3RlY3RlZEhlYWRlcixcbiAgY2Fub25pY2FsaXplUGFyYW1ldGVycyhyZXN0LCBvcHRpb25zLCB0b2tlbikgeyAvLyBSZXR1cm4gdGhlIGFjdHVhbCBsaXN0IG9mIHRhZ3MsIGFuZCBiYXNoIG9wdGlvbnMuXG4gICAgLy8gcmVzdCBtYXkgYmUgYSBsaXN0IG9mIHRhZyBzdHJpbmdzXG4gICAgLy8gICAgb3IgYSBsaXN0IG9mIG9uZSBzaW5nbGUgb2JqZWN0IHNwZWNpZnlpbmcgbmFtZWQgcGFyYW1ldGVycywgaW5jbHVkaW5nIGVpdGhlciB0ZWFtLCB0YWdzLCBvciBuZWl0aGVyXG4gICAgLy8gdG9rZW4gbWF5IGJlIGEgSldFIG9yIEpTRSwgb3IgZmFsc3ksIGFuZCBpcyB1c2VkIHRvIHN1cHBseSB0YWdzIGlmIG5lY2Vzc2FyeS5cbiAgICBpZiAocmVzdC5sZW5ndGggPiAxIHx8IHJlc3RbMF0/Lmxlbmd0aCAhPT0gdW5kZWZpbmVkKSByZXR1cm4gcmVzdDtcbiAgICBsZXQge3RhZ3MgPSBbXSwgY29udGVudFR5cGUsIHRpbWUsIC4uLm90aGVyc30gPSByZXN0WzBdIHx8IHt9LFxuXHR7dGVhbX0gPSBvdGhlcnM7IC8vIERvIG5vdCBzdHJpcCB0ZWFtIGZyb20gb3RoZXJzLlxuICAgIGlmICghdGFncy5sZW5ndGgpIHtcbiAgICAgIGlmIChyZXN0Lmxlbmd0aCAmJiByZXN0WzBdLmxlbmd0aCkgdGFncyA9IHJlc3Q7IC8vIHJlc3Qgbm90IGVtcHR5LCBhbmQgaXRzIGZpcnN0IGlzIHN0cmluZy1saWtlLlxuICAgICAgZWxzZSBpZiAodG9rZW4pIHsgLy8gZ2V0IGZyb20gdG9rZW5cbiAgICAgICAgaWYgKHRva2VuLnNpZ25hdHVyZXMpIHRhZ3MgPSB0b2tlbi5zaWduYXR1cmVzLm1hcChzaWcgPT4gdGhpcy5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIoc2lnKS5raWQpO1xuICAgICAgICBlbHNlIGlmICh0b2tlbi5yZWNpcGllbnRzKSB0YWdzID0gdG9rZW4ucmVjaXBpZW50cy5tYXAocmVjID0+IHJlYy5oZWFkZXIua2lkKTtcbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgbGV0IGtpZCA9IHRoaXMuZGVjb2RlUHJvdGVjdGVkSGVhZGVyKHRva2VuKS5raWQ7IC8vIGNvbXBhY3QgdG9rZW5cbiAgICAgICAgICBpZiAoa2lkKSB0YWdzID0gW2tpZF07XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gICAgaWYgKHRlYW0gJiYgIXRhZ3MuaW5jbHVkZXModGVhbSkpIHRhZ3MgPSBbdGVhbSwgLi4udGFnc107XG4gICAgaWYgKGNvbnRlbnRUeXBlKSBvcHRpb25zLmN0eSA9IGNvbnRlbnRUeXBlO1xuICAgIGlmICh0aW1lKSBvcHRpb25zLmlhdCA9IHRpbWU7XG4gICAgT2JqZWN0LmFzc2lnbihvcHRpb25zLCBvdGhlcnMpO1xuXG4gICAgcmV0dXJuIHRhZ3M7XG4gIH1cbn07XG5cbmV4cG9ydCBkZWZhdWx0IFNlY3VyaXR5O1xuIiwiXG5mdW5jdGlvbiB0cmFuc2ZlcnJhYmxlRXJyb3IoZXJyb3IpIHsgLy8gQW4gZXJyb3Igb2JqZWN0IHRoYXQgd2UgcmVjZWl2ZSBvbiBvdXIgc2lkZSBtaWdodCBub3QgYmUgdHJhbnNmZXJyYWJsZSB0byB0aGUgb3RoZXIuXG4gIGxldCB7bmFtZSwgbWVzc2FnZSwgY29kZSwgZGF0YX0gPSBlcnJvcjtcbiAgcmV0dXJuIHtuYW1lLCBtZXNzYWdlLCBjb2RlLCBkYXRhfTtcbn1cblxuLy8gU2V0IHVwIGJpZGlyZWN0aW9uYWwgY29tbXVuY2F0aW9ucyB3aXRoIHRhcmdldCwgcmV0dXJuaW5nIGEgZnVuY3Rpb24gKG1ldGhvZE5hbWUsIC4uLnBhcmFtcykgdGhhdCB3aWxsIHNlbmQgdG8gdGFyZ2V0LlxuZnVuY3Rpb24gZGlzcGF0Y2goe3RhcmdldCA9IHNlbGYsICAgICAgICAvLyBUaGUgd2luZG93LCB3b3JrZXIsIG9yIG90aGVyIG9iamVjdCB0byB3aGljaCB3ZSB3aWxsIHBvc3RNZXNzYWdlLlxuXHRcdCAgIHJlY2VpdmVyID0gdGFyZ2V0LCAgICAvLyBUaGUgd2luZG93LCB3b3JrZXIsIG9yIG90aGVyIG9iamVjdCBvZiB3aGljaCBXRSB3aWxsIGhhbmRsZSAnbWVzc2FnZScgZXZlbnRzIGZyb20gdGFyZ2V0LlxuXHRcdCAgIG5hbWVzcGFjZSA9IHJlY2VpdmVyLCAvLyBBbiBvYmplY3QgdGhhdCBkZWZpbmVzIGFueSBtZXRob2RzIHRoYXQgbWF5IGJlIHJlcXVlc3RlZCBieSB0YXJnZXQuXG5cblx0XHQgICBvcmlnaW4gPSAoKHRhcmdldCAhPT0gcmVjZWl2ZXIpICYmIHRhcmdldC5sb2NhdGlvbi5vcmlnaW4pLFxuXG5cdFx0ICAgZGlzcGF0Y2hlckxhYmVsID0gbmFtZXNwYWNlLm5hbWUgfHwgcmVjZWl2ZXIubmFtZSB8fCByZWNlaXZlci5sb2NhdGlvbj8uaHJlZiB8fCByZWNlaXZlcixcblx0XHQgICB0YXJnZXRMYWJlbCA9IHRhcmdldC5uYW1lIHx8IG9yaWdpbiB8fCB0YXJnZXQubG9jYXRpb24/LmhyZWYgfHwgdGFyZ2V0LFxuXG5cdFx0ICAgbG9nID0gbnVsbCxcblx0XHQgICBpbmZvOmxvZ2luZm8gPSBjb25zb2xlLmluZm8uYmluZChjb25zb2xlKSxcblx0XHQgICB3YXJuOmxvZ3dhcm4gPSBjb25zb2xlLndhcm4uYmluZChjb25zb2xlKSxcblx0XHQgICBlcnJvcjpsb2dlcnJvciA9IGNvbnNvbGUuZXJyb3IuYmluZChjb25zb2xlKVxuXHRcdCAgfSkge1xuICBjb25zdCByZXF1ZXN0cyA9IHt9LFxuICAgICAgICBqc29ucnBjID0gJzIuMCcsXG4gICAgICAgIGNhcHR1cmVkUG9zdCA9IHRhcmdldC5wb3N0TWVzc2FnZS5iaW5kKHRhcmdldCksIC8vIEluIGNhc2UgKG1hbGljaW91cykgY29kZSBsYXRlciBjaGFuZ2VzIGl0LlxuICAgICAgICAvLyB3aW5kb3cucG9zdE1lc3NhZ2UgYW5kIGZyaWVuZHMgdGFrZXMgYSB0YXJnZXRPcmlnaW4gdGhhdCB3ZSBzdXBwbHkuXG4gICAgICAgIC8vIEJ1dCB3b3JrZXIucG9zdE1lc3NhZ2UgZ2l2ZXMgZXJyb3IgcmF0aGVyIHRoYW4gaWdub3JpbmcgdGhlIGV4dHJhIGFyZy4gU28gc2V0IHRoZSByaWdodCBmb3JtIGF0IGluaXRpYWxpemF0aW9uLlxuICAgICAgICBwb3N0ID0gb3JpZ2luID8gbWVzc2FnZSA9PiBjYXB0dXJlZFBvc3QobWVzc2FnZSwgb3JpZ2luKSA6IGNhcHR1cmVkUG9zdCxcbiAgICAgICAgbnVsbExvZyA9ICgpID0+IHt9O1xuICBsZXQgbWVzc2FnZUlkID0gMDsgLy8gcHJlLWluY3JlbWVudGVkIGlkIHN0YXJ0cyBhdCAxLlxuXG4gIGZ1bmN0aW9uIHJlcXVlc3QobWV0aG9kLCAuLi5wYXJhbXMpIHsgLy8gUHJvbWlzZSB0aGUgcmVzdWx0IG9mIG1ldGhvZCguLi5wYXJhbXMpIGluIHRhcmdldC5cbiAgICAvLyBXZSBkbyBhIHRhcmdldC5wb3N0TWVzc2FnZSBvZiBhIGpzb25ycGMgcmVxdWVzdCwgYW5kIHJlc29sdmUgdGhlIHByb21pc2Ugd2l0aCB0aGUgcmVzcG9uc2UsIG1hdGNoZWQgYnkgaWQuXG4gICAgLy8gSWYgdGhlIHRhcmdldCBoYXBwZW5zIHRvIGJlIHNldCB1cCBieSBhIGRpc3BhdGNoIGxpa2UgdGhpcyBvbmUsIGl0IHdpbGwgcmVzcG9uZCB3aXRoIHdoYXRldmVyIGl0J3NcbiAgICAvLyBuYW1lc3BhY2VbbWV0aG9kXSguLi5wYXJhbXMpIHJlc29sdmVzIHRvLiBXZSBvbmx5IHNlbmQganNvbnJwYyByZXF1ZXN0cyAod2l0aCBhbiBpZCksIG5vdCBub3RpZmljYXRpb25zLFxuICAgIC8vIGJlY2F1c2UgdGhlcmUgaXMgbm8gd2F5IHRvIGdldCBlcnJvcnMgYmFjayBmcm9tIGEganNvbnJwYyBub3RpZmljYXRpb24uXG4gICAgbGV0IGlkID0gKyttZXNzYWdlSWQsXG5cdHJlcXVlc3QgPSByZXF1ZXN0c1tpZF0gPSB7fTtcbiAgICAvLyBJdCB3b3VsZCBiZSBuaWNlIHRvIG5vdCBsZWFrIHJlcXVlc3Qgb2JqZWN0cyBpZiB0aGV5IGFyZW4ndCBhbnN3ZXJlZC5cbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgbG9nPy4oZGlzcGF0Y2hlckxhYmVsLCAncmVxdWVzdCcsIGlkLCBtZXRob2QsIHBhcmFtcywgJ3RvJywgdGFyZ2V0TGFiZWwpO1xuICAgICAgT2JqZWN0LmFzc2lnbihyZXF1ZXN0LCB7cmVzb2x2ZSwgcmVqZWN0fSk7XG4gICAgICBwb3N0KHtpZCwgbWV0aG9kLCBwYXJhbXMsIGpzb25ycGN9KTtcbiAgICB9KTtcbiAgfVxuXG4gIGFzeW5jIGZ1bmN0aW9uIHJlc3BvbmQoZXZlbnQpIHsgLy8gSGFuZGxlICdtZXNzYWdlJyBldmVudHMgdGhhdCB3ZSByZWNlaXZlIGZyb20gdGFyZ2V0LlxuICAgIGxvZz8uKGRpc3BhdGNoZXJMYWJlbCwgJ2dvdCBtZXNzYWdlJywgZXZlbnQuZGF0YSwgJ2Zyb20nLCB0YXJnZXRMYWJlbCwgZXZlbnQub3JpZ2luKTtcbiAgICBsZXQge2lkLCBtZXRob2QsIHBhcmFtcyA9IFtdLCByZXN1bHQsIGVycm9yLCBqc29ucnBjOnZlcnNpb259ID0gZXZlbnQuZGF0YSB8fCB7fTtcblxuICAgIC8vIE5vaXNpbHkgaWdub3JlIG1lc3NhZ2VzIHRoYXQgYXJlIG5vdCBmcm9tIHRoZSBleHBlY3QgdGFyZ2V0IG9yIG9yaWdpbiwgb3Igd2hpY2ggYXJlIG5vdCBqc29ucnBjLlxuICAgIGlmIChldmVudC5zb3VyY2UgJiYgKGV2ZW50LnNvdXJjZSAhPT0gdGFyZ2V0KSkgcmV0dXJuIGxvZ2Vycm9yPy4oZGlzcGF0Y2hlckxhYmVsLCAndG8nLCB0YXJnZXRMYWJlbCwgICdnb3QgbWVzc2FnZSBmcm9tJywgZXZlbnQuc291cmNlKTtcbiAgICBpZiAob3JpZ2luICYmIChvcmlnaW4gIT09IGV2ZW50Lm9yaWdpbikpIHJldHVybiBsb2dlcnJvcj8uKGRpc3BhdGNoZXJMYWJlbCwgb3JpZ2luLCAnbWlzbWF0Y2hlZCBvcmlnaW4nLCB0YXJnZXRMYWJlbCwgZXZlbnQub3JpZ2luKTtcbiAgICBpZiAodmVyc2lvbiAhPT0ganNvbnJwYykgcmV0dXJuIGxvZ3dhcm4/LihgJHtkaXNwYXRjaGVyTGFiZWx9IGlnbm9yaW5nIG5vbi1qc29ucnBjIG1lc3NhZ2UgJHtKU09OLnN0cmluZ2lmeShldmVudC5kYXRhKX0uYCk7XG5cbiAgICBpZiAobWV0aG9kKSB7IC8vIEluY29taW5nIHJlcXVlc3Qgb3Igbm90aWZpY2F0aW9uIGZyb20gdGFyZ2V0LlxuICAgICAgbGV0IGVycm9yID0gbnVsbCwgcmVzdWx0LFxuICAgICAgICAgIC8vIGpzb25ycGMgcmVxdWVzdC9ub3RpZmljYXRpb24gY2FuIGhhdmUgcG9zaXRpb25hbCBhcmdzIChhcnJheSkgb3IgbmFtZWQgYXJncyAoYSBQT0pPKS5cblx0ICBhcmdzID0gQXJyYXkuaXNBcnJheShwYXJhbXMpID8gcGFyYW1zIDogW3BhcmFtc107IC8vIEFjY2VwdCBlaXRoZXIuXG4gICAgICB0cnkgeyAvLyBtZXRob2QgcmVzdWx0IG1pZ2h0IG5vdCBiZSBhIHByb21pc2UsIHNvIHdlIGNhbid0IHJlbHkgb24gLmNhdGNoKCkuXG4gICAgICAgIHJlc3VsdCA9IGF3YWl0IG5hbWVzcGFjZVttZXRob2RdKC4uLmFyZ3MpOyAvLyBDYWxsIHRoZSBtZXRob2QuXG4gICAgICB9IGNhdGNoIChlKSB7IC8vIFNlbmQgYmFjayBhIGNsZWFuIHtuYW1lLCBtZXNzYWdlfSBvYmplY3QuXG4gICAgICAgIGVycm9yID0gdHJhbnNmZXJyYWJsZUVycm9yKGUpO1xuICAgICAgICBpZiAoIW5hbWVzcGFjZVttZXRob2RdICYmICFlcnJvci5tZXNzYWdlLmluY2x1ZGVzKG1ldGhvZCkpIHtcblx0ICBlcnJvci5tZXNzYWdlID0gYCR7bWV0aG9kfSBpcyBub3QgZGVmaW5lZC5gOyAvLyBCZSBtb3JlIGhlbHBmdWwgdGhhbiBzb21lIGJyb3dzZXJzLlxuICAgICAgICAgIGVycm9yLmNvZGUgPSAtMzI2MDE7IC8vIERlZmluZWQgYnkganNvbi1ycGMgc3BlYy5cbiAgICAgICAgfSBlbHNlIGlmICghZXJyb3IubWVzc2FnZSkgLy8gSXQgaGFwcGVucy4gRS5nLiwgb3BlcmF0aW9uYWwgZXJyb3JzIGZyb20gY3J5cHRvLlxuXHQgIGVycm9yLm1lc3NhZ2UgPSBgJHtlcnJvci5uYW1lIHx8IGVycm9yLnRvU3RyaW5nKCl9IGluICR7bWV0aG9kfS5gO1xuICAgICAgfVxuICAgICAgaWYgKGlkID09PSB1bmRlZmluZWQpIHJldHVybjsgLy8gRG9uJ3QgcmVzcG9uZCB0byBhICdub3RpZmljYXRpb24nLiBudWxsIGlkIGlzIHN0aWxsIHNlbnQgYmFjay5cbiAgICAgIGxldCByZXNwb25zZSA9IGVycm9yID8ge2lkLCBlcnJvciwganNvbnJwY30gOiB7aWQsIHJlc3VsdCwganNvbnJwY307XG4gICAgICBsb2c/LihkaXNwYXRjaGVyTGFiZWwsICdhbnN3ZXJpbmcnLCBpZCwgZXJyb3IgfHwgcmVzdWx0LCAndG8nLCB0YXJnZXRMYWJlbCk7XG4gICAgICByZXR1cm4gcG9zdChyZXNwb25zZSk7XG4gICAgfVxuXG4gICAgLy8gT3RoZXJ3aXNlLCBpdCBpcyBhIHJlc3BvbnNlIGZyb20gdGFyZ2V0IHRvIG91ciBlYXJsaWVyIG91dGdvaW5nIHJlcXVlc3QuXG4gICAgbGV0IHJlcXVlc3QgPSByZXF1ZXN0c1tpZF07ICAvLyBSZXNvbHZlIG9yIHJlamVjdCB0aGUgcHJvbWlzZSB0aGF0IGFuIGFuIGVhcmxpZXIgcmVxdWVzdCBjcmVhdGVkLlxuICAgIGRlbGV0ZSByZXF1ZXN0c1tpZF07XG4gICAgaWYgKCFyZXF1ZXN0KSByZXR1cm4gbG9nd2Fybj8uKGAke2Rpc3BhdGNoZXJMYWJlbH0gaWdub3JpbmcgcmVzcG9uc2UgJHtldmVudC5kYXRhfS5gKTtcbiAgICBpZiAoZXJyb3IpIHJlcXVlc3QucmVqZWN0KGVycm9yKTtcbiAgICBlbHNlIHJlcXVlc3QucmVzb2x2ZShyZXN1bHQpO1xuICB9XG5cbiAgLy8gTm93IHNldCB1cCB0aGUgaGFuZGxlciBhbmQgcmV0dXJuIHRoZSBmdW5jdGlvbiBmb3IgdGhlIGNhbGxlciB0byB1c2UgdG8gbWFrZSByZXF1ZXN0cy5cbiAgcmVjZWl2ZXIuYWRkRXZlbnRMaXN0ZW5lcihcIm1lc3NhZ2VcIiwgcmVzcG9uZCk7XG4gIGxvZ2luZm8/LihgJHtkaXNwYXRjaGVyTGFiZWx9IHdpbGwgZGlzcGF0Y2ggdG8gJHt0YXJnZXRMYWJlbH1gKTtcbiAgcmV0dXJuIHJlcXVlc3Q7XG59XG5cbmV4cG9ydCBkZWZhdWx0IGRpc3BhdGNoO1xuIl0sIm5hbWVzIjpbImRpZ2VzdCIsImNyeXB0byIsImVuY29kZSIsImRlY29kZSIsImJpdExlbmd0aCIsImRlY3J5cHQiLCJnZXRDcnlwdG9LZXkiLCJ3cmFwIiwidW53cmFwIiwiZGVyaXZlS2V5IiwicDJzIiwiY29uY2F0U2FsdCIsImVuY3J5cHQiLCJiYXNlNjR1cmwiLCJzdWJ0bGVBbGdvcml0aG0iLCJkZWNvZGVCYXNlNjRVUkwiLCJpbnZhbGlkS2V5SW5wdXQiLCJFQ0RILmVjZGhBbGxvd2VkIiwiRUNESC5kZXJpdmVLZXkiLCJjZWtMZW5ndGgiLCJhZXNLdyIsInJzYUVzIiwicGJlczJLdyIsImFlc0djbUt3Iiwia2V5VG9KV0siLCJFQ0RILmdlbmVyYXRlRXBrIiwiZ2V0VmVyaWZ5S2V5IiwiZ2V0U2lnbktleSIsImJhc2U2NHVybC5lbmNvZGUiLCJiYXNlNjR1cmwuZGVjb2RlIiwiZ2VuZXJhdGVTZWNyZXQiLCJnZW5lcmF0ZUtleVBhaXIiLCJnZW5lcmF0ZSIsIkpPU0UuZGVjb2RlUHJvdGVjdGVkSGVhZGVyIiwiSk9TRS5nZW5lcmF0ZUtleVBhaXIiLCJKT1NFLkNvbXBhY3RTaWduIiwiSk9TRS5jb21wYWN0VmVyaWZ5IiwiSk9TRS5Db21wYWN0RW5jcnlwdCIsIkpPU0UuY29tcGFjdERlY3J5cHQiLCJKT1NFLmdlbmVyYXRlU2VjcmV0IiwiSk9TRS5iYXNlNjR1cmwuZW5jb2RlIiwiSk9TRS5iYXNlNjR1cmwuZGVjb2RlIiwiSk9TRS5leHBvcnRKV0siLCJKT1NFLmltcG9ydEpXSyIsIkpPU0UuR2VuZXJhbEVuY3J5cHQiLCJKT1NFLmdlbmVyYWxEZWNyeXB0IiwiSk9TRS5HZW5lcmFsU2lnbiIsIkpPU0UuZ2VuZXJhbFZlcmlmeSIsIkxvY2FsQ29sbGVjdGlvbiJdLCJtYXBwaW5ncyI6IkFBQUEsZUFBZSxNQUFNLENBQUM7QUFDZixNQUFNLFdBQVcsR0FBRyxDQUFDLEdBQUcsS0FBSyxHQUFHLFlBQVksU0FBUzs7QUNBNUQsTUFBTUEsUUFBTSxHQUFHLE9BQU8sU0FBUyxFQUFFLElBQUksS0FBSztBQUMxQyxJQUFJLE1BQU0sWUFBWSxHQUFHLENBQUMsSUFBSSxFQUFFLFNBQVMsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7QUFDdEQsSUFBSSxPQUFPLElBQUksVUFBVSxDQUFDLE1BQU1DLFFBQU0sQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLFlBQVksRUFBRSxJQUFJLENBQUMsQ0FBQyxDQUFDO0FBQzFFLENBQUM7O0FDSE0sTUFBTSxPQUFPLEdBQUcsSUFBSSxXQUFXLEVBQUUsQ0FBQztBQUNsQyxNQUFNLE9BQU8sR0FBRyxJQUFJLFdBQVcsRUFBRSxDQUFDO0FBQ3pDLE1BQU0sU0FBUyxHQUFHLENBQUMsSUFBSSxFQUFFLENBQUM7QUFDbkIsU0FBUyxNQUFNLENBQUMsR0FBRyxPQUFPLEVBQUU7QUFDbkMsSUFBSSxNQUFNLElBQUksR0FBRyxPQUFPLENBQUMsTUFBTSxDQUFDLENBQUMsR0FBRyxFQUFFLEVBQUUsTUFBTSxFQUFFLEtBQUssR0FBRyxHQUFHLE1BQU0sRUFBRSxDQUFDLENBQUMsQ0FBQztBQUN0RSxJQUFJLE1BQU0sR0FBRyxHQUFHLElBQUksVUFBVSxDQUFDLElBQUksQ0FBQyxDQUFDO0FBQ3JDLElBQUksSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDO0FBQ2QsSUFBSSxLQUFLLE1BQU0sTUFBTSxJQUFJLE9BQU8sRUFBRTtBQUNsQyxRQUFRLEdBQUcsQ0FBQyxHQUFHLENBQUMsTUFBTSxFQUFFLENBQUMsQ0FBQyxDQUFDO0FBQzNCLFFBQVEsQ0FBQyxJQUFJLE1BQU0sQ0FBQyxNQUFNLENBQUM7QUFD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LElBQUksT0FBTyxRQUFRLENBQUMsRUFBRSxDQUFDLENBQUM7QUFDeEIsSUFBSSxJQUFJLENBQUMsT0FBTyxFQUFFLE9BQU8sT0FBTyxHQUFHLENBQUMsRUFBRSxlQUFlLENBQUMsbUJBQW1CLEVBQUUsS0FBSyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0FBQzFGLElBQUksSUFBSSxLQUFLLEVBQUUsT0FBTyxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQztBQUNyQyxTQUFTLE9BQU8sQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLENBQUM7QUFDakMsR0FBRztBQUNIO0FBQ0E7QUFDQSxFQUFFLFFBQVEsQ0FBQyxnQkFBZ0IsQ0FBQyxTQUFTLEVBQUUsT0FBTyxDQUFDLENBQUM7QUFDaEQsRUFBRSxPQUFPLEdBQUcsQ0FBQyxFQUFFLGVBQWUsQ0FBQyxrQkFBa0IsRUFBRSxXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUM7QUFDbEUsRUFBRSxPQUFPLE9BQU8sQ0FBQztBQUNqQjs7OzsiLCJ4X2dvb2dsZV9pZ25vcmVMaXN0IjpbMCwxLDIsMyw0LDUsNiw3LDgsOSwxMCwxMSwxMiwxMywxNCwxNSwxNiwxNywxOCwxOSwyMCwyMSwyMiwyMywyNCwyNSwyNiwyNywyOCwyOSwzMCwzMSwzMiwzMywzNCwzNSwzNiwzNywzOCwzOSw0MCw0MSw0Miw0Myw0NCw0NSw0Niw0Nyw0OCw0OSw1MCw1MSw1Miw1Myw1NCw1NSw1Niw3MF19
