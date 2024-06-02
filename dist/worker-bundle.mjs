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

// See https://kilroy-code.github.io/distributed-security/docs/implementation.html#web-worker-and-iframe

// self is a Worker: we will postMessage to that and listen for 'message' on that.
const postClient = dispatch({
  targetLabel: 'vault:' + self.name.split('!')[1], // A debugging label for the window we are communicating with.
  namespace: Security  // jsonrpc requests from the client are handled by calling the specified method on Security.
});

// Provide Security with three operations that are handled by making jsonrpc requests to the client.
// If Security (api.mjs) is running outside a browser (e.g., in node), it supplies its own default
// implementation of Storage and getUserDeviceSecret. Here (in a browser worker), we override these
// with implementations that post the requests to the client.
Security.Storage = {
  store(...args) {
    return postClient('store', ...args);
  },
  retrieve(...args) {
    return postClient('retrieve', ...args);
  }
};
Security.getUserDeviceSecret = (tag, prompt = '') => postClient('getUserDeviceSecret', tag, prompt);

postClient('ready', Security.ready); // Tell the client that everything is now in place for operations.
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoid29ya2VyLWJ1bmRsZS5tanMiLCJzb3VyY2VzIjpbIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3dlYmNyeXB0by5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2RpZ2VzdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvYnVmZmVyX3V0aWxzLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvYmFzZTY0dXJsLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3V0aWwvZXJyb3JzLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvcmFuZG9tLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9pdi5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvY2hlY2tfaXZfbGVuZ3RoLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvY2hlY2tfY2VrX2xlbmd0aC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3RpbWluZ19zYWZlX2VxdWFsLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9jcnlwdG9fa2V5LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2lzX2tleV9saWtlLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvZGVjcnlwdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvaXNfZGlzam9pbnQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2lzX29iamVjdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2JvZ3VzLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvYWVza3cuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9lY2RoZXMuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2NoZWNrX3Aycy5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL3BiZXMya3cuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9zdWJ0bGVfcnNhZXMuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9jaGVja19rZXlfbGVuZ3RoLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvcnNhZXMuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvbGliL2Nlay5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2p3a190b19rZXkuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIva2V5L2ltcG9ydC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvY2hlY2tfa2V5X3R5cGUuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9lbmNyeXB0LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9hZXNnY21rdy5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvZGVjcnlwdF9rZXlfbWFuYWdlbWVudC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvdmFsaWRhdGVfY3JpdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9saWIvdmFsaWRhdGVfYWxnb3JpdGhtcy5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd2UvZmxhdHRlbmVkL2RlY3J5cHQuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandlL2NvbXBhY3QvZGVjcnlwdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd2UvZ2VuZXJhbC9kZWNyeXB0LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUva2V5X3RvX2p3ay5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9rZXkvZXhwb3J0LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2xpYi9lbmNyeXB0X2tleV9tYW5hZ2VtZW50LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3ZS9mbGF0dGVuZWQvZW5jcnlwdC5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd2UvZ2VuZXJhbC9lbmNyeXB0LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvc3VidGxlX2RzYS5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9ydW50aW1lL2dldF9zaWduX3ZlcmlmeV9rZXkuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS92ZXJpZnkuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandzL2ZsYXR0ZW5lZC92ZXJpZnkuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandzL2NvbXBhY3QvdmVyaWZ5LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL2p3cy9nZW5lcmFsL3ZlcmlmeS5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd2UvY29tcGFjdC9lbmNyeXB0LmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3J1bnRpbWUvc2lnbi5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd3MvZmxhdHRlbmVkL3NpZ24uanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvandzL2NvbXBhY3Qvc2lnbi5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9qd3MvZ2VuZXJhbC9zaWduLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3V0aWwvYmFzZTY0dXJsLmpzIiwiLi4vbm9kZV9tb2R1bGVzL2pvc2UvZGlzdC9icm93c2VyL3V0aWwvZGVjb2RlX3Byb3RlY3RlZF9oZWFkZXIuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIvcnVudGltZS9nZW5lcmF0ZS5qcyIsIi4uL25vZGVfbW9kdWxlcy9qb3NlL2Rpc3QvYnJvd3Nlci9rZXkvZ2VuZXJhdGVfa2V5X3BhaXIuanMiLCIuLi9ub2RlX21vZHVsZXMvam9zZS9kaXN0L2Jyb3dzZXIva2V5L2dlbmVyYXRlX3NlY3JldC5qcyIsIi4uL2xpYi9hbGdvcml0aG1zLm1qcyIsIi4uL2xpYi9yYXctYnJvd3Nlci5tanMiLCIuLi9saWIva3J5cHRvLm1qcyIsIi4uL2xpYi9tdWx0aUtyeXB0by5tanMiLCIuLi9saWIvc3RvcmUtaW5kZXhlZC5tanMiLCIuLi9saWIvc2VjcmV0Lm1qcyIsIi4uL2xpYi9vcmlnaW4tYnJvd3Nlci5tanMiLCIuLi9saWIvbWtkaXItYnJvd3Nlci5tanMiLCIuLi9saWIvdGFnUGF0aC5tanMiLCIuLi9saWIvc3RvcmFnZS5tanMiLCIuLi9saWIva2V5U2V0Lm1qcyIsIi4uL2xpYi9wYWNrYWdlLWxvYWRlci5tanMiLCIuLi9saWIvYXBpLm1qcyIsIi4uL25vZGVfbW9kdWxlcy9Aa2kxcjB5L2pzb25ycGMvaW5kZXgubWpzIiwiLi4vbGliL3dvcmtlci5tanMiXSwic291cmNlc0NvbnRlbnQiOlsiZXhwb3J0IGRlZmF1bHQgY3J5cHRvO1xuZXhwb3J0IGNvbnN0IGlzQ3J5cHRvS2V5ID0gKGtleSkgPT4ga2V5IGluc3RhbmNlb2YgQ3J5cHRvS2V5O1xuIiwiaW1wb3J0IGNyeXB0byBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5jb25zdCBkaWdlc3QgPSBhc3luYyAoYWxnb3JpdGhtLCBkYXRhKSA9PiB7XG4gICAgY29uc3Qgc3VidGxlRGlnZXN0ID0gYFNIQS0ke2FsZ29yaXRobS5zbGljZSgtMyl9YDtcbiAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5kaWdlc3Qoc3VidGxlRGlnZXN0LCBkYXRhKSk7XG59O1xuZXhwb3J0IGRlZmF1bHQgZGlnZXN0O1xuIiwiaW1wb3J0IGRpZ2VzdCBmcm9tICcuLi9ydW50aW1lL2RpZ2VzdC5qcyc7XG5leHBvcnQgY29uc3QgZW5jb2RlciA9IG5ldyBUZXh0RW5jb2RlcigpO1xuZXhwb3J0IGNvbnN0IGRlY29kZXIgPSBuZXcgVGV4dERlY29kZXIoKTtcbmNvbnN0IE1BWF9JTlQzMiA9IDIgKiogMzI7XG5leHBvcnQgZnVuY3Rpb24gY29uY2F0KC4uLmJ1ZmZlcnMpIHtcbiAgICBjb25zdCBzaXplID0gYnVmZmVycy5yZWR1Y2UoKGFjYywgeyBsZW5ndGggfSkgPT4gYWNjICsgbGVuZ3RoLCAwKTtcbiAgICBjb25zdCBidWYgPSBuZXcgVWludDhBcnJheShzaXplKTtcbiAgICBsZXQgaSA9IDA7XG4gICAgZm9yIChjb25zdCBidWZmZXIgb2YgYnVmZmVycykge1xuICAgICAgICBidWYuc2V0KGJ1ZmZlciwgaSk7XG4gICAgICAgIGkgKz0gYnVmZmVyLmxlbmd0aDtcbiAgICB9XG4gICAgcmV0dXJuIGJ1Zjtcbn1cbmV4cG9ydCBmdW5jdGlvbiBwMnMoYWxnLCBwMnNJbnB1dCkge1xuICAgIHJldHVybiBjb25jYXQoZW5jb2Rlci5lbmNvZGUoYWxnKSwgbmV3IFVpbnQ4QXJyYXkoWzBdKSwgcDJzSW5wdXQpO1xufVxuZnVuY3Rpb24gd3JpdGVVSW50MzJCRShidWYsIHZhbHVlLCBvZmZzZXQpIHtcbiAgICBpZiAodmFsdWUgPCAwIHx8IHZhbHVlID49IE1BWF9JTlQzMikge1xuICAgICAgICB0aHJvdyBuZXcgUmFuZ2VFcnJvcihgdmFsdWUgbXVzdCBiZSA+PSAwIGFuZCA8PSAke01BWF9JTlQzMiAtIDF9LiBSZWNlaXZlZCAke3ZhbHVlfWApO1xuICAgIH1cbiAgICBidWYuc2V0KFt2YWx1ZSA+Pj4gMjQsIHZhbHVlID4+PiAxNiwgdmFsdWUgPj4+IDgsIHZhbHVlICYgMHhmZl0sIG9mZnNldCk7XG59XG5leHBvcnQgZnVuY3Rpb24gdWludDY0YmUodmFsdWUpIHtcbiAgICBjb25zdCBoaWdoID0gTWF0aC5mbG9vcih2YWx1ZSAvIE1BWF9JTlQzMik7XG4gICAgY29uc3QgbG93ID0gdmFsdWUgJSBNQVhfSU5UMzI7XG4gICAgY29uc3QgYnVmID0gbmV3IFVpbnQ4QXJyYXkoOCk7XG4gICAgd3JpdGVVSW50MzJCRShidWYsIGhpZ2gsIDApO1xuICAgIHdyaXRlVUludDMyQkUoYnVmLCBsb3csIDQpO1xuICAgIHJldHVybiBidWY7XG59XG5leHBvcnQgZnVuY3Rpb24gdWludDMyYmUodmFsdWUpIHtcbiAgICBjb25zdCBidWYgPSBuZXcgVWludDhBcnJheSg0KTtcbiAgICB3cml0ZVVJbnQzMkJFKGJ1ZiwgdmFsdWUpO1xuICAgIHJldHVybiBidWY7XG59XG5leHBvcnQgZnVuY3Rpb24gbGVuZ3RoQW5kSW5wdXQoaW5wdXQpIHtcbiAgICByZXR1cm4gY29uY2F0KHVpbnQzMmJlKGlucHV0Lmxlbmd0aCksIGlucHV0KTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjb25jYXRLZGYoc2VjcmV0LCBiaXRzLCB2YWx1ZSkge1xuICAgIGNvbnN0IGl0ZXJhdGlvbnMgPSBNYXRoLmNlaWwoKGJpdHMgPj4gMykgLyAzMik7XG4gICAgY29uc3QgcmVzID0gbmV3IFVpbnQ4QXJyYXkoaXRlcmF0aW9ucyAqIDMyKTtcbiAgICBmb3IgKGxldCBpdGVyID0gMDsgaXRlciA8IGl0ZXJhdGlvbnM7IGl0ZXIrKykge1xuICAgICAgICBjb25zdCBidWYgPSBuZXcgVWludDhBcnJheSg0ICsgc2VjcmV0Lmxlbmd0aCArIHZhbHVlLmxlbmd0aCk7XG4gICAgICAgIGJ1Zi5zZXQodWludDMyYmUoaXRlciArIDEpKTtcbiAgICAgICAgYnVmLnNldChzZWNyZXQsIDQpO1xuICAgICAgICBidWYuc2V0KHZhbHVlLCA0ICsgc2VjcmV0Lmxlbmd0aCk7XG4gICAgICAgIHJlcy5zZXQoYXdhaXQgZGlnZXN0KCdzaGEyNTYnLCBidWYpLCBpdGVyICogMzIpO1xuICAgIH1cbiAgICByZXR1cm4gcmVzLnNsaWNlKDAsIGJpdHMgPj4gMyk7XG59XG4iLCJpbXBvcnQgeyBlbmNvZGVyLCBkZWNvZGVyIH0gZnJvbSAnLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5leHBvcnQgY29uc3QgZW5jb2RlQmFzZTY0ID0gKGlucHV0KSA9PiB7XG4gICAgbGV0IHVuZW5jb2RlZCA9IGlucHV0O1xuICAgIGlmICh0eXBlb2YgdW5lbmNvZGVkID09PSAnc3RyaW5nJykge1xuICAgICAgICB1bmVuY29kZWQgPSBlbmNvZGVyLmVuY29kZSh1bmVuY29kZWQpO1xuICAgIH1cbiAgICBjb25zdCBDSFVOS19TSVpFID0gMHg4MDAwO1xuICAgIGNvbnN0IGFyciA9IFtdO1xuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgdW5lbmNvZGVkLmxlbmd0aDsgaSArPSBDSFVOS19TSVpFKSB7XG4gICAgICAgIGFyci5wdXNoKFN0cmluZy5mcm9tQ2hhckNvZGUuYXBwbHkobnVsbCwgdW5lbmNvZGVkLnN1YmFycmF5KGksIGkgKyBDSFVOS19TSVpFKSkpO1xuICAgIH1cbiAgICByZXR1cm4gYnRvYShhcnIuam9pbignJykpO1xufTtcbmV4cG9ydCBjb25zdCBlbmNvZGUgPSAoaW5wdXQpID0+IHtcbiAgICByZXR1cm4gZW5jb2RlQmFzZTY0KGlucHV0KS5yZXBsYWNlKC89L2csICcnKS5yZXBsYWNlKC9cXCsvZywgJy0nKS5yZXBsYWNlKC9cXC8vZywgJ18nKTtcbn07XG5leHBvcnQgY29uc3QgZGVjb2RlQmFzZTY0ID0gKGVuY29kZWQpID0+IHtcbiAgICBjb25zdCBiaW5hcnkgPSBhdG9iKGVuY29kZWQpO1xuICAgIGNvbnN0IGJ5dGVzID0gbmV3IFVpbnQ4QXJyYXkoYmluYXJ5Lmxlbmd0aCk7XG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBiaW5hcnkubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgYnl0ZXNbaV0gPSBiaW5hcnkuY2hhckNvZGVBdChpKTtcbiAgICB9XG4gICAgcmV0dXJuIGJ5dGVzO1xufTtcbmV4cG9ydCBjb25zdCBkZWNvZGUgPSAoaW5wdXQpID0+IHtcbiAgICBsZXQgZW5jb2RlZCA9IGlucHV0O1xuICAgIGlmIChlbmNvZGVkIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICBlbmNvZGVkID0gZGVjb2Rlci5kZWNvZGUoZW5jb2RlZCk7XG4gICAgfVxuICAgIGVuY29kZWQgPSBlbmNvZGVkLnJlcGxhY2UoLy0vZywgJysnKS5yZXBsYWNlKC9fL2csICcvJykucmVwbGFjZSgvXFxzL2csICcnKTtcbiAgICB0cnkge1xuICAgICAgICByZXR1cm4gZGVjb2RlQmFzZTY0KGVuY29kZWQpO1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1RoZSBpbnB1dCB0byBiZSBkZWNvZGVkIGlzIG5vdCBjb3JyZWN0bHkgZW5jb2RlZC4nKTtcbiAgICB9XG59O1xuIiwiZXhwb3J0IGNsYXNzIEpPU0VFcnJvciBleHRlbmRzIEVycm9yIHtcbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pPU0VfR0VORVJJQyc7XG4gICAgfVxuICAgIGNvbnN0cnVjdG9yKG1lc3NhZ2UpIHtcbiAgICAgICAgc3VwZXIobWVzc2FnZSk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSk9TRV9HRU5FUklDJztcbiAgICAgICAgdGhpcy5uYW1lID0gdGhpcy5jb25zdHJ1Y3Rvci5uYW1lO1xuICAgICAgICBFcnJvci5jYXB0dXJlU3RhY2tUcmFjZT8uKHRoaXMsIHRoaXMuY29uc3RydWN0b3IpO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV1RDbGFpbVZhbGlkYXRpb25GYWlsZWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldUX0NMQUlNX1ZBTElEQVRJT05fRkFJTEVEJztcbiAgICB9XG4gICAgY29uc3RydWN0b3IobWVzc2FnZSwgY2xhaW0gPSAndW5zcGVjaWZpZWQnLCByZWFzb24gPSAndW5zcGVjaWZpZWQnKSB7XG4gICAgICAgIHN1cGVyKG1lc3NhZ2UpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXVF9DTEFJTV9WQUxJREFUSU9OX0ZBSUxFRCc7XG4gICAgICAgIHRoaXMuY2xhaW0gPSBjbGFpbTtcbiAgICAgICAgdGhpcy5yZWFzb24gPSByZWFzb247XG4gICAgfVxufVxuZXhwb3J0IGNsYXNzIEpXVEV4cGlyZWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldUX0VYUElSRUQnO1xuICAgIH1cbiAgICBjb25zdHJ1Y3RvcihtZXNzYWdlLCBjbGFpbSA9ICd1bnNwZWNpZmllZCcsIHJlYXNvbiA9ICd1bnNwZWNpZmllZCcpIHtcbiAgICAgICAgc3VwZXIobWVzc2FnZSk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldUX0VYUElSRUQnO1xuICAgICAgICB0aGlzLmNsYWltID0gY2xhaW07XG4gICAgICAgIHRoaXMucmVhc29uID0gcmVhc29uO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKT1NFQWxnTm90QWxsb3dlZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSk9TRV9BTEdfTk9UX0FMTE9XRUQnO1xuICAgIH1cbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pPU0VfQUxHX05PVF9BTExPV0VEJztcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgSk9TRU5vdFN1cHBvcnRlZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSk9TRV9OT1RfU1VQUE9SVEVEJztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KT1NFX05PVF9TVVBQT1JURUQnO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV0VEZWNyeXB0aW9uRmFpbGVkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0VfREVDUllQVElPTl9GQUlMRUQnO1xuICAgICAgICB0aGlzLm1lc3NhZ2UgPSAnZGVjcnlwdGlvbiBvcGVyYXRpb24gZmFpbGVkJztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV0VfREVDUllQVElPTl9GQUlMRUQnO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV0VJbnZhbGlkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0VfSU5WQUxJRCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldFX0lOVkFMSUQnO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV1NJbnZhbGlkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV1NfSU5WQUxJRCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldTX0lOVkFMSUQnO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV1RJbnZhbGlkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV1RfSU5WQUxJRCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldUX0lOVkFMSUQnO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV0tJbnZhbGlkIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0tfSU5WQUxJRCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldLX0lOVkFMSUQnO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV0tTSW52YWxpZCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldLU19JTlZBTElEJztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV0tTX0lOVkFMSUQnO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV0tTTm9NYXRjaGluZ0tleSBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldLU19OT19NQVRDSElOR19LRVknO1xuICAgICAgICB0aGlzLm1lc3NhZ2UgPSAnbm8gYXBwbGljYWJsZSBrZXkgZm91bmQgaW4gdGhlIEpTT04gV2ViIEtleSBTZXQnO1xuICAgIH1cbiAgICBzdGF0aWMgZ2V0IGNvZGUoKSB7XG4gICAgICAgIHJldHVybiAnRVJSX0pXS1NfTk9fTUFUQ0hJTkdfS0VZJztcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgSldLU011bHRpcGxlTWF0Y2hpbmdLZXlzIGV4dGVuZHMgSk9TRUVycm9yIHtcbiAgICBjb25zdHJ1Y3RvcigpIHtcbiAgICAgICAgc3VwZXIoLi4uYXJndW1lbnRzKTtcbiAgICAgICAgdGhpcy5jb2RlID0gJ0VSUl9KV0tTX01VTFRJUExFX01BVENISU5HX0tFWVMnO1xuICAgICAgICB0aGlzLm1lc3NhZ2UgPSAnbXVsdGlwbGUgbWF0Y2hpbmcga2V5cyBmb3VuZCBpbiB0aGUgSlNPTiBXZWIgS2V5IFNldCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldLU19NVUxUSVBMRV9NQVRDSElOR19LRVlTJztcbiAgICB9XG59XG5TeW1ib2wuYXN5bmNJdGVyYXRvcjtcbmV4cG9ydCBjbGFzcyBKV0tTVGltZW91dCBleHRlbmRzIEpPU0VFcnJvciB7XG4gICAgY29uc3RydWN0b3IoKSB7XG4gICAgICAgIHN1cGVyKC4uLmFyZ3VtZW50cyk7XG4gICAgICAgIHRoaXMuY29kZSA9ICdFUlJfSldLU19USU1FT1VUJztcbiAgICAgICAgdGhpcy5tZXNzYWdlID0gJ3JlcXVlc3QgdGltZWQgb3V0JztcbiAgICB9XG4gICAgc3RhdGljIGdldCBjb2RlKCkge1xuICAgICAgICByZXR1cm4gJ0VSUl9KV0tTX1RJTUVPVVQnO1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBKV1NTaWduYXR1cmVWZXJpZmljYXRpb25GYWlsZWQgZXh0ZW5kcyBKT1NFRXJyb3Ige1xuICAgIGNvbnN0cnVjdG9yKCkge1xuICAgICAgICBzdXBlciguLi5hcmd1bWVudHMpO1xuICAgICAgICB0aGlzLmNvZGUgPSAnRVJSX0pXU19TSUdOQVRVUkVfVkVSSUZJQ0FUSU9OX0ZBSUxFRCc7XG4gICAgICAgIHRoaXMubWVzc2FnZSA9ICdzaWduYXR1cmUgdmVyaWZpY2F0aW9uIGZhaWxlZCc7XG4gICAgfVxuICAgIHN0YXRpYyBnZXQgY29kZSgpIHtcbiAgICAgICAgcmV0dXJuICdFUlJfSldTX1NJR05BVFVSRV9WRVJJRklDQVRJT05fRkFJTEVEJztcbiAgICB9XG59XG4iLCJpbXBvcnQgY3J5cHRvIGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmV4cG9ydCBkZWZhdWx0IGNyeXB0by5nZXRSYW5kb21WYWx1ZXMuYmluZChjcnlwdG8pO1xuIiwiaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCByYW5kb20gZnJvbSAnLi4vcnVudGltZS9yYW5kb20uanMnO1xuZXhwb3J0IGZ1bmN0aW9uIGJpdExlbmd0aChhbGcpIHtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdBMTI4R0NNJzpcbiAgICAgICAgY2FzZSAnQTEyOEdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTE5MkdDTSc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ00nOlxuICAgICAgICBjYXNlICdBMjU2R0NNS1cnOlxuICAgICAgICAgICAgcmV0dXJuIDk2O1xuICAgICAgICBjYXNlICdBMTI4Q0JDLUhTMjU2JzpcbiAgICAgICAgY2FzZSAnQTE5MkNCQy1IUzM4NCc6XG4gICAgICAgIGNhc2UgJ0EyNTZDQkMtSFM1MTInOlxuICAgICAgICAgICAgcmV0dXJuIDEyODtcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKGBVbnN1cHBvcnRlZCBKV0UgQWxnb3JpdGhtOiAke2FsZ31gKTtcbiAgICB9XG59XG5leHBvcnQgZGVmYXVsdCAoYWxnKSA9PiByYW5kb20obmV3IFVpbnQ4QXJyYXkoYml0TGVuZ3RoKGFsZykgPj4gMykpO1xuIiwiaW1wb3J0IHsgSldFSW52YWxpZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IGJpdExlbmd0aCB9IGZyb20gJy4vaXYuanMnO1xuY29uc3QgY2hlY2tJdkxlbmd0aCA9IChlbmMsIGl2KSA9PiB7XG4gICAgaWYgKGl2Lmxlbmd0aCA8PCAzICE9PSBiaXRMZW5ndGgoZW5jKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSW52YWxpZCBJbml0aWFsaXphdGlvbiBWZWN0b3IgbGVuZ3RoJyk7XG4gICAgfVxufTtcbmV4cG9ydCBkZWZhdWx0IGNoZWNrSXZMZW5ndGg7XG4iLCJpbXBvcnQgeyBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuY29uc3QgY2hlY2tDZWtMZW5ndGggPSAoY2VrLCBleHBlY3RlZCkgPT4ge1xuICAgIGNvbnN0IGFjdHVhbCA9IGNlay5ieXRlTGVuZ3RoIDw8IDM7XG4gICAgaWYgKGFjdHVhbCAhPT0gZXhwZWN0ZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEludmFsaWQgQ29udGVudCBFbmNyeXB0aW9uIEtleSBsZW5ndGguIEV4cGVjdGVkICR7ZXhwZWN0ZWR9IGJpdHMsIGdvdCAke2FjdHVhbH0gYml0c2ApO1xuICAgIH1cbn07XG5leHBvcnQgZGVmYXVsdCBjaGVja0Nla0xlbmd0aDtcbiIsImNvbnN0IHRpbWluZ1NhZmVFcXVhbCA9IChhLCBiKSA9PiB7XG4gICAgaWYgKCEoYSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0ZpcnN0IGFyZ3VtZW50IG11c3QgYmUgYSBidWZmZXInKTtcbiAgICB9XG4gICAgaWYgKCEoYiBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1NlY29uZCBhcmd1bWVudCBtdXN0IGJlIGEgYnVmZmVyJyk7XG4gICAgfVxuICAgIGlmIChhLmxlbmd0aCAhPT0gYi5sZW5ndGgpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignSW5wdXQgYnVmZmVycyBtdXN0IGhhdmUgdGhlIHNhbWUgbGVuZ3RoJyk7XG4gICAgfVxuICAgIGNvbnN0IGxlbiA9IGEubGVuZ3RoO1xuICAgIGxldCBvdXQgPSAwO1xuICAgIGxldCBpID0gLTE7XG4gICAgd2hpbGUgKCsraSA8IGxlbikge1xuICAgICAgICBvdXQgfD0gYVtpXSBeIGJbaV07XG4gICAgfVxuICAgIHJldHVybiBvdXQgPT09IDA7XG59O1xuZXhwb3J0IGRlZmF1bHQgdGltaW5nU2FmZUVxdWFsO1xuIiwiZnVuY3Rpb24gdW51c2FibGUobmFtZSwgcHJvcCA9ICdhbGdvcml0aG0ubmFtZScpIHtcbiAgICByZXR1cm4gbmV3IFR5cGVFcnJvcihgQ3J5cHRvS2V5IGRvZXMgbm90IHN1cHBvcnQgdGhpcyBvcGVyYXRpb24sIGl0cyAke3Byb3B9IG11c3QgYmUgJHtuYW1lfWApO1xufVxuZnVuY3Rpb24gaXNBbGdvcml0aG0oYWxnb3JpdGhtLCBuYW1lKSB7XG4gICAgcmV0dXJuIGFsZ29yaXRobS5uYW1lID09PSBuYW1lO1xufVxuZnVuY3Rpb24gZ2V0SGFzaExlbmd0aChoYXNoKSB7XG4gICAgcmV0dXJuIHBhcnNlSW50KGhhc2gubmFtZS5zbGljZSg0KSwgMTApO1xufVxuZnVuY3Rpb24gZ2V0TmFtZWRDdXJ2ZShhbGcpIHtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdFUzI1Nic6XG4gICAgICAgICAgICByZXR1cm4gJ1AtMjU2JztcbiAgICAgICAgY2FzZSAnRVMzODQnOlxuICAgICAgICAgICAgcmV0dXJuICdQLTM4NCc7XG4gICAgICAgIGNhc2UgJ0VTNTEyJzpcbiAgICAgICAgICAgIHJldHVybiAnUC01MjEnO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCd1bnJlYWNoYWJsZScpO1xuICAgIH1cbn1cbmZ1bmN0aW9uIGNoZWNrVXNhZ2Uoa2V5LCB1c2FnZXMpIHtcbiAgICBpZiAodXNhZ2VzLmxlbmd0aCAmJiAhdXNhZ2VzLnNvbWUoKGV4cGVjdGVkKSA9PiBrZXkudXNhZ2VzLmluY2x1ZGVzKGV4cGVjdGVkKSkpIHtcbiAgICAgICAgbGV0IG1zZyA9ICdDcnlwdG9LZXkgZG9lcyBub3Qgc3VwcG9ydCB0aGlzIG9wZXJhdGlvbiwgaXRzIHVzYWdlcyBtdXN0IGluY2x1ZGUgJztcbiAgICAgICAgaWYgKHVzYWdlcy5sZW5ndGggPiAyKSB7XG4gICAgICAgICAgICBjb25zdCBsYXN0ID0gdXNhZ2VzLnBvcCgpO1xuICAgICAgICAgICAgbXNnICs9IGBvbmUgb2YgJHt1c2FnZXMuam9pbignLCAnKX0sIG9yICR7bGFzdH0uYDtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGlmICh1c2FnZXMubGVuZ3RoID09PSAyKSB7XG4gICAgICAgICAgICBtc2cgKz0gYG9uZSBvZiAke3VzYWdlc1swXX0gb3IgJHt1c2FnZXNbMV19LmA7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBtc2cgKz0gYCR7dXNhZ2VzWzBdfS5gO1xuICAgICAgICB9XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IobXNnKTtcbiAgICB9XG59XG5leHBvcnQgZnVuY3Rpb24gY2hlY2tTaWdDcnlwdG9LZXkoa2V5LCBhbGcsIC4uLnVzYWdlcykge1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ0hTMjU2JzpcbiAgICAgICAgY2FzZSAnSFMzODQnOlxuICAgICAgICBjYXNlICdIUzUxMic6IHtcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ0hNQUMnKSlcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZSgnSE1BQycpO1xuICAgICAgICAgICAgY29uc3QgZXhwZWN0ZWQgPSBwYXJzZUludChhbGcuc2xpY2UoMiksIDEwKTtcbiAgICAgICAgICAgIGNvbnN0IGFjdHVhbCA9IGdldEhhc2hMZW5ndGgoa2V5LmFsZ29yaXRobS5oYXNoKTtcbiAgICAgICAgICAgIGlmIChhY3R1YWwgIT09IGV4cGVjdGVkKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKGBTSEEtJHtleHBlY3RlZH1gLCAnYWxnb3JpdGhtLmhhc2gnKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ1JTMjU2JzpcbiAgICAgICAgY2FzZSAnUlMzODQnOlxuICAgICAgICBjYXNlICdSUzUxMic6IHtcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ1JTQVNTQS1QS0NTMS12MV81JykpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ1JTQVNTQS1QS0NTMS12MV81Jyk7XG4gICAgICAgICAgICBjb25zdCBleHBlY3RlZCA9IHBhcnNlSW50KGFsZy5zbGljZSgyKSwgMTApO1xuICAgICAgICAgICAgY29uc3QgYWN0dWFsID0gZ2V0SGFzaExlbmd0aChrZXkuYWxnb3JpdGhtLmhhc2gpO1xuICAgICAgICAgICAgaWYgKGFjdHVhbCAhPT0gZXhwZWN0ZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoYFNIQS0ke2V4cGVjdGVkfWAsICdhbGdvcml0aG0uaGFzaCcpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnUFMyNTYnOlxuICAgICAgICBjYXNlICdQUzM4NCc6XG4gICAgICAgIGNhc2UgJ1BTNTEyJzoge1xuICAgICAgICAgICAgaWYgKCFpc0FsZ29yaXRobShrZXkuYWxnb3JpdGhtLCAnUlNBLVBTUycpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdSU0EtUFNTJyk7XG4gICAgICAgICAgICBjb25zdCBleHBlY3RlZCA9IHBhcnNlSW50KGFsZy5zbGljZSgyKSwgMTApO1xuICAgICAgICAgICAgY29uc3QgYWN0dWFsID0gZ2V0SGFzaExlbmd0aChrZXkuYWxnb3JpdGhtLmhhc2gpO1xuICAgICAgICAgICAgaWYgKGFjdHVhbCAhPT0gZXhwZWN0ZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoYFNIQS0ke2V4cGVjdGVkfWAsICdhbGdvcml0aG0uaGFzaCcpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnRWREU0EnOiB7XG4gICAgICAgICAgICBpZiAoa2V5LmFsZ29yaXRobS5uYW1lICE9PSAnRWQyNTUxOScgJiYga2V5LmFsZ29yaXRobS5uYW1lICE9PSAnRWQ0NDgnKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ0VkMjU1MTkgb3IgRWQ0NDgnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0VTMjU2JzpcbiAgICAgICAgY2FzZSAnRVMzODQnOlxuICAgICAgICBjYXNlICdFUzUxMic6IHtcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ0VDRFNBJykpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ0VDRFNBJyk7XG4gICAgICAgICAgICBjb25zdCBleHBlY3RlZCA9IGdldE5hbWVkQ3VydmUoYWxnKTtcbiAgICAgICAgICAgIGNvbnN0IGFjdHVhbCA9IGtleS5hbGdvcml0aG0ubmFtZWRDdXJ2ZTtcbiAgICAgICAgICAgIGlmIChhY3R1YWwgIT09IGV4cGVjdGVkKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKGV4cGVjdGVkLCAnYWxnb3JpdGhtLm5hbWVkQ3VydmUnKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdDcnlwdG9LZXkgZG9lcyBub3Qgc3VwcG9ydCB0aGlzIG9wZXJhdGlvbicpO1xuICAgIH1cbiAgICBjaGVja1VzYWdlKGtleSwgdXNhZ2VzKTtcbn1cbmV4cG9ydCBmdW5jdGlvbiBjaGVja0VuY0NyeXB0b0tleShrZXksIGFsZywgLi4udXNhZ2VzKSB7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnQTEyOEdDTSc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ00nOlxuICAgICAgICBjYXNlICdBMjU2R0NNJzoge1xuICAgICAgICAgICAgaWYgKCFpc0FsZ29yaXRobShrZXkuYWxnb3JpdGhtLCAnQUVTLUdDTScpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdBRVMtR0NNJyk7XG4gICAgICAgICAgICBjb25zdCBleHBlY3RlZCA9IHBhcnNlSW50KGFsZy5zbGljZSgxLCA0KSwgMTApO1xuICAgICAgICAgICAgY29uc3QgYWN0dWFsID0ga2V5LmFsZ29yaXRobS5sZW5ndGg7XG4gICAgICAgICAgICBpZiAoYWN0dWFsICE9PSBleHBlY3RlZClcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZShleHBlY3RlZCwgJ2FsZ29yaXRobS5sZW5ndGgnKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ0FFUy1LVycpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdBRVMtS1cnKTtcbiAgICAgICAgICAgIGNvbnN0IGV4cGVjdGVkID0gcGFyc2VJbnQoYWxnLnNsaWNlKDEsIDQpLCAxMCk7XG4gICAgICAgICAgICBjb25zdCBhY3R1YWwgPSBrZXkuYWxnb3JpdGhtLmxlbmd0aDtcbiAgICAgICAgICAgIGlmIChhY3R1YWwgIT09IGV4cGVjdGVkKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKGV4cGVjdGVkLCAnYWxnb3JpdGhtLmxlbmd0aCcpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnRUNESCc6IHtcbiAgICAgICAgICAgIHN3aXRjaCAoa2V5LmFsZ29yaXRobS5uYW1lKSB7XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESCc6XG4gICAgICAgICAgICAgICAgY2FzZSAnWDI1NTE5JzpcbiAgICAgICAgICAgICAgICBjYXNlICdYNDQ4JzpcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ0VDREgsIFgyNTUxOSwgb3IgWDQ0OCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnUEJFUzItSFMyNTYrQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnUEJFUzItSFMzODQrQTE5MktXJzpcbiAgICAgICAgY2FzZSAnUEJFUzItSFM1MTIrQTI1NktXJzpcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ1BCS0RGMicpKVxuICAgICAgICAgICAgICAgIHRocm93IHVudXNhYmxlKCdQQktERjInKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdSU0EtT0FFUCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTI1Nic6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTM4NCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTUxMic6IHtcbiAgICAgICAgICAgIGlmICghaXNBbGdvcml0aG0oa2V5LmFsZ29yaXRobSwgJ1JTQS1PQUVQJykpXG4gICAgICAgICAgICAgICAgdGhyb3cgdW51c2FibGUoJ1JTQS1PQUVQJyk7XG4gICAgICAgICAgICBjb25zdCBleHBlY3RlZCA9IHBhcnNlSW50KGFsZy5zbGljZSg5KSwgMTApIHx8IDE7XG4gICAgICAgICAgICBjb25zdCBhY3R1YWwgPSBnZXRIYXNoTGVuZ3RoKGtleS5hbGdvcml0aG0uaGFzaCk7XG4gICAgICAgICAgICBpZiAoYWN0dWFsICE9PSBleHBlY3RlZClcbiAgICAgICAgICAgICAgICB0aHJvdyB1bnVzYWJsZShgU0hBLSR7ZXhwZWN0ZWR9YCwgJ2FsZ29yaXRobS5oYXNoJyk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignQ3J5cHRvS2V5IGRvZXMgbm90IHN1cHBvcnQgdGhpcyBvcGVyYXRpb24nKTtcbiAgICB9XG4gICAgY2hlY2tVc2FnZShrZXksIHVzYWdlcyk7XG59XG4iLCJmdW5jdGlvbiBtZXNzYWdlKG1zZywgYWN0dWFsLCAuLi50eXBlcykge1xuICAgIGlmICh0eXBlcy5sZW5ndGggPiAyKSB7XG4gICAgICAgIGNvbnN0IGxhc3QgPSB0eXBlcy5wb3AoKTtcbiAgICAgICAgbXNnICs9IGBvbmUgb2YgdHlwZSAke3R5cGVzLmpvaW4oJywgJyl9LCBvciAke2xhc3R9LmA7XG4gICAgfVxuICAgIGVsc2UgaWYgKHR5cGVzLmxlbmd0aCA9PT0gMikge1xuICAgICAgICBtc2cgKz0gYG9uZSBvZiB0eXBlICR7dHlwZXNbMF19IG9yICR7dHlwZXNbMV19LmA7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBtc2cgKz0gYG9mIHR5cGUgJHt0eXBlc1swXX0uYDtcbiAgICB9XG4gICAgaWYgKGFjdHVhbCA9PSBudWxsKSB7XG4gICAgICAgIG1zZyArPSBgIFJlY2VpdmVkICR7YWN0dWFsfWA7XG4gICAgfVxuICAgIGVsc2UgaWYgKHR5cGVvZiBhY3R1YWwgPT09ICdmdW5jdGlvbicgJiYgYWN0dWFsLm5hbWUpIHtcbiAgICAgICAgbXNnICs9IGAgUmVjZWl2ZWQgZnVuY3Rpb24gJHthY3R1YWwubmFtZX1gO1xuICAgIH1cbiAgICBlbHNlIGlmICh0eXBlb2YgYWN0dWFsID09PSAnb2JqZWN0JyAmJiBhY3R1YWwgIT0gbnVsbCkge1xuICAgICAgICBpZiAoYWN0dWFsLmNvbnN0cnVjdG9yPy5uYW1lKSB7XG4gICAgICAgICAgICBtc2cgKz0gYCBSZWNlaXZlZCBhbiBpbnN0YW5jZSBvZiAke2FjdHVhbC5jb25zdHJ1Y3Rvci5uYW1lfWA7XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIG1zZztcbn1cbmV4cG9ydCBkZWZhdWx0IChhY3R1YWwsIC4uLnR5cGVzKSA9PiB7XG4gICAgcmV0dXJuIG1lc3NhZ2UoJ0tleSBtdXN0IGJlICcsIGFjdHVhbCwgLi4udHlwZXMpO1xufTtcbmV4cG9ydCBmdW5jdGlvbiB3aXRoQWxnKGFsZywgYWN0dWFsLCAuLi50eXBlcykge1xuICAgIHJldHVybiBtZXNzYWdlKGBLZXkgZm9yIHRoZSAke2FsZ30gYWxnb3JpdGhtIG11c3QgYmUgYCwgYWN0dWFsLCAuLi50eXBlcyk7XG59XG4iLCJpbXBvcnQgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmV4cG9ydCBkZWZhdWx0IChrZXkpID0+IHtcbiAgICByZXR1cm4gaXNDcnlwdG9LZXkoa2V5KTtcbn07XG5leHBvcnQgY29uc3QgdHlwZXMgPSBbJ0NyeXB0b0tleSddO1xuIiwiaW1wb3J0IHsgY29uY2F0LCB1aW50NjRiZSB9IGZyb20gJy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IGNoZWNrSXZMZW5ndGggZnJvbSAnLi4vbGliL2NoZWNrX2l2X2xlbmd0aC5qcyc7XG5pbXBvcnQgY2hlY2tDZWtMZW5ndGggZnJvbSAnLi9jaGVja19jZWtfbGVuZ3RoLmpzJztcbmltcG9ydCB0aW1pbmdTYWZlRXF1YWwgZnJvbSAnLi90aW1pbmdfc2FmZV9lcXVhbC5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkLCBKV0VEZWNyeXB0aW9uRmFpbGVkLCBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IGNyeXB0bywgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IGNoZWNrRW5jQ3J5cHRvS2V5IH0gZnJvbSAnLi4vbGliL2NyeXB0b19rZXkuanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmFzeW5jIGZ1bmN0aW9uIGNiY0RlY3J5cHQoZW5jLCBjZWssIGNpcGhlcnRleHQsIGl2LCB0YWcsIGFhZCkge1xuICAgIGlmICghKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGNlaywgJ1VpbnQ4QXJyYXknKSk7XG4gICAgfVxuICAgIGNvbnN0IGtleVNpemUgPSBwYXJzZUludChlbmMuc2xpY2UoMSwgNCksIDEwKTtcbiAgICBjb25zdCBlbmNLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLnN1YmFycmF5KGtleVNpemUgPj4gMyksICdBRVMtQ0JDJywgZmFsc2UsIFsnZGVjcnlwdCddKTtcbiAgICBjb25zdCBtYWNLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLnN1YmFycmF5KDAsIGtleVNpemUgPj4gMyksIHtcbiAgICAgICAgaGFzaDogYFNIQS0ke2tleVNpemUgPDwgMX1gLFxuICAgICAgICBuYW1lOiAnSE1BQycsXG4gICAgfSwgZmFsc2UsIFsnc2lnbiddKTtcbiAgICBjb25zdCBtYWNEYXRhID0gY29uY2F0KGFhZCwgaXYsIGNpcGhlcnRleHQsIHVpbnQ2NGJlKGFhZC5sZW5ndGggPDwgMykpO1xuICAgIGNvbnN0IGV4cGVjdGVkVGFnID0gbmV3IFVpbnQ4QXJyYXkoKGF3YWl0IGNyeXB0by5zdWJ0bGUuc2lnbignSE1BQycsIG1hY0tleSwgbWFjRGF0YSkpLnNsaWNlKDAsIGtleVNpemUgPj4gMykpO1xuICAgIGxldCBtYWNDaGVja1Bhc3NlZDtcbiAgICB0cnkge1xuICAgICAgICBtYWNDaGVja1Bhc3NlZCA9IHRpbWluZ1NhZmVFcXVhbCh0YWcsIGV4cGVjdGVkVGFnKTtcbiAgICB9XG4gICAgY2F0Y2gge1xuICAgIH1cbiAgICBpZiAoIW1hY0NoZWNrUGFzc2VkKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VEZWNyeXB0aW9uRmFpbGVkKCk7XG4gICAgfVxuICAgIGxldCBwbGFpbnRleHQ7XG4gICAgdHJ5IHtcbiAgICAgICAgcGxhaW50ZXh0ID0gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5kZWNyeXB0KHsgaXYsIG5hbWU6ICdBRVMtQ0JDJyB9LCBlbmNLZXksIGNpcGhlcnRleHQpKTtcbiAgICB9XG4gICAgY2F0Y2gge1xuICAgIH1cbiAgICBpZiAoIXBsYWludGV4dCkge1xuICAgICAgICB0aHJvdyBuZXcgSldFRGVjcnlwdGlvbkZhaWxlZCgpO1xuICAgIH1cbiAgICByZXR1cm4gcGxhaW50ZXh0O1xufVxuYXN5bmMgZnVuY3Rpb24gZ2NtRGVjcnlwdChlbmMsIGNlaywgY2lwaGVydGV4dCwgaXYsIHRhZywgYWFkKSB7XG4gICAgbGV0IGVuY0tleTtcbiAgICBpZiAoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICBlbmNLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLCAnQUVTLUdDTScsIGZhbHNlLCBbJ2RlY3J5cHQnXSk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBjaGVja0VuY0NyeXB0b0tleShjZWssIGVuYywgJ2RlY3J5cHQnKTtcbiAgICAgICAgZW5jS2V5ID0gY2VrO1xuICAgIH1cbiAgICB0cnkge1xuICAgICAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5kZWNyeXB0KHtcbiAgICAgICAgICAgIGFkZGl0aW9uYWxEYXRhOiBhYWQsXG4gICAgICAgICAgICBpdixcbiAgICAgICAgICAgIG5hbWU6ICdBRVMtR0NNJyxcbiAgICAgICAgICAgIHRhZ0xlbmd0aDogMTI4LFxuICAgICAgICB9LCBlbmNLZXksIGNvbmNhdChjaXBoZXJ0ZXh0LCB0YWcpKSk7XG4gICAgfVxuICAgIGNhdGNoIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRURlY3J5cHRpb25GYWlsZWQoKTtcbiAgICB9XG59XG5jb25zdCBkZWNyeXB0ID0gYXN5bmMgKGVuYywgY2VrLCBjaXBoZXJ0ZXh0LCBpdiwgdGFnLCBhYWQpID0+IHtcbiAgICBpZiAoIWlzQ3J5cHRvS2V5KGNlaykgJiYgIShjZWsgaW5zdGFuY2VvZiBVaW50OEFycmF5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChjZWssIC4uLnR5cGVzLCAnVWludDhBcnJheScpKTtcbiAgICB9XG4gICAgaWYgKCFpdikge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEluaXRpYWxpemF0aW9uIFZlY3RvciBtaXNzaW5nJyk7XG4gICAgfVxuICAgIGlmICghdGFnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgQXV0aGVudGljYXRpb24gVGFnIG1pc3NpbmcnKTtcbiAgICB9XG4gICAgY2hlY2tJdkxlbmd0aChlbmMsIGl2KTtcbiAgICBzd2l0Y2ggKGVuYykge1xuICAgICAgICBjYXNlICdBMTI4Q0JDLUhTMjU2JzpcbiAgICAgICAgY2FzZSAnQTE5MkNCQy1IUzM4NCc6XG4gICAgICAgIGNhc2UgJ0EyNTZDQkMtSFM1MTInOlxuICAgICAgICAgICAgaWYgKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpXG4gICAgICAgICAgICAgICAgY2hlY2tDZWtMZW5ndGgoY2VrLCBwYXJzZUludChlbmMuc2xpY2UoLTMpLCAxMCkpO1xuICAgICAgICAgICAgcmV0dXJuIGNiY0RlY3J5cHQoZW5jLCBjZWssIGNpcGhlcnRleHQsIGl2LCB0YWcsIGFhZCk7XG4gICAgICAgIGNhc2UgJ0ExMjhHQ00nOlxuICAgICAgICBjYXNlICdBMTkyR0NNJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTSc6XG4gICAgICAgICAgICBpZiAoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSlcbiAgICAgICAgICAgICAgICBjaGVja0Nla0xlbmd0aChjZWssIHBhcnNlSW50KGVuYy5zbGljZSgxLCA0KSwgMTApKTtcbiAgICAgICAgICAgIHJldHVybiBnY21EZWNyeXB0KGVuYywgY2VrLCBjaXBoZXJ0ZXh0LCBpdiwgdGFnLCBhYWQpO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ1Vuc3VwcG9ydGVkIEpXRSBDb250ZW50IEVuY3J5cHRpb24gQWxnb3JpdGhtJyk7XG4gICAgfVxufTtcbmV4cG9ydCBkZWZhdWx0IGRlY3J5cHQ7XG4iLCJjb25zdCBpc0Rpc2pvaW50ID0gKC4uLmhlYWRlcnMpID0+IHtcbiAgICBjb25zdCBzb3VyY2VzID0gaGVhZGVycy5maWx0ZXIoQm9vbGVhbik7XG4gICAgaWYgKHNvdXJjZXMubGVuZ3RoID09PSAwIHx8IHNvdXJjZXMubGVuZ3RoID09PSAxKSB7XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cbiAgICBsZXQgYWNjO1xuICAgIGZvciAoY29uc3QgaGVhZGVyIG9mIHNvdXJjZXMpIHtcbiAgICAgICAgY29uc3QgcGFyYW1ldGVycyA9IE9iamVjdC5rZXlzKGhlYWRlcik7XG4gICAgICAgIGlmICghYWNjIHx8IGFjYy5zaXplID09PSAwKSB7XG4gICAgICAgICAgICBhY2MgPSBuZXcgU2V0KHBhcmFtZXRlcnMpO1xuICAgICAgICAgICAgY29udGludWU7XG4gICAgICAgIH1cbiAgICAgICAgZm9yIChjb25zdCBwYXJhbWV0ZXIgb2YgcGFyYW1ldGVycykge1xuICAgICAgICAgICAgaWYgKGFjYy5oYXMocGFyYW1ldGVyKSkge1xuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGFjYy5hZGQocGFyYW1ldGVyKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gdHJ1ZTtcbn07XG5leHBvcnQgZGVmYXVsdCBpc0Rpc2pvaW50O1xuIiwiZnVuY3Rpb24gaXNPYmplY3RMaWtlKHZhbHVlKSB7XG4gICAgcmV0dXJuIHR5cGVvZiB2YWx1ZSA9PT0gJ29iamVjdCcgJiYgdmFsdWUgIT09IG51bGw7XG59XG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBpc09iamVjdChpbnB1dCkge1xuICAgIGlmICghaXNPYmplY3RMaWtlKGlucHV0KSB8fCBPYmplY3QucHJvdG90eXBlLnRvU3RyaW5nLmNhbGwoaW5wdXQpICE9PSAnW29iamVjdCBPYmplY3RdJykge1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuICAgIGlmIChPYmplY3QuZ2V0UHJvdG90eXBlT2YoaW5wdXQpID09PSBudWxsKSB7XG4gICAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cbiAgICBsZXQgcHJvdG8gPSBpbnB1dDtcbiAgICB3aGlsZSAoT2JqZWN0LmdldFByb3RvdHlwZU9mKHByb3RvKSAhPT0gbnVsbCkge1xuICAgICAgICBwcm90byA9IE9iamVjdC5nZXRQcm90b3R5cGVPZihwcm90byk7XG4gICAgfVxuICAgIHJldHVybiBPYmplY3QuZ2V0UHJvdG90eXBlT2YoaW5wdXQpID09PSBwcm90bztcbn1cbiIsImNvbnN0IGJvZ3VzV2ViQ3J5cHRvID0gW1xuICAgIHsgaGFzaDogJ1NIQS0yNTYnLCBuYW1lOiAnSE1BQycgfSxcbiAgICB0cnVlLFxuICAgIFsnc2lnbiddLFxuXTtcbmV4cG9ydCBkZWZhdWx0IGJvZ3VzV2ViQ3J5cHRvO1xuIiwiaW1wb3J0IGJvZ3VzV2ViQ3J5cHRvIGZyb20gJy4vYm9ndXMuanMnO1xuaW1wb3J0IGNyeXB0bywgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IGNoZWNrRW5jQ3J5cHRvS2V5IH0gZnJvbSAnLi4vbGliL2NyeXB0b19rZXkuanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmZ1bmN0aW9uIGNoZWNrS2V5U2l6ZShrZXksIGFsZykge1xuICAgIGlmIChrZXkuYWxnb3JpdGhtLmxlbmd0aCAhPT0gcGFyc2VJbnQoYWxnLnNsaWNlKDEsIDQpLCAxMCkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgSW52YWxpZCBrZXkgc2l6ZSBmb3IgYWxnOiAke2FsZ31gKTtcbiAgICB9XG59XG5mdW5jdGlvbiBnZXRDcnlwdG9LZXkoa2V5LCBhbGcsIHVzYWdlKSB7XG4gICAgaWYgKGlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgY2hlY2tFbmNDcnlwdG9LZXkoa2V5LCBhbGcsIHVzYWdlKTtcbiAgICAgICAgcmV0dXJuIGtleTtcbiAgICB9XG4gICAgaWYgKGtleSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBrZXksICdBRVMtS1cnLCB0cnVlLCBbdXNhZ2VdKTtcbiAgICB9XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcywgJ1VpbnQ4QXJyYXknKSk7XG59XG5leHBvcnQgY29uc3Qgd3JhcCA9IGFzeW5jIChhbGcsIGtleSwgY2VrKSA9PiB7XG4gICAgY29uc3QgY3J5cHRvS2V5ID0gYXdhaXQgZ2V0Q3J5cHRvS2V5KGtleSwgYWxnLCAnd3JhcEtleScpO1xuICAgIGNoZWNrS2V5U2l6ZShjcnlwdG9LZXksIGFsZyk7XG4gICAgY29uc3QgY3J5cHRvS2V5Q2VrID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGNlaywgLi4uYm9ndXNXZWJDcnlwdG8pO1xuICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLndyYXBLZXkoJ3JhdycsIGNyeXB0b0tleUNlaywgY3J5cHRvS2V5LCAnQUVTLUtXJykpO1xufTtcbmV4cG9ydCBjb25zdCB1bndyYXAgPSBhc3luYyAoYWxnLCBrZXksIGVuY3J5cHRlZEtleSkgPT4ge1xuICAgIGNvbnN0IGNyeXB0b0tleSA9IGF3YWl0IGdldENyeXB0b0tleShrZXksIGFsZywgJ3Vud3JhcEtleScpO1xuICAgIGNoZWNrS2V5U2l6ZShjcnlwdG9LZXksIGFsZyk7XG4gICAgY29uc3QgY3J5cHRvS2V5Q2VrID0gYXdhaXQgY3J5cHRvLnN1YnRsZS51bndyYXBLZXkoJ3JhdycsIGVuY3J5cHRlZEtleSwgY3J5cHRvS2V5LCAnQUVTLUtXJywgLi4uYm9ndXNXZWJDcnlwdG8pO1xuICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgncmF3JywgY3J5cHRvS2V5Q2VrKSk7XG59O1xuIiwiaW1wb3J0IHsgZW5jb2RlciwgY29uY2F0LCB1aW50MzJiZSwgbGVuZ3RoQW5kSW5wdXQsIGNvbmNhdEtkZiB9IGZyb20gJy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IGNyeXB0bywgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IGNoZWNrRW5jQ3J5cHRvS2V5IH0gZnJvbSAnLi4vbGliL2NyeXB0b19rZXkuanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZXJpdmVLZXkocHVibGljS2V5LCBwcml2YXRlS2V5LCBhbGdvcml0aG0sIGtleUxlbmd0aCwgYXB1ID0gbmV3IFVpbnQ4QXJyYXkoMCksIGFwdiA9IG5ldyBVaW50OEFycmF5KDApKSB7XG4gICAgaWYgKCFpc0NyeXB0b0tleShwdWJsaWNLZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KHB1YmxpY0tleSwgLi4udHlwZXMpKTtcbiAgICB9XG4gICAgY2hlY2tFbmNDcnlwdG9LZXkocHVibGljS2V5LCAnRUNESCcpO1xuICAgIGlmICghaXNDcnlwdG9LZXkocHJpdmF0ZUtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQocHJpdmF0ZUtleSwgLi4udHlwZXMpKTtcbiAgICB9XG4gICAgY2hlY2tFbmNDcnlwdG9LZXkocHJpdmF0ZUtleSwgJ0VDREgnLCAnZGVyaXZlQml0cycpO1xuICAgIGNvbnN0IHZhbHVlID0gY29uY2F0KGxlbmd0aEFuZElucHV0KGVuY29kZXIuZW5jb2RlKGFsZ29yaXRobSkpLCBsZW5ndGhBbmRJbnB1dChhcHUpLCBsZW5ndGhBbmRJbnB1dChhcHYpLCB1aW50MzJiZShrZXlMZW5ndGgpKTtcbiAgICBsZXQgbGVuZ3RoO1xuICAgIGlmIChwdWJsaWNLZXkuYWxnb3JpdGhtLm5hbWUgPT09ICdYMjU1MTknKSB7XG4gICAgICAgIGxlbmd0aCA9IDI1NjtcbiAgICB9XG4gICAgZWxzZSBpZiAocHVibGljS2V5LmFsZ29yaXRobS5uYW1lID09PSAnWDQ0OCcpIHtcbiAgICAgICAgbGVuZ3RoID0gNDQ4O1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgbGVuZ3RoID1cbiAgICAgICAgICAgIE1hdGguY2VpbChwYXJzZUludChwdWJsaWNLZXkuYWxnb3JpdGhtLm5hbWVkQ3VydmUuc3Vic3RyKC0zKSwgMTApIC8gOCkgPDwgMztcbiAgICB9XG4gICAgY29uc3Qgc2hhcmVkU2VjcmV0ID0gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5kZXJpdmVCaXRzKHtcbiAgICAgICAgbmFtZTogcHVibGljS2V5LmFsZ29yaXRobS5uYW1lLFxuICAgICAgICBwdWJsaWM6IHB1YmxpY0tleSxcbiAgICB9LCBwcml2YXRlS2V5LCBsZW5ndGgpKTtcbiAgICByZXR1cm4gY29uY2F0S2RmKHNoYXJlZFNlY3JldCwga2V5TGVuZ3RoLCB2YWx1ZSk7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhdGVFcGsoa2V5KSB7XG4gICAgaWYgKCFpc0NyeXB0b0tleShrZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGtleSwgLi4udHlwZXMpKTtcbiAgICB9XG4gICAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuZ2VuZXJhdGVLZXkoa2V5LmFsZ29yaXRobSwgdHJ1ZSwgWydkZXJpdmVCaXRzJ10pO1xufVxuZXhwb3J0IGZ1bmN0aW9uIGVjZGhBbGxvd2VkKGtleSkge1xuICAgIGlmICghaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzKSk7XG4gICAgfVxuICAgIHJldHVybiAoWydQLTI1NicsICdQLTM4NCcsICdQLTUyMSddLmluY2x1ZGVzKGtleS5hbGdvcml0aG0ubmFtZWRDdXJ2ZSkgfHxcbiAgICAgICAga2V5LmFsZ29yaXRobS5uYW1lID09PSAnWDI1NTE5JyB8fFxuICAgICAgICBrZXkuYWxnb3JpdGhtLm5hbWUgPT09ICdYNDQ4Jyk7XG59XG4iLCJpbXBvcnQgeyBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gY2hlY2tQMnMocDJzKSB7XG4gICAgaWYgKCEocDJzIGluc3RhbmNlb2YgVWludDhBcnJheSkgfHwgcDJzLmxlbmd0aCA8IDgpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ1BCRVMyIFNhbHQgSW5wdXQgbXVzdCBiZSA4IG9yIG1vcmUgb2N0ZXRzJyk7XG4gICAgfVxufVxuIiwiaW1wb3J0IHJhbmRvbSBmcm9tICcuL3JhbmRvbS5qcyc7XG5pbXBvcnQgeyBwMnMgYXMgY29uY2F0U2FsdCB9IGZyb20gJy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IHsgZW5jb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4vYmFzZTY0dXJsLmpzJztcbmltcG9ydCB7IHdyYXAsIHVud3JhcCB9IGZyb20gJy4vYWVza3cuanMnO1xuaW1wb3J0IGNoZWNrUDJzIGZyb20gJy4uL2xpYi9jaGVja19wMnMuanMnO1xuaW1wb3J0IGNyeXB0bywgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IGNoZWNrRW5jQ3J5cHRvS2V5IH0gZnJvbSAnLi4vbGliL2NyeXB0b19rZXkuanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmZ1bmN0aW9uIGdldENyeXB0b0tleShrZXksIGFsZykge1xuICAgIGlmIChrZXkgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIHJldHVybiBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3Jywga2V5LCAnUEJLREYyJywgZmFsc2UsIFsnZGVyaXZlQml0cyddKTtcbiAgICB9XG4gICAgaWYgKGlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgY2hlY2tFbmNDcnlwdG9LZXkoa2V5LCBhbGcsICdkZXJpdmVCaXRzJywgJ2Rlcml2ZUtleScpO1xuICAgICAgICByZXR1cm4ga2V5O1xuICAgIH1cbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzLCAnVWludDhBcnJheScpKTtcbn1cbmFzeW5jIGZ1bmN0aW9uIGRlcml2ZUtleShwMnMsIGFsZywgcDJjLCBrZXkpIHtcbiAgICBjaGVja1AycyhwMnMpO1xuICAgIGNvbnN0IHNhbHQgPSBjb25jYXRTYWx0KGFsZywgcDJzKTtcbiAgICBjb25zdCBrZXlsZW4gPSBwYXJzZUludChhbGcuc2xpY2UoMTMsIDE2KSwgMTApO1xuICAgIGNvbnN0IHN1YnRsZUFsZyA9IHtcbiAgICAgICAgaGFzaDogYFNIQS0ke2FsZy5zbGljZSg4LCAxMSl9YCxcbiAgICAgICAgaXRlcmF0aW9uczogcDJjLFxuICAgICAgICBuYW1lOiAnUEJLREYyJyxcbiAgICAgICAgc2FsdCxcbiAgICB9O1xuICAgIGNvbnN0IHdyYXBBbGcgPSB7XG4gICAgICAgIGxlbmd0aDoga2V5bGVuLFxuICAgICAgICBuYW1lOiAnQUVTLUtXJyxcbiAgICB9O1xuICAgIGNvbnN0IGNyeXB0b0tleSA9IGF3YWl0IGdldENyeXB0b0tleShrZXksIGFsZyk7XG4gICAgaWYgKGNyeXB0b0tleS51c2FnZXMuaW5jbHVkZXMoJ2Rlcml2ZUJpdHMnKSkge1xuICAgICAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5kZXJpdmVCaXRzKHN1YnRsZUFsZywgY3J5cHRvS2V5LCBrZXlsZW4pKTtcbiAgICB9XG4gICAgaWYgKGNyeXB0b0tleS51c2FnZXMuaW5jbHVkZXMoJ2Rlcml2ZUtleScpKSB7XG4gICAgICAgIHJldHVybiBjcnlwdG8uc3VidGxlLmRlcml2ZUtleShzdWJ0bGVBbGcsIGNyeXB0b0tleSwgd3JhcEFsZywgZmFsc2UsIFsnd3JhcEtleScsICd1bndyYXBLZXknXSk7XG4gICAgfVxuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1BCS0RGMiBrZXkgXCJ1c2FnZXNcIiBtdXN0IGluY2x1ZGUgXCJkZXJpdmVCaXRzXCIgb3IgXCJkZXJpdmVLZXlcIicpO1xufVxuZXhwb3J0IGNvbnN0IGVuY3J5cHQgPSBhc3luYyAoYWxnLCBrZXksIGNlaywgcDJjID0gMjA0OCwgcDJzID0gcmFuZG9tKG5ldyBVaW50OEFycmF5KDE2KSkpID0+IHtcbiAgICBjb25zdCBkZXJpdmVkID0gYXdhaXQgZGVyaXZlS2V5KHAycywgYWxnLCBwMmMsIGtleSk7XG4gICAgY29uc3QgZW5jcnlwdGVkS2V5ID0gYXdhaXQgd3JhcChhbGcuc2xpY2UoLTYpLCBkZXJpdmVkLCBjZWspO1xuICAgIHJldHVybiB7IGVuY3J5cHRlZEtleSwgcDJjLCBwMnM6IGJhc2U2NHVybChwMnMpIH07XG59O1xuZXhwb3J0IGNvbnN0IGRlY3J5cHQgPSBhc3luYyAoYWxnLCBrZXksIGVuY3J5cHRlZEtleSwgcDJjLCBwMnMpID0+IHtcbiAgICBjb25zdCBkZXJpdmVkID0gYXdhaXQgZGVyaXZlS2V5KHAycywgYWxnLCBwMmMsIGtleSk7XG4gICAgcmV0dXJuIHVud3JhcChhbGcuc2xpY2UoLTYpLCBkZXJpdmVkLCBlbmNyeXB0ZWRLZXkpO1xufTtcbiIsImltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5leHBvcnQgZGVmYXVsdCBmdW5jdGlvbiBzdWJ0bGVSc2FFcyhhbGcpIHtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdSU0EtT0FFUCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTI1Nic6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTM4NCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTUxMic6XG4gICAgICAgICAgICByZXR1cm4gJ1JTQS1PQUVQJztcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKGBhbGcgJHthbGd9IGlzIG5vdCBzdXBwb3J0ZWQgZWl0aGVyIGJ5IEpPU0Ugb3IgeW91ciBqYXZhc2NyaXB0IHJ1bnRpbWVgKTtcbiAgICB9XG59XG4iLCJleHBvcnQgZGVmYXVsdCAoYWxnLCBrZXkpID0+IHtcbiAgICBpZiAoYWxnLnN0YXJ0c1dpdGgoJ1JTJykgfHwgYWxnLnN0YXJ0c1dpdGgoJ1BTJykpIHtcbiAgICAgICAgY29uc3QgeyBtb2R1bHVzTGVuZ3RoIH0gPSBrZXkuYWxnb3JpdGhtO1xuICAgICAgICBpZiAodHlwZW9mIG1vZHVsdXNMZW5ndGggIT09ICdudW1iZXInIHx8IG1vZHVsdXNMZW5ndGggPCAyMDQ4KSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGAke2FsZ30gcmVxdWlyZXMga2V5IG1vZHVsdXNMZW5ndGggdG8gYmUgMjA0OCBiaXRzIG9yIGxhcmdlcmApO1xuICAgICAgICB9XG4gICAgfVxufTtcbiIsImltcG9ydCBzdWJ0bGVBbGdvcml0aG0gZnJvbSAnLi9zdWJ0bGVfcnNhZXMuanMnO1xuaW1wb3J0IGJvZ3VzV2ViQ3J5cHRvIGZyb20gJy4vYm9ndXMuanMnO1xuaW1wb3J0IGNyeXB0bywgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IGNoZWNrRW5jQ3J5cHRvS2V5IH0gZnJvbSAnLi4vbGliL2NyeXB0b19rZXkuanMnO1xuaW1wb3J0IGNoZWNrS2V5TGVuZ3RoIGZyb20gJy4vY2hlY2tfa2V5X2xlbmd0aC5qcyc7XG5pbXBvcnQgaW52YWxpZEtleUlucHV0IGZyb20gJy4uL2xpYi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgeyB0eXBlcyB9IGZyb20gJy4vaXNfa2V5X2xpa2UuanMnO1xuZXhwb3J0IGNvbnN0IGVuY3J5cHQgPSBhc3luYyAoYWxnLCBrZXksIGNlaykgPT4ge1xuICAgIGlmICghaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzKSk7XG4gICAgfVxuICAgIGNoZWNrRW5jQ3J5cHRvS2V5KGtleSwgYWxnLCAnZW5jcnlwdCcsICd3cmFwS2V5Jyk7XG4gICAgY2hlY2tLZXlMZW5ndGgoYWxnLCBrZXkpO1xuICAgIGlmIChrZXkudXNhZ2VzLmluY2x1ZGVzKCdlbmNyeXB0JykpIHtcbiAgICAgICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KGF3YWl0IGNyeXB0by5zdWJ0bGUuZW5jcnlwdChzdWJ0bGVBbGdvcml0aG0oYWxnKSwga2V5LCBjZWspKTtcbiAgICB9XG4gICAgaWYgKGtleS51c2FnZXMuaW5jbHVkZXMoJ3dyYXBLZXknKSkge1xuICAgICAgICBjb25zdCBjcnlwdG9LZXlDZWsgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLCAuLi5ib2d1c1dlYkNyeXB0byk7XG4gICAgICAgIHJldHVybiBuZXcgVWludDhBcnJheShhd2FpdCBjcnlwdG8uc3VidGxlLndyYXBLZXkoJ3JhdycsIGNyeXB0b0tleUNlaywga2V5LCBzdWJ0bGVBbGdvcml0aG0oYWxnKSkpO1xuICAgIH1cbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdSU0EtT0FFUCBrZXkgXCJ1c2FnZXNcIiBtdXN0IGluY2x1ZGUgXCJlbmNyeXB0XCIgb3IgXCJ3cmFwS2V5XCIgZm9yIHRoaXMgb3BlcmF0aW9uJyk7XG59O1xuZXhwb3J0IGNvbnN0IGRlY3J5cHQgPSBhc3luYyAoYWxnLCBrZXksIGVuY3J5cHRlZEtleSkgPT4ge1xuICAgIGlmICghaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzKSk7XG4gICAgfVxuICAgIGNoZWNrRW5jQ3J5cHRvS2V5KGtleSwgYWxnLCAnZGVjcnlwdCcsICd1bndyYXBLZXknKTtcbiAgICBjaGVja0tleUxlbmd0aChhbGcsIGtleSk7XG4gICAgaWYgKGtleS51c2FnZXMuaW5jbHVkZXMoJ2RlY3J5cHQnKSkge1xuICAgICAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5kZWNyeXB0KHN1YnRsZUFsZ29yaXRobShhbGcpLCBrZXksIGVuY3J5cHRlZEtleSkpO1xuICAgIH1cbiAgICBpZiAoa2V5LnVzYWdlcy5pbmNsdWRlcygndW53cmFwS2V5JykpIHtcbiAgICAgICAgY29uc3QgY3J5cHRvS2V5Q2VrID0gYXdhaXQgY3J5cHRvLnN1YnRsZS51bndyYXBLZXkoJ3JhdycsIGVuY3J5cHRlZEtleSwga2V5LCBzdWJ0bGVBbGdvcml0aG0oYWxnKSwgLi4uYm9ndXNXZWJDcnlwdG8pO1xuICAgICAgICByZXR1cm4gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoJ3JhdycsIGNyeXB0b0tleUNlaykpO1xuICAgIH1cbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdSU0EtT0FFUCBrZXkgXCJ1c2FnZXNcIiBtdXN0IGluY2x1ZGUgXCJkZWNyeXB0XCIgb3IgXCJ1bndyYXBLZXlcIiBmb3IgdGhpcyBvcGVyYXRpb24nKTtcbn07XG4iLCJpbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHJhbmRvbSBmcm9tICcuLi9ydW50aW1lL3JhbmRvbS5qcyc7XG5leHBvcnQgZnVuY3Rpb24gYml0TGVuZ3RoKGFsZykge1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ0ExMjhHQ00nOlxuICAgICAgICAgICAgcmV0dXJuIDEyODtcbiAgICAgICAgY2FzZSAnQTE5MkdDTSc6XG4gICAgICAgICAgICByZXR1cm4gMTkyO1xuICAgICAgICBjYXNlICdBMjU2R0NNJzpcbiAgICAgICAgY2FzZSAnQTEyOENCQy1IUzI1Nic6XG4gICAgICAgICAgICByZXR1cm4gMjU2O1xuICAgICAgICBjYXNlICdBMTkyQ0JDLUhTMzg0JzpcbiAgICAgICAgICAgIHJldHVybiAzODQ7XG4gICAgICAgIGNhc2UgJ0EyNTZDQkMtSFM1MTInOlxuICAgICAgICAgICAgcmV0dXJuIDUxMjtcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKGBVbnN1cHBvcnRlZCBKV0UgQWxnb3JpdGhtOiAke2FsZ31gKTtcbiAgICB9XG59XG5leHBvcnQgZGVmYXVsdCAoYWxnKSA9PiByYW5kb20obmV3IFVpbnQ4QXJyYXkoYml0TGVuZ3RoKGFsZykgPj4gMykpO1xuIiwiaW1wb3J0IGNyeXB0byBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuZnVuY3Rpb24gc3VidGxlTWFwcGluZyhqd2spIHtcbiAgICBsZXQgYWxnb3JpdGhtO1xuICAgIGxldCBrZXlVc2FnZXM7XG4gICAgc3dpdGNoIChqd2sua3R5KSB7XG4gICAgICAgIGNhc2UgJ1JTQSc6IHtcbiAgICAgICAgICAgIHN3aXRjaCAoandrLmFsZykge1xuICAgICAgICAgICAgICAgIGNhc2UgJ1BTMjU2JzpcbiAgICAgICAgICAgICAgICBjYXNlICdQUzM4NCc6XG4gICAgICAgICAgICAgICAgY2FzZSAnUFM1MTInOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdSU0EtUFNTJywgaGFzaDogYFNIQS0ke2p3ay5hbGcuc2xpY2UoLTMpfWAgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ3NpZ24nXSA6IFsndmVyaWZ5J107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ1JTMjU2JzpcbiAgICAgICAgICAgICAgICBjYXNlICdSUzM4NCc6XG4gICAgICAgICAgICAgICAgY2FzZSAnUlM1MTInOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdSU0FTU0EtUEtDUzEtdjFfNScsIGhhc2g6IGBTSEEtJHtqd2suYWxnLnNsaWNlKC0zKX1gIH07XG4gICAgICAgICAgICAgICAgICAgIGtleVVzYWdlcyA9IGp3ay5kID8gWydzaWduJ10gOiBbJ3ZlcmlmeSddO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlICdSU0EtT0FFUCc6XG4gICAgICAgICAgICAgICAgY2FzZSAnUlNBLU9BRVAtMjU2JzpcbiAgICAgICAgICAgICAgICBjYXNlICdSU0EtT0FFUC0zODQnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1JTQS1PQUVQLTUxMic6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIG5hbWU6ICdSU0EtT0FFUCcsXG4gICAgICAgICAgICAgICAgICAgICAgICBoYXNoOiBgU0hBLSR7cGFyc2VJbnQoandrLmFsZy5zbGljZSgtMyksIDEwKSB8fCAxfWAsXG4gICAgICAgICAgICAgICAgICAgIH07XG4gICAgICAgICAgICAgICAgICAgIGtleVVzYWdlcyA9IGp3ay5kID8gWydkZWNyeXB0JywgJ3Vud3JhcEtleSddIDogWydlbmNyeXB0JywgJ3dyYXBLZXknXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgSldLIFwiYWxnXCIgKEFsZ29yaXRobSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdFQyc6IHtcbiAgICAgICAgICAgIHN3aXRjaCAoandrLmFsZykge1xuICAgICAgICAgICAgICAgIGNhc2UgJ0VTMjU2JzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNEU0EnLCBuYW1lZEN1cnZlOiAnUC0yNTYnIH07XG4gICAgICAgICAgICAgICAgICAgIGtleVVzYWdlcyA9IGp3ay5kID8gWydzaWduJ10gOiBbJ3ZlcmlmeSddO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBjYXNlICdFUzM4NCc6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0VDRFNBJywgbmFtZWRDdXJ2ZTogJ1AtMzg0JyB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnc2lnbiddIDogWyd2ZXJpZnknXTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgY2FzZSAnRVM1MTInOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RTQScsIG5hbWVkQ3VydmU6ICdQLTUyMScgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ3NpZ24nXSA6IFsndmVyaWZ5J107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMrQTEyOEtXJzpcbiAgICAgICAgICAgICAgICBjYXNlICdFQ0RILUVTK0ExOTJLVyc6XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUytBMjU2S1cnOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6ICdFQ0RIJywgbmFtZWRDdXJ2ZTogandrLmNydiB9O1xuICAgICAgICAgICAgICAgICAgICBrZXlVc2FnZXMgPSBqd2suZCA/IFsnZGVyaXZlQml0cyddIDogW107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIEpXSyBcImFsZ1wiIChBbGdvcml0aG0pIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnT0tQJzoge1xuICAgICAgICAgICAgc3dpdGNoIChqd2suYWxnKSB7XG4gICAgICAgICAgICAgICAgY2FzZSAnRWREU0EnOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6IGp3ay5jcnYgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ3NpZ24nXSA6IFsndmVyaWZ5J107XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ0VDREgtRVMrQTEyOEtXJzpcbiAgICAgICAgICAgICAgICBjYXNlICdFQ0RILUVTK0ExOTJLVyc6XG4gICAgICAgICAgICAgICAgY2FzZSAnRUNESC1FUytBMjU2S1cnOlxuICAgICAgICAgICAgICAgICAgICBhbGdvcml0aG0gPSB7IG5hbWU6IGp3ay5jcnYgfTtcbiAgICAgICAgICAgICAgICAgICAga2V5VXNhZ2VzID0gandrLmQgPyBbJ2Rlcml2ZUJpdHMnXSA6IFtdO1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBKV0sgXCJhbGdcIiAoQWxnb3JpdGhtKSBQYXJhbWV0ZXIgdmFsdWUnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBKV0sgXCJrdHlcIiAoS2V5IFR5cGUpIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgIH1cbiAgICByZXR1cm4geyBhbGdvcml0aG0sIGtleVVzYWdlcyB9O1xufVxuY29uc3QgcGFyc2UgPSBhc3luYyAoandrKSA9PiB7XG4gICAgaWYgKCFqd2suYWxnKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1wiYWxnXCIgYXJndW1lbnQgaXMgcmVxdWlyZWQgd2hlbiBcImp3ay5hbGdcIiBpcyBub3QgcHJlc2VudCcpO1xuICAgIH1cbiAgICBjb25zdCB7IGFsZ29yaXRobSwga2V5VXNhZ2VzIH0gPSBzdWJ0bGVNYXBwaW5nKGp3ayk7XG4gICAgY29uc3QgcmVzdCA9IFtcbiAgICAgICAgYWxnb3JpdGhtLFxuICAgICAgICBqd2suZXh0ID8/IGZhbHNlLFxuICAgICAgICBqd2sua2V5X29wcyA/PyBrZXlVc2FnZXMsXG4gICAgXTtcbiAgICBjb25zdCBrZXlEYXRhID0geyAuLi5qd2sgfTtcbiAgICBkZWxldGUga2V5RGF0YS5hbGc7XG4gICAgZGVsZXRlIGtleURhdGEudXNlO1xuICAgIHJldHVybiBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgnandrJywga2V5RGF0YSwgLi4ucmVzdCk7XG59O1xuZXhwb3J0IGRlZmF1bHQgcGFyc2U7XG4iLCJpbXBvcnQgeyBkZWNvZGUgYXMgZGVjb2RlQmFzZTY0VVJMIH0gZnJvbSAnLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHsgZnJvbVNQS0ksIGZyb21QS0NTOCwgZnJvbVg1MDkgfSBmcm9tICcuLi9ydW50aW1lL2FzbjEuanMnO1xuaW1wb3J0IGFzS2V5T2JqZWN0IGZyb20gJy4uL3J1bnRpbWUvandrX3RvX2tleS5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4uL2xpYi9pc19vYmplY3QuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGltcG9ydFNQS0koc3BraSwgYWxnLCBvcHRpb25zKSB7XG4gICAgaWYgKHR5cGVvZiBzcGtpICE9PSAnc3RyaW5nJyB8fCBzcGtpLmluZGV4T2YoJy0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tJykgIT09IDApIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignXCJzcGtpXCIgbXVzdCBiZSBTUEtJIGZvcm1hdHRlZCBzdHJpbmcnKTtcbiAgICB9XG4gICAgcmV0dXJuIGZyb21TUEtJKHNwa2ksIGFsZywgb3B0aW9ucyk7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gaW1wb3J0WDUwOSh4NTA5LCBhbGcsIG9wdGlvbnMpIHtcbiAgICBpZiAodHlwZW9mIHg1MDkgIT09ICdzdHJpbmcnIHx8IHg1MDkuaW5kZXhPZignLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tJykgIT09IDApIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignXCJ4NTA5XCIgbXVzdCBiZSBYLjUwOSBmb3JtYXR0ZWQgc3RyaW5nJyk7XG4gICAgfVxuICAgIHJldHVybiBmcm9tWDUwOSh4NTA5LCBhbGcsIG9wdGlvbnMpO1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGltcG9ydFBLQ1M4KHBrY3M4LCBhbGcsIG9wdGlvbnMpIHtcbiAgICBpZiAodHlwZW9mIHBrY3M4ICE9PSAnc3RyaW5nJyB8fCBwa2NzOC5pbmRleE9mKCctLS0tLUJFR0lOIFBSSVZBVEUgS0VZLS0tLS0nKSAhPT0gMCkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdcInBrY3M4XCIgbXVzdCBiZSBQS0NTIzggZm9ybWF0dGVkIHN0cmluZycpO1xuICAgIH1cbiAgICByZXR1cm4gZnJvbVBLQ1M4KHBrY3M4LCBhbGcsIG9wdGlvbnMpO1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGltcG9ydEpXSyhqd2ssIGFsZykge1xuICAgIGlmICghaXNPYmplY3QoandrKSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdKV0sgbXVzdCBiZSBhbiBvYmplY3QnKTtcbiAgICB9XG4gICAgYWxnIHx8IChhbGcgPSBqd2suYWxnKTtcbiAgICBzd2l0Y2ggKGp3ay5rdHkpIHtcbiAgICAgICAgY2FzZSAnb2N0JzpcbiAgICAgICAgICAgIGlmICh0eXBlb2YgandrLmsgIT09ICdzdHJpbmcnIHx8ICFqd2suaykge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ21pc3NpbmcgXCJrXCIgKEtleSBWYWx1ZSkgUGFyYW1ldGVyIHZhbHVlJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gZGVjb2RlQmFzZTY0VVJMKGp3ay5rKTtcbiAgICAgICAgY2FzZSAnUlNBJzpcbiAgICAgICAgICAgIGlmIChqd2sub3RoICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnUlNBIEpXSyBcIm90aFwiIChPdGhlciBQcmltZXMgSW5mbykgUGFyYW1ldGVyIHZhbHVlIGlzIG5vdCBzdXBwb3J0ZWQnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgY2FzZSAnRUMnOlxuICAgICAgICBjYXNlICdPS1AnOlxuICAgICAgICAgICAgcmV0dXJuIGFzS2V5T2JqZWN0KHsgLi4uandrLCBhbGcgfSk7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnVW5zdXBwb3J0ZWQgXCJrdHlcIiAoS2V5IFR5cGUpIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgIH1cbn1cbiIsImltcG9ydCB7IHdpdGhBbGcgYXMgaW52YWxpZEtleUlucHV0IH0gZnJvbSAnLi9pbnZhbGlkX2tleV9pbnB1dC5qcyc7XG5pbXBvcnQgaXNLZXlMaWtlLCB7IHR5cGVzIH0gZnJvbSAnLi4vcnVudGltZS9pc19rZXlfbGlrZS5qcyc7XG5jb25zdCBzeW1tZXRyaWNUeXBlQ2hlY2sgPSAoYWxnLCBrZXkpID0+IHtcbiAgICBpZiAoa2V5IGluc3RhbmNlb2YgVWludDhBcnJheSlcbiAgICAgICAgcmV0dXJuO1xuICAgIGlmICghaXNLZXlMaWtlKGtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoYWxnLCBrZXksIC4uLnR5cGVzLCAnVWludDhBcnJheScpKTtcbiAgICB9XG4gICAgaWYgKGtleS50eXBlICE9PSAnc2VjcmV0Jykge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGAke3R5cGVzLmpvaW4oJyBvciAnKX0gaW5zdGFuY2VzIGZvciBzeW1tZXRyaWMgYWxnb3JpdGhtcyBtdXN0IGJlIG9mIHR5cGUgXCJzZWNyZXRcImApO1xuICAgIH1cbn07XG5jb25zdCBhc3ltbWV0cmljVHlwZUNoZWNrID0gKGFsZywga2V5LCB1c2FnZSkgPT4ge1xuICAgIGlmICghaXNLZXlMaWtlKGtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoYWxnLCBrZXksIC4uLnR5cGVzKSk7XG4gICAgfVxuICAgIGlmIChrZXkudHlwZSA9PT0gJ3NlY3JldCcpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHt0eXBlcy5qb2luKCcgb3IgJyl9IGluc3RhbmNlcyBmb3IgYXN5bW1ldHJpYyBhbGdvcml0aG1zIG11c3Qgbm90IGJlIG9mIHR5cGUgXCJzZWNyZXRcImApO1xuICAgIH1cbiAgICBpZiAodXNhZ2UgPT09ICdzaWduJyAmJiBrZXkudHlwZSA9PT0gJ3B1YmxpYycpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHt0eXBlcy5qb2luKCcgb3IgJyl9IGluc3RhbmNlcyBmb3IgYXN5bW1ldHJpYyBhbGdvcml0aG0gc2lnbmluZyBtdXN0IGJlIG9mIHR5cGUgXCJwcml2YXRlXCJgKTtcbiAgICB9XG4gICAgaWYgKHVzYWdlID09PSAnZGVjcnlwdCcgJiYga2V5LnR5cGUgPT09ICdwdWJsaWMnKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYCR7dHlwZXMuam9pbignIG9yICcpfSBpbnN0YW5jZXMgZm9yIGFzeW1tZXRyaWMgYWxnb3JpdGhtIGRlY3J5cHRpb24gbXVzdCBiZSBvZiB0eXBlIFwicHJpdmF0ZVwiYCk7XG4gICAgfVxuICAgIGlmIChrZXkuYWxnb3JpdGhtICYmIHVzYWdlID09PSAndmVyaWZ5JyAmJiBrZXkudHlwZSA9PT0gJ3ByaXZhdGUnKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoYCR7dHlwZXMuam9pbignIG9yICcpfSBpbnN0YW5jZXMgZm9yIGFzeW1tZXRyaWMgYWxnb3JpdGhtIHZlcmlmeWluZyBtdXN0IGJlIG9mIHR5cGUgXCJwdWJsaWNcImApO1xuICAgIH1cbiAgICBpZiAoa2V5LmFsZ29yaXRobSAmJiB1c2FnZSA9PT0gJ2VuY3J5cHQnICYmIGtleS50eXBlID09PSAncHJpdmF0ZScpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgJHt0eXBlcy5qb2luKCcgb3IgJyl9IGluc3RhbmNlcyBmb3IgYXN5bW1ldHJpYyBhbGdvcml0aG0gZW5jcnlwdGlvbiBtdXN0IGJlIG9mIHR5cGUgXCJwdWJsaWNcImApO1xuICAgIH1cbn07XG5jb25zdCBjaGVja0tleVR5cGUgPSAoYWxnLCBrZXksIHVzYWdlKSA9PiB7XG4gICAgY29uc3Qgc3ltbWV0cmljID0gYWxnLnN0YXJ0c1dpdGgoJ0hTJykgfHxcbiAgICAgICAgYWxnID09PSAnZGlyJyB8fFxuICAgICAgICBhbGcuc3RhcnRzV2l0aCgnUEJFUzInKSB8fFxuICAgICAgICAvXkFcXGR7M30oPzpHQ00pP0tXJC8udGVzdChhbGcpO1xuICAgIGlmIChzeW1tZXRyaWMpIHtcbiAgICAgICAgc3ltbWV0cmljVHlwZUNoZWNrKGFsZywga2V5KTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIGFzeW1tZXRyaWNUeXBlQ2hlY2soYWxnLCBrZXksIHVzYWdlKTtcbiAgICB9XG59O1xuZXhwb3J0IGRlZmF1bHQgY2hlY2tLZXlUeXBlO1xuIiwiaW1wb3J0IHsgY29uY2F0LCB1aW50NjRiZSB9IGZyb20gJy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IGNoZWNrSXZMZW5ndGggZnJvbSAnLi4vbGliL2NoZWNrX2l2X2xlbmd0aC5qcyc7XG5pbXBvcnQgY2hlY2tDZWtMZW5ndGggZnJvbSAnLi9jaGVja19jZWtfbGVuZ3RoLmpzJztcbmltcG9ydCBjcnlwdG8sIHsgaXNDcnlwdG9LZXkgfSBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgeyBjaGVja0VuY0NyeXB0b0tleSB9IGZyb20gJy4uL2xpYi9jcnlwdG9fa2V5LmpzJztcbmltcG9ydCBpbnZhbGlkS2V5SW5wdXQgZnJvbSAnLi4vbGliL2ludmFsaWRfa2V5X2lucHV0LmpzJztcbmltcG9ydCBnZW5lcmF0ZUl2IGZyb20gJy4uL2xpYi9pdi5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmFzeW5jIGZ1bmN0aW9uIGNiY0VuY3J5cHQoZW5jLCBwbGFpbnRleHQsIGNlaywgaXYsIGFhZCkge1xuICAgIGlmICghKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoaW52YWxpZEtleUlucHV0KGNlaywgJ1VpbnQ4QXJyYXknKSk7XG4gICAgfVxuICAgIGNvbnN0IGtleVNpemUgPSBwYXJzZUludChlbmMuc2xpY2UoMSwgNCksIDEwKTtcbiAgICBjb25zdCBlbmNLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLnN1YmFycmF5KGtleVNpemUgPj4gMyksICdBRVMtQ0JDJywgZmFsc2UsIFsnZW5jcnlwdCddKTtcbiAgICBjb25zdCBtYWNLZXkgPSBhd2FpdCBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgY2VrLnN1YmFycmF5KDAsIGtleVNpemUgPj4gMyksIHtcbiAgICAgICAgaGFzaDogYFNIQS0ke2tleVNpemUgPDwgMX1gLFxuICAgICAgICBuYW1lOiAnSE1BQycsXG4gICAgfSwgZmFsc2UsIFsnc2lnbiddKTtcbiAgICBjb25zdCBjaXBoZXJ0ZXh0ID0gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5lbmNyeXB0KHtcbiAgICAgICAgaXYsXG4gICAgICAgIG5hbWU6ICdBRVMtQ0JDJyxcbiAgICB9LCBlbmNLZXksIHBsYWludGV4dCkpO1xuICAgIGNvbnN0IG1hY0RhdGEgPSBjb25jYXQoYWFkLCBpdiwgY2lwaGVydGV4dCwgdWludDY0YmUoYWFkLmxlbmd0aCA8PCAzKSk7XG4gICAgY29uc3QgdGFnID0gbmV3IFVpbnQ4QXJyYXkoKGF3YWl0IGNyeXB0by5zdWJ0bGUuc2lnbignSE1BQycsIG1hY0tleSwgbWFjRGF0YSkpLnNsaWNlKDAsIGtleVNpemUgPj4gMykpO1xuICAgIHJldHVybiB7IGNpcGhlcnRleHQsIHRhZywgaXYgfTtcbn1cbmFzeW5jIGZ1bmN0aW9uIGdjbUVuY3J5cHQoZW5jLCBwbGFpbnRleHQsIGNlaywgaXYsIGFhZCkge1xuICAgIGxldCBlbmNLZXk7XG4gICAgaWYgKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgZW5jS2V5ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoJ3JhdycsIGNlaywgJ0FFUy1HQ00nLCBmYWxzZSwgWydlbmNyeXB0J10pO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgY2hlY2tFbmNDcnlwdG9LZXkoY2VrLCBlbmMsICdlbmNyeXB0Jyk7XG4gICAgICAgIGVuY0tleSA9IGNlaztcbiAgICB9XG4gICAgY29uc3QgZW5jcnlwdGVkID0gbmV3IFVpbnQ4QXJyYXkoYXdhaXQgY3J5cHRvLnN1YnRsZS5lbmNyeXB0KHtcbiAgICAgICAgYWRkaXRpb25hbERhdGE6IGFhZCxcbiAgICAgICAgaXYsXG4gICAgICAgIG5hbWU6ICdBRVMtR0NNJyxcbiAgICAgICAgdGFnTGVuZ3RoOiAxMjgsXG4gICAgfSwgZW5jS2V5LCBwbGFpbnRleHQpKTtcbiAgICBjb25zdCB0YWcgPSBlbmNyeXB0ZWQuc2xpY2UoLTE2KTtcbiAgICBjb25zdCBjaXBoZXJ0ZXh0ID0gZW5jcnlwdGVkLnNsaWNlKDAsIC0xNik7XG4gICAgcmV0dXJuIHsgY2lwaGVydGV4dCwgdGFnLCBpdiB9O1xufVxuY29uc3QgZW5jcnlwdCA9IGFzeW5jIChlbmMsIHBsYWludGV4dCwgY2VrLCBpdiwgYWFkKSA9PiB7XG4gICAgaWYgKCFpc0NyeXB0b0tleShjZWspICYmICEoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoY2VrLCAuLi50eXBlcywgJ1VpbnQ4QXJyYXknKSk7XG4gICAgfVxuICAgIGlmIChpdikge1xuICAgICAgICBjaGVja0l2TGVuZ3RoKGVuYywgaXYpO1xuICAgIH1cbiAgICBlbHNlIHtcbiAgICAgICAgaXYgPSBnZW5lcmF0ZUl2KGVuYyk7XG4gICAgfVxuICAgIHN3aXRjaCAoZW5jKSB7XG4gICAgICAgIGNhc2UgJ0ExMjhDQkMtSFMyNTYnOlxuICAgICAgICBjYXNlICdBMTkyQ0JDLUhTMzg0JzpcbiAgICAgICAgY2FzZSAnQTI1NkNCQy1IUzUxMic6XG4gICAgICAgICAgICBpZiAoY2VrIGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICAgICAgICAgIGNoZWNrQ2VrTGVuZ3RoKGNlaywgcGFyc2VJbnQoZW5jLnNsaWNlKC0zKSwgMTApKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBjYmNFbmNyeXB0KGVuYywgcGxhaW50ZXh0LCBjZWssIGl2LCBhYWQpO1xuICAgICAgICBjYXNlICdBMTI4R0NNJzpcbiAgICAgICAgY2FzZSAnQTE5MkdDTSc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ00nOlxuICAgICAgICAgICAgaWYgKGNlayBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgICAgICAgICAgICBjaGVja0Nla0xlbmd0aChjZWssIHBhcnNlSW50KGVuYy5zbGljZSgxLCA0KSwgMTApKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBnY21FbmNyeXB0KGVuYywgcGxhaW50ZXh0LCBjZWssIGl2LCBhYWQpO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ1Vuc3VwcG9ydGVkIEpXRSBDb250ZW50IEVuY3J5cHRpb24gQWxnb3JpdGhtJyk7XG4gICAgfVxufTtcbmV4cG9ydCBkZWZhdWx0IGVuY3J5cHQ7XG4iLCJpbXBvcnQgZW5jcnlwdCBmcm9tICcuLi9ydW50aW1lL2VuY3J5cHQuanMnO1xuaW1wb3J0IGRlY3J5cHQgZnJvbSAnLi4vcnVudGltZS9kZWNyeXB0LmpzJztcbmltcG9ydCB7IGVuY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gd3JhcChhbGcsIGtleSwgY2VrLCBpdikge1xuICAgIGNvbnN0IGp3ZUFsZ29yaXRobSA9IGFsZy5zbGljZSgwLCA3KTtcbiAgICBjb25zdCB3cmFwcGVkID0gYXdhaXQgZW5jcnlwdChqd2VBbGdvcml0aG0sIGNlaywga2V5LCBpdiwgbmV3IFVpbnQ4QXJyYXkoMCkpO1xuICAgIHJldHVybiB7XG4gICAgICAgIGVuY3J5cHRlZEtleTogd3JhcHBlZC5jaXBoZXJ0ZXh0LFxuICAgICAgICBpdjogYmFzZTY0dXJsKHdyYXBwZWQuaXYpLFxuICAgICAgICB0YWc6IGJhc2U2NHVybCh3cmFwcGVkLnRhZyksXG4gICAgfTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiB1bndyYXAoYWxnLCBrZXksIGVuY3J5cHRlZEtleSwgaXYsIHRhZykge1xuICAgIGNvbnN0IGp3ZUFsZ29yaXRobSA9IGFsZy5zbGljZSgwLCA3KTtcbiAgICByZXR1cm4gZGVjcnlwdChqd2VBbGdvcml0aG0sIGtleSwgZW5jcnlwdGVkS2V5LCBpdiwgdGFnLCBuZXcgVWludDhBcnJheSgwKSk7XG59XG4iLCJpbXBvcnQgeyB1bndyYXAgYXMgYWVzS3cgfSBmcm9tICcuLi9ydW50aW1lL2Flc2t3LmpzJztcbmltcG9ydCAqIGFzIEVDREggZnJvbSAnLi4vcnVudGltZS9lY2RoZXMuanMnO1xuaW1wb3J0IHsgZGVjcnlwdCBhcyBwYmVzMkt3IH0gZnJvbSAnLi4vcnVudGltZS9wYmVzMmt3LmpzJztcbmltcG9ydCB7IGRlY3J5cHQgYXMgcnNhRXMgfSBmcm9tICcuLi9ydW50aW1lL3JzYWVzLmpzJztcbmltcG9ydCB7IGRlY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkLCBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHsgYml0TGVuZ3RoIGFzIGNla0xlbmd0aCB9IGZyb20gJy4uL2xpYi9jZWsuanMnO1xuaW1wb3J0IHsgaW1wb3J0SldLIH0gZnJvbSAnLi4va2V5L2ltcG9ydC5qcyc7XG5pbXBvcnQgY2hlY2tLZXlUeXBlIGZyb20gJy4vY2hlY2tfa2V5X3R5cGUuanMnO1xuaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4vaXNfb2JqZWN0LmpzJztcbmltcG9ydCB7IHVud3JhcCBhcyBhZXNHY21LdyB9IGZyb20gJy4vYWVzZ2Nta3cuanMnO1xuYXN5bmMgZnVuY3Rpb24gZGVjcnlwdEtleU1hbmFnZW1lbnQoYWxnLCBrZXksIGVuY3J5cHRlZEtleSwgam9zZUhlYWRlciwgb3B0aW9ucykge1xuICAgIGNoZWNrS2V5VHlwZShhbGcsIGtleSwgJ2RlY3J5cHQnKTtcbiAgICBzd2l0Y2ggKGFsZykge1xuICAgICAgICBjYXNlICdkaXInOiB7XG4gICAgICAgICAgICBpZiAoZW5jcnlwdGVkS2V5ICE9PSB1bmRlZmluZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0VuY291bnRlcmVkIHVuZXhwZWN0ZWQgSldFIEVuY3J5cHRlZCBLZXknKTtcbiAgICAgICAgICAgIHJldHVybiBrZXk7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnRUNESC1FUyc6XG4gICAgICAgICAgICBpZiAoZW5jcnlwdGVkS2V5ICE9PSB1bmRlZmluZWQpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0VuY291bnRlcmVkIHVuZXhwZWN0ZWQgSldFIEVuY3J5cHRlZCBLZXknKTtcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMTI4S1cnOlxuICAgICAgICBjYXNlICdFQ0RILUVTK0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTI1NktXJzoge1xuICAgICAgICAgICAgaWYgKCFpc09iamVjdChqb3NlSGVhZGVyLmVwaykpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwiZXBrXCIgKEVwaGVtZXJhbCBQdWJsaWMgS2V5KSBtaXNzaW5nIG9yIGludmFsaWRgKTtcbiAgICAgICAgICAgIGlmICghRUNESC5lY2RoQWxsb3dlZChrZXkpKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdFQ0RIIHdpdGggdGhlIHByb3ZpZGVkIGtleSBpcyBub3QgYWxsb3dlZCBvciBub3Qgc3VwcG9ydGVkIGJ5IHlvdXIgamF2YXNjcmlwdCBydW50aW1lJyk7XG4gICAgICAgICAgICBjb25zdCBlcGsgPSBhd2FpdCBpbXBvcnRKV0soam9zZUhlYWRlci5lcGssIGFsZyk7XG4gICAgICAgICAgICBsZXQgcGFydHlVSW5mbztcbiAgICAgICAgICAgIGxldCBwYXJ0eVZJbmZvO1xuICAgICAgICAgICAgaWYgKGpvc2VIZWFkZXIuYXB1ICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgICAgICBpZiAodHlwZW9mIGpvc2VIZWFkZXIuYXB1ICE9PSAnc3RyaW5nJylcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwiYXB1XCIgKEFncmVlbWVudCBQYXJ0eVVJbmZvKSBpbnZhbGlkYCk7XG4gICAgICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgICAgICAgcGFydHlVSW5mbyA9IGJhc2U2NHVybChqb3NlSGVhZGVyLmFwdSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBhcHUnKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAoam9zZUhlYWRlci5hcHYgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgICAgIGlmICh0eXBlb2Ygam9zZUhlYWRlci5hcHYgIT09ICdzdHJpbmcnKVxuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSk9TRSBIZWFkZXIgXCJhcHZcIiAoQWdyZWVtZW50IFBhcnR5VkluZm8pIGludmFsaWRgKTtcbiAgICAgICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgICAgICBwYXJ0eVZJbmZvID0gYmFzZTY0dXJsKGpvc2VIZWFkZXIuYXB2KTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIGFwdicpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNvbnN0IHNoYXJlZFNlY3JldCA9IGF3YWl0IEVDREguZGVyaXZlS2V5KGVwaywga2V5LCBhbGcgPT09ICdFQ0RILUVTJyA/IGpvc2VIZWFkZXIuZW5jIDogYWxnLCBhbGcgPT09ICdFQ0RILUVTJyA/IGNla0xlbmd0aChqb3NlSGVhZGVyLmVuYykgOiBwYXJzZUludChhbGcuc2xpY2UoLTUsIC0yKSwgMTApLCBwYXJ0eVVJbmZvLCBwYXJ0eVZJbmZvKTtcbiAgICAgICAgICAgIGlmIChhbGcgPT09ICdFQ0RILUVTJylcbiAgICAgICAgICAgICAgICByZXR1cm4gc2hhcmVkU2VjcmV0O1xuICAgICAgICAgICAgaWYgKGVuY3J5cHRlZEtleSA9PT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgRW5jcnlwdGVkIEtleSBtaXNzaW5nJyk7XG4gICAgICAgICAgICByZXR1cm4gYWVzS3coYWxnLnNsaWNlKC02KSwgc2hhcmVkU2VjcmV0LCBlbmNyeXB0ZWRLZXkpO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ1JTQTFfNSc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQJzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMjU2JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMzg0JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtNTEyJzoge1xuICAgICAgICAgICAgaWYgKGVuY3J5cHRlZEtleSA9PT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgRW5jcnlwdGVkIEtleSBtaXNzaW5nJyk7XG4gICAgICAgICAgICByZXR1cm4gcnNhRXMoYWxnLCBrZXksIGVuY3J5cHRlZEtleSk7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnUEJFUzItSFMyNTYrQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnUEJFUzItSFMzODQrQTE5MktXJzpcbiAgICAgICAgY2FzZSAnUEJFUzItSFM1MTIrQTI1NktXJzoge1xuICAgICAgICAgICAgaWYgKGVuY3J5cHRlZEtleSA9PT0gdW5kZWZpbmVkKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgRW5jcnlwdGVkIEtleSBtaXNzaW5nJyk7XG4gICAgICAgICAgICBpZiAodHlwZW9mIGpvc2VIZWFkZXIucDJjICE9PSAnbnVtYmVyJylcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSk9TRSBIZWFkZXIgXCJwMmNcIiAoUEJFUzIgQ291bnQpIG1pc3Npbmcgb3IgaW52YWxpZGApO1xuICAgICAgICAgICAgY29uc3QgcDJjTGltaXQgPSBvcHRpb25zPy5tYXhQQkVTMkNvdW50IHx8IDEwMDAwO1xuICAgICAgICAgICAgaWYgKGpvc2VIZWFkZXIucDJjID4gcDJjTGltaXQpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwicDJjXCIgKFBCRVMyIENvdW50KSBvdXQgaXMgb2YgYWNjZXB0YWJsZSBib3VuZHNgKTtcbiAgICAgICAgICAgIGlmICh0eXBlb2Ygam9zZUhlYWRlci5wMnMgIT09ICdzdHJpbmcnKVxuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKGBKT1NFIEhlYWRlciBcInAyc1wiIChQQkVTMiBTYWx0KSBtaXNzaW5nIG9yIGludmFsaWRgKTtcbiAgICAgICAgICAgIGxldCBwMnM7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIHAycyA9IGJhc2U2NHVybChqb3NlSGVhZGVyLnAycyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSBwMnMnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBwYmVzMkt3KGFsZywga2V5LCBlbmNyeXB0ZWRLZXksIGpvc2VIZWFkZXIucDJjLCBwMnMpO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZLVyc6IHtcbiAgICAgICAgICAgIGlmIChlbmNyeXB0ZWRLZXkgPT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEVuY3J5cHRlZCBLZXkgbWlzc2luZycpO1xuICAgICAgICAgICAgcmV0dXJuIGFlc0t3KGFsZywga2V5LCBlbmNyeXB0ZWRLZXkpO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0ExMjhHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ01LVyc6IHtcbiAgICAgICAgICAgIGlmIChlbmNyeXB0ZWRLZXkgPT09IHVuZGVmaW5lZClcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEVuY3J5cHRlZCBLZXkgbWlzc2luZycpO1xuICAgICAgICAgICAgaWYgKHR5cGVvZiBqb3NlSGVhZGVyLml2ICE9PSAnc3RyaW5nJylcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZChgSk9TRSBIZWFkZXIgXCJpdlwiIChJbml0aWFsaXphdGlvbiBWZWN0b3IpIG1pc3Npbmcgb3IgaW52YWxpZGApO1xuICAgICAgICAgICAgaWYgKHR5cGVvZiBqb3NlSGVhZGVyLnRhZyAhPT0gJ3N0cmluZycpXG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoYEpPU0UgSGVhZGVyIFwidGFnXCIgKEF1dGhlbnRpY2F0aW9uIFRhZykgbWlzc2luZyBvciBpbnZhbGlkYCk7XG4gICAgICAgICAgICBsZXQgaXY7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIGl2ID0gYmFzZTY0dXJsKGpvc2VIZWFkZXIuaXYpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgaXYnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGxldCB0YWc7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICAgIHRhZyA9IGJhc2U2NHVybChqb3NlSGVhZGVyLnRhZyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSB0YWcnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBhZXNHY21LdyhhbGcsIGtleSwgZW5jcnlwdGVkS2V5LCBpdiwgdGFnKTtcbiAgICAgICAgfVxuICAgICAgICBkZWZhdWx0OiB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSW52YWxpZCBvciB1bnN1cHBvcnRlZCBcImFsZ1wiIChKV0UgQWxnb3JpdGhtKSBoZWFkZXIgdmFsdWUnKTtcbiAgICAgICAgfVxuICAgIH1cbn1cbmV4cG9ydCBkZWZhdWx0IGRlY3J5cHRLZXlNYW5hZ2VtZW50O1xuIiwiaW1wb3J0IHsgSk9TRU5vdFN1cHBvcnRlZCB9IGZyb20gJy4uL3V0aWwvZXJyb3JzLmpzJztcbmZ1bmN0aW9uIHZhbGlkYXRlQ3JpdChFcnIsIHJlY29nbml6ZWREZWZhdWx0LCByZWNvZ25pemVkT3B0aW9uLCBwcm90ZWN0ZWRIZWFkZXIsIGpvc2VIZWFkZXIpIHtcbiAgICBpZiAoam9zZUhlYWRlci5jcml0ICE9PSB1bmRlZmluZWQgJiYgcHJvdGVjdGVkSGVhZGVyPy5jcml0ID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycignXCJjcml0XCIgKENyaXRpY2FsKSBIZWFkZXIgUGFyYW1ldGVyIE1VU1QgYmUgaW50ZWdyaXR5IHByb3RlY3RlZCcpO1xuICAgIH1cbiAgICBpZiAoIXByb3RlY3RlZEhlYWRlciB8fCBwcm90ZWN0ZWRIZWFkZXIuY3JpdCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHJldHVybiBuZXcgU2V0KCk7XG4gICAgfVxuICAgIGlmICghQXJyYXkuaXNBcnJheShwcm90ZWN0ZWRIZWFkZXIuY3JpdCkgfHxcbiAgICAgICAgcHJvdGVjdGVkSGVhZGVyLmNyaXQubGVuZ3RoID09PSAwIHx8XG4gICAgICAgIHByb3RlY3RlZEhlYWRlci5jcml0LnNvbWUoKGlucHV0KSA9PiB0eXBlb2YgaW5wdXQgIT09ICdzdHJpbmcnIHx8IGlucHV0Lmxlbmd0aCA9PT0gMCkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycignXCJjcml0XCIgKENyaXRpY2FsKSBIZWFkZXIgUGFyYW1ldGVyIE1VU1QgYmUgYW4gYXJyYXkgb2Ygbm9uLWVtcHR5IHN0cmluZ3Mgd2hlbiBwcmVzZW50Jyk7XG4gICAgfVxuICAgIGxldCByZWNvZ25pemVkO1xuICAgIGlmIChyZWNvZ25pemVkT3B0aW9uICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmVjb2duaXplZCA9IG5ldyBNYXAoWy4uLk9iamVjdC5lbnRyaWVzKHJlY29nbml6ZWRPcHRpb24pLCAuLi5yZWNvZ25pemVkRGVmYXVsdC5lbnRyaWVzKCldKTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIHJlY29nbml6ZWQgPSByZWNvZ25pemVkRGVmYXVsdDtcbiAgICB9XG4gICAgZm9yIChjb25zdCBwYXJhbWV0ZXIgb2YgcHJvdGVjdGVkSGVhZGVyLmNyaXQpIHtcbiAgICAgICAgaWYgKCFyZWNvZ25pemVkLmhhcyhwYXJhbWV0ZXIpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZChgRXh0ZW5zaW9uIEhlYWRlciBQYXJhbWV0ZXIgXCIke3BhcmFtZXRlcn1cIiBpcyBub3QgcmVjb2duaXplZGApO1xuICAgICAgICB9XG4gICAgICAgIGlmIChqb3NlSGVhZGVyW3BhcmFtZXRlcl0gPT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycihgRXh0ZW5zaW9uIEhlYWRlciBQYXJhbWV0ZXIgXCIke3BhcmFtZXRlcn1cIiBpcyBtaXNzaW5nYCk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHJlY29nbml6ZWQuZ2V0KHBhcmFtZXRlcikgJiYgcHJvdGVjdGVkSGVhZGVyW3BhcmFtZXRlcl0gPT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycihgRXh0ZW5zaW9uIEhlYWRlciBQYXJhbWV0ZXIgXCIke3BhcmFtZXRlcn1cIiBNVVNUIGJlIGludGVncml0eSBwcm90ZWN0ZWRgKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gbmV3IFNldChwcm90ZWN0ZWRIZWFkZXIuY3JpdCk7XG59XG5leHBvcnQgZGVmYXVsdCB2YWxpZGF0ZUNyaXQ7XG4iLCJjb25zdCB2YWxpZGF0ZUFsZ29yaXRobXMgPSAob3B0aW9uLCBhbGdvcml0aG1zKSA9PiB7XG4gICAgaWYgKGFsZ29yaXRobXMgIT09IHVuZGVmaW5lZCAmJlxuICAgICAgICAoIUFycmF5LmlzQXJyYXkoYWxnb3JpdGhtcykgfHwgYWxnb3JpdGhtcy5zb21lKChzKSA9PiB0eXBlb2YgcyAhPT0gJ3N0cmluZycpKSkge1xuICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGBcIiR7b3B0aW9ufVwiIG9wdGlvbiBtdXN0IGJlIGFuIGFycmF5IG9mIHN0cmluZ3NgKTtcbiAgICB9XG4gICAgaWYgKCFhbGdvcml0aG1zKSB7XG4gICAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgfVxuICAgIHJldHVybiBuZXcgU2V0KGFsZ29yaXRobXMpO1xufTtcbmV4cG9ydCBkZWZhdWx0IHZhbGlkYXRlQWxnb3JpdGhtcztcbiIsImltcG9ydCB7IGRlY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi8uLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgZGVjcnlwdCBmcm9tICcuLi8uLi9ydW50aW1lL2RlY3J5cHQuanMnO1xuaW1wb3J0IHsgSk9TRUFsZ05vdEFsbG93ZWQsIEpPU0VOb3RTdXBwb3J0ZWQsIEpXRUludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgaXNEaXNqb2ludCBmcm9tICcuLi8uLi9saWIvaXNfZGlzam9pbnQuanMnO1xuaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4uLy4uL2xpYi9pc19vYmplY3QuanMnO1xuaW1wb3J0IGRlY3J5cHRLZXlNYW5hZ2VtZW50IGZyb20gJy4uLy4uL2xpYi9kZWNyeXB0X2tleV9tYW5hZ2VtZW50LmpzJztcbmltcG9ydCB7IGVuY29kZXIsIGRlY29kZXIsIGNvbmNhdCB9IGZyb20gJy4uLy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IGdlbmVyYXRlQ2VrIGZyb20gJy4uLy4uL2xpYi9jZWsuanMnO1xuaW1wb3J0IHZhbGlkYXRlQ3JpdCBmcm9tICcuLi8uLi9saWIvdmFsaWRhdGVfY3JpdC5qcyc7XG5pbXBvcnQgdmFsaWRhdGVBbGdvcml0aG1zIGZyb20gJy4uLy4uL2xpYi92YWxpZGF0ZV9hbGdvcml0aG1zLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBmbGF0dGVuZWREZWNyeXB0KGp3ZSwga2V5LCBvcHRpb25zKSB7XG4gICAgaWYgKCFpc09iamVjdChqd2UpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGbGF0dGVuZWQgSldFIG11c3QgYmUgYW4gb2JqZWN0Jyk7XG4gICAgfVxuICAgIGlmIChqd2UucHJvdGVjdGVkID09PSB1bmRlZmluZWQgJiYgandlLmhlYWRlciA9PT0gdW5kZWZpbmVkICYmIGp3ZS51bnByb3RlY3RlZCA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKT1NFIEhlYWRlciBtaXNzaW5nJyk7XG4gICAgfVxuICAgIGlmIChqd2UuaXYgIT09IHVuZGVmaW5lZCAmJiB0eXBlb2YgandlLml2ICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEluaXRpYWxpemF0aW9uIFZlY3RvciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIGp3ZS5jaXBoZXJ0ZXh0ICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIENpcGhlcnRleHQgbWlzc2luZyBvciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoandlLnRhZyAhPT0gdW5kZWZpbmVkICYmIHR5cGVvZiBqd2UudGFnICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEF1dGhlbnRpY2F0aW9uIFRhZyBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoandlLnByb3RlY3RlZCAhPT0gdW5kZWZpbmVkICYmIHR5cGVvZiBqd2UucHJvdGVjdGVkICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFByb3RlY3RlZCBIZWFkZXIgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3ZS5lbmNyeXB0ZWRfa2V5ICE9PSB1bmRlZmluZWQgJiYgdHlwZW9mIGp3ZS5lbmNyeXB0ZWRfa2V5ICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIEVuY3J5cHRlZCBLZXkgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3ZS5hYWQgIT09IHVuZGVmaW5lZCAmJiB0eXBlb2YgandlLmFhZCAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBBQUQgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3ZS5oZWFkZXIgIT09IHVuZGVmaW5lZCAmJiAhaXNPYmplY3QoandlLmhlYWRlcikpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBTaGFyZWQgVW5wcm90ZWN0ZWQgSGVhZGVyIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGlmIChqd2UudW5wcm90ZWN0ZWQgIT09IHVuZGVmaW5lZCAmJiAhaXNPYmplY3QoandlLnVucHJvdGVjdGVkKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFBlci1SZWNpcGllbnQgVW5wcm90ZWN0ZWQgSGVhZGVyIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGxldCBwYXJzZWRQcm90O1xuICAgIGlmIChqd2UucHJvdGVjdGVkKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBjb25zdCBwcm90ZWN0ZWRIZWFkZXIgPSBiYXNlNjR1cmwoandlLnByb3RlY3RlZCk7XG4gICAgICAgICAgICBwYXJzZWRQcm90ID0gSlNPTi5wYXJzZShkZWNvZGVyLmRlY29kZShwcm90ZWN0ZWRIZWFkZXIpKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFByb3RlY3RlZCBIZWFkZXIgaXMgaW52YWxpZCcpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGlmICghaXNEaXNqb2ludChwYXJzZWRQcm90LCBqd2UuaGVhZGVyLCBqd2UudW5wcm90ZWN0ZWQpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgUHJvdGVjdGVkLCBKV0UgVW5wcm90ZWN0ZWQgSGVhZGVyLCBhbmQgSldFIFBlci1SZWNpcGllbnQgVW5wcm90ZWN0ZWQgSGVhZGVyIFBhcmFtZXRlciBuYW1lcyBtdXN0IGJlIGRpc2pvaW50Jyk7XG4gICAgfVxuICAgIGNvbnN0IGpvc2VIZWFkZXIgPSB7XG4gICAgICAgIC4uLnBhcnNlZFByb3QsXG4gICAgICAgIC4uLmp3ZS5oZWFkZXIsXG4gICAgICAgIC4uLmp3ZS51bnByb3RlY3RlZCxcbiAgICB9O1xuICAgIHZhbGlkYXRlQ3JpdChKV0VJbnZhbGlkLCBuZXcgTWFwKCksIG9wdGlvbnM/LmNyaXQsIHBhcnNlZFByb3QsIGpvc2VIZWFkZXIpO1xuICAgIGlmIChqb3NlSGVhZGVyLnppcCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdKV0UgXCJ6aXBcIiAoQ29tcHJlc3Npb24gQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIGlzIG5vdCBzdXBwb3J0ZWQuJyk7XG4gICAgfVxuICAgIGNvbnN0IHsgYWxnLCBlbmMgfSA9IGpvc2VIZWFkZXI7XG4gICAgaWYgKHR5cGVvZiBhbGcgIT09ICdzdHJpbmcnIHx8ICFhbGcpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ21pc3NpbmcgSldFIEFsZ29yaXRobSAoYWxnKSBpbiBKV0UgSGVhZGVyJyk7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgZW5jICE9PSAnc3RyaW5nJyB8fCAhZW5jKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdtaXNzaW5nIEpXRSBFbmNyeXB0aW9uIEFsZ29yaXRobSAoZW5jKSBpbiBKV0UgSGVhZGVyJyk7XG4gICAgfVxuICAgIGNvbnN0IGtleU1hbmFnZW1lbnRBbGdvcml0aG1zID0gb3B0aW9ucyAmJiB2YWxpZGF0ZUFsZ29yaXRobXMoJ2tleU1hbmFnZW1lbnRBbGdvcml0aG1zJywgb3B0aW9ucy5rZXlNYW5hZ2VtZW50QWxnb3JpdGhtcyk7XG4gICAgY29uc3QgY29udGVudEVuY3J5cHRpb25BbGdvcml0aG1zID0gb3B0aW9ucyAmJlxuICAgICAgICB2YWxpZGF0ZUFsZ29yaXRobXMoJ2NvbnRlbnRFbmNyeXB0aW9uQWxnb3JpdGhtcycsIG9wdGlvbnMuY29udGVudEVuY3J5cHRpb25BbGdvcml0aG1zKTtcbiAgICBpZiAoKGtleU1hbmFnZW1lbnRBbGdvcml0aG1zICYmICFrZXlNYW5hZ2VtZW50QWxnb3JpdGhtcy5oYXMoYWxnKSkgfHxcbiAgICAgICAgKCFrZXlNYW5hZ2VtZW50QWxnb3JpdGhtcyAmJiBhbGcuc3RhcnRzV2l0aCgnUEJFUzInKSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpPU0VBbGdOb3RBbGxvd2VkKCdcImFsZ1wiIChBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgdmFsdWUgbm90IGFsbG93ZWQnKTtcbiAgICB9XG4gICAgaWYgKGNvbnRlbnRFbmNyeXB0aW9uQWxnb3JpdGhtcyAmJiAhY29udGVudEVuY3J5cHRpb25BbGdvcml0aG1zLmhhcyhlbmMpKSB7XG4gICAgICAgIHRocm93IG5ldyBKT1NFQWxnTm90QWxsb3dlZCgnXCJlbmNcIiAoRW5jcnlwdGlvbiBBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgdmFsdWUgbm90IGFsbG93ZWQnKTtcbiAgICB9XG4gICAgbGV0IGVuY3J5cHRlZEtleTtcbiAgICBpZiAoandlLmVuY3J5cHRlZF9rZXkgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgZW5jcnlwdGVkS2V5ID0gYmFzZTY0dXJsKGp3ZS5lbmNyeXB0ZWRfa2V5KTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIGVuY3J5cHRlZF9rZXknKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBsZXQgcmVzb2x2ZWRLZXkgPSBmYWxzZTtcbiAgICBpZiAodHlwZW9mIGtleSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICBrZXkgPSBhd2FpdCBrZXkocGFyc2VkUHJvdCwgandlKTtcbiAgICAgICAgcmVzb2x2ZWRLZXkgPSB0cnVlO1xuICAgIH1cbiAgICBsZXQgY2VrO1xuICAgIHRyeSB7XG4gICAgICAgIGNlayA9IGF3YWl0IGRlY3J5cHRLZXlNYW5hZ2VtZW50KGFsZywga2V5LCBlbmNyeXB0ZWRLZXksIGpvc2VIZWFkZXIsIG9wdGlvbnMpO1xuICAgIH1cbiAgICBjYXRjaCAoZXJyKSB7XG4gICAgICAgIGlmIChlcnIgaW5zdGFuY2VvZiBUeXBlRXJyb3IgfHwgZXJyIGluc3RhbmNlb2YgSldFSW52YWxpZCB8fCBlcnIgaW5zdGFuY2VvZiBKT1NFTm90U3VwcG9ydGVkKSB7XG4gICAgICAgICAgICB0aHJvdyBlcnI7XG4gICAgICAgIH1cbiAgICAgICAgY2VrID0gZ2VuZXJhdGVDZWsoZW5jKTtcbiAgICB9XG4gICAgbGV0IGl2O1xuICAgIGxldCB0YWc7XG4gICAgaWYgKGp3ZS5pdiAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBpdiA9IGJhc2U2NHVybChqd2UuaXYpO1xuICAgICAgICB9XG4gICAgICAgIGNhdGNoIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgaXYnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBpZiAoandlLnRhZyAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICB0YWcgPSBiYXNlNjR1cmwoandlLnRhZyk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ZhaWxlZCB0byBiYXNlNjR1cmwgZGVjb2RlIHRoZSB0YWcnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBjb25zdCBwcm90ZWN0ZWRIZWFkZXIgPSBlbmNvZGVyLmVuY29kZShqd2UucHJvdGVjdGVkID8/ICcnKTtcbiAgICBsZXQgYWRkaXRpb25hbERhdGE7XG4gICAgaWYgKGp3ZS5hYWQgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICBhZGRpdGlvbmFsRGF0YSA9IGNvbmNhdChwcm90ZWN0ZWRIZWFkZXIsIGVuY29kZXIuZW5jb2RlKCcuJyksIGVuY29kZXIuZW5jb2RlKGp3ZS5hYWQpKTtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICAgIGFkZGl0aW9uYWxEYXRhID0gcHJvdGVjdGVkSGVhZGVyO1xuICAgIH1cbiAgICBsZXQgY2lwaGVydGV4dDtcbiAgICB0cnkge1xuICAgICAgICBjaXBoZXJ0ZXh0ID0gYmFzZTY0dXJsKGp3ZS5jaXBoZXJ0ZXh0KTtcbiAgICB9XG4gICAgY2F0Y2gge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIGNpcGhlcnRleHQnKTtcbiAgICB9XG4gICAgY29uc3QgcGxhaW50ZXh0ID0gYXdhaXQgZGVjcnlwdChlbmMsIGNlaywgY2lwaGVydGV4dCwgaXYsIHRhZywgYWRkaXRpb25hbERhdGEpO1xuICAgIGNvbnN0IHJlc3VsdCA9IHsgcGxhaW50ZXh0IH07XG4gICAgaWYgKGp3ZS5wcm90ZWN0ZWQgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICByZXN1bHQucHJvdGVjdGVkSGVhZGVyID0gcGFyc2VkUHJvdDtcbiAgICB9XG4gICAgaWYgKGp3ZS5hYWQgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgcmVzdWx0LmFkZGl0aW9uYWxBdXRoZW50aWNhdGVkRGF0YSA9IGJhc2U2NHVybChqd2UuYWFkKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIGFhZCcpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGlmIChqd2UudW5wcm90ZWN0ZWQgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICByZXN1bHQuc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIgPSBqd2UudW5wcm90ZWN0ZWQ7XG4gICAgfVxuICAgIGlmIChqd2UuaGVhZGVyICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmVzdWx0LnVucHJvdGVjdGVkSGVhZGVyID0gandlLmhlYWRlcjtcbiAgICB9XG4gICAgaWYgKHJlc29sdmVkS2V5KSB7XG4gICAgICAgIHJldHVybiB7IC4uLnJlc3VsdCwga2V5IH07XG4gICAgfVxuICAgIHJldHVybiByZXN1bHQ7XG59XG4iLCJpbXBvcnQgeyBmbGF0dGVuZWREZWNyeXB0IH0gZnJvbSAnLi4vZmxhdHRlbmVkL2RlY3J5cHQuanMnO1xuaW1wb3J0IHsgSldFSW52YWxpZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IGRlY29kZXIgfSBmcm9tICcuLi8uLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBjb21wYWN0RGVjcnlwdChqd2UsIGtleSwgb3B0aW9ucykge1xuICAgIGlmIChqd2UgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIGp3ZSA9IGRlY29kZXIuZGVjb2RlKGp3ZSk7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgandlICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnQ29tcGFjdCBKV0UgbXVzdCBiZSBhIHN0cmluZyBvciBVaW50OEFycmF5Jyk7XG4gICAgfVxuICAgIGNvbnN0IHsgMDogcHJvdGVjdGVkSGVhZGVyLCAxOiBlbmNyeXB0ZWRLZXksIDI6IGl2LCAzOiBjaXBoZXJ0ZXh0LCA0OiB0YWcsIGxlbmd0aCwgfSA9IGp3ZS5zcGxpdCgnLicpO1xuICAgIGlmIChsZW5ndGggIT09IDUpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0ludmFsaWQgQ29tcGFjdCBKV0UnKTtcbiAgICB9XG4gICAgY29uc3QgZGVjcnlwdGVkID0gYXdhaXQgZmxhdHRlbmVkRGVjcnlwdCh7XG4gICAgICAgIGNpcGhlcnRleHQsXG4gICAgICAgIGl2OiBpdiB8fCB1bmRlZmluZWQsXG4gICAgICAgIHByb3RlY3RlZDogcHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICB0YWc6IHRhZyB8fCB1bmRlZmluZWQsXG4gICAgICAgIGVuY3J5cHRlZF9rZXk6IGVuY3J5cHRlZEtleSB8fCB1bmRlZmluZWQsXG4gICAgfSwga2V5LCBvcHRpb25zKTtcbiAgICBjb25zdCByZXN1bHQgPSB7IHBsYWludGV4dDogZGVjcnlwdGVkLnBsYWludGV4dCwgcHJvdGVjdGVkSGVhZGVyOiBkZWNyeXB0ZWQucHJvdGVjdGVkSGVhZGVyIH07XG4gICAgaWYgKHR5cGVvZiBrZXkgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAgcmV0dXJuIHsgLi4ucmVzdWx0LCBrZXk6IGRlY3J5cHRlZC5rZXkgfTtcbiAgICB9XG4gICAgcmV0dXJuIHJlc3VsdDtcbn1cbiIsImltcG9ydCB7IGZsYXR0ZW5lZERlY3J5cHQgfSBmcm9tICcuLi9mbGF0dGVuZWQvZGVjcnlwdC5qcyc7XG5pbXBvcnQgeyBKV0VEZWNyeXB0aW9uRmFpbGVkLCBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IGlzT2JqZWN0IGZyb20gJy4uLy4uL2xpYi9pc19vYmplY3QuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdlbmVyYWxEZWNyeXB0KGp3ZSwga2V5LCBvcHRpb25zKSB7XG4gICAgaWYgKCFpc09iamVjdChqd2UpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdHZW5lcmFsIEpXRSBtdXN0IGJlIGFuIG9iamVjdCcpO1xuICAgIH1cbiAgICBpZiAoIUFycmF5LmlzQXJyYXkoandlLnJlY2lwaWVudHMpIHx8ICFqd2UucmVjaXBpZW50cy5ldmVyeShpc09iamVjdCkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBSZWNpcGllbnRzIG1pc3Npbmcgb3IgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKCFqd2UucmVjaXBpZW50cy5sZW5ndGgpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBSZWNpcGllbnRzIGhhcyBubyBtZW1iZXJzJyk7XG4gICAgfVxuICAgIGZvciAoY29uc3QgcmVjaXBpZW50IG9mIGp3ZS5yZWNpcGllbnRzKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICByZXR1cm4gYXdhaXQgZmxhdHRlbmVkRGVjcnlwdCh7XG4gICAgICAgICAgICAgICAgYWFkOiBqd2UuYWFkLFxuICAgICAgICAgICAgICAgIGNpcGhlcnRleHQ6IGp3ZS5jaXBoZXJ0ZXh0LFxuICAgICAgICAgICAgICAgIGVuY3J5cHRlZF9rZXk6IHJlY2lwaWVudC5lbmNyeXB0ZWRfa2V5LFxuICAgICAgICAgICAgICAgIGhlYWRlcjogcmVjaXBpZW50LmhlYWRlcixcbiAgICAgICAgICAgICAgICBpdjogandlLml2LFxuICAgICAgICAgICAgICAgIHByb3RlY3RlZDogandlLnByb3RlY3RlZCxcbiAgICAgICAgICAgICAgICB0YWc6IGp3ZS50YWcsXG4gICAgICAgICAgICAgICAgdW5wcm90ZWN0ZWQ6IGp3ZS51bnByb3RlY3RlZCxcbiAgICAgICAgICAgIH0sIGtleSwgb3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICB9XG4gICAgfVxuICAgIHRocm93IG5ldyBKV0VEZWNyeXB0aW9uRmFpbGVkKCk7XG59XG4iLCJpbXBvcnQgY3J5cHRvLCB7IGlzQ3J5cHRvS2V5IH0gZnJvbSAnLi93ZWJjcnlwdG8uanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IHsgZW5jb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4vYmFzZTY0dXJsLmpzJztcbmltcG9ydCB7IHR5cGVzIH0gZnJvbSAnLi9pc19rZXlfbGlrZS5qcyc7XG5jb25zdCBrZXlUb0pXSyA9IGFzeW5jIChrZXkpID0+IHtcbiAgICBpZiAoa2V5IGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAga3R5OiAnb2N0JyxcbiAgICAgICAgICAgIGs6IGJhc2U2NHVybChrZXkpLFxuICAgICAgICB9O1xuICAgIH1cbiAgICBpZiAoIWlzQ3J5cHRvS2V5KGtleSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcywgJ1VpbnQ4QXJyYXknKSk7XG4gICAgfVxuICAgIGlmICgha2V5LmV4dHJhY3RhYmxlKSB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ25vbi1leHRyYWN0YWJsZSBDcnlwdG9LZXkgY2Fubm90IGJlIGV4cG9ydGVkIGFzIGEgSldLJyk7XG4gICAgfVxuICAgIGNvbnN0IHsgZXh0LCBrZXlfb3BzLCBhbGcsIHVzZSwgLi4uandrIH0gPSBhd2FpdCBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgnandrJywga2V5KTtcbiAgICByZXR1cm4gandrO1xufTtcbmV4cG9ydCBkZWZhdWx0IGtleVRvSldLO1xuIiwiaW1wb3J0IHsgdG9TUEtJIGFzIGV4cG9ydFB1YmxpYyB9IGZyb20gJy4uL3J1bnRpbWUvYXNuMS5qcyc7XG5pbXBvcnQgeyB0b1BLQ1M4IGFzIGV4cG9ydFByaXZhdGUgfSBmcm9tICcuLi9ydW50aW1lL2FzbjEuanMnO1xuaW1wb3J0IGtleVRvSldLIGZyb20gJy4uL3J1bnRpbWUva2V5X3RvX2p3ay5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZXhwb3J0U1BLSShrZXkpIHtcbiAgICByZXR1cm4gZXhwb3J0UHVibGljKGtleSk7XG59XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZXhwb3J0UEtDUzgoa2V5KSB7XG4gICAgcmV0dXJuIGV4cG9ydFByaXZhdGUoa2V5KTtcbn1cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBleHBvcnRKV0soa2V5KSB7XG4gICAgcmV0dXJuIGtleVRvSldLKGtleSk7XG59XG4iLCJpbXBvcnQgeyB3cmFwIGFzIGFlc0t3IH0gZnJvbSAnLi4vcnVudGltZS9hZXNrdy5qcyc7XG5pbXBvcnQgKiBhcyBFQ0RIIGZyb20gJy4uL3J1bnRpbWUvZWNkaGVzLmpzJztcbmltcG9ydCB7IGVuY3J5cHQgYXMgcGJlczJLdyB9IGZyb20gJy4uL3J1bnRpbWUvcGJlczJrdy5qcyc7XG5pbXBvcnQgeyBlbmNyeXB0IGFzIHJzYUVzIH0gZnJvbSAnLi4vcnVudGltZS9yc2Flcy5qcyc7XG5pbXBvcnQgeyBlbmNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IGdlbmVyYXRlQ2VrLCB7IGJpdExlbmd0aCBhcyBjZWtMZW5ndGggfSBmcm9tICcuLi9saWIvY2VrLmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQgfSBmcm9tICcuLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgeyBleHBvcnRKV0sgfSBmcm9tICcuLi9rZXkvZXhwb3J0LmpzJztcbmltcG9ydCBjaGVja0tleVR5cGUgZnJvbSAnLi9jaGVja19rZXlfdHlwZS5qcyc7XG5pbXBvcnQgeyB3cmFwIGFzIGFlc0djbUt3IH0gZnJvbSAnLi9hZXNnY21rdy5qcyc7XG5hc3luYyBmdW5jdGlvbiBlbmNyeXB0S2V5TWFuYWdlbWVudChhbGcsIGVuYywga2V5LCBwcm92aWRlZENlaywgcHJvdmlkZWRQYXJhbWV0ZXJzID0ge30pIHtcbiAgICBsZXQgZW5jcnlwdGVkS2V5O1xuICAgIGxldCBwYXJhbWV0ZXJzO1xuICAgIGxldCBjZWs7XG4gICAgY2hlY2tLZXlUeXBlKGFsZywga2V5LCAnZW5jcnlwdCcpO1xuICAgIHN3aXRjaCAoYWxnKSB7XG4gICAgICAgIGNhc2UgJ2Rpcic6IHtcbiAgICAgICAgICAgIGNlayA9IGtleTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0VDREgtRVMnOlxuICAgICAgICBjYXNlICdFQ0RILUVTK0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTE5MktXJzpcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMjU2S1cnOiB7XG4gICAgICAgICAgICBpZiAoIUVDREguZWNkaEFsbG93ZWQoa2V5KSkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdFQ0RIIHdpdGggdGhlIHByb3ZpZGVkIGtleSBpcyBub3QgYWxsb3dlZCBvciBub3Qgc3VwcG9ydGVkIGJ5IHlvdXIgamF2YXNjcmlwdCBydW50aW1lJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjb25zdCB7IGFwdSwgYXB2IH0gPSBwcm92aWRlZFBhcmFtZXRlcnM7XG4gICAgICAgICAgICBsZXQgeyBlcGs6IGVwaGVtZXJhbEtleSB9ID0gcHJvdmlkZWRQYXJhbWV0ZXJzO1xuICAgICAgICAgICAgZXBoZW1lcmFsS2V5IHx8IChlcGhlbWVyYWxLZXkgPSAoYXdhaXQgRUNESC5nZW5lcmF0ZUVwayhrZXkpKS5wcml2YXRlS2V5KTtcbiAgICAgICAgICAgIGNvbnN0IHsgeCwgeSwgY3J2LCBrdHkgfSA9IGF3YWl0IGV4cG9ydEpXSyhlcGhlbWVyYWxLZXkpO1xuICAgICAgICAgICAgY29uc3Qgc2hhcmVkU2VjcmV0ID0gYXdhaXQgRUNESC5kZXJpdmVLZXkoa2V5LCBlcGhlbWVyYWxLZXksIGFsZyA9PT0gJ0VDREgtRVMnID8gZW5jIDogYWxnLCBhbGcgPT09ICdFQ0RILUVTJyA/IGNla0xlbmd0aChlbmMpIDogcGFyc2VJbnQoYWxnLnNsaWNlKC01LCAtMiksIDEwKSwgYXB1LCBhcHYpO1xuICAgICAgICAgICAgcGFyYW1ldGVycyA9IHsgZXBrOiB7IHgsIGNydiwga3R5IH0gfTtcbiAgICAgICAgICAgIGlmIChrdHkgPT09ICdFQycpXG4gICAgICAgICAgICAgICAgcGFyYW1ldGVycy5lcGsueSA9IHk7XG4gICAgICAgICAgICBpZiAoYXB1KVxuICAgICAgICAgICAgICAgIHBhcmFtZXRlcnMuYXB1ID0gYmFzZTY0dXJsKGFwdSk7XG4gICAgICAgICAgICBpZiAoYXB2KVxuICAgICAgICAgICAgICAgIHBhcmFtZXRlcnMuYXB2ID0gYmFzZTY0dXJsKGFwdik7XG4gICAgICAgICAgICBpZiAoYWxnID09PSAnRUNESC1FUycpIHtcbiAgICAgICAgICAgICAgICBjZWsgPSBzaGFyZWRTZWNyZXQ7XG4gICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjZWsgPSBwcm92aWRlZENlayB8fCBnZW5lcmF0ZUNlayhlbmMpO1xuICAgICAgICAgICAgY29uc3Qga3dBbGcgPSBhbGcuc2xpY2UoLTYpO1xuICAgICAgICAgICAgZW5jcnlwdGVkS2V5ID0gYXdhaXQgYWVzS3coa3dBbGcsIHNoYXJlZFNlY3JldCwgY2VrKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ1JTQTFfNSc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQJzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMjU2JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtMzg0JzpcbiAgICAgICAgY2FzZSAnUlNBLU9BRVAtNTEyJzoge1xuICAgICAgICAgICAgY2VrID0gcHJvdmlkZWRDZWsgfHwgZ2VuZXJhdGVDZWsoZW5jKTtcbiAgICAgICAgICAgIGVuY3J5cHRlZEtleSA9IGF3YWl0IHJzYUVzKGFsZywga2V5LCBjZWspO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnUEJFUzItSFMyNTYrQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnUEJFUzItSFMzODQrQTE5MktXJzpcbiAgICAgICAgY2FzZSAnUEJFUzItSFM1MTIrQTI1NktXJzoge1xuICAgICAgICAgICAgY2VrID0gcHJvdmlkZWRDZWsgfHwgZ2VuZXJhdGVDZWsoZW5jKTtcbiAgICAgICAgICAgIGNvbnN0IHsgcDJjLCBwMnMgfSA9IHByb3ZpZGVkUGFyYW1ldGVycztcbiAgICAgICAgICAgICh7IGVuY3J5cHRlZEtleSwgLi4ucGFyYW1ldGVycyB9ID0gYXdhaXQgcGJlczJLdyhhbGcsIGtleSwgY2VrLCBwMmMsIHAycykpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnQTEyOEtXJzpcbiAgICAgICAgY2FzZSAnQTE5MktXJzpcbiAgICAgICAgY2FzZSAnQTI1NktXJzoge1xuICAgICAgICAgICAgY2VrID0gcHJvdmlkZWRDZWsgfHwgZ2VuZXJhdGVDZWsoZW5jKTtcbiAgICAgICAgICAgIGVuY3J5cHRlZEtleSA9IGF3YWl0IGFlc0t3KGFsZywga2V5LCBjZWspO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgY2FzZSAnQTEyOEdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTE5MkdDTUtXJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTUtXJzoge1xuICAgICAgICAgICAgY2VrID0gcHJvdmlkZWRDZWsgfHwgZ2VuZXJhdGVDZWsoZW5jKTtcbiAgICAgICAgICAgIGNvbnN0IHsgaXYgfSA9IHByb3ZpZGVkUGFyYW1ldGVycztcbiAgICAgICAgICAgICh7IGVuY3J5cHRlZEtleSwgLi4ucGFyYW1ldGVycyB9ID0gYXdhaXQgYWVzR2NtS3coYWxnLCBrZXksIGNlaywgaXYpKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGRlZmF1bHQ6IHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIFwiYWxnXCIgKEpXRSBBbGdvcml0aG0pIGhlYWRlciB2YWx1ZScpO1xuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiB7IGNlaywgZW5jcnlwdGVkS2V5LCBwYXJhbWV0ZXJzIH07XG59XG5leHBvcnQgZGVmYXVsdCBlbmNyeXB0S2V5TWFuYWdlbWVudDtcbiIsImltcG9ydCB7IGVuY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi8uLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgZW5jcnlwdCBmcm9tICcuLi8uLi9ydW50aW1lL2VuY3J5cHQuanMnO1xuaW1wb3J0IGVuY3J5cHRLZXlNYW5hZ2VtZW50IGZyb20gJy4uLy4uL2xpYi9lbmNyeXB0X2tleV9tYW5hZ2VtZW50LmpzJztcbmltcG9ydCB7IEpPU0VOb3RTdXBwb3J0ZWQsIEpXRUludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgaXNEaXNqb2ludCBmcm9tICcuLi8uLi9saWIvaXNfZGlzam9pbnQuanMnO1xuaW1wb3J0IHsgZW5jb2RlciwgZGVjb2RlciwgY29uY2F0IH0gZnJvbSAnLi4vLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5pbXBvcnQgdmFsaWRhdGVDcml0IGZyb20gJy4uLy4uL2xpYi92YWxpZGF0ZV9jcml0LmpzJztcbmV4cG9ydCBjb25zdCB1bnByb3RlY3RlZCA9IFN5bWJvbCgpO1xuZXhwb3J0IGNsYXNzIEZsYXR0ZW5lZEVuY3J5cHQge1xuICAgIGNvbnN0cnVjdG9yKHBsYWludGV4dCkge1xuICAgICAgICBpZiAoIShwbGFpbnRleHQgaW5zdGFuY2VvZiBVaW50OEFycmF5KSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcigncGxhaW50ZXh0IG11c3QgYmUgYW4gaW5zdGFuY2Ugb2YgVWludDhBcnJheScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3BsYWludGV4dCA9IHBsYWludGV4dDtcbiAgICB9XG4gICAgc2V0S2V5TWFuYWdlbWVudFBhcmFtZXRlcnMocGFyYW1ldGVycykge1xuICAgICAgICBpZiAodGhpcy5fa2V5TWFuYWdlbWVudFBhcmFtZXRlcnMpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldEtleU1hbmFnZW1lbnRQYXJhbWV0ZXJzIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fa2V5TWFuYWdlbWVudFBhcmFtZXRlcnMgPSBwYXJhbWV0ZXJzO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy5fcHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRQcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9wcm90ZWN0ZWRIZWFkZXIgPSBwcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRTaGFyZWRVbnByb3RlY3RlZEhlYWRlcihzaGFyZWRVbnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFNoYXJlZFVucHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIgPSBzaGFyZWRVbnByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldFVucHJvdGVjdGVkSGVhZGVyKHVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLl91bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0VW5wcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl91bnByb3RlY3RlZEhlYWRlciA9IHVucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0QWRkaXRpb25hbEF1dGhlbnRpY2F0ZWREYXRhKGFhZCkge1xuICAgICAgICB0aGlzLl9hYWQgPSBhYWQ7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRDb250ZW50RW5jcnlwdGlvbktleShjZWspIHtcbiAgICAgICAgaWYgKHRoaXMuX2Nlaykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0Q29udGVudEVuY3J5cHRpb25LZXkgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9jZWsgPSBjZWs7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRJbml0aWFsaXphdGlvblZlY3Rvcihpdikge1xuICAgICAgICBpZiAodGhpcy5faXYpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldEluaXRpYWxpemF0aW9uVmVjdG9yIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5faXYgPSBpdjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIGFzeW5jIGVuY3J5cHQoa2V5LCBvcHRpb25zKSB7XG4gICAgICAgIGlmICghdGhpcy5fcHJvdGVjdGVkSGVhZGVyICYmICF0aGlzLl91bnByb3RlY3RlZEhlYWRlciAmJiAhdGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdlaXRoZXIgc2V0UHJvdGVjdGVkSGVhZGVyLCBzZXRVbnByb3RlY3RlZEhlYWRlciwgb3Igc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIgbXVzdCBiZSBjYWxsZWQgYmVmb3JlICNlbmNyeXB0KCknKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIWlzRGlzam9pbnQodGhpcy5fcHJvdGVjdGVkSGVhZGVyLCB0aGlzLl91bnByb3RlY3RlZEhlYWRlciwgdGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFByb3RlY3RlZCwgSldFIFNoYXJlZCBVbnByb3RlY3RlZCBhbmQgSldFIFBlci1SZWNpcGllbnQgSGVhZGVyIFBhcmFtZXRlciBuYW1lcyBtdXN0IGJlIGRpc2pvaW50Jyk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3Qgam9zZUhlYWRlciA9IHtcbiAgICAgICAgICAgIC4uLnRoaXMuX3Byb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgIC4uLnRoaXMuX3VucHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgLi4udGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgIH07XG4gICAgICAgIHZhbGlkYXRlQ3JpdChKV0VJbnZhbGlkLCBuZXcgTWFwKCksIG9wdGlvbnM/LmNyaXQsIHRoaXMuX3Byb3RlY3RlZEhlYWRlciwgam9zZUhlYWRlcik7XG4gICAgICAgIGlmIChqb3NlSGVhZGVyLnppcCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZCgnSldFIFwiemlwXCIgKENvbXByZXNzaW9uIEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBpcyBub3Qgc3VwcG9ydGVkLicpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHsgYWxnLCBlbmMgfSA9IGpvc2VIZWFkZXI7XG4gICAgICAgIGlmICh0eXBlb2YgYWxnICE9PSAnc3RyaW5nJyB8fCAhYWxnKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFwiYWxnXCIgKEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBtaXNzaW5nIG9yIGludmFsaWQnKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodHlwZW9mIGVuYyAhPT0gJ3N0cmluZycgfHwgIWVuYykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ0pXRSBcImVuY1wiIChFbmNyeXB0aW9uIEFsZ29yaXRobSkgSGVhZGVyIFBhcmFtZXRlciBtaXNzaW5nIG9yIGludmFsaWQnKTtcbiAgICAgICAgfVxuICAgICAgICBsZXQgZW5jcnlwdGVkS2V5O1xuICAgICAgICBpZiAodGhpcy5fY2VrICYmIChhbGcgPT09ICdkaXInIHx8IGFsZyA9PT0gJ0VDREgtRVMnKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcihgc2V0Q29udGVudEVuY3J5cHRpb25LZXkgY2Fubm90IGJlIGNhbGxlZCB3aXRoIEpXRSBcImFsZ1wiIChBbGdvcml0aG0pIEhlYWRlciAke2FsZ31gKTtcbiAgICAgICAgfVxuICAgICAgICBsZXQgY2VrO1xuICAgICAgICB7XG4gICAgICAgICAgICBsZXQgcGFyYW1ldGVycztcbiAgICAgICAgICAgICh7IGNlaywgZW5jcnlwdGVkS2V5LCBwYXJhbWV0ZXJzIH0gPSBhd2FpdCBlbmNyeXB0S2V5TWFuYWdlbWVudChhbGcsIGVuYywga2V5LCB0aGlzLl9jZWssIHRoaXMuX2tleU1hbmFnZW1lbnRQYXJhbWV0ZXJzKSk7XG4gICAgICAgICAgICBpZiAocGFyYW1ldGVycykge1xuICAgICAgICAgICAgICAgIGlmIChvcHRpb25zICYmIHVucHJvdGVjdGVkIGluIG9wdGlvbnMpIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCF0aGlzLl91bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5zZXRVbnByb3RlY3RlZEhlYWRlcihwYXJhbWV0ZXJzKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyID0geyAuLi50aGlzLl91bnByb3RlY3RlZEhlYWRlciwgLi4ucGFyYW1ldGVycyB9O1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICBpZiAoIXRoaXMuX3Byb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGhpcy5zZXRQcm90ZWN0ZWRIZWFkZXIocGFyYW1ldGVycyk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0aGlzLl9wcm90ZWN0ZWRIZWFkZXIgPSB7IC4uLnRoaXMuX3Byb3RlY3RlZEhlYWRlciwgLi4ucGFyYW1ldGVycyB9O1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIGxldCBhZGRpdGlvbmFsRGF0YTtcbiAgICAgICAgbGV0IHByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgbGV0IGFhZE1lbWJlcjtcbiAgICAgICAgaWYgKHRoaXMuX3Byb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgcHJvdGVjdGVkSGVhZGVyID0gZW5jb2Rlci5lbmNvZGUoYmFzZTY0dXJsKEpTT04uc3RyaW5naWZ5KHRoaXMuX3Byb3RlY3RlZEhlYWRlcikpKTtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHByb3RlY3RlZEhlYWRlciA9IGVuY29kZXIuZW5jb2RlKCcnKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5fYWFkKSB7XG4gICAgICAgICAgICBhYWRNZW1iZXIgPSBiYXNlNjR1cmwodGhpcy5fYWFkKTtcbiAgICAgICAgICAgIGFkZGl0aW9uYWxEYXRhID0gY29uY2F0KHByb3RlY3RlZEhlYWRlciwgZW5jb2Rlci5lbmNvZGUoJy4nKSwgZW5jb2Rlci5lbmNvZGUoYWFkTWVtYmVyKSk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBhZGRpdGlvbmFsRGF0YSA9IHByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCB7IGNpcGhlcnRleHQsIHRhZywgaXYgfSA9IGF3YWl0IGVuY3J5cHQoZW5jLCB0aGlzLl9wbGFpbnRleHQsIGNlaywgdGhpcy5faXYsIGFkZGl0aW9uYWxEYXRhKTtcbiAgICAgICAgY29uc3QgandlID0ge1xuICAgICAgICAgICAgY2lwaGVydGV4dDogYmFzZTY0dXJsKGNpcGhlcnRleHQpLFxuICAgICAgICB9O1xuICAgICAgICBpZiAoaXYpIHtcbiAgICAgICAgICAgIGp3ZS5pdiA9IGJhc2U2NHVybChpdik7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRhZykge1xuICAgICAgICAgICAgandlLnRhZyA9IGJhc2U2NHVybCh0YWcpO1xuICAgICAgICB9XG4gICAgICAgIGlmIChlbmNyeXB0ZWRLZXkpIHtcbiAgICAgICAgICAgIGp3ZS5lbmNyeXB0ZWRfa2V5ID0gYmFzZTY0dXJsKGVuY3J5cHRlZEtleSk7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGFhZE1lbWJlcikge1xuICAgICAgICAgICAgandlLmFhZCA9IGFhZE1lbWJlcjtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5fcHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICBqd2UucHJvdGVjdGVkID0gZGVjb2Rlci5kZWNvZGUocHJvdGVjdGVkSGVhZGVyKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAodGhpcy5fc2hhcmVkVW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIGp3ZS51bnByb3RlY3RlZCA9IHRoaXMuX3NoYXJlZFVucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl91bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgandlLmhlYWRlciA9IHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBqd2U7XG4gICAgfVxufVxuIiwiaW1wb3J0IHsgRmxhdHRlbmVkRW5jcnlwdCwgdW5wcm90ZWN0ZWQgfSBmcm9tICcuLi9mbGF0dGVuZWQvZW5jcnlwdC5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkLCBKV0VJbnZhbGlkIH0gZnJvbSAnLi4vLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IGdlbmVyYXRlQ2VrIGZyb20gJy4uLy4uL2xpYi9jZWsuanMnO1xuaW1wb3J0IGlzRGlzam9pbnQgZnJvbSAnLi4vLi4vbGliL2lzX2Rpc2pvaW50LmpzJztcbmltcG9ydCBlbmNyeXB0S2V5TWFuYWdlbWVudCBmcm9tICcuLi8uLi9saWIvZW5jcnlwdF9rZXlfbWFuYWdlbWVudC5qcyc7XG5pbXBvcnQgeyBlbmNvZGUgYXMgYmFzZTY0dXJsIH0gZnJvbSAnLi4vLi4vcnVudGltZS9iYXNlNjR1cmwuanMnO1xuaW1wb3J0IHZhbGlkYXRlQ3JpdCBmcm9tICcuLi8uLi9saWIvdmFsaWRhdGVfY3JpdC5qcyc7XG5jbGFzcyBJbmRpdmlkdWFsUmVjaXBpZW50IHtcbiAgICBjb25zdHJ1Y3RvcihlbmMsIGtleSwgb3B0aW9ucykge1xuICAgICAgICB0aGlzLnBhcmVudCA9IGVuYztcbiAgICAgICAgdGhpcy5rZXkgPSBrZXk7XG4gICAgICAgIHRoaXMub3B0aW9ucyA9IG9wdGlvbnM7XG4gICAgfVxuICAgIHNldFVucHJvdGVjdGVkSGVhZGVyKHVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLnVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRVbnByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMudW5wcm90ZWN0ZWRIZWFkZXIgPSB1bnByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIGFkZFJlY2lwaWVudCguLi5hcmdzKSB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhcmVudC5hZGRSZWNpcGllbnQoLi4uYXJncyk7XG4gICAgfVxuICAgIGVuY3J5cHQoLi4uYXJncykge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXJlbnQuZW5jcnlwdCguLi5hcmdzKTtcbiAgICB9XG4gICAgZG9uZSgpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGFyZW50O1xuICAgIH1cbn1cbmV4cG9ydCBjbGFzcyBHZW5lcmFsRW5jcnlwdCB7XG4gICAgY29uc3RydWN0b3IocGxhaW50ZXh0KSB7XG4gICAgICAgIHRoaXMuX3JlY2lwaWVudHMgPSBbXTtcbiAgICAgICAgdGhpcy5fcGxhaW50ZXh0ID0gcGxhaW50ZXh0O1xuICAgIH1cbiAgICBhZGRSZWNpcGllbnQoa2V5LCBvcHRpb25zKSB7XG4gICAgICAgIGNvbnN0IHJlY2lwaWVudCA9IG5ldyBJbmRpdmlkdWFsUmVjaXBpZW50KHRoaXMsIGtleSwgeyBjcml0OiBvcHRpb25zPy5jcml0IH0pO1xuICAgICAgICB0aGlzLl9yZWNpcGllbnRzLnB1c2gocmVjaXBpZW50KTtcbiAgICAgICAgcmV0dXJuIHJlY2lwaWVudDtcbiAgICB9XG4gICAgc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy5fcHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdzZXRQcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl9wcm90ZWN0ZWRIZWFkZXIgPSBwcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRTaGFyZWRVbnByb3RlY3RlZEhlYWRlcihzaGFyZWRVbnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFNoYXJlZFVucHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIgPSBzaGFyZWRVbnByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldEFkZGl0aW9uYWxBdXRoZW50aWNhdGVkRGF0YShhYWQpIHtcbiAgICAgICAgdGhpcy5fYWFkID0gYWFkO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgYXN5bmMgZW5jcnlwdCgpIHtcbiAgICAgICAgaWYgKCF0aGlzLl9yZWNpcGllbnRzLmxlbmd0aCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXRUludmFsaWQoJ2F0IGxlYXN0IG9uZSByZWNpcGllbnQgbXVzdCBiZSBhZGRlZCcpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl9yZWNpcGllbnRzLmxlbmd0aCA9PT0gMSkge1xuICAgICAgICAgICAgY29uc3QgW3JlY2lwaWVudF0gPSB0aGlzLl9yZWNpcGllbnRzO1xuICAgICAgICAgICAgY29uc3QgZmxhdHRlbmVkID0gYXdhaXQgbmV3IEZsYXR0ZW5lZEVuY3J5cHQodGhpcy5fcGxhaW50ZXh0KVxuICAgICAgICAgICAgICAgIC5zZXRBZGRpdGlvbmFsQXV0aGVudGljYXRlZERhdGEodGhpcy5fYWFkKVxuICAgICAgICAgICAgICAgIC5zZXRQcm90ZWN0ZWRIZWFkZXIodGhpcy5fcHJvdGVjdGVkSGVhZGVyKVxuICAgICAgICAgICAgICAgIC5zZXRTaGFyZWRVbnByb3RlY3RlZEhlYWRlcih0aGlzLl91bnByb3RlY3RlZEhlYWRlcilcbiAgICAgICAgICAgICAgICAuc2V0VW5wcm90ZWN0ZWRIZWFkZXIocmVjaXBpZW50LnVucHJvdGVjdGVkSGVhZGVyKVxuICAgICAgICAgICAgICAgIC5lbmNyeXB0KHJlY2lwaWVudC5rZXksIHsgLi4ucmVjaXBpZW50Lm9wdGlvbnMgfSk7XG4gICAgICAgICAgICBjb25zdCBqd2UgPSB7XG4gICAgICAgICAgICAgICAgY2lwaGVydGV4dDogZmxhdHRlbmVkLmNpcGhlcnRleHQsXG4gICAgICAgICAgICAgICAgaXY6IGZsYXR0ZW5lZC5pdixcbiAgICAgICAgICAgICAgICByZWNpcGllbnRzOiBbe31dLFxuICAgICAgICAgICAgICAgIHRhZzogZmxhdHRlbmVkLnRhZyxcbiAgICAgICAgICAgIH07XG4gICAgICAgICAgICBpZiAoZmxhdHRlbmVkLmFhZClcbiAgICAgICAgICAgICAgICBqd2UuYWFkID0gZmxhdHRlbmVkLmFhZDtcbiAgICAgICAgICAgIGlmIChmbGF0dGVuZWQucHJvdGVjdGVkKVxuICAgICAgICAgICAgICAgIGp3ZS5wcm90ZWN0ZWQgPSBmbGF0dGVuZWQucHJvdGVjdGVkO1xuICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC51bnByb3RlY3RlZClcbiAgICAgICAgICAgICAgICBqd2UudW5wcm90ZWN0ZWQgPSBmbGF0dGVuZWQudW5wcm90ZWN0ZWQ7XG4gICAgICAgICAgICBpZiAoZmxhdHRlbmVkLmVuY3J5cHRlZF9rZXkpXG4gICAgICAgICAgICAgICAgandlLnJlY2lwaWVudHNbMF0uZW5jcnlwdGVkX2tleSA9IGZsYXR0ZW5lZC5lbmNyeXB0ZWRfa2V5O1xuICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC5oZWFkZXIpXG4gICAgICAgICAgICAgICAgandlLnJlY2lwaWVudHNbMF0uaGVhZGVyID0gZmxhdHRlbmVkLmhlYWRlcjtcbiAgICAgICAgICAgIHJldHVybiBqd2U7XG4gICAgICAgIH1cbiAgICAgICAgbGV0IGVuYztcbiAgICAgICAgZm9yIChsZXQgaSA9IDA7IGkgPCB0aGlzLl9yZWNpcGllbnRzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBjb25zdCByZWNpcGllbnQgPSB0aGlzLl9yZWNpcGllbnRzW2ldO1xuICAgICAgICAgICAgaWYgKCFpc0Rpc2pvaW50KHRoaXMuX3Byb3RlY3RlZEhlYWRlciwgdGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIsIHJlY2lwaWVudC51bnByb3RlY3RlZEhlYWRlcikpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnSldFIFByb3RlY3RlZCwgSldFIFNoYXJlZCBVbnByb3RlY3RlZCBhbmQgSldFIFBlci1SZWNpcGllbnQgSGVhZGVyIFBhcmFtZXRlciBuYW1lcyBtdXN0IGJlIGRpc2pvaW50Jyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjb25zdCBqb3NlSGVhZGVyID0ge1xuICAgICAgICAgICAgICAgIC4uLnRoaXMuX3Byb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgICAgICAuLi50aGlzLl91bnByb3RlY3RlZEhlYWRlcixcbiAgICAgICAgICAgICAgICAuLi5yZWNpcGllbnQudW5wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAgY29uc3QgeyBhbGcgfSA9IGpvc2VIZWFkZXI7XG4gICAgICAgICAgICBpZiAodHlwZW9mIGFsZyAhPT0gJ3N0cmluZycgfHwgIWFsZykge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgXCJhbGdcIiAoQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIG1pc3Npbmcgb3IgaW52YWxpZCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKGFsZyA9PT0gJ2RpcicgfHwgYWxnID09PSAnRUNESC1FUycpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldFSW52YWxpZCgnXCJkaXJcIiBhbmQgXCJFQ0RILUVTXCIgYWxnIG1heSBvbmx5IGJlIHVzZWQgd2l0aCBhIHNpbmdsZSByZWNpcGllbnQnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmICh0eXBlb2Ygam9zZUhlYWRlci5lbmMgIT09ICdzdHJpbmcnIHx8ICFqb3NlSGVhZGVyLmVuYykge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgXCJlbmNcIiAoRW5jcnlwdGlvbiBBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgbWlzc2luZyBvciBpbnZhbGlkJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAoIWVuYykge1xuICAgICAgICAgICAgICAgIGVuYyA9IGpvc2VIZWFkZXIuZW5jO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZWxzZSBpZiAoZW5jICE9PSBqb3NlSGVhZGVyLmVuYykge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKV0VJbnZhbGlkKCdKV0UgXCJlbmNcIiAoRW5jcnlwdGlvbiBBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgbXVzdCBiZSB0aGUgc2FtZSBmb3IgYWxsIHJlY2lwaWVudHMnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHZhbGlkYXRlQ3JpdChKV0VJbnZhbGlkLCBuZXcgTWFwKCksIHJlY2lwaWVudC5vcHRpb25zLmNyaXQsIHRoaXMuX3Byb3RlY3RlZEhlYWRlciwgam9zZUhlYWRlcik7XG4gICAgICAgICAgICBpZiAoam9zZUhlYWRlci56aXAgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdKV0UgXCJ6aXBcIiAoQ29tcHJlc3Npb24gQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIGlzIG5vdCBzdXBwb3J0ZWQuJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgY2VrID0gZ2VuZXJhdGVDZWsoZW5jKTtcbiAgICAgICAgY29uc3QgandlID0ge1xuICAgICAgICAgICAgY2lwaGVydGV4dDogJycsXG4gICAgICAgICAgICBpdjogJycsXG4gICAgICAgICAgICByZWNpcGllbnRzOiBbXSxcbiAgICAgICAgICAgIHRhZzogJycsXG4gICAgICAgIH07XG4gICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgdGhpcy5fcmVjaXBpZW50cy5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgY29uc3QgcmVjaXBpZW50ID0gdGhpcy5fcmVjaXBpZW50c1tpXTtcbiAgICAgICAgICAgIGNvbnN0IHRhcmdldCA9IHt9O1xuICAgICAgICAgICAgandlLnJlY2lwaWVudHMucHVzaCh0YXJnZXQpO1xuICAgICAgICAgICAgY29uc3Qgam9zZUhlYWRlciA9IHtcbiAgICAgICAgICAgICAgICAuLi50aGlzLl9wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICAgICAgLi4udGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgICAgICAgICAgLi4ucmVjaXBpZW50LnVucHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIGNvbnN0IHAyYyA9IGpvc2VIZWFkZXIuYWxnLnN0YXJ0c1dpdGgoJ1BCRVMyJykgPyAyMDQ4ICsgaSA6IHVuZGVmaW5lZDtcbiAgICAgICAgICAgIGlmIChpID09PSAwKSB7XG4gICAgICAgICAgICAgICAgY29uc3QgZmxhdHRlbmVkID0gYXdhaXQgbmV3IEZsYXR0ZW5lZEVuY3J5cHQodGhpcy5fcGxhaW50ZXh0KVxuICAgICAgICAgICAgICAgICAgICAuc2V0QWRkaXRpb25hbEF1dGhlbnRpY2F0ZWREYXRhKHRoaXMuX2FhZClcbiAgICAgICAgICAgICAgICAgICAgLnNldENvbnRlbnRFbmNyeXB0aW9uS2V5KGNlaylcbiAgICAgICAgICAgICAgICAgICAgLnNldFByb3RlY3RlZEhlYWRlcih0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpXG4gICAgICAgICAgICAgICAgICAgIC5zZXRTaGFyZWRVbnByb3RlY3RlZEhlYWRlcih0aGlzLl91bnByb3RlY3RlZEhlYWRlcilcbiAgICAgICAgICAgICAgICAgICAgLnNldFVucHJvdGVjdGVkSGVhZGVyKHJlY2lwaWVudC51bnByb3RlY3RlZEhlYWRlcilcbiAgICAgICAgICAgICAgICAgICAgLnNldEtleU1hbmFnZW1lbnRQYXJhbWV0ZXJzKHsgcDJjIH0pXG4gICAgICAgICAgICAgICAgICAgIC5lbmNyeXB0KHJlY2lwaWVudC5rZXksIHtcbiAgICAgICAgICAgICAgICAgICAgLi4ucmVjaXBpZW50Lm9wdGlvbnMsXG4gICAgICAgICAgICAgICAgICAgIFt1bnByb3RlY3RlZF06IHRydWUsXG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgandlLmNpcGhlcnRleHQgPSBmbGF0dGVuZWQuY2lwaGVydGV4dDtcbiAgICAgICAgICAgICAgICBqd2UuaXYgPSBmbGF0dGVuZWQuaXY7XG4gICAgICAgICAgICAgICAgandlLnRhZyA9IGZsYXR0ZW5lZC50YWc7XG4gICAgICAgICAgICAgICAgaWYgKGZsYXR0ZW5lZC5hYWQpXG4gICAgICAgICAgICAgICAgICAgIGp3ZS5hYWQgPSBmbGF0dGVuZWQuYWFkO1xuICAgICAgICAgICAgICAgIGlmIChmbGF0dGVuZWQucHJvdGVjdGVkKVxuICAgICAgICAgICAgICAgICAgICBqd2UucHJvdGVjdGVkID0gZmxhdHRlbmVkLnByb3RlY3RlZDtcbiAgICAgICAgICAgICAgICBpZiAoZmxhdHRlbmVkLnVucHJvdGVjdGVkKVxuICAgICAgICAgICAgICAgICAgICBqd2UudW5wcm90ZWN0ZWQgPSBmbGF0dGVuZWQudW5wcm90ZWN0ZWQ7XG4gICAgICAgICAgICAgICAgdGFyZ2V0LmVuY3J5cHRlZF9rZXkgPSBmbGF0dGVuZWQuZW5jcnlwdGVkX2tleTtcbiAgICAgICAgICAgICAgICBpZiAoZmxhdHRlbmVkLmhlYWRlcilcbiAgICAgICAgICAgICAgICAgICAgdGFyZ2V0LmhlYWRlciA9IGZsYXR0ZW5lZC5oZWFkZXI7XG4gICAgICAgICAgICAgICAgY29udGludWU7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjb25zdCB7IGVuY3J5cHRlZEtleSwgcGFyYW1ldGVycyB9ID0gYXdhaXQgZW5jcnlwdEtleU1hbmFnZW1lbnQocmVjaXBpZW50LnVucHJvdGVjdGVkSGVhZGVyPy5hbGcgfHxcbiAgICAgICAgICAgICAgICB0aGlzLl9wcm90ZWN0ZWRIZWFkZXI/LmFsZyB8fFxuICAgICAgICAgICAgICAgIHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyPy5hbGcsIGVuYywgcmVjaXBpZW50LmtleSwgY2VrLCB7IHAyYyB9KTtcbiAgICAgICAgICAgIHRhcmdldC5lbmNyeXB0ZWRfa2V5ID0gYmFzZTY0dXJsKGVuY3J5cHRlZEtleSk7XG4gICAgICAgICAgICBpZiAocmVjaXBpZW50LnVucHJvdGVjdGVkSGVhZGVyIHx8IHBhcmFtZXRlcnMpXG4gICAgICAgICAgICAgICAgdGFyZ2V0LmhlYWRlciA9IHsgLi4ucmVjaXBpZW50LnVucHJvdGVjdGVkSGVhZGVyLCAuLi5wYXJhbWV0ZXJzIH07XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGp3ZTtcbiAgICB9XG59XG4iLCJpbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gc3VidGxlRHNhKGFsZywgYWxnb3JpdGhtKSB7XG4gICAgY29uc3QgaGFzaCA9IGBTSEEtJHthbGcuc2xpY2UoLTMpfWA7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnSFMyNTYnOlxuICAgICAgICBjYXNlICdIUzM4NCc6XG4gICAgICAgIGNhc2UgJ0hTNTEyJzpcbiAgICAgICAgICAgIHJldHVybiB7IGhhc2gsIG5hbWU6ICdITUFDJyB9O1xuICAgICAgICBjYXNlICdQUzI1Nic6XG4gICAgICAgIGNhc2UgJ1BTMzg0JzpcbiAgICAgICAgY2FzZSAnUFM1MTInOlxuICAgICAgICAgICAgcmV0dXJuIHsgaGFzaCwgbmFtZTogJ1JTQS1QU1MnLCBzYWx0TGVuZ3RoOiBhbGcuc2xpY2UoLTMpID4+IDMgfTtcbiAgICAgICAgY2FzZSAnUlMyNTYnOlxuICAgICAgICBjYXNlICdSUzM4NCc6XG4gICAgICAgIGNhc2UgJ1JTNTEyJzpcbiAgICAgICAgICAgIHJldHVybiB7IGhhc2gsIG5hbWU6ICdSU0FTU0EtUEtDUzEtdjFfNScgfTtcbiAgICAgICAgY2FzZSAnRVMyNTYnOlxuICAgICAgICBjYXNlICdFUzM4NCc6XG4gICAgICAgIGNhc2UgJ0VTNTEyJzpcbiAgICAgICAgICAgIHJldHVybiB7IGhhc2gsIG5hbWU6ICdFQ0RTQScsIG5hbWVkQ3VydmU6IGFsZ29yaXRobS5uYW1lZEN1cnZlIH07XG4gICAgICAgIGNhc2UgJ0VkRFNBJzpcbiAgICAgICAgICAgIHJldHVybiB7IG5hbWU6IGFsZ29yaXRobS5uYW1lIH07XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICB0aHJvdyBuZXcgSk9TRU5vdFN1cHBvcnRlZChgYWxnICR7YWxnfSBpcyBub3Qgc3VwcG9ydGVkIGVpdGhlciBieSBKT1NFIG9yIHlvdXIgamF2YXNjcmlwdCBydW50aW1lYCk7XG4gICAgfVxufVxuIiwiaW1wb3J0IGNyeXB0bywgeyBpc0NyeXB0b0tleSB9IGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCB7IGNoZWNrU2lnQ3J5cHRvS2V5IH0gZnJvbSAnLi4vbGliL2NyeXB0b19rZXkuanMnO1xuaW1wb3J0IGludmFsaWRLZXlJbnB1dCBmcm9tICcuLi9saWIvaW52YWxpZF9rZXlfaW5wdXQuanMnO1xuaW1wb3J0IHsgdHlwZXMgfSBmcm9tICcuL2lzX2tleV9saWtlLmpzJztcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIGdldENyeXB0b0tleShhbGcsIGtleSwgdXNhZ2UpIHtcbiAgICBpZiAoaXNDcnlwdG9LZXkoa2V5KSkge1xuICAgICAgICBjaGVja1NpZ0NyeXB0b0tleShrZXksIGFsZywgdXNhZ2UpO1xuICAgICAgICByZXR1cm4ga2V5O1xuICAgIH1cbiAgICBpZiAoa2V5IGluc3RhbmNlb2YgVWludDhBcnJheSkge1xuICAgICAgICBpZiAoIWFsZy5zdGFydHNXaXRoKCdIUycpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKGludmFsaWRLZXlJbnB1dChrZXksIC4uLnR5cGVzKSk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBrZXksIHsgaGFzaDogYFNIQS0ke2FsZy5zbGljZSgtMyl9YCwgbmFtZTogJ0hNQUMnIH0sIGZhbHNlLCBbdXNhZ2VdKTtcbiAgICB9XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcihpbnZhbGlkS2V5SW5wdXQoa2V5LCAuLi50eXBlcywgJ1VpbnQ4QXJyYXknKSk7XG59XG4iLCJpbXBvcnQgc3VidGxlQWxnb3JpdGhtIGZyb20gJy4vc3VidGxlX2RzYS5qcyc7XG5pbXBvcnQgY3J5cHRvIGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCBjaGVja0tleUxlbmd0aCBmcm9tICcuL2NoZWNrX2tleV9sZW5ndGguanMnO1xuaW1wb3J0IGdldFZlcmlmeUtleSBmcm9tICcuL2dldF9zaWduX3ZlcmlmeV9rZXkuanMnO1xuY29uc3QgdmVyaWZ5ID0gYXN5bmMgKGFsZywga2V5LCBzaWduYXR1cmUsIGRhdGEpID0+IHtcbiAgICBjb25zdCBjcnlwdG9LZXkgPSBhd2FpdCBnZXRWZXJpZnlLZXkoYWxnLCBrZXksICd2ZXJpZnknKTtcbiAgICBjaGVja0tleUxlbmd0aChhbGcsIGNyeXB0b0tleSk7XG4gICAgY29uc3QgYWxnb3JpdGhtID0gc3VidGxlQWxnb3JpdGhtKGFsZywgY3J5cHRvS2V5LmFsZ29yaXRobSk7XG4gICAgdHJ5IHtcbiAgICAgICAgcmV0dXJuIGF3YWl0IGNyeXB0by5zdWJ0bGUudmVyaWZ5KGFsZ29yaXRobSwgY3J5cHRvS2V5LCBzaWduYXR1cmUsIGRhdGEpO1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG59O1xuZXhwb3J0IGRlZmF1bHQgdmVyaWZ5O1xuIiwiaW1wb3J0IHsgZGVjb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4uLy4uL3J1bnRpbWUvYmFzZTY0dXJsLmpzJztcbmltcG9ydCB2ZXJpZnkgZnJvbSAnLi4vLi4vcnVudGltZS92ZXJpZnkuanMnO1xuaW1wb3J0IHsgSk9TRUFsZ05vdEFsbG93ZWQsIEpXU0ludmFsaWQsIEpXU1NpZ25hdHVyZVZlcmlmaWNhdGlvbkZhaWxlZCB9IGZyb20gJy4uLy4uL3V0aWwvZXJyb3JzLmpzJztcbmltcG9ydCB7IGNvbmNhdCwgZW5jb2RlciwgZGVjb2RlciB9IGZyb20gJy4uLy4uL2xpYi9idWZmZXJfdXRpbHMuanMnO1xuaW1wb3J0IGlzRGlzam9pbnQgZnJvbSAnLi4vLi4vbGliL2lzX2Rpc2pvaW50LmpzJztcbmltcG9ydCBpc09iamVjdCBmcm9tICcuLi8uLi9saWIvaXNfb2JqZWN0LmpzJztcbmltcG9ydCBjaGVja0tleVR5cGUgZnJvbSAnLi4vLi4vbGliL2NoZWNrX2tleV90eXBlLmpzJztcbmltcG9ydCB2YWxpZGF0ZUNyaXQgZnJvbSAnLi4vLi4vbGliL3ZhbGlkYXRlX2NyaXQuanMnO1xuaW1wb3J0IHZhbGlkYXRlQWxnb3JpdGhtcyBmcm9tICcuLi8uLi9saWIvdmFsaWRhdGVfYWxnb3JpdGhtcy5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZmxhdHRlbmVkVmVyaWZ5KGp3cywga2V5LCBvcHRpb25zKSB7XG4gICAgaWYgKCFpc09iamVjdChqd3MpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdGbGF0dGVuZWQgSldTIG11c3QgYmUgYW4gb2JqZWN0Jyk7XG4gICAgfVxuICAgIGlmIChqd3MucHJvdGVjdGVkID09PSB1bmRlZmluZWQgJiYgandzLmhlYWRlciA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdGbGF0dGVuZWQgSldTIG11c3QgaGF2ZSBlaXRoZXIgb2YgdGhlIFwicHJvdGVjdGVkXCIgb3IgXCJoZWFkZXJcIiBtZW1iZXJzJyk7XG4gICAgfVxuICAgIGlmIChqd3MucHJvdGVjdGVkICE9PSB1bmRlZmluZWQgJiYgdHlwZW9mIGp3cy5wcm90ZWN0ZWQgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgUHJvdGVjdGVkIEhlYWRlciBpbmNvcnJlY3QgdHlwZScpO1xuICAgIH1cbiAgICBpZiAoandzLnBheWxvYWQgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSldTIFBheWxvYWQgbWlzc2luZycpO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIGp3cy5zaWduYXR1cmUgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgU2lnbmF0dXJlIG1pc3Npbmcgb3IgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgaWYgKGp3cy5oZWFkZXIgIT09IHVuZGVmaW5lZCAmJiAhaXNPYmplY3QoandzLmhlYWRlcikpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBVbnByb3RlY3RlZCBIZWFkZXIgaW5jb3JyZWN0IHR5cGUnKTtcbiAgICB9XG4gICAgbGV0IHBhcnNlZFByb3QgPSB7fTtcbiAgICBpZiAoandzLnByb3RlY3RlZCkge1xuICAgICAgICB0cnkge1xuICAgICAgICAgICAgY29uc3QgcHJvdGVjdGVkSGVhZGVyID0gYmFzZTY0dXJsKGp3cy5wcm90ZWN0ZWQpO1xuICAgICAgICAgICAgcGFyc2VkUHJvdCA9IEpTT04ucGFyc2UoZGVjb2Rlci5kZWNvZGUocHJvdGVjdGVkSGVhZGVyKSk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBQcm90ZWN0ZWQgSGVhZGVyIGlzIGludmFsaWQnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBpZiAoIWlzRGlzam9pbnQocGFyc2VkUHJvdCwgandzLmhlYWRlcikpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBQcm90ZWN0ZWQgYW5kIEpXUyBVbnByb3RlY3RlZCBIZWFkZXIgUGFyYW1ldGVyIG5hbWVzIG11c3QgYmUgZGlzam9pbnQnKTtcbiAgICB9XG4gICAgY29uc3Qgam9zZUhlYWRlciA9IHtcbiAgICAgICAgLi4ucGFyc2VkUHJvdCxcbiAgICAgICAgLi4uandzLmhlYWRlcixcbiAgICB9O1xuICAgIGNvbnN0IGV4dGVuc2lvbnMgPSB2YWxpZGF0ZUNyaXQoSldTSW52YWxpZCwgbmV3IE1hcChbWydiNjQnLCB0cnVlXV0pLCBvcHRpb25zPy5jcml0LCBwYXJzZWRQcm90LCBqb3NlSGVhZGVyKTtcbiAgICBsZXQgYjY0ID0gdHJ1ZTtcbiAgICBpZiAoZXh0ZW5zaW9ucy5oYXMoJ2I2NCcpKSB7XG4gICAgICAgIGI2NCA9IHBhcnNlZFByb3QuYjY0O1xuICAgICAgICBpZiAodHlwZW9mIGI2NCAhPT0gJ2Jvb2xlYW4nKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnVGhlIFwiYjY0XCIgKGJhc2U2NHVybC1lbmNvZGUgcGF5bG9hZCkgSGVhZGVyIFBhcmFtZXRlciBtdXN0IGJlIGEgYm9vbGVhbicpO1xuICAgICAgICB9XG4gICAgfVxuICAgIGNvbnN0IHsgYWxnIH0gPSBqb3NlSGVhZGVyO1xuICAgIGlmICh0eXBlb2YgYWxnICE9PSAnc3RyaW5nJyB8fCAhYWxnKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgXCJhbGdcIiAoQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIG1pc3Npbmcgb3IgaW52YWxpZCcpO1xuICAgIH1cbiAgICBjb25zdCBhbGdvcml0aG1zID0gb3B0aW9ucyAmJiB2YWxpZGF0ZUFsZ29yaXRobXMoJ2FsZ29yaXRobXMnLCBvcHRpb25zLmFsZ29yaXRobXMpO1xuICAgIGlmIChhbGdvcml0aG1zICYmICFhbGdvcml0aG1zLmhhcyhhbGcpKSB7XG4gICAgICAgIHRocm93IG5ldyBKT1NFQWxnTm90QWxsb3dlZCgnXCJhbGdcIiAoQWxnb3JpdGhtKSBIZWFkZXIgUGFyYW1ldGVyIHZhbHVlIG5vdCBhbGxvd2VkJyk7XG4gICAgfVxuICAgIGlmIChiNjQpIHtcbiAgICAgICAgaWYgKHR5cGVvZiBqd3MucGF5bG9hZCAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgUGF5bG9hZCBtdXN0IGJlIGEgc3RyaW5nJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgZWxzZSBpZiAodHlwZW9mIGp3cy5wYXlsb2FkICE9PSAnc3RyaW5nJyAmJiAhKGp3cy5wYXlsb2FkIGluc3RhbmNlb2YgVWludDhBcnJheSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBQYXlsb2FkIG11c3QgYmUgYSBzdHJpbmcgb3IgYW4gVWludDhBcnJheSBpbnN0YW5jZScpO1xuICAgIH1cbiAgICBsZXQgcmVzb2x2ZWRLZXkgPSBmYWxzZTtcbiAgICBpZiAodHlwZW9mIGtleSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICBrZXkgPSBhd2FpdCBrZXkocGFyc2VkUHJvdCwgandzKTtcbiAgICAgICAgcmVzb2x2ZWRLZXkgPSB0cnVlO1xuICAgIH1cbiAgICBjaGVja0tleVR5cGUoYWxnLCBrZXksICd2ZXJpZnknKTtcbiAgICBjb25zdCBkYXRhID0gY29uY2F0KGVuY29kZXIuZW5jb2RlKGp3cy5wcm90ZWN0ZWQgPz8gJycpLCBlbmNvZGVyLmVuY29kZSgnLicpLCB0eXBlb2YgandzLnBheWxvYWQgPT09ICdzdHJpbmcnID8gZW5jb2Rlci5lbmNvZGUoandzLnBheWxvYWQpIDogandzLnBheWxvYWQpO1xuICAgIGxldCBzaWduYXR1cmU7XG4gICAgdHJ5IHtcbiAgICAgICAgc2lnbmF0dXJlID0gYmFzZTY0dXJsKGp3cy5zaWduYXR1cmUpO1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdGYWlsZWQgdG8gYmFzZTY0dXJsIGRlY29kZSB0aGUgc2lnbmF0dXJlJyk7XG4gICAgfVxuICAgIGNvbnN0IHZlcmlmaWVkID0gYXdhaXQgdmVyaWZ5KGFsZywga2V5LCBzaWduYXR1cmUsIGRhdGEpO1xuICAgIGlmICghdmVyaWZpZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IEpXU1NpZ25hdHVyZVZlcmlmaWNhdGlvbkZhaWxlZCgpO1xuICAgIH1cbiAgICBsZXQgcGF5bG9hZDtcbiAgICBpZiAoYjY0KSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICBwYXlsb2FkID0gYmFzZTY0dXJsKGp3cy5wYXlsb2FkKTtcbiAgICAgICAgfVxuICAgICAgICBjYXRjaCB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnRmFpbGVkIHRvIGJhc2U2NHVybCBkZWNvZGUgdGhlIHBheWxvYWQnKTtcbiAgICAgICAgfVxuICAgIH1cbiAgICBlbHNlIGlmICh0eXBlb2YgandzLnBheWxvYWQgPT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHBheWxvYWQgPSBlbmNvZGVyLmVuY29kZShqd3MucGF5bG9hZCk7XG4gICAgfVxuICAgIGVsc2Uge1xuICAgICAgICBwYXlsb2FkID0gandzLnBheWxvYWQ7XG4gICAgfVxuICAgIGNvbnN0IHJlc3VsdCA9IHsgcGF5bG9hZCB9O1xuICAgIGlmIChqd3MucHJvdGVjdGVkICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmVzdWx0LnByb3RlY3RlZEhlYWRlciA9IHBhcnNlZFByb3Q7XG4gICAgfVxuICAgIGlmIChqd3MuaGVhZGVyICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgcmVzdWx0LnVucHJvdGVjdGVkSGVhZGVyID0gandzLmhlYWRlcjtcbiAgICB9XG4gICAgaWYgKHJlc29sdmVkS2V5KSB7XG4gICAgICAgIHJldHVybiB7IC4uLnJlc3VsdCwga2V5IH07XG4gICAgfVxuICAgIHJldHVybiByZXN1bHQ7XG59XG4iLCJpbXBvcnQgeyBmbGF0dGVuZWRWZXJpZnkgfSBmcm9tICcuLi9mbGF0dGVuZWQvdmVyaWZ5LmpzJztcbmltcG9ydCB7IEpXU0ludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgeyBkZWNvZGVyIH0gZnJvbSAnLi4vLi4vbGliL2J1ZmZlcl91dGlscy5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gY29tcGFjdFZlcmlmeShqd3MsIGtleSwgb3B0aW9ucykge1xuICAgIGlmIChqd3MgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG4gICAgICAgIGp3cyA9IGRlY29kZXIuZGVjb2RlKGp3cyk7XG4gICAgfVxuICAgIGlmICh0eXBlb2YgandzICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnQ29tcGFjdCBKV1MgbXVzdCBiZSBhIHN0cmluZyBvciBVaW50OEFycmF5Jyk7XG4gICAgfVxuICAgIGNvbnN0IHsgMDogcHJvdGVjdGVkSGVhZGVyLCAxOiBwYXlsb2FkLCAyOiBzaWduYXR1cmUsIGxlbmd0aCB9ID0gandzLnNwbGl0KCcuJyk7XG4gICAgaWYgKGxlbmd0aCAhPT0gMykge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnSW52YWxpZCBDb21wYWN0IEpXUycpO1xuICAgIH1cbiAgICBjb25zdCB2ZXJpZmllZCA9IGF3YWl0IGZsYXR0ZW5lZFZlcmlmeSh7IHBheWxvYWQsIHByb3RlY3RlZDogcHJvdGVjdGVkSGVhZGVyLCBzaWduYXR1cmUgfSwga2V5LCBvcHRpb25zKTtcbiAgICBjb25zdCByZXN1bHQgPSB7IHBheWxvYWQ6IHZlcmlmaWVkLnBheWxvYWQsIHByb3RlY3RlZEhlYWRlcjogdmVyaWZpZWQucHJvdGVjdGVkSGVhZGVyIH07XG4gICAgaWYgKHR5cGVvZiBrZXkgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAgcmV0dXJuIHsgLi4ucmVzdWx0LCBrZXk6IHZlcmlmaWVkLmtleSB9O1xuICAgIH1cbiAgICByZXR1cm4gcmVzdWx0O1xufVxuIiwiaW1wb3J0IHsgZmxhdHRlbmVkVmVyaWZ5IH0gZnJvbSAnLi4vZmxhdHRlbmVkL3ZlcmlmeS5qcyc7XG5pbXBvcnQgeyBKV1NJbnZhbGlkLCBKV1NTaWduYXR1cmVWZXJpZmljYXRpb25GYWlsZWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgaXNPYmplY3QgZnJvbSAnLi4vLi4vbGliL2lzX29iamVjdC5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhbFZlcmlmeShqd3MsIGtleSwgb3B0aW9ucykge1xuICAgIGlmICghaXNPYmplY3QoandzKSkge1xuICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnR2VuZXJhbCBKV1MgbXVzdCBiZSBhbiBvYmplY3QnKTtcbiAgICB9XG4gICAgaWYgKCFBcnJheS5pc0FycmF5KGp3cy5zaWduYXR1cmVzKSB8fCAhandzLnNpZ25hdHVyZXMuZXZlcnkoaXNPYmplY3QpKSB7XG4gICAgICAgIHRocm93IG5ldyBKV1NJbnZhbGlkKCdKV1MgU2lnbmF0dXJlcyBtaXNzaW5nIG9yIGluY29ycmVjdCB0eXBlJyk7XG4gICAgfVxuICAgIGZvciAoY29uc3Qgc2lnbmF0dXJlIG9mIGp3cy5zaWduYXR1cmVzKSB7XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgICByZXR1cm4gYXdhaXQgZmxhdHRlbmVkVmVyaWZ5KHtcbiAgICAgICAgICAgICAgICBoZWFkZXI6IHNpZ25hdHVyZS5oZWFkZXIsXG4gICAgICAgICAgICAgICAgcGF5bG9hZDogandzLnBheWxvYWQsXG4gICAgICAgICAgICAgICAgcHJvdGVjdGVkOiBzaWduYXR1cmUucHJvdGVjdGVkLFxuICAgICAgICAgICAgICAgIHNpZ25hdHVyZTogc2lnbmF0dXJlLnNpZ25hdHVyZSxcbiAgICAgICAgICAgIH0sIGtleSwgb3B0aW9ucyk7XG4gICAgICAgIH1cbiAgICAgICAgY2F0Y2gge1xuICAgICAgICB9XG4gICAgfVxuICAgIHRocm93IG5ldyBKV1NTaWduYXR1cmVWZXJpZmljYXRpb25GYWlsZWQoKTtcbn1cbiIsImltcG9ydCB7IEZsYXR0ZW5lZEVuY3J5cHQgfSBmcm9tICcuLi9mbGF0dGVuZWQvZW5jcnlwdC5qcyc7XG5leHBvcnQgY2xhc3MgQ29tcGFjdEVuY3J5cHQge1xuICAgIGNvbnN0cnVjdG9yKHBsYWludGV4dCkge1xuICAgICAgICB0aGlzLl9mbGF0dGVuZWQgPSBuZXcgRmxhdHRlbmVkRW5jcnlwdChwbGFpbnRleHQpO1xuICAgIH1cbiAgICBzZXRDb250ZW50RW5jcnlwdGlvbktleShjZWspIHtcbiAgICAgICAgdGhpcy5fZmxhdHRlbmVkLnNldENvbnRlbnRFbmNyeXB0aW9uS2V5KGNlayk7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRJbml0aWFsaXphdGlvblZlY3Rvcihpdikge1xuICAgICAgICB0aGlzLl9mbGF0dGVuZWQuc2V0SW5pdGlhbGl6YXRpb25WZWN0b3IoaXYpO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICB0aGlzLl9mbGF0dGVuZWQuc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcik7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRLZXlNYW5hZ2VtZW50UGFyYW1ldGVycyhwYXJhbWV0ZXJzKSB7XG4gICAgICAgIHRoaXMuX2ZsYXR0ZW5lZC5zZXRLZXlNYW5hZ2VtZW50UGFyYW1ldGVycyhwYXJhbWV0ZXJzKTtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIGFzeW5jIGVuY3J5cHQoa2V5LCBvcHRpb25zKSB7XG4gICAgICAgIGNvbnN0IGp3ZSA9IGF3YWl0IHRoaXMuX2ZsYXR0ZW5lZC5lbmNyeXB0KGtleSwgb3B0aW9ucyk7XG4gICAgICAgIHJldHVybiBbandlLnByb3RlY3RlZCwgandlLmVuY3J5cHRlZF9rZXksIGp3ZS5pdiwgandlLmNpcGhlcnRleHQsIGp3ZS50YWddLmpvaW4oJy4nKTtcbiAgICB9XG59XG4iLCJpbXBvcnQgc3VidGxlQWxnb3JpdGhtIGZyb20gJy4vc3VidGxlX2RzYS5qcyc7XG5pbXBvcnQgY3J5cHRvIGZyb20gJy4vd2ViY3J5cHRvLmpzJztcbmltcG9ydCBjaGVja0tleUxlbmd0aCBmcm9tICcuL2NoZWNrX2tleV9sZW5ndGguanMnO1xuaW1wb3J0IGdldFNpZ25LZXkgZnJvbSAnLi9nZXRfc2lnbl92ZXJpZnlfa2V5LmpzJztcbmNvbnN0IHNpZ24gPSBhc3luYyAoYWxnLCBrZXksIGRhdGEpID0+IHtcbiAgICBjb25zdCBjcnlwdG9LZXkgPSBhd2FpdCBnZXRTaWduS2V5KGFsZywga2V5LCAnc2lnbicpO1xuICAgIGNoZWNrS2V5TGVuZ3RoKGFsZywgY3J5cHRvS2V5KTtcbiAgICBjb25zdCBzaWduYXR1cmUgPSBhd2FpdCBjcnlwdG8uc3VidGxlLnNpZ24oc3VidGxlQWxnb3JpdGhtKGFsZywgY3J5cHRvS2V5LmFsZ29yaXRobSksIGNyeXB0b0tleSwgZGF0YSk7XG4gICAgcmV0dXJuIG5ldyBVaW50OEFycmF5KHNpZ25hdHVyZSk7XG59O1xuZXhwb3J0IGRlZmF1bHQgc2lnbjtcbiIsImltcG9ydCB7IGVuY29kZSBhcyBiYXNlNjR1cmwgfSBmcm9tICcuLi8uLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5pbXBvcnQgc2lnbiBmcm9tICcuLi8uLi9ydW50aW1lL3NpZ24uanMnO1xuaW1wb3J0IGlzRGlzam9pbnQgZnJvbSAnLi4vLi4vbGliL2lzX2Rpc2pvaW50LmpzJztcbmltcG9ydCB7IEpXU0ludmFsaWQgfSBmcm9tICcuLi8uLi91dGlsL2Vycm9ycy5qcyc7XG5pbXBvcnQgeyBlbmNvZGVyLCBkZWNvZGVyLCBjb25jYXQgfSBmcm9tICcuLi8uLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmltcG9ydCBjaGVja0tleVR5cGUgZnJvbSAnLi4vLi4vbGliL2NoZWNrX2tleV90eXBlLmpzJztcbmltcG9ydCB2YWxpZGF0ZUNyaXQgZnJvbSAnLi4vLi4vbGliL3ZhbGlkYXRlX2NyaXQuanMnO1xuZXhwb3J0IGNsYXNzIEZsYXR0ZW5lZFNpZ24ge1xuICAgIGNvbnN0cnVjdG9yKHBheWxvYWQpIHtcbiAgICAgICAgaWYgKCEocGF5bG9hZCBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgVHlwZUVycm9yKCdwYXlsb2FkIG11c3QgYmUgYW4gaW5zdGFuY2Ugb2YgVWludDhBcnJheScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3BheWxvYWQgPSBwYXlsb2FkO1xuICAgIH1cbiAgICBzZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ3NldFByb3RlY3RlZEhlYWRlciBjYW4gb25seSBiZSBjYWxsZWQgb25jZScpO1xuICAgICAgICB9XG4gICAgICAgIHRoaXMuX3Byb3RlY3RlZEhlYWRlciA9IHByb3RlY3RlZEhlYWRlcjtcbiAgICAgICAgcmV0dXJuIHRoaXM7XG4gICAgfVxuICAgIHNldFVucHJvdGVjdGVkSGVhZGVyKHVucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLl91bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0VW5wcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLl91bnByb3RlY3RlZEhlYWRlciA9IHVucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICByZXR1cm4gdGhpcztcbiAgICB9XG4gICAgYXN5bmMgc2lnbihrZXksIG9wdGlvbnMpIHtcbiAgICAgICAgaWYgKCF0aGlzLl9wcm90ZWN0ZWRIZWFkZXIgJiYgIXRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnZWl0aGVyIHNldFByb3RlY3RlZEhlYWRlciBvciBzZXRVbnByb3RlY3RlZEhlYWRlciBtdXN0IGJlIGNhbGxlZCBiZWZvcmUgI3NpZ24oKScpO1xuICAgICAgICB9XG4gICAgICAgIGlmICghaXNEaXNqb2ludCh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIsIHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBQcm90ZWN0ZWQgYW5kIEpXUyBVbnByb3RlY3RlZCBIZWFkZXIgUGFyYW1ldGVyIG5hbWVzIG11c3QgYmUgZGlzam9pbnQnKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBqb3NlSGVhZGVyID0ge1xuICAgICAgICAgICAgLi4udGhpcy5fcHJvdGVjdGVkSGVhZGVyLFxuICAgICAgICAgICAgLi4udGhpcy5fdW5wcm90ZWN0ZWRIZWFkZXIsXG4gICAgICAgIH07XG4gICAgICAgIGNvbnN0IGV4dGVuc2lvbnMgPSB2YWxpZGF0ZUNyaXQoSldTSW52YWxpZCwgbmV3IE1hcChbWydiNjQnLCB0cnVlXV0pLCBvcHRpb25zPy5jcml0LCB0aGlzLl9wcm90ZWN0ZWRIZWFkZXIsIGpvc2VIZWFkZXIpO1xuICAgICAgICBsZXQgYjY0ID0gdHJ1ZTtcbiAgICAgICAgaWYgKGV4dGVuc2lvbnMuaGFzKCdiNjQnKSkge1xuICAgICAgICAgICAgYjY0ID0gdGhpcy5fcHJvdGVjdGVkSGVhZGVyLmI2NDtcbiAgICAgICAgICAgIGlmICh0eXBlb2YgYjY0ICE9PSAnYm9vbGVhbicpIHtcbiAgICAgICAgICAgICAgICB0aHJvdyBuZXcgSldTSW52YWxpZCgnVGhlIFwiYjY0XCIgKGJhc2U2NHVybC1lbmNvZGUgcGF5bG9hZCkgSGVhZGVyIFBhcmFtZXRlciBtdXN0IGJlIGEgYm9vbGVhbicpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHsgYWxnIH0gPSBqb3NlSGVhZGVyO1xuICAgICAgICBpZiAodHlwZW9mIGFsZyAhPT0gJ3N0cmluZycgfHwgIWFsZykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ0pXUyBcImFsZ1wiIChBbGdvcml0aG0pIEhlYWRlciBQYXJhbWV0ZXIgbWlzc2luZyBvciBpbnZhbGlkJyk7XG4gICAgICAgIH1cbiAgICAgICAgY2hlY2tLZXlUeXBlKGFsZywga2V5LCAnc2lnbicpO1xuICAgICAgICBsZXQgcGF5bG9hZCA9IHRoaXMuX3BheWxvYWQ7XG4gICAgICAgIGlmIChiNjQpIHtcbiAgICAgICAgICAgIHBheWxvYWQgPSBlbmNvZGVyLmVuY29kZShiYXNlNjR1cmwocGF5bG9hZCkpO1xuICAgICAgICB9XG4gICAgICAgIGxldCBwcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIGlmICh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIHByb3RlY3RlZEhlYWRlciA9IGVuY29kZXIuZW5jb2RlKGJhc2U2NHVybChKU09OLnN0cmluZ2lmeSh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpKSk7XG4gICAgICAgIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBwcm90ZWN0ZWRIZWFkZXIgPSBlbmNvZGVyLmVuY29kZSgnJyk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgZGF0YSA9IGNvbmNhdChwcm90ZWN0ZWRIZWFkZXIsIGVuY29kZXIuZW5jb2RlKCcuJyksIHBheWxvYWQpO1xuICAgICAgICBjb25zdCBzaWduYXR1cmUgPSBhd2FpdCBzaWduKGFsZywga2V5LCBkYXRhKTtcbiAgICAgICAgY29uc3QgandzID0ge1xuICAgICAgICAgICAgc2lnbmF0dXJlOiBiYXNlNjR1cmwoc2lnbmF0dXJlKSxcbiAgICAgICAgICAgIHBheWxvYWQ6ICcnLFxuICAgICAgICB9O1xuICAgICAgICBpZiAoYjY0KSB7XG4gICAgICAgICAgICBqd3MucGF5bG9hZCA9IGRlY29kZXIuZGVjb2RlKHBheWxvYWQpO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl91bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgandzLmhlYWRlciA9IHRoaXMuX3VucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgICB9XG4gICAgICAgIGlmICh0aGlzLl9wcm90ZWN0ZWRIZWFkZXIpIHtcbiAgICAgICAgICAgIGp3cy5wcm90ZWN0ZWQgPSBkZWNvZGVyLmRlY29kZShwcm90ZWN0ZWRIZWFkZXIpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBqd3M7XG4gICAgfVxufVxuIiwiaW1wb3J0IHsgRmxhdHRlbmVkU2lnbiB9IGZyb20gJy4uL2ZsYXR0ZW5lZC9zaWduLmpzJztcbmV4cG9ydCBjbGFzcyBDb21wYWN0U2lnbiB7XG4gICAgY29uc3RydWN0b3IocGF5bG9hZCkge1xuICAgICAgICB0aGlzLl9mbGF0dGVuZWQgPSBuZXcgRmxhdHRlbmVkU2lnbihwYXlsb2FkKTtcbiAgICB9XG4gICAgc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICB0aGlzLl9mbGF0dGVuZWQuc2V0UHJvdGVjdGVkSGVhZGVyKHByb3RlY3RlZEhlYWRlcik7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBhc3luYyBzaWduKGtleSwgb3B0aW9ucykge1xuICAgICAgICBjb25zdCBqd3MgPSBhd2FpdCB0aGlzLl9mbGF0dGVuZWQuc2lnbihrZXksIG9wdGlvbnMpO1xuICAgICAgICBpZiAoandzLnBheWxvYWQgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcigndXNlIHRoZSBmbGF0dGVuZWQgbW9kdWxlIGZvciBjcmVhdGluZyBKV1Mgd2l0aCBiNjQ6IGZhbHNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGAke2p3cy5wcm90ZWN0ZWR9LiR7andzLnBheWxvYWR9LiR7andzLnNpZ25hdHVyZX1gO1xuICAgIH1cbn1cbiIsImltcG9ydCB7IEZsYXR0ZW5lZFNpZ24gfSBmcm9tICcuLi9mbGF0dGVuZWQvc2lnbi5qcyc7XG5pbXBvcnQgeyBKV1NJbnZhbGlkIH0gZnJvbSAnLi4vLi4vdXRpbC9lcnJvcnMuanMnO1xuY2xhc3MgSW5kaXZpZHVhbFNpZ25hdHVyZSB7XG4gICAgY29uc3RydWN0b3Ioc2lnLCBrZXksIG9wdGlvbnMpIHtcbiAgICAgICAgdGhpcy5wYXJlbnQgPSBzaWc7XG4gICAgICAgIHRoaXMua2V5ID0ga2V5O1xuICAgICAgICB0aGlzLm9wdGlvbnMgPSBvcHRpb25zO1xuICAgIH1cbiAgICBzZXRQcm90ZWN0ZWRIZWFkZXIocHJvdGVjdGVkSGVhZGVyKSB7XG4gICAgICAgIGlmICh0aGlzLnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0UHJvdGVjdGVkSGVhZGVyIGNhbiBvbmx5IGJlIGNhbGxlZCBvbmNlJyk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5wcm90ZWN0ZWRIZWFkZXIgPSBwcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBzZXRVbnByb3RlY3RlZEhlYWRlcih1bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICBpZiAodGhpcy51bnByb3RlY3RlZEhlYWRlcikge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFR5cGVFcnJvcignc2V0VW5wcm90ZWN0ZWRIZWFkZXIgY2FuIG9ubHkgYmUgY2FsbGVkIG9uY2UnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLnVucHJvdGVjdGVkSGVhZGVyID0gdW5wcm90ZWN0ZWRIZWFkZXI7XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBhZGRTaWduYXR1cmUoLi4uYXJncykge1xuICAgICAgICByZXR1cm4gdGhpcy5wYXJlbnQuYWRkU2lnbmF0dXJlKC4uLmFyZ3MpO1xuICAgIH1cbiAgICBzaWduKC4uLmFyZ3MpIHtcbiAgICAgICAgcmV0dXJuIHRoaXMucGFyZW50LnNpZ24oLi4uYXJncyk7XG4gICAgfVxuICAgIGRvbmUoKSB7XG4gICAgICAgIHJldHVybiB0aGlzLnBhcmVudDtcbiAgICB9XG59XG5leHBvcnQgY2xhc3MgR2VuZXJhbFNpZ24ge1xuICAgIGNvbnN0cnVjdG9yKHBheWxvYWQpIHtcbiAgICAgICAgdGhpcy5fc2lnbmF0dXJlcyA9IFtdO1xuICAgICAgICB0aGlzLl9wYXlsb2FkID0gcGF5bG9hZDtcbiAgICB9XG4gICAgYWRkU2lnbmF0dXJlKGtleSwgb3B0aW9ucykge1xuICAgICAgICBjb25zdCBzaWduYXR1cmUgPSBuZXcgSW5kaXZpZHVhbFNpZ25hdHVyZSh0aGlzLCBrZXksIG9wdGlvbnMpO1xuICAgICAgICB0aGlzLl9zaWduYXR1cmVzLnB1c2goc2lnbmF0dXJlKTtcbiAgICAgICAgcmV0dXJuIHNpZ25hdHVyZTtcbiAgICB9XG4gICAgYXN5bmMgc2lnbigpIHtcbiAgICAgICAgaWYgKCF0aGlzLl9zaWduYXR1cmVzLmxlbmd0aCkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ2F0IGxlYXN0IG9uZSBzaWduYXR1cmUgbXVzdCBiZSBhZGRlZCcpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IGp3cyA9IHtcbiAgICAgICAgICAgIHNpZ25hdHVyZXM6IFtdLFxuICAgICAgICAgICAgcGF5bG9hZDogJycsXG4gICAgICAgIH07XG4gICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgdGhpcy5fc2lnbmF0dXJlcy5sZW5ndGg7IGkrKykge1xuICAgICAgICAgICAgY29uc3Qgc2lnbmF0dXJlID0gdGhpcy5fc2lnbmF0dXJlc1tpXTtcbiAgICAgICAgICAgIGNvbnN0IGZsYXR0ZW5lZCA9IG5ldyBGbGF0dGVuZWRTaWduKHRoaXMuX3BheWxvYWQpO1xuICAgICAgICAgICAgZmxhdHRlbmVkLnNldFByb3RlY3RlZEhlYWRlcihzaWduYXR1cmUucHJvdGVjdGVkSGVhZGVyKTtcbiAgICAgICAgICAgIGZsYXR0ZW5lZC5zZXRVbnByb3RlY3RlZEhlYWRlcihzaWduYXR1cmUudW5wcm90ZWN0ZWRIZWFkZXIpO1xuICAgICAgICAgICAgY29uc3QgeyBwYXlsb2FkLCAuLi5yZXN0IH0gPSBhd2FpdCBmbGF0dGVuZWQuc2lnbihzaWduYXR1cmUua2V5LCBzaWduYXR1cmUub3B0aW9ucyk7XG4gICAgICAgICAgICBpZiAoaSA9PT0gMCkge1xuICAgICAgICAgICAgICAgIGp3cy5wYXlsb2FkID0gcGF5bG9hZDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGVsc2UgaWYgKGp3cy5wYXlsb2FkICE9PSBwYXlsb2FkKSB7XG4gICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpXU0ludmFsaWQoJ2luY29uc2lzdGVudCB1c2Ugb2YgSldTIFVuZW5jb2RlZCBQYXlsb2FkIChSRkM3Nzk3KScpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgandzLnNpZ25hdHVyZXMucHVzaChyZXN0KTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gandzO1xuICAgIH1cbn1cbiIsImltcG9ydCAqIGFzIGJhc2U2NHVybCBmcm9tICcuLi9ydW50aW1lL2Jhc2U2NHVybC5qcyc7XG5leHBvcnQgY29uc3QgZW5jb2RlID0gYmFzZTY0dXJsLmVuY29kZTtcbmV4cG9ydCBjb25zdCBkZWNvZGUgPSBiYXNlNjR1cmwuZGVjb2RlO1xuIiwiaW1wb3J0IHsgZGVjb2RlIGFzIGJhc2U2NHVybCB9IGZyb20gJy4vYmFzZTY0dXJsLmpzJztcbmltcG9ydCB7IGRlY29kZXIgfSBmcm9tICcuLi9saWIvYnVmZmVyX3V0aWxzLmpzJztcbmltcG9ydCBpc09iamVjdCBmcm9tICcuLi9saWIvaXNfb2JqZWN0LmpzJztcbmV4cG9ydCBmdW5jdGlvbiBkZWNvZGVQcm90ZWN0ZWRIZWFkZXIodG9rZW4pIHtcbiAgICBsZXQgcHJvdGVjdGVkQjY0dTtcbiAgICBpZiAodHlwZW9mIHRva2VuID09PSAnc3RyaW5nJykge1xuICAgICAgICBjb25zdCBwYXJ0cyA9IHRva2VuLnNwbGl0KCcuJyk7XG4gICAgICAgIGlmIChwYXJ0cy5sZW5ndGggPT09IDMgfHwgcGFydHMubGVuZ3RoID09PSA1KSB7XG4gICAgICAgICAgICA7XG4gICAgICAgICAgICBbcHJvdGVjdGVkQjY0dV0gPSBwYXJ0cztcbiAgICAgICAgfVxuICAgIH1cbiAgICBlbHNlIGlmICh0eXBlb2YgdG9rZW4gPT09ICdvYmplY3QnICYmIHRva2VuKSB7XG4gICAgICAgIGlmICgncHJvdGVjdGVkJyBpbiB0b2tlbikge1xuICAgICAgICAgICAgcHJvdGVjdGVkQjY0dSA9IHRva2VuLnByb3RlY3RlZDtcbiAgICAgICAgfVxuICAgICAgICBlbHNlIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ1Rva2VuIGRvZXMgbm90IGNvbnRhaW4gYSBQcm90ZWN0ZWQgSGVhZGVyJyk7XG4gICAgICAgIH1cbiAgICB9XG4gICAgdHJ5IHtcbiAgICAgICAgaWYgKHR5cGVvZiBwcm90ZWN0ZWRCNjR1ICE9PSAnc3RyaW5nJyB8fCAhcHJvdGVjdGVkQjY0dSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgcmVzdWx0ID0gSlNPTi5wYXJzZShkZWNvZGVyLmRlY29kZShiYXNlNjR1cmwocHJvdGVjdGVkQjY0dSkpKTtcbiAgICAgICAgaWYgKCFpc09iamVjdChyZXN1bHQpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgIH1cbiAgICBjYXRjaCB7XG4gICAgICAgIHRocm93IG5ldyBUeXBlRXJyb3IoJ0ludmFsaWQgVG9rZW4gb3IgUHJvdGVjdGVkIEhlYWRlciBmb3JtYXR0aW5nJyk7XG4gICAgfVxufVxuIiwiaW1wb3J0IGNyeXB0byBmcm9tICcuL3dlYmNyeXB0by5qcyc7XG5pbXBvcnQgeyBKT1NFTm90U3VwcG9ydGVkIH0gZnJvbSAnLi4vdXRpbC9lcnJvcnMuanMnO1xuaW1wb3J0IHJhbmRvbSBmcm9tICcuL3JhbmRvbS5qcyc7XG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZ2VuZXJhdGVTZWNyZXQoYWxnLCBvcHRpb25zKSB7XG4gICAgbGV0IGxlbmd0aDtcbiAgICBsZXQgYWxnb3JpdGhtO1xuICAgIGxldCBrZXlVc2FnZXM7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnSFMyNTYnOlxuICAgICAgICBjYXNlICdIUzM4NCc6XG4gICAgICAgIGNhc2UgJ0hTNTEyJzpcbiAgICAgICAgICAgIGxlbmd0aCA9IHBhcnNlSW50KGFsZy5zbGljZSgtMyksIDEwKTtcbiAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0hNQUMnLCBoYXNoOiBgU0hBLSR7bGVuZ3RofWAsIGxlbmd0aCB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWydzaWduJywgJ3ZlcmlmeSddO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ0ExMjhDQkMtSFMyNTYnOlxuICAgICAgICBjYXNlICdBMTkyQ0JDLUhTMzg0JzpcbiAgICAgICAgY2FzZSAnQTI1NkNCQy1IUzUxMic6XG4gICAgICAgICAgICBsZW5ndGggPSBwYXJzZUludChhbGcuc2xpY2UoLTMpLCAxMCk7XG4gICAgICAgICAgICByZXR1cm4gcmFuZG9tKG5ldyBVaW50OEFycmF5KGxlbmd0aCA+PiAzKSk7XG4gICAgICAgIGNhc2UgJ0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJLVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZLVyc6XG4gICAgICAgICAgICBsZW5ndGggPSBwYXJzZUludChhbGcuc2xpY2UoMSwgNCksIDEwKTtcbiAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0FFUy1LVycsIGxlbmd0aCB9O1xuICAgICAgICAgICAga2V5VXNhZ2VzID0gWyd3cmFwS2V5JywgJ3Vud3JhcEtleSddO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ0ExMjhHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0ExOTJHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0EyNTZHQ01LVyc6XG4gICAgICAgIGNhc2UgJ0ExMjhHQ00nOlxuICAgICAgICBjYXNlICdBMTkyR0NNJzpcbiAgICAgICAgY2FzZSAnQTI1NkdDTSc6XG4gICAgICAgICAgICBsZW5ndGggPSBwYXJzZUludChhbGcuc2xpY2UoMSwgNCksIDEwKTtcbiAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogJ0FFUy1HQ00nLCBsZW5ndGggfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnZW5jcnlwdCcsICdkZWNyeXB0J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIEpXSyBcImFsZ1wiIChBbGdvcml0aG0pIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgIH1cbiAgICByZXR1cm4gY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleShhbGdvcml0aG0sIG9wdGlvbnM/LmV4dHJhY3RhYmxlID8/IGZhbHNlLCBrZXlVc2FnZXMpO1xufVxuZnVuY3Rpb24gZ2V0TW9kdWx1c0xlbmd0aE9wdGlvbihvcHRpb25zKSB7XG4gICAgY29uc3QgbW9kdWx1c0xlbmd0aCA9IG9wdGlvbnM/Lm1vZHVsdXNMZW5ndGggPz8gMjA0ODtcbiAgICBpZiAodHlwZW9mIG1vZHVsdXNMZW5ndGggIT09ICdudW1iZXInIHx8IG1vZHVsdXNMZW5ndGggPCAyMDQ4KSB7XG4gICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIG1vZHVsdXNMZW5ndGggb3B0aW9uIHByb3ZpZGVkLCAyMDQ4IGJpdHMgb3IgbGFyZ2VyIGtleXMgbXVzdCBiZSB1c2VkJyk7XG4gICAgfVxuICAgIHJldHVybiBtb2R1bHVzTGVuZ3RoO1xufVxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdlbmVyYXRlS2V5UGFpcihhbGcsIG9wdGlvbnMpIHtcbiAgICBsZXQgYWxnb3JpdGhtO1xuICAgIGxldCBrZXlVc2FnZXM7XG4gICAgc3dpdGNoIChhbGcpIHtcbiAgICAgICAgY2FzZSAnUFMyNTYnOlxuICAgICAgICBjYXNlICdQUzM4NCc6XG4gICAgICAgIGNhc2UgJ1BTNTEyJzpcbiAgICAgICAgICAgIGFsZ29yaXRobSA9IHtcbiAgICAgICAgICAgICAgICBuYW1lOiAnUlNBLVBTUycsXG4gICAgICAgICAgICAgICAgaGFzaDogYFNIQS0ke2FsZy5zbGljZSgtMyl9YCxcbiAgICAgICAgICAgICAgICBwdWJsaWNFeHBvbmVudDogbmV3IFVpbnQ4QXJyYXkoWzB4MDEsIDB4MDAsIDB4MDFdKSxcbiAgICAgICAgICAgICAgICBtb2R1bHVzTGVuZ3RoOiBnZXRNb2R1bHVzTGVuZ3RoT3B0aW9uKG9wdGlvbnMpLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnc2lnbicsICd2ZXJpZnknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdSUzI1Nic6XG4gICAgICAgIGNhc2UgJ1JTMzg0JzpcbiAgICAgICAgY2FzZSAnUlM1MTInOlxuICAgICAgICAgICAgYWxnb3JpdGhtID0ge1xuICAgICAgICAgICAgICAgIG5hbWU6ICdSU0FTU0EtUEtDUzEtdjFfNScsXG4gICAgICAgICAgICAgICAgaGFzaDogYFNIQS0ke2FsZy5zbGljZSgtMyl9YCxcbiAgICAgICAgICAgICAgICBwdWJsaWNFeHBvbmVudDogbmV3IFVpbnQ4QXJyYXkoWzB4MDEsIDB4MDAsIDB4MDFdKSxcbiAgICAgICAgICAgICAgICBtb2R1bHVzTGVuZ3RoOiBnZXRNb2R1bHVzTGVuZ3RoT3B0aW9uKG9wdGlvbnMpLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnc2lnbicsICd2ZXJpZnknXTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdSU0EtT0FFUCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTI1Nic6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTM4NCc6XG4gICAgICAgIGNhc2UgJ1JTQS1PQUVQLTUxMic6XG4gICAgICAgICAgICBhbGdvcml0aG0gPSB7XG4gICAgICAgICAgICAgICAgbmFtZTogJ1JTQS1PQUVQJyxcbiAgICAgICAgICAgICAgICBoYXNoOiBgU0hBLSR7cGFyc2VJbnQoYWxnLnNsaWNlKC0zKSwgMTApIHx8IDF9YCxcbiAgICAgICAgICAgICAgICBwdWJsaWNFeHBvbmVudDogbmV3IFVpbnQ4QXJyYXkoWzB4MDEsIDB4MDAsIDB4MDFdKSxcbiAgICAgICAgICAgICAgICBtb2R1bHVzTGVuZ3RoOiBnZXRNb2R1bHVzTGVuZ3RoT3B0aW9uKG9wdGlvbnMpLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIGtleVVzYWdlcyA9IFsnZGVjcnlwdCcsICd1bndyYXBLZXknLCAnZW5jcnlwdCcsICd3cmFwS2V5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnRVMyNTYnOlxuICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNEU0EnLCBuYW1lZEN1cnZlOiAnUC0yNTYnIH07XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3NpZ24nLCAndmVyaWZ5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnRVMzODQnOlxuICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNEU0EnLCBuYW1lZEN1cnZlOiAnUC0zODQnIH07XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3NpZ24nLCAndmVyaWZ5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnRVM1MTInOlxuICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNEU0EnLCBuYW1lZEN1cnZlOiAnUC01MjEnIH07XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3NpZ24nLCAndmVyaWZ5J107XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnRWREU0EnOiB7XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ3NpZ24nLCAndmVyaWZ5J107XG4gICAgICAgICAgICBjb25zdCBjcnYgPSBvcHRpb25zPy5jcnYgPz8gJ0VkMjU1MTknO1xuICAgICAgICAgICAgc3dpdGNoIChjcnYpIHtcbiAgICAgICAgICAgICAgICBjYXNlICdFZDI1NTE5JzpcbiAgICAgICAgICAgICAgICBjYXNlICdFZDQ0OCc6XG4gICAgICAgICAgICAgICAgICAgIGFsZ29yaXRobSA9IHsgbmFtZTogY3J2IH07XG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIGNydiBvcHRpb24gcHJvdmlkZWQnKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICAgIGNhc2UgJ0VDREgtRVMnOlxuICAgICAgICBjYXNlICdFQ0RILUVTK0ExMjhLVyc6XG4gICAgICAgIGNhc2UgJ0VDREgtRVMrQTE5MktXJzpcbiAgICAgICAgY2FzZSAnRUNESC1FUytBMjU2S1cnOiB7XG4gICAgICAgICAgICBrZXlVc2FnZXMgPSBbJ2Rlcml2ZUtleScsICdkZXJpdmVCaXRzJ107XG4gICAgICAgICAgICBjb25zdCBjcnYgPSBvcHRpb25zPy5jcnYgPz8gJ1AtMjU2JztcbiAgICAgICAgICAgIHN3aXRjaCAoY3J2KSB7XG4gICAgICAgICAgICAgICAgY2FzZSAnUC0yNTYnOlxuICAgICAgICAgICAgICAgIGNhc2UgJ1AtMzg0JzpcbiAgICAgICAgICAgICAgICBjYXNlICdQLTUyMSc6IHtcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiAnRUNESCcsIG5hbWVkQ3VydmU6IGNydiB9O1xuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgY2FzZSAnWDI1NTE5JzpcbiAgICAgICAgICAgICAgICBjYXNlICdYNDQ4JzpcbiAgICAgICAgICAgICAgICAgICAgYWxnb3JpdGhtID0geyBuYW1lOiBjcnYgfTtcbiAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEpPU0VOb3RTdXBwb3J0ZWQoJ0ludmFsaWQgb3IgdW5zdXBwb3J0ZWQgY3J2IG9wdGlvbiBwcm92aWRlZCwgc3VwcG9ydGVkIHZhbHVlcyBhcmUgUC0yNTYsIFAtMzg0LCBQLTUyMSwgWDI1NTE5LCBhbmQgWDQ0OCcpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgIHRocm93IG5ldyBKT1NFTm90U3VwcG9ydGVkKCdJbnZhbGlkIG9yIHVuc3VwcG9ydGVkIEpXSyBcImFsZ1wiIChBbGdvcml0aG0pIFBhcmFtZXRlciB2YWx1ZScpO1xuICAgIH1cbiAgICByZXR1cm4gKGNyeXB0by5zdWJ0bGUuZ2VuZXJhdGVLZXkoYWxnb3JpdGhtLCBvcHRpb25zPy5leHRyYWN0YWJsZSA/PyBmYWxzZSwga2V5VXNhZ2VzKSk7XG59XG4iLCJpbXBvcnQgeyBnZW5lcmF0ZUtleVBhaXIgYXMgZ2VuZXJhdGUgfSBmcm9tICcuLi9ydW50aW1lL2dlbmVyYXRlLmpzJztcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZUtleVBhaXIoYWxnLCBvcHRpb25zKSB7XG4gICAgcmV0dXJuIGdlbmVyYXRlKGFsZywgb3B0aW9ucyk7XG59XG4iLCJpbXBvcnQgeyBnZW5lcmF0ZVNlY3JldCBhcyBnZW5lcmF0ZSB9IGZyb20gJy4uL3J1bnRpbWUvZ2VuZXJhdGUuanMnO1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdlbmVyYXRlU2VjcmV0KGFsZywgb3B0aW9ucykge1xuICAgIHJldHVybiBnZW5lcmF0ZShhbGcsIG9wdGlvbnMpO1xufVxuIiwiLy8gT25lIGNvbnNpc3RlbnQgYWxnb3JpdGhtIGZvciBlYWNoIGZhbWlseS5cbi8vIGh0dHBzOi8vZGF0YXRyYWNrZXIuaWV0Zi5vcmcvZG9jL2h0bWwvcmZjNzUxOFxuXG5leHBvcnQgY29uc3Qgc2lnbmluZ05hbWUgPSAnRUNEU0EnO1xuZXhwb3J0IGNvbnN0IHNpZ25pbmdDdXJ2ZSA9ICdQLTM4NCc7XG5leHBvcnQgY29uc3Qgc2lnbmluZ0FsZ29yaXRobSA9ICdFUzM4NCc7XG5cbmV4cG9ydCBjb25zdCBlbmNyeXB0aW5nTmFtZSA9ICdSU0EtT0FFUCc7XG5leHBvcnQgY29uc3QgaGFzaExlbmd0aCA9IDI1NjtcbmV4cG9ydCBjb25zdCBoYXNoTmFtZSA9ICdTSEEtMjU2JztcbmV4cG9ydCBjb25zdCBtb2R1bHVzTGVuZ3RoID0gNDA5NjsgLy8gcGFudmEgSk9TRSBsaWJyYXJ5IGRlZmF1bHQgaXMgMjA0OFxuZXhwb3J0IGNvbnN0IGVuY3J5cHRpbmdBbGdvcml0aG0gPSAnUlNBLU9BRVAtMjU2JztcblxuZXhwb3J0IGNvbnN0IHN5bW1ldHJpY05hbWUgPSAnQUVTLUdDTSc7XG5leHBvcnQgY29uc3Qgc3ltbWV0cmljQWxnb3JpdGhtID0gJ0EyNTZHQ00nO1xuZXhwb3J0IGNvbnN0IHN5bW1ldHJpY1dyYXAgPSAnQTI1NkdDTUtXJztcbmV4cG9ydCBjb25zdCBzZWNyZXRBbGdvcml0aG0gPSAnUEJFUzItSFM1MTIrQTI1NktXJztcblxuZXhwb3J0IGNvbnN0IGV4dHJhY3RhYmxlID0gdHJ1ZTsgIC8vIGFsd2F5cyB3cmFwcGVkXG5cbiIsImltcG9ydCB7ZXh0cmFjdGFibGUsIHNpZ25pbmdOYW1lLCBzaWduaW5nQ3VydmUsIHN5bW1ldHJpY05hbWUsIGhhc2hMZW5ndGh9IGZyb20gXCIuL2FsZ29yaXRobXMubWpzXCI7XG5cbmV4cG9ydCBmdW5jdGlvbiBkaWdlc3QoaGFzaE5hbWUsIGJ1ZmZlcikge1xuICByZXR1cm4gY3J5cHRvLnN1YnRsZS5kaWdlc3QoaGFzaE5hbWUsIGJ1ZmZlcik7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBleHBvcnRSYXdLZXkoa2V5KSB7XG4gIHJldHVybiBjcnlwdG8uc3VidGxlLmV4cG9ydEtleSgncmF3Jywga2V5KTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGltcG9ydFJhd0tleShhcnJheUJ1ZmZlcikge1xuICBjb25zdCBhbGdvcml0aG0gPSB7bmFtZTogc2lnbmluZ05hbWUsIG5hbWVkQ3VydmU6IHNpZ25pbmdDdXJ2ZX07XG4gIHJldHVybiBjcnlwdG8uc3VidGxlLmltcG9ydEtleSgncmF3JywgYXJyYXlCdWZmZXIsIGFsZ29yaXRobSwgZXh0cmFjdGFibGUsIFsndmVyaWZ5J10pO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gaW1wb3J0U2VjcmV0KGJ5dGVBcnJheSkge1xuICBjb25zdCBhbGdvcml0aG0gPSB7bmFtZTogc3ltbWV0cmljTmFtZSwgbGVuZ3RoOiBoYXNoTGVuZ3RofTtcbiAgcmV0dXJuIGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCdyYXcnLCBieXRlQXJyYXksIGFsZ29yaXRobSwgdHJ1ZSwgWydlbmNyeXB0JywgJ2RlY3J5cHQnXSlcbn1cbiIsImltcG9ydCAqIGFzIEpPU0UgZnJvbSBcImpvc2VcIjtcbmltcG9ydCB7ZGlnZXN0LCBleHBvcnRSYXdLZXksIGltcG9ydFJhd0tleSwgaW1wb3J0U2VjcmV0fSBmcm9tIFwiI3Jhd1wiO1xuaW1wb3J0IHtleHRyYWN0YWJsZSwgc2lnbmluZ05hbWUsIHNpZ25pbmdDdXJ2ZSwgc2lnbmluZ0FsZ29yaXRobSwgZW5jcnlwdGluZ05hbWUsIGhhc2hMZW5ndGgsIGhhc2hOYW1lLCBtb2R1bHVzTGVuZ3RoLCBlbmNyeXB0aW5nQWxnb3JpdGhtLCBzeW1tZXRyaWNOYW1lLCBzeW1tZXRyaWNBbGdvcml0aG19IGZyb20gXCIuL2FsZ29yaXRobXMubWpzXCI7XG5cbmNvbnN0IEtyeXB0byA9IHtcbiAgLy8gQW4gaW5oZXJpdGFibGUgc2luZ2xldG9uIGZvciBjb21wYWN0IEpPU0Ugb3BlcmF0aW9ucy5cbiAgLy8gU2VlIGh0dHBzOi8va2lscm95LWNvZGUuZ2l0aHViLmlvL2Rpc3RyaWJ1dGVkLXNlY3VyaXR5L2RvY3MvaW1wbGVtZW50YXRpb24uaHRtbCN3cmFwcGluZy1zdWJ0bGVrcnlwdG9cbiAgZGVjb2RlUHJvdGVjdGVkSGVhZGVyOiBKT1NFLmRlY29kZVByb3RlY3RlZEhlYWRlcixcbiAgaXNFbXB0eUpXU1BheWxvYWQoY29tcGFjdEpXUykgeyAvLyBhcmcgaXMgYSBzdHJpbmdcbiAgICByZXR1cm4gIWNvbXBhY3RKV1Muc3BsaXQoJy4nKVsxXTtcbiAgfSxcblxuICAvLyBUaGUgY3R5IGNhbiBiZSBzcGVjaWZpZWQgaW4gZW5jcnlwdC9zaWduLCBidXQgZGVmYXVsdHMgdG8gYSBnb29kIGd1ZXNzLlxuICAvLyBUaGUgY3R5IGNhbiBiZSBzcGVjaWZpZWQgaW4gZGVjcnlwdC92ZXJpZnksIGJ1dCBkZWZhdWx0cyB0byB3aGF0IGlzIHNwZWNpZmllZCBpbiB0aGUgcHJvdGVjdGVkIGhlYWRlci5cbiAgaW5wdXRCdWZmZXIoZGF0YSwgaGVhZGVyKSB7IC8vIEFuc3dlcnMgYSBidWZmZXIgdmlldyBvZiBkYXRhIGFuZCwgaWYgbmVjZXNzYXJ5IHRvIGNvbnZlcnQsIGJhc2hlcyBjdHkgb2YgaGVhZGVyLlxuICAgIGlmIChBcnJheUJ1ZmZlci5pc1ZpZXcoZGF0YSkgJiYgIWhlYWRlci5jdHkpIHJldHVybiBkYXRhO1xuICAgIGxldCBnaXZlbkN0eSA9IGhlYWRlci5jdHkgfHwgJyc7XG4gICAgaWYgKGdpdmVuQ3R5LmluY2x1ZGVzKCd0ZXh0JykgfHwgKCdzdHJpbmcnID09PSB0eXBlb2YgZGF0YSkpIHtcbiAgICAgIGhlYWRlci5jdHkgPSBnaXZlbkN0eSB8fCAndGV4dC9wbGFpbic7XG4gICAgfSBlbHNlIHtcbiAgICAgIGhlYWRlci5jdHkgPSBnaXZlbkN0eSB8fCAnanNvbic7IC8vIEpXUyByZWNvbW1lbmRzIGxlYXZpbmcgb2ZmIHRoZSBsZWFkaW5nICdhcHBsaWNhdGlvbi8nLlxuICAgICAgZGF0YSA9IEpTT04uc3RyaW5naWZ5KGRhdGEpOyAvLyBOb3RlIHRoYXQgbmV3IFN0cmluZyhcInNvbWV0aGluZ1wiKSB3aWxsIHBhc3MgdGhpcyB3YXkuXG4gICAgfVxuICAgIHJldHVybiBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUoZGF0YSk7XG4gIH0sXG4gIHJlY292ZXJEYXRhRnJvbUNvbnRlbnRUeXBlKHJlc3VsdCwge2N0eSA9IHJlc3VsdD8ucHJvdGVjdGVkSGVhZGVyPy5jdHl9ID0ge30pIHtcbiAgICAvLyBFeGFtaW5lcyByZXN1bHQ/LnByb3RlY3RlZEhlYWRlciBhbmQgYmFzaGVzIGluIHJlc3VsdC50ZXh0IG9yIHJlc3VsdC5qc29uIGlmIGFwcHJvcHJpYXRlLCByZXR1cm5pbmcgcmVzdWx0LlxuICAgIGlmIChyZXN1bHQgJiYgIU9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChyZXN1bHQsICdwYXlsb2FkJykpIHJlc3VsdC5wYXlsb2FkID0gcmVzdWx0LnBsYWludGV4dDsgIC8vIGJlY2F1c2UgSk9TRSB1c2VzIHBsYWludGV4dCBmb3IgZGVjcnlwdCBhbmQgcGF5bG9hZCBmb3Igc2lnbi5cbiAgICBpZiAoIWN0eSB8fCAhcmVzdWx0Py5wYXlsb2FkKSByZXR1cm4gcmVzdWx0OyAvLyBlaXRoZXIgbm8gY3R5IG9yIG5vIHJlc3VsdFxuICAgIHJlc3VsdC50ZXh0ID0gbmV3IFRleHREZWNvZGVyKCkuZGVjb2RlKHJlc3VsdC5wYXlsb2FkKTtcbiAgICBpZiAoY3R5LmluY2x1ZGVzKCdqc29uJykpIHJlc3VsdC5qc29uID0gSlNPTi5wYXJzZShyZXN1bHQudGV4dCk7XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfSxcblxuICAvLyBTaWduL1ZlcmlmeVxuICBnZW5lcmF0ZVNpZ25pbmdLZXkoKSB7IC8vIFByb21pc2Uge3ByaXZhdGVLZXksIHB1YmxpY0tleX0gaW4gb3VyIHN0YW5kYXJkIHNpZ25pbmcgYWxnb3JpdGhtLlxuICAgIHJldHVybiBKT1NFLmdlbmVyYXRlS2V5UGFpcihzaWduaW5nQWxnb3JpdGhtLCB7ZXh0cmFjdGFibGV9KTtcbiAgfSxcbiAgYXN5bmMgc2lnbihwcml2YXRlS2V5LCBtZXNzYWdlLCBoZWFkZXJzID0ge30pIHsgLy8gUHJvbWlzZSBhIGNvbXBhY3QgSldTIHN0cmluZy4gQWNjZXB0cyBoZWFkZXJzIHRvIGJlIHByb3RlY3RlZC5cbiAgICBsZXQgaGVhZGVyID0ge2FsZzogc2lnbmluZ0FsZ29yaXRobSwgLi4uaGVhZGVyc30sXG4gICAgICAgIGlucHV0QnVmZmVyID0gdGhpcy5pbnB1dEJ1ZmZlcihtZXNzYWdlLCBoZWFkZXIpO1xuICAgIHJldHVybiBuZXcgSk9TRS5Db21wYWN0U2lnbihpbnB1dEJ1ZmZlcikuc2V0UHJvdGVjdGVkSGVhZGVyKGhlYWRlcikuc2lnbihwcml2YXRlS2V5KTtcbiAgfSxcbiAgYXN5bmMgdmVyaWZ5KHB1YmxpY0tleSwgc2lnbmF0dXJlLCBvcHRpb25zKSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259LCB3aGVyZSB0ZXh0IGFuZCBqc29uIGFyZSBvbmx5IGRlZmluZWQgd2hlbiBhcHByb3ByaWF0ZS5cbiAgICBsZXQgcmVzdWx0ID0gYXdhaXQgSk9TRS5jb21wYWN0VmVyaWZ5KHNpZ25hdHVyZSwgcHVibGljS2V5KS5jYXRjaCgoKSA9PiB1bmRlZmluZWQpO1xuICAgIHJldHVybiB0aGlzLnJlY292ZXJEYXRhRnJvbUNvbnRlbnRUeXBlKHJlc3VsdCwgb3B0aW9ucyk7XG4gIH0sXG5cbiAgLy8gRW5jcnlwdC9EZWNyeXB0XG4gIGdlbmVyYXRlRW5jcnlwdGluZ0tleSgpIHsgLy8gUHJvbWlzZSB7cHJpdmF0ZUtleSwgcHVibGljS2V5fSBpbiBvdXIgc3RhbmRhcmQgZW5jcnlwdGlvbiBhbGdvcml0aG0uXG4gICAgcmV0dXJuIEpPU0UuZ2VuZXJhdGVLZXlQYWlyKGVuY3J5cHRpbmdBbGdvcml0aG0sIHtleHRyYWN0YWJsZSwgbW9kdWx1c0xlbmd0aH0pO1xuICB9LFxuICBhc3luYyBlbmNyeXB0KGtleSwgbWVzc2FnZSwgaGVhZGVycyA9IHt9KSB7IC8vIFByb21pc2UgYSBjb21wYWN0IEpXRSBzdHJpbmcuIEFjY2VwdHMgaGVhZGVycyB0byBiZSBwcm90ZWN0ZWQuXG4gICAgbGV0IGFsZyA9IHRoaXMuaXNTeW1tZXRyaWMoa2V5KSA/ICdkaXInIDogZW5jcnlwdGluZ0FsZ29yaXRobSxcbiAgICAgICAgaGVhZGVyID0ge2FsZywgZW5jOiBzeW1tZXRyaWNBbGdvcml0aG0sIC4uLmhlYWRlcnN9LFxuICAgICAgICBpbnB1dEJ1ZmZlciA9IHRoaXMuaW5wdXRCdWZmZXIobWVzc2FnZSwgaGVhZGVyKSxcbiAgICAgICAgc2VjcmV0ID0gdGhpcy5rZXlTZWNyZXQoa2V5KTtcbiAgICByZXR1cm4gbmV3IEpPU0UuQ29tcGFjdEVuY3J5cHQoaW5wdXRCdWZmZXIpLnNldFByb3RlY3RlZEhlYWRlcihoZWFkZXIpLmVuY3J5cHQoc2VjcmV0KTtcbiAgfSxcbiAgYXN5bmMgZGVjcnlwdChrZXksIGVuY3J5cHRlZCwgb3B0aW9ucyA9IHt9KSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259LCB3aGVyZSB0ZXh0IGFuZCBqc29uIGFyZSBvbmx5IGRlZmluZWQgd2hlbiBhcHByb3ByaWF0ZS5cbiAgICBsZXQgc2VjcmV0ID0gdGhpcy5rZXlTZWNyZXQoa2V5KSxcbiAgICAgICAgcmVzdWx0ID0gYXdhaXQgSk9TRS5jb21wYWN0RGVjcnlwdChlbmNyeXB0ZWQsIHNlY3JldCk7XG4gICAgdGhpcy5yZWNvdmVyRGF0YUZyb21Db250ZW50VHlwZShyZXN1bHQsIG9wdGlvbnMpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH0sXG4gIGFzeW5jIGdlbmVyYXRlU2VjcmV0S2V5KHRleHQpIHsgLy8gSk9TRSB1c2VzIGEgZGlnZXN0IGZvciBQQkVTLCBidXQgbWFrZSBpdCByZWNvZ25pemFibGUgYXMgYSB7dHlwZTogJ3NlY3JldCd9IGtleS5cbiAgICBsZXQgYnVmZmVyID0gbmV3IFRleHRFbmNvZGVyKCkuZW5jb2RlKHRleHQpLFxuICAgICAgICBoYXNoID0gYXdhaXQgZGlnZXN0KGhhc2hOYW1lLCBidWZmZXIpO1xuICAgIHJldHVybiB7dHlwZTogJ3NlY3JldCcsIHRleHQ6IG5ldyBVaW50OEFycmF5KGhhc2gpfTtcbiAgfSxcbiAgZ2VuZXJhdGVTeW1tZXRyaWNLZXkodGV4dCkgeyAvLyBQcm9taXNlIGEga2V5IGZvciBzeW1tZXRyaWMgZW5jcnlwdGlvbi5cbiAgICBpZiAodGV4dCkgcmV0dXJuIHRoaXMuZ2VuZXJhdGVTZWNyZXRLZXkodGV4dCk7IC8vIFBCRVNcbiAgICByZXR1cm4gSk9TRS5nZW5lcmF0ZVNlY3JldChzeW1tZXRyaWNBbGdvcml0aG0sIHtleHRyYWN0YWJsZX0pOyAvLyBBRVNcbiAgfSxcbiAgaXNTeW1tZXRyaWMoa2V5KSB7IC8vIEVpdGhlciBBRVMgb3IgUEJFUywgYnV0IG5vdCBwdWJsaWNLZXkgb3IgcHJpdmF0ZUtleS5cbiAgICByZXR1cm4ga2V5LnR5cGUgPT09ICdzZWNyZXQnO1xuICB9LFxuICBrZXlTZWNyZXQoa2V5KSB7IC8vIFJldHVybiB3aGF0IGlzIGFjdHVhbGx5IHVzZWQgYXMgaW5wdXQgaW4gSk9TRSBsaWJyYXJ5LlxuICAgIGlmIChrZXkudGV4dCkgcmV0dXJuIGtleS50ZXh0O1xuICAgIHJldHVybiBrZXk7XG4gIH0sXG5cbiAgLy8gRXhwb3J0L0ltcG9ydFxuICBhc3luYyBleHBvcnRSYXcoa2V5KSB7IC8vIGJhc2U2NHVybCBmb3IgcHVibGljIHZlcmZpY2F0aW9uIGtleXNcbiAgICBsZXQgYXJyYXlCdWZmZXIgPSBhd2FpdCBleHBvcnRSYXdLZXkoa2V5KTtcbiAgICByZXR1cm4gSk9TRS5iYXNlNjR1cmwuZW5jb2RlKG5ldyBVaW50OEFycmF5KGFycmF5QnVmZmVyKSk7XG4gIH0sXG4gIGFzeW5jIGltcG9ydFJhdyhzdHJpbmcpIHsgLy8gUHJvbWlzZSB0aGUgdmVyaWZpY2F0aW9uIGtleSBmcm9tIGJhc2U2NHVybFxuICAgIGxldCBhcnJheUJ1ZmZlciA9IEpPU0UuYmFzZTY0dXJsLmRlY29kZShzdHJpbmcpO1xuICAgIHJldHVybiBpbXBvcnRSYXdLZXkoYXJyYXlCdWZmZXIpO1xuICB9LFxuICBhc3luYyBleHBvcnRKV0soa2V5KSB7IC8vIFByb21pc2UgSldLIG9iamVjdCwgd2l0aCBhbGcgaW5jbHVkZWQuXG4gICAgbGV0IGV4cG9ydGVkID0gYXdhaXQgSk9TRS5leHBvcnRKV0soa2V5KSxcbiAgICAgICAgYWxnID0ga2V5LmFsZ29yaXRobTsgLy8gSk9TRSBsaWJyYXJ5IGdpdmVzIGFsZ29yaXRobSwgYnV0IG5vdCBhbGcgdGhhdCBpcyBuZWVkZWQgZm9yIGltcG9ydC5cbiAgICBpZiAoYWxnKSB7IC8vIHN1YnRsZS5jcnlwdG8gdW5kZXJseWluZyBrZXlzXG4gICAgICBpZiAoYWxnLm5hbWUgPT09IHNpZ25pbmdOYW1lICYmIGFsZy5uYW1lZEN1cnZlID09PSBzaWduaW5nQ3VydmUpIGV4cG9ydGVkLmFsZyA9IHNpZ25pbmdBbGdvcml0aG07XG4gICAgICBlbHNlIGlmIChhbGcubmFtZSA9PT0gZW5jcnlwdGluZ05hbWUgJiYgYWxnLmhhc2gubmFtZSA9PT0gaGFzaE5hbWUpIGV4cG9ydGVkLmFsZyA9IGVuY3J5cHRpbmdBbGdvcml0aG07XG4gICAgICBlbHNlIGlmIChhbGcubmFtZSA9PT0gc3ltbWV0cmljTmFtZSAmJiBhbGcubGVuZ3RoID09PSBoYXNoTGVuZ3RoKSBleHBvcnRlZC5hbGcgPSBzeW1tZXRyaWNBbGdvcml0aG07XG4gICAgfSBlbHNlIHN3aXRjaCAoZXhwb3J0ZWQua3R5KSB7IC8vIEpPU0Ugb24gTm9kZUpTIHVzZWQgbm9kZTpjcnlwdG8ga2V5cywgd2hpY2ggZG8gbm90IGV4cG9zZSB0aGUgcHJlY2lzZSBhbGdvcml0aG1cbiAgICAgIGNhc2UgJ0VDJzogZXhwb3J0ZWQuYWxnID0gc2lnbmluZ0FsZ29yaXRobTsgYnJlYWs7XG4gICAgICBjYXNlICdSU0EnOiBleHBvcnRlZC5hbGcgPSBlbmNyeXB0aW5nQWxnb3JpdGhtOyBicmVhaztcbiAgICAgIGNhc2UgJ29jdCc6IGV4cG9ydGVkLmFsZyA9IHN5bW1ldHJpY0FsZ29yaXRobTsgYnJlYWs7XG4gICAgfVxuICAgIHJldHVybiBleHBvcnRlZDtcbiAgfSxcbiAgYXN5bmMgaW1wb3J0SldLKGp3aykgeyAvLyBQcm9taXNlIGEga2V5IG9iamVjdFxuICAgIGp3ayA9IHtleHQ6IHRydWUsIC4uLmp3a307IC8vIFdlIG5lZWQgdGhlIHJlc3VsdCB0byBiZSBiZSBhYmxlIHRvIGdlbmVyYXRlIGEgbmV3IEpXSyAoZS5nLiwgb24gY2hhbmdlTWVtYmVyc2hpcClcbiAgICBsZXQgaW1wb3J0ZWQgPSBhd2FpdCBKT1NFLmltcG9ydEpXSyhqd2spO1xuICAgIGlmIChpbXBvcnRlZCBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcbiAgICAgIC8vIFdlIGRlcGVuZCBhbiByZXR1cm5pbmcgYW4gYWN0dWFsIGtleSwgYnV0IHRoZSBKT1NFIGxpYnJhcnkgd2UgdXNlXG4gICAgICAvLyB3aWxsIGFib3ZlIHByb2R1Y2UgdGhlIHJhdyBVaW50OEFycmF5IGlmIHRoZSBqd2sgaXMgZnJvbSBhIHNlY3JldC5cbiAgICAgIGltcG9ydGVkID0gYXdhaXQgaW1wb3J0U2VjcmV0KGltcG9ydGVkKTtcbiAgICB9XG4gICAgcmV0dXJuIGltcG9ydGVkO1xuICB9LFxuXG4gIGFzeW5jIHdyYXBLZXkoa2V5LCB3cmFwcGluZ0tleSwgaGVhZGVycyA9IHt9KSB7IC8vIFByb21pc2UgYSBKV0UgZnJvbSB0aGUgcHVibGljIHdyYXBwaW5nS2V5XG4gICAgbGV0IGV4cG9ydGVkID0gYXdhaXQgdGhpcy5leHBvcnRKV0soa2V5KTtcbiAgICByZXR1cm4gdGhpcy5lbmNyeXB0KHdyYXBwaW5nS2V5LCBleHBvcnRlZCwgaGVhZGVycyk7XG4gIH0sXG4gIGFzeW5jIHVud3JhcEtleSh3cmFwcGVkS2V5LCB1bndyYXBwaW5nS2V5KSB7IC8vIFByb21pc2UgdGhlIGtleSB1bmxvY2tlZCBieSB0aGUgcHJpdmF0ZSB1bndyYXBwaW5nS2V5LlxuICAgIGxldCBkZWNyeXB0ZWQgPSBhd2FpdCB0aGlzLmRlY3J5cHQodW53cmFwcGluZ0tleSwgd3JhcHBlZEtleSk7XG4gICAgcmV0dXJuIHRoaXMuaW1wb3J0SldLKGRlY3J5cHRlZC5qc29uKTtcbiAgfVxufVxuXG5leHBvcnQgZGVmYXVsdCBLcnlwdG87XG4vKlxuU29tZSB1c2VmdWwgSk9TRSByZWNpcGVzIGZvciBwbGF5aW5nIGFyb3VuZC5cbnNrID0gYXdhaXQgSk9TRS5nZW5lcmF0ZUtleVBhaXIoJ0VTMzg0Jywge2V4dHJhY3RhYmxlOiB0cnVlfSlcbmp3dCA9IGF3YWl0IG5ldyBKT1NFLlNpZ25KV1QoKS5zZXRTdWJqZWN0KFwiZm9vXCIpLnNldFByb3RlY3RlZEhlYWRlcih7YWxnOidFUzM4NCd9KS5zaWduKHNrLnByaXZhdGVLZXkpXG5hd2FpdCBKT1NFLmp3dFZlcmlmeShqd3QsIHNrLnB1YmxpY0tleSkgLy8ucGF5bG9hZC5zdWJcblxubWVzc2FnZSA9IG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZSgnc29tZSBtZXNzYWdlJylcbmp3cyA9IGF3YWl0IG5ldyBKT1NFLkNvbXBhY3RTaWduKG1lc3NhZ2UpLnNldFByb3RlY3RlZEhlYWRlcih7YWxnOidFUzM4NCd9KS5zaWduKHNrLnByaXZhdGVLZXkpIC8vIE9yIEZsYXR0ZW5lZFNpZ25cbmp3cyA9IGF3YWl0IG5ldyBKT1NFLkdlbmVyYWxTaWduKG1lc3NhZ2UpLmFkZFNpZ25hdHVyZShzay5wcml2YXRlS2V5KS5zZXRQcm90ZWN0ZWRIZWFkZXIoe2FsZzonRVMzODQnfSkuc2lnbigpXG52ZXJpZmllZCA9IGF3YWl0IEpPU0UuZ2VuZXJhbFZlcmlmeShqd3MsIHNrLnB1YmxpY0tleSlcbm9yIGNvbXBhY3RWZXJpZnkgb3IgZmxhdHRlbmVkVmVyaWZ5XG5uZXcgVGV4dERlY29kZXIoKS5kZWNvZGUodmVyaWZpZWQucGF5bG9hZClcblxuZWsgPSBhd2FpdCBKT1NFLmdlbmVyYXRlS2V5UGFpcignUlNBLU9BRVAtMjU2Jywge2V4dHJhY3RhYmxlOiB0cnVlfSlcbmp3ZSA9IGF3YWl0IG5ldyBKT1NFLkNvbXBhY3RFbmNyeXB0KG1lc3NhZ2UpLnNldFByb3RlY3RlZEhlYWRlcih7YWxnOiAnUlNBLU9BRVAtMjU2JywgZW5jOiAnQTI1NkdDTScgfSkuZW5jcnlwdChlay5wdWJsaWNLZXkpXG5vciBGbGF0dGVuZWRFbmNyeXB0LiBGb3Igc3ltbWV0cmljIHNlY3JldCwgc3BlY2lmeSBhbGc6J2RpcicuXG5kZWNyeXB0ZWQgPSBhd2FpdCBKT1NFLmNvbXBhY3REZWNyeXB0KGp3ZSwgZWsucHJpdmF0ZUtleSlcbm5ldyBUZXh0RGVjb2RlcigpLmRlY29kZShkZWNyeXB0ZWQucGxhaW50ZXh0KVxuandlID0gYXdhaXQgbmV3IEpPU0UuR2VuZXJhbEVuY3J5cHQobWVzc2FnZSkuc2V0UHJvdGVjdGVkSGVhZGVyKHthbGc6ICdSU0EtT0FFUC0yNTYnLCBlbmM6ICdBMjU2R0NNJyB9KS5hZGRSZWNpcGllbnQoZWsucHVibGljS2V5KS5lbmNyeXB0KCkgLy8gd2l0aCBhZGRpdGlvbmFsIGFkZFJlY2lwZW50KCkgYXMgbmVlZGVkXG5kZWNyeXB0ZWQgPSBhd2FpdCBKT1NFLmdlbmVyYWxEZWNyeXB0KGp3ZSwgZWsucHJpdmF0ZUtleSlcblxubWF0ZXJpYWwgPSBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUoJ3NlY3JldCcpXG5qd2UgPSBhd2FpdCBuZXcgSk9TRS5Db21wYWN0RW5jcnlwdChtZXNzYWdlKS5zZXRQcm90ZWN0ZWRIZWFkZXIoe2FsZzogJ1BCRVMyLUhTNTEyK0EyNTZLVycsIGVuYzogJ0EyNTZHQ00nIH0pLmVuY3J5cHQobWF0ZXJpYWwpXG5kZWNyeXB0ZWQgPSBhd2FpdCBKT1NFLmNvbXBhY3REZWNyeXB0KGp3ZSwgbWF0ZXJpYWwsIHtrZXlNYW5hZ2VtZW50QWxnb3JpdGhtczogWydQQkVTMi1IUzUxMitBMjU2S1cnXSwgY29udGVudEVuY3J5cHRpb25BbGdvcml0aG1zOiBbJ0EyNTZHQ00nXX0pXG5qd2UgPSBhd2FpdCBuZXcgSk9TRS5HZW5lcmFsRW5jcnlwdChtZXNzYWdlKS5zZXRQcm90ZWN0ZWRIZWFkZXIoe2FsZzogJ1BCRVMyLUhTNTEyK0EyNTZLVycsIGVuYzogJ0EyNTZHQ00nIH0pLmFkZFJlY2lwaWVudChtYXRlcmlhbCkuZW5jcnlwdCgpXG5qd2UgPSBhd2FpdCBuZXcgSk9TRS5HZW5lcmFsRW5jcnlwdChtZXNzYWdlKS5zZXRQcm90ZWN0ZWRIZWFkZXIoe2VuYzogJ0EyNTZHQ00nIH0pXG4gIC5hZGRSZWNpcGllbnQoZWsucHVibGljS2V5KS5zZXRVbnByb3RlY3RlZEhlYWRlcih7a2lkOiAnZm9vJywgYWxnOiAnUlNBLU9BRVAtMjU2J30pXG4gIC5hZGRSZWNpcGllbnQobWF0ZXJpYWwpLnNldFVucHJvdGVjdGVkSGVhZGVyKHtraWQ6ICdzZWNyZXQxJywgYWxnOiAnUEJFUzItSFM1MTIrQTI1NktXJ30pXG4gIC5hZGRSZWNpcGllbnQobWF0ZXJpYWwyKS5zZXRVbnByb3RlY3RlZEhlYWRlcih7a2lkOiAnc2VjcmV0MicsIGFsZzogJ1BCRVMyLUhTNTEyK0EyNTZLVyd9KVxuICAuZW5jcnlwdCgpXG5kZWNyeXB0ZWQgPSBhd2FpdCBKT1NFLmdlbmVyYWxEZWNyeXB0KGp3ZSwgZWsucHJpdmF0ZUtleSlcbmRlY3J5cHRlZCA9IGF3YWl0IEpPU0UuZ2VuZXJhbERlY3J5cHQoandlLCBtYXRlcmlhbCwge2tleU1hbmFnZW1lbnRBbGdvcml0aG1zOiBbJ1BCRVMyLUhTNTEyK0EyNTZLVyddfSlcbiovXG4iLCJpbXBvcnQgS3J5cHRvIGZyb20gXCIuL2tyeXB0by5tanNcIjtcbmltcG9ydCAqIGFzIEpPU0UgZnJvbSBcImpvc2VcIjtcbmltcG9ydCB7c2lnbmluZ0FsZ29yaXRobSwgZW5jcnlwdGluZ0FsZ29yaXRobSwgc3ltbWV0cmljQWxnb3JpdGhtLCBzeW1tZXRyaWNXcmFwLCBzZWNyZXRBbGdvcml0aG19IGZyb20gXCIuL2FsZ29yaXRobXMubWpzXCI7XG5cbmZ1bmN0aW9uIG1pc21hdGNoKGtpZCwgZW5jb2RlZEtpZCkgeyAvLyBQcm9taXNlIGEgcmVqZWN0aW9uLlxuICBsZXQgbWVzc2FnZSA9IGBLZXkgJHtraWR9IGRvZXMgbm90IG1hdGNoIGVuY29kZWQgJHtlbmNvZGVkS2lkfS5gO1xuICByZXR1cm4gUHJvbWlzZS5yZWplY3QobWVzc2FnZSk7XG59XG5cbmNvbnN0IE11bHRpS3J5cHRvID0ge1xuICAvLyBFeHRlbmQgS3J5cHRvIGZvciBnZW5lcmFsIChtdWx0aXBsZSBrZXkpIEpPU0Ugb3BlcmF0aW9ucy5cbiAgLy8gU2VlIGh0dHBzOi8va2lscm95LWNvZGUuZ2l0aHViLmlvL2Rpc3RyaWJ1dGVkLXNlY3VyaXR5L2RvY3MvaW1wbGVtZW50YXRpb24uaHRtbCNjb21iaW5pbmcta2V5c1xuICBcbiAgLy8gT3VyIG11bHRpIGtleXMgYXJlIGRpY3Rpb25hcmllcyBvZiBuYW1lIChvciBraWQpID0+IGtleU9iamVjdC5cbiAgaXNNdWx0aUtleShrZXkpIHsgLy8gQSBTdWJ0bGVDcnlwdG8gQ3J5cHRvS2V5IGlzIGFuIG9iamVjdCB3aXRoIGEgdHlwZSBwcm9wZXJ0eS4gT3VyIG11bHRpa2V5cyBhcmVcbiAgICAvLyBvYmplY3RzIHdpdGggYSBzcGVjaWZpYyB0eXBlIG9yIG5vIHR5cGUgcHJvcGVydHkgYXQgYWxsLlxuICAgIHJldHVybiAoa2V5LnR5cGUgfHwgJ211bHRpJykgPT09ICdtdWx0aSc7XG4gIH0sXG4gIGtleVRhZ3Moa2V5KSB7IC8vIEp1c3QgdGhlIGtpZHMgdGhhdCBhcmUgZm9yIGFjdHVhbCBrZXlzLiBObyAndHlwZScuXG4gICAgcmV0dXJuIE9iamVjdC5rZXlzKGtleSkuZmlsdGVyKGtleSA9PiBrZXkgIT09ICd0eXBlJyk7XG4gIH0sXG5cbiAgLy8gRXhwb3J0L0ltcG9ydFxuICBhc3luYyBleHBvcnRKV0soa2V5KSB7IC8vIFByb21pc2UgYSBKV0sga2V5IHNldCBpZiBuZWNlc3NhcnksIHJldGFpbmluZyB0aGUgbmFtZXMgYXMga2lkIHByb3BlcnR5LlxuICAgIGlmICghdGhpcy5pc011bHRpS2V5KGtleSkpIHJldHVybiBzdXBlci5leHBvcnRKV0soa2V5KTtcbiAgICBsZXQgbmFtZXMgPSB0aGlzLmtleVRhZ3Moa2V5KSxcbiAgICAgICAga2V5cyA9IGF3YWl0IFByb21pc2UuYWxsKG5hbWVzLm1hcChhc3luYyBuYW1lID0+IHtcbiAgICAgICAgICBsZXQgandrID0gYXdhaXQgdGhpcy5leHBvcnRKV0soa2V5W25hbWVdKTtcbiAgICAgICAgICBqd2sua2lkID0gbmFtZTtcbiAgICAgICAgICByZXR1cm4gandrO1xuICAgICAgICB9KSk7XG4gICAgcmV0dXJuIHtrZXlzfTtcbiAgfSxcbiAgYXN5bmMgaW1wb3J0SldLKGp3aykgeyAvLyBQcm9taXNlIGEgc2luZ2xlIFwia2V5XCIgb2JqZWN0LlxuICAgIC8vIFJlc3VsdCB3aWxsIGJlIGEgbXVsdGkta2V5IGlmIEpXSyBpcyBhIGtleSBzZXQsIGluIHdoaWNoIGNhc2UgZWFjaCBtdXN0IGluY2x1ZGUgYSBraWQgcHJvcGVydHkuXG4gICAgaWYgKCFqd2sua2V5cykgcmV0dXJuIHN1cGVyLmltcG9ydEpXSyhqd2spO1xuICAgIGxldCBrZXkgPSB7fTsgLy8gVE9ETzogZ2V0IHR5cGUgZnJvbSBrdHkgb3Igc29tZSBzdWNoP1xuICAgIGF3YWl0IFByb21pc2UuYWxsKGp3ay5rZXlzLm1hcChhc3luYyBqd2sgPT4ga2V5W2p3ay5raWRdID0gYXdhaXQgdGhpcy5pbXBvcnRKV0soandrKSkpO1xuICAgIHJldHVybiBrZXk7XG4gIH0sXG5cbiAgLy8gRW5jcnlwdC9EZWNyeXB0XG4gIGFzeW5jIGVuY3J5cHQoa2V5LCBtZXNzYWdlLCBoZWFkZXJzID0ge30pIHsgLy8gUHJvbWlzZSBhIEpXRSwgaW4gZ2VuZXJhbCBmb3JtIGlmIGFwcHJvcHJpYXRlLlxuICAgIGlmICghdGhpcy5pc011bHRpS2V5KGtleSkpIHJldHVybiBzdXBlci5lbmNyeXB0KGtleSwgbWVzc2FnZSwgaGVhZGVycyk7XG4gICAgLy8ga2V5IG11c3QgYmUgYSBkaWN0aW9uYXJ5IG1hcHBpbmcgdGFncyB0byBlbmNyeXB0aW5nIGtleXMuXG4gICAgbGV0IGJhc2VIZWFkZXIgPSB7ZW5jOiBzeW1tZXRyaWNBbGdvcml0aG0sIC4uLmhlYWRlcnN9LFxuICAgICAgICBpbnB1dEJ1ZmZlciA9IHRoaXMuaW5wdXRCdWZmZXIobWVzc2FnZSwgYmFzZUhlYWRlciksXG4gICAgICAgIGp3ZSA9IG5ldyBKT1NFLkdlbmVyYWxFbmNyeXB0KGlucHV0QnVmZmVyKS5zZXRQcm90ZWN0ZWRIZWFkZXIoYmFzZUhlYWRlcik7XG4gICAgZm9yIChsZXQgdGFnIG9mIHRoaXMua2V5VGFncyhrZXkpKSB7XG4gICAgICBsZXQgdGhpc0tleSA9IGtleVt0YWddLFxuICAgICAgICAgIGlzU3RyaW5nID0gJ3N0cmluZycgPT09IHR5cGVvZiB0aGlzS2V5LFxuICAgICAgICAgIGlzU3ltID0gaXNTdHJpbmcgfHwgdGhpcy5pc1N5bW1ldHJpYyh0aGlzS2V5KSxcbiAgICAgICAgICBzZWNyZXQgPSBpc1N0cmluZyA/IG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZSh0aGlzS2V5KSA6IHRoaXMua2V5U2VjcmV0KHRoaXNLZXkpLFxuICAgICAgICAgIGFsZyA9IGlzU3RyaW5nID8gc2VjcmV0QWxnb3JpdGhtIDogKGlzU3ltID8gc3ltbWV0cmljV3JhcCA6IGVuY3J5cHRpbmdBbGdvcml0aG0pO1xuICAgICAgLy8gVGhlIGtpZCBhbmQgYWxnIGFyZSBwZXIvc3ViLWtleSwgYW5kIHNvIGNhbm5vdCBiZSBzaWduZWQgYnkgYWxsLCBhbmQgc28gY2Fubm90IGJlIHByb3RlY3RlZCB3aXRoaW4gdGhlIGVuY3J5cHRpb24uXG4gICAgICAvLyBUaGlzIGlzIG9rLCBiZWNhdXNlIHRoZSBvbmx5IHRoYXQgY2FuIGhhcHBlbiBhcyBhIHJlc3VsdCBvZiB0YW1wZXJpbmcgd2l0aCB0aGVzZSBpcyB0aGF0IHRoZSBkZWNyeXB0aW9uIHdpbGwgZmFpbCxcbiAgICAgIC8vIHdoaWNoIGlzIHRoZSBzYW1lIHJlc3VsdCBhcyB0YW1wZXJpbmcgd2l0aCB0aGUgY2lwaGVydGV4dCBvciBhbnkgb3RoZXIgcGFydCBvZiB0aGUgSldFLlxuICAgICAgandlLmFkZFJlY2lwaWVudChzZWNyZXQpLnNldFVucHJvdGVjdGVkSGVhZGVyKHtraWQ6IHRhZywgYWxnfSk7XG4gICAgfVxuICAgIGxldCBlbmNyeXB0ZWQgPSBhd2FpdCBqd2UuZW5jcnlwdCgpO1xuICAgIHJldHVybiBlbmNyeXB0ZWQ7XG4gIH0sXG4gIGFzeW5jIGRlY3J5cHQoa2V5LCBlbmNyeXB0ZWQsIG9wdGlvbnMpIHsgLy8gUHJvbWlzZSB7cGF5bG9hZCwgdGV4dCwganNvbn0sIHdoZXJlIHRleHQgYW5kIGpzb24gYXJlIG9ubHkgZGVmaW5lZCB3aGVuIGFwcHJvcHJpYXRlLlxuICAgIGlmICghdGhpcy5pc011bHRpS2V5KGtleSkpIHJldHVybiBzdXBlci5kZWNyeXB0KGtleSwgZW5jcnlwdGVkLCBvcHRpb25zKTtcbiAgICBsZXQgandlID0gZW5jcnlwdGVkLFxuICAgICAgICB7cmVjaXBpZW50c30gPSBqd2UsXG4gICAgICAgIHVud3JhcHBpbmdQcm9taXNlcyA9IHJlY2lwaWVudHMubWFwKGFzeW5jICh7aGVhZGVyfSkgPT4ge1xuICAgICAgICAgIGxldCB7a2lkfSA9IGhlYWRlcixcbiAgICAgICAgICAgICAgdW53cmFwcGluZ0tleSA9IGtleVtraWRdLFxuICAgICAgICAgICAgICBvcHRpb25zID0ge307XG4gICAgICAgICAgaWYgKCF1bndyYXBwaW5nS2V5KSByZXR1cm4gUHJvbWlzZS5yZWplY3QoJ21pc3NpbmcnKTtcbiAgICAgICAgICBpZiAoJ3N0cmluZycgPT09IHR5cGVvZiB1bndyYXBwaW5nS2V5KSB7IC8vIFRPRE86IG9ubHkgc3BlY2lmaWVkIGlmIGFsbG93ZWQgYnkgc2VjdXJlIGhlYWRlcj9cbiAgICAgICAgICAgIHVud3JhcHBpbmdLZXkgPSBuZXcgVGV4dEVuY29kZXIoKS5lbmNvZGUodW53cmFwcGluZ0tleSk7XG4gICAgICAgICAgICBvcHRpb25zLmtleU1hbmFnZW1lbnRBbGdvcml0aG1zID0gW3NlY3JldEFsZ29yaXRobV07XG4gICAgICAgICAgfVxuICAgICAgICAgIGxldCByZXN1bHQgPSBhd2FpdCBKT1NFLmdlbmVyYWxEZWNyeXB0KGp3ZSwgdGhpcy5rZXlTZWNyZXQodW53cmFwcGluZ0tleSksIG9wdGlvbnMpLFxuICAgICAgICAgICAgICBlbmNvZGVkS2lkID0gcmVzdWx0LnVucHJvdGVjdGVkSGVhZGVyLmtpZDtcbiAgICAgICAgICBpZiAoZW5jb2RlZEtpZCAhPT0ga2lkKSByZXR1cm4gbWlzbWF0Y2goa2lkLCBlbmNvZGVkS2lkKTtcbiAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgICB9KTtcbiAgICAvLyBEbyB3ZSByZWFsbHkgd2FudCB0byByZXR1cm4gdW5kZWZpbmVkIGlmIGV2ZXJ5dGhpbmcgZmFpbHM/IFNob3VsZCBqdXN0IGFsbG93IHRoZSByZWplY3Rpb24gdG8gcHJvcGFnYXRlP1xuICAgIHJldHVybiBhd2FpdCBQcm9taXNlLmFueSh1bndyYXBwaW5nUHJvbWlzZXMpLnRoZW4oXG4gICAgICByZXN1bHQgPT4ge1xuICAgICAgICB0aGlzLnJlY292ZXJEYXRhRnJvbUNvbnRlbnRUeXBlKHJlc3VsdCwgb3B0aW9ucyk7XG4gICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICB9LFxuICAgICAgKCkgPT4gdW5kZWZpbmVkKTtcbiAgfSxcblxuICAvLyBTaWduL1ZlcmlmeVxuICBhc3luYyBzaWduKGtleSwgbWVzc2FnZSwgaGVhZGVyID0ge30pIHsgLy8gUHJvbWlzZSBKV1MsIGluIGdlbmVyYWwgZm9ybSB3aXRoIGtpZCBoZWFkZXJzIGlmIG5lY2Vzc2FyeS5cbiAgICBpZiAoIXRoaXMuaXNNdWx0aUtleShrZXkpKSByZXR1cm4gc3VwZXIuc2lnbihrZXksIG1lc3NhZ2UsIGhlYWRlcik7XG4gICAgbGV0IGlucHV0QnVmZmVyID0gdGhpcy5pbnB1dEJ1ZmZlcihtZXNzYWdlLCBoZWFkZXIpLFxuICAgICAgICBqd3MgPSBuZXcgSk9TRS5HZW5lcmFsU2lnbihpbnB1dEJ1ZmZlcik7XG4gICAgZm9yIChsZXQgdGFnIG9mIHRoaXMua2V5VGFncyhrZXkpKSB7XG4gICAgICBsZXQgdGhpc0tleSA9IGtleVt0YWddLFxuICAgICAgICAgIHRoaXNIZWFkZXIgPSB7a2lkOiB0YWcsIGFsZzogc2lnbmluZ0FsZ29yaXRobSwgLi4uaGVhZGVyfTtcbiAgICAgIGp3cy5hZGRTaWduYXR1cmUodGhpc0tleSkuc2V0UHJvdGVjdGVkSGVhZGVyKHRoaXNIZWFkZXIpO1xuICAgIH1cbiAgICByZXR1cm4gandzLnNpZ24oKTtcbiAgfSxcbiAgdmVyaWZ5U3ViU2lnbmF0dXJlKGp3cywgc2lnbmF0dXJlRWxlbWVudCwgbXVsdGlLZXksIGtpZHMpIHtcbiAgICAvLyBWZXJpZnkgYSBzaW5nbGUgZWxlbWVudCBvZiBqd3Muc2lnbmF0dXJlIHVzaW5nIG11bHRpS2V5LlxuICAgIC8vIEFsd2F5cyBwcm9taXNlcyB7cHJvdGVjdGVkSGVhZGVyLCB1bnByb3RlY3RlZEhlYWRlciwga2lkfSwgZXZlbiBpZiB2ZXJpZmljYXRpb24gZmFpbHMsXG4gICAgLy8gd2hlcmUga2lkIGlzIHRoZSBwcm9wZXJ0eSBuYW1lIHdpdGhpbiBtdWx0aUtleSB0aGF0IG1hdGNoZWQgKGVpdGhlciBieSBiZWluZyBzcGVjaWZpZWQgaW4gYSBoZWFkZXJcbiAgICAvLyBvciBieSBzdWNjZXNzZnVsIHZlcmlmaWNhdGlvbikuIEFsc28gaW5jbHVkZXMgdGhlIGRlY29kZWQgcGF5bG9hZCBJRkYgdGhlcmUgaXMgYSBtYXRjaC5cbiAgICBsZXQgcHJvdGVjdGVkSGVhZGVyID0gc2lnbmF0dXJlRWxlbWVudC5wcm90ZWN0ZWRIZWFkZXIgPz8gdGhpcy5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIoc2lnbmF0dXJlRWxlbWVudCksXG4gICAgICAgIHVucHJvdGVjdGVkSGVhZGVyID0gc2lnbmF0dXJlRWxlbWVudC51bnByb3RlY3RlZEhlYWRlcixcbiAgICAgICAga2lkID0gcHJvdGVjdGVkSGVhZGVyPy5raWQgfHwgdW5wcm90ZWN0ZWRIZWFkZXI/LmtpZCxcbiAgICAgICAgc2luZ2xlSldTID0gey4uLmp3cywgc2lnbmF0dXJlczogW3NpZ25hdHVyZUVsZW1lbnRdfSxcbiAgICAgICAgZmFpbHVyZVJlc3VsdCA9IHtwcm90ZWN0ZWRIZWFkZXIsIHVucHJvdGVjdGVkSGVhZGVyLCBraWR9LFxuICAgICAgICBraWRzVG9UcnkgPSBraWQgPyBba2lkXSA6IGtpZHM7XG4gICAgbGV0IHByb21pc2UgPSBQcm9taXNlLmFueShraWRzVG9UcnkubWFwKGFzeW5jIGtpZCA9PiBKT1NFLmdlbmVyYWxWZXJpZnkoc2luZ2xlSldTLCBtdWx0aUtleVtraWRdKS50aGVuKHJlc3VsdCA9PiB7cmV0dXJuIHtraWQsIC4uLnJlc3VsdH07fSkpKTtcbiAgICByZXR1cm4gcHJvbWlzZS5jYXRjaCgoKSA9PiBmYWlsdXJlUmVzdWx0KTtcbiAgfSxcbiAgYXN5bmMgdmVyaWZ5KGtleSwgc2lnbmF0dXJlLCBvcHRpb25zID0ge30pIHsgLy8gUHJvbWlzZSB7cGF5bG9hZCwgdGV4dCwganNvbn0sIHdoZXJlIHRleHQgYW5kIGpzb24gYXJlIG9ubHkgZGVmaW5lZCB3aGVuIGFwcHJvcHJpYXRlLlxuICAgIC8vIEFkZGl0aW9uYWxseSwgaWYga2V5IGlzIGEgbXVsdGlLZXkgQU5EIHNpZ25hdHVyZSBpcyBhIGdlbmVyYWwgZm9ybSBKV1MsIHRoZW4gYW5zd2VyIGluY2x1ZGVzIGEgc2lnbmVycyBwcm9wZXJ0eVxuICAgIC8vIGJ5IHdoaWNoIGNhbGxlciBjYW4gZGV0ZXJtaW5lIGlmIGl0IHdoYXQgdGhleSBleHBlY3QuIFRoZSBwYXlsb2FkIG9mIGVhY2ggc2lnbmVycyBlbGVtZW50IGlzIGRlZmluZWQgb25seSB0aGF0XG4gICAgLy8gc2lnbmVyIHdhcyBtYXRjaGVkIGJ5IHNvbWV0aGluZyBpbiBrZXkuXG4gICAgXG4gICAgaWYgKCF0aGlzLmlzTXVsdGlLZXkoa2V5KSkgcmV0dXJuIHN1cGVyLnZlcmlmeShrZXksIHNpZ25hdHVyZSwgb3B0aW9ucyk7XG4gICAgaWYgKCFzaWduYXR1cmUuc2lnbmF0dXJlcykgcmV0dXJuO1xuXG4gICAgLy8gQ29tcGFyaXNvbiB0byBwYW52YSBKT1NFLmdlbmVyYWxWZXJpZnkuXG4gICAgLy8gSk9TRSB0YWtlcyBhIGp3cyBhbmQgT05FIGtleSBhbmQgYW5zd2VycyB7cGF5bG9hZCwgcHJvdGVjdGVkSGVhZGVyLCB1bnByb3RlY3RlZEhlYWRlcn0gbWF0Y2hpbmcgdGhlIG9uZVxuICAgIC8vIGp3cy5zaWduYXR1cmUgZWxlbWVudCB0aGF0IHdhcyB2ZXJpZmllZCwgb3RoZXJpc2UgYW4gZXJvci4gKEl0IHRyaWVzIGVhY2ggb2YgdGhlIGVsZW1lbnRzIG9mIHRoZSBqd3Muc2lnbmF0dXJlcy4pXG4gICAgLy8gSXQgaXMgbm90IGdlbmVyYWxseSBwb3NzaWJsZSB0byBrbm93IFdISUNIIG9uZSBvZiB0aGUgandzLnNpZ25hdHVyZXMgd2FzIG1hdGNoZWQuXG4gICAgLy8gKEl0IE1BWSBiZSBwb3NzaWJsZSBpZiB0aGVyZSBhcmUgdW5pcXVlIGtpZCBlbGVtZW50cywgYnV0IHRoYXQncyBhcHBsaWNhdGlvbi1kZXBlbmRlbnQuKVxuICAgIC8vXG4gICAgLy8gTXVsdGlLcnlwdG8gdGFrZXMgYSBkaWN0aW9uYXJ5IHRoYXQgY29udGFpbnMgbmFtZWQga2V5cyBhbmQgcmVjb2duaXplZEhlYWRlciBwcm9wZXJ0aWVzLCBhbmQgaXQgcmV0dXJuc1xuICAgIC8vIGEgcmVzdWx0IHRoYXQgaGFzIGEgc2lnbmVycyBhcnJheSB0aGF0IGhhcyBhbiBlbGVtZW50IGNvcnJlc3BvbmRpbmcgdG8gZWFjaCBvcmlnaW5hbCBzaWduYXR1cmUgaWYgYW55XG4gICAgLy8gYXJlIG1hdGNoZWQgYnkgdGhlIG11bHRpa2V5LiAoSWYgbm9uZSBtYXRjaCwgd2UgcmV0dXJuIHVuZGVmaW5lZC5cbiAgICAvLyBFYWNoIGVsZW1lbnQgY29udGFpbnMgdGhlIGtpZCwgcHJvdGVjdGVkSGVhZGVyLCBwb3NzaWJseSB1bnByb3RlY3RlZEhlYWRlciwgYW5kIHBvc3NpYmx5IHBheWxvYWQgKGkuZS4gaWYgc3VjY2Vzc2Z1bCkuXG4gICAgLy9cbiAgICAvLyBBZGRpdGlvbmFsbHkgaWYgYSByZXN1bHQgaXMgcHJvZHVjZWQsIHRoZSBvdmVyYWxsIHByb3RlY3RlZEhlYWRlciBhbmQgdW5wcm90ZWN0ZWRIZWFkZXIgY29udGFpbnMgb25seSB2YWx1ZXNcbiAgICAvLyB0aGF0IHdlcmUgY29tbW9uIHRvIGVhY2ggb2YgdGhlIHZlcmlmaWVkIHNpZ25hdHVyZSBlbGVtZW50cy5cbiAgICBcbiAgICBsZXQgandzID0gc2lnbmF0dXJlLFxuICAgICAgICBraWRzID0gdGhpcy5rZXlUYWdzKGtleSksXG4gICAgICAgIHNpZ25lcnMgPSBhd2FpdCBQcm9taXNlLmFsbChqd3Muc2lnbmF0dXJlcy5tYXAoc2lnbmF0dXJlID0+IHRoaXMudmVyaWZ5U3ViU2lnbmF0dXJlKGp3cywgc2lnbmF0dXJlLCBrZXksIGtpZHMpKSk7XG4gICAgaWYgKCFzaWduZXJzLmZpbmQoc2lnbmVyID0+IHNpZ25lci5wYXlsb2FkKSkgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICAvLyBOb3cgY2Fub25pY2FsaXplIHRoZSBzaWduZXJzIGFuZCBidWlsZCB1cCBhIHJlc3VsdC5cbiAgICBsZXQgW2ZpcnN0LCAuLi5yZXN0XSA9IHNpZ25lcnMsXG4gICAgICAgIHJlc3VsdCA9IHtwcm90ZWN0ZWRIZWFkZXI6IHt9LCB1bnByb3RlY3RlZEhlYWRlcjoge30sIHNpZ25lcnN9LFxuICAgICAgICAvLyBGb3IgYSBoZWFkZXIgdmFsdWUgdG8gYmUgY29tbW9uIHRvIHZlcmlmaWVkIHJlc3VsdHMsIGl0IG11c3QgYmUgaW4gdGhlIGZpcnN0IHJlc3VsdC5cbiAgICAgICAgZ2V0VW5pcXVlID0gY2F0ZWdvcnlOYW1lID0+IHtcbiAgICAgICAgICBsZXQgZmlyc3RIZWFkZXIgPSBmaXJzdFtjYXRlZ29yeU5hbWVdLFxuICAgICAgICAgICAgICBhY2N1bXVsYXRvckhlYWRlciA9IHJlc3VsdFtjYXRlZ29yeU5hbWVdO1xuICAgICAgICAgIGZvciAobGV0IGxhYmVsIGluIGZpcnN0SGVhZGVyKSB7XG4gICAgICAgICAgICBsZXQgdmFsdWUgPSBmaXJzdEhlYWRlcltsYWJlbF07XG4gICAgICAgICAgICBpZiAocmVzdC5zb21lKHNpZ25lclJlc3VsdCA9PiBzaWduZXJSZXN1bHRbY2F0ZWdvcnlOYW1lXVtsYWJlbF0gIT09IHZhbHVlKSkgY29udGludWU7XG4gICAgICAgICAgICBhY2N1bXVsYXRvckhlYWRlcltsYWJlbF0gPSB2YWx1ZTtcbiAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgZ2V0VW5pcXVlKCdwcm90ZWN0ZWRIZWFkZXInKTtcbiAgICBnZXRVbmlxdWUoJ3Byb3RlY3RlZEhlYWRlcicpO1xuICAgIC8vIElmIGFueXRoaW5nIHZlcmlmaWVkLCB0aGVuIHNldCBwYXlsb2FkIGFuZCBhbGxvdyB0ZXh0L2pzb24gdG8gYmUgcHJvZHVjZWQuXG4gICAgLy8gQ2FsbGVycyBjYW4gY2hlY2sgc2lnbmVyc1tuXS5wYXlsb2FkIHRvIGRldGVybWluZSBpZiB0aGUgcmVzdWx0IGlzIHdoYXQgdGhleSB3YW50LlxuICAgIHJlc3VsdC5wYXlsb2FkID0gc2lnbmVycy5maW5kKHNpZ25lciA9PiBzaWduZXIucGF5bG9hZCkucGF5bG9hZDtcbiAgICByZXR1cm4gdGhpcy5yZWNvdmVyRGF0YUZyb21Db250ZW50VHlwZShyZXN1bHQsIG9wdGlvbnMpO1xuICB9XG59O1xuXG5PYmplY3Quc2V0UHJvdG90eXBlT2YoTXVsdGlLcnlwdG8sIEtyeXB0byk7IC8vIEluaGVyaXQgZnJvbSBLcnlwdG8gc28gdGhhdCBzdXBlci5tdW1ibGUoKSB3b3Jrcy5cbmV4cG9ydCBkZWZhdWx0IE11bHRpS3J5cHRvO1xuIiwiY2xhc3MgUGVyc2lzdGVkQ29sbGVjdGlvbiB7XG4gIC8vIEFzeW5jaHJvbm91cyBsb2NhbCBzdG9yYWdlLCBhdmFpbGFibGUgaW4gd2ViIHdvcmtlcnMuXG4gIGNvbnN0cnVjdG9yKHtjb2xsZWN0aW9uTmFtZSA9ICdjb2xsZWN0aW9uJywgZGJOYW1lID0gJ2FzeW5jTG9jYWxTdG9yYWdlJ30gPSB7fSkge1xuICAgIC8vIENhcHR1cmUgdGhlIGRhdGEgaGVyZSwgYnV0IGRvbid0IG9wZW4gdGhlIGRiIHVudGlsIHdlIG5lZWQgdG8uXG4gICAgdGhpcy5jb2xsZWN0aW9uTmFtZSA9IGNvbGxlY3Rpb25OYW1lO1xuICAgIHRoaXMuZGJOYW1lID0gZGJOYW1lO1xuICAgIHRoaXMudmVyc2lvbiA9IDE7XG4gIH1cbiAgZ2V0IGRiKCkgeyAvLyBBbnN3ZXIgYSBwcm9taXNlIGZvciB0aGUgZGF0YWJhc2UsIGNyZWF0aW5nIGl0IGlmIG5lZWRlZC5cbiAgICByZXR1cm4gdGhpcy5fZGIgPz89IG5ldyBQcm9taXNlKHJlc29sdmUgPT4ge1xuICAgICAgY29uc3QgcmVxdWVzdCA9IGluZGV4ZWREQi5vcGVuKHRoaXMuZGJOYW1lLCB0aGlzLnZlcnNpb24pO1xuICAgICAgLy8gY3JlYXRlT2JqZWN0U3RvcmUgY2FuIG9ubHkgYmUgY2FsbGVkIGZyb20gdXBncmFkZW5lZWRlZCwgd2hpY2ggaXMgb25seSBjYWxsZWQgZm9yIG5ldyB2ZXJzaW9ucy5cbiAgICAgIHJlcXVlc3Qub251cGdyYWRlbmVlZGVkID0gZXZlbnQgPT4gZXZlbnQudGFyZ2V0LnJlc3VsdC5jcmVhdGVPYmplY3RTdG9yZSh0aGlzLmNvbGxlY3Rpb25OYW1lKTtcbiAgICAgIHRoaXMucmVzdWx0KHJlc29sdmUsIHJlcXVlc3QpO1xuICAgIH0pO1xuICB9XG4gIHRyYW5zYWN0aW9uKG1vZGUgPSAncmVhZCcpIHsgLy8gQW5zd2VyIGEgcHJvbWlzZSBmb3IgdGhlIG5hbWVkIG9iamVjdCBzdG9yZSBvbiBhIG5ldyB0cmFuc2FjdGlvbi5cbiAgICBjb25zdCBjb2xsZWN0aW9uTmFtZSA9IHRoaXMuY29sbGVjdGlvbk5hbWU7XG4gICAgcmV0dXJuIHRoaXMuZGIudGhlbihkYiA9PiBkYi50cmFuc2FjdGlvbihjb2xsZWN0aW9uTmFtZSwgbW9kZSkub2JqZWN0U3RvcmUoY29sbGVjdGlvbk5hbWUpKTtcbiAgfVxuICByZXN1bHQocmVzb2x2ZSwgb3BlcmF0aW9uKSB7XG4gICAgb3BlcmF0aW9uLm9uc3VjY2VzcyA9IGV2ZW50ID0+IHJlc29sdmUoZXZlbnQudGFyZ2V0LnJlc3VsdCB8fCAnJyk7IC8vIE5vdCB1bmRlZmluZWQuXG4gIH1cbiAgcmV0cmlldmUodGFnKSB7IC8vIFByb21pc2UgdG8gcmV0cmlldmUgdGFnIGZyb20gY29sbGVjdGlvbk5hbWUuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKHJlc29sdmUgPT4ge1xuICAgICAgdGhpcy50cmFuc2FjdGlvbigncmVhZG9ubHknKS50aGVuKHN0b3JlID0+IHRoaXMucmVzdWx0KHJlc29sdmUsIHN0b3JlLmdldCh0YWcpKSk7XG4gICAgfSk7XG4gIH1cbiAgc3RvcmUodGFnLCBkYXRhKSB7IC8vIFByb21pc2UgdG8gc3RvcmUgZGF0YSBhdCB0YWcgaW4gY29sbGVjdGlvbk5hbWUuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKHJlc29sdmUgPT4ge1xuICAgICAgdGhpcy50cmFuc2FjdGlvbigncmVhZHdyaXRlJykudGhlbihzdG9yZSA9PiB0aGlzLnJlc3VsdChyZXNvbHZlLCBzdG9yZS5wdXQoZGF0YSwgdGFnKSkpO1xuICAgIH0pO1xuICB9XG4gIHJlbW92ZSh0YWcpIHsgLy8gUHJvbWlzZSB0byByZW1vdmUgdGFnIGZyb20gY29sbGVjdGlvbk5hbWUuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKHJlc29sdmUgPT4ge1xuICAgICAgdGhpcy50cmFuc2FjdGlvbigncmVhZHdyaXRlJykudGhlbihzdG9yZSA9PiB0aGlzLnJlc3VsdChyZXNvbHZlLCBzdG9yZS5kZWxldGUodGFnKSkpO1xuICAgIH0pO1xuICB9XG59XG5leHBvcnQgZGVmYXVsdCBQZXJzaXN0ZWRDb2xsZWN0aW9uO1xuIiwidmFyIHByb21wdGVyID0gcHJvbXB0U3RyaW5nID0+IHByb21wdFN0cmluZztcbmlmICh0eXBlb2Yod2luZG93KSAhPT0gJ3VuZGVmaW5lZCcpIHtcbiAgcHJvbXB0ZXIgPSB3aW5kb3cucHJvbXB0O1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZ2V0VXNlckRldmljZVNlY3JldCh0YWcsIHByb21wdFN0cmluZykge1xuICByZXR1cm4gcHJvbXB0U3RyaW5nID8gKHRhZyArIHByb21wdGVyKHByb21wdFN0cmluZykpIDogdGFnO1xufVxuIiwiY29uc3Qgb3JpZ2luID0gbmV3IFVSTChpbXBvcnQubWV0YS51cmwpLm9yaWdpbjtcbmV4cG9ydCBkZWZhdWx0IG9yaWdpbjtcbiIsImV4cG9ydCBjb25zdCBta2RpciA9IHVuZGVmaW5lZDtcbiIsImNvbnN0IHRhZ0JyZWFrdXAgPSAvKFxcU3s1MH0pKFxcU3syfSkoXFxTezJ9KShcXFMrKS87XG5leHBvcnQgZnVuY3Rpb24gdGFnUGF0aChjb2xsZWN0aW9uTmFtZSwgdGFnLCBleHRlbnNpb24gPSAnanNvbicpIHsgLy8gUGF0aG5hbWUgdG8gdGFnIHJlc291cmNlLlxuICAvLyBVc2VkIGluIFN0b3JhZ2UgVVJJIGFuZCBmaWxlIHN5c3RlbSBzdG9yZXMuIEJvdHRsZW5lY2tlZCBoZXJlIHRvIHByb3ZpZGUgY29uc2lzdGVudCBhbHRlcm5hdGUgaW1wbGVtZW50YXRpb25zLlxuICAvLyBQYXRoIGlzIC5qc29uIHNvIHRoYXQgc3RhdGljLWZpbGUgd2ViIHNlcnZlcnMgd2lsbCBzdXBwbHkgYSBqc29uIG1pbWUgdHlwZS5cbiAgLy8gUGF0aCBpcyBicm9rZW4gdXAgc28gdGhhdCBkaXJlY3RvcnkgcmVhZHMgZG9uJ3QgZ2V0IGJvZ2dlZCBkb3duIGZyb20gaGF2aW5nIHRvbyBtdWNoIGluIGEgZGlyZWN0b3J5LlxuICAvL1xuICAvLyBOT1RFOiBjaGFuZ2VzIGhlcmUgbXVzdCBiZSBtYXRjaGVkIGJ5IHRoZSBQVVQgcm91dGUgc3BlY2lmaWVkIGluIHNpZ25lZC1jbG91ZC1zZXJ2ZXIvc3RvcmFnZS5tanMgYW5kIHRhZ05hbWUubWpzXG4gIGlmICghdGFnKSByZXR1cm4gY29sbGVjdGlvbk5hbWU7XG4gIGxldCBtYXRjaCA9IHRhZy5tYXRjaCh0YWdCcmVha3VwKTtcbiAgaWYgKCFtYXRjaCkgcmV0dXJuIGAke2NvbGxlY3Rpb25OYW1lfS8ke3RhZ31gO1xuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbm8tdW51c2VkLXZhcnNcbiAgbGV0IFtfLCBhLCBiLCBjLCByZXN0XSA9IG1hdGNoO1xuICByZXR1cm4gYCR7Y29sbGVjdGlvbk5hbWV9LyR7YX0vJHtifS8ke2N9LyR7cmVzdH0uJHtleHRlbnNpb259YDtcbn1cbiIsImltcG9ydCBvcmlnaW4gZnJvbSAnI29yaWdpbic7IC8vIFdoZW4gcnVubmluZyBpbiBhIGJyb3dzZXIsIGxvY2F0aW9uLm9yaWdpbiB3aWxsIGJlIGRlZmluZWQuIEhlcmUgd2UgYWxsb3cgZm9yIE5vZGVKUy5cbmltcG9ydCB7bWtkaXJ9IGZyb20gJyNta2Rpcic7XG5pbXBvcnQge3RhZ1BhdGh9IGZyb20gJy4vdGFnUGF0aC5tanMnO1xuXG5hc3luYyBmdW5jdGlvbiByZXNwb25zZUhhbmRsZXIocmVzcG9uc2UpIHtcbiAgLy8gUmVqZWN0IGlmIHNlcnZlciBkb2VzLCBlbHNlIHJlc3BvbnNlLnRleHQoKS5cbiAgaWYgKHJlc3BvbnNlLnN0YXR1cyA9PT0gNDA0KSByZXR1cm4gJyc7XG4gIGlmICghcmVzcG9uc2Uub2spIHJldHVybiBQcm9taXNlLnJlamVjdChyZXNwb25zZS5zdGF0dXNUZXh0KTtcbiAgbGV0IHRleHQgPSBhd2FpdCByZXNwb25zZS50ZXh0KCk7XG4gIGlmICghdGV4dCkgcmV0dXJuIHRleHQ7IC8vIFJlc3VsdCBvZiBzdG9yZSBjYW4gYmUgZW1wdHkuXG4gIHJldHVybiBKU09OLnBhcnNlKHRleHQpO1xufVxuXG5jb25zdCBTdG9yYWdlID0ge1xuICBnZXQgb3JpZ2luKCkgeyByZXR1cm4gb3JpZ2luOyB9LFxuICB0YWdQYXRoLFxuICBta2RpcixcbiAgdXJpKGNvbGxlY3Rpb25OYW1lLCB0YWcpIHtcbiAgICAvLyBQYXRobmFtZSBleHBlY3RlZCBieSBvdXIgc2lnbmVkLWNsb3VkLXNlcnZlci5cbiAgICByZXR1cm4gYCR7b3JpZ2lufS9kYi8ke3RoaXMudGFnUGF0aChjb2xsZWN0aW9uTmFtZSwgdGFnKX1gO1xuICB9LFxuICBzdG9yZShjb2xsZWN0aW9uTmFtZSwgdGFnLCBzaWduYXR1cmUsIG9wdGlvbnMgPSB7fSkge1xuICAgIC8vIFN0b3JlIHRoZSBzaWduZWQgY29udGVudCBvbiB0aGUgc2lnbmVkLWNsb3VkLXNlcnZlciwgcmVqZWN0aW5nIGlmXG4gICAgLy8gdGhlIHNlcnZlciBpcyB1bmFibGUgdG8gdmVyaWZ5IHRoZSBzaWduYXR1cmUgZm9sbG93aW5nIHRoZSBydWxlcyBvZlxuICAgIC8vIGh0dHBzOi8va2lscm95LWNvZGUuZ2l0aHViLmlvL2Rpc3RyaWJ1dGVkLXNlY3VyaXR5LyNzdG9yaW5nLWtleXMtdXNpbmctdGhlLWNsb3VkLXN0b3JhZ2UtYXBpXG4gICAgcmV0dXJuIGZldGNoKHRoaXMudXJpKGNvbGxlY3Rpb25OYW1lLCB0YWcpLCB7XG4gICAgICBtZXRob2Q6ICdQVVQnLFxuICAgICAgYm9keTogSlNPTi5zdHJpbmdpZnkoc2lnbmF0dXJlKSxcbiAgICAgIGhlYWRlcnM6IHsnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nLCAuLi4ob3B0aW9ucy5oZWFkZXJzIHx8IHt9KX1cbiAgICB9KS50aGVuKHJlc3BvbnNlSGFuZGxlcik7XG4gIH0sXG4gIHJldHJpZXZlKGNvbGxlY3Rpb25OYW1lLCB0YWcsIG9wdGlvbnMgPSB7fSkge1xuICAgIC8vIFdlIGRvIG5vdCB2ZXJpZnkgYW5kIGdldCB0aGUgb3JpZ2luYWwgZGF0YSBvdXQgaGVyZSwgYmVjYXVzZSB0aGUgY2FsbGVyIGhhc1xuICAgIC8vIHRoZSByaWdodCB0byBkbyBzbyB3aXRob3V0IHRydXN0aW5nIHVzLlxuICAgIHJldHVybiBmZXRjaCh0aGlzLnVyaShjb2xsZWN0aW9uTmFtZSwgdGFnKSwge1xuICAgICAgY2FjaGU6ICdkZWZhdWx0JyxcbiAgICAgIGhlYWRlcnM6IHsnQWNjZXB0JzogJ2FwcGxpY2F0aW9uL2pzb24nLCAuLi4ob3B0aW9ucy5oZWFkZXJzIHx8IHt9KX1cbiAgICB9KS50aGVuKHJlc3BvbnNlSGFuZGxlcik7XG4gIH1cbn07XG5leHBvcnQgZGVmYXVsdCBTdG9yYWdlO1xuIiwiaW1wb3J0IE11bHRpS3J5cHRvIGZyb20gJy4vbXVsdGlLcnlwdG8ubWpzJztcbmltcG9ydCBMb2NhbENvbGxlY3Rpb24gZnJvbSAnI2xvY2FsU3RvcmUnO1xuaW1wb3J0IHtnZXRVc2VyRGV2aWNlU2VjcmV0fSBmcm9tICcuL3NlY3JldC5tanMnO1xuaW1wb3J0IFN0b3JhZ2UgZnJvbSAnLi9zdG9yYWdlLm1qcyc7XG5cbmZ1bmN0aW9uIGVycm9yKHRlbXBsYXRlRnVuY3Rpb24sIHRhZywgY2F1c2UgPSB1bmRlZmluZWQpIHtcbiAgLy8gRm9ybWF0cyB0YWcgKGUuZy4sIHNob3J0ZW5zIGl0KSBhbmQgZ2l2ZXMgaXQgdG8gdGVtcGxhdGVGdW5jdGlvbih0YWcpIHRvIGdldFxuICAvLyBhIHN1aXRhYmxlIGVycm9yIG1lc3NhZ2UuIEFuc3dlcnMgYSByZWplY3RlZCBwcm9taXNlIHdpdGggdGhhdCBFcnJvci5cbiAgbGV0IHNob3J0ZW5lZFRhZyA9IHRhZy5zbGljZSgwLCAxNikgKyBcIi4uLlwiLFxuICAgICAgbWVzc2FnZSA9IHRlbXBsYXRlRnVuY3Rpb24oc2hvcnRlbmVkVGFnKTtcbiAgcmV0dXJuIFByb21pc2UucmVqZWN0KG5ldyBFcnJvcihtZXNzYWdlLCB7Y2F1c2V9KSk7XG59XG5mdW5jdGlvbiB1bmF2YWlsYWJsZSh0YWcpIHsgLy8gRG8gd2Ugd2FudCB0byBkaXN0aW5ndWlzaCBiZXR3ZWVuIGEgdGFnIGJlaW5nXG4gIC8vIHVuYXZhaWxhYmxlIGF0IGFsbCwgdnMganVzdCB0aGUgcHVibGljIGVuY3J5cHRpb24ga2V5IGJlaW5nIHVuYXZhaWxhYmxlP1xuICAvLyBSaWdodCBub3cgd2UgZG8gbm90IGRpc3Rpbmd1aXNoLCBhbmQgdXNlIHRoaXMgZm9yIGJvdGguXG4gIHJldHVybiBlcnJvcih0YWcgPT4gYFRoZSB0YWcgJHt0YWd9IGlzIG5vdCBhdmFpbGFibGUuYCwgdGFnKTtcbn1cblxuZXhwb3J0IGNsYXNzIEtleVNldCB7XG4gIC8vIEEgS2V5U2V0IG1haW50YWlucyB0d28gcHJpdmF0ZSBrZXlzOiBzaWduaW5nS2V5IGFuZCBkZWNyeXB0aW5nS2V5LlxuICAvLyBTZWUgaHR0cHM6Ly9raWxyb3ktY29kZS5naXRodWIuaW8vZGlzdHJpYnV0ZWQtc2VjdXJpdHkvZG9jcy9pbXBsZW1lbnRhdGlvbi5odG1sI3dlYi13b3JrZXItYW5kLWlmcmFtZVxuXG4gIC8vIENhY2hpbmdcbiAgc3RhdGljIGtleVNldHMgPSB7fTtcbiAgc3RhdGljIGNhY2hlZCh0YWcpIHsgLy8gUmV0dXJuIGFuIGFscmVhZHkgcG9wdWxhdGVkIEtleVNldC5cbiAgICByZXR1cm4gdGhpcy5rZXlTZXRzW3RhZ107XG4gIH1cbiAgc3RhdGljIGNsZWFyKHRhZyA9IG51bGwpIHsgLy8gUmVtb3ZlIGFsbCBLZXlTZXQgaW5zdGFuY2VzIG9yIGp1c3QgdGhlIHNwZWNpZmllZCBvbmUsIGJ1dCBkb2VzIG5vdCBkZXN0cm95IHRoZWlyIHN0b3JhZ2UuXG4gICAgaWYgKCF0YWcpIHJldHVybiBLZXlTZXQua2V5U2V0cyA9IHt9O1xuICAgIGRlbGV0ZSBLZXlTZXQua2V5U2V0c1t0YWddXG4gIH1cbiAgY29uc3RydWN0b3IodGFnKSB7XG4gICAgdGhpcy50YWcgPSB0YWc7XG4gICAgdGhpcy5tZW1iZXJUYWdzID0gW107IC8vIFVzZWQgd2hlbiByZWN1cnNpdmVseSBkZXN0cm95aW5nLlxuICAgIEtleVNldC5rZXlTZXRzW3RhZ10gPSB0aGlzOyAvLyBDYWNoZSBpdC5cbiAgfVxuICAvLyBhcGkubWpzIHByb3ZpZGVzIHRoZSBzZXR0ZXIgdG8gY2hhbmdlcyB0aGVzZSwgYW5kIHdvcmtlci5tanMgZXhlcmNpc2VzIGl0IGluIGJyb3dzZXJzLlxuICBzdGF0aWMgZ2V0VXNlckRldmljZVNlY3JldCA9IGdldFVzZXJEZXZpY2VTZWNyZXQ7XG4gIHN0YXRpYyBTdG9yYWdlID0gU3RvcmFnZTtcblxuICAvLyBQcmluY2lwbGUgb3BlcmF0aW9ucy5cbiAgc3RhdGljIGFzeW5jIGNyZWF0ZSh3cmFwcGluZ0RhdGEpIHsgLy8gQ3JlYXRlIGEgcGVyc2lzdGVkIEtleVNldCBvZiB0aGUgY29ycmVjdCB0eXBlLCBwcm9taXNpbmcgdGhlIG5ld2x5IGNyZWF0ZWQgdGFnLlxuICAgIGxldCB7dGltZSwgLi4ua2V5c30gPSBhd2FpdCB0aGlzLmNyZWF0ZUtleXMod3JhcHBpbmdEYXRhKSxcbiAgICAgICAge3RhZ30gPSBrZXlzO1xuICAgIGF3YWl0IHRoaXMucGVyc2lzdCh0YWcsIGtleXMsIHdyYXBwaW5nRGF0YSwgdGltZSk7XG4gICAgcmV0dXJuIHRhZztcbiAgfVxuICBhc3luYyBkZXN0cm95KG9wdGlvbnMgPSB7fSkgeyAvLyBUZXJtaW5hdGVzIHRoaXMga2V5U2V0IGFuZCBhc3NvY2lhdGVkIHN0b3JhZ2UsIGFuZCBzYW1lIGZvciBPV05FRCByZWN1cnNpdmVNZW1iZXJzIGlmIGFza2VkLlxuICAgIGxldCB7dGFnLCBtZW1iZXJUYWdzLCBzaWduaW5nS2V5fSA9IHRoaXMsXG4gICAgICAgIGNvbnRlbnQgPSBcIlwiLCAvLyBTaG91bGQgc3RvcmFnZSBoYXZlIGEgc2VwYXJhdGUgb3BlcmF0aW9uIHRvIGRlbGV0ZSwgb3RoZXIgdGhhbiBzdG9yaW5nIGVtcHR5P1xuICAgICAgICBzaWduYXR1cmUgPSBhd2FpdCB0aGlzLmNvbnN0cnVjdG9yLnNpZ25Gb3JTdG9yYWdlKHsuLi5vcHRpb25zLCBtZXNzYWdlOiBjb250ZW50LCB0YWcsIG1lbWJlclRhZ3MsIHNpZ25pbmdLZXksIHRpbWU6IERhdGUubm93KCksIHJlY292ZXJ5OiB0cnVlfSk7XG4gICAgYXdhaXQgdGhpcy5jb25zdHJ1Y3Rvci5zdG9yZSgnRW5jcnlwdGlvbktleScsIHRhZywgc2lnbmF0dXJlKTtcbiAgICBhd2FpdCB0aGlzLmNvbnN0cnVjdG9yLnN0b3JlKHRoaXMuY29uc3RydWN0b3IuY29sbGVjdGlvbiwgdGFnLCBzaWduYXR1cmUpO1xuICAgIHRoaXMuY29uc3RydWN0b3IuY2xlYXIodGFnKTtcbiAgICBpZiAoIW9wdGlvbnMucmVjdXJzaXZlTWVtYmVycykgcmV0dXJuO1xuICAgIGF3YWl0IFByb21pc2UuYWxsU2V0dGxlZCh0aGlzLm1lbWJlclRhZ3MubWFwKGFzeW5jIG1lbWJlclRhZyA9PiB7XG4gICAgICBsZXQgbWVtYmVyS2V5U2V0ID0gYXdhaXQgS2V5U2V0LmVuc3VyZShtZW1iZXJUYWcsIHsuLi5vcHRpb25zLCByZWNvdmVyeTogdHJ1ZX0pO1xuICAgICAgYXdhaXQgbWVtYmVyS2V5U2V0LmRlc3Ryb3kob3B0aW9ucyk7XG4gICAgfSkpO1xuICB9XG4gIGRlY3J5cHQoZW5jcnlwdGVkLCBvcHRpb25zKSB7IC8vIFByb21pc2Uge3BheWxvYWQsIHRleHQsIGpzb259IGFzIGFwcHJvcHJpYXRlLlxuICAgIGxldCB7dGFnLCBkZWNyeXB0aW5nS2V5fSA9IHRoaXMsXG4gICAgICAgIGtleSA9IGVuY3J5cHRlZC5yZWNpcGllbnRzID8ge1t0YWddOiBkZWNyeXB0aW5nS2V5fSA6IGRlY3J5cHRpbmdLZXk7XG4gICAgcmV0dXJuIE11bHRpS3J5cHRvLmRlY3J5cHQoa2V5LCBlbmNyeXB0ZWQsIG9wdGlvbnMpO1xuICB9XG4gIC8vIHNpZ24gYXMgZWl0aGVyIGNvbXBhY3Qgb3IgbXVsdGlLZXkgZ2VuZXJhbCBKV1MuXG4gIC8vIFRoZXJlJ3Mgc29tZSBjb21wbGV4aXR5IGhlcmUgYXJvdW5kIGJlaW5nIGFibGUgdG8gcGFzcyBpbiBtZW1iZXJUYWdzIGFuZCBzaWduaW5nS2V5IHdoZW4gdGhlIGtleVNldCBpc1xuICAvLyBiZWluZyBjcmVhdGVkIGFuZCBkb2Vzbid0IHlldCBleGlzdC5cbiAgc3RhdGljIGFzeW5jIHNpZ24obWVzc2FnZSwge3RhZ3MgPSBbXSwgdGVhbTppc3MsIG1lbWJlcjphY3QsIHRpbWU6aWF0ID0gaXNzICYmIERhdGUubm93KCksXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICBtZW1iZXJUYWdzLCBzaWduaW5nS2V5LFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLi4ub3B0aW9uc30pIHtcbiAgICBpZiAoaXNzICYmICFhY3QpIHsgLy8gU3VwcGx5IHRoZSB2YWx1ZVxuICAgICAgaWYgKCFtZW1iZXJUYWdzKSBtZW1iZXJUYWdzID0gKGF3YWl0IEtleVNldC5lbnN1cmUoaXNzKSkubWVtYmVyVGFncztcbiAgICAgIGxldCBjYWNoZWRNZW1iZXIgPSBtZW1iZXJUYWdzLmZpbmQodGFnID0+IHRoaXMuY2FjaGVkKHRhZykpO1xuICAgICAgYWN0ID0gY2FjaGVkTWVtYmVyIHx8IGF3YWl0IHRoaXMuZW5zdXJlMShtZW1iZXJUYWdzKS50aGVuKGtleVNldCA9PiBrZXlTZXQudGFnKTtcbiAgICB9XG4gICAgaWYgKGlzcyAmJiAhdGFncy5pbmNsdWRlcyhpc3MpKSB0YWdzID0gW2lzcywgLi4udGFnc107IC8vIE11c3QgYmUgZmlyc3RcbiAgICBpZiAoYWN0ICYmICF0YWdzLmluY2x1ZGVzKGFjdCkpIHRhZ3MgPSBbLi4udGFncywgYWN0XTtcblxuICAgIGxldCBrZXkgPSBhd2FpdCB0aGlzLnByb2R1Y2VLZXkodGFncywgYXN5bmMgdGFnID0+IHtcbiAgICAgIC8vIFVzZSBzcGVjaWZpZWQgc2lnbmluZ0tleSAoaWYgYW55KSBmb3IgdGhlIGZpcnN0IG9uZS5cbiAgICAgIGxldCBrZXkgPSBzaWduaW5nS2V5IHx8IChhd2FpdCBLZXlTZXQuZW5zdXJlKHRhZywgb3B0aW9ucykpLnNpZ25pbmdLZXk7XG4gICAgICBzaWduaW5nS2V5ID0gbnVsbDtcbiAgICAgIHJldHVybiBrZXk7XG4gICAgfSwgb3B0aW9ucyk7XG4gICAgcmV0dXJuIE11bHRpS3J5cHRvLnNpZ24oa2V5LCBtZXNzYWdlLCB7aXNzLCBhY3QsIGlhdCwgLi4ub3B0aW9uc30pO1xuICB9XG5cbiAgLy8gVmVyaWZ5IGluIHRoZSBub3JtYWwgd2F5LCBhbmQgdGhlbiBjaGVjayBkZWVwbHkgaWYgYXNrZWQuXG4gIHN0YXRpYyBhc3luYyB2ZXJpZnkoc2lnbmF0dXJlLCB0YWdzLCBvcHRpb25zKSB7XG4gICAgbGV0IGlzQ29tcGFjdCA9ICFzaWduYXR1cmUuc2lnbmF0dXJlcyxcbiAgICAgICAga2V5ID0gYXdhaXQgdGhpcy5wcm9kdWNlS2V5KHRhZ3MsIHRhZyA9PiBLZXlTZXQudmVyaWZ5aW5nS2V5KHRhZyksIG9wdGlvbnMsIGlzQ29tcGFjdCksXG4gICAgICAgIHJlc3VsdCA9IGF3YWl0IE11bHRpS3J5cHRvLnZlcmlmeShrZXksIHNpZ25hdHVyZSwgb3B0aW9ucyksXG4gICAgICAgIG1lbWJlclRhZyA9IG9wdGlvbnMubWVtYmVyID09PSB1bmRlZmluZWQgPyByZXN1bHQ/LnByb3RlY3RlZEhlYWRlci5hY3QgOiBvcHRpb25zLm1lbWJlcixcbiAgICAgICAgbm90QmVmb3JlID0gb3B0aW9ucy5ub3RCZWZvcmU7XG4gICAgZnVuY3Rpb24gZXhpdChsYWJlbCkge1xuICAgICAgaWYgKG9wdGlvbnMuaGFyZEVycm9yKSByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IEVycm9yKGxhYmVsKSk7XG4gICAgfVxuICAgIGlmICghcmVzdWx0KSByZXR1cm4gZXhpdCgnSW5jb3JyZWN0IHNpZ25hdHVyZS4nKTtcbiAgICBpZiAobWVtYmVyVGFnKSB7XG4gICAgICBpZiAob3B0aW9ucy5tZW1iZXIgPT09ICd0ZWFtJykge1xuICAgICAgICBtZW1iZXJUYWcgPSByZXN1bHQucHJvdGVjdGVIZWFkZXIuYWN0O1xuICAgICAgICBpZiAoIW1lbWJlclRhZykgcmV0dXJuIGV4aXQoJ05vIG1lbWJlciBpZGVudGlmaWVkIGluIHNpZ25hdHVyZS4nKTtcbiAgICAgIH1cbiAgICAgIGlmICghdGFncy5pbmNsdWRlcyhtZW1iZXJUYWcpKSB7IC8vIEFkZCB0byB0YWdzIGFuZCByZXN1bHQgaWYgbm90IGFscmVhZHkgcHJlc2VudFxuICAgICAgICBsZXQgbWVtYmVyS2V5ID0gYXdhaXQgS2V5U2V0LnZlcmlmeWluZ0tleShtZW1iZXJUYWcpLFxuICAgICAgICAgICAgbWVtYmVyTXVsdGlrZXkgPSB7W21lbWJlclRhZ106IG1lbWJlcktleX0sXG4gICAgICAgICAgICBhdXggPSBhd2FpdCBNdWx0aUtyeXB0by52ZXJpZnkobWVtYmVyTXVsdGlrZXksIHNpZ25hdHVyZSwgb3B0aW9ucyk7XG4gICAgICAgIGlmICghYXV4KSByZXR1cm4gZXhpdCgnSW5jb3JyZWN0IG1lbWJlciBzaWduYXR1cmUuJyk7XG4gICAgICAgIHRhZ3MucHVzaChtZW1iZXJUYWcpO1xuICAgICAgICByZXN1bHQuc2lnbmVycy5maW5kKHNpZ25lciA9PiBzaWduZXIucHJvdGVjdGVkSGVhZGVyLmtpZCA9PT0gbWVtYmVyVGFnKS5wYXlsb2FkID0gcmVzdWx0LnBheWxvYWQ7XG4gICAgICB9XG4gICAgfVxuICAgIGlmIChtZW1iZXJUYWcgfHwgbm90QmVmb3JlID09PSAndGVhbScpIHtcbiAgICAgIGxldCB0ZWFtVGFnID0gcmVzdWx0LnByb3RlY3RlZEhlYWRlci5pc3MgfHwgcmVzdWx0LnByb3RlY3RlZEhlYWRlci5raWQsIC8vIE11bHRpIG9yIHNpbmdsZSBjYXNlLlxuICAgICAgICAgIHZlcmlmaWVkSldTID0gYXdhaXQgdGhpcy5yZXRyaWV2ZShUZWFtS2V5U2V0LmNvbGxlY3Rpb24sIHRlYW1UYWcpLFxuICAgICAgICAgIGp3ZSA9IHZlcmlmaWVkSldTPy5qc29uO1xuICAgICAgaWYgKG1lbWJlclRhZyAmJiAhdGVhbVRhZykgcmV0dXJuIGV4aXQoJ05vIHRlYW0gb3IgbWFpbiB0YWcgaWRlbnRpZmllZCBpbiBzaWduYXR1cmUnKTtcbiAgICAgIGlmIChtZW1iZXJUYWcgJiYgandlICYmICFqd2UucmVjaXBpZW50cy5maW5kKG1lbWJlciA9PiBtZW1iZXIuaGVhZGVyLmtpZCA9PT0gbWVtYmVyVGFnKSkgcmV0dXJuIGV4aXQoJ1NpZ25lciBpcyBub3QgYSBtZW1iZXIuJyk7XG4gICAgICBpZiAobm90QmVmb3JlID09PSAndGVhbScpIG5vdEJlZm9yZSA9IHZlcmlmaWVkSldTPy5wcm90ZWN0ZWRIZWFkZXIuaWF0XG4gICAgICAgIHx8IChhd2FpdCB0aGlzLnJldHJpZXZlKCdFbmNyeXB0aW9uS2V5JywgdGVhbVRhZykpPy5wcm90ZWN0ZWRIZWFkZXIuaWF0O1xuICAgIH1cbiAgICBpZiAobm90QmVmb3JlKSB7XG4gICAgICBsZXQge2lhdH0gPSByZXN1bHQucHJvdGVjdGVkSGVhZGVyO1xuICAgICAgaWYgKGlhdCA8IG5vdEJlZm9yZSkgcmV0dXJuIGV4aXQoJ1NpZ25hdHVyZSBwcmVkYXRlcyByZXF1aXJlZCB0aW1lc3RhbXAuJyk7XG4gICAgfVxuICAgIC8vIEVhY2ggc2lnbmVyIHNob3VsZCBub3cgYmUgdmVyaWZpZWQuXG4gICAgaWYgKChyZXN1bHQuc2lnbmVycz8uZmlsdGVyKHNpZ25lciA9PiBzaWduZXIucGF5bG9hZCkubGVuZ3RoIHx8IDEpICE9PSB0YWdzLmxlbmd0aCkgcmV0dXJuIGV4aXQoJ1VudmVyaWZpZWQgc2lnbmVyJyk7XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfVxuXG4gIC8vIEtleSBtYW5hZ2VtZW50XG4gIHN0YXRpYyBhc3luYyBwcm9kdWNlS2V5KHRhZ3MsIHByb2R1Y2VyLCBvcHRpb25zLCB1c2VTaW5nbGVLZXkgPSB0YWdzLmxlbmd0aCA9PT0gMSkge1xuICAgIC8vIFByb21pc2UgYSBrZXkgb3IgbXVsdGlLZXksIGFzIGRlZmluZWQgYnkgcHJvZHVjZXIodGFnKSBmb3IgZWFjaCBrZXkuXG4gICAgaWYgKHVzZVNpbmdsZUtleSkge1xuICAgICAgbGV0IHRhZyA9IHRhZ3NbMF07XG4gICAgICBvcHRpb25zLmtpZCA9IHRhZzsgICAvLyBCYXNoZXMgb3B0aW9ucyBpbiB0aGUgc2luZ2xlLWtleSBjYXNlLCBiZWNhdXNlIG11bHRpS2V5J3MgaGF2ZSB0aGVpciBvd24uXG4gICAgICByZXR1cm4gcHJvZHVjZXIodGFnKTtcbiAgICB9XG4gICAgbGV0IGtleSA9IHt9LFxuICAgICAgICBrZXlzID0gYXdhaXQgUHJvbWlzZS5hbGwodGFncy5tYXAodGFnID0+IHByb2R1Y2VyKHRhZykpKTtcbiAgICAvLyBUaGlzIGlzbid0IGRvbmUgaW4gb25lIHN0ZXAsIGJlY2F1c2Ugd2UnZCBsaWtlIChmb3IgZGVidWdnaW5nIGFuZCB1bml0IHRlc3RzKSB0byBtYWludGFpbiBhIHByZWRpY3RhYmxlIG9yZGVyLlxuICAgIHRhZ3MuZm9yRWFjaCgodGFnLCBpbmRleCkgPT4ga2V5W3RhZ10gPSBrZXlzW2luZGV4XSk7XG4gICAgcmV0dXJuIGtleTtcbiAgfVxuICAvLyBUaGUgY29ycmVzcG9uZGluZyBwdWJsaWMga2V5cyBhcmUgYXZhaWxhYmxlIHB1YmxpY2FsbHksIG91dHNpZGUgdGhlIGtleVNldC5cbiAgc3RhdGljIHZlcmlmeWluZ0tleSh0YWcpIHsgLy8gUHJvbWlzZSB0aGUgb3JkaW5hcnkgc2luZ3VsYXIgcHVibGljIGtleSBjb3JyZXNwb25kaW5nIHRvIHRoZSBzaWduaW5nIGtleSwgZGlyZWN0bHkgZnJvbSB0aGUgdGFnIHdpdGhvdXQgcmVmZXJlbmNlIHRvIHN0b3JhZ2UuXG4gICAgcmV0dXJuIE11bHRpS3J5cHRvLmltcG9ydFJhdyh0YWcpLmNhdGNoKCgpID0+IHVuYXZhaWxhYmxlKHRhZykpO1xuICB9XG4gIHN0YXRpYyBhc3luYyBlbmNyeXB0aW5nS2V5KHRhZykgeyAvLyBQcm9taXNlIHRoZSBvcmRpbmFyeSBzaW5ndWxhciBwdWJsaWMga2V5IGNvcnJlc3BvbmRpbmcgdG8gdGhlIGRlY3J5cHRpb24ga2V5LCB3aGljaCBkZXBlbmRzIG9uIHB1YmxpYyBzdG9yYWdlLlxuICAgIGxldCBleHBvcnRlZFB1YmxpY0tleSA9IGF3YWl0IHRoaXMucmV0cmlldmUoJ0VuY3J5cHRpb25LZXknLCB0YWcpO1xuICAgIGlmICghZXhwb3J0ZWRQdWJsaWNLZXkpIHJldHVybiB1bmF2YWlsYWJsZSh0YWcpO1xuICAgIHJldHVybiBhd2FpdCBNdWx0aUtyeXB0by5pbXBvcnRKV0soZXhwb3J0ZWRQdWJsaWNLZXkuanNvbik7XG4gIH1cbiAgc3RhdGljIGFzeW5jIGNyZWF0ZUtleXMobWVtYmVyVGFncykgeyAvLyBQcm9taXNlIGEgbmV3IHRhZyBhbmQgcHJpdmF0ZSBrZXlzLCBhbmQgc3RvcmUgdGhlIGVuY3J5cHRpbmcga2V5LlxuICAgIGxldCB7cHVibGljS2V5OnZlcmlmeWluZ0tleSwgcHJpdmF0ZUtleTpzaWduaW5nS2V5fSA9IGF3YWl0IE11bHRpS3J5cHRvLmdlbmVyYXRlU2lnbmluZ0tleSgpLFxuICAgICAgICB7cHVibGljS2V5OmVuY3J5cHRpbmdLZXksIHByaXZhdGVLZXk6ZGVjcnlwdGluZ0tleX0gPSBhd2FpdCBNdWx0aUtyeXB0by5nZW5lcmF0ZUVuY3J5cHRpbmdLZXkoKSxcbiAgICAgICAgdGFnID0gYXdhaXQgTXVsdGlLcnlwdG8uZXhwb3J0UmF3KHZlcmlmeWluZ0tleSksXG4gICAgICAgIGV4cG9ydGVkRW5jcnlwdGluZ0tleSA9IGF3YWl0IE11bHRpS3J5cHRvLmV4cG9ydEpXSyhlbmNyeXB0aW5nS2V5KSxcbiAgICAgICAgdGltZSA9IERhdGUubm93KCksXG4gICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IHRoaXMuc2lnbkZvclN0b3JhZ2Uoe21lc3NhZ2U6IGV4cG9ydGVkRW5jcnlwdGluZ0tleSwgdGFnLCBzaWduaW5nS2V5LCBtZW1iZXJUYWdzLCB0aW1lLCByZWNvdmVyeTogdHJ1ZX0pO1xuICAgIGF3YWl0IHRoaXMuc3RvcmUoJ0VuY3J5cHRpb25LZXknLCB0YWcsIHNpZ25hdHVyZSk7XG4gICAgcmV0dXJuIHtzaWduaW5nS2V5LCBkZWNyeXB0aW5nS2V5LCB0YWcsIHRpbWV9O1xuICB9XG4gIHN0YXRpYyBnZXRXcmFwcGVkKHRhZykgeyAvLyBQcm9taXNlIHRoZSB3cmFwcGVkIGtleSBhcHByb3ByaWF0ZSBmb3IgdGhpcyBjbGFzcy5cbiAgICByZXR1cm4gdGhpcy5yZXRyaWV2ZSh0aGlzLmNvbGxlY3Rpb24sIHRhZyk7XG4gIH1cbiAgc3RhdGljIGFzeW5jIGVuc3VyZSh0YWcsIHtkZXZpY2UgPSB0cnVlLCB0ZWFtID0gdHJ1ZSwgcmVjb3ZlcnkgPSBmYWxzZX0gPSB7fSkgeyAvLyBQcm9taXNlIHRvIHJlc29sdmUgdG8gYSB2YWxpZCBrZXlTZXQsIGVsc2UgcmVqZWN0LlxuICAgIGxldCBrZXlTZXQgPSB0aGlzLmNhY2hlZCh0YWcpLFxuICAgICAgICBzdG9yZWQgPSBkZXZpY2UgJiYgYXdhaXQgRGV2aWNlS2V5U2V0LmdldFdyYXBwZWQodGFnKTtcbiAgICBpZiAoc3RvcmVkKSB7XG4gICAgICBrZXlTZXQgPSBuZXcgRGV2aWNlS2V5U2V0KHRhZyk7XG4gICAgfSBlbHNlIGlmICh0ZWFtICYmIChzdG9yZWQgPSBhd2FpdCBUZWFtS2V5U2V0LmdldFdyYXBwZWQodGFnKSkpIHtcbiAgICAgIGtleVNldCA9IG5ldyBUZWFtS2V5U2V0KHRhZyk7XG4gICAgfSBlbHNlIGlmIChyZWNvdmVyeSAmJiAoc3RvcmVkID0gYXdhaXQgUmVjb3ZlcnlLZXlTZXQuZ2V0V3JhcHBlZCh0YWcpKSkgeyAvLyBMYXN0LCBpZiBhdCBhbGwuXG4gICAgICBrZXlTZXQgPSBuZXcgUmVjb3ZlcnlLZXlTZXQodGFnKTtcbiAgICB9XG4gICAgLy8gSWYgdGhpbmdzIGhhdmVuJ3QgY2hhbmdlZCwgZG9uJ3QgYm90aGVyIHdpdGggc2V0VW53cmFwcGVkLlxuICAgIGlmIChrZXlTZXQ/LmNhY2hlZCAmJiBrZXlTZXQuY2FjaGVkID09PSBzdG9yZWQgJiYga2V5U2V0LmRlY3J5cHRpbmdLZXkgJiYga2V5U2V0LnNpZ25pbmdLZXkpIHJldHVybiBrZXlTZXQ7XG4gICAgaWYgKHN0b3JlZCkga2V5U2V0LmNhY2hlZCA9IHN0b3JlZDtcbiAgICBlbHNlIHsgLy8gTm90IGZvdW5kLiBDb3VsZCBiZSBhIGJvZ3VzIHRhZywgb3Igb25lIG9uIGFub3RoZXIgY29tcHV0ZXIuXG4gICAgICB0aGlzLmNsZWFyKHRhZyk7XG4gICAgICByZXR1cm4gdW5hdmFpbGFibGUodGFnKTtcbiAgICB9XG4gICAgcmV0dXJuIGtleVNldC51bndyYXAoa2V5U2V0LmNhY2hlZCkudGhlbihcbiAgICAgIHVud3JhcHBlZCA9PiBPYmplY3QuYXNzaWduKGtleVNldCwgdW53cmFwcGVkKSxcbiAgICAgIGNhdXNlID0+IHtcbiAgICAgICAgdGhpcy5jbGVhcihrZXlTZXQudGFnKVxuICAgICAgICByZXR1cm4gZXJyb3IodGFnID0+IGBZb3UgZG8gbm90IGhhdmUgYWNjZXNzIHRvIHRoZSBwcml2YXRlIGtleSBmb3IgJHt0YWd9LmAsIGtleVNldC50YWcsIGNhdXNlKTtcbiAgICAgIH0pO1xuICB9XG4gIHN0YXRpYyBlbnN1cmUxKHRhZ3MpIHsgLy8gRmluZCBvbmUgdmFsaWQga2V5U2V0IGFtb25nIHRhZ3MsIHVzaW5nIHJlY292ZXJ5IHRhZ3Mgb25seSBpZiBuZWNlc3NhcnkuXG4gICAgcmV0dXJuIFByb21pc2UuYW55KHRhZ3MubWFwKHRhZyA9PiBLZXlTZXQuZW5zdXJlKHRhZykpKVxuICAgICAgLmNhdGNoKGFzeW5jIHJlYXNvbiA9PiB7IC8vIElmIHdlIGZhaWxlZCwgdHJ5IHRoZSByZWNvdmVyeSB0YWdzLCBpZiBhbnksIG9uZSBhdCBhIHRpbWUuXG4gICAgICAgIGZvciAobGV0IGNhbmRpZGF0ZSBvZiB0YWdzKSB7XG4gICAgICAgICAgbGV0IGtleVNldCA9IGF3YWl0IEtleVNldC5lbnN1cmUoY2FuZGlkYXRlLCB7ZGV2aWNlOiBmYWxzZSwgdGVhbTogZmFsc2UsIHJlY292ZXJ5OiB0cnVlfSkuY2F0Y2goKCkgPT4gbnVsbCk7XG4gICAgICAgICAgaWYgKGtleVNldCkgcmV0dXJuIGtleVNldDtcbiAgICAgICAgfVxuICAgICAgICB0aHJvdyByZWFzb247XG4gICAgICB9KTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgcGVyc2lzdCh0YWcsIGtleXMsIHdyYXBwaW5nRGF0YSwgdGltZSA9IERhdGUubm93KCksIG1lbWJlclRhZ3MgPSB3cmFwcGluZ0RhdGEpIHsgLy8gUHJvbWlzZSB0byB3cmFwIGEgc2V0IG9mIGtleXMgZm9yIHRoZSB3cmFwcGluZ0RhdGEgbWVtYmVycywgYW5kIHBlcnNpc3QgYnkgdGFnLlxuICAgIGxldCB7c2lnbmluZ0tleX0gPSBrZXlzLFxuICAgICAgICB3cmFwcGVkID0gYXdhaXQgdGhpcy53cmFwKGtleXMsIHdyYXBwaW5nRGF0YSksXG4gICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IHRoaXMuc2lnbkZvclN0b3JhZ2Uoe21lc3NhZ2U6IHdyYXBwZWQsIHRhZywgc2lnbmluZ0tleSwgbWVtYmVyVGFncywgdGltZSwgcmVjb3Zlcnk6IHRydWV9KTtcbiAgICBhd2FpdCB0aGlzLnN0b3JlKHRoaXMuY29sbGVjdGlvbiwgdGFnLCBzaWduYXR1cmUpO1xuICB9XG5cbiAgLy8gSW50ZXJhY3Rpb25zIHdpdGggdGhlIGNsb3VkIG9yIGxvY2FsIHN0b3JhZ2UuXG4gIHN0YXRpYyBhc3luYyBzdG9yZShjb2xsZWN0aW9uTmFtZSwgdGFnLCBzaWduYXR1cmUpIHsgLy8gU3RvcmUgc2lnbmF0dXJlLlxuICAgIGlmIChjb2xsZWN0aW9uTmFtZSA9PT0gRGV2aWNlS2V5U2V0LmNvbGxlY3Rpb24pIHtcbiAgICAgIC8vIFdlIGNhbGxlZCB0aGlzLiBObyBuZWVkIHRvIHZlcmlmeSBoZXJlLiBCdXQgc2VlIHJldHJpZXZlKCkuXG4gICAgICBpZiAoTXVsdGlLcnlwdG8uaXNFbXB0eUpXU1BheWxvYWQoc2lnbmF0dXJlKSkgcmV0dXJuIExvY2FsU3RvcmUucmVtb3ZlKHRhZyk7XG4gICAgICByZXR1cm4gTG9jYWxTdG9yZS5zdG9yZSh0YWcsIHNpZ25hdHVyZSk7XG4gICAgfVxuICAgIHJldHVybiBLZXlTZXQuU3RvcmFnZS5zdG9yZShjb2xsZWN0aW9uTmFtZSwgdGFnLCBzaWduYXR1cmUpO1xuICB9XG4gIHN0YXRpYyBhc3luYyByZXRyaWV2ZShjb2xsZWN0aW9uTmFtZSwgdGFnKSB7ICAvLyBHZXQgYmFjayBhIHZlcmlmaWVkIHJlc3VsdC5cbiAgICBsZXQgcHJvbWlzZSA9IChjb2xsZWN0aW9uTmFtZSA9PT0gRGV2aWNlS2V5U2V0LmNvbGxlY3Rpb24pID8gTG9jYWxTdG9yZS5yZXRyaWV2ZSh0YWcpIDogS2V5U2V0LlN0b3JhZ2UucmV0cmlldmUoY29sbGVjdGlvbk5hbWUsIHRhZyksXG4gICAgICAgIHNpZ25hdHVyZSA9IGF3YWl0IHByb21pc2UsXG4gICAgICAgIGtleSA9IHNpZ25hdHVyZSAmJiBhd2FpdCBLZXlTZXQudmVyaWZ5aW5nS2V5KHRhZyk7XG4gICAgaWYgKCFzaWduYXR1cmUpIHJldHVybjtcbiAgICAvLyBXaGlsZSB3ZSByZWx5IG9uIHRoZSBTdG9yYWdlIGFuZCBMb2NhbFN0b3JlIGltcGxlbWVudGF0aW9ucyB0byBkZWVwbHkgY2hlY2sgc2lnbmF0dXJlcyBkdXJpbmcgd3JpdGUsXG4gICAgLy8gaGVyZSB3ZSBzdGlsbCBkbyBhIHNoYWxsb3cgdmVyaWZpY2F0aW9uIGNoZWNrIGp1c3QgdG8gbWFrZSBzdXJlIHRoYXQgdGhlIGRhdGEgaGFzbid0IGJlZW4gbWVzc2VkIHdpdGggYWZ0ZXIgd3JpdGUuXG4gICAgaWYgKHNpZ25hdHVyZS5zaWduYXR1cmVzKSBrZXkgPSB7W3RhZ106IGtleX07IC8vIFByZXBhcmUgYSBtdWx0aS1rZXlcbiAgICByZXR1cm4gYXdhaXQgTXVsdGlLcnlwdG8udmVyaWZ5KGtleSwgc2lnbmF0dXJlKTtcbiAgfVxufVxuXG5leHBvcnQgY2xhc3MgU2VjcmV0S2V5U2V0IGV4dGVuZHMgS2V5U2V0IHsgLy8gS2V5cyBhcmUgZW5jcnlwdGVkIGJhc2VkIG9uIGEgc3ltbWV0cmljIHNlY3JldC5cbiAgc3RhdGljIHNpZ25Gb3JTdG9yYWdlKHttZXNzYWdlLCB0YWcsIHNpZ25pbmdLZXksIHRpbWV9KSB7XG4gICAgLy8gQ3JlYXRlIGEgc2ltcGxlIHNpZ25hdHVyZSB0aGF0IGRvZXMgbm90IHNwZWNpZnkgaXNzIG9yIGFjdC5cbiAgICAvLyBUaGVyZSBhcmUgbm8gdHJ1ZSBtZW1iZXJUYWdzIHRvIHBhc3Mgb24gYW5kIHRoZXkgYXJlIG5vdCB1c2VkIGluIHNpbXBsZSBzaWduYXR1cmVzLiBIb3dldmVyLCB0aGUgY2FsbGVyIGRvZXNcbiAgICAvLyBnZW5lcmljYWxseSBwYXNzIHdyYXBwaW5nRGF0YSBhcyBtZW1iZXJUYWdzLCBhbmQgZm9yIFJlY292ZXJ5S2V5U2V0cywgd3JhcHBpbmdEYXRhIGlzIHRoZSBwcm9tcHQuIFxuICAgIC8vIFdlIGRvbid0IHN0b3JlIG11bHRpcGxlIHRpbWVzLCBzbyB0aGVyZSdzIGFsc28gbm8gbmVlZCBmb3IgaWF0ICh3aGljaCBjYW4gYmUgdXNlZCB0byBwcmV2ZW50IHJlcGxheSBhdHRhY2tzKS5cbiAgICByZXR1cm4gdGhpcy5zaWduKG1lc3NhZ2UsIHt0YWdzOiBbdGFnXSwgc2lnbmluZ0tleSwgdGltZX0pO1xuICB9XG4gIHN0YXRpYyBhc3luYyB3cmFwcGluZ0tleSh0YWcsIHByb21wdCkgeyAvLyBUaGUga2V5IHVzZWQgdG8gKHVuKXdyYXAgdGhlIHZhdWx0IG11bHRpLWtleS5cbiAgICBsZXQgc2VjcmV0ID0gIGF3YWl0IHRoaXMuZ2V0U2VjcmV0KHRhZywgcHJvbXB0KTtcbiAgICAvLyBBbHRlcm5hdGl2ZWx5LCBvbmUgY291bGQgdXNlIHtbd3JhcHBpbmdEYXRhXTogc2VjcmV0fSwgYnV0IHRoYXQncyBhIGJpdCB0b28gY3V0ZSwgYW5kIGdlbmVyYXRlcyBhIGdlbmVyYWwgZm9ybSBlbmNyeXB0aW9uLlxuICAgIC8vIFRoaXMgdmVyc2lvbiBnZW5lcmF0ZXMgYSBjb21wYWN0IGZvcm0gZW5jcnlwdGlvbi5cbiAgICByZXR1cm4gTXVsdGlLcnlwdG8uZ2VuZXJhdGVTZWNyZXRLZXkoc2VjcmV0KTtcbiAgfVxuICBzdGF0aWMgYXN5bmMgd3JhcChrZXlzLCBwcm9tcHQgPSAnJykgeyAvLyBFbmNyeXB0IGtleXNldCBieSBnZXRVc2VyRGV2aWNlU2VjcmV0LlxuICAgIGxldCB7ZGVjcnlwdGluZ0tleSwgc2lnbmluZ0tleSwgdGFnfSA9IGtleXMsXG4gICAgICAgIHZhdWx0S2V5ID0ge2RlY3J5cHRpbmdLZXksIHNpZ25pbmdLZXl9LFxuICAgICAgICB3cmFwcGluZ0tleSA9IGF3YWl0IHRoaXMud3JhcHBpbmdLZXkodGFnLCBwcm9tcHQpO1xuICAgIHJldHVybiBNdWx0aUtyeXB0by53cmFwS2V5KHZhdWx0S2V5LCB3cmFwcGluZ0tleSwge3Byb21wdH0pOyAvLyBPcmRlciBpcyBiYWNrd2FyZHMgZnJvbSBlbmNyeXB0LlxuICB9XG4gIGFzeW5jIHVud3JhcCh3cmFwcGVkS2V5KSB7IC8vIERlY3J5cHQga2V5c2V0IGJ5IGdldFVzZXJEZXZpY2VTZWNyZXQuXG4gICAgbGV0IHBhcnNlZCA9IHdyYXBwZWRLZXkuanNvbiB8fCB3cmFwcGVkS2V5LnRleHQsIC8vIEhhbmRsZSBib3RoIGpzb24gYW5kIGNvcGFjdCBmb3JtcyBvZiB3cmFwcGVkS2V5LlxuXG4gICAgICAgIC8vIFRoZSBjYWxsIHRvIHdyYXBLZXksIGFib3ZlLCBleHBsaWNpdGx5IGRlZmluZXMgdGhlIHByb21wdCBpbiB0aGUgaGVhZGVyIG9mIHRoZSBlbmNyeXB0aW9uLlxuICAgICAgICBwcm90ZWN0ZWRIZWFkZXIgPSBNdWx0aUtyeXB0by5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIocGFyc2VkKSxcbiAgICAgICAgcHJvbXB0ID0gcHJvdGVjdGVkSGVhZGVyLnByb21wdCwgLy8gSW4gdGhlIFwiY3V0ZVwiIGZvcm0gb2Ygd3JhcHBpbmdLZXksIHByb21wdCBjYW4gYmUgcHVsbGVkIGZyb20gcGFyc2VkLnJlY2lwaWVudHNbMF0uaGVhZGVyLmtpZCxcblxuICAgICAgICB3cmFwcGluZ0tleSA9IGF3YWl0IHRoaXMuY29uc3RydWN0b3Iud3JhcHBpbmdLZXkodGhpcy50YWcsIHByb21wdCksXG4gICAgICAgIGV4cG9ydGVkID0gKGF3YWl0IE11bHRpS3J5cHRvLmRlY3J5cHQod3JhcHBpbmdLZXksIHBhcnNlZCkpLmpzb247XG4gICAgcmV0dXJuIGF3YWl0IE11bHRpS3J5cHRvLmltcG9ydEpXSyhleHBvcnRlZCwge2RlY3J5cHRpbmdLZXk6ICdkZWNyeXB0Jywgc2lnbmluZ0tleTogJ3NpZ24nfSk7XG4gIH1cbiAgc3RhdGljIGFzeW5jIGdldFNlY3JldCh0YWcsIHByb21wdCkgeyAvLyBnZXRVc2VyRGV2aWNlU2VjcmV0IGZyb20gYXBwLlxuICAgIHJldHVybiBLZXlTZXQuZ2V0VXNlckRldmljZVNlY3JldCh0YWcsIHByb21wdCk7XG4gIH1cbn1cblxuIC8vIFRoZSB1c2VyJ3MgYW5zd2VyKHMpIHRvIGEgc2VjdXJpdHkgcXVlc3Rpb24gZm9ybXMgYSBzZWNyZXQsIGFuZCB0aGUgd3JhcHBlZCBrZXlzIGlzIHN0b3JlZCBpbiB0aGUgY2xvdWRlLlxuZXhwb3J0IGNsYXNzIFJlY292ZXJ5S2V5U2V0IGV4dGVuZHMgU2VjcmV0S2V5U2V0IHtcbiAgc3RhdGljIGNvbGxlY3Rpb24gPSAnS2V5UmVjb3ZlcnknO1xufVxuXG4vLyBBIEtleVNldCBjb3JyZXNwb25kaW5nIHRvIHRoZSBjdXJyZW50IGhhcmR3YXJlLiBXcmFwcGluZyBzZWNyZXQgY29tZXMgZnJvbSB0aGUgYXBwLlxuZXhwb3J0IGNsYXNzIERldmljZUtleVNldCBleHRlbmRzIFNlY3JldEtleVNldCB7XG4gIHN0YXRpYyBjb2xsZWN0aW9uID0gJ0RldmljZSc7XG59XG5jb25zdCBMb2NhbFN0b3JlID0gbmV3IExvY2FsQ29sbGVjdGlvbih7Y29sbGVjdGlvbk5hbWU6IERldmljZUtleVNldC5jb2xsZWN0aW9ufSk7XG5cbmV4cG9ydCBjbGFzcyBUZWFtS2V5U2V0IGV4dGVuZHMgS2V5U2V0IHsgLy8gQSBLZXlTZXQgY29ycmVzcG9uZGluZyB0byBhIHRlYW0gb2Ygd2hpY2ggdGhlIGN1cnJlbnQgdXNlciBpcyBhIG1lbWJlciAoaWYgZ2V0VGFnKCkpLlxuICBzdGF0aWMgY29sbGVjdGlvbiA9ICdUZWFtJztcbiAgc3RhdGljIHNpZ25Gb3JTdG9yYWdlKHttZXNzYWdlLCB0YWcsIC4uLm9wdGlvbnN9KSB7XG4gICAgcmV0dXJuIHRoaXMuc2lnbihtZXNzYWdlLCB7dGVhbTogdGFnLCAuLi5vcHRpb25zfSk7XG4gIH1cbiAgc3RhdGljIGFzeW5jIHdyYXAoa2V5cywgbWVtYmVycykge1xuICAgIC8vIFRoaXMgaXMgdXNlZCBieSBwZXJzaXN0LCB3aGljaCBpbiB0dXJuIGlzIHVzZWQgdG8gY3JlYXRlIGFuZCBjaGFuZ2VNZW1iZXJzaGlwLlxuICAgIGxldCB7ZGVjcnlwdGluZ0tleSwgc2lnbmluZ0tleX0gPSBrZXlzLFxuICAgICAgICB0ZWFtS2V5ID0ge2RlY3J5cHRpbmdLZXksIHNpZ25pbmdLZXl9LFxuICAgICAgICB3cmFwcGluZ0tleSA9IHt9O1xuICAgIGF3YWl0IFByb21pc2UuYWxsKG1lbWJlcnMubWFwKG1lbWJlclRhZyA9PiBLZXlTZXQuZW5jcnlwdGluZ0tleShtZW1iZXJUYWcpLnRoZW4oa2V5ID0+IHdyYXBwaW5nS2V5W21lbWJlclRhZ10gPSBrZXkpKSk7XG4gICAgbGV0IHdyYXBwZWRUZWFtID0gYXdhaXQgTXVsdGlLcnlwdG8ud3JhcEtleSh0ZWFtS2V5LCB3cmFwcGluZ0tleSk7XG4gICAgcmV0dXJuIHdyYXBwZWRUZWFtO1xuICB9XG4gIGFzeW5jIHVud3JhcCh3cmFwcGVkKSB7XG4gICAgbGV0IHtyZWNpcGllbnRzfSA9IHdyYXBwZWQuanNvbixcbiAgICAgICAgbWVtYmVyVGFncyA9IHRoaXMubWVtYmVyVGFncyA9IHJlY2lwaWVudHMubWFwKHJlY2lwaWVudCA9PiByZWNpcGllbnQuaGVhZGVyLmtpZCk7XG4gICAgbGV0IGtleVNldCA9IGF3YWl0IHRoaXMuY29uc3RydWN0b3IuZW5zdXJlMShtZW1iZXJUYWdzKTsgLy8gV2Ugd2lsbCB1c2UgcmVjb3ZlcnkgdGFncyBvbmx5IGlmIHdlIG5lZWQgdG8uXG4gICAgbGV0IGRlY3J5cHRlZCA9IGF3YWl0IGtleVNldC5kZWNyeXB0KHdyYXBwZWQuanNvbik7XG4gICAgcmV0dXJuIGF3YWl0IE11bHRpS3J5cHRvLmltcG9ydEpXSyhkZWNyeXB0ZWQuanNvbik7XG4gIH1cbiAgYXN5bmMgY2hhbmdlTWVtYmVyc2hpcCh7YWRkID0gW10sIHJlbW92ZSA9IFtdfSA9IHt9KSB7XG4gICAgbGV0IHttZW1iZXJUYWdzfSA9IHRoaXMsXG4gICAgICAgIG5ld01lbWJlcnMgPSBtZW1iZXJUYWdzLmNvbmNhdChhZGQpLmZpbHRlcih0YWcgPT4gIXJlbW92ZS5pbmNsdWRlcyh0YWcpKTtcbiAgICBhd2FpdCB0aGlzLmNvbnN0cnVjdG9yLnBlcnNpc3QodGhpcy50YWcsIHRoaXMsIG5ld01lbWJlcnMsIERhdGUubm93KCksIG1lbWJlclRhZ3MpO1xuICAgIHRoaXMubWVtYmVyVGFncyA9IG5ld01lbWJlcnM7XG4gIH1cbn1cbiIsIi8vIEJlY2F1c2UgZXNsaW50IGRvZXNuJ3QgcmVjb2duaXplIGltcG9ydCBhc3NlcnRpb25zXG5pbXBvcnQgKiBhcyBwa2cgZnJvbSBcIi4uL3BhY2thZ2UuanNvblwiIHdpdGggeyB0eXBlOiAnanNvbicgfTtcbmV4cG9ydCBjb25zdCB7bmFtZSwgdmVyc2lvbn0gPSBwa2cuZGVmYXVsdDtcbiIsImltcG9ydCBNdWx0aUtyeXB0byBmcm9tIFwiLi9tdWx0aUtyeXB0by5tanNcIjtcbmltcG9ydCB7S2V5U2V0LCBEZXZpY2VLZXlTZXQsIFJlY292ZXJ5S2V5U2V0LCBUZWFtS2V5U2V0fSBmcm9tIFwiLi9rZXlTZXQubWpzXCI7XG5pbXBvcnQge25hbWUsIHZlcnNpb259IGZyb20gXCIuL3BhY2thZ2UtbG9hZGVyLm1qc1wiO1xuXG5jb25zdCBTZWN1cml0eSA9IHsgLy8gVGhpcyBpcyB0aGUgYXBpIGZvciB0aGUgdmF1bHQuIFNlZSBodHRwczovL2tpbHJveS1jb2RlLmdpdGh1Yi5pby9kaXN0cmlidXRlZC1zZWN1cml0eS9kb2NzL2ltcGxlbWVudGF0aW9uLmh0bWwjY3JlYXRpbmctdGhlLXZhdWx0LXdlYi13b3JrZXItYW5kLWlmcmFtZVxuXG4gIC8vIENsaWVudC1kZWZpbmVkIHJlc291cmNlcy5cbiAgc2V0IFN0b3JhZ2Uoc3RvcmFnZSkgeyAvLyBBbGxvd3MgYSBub2RlIGFwcCAobm8gdmF1bHR0KSB0byBvdmVycmlkZSB0aGUgZGVmYXVsdCBzdG9yYWdlLlxuICAgIEtleVNldC5TdG9yYWdlID0gc3RvcmFnZTtcbiAgfSxcbiAgZ2V0IFN0b3JhZ2UoKSB7IC8vIEFsbG93cyBhIG5vZGUgYXBwIChubyB2YXVsdCkgdG8gZXhhbWluZSBzdG9yYWdlLlxuICAgIHJldHVybiBLZXlTZXQuU3RvcmFnZTtcbiAgfSxcbiAgc2V0IGdldFVzZXJEZXZpY2VTZWNyZXQoZnVuY3Rpb25PZlRhZ0FuZFByb21wdCkgeyAgLy8gQWxsb3dzIGEgbm9kZSBhcHAgKG5vIHZhdWx0KSB0byBvdmVycmlkZSB0aGUgZGVmYXVsdC5cbiAgICBLZXlTZXQuZ2V0VXNlckRldmljZVNlY3JldCA9IGZ1bmN0aW9uT2ZUYWdBbmRQcm9tcHQ7XG4gIH0sXG4gIGdldCBnZXRVc2VyRGV2aWNlU2VjcmV0KCkge1xuICAgIHJldHVybiBLZXlTZXQuZ2V0VXNlckRldmljZVNlY3JldDtcbiAgfSxcbiAgcmVhZHk6IHtuYW1lLCB2ZXJzaW9uLCBvcmlnaW46IEtleVNldC5TdG9yYWdlLm9yaWdpbn0sXG5cbiAgLy8gVGhlIGZvdXIgYmFzaWMgb3BlcmF0aW9ucy4gLi4ucmVzdCBtYXkgYmUgb25lIG9yIG1vcmUgdGFncywgb3IgbWF5IGJlIHt0YWdzLCB0ZWFtLCBtZW1iZXIsIGNvbnRlbnRUeXBlLCAuLi59XG4gIGFzeW5jIGVuY3J5cHQobWVzc2FnZSwgLi4ucmVzdCkgeyAvLyBQcm9taXNlIGEgSldFLlxuICAgIGxldCBvcHRpb25zID0ge30sIHRhZ3MgPSB0aGlzLmNhbm9uaWNhbGl6ZVBhcmFtZXRlcnMocmVzdCwgb3B0aW9ucyksXG4gICAgICAgIGtleSA9IGF3YWl0IEtleVNldC5wcm9kdWNlS2V5KHRhZ3MsIHRhZyA9PiBLZXlTZXQuZW5jcnlwdGluZ0tleSh0YWcpLCBvcHRpb25zKTtcbiAgICByZXR1cm4gTXVsdGlLcnlwdG8uZW5jcnlwdChrZXksIG1lc3NhZ2UsIG9wdGlvbnMpO1xuICB9LFxuICBhc3luYyBkZWNyeXB0KGVuY3J5cHRlZCwgLi4ucmVzdCkgeyAvLyBQcm9taXNlIHtwYXlsb2FkLCB0ZXh0LCBqc29ufSBhcyBhcHByb3ByaWF0ZS5cbiAgICBsZXQgb3B0aW9ucyA9IHt9LFxuICAgICAgICBbdGFnXSA9IHRoaXMuY2Fub25pY2FsaXplUGFyYW1ldGVycyhyZXN0LCBvcHRpb25zLCBlbmNyeXB0ZWQpLFxuICAgICAgICB7cmVjb3ZlcnksIC4uLm90aGVyT3B0aW9uc30gPSBvcHRpb25zLFxuICAgICAgICBrZXlTZXQgPSBhd2FpdCBLZXlTZXQuZW5zdXJlKHRhZywge3JlY292ZXJ5fSk7XG4gICAgcmV0dXJuIGtleVNldC5kZWNyeXB0KGVuY3J5cHRlZCwgb3RoZXJPcHRpb25zKTtcbiAgfSxcbiAgYXN5bmMgc2lnbihtZXNzYWdlLCAuLi5yZXN0KSB7IC8vIFByb21pc2UgYSBKV1MuXG4gICAgbGV0IG9wdGlvbnMgPSB7fSwgdGFncyA9IHRoaXMuY2Fub25pY2FsaXplUGFyYW1ldGVycyhyZXN0LCBvcHRpb25zKTtcbiAgICByZXR1cm4gS2V5U2V0LnNpZ24obWVzc2FnZSwge3RhZ3MsIC4uLm9wdGlvbnN9KTtcbiAgfSxcbiAgYXN5bmMgdmVyaWZ5KHNpZ25hdHVyZSwgLi4ucmVzdCkgeyAvLyBQcm9taXNlIHtwYXlsb2FkLCB0ZXh0LCBqc29ufSBhcyBhcHByb3ByaWF0ZS5cbiAgICBsZXQgb3B0aW9ucyA9IHt9LCB0YWdzID0gdGhpcy5jYW5vbmljYWxpemVQYXJhbWV0ZXJzKHJlc3QsIG9wdGlvbnMsIHNpZ25hdHVyZSk7XG4gICAgcmV0dXJuIEtleVNldC52ZXJpZnkoc2lnbmF0dXJlLCB0YWdzLCBvcHRpb25zKTtcbiAgfSxcblxuICAvLyBUYWcgbWFpbnRhbmNlLlxuICBhc3luYyBjcmVhdGUoLi4ubWVtYmVycykgeyAvLyBQcm9taXNlIGEgbmV3bHktY3JlYXRlZCB0YWcgd2l0aCB0aGUgZ2l2ZW4gbWVtYmVycy4gVGhlIG1lbWJlciB0YWdzIChpZiBhbnkpIG11c3QgYWxyZWFkeSBleGlzdC5cbiAgICBpZiAoIW1lbWJlcnMubGVuZ3RoKSByZXR1cm4gYXdhaXQgRGV2aWNlS2V5U2V0LmNyZWF0ZSgpO1xuICAgIGxldCBwcm9tcHQgPSBtZW1iZXJzWzBdLnByb21wdDtcbiAgICBpZiAocHJvbXB0KSByZXR1cm4gYXdhaXQgUmVjb3ZlcnlLZXlTZXQuY3JlYXRlKHByb21wdCk7XG4gICAgcmV0dXJuIGF3YWl0IFRlYW1LZXlTZXQuY3JlYXRlKG1lbWJlcnMpO1xuICB9LFxuICBhc3luYyBjaGFuZ2VNZW1iZXJzaGlwKHt0YWcsIHJlY292ZXJ5ID0gZmFsc2UsIC4uLm9wdGlvbnN9KSB7IC8vIFByb21pc2UgdG8gYWRkIG9yIHJlbW92ZSBtZW1iZXJzLlxuICAgIGxldCBrZXlTZXQgPSBhd2FpdCBLZXlTZXQuZW5zdXJlKHRhZywge3JlY292ZXJ5LCAuLi5vcHRpb25zfSk7IC8vIE1ha2VzIG5vIHNlbnNlIHRvIGNoYW5nZU1lbWJlcnNoaXAgb2YgYSByZWNvdmVyeSBrZXkuXG4gICAgcmV0dXJuIGtleVNldC5jaGFuZ2VNZW1iZXJzaGlwKG9wdGlvbnMpO1xuICB9LFxuICBhc3luYyBkZXN0cm95KHRhZ09yT3B0aW9ucykgeyAvLyBQcm9taXNlIHRvIHJlbW92ZSB0aGUgdGFnIGFuZCBhbnkgYXNzb2NpYXRlZCBkYXRhIGZyb20gYWxsIHN0b3JhZ2UuXG4gICAgaWYgKCdzdHJpbmcnID09PSB0eXBlb2YgdGFnT3JPcHRpb25zKSB0YWdPck9wdGlvbnMgPSB7dGFnOiB0YWdPck9wdGlvbnN9O1xuICAgIGxldCB7dGFnLCByZWNvdmVyeSA9IHRydWUsIC4uLm90aGVyT3B0aW9uc30gPSB0YWdPck9wdGlvbnMsXG4gICAgICAgIG9wdGlvbnMgPSB7cmVjb3ZlcnksIC4uLm90aGVyT3B0aW9uc30sXG4gICAgICAgIGtleVNldCA9IGF3YWl0IEtleVNldC5lbnN1cmUodGFnLCBvcHRpb25zKTtcbiAgICByZXR1cm4ga2V5U2V0LmRlc3Ryb3kob3B0aW9ucyk7XG4gIH0sXG4gIGNsZWFyKHRhZykgeyAvLyBSZW1vdmUgYW55IGxvY2FsbHkgY2FjaGVkIEtleVNldCBmb3IgdGhlIHRhZywgb3IgYWxsIEtleVNldHMgaWYgbm90IHRhZyBzcGVjaWZpZWQuXG4gICAgS2V5U2V0LmNsZWFyKHRhZyk7XG4gIH0sXG5cbiAgZGVjb2RlUHJvdGVjdGVkSGVhZGVyOiBNdWx0aUtyeXB0by5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIsXG4gIGNhbm9uaWNhbGl6ZVBhcmFtZXRlcnMocmVzdCwgb3B0aW9ucywgdG9rZW4pIHsgLy8gUmV0dXJuIHRoZSBhY3R1YWwgbGlzdCBvZiB0YWdzLCBhbmQgYmFzaCBvcHRpb25zLlxuICAgIC8vIHJlc3QgbWF5IGJlIGEgbGlzdCBvZiB0YWcgc3RyaW5nc1xuICAgIC8vICAgIG9yIGEgbGlzdCBvZiBvbmUgc2luZ2xlIG9iamVjdCBzcGVjaWZ5aW5nIG5hbWVkIHBhcmFtZXRlcnMsIGluY2x1ZGluZyBlaXRoZXIgdGVhbSwgdGFncywgb3IgbmVpdGhlclxuICAgIC8vIHRva2VuIG1heSBiZSBhIEpXRSBvciBKU0UsIG9yIGZhbHN5LCBhbmQgaXMgdXNlZCB0byBzdXBwbHkgdGFncyBpZiBuZWNlc3NhcnkuXG4gICAgaWYgKHJlc3QubGVuZ3RoID4gMSB8fCByZXN0WzBdPy5sZW5ndGggIT09IHVuZGVmaW5lZCkgcmV0dXJuIHJlc3Q7XG4gICAgbGV0IHt0YWdzID0gW10sIGNvbnRlbnRUeXBlLCB0aW1lLCAuLi5vdGhlcnN9ID0gcmVzdFswXSB8fCB7fSxcblx0e3RlYW19ID0gb3RoZXJzOyAvLyBEbyBub3Qgc3RyaXAgdGVhbSBmcm9tIG90aGVycy5cbiAgICBpZiAoIXRhZ3MubGVuZ3RoKSB7XG4gICAgICBpZiAocmVzdC5sZW5ndGggJiYgcmVzdFswXS5sZW5ndGgpIHRhZ3MgPSByZXN0OyAvLyByZXN0IG5vdCBlbXB0eSwgYW5kIGl0cyBmaXJzdCBpcyBzdHJpbmctbGlrZS5cbiAgICAgIGVsc2UgaWYgKHRva2VuKSB7IC8vIGdldCBmcm9tIHRva2VuXG4gICAgICAgIGlmICh0b2tlbi5zaWduYXR1cmVzKSB0YWdzID0gdG9rZW4uc2lnbmF0dXJlcy5tYXAoc2lnID0+IHRoaXMuZGVjb2RlUHJvdGVjdGVkSGVhZGVyKHNpZykua2lkKTtcbiAgICAgICAgZWxzZSBpZiAodG9rZW4ucmVjaXBpZW50cykgdGFncyA9IHRva2VuLnJlY2lwaWVudHMubWFwKHJlYyA9PiByZWMuaGVhZGVyLmtpZCk7XG4gICAgICAgIGVsc2Uge1xuICAgICAgICAgIGxldCBraWQgPSB0aGlzLmRlY29kZVByb3RlY3RlZEhlYWRlcih0b2tlbikua2lkOyAvLyBjb21wYWN0IHRva2VuXG4gICAgICAgICAgaWYgKGtpZCkgdGFncyA9IFtraWRdO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICAgIGlmICh0ZWFtICYmICF0YWdzLmluY2x1ZGVzKHRlYW0pKSB0YWdzID0gW3RlYW0sIC4uLnRhZ3NdO1xuICAgIGlmIChjb250ZW50VHlwZSkgb3B0aW9ucy5jdHkgPSBjb250ZW50VHlwZTtcbiAgICBpZiAodGltZSkgb3B0aW9ucy5pYXQgPSB0aW1lO1xuICAgIE9iamVjdC5hc3NpZ24ob3B0aW9ucywgb3RoZXJzKTtcblxuICAgIHJldHVybiB0YWdzO1xuICB9XG59O1xuXG5leHBvcnQgZGVmYXVsdCBTZWN1cml0eTtcbiIsIlxuZnVuY3Rpb24gdHJhbnNmZXJyYWJsZUVycm9yKGVycm9yKSB7IC8vIEFuIGVycm9yIG9iamVjdCB0aGF0IHdlIHJlY2VpdmUgb24gb3VyIHNpZGUgbWlnaHQgbm90IGJlIHRyYW5zZmVycmFibGUgdG8gdGhlIG90aGVyLlxuICBsZXQge25hbWUsIG1lc3NhZ2UsIGNvZGUsIGRhdGF9ID0gZXJyb3I7XG4gIHJldHVybiB7bmFtZSwgbWVzc2FnZSwgY29kZSwgZGF0YX07XG59XG5cbi8vIFNldCB1cCBiaWRpcmVjdGlvbmFsIGNvbW11bmNhdGlvbnMgd2l0aCB0YXJnZXQsIHJldHVybmluZyBhIGZ1bmN0aW9uIChtZXRob2ROYW1lLCAuLi5wYXJhbXMpIHRoYXQgd2lsbCBzZW5kIHRvIHRhcmdldC5cbmZ1bmN0aW9uIGRpc3BhdGNoKHt0YXJnZXQgPSBzZWxmLCAgICAgICAgLy8gVGhlIHdpbmRvdywgd29ya2VyLCBvciBvdGhlciBvYmplY3QgdG8gd2hpY2ggd2Ugd2lsbCBwb3N0TWVzc2FnZS5cblx0XHQgICByZWNlaXZlciA9IHRhcmdldCwgICAgLy8gVGhlIHdpbmRvdywgd29ya2VyLCBvciBvdGhlciBvYmplY3Qgb2Ygd2hpY2ggV0Ugd2lsbCBoYW5kbGUgJ21lc3NhZ2UnIGV2ZW50cyBmcm9tIHRhcmdldC5cblx0XHQgICBuYW1lc3BhY2UgPSByZWNlaXZlciwgLy8gQW4gb2JqZWN0IHRoYXQgZGVmaW5lcyBhbnkgbWV0aG9kcyB0aGF0IG1heSBiZSByZXF1ZXN0ZWQgYnkgdGFyZ2V0LlxuXG5cdFx0ICAgb3JpZ2luID0gKCh0YXJnZXQgIT09IHJlY2VpdmVyKSAmJiB0YXJnZXQubG9jYXRpb24ub3JpZ2luKSxcblxuXHRcdCAgIGRpc3BhdGNoZXJMYWJlbCA9IG5hbWVzcGFjZS5uYW1lIHx8IHJlY2VpdmVyLm5hbWUgfHwgcmVjZWl2ZXIubG9jYXRpb24/LmhyZWYgfHwgcmVjZWl2ZXIsXG5cdFx0ICAgdGFyZ2V0TGFiZWwgPSB0YXJnZXQubmFtZSB8fCBvcmlnaW4gfHwgdGFyZ2V0LmxvY2F0aW9uPy5ocmVmIHx8IHRhcmdldCxcblxuXHRcdCAgIGxvZyA9IG51bGwsXG5cdFx0ICAgaW5mbzpsb2dpbmZvID0gY29uc29sZS5pbmZvLmJpbmQoY29uc29sZSksXG5cdFx0ICAgd2Fybjpsb2d3YXJuID0gY29uc29sZS53YXJuLmJpbmQoY29uc29sZSksXG5cdFx0ICAgZXJyb3I6bG9nZXJyb3IgPSBjb25zb2xlLmVycm9yLmJpbmQoY29uc29sZSlcblx0XHQgIH0pIHtcbiAgY29uc3QgcmVxdWVzdHMgPSB7fSxcbiAgICAgICAganNvbnJwYyA9ICcyLjAnLFxuICAgICAgICBjYXB0dXJlZFBvc3QgPSB0YXJnZXQucG9zdE1lc3NhZ2UuYmluZCh0YXJnZXQpLCAvLyBJbiBjYXNlIChtYWxpY2lvdXMpIGNvZGUgbGF0ZXIgY2hhbmdlcyBpdC5cbiAgICAgICAgLy8gd2luZG93LnBvc3RNZXNzYWdlIGFuZCBmcmllbmRzIHRha2VzIGEgdGFyZ2V0T3JpZ2luIHRoYXQgd2Ugc3VwcGx5LlxuICAgICAgICAvLyBCdXQgd29ya2VyLnBvc3RNZXNzYWdlIGdpdmVzIGVycm9yIHJhdGhlciB0aGFuIGlnbm9yaW5nIHRoZSBleHRyYSBhcmcuIFNvIHNldCB0aGUgcmlnaHQgZm9ybSBhdCBpbml0aWFsaXphdGlvbi5cbiAgICAgICAgcG9zdCA9IG9yaWdpbiA/IG1lc3NhZ2UgPT4gY2FwdHVyZWRQb3N0KG1lc3NhZ2UsIG9yaWdpbikgOiBjYXB0dXJlZFBvc3QsXG4gICAgICAgIG51bGxMb2cgPSAoKSA9PiB7fTtcbiAgbGV0IG1lc3NhZ2VJZCA9IDA7IC8vIHByZS1pbmNyZW1lbnRlZCBpZCBzdGFydHMgYXQgMS5cblxuICBmdW5jdGlvbiByZXF1ZXN0KG1ldGhvZCwgLi4ucGFyYW1zKSB7IC8vIFByb21pc2UgdGhlIHJlc3VsdCBvZiBtZXRob2QoLi4ucGFyYW1zKSBpbiB0YXJnZXQuXG4gICAgLy8gV2UgZG8gYSB0YXJnZXQucG9zdE1lc3NhZ2Ugb2YgYSBqc29ucnBjIHJlcXVlc3QsIGFuZCByZXNvbHZlIHRoZSBwcm9taXNlIHdpdGggdGhlIHJlc3BvbnNlLCBtYXRjaGVkIGJ5IGlkLlxuICAgIC8vIElmIHRoZSB0YXJnZXQgaGFwcGVucyB0byBiZSBzZXQgdXAgYnkgYSBkaXNwYXRjaCBsaWtlIHRoaXMgb25lLCBpdCB3aWxsIHJlc3BvbmQgd2l0aCB3aGF0ZXZlciBpdCdzXG4gICAgLy8gbmFtZXNwYWNlW21ldGhvZF0oLi4ucGFyYW1zKSByZXNvbHZlcyB0by4gV2Ugb25seSBzZW5kIGpzb25ycGMgcmVxdWVzdHMgKHdpdGggYW4gaWQpLCBub3Qgbm90aWZpY2F0aW9ucyxcbiAgICAvLyBiZWNhdXNlIHRoZXJlIGlzIG5vIHdheSB0byBnZXQgZXJyb3JzIGJhY2sgZnJvbSBhIGpzb25ycGMgbm90aWZpY2F0aW9uLlxuICAgIGxldCBpZCA9ICsrbWVzc2FnZUlkLFxuXHRyZXF1ZXN0ID0gcmVxdWVzdHNbaWRdID0ge307XG4gICAgLy8gSXQgd291bGQgYmUgbmljZSB0byBub3QgbGVhayByZXF1ZXN0IG9iamVjdHMgaWYgdGhleSBhcmVuJ3QgYW5zd2VyZWQuXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICAgIGxvZz8uKGRpc3BhdGNoZXJMYWJlbCwgJ3JlcXVlc3QnLCBpZCwgbWV0aG9kLCBwYXJhbXMsICd0bycsIHRhcmdldExhYmVsKTtcbiAgICAgIE9iamVjdC5hc3NpZ24ocmVxdWVzdCwge3Jlc29sdmUsIHJlamVjdH0pO1xuICAgICAgcG9zdCh7aWQsIG1ldGhvZCwgcGFyYW1zLCBqc29ucnBjfSk7XG4gICAgfSk7XG4gIH1cblxuICBhc3luYyBmdW5jdGlvbiByZXNwb25kKGV2ZW50KSB7IC8vIEhhbmRsZSAnbWVzc2FnZScgZXZlbnRzIHRoYXQgd2UgcmVjZWl2ZSBmcm9tIHRhcmdldC5cbiAgICBsb2c/LihkaXNwYXRjaGVyTGFiZWwsICdnb3QgbWVzc2FnZScsIGV2ZW50LmRhdGEsICdmcm9tJywgdGFyZ2V0TGFiZWwsIGV2ZW50Lm9yaWdpbik7XG4gICAgbGV0IHtpZCwgbWV0aG9kLCBwYXJhbXMgPSBbXSwgcmVzdWx0LCBlcnJvciwganNvbnJwYzp2ZXJzaW9ufSA9IGV2ZW50LmRhdGEgfHwge307XG5cbiAgICAvLyBOb2lzaWx5IGlnbm9yZSBtZXNzYWdlcyB0aGF0IGFyZSBub3QgZnJvbSB0aGUgZXhwZWN0IHRhcmdldCBvciBvcmlnaW4sIG9yIHdoaWNoIGFyZSBub3QganNvbnJwYy5cbiAgICBpZiAoZXZlbnQuc291cmNlICYmIChldmVudC5zb3VyY2UgIT09IHRhcmdldCkpIHJldHVybiBsb2dlcnJvcj8uKGRpc3BhdGNoZXJMYWJlbCwgJ3RvJywgdGFyZ2V0TGFiZWwsICAnZ290IG1lc3NhZ2UgZnJvbScsIGV2ZW50LnNvdXJjZSk7XG4gICAgaWYgKG9yaWdpbiAmJiAob3JpZ2luICE9PSBldmVudC5vcmlnaW4pKSByZXR1cm4gbG9nZXJyb3I/LihkaXNwYXRjaGVyTGFiZWwsIG9yaWdpbiwgJ21pc21hdGNoZWQgb3JpZ2luJywgdGFyZ2V0TGFiZWwsIGV2ZW50Lm9yaWdpbik7XG4gICAgaWYgKHZlcnNpb24gIT09IGpzb25ycGMpIHJldHVybiBsb2d3YXJuPy4oYCR7ZGlzcGF0Y2hlckxhYmVsfSBpZ25vcmluZyBub24tanNvbnJwYyBtZXNzYWdlICR7SlNPTi5zdHJpbmdpZnkoZXZlbnQuZGF0YSl9LmApO1xuXG4gICAgaWYgKG1ldGhvZCkgeyAvLyBJbmNvbWluZyByZXF1ZXN0IG9yIG5vdGlmaWNhdGlvbiBmcm9tIHRhcmdldC5cbiAgICAgIGxldCBlcnJvciA9IG51bGwsIHJlc3VsdCxcbiAgICAgICAgICAvLyBqc29ucnBjIHJlcXVlc3Qvbm90aWZpY2F0aW9uIGNhbiBoYXZlIHBvc2l0aW9uYWwgYXJncyAoYXJyYXkpIG9yIG5hbWVkIGFyZ3MgKGEgUE9KTykuXG5cdCAgYXJncyA9IEFycmF5LmlzQXJyYXkocGFyYW1zKSA/IHBhcmFtcyA6IFtwYXJhbXNdOyAvLyBBY2NlcHQgZWl0aGVyLlxuICAgICAgdHJ5IHsgLy8gbWV0aG9kIHJlc3VsdCBtaWdodCBub3QgYmUgYSBwcm9taXNlLCBzbyB3ZSBjYW4ndCByZWx5IG9uIC5jYXRjaCgpLlxuICAgICAgICByZXN1bHQgPSBhd2FpdCBuYW1lc3BhY2VbbWV0aG9kXSguLi5hcmdzKTsgLy8gQ2FsbCB0aGUgbWV0aG9kLlxuICAgICAgfSBjYXRjaCAoZSkgeyAvLyBTZW5kIGJhY2sgYSBjbGVhbiB7bmFtZSwgbWVzc2FnZX0gb2JqZWN0LlxuICAgICAgICBlcnJvciA9IHRyYW5zZmVycmFibGVFcnJvcihlKTtcbiAgICAgICAgaWYgKCFuYW1lc3BhY2VbbWV0aG9kXSAmJiAhZXJyb3IubWVzc2FnZS5pbmNsdWRlcyhtZXRob2QpKSB7XG5cdCAgZXJyb3IubWVzc2FnZSA9IGAke21ldGhvZH0gaXMgbm90IGRlZmluZWQuYDsgLy8gQmUgbW9yZSBoZWxwZnVsIHRoYW4gc29tZSBicm93c2Vycy5cbiAgICAgICAgICBlcnJvci5jb2RlID0gLTMyNjAxOyAvLyBEZWZpbmVkIGJ5IGpzb24tcnBjIHNwZWMuXG4gICAgICAgIH0gZWxzZSBpZiAoIWVycm9yLm1lc3NhZ2UpIC8vIEl0IGhhcHBlbnMuIEUuZy4sIG9wZXJhdGlvbmFsIGVycm9ycyBmcm9tIGNyeXB0by5cblx0ICBlcnJvci5tZXNzYWdlID0gYCR7ZXJyb3IubmFtZSB8fCBlcnJvci50b1N0cmluZygpfSBpbiAke21ldGhvZH0uYDtcbiAgICAgIH1cbiAgICAgIGlmIChpZCA9PT0gdW5kZWZpbmVkKSByZXR1cm47IC8vIERvbid0IHJlc3BvbmQgdG8gYSAnbm90aWZpY2F0aW9uJy4gbnVsbCBpZCBpcyBzdGlsbCBzZW50IGJhY2suXG4gICAgICBsZXQgcmVzcG9uc2UgPSBlcnJvciA/IHtpZCwgZXJyb3IsIGpzb25ycGN9IDoge2lkLCByZXN1bHQsIGpzb25ycGN9O1xuICAgICAgbG9nPy4oZGlzcGF0Y2hlckxhYmVsLCAnYW5zd2VyaW5nJywgaWQsIGVycm9yIHx8IHJlc3VsdCwgJ3RvJywgdGFyZ2V0TGFiZWwpO1xuICAgICAgcmV0dXJuIHBvc3QocmVzcG9uc2UpO1xuICAgIH1cblxuICAgIC8vIE90aGVyd2lzZSwgaXQgaXMgYSByZXNwb25zZSBmcm9tIHRhcmdldCB0byBvdXIgZWFybGllciBvdXRnb2luZyByZXF1ZXN0LlxuICAgIGxldCByZXF1ZXN0ID0gcmVxdWVzdHNbaWRdOyAgLy8gUmVzb2x2ZSBvciByZWplY3QgdGhlIHByb21pc2UgdGhhdCBhbiBhbiBlYXJsaWVyIHJlcXVlc3QgY3JlYXRlZC5cbiAgICBkZWxldGUgcmVxdWVzdHNbaWRdO1xuICAgIGlmICghcmVxdWVzdCkgcmV0dXJuIGxvZ3dhcm4/LihgJHtkaXNwYXRjaGVyTGFiZWx9IGlnbm9yaW5nIHJlc3BvbnNlICR7ZXZlbnQuZGF0YX0uYCk7XG4gICAgaWYgKGVycm9yKSByZXF1ZXN0LnJlamVjdChlcnJvcik7XG4gICAgZWxzZSByZXF1ZXN0LnJlc29sdmUocmVzdWx0KTtcbiAgfVxuXG4gIC8vIE5vdyBzZXQgdXAgdGhlIGhhbmRsZXIgYW5kIHJldHVybiB0aGUgZnVuY3Rpb24gZm9yIHRoZSBjYWxsZXIgdG8gdXNlIHRvIG1ha2UgcmVxdWVzdHMuXG4gIHJlY2VpdmVyLmFkZEV2ZW50TGlzdGVuZXIoXCJtZXNzYWdlXCIsIHJlc3BvbmQpO1xuICBsb2dpbmZvPy4oYCR7ZGlzcGF0Y2hlckxhYmVsfSB3aWxsIGRpc3BhdGNoIHRvICR7dGFyZ2V0TGFiZWx9YCk7XG4gIHJldHVybiByZXF1ZXN0O1xufVxuXG5leHBvcnQgZGVmYXVsdCBkaXNwYXRjaDtcbiIsImltcG9ydCBTZWN1cml0eSBmcm9tIFwiLi9hcGkubWpzXCI7XG5pbXBvcnQgZGlzcGF0Y2ggZnJvbSBcIkBraTFyMHkvanNvbnJwY1wiO1xuXG4vLyBTZWUgaHR0cHM6Ly9raWxyb3ktY29kZS5naXRodWIuaW8vZGlzdHJpYnV0ZWQtc2VjdXJpdHkvZG9jcy9pbXBsZW1lbnRhdGlvbi5odG1sI3dlYi13b3JrZXItYW5kLWlmcmFtZVxuXG4vLyBzZWxmIGlzIGEgV29ya2VyOiB3ZSB3aWxsIHBvc3RNZXNzYWdlIHRvIHRoYXQgYW5kIGxpc3RlbiBmb3IgJ21lc3NhZ2UnIG9uIHRoYXQuXG5jb25zdCBwb3N0Q2xpZW50ID0gZGlzcGF0Y2goe1xuICB0YXJnZXRMYWJlbDogJ3ZhdWx0OicgKyBzZWxmLm5hbWUuc3BsaXQoJyEnKVsxXSwgLy8gQSBkZWJ1Z2dpbmcgbGFiZWwgZm9yIHRoZSB3aW5kb3cgd2UgYXJlIGNvbW11bmljYXRpbmcgd2l0aC5cbiAgbmFtZXNwYWNlOiBTZWN1cml0eSAgLy8ganNvbnJwYyByZXF1ZXN0cyBmcm9tIHRoZSBjbGllbnQgYXJlIGhhbmRsZWQgYnkgY2FsbGluZyB0aGUgc3BlY2lmaWVkIG1ldGhvZCBvbiBTZWN1cml0eS5cbn0pO1xuXG4vLyBQcm92aWRlIFNlY3VyaXR5IHdpdGggdGhyZWUgb3BlcmF0aW9ucyB0aGF0IGFyZSBoYW5kbGVkIGJ5IG1ha2luZyBqc29ucnBjIHJlcXVlc3RzIHRvIHRoZSBjbGllbnQuXG4vLyBJZiBTZWN1cml0eSAoYXBpLm1qcykgaXMgcnVubmluZyBvdXRzaWRlIGEgYnJvd3NlciAoZS5nLiwgaW4gbm9kZSksIGl0IHN1cHBsaWVzIGl0cyBvd24gZGVmYXVsdFxuLy8gaW1wbGVtZW50YXRpb24gb2YgU3RvcmFnZSBhbmQgZ2V0VXNlckRldmljZVNlY3JldC4gSGVyZSAoaW4gYSBicm93c2VyIHdvcmtlciksIHdlIG92ZXJyaWRlIHRoZXNlXG4vLyB3aXRoIGltcGxlbWVudGF0aW9ucyB0aGF0IHBvc3QgdGhlIHJlcXVlc3RzIHRvIHRoZSBjbGllbnQuXG5TZWN1cml0eS5TdG9yYWdlID0ge1xuICBzdG9yZSguLi5hcmdzKSB7XG4gICAgcmV0dXJuIHBvc3RDbGllbnQoJ3N0b3JlJywgLi4uYXJncyk7XG4gIH0sXG4gIHJldHJpZXZlKC4uLmFyZ3MpIHtcbiAgICByZXR1cm4gcG9zdENsaWVudCgncmV0cmlldmUnLCAuLi5hcmdzKTtcbiAgfVxufVxuU2VjdXJpdHkuZ2V0VXNlckRldmljZVNlY3JldCA9ICh0YWcsIHByb21wdCA9ICcnKSA9PiBwb3N0Q2xpZW50KCdnZXRVc2VyRGV2aWNlU2VjcmV0JywgdGFnLCBwcm9tcHQpO1xuXG5wb3N0Q2xpZW50KCdyZWFkeScsIFNlY3VyaXR5LnJlYWR5KTsgLy8gVGVsbCB0aGUgY2xpZW50IHRoYXQgZXZlcnl0aGluZyBpcyBub3cgaW4gcGxhY2UgZm9yIG9wZXJhdGlvbnMuXG4iXSwibmFtZXMiOlsiZGlnZXN0IiwiY3J5cHRvIiwiZW5jb2RlIiwiZGVjb2RlIiwiYml0TGVuZ3RoIiwiZGVjcnlwdCIsImdldENyeXB0b0tleSIsIndyYXAiLCJ1bndyYXAiLCJkZXJpdmVLZXkiLCJwMnMiLCJjb25jYXRTYWx0IiwiZW5jcnlwdCIsImJhc2U2NHVybCIsInN1YnRsZUFsZ29yaXRobSIsImRlY29kZUJhc2U2NFVSTCIsImludmFsaWRLZXlJbnB1dCIsIkVDREguZWNkaEFsbG93ZWQiLCJFQ0RILmRlcml2ZUtleSIsImNla0xlbmd0aCIsImFlc0t3IiwicnNhRXMiLCJwYmVzMkt3IiwiYWVzR2NtS3ciLCJrZXlUb0pXSyIsIkVDREguZ2VuZXJhdGVFcGsiLCJnZXRWZXJpZnlLZXkiLCJnZXRTaWduS2V5IiwiYmFzZTY0dXJsLmVuY29kZSIsImJhc2U2NHVybC5kZWNvZGUiLCJnZW5lcmF0ZVNlY3JldCIsImdlbmVyYXRlS2V5UGFpciIsImdlbmVyYXRlIiwiSk9TRS5kZWNvZGVQcm90ZWN0ZWRIZWFkZXIiLCJKT1NFLmdlbmVyYXRlS2V5UGFpciIsIkpPU0UuQ29tcGFjdFNpZ24iLCJKT1NFLmNvbXBhY3RWZXJpZnkiLCJKT1NFLkNvbXBhY3RFbmNyeXB0IiwiSk9TRS5jb21wYWN0RGVjcnlwdCIsIkpPU0UuZ2VuZXJhdGVTZWNyZXQiLCJKT1NFLmJhc2U2NHVybC5lbmNvZGUiLCJKT1NFLmJhc2U2NHVybC5kZWNvZGUiLCJKT1NFLmV4cG9ydEpXSyIsIkpPU0UuaW1wb3J0SldLIiwiSk9TRS5HZW5lcmFsRW5jcnlwdCIsIkpPU0UuZ2VuZXJhbERlY3J5cHQiLCJKT1NFLkdlbmVyYWxTaWduIiwiSk9TRS5nZW5lcmFsVmVyaWZ5IiwiTG9jYWxDb2xsZWN0aW9uIiwicGtnLmRlZmF1bHQiXSwibWFwcGluZ3MiOiJBQUFBLGVBQWUsTUFBTSxDQUFDO0FBQ2YsTUFBTSxXQUFXLEdBQUcsQ0FBQyxHQUFHLEtBQUssR0FBRyxZQUFZLFNBQVM7O0FDQTVELE1BQU1BLFFBQU0sR0FBRyxPQUFPLFNBQVMsRUFBRSxJQUFJLEtBQUs7QUFDMUMsSUFBSSxNQUFNLFlBQVksR0FBRyxDQUFDLElBQUksRUFBRSxTQUFTLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0FBQ3RELElBQUksT0FBTyxJQUFJLFVBQVUsQ0FBQyxNQUFNQyxRQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxZQUFZLEVBQUUsSUFBSSxDQUFDLENBQUMsQ0FBQztBQUMxRSxDQUFDOztBQ0hNLE1BQU0sT0FBTyxHQUFHLElBQUksV0FBVyxFQUFFLENBQUM7QUFDbEMsTUFBTSxPQUFPLEdBQUcsSUFBSSxXQUFXLEVBQUUsQ0FBQztBQUN6QyxNQUFNLFNBQVMsR0FBRyxDQUFDLElBQUksRUFBRSxDQUFDO0FBQ25CLFNBQVMsTUFBTSxDQUFDLEdBQUcsT0FBTyxFQUFFO0FBQ25DLElBQUksTUFBTSxJQUFJLEdBQUcsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFDLEdBQUcsRUFBRSxFQUFFLE1BQU0sRUFBRSxLQUFLLEdBQUcsR0FBRyxNQUFNLEVBQUUsQ0FBQyxDQUFD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QUFDLENBQUM7QUFDOUIsS0FBSztBQUNMLElBQUksT0FBTyxNQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsQ0FBQyxJQUFJO0FBQzVDLE1BQU0sU0FBUyxJQUFJLE1BQU0sQ0FBQyxNQUFNLENBQUMsTUFBTSxFQUFFLFNBQVMsQ0FBQztBQUNuRCxNQUFNLEtBQUssSUFBSTtBQUNmLFFBQVEsSUFBSSxDQUFDLEtBQUssQ0FBQyxNQUFNLENBQUMsR0FBRyxFQUFDO0FBQzlCLFFBQVEsT0FBTyxLQUFLLENBQUMsR0FBRyxJQUFJLENBQUMsOENBQThDLEVBQUUsR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFLE1BQU0sQ0FBQyxHQUFHLEVBQUUsS0FBSyxDQUFDLENBQUM7QUFDeEcsT0FBTyxDQUFDLENBQUM7QUFDVCxHQUFHO0FBQ0gsRUFBRSxPQUFPLE9BQU8sQ0FBQyxJQUFJLEVBQUU7QUFDdkIsSUFBSSxPQUFPLE9BQU8sQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxHQUFHLElBQUksTUFBTSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDO0FBQzNELE9BQU8sS0FBSyxDQUFDLE1BQU0sTUFBTSxJQUFJO0FBQzdCLFFBQVEsS0FBSyxJQUFJLFNBQVMsSUFBSSxJQUFJLEVBQUU7QUFDcEMsVUFBVSxJQUFJLE1BQU0sR0FBRyxNQUFNLE1BQU0sQ0FBQyxNQUFNLENBQUMsU0FBUyxFQUFFLENBQUMsTUFBTSxFQUFFLEtBQUssRUFBRSxJQUFJLEVBQUUsS0FBSyxFQUFFLFFBQVEsRUFBRSxJQUFJLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxNQUFNLElBQUksQ0FBQyxDQUFDO0FBQ3RILFVBQVUsSUFBSSxNQUFNLEVBQUUsT0FBTyxNQUFNLENBQUM7QUFDcEMsU0FBUztBQUNULFFBQVEsTUFBTSxNQUFNLENBQUM7QUFDckIsT0FBTyxDQUFDLENBQUM7QUFDVCxHQUFHO0FBQ0gsRUFBRSxhQUFhLE9BQU8sQ0FBQyxHQUFHLEVBQUUsSUFBSSxFQUFFLFlB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QU0sTUFBTSxDQUFDLEdBQUcsT0FBTyxFQUFFO0FBQzNCLElBQUksSUFBSSxDQUFDLE9BQU8sQ0FBQyxNQUFNLEVBQUUsT0FBTyxNQUFNLFlBQVksQ0FBQyxNQUFNLEVBQUUsQ0FBQztBQUM1RCxJQUFJLElBQUksTUFBTSxHQUFHLE9BQU8sQ0FBQyxDQUFDLENBQUMsQ0FBQyxNQUFNLENBQUM7QUFDbkMsSUFBSSxJQUFJLE1BQU0sRUFBRSxPQUFPLE1BQU0sY0FBYyxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsQ0FBQztBQUMzRCxJQUFJLE9BQU8sTUFBTSxVQUFVLENBQUMsTUFBTSxDQUFDLE9BQU8sQ0FBQyxDQUFDO0FBQzVDLEdBQUc7QUFDSCxFQUFFLE1BQU0sZ0JBQWdCLENBQUMsQ0FBQyxHQUFHLEVBQUUsUUFBUSxHQUFHLEtBQUssRUFBRSxHQUFHLE9BQU8sQ0FBQyxFQUFFO0FBQzlELElBQUksSUFBSSxNQUFNLEdBQUcsTUFBTSxNQUFNLENBQUMsTUFBTSxDQUFDLEdBQUcsRUFBRSxDQUFDLFFBQVEsRUFBRSxHQUFHLE9BQU8sQ0FBQyxDQUFDLENBQUM7QUFDbEUsSUFBSSxPQUFPLE1BQU0sQ0FBQyxnQkFBZ0IsQ0FBQyxPQUFPLENBQUMsQ0FBQztBQUM1QyxHQUFHO0FBQ0gsRUFBRSxNQUFNLE9BQU8sQ0FBQyxZQUFZLEVBQUU7QUFDOUIsSUFBSSxJQUFJLFFBQVEsS0FBSyxPQUFPLFlBQVksRUFBRSxZQUFZLEdBQUcsQ0FBQyxHQUFHLEVBQUUsWUFBWSxDQUFDLENBQUM7QUFDN0UsSUFBSSxJQUFJLENBQUMsR0FBRyxFQUFFLFFBQVEsR0FBRyxJQUFJLEVBQUUsR0FBRyxZQUFZLENBQUMsR0FBRyxZQUFZO0FBQzlELFFBQVEsT0FBTyxHQUFHLENBQUMsUUFBUSxFQUFFLEdBQUcsWUFBWSxDQUFDO0FBQzdDLFFBQVEsTUFBTSxHQUFHLE1BQU0sTUFBTSxDQUFDLE1BQU0sQ0FBQyxHQUFHLEVBQUUsT0FBTyxDQUFDLENBQUM7QUFDbkQsSUFBSSxPQUFPLE1BQU0sQ0FBQyxPQUFPLENBQUMs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RSxTQUFTLEVBQUUsUUFBUTtBQUNyQixDQUFDLENBQUMsQ0FBQztBQUNIO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQUFRLENBQUMsT0FBTyxHQUFHO0FBQ25CLEVBQUUsS0FBSyxDQUFDLEdBQUcsSUFBSSxFQUFFO0FBQ2pCLElBQUksT0FBTyxVQUFVLENBQUMsT0FBTyxFQUFFLEdBQUcsSUFBSSxDQUFDLENBQUM7QUFDeEMsR0FBRztBQUNILEVBQUUsUUFBUSxDQUFDLEdBQUcsSUFBSSxFQUFFO0FBQ3BCLElBQUksT0FBTyxVQUFVLENBQUMsVUFBVSxFQUFFLEdBQUcsSUFBSSxDQUFDLENBQUM7QUFDM0MsR0FBRztBQUNILEVBQUM7QUFDRCxRQUFRLENBQUMsbUJBQW1CLEdBQUcsQ0FBQyxHQUFHLEVBQUUsTUFBTSxHQUFHLEVBQUUsS0FBSyxVQUFVLENBQUMscUJBQXFCLEVBQUUsR0FBRyxFQUFFLE1BQU0sQ0FBQyxDQUFDO0FBQ3BHO0FBQ0EsVUFBVSxDQUFDLE9BQU8sRUFBRSxRQUFRLENBQUMsS0FBSyxDQUFDLENBQUMiLCJ4X2dvb2dsZV9pZ25vcmVMaXN0IjpbMCwxLDIsMyw0LDUsNiw3LDgsOSwxMCwxMSwxMiwxMywxNCwxNSwxNiwxNywxOCwxOSwyMCwyMSwyMiwyMywyNCwyNSwyNiwyNywyOCwyOSwzMCwzMSwzMiwzMywzNCwzNSwzNiwzNywzOCwzOSw0MCw0MSw0Miw0Myw0NCw0NSw0Niw0Nyw0OCw0OSw1MCw1MSw1Miw1Myw1NCw1NSw1Niw3MF19
