// One consistent algorithm for each family.
// https://datatracker.ietf.org/doc/html/rfc7518

export const signingName = 'EdDSA';
export const signingCurve = 'Ed25519';
export const signingAlgorithm = 'EdDSA';

export const encryptingName = 'RSA-OAEP';
export const hashLength = 256;
export const hashName = 'SHA-256';
export const modulusLength = 4096; // panva JOSE library default is 2048
export const encryptingAlgorithm = 'RSA-OAEP-256';

export const symmetricName = 'AES-GCM';
export const symmetricAlgorithm = 'A256GCM';
export const symmetricWrap = 'A256GCMKW';
export const secretAlgorithm = 'PBES2-HS512+A256KW';

export const extractable = true;  // always wrapped

