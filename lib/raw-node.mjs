import * as JOSE from 'jose';
import crypto from '#crypto';

export function exportRawKey(key) {
  // When runing in Node, our/JOSE keys are node:crypto keys, not node:crypto.subtle keys,
  // and so the usual crypto.subtle.exportKey('raw', key) won't work on these keys.
  // Additionally, there isn't any raw export of node:crypto keys.
  return key.export({type: 'spki', format: 'der'}).slice(head.length);
}

// For our constant algorithm, the first 23 bytes of spki/der are constant,
// and not part of the 97 bytes of 'raw'
const head = JOSE.base64url.decode('MHYwEAYHKoZIzj0CAQYFK4EEACIDYgA');

export function importRawKey(arrayBuffer) {
  let pad = Buffer.alloc(97 - arrayBuffer.length),
      keyMaterial = Buffer.concat([head, pad, arrayBuffer]);
  return crypto.createPublicKey({key: keyMaterial, type: 'spki', format: 'der'});
}

export function importSecret(byteArray) {
  return crypto.createSecretKey(byteArray)
}
