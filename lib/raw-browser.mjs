import {extractable, signingName, signingCurve, symmetricName, hashLength} from "./algorithms.mjs";
import crypto from '#crypto';

export function exportRawKey(key) {
  return crypto.subtle.exportKey('raw', key);
}

export function importRawKey(arrayBuffer) {
  const algorithm = {name: signingCurve};
  return crypto.subtle.importKey('raw', arrayBuffer, algorithm, extractable, ['verify']);
}

export function importSecret(byteArray) {
  const algorithm = {name: symmetricName, length: hashLength};
  return crypto.subtle.importKey('raw', byteArray, algorithm, true, ['encrypt', 'decrypt']);
}
