import crypto from '#crypto';
import * as JOSE from 'jose';
import {hashName} from './algorithms.mjs';
export {crypto, JOSE};

export async function hashBuffer(buffer) { // Promise a Uint8Array digest of buffer.
  let hash = await crypto.subtle.digest(hashName, buffer);
  return new Uint8Array(hash);
}
export function hashText(text) { // Promise a Uint8Array digest of text string.
  let buffer = new TextEncoder().encode(text);
  return hashBuffer(buffer);
}
export function encodeBase64url(uint8Array) { // Answer base64url encoded string of array.
  return JOSE.base64url.encode(uint8Array);
}
export function decodeBase64url(string) { // Answer the decoded Uint8Array of the base64url string.
  return JOSE.base64url.decode(string);
}
export function decodeClaims(jwSomething, index = 0) { // Answer an object whose keys are the decoded protected header of the JWS or JWE (using signatures[index] of a general-form JWS).
  return JOSE.decodeProtectedHeader(jwSomething.signatures?.[index] || jwSomething);
}
    
