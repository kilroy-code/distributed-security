export function isEmptyJWS(jws) {
  return !jws.split('.')[1];
}
