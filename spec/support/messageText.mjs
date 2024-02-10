export const scale = 10 * 1024 * 1024;
export function makeMessage(length = scale) {
  return Array.from({length}, (_, index) => index & 1).join('');
}
const base64withDot = /^[A-Za-z0-9_\-\.]+$/;
export function isBase64URL(string, regex = base64withDot) {
  expect(regex.test(string)).toBeTruthy();
}
