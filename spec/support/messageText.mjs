export const scale = 10 * 1024 * 1024;
export function makeMessage(length = scale) {
  return Array.from({length}, (_, index) => index & 1).join('');
}
