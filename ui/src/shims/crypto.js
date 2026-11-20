/**
 * Lightweight browser-compatible shim for Node's `crypto.randomBytes(size)`
 * used internally by `@nethserver/ns8-ui-lib` UUID helper under Webpack 5.
 */
export function randomBytes(size) {
  const bytes = new Uint8Array(size);
  if (typeof window !== "undefined" && window.crypto && window.crypto.getRandomValues) {
    window.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < size; i += 1) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return bytes;
}

export default {
  randomBytes,
};
