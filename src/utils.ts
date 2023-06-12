declare const Deno: undefined;
declare const caches: undefined;

/**
 * Checks whether the execution env is browser or not.
 */
export const isBrowser = () => typeof window !== "undefined";

/**
 * Checks whether the execution env is Cloudflare Workers or not.
 */
export const isCloudflareWorkers = () => typeof caches !== "undefined";

/**
 * Checks whether the execution env is Deno or not.
 */
export const isDeno = () => typeof Deno !== "undefined";

/**
 * Checks whetehr the type of input is CryptoKeyPair or not.
 */
export const isCryptoKeyPair = (x: unknown): x is CryptoKeyPair =>
  typeof x === "object" &&
  x !== null &&
  typeof (x as CryptoKeyPair).privateKey === "object" &&
  typeof (x as CryptoKeyPair).publicKey === "object";

/**
 * Converts integer to octet string. I2OSP implementation.
 */
export function i2Osp(n: number, w: number): Uint8Array {
  if (w <= 0) {
    throw new Error("i2Osp: too small size");
  }
  if (n >= 256 ** w) {
    throw new Error("i2Osp: too large integer");
  }
  const ret = new Uint8Array(w);
  for (let i = 0; i < w && n; i++) {
    ret[w - (i + 1)] = n % 256;
    n = n >> 8;
  }
  return ret;
}

/**
 * Return a new array that is the concatennation of the two input arrays.
 * @param a array
 * @param b array
 * @returns concatenation of a and b
 */
export function concatArrays(a: Uint8Array, b: Uint8Array): Uint8Array {
  const c = new Uint8Array(a.length + b.length);
  c.set(a, 0);
  c.set(b, a.length);
  return c;
}

/**
 * Return the maximum of two numbers.
 * @param a number
 * @param b number
 * @returns the larger of a and b
 */
export function max(a: number, b: number): number {
  if (a > b) {
    return a;
  }
  return b;
}
