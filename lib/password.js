/**
 * Password hashing for the auth gate.
 *
 * Format: `scrypt$N$r$p$saltB64$hashB64` (salt 16 bytes, key 32 bytes).
 * Verification is constant-time via `crypto.timingSafeEqual`.
 */

import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);

export const SCRYPT_DEFAULTS = Object.freeze({ N: 16384, r: 8, p: 1, keylen: 32, saltBytes: 16 });
export const PASSWORD_MIN_LENGTH = 10;
export const PASSWORD_MAX_LENGTH = 200;

const MAX_N = 1 << 20;
const MAX_R = 32;
const MAX_P = 16;
const MAX_KEYLEN = 128;

/**
 * Validate a candidate password against the gate's basic policy.
 * @param {unknown} password
 * @returns {{ok:true}|{ok:false,reason:'too_short'|'too_long'|'not_a_string'}}
 */
export function checkPasswordPolicy(password) {
  if (typeof password !== 'string') return { ok: false, reason: 'not_a_string' };
  if (password.length < PASSWORD_MIN_LENGTH) return { ok: false, reason: 'too_short' };
  if (password.length > PASSWORD_MAX_LENGTH) return { ok: false, reason: 'too_long' };
  return { ok: true };
}

/**
 * @param {string} password
 * @param {{N?:number,r?:number,p?:number,keylen?:number,saltBytes?:number}} [params]
 * @returns {Promise<string>} the encoded hash
 */
export async function hashPassword(password, params = {}) {
  if (typeof password !== 'string' || password.length === 0) throw new TypeError('password: value must be a non-empty string');
  if (password.length > 4096) throw new TypeError('password: value is too long');
  const { N, r, p, keylen, saltBytes } = { ...SCRYPT_DEFAULTS, ...params };
  assertParams(N, r, p, keylen);
  const salt = randomBytes(saltBytes);
  const derived = /** @type {Buffer} */ (await scrypt(password, salt, keylen, { N, r, p }));
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${derived.toString('base64')}`;
}

/**
 * Constant-time verification of a password against an encoded hash.
 * Malformed hashes are rejected without throwing.
 * @param {string} password
 * @param {unknown} encoded
 * @returns {Promise<boolean>}
 */
export async function verifyPassword(password, encoded) {
  if (typeof password !== 'string' || typeof encoded !== 'string') return false;
  if (password.length > 4096) return false;
  const parts = encoded.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p)) return false;
  if (N < 2 || N > MAX_N || (N & (N - 1)) !== 0) return false;
  if (r < 1 || r > MAX_R || p < 1 || p > MAX_P) return false;
  let salt;
  let expected;
  try {
    salt = Buffer.from(parts[4], 'base64');
    expected = Buffer.from(parts[5], 'base64');
  } catch {
    return false;
  }
  if (salt.length < 8 || salt.length > 64) return false;
  if (expected.length < 16 || expected.length > MAX_KEYLEN) return false;
  // Round-trip check: Buffer.from() is permissive, so reject non-canonical b64.
  if (salt.toString('base64').replace(/=+$/u, '') !== parts[4].replace(/=+$/u, '')) return false;
  if (expected.toString('base64').replace(/=+$/u, '') !== parts[5].replace(/=+$/u, '')) return false;
  let derived;
  try {
    derived = /** @type {Buffer} */ (await scrypt(password, salt, expected.length, { N, r, p }));
  } catch {
    return false;
  }
  return derived.length === expected.length && timingSafeEqual(derived, expected);
}

function assertParams(N, r, p, keylen) {
  if (!Number.isInteger(N) || N < 2 || N > MAX_N || (N & (N - 1)) !== 0) throw new TypeError('password: invalid scrypt N');
  if (!Number.isInteger(r) || r < 1 || r > MAX_R) throw new TypeError('password: invalid scrypt r');
  if (!Number.isInteger(p) || p < 1 || p > MAX_P) throw new TypeError('password: invalid scrypt p');
  if (!Number.isInteger(keylen) || keylen < 16 || keylen > MAX_KEYLEN) throw new TypeError('password: invalid key length');
}
