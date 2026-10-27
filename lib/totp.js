/**
 * RFC 6238 TOTP (SHA-1, 6 digits, 30 second period) with a ±1 step window.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { decodeBase32, encodeBase32 } from './base32.js';

export const TOTP_PERIOD_SECONDS = 30;
export const TOTP_DIGITS = 6;
export const TOTP_ALGORITHM = 'sha1';
export const TOTP_DEFAULT_WINDOW = 1;
export const TOTP_SECRET_BYTES = 20;

/**
 * Generate a new random TOTP secret (base32, 160 bit).
 * @param {number} [bytes]
 * @returns {string}
 */
export function generateSecret(bytes = TOTP_SECRET_BYTES) {
  if (!Number.isInteger(bytes) || bytes < 16 || bytes > 64) throw new TypeError('totp: secret must be 16..64 bytes');
  return encodeBase32(randomBytes(bytes));
}

/**
 * Hotp value for one counter.
 * @param {string|Buffer} secret base32 secret or raw key
 * @param {number} counter
 * @param {number} [digits]
 * @returns {string}
 */
export function hotp(secret, counter, digits = TOTP_DIGITS) {
  const key = typeof secret === 'string' ? decodeBase32(secret) : secret;
  if (key.length === 0) throw new TypeError('totp: secret is empty');
  if (!Number.isSafeInteger(counter) || counter < 0) throw new TypeError('totp: invalid counter');
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', key).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) | ((digest[offset + 1] & 0xff) << 16) | ((digest[offset + 2] & 0xff) << 8) | (digest[offset + 3] & 0xff);
  return String(binary % 10 ** digits).padStart(digits, '0');
}

/** Counter for a wall-clock millisecond timestamp. */
export function counterAt(now = Date.now(), periodSeconds = TOTP_PERIOD_SECONDS) {
  return Math.floor(now / 1000 / periodSeconds);
}

/**
 * Current code for a secret.
 * @param {string} secret base32
 * @param {{now?:number,digits?:number,period?:number}} [options]
 * @returns {string}
 */
export function generateTotp(secret, options = {}) {
  const { now = Date.now(), digits = TOTP_DIGITS, period = TOTP_PERIOD_SECONDS } = options;
  return hotp(secret, counterAt(now, period), digits);
}

/**
 * Verify a code with a ±window of accepted steps. All candidates are compared
 * in constant time, even after a match, so timing does not depend on position.
 * @param {string} secret base32
 * @param {string} code
 * @param {{now?:number,digits?:number,period?:number,window?:number}} [options]
 * @returns {boolean}
 */
export function verifyTotp(secret, code, options = {}) {
  return verifyTotpCounter(secret, code, options) >= 0;
}

/**
 * Like {@link verifyTotp}, but returns the matched time-step counter (needed
 * for RFC 6238 §5.2 replay protection) or `-1` when no step matches.
 *
 * @param {string} secret base32
 * @param {string} code
 * @param {{now?:number,digits?:number,period?:number,window?:number}} [options]
 * @returns {number} matched counter, or -1
 */
export function verifyTotpCounter(secret, code, options = {}) {
  const { now = Date.now(), digits = TOTP_DIGITS, period = TOTP_PERIOD_SECONDS, window = TOTP_DEFAULT_WINDOW } = options;
  if (typeof code !== 'string') return -1;
  const normalized = code.replace(/[\s-]/gu, '');
  if (!new RegExp(`^\\d{${digits}}$`, 'u').test(normalized)) return -1;
  if (typeof secret !== 'string' || secret.length === 0) return -1;
  if (!Number.isInteger(window) || window < 0 || window > 5) return -1;
  const provided = Buffer.from(normalized, 'utf8');
  const counter = counterAt(now, period);
  let matched = -1;
  for (let offset = -window; offset <= window; offset += 1) {
    const step = counter + offset;
    if (step < 0) continue;
    const candidate = hotp(secret, step, digits);
    const candidateBuffer = Buffer.from(candidate, 'utf8');
    if (candidateBuffer.length === provided.length && timingSafeEqual(candidateBuffer, provided)) matched = step;
  }
  return matched;
}

/**
 * Build an otpauth:// URI for authenticator apps.
 * @param {{account:string,secret:string,issuer?:string,digits?:number,period?:number}} input
 * @returns {string}
 */
export function otpauthUri(input) {
  const { account, secret, issuer = 'DSH', digits = TOTP_DIGITS, period = TOTP_PERIOD_SECONDS } = input;
  if (typeof account !== 'string' || account.length === 0) throw new TypeError('totp: account is required');
  if (typeof secret !== 'string' || secret.length === 0) throw new TypeError('totp: secret is required');
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: String(digits),
    period: String(period)
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}
