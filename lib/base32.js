/**
 * RFC 4648 base32 (upper-case, no padding) — the encoding authenticator apps
 * expect for TOTP secrets.
 *
 * Only the canonical alphabet is emitted; decoding accepts lower-case input and
 * optional `=` padding because people paste secrets in both forms.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const ALPHABET_LOOKUP = new Map([...ALPHABET].map((char, index) => [char, index]));

/** @param {Buffer|Uint8Array|string} input */
export function encodeBase32(input) {
  const bytes = typeof input === 'string' ? Buffer.from(input, 'utf8') : Buffer.from(input);
  if (bytes.length === 0) return '';
  let out = '';
  let value = 0;
  let bits = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(value >>> bits) & 31];
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/**
 * Decode a base32 string.
 * @param {string} input
 * @returns {Buffer}
 * @throws {TypeError} on characters outside the alphabet or impossible lengths.
 */
export function decodeBase32(input) {
  if (typeof input !== 'string') throw new TypeError('base32: input must be a string');
  const normalized = input.trim().replace(/=+$/u, '').toUpperCase();
  if (normalized.length === 0) return Buffer.alloc(0);
  // 5 bits per char; a valid byte-aligned encoding can never leave 1..4 bits
  // that are non-zero, so lengths 1, 3, 6 (mod 8) are invalid.
  if (normalized.length % 8 === 1 || normalized.length % 8 === 3 || normalized.length % 8 === 6) {
    throw new TypeError('base32: invalid encoded length');
  }
  const out = [];
  let value = 0;
  let bits = 0;
  for (const char of normalized) {
    const index = ALPHABET_LOOKUP.get(char);
    if (index === undefined) throw new TypeError('base32: invalid character in input');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0 && value !== 0) throw new TypeError('base32: non-zero padding bits');
  return Buffer.from(out);
}
