import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';

import { decodeBase32, encodeBase32 } from '../lib/base32.js';

test('RFC 4648 base32 vectors (padding omitted by the encoder)', () => {
  const vectors = [
    ['', ''],
    ['f', 'MY'],
    ['fo', 'MZXQ'],
    ['foo', 'MZXW6'],
    ['foob', 'MZXW6YQ'],
    ['fooba', 'MZXW6YTB'],
    ['foobar', 'MZXW6YTBOI']
  ];
  for (const [plain, encoded] of vectors) {
    assert.equal(encodeBase32(plain), encoded);
    assert.equal(decodeBase32(encoded).toString('utf8'), plain);
    assert.equal(decodeBase32(`${encoded}====`).toString('utf8'), plain);
    assert.equal(decodeBase32(encoded.toLowerCase()).toString('utf8'), plain);
  }
});

test('round-trips arbitrary bytes', () => {
  for (let length = 0; length <= 64; length += 1) {
    const bytes = randomBytes(length);
    const decoded = decodeBase32(encodeBase32(bytes));
    assert.deepEqual(decoded, bytes);
  }
});

test('rejects invalid alphabet and impossible lengths', () => {
  for (const value of ['MZXW6!', 'MZXW1', 'ABC DEF', 'MZXW6YQ=AAAA']) {
    assert.throws(() => decodeBase32(value), TypeError, value);
  }
  assert.throws(() => decodeBase32('A'), TypeError);
  assert.throws(() => decodeBase32('ABC'), TypeError);
  assert.throws(() => decodeBase32('MZXW6Y'), TypeError);
  assert.throws(() => decodeBase32(42), TypeError);
});

test('a TOTP-sized secret round-trips', () => {
  const secret = encodeBase32(randomBytes(20));
  assert.equal(secret.length, 32);
  assert.equal(decodeBase32(secret).length, 20);
});
