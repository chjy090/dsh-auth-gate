import assert from 'node:assert/strict';
import test from 'node:test';

import { counterAt, generateSecret, generateTotp, hotp, otpauthUri, verifyTotp } from '../lib/totp.js';

// RFC 6238 SHA-1 test secret: ASCII "12345678901234567890".
const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

test('HOTP matches RFC 4226 / RFC 6238 SHA-1 vectors', () => {
  // RFC 4226 Appendix D (6 digits).
  assert.deepEqual(
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9].map((counter) => hotp(RFC_SECRET, counter)),
    ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489']
  );
  // RFC 6238 Appendix B (8 digits, SHA-1) at its three timestamps.
  assert.equal(hotp(RFC_SECRET, counterAt(59_000), 8), '94287082');
  assert.equal(hotp(RFC_SECRET, counterAt(1_111_111_109_000), 8), '07081804');
  assert.equal(hotp(RFC_SECRET, counterAt(2_000_000_000_000), 8), '69279037');
});

test('generateTotp produces the RFC code at T=59s', () => {
  assert.equal(generateTotp(RFC_SECRET, { now: 59_000 }), '287082');
  assert.equal(generateTotp(RFC_SECRET, { now: 60_000 }), '359152');
});

test('verifyTotp accepts the current step and a ±1 window', () => {
  const now = 1_700_000_000_000;
  const current = generateTotp(RFC_SECRET, { now });
  const previous = generateTotp(RFC_SECRET, { now: now - 30_000 });
  const next = generateTotp(RFC_SECRET, { now: now + 30_000 });
  assert.equal(verifyTotp(RFC_SECRET, current, { now }), true);
  assert.equal(verifyTotp(RFC_SECRET, previous, { now }), true);
  assert.equal(verifyTotp(RFC_SECRET, next, { now }), true);
  assert.equal(verifyTotp(RFC_SECRET, generateTotp(RFC_SECRET, { now: now + 90_000 }), { now }), false);
  assert.equal(verifyTotp(RFC_SECRET, generateTotp(RFC_SECRET, { now: now - 90_000 }), { now }), false);
});

test('verifyTotp rejects malformed codes and bad secrets', () => {
  const now = 1_700_000_000_000;
  assert.equal(verifyTotp(RFC_SECRET, '', { now }), false);
  assert.equal(verifyTotp(RFC_SECRET, '12345', { now }), false);
  assert.equal(verifyTotp(RFC_SECRET, '1234567', { now }), false);
  assert.equal(verifyTotp(RFC_SECRET, 'abcdef', { now }), false);
  assert.equal(verifyTotp('', '123456', { now }), false);
  assert.equal(verifyTotp(RFC_SECRET, null, { now }), false);
  assert.equal(verifyTotp(RFC_SECRET, '123456', { now, window: 99 }), false);
});

test('generateSecret is 160-bit base32', () => {
  const secret = generateSecret();
  assert.match(secret, /^[A-Z2-7]{32}$/u);
  assert.notEqual(generateSecret(), generateSecret());
});

test('otpauth URI carries issuer, secret and algorithm', () => {
  const uri = otpauthUri({ account: 'admin', secret: RFC_SECRET });
  assert.match(uri, /^otpauth:\/\/totp\/DSH:admin\?/u);
  const url = new URL(uri);
  assert.equal(url.searchParams.get('secret'), RFC_SECRET);
  assert.equal(url.searchParams.get('issuer'), 'DSH');
  assert.equal(url.searchParams.get('algorithm'), 'SHA1');
  assert.equal(url.searchParams.get('digits'), '6');
  assert.equal(url.searchParams.get('period'), '30');
});
