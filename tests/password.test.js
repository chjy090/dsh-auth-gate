import assert from 'node:assert/strict';
import test from 'node:test';

import { checkPasswordPolicy, hashPassword, PASSWORD_MIN_LENGTH, verifyPassword } from '../lib/password.js';

test('password hash uses the documented scrypt format', async () => {
  const encoded = await hashPassword('correct horse battery staple');
  const parts = encoded.split('$');
  assert.equal(parts.length, 6);
  assert.equal(parts[0], 'scrypt');
  assert.equal(parts[1], '16384');
  assert.equal(parts[2], '8');
  assert.equal(parts[3], '1');
  assert.ok(Buffer.from(parts[4], 'base64').length >= 16);
  assert.equal(Buffer.from(parts[5], 'base64').length, 32);
});

test('password verify accepts the right password and rejects the wrong one', async () => {
  const encoded = await hashPassword('Test-Password-123');
  assert.equal(await verifyPassword('Test-Password-123', encoded), true);
  assert.equal(await verifyPassword('test-password-123', encoded), false);
  assert.equal(await verifyPassword('', encoded), false);
});

test('two hashes of the same password differ (random salt)', async () => {
  const first = await hashPassword('same-password-123');
  const second = await hashPassword('same-password-123');
  assert.notEqual(first, second);
  assert.equal(await verifyPassword('same-password-123', first), true);
  assert.equal(await verifyPassword('same-password-123', second), true);
});

test('malformed encoded hashes are rejected without throwing', async () => {
  for (const value of [
    undefined,
    null,
    42,
    '',
    'plaintext',
    'bcrypt$16384$8$1$AAAA$AAAA',
    'scrypt$16384$8$1$AAAA',
    'scrypt$notanumber$8$1$AAAA$BBBB',
    'scrypt$16384$8$1$!!!!$!!!!',
    'scrypt$16384$8$1$AAAA$' + 'A'.repeat(2000)
  ]) {
    assert.equal(await verifyPassword('anything', value), false, String(value));
  }
});

test('password policy enforces a non-empty minimum and a maximum', () => {
  assert.equal(checkPasswordPolicy('short').ok, false);
  assert.equal(checkPasswordPolicy('x'.repeat(PASSWORD_MIN_LENGTH)).ok, true);
  assert.equal(checkPasswordPolicy('x'.repeat(201)).ok, false);
  assert.equal(checkPasswordPolicy(null).ok, false);
});
