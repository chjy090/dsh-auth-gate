import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { certificateFingerprint, pairUrl, qrPng, qrSvg } from '../lib/qr.js';

const FIXTURE_CERT = readFileSync(new URL('./fixtures/test-cert.pem', import.meta.url));

test('pair URL puts the ticket in the fragment and keeps the documented fields', () => {
  const url = pairUrl({ publicUrl: 'https://192.0.2.10:3443/', ticket: 't_abcDEF123', fingerprint: 'a'.repeat(64), hostname: 'dsh-box' });
  assert.ok(url.startsWith('https://192.0.2.10:3443/__auth/pair#'));
  const fragment = new URLSearchParams(url.split('#')[1]);
  assert.equal(fragment.get('v'), '1');
  assert.equal(fragment.get('t'), 't_abcDEF123');
  assert.equal(fragment.get('fp'), 'a'.repeat(64));
  assert.equal(fragment.get('n'), 'dsh-box');
  assert.equal(url.includes('?t='), false);
});

test('pair URL omits the hostname when unknown and tolerates an empty fingerprint', () => {
  const url = pairUrl({ publicUrl: 'https://gateway.example', ticket: 't_x', fingerprint: '', hostname: '' });
  const fragment = new URLSearchParams(url.split('#')[1]);
  assert.equal(fragment.get('v'), '1');
  assert.equal(fragment.get('t'), 't_x');
  assert.equal(fragment.get('fp'), '');
  assert.equal(fragment.has('n'), false);
});

test('pair URL rejects missing publicUrl or ticket', () => {
  assert.throws(() => pairUrl({ publicUrl: '', ticket: 't_x' }), TypeError);
  assert.throws(() => pairUrl({ publicUrl: 'https://x', ticket: '' }), TypeError);
});

test('certificate fingerprint is the SHA-256 of the DER encoding', () => {
  const fingerprint = certificateFingerprint(FIXTURE_CERT);
  assert.match(fingerprint, /^[0-9a-f]{64}$/u);
  assert.equal(certificateFingerprint(FIXTURE_CERT.toString('utf8')), fingerprint);
  assert.equal(certificateFingerprint('not a certificate'), null);
  assert.equal(certificateFingerprint(undefined), null);
});

test('SVG output is inline-safe and PNG output is a real PNG', async () => {
  const svg = await qrSvg('otpauth://totp/DSH:test?secret=ABC');
  assert.ok(svg.startsWith('<svg'));
  assert.equal(svg.includes('<?xml'), false);
  assert.ok(svg.length > 500);
  const png = await qrPng('otpauth://totp/DSH:test?secret=ABC');
  assert.deepEqual([...png.subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
});
