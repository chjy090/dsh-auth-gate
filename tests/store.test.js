import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import test from 'node:test';

import { hashPassword, verifyPassword } from '../lib/password.js';
import { generateSecret } from '../lib/totp.js';
import { randomToken, safeEqualString, sha256Hex, StateStore } from '../lib/store.js';

const ROOT = path.join(process.cwd(), '.test-tmp', 'store-tests');
let counter = 0;

async function tempDir() {
  counter += 1;
  const dir = path.join(ROOT, `${process.pid}-${counter}`);
  await fs.rm(dir, { recursive: true, force: true });
  await fs.mkdir(dir, { recursive: true });
  return dir;
}

function silentLogger() {
  const calls = { info: [], warn: [], error: [] };
  return {
    calls,
    info: (...args) => calls.info.push(args.join(' ')),
    warn: (...args) => calls.warn.push(args.join(' ')),
    error: (...args) => calls.error.push(args.join(' '))
  };
}

async function openStore(dir, extra = {}) {
  const logger = extra.logger ?? silentLogger();
  const store = await StateStore.open({ stateDir: dir, logger, ...extra });
  return { store, logger };
}

async function createUser(store) {
  return store.createUser({
    username: 'admin',
    passwordHash: await hashPassword('Test-Password-123'),
    totpSecretB32: generateSecret()
  });
}

test('first open generates a 0600 admin key once without logging it', async () => {
  const dir = await tempDir();
  const firstLogger = silentLogger();
  const { store } = await openStore(dir, { logger: firstLogger });
  const key = store.adminKey;
  assert.match(key, /^[0-9a-f]{64}$/u);
  const stat = await fs.stat(path.join(dir, 'admin.key'));
  assert.equal(stat.mode & 0o777, 0o600);
  // P2-7: the key itself must never reach journald; only a mask + path.
  assert.equal(firstLogger.calls.info.some((line) => line.includes(key)), false);
  assert.ok(firstLogger.calls.info.some((line) => line.includes('generated admin key')));
  assert.equal((await fs.readFile(path.join(dir, 'admin.key'), 'utf8')).trim(), key);
  await store.close();

  const secondLogger = silentLogger();
  const reopened = await openStore(dir, { logger: secondLogger });
  assert.equal(reopened.store.adminKey, key);
  assert.equal(secondLogger.calls.info.filter((line) => line.includes(key)).length, 0);
  assert.equal(secondLogger.calls.info.length, 0);
  await reopened.store.close();
});

test('invalid admin key content is a startup error', async () => {
  const dir = await tempDir();
  await fs.writeFile(path.join(dir, 'admin.key'), 'not-a-valid-key\n', { mode: 0o600 });
  await assert.rejects(StateStore.open({ stateDir: dir, logger: silentLogger() }), /does not contain 32 bytes/i);
});

test('state is written atomically with 0600 and no plaintext secrets', async () => {
  const dir = await tempDir();
  const { store } = await openStore(dir);
  await createUser(store);
  await store.flush();
  const statePath = path.join(dir, 'state.json');
  const stat = await fs.stat(statePath);
  assert.equal(stat.mode & 0o777, 0o600);
  const raw = await fs.readFile(statePath, 'utf8');
  assert.doesNotMatch(raw, /Test-Password-123/u);
  assert.match(raw, /scrypt\$16384\$8\$1\$/u);
  const parsed = JSON.parse(raw);
  assert.equal(parsed.version, 1);
  assert.equal(parsed.user.username, 'admin');
  const leftover = (await fs.readdir(dir)).filter((name) => name.includes('.tmp-'));
  assert.deepEqual(leftover, []);
  await store.close();
});

test('password hash round-trips through the store', async () => {
  const dir = await tempDir();
  const { store } = await openStore(dir);
  await createUser(store);
  assert.equal(await verifyPassword('Test-Password-123', store.user.passwordHash), true);
  assert.equal(await verifyPassword('wrong-password', store.user.passwordHash), false);
  await store.close();
});

test('pairing ticket is single-use, hashed and expires', async () => {
  const dir = await tempDir();
  const { store } = await openStore(dir);
  await createUser(store);

  const { ticket } = await store.issueTicket({ ttlMs: 120_000 });
  assert.match(ticket, /^t_[A-Za-z0-9_-]{40,}$/u);
  const rawState = await fs.readFile(path.join(dir, 'state.json'), 'utf8');
  assert.doesNotMatch(rawState, new RegExp(ticket, 'u'));
  assert.equal(JSON.parse(rawState).tickets[0].ticketHash, createHash('sha256').update(ticket).digest('hex'));

  const redeemed = await store.redeemTicket(ticket, { maxDevices: 8, deviceTtlMs: 86_400_000, name: 'phone', platform: 'android', origin: 'https://gateway.example' });
  assert.equal(redeemed.status, 'ok');
  assert.match(redeemed.token, /^dt_/u);
  assert.equal(redeemed.device.name, 'phone');
  const state = JSON.parse(await fs.readFile(path.join(dir, 'state.json'), 'utf8'));
  assert.equal(state.devices.length, 1);
  assert.notEqual(state.devices[0].tokenHash, redeemed.token);
  assert.equal(state.devices[0].tokenHash, sha256Hex(redeemed.token));
  assert.doesNotMatch(await fs.readFile(path.join(dir, 'state.json'), 'utf8'), new RegExp(redeemed.token, 'u'));

  const again = await store.redeemTicket(ticket, { maxDevices: 8, deviceTtlMs: 86_400_000, name: 'phone', platform: 'android', origin: 'https://gateway.example' });
  assert.equal(again.status, 'invalid_ticket');

  const expired = await store.issueTicket({ ttlMs: 1 });
  await new Promise((resolve) => setTimeout(resolve, 10));
  const expiredResult = await store.redeemTicket(expired.ticket, { maxDevices: 8, deviceTtlMs: 86_400_000, name: 'x', platform: 'web', origin: 'https://gateway.example' });
  assert.equal(expiredResult.status, 'expired_ticket');
  await store.close();
});

test('device limit is enforced before consuming a ticket', async () => {
  const dir = await tempDir();
  const { store } = await openStore(dir);
  await createUser(store);
  const first = await store.issueTicket({ ttlMs: 60_000 });
  const redeemInput = { maxDevices: 1, deviceTtlMs: 86_400_000, name: 'one', platform: 'android', origin: 'https://g' };
  assert.equal((await store.redeemTicket(first.ticket, redeemInput)).status, 'ok');
  const second = await store.issueTicket({ ttlMs: 60_000 });
  assert.equal((await store.redeemTicket(second.ticket, { ...redeemInput, name: 'two' })).status, 'device_limit');
  // The ticket was not burned by the rejected attempt.
  const state = JSON.parse(await fs.readFile(path.join(dir, 'state.json'), 'utf8'));
  assert.equal(state.tickets.length, 1);
  await store.close();
});

test('device lookup hashes tokens, tracks lastSeen and revokes sessions', async () => {
  const dir = await tempDir();
  const { store } = await openStore(dir);
  await createUser(store);
  const { ticket } = await store.issueTicket({ ttlMs: 60_000 });
  const redeemed = await store.redeemTicket(ticket, { maxDevices: 8, deviceTtlMs: 86_400_000, name: 'phone', platform: 'android', origin: 'https://g' });
  assert.equal(redeemed.status, 'ok');
  const device = await store.findDeviceByToken(redeemed.token);
  assert.equal(device.id, redeemed.device.id);
  assert.equal(await store.findDeviceByToken('dt_wrong'), null);
  const session = await store.createSession({ deviceId: device.id, ttlMs: 3_600_000 });
  assert.equal((await store.findSession(session.token)).deviceId, device.id);
  assert.equal(await store.findSession('s_wrong'), null);
  assert.equal(await store.revokeDevice(device.id), true);
  assert.equal(await store.findSession(session.token), null);
  assert.equal(await store.findDeviceByToken(redeemed.token), null);
  await store.close();
});

test('revoking a device invalidates every pending pairing ticket', async () => {
  const dir = await tempDir();
  const { store } = await openStore(dir);
  await createUser(store);
  const redeemInput = { maxDevices: 8, deviceTtlMs: 86_400_000, name: 'phone', platform: 'android', origin: 'https://g' };
  const first = await store.issueTicket({ ttlMs: 60_000 });
  const redeemed = await store.redeemTicket(first.ticket, redeemInput);
  assert.equal(redeemed.status, 'ok');
  // A second ticket is issued but not redeemed yet.
  const pending = await store.issueTicket({ ttlMs: 60_000 });
  assert.equal(await store.revokeDevice(redeemed.device.id), true);
  // Revocation flushes pending tickets, so the pre-revocation ticket can no
  // longer be exchanged for a brand-new device + 90-day token.
  const afterRevoke = await store.redeemTicket(pending.ticket, { ...redeemInput, name: 'attacker' });
  assert.equal(afterRevoke.status, 'invalid_ticket');
  const state = JSON.parse(await fs.readFile(path.join(dir, 'state.json'), 'utf8'));
  assert.equal(state.tickets.length, 0);
  assert.equal(state.devices.length, 0);
  await store.close();
});

test('sessions are deleted on logout and password/TOTP changes', async () => {
  const dir = await tempDir();
  const { store } = await openStore(dir);
  await createUser(store);
  const { ticket } = await store.issueTicket({ ttlMs: 60_000 });
  const redeemed = await store.redeemTicket(ticket, { maxDevices: 8, deviceTtlMs: 86_400_000, name: 'phone', platform: 'android', origin: 'https://g' });
  const first = await store.createSession({ deviceId: redeemed.device.id, ttlMs: 3_600_000 });
  assert.equal((await store.findSession(first.token)).id, first.session.id);
  assert.equal(await store.deleteSession(first.token), true);
  assert.equal(await store.findSession(first.token), null);

  const second = await store.createSession({ deviceId: redeemed.device.id, ttlMs: 3_600_000 });
  await store.setPasswordHash(await hashPassword('Another-Password-123'));
  assert.equal(await store.findSession(second.token), null);
  const third = await store.createSession({ deviceId: redeemed.device.id, ttlMs: 3_600_000 });
  await store.resetTotp(generateSecret());
  assert.equal(await store.findSession(third.token), null);
  await store.close();
});

test('audit is bounded and persisted', async () => {
  const dir = await tempDir();
  const { store } = await openStore(dir, { auditLimit: 10 });
  for (let index = 0; index < 25; index += 1) store.recordAudit({ type: 'login_fail', ip: '10.0.0.1', detail: `attempt-${index}` });
  assert.equal(store.auditLog.length, 10);
  assert.equal(store.auditTail(100).length, 10);
  assert.equal(store.auditTail(100)[0].detail, 'attempt-24');
  await store.flush();
  const state = JSON.parse(await fs.readFile(path.join(dir, 'state.json'), 'utf8'));
  assert.equal(state.audit.length, 10);
  await store.close();
});

test('corrupt or incompatible state refuses to start and is not reset', async () => {
  for (const [name, content, pattern] of [
    ['invalid-json', '{"version":1,', /not valid JSON/u],
    ['wrong-version', JSON.stringify({ version: 99, user: null, devices: [], tickets: [], sessions: [], audit: [] }), /unsupported version/u],
    ['bad-arrays', JSON.stringify({ version: 1, user: null, devices: {}, tickets: [], sessions: [], audit: [] }), /not an array/u]
  ]) {
    const dir = await tempDir();
    const file = path.join(dir, 'state.json');
    await fs.writeFile(file, content, { mode: 0o600 });
    await assert.rejects(StateStore.open({ stateDir: dir, logger: silentLogger() }), pattern, name);
    assert.equal(await fs.readFile(file, 'utf8'), content);
  }
});

test('tokens and constant-time comparison helpers', () => {
  const token = randomToken('x');
  assert.match(token, /^x_[A-Za-z0-9_-]{40,}$/u);
  assert.equal(sha256Hex(token).length, 64);
  assert.equal(safeEqualString('abc', 'abc'), true);
  assert.equal(safeEqualString('abc', 'abd'), false);
  assert.equal(safeEqualString('abc', 'abcd'), false);
});

test('public state never exposes hashes or token material', async () => {
  const dir = await tempDir();
  const { store } = await openStore(dir);
  await createUser(store);
  const { ticket } = await store.issueTicket({ ttlMs: 60_000 });
  await store.redeemTicket(ticket, { maxDevices: 8, deviceTtlMs: 86_400_000, name: 'phone', platform: 'android', origin: 'https://g' });
  const state = store.publicState();
  assert.equal(state.configured, true);
  assert.equal(state.user.username, 'admin');
  assert.equal(state.user.totpConfigured, true);
  assert.equal(state.user.totpConfirmed, false, 'legacy flag is not a binding status and stays false without a session proof');
  assert.equal(state.devices.length, 1);
  const serialized = JSON.stringify(state);
  assert.doesNotMatch(serialized, /tokenHash|passwordHash|totpSecretB32/u);
  await store.close();
});
