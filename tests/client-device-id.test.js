/**
 * v0.7.3 same-device pairing de-duplication.
 *
 * `POST /__auth/pair/redeem` may carry an optional `clientDeviceId`
 * (`^[A-Za-z0-9._-]{8,64}$`). A repeated redeem with the same id must reuse the
 * existing, unexpired device record in place: same `device.id`, rotated token,
 * all old sessions gone, absolute-ceiling window restarted, no extra device
 * slot consumed. Omitting the field keeps the historical behaviour (one new
 * device per redeem); a malformed value is a 400 and must not burn the ticket.
 */

import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as http from 'node:http';
import * as path from 'node:path';
import test from 'node:test';

import { DshSessionProvider } from '../lib/dsh-session.js';
import { createGateway } from '../lib/gateway.js';
import { StateStore } from '../lib/store.js';

const silent = { info() {}, warn() {}, error() {} };
const ROOT = path.join(process.cwd(), '.test-tmp', 'client-device-id');
const T0 = 1_800_000_000_000;
const DAY = 86_400_000;
const DEVICE_TTL_DAYS = 90;
const DEVICE_ABS_DAYS = 365;

function request(port, { method = 'GET', reqPath = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path: reqPath,
        method,
        headers: {
          host: `127.0.0.1:${port}`,
          accept: 'application/json',
          ...(payload === undefined ? {} : { 'content-type': 'application/json', 'content-length': payload.length }),
          ...headers
        }
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
      }
    );
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

function setCookie(response, name) {
  const lines = response.headers['set-cookie'];
  if (!Array.isArray(lines)) return null;
  for (const line of lines) {
    if (line.startsWith(`${name}=`)) return line;
  }
  return null;
}

function setCookieValue(response, name) {
  const line = setCookie(response, name);
  if (line === null) return null;
  const pair = line.split(';')[0];
  return pair.slice(pair.indexOf('=') + 1);
}

async function openStore(label, clock) {
  const dir = path.join(ROOT, `${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}-${label}`);
  await fs.mkdir(dir, { recursive: true });
  return { dir, store: await StateStore.open({ stateDir: dir, logger: silent, now: () => clock.value }) };
}

async function pair(store, { clientDeviceId, name = 'Android 测试机', platform = 'android', origin = 'https://gateway.example' } = {}) {
  const ticket = await store.issueTicket({ ttlMs: 60_000 });
  const result = await store.redeemTicket(ticket.ticket, {
    maxDevices: 100,
    deviceTtlMs: DEVICE_TTL_DAYS * DAY,
    deviceAbsoluteTtlMs: DEVICE_ABS_DAYS * DAY,
    name,
    platform,
    origin,
    clientDeviceId
  });
  assert.equal(result.status, 'ok');
  return result;
}

async function startGateway(store, clock, overrides = {}) {
  const gateway = createGateway({
    config: {
      listenHost: '127.0.0.1',
      listenPort: 0,
      publicUrl: 'http://127.0.0.1',
      upstream: 'http://127.0.0.1:9',
      upstreamInsecureTls: false,
      sessionTtlHours: 48,
      sessionAbsoluteTtlDays: 30,
      deviceTtlDays: DEVICE_TTL_DAYS,
      deviceAbsoluteTtlDays: DEVICE_ABS_DAYS,
      maxDevices: 100,
      pairTicketTtlSeconds: 120,
      loginLock: { maxFailures: 5, windowMinutes: 15, lockMinutes: 15 },
      ...overrides
    },
    store,
    dshSession: new DshSessionProvider({ tokenUrl: 'http://127.0.0.1:9/?token=unused', logger: silent }),
    tls: null,
    logger: silent,
    now: () => clock.value
  });
  await gateway.listen();
  return { gateway, port: gateway.server.address().port };
}

test('same clientDeviceId reuses the device: same id, rotated token, sessions dropped, absolute window restarted', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('reuse', clock);
  try {
    const first = await pair(store, { clientDeviceId: 'android-install-0001', name: 'old name' });
    assert.equal(first.replaced, false);
    const oldToken = first.token;
    const sessionA = await store.createSession({ deviceId: first.device.id, ttlMs: 3_600_000 });
    const sessionB = await store.createSession({ deviceId: first.device.id, ttlMs: 3_600_000 });
    assert.equal(store.sessions.length, 2);

    clock.value = T0 + 10 * DAY;
    const second = await pair(store, {
      clientDeviceId: 'android-install-0001',
      name: 'new name',
      platform: 'web',
      origin: 'https://new-gateway.example'
    });
    assert.equal(second.replaced, true);
    assert.equal(second.device.id, first.device.id, 'the device record is reused in place');
    assert.notEqual(second.token, oldToken, 'the device token is rotated');
    assert.equal(store.devices.length, 1, 'no new device record is created');
    assert.equal(second.device.name, 'new name');
    assert.equal(second.device.platform, 'web');
    assert.equal(second.device.origin, 'https://new-gateway.example');
    assert.equal(second.device.clientDeviceId, 'android-install-0001');
    assert.equal(second.device.createdAt, clock.value, 'createdAt restarts the absolute ceiling');
    assert.equal(second.device.expiresAt, clock.value + DEVICE_TTL_DAYS * DAY);
    assert.equal(second.device.expiresAt, Math.min(clock.value + DEVICE_TTL_DAYS * DAY, second.device.createdAt + DEVICE_ABS_DAYS * DAY));

    assert.equal(await store.findDeviceByToken(oldToken), null, 'the old token stops resolving immediately');
    assert.equal(await store.findSession(sessionA.token), null, 'every old session is deleted');
    assert.equal(await store.findSession(sessionB.token), null);
    assert.equal(store.sessions.length, 0);
    const current = await store.findDeviceByToken(second.token);
    assert.equal(current.id, first.device.id, 'the new token resolves to the same device');
    assert.equal(current.tokenHash, undefined);
  } finally {
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('different ids create separate devices; an absent id keeps one-new-device-per-redeem', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('distinct', clock);
  try {
    const a = await pair(store, { clientDeviceId: 'device-aaaa-0001' });
    const b = await pair(store, { clientDeviceId: 'device-bbbb-0002' });
    assert.equal(a.replaced, false);
    assert.equal(b.replaced, false);
    assert.notEqual(a.device.id, b.device.id);
    assert.equal(store.devices.length, 2);

    const plain1 = await pair(store, { name: 'browser one' });
    const plain2 = await pair(store, { name: 'browser two' });
    assert.equal(plain1.replaced, false);
    assert.equal(plain2.replaced, false);
    assert.notEqual(plain1.device.id, plain2.device.id);
    assert.equal(plain1.device.clientDeviceId, undefined);
    assert.equal(store.devices.length, 4, 'redeems without an id keep creating devices');

    // A device created without an id cannot later be matched by an id: the
    // first id-bearing redeem creates a new record instead of hijacking it.
    const tagged = await pair(store, { clientDeviceId: 'device-cccc-0003' });
    assert.equal(tagged.replaced, false);
    assert.equal(store.devices.length, 5);
  } finally {
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('concurrent redeems with one id serialize onto a single record', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('concurrent', clock);
  try {
    const ticketA = await store.issueTicket({ ttlMs: 60_000 });
    const ticketB = await store.issueTicket({ ttlMs: 60_000 });
    const input = {
      maxDevices: 100,
      deviceTtlMs: DEVICE_TTL_DAYS * DAY,
      deviceAbsoluteTtlMs: DEVICE_ABS_DAYS * DAY,
      name: 'race',
      platform: 'android',
      origin: 'https://gateway.example',
      clientDeviceId: 'race-device-0001'
    };
    const [first, second] = await Promise.all([
      store.redeemTicket(ticketA.ticket, input),
      store.redeemTicket(ticketB.ticket, input)
    ]);
    assert.equal(first.status, 'ok');
    assert.equal(second.status, 'ok');
    assert.deepEqual([first.replaced, second.replaced].sort(), [false, true]);
    assert.equal(first.device.id, second.device.id);
    assert.equal(store.devices.length, 1);
    // Exactly the second (replacement) token is live.
    const live = [first, second].filter((result) => result.replaced)[0];
    const dead = [first, second].filter((result) => !result.replaced)[0];
    assert.equal((await store.findDeviceByToken(live.token)).id, live.device.id);
    assert.equal(await store.findDeviceByToken(dead.token), null);
  } finally {
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('store redeem: a malformed clientDeviceId is rejected without burning the ticket or creating a device', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('store-invalid', clock);
  try {
    const ticket = await store.issueTicket({ ttlMs: 60_000 });
    const base = {
      maxDevices: 100,
      deviceTtlMs: DEVICE_TTL_DAYS * DAY,
      deviceAbsoluteTtlMs: DEVICE_ABS_DAYS * DAY,
      name: 'invalid',
      platform: 'android',
      origin: 'https://gateway.example'
    };
    for (const bad of ['short', 'has space 123', 'x'.repeat(65), 42, null, '']) {
      const result = await store.redeemTicket(ticket.ticket, { ...base, clientDeviceId: bad });
      assert.equal(result.status, 'invalid_client_device_id', `clientDeviceId ${JSON.stringify(bad)} must not fall back to a new device`);
    }
    assert.equal(store.devices.length, 0, 'no device was created from a malformed id');
    assert.equal(store.tickets.length, 1, 'the ticket was not consumed');
    // The same ticket still works with a valid id.
    const accepted = await store.redeemTicket(ticket.ticket, { ...base, clientDeviceId: 'valid-device-0001' });
    assert.equal(accepted.status, 'ok');
    assert.equal(accepted.replaced, false);
    assert.equal(store.devices.length, 1);
    assert.equal(store.tickets.length, 0);
  } finally {
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('re-pairing consumes every other pending ticket in the same locked write', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('replace-cascade', clock);
  try {
    const first = await pair(store, { clientDeviceId: 'cascade-device-0001' });
    const presented = await store.issueTicket({ ttlMs: 60_000 });
    const otherA = await store.issueTicket({ ttlMs: 60_000 });
    const otherB = await store.issueTicket({ ttlMs: 60_000 });
    assert.equal(store.tickets.length, 3);

    const replaced = await store.redeemTicket(presented.ticket, {
      maxDevices: 100,
      deviceTtlMs: DEVICE_TTL_DAYS * DAY,
      deviceAbsoluteTtlMs: DEVICE_ABS_DAYS * DAY,
      name: 'cascade',
      platform: 'android',
      origin: 'https://gateway.example',
      clientDeviceId: 'cascade-device-0001'
    });
    assert.equal(replaced.status, 'ok');
    assert.equal(replaced.replaced, true);
    assert.equal(replaced.device.id, first.device.id);
    assert.equal(store.tickets.length, 0, 'all pending tickets are cleared by the replacement');
    assert.equal(store.devices.length, 1);

    const otherInput = {
      maxDevices: 100,
      deviceTtlMs: DEVICE_TTL_DAYS * DAY,
      deviceAbsoluteTtlMs: DEVICE_ABS_DAYS * DAY,
      name: 'attacker',
      platform: 'android',
      origin: 'https://gateway.example'
    };
    assert.equal((await store.redeemTicket(otherA.ticket, otherInput)).status, 'invalid_ticket');
    assert.equal((await store.redeemTicket(otherB.ticket, otherInput)).status, 'invalid_ticket');
    assert.equal((await store.redeemTicket(presented.ticket, otherInput)).status, 'invalid_ticket', 'the presented ticket is consumed');
    assert.equal(store.devices.length, 1);
  } finally {
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('state validation refuses duplicate non-empty clientDeviceIds but accepts legacy devices without the field', async () => {
  const dir = path.join(ROOT, `${process.pid}-duplicate-${Date.now()}`);
  await fs.mkdir(dir, { recursive: true });
  try {
    const seed = await StateStore.open({ stateDir: dir, logger: silent, now: () => T0 });
    try {
      await pair(seed, { name: 'legacy' });
      await pair(seed, { clientDeviceId: 'duplicate-device-0001' });
      await pair(seed, { clientDeviceId: 'duplicate-device-0002' });
      await seed.flush();
    } finally {
      await seed.close();
    }
    const stateFile = path.join(dir, 'state.json');
    const state = JSON.parse(await fs.readFile(stateFile, 'utf8'));
    const legacy = state.devices.find((device) => device.clientDeviceId === undefined);
    assert.ok(legacy, 'a legacy device has no clientDeviceId field');

    // Distinct ids and a legacy record are valid (backwards compatible).
    const reopened = await StateStore.open({ stateDir: dir, logger: silent, now: () => T0 });
    assert.equal(reopened.devices.length, 3);
    await reopened.close();

    // Two devices sharing the same non-empty id are ambiguous for replacement.
    const duplicate = state.devices.find((device) => device.clientDeviceId === 'duplicate-device-0002');
    duplicate.clientDeviceId = 'duplicate-device-0001';
    await fs.writeFile(stateFile, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
    await assert.rejects(StateStore.open({ stateDir: dir, logger: silent }), /duplicate device\.clientDeviceId/u);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('HTTP redeem: replaced flag/echo, old token renew 401, new token renew 200, old session dead, maxDevices', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('gateway', clock);
  let gateway;
  let port;
  try {
    ({ gateway, port } = await startGateway(store, clock, { maxDevices: 1 }));

    const ticket = await store.issueTicket({ ttlMs: 60_000 });
    const first = await request(port, {
      method: 'POST',
      reqPath: '/__auth/pair/redeem',
      body: { ticket: ticket.ticket, deviceName: 'App', platform: 'android', clientDeviceId: 'app-install-0001' }
    });
    assert.equal(first.status, 200, first.body);
    const firstPayload = JSON.parse(first.body);
    assert.equal(firstPayload.replaced, false);
    assert.equal(firstPayload.clientDeviceId, 'app-install-0001');
    const firstDeviceId = firstPayload.deviceId;
    const firstToken = firstPayload.deviceToken;
    assert.match(firstToken, /^dt_/u);
    assert.equal(setCookieValue(first, 'dsh_gate_device'), firstToken);
    const oldSession = await store.createSession({ deviceId: firstDeviceId, ttlMs: 3_600_000 });

    clock.value = T0 + 2 * DAY;
    const secondTicket = await store.issueTicket({ ttlMs: 60_000 });
    const second = await request(port, {
      method: 'POST',
      reqPath: '/__auth/pair/redeem',
      body: { ticket: secondTicket.ticket, deviceName: 'App renamed', platform: 'web', clientDeviceId: 'app-install-0001' }
    });
    assert.equal(second.status, 200, second.body);
    const secondPayload = JSON.parse(second.body);
    assert.equal(secondPayload.replaced, true);
    assert.equal(secondPayload.deviceId, firstDeviceId);
    assert.equal(secondPayload.clientDeviceId, 'app-install-0001');
    assert.notEqual(secondPayload.deviceToken, firstToken);
    assert.equal(secondPayload.deviceExpiresAt, clock.value + DEVICE_TTL_DAYS * DAY);
    assert.equal(store.devices.length, 1);
    assert.equal(store.devices[0].name, 'App renamed');

    const oldRenew = await request(port, { method: 'POST', reqPath: '/__auth/renew', body: { deviceToken: firstToken } });
    assert.equal(oldRenew.status, 401, 'the pre-replacement token must not renew');
    assert.equal(JSON.parse(oldRenew.body).error, 'device_required');
    const oldWhoami = await request(port, { reqPath: '/__auth/whoami', headers: { cookie: `dsh_gate_session=${oldSession.token}` } });
    assert.equal(oldWhoami.status, 200);
    assert.equal(JSON.parse(oldWhoami.body).authenticated, false, 'sessions of the old token are dead');

    const newRenew = await request(port, { method: 'POST', reqPath: '/__auth/renew', body: { deviceToken: secondPayload.deviceToken } });
    assert.equal(newRenew.status, 200, 'the rotated token renews');
    assert.equal(JSON.parse(newRenew.body).deviceId, firstDeviceId);
    assert.ok(setCookie(newRenew, 'dsh_gate_session'));

    // maxDevices=1 is already used by the reused record. Replacing it again
    // succeeds without a new slot; a *new* id is rejected with device_limit.
    const thirdTicket = await store.issueTicket({ ttlMs: 60_000 });
    const third = await request(port, {
      method: 'POST',
      reqPath: '/__auth/pair/redeem',
      body: { ticket: thirdTicket.ticket, clientDeviceId: 'app-install-0001' }
    });
    assert.equal(third.status, 200, 'an existing id replaces even at the device limit');
    assert.equal(JSON.parse(third.body).replaced, true);

    const fourthTicket = await store.issueTicket({ ttlMs: 60_000 });
    const fourth = await request(port, {
      method: 'POST',
      reqPath: '/__auth/pair/redeem',
      body: { ticket: fourthTicket.ticket, clientDeviceId: 'other-device-9999' }
    });
    assert.equal(fourth.status, 401);
    assert.equal(JSON.parse(fourth.body).error, 'device_limit');
    assert.equal(store.tickets.length, 1, 'a device_limit rejection leaves the ticket pending');
    // Free the slot (revocation clears pending tickets too) and pair a fresh
    // ticket for the new id.
    await store.revokeDevice(firstDeviceId);
    const retryTicket = await store.issueTicket({ ttlMs: 60_000 });
    const retry = await request(port, {
      method: 'POST',
      reqPath: '/__auth/pair/redeem',
      body: { ticket: retryTicket.ticket, clientDeviceId: 'other-device-9999' }
    });
    assert.equal(retry.status, 200, retry.body);
    assert.equal(JSON.parse(retry.body).replaced, false);
    assert.equal(store.devices.length, 1);
  } finally {
    await gateway?.close();
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('HTTP redeem: invalid clientDeviceId is 400 with an audit entry and does not burn the ticket', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('invalid', clock);
  let gateway;
  let port;
  try {
    ({ gateway, port } = await startGateway(store, clock));
    const ticket = await store.issueTicket({ ttlMs: 60_000 });
    for (const bad of ['short', 'has space 123', 'x'.repeat(65), 42, null, '']) {
      const rejected = await request(port, {
        method: 'POST',
        reqPath: '/__auth/pair/redeem',
        body: { ticket: ticket.ticket, clientDeviceId: bad }
      });
      assert.equal(rejected.status, 400, `clientDeviceId ${JSON.stringify(bad)} must be rejected`);
      assert.equal(JSON.parse(rejected.body).error, 'invalid_client_device_id');
    }
    assert.ok(
      store.auditTail(20).some((entry) => entry.type === 'pair_redeem' && entry.detail === 'invalid_client_device_id'),
      'the rejection is audited as pair_redeem/invalid_client_device_id'
    );
    assert.equal(store.devices.length, 0);
    // The malformed attempts did not consume the ticket.
    const accepted = await request(port, {
      method: 'POST',
      reqPath: '/__auth/pair/redeem',
      body: { ticket: ticket.ticket, deviceName: 'App' }
    });
    assert.equal(accepted.status, 200, accepted.body);
    const payload = JSON.parse(accepted.body);
    assert.equal(payload.replaced, false);
    assert.equal(payload.clientDeviceId, undefined, 'an absent id is not echoed');
    // A non-string/number body value is also rejected, never coerced.
    const numericTicket = await store.issueTicket({ ttlMs: 60_000 });
    const numeric = await request(port, {
      method: 'POST',
      reqPath: '/__auth/pair/redeem',
      body: { ticket: numericTicket.ticket, clientDeviceId: 12345678 }
    });
    assert.equal(numeric.status, 400);
    // The number ticket is still usable with a valid id.
    const valid = await request(port, {
      method: 'POST',
      reqPath: '/__auth/pair/redeem',
      body: { ticket: numericTicket.ticket, clientDeviceId: 'numeric-ticket-0001' }
    });
    assert.equal(valid.status, 200, valid.body);
  } finally {
    await gateway?.close();
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('state round-trips clientDeviceId, legacy devices have none, and a malformed persisted value is refused', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('state', clock);
  const stateFile = path.join(dir, 'state.json');
  let reopened;
  try {
    // A device created without an id (legacy shape) has no field in state.json.
    const legacy = await pair(store, { name: 'legacy' });
    const tagged = await pair(store, { clientDeviceId: 'persisted-device-0001' });
    await store.flush();
    const raw = JSON.parse(await fs.readFile(stateFile, 'utf8'));
    const legacyRecord = raw.devices.find((device) => device.id === legacy.device.id);
    const taggedRecord = raw.devices.find((device) => device.id === tagged.device.id);
    assert.equal('clientDeviceId' in legacyRecord, false, 'absent id stays absent in state.json');
    assert.equal(taggedRecord.clientDeviceId, 'persisted-device-0001');
    // The administrative view must never expose the client-side identifier.
    assert.doesNotMatch(JSON.stringify(store.publicState()), /clientDeviceId/u);
    // Neither the id nor the token is security material: the token itself is
    // still only stored hashed.
    assert.doesNotMatch(await fs.readFile(stateFile, 'utf8'), new RegExp(tagged.token, 'u'));

    await store.close();
    reopened = await StateStore.open({ stateDir: dir, logger: silent, now: () => clock.value });
    clock.value = T0 + DAY;
    const { ticket } = await reopened.issueTicket({ ttlMs: 60_000 });
    const replaced = await reopened.redeemTicket(ticket, {
      maxDevices: 100,
      deviceTtlMs: DEVICE_TTL_DAYS * DAY,
      deviceAbsoluteTtlMs: DEVICE_ABS_DAYS * DAY,
      name: 'legacy',
      platform: 'android',
      origin: 'https://gateway.example',
      clientDeviceId: 'persisted-device-0001'
    });
    assert.equal(replaced.status, 'ok');
    assert.equal(replaced.replaced, true, 'the id survives a store restart');
    assert.equal(replaced.device.id, tagged.device.id);
    assert.equal(reopened.devices.length, 2);
  } finally {
    await reopened?.close();
    try {
      await store.close();
    } catch {
      /* already closed */
    }
    await fs.rm(dir, { recursive: true, force: true });
  }

  // A hand-edited state file with a malformed clientDeviceId is a startup error
  // (validateState performs the same length/format check as the API).
  const brokenDir = path.join(ROOT, `${process.pid}-broken-${Date.now()}`);
  await fs.mkdir(brokenDir, { recursive: true });
  try {
    const legacyDir = path.join(brokenDir, 'state');
    await fs.mkdir(legacyDir, { recursive: true });
    const seed = await StateStore.open({ stateDir: legacyDir, logger: silent, now: () => T0 });
    const seeded = await pair(seed, {});
    await seed.close();
    const broken = JSON.parse(await fs.readFile(path.join(legacyDir, 'state.json'), 'utf8'));
    broken.devices[0].clientDeviceId = 'bad id!';
    await fs.writeFile(path.join(legacyDir, 'state.json'), `${JSON.stringify(broken, null, 2)}\n`, { mode: 0o600 });
    await assert.rejects(StateStore.open({ stateDir: legacyDir, logger: silent }), /clientDeviceId is invalid/u);
    assert.equal(seeded.status, 'ok');
  } finally {
    await fs.rm(brokenDir, { recursive: true, force: true });
  }
});
