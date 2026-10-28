/**
 * v0.7.3 P1: device-token authentication and session creation are atomic.
 *
 * `pair/redeem` with the same `clientDeviceId` rotates the device token and
 * deletes every session of the device in one locked write. Login/renew used to
 * resolve the device by token and then extend it by id in separate store calls;
 * a replacement landing between the calls let a request with the *old* token
 * extend the replacement record and create a live session (the "old token is
 * dead immediately" promise was broken).
 *
 * The contract asserted here is `StateStore.authenticateDeviceToken(token,
 * input)`: the token hash is compared with the current record under the same
 * lock that slides the deadline, creates the session and persists, so a
 * rotated token returns null and writes nothing.
 */

import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as http from 'node:http';
import * as path from 'node:path';
import test from 'node:test';

import { DshSessionProvider } from '../lib/dsh-session.js';
import { createGateway } from '../lib/gateway.js';
import { hashPassword } from '../lib/password.js';
import { StateStore } from '../lib/store.js';
import { generateSecret } from '../lib/totp.js';

const silent = { info() {}, warn() {}, error() {} };
const ROOT = path.join(process.cwd(), '.test-tmp', 'device-token-atomic');
const T0 = 1_800_000_000_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;
const DEVICE_TTL_DAYS = 90;
const DEVICE_ABS_DAYS = 365;
const CLIENT_DEVICE_ID = 'atomic-stable-0001';
const PASSWORD = 'Atomic-Test-Password-2026';
const LOGIN_INPUT = {
  idleMs: DEVICE_TTL_DAYS * DAY,
  absoluteMs: DEVICE_ABS_DAYS * DAY,
  sessionTtlMs: HOUR,
  sessionAbsoluteTtlMs: 30 * DAY
};

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

function setCookieLines(response) {
  const lines = response.headers['set-cookie'];
  return Array.isArray(lines) ? lines : [];
}

async function openStore(label, clock) {
  const dir = path.join(ROOT, `${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}-${label}`);
  await fs.mkdir(dir, { recursive: true });
  return { dir, store: await StateStore.open({ stateDir: dir, logger: silent, now: () => clock.value }) };
}

async function pair(store, { clientDeviceId = CLIENT_DEVICE_ID, name = 'Atomic 测试机', platform = 'android', origin = 'https://gateway.example' } = {}) {
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

function deviceSessions(store, deviceId) {
  return store.sessions.filter((session) => session.deviceId === deviceId);
}

/**
 * Wrap a store so `authenticateDeviceToken` first runs `onTokenCall` (used to
 * deterministically inject a same-device re-pairing at the exact moment the
 * gateway authenticates the presented token). Every other method keeps its
 * original receiver so the class's private fields stay valid.
 */
function racingStore(store, onTokenCall) {
  return new Proxy(store, {
    get(target, property) {
      if (property === 'authenticateDeviceToken') {
        return async (tokenValue, input) => {
          await onTokenCall(tokenValue);
          return target.authenticateDeviceToken(tokenValue, input);
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    }
  });
}

async function startGateway(store, clock) {
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
      loginLock: { maxFailures: 5, windowMinutes: 15, lockMinutes: 15 }
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

const CSRF = 'atomic-test-csrf-token-0123456789';

function loginRequest(port, deviceToken) {
  return request(port, {
    method: 'POST',
    reqPath: '/__auth/login',
    headers: {
      cookie: `dsh_gate_csrf=${CSRF}; dsh_gate_device=${deviceToken}`,
      'x-auth-gate-csrf': CSRF
    },
    body: { username: 'admin', password: PASSWORD }
  });
}

function renewRequest(port, deviceToken) {
  return request(port, { method: 'POST', reqPath: '/__auth/renew', body: { deviceToken } });
}

async function redeemOverHttp(port, store, clientDeviceId = CLIENT_DEVICE_ID) {
  const ticket = await store.issueTicket({ ttlMs: 60_000 });
  return request(port, {
    method: 'POST',
    reqPath: '/__auth/pair/redeem',
    body: { ticket: ticket.ticket, deviceName: 'Atomic 测试机', platform: 'android', clientDeviceId }
  });
}

// ---------------------------------------------------------------- store

test('v0.7.3 P1 store: a token rotated by a same-id re-pairing cannot authenticate or create a session', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('rotated-token', clock);
  try {
    const first = await pair(store);
    const oldToken = first.token;
    const sessionA = await store.createSession({ deviceId: first.device.id, ttlMs: HOUR });
    const sessionB = await store.createSession({ deviceId: first.device.id, ttlMs: HOUR });
    assert.equal(deviceSessions(store, first.device.id).length, 2);

    // What a vulnerable login/renew did first: resolve the device by the token
    // it presented, then use `device.id` later.
    const staleLookup = await store.findDeviceByToken(oldToken);
    assert.equal(staleLookup.id, first.device.id);

    clock.value = T0 + HOUR;
    const second = await pair(store);
    assert.equal(second.replaced, true);
    assert.equal(second.device.id, first.device.id, 'the replacement reuses the device id');

    // The stale lookup result must be worthless now: the *presented* token is
    // re-checked under the store lock.
    assert.equal(
      await store.authenticateDeviceToken(oldToken, LOGIN_INPUT),
      null,
      'authenticateDeviceToken must reject the rotated token'
    );
    assert.equal(deviceSessions(store, first.device.id).length, 0, 'no old session and no new session survives');
    assert.equal(store.sessions.length, 0);
    assert.equal(await store.findSession(sessionA.token), null);
    assert.equal(await store.findSession(sessionB.token), null);

    const authenticated = await store.authenticateDeviceToken(second.token, LOGIN_INPUT);
    assert.equal(authenticated.status, 'ok');
    assert.equal(authenticated.device.id, first.device.id);
    assert.equal(authenticated.device.tokenHash, undefined, 'the device copy still hides tokenHash');
    assert.equal(authenticated.session.deviceId, first.device.id);
    assert.equal(authenticated.session.tokenHash, undefined, 'the session copy still hides tokenHash');
    assert.match(authenticated.token, /^s_/u);
    assert.equal(authenticated.session.expiresAt, clock.value + HOUR);
    assert.equal(authenticated.maxAgeSeconds, Math.ceil((DEVICE_TTL_DAYS * DAY) / 1000), 'maxAgeSeconds is the remaining device lifetime');
    assert.equal(deviceSessions(store, first.device.id).length, 1, 'exactly one session is created');
    assert.equal(store.sessions.length, 1);
    const stored = await store.findSession(authenticated.token);
    assert.ok(stored, 'the returned session token resolves');
    assert.equal(stored.deviceId, first.device.id);
  } finally {
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('v0.7.3 P1 store: origin and the absolute ceiling are enforced inside the same call', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('origin-absolute', clock);
  try {
    const paired = await pair(store);
    await store.createSession({ deviceId: paired.device.id, ttlMs: HOUR });

    const wrongOrigin = await store.authenticateDeviceToken(paired.token, {
      ...LOGIN_INPUT,
      origin: 'https://other.example'
    });
    assert.equal(wrongOrigin.status, 'origin_changed');
    assert.equal(wrongOrigin.device.id, paired.device.id);
    assert.equal(wrongOrigin.device.tokenHash, undefined);
    assert.equal(deviceSessions(store, paired.device.id).length, 1, 'origin mismatch writes nothing');
    assert.equal(store.devices.length, 1);

    // Past the absolute ceiling (counted from pairing time) the token must not
    // resolve, and the device + its sessions are deleted.
    clock.value = T0 + DEVICE_ABS_DAYS * DAY + 1;
    assert.equal(await store.authenticateDeviceToken(paired.token, LOGIN_INPUT), null);
    assert.equal(store.devices.length, 0);
    assert.equal(store.sessions.length, 0);
    assert.equal(await store.findDeviceByToken(paired.token), null);
  } finally {
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('v0.7.3 P1 store: in-flight old-token authentications never outlive a same-id replacement', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('store-concurrency', clock);
  try {
    const first = await pair(store);
    const oldToken = first.token;
    const ticket = await store.issueTicket({ ttlMs: 60_000 });
    const redeemInput = {
      maxDevices: 100,
      deviceTtlMs: DEVICE_TTL_DAYS * DAY,
      deviceAbsoluteTtlMs: DEVICE_ABS_DAYS * DAY,
      name: 'replacement',
      platform: 'android',
      origin: 'https://gateway.example',
      clientDeviceId: CLIENT_DEVICE_ID
    };

    // 20 old-token calls are queued on the store lock first; the replacement is
    // queued last and therefore deletes every session they created.
    const renewals = Array.from({ length: 20 }, () => store.authenticateDeviceToken(oldToken, LOGIN_INPUT));
    const replacementPromise = store.redeemTicket(ticket.ticket, redeemInput);
    const [renewalResults, replacement] = await Promise.all([Promise.all(renewals), replacementPromise]);
    assert.equal(replacement.status, 'ok');
    assert.equal(replacement.replaced, true);
    assert.ok(renewalResults.every((result) => result !== null && result.status === 'ok'), 'the queued renewals completed before the replacement');
    assert.equal(deviceSessions(store, first.device.id).length, 0, 'the replacement deleted every in-flight session');
    assert.equal(store.sessions.length, 0);

    // Calls that reach the store after the replacement are rejected outright.
    const late = await Promise.all(Array.from({ length: 10 }, () => store.authenticateDeviceToken(oldToken, LOGIN_INPUT)));
    assert.deepEqual(late, Array.from({ length: 10 }, () => null));
    assert.equal(store.sessions.length, 0, 'a rotated token never creates a session');

    const fresh = await store.authenticateDeviceToken(replacement.token, LOGIN_INPUT);
    assert.equal(fresh.status, 'ok');
    assert.equal(deviceSessions(store, first.device.id).length, 1);
  } finally {
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- gateway

test('v0.7.3 P1 gateway: renew with a token rotated mid-request is 401 and creates no session', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('gateway-renew', clock);
  let gateway;
  try {
    const paired = await pair(store, { origin: 'http://127.0.0.1' });
    const oldToken = paired.token;
    let replacement = null;
    const wrapped = racingStore(store, async (tokenValue) => {
      if (replacement === null && tokenValue === oldToken) {
        const ticket = await store.issueTicket({ ttlMs: 60_000 });
        replacement = await store.redeemTicket(ticket.ticket, {
          maxDevices: 100,
          deviceTtlMs: DEVICE_TTL_DAYS * DAY,
          deviceAbsoluteTtlMs: DEVICE_ABS_DAYS * DAY,
          name: 'replacement',
          platform: 'android',
          origin: 'http://127.0.0.1',
          clientDeviceId: CLIENT_DEVICE_ID
        });
        assert.equal(replacement.replaced, true);
      }
    });
    ({ gateway } = await startGateway(wrapped, clock));

    const oldRenew = await renewRequest(gateway.server.address().port, oldToken);
    assert.equal(oldRenew.status, 401, oldRenew.body);
    assert.equal(JSON.parse(oldRenew.body).error, 'device_required');
    assert.equal(store.sessions.length, 0, 'the renewal in flight during the rotation created no session');
    assert.equal(setCookieLines(oldRenew).length, 0, 'a rejected renew sets no cookies');

    const newRenew = await renewRequest(gateway.server.address().port, replacement.token);
    assert.equal(newRenew.status, 200, newRenew.body);
    assert.equal(JSON.parse(newRenew.body).deviceId, paired.device.id);
    assert.equal(store.sessions.length, 1);
  } finally {
    await gateway?.close();
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('v0.7.3 P1 gateway: login whose password check outlives the device token is 401, clears the cookie and creates no session', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('gateway-login', clock);
  let gateway;
  try {
    await store.createUser({ username: 'admin', passwordHash: await hashPassword(PASSWORD), totpSecretB32: generateSecret() });
    const paired = await pair(store, { origin: 'http://127.0.0.1' });
    const oldToken = paired.token;
    let replacement = null;
    const wrapped = racingStore(store, async (tokenValue) => {
      if (replacement === null && tokenValue === oldToken) {
        // Committed after verifyPassword already accepted the password.
        const ticket = await store.issueTicket({ ttlMs: 60_000 });
        replacement = await store.redeemTicket(ticket.ticket, {
          maxDevices: 100,
          deviceTtlMs: DEVICE_TTL_DAYS * DAY,
          deviceAbsoluteTtlMs: DEVICE_ABS_DAYS * DAY,
          name: 'replacement',
          platform: 'android',
          origin: 'http://127.0.0.1',
          clientDeviceId: CLIENT_DEVICE_ID
        });
        assert.equal(replacement.replaced, true);
      }
    });
    ({ gateway } = await startGateway(wrapped, clock));
    const port = gateway.server.address().port;

    const login = await loginRequest(port, oldToken);
    assert.equal(login.status, 401, login.body);
    assert.equal(JSON.parse(login.body).error, 'device_required');
    assert.equal(store.sessions.length, 0, 'no session may be created for the rotated device token');
    const cleared = setCookieLines(login).filter((line) => line.startsWith('dsh_gate_device='));
    assert.equal(cleared.length, 1, 'the stale device cookie is expired');
    assert.match(cleared[0], /Max-Age=0/u);
    assert.ok(
      store.auditTail(10).some((entry) => entry.type === 'login_fail' && entry.detail === 'device_invalidated'),
      'the race is audited as device_invalidated'
    );

    // The rotated token still logs in with the same credentials.
    const relogin = await loginRequest(port, replacement.token);
    assert.equal(relogin.status, 200, relogin.body);
    assert.equal(JSON.parse(relogin.body).ok, true);
    assert.equal(store.sessions.length, 1);
    assert.ok(setCookieLines(relogin).some((line) => line.startsWith('dsh_gate_session=')));
  } finally {
    await gateway?.close();
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('v0.7.3 P1 gateway: concurrent old-token renewals interleaved with a re-pairing leave zero sessions', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('gateway-concurrency', clock);
  let gateway;
  try {
    const paired = await pair(store, { origin: 'http://127.0.0.1' });
    const oldToken = paired.token;
    await store.createSession({ deviceId: paired.device.id, ttlMs: HOUR });
    ({ gateway } = await startGateway(store, clock));
    const port = gateway.server.address().port;

    const renewals = Array.from({ length: 12 }, () => renewRequest(port, oldToken));
    const replacementResponse = redeemOverHttp(port, store);
    const [results, replacementResult] = await Promise.all([Promise.all(renewals), replacementResponse]);
    assert.equal(replacementResult.status, 200, replacementResult.body);
    const replacementBody = JSON.parse(replacementResult.body);
    assert.equal(replacementBody.replaced, true);
    assert.equal(replacementBody.deviceId, paired.device.id);

    for (const result of results) {
      assert.ok(result.status === 200 || result.status === 401, `unexpected status ${result.status}: ${result.body}`);
      if (result.status === 401) assert.equal(JSON.parse(result.body).error, 'device_required');
    }
    assert.equal(deviceSessions(store, paired.device.id).length, 0, 'no in-flight renewal session survives the replacement');
    assert.equal(store.sessions.length, 0);

    const oldAfter = await renewRequest(port, oldToken);
    assert.equal(oldAfter.status, 401);
    assert.equal(JSON.parse(oldAfter.body).error, 'device_required');

    const newAfter = await renewRequest(port, replacementBody.deviceToken);
    assert.equal(newAfter.status, 200, newAfter.body);
    assert.equal(JSON.parse(newAfter.body).deviceId, paired.device.id);
    assert.equal(deviceSessions(store, paired.device.id).length, 1);
  } finally {
    await gateway?.close();
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});
