/**
 * v0.7.0 sliding lifetimes.
 *
 * These tests use a real HTTP gateway (not just the store) with an injected
 * clock, so the assertions cover:
 *  - device token renewal moves `expiresAt` forward and stops at the absolute
 *    ceiling;
 *  - password login also slides the device and re-issues the device cookie;
 *  - an authenticated HTTP request slides the session, re-issues the cookie
 *    with the correct remaining `Max-Age`, and writes only when due;
 *  - the absolute session ceiling invalidates an otherwise-active session;
 *  - revoking a device kills its token, *all* of its sessions and pending
 *    pairing tickets; pruning an expired device kills its sessions too.
 */

import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as http from 'node:http';
import * as path from 'node:path';
import test from 'node:test';

import { DshSessionProvider } from '../lib/dsh-session.js';
import { createGateway, hardenCookieResponse, privateCacheControl, varyCookie } from '../lib/gateway.js';
import { hashPassword } from '../lib/password.js';
import { StateStore } from '../lib/store.js';
import { generateSecret } from '../lib/totp.js';

const silent = { info() {}, warn() {}, error() {} };
const ROOT = path.join(process.cwd(), '.test-tmp', 'sliding');
const T0 = 1_800_000_000_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;
const SESSION_TTL_HOURS = 48;
const SESSION_ABS_DAYS = 30;
const DEVICE_TTL_DAYS = 90;
const DEVICE_ABS_DAYS = 365;
const PASSWORD = 'Sliding-Test-Password-2026!';

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

function maxAgeOf(line) {
  const match = /Max-Age=(\d+)/iu.exec(line ?? '');
  return match === null ? null : Number(match[1]);
}

async function openStore(label, clock) {
  const dir = path.join(ROOT, `${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}-${label}`);
  await fs.mkdir(dir, { recursive: true });
  return { dir, store: await StateStore.open({ stateDir: dir, logger: silent, now: () => clock.value }) };
}

async function pairDevice(store, { deviceTtlMs = DEVICE_TTL_DAYS * DAY, deviceAbsoluteTtlMs = DEVICE_ABS_DAYS * DAY } = {}) {
  const ticket = await store.issueTicket({ ttlMs: 60_000 });
  const result = await store.redeemTicket(ticket.ticket, {
    maxDevices: 8,
    deviceTtlMs,
    deviceAbsoluteTtlMs,
    name: 'Android 测试机',
    platform: 'android',
    origin: 'http://127.0.0.1'
  });
  assert.equal(result.status, 'ok');
  return result;
}

async function startGateway(store, clock) {
  const gateway = createGateway({
    config: {
      listenHost: '127.0.0.1',
      listenPort: 0,
      publicUrl: 'http://127.0.0.1',
      upstream: 'http://127.0.0.1:9',
      upstreamInsecureTls: false,
      sessionTtlHours: SESSION_TTL_HOURS,
      sessionAbsoluteTtlDays: SESSION_ABS_DAYS,
      deviceTtlDays: DEVICE_TTL_DAYS,
      deviceAbsoluteTtlDays: DEVICE_ABS_DAYS,
      maxDevices: 8,
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

test('renewing a device slides expiresAt and is capped by deviceAbsoluteTtlDays', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('device-slide', clock);
  try {
    const idle = 5 * DAY;
    const absolute = 10 * DAY;
    const paired = await pairDevice(store, { deviceTtlMs: idle, deviceAbsoluteTtlMs: absolute });
    assert.equal(paired.device.expiresAt, T0 + idle, 'initial deadline is now + idle window');

    clock.value = T0 + 4 * DAY;
    const first = await store.extendDevice(paired.device.id, { idleMs: idle, absoluteMs: absolute });
    assert.ok(first);
    assert.equal(first.device.expiresAt, T0 + 9 * DAY, 'renew advances the idle deadline from now');
    assert.equal(first.maxAgeSeconds, 5 * 86_400);

    clock.value = T0 + 9 * DAY - HOUR;
    const nearCap = await store.extendDevice(paired.device.id, { idleMs: idle, absoluteMs: absolute });
    assert.ok(nearCap);
    assert.equal(nearCap.device.expiresAt, T0 + absolute, 'absolute ceiling wins when the idle window would overshoot it');
    assert.equal(nearCap.maxAgeSeconds, 25 * 3600, 'Max-Age shrinks to the remaining absolute lifetime');

    const session = await store.createSession({ deviceId: paired.device.id, ttlMs: SESSION_TTL_HOURS * HOUR });
    clock.value = T0 + absolute + 1000;
    assert.equal(await store.extendDevice(paired.device.id, { idleMs: idle, absoluteMs: absolute }), null);
    assert.equal(store.devices.length, 0, 'device past its absolute ceiling is removed');
    assert.equal(await store.findSession(session.token), null, 'its sessions die with it');
  } finally {
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('password login slides the device and reissues the device cookie', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('login-slide', clock);
  let gateway;
  let port;
  try {
    await store.createUser({ username: 'admin', passwordHash: await hashPassword(PASSWORD), totpSecretB32: generateSecret() });
    const paired = await pairDevice(store);
    ({ gateway, port } = await startGateway(store, clock));

    const csrfResponse = await request(port, { reqPath: '/__auth/csrf' });
    const csrf = JSON.parse(csrfResponse.body).csrf;
    assert.ok(csrf);

    clock.value = T0 + 10 * DAY;
    const login = await request(port, {
      method: 'POST',
      reqPath: '/__auth/login',
      headers: {
        cookie: `dsh_gate_device=${paired.token}; dsh_gate_csrf=${csrf}`,
        'x-auth-gate-csrf': csrf
      },
      body: { username: 'admin', password: PASSWORD }
    });
    assert.equal(login.status, 200, login.body);
    const payload = JSON.parse(login.body);
    assert.equal(payload.deviceExpiresAt, T0 + 100 * DAY, 'login response reports the new device deadline');

    const deviceCookie = setCookie(login, 'dsh_gate_device');
    assert.ok(deviceCookie, 'device cookie must be re-issued');
    assert.equal(maxAgeOf(deviceCookie), DEVICE_TTL_DAYS * 86_400, 'device cookie carries the new remaining Max-Age');
    assert.ok(setCookieValue(login, 'dsh_gate_device').length > 0);
    assert.ok(setCookieValue(login, 'dsh_gate_session').length > 0);

    const record = await store.findDeviceById(paired.device.id);
    assert.equal(record.expiresAt, T0 + 100 * DAY, 'device record persisted the sliding deadline');
    assert.equal(record.lastSeenAt, T0 + 10 * DAY);
  } finally {
    await gateway?.close();
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('a device token renewal reissues both cookies and reports deviceExpiresAt', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('renew-http', clock);
  let gateway;
  let port;
  try {
    const paired = await pairDevice(store);
    ({ gateway, port } = await startGateway(store, clock));
    clock.value = T0 + 5 * DAY;
    const first = await request(port, { method: 'POST', reqPath: '/__auth/renew', body: { deviceToken: paired.token } });
    assert.equal(first.status, 200, first.body);
    const firstPayload = JSON.parse(first.body);
    assert.equal(firstPayload.deviceExpiresAt, T0 + 95 * DAY);
    assert.equal(maxAgeOf(setCookie(first, 'dsh_gate_device')), DEVICE_TTL_DAYS * 86_400);
    assert.equal(maxAgeOf(setCookie(first, 'dsh_gate_session')), SESSION_TTL_HOURS * 3600);

    clock.value += 1000;
    const second = await request(port, { method: 'POST', reqPath: '/__auth/renew', body: { deviceToken: paired.token } });
    assert.equal(second.status, 200, second.body);
    assert.ok(JSON.parse(second.body).deviceExpiresAt > firstPayload.deviceExpiresAt, 'a later renew moves the deadline forward');
  } finally {
    await gateway?.close();
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('authenticated HTTP requests slide the session once, reissue the cookie, and stop at the absolute ceiling', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('session-slide', clock);
  let gateway;
  let port;
  try {
    const paired = await pairDevice(store);
    const session = await store.createSession({
      deviceId: paired.device.id,
      ttlMs: SESSION_TTL_HOURS * HOUR,
      absoluteTtlMs: SESSION_ABS_DAYS * DAY
    });
    ({ gateway, port } = await startGateway(store, clock));
    const cookie = `dsh_gate_session=${session.token}`;

    // Not due right after creation: no Set-Cookie, no write.
    const fresh = await request(port, { reqPath: '/__auth/whoami', headers: { cookie } });
    assert.equal(fresh.status, 200);
    assert.equal(setCookie(fresh, 'dsh_gate_session'), null, 'a fresh session must not be rewritten');
    const untouched = await store.findSession(session.token);
    assert.equal(untouched.expiresAt, T0 + SESSION_TTL_HOURS * HOUR);

    // Two hours later the periodic interval (1h) has passed: refresh + cookie.
    clock.value = T0 + 2 * HOUR;
    const slid = await request(port, { reqPath: '/__auth/whoami', headers: { cookie } });
    assert.equal(slid.status, 200);
    const sessionCookie = setCookie(slid, 'dsh_gate_session');
    assert.ok(sessionCookie, 'a due refresh must re-issue the session cookie');
    assert.equal(setCookieValue(slid, 'dsh_gate_session'), session.token, 'the token itself is not rotated');
    assert.equal(maxAgeOf(sessionCookie), SESSION_TTL_HOURS * 3600, 'Max-Age equals the full idle window');
    const refreshed = await store.findSession(session.token);
    assert.equal(refreshed.expiresAt, T0 + 2 * HOUR + SESSION_TTL_HOURS * HOUR, 'expiresAt moved forward');
    assert.equal(refreshed.lastRefreshedAt, T0 + 2 * HOUR);

    // A burst of requests in the same instant writes nothing more.
    const burst = await request(port, { reqPath: '/__auth/whoami', headers: { cookie } });
    assert.equal(setCookie(burst, 'dsh_gate_session'), null, 'an already refreshed session is not rewritten');

    // Keep the session alive every 24h (inside the 48h idle window). Even so,
    // it must die at the 30-day absolute ceiling.
    let at = T0 + 2 * HOUR;
    for (let step = 1; step <= 28; step += 1) {
      at += 24 * HOUR;
      clock.value = at;
      const alive = await request(port, { reqPath: '/__auth/whoami', headers: { cookie } });
      assert.equal(alive.status, 200);
      assert.equal(JSON.parse(alive.body).authenticated, true, `session must stay valid at ${(at - T0) / DAY} days`);
    }
    // Last request just before the ceiling keeps it alive; one hour later both
    // the absolute ceiling and the (capped) idle deadline have passed.
    clock.value = T0 + 30 * DAY - HOUR;
    const beforeCap = await request(port, { reqPath: '/__auth/whoami', headers: { cookie } });
    assert.equal(JSON.parse(beforeCap.body).authenticated, true);
    clock.value = T0 + 30 * DAY + HOUR;
    const expired = await request(port, { reqPath: '/__auth/whoami', headers: { cookie } });
    assert.equal(expired.status, 200);
    assert.equal(JSON.parse(expired.body).authenticated, false, 'absolute ceiling invalidates an active session');
    // Admin access through the same cookie is refused as well.
    const admin = await request(port, { reqPath: '/__admin/api/state', headers: { cookie } });
    assert.equal(admin.status, 403);
    assert.equal(await store.findSession(session.token), null);
  } finally {
    await gateway?.close();
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('idle expiry invalidates a session and removes it from the store', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('session-idle', clock);
  try {
    const paired = await pairDevice(store);
    const session = await store.createSession({ deviceId: paired.device.id, ttlMs: HOUR, absoluteTtlMs: SESSION_ABS_DAYS * DAY });
    clock.value = T0 + HOUR + 1;
    assert.equal(await store.findSession(session.token), null);
    assert.equal(store.sessions.length, 0);
  } finally {
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('revoke cascade deletes the device, all its sessions and pending tickets', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('revoke-cascade', clock);
  try {
    const paired = await pairDevice(store);
    const second = await pairDevice(store);
    const firstSession = await store.createSession({ deviceId: paired.device.id, ttlMs: SESSION_TTL_HOURS * HOUR });
    const secondSession = await store.createSession({ deviceId: paired.device.id, ttlMs: SESSION_TTL_HOURS * HOUR });
    const otherSession = await store.createSession({ deviceId: second.device.id, ttlMs: SESSION_TTL_HOURS * HOUR });
    const pendingTicket = await store.issueTicket({ ttlMs: 60_000 });
    assert.equal(store.sessions.length, 3);

    assert.equal(await store.revokeDevice(paired.device.id), true);
    assert.equal(store.devices.length, 1);
    assert.equal(store.sessions.length, 1, 'every session of the revoked device is gone');
    assert.equal(store.tickets.length, 0, 'pending pairing tickets are cleared');
    assert.equal(await store.findDeviceByToken(paired.token), null, 'device token no longer resolves');
    assert.equal(await store.findSession(firstSession.token), null);
    assert.equal(await store.findSession(secondSession.token), null);
    assert.equal(await store.findSession(otherSession.token) !== null, true, 'other devices keep their sessions');
    const redeem = await store.redeemTicket(pendingTicket.ticket, {
      maxDevices: 8,
      deviceTtlMs: DEVICE_TTL_DAYS * DAY,
      deviceAbsoluteTtlMs: DEVICE_ABS_DAYS * DAY,
      name: 'stale',
      platform: 'web',
      origin: 'http://127.0.0.1'
    });
    assert.equal(redeem.status, 'invalid_ticket', 'a ticket minted before the revoke cannot pair a replacement');
  } finally {
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('pruning an expired device also deletes its sessions', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('device-prune', clock);
  try {
    const paired = await pairDevice(store, { deviceAbsoluteTtlMs: 10 * DAY });
    // The session outlives the device: only the device prune can remove it.
    const session = await store.createSession({
      deviceId: paired.device.id,
      ttlMs: 60 * DAY,
      absoluteTtlMs: 60 * DAY
    });
    clock.value = T0 + 11 * DAY;
    // Any locked state transition runs the maintenance prune.
    await store.issueTicket({ ttlMs: 60_000 });
    assert.equal(store.devices.length, 0, 'expired device pruned');
    assert.equal(store.sessions.some((candidate) => candidate.deviceId === paired.device.id), false);
    assert.equal(await store.findSession(session.token), null);
    assert.equal(await store.findDeviceByToken(paired.token), null);
  } finally {
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('revocation over HTTP invalidates device token, session cookies and device cookie immediately', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('revoke-http', clock);
  let gateway;
  let port;
  try {
    const paired = await pairDevice(store);
    const sessionA = await store.createSession({ deviceId: paired.device.id, ttlMs: SESSION_TTL_HOURS * HOUR });
    const sessionB = await store.createSession({ deviceId: paired.device.id, ttlMs: SESSION_TTL_HOURS * HOUR });
    const staleTicket = await store.issueTicket({ ttlMs: 60_000 });
    ({ gateway, port } = await startGateway(store, clock));

    const revoke = await request(port, {
      method: 'POST',
      reqPath: '/__admin/api/devices/revoke',
      headers: { 'x-auth-gate-admin-key': store.adminKey },
      body: { deviceId: paired.device.id }
    });
    assert.equal(revoke.status, 200);
    const revokePayload = JSON.parse(revoke.body);
    assert.equal(revokePayload.sessionsRevoked, 2);

    const renew = await request(port, { method: 'POST', reqPath: '/__auth/renew', body: { deviceToken: paired.token } });
    assert.equal(renew.status, 401);
    assert.equal(JSON.parse(renew.body).error, 'device_required');

    for (const session of [sessionA, sessionB]) {
      const whoami = await request(port, { reqPath: '/__auth/whoami', headers: { cookie: `dsh_gate_session=${session.token}` } });
      assert.equal(whoami.status, 200);
      assert.equal(JSON.parse(whoami.body).authenticated, false, 'every session cookie of the device is dead');
      const admin = await request(port, { reqPath: '/__admin/api/state', headers: { cookie: `dsh_gate_session=${session.token}` } });
      assert.equal(admin.status, 403);
    }

    const redeem = await request(port, { method: 'POST', reqPath: '/__auth/pair/redeem', body: { ticket: staleTicket.ticket } });
    assert.equal(redeem.status, 401);
    assert.equal(JSON.parse(redeem.body).error, 'invalid_ticket');
  } finally {
    await gateway?.close();
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('v0.7.1 P2-1: cookie responses are private/no-store + Vary: cookie; assets never refresh', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('cookie-cache', clock);
  let gateway;
  let port;
  try {
    await store.createUser({ username: 'admin', passwordHash: await hashPassword(PASSWORD), totpSecretB32: generateSecret() });
    const paired = await pairDevice(store);
    ({ gateway, port } = await startGateway(store, clock));

    // Pure merge used for proxied responses too: whatever dsh sent, a
    // cookie-bearing response must become private/no-store + Vary: cookie.
    assert.equal(privateCacheControl('public, max-age=60'), 'private, no-store, max-age=60');
    assert.equal(privateCacheControl('no-cache, private'), 'private, no-store, no-cache');
    assert.equal(varyCookie('accept-encoding'), 'accept-encoding, cookie');
    assert.equal(varyCookie('Accept-Encoding, Cookie'), 'Accept-Encoding, Cookie');
    const proxied = { 'cache-control': 'public, max-age=60', vary: 'accept-encoding', 'set-cookie': ['a=b'] };
    hardenCookieResponse({ getHeader() { return undefined; } }, proxied);
    assert.equal(proxied['cache-control'], 'private, no-store, max-age=60');
    assert.equal(proxied.vary, 'accept-encoding, cookie');

    // The CSRF cookie and the login cookies must carry the cache hints too.
    const csrfResponse = await request(port, { reqPath: '/__auth/csrf' });
    assert.equal(csrfResponse.status, 200);
    assert.match(csrfResponse.headers['cache-control'], /private, no-store/u);
    assert.equal(csrfResponse.headers.vary, 'cookie');
    const csrf = JSON.parse(csrfResponse.body).csrf;

    const login = await request(port, {
      method: 'POST',
      reqPath: '/__auth/login',
      headers: {
        cookie: `dsh_gate_device=${paired.token}; dsh_gate_csrf=${csrf}`,
        'x-auth-gate-csrf': csrf
      },
      body: { username: 'admin', password: PASSWORD }
    });
    assert.equal(login.status, 200, login.body);
    assert.match(login.headers['cache-control'], /private, no-store/u);
    assert.equal(login.headers.vary, 'cookie');
    const sessionToken = setCookieValue(login, 'dsh_gate_session');
    assert.ok(sessionToken);
    const cookie = `dsh_gate_session=${sessionToken}`;

    // 2h later the refresh interval has passed: an authenticated API request
    // re-issues the cookie and the response must stay uncacheable.
    clock.value = T0 + 2 * HOUR;
    const whoami = await request(port, { reqPath: '/__auth/whoami', headers: { cookie } });
    assert.equal(whoami.status, 200);
    assert.ok(setCookie(whoami, 'dsh_gate_session'), 'due API request refreshes');
    assert.match(whoami.headers['cache-control'], /private, no-store/u);
    assert.equal(whoami.headers.vary, 'cookie');

    // A public asset fetched with the same cookie two hours later would be due
    // for another refresh; it must not touch the session nor set any cookie.
    const before = await store.findSession(sessionToken);
    clock.value = T0 + 4 * HOUR;
    const asset = await request(port, { reqPath: '/assets/index-test.js', accept: '*/*', headers: { cookie } });
    assert.equal(asset.headers['set-cookie'], undefined, 'asset responses must not set cookies');
    const after = await store.findSession(sessionToken);
    assert.equal(after.lastRefreshedAt, before.lastRefreshedAt, 'asset request must not refresh the session');
    assert.equal(after.expiresAt, before.expiresAt, 'asset request must not slide the session');

    // The same instant, an authenticated HTML request is due again and does
    // refresh, with the hardened headers.
    const admin = await request(port, { reqPath: '/__admin', accept: 'text/html', headers: { cookie } });
    assert.equal(admin.status, 200, 'the session is still valid');
    assert.ok(setCookie(admin, 'dsh_gate_session'), 'due HTML request refreshes');
    assert.match(admin.headers['cache-control'], /private, no-store/u);
    assert.equal(admin.headers.vary, 'cookie');
  } finally {
    await gateway?.close();
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('v0.7.1 P2-3: over-age devices are rejected on session and token read paths', async () => {
  const clock = { value: T0 };
  const { dir, store } = await openStore('device-absolute-read', clock);
  let gateway;
  let port;
  try {
    // Persisted by an "older version": pairing had no absolute ceiling and a
    // 400-day idle window, so expiresAt is still future when the currently
    // configured 365-day ceiling passes.
    const sessionDevice = await pairDevice(store, { deviceTtlMs: 400 * DAY, deviceAbsoluteTtlMs: 0 });
    const session = await store.createSession({ deviceId: sessionDevice.device.id, ttlMs: 400 * DAY, absoluteTtlMs: 400 * DAY });
    const tokenDevice = await pairDevice(store, { deviceTtlMs: 400 * DAY, deviceAbsoluteTtlMs: 0 });
    ({ gateway, port } = await startGateway(store, clock));

    clock.value = T0 + 366 * DAY;
    const whoami = await request(port, { reqPath: '/__auth/whoami', headers: { cookie: `dsh_gate_session=${session.token}` } });
    assert.equal(whoami.status, 200);
    assert.equal(JSON.parse(whoami.body).authenticated, false, 'over-age device invalidates its session');
    assert.equal(await store.findDeviceById(sessionDevice.device.id), null, 'the device is removed');
    assert.equal(await store.findSession(session.token), null, 'all sessions of the device are removed');

    const renew = await request(port, { method: 'POST', reqPath: '/__auth/renew', body: { deviceToken: tokenDevice.token } });
    assert.equal(renew.status, 401, 'an over-age device token must not renew');
    assert.equal(JSON.parse(renew.body).error, 'device_required');
    assert.equal(await store.findDeviceById(tokenDevice.device.id), null);
  } finally {
    await gateway?.close();
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});
