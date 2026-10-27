import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as http from 'node:http';
import * as path from 'node:path';
import test from 'node:test';

import { DshSessionProvider } from '../lib/dsh-session.js';
import { createGateway, rewriteLocation } from '../lib/gateway.js';
import { hashPassword } from '../lib/password.js';
import { StateStore } from '../lib/store.js';
import { generateSecret } from '../lib/totp.js';

const silent = { info() {}, warn() {}, error() {} };
const ROOT = path.join(process.cwd(), '.test-tmp', 'security-fixes');
const UPSTREAM = { host: '192.0.2.10:3080', origin: 'https://192.0.2.10:3080' };
const PASSWORD = 'Security-Test-Password-2026!';
const NEW_PASSWORD = 'Security-Test-Password-2026-NEW!';
const NOW = 1_800_000_000_000;

function httpRequest(port, { method = 'GET', path: reqPath = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
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
        res.on('end', () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8')
          });
        });
      }
    );
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

function cookieValue(response, name) {
  const set = response.headers['set-cookie'];
  if (!Array.isArray(set)) return null;
  for (const line of set) {
    const [pair] = line.split(';');
    const at = pair.indexOf('=');
    if (at > 0 && pair.slice(0, at) === name) return pair.slice(at + 1);
  }
  return null;
}

async function makeHarness(label) {
  const dir = path.join(ROOT, `${process.pid}-${Date.now()}-${label}`);
  await fs.mkdir(dir, { recursive: true });
  const store = await StateStore.open({ stateDir: dir, logger: silent, now: () => NOW });
  const secret = generateSecret();
  await store.createUser({ username: 'admin', passwordHash: await hashPassword(PASSWORD), totpSecretB32: secret });
  const ticket = await store.issueTicket({ ttlMs: 60_000 });
  const device = await store.redeemTicket(ticket.ticket, {
    maxDevices: 8,
    deviceTtlMs: 90 * 86_400_000,
    name: 'test',
    platform: 'android',
    origin: 'http://127.0.0.1'
  });
  assert.equal(device.status, 'ok');
  const gateway = createGateway({
    config: {
      listenHost: '127.0.0.1',
      listenPort: 0,
      publicUrl: 'http://127.0.0.1',
      upstream: 'http://127.0.0.1:9',
      upstreamInsecureTls: false,
      sessionTtlHours: 8,
      deviceTtlDays: 90,
      maxDevices: 8,
      pairTicketTtlSeconds: 120,
      loginLock: { maxFailures: 5, windowMinutes: 15, lockMinutes: 15 }
    },
    store,
    dshSession: new DshSessionProvider({ tokenUrl: 'http://127.0.0.1:9/?token=unused', logger: silent }),
    tls: null,
    logger: silent,
    now: () => NOW
  });
  await gateway.listen();
  const port = gateway.server.address().port;
  const cleanup = async () => {
    await gateway.close();
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  };
  return { store, secret, deviceToken: device.token, deviceId: device.device.id, gateway, port, cleanup };
}

async function login(port, { deviceToken, csrf, password = PASSWORD, totp }) {
  const body = { username: 'admin', password };
  if (totp !== undefined) body.totp = totp;
  const headers = { 'x-auth-gate-csrf': csrf };
  const cookies = [`dsh_gate_csrf=${csrf}`];
  if (deviceToken !== undefined && deviceToken !== null) cookies.push(`dsh_gate_device=${deviceToken}`);
  headers.cookie = cookies.join('; ');
  return httpRequest(port, { method: 'POST', path: '/__auth/login', headers, body });
}

test('renew only accepts a JSON body deviceToken (no empty body / cookie fallback)', async () => {
  const h = await makeHarness('renew');
  try {
    const emptyBody = await httpRequest(h.port, {
      method: 'POST',
      path: '/__auth/renew',
      headers: { 'content-type': 'application/json' },
      body: '{}'
    });
    assert.equal(emptyBody.status, 401);
    assert.equal(JSON.parse(emptyBody.body).error, 'device_required');

    const noContentType = await httpRequest(h.port, { method: 'POST', path: '/__auth/renew' });
    assert.equal(noContentType.status, 401);

    const cookieOnly = await httpRequest(h.port, {
      method: 'POST',
      path: '/__auth/renew',
      headers: { cookie: `dsh_gate_device=${h.deviceToken}` }
    });
    assert.equal(cookieOnly.status, 401);
    assert.equal(JSON.parse(cookieOnly.body).error, 'device_required');

    const bodyToken = await httpRequest(h.port, {
      method: 'POST',
      path: '/__auth/renew',
      body: { deviceToken: h.deviceToken }
    });
    assert.equal(bodyToken.status, 200);
    assert.equal(JSON.parse(bodyToken.body).ok, true);
    assert.match(String(bodyToken.headers['set-cookie']), /dsh_gate_session=/u);
  } finally {
    await h.cleanup();
  }
});

test('password change and TOTP reset revoke every device and session', async () => {
  const h = await makeHarness('revoke');
  const adminKey = h.store.adminKey;
  try {
    const nowSecret = h.secret;
    // --- password change: device token stops working.
    let res = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/user',
      headers: { 'x-auth-gate-admin-key': adminKey },
      body: { password: NEW_PASSWORD }
    });
    assert.equal(res.status, 200);
    const changed = JSON.parse(res.body);
    assert.equal(changed.devicesRevoked, 1);
    assert.equal(changed.rePairRequired, true);
    assert.equal(h.store.devices.length, 0);
    assert.equal(h.store.sessions.length, 0);

    res = await httpRequest(h.port, {
      method: 'POST',
      path: '/__auth/renew',
      body: { deviceToken: h.deviceToken }
    });
    assert.equal(res.status, 401);
    assert.equal(JSON.parse(res.body).error, 'device_required');

    // Re-pair, then reset TOTP: same revocation contract.
    const ticket = await h.store.issueTicket({ ttlMs: 60_000 });
    const device = await h.store.redeemTicket(ticket.ticket, {
      maxDevices: 8,
      deviceTtlMs: 90 * 86_400_000,
      name: 'second',
      platform: 'android',
      origin: 'http://127.0.0.1'
    });
    assert.equal(device.status, 'ok');
    res = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/user',
      headers: { 'x-auth-gate-admin-key': adminKey },
      body: { resetTotp: true }
    });
    assert.equal(res.status, 200);
    const reset = JSON.parse(res.body);
    assert.equal(reset.devicesRevoked, 1);
    assert.equal(reset.rePairRequired, true);
    assert.equal(h.store.devices.length, 0);
    assert.equal(h.store.sessions.length, 0);

    res = await httpRequest(h.port, {
      method: 'POST',
      path: '/__auth/renew',
      body: { deviceToken: device.token }
    });
    assert.equal(res.status, 401);
    assert.equal(JSON.parse(res.body).error, 'device_required');
    assert.notEqual(nowSecret, h.store.user.totpSecretB32);
  } finally {
    await h.cleanup();
  }
});

test('v0.4.0 login: paired device + password only; no TOTP and no replay counter', async () => {
  const h = await makeHarness('password-login');
  try {
    const csrfRes = await httpRequest(h.port, { path: '/__auth/csrf' });
    const csrf = cookieValue(csrfRes, 'dsh_gate_csrf');
    assert.ok(csrf);

    // Wrong password is still refused, with the device present.
    const wrong = await login(h.port, { deviceToken: h.deviceToken, csrf, password: 'not-the-password' });
    assert.equal(wrong.status, 401);
    assert.equal(JSON.parse(wrong.body).error, 'invalid_credentials');
    assert.ok(h.store.auditTail(10).some((entry) => entry.type === 'login_fail' && entry.detail === 'invalid_credentials'));

    // A paired device logs in with username + password; no TOTP field at all.
    const first = await login(h.port, { deviceToken: h.deviceToken, csrf });
    assert.equal(first.status, 200);
    assert.equal(JSON.parse(first.body).ok, true);
    assert.match(String(first.headers['set-cookie']), /dsh_gate_session=/u);
    assert.ok(h.store.auditTail(10).some((entry) => entry.type === 'login_ok' && entry.detail === 'password'));
    assert.equal(h.store.user.lastTotpCounter ?? null, null, 'login must not consume a TOTP counter');

    // A second login in the same instant also succeeds (no replay window).
    const second = await login(h.port, { deviceToken: h.deviceToken, csrf });
    assert.equal(second.status, 200);
  } finally {
    await h.cleanup();
  }
});

test('v0.4.0 login: an unpaired device is still refused with device_required', async () => {
  const h = await makeHarness('password-login-unpaired');
  try {
    const csrfRes = await httpRequest(h.port, { path: '/__auth/csrf' });
    const csrf = cookieValue(csrfRes, 'dsh_gate_csrf');
    assert.ok(csrf);
    const res = await login(h.port, { csrf });
    assert.equal(res.status, 401);
    assert.equal(JSON.parse(res.body).error, 'device_required');
  } finally {
    await h.cleanup();
  }
});

test('rewriteLocation never leaves the upstream origin', () => {
  assert.equal(rewriteLocation('//evil.example/phish', UPSTREAM), '/');
  assert.equal(rewriteLocation('https://evil.example/phish', UPSTREAM), '/');
  assert.equal(rewriteLocation('javascript:alert(1)', UPSTREAM), '/');
  assert.equal(rewriteLocation('http://[invalid', UPSTREAM), '/');
  assert.equal(rewriteLocation('https://192.0.2.10:3080/dash?q=1#x', UPSTREAM), '/dash?q=1#x');
  assert.equal(rewriteLocation('/relative/path', UPSTREAM), '/relative/path');
});

test('the generated admin key is never written to the log', async () => {
  const dir = path.join(ROOT, `${process.pid}-${Date.now()}-adminlog`);
  await fs.mkdir(dir, { recursive: true });
  const lines = [];
  const logger = {
    info: (line) => lines.push(String(line)),
    warn: (line) => lines.push(String(line)),
    error: (line) => lines.push(String(line))
  };
  const store = await StateStore.open({ stateDir: dir, logger, now: () => NOW });
  try {
    const key = store.adminKey;
    assert.match(key, /^[0-9a-f]{64}$/u);
    const joined = lines.join('\n');
    assert.equal(joined.includes(key), false);
    assert.match(joined, /generated admin key/u);
    assert.match(joined, /admin\.key/u);
    const stat = await fs.stat(path.join(dir, 'admin.key'));
    assert.equal(stat.mode & 0o777, 0o600);
  } finally {
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});
