import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as http from 'node:http';
import * as path from 'node:path';
import test from 'node:test';

import { DshSessionProvider } from '../lib/dsh-session.js';
import { createGateway, sanitizeNext } from '../lib/gateway.js';
import { adminPage } from '../lib/pages.js';
import { hashPassword, verifyPassword } from '../lib/password.js';
import { StateStore } from '../lib/store.js';
import { generateSecret, generateTotp } from '../lib/totp.js';

const silent = { info() {}, warn() {}, error() {} };
const ROOT = path.join(process.cwd(), '.test-tmp', 'admin-session');
const NOW = 1_800_000_000_000;
const PASSWORD = 'Admin-Session-Password-2026!';
const NEW_PASSWORD = 'Admin-Session-Password-2026-NEW!';

function httpRequest(port, { method = 'GET', path: reqPath = '/', headers = {}, body, host } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path: reqPath,
        method,
        headers: {
          host: host ?? `127.0.0.1:${port}`,
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

function cookieHeader(...values) {
  return values.filter((value) => typeof value === 'string' && value.length > 0).join('; ');
}

async function makeHarness(label, clock = { value: NOW }) {
  const dir = path.join(ROOT, `${process.pid}-${Date.now()}-${label}`);
  await fs.mkdir(dir, { recursive: true });
  const store = await StateStore.open({ stateDir: dir, logger: silent, now: () => clock.value });
  const secret = generateSecret();
  await store.createUser({ username: 'admin', passwordHash: await hashPassword(PASSWORD), totpSecretB32: secret });
  const ticket = await store.issueTicket({ ttlMs: 60_000 });
  const device = await store.redeemTicket(ticket.ticket, {
    maxDevices: 8,
    deviceTtlMs: 90 * 86_400_000,
    name: 'Android 测试机',
    platform: 'android',
    origin: 'http://127.0.0.1'
  });
  assert.equal(device.status, 'ok');
  const session = await store.createSession({ deviceId: device.device.id, ttlMs: 8 * 3_600_000 });
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
    now: () => clock.value
  });
  await gateway.listen();
  const port = gateway.server.address().port;
  const cleanup = async () => {
    await gateway.close();
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  };
  return {
    store,
    secret,
    deviceToken: device.token,
    deviceId: device.device.id,
    sessionToken: session.token,
    gateway,
    port,
    clock,
    cleanup
  };
}

async function getCsrf(port, cookie) {
  const response = await httpRequest(port, { path: '/__auth/csrf', headers: cookie ? { cookie } : {} });
  assert.equal(response.status, 200);
  const csrf = cookieValue(response, 'dsh_gate_csrf');
  assert.ok(csrf);
  return csrf;
}

function sessionCookie(harness, token = harness.sessionToken) {
  return `dsh_gate_session=${token}`;
}

/** Current 6-digit code for the harness clock. */
function currentTotp(harness, now = NOW) {
  return generateTotp(harness.secret, { now });
}

/** A deterministic wrong 6-digit code (never the current one). */
function wrongTotp(harness, now = NOW) {
  return currentTotp(harness, now) === '000000' ? '000001' : '000000';
}

test('admin page: no session redirects to login; session and adminKey pass, loopback auto-admin is disabled', async () => {
  const h = await makeHarness('channels');
  try {
    const anonymousHtml = await httpRequest(h.port, {
      path: '/__admin',
      headers: { accept: 'text/html,application/xhtml+xml' }
    });
    assert.equal(anonymousHtml.status, 302);
    assert.equal(anonymousHtml.headers.location, '/__auth/login?next=/__admin');

    const anonymousApi = await httpRequest(h.port, { path: '/__admin/api/state' });
    assert.equal(anonymousApi.status, 403);
    assert.equal(JSON.parse(anonymousApi.body).error, 'forbidden');

    const page = await httpRequest(h.port, {
      path: '/__admin',
      headers: { accept: 'text/html', cookie: sessionCookie(h) }
    });
    assert.equal(page.status, 200);
    assert.match(page.body, /DSH 认证管理/u);
    assert.match(page.body, /id="section-account"/u);
    assert.match(page.body, /id="section-pair"/u);
    assert.match(page.body, /id="pair-totp"/u);
    assert.match(page.body, /id="section-devices"/u);
    assert.match(page.body, /id="section-sessions"/u);
    assert.match(page.body, /id="section-audit"/u);
    assert.match(page.body, /Android 测试机/u);
    assert.match(page.body, new RegExp(`data-device-id="${h.deviceId}"`, 'u'));
    assert.match(page.body, /所有设备需重新扫码/u);
    assert.match(page.body, /登录会话/u);
    assert.equal(page.body.includes(h.secret), false, 'TOTP secret must not be echoed');
    assert.equal(page.body.includes(h.deviceToken), false, 'device token must not be echoed');
    assert.equal(page.body.includes(h.store.user.passwordHash), false, 'password hash must not be echoed');
    assert.equal(page.body.includes(h.store.adminKey), false, 'admin key must not be echoed');

    const stateBySession = await httpRequest(h.port, {
      path: '/__admin/api/state',
      headers: { cookie: sessionCookie(h) }
    });
    assert.equal(stateBySession.status, 200);
    assert.equal(JSON.parse(stateBySession.body).devices.length, 1);

    // The harness listens on loopback, so the automatic loopback admin channel
    // must be disabled even when the peer and Host look local (P0-1). The
    // adminKey file remains the local recovery channel.
    const stateByLoopback = await httpRequest(h.port, { path: '/__admin/api/state', host: `127.0.0.1:${h.port}` });
    assert.equal(stateByLoopback.status, 403);
    assert.equal(JSON.parse(stateByLoopback.body).error, 'forbidden');

    // adminKey channel still works.
    const stateByKey = await httpRequest(h.port, {
      path: '/__admin/api/state',
      headers: { 'x-auth-gate-admin-key': h.store.adminKey }
    });
    assert.equal(stateByKey.status, 200);
  } finally {
    await h.cleanup();
  }
});

test('session POST requires CSRF; pairing QR requires TOTP while key/loopback are exempt', async () => {
  const h = await makeHarness('csrf-qr');
  try {
    const noCsrf = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/qr',
      headers: { cookie: sessionCookie(h) },
      body: {}
    });
    assert.equal(noCsrf.status, 403);
    assert.equal(JSON.parse(noCsrf.body).error, 'csrf_invalid');

    const csrf = await getCsrf(h.port, sessionCookie(h));
    const headerNoCookie = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/qr',
      headers: { cookie: sessionCookie(h), 'x-auth-gate-csrf': csrf },
      body: {}
    });
    assert.equal(headerNoCookie.status, 403, 'header without the CSRF cookie must fail');

    const headers = {
      cookie: cookieHeader(sessionCookie(h), `dsh_gate_csrf=${csrf}`),
      'x-auth-gate-csrf': csrf
    };
    const totp = currentTotp(h);

    // v0.4.0: pairing is the second factor. Minting a ticket from a WebUI
    // session must prove a fresh TOTP code; the current password is not asked.
    const missing = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/qr',
      headers,
      body: { platform: 'web' }
    });
    assert.equal(missing.status, 403);
    assert.equal(JSON.parse(missing.body).error, 'totp_required');
    assert.equal(h.store.devices.length, 1, 'a rejected QR must not add a device');
    assert.ok(h.store.auditTail(10).some((entry) => entry.type === 'admin_denied' && entry.detail === 'totp_required'));
    assert.equal(h.store.auditTail(20).some((entry) => String(entry.detail).includes('pair_ticket_issued')), false);

    // A correct current password is NOT an alternative pairing proof: QR
    // minting from the session channel always requires a TOTP code. Without
    // this, stolen credentials could be replayed to bind a new 90-day device.
    const withPasswordOnly = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/qr',
      headers,
      body: { platform: 'web', currentPassword: PASSWORD }
    });
    assert.equal(withPasswordOnly.status, 403, 'currentPassword must not replace TOTP for QR minting');
    assert.equal(JSON.parse(withPasswordOnly.body).error, 'totp_required');
    assert.equal(h.store.devices.length, 1, 'a rejected QR must not add a device');
    assert.ok(h.store.auditTail(10).some((entry) => entry.type === 'admin_denied' && entry.detail === 'totp_required'));

    const wrong = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/qr',
      headers,
      body: { platform: 'web', totp: wrongTotp(h) }
    });
    assert.equal(wrong.status, 403);
    assert.equal(JSON.parse(wrong.body).error, 'totp_invalid');
    assert.ok(h.store.auditTail(10).some((entry) => entry.type === 'admin_denied' && entry.detail === 'totp_invalid'));

    const qr = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/qr',
      headers,
      body: { platform: 'web', totp }
    });
    assert.equal(qr.status, 200);
    const payload = JSON.parse(qr.body);
    assert.match(payload.url, /^http:\/\/127\.0\.0\.1\/__auth\/pair#v=1&t=/u);
    assert.match(payload.qrSvg, /<svg/u);
    assert.ok(payload.expiresAt > NOW);
    assert.equal(qr.body.includes(totp), false, 'the TOTP code must never be echoed');
    assert.equal(qr.body.includes(PASSWORD), false, 'the password must never be echoed');
    assert.equal(h.store.devices.length, 1, 'issuing a QR must not pair a device');
    assert.ok(h.store.auditTail(10).some((entry) => String(entry.detail).includes('pair_ticket_issued')));
    const ticket = new URLSearchParams(new URL(payload.url).hash.slice(1)).get('t');
    assert.ok(ticket);
    const state = await httpRequest(h.port, { path: '/__admin/api/state', headers: { cookie: sessionCookie(h) } });
    assert.equal(state.body.includes(ticket), false, 'ticket must not be echoed by /state');

    // Verification does not consume the login replay counter: the same code
    // may mint several QR codes inside one 30s window.
    const second = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/qr',
      headers,
      body: { platform: 'android', totp }
    });
    assert.equal(second.status, 200, 'the same TOTP window must be reusable for pairing');
    assert.equal(h.store.user.lastTotpCounter ?? null, null, 'pairing must not consume the TOTP counter');

    // adminKey is a bearer credential and stays exempt from TOTP.
    const byKey = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/qr',
      headers: { 'x-auth-gate-admin-key': h.store.adminKey },
      body: { platform: 'web' }
    });
    assert.equal(byKey.status, 200);
    assert.match(JSON.parse(byKey.body).url, /^http:\/\/127\.0\.0\.1\/__auth\/pair#v=1&t=/u);

    // A loopback listener disables the automatic loopback admin channel: even a
    // loopback peer with a pinned Host and a valid CSRF pair gets no access.
    const loopbackCsrf = await getCsrf(h.port);
    const byLoopback = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/qr',
      host: `127.0.0.1:${h.port}`,
      headers: {
        cookie: `dsh_gate_csrf=${loopbackCsrf}`,
        'x-auth-gate-csrf': loopbackCsrf
      },
      body: { platform: 'web' }
    });
    assert.equal(byLoopback.status, 403);
    assert.equal(JSON.parse(byLoopback.body).error, 'forbidden');
  } finally {
    await h.cleanup();
  }
});

test('session pairing TOTP failures are rate limited per IP: the fifth failure is 429', async () => {
  const h = await makeHarness('totp-ratelimit');
  try {
    const csrf = await getCsrf(h.port, sessionCookie(h));
    const headers = {
      cookie: cookieHeader(sessionCookie(h), `dsh_gate_csrf=${csrf}`),
      'x-auth-gate-csrf': csrf
    };
    for (let attempt = 1; attempt <= 4; attempt += 1) {
      const response = await httpRequest(h.port, {
        method: 'POST',
        path: '/__admin/api/qr',
        headers,
        body: { platform: 'web', totp: wrongTotp(h) }
      });
      assert.equal(response.status, 403, `failure ${attempt} must be 403`);
      assert.equal(JSON.parse(response.body).error, 'totp_invalid');
    }
    // The pairing-TOTP scope has its own counter: a wrong current password on
    // the credential-rotation endpoint is not affected by the TOTP failures.
    const passwordWrong = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/user',
      headers,
      body: { currentPassword: 'wrong-password', resetTotp: true }
    });
    assert.equal(passwordWrong.status, 403);
    assert.equal(JSON.parse(passwordWrong.body).error, 'invalid_current_password');

    const fifth = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/qr',
      headers,
      body: { platform: 'web', totp: wrongTotp(h) }
    });
    assert.equal(fifth.status, 429);
    assert.equal(JSON.parse(fifth.body).error, 'rate_limited');
    assert.ok(Number(fifth.headers['retry-after']) >= 1);
    assert.equal(h.store.user.totpSecretB32, h.secret, 'a locked reset must not mutate the secret');

    // A correct code does not bypass an active lock.
    const locked = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/qr',
      headers,
      body: { platform: 'web', totp: currentTotp(h) }
    });
    assert.equal(locked.status, 429);
    assert.equal(JSON.parse(locked.body).error, 'rate_limited');
    assert.ok(h.store.auditTail(20).some((entry) => entry.type === 'admin_denied' && entry.detail === 'pairing_totp_rate_limited'));

    // The lock expires after five minutes.
    h.clock.value += 5 * 60_000 + 1;
    const after = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/qr',
      headers,
      body: { platform: 'web', totp: currentTotp(h, h.clock.value) }
    });
    assert.equal(after.status, 200);
    assert.match(JSON.parse(after.body).qrSvg, /<svg/u);
  } finally {
    await h.cleanup();
  }
});

test('a successful pairing-TOTP check clears the session failure counter', async () => {
  const h = await makeHarness('totp-reset');
  try {
    const csrf = await getCsrf(h.port, sessionCookie(h));
    const headers = {
      cookie: cookieHeader(sessionCookie(h), `dsh_gate_csrf=${csrf}`),
      'x-auth-gate-csrf': csrf
    };
    for (let attempt = 1; attempt <= 4; attempt += 1) {
      const response = await httpRequest(h.port, {
        method: 'POST',
        path: '/__admin/api/qr',
        headers,
        body: { platform: 'web', totp: wrongTotp(h) }
      });
      assert.equal(response.status, 403);
    }
    const success = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/qr',
      headers,
      body: { platform: 'web', totp: currentTotp(h) }
    });
    assert.equal(success.status, 200);

    // If the success had not cleared the counter, the next failure would be
    // the fifth overall and therefore 429 instead of 403.
    for (let attempt = 1; attempt <= 4; attempt += 1) {
      const response = await httpRequest(h.port, {
        method: 'POST',
        path: '/__admin/api/qr',
        headers,
        body: { platform: 'web', totp: wrongTotp(h) }
      });
      assert.equal(response.status, 403, `post-success failure ${attempt} must be 403`);
    }
    const finalSuccess = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/qr',
      headers,
      body: { platform: 'web', totp: currentTotp(h) }
    });
    assert.equal(finalSuccess.status, 200);
  } finally {
    await h.cleanup();
  }
});

test('QR issuance is rate limited to 10 per minute per IP', async () => {
  const h = await makeHarness('qr-ratelimit');
  try {
    for (let attempt = 1; attempt <= 10; attempt += 1) {
      const response = await httpRequest(h.port, {
        method: 'POST',
        path: '/__admin/api/qr',
        headers: { 'x-auth-gate-admin-key': h.store.adminKey },
        body: { platform: 'web' }
      });
      assert.equal(response.status, 200, `QR issuance ${attempt} must succeed`);
    }
    const eleventh = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/qr',
      headers: { 'x-auth-gate-admin-key': h.store.adminKey },
      body: { platform: 'web' }
    });
    assert.equal(eleventh.status, 429);
    assert.equal(JSON.parse(eleventh.body).error, 'rate_limited');
    assert.ok(Number(eleventh.headers['retry-after']) >= 1);
    assert.equal(h.store.devices.length, 1, 'rate-limited requests must not pair devices');

    h.clock.value += 60_000 + 1;
    const after = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/qr',
      headers: { 'x-auth-gate-admin-key': h.store.adminKey },
      body: { platform: 'web' }
    });
    assert.equal(after.status, 200);
  } finally {
    await h.cleanup();
  }
});

test('session channel can revoke another device and its token/session die', async () => {
  const h = await makeHarness('revoke');
  try {
    const ticket = await h.store.issueTicket({ ttlMs: 60_000 });
    const second = await h.store.redeemTicket(ticket.ticket, {
      maxDevices: 8,
      deviceTtlMs: 90 * 86_400_000,
      name: '浏览器配对',
      platform: 'web',
      origin: 'http://127.0.0.1'
    });
    assert.equal(second.status, 'ok');
    const secondSession = await h.store.createSession({ deviceId: second.device.id, ttlMs: 3_600_000 });

    const stateBefore = await httpRequest(h.port, { path: '/__admin/api/state', headers: { cookie: sessionCookie(h) } });
    assert.equal(JSON.parse(stateBefore.body).devices.length, 2);

    const csrf = await getCsrf(h.port, sessionCookie(h));
    const revoke = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/devices/revoke',
      headers: {
        cookie: cookieHeader(sessionCookie(h), `dsh_gate_csrf=${csrf}`),
        'x-auth-gate-csrf': csrf
      },
      body: { deviceId: second.device.id }
    });
    assert.equal(revoke.status, 200);
    assert.deepEqual(JSON.parse(revoke.body), { ok: true, revoked: true, sessionsRevoked: 1, ticketsRevoked: 0 });

    // The revoked device's session no longer authorizes admin access.
    const revokedSession = await httpRequest(h.port, {
      path: '/__admin/api/state',
      headers: { cookie: sessionCookie(h, secondSession.token) }
    });
    assert.equal(revokedSession.status, 403);

    const renew = await httpRequest(h.port, {
      method: 'POST',
      path: '/__auth/renew',
      body: { deviceToken: second.token }
    });
    assert.equal(renew.status, 401);
    assert.equal(JSON.parse(renew.body).error, 'device_required');

    const stateAfter = await httpRequest(h.port, { path: '/__admin/api/state', headers: { cookie: sessionCookie(h) } });
    assert.equal(stateAfter.status, 200);
    assert.equal(JSON.parse(stateAfter.body).devices.length, 1);
    assert.ok(h.store.auditTail(10).some((entry) => entry.type === 'device_revoke'));
  } finally {
    await h.cleanup();
  }
});

test('session password change demands currentPassword and revokes devices/sessions', async () => {
  const h = await makeHarness('password');
  try {
    const beforeHash = h.store.user.passwordHash;
    const csrf = await getCsrf(h.port, sessionCookie(h));
    const headers = {
      cookie: cookieHeader(sessionCookie(h), `dsh_gate_csrf=${csrf}`),
      'x-auth-gate-csrf': csrf
    };

    const missing = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/user',
      headers,
      body: { password: NEW_PASSWORD }
    });
    assert.equal(missing.status, 403);
    assert.equal(JSON.parse(missing.body).error, 'invalid_current_password');
    assert.equal(h.store.user.passwordHash, beforeHash, 'a rejected change must not mutate the hash');

    const wrong = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/user',
      headers,
      body: { currentPassword: 'not-the-current-password', password: NEW_PASSWORD }
    });
    assert.equal(wrong.status, 403);
    assert.equal(JSON.parse(wrong.body).error, 'invalid_current_password');
    assert.equal(h.store.user.passwordHash, beforeHash);

    const changed = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/user',
      headers,
      body: { currentPassword: PASSWORD, password: NEW_PASSWORD }
    });
    assert.equal(changed.status, 200);
    const payload = JSON.parse(changed.body);
    assert.equal(payload.ok, true);
    assert.equal(payload.devicesRevoked, 1);
    assert.equal(payload.sessionsRevoked, 1);
    assert.equal(payload.rePairRequired, true);
    assert.equal(h.store.devices.length, 0);
    assert.equal(h.store.sessions.length, 0);
    assert.equal(await verifyPassword(NEW_PASSWORD, h.store.user.passwordHash), true);
    assert.equal(changed.body.includes(beforeHash), false);

    const renew = await httpRequest(h.port, {
      method: 'POST',
      path: '/__auth/renew',
      body: { deviceToken: h.deviceToken }
    });
    assert.equal(renew.status, 401);

    const page = await httpRequest(h.port, {
      path: '/__admin',
      headers: { accept: 'text/html', cookie: sessionCookie(h) }
    });
    assert.equal(page.status, 302);
    assert.equal(page.headers.location, '/__auth/login?next=/__admin');
  } finally {
    await h.cleanup();
  }
});

test('session TOTP reset returns the new secret/QR and revokes every device', async () => {
  const h = await makeHarness('totp');
  try {
    const csrf = await getCsrf(h.port, sessionCookie(h));
    const headers = {
      cookie: cookieHeader(sessionCookie(h), `dsh_gate_csrf=${csrf}`),
      'x-auth-gate-csrf': csrf
    };
    const wrong = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/user',
      headers,
      body: { currentPassword: 'wrong', resetTotp: true }
    });
    assert.equal(wrong.status, 403);
    assert.equal(h.store.user.totpSecretB32, h.secret);

    const reset = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/user',
      headers,
      body: { currentPassword: PASSWORD, resetTotp: true }
    });
    assert.equal(reset.status, 200);
    const payload = JSON.parse(reset.body);
    assert.equal(payload.ok, true);
    assert.equal(payload.devicesRevoked, 1);
    assert.equal(payload.sessionsRevoked, 1);
    assert.equal(payload.rePairRequired, true);
    assert.notEqual(payload.secretB32, h.secret);
    assert.equal(payload.secretB32, h.store.user.totpSecretB32);
    assert.match(payload.otpauthUri, /^otpauth:\/\/totp\//u);
    assert.equal(payload.otpauthUri.includes(payload.secretB32), true);
    assert.match(payload.qrSvg, /<svg/u);
    assert.equal(reset.body.includes(h.secret), false, 'the old TOTP secret must not be echoed');
    assert.equal(h.store.devices.length, 0);
    assert.equal(h.store.sessions.length, 0);

    const page = await httpRequest(h.port, {
      path: '/__admin',
      headers: { accept: 'text/html', cookie: sessionCookie(h) }
    });
    assert.equal(page.status, 302);
  } finally {
    await h.cleanup();
  }
});

test('adminKey keeps working without currentPassword/TOTP; loopback auto-admin is disabled on a loopback listener', async () => {
  const h = await makeHarness('legacy');
  try {
    // adminKey is a bearer credential: no CSRF, no currentPassword.
    const byKey = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/user',
      headers: { 'x-auth-gate-admin-key': h.store.adminKey },
      body: { password: NEW_PASSWORD }
    });
    assert.equal(byKey.status, 200);
    assert.equal(JSON.parse(byKey.body).rePairRequired, true);

    // adminKey QR remains password-free.
    const qrByKey = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/qr',
      headers: { 'x-auth-gate-admin-key': h.store.adminKey },
      body: { platform: 'web' }
    });
    assert.equal(qrByKey.status, 200);
    assert.match(JSON.parse(qrByKey.body).qrSvg, /<svg/u);

    // The harness binds 127.0.0.1: the loopback channel is disabled outright,
    // with or without a valid CSRF pair, and adminKey remains usable.
    const loopbackNoCsrf = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/user',
      host: `127.0.0.1:${h.port}`,
      body: { resetTotp: true }
    });
    assert.equal(loopbackNoCsrf.status, 403);
    assert.equal(JSON.parse(loopbackNoCsrf.body).error, 'forbidden');

    const csrf = await getCsrf(h.port);
    const loopbackQr = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/qr',
      host: `127.0.0.1:${h.port}`,
      headers: {
        cookie: `dsh_gate_csrf=${csrf}`,
        'x-auth-gate-csrf': csrf
      },
      body: { platform: 'web' }
    });
    assert.equal(loopbackQr.status, 403);
    assert.equal(JSON.parse(loopbackQr.body).error, 'forbidden');

    const resetByKey = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/user',
      headers: { 'x-auth-gate-admin-key': h.store.adminKey },
      body: { resetTotp: true }
    });
    assert.equal(resetByKey.status, 200);
    assert.match(JSON.parse(resetByKey.body).qrSvg, /<svg/u);
  } finally {
    await h.cleanup();
  }
});

test('state and sessions summaries expose online/current but no secret material', async () => {
  const h = await makeHarness('summaries');
  try {
    const state = await httpRequest(h.port, {
      path: '/__admin/api/state',
      headers: { cookie: sessionCookie(h) }
    });
    assert.equal(state.status, 200);
    const payload = JSON.parse(state.body);
    assert.equal(payload.sessions, 1);
    assert.equal(payload.sessionCount, 1);
    assert.equal(payload.devices.length, 1);
    assert.equal(payload.devices[0].online, true);
    assert.equal(typeof payload.devices[0].lastActiveAt, 'number');
    assert.equal(payload.sessionList.length, 1);
    assert.deepEqual(Object.keys(payload.sessionList[0]).sort(), ['createdAt', 'current', 'deviceId', 'expiresAt', 'lastSeenAt']);
    assert.equal(payload.sessionList[0].deviceId, h.deviceId);
    assert.equal(payload.sessionList[0].current, true);
    assert.equal(state.body.includes(h.secret), false);
    assert.equal(state.body.includes(h.deviceToken), false);
    assert.equal(state.body.includes(h.store.user.passwordHash), false);
    assert.doesNotMatch(state.body, /passwordHash|totpSecretB32|tokenHash|deviceToken/u);

    const sessions = await httpRequest(h.port, {
      path: '/__admin/api/sessions',
      headers: { cookie: sessionCookie(h) }
    });
    assert.equal(sessions.status, 200);
    const sessionsPayload = JSON.parse(sessions.body);
    assert.equal(sessionsPayload.sessionCount, 1);
    assert.equal(sessionsPayload.sessionList[0].current, true);
    assert.doesNotMatch(sessions.body, /passwordHash|totpSecretB32|tokenHash|deviceToken/u);

    // Advancing the clock without touching the session makes the device offline.
    h.clock.value += 121_000;
    const offline = await httpRequest(h.port, {
      path: '/__admin/api/state',
      headers: { 'x-auth-gate-admin-key': h.store.adminKey }
    });
    assert.equal(offline.status, 200);
    const offlinePayload = JSON.parse(offline.body);
    assert.equal(offlinePayload.devices[0].online, false);
    assert.equal(offlinePayload.sessionList[0].current, false);

    // A session request touches lastSeenAt again, so it is online once more.
    const onlineAgain = await httpRequest(h.port, {
      path: '/__admin/api/state',
      headers: { cookie: sessionCookie(h) }
    });
    assert.equal(JSON.parse(onlineAgain.body).devices[0].online, true);
    assert.equal(JSON.parse(onlineAgain.body).sessionList[0].current, true);
  } finally {
    await h.cleanup();
  }
});

test('admin page escapes untrusted names/audit values, orders sections and leaks no secrets', () => {
  const html = adminPage({
    nonce: 'nonce-1',
    csrf: 'csrf-token',
    channel: 'session',
    requiresCurrentPassword: true,
    requiresPairingTotp: true,
    pairTicketTtlSeconds: 120,
    serverTime: NOW,
    state: {
      configured: true,
      user: { username: '<script>alert(1)</script>', totpConfigured: false, totpConfirmed: false },
      devices: [
        {
          id: 'd_1"><img src=x onerror=alert(1)>',
          name: '<img src=x onerror=alert(1)>',
          platform: 'web',
          createdAt: 1,
          lastSeenAt: 2,
          expiresAt: 3,
          online: false
        }
      ],
      sessionList: [{ deviceId: 'd_1"><img src=x onerror=alert(1)>', createdAt: 1, lastSeenAt: 2, expiresAt: 3, current: true }],
      instanceId: 'instance-1'
    },
    audit: [{ at: NOW, type: 'admin_change', ip: '<b>ip</b>', deviceId: '', detail: '<img src=x onerror=alert(2)>' }]
  });
  assert.equal(html.includes('<img src=x'), false);
  assert.equal(html.includes('<script>alert(1)'), false);
  assert.match(html, /&lt;img src=x/u);
  assert.match(html, /&lt;b&gt;ip&lt;\/b&gt;/u);
  assert.match(html, /浏览器/u);
  assert.match(html, /当前/u);
  assert.match(html, /nonce="nonce-1"/u);
  assert.match(html, /id="section-account"/u);
  assert.match(html, /id="section-pair"/u);
  assert.match(html, /id="section-devices"/u);
  assert.match(html, /id="section-sessions"/u);
  assert.match(html, /id="section-audit"/u);
  const order = ['section-account', 'section-pair', 'section-devices', 'section-sessions', 'section-audit'].map((id) =>
    html.indexOf(`id="${id}"`)
  );
  assert.deepEqual(order, [...order].sort((left, right) => left - right));
  // v0.4.0: the pairing section asks for a 6-digit TOTP code, not the current
  // password; the account section keeps its separate current-password input.
  const pairHtml = html.slice(html.indexOf('id="section-pair"'), html.indexOf('id="section-devices"'));
  assert.match(pairHtml, /id="pair-totp"/u);
  assert.match(pairHtml, /inputmode="numeric" pattern="\[0-9\]\{6\}" maxlength="6"/u);
  assert.match(pairHtml, /6 位动态验证码（生成配对码必填）/u);
  assert.equal(pairHtml.includes('id="pair-current-password"'), false);
  assert.equal(pairHtml.includes('type="password"'), false);
  const accountHtml = html.slice(html.indexOf('id="section-account"'), html.indexOf('id="section-pair"'));
  assert.match(accountHtml, /id="current-password"/u);
  assert.equal(pairHtml.includes('csrf-token'), false, 'the pair block must not embed the CSRF token');
  assert.equal(html.includes('passwordHash'), false);
  assert.equal(html.includes('totpSecretB32'), false);
  assert.equal(html.includes('deviceToken'), false);
  assert.equal(html.includes('adminKey'), false);
});

test('sanitizeNext allows the admin page itself but not admin APIs', () => {
  assert.equal(sanitizeNext('/__admin'), '/__admin');
  assert.equal(sanitizeNext('/__admin/api/state'), '/');
  assert.equal(sanitizeNext('/__admin/anything'), '/');
});
