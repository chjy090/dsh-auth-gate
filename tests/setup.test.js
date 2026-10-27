/**
 * First-run WebUI setup (v0.5.0): setup token lifecycle, public wizard page,
 * begin/confirm APIs, rate limiting, origin checks, initial device pairing and
 * the "closed forever after configured" invariant.
 */

import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as http from 'node:http';
import * as path from 'node:path';
import test from 'node:test';

import { DshSessionProvider } from '../lib/dsh-session.js';
import { createGateway } from '../lib/gateway.js';
import { hashPassword, verifyPassword } from '../lib/password.js';
import { StateStore } from '../lib/store.js';
import { generateSecret, generateTotp } from '../lib/totp.js';

const silent = { info() {}, warn() {}, error() {} };
const ROOT = path.join(process.cwd(), '.test-tmp', 'setup');
const NOW = 1_800_000_000_000;
const PASSWORD = 'Setup-Wizard-Password-2026!';
const USERNAME = 'setup-admin';

function recordLogger() {
  const lines = { info: [], warn: [], error: [] };
  return {
    lines,
    info: (...args) => lines.info.push(args.join(' ')),
    warn: (...args) => lines.warn.push(args.join(' ')),
    error: (...args) => lines.error.push(args.join(' '))
  };
}

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
          resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') });
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

function parseJson(response) {
  return JSON.parse(response.body);
}

async function tempDir(label) {
  const dir = path.join(ROOT, `${process.pid}-${Date.now()}-${label}`);
  await fs.rm(dir, { recursive: true, force: true });
  await fs.mkdir(dir, { recursive: true });
  return dir;
}

async function makeHarness(label, options = {}) {
  const dir = await tempDir(label);
  const logger = options.logger ?? silent;
  const store = await StateStore.open({ stateDir: dir, logger, now: () => NOW });
  if (options.configured === true) {
    await store.createUser({
      username: USERNAME,
      passwordHash: await hashPassword(PASSWORD),
      totpSecretB32: generateSecret()
    });
    // Mirrors the real confirm path: once configured no setup token remains.
    await store.clearSetupToken();
  }
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
    logger,
    now: () => NOW
  });
  await gateway.listen();
  const port = gateway.server.address().port;
  const cleanup = async () => {
    await gateway.close();
    await fs.rm(dir, { recursive: true, force: true });
  };
  return { dir, store, gateway, port, logger, cleanup };
}

function beginBody(token, overrides = {}) {
  return { token, username: USERNAME, password: PASSWORD, ...overrides };
}

function statusPath() {
  return '/__admin/api/setup/status';
}

// ---------------------------------------------------------------- store

test('setup token: generated 0600, reused, rotated, and removed once configured', async () => {
  const dir = await tempDir('store-token');
  const logger = recordLogger();
  const first = await StateStore.open({ stateDir: dir, logger, now: () => NOW });
  const token = first.setupToken;
  assert.match(token, /^[0-9a-f]{64}$/u);
  assert.equal(first.setupTokenPath, path.join(dir, 'setup.token'));
  assert.equal((await fs.readFile(first.setupTokenPath, 'utf8')).trim(), token);
  assert.equal((await fs.stat(first.setupTokenPath)).mode & 0o777, 0o600);
  // The token must never be logged by the store itself.
  assert.equal(logger.lines.info.some((line) => line.includes(token)), false);

  const rotated = await first.rotateSetupToken();
  assert.match(rotated, /^[0-9a-f]{64}$/u);
  assert.notEqual(rotated, token);
  assert.equal(first.setupToken, rotated);
  assert.equal((await fs.readFile(first.setupTokenPath, 'utf8')).trim(), rotated);
  await first.close();

  const second = await StateStore.open({ stateDir: dir, logger, now: () => NOW });
  assert.equal(second.setupToken, rotated, 'restart must reuse the existing token');
  await second.clearSetupToken();
  assert.equal(second.setupToken, '');
  await assert.rejects(fs.stat(path.join(dir, 'setup.token')), { code: 'ENOENT' });
  // Clear while still unconfigured regenerates on the next start.
  await second.close();
  const third = await StateStore.open({ stateDir: dir, logger, now: () => NOW });
  assert.match(third.setupToken, /^[0-9a-f]{64}$/u);
  // Simulate a crash between completing setup and clearing the file.
  await third.createUser({
    username: USERNAME,
    passwordHash: await hashPassword(PASSWORD),
    totpSecretB32: generateSecret()
  });
  await third.close();
  const configured = await StateStore.open({ stateDir: dir, logger, now: () => NOW });
  assert.equal(configured.configured, true);
  assert.equal(configured.setupToken, '');
  await assert.rejects(fs.stat(path.join(dir, 'setup.token')), { code: 'ENOENT' });
  await configured.close();
  await fs.rm(dir, { recursive: true, force: true });
});

// ------------------------------------------------------------- startup log

test('startup log prints the full setup link only while unconfigured', async () => {
  const logger = recordLogger();
  const h = await makeHarness('startup-log', { logger });
  try {
    const token = h.store.setupToken;
    assert.match(token, /^[0-9a-f]{64}$/u);
    const withToken = logger.lines.info.filter((line) => line.includes(token));
    assert.equal(withToken.length, 1, 'exactly one log line may carry the token');
    assert.match(withToken[0], /auth-gate: setup required — open /u);
    assert.match(withToken[0], new RegExp(`http://127\\.0\\.0\\.1/__admin#setup=${token}`, 'u'));
    assert.match(withToken[0], new RegExp(`也可从 ${h.store.setupTokenPath.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')} 读取`, 'u'));
  } finally {
    await h.cleanup();
  }

  const configuredLogger = recordLogger();
  const configured = await makeHarness('startup-log-configured', { logger: configuredLogger, configured: true });
  try {
    assert.equal(configuredLogger.lines.info.some((line) => line.includes('setup required')), false);
    assert.equal(configured.store.setupToken, '');
  } finally {
    await configured.cleanup();
  }
});

// --------------------------------------------------------- page + status

test('unconfigured /__admin serves the wizard with hard security headers', async () => {
  const h = await makeHarness('page');
  try {
    const page = await httpRequest(h.port, { path: '/__admin', headers: { accept: 'text/html' } });
    assert.equal(page.status, 200);
    assert.match(page.headers['content-type'], /text\/html/u);
    assert.equal(page.headers['x-frame-options'], 'DENY');
    assert.equal(page.headers['cache-control'], 'no-store');
    assert.match(page.headers['content-security-policy'], /script-src 'nonce-/u);
    assert.match(page.headers['content-security-policy'], /frame-ancestors 'none'/u);
    assert.match(page.body, /初始化 DSH 认证网关/u);
    assert.match(page.body, /id="setup-form"/u);
    assert.match(page.body, /id="setup-confirm-form"/u);
    assert.match(page.body, /id="setup-totp"/u);
    assert.match(page.body, /location\.hash/u);
    assert.match(page.body, /\/__admin\/api\/setup\/begin/u);
    assert.match(page.body, /\/__admin\/api\/setup\/confirm/u);
    // The server does not know the token, so it cannot (and must not) echo it.
    assert.equal(page.body.includes(h.store.setupToken), false);
    assert.equal(page.body.includes(PASSWORD), false);

    const status = await httpRequest(h.port, { path: statusPath() });
    assert.equal(status.status, 200);
    const payload = parseJson(status);
    assert.deepEqual(payload, { configured: false, hasToken: true, setupPath: '/__admin' });
    assert.equal(status.body.includes(h.store.setupToken), false);

    // Every other admin API keeps its original auth behaviour.
    const state = await httpRequest(h.port, { path: '/__admin/api/state' });
    assert.equal(state.status, 403);
    assert.equal(parseJson(state).error, 'forbidden');
  } finally {
    await h.cleanup();
  }
});

test('legacy adminKey bootstrap also retires the setup token', async () => {
  const h = await makeHarness('bootstrap-clears-token');
  try {
    assert.match(h.store.setupToken, /^[0-9a-f]{64}$/u);
    const response = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/bootstrap',
      headers: { 'x-auth-gate-admin-key': h.store.adminKey },
      body: { username: USERNAME, password: PASSWORD }
    });
    assert.equal(response.status, 200);
    assert.equal(h.store.configured, true);
    assert.equal(h.store.setupToken, '');
    await assert.rejects(fs.stat(h.store.setupTokenPath), { code: 'ENOENT' });
  } finally {
    await h.cleanup();
  }
});

// -------------------------------------------------------------- begin

test('setup begin validates token, username, password and origin; does not create the user', async () => {
  const h = await makeHarness('begin');
  try {
    const wrong = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/begin',
      body: beginBody('0'.repeat(64))
    });
    assert.equal(wrong.status, 403);
    assert.equal(parseJson(wrong).error, 'setup_token_invalid');

    const badUsername = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/begin',
      body: beginBody(h.store.setupToken, { username: '<bad user>' })
    });
    assert.equal(badUsername.status, 400);
    assert.equal(parseJson(badUsername).error, 'invalid_username');

    const weak = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/begin',
      body: beginBody(h.store.setupToken, { password: 'short' })
    });
    assert.equal(weak.status, 400);
    assert.equal(parseJson(weak).error, 'weak_password');

    const badOrigin = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/begin',
      headers: { origin: 'https://evil.example' },
      body: beginBody(h.store.setupToken)
    });
    assert.equal(badOrigin.status, 403);
    assert.equal(parseJson(badOrigin).error, 'forbidden_origin');

    // A same-authority Origin is accepted (missing Origin is also accepted so
    // the documented curl fallback works).
    const sameOrigin = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/begin',
      headers: { origin: `http://127.0.0.1:${h.port}` },
      body: beginBody(h.store.setupToken)
    });
    assert.equal(sameOrigin.status, 200);

    const ok = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/begin',
      body: beginBody(h.store.setupToken)
    });
    assert.equal(ok.status, 200);
    const payload = parseJson(ok);
    assert.equal(payload.ok, true);
    assert.match(payload.secretB32, /^[A-Z2-7]{16,128}$/u);
    assert.match(payload.otpauthUri, /^otpauth:\/\/totp\/DSH:setup-admin\?/u);
    assert.match(payload.qrSvg, /^<svg/u);
    // Nothing is persisted before confirm: a refresh cannot half-configure.
    assert.equal(h.store.configured, false);
    const stateFile = path.join(h.dir, 'state.json');
    let state = null;
    try {
      state = JSON.parse(await fs.readFile(stateFile, 'utf8'));
    } catch (error) {
      assert.equal(error.code, 'ENOENT');
    }
    if (state !== null) assert.equal(state.user, null);
    // Audit records the coarse event only.
    const audit = JSON.stringify(h.store.auditLog);
    assert.match(audit, /setup_begin/u);
    assert.equal(audit.includes(payload.secretB32), false);
    assert.equal(audit.includes(h.store.setupToken), false);
  } finally {
    await h.cleanup();
  }
});

test('setup begin is rate limited per IP (10 requests / 5 minutes)', async () => {
  const h = await makeHarness('begin-limit');
  try {
    for (let attempt = 1; attempt <= 10; attempt += 1) {
      const response = await httpRequest(h.port, {
        method: 'POST',
        path: '/__admin/api/setup/begin',
        body: beginBody('0'.repeat(64))
      });
      assert.equal(response.status, 403, `attempt ${attempt}`);
    }
    const limited = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/begin',
      body: beginBody('0'.repeat(64))
    });
    assert.equal(limited.status, 429);
    assert.equal(parseJson(limited).error, 'rate_limited');
    assert.ok(Number(limited.headers['retry-after']) > 0);
  } finally {
    await h.cleanup();
  }
});

// ------------------------------------------------------------ confirm

test('setup confirm creates the admin + TOTP + paired browser atomically and closes setup', async () => {
  const h = await makeHarness('confirm');
  try {
    const token = h.store.setupToken;
    const begin = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/begin',
      body: beginBody(token)
    });
    assert.equal(begin.status, 200);
    const draft = parseJson(begin);
    assert.equal(h.store.configured, false);

    const wrong = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/confirm',
      body: { token, totp: generateTotp(draft.secretB32, { now: NOW }) === '000000' ? '000001' : '000000' }
    });
    assert.equal(wrong.status, 403);
    assert.equal(parseJson(wrong).error, 'totp_invalid');
    assert.equal(h.store.configured, false);

    const code = generateTotp(draft.secretB32, { now: NOW });
    const confirmed = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/confirm',
      body: { token, totp: code }
    });
    assert.equal(confirmed.status, 200);
    assert.deepEqual(parseJson(confirmed), { ok: true });
    const deviceToken = cookieValue(confirmed, 'dsh_gate_device');
    assert.match(deviceToken, /^dt_[A-Za-z0-9_-]+$/u);
    const setCookie = confirmed.headers['set-cookie'].find((line) => line.startsWith('dsh_gate_device='));
    assert.match(setCookie, /HttpOnly/iu);
    assert.match(setCookie, /SameSite=Lax/iu);
    assert.match(setCookie, /Max-Age=7776000/u);
    assert.match(setCookie, /Path=\//u);

    assert.equal(h.store.configured, true);
    assert.equal(h.store.user.username, USERNAME);
    assert.equal(await verifyPassword(PASSWORD, h.store.user.passwordHash), true);
    assert.equal(h.store.user.totpConfirmedAt, NOW);
    assert.equal(h.store.user.totpSecretB32, draft.secretB32);
    assert.equal(h.store.devices.length, 1);
    assert.equal(h.store.devices[0].name, '初始化浏览器');
    assert.equal(h.store.devices[0].platform, 'web');
    assert.equal(h.store.devices[0].origin, 'http://127.0.0.1');
    assert.equal(h.store.setupToken, '');
    await assert.rejects(fs.stat(h.store.setupTokenPath), { code: 'ENOENT' });

    const status = await httpRequest(h.port, { path: statusPath() });
    assert.equal(status.status, 200);
    assert.deepEqual(parseJson(status), { configured: true, hasToken: false, setupPath: '/__admin' });

    // The token is consumed: writes are 409 even with the old/correct token.
    const beginAgain = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/begin',
      body: beginBody(token)
    });
    assert.equal(beginAgain.status, 409);
    assert.equal(parseJson(beginAgain).error, 'already_configured');
    const confirmAgain = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/confirm',
      body: { token, totp: code }
    });
    assert.equal(confirmAgain.status, 409);
    assert.equal(parseJson(confirmAgain).error, 'already_configured');
    const rotateAgain = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/token',
      body: {}
    });
    assert.equal(rotateAgain.status, 409);

    // The device cookie + password are enough to log in.
    const csrfResponse = await httpRequest(h.port, { path: '/__auth/csrf' });
    const csrf = cookieValue(csrfResponse, 'dsh_gate_csrf');
    const login = await httpRequest(h.port, {
      method: 'POST',
      path: '/__auth/login',
      headers: {
        cookie: cookieHeader(`dsh_gate_device=${deviceToken}`, `dsh_gate_csrf=${csrf}`),
        'x-auth-gate-csrf': csrf
      },
      body: { username: USERNAME, password: PASSWORD }
    });
    assert.equal(login.status, 200);
    const session = cookieValue(login, 'dsh_gate_session');
    assert.ok(session);

    // Logged-in /__admin is the normal console; anonymous HTML still 302s.
    const admin = await httpRequest(h.port, {
      path: '/__admin',
      headers: { accept: 'text/html', cookie: `dsh_gate_session=${session}` }
    });
    assert.equal(admin.status, 200);
    assert.match(admin.body, /DSH 认证管理/u);
    const anonymous = await httpRequest(h.port, { path: '/__admin', headers: { accept: 'text/html' } });
    assert.equal(anonymous.status, 302);
    assert.equal(anonymous.headers.location, '/__auth/login?next=/__admin');

    const audit = JSON.stringify(h.store.auditLog);
    assert.match(audit, /setup_begin/u);
    assert.match(audit, /setup_confirm/u);
    assert.equal(audit.includes(token), false);
    assert.equal(audit.includes(draft.secretB32), false);
    assert.equal(audit.includes(PASSWORD), false);
  } finally {
    await h.cleanup();
  }
});

test('setup confirm rejects a valid token before begin (no pending draft)', async () => {
  const h = await makeHarness('confirm-no-draft');
  try {
    const response = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/confirm',
      body: { token: h.store.setupToken, totp: '000000' }
    });
    assert.equal(response.status, 403);
    assert.equal(parseJson(response).error, 'setup_token_invalid');
    assert.equal(h.store.configured, false);
  } finally {
    await h.cleanup();
  }
});

// ------------------------------------------------------- token rotation

test('setup token rotation is available on the adminKey channel', async () => {
  const h = await makeHarness('rotate-key');
  try {
    // Loopback auto-admin is disabled on a loopback listener (P0-1), so the
    // trusted recovery channel for token rotation is the adminKey header.
    const denied = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/token',
      headers: { host: `127.0.0.1:${h.port}` },
      body: {}
    });
    assert.equal(denied.status, 403);
    assert.equal(parseJson(denied).error, 'forbidden');
    const response = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/token',
      headers: { 'x-auth-gate-admin-key': h.store.adminKey },
      body: {}
    });
    assert.equal(response.status, 200);
    const payload = parseJson(response);
    const token = payload.setupUrl.split('#setup=')[1];
    assert.match(token, /^[0-9a-f]{64}$/u);
    assert.equal(h.store.setupToken, token);
    assert.equal((await fs.readFile(h.store.setupTokenPath, 'utf8')).trim(), token);
  } finally {
    await h.cleanup();
  }
});

test('setup token rotation requires the trusted channel and invalidates pending drafts', async () => {
  const h = await makeHarness('rotate');
  try {
    const denied = await httpRequest(h.port, { method: 'POST', path: '/__admin/api/setup/token', body: {} });
    assert.equal(denied.status, 403);
    assert.equal(parseJson(denied).error, 'forbidden');

    const oldToken = h.store.setupToken;
    const begin = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/begin',
      body: beginBody(oldToken)
    });
    assert.equal(begin.status, 200);

    const rotated = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/token',
      headers: { 'x-auth-gate-admin-key': h.store.adminKey },
      body: {}
    });
    assert.equal(rotated.status, 200);
    const payload = parseJson(rotated);
    const newToken = payload.setupUrl.split('#setup=')[1];
    assert.match(newToken, /^[0-9a-f]{64}$/u);
    assert.notEqual(newToken, oldToken);
    assert.equal(h.store.setupToken, newToken);
    assert.equal((await fs.readFile(h.store.setupTokenPath, 'utf8')).trim(), newToken);

    // The draft was bound to the old token: confirm must not be possible.
    const oldDraft = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/confirm',
      body: { token: newToken, totp: '000000' }
    });
    assert.equal(oldDraft.status, 403);
    assert.equal(parseJson(oldDraft).error, 'setup_token_invalid');

    const oldBegin = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/begin',
      body: beginBody(oldToken)
    });
    assert.equal(oldBegin.status, 403);
    assert.equal(parseJson(oldBegin).error, 'setup_token_invalid');

    const newBegin = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/setup/begin',
      body: beginBody(newToken)
    });
    assert.equal(newBegin.status, 200);
    const audit = JSON.stringify(h.store.auditLog);
    assert.match(audit, /setup_token_rotated/u);
    assert.equal(audit.includes(oldToken), false);
    assert.equal(audit.includes(newToken), false);
  } finally {
    await h.cleanup();
  }
});
