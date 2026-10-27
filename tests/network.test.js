import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as http from 'node:http';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import test from 'node:test';

import { resolveConfig, resolveConfigWithNetworkFallback } from '../lib/config.js';
import { DshSessionProvider } from '../lib/dsh-session.js';
import { createGateway } from '../lib/gateway.js';
import {
  NetworkValidationError,
  networkFilePath,
  readNetworkOverride,
  validateListenHost,
  validateListenPort,
  validateNetworkSettings,
  validatePublicUrl,
  writeNetworkOverride
} from '../lib/network.js';
import { adminPage } from '../lib/pages.js';
import { hashPassword } from '../lib/password.js';
import { StateStore } from '../lib/store.js';
import { generateSecret, generateTotp } from '../lib/totp.js';

const silent = { info() {}, warn() {}, error() {} };
const logger = process.env.NETWORK_TEST_DEBUG === '1' ? { info: console.log, warn: console.warn, error: console.error } : silent;
const ROOT = path.join(process.cwd(), '.test-tmp', 'network-tests');
const NOW = 1_800_000_000_000;
const PASSWORD = 'Network-Test-Password-2026!';
/**
 * These tests exercise the real network settings API. A loopback listener is
 * deliberately rejected by `network.js`, and the API refuses to persist a
 * loopback listenHost, so the harness binds this host's non-loopback LAN
 * address (the same requirement as the e2e script).
 */
const LAN = (() => {
  for (const entries of Object.values(os.networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === 'IPv4' && entry.internal === false && !entry.address.startsWith('127.')) return entry.address;
    }
  }
  return null;
})();
if (LAN === null) throw new Error('network tests require a non-loopback IPv4 interface (set up a LAN address)');

let counter = 0;
async function tempDir() {
  counter += 1;
  const dir = path.join(ROOT, `${process.pid}-${counter}`);
  await fs.rm(dir, { recursive: true, force: true });
  await fs.mkdir(dir, { recursive: true });
  return dir;
}

function httpRequest(port, { method = 'GET', path: reqPath = '/', headers = {}, body, host, connectHost = LAN } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    const req = http.request(
      {
        host: connectHost,
        port,
        path: reqPath,
        method,
        headers: {
          host: host ?? 'gateway.invalid',
          accept: 'application/json',
          connection: 'close',
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

async function getCsrf(port, cookie) {
  const response = await httpRequest(port, { path: '/__auth/csrf', headers: cookie ? { cookie } : {} });
  assert.equal(response.status, 200);
  const csrf = cookieValue(response, 'dsh_gate_csrf');
  assert.ok(csrf);
  return csrf;
}

/** A currently free port on the harness interface (bound then immediately released). */
async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, LAN, resolve);
  });
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function makeHarness(label) {
  const dir = path.join(ROOT, `${process.pid}-${counter}-${label}`);
  await fs.mkdir(dir, { recursive: true });
  const initialPort = await freePort();
  const store = await StateStore.open({ stateDir: dir, logger, now: () => NOW });
  const secret = generateSecret();
  await store.createUser({ username: 'admin', passwordHash: await hashPassword(PASSWORD), totpSecretB32: secret });
  const ticket = await store.issueTicket({ ttlMs: 60_000 });
  const device = await store.redeemTicket(ticket.ticket, {
    maxDevices: 8,
    deviceTtlMs: 90 * 86_400_000,
    name: 'Android 网络测试机',
    platform: 'android',
    origin: `http://${LAN}`
  });
  assert.equal(device.status, 'ok');
  const session = await store.createSession({ deviceId: device.device.id, ttlMs: 8 * 3_600_000 });
  const gateway = createGateway({
    config: {
      listenHost: LAN,
      listenPort: initialPort,
      publicUrl: `http://${LAN}`,
      upstream: 'http://127.0.0.1:9',
      upstreamInsecureTls: false,
      sessionTtlHours: 8,
      deviceTtlDays: 90,
      maxDevices: 8,
      pairTicketTtlSeconds: 120,
      loginLock: { maxFailures: 5, windowMinutes: 15, lockMinutes: 15 },
      networkSource: 'config'
    },
    store,
    dshSession: new DshSessionProvider({ tokenUrl: 'http://127.0.0.1:9/?token=unused', logger: silent }),
    tls: null,
    logger,
    now: () => NOW
  });
  await gateway.listen();
  const port = gateway.server.address().port;
  assert.equal(port, initialPort);
  const cleanup = async () => {
    await gateway.close();
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  };
  return {
    store,
    dir,
    secret,
    deviceToken: device.token,
    deviceId: device.device.id,
    sessionToken: session.token,
    gateway,
    port,
    initialPort,
    cleanup
  };
}

const sessionCookie = (h) => `dsh_gate_session=${h.sessionToken}`;
const totpNow = (h) => generateTotp(h.secret, { now: NOW });

// ---------------------------------------------------------------- validation

test('listenHost accepts LAN literals, refuses every wildcard spelling and loopback', () => {
  assert.equal(validateListenHost(' 172.16.180.14 '), '172.16.180.14');
  assert.equal(validateListenHost('2001:db8::10'), '2001:db8::10');
  for (const host of ['0.0.0.0', '::', '::0', '0::0', '00::', '::ffff:0.0.0.0', '0:0:0:0:0:0:0:0', '[::]', '*', '', 'localhost', 'example.com', '[::1]']) {
    assert.throws(() => validateListenHost(host), NetworkValidationError, host);
  }
  assert.throws(
    () => validateListenHost('0.0.0.0'),
    (error) => error.code === 'invalid_listen_host' && error.reason === 'wildcard'
  );
  assert.throws(
    () => validateListenHost('::0'),
    (error) => error.code === 'invalid_listen_host' && error.reason === 'wildcard',
    'IPv6 wildcard variants must be normalized, not accepted verbatim'
  );
  for (const host of ['127.0.0.1', '127.42.0.9', '::1', '0:0:0:0:0:0:0:1', '::ffff:127.0.0.1']) {
    assert.throws(
      () => validateListenHost(host),
      (error) => error.code === 'listen_host_loopback_not_allowed' && error.reason === 'loopback',
      host
    );
  }
});

test('listenPort accepts 1..65535 and refuses the upstream port', () => {
  assert.equal(validateListenPort(1), 1);
  assert.equal(validateListenPort(65535), 65535);
  assert.equal(validateListenPort('3443'), 3443);
  for (const port of [0, 65536, 3.5, -1, 'abc', '', null, undefined]) {
    assert.throws(() => validateListenPort(port), NetworkValidationError, String(port));
  }
  assert.throws(
    () => validateListenPort(3080, { upstreamPort: 3080 }),
    (error) => error.code === 'invalid_listen_port' && error.reason === 'upstream_port'
  );
  assert.equal(validateListenPort(3443, { upstreamPort: 3080 }), 3443);
});

test('publicUrl accepts pure origins and enforces the TLS protocol rule', () => {
  assert.equal(validatePublicUrl('https://relay.example:8443'), 'https://relay.example:8443');
  assert.equal(validatePublicUrl('https://relay.example/'), 'https://relay.example');
  assert.equal(validatePublicUrl('http://203.0.113.10:23443', { tlsConfigured: false }), 'http://203.0.113.10:23443');
  assert.equal(validatePublicUrl('https://[2001:db8::1]:8443', { tlsConfigured: true }), 'https://[2001:db8::1]:8443');
  for (const value of [
    'https://relay.example/path',
    'https://relay.example?x=1',
    'https://relay.example#frag',
    'https://user:pass@relay.example',
    'ftp://relay.example',
    'relay.example:443',
    '',
    'https://relay.example:99999'
  ]) {
    assert.throws(() => validatePublicUrl(value), NetworkValidationError, value);
  }
  assert.throws(
    () => validatePublicUrl('http://relay.example', { tlsConfigured: true }),
    (error) => error.code === 'invalid_public_url' && error.reason === 'tls_requires_https'
  );
  assert.throws(
    () => validatePublicUrl('https://relay.example', { tlsConfigured: false }),
    (error) => error.code === 'invalid_public_url' && error.reason === 'plain_requires_http'
  );
});

test('validateNetworkSettings only validates provided fields', () => {
  assert.deepEqual(validateNetworkSettings({}), {});
  assert.deepEqual(validateNetworkSettings({ listenPort: 3555 }, { upstreamPort: 3080 }), { listenPort: 3555 });
  assert.throws(() => validateNetworkSettings({ publicUrl: 'https://x.example:1' }, { tlsConfigured: false }), NetworkValidationError);
});

// -------------------------------------------------------------- persistence

test('network.json is atomic 0600 and read back with only known fields', async () => {
  const dir = await tempDir();
  const written = await writeNetworkOverride(
    dir,
    { listenHost: '192.0.2.10', listenPort: 3555, publicUrl: 'http://relay.example:3555' },
    { now: () => NOW }
  );
  assert.equal(written.updatedAt, NOW);
  const file = networkFilePath(dir);
  const stat = await fs.stat(file);
  assert.equal(stat.mode & 0o777, 0o600);
  assert.equal((await fs.readdir(dir)).filter((name) => name.includes('.tmp-')).length, 0);
  const parsed = JSON.parse(await fs.readFile(file, 'utf8'));
  assert.deepEqual(parsed, { listenHost: '192.0.2.10', listenPort: 3555, publicUrl: 'http://relay.example:3555', updatedAt: NOW });
  const loaded = await readNetworkOverride(dir, { tlsConfigured: false, upstreamPort: 3080 });
  assert.deepEqual(loaded, parsed);
  await fs.rm(dir, { recursive: true, force: true });
});

test('missing network.json means config; invalid content is a startup error', async () => {
  const dir = await tempDir();
  assert.equal(await readNetworkOverride(dir, {}), null);

  await fs.writeFile(networkFilePath(dir), '{"listenHost":"0.0.0.0","listenPort":3443,"publicUrl":"http://192.0.2.10:3443"}\n');
  await assert.rejects(readNetworkOverride(dir, {}), /network override.*wildcard/u);

  await fs.writeFile(networkFilePath(dir), '{"listenHost":"127.0.0.1","listenPort":3443,"publicUrl":"http://192.0.2.10:3443"}\n');
  await assert.rejects(readNetworkOverride(dir, {}), /network override.*loopback/u);

  await fs.writeFile(networkFilePath(dir), '{"listenPort":3080}\n');
  await assert.rejects(readNetworkOverride(dir, { upstreamPort: 3080 }), /network override/u);

  await fs.writeFile(networkFilePath(dir), '{not json');
  await assert.rejects(readNetworkOverride(dir, {}), /not valid JSON/u);

  await fs.writeFile(networkFilePath(dir), '{}\n');
  await assert.rejects(readNetworkOverride(dir, {}), /no listenHost\/listenPort\/publicUrl/u);
  await fs.rm(dir, { recursive: true, force: true });
});

test('resolveConfig gives network.json priority over the bundle config', async () => {
  const dir = await tempDir();
  await writeNetworkOverride(dir, {
    listenHost: '192.0.2.10',
    listenPort: 3555,
    publicUrl: 'http://relay.example:3555'
  });
  const resolved = await resolveConfig(
    {
      listenHost: '192.0.2.11',
      listenPort: 3443,
      upstream: 'http://127.0.0.1:3999',
      publicUrl: 'http://192.0.2.11:3443',
      stateDir: dir
    },
    { env: {} }
  );
  assert.equal(resolved.listenHost, '192.0.2.10');
  assert.equal(resolved.listenPort, 3555);
  assert.equal(resolved.publicUrl, 'http://relay.example:3555');
  assert.equal(resolved.networkSource, 'override');

  const fresh = await tempDir();
  const byConfig = await resolveConfig(
    { listenHost: '192.0.2.11', listenPort: 3456, upstream: 'http://127.0.0.1:3999', stateDir: fresh },
    { env: {} }
  );
  assert.equal(byConfig.networkSource, 'config');
  assert.equal(byConfig.publicUrl, 'http://192.0.2.11:3456');
  await fs.rm(dir, { recursive: true, force: true });
  await fs.rm(fresh, { recursive: true, force: true });
});

test('server-rendered admin page renders the network section with escaped values', () => {
  const html = adminPage({
    nonce: 'n',
    csrf: 'c',
    state: { configured: true, user: { username: 'admin', totpConfigured: true }, devices: [] },
    network: {
      listenHost: '127.0.0.1',
      listenPort: 3443,
      publicUrl: 'https://relay.example:8443"><script>alert(1)</script>',
      tlsConfigured: true,
      source: 'override'
    }
  });
  assert.match(html, /id="section-network"/u);
  assert.match(html, /id="network-listen-host"/u);
  assert.match(html, /id="network-listen-port"/u);
  assert.match(html, /id="network-public-url"/u);
  assert.match(html, /id="network-totp"/u);
  assert.match(html, /运行时覆盖（network\.json）/u);
  assert.equal(html.includes('<script>alert(1)</script>'), false);
});

// -------------------------------------------------------------- admin API + rebind

test('network API: validation, TOTP, publicUrl QR origin, audit and origin_changed', async () => {
  const h = await makeHarness('api');
  try {
    // adminKey channel: read-only GET is allowed without TOTP.
    const byKey = await httpRequest(h.port, {
      path: '/__admin/api/network',
      headers: { 'x-auth-gate-admin-key': h.store.adminKey }
    });
    assert.equal(byKey.status, 200);
    const byKeyBody = JSON.parse(byKey.body);
    assert.deepEqual(byKeyBody.network, {
      listenHost: LAN,
      listenPort: h.initialPort,
      publicUrl: `http://${LAN}`,
      tlsConfigured: false,
      source: 'config',
      publicFingerprint: '',
      effectiveFingerprint: '',
      fingerprintHint: '二维码使用网关自身 TLS 证书指纹；若 TLS 在 frp/反向代理处终止，请设置「对外证书指纹」。'
    });
    assert.match(byKeyBody.rules.listenPort, /上游端口 9/u);
    assert.match(byKeyBody.rules.publicFingerprint, /auto/u);

    // state carries the same network view for the UI.
    const state = await httpRequest(h.port, { path: '/__admin/api/state', headers: { cookie: sessionCookie(h) } });
    assert.equal(state.status, 200);
    assert.equal(JSON.parse(state.body).network.publicUrl, `http://${LAN}`);

    // Read-only network view needs no TOTP, even on the session channel.
    const readBySession = await httpRequest(h.port, {
      path: '/__admin/api/network',
      headers: { cookie: sessionCookie(h) }
    });
    assert.equal(readBySession.status, 200);
    assert.equal(JSON.parse(readBySession.body).network.listenPort, h.initialPort);

    // Session channel: TOTP required for any write.
    const csrf = await getCsrf(h.port, sessionCookie(h));
    const headers = {
      cookie: `${sessionCookie(h)}; dsh_gate_csrf=${csrf}`,
      'x-auth-gate-csrf': csrf
    };
    const noTotp = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/network',
      headers,
      body: { publicUrl: 'http://relay.example:8443' }
    });
    assert.equal(noTotp.status, 403);
    assert.equal(JSON.parse(noTotp.body).error, 'totp_required');

    const wrongTotp = totpNow(h) === '000000' ? '000001' : '000000';
    const wrong = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/network',
      headers,
      body: { publicUrl: 'http://relay.example:8443', totp: wrongTotp }
    });
    assert.equal(wrong.status, 403);
    assert.equal(JSON.parse(wrong.body).error, 'totp_invalid');

    const missingCsrf = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/network',
      headers: { cookie: sessionCookie(h) },
      body: { publicUrl: 'http://relay.example:8443', totp: totpNow(h) }
    });
    assert.equal(missingCsrf.status, 403);
    assert.equal(JSON.parse(missingCsrf.body).error, 'csrf_invalid');

    // Invalid values are 400 and must not create network.json.
    const badHost = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/network',
      headers,
      body: { listenHost: '0.0.0.0', totp: totpNow(h) }
    });
    assert.equal(badHost.status, 400);
    assert.equal(JSON.parse(badHost.body).error, 'invalid_listen_host');
    assert.equal(JSON.parse(badHost.body).field, 'listenHost');
    const badPort = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/network',
      headers,
      body: { listenPort: 9, totp: totpNow(h) }
    });
    assert.equal(badPort.status, 400);
    assert.equal(JSON.parse(badPort.body).error, 'invalid_listen_port');
    assert.equal(JSON.parse(badPort.body).reason, 'upstream_port');
    const badUrl = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/network',
      headers,
      body: { publicUrl: 'http://relay.example:8443/path', totp: totpNow(h) }
    });
    assert.equal(badUrl.status, 400);
    assert.equal(JSON.parse(badUrl.body).error, 'invalid_public_url');
    await assert.rejects(fs.stat(networkFilePath(h.dir)));

    // Correct TOTP: publicUrl changes immediately (no listener change).
    const totp = totpNow(h);
    const changed = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/network',
      headers,
      body: { publicUrl: 'http://relay.example:8443', totp }
    });
    assert.equal(changed.status, 200);
    const changedBody = JSON.parse(changed.body);
    assert.equal(changedBody.ok, true);
    assert.equal(changedBody.rebound, false);
    assert.equal(changedBody.network.publicUrl, 'http://relay.example:8443');
    assert.equal(changedBody.network.source, 'override');
    assert.equal(changed.body.includes(totp), false, 'the TOTP code must never be echoed');
    const persisted = JSON.parse(await fs.readFile(networkFilePath(h.dir), 'utf8'));
    assert.equal(persisted.publicUrl, 'http://relay.example:8443');
    assert.equal((await fs.stat(networkFilePath(h.dir))).mode & 0o777, 0o600);
    assert.ok(h.store.auditTail(20).some((entry) => entry.type === 'admin_change' && String(entry.detail).includes('network_update')));
    assert.equal(h.store.auditTail(20).some((entry) => String(entry.detail).includes(totp)), false);

    // QR host follows publicUrl immediately.
    const qr = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/qr',
      headers,
      body: { platform: 'android', totp: totpNow(h) }
    });
    assert.equal(qr.status, 200);
    assert.match(JSON.parse(qr.body).url, /^http:\/\/relay\.example:8443\/__auth\/pair#v=1&t=/u);

    // Devices bound to the old origin are told to re-pair instead of silently
    // working from the retired authority.
    const renew = await httpRequest(h.port, {
      method: 'POST',
      path: '/__auth/renew',
      body: { deviceToken: h.deviceToken }
    });
    assert.equal(renew.status, 401);
    assert.equal(JSON.parse(renew.body).error, 'origin_changed');

    // adminKey channel is exempt from TOTP and CSRF; switch back.
    const byKeyChanged = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/network',
      headers: { 'x-auth-gate-admin-key': h.store.adminKey },
      body: { publicUrl: `http://${LAN}` }
    });
    assert.equal(byKeyChanged.status, 200);
    assert.equal(JSON.parse(byKeyChanged.body).network.publicUrl, `http://${LAN}`);
    const renewAgain = await httpRequest(h.port, {
      method: 'POST',
      path: '/__auth/renew',
      body: { deviceToken: h.deviceToken }
    });
    assert.equal(renewAgain.status, 200, 'switching the origin back makes the old device valid again');

    // no changes -> explicit 400 instead of a pointless write.
    const noChanges = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/network',
      headers: { 'x-auth-gate-admin-key': h.store.adminKey },
      body: {}
    });
    assert.equal(noChanges.status, 400);
    assert.equal(JSON.parse(noChanges.body).error, 'no_changes');
  } finally {
    await h.cleanup();
  }
});

test('listenPort rebind: occupied port rolls back, a free port switches listeners immediately', async () => {
  const h = await makeHarness('rebind');
  const blocker = net.createServer();
  try {
    // Occupy a port so the bind fails; the old listener must stay reachable and
    // network.json must not be written.
    await new Promise((resolve, reject) => {
      blocker.once('error', reject);
      blocker.listen(0, LAN, resolve);
    });
    const occupiedPort = blocker.address().port;
    const failed = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/network',
      headers: { 'x-auth-gate-admin-key': h.store.adminKey },
      body: { listenPort: occupiedPort }
    });
    assert.equal(failed.status, 400);
    const failedBody = JSON.parse(failed.body);
    assert.equal(failedBody.error, 'rebind_failed');
    assert.equal(failedBody.reason, 'address_in_use');
    assert.equal(h.gateway.network.listenPort, h.initialPort, 'failed rebind must not change the effective settings');
    assert.equal(h.gateway.network.source, 'config');
    await assert.rejects(fs.stat(networkFilePath(h.dir)));
    const oldStillWorks = await httpRequest(h.port, { path: '/__auth/csrf' });
    assert.equal(oldStillWorks.status, 200, 'rollback must keep the old listener serving');

    // Free port: bind succeeds, the old listening socket closes and the new
    // one answers. Response is delivered before the old socket is retired.
    const newPort = await freePort();
    assert.notEqual(newPort, h.port);
    const rebound = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/network',
      headers: { 'x-auth-gate-admin-key': h.store.adminKey },
      body: { listenPort: newPort }
    });
    assert.equal(rebound.status, 200);
    const reboundBody = JSON.parse(rebound.body);
    assert.equal(reboundBody.ok, true);
    assert.equal(reboundBody.rebound, true);
    assert.equal(reboundBody.network.listenPort, newPort);
    assert.equal(h.gateway.network.listenPort, newPort);

    const persisted = JSON.parse(await fs.readFile(networkFilePath(h.dir), 'utf8'));
    assert.equal(persisted.listenPort, newPort);
    assert.equal(persisted.publicUrl, `http://${LAN}`);

    // Old port refuses new connections; new port answers a full TLS/plain HTTP
    // health request without any self-request from the gateway.
    await assert.rejects(httpRequest(h.port, { path: '/__auth/login' }));
    const healthy = await httpRequest(newPort, { path: '/__auth/login' });
    assert.equal(healthy.status, 200);

    const afterNetwork = await httpRequest(newPort, { path: '/__admin/api/network', headers: { 'x-auth-gate-admin-key': h.store.adminKey } });
    assert.equal(afterNetwork.status, 200);
    assert.equal(JSON.parse(afterNetwork.body).network.source, 'override');
    assert.equal(h.store.auditTail(20).some((entry) => String(entry.detail).includes('rebound=true')), true);
  } finally {
    await new Promise((resolve) => blocker.close(resolve));
    await h.cleanup();
  }
});


test('P0-1: a loopback listener disables the automatic loopback admin channel', async () => {
  const dir = await tempDir();
  const store = await StateStore.open({ stateDir: dir, logger, now: () => NOW });
  const warnings = [];
  const capture = { info() {}, warn: (message) => warnings.push(String(message)), error() {} };
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
      loginLock: { maxFailures: 5, windowMinutes: 15, lockMinutes: 15 },
      networkSource: 'config'
    },
    store,
    dshSession: new DshSessionProvider({ tokenUrl: 'http://127.0.0.1:9/?token=unused', logger: silent }),
    tls: null,
    logger: capture,
    now: () => NOW
  });
  try {
    await gateway.listen();
    const port = gateway.server.address().port;
    const pinnedHost = `127.0.0.1:${port}`;
    // The original PoC: frp/反代 makes a public visitor look like loopback and
    // the visitor sends Host: 127.0.0.1:<port> to read the admin key.
    const leak = await httpRequest(port, {
      path: '/__admin/api/admin-key',
      host: pinnedHost,
      connectHost: '127.0.0.1'
    });
    assert.equal(leak.status, 403);
    assert.equal(JSON.parse(leak.body).error, 'forbidden');
    assert.equal(leak.body.includes(store.adminKey), false, 'the admin key must never be returned to a loopback peer');
    const state = await httpRequest(port, { path: '/__admin/api/state', host: pinnedHost, connectHost: '127.0.0.1' });
    assert.equal(state.status, 403);
    // The documented local recovery path still works.
    const byKey = await httpRequest(port, {
      path: '/__admin/api/state',
      host: pinnedHost,
      connectHost: '127.0.0.1',
      headers: { 'x-auth-gate-admin-key': store.adminKey }
    });
    assert.equal(byKey.status, 200);
    assert.equal(warnings.filter((message) => message.includes('loopback admin channel is DISABLED')).length, 1);
    // P0 via the settings API: loopback listenHost + a public publicUrl must be
    // refused before anything is bound or persisted.
    const loopbackPublic = await httpRequest(port, {
      method: 'POST',
      path: '/__admin/api/network',
      connectHost: '127.0.0.1',
      headers: { 'x-auth-gate-admin-key': store.adminKey },
      body: { listenHost: '127.0.0.1', publicUrl: 'https://relay.example:8443' }
    });
    assert.equal(loopbackPublic.status, 400);
    assert.equal(JSON.parse(loopbackPublic.body).error, 'listen_host_loopback_not_allowed');
    await assert.rejects(fs.stat(networkFilePath(dir)));
  } finally {
    await gateway.close();
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('P1-1: a wildcard spelling accepted by config is closed and refused after listen()', async () => {
  const dir = await tempDir();
  const store = await StateStore.open({ stateDir: dir, logger, now: () => NOW });
  const gateway = createGateway({
    config: {
      listenHost: '::0',
      listenPort: 0,
      publicUrl: 'http://[::]:0',
      upstream: 'http://127.0.0.1:9',
      upstreamInsecureTls: false,
      sessionTtlHours: 8,
      deviceTtlDays: 90,
      maxDevices: 8,
      pairTicketTtlSeconds: 120,
      loginLock: { maxFailures: 5, windowMinutes: 15, lockMinutes: 15 },
      networkSource: 'config'
    },
    store,
    dshSession: new DshSessionProvider({ tokenUrl: 'http://127.0.0.1:9/?token=unused', logger: silent }),
    tls: null,
    logger,
    now: () => NOW
  });
  try {
    await assert.rejects(
      gateway.listen(),
      (error) => error instanceof NetworkValidationError && error.code === 'invalid_listen_host' && error.reason === 'wildcard'
    );
    assert.equal(gateway.server.listening, false, 'the wildcard listener must be closed again (no leaked server)');
  } finally {
    await gateway.close();
    await store.close();
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('P1-2/P2-3: persistence failure after the new bind retires it and keeps the old listener', async () => {
  const h = await makeHarness('persist-fail');
  // Make the destination path un-renameable: network.json is a non-empty dir.
  await fs.mkdir(path.join(h.dir, 'network.json'));
  await fs.writeFile(path.join(h.dir, 'network.json', 'blocker'), 'x');
  const newPort = await freePort();
  try {
    const response = await httpRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/network',
      headers: { 'x-auth-gate-admin-key': h.store.adminKey },
      body: { listenPort: newPort }
    });
    assert.equal(response.status, 400);
    const body = JSON.parse(response.body);
    assert.equal(body.error, 'rebind_failed');
    assert.equal(body.reason, 'persist_failed');
    // The old listener was never closed (bind-first) and still serves.
    const oldStill = await httpRequest(h.port, { path: '/__auth/csrf' });
    assert.equal(oldStill.status, 200);
    assert.equal(h.gateway.network.listenPort, h.initialPort);
    // The new server bound to the new port must have been closed again.
    await assert.rejects(httpRequest(newPort, { path: '/__auth/csrf' }), /ECONNREFUSED/u);
    // No temp files leak next to the failed target.
    const leftovers = (await fs.readdir(h.dir)).filter((name) => name.includes('.network.json.tmp-'));
    assert.deepEqual(leftovers, []);
  } finally {
    await fs.rm(path.join(h.dir, 'network.json'), { recursive: true, force: true });
    await h.cleanup();
  }
});

test('P2-2: concurrent network updates are serialized and leave one coherent state', async () => {
  const h = await makeHarness('concurrent');
  try {
    const updates = await Promise.all([
      httpRequest(h.port, {
        method: 'POST',
        path: '/__admin/api/network',
        headers: { 'x-auth-gate-admin-key': h.store.adminKey },
        body: { publicUrl: 'http://relay-a.example:8443' }
      }),
      httpRequest(h.port, {
        method: 'POST',
        path: '/__admin/api/network',
        headers: { 'x-auth-gate-admin-key': h.store.adminKey },
        body: { publicUrl: 'http://relay-b.example:8443' }
      })
    ]);
    for (const response of updates) {
      assert.equal(response.status, 200);
      assert.equal(JSON.parse(response.body).rebound, false);
    }
    const persisted = JSON.parse(await fs.readFile(networkFilePath(h.dir), 'utf8'));
    assert.ok(['http://relay-a.example:8443', 'http://relay-b.example:8443'].includes(persisted.publicUrl));
    assert.equal(persisted.listenHost, LAN);
    assert.equal(persisted.listenPort, h.initialPort);
    assert.equal(h.gateway.network.publicUrl, persisted.publicUrl, 'in-memory and persisted state must agree');
    const after = await httpRequest(h.port, { path: '/__admin/api/network', headers: { 'x-auth-gate-admin-key': h.store.adminKey } });
    assert.equal(after.status, 200);
    assert.equal(JSON.parse(after.body).network.publicUrl, persisted.publicUrl);
  } finally {
    await h.cleanup();
  }
});

test('P2-1: a damaged network.json is logged with recovery guidance and falls back to config', async () => {
  const dir = await tempDir();
  await fs.writeFile(networkFilePath(dir), '{not json');
  const errors = [];
  const capture = { info() {}, warn() {}, error: (message) => errors.push(String(message)) };
  const fallback = await resolveConfigWithNetworkFallback(
    {
      listenHost: '192.0.2.11',
      listenPort: 3456,
      upstream: 'http://127.0.0.1:3999',
      publicUrl: 'http://192.0.2.11:3456',
      stateDir: dir
    },
    { env: {}, logger: capture }
  );
  assert.equal(fallback.listenHost, '192.0.2.11');
  assert.equal(fallback.networkSource, 'config');
  assert.ok(fallback.networkFallback !== undefined);
  assert.equal(fallback.networkFallback.file, networkFilePath(dir));
  const log = errors.join('\n');
  assert.match(log, /network override/u);
  assert.match(log, /IGNORED/u);
  assert.match(log, /rm -f/u);
  assert.match(log, /restart dsh/u);
  // The raw resolver stays strict for callers that opt into fail-fast.
  await assert.rejects(resolveConfig({ listenHost: '192.0.2.11', listenPort: 3456, stateDir: dir }, { env: {} }), /not valid JSON/u);
  await fs.rm(dir, { recursive: true, force: true });
});
