import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import * as https from 'node:https';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import test from 'node:test';

import { resolveConfig } from '../lib/config.js';
import { DshSessionProvider } from '../lib/dsh-session.js';
import { fetchPeerFingerprint, FingerprintProbeError } from '../lib/fingerprint.js';
import { createGateway } from '../lib/gateway.js';
import {
  NetworkValidationError,
  networkFilePath,
  readNetworkOverride,
  validateNetworkSettings,
  validatePublicFingerprint,
  writeNetworkOverride
} from '../lib/network.js';
import { hashPassword } from '../lib/password.js';
import { certificateFingerprint } from '../lib/qr.js';
import { StateStore } from '../lib/store.js';
import { generateSecret, generateTotp } from '../lib/totp.js';

const ROOT = path.join(process.cwd(), '.test-tmp', 'fingerprint-tests');
/**
 * The network API persists listenHost through the same strict validation as
 * config.js (loopback is refused), so this harness listens on the host's LAN
 * address exactly like tests/network.test.js.
 */
const LAN = (() => {
  for (const entries of Object.values(os.networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry.family === 'IPv4' && entry.internal === false && !entry.address.startsWith('127.')) return entry.address;
    }
  }
  return null;
})();
if (LAN === null) throw new Error('fingerprint tests require a non-loopback IPv4 interface (set up a LAN address)');
const NOW = 1_800_000_000_000;
const PASSWORD = 'Fingerprint-Test-Password-2026!';
const FIXTURES = new URL('./fixtures/', import.meta.url);
const GATEWAY_CERT = readFileSync(new URL('fp-gateway-cert.pem', FIXTURES));
const GATEWAY_KEY = readFileSync(new URL('fp-gateway-key.pem', FIXTURES));
const PEER_CERT = readFileSync(new URL('fp-peer-cert.pem', FIXTURES));
const PEER_KEY = readFileSync(new URL('fp-peer-key.pem', FIXTURES));
const SELF_FP = certificateFingerprint(GATEWAY_CERT);
const PEER_FP = certificateFingerprint(PEER_CERT);
const FIXED_FP = 'ab'.repeat(32);
const silent = { info() {}, warn() {}, error() {} };
const logger = process.env.FINGERPRINT_TEST_DEBUG === '1' ? { info: console.log, warn: console.warn, error: console.error } : silent;

let counter = 0;
async function tempDir() {
  counter += 1;
  const dir = path.join(ROOT, `${process.pid}-${counter}`);
  await fs.rm(dir, { recursive: true, force: true });
  await fs.mkdir(dir, { recursive: true });
  return dir;
}

/** HTTPS request to this test's loopback gateway (self-signed fixtures). */
function httpsRequest(port, { method = 'GET', path: reqPath = '/', headers = {}, body, host = LAN } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    const req = https.request(
      {
        host,
        port,
        path: reqPath,
        method,
        rejectUnauthorized: false,
        headers: {
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

/** Start a throwaway TLS server that serves the peer fixture certificate. */
async function startPeerTlsServer() {
  const server = https.createServer({ key: PEER_KEY, cert: PEER_CERT }, (_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('ok');
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return { server, port: server.address().port };
}

/** Extract `fp=` from a pairing URL fragment. */
function pairingFingerprint(url) {
  const parsed = new URL(url);
  return new URLSearchParams(parsed.hash.replace(/^#/u, '')).get('fp');
}

async function makeHarness(label) {
  const dir = path.join(ROOT, `${process.pid}-${counter}-${label}`);
  await fs.rm(dir, { recursive: true, force: true });
  await fs.mkdir(dir, { recursive: true });
  const initialPort = await freePort();
  const publicUrl = `https://${LAN}:${initialPort}`;
  const store = await StateStore.open({ stateDir: dir, logger, now: () => NOW });
  const secret = generateSecret();
  await store.createUser({ username: 'admin', passwordHash: await hashPassword(PASSWORD), totpSecretB32: secret });
  const ticket = await store.issueTicket({ ttlMs: 60_000 });
  const device = await store.redeemTicket(ticket.ticket, {
    maxDevices: 8,
    deviceTtlMs: 90 * 86_400_000,
    name: 'Android 指纹测试机',
    platform: 'android',
    origin: publicUrl
  });
  assert.equal(device.status, 'ok');
  const session = await store.createSession({ deviceId: device.device.id, ttlMs: 8 * 3_600_000 });
  const gateway = createGateway({
    config: {
      listenHost: LAN,
      listenPort: initialPort,
      publicUrl,
      publicFingerprint: '',
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
    tls: { cert: GATEWAY_CERT, key: GATEWAY_KEY },
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
    sessionToken: session.token,
    gateway,
    port,
    publicUrl,
    keyHeaders: { 'x-auth-gate-admin-key': store.adminKey },
    cleanup
  };
}

const qrBody = { platform: 'android' };

// ---------------------------------------------------------------- validation

test('validatePublicFingerprint: empty, lower-casing, auto and every invalid shape', () => {
  assert.equal(validatePublicFingerprint(''), '');
  assert.equal(validatePublicFingerprint('   '), '');
  assert.equal(validatePublicFingerprint(FIXED_FP), FIXED_FP);
  assert.equal(validatePublicFingerprint(FIXED_FP.toUpperCase()), FIXED_FP, 'upper-case hex is normalized');
  assert.equal(validatePublicFingerprint(`  ${FIXED_FP.toUpperCase()}  `), FIXED_FP);
  assert.equal(validatePublicFingerprint('auto', { allowAuto: true }), 'auto');
  assert.equal(validatePublicFingerprint(' AUTO ', { allowAuto: true }), 'auto');
  // 'auto' is a POST-only sentinel: persisted/bundle configuration must not contain it.
  assert.throws(
    () => validatePublicFingerprint('auto'),
    (error) => error instanceof NetworkValidationError && error.code === 'invalid_public_fingerprint' && error.reason === 'auto_not_allowed_here'
  );
  for (const value of ['abc', 'a'.repeat(63), 'a'.repeat(65), 'g'.repeat(64), `${FIXED_FP}0`, `sha256:${FIXED_FP}`, 123, null, undefined, {}]) {
    assert.throws(
      () => validatePublicFingerprint(value),
      (error) => error instanceof NetworkValidationError && error.field === 'publicFingerprint' && error.code === 'invalid_public_fingerprint',
      String(value)
    );
  }
  assert.deepEqual(validateNetworkSettings({ publicFingerprint: FIXED_FP }), { publicFingerprint: FIXED_FP });
  assert.deepEqual(validateNetworkSettings({ publicFingerprint: 'auto' }, { allowAutoFingerprint: true }), { publicFingerprint: 'auto' });
  assert.throws(() => validateNetworkSettings({ publicFingerprint: 'auto' }), NetworkValidationError);
});

test('publicFingerprint persists in network.json (empty is omitted) and overrides the bundle default', async () => {
  const dir = await tempDir();
  await writeNetworkOverride(dir, { listenHost: '192.0.2.10', listenPort: 3555, publicUrl: 'http://relay.example:3555', publicFingerprint: FIXED_FP.toUpperCase() });
  const raw = JSON.parse(await fs.readFile(networkFilePath(dir), 'utf8'));
  assert.equal(raw.publicFingerprint, FIXED_FP);
  assert.equal((await readNetworkOverride(dir)).publicFingerprint, FIXED_FP);
  await writeNetworkOverride(dir, { listenHost: '192.0.2.10', listenPort: 3555, publicUrl: 'http://relay.example:3555', publicFingerprint: '' });
  assert.equal('publicFingerprint' in JSON.parse(await fs.readFile(networkFilePath(dir), 'utf8')), false);

  const bundleDir = await tempDir();
  const bundle = await resolveConfig(
    {
      listenHost: '192.0.2.10',
      listenPort: 3555,
      upstream: 'http://127.0.0.1:3999',
      publicUrl: 'http://relay.example:3555',
      publicFingerprint: FIXED_FP.toUpperCase(),
      stateDir: bundleDir
    },
    { env: {} }
  );
  assert.equal(bundle.publicFingerprint, FIXED_FP);
  assert.equal(bundle.networkSource, 'config');
  await fs.rm(bundleDir, { recursive: true, force: true });

  await writeNetworkOverride(dir, { listenHost: '192.0.2.10', listenPort: 3555, publicUrl: 'http://relay.example:3555', publicFingerprint: 'cd'.repeat(32) });
  const overridden = await resolveConfig(
    { listenHost: '192.0.2.10', listenPort: 3555, upstream: 'http://127.0.0.1:3999', publicUrl: 'http://relay.example:3555', stateDir: dir },
    { env: {} }
  );
  assert.equal(overridden.publicFingerprint, 'cd'.repeat(32), 'network.json wins over the bundle default');
  assert.equal(overridden.networkSource, 'override');

  await assert.rejects(
    resolveConfig(
      { listenHost: '192.0.2.10', listenPort: 3555, upstream: 'http://127.0.0.1:3999', publicFingerprint: 'auto', stateDir: dir },
      { env: {}, ignoreNetworkOverride: true }
    ),
    /publicFingerprint/u
  );
  await assert.rejects(
    resolveConfig(
      { listenHost: '192.0.2.10', listenPort: 3555, upstream: 'http://127.0.0.1:3999', publicFingerprint: 'not-hex', stateDir: dir },
      { env: {}, ignoreNetworkOverride: true }
    ),
    /publicFingerprint/u
  );
  await fs.rm(dir, { recursive: true, force: true });
});

// ------------------------------------------------------------------- API/QR

test('network API: fixed publicFingerprint drives the QR fp, empty falls back to the gateway certificate', async () => {
  const h = await makeHarness('fixed');
  try {
    const initial = await httpsRequest(h.port, { path: '/__admin/api/network', headers: h.keyHeaders });
    assert.equal(initial.status, 200);
    const initialNetwork = JSON.parse(initial.body).network;
    assert.equal(initialNetwork.publicFingerprint, '');
    assert.equal(initialNetwork.effectiveFingerprint, SELF_FP, 'default is the gateway own certificate');
    assert.equal(typeof initialNetwork.fingerprintHint, 'string');
    assert.match(initialNetwork.fingerprintHint, /网关自身/u);
    assert.match(JSON.parse(initial.body).rules.publicFingerprint, /auto/u);

    const setFixed = await httpsRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/network',
      headers: h.keyHeaders,
      body: { publicFingerprint: FIXED_FP.toUpperCase() }
    });
    assert.equal(setFixed.status, 200, setFixed.body);
    const setFixedNetwork = JSON.parse(setFixed.body).network;
    assert.equal(setFixedNetwork.publicFingerprint, FIXED_FP);
    assert.equal(setFixedNetwork.effectiveFingerprint, FIXED_FP);
    const persisted = JSON.parse(await fs.readFile(networkFilePath(h.dir), 'utf8'));
    assert.equal(persisted.publicFingerprint, FIXED_FP);
    assert.equal((await fs.stat(networkFilePath(h.dir))).mode & 0o777, 0o600);

    const qrFixed = await httpsRequest(h.port, { method: 'POST', path: '/__admin/api/qr', headers: h.keyHeaders, body: qrBody });
    assert.equal(qrFixed.status, 200);
    assert.equal(pairingFingerprint(JSON.parse(qrFixed.body).url), FIXED_FP);

    // Invalid values are rejected before anything is applied/persisted.
    const invalid = await httpsRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/network',
      headers: h.keyHeaders,
      body: { publicFingerprint: 'not-a-fingerprint' }
    });
    assert.equal(invalid.status, 400);
    assert.equal(JSON.parse(invalid.body).error, 'invalid_public_fingerprint');
    assert.equal(JSON.parse(invalid.body).field, 'publicFingerprint');
    assert.equal(h.gateway.network.publicFingerprint, FIXED_FP, 'a rejected update must not change the effective value');

    // Clearing the override returns to the gateway's own certificate.
    const cleared = await httpsRequest(h.port, { method: 'POST', path: '/__admin/api/network', headers: h.keyHeaders, body: { publicFingerprint: '' } });
    assert.equal(cleared.status, 200);
    assert.equal(JSON.parse(cleared.body).network.publicFingerprint, '');
    assert.equal(JSON.parse(cleared.body).network.effectiveFingerprint, SELF_FP);
    const persistedAfterClear = JSON.parse(await fs.readFile(networkFilePath(h.dir), 'utf8'));
    assert.equal('publicFingerprint' in persistedAfterClear, false);
    const qrSelf = await httpsRequest(h.port, { method: 'POST', path: '/__admin/api/qr', headers: h.keyHeaders, body: qrBody });
    assert.equal(pairingFingerprint(JSON.parse(qrSelf.body).url), SELF_FP);

    // Session channel still needs TOTP for this write (adminKey is exempt).
    const csrfResponse = await httpsRequest(h.port, { path: '/__auth/csrf', headers: { cookie: `dsh_gate_session=${h.sessionToken}` } });
    const csrf = cookieValue(csrfResponse, 'dsh_gate_csrf');
    assert.ok(csrf);
    const sessionHeaders = { cookie: `dsh_gate_session=${h.sessionToken}; dsh_gate_csrf=${csrf}`, 'x-auth-gate-csrf': csrf };
    const noTotp = await httpsRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/network',
      headers: sessionHeaders,
      body: { publicFingerprint: FIXED_FP }
    });
    assert.equal(noTotp.status, 403);
    assert.equal(JSON.parse(noTotp.body).error, 'totp_required');
    const withTotp = await httpsRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/network',
      headers: sessionHeaders,
      body: { publicFingerprint: FIXED_FP, totp: generateTotp(h.secret, { now: NOW }) }
    });
    assert.equal(withTotp.status, 200);
    assert.equal(JSON.parse(withTotp.body).network.publicFingerprint, FIXED_FP);

    const audit = h.store.auditTail(50);
    const update = audit.find((entry) => entry.type === 'admin_change' && String(entry.detail).includes('network_update') && String(entry.detail).includes(FIXED_FP.slice(0, 8)));
    assert.ok(update, 'audit records a short public_fp prefix');
    assert.equal(JSON.stringify(audit).includes(generateTotp(h.secret, { now: NOW })), false, 'the TOTP must never be audited');
  } finally {
    await h.cleanup();
  }
});

test('auto: probes the saved https publicUrl, persists the peer certificate fingerprint and uses it in the QR', async () => {
  const h = await makeHarness('auto');
  const peer = await startPeerTlsServer();
  try {
    const peerUrl = `https://127.0.0.1:${peer.port}`;
    // Save the public origin first (the UI's "auto" button probes the saved URL).
    const saveUrl = await httpsRequest(h.port, { method: 'POST', path: '/__admin/api/network', headers: h.keyHeaders, body: { publicUrl: peerUrl } });
    assert.equal(saveUrl.status, 200, saveUrl.body);

    const detected = await httpsRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/network',
      headers: h.keyHeaders,
      body: { publicFingerprint: 'auto' }
    });
    assert.equal(detected.status, 200);
    const network = JSON.parse(detected.body).network;
    assert.equal(network.publicFingerprint, PEER_FP, 'the probe reads the certificate served on the public origin');
    assert.equal(network.effectiveFingerprint, PEER_FP);
    assert.equal(network.publicUrl, peerUrl);
    const persisted = JSON.parse(await fs.readFile(networkFilePath(h.dir), 'utf8'));
    assert.equal(persisted.publicFingerprint, PEER_FP);
    assert.equal(persisted.publicUrl, peerUrl);

    const qr = await httpsRequest(h.port, { method: 'POST', path: '/__admin/api/qr', headers: h.keyHeaders, body: qrBody });
    const url = JSON.parse(qr.body).url;
    assert.match(url, new RegExp(`^${peerUrl.replaceAll('.', '\\.')}/__auth/pair#`, 'u'));
    assert.equal(pairingFingerprint(url), PEER_FP);
    assert.ok(
      h.store.auditTail(50).some((entry) => String(entry.detail).includes(`public_fp=${PEER_FP.slice(0, 8)}`)),
      'audit records the resolved fingerprint prefix'
    );
  } finally {
    await new Promise((resolve) => peer.server.close(resolve));
    await h.cleanup();
  }
});

test('auto failure: connection refused is a 400 fingerprint_fetch_failed and persists nothing', async () => {
  const h = await makeHarness('auto-fail');
  try {
    const before = await fs.readFile(networkFilePath(h.dir), 'utf8').catch(() => null);
    const closedPort = await freePort();
    const target = `https://127.0.0.1:${closedPort}`;
    const failed = await httpsRequest(h.port, {
      method: 'POST',
      path: '/__admin/api/network',
      headers: h.keyHeaders,
      body: { publicUrl: target, publicFingerprint: 'auto' }
    });
    assert.equal(failed.status, 400);
    const body = JSON.parse(failed.body);
    assert.equal(body.error, 'fingerprint_fetch_failed');
    assert.equal(body.reason, 'connection_refused');
    const after = await fs.readFile(networkFilePath(h.dir), 'utf8').catch(() => null);
    assert.equal(after, before, 'a failed probe must not create or modify network.json');
    assert.equal(h.gateway.network.publicUrl, h.publicUrl, 'the submitted publicUrl must not be applied');
    assert.equal(h.gateway.network.publicFingerprint, '');
    assert.ok(
      h.store.auditTail(20).some((entry) => entry.type === 'admin_denied' && String(entry.detail).includes('fingerprint_fetch_failed')),
      'audit records the failed probe'
    );
  } finally {
    await h.cleanup();
  }
});

test('fetchPeerFingerprint: https only, hard timeout, coarse reasons (never the target address)', async () => {
  await assert.rejects(
    fetchPeerFingerprint('http://127.0.0.1:9'),
    (error) => error instanceof FingerprintProbeError && error.reason === 'not_https'
  );
  // A TCP server that accepts connections but never completes the TLS
  // handshake: the probe must give up instead of hanging.
  const accepted = new Set();
  const silentTcp = net.createServer((socket) => {
    accepted.add(socket);
    socket.on('error', () => {});
    socket.on('close', () => accepted.delete(socket));
  });
  await new Promise((resolve, reject) => {
    silentTcp.once('error', reject);
    silentTcp.listen(0, '127.0.0.1', resolve);
  });
  const timeoutPort = silentTcp.address().port;
  try {
    await assert.rejects(
      fetchPeerFingerprint(`https://127.0.0.1:${timeoutPort}`, { timeoutMs: 150 }),
      (error) => error instanceof FingerprintProbeError && error.reason === 'timeout' && !error.message.includes(String(timeoutPort))
    );
  } finally {
    for (const socket of accepted) socket.destroy();
    await new Promise((resolve) => silentTcp.close(resolve));
  }
});
