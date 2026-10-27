import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as http from 'node:http';
import * as path from 'node:path';
import test from 'node:test';

import { DshSessionProvider } from '../lib/dsh-session.js';
import { createGateway } from '../lib/gateway.js';
import { StateStore } from '../lib/store.js';

const silent = { info() {}, warn() {}, error() {} };
const ROOT = path.join(process.cwd(), '.test-tmp', 'gateway-tests');

function request(port, { cookie, accept = 'application/json' } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path: '/',
        method: 'GET',
        headers: {
          host: `127.0.0.1:${port}`,
          accept,
          ...(cookie === undefined ? {} : { cookie })
        }
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
      }
    );
    req.on('error', reject);
    req.end();
  });
}

test('a 401 from dsh refreshes the cookie and retries once', async () => {
  const dir = path.join(ROOT, `${process.pid}-${Date.now()}`);
  await fs.mkdir(dir, { recursive: true });
  let cookieVersion = 0;
  let expectedCookie = '';
  let exchangeCount = 0;
  let originHeader = '';
  let hostHeader = '';
  const mock = http.createServer((req, res) => {
    if (req.url.startsWith('/?token=')) {
      exchangeCount += 1;
      cookieVersion += 1;
      expectedCookie = `dsh-auth-mock=v1.${cookieVersion}.sig`;
      res.writeHead(303, { 'set-cookie': `${expectedCookie}; Path=/; HttpOnly`, location: './' });
      res.end();
      return;
    }
    hostHeader = String(req.headers.host ?? '');
    originHeader = String(req.headers.origin ?? '');
    if (req.headers.cookie !== expectedCookie) {
      res.writeHead(401, { 'content-type': 'text/plain', 'set-cookie': 'upstream=leak; Path=/' });
      res.end('unauthorized');
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end('<!doctype html><script>window.__DSH_BOOT__={"ok":true}</script>');
  });
  await new Promise((resolve) => mock.listen(0, '127.0.0.1', resolve));
  const mockPort = mock.address().port;

  const store = await StateStore.open({ stateDir: dir, logger: silent });
  await store.createUser({ username: 'admin', passwordHash: 'scrypt$16384$8$1$c2FsdA==$aGFzaA==', totpSecretB32: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' });
  const ticket = await store.issueTicket({ ttlMs: 60_000 });
  const device = await store.redeemTicket(ticket.ticket, {
    maxDevices: 8,
    deviceTtlMs: 3_600_000,
    name: 'test',
    platform: 'android',
    origin: 'http://127.0.0.1'
  });
  const session = await store.createSession({ deviceId: device.device.id, ttlMs: 3_600_000 });

  const dshSession = new DshSessionProvider({ tokenUrl: `http://127.0.0.1:${mockPort}/?token=test-token`, logger: silent });
  const gateway = createGateway({
    config: {
      listenHost: '127.0.0.1',
      listenPort: 0,
      publicUrl: 'http://127.0.0.1',
      upstream: `http://127.0.0.1:${mockPort}`,
      upstreamInsecureTls: false,
      sessionTtlHours: 8,
      deviceTtlDays: 90,
      maxDevices: 8,
      pairTicketTtlSeconds: 120,
      loginLock: { maxFailures: 5, windowMinutes: 15, lockMinutes: 15 }
    },
    store,
    dshSession,
    tls: null,
    logger: silent
  });
  await gateway.listen();
  const port = gateway.server.address().port;
  try {
    const first = await request(port, { cookie: `dsh_gate_session=${session.token}`, accept: 'text/html' });
    assert.equal(first.status, 200);
    assert.match(first.body, /__DSH_BOOT__/u);
    assert.equal(hostHeader, `127.0.0.1:${mockPort}`);
    assert.equal(exchangeCount, 1);

    // Invalidate the server-side cookie without telling the gateway, then make
    // the next proxied request. The first attempt gets 401, the gate refreshes
    // the cookie via the launch URL and retries once.
    expectedCookie = 'dsh-auth-mock=v1.expired.sig';
    const second = await request(port, { cookie: `dsh_gate_session=${session.token}`, accept: 'text/html' });
    assert.equal(second.status, 200);
    assert.match(second.body, /__DSH_BOOT__/u);
    assert.equal(exchangeCount, 2);
    assert.equal(second.headers['set-cookie'], undefined, 'upstream Set-Cookie must be stripped');

    // The retry must not leak the browser's gate cookie upstream.
    assert.equal(hostHeader, `127.0.0.1:${mockPort}`);
    assert.equal(originHeader, '');
  } finally {
    await gateway.close();
    await new Promise((resolve) => mock.close(resolve));
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('a 401 after one retry becomes 502 without leaking the upstream body', async () => {
  const dir = path.join(ROOT, `${process.pid}-${Date.now()}-retry-fail`);
  await fs.mkdir(dir, { recursive: true });
  let exchanges = 0;
  const mock = http.createServer((req, res) => {
    if (req.url.startsWith('/?token=')) {
      exchanges += 1;
      res.writeHead(303, { 'set-cookie': `dsh-auth-mock=v1.${exchanges}.sig; Path=/`, location: './' });
      res.end();
      return;
    }
    res.writeHead(401, { 'content-type': 'text/html' });
    res.end('<html>dsh launch token page</html>');
  });
  await new Promise((resolve) => mock.listen(0, '127.0.0.1', resolve));
  const mockPort = mock.address().port;
  const store = await StateStore.open({ stateDir: dir, logger: silent });
  await store.createUser({ username: 'admin', passwordHash: 'scrypt$16384$8$1$c2FsdA==$aGFzaA==', totpSecretB32: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' });
  const ticket = await store.issueTicket({ ttlMs: 60_000 });
  const device = await store.redeemTicket(ticket.ticket, { maxDevices: 8, deviceTtlMs: 3_600_000, name: 't', platform: 'web', origin: 'http://127.0.0.1' });
  const session = await store.createSession({ deviceId: device.device.id, ttlMs: 3_600_000 });
  const dshSession = new DshSessionProvider({ tokenUrl: `http://127.0.0.1:${mockPort}/?token=test-token`, logger: silent });
  const gateway = createGateway({
    config: {
      listenHost: '127.0.0.1',
      listenPort: 0,
      publicUrl: 'http://127.0.0.1',
      upstream: `http://127.0.0.1:${mockPort}`,
      upstreamInsecureTls: false,
      sessionTtlHours: 8,
      deviceTtlDays: 90,
      maxDevices: 8,
      pairTicketTtlSeconds: 120,
      loginLock: { maxFailures: 5, windowMinutes: 15, lockMinutes: 15 }
    },
    store,
    dshSession,
    tls: null,
    logger: silent
  });
  await gateway.listen();
  try {
    const result = await request(gateway.server.address().port, { cookie: `dsh_gate_session=${session.token}` });
    assert.equal(result.status, 502);
    assert.equal(result.body.includes('launch token page'), false);
    assert.equal(exchanges, 2);
  } finally {
    await gateway.close();
    await new Promise((resolve) => mock.close(resolve));
    await fs.rm(dir, { recursive: true, force: true });
  }
});
