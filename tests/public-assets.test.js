import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as http from 'node:http';
import * as path from 'node:path';
import test from 'node:test';

import { DshSessionProvider } from '../lib/dsh-session.js';
import { createGateway } from '../lib/gateway.js';
import { StateStore } from '../lib/store.js';

const silent = { info() {}, warn() {}, error() {} };
const ROOT = path.join(process.cwd(), '.test-tmp', 'public-assets-tests');

const DIST_ASSETS = new Set([
  '/manifest.webmanifest',
  '/favicon.svg',
  '/favicon-dark.svg',
  '/favicon.ico',
  '/apple-touch-icon.png',
  '/apple-touch-icon-precomposed.png'
]);

function request(port, { method = 'GET', path: requestPath = '/', accept = 'application/json', body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(body);
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path: requestPath,
        method,
        headers: {
          host: `127.0.0.1:${port}`,
          accept,
          ...(payload === undefined ? {} : { 'content-type': 'application/json', 'content-length': payload.length })
        }
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
      }
    );
    req.on('error', reject);
    req.end(payload);
  });
}

async function start() {
  const dir = path.join(ROOT, `${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  await fs.mkdir(dir, { recursive: true });
  const upstreamPaths = [];
  const mock = http.createServer((req, res) => {
    if (req.url.startsWith('/?token=')) {
      res.writeHead(303, { 'set-cookie': 'dsh-auth-mock=v1.sig; Path=/; HttpOnly', location: './' });
      res.end();
      return;
    }
    upstreamPaths.push(`${req.method} ${req.url}`);
    const pathname = new URL(req.url, 'http://upstream.invalid').pathname;
    // dsh's frontend-static fallback: dist files are served without dsh auth.
    if ((req.method === 'GET' || req.method === 'HEAD') && (DIST_ASSETS.has(pathname) || pathname.startsWith('/assets/'))) {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(req.method === 'HEAD' ? undefined : 'dist-file');
      return;
    }
    res.writeHead(401, { 'content-type': 'application/json' });
    res.end('{"error":"unauthorized"}');
  });
  await new Promise((resolve) => mock.listen(0, '127.0.0.1', resolve));
  const mockPort = mock.address().port;
  const store = await StateStore.open({ stateDir: dir, logger: silent });
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
  return {
    port,
    upstreamPaths,
    async close() {
      await gateway.close();
      await new Promise((resolve) => mock.close(resolve));
      await fs.rm(dir, { recursive: true, force: true });
    }
  };
}

test('public dist assets are proxied without a gate session but API routes stay 401', async () => {
  const harness = await start();
  const { port, upstreamPaths } = harness;
  try {
    // No dsh_gate_session cookie at all: the browser fetches these without one.
    const manifest = await request(port, { path: '/manifest.webmanifest', accept: '*/*' });
    assert.equal(manifest.status, 200, manifest.body);
    assert.equal(manifest.body, 'dist-file');

    const favicon = await request(port, { path: '/favicon.svg', accept: 'image/svg+xml' });
    assert.equal(favicon.status, 200);

    const asset = await request(port, { path: '/assets/index-CN7NIWNw.js', accept: '*/*' });
    assert.equal(asset.status, 200);

    const head = await request(port, { method: 'HEAD', path: '/apple-touch-icon.png' });
    assert.equal(head.status, 200);

    // Everything data-bearing still requires a session (JSON 401, no redirect).
    const api = await request(port, { path: '/api/remote.mux' });
    assert.equal(api.status, 401);
    assert.equal(JSON.parse(api.body).error, 'authentication_required');

    const plugins = await request(port, { path: '/plugins/some-plugin/client.js' });
    assert.equal(plugins.status, 401);

    // HTML navigations still bounce to the login page.
    const page = await request(port, { path: '/', accept: 'text/html' });
    assert.equal(page.status, 302);
    assert.match(page.headers.location, /^\/__auth\/login\?next=/u);

    // Non-GET/HEAD never rides the static exemption.
    const postManifest = await request(port, { method: 'POST', path: '/manifest.webmanifest', body: '{}' });
    assert.equal(postManifest.status, 401);
    const postAsset = await request(port, { method: 'POST', path: '/assets/index-CN7NIWNw.js', body: '{}' });
    assert.equal(postAsset.status, 401);

    // Encoded traversal / separators are rejected before forwarding.
    const encodedDot = await request(port, { path: '/assets/%2e%2e/api/remote.mux' });
    assert.equal(encodedDot.status, 401);
    const encodedSlash = await request(port, { path: '/assets/%2fetc%2fpasswd' });
    assert.equal(encodedSlash.status, 401);

    // The protected requests never reached the upstream mock.
    const protectedHits = upstreamPaths.filter((line) => !line.includes('manifest') && !line.includes('/assets/') && !line.includes('favicon') && !line.includes('apple-touch-icon'));
    assert.deepEqual(protectedHits, []);
  } finally {
    await harness.close();
  }
});
