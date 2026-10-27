import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import test from 'node:test';

import { gatewayConfig, resolveConfig } from '../lib/config.js';

const ROOT = path.join(process.cwd(), '.test-tmp', 'config-tests');
const CERT = path.join(process.cwd(), 'tests', 'fixtures', 'test-cert.pem');
// Keep default stateDir inside .test-tmp so a production network.json in the
// real $DSH_HOME can never influence the unit tests.
const TEST_ENV = Object.freeze({ HOME: path.join(ROOT, 'home'), DSH_HOME: path.join(ROOT, 'dsh-home') });

async function tempDir() {
  const dir = path.join(ROOT, `${process.pid}-${Math.random().toString(16).slice(2)}`);
  await fs.rm(dir, { recursive: true, force: true });
  await fs.mkdir(dir, { recursive: true });
  return dir;
}

test('plain-HTTP defaults resolve and publicUrl is derived', async () => {
  const dir = await tempDir();
  const resolved = await resolveConfig(
    { listenHost: '127.0.0.1', listenPort: 3456, upstream: 'http://127.0.0.1:3999', stateDir: dir },
    { env: { DSH_HOME: dir } }
  );
  assert.equal(resolved.listenHost, '127.0.0.1');
  assert.equal(resolved.listenPort, 3456);
  assert.equal(resolved.publicUrl, 'http://127.0.0.1:3456');
  assert.equal(resolved.upstreamBaseUrl, 'http://127.0.0.1:3999/');
  assert.equal(resolved.tls, null);
  assert.equal(resolved.fingerprint, '');
  assert.equal(resolved.sessionTtlHours, 8);
  assert.deepEqual(resolved.loginLock, { maxFailures: 5, windowMinutes: 15, lockMinutes: 15 });
  assert.equal(gatewayConfig(resolved).listenPort, 3456);
});

test('string values from environment-style config are coerced', async () => {
  const dir = await tempDir();
  const resolved = await resolveConfig(
    {
      listenHost: '127.0.0.1',
      listenPort: '3456',
      upstream: 'http://127.0.0.1:3999',
      upstreamInsecureTls: 'true',
      stateDir: dir,
      maxDevices: '3',
      pairTicketTtlSeconds: '5',
      loginLock: { maxFailures: '4', windowMinutes: '2', lockMinutes: '3' }
    },
    { env: TEST_ENV }
  );
  assert.equal(resolved.upstreamInsecureTls, true);
  assert.equal(resolved.maxDevices, 3);
  assert.equal(resolved.pairTicketTtlSeconds, 5);
  assert.deepEqual(resolved.loginLock, { maxFailures: 4, windowMinutes: 2, lockMinutes: 3 });
});

test('wildcard binds are refused', async () => {
  for (const host of ['0.0.0.0', '::', '*']) {
    await assert.rejects(resolveConfig({ listenHost: host, listenPort: 3456 }, { env: TEST_ENV }), /wildcard/u, host);
  }
});

test('TLS material must be complete and publicUrl must match the protocol', async () => {
  await assert.rejects(resolveConfig({ listenHost: '127.0.0.1', listenPort: 3443, tlsCert: CERT }, { env: TEST_ENV }), /together/u);
  await assert.rejects(
    resolveConfig(
      { listenHost: '127.0.0.1', listenPort: 3443, tlsCert: CERT, tlsKey: CERT, publicUrl: 'http://127.0.0.1:3443' },
      { env: TEST_ENV }
    ),
    /https/u
  );
  await assert.rejects(
    resolveConfig(
      { listenHost: '127.0.0.1', listenPort: 3443, publicUrl: 'https://127.0.0.1:3443' },
      { env: TEST_ENV }
    ),
    /http when TLS is not configured/u
  );
});

test('IPv6 listen hosts are bracketed in the derived public URL', async () => {
  const dir = await tempDir();
  const resolved = await resolveConfig(
    { listenHost: '::1', listenPort: 3456, upstream: 'http://127.0.0.1:3999', stateDir: dir },
    { env: TEST_ENV }
  );
  assert.equal(resolved.publicUrl, 'http://[::1]:3456');
});

test('upstream path prefixes and publicUrl credentials are rejected', async () => {
  await assert.rejects(
    resolveConfig({ listenHost: '127.0.0.1', listenPort: 3456, upstream: 'http://127.0.0.1:3999/prefix' }, { env: TEST_ENV }),
    /root URL/u
  );
  await assert.rejects(
    resolveConfig(
      { listenHost: '127.0.0.1', listenPort: 3456, upstream: 'http://127.0.0.1:3999', publicUrl: 'http://user:pass@127.0.0.1:3456' },
      { env: TEST_ENV }
    ),
    /without credentials/u
  );
});

test('$DSH_HOME expansion and admin key path defaults', async () => {
  const dir = await tempDir();
  const resolved = await resolveConfig(
    {
      listenHost: '127.0.0.1',
      listenPort: 3456,
      upstream: 'http://127.0.0.1:3999',
      stateDir: '$DSH_HOME/auth-gate'
    },
    { env: { DSH_HOME: dir } }
  );
  assert.equal(resolved.stateDir, path.join(dir, 'auth-gate'));
  assert.equal(resolved.adminKeyFile, path.join(dir, 'auth-gate', 'admin.key'));
});

test('bad numeric and URL values are rejected', async () => {
  await assert.rejects(resolveConfig({ listenHost: '127.0.0.1', listenPort: 0 }, { env: TEST_ENV }), /listenPort/u);
  await assert.rejects(resolveConfig({ listenHost: '127.0.0.1', listenPort: 3456, upstream: 'not a url' }, { env: TEST_ENV }), /upstream/u);
  await assert.rejects(
    resolveConfig({ listenHost: '127.0.0.1', listenPort: 3456, upstream: 'ftp://127.0.0.1/x' }, { env: TEST_ENV }),
    /upstream/u
  );
  await assert.rejects(
    resolveConfig({ listenHost: '127.0.0.1', listenPort: 3456, loginLock: { maxFailures: 0 } }, { env: TEST_ENV }),
    /maxFailures/u
  );
});
