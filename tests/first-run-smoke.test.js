/**
 * First-install smoke test (v0.7.4).
 *
 * Starts the standalone gateway with the portable defaults (loopback, plain
 * HTTP, no TLS, default state/limits) on a free port, then verifies the parts a
 * brand-new installation needs before any profile override exists:
 *   - it binds http://127.0.0.1:<port> and warns about loopback/no TLS;
 *   - the login page is reachable and /__admin serves the setup wizard;
 *   - a one-time setup link is logged and the 0600 setup.token file is readable;
 *   - SIGTERM shuts it down cleanly without leftover processes or temp files.
 *
 * The real dsh upstream is never contacted: only public pages are requested and
 * DSH_TOKEN_URL points at a closed local port.
 */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import * as fs from 'node:fs/promises';
import * as net from 'node:net';
import * as path from 'node:path';
import test from 'node:test';

const ROOT = process.cwd();
const TMP_ROOT = path.join(ROOT, '.test-tmp', 'first-run-smoke');
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(() => resolve(address.port));
    });
  });
}

function waitFor(predicate, { timeoutMs = 20_000, intervalMs = 50 } = {}) {
  const deadline = Date.now() + timeoutMs;
  return (async () => {
    while (Date.now() < deadline) {
      const value = await predicate();
      if (value) return value;
      await delay(intervalMs);
    }
    throw new Error('timed out waiting for condition');
  })();
}

async function waitForLogin(url, child, output) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`standalone exited early (code ${child.exitCode})\n${output()}`);
    }
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1_000) });
      if (response.status === 200) return response;
    } catch {
      // listener not accepting connections yet
    }
    await delay(100);
  }
  throw new Error(`timed out waiting for ${url}\n${output()}`);
}

function waitForExit(child, timeoutMs = 10_000) {
  return new Promise((resolve, reject) => {
    if (child.exitCode !== null) {
      resolve({ code: child.exitCode, signal: child.signalCode });
      return;
    }
    const timer = setTimeout(() => reject(new Error('standalone did not exit after SIGTERM')), timeoutMs);
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
  });
}

test('first install starts with the portable defaults and exits cleanly', async (t) => {
  const stateDir = path.join(TMP_ROOT, `${process.pid}-${Date.now()}`);
  const homeDir = path.join(stateDir, 'home');
  const port = await freePort();
  await fs.rm(stateDir, { recursive: true, force: true });
  await fs.mkdir(homeDir, { recursive: true, mode: 0o700 });

  const env = { ...process.env };
  // Do not let the developer/CI shell inject deployment-specific gate settings.
  for (const key of Object.keys(env)) {
    if (key.startsWith('AUTH_GATE_')) delete env[key];
  }
  Object.assign(env, {
    HOME: homeDir,
    DSH_HOME: path.join(stateDir, 'dsh-home'),
    // Only the port and the temp state directory are overridden; listenHost,
    // upstream, TLS, TTLs, maxDevices and loginLock all come from defaults.
    AUTH_GATE_LISTEN_PORT: String(port),
    AUTH_GATE_STATE_DIR: stateDir,
    DSH_TOKEN_URL: 'http://127.0.0.1:9/?token=first-run-smoke'
  });

  const child = spawn(process.execPath, [path.join(ROOT, 'lib', 'standalone.js')], {
    cwd: ROOT,
    env,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    stdout += chunk;
  });
  child.stderr.on('data', (chunk) => {
    stderr += chunk;
  });
  const output = () => `--- stdout ---\n${stdout}\n--- stderr ---\n${stderr}`;

  t.after(async () => {
    if (child.exitCode === null) child.kill('SIGKILL');
    await fs.rm(stateDir, { recursive: true, force: true });
  });

  const base = `http://127.0.0.1:${port}`;
  const login = await waitForLogin(`${base}/__auth/login`, child, output);
  assert.equal(login.status, 200);
  assert.match(login.headers.get('content-type') ?? '', /text\/html/u);

  // The log must say exactly what was bound: loopback + plain HTTP. Gateway
  // warnings go to stderr while the info lines go to stdout.
  await waitFor(() => stdout.includes(`listening on ${base}`));
  await waitFor(() => stderr.includes('listener is bound to loopback'));
  const allOutput = `${stdout}\n${stderr}`;
  assert.match(allOutput, new RegExp(`listening on http://127\\.0\\.0\\.1:${port}`, 'u'));
  assert.match(allOutput, /upstream http:\/\/127\.0\.0\.1:3080/u);
  assert.match(allOutput, /over PLAIN HTTP/u);
  assert.match(allOutput, /listener is bound to loopback/u);
  assert.match(allOutput, /automatic loopback admin channel is DISABLED/u);
  assert.match(allOutput, /TLS is not configured/u);

  // /__admin is the first-run wizard (200) before any user exists; a 302 to the
  // login page is also acceptable if routing changes, but it must not 404/403.
  const admin = await fetch(`${base}/__admin`, { redirect: 'manual', signal: AbortSignal.timeout(5_000) });
  assert.ok([200, 302].includes(admin.status), `unexpected /__admin status ${admin.status}`);

  // v0.6.1 P0 regression: a listener bound to loopback disables the automatic
  // loopback admin channel, so an unauthenticated /__admin/api/admin-key must
  // be rejected and must never echo the key it protects.
  const adminKeyResponse = await fetch(`${base}/__admin/api/admin-key`, {
    redirect: 'manual',
    signal: AbortSignal.timeout(5_000)
  });
  assert.equal(adminKeyResponse.status, 403);
  const adminKeyBody = await adminKeyResponse.text();
  const storedAdminKey = (await fs.readFile(path.join(stateDir, 'admin.key'), 'utf8')).trim();
  assert.ok(adminKeyBody.length > 0, 'rejection should carry a JSON error body');
  assert.ok(!adminKeyBody.includes(storedAdminKey), 'admin-key response must not leak the key');
  assert.ok(!adminKeyBody.includes('adminKey'), 'admin-key response must not contain the adminKey field');

  // One-time setup link in the log and the same secret in the 0600 file.
  const setupMatch = await waitFor(() => /#setup=([0-9a-f]{64})/u.exec(stdout));
  const setupToken = setupMatch[1];
  const tokenFile = path.join(stateDir, 'setup.token');
  const fileToken = (await fs.readFile(tokenFile, 'utf8')).trim();
  assert.equal(fileToken, setupToken);
  assert.match(stdout, /auth-gate: setup required/u);
  assert.ok(stdout.includes(tokenFile), 'setup log line should mention setup.token path');
  const tokenStat = await fs.stat(tokenFile);
  assert.equal(tokenStat.mode & 0o777, 0o600);

  // Avoid depending on dsh: the setup status endpoint is public and local.
  const status = await fetch(`${base}/__admin/api/setup/status`, { signal: AbortSignal.timeout(5_000) });
  assert.equal(status.status, 200);
  assert.equal((await status.json()).configured, false);

  child.kill('SIGTERM');
  const exit = await waitForExit(child);
  assert.equal(exit.code, 0);
  assert.equal(exit.signal, null);
  assert.equal(child.exitCode, 0);

  // Persistent state is expected; atomic-write temp files and PID files are not.
  // state.json is only written on the first mutation, so a fresh start leaves
  // just the admin key (0600) and the one-time setup token (0600).
  const files = await fs.readdir(stateDir);
  for (const expected of ['admin.key', 'setup.token']) assert.ok(files.includes(expected), `missing ${expected}`);
  assert.deepEqual(
    files.filter((name) => name.includes('.tmp-') || name.endsWith('.pid') || name.endsWith('.lock')),
    []
  );
  assert.equal((await fs.stat(stateDir)).mode & 0o777, 0o700);
  assert.equal((await fs.stat(path.join(stateDir, 'admin.key'))).mode & 0o777, 0o600);
});
