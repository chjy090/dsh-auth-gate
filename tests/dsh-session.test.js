import assert from 'node:assert/strict';
import * as http from 'node:http';
import test from 'node:test';

import { DshSessionProvider, pickSessionCookie } from '../lib/dsh-session.js';

async function startTokenServer(handler) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    port,
    close: () => new Promise((resolve) => server.close(resolve))
  };
}

const silent = { info() {}, warn() {}, error() {} };

test('picks the dsh-auth cookie and ignores other cookies', () => {
  assert.deepEqual(pickSessionCookie(['theme=dark; Path=/', 'dsh-auth-abc=v1.payload.sig; Path=/; HttpOnly; Secure']), {
    cookie: 'dsh-auth-abc=v1.payload.sig',
    name: 'dsh-auth-abc'
  });
  assert.deepEqual(pickSessionCookie('other=1; Path=/'), { cookie: 'other=1', name: 'other' });
  assert.equal(pickSessionCookie([]), null);
  assert.equal(pickSessionCookie(['broken']), null);
  assert.equal(pickSessionCookie(undefined), null);
  assert.equal(pickSessionCookie(['x=\r\nInjected: 1']), null);
});

test('exchanges the launch token once and caches the cookie', async () => {
  let requests = 0;
  let lastUrl = '';
  const server = await startTokenServer((req, res) => {
    requests += 1;
    lastUrl = req.url;
    res.writeHead(303, {
      location: './',
      'set-cookie': ['dsh-auth-abc=v1.payload.sig; Max-Age=60; Path=/; HttpOnly; Secure']
    });
    res.end();
  });
  try {
    const provider = new DshSessionProvider({
      tokenUrl: `http://127.0.0.1:${server.port}/?token=launch-token-value`,
      logger: silent
    });
    const first = await provider.getCookie();
    assert.equal(first, 'dsh-auth-abc=v1.payload.sig');
    assert.equal(await provider.getCookie(), first);
    assert.equal(requests, 1);
    assert.equal(provider.cookieName, 'dsh-auth-abc');
    assert.equal(lastUrl, '/?token=launch-token-value');
  } finally {
    await server.close();
  }
});

test('force refresh and invalidation exchange the token again', async () => {
  let requests = 0;
  const server = await startTokenServer((req, res) => {
    requests += 1;
    res.writeHead(303, { 'set-cookie': [`dsh-auth-abc=v1.${requests}.sig; Path=/`] });
    res.end();
  });
  try {
    const provider = new DshSessionProvider({ tokenUrl: `http://127.0.0.1:${server.port}/?token=abc`, logger: silent });
    assert.equal(await provider.getCookie(), 'dsh-auth-abc=v1.1.sig');
    assert.equal(await provider.getCookie({ force: true }), 'dsh-auth-abc=v1.2.sig');
    provider.invalidate();
    assert.equal(await provider.getCookie(), 'dsh-auth-abc=v1.3.sig');
    assert.equal(requests, 3);
  } finally {
    await server.close();
  }
});

test('concurrent callers share one exchange', async () => {
  let requests = 0;
  const server = await startTokenServer((req, res) => {
    requests += 1;
    setTimeout(() => {
      res.writeHead(303, { 'set-cookie': ['dsh-auth-abc=v1.sig; Path=/'] });
      res.end();
    }, 20);
  });
  try {
    const provider = new DshSessionProvider({ tokenUrl: `http://127.0.0.1:${server.port}/?token=abc`, logger: silent });
    const results = await Promise.all([provider.getCookie(), provider.getCookie(), provider.getCookie()]);
    assert.deepEqual(results, ['dsh-auth-abc=v1.sig', 'dsh-auth-abc=v1.sig', 'dsh-auth-abc=v1.sig']);
    assert.equal(requests, 1);
  } finally {
    await server.close();
  }
});

test('rejections do not expose the launch token', async () => {
  const server = await startTokenServer((req, res) => {
    res.writeHead(401, { 'content-type': 'text/plain' });
    res.end('unauthorized');
  });
  try {
    const provider = new DshSessionProvider({ tokenUrl: `http://127.0.0.1:${server.port}/?token=super-secret-launch`, logger: silent });
    await assert.rejects(provider.getCookie(), (error) => {
      assert.match(error.message, /launch token was rejected/u);
      assert.equal(error.message.includes('super-secret-launch'), false);
      return true;
    });
  } finally {
    await server.close();
  }
});

test('a response without a session cookie is an error', async () => {
  const server = await startTokenServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<html>no cookie</html>');
  });
  try {
    const provider = new DshSessionProvider({ tokenUrl: `http://127.0.0.1:${server.port}/?token=abc`, logger: silent });
    await assert.rejects(provider.getCookie(), /no dsh session cookie/u);
  } finally {
    await server.close();
  }
});

test('non-http(s) token URLs are rejected', async () => {
  const provider = new DshSessionProvider({ tokenUrl: 'file:///etc/passwd', logger: silent });
  await assert.rejects(provider.getCookie(), /http\(s\)/u);
});
