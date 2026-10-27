import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildUpstreamHeaders,
  buildWebSocketHeaders,
  _isReservedPathForTests as isReservedPath,
  clientIp,
  connectionTokens,
  sanitizeUpgradeResponseHead,
  filterResponseHeaders,
  isHtmlRequest,
  isLoopbackAddress,
  isPublicAssetRequest,
  parseCookies,
  rewriteLocation,
  rewriteReferer,
  sanitizeNext,
  serializeCookie
} from '../lib/gateway.js';

const UPSTREAM = { host: '192.0.2.10:3080', origin: 'https://192.0.2.10:3080' };

test('upstream headers rewrite Host/Origin and replace cookies', () => {
  const headers = buildUpstreamHeaders(
    {
      host: '192.0.2.10:3443',
      cookie: 'dsh_gate_session=session-secret; dsh_gate_device=device-secret',
      origin: 'https://192.0.2.10:3443',
      referer: 'https://192.0.2.10:3443/some/path?q=1',
      connection: 'keep-alive',
      'proxy-connection': 'keep-alive',
      'x-forwarded-proto': 'http',
      'x-forwarded-for': '1.2.3.4',
      'x-real-ip': '1.2.3.4',
      'content-type': 'application/json',
      accept: '*/*',
      'sec-fetch-site': 'same-origin'
    },
    { upstream: UPSTREAM, dshCookie: 'dsh-auth-abc=v1.payload.sig' }
  );
  assert.equal(headers.host, '192.0.2.10:3080');
  assert.equal(headers.origin, 'https://192.0.2.10:3080');
  assert.equal(headers.cookie, 'dsh-auth-abc=v1.payload.sig');
  assert.equal(headers.referer, 'https://192.0.2.10:3080/some/path?q=1');
  assert.equal(headers['x-forwarded-proto'], 'https');
  assert.equal(headers['x-forwarded-for'], undefined);
  assert.equal(headers['x-real-ip'], undefined);
  assert.equal(headers.connection, undefined);
  assert.equal(headers['proxy-connection'], undefined);
  assert.equal(headers['content-type'], 'application/json');
  assert.equal(headers['sec-fetch-site'], 'same-origin');
});

test('Connection-named headers are dropped as hop-by-hop', () => {
  const headers = buildUpstreamHeaders(
    { host: 'g:3443', connection: 'keep-alive, x-remove-me', 'x-remove-me': 'secret', 'x-keep-me': 'ok' },
    { upstream: UPSTREAM, dshCookie: 'dsh-auth-abc=v1.sig' }
  );
  assert.equal(headers['x-remove-me'], undefined);
  assert.equal(headers['x-keep-me'], 'ok');
  assert.deepEqual(connectionTokens('keep-alive, Upgrade'), ['keep-alive', 'upgrade']);
  assert.deepEqual(connectionTokens(undefined), []);
});

test('WebSocket handshake response heads are stripped of Set-Cookie', () => {
  const sanitized = sanitizeUpgradeResponseHead(
    ['HTTP/1.1 101 Switching Protocols', 'Upgrade: websocket', 'Set-Cookie: dsh-auth-x=secret; Path=/', 'Connection: Upgrade'].join('\r\n')
  );
  assert.equal(sanitized.includes('dsh-auth-x'), false);
  assert.match(sanitized, /^HTTP\/1\.1 101/u);
  assert.match(sanitized, /Upgrade: websocket/u);
});

test('upstream headers never leak the inbound cookie when no dsh cookie exists', () => {
  const headers = buildUpstreamHeaders({ cookie: 'dsh_gate_session=abc', host: 'g:3443' }, { upstream: UPSTREAM });
  assert.equal(headers.cookie, undefined);
  assert.equal(headers.host, UPSTREAM.host);
});

test('response headers drop hop-by-hop and Set-Cookie', () => {
  const filtered = filterResponseHeaders({
    'set-cookie': ['dsh-auth-abc=secret; Path=/; HttpOnly', 'other=1'],
    connection: 'keep-alive, x-secret',
    'x-secret': 'should-be-dropped',
    'keep-alive': 'timeout=5',
    'transfer-encoding': 'chunked',
    'content-type': 'text/html; charset=utf-8',
    'content-encoding': 'gzip',
    location: '/after',
    'strict-transport-security': 'max-age=10'
  });
  assert.deepEqual(filtered, {
    'content-type': 'text/html; charset=utf-8',
    'content-encoding': 'gzip',
    location: '/after',
    'strict-transport-security': 'max-age=10'
  });
});

test('Location rewriting keeps the browser on the gateway', () => {
  assert.equal(rewriteLocation('https://192.0.2.10:3080/login?next=%2F', UPSTREAM), '/login?next=%2F');
  assert.equal(rewriteLocation('//192.0.2.10:3080/root', UPSTREAM), '/root');
  assert.equal(rewriteLocation('http://192.0.2.10:3080/x', UPSTREAM), '/x');
  assert.equal(rewriteLocation('/relative', UPSTREAM), '/relative');
  assert.equal(rewriteLocation('https://example.com/external', UPSTREAM), '/');
  assert.equal(rewriteLocation('//evil.example/phish', UPSTREAM), '/');
  assert.equal(rewriteLocation('javascript:alert(1)', UPSTREAM), '/');
  assert.equal(rewriteLocation(undefined, UPSTREAM), undefined);
});

test('Referer is rewritten to the upstream origin', () => {
  assert.equal(rewriteReferer('https://192.0.2.10:3443/ui?x=1', UPSTREAM), 'https://192.0.2.10:3080/ui?x=1');
  assert.equal(rewriteReferer('not a url', UPSTREAM), undefined);
  assert.equal(rewriteReferer(undefined, UPSTREAM), undefined);
});

test('WebSocket handshake headers keep upgrade fields and replace identity', () => {
  const headers = buildWebSocketHeaders(
    {
      host: '192.0.2.10:3443',
      origin: 'https://192.0.2.10:3443',
      cookie: 'dsh_gate_session=session-secret',
      connection: 'Upgrade',
      upgrade: 'websocket',
      'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
      'sec-websocket-version': '13',
      'sec-websocket-extensions': 'permessage-deflate',
      'x-forwarded-proto': 'http'
    },
    { upstream: UPSTREAM, dshCookie: 'dsh-auth-abc=v1.payload.sig' }
  );
  assert.equal(headers.host, UPSTREAM.host);
  assert.equal(headers.origin, UPSTREAM.origin);
  assert.equal(headers.cookie, 'dsh-auth-abc=v1.payload.sig');
  assert.equal(headers.connection, 'Upgrade');
  assert.equal(headers.upgrade, 'websocket');
  assert.equal(headers['sec-websocket-key'], 'dGhlIHNhbXBsZSBub25jZQ==');
  assert.equal(headers['sec-websocket-extensions'], 'permessage-deflate');
  assert.equal(headers['x-forwarded-proto'], 'https');
});

test('sanitizeNext only accepts same-site absolute paths', () => {
  assert.equal(sanitizeNext('/ui?x=1'), '/ui?x=1');
  assert.equal(sanitizeNext(undefined), '/');
  assert.equal(sanitizeNext(''), '/');
  assert.equal(sanitizeNext('https://evil.example/'), '/');
  assert.equal(sanitizeNext('//evil.example/'), '/');
  assert.equal(sanitizeNext('/\\evil.example/'), '/');
  assert.equal(sanitizeNext('/ok\u0000bad'), '/');
  assert.equal(sanitizeNext('/__auth/login'), '/');
  assert.equal(sanitizeNext('/__admin/api/state'), '/');
  assert.equal(sanitizeNext(`/${'a'.repeat(3000)}`), '/');
});

test('loopback detection covers IPv4, IPv6 and mapped addresses', () => {
  assert.equal(isLoopbackAddress('127.0.0.1'), true);
  assert.equal(isLoopbackAddress('127.42.0.9'), true);
  assert.equal(isLoopbackAddress('::1'), true);
  assert.equal(isLoopbackAddress('::ffff:127.0.0.1'), true);
  assert.equal(isLoopbackAddress('192.0.2.10'), false);
  assert.equal(isLoopbackAddress('::ffff:192.0.2.10'), false);
  assert.equal(isLoopbackAddress(''), false);
  assert.equal(isLoopbackAddress('not-an-ip'), false);
});

test('cookie parsing and serialization', () => {
  const cookies = parseCookies('a=1; b="two"; c=3=4; malformed; a=ignored');
  assert.deepEqual(cookies, { a: '1', b: 'two', c: '3=4' });
  assert.deepEqual(parseCookies(undefined), {});
  const cookie = serializeCookie('dsh_gate_session', 'abc', { secure: true, maxAgeSeconds: 3600 });
  assert.match(cookie, /^dsh_gate_session=abc; Path=\//u);
  assert.match(cookie, /; Max-Age=3600/u);
  assert.match(cookie, /; HttpOnly/u);
  assert.match(cookie, /; SameSite=Lax/u);
  assert.match(cookie, /; Secure/u);
  assert.doesNotMatch(cookie, /Expires=/u);
});

test('HTML request detection and reserved paths', () => {
  assert.equal(isHtmlRequest({ headers: { accept: 'text/html,application/xhtml+xml' } }), true);
  assert.equal(isHtmlRequest({ headers: { accept: '*/*' } }), false);
  assert.equal(isHtmlRequest({ headers: {} }), false);
  assert.equal(isReservedPath('/__auth/login'), true);
  assert.equal(isReservedPath('/__auth'), true);
  assert.equal(isReservedPath('/__admin/api/state'), true);
  assert.equal(isReservedPath('/__authx'), false);
  assert.equal(isReservedPath('/api/remote.mux'), false);
});

test('public static assets are GET/HEAD-only and never cover reserved paths', () => {
  for (const path of [
    '/manifest.webmanifest',
    '/favicon.svg',
    '/favicon-dark.svg',
    '/favicon.ico',
    '/apple-touch-icon.png',
    '/apple-touch-icon-precomposed.png',
    '/assets/index-CN7NIWNw.js',
    '/assets/vendor-DV2921Zo.css'
  ]) {
    assert.equal(isPublicAssetRequest('GET', path), true, `GET ${path}`);
    assert.equal(isPublicAssetRequest('HEAD', path), true, `HEAD ${path}`);
    assert.equal(isPublicAssetRequest('POST', path), false, `POST ${path}`);
    assert.equal(isPublicAssetRequest('PUT', path), false, `PUT ${path}`);
    assert.equal(isPublicAssetRequest(undefined, path), false, `undefined method ${path}`);
  }
  // Data/API/admin routes can never ride the static exemption.
  assert.equal(isPublicAssetRequest('GET', '/api/remote.mux'), false);
  assert.equal(isPublicAssetRequest('GET', '/api/remote.mux?path=/manifest.webmanifest'), false);
  assert.equal(isPublicAssetRequest('GET', '/plugins/some-plugin/client.js'), false);
  assert.equal(isPublicAssetRequest('GET', '/__auth/whoami'), false);
  assert.equal(isPublicAssetRequest('GET', '/__admin'), false);
  assert.equal(isPublicAssetRequest('GET', '/__admin/api/state'), false);
  assert.equal(isPublicAssetRequest('GET', '/manifest.webmanifest/extra'), false);
  assert.equal(isPublicAssetRequest('GET', '/assets'), false);
  assert.equal(isPublicAssetRequest('GET', '/assets/'), false);
  assert.equal(isPublicAssetRequest('GET', '/assets/../__admin/api/state'), false);
  assert.equal(isPublicAssetRequest('GET', '/assets/%2e%2e/api/remote.mux'), false);
  assert.equal(isPublicAssetRequest('GET', '/assets/%2fetc%2fpasswd'), false);
  assert.equal(isPublicAssetRequest('GET', '/assets/a\\\\b.js'), false);
});

test('clientIp strips the IPv4-mapped prefix', () => {
  assert.equal(clientIp({ socket: { remoteAddress: '::ffff:192.0.2.10' } }), '192.0.2.10');
  assert.equal(clientIp({ socket: { remoteAddress: '::1' } }), '::1');
  assert.equal(clientIp({ socket: {} }), '');
});
