import assert from 'node:assert/strict';
import test from 'node:test';

import { adminPage, escapeHtml, loginPage, pairPage } from '../lib/pages.js';

test('escapeHtml covers all HTML metacharacters', () => {
  assert.equal(escapeHtml(`<a href="x">'&'</a>`), '&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;');
});

test('v0.4.0 login page asks for username + password only (no TOTP)', () => {
  const html = loginPage({
    csrf: '</script><script>alert(1)</script>',
    next: '/ui?x=1',
    configured: true,
    nonce: 'nonce-123',
    loopback: true
  });
  assert.match(html, /autocomplete="username"/u);
  assert.match(html, /autocomplete="current-password"/u);
  // Device pairing is the second factor; the login form has no OTP field.
  assert.equal(html.includes('one-time-code'), false);
  assert.equal(html.includes('id="totp"'), false);
  assert.equal(html.includes('name="totp"'), false);
  assert.match(html, /nonce="nonce-123"/u);
  assert.match(html, /配对后的设备登录只需用户名 \+ 密码/u);
  assert.equal(html.includes('</script><script>alert(1)'), false);
  assert.match(html, /\\u003c\/script\\u003e/u);
});

test('unconfigured login page does not render a password form', () => {
  const html = loginPage({ csrf: 'abc', next: '/', configured: false, nonce: 'n', loopback: false });
  assert.equal(html.includes('id="login-form"'), false);
  assert.equal(html.includes('autocomplete="current-password"'), false);
  assert.match(html, /尚未初始化/u);
});

test('admin page escapes device names and never trusts state HTML', () => {
  const html = adminPage({
    nonce: 'n',
    csrf: 'c',
    state: {
      configured: true,
      user: { username: 'admin', totpConfigured: true, totpConfirmed: false },
      devices: [
        {
          id: 'd_1',
          name: '<img src=x onerror=alert(1)>',
          platform: 'android',
          createdAt: 1,
          lastSeenAt: 2,
          expiresAt: 3
        }
      ]
    }
  });
  assert.equal(html.includes('<img src=x'), false);
  assert.match(html, /&lt;img src=x/u);
  assert.match(html, /id="qr-button"/u);
  assert.match(html, /id="pair-totp"/u);
  assert.match(html, /inputmode="numeric"/u);
  assert.equal(html.includes('id="pair-current-password"'), false);
  assert.match(html, /data-device-id="d_1"/u);
  assert.match(html, /TOTP 状态<strong>已配置<\/strong>/u);
  assert.equal(html.includes('未配置'), false);
});

test('admin page derives the TOTP badge from totpConfigured, not legacy totpConfirmed', () => {
  // A user created via bootstrap/loopback/adminKey has a secret but never
  // passed the session-channel proof, so legacy totpConfirmed stays false.
  const state = {
    configured: true,
    user: { username: 'admin', totpConfigured: false, totpConfirmed: true },
    devices: []
  };
  const html = adminPage({ nonce: 'n', csrf: 'c', state });
  assert.match(html, /TOTP 状态<strong>未配置<\/strong>/u);
  assert.equal(html.includes('已配置'), false);
});

test('pair page reads the fragment and never embeds a ticket server-side', () => {
  const html = pairPage({ nonce: 'n' });
  assert.match(html, /location\.hash/u);
  assert.match(html, /\/__auth\/pair\/redeem/u);
  assert.equal(html.includes('v=1&t='), false);
});
