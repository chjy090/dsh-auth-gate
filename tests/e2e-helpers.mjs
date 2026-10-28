#!/usr/bin/env node
/**
 * Helpers for tests/e2e-standalone.sh.
 *
 * Kept in a file (instead of `node -e`) so passwords, TOTP secrets, tickets and
 * session cookies never appear on a command line or in shell tracing output.
 */

import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import * as tls from 'node:tls';

import { generateTotp } from '../lib/totp.js';

const [, , command, ...args] = process.argv;

function die(message) {
  process.stderr.write(`e2e-helper: ${message}\n`);
  process.exit(2);
}

function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    die(`cannot read JSON from ${file}: ${error.message}`);
  }
}

function getPath(object, dotted) {
  let value = object;
  for (const part of dotted.split('.')) {
    if (value === null || value === undefined || typeof value !== 'object' || !(part in value)) return undefined;
    value = value[part];
  }
  return value;
}

function cookieValue(jarFile, name) {
  let text;
  try {
    text = readFileSync(jarFile, 'utf8');
  } catch (error) {
    die(`cannot read cookie jar ${jarFile}: ${error.message}`);
  }
  for (let line of text.split('\n')) {
    if (line.startsWith('#HttpOnly_')) line = line.slice('#HttpOnly_'.length);
    else if (line.startsWith('#')) continue;
    if (line.trim() === '') continue;
    const fields = line.split('\t');
    if (fields.length >= 7 && fields[5] === name) return fields[6];
  }
  return '';
}

function ws({ host, port, jar, origin }) {
  const cookie = jar === '' ? '' : cookieValue(jar, 'dsh_gate_session');
  const socket = tls.connect({ host, port: Number(port), rejectUnauthorized: false }, () => {
    const lines = [
      'GET /api/remote.mux HTTP/1.1',
      `Host: ${host}:${port}`,
      'Upgrade: websocket',
      'Connection: Upgrade',
      'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
      'Sec-WebSocket-Version: 13',
      `Origin: ${origin}`
    ];
    if (cookie !== '') lines.push(`Cookie: dsh_gate_session=${cookie}`);
    socket.write(`${lines.join('\r\n')}\r\n\r\n`);
  });
  const timer = setTimeout(() => {
    process.stderr.write('e2e-helper: websocket handshake timed out\n');
    socket.destroy();
    process.exit(3);
  }, 15_000);
  socket.once('data', (chunk) => {
    clearTimeout(timer);
    const first = chunk.toString('latin1').split('\r\n')[0];
    process.stdout.write(`${first}\n`);
    socket.destroy();
    process.exit(first.includes('101') ? 0 : 1);
  });
  socket.on('error', (error) => {
    clearTimeout(timer);
    process.stderr.write(`e2e-helper: websocket error: ${error.message}\n`);
    process.exit(4);
  });
}

switch (command) {
  case 'json': {
    const [file, path] = args;
    const value = getPath(readJson(file), path);
    if (value === undefined) die(`missing JSON path ${path} in ${file}`);
    process.stdout.write(`${typeof value === 'string' ? value : JSON.stringify(value)}\n`);
    break;
  }
  case 'totp': {
    const [secret] = args;
    if (!secret) die('totp requires a secret');
    process.stdout.write(`${generateTotp(secret)}\n`);
    break;
  }
  case 'totp-env': {
    const secret = process.env.E2E_TOTP_SECRET ?? '';
    if (!secret) die('totp-env requires E2E_TOTP_SECRET');
    process.stdout.write(`${generateTotp(secret)}\n`);
    break;
  }
  case 'login-json': {
    // v0.4.0: login is username + password; the device cookie is the second
    // factor. No TOTP field is sent.
    writeFileSync(
      args[0],
      JSON.stringify({
        username: process.env.E2E_USERNAME ?? '',
        password: process.env.E2E_PASSWORD ?? ''
      }),
      { mode: 0o600 }
    );
    break;
  }
  case 'bootstrap-json': {
    writeFileSync(
      args[0],
      JSON.stringify({ username: process.env.E2E_USERNAME ?? '', password: process.env.E2E_PASSWORD ?? '' }),
      { mode: 0o600 }
    );
    break;
  }
  case 'setup-begin-json': {
    // The setup token is passed through the environment so it never appears in
    // argv or shell tracing.
    writeFileSync(
      args[0],
      JSON.stringify({
        token: process.env.E2E_SETUP_TOKEN ?? '',
        username: process.env.E2E_USERNAME ?? '',
        password: process.env.E2E_PASSWORD ?? ''
      }),
      { mode: 0o600 }
    );
    break;
  }
  case 'setup-confirm-json': {
    writeFileSync(
      args[0],
      JSON.stringify({ token: process.env.E2E_SETUP_TOKEN ?? '', totp: process.env.E2E_TOTP ?? '' }),
      { mode: 0o600 }
    );
    break;
  }
  case 'redeem-json': {
    const payload = {
      ticket: process.env.E2E_TICKET ?? '',
      deviceName: process.env.E2E_DEVICE_NAME ?? 'e2e-device',
      platform: process.env.E2E_PLATFORM ?? 'android'
    };
    // v0.7.3: optional stable client-side device id for same-device re-pairing.
    if (process.env.E2E_CLIENT_DEVICE_ID !== undefined) payload.clientDeviceId = process.env.E2E_CLIENT_DEVICE_ID;
    writeFileSync(args[0], JSON.stringify(payload), { mode: 0o600 });
    break;
  }
  case 'json-length': {
    const [file, path] = args;
    const value = getPath(readJson(file), path);
    if (!Array.isArray(value)) die(`${path} in ${file} is not an array`);
    process.stdout.write(`${value.length}\n`);
    break;
  }
  case 'session-count': {
    // Count stored sessions of one device in state.json. Used by the v0.7.3 P1
    // race step: after a re-pairing, no session of the device may remain.
    const [file, deviceId] = args;
    if (!deviceId) die('session-count requires a device id');
    const state = readJson(file);
    const sessions = Array.isArray(state.sessions) ? state.sessions : [];
    process.stdout.write(`${sessions.filter((session) => session.deviceId === deviceId).length}\n`);
    break;
  }
  case 'renew-json': {
    writeFileSync(args[0], JSON.stringify({ deviceToken: process.env.E2E_DEVICE_TOKEN ?? '' }), { mode: 0o600 });
    break;
  }
  case 'admin-user-json': {
    const body = {};
    if (process.env.E2E_CURRENT_PASSWORD !== undefined) body.currentPassword = process.env.E2E_CURRENT_PASSWORD;
    if (process.env.E2E_NEW_PASSWORD !== undefined) body.password = process.env.E2E_NEW_PASSWORD;
    if (process.env.E2E_RESET_TOTP === '1') body.resetTotp = true;
    writeFileSync(args[0], JSON.stringify(body), { mode: 0o600 });
    break;
  }
  case 'admin-network-json': {
    // Network settings are read from the environment so a TOTP code never
    // appears in argv or shell tracing output.
    const body = {};
    if (process.env.E2E_LISTEN_HOST !== undefined) body.listenHost = process.env.E2E_LISTEN_HOST;
    if (process.env.E2E_LISTEN_PORT !== undefined) body.listenPort = process.env.E2E_LISTEN_PORT;
    if (process.env.E2E_PUBLIC_URL !== undefined) body.publicUrl = process.env.E2E_PUBLIC_URL;
    if (process.env.E2E_PUBLIC_FP !== undefined) body.publicFingerprint = process.env.E2E_PUBLIC_FP;
    if (process.env.E2E_TOTP !== undefined) body.totp = process.env.E2E_TOTP;
    writeFileSync(args[0], JSON.stringify(body), { mode: 0o600 });
    break;
  }
  case 'admin-qr-json': {
    // Used by the session-channel QR tests: the TOTP code must never appear in
    // argv, so it is read from the environment and written to a 0600 file.
    const body = { platform: process.env.E2E_PLATFORM ?? 'web' };
    if (process.env.E2E_TOTP !== undefined) body.totp = process.env.E2E_TOTP;
    writeFileSync(args[0], JSON.stringify(body), { mode: 0o600 });
    break;
  }
  case 'cert-fingerprint': {
    // SHA-256 DER fingerprint of a PEM certificate (same value the App pins).
    const cert = new X509Certificate(readFileSync(args[0]));
    process.stdout.write(`${createHash('sha256').update(cert.raw).digest('hex')}\n`);
    break;
  }
  case 'url-host': {
    const url = new URL(getPath(readJson(args[0]), 'url'));
    process.stdout.write(`${url.origin}${url.pathname}\n`);
    break;
  }
  case 'file-contains': {
    const needle = process.env.E2E_NEEDLE ?? '';
    const haystack = readFileSync(args[0], 'utf8');
    process.exit(haystack.includes(needle) ? 0 : 1);
  }
  case 'file-not-contains': {
    const needle = process.env.E2E_NEEDLE ?? '';
    const haystack = readFileSync(args[0], 'utf8');
    process.exit(haystack.includes(needle) ? 1 : 0);
  }
  case 'ticket': {
    const [file] = args;
    const url = new URL(getPath(readJson(file), 'url'));
    const fragment = new URLSearchParams(url.hash.startsWith('#') ? url.hash.slice(1) : url.hash);
    const ticket = fragment.get('t');
    if (!ticket) die('pair URL has no ticket');
    process.stdout.write(`${ticket}\n`);
    break;
  }
  case 'pair-fp': {
    const [file] = args;
    const url = new URL(getPath(readJson(file), 'url'));
    const fragment = new URLSearchParams(url.hash.startsWith('#') ? url.hash.slice(1) : url.hash);
    process.stdout.write(`${fragment.get('fp') ?? ''}\n`);
    break;
  }
  case 'cookie': {
    const [jar, name] = args;
    const value = cookieValue(jar, name);
    if (!value) die(`cookie ${name} not found in ${jar}`);
    process.stdout.write(`${value}\n`);
    break;
  }
  case 'ws': {
    const [host, port, jar, origin] = args;
    ws({ host, port, jar, origin });
    break;
  }
  default:
    die(`unknown command ${JSON.stringify(command)}`);
}
