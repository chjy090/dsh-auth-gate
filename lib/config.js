/**
 * Configuration resolution shared by the Cordis plugin and the standalone
 * development entry point. Validation is deliberately strict: this process is
 * the only thing standing between the network and a launch-token-authenticated
 * dsh, so an ambiguous configuration is a startup error (reported, not thrown
 * through Cordis boot — see index.js).
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { certificateFingerprint } from './qr.js';
import { defaultStateDir } from './store.js';

export const CONFIG_DEFAULTS = Object.freeze({
  listenHost: '127.0.0.1',
  listenPort: 3443,
  upstream: 'http://127.0.0.1:3080',
  upstreamInsecureTls: false,
  sessionTtlHours: 8,
  deviceTtlDays: 90,
  maxDevices: 8,
  pairTicketTtlSeconds: 120,
  loginLock: Object.freeze({ maxFailures: 5, windowMinutes: 15, lockMinutes: 15 })
});

const WILDCARD_HOSTS = new Set(['0.0.0.0', '::', '[::]', '*']);

function expandPath(value, env) {
  if (typeof value !== 'string' || value.length === 0) return value;
  let expanded = value;
  if (expanded === '~') expanded = env.HOME ?? expanded;
  else if (expanded.startsWith('~/')) expanded = path.join(env.HOME ?? '', expanded.slice(2));
  expanded = expanded.replaceAll('${DSH_HOME}', env.DSH_HOME ?? '').replaceAll('$DSH_HOME', env.DSH_HOME ?? '');
  expanded = expanded.replaceAll('${HOME}', env.HOME ?? '').replaceAll('$HOME', env.HOME ?? '');
  return path.resolve(expanded);
}

function positiveInteger(value, name, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  const number = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
  if (!Number.isInteger(number) || number < min || number > max) throw new Error(`config: ${name} must be an integer between ${min} and ${max}`);
  return number;
}

function booleanValue(value) {
  if (value === undefined) return undefined;
  if (typeof value === 'boolean') return value;
  if (value === 'true' || value === '1') return true;
  if (value === 'false' || value === '0') return false;
  throw new Error(`config: invalid boolean ${JSON.stringify(value)}`);
}

/**
 * @param {Record<string,unknown>} raw
 * @param {{env?:Record<string,string|undefined>, defaults?:Record<string,unknown>}} [options]
 */
export async function resolveConfig(raw = {}, options = {}) {
  const env = options.env ?? process.env;
  const input = { ...CONFIG_DEFAULTS, ...options.defaults };
  for (const [key, value] of Object.entries(raw ?? {})) {
    if (value !== undefined) input[key] = value;
  }
  if (input.loginLock !== undefined && input.loginLock !== null) {
    input.loginLock = Object.fromEntries(Object.entries(input.loginLock).filter(([, value]) => value !== undefined));
  }
  const listenHost = String(input.listenHost ?? '').trim();
  if (listenHost.length === 0) throw new Error('config: listenHost is required');
  if (WILDCARD_HOSTS.has(listenHost)) {
    throw new Error('config: listenHost must be a concrete interface address, not a wildcard (bind 192.0.2.10 or 127.0.0.1)');
  }
  const listenPort = positiveInteger(input.listenPort, 'listenPort', { min: 1, max: 65535 });

  let upstreamUrl;
  try {
    upstreamUrl = new URL(String(input.upstream));
  } catch {
    throw new Error('config: upstream must be an absolute http(s) URL');
  }
  if (upstreamUrl.protocol !== 'https:' && upstreamUrl.protocol !== 'http:') throw new Error('config: upstream must be http(s)');
  if (upstreamUrl.username !== '' || upstreamUrl.password !== '') throw new Error('config: upstream must not embed credentials');
  if (upstreamUrl.pathname !== '/' && upstreamUrl.pathname !== '') throw new Error('config: upstream must point at the dsh root URL (no path prefix)');

  const upstreamInsecureTls = booleanValue(input.upstreamInsecureTls) ?? false;

  const tlsCertPath = input.tlsCert === undefined || input.tlsCert === null || input.tlsCert === '' ? null : expandPath(String(input.tlsCert), env);
  const tlsKeyPath = input.tlsKey === undefined || input.tlsKey === null || input.tlsKey === '' ? null : expandPath(String(input.tlsKey), env);
  if ((tlsCertPath === null) !== (tlsKeyPath === null)) throw new Error('config: tlsCert and tlsKey must be configured together');
  let tls = null;
  let fingerprint = '';
  if (tlsCertPath !== null) {
    let cert;
    let key;
    try {
      [cert, key] = await Promise.all([fs.readFile(tlsCertPath), fs.readFile(tlsKeyPath)]);
    } catch (error) {
      throw new Error(`config: cannot read TLS material (${error.code ?? error.message})`);
    }
    fingerprint = certificateFingerprint(cert) ?? '';
    if (fingerprint === '') throw new Error('config: tlsCert is not a PEM certificate');
    tls = { cert, key };
  }

  const publicUrlRaw = input.publicUrl === undefined || input.publicUrl === null || input.publicUrl === '' ? undefined : String(input.publicUrl);
  const listenHostForUrl = listenHost.includes(':') && !listenHost.startsWith('[') ? `[${listenHost}]` : listenHost;
  let publicUrl;
  try {
    const parsed = publicUrlRaw === undefined ? new URL(`${tls === null ? 'http' : 'https'}://${listenHostForUrl}:${listenPort}`) : new URL(publicUrlRaw);
    if (parsed.username !== '' || parsed.password !== '') throw new Error('credentials');
    publicUrl = parsed.origin;
  } catch {
    throw new Error('config: publicUrl must be an absolute URL without credentials');
  }
  const publicProto = new URL(publicUrl).protocol;
  if (tlsCertPath !== null && publicProto !== 'https:') throw new Error('config: publicUrl must be https when TLS is configured');
  if (tlsCertPath === null && publicProto !== 'http:') throw new Error('config: publicUrl must be http when TLS is not configured (terminate TLS in the gate, not in front of it)');

  const stateDir = expandPath(String(input.stateDir ?? defaultStateDir(env)), env);
  if (typeof stateDir !== 'string' || stateDir.length === 0) throw new Error('config: stateDir is required');
  const adminKeyFile = input.adminKeyFile === undefined || input.adminKeyFile === null || input.adminKeyFile === '' ? path.join(stateDir, 'admin.key') : expandPath(String(input.adminKeyFile), env);

  const loginLockInput = { ...CONFIG_DEFAULTS.loginLock, ...(input.loginLock ?? {}) };
  const loginLock = {
    maxFailures: positiveInteger(loginLockInput.maxFailures, 'loginLock.maxFailures', { min: 1, max: 100 }),
    windowMinutes: positiveInteger(loginLockInput.windowMinutes, 'loginLock.windowMinutes', { min: 1, max: 1440 }),
    lockMinutes: positiveInteger(loginLockInput.lockMinutes, 'loginLock.lockMinutes', { min: 1, max: 1440 })
  };

  return {
    listenHost,
    listenPort,
    publicUrl,
    upstream: upstreamUrl.href,
    upstreamOrigin: upstreamUrl.origin,
    upstreamBaseUrl: new URL('/', upstreamUrl).href,
    upstreamInsecureTls,
    tlsCert: tlsCertPath,
    tlsKey: tlsKeyPath,
    tls,
    fingerprint,
    stateDir,
    adminKeyFile,
    sessionTtlHours: positiveInteger(input.sessionTtlHours, 'sessionTtlHours', { min: 1, max: 24 * 30 }),
    deviceTtlDays: positiveInteger(input.deviceTtlDays, 'deviceTtlDays', { min: 1, max: 3650 }),
    maxDevices: positiveInteger(input.maxDevices, 'maxDevices', { min: 1, max: 100 }),
    pairTicketTtlSeconds: positiveInteger(input.pairTicketTtlSeconds, 'pairTicketTtlSeconds', { min: 1, max: 3600 }),
    loginLock
  };
}

/** Config view expected by the gateway. */
export function gatewayConfig(resolved) {
  return {
    listenHost: resolved.listenHost,
    listenPort: resolved.listenPort,
    publicUrl: resolved.publicUrl,
    upstream: resolved.upstream,
    upstreamInsecureTls: resolved.upstreamInsecureTls,
    sessionTtlHours: resolved.sessionTtlHours,
    deviceTtlDays: resolved.deviceTtlDays,
    maxDevices: resolved.maxDevices,
    pairTicketTtlSeconds: resolved.pairTicketTtlSeconds,
    loginLock: resolved.loginLock
  };
}
