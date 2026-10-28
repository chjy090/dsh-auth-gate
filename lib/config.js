/**
 * Configuration resolution shared by the Cordis plugin and the standalone
 * development entry point. Validation is deliberately strict: this process is
 * the only thing standing between the network and a launch-token-authenticated
 * dsh, so an ambiguous configuration is a startup error (reported, not thrown
 * through Cordis boot — see index.js).
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { NetworkOverrideError, isWildcardListenHost, readNetworkOverride, validatePublicFingerprint } from './network.js';
import { certificateFingerprint } from './qr.js';
import { defaultStateDir } from './store.js';

export const CONFIG_DEFAULTS = Object.freeze({
  listenHost: '127.0.0.1',
  listenPort: 3443,
  publicFingerprint: '',
  upstream: 'http://127.0.0.1:3080',
  upstreamInsecureTls: false,
  sessionTtlHours: 48,
  sessionAbsoluteTtlDays: 30,
  deviceTtlDays: 90,
  deviceAbsoluteTtlDays: 365,
  maxDevices: 100,
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

/** Like {@link positiveInteger} but 0 is allowed and means "no ceiling". */
function nonNegativeInteger(value, name, { max = Number.MAX_SAFE_INTEGER } = {}) {
  const number = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
  if (!Number.isInteger(number) || number < 0 || number > max) throw new Error(`config: ${name} must be an integer between 0 and ${max}`);
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
 * @param {{env?:Record<string,string|undefined>, defaults?:Record<string,unknown>, ignoreNetworkOverride?:boolean}} [options]
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
  const stateDir = expandPath(String(input.stateDir ?? defaultStateDir(env)), env);
  if (typeof stateDir !== 'string' || stateDir.length === 0) throw new Error('config: stateDir is required');

  let upstreamUrl;
  try {
    upstreamUrl = new URL(String(input.upstream));
  } catch {
    throw new Error('config: upstream must be an absolute http(s) URL');
  }
  if (upstreamUrl.protocol !== 'https:' && upstreamUrl.protocol !== 'http:') throw new Error('config: upstream must be http(s)');
  if (upstreamUrl.username !== '' || upstreamUrl.password !== '') throw new Error('config: upstream must not embed credentials');
  if (upstreamUrl.pathname !== '/' && upstreamUrl.pathname !== '') throw new Error('config: upstream must point at the dsh root URL (no path prefix)');
  const upstreamPort = Number(upstreamUrl.port || (upstreamUrl.protocol === 'https:' ? 443 : 80));

  // Runtime override: network.json wins over the bundle config for these three
  // values only. Its presence is reported to the UI as `source: override`.
  const tlsHint =
    input.tlsCert !== undefined && input.tlsCert !== null && input.tlsCert !== '' &&
    input.tlsKey !== undefined && input.tlsKey !== null && input.tlsKey !== '';
  const networkOverride =
    options.ignoreNetworkOverride === true
      ? null
      : await readNetworkOverride(stateDir, {
          tlsConfigured: tlsHint,
          upstreamPort
        });
  if (networkOverride !== null) {
    for (const key of ['listenHost', 'listenPort', 'publicUrl', 'publicFingerprint']) {
      if (networkOverride[key] !== undefined) input[key] = networkOverride[key];
    }
  }
  const networkSource = networkOverride === null ? 'config' : 'override';

  // External certificate fingerprint (v0.6.2). Empty means "use the gateway's
  // own TLS certificate"; a fixed value is the certificate the App sees when a
  // proxy terminates TLS in front of the gate. `auto` is a POST-only sentinel
  // and never valid in persisted configuration.
  let publicFingerprint;
  try {
    publicFingerprint = validatePublicFingerprint(input.publicFingerprint ?? '');
  } catch {
    throw new Error('config: publicFingerprint must be empty or a 64-character hex SHA-256 certificate fingerprint');
  }

  const listenHost = String(input.listenHost ?? '').trim();
  if (listenHost.length === 0) throw new Error('config: listenHost is required');
  if (WILDCARD_HOSTS.has(listenHost) || isWildcardListenHost(listenHost)) {
    throw new Error('config: listenHost must be a concrete host interface address, not a wildcard (e.g. the LAN address 192.0.2.10)');
  }
  const listenPort = positiveInteger(input.listenPort, 'listenPort', { min: 1, max: 65535 });

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
    publicFingerprint,
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
    networkSource,
    sessionTtlHours: positiveInteger(input.sessionTtlHours, 'sessionTtlHours', { min: 1, max: 24 * 30 }),
    sessionAbsoluteTtlDays: nonNegativeInteger(input.sessionAbsoluteTtlDays, 'sessionAbsoluteTtlDays', { max: 3650 }),
    deviceTtlDays: positiveInteger(input.deviceTtlDays, 'deviceTtlDays', { min: 1, max: 3650 }),
    deviceAbsoluteTtlDays: nonNegativeInteger(input.deviceAbsoluteTtlDays, 'deviceAbsoluteTtlDays', { max: 3650 }),
    maxDevices: positiveInteger(input.maxDevices, 'maxDevices', { min: 1, max: 100 }),
    pairTicketTtlSeconds: positiveInteger(input.pairTicketTtlSeconds, 'pairTicketTtlSeconds', { min: 1, max: 3600 }),
    loginLock
  };
}

/**
 * Resolve the config, but keep the front door starting when *only* the runtime
 * `network.json` override is damaged. Silently ignoring the file would move the
 * listener/QR authority without telling the operator, so this logs a loud,
 * actionable error (including the exact recovery command) and retries with the
 * bundle config. Every other configuration error stays fatal for this plugin.
 *
 * @param {Record<string,unknown>} raw
 * @param {{env?:Record<string,string|undefined>, defaults?:Record<string,unknown>, logger?:{warn?:Function,error?:Function}}} [options]
 */
export async function resolveConfigWithNetworkFallback(raw = {}, options = {}) {
  const logger = options.logger ?? console;
  try {
    return await resolveConfig(raw, options);
  } catch (error) {
    if (!(error instanceof NetworkOverrideError)) throw error;
    const file = error.file;
    logger.error?.(`${error.message}. The runtime network override is IGNORED for this start; continuing with the bundle config.`);
    logger.error?.(
      `auth-gate: to fix, correct the JSON/values in ${file} or run \`rm -f '${file}'\` and restart dsh. ` +
        'Until then the listener/publicUrl come from the bundle config and the UI shows source=config.'
    );
    const resolved = await resolveConfig(raw, { ...options, ignoreNetworkOverride: true });
    resolved.networkFallback = { file, reason: error.reason, message: error.message };
    return resolved;
  }
}

/** Config view expected by the gateway. */
export function gatewayConfig(resolved) {
  return {
    listenHost: resolved.listenHost,
    listenPort: resolved.listenPort,
    publicUrl: resolved.publicUrl,
    publicFingerprint: resolved.publicFingerprint ?? '',
    upstream: resolved.upstream,
    upstreamInsecureTls: resolved.upstreamInsecureTls,
    sessionTtlHours: resolved.sessionTtlHours,
    sessionAbsoluteTtlDays: resolved.sessionAbsoluteTtlDays,
    deviceTtlDays: resolved.deviceTtlDays,
    deviceAbsoluteTtlDays: resolved.deviceAbsoluteTtlDays,
    maxDevices: resolved.maxDevices,
    pairTicketTtlSeconds: resolved.pairTicketTtlSeconds,
    loginLock: resolved.loginLock,
    networkSource: resolved.networkSource ?? 'config'
  };
}
