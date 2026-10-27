/**
 * Runtime network overrides (`$stateDir/network.json`).
 *
 * The bundle config (cordis.patch.yml / AUTH_GATE_* environment) is the
 * deployment default. An operator can override the listening address/port, the
 * public origin and (v0.6.2) the external certificate fingerprint from the
 * admin UI; those values are persisted here so they survive a dsh restart and
 * win over the bundle config. Everything else (upstream, TLS material,
 * stateDir, limits) still comes from the bundle.
 *
 * Validation is intentionally as strict as `config.js`: this file decides which
 * interface the front door binds and which authority ends up in pairing QR
 * codes, so an ambiguous value is rejected instead of guessed. Writes are
 * atomic (temp file + fsync + rename) and 0600.
 */

import { constants as fsConstants } from 'node:fs';
import * as fs from 'node:fs/promises';
import { isIP } from 'node:net';
import * as path from 'node:path';
import { randomBytes } from 'node:crypto';

export const NETWORK_FILE = 'network.json';
export const NETWORK_VERSION = 1;

/** Bind-all / unspecified addresses are refused (same rule as config.js). */
const WILDCARD_HOSTS = new Set(['0.0.0.0', '::', '0:0:0:0:0:0:0:0', '[::]', '*']);
/** Canonical (RFC 5952) spellings that `net.Server#address()` may report. */
const CANONICAL_WILDCARDS = new Set(['0.0.0.0', '::', '::ffff:0:0', '::ffff:0.0.0.0']);

/**
 * A network.json read/validation failure. Unlike a plain config error this is
 * recoverable: the plugin logs it, tells the operator how to restore the file
 * and keeps starting with the bundle config (see lib/index.js).
 */
export class NetworkOverrideError extends Error {
  /**
   * @param {string} file
   * @param {string} reason human-readable, never contains secrets
   * @param {unknown} [cause]
   */
  constructor(file, reason, cause = undefined) {
    super(`auth-gate: network override ${file} ${reason}`);
    this.name = 'NetworkOverrideError';
    this.file = file;
    this.reason = reason;
    if (cause !== undefined) this.cause = cause;
  }
}

/**
 * Canonicalize an IP literal so wildcard/loopback detection cannot be fooled by
 * alternative spellings (`::0`, `0::0`, `00::`, `::ffff:0.0.0.0`, expanded
 * `0:0:…` forms). Returns null when the value is not an IP literal.
 * @param {string} host
 * @returns {string|null}
 */
function canonicalIp(host) {
  const family = isIP(host);
  if (family === 0) return null;
  if (family === 4) return host;
  try {
    // WHATWG URL parsing applies RFC 5952 IPv6 serialization to the host.
    const { hostname } = new URL(`http://[${host}]/`);
    return hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : null;
  } catch {
    return null;
  }
}

/**
 * The IPv4 address embedded in an IPv4-mapped IPv6 literal, or null.
 * @param {string} canonical
 * @returns {string|null}
 */
function mappedIpv4(canonical) {
  if (!canonical.startsWith('::ffff:')) return null;
  const parts = canonical.slice('::ffff:'.length).split(':');
  if (parts.length !== 2) return null;
  const hi = Number.parseInt(parts[0], 16);
  const lo = Number.parseInt(parts[1], 16);
  if (!Number.isInteger(hi) || !Number.isInteger(lo) || hi < 0 || hi > 0xffff || lo < 0 || lo > 0xffff) return null;
  return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
}

/**
 * True when the host is any spelling of a bind-all address. Used both by the
 * request validation and after `server.listen()` as a defense-in-depth check of
 * the address the kernel actually reported.
 * @param {unknown} value
 * @returns {boolean}
 */
export function isWildcardListenHost(value) {
  if (typeof value !== 'string') return false;
  const host = value.trim();
  if (WILDCARD_HOSTS.has(host)) return true;
  const canonical = canonicalIp(host);
  if (canonical === null) return false;
  return CANONICAL_WILDCARDS.has(canonical) || CANONICAL_WILDCARDS.has(mappedIpv4(canonical) ?? '');
}

/**
 * True for 127.0.0.0/8, ::1 and IPv4-mapped loopback. The listener refuses
 * these addresses: loopback + a local proxy (frp/nginx) is indistinguishable
 * from a real local administrator, so the automatic loopback admin channel
 * cannot be made safe there.
 * @param {unknown} value
 * @returns {boolean}
 */
export function isLoopbackListenHost(value) {
  if (typeof value !== 'string') return false;
  const host = value.trim();
  if (!host.startsWith('[') && !host.endsWith(']') && isIP(host) === 4) return host.split('.')[0] === '127';
  const canonical = canonicalIp(host);
  if (canonical === null) return false;
  if (canonical === '::1') return true;
  const mapped = mappedIpv4(canonical);
  return mapped !== null && mapped.split('.')[0] === '127';
}

/**
 * A validation failure carrying the API field name, the stable error code and
 * a coarse reason (never echoes the rejected value back to the caller).
 */
export class NetworkValidationError extends Error {
  /**
   * @param {'listenHost'|'listenPort'|'publicUrl'|'publicFingerprint'} field
   * @param {'invalid_listen_host'|'listen_host_loopback_not_allowed'|'invalid_listen_port'|'invalid_public_url'|'invalid_public_fingerprint'} code
   * @param {string} reason
   */
  constructor(field, code, reason) {
    super(`network: ${field} is invalid (${reason})`);
    this.name = 'NetworkValidationError';
    this.field = field;
    this.code = code;
    this.reason = reason;
  }
}

/**
 * A listen host must be a concrete LAN IPv4/IPv6 literal. Hostnames are
 * refused (DNS can change), all spellings of bind-all are refused, and
 * loopback is refused outright: with frp (or any local reverse proxy)
 * forwarding from 127.0.0.1 every public visitor looks like a local
 * administrator, so a loopback listener can never be made safe.
 * @param {unknown} value
 * @returns {string}
 */
export function validateListenHost(value) {
  if (typeof value !== 'string') throw new NetworkValidationError('listenHost', 'invalid_listen_host', 'not_a_string');
  const host = value.trim();
  if (host.length === 0) throw new NetworkValidationError('listenHost', 'invalid_listen_host', 'empty');
  if (host.length > 255) throw new NetworkValidationError('listenHost', 'invalid_listen_host', 'too_long');
  if (host.startsWith('[') || host.endsWith(']')) {
    throw new NetworkValidationError('listenHost', 'invalid_listen_host', 'bracketed');
  }
  if (isIP(host) === 0) throw new NetworkValidationError('listenHost', 'invalid_listen_host', 'not_ip_literal');
  if (isWildcardListenHost(host)) throw new NetworkValidationError('listenHost', 'invalid_listen_host', 'wildcard');
  if (isLoopbackListenHost(host)) {
    throw new NetworkValidationError('listenHost', 'listen_host_loopback_not_allowed', 'loopback');
  }
  return host;
}

/**
 * @param {unknown} value
 * @param {{upstreamPort?:number}} [options]
 * @returns {number}
 */
export function validateListenPort(value, options = {}) {
  const number = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
  if (!Number.isInteger(number) || number < 1 || number > 65535) {
    throw new NetworkValidationError('listenPort', 'invalid_listen_port', 'out_of_range');
  }
  const upstreamPort = Number(options.upstreamPort);
  if (Number.isInteger(upstreamPort) && upstreamPort > 0 && number === upstreamPort) {
    throw new NetworkValidationError('listenPort', 'invalid_listen_port', 'upstream_port');
  }
  return number;
}

/**
 * Validate an external origin used in pairing QR codes and links.
 * Only `http(s)://host[:port]` is accepted: credentials, a path, a query string
 * or a fragment are rejected rather than silently dropped by `URL#origin`, so
 * the value the operator sees is exactly the value that ends up in QR codes.
 * @param {unknown} value
 * @param {{tlsConfigured?:boolean}} [options]
 * @returns {string}
 */
export function validatePublicUrl(value, options = {}) {
  if (typeof value !== 'string') throw new NetworkValidationError('publicUrl', 'invalid_public_url', 'not_a_string');
  const raw = value.trim();
  if (raw.length === 0) throw new NetworkValidationError('publicUrl', 'invalid_public_url', 'empty');
  if (raw.length > 2048) throw new NetworkValidationError('publicUrl', 'invalid_public_url', 'too_long');
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new NetworkValidationError('publicUrl', 'invalid_public_url', 'not_absolute_url');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new NetworkValidationError('publicUrl', 'invalid_public_url', 'not_http_s');
  }
  if (url.username !== '' || url.password !== '') {
    throw new NetworkValidationError('publicUrl', 'invalid_public_url', 'credentials');
  }
  if (url.pathname !== '/' || url.search !== '' || url.hash !== '') {
    throw new NetworkValidationError('publicUrl', 'invalid_public_url', 'path_query_or_fragment');
  }
  if (options.tlsConfigured === true && url.protocol !== 'https:') {
    throw new NetworkValidationError('publicUrl', 'invalid_public_url', 'tls_requires_https');
  }
  if (options.tlsConfigured === false && url.protocol !== 'http:') {
    throw new NetworkValidationError('publicUrl', 'invalid_public_url', 'plain_requires_http');
  }
  return url.origin;
}

/** A certificate DER SHA-256 digest: exactly 64 lower-case hex characters. */
const PUBLIC_FINGERPRINT_PATTERN = /^[0-9a-f]{64}$/u;

/**
 * Validate the *external* TLS certificate fingerprint carried in pairing QR
 * codes (`fp=`).
 *
 * The fingerprint is what the App pins against the certificate it sees on the
 * wire. When TLS terminates in front of the gate (frp + Caddy/nginx), that is
 * the proxy certificate, not the gate's own self-signed one — hence this
 * override. Values:
 *
 *  - `''` — use the gateway's own TLS certificate (default, backwards compat);
 *  - 64 lower-case hex chars — SHA-256 of the public certificate's DER bytes,
 *    upper-case input is normalized, never silently truncated;
 *  - `'auto'` — *POST only*: resolve it by probing the current `publicUrl`
 *    (see `lib/fingerprint.js`). Never persisted, because the certificate can
 *    be renewed at any time.
 *
 * @param {unknown} value
 * @param {{allowAuto?:boolean}} [options]
 * @returns {''|'auto'|string}
 */
export function validatePublicFingerprint(value, options = {}) {
  if (typeof value !== 'string') {
    throw new NetworkValidationError('publicFingerprint', 'invalid_public_fingerprint', 'not_a_string');
  }
  const raw = value.trim().toLowerCase();
  if (raw === '') return '';
  if (raw === 'auto') {
    if (options.allowAuto === true) return 'auto';
    throw new NetworkValidationError('publicFingerprint', 'invalid_public_fingerprint', 'auto_not_allowed_here');
  }
  if (raw.length !== 64 || !PUBLIC_FINGERPRINT_PATTERN.test(raw)) {
    throw new NetworkValidationError('publicFingerprint', 'invalid_public_fingerprint', 'not_hex64');
  }
  return raw;
}

/**
 * Validate the fields that are present. Unknown keys are ignored by the caller.
 * `publicFingerprint: 'auto'` is accepted only with `allowAutoFingerprint`
 * (the POST path, which resolves it before persisting).
 * @param {{listenHost?:unknown,listenPort?:unknown,publicUrl?:unknown,publicFingerprint?:unknown}} input
 * @param {{tlsConfigured?:boolean,upstreamPort?:number,allowAutoFingerprint?:boolean}} [options]
 * @returns {{listenHost?:string,listenPort?:number,publicUrl?:string,publicFingerprint?:string}}
 */
export function validateNetworkSettings(input, options = {}) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('network: settings must be an object');
  }
  /** @type {{listenHost?:string,listenPort?:number,publicUrl?:string,publicFingerprint?:string}} */
  const out = {};
  if (input.listenHost !== undefined) out.listenHost = validateListenHost(input.listenHost);
  if (input.listenPort !== undefined) out.listenPort = validateListenPort(input.listenPort, { upstreamPort: options.upstreamPort });
  if (input.publicUrl !== undefined) out.publicUrl = validatePublicUrl(input.publicUrl, { tlsConfigured: options.tlsConfigured });
  if (input.publicFingerprint !== undefined) {
    out.publicFingerprint = validatePublicFingerprint(input.publicFingerprint, { allowAuto: options.allowAutoFingerprint === true });
  }
  return out;
}

/** @param {string} stateDir */
export function networkFilePath(stateDir) {
  return path.join(stateDir, NETWORK_FILE);
}

/**
 * Read the runtime override. Returns `null` when the file does not exist.
 * A corrupt or invalid file raises a typed `NetworkOverrideError`; callers must
 * not ignore it silently. `resolveConfigWithNetworkFallback()` reports it and
 * continues on the bundle config, while the raw reader stays strict for tests
 * and for callers that want fail-fast. Only the fields present in the file are
 * returned, so a hand-written partial override is possible.
 * @param {string} stateDir
 * @param {{tlsConfigured?:boolean,upstreamPort?:number}} [options]
 * @returns {Promise<null|{listenHost?:string,listenPort?:number,publicUrl?:string,publicFingerprint?:string,updatedAt?:number}>}
 */
export async function readNetworkOverride(stateDir, options = {}) {
  const file = networkFilePath(stateDir);
  let raw;
  try {
    raw = await fs.readFile(file, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw new NetworkOverrideError(file, `cannot be read (${error.code ?? error.message})`, error);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new NetworkOverrideError(file, `is not valid JSON (${error.message})`, error);
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new NetworkOverrideError(file, 'must be a JSON object');
  }
  const known = {};
  for (const key of ['listenHost', 'listenPort', 'publicUrl', 'publicFingerprint']) {
    if (parsed[key] !== undefined) known[key] = parsed[key];
  }
  if (Object.keys(known).length === 0) {
    throw new NetworkOverrideError(file, 'has no listenHost/listenPort/publicUrl');
  }
  let validated;
  try {
    validated = validateNetworkSettings(known, options);
  } catch (error) {
    if (error instanceof NetworkValidationError) {
      throw new NetworkOverrideError(file, `is invalid (${error.reason})`, error);
    }
    throw error;
  }
  if (Number.isFinite(parsed.updatedAt)) validated.updatedAt = parsed.updatedAt;
  // This file is not secret, but it controls the public authority; keep it
  // owner-only like every other file in the state directory.
  try {
    const stat = await fs.stat(file);
    if ((stat.mode & 0o077) !== 0) await fs.chmod(file, 0o600);
  } catch {
    // The read succeeded; a chmod race is not a startup blocker.
  }
  return validated;
}

/**
 * Atomic 0600 write of the effective network settings. An empty
 * `publicFingerprint` is omitted from the file: "no override" and "empty
 * override" mean the same thing (use the gateway's own certificate), so a
 * legacy three-field network.json stays byte-compatible.
 * @param {string} stateDir
 * @param {{listenHost:string,listenPort:number,publicUrl:string,publicFingerprint?:string}} values
 * @param {{now?:() => number}} [options]
 * @returns {Promise<{listenHost:string,listenPort:number,publicUrl:string,publicFingerprint?:string,updatedAt:number}>}
 */
export async function writeNetworkOverride(stateDir, values, options = {}) {
  const now = (options.now ?? Date.now)();
  const publicFingerprint = values.publicFingerprint === undefined ? '' : validatePublicFingerprint(values.publicFingerprint);
  const record = {
    listenHost: validateListenHost(values.listenHost),
    listenPort: validateListenPort(values.listenPort),
    publicUrl: validatePublicUrl(values.publicUrl),
    ...(publicFingerprint === '' ? {} : { publicFingerprint }),
    updatedAt: now
  };
  await fs.mkdir(stateDir, { recursive: true, mode: 0o700 });
  const file = networkFilePath(stateDir);
  const tmp = path.join(stateDir, `.${NETWORK_FILE}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`);
  const json = `${JSON.stringify(record, null, 2)}\n`;
  const handle = await fs.open(tmp, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
  try {
    await handle.writeFile(json, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await fs.rename(tmp, file);
    await fs.chmod(file, 0o600);
    const dirHandle = await fs.open(stateDir, 'r');
    try {
      await dirHandle.sync();
    } finally {
      await dirHandle.close();
    }
  } catch (error) {
    await fs.rm(tmp, { force: true });
    throw error;
  }
  return record;
}
