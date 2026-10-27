/**
 * Front-door HTTPS gateway: authentication routes, admin API, HTTP reverse
 * proxy and WebSocket tunnel to a local dsh.
 *
 * Security invariants:
 *  - the browser only ever holds the gate's own cookies; dsh's launch token and
 *    `dsh-auth-*` cookie stay in this process;
 *  - every proxied request carries an upstream Host/Origin that dsh's fence
 *    accepts, and never the inbound Cookie header;
 *  - upstream `Set-Cookie` headers are stripped;
 *  - per-IP/per-username failure limits and per-IP ticket limits;
 *  - audit records contain coarse reasons only, never secrets.
 */

import { randomBytes } from 'node:crypto';
import * as http from 'node:http';
import * as https from 'node:https';
import { STATUS_CODES } from 'node:http';
import { isIP } from 'node:net';
import * as net from 'node:net';
import * as os from 'node:os';
import * as tls from 'node:tls';
import { certificateFingerprint, pairUrl, qrSvg } from './qr.js';
import { checkPasswordPolicy, hashPassword, verifyPassword } from './password.js';
import { FixedWindowLimiter, LoginLimiter } from './ratelimit.js';
import { safeEqualString } from './store.js';
import { generateSecret, otpauthUri, verifyTotpCounter } from './totp.js';
import { adminPage, loginPage, pairPage, plainPage, setupPage, t } from './pages.js';

export const SESSION_COOKIE = 'dsh_gate_session';
export const DEVICE_COOKIE = 'dsh_gate_device';
export const CSRF_COOKIE = 'dsh_gate_csrf';
export const SESSION_COOKIE_MAX_AGE_SECONDS = 8 * 60 * 60;
export const DEVICE_COOKIE_MAX_AGE_SECONDS = 90 * 24 * 60 * 60;
export const CSRF_COOKIE_MAX_AGE_SECONDS = 8 * 60 * 60;
export const MAX_JSON_BODY_BYTES = 64 * 1024;
export const MAX_BUFFERED_PROXY_BYTES = 8 * 1024 * 1024;
const MAX_DRAIN_BYTES = 64 * 1024 * 1024;
const USERNAME_PATTERN = /^[A-Za-z0-9._-]{1,64}$/u;
const PLATFORM_PATTERN = /^[a-z0-9_-]{1,32}$/u;
/** Fixed LoginLimiter scope used for session-channel currentPassword proofs. */
const CURRENT_PASSWORD_SCOPE = 'admin:current-password';
/** Fixed LoginLimiter scope used for session-channel pairing-TOTP proofs. */
const ADMIN_TOTP_SCOPE = 'admin:totp';

/** Headers that must not be forwarded by a proxy (RFC 7230 §6.1). */
export const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade'
]);

/** HTTP error carrying a machine-readable code for JSON responses. */
export class HttpError extends Error {
  constructor(status, code, message = code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/**
 * @param {string|undefined} address
 * @returns {boolean}
 */
export function isLoopbackAddress(address) {
  if (typeof address !== 'string' || address.length === 0) return false;
  const value = address.startsWith('::ffff:') ? address.slice(7) : address;
  if (value === '::1') return true;
  if (!net.isIP(value)) return false;
  if (net.isIPv4(value)) return value.startsWith('127.');
  return value === '::1';
}

/** @param {http.IncomingMessage} req */
export function clientIp(req) {
  const raw = req.socket?.remoteAddress ?? '';
  return raw.startsWith('::ffff:') ? raw.slice(7) : raw;
}

/**
 * Parse a Cookie header into a plain object (first value wins).
 * @param {string|undefined} header
 * @returns {Record<string,string>}
 */
export function parseCookies(header) {
  /** @type {Record<string,string>} */
  const cookies = {};
  if (typeof header !== 'string' || header.length === 0) return cookies;
  for (const segment of header.split(';')) {
    const at = segment.indexOf('=');
    if (at <= 0) continue;
    const name = segment.slice(0, at).trim();
    if (name.length === 0 || Object.hasOwn(cookies, name)) continue;
    let value = segment.slice(at + 1).trim();
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) value = value.slice(1, -1);
    cookies[name] = value;
  }
  return cookies;
}

/**
 * @param {string} name
 * @param {string} value
 * @param {{secure?:boolean,maxAgeSeconds?:number,httpOnly?:boolean,sameSite?:'Lax'|'Strict'|'None',path?:string}} [options]
 */
export function serializeCookie(name, value, options = {}) {
  const { secure = false, maxAgeSeconds, httpOnly = true, sameSite = 'Lax', path = '/' } = options;
  let out = `${name}=${value}; Path=${path}`;
  if (Number.isFinite(maxAgeSeconds)) out += `; Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`;
  if (httpOnly) out += '; HttpOnly';
  if (sameSite !== undefined) out += `; SameSite=${sameSite}`;
  if (secure) out += '; Secure';
  return out;
}

/**
 * Only same-site absolute paths are valid post-login destinations.
 * @param {unknown} value
 * @param {string} [fallback]
 */
export function sanitizeNext(value, fallback = '/') {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048) return fallback;
  if (!value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return fallback;
  if (/[\u0000-\u001f\u007f]/u.test(value)) return fallback;
  // Never bounce back into the gate's own protocol surfaces, with one safe
  // exception: the admin page itself. A logged-in user who opens /__admin and
  // is redirected to the login page should land back on /__admin afterwards.
  // The page re-checks auth and redirects again if the session is gone, so this
  // cannot loop (the login page only renders when there is no session).
  if (value === '/__auth' || value.startsWith('/__auth/') || value.startsWith('/__admin/')) return fallback;
  if (value === '/__admin') return value;
  return value;
}

/** Tokens named by a Connection header are hop-by-hop too. */
export function connectionTokens(value) {
  if (typeof value !== 'string' || value.length === 0) return [];
  return value
    .split(',')
    .map((token) => token.trim().toLowerCase())
    .filter((token) => token.length > 0);
}

/**
 * Remove Set-Cookie lines from a WebSocket handshake response head. The
 * handshake is tunneled as raw bytes, so this is the only place that can keep
 * an upstream cookie from reaching the browser.
 * @param {string} headText header block without the trailing blank line
 * @returns {string}
 */
export function sanitizeUpgradeResponseHead(headText) {
  const lines = String(headText).split('\r\n');
  const kept = [lines[0]];
  for (const line of lines.slice(1)) {
    if (/^set-cookie\s*:/iu.test(line)) continue;
    kept.push(line);
  }
  return kept.join('\r\n');
}

/**
 * True when the client prefers an HTML document (browser navigation).
 * @param {{headers:Record<string,string|string[]|undefined>}} req
 */
export function isHtmlRequest(req) {
  const accept = req.headers.accept;
  return typeof accept === 'string' && accept.toLowerCase().includes('text/html');
}

/**
 * Build the upstream request headers.
 * @param {Record<string,string|string[]|undefined>} incoming
 * @param {{upstream:{host:string,origin:string},dshCookie?:string}} input
 * @returns {Record<string,string|string[]>}
 */
export function buildUpstreamHeaders(incoming, input) {
  const { upstream, dshCookie } = input;
  /** @type {Record<string,string|string[]>} */
  const headers = {};
  const connectionNamed = new Set(connectionTokens(Array.isArray(incoming.connection) ? incoming.connection[0] : incoming.connection));
  for (const [name, value] of Object.entries(incoming)) {
    if (value === undefined) continue;
    const lower = name.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lower) || connectionNamed.has(lower)) continue;
    if (lower === 'host' || lower === 'cookie' || lower === 'origin') continue;
    if (lower === 'referer') {
      const rewritten = rewriteReferer(Array.isArray(value) ? value[0] : value, upstream);
      if (rewritten !== undefined) headers.referer = rewritten;
      continue;
    }
    if (lower === 'forwarded' || lower.startsWith('x-forwarded-') || lower === 'x-real-ip') continue;
    headers[lower] = value;
  }
  headers.host = upstream.host;
  if (incoming.origin !== undefined) headers.origin = upstream.origin;
  headers['x-forwarded-proto'] = 'https';
  if (typeof dshCookie === 'string' && dshCookie.length > 0) headers.cookie = dshCookie;
  return headers;
}

/**
 * Rewrite a gateway Referer to the upstream origin so dsh's origin checks do
 * not see the front-door authority.
 * @param {string|undefined} referer
 * @param {{host:string,origin:string}} upstream
 */
export function rewriteReferer(referer, upstream) {
  if (typeof referer !== 'string' || referer.length === 0) return undefined;
  try {
    const url = new URL(referer);
    return `${upstream.origin}${url.pathname}${url.search}`;
  } catch {
    return undefined;
  }
}

/**
 * Strip hop-by-hop and cookie-setting headers from an upstream response.
 * @param {Record<string,string|string[]|undefined>} headers
 * @returns {Record<string,string|string[]>}
 */
export function filterResponseHeaders(headers) {
  /** @type {Record<string,string|string[]>} */
  const out = {};
  const connectionValue = headers.connection;
  const connectionNamed = new Set(connectionTokens(Array.isArray(connectionValue) ? connectionValue[0] : connectionValue));
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    const lower = name.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lower) || connectionNamed.has(lower)) continue;
    if (lower === 'set-cookie') continue;
    out[lower] = value;
  }
  return out;
}

/**
 * Make a Location header usable by the browser: an absolute URL that points at
 * dsh becomes origin-relative so it resolves against the gateway.
 * @param {string|undefined} location
 * @param {{origin:string}} upstream
 * @returns {string|undefined}
 */
export function rewriteLocation(location, upstream) {
  if (typeof location !== 'string' || location.length === 0) return location;
  let url;
  try {
    url = new URL(location, `${upstream.origin}/`);
  } catch {
    // Unparseable: never reflect it back to the browser.
    return '/';
  }
  // Only http(s) redirects that resolve to the upstream authority may become
  // origin-relative. Everything else — `//evil.example`, absolute URLs for
  // another host, `javascript:`/`data:` — is neutralised to `/` so the
  // gateway cannot be used as an open redirect.
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return '/';
  if (url.host !== upstream.host) return '/';
  return `${url.pathname}${url.search}${url.hash}`;
}

/**
 * Build the upstream request headers for a WebSocket handshake.
 * @param {Record<string,string|string[]|undefined>} incoming
 * @param {{upstream:{host:string,origin:string},dshCookie?:string}} input
 */
export function buildWebSocketHeaders(incoming, input) {
  const { upstream, dshCookie } = input;
  /** @type {Record<string,string|string[]>} */
  const headers = {};
  for (const [name, value] of Object.entries(incoming)) {
    if (value === undefined) continue;
    const lower = name.toLowerCase();
    if (lower === 'host' || lower === 'cookie' || lower === 'origin') continue;
    if (lower === 'forwarded' || lower.startsWith('x-forwarded-') || lower === 'x-real-ip') continue;
    headers[lower] = value;
  }
  headers.host = upstream.host;
  headers.origin = upstream.origin;
  headers.connection = 'Upgrade';
  headers.upgrade = 'websocket';
  headers['x-forwarded-proto'] = 'https';
  if (typeof dshCookie === 'string' && dshCookie.length > 0) headers.cookie = dshCookie;
  return headers;
}

function isReservedPath(pathname) {
  return pathname === '/__auth' || pathname.startsWith('/__auth/') || pathname === '/__admin' || pathname.startsWith('/__admin/');
}

/**
 * Browser-fetched, non-sensitive files that dsh's built frontend dist serves
 * (see `@deepseek-ai/dsh-host-frontend-static`): the web manifest, favicons and
 * touch icons. Browsers request these without credentials, so requiring a gate
 * session here only produces 401/redirect noise in the Console.
 *
 * This allowlist is exact-match and GET/HEAD-only. `/assets/` is limited to the
 * dist asset directory: dsh serves it from `${distRoot}/assets` with a resolved
 * path that must stay inside the dist root (missing files are 404, traversal is
 * 403), and dsh's dynamic API routes are registered before that fallback, so
 * no `/api/*`, `/plugins/*`, `/__auth/*` or `/__admin*` content is reachable
 * through this exemption.
 */
export const PUBLIC_ASSET_PATHS = new Set([
  '/manifest.webmanifest',
  '/favicon.svg',
  '/favicon-dark.svg',
  '/favicon.ico',
  '/apple-touch-icon.png',
  '/apple-touch-icon-precomposed.png'
]);

/**
 * True when a request may skip the *gateway session* check because it is a
 * read-only public static asset. The request still goes through the reverse
 * proxy (and therefore dsh's own authentication fence); this never relaxes
 * API/plugin/admin routes.
 *
 * @param {string|undefined} method
 * @param {string} pathname
 * @returns {boolean}
 */
export function isPublicAssetRequest(method, pathname) {
  if (method !== 'GET' && method !== 'HEAD') return false;
  if (typeof pathname !== 'string' || !pathname.startsWith('/')) return false;
  if (isReservedPath(pathname)) return false;
  if (PUBLIC_ASSET_PATHS.has(pathname)) return true;
  const prefix = '/assets/';
  if (!pathname.startsWith(prefix) || pathname.length === prefix.length) return false;
  // Defence in depth: dsh already refuses traversal, but never forward an
  // encoded separator/dot segment that could be decoded into a different path.
  if (pathname.includes('\\') || pathname.includes('..') || /%(?:2e|2f|5c)/iu.test(pathname)) return false;
  return true;
}

function isWebSocketUpgrade(req) {
  return (req.headers.upgrade ?? '').toLowerCase() === 'websocket';
}

function sameBrowserOrigin(originHeader, hostHeader, secure) {
  if (typeof originHeader !== 'string' || originHeader.length === 0) return true;
  let origin;
  try {
    origin = new URL(originHeader);
  } catch {
    return false;
  }
  const expectedProtocol = secure ? 'https:' : 'http:';
  if (origin.protocol !== expectedProtocol) return false;
  return origin.host === (hostHeader ?? '');
}

function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > maxBytes) {
      req.resume();
      reject(new HttpError(413, 'payload_too_large'));
      return;
    }
    const chunks = [];
    let total = 0;
    let exceeded = false;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (exceeded) {
        if (total > MAX_DRAIN_BYTES) req.destroy();
        return;
      }
      if (total > maxBytes) {
        exceeded = true;
        chunks.length = 0;
        reject(new HttpError(413, 'payload_too_large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!exceeded) resolve(Buffer.concat(chunks));
    });
    req.on('error', (error) => {
      if (!exceeded) reject(error);
    });
  });
}

/**
 * @typedef {object} GatewayConfig
 * @property {string} listenHost
 * @property {number} listenPort
 * @property {string} publicUrl
 * @property {string} upstream
 * @property {boolean} upstreamInsecureTls
 * @property {number} sessionTtlHours
 * @property {number} deviceTtlDays
 * @property {number} maxDevices
 * @property {number} pairTicketTtlSeconds
 * @property {{maxFailures:number,windowMinutes:number,lockMinutes:number}} loginLock
 */

/**
 * @param {{
 *   config:GatewayConfig,
 *   store:import('./store.js').StateStore,
 *   dshSession:import('./dsh-session.js').DshSessionProvider,
 *   tls?:{cert:Buffer|string,key:Buffer|string}|null,
 *   fingerprint?:string,
 *   hostname?:string,
 *   logger?:{info?:Function,warn?:Function,error?:Function},
 *   now?:()=>number
 * }} options
 */
export function createGateway(options) {
  return new Gateway(options);
}

class Gateway {
  #config;
  #store;
  #dshSession;
  #logger;
  #now;
  #tls;
  #fingerprint;
  #hostname;
  #server;
  #secure;
  #publicUrl;
  #upstream;
  #httpAgent;
  #httpsAgent;
  #sockets = new Set();
  #closed = false;
  #loginLimiter;
  #pairLimiter;
  #renewLimiter;
  #adminPasswordLimiter;
  #qrIssueLimiter;
  #adminHosts;
  #setupBeginLimiter;
  #setupConfirmLimiter;
  /**
   * Single in-memory first-run draft. It is bound to the setup token that was
   * current when `begin` succeeded, never persisted, and discarded on confirm,
   * rotation or process exit. Only the password hash and TOTP secret live here;
   * the plaintext password is never stored.
   * @type {null|{token:string,username:string,passwordHash:string,totpSecretB32:string,createdAt:number}}
   */
  #setupPending = null;

  constructor(options) {
    if (options === null || typeof options !== 'object') throw new TypeError('gateway: options are required');
    const { config, store, dshSession } = options;
    if (config === null || typeof config !== 'object') throw new TypeError('gateway: config is required');
    if (store === undefined || dshSession === undefined) throw new TypeError('gateway: store and dshSession are required');
    this.#config = config;
    this.#store = store;
    this.#dshSession = dshSession;
    this.#logger = options.logger ?? console;
    this.#now = options.now ?? Date.now;
    this.#tls = options.tls ?? null;
    this.#secure = this.#tls !== null;
    this.#publicUrl = config.publicUrl.replace(/\/+$/u, '');
    const upstreamUrl = new URL(config.upstream);
    if (upstreamUrl.protocol !== 'https:' && upstreamUrl.protocol !== 'http:') throw new TypeError('gateway: upstream must be http(s)');
    this.#upstream = {
      protocol: upstreamUrl.protocol,
      hostname: upstreamUrl.hostname.replace(/^\[|\]$/gu, ''),
      port: upstreamUrl.port === '' ? undefined : Number(upstreamUrl.port),
      host: upstreamUrl.host,
      origin: upstreamUrl.origin,
      pathPrefix: upstreamUrl.pathname === '/' ? '' : upstreamUrl.pathname.replace(/\/+$/u, '')
    };
    const fingerprint = options.fingerprint ?? (this.#tls?.cert === undefined ? null : certificateFingerprint(this.#tls.cert));
    this.#fingerprint = fingerprint ?? '';
    this.#hostname = options.hostname ?? os.hostname();
    const listenHostForHost = config.listenHost.includes(':') && !config.listenHost.startsWith('[') ? `[${config.listenHost}]` : config.listenHost;
    const listenPort = config.listenPort;
    // Loopback-level admin access is additionally pinned to authorities that
    // actually belong to this deployment. Without this, DNS rebinding could
    // present Host: attacker.example from a loopback peer and read the admin API.
    this.#adminHosts = new Set(
      [
        new URL(this.#publicUrl).host.toLowerCase(),
        `${listenHostForHost}:${listenPort}`.toLowerCase(),
        `localhost:${listenPort}`,
        `127.0.0.1:${listenPort}`,
        `[::1]:${listenPort}`
      ]
    );
    this.#loginLimiter = new LoginLimiter({
      maxFailures: config.loginLock.maxFailures,
      windowMs: config.loginLock.windowMinutes * 60_000,
      lockMs: config.loginLock.lockMinutes * 60_000,
      now: this.#now
    });
    this.#pairLimiter = new FixedWindowLimiter({ limit: 30, windowMs: 60_000, now: this.#now });
    this.#renewLimiter = new FixedWindowLimiter({ limit: 30, windowMs: 60_000, now: this.#now });
    // The session channel must prove the current password before rotating
    // credentials or minting a pairing ticket. Failed proofs are rate limited
    // per IP so a stolen cookie cannot turn scrypt verification into an
    // online-guessing / CPU-DoS oracle.
    this.#adminPasswordLimiter = new LoginLimiter({
      maxFailures: 5,
      windowMs: 5 * 60_000,
      lockMs: 5 * 60_000,
      now: this.#now
    });
    // Limit actual QR issuance (not merely failed password proofs) per IP.
    this.#qrIssueLimiter = new FixedWindowLimiter({ limit: 10, windowMs: 60_000, now: this.#now });
    // First-run setup is unauthenticated but token-gated. Both steps are
    // limited per IP (10 requests / 5 minutes) so a hostile LAN peer cannot
    // brute-force the 256-bit token or turn scrypt into a CPU oracle.
    this.#setupBeginLimiter = new FixedWindowLimiter({ limit: 10, windowMs: 5 * 60_000, now: this.#now });
    this.#setupConfirmLimiter = new FixedWindowLimiter({ limit: 10, windowMs: 5 * 60_000, now: this.#now });
    this.#httpAgent = new http.Agent({ keepAlive: true, maxSockets: 64 });
    this.#httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 64, rejectUnauthorized: !config.upstreamInsecureTls });
    this.#server = this.#createServer();
  }

  get server() {
    return this.#server;
  }

  get publicUrl() {
    return this.#publicUrl;
  }

  get upstream() {
    return { ...this.#upstream };
  }

  get secure() {
    return this.#secure;
  }

  get fingerprint() {
    return this.#fingerprint;
  }

  /** @returns {Promise<void>} */
  async listen() {
    if (this.#closed) throw new Error('gateway: already closed');
    await new Promise((resolve, reject) => {
      const onError = (error) => {
        this.#server.off('listening', onListening);
        reject(error);
      };
      const onListening = () => {
        this.#server.off('error', onError);
        resolve();
      };
      this.#server.once('error', onError);
      this.#server.once('listening', onListening);
      this.#server.listen(this.#config.listenPort, this.#config.listenHost);
    });
    const address = this.#server.address();
    const bound = typeof address === 'object' && address !== null ? `${address.address}:${address.port}` : String(address);
    this.#logger.info?.(`auth-gate: listening on ${this.#publicUrl} (${bound}), upstream ${this.#upstream.origin}${this.#secure ? '' : ' over PLAIN HTTP — do not expose this listener'}`);
    if (this.#secure && this.#fingerprint === '') this.#logger.warn?.('auth-gate: TLS is enabled but no certificate fingerprint could be computed; pairing QR codes will carry an empty fp');
    if (!this.#secure) this.#logger.warn?.('auth-gate: TLS is not configured; cookies will not carry Secure and the QR fingerprint is empty. Configure tlsCert/tlsKey for production.');
    // The one-time setup link is printed exactly here (and only while the gate
    // has no user). It is intentionally the only log line carrying the token;
    // the same secret also lives in the 0600 setup.token file for operators
    // who cannot read journald.
    if (!this.#store.configured && typeof this.#store.setupToken === 'string' && this.#store.setupToken.length > 0) {
      this.#logger.info?.(
        `auth-gate: setup required — open ${this.#publicUrl}/__admin#setup=${this.#store.setupToken}（也可从 ${this.#store.setupTokenPath} 读取）`
      );
    }
  }

  async close() {
    if (this.#closed) return;
    this.#closed = true;
    this.#loginLimiter.reset();
    this.#pairLimiter.reset();
    this.#renewLimiter.reset();
    this.#adminPasswordLimiter.reset();
    this.#qrIssueLimiter.reset();
    this.#setupBeginLimiter.reset();
    this.#setupConfirmLimiter.reset();
    this.#setupPending = null;
    for (const socket of this.#sockets) socket.destroy();
    this.#sockets.clear();
    this.#httpAgent.destroy();
    this.#httpsAgent.destroy();
    await new Promise((resolve) => {
      try {
        this.#server.close(() => resolve());
      } catch {
        resolve();
      }
    });
    await this.#store.close();
  }

  // --------------------------------------------------------------- server

  #createServer() {
    const handler = (req, res) => {
      res.setHeader('x-content-type-options', 'nosniff');
      if (this.#secure) res.setHeader('strict-transport-security', 'max-age=31536000');
      this.#dispatch(req, res).catch((error) => {
        this.#logger.error?.(`auth-gate: request handler failed: ${error?.message ?? error}`);
        if (res.headersSent) {
          res.destroy();
          return;
        }
        this.#sendJson(res, 500, { error: 'internal' });
      });
    };
    const server = this.#secure
      ? https.createServer({ key: this.#tls.key, cert: this.#tls.cert, minVersion: 'TLSv1.2' }, handler)
      : http.createServer(handler);
    server.on('connection', (socket) => {
      this.#sockets.add(socket);
      socket.on('close', () => this.#sockets.delete(socket));
    });
    server.on('clientError', (_error, socket) => {
      if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      else socket.destroy();
    });
    server.on('upgrade', (req, socket, head) => {
      this.#handleUpgrade(req, socket, head).catch((error) => {
        this.#logger.error?.(`auth-gate: upgrade handler failed: ${error?.message ?? error}`);
        this.#rejectUpgrade(socket, 500, 'internal');
      });
    });
    return server;
  }

  async #dispatch(req, res) {
    let url;
    try {
      url = new URL(req.url ?? '/', 'https://gateway.invalid');
    } catch {
      this.#sendJson(res, 400, { error: 'bad_request' });
      return;
    }
    if (req.method === 'CONNECT' || req.method === 'TRACE') {
      this.#sendJson(res, 405, { error: 'method_not_allowed' }, { allow: 'GET, HEAD, POST' });
      return;
    }
    try {
      if (url.pathname === '/__auth' || url.pathname.startsWith('/__auth/')) await this.#handleAuth(req, res, url);
      else if (url.pathname === '/__admin' || url.pathname.startsWith('/__admin/')) await this.#handleAdmin(req, res, url);
      else await this.#handleProxy(req, res, url);
    } catch (error) {
      if (error instanceof HttpError) {
        if (res.headersSent) {
          res.destroy();
          return;
        }
        const extra = {};
        if (error.status === 405) extra.allow = 'GET, POST';
        if (error.status === 429) extra['retry-after'] = '60';
        this.#sendJson(res, error.status, { error: error.code }, extra);
        return;
      }
      throw error;
    }
  }

  // ---------------------------------------------------------------- auth

  async #handleAuth(req, res, url) {
    const path = url.pathname;
    const method = req.method ?? 'GET';
    switch (path) {
      case '/__auth/login':
        if (method === 'GET' || method === 'HEAD') return this.#loginPage(req, res, url);
        if (method === 'POST') return this.#login(req, res);
        throw new HttpError(405, 'method_not_allowed');
      case '/__auth/csrf':
        if (method !== 'GET' && method !== 'HEAD') throw new HttpError(405, 'method_not_allowed');
        return this.#sendCsrf(req, res);
      case '/__auth/pair':
        if (method !== 'GET' && method !== 'HEAD') throw new HttpError(405, 'method_not_allowed');
        return this.#pairLanding(req, res);
      case '/__auth/pair/redeem':
        if (method !== 'POST') throw new HttpError(405, 'method_not_allowed');
        return this.#pairRedeem(req, res);
      case '/__auth/renew':
        if (method !== 'POST') throw new HttpError(405, 'method_not_allowed');
        return this.#renew(req, res);
      case '/__auth/logout':
        if (method !== 'POST') throw new HttpError(405, 'method_not_allowed');
        return this.#logout(req, res);
      case '/__auth/whoami':
        if (method !== 'GET' && method !== 'HEAD') throw new HttpError(405, 'method_not_allowed');
        return this.#whoami(req, res);
      default:
        throw new HttpError(404, 'not_found');
    }
  }

  #nonce() {
    return randomBytes(16).toString('base64url');
  }

  /**
   * Security headers shared by every server-rendered page.
   *
   * `embed` is set only for `/__admin?embed=1`, which the dsh Web GUI renders
   * in a same-origin iframe. Same-origin framing needs `frame-ancestors 'self'`
   * and `X-Frame-Options: SAMEORIGIN`; every other page keeps the stricter
   * `'none'`/`DENY` pair so it can never be framed.
   * @param {string} nonce
   * @param {{embed?:boolean}} [options]
   */
  #pageHeaders(nonce, { embed = false } = {}) {
    return {
      'cache-control': 'no-store',
      'content-type': 'text/html; charset=utf-8',
      'referrer-policy': 'no-referrer',
      'x-frame-options': embed ? 'SAMEORIGIN' : 'DENY',
      'content-security-policy': `default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors ${embed ? "'self'" : "'none'"}; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'`
    };
  }

  #sendHtml(res, status, html, nonce, extra = {}, options = {}) {
    const body = Buffer.from(html, 'utf8');
    res.writeHead(status, {
      ...this.#pageHeaders(nonce, options),
      'content-length': body.length,
      ...extra
    });
    res.end(body);
  }

  #sendPlain(res, status, title, message) {
    const nonce = this.#nonce();
    this.#sendHtml(res, status, plainPage(title, message), nonce);
  }

  #sendJson(res, status, payload, extra = {}) {
    const body = Buffer.from(JSON.stringify(payload), 'utf8');
    res.writeHead(status, {
      'cache-control': 'no-store',
      'content-type': 'application/json; charset=utf-8',
      'content-length': body.length,
      'x-content-type-options': 'nosniff',
      ...extra
    });
    res.end(body);
  }

  #cookieOptions(maxAgeSeconds) {
    return { secure: this.#secure, maxAgeSeconds, httpOnly: true, sameSite: 'Lax', path: '/' };
  }

  #appendSetCookie(res, cookie) {
    const existing = res.getHeader('set-cookie');
    if (existing === undefined) res.setHeader('set-cookie', [cookie]);
    else res.setHeader('set-cookie', [...(Array.isArray(existing) ? existing : [String(existing)]), cookie]);
  }

  #csrfToken(req) {
    const cookies = parseCookies(req.headers.cookie);
    const value = cookies[CSRF_COOKIE];
    return typeof value === 'string' && /^[A-Za-z0-9_-]{16,128}$/u.test(value) ? value : null;
  }

  #ensureCsrf(req, res) {
    let token = this.#csrfToken(req);
    if (token === null) {
      token = randomBytes(32).toString('base64url');
    }
    this.#appendSetCookie(res, serializeCookie(CSRF_COOKIE, token, this.#cookieOptions(CSRF_COOKIE_MAX_AGE_SECONDS)));
    return token;
  }

  #verifyCsrf(req) {
    const cookie = this.#csrfToken(req);
    const header = req.headers['x-auth-gate-csrf'];
    if (cookie === null || typeof header !== 'string' || header.length === 0) return false;
    return safeEqualString(header, cookie);
  }

  async #loginPage(req, res, url) {
    const session = await this.#sessionFromRequest(req);
    const next = sanitizeNext(url.searchParams.get('next'));
    if (session !== null) {
      res.writeHead(302, { location: next, 'cache-control': 'no-store' });
      res.end();
      return;
    }
    const csrf = this.#ensureCsrf(req, res);
    const nonce = this.#nonce();
    this.#sendHtml(
      res,
      200,
      loginPage({
        csrf,
        next,
        configured: this.#store.configured,
        nonce,
        loopback: isLoopbackAddress(clientIp(req))
      }),
      nonce
    );
  }

  async #readJson(req, maxBytes = MAX_JSON_BODY_BYTES) {
    const contentType = String(req.headers['content-type'] ?? '').toLowerCase();
    if (!contentType.includes('application/json')) throw new HttpError(415, 'unsupported_media_type');
    const raw = await readBody(req, maxBytes);
    if (raw.length === 0) return {};
    let parsed;
    try {
      parsed = JSON.parse(raw.toString('utf8'));
    } catch {
      throw new HttpError(400, 'bad_request');
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new HttpError(400, 'bad_request');
    return parsed;
  }

  async #deviceFromToken(tokenValue) {
    if (typeof tokenValue !== 'string' || tokenValue.length === 0) return null;
    const device = await this.#store.findDeviceByToken(tokenValue);
    if (device === null) return null;
    if (device.expiresAt <= this.#now()) return null;
    if (device.origin !== this.#publicUrl) return null;
    return device;
  }

  async #deviceFromCookie(req) {
    const cookies = parseCookies(req.headers.cookie);
    return this.#deviceFromToken(cookies[DEVICE_COOKIE]);
  }

  #rateLimited(res, retryAfterSeconds) {
    this.#sendJson(res, 429, { error: 'rate_limited' }, { 'retry-after': String(Math.max(1, retryAfterSeconds)) });
  }

  async #login(req, res) {
    const ip = clientIp(req);
    const body = await this.#readJson(req, MAX_JSON_BODY_BYTES);
    if (!this.#verifyCsrf(req)) {
      this.#store.recordAudit({ type: 'login_fail', ip, detail: 'csrf_invalid' });
      this.#sendJson(res, 403, { error: 'csrf_invalid' });
      return;
    }
    const username = typeof body.username === 'string' ? body.username.trim() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    if (username.length === 0 || username.length > 64 || password.length === 0 || password.length > 512) {
      this.#sendJson(res, 400, { error: 'bad_request' });
      return;
    }
    const lock = this.#loginLimiter.check(ip, username);
    if (!lock.allowed) {
      this.#rateLimited(res, lock.retryAfterSeconds);
      return;
    }
    if (!this.#store.configured) {
      this.#sendJson(res, 401, { error: 'not_configured' });
      return;
    }
    const device = await this.#deviceFromCookie(req);
    if (device === null) {
      this.#store.recordAudit({ type: 'login_fail', ip, detail: 'device_required' });
      this.#sendJson(res, 401, { error: 'device_required' });
      return;
    }
    const user = this.#store.user;
    const passwordOk = await verifyPassword(password, user.passwordHash);
    if (username !== user.username || !passwordOk) {
      const failure = this.#loginLimiter.fail(ip, username);
      this.#store.recordAudit({ type: 'login_fail', ip, deviceId: device.id, detail: 'invalid_credentials' });
      if (failure.locked) {
        this.#rateLimited(res, failure.retryAfterSeconds);
        return;
      }
      this.#sendJson(res, 401, { error: 'invalid_credentials' });
      return;
    }
    // Device pairing is the second factor in v0.4.0: a valid `dsh_gate_device`
    // cookie proves the device was bound by a TOTP-authorised pairing, so the
    // password alone completes login here. TOTP is *not* part of this request.
    this.#loginLimiter.succeed(ip, username);
    const session = await this.#store.createSession({ deviceId: device.id, ttlMs: this.#config.sessionTtlHours * 3_600_000 });
    this.#appendSetCookie(
      res,
      serializeCookie(SESSION_COOKIE, session.token, this.#cookieOptions(this.#config.sessionTtlHours * 3600))
    );
    this.#store.recordAudit({ type: 'login_ok', ip, deviceId: device.id, detail: 'password' });
    this.#sendJson(res, 200, { ok: true, user: { username: user.username }, expiresAt: session.session.expiresAt });
  }

  async #sendCsrf(req, res) {
    const token = this.#ensureCsrf(req, res);
    this.#sendJson(res, 200, { csrf: token });
  }

  async #pairLanding(req, res) {
    const nonce = this.#nonce();
    this.#ensureCsrf(req, res);
    this.#sendHtml(res, 200, pairPage({ nonce }), nonce);
  }

  async #pairRedeem(req, res) {
    const ip = clientIp(req);
    const limit = this.#pairLimiter.hit(`pair:${ip}`);
    if (!limit.allowed) {
      this.#rateLimited(res, limit.retryAfterSeconds);
      return;
    }
    const body = await this.#readJson(req, 8 * 1024);
    const ticket = typeof body.ticket === 'string' ? body.ticket : '';
    if (ticket.length < 8 || ticket.length > 200) {
      this.#sendJson(res, 401, { error: 'invalid_ticket' });
      return;
    }
    const name = sanitizeDeviceName(body.deviceName);
    const platform = typeof body.platform === 'string' && PLATFORM_PATTERN.test(body.platform.toLowerCase()) ? body.platform.toLowerCase() : 'unknown';
    const result = await this.#store.redeemTicket(ticket, {
      maxDevices: this.#config.maxDevices,
      deviceTtlMs: this.#config.deviceTtlDays * 86_400_000,
      name,
      platform,
      origin: this.#publicUrl
    });
    if (result.status !== 'ok') {
      this.#store.recordAudit({ type: 'pair_redeem', ip, detail: result.status });
      this.#sendJson(res, 401, { error: result.status });
      return;
    }
    this.#appendSetCookie(
      res,
      serializeCookie(DEVICE_COOKIE, result.token, this.#cookieOptions(this.#config.deviceTtlDays * 86_400))
    );
    this.#store.recordAudit({ type: 'pair_redeem', ip, deviceId: result.device.id, detail: 'ok' });
    this.#sendJson(res, 200, {
      deviceToken: result.token,
      deviceId: result.device.id,
      instanceId: this.#store.instanceId,
      expiresAt: result.device.expiresAt
    });
  }

  async #renew(req, res) {
    const ip = clientIp(req);
    const limit = this.#renewLimiter.hit(`renew:${ip}`);
    if (!limit.allowed) {
      this.#rateLimited(res, limit.retryAfterSeconds);
      return;
    }
    // Renewal is a bearer-credential exchange: the long-lived device token MUST
    // come from the JSON body. The old "fall back to the dsh_gate_device cookie"
    // path turned a cross-site cookie into a passwordless session grant, so it
    // is gone. A requests without a JSON body is simply unauthenticated.
    const contentType = String(req.headers['content-type'] ?? '').toLowerCase();
    const body = contentType.includes('application/json') ? await this.#readJson(req, 8 * 1024) : {};
    const token = typeof body.deviceToken === 'string' ? body.deviceToken.trim() : '';
    if (token.length === 0) {
      this.#store.recordAudit({ type: 'login_fail', ip, detail: 'device_required' });
      this.#sendJson(res, 401, { error: 'device_required' });
      return;
    }
    const device = await this.#deviceFromToken(token);
    if (device === null) {
      this.#store.recordAudit({ type: 'login_fail', ip, detail: 'device_required' });
      this.#sendJson(res, 401, { error: 'device_required' });
      return;
    }
    const session = await this.#store.createSession({ deviceId: device.id, ttlMs: this.#config.sessionTtlHours * 3_600_000 });
    this.#appendSetCookie(
      res,
      serializeCookie(SESSION_COOKIE, session.token, this.#cookieOptions(this.#config.sessionTtlHours * 3600))
    );
    this.#store.recordAudit({ type: 'login_ok', ip, deviceId: device.id, detail: 'renew' });
    this.#sendJson(res, 200, { ok: true, deviceId: device.id, expiresAt: session.session.expiresAt });
  }

  async #logout(req, res) {
    const cookies = parseCookies(req.headers.cookie);
    const token = cookies[SESSION_COOKIE];
    if (typeof token === 'string' && token.length > 0) await this.#store.deleteSession(token);
    this.#appendSetCookie(res, serializeCookie(SESSION_COOKIE, '', { ...this.#cookieOptions(0), httpOnly: true }));
    this.#store.recordAudit({ type: 'logout', ip: clientIp(req) });
    this.#sendJson(res, 200, { ok: true });
  }

  async #whoami(req, res) {
    const session = await this.#sessionFromRequest(req);
    if (session === null) {
      this.#sendJson(res, 200, { authenticated: false });
      return;
    }
    this.#sendJson(res, 200, {
      authenticated: true,
      user: this.#store.user === null ? null : { username: this.#store.user.username },
      device: { id: session.device.id, name: session.device.name, platform: session.device.platform },
      expiresAt: session.session.expiresAt
    });
  }

  async #sessionFromRequest(req) {
    const cookies = parseCookies(req.headers.cookie);
    const token = cookies[SESSION_COOKIE];
    if (typeof token !== 'string' || token.length === 0) return null;
    const session = await this.#store.findSession(token);
    if (session === null) return null;
    const device = await this.#store.findDeviceById(session.deviceId);
    if (device === null || device.expiresAt <= this.#now()) {
      await this.#store.deleteSession(token);
      return null;
    }
    return { session, device, token };
  }

  // --------------------------------------------------------------- admin

  /**
   * Admin access has three channels, checked in this order:
   *  - `key`: the `x-auth-gate-admin-key` bearer header (scripting escape hatch);
   *  - `loopback`: a TCP peer on 127.0.0.0/8 or ::1, pinned to a known Host;
   *  - `session`: a valid, unexpired `dsh_gate_session` cookie from a paired
   *    device (the WebUI path).
   * The session channel never weakens `/__auth/*` or the reverse proxy: it only
   * unlocks `/__admin*`; every mutating call needs CSRF, credential rotation
   * additionally needs `currentPassword`, and pairing-ticket minting needs a
   * fresh 6-digit TOTP code.
   * @param {import('node:http').IncomingMessage} req
   * @returns {Promise<{channel:'key'|'loopback'|'session',session:null|{session:object,device:object,token:string}}|null>}
   */
  async #authorizeAdmin(req) {
    const header = req.headers['x-auth-gate-admin-key'];
    if (typeof header === 'string' && this.#store.adminKeyMatches(header)) return { channel: 'key', session: null };
    if (isLoopbackAddress(clientIp(req)) && this.#isAdminHost(req.headers.host)) return { channel: 'loopback', session: null };
    const session = await this.#sessionFromRequest(req);
    if (session !== null) return { channel: 'session', session };
    return null;
  }

  #isAdminHost(hostHeader) {
    return typeof hostHeader === 'string' && this.#adminHosts.has(hostHeader.toLowerCase());
  }

  async #handleAdmin(req, res, url) {
    const path = url.pathname;
    const method = req.method ?? 'GET';
    if (path.startsWith('/__admin/api/setup/')) {
      await this.#handleSetupApi(req, res, url);
      return;
    }
    if (!this.#store.configured && path === '/__admin') {
      // Before the first user exists /__admin *is* the setup wizard. It is
      // public by design (the token is the credential), never framable, and
      // stops being reachable as soon as `configured` flips.
      if (method !== 'GET' && method !== 'HEAD') throw new HttpError(405, 'method_not_allowed');
      const nonce = this.#nonce();
      this.#sendHtml(res, 200, setupPage({ nonce }), nonce);
      return;
    }
    const auth = await this.#authorizeAdmin(req);
    const currentSessionId = auth?.session?.session.id ?? null;
    if (auth === null) {
      if (path === '/__admin' && isHtmlRequest(req)) {
        // A human who is not logged in gets the login page, not a dead 403.
        // `next=/__admin` is honoured by sanitizeNext only for the exact page.
        res.writeHead(302, { location: '/__auth/login?next=/__admin', 'cache-control': 'no-store' });
        res.end();
      } else {
        this.#sendJson(res, 403, { error: 'forbidden' });
      }
      return;
    }
    if (path === '/__admin') {
      if (method !== 'GET' && method !== 'HEAD') throw new HttpError(405, 'method_not_allowed');
      const csrf = this.#ensureCsrf(req, res);
      const nonce = this.#nonce();
      const state = this.#store.publicState({ currentSessionId });
      // `embed=1` is the dsh Web GUI's same-origin sidebar mode: compact chrome
      // plus `frame-ancestors 'self'`. It changes presentation and framing
      // headers only — the auth channels, CSRF and APIs are identical.
      const embed = url.searchParams.get('embed') === '1';
      const html = adminPage({
        state,
        csrf,
        nonce,
        audit: this.#store.auditTail(100),
        serverTime: this.#now(),
        channel: auth.channel,
        requiresCurrentPassword: auth.channel === 'session',
        requiresPairingTotp: auth.channel === 'session',
        pairTicketTtlSeconds: this.#config.pairTicketTtlSeconds,
        embed
      });
      this.#sendHtml(res, 200, html, nonce, {}, { embed });
      return;
    }
    if (!path.startsWith('/__admin/api/')) throw new HttpError(404, 'not_found');
    if (path === '/__admin/api/admin-key') {
      if (method !== 'GET') throw new HttpError(405, 'method_not_allowed');
      if (auth.channel !== 'loopback') {
        this.#sendJson(res, 403, { error: 'loopback_only' });
        return;
      }
      this.#sendJson(res, 200, { adminKey: this.#store.adminKey });
      return;
    }
    const mutating = method === 'POST';
    if (!mutating && method !== 'GET') throw new HttpError(405, 'method_not_allowed');
    // adminKey is a bearer credential in a header: it cannot be sent by a
    // cross-site page, so it is exempt from double-submit CSRF. Loopback and
    // session channels are cookie-authenticated and must present CSRF.
    if (mutating && auth.channel !== 'key' && !this.#verifyCsrf(req)) {
      this.#sendJson(res, 403, { error: 'csrf_invalid' });
      return;
    }
    switch (path) {
      case '/__admin/api/state':
        if (mutating) throw new HttpError(405, 'method_not_allowed');
        this.#sendJson(res, 200, this.#store.publicState({ currentSessionId }));
        return;
      case '/__admin/api/sessions':
        if (mutating) throw new HttpError(405, 'method_not_allowed');
        this.#sendJson(res, 200, this.#store.publicSessions({ currentSessionId }));
        return;
      case '/__admin/api/bootstrap':
        if (!mutating) throw new HttpError(405, 'method_not_allowed');
        if (auth.channel === 'session') {
          // A session can only exist after bootstrap; keep this route limited to
          // the explicit local/bearer channels anyway.
          this.#sendJson(res, 403, { error: 'forbidden' });
          return;
        }
        await this.#adminBootstrap(req, res);
        return;
      case '/__admin/api/user':
        if (!mutating) throw new HttpError(405, 'method_not_allowed');
        await this.#adminUser(req, res, auth);
        return;
      case '/__admin/api/qr':
        if (!mutating) throw new HttpError(405, 'method_not_allowed');
        await this.#adminQr(req, res, auth);
        return;
      case '/__admin/api/devices/revoke':
        if (!mutating) throw new HttpError(405, 'method_not_allowed');
        await this.#adminRevoke(req, res, auth);
        return;
      case '/__admin/api/audit':
        if (mutating) throw new HttpError(405, 'method_not_allowed');
        this.#sendJson(res, 200, { audit: this.#store.auditTail(100) });
        return;
      default:
        throw new HttpError(404, 'not_found');
    }
  }

  /**
   * Defence in depth for the session channel: a stolen session cookie must not
   * be enough to rotate credentials. Loopback/adminKey callers are already
   * trusted by network position/bearer secret and may omit `currentPassword`.
   *
   * Failed proofs are counted per IP: 5 failures inside 5 minutes lock the
   * session channel's currentPassword checks for 5 minutes (429). A single
   * success clears the counter.
   * @param {Record<string,unknown>} body
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:http').ServerResponse} res
   * @param {{channel:string}} auth
   * @returns {Promise<boolean>} true when the request may proceed
   */
  async #verifyCurrentPasswordForAdmin(body, req, res, auth) {
    if (auth.channel !== 'session') return true;
    const ip = clientIp(req);
    const lock = this.#adminPasswordLimiter.check(ip, CURRENT_PASSWORD_SCOPE);
    if (!lock.allowed) {
      this.#store.recordAudit({ type: 'admin_denied', ip, detail: 'current_password_rate_limited' });
      this.#rateLimited(res, lock.retryAfterSeconds);
      return false;
    }
    const current = typeof body.currentPassword === 'string' ? body.currentPassword : '';
    let valid = false;
    let reason = 'current_password_required';
    if (current.length > 0 && current.length <= 512) {
      const user = this.#store.user;
      valid = user !== null && (await verifyPassword(current, user.passwordHash));
      reason = valid ? '' : 'current_password_invalid';
    }
    if (!valid) {
      const failure = this.#adminPasswordLimiter.fail(ip, CURRENT_PASSWORD_SCOPE);
      this.#store.recordAudit({ type: 'admin_denied', ip, detail: reason });
      if (failure.locked) this.#rateLimited(res, failure.retryAfterSeconds);
      else this.#sendJson(res, 403, { error: 'invalid_current_password' });
      return false;
    }
    this.#adminPasswordLimiter.succeed(ip, CURRENT_PASSWORD_SCOPE);
    return true;
  }

  /**
   * Pairing-ticket minting from a WebUI session requires a fresh TOTP code:
   * the second factor authorises the device binding itself, not every login.
   * The code is only *verified*, never consumed, so the same 30s window can
   * mint (or re-mint) several QR codes; actual issuance stays capped by
   * `#qrIssueLimiter`. Failures are counted per IP on their own scope: 5
   * failures inside 5 minutes lock the check for 5 minutes (429).
   * @param {Record<string,unknown>} body
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:http').ServerResponse} res
   * @param {{channel:string}} auth
   * @returns {Promise<boolean>} true when the request may proceed
   */
  async #verifyPairingTotpForAdmin(body, req, res, auth) {
    if (auth.channel !== 'session') return true;
    const ip = clientIp(req);
    const lock = this.#adminPasswordLimiter.check(ip, ADMIN_TOTP_SCOPE);
    if (!lock.allowed) {
      this.#store.recordAudit({ type: 'admin_denied', ip, detail: 'pairing_totp_rate_limited' });
      this.#rateLimited(res, lock.retryAfterSeconds);
      return false;
    }
    const code = typeof body.totp === 'string' ? body.totp.trim() : '';
    let valid = false;
    let reason = 'totp_required';
    if (code.length > 0) {
      const user = this.#store.user;
      try {
        // Verification only: never call `consumeTotpCounter` here. Pairing
        // authorisation must not burn the login replay counter, so the same
        // 30s window can issue several QR codes.
        valid = user !== null && verifyTotpCounter(user.totpSecretB32, code, { now: this.#now() }) >= 0;
      } catch {
        valid = false;
      }
      reason = valid ? '' : 'totp_invalid';
    }
    if (!valid) {
      const failure = this.#adminPasswordLimiter.fail(ip, ADMIN_TOTP_SCOPE);
      this.#store.recordAudit({ type: 'admin_denied', ip, detail: reason });
      if (failure.locked) this.#rateLimited(res, failure.retryAfterSeconds);
      else this.#sendJson(res, 403, { error: reason });
      return false;
    }
    this.#adminPasswordLimiter.succeed(ip, ADMIN_TOTP_SCOPE);
    // TOTP is no longer proven at login; record the confirmation here so the
    // admin status badge reflects a real proof of the authenticator.
    await this.#store.confirmTotp(this.#now());
    return true;
  }

  // ------------------------------------------------------------- setup API

  /**
   * First-run WebUI setup routes. They exist only while the gate is
   * unconfigured: `status` stays readable afterwards (the sidebar panel needs
   * it to choose its screen), every write returns 409 `already_configured`.
   * `begin`/`confirm` are public but token-gated; `token` requires the
   * adminKey/loopback channels.
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:http').ServerResponse} res
   * @param {URL} url
   */
  async #handleSetupApi(req, res, url) {
    const path = url.pathname;
    const method = req.method ?? 'GET';
    if (path === '/__admin/api/setup/status') {
      if (method !== 'GET' && method !== 'HEAD') throw new HttpError(405, 'method_not_allowed');
      // Never echo the token or the pending draft. `hasToken` only tells a
      // client whether a usable setup token exists on disk.
      this.#sendJson(res, 200, {
        configured: this.#store.configured,
        hasToken: !this.#store.configured && typeof this.#store.setupToken === 'string' && this.#store.setupToken.length > 0,
        setupPath: '/__admin'
      });
      return;
    }
    if (this.#store.configured) {
      this.#sendJson(res, 409, { error: 'already_configured' });
      return;
    }
    if (path === '/__admin/api/setup/begin') {
      if (method !== 'POST') throw new HttpError(405, 'method_not_allowed');
      await this.#setupBegin(req, res);
      return;
    }
    if (path === '/__admin/api/setup/confirm') {
      if (method !== 'POST') throw new HttpError(405, 'method_not_allowed');
      await this.#setupConfirm(req, res);
      return;
    }
    if (path === '/__admin/api/setup/token') {
      if (method !== 'POST') throw new HttpError(405, 'method_not_allowed');
      await this.#setupRotateToken(req, res);
      return;
    }
    throw new HttpError(404, 'not_found');
  }

  /**
   * Same-origin check for the two unauthenticated POSTs. Browsers always send
   * Origin on cross-site JSON POSTs; a missing Origin (curl, tests) is allowed
   * deliberately so the documented CLI fallback keeps working. When Origin is
   * present it must match this gateway's authority exactly.
   */
  #setupOriginAllowed(req, res, detail) {
    if (sameBrowserOrigin(req.headers.origin, req.headers.host, this.#secure)) return true;
    this.#store.recordAudit({ type: 'admin_denied', ip: clientIp(req), detail: `${detail}_bad_origin` });
    this.#sendJson(res, 403, { error: 'forbidden_origin' });
    return false;
  }

  async #setupBegin(req, res) {
    const ip = clientIp(req);
    const limit = this.#setupBeginLimiter.hit(ip);
    if (!limit.allowed) {
      this.#store.recordAudit({ type: 'admin_denied', ip, detail: 'setup_begin_rate_limited' });
      this.#rateLimited(res, limit.retryAfterSeconds);
      return;
    }
    if (!this.#setupOriginAllowed(req, res, 'setup_begin')) return;
    const body = await this.#readJson(req, 8 * 1024);
    const token = typeof body.token === 'string' ? body.token.trim() : '';
    const currentToken = this.#store.setupToken;
    // Constant-time comparison. The setup token is the only credential here.
    if (!safeEqualString(token, currentToken)) {
      this.#store.recordAudit({ type: 'admin_denied', ip, detail: 'setup_token_invalid' });
      this.#sendJson(res, 403, { error: 'setup_token_invalid' });
      return;
    }
    const username = typeof body.username === 'string' ? body.username.trim() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    if (!USERNAME_PATTERN.test(username)) {
      this.#store.recordAudit({ type: 'admin_denied', ip, detail: 'setup_invalid_username' });
      this.#sendJson(res, 400, { error: 'invalid_username' });
      return;
    }
    const policy = checkPasswordPolicy(password);
    if (!policy.ok) {
      this.#store.recordAudit({ type: 'admin_denied', ip, detail: 'setup_weak_password' });
      this.#sendJson(res, 400, { error: 'weak_password' });
      return;
    }
    // Deliberately do NOT create the user yet: a refresh/abandoned wizard must
    // not leave a half-initialized gate. The draft is memory-only and tied to
    // the token that is current right now.
    const pending = {
      token: currentToken,
      username,
      passwordHash: await hashPassword(password),
      totpSecretB32: generateSecret(),
      createdAt: this.#now()
    };
    // Repeated begin calls replace the draft (new secret). The wizard always
    // displays the response of the latest call, so this is not observable as a
    // stale QR code.
    this.#setupPending = pending;
    this.#store.recordAudit({ type: 'admin_change', ip, detail: 'setup_begin' });
    const uri = otpauthUri({ account: username, secret: pending.totpSecretB32 });
    this.#sendJson(res, 200, {
      ok: true,
      username,
      otpauthUri: uri,
      secretB32: pending.totpSecretB32,
      qrSvg: await qrSvg(uri)
    });
  }

  async #setupConfirm(req, res) {
    const ip = clientIp(req);
    const limit = this.#setupConfirmLimiter.hit(ip);
    if (!limit.allowed) {
      this.#store.recordAudit({ type: 'admin_denied', ip, detail: 'setup_confirm_rate_limited' });
      this.#rateLimited(res, limit.retryAfterSeconds);
      return;
    }
    if (!this.#setupOriginAllowed(req, res, 'setup_confirm')) return;
    const body = await this.#readJson(req, 8 * 1024);
    const token = typeof body.token === 'string' ? body.token.trim() : '';
    const pending = this.#setupPending;
    const currentToken = this.#store.setupToken;
    // The draft must belong to the token that is current *now*: rotating the
    // token invalidates an in-flight wizard.
    if (
      pending === null ||
      !safeEqualString(token, currentToken) ||
      !safeEqualString(token, pending.token)
    ) {
      this.#store.recordAudit({ type: 'admin_denied', ip, detail: 'setup_token_invalid' });
      this.#sendJson(res, 403, { error: 'setup_token_invalid' });
      return;
    }
    const code = typeof body.totp === 'string' ? body.totp.trim() : '';
    const matched = verifyTotpCounter(pending.totpSecretB32, code, { now: this.#now(), window: 1 });
    if (matched < 0) {
      this.#store.recordAudit({ type: 'admin_denied', ip, detail: 'setup_totp_invalid' });
      this.#sendJson(res, 403, { error: 'totp_invalid' });
      return;
    }
    let result;
    try {
      // Atomic: user + confirmed TOTP + initial web device in a single state
      // write. Equivalent to createUser → confirmTotp(now) → createDevice.
      result = await this.#store.completeSetup({
        username: pending.username,
        passwordHash: pending.passwordHash,
        totpSecretB32: pending.totpSecretB32,
        name: '初始化浏览器',
        platform: 'web',
        origin: this.#publicUrl,
        deviceTtlMs: this.#config.deviceTtlDays * 86_400_000,
        maxDevices: this.#config.maxDevices
      });
    } catch (error) {
      if (String(error.message).includes('already configured')) {
        this.#setupPending = null;
        this.#sendJson(res, 409, { error: 'already_configured' });
        return;
      }
      throw error;
    }
    if (result.status !== 'ok') {
      // Practically unreachable on a fresh deployment (maxDevices >= 1 and no
      // devices exist), but never half-configure if configuration allows 0.
      this.#sendJson(res, 409, { error: result.status });
      return;
    }
    // The credential is now consumed: remove the file before answering so the
    // response is only sent when setup has really finished.
    await this.#store.clearSetupToken();
    this.#setupPending = null;
    this.#appendSetCookie(
      res,
      serializeCookie(DEVICE_COOKIE, result.token, this.#cookieOptions(this.#config.deviceTtlDays * 86_400))
    );
    this.#store.recordAudit({ type: 'admin_change', ip, deviceId: result.device.id, detail: 'setup_confirm' });
    // The browser now holds dsh_gate_device, so the follow-up login only needs
    // username + password.
    this.#sendJson(res, 200, { ok: true });
  }

  /**
   * Rotate the setup token through the trusted adminKey/loopback channels.
   * Returns the full setup URL (the only API allowed to echo the token, and
   * only while unconfigured).
   */
  async #setupRotateToken(req, res) {
    const auth = await this.#authorizeAdmin(req);
    if (auth === null || auth.channel === 'session') {
      this.#store.recordAudit({ type: 'admin_denied', ip: clientIp(req), detail: 'setup_token_denied' });
      this.#sendJson(res, 403, { error: 'forbidden' });
      return;
    }
    const token = await this.#store.rotateSetupToken().catch((error) => {
      if (String(error.message).includes('already configured')) return null;
      throw error;
    });
    if (token === null) {
      this.#setupPending = null;
      this.#sendJson(res, 409, { error: 'already_configured' });
      return;
    }
    this.#setupPending = null;
    this.#store.recordAudit({
      type: 'admin_change',
      ip: clientIp(req),
      detail: `setup_token_rotated; via=${auth.channel}`
    });
    this.#sendJson(res, 200, {
      setupUrl: `${this.#publicUrl}/__admin#setup=${token}`,
      setupPath: '/__admin'
    });
  }

  async #adminBootstrap(req, res) {
    if (this.#store.configured) {
      this.#sendJson(res, 409, { error: 'already_configured' });
      return;
    }
    const body = await this.#readJson(req, 8 * 1024);
    const username = typeof body.username === 'string' ? body.username.trim() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    if (!USERNAME_PATTERN.test(username)) {
      this.#sendJson(res, 400, { error: 'invalid_username' });
      return;
    }
    const policy = checkPasswordPolicy(password);
    if (!policy.ok) {
      this.#sendJson(res, 400, { error: policy.reason === 'too_long' ? 'weak_password' : 'weak_password' });
      return;
    }
    const passwordHash = await hashPassword(password);
    const secretB32 = generateSecret();
    try {
      await this.#store.createUser({ username, passwordHash, totpSecretB32: secretB32 });
    } catch (error) {
      if (String(error.message).includes('already configured')) {
        this.#sendJson(res, 409, { error: 'already_configured' });
        return;
      }
      throw error;
    }
    // The legacy adminKey bootstrap is also an initialization path: retire the
    // WebUI setup credential (and any pending draft) so no setup secret lingers
    // in the state directory or memory.
    this.#setupPending = null;
    await this.#store.clearSetupToken();
    this.#store.recordAudit({ type: 'admin_change', ip: clientIp(req), detail: 'bootstrap' });
    const uri = otpauthUri({ account: username, secret: secretB32 });
    this.#sendJson(res, 200, { ok: true, username, otpauthUri: uri, secretB32, qrSvg: await qrSvg(uri) });
  }

  async #adminUser(req, res, auth) {
    if (!this.#store.configured) {
      this.#sendJson(res, 400, { error: 'no_user' });
      return;
    }
    const body = await this.#readJson(req, 8 * 1024);
    const wantsPassword = typeof body.password === 'string' && body.password.length > 0;
    const wantsTotp = body.resetTotp === true;
    if (!wantsPassword && !wantsTotp) {
      this.#sendJson(res, 400, { error: 'bad_request' });
      return;
    }
    // A session is not a password: rotating credentials from the WebUI requires
    // proving knowledge of the current password. Verify once for both branches.
    if (!(await this.#verifyCurrentPasswordForAdmin(body, req, res, auth))) return;
    let newSecret = null;
    // Credential rotation invalidates the whole trust surface: sessions *and*
    // paired devices. Both branches use the same store-level semantics, and the
    // response reports the same counters so callers/UI can say "re-pair".
    let devicesRevoked = 0;
    let sessionsRevoked = 0;
    const via = auth.channel;
    if (wantsPassword) {
      const policy = checkPasswordPolicy(body.password);
      if (!policy.ok) {
        this.#sendJson(res, 400, { error: 'weak_password' });
        return;
      }
      const revoked = await this.#store.setPasswordHash(await hashPassword(body.password));
      devicesRevoked += revoked.devicesRevoked;
      sessionsRevoked += revoked.sessionsRevoked;
      this.#store.recordAudit({ type: 'admin_change', ip: clientIp(req), detail: `password_changed; devices_revoked; via=${via}` });
    }
    if (wantsTotp) {
      newSecret = generateSecret();
      const revoked = await this.#store.resetTotp(newSecret);
      devicesRevoked += revoked.devicesRevoked;
      sessionsRevoked += revoked.sessionsRevoked;
      this.#store.recordAudit({ type: 'admin_change', ip: clientIp(req), detail: `totp_reset; devices_revoked; via=${via}` });
    }
    const payload = { ok: true, devicesRevoked, sessionsRevoked, rePairRequired: true };
    if (newSecret !== null) {
      const uri = otpauthUri({ account: this.#store.user.username, secret: newSecret });
      payload.secretB32 = newSecret;
      payload.otpauthUri = uri;
      payload.qrSvg = await qrSvg(uri);
    }
    this.#sendJson(res, 200, payload);
  }

  async #adminQr(req, res, auth) {
    if (!this.#store.configured) {
      this.#sendJson(res, 409, { error: 'no_user' });
      return;
    }
    // `platform` only shapes the WebUI hint; ticket semantics stay identical.
    // Ignore unknown values instead of rejecting them (backwards compatible).
    let platform = '';
    const contentType = String(req.headers['content-type'] ?? '').toLowerCase();
    const body = contentType.includes('application/json') ? await this.#readJson(req, 8 * 1024) : {};
    if (body.platform === 'android' || body.platform === 'web') platform = body.platform;
    // This is the pairing gate: minting a pairing ticket binds a new 90-day
    // device, so the session channel must prove a fresh TOTP code. A stolen
    // session alone therefore cannot add its own device and renew a session.
    if (!(await this.#verifyPairingTotpForAdmin(body, req, res, auth))) return;
    const ip = clientIp(req);
    const limit = this.#qrIssueLimiter.hit(`qr:${ip}`);
    if (!limit.allowed) {
      this.#rateLimited(res, limit.retryAfterSeconds);
      return;
    }
    const { ticket, record } = await this.#store.issueTicket({ ttlMs: this.#config.pairTicketTtlSeconds * 1000 });
    const url = pairUrl({
      publicUrl: this.#publicUrl,
      ticket,
      fingerprint: this.#fingerprint,
      hostname: this.#hostname
    });
    this.#store.recordAudit({
      type: 'admin_change',
      ip,
      detail: `pair_ticket_issued${platform === '' ? '' : `; platform=${platform}`}; via=${auth.channel}`
    });
    this.#sendJson(res, 200, { url, expiresAt: record.expiresAt, qrSvg: await qrSvg(url) });
  }

  async #adminRevoke(req, res, auth) {
    const body = await this.#readJson(req, 8 * 1024);
    const deviceId = typeof body.deviceId === 'string' ? body.deviceId : '';
    const revoked = deviceId.length > 0 ? await this.#store.revokeDevice(deviceId) : false;
    if (!revoked) {
      this.#store.recordAudit({ type: 'device_revoke', ip: clientIp(req), detail: 'not_found' });
      this.#sendJson(res, 404, { error: 'device_not_found' });
      return;
    }
    this.#store.recordAudit({
      type: 'device_revoke',
      ip: clientIp(req),
      deviceId,
      detail: `revoked; via=${auth.channel}`
    });
    this.#sendJson(res, 200, { ok: true, revoked: true });
  }

  // --------------------------------------------------------------- proxy

  async #handleProxy(req, res, url) {
    // The proxy rewrites Origin to dsh's own authority, so it must first make
    // sure the browser's Origin really belongs to this gateway. Otherwise a
    // malicious same-site page could borrow the session cookie and have dsh
    // accept the request as same-origin.
    const origin = req.headers.origin;
    if (origin !== undefined && !sameBrowserOrigin(origin, req.headers.host, this.#secure)) {
      this.#store.recordAudit({ type: 'proxy_error', ip: clientIp(req), detail: 'bad_origin' });
      this.#sendJson(res, 403, { error: 'forbidden_origin' });
      return;
    }
    const session = await this.#sessionFromRequest(req);
    // Public dist assets (manifest/favicon/touch icons/dist JS+CSS) are fetched
    // by the browser without credentials. They carry no user data and stay
    // GET/HEAD-only; every data route below still requires a session.
    if (session === null && !isPublicAssetRequest(req.method, url.pathname)) {
      if (isHtmlRequest(req)) {
        const next = sanitizeNext(`${url.pathname}${url.search}`);
        res.writeHead(302, { location: `/__auth/login?next=${encodeURIComponent(next)}`, 'cache-control': 'no-store' });
        res.end();
      } else {
        this.#sendJson(res, 401, { error: 'authentication_required' });
      }
      return;
    }
    let cookie;
    try {
      cookie = await this.#dshSession.getCookie();
    } catch (error) {
      this.#store.recordAudit({ type: 'proxy_error', ip: clientIp(req), detail: 'dsh_cookie_unavailable' });
      this.#sendUpstreamFailure(req, res);
      return;
    }
    const prepared = await this.#prepareBody(req);
    await this.#forward(req, res, prepared, { cookie, retried: false, target: `${url.pathname}${url.search}` });
  }

  async #prepareBody(req) {
    const method = req.method ?? 'GET';
    if (method === 'GET' || method === 'HEAD') return { buffer: Buffer.alloc(0) };
    const declared = Number(req.headers['content-length']);
    // Large or streaming (chunked) bodies are forwarded as a stream so uploads
    // are not capped by the retry buffer. Such a request cannot be replayed if
    // dsh answers 401; the caller gets a 502 instead of a silently truncated
    // upload. Everything with a small declared length is buffered so the cookie
    // refresh can retry once.
    if (!Number.isFinite(declared) || declared > MAX_BUFFERED_PROXY_BYTES) return { buffer: null, stream: true };
    const buffer = await readBody(req, MAX_BUFFERED_PROXY_BYTES);
    return { buffer };
  }

  #sendUpstreamFailure(req, res) {
    if (res.headersSent) {
      res.destroy();
      return;
    }
    if (isHtmlRequest(req)) {
      this.#sendPlain(res, 502, 'DSH', t('error.upstream_auth_failed'));
    } else {
      this.#sendJson(res, 502, { error: 'upstream_auth_failed' });
    }
  }

  async #forward(req, res, prepared, context) {
    const upstream = this.#upstream;
    const headers = buildUpstreamHeaders(req.headers, { upstream, dshCookie: context.cookie });
    if (prepared.buffer !== null) {
      if (prepared.buffer.length > 0) {
        headers['content-length'] = String(prepared.buffer.length);
        if (headers['transfer-encoding'] !== undefined) delete headers['transfer-encoding'];
      } else {
        headers['content-length'] = '0';
      }
    }
    const options = {
      protocol: upstream.protocol,
      hostname: upstream.hostname,
      port: upstream.port,
      path: `${upstream.pathPrefix}${context.target}`,
      method: req.method,
      headers,
      agent: upstream.protocol === 'https:' ? this.#httpsAgent : this.#httpAgent,
      rejectUnauthorized: !this.#config.upstreamInsecureTls
    };
    if (upstream.protocol === 'https:' && isIP(upstream.hostname) === 0 && this.#config.upstreamInsecureTls === false) options.servername = upstream.hostname;

    const transport = upstream.protocol === 'https:' ? https : http;
    const upstreamReq = transport.request(options);
    upstreamReq.setTimeout(120_000, () => upstreamReq.destroy(new Error('upstream request timed out')));
    let finished = false;
    req.on('aborted', () => upstreamReq.destroy());
    res.on('close', () => {
      if (!res.writableEnded) upstreamReq.destroy();
    });
    upstreamReq.on('error', (error) => {
      if (finished) return;
      finished = true;
      this.#logger.warn?.(`auth-gate: upstream ${upstream.origin} request failed: ${error.message}`);
      this.#store.recordAudit({ type: 'proxy_error', ip: clientIp(req), detail: 'upstream_error' });
      this.#sendUpstreamFailure(req, res);
    });
    upstreamReq.on('response', (upstreamRes) => {
      // Long-lived SSE/download responses must not be cut by the request-header
      // idle timeout; only the time to first response byte is bounded.
      upstreamReq.setTimeout(0);
      const status = upstreamRes.statusCode ?? 502;
      if (status === 401) {
        upstreamRes.resume();
        if (context.retried || prepared.buffer === null) {
          this.#store.recordAudit({ type: 'proxy_error', ip: clientIp(req), detail: 'upstream_auth_failed' });
          this.#sendUpstreamFailure(req, res);
          return;
        }
        void (async () => {
          try {
            this.#dshSession.invalidate();
            const cookie = await this.#dshSession.getCookie({ force: true });
            await this.#forward(req, res, prepared, { cookie, retried: true, target: context.target });
          } catch (error) {
            this.#store.recordAudit({ type: 'proxy_error', ip: clientIp(req), detail: 'dsh_cookie_refresh_failed' });
            this.#sendUpstreamFailure(req, res);
          }
        })();
        return;
      }
      const responseHeaders = filterResponseHeaders(upstreamRes.headers);
      if (upstreamRes.headers.location !== undefined) {
        const rewritten = rewriteLocation(upstreamRes.headers.location, upstream);
        if (rewritten !== undefined) responseHeaders.location = rewritten;
      }
      res.writeHead(status, responseHeaders);
      upstreamRes.pipe(res);
      res.on('close', () => {
        if (!res.writableEnded) upstreamRes.destroy();
      });
    });
    if (prepared.buffer !== null) {
      if (prepared.buffer.length > 0) upstreamReq.write(prepared.buffer);
      upstreamReq.end();
    } else {
      req.pipe(upstreamReq);
    }
  }

  // ---------------------------------------------------------- websocket

  #rejectUpgrade(socket, status, message) {
    if (!socket.writable) {
      socket.destroy();
      return;
    }
    const body = `${message}\n`;
    const head = `HTTP/1.1 ${status} ${STATUS_CODES[status] ?? 'Error'}\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`;
    socket.write(head);
    socket.destroy();
  }

  async #handleUpgrade(req, socket, head) {
    socket.on('error', () => {});
    let url;
    try {
      url = new URL(req.url ?? '/', 'https://gateway.invalid');
    } catch {
      this.#rejectUpgrade(socket, 400, 'bad request');
      return;
    }
    if (isReservedPath(url.pathname)) {
      this.#rejectUpgrade(socket, 403, 'forbidden');
      return;
    }
    if (req.method !== 'GET' || !isWebSocketUpgrade(req)) {
      this.#rejectUpgrade(socket, 400, 'expected a websocket upgrade');
      return;
    }
    if (!sameBrowserOrigin(req.headers.origin, req.headers.host, this.#secure)) {
      this.#store.recordAudit({ type: 'ws_reject', ip: clientIp(req), detail: 'bad_origin' });
      this.#rejectUpgrade(socket, 403, 'forbidden');
      return;
    }
    const session = await this.#sessionFromRequest(req);
    if (session === null) {
      this.#store.recordAudit({ type: 'ws_reject', ip: clientIp(req), detail: 'unauthenticated' });
      this.#rejectUpgrade(socket, 401, 'authentication required');
      return;
    }
    let cookie;
    try {
      cookie = await this.#dshSession.getCookie();
    } catch {
      this.#store.recordAudit({ type: 'ws_reject', ip: clientIp(req), detail: 'dsh_cookie_unavailable' });
      this.#rejectUpgrade(socket, 502, 'upstream authentication unavailable');
      return;
    }

    const upstream = this.#upstream;
    const headers = buildWebSocketHeaders(req.headers, { upstream, dshCookie: cookie });
    const path = `${upstream.pathPrefix}${url.pathname}${url.search}`;
    const lines = [`GET ${path} HTTP/1.1`];
    for (const [name, value] of Object.entries(headers)) {
      if (Array.isArray(value)) for (const item of value) lines.push(`${name}: ${item}`);
      else if (value !== undefined) lines.push(`${name}: ${value}`);
    }
    const requestHead = Buffer.from(`${lines.join('\r\n')}\r\n\r\n`, 'latin1');

    /** @type {import('node:net').Socket} */
    let upstreamSocket;
    let settled = false;
    const fail = () => {
      if (settled) return;
      settled = true;
      upstreamSocket?.destroy();
      this.#rejectUpgrade(socket, 502, 'upstream connection failed');
    };
    const connectOptions = { host: upstream.hostname, port: upstream.port };
    if (upstream.protocol === 'https:') {
      if (isIP(upstream.hostname) === 0) connectOptions.servername = upstream.hostname;
      upstreamSocket = tls.connect({ ...connectOptions, rejectUnauthorized: !this.#config.upstreamInsecureTls }, onConnect);
    } else {
      upstreamSocket = net.connect(connectOptions, onConnect);
    }
    this.#sockets.add(upstreamSocket);
    upstreamSocket.on('close', () => this.#sockets.delete(upstreamSocket));
    upstreamSocket.on('error', (error) => {
      this.#logger.warn?.(`auth-gate: websocket upstream error: ${error.message}`);
      fail();
    });
    upstreamSocket.setTimeout(20_000, () => upstreamSocket.destroy(new Error('upstream websocket timeout')));
    upstreamSocket.once('data', () => upstreamSocket.setTimeout(0));

    function onConnect() {
      if (settled) return;
      settled = true;
      upstreamSocket.write(requestHead);
      if (head !== undefined && head.length > 0) upstreamSocket.write(head);
      socket.pipe(upstreamSocket);
      socket.on('error', () => upstreamSocket.destroy());
      upstreamSocket.on('error', () => socket.destroy());
      upstreamSocket.on('end', () => socket.end());
      socket.on('end', () => upstreamSocket.end());
      socket.on('close', () => upstreamSocket.destroy());
      upstreamSocket.on('close', () => socket.destroy());

      // Buffer only the response head so upstream Set-Cookie headers can be
      // stripped before the raw tunnel starts.
      let headBuffer = Buffer.alloc(0);
      let headForwarded = false;
      const onUpstreamData = (chunk) => {
        if (headForwarded) return;
        headBuffer = Buffer.concat([headBuffer, chunk]);
        if (headBuffer.length > 64 * 1024) {
          upstreamSocket.destroy();
          return;
        }
        const marker = headBuffer.indexOf('\r\n\r\n');
        if (marker === -1) return;
        const headText = headBuffer.subarray(0, marker).toString('latin1');
        const rest = headBuffer.subarray(marker + 4);
        headForwarded = true;
        upstreamSocket.off('data', onUpstreamData);
        socket.write(`${sanitizeUpgradeResponseHead(headText)}\r\n\r\n`, 'latin1');
        if (rest.length > 0) socket.write(rest);
        upstreamSocket.pipe(socket);
      };
      upstreamSocket.on('data', onUpstreamData);
    }
  }
}

function sanitizeDeviceName(value) {
  if (typeof value !== 'string') return 'device';
  const cleaned = value.replace(/[\u0000-\u001f\u007f]/gu, '').trim();
  return cleaned.length === 0 ? 'device' : cleaned.slice(0, 64);
}

export { isReservedPath as _isReservedPathForTests };
