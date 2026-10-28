/**
 * Server-side holder of the dsh browser session cookie.
 *
 * The browser never sees the launch token or the `dsh-auth-*` cookie. This
 * module exchanges the process launch token (`ctx.connection.authenticatedUrl()`
 * inside dsh, `DSH_TOKEN_URL` in standalone mode) for the signed cookie that
 * dsh's Host Connection expects, caches it, and refreshes it on 401.
 *
 * The token URL is never logged: diagnostics only mention scheme + path.
 */

import * as http from 'node:http';
import * as https from 'node:https';
import { isIP } from 'node:net';

const DEFAULT_REFRESH_AFTER_MS = 30 * 60 * 1000;

/** Remove query strings (which carry the launch token) from an error message. */
function sanitizeMessage(message, tokenUrl) {
  let text = String(message);
  try {
    const url = new URL(tokenUrl);
    text = text.split(url.search).join('?<redacted>');
    if (url.search.length > 1) text = text.split(url.search.slice(1)).join('<redacted>');
  } catch {
    // token URL is not a URL; nothing to redact
  }
  text = text.replace(/([?&]token=)[^\s&"']+/gu, '$1<redacted>');
  return text;
}

function redactUrl(rawUrl) {
  try {
    const url = new URL(rawUrl);
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    return '<invalid token url>';
  }
}

/**
 * @typedef {object} DshSessionOptions
 * @property {string|(()=>string|Promise<string>)} tokenUrl launch-token URL (or provider)
 * @property {boolean} [insecureTls] accept self-signed upstream certificates
 * @property {{info?:Function,warn?:Function,error?:Function}} [logger]
 * @property {number} [timeoutMs]
 * @property {number} [refreshAfterMs]
 * @property {()=>number} [now]
 * @property {typeof http.request} [requestImpl] test seam
 */

export class DshSessionProvider {
  #tokenUrl;
  #insecureTls;
  #logger;
  #timeoutMs;
  #refreshAfterMs;
  #now;
  #requestImpl;
  #cookie = null;
  #cookieName = null;
  #obtainedAt = 0;
  #pending = null;

  /** @param {DshSessionOptions} options */
  constructor(options) {
    if (options === null || typeof options !== 'object') throw new TypeError('dsh-session: options are required');
    const { tokenUrl } = options;
    if (typeof tokenUrl !== 'string' && typeof tokenUrl !== 'function') throw new TypeError('dsh-session: tokenUrl is required');
    this.#tokenUrl = tokenUrl;
    this.#insecureTls = options.insecureTls === true;
    this.#logger = options.logger ?? console;
    this.#timeoutMs = options.timeoutMs ?? 15_000;
    this.#refreshAfterMs = options.refreshAfterMs ?? DEFAULT_REFRESH_AFTER_MS;
    this.#now = options.now ?? Date.now;
    this.#requestImpl = options.requestImpl ?? undefined;
  }

  /** Cached cookie name (contains a hash of the dsh authority, not a secret). */
  get cookieName() {
    return this.#cookieName;
  }

  get hasCookie() {
    return this.#cookie !== null;
  }

  /** Test/diagnostic view; never returns the cookie value. */
  describe() {
    return {
      hasCookie: this.#cookie !== null,
      cookieName: this.#cookieName,
      ageMs: this.#cookie === null ? null : this.#now() - this.#obtainedAt
    };
  }

  /** Drop the cached cookie so the next call exchanges the token again. */
  invalidate() {
    this.#cookie = null;
    this.#cookieName = null;
    this.#obtainedAt = 0;
  }

  /**
   * Return the `name=value` cookie pair for upstream requests.
   * @param {{force?:boolean}} [options]
   * @returns {Promise<string>}
   */
  async getCookie(options = {}) {
    const force = options.force === true;
    if (!force && this.#cookie !== null && this.#now() - this.#obtainedAt < this.#refreshAfterMs) return this.#cookie;
    if (this.#pending !== null) {
      if (!force) return this.#pending;
      // A forced refresh must not simply reuse an in-flight exchange that may
      // have started before the 401 arrived; wait for it, then exchange again.
      await this.#pending.catch(() => {});
    }
    const hadCookie = this.#cookie !== null;
    this.#pending = (async () => {
      try {
        const tokenUrl = await this.#resolveTokenUrl();
        const result = await this.#exchange(tokenUrl);
        this.#cookie = result.cookie;
        this.#cookieName = result.name;
        this.#obtainedAt = this.#now();
        this.#logger.info?.(`auth-gate: obtained dsh session cookie (${result.name}) from ${redactUrl(tokenUrl)}`);
        return this.#cookie;
      } catch (error) {
        const message = sanitizeMessage(error?.message ?? error, await this.#safeResolveTokenUrl());
        if (!force && hadCookie) {
          this.#logger.warn?.(`auth-gate: could not refresh dsh session cookie (${message}); reusing the cached cookie`);
          return this.#cookie;
        }
        throw new Error(`dsh-session: token exchange failed: ${message}`);
      } finally {
        this.#pending = null;
      }
    })();
    return this.#pending;
  }

  async #safeResolveTokenUrl() {
    try {
      return await this.#resolveTokenUrl();
    } catch {
      return '';
    }
  }

  async #resolveTokenUrl() {
    const value = typeof this.#tokenUrl === 'function' ? await this.#tokenUrl() : this.#tokenUrl;
    if (typeof value !== 'string' || value.length === 0) throw new Error('token URL provider returned no URL');
    const url = new URL(value);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('token URL must be http(s)');
    if (url.username !== '' || url.password !== '') throw new Error('token URL must not embed credentials');
    return value;
  }

  /**
   * GET the launch-token URL and read the `Set-Cookie` header (no redirects:
   * dsh answers 303 with the cookie, and following it would waste a second hop).
   * @param {string} tokenUrl
   * @returns {Promise<{cookie:string,name:string}>}
   */
  #exchange(tokenUrl) {
    const url = new URL(tokenUrl);
    const transport = url.protocol === 'https:' ? https : http;
    const hostname = url.hostname.replace(/^\[|\]$/gu, '');
    const options = {
      protocol: url.protocol,
      hostname,
      port: url.port === '' ? undefined : Number(url.port),
      path: `${url.pathname}${url.search}`,
      method: 'GET',
      headers: {
        host: url.host,
        accept: 'text/html,application/xhtml+xml',
        'user-agent': 'dsh-pairing-gate/0.7.2',
        connection: 'close'
      },
      timeout: this.#timeoutMs
    };
    if (url.protocol === 'https:') {
      options.rejectUnauthorized = !this.#insecureTls;
      if (isIP(hostname) === 0) options.servername = hostname;
    }
    const requestImpl = this.#requestImpl ?? transport.request;
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        fn(value);
      };
      let request;
      try {
        request = requestImpl(options, (response) => {
          const status = response.statusCode ?? 0;
          const cookies = response.headers['set-cookie'] ?? [];
          response.resume();
          response.on('error', (error) => finish(reject, error));
          response.on('end', () => {
            if (status === 401 || status === 403) {
              finish(reject, new Error(`launch token was rejected with HTTP ${status}`));
              return;
            }
            if (status < 200 || status >= 400) {
              finish(reject, new Error(`HTTP ${status}`));
              return;
            }
            const parsed = pickSessionCookie(cookies);
            if (parsed === null) {
              finish(reject, new Error(`HTTP ${status} response carried no dsh session cookie`));
              return;
            }
            finish(resolve, parsed);
          });
        });
      } catch (error) {
        finish(reject, error);
        return;
      }
      request.on('timeout', () => request.destroy(new Error('token exchange timed out')));
      request.on('error', (error) => finish(reject, error));
      request.end();
    });
  }
}

/**
 * Pick the dsh session cookie out of a Set-Cookie list.
 * @param {string[]|string|undefined} setCookie
 * @returns {{cookie:string,name:string}|null}
 */
export function pickSessionCookie(setCookie) {
  if (setCookie === undefined) return null;
  const list = Array.isArray(setCookie) ? setCookie : [setCookie];
  let fallback = null;
  for (const raw of list) {
    if (typeof raw !== 'string' || /[\r\n]/u.test(raw)) continue;
    const pair = raw.split(';', 1)[0].trim();
    const at = pair.indexOf('=');
    if (at <= 0) continue;
    const name = pair.slice(0, at).trim();
    const value = pair.slice(at + 1).trim();
    if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u.test(name) || value.length === 0 || /[\r\n]/u.test(value)) continue;
    if (name.startsWith('dsh-auth-')) return { cookie: `${name}=${value}`, name };
    fallback ??= { cookie: `${name}=${value}`, name };
  }
  return fallback;
}
