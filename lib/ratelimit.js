/**
 * In-process rate limiting.
 *
 * - `LoginLimiter`: per (IP, username) sliding failure window; after
 *   `maxFailures` inside `windowMs` the key is locked for `lockMs`.
 * - `FixedWindowLimiter`: per-key fixed window counter for unauthenticated
 *   endpoints such as pair/ticket redemption.
 *
 * Both accept an injectable `now` so tests need no real clock.
 */

export const LOGIN_LOCK_DEFAULTS = Object.freeze({ maxFailures: 5, windowMinutes: 15, lockMinutes: 15 });

export class LoginLimiter {
  /**
   * @param {{maxFailures?:number,windowMs?:number,lockMs?:number,maxKeys?:number,now?:()=>number}} [options]
   */
  constructor(options = {}) {
    this.maxFailures = options.maxFailures ?? LOGIN_LOCK_DEFAULTS.maxFailures;
    this.windowMs = options.windowMs ?? LOGIN_LOCK_DEFAULTS.windowMinutes * 60_000;
    this.lockMs = options.lockMs ?? LOGIN_LOCK_DEFAULTS.lockMinutes * 60_000;
    this.maxKeys = options.maxKeys ?? 10_000;
    this.now = options.now ?? Date.now;
    if (!Number.isInteger(this.maxFailures) || this.maxFailures < 1) throw new TypeError('ratelimit: maxFailures must be a positive integer');
    if (!(this.windowMs > 0) || !(this.lockMs > 0)) throw new TypeError('ratelimit: windows must be positive');
    this.entries = new Map();
  }

  /** @param {string} ip @param {string} username */
  static key(ip, username) {
    return `${ip}\u0000${String(username ?? '').trim().toLowerCase()}`;
  }

  /**
   * Inspect the key without recording a failure.
   * @param {string} ip
   * @param {string} username
   * @returns {{allowed:boolean,locked:boolean,retryAfterSeconds:number,failures:number}}
   */
  check(ip, username) {
    const now = this.now();
    const key = LoginLimiter.key(ip, username);
    const entry = this.entries.get(key);
    if (entry === undefined) return { allowed: true, locked: false, retryAfterSeconds: 0, failures: 0 };
    if (entry.lockedUntil > now) {
      return {
        allowed: false,
        locked: true,
        retryAfterSeconds: Math.max(1, Math.ceil((entry.lockedUntil - now) / 1000)),
        failures: entry.failures.length
      };
    }
    if (entry.lockedUntil !== 0) {
      // Lock elapsed: start a clean window.
      this.entries.delete(key);
      return { allowed: true, locked: false, retryAfterSeconds: 0, failures: 0 };
    }
    entry.failures = entry.failures.filter((at) => now - at < this.windowMs);
    return { allowed: true, locked: false, retryAfterSeconds: 0, failures: entry.failures.length };
  }

  /**
   * Record a failed credential/TOTP attempt.
   * @param {string} ip
   * @param {string} username
   * @returns {{locked:boolean,retryAfterSeconds:number,failures:number}}
   */
  fail(ip, username) {
    const now = this.now();
    const key = LoginLimiter.key(ip, username);
    let entry = this.entries.get(key);
    if (entry === undefined || (entry.lockedUntil !== 0 && entry.lockedUntil <= now)) {
      if (this.entries.size >= this.maxKeys) {
        this.prune();
        if (this.entries.size >= this.maxKeys) this.entries.delete(this.entries.keys().next().value);
      }
      entry = { failures: [], lockedUntil: 0 };
      this.entries.set(key, entry);
    }
    entry.failures = entry.failures.filter((at) => now - at < this.windowMs);
    entry.failures.push(now);
    if (entry.failures.length >= this.maxFailures) {
      entry.lockedUntil = now + this.lockMs;
      return { locked: true, retryAfterSeconds: Math.ceil(this.lockMs / 1000), failures: entry.failures.length };
    }
    return { locked: false, retryAfterSeconds: 0, failures: entry.failures.length };
  }

  /** Clear the key after a successful login. */
  succeed(ip, username) {
    this.entries.delete(LoginLimiter.key(ip, username));
  }

  /** Drop expired state; safe to call periodically. */
  prune() {
    const now = this.now();
    for (const [key, entry] of this.entries) {
      if (entry.lockedUntil > now) continue;
      if (entry.lockedUntil !== 0 || entry.failures.every((at) => now - at >= this.windowMs)) this.entries.delete(key);
    }
  }

  reset() {
    this.entries.clear();
  }
}

export class FixedWindowLimiter {
  /**
   * @param {{limit?:number,windowMs?:number,maxKeys?:number,now?:()=>number}} [options]
   */
  constructor(options = {}) {
    this.limit = options.limit ?? 30;
    this.windowMs = options.windowMs ?? 60_000;
    this.maxKeys = options.maxKeys ?? 5000;
    this.now = options.now ?? Date.now;
    if (!Number.isInteger(this.limit) || this.limit < 1) throw new TypeError('ratelimit: limit must be a positive integer');
    if (!(this.windowMs > 0)) throw new TypeError('ratelimit: windowMs must be positive');
    this.entries = new Map();
  }

  /**
   * Count one request for the key.
   * @param {string} key
   * @returns {{allowed:boolean,remaining:number,retryAfterSeconds:number}}
   */
  hit(key) {
    const now = this.now();
    let entry = this.entries.get(key);
    if (entry === undefined || now - entry.windowStart >= this.windowMs) {
      if (this.entries.size >= this.maxKeys) this.prune(now);
      if (this.entries.size >= this.maxKeys) this.entries.delete(this.entries.keys().next().value);
      entry = { windowStart: now, count: 0 };
      this.entries.set(key, entry);
    }
    entry.count += 1;
    const allowed = entry.count <= this.limit;
    return {
      allowed,
      remaining: Math.max(0, this.limit - entry.count),
      retryAfterSeconds: allowed ? 0 : Math.max(1, Math.ceil((entry.windowStart + this.windowMs - now) / 1000))
    };
  }

  /** Inspect without counting. */
  peek(key) {
    const now = this.now();
    const entry = this.entries.get(key);
    if (entry === undefined || now - entry.windowStart >= this.windowMs) return { allowed: true, remaining: this.limit, retryAfterSeconds: 0 };
    return {
      allowed: entry.count < this.limit,
      remaining: Math.max(0, this.limit - entry.count),
      retryAfterSeconds: entry.count < this.limit ? 0 : Math.max(1, Math.ceil((entry.windowStart + this.windowMs - now) / 1000))
    };
  }

  prune(now = this.now()) {
    for (const [key, entry] of this.entries) if (now - entry.windowStart >= this.windowMs) this.entries.delete(key);
  }

  reset() {
    this.entries.clear();
  }
}
