/**
 * Durable state for the auth gate.
 *
 * `$stateDir/state.json` (0600) holds the single user, paired devices, one-time
 * pairing tickets, gateway sessions and a bounded audit log. Every secret is
 * stored as a SHA-256 hash — password hashes, TOTP secrets (needed to verify)
 * and the admin key (separate 0600 file) are the only material that is not
 * single-use random data.
 *
 * Writes are atomic (temp file + fsync + rename) and serialized through one
 * queue. A corrupt state file is a hard startup error: silently resetting it
 * would silently drop every paired device and the configured password.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

export const STATE_VERSION = 1;
export const AUDIT_LIMIT = 500;
export const ADMIN_KEY_BYTES = 32;
/** Raw entropy of the one-time WebUI setup token (hex-encoded, 64 chars). */
export const SETUP_TOKEN_BYTES = 32;
/** A device counts as online when it (or one of its sessions) was active this recently. */
export const ONLINE_WINDOW_MS = 120_000;
const ADMIN_KEY_PATTERN = /^[0-9a-f]{64}$/u;
const SETUP_TOKEN_PATTERN = /^[0-9a-f]{64}$/u;
const TOKEN_BYTES = 32;

/** @param {string|Buffer} value */
export function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

/** @param {Buffer|string} a @param {Buffer|string} b */
export function safeEqualString(a, b) {
  const left = Buffer.from(String(a), 'utf8');
  const right = Buffer.from(String(b), 'utf8');
  return left.length === right.length && timingSafeEqual(left, right);
}

/** Random opaque token (`<prefix>_<base64url of 32 bytes>`). */
export function randomToken(prefix) {
  return `${prefix}_${randomBytes(TOKEN_BYTES).toString('base64url')}`;
}

export function randomId(prefix) {
  return `${prefix}_${randomBytes(8).toString('hex')}`;
}

/** Default state directory, honouring `$DSH_HOME` when present. */
export function defaultStateDir(env = process.env) {
  const home = env.DSH_HOME && env.DSH_HOME.length > 0 ? env.DSH_HOME : path.join(env.HOME ?? process.cwd(), '.dsh');
  return path.join(home, 'auth-gate');
}

/**
 * Sliding-expiry arithmetic shared by devices and sessions.
 *
 * `idleMs` is the *rolling* window: every successful use moves the deadline to
 * `now + idleMs`. `absoluteMs > 0` pins a hard ceiling counted from creation
 * (the record's `createdAt`), so a continuously used credential can never live
 * forever. `absoluteMs = 0` disables the absolute ceiling.
 *
 * @param {number} now
 * @param {number} idleMs
 * @param {number} [absoluteMs]
 * @returns {{expiresAt:number, absoluteExpiresAt:number|null}}
 */
export function slidingExpiry(now, idleMs, absoluteMs = 0) {
  const idleExpiresAt = now + idleMs;
  const absolute = Number.isFinite(absoluteMs) && absoluteMs > 0 ? now + absoluteMs : null;
  return {
    expiresAt: absolute === null ? idleExpiresAt : Math.min(idleExpiresAt, absolute),
    absoluteExpiresAt: absolute
  };
}

/** Remaining whole seconds for a cookie `Max-Age`, never negative/zero. */
export function remainingSeconds(expiresAt, now) {
  return Math.max(1, Math.ceil((expiresAt - now) / 1000));
}

/**
 * True when a session passed its absolute ceiling. Sessions persisted by an
 * older version have no `absoluteExpiresAt` (undefined/null) and therefore no
 * ceiling until their next refresh establishes one from the current config.
 * @param {{absoluteExpiresAt?:number|null}} session
 * @param {number} now
 */
function isAbsoluteExpired(session, now) {
  return Number.isFinite(session.absoluteExpiresAt) && session.absoluteExpiresAt <= now;
}

/**
 * P2-3: true when a device passed its *pairing-time* absolute ceiling.
 * `absoluteMs` is not persisted on the device, so callers pass the active
 * policy (`deviceAbsoluteTtlMs`) on every read. This catches devices persisted
 * by an older version whose `expiresAt` is still in the future, and devices
 * whose `expiresAt` was extended before the operator lowered the ceiling.
 * @param {{createdAt:number}} device
 * @param {number} now
 * @param {number|undefined} absoluteMs
 */
function isDeviceAbsoluteExpired(device, now, absoluteMs) {
  return Number.isFinite(absoluteMs) && absoluteMs > 0 && device.createdAt + absoluteMs <= now;
}

function initialState() {
  return {
    version: STATE_VERSION,
    createdAt: Date.now(),
    user: null,
    devices: [],
    tickets: [],
    sessions: [],
    audit: []
  };
}

/**
 * @typedef {object} StoreOptions
 * @property {string} stateDir
 * @property {string} [adminKeyFile]
 * @property {number} [auditLimit]
 * @property {{info?:Function,warn?:Function,error?:Function}} [logger]
 * @property {boolean} [logAdminKey] deprecated/ignored: the key is only written to `adminKeyFile`
 * @property {() => number} [now]
 */

export class StateStore {
  /** @type {StoreOptions} */
  #options;
  #state;
  #adminKey = '';
  #setupToken = '';
  #stateFile;
  #adminKeyFile;
  #setupTokenFile;
  #auditLimit;
  #logger;
  #now;
  #lockTail = Promise.resolve();
  #writeTail = Promise.resolve();
  #saveTimer = null;
  #maintenanceTimer = null;
  #dirty = false;
  #closed = false;
  #lastSessionTouchWrite = 0;

  /** @param {StoreOptions} options */
  constructor(options) {
    this.#options = options;
    this.#stateFile = path.join(options.stateDir, 'state.json');
    this.#adminKeyFile = options.adminKeyFile ?? path.join(options.stateDir, 'admin.key');
    this.#setupTokenFile = path.join(options.stateDir, 'setup.token');
    this.#auditLimit = options.auditLimit ?? AUDIT_LIMIT;
    this.#logger = options.logger ?? console;
    this.#now = options.now ?? Date.now;
    this.#state = initialState();
  }

  /**
   * Open (and if needed create) a state directory.
   * @param {StoreOptions} options
   * @returns {Promise<StateStore>}
   */
  static async open(options) {
    if (!options || typeof options.stateDir !== 'string' || options.stateDir.length === 0) throw new TypeError('store: stateDir is required');
    const store = new StateStore(options);
    await fs.mkdir(options.stateDir, { recursive: true, mode: 0o700 });
    await fs.chmod(options.stateDir, 0o700);
    store.#state = await store.#loadState();
    store.#adminKey = await store.#loadOrCreateAdminKey();
    store.#setupToken = await store.#loadOrCreateSetupToken();
    store.#pruneExpired(store.#now(), true);
    store.#maintenanceTimer = setInterval(() => {
      void store.#runMaintenance();
    }, 60_000);
    store.#maintenanceTimer.unref?.();
    return store;
  }

  get stateFile() {
    return this.#stateFile;
  }

  /** Directory holding state.json, admin.key, setup.token and network.json. */
  get stateDir() {
    return this.#options.stateDir;
  }

  get adminKeyFile() {
    return this.#adminKeyFile;
  }

  get adminKey() {
    return this.#adminKey;
  }

  /** One-time WebUI setup token; empty once a user is configured. */
  get setupToken() {
    return this.#setupToken;
  }

  /** 0600 file holding the setup token (for operator retrieval). */
  get setupTokenPath() {
    return this.#setupTokenFile;
  }

  /** Stable, non-secret instance identifier used by the App. */
  get instanceId() {
    return createHash('sha256').update(`dsh-auth-gate:instance:${this.#adminKey}`).digest('hex').slice(0, 16);
  }

  get configured() {
    return this.#state.user !== null;
  }

  get user() {
    return this.#state.user;
  }

  get devices() {
    return this.#state.devices;
  }

  get auditLog() {
    return this.#state.audit;
  }

  get sessions() {
    return this.#state.sessions;
  }

  /** Pending pairing tickets (hashes only; used for admin/audit counts). */
  get tickets() {
    return this.#state.tickets;
  }

  /** Constant-time admin key comparison. */
  adminKeyMatches(candidate) {
    return typeof candidate === 'string' && candidate.length > 0 && safeEqualString(candidate, this.#adminKey);
  }

  /**
   * Public admin state. Never exposes hashes or token material.
   *
   * `sessions` stays a number for backwards compatibility; the detailed view
   * lives in `sessionList` (`current` marks the session that authenticated the
   * admin request, when known).
   * @param {{currentSessionId?:string|null}} [options]
   */
  publicState(options = {}) {
    const now = this.#now();
    const sessionList = this.#sessionSummaries(options.currentSessionId ?? null, now);
    const lastSessionSeen = new Map();
    for (const session of this.#state.sessions) {
      if (session.expiresAt <= now || isAbsoluteExpired(session, now)) continue;
      const previous = lastSessionSeen.get(session.deviceId) ?? 0;
      if (session.lastSeenAt > previous) lastSessionSeen.set(session.deviceId, session.lastSeenAt);
    }
    return {
      configured: this.configured,
      user: this.#state.user
        ? {
            username: this.#state.user.username,
            // `totpConfigured` is the only field UIs may use to decide whether
            // the account has an authenticator secret. The secret itself is
            // never echoed. `totpConfirmed` is legacy (it only flipped on the
            // session-channel pairing proof, so bootstrap/loopback/adminKey
            // pairing showed a misleading "unbound" badge) and is kept for API
            // compatibility only; it is NOT a binding status.
            totpConfigured: this.#state.user.totpSecretB32 !== '',
            totpConfirmed: this.#state.user.totpConfirmedAt !== null
          }
        : null,
      devices: this.#state.devices
        .filter((device) => device.expiresAt > now)
        .map((device) => {
          // "Online" means activity within the last two minutes. A session
          // cookie alone touches the session record every request, so consider
          // both the device token's last use and its sessions' last activity.
          const lastActivity = Math.max(device.lastSeenAt, lastSessionSeen.get(device.id) ?? 0);
          return {
            id: device.id,
            name: device.name,
            platform: device.platform,
            createdAt: device.createdAt,
            lastSeenAt: device.lastSeenAt,
            // Activity seen through either the device token or its sessions.
            lastActiveAt: lastActivity,
            expiresAt: device.expiresAt,
            online: lastActivity >= now - ONLINE_WINDOW_MS
          };
        }),
      sessions: sessionList.length,
      sessionCount: sessionList.length,
      sessionList,
      serverTime: now,
      instanceId: this.instanceId
    };
  }

  /**
   * Session summary for `GET /__admin/api/sessions`. Same shape as the list
   * embedded in {@link publicState}; never contains token material.
   * @param {{currentSessionId?:string|null}} [options]
   */
  publicSessions(options = {}) {
    const now = this.#now();
    const sessionList = this.#sessionSummaries(options.currentSessionId ?? null, now);
    return {
      sessions: sessionList.length,
      sessionCount: sessionList.length,
      sessionList,
      serverTime: now
    };
  }

  /**
   * @param {string|null} currentSessionId
   * @param {number} now
   * @returns {Array<{deviceId:string,createdAt:number,lastSeenAt:number,expiresAt:number,current:boolean}>}
   */
  #sessionSummaries(currentSessionId, now) {
    return this.#state.sessions
      .filter((session) => session.expiresAt > now && !isAbsoluteExpired(session, now))
      .sort((left, right) => right.lastSeenAt - left.lastSeenAt)
      .map((session) => ({
        deviceId: session.deviceId,
        createdAt: session.createdAt,
        lastSeenAt: session.lastSeenAt,
        expiresAt: session.expiresAt,
        current: currentSessionId !== null && session.id === currentSessionId
      }));
  }

  auditTail(limit = 100) {
    return this.#state.audit.slice(-limit).reverse();
  }

  // ---------------------------------------------------------------- user

  /**
   * @param {{username:string,passwordHash:string,totpSecretB32:string}} input
   */
  async createUser(input) {
    return this.#withLock(async () => {
      if (this.#state.user !== null) throw new Error('store: a user is already configured');
      const now = this.#now();
      this.#state.user = {
        username: input.username,
        passwordHash: input.passwordHash,
        totpSecretB32: input.totpSecretB32,
        totpConfirmedAt: null,
        createdAt: now
      };
      await this.#persistLocked();
      return this.#state.user;
    });
  }

  /**
   * Change the password and revoke every session *and every paired device*.
   * A credential rotation is a full reset of the trust surface: the old
   * password may have leaked together with device tokens, so devices must be
   * re-paired (new QR scan) before they can renew again.
   * @returns {Promise<{devicesRevoked:number,sessionsRevoked:number}>}
   */
  async setPasswordHash(passwordHash) {
    return this.#withLock(async () => {
      if (this.#state.user === null) throw new Error('store: no user configured');
      const devicesRevoked = this.#state.devices.length;
      const sessionsRevoked = this.#state.sessions.length;
      this.#state.user.passwordHash = passwordHash;
      this.#state.user.updatedAt = this.#now();
      this.#state.sessions = [];
      this.#state.devices = [];
      this.#state.tickets = [];
      await this.#persistLocked();
      return { devicesRevoked, sessionsRevoked };
    });
  }

  /**
   * Rotate the TOTP secret and revoke every session/device (see
   * {@link setPasswordHash}). The replay counter belongs to the old secret and
   * is reset with it.
   * @returns {Promise<{devicesRevoked:number,sessionsRevoked:number}>}
   */
  async resetTotp(totpSecretB32) {
    return this.#withLock(async () => {
      if (this.#state.user === null) throw new Error('store: no user configured');
      const devicesRevoked = this.#state.devices.length;
      const sessionsRevoked = this.#state.sessions.length;
      this.#state.user.totpSecretB32 = totpSecretB32;
      this.#state.user.totpConfirmedAt = null;
      this.#state.user.lastTotpCounter = null;
      this.#state.user.updatedAt = this.#now();
      this.#state.sessions = [];
      this.#state.devices = [];
      this.#state.tickets = [];
      await this.#persistLocked();
      return { devicesRevoked, sessionsRevoked };
    });
  }

  /**
   * Atomically accept a TOTP time-step exactly once. Rejects a counter that is
   * not strictly greater than the last accepted one (RFC 6238 §5.2 replay
   * defence). The check and the write happen under the store lock, so two
   * concurrent logins with the same code cannot both succeed.
   * @param {number} counter
   * @returns {Promise<boolean>}
   */
  async consumeTotpCounter(counter) {
    return this.#withLock(async () => {
      if (this.#state.user === null) return false;
      const last = Number.isSafeInteger(this.#state.user.lastTotpCounter)
        ? this.#state.user.lastTotpCounter
        : -1;
      if (!Number.isSafeInteger(counter) || counter <= last) return false;
      this.#state.user.lastTotpCounter = counter;
      this.#state.user.updatedAt = this.#now();
      await this.#persistLocked();
      return true;
    });
  }

  async confirmTotp(at = this.#now()) {
    return this.#withLock(async () => {
      if (this.#state.user === null || this.#state.user.totpConfirmedAt !== null) return;
      this.#state.user.totpConfirmedAt = at;
      await this.#persistLocked();
    });
  }

  // ---------------------------------------------------------- first-run setup

  /**
   * Rotate the one-time WebUI setup token. Only valid before initialization;
   * the token is 32 random bytes hex, stored 0600 in `$stateDir/setup.token`.
   * A rotated token invalidates any pending setup draft in the gateway because
   * that draft is bound to the old token.
   * @returns {Promise<string>}
   */
  async rotateSetupToken() {
    return this.#withLock(async () => {
      if (this.#state.user !== null) throw new Error('store: already configured');
      const token = randomBytes(SETUP_TOKEN_BYTES).toString('hex');
      await this.#writeSetupTokenFile(token);
      this.#setupToken = token;
      return token;
    });
  }

  /**
   * Remove the setup token after a successful initialization. Best effort:
   * once `configured` is true every setup route is closed even if the file
   * could not be unlinked, and the next startup retries the removal.
   */
  async clearSetupToken() {
    return this.#withLock(async () => {
      this.#setupToken = '';
      try {
        await fs.rm(this.#setupTokenFile, { force: true });
      } catch (error) {
        this.#logger.warn?.(`auth-gate: could not remove ${this.#setupTokenFile}: ${error.message}`);
      }
    });
  }

  /**
   * Atomically finish first-run setup: create the single user with an already
   * confirmed TOTP secret and bind the initial browser device in one state
   * write. This is equivalent to createUser → confirmTotp(now) → createDevice
   * but cannot leave a half-initialized account if the process dies between
   * the calls.
   * @param {{username:string,passwordHash:string,totpSecretB32:string,name:string,platform:string,origin:string,deviceTtlMs:number,maxDevices:number}} input
   * @returns {Promise<{status:'ok',device:object,token:string}|{status:'device_limit'}>}
   */
  async completeSetup(input) {
    return this.#withLock(async () => {
      if (this.#state.user !== null) throw new Error('store: a user is already configured');
      const now = this.#now();
      this.#pruneExpired(now, false);
      const active = this.#state.devices.filter((device) => device.expiresAt > now).length;
      if (active >= input.maxDevices) return { status: 'device_limit' };
      this.#state.user = {
        username: input.username,
        passwordHash: input.passwordHash,
        totpSecretB32: input.totpSecretB32,
        totpConfirmedAt: now,
        createdAt: now
      };
      const paired = this.#appendDeviceLocked(input, now);
      await this.#persistLocked();
      return { status: 'ok', ...paired };
    });
  }

  /**
   * Create one paired device (used by first-run setup; regular pairing goes
   * through {@link redeemTicket}).
   * @param {{name:string,platform:string,origin:string,deviceTtlMs:number,maxDevices:number}} input
   * @returns {Promise<{status:'ok',device:object,token:string}|{status:'device_limit'}>}
   */
  async createDevice(input) {
    return this.#withLock(async () => {
      const now = this.#now();
      this.#pruneExpired(now, false);
      const active = this.#state.devices.filter((device) => device.expiresAt > now).length;
      if (active >= input.maxDevices) return { status: 'device_limit' };
      const paired = this.#appendDeviceLocked(input, now);
      await this.#persistLocked();
      return { status: 'ok', ...paired };
    });
  }

  /** Caller must hold the store lock. */
  #appendDeviceLocked(input, now) {
    const token = randomToken('dt');
    const device = {
      id: randomId('d'),
      name: input.name,
      platform: input.platform,
      tokenHash: sha256Hex(token),
      origin: input.origin,
      createdAt: now,
      lastSeenAt: now,
      // v0.7.0: initial deadline = min(now + idle window, createdAt + absolute
      // ceiling). The absolute ceiling is stable for the device's whole life.
      expiresAt: slidingExpiry(now, input.deviceTtlMs, input.deviceAbsoluteTtlMs).expiresAt
    };
    this.#state.devices.push(device);
    return { device: { ...device, tokenHash: undefined }, token };
  }

  // ------------------------------------------------------------- tickets

  /**
   * Issue a single-use pairing ticket. Only its hash is persisted.
   * @param {{ttlMs:number}} input
   * @returns {Promise<{ticket:string,record:{id:string,ticketHash:string,createdAt:number,expiresAt:number}}>}
   */
  async issueTicket(input) {
    return this.#withLock(async () => {
      const now = this.#now();
      this.#pruneExpired(now, false);
      const ticket = randomToken('t');
      const record = {
        id: randomId('tk'),
        ticketHash: sha256Hex(ticket),
        createdAt: now,
        expiresAt: now + input.ttlMs
      };
      this.#state.tickets.push(record);
      await this.#persistLocked();
      return { ticket, record };
    });
  }

  /**
   * Atomically consume a ticket and create the paired device.
   * @param {string} ticketValue
   * @param {{maxDevices:number,deviceTtlMs:number,deviceAbsoluteTtlMs?:number,name:string,platform:string,origin:string}} input
   * @returns {Promise<{status:'ok',device:object,token:string}|{status:'invalid_ticket'|'expired_ticket'|'device_limit'}>}
   */
  async redeemTicket(ticketValue, input) {
    return this.#withLock(async () => {
      const now = this.#now();
      this.#pruneExpired(now, false);
      const hash = sha256Hex(ticketValue);
      const index = this.#state.tickets.findIndex((ticket) => safeEqualString(ticket.ticketHash, hash));
      if (index === -1) return { status: 'invalid_ticket' };
      const ticket = this.#state.tickets[index];
      if (ticket.expiresAt <= now) {
        this.#state.tickets.splice(index, 1);
        await this.#persistLocked();
        return { status: 'expired_ticket' };
      }
      const active = this.#state.devices.filter((device) => device.expiresAt > now);
      if (active.length >= input.maxDevices) return { status: 'device_limit' };
      this.#state.tickets.splice(index, 1);
      const token = randomToken('dt');
      const device = {
        id: randomId('d'),
        name: input.name,
        platform: input.platform,
        tokenHash: sha256Hex(token),
        origin: input.origin,
        createdAt: now,
        lastSeenAt: now,
        // The absolute ceiling starts at pairing time, not at first renewal.
        expiresAt: slidingExpiry(now, input.deviceTtlMs, input.deviceAbsoluteTtlMs).expiresAt
      };
      this.#state.devices.push(device);
      await this.#persistLocked();
      return { status: 'ok', device: { ...device, tokenHash: undefined }, token };
    });
  }

  // ------------------------------------------------------------- devices

  /**
   * Resolve a device by its opaque token.
   *
   * P2-3: besides the idle `expiresAt`, the device dies at
   * `createdAt + absoluteMs` when the caller supplies the active
   * `deviceAbsoluteTtlMs` (old state / lowered config cannot outlive it).
   * Hitting either ceiling removes the device *and all of its sessions*.
   * The returned copy never carries `tokenHash`.
   * @param {string} tokenValue
   * @param {{absoluteMs?:number}} [options] active device absolute ceiling (0/absent = none)
   * @returns {Promise<object|null>}
   */
  async findDeviceByToken(tokenValue, options = {}) {
    return this.#withLock(async () => {
      if (typeof tokenValue !== 'string' || tokenValue.length === 0) return null;
      const hash = sha256Hex(tokenValue);
      const now = this.#now();
      const device = this.#state.devices.find((candidate) => safeEqualString(candidate.tokenHash, hash));
      if (device === undefined) return null;
      if (device.expiresAt <= now || isDeviceAbsoluteExpired(device, now, options?.absoluteMs)) {
        this.#dropDevice(device.id);
        return null;
      }
      device.lastSeenAt = now;
      this.#dirty = true;
      this.#scheduleSave(5_000);
      return { ...device, tokenHash: undefined };
    });
  }

  /**
   * Find a device by id (session checks / admin APIs).
   *
   * P2-3: like {@link findDeviceByToken} this is a *read* path that must
   * enforce the active absolute ceiling; an old `expiresAt` in the future no
   * longer keeps the device (or any session of it) alive.
   * @param {string} deviceId
   * @param {{absoluteMs?:number}} [options] active device absolute ceiling (0/absent = none)
   * @returns {Promise<object|null>}
   */
  async findDeviceById(deviceId, options = {}) {
    if (typeof deviceId !== 'string' || deviceId.length === 0) return null;
    const now = this.#now();
    const device = this.#state.devices.find((candidate) => candidate.id === deviceId);
    if (device === undefined) return null;
    if (device.expiresAt <= now || isDeviceAbsoluteExpired(device, now, options?.absoluteMs)) {
      this.#dropDevice(device.id);
      return null;
    }
    return { ...device, tokenHash: undefined };
  }

  /** Remove one device and every session it owns (in-memory + debounced save). */
  #dropDevice(deviceId) {
    this.#state.devices = this.#state.devices.filter((candidate) => candidate.id !== deviceId);
    this.#state.sessions = this.#state.sessions.filter((session) => session.deviceId !== deviceId);
    this.#dirty = true;
    this.#scheduleSave();
  }

  /**
   * Slide a paired device's lifetime forward (v0.7.0 App renewal / password
   * login). The deadline becomes
   * `min(now + idleMs, createdAt + absoluteMs)` (absolute part only when
   * `absoluteMs > 0`), and the updated record is persisted *once* under the
   * store lock, so a burst of renew calls cannot interleave or write twice.
   *
   * @param {string} deviceId
   * @param {{idleMs:number,absoluteMs?:number}} input
   * @returns {Promise<{device:object,maxAgeSeconds:number}|null>} null when the
   *   device no longer exists or the absolute ceiling has already been reached
   *   (the caller must then answer 401 and the device/sessions are removed).
   */
  async extendDevice(deviceId, input) {
    return this.#withLock(async () => {
      const now = this.#now();
      const pruned = this.#pruneExpired(now, false);
      let device = this.#state.devices.find((candidate) => candidate.id === deviceId);
      if (device === undefined) {
        if (pruned) await this.#persistLocked();
        return null;
      }
      // The absolute ceiling is counted from pairing time, not from `now`.
      const absoluteMs = Number.isFinite(input.absoluteMs) && input.absoluteMs > 0 ? input.absoluteMs : 0;
      const ceiling = absoluteMs > 0 ? device.createdAt + absoluteMs : null;
      const idleExpiresAt = now + input.idleMs;
      const deadline = ceiling === null ? idleExpiresAt : Math.min(idleExpiresAt, ceiling);
      if (deadline <= now) {
        // The absolute ceiling has passed even though the last idle deadline
        // has not (e.g. a session issued shortly before the cap). Remove the
        // device and every session it owns: the credential is dead.
        this.#state.devices = this.#state.devices.filter((candidate) => candidate.id !== device.id);
        this.#state.sessions = this.#state.sessions.filter((session) => session.deviceId !== device.id);
        await this.#persistLocked();
        return null;
      }
      device.lastSeenAt = now;
      device.expiresAt = deadline;
      await this.#persistLocked();
      // P2-2: never hand the stored token hash back to callers.
      return { device: { ...device, tokenHash: undefined }, maxAgeSeconds: remainingSeconds(deadline, now) };
    });
  }

  /**
   * Revoke a device and every session it owns.
   *
   * v0.7.0 cascade guarantee: the device record, *all* of its sessions and
   * every pending pairing ticket are removed in the same locked state write.
   * The device token no longer resolves (renew 401), any session cookie of
   * that device stops authenticating on its very next request, and a ticket
   * minted before the revocation cannot pair a replacement device afterwards.
   *
   * The gateway writes the audit entry (it has the client IP / channel); this
   * method stays a pure state transition so embedders cannot double-audit.
   * @param {string} deviceId
   * @returns {Promise<boolean>}
   */
  async revokeDevice(deviceId) {
    return this.#withLock(async () => {
      const before = this.#state.devices.length;
      this.#state.devices = this.#state.devices.filter((device) => device.id !== deviceId);
      this.#state.sessions = this.#state.sessions.filter((session) => session.deviceId !== deviceId);
      if (this.#state.devices.length === before) return false;
      this.#state.tickets = [];
      await this.#persistLocked();
      return true;
    });
  }

  // ------------------------------------------------------------ sessions

  /**
   * Create a browser session. Besides the idle deadline (`expiresAt`) the
   * record carries a stable `absoluteExpiresAt` ceiling (null = no ceiling) and
   * `lastRefreshedAt`, both persisted so a restart keeps the same sliding
   * semantics.
   * @param {{deviceId:string,ttlMs:number,absoluteTtlMs?:number}} input
   * @returns {Promise<{session:object,token:string}>}
   */
  async createSession(input) {
    return this.#withLock(async () => {
      const now = this.#now();
      this.#pruneExpired(now, false);
      const token = randomToken('s');
      const deadline = slidingExpiry(now, input.ttlMs, input.absoluteTtlMs ?? 0);
      const session = {
        id: randomId('se'),
        tokenHash: sha256Hex(token),
        deviceId: input.deviceId,
        createdAt: now,
        lastSeenAt: now,
        lastRefreshedAt: now,
        absoluteExpiresAt: deadline.absoluteExpiresAt,
        expiresAt: deadline.expiresAt
      };
      this.#state.sessions.push(session);
      if (this.#state.sessions.length > 100) {
        this.#state.sessions.sort((left, right) => left.createdAt - right.createdAt);
        this.#state.sessions = this.#state.sessions.slice(-100);
      }
      await this.#persistLocked();
      return { session: { ...session, tokenHash: undefined }, token };
    });
  }

  /**
   * Resolve a session cookie for authentication.
   *
   * A session is invalid when either deadline has passed:
   *  - idle: `now >= expiresAt` (no request for the idle window);
   *  - absolute: `now >= absoluteExpiresAt` (the hard ceiling since creation,
   *    even if the session has been refreshed continuously).
   * Both checks live here — every entry point (`#sessionFromRequest`, admin,
   * reverse proxy, WebSocket) goes through this method.
   * Touches `lastSeenAt` in memory and persists at most once a minute so
   * ordinary traffic does not rewrite the state file.
   * @param {string} tokenValue
   * @returns {Promise<object|null>}
   */
  async findSession(tokenValue) {
    if (typeof tokenValue !== 'string' || tokenValue.length === 0) return null;
    const hash = sha256Hex(tokenValue);
    const now = this.#now();
    const session = this.#state.sessions.find((candidate) => safeEqualString(candidate.tokenHash, hash));
    if (session === undefined) return null;
    const absoluteExpiresAt = Number.isFinite(session.absoluteExpiresAt) ? session.absoluteExpiresAt : null;
    if (session.expiresAt <= now || (absoluteExpiresAt !== null && absoluteExpiresAt <= now)) {
      this.#state.sessions = this.#state.sessions.filter((candidate) => candidate.id !== session.id);
      this.#dirty = true;
      this.#scheduleSave();
      return null;
    }
    session.lastSeenAt = now;
    if (now - this.#lastSessionTouchWrite > 60_000) {
      this.#lastSessionTouchWrite = now;
      this.#dirty = true;
      this.#scheduleSave(30_000);
    }
    return { ...session };
  }

  /**
   * Sliding renewal for an already-authenticated HTTP request (v0.7.0).
   *
   * The refresh is due when either
   *  - `now - lastRefreshedAt >= min(1h, idle/2)` (periodic), or
   *  - the remaining lifetime is below `idle/2`.
   * When due, `expiresAt = min(now + idle, createdAt + absolute)` and
   * `lastRefreshedAt = now`, persisted in exactly one locked write. The
   * caller re-issues the cookie with `maxAgeSeconds` (same token value).
   *
   * The fast path avoids the store lock for the common case (not due); the
   * locked path re-checks the decision so concurrent requests cannot refresh
   * twice. A session that reached its absolute ceiling is removed and `null`
   * is returned: the request must be treated as unauthenticated.
   *
   * @param {string} tokenValue
   * @param {{idleTtlMs:number,absoluteTtlMs?:number,minIntervalMs?:number}} input
   * @returns {Promise<{refreshed:boolean,session:object,maxAgeSeconds:number}|null>}
   */
  async refreshSession(tokenValue, input) {
    if (typeof tokenValue !== 'string' || tokenValue.length === 0) return null;
    const hash = sha256Hex(tokenValue);
    const now = this.#now();
    const current = this.#state.sessions.find((candidate) => safeEqualString(candidate.tokenHash, hash));
    if (current === undefined) return null;
    const absolute = Number.isFinite(current.absoluteExpiresAt) ? current.absoluteExpiresAt : null;
    if (current.expiresAt <= now || (absolute !== null && absolute <= now)) return null;
    const idleExpiresAt = now + input.idleTtlMs;
    const newExpiresAt = absolute === null ? idleExpiresAt : Math.min(idleExpiresAt, absolute);
    const lastRefreshedAt = Number.isFinite(current.lastRefreshedAt) ? current.lastRefreshedAt : current.createdAt;
    const interval = Number.isFinite(input.minIntervalMs) ? Math.max(0, input.minIntervalMs) : Math.min(3_600_000, input.idleTtlMs / 2);
    const canExtend = absolute === null || absolute - now > input.idleTtlMs / 2;
    const due = now - lastRefreshedAt >= interval || (newExpiresAt - now < input.idleTtlMs / 2 && canExtend);
    if (!due) return { refreshed: false, session: { ...current }, maxAgeSeconds: remainingSeconds(newExpiresAt, now) };

    return this.#withLock(async () => {
      const lockedNow = this.#now();
      const session = this.#state.sessions.find((candidate) => candidate.id === current.id);
      if (session === undefined) return null;
      const lockedAbsolute = Number.isFinite(session.absoluteExpiresAt) ? session.absoluteExpiresAt : null;
      if (session.expiresAt <= lockedNow || (lockedAbsolute !== null && lockedAbsolute <= lockedNow)) {
        this.#state.sessions = this.#state.sessions.filter((candidate) => candidate.id !== session.id);
        await this.#persistLocked();
        return null;
      }
      // Recompute with the config submitted by the caller. `absoluteTtlMs` also
      // (re)establishes a ceiling for sessions created by an older version that
      // did not persist `absoluteExpiresAt` yet.
      const ceiling =
        Number.isFinite(input.absoluteTtlMs) && input.absoluteTtlMs > 0
          ? session.createdAt + input.absoluteTtlMs
          : lockedAbsolute;
      const lockedIdle = lockedNow + input.idleTtlMs;
      const deadline = ceiling === null ? lockedIdle : Math.min(lockedIdle, ceiling);
      if (deadline <= lockedNow) {
        this.#state.sessions = this.#state.sessions.filter((candidate) => candidate.id !== session.id);
        await this.#persistLocked();
        return null;
      }
      const last = Number.isFinite(session.lastRefreshedAt) ? session.lastRefreshedAt : session.createdAt;
      const remaining = deadline - lockedNow;
      const canExtendLocked = ceiling === null || ceiling - lockedNow > input.idleTtlMs / 2;
      if (lockedNow - last < interval && (!(remaining < input.idleTtlMs / 2) || !canExtendLocked)) {
        // Another concurrent request already refreshed this session.
        return { refreshed: false, session: { ...session }, maxAgeSeconds: remainingSeconds(deadline, lockedNow) };
      }
      session.expiresAt = deadline;
      session.absoluteExpiresAt = ceiling;
      session.lastRefreshedAt = lockedNow;
      session.lastSeenAt = lockedNow;
      await this.#persistLocked();
      return { refreshed: true, session: { ...session }, maxAgeSeconds: remainingSeconds(deadline, lockedNow) };
    });
  }

  /** @param {string} tokenValue @returns {Promise<boolean>} */
  async deleteSession(tokenValue) {
    return this.#withLock(async () => {
      const hash = sha256Hex(tokenValue);
      const before = this.#state.sessions.length;
      this.#state.sessions = this.#state.sessions.filter((session) => !safeEqualString(session.tokenHash, hash));
      if (this.#state.sessions.length === before) return false;
      await this.#persistLocked();
      return true;
    });
  }

  /** @param {string} deviceId */
  async deleteSessionsForDevice(deviceId) {
    return this.#withLock(async () => {
      this.#state.sessions = this.#state.sessions.filter((session) => session.deviceId !== deviceId);
      await this.#persistLocked();
    });
  }

  // --------------------------------------------------------------- audit

  /**
   * Append an audit event. Never pass passwords, TOTP codes, tickets or device
   * tokens here; callers only record coarse reasons.
   * @param {{type:string,ip?:string,deviceId?:string,detail?:string}} entry
   */
  recordAudit(entry) {
    const at = this.#now();
    this.#state.audit.push({
      at,
      type: String(entry.type ?? 'unknown').slice(0, 32),
      ip: String(entry.ip ?? '').slice(0, 64),
      deviceId: String(entry.deviceId ?? '').slice(0, 64),
      detail: String(entry.detail ?? '').slice(0, 160)
    });
    if (this.#state.audit.length > this.#auditLimit) this.#state.audit = this.#state.audit.slice(-this.#auditLimit);
    this.#dirty = true;
    this.#scheduleSave();
  }

  // ----------------------------------------------------------- persistence

  /** Flush pending changes to disk. */
  async flush() {
    if (!this.#dirty) {
      await this.#writeTail;
      return;
    }
    await this.#enqueueWrite();
  }

  async close() {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#saveTimer !== null) {
      clearTimeout(this.#saveTimer);
      this.#saveTimer = null;
    }
    if (this.#maintenanceTimer !== null) {
      clearInterval(this.#maintenanceTimer);
      this.#maintenanceTimer = null;
    }
    try {
      await this.flush();
    } finally {
      this.#state.sessions = this.#state.sessions.filter((session) => session.expiresAt > this.#now());
    }
  }

  #withLock(fn) {
    const run = this.#lockTail.then(
      () => fn(),
      () => fn()
    );
    this.#lockTail = run.catch(() => {});
    return run;
  }

  #enqueueWrite() {
    this.#writeTail = this.#writeTail.then(
      () => this.#writeState(),
      () => this.#writeState()
    );
    return this.#writeTail;
  }

  async #persistLocked() {
    this.#dirty = false;
    await this.#enqueueWrite();
  }

  #scheduleSave(delayMs = 250) {
    if (this.#closed) return;
    if (this.#saveTimer !== null) return;
    this.#saveTimer = setTimeout(() => {
      this.#saveTimer = null;
      if (!this.#dirty) return;
      this.#dirty = false;
      this.#enqueueWrite().catch((error) => {
        this.#dirty = true;
        this.#logger.error?.(`auth-gate: could not persist state: ${error.message}`);
      });
    }, delayMs);
    this.#saveTimer.unref?.();
  }

  async #writeState() {
    const json = `${JSON.stringify(this.#state, null, 2)}\n`;
    const tmp = path.join(this.#options.stateDir, `.state.json.tmp-${process.pid}-${randomBytes(6).toString('hex')}`);
    const handle = await fs.open(tmp, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    try {
      await handle.writeFile(json, 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await fs.rename(tmp, this.#stateFile);
      await fs.chmod(this.#stateFile, 0o600);
      const dirHandle = await fs.open(this.#options.stateDir, 'r');
      try {
        await dirHandle.sync();
      } finally {
        await dirHandle.close();
      }
    } catch (error) {
      await fs.rm(tmp, { force: true });
      throw error;
    }
  }

  async #loadState() {
    let raw;
    try {
      raw = await fs.readFile(this.#stateFile, 'utf8');
    } catch (error) {
      if (error.code === 'ENOENT') return initialState();
      throw new Error(`auth-gate: cannot read state file ${this.#stateFile}: ${error.message}`);
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new Error(`auth-gate: state file ${this.#stateFile} is not valid JSON (${error.message}); refusing to start and refusing to reset it`);
    }
    validateState(parsed, this.#stateFile);
    const stat = await fs.stat(this.#stateFile);
    if ((stat.mode & 0o077) !== 0) {
      await fs.chmod(this.#stateFile, 0o600);
      this.#logger.warn?.(`auth-gate: tightened permissions on ${this.#stateFile} to 0600`);
    }
    return parsed;
  }

  async #loadOrCreateAdminKey() {
    try {
      const raw = (await fs.readFile(this.#adminKeyFile, 'utf8')).trim();
      if (!ADMIN_KEY_PATTERN.test(raw)) throw new Error(`auth-gate: admin key file ${this.#adminKeyFile} does not contain 32 bytes of hex; refusing to start`);
      const stat = await fs.stat(this.#adminKeyFile);
      if ((stat.mode & 0o077) !== 0) await fs.chmod(this.#adminKeyFile, 0o600);
      return raw;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    await fs.mkdir(path.dirname(this.#adminKeyFile), { recursive: true, mode: 0o700 });
    const key = randomBytes(ADMIN_KEY_BYTES).toString('hex');
    const tmp = `${this.#adminKeyFile}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
    const handle = await fs.open(tmp, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    try {
      await handle.writeFile(`${key}\n`, 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    await fs.rename(tmp, this.#adminKeyFile);
    await fs.chmod(this.#adminKeyFile, 0o600);
    // Printed exactly once, on first start. The file is 0600; this line exists
    // so the operator can save the key in a password manager.
    // Never print the key itself: journald/syslog is often readable by more
    // principals than the 0600 file. Only a fingerprint hint and the path.
    this.#logger.info?.(
      `auth-gate: generated admin key ${'*'.repeat(56)}${key.slice(-8)} ` +
        `(stored 0600 at ${this.#adminKeyFile}; read it from that file, not the log)`
    );
    return key;
  }

  /**
   * Load an existing setup token (reused across restarts) or create one.
   * Configured deployments never expose a token: a leftover file from a crash
   * between `completeSetup` and `clearSetupToken` is removed here.
   * @returns {Promise<string>}
   */
  async #loadOrCreateSetupToken() {
    if (this.#state.user !== null) {
      try {
        await fs.rm(this.#setupTokenFile, { force: true });
      } catch (error) {
        this.#logger.warn?.(`auth-gate: could not remove stale ${this.#setupTokenFile}: ${error.message}`);
      }
      return '';
    }
    let token = '';
    try {
      const raw = (await fs.readFile(this.#setupTokenFile, 'utf8')).trim();
      if (SETUP_TOKEN_PATTERN.test(raw)) token = raw;
      else this.#logger.warn?.(`auth-gate: setup token file ${this.#setupTokenFile} is invalid; replacing it`);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    if (token === '') {
      token = randomBytes(SETUP_TOKEN_BYTES).toString('hex');
      await this.#writeSetupTokenFile(token);
      return token;
    }
    const stat = await fs.stat(this.#setupTokenFile);
    if ((stat.mode & 0o077) !== 0) await fs.chmod(this.#setupTokenFile, 0o600);
    return token;
  }

  /** @param {string} token */
  async #writeSetupTokenFile(token) {
    await fs.mkdir(path.dirname(this.#setupTokenFile), { recursive: true, mode: 0o700 });
    const tmp = `${this.#setupTokenFile}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`;
    const handle = await fs.open(tmp, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    try {
      await handle.writeFile(`${token}\n`, 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await fs.rename(tmp, this.#setupTokenFile);
      await fs.chmod(this.#setupTokenFile, 0o600);
    } catch (error) {
      await fs.rm(tmp, { force: true });
      throw error;
    }
  }

  #pruneExpired(now, markDirty) {
    const beforeTickets = this.#state.tickets.length;
    const beforeDevices = this.#state.devices.length;
    const beforeSessions = this.#state.sessions.length;
    // Keep recently expired tickets for a short grace period so redemption can
    // answer `expired_ticket` instead of the indistinguishable `invalid_ticket`.
    this.#state.tickets = this.#state.tickets.filter((ticket) => ticket.expiresAt + 10 * 60_000 > now);
    const revokedDevices = new Set(
      this.#state.devices.filter((device) => device.expiresAt <= now).map((device) => device.id)
    );
    if (revokedDevices.size > 0) {
      this.#state.devices = this.#state.devices.filter((device) => device.expiresAt > now);
      this.#state.sessions = this.#state.sessions.filter((session) => !revokedDevices.has(session.deviceId));
    }
    this.#state.sessions = this.#state.sessions.filter((session) => session.expiresAt > now && !isAbsoluteExpired(session, now));
    const changed =
      beforeTickets !== this.#state.tickets.length ||
      beforeDevices !== this.#state.devices.length ||
      beforeSessions !== this.#state.sessions.length;
    if (changed && markDirty) this.#dirty = true;
    return changed;
  }

  async #runMaintenance() {
    const changed = this.#pruneExpired(this.#now(), false);
    if (changed) {
      this.#dirty = true;
      this.#scheduleSave(0);
    }
  }
}

/** @param {unknown} state @param {string} file */
function validateState(state, file) {
  const fail = (reason) => {
    throw new Error(`auth-gate: state file ${file} is invalid (${reason}); refusing to start and refusing to reset it`);
  };
  if (state === null || typeof state !== 'object' || Array.isArray(state)) fail('not an object');
  if (state.version !== STATE_VERSION) fail(`unsupported version ${JSON.stringify(state.version)}`);
  for (const key of ['devices', 'tickets', 'sessions', 'audit']) {
    if (!Array.isArray(state[key])) fail(`"${key}" is not an array`);
  }
  if (state.user !== null) {
    if (typeof state.user !== 'object' || state.user === null || Array.isArray(state.user)) fail('"user" is invalid');
    for (const key of ['username', 'passwordHash', 'totpSecretB32']) {
      if (typeof state.user[key] !== 'string' || state.user[key].length === 0) fail(`user.${key} is missing`);
    }
    if (!/^[A-Z2-7]{16,128}$/u.test(state.user.totpSecretB32)) fail('user.totpSecretB32 is not valid base32');
    if (state.user.lastTotpCounter !== undefined && state.user.lastTotpCounter !== null && !Number.isSafeInteger(state.user.lastTotpCounter)) {
      fail('user.lastTotpCounter is invalid');
    }
  }
  for (const device of state.devices) {
    for (const key of ['id', 'name', 'platform', 'tokenHash', 'origin']) {
      if (typeof device[key] !== 'string') fail(`device.${key} is invalid`);
    }
    for (const key of ['createdAt', 'lastSeenAt', 'expiresAt']) {
      if (!Number.isFinite(device[key])) fail(`device.${key} is invalid`);
    }
  }
  for (const ticket of state.tickets) {
    if (typeof ticket.ticketHash !== 'string' || !Number.isFinite(ticket.expiresAt)) fail('ticket record is invalid');
  }
  for (const session of state.sessions) {
    if (typeof session.tokenHash !== 'string' || !Number.isFinite(session.expiresAt)) fail('session record is invalid');
    if (session.lastRefreshedAt !== undefined && session.lastRefreshedAt !== null && !Number.isFinite(session.lastRefreshedAt)) {
      fail('session.lastRefreshedAt is invalid');
    }
    if (session.absoluteExpiresAt !== undefined && session.absoluteExpiresAt !== null && !Number.isFinite(session.absoluteExpiresAt)) {
      fail('session.absoluteExpiresAt is invalid');
    }
  }
}

export { initialState as _initialStateForTests };
