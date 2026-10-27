/**
 * dsh-auth-gate — dsh Web GUI client half (v0.4.2).
 *
 * Hand-written client bundle in the same lazy-CJS shape the dsh build emits:
 * `window.__ModuleLoader__.load({ id, factory })` registers the factory; the
 * module body only runs when the Loader materializes the entry. Besides
 * `react`, the bundle requires `@deepseek-ai/dsh-client-ui-primitives`, which
 * the dsh Web shell always exposes in its module table (the shipped sidebar
 * does the same), so the panel is built from the real design system instead of
 * an iframe.
 *
 * Registrations (unchanged from 0.2.0):
 *   - `sidebar.panellist` — the "认证管理" glyph in the sidebar's global-panel
 *     list; the sidebar owns the click and calls
 *     `ctx.layout.selectPanel("auth-gate")`.
 *   - `main` keyed slot (`auth-gate`) — the native management panel rendered in
 *     the centre column.
 *
 * The panel talks to the gateway with the browser's own same-origin cookies:
 * `GET /__auth/csrf` (double-submit token), `GET /__auth/whoami`,
 * `GET /__admin/api/state`, `POST /__admin/api/qr`,
 * `POST /__admin/api/user`, `POST /__admin/api/devices/revoke` and
 * `GET /__admin/api/audit`. Every response is rendered as React text (no HTML
 * injection); the only `dangerouslySetInnerHTML` is the server-generated QR
 * SVG, validated first.
 *
 * Degradation:
 *   - not on the gateway origin (e.g. dsh opened directly on :3080) → a short
 *     explanation card and a link to https://<host>:3443/__admin; no API calls;
 *   - no session / expired session → "未登录 / 去登录" CTA with the current
 *     path as `next` (full-page navigation);
 *   - local loopback visitors (whoami anonymous but /__admin reachable) keep
 *     working through the gateway's loopback channel;
 *   - HTTP 429 → countdown from `retry-after`; HTTP 401/403 → stop polling and
 *     show the login entry instead of retrying.
 *
 * Registrations run inside `ctx.slots.inject(...)`, whose callback is wrapped
 * in a ctx.effect: unloading the plugin fiber disposes both entries. Timers and
 * DOM listeners created by the panel are owned by React effects and cleaned up
 * on unmount; the only global node is one idempotent `<style>` tag scoped to
 * this plugin.
 *
 * v0.4.2 robustness:
 *   - the panel is wrapped in a React error boundary, so a render crash shows
 *     a readable card (message + first 1500 chars of the stack) and logs
 *     `[auth-gate] render failed` to the Console instead of a blank panel;
 *   - every primitives binding is validated and individually guarded, with a
 *     local DOM/`--dsw-*` fallback when the export is missing or throws;
 *   - `?authgate-debug=1` / `#authgate-debug` adds a diagnostic card with the
 *     location, React version, primitives exports and panel phase.
 */

window.__ModuleLoader__.load({
  id: 'dsh-auth-gate',
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;
    Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });

    const React = require('react');
    const h = React.createElement;

    /** Console prefix for every diagnostic line this bundle prints. */
    const LOG_PREFIX = '[auth-gate]';

    /** `console.*` must never be the reason the panel fails. */
    function logError(message, detail) {
      try {
        if (detail === undefined) console.error(LOG_PREFIX + ' ' + message);
        else console.error(LOG_PREFIX + ' ' + message, detail);
      } catch {
        // console is best-effort only
      }
    }

    function logInfo(message, detail) {
      try {
        if (detail === undefined) console.info(LOG_PREFIX + ' ' + message);
        else console.info(LOG_PREFIX + ' ' + message, detail);
      } catch {
        // console is best-effort only
      }
    }

    /**
     * The shell module table exposes the primitives package; keep a guarded
     * require so an older/partial dsh build degrades to small local fallbacks
     * instead of losing the whole sidebar entry. Some loader builds expose the
     * values under `default`, so merge that object in when present.
     */
    let primitives = {};
    let primitivesLoaded = false;
    let primitivesError = '';
    try {
      const loaded = require('@deepseek-ai/dsh-client-ui-primitives');
      if (loaded !== null && typeof loaded === 'object') {
        const defaults = loaded.default !== null && typeof loaded.default === 'object' ? loaded.default : {};
        primitives = Object.assign({}, defaults, loaded);
        primitivesLoaded = true;
      } else if (typeof loaded === 'function') {
        primitivesLoaded = true;
      } else {
        primitivesError = 'module is ' + typeof loaded;
      }
    } catch (error) {
      primitives = {};
      primitivesError = error !== null && typeof error === 'object' && typeof error.message === 'string' ? error.message : String(error);
    }

    /** A component is renderable when it is a function or a memo/forwardRef object. */
    function isRenderableComponent(value) {
      if (typeof value === 'function') return true;
      return value !== null && typeof value === 'object' && typeof value.$$typeof === 'symbol';
    }

    /** Snapshot of the primitives situation for the debug card. */
    function primitivesDiagnostics() {
      let keys = [];
      try {
        keys = Object.keys(primitives).filter((key) => key !== 'default').slice(0, 40);
      } catch {
        keys = [];
      }
      return {
        loaded: primitivesLoaded,
        error: primitivesError,
        keys,
        bindings: Object.assign({}, PRIMITIVE_BINDINGS)
      };
    }

    /** Which bindings are real vs local fallbacks (filled while binding). */
    const PRIMITIVE_BINDINGS = {};

    /** Locale namespace (labels are literal here; no dictionary package needed). */
    const NS = 'auth-gate';
    /** Stable id shared by the sidebar entry and the `main` keyed slot. */
    const PANEL_ID = 'auth-gate';
    /** Public port of the auth gateway; the panel only works same-origin. */
    const GATEWAY_PORT = '3443';
    /** Management page path on the gateway. */
    const ADMIN_PATH = '/__admin';
    /** Services required before apply(): the slot registry. */
    const inject = ['slots'];
    /** State refresh cadence; paused while the document is hidden. */
    const POLL_INTERVAL_MS = 20_000;
    /** Audit table keeps the server's newest-first 100 rows. */
    const AUDIT_LIMIT = 100;
    /** Transient toast lifetime. */
    const TOAST_MS = 6_000;

    /** Error-code → user-facing sentence. Never interpolates server text. */
    const MESSAGES = Object.freeze({
      forbidden: '当前访问通道无权管理认证网关，请通过网关重新登录。',
      not_configured: '认证网关尚未初始化。',
      no_user: '认证网关尚未初始化管理员账号。',
      invalid_current_password: '当前密码不正确。',
      current_password_required: '请输入当前密码。',
      totp_required: '请输入 6 位动态验证码。',
      totp_invalid: '动态验证码不正确或已过期。',
      csrf_invalid: '安全校验失败，请刷新页面后重试。',
      rate_limited: '操作过于频繁，请稍后再试。',
      device_not_found: '设备不存在或已被吊销。',
      weak_password: '新密码强度不足（至少 10 位）。',
      bad_request: '请求参数无效。',
      invalid_listen_host: '监听地址无效：必须是本机 LAN 网卡的具体 IPv4/IPv6 字面量，不能是 0.0.0.0、:: 等通配地址。',
      listen_host_loopback_not_allowed: '监听地址不能是 loopback（127.0.0.1 / ::1）：本机 frp/反代会让公网访客被当成管理员。请改填本机 LAN 网卡地址，并把 frpc 的 local_ip 改成同一地址。',
      invalid_listen_port: '监听端口无效：必须是 1–65535，且不能等于 dsh 上游端口。',
      invalid_public_url: '对外地址无效：必须是 http(s)://host[:port]，不能带路径/查询/片段/凭据，且协议需与 TLS 状态一致。',
      invalid_public_fingerprint: '对外证书指纹无效：留空表示使用网关自身证书，否则必须是 64 位十六进制 SHA-256。',
      fingerprint_fetch_failed: '无法从对外地址读取证书指纹：请确认 publicUrl 是 https 且当前可从网关访问；读取失败不会保存任何修改。',
      rebind_failed: '监听地址/端口重建失败，已回滚到原地址。',
      network_persist_failed: '网络设置保存失败，未生效。',
      no_changes: '没有需要保存的网络设置修改。',
      origin_changed: '设备绑定的对外地址已变更，请重新配对。',
      unsupported_media_type: '请求格式无效。',
      not_found: '接口不存在。',
      network: '无法连接认证网关，请确认页面从网关端口 3443 打开且网络正常。'
    });

    /** Audit event type → short Chinese label. Unknown types stay verbatim. */
    const AUDIT_LABELS = Object.freeze({
      login_ok: '登录成功',
      login_fail: '登录失败',
      pair_redeem: '设备配对',
      admin_change: '管理变更',
      admin_denied: '管理拒绝',
      device_revoke: '设备吊销'
    });

    /** Platform slug → display label; unknown values are shown as-is. */
    const PLATFORM_LABELS = Object.freeze({
      android: '安卓',
      web: '浏览器',
      ios: 'iOS',
      desktop: '桌面端'
    });

    // ------------------------------------------------------------- utilities

    /** Absolute URL of the gateway management page on the current host. */
    function gatewayAdminUrl() {
      // `location.hostname` keeps IPv6 brackets, so concatenation is safer
      // than URL rewriting of the current location.
      return 'https://' + window.location.hostname + ':' + GATEWAY_PORT + ADMIN_PATH;
    }

    /** True when this document itself is served by the gateway (same origin). */
    function isGatewayOrigin() {
      return window.location.port === GATEWAY_PORT;
    }

    /** Full-page login URL that returns to the current panel after success. */
    function loginUrl() {
      const next = window.location.pathname + window.location.search;
      return '/__auth/login?next=' + encodeURIComponent(next);
    }

    /** Navigate the whole document (the gateway login page is not a React route). */
    function goToLogin() {
      window.location.assign(loginUrl());
    }

    /** `YYYY/MM/DD HH:mm:ss` in the browser locale's zh-CN rendering. */
    function formatTime(value) {
      if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return '—';
      try {
        return new Date(value).toLocaleString('zh-CN', { hour12: false });
      } catch {
        try {
          return new Date(value).toISOString();
        } catch {
          return '—';
        }
      }
    }

    /** Human countdown, e.g. "1 分 05 秒". */
    function formatRemaining(totalSeconds) {
      const seconds = Math.max(0, Math.ceil(totalSeconds));
      const minutes = Math.floor(seconds / 60);
      const rest = seconds % 60;
      if (minutes <= 0) return rest + ' 秒';
      return minutes + ' 分 ' + String(rest).padStart(2, '0') + ' 秒';
    }

    /** Platform slug → label (never trusts the value to be a known slug). */
    function platformLabel(value) {
      if (typeof value !== 'string' || value.length === 0) return '未知';
      return PLATFORM_LABELS[value.toLowerCase()] ?? value;
    }

    /** Tag tone for a platform badge. */
    function platformTone(value) {
      if (value === 'android') return 'info';
      if (value === 'web') return 'neutral';
      return 'outline';
    }

    /** Audit type label. */
    function auditLabel(type) {
      if (typeof type !== 'string' || type.length === 0) return '—';
      return AUDIT_LABELS[type] ?? type;
    }

    /** Map a thrown request error to a safe display sentence. */
    function errorText(error) {
      if (!error) return '操作失败。';
      if (typeof error.code === 'string' && MESSAGES[error.code] !== undefined) return MESSAGES[error.code];
      if (error.status === 429) return '操作过于频繁，请稍后再试。';
      if (error.code === 'network' || error.status === undefined) return MESSAGES.network;
      return '操作失败（' + (error.code || 'HTTP ' + error.status) + '）。';
    }

    /** 401/403 that mean "this channel no longer has admin access". */
    function isAuthFailure(error) {
      if (!error) return false;
      if (error.status === 401) return true;
      return error.status === 403 && (error.code === 'forbidden' || error.code === 'not_configured');
    }

    /**
     * The only HTML the panel injects: the gateway's own QR SVG. Validate the
     * envelope and reject scripts, event handlers, foreignObject and URLs with
     * a javascript: scheme before handing it to React.
     */
    function sanitizeQrSvg(value) {
      if (typeof value !== 'string') return '';
      const svg = value.trim();
      if (svg.length < 20 || svg.length > 200_000) return '';
      if (!/^<svg[\s>]/i.test(svg) || !/<\/svg>$/i.test(svg)) return '';
      if (/<script[\s>]/i.test(svg)) return '';
      if (/<foreignObject[\s>]/i.test(svg)) return '';
      if (/\son[a-z]+\s*=/i.test(svg)) return '';
      if (/javascript:/i.test(svg)) return '';
      return svg;
    }

    /**
     * One JSON request against the gateway.
     *
     * Every call is same-origin and carries cookies (`credentials`); mutations
     * additionally send the double-submit CSRF header. No response is cached.
     * The thrown error carries only status/code/retryAfter — never a body that
     * could contain secrets.
     *
     * @param {string} path
     * @param {{method?:string, body?:unknown, csrf?:string}} [options]
     * @returns {Promise<Record<string, unknown>>}
     */
    async function requestJson(path, options = {}) {
      const method = options.method || 'GET';
      const headers = { accept: 'application/json' };
      if (method !== 'GET') headers['x-auth-gate-csrf'] = typeof options.csrf === 'string' ? options.csrf : '';
      let body;
      if (options.body !== undefined) {
        headers['content-type'] = 'application/json';
        body = JSON.stringify(options.body);
      }
      let response;
      try {
        response = await fetch(path, {
          method,
          credentials: 'same-origin',
          cache: 'no-store',
          headers,
          body
        });
      } catch {
        const error = new Error('network');
        error.code = 'network';
        throw error;
      }
      let data = {};
      try {
        const parsed = await response.json();
        if (parsed !== null && typeof parsed === 'object') data = parsed;
      } catch {
        data = {};
      }
      if (!response.ok) {
        const code = typeof data.error === 'string' ? data.error : '';
        const error = new Error(code || 'http_' + response.status);
        error.status = response.status;
        error.code = code;
        if (response.status === 429) {
          const raw = response.headers && typeof response.headers.get === 'function' ? Number(response.headers.get('retry-after')) : NaN;
          error.retryAfter = Number.isFinite(raw) && raw > 0 ? Math.ceil(raw) : 60;
        }
        throw error;
      }
      return data;
    }

    /**
     * Public first-run probe. The gateway answers this without a session, so
     * the panel can tell "not initialized yet" apart from "not logged in"
     * without touching any authenticated API.
     * @returns {Promise<object>}
     */
    async function loadSetupStatus() {
      const status = await requestJson('/__admin/api/setup/status');
      return status !== null && typeof status === 'object' ? status : {};
    }

    /**
     * Decide whether this document is served by the auth gateway. `location.port`
     * is only a fast path: the gateway may be published through frp on another
     * port (or on 443 via a custom domain), so the authoritative probe is the
     * gateway's own public status endpoint. A dsh page opened directly on :3080
     * either 401s that path or returns HTML, and therefore fails the probe.
     * @returns {Promise<boolean>}
     */
    async function probeGatewayOrigin() {
      try {
        const status = await loadSetupStatus();
        return typeof status.configured === 'boolean';
      } catch {
        return false;
      }
    }

    /** Clipboard write with the same fallback chain as the design system. */
    async function copyToClipboard(text) {
      const fromPrimitives = primitiveWriteClipboard(text);
      if (fromPrimitives !== null) {
        try {
          if (await fromPrimitives) return true;
        } catch {
          // fall through to the local implementation
        }
      }
      try {
        if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
          await navigator.clipboard.writeText(text);
          return true;
        }
      } catch {
        // fall through
      }
      try {
        const area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        const ok = typeof document.execCommand === 'function' ? document.execCommand('copy') : false;
        area.remove();
        return ok === true;
      } catch {
        return false;
      }
    }

    // --------------------------------------------------------- design tokens

    /**
     * Layout/table/card styles. Every colour, radius, font and border comes
     * from the live dsh theme (`--dsw-*`), so light/dark follow the app. The
     * primitives (Button/Input/SegmentedControl/SegmentedTabs/Tag/icons) keep
     * their own shipped design-system styles.
     */
    const PLUGIN_CSS = `
.ag-root{display:flex;flex-direction:column;flex:1 1 auto;min-height:0;width:100%;height:100%;background:var(--dsw-alias-bg-base,transparent);color:var(--dsw-alias-label-primary);font:var(--dsw-font-s-14,14px/22px sans-serif);}
.ag-header{display:flex;align-items:flex-start;gap:12px;flex-wrap:wrap;flex:0 0 auto;padding:12px 18px;border-bottom:.5px solid var(--dsw-alias-border-l2);}
.ag-title-wrap{display:flex;flex-direction:column;gap:6px;min-width:0;flex:1 1 320px;}
.ag-title{display:flex;align-items:center;gap:8px;margin:0;font:var(--dsw-font-m-18,600 18px/26px sans-serif);color:var(--dsw-alias-label-primary);}
.ag-title svg{color:var(--dsw-alias-label-secondary);}
.ag-status{display:flex;align-items:center;gap:8px;flex-wrap:wrap;min-width:0;color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:18px;}
.ag-origin{display:inline-flex;align-items:center;gap:4px;min-width:0;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--dsw-alias-label-tertiary);}
.ag-origin svg{flex:none;}
.ag-header-actions{display:flex;align-items:center;gap:8px;margin-left:auto;}
.ag-admin-link{display:inline-flex;align-items:center;gap:4px;color:var(--dsw-alias-link);font-size:12px;line-height:18px;text-decoration:none;white-space:nowrap;border-radius:var(--dsw-radius-sm);padding:2px 4px;}
.ag-admin-link:hover{background:var(--dsw-alias-interactive-bg-hover);}
.ag-admin-link:focus-visible{outline:var(--dsw-focus-ring-width) solid var(--dsw-focus-ring-color,var(--dsw-alias-state-business-primary));outline-offset:2px;}
.ag-scroll{flex:1 1 auto;min-height:0;overflow:auto;scrollbar-color:var(--dsw-alias-scrollbar-bg-l2) transparent;}
.ag-body{width:100%;max-width:1040px;margin:0 auto;padding:16px 18px 32px;box-sizing:border-box;display:flex;flex-direction:column;gap:14px;}
.ag-tabs{margin:0 0 2px;}
.ag-card{display:flex;flex-direction:column;gap:12px;background:var(--dsw-alias-bg-layer-1);border:.5px solid var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-lg);padding:16px;box-sizing:border-box;min-width:0;}
.ag-card-head{display:flex;flex-direction:column;gap:4px;}
.ag-card-title{display:flex;align-items:center;gap:8px;margin:0;font:var(--dsw-font-s-strong-14,600 14px/22px sans-serif);color:var(--dsw-alias-label-primary);}
.ag-card-desc{margin:0;color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:18px;}
.ag-subtitle{margin:0;font:var(--dsw-font-s-strong-14,600 14px/22px sans-serif);color:var(--dsw-alias-label-primary);}
.ag-form{display:flex;flex-direction:column;gap:12px;}
.ag-grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));}
.ag-wide{grid-column:1/-1;}
.ag-field{display:flex;flex-direction:column;gap:6px;min-width:0;}
.ag-label{font-size:13px;line-height:20px;font-weight:500;color:var(--dsw-alias-label-secondary);}
.ag-input-wrap{display:flex;width:100%;height:36px;box-sizing:border-box;}
.ag-input-wrap input{font-size:14px;}
.ag-hint{margin:0;color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:18px;}
.ag-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
.ag-confirm{display:flex;flex-direction:column;gap:10px;border:.5px solid var(--dsw-alias-state-warn-primary);background:color-mix(in srgb,var(--dsw-alias-state-warn-primary) 8%,transparent);border-radius:var(--dsw-radius-md);padding:12px;}
.ag-alert{display:flex;align-items:flex-start;gap:6px;border-radius:var(--dsw-radius-md);padding:8px 10px;font-size:13px;line-height:20px;border:.5px solid transparent;word-break:break-word;}
.ag-alert[data-tone=error]{color:var(--dsw-alias-state-error-primary);background:color-mix(in srgb,var(--dsw-alias-state-error-primary) 8%,transparent);border-color:color-mix(in srgb,var(--dsw-alias-state-error-primary) 30%,transparent);}
.ag-alert[data-tone=success]{color:var(--dsw-alias-state-success-primary);background:color-mix(in srgb,var(--dsw-alias-state-success-primary) 10%,transparent);border-color:color-mix(in srgb,var(--dsw-alias-state-success-primary) 30%,transparent);}
.ag-alert[data-tone=warning]{color:var(--dsw-alias-state-warn-label);background:color-mix(in srgb,var(--dsw-alias-state-warn-primary) 10%,transparent);border-color:color-mix(in srgb,var(--dsw-alias-state-warn-primary) 30%,transparent);}
.ag-alert[data-tone=info]{color:var(--dsw-alias-label-secondary);background:var(--dsw-alias-bg-layer-2);border-color:var(--dsw-alias-border-l2);}
.ag-danger{color:var(--dsw-alias-state-error-primary);}
.ag-danger:hover{background:var(--dsw-alias-interactive-bg-hover-danger);}
.ag-muted{color:var(--dsw-alias-label-tertiary);}
.ag-mono{font-family:var(--dsw-font-markdown-code-font-family,ui-monospace,SFMono-Regular,Menlo,Consolas,monospace);font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary);word-break:break-all;}
.ag-qr-panel{display:flex;flex-direction:column;gap:10px;align-items:flex-start;}
.ag-qr-frame{width:220px;height:220px;padding:10px;box-sizing:border-box;border-radius:var(--dsw-radius-md);background:var(--dsw-static-neutral-00,#fff);border:.5px solid var(--dsw-alias-border-l2);}
.ag-qr-frame svg{display:block;width:100%;height:100%;}
.ag-url{display:block;max-width:100%;padding:8px 10px;border-radius:var(--dsw-radius-sm);background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-secondary);font-family:var(--dsw-font-markdown-code-font-family,ui-monospace,SFMono-Regular,Menlo,Consolas,monospace);font-size:12px;line-height:18px;word-break:break-all;user-select:all;}
.ag-empty{margin:0;padding:18px 4px;color:var(--dsw-alias-label-tertiary);font-size:13px;line-height:20px;}
.ag-table-wrap{width:100%;overflow:auto;border:.5px solid var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-md);}
.ag-table-wrap[data-scroll=true]{max-height:440px;}
.ag-table{width:100%;border-collapse:collapse;font-size:13px;line-height:20px;}
.ag-table th{position:sticky;top:0;z-index:1;text-align:left;padding:8px 10px;font-size:12px;font-weight:500;color:var(--dsw-alias-label-tertiary);background:var(--dsw-alias-bg-layer-2);border-bottom:.5px solid var(--dsw-alias-border-l2);white-space:nowrap;}
.ag-table td{padding:8px 10px;vertical-align:top;border-bottom:.5px solid var(--dsw-alias-border-l2);color:var(--dsw-alias-label-primary);word-break:break-word;}
.ag-table tr:last-child td{border-bottom:0;}
.ag-table .ag-cell-muted{color:var(--dsw-alias-label-tertiary);}
.ag-cell-stack{display:flex;flex-direction:column;gap:2px;min-width:0;}
.ag-badges{display:flex;align-items:center;gap:4px;flex-wrap:wrap;}
.ag-center{display:flex;align-items:center;justify-content:center;padding:32px 18px;flex:1 1 auto;}
.ag-center-card{max-width:560px;width:100%;display:flex;flex-direction:column;gap:14px;}
.ag-loading{display:inline-flex;align-items:center;gap:8px;color:var(--dsw-alias-label-tertiary);font-size:13px;}
.ag-toast{position:fixed;left:50%;bottom:28px;transform:translateX(-50%);z-index:1200;max-width:min(560px,calc(100vw - 32px));padding:9px 14px;border-radius:var(--dsw-radius-md);background:var(--dsw-alias-toast-bg,var(--dsw-alias-bg-layer-3));color:var(--dsw-alias-toast-label,var(--dsw-alias-label-primary));box-shadow:var(--dsw-shadow-lv2);font-size:13px;line-height:20px;border:.5px solid var(--dsw-alias-border-l2);}
.ag-toast[data-tone=error]{color:var(--dsw-alias-state-error-primary);}
.ag-toast[data-tone=success]{color:var(--dsw-alias-state-success-primary);}
.ag-sr{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0;}
.ag-btn{box-sizing:border-box;display:inline-flex;align-items:center;justify-content:center;gap:6px;height:36px;padding:0 14px;border:0;border-radius:var(--dsw-radius-md);cursor:pointer;font:inherit;font-size:14px;color:var(--dsw-alias-label-primary);background:transparent;}
.ag-btn:hover{background:var(--dsw-alias-interactive-bg-hover);}
.ag-btn:disabled{cursor:not-allowed;opacity:.4;}
.ag-btn-primary{background:var(--dsw-alias-button-primary-fill);color:var(--dsw-alias-label-primary-foreground);}
.ag-btn-primary:hover:not(:disabled){background:var(--dsw-alias-button-primary-hover);}
.ag-btn-outline{border:.5px solid var(--dsw-alias-border-l3);}
.ag-btn-sm{height:28px;padding:0 10px;font-size:12px;border-radius:var(--dsw-radius-sm);}
.ag-seg{display:inline-flex;gap:2px;padding:4px;border-radius:var(--dsw-radius-md);background:var(--dsw-alias-interactive-bg-hover);}
.ag-seg button{height:28px;padding:0 14px;border:0;border-radius:var(--dsw-radius-sm);background:transparent;color:var(--dsw-alias-label-secondary);font:inherit;font-size:13px;cursor:pointer;}
.ag-seg button[aria-pressed=true]{background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);box-shadow:var(--dsw-elevation-soft);}
.ag-seg button:focus-visible{outline:var(--dsw-focus-ring-width) solid var(--dsw-focus-ring-color,var(--dsw-alias-state-business-primary));outline-offset:-2px;}
.ag-link{color:var(--dsw-alias-link);text-decoration:none;font-size:13px;}
.ag-link:hover{text-decoration:underline;}
.ag-notice-card{max-width:600px;width:100%;display:flex;flex-direction:column;gap:12px;background:var(--dsw-alias-bg-layer-1);border:.5px solid var(--dsw-alias-border-l2);border-radius:var(--dsw-radius-lg);padding:22px;box-sizing:border-box;line-height:1.65;}
.ag-notice-card h2{margin:0;font:var(--dsw-font-m-18,600 18px/26px sans-serif);}
.ag-notice-card p{margin:0;color:var(--dsw-alias-label-secondary);font-size:14px;word-break:break-word;}
.ag-notice-code{font-family:var(--dsw-font-markdown-code-font-family,ui-monospace,SFMono-Regular,Menlo,Consolas,monospace);font-size:12px;background:var(--dsw-alias-bg-layer-2);border-radius:var(--dsw-radius-xs);padding:1px 5px;word-break:break-all;}
.ag-divider{height:.5px;background:var(--dsw-alias-border-l2);margin:2px 0;border:0;}
.ag-shell{display:flex;flex-direction:column;flex:1 1 auto;min-height:0;width:100%;height:100%;}
.ag-debug{position:fixed;top:8px;right:8px;z-index:1300;max-width:min(560px,calc(100vw - 24px));max-height:60vh;overflow:auto;padding:10px 12px;border:.5px solid var(--dsw-alias-state-warn-primary);border-radius:var(--dsw-radius-md);background:var(--dsw-alias-bg-layer-1);box-shadow:var(--dsw-shadow-lv2);font-size:11px;line-height:16px;color:var(--dsw-alias-label-secondary);}
.ag-debug-head{font-weight:600;color:var(--dsw-alias-state-warn-label);margin-bottom:6px;}
.ag-debug-list{display:grid;grid-template-columns:auto minmax(0,1fr);gap:2px 10px;margin:0;}
.ag-debug-list dt{color:var(--dsw-alias-label-tertiary);white-space:nowrap;}
.ag-debug-list dd{margin:0;word-break:break-all;color:var(--dsw-alias-label-primary);font-family:var(--dsw-font-markdown-code-font-family,ui-monospace,SFMono-Regular,Menlo,Consolas,monospace);}
.ag-stack{margin:0;padding:10px;max-height:240px;overflow:auto;background:var(--dsw-alias-bg-layer-2);border-radius:var(--dsw-radius-sm);font-family:var(--dsw-font-markdown-code-font-family,ui-monospace,SFMono-Regular,Menlo,Consolas,monospace);font-size:11px;line-height:16px;white-space:pre-wrap;word-break:break-all;color:var(--dsw-alias-label-secondary);}
@media (max-width:640px){.ag-header{padding:10px 12px;}.ag-body{padding:12px 12px 28px;}.ag-header-actions{margin-left:0;}}
`;

    /** Inject the plugin style once; no-op outside a DOM (tests/SSR). */
    function ensureStyles() {
      if (typeof document === 'undefined' || typeof document.createElement !== 'function') return;
      const tagId = 'dsh-auth-gate/NativePanel.css';
      try {
        if (typeof document.querySelector === 'function' && document.querySelector('style[data-plugin-css=' + JSON.stringify(tagId) + ']') !== null) return;
        const tag = document.createElement('style');
        tag.dataset.plugin = 'dsh-auth-gate';
        tag.dataset.pluginCss = tagId;
        tag.textContent = PLUGIN_CSS;
        document.head.appendChild(tag);
      } catch {
        // Style injection is cosmetic; never break the panel over it.
      }
    }

    // ------------------------------------------------------ primitive aliases

    /**
     * Wrap one primitives (or icon) component in a tiny error boundary: if the
     * real design-system component throws (missing provider, changed props),
     * this instance silently degrades to the local fallback for the rest of its
     * life instead of taking down the whole panel.
     */
    function guardedComponent(kind, Real, Fallback) {
      class Guarded extends React.Component {
        constructor(props) {
          super(props);
          this.state = { failed: false };
        }

        static getDerivedStateFromError() {
          return { failed: true };
        }

        componentDidCatch(error) {
          logError('primitive failed: ' + kind, error);
        }

        render() {
          if (this.state.failed) return h(Fallback, this.props);
          return h(Real, this.props);
        }
      }
      Guarded.displayName = 'AuthGateGuarded(' + kind + ')';
      return Guarded;
    }

    /** Render a design-system icon by its exported name (missing → nothing). */
    function Glyph({ name, size = 14 }) {
      const Component = primitives[name];
      let Render = null;
      if (isRenderableComponent(Component)) {
        if (!iconGuards.has(name)) iconGuards.set(name, guardedComponent('icon:' + name, Component, EmptyGlyph));
        Render = iconGuards.get(name);
      }
      if (Render === null) return null;
      return h(Render, { size, 'aria-hidden': true, focusable: 'false' });
    }

    /** Icons are decorative: a broken icon renders nothing. */
    function EmptyGlyph() {
      return null;
    }

    /** Stable per-icon guard components (never recreated between renders). */
    const iconGuards = new Map();

    /** Fallback button used only when the primitives package is unavailable. */
    function FallbackButton({ variant = 'ghost', size = 'md', icon, className, children, ...rest }) {
      const classes = ['ag-btn', variant === 'primary' ? 'ag-btn-primary' : '', variant === 'outline' ? 'ag-btn-outline' : '', size === 'sm' ? 'ag-btn-sm' : '', className ?? '']
        .filter(Boolean)
        .join(' ');
      return h('button', { type: 'button', className: classes, ...rest }, icon ?? null, children);
    }

    /** Fallback text/password input. */
    function FallbackInput({ className, icon, ...rest }) {
      return h(
        'span',
        { className: ['ag-input-wrap', 'ag-seg', className ?? ''].filter(Boolean).join(' ') },
        h('input', { ...rest, className: 'ag-input' })
      );
    }

    /** Fallback segmented control. */
    function FallbackSegmented({ value, options, onChange, label, disabled = false }) {
      return h(
        'div',
        { className: 'ag-seg', role: 'group', 'aria-label': label },
        options.map((option) =>
          h(
            'button',
            {
              key: option.value,
              type: 'button',
              'aria-pressed': option.value === value,
              disabled: disabled || option.disabled === true,
              onClick: () => onChange(option.value)
            },
            option.label
          )
        )
      );
    }

    /** Fallback tab strip. */
    function FallbackTabs({ items, value, onChange, label }) {
      return h(
        'div',
        { className: 'ag-seg', role: 'tablist', 'aria-label': label },
        items.map((item) =>
          h(
            'button',
            {
              key: item.value,
              id: item.id,
              type: 'button',
              role: 'tab',
              'aria-selected': item.value === value,
              onClick: () => onChange(item.value)
            },
            item.label
          )
        )
      );
    }

    /** Fallback tag chip. */
    function FallbackTag({ children }) {
      return h('span', { className: 'ag-mono' }, children);
    }

    /**
     * Bind one primitives export. Missing exports and non-component values use
     * the local fallback outright; real components are wrapped so a render-time
     * throw degrades just that control.
     */
    function bindPrimitive(name, Fallback) {
      const real = isRenderableComponent(primitives[name]) ? primitives[name] : null;
      PRIMITIVE_BINDINGS[name] = real === null ? 'fallback' : 'real';
      return real === null ? Fallback : guardedComponent(name, real, Fallback);
    }

    // Bind the real primitives once; missing/broken ones keep the tree renderable.
    const Button = bindPrimitive('Button', FallbackButton);
    const Input = bindPrimitive('Input', FallbackInput);
    const SegmentedControl = bindPrimitive('SegmentedControl', FallbackSegmented);
    const SegmentedTabs = bindPrimitive('SegmentedTabs', FallbackTabs);
    const Tag = bindPrimitive('Tag', FallbackTag);

    /** Clipboard helper from primitives (optional; navigator is the fallback). */
    function primitiveWriteClipboard(text) {
      if (typeof primitives.writeClipboard !== 'function') return null;
      try {
        return Promise.resolve(primitives.writeClipboard(text));
      } catch (error) {
        logError('writeClipboard failed', error);
        return null;
      }
    }

    // -------------------------------------------------------- small fragments

    /** Field label + control + hint. */
    function Field({ label, htmlFor, hint, children }) {
      return h(
        'div',
        { className: 'ag-field' },
        label === undefined ? null : h('label', { className: 'ag-label', htmlFor }, label),
        children,
        hint === undefined ? null : h('p', { className: 'ag-hint' }, hint)
      );
    }

    /** Inline, theme-aware status box. */
    function Alert({ tone = 'error', children }) {
      return h('div', { className: 'ag-alert', 'data-tone': tone, role: tone === 'error' ? 'alert' : 'status' }, children);
    }

    /** Loading indicator. */
    function Loading({ label }) {
      return h('span', { className: 'ag-loading', role: 'status' }, h(Glyph, { name: 'IconLoadingOutlineRegular', size: 14 }), label ?? '加载中…');
    }

    /** Fixed toast. */
    function ToastView({ toast }) {
      if (toast === null) return null;
      return h('div', { className: 'ag-toast', 'data-tone': toast.tone, role: 'alert' }, toast.text);
    }

    // ------------------------------------------------------------ diagnostics

    /** Last render phase of the panel, read by the debug and error cards. */
    const runtimeState = {
      screen: 'not-rendered',
      phase: 'init',
      channel: null,
      tab: null,
      gatewayOrigin: null,
      authExpired: false,
      initError: '',
      configured: null,
      stateLoaded: false,
      updatedAt: 0
    };

    /** Record which screen is being rendered (called before each early return). */
    function markScreen(name) {
      runtimeState.screen = name;
      runtimeState.updatedAt = Date.now();
    }

    /** `?authgate-debug=1` or a `#authgate-debug` hash turns the debug card on. */
    function debugEnabled() {
      try {
        if (typeof window === 'undefined' || window.location === null || window.location === undefined) return false;
        const search = typeof window.location.search === 'string' ? window.location.search : '';
        const hash = typeof window.location.hash === 'string' ? window.location.hash : '';
        if (/(?:^|[?&])authgate-debug=1(?:&|$)/u.test(search)) return true;
        return hash.indexOf('authgate-debug') !== -1;
      } catch {
        return false;
      }
    }

    /** Read one location field without letting a broken global blank the card. */
    function locationText(property) {
      try {
        const value = window.location[property];
        if (typeof value === 'string' && value.length > 0) return value;
        return String(value ?? '');
      } catch {
        return '—';
      }
    }

    function safeErrorMessage(error) {
      if (error === null || error === undefined) return '(no error object)';
      if (typeof error === 'string') return error;
      try {
        if (typeof error.message === 'string' && error.message.length > 0) return error.message;
        return String(error);
      } catch {
        return '(unprintable error)';
      }
    }

    function safeErrorStack(error) {
      if (error === null || typeof error !== 'object') return '';
      try {
        return typeof error.stack === 'string' ? error.stack : '';
      } catch {
        return '';
      }
    }

    /** Normalise a thrown value into `{ message, stack }` (cross-realm safe). */
    function normalizeError(error) {
      if (error !== null && typeof error === 'object' && typeof error.message === 'string') return error;
      return { message: safeErrorMessage(error), stack: safeErrorStack(error) };
    }

    /** First 1500 stack characters, as rendered on the failure card. */
    const ERROR_STACK_LIMIT = 1500;

    /** Same-origin admin page when the probe confirmed the gateway origin. */
    function currentAdminHref() {
      if (runtimeState.gatewayOrigin === true) return ADMIN_PATH;
      try {
        return isGatewayOrigin() ? ADMIN_PATH : gatewayAdminUrl();
      } catch {
        return ADMIN_PATH;
      }
    }

    /** Admin URL for the failure card; never let a broken location break it. */
    function safeAdminHref() {
      try {
        return currentAdminHref();
      } catch {
        return ADMIN_PATH;
      }
    }

    /** Diagnostic card rendered only when the debug flag is on. */
    function DebugCard({ error }) {
      const prim = primitivesDiagnostics();
      const bindingText = Object.keys(prim.bindings)
        .map((key) => key + '=' + prim.bindings[key])
        .join(', ');
      const rows = [
        ['location.href', locationText('href') || '—'],
        ['location.port', locationText('port') || '(default)'],
        ['React.version', typeof React.version === 'string' && React.version.length > 0 ? React.version : '(unknown)'],
        ['primitives', prim.loaded ? '已加载' : '未加载' + (prim.error === '' ? '' : '：' + prim.error)],
        ['primitives keys', prim.keys.length === 0 ? '(none)' : prim.keys.join(', ')],
        ['primitives bindings', bindingText === '' ? '(none)' : bindingText],
        ['当前渲染', runtimeState.screen],
        ['hook: phase', String(runtimeState.phase)],
        ['hook: channel', String(runtimeState.channel === null ? '(unknown)' : runtimeState.channel)],
        ['hook: tab', String(runtimeState.tab === null ? '(none)' : runtimeState.tab)],
        ['hook: authExpired', runtimeState.authExpired ? 'true' : 'false'],
        ['hook: initError', runtimeState.initError === '' ? '(empty)' : runtimeState.initError],
        ['gatewayOrigin', runtimeState.gatewayOrigin === null ? '(unknown)' : String(runtimeState.gatewayOrigin)],
        ['configured', runtimeState.configured === null ? '(unknown)' : String(runtimeState.configured)],
        ['state loaded', runtimeState.stateLoaded ? 'yes' : 'no']
      ];
      if (error !== undefined && error !== null) rows.push(['error.message', safeErrorMessage(error)]);
      const children = [];
      for (const [label, value] of rows) {
        children.push(h('dt', { key: 'k-' + label }, label));
        children.push(h('dd', { key: 'v-' + label }, value));
      }
      return h(
        'section',
        { className: 'ag-debug', 'data-authgate-debug': 'true', 'aria-label': 'auth-gate 调试信息' },
        h('div', { className: 'ag-debug-head' }, 'auth-gate 调试（?authgate-debug=1）'),
        h('dl', { className: 'ag-debug-list' }, children)
      );
    }

    /** Visible stand-in for a crashed panel; always offers `/__admin`. */
    function ErrorFallbackCard({ error, label }) {
      const message = safeErrorMessage(error);
      const rawStack = safeErrorStack(error);
      const stack = rawStack.slice(0, ERROR_STACK_LIMIT);
      const truncated = rawStack.length > ERROR_STACK_LIMIT;
      // Same-origin `/__admin` when the gateway serves this document, otherwise
      // the absolute 3443 URL (the only place the admin page exists).
      const adminHref = safeAdminHref();
      return h(
        'div',
        { className: 'ag-root' },
        h(
          'div',
          { className: 'ag-scroll' },
          h(
            'div',
            { className: 'ag-body' },
            h(
              'section',
              { className: 'ag-card', 'data-authgate-error': 'true', role: 'alert' },
              h('h2', { className: 'ag-card-title' }, '认证管理渲染失败'),
              label === undefined ? null : h('p', { className: 'ag-hint' }, '失败区域：', h('code', { className: 'ag-notice-code' }, label)),
              h(Alert, { tone: 'error' }, message),
              stack === '' ? null : h('pre', { className: 'ag-stack' }, stack),
              truncated ? h('p', { className: 'ag-hint' }, '堆栈已截断为前 ', String(ERROR_STACK_LIMIT), ' 个字符。') : null,
              h(
                'p',
                { className: 'ag-hint' },
                '按 F12 打开 Console，复制以 ',
                h('code', { className: 'ag-notice-code' }, LOG_PREFIX),
                ' 开头的日志（render failed / primitive failed）即可定位失败组件；也可以直接用下方独立管理页。'
              ),
              h(
                'div',
                { className: 'ag-actions' },
                h('a', { className: 'ag-link', href: adminHref, target: '_blank', rel: 'noopener noreferrer' }, '打开独立管理页 /__admin'),
                h(Button, { variant: 'primary', onClick: () => window.location.reload() }, '重新加载'),
                h('a', { className: 'ag-link', href: safeAdminHref(), target: '_blank', rel: 'noopener noreferrer' }, '网关管理页（3443）')
              ),
              debugEnabled() ? h(DebugCard, { error }) : null
            )
          )
        )
      );
    }

    /**
     * Panel-level React error boundary. Without it a render-time ReferenceError
     * unmounts the whole React tree and the centre column goes blank (the dsh
     * shell keeps the sidebar, so it looks like "the panel did nothing").
     */
    class PanelErrorBoundary extends React.Component {
      constructor(props) {
        super(props);
        this.state = { error: null };
      }

      static getDerivedStateFromError(error) {
        return { error: normalizeError(error) };
      }

      componentDidCatch(error) {
        logError('render failed', normalizeError(error));
        if (debugEnabled()) {
          logInfo('render context', {
            screen: runtimeState.screen,
            phase: runtimeState.phase,
            channel: runtimeState.channel,
            tab: runtimeState.tab,
            gatewayOrigin: runtimeState.gatewayOrigin,
            primitives: primitivesDiagnostics()
          });
        }
      }

      render() {
        if (this.state.error !== null) {
          return h(ErrorFallbackCard, { error: this.state.error, label: this.props.label });
        }
        return this.props.children;
      }
    }

    /**
     * Root component registered in the `main` slot: structural wrapper + debug
     * overlay + boundary around the real page. Keeping it hook-free means it
     * cannot itself break hook order.
     */
    function AuthGateRoot() {
      const debug = debugEnabled();
      return h(
        'div',
        { className: 'ag-shell', 'data-authgate-root': 'true' },
        h(
          PanelErrorBoundary,
          { label: '认证管理面板' },
          debug ? h(DebugCard, {}) : null,
          h(AuthGatePage)
        )
      );
    }

    /** Explanation shown when the GUI is not served through the gateway port. */
    function PortNotice() {
      const adminUrl = gatewayAdminUrl();
      return h(
        'div',
        { className: 'ag-root' },
        h(
          'div',
          { className: 'ag-center' },
          h(
            'div',
            { className: 'ag-notice-card' },
            h('h2', null, '认证管理'),
            h('p', null, '当前页面地址 ', h('code', { className: 'ag-notice-code' }, window.location.origin), ' 不是认证网关提供的页面（默认端口 ', GATEWAY_PORT, '；也可能是网关探测失败），因此这里不加载管理面板。'),
            h(
              'p',
              null,
              '管理面板必须与网关同源，浏览器才会携带网关登录会话并通过 CSRF 校验。请改用 ',
              h('code', { className: 'ag-notice-code' }, adminUrl),
              ' 打开 dsh，再从左侧栏「认证管理」进入。'
            ),
            h(
              'div',
              { className: 'ag-actions' },
              h(
                Button,
                { variant: 'primary', onClick: () => window.location.assign(adminUrl) },
                '打开认证网关管理页'
              ),
              h('a', { className: 'ag-link', href: adminUrl, target: '_blank', rel: 'noopener noreferrer' }, '在新窗口打开')
            )
          )
        )
      );
    }

    /** Login / session-expired screen. */
    function LoginScreen({ expired, message }) {
      return h(
        'div',
        { className: 'ag-root' },
        h(
          'div',
          { className: 'ag-center' },
          h(
            'div',
            { className: 'ag-center-card' },
            h('div', { className: 'ag-card ag-center-card' }, h('h2', { className: 'ag-title' }, h(Glyph, { name: 'IconShieldOutlineRegular', size: 18 }), '认证管理'), h(Tag, { tone: expired ? 'warning' : 'outline' }, expired ? '会话已失效' : '未登录'),
              h('p', { className: 'ag-hint' }, message || '认证网关会话尚未建立。登录后即可配对设备、修改密码与重置 TOTP。'),
              h(
                'div',
                { className: 'ag-actions' },
                h(Button, { variant: 'primary', onClick: goToLogin }, expired ? '重新登录' : '去登录'),
                h('a', { className: 'ag-link', href: gatewayAdminUrl(), target: '_blank', rel: 'noopener noreferrer' }, '打开网关管理页')
              )
            )
          )
        )
      );
    }

    /** Fatal bootstrap error (network / unexpected response). */
    function ErrorScreen({ message }) {
      return h(
        'div',
        { className: 'ag-root' },
        h(
          'div',
          { className: 'ag-center' },
          h(
            'div',
            { className: 'ag-center-card' },
            h(
              'div',
              { className: 'ag-card ag-center-card' },
              h('h2', { className: 'ag-title' }, h(Glyph, { name: 'IconShieldOutlineRegular', size: 18 }), '认证管理'),
              h(Alert, { tone: 'error' }, message),
              h(
                'div',
                { className: 'ag-actions' },
                h(Button, { variant: 'primary', onClick: () => window.location.reload() }, '重新加载'),
                h('a', { className: 'ag-link', href: gatewayAdminUrl(), target: '_blank', rel: 'noopener noreferrer' }, '打开网关管理页')
              )
            )
          )
        )
      );
    }

    /** One-time screen after a TOTP reset (sessions were revoked server-side). */
    function TotpResetScreen({ result, onDone }) {
      const svg = sanitizeQrSvg(result.qrSvg);
      const [copyState, setCopyState] = React.useState('');
      async function copySecret() {
        const ok = await copyToClipboard(result.secretB32);
        setCopyState(ok ? '密钥已复制，请妥善保存。' : '复制失败，请手动选择密钥复制。');
      }
      return h(
        'div',
        { className: 'ag-root' },
        h(
          'div',
          { className: 'ag-scroll' },
          h(
            'div',
            { className: 'ag-body' },
            h(
              'section',
              { className: 'ag-card' },
              h('h2', { className: 'ag-title' }, h(Glyph, { name: 'IconShieldOutlineRegular', size: 18 }), 'TOTP 已重置'),
              h(Alert, { tone: 'warning' }, '新密钥只显示这一次。全部设备与登录会话已被撤销，所有设备需要重新扫码并登录。'),
              h(
                'div',
                { className: 'ag-qr-panel' },
                svg === ''
                  ? h(Alert, { tone: 'error' }, '二维码渲染失败，请使用下方密钥手动添加。')
                  : h('div', { className: 'ag-qr-frame', dangerouslySetInnerHTML: { __html: svg } }),
                h('div', { className: 'ag-field' }, h('span', { className: 'ag-label' }, '密钥（Base32）'), h('code', { className: 'ag-url' }, result.secretB32)),
                h('div', { className: 'ag-actions' }, h(Button, { variant: 'outline', size: 'sm', icon: h(Glyph, { name: 'IconCopyOutlineRegular' }), onClick: copySecret }, '复制密钥')),
                copyState === '' ? null : h(Alert, { tone: copyState.startsWith('密钥已复制') ? 'success' : 'error' }, copyState),
                result.otpauthUri ? h('p', { className: 'ag-hint' }, 'otpauth URI：', h('code', { className: 'ag-notice-code' }, result.otpauthUri)) : null
              ),
              h(
                'div',
                { className: 'ag-actions' },
                h(Button, { variant: 'primary', onClick: goToLogin }, '我已保存，去登录'),
                h(Button, { variant: 'ghost', onClick: onDone }, '返回管理面板')
              )
            )
          )
        )
      );
    }

    /** Not-configured guidance card. */
    function SetupCard() {
      const adminUrl = gatewayAdminUrl();
      return h(
        'section',
        { className: 'ag-card' },
        h('h2', { className: 'ag-card-title' }, '网关尚未初始化'),
        h(
          'p',
          { className: 'ag-card-desc' },
          '认证网关还没有管理员账号。请在同一浏览器打开 ',
          h('code', { className: 'ag-notice-code' }, adminUrl),
          '，按向导创建管理员、绑定 TOTP；向导会自动把当前浏览器配对为可信设备，之后只需用户名 + 密码登录。'
        ),
        h(
          'p',
          { className: 'ag-hint' },
          '初始化链接只输出在网关启动日志（journalctl）；无法读取日志时，从服务器上的 auth-gate/setup.token 文件（0600）读取。侧边栏面板不会创建首个凭据。'
        ),
        h('div', { className: 'ag-actions' }, h('a', { className: 'ag-link', href: adminUrl, target: '_blank', rel: 'noopener noreferrer' }, '打开初始化页面'))
      );
    }

    /** Empty-table hint. */
    function Empty({ children }) {
      return h('p', { className: 'ag-empty' }, children);
    }

    /** Stable tab descriptors (ids are referenced by aria-controls). */
    const TABS = Object.freeze([
      { value: 'pair', label: '配对', id: 'ag-tab-pair', panelId: 'ag-panel-pair' },
      { value: 'account', label: '账号', id: 'ag-tab-account', panelId: 'ag-panel-account' },
      { value: 'devices', label: '设备', id: 'ag-tab-devices', panelId: 'ag-panel-devices' },
      { value: 'sessions', label: '会话', id: 'ag-tab-sessions', panelId: 'ag-panel-sessions' },
      { value: 'settings', label: '设置', id: 'ag-tab-settings', panelId: 'ag-panel-settings' },
      { value: 'audit', label: '审计', id: 'ag-tab-audit', panelId: 'ag-panel-audit' }
    ]);

    const PLATFORM_OPTIONS = Object.freeze([
      { value: 'android', label: '安卓' },
      { value: 'web', label: '浏览器' }
    ]);

    // -------------------------------------------------------------- the panel

    /**
     * Centre-column page for the `main` keyed slot. All hooks run on every
     * render, before any early return, so the branch screens do not break the
     * hook order.
     */
    function AuthGatePage() {
      const [phase, setPhase] = React.useState('checking');
      const [session, setSession] = React.useState(null);
      const [adminState, setAdminState] = React.useState(null);
      const [channel, setChannel] = React.useState(null);
      const [tab, setTab] = React.useState('pair');
      const [csrf, setCsrf] = React.useState('');
      const [toast, setToast] = React.useState(null);
      const [authExpired, setAuthExpired] = React.useState(false);
      const [authMessage, setAuthMessage] = React.useState('');
      const [initError, setInitError] = React.useState('');
      const [rateLimit, setRateLimit] = React.useState(null);
      const [clock, setClock] = React.useState(() => Date.now());
      const [refreshing, setRefreshing] = React.useState(false);
      const [lastRefresh, setLastRefresh] = React.useState(0);
      const [qr, setQr] = React.useState(null);
      const [pairForm, setPairForm] = React.useState({ platform: 'android', totp: '' });
      const [pairError, setPairError] = React.useState('');
      const [accountForm, setAccountForm] = React.useState({ current: '', password: '', confirm: '' });
      const [accountError, setAccountError] = React.useState('');
      const [confirmAction, setConfirmAction] = React.useState(null);
      const [resetResult, setResetResult] = React.useState(null);
      const [revokeTarget, setRevokeTarget] = React.useState(null);
      const [revokeError, setRevokeError] = React.useState('');
      const [busy, setBusy] = React.useState(null);
      const [busyDevice, setBusyDevice] = React.useState(null);
      const [audit, setAudit] = React.useState(null);
      const [auditError, setAuditError] = React.useState('');
      const [auditLoading, setAuditLoading] = React.useState(false);
      const [network, setNetwork] = React.useState(null);
      const [networkError, setNetworkError] = React.useState('');
      const [networkLoading, setNetworkLoading] = React.useState(false);
      const [networkForm, setNetworkForm] = React.useState({ listenHost: '', listenPort: '', publicUrl: '', publicFingerprint: '', totp: '' });
      const [networkDirty, setNetworkDirty] = React.useState(false);
      const [networkConfirm, setNetworkConfirm] = React.useState(false);
      const [networkBusy, setNetworkBusy] = React.useState(false);
      const [networkNotice, setNetworkNotice] = React.useState(null);

      const gatewayOriginRef = React.useRef(isGatewayOrigin());
      const csrfRef = React.useRef('');
      const phaseRef = React.useRef('checking');
      const authLostRef = React.useRef(false);
      const refreshingRef = React.useRef(false);
      const refreshRef = React.useRef(null);
      const toastSeqRef = React.useRef(0);
      const auditAttemptedRef = React.useRef(false);

      phaseRef.current = phase;
      csrfRef.current = csrf;

      const gatewayOrigin = gatewayOriginRef.current;
      const requireCurrentPassword = channel === 'session';
      const requirePairingTotp = channel === 'session';
      const configured = adminState !== null && adminState.configured === true;
      const devices = adminState !== null && Array.isArray(adminState.devices) ? adminState.devices : [];
      const sessionList = adminState !== null && Array.isArray(adminState.sessionList) ? adminState.sessionList : [];
      const currentSession = sessionList.find((item) => item && item.current === true) ?? null;
      const currentDeviceId = currentSession !== null && typeof currentSession.deviceId === 'string' ? currentSession.deviceId : null;
      const rateLimitRemaining = rateLimit === null ? 0 : Math.max(0, Math.ceil((rateLimit.until - clock) / 1000));
      const qrRemaining = qr === null ? 0 : Math.max(0, Math.ceil((qr.expiresAt - clock) / 1000));

      // Diagnostics only: plain assignments, no hooks, safe on every render.
      // They run after every hook above and before every early return below.
      runtimeState.phase = phase;
      runtimeState.channel = channel;
      runtimeState.tab = tab;
      runtimeState.gatewayOrigin = gatewayOrigin;
      runtimeState.authExpired = authExpired;
      runtimeState.initError = initError;
      runtimeState.configured = configured;
      runtimeState.stateLoaded = adminState !== null;
      markScreen('AuthGatePage');

      /** Show a transient toast. `tone` is success/error/info. */
      function showToast(text, tone) {
        toastSeqRef.current += 1;
        setToast({ id: toastSeqRef.current, text, tone: tone ?? 'success' });
      }

      /** Stop polling and show the login screen. */
      function markAuthLost(message) {
        if (authLostRef.current) return;
        authLostRef.current = true;
        setAuthExpired(true);
        setAuthMessage(typeof message === 'string' && message.length > 0 ? message : '登录会话已失效，请重新登录。');
      }

      /** Record a rate-limit window and surface it. */
      function applyRateLimit(error) {
        const seconds = Math.max(1, Number(error && error.retryAfter) || 60);
        setRateLimit({ until: Date.now() + seconds * 1000, seconds });
        setClock(Date.now());
      }

      /** Central error routing: auth loss, throttle, or toast. */
      function handleError(error) {
        if (error === null || error === undefined) return;
        if (isAuthFailure(error)) {
          markAuthLost();
          return;
        }
        if (error.status === 429) applyRateLimit(error);
        showToast(errorText(error), 'error');
      }

      /** Inline form error routing: auth loss/throttle go global, rest inline. */
      function handleFormError(error, setInline) {
        if (isAuthFailure(error)) {
          markAuthLost();
          return;
        }
        if (error.status === 429) applyRateLimit(error);
        setInline(errorText(error));
      }

      /** Fetch a JSON admin API endpoint, refreshing CSRF once on csrf_invalid. */
      async function callAdmin(path, method, body, allowRetry) {
        const useMethod = method || 'GET';
        try {
          return await requestJson(path, { method: useMethod, body, csrf: csrfRef.current });
        } catch (error) {
          if (allowRetry !== false && error.code === 'csrf_invalid') {
            const refreshed = await requestJson('/__auth/csrf');
            csrfRef.current = typeof refreshed.csrf === 'string' ? refreshed.csrf : '';
            setCsrf(csrfRef.current);
            return requestJson(path, { method: useMethod, body, csrf: csrfRef.current });
          }
          throw error;
        }
      }

      /** Refresh public state (devices + sessions). Silent polls do not flash. */
      async function refreshState(options) {
        const silent = options !== undefined && options.silent === true;
        if (phaseRef.current !== 'ready' || authLostRef.current || refreshingRef.current) return;
        refreshingRef.current = true;
        if (!silent) setRefreshing(true);
        try {
          const next = await callAdmin('/__admin/api/state', 'GET');
          setAdminState(next);
          setLastRefresh(Date.now());
        } catch (error) {
          handleError(error);
        } finally {
          refreshingRef.current = false;
          if (!silent) setRefreshing(false);
        }
      }

      /** Load the newest audit rows, newest first. */
      async function loadAudit() {
        if (auditLoading || authLostRef.current) return;
        auditAttemptedRef.current = true;
        setAuditLoading(true);
        setAuditError('');
        try {
          const data = await callAdmin('/__admin/api/audit', 'GET');
          // The gateway returns newest-first; keep that order (no extra reverse).
          const rows = Array.isArray(data.audit) ? data.audit.slice(0, AUDIT_LIMIT) : [];
          rows.sort((left, right) => (Number(right?.at) || 0) - (Number(left?.at) || 0));
          setAudit(rows);
        } catch (error) {
          if (isAuthFailure(error)) markAuthLost();
          else {
            if (error.status === 429) applyRateLimit(error);
            setAuditError(errorText(error));
          }
          setAudit([]);
        } finally {
          setAuditLoading(false);
        }
      }

      /** Load the effective network settings and seed the settings form. */
      async function loadNetwork() {
        if (networkLoading || authLostRef.current) return;
        setNetworkLoading(true);
        setNetworkError('');
        try {
          const data = await callAdmin('/__admin/api/network', 'GET');
          const next = data !== null && typeof data === 'object' && data.network !== null && typeof data.network === 'object' ? data.network : null;
          if (next === null) throw { code: 'bad_request', status: 400 };
          setNetwork(next);
          setNetworkForm({
            listenHost: typeof next.listenHost === 'string' ? next.listenHost : '',
            listenPort: typeof next.listenPort === 'number' ? String(next.listenPort) : '',
            publicUrl: typeof next.publicUrl === 'string' ? next.publicUrl : '',
            publicFingerprint: typeof next.publicFingerprint === 'string' ? next.publicFingerprint : '',
            totp: ''
          });
          setNetworkDirty(false);
        } catch (error) {
          if (isAuthFailure(error)) markAuthLost();
          else {
            if (error.status === 429) applyRateLimit(error);
            setNetworkError(errorText(error));
          }
        } finally {
          setNetworkLoading(false);
        }
      }

      /** Header refresh: state + audit/network (when the matching tab is open). */
      function refreshAll() {
        if (phaseRef.current !== 'ready' || authLostRef.current) return;
        refreshState({ silent: false });
        if (tab === 'audit') loadAudit();
        if (tab === 'settings') loadNetwork();
      }

      // Bootstrap: CSRF → whoami → (loopback probe) → state.
      React.useEffect(() => {
        ensureStyles();
        let cancelled = false;
        (async () => {
          try {
            // The port is only a fast path. A frp-published gateway can be
            // served on an arbitrary port/domain, so confirm by probing its
            // public status endpoint before rendering the panel.
            if (!gatewayOriginRef.current) {
              const probed = await probeGatewayOrigin();
              if (cancelled) return;
              if (!probed) {
                setPhase('offgateway');
                return;
              }
              gatewayOriginRef.current = true;
            }
            // First question: is this deployment initialized at all? The
            // status endpoint is public, so an unconfigured gate must render
            // guidance without CSRF/whoami/state calls (those would only 403
            // and bounce the user to a useless login page). Older gateways
            // without the endpoint fall through to the legacy bootstrap.
            try {
              const setupStatus = await loadSetupStatus();
              if (cancelled) return;
              if (setupStatus.configured === false) {
                setPhase('setup');
                return;
              }
            } catch {
              // Endpoint missing (older version) or transient failure: let the
              // ordinary path surface a precise error.
            }
            const csrfData = await requestJson('/__auth/csrf');
            if (cancelled) return;
            csrfRef.current = typeof csrfData.csrf === 'string' ? csrfData.csrf : '';
            setCsrf(csrfRef.current);
            const who = await requestJson('/__auth/whoami');
            if (cancelled) return;
            if (who !== null && typeof who === 'object' && who.authenticated === true) {
              setSession(who);
              setChannel('session');
              setPhase('ready');
              const next = await requestJson('/__admin/api/state');
              if (cancelled) return;
              setAdminState(next);
              setLastRefresh(Date.now());
              return;
            }
            setSession(who !== null && typeof who === 'object' ? who : null);
            // Anonymous whoami can still be a local loopback/admin-key caller;
            // probe /__admin once. A 403 means "really not logged in".
            try {
              const next = await requestJson('/__admin/api/state');
              if (cancelled) return;
              setChannel('loopback');
              setAdminState(next);
              setPhase('ready');
              setLastRefresh(Date.now());
            } catch (probeError) {
              if (cancelled) return;
              if (isAuthFailure(probeError)) {
                setPhase('unauth');
                return;
              }
              throw probeError;
            }
          } catch (error) {
            if (cancelled) return;
            if (isAuthFailure(error)) {
              setPhase('unauth');
              return;
            }
            setInitError(errorText(error));
            setPhase('error');
          }
        })();
        return () => {
          cancelled = true;
        };
      }, []);

      // 20-second state poll, paused while the document is hidden.
      React.useEffect(() => {
        if (typeof window === 'undefined') return undefined;
        const tick = () => {
          if (typeof document !== 'undefined' && document.visibilityState !== 'visible') return;
          if (phaseRef.current !== 'ready' || authLostRef.current) return;
          const refresh = refreshRef.current;
          if (typeof refresh === 'function') refresh({ silent: true });
        };
        const timer = setInterval(tick, POLL_INTERVAL_MS);
        const onVisibility = () => {
          if (typeof document !== 'undefined' && document.visibilityState === 'visible') tick();
        };
        document.addEventListener('visibilitychange', onVisibility);
        return () => {
          clearInterval(timer);
          document.removeEventListener('visibilitychange', onVisibility);
        };
      }, []);

      // 1-second clock only while a countdown is visible.
      const ticking = qr !== null || rateLimit !== null;
      React.useEffect(() => {
        if (!ticking) return undefined;
        const timer = setInterval(() => setClock(Date.now()), 1000);
        return () => clearInterval(timer);
      }, [ticking]);

      // Drop an expired throttle state (the banner disappears immediately).
      React.useEffect(() => {
        if (rateLimit !== null && clock >= rateLimit.until) setRateLimit(null);
      }, [clock, rateLimit]);

      // Toast auto-dismiss.
      React.useEffect(() => {
        if (toast === null) return undefined;
        const timer = setTimeout(() => setToast(null), TOAST_MS);
        return () => clearTimeout(timer);
      }, [toast]);

      // Lazy audit load the first time the audit tab becomes visible.
      React.useEffect(() => {
        if (tab !== 'audit' || phaseRef.current !== 'ready' || authLostRef.current) return;
        if (auditAttemptedRef.current) return;
        loadAudit();
      }, [tab]);

      // Lazy network-settings load the first time the settings tab is opened.
      React.useEffect(() => {
        if (tab !== 'settings' || phaseRef.current !== 'ready' || authLostRef.current) return;
        if (network !== null || networkLoading) return;
        loadNetwork();
      }, [tab]);

      // Latest refresh function for the interval closure.
      refreshRef.current = refreshState;

      // --------------------------------------------------------- form actions

      async function submitPair(event) {
        if (event !== undefined && event !== null && typeof event.preventDefault === 'function') event.preventDefault();
        setPairError('');
        if (requirePairingTotp && pairForm.totp.length !== 6) {
          setPairError(MESSAGES.totp_required);
          return;
        }
        if (rateLimitRemaining > 0) {
          setPairError('操作过于频繁，请 ' + rateLimitRemaining + ' 秒后重试。');
          return;
        }
        setBusy('qr');
        try {
          const body = { platform: pairForm.platform };
          if (pairForm.totp.length > 0) body.totp = pairForm.totp;
          const data = await callAdmin('/__admin/api/qr', 'POST', body);
          const svg = sanitizeQrSvg(data.qrSvg);
          setQr({
            url: typeof data.url === 'string' ? data.url : '',
            expiresAt: typeof data.expiresAt === 'number' ? data.expiresAt : 0,
            qrSvg: svg
          });
          setPairForm((previous) => ({ ...previous, totp: '' }));
          setClock(Date.now());
          showToast('配对二维码已生成，请在有效期内完成扫码或打开链接。', 'success');
        } catch (error) {
          handleFormError(error, setPairError);
        } finally {
          setBusy(null);
        }
      }

      async function copyPairUrl() {
        if (qr === null) return;
        const ok = await copyToClipboard(qr.url);
        if (ok) showToast('配对链接已复制。', 'success');
        else showToast('复制失败，请手动选择链接复制。', 'error');
      }

      function requestPasswordChange(event) {
        if (event !== undefined && event !== null && typeof event.preventDefault === 'function') event.preventDefault();
        setAccountError('');
        if (requireCurrentPassword && accountForm.current.length === 0) {
          setAccountError(MESSAGES.current_password_required);
          return;
        }
        if (accountForm.password.length < 10) {
          setAccountError(MESSAGES.weak_password);
          return;
        }
        if (accountForm.password !== accountForm.confirm) {
          setAccountError('两次输入的新密码不一致。');
          return;
        }
        if (rateLimitRemaining > 0) {
          setAccountError('操作过于频繁，请 ' + rateLimitRemaining + ' 秒后重试。');
          return;
        }
        setConfirmAction('password');
      }

      async function confirmPasswordChange() {
        if (busy === 'password') return;
        setBusy('password');
        setAccountError('');
        try {
          const body = { password: accountForm.password };
          if (accountForm.current.length > 0) body.currentPassword = accountForm.current;
          const data = await callAdmin('/__admin/api/user', 'POST', body);
          const devicesRevoked = Number(data.devicesRevoked) || 0;
          const sessionsRevoked = Number(data.sessionsRevoked) || 0;
          setAccountForm({ current: '', password: '', confirm: '' });
          setConfirmAction(null);
          setAudit(null);
          showToast('密码已修改。', 'success');
          markAuthLost('密码已修改：撤销 ' + devicesRevoked + ' 台设备、' + sessionsRevoked + ' 个会话。所有设备需要重新扫码并登录。');
        } catch (error) {
          setConfirmAction(null);
          handleFormError(error, setAccountError);
        } finally {
          setBusy(null);
        }
      }

      function requestTotpReset() {
        setAccountError('');
        if (requireCurrentPassword && accountForm.current.length === 0) {
          setAccountError('请输入当前密码后再重置 TOTP。');
          return;
        }
        if (rateLimitRemaining > 0) {
          setAccountError('操作过于频繁，请 ' + rateLimitRemaining + ' 秒后重试。');
          return;
        }
        setConfirmAction('totp');
      }

      async function confirmTotpReset() {
        if (busy === 'totp') return;
        setBusy('totp');
        setAccountError('');
        try {
          const body = { resetTotp: true };
          if (accountForm.current.length > 0) body.currentPassword = accountForm.current;
          const data = await callAdmin('/__admin/api/user', 'POST', body);
          setResetResult({
            secretB32: typeof data.secretB32 === 'string' ? data.secretB32 : '',
            otpauthUri: typeof data.otpauthUri === 'string' ? data.otpauthUri : '',
            qrSvg: sanitizeQrSvg(data.qrSvg),
            devicesRevoked: Number(data.devicesRevoked) || 0,
            sessionsRevoked: Number(data.sessionsRevoked) || 0
          });
          setAccountForm({ current: '', password: '', confirm: '' });
          setConfirmAction(null);
          authLostRef.current = true;
          setAuthExpired(true);
          setAuthMessage('TOTP 已重置，全部设备与登录会话已撤销。请保存新密钥并重新登录。');
          setAudit(null);
        } catch (error) {
          setConfirmAction(null);
          handleFormError(error, setAccountError);
        } finally {
          setBusy(null);
        }
      }

      async function revokeDevice(device) {
        if (device === null || typeof device.id !== 'string') return;
        if (busyDevice !== null) return;
        setBusyDevice(device.id);
        setRevokeError('');
        try {
          await callAdmin('/__admin/api/devices/revoke', 'POST', { deviceId: device.id });
          setRevokeTarget(null);
          setAudit(null);
          showToast('设备已吊销，其会话与续期已立即失效。', 'success');
          await refreshState({ silent: true });
        } catch (error) {
          if (isAuthFailure(error)) markAuthLost();
          else {
            if (error.status === 429) applyRateLimit(error);
            setRevokeError(errorText(error));
            showToast(errorText(error), 'error');
          }
        } finally {
          setBusyDevice(null);
        }
      }

      function setNetworkField(field, value) {
        setNetworkForm((previous) => ({ ...previous, [field]: value }));
        setNetworkDirty(true);
      }

      /** Inline confirm before applying any network change. */
      function requestNetworkSave(event) {
        if (event !== undefined && event !== null && typeof event.preventDefault === 'function') event.preventDefault();
        setNetworkError('');
        setNetworkNotice(null);
        if (network === null) {
          setNetworkError('网络设置尚未加载，请点击刷新后重试。');
          return;
        }
        const host = networkForm.listenHost.trim();
        const port = networkForm.listenPort.trim();
        const publicUrl = networkForm.publicUrl.trim();
        const publicFingerprint = networkForm.publicFingerprint.trim();
        if (host === '' || port === '' || publicUrl === '') {
          setNetworkError('监听地址、监听端口和对外访问地址均不能为空。');
          return;
        }
        if (publicFingerprint !== '' && !/^[0-9a-fA-F]{64}$/u.test(publicFingerprint)) {
          setNetworkError(MESSAGES.invalid_public_fingerprint);
          return;
        }
        if (requirePairingTotp && networkForm.totp.length !== 6) {
          setNetworkError(MESSAGES.totp_required);
          return;
        }
        if (rateLimitRemaining > 0) {
          setNetworkError('操作过于频繁，请 ' + rateLimitRemaining + ' 秒后重试。');
          return;
        }
        setNetworkConfirm(true);
      }

      async function confirmNetworkSave() {
        if (networkBusy) return;
        setNetworkBusy(true);
        setNetworkError('');
        try {
          const body = {
            listenHost: networkForm.listenHost.trim(),
            listenPort: Number(networkForm.listenPort.trim()),
            publicUrl: networkForm.publicUrl.trim(),
            publicFingerprint: networkForm.publicFingerprint.trim()
          };
          if (channel === 'session') body.totp = networkForm.totp;
          const data = await callAdmin('/__admin/api/network', 'POST', body);
          const next = data !== null && typeof data === 'object' && data.network !== null && typeof data.network === 'object' ? data.network : null;
          if (next !== null) {
            setNetwork(next);
            setNetworkForm({
              listenHost: String(next.listenHost ?? ''),
              listenPort: String(next.listenPort ?? ''),
              publicUrl: String(next.publicUrl ?? ''),
              publicFingerprint: String(next.publicFingerprint ?? ''),
              totp: ''
            });
          } else {
            setNetworkForm((previous) => ({ ...previous, totp: '' }));
          }
          setNetworkDirty(false);
          setNetworkConfirm(false);
          const rebound = data !== null && typeof data === 'object' && data.rebound === true;
          setNetworkNotice({
            tone: rebound ? 'warning' : 'success',
            text: rebound
              ? '网络设置已保存：监听地址/端口已重建，当前连接可能已断开；请稍后刷新页面或使用新的地址重新访问。'
              : '网络设置已保存：下次生成配对二维码/链接将使用新的对外访问地址。'
          });
          showToast(rebound ? '监听地址/端口已重建，连接可能短暂中断。' : '网络设置已保存。', 'success');
          // A rebind may have retired the current origin; only refresh state
          // automatically for the non-disruptive publicUrl-only case.
          if (!rebound && typeof refreshState === 'function') await refreshState({ silent: true });
        } catch (error) {
          setNetworkConfirm(false);
          handleFormError(error, setNetworkError);
        } finally {
          setNetworkBusy(false);
        }
      }

      /**
       * Read the public certificate fingerprint for the *already saved*
       * publicUrl ("auto"). A changed publicUrl must be saved first: the probe
       * only ever targets the saved/submitted origin, never an arbitrary host.
       */
      async function autoNetworkFingerprint() {
        if (networkBusy) return;
        setNetworkError('');
        setNetworkNotice(null);
        if (network === null) {
          setNetworkError('网络设置尚未加载，请点击重新加载后重试。');
          return;
        }
        if (requirePairingTotp && networkForm.totp.length !== 6) {
          setNetworkError(MESSAGES.totp_required);
          return;
        }
        if (rateLimitRemaining > 0) {
          setNetworkError('操作过于频繁，请 ' + rateLimitRemaining + ' 秒后重试。');
          return;
        }
        const savedPublicUrl = String(network.publicUrl ?? '');
        if (networkForm.publicUrl.trim() !== savedPublicUrl) {
          setNetworkError('对外地址已修改但尚未保存：请先保存 publicUrl，再读取对外证书指纹。');
          return;
        }
        setNetworkBusy(true);
        try {
          const body = { publicFingerprint: 'auto' };
          if (channel === 'session') body.totp = networkForm.totp;
          const data = await callAdmin('/__admin/api/network', 'POST', body);
          const next = data !== null && typeof data === 'object' && data.network !== null && typeof data.network === 'object' ? data.network : null;
          const saved = next !== null ? String(next.publicFingerprint ?? '') : '';
          const effective = next !== null ? String(next.effectiveFingerprint ?? '') : '';
          setNetworkForm((previous) => ({ ...previous, publicFingerprint: saved, totp: '' }));
          if (next !== null) setNetwork(next);
          setNetworkDirty(false);
          setNetworkNotice({
            tone: 'success',
            text:
              saved === ''
                ? '已读取对外证书指纹；实际生效：' + effective + '。'
                : '已读取并保存对外证书指纹：' + saved + '（实际生效：' + effective + '）。'
          });
          showToast('对外证书指纹已读取。', 'success');
        } catch (error) {
          handleFormError(error, setNetworkError);
        } finally {
          setNetworkBusy(false);
        }
      }

      // ------------------------------------------------------------- branches

      if (phase === 'offgateway') {
        markScreen('PortNotice');
        return h(PortNotice);
      }
      if (resetResult !== null) {
        markScreen('TotpResetScreen');
        return h(TotpResetScreen, { result: resetResult, onDone: () => setResetResult(null) });
      }
      if (authExpired) {
        markScreen('LoginScreen(expired)');
        return h(LoginScreen, { expired: true, message: authMessage });
      }
      if (phase === 'setup') {
        markScreen('SetupRequiredScreen');
        return h('div', { className: 'ag-root' }, h('div', { className: 'ag-scroll' }, h('div', { className: 'ag-body' }, h(SetupCard))));
      }
      if (phase === 'checking') {
        markScreen('LoadingScreen');
        return h(
          'div',
          { className: 'ag-root' },
          h('div', { className: 'ag-center' }, h('div', { className: 'ag-card' }, h('div', { className: 'ag-title' }, h(Glyph, { name: 'IconShieldOutlineRegular', size: 18 }), '认证管理'), h(Loading, { label: '正在检查登录状态…' })))
        );
      }
      if (phase === 'unauth') {
        markScreen('LoginScreen');
        return h(LoginScreen, { expired: false, message: '' });
      }
      if (phase === 'error') {
        markScreen('ErrorScreen');
        return h(ErrorScreen, { message: initError });
      }

      const username =
        adminState !== null && adminState.user !== null && typeof adminState.user === 'object' && typeof adminState.user.username === 'string'
          ? adminState.user.username
          : session !== null && typeof session === 'object' && session.user !== null && typeof session.user === 'object' && typeof session.user.username === 'string'
            ? session.user.username
            : '';
      // `totpConfigured` reflects the stored secret, so bootstrap/loopback/
      // adminKey pairing no longer renders a misleading "unbound" badge.
      // `totpConfirmed` is legacy and must not drive the UI.
      const totpConfigured = adminState !== null && adminState.user !== null && typeof adminState.user === 'object' && adminState.user.totpConfigured === true;
      const channelLabel = channel === 'session' ? '用户 ' + (username || '—') : '本机通道';
      const totpLabel = totpConfigured ? 'TOTP 已配置' : 'TOTP 未配置';

      const header = h(
        'header',
        { className: 'ag-header' },
        h(
          'div',
          { className: 'ag-title-wrap' },
          h('h1', { className: 'ag-title' }, h(Glyph, { name: 'IconShieldOutlineRegular', size: 18 }), '认证管理'),
          h(
            'div',
            { className: 'ag-status' },
            h(Tag, { tone: channel === 'session' ? 'neutral' : 'quiet' }, channelLabel),
            h(Tag, { tone: totpConfigured ? 'success' : 'warning' }, totpLabel),
            h('span', { className: 'ag-origin', title: window.location.origin }, h(Glyph, { name: 'IconGlobeOutlineRegular', size: 12 }), window.location.origin)
          )
        ),
        h(
          'div',
          { className: 'ag-header-actions' },
          h(
            Button,
            {
              variant: 'ghost',
              size: 'sm',
              icon: h(Glyph, { name: 'IconRefreshOutlineRegular' }),
              onClick: refreshAll,
              disabled: refreshing || rateLimitRemaining > 0,
              title: lastRefresh > 0 ? '上次刷新 ' + formatTime(lastRefresh) : '刷新状态'
            },
            refreshing ? '刷新中…' : '刷新'
          ),
          h('a', { className: 'ag-admin-link', href: currentAdminHref(), target: '_blank', rel: 'noopener noreferrer' }, '网关管理页', h(Glyph, { name: 'IconRightUpOutlineRegular', size: 12 }))
        )
      );

      const banners = [];
      if (rateLimitRemaining > 0) banners.push(h(Alert, { key: 'rate', tone: 'warning' }, '请求过于频繁，请 ', rateLimitRemaining, ' 秒后重试。'));
      if (csrf === '') banners.push(h(Alert, { key: 'csrf', tone: 'warning' }, '安全令牌尚未就绪，写操作暂时不可用。请点击刷新。'));

      if (!configured) {
        markScreen('SetupCard');
        return h(
          'div',
          { className: 'ag-root' },
          header,
          h('div', { className: 'ag-scroll' }, h('div', { className: 'ag-body' }, banners, h(SetupCard), h(ToastView, { toast })))
        );
      }

      const pairPanel = h(
        'section',
        { className: 'ag-card', id: 'ag-panel-pair', role: 'tabpanel', 'aria-labelledby': 'ag-tab-pair' },
        h('div', { className: 'ag-card-head' }, h('h2', { className: 'ag-card-title' }, '配对'), h('p', { className: 'ag-card-desc' }, '生成一次性配对二维码或链接：手机扫码，或在浏览器中打开链接完成设备配对。')),
        h(
          'form',
          { className: 'ag-form', onSubmit: submitPair, noValidate: true },
          h(
            Field,
            { label: '平台', hint: '仅影响配对提示，票据本身通用。' },
            h(SegmentedControl, {
              id: 'ag-platform',
              value: pairForm.platform,
              options: PLATFORM_OPTIONS,
              onChange: (value) => setPairForm((previous) => ({ ...previous, platform: value })),
              label: '配对平台',
              disabled: busy === 'qr'
            })
          ),
          h(
            Field,
            {
              label: '6 位动态验证码' + (requirePairingTotp ? '（必填）' : '（本机通道可留空）'),
              htmlFor: 'ag-pair-totp',
              hint: requirePairingTotp
                ? '打开认证器 App 输入当前 6 位数字，用于确认是你本人操作。配对成功后本设备登录只需用户名 + 密码。'
                : '本机 loopback / 管理密钥通道无需动态验证码。'
            },
            h(Input, {
              id: 'ag-pair-totp',
              className: 'ag-input-wrap',
              type: 'text',
              inputMode: 'numeric',
              autoComplete: 'one-time-code',
              maxLength: 6,
              value: pairForm.totp,
              placeholder: '000000',
              onChange: (event) => setPairForm((previous) => ({ ...previous, totp: event.target.value.replace(/\D/gu, '').slice(0, 6) }))
            })
          ),
          pairError === '' ? null : h(Alert, { tone: 'error' }, pairError),
          h(
            'div',
            { className: 'ag-actions' },
            h(
              Button,
              { type: 'submit', variant: 'primary', disabled: busy === 'qr' || rateLimitRemaining > 0, icon: h(Glyph, { name: 'IconLinkOutlineRegular' }) },
              busy === 'qr' ? '生成中…' : qr === null ? '生成配对二维码' : '重新生成配对二维码'
            )
          )
        ),
        qr === null
          ? null
          : h(
              'div',
              { className: 'ag-qr-panel' },
              qr.qrSvg === ''
                ? h(Alert, { tone: 'error' }, '二维码渲染失败，请复制下方链接使用。')
                : h('div', { className: 'ag-qr-frame', dangerouslySetInnerHTML: { __html: qr.qrSvg } }),
              qrRemaining > 0 ? h(Tag, { tone: 'info' }, '剩余 ' + formatRemaining(qrRemaining)) : h(Tag, { tone: 'danger' }, '已过期，请重新生成'),
              h('div', { className: 'ag-actions' }, h(Button, { variant: 'outline', size: 'sm', icon: h(Glyph, { name: 'IconCopyOutlineRegular' }), onClick: copyPairUrl }, '复制配对链接')),
              qr.url === '' ? null : h('code', { className: 'ag-url' }, qr.url),
              h('p', { className: 'ag-hint' }, '同一条链接在浏览器中打开即可配对浏览器设备；二维码用于 DSH Mobile 扫码。')
            )
      );

      const accountPanel = h(
        'section',
        { className: 'ag-card', id: 'ag-panel-account', role: 'tabpanel', 'aria-labelledby': 'ag-tab-account' },
        h('h2', { className: 'ag-card-title' }, '账号'),
        h('p', { className: 'ag-card-desc' }, requireCurrentPassword ? '通过登录会话访问时，修改密码或重置 TOTP 必须输入当前密码。' : '本机通道可以不填当前密码；管理密钥等同于 bearer 凭据，请妥善保管。'),
        h('h3', { className: 'ag-subtitle' }, '修改密码'),
        h(
          'form',
          { className: 'ag-form', onSubmit: requestPasswordChange, noValidate: true },
          h(
            'div',
            { className: 'ag-grid' },
            h(
              Field,
              { label: '当前密码' + (requireCurrentPassword ? '（必填）' : '（可留空）'), htmlFor: 'ag-current-password' },
              h(Input, {
                id: 'ag-current-password',
                className: 'ag-input-wrap',
                type: 'password',
                autoComplete: 'current-password',
                maxLength: 512,
                value: accountForm.current,
                onChange: (event) => setAccountForm((previous) => ({ ...previous, current: event.target.value }))
              })
            ),
            h(
              Field,
              { label: '新密码（至少 10 位）', htmlFor: 'ag-new-password' },
              h(Input, {
                id: 'ag-new-password',
                className: 'ag-input-wrap',
                type: 'password',
                autoComplete: 'new-password',
                minLength: 10,
                maxLength: 200,
                value: accountForm.password,
                onChange: (event) => setAccountForm((previous) => ({ ...previous, password: event.target.value }))
              })
            ),
            h(
              Field,
              { label: '确认新密码', htmlFor: 'ag-confirm-password' },
              h(Input, {
                id: 'ag-confirm-password',
                className: 'ag-input-wrap',
                type: 'password',
                autoComplete: 'new-password',
                minLength: 10,
                maxLength: 200,
                value: accountForm.confirm,
                onChange: (event) => setAccountForm((previous) => ({ ...previous, confirm: event.target.value }))
              })
            )
          ),
          accountError === '' ? null : h(Alert, { tone: 'error' }, accountError),
          h(Alert, { tone: 'warning' }, '修改密码或重置 TOTP 后，全部已配对设备与会话会被立即撤销，所有设备需重新扫码后再登录。'),
          confirmAction === 'password'
            ? h(
                'div',
                { className: 'ag-confirm' },
                h('p', { className: 'ag-card-desc' }, '确认修改密码？此操作会立即让全部设备与登录会话失效。'),
                h(
                  'div',
                  { className: 'ag-actions' },
                  h(Button, { variant: 'primary', disabled: busy === 'password', onClick: confirmPasswordChange }, busy === 'password' ? '提交中…' : '确认修改'),
                  h(Button, { variant: 'ghost', disabled: busy === 'password', onClick: () => setConfirmAction(null) }, '取消')
                )
              )
            : h('div', { className: 'ag-actions' }, h(Button, { type: 'submit', variant: 'primary', disabled: busy === 'password' || rateLimitRemaining > 0, icon: h(Glyph, { name: 'IconEditOutlineRegular' }) }, '修改密码'))
        ),
        h('hr', { className: 'ag-divider' }),
        h('h3', { className: 'ag-subtitle' }, '重置 TOTP'),
        h('p', { className: 'ag-card-desc' }, '重置后会生成新的 TOTP 密钥，旧验证码立即失效；新密钥只在重置成功后显示一次。'),
        confirmAction === 'totp'
          ? h(
              'div',
              { className: 'ag-confirm' },
              h('p', { className: 'ag-card-desc' }, '确认重置 TOTP？全部设备与会话会被立即撤销，旧验证码失效。'),
              h(
                'div',
                { className: 'ag-actions' },
                h(Button, { variant: 'primary', disabled: busy === 'totp', onClick: confirmTotpReset }, busy === 'totp' ? '重置中…' : '确认重置'),
                h(Button, { variant: 'ghost', disabled: busy === 'totp', onClick: () => setConfirmAction(null) }, '取消')
              )
            )
          : h('div', { className: 'ag-actions' }, h(Button, { variant: 'outline', disabled: busy === 'totp' || rateLimitRemaining > 0, icon: h(Glyph, { name: 'IconWarningTriangleOutlineRegular' }), onClick: requestTotpReset }, '重置 TOTP'))
      );

      const deviceRows = devices.map((device) => {
        const row = device !== null && typeof device === 'object' ? device : {};
        const id = typeof row.id === 'string' ? row.id : '';
        const name = typeof row.name === 'string' && row.name.length > 0 ? row.name : '未命名设备';
        const isCurrent = id !== '' && id === currentDeviceId;
        const confirming = revokeTarget !== null && revokeTarget === id;
        return h(
          'tr',
          { key: id || name + String(row.createdAt) },
          h('td', null, h('div', { className: 'ag-cell-stack' }, h('span', null, name), h('code', { className: 'ag-mono' }, id))),
          h('td', null, h(Tag, { tone: platformTone(row.platform) }, platformLabel(row.platform))),
          h(
            'td',
            null,
            h(
              'div',
              { className: 'ag-badges' },
              h(Tag, { tone: row.online === true ? 'success' : 'quiet' }, row.online === true ? '在线' : '离线'),
              isCurrent ? h(Tag, { tone: 'info' }, '当前设备') : null
            )
          ),
          h('td', { className: 'ag-cell-muted' }, formatTime(row.createdAt)),
          h('td', { className: 'ag-cell-muted' }, formatTime(typeof row.lastActiveAt === 'number' ? row.lastActiveAt : row.lastSeenAt)),
          h('td', { className: 'ag-cell-muted' }, formatTime(row.expiresAt)),
          h(
            'td',
            null,
            confirming
              ? h(
                  'div',
                  { className: 'ag-actions' },
                  h(Button, { variant: 'outline', size: 'sm', className: 'ag-danger', disabled: busyDevice === id, onClick: () => revokeDevice(row) }, busyDevice === id ? '吊销中…' : '确认吊销'),
                  h(Button, { variant: 'ghost', size: 'sm', disabled: busyDevice === id, onClick: () => setRevokeTarget(null) }, '取消')
                )
              : h(Button, { variant: 'ghost', size: 'sm', className: 'ag-danger', icon: h(Glyph, { name: 'IconTrashOutlineRegular' }), onClick: () => setRevokeTarget(id) }, '吊销')
          )
        );
      });

      const devicesPanel = h(
        'section',
        { className: 'ag-card', id: 'ag-panel-devices', role: 'tabpanel', 'aria-labelledby': 'ag-tab-devices' },
        h('div', { className: 'ag-card-head' }, h('h2', { className: 'ag-card-title' }, '已配对设备'), h('p', { className: 'ag-card-desc' }, '在线状态按最近两分钟活跃计算。吊销设备会同时撤销其全部会话。')),
        revokeError === '' ? null : h(Alert, { tone: 'error' }, revokeError),
        devices.length === 0
          ? h(Empty, null, '暂无设备。切到「配对」生成二维码，用 DSH Mobile 扫码或复制链接在浏览器中配对。')
          : h(
              'div',
              { className: 'ag-table-wrap' },
              h(
                'table',
                { className: 'ag-table' },
                h('thead', null, h('tr', null, ['名称', '平台', '状态', '创建时间', '最近活跃', '到期时间', '操作'].map((label) => h('th', { key: label }, label)))),
                h('tbody', null, deviceRows)
              )
            )
      );

      const deviceNames = new Map();
      for (const device of devices) {
        if (device !== null && typeof device === 'object' && typeof device.id === 'string') deviceNames.set(device.id, device.name);
      }
      const sessionRows = sessionList.map((item, index) => {
        const row = item !== null && typeof item === 'object' ? item : {};
        const deviceId = typeof row.deviceId === 'string' ? row.deviceId : '';
        const deviceName = deviceNames.get(deviceId);
        return h(
          'tr',
          { key: deviceId + ':' + String(row.createdAt) + ':' + index },
          h('td', null, h('div', { className: 'ag-cell-stack' }, h('span', null, typeof deviceName === 'string' && deviceName.length > 0 ? deviceName : '未知设备'), h('code', { className: 'ag-mono' }, deviceId))),
          h('td', { className: 'ag-cell-muted' }, formatTime(row.createdAt)),
          h('td', { className: 'ag-cell-muted' }, formatTime(row.lastSeenAt)),
          h('td', { className: 'ag-cell-muted' }, formatTime(row.expiresAt)),
          h('td', null, h(Tag, { tone: row.current === true ? 'info' : 'quiet' }, row.current === true ? '当前会话' : '有效'))
        );
      });

      const sessionsPanel = h(
        'section',
        { className: 'ag-card', id: 'ag-panel-sessions', role: 'tabpanel', 'aria-labelledby': 'ag-tab-sessions' },
        h('div', { className: 'ag-card-head' }, h('h2', { className: 'ag-card-title' }, '会话'), h('p', { className: 'ag-card-desc' }, '当前有效的登录会话；吊销设备会立即清空对应会话。')),
        sessionList.length === 0
          ? h(Empty, null, '当前没有有效会话。')
          : h(
              'div',
              { className: 'ag-table-wrap' },
              h(
                'table',
                { className: 'ag-table' },
                h('thead', null, h('tr', null, ['设备', '创建时间', '最近活跃', '到期时间', '状态'].map((label) => h('th', { key: label }, label)))),
                h('tbody', null, sessionRows)
              )
            )
      );

      const auditRows = (Array.isArray(audit) ? audit : []).map((entry, index) => {
        const row = entry !== null && typeof entry === 'object' ? entry : {};
        return h(
          'tr',
          { key: String(row.at) + ':' + index },
          h('td', { className: 'ag-cell-muted' }, formatTime(row.at)),
          h('td', null, auditLabel(row.type)),
          h('td', { className: 'ag-mono' }, typeof row.ip === 'string' ? row.ip : '—'),
          h('td', { className: 'ag-mono' }, typeof row.deviceId === 'string' && row.deviceId.length > 0 ? row.deviceId : '—'),
          h('td', null, typeof row.detail === 'string' ? row.detail : '—')
        );
      });

      const auditPanel = h(
        'section',
        { className: 'ag-card', id: 'ag-panel-audit', role: 'tabpanel', 'aria-labelledby': 'ag-tab-audit' },
        h(
          'div',
          { className: 'ag-card-head' },
          h('h2', { className: 'ag-card-title' }, '审计日志'),
          h('p', { className: 'ag-card-desc' }, '最近 ' + AUDIT_LIMIT + ' 条，按时间倒序，可滚动查看。'),
          h('div', { className: 'ag-actions' }, h(Button, { variant: 'outline', size: 'sm', icon: h(Glyph, { name: 'IconRefreshOutlineRegular' }), disabled: auditLoading, onClick: loadAudit }, auditLoading ? '刷新中…' : '刷新审计'))
        ),
        auditError === '' ? null : h(Alert, { tone: 'error' }, auditError),
        auditLoading && audit === null ? h(Loading, { label: '正在加载审计日志…' }) : null,
        auditRows.length === 0
          ? h(Empty, null, '暂无审计记录。')
          : h(
              'div',
              { className: 'ag-table-wrap', 'data-scroll': 'true' },
              h(
                'table',
                { className: 'ag-table' },
                h('thead', null, h('tr', null, ['时间', '类型', 'IP', '设备', '详情'].map((label) => h('th', { key: label }, label)))),
                h('tbody', null, auditRows)
              )
            )
      );

      const networkSourceLabel =
        network !== null && network.source === 'override' ? '运行时覆盖（network.json）' : '插件配置（cordis.patch.yml）';
      const networkPanel = h(
        'section',
        { className: 'ag-card', id: 'ag-panel-settings', role: 'tabpanel', 'aria-labelledby': 'ag-tab-settings' },
        h(
          'div',
          { className: 'ag-card-head' },
          h('h2', { className: 'ag-card-title' }, '网络设置'),
          h('p', { className: 'ag-card-desc' }, '修改网关监听地址/端口，以及生成配对二维码/链接使用的对外访问地址（publicUrl）与对外证书指纹。frp 内网穿透时 publicUrl 填中转公网 IP/域名，二维码不使用监听地址；若 TLS 由 frp/反向代理终止，请用「从对外地址自动读取」填写证书指纹，否则 App 会拒绝配对。')
        ),
        networkNotice !== null ? h(Alert, { tone: networkNotice.tone }, networkNotice.text) : null,
        h(
          'div',
          { className: 'ag-grid' },
          h(Field, { label: 'TLS 状态' }, h(Tag, { tone: network !== null && network.tlsConfigured === true ? 'success' : 'warning' }, network !== null && network.tlsConfigured === true ? '已配置（HTTPS）' : '未配置（HTTP）')),
          h(Field, { label: '当前生效来源' }, h('code', { className: 'ag-mono' }, network === null ? '—' : networkSourceLabel)),
          h(Field, { label: '当前监听' }, h('code', { className: 'ag-mono' }, network === null ? '—' : String(network.listenHost) + ':' + String(network.listenPort))),
          h(Field, { label: '对外访问地址' }, h('code', { className: 'ag-mono' }, network === null ? '—' : String(network.publicUrl))),
          h(Field, { label: '二维码当前生效指纹' }, h('code', { className: 'ag-mono' }, network === null ? '—' : String(network.effectiveFingerprint ?? '')))
        ),
        networkError === '' ? null : h(Alert, { tone: 'error' }, networkError),
        networkLoading && network === null ? h(Loading, { label: '正在加载网络设置…' }) : null,
        network === null && !networkLoading
          ? h(
              'div',
              { className: 'ag-actions' },
              h(
                Button,
                { type: 'button', variant: 'outline', size: 'sm', icon: h(Glyph, { name: 'IconRefreshOutlineRegular' }), onClick: loadNetwork },
                '重新加载网络设置'
              )
            )
          : null,
        h(Alert, { tone: 'warning' }, '修改监听地址/端口会关闭旧监听并立即用新地址重建，当前连接会短暂中断；保存成功后请稍后刷新页面，或使用新的地址重新访问。只修改 publicUrl 不会断开连接。'),
        h(
          'form',
          { className: 'ag-form', onSubmit: requestNetworkSave, noValidate: true },
          h(
            'div',
            { className: 'ag-grid' },
            h(
              Field,
              { label: '监听地址', htmlFor: 'ag-network-host', hint: '本机 LAN 网卡的具体 IPv4/IPv6 字面量；禁止 127.0.0.1/::1（loopback）与 0.0.0.0/:: 等通配地址；frp 时 frpc 的 local_ip 必须是同一 LAN 地址。' },
              h(Input, {
                id: 'ag-network-host',
                className: 'ag-input-wrap',
                type: 'text',
                autoComplete: 'off',
                value: networkForm.listenHost,
                disabled: networkBusy,
                onChange: (event) => setNetworkField('listenHost', event.target.value)
              })
            ),
            h(
              Field,
              { label: '监听端口', htmlFor: 'ag-network-port', hint: '1–65535，且不能等于 dsh 上游端口。' },
              h(Input, {
                id: 'ag-network-port',
                className: 'ag-input-wrap',
                type: 'text',
                inputMode: 'numeric',
                value: networkForm.listenPort,
                disabled: networkBusy,
                onChange: (event) => setNetworkField('listenPort', event.target.value.replace(/\D/gu, '').slice(0, 5))
              })
            ),
            h(
              'div',
              { className: 'ag-wide' },
              h(
                Field,
                {
                  label: '对外访问地址（publicUrl）',
                  htmlFor: 'ag-network-public',
                  hint: '用于生成配对二维码/链接；frp 中转时填中转公网 IP/域名。纯 origin，不能带路径/查询/片段/凭据，协议需与 TLS 状态一致。'
                },
                h(Input, {
                  id: 'ag-network-public',
                  className: 'ag-input-wrap',
                  type: 'text',
                  autoComplete: 'off',
                  value: networkForm.publicUrl,
                  disabled: networkBusy,
                  onChange: (event) => setNetworkField('publicUrl', event.target.value)
                })
              )
            ),
            h(
              'div',
              { className: 'ag-wide' },
              h(
                Field,
                {
                  label: '对外证书指纹（可选）',
                  htmlFor: 'ag-network-public-fp',
                  hint:
                    '留空 = 使用网关自身 TLS 证书；经 frp/反向代理（如 Caddy）终止 TLS 时填代理证书 SHA-256 DER（64 位十六进制）。「从对外地址自动读取」会对当前已保存的 publicUrl 建立 TLS 连接读取对端证书并保存；证书续期后需重新读取，否则 App 会因指纹不匹配拒绝配对。'
                },
                h(
                  'div',
                  { className: 'ag-actions' },
                  h(Input, {
                    id: 'ag-network-public-fp',
                    className: 'ag-input-wrap',
                    type: 'text',
                    autoComplete: 'off',
                    placeholder: '留空 = 网关自身证书；或 64 位 SHA-256',
                    value: networkForm.publicFingerprint,
                    disabled: networkBusy,
                    onChange: (event) => setNetworkField('publicFingerprint', event.target.value.trim())
                  }),
                  h(
                    Button,
                    {
                      type: 'button',
                      variant: 'outline',
                      size: 'sm',
                      disabled: networkBusy || networkLoading || network === null || rateLimitRemaining > 0,
                      icon: h(Glyph, { name: 'IconRefreshOutlineRegular' }),
                      onClick: autoNetworkFingerprint
                    },
                    networkBusy ? '读取中…' : '从对外地址自动读取'
                  )
                )
              )
            ),
            h(
              Field,
              {
                label: '6 位动态验证码' + (requirePairingTotp ? '（必填）' : '（本机通道可留空）'),
                htmlFor: 'ag-network-totp',
                hint: requirePairingTotp
                  ? '修改网络设置需验证动态码；该码只用于本次校验，不写入日志。'
                  : '管理密钥通道无需动态验证码；监听 loopback 时本机自动管理通道已禁用。'
              },
              h(Input, {
                id: 'ag-network-totp',
                className: 'ag-input-wrap',
                type: 'text',
                inputMode: 'numeric',
                autoComplete: 'one-time-code',
                maxLength: 6,
                value: networkForm.totp,
                disabled: networkBusy,
                placeholder: '000000',
                onChange: (event) => setNetworkField('totp', event.target.value.replace(/\D/gu, '').slice(0, 6))
              })
            )
          ),
          network !== null && typeof network.fingerprintHint === 'string' && network.fingerprintHint !== ''
            ? h('p', { className: 'ag-hint' }, network.fingerprintHint)
            : null,
          networkDirty ? h('p', { className: 'ag-hint' }, '有未保存的网络设置修改。') : null,
          networkConfirm
            ? h(
                'div',
                { className: 'ag-confirm' },
                h('p', { className: 'ag-card-desc' }, '确认保存网络设置？修改监听地址/端口会立即重建监听，当前连接会短暂中断；publicUrl 变更会影响后续配对二维码，已绑定旧地址的设备需要重新配对。'),
                h(
                  'div',
                  { className: 'ag-actions' },
                  h(Button, { variant: 'primary', disabled: networkBusy, onClick: confirmNetworkSave }, networkBusy ? '保存中…' : '确认保存'),
                  h(Button, { variant: 'ghost', disabled: networkBusy, onClick: () => setNetworkConfirm(false) }, '取消')
                )
              )
            : h(
                'div',
                { className: 'ag-actions' },
                h(
                  Button,
                  {
                    type: 'submit',
                    variant: 'primary',
                    disabled: networkBusy || networkLoading || network === null || rateLimitRemaining > 0,
                    icon: h(Glyph, { name: 'IconEditOutlineRegular' })
                  },
                  '保存网络设置'
                )
              )
        )
      );

      const panels = {
        pair: pairPanel,
        account: accountPanel,
        devices: devicesPanel,
        sessions: sessionsPanel,
        settings: networkPanel,
        audit: auditPanel
      };
      markScreen('tabs:' + tab);

      return h(
        'div',
        { className: 'ag-root' },
        header,
        h(
          'div',
          { className: 'ag-scroll' },
          h(
            'div',
            { className: 'ag-body' },
            banners,
            h('div', { className: 'ag-tabs' }, h(SegmentedTabs, { items: TABS, value: tab, onChange: setTab, label: '认证管理分区' })),
            h(PanelErrorBoundary, { label: '标签页 ' + tab }, panels[tab] ?? pairPanel),
            h(ToastView, { toast })
          )
        )
      );
    }

    /**
     * The sidebar glyph. The sidebar passes the requested edge (`size`) and
     * whether the panel is active; the glyph inherits the button's colour.
     * @param {{size?:number}} props
     */
    function AuthGateIcon({ size }) {
      const edge = typeof size === 'number' && size > 0 ? size : 18;
      return h(
        'svg',
        {
          width: edge,
          height: edge,
          viewBox: '0 0 24 24',
          fill: 'none',
          stroke: 'currentColor',
          strokeWidth: 1.7,
          strokeLinecap: 'round',
          strokeLinejoin: 'round',
          'aria-hidden': 'true',
          focusable: 'false'
        },
        h('path', { d: 'M12 3 5 6v5.2c0 4.4 2.9 7.9 7 9.8 4.1-1.9 7-5.4 7-9.8V6l-7-3Z' }),
        h('circle', { cx: 12, cy: 10.2, r: 2.1 }),
        h('path', { d: 'M12 12.3v2.8' })
      );
    }

    /**
     * Register the sidebar entry and its centre-column page. Both run through
     * `ctx.slots.inject`, which installs the callback as a ctx.effect: plugin
     * unload disposes the registrations and the React tree cleans its timers.
     * @param {import('@cordisjs/core').Context} ctx
     */
    function apply(ctx) {
      ctx.slots.inject('main', () =>
        ctx.slots.register(
          {
            name: 'main',
            key: PANEL_ID,
            label: () => '认证管理'
          },
          AuthGateRoot
        )
      );
      ctx.slots.inject('sidebar.panellist', () =>
        ctx.slots.register(
          {
            name: 'sidebar.panellist',
            id: PANEL_ID,
            order: 30,
            label: () => '认证管理'
          },
          AuthGateIcon
        )
      );
    }

    exports.NS = NS;
    exports.PANEL_ID = PANEL_ID;
    exports.GATEWAY_PORT = GATEWAY_PORT;
    exports.AuthGatePage = AuthGatePage;
    exports.AuthGateRoot = AuthGateRoot;
    exports.PortNotice = PortNotice;
    exports.PanelErrorBoundary = PanelErrorBoundary;
    exports.DebugCard = DebugCard;
    exports.ErrorFallbackCard = ErrorFallbackCard;
    exports.apply = apply;
    exports.inject = inject;
    // Small, side-effect-free helpers exposed for the isolated render harness.
    exports.__internals = {
      requestJson,
      loadSetupStatus,
      loginUrl,
      gatewayAdminUrl,
      isGatewayOrigin,
      sanitizeQrSvg,
      errorText,
      formatTime,
      platformLabel,
      auditLabel,
      debugEnabled,
      primitivesDiagnostics,
      runtimeState,
      isRenderableComponent
    };
    return module.exports;
  }
});
