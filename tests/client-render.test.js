/**
 * Isolated render harness for lib/client.js (no browser, no real React).
 *
 * The bundle registers its factory on `window.__ModuleLoader__`; a fake React
 * with hook state allows rendering the panel tree synchronously, and a fake
 * primitives module exercises the local fallbacks. This is deliberately small:
 * it asserts the regressions that used to blank the native panel (a
 * ReferenceError in the ready branch, unhandled render errors, missing
 * primitives) without needing react-dom.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

// AUTH_GATE_CLIENT_SOURCE lets the isolated preflight render the *downloaded*
// bundle (the same bytes dsh served in its boot manifest), not just the source.
const CLIENT_SOURCE = readFileSync(process.env.AUTH_GATE_CLIENT_SOURCE ?? new URL('../lib/client.js', import.meta.url), 'utf8');

/** Minimal React stand-in: hooks are state-plan overrides, effects are queued. */
function createFakeReact() {
  let statePlan = null;
  let stateIndex = 0;
  const effects = [];

  class Component {
    constructor(props) {
      this.props = props || {};
      this.state = {};
    }

    setState(next) {
      const patch = typeof next === 'function' ? next(this.state) : next;
      this.state = Object.assign({}, this.state, patch);
    }
  }

  const React = {
    version: '18.2.0-fake',
    Component,
    createElement(type, props, ...children) {
      const nextProps = Object.assign({}, props || {});
      if (children.length === 1) nextProps.children = children[0];
      else if (children.length > 1) nextProps.children = children;
      return { $$typeof: 'fake.element', type, props: nextProps };
    },
    useState(initial) {
      const index = stateIndex;
      stateIndex += 1;
      let value;
      if (statePlan !== null && Object.prototype.hasOwnProperty.call(statePlan, index)) value = statePlan[index];
      else value = typeof initial === 'function' ? initial() : initial;
      return [value, () => {}];
    },
    useRef(initial) {
      return { current: initial };
    },
    useEffect(fn) {
      effects.push(fn);
    },
    useLayoutEffect() {},
    useMemo(factory) {
      return factory();
    },
    useCallback(fn) {
      return fn;
    },
    Fragment: 'FakeFragment'
  };

  return {
    React,
    setStatePlan(plan) {
      statePlan = plan;
      stateIndex = 0;
    },
    resetHooks() {
      statePlan = null;
      stateIndex = 0;
      effects.length = 0;
    },
    /** Run effects queued by the last render (cleanups are ignored). */
    async runEffects() {
      const queued = effects.splice(0);
      for (const effect of queued) {
        const cleanup = effect();
        if (cleanup !== null && typeof cleanup === 'object' && typeof cleanup.then === 'function') await cleanup;
      }
    }
  };
}

/** Load a fresh copy of the bundle inside a VM context. */
function loadClient(options = {}) {
  const fake = createFakeReact();
  const logs = [];
  const loader = { factory: null };
  const location = Object.assign(
    {
      href: 'https://192.0.2.10:3443/ui',
      port: '3443',
      hostname: '192.0.2.10',
      origin: 'https://192.0.2.10:3443',
      pathname: '/ui',
      search: '',
      hash: ''
    },
    options.location || {}
  );
  const primitives = options.primitives === undefined ? {} : options.primitives;
  const fetchCalls = [];
  const fetchImpl =
    typeof options.fetch === 'function'
      ? options.fetch
      : async () => {
          throw new Error('network disabled in harness');
        };
  const sandbox = {
    window: {
      __ModuleLoader__: {
        load(entry) {
          loader.factory = entry.factory;
        }
      },
      location
    },
    console: {
      error(...args) {
        logs.push({ level: 'error', args });
      },
      info(...args) {
        logs.push({ level: 'info', args });
      },
      log() {},
      warn() {}
    },
    document: {
      visibilityState: 'visible',
      createElement() {
        return { style: {}, setAttribute() {}, select() {}, remove() {}, appendChild() {} };
      },
      querySelector() {
        return null;
      },
      head: { appendChild() {} },
      body: { appendChild() {} },
      addEventListener() {},
      removeEventListener() {}
    },
    navigator: { clipboard: null },
    setInterval() {
      return 1;
    },
    clearInterval() {},
    setTimeout() {
      return 1;
    },
    clearTimeout() {},
    async fetch(url, init) {
      fetchCalls.push({ url, init });
      return fetchImpl(url, init);
    },
    Date,
    Math,
    JSON
  };
  vm.createContext(sandbox);
  vm.runInContext(CLIENT_SOURCE, sandbox, { filename: 'lib/client.js' });
  assert.equal(typeof loader.factory, 'function', 'client bundle did not register a factory');

  const requireFn = (id) => {
    if (id === 'react') return fake.React;
    if (id === '@deepseek-ai/dsh-client-ui-primitives') {
      if (primitives instanceof Error) throw primitives;
      if (typeof primitives === 'function') return primitives();
      return primitives;
    }
    throw new Error('unexpected require: ' + id);
  };

  const mod = loader.factory(requireFn);
  return { mod, fake, logs, location, fetchCalls };
}

/**
 * Flatten a fake element tree into text, executing function components and
 * class components (guards, the error boundary, cards) as a renderer would.
 */
function renderText(node, depth = 0) {
  if (node === null || node === undefined || typeof node === 'boolean') return '';
  if (typeof node === 'string') return node;
  if (typeof node === 'number') return String(node);
  if (depth > 40) return '';
  if (Array.isArray(node)) return node.map((child) => renderText(child, depth)).join('');
  if (typeof node !== 'object') return '';
  const type = node.type;
  const props = node.props || {};
  if (typeof type === 'string') return renderText(props.children, depth + 1);
  if (typeof type === 'function') {
    if (type.prototype && typeof type.prototype.render === 'function') {
      return renderText(new type(props).render(), depth + 1);
    }
    return renderText(type(props), depth + 1);
  }
  return '';
}

/** Admin state for the configured ready branch. */
function readyAdminState(configured = true) {
  return {
    configured,
    user: configured ? { username: 'tester', totpConfigured: true } : null,
    devices: configured
      ? [{ id: 'dev_1', name: 'Pixel', platform: 'android', online: true, createdAt: 1, lastSeenAt: 2, expiresAt: 3 }]
      : [],
    sessionList: configured ? [{ deviceId: 'dev_1', createdAt: 1, lastSeenAt: 2, expiresAt: 3, current: true }] : []
  };
}

test('ready panel renders the header without throwing (totpBound regression)', () => {
  const { mod, fake } = loadClient();
  fake.setStatePlan({
    0: 'ready',
    1: { authenticated: true, user: { username: 'tester' } },
    2: readyAdminState(true),
    3: 'session',
    5: 'csrf-token'
  });
  const tree = mod.AuthGatePage({});
  const text = renderText(tree);
  assert.match(text, /认证管理/u);
  assert.match(text, /TOTP 已配置/u);
  assert.match(text, /用户 tester/u);
  assert.match(text, /192\.0\.2\.10:3443/u);
});

test('ready but unconfigured panel renders the setup card instead of blank', () => {
  const { mod, fake } = loadClient();
  fake.setStatePlan({
    0: 'ready',
    1: { authenticated: true, user: { username: 'tester' } },
    2: readyAdminState(false),
    3: 'session'
  });
  const text = renderText(mod.AuthGatePage({}));
  assert.match(text, /尚未初始化/u);
  assert.match(text, /认证管理/u);
});

test('setup/status=false renders the uninitialized card and sends no other request', async () => {
  const { mod, fake, fetchCalls } = loadClient({
    fetch: async () => ({
      ok: true,
      status: 200,
      headers: { get: () => null },
      json: async () => ({ configured: false, hasToken: true, setupPath: '/__admin' })
    })
  });
  // Render once (queues the bootstrap effect), then run the effect. With an
  // unconfigured gateway the panel must stop after the public status probe:
  // no CSRF, whoami, state, audit or polling request.
  renderText(mod.AuthGatePage({}));
  await fake.runEffects();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.deepEqual(
    fetchCalls.map((call) => call.url),
    ['/__admin/api/setup/status']
  );

  fake.resetHooks();
  fake.setStatePlan({ 0: 'setup' });
  const text = renderText(mod.AuthGatePage({}));
  assert.match(text, /网关尚未初始化/u);
  assert.match(text, /setup\.token/u);
  assert.match(text, /打开初始化页面/u);
  assert.doesNotMatch(text, /去登录/u);
  assert.doesNotMatch(text, /登录后即可/u);
});

test('panel opened on the dsh port still shows the gateway notice', () => {
  const { mod, fake } = loadClient({ location: { port: '3080', origin: 'https://192.0.2.10:3080' } });
  fake.resetHooks();
  fake.setStatePlan({ 0: 'offgateway' });
  const text = renderText(mod.AuthGatePage({}));
  assert.match(text, /不是认证网关/u);
  assert.match(text, /3443/u);
});

test('a non-3443 frp origin is confirmed through the public status probe', async () => {
  const jsonResponse = (data) => ({
    ok: true,
    status: 200,
    headers: { get: () => null },
    json: async () => data
  });
  const { mod, fake, fetchCalls } = loadClient({
    location: { port: '3457', hostname: 'relay.example', origin: 'https://relay.example:3457' },
    fetch: async (url) => {
      if (url === '/__admin/api/setup/status') return jsonResponse({ configured: true, hasToken: false, setupPath: '/__admin' });
      if (url === '/__auth/csrf') return jsonResponse({ csrf: 'token' });
      if (url === '/__auth/whoami') return jsonResponse({ authenticated: false });
      if (url === '/__admin/api/state') return jsonResponse(readyAdminState(true));
      throw new Error('unexpected request ' + url);
    }
  });
  renderText(mod.AuthGatePage({}));
  await fake.runEffects();
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.equal(fetchCalls[0].url, '/__admin/api/setup/status', 'the port gate must first probe the gateway status endpoint');
  assert.equal(
    fetchCalls.some((call) => call.url === '/__admin/api/state'),
    true,
    'a successful probe must continue the normal bootstrap (no port-based degradation)'
  );
});

test('missing primitives degrade to local fallbacks and still render', () => {
  const { mod, fake, logs } = loadClient({ primitives: new Error('module not found'), location: { port: '3080', origin: 'https://192.0.2.10:3080' } });
  const diag = mod.__internals.primitivesDiagnostics();
  assert.equal(diag.loaded, false);
  assert.match(diag.error, /module not found/u);
  assert.equal(diag.bindings.Button, 'fallback');
  assert.equal(diag.bindings.Input, 'fallback');
  assert.equal(diag.bindings.SegmentedControl, 'fallback');
  assert.equal(diag.bindings.SegmentedTabs, 'fallback');
  assert.equal(diag.bindings.Tag, 'fallback');
  // Rendering must not throw just because the design system is absent.
  fake.setStatePlan({ 0: 'offgateway' });
  const text = renderText(mod.AuthGatePage({}));
  assert.match(text, /不是认证网关/u);
  assert.equal(logs.filter((entry) => entry.level === 'error').length, 0);
});

test('settings tab renders the network form, source, publicUrl and TOTP hint', () => {
  const { mod, fake } = loadClient();
  fake.setStatePlan({
    0: 'ready',
    1: { authenticated: true, user: { username: 'tester' } },
    2: readyAdminState(true),
    3: 'session',
    4: 'settings',
    5: 'csrf-token',
    28: {
      listenHost: '127.0.0.1',
      listenPort: 3443,
      publicUrl: 'https://relay.example:8443',
      tlsConfigured: true,
      source: 'override',
      publicFingerprint: '',
      effectiveFingerprint: '70a78d74d75fc65a17685b11408b5337cb3f5c32f91346e8705043251a45aaac',
      fingerprintHint: '二维码使用网关自身 TLS 证书指纹；若 TLS 在 frp/反向代理处终止，请设置「对外证书指纹」。'
    },
    31: { listenHost: '127.0.0.1', listenPort: '3443', publicUrl: 'https://relay.example:8443', publicFingerprint: '', totp: '' }
  });
  const text = renderText(mod.AuthGatePage({}));
  assert.match(text, /网络设置/u);
  assert.match(text, /运行时覆盖（network\.json）/u);
  assert.match(text, /已配置（HTTPS）/u);
  assert.match(text, /https:\/\/relay\.example:8443/u);
  assert.match(text, /对外访问地址（publicUrl）/u);
  assert.match(text, /对外证书指纹（可选）/u);
  assert.match(text, /从对外地址自动读取/u);
  assert.match(text, /二维码当前生效指纹/u);
  assert.match(text, /70a78d74d75fc65a17685b11408b5337cb3f5c32f91346e8705043251a45aaac/u);
  assert.match(text, /frp/u);
  assert.match(text, /修改网络设置需验证动态码/u);
  assert.match(text, /保存网络设置/u);
  assert.match(text, /当前连接会短暂中断/u);
  assert.doesNotMatch(text, /渲染失败/u);
});

test('debug card is off by default and appears for the debug flag', () => {
  const off = loadClient();
  assert.equal(off.mod.__internals.debugEnabled(), false);
  assert.equal(renderText(off.mod.AuthGatePage({})).includes('auth-gate 调试'), false);

  const byQuery = loadClient({ location: { search: '?authgate-debug=1' } });
  assert.equal(byQuery.mod.__internals.debugEnabled(), true);

  const byHash = loadClient({ location: { hash: '#authgate-debug' } });
  assert.equal(byHash.mod.__internals.debugEnabled(), true);

  const text = renderText(byHash.mod.DebugCard({}));
  assert.match(text, /auth-gate 调试/u);
  assert.match(text, /location\.href/u);
  assert.match(text, /location\.port/u);
  assert.match(text, /React\.version/u);
  assert.match(text, /primitives keys/u);
  assert.match(text, /hook: phase/u);
  assert.match(text, /当前渲染/u);
});

test('error boundary renders a visible card, truncates the stack and logs', () => {
  const { mod, logs } = loadClient({ location: { search: '?authgate-debug=1' } });
  const thrown = new Error('totpBound is not defined');
  const longStack = 'ReferenceError: totpBound is not defined\n' + '    at AuthGatePage (client.js:1:1)\n'.repeat(80);
  thrown.stack = longStack;
  assert.ok(longStack.length > 1500, 'fixture stack must exceed the truncation limit');

  const boundary = new mod.PanelErrorBoundary({ label: '认证管理面板' });
  boundary.state = mod.PanelErrorBoundary.getDerivedStateFromError(thrown);
  boundary.componentDidCatch(thrown);

  const text = renderText(boundary.render());
  assert.match(text, /认证管理渲染失败/u);
  assert.match(text, /totpBound is not defined/u);
  assert.ok(text.includes(longStack.slice(0, 1500)), 'stack prefix must be rendered');
  assert.equal(text.includes(longStack.slice(0, 1501)), false, 'stack must be truncated at 1500 characters');
  assert.match(text, /F12/u);
  assert.match(text, /\[auth-gate\]/u);
  assert.match(text, /\/__admin/u);

  const renderFailure = logs.find((entry) => entry.args[0] === '[auth-gate] render failed');
  assert.ok(renderFailure, 'componentDidCatch must log [auth-gate] render failed');
  assert.equal(renderFailure.args[1].message, 'totpBound is not defined');
});

test('error boundary falls back to the absolute 3443 admin URL off-gateway', () => {
  const { mod } = loadClient({ location: { port: '3080', origin: 'https://192.0.2.10:3080' } });
  const card = mod.ErrorFallbackCard({ error: new Error('boom'), label: '认证管理面板' });
  const serialized = JSON.stringify(card);
  assert.match(serialized, /https:\/\/192\.0\.2\.10:3443\/__admin/u);
});

test('registered root is a boundary wrapper, and exports keep the public API', () => {
  const { mod } = loadClient();
  assert.equal(typeof mod.AuthGateRoot, 'function');
  assert.equal(typeof mod.PanelErrorBoundary, 'function');
  assert.equal(typeof mod.AuthGatePage, 'function');
  assert.equal(typeof mod.PortNotice, 'function');
  assert.deepEqual([...mod.inject], ['slots']);
  assert.equal(mod.PANEL_ID, 'auth-gate');
  assert.equal(mod.GATEWAY_PORT, '3443');

  const registrations = [];
  mod.apply({
    slots: {
      inject(_name, callback) {
        callback();
      },
      register(spec, component) {
        registrations.push({ spec, component });
        return spec;
      }
    }
  });
  const main = registrations.find((entry) => entry.spec.name === 'main');
  assert.equal(main.component, mod.AuthGateRoot);
});
