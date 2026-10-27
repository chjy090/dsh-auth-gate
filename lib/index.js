/**
 * Cordis plugin entry for dsh-auth-gate.
 *
 * Startup failures are logged and swallowed on purpose: this plugin is loaded
 * during boot, and a bad optional configuration must not take down the whole
 * Harness. The front door simply stays closed; dsh itself keeps working on its
 * own listener.
 */

import { resolveConfig, gatewayConfig } from './config.js';
import { DshSessionProvider } from './dsh-session.js';
import { createGateway } from './gateway.js';
import { StateStore } from './store.js';

export const name = 'dsh-auth-gate';
export const inject = ['connection'];

const logger = {
  info: (...args) => console.log(...args),
  warn: (...args) => console.warn(...args),
  error: (...args) => console.error(...args)
};

/**
 * @param {import('@cordisjs/core').Context} ctx
 * @param {Record<string, unknown>} config
 */
export async function apply(ctx, config) {
  let store;
  let gateway;
  try {
    const resolved = await resolveConfig(config ?? {}, { env: process.env });
    store = await StateStore.open({
      stateDir: resolved.stateDir,
      adminKeyFile: resolved.adminKeyFile,
      logger
    });
    const dshSession = new DshSessionProvider({
      // The launch token is exchanged server-side; it never reaches a browser.
      tokenUrl: () => ctx.connection.authenticatedUrl(resolved.upstreamBaseUrl),
      insecureTls: resolved.upstreamInsecureTls,
      logger
    });
    gateway = createGateway({
      config: gatewayConfig(resolved),
      store,
      dshSession,
      tls: resolved.tls,
      fingerprint: resolved.fingerprint,
      logger
    });
    ctx.effect(
      () => () => gateway.close().catch((error) => logger.error(`auth-gate: shutdown failed: ${error.message}`)),
      'dsh-auth-gate: gateway'
    );
    await gateway.listen();
  } catch (error) {
    logger.error(`auth-gate: failed to start: ${error?.message ?? error}`);
    if (gateway !== undefined) {
      try {
        await gateway.close();
      } catch {
        // already logged above; do not throw out of a boot path
      }
    } else if (store !== undefined) {
      try {
        await store.close();
      } catch {
        // ignore
      }
    }
  }
}
