#!/usr/bin/env node
/**
 * Standalone development/test entry point.
 *
 * Runs the same gateway without Cordis: the dsh launch token comes from
 * `DSH_TOKEN_URL` (a journal URL such as
 * `http://127.0.0.1:3080/?token=...`) or from `DSH_TOKEN` (a bare token, which
 * is appended to the configured upstream root). Configuration comes from
 * `AUTH_GATE_*` environment variables; secrets are never printed.
 */

import { gatewayConfig, resolveConfigWithNetworkFallback } from './config.js';
import { DshSessionProvider } from './dsh-session.js';
import { createGateway } from './gateway.js';
import { StateStore } from './store.js';

const logger = {
  info: (...args) => console.log(...args),
  warn: (...args) => console.warn(...args),
  error: (...args) => console.error(...args)
};

function envValue(env, ...names) {
  for (const name of names) {
    const value = env[name];
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return undefined;
}

function numberFromEnv(env, name) {
  const value = env[name];
  if (value === undefined || value === '') return undefined;
  return value;
}

function rawConfigFromEnv(env) {
  return {
    listenHost: envValue(env, 'AUTH_GATE_LISTEN_HOST', 'AUTH_GATE_HOST'),
    listenPort: numberFromEnv(env, 'AUTH_GATE_LISTEN_PORT') ?? numberFromEnv(env, 'AUTH_GATE_PORT'),
    upstream: envValue(env, 'AUTH_GATE_UPSTREAM'),
    upstreamInsecureTls: envValue(env, 'AUTH_GATE_UPSTREAM_INSECURE_TLS'),
    publicUrl: envValue(env, 'AUTH_GATE_PUBLIC_URL'),
    publicFingerprint: envValue(env, 'AUTH_GATE_PUBLIC_FINGERPRINT'),
    tlsCert: envValue(env, 'AUTH_GATE_TLS_CERT'),
    tlsKey: envValue(env, 'AUTH_GATE_TLS_KEY'),
    stateDir: envValue(env, 'AUTH_GATE_STATE_DIR'),
    adminKeyFile: envValue(env, 'AUTH_GATE_ADMIN_KEY_FILE'),
    sessionTtlHours: numberFromEnv(env, 'AUTH_GATE_SESSION_TTL_HOURS'),
    sessionAbsoluteTtlDays: numberFromEnv(env, 'AUTH_GATE_SESSION_ABSOLUTE_TTL_DAYS'),
    deviceTtlDays: numberFromEnv(env, 'AUTH_GATE_DEVICE_TTL_DAYS'),
    deviceAbsoluteTtlDays: numberFromEnv(env, 'AUTH_GATE_DEVICE_ABSOLUTE_TTL_DAYS'),
    maxDevices: numberFromEnv(env, 'AUTH_GATE_MAX_DEVICES'),
    pairTicketTtlSeconds: numberFromEnv(env, 'AUTH_GATE_PAIR_TICKET_TTL_SECONDS'),
    loginLock: {
      maxFailures: numberFromEnv(env, 'AUTH_GATE_LOGIN_MAX_FAILURES'),
      windowMinutes: numberFromEnv(env, 'AUTH_GATE_LOGIN_WINDOW_MINUTES'),
      lockMinutes: numberFromEnv(env, 'AUTH_GATE_LOGIN_LOCK_MINUTES')
    }
  };
}

function tokenUrlFor(resolved, env) {
  const direct = envValue(env, 'DSH_TOKEN_URL', 'AUTH_GATE_DSH_TOKEN_URL');
  if (direct !== undefined) {
    if (!/^https?:\/\//iu.test(direct)) throw new Error('standalone: DSH_TOKEN_URL must be an absolute http(s) URL');
    return direct;
  }
  const token = envValue(env, 'DSH_TOKEN', 'AUTH_GATE_DSH_TOKEN');
  if (token === undefined) {
    throw new Error('standalone: DSH_TOKEN_URL (or DSH_TOKEN) is required; take the launch URL from the dsh journal');
  }
  if (/^https?:\/\//iu.test(token)) return token;
  const root = new URL('/', resolved.upstreamBaseUrl);
  root.searchParams.set('token', token);
  return root.href;
}

async function main() {
  const env = process.env;
  const resolved = await resolveConfigWithNetworkFallback(rawConfigFromEnv(env), { env, logger });
  const tokenUrl = tokenUrlFor(resolved, env);
  const store = await StateStore.open({
    stateDir: resolved.stateDir,
    adminKeyFile: resolved.adminKeyFile,
    logger
  });
  const dshSession = new DshSessionProvider({
    tokenUrl,
    insecureTls: resolved.upstreamInsecureTls,
    logger
  });
  const gateway = createGateway({
    config: gatewayConfig(resolved),
    store,
    dshSession,
    tls: resolved.tls,
    fingerprint: resolved.fingerprint,
    logger
  });
  try {
    await gateway.listen();
  } catch (error) {
    await gateway.close();
    throw error;
  }
  logger.info(`auth-gate[standalone]: public ${resolved.publicUrl}, upstream ${resolved.upstreamOrigin}, state ${resolved.stateDir}`);
  logger.info(`auth-gate[standalone]: admin key file ${resolved.adminKeyFile}, certificate fingerprint ${resolved.fingerprint || '(none)'}`);
  logger.info('auth-gate[standalone]: press Ctrl+C to stop');

  let stopping = false;
  const stop = async (signal) => {
    if (stopping) {
      logger.warn(`auth-gate[standalone]: ${signal} again, exiting immediately`);
      process.exit(1);
      return;
    }
    stopping = true;
    logger.info(`auth-gate[standalone]: ${signal} received, shutting down`);
    try {
      await gateway.close();
    } catch (error) {
      logger.error(`auth-gate[standalone]: shutdown error: ${error.message}`);
      process.exitCode = 1;
    }
    process.exit(process.exitCode ?? 0);
  };
  process.on('SIGINT', () => void stop('SIGINT'));
  process.on('SIGTERM', () => void stop('SIGTERM'));
  process.on('unhandledRejection', (reason) => {
    logger.error(`auth-gate[standalone]: unhandled rejection: ${reason instanceof Error ? reason.message : String(reason)}`);
  });
  process.on('uncaughtException', (error) => {
    logger.error(`auth-gate[standalone]: uncaught exception: ${error.message}`);
    void stop('uncaughtException');
  });
}

main().catch((error) => {
  logger.error(`auth-gate[standalone]: ${error?.message ?? error}`);
  process.exitCode = 1;
});
