/**
 * Public-certificate fingerprint probe (v0.6.2).
 *
 * When the gateway sits behind frp + a TLS-terminating reverse proxy (Caddy,
 * nginx, …), the App sees the *proxy* certificate while the gateway's own
 * certificate is never on the wire. Device pairing is fail-closed: the App
 * pins the `fp=` value from the QR code, so that value must be the public
 * certificate. `publicFingerprint: "auto"` resolves it by opening a TLS
 * connection to the current `publicUrl` and hashing the leaf certificate.
 *
 * Safety properties:
 *  - the target is derived exclusively from the validated `publicUrl`
 *    (host + port), never from a caller-supplied address — the API cannot be
 *    used as a generic SSRF/TLS-scan primitive;
 *  - https only (a plain-HTTP origin has no certificate to pin);
 *  - no HTTP request is sent: connect, read `getPeerCertificate()`, destroy;
 *  - certificate verification is deliberately disabled (self-signed public
 *    proxies are legitimate) but the result is only a fingerprint;
 *  - a hard timeout (5 s by default) bounds the operation.
 */

import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import * as tls from 'node:tls';

/** Default probe budget; the network API serializes updates while probing. */
export const FINGERPRINT_PROBE_TIMEOUT_MS = 5_000;

/**
 * A probe failure carrying a coarse, non-reflective reason
 * (`not_https`, `timeout`, `connection_refused`, `dns_failed`, …).
 */
export class FingerprintProbeError extends Error {
  /**
   * @param {string} reason
   * @param {unknown} [cause]
   */
  constructor(reason, cause = undefined) {
    super(`fingerprint probe failed (${reason})`);
    this.name = 'FingerprintProbeError';
    this.reason = reason;
    if (cause !== undefined) this.cause = cause;
  }
}

/**
 * Map socket/TLS errors to a stable reason code (never the raw message, which
 * could reflect the target address back to the caller).
 * @param {any} error
 * @returns {string}
 */
function probeReason(error) {
  switch (error?.code) {
    case 'ECONNREFUSED':
      return 'connection_refused';
    case 'ETIMEDOUT':
      return 'timeout';
    case 'ECONNRESET':
      return 'connection_reset';
    case 'ENOTFOUND':
    case 'EAI_AGAIN':
      return 'dns_failed';
    case 'EHOSTUNREACH':
    case 'ENETUNREACH':
      return 'unreachable';
    default:
      return 'connect_failed';
  }
}

/**
 * Read the leaf certificate served by `publicUrl` and return the SHA-256 of its
 * DER encoding (lower-case hex) — the same value `certificateFingerprint()`
 * computes from a PEM file and the App compares after scanning.
 *
 * @param {string} publicUrl a validated public origin (https only)
 * @param {{timeoutMs?:number}} [options]
 * @returns {Promise<string>} 64 lower-case hex characters
 */
export function fetchPeerFingerprint(publicUrl, options = {}) {
  const timeoutMs = Number.isInteger(options.timeoutMs) && options.timeoutMs > 0 ? options.timeoutMs : FINGERPRINT_PROBE_TIMEOUT_MS;
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(String(publicUrl));
    } catch {
      reject(new FingerprintProbeError('invalid_public_url'));
      return;
    }
    if (url.protocol !== 'https:') {
      reject(new FingerprintProbeError('not_https'));
      return;
    }
    // WHATWG URL keeps the brackets on IPv6 hostnames; net/tls want them gone.
    const hostname = url.hostname.replace(/^\[|\]$/gu, '');
    if (hostname.length === 0) {
      reject(new FingerprintProbeError('invalid_public_url'));
      return;
    }
    const port = url.port === '' ? 443 : Number(url.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      reject(new FingerprintProbeError('invalid_public_url'));
      return;
    }
    // SNI is only meaningful for DNS names; an IP literal is connected to
    // directly (no resolver involved).
    const ipFamily = isIP(hostname);
    let settled = false;
    /** @type {import('node:tls').TLSSocket} */
    let socket;
    const finish = (error, fingerprint) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        // already gone
      }
      if (error !== null && error !== undefined) reject(error);
      else resolve(fingerprint);
    };
    try {
      socket = tls.connect({
        host: hostname,
        port,
        ...(ipFamily === 0 ? { servername: hostname } : {}),
        rejectUnauthorized: false,
        timeout: timeoutMs
      });
    } catch (error) {
      reject(new FingerprintProbeError('connect_failed', error));
      return;
    }
    socket.once('secureConnect', () => {
      try {
        const certificate = socket.getPeerCertificate();
        if (
          certificate === null ||
          typeof certificate !== 'object' ||
          !(certificate.raw instanceof Uint8Array) ||
          certificate.raw.length === 0
        ) {
          finish(new FingerprintProbeError('no_certificate'));
          return;
        }
        finish(null, createHash('sha256').update(certificate.raw).digest('hex'));
      } catch (error) {
        finish(new FingerprintProbeError('certificate_failed', error));
      }
    });
    socket.once('timeout', () => finish(new FingerprintProbeError('timeout')));
    socket.once('error', (error) => finish(new FingerprintProbeError(probeReason(error), error)));
  });
}
