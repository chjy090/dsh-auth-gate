/**
 * QR generation and the pairing payload shared with the Android client.
 *
 * The pairing URL keeps the one-time ticket in the URL **fragment** so it is
 * never sent to a server, never lands in access logs, and is not forwarded in a
 * `Referer` header:
 *
 *   {publicUrl}/__auth/pair#v=1&t=<ticket>&fp=<cert DER SHA256>&n=<hostname>
 */

import { createHash, X509Certificate } from 'node:crypto';
import { hostname as osHostname } from 'node:os';
import QRCode from 'qrcode';

export const PAIR_VERSION = '1';

/**
 * Render an SVG string (no XML prolog, safe to inline into HTML).
 * @param {string} text
 * @param {{width?:number,margin?:number,errorCorrectionLevel?:'L'|'M'|'Q'|'H'}} [options]
 * @returns {Promise<string>}
 */
export async function qrSvg(text, options = {}) {
  const svg = await QRCode.toString(String(text), {
    type: 'svg',
    margin: options.margin ?? 1,
    width: options.width ?? 320,
    errorCorrectionLevel: options.errorCorrectionLevel ?? 'M'
  });
  return svg.replace(/^<\?xml[^>]*\?>\s*/u, '').replace(/<!DOCTYPE[^>]*>\s*/u, '');
}

/**
 * Render a PNG buffer.
 * @param {string} text
 * @param {{width?:number,margin?:number}} [options]
 * @returns {Promise<Buffer>}
 */
export async function qrPng(text, options = {}) {
  return QRCode.toBuffer(String(text), {
    type: 'png',
    margin: options.margin ?? 1,
    width: options.width ?? 320,
    errorCorrectionLevel: options.errorCorrectionLevel ?? 'M'
  });
}

/**
 * SHA-256 of a certificate's DER encoding, lower-case hex — the fingerprint the
 * App compares after scanning.
 * @param {string|Buffer|Uint8Array} certificate PEM text or DER bytes
 * @returns {string|null} 64 hex chars, or null when the input is not a certificate
 */
export function certificateFingerprint(certificate) {
  if (certificate === undefined || certificate === null) return null;
  const buffer = typeof certificate === 'string' ? Buffer.from(certificate, 'utf8') : Buffer.from(certificate);
  if (buffer.length === 0) return null;
  try {
    const cert = new X509Certificate(buffer);
    return createHash('sha256').update(cert.raw).digest('hex');
  } catch {
    return null;
  }
}

/**
 * Build the pairing URL.
 * @param {{publicUrl:string,ticket:string,fingerprint?:string,hostname?:string}} input
 * @returns {string}
 */
export function pairUrl(input) {
  const { publicUrl, ticket, fingerprint = '', hostname = osHostname() } = input;
  if (typeof publicUrl !== 'string' || publicUrl.length === 0) throw new TypeError('qr: publicUrl is required');
  if (typeof ticket !== 'string' || ticket.length === 0) throw new TypeError('qr: ticket is required');
  const base = publicUrl.replace(/\/+$/u, '');
  const params = new URLSearchParams();
  params.set('v', PAIR_VERSION);
  params.set('t', ticket);
  params.set('fp', fingerprint);
  if (typeof hostname === 'string' && hostname.length > 0) params.set('n', hostname);
  // URLSearchParams encodes with '+'; fragments are opaque to servers but the
  // App parses them with standard URLSearchParams, so both sides agree.
  return `${base}/__auth/pair#${params.toString()}`;
}
