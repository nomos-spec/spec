/**
 * Cryptographic utilities — JCS canonicalization + seal verification
 * Per NOMOS-SPEC-001 §8 and RFC 8785
 */

import * as crypto from 'crypto';
import type { NomosArtifact } from './types';

// ─── JCS (RFC 8785) ──────────────────────────────────────────────────────────

type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };

function jcsValue(v: JsonValue): string {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') {
    if (!isFinite(v)) throw new Error('NaN/Infinity not valid in JCS');
    return String(v);
  }
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcsValue).join(',') + ']';
  // Object — sort keys lexicographically
  const keys = Object.keys(v).sort();
  const pairs = keys.map(k => `${JSON.stringify(k)}:${jcsValue(v[k])}`);
  return '{' + pairs.join(',') + '}';
}

export function canonicalizeJCS(obj: unknown): string {
  return jcsValue(obj as JsonValue);
}

// ─── Seal verification ───────────────────────────────────────────────────────

/**
 * Verify the cryptographic seal of a .nomos artifact.
 * Returns true if valid, false if tampered or key mismatch.
 */
export function verifySeal(artifact: NomosArtifact, sealKey: string): boolean {
  try {
    const { seal, ...payload } = artifact;
    const canonical = canonicalizeJCS(payload);
    const expectedHash = crypto
      .createHash('sha256')
      .update(canonical, 'utf8')
      .digest('hex');

    const keyBuffer = Buffer.from(sealKey, 'hex').length === 32
      ? Buffer.from(sealKey, 'hex')
      : Buffer.from(sealKey, 'utf8');

    const expectedSig = crypto
      .createHmac('sha256', keyBuffer)
      .update(expectedHash, 'utf8')
      .digest('hex');

    const hashMatch = crypto.timingSafeEqual(
      Buffer.from(expectedHash, 'hex'),
      Buffer.from(seal.hash.padEnd(64, '0').slice(0, 64), 'hex'),
    );
    const sigMatch = crypto.timingSafeEqual(
      Buffer.from(expectedSig, 'hex'),
      Buffer.from(seal.sig.padEnd(64, '0').slice(0, 64), 'hex'),
    );
    return hashMatch && sigMatch;
  } catch {
    return false;
  }
}

// ─── Audit hash chaining ─────────────────────────────────────────────────────

/**
 * Compute the next audit hash in the chain.
 * SHA-256(previousHash || requestId || verdict || ts)
 */
export function computeAuditHash(
  previousHash: string,
  requestId: string,
  verdict: string,
  ts: string,
): string {
  return crypto
    .createHash('sha256')
    .update(previousHash + requestId + verdict + ts)
    .digest('hex');
}

/** Genesis hash for the first entry in an artifact's audit chain */
export function genesisHash(artifactId: string, sealTs: string): string {
  return crypto
    .createHash('sha256')
    .update('genesis:' + artifactId + ':' + sealTs)
    .digest('hex');
}
