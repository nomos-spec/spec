/**
 * Generates FIXED interop test vectors for NOMOS-SPEC-007's chain-verification logic.
 *
 * Deliberately NOT regenerated with fresh keys on every run, unlike prototype/chain-of-trust's
 * own demo.ts — a third party checking their own implementation against these needs the same
 * bytes every time, not a moving target. The private keys here are published in the clear on
 * purpose: they exist ONLY to make these vectors independently regenerable/auditable, and must
 * never be treated as real trust material by anything.
 *
 * Uses this repo's own reference implementation (../prototype/chain-of-trust/key-cert.ts) —
 * the public spec's own vectors should be provably self-consistent with the public spec's own
 * reference code, not silently dependent on a private deployment's internals.
 *
 * Run once to (re)produce vectors.json:  npx tsx chain-of-trust-vectors/generate.ts
 */
import crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { createKeyCertificate, jcs } from '../prototype/chain-of-trust/key-cert.js';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const FIXED_ISSUED_AT = new Date('2026-01-01T00:00:00.000Z');
const FIXED_EXPIRES_AT = new Date('2030-01-01T00:00:00.000Z');
const FIXED_EXPIRED_AT = new Date('2026-06-01T00:00:00.000Z'); // in the past relative to "now" checks below
const CHECK_AT = new Date('2027-01-01T00:00:00.000Z');          // the `now` a checker should pass in

function kid(pub: crypto.KeyObject): string {
  const der = pub.export({ type: 'spki', format: 'der' }) as Buffer;
  return crypto.createHash('sha256').update(der).digest('base64url').slice(0, 16);
}

// Fixed, published-in-the-clear keypairs — test material only, never a real trust anchor.
// Generated once with crypto.generateKeyPairSync('ed25519') and frozen here as literals so
// regenerating vectors.json reproduces byte-identical output every time.
const ROOT_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIxzZXB+lxjjkztkpEcXq7AGhmNvfQX7iltRN3LMlW5Q
-----END PRIVATE KEY-----`;
const INTERMEDIATE_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBj/lAnjdkmXGenzPTnRbijlYtVaLMImlZcwNha+s4Rk
-----END PRIVATE KEY-----`;
const LEAF_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDLDEJxaD4dETET16u1mVoYrnYvmYrmdWnTirUHDh9Pn
-----END PRIVATE KEY-----`;
const IMPOSTOR_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKnV4sbM9+ybONFmoRH5RKOr39EJ8ptUB16gPyKJFcrw
-----END PRIVATE KEY-----`;

function loadKeypair(privatePem: string) {
  const privateKeyPem = privatePem;
  const publicKey = crypto.createPublicKey(crypto.createPrivateKey(privatePem));
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  return { privateKeyPem, publicKeyPem, kid: kid(publicKey) };
}

function sealToyArtifact(signerKid: string, signerPrivateKeyPem: string, label: string) {
  const unsealed = { meta: { artifact_id: `vector-${label}`, version: '1.0.0' }, logic: { decisions: [] } };
  const hash = crypto.createHash('sha256').update(jcs(unsealed)).digest('hex');
  const signed_by = `vectors:${label}`;
  const signature = crypto.sign(null, jcs({ hash, signed_by }), crypto.createPrivateKey(signerPrivateKeyPem)).toString('base64');
  return { ...unsealed, seal: { status: 'sealed', hash, signature, algorithm: 'Ed25519', kid: signerKid, signed_by } };
}

function main() {
  const root = loadKeypair(ROOT_PRIVATE_KEY_PEM);
  const intermediate = loadKeypair(INTERMEDIATE_PRIVATE_KEY_PEM);
  const leaf = loadKeypair(LEAF_PRIVATE_KEY_PEM);
  const impostor = loadKeypair(IMPOSTOR_PRIVATE_KEY_PEM);

  const rootToIntermediate = createKeyCertificate({
    parentPrivateKeyPem: root.privateKeyPem, parentKid: root.kid, childPublicKeyPem: intermediate.publicKeyPem,
    issuedAt: FIXED_ISSUED_AT, expiresAt: FIXED_EXPIRES_AT,
  });
  const intermediateToLeaf = createKeyCertificate({
    parentPrivateKeyPem: intermediate.privateKeyPem, parentKid: intermediate.kid, childPublicKeyPem: leaf.publicKeyPem,
    issuedAt: FIXED_ISSUED_AT, expiresAt: FIXED_EXPIRES_AT,
  });
  const intermediateToLeafExpired = createKeyCertificate({
    parentPrivateKeyPem: intermediate.privateKeyPem, parentKid: intermediate.kid, childPublicKeyPem: leaf.publicKeyPem,
    issuedAt: FIXED_ISSUED_AT, expiresAt: FIXED_EXPIRED_AT,
  });

  const artifactHonored = sealToyArtifact(leaf.kid, leaf.privateKeyPem, 'honored');
  const artifactImpostor = sealToyArtifact(impostor.kid, impostor.privateKeyPem, 'impostor');
  const artifactTampered = { ...artifactHonored, logic: { decisions: [{ injected: true }] } };

  const vectors = {
    _readme: 'See README.md in this directory. check_at is the `now` a checker should pass in — these fixtures are pinned to fixed dates, not wall-clock time, precisely so results stay reproducible indefinitely.',
    check_at: CHECK_AT.toISOString(),
    root_public_key_pem: root.publicKeyPem,
    cases: [
      {
        name: 'allowed',
        artifact: artifactHonored,
        key_certs: [rootToIntermediate, intermediateToLeaf],
        expected: { decision: 'ALLOWED', leaf_kid: leaf.kid, path: [root.kid, intermediate.kid, leaf.kid] },
      },
      {
        name: 'allowed_reversed_order',
        artifact: artifactHonored,
        key_certs: [intermediateToLeaf, rootToIntermediate],
        expected: { decision: 'ALLOWED', leaf_kid: leaf.kid, path: [root.kid, intermediate.kid, leaf.kid] },
        note: 'Same two certificates as "allowed", reversed. Must reach the byte-identical verdict — presentation order carries no trust meaning.',
      },
      {
        name: 'issuer_not_recognized_uncertified_key',
        artifact: artifactImpostor,
        key_certs: [rootToIntermediate, intermediateToLeaf],
        expected: { decision: 'ISSUER_NOT_RECOGNIZED', reason: 'chain_broken' },
      },
      {
        name: 'issuer_not_recognized_expired',
        artifact: artifactHonored,
        key_certs: [rootToIntermediate, intermediateToLeafExpired],
        expected: { decision: 'ISSUER_NOT_RECOGNIZED', reason: 'expired' },
      },
      {
        name: 'seal_invalid_tampered_after_sealing',
        artifact: artifactTampered,
        key_certs: [rootToIntermediate, intermediateToLeaf],
        expected: { decision: 'SEAL_INVALID' },
      },
      {
        name: 'malformed_chain_over_length_cap',
        artifact: artifactHonored,
        key_certs: Array.from({ length: 21 }, () => ({})),
        expected: { decision: 'MALFORMED' },
      },
      {
        name: 'malformed_unsealed_artifact',
        artifact: { meta: {} },
        key_certs: [],
        expected: { decision: 'MALFORMED' },
      },
    ],
  };

  fs.writeFileSync(path.join(DIR, 'vectors.json'), JSON.stringify(vectors, null, 2) + '\n');
  console.log(`Wrote ${vectors.cases.length} vectors to chain-of-trust-vectors/vectors.json`);
}

main();
