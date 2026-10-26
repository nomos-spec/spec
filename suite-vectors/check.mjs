// NOMOS-SPEC-010: a second, independent verifier, written from the specification text alone.
// Node's built-in crypto only; shares no code with python/nomos/suites.py.
//
//   node check.mjs vectors.json
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';

const SUITES = new Set(['Ed25519', 'ES256', 'WebAuthn-ES256']);
const N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;
const sha256 = (b) => createHash('sha256').update(b).digest();
const ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const P256_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d03010703420004', 'hex');

// canonical base64 (§2): decode, re-encode, require identity
function b64(s) {
  if (typeof s !== 'string' || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  const raw = Buffer.from(s, 'base64');
  return raw.toString('base64') === s ? raw : null;
}
function b64url(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
  const raw = Buffer.from(s, 'base64url');
  return raw.toString('base64url') === s ? raw : null;
}

// keys (§3): decode PEM, require the DER to be the key's canonical SPKI
function loadKey(pem) {
  if (typeof pem !== 'string') return { reason: 'invalid_key' };
  const m = pem.match(/^\s*-----BEGIN PUBLIC KEY-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END PUBLIC KEY-----\s*$/);
  if (!m) return { reason: 'invalid_key' };
  const der = b64(m[1].replace(/\s+/g, ''));
  if (!der) return { reason: 'invalid_key' };
  // §3.1: the exact canonical bytes, never a library's re-encoding.
  let type;
  if (der.length === 44 && der.subarray(0, 12).equals(ED25519_PREFIX)) type = 'Ed25519';
  else if (der.length === 91 && der.subarray(0, 27).equals(P256_PREFIX)) type = 'P-256';
  else return { reason: 'invalid_key' };
  let key;
  try { key = createPublicKey({ key: der, format: 'der', type: 'spki' }); } catch { return { reason: 'invalid_key' }; }
  return { type, key };
}

const SUITES_FOR = { 'Ed25519': ['Ed25519'], 'P-256': ['ES256', 'WebAuthn-ES256'] };

function verify(suite, pem, payload, proof) {
  if (!SUITES.has(suite)) return [false, 'unknown_suite'];
  const k = loadKey(pem);
  if (k.reason) return [false, k.reason];
  if (!SUITES_FOR[k.type].includes(suite)) return [false, 'suite_key_mismatch'];
  if (!proof || typeof proof !== 'object') return [false, 'bad_encoding'];

  if (suite === 'Ed25519') {
    const sig = b64(proof.signature);
    if (!sig || sig.length !== 64) return [false, 'bad_encoding'];
    return cryptoVerify(null, payload, k.key, sig) ? [true, null] : [false, 'bad_signature'];
  }
  if (suite === 'ES256') {
    const sig = b64(proof.signature);
    if (!sig || sig.length !== 64) return [false, 'bad_encoding'];
    const r = BigInt('0x' + sig.subarray(0, 32).toString('hex')), s = BigInt('0x' + sig.subarray(32).toString('hex'));
    if (r < 1n || r >= N || s < 1n || s >= N) return [false, 'bad_encoding'];
    if (s > N / 2n) return [false, 'high_s'];
    return cryptoVerify('sha256', payload, { key: k.key, dsaEncoding: 'ieee-p1363' }, sig) ? [true, null] : [false, 'bad_signature'];
  }
  // WebAuthn-ES256 (§5)
  const auth = b64url(proof.authenticator_data), cdj = b64url(proof.client_data_json), sig = b64url(proof.signature);
  if (!auth || !cdj || !sig) return [false, 'bad_encoding'];
  let client;
  try { client = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(cdj)); } catch { return [false, 'bad_client_data']; }
  if (!client || typeof client !== 'object' || Array.isArray(client) || client.type !== 'webauthn.get') return [false, 'bad_client_data'];
  if (client.challenge !== sha256(payload).toString('base64url')) return [false, 'challenge_mismatch'];
  if (auth.length < 37) return [false, 'bad_encoding'];
  const flags = auth[32];
  if (!(flags & 0x01) || !(flags & 0x04)) return [false, 'user_not_verified'];
  let ok;
  try { ok = cryptoVerify('sha256', Buffer.concat([auth, sha256(cdj)]), { key: k.key, dsaEncoding: 'der' }, sig); }
  catch { return [false, 'bad_encoding']; }
  return ok ? [true, null] : [false, 'bad_signature'];
}

const vectors = JSON.parse(readFileSync(process.argv[2] ?? 'vectors.json', 'utf8'));
let passed = 0, failed = 0;
for (const c of vectors.cases) {
  const [ok, reason] = verify(c.suite, c.public_key_pem, Buffer.from(c.payload_b64, 'base64'), c.proof);
  if (ok === c.expected.ok && reason === c.expected.reason) { passed++; console.log(`  ok    ${c.name}`); }
  else { failed++; console.log(`  FAIL  ${c.name}: got ok=${ok} reason=${reason}, expected ${JSON.stringify(c.expected)}`); }
}
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
