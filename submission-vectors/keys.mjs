// Conformance test keys and builders, shared by the profile, the runner and the reference relying
// party. Every key is derived from a published seed: never use them as trust material.
import { createHash, createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto';
import { jcs, sha256Hex, certPayload, testimonyPayload, consentPayload, bindingDigest } from '@nomosprotocol/verify';

export function key(label) {
  const raw = createHash('sha256').update(`nomos-spec-009-conformance:${label}`).digest();
  const priv = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), raw]), format: 'der', type: 'pkcs8' });
  const pem = createPublicKey(priv).export({ type: 'spki', format: 'pem' }).toString();
  const der = createPublicKey(priv).export({ type: 'spki', format: 'der' });
  return { label, pem, kid: createHash('sha256').update(der).digest('base64url').slice(0, 16), sign: (bytes) => nodeSign(null, Buffer.from(bytes), priv).toString('base64') };
}
export const ROOT = key('root'), ISSUER = key('issuer'), WITNESS = key('witness'), APPROVER = key('approver');
export const RELYING_PARTY_ID = 'nomos-conformance:rp';
export const ARTIFACT_ID = 'nomos-conformance-purchasing';
const ISSUED = '2026-01-01T00:00:00.000Z', EXPIRES = '2036-01-01T00:00:00.000Z';

export function cert(parent, child, scope) {
  const c = { parent_kid: parent.kid, child_kid: child.kid, child_public_key_pem: child.pem, scope, issued_at: ISSUED, expires_at: EXPIRES, algorithm: 'Ed25519' };
  return { ...c, signature: parent.sign(jcs(certPayload(c))) };
}
export const KEY_CERTS = [cert(ROOT, ISSUER, `artifact:${ARTIFACT_ID}`), cert(ROOT, WITNESS, 'claim:budget_remaining'), cert(ROOT, APPROVER, 'consent:MANAGER approver:conformance-manager')];

function sealed(body) {
  const hash = sha256Hex(jcs(body));
  const signed_by = { name: 'NOMOS-SPEC-009 conformance issuer (test)', org_id: 'nomos-conformance', role: 'policy_issuer', timestamp: ISSUED };
  return { ...body, seal: { status: 'sealed', hash, canonicalization: 'JCS', signature_algorithm: 'Ed25519', kid: ISSUER.kid, signed_by, signature: ISSUER.sign(jcs({ hash, signed_by })) } };
}
export const ARTIFACT = sealed({
  nomos_version: '2.2.0',
  meta: { artifact_id: ARTIFACT_ID, version: '1.0.0', name: 'NOMOS-SPEC-009 conformance policy' },
  data_contract: { inputs: {
    amount: { type: 'number', source: 'action' }, vendor: { type: 'string', source: 'action' },
    budget_remaining: { type: 'number', source: 'testimony' }, vendor_blocked: { type: 'boolean', source: 'relying_party' },
  } },
  logic: {
    decisions: [
      { id: 'P1', when: 'vendor_blocked == true', then: [{ type: 'block' }], priority: 100 },
      { id: 'P2', when: 'amount > budget_remaining', then: [{ type: 'block' }], priority: 90 },
      { id: 'P3', when: 'amount > 1000', then: [{ type: 'escalate', escalation_id: 'ESC_MANAGER' }], priority: 50 },
      { id: 'P4', when: 'amount <= 1000', then: [{ type: 'allow' }], priority: 10 },
    ],
    resolution: { conflict_policy: 'highest_priority', tie_breaker: 'deny_wins', default_outcome: 'block' },
  },
  governance: { roles: [{ role_id: 'MANAGER' }], escalations: [{ id: 'ESC_MANAGER', role_required: 'MANAGER', required_consents: 1 }] },
});

/** The relying party's own fact, as the profile defines it: a vendor named "blocked-vendor" is blocked. */
export const localFactsFor = (act) => ({ vendor_blocked: act?.action?.params?.vendor === 'blocked-vendor' });

export function testimony(value, about, seconds) {
  const t = { claim: 'budget_remaining', value, about, as_of: new Date(Date.now() - 1000).toISOString(), valid_until: new Date(Date.now() + seconds * 1000).toISOString(), kid: WITNESS.kid, algorithm: 'Ed25519' };
  return { ...t, signature: WITNESS.sign(jcs(testimonyPayload(t))) };
}
export function consent(act, role = 'MANAGER') {
  const c = { binding_digest: bindingDigest(act), role, decision: 'approve', signed_at: new Date().toISOString(), kid: APPROVER.kid, algorithm: 'Ed25519' };
  return { ...c, signature: APPROVER.sign(jcs(consentPayload(c))) };
}
