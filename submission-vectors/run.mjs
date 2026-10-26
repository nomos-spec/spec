// NOMOS-SPEC-009 relying-party conformance runner. Language-neutral: it only speaks HTTP.
//   node run.mjs http://localhost:4747
// The relying party under test must be configured with profile.json (see its _readme).
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { ROOT, RELYING_PARTY_ID, ARTIFACT, ARTIFACT_ID, KEY_CERTS, testimony, consent } from './keys.mjs';

const origin = (process.argv[2] ?? '').replace(/\/$/, '');
if (!origin) { console.error('usage: node run.mjs <relying party origin>'); process.exit(2); }
const status = JSON.parse(readFileSync(new URL('./status.json', import.meta.url), 'utf8')).statuses;
let passed = 0, failed = 0;
const check = (ok, label, got) => { if (ok) { passed++; console.log(`  ok    ${label}`); } else { failed++; console.log(`  FAIL  ${label}\n        ${JSON.stringify(got)?.slice(0, 300)}`); } };

// §3.1 discovery
const docRes = await fetch(`${origin}/.well-known/nomos-relying-party`);
const doc = await docRes.json().catch(() => null);
check(docRes.ok && doc?.nomos_document === 'relying-party' && doc?.version === '1', '§3.1 serves a version-1 relying-party document', doc);
check(doc?.relying_party_id === RELYING_PARTY_ID, '§3.1 relying_party_id is the profile\'s', doc?.relying_party_id);
check(doc?.roots?.some((r) => r.kid === ROOT.kid), '§3.1 pins the profile root', doc?.roots);
const auth = doc?.authorities?.find((a) => a.artifact_id === ARTIFACT_ID);
check(auth?.actions?.includes('purchase') && auth?.currency_policy === 'record' && auth?.in_force_seal_hash === ARTIFACT.seal.hash, '§3.1 advertises the profile authority, record currency, its in-force record', auth);
check(Number(doc?.max_window_seconds) >= 600, '§3.1 max_window_seconds leaves time to approve (>= 600)', doc?.max_window_seconds);
const endpoint = doc?.act_endpoint;
if (!endpoint) { console.log(`\n${passed} passed, ${failed + 1} failed (no act_endpoint)`); process.exit(1); }

function newAct({ amount, vendor = 'paperco', subject = 'DEPT-1', budget = 5000, withTestimony = true, window = 300, relyingParty = RELYING_PARTY_ID }) {
  const now = Date.now();
  return {
    act_version: '1', act_id: `conformance-${randomUUID()}`, nonce: randomBytes(16).toString('base64'),
    issued_at: new Date(now - 1000).toISOString(), expires_at: new Date(now - 1000 + window * 1000).toISOString(),
    relying_party: relyingParty, action: { type: 'purchase', subject, params: { amount, vendor } },
    authority: { artifact: ARTIFACT, key_certs: KEY_CERTS }, testimony: withTestimony ? [testimony(budget, subject, window + 60)] : [], consents: [],
  };
}
const submit = async (act, type = 'application/nomos-act+json', raw) => {
  const res = await fetch(endpoint, { method: 'POST', headers: { 'content-type': type }, body: raw ?? JSON.stringify(act) });
  return { status: res.status, body: await res.json().catch(() => null) };
};

// §6.2 one verdict, one status
const a1 = newAct({ amount: 100 });
const r1 = await submit(a1);
check(r1.status === status.AUTHORIZED && r1.body?.decision === 'AUTHORIZED' && r1.body?.receipt?.act_id === a1.act_id, '§6.2 AUTHORIZED, committed: 201 with the receipt', r1);
const r1b = await submit(a1);
check(r1b.status === status.REPLAYED && r1b.body?.decision === 'REPLAYED' && JSON.stringify(r1b.body?.receipt) === JSON.stringify(r1.body?.receipt), '§6.3 the same Act again: 409 with the stored receipt, no second commit', r1b);

const r2 = await submit(newAct({ amount: 100, withTestimony: false }));
check(r2.status === status.INCOMPLETE && JSON.stringify(r2.body?.open_facts) === '["budget_remaining"]', '§6.2 INCOMPLETE: 422 naming exactly the missing fact', r2);

const r3 = await submit(newAct({ amount: 9000 }));
check(r3.status === status.DENIED && r3.body?.rule === 'P2', '§6.2 DENIED: 403 naming the rule', r3);
const r4 = await submit(newAct({ amount: 100, vendor: 'blocked-vendor' }));
check(r4.status === status.DENIED && r4.body?.rule === 'P1', '§6.4 the relying party\'s own fact is applied (blocked vendor): 403 P1', r4);

const a5 = newAct({ amount: 2000, window: 600 });
const r5 = await submit(a5);
check(r5.status === status.ESCALATED && r5.body?.role === 'MANAGER' && r5.body?.consents_required === 1 && r5.body?.retry_until === a5.expires_at && typeof r5.body?.act_digest === 'string',
  '§6.2 ESCALATED: 202 with act_digest, role, consents and retry_until', r5);
a5.consents.push(consent(a5));
const r5b = await submit(a5);
check(r5b.status === status.AUTHORIZED && r5b.body?.by_consent === true, '§6.3 the same Act resubmitted with consent: 201, by consent', r5b);

const tampered = newAct({ amount: 100 }); tampered.authority.artifact = structuredClone(ARTIFACT); tampered.authority.artifact.logic.decisions[1].when = 'amount > 99999999';
const r6 = await submit(tampered);
check(r6.status === status.SEAL_INVALID && r6.body?.decision === 'SEAL_INVALID', '§6.2 a tampered authority: 400 SEAL_INVALID', r6);
const r7 = await submit(newAct({ amount: 100, relyingParty: 'someone-else' }));
check(r7.status === status.WRONG_RELYING_PARTY && r7.body?.decision === 'WRONG_RELYING_PARTY', '§6.2 addressed elsewhere: 400 WRONG_RELYING_PARTY', r7);
const altered = newAct({ amount: 2000, window: 600 }); altered.consents.push(consent(altered)); altered.action.params.amount = 2500;
const r8 = await submit(altered);
check(r8.status === status.CONSENT_INVALID && r8.body?.reason_code === 'binding_mismatch', '§6.2 an approval of a different change: 400 CONSENT_INVALID binding_mismatch', r8);

const r9 = await submit(newAct({ amount: 100 }), 'application/json');
check(r9.status === 415, '§6.1 any other media type: 415', r9.status);
const r10 = await submit(null, 'application/nomos-act+json', '{"x":"' + 'a'.repeat((doc.max_act_bytes ?? 1048576) + 16) + '"}');
check(r10.status === 413, '§6.1 longer than max_act_bytes: 413', r10.status);

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
