// A minimal NOMOS-SPEC-009 relying party, configured with the conformance profile: plain node:http
// on @nomosprotocol/verify, sharing no code with @nomosprotocol/sdk's accept(). In-memory, single
// process: a reference for the binding, not a production store.
//   node reference-rp.mjs [port]      then: node run.mjs http://localhost:<port>
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { verifyAct, kidOf } from '@nomosprotocol/verify';
import { localFactsFor } from './keys.mjs';

const profile = JSON.parse(readFileSync(new URL('./profile.json', import.meta.url), 'utf8'));
const port = Number(process.argv[2] ?? 4800);
const origin = `http://localhost:${port}`;
const MAX_BYTES = 1048576, MAX_WINDOW = 900;
const STATUS = { AUTHORIZED: 201, ESCALATED: 202, INCOMPLETE: 422, DENIED: 403, REPLAYED: 409 };
const committed = new Map();          // nonce → receipt (SPEC-009 §6.3)

const document = () => ({
  nomos_document: 'relying-party', version: '1', relying_party_id: profile.relying_party_id,
  act_endpoint: `${origin}/acts`, roots: [{ kid: kidOf(profile.root_public_key_pem), public_key_pem: profile.root_public_key_pem }],
  authorities: [{ ...profile.authority }], local_facts: ['vendor_blocked'], max_window_seconds: MAX_WINDOW, max_act_bytes: MAX_BYTES,
  valid_until: new Date(Date.now() + 86400_000).toISOString(),
});

function verify(act) {
  return verifyAct(act, {
    relyingPartyId: profile.relying_party_id, rootPublicKeyPem: profile.root_public_key_pem, currencyPolicy: profile.authority.currency_policy,
    inForce: { [profile.authority.artifact_id]: profile.authority.in_force_seal_hash }, localFacts: localFactsFor(act),
    seenNonces: { has: (n) => committed.has(n) }, maxWindowSeconds: MAX_WINDOW,
  });
}

const send = (res, status, body) => { res.statusCode = status; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(body)); };

createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/.well-known/nomos-relying-party') return send(res, 200, document());
  if (req.url !== '/acts' || req.method !== 'POST') return send(res, 404, { error: 'not found' });
  if ((req.headers['content-type'] ?? '').split(';')[0].trim() !== 'application/nomos-act+json') return send(res, 415, { error: 'media type' });
  const chunks = []; let size = 0;
  for await (const c of req) { size += c.length; if (size > MAX_BYTES) return send(res, 413, { error: 'too large' }); chunks.push(c); }
  let act; try { act = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return send(res, 400, { decision: 'MALFORMED', reason_code: 'bad_json' }); }
  if (act?.authority?.artifact?.meta?.artifact_id !== profile.authority.artifact_id) return send(res, 400, { decision: 'NOT_ACCEPTED', reason_code: 'authority_not_accepted' });
  if (!profile.authority.actions.includes(act?.action?.type)) return send(res, 400, { decision: 'NOT_ACCEPTED', reason_code: 'action_not_accepted' });
  const v = verify(act);
  const { detail, ...body } = v;
  if (v.decision === 'REPLAYED') return send(res, 409, { ...body, act_id: act.act_id, receipt: committed.get(act.nonce) });
  if (v.decision === 'ESCALATED') {
    const esc = act.authority.artifact.governance?.escalations?.find((e) => e.id === v.escalation_id);
    return send(res, 202, { ...body, role: esc?.role_required ?? null, retry_until: act.expires_at });
  }
  if (v.decision !== 'AUTHORIZED') return send(res, STATUS[v.decision] ?? 400, body);
  // §6.4, in one synchronous step (single process): record the nonce, re-read own facts, commit, store the receipt.
  if (committed.has(act.nonce)) return send(res, 409, { decision: 'REPLAYED', act_id: act.act_id, receipt: committed.get(act.nonce) });
  const facts = localFactsFor(act);
  const receipt = { act_id: act.act_id, act_digest: v.act_digest, decision: v.decision, rule: v.rule ?? null, ...(v.by_consent ? { by_consent: true } : {}),
    verified_at: new Date().toISOString(), committed_at: new Date().toISOString(), relying_party_facts: facts, in_force_source: v.in_force_source, currency_policy: profile.authority.currency_policy };
  committed.set(act.nonce, receipt);
  return send(res, 201, { ...body, receipt });
}).listen(port, '127.0.0.1', () => console.log(`reference relying party on ${origin}`));
