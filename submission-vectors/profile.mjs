// The conformance profile: what a relying party under test is configured with. Deterministic.
//   node profile.mjs > profile.json
import { ROOT, RELYING_PARTY_ID, ARTIFACT, ARTIFACT_ID } from './keys.mjs';
console.log(JSON.stringify({
  _readme: 'NOMOS-SPEC-009 conformance profile. Configure the relying party under test with exactly this: its relying_party_id, '
    + 'the pinned root, one authority (record currency, the in-force seal hash below, action type "purchase"), '
    + 'max_window_seconds of at least 600, and its own fact vendor_blocked = (action.params.vendor === "blocked-vendor"). '
    + 'Its commit may do anything. Then run: node run.mjs <relying party origin>. Keys are test keys: never trust material.',
  spec: 'NOMOS-SPEC-009 0.1.0',
  relying_party_id: RELYING_PARTY_ID,
  root_public_key_pem: ROOT.pem,
  authority: { artifact_id: ARTIFACT_ID, actions: ['purchase'], currency_policy: 'record', in_force_seal_hash: ARTIFACT.seal.hash },
  local_facts: { vendor_blocked: 'action.params.vendor === "blocked-vendor"' },
  min_max_window_seconds: 600,
  artifact: ARTIFACT,
}, null, 2));
