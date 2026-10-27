// NOMOS-SPEC-009 0.2.0 §6.5: which certificates an Act presents.
//   node selection.mjs > selection.json      regenerate (deterministic)
//   node selection.mjs --check               check the reference closure against selection.json
// The reference closure is `closure()` below. Every key comes from a published seed; never use them
// as trust material.
import { readFileSync } from 'node:fs';
import { fingerprint } from '@nomosprotocol/verify';
import { key, cert } from './keys.mjs';

/** §6.5: the closure of `available` over `relied` kids. Returns the certificates, each once. */
export function closure(available, relied) {
  const unique = new Map();
  for (const c of available) unique.set(fingerprint(c), c);
  const kids = new Set(relied), chosen = new Map();
  for (let grew = true; grew;) {
    grew = false;
    for (const [fp, c] of unique) {
      if (!chosen.has(fp) && kids.has(c.child_kid)) { chosen.set(fp, c); kids.add(c.parent_kid); grew = true; }
    }
  }
  return [...chosen.values()];
}
const fps = (certs) => certs.map(fingerprint).sort();

function cases() {
  const root = key('sel:root'), issuer = key('sel:issuer'), finance = key('sel:witness');
  const base = [cert(root, issuer, 'artifact:sel-purchasing'), cert(root, finance, 'claim:budget_remaining')];
  const people = Array.from({ length: 15 }, (_, i) => {
    const enrol = key(`sel:enrol-${i}`), device = key(`sel:device-${i}`);
    return { enrol, device, certs: [cert(root, enrol, `consent:MANAGER approver:p${i}`), cert(enrol, device, `consent:MANAGER approver:p${i}`)] };
  });
  const out = [];
  const add = (name, description, available, relied, expect = {}) => {
    const flat = Object.values(available).flat();
    const sel = closure(flat, relied);
    out.push({ name, description, available, relied_kids: relied,
      expected: sel.length > 20 ? { presentable: false, size: sel.length } : { presentable: true, size: sel.length, fingerprints: fps(sel) }, ...expect });
  };

  add('large_pool_one_approver',
    'An issuer pool of 32 certificates, far over 20: the sealing key, one witness, and fifteen people each with an enrolment key and a device key. The Act relies on the seal, the witness and person 7\'s device. Its closure is 4 certificates.',
    { issuer: [...base, ...people.flatMap((p) => p.certs)] }, [issuer.kid, finance.kid, people[7].device.kid]);

  const inter = key('sel:intermediate'), approver = key('sel:approver');
  add('key_certified_by_two_parents',
    'The approver\'s key is certified twice, by the root and by an intermediate. Both paths are presented, so the relying party evaluates both (SPEC-008 §4.4) and the carrier chooses neither.',
    { issuer: [...base, cert(root, inter, 'consent:MANAGER'), cert(root, approver, 'consent:MANAGER approver:dana'), cert(inter, approver, 'consent:MANAGER approver:dana')] },
    [issuer.kid, approver.kid]);

  const a = key('sel:cycle-a'), b = key('sel:cycle-b');
  add('cycle_terminates',
    'A certifies B and B certifies A; the root certifies A. The closure from B takes all three and stops.',
    { issuer: [cert(root, a, 'claim:x'), cert(a, b, 'claim:x'), cert(b, a, 'claim:x')] }, [b.kid]);

  add('chains_returned_with_statements',
    'The issuer pool holds only the sealing key\'s certificate. The witness returns its chain with its testimony and the approver returns hers with her consent (§4, §5). The closure is drawn from all three.',
    { issuer: [base[0]], testimony: [base[1]], consent: people[3].certs }, [issuer.kid, finance.kid, people[3].device.kid]);

  add('unrelated_certificates_left_out',
    'Certificates for keys the Act does not rely on, and for other people, are not presented.',
    { issuer: [...base, ...people.slice(0, 4).flatMap((p) => p.certs)] }, [issuer.kid]);

  add('duplicate_presented_once',
    'The witness returns the same certificate the issuer pool already has. It is presented once.',
    { issuer: base, testimony: [base[1]] }, [issuer.kid, finance.kid]);

  let parent = root; const deep = [];
  for (let i = 0; i < 21; i++) { const k = key(`sel:deep-${i}`); deep.push(cert(parent, k, 'artifact:sel-purchasing')); parent = k; }
  const deepIssuer = key('sel:deep-issuer'); deep.push(cert(parent, deepIssuer, 'artifact:sel-purchasing'));
  add('closure_over_twenty_is_not_presentable',
    'The sealing key sits under 21 intermediates: its closure is 22 certificates. The Act cannot be presented, and the carrier must not drop certificates to fit.',
    { issuer: deep }, [deepIssuer.kid]);
  return out;
}

if (process.argv.includes('--check')) {
  const vectors = JSON.parse(readFileSync(new URL('./selection.json', import.meta.url), 'utf8')).cases;
  let passed = 0, failed = 0;
  for (const v of vectors) {
    const sel = closure(Object.values(v.available).flat(), v.relied_kids);
    const got = sel.length > 20 ? { presentable: false, size: sel.length } : { presentable: true, size: sel.length, fingerprints: fps(sel) };
    const ok = JSON.stringify(got) === JSON.stringify(v.expected);
    ok ? passed++ : failed++;
    console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${v.name}`);
  }
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
} else {
  console.log(JSON.stringify({
    _readme: 'NOMOS-SPEC-009 0.2.0 §6.5 certificate selection. For each case, the certificates available to a carrier (by where they came from) and the kids the Act relies on; `expected` is the closure an implementation must present, as sorted SPEC-007 §5.4 fingerprints, or presentable:false when it exceeds 20. Keys are from published seeds: never trust material.',
    spec: 'NOMOS-SPEC-009 0.2.0', cases: cases(),
  }, null, 2));
}
