#!/usr/bin/env python3
"""Generate the NOMOS-SPEC-007 rev. 1.9 vectors, deterministically.

    python3 generate_19.py > vectors-1.9.json

Every key is derived from a published seed and ES256 signatures use RFC 6979 nonces, so the
output is byte-identical on every run. Every `expected` value is written by hand from the
specification text; the generator never asks a verifier what the answer is.

Each case resolves one key for one purpose:
  purpose "artifact"   resolve seal.kid and verify the seal (§4)        -> ALLOWED | failure
  purpose "statement"  resolve `statement.kid` for a claim or consent (§4.6) -> RESOLVED | failure
and lists the presentation `orders` (permutations of key_certs) under which it must give the
same answer (§4.3). A conformant verifier reproduces `expected` field for field, in every order.
"""
import base64
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))
from nomosprotocol import suites as S  # noqa: E402
from nomosprotocol.chain import cert_payload, fingerprint  # noqa: E402
from nomosprotocol.jcs import jcs, sha256_hex  # noqa: E402

ISS, EXP, CHECK_AT = "2026-01-01T00:00:00.000Z", "2030-01-01T00:00:00.000Z", "2027-01-01T00:00:00.000Z"


class Key:
    def __init__(self, label, kind):
        seed = f"nomos-spec-007-rev-1.9:{label}".encode()
        self.label, self.kind = label, kind
        self.priv = S.ed25519_key_from_seed(seed) if kind == "Ed25519" else S.p256_key_from_seed(seed)
        self.pem = S.public_pem(self.priv)
        self.kid = S.compute_kid(self.pem)

    def sign(self, payload: bytes, *, low_s=True) -> str:
        return S.sign_ed25519(self.priv, payload) if self.kind == "Ed25519" else S.sign_es256(self.priv, payload, low_s=low_s)

    @property
    def suite(self): return "Ed25519" if self.kind == "Ed25519" else "ES256"


ROOT = Key("root", "Ed25519")
INT = Key("intermediate", "Ed25519")
INT_P = Key("intermediate-p256", "P-256")
ISSUER = Key("issuer", "Ed25519")
ISSUER_P = Key("issuer-p256", "P-256")
WITNESS = Key("witness-p256", "P-256")
PASSKEY = Key("passkey", "P-256")
PASSKEY_2 = Key("passkey-2", "P-256")
APPROVER = Key("approver", "Ed25519")
CHILD = Key("child", "Ed25519")


def cert(parent: Key, child: Key, scope=None, *, issued_at=ISS, expires_at=EXP, algorithm=None, low_s=True, child_pem=None, child_kid=None):
    c = {"parent_kid": parent.kid, "child_kid": child_kid or child.kid, "child_public_key_pem": child_pem or child.pem,
         "issued_at": issued_at, "expires_at": expires_at}
    if scope is not None: c["scope"] = scope
    c["algorithm"] = algorithm or parent.suite
    c["signature"] = parent.sign(jcs(cert_payload(c)), low_s=low_s)
    return c


def lower_fingerprint_than(make, other):
    """Re-issue `make(issued_at)` one second later until its fingerprint sorts below `other`'s:
    the paper's scenario needs the narrow direct certificate to be the first candidate tried."""
    for i in range(10_000):
        c = make(f"2026-01-01T00:00:{i // 1000:02d}.{i % 1000:03d}Z")
        if fingerprint(c) < fingerprint(other): return c
    raise RuntimeError("no ordering found")


def higher_fingerprint_than(make, other):
    for i in range(10_000):
        c = make(f"2026-01-01T00:00:{i // 1000:02d}.{i % 1000:03d}Z")
        if fingerprint(c) > fingerprint(other): return c
    raise RuntimeError("no ordering found")


def seal(signer: Key, label: str, meta_extra=None, *, signature_algorithm=None, sign_with=None):
    art = {"meta": {"artifact_id": f"rev19-{label}", "version": "1.0.0", **(meta_extra or {})}, "logic": {"decisions": []}}
    h = sha256_hex(jcs(art))
    signed_by = f"vectors-1.9:{label}"
    alg = signature_algorithm or signer.suite
    sig = (sign_with or signer).sign(jcs({"hash": h, "signed_by": signed_by}))
    art["seal"] = {"status": "sealed", "hash": h, "canonicalization": "JCS", "signature_algorithm": alg,
                   "kid": signer.kid, "signed_by": signed_by, "signature": sig}
    return art


def compressed_pem(k: Key) -> str:
    from cryptography.hazmat.primitives import serialization
    point = k.priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    body = base64.b64encode(bytes.fromhex("3039301306072a8648ce3d020106082a8648ce3d030107032200") + point).decode()
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64)) + "\n-----END PUBLIC KEY-----\n"


def high_s(c: dict) -> dict:
    """The same ES256 certificate, re-encoded with s replaced by n - s: valid ECDSA, second encoding."""
    raw = base64.b64decode(c["signature"])
    r, s = raw[:32], int.from_bytes(raw[32:], "big")
    return {**c, "signature": base64.b64encode(r + (S.P256_N - s).to_bytes(32, "big")).decode()}


cases = []


def all_orders(n):
    """The identity, the reverse, and every rotation: enough to separate any order-dependent walk."""
    base = list(range(n))
    out = [base, base[::-1]] + [base[i:] + base[:i] for i in range(1, n)]
    uniq = []
    for o in out:
        if o not in uniq: uniq.append(o)
    return uniq


def artifact_case(name, artifact, key_certs, expected, why, *, revoked_kids=None, revoked_certs=None, orders=None):
    c = {"name": name, "purpose": "artifact", "artifact": artifact, "key_certs": key_certs,
         "orders": orders or all_orders(len(key_certs)), "expected": expected, "why": why}
    if revoked_kids is not None: c["revoked_kids"] = revoked_kids
    if revoked_certs is not None: c["revoked_certs"] = revoked_certs
    cases.append(c)


def statement_case(name, kind, stmt_name, key: Key, suite, key_certs, expected, why, *, meta=None):
    cases.append({"name": name, "purpose": "statement",
                  "statement": {"kind": kind, "name": stmt_name, "kid": key.kid, "suite": suite,
                                "authority_meta": meta or {"artifact_id": "rev19-authority", "industry": "financial/lending"}},
                  "key_certs": key_certs, "orders": all_orders(len(key_certs)), "expected": expected, "why": why})


def p(*keys): return [ROOT.kid] + [k.kid for k in keys]


LENDING = {"industry": "financial/lending", "jurisdiction_codes": ["AE"]}

# ── scope-aware path selection (§4.2a step 4): R-19 §5.6, exactly ─────────────────────────────
via_int = cert(INT, ISSUER)
root_int = cert(ROOT, INT)
direct_narrow = lower_fingerprint_than(lambda t: cert(ROOT, ISSUER, "industry:insurance", issued_at=t), via_int)
art_lending = seal(ISSUER, "lending", LENDING)
artifact_case("scope_aware_selection_r19", art_lending, [direct_narrow, root_int, via_int],
              {"decision": "ALLOWED", "path": p(INT, ISSUER)},
              "R-19 §5.6. The issuer is certified twice: directly with industry:insurance (the lower "
              "fingerprint, so tried first) and through an unscoped intermediate. The artifact is "
              "financial/lending. Rev. 1.8 chose the direct path on its signature alone and returned "
              "OUT_OF_SCOPE; rev. 1.9 treats the out-of-scope path as a failed candidate and resolves the other.")
artifact_case("scope_aware_selection_only_intermediate", art_lending, [root_int, via_int],
              {"decision": "ALLOWED", "path": p(INT, ISSUER)},
              "The same Act without the extra certificate. Adding a valid certificate must never turn this into a refusal.")
narrow_health = cert(INT, ISSUER, "industry:health")
direct_narrow_2 = lower_fingerprint_than(lambda t: cert(ROOT, ISSUER, "industry:insurance", issued_at=t), narrow_health)
artifact_case("scope_aware_all_fail_first_reported", art_lending, [direct_narrow_2, root_int, narrow_health],
              {"decision": "OUT_OF_SCOPE", "dimension": "industry"},
              "Both paths are out of scope. The failure of the first candidate tried (fingerprint order) is reported.")
juris_qa = cert(INT, ISSUER, "jurisdiction:QA")
direct_narrow_3 = lower_fingerprint_than(lambda t: cert(ROOT, ISSUER, "industry:insurance", issued_at=t), juris_qa)
artifact_case("scope_aware_first_failure_is_the_lowest_fingerprint", art_lending, [juris_qa, root_int, direct_narrow_3],
              {"decision": "OUT_OF_SCOPE", "dimension": "industry"},
              "The two paths fail on different dimensions. The reported one is the lowest-fingerprint "
              "candidate's (industry), whatever the presentation order.")
expired_direct = lower_fingerprint_than(lambda t: cert(ROOT, ISSUER, issued_at=t, expires_at="2026-06-01T00:00:00.000Z"), via_int)
artifact_case("expired_direct_path_falls_through", art_lending, [expired_direct, root_int, via_int],
              {"decision": "ALLOWED", "path": p(INT, ISSUER)},
              "An expired candidate is a failed candidate (unchanged from rev. 1.8).")
artifact_case("revoked_key_is_dead_on_every_path", art_lending, [direct_narrow, root_int, via_int],
              {"decision": "KEY_REVOKED", "revoked_kid": ISSUER.kid},
              "Proposition 3: a revoked key fails every candidate, so no alternative path resurrects it.",
              revoked_kids=[ISSUER.kid])
direct_wide = lower_fingerprint_than(lambda t: cert(ROOT, ISSUER, issued_at=t), via_int)
artifact_case("revoked_certificate_withdraws_one_delegation", art_lending, [direct_wide, root_int, via_int],
              {"decision": "ALLOWED", "path": p(INT, ISSUER)},
              "A revoked certificate withdraws one delegation; the other, unrevoked, still resolves the key (§5.4).",
              revoked_certs=[fingerprint(direct_wide)])

# ── trees (§4.3) ──────────────────────────────────────────────────────────────────────────────
tree = [cert(ROOT, ISSUER), cert(ROOT, WITNESS, "claim:credit_score"), cert(ROOT, INT), cert(INT, APPROVER, "consent:SENIOR approver:p-17")]
artifact_case("tree_resolves_in_every_order", seal(ISSUER, "tree", LENDING), tree,
              {"decision": "ALLOWED", "path": p(ISSUER)},
              "A pool carrying the sealing key, a witness and an approver forms a tree. Every order resolves.")
statement_case("tree_statement_key_in_every_order", "consent", "SENIOR", APPROVER, "Ed25519", tree,
               {"decision": "RESOLVED", "path": p(INT, APPROVER), "effective_scope": "consent:SENIOR approver:p-17"},
               "The approver's key, resolved from the same tree, in every order.")

# ── ES256 and mixed chains (§3.1) ────────────────────────────────────────────────────────────
artifact_case("es256_issuer_es256_seal", seal(ISSUER_P, "es256", LENDING), [cert(ROOT, ISSUER_P)],
              {"decision": "ALLOWED", "path": p(ISSUER_P)},
              "An Ed25519 root certifies a P-256 issuer; the artifact carries an ES256 seal (NOMOS-SPEC-010).")
artifact_case("mixed_chain", seal(ISSUER, "mixed", LENDING), [cert(ROOT, INT_P), cert(INT_P, ISSUER)],
              {"decision": "ALLOWED", "path": p(INT_P, ISSUER)},
              "Ed25519 root, P-256 intermediate signing an ES256 certificate, Ed25519 issuer.")
artifact_case("es256_certificate_high_s", seal(ISSUER, "high-s", LENDING), [cert(ROOT, INT_P), high_s(cert(INT_P, ISSUER))],
              {"decision": "ISSUER_NOT_RECOGNIZED", "reason_code": "high_s"},
              "The certificate's ES256 signature with s replaced by n - s: one canonical encoding only (NOMOS-SPEC-010 §4).")
artifact_case("certificate_suite_does_not_match_parent_key", seal(ISSUER, "mismatch", LENDING),
              [cert(ROOT, INT_P), {**cert(INT_P, ISSUER), "algorithm": "Ed25519"}],
              {"decision": "ISSUER_NOT_RECOGNIZED", "reason_code": "suite_key_mismatch"},
              "The certificate names Ed25519, but its parent is a P-256 key. The key decides what it can be.")
artifact_case("certificate_algorithm_webauthn_is_malformed", seal(ISSUER, "webauthn-cert", LENDING),
              [{**cert(ROOT, INT_P), "algorithm": "WebAuthn-ES256"}],
              {"decision": "MALFORMED", "reason_code": "bad_certificate"},
              "No certificate is WebAuthn-signed (§3.1); the shape is rejected before any cryptography.")
artifact_case("compressed_child_key", seal(ISSUER_P, "compressed", LENDING),
              [cert(ROOT, ISSUER_P, child_pem=compressed_pem(ISSUER_P), child_kid=ISSUER_P.kid)],
              {"decision": "ISSUER_NOT_RECOGNIZED", "reason_code": "invalid_key"},
              "A compressed P-256 point is not the canonical SPKI (NOMOS-SPEC-010 §3.1): one key, one kid.")
artifact_case("es256_seal_on_ed25519_key", seal(ISSUER, "seal-mismatch", LENDING, signature_algorithm="ES256"), [cert(ROOT, ISSUER)],
              {"decision": "SEAL_INVALID", "reason_code": "suite_key_mismatch"},
              "The seal declares ES256; the resolved key is Ed25519.")
artifact_case("seal_hmac_not_chain_verifiable", seal(ISSUER, "hmac", LENDING, signature_algorithm="HMAC-SHA256"), [cert(ROOT, ISSUER)],
              {"decision": "MALFORMED", "reason_code": "seal_algorithm"},
              "HMAC is not publicly verifiable; a chain cannot vouch for it.")

# ── the suite dimension (§3.6) ───────────────────────────────────────────────────────────────
artifact_case("passkey_cannot_seal", seal(PASSKEY, "passkey-seal", LENDING), [cert(ROOT, PASSKEY, "suite:WebAuthn-ES256 consent:SENIOR approver:p-17")],
              {"decision": "OUT_OF_SCOPE", "dimension": "suite"},
              "An enrolled passkey cannot seal. Its first term, suite, already refuses an ES256 seal (§3.6, §3.8).")
artifact_case("consent_key_cannot_seal", seal(APPROVER, "consent-seal", LENDING), [cert(ROOT, APPROVER, "consent:SENIOR approver:p-17")],
              {"decision": "OUT_OF_SCOPE", "dimension": "consent"},
              "A key certified to consent cannot seal rules (§3.5).")
artifact_case("passkey_suite_alone_cannot_seal", seal(PASSKEY, "passkey-seal-2", LENDING), [cert(ROOT, PASSKEY, "suite:WebAuthn-ES256")],
              {"decision": "OUT_OF_SCOPE", "dimension": "suite"},
              "A key restricted to WebAuthn-ES256 cannot sign an ES256 seal.")
artifact_case("passkey_cannot_be_a_parent", seal(CHILD, "passkey-parent", LENDING),
              [cert(ROOT, PASSKEY, "suite:WebAuthn-ES256"), cert(PASSKEY, CHILD)],
              {"decision": "OUT_OF_SCOPE", "dimension": "suite", "reason_code": "suite_not_permitted"},
              "A key restricted to WebAuthn-ES256 signed an ES256 certificate. It may not certify anything (§3.6).")
artifact_case("suite_restricts_issuer_to_ed25519", seal(ISSUER_P, "suite-ed", LENDING), [cert(ROOT, ISSUER_P, "suite:Ed25519")],
              {"decision": "OUT_OF_SCOPE", "dimension": "suite"},
              "The issuer's certificate permits Ed25519 only; it sealed under ES256.")
artifact_case("suite_widening_rejected", seal(ISSUER, "suite-widen", LENDING),
              [cert(ROOT, INT, "suite:Ed25519"), cert(INT, ISSUER, "suite:Ed25519,ES256")],
              {"decision": "OUT_OF_SCOPE", "dimension": "suite", "reason_code": "widening"},
              "A child's suite set must be a subset of its parent's.")
artifact_case("suite_webauthn_with_another_is_malformed", seal(ISSUER_P, "suite-mixed", LENDING),
              [cert(ROOT, ISSUER_P, "suite:ES256,WebAuthn-ES256")],
              {"decision": "OUT_OF_SCOPE", "reason_code": "malformed_scope"},
              "WebAuthn-ES256 must stand alone in a suite set, or a passkey could also testify or seal (§3.6).")
artifact_case("suite_unknown_name_is_malformed", seal(ISSUER, "suite-unknown", LENDING), [cert(ROOT, ISSUER, "suite:RS256")],
              {"decision": "OUT_OF_SCOPE", "reason_code": "malformed_scope"},
              "Suite names come from the closed registry (NOMOS-SPEC-010 §2).")
artifact_case("malformed_scope_is_out_of_scope", seal(ISSUER, "scope-bad", LENDING), [cert(ROOT, ISSUER, "industry")],
              {"decision": "OUT_OF_SCOPE", "reason_code": "malformed_scope"},
              "A malformed scope fails its candidate path (OUT_OF_SCOPE, malformed_scope), never the whole "
              "presentation: another, well-formed path may still resolve the key.")
artifact_case("malformed_scope_on_one_path_falls_through", art_lending,
              [lower_fingerprint_than(lambda t: cert(ROOT, ISSUER, "industry", issued_at=t), via_int), root_int, via_int],
              {"decision": "ALLOWED", "path": p(INT, ISSUER)},
              "The direct certificate's scope is malformed; the path through the intermediate resolves.")

# ── the approver dimension (§3.7) ────────────────────────────────────────────────────────────
artifact_case("approver_key_cannot_seal", seal(ISSUER, "approver-seal", LENDING), [cert(ROOT, ISSUER, "approver:p-17")],
              {"decision": "OUT_OF_SCOPE", "dimension": "approver"},
              "An approver term marks a person's approval key; it never seals rules.")
statement_case("passkey_consent_resolves", "consent", "SENIOR", PASSKEY, "WebAuthn-ES256",
               [cert(ROOT, INT), cert(INT, PASSKEY, "suite:WebAuthn-ES256 consent:SENIOR approver:p-17")],
               {"decision": "RESOLVED", "path": p(INT, PASSKEY), "effective_scope": "suite:WebAuthn-ES256 consent:SENIOR approver:p-17"},
               "An enrolled passkey resolves for a WebAuthn consent in its role.")
statement_case("p256_key_without_suite_term_cannot_use_webauthn", "consent", "SENIOR", PASSKEY, "WebAuthn-ES256",
               [cert(ROOT, PASSKEY, "consent:SENIOR approver:p-17")],
               {"decision": "OUT_OF_SCOPE", "dimension": "suite"},
               "WebAuthn-ES256 is accepted only when the effective scope names it explicitly (§3.6).")
statement_case("passkey_cannot_testify", "claim", "credit_score", PASSKEY, "ES256",
               [cert(ROOT, PASSKEY, "suite:WebAuthn-ES256 claim:credit_score")],
               {"decision": "OUT_OF_SCOPE", "dimension": "suite"},
               "Even with a claim term, a WebAuthn-only key cannot sign ES256 testimony.")
statement_case("approver_on_a_claim_key", "claim", "credit_score", WITNESS, "ES256",
               [cert(ROOT, WITNESS, "claim:credit_score approver:p-17")],
               {"decision": "OUT_OF_SCOPE", "dimension": "approver"},
               "The approver dimension belongs to consent keys only (§3.7).")
statement_case("approver_changed_by_a_child", "consent", "SENIOR", PASSKEY_2, "WebAuthn-ES256",
               [cert(ROOT, INT, "approver:p-17"), cert(INT, PASSKEY_2, "suite:WebAuthn-ES256 consent:SENIOR approver:p-18")],
               {"decision": "OUT_OF_SCOPE", "dimension": "approver", "reason_code": "widening"},
               "A child may repeat its parent's approver and must not change it.")
statement_case("approver_repeated_by_a_child", "consent", "SENIOR", PASSKEY_2, "WebAuthn-ES256",
               [cert(ROOT, INT, "approver:p-17"), cert(INT, PASSKEY_2, "suite:WebAuthn-ES256 consent:SENIOR approver:p-17")],
               {"decision": "RESOLVED", "path": p(INT, PASSKEY_2), "effective_scope": "approver:p-17 suite:WebAuthn-ES256 consent:SENIOR"},
               "An institution certifies a person's enrolment key with approver:p-17, and it certifies that person's passkeys.")
statement_case("approver_set_is_malformed", "consent", "SENIOR", APPROVER, "Ed25519",
               [cert(ROOT, APPROVER, "consent:SENIOR approver:p-17,p-18")],
               {"decision": "OUT_OF_SCOPE", "reason_code": "malformed_scope"},
               "An approver term names exactly one person.")
witness_via_int = cert(INT, WITNESS, "claim:credit_score,dti_ratio")
witness_direct = lower_fingerprint_than(lambda t: cert(ROOT, WITNESS, "claim:dti_ratio", issued_at=t), witness_via_int)
statement_case("scope_aware_selection_for_a_witness", "claim", "credit_score", WITNESS, "ES256",
               [witness_direct, cert(ROOT, INT), witness_via_int],
               {"decision": "RESOLVED", "path": p(INT, WITNESS), "effective_scope": "claim:credit_score,dti_ratio"},
               "The witness is certified directly for dti_ratio only (tried first) and through an intermediate "
               "for both facts. Its credit_score statement resolves through the intermediate.")
statement_case("es256_witness_resolves", "claim", "credit_score", WITNESS, "ES256",
               [cert(ROOT, WITNESS, "claim:credit_score")],
               {"decision": "RESOLVED", "path": p(WITNESS), "effective_scope": "claim:credit_score"},
               "A P-256 witness signing ES256 testimony.")

out = {
    "_readme": "NOMOS-SPEC-007 rev. 1.9 vectors. For each case and for every permutation in `orders`, present "
               "key_certs in that order and resolve: purpose 'artifact' resolves artifact.seal.kid for the artifact "
               "and verifies the seal; purpose 'statement' resolves statement.kid for a statement of that kind, "
               "name and suite. Compare decision, reason_code, dimension, path, effective_scope and revoked_kid "
               "with `expected`; a field absent from `expected` must be absent from the result. "
               "Keys are derived from published seeds: never use them as trust material.",
    "spec": "NOMOS-SPEC-007 rev. 1.9.0",
    "check_at": CHECK_AT,
    "root_public_key_pem": ROOT.pem,
    "cases": cases,
}
json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
