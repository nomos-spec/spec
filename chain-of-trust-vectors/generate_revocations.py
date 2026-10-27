#!/usr/bin/env python3
"""Generate the NOMOS-SPEC-007 rev. 1.10 revocation-source vectors, deterministically.

    python3 generate_revocations.py > revocation-vectors-1.10.json

Each case is a revocation list, the relying party's pinned root, its own certificates and the
time. `expected` is the result of §5.3a, written by hand from the specification text. The
generator never asks a verifier what the answer is. Keys come from published seeds and ES256
signatures use RFC 6979 nonces, so the output is byte-identical on every run.
"""
import copy
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))
from nomosprotocol import suites as S  # noqa: E402
from nomosprotocol.chain import cert_payload, fingerprint, revocation_payload, revocation_list_payload  # noqa: E402
from nomosprotocol.jcs import jcs  # noqa: E402

ISS, EXP = "2026-01-01T00:00:00.000Z", "2030-01-01T00:00:00.000Z"
STATED = "2026-06-01T00:00:00.000Z"          # when the statements were signed
GEN = "2026-12-31T23:00:00.000Z"             # when the lists were assembled
NOW = "2027-01-01T00:00:00.000Z"             # when the relying party checks them


class Key:
    def __init__(self, label, kind="Ed25519"):
        seed = f"nomos-spec-007-rev-1.10:{label}".encode()
        self.kind = kind
        self.priv = S.ed25519_key_from_seed(seed) if kind == "Ed25519" else S.p256_key_from_seed(seed)
        self.pem = S.public_pem(self.priv)
        self.kid = S.compute_kid(self.pem)

    @property
    def suite(self): return "Ed25519" if self.kind == "Ed25519" else "ES256"

    def sign(self, payload: bytes) -> str:
        return S.sign_ed25519(self.priv, payload) if self.kind == "Ed25519" else S.sign_es256(self.priv, payload)


ROOT, INT, INT_P = Key("root"), Key("intermediate"), Key("intermediate-p256", "P-256")
K, K2 = Key("key"), Key("key-2")
FORGER, PLATFORM, LISTER = Key("forger"), Key("platform"), Key("list-signer")
PASSKEY, VICTIM = Key("passkey", "P-256"), Key("victim")


def cert(parent, child, scope=None, *, issued_at=ISS, expires_at=EXP):
    c = {"parent_kid": parent.kid, "child_kid": child.kid, "child_public_key_pem": child.pem, "issued_at": issued_at, "expires_at": expires_at}
    if scope is not None: c["scope"] = scope
    c["algorithm"] = parent.suite
    c["signature"] = parent.sign(jcs(cert_payload(c)))
    return c


def stmt(parent, *, kid=None, fp=None, reason="Withdrawn.", issued_at=STATED, algorithm=None):
    st = {("revoked_kid" if kid else "revoked_fingerprint"): kid or fp, "reason": reason, "issued_at": issued_at, "kid": parent.kid, "algorithm": algorithm or parent.suite}
    st["signature"] = parent.sign(jcs(revocation_payload(st))) if (algorithm or parent.suite) == parent.suite else \
        Key("wrong-suite-signer", "P-256").sign(jcs(revocation_payload(st)))
    return st


def lst(signer, statements, key_certs=None, generated_at=GEN):
    L = {"generated_at": generated_at, "kid": signer.kid, "algorithm": signer.suite, "statements": statements}
    if key_certs is not None: L["key_certs"] = key_certs
    L["signature"] = signer.sign(jcs(revocation_list_payload(L)))
    return L


c_ri, c_rip = cert(ROOT, INT), cert(ROOT, INT_P)
c_ik, c_ipk2, c_rk = cert(INT, K, "claim:budget_remaining"), cert(INT_P, K2, "claim:budget_remaining"), cert(ROOT, K, "claim:credit_score")
c_rl = cert(ROOT, LISTER, "artifact:acme-purchasing")
c_ri_short = cert(ROOT, INT, issued_at=ISS, expires_at="2026-09-01T00:00:00.000Z")
cases = []


def case(name, description, L, expected, own=None, root=ROOT):
    cases.append({"name": name, "description": description, "root_public_key_pem": root.pem, "now": NOW,
                  "own_certs": own or [], "list": L, "expected": expected})


def ok(kids=(), certs=(), as_of=GEN, ignored=()):
    e = {"decision": "OK", "revoked_kids": sorted(kids), "revoked_certs": sorted(certs), "ignored": list(ignored)}
    if as_of: e["as_of"] = as_of
    return e


case("key_revocation_ed25519", "An intermediate revokes a key it certified. The list carries both certificates and is signed by the root: the key is revoked and the list is current as of generated_at.",
     lst(ROOT, [stmt(INT, kid=K.kid)], [c_ri, c_ik]), ok(kids=[K.kid]))

case("key_revocation_es256", "A P-256 intermediate, as held in a KMS, revokes a key with an ES256 statement (1.10 §5.1). Under 1.9 it could certify the key but never revoke it.",
     lst(ROOT, [stmt(INT_P, kid=K2.kid)], [c_rip, c_ipk2]), ok(kids=[K2.kid]))

case("certificate_revocation", "The root withdraws one certificate it issued, by fingerprint. Only that delegation is revoked; the key itself is not.",
     lst(ROOT, [stmt(ROOT, fp=fingerprint(c_rk))], [c_rk, c_ri, c_ik]), ok(certs=[fingerprint(c_rk)]))

forged = cert(FORGER, K)
case("forged_parent_ignored", "A key the root never certified signs a certificate for K (K's public key is public) and then revokes K. Under 1.7.0 §5.1 that counted; under 1.10 the signer is not recognized and the statement is ignored.",
     lst(ROOT, [stmt(FORGER, kid=K.kid)], [forged, c_ri, c_ik]), ok(ignored=[{"index": 0, "reason": "signer_not_recognized"}]))

case("parent_certificate_missing", "The intermediate revokes K, but no certificate INT→K is available. The statement cannot be checked, so it is ignored, never trusted.",
     lst(ROOT, [stmt(INT, kid=K.kid)], [c_ri]), ok(ignored=[{"index": 0, "reason": "no_certificate"}]))

not_by_parent = dict(c_ik); not_by_parent["signature"] = FORGER.sign(jcs(cert_payload(c_ik)))
case("certificate_not_signed_by_the_parent", "The intermediate is recognized and signs the statement, but the certificate INT→K it relies on was not signed by the intermediate. Without a certificate the parent really made, it has no standing over K (§5.1a rule 4).",
     lst(ROOT, [stmt(INT, kid=K.kid)], [c_ri, not_by_parent]), ok(ignored=[{"index": 0, "reason": "bad_certificate_signature"}]))

bad = stmt(INT, kid=K.kid); bad["reason"] = "Altered after signing."
case("statement_signature_invalid", "A statement altered after it was signed.",
     lst(ROOT, [bad], [c_ri, c_ik]), ok(ignored=[{"index": 0, "reason": "bad_signature"}]))

legacy = {"revoked_kid": fingerprint(c_ik), "reason": "Withdrawn.", "issued_at": STATED, "kid": INT.kid, "algorithm": "Ed25519"}
legacy["signature"] = INT.sign(jcs({"revoked_kid": legacy["revoked_kid"], "reason": legacy["reason"], "issued_at": legacy["issued_at"]}))
case("fingerprint_in_revoked_kid", "The pre-1.10 reference platform signed certificate revocations with the fingerprint in revoked_kid. Read as 1.10 requires, that is a key revocation of a kid no certificate names, so it revokes nothing. It must be re-signed as revoked_fingerprint.",
     lst(ROOT, [legacy], [c_ri, c_ik]), ok(ignored=[{"index": 0, "reason": "no_certificate"}]))

both = stmt(INT, kid=K.kid); both["revoked_fingerprint"] = fingerprint(c_ik)
case("both_targets_malformed", "A statement naming a key and a certificate is malformed: exactly one is allowed.",
     lst(ROOT, [both], [c_ri, c_ik]), ok(ignored=[{"index": 0, "reason": "bad_statement"}]))

case("statement_from_the_future", "A statement issued after the relying party's clock is malformed.",
     lst(ROOT, [stmt(INT, kid=K.kid, issued_at="2027-06-01T00:00:00.000Z")], [c_ri, c_ik]), ok(ignored=[{"index": 0, "reason": "bad_statement"}]))

c_rpass = cert(ROOT, PASSKEY, "suite:WebAuthn-ES256 consent:MANAGER approver:dana")
c_pass_victim = cert(PASSKEY, VICTIM)
case("passkey_cannot_revoke", "A passkey may sign consents and nothing else (rev. 1.9 §3.6). It signs a certificate and an ES256 revocation anyway: its scope does not permit ES256, so it is not recognized as a signer.",
     lst(ROOT, [stmt(PASSKEY, kid=VICTIM.kid)], [c_rpass, c_pass_victim]), ok(ignored=[{"index": 0, "reason": "signer_not_recognized"}]))

case("revoked_parent_still_counts", "The intermediate revoked K, and was later revoked by the root itself. Revocations accumulate (§5.1a): K stays revoked. If a revoked parent's statements stopped counting, K would come back to life on its other path (root→K).",
     lst(ROOT, [stmt(INT, kid=K.kid), stmt(ROOT, kid=INT.kid, issued_at="2026-10-01T00:00:00.000Z")], [c_ri, c_ik, c_rk]), ok(kids=[INT.kid, K.kid]))

case("statements_reordered", "The previous case with its statements and certificates in reverse order: the same result.",
     lst(ROOT, [stmt(ROOT, kid=INT.kid, issued_at="2026-10-01T00:00:00.000Z"), stmt(INT, kid=K.kid)], [c_rk, c_ik, c_ri]), ok(kids=[INT.kid, K.kid]))

case("list_signer_outside_the_hierarchy", "A hosting platform's own key signs the list. Its statements count on their own authority, but the root does not reach the platform key, so the list establishes no as_of.",
     lst(PLATFORM, [stmt(INT, kid=K.kid)], [c_ri, c_ik]), ok(kids=[K.kid], as_of=None))

tampered = lst(ROOT, [stmt(INT, kid=K.kid)], [c_ri, c_ik]); tampered["generated_at"] = "2026-12-31T23:59:00.000Z"
case("list_signature_invalid", "The list's date was changed after signing. Its statements still count; it establishes no as_of.",
     tampered, ok(kids=[K.kid], as_of=None))

case("list_signer_revoked", "A list signer certified by the root, revoked by a statement in this very list. The statement counts; a revoked key cannot vouch that the list is current, so there is no as_of.",
     lst(LISTER, [stmt(ROOT, kid=LISTER.kid)], [c_rl]), ok(kids=[LISTER.kid], as_of=None))

case("list_signer_certified", "The same list signer, unrevoked: the list is current as of generated_at.",
     lst(LISTER, [stmt(INT, kid=K.kid)], [c_rl, c_ri, c_ik]), ok(kids=[K.kid]))

case("own_certificates_supply_the_parent", "The list carries no certificates. The relying party's own (from the issuer document, say) supply the path.",
     lst(ROOT, [stmt(INT, kid=K.kid)], []), ok(kids=[K.kid]), own=[c_ri, c_ik])

case("list_from_the_future", "A list dated after the relying party's clock establishes no as_of; its statements still count.",
     lst(ROOT, [stmt(INT, kid=K.kid)], [c_ri, c_ik], generated_at="2027-01-02T00:00:00.000Z"), ok(kids=[K.kid], as_of=None))

case("parent_certificate_expired_since", "The intermediate's certificate expired in September. A statement it signed in June still counts: the parent is checked at issued_at. One it signed in October, after expiry, does not.",
     lst(ROOT, [stmt(INT, kid=K.kid), stmt(INT, kid=K2.kid, issued_at="2026-10-01T00:00:00.000Z")], [c_ri_short, c_ik, cert(INT, K2)]),
     ok(kids=[K.kid], ignored=[{"index": 1, "reason": "signer_not_recognized"}]))

case("wrong_suite_statement", "An Ed25519 parent's statement labelled ES256: the key type fixes the suite, so the signature does not verify.",
     lst(ROOT, [stmt(INT, kid=K.kid, algorithm="ES256")], [c_ri, c_ik]), ok(ignored=[{"index": 0, "reason": "bad_signature"}]))

case("malformed_list", "statements is not an array: the list is MALFORMED and contributes nothing.",
     {"generated_at": GEN, "kid": ROOT.kid, "algorithm": "Ed25519", "statements": {}, "signature": "AA=="}, {"decision": "MALFORMED", "reason_code": "bad_list"})

print(json.dumps({
    "_readme": "NOMOS-SPEC-007 rev. 1.10 §5.3a: verifying a revocation source. For each case, apply §5.3a to `list` with `root_public_key_pem`, `own_certs` and `now`, and compare with `expected` field for field (revoked_kids and revoked_certs sorted). Expectations are written by hand. Keys come from published seeds: never trust material.",
    "spec": "NOMOS-SPEC-007 rev. 1.10.0", "cases": cases,
}, indent=2))
