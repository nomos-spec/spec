#!/usr/bin/env python3
"""
Deterministic generator for the NOMOS-SPEC-008 Act test vectors.

Every key is derived from a fixed, published seed and every timestamp is fixed, so running this
twice produces byte-identical vectors.json. THESE PRIVATE KEYS ARE PUBLISHED ON PURPOSE: they
exist only to make the vectors regenerable and auditable. Never treat them as trust material.

Usage:  python3 generate.py <path/to/pub_lending_v1.nomos>  >  vectors.json
"""
import base64, copy, hashlib, json, sys
from act_verify import jcs, sha256_hex, cert_payload, testimony_payload, consent_payload, in_force_payload, binding_digest
from nomosprotocol import suites as S

def key(label, kind="Ed25519"):
    seed = b"nomos-spec-008-vector:" + label.encode()
    sk = S.ed25519_key_from_seed(seed) if kind == "Ed25519" else S.p256_key_from_seed(seed)
    pem = S.public_pem(sk)
    return {"sk": sk, "pem": pem, "kid": S.compute_kid(pem), "label": label, "suite": "Ed25519" if kind == "Ed25519" else "ES256"}

def sign(k, payload):
    return S.sign_ed25519(k["sk"], jcs(payload)) if k["suite"] == "Ed25519" else S.sign_es256(k["sk"], jcs(payload))

ROOT, ISSUER, BUREAU, APPROVER_A, APPROVER_B, REVIEWER, ROGUE = (key(x) for x in
    ("root", "issuer:acme-bank-credit-policy", "witness:credit-bureau", "approver:senior-a", "approver:senior-b", "approver:reviewer", "rogue:uncertified"))
# 0.6.0: P-256 keys (NOMOS-SPEC-010) — a second key of approver A, two passkeys, a P-256 witness
APPROVER_A2 = key("approver:senior-a:second-device", "P-256")
PASSKEY_B = key("approver:senior-b:passkey", "P-256")
UNNAMED = key("approver:no-approver-term")
DOUBLE = key("approver:certified-as-two-people")
BUREAU_P = key("witness:credit-bureau:p256", "P-256")
PASSKEY_W = key("witness:passkey", "P-256")
ISS, EXP = "2026-01-01T00:00:00.000Z", "2030-01-01T00:00:00.000Z"
NOW = "2026-10-01T12:00:00.000Z"
RP = "acme-bank:core-ledger"

def cert(parent, child, scope=None):
    c = {"parent_kid": parent["kid"], "child_kid": child["kid"], "child_public_key_pem": child["pem"],
         "scope": scope, "issued_at": ISS, "expires_at": EXP, "algorithm": parent["suite"]}
    c["signature"] = sign(parent, cert_payload(c)); return c

POOL = [
    cert(ROOT, ISSUER),                                                             # may seal rules
    cert(ROOT, BUREAU, "claim:credit_score,dti_ratio,bankruptcy_active,delinquency_severity,days_since_delinquency"),
    cert(ROOT, APPROVER_A, "consent:SENIOR_APPROVER approver:p-senior-a"),         # 0.6.0 §4.4: consent keys
    cert(ROOT, APPROVER_B, "consent:SENIOR_APPROVER approver:p-senior-b"),         # name the person they belong to
    cert(ROOT, REVIEWER, "consent:REVIEWER approver:p-reviewer"),
]
# 0.6.0 certificates, presented only by the cases that use them
CERT_A2 = cert(ROOT, APPROVER_A2, "consent:SENIOR_APPROVER approver:p-senior-a")      # a second key of the same person
CERT_PASSKEY_B = cert(ROOT, PASSKEY_B, "suite:WebAuthn-ES256 consent:SENIOR_APPROVER approver:p-senior-b")
CERT_UNNAMED = cert(ROOT, UNNAMED, "consent:SENIOR_APPROVER")                        # 0.5.0-style: no approver term
CERT_DOUBLE_1 = cert(ROOT, DOUBLE, "consent:SENIOR_APPROVER approver:p-senior-c")
CERT_DOUBLE_2 = cert(ROOT, DOUBLE, "consent:SENIOR_APPROVER approver:p-senior-d")    # the same key, a different person
CERT_BUREAU_P = cert(ROOT, BUREAU_P, "claim:credit_score,dti_ratio,bankruptcy_active,delinquency_severity,days_since_delinquency")
CERT_PASSKEY_W = cert(ROOT, PASSKEY_W, "suite:WebAuthn-ES256 claim:credit_score,dti_ratio,bankruptcy_active,delinquency_severity")

# ── the authority: the public lending policy, re-sealed for these vectors ──────────────
SOURCES = {"amount": "action", "loan_purpose": "action", "has_cosigner": "action",
           "credit_score": "testimony", "dti_ratio": "testimony", "bankruptcy_active": "testimony",
           "delinquency_severity": "testimony", "days_since_delinquency": "testimony",
           "employment_type": "testimony", "is_first_loan": "relying_party"}

def build_artifact(src, extra_rule=None, extra_inputs=None, artifact_id=None, version=None):
    a = copy.deepcopy(src)
    if extra_inputs: a["data_contract"]["inputs"].update(extra_inputs)
    a.pop("seal", None)
    a["meta"]["artifact_id"] = "vector-lending-acts"
    a["meta"]["description"] = "SPEC-008 test vector authority: the public Consumer Loan Approval policy with declared fact sources, an explicit allow rule and default-deny."
    a["meta"].pop("confidence_band", None); a["meta"].pop("evaluation_model", None)
    a["meta"]["verification_tier"] = "compiled"
    for name, s in SOURCES.items():
        a["data_contract"]["inputs"].setdefault(name, {"type": "string", "required": False})
        a["data_contract"]["inputs"][name]["source"] = s
    a["logic"]["decisions"].append({
        "id": "R0", "name": "standard_small_loan_allow",
        "description": "Loans up to $10,000 to applicants with credit score 680+ and DTI up to 40% are approved.",
        "when": "amount <= 10000 and credit_score >= 680 and dti_ratio <= 0.40",
        "then": [{"type": "allow"}], "else": [], "priority": 10})
    if extra_rule:
        a["meta"]["artifact_id"] = "vector-lending-acts-" + extra_rule["id"].lower()
        a["logic"]["decisions"].append(extra_rule)
    if artifact_id: a["meta"]["artifact_id"] = artifact_id
    if version: a["meta"]["version"] = version
    a["logic"]["resolution"] = {"conflict_policy": "highest_priority", "tie_breaker": "deny_wins", "default_outcome": "block"}
    for e in a["governance"]["escalations"]:
        e["required_consents"] = 2 if e["id"] == "ESC_DUAL" else 1
    a["seal"] = None
    body = {k: v for k, v in a.items() if k not in ("seal", "attestations")}
    h = sha256_hex(jcs(body))
    signed_by = {"name": "Acme Bank Credit Policy (test vector issuer)", "org_id": "acme-bank", "role": "policy_issuer", "timestamp": ISS}
    a["seal"] = {"status": "sealed", "hash": h, "canonicalization": "JCS", "signature_algorithm": "Ed25519",
                 "kid": ISSUER["kid"], "signed_by": signed_by, "signature": sign(ISSUER, {"hash": h, "signed_by": signed_by})}
    return a

def testimony(witness, claim, value, about="APP-1042", as_of="2026-10-01T11:30:00.000Z", valid_until="2026-10-02T11:30:00.000Z"):
    t = {"claim": claim, "value": value, "about": about, "as_of": as_of, "valid_until": valid_until, "kid": witness["kid"], "algorithm": witness["suite"]}
    t["signature"] = sign(witness, testimony_payload(t)); return t

def act(n, params, witnessed, artifact, presenter_facts=None, rp=RP, issued="2026-10-01T11:59:00.000Z", expires="2026-10-01T12:04:00.000Z", pool=None):
    a = {"act_version": "1", "act_id": f"act-{n:03d}", "nonce": base64.b64encode(hashlib.sha256(f"nonce-{n}".encode()).digest()[:16]).decode(),
         "issued_at": issued, "expires_at": expires, "relying_party": rp,
         "action": {"type": "approve_loan", "subject": "APP-1042", "params": params},
         "authority": {"artifact": artifact, "key_certs": pool if pool is not None else POOL},
         "testimony": witnessed, "consents": []}
    if presenter_facts: a["presenter_facts"] = presenter_facts
    return a

def consent(approver, a, role="SENIOR_APPROVER"):
    c = {"binding_digest": binding_digest(a), "role": role, "decision": "approve", "signed_at": "2026-10-01T11:59:30.000Z", "kid": approver["kid"], "algorithm": approver["suite"]}
    c["signature"] = sign(approver, consent_payload(c)); return c

def passkey_consent(passkey, a, role="SENIOR_APPROVER", **assertion):
    """A WebAuthn-ES256 consent (0.6.0 §4.5): the authenticator signs authenticatorData ‖
    SHA-256(clientDataJSON), and the challenge commits to the consent payload."""
    c = {"binding_digest": binding_digest(a), "role": role, "decision": "approve", "signed_at": "2026-10-01T11:59:30.000Z", "kid": passkey["kid"], "algorithm": "WebAuthn-ES256"}
    c.update(S.webauthn_assert(passkey["sk"], jcs(consent_payload(c)), **assertion)); return c

def good_profile(credit, dti):
    # The bureau states the absence of a 90-day delinquency explicitly: under SPEC-008 §6.2 an
    # unstated fact is undecided, not false, so silence cannot clear the delinquency rule R4.
    return [testimony(BUREAU, "credit_score", credit), testimony(BUREAU, "dti_ratio", dti), testimony(BUREAU, "bankruptcy_active", False),
            testimony(BUREAU, "delinquency_severity", "none")]

def main():
    art = build_artifact(json.load(open(sys.argv[1])))
    cases = []
    def add(name, a, expected, note, now=NOW, seen=None, revoked_artifacts=None, currency_policy=None):
        c = {"name": name, "note": note, "now": now, "seen_nonces": seen or [], "act": a, "expected": expected}
        if revoked_artifacts: c["revoked_artifacts"] = revoked_artifacts
        if currency_policy: c["currency_policy"] = currency_policy
        cases.append(c)

    small = {"amount": 4000, "loan_purpose": "education", "has_cosigner": False}
    a1 = act(1, small, good_profile(768, 0.22), art)
    add("authorized_by_rule", a1, {"decision": "AUTHORIZED", "rule": "R0", "commit": True},
        "Every fact is either part of the action itself, testimony from a scoped witness, or the relying party's own state. R0 permits it.")
    add("denied_by_rule", act(2, {"amount": 250000, "loan_purpose": "home_improvement", "has_cosigner": False}, good_profile(702, 0.58), art),
        {"decision": "DENIED", "rule": "R3", "commit": False}, "The bureau testifies DTI 58%. R3 (priority 100) outranks the $250k escalation R6 (85).")
    lie = act(3, {"amount": 250000, "loan_purpose": "home_improvement", "has_cosigner": False},
              [testimony(BUREAU, "credit_score", 702), testimony(BUREAU, "bankruptcy_active", False), testimony(BUREAU, "delinquency_severity", "none")], art, presenter_facts={"dti_ratio": 0.38})
    add("agent_asserts_a_testimony_fact", lie, {"decision": "FACT_SOURCE_VIOLATION", "field": "dti_ratio"},
        "The agent supplies dti_ratio itself. The artifact declares that input's source as testimony, so the agent's value is refused rather than evaluated.")
    forged = act(4, small, [testimony(BUREAU, "credit_score", 768), testimony(ISSUER, "dti_ratio", 0.22), testimony(BUREAU, "bankruptcy_active", False), testimony(BUREAU, "delinquency_severity", "none")], art)
    add("rule_issuer_cannot_testify", forged, {"decision": "TESTIMONY_OUT_OF_SCOPE", "claim": "dti_ratio", "dimension": "claim"},
        "The key that sealed the rules is fully trusted to issue rules, but carries no claim: scope, so it cannot manufacture facts.")
    beyond = act(5, small, good_profile(768, 0.22) + [testimony(BUREAU, "employment_type", "salaried")], art)
    add("witness_beyond_its_scope", beyond, {"decision": "TESTIMONY_OUT_OF_SCOPE", "claim": "employment_type", "dimension": "claim"},
        "The bureau may attest credit facts only; employment status is outside its certified claim set.")
    mid = {"amount": 75000, "loan_purpose": "home_improvement", "has_cosigner": False}
    a6 = act(6, mid, good_profile(742, 0.31), art)
    add("escalated_no_consent", a6, {"decision": "ESCALATED", "rule": "R6", "escalation_id": "ESC_DUAL", "consents_valid": 0, "consents_required": 2, "commit": False},
        "R6 requires two senior approvers. Nothing is committed until both have signed this exact Act.")
    a7 = act(7, mid, good_profile(742, 0.31), art); a7["consents"] = [consent(APPROVER_A, a7)]
    add("escalated_one_of_two", a7, {"decision": "ESCALATED", "consents_valid": 1, "consents_required": 2, "commit": False}, "One valid senior consent of the two required.")
    a8 = act(8, mid, good_profile(742, 0.31), art); c = consent(APPROVER_A, a8); a8["consents"] = [c, c]
    add("same_approver_twice_counts_once", a8, {"decision": "ESCALATED", "consents_valid": 1, "consents_required": 2, "commit": False},
        "Dual control means two different people, not the same approval presented twice.")
    a9 = act(9, mid, good_profile(742, 0.31), art); a9["consents"] = [consent(APPROVER_A, a9), consent(APPROVER_B, a9)]
    add("authorized_by_dual_consent", a9, {"decision": "AUTHORIZED", "rule": "R6", "by_consent": True, "consents_valid": 2, "commit": True},
        "Both senior approvers signed this Act's binding digest. The escalation is satisfied and the exact change may be committed.")
    a10 = copy.deepcopy(a9); a10["act_id"] = "act-010"; a10["action"]["params"]["amount"] = 750000
    add("action_altered_after_consent", a10, {"decision": "CONSENT_INVALID", "reason_code": "binding_mismatch"},
        "The consents from the previous case, re-used after the amount was changed to $750,000. They were signed over a different change.")
    a11 = act(11, mid, good_profile(742, 0.31), art); a11["consents"] = [consent(APPROVER_A, a11), consent(REVIEWER, a11, role="SENIOR_APPROVER")]
    add("approver_claims_a_role_it_lacks", a11, {"decision": "CONSENT_OUT_OF_SCOPE", "role": "SENIOR_APPROVER"},
        "A reviewer key signs as SENIOR_APPROVER. Its certificate grants consent:REVIEWER only.")
    add("no_rule_matches_default_deny", act(12, {"amount": 2000, "loan_purpose": "education", "has_cosigner": False}, good_profile(600, 0.30), art),
        {"decision": "DENIED", "rule": None, "reason_code": "no_matching_rule", "commit": False},
        "No decision matches. Under default_outcome: block the Act is denied, not silently permitted.")
    add("expired", a1, {"decision": "EXPIRED"}, "The authorized Act from the first case, presented after its five-minute window.", now="2026-10-01T12:05:00.000Z")
    add("wrong_relying_party", act(14, small, good_profile(768, 0.22), art, rp="acme-bank:card-ledger"), {"decision": "WRONG_RELYING_PARTY"},
        "An Act addressed to a different system cannot be committed here, even if everything else verifies.")
    add("replayed", a1, {"decision": "REPLAYED"}, "The first case's Act, presented again after it was committed.", seen=[a1["nonce"]])
    stale = act(16, small, [testimony(BUREAU, "credit_score", 768, valid_until="2026-10-01T09:00:00.000Z"), testimony(BUREAU, "dti_ratio", 0.22), testimony(BUREAU, "bankruptcy_active", False), testimony(BUREAU, "delinquency_severity", "none")], art)
    add("stale_testimony", stale, {"decision": "TESTIMONY_INVALID", "claim": "credit_score", "reason_code": "stale"}, "The credit score attestation expired before the Act was presented.")
    other = act(17, small, [testimony(BUREAU, "credit_score", 768, about="APP-9999"), testimony(BUREAU, "dti_ratio", 0.22), testimony(BUREAU, "bankruptcy_active", False), testimony(BUREAU, "delinquency_severity", "none")], art)
    add("testimony_about_someone_else", other, {"decision": "TESTIMONY_INVALID", "claim": "credit_score", "reason_code": "wrong_subject"},
        "A genuine, signed credit score, but for a different applicant.")
    rogue_art = copy.deepcopy(art); body = {k: v for k, v in rogue_art.items() if k not in ("seal", "attestations")}
    rogue_art["seal"]["kid"] = ROGUE["kid"]; rogue_art["seal"]["signature"] = sign(ROGUE, {"hash": sha256_hex(jcs(body)), "signed_by": rogue_art["seal"]["signed_by"]})
    add("rules_from_uncertified_issuer", act(18, small, good_profile(768, 0.22), rogue_art), {"decision": "ISSUER_NOT_RECOGNIZED"},
        "The same rules, sealed by a key with no certificate from the pinned root.")

    add("tree_pool_presented_in_reverse", act(19, small, good_profile(768, 0.22), art, pool=list(reversed(POOL))),
        {"decision": "AUTHORIZED", "rule": "R0", "commit": True},
        "The same certificates in reverse order. The pool is a tree (one root, five children), so resolution must search from each statement's own key toward the root; the verdict cannot depend on presentation order.")

    withheld = act(20, small, [testimony(BUREAU, "credit_score", 768), testimony(BUREAU, "dti_ratio", 0.22), testimony(BUREAU, "delinquency_severity", "none")], art)
    add("omitted_fact_withholds_authorization", withheld,
        {"decision": "INCOMPLETE", "reason_code": "undecided_rules", "open_rules": ["R1"], "open_facts": ["bankruptcy_active"], "commit": False},
        "The first case without the bureau's bankruptcy statement. R0 would permit the loan, but R1 (an active bankruptcy blocks it) outranks R0 and cannot be decided. An agent that leaves out the statement that would deny it gets nothing committed, and is told exactly which fact is missing.")
    big = {"amount": 250000, "loan_purpose": "home_improvement", "has_cosigner": False}
    a21 = act(21, big, [testimony(BUREAU, "credit_score", 702), testimony(BUREAU, "bankruptcy_active", False), testimony(BUREAU, "delinquency_severity", "none")], art)
    a21["consents"] = [consent(APPROVER_A, a21), consent(APPROVER_B, a21)]
    add("omitted_fact_cannot_be_consented_away", a21,
        {"decision": "INCOMPLETE", "reason_code": "undecided_rules", "open_rules": ["R3"], "open_facts": ["dti_ratio"], "commit": False},
        "The denied case's loan with the bureau's DTI statement left out and two valid senior consents attached. R6 would escalate and the consents would satisfy it, but R3 (DTI above 50% denies the loan) outranks R6 and cannot be decided. Human approval cannot stand in for a missing fact.")

    wrong_type = act(22, {"amount": "4000", "loan_purpose": "education", "has_cosigner": False}, good_profile(768, 0.22), art)
    add("action_param_wrong_type", wrong_type,
        {"decision": "FACT_TYPE_VIOLATION", "field": "amount", "declared": "number", "supplied_via": "action"},
        "The first case with the amount sent as the string \"4000\". A comparison against a value of the wrong type cannot be TRUE, so a rule like `amount > 50000` would fall silent while a relying party that coerces the string still commits the amount. The Act is refused before any rule is read.")

    flagged = build_artifact(json.load(open(sys.argv[1])), extra_rule={
        "id": "R13", "name": "fraud_alert_block", "description": "Any open fraud alert on the applicant blocks the loan.",
        "when": "exists(fraud_alert)", "then": [{"type": "block"}], "else": [], "priority": 120},
        extra_inputs={"fraud_alert": {"type": "string", "required": False, "description": "Open fraud alert reference, if any", "source": "testimony"}})
    add("omitted_fact_exists_undecided", act(23, small, good_profile(768, 0.22), flagged),
        {"decision": "INCOMPLETE", "reason_code": "undecided_rules", "open_rules": ["R13"], "open_facts": ["fraud_alert"], "commit": False},
        "The first case under a policy that blocks any open fraud alert, written as exists(fraud_alert) on a testimony input. The Act carries no fraud-alert statement. A missing witness statement is unknown, not a statement that no alert exists, so R13 is undecided and nothing commits.")

    termed = build_artifact(json.load(open(sys.argv[1])), extra_rule={
        "id": "R14", "name": "long_term_block", "description": "Loans with a term over 360 months are refused.",
        "when": "terms.months > 360", "then": [{"type": "block"}], "else": [], "priority": 120},
        extra_inputs={"terms": {"type": "object", "required": False, "description": "Repayment terms proposed with the loan", "source": "action"}})
    add("nested_param_wrong_type_undecided", act(24, dict(small, terms={"months": "480"}), good_profile(768, 0.22), termed),
        {"decision": "INCOMPLETE", "reason_code": "undecided_rules", "open_rules": ["R14"], "open_facts": ["terms.months"], "commit": False},
        "The first case under a policy that refuses terms over 360 months, with the term sent as the string \"480\" inside an object-typed parameter. The object passes the §7.1 type check; the comparison inside it cannot be evaluated on a string, so R14 is undecided rather than false, and nothing commits.")

    # ── §5.4 the authority in force ─────────────────────────────────────────────────────
    older = build_artifact(json.load(open(sys.argv[1])), version="0.9.0")
    add("superseded_version_presented", act(25, small, good_profile(768, 0.22), older),
        {"decision": "SUPERSEDED", "artifact_id": "vector-lending-acts", "in_force_seal_hash": art["seal"]["hash"]},
        "The first case's Act carrying version 0.9.0 of the same authority: genuinely sealed by the certified issuer and never revoked, but the relying party's record shows a newer version in force. A superseded version stays valid for verifying decisions made under it; it cannot authorize a new action.")
    add("revoked_authority", act(26, small, good_profile(768, 0.22), art),
        {"decision": "ARTIFACT_REVOKED", "artifact_id": "vector-lending-acts"},
        "The first case after the issuer revoked the authority itself (NOMOS-SPEC-006). Every key on the chain is still valid; the rules are not.",
        revoked_artifacts=[art["seal"]["hash"]])
    unpinned = build_artifact(json.load(open(sys.argv[1])), artifact_id="vector-lending-acts-partner")
    def in_force_statement(artifact, as_of="2026-10-01T06:00:00.000Z", valid_until="2026-10-02T06:00:00.000Z"):
        st = {"artifact_id": artifact["meta"]["artifact_id"], "version": artifact["meta"]["version"], "seal_hash": artifact["seal"]["hash"],
              "as_of": as_of, "valid_until": valid_until, "kid": ISSUER["kid"], "algorithm": "Ed25519"}
        st["signature"] = sign(ISSUER, in_force_payload(st)); return st
    a27 = act(27, small, good_profile(768, 0.22), unpinned); a27["authority"]["in_force"] = in_force_statement(unpinned)
    add("in_force_statement_accepted", a27, {"decision": "AUTHORIZED", "rule": "R0", "commit": True, "in_force_source": "statement"},
        "An authority this relying party keeps no record for. The Act carries the issuer's signed statement that this exact version is in force, valid for a day, so the relying party can establish currency without a call out.")
    a28 = act(28, small, good_profile(768, 0.22), unpinned)
    a28["authority"]["in_force"] = in_force_statement(unpinned, as_of="2026-09-29T06:00:00.000Z", valid_until="2026-09-30T06:00:00.000Z")
    add("in_force_statement_stale", a28, {"decision": "VERSION_UNVERIFIED", "reason_code": "stale"},
        "The same, with Monday's statement presented on Wednesday. A statement that this version was in force then says nothing about now.")
    add("no_in_force_evidence", act(29, small, good_profile(768, 0.22), unpinned), {"decision": "VERSION_UNVERIFIED", "reason_code": "no_in_force_evidence"},
        "The same authority with neither a relying-party record nor an in-force statement. Genuine rules of unknown currency cannot authorize.")

    # ── 0.5.0: equal-priority escalations ─────────────────────────────────────────────
    tie_src = json.load(open(sys.argv[1]))
    tie_src["logic"]["decisions"].insert(0, {"id": "R16", "name": "recent_delinquency_dual",
        "description": "Any delinquency in the last year needs dual senior approval.",
        "when": "days_since_delinquency < 365", "then": [{"type": "escalate", "escalation_id": "ESC_DUAL"}], "else": [], "priority": 70})
    tied = build_artifact(tie_src, artifact_id="vector-lending-acts-r16")
    a30 = act(30, {"amount": 20000, "loan_purpose": "education", "has_cosigner": False}, good_profile(768, 0.22), tied)
    a30["consents"] = [consent(REVIEWER, a30, role="REVIEWER")]
    add("equal_priority_escalation_refused", a30,
        {"decision": "MALFORMED", "reason_code": "ambiguous_escalation"},
        "A $20,000 loan under a policy where R16 (a delinquency in the last year needs two senior approvers) and R10 (loans over $10,000 need one reviewer) share priority 70. Under 0.4.0 the carrier could choose who approves by staying silent; 0.5.0 withheld the verdict (INCOMPLETE). Under 0.6.0 (NOMOS-SPEC-001 amendment 2.3.0) such an authority cannot authorize anything new: which escalation governs would depend on listing order, so the author must give the two rules distinct priorities. Historical verification is unaffected.")

    # ── 0.6.0: consents counted by person (§4.4), WebAuthn (§4.5), suites (§6.3) ──────────
    def mid_act(n, consents_of, extra_certs=(), witnessed=None):
        a = act(n, mid, witnessed or good_profile(742, 0.31), art, pool=POOL + list(extra_certs))
        a["consents"] = consents_of(a); return a
    add("two_keys_of_one_person_count_once", mid_act(31, lambda a: [consent(APPROVER_A, a), consent(APPROVER_A2, a)], [CERT_A2]),
        {"decision": "ESCALATED", "consents_valid": 1, "consents_required": 2, "commit": False},
        "Senior approver A signs from two devices, with two different keys certified as the same person (approver:p-senior-a). Dual control needs two people; this is one.")
    add("two_people_count_twice", mid_act(32, lambda a: [consent(APPROVER_A2, a), consent(APPROVER_B, a)], [CERT_A2]),
        {"decision": "AUTHORIZED", "rule": "R6", "by_consent": True, "consents_valid": 2, "commit": True},
        "A's second device (an ES256 key) and B: two people, so the escalation is satisfied.")
    add("consent_key_without_approver", mid_act(33, lambda a: [consent(APPROVER_A, a), consent(UNNAMED, a)], [CERT_UNNAMED]),
        {"decision": "CONSENT_OUT_OF_SCOPE", "role": "SENIOR_APPROVER", "dimension": "approver"},
        "A key certified to consent as SENIOR_APPROVER but not tied to a person. Under 0.6.0 its consent cannot be counted, so it is refused rather than ignored.")
    add("approver_depends_on_the_path", mid_act(34, lambda a: [consent(APPROVER_A, a), consent(DOUBLE, a)], [CERT_DOUBLE_1, CERT_DOUBLE_2]),
        {"decision": "CONSENT_INVALID", "reason_code": "approver_ambiguous"},
        "One key certified twice, as two different people. Whoever carries the Act would choose which person the consent counts for by choosing which certificate to send, so the consent is refused.")
    add("passkey_consent_authorizes", mid_act(35, lambda a: [consent(APPROVER_A, a), passkey_consent(PASSKEY_B, a)], [CERT_PASSKEY_B]),
        {"decision": "AUTHORIZED", "rule": "R6", "by_consent": True, "consents_valid": 2, "commit": True},
        "B approves with a passkey: a WebAuthn assertion whose challenge commits to this exact Act's binding digest, the role, the decision and the time.")
    add("passkey_user_not_verified", mid_act(36, lambda a: [consent(APPROVER_A, a), passkey_consent(PASSKEY_B, a, flags=0x01)], [CERT_PASSKEY_B]),
        {"decision": "CONSENT_INVALID", "reason_code": "user_not_verified"},
        "The authenticator reports user presence (a touch) but not user verification. A touch is not an approval.")
    def other_role_challenge(a):
        c = passkey_consent(PASSKEY_B, a)
        forged = dict(c, role="REVIEWER")
        made_for = S.b64url_encode(hashlib.sha256(jcs(consent_payload(forged))).digest())
        return [consent(APPROVER_A, a), passkey_consent(PASSKEY_B, a, challenge=made_for)]
    add("passkey_challenge_for_another_role", mid_act(37, other_role_challenge, [CERT_PASSKEY_B]),
        {"decision": "CONSENT_INVALID", "reason_code": "challenge_mismatch"},
        "A genuine passkey assertion whose challenge was made for a REVIEWER consent, presented as a SENIOR_APPROVER consent.")
    add("passkey_registration_is_not_approval", mid_act(38, lambda a: [consent(APPROVER_A, a), passkey_consent(PASSKEY_B, a, type_="webauthn.create")], [CERT_PASSKEY_B]),
        {"decision": "CONSENT_INVALID", "reason_code": "bad_client_data"},
        "The authenticator data comes from a registration ceremony, not an approval.")
    add("es256_witness", act(39, small, [testimony(BUREAU_P, "credit_score", 768), testimony(BUREAU_P, "dti_ratio", 0.22),
                                          testimony(BUREAU_P, "bankruptcy_active", False), testimony(BUREAU_P, "delinquency_severity", "none")],
                             art, pool=POOL + [CERT_BUREAU_P]),
        {"decision": "AUTHORIZED", "rule": "R0", "commit": True},
        "The first case with the bureau signing from a P-256 key held in a KMS (ES256, low-S).")
    add("passkey_cannot_testify", act(40, small, [testimony(PASSKEY_W, "credit_score", 768), testimony(BUREAU, "dti_ratio", 0.22),
                                                   testimony(BUREAU, "bankruptcy_active", False), testimony(BUREAU, "delinquency_severity", "none")],
                                      art, pool=POOL + [CERT_PASSKEY_W]),
        {"decision": "TESTIMONY_OUT_OF_SCOPE", "claim": "credit_score", "dimension": "suite"},
        "A key enrolled as a passkey (suite:WebAuthn-ES256) signs testimony under ES256. Even with a claim term, a passkey approves and does nothing else.")

    # ── 0.6.0: open_facts names only the absent operand (§6.2) ────────────────────────
    limited = build_artifact(json.load(open(sys.argv[1])), extra_rule={
        "id": "R15", "name": "over_approved_limit", "description": "A loan above the applicant's approved limit is refused.",
        "when": "amount > approved_limit", "then": [{"type": "block"}], "else": [], "priority": 120},
        extra_inputs={"approved_limit": {"type": "number", "required": False, "description": "The applicant's approved limit", "source": "testimony"}})
    add("two_field_rule_names_only_the_absent_fact", act(43, small, good_profile(768, 0.22), limited),
        {"decision": "INCOMPLETE", "reason_code": "undecided_rules", "open_rules": ["R15"], "open_facts": ["approved_limit"], "commit": False},
        "A rule compares two facts, amount (in the action) and approved_limit (witnessed, and withheld). It is undecided, and open_facts names approved_limit alone: the amount is present and well typed, so it did not leave the rule undecided (§6.2).")

    # ── 0.6.0: currency policy (§5.5) ─────────────────────────────────────────────────
    a41 = act(41, small, good_profile(768, 0.22), unpinned); a41["authority"]["in_force"] = in_force_statement(unpinned)
    add("record_only_refuses_a_statement", a41, {"decision": "VERSION_UNVERIFIED", "reason_code": "not_in_record"},
        "The in-force statement case, at a relying party that establishes currency from its own record only. The issuer's statement is not read: under this policy a compromised issuer key cannot make any version current (R-19 Theorem 9.4).",
        currency_policy="record")
    add("record_only_with_a_record", act(42, small, good_profile(768, 0.22), art),
        {"decision": "AUTHORIZED", "rule": "R0", "commit": True, "in_force_source": "record", "currency_policy": "record"},
        "The first case under record-only currency: the relying party's own record shows this version in force.",
        currency_policy="record")

    out = {"_readme": "NOMOS-SPEC-008 Act test vectors. Verify each case's act with root_public_key_pem as the pinned root, relying_party_id, local_facts and currency_policy (a case's own currency_policy overrides it) as the relying party's own configuration, `now` as the evaluation time and `seen_nonces` as the nonce ledger, and compare against expected (only the keys present in expected are normative). Keys are derived from published seeds: never use them as trust material.",
           "spec": "NOMOS-SPEC-008 0.6.0",
           "root_public_key_pem": ROOT["pem"], "relying_party_id": RP, "local_facts": {"is_first_loan": False}, "currency_policy": "record_or_statement",
           "in_force": {a["meta"]["artifact_id"]: a["seal"]["hash"] for a in (art, flagged, termed, tied, limited)},
           "keys": {k["label"]: k["kid"] for k in (ROOT, ISSUER, BUREAU, APPROVER_A, APPROVER_B, REVIEWER, ROGUE, APPROVER_A2, PASSKEY_B, UNNAMED, DOUBLE, BUREAU_P, PASSKEY_W)},
           "cases": cases}
    print(json.dumps(out, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
