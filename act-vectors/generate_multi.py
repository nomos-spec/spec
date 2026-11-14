#!/usr/bin/env python3
"""
Deterministic generator for the NOMOS-SPEC-008 rev. 0.8.0 vectors: an Act under several laws.

It reuses generate.py's published test keys, certificates and lending authority, and adds a second
authority (a data protection law, sealed by the same issuer) with its own witness and its own
approver. Running it twice produces byte-identical output. THESE PRIVATE KEYS ARE PUBLISHED ON
PURPOSE; never treat them as trust material. vectors.json and mutants.json are not touched.

Usage:  python3 generate_multi.py <path/to/pub_lending_v1.nomos>  >  multi-authority-vectors.json
"""
import copy, json, sys
import generate as G
from act_verify import jcs, sha256_hex, binding_digest

PRIVACY_W = G.key("witness:privacy-register")
DPO = G.key("approver:dpo")
POOL = G.POOL + [G.cert(G.ROOT, PRIVACY_W, "claim:consent_recorded"),
                 G.cert(G.ROOT, DPO, "consent:DPO approver:p-dpo")]

def seal(a):
    a["seal"] = None
    body = {k: v for k, v in a.items() if k not in ("seal", "attestations")}
    h = sha256_hex(jcs(body))
    signed_by = {"name": "Acme Bank Credit Policy (test vector issuer)", "org_id": "acme-bank", "role": "policy_issuer", "timestamp": G.ISS}
    a["seal"] = {"status": "sealed", "hash": h, "canonicalization": "JCS", "signature_algorithm": "Ed25519",
                 "kid": G.ISSUER["kid"], "signed_by": signed_by, "signature": G.sign(G.ISSUER, {"hash": h, "signed_by": signed_by})}
    return a

def privacy_law(lending, artifact_id="vector-data-protection", amount_source="action"):
    """A second law: sharing a person's data with a third party needs their recorded consent, and a
    large shared transaction needs the data protection officer. It declares `amount` as the lending
    authority does (unless a case changes `amount_source` to make the declarations conflict)."""
    a = copy.deepcopy(lending)
    a["meta"]["artifact_id"] = artifact_id
    a["meta"]["name"] = "Vector data protection law"
    a["meta"]["description"] = "SPEC-008 rev. 0.8.0 test vector authority: a second law governing the same act."
    a["data_contract"]["inputs"] = {
        "amount": {"type": "number", "required": False, "source": amount_source},
        "data_shared_with_third_party": {"type": "boolean", "required": False, "source": "action"},
        "consent_recorded": {"type": "boolean", "required": False, "source": "testimony"},
    }
    a["logic"]["decisions"] = [
        {"id": "P1", "name": "no_sharing_without_consent", "description": "Personal data is not shared with a third party without the person's recorded consent.",
         "when": "data_shared_with_third_party == true and consent_recorded == false", "then": [{"type": "block"}], "else": [], "priority": 100},
        {"id": "P2", "name": "large_shared_needs_dpo", "description": "A shared transaction above 50,000 needs the data protection officer.",
         "when": "data_shared_with_third_party == true and amount > 50000", "then": [{"type": "escalate", "escalation_id": "ESC_DPO"}], "else": [], "priority": 50},
        {"id": "P0", "name": "otherwise_permitted", "description": "Anything this law does not restrict is permitted.",
         "when": "amount >= 0", "then": [{"type": "allow"}], "else": [], "priority": 10},
    ]
    a["logic"]["resolution"] = {"conflict_policy": "highest_priority", "tie_breaker": "deny_wins", "default_outcome": "block"}
    a["governance"]["escalations"] = [{"id": "ESC_DPO", "role_required": "DPO", "required_consents": 1, "description": "The data protection officer approves."}]
    return seal(a)

def main():
    lending = G.build_artifact(json.load(open(sys.argv[1])))
    privacy = privacy_law(lending)
    conflicting = privacy_law(lending, artifact_id="vector-data-protection-conflicting", amount_source="testimony")
    LID, PID = lending["meta"]["artifact_id"], privacy["meta"]["artifact_id"]
    cases = []
    def add(name, a, expected, note, evaluate_only=None):
        c = {"name": name, "note": note, "now": G.NOW, "seen_nonces": [], "act": a, "expected": expected}
        if evaluate_only is not None: c["evaluate_only"] = evaluate_only
        cases.append(c)
    def act(n, params, witnessed, further=(privacy,)):
        a = G.act(100 + n, params, witnessed, lending, pool=POOL)
        if further is not None: a["further_authorities"] = [{"artifact": f} for f in further]
        return a
    consent_given = G.testimony(PRIVACY_W, "consent_recorded", True)
    no_consent = G.testimony(PRIVACY_W, "consent_recorded", False)
    small = {"amount": 4000, "loan_purpose": "education", "has_cosigner": False}
    mid = {"amount": 75000, "loan_purpose": "home_improvement", "has_cosigner": False}

    a1 = act(1, {**small, "data_shared_with_third_party": False}, G.good_profile(768, 0.22))
    add("two_laws_both_allow", a1,
        {"decision": "AUTHORIZED", "commit": True, "laws": [{"artifact_id": LID, "rule": "R0", "decision": "AUTHORIZED"}, {"artifact_id": PID, "rule": "P0", "decision": "AUTHORIZED"}]},
        "The lending policy and the data protection law both govern the act; each permits it over the facts it declares, so the Act commits.")
    add("second_law_denies", act(2, {**small, "data_shared_with_third_party": True}, G.good_profile(768, 0.22) + [no_consent]),
        {"decision": "DENIED", "commit": False, "laws": [{"artifact_id": LID, "rule": "R0", "decision": "AUTHORIZED"}, {"artifact_id": PID, "rule": "P1", "decision": "DENIED"}]},
        "The lending policy permits the loan; the data protection law forbids sharing without consent. Any law that denies denies the act.")
    add("second_law_undecided", act(3, {**small, "data_shared_with_third_party": True}, G.good_profile(768, 0.22)),
        {"decision": "INCOMPLETE", "reason_code": "undecided_rules", "commit": False,
         "laws": [{"artifact_id": LID, "rule": "R0", "decision": "AUTHORIZED"}, {"artifact_id": PID, "rule": "P0", "decision": "INCOMPLETE", "open_rules": ["P1"], "open_facts": ["consent_recorded"]}]},
        "The privacy register's statement is left out. The data protection law cannot decide, so nothing commits, and the missing fact is named.")
    a4 = act(4, {**mid, "data_shared_with_third_party": True}, G.good_profile(742, 0.31) + [consent_given])
    a4["consents"] = [G.consent(G.APPROVER_A, a4), G.consent(G.APPROVER_B, a4)]
    add("one_law_satisfied_the_other_escalated", a4,
        {"decision": "ESCALATED", "commit": False, "laws": [
            {"artifact_id": LID, "rule": "R6", "decision": "AUTHORIZED", "by_consent": True, "escalation_id": "ESC_DUAL", "consents_valid": 2, "consents_required": 2},
            {"artifact_id": PID, "rule": "P2", "decision": "ESCALATED", "by_consent": False, "escalation_id": "ESC_DPO", "consents_valid": 0, "consents_required": 1}]},
        "Both senior approvers satisfy the lending escalation; the data protection officer has not approved. Each law's escalation is counted separately.")
    a5 = act(5, {**mid, "data_shared_with_third_party": True}, G.good_profile(742, 0.31) + [consent_given])
    a5["consents"] = [G.consent(G.APPROVER_A, a5), G.consent(G.APPROVER_B, a5), G.consent(DPO, a5, role="DPO")]
    add("both_escalations_satisfied", a5,
        {"decision": "AUTHORIZED", "commit": True, "laws": [
            {"artifact_id": LID, "rule": "R6", "decision": "AUTHORIZED", "by_consent": True, "escalation_id": "ESC_DUAL", "consents_valid": 2, "consents_required": 2},
            {"artifact_id": PID, "rule": "P2", "decision": "AUTHORIZED", "by_consent": True, "escalation_id": "ESC_DPO", "consents_valid": 1, "consents_required": 1}]},
        "Two senior approvers and the data protection officer, all over this exact Act. Every law says yes, so the act commits.")
    one = G.act(106, {**mid, "data_shared_with_third_party": True}, G.good_profile(742, 0.31) + [consent_given], lending, pool=POOL)
    lifted = act(6, {**mid, "data_shared_with_third_party": True}, G.good_profile(742, 0.31) + [consent_given])
    lifted["act_id"], lifted["nonce"] = one["act_id"], one["nonce"]
    lifted["consents"] = [G.consent(G.APPROVER_A, one), G.consent(G.APPROVER_B, one)]
    add("consent_lifted_from_a_one_law_act", lifted, {"decision": "CONSENT_INVALID", "reason_code": "binding_mismatch"},
        "The same act, with consents signed when it carried the lending policy alone. The binding digest covers the exact set of laws, so they do not carry over.")
    undeclared = act(7, {**small, "data_shared_with_third_party": False}, G.good_profile(768, 0.22))
    undeclared["presenter_facts"] = {"favourite_colour": "blue"}
    add("fact_declared_by_no_law", undeclared, {"decision": "FACT_SOURCE_VIOLATION", "field": "favourite_colour", "reason_code": "undeclared_input"},
        "A fact neither law declares is refused, whichever law the presenter hoped would read it.")
    add("conflicting_declarations", act(8, {**small, "data_shared_with_third_party": False}, G.good_profile(768, 0.22), further=(conflicting,)),
        {"decision": "FACT_SOURCE_VIOLATION", "field": "amount", "reason_code": "conflicting_declarations"},
        "One law reads amount from the action, the other from testimony. The channel would depend on which law is read, so the Act is refused.")
    add("duplicate_authority", act(9, small, G.good_profile(768, 0.22), further=(lending,)),
        {"decision": "MALFORMED", "reason_code": "duplicate_authority"}, "The same law carried twice.")
    a10 = G.act(110, small, G.good_profile(768, 0.22), lending, pool=POOL)
    old_core = {k: a10[k] for k in ("act_version", "act_id", "nonce", "issued_at", "expires_at", "relying_party", "action")}
    old_core["artifact_hash"] = lending["seal"]["hash"]
    old_core["testimony_digest"] = sha256_hex(jcs(sorted(a10["testimony"], key=lambda t: jcs(t))))
    assert binding_digest(a10) == sha256_hex(jcs(old_core)), "a one-law Act's binding digest must be unchanged from 0.7.0"
    add("one_law_act_unchanged", a10, {"decision": "AUTHORIZED", "rule": "R0", "commit": True, "act_digest": sha256_hex(jcs(old_core))},
        "An Act with no further authorities verifies exactly as under 0.7.0, with the same binding digest.")
    add("resolution_ignores_a_law_that_does_not_govern", act(11, {**small, "data_shared_with_third_party": True}, G.good_profile(768, 0.22) + [no_consent]),
        {"decision": "AUTHORIZED", "commit": True, "laws": [{"artifact_id": LID, "rule": "R0", "decision": "AUTHORIZED"}]},
        "The relying party resolved only the lending policy as governing. The data protection law the presenter carried would deny, but it is not evaluated: adding a law cannot change the verdict.",
        evaluate_only=[LID])
    add("resolution_names_a_law_not_carried", G.act(112, small, G.good_profile(768, 0.22), lending, pool=POOL),
        {"decision": "INCOMPLETE", "commit": False, "reason_code": "laws_not_presented", "laws": [PID]},
        "Both laws govern the act; the Act carries only the lending policy. Nothing commits, and the missing law is named.",
        evaluate_only=[LID, PID])
    add("resolution_before_an_undeclared_input", G.act(113, {**small, "data_shared_with_third_party": True}, G.good_profile(768, 0.22), lending, pool=POOL),
        {"decision": "INCOMPLETE", "commit": False, "reason_code": "laws_not_presented", "laws": [PID]},
        "The Act carries only the lending policy, and supplies data_shared_with_third_party, which only the data protection law declares. Both laws govern, so the missing law is named rather than the input refused.",
        evaluate_only=[LID, PID])

    out = {"_readme": "NOMOS-SPEC-008 rev. 0.8.0 vectors: an Act under several laws. Verify each case's act as for vectors.json (root_public_key_pem, relying_party_id, local_facts, currency_policy, in_force); where a case carries evaluate_only, pass it as the artifact ids of the resolved applicable set (rev. 0.8.0 §6.4). Compare every field `expected` names; `laws` is compared as a list, in the order the Act carries its authorities.",
           "spec": "NOMOS-SPEC-008 rev. 0.8.0",
           "root_public_key_pem": G.ROOT["pem"], "relying_party_id": G.RP, "local_facts": {"is_first_loan": False}, "currency_policy": "record",
           "in_force": {a["meta"]["artifact_id"]: a["seal"]["hash"] for a in (lending, privacy, conflicting)},
           "keys": {k["label"]: k["kid"] for k in (G.ROOT, G.ISSUER, G.BUREAU, G.APPROVER_A, G.APPROVER_B, PRIVACY_W, DPO)},
           "cases": cases}
    print(json.dumps(out, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
