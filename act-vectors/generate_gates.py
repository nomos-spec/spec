#!/usr/bin/env python3
"""
Deterministic generator for the NOMOS-SPEC-008 rev. 0.9.0 vectors: intake questions (gates) in an Act.

A transfer law declares two intake questions: one answered by the presenter, one by the relying
party. A "no" settles the facts each question covers; a covered fact supplied with another value
contradicts the answer. It reuses generate.py's published keys and lending authority. Running it
twice produces byte-identical output. THESE PRIVATE KEYS ARE PUBLISHED ON PURPOSE.

Usage:  python3 generate_gates.py <path/to/pub_lending_v1.nomos>  >  gate-vectors.json
"""
import copy, json, sys
import generate as G
from generate_multi import seal

TRANSFER_W = G.key("witness:transfer-register")
POOL = G.POOL + [G.cert(G.ROOT, TRANSFER_W, "claim:recipient_adequate")]

def transfer_law(lending, artifact_id="vector-transfer-law", bad_gate=False):
    a = copy.deepcopy(lending)
    a["meta"]["artifact_id"] = artifact_id
    a["meta"]["name"] = "Vector transfer law"
    a["meta"]["description"] = "SPEC-008 rev. 0.9.0 test vector authority: a law decided through intake questions."
    a["data_contract"]["inputs"] = {
        "amount": {"type": "number", "required": True, "source": "action"},
        "transfer_abroad": {"type": "boolean", "required": False, "source": "presenter"},
        "recipient_adequate": {"type": "boolean", "required": False, "source": "testimony"},
        "open_incident": {"type": "boolean", "required": False, "source": "relying_party"},
    }
    a["data_contract"]["gates"] = {
        "q_cross_border": {"question": "Does this send data outside the jurisdiction?", "source": "presenter", "when_false": {"transfer_abroad": False}},
        "q_incident": {"question": "Is there an open security incident on this system?", "source": "relying_party", "when_false": {"open_incident": False}},
    }
    if bad_gate:   # a question named like a fact the rules read
        a["data_contract"]["gates"]["open_incident"] = {"question": "x", "source": "relying_party", "when_false": {"transfer_abroad": False}}
    a["logic"]["decisions"] = [
        {"id": "T2", "name": "no_transfer_without_adequacy", "description": "Data goes abroad only to an adequate recipient.",
         "when": "transfer_abroad == true and recipient_adequate == false", "then": [{"type": "block"}], "else": [], "priority": 100},
        {"id": "T3", "name": "no_processing_during_incident", "description": "Nothing is processed while a security incident is open.",
         "when": "open_incident == true", "then": [{"type": "block"}], "else": [], "priority": 90},
        {"id": "T0", "name": "otherwise_permitted", "description": "Anything this law does not restrict is permitted.",
         "when": "amount >= 0", "then": [{"type": "allow"}], "else": [], "priority": 10},
    ]
    a["logic"]["resolution"] = {"conflict_policy": "highest_priority", "tie_breaker": "deny_wins", "default_outcome": "block"}
    a["governance"]["escalations"] = []
    return seal(a)

def main():
    lending = G.build_artifact(json.load(open(sys.argv[1])))
    law = transfer_law(lending)
    bad = transfer_law(lending, artifact_id="vector-transfer-law-bad", bad_gate=True)
    TID, LID = law["meta"]["artifact_id"], lending["meta"]["artifact_id"]
    cases = []
    def add(name, a, expected, note, local_facts=None, evaluate_only=None):
        c = {"name": name, "note": note, "now": G.NOW, "seen_nonces": [], "act": a, "expected": expected}
        if local_facts is not None: c["local_facts"] = local_facts
        if evaluate_only is not None: c["evaluate_only"] = evaluate_only
        cases.append(c)
    def act(n, presenter=None, witnessed=(), artifact=law, further=None, params=None):
        a = G.act(200 + n, params or {"amount": 500}, list(witnessed), artifact, presenter_facts=presenter, pool=POOL)
        if further: a["further_authorities"] = [{"artifact": f} for f in further]
        return a
    adequate = lambda v: G.testimony(TRANSFER_W, "recipient_adequate", v)

    add("questions_unanswered", act(1), {"decision": "INCOMPLETE", "reason_code": "undecided_rules", "rule": "T0",
        "open_rules": ["T2", "T3"], "open_facts": ["open_incident", "recipient_adequate", "transfer_abroad"], "open_gates": ["q_cross_border", "q_incident"]},
        "Nothing answered: the rules that could deny are open, and the result names the questions that would settle them.", local_facts={})
    add("both_questions_no", act(2, {"q_cross_border": False}), {"decision": "AUTHORIZED", "rule": "T0", "commit": True},
        "The presenter answers that nothing goes abroad; the relying party that no incident is open. Each 'no' settles its facts, and the act is authorized.",
        local_facts={"q_incident": False})
    add("one_question_no", act(3, {"q_cross_border": False}), {"decision": "INCOMPLETE", "open_rules": ["T3"], "open_facts": ["open_incident"], "open_gates": ["q_incident"]},
        "Only the cross-border question is answered. The incident rule stays open, and only the incident question is named.", local_facts={})
    add("answer_contradicted", act(4, {"q_cross_border": False, "transfer_abroad": True}),
        {"decision": "FACT_SOURCE_VIOLATION", "field": "transfer_abroad", "reason_code": "contradicts_gate", "gate": "q_cross_border"},
        "The presenter says nothing goes abroad and, in the same Act, that it does. The Act is refused.", local_facts={"q_incident": False})
    add("answer_and_fact_agree", act(12, {"q_cross_border": False, "transfer_abroad": False}), {"decision": "AUTHORIZED", "rule": "T0"},
        "A covered fact supplied with the same value the answer settles it to is no contradiction.", local_facts={"q_incident": False})
    add("question_yes_then_facts_deny", act(5, {"q_cross_border": True, "transfer_abroad": True}, [adequate(False)]),
        {"decision": "DENIED", "rule": "T2"},
        "A 'yes' settles nothing: the facts it covers arrive through their own channels, and the transfer rule denies.", local_facts={"q_incident": False})
    add("question_yes_then_facts_allow", act(6, {"q_cross_border": True, "transfer_abroad": True}, [adequate(True)]),
        {"decision": "AUTHORIZED", "rule": "T0"}, "The witness states the recipient is adequate; the transfer is permitted.", local_facts={"q_incident": False})
    add("answer_through_wrong_channel", act(7, {"q_cross_border": False, "q_incident": False}),
        {"decision": "FACT_SOURCE_VIOLATION", "field": "q_incident", "declared": "relying_party", "supplied_via": "presenter"},
        "The incident question is the relying party's to answer. A presenter's answer is refused, as any fact through the wrong channel is.", local_facts={})
    add("answer_not_boolean", act(8, {"q_cross_border": "no"}), {"decision": "FACT_TYPE_VIOLATION", "field": "q_cross_border", "declared": "boolean"},
        "An intake question is answered true or false.", local_facts={"q_incident": False})
    add("question_named_like_a_fact", act(9, artifact=bad), {"decision": "MALFORMED", "reason_code": "bad_gates"},
        "A question named like a fact the rules read would let one answer stand for two things. The authority is refused.", local_facts={})
    add("under_several_laws", act(10, {"q_cross_border": False}, G.good_profile(768, 0.22), artifact=lending, further=(law,), params={"amount": 4000, "loan_purpose": "education", "has_cosigner": False}),
        {"decision": "AUTHORIZED", "commit": True, "laws": [{"artifact_id": LID, "rule": "R0", "decision": "AUTHORIZED"}, {"artifact_id": TID, "rule": "T0", "decision": "AUTHORIZED"}]},
        "The lending policy and the transfer law together. Each law reads its own questions and facts.",
        local_facts={"is_first_loan": False, "q_incident": False})
    add("under_several_laws_question_open", act(11, {}, G.good_profile(768, 0.22), artifact=lending, further=(law,), params={"amount": 4000, "loan_purpose": "education", "has_cosigner": False}),
        {"decision": "INCOMPLETE", "laws": [{"artifact_id": LID, "rule": "R0", "decision": "AUTHORIZED"},
                                            {"artifact_id": TID, "rule": "T0", "decision": "INCOMPLETE", "open_rules": ["T2"], "open_facts": ["recipient_adequate", "transfer_abroad"], "open_gates": ["q_cross_border"]}]},
        "The transfer law's cross-border question is unanswered; its row names it.", local_facts={"is_first_loan": False, "q_incident": False})
    for c in cases:
        if c["act"].get("presenter_facts") == {}: c["act"].pop("presenter_facts")

    out = {"_readme": "NOMOS-SPEC-008 rev. 0.9.0 vectors: intake questions (data_contract.gates) answered in an Act. Verify each case's act as for vectors.json; a case's local_facts, when present, replace the file's. Compare every field `expected` names.",
           "spec": "NOMOS-SPEC-008 rev. 0.9.0",
           "root_public_key_pem": G.ROOT["pem"], "relying_party_id": G.RP, "local_facts": {}, "currency_policy": "record",
           "in_force": {a["meta"]["artifact_id"]: a["seal"]["hash"] for a in (lending, law, bad)},
           "keys": {k["label"]: k["kid"] for k in (G.ROOT, G.ISSUER, G.BUREAU, TRANSFER_W)},
           "cases": cases}
    print(json.dumps(out, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
