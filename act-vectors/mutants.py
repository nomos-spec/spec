"""Derived mutants of every NOMOS-SPEC-008 vector, with the reference verdict for each.

    python3 mutants.py vectors.json > mutants.json

Each mutant is one small, deliberate change an attacker or a faulty presenter could make to a
published Act: a dropped, tampered or relabelled statement, a dropped or duplicated consent, a
removed or widened certificate, a reversed pool, a changed parameter, tampered rules, a relabelled
seal, a re-addressed Act, a presenter asserting a fact, either currency policy. A second
implementation derives the same mutants (the recipe below, in order) and must reproduce every
`expected` verdict field for field; only `detail`, which is free text, is excluded."""
import copy, json, sys
v = json.load(open(sys.argv[1]))
out = []
def add(c, name, act, **over):
    out.append({"base": c["name"], "mutant": name, "act": act, "now": over.get("now", c["now"]), "seen_nonces": c["seen_nonces"],
                "revoked_artifacts": c.get("revoked_artifacts", []), "currency_policy": over.get("currency_policy", c.get("currency_policy", v["currency_policy"]))})
for c in v["cases"]:
    a = c["act"]
    add(c, "identity", a)
    add(c, "policy_record", a, currency_policy="record")
    add(c, "policy_statement", a, currency_policy="record_or_statement")
    for i in range(len(a.get("testimony") or [])):
        m = copy.deepcopy(a); del m["testimony"][i]; add(c, f"drop_testimony_{i}", m)
        m = copy.deepcopy(a); m["testimony"][i]["value"] = "tampered"; add(c, f"tamper_testimony_{i}", m)
        m = copy.deepcopy(a); m["testimony"][i]["algorithm"] = "ES256"; add(c, f"relabel_testimony_{i}", m)
    for i in range(len(a.get("consents") or [])):
        m = copy.deepcopy(a); del m["consents"][i]; add(c, f"drop_consent_{i}", m)
        m = copy.deepcopy(a); m["consents"][i]["role"] = "REVIEWER"; add(c, f"role_consent_{i}", m)
        m = copy.deepcopy(a); m["consents"][i] = dict(m["consents"][i]); m["consents"].append(m["consents"][i]); add(c, f"dup_consent_{i}", m)
    pool = a["authority"]["key_certs"]
    for i in range(len(pool)):
        m = copy.deepcopy(a); del m["authority"]["key_certs"][i]; add(c, f"drop_cert_{i}", m)
        m = copy.deepcopy(a); m["authority"]["key_certs"][i]["scope"] = (m["authority"]["key_certs"][i].get("scope") or "") + " industry:insurance"; add(c, f"widen_cert_{i}", m)
    m = copy.deepcopy(a); m["authority"]["key_certs"] = list(reversed(pool)); add(c, "reverse_pool", m)
    for k in list((a["action"].get("params") or {}).keys()):
        m = copy.deepcopy(a); del m["action"]["params"][k]; add(c, f"drop_param_{k}", m)
        m = copy.deepcopy(a); val = m["action"]["params"][k]; m["action"]["params"][k] = val * 10 if isinstance(val, (int, float)) and not isinstance(val, bool) else "changed"; add(c, f"change_param_{k}", m)
    m = copy.deepcopy(a); m["authority"]["artifact"]["logic"]["decisions"][0]["priority"] = 999; add(c, "tamper_rules", m)
    m = copy.deepcopy(a); m["authority"]["artifact"]["seal"]["signature_algorithm"] = "ES256"; add(c, "relabel_seal", m)
    m = copy.deepcopy(a); m["relying_party"] = "elsewhere"; add(c, "readdress", m)
    m = copy.deepcopy(a); m["presenter_facts"] = {"credit_score": 900}; add(c, "presenter_claims_fact", m)
    m = copy.deepcopy(a); m["authority"] = "not-an-object"; add(c, "bad_authority", m)
from act_verify import verify_act, ts
for c in out:
    r = verify_act(c["act"], relying_party_id=v["relying_party_id"], root_pem=v["root_public_key_pem"], now=ts(c["now"]),
                   seen_nonces=set(c["seen_nonces"]), local_facts=v["local_facts"], in_force=v["in_force"],
                   revoked_artifacts=set(c["revoked_artifacts"]), currency_policy=c["currency_policy"])
    c["expected"] = {k: x for k, x in r.items() if k != "detail"}
    del c["act"]                      # the recipe regenerates it; the file stays small
json.dump({"_readme": __doc__.strip(), "spec": "NOMOS-SPEC-008 0.6.0", "count": len(out), "cases": out}, sys.stdout, indent=1, sort_keys=True)
sys.stdout.write("\n")
