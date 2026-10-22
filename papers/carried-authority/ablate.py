#!/usr/bin/env python3
"""
Ablation study for "Authorize the Act, Not the Agent" (Computable Authority, Part II).

Each necessity theorem says: a verifier lacking property P admits an action the institution's own
rules (or its approvers) did not authorize. This script makes each theorem executable. It builds a
weakened copy of the reference verifier (act_verify.py) with exactly one property removed, then
presents a genuinely signed attack Act — every signature valid, no cryptography broken — and
records three verdicts:

  full     the unmodified SPEC-008 reference verifier on the attack Act
  ablated  the verifier with property P removed, on the same attack Act
  truth    what the institution's rules return on the complete, truthful facts (or, for binding
           attacks, what the approvers actually approved)

The theorem is witnessed when `ablated` commits, `full` does not, and `truth` would not have.

Usage: python3 ablate.py vectors.json
"""
import copy, json, re, sys, types, hashlib, base64
import act_verify_040 as AV          # SPEC-008 0.4.0 reference verifier, frozen from nomos-spec c8fa382
import generate_040 as G             # SPEC-008 0.4.0 generator (29 vectors), frozen from c8fa382
from act_verify_040 import ts, jcs, sha256_hex

V = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "vectors.json"))
NOW = ts(G.NOW); RP = V["relying_party_id"]; ROOT = V["root_public_key_pem"]
LOCAL = V["local_facts"]
SRC = open(AV.__file__).read()

def variant(name, patches):
    """A copy of the reference verifier with textual patches applied (each must match once)."""
    src = SRC
    for old, new in patches:
        n = src.count(old)
        assert n == 1, f"{name}: patch target found {n} times: {old[:60]!r}"
        src = src.replace(old, new)
    m = types.ModuleType("act_verify_" + name); m.__file__ = AV.__file__
    exec(compile(src, f"<{name}>", "exec"), m.__dict__)
    return m

RECORD = {}   # the relying party's own record of the version in force, filled once the authorities are built
def run(mod, act, *, in_force=None, seen=(), rp=RP, pool_root=ROOT):
    return mod.verify_act(act, relying_party_id=rp, root_pem=pool_root, now=NOW, seen_nonces=set(seen),
                          local_facts=LOCAL, in_force=in_force if in_force is not None else RECORD)

COMMITS = lambda r: r.get("decision") == "AUTHORIZED"

# ── weakened verifiers ───────────────────────────────────────────────────────────────────
TWO_VALUED = variant("two_valued", [(
    "    results = [(d, r) for d, r, _ in detail]",
    "    results = [(d, (F if r == U else r)) for d, r, _ in detail]   # ABLATION: unknown read as false")])
NO_CHANNELS = variant("no_channels", [(
    "        if declared != src:",
    "        if False:   # ABLATION: any channel may supply any declared input")])
NO_CURRENCY = variant("no_currency", [(
    "    if art_id in in_force:",
    "    if True:   # ABLATION: authenticity and revocation only, currency not checked\n        in_force_source = \"unchecked\"\n    elif art_id in in_force:")])
ORDER_DEPENDENT = variant("order_dependent", [(
    '    for c in sorted((c for c in pool if c.get("child_kid") == target), key=_fp):',
    '    for c in [c for c in pool if c.get("child_kid") == target][:1]:   # ABLATION: first match in presentation order')])

def binding_without(field):
    m = variant("binding_without_" + field, [])
    full_core = m.binding_core
    m.binding_core = lambda act: {k: v for k, v in full_core(act).items() if k != field}
    return m

def consent_under(mod, approver, act, role="SENIOR_APPROVER"):
    """An approver's genuine signature over the digest *as that scheme defines it*."""
    c = {"binding_digest": mod.binding_digest(act), "role": role, "decision": "approve",
         "signed_at": "2026-10-01T11:59:30.000Z", "kid": approver["kid"], "algorithm": "Ed25519"}
    c["signature"] = G.sign(approver, AV.consent_payload(c)); return c

def fresh_nonce(act, tag):
    act["nonce"] = base64.b64encode(hashlib.sha256(f"attack-{tag}".encode()).digest()[:16]).decode()
    act["act_id"] = f"attack-{tag}"

# ── the authorities used by the attacks ─────────────────────────────────────────────────
BASE = json.load(open("pub_lending_v1.nomos"))
ART = G.build_artifact(BASE)
FLAGGED = G.build_artifact(BASE, extra_rule={
    "id": "R13", "name": "fraud_alert_block", "description": "Any open fraud alert blocks the loan.",
    "when": "exists(fraud_alert)", "then": [{"type": "block"}], "else": [], "priority": 120},
    extra_inputs={"fraud_alert": {"type": "string", "required": False, "source": "testimony"}})
TERMED = G.build_artifact(BASE, extra_rule={
    "id": "R14", "name": "long_term_block", "description": "Terms over 360 months are refused.",
    "when": "terms.months > 360", "then": [{"type": "block"}], "else": [], "priority": 120},
    extra_inputs={"terms": {"type": "object", "required": False, "source": "action"}})

RECORD.update({x["meta"]["artifact_id"]: x["seal"]["hash"] for x in (ART, FLAGGED, TERMED)})
rows = []
def record(theorem, prop, attack, full, ablated, truth, note):
    witnessed = COMMITS(ablated) and not COMMITS(full) and not truth.get("commits", COMMITS(truth))
    rows.append({"theorem": theorem, "property_removed": prop, "attack": attack,
                 "full": full.get("decision"), "ablated": ablated.get("decision"),
                 "truth": truth.get("decision"), "witnessed": witnessed, "note": note})

small = {"amount": 4000, "loan_purpose": "education", "has_cosigner": False}
mid = {"amount": 75000, "loan_purpose": "home_improvement", "has_cosigner": False}
big = {"amount": 250000, "loan_purpose": "home_improvement", "has_cosigner": False}

# T4 omission — the presenter withholds the statement that would deny the action
a = G.act(101, small, [G.testimony(G.BUREAU, "credit_score", 768), G.testimony(G.BUREAU, "dti_ratio", 0.22),
                       G.testimony(G.BUREAU, "delinquency_severity", "none")], ART)
truth = G.act(101, small, G.good_profile(768, 0.22)[:2] + [G.testimony(G.BUREAU, "bankruptcy_active", True),
                                                           G.testimony(G.BUREAU, "delinquency_severity", "none")], ART)
record("T4", "three-valued evaluation", "withhold bankruptcy_active (true in the world)",
       run(AV, a), run(TWO_VALUED, a), run(AV, truth), "R1 outranks R0; read as false, the bankruptcy rule falls silent")

a = G.act(102, big, [G.testimony(G.BUREAU, "credit_score", 702), G.testimony(G.BUREAU, "bankruptcy_active", False),
                     G.testimony(G.BUREAU, "delinquency_severity", "none")], ART)
a["consents"] = [consent_under(TWO_VALUED, G.APPROVER_A, a), consent_under(TWO_VALUED, G.APPROVER_B, a)]
truth = G.act(102, big, G.good_profile(702, 0.58), ART)
record("T4", "three-valued evaluation", "withhold dti_ratio (0.58 in the world), attach two genuine consents",
       run(AV, a), run(TWO_VALUED, a), run(AV, truth), "approvers cannot stand in for a missing fact")

a = G.act(103, small, G.good_profile(768, 0.22), FLAGGED)
truth = G.act(103, small, G.good_profile(768, 0.22) + [G.testimony(G.BUREAU, "fraud_alert", "FA-77")], FLAGGED)
# (the bureau's certificate does not cover fraud_alert; the truthful reference run uses a scope-extended pool)
pool_fa = [G.cert(G.ROOT, G.ISSUER), G.cert(G.ROOT, G.BUREAU, "claim:credit_score,dti_ratio,bankruptcy_active,delinquency_severity,days_since_delinquency,fraud_alert")] + G.POOL[2:]
truth["authority"]["key_certs"] = pool_fa
record("T4", "three-valued evaluation", "withhold the fraud alert read by exists(fraud_alert)",
       run(AV, a), run(TWO_VALUED, a), run(AV, truth), "exists() decided by absence for a witnessed fact")

a = G.act(104, dict(small, terms={"months": "480"}), G.good_profile(768, 0.22), TERMED)
truth = G.act(104, dict(small, terms={"months": 480}), G.good_profile(768, 0.22), TERMED)
record("T4", "three-valued evaluation", "send terms.months as the string \"480\" inside an object parameter",
       run(AV, a), run(TWO_VALUED, a), run(AV, truth), "a value of the wrong kind is a way to be silent")

# T1 authenticity — the verifier trusts an anchor the presenter chose (cf. JWT jku/x5u header injection)
R_ROOT, R_ISS = G.key("attacker:root"), G.key("attacker:issuer")
FORGED = copy.deepcopy(BASE)
FORGED["logic"]["decisions"] = [{"id": "X1", "name": "allow_all", "description": "Approve everything.",
                                 "when": "amount > 0", "then": [{"type": "allow"}], "else": [], "priority": 999}]
def seal_with(src, k, artifact_id):
    a = G.build_artifact(src, artifact_id=artifact_id)          # sealed by the genuine issuer ...
    body = {kk: v for kk, v in a.items() if kk not in ("seal", "attestations")}
    a["seal"]["kid"] = k["kid"]                                  # ... then re-signed by the attacker's key
    a["seal"]["signature"] = G.sign(k, {"hash": a["seal"]["hash"], "signed_by": a["seal"]["signed_by"]}); return a
FORGED_ART = seal_with(FORGED, R_ISS, "acme-bank-express-lending")
st = {"artifact_id": "acme-bank-express-lending", "version": FORGED_ART["meta"]["version"], "seal_hash": FORGED_ART["seal"]["hash"],
      "as_of": "2026-10-01T06:00:00.000Z", "valid_until": "2026-10-02T06:00:00.000Z", "kid": R_ISS["kid"], "algorithm": "Ed25519"}
st["signature"] = G.sign(R_ISS, AV.in_force_payload(st))
a = G.act(100, dict(big, amount=900000), [], FORGED_ART, pool=[G.cert(R_ROOT, R_ISS)])
a["authority"]["in_force"] = st
truth = G.act(100, dict(big, amount=900000), G.good_profile(702, 0.58), ART)
rows_before = len(rows)
full_r = run(AV, a); abl_r = run(AV, a, pool_root=R_ROOT["pem"])
record("T1", "relying-party-pinned root", "an allow-everything authority sealed under a root the presenter supplies",
       full_r, abl_r, run(AV, truth), "the institution never issued this authority")

# T2 provenance — the presenter supplies a fact the rules assigned to a witness
a = G.act(105, small, [G.testimony(G.BUREAU, "dti_ratio", 0.22), G.testimony(G.BUREAU, "bankruptcy_active", False),
                       G.testimony(G.BUREAU, "delinquency_severity", "none")], ART, presenter_facts={"credit_score": 768})
truth = G.act(105, small, G.good_profile(600, 0.22), ART)
record("T2", "rule-declared fact channels", "agent asserts credit_score 768 (bureau holds 600)",
       run(AV, a), run(NO_CHANNELS, a), run(AV, truth), "the rules evaluate the agent's story, not the world")

# T3 binding — each component of the binding core, removed in turn
def binding_attack(field, build):
    m = binding_without(field)
    approved, attack, extra = build(m)
    full = run(AV, attack, **extra.get("full", {})); abl = run(m, attack, **extra.get("ablated", {}))
    truth = {"decision": f"approved: {approved}", "commits": False}
    record("T3", f"binding over {field}", extra["what"], full, abl, truth, extra["note"])

def b_action(m):
    a = G.act(110, mid, G.good_profile(742, 0.31), ART)
    a["consents"] = [consent_under(m, G.APPROVER_A, a), consent_under(m, G.APPROVER_B, a)]
    x = copy.deepcopy(a); x["action"]["params"]["amount"] = 750000
    return "$75,000", x, {"what": "consents for $75,000 reused for $750,000", "note": "approval transfers to a different change"}
binding_attack("action", b_action)

def b_testimony(m):
    shown = G.good_profile(742, 0.31)
    a = G.act(111, mid, shown, ART)
    a["consents"] = [consent_under(m, G.APPROVER_A, a), consent_under(m, G.APPROVER_B, a)]
    later = G.testimony(G.BUREAU, "dti_ratio", 0.48, as_of="2026-10-01T11:45:00.000Z")   # also genuine, also in window
    x = copy.deepcopy(a); x["testimony"] = [t if t["claim"] != "dti_ratio" else later for t in x["testimony"]]
    return "DTI 31%", x, {"what": "approvers shown DTI 31%; a second genuine, in-window statement (48%) swapped in",
                          "note": "approval transfers to a different evidentiary basis"}
binding_attack("testimony_digest", b_testimony)

def b_audience(m):
    a = G.act(112, mid, G.good_profile(742, 0.31), ART)
    a["consents"] = [consent_under(m, G.APPROVER_A, a), consent_under(m, G.APPROVER_B, a)]
    x = copy.deepcopy(a); x["relying_party"] = "acme-bank:card-ledger"
    return "commit at core-ledger", x, {"what": "consents for the core ledger re-addressed to the card ledger",
                                        "full": {"rp": "acme-bank:card-ledger"}, "ablated": {"rp": "acme-bank:card-ledger"},
                                        "note": "one approval, two systems of record"}
binding_attack("relying_party", b_audience)

def b_nonce(m):
    a = G.act(113, mid, G.good_profile(742, 0.31), ART)
    a["consents"] = [consent_under(m, G.APPROVER_A, a), consent_under(m, G.APPROVER_B, a)]
    x = copy.deepcopy(a); fresh_nonce(x, "113b"); x["act_id"] = a["act_id"]
    return "one disbursement", x, {"what": "the committed Act resubmitted with a fresh nonce and the same consents",
                                   "full": {"seen": [a["nonce"]]}, "ablated": {"seen": [a["nonce"]]},
                                   "note": "approved once, committed twice"}
binding_attack("nonce", b_nonce)

WAIVER = G.build_artifact(BASE, artifact_id="vector-lending-acts-waiver", extra_rule={
    "id": "R15", "name": "cosigner_waiver", "description": "Waiving the cosigner on loans above $60,000 needs senior approval of the waiver.",
    "when": "amount > 60000 and has_cosigner == false", "then": [{"type": "escalate", "escalation_id": "ESC_DUAL"}], "else": [], "priority": 88})
def b_artifact(m):
    a = G.act(114, mid, G.good_profile(742, 0.31), ART)
    a["consents"] = [consent_under(m, G.APPROVER_A, a), consent_under(m, G.APPROVER_B, a)]
    x = copy.deepcopy(a); x["authority"]["artifact"] = WAIVER
    rec = dict(RECORD, **{"vector-lending-acts-waiver": WAIVER["seal"]["hash"]})
    return "R6 under the base policy", x, {"what": "consents given under one policy satisfy a different escalation (R15, cosigner waiver) under another in-force policy",
                                           "full": {"in_force": rec}, "ablated": {"in_force": rec},
                                           "note": "approval transfers to a different rule"}
binding_attack("artifact_hash", b_artifact)

# T5 currency — a genuine, unrevoked, superseded version
OLD = copy.deepcopy(BASE); OLD["logic"]["decisions"] = [d for d in OLD["logic"]["decisions"] if d["id"] not in ("R8", "R10")]
OLD_ART = G.build_artifact(OLD, version="0.9.0", artifact_id="vector-lending-acts", extra_rule={
    "id": "R0b", "name": "old_small_loan_allow", "description": "v0.9.0: loans up to $25,000 at score 680+ and DTI 40% or less are approved.",
    "when": "amount <= 25000 and credit_score >= 680 and dti_ratio <= 0.40", "then": [{"type": "allow"}], "else": [], "priority": 10})
a = G.act(120, dict(small, amount=20000), G.good_profile(768, 0.22), OLD_ART)
truth = G.act(120, dict(small, amount=20000), G.good_profile(768, 0.22), ART)
record("T5", "currency separate from authenticity", "present v0.9.0 (no review threshold), superseded but never revoked",
       run(AV, a), run(NO_CURRENCY, a), run(AV, truth), "the current version sends a $20,000 loan to a reviewer")

# P6 order — the presenter chooses the verdict by ordering certificates
INTER = G.key("intermediate:expired-bureau-ca")
expired_c = {"parent_kid": INTER["kid"], "child_kid": G.BUREAU["kid"], "child_public_key_pem": G.BUREAU["pem"],
             "scope": "claim:credit_score,dti_ratio,bankruptcy_active,delinquency_severity", "issued_at": "2025-01-01T00:00:00.000Z",
             "expires_at": "2025-12-31T00:00:00.000Z", "algorithm": "Ed25519"}
expired_c["signature"] = G.sign(INTER, AV.cert_payload(expired_c))
inter_c = G.cert(G.ROOT, INTER)
for label, pool in (("expired path first", [inter_c, expired_c] + G.POOL), ("valid path first", G.POOL + [inter_c, expired_c])):
    a = G.act(130, small, G.good_profile(768, 0.22), ART, pool=pool)
    rows.append({"theorem": "P6", "property_removed": "order-independent resolution", "attack": f"same certificates, {label}",
                 "full": run(AV, a).get("decision"), "ablated": run(ORDER_DEPENDENT, a).get("decision"), "truth": "AUTHORIZED",
                 "witnessed": None, "note": "verdict selected by presentation order"})

w = sum(1 for r in rows if r["witnessed"]); n = sum(1 for r in rows if r["witnessed"] is not None)
for r in rows:
    mark = {True: "WITNESSED", False: "not witnessed", None: "  (order)"}[r["witnessed"]]
    print(f"{r['theorem']:3s} {mark:13s} full={r['full']:<22s} ablated={r['ablated']:<22s} truth={r['truth']:<26s} | {r['attack']}")
order = [r for r in rows if r["theorem"] == "P6"]
print(f"\n{w}/{n} necessity counterexamples witnessed; order ablation: verdicts "
      f"{[r['ablated'] for r in order]} (ablated) vs {[r['full'] for r in order]} (full)")
json.dump(rows, open("ablation-results.json", "w"), indent=2)
