#!/usr/bin/env python3
"""Generate the NOMOS-SPEC-014 0.4.0 registrar-log vectors, deterministically.

    python3 resolution-vectors/generate_registrar_logs.py > resolution-vectors/registrar-logs.json

Keys come from published seeds and ES256 signatures use RFC 6979 nonces, so the output is
byte-identical on every run. Every `expect` is written by hand from the specification text; the
generator never asks a verifier what the answer is.

Three kinds of case:
  log        verify one copy of a log under a pinned key (§2.1, §2.2)        -> ok | reason
  network    assemble the world from pins and delegations (§2.3), then resolve -> registrars, absent, result
  discovery  read `_nomos-registrar` TXT records for a registrar whose kid is already held (§2.5)
"""
import copy
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))
from nomosprotocol import suites as S  # noqa: E402
from nomosprotocol.jcs import jcs, sha256_hex  # noqa: E402
from nomosprotocol.registrar import head_payload, rotation_payload, PLATFORM_LOG, registrar_log_name  # noqa: E402

NOW = "2026-11-13T00:00:00.000Z"
HEAD_AT = "2026-11-12T23:58:00.000Z"
MAX_AGE = 600


class Key:
    def __init__(self, label, kind):
        seed = f"nomos-spec-014-0.4.0:{label}".encode()
        self.kind = kind
        self.priv = S.ed25519_key_from_seed(seed) if kind == "Ed25519" else S.p256_key_from_seed(seed)
        self.pem = S.public_pem(self.priv)
        self.kid = S.compute_kid(self.pem)
        self.suite = "Ed25519" if kind == "Ed25519" else "ES256"

    def sign(self, payload, *, low_s=True):
        return S.sign_ed25519(self.priv, payload) if self.kind == "Ed25519" else S.sign_es256(self.priv, payload, low_s=low_s)


PLATFORM = Key("platform", "Ed25519")
DIFC = Key("difc", "P-256")
DIFC_NEXT = Key("difc-next", "Ed25519")
GOV = Key("government", "Ed25519")
ATTACKER = Key("attacker", "Ed25519")
ATTACKER_P = Key("attacker-p256", "P-256")
DEEP = Key("deep", "Ed25519")

DIFC_LOG = registrar_log_name("difc")
URL_PLATFORM = "https://www.nomosprotocol.example/.well-known/nomos-exchange-log"
URL_DIFC = "https://difc.example/.well-known/nomos-registrar/difc"
URL_GOV = "https://gov.example/.well-known/nomos-registrar/gov"
URL_DEEP = "https://deep.example/.well-known/nomos-registrar/deep"


class Log:
    def __init__(self, name, signer):
        self.name, self.signer, self.entries = name, signer, []

    def append(self, kind, name, entry, at, version=None):
        prev = self.entries[-1]["hash"] if self.entries else "0" * 64
        body = {"seq": len(self.entries) + 1, "kind": kind, "name": name, "version": version, "seal_hash": None,
                "entry": entry, "at": at, "prev_hash": prev}
        body["hash"] = sha256_hex(jcs(body))
        self.entries.append(body)
        return self

    def rotate(self, new: Key, at, *, signer=None):
        seq = len(self.entries) + 1
        prev = self.entries[-1]["hash"] if self.entries else "0" * 64
        sig = (signer or self.signer).sign(rotation_payload(self.name, seq, prev, new.kid, new.pem))
        self.append("key", new.kid, {"public_key_pem": new.pem, "signature": sig}, at)
        self.signer = new
        return self

    def head(self, *, signer=None, log=None, signed_log=None, at=HEAD_AT, size=None, algorithm=None, kid=None, low_s=True, with_log=True):
        k = signer or self.signer
        size = len(self.entries) if size is None else size
        h = {"size": size, "hash": self.entries[size - 1]["hash"] if size else "0" * 64, "at": at}
        sig = k.sign(head_payload(h, signed_log or self.name), low_s=low_s)
        out = {**({"log": log or self.name} if with_log else {}), **h, "algorithm": algorithm or k.suite, "kid": kid or k.kid, "signature": sig}
        return out


def platform_log(recognitions=()):
    log = Log(PLATFORM_LOG, PLATFORM)
    log.append("listed", "uae-pdpl", {}, "2026-10-01T00:00:00.000Z", version="1.0")
    log.append("applies", "uae-pdpl", {"scope": "jurisdiction == \"AE\" and established_in != \"DIFC\"", "basis": "Federal Decree-Law No. 45 of 2021, Art. 2"}, "2026-10-02T00:00:00.000Z")
    for r in recognitions:
        log.append("recognizes", r["to"], r["entry"], r.get("at", "2026-11-01T00:00:00.000Z"))
    log.append("closed", "uae", {"scope": "always", "authorities": ["uae-pdpl"], "max_age_days": 90}, "2026-11-02T00:00:00.000Z")
    return log


def difc_log(signer=DIFC):
    log = Log(DIFC_LOG, signer)
    log.append("applies", "difc-dpl", {"scope": "always", "basis": "DIFC Law No. 5 of 2020, Art. 6"}, "2026-11-03T00:00:00.000Z")
    log.append("closed", "difc", {"scope": "always", "authorities": ["difc-dpl"], "max_age_days": 90}, "2026-11-03T00:00:00.000Z")
    return log


def delegation(to, key: Key, url, scope="established_in == \"DIFC\"", **extra):
    return {"to": to, "entry": {"scope": scope, "kid": key.kid, "public_key_pem": key.pem, "url": url, **extra}}


cases = []


def log_case(cid, why, log: Log, head, pinned: Key, expect, *, expected_log=None, previous=None, entries=None):
    c = {"id": cid, "kind": "log", "description": why, "log": expected_log or log.name, "pinned_key": pinned.pem,
         "now": NOW, "max_head_age_seconds": MAX_AGE, "entries": entries if entries is not None else log.entries, "head": head, "expect": expect}
    if previous:
        c["previous"] = previous
    cases.append(c)


# ── log ─────────────────────────────────────────────────────────────────────────────────────
pl = platform_log()
log_case("log-ed25519", "A genuine log under an Ed25519 key: chain from 64 zeros, head signed for this log's name.",
         pl, pl.head(), PLATFORM, {"ok": True, "kid": PLATFORM.kid})
dl = difc_log()
log_case("log-es256", "A genuine log under a P-256 key held in an HSM: the suite is ES256 because the key is P-256 (§2.1).",
         dl, dl.head(), DIFC, {"ok": True, "kid": DIFC.kid})
log_case("head-without-log-field", "A head that omits its `log` field still verifies: the log name is inside the signed payload.",
         dl, dl.head(with_log=False), DIFC, {"ok": True, "kid": DIFC.kid})
other = Log(registrar_log_name("qfc"), DIFC)
for e in difc_log().entries:
    other.entries.append(copy.deepcopy(e))
log_case("head-for-another-log", "A head the same key signed for another registrar's log (qfc), presented as the DIFC's: its `log` names the other log.",
         dl, other.head(), DIFC, {"ok": False, "reason": "wrong_log"})
log_case("head-replayed-across-logs", "The same replay with the `log` field stripped: the signature covers the other log's name, so it fails here.",
         dl, other.head(with_log=False), DIFC, {"ok": False, "reason": "bad_signature"})
log_case("algorithm-mismatch", "A P-256 key's head that names Ed25519: the key fixes the suite, never the head (§2.1).",
         dl, dl.head(algorithm="Ed25519"), DIFC, {"ok": False, "reason": "algorithm_mismatch"})
log_case("algorithm-webauthn", "A P-256 key's head that names WebAuthn-ES256, a weaker framing: refused, the key verifies ES256 only.",
         dl, dl.head(algorithm="WebAuthn-ES256"), DIFC, {"ok": False, "reason": "algorithm_mismatch"})
log_case("head-wrong-key", "A head signed by another key under its own kid: not the key the relying party pinned.",
         dl, dl.head(signer=ATTACKER_P), DIFC, {"ok": False, "reason": "wrong_key"})
log_case("head-bad-signature", "A head naming the pinned kid, signed by another key.",
         dl, dl.head(signer=ATTACKER_P, kid=DIFC.kid), DIFC, {"ok": False, "reason": "bad_signature"})
log_case("head-high-s", "An ES256 head signature with a high S value: SPEC-010 refuses it.",
         dl, dl.head(low_s=False), DIFC, {"ok": False, "reason": "bad_signature"})

rot = difc_log()
rot.rotate(DIFC_NEXT, "2026-11-10T00:00:00.000Z")
rot.append("applies", "difc-employment", {"scope": "always"}, "2026-11-11T00:00:00.000Z")
log_case("rotation", "The DIFC rotates from its P-256 key to an Ed25519 key with a `key` entry its old key signed; a relying party pinned to the old key follows it (§2.2).",
         rot, rot.head(), DIFC, {"ok": True, "kid": DIFC_NEXT.kid})
log_case("rotation-pinned-new-key", "A relying party that pins the new key: the walk starts after the entry that introduced it.",
         rot, rot.head(), DIFC_NEXT, {"ok": True, "kid": DIFC_NEXT.kid})
log_case("rotation-head-old-key", "After a rotation, a head still signed by the old key: the key in force is the new one.",
         rot, rot.head(signer=DIFC), DIFC, {"ok": False, "reason": "wrong_key"})
forged = difc_log()
forged.rotate(ATTACKER, "2026-11-10T00:00:00.000Z", signer=ATTACKER)
log_case("rotation-forged", "A `key` entry the key in force did not sign, appended to hand the log to an attacker's key, with a head the attacker signed: the whole log is refused.",
         forged, forged.head(), DIFC, {"ok": False, "reason": "rotation_invalid"})

log_case("history-rewritten", "A head kept from an earlier read that this copy of the log does not contain: history was rewritten.",
         dl, dl.head(), DIFC, {"ok": False, "reason": "history_rewritten"}, previous={"size": 1, "hash": "f" * 64})
log_case("history-extended", "A head kept from an earlier read, extended by today's log.",
         dl, dl.head(), DIFC, {"ok": True, "kid": DIFC.kid}, previous={"size": 1, "hash": dl.entries[0]["hash"]})
log_case("head-stale", "A head signed an hour before now, past the relying party's 600 s bound.",
         dl, dl.head(at="2026-11-12T23:00:00.000Z"), DIFC, {"ok": False, "reason": "head_stale"})
tampered = copy.deepcopy(dl.entries)
tampered[0]["entry"]["scope"] = "jurisdiction == \"QA\""
log_case("chain-broken", "An entry altered after it was chained: its hash no longer matches its contents.",
         dl, dl.head(), DIFC, {"ok": False, "reason": "chain_broken"}, entries=tampered)
log_case("head-beyond-chain", "A head naming more entries than the copy holds.",
         dl, {**dl.head(), "size": 9}, DIFC, {"ok": False, "reason": "head_mismatch"})

# ── network ─────────────────────────────────────────────────────────────────────────────────
PINS = [{"id": "platform", "url": URL_PLATFORM, "public_key_pem": PLATFORM.pem, "certified_scope": "always", "log": PLATFORM_LOG}]


def net_case(cid, why, pins, logs, query, expect_registrars, expect_absent, expect_result, **extra):
    served = {url: {"entries": lg.entries, "head": hd} for url, (lg, hd) in logs.items()}
    cases.append({"id": cid, "kind": "network", "description": why, "now": NOW, "max_head_age_seconds": MAX_AGE, **extra,
                  "pins": pins, "logs": served, "query": query,
                  "expect": {"registrars": expect_registrars, "absent": expect_absent, "result": expect_result}})


p1 = platform_log([delegation("difc", DIFC, URL_DIFC)])
d1 = difc_log()
net_case("network-delegation", "The pinned platform registrar recognizes the DIFC's own registrar for acts by DIFC establishments, naming its P-256 key and log. The DIFC's log is fetched, verified under that key and folded as a delegate; on a DIFC act its law is resolved.",
         PINS, {URL_PLATFORM: (p1, p1.head()), URL_DIFC: (d1, d1.head())},
         {"context": {"jurisdiction": "AE", "established_in": "DIFC"}, "at": NOW},
         {"platform": {"delegated": False}, "difc": {"delegated": True}}, {}, {"status": "RESOLVED", "authorities": ["difc-dpl"]})
net_case("network-delegation-not-walked", "The same world on an act in the UAE by a mainland firm: the edge is FALSE, the DIFC's law is not walked, and the UAE's law is resolved.",
         PINS, {URL_PLATFORM: (p1, p1.head()), URL_DIFC: (d1, d1.head())},
         {"context": {"jurisdiction": "AE", "established_in": "AE"}, "at": NOW},
         {"platform": {"delegated": False}, "difc": {"delegated": True}}, {}, {"status": "RESOLVED", "authorities": ["uae-pdpl"]})
net_case("network-delegate-key-substituted", "The DIFC's log is served with a head an attacker signed under its own key: not the key the recognizing entry named. The delegate is left out, and a DIFC act is INCOMPLETE naming it, never resolved without its law.",
         PINS, {URL_PLATFORM: (p1, p1.head()), URL_DIFC: (d1, d1.head(signer=ATTACKER_P))},
         {"context": {"jurisdiction": "AE", "established_in": "DIFC"}, "at": NOW},
         {"platform": {"delegated": False}}, {"difc": "wrong_key"}, {"status": "INCOMPLETE", "unreachable_registrars": ["difc"]})
net_case("network-delegate-unreachable", "The DIFC's log cannot be fetched. A DIFC act is INCOMPLETE naming the DIFC registrar; an act it does not reach is unaffected.",
         PINS, {URL_PLATFORM: (p1, p1.head())},
         {"context": {"jurisdiction": "AE", "established_in": "DIFC"}, "at": NOW},
         {"platform": {"delegated": False}}, {"difc": "unreachable"}, {"status": "INCOMPLETE", "unreachable_registrars": ["difc"]})
gov = Log(registrar_log_name("gov"), GOV)
gov.append("recognizes", "difc", delegation("difc", ATTACKER_P, URL_DIFC)["entry"], "2026-11-01T00:00:00.000Z")
gov.append("closed", "gov", {"scope": "always", "authorities": []}, "2026-11-02T00:00:00.000Z")
net_case("network-key-disagreement", "Two pinned registrars recognize the same delegate under different keys. The resolver does not choose: the delegate is left out, and a DIFC act is INCOMPLETE.",
         PINS + [{"id": "gov", "url": URL_GOV, "public_key_pem": GOV.pem, "certified_scope": "always"}],
         {URL_PLATFORM: (p1, p1.head()), URL_GOV: (gov, gov.head()), URL_DIFC: (d1, d1.head())},
         {"context": {"jurisdiction": "AE", "established_in": "DIFC"}, "at": NOW},
         {"platform": {"delegated": False}, "gov": {"delegated": False}}, {"difc": "key_disagreement"}, {"status": "INCOMPLETE", "unreachable_registrars": ["difc"]})
d2 = difc_log()
d2.rotate(DIFC_NEXT, "2026-11-10T00:00:00.000Z")
net_case("network-delegate-rotated", "The DIFC rotated its key after it was recognized. The recognizing entry still names the old key; the rotation, signed by that key, is followed.",
         PINS, {URL_PLATFORM: (p1, p1.head()), URL_DIFC: (d2, d2.head())},
         {"context": {"jurisdiction": "AE", "established_in": "DIFC"}, "at": NOW},
         {"platform": {"delegated": False}, "difc": {"delegated": True}}, {}, {"status": "RESOLVED", "authorities": ["difc-dpl"]})
d3 = difc_log()
d3.append("recognizes", "deep", delegation("deep", DEEP, URL_DEEP, scope="always")["entry"], "2026-11-04T00:00:00.000Z")
deep = Log(registrar_log_name("deep"), DEEP)
deep.append("applies", "deep-law", {"scope": "always"}, "2026-11-04T00:00:00.000Z")
deep.append("closed", "deep", {"scope": "always", "authorities": ["deep-law"]}, "2026-11-04T00:00:00.000Z")
net_case("network-beyond-hops", "With a bound of one recognition hop, a registrar two hops from the pin is not read: it is beyond bounds, and a resolution that walks to it is INCOMPLETE naming it.",
         PINS, {URL_PLATFORM: (p1, p1.head()), URL_DIFC: (d3, d3.head()), URL_DEEP: (deep, deep.head())},
         {"context": {"jurisdiction": "AE", "established_in": "DIFC"}, "at": NOW},
         {"platform": {"delegated": False}, "difc": {"delegated": True}}, {"deep": "beyond_bounds"}, {"status": "INCOMPLETE", "unreachable_registrars": ["deep"]},
         max_hops=1)
p2 = platform_log([delegation("difc", DIFC, URL_DIFC)])
p2.append("withdrawn", "difc", {}, "2026-11-08T00:00:00.000Z")
net_case("network-recognition-withdrawn", "The platform registrar withdrew its recognition of the DIFC registrar. The delegate is not fetched and not walked, and on a DIFC act the platform's own law does not apply: RESOLVED with no law, under the platform's closure. This is why a registrar hands law over by recognizing first and withdrawing its own claim after, never the reverse.",
         PINS, {URL_PLATFORM: (p2, p2.head()), URL_DIFC: (d1, d1.head())},
         {"context": {"jurisdiction": "AE", "established_in": "DIFC"}, "at": NOW},
         {"platform": {"delegated": False}}, {}, {"status": "RESOLVED", "authorities": []})

# ── discovery ───────────────────────────────────────────────────────────────────────────────


def disc(cid, why, records, rid, kid, expect):
    cases.append({"id": cid, "kind": "discovery", "description": why, "records": records, "registrar": rid, "kid": kid, "expect": expect})


GOOD = f"v=nomos1; id=difc; url={URL_DIFC}; kid={DIFC.kid}"
disc("dns-found", "The record names the registrar and the kid already held: its URL is where the log is read.", [GOOD], "difc", DIFC.kid, {"ok": True, "url": URL_DIFC})
disc("dns-among-other-records", "Unrelated TXT records at the same name are skipped.", ["google-site-verification=abc", GOOD], "difc", DIFC.kid, {"ok": True, "url": URL_DIFC})
disc("dns-key-substituted", "A spoofed record naming an attacker's kid: DNS never supplies a key, and a record that disagrees with the held kid refuses the registrar.",
     [f"v=nomos1; id=difc; url={URL_DIFC}; kid={ATTACKER_P.kid}"], "difc", DIFC.kid, {"ok": False, "reason": "discovery_mismatch"})
disc("dns-other-registrar", "A record for another registrar id.", [f"v=nomos1; id=qfc; url={URL_DIFC}; kid={DIFC.kid}"], "difc", DIFC.kid, {"ok": False, "reason": "discovery_mismatch"})
disc("dns-not-https", "A record pointing at plain http.", [f"v=nomos1; id=difc; url=http://difc.example/log; kid={DIFC.kid}"], "difc", DIFC.kid, {"ok": False, "reason": "discovery_mismatch"})
disc("dns-incomplete-record", "A record without a kid is not a record.", [f"v=nomos1; id=difc; url={URL_DIFC}"], "difc", DIFC.kid, {"ok": False, "reason": "unreachable"})
disc("dns-wrong-version", "A record of another version is not a record.", [f"v=nomos2; id=difc; url={URL_DIFC}; kid={DIFC.kid}"], "difc", DIFC.kid, {"ok": False, "reason": "unreachable"})

out = {
    "spec": "NOMOS-SPEC-014",
    "version": "0.4.0",
    "note": "Registrar-log vectors (§2). `log` cases verify one copy of a log under a pinned key; `network` cases assemble the world from pins and the delegations their logs name, then resolve; `discovery` cases read `_nomos-registrar` TXT records. Every expect is written from the specification text. Generated by generate_registrar_logs.py, byte-identical on every run.",
    "keys": {name: {"kid": k.kid, "suite": k.suite, "public_key_pem": k.pem} for name, k in
             [("platform", PLATFORM), ("difc", DIFC), ("difc-next", DIFC_NEXT), ("government", GOV), ("attacker", ATTACKER), ("attacker-p256", ATTACKER_P), ("deep", DEEP)]},
    "cases": cases,
}
print(json.dumps(out, indent=1, ensure_ascii=False))
