#!/usr/bin/env python3
"""Check the NOMOS-SPEC-010 reference verifier against the published vectors.

    python3 check.py vectors.json
"""
import base64
import json
import sys

import nomos_suites as S

vectors = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "vectors.json"))
passed = failed = 0
for c in vectors["cases"]:
    ok, reason = S.verify(c["suite"], c["public_key_pem"], base64.b64decode(c["payload_b64"]), c["proof"])
    exp = c["expected"]
    if ok == exp["ok"] and reason == exp["reason"]:
        passed += 1
        print(f"  ok    {c['name']}")
    else:
        failed += 1
        print(f"  FAIL  {c['name']}: got ok={ok} reason={reason}, expected {exp}")
print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
