#!/usr/bin/env python3
"""Check the Python reference against the rev. 1.10 revocation-source vectors.
    python3 chain-of-trust-vectors/python/check_revocations.py chain-of-trust-vectors/revocation-vectors-1.10.json
"""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "python"))
from nomosprotocol.chain import verify_revocation_list, ts  # noqa: E402

vectors = json.load(open(sys.argv[1]))["cases"]
passed = failed = 0
for v in vectors:
    got = verify_revocation_list(v["list"], v["root_public_key_pem"], ts(v["now"]), v["own_certs"])
    if got == v["expected"]:
        passed += 1; print(f"  ok    {v['name']}")
    else:
        failed += 1; print(f"  FAIL  {v['name']}\n        expected {json.dumps(v['expected'])}\n        got      {json.dumps(got)}")
print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
