"""RFC 8785 JSON Canonicalization Scheme, sufficient for NOMOS objects (JSON-native types).

A non-finite number has no canonical form: canonicalizing one raises ValueError, and a caller
treats that object as malformed rather than signing or hashing some other encoding of it.
"""
import hashlib
import json
from typing import Any


def _es_number(v: float) -> str:
    """ECMAScript Number::toString (RFC 8785 §3.2.2.3), from Python's shortest round-trip digits."""
    if v == 0: return "0"
    if v < 0: return "-" + _es_number(-v)
    mant, _, exp = repr(v).partition("e")
    whole, _, frac = mant.partition(".")
    digits = (whole + frac).lstrip("0")
    n = len(whole.lstrip("0")) + int(exp or 0) if whole.lstrip("0") else int(exp or 0) - (len(frac) - len(frac.lstrip("0")))
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21: return digits + "0" * (n - k)
    if 0 < n <= 21: return digits[:n] + "." + digits[n:]
    if -6 < n <= 0: return "0." + "0" * (-n) + digits
    e = n - 1
    return (digits[0] + ("." + digits[1:] if k > 1 else "")) + "e" + ("+" if e >= 0 else "-") + str(abs(e))


def _jcs(v: Any) -> str:
    if v is None: return "null"
    if v is True: return "true"
    if v is False: return "false"
    if isinstance(v, int): return str(v)
    if isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")): raise ValueError("non-finite number")
        return _es_number(v)
    if isinstance(v, str): return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list): return "[" + ",".join(_jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        ks = sorted(v, key=lambda k: k.encode("utf-16-be"))      # JCS sorts by UTF-16 code units
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _jcs(v[k]) for k in ks) + "}"
    raise TypeError(type(v))


def jcs_text(o: Any) -> str: return _jcs(o)
def jcs(o: Any) -> bytes: return _jcs(o).encode("utf-8")
def sha256_hex(b: bytes) -> str: return hashlib.sha256(b).hexdigest()
