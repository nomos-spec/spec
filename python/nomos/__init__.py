"""The NOMOS reference implementation in Python, shared by every reference verifier in this
repository so that canonicalization, signature suites and chain resolution exist exactly once.

    jcs     RFC 8785 canonical JSON (NOMOS-SPEC-001 §8.1)
    suites  signature suites (NOMOS-SPEC-010)
    chain   chain-of-trust resolution (NOMOS-SPEC-007 rev. 1.9) and revocation sources (rev. 1.10)
"""
