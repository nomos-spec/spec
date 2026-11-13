"""nomosprotocol: NOMOS for Python.

The reference implementation of the NOMOS specifications and the developer layer on top of it.
The verifiers here are the same code the specification's published vectors are generated and
checked with, so there is no second implementation to drift from the reference.

    verify_act(act, ...)              NOMOS-SPEC-008 0.6.0: may this exact change be committed here?
    chain.resolve(...)                NOMOS-SPEC-007 rev. 1.11: resolve a key to a pinned root, for a purpose
    chain.verify_revocation_list(...) NOMOS-SPEC-007 rev. 1.10: which revocations count, and since when
    accept(...)                       be the relying party: verify, commit exactly once, receipt (NOMOS-SPEC-009)
    act(...)                          be the carrier: discover, gather testimony, submit, get approval
    witness(...)                      be a witness: sign one fact about one subject on request
    issuer(...)                       publish authorities, the version in force, certificates and revocations
    local_signer, generate_signer     keys in this process (development); pass your own Signer for a KMS

Modules: jcs (RFC 8785), suites (NOMOS-SPEC-010), chain (NOMOS-SPEC-007), act (NOMOS-SPEC-008),
statements, accept, carrier, witness, issuer, bindings (NOMOS-SPEC-011 tool bindings: parse, apply, digest),
registrar (NOMOS-SPEC-014 0.4.0 registrar logs: verify, fold, DNS discovery, world assembly).
"""
from .act import verify_act, evaluate, binding_digest
from .chain import resolve, verify_revocation_list, fingerprint
from .jcs import jcs, sha256_hex
from .statements import (
    Signer, LocalSigner, local_signer, generate_signer, seeded_signer,
    certify, seal, sign_testimony, sign_consent, sign_in_force, sign_revocation, sign_revocation_list,
    build_act, presented_certificates, relied_kids, MAX_PRESENTED,
)
from .accept import accept, RelyingParty, MemoryStore, postgres_store, RevocationUnavailable, status_for, ACT_MEDIA_TYPE
from .carrier import act, NomosActError, fetch_document
from .witness import witness, Witness
from .issuer import issuer, Issuer
from . import registrar
from .registrar import verify_registrar_log, fold_registrar_log, load_registrar_world, discover as discover_registrar_log

__version__ = "0.2.0"
SPECIFICATIONS = {
    "NOMOS-SPEC-001": "2.2.0 + amendment 2.3.0", "NOMOS-SPEC-007": "rev. 1.11.0", "NOMOS-SPEC-008": "0.6.0",
    "NOMOS-SPEC-009": "0.2.0", "NOMOS-SPEC-010": "0.2.0", "NOMOS-SPEC-014": "0.4.0 (registrar logs)",
}
