# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| NOMOS-SPEC-001 (1.x) | Yes |

## Reporting a Vulnerability

If you discover a security issue in the NOMOS Protocol specification, a reference
verifier implementation, or an example artifact, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

### How to report

Email: **allan@nomosprotocol.com**

Include in your report:
- A description of the vulnerability
- Which file(s) or section(s) of the spec are affected
- A proof-of-concept or reproduction steps if applicable
- Your assessment of severity and impact

### Response timeline

| Stage | Target |
|-------|--------|
| Acknowledgement | 48 hours |
| Initial assessment | 5 business days |
| Fix or mitigation | 30 days for critical; 90 days for others |
| Public disclosure | Coordinated with reporter |

We follow [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure).
We will credit reporters in the release notes unless anonymity is requested.

## Scope

In scope:
- Cryptographic seal weaknesses in NOMOS-SPEC-001 §8
- Hash chain vulnerabilities in the audit trail spec (§7)
- Incorrect or bypassable conformance requirements (§9)
- Bugs in `verify/verify.py` or `verify/verify.ts` that would cause a tampered
  artifact to pass verification

Out of scope:
- Vulnerabilities in third-party NOMOS runtime implementations (report to their maintainers)
- Issues with the nomosprotocol.com hosted service (use the contact form at nomosprotocol.com/contact)
- General cryptography questions

## Key management

The `SEAL_KEY` used to sign `.nomos` artifacts is held by the organisation that
sealed them. The NOMOS Protocol Working Group does not hold or manage seal keys
for third-party artifacts. If you believe a seal key has been compromised, the
affected organisation must re-issue and re-seal all artifacts under a new key.

See NOMOS-SPEC-001 §8.2 and §10 for key management requirements.
