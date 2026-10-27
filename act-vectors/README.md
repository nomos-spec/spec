# NOMOS-SPEC-008 reference implementation and test vectors

`act_verify.py` verifies an Act at the relying party (NOMOS-SPEC-008 0.6.0): audience, window and replay; the rule
issuer's chain (NOMOS-SPEC-007 rev. 1.9 target-first, scope-aware resolution, shared in `../python/nomosprotocol`); every testimony statement
against its witness's `claim` scope; every fact against the channel and type its input declares; the sealed
rules over exactly those facts; and, for escalations, consents signed over this Act's binding
digest by distinct *people* (approvers) holding the required role, signed Ed25519, ES256 or by passkey. Rules are evaluated three-valued: a missing fact is
undecided, never false, and nothing commits while a rule that could stop the action is undecided (§6.2);
`exists()` reads absence as FALSE only for action and relying-party inputs. The artifact must be the
version in force at verification time (§5.4), from the relying party's own record or an issuer-signed
in-force statement as the relying party's declared currency policy allows (`record` or
`record_or_statement`), and not revoked. An authority with equal-priority escalations naming different
escalations is refused (`ambiguous_escalation`).

```
pip install cryptography
python3 generate.py pub_lending_v1.nomos > vectors.json   # deterministic, byte-identical
python3 check.py vectors.json
45 passed, 0 failed     # 43 vectors, plus NaN and Infinity built in memory
```

`pub_lending_v1.nomos` is the generator's input: the public Consumer Loan Approval policy, which `generate.py`
re-seals with declared fact sources and an explicit allow rule. `generate.py` derives every key from a published seed. **These private keys are public on
purpose. Never use them as trust material.**

## Cases

| Case | Verdict | What it shows |
|---|---|---|
| authorized_by_rule | AUTHORIZED | Facts from action, witness and ledger; R0 permits |
| denied_by_rule | DENIED | Bureau testifies DTI 58%; R3 denies |
| agent_asserts_a_testimony_fact | FACT_SOURCE_VIOLATION | The agent's own DTI is refused, not evaluated |
| rule_issuer_cannot_testify | TESTIMONY_OUT_OF_SCOPE | The key that wrote the rules cannot state facts |
| witness_beyond_its_scope | TESTIMONY_OUT_OF_SCOPE | A credit bureau cannot attest employment |
| escalated_no_consent | ESCALATED (0 of 2) | Dual approval required |
| escalated_one_of_two | ESCALATED (1 of 2) | One approver is not enough |
| same_approver_twice_counts_once | ESCALATED (1 of 2) | Dual control means two people |
| authorized_by_dual_consent | AUTHORIZED | Both approvers signed this exact Act |
| action_altered_after_consent | CONSENT_INVALID | Approvals do not survive a changed amount |
| approver_claims_a_role_it_lacks | CONSENT_OUT_OF_SCOPE | A reviewer cannot sign as senior approver |
| no_rule_matches_default_deny | DENIED | Unmatched requests are refused |
| expired | EXPIRED | Five-minute window |
| wrong_relying_party | WRONG_RELYING_PARTY | An Act works on one system only |
| replayed | REPLAYED | Single use |
| stale_testimony | TESTIMONY_INVALID | Expired attestation |
| testimony_about_someone_else | TESTIMONY_INVALID | Genuine fact, wrong applicant |
| rules_from_uncertified_issuer | ISSUER_NOT_RECOGNIZED | Unchanged SPEC-007 behavior |
| tree_pool_presented_in_reverse | AUTHORIZED | Order independence for tree-shaped certificate sets |
| omitted_fact_withholds_authorization | INCOMPLETE | Leaving out the bankruptcy statement leaves R1 undecided; nothing commits |
| omitted_fact_cannot_be_consented_away | INCOMPLETE | Two valid consents cannot stand in for a withheld DTI statement |
| action_param_wrong_type | FACT_TYPE_VIOLATION | An amount sent as a string is refused before any rule reads it |
| omitted_fact_exists_undecided | INCOMPLETE | `exists(fraud_alert)` on a withheld witness statement is undecided, not false |
| nested_param_wrong_type_undecided | INCOMPLETE | `terms.months > 360` on the string "480" inside an object parameter is undecided, not false |
| superseded_version_presented | SUPERSEDED | Genuine, unrevoked, but not the version in force: valid for audit, not for a new action |
| revoked_authority | ARTIFACT_REVOKED | Every key still valid; the rules themselves withdrawn |
| in_force_statement_accepted | AUTHORIZED | No relying-party record; the issuer's signed in-force statement establishes currency |
| in_force_statement_stale | VERSION_UNVERIFIED | Monday's statement says nothing about Wednesday |
| no_in_force_evidence | VERSION_UNVERIFIED | Genuine rules of unknown currency cannot authorize |
| equal_priority_escalation_refused | MALFORMED | Two equal-priority escalations naming different escalations: which governs would depend on listing order (0.5.0 returned INCOMPLETE) |
| two_keys_of_one_person_count_once | ESCALATED (1 of 2) | A second device of the same approver is not a second approver |
| two_people_count_twice | AUTHORIZED | An ES256 key and an Ed25519 key of two different people |
| consent_key_without_approver | CONSENT_OUT_OF_SCOPE | A consent key not tied to a person cannot be counted |
| approver_depends_on_the_path | CONSENT_INVALID | One key certified as two people: the presenter would choose who it counts for |
| passkey_consent_authorizes | AUTHORIZED | A passkey approval whose challenge commits to this exact Act |
| passkey_user_not_verified | CONSENT_INVALID | A touch is not an approval |
| passkey_challenge_for_another_role | CONSENT_INVALID | A genuine assertion made for a different consent |
| passkey_registration_is_not_approval | CONSENT_INVALID | `webauthn.create` is not `webauthn.get` |
| es256_witness | AUTHORIZED | A witness signing from a KMS-held P-256 key |
| passkey_cannot_testify | TESTIMONY_OUT_OF_SCOPE | A passkey approves and does nothing else |
| record_only_refuses_a_statement | VERSION_UNVERIFIED | Under `record`, an issuer's in-force statement is never read |
| record_only_with_a_record | AUTHORIZED | Under `record`, the relying party's own record establishes currency |
| two_field_rule_names_only_the_absent_fact | INCOMPLETE | `amount > approved_limit` with only `approved_limit` missing names `approved_limit`, not `amount` |

`mutants.py` derives 1,693 mutants of the 43 vectors and records the reference verdict for each, in
`mutants.json`. Each mutant is one small change an attacker or a faulty presenter could make:
- a dropped, tampered or relabelled statement;
- a dropped or duplicated consent;
- a removed or widened certificate;
- a reversed certificate pool;
- a changed parameter;
- tampered rules or a relabelled seal;
- a re-addressed Act, or the presenter asserting a fact;
- either currency policy.

A second implementation re-derives them from the recipe and must reproduce every verdict field for
field.

All 43 cases pass in `act_verify.py` here and in `@nomosprotocol/verify`, the TypeScript verifier the
NOMOS platform and SDK use, and the two agree on every field of all 1,693 mutants. Both are by the authors. Second-party implementations are invited — run `check.py`'s cases against
yours and open an issue with the result.
