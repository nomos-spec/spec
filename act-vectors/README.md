# NOMOS-SPEC-008 reference implementation and test vectors

`act_verify.py` verifies an Act at the relying party: audience, window and replay; the rule
issuer's chain (NOMOS-SPEC-007 rev. 1.8 target-first resolution); every testimony statement
against its witness's `claim` scope; every fact against the channel and type its input declares; the sealed
rules over exactly those facts; and, for escalations, consents signed over this Act's binding
digest by distinct keys holding the required role. Rules are evaluated three-valued: a missing fact is
undecided, never false, and nothing commits while a rule that could stop the action is undecided (§6.2);
`exists()` reads absence as FALSE only for action and relying-party inputs.

```
pip install cryptography
python3 generate.py pub_lending_v1.nomos > vectors.json   # deterministic, byte-identical
python3 check.py vectors.json
26 passed, 0 failed     # 24 vectors, plus NaN and Infinity built in memory
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
| same_approver_twice_counts_once | ESCALATED (1 of 2) | Dual control means two keys |
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

Two implementations pass all 24 cases: `act_verify.py` here, and the TypeScript verifier in the
hosted NOMOS platform. Second-party implementations are invited — run `check.py`'s cases against
yours and open an issue with the result.
