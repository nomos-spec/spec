# NOMOS Protocol — Open Specification

[![Validate](https://github.com/nomos-spec/spec/actions/workflows/validate.yml/badge.svg)](https://github.com/nomos-spec/spec/actions/workflows/validate.yml)
[![Specifications: 15](https://img.shields.io/badge/specifications-15-blue)](spec/)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)
[![IANA Media Type](https://img.shields.io/badge/IANA-application%2Fvnd.nomos%2Bjson-brightgreen)](https://www.iana.org/assignments/media-types/application/vnd.nomos+json)

The **NOMOS Protocol** is an open, vendor-neutral specification for **Computable Authority**: making an institution's authority over an action something any system can check, before the action takes effect. Its principle: **authorize the act, not the agent**.

Policy-as-code makes rules executable by whoever runs the engine. Computable Authority makes the authorization itself checkable: the system where an action would take effect can establish — without trusting the agent, the model, or the vendor — that this exact action is authorized under the institution's rules.

An institution's rules travel as a `.nomos` artifact: a JSON document holding the rules, references to the source text they came from, and a cryptographic seal (Ed25519 by default). The seal is checkable offline with the publisher's public key alone — no server call, no shared secret — and it proves exactly one thing: this artifact, unmodified, from this key. Who that key belongs to is a separate question, answered by a chain of certificates to a root the verifier pins ([SPEC-007](spec/NOMOS-SPEC-007.md)). Whether the institution itself — by its own constitution, not just a keyholder — decided the sealing is a third, answered by an issuance proof ([SPEC-015](spec/NOMOS-SPEC-015.md)). The protocol keeps these apart, because collapsing them is how key custody quietly becomes institutional authority. Any compliant runtime can load a `.nomos` artifact and evaluate decisions against it — deterministically, without calling an AI model at runtime.

Agents increasingly act on behalf of organisations — a bank, a hospital, a ministry, a supplier. A service an agent calls needs more than "this is an agent": it needs to know who the agent acts for, what is allowed, and how to check that without calling anyone. The fifteen specifications cover it in five layers:

| Layer | Specs | What it answers |
|-------|-------|-----------------|
| **Authority** | [001](spec/NOMOS-SPEC-001.md)–[006](spec/NOMOS-SPEC-006.md) | The institution's rules as a sealed artifact: evaluated deterministically, composed, time-bounded, queried publicly, revoked |
| **Recognition** | [007](spec/NOMOS-SPEC-007.md) | A stranger recognizes the issuer — offline, through key certificates, against a root the verifier pins |
| **The Act** | [008](spec/NOMOS-SPEC-008.md)–[010](spec/NOMOS-SPEC-010.md) | One exact action bound to sealed rules, signed facts from authorized witnesses and human consents, so the system that would make the change verifies locally and commits exactly that change or nothing; how an agent finds that system and hands it the Act; the signature suites every verifier accepts |
| **Enforcement** | [011](spec/NOMOS-SPEC-011.md)–[012](spec/NOMOS-SPEC-012.md) | Where Acts aren't verifiable yet: which tool argument is which fact the policy reads, and what a gateway or an agent's pre-tool hook must do, from failing closed to approvals bound to one exact call |
| **The public square** | [013](spec/NOMOS-SPEC-013.md)–[015](spec/NOMOS-SPEC-015.md) | A registry of authorities that publishes what it offers so nobody has to trust it; resolution — *which* authorities govern this act, completely, from registrar logs the carrier cannot influence; issuance proofs — did the institution *decide* this sealing, not just sign it |

Each specification states its own status. Five are Active; the rest are Drafts, and a Draft leaves Draft only when a second, **independent** implementation passes its published vectors — two such implementations are invited now ([#32](https://github.com/nomos-spec/spec/issues/32), [#33](https://github.com/nomos-spec/spec/issues/33)).

The research behind the discipline is at **[computableauthority.com](https://computableauthority.com)**.

**Contents:** [Specifications](#specifications) · [Start here](#start-here) · [Try it in a minute](#try-it-in-a-minute) · [Why](#why) · [Implementations](#implementations) · [Conformance](#conformance) · [Repository map](#repository-map) · [How the specifications change](#how-the-specifications-change) · [Citing](#citing) · [Links](#links)

---

## Specifications

Every specification is in [`spec/`](spec/), whatever its status. Each file states its own status, version and date.

| Spec | Title | Status | Version | Checked by |
|------|-------|--------|---------|------------|
| [001](spec/NOMOS-SPEC-001.md) | Governance Artifact Protocol: rules, sealing, execution, conflict resolution | Active | 2.1.0 | [`conformance/`](conformance/) (23 checks), [`examples/`](examples/) |
| [002](spec/NOMOS-SPEC-002.md) | Multi-Agent Governance Extension: agents manifest, guard phases, constraints DSL | Active | 1.2.0 | |
| [003](spec/NOMOS-SPEC-003.md) | Temporal Validity and Staleness Signalling, deterministic replay | Active | 1.3.1 | |
| [004](spec/NOMOS-SPEC-004.md) | Composable Artifacts (`extends`) and Third-Party Attestations | Active | 1.4.0 | |
| [005](spec/NOMOS-SPEC-005.md) | Public Query Extension: keyless queries, permanent transcripts, signed statements | Draft | 1.6.0 | [`query-statement-vectors/`](query-statement-vectors/) (7) |
| [006](spec/NOMOS-SPEC-006.md) | Artifact Revocation: detached issuer-signed statements, signed revocation list, `max_age` | Active | 1.6.0 | |
| [007](spec/NOMOS-SPEC-007.md) | Chain-of-Trust Key Certificates: recognizing an issuer with no prior relationship and no call home | Draft | 1.7.0 | [`chain-of-trust-vectors/`](chain-of-trust-vectors/) (14 + 41 + 22, 349 mutants) |
| [008](spec/NOMOS-SPEC-008.md) | Act Binding: one exact action bound to sealed rules, signed testimony and human consents | Draft | 0.7.0 | [`act-vectors/`](act-vectors/) (46, 1,804 mutants) |
| [009](spec/NOMOS-SPEC-009.md) | Discovery and Submission: well-known documents, the HTTP binding, certificate presentation | Draft | 0.2.0 | [`submission-vectors/`](submission-vectors/) (17 HTTP checks, 7 selection cases) |
| [010](spec/NOMOS-SPEC-010.md) | Signature Suites: `Ed25519`, `ES256`, `WebAuthn-ES256`; canonical keys | Draft | 0.2.0 | [`suite-vectors/`](suite-vectors/) (30) |
| [011](spec/NOMOS-SPEC-011.md) | Tool Bindings: which tool argument is which fact a policy reads | Draft | 0.1.0 | [`binding-vectors/`](binding-vectors/) (31 parse cases, 19 calls) |
| [012](spec/NOMOS-SPEC-012.md) | Enforcement Points: what a gateway or agent hook must do before a tool call runs | Draft | 0.1.0 | |
| [013](spec/NOMOS-SPEC-013.md) | Authority Registries: a signed catalogue and a hash-chained public log | Draft | 0.1.0 | |
| [014](spec/NOMOS-SPEC-014.md) | Resolution: which authorities govern an act, completely, from registrar logs the carrier cannot influence | Draft | 0.3.0 | [`resolution-vectors/`](resolution-vectors/) |
| [015](spec/NOMOS-SPEC-015.md) | Issuance Proofs: did the institution, by its own constitution, decide this sealing | Draft | 0.2.0 | [`issuance-vectors/`](issuance-vectors/) |

Proposed amendments and revisions awaiting promotion are in [`spec/drafts/`](spec/drafts/):

| Draft | Amends | What it adds |
|-------|--------|--------------|
| [SPEC-001 amendment 2.2.0](spec/drafts/NOMOS-SPEC-001-amendment-2.2.0.md) | 001 | Unmatched outcome, declared fact sources, consent counts |
| [SPEC-001 amendment 2.3.0](spec/drafts/NOMOS-SPEC-001-amendment-2.3.0.md) | 001 | Equal-priority escalations naming different escalations cannot be sealed |
| [SPEC-001 amendment 2.4.0](spec/drafts/NOMOS-SPEC-001-amendment-2.4.0.md) | 001 | Comparisons between two fields |
| [SPEC-001 amendment 2.5.0](spec/drafts/NOMOS-SPEC-001-amendment-2.5.0.md) | 001 | Derived values: a law's classifications decide the rules that read them, by legal relation (overrides, closed definitions); three-valued `not` |
| [SPEC-007 rev. 1.8.0](spec/drafts/NOMOS-SPEC-007-rev-1.8.0.md) | 007 | Statement keys (witness `claim`, approver `consent` scopes) and target-first chain resolution |
| [SPEC-007 rev. 1.9.0](spec/drafts/NOMOS-SPEC-007-rev-1.9.0.md) | 007 | Scope-aware path selection, normative check order, `suite` and `approver` dimensions, ES256 |
| [SPEC-007 rev. 1.10.0](spec/drafts/NOMOS-SPEC-007-rev-1.10.0.md) | 007 | Revocation a relying party can check: ES256 and certificate revocations, statements count only from a parent the root reaches, self-checkable lists, fail closed on stale knowledge |
| [SPEC-007 rev. 1.11.0](spec/drafts/NOMOS-SPEC-007-rev-1.11.0.md) | 007 | Statement authority comes from the root: a sealing key cannot certify witnesses or approvers; ties in candidate order break on the signature |

Each draft names the specification it amends, and SPEC-008 names the ones it builds on in its header. The rendered specifications are also at [nomosprotocol.com/spec](https://nomosprotocol.com/spec).

---

## Start here

| You are | Read | Then run |
|---------|------|----------|
| **Building a verifier or a relying party** in any language | [`IMPLEMENTING.md`](IMPLEMENTING.md): the order to build in and the rules that are easiest to get wrong | The vector files for each step, then [`submission-vectors/run.mjs`](submission-vectors/) against your relying party |
| **Building agents, or a service agents call** | [SPEC-008](spec/NOMOS-SPEC-008.md) §1–2, then [SPEC-009](spec/NOMOS-SPEC-009.md) | `npx @nomosprotocol/cli dev`: a complete local relying party, issuer, witness and approver |
| **Putting a gateway or hook in front of tools** | [SPEC-011](spec/NOMOS-SPEC-011.md), [SPEC-012](spec/NOMOS-SPEC-012.md) | [`binding-vectors/`](binding-vectors/) |
| **Writing or publishing policy as a `.nomos` artifact** | [SPEC-001](spec/NOMOS-SPEC-001.md), then the [guided tour](docs/overview.md) | `npx tsx cli/nomos.ts validate <file>` |
| **Reviewing the design or the security argument** | [Computable Authority](https://computableauthority.com), [`papers/carried-authority/`](papers/carried-authority/) (ablation, model checks, a Lean proof of omission safety), [`SECURITY.md`](SECURITY.md) | `cd papers/carried-authority && python3 ablate.py vectors_040.json` |

---

## Try it in a minute

Nothing below needs an account, a key of yours or a call to our servers. Once installed, the checks run offline.

**Check a seal and evaluate a decision** with the reference CLI:

```bash
git clone https://github.com/nomos-spec/spec.git nomos-spec && cd nomos-spec
npm ci
npx tsx verify/verify.ts examples/lending_policy_v1.nomos --key deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
npx tsx cli/nomos.ts exec examples/lending_policy_v1.nomos \
  --input '{"patron_age": 18, "account_standing": "good", "item_type": "book"}'
```

The examples are sealed with a public test key so anyone can check them. Production artifacts are sealed with Ed25519 and verified with the publisher's public key alone (`--pubkey <pem>`, or `--url <host>` to fetch it from `/.well-known/nomos-signing-keys`).

**Verify Acts** with the Python reference — every published vector, with the verdict each must get:

```bash
pip install ./python
python3 act-vectors/check.py act-vectors/vectors.json   # 48 passed: 46 vectors + 2 non-finite cases
```

**Commit a change through an Act**, as an agent and as the system that makes the change:

```bash
npx @nomosprotocol/cli dev    # a shop, a purchasing policy, a finance witness and an approving manager, all with labelled test keys
```

```ts
import { act } from '@nomosprotocol/sdk';

const r = await act({
  to: 'http://localhost:4747',
  action: { type: 'purchase', subject: 'DEPT-17', params: { amount: 500, vendor: 'paperco' } },
});
console.log(r.status, r.summary);   // committed Committed by shop.local.
```

Try `amount: 2000` (the manager must approve), `amount: 9000` (over budget) or `vendor: 'shadyco'` (blocked). The [guided tour](docs/overview.md) walks through each specification with its fields and commands.

---

## Why

Institutions publish their rules as text. AI agents now act inside institutions' workflows: approving a permit, opening a record, making a payment. The system that carries out the action usually has no way to check that the exact action is authorized. The agent was prompted with the policy, and that cannot be audited. It also fails when the agent is wrong, manipulated or replaced.

NOMOS moves the check to where the action takes effect. The institution's rules are compiled into a sealed, versioned artifact that its own reviewers approve and its own key signs. The receiving system verifies, offline and without asking a model, three things: that the rules come from the right authority and are in force; that this exact action is permitted; and that the facts it depends on are signed by the systems designated to state them. The answer is AUTHORIZED, DENIED or ESCALATED to a named role, and the decision can be verified by anyone the issuer trusts.

A `.nomos` artifact now moves through four distinct moments:

**Compile-time**: A policy document is uploaded to NOMOS Studio. Rules are extracted and verified — optionally composed from a shared base artifact (SPEC-004). The result is sealed.

**Runtime**: Your system calls the NOMOS Runtime API (or runs the CLI locally). Rules are evaluated deterministically, respecting any temporal bounds (SPEC-003). Every verdict comes with an audit hash.

**Attest** *(optional, post-seal)*: An independent party — a regulator, an auditor — co-signs the exact sealed version with their own key (SPEC-004), without altering the artifact or its seal.

**Act** *(at the point of change)*: An agent presents an Act to the system that would make the change — a ledger, a registry, an API. That relying party verifies the issuer's chain (SPEC-007), the facts as signed testimony, any required consents, and the rules over exactly those facts (SPEC-008). A fact the Act does not establish is unknown, never false; nothing commits while an unknown fact could still change the outcome.

---

## Implementations

| Implementation | Language | Covers | Checked against |
|----------------|----------|--------|-----------------|
| [`python/nomosprotocol/`](python/) — [`nomosprotocol` on PyPI](https://pypi.org/project/nomosprotocol/) | Python | JCS, SPEC-010 suites, SPEC-007 chains and revocation sources, the SPEC-008 Act verifier, SPEC-011 bindings; `accept()`, `act()`, `witness()`, `issuer()` for SPEC-009 | Every vector file here; generates the mutant sets |
| [`prototype/chain-of-trust/`](prototype/chain-of-trust/) | TypeScript | SPEC-007 key certificates and chain verification, a CLI verifier, an HTTP receiver/presenter pair | SPEC-007 1.7.0 (14) and rev. 1.11 (41) vectors, SPEC-010 (30) |
| [`suite-vectors/check.mjs`](suite-vectors/) | JavaScript, Node built-ins only | SPEC-010 suites, written separately from the Python reference | SPEC-010 (30) |
| [`submission-vectors/reference-rp.mjs`](submission-vectors/) | JavaScript | A SPEC-009 relying party | `run.mjs` (17) |
| [`verify/`](verify/), [`cli/`](cli/) | TypeScript, Python | Seal verification (SPEC-001 §8, SPEC-006 revocations); validate, exec, diff, lint | [`examples/`](examples/), [`conformance/`](conformance/) |
| [`@nomosprotocol/verify`](https://www.npmjs.com/package/@nomosprotocol/verify) | TypeScript, any runtime | SPEC-007 to 010 verification | Every SPEC-007, 008 and 010 vector; agrees with the Python reference on all 1,804 SPEC-008 mutants and 349 revocation mutants |
| [`@nomosprotocol/sdk`](https://www.npmjs.com/package/@nomosprotocol/sdk), [`@nomosprotocol/cli`](https://www.npmjs.com/package/@nomosprotocol/cli) | TypeScript | `act()`, `accept()`, `issuer()`, `witness()`, `approver()`; `nomos dev` | SPEC-009 `run.mjs` (17) |
| [`nomos-guard`](https://www.npmjs.com/package/nomos-guard) | TypeScript | A SPEC-012 enforcement point for MCP servers and agent hooks, reading SPEC-011 bindings | |
| [`nomos-spec014-resolver`](https://github.com/SvvBot/nomos-spec014-resolver) | Python | Independent clean-room reference implementation of NOMOS-SPEC-014 Resolution | All 23 resolution vectors (exact `expect`), 8 necessity ablations, graph shuffle invariance, verified pinned SHA256 digest |

Every implementation listed is by the authors. SPEC-007 to 013 stay Drafts until an independent implementation reproduces their verdicts from the text; [`IMPLEMENTING.md`](IMPLEMENTING.md) is written for that. If you build one, open an issue or email allan@nomosprotocol.com, and it will be listed here.

---

## Conformance

The workflow in [`.github/workflows/validate.yml`](.github/workflows/validate.yml) runs on every pull request. It checks every published vector file with every implementation in this repository that claims it, requires every generator to reproduce its committed file byte for byte, runs the SPEC-009 runner against the reference relying party, and checks every relative link and heading anchor in the Markdown. To run the same checks locally:

```bash
npm ci && pip install jsonschema ./python
node scripts/check-links.mjs
npx tsx conformance/run.ts                                            # SPEC-001: 23 checks
node query-statement-vectors/check.mjs                                # SPEC-005: 7
python3 chain-of-trust-vectors/python/check_19.py chain-of-trust-vectors/vectors-1.11.json                   # SPEC-007: 41
python3 chain-of-trust-vectors/python/check_revocations.py chain-of-trust-vectors/revocation-vectors-1.10.json # SPEC-007: 22
python3 act-vectors/check.py act-vectors/vectors.json                 # SPEC-008: 48
python3 suite-vectors/check.py suite-vectors/vectors.json             # SPEC-010: 30
python3 binding-vectors/check.py binding-vectors/vectors.json         # SPEC-011: 50
(cd submission-vectors && npm install && node selection.mjs --check)  # SPEC-009: 7
```

---

## Repository map

| Path | What it holds |
|------|---------------|
| [`spec/`](spec/) | The thirteen specifications; [`spec/drafts/`](spec/drafts/) holds proposed amendments and revisions |
| [`schema/`](schema/) | JSON Schemas: the artifact and its rules, execution and public-query requests and responses, revocation statements and lists, key certificates and chain verification, SPEC-009 discovery documents, freshness staples |
| `*-vectors/` | Test vectors, each folder with its generator, its checker and a README saying what to compute: [`act-vectors/`](act-vectors/), [`binding-vectors/`](binding-vectors/), [`chain-of-trust-vectors/`](chain-of-trust-vectors/), [`query-statement-vectors/`](query-statement-vectors/), [`submission-vectors/`](submission-vectors/), [`suite-vectors/`](suite-vectors/) |
| [`conformance/`](conformance/) | SPEC-001 §9 runtime and producer requirements as runnable checks |
| [`python/`](python/), [`prototype/`](prototype/) | The Python reference and the SPEC-007 TypeScript prototype |
| [`cli/`](cli/), [`verify/`](verify/) | The reference CLI and seal verifiers |
| [`examples/`](examples/) | Example artifacts sealed with the public test key; [`scripts/seal-example.mjs`](scripts/seal-example.mjs) re-seals one after a change |
| [`docs/overview.md`](docs/overview.md) | A guided tour: each specification's fields and commands |
| [`papers/`](papers/) | Evidence for the published papers: ablations, model checks, a Lean 4 proof |
| [`proposals/`](proposals/) | RFCs that led to specifications |
| [`.claude-plugin/`](.claude-plugin/) | The Claude Code plugin marketplace: `claude plugin install nomos --marketplace nomos-spec/spec` installs `nomos-guard`'s agent hook (SPEC-012) |

---

## How the specifications change

Each specification is a **Draft** or **Active**, as its own header states. NOMOS-SPEC-007 onward stay Drafts until an independent implementation passes their vectors ([SPEC-007 §8](spec/NOMOS-SPEC-007.md#8-conformance-and-implementation-status), SPEC-008 §10). Within a specification, compatible changes raise the minor version; larger ones may be proposed first as an amendment or revision in [`spec/drafts/`](spec/drafts/). A backward-incompatible change to an Active specification takes a new specification number ([`DEPRECATION.md`](DEPRECATION.md)). Every change is recorded in [`CHANGELOG.md`](CHANGELOG.md).

To propose a change, report an ambiguity or contribute an implementation, see [`CONTRIBUTING.md`](CONTRIBUTING.md). Security issues: [`SECURITY.md`](SECURITY.md). Conduct: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

---

## Citing

[`CITATION.cff`](CITATION.cff) gives the citation; GitHub shows it under "Cite this repository". Cite a specification by number and version, for example *NOMOS-SPEC-008 0.7.0*.

---

## License

The NOMOS Protocol specification and schemas are released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Implementations may be proprietary.

---

## Links

- Computable Authority (the discipline NOMOS implements): [computableauthority.com](https://computableauthority.com)
- Protocol site: [nomos.nomosprotocol.com](https://nomos.nomosprotocol.com)
- Hosted runtime: [nomosprotocol.com](https://nomosprotocol.com)
- Protocol Spec: [nomosprotocol.com/spec](https://nomosprotocol.com/spec)
- API Reference: [nomosprotocol.com/docs](https://nomosprotocol.com/docs)
- TypeScript SDK: [@nomosprotocol/sdk on npm](https://www.npmjs.com/package/@nomosprotocol/sdk)
- Studio: [nomosprotocol.com/studio](https://nomosprotocol.com/studio)
- Exchange: [nomosprotocol.com/exchange](https://nomosprotocol.com/exchange)
- Python: [nomosprotocol on PyPI](https://pypi.org/project/nomosprotocol/) (the reference verifiers, `accept()`, `act()`, `witness()`, `issuer()`)
- MCP server: [nomos-mcp on npm](https://www.npmjs.com/package/nomos-mcp), or the hosted connector `https://www.nomosprotocol.com/api/mcp` ([nomosprotocol.com/mcp](https://www.nomosprotocol.com/mcp))
- Enforcement for agents' tool calls: [nomos-guard on npm](https://www.npmjs.com/package/nomos-guard)
