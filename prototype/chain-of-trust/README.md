# Reference Implementation: NOMOS-SPEC-007 (Draft) — Chain-of-Trust Key Certificates

**Status: this code is now the pure reference implementation for [NOMOS-SPEC-007](../../spec/NOMOS-SPEC-007.md),
published as Draft.** It began as an unnumbered prototype to test whether the primitives below
survived contact with real code — over a real socket, not just in-process — before anything was
proposed for standardization. They did; the spec is now written. What has **not** changed:
NOMOS-SPEC-007 has exactly one implementation (this one), and makes no interoperability claim
until a second, independent implementation exists — see the spec's §8 for what Draft status does
and does not establish. Do not depend on this as proven interoperable infrastructure yet; do
treat it as a complete, tested starting point for anyone building a second implementation.

## Why this exists

[Paper 5 / R-08 — "Bounded Contextual Authority"](https://www.nomosprotocol.com/paper-5) named a
gap: every existing NOMOS mechanism (sealing, attestation, revocation) proves part of "can this
authority be trusted," but none let an **independent system with no prior relationship to the
issuer** recognize that issuer live, without calling home. Today, every key lookup in the
ecosystem — seal verification, attestation, revocation — resolves through one flat
`Map<kid, publicKey>`, published from one place. That's fine when the relying party already knows
to ask NOMOS's own `/.well-known/nomos-signing-keys`. It doesn't generalize to a foreign system
that has never heard of NOMOS and isn't going to call its server to find out.

This prototype has two layers. The first (`key-cert.ts` / `chain-verify-core.ts` / `verify-chain.ts`)
tests the primitive that generalization needs: a way for one key to certify another, chained back
to a single root the relying party has already decided to trust, resolved entirely locally — the
same way a browser walks a certificate chain against its pinned root store. The second
(`receiver.ts` / `presenter.ts`) puts that primitive on an actual socket, to see what a minimal
handshake built on top of it looks like.

## What's here

- **`key-cert.ts`** — the primitive. A `KeyCertificate` is a detached, Ed25519-signed statement:
  "parent key certifies this child key, until this expiry." Deliberately a sibling of
  `nomos-attest.ts` (same cryptographic shape) rather than a variant of it — an attestation is
  advisory and never gates evaluation; a key certificate is exactly what gates whether an issuer
  is recognized. Conflating the two trust semantics in one object type was the bigger risk.
- **`chain-verify-core.ts`** — the pure verdict logic: `verifyChainPresentation({ artifact, chain,
  rootPublicKeyPem })` → a structured `ChainVerdict`, never a `process.exit()` or a `console.log`.
  Both `verify-chain.ts` (CLI) and `receiver.ts` (HTTP) call this same function, so a CLI verdict
  and a wire verdict can never quietly drift onto two different notions of what a valid chain is.
- **`verify-chain.ts`** — the offline CLI: extends the existing `verify/verify.ts --pubkey` path
  with one new question — does the presented chain resolve back to a root the caller supplies via
  **`--root-pubkey`**, always required, never defaulted? No default is deliberate: it's what keeps
  "who operates the root" visibly unresolved in the code, instead of silently answered by whatever
  key ships first.
- **`receiver.ts`** — a standalone `node:http` server (zero dependencies, matching this repo's
  ethos) playing the independent relying party. `POST /verify` with `{ artifact, key_certs }`
  returns a JSON verdict. The root key comes **only** from the receiver's own `--root-pubkey`
  startup argument — never from the request — so a presenter cannot name, hint at, or influence
  the trust anchor it's being judged against.
- **`presenter.ts`** — the agent side: reads an artifact + chain from disk, POSTs the envelope,
  prints the verdict. Deliberately dumb; it has no way to supply a root even if it tried.
- **`demo.ts`** — generates a fresh, disposable Ed25519 root/intermediate/leaf (never
  `NOMOS_SIGNING_KEY`), plus an uncertified impostor key, issues certificates, seals toy
  artifacts, and writes fixtures under `fixtures/` for both the CLI and the wire tools to run
  against identically.

## Run it

```bash
npx tsx demo.ts
```

### Offline (CLI)

Run the five printed `verify-chain.ts` commands. Each is a real process run against real
fixtures, not an assertion from reading the code:

1. **`ALLOWED`** (exit 0) — the full chain resolves from the pinned root to the artifact's actual
   signing key; the seal verifies.
2. **`ISSUER_NOT_RECOGNIZED`** (exit 2, reason `chain_broken`) — the artifact was sealed by a key
   with no certificate anywhere in the presented chain. No crash, no false accept.
3. **`ISSUER_NOT_RECOGNIZED`** (exit 2, reason `expired`) — the chain connects, but a link has
   lapsed. Reported with a distinct reason, not conflated with "never recognized."
4. **Order independence** — the same two certificates as case 1, reversed, reach the
   byte-identical `ALLOWED` result. `--chain` is a **set**, not a sequence:
   `chain-verify-core.ts`'s `walkChain()` matches each step by `parent_kid`/`child_kid` content
   across the whole remaining set, never by array position. Deliberate, not incidental — a wire
   format that required certificates in a specific order would be smuggling in a trust assumption
   ("as-transmitted sequence implies as-intended chain") that doesn't belong there.
5. **`SEAL_INVALID`** (exit 3) — the chain resolves fine, but the artifact's content was edited
   after sealing. Kept distinct from `ISSUER_NOT_RECOGNIZED` on purpose: re-presenting a better
   chain can never fix a tampered artifact, so collapsing the two into one error would tell the
   caller the wrong thing to do next.

### Over the wire

```bash
npx tsx receiver.ts --root-pubkey fixtures/root.pub.pem --port 8420 &
npx tsx presenter.ts fixtures/artifact-honored.nomos  --chain fixtures/chain-success.json --url http://localhost:8420/verify
npx tsx presenter.ts fixtures/artifact-impostor.nomos --chain fixtures/chain-success.json --url http://localhost:8420/verify
npx tsx presenter.ts fixtures/artifact-tampered.nomos --chain fixtures/chain-success.json --url http://localhost:8420/verify
```

Confirmed by an actual HTTP round trip, not an in-process function call: `200 ALLOWED` with the
resolved chain path, `403 ISSUER_NOT_RECOGNIZED`, and `422 SEAL_INVALID` — three distinguishable
outcomes in the response **body** (HTTP status alone is deliberately not treated as authoritative;
`decision` is what a caller branches on). Also confirmed: posting a body with an extra
`root_pubkey_pem` field is silently ignored by the receiver — there is no code path by which a
presenter's request can influence which root the receiver trusts.

**Wire shape, deliberately minimal:** a JSON POST body, no custom header convention, no MCP tool
binding, no version field. The pasted requirements this responds to (a way to present the
credential, a standard verification response, defined behavior for "I don't recognize this
issuer") are each covered, but at the smallest scope that demonstrates the shape — the honest
answer at this stage, not a standard. Nothing here is wired into `nomos-guard` or `nomos-mcp`
(both published packages on the mediation path); this stays a standalone prototype until the
shape has been exercised more.

## Security hardening + automated tests

A dedicated pass found and fixed real issues, rather than assuming the happy-path demo generalized:

- **`verifyChainPresentation` no longer throws.** `chain-verify-core.ts` and `key-cert.ts`'s
  `verifyKeyCertificate` both used to let a malformed PEM or bad base64 propagate as an uncaught
  exception on the *next* hop of the walk — safety-netted by the receiver's own try/catch, but not
  by the CLI, which would have printed a raw stack trace. Fixed at the root (inside the core), so
  neither caller needs its own defense.
- **Every certificate's shape is validated before any crypto touches it** — each field must be the
  right primitive type, `algorithm` must literally be `"Ed25519"` — producing a clear `MALFORMED`
  instead of an incidental crypto exception or a silent type-coercion.
- **A 20-certificate chain-length cap**, independent of and in addition to the transport's body
  size limit — no real chain is ever that deep.
- **Cycle detection is tested with a real signed cycle** (root certifies A, A certifies root, the
  walk must detect it rather than loop), not just traced by reading the code.
- **The receiver binds to `127.0.0.1` by default**, not `0.0.0.0` — Node's own `server.listen(port)`
  binds every interface if you don't say otherwise, and a demo server silently reachable from the
  network was a real footgun. `--host` opts into anything wider deliberately.
- **Oversized requests get a real `413` response.** The previous version called `req.destroy()`
  before writing the error, which killed the socket before the client could read why — fixed so
  the connection yields a proper JSON error first.
- **Explicit `Content-Type` enforcement** — a non-JSON body is rejected before it's parsed.

`test.ts` (`npx tsx --test test.ts`, `node:test` + `node:assert`, zero deps) runs all of the above
as real assertions — including two real HTTP round trips per wire test via `startReceiver()`, not
in-process shortcuts — plus every scenario from the walkthrough above. 17 assertions, all passing.

**What "hardened" means here, precisely:** this pass makes the *verification code* solid against
malformed and adversarial input. It does not, and cannot, resolve the property this prototype
was built to leave open — see the next section. Don't read "no corners in the code" as "no open
questions in the design"; the two are independent, and only the first one was in scope to close.

## What this proves, and what it doesn't

A successful run shows verification needing no live call to the issuer **and** no per-issuer
lookup — only the artifact, the chain, and one already-pinned root key, over a real socket with no
shared prior state beyond that one key. It does **not** eliminate the trust bootstrap: the relying
party still had to obtain and pin that root key through some prior decision. That's what PKI does
for the web — a real reduction of the trust problem, not its removal. This prototype takes no
position on who a real root should be; it only makes that question a required, undefaultable
argument rather than an implicit one, and confirms that argument can't be smuggled in by the
other side of the handshake either.

## Explicitly out of scope here

- **Revoking a key certificate itself.** SPEC-006 revokes *artifacts*; revoking a *certificate*
  is a different operation with a nastier property — revoking an intermediate should invalidate
  every leaf certified under it, and whether that's checked at verify time or precomputed is a
  real design question deferred until the simpler expiry-only version has been exercised.
- **A standardized wire protocol.** What's here is a minimal, real demonstration of the shape —
  not a header convention, not versioned, not an MCP tool binding, not reviewed by anyone but
  this exercise. Standardizing the actual handshake should follow more of this kind of contact,
  not this one prototype alone.
- **Any change to the production platform.** Nothing in `AI_Navigator` — `org-signing-keys.ts`,
  `policy-store.ts`, the DB schema, `nomos-guard`, `nomos-mcp` — is touched by this prototype.
