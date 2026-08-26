# Prototype: Chain-of-Trust Key Certificates

**Status: prototype, not a spec.** Nothing here is NOMOS-SPEC-007 or any other numbered spec.
This directory exists to test whether the primitive shape below survives contact with real code
before anything is proposed for standardization. Do not depend on this for anything beyond that.

## Why this exists

[Paper 5 / R-08 — "Bounded Contextual Authority"](https://www.nomosprotocol.com/paper-5) named a
gap: every existing NOMOS mechanism (sealing, attestation, revocation) proves part of "can this
authority be trusted," but none let an **independent system with no prior relationship to the
issuer** recognize that issuer live, without calling home. Today, every key lookup in the
ecosystem — seal verification, attestation, revocation — resolves through one flat
`Map<kid, publicKey>`, published from one place. That's fine when the relying party already knows
to ask NOMOS's own `/.well-known/nomos-signing-keys`. It doesn't generalize to a foreign system
that has never heard of NOMOS and isn't going to call its server to find out.

This prototype tests the piece that generalization needs: a way for one key to certify another,
chained back to a single root the relying party has already decided to trust — resolved entirely
locally, the same way a browser walks a certificate chain against its pinned root store.

## What's here

- **`key-cert.ts`** — the primitive. A `KeyCertificate` is a detached, Ed25519-signed statement:
  "parent key certifies this child key, until this expiry." Deliberately a sibling of
  `nomos-attest.ts` (same cryptographic shape) rather than a variant of it — an attestation is
  advisory and never gates evaluation; a key certificate is exactly what gates whether an issuer
  is recognized. Conflating the two trust semantics in one object type was the bigger risk.
- **`verify-chain.ts`** — an offline CLI that extends the existing `verify/verify.ts --pubkey`
  path with one new question: given an artifact and a chain of certificates presented alongside
  it, does the chain resolve back to a root the caller supplies via **`--root-pubkey`** — always
  required, never defaulted? No default is deliberate: it's what keeps "who operates the root"
  visibly unresolved in the code, instead of silently answered by whatever key ships first.
- **`demo.ts`** — generates a fresh, disposable Ed25519 root/intermediate/leaf (never
  `NOMOS_SIGNING_KEY`), issues certificates between them, seals a toy artifact, and writes fixtures
  under `fixtures/` for `verify-chain.ts` to run against.

## Run it

```bash
npx tsx demo.ts
```

Then run each of the four printed commands. They demonstrate, with real fixtures and a real CLI,
not just code inspection:

1. **`ALLOWED`** — the full chain resolves from the pinned root to the artifact's actual signing
   key; the seal verifies.
2. **`ISSUER_NOT_RECOGNIZED`** (exit 2) — the artifact was sealed by a key with no certificate
   anywhere in the presented chain. The chain walk breaks cleanly; no crash, no false accept.
3. **`ISSUER_NOT_RECOGNIZED`** (exit 2) — the chain connects, but a link has expired. Reported
   with a distinct reason, not conflated with "never recognized."
4. **Order independence** — the same two certificates as case 1, reversed, reach the byte-identical
   `ALLOWED` result. `--chain` is a **set**, not a sequence: `walkChain()` in `verify-chain.ts`
   matches each step by `parent_kid`/`child_kid` content across the whole remaining set, never by
   array position. This is deliberate, not incidental — a wire format that required certificates
   to arrive in a specific order would be smuggling in trust semantics ("as-transmitted sequence
   implies as-intended chain") that don't belong there. Verified empirically, not just by
   inspection: forward and reversed fixtures produce identical output and exit codes.

## What this proves, and what it doesn't

A successful run shows verification needing no live call to the issuer **and** no per-issuer
lookup — only the artifact, the chain, and one already-pinned root key. It does **not** eliminate
the trust bootstrap: the relying party still had to obtain and pin that root key through some
prior decision. That's what PKI does for the web — a real reduction of the trust problem, not its
removal. This prototype takes no position on who a real root should be; it only makes that
question a required, undefaultable argument rather than an implicit one.

## Explicitly out of scope here

- **Revoking a key certificate itself.** SPEC-006 revokes *artifacts*; revoking a *certificate*
  is a different operation with a nastier property — revoking an intermediate should invalidate
  every leaf certified under it, and whether that's checked at verify time or precomputed is a
  real design question deferred until the simpler expiry-only version has been exercised.
- **A real wire protocol.** "Presenting" a chain here is a CLI argument, not a network exchange.
  Standardizing the actual handshake (headers, MCP tool shape, HTTP) should follow proof this
  primitive is sound, not precede it.
- **Any change to the production platform.** Nothing in `AI_Navigator` — `org-signing-keys.ts`,
  `policy-store.ts`, the DB schema — is touched by this prototype.
