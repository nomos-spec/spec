#!/usr/bin/env node
/**
 * PROTOTYPE — Offline chain-of-trust verifier (CLI)
 *
 * NOT a spec, not wired into any production path. See ./README.md.
 *
 * Thin wrapper over chain-verify-core.ts's verifyChainPresentation() — the same function backs
 * receiver.ts's HTTP path, so the CLI and the wire receiver can never drift onto two different
 * notions of what a valid chain is.
 *
 * Extends the existing fully-offline verification path (verify/verify.ts's --pubkey mode) with
 * one new question: not just "is this seal authentic," but "is the key that signed it one a
 * pinned root actually vouches for" — without looking anything up in a central directory.
 *
 * Usage:
 *   npx tsx verify-chain.ts <artifact.nomos> --chain <certs.json> --root-pubkey <root.pub.pem>
 *
 * --chain is a SET of certificates, not a sequence — presentation order must not affect the
 * verdict (see chain-verify-core.ts's walkChain() invariant).
 *
 * There is deliberately NO default for --root-pubkey and no fallback to any NOMOS-hosted key.
 * The relying party must supply the one root key it has independently decided to trust. That
 * decision — who operates a root, and why it should be trusted — is exactly the open governance
 * question this prototype does not answer; the required, no-default flag is what keeps it
 * visibly open in the code instead of silently resolved by a shipped default.
 */

import * as fs from "fs";
import * as path from "path";
import { verifyChainPresentation, type ChainVerdict } from "./chain-verify-core.js";
import type { KeyCertificate } from "./key-cert.js";

const EXIT_CODE: Record<ChainVerdict["decision"], number> = {
  ALLOWED: 0,
  ISSUER_NOT_RECOGNIZED: 2,
  SEAL_INVALID: 3,
  MALFORMED: 1,
};

function printAndExit(verdict: ChainVerdict): never {
  if (verdict.decision === "ALLOWED") {
    console.log(`  path: ${verdict.path.join(" → ")}`);
    console.log(`\nResult: ALLOWED — chain resolves from the pinned root to the artifact's signing key, seal verifies.\n`);
  } else if (verdict.decision === "ISSUER_NOT_RECOGNIZED") {
    console.error(`\n  [FAIL] ${verdict.detail}\n\nResult: ISSUER_NOT_RECOGNIZED (reason: ${verdict.reason})\n`);
  } else if (verdict.decision === "SEAL_INVALID") {
    console.error(`\n  [FAIL] ${verdict.detail}\n\nResult: SEAL_INVALID\n`);
  } else {
    console.error(`\n  [FAIL] ${verdict.detail}\n\nResult: MALFORMED\n`);
  }
  process.exit(EXIT_CODE[verdict.decision]);
}

function main(): void {
  const args = process.argv.slice(2);
  if (!args.length) {
    console.error("Usage: verify-chain.ts <artifact.nomos> --chain <certs.json> --root-pubkey <root.pub.pem>");
    process.exit(1);
  }
  const artifactPath = path.resolve(args[0]);
  let chainPath: string | null = null;
  let rootPubkeyPath: string | null = null;
  for (let i = 1; i < args.length; i++) {
    if (args[i] === "--chain" && args[i + 1]) chainPath = path.resolve(args[++i]);
    else if (args[i] === "--root-pubkey" && args[i + 1]) rootPubkeyPath = path.resolve(args[++i]);
  }
  if (!rootPubkeyPath) printAndExit({ decision: "MALFORMED", detail: "--root-pubkey is required. There is no default root — you must supply the key you've decided to trust." });
  if (!chainPath) printAndExit({ decision: "MALFORMED", detail: "--chain <certs.json> is required — the set of key certificates presented alongside the artifact (order does not matter)." });

  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  const chain: KeyCertificate[] = JSON.parse(fs.readFileSync(chainPath, "utf8"));
  const rootPublicKeyPem = fs.readFileSync(rootPubkeyPath, "utf8");

  console.log(`\nVerifying chain for: ${artifactPath}`);
  console.log(`  target kid (artifact signer) : ${artifact?.seal?.kid ?? "—"}`);

  printAndExit(verifyChainPresentation({ artifact, chain, rootPublicKeyPem }));
}

main();
