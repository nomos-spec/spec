#!/usr/bin/env node
/**
 * PROTOTYPE — reference "presenter": an agent carrying a `.nomos` artifact plus its key-cert
 * chain into an independent system it has no prior relationship with, and asking to be honored.
 *
 * Reference implementation for NOMOS-SPEC-007 (Draft) §6. Deliberately dumb: reads an artifact and a chain from disk, POSTs the envelope
 * `{ artifact, key_certs }` to a receiver's /verify endpoint, prints whatever comes back. It does
 * not name a root, does not hint at one, and could not influence the receiver's trust decision
 * even if it tried — that property belongs entirely to the receiver's own configuration.
 *
 * Usage:
 *   npx tsx presenter.ts <artifact.nomos> --chain <certs.json> --url http://localhost:8420/verify
 */

import * as fs from "fs";

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (!args.length) {
    console.error("Usage: presenter.ts <artifact.nomos> --chain <certs.json> --url <receiver-url>");
    process.exit(1);
  }
  const artifactPath = args[0];
  let chainPath: string | null = null;
  let url: string | null = null;
  for (let i = 1; i < args.length; i++) {
    if (args[i] === "--chain" && args[i + 1]) chainPath = args[++i];
    else if (args[i] === "--url" && args[i + 1]) url = args[++i];
  }
  if (!chainPath || !url) {
    console.error("Both --chain and --url are required.");
    process.exit(1);
  }

  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  const key_certs = JSON.parse(fs.readFileSync(chainPath, "utf8"));

  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ artifact, key_certs }),
  });
  const body = await res.json();
  console.log(`HTTP ${res.status}`);
  console.log(JSON.stringify(body, null, 2));
  process.exit(body.decision === "ALLOWED" ? 0 : 1);
}

main();
