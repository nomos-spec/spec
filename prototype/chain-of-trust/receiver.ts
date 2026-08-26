#!/usr/bin/env node
/**
 * PROTOTYPE — reference "receiver": an independent system deciding whether to honor a presented
 * artifact, over an actual socket.
 *
 * NOT a spec, not wired into nomos-guard or nomos-mcp (both published packages on the mediation
 * path — entangling an experimental handshake into either would put real users on unstable
 * ground). This is a standalone `node:http` server, zero dependencies, matching this repo's
 * existing verifier ethos.
 *
 * Wire shape, deliberately minimal — "the honest answer at this stage," not a header convention:
 *   POST /verify
 *   Content-Type: application/json
 *   { "artifact": { ... }, "key_certs": [ ... ] }
 *
 *   → 200 { "decision": "ALLOWED", "leaf_kid": "...", "path": [...] }
 *   → 403 { "decision": "ISSUER_NOT_RECOGNIZED", "reason": "...", "detail": "..." }
 *   → 422 { "decision": "SEAL_INVALID", "detail": "..." }
 *   → 400 { "decision": "MALFORMED", "detail": "..." }
 *
 * HTTP status is a hint, not the authoritative signal — `decision` in the body is what a caller
 * should branch on. The three failure decisions are kept distinguishable on purpose: a caller
 * needs to tell "re-present with a different chain" (ISSUER_NOT_RECOGNIZED) apart from "this
 * artifact itself is bad, re-presenting won't help" (SEAL_INVALID) apart from "your request was
 * malformed" (MALFORMED) — collapsing these into one wire-level error would be an interop defect,
 * not a simplification.
 *
 * The root key comes ONLY from this process's own --root-pubkey argument at startup, never from
 * the request body. A presenter cannot name, hint at, or supply a root — if it could, the sender
 * would be choosing its own trust anchor, which defeats the entire property being tested.
 *
 * Usage:
 *   npx tsx receiver.ts --root-pubkey <root.pub.pem> --port 8420
 */

import * as fs from "fs";
import * as http from "http";
import { verifyChainPresentation, type ChainVerdict } from "./chain-verify-core.js";

const STATUS: Record<ChainVerdict["decision"], number> = {
  ALLOWED: 200,
  ISSUER_NOT_RECOGNIZED: 403,
  SEAL_INVALID: 422,
  MALFORMED: 400,
};

function readBody(req: http.IncomingMessage, maxBytes = 1_000_000): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) { reject(new Error("body too large")); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function startReceiver(rootPublicKeyPem: string, port: number): http.Server {
  const server = http.createServer(async (req, res) => {
    if (req.method !== "POST" || req.url !== "/verify") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ decision: "MALFORMED", detail: "POST /verify is the only route." }));
      return;
    }

    let verdict: ChainVerdict;
    try {
      const raw = await readBody(req);
      const body = JSON.parse(raw);
      if (typeof body !== "object" || body === null || !("artifact" in body) || !("key_certs" in body)) {
        verdict = { decision: "MALFORMED", detail: "Body must be { artifact, key_certs }." };
      } else {
        // rootPublicKeyPem comes from this process's own startup argument — never from `body`.
        verdict = verifyChainPresentation({ artifact: body.artifact, chain: body.key_certs, rootPublicKeyPem });
      }
    } catch (e: any) {
      verdict = { decision: "MALFORMED", detail: `Could not parse request body as JSON: ${e?.message ?? e}` };
    }

    res.writeHead(STATUS[verdict.decision], { "content-type": "application/json" });
    res.end(JSON.stringify(verdict));
  });
  server.listen(port);
  return server;
}

function main(): void {
  const args = process.argv.slice(2);
  let rootPubkeyPath: string | null = null;
  let port = 8420;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--root-pubkey" && args[i + 1]) rootPubkeyPath = args[++i];
    else if (args[i] === "--port" && args[i + 1]) port = Number(args[++i]);
  }
  if (!rootPubkeyPath) {
    console.error("Usage: receiver.ts --root-pubkey <root.pub.pem> [--port 8420]");
    console.error("There is no default root — the receiver must be started with the key it trusts.");
    process.exit(1);
  }
  const rootPublicKeyPem = fs.readFileSync(rootPubkeyPath, "utf8");
  startReceiver(rootPublicKeyPem, port);
  console.log(`Receiver listening on http://localhost:${port}/verify (root-pinned, no other trust input)`);
}

if (import.meta.url === `file://${process.argv[1]}`) main();

export { startReceiver };
