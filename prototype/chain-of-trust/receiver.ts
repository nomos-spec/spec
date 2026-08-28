#!/usr/bin/env node
/**
 * PROTOTYPE — reference "receiver": an independent system deciding whether to honor a presented
 * artifact, over an actual socket.
 *
 * Reference implementation for NOMOS-SPEC-007 (Draft) §6, not wired into nomos-guard or nomos-mcp (both published packages on the mediation
 * path — entangling an experimental handshake into either would put real users on unstable
 * ground). This is a standalone `node:http` server, zero dependencies, matching this repo's
 * existing verifier ethos.
 *
 * Wire shape, deliberately minimal — "the honest answer at this stage," not a header convention:
 *   POST /verify
 *   Content-Type: application/json
 *   { "artifact": { ... }, "key_certs": [ ... ], "freshness_staples": [ ... ] }  (staples optional, §5.5)
 *
 *   → 200 { "decision": "ALLOWED", "leaf_kid": "...", "path": [...], "revocation_checked": "unchecked" | "staple" | "live" }
 *   → 403 { "decision": "ISSUER_NOT_RECOGNIZED", "reason_code": "...", "detail": "..." }
 *   → 403 { "decision": "KEY_REVOKED", "revoked_kid": "...", "detail": "..." }
 *   → 403 { "decision": "CERTIFICATE_REVOKED", "revoked_fingerprint": "...", "detail": "..." }
 *   → 403 { "decision": "OUT_OF_SCOPE", "dimension": "...", "detail": "..." }
 *   → 422 { "decision": "SEAL_INVALID", "detail": "..." }
 *   → 400 { "decision": "MALFORMED", "detail": "..." }
 *   → 413 { "decision": "MALFORMED", "detail": "..." }  (request body over the size limit)
 *
 * This process passes no `revokedKids`/`revokedCerts` to the verifier — it holds no revocation
 * source of its own. `revocation_checked` on an ALLOWED verdict will read `staple` only when the
 * presenter attached a valid one, `unchecked` otherwise. That is the honest, disclosed limit of
 * what a receiver with no revocation list can know (§5.5, §10.1) — never silently reported as if
 * it were `live`.
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
 * Binds to 127.0.0.1 by default — not 0.0.0.0 — since Node's own `server.listen(port)` binds all
 * interfaces if you don't say otherwise, and a demo server silently reachable from the network is
 * exactly the kind of default this prototype shouldn't ship. Pass --host to opt into anything
 * wider deliberately.
 *
 * Usage:
 *   npx tsx receiver.ts --root-pubkey <root.pub.pem> --port 8420 [--host 0.0.0.0]
 */

import * as fs from "fs";
import * as http from "http";
import { verifyChainPresentation, type ChainVerdict } from "./chain-verify-core.js";

const MAX_BODY_BYTES = 1_000_000;

const STATUS: Record<ChainVerdict["decision"], number> = {
  ALLOWED: 200,
  ISSUER_NOT_RECOGNIZED: 403,
  // A key's standing to sign was withdrawn entirely by its own parent (§5.1-5.2).
  KEY_REVOKED: 403,
  // One delegation withdrawn; the key may still be certified elsewhere (§5.4).
  CERTIFICATE_REVOKED: 403,
  // Recognized issuer, not delegated authority over this artifact (§3.4). Shares 403 with the
  // other refusals; `decision` in the body is what a caller branches on.
  OUT_OF_SCOPE: 403,
  SEAL_INVALID: 422,
  MALFORMED: 400,
};

class PayloadTooLargeError extends Error {}

/**
 * Stops accumulating once the limit is exceeded but does NOT destroy the request/socket here —
 * destroying it before the caller has a chance to write a response means the client never learns
 * why the connection died. The caller (the request handler below) is responsible for sending a
 * proper 413 and closing the connection afterward.
 */
function readBody(req: http.IncomingMessage, maxBytes = MAX_BODY_BYTES): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    let tooLarge = false;
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => {
      if (tooLarge) return;
      size += chunk.length;
      if (size > maxBytes) { tooLarge = true; reject(new PayloadTooLargeError(`body exceeds ${maxBytes} bytes`)); return; }
      chunks.push(chunk);
    });
    req.on("end", () => { if (!tooLarge) resolve(Buffer.concat(chunks).toString("utf8")); });
    req.on("error", reject);
  });
}

function startReceiver(rootPublicKeyPem: string, port: number, host = "127.0.0.1"): http.Server {
  const server = http.createServer(async (req, res) => {
    if (req.method !== "POST" || req.url !== "/verify") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ decision: "MALFORMED", detail: "POST /verify is the only route." }));
      return;
    }

    const contentType = req.headers["content-type"] ?? "";
    if (!contentType.startsWith("application/json")) {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ decision: "MALFORMED", detail: "Content-Type must be application/json." }));
      return;
    }

    let verdict: ChainVerdict;
    let status: number;
    try {
      const raw = await readBody(req);
      const body = JSON.parse(raw);
      if (typeof body !== "object" || body === null || !("artifact" in body) || !("key_certs" in body)) {
        verdict = { decision: "MALFORMED", detail: "Body must be { artifact, key_certs }." };
      } else {
        // rootPublicKeyPem comes from this process's own startup argument — never from `body`.
        // This receiver supplies no revocation source of its own (no `revokedKids` argument
        // below) — the real hasOwnKeySource=false case (§5.5): an optional `freshness_staples`
        // in the body is the only way this process can gain any confidence beyond 'unchecked'.
        verdict = verifyChainPresentation({
          artifact: body.artifact, chain: body.key_certs, rootPublicKeyPem,
          freshnessStaples: body.freshness_staples,
        });
      }
      status = STATUS[verdict.decision];
    } catch (e: any) {
      if (e instanceof PayloadTooLargeError) {
        verdict = { decision: "MALFORMED", detail: e.message };
        status = 413;
      } else {
        verdict = { decision: "MALFORMED", detail: `Could not parse request body as JSON: ${e?.message ?? e}` };
        status = 400;
      }
    }

    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(verdict));
  });
  server.listen(port, host);
  return server;
}

function main(): void {
  const args = process.argv.slice(2);
  let rootPubkeyPath: string | null = null;
  let port = 8420;
  let host = "127.0.0.1";
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--root-pubkey" && args[i + 1]) rootPubkeyPath = args[++i];
    else if (args[i] === "--port" && args[i + 1]) port = Number(args[++i]);
    else if (args[i] === "--host" && args[i + 1]) host = args[++i];
  }
  if (!rootPubkeyPath) {
    console.error("Usage: receiver.ts --root-pubkey <root.pub.pem> [--port 8420] [--host 0.0.0.0]");
    console.error("There is no default root — the receiver must be started with the key it trusts.");
    process.exit(1);
  }
  const rootPublicKeyPem = fs.readFileSync(rootPubkeyPath, "utf8");
  startReceiver(rootPublicKeyPem, port, host);
  console.log(`Receiver listening on http://${host}:${port}/verify (root-pinned, no other trust input)`);
}

if (import.meta.url === `file://${process.argv[1]}`) main();

export { startReceiver };
