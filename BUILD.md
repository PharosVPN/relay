# beacon — Build Brief (subagent)

**Read first, in order:** `docs/BUILD.md` → `docs/DESIGN.md` → this file.
This is a delegated subproject. If the design is silent on a contract you need,
stop and raise it — do not invent one.

---

## What you are building

`beacon` is the relay: a stateless, public-facing transparent gRPC proxy. It
lets clients (`caravel`) reach a `coxswain` controller that has no public IP and no
inbound ports. It holds no state and makes no policy decisions — `coxswain` does all
of that.

## Reuse — this is mostly an adapt-and-rebrand

The relay machinery already exists in an earlier private project by the same
operator. Adapt:

- The transparent gRPC proxy: raw-byte codec, stream director, metadata
  sanitization (strip spoofable headers, inject the verified device
  fingerprint).
- The reverse-tunnel transport: the controller dials *out* to the relay, the
  relay accepts; substreams multiplexed over the outer mTLS connection;
  reconnect with exponential backoff; keepalive.
- The embedded-relay (in-process, in-memory pipe) wiring.
- The device-CA mTLS verification helpers.

**Rebrand obligation (`docs/BUILD.md` §4):** strip *every* identifier from the
origin project — package paths, type names, metadata keys, comments,
filenames. The `beacon` repo must contain zero trace of it. Re-license all
adapted files to AGPL-3.0.

## Behaviour

- **Client side (public):** terminate client mTLS; the client leaf must chain to
  the Device CA. Read the cert fingerprint → inject as the one trusted metadata
  value. Strip everything else a client could spoof.
- **Controller side:** two modes —
  - *Embedded:* run in-process inside `coxswain` over an in-memory pipe.
  - *Remote:* accept the reverse tunnel that `coxswain` dials out; multiplex each
    client RPC as a substream back through it.
- **Forward, don't inspect.** `beacon` proxies opaque gRPC streams (unary,
  server-stream, client-stream, bidi). It must never need to parse profile
  payloads — and profile bundles are E2E-encrypted ciphertext anyway.

### Planned — node cascade / multi-hop (DESIGN decision 18, not scheduled)

No `beacon` work is foreseen, and that is the point: a future client exit-switch
call (`caravel → beacon → coxswain`) is just another opaque control RPC. Keep the
proxy **method-agnostic** — never enumerate or whitelist the set of RPCs
relayed, so a new control RPC needs zero relay change. (The reverse-tunnel
transport may also later be reused for `buoy`→`buoy` NAT traversal to a NAT'd
exit node; no action now, just don't assume the tunnel is client-traffic-only.)

## Milestones

| # | Output |
|---|---|
| R1 | Skeleton; adapt + rebrand the proxy + tunnel packages |
| R2 | Client-side mTLS termination + metadata sanitization |
| R3 | Embedded mode (in-process with `coxswain`) |
| R4 | Remote reverse-tunnel mode (`coxswain` dials out) + reconnect/keepalive |
| R5 | Relay enrollment — `gen-csr` CSR-over-SSH, Fleet-CA relay cert (decision 14, no token) |
| R6 | Static-binary packaging + deploy docs |

## Non-negotiables

- Stateless. No database. All lookups delegated to `coxswain`.
- `coxswain` dials `beacon`, never the reverse, in remote mode.
- `beacon` never sees plaintext profile bundles.
- Zero origin-project lineage in the source.

## Depends on

The relay reverse-tunnel + relayed-client protos, owned by `coxswain`, in
`docs/proto/`. Coordinate any change with the `coxswain` build.
