# Integrating relay into coxswain

This document is the contract surface `coxswain` builds its **M6b-2** against —
the embedded relay and the remote-relay dialer (DESIGN §2, §3). It describes
two public Go packages:

| Package | Import path | Used for |
|---|---|---|
| `relay` | `github.com/PharosVPN/relay/relay` | running a relay (embedded **and** remote) |
| `tunnel` | `github.com/PharosVPN/relay/tunnel` | the reverse tunnel — `coxswain` dials a remote relay |

relay is a **transparent** gRPC proxy. It registers no services and never
decodes a message body, so `coxswain` adds an `AccountSync` RPC without touching
relay. relay carries only ciphertext profile bundles (DESIGN §8).

Both transports are **identical trust** — the only difference is the
`relay.Config.BackendDialer` (DESIGN §2).

---

## 1. Embedded relay (in-process)

The always-on relay of DESIGN §2: `coxswain` runs a relay in its own process and
reaches it over an in-memory pipe — no TCP, no loopback hop. mTLS still runs
over the pipe, so the embedded and remote auth paths are one path.

```go
import "github.com/PharosVPN/relay/relay"

// 1. An in-memory listener+dialer pair.
pipe := relay.NewPipe()
defer pipe.Close()

// 2. Serve coxswain's AccountSync gRPC server on the pipe. The server must
//    use mTLS: present coxswain's Fleet-CA leaf (CN/SAN "coxswain-grpc"), require
//    a client cert chaining to the Fleet CA. pipe satisfies net.Listener.
go coxswainGRPCServer.Serve(pipe)

// 3. Start the relay; its backend dials coxswain through the pipe.
r, err := relay.Start(relay.Config{
    ClientListenAddr: ":8443",          // public mTLS port for caravel
    RelayCertPEM:     relayCertPEM,      // single Fleet-CA leaf — see §4
    RelayKeyPEM:      relayKeyPEM,
    ClientTrustPEM:   deviceCAPEM,       // verifies caravel device leaves
    BackendTrustPEM:  fleetCAPEM,        // verifies coxswain's gRPC leaf
    BackendDialer:    pipe.DialContext,  // <-- the only embedded-specific line
})
if err != nil { /* ... */ }
defer r.Stop()
```

`relay.Start` returns once the public listener is bound; streams are served on
a background goroutine. `r.Addr()` reports the bound address (useful with
`:0`). `r.Stop()` drains in-flight streams and is idempotent.

The admin UI's "embedded relay" toggle (DESIGN §2) maps to `Start` / `Stop`.

---

## 2. Remote relay (coxswain dials out)

A `relay` binary runs the relay on a public host. `coxswain` keeps **zero inbound
ports** and dials OUT to it; each caravel RPC rides a multiplexed substream
back through that one connection.

`coxswain` uses the `tunnel` package:

```go
import "github.com/PharosVPN/relay/tunnel"

err := tunnel.DialAndAcceptLoop(
    ctx,
    "relay.example.net:8444",  // the remote relay's --tunnel-addr
    coxswainTunnelTLS,              // *tls.Config — see §3
    func(_ context.Context, lis *tunnel.SessionListener) error {
        // Each yamux substream looks like an inbound TCP conn. Serve
        // coxswain's AccountSync gRPC server on it — the SAME server value
        // used for the embedded pipe.
        return coxswainGRPCServer.Serve(lis)
    },
    log.Printf,   // or nil
    &tunnel.Observer{ /* OnConnect, OnDialFail, ... — optional, for the admin UI */ },
)
```

`DialAndAcceptLoop` blocks until `ctx` is cancelled. It reconnects forever
with exponential backoff (1s→60s), 20s yamux keepalive, and a fast-fail guard;
every transition is reported through the optional `Observer` so the admin UI
can show attempts / last error / uptime. To stop it: cancel `ctx`, then
`coxswainGRPCServer.Stop()` to unblock the in-flight `Serve`.

`coxswain` does **not** import `relay` for remote mode — the remote `relay`
binary owns the relay; `coxswain` owns only the dial side.

---

## 3. PKI — what coxswain must issue

PharosVPN runs two CA intermediates (DESIGN §4). The relay legs use them as
follows. `coxswain` issues every certificate; relay stores no CA key.

| Leg | Server cert | Client cert | Trust root |
|---|---|---|---|
| caravel → relay (public) | relay cert (Fleet CA) | caravel device leaf (Device CA) | relay verifies clients against **Device CA** |
| coxswain → relay (tunnel, remote only) | relay cert (Fleet CA) | coxswain leaf, `O="PharosVPN Relay"` (Fleet CA) | both verify against **Fleet CA** |
| relay → coxswain (gRPC, over the pipe or a substream) | coxswain leaf, `CN/SAN="coxswain-grpc"` (Fleet CA) | relay leaf, `O="PharosVPN Relay"` (Fleet CA) | both verify against **Fleet CA** |

The inner gRPC leg is mutually authenticated **even inside the tunnel's own
TLS** — that inner client cert is what coxswain's gRPC auth interceptor reads for
delegation. Embedded mode runs the same inner mTLS over the pipe.

### Pinned identifiers

Confirmed during relay R1, pinned in `coxswain/BUILD.md`:

| Role | Value |
|---|---|
| Injected verified-device-fingerprint metadata key | `x-pharos-device-fp` |
| Stripped client-metadata prefix (anti-spoofing) | `x-pharos-` |
| Backend delegation cert `Organization` | `PharosVPN Relay` |
| coxswain gRPC-leg leaf `CN` / backend SNI | `coxswain-grpc` |

relay strips **every** inbound metadata key under `x-pharos-` and injects
exactly one trusted value — `x-pharos-device-fp: sha256:<hex>`, the SHA-256 of
the PEM-encoded caravel leaf. coxswain's gRPC auth path: when the peer cert
carries `O="PharosVPN Relay"`, trust `x-pharos-device-fp` and do the
device→user lookup; otherwise treat the caller as anonymous (the pre-enrolment
path — caravel devices reach `Authenticate`/`EnrollKeys` before they hold a
Device-CA leaf). The default backend SNI is `coxswain-grpc`; override it with
`Config.BackendServerName` if coxswain's leaf CN differs.

---

## 4. The relay certificate

A relay holds **one** certificate, pinned in `coxswain/BUILD.md`: a single
Fleet-CA leaf carrying

- the **ServerAuth** EKU (public listener + tunnel listener), and
- the **ClientAuth** EKU (the backend gRPC leg), and
- `Organization="PharosVPN Relay"` — coxswain's gRPC auth path keys delegation
  off this Organization.

coxswain's M6b PKI issues exactly that. `relay.Config` takes it as `RelayCertPEM`
/ `RelayKeyPEM`; the remote `relay run` binary reads it as `relay.crt` /
`relay.key`. relay stores no CA key — coxswain owns all issuance.
