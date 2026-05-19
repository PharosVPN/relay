# Integrating beacon into helm

This document is the contract surface `helm` builds its **M6b-2** against —
the embedded relay and the remote-relay dialer (DESIGN §2, §3). It describes
two public Go packages:

| Package | Import path | Used for |
|---|---|---|
| `relay` | `github.com/PharosVPN/beacon/relay` | running a relay (embedded **and** remote) |
| `tunnel` | `github.com/PharosVPN/beacon/tunnel` | the reverse tunnel — `helm` dials a remote relay |

beacon is a **transparent** gRPC proxy. It registers no services and never
decodes a message body, so `helm` adds an `AccountSync` RPC without touching
beacon. beacon carries only ciphertext profile bundles (DESIGN §8).

Both transports are **identical trust** — the only difference is the
`relay.Config.BackendDialer` (DESIGN §2).

---

## 1. Embedded relay (in-process)

The always-on relay of DESIGN §2: `helm` runs a relay in its own process and
reaches it over an in-memory pipe — no TCP, no loopback hop. mTLS still runs
over the pipe, so the embedded and remote auth paths are one path.

```go
import "github.com/PharosVPN/beacon/relay"

// 1. An in-memory listener+dialer pair.
pipe := relay.NewPipe()
defer pipe.Close()

// 2. Serve helm's AccountSync gRPC server on the pipe. The server must
//    use mTLS: present helm's Fleet-CA leaf (CN/SAN "helm-grpc"), require
//    a client cert chaining to the Fleet CA. pipe satisfies net.Listener.
go helmGRPCServer.Serve(pipe)

// 3. Start the relay; its backend dials helm through the pipe.
r, err := relay.Start(relay.Config{
    ClientListenAddr: ":8443",          // public mTLS port for caravel
    RelayCertPEM:     relayCertPEM,      // single Fleet-CA leaf — see §4
    RelayKeyPEM:      relayKeyPEM,
    ClientTrustPEM:   deviceCAPEM,       // verifies caravel device leaves
    BackendTrustPEM:  fleetCAPEM,        // verifies helm's gRPC leaf
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

## 2. Remote relay (helm dials out)

A `beacon` binary runs the relay on a public host. `helm` keeps **zero inbound
ports** and dials OUT to it; each caravel RPC rides a multiplexed substream
back through that one connection.

`helm` uses the `tunnel` package:

```go
import "github.com/PharosVPN/beacon/tunnel"

err := tunnel.DialAndAcceptLoop(
    ctx,
    "beacon.example.net:8444",  // the remote beacon's --tunnel-addr
    helmTunnelTLS,              // *tls.Config — see §3
    func(_ context.Context, lis *tunnel.SessionListener) error {
        // Each yamux substream looks like an inbound TCP conn. Serve
        // helm's AccountSync gRPC server on it — the SAME server value
        // used for the embedded pipe.
        return helmGRPCServer.Serve(lis)
    },
    log.Printf,   // or nil
    &tunnel.Observer{ /* OnConnect, OnDialFail, ... — optional, for the admin UI */ },
)
```

`DialAndAcceptLoop` blocks until `ctx` is cancelled. It reconnects forever
with exponential backoff (1s→60s), 20s yamux keepalive, and a fast-fail guard;
every transition is reported through the optional `Observer` so the admin UI
can show attempts / last error / uptime. To stop it: cancel `ctx`, then
`helmGRPCServer.Stop()` to unblock the in-flight `Serve`.

`helm` does **not** import `relay` for remote mode — the remote `beacon`
binary owns the relay; `helm` owns only the dial side.

---

## 3. PKI — what helm must issue

PharosVPN runs two CA intermediates (DESIGN §4). The relay legs use them as
follows. `helm` issues every certificate; beacon stores no CA key.

| Leg | Server cert | Client cert | Trust root |
|---|---|---|---|
| caravel → relay (public) | relay cert (Fleet CA) | caravel device leaf (Device CA) | relay verifies clients against **Device CA** |
| helm → relay (tunnel, remote only) | relay cert (Fleet CA) | helm leaf, `O="PharosVPN Relay"` (Fleet CA) | both verify against **Fleet CA** |
| relay → helm (gRPC, over the pipe or a substream) | helm leaf, `CN/SAN="helm-grpc"` (Fleet CA) | relay leaf, `O="PharosVPN Relay"` (Fleet CA) | both verify against **Fleet CA** |

The inner gRPC leg is mutually authenticated **even inside the tunnel's own
TLS** — that inner client cert is what helm's gRPC auth interceptor reads for
delegation. Embedded mode runs the same inner mTLS over the pipe.

### Pinned identifiers

Confirmed during beacon R1, pinned in `helm/BUILD.md`:

| Role | Value |
|---|---|
| Injected verified-device-fingerprint metadata key | `x-pharos-device-fp` |
| Stripped client-metadata prefix (anti-spoofing) | `x-pharos-` |
| Backend delegation cert `Organization` | `PharosVPN Relay` |
| helm gRPC-leg leaf `CN` / backend SNI | `helm-grpc` |

beacon strips **every** inbound metadata key under `x-pharos-` and injects
exactly one trusted value — `x-pharos-device-fp: sha256:<hex>`, the SHA-256 of
the PEM-encoded caravel leaf. helm's gRPC auth path: when the peer cert
carries `O="PharosVPN Relay"`, trust `x-pharos-device-fp` and do the
device→user lookup; otherwise treat the caller as anonymous (the pre-enrolment
path — caravel devices reach `Authenticate`/`EnrollKeys` before they hold a
Device-CA leaf). The default backend SNI is `helm-grpc`; override it with
`Config.BackendServerName` if helm's leaf CN differs.

---

## 4. The relay certificate

A relay holds **one** certificate, pinned in `helm/BUILD.md`: a single
Fleet-CA leaf carrying

- the **ServerAuth** EKU (public listener + tunnel listener), and
- the **ClientAuth** EKU (the backend gRPC leg), and
- `Organization="PharosVPN Relay"` — helm's gRPC auth path keys delegation
  off this Organization.

helm's M6b PKI issues exactly that. `relay.Config` takes it as `RelayCertPEM`
/ `RelayKeyPEM`; the remote `beacon run` binary reads it as `relay.crt` /
`relay.key`. beacon stores no CA key — helm owns all issuance.
