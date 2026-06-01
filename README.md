# beacon

> A signal relayed onward — so the lighthouse can stay hidden.

**`beacon` is the PharosVPN relay.** It is a stateless, public, mTLS-terminating
proxy that lets end-user clients reach a controller that has no public presence.
The controller (`coxswain`) stays behind NAT; `beacon` is the only public ingress
for clients.

Part of the [PharosVPN](https://github.com/PharosVPN) platform — see
[`docs/DESIGN.md`](https://github.com/PharosVPN/docs/blob/main/DESIGN.md).

## Role

- **Public ingress for clients only.** Terminates client mTLS, forwards their
  gRPC streams to `coxswain`.
- **Stateless.** No database. Every identity lookup is delegated to `coxswain`.
- **Sanitizing.** Strips spoofable client metadata; injects exactly one trusted
  value — the verified device fingerprint.
- **Two transports to `coxswain`:** *embedded* (in-process inside `coxswain`) or
  *remote reverse tunnel* (`coxswain` dials out to a public `beacon`). Identical
  trust either way.
- **Sees only ciphertext.** Profile bundles cross `beacon` end-to-end encrypted;
  a compromised remote `beacon` host cannot read user profiles.

## Stack

Go · transparent gRPC proxy · reverse-tunnel transport (multiplexed) · mTLS.

## Layout

- [`relay/`](relay/) — the embeddable relay: the transparent proxy, the public
  mTLS listener, and the in-memory `Pipe` for embedded mode.
- [`tunnel/`](tunnel/) — the reverse-tunnel transport `coxswain` dials out over.
- [`cmd/beacon`](cmd/beacon/) — the relay binary: `gen-csr` (SSH enrolment)
  and `run` (the remote relay).

`coxswain` embeds a relay in-process by importing the `relay` package — see
[docs/COXSWAIN-INTEGRATION.md](docs/COXSWAIN-INTEGRATION.md).

## Build & deploy

`make build` produces a static binary in `dist/`. To run a remote relay, see
[docs/DEPLOY.md](docs/DEPLOY.md) and the [`deploy/beacon.service`](deploy/beacon.service)
systemd unit.

## Status

🚧 Pre-alpha. The transparent proxy, both transports (embedded + remote), SSH
relay enrolment (`gen-csr`), and static-binary packaging are built. See
[BUILD.md](BUILD.md).

## License

Apache-2.0. Contributions under the DCO (`git commit -s`).
