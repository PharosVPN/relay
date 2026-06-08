# Deploying a remote relay relay

This guide covers running `relay` as a **remote** relay on a public host.

The **embedded** relay needs no deployment — `coxswain` runs it in-process by
importing the `relay` package ([docs/COXSWAIN-INTEGRATION.md](COXSWAIN-INTEGRATION.md)).
Deploy a remote relay only when the controller sits behind NAT and must serve
caravel clients from a public address (DESIGN §2).

A remote `relay` is a single static binary. It holds no database, writes
nothing at runtime, and makes **no outbound connections** — `coxswain` dials in to
it and caravel clients dial in to it.

---

## 1. Build

```sh
GOOS=linux GOARCH=amd64 make build      # → dist/relay
```

`relay` has no cgo dependencies, so the result is a static binary that runs on
any Linux host of that architecture. Drop `GOOS`/`GOARCH` to build for the
current platform. `make build` stamps the version from `git describe`.

## 2. Prepare the host

```sh
# Unprivileged service account — owns /etc/relay and the private key.
useradd --system --no-create-home --shell /usr/sbin/nologin relay
install -d -o relay -g relay -m 0750 /etc/relay

# The binary.
install -m 0755 dist/relay /usr/local/bin/relay
```

## 3. Enrol with coxswain (CSR-over-SSH)

Enrolment mirrors `node` onboarding — CSR-over-SSH, no bootstrap token
(DESIGN §5, decision 14). `coxswain` automates the steps below over SSH; the
manual equivalent is:

1. **Generate the keypair and a CSR.** Run as the `relay` user so the private
   key is owned by the service account:

   ```sh
   sudo -u relay relay gen-csr --config-dir /etc/relay
   ```

   This writes `/etc/relay/relay.key` (mode `0600`, never leaves the host)
   and prints a PKCS#10 CSR to stdout. Re-running it is idempotent.

2. **Hand the CSR to coxswain.** `coxswain` signs it with the Fleet CA, assigning the
   relay's identity itself — `Organization="PharosVPN Relay"`, dual
   ServerAuth+ClientAuth EKU, and the public-endpoint DNS SAN (a relay host
   does not self-assert these; see coxswain/BUILD.md, "Relay enrollment contract").

3. **Install the material coxswain returns** — owned by `relay`:

   ```sh
   install -o relay -g relay -m 0644 relay.crt     /etc/relay/relay.crt
   install -o relay -g relay -m 0644 fleet-ca.crt  /etc/relay/fleet-ca.crt
   install -o relay -g relay -m 0644 device-ca.crt /etc/relay/device-ca.crt
   ```

`/etc/relay` then holds: `relay.key`, `relay.crt` (relay leaf + Fleet
intermediate), `fleet-ca.crt`, `device-ca.crt`.

## 4. Install the service

```sh
install -m 0644 deploy/relay.service /etc/systemd/system/relay.service
systemctl daemon-reload
systemctl enable --now relay
```

The unit runs `relay run --config-dir /etc/relay` as the `relay` user under
a strict sandbox (see [`deploy/relay.service`](../deploy/relay.service)).

## 5. Networking

Open **inbound** TCP only — `relay` initiates nothing:

| Port | Flag | Reached by |
|---|---|---|
| client | `--client-addr` (default `:8443`) | caravel clients |
| tunnel | `--tunnel-addr` (default `:8444`) | `coxswain` dialling in |

Override the defaults in the unit's `ExecStart` if needed; serving the client
port below 1024 needs the `CAP_NET_BIND_SERVICE` already granted in the unit.

## 6. Verify

```sh
relay version
systemctl status relay
journalctl -u relay -f
```

A healthy relay logs `relay serving caravel clients on …`; once `coxswain` dials
in it logs `cox tunnel connected`. `coxswain`'s admin UI shows the relay's tunnel
state.

## Certificate rotation

Relay certs are valid one year and `coxswain` rotates them (DESIGN §4) by pushing a
fresh `relay.crt` and restarting the service. `relay` reads its mTLS material
once at startup, so a rotation takes effect on `systemctl restart relay`.
