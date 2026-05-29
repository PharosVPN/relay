# Deploying a remote beacon relay

This guide covers running `beacon` as a **remote** relay on a public host.

The **embedded** relay needs no deployment — `coxswain` runs it in-process by
importing the `relay` package ([docs/COXSWAIN-INTEGRATION.md](COXSWAIN-INTEGRATION.md)).
Deploy a remote relay only when the controller sits behind NAT and must serve
caravel clients from a public address (DESIGN §2).

A remote `beacon` is a single static binary. It holds no database, writes
nothing at runtime, and makes **no outbound connections** — `coxswain` dials in to
it and caravel clients dial in to it.

---

## 1. Build

```sh
GOOS=linux GOARCH=amd64 make build      # → dist/beacon
```

`beacon` has no cgo dependencies, so the result is a static binary that runs on
any Linux host of that architecture. Drop `GOOS`/`GOARCH` to build for the
current platform. `make build` stamps the version from `git describe`.

## 2. Prepare the host

```sh
# Unprivileged service account — owns /etc/beacon and the private key.
useradd --system --no-create-home --shell /usr/sbin/nologin beacon
install -d -o beacon -g beacon -m 0750 /etc/beacon

# The binary.
install -m 0755 dist/beacon /usr/local/bin/beacon
```

## 3. Enrol with coxswain (CSR-over-SSH)

Enrolment mirrors `buoy` node onboarding — CSR-over-SSH, no bootstrap token
(DESIGN §5, decision 14). `coxswain` automates the steps below over SSH; the
manual equivalent is:

1. **Generate the keypair and a CSR.** Run as the `beacon` user so the private
   key is owned by the service account:

   ```sh
   sudo -u beacon beacon gen-csr --config-dir /etc/beacon
   ```

   This writes `/etc/beacon/relay.key` (mode `0600`, never leaves the host)
   and prints a PKCS#10 CSR to stdout. Re-running it is idempotent.

2. **Hand the CSR to coxswain.** `coxswain` signs it with the Fleet CA, assigning the
   relay's identity itself — `Organization="PharosVPN Relay"`, dual
   ServerAuth+ClientAuth EKU, and the public-endpoint DNS SAN (a relay host
   does not self-assert these; see coxswain/BUILD.md, "Relay enrollment contract").

3. **Install the material coxswain returns** — owned by `beacon`:

   ```sh
   install -o beacon -g beacon -m 0644 relay.crt     /etc/beacon/relay.crt
   install -o beacon -g beacon -m 0644 fleet-ca.crt  /etc/beacon/fleet-ca.crt
   install -o beacon -g beacon -m 0644 device-ca.crt /etc/beacon/device-ca.crt
   ```

`/etc/beacon` then holds: `relay.key`, `relay.crt` (relay leaf + Fleet
intermediate), `fleet-ca.crt`, `device-ca.crt`.

## 4. Install the service

```sh
install -m 0644 deploy/beacon.service /etc/systemd/system/beacon.service
systemctl daemon-reload
systemctl enable --now beacon
```

The unit runs `beacon run --config-dir /etc/beacon` as the `beacon` user under
a strict sandbox (see [`deploy/beacon.service`](../deploy/beacon.service)).

## 5. Networking

Open **inbound** TCP only — `beacon` initiates nothing:

| Port | Flag | Reached by |
|---|---|---|
| client | `--client-addr` (default `:8443`) | caravel clients |
| tunnel | `--tunnel-addr` (default `:8444`) | `coxswain` dialling in |

Override the defaults in the unit's `ExecStart` if needed; serving the client
port below 1024 needs the `CAP_NET_BIND_SERVICE` already granted in the unit.

## 6. Verify

```sh
beacon version
systemctl status beacon
journalctl -u beacon -f
```

A healthy relay logs `relay serving caravel clients on …`; once `coxswain` dials
in it logs `cox tunnel connected`. `coxswain`'s admin UI shows the relay's tunnel
state.

## Certificate rotation

Relay certs are valid one year and `coxswain` rotates them (DESIGN §4) by pushing a
fresh `relay.crt` and restarting the service. `beacon` reads its mTLS material
once at startup, so a rotation takes effect on `systemctl restart beacon`.
