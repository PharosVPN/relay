# Contributing to beacon

Thanks for helping build PharosVPN. Before you start, read
[`docs/DESIGN.md`](https://github.com/PharosVPN/docs/blob/main/DESIGN.md) — the
platform's single source of truth — and this repo's [BUILD.md](BUILD.md).

## Developer Certificate of Origin (DCO)

PharosVPN takes contributions under the
[Developer Certificate of Origin](https://developercertificate.org/). There is
**no CLA** — there is no plan to relicense.

Every commit must be signed off, certifying you wrote the change or have the
right to submit it under the project's licence:

```
git commit -s
```

This appends a `Signed-off-by: Your Name <you@example.com>` trailer. The name
and email must be real and match your `git config user.name` / `user.email`.

## Workflow

- Branch from `main`; never commit straight to `main`. Open a PR.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `perf:`, `refactor:`, `test:`, `chore:`).
- If the design is silent or contradictory on something you need, stop and
  raise it — do not invent a contract. Update `docs/DESIGN.md` in the same PR.

## Wire contracts

`beacon` does not own a wire contract. The beacon↔helm reverse-tunnel and
relayed-client protos are owned by `helm` and published in `docs/proto/`;
`beacon` builds against them and never forks them (docs/BUILD.md §3).

## Reused code — rebrand obligation

`beacon`'s transparent-proxy and reverse-tunnel machinery is lifted from a
private predecessor project (docs/BUILD.md §4, DESIGN decision 13). Any further
lift must strip **every** identifier of the origin project — package paths,
type names, metadata keys, comments, file names. This repo contains zero trace
of it; keep it that way.

## Quality bar

Before opening a PR, make sure:

```
gofmt -l .          # no output
go vet ./...        # clean
go test -race ./... # green
golangci-lint run   # clean
```

Add unit tests for logic and integration tests for anything crossing mTLS.
Never commit secrets — not even in test fixtures.

## Licence

beacon is licensed **AGPL-3.0-or-later**. Every source file carries the SPDX
header:

```
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors
```
