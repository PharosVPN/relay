#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build relay with the version from VERSION injected at link time.
#   scripts/build.sh [output-path]
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="$(tr -d '[:space:]' < VERSION)"
go build -ldflags "-X github.com/PharosVPN/relay/internal/cli.version=$VERSION" -o "${1:-bin/relay}" ./cmd/relay
echo "built relay $VERSION -> ${1:-bin/relay}"
