#!/usr/bin/env sh
# Builds the WASM artifact next to this script and copies the matching
# wasm_exec.js loader out of the local Go toolchain (its path moved from
# misc/wasm to lib/wasm in Go 1.24).
set -eu
cd "$(dirname "$0")"

GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o radius-client-config.wasm .

GOROOT="$(go env GOROOT)"
if [ -f "$GOROOT/lib/wasm/wasm_exec.js" ]; then
	cp "$GOROOT/lib/wasm/wasm_exec.js" .
else
	cp "$GOROOT/misc/wasm/wasm_exec.js" .
fi

ls -lh radius-client-config.wasm
