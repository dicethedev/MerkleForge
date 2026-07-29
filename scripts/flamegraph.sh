#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <bench_name> [cargo-flamegraph args...]" >&2
  echo "Example: $0 baseline_construction" >&2
  exit 64
fi

bench_name="$1"
shift

if ! command -v cargo-flamegraph >/dev/null 2>&1 && ! cargo flamegraph --help >/dev/null 2>&1; then
  echo "cargo-flamegraph is not installed." >&2
  echo "Install it with: cargo install flamegraph" >&2
  exit 69
fi

cargo flamegraph --bench "$bench_name" "$@" -- --bench
