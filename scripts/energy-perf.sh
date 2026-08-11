#!/usr/bin/env bash
set -euo pipefail

bench_name="${1:-bench_energy}"
repeat_count="${REPEAT:-3}"

if ! command -v perf >/dev/null 2>&1; then
  echo "perf is not installed or not available on PATH." >&2
  echo "Install the Linux perf tools package for your kernel, then rerun this script." >&2
  exit 69
fi

event_available() {
  perf list 2>/dev/null | grep -Fq "$1"
}

events=(
  "cycles"
  "instructions"
  "cache-references"
  "cache-misses"
  "duration_time"
)

power_events=(
  "power/energy-pkg/"
  "power/energy-cores/"
  "power/energy-ram/"
)

power_event_found=false
for event in "${power_events[@]}"; do
  if event_available "$event"; then
    events+=("$event")
    power_event_found=true
  fi
done

if [[ "$power_event_found" == "false" ]]; then
  echo "No perf RAPL power events were detected on this machine." >&2
  echo "The run will still collect cycles/cache counters; see benchmarks/ENERGY.md for turbostat and powertop alternatives." >&2
fi

event_list="$(IFS=,; echo "${events[*]}")"

echo "Running energy-aware benchmark: cargo bench --bench ${bench_name}" >&2
echo "perf events: ${event_list}" >&2
echo "repeat count: ${repeat_count}" >&2

exec perf stat -a -r "$repeat_count" -e "$event_list" -- cargo bench --bench "$bench_name"
