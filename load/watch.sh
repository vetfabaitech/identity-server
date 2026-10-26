#!/usr/bin/env bash
# Samples the identity container every 2 s during a run (load/README.md): CPU, memory, restarts, OOM kills.
#   load/watch.sh out.csv &   ...   kill %1
set -euo pipefail
out="${1:?usage: load/watch.sh <out.csv>}"
c="${CONTAINER:-vetfab-identity-identity-1}"
echo "time,cpu,mem,restarts,oom" > "$out"
while true; do
  stats="$(docker stats --no-stream --format '{{.CPUPerc}},{{.MemUsage}}' "$c" 2>/dev/null | sed 's/ \/ .*//')"
  state="$(docker inspect "$c" --format '{{.RestartCount}},{{.State.OOMKilled}}' 2>/dev/null || echo "?,?")"
  echo "$(date +%T),$stats,$state" >> "$out"
  sleep 2
done
