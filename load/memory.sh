#!/usr/bin/env bash
# Samples where the identity container's memory goes, every 2 s (load/README.md): the cgroup's total, anonymous
# (heap, argon2 working memory) and file-backed (the Python runtime's mapped files) pages, the process's RSS and
# thread count, and the limit. Columns are MiB.
#   load/memory.sh out.csv &   ...   kill %1
set -euo pipefail
out="${1:?usage: load/memory.sh <out.csv>}"
c="${CONTAINER:-vetfab-identity-identity-1}"
echo "time,total,anon,file,rss,threads,limit" > "$out"
while true; do
  docker exec "$c" sh -c '
    cur=$(cat /sys/fs/cgroup/memory.current); max=$(cat /sys/fs/cgroup/memory.max)
    anon=$(awk "/^anon /{print \$2}" /sys/fs/cgroup/memory.stat); file=$(awk "/^file /{print \$2}" /sys/fs/cgroup/memory.stat)
    pid=$(ls /proc | grep -E "^[0-9]+$" | while read p; do grep -q uvicorn /proc/$p/cmdline 2>/dev/null && echo $p && break; done)
    rss=$(awk "/VmRSS/{print \$2*1024}" /proc/$pid/status); threads=$(awk "/Threads/{print \$2}" /proc/$pid/status)
    printf "%d,%d,%d,%d,%d,%s\n" $((cur/1048576)) $((anon/1048576)) $((file/1048576)) $((rss/1048576)) $threads \
      "$( [ "$max" = max ] && echo max || echo $((max/1048576)) )"' 2>/dev/null | sed "s/^/$(date +%T),/" >> "$out" || true
  sleep 2
done
