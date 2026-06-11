#!/bin/bash
# Quick Class A performance comparison: last-iteration time of -n 6 runs,
# 2 invocations per (benchmark, config). NOT paper-grade (no PGO, single
# heap size) — directional numbers only.
set -u
JH=/mydata/openjdk-mmtk/build/linux-x86_64-server-release/images/jdk
DACAPO=/mydata/dacapo/dacapo-23.11/dacapo-23.11-MR2-chopin.jar
OUT=${1:-/mydata/gc-bpf-fault/results/perf_quick}
mkdir -p "$OUT"
for bench in lusearch xalan h2 pmd; do
  for cfg in Barrier Bpf Uffd Segv; do
    for inv in 1 2; do
      log="$OUT/${bench}.${cfg}.${inv}.log"
      sudo MMTK_PLAN=GenImmix MMTK_DIRTY_TRACKING=$cfg \
        timeout 900 "$JH/bin/java" -XX:+UseThirdPartyHeap -Xms4G -Xmx4G \
        -jar "$DACAPO" "$bench" -n 6 > "$log" 2>&1
      msec=$(grep -oP "PASSED in \K[0-9]+" "$log" || echo FAIL)
      echo "$bench $cfg inv$inv ${msec}ms"
    done
  done
done
