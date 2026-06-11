#!/bin/bash
# Correctness sweep: DaCapo subset x dirty-tracking configs.
# Usage: correctness_sweep.sh [output-dir]
set -u
JH=/mydata/openjdk-mmtk/build/linux-x86_64-server-release/images/jdk
DACAPO=/mydata/dacapo/dacapo-23.11/dacapo-23.11-MR2-chopin.jar
OUT=${1:-/mydata/gc-bpf-fault/results/correctness}
mkdir -p "$OUT"
BENCHES="avrora fop h2 jython luindex lusearch pmd sunflow xalan zxing"
CONFIGS="Barrier Bpf Uffd Segv"

for bench in $BENCHES; do
  for cfg in $CONFIGS; do
    log="$OUT/${bench}.${cfg}.log"
    sudo MMTK_PLAN=GenImmix MMTK_DIRTY_TRACKING=$cfg \
      timeout 600 "$JH/bin/java" -XX:+UseThirdPartyHeap -Xms4G -Xmx4G \
      -jar "$DACAPO" "$bench" -n 2 > "$log" 2>&1
    if grep -q "PASSED" "$log"; then
      echo "PASS $bench $cfg"
    else
      echo "FAIL $bench $cfg ($(tail -1 "$log" | head -c 100))"
    fi
  done
done
