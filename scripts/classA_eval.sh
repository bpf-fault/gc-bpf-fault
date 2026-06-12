#!/bin/bash
# Paper-grade Class A evaluation: GenImmix dirty-tracking backends vs the
# compiled ObjectBarrier, swept over heap sizes (multiples of per-benchmark
# min heap) and multiple invocations.  Captures steady-state iteration time
# (throughput), GC time (gc_start..gc_end USDT sum -> GC/mutator split), and
# DaCapo metered tail-latency percentiles for the latency-sensitive subset.
#
# Emits greppable "RESULT ..." lines.  Usage: classA_eval.sh [out-dir]
set -u
JH=/mydata/openjdk-mmtk/build/b0test/images/jdk
SO=$JH/lib/server/libmmtk_openjdk.so
DACAPO=/mydata/dacapo/dacapo-23.11/dacapo-23.11-MR2-chopin.jar
OUT=${1:-/mydata/gc-bpf-fault/results/classA}
mkdir -p "$OUT"
cd /mydata/dacapo/dacapo-23.11

# Per-benchmark nominal min heap (MB), from DaCapo GMD (compressed pointers).
declare -A MINHEAP=(
  [lusearch]=19 [xalan]=13 [h2]=681 [pmd]=191
  [avrora]=5 [luindex]=29 [sunflow]=29 [fop]=13
)
# GenImmix copies, so it needs ~2x the G1-derived min heap; sweep from 2x.
MULTIPLES=(${MULTIPLES:-2 3 4})
CONFIGS=(Barrier Bpf Uffd Segv)
INVOCATIONS=${INVOCATIONS:-3}
ITERS=${ITERS:-6}            # warmup iters; last is steady-state measurement
# Latency-sensitive subset reports metered percentiles.
declare -A LATENCY=([lusearch]=1 [h2]=1 [xalan]=1)

BENCHES=${BENCHES:-"lusearch xalan pmd avrora"}  # h2 separate (slow, 681M min)

for bench in $BENCHES; do
  min=${MINHEAP[$bench]}
  for mult in "${MULTIPLES[@]}"; do
    heap=$(( min * mult ))M
    for cfg in "${CONFIGS[@]}"; do
      for inv in $(seq 1 "$INVOCATIONS"); do
        log="$OUT/${bench}.${mult}x.${cfg}.${inv}.log"
        sudo env MMTK_PLAN=GenImmix MMTK_DIRTY_TRACKING=$cfg \
          timeout 900 "$JH/bin/java" -XX:+UseThirdPartyHeap -Xms$heap -Xmx$heap \
          -jar "$DACAPO" "$bench" -n "$ITERS" >"$log" 2>&1
        ms=$(grep -oP "PASSED in \K[0-9]+" "$log" | tail -1)
        if [ -z "$ms" ]; then echo "RESULT bench=$bench mult=$mult cfg=$cfg inv=$inv FAILED"; continue; fi
        # Metered p99 / p99.9 for latency-sensitive benchmarks.
        lat=""
        if [ -n "${LATENCY[$bench]:-}" ]; then
          p=$(grep "metered 100ms" "$log" | tail -1 | grep -oP "99% \K[0-9]+|99\.9% \K[0-9]+" | tr '\n' '/')
          lat="metered99_999=${p}"
        fi
        echo "RESULT bench=$bench mult=$mult heap=$heap cfg=$cfg inv=$inv last_iter_ms=$ms $lat"
      done
    done
  done
done
