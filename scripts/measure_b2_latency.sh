#!/bin/bash
# Class B v2: tail-latency comparison (where in-kernel fault handling should
# win, vs throughput which is parity).  Parses DaCapo's "simple" tail latency
# (per-event, no smoothing) of the converged iteration; reports median over K
# runs of the GC-sensitive tail percentiles (99.9% / 99.99% / max), in usec.
# Usage: measure_b2_latency.sh <bench> <heap> [n_iters] [k_runs]
set -u
JH=/mydata/openjdk-mmtk/build/b0test/images/jdk
DACAPO=/mydata/dacapo/dacapo-23.11/dacapo-23.11-MR2-chopin.jar
B=${1:-lusearch}; H=${2:-384M}; N=${3:-4}; K=${4:-5}
cd /mydata/dacapo/dacapo-23.11
base="MMTK_PLAN=Compressor MMTK_NO_REFERENCE_TYPES=true MMTK_NO_FINALIZER=true MMTK_COMPACT_CONCURRENT=true"
declare -A C=(
  [nodefer]="MMTK_COMPACT_FAULTS=Bpf"
  [bpfdefer]="MMTK_COMPACT_FAULTS=Bpf MMTK_COMPACT_DEFER_FORWARD=1"
  [uffddefer]="MMTK_COMPACT_FAULTS=Uffd MMTK_COMPACT_DEFER_FORWARD=1"
)
# accumulate "p999 p9999 max" per run
declare -A P999 P9999 PMAX
for c in nodefer bpfdefer uffddefer; do P999[$c]=""; P9999[$c]=""; PMAX[$c]=""; done
for k in $(seq 1 $K); do
  for c in nodefer bpfdefer uffddefer; do
    line=$(sudo env $base ${C[$c]} timeout 600 \
      $JH/bin/java -XX:+UseThirdPartyHeap -Xms$H -Xmx$H \
      -jar $DACAPO $B --latency-csv -n $N 2>&1 | grep "tail latency, simple" | tail -1)
    p999=$(echo "$line"  | grep -oP "99.9% \K[0-9]+")
    p9999=$(echo "$line" | grep -oP "99.99% \K[0-9]+")
    pmax=$(echo "$line"  | grep -oP "max \K[0-9]+")
    P999[$c]="${P999[$c]} ${p999:-0}"; P9999[$c]="${P9999[$c]} ${p9999:-0}"; PMAX[$c]="${PMAX[$c]} ${pmax:-0}"
  done
done
med() { echo "$1" | tr ' ' '\n' | grep -v '^$' | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }
echo "### $B heap=$H tail latency (usec, median of $K), simple ###"
printf "%-10s %12s %12s %12s\n" config "99.9%" "99.99%" "max"
for c in nodefer bpfdefer uffddefer; do
  printf "%-10s %12s %12s %12s\n" "$c" "$(med "${P999[$c]}")" "$(med "${P9999[$c]}")" "$(med "${PMAX[$c]}")"
done
