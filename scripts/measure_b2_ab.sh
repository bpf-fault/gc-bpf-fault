#!/bin/bash
# Class B v2: clean interleaved A/B of forward placement, best-of-K to damp
# the shared node's load noise.  Reports min and median converged time.
# Usage: measure_b2_ab.sh <bench> <heap> [n_iters] [k_runs]
set -u
JH=/mydata/openjdk-mmtk/build/b0test/images/jdk
DACAPO=/mydata/dacapo/dacapo-23.11/dacapo-23.11-MR2-chopin.jar
B=${1:-pmd}; H=${2:-512M}; N=${3:-4}; K=${4:-5}
cd /mydata/dacapo/dacapo-23.11
base="MMTK_PLAN=Compressor MMTK_NO_REFERENCE_TYPES=true MMTK_NO_FINALIZER=true MMTK_COMPACT_CONCURRENT=true"
declare -A C=(
  [nodefer]="MMTK_COMPACT_FAULTS=Bpf"
  [bpfdefer]="MMTK_COMPACT_FAULTS=Bpf MMTK_COMPACT_DEFER_FORWARD=1"
  [uffddefer]="MMTK_COMPACT_FAULTS=Uffd MMTK_COMPACT_DEFER_FORWARD=1"
)
declare -A R
for c in nodefer bpfdefer uffddefer; do R[$c]=""; done
for k in $(seq 1 $K); do
  for c in nodefer bpfdefer uffddefer; do   # interleave so load hits all equally
    ms=$(sudo env $base ${C[$c]} timeout 600 \
      $JH/bin/java -XX:+UseThirdPartyHeap -Xms$H -Xmx$H \
      -jar $DACAPO $B -n $N 2>&1 | grep -oP "PASSED in \K[0-9]+" | tail -1)
    R[$c]="${R[$c]} ${ms:-0}"
  done
done
echo "### $B heap=$H (-n$N, best-of-$K interleaved) ###"
for c in nodefer bpfdefer uffddefer; do
  echo "${R[$c]}" | tr ' ' '\n' | grep -v '^$' | sort -n | \
    awk -v c="$c" '{a[NR]=$1} END{n=NR; printf "%-10s min=%dms median=%dms  (%s)\n", c, a[1], a[int((n+1)/2)], "'"${R[$c]}"'"}'
done
