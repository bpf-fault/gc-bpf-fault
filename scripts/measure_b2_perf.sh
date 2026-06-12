#!/bin/bash
# Class B v2 performance: forwarding during staging (baseline) vs deferred to
# install time, in userspace (uffd) vs in-kernel (bpf eBPF handler).
# Configs: bpf-nodefer | bpf-defer | uffd-defer.  Metrics: converged DaCapo
# time + avg window mutator-faults + total refs forwarded in-kernel.
# Usage: measure_b2_perf.sh <bench> <heap> [iters]
set -u
JH=/mydata/openjdk-mmtk/build/b0test/images/jdk
DACAPO=/mydata/dacapo/dacapo-23.11/dacapo-23.11-MR2-chopin.jar
B=${1:-h2}; H=${2:-768M}; N=${3:-6}
cd /mydata/dacapo/dacapo-23.11
base="MMTK_PLAN=Compressor MMTK_NO_REFERENCE_TYPES=true MMTK_NO_FINALIZER=true MMTK_WINDOW_STATS=1 MMTK_COMPACT_CONCURRENT=true"
run() {
  local name="$1" extra="$2"
  out=$(sudo env $base $extra timeout 1200 \
    $JH/bin/java -XX:+UseThirdPartyHeap -Xms$H -Xmx$H \
    -jar $DACAPO $B -n $N 2>&1)
  ms=$(echo "$out" | grep -oP "PASSED in \K[0-9]+" | tail -1)
  faults=$(echo "$out" | grep -oP "mutator_faults=\K[0-9]+" | awk '{s+=$1;n++} END{if(n)printf "%d",s/n; else print 0}')
  echo "$B $name heap=$H converged=${ms}ms avg_window_faults=${faults}"
}
echo "### Class B v2 forward-placement comparison ($B, heap=$H, -n$N) ###"
run "bpf-nodefer(stage-fwd)"  "MMTK_COMPACT_FAULTS=Bpf"
run "bpf-defer(in-kernel)"    "MMTK_COMPACT_FAULTS=Bpf MMTK_COMPACT_DEFER_FORWARD=1"
run "uffd-defer(userspace)"   "MMTK_COMPACT_FAULTS=Uffd MMTK_COMPACT_DEFER_FORWARD=1"
