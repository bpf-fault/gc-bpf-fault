#!/bin/bash
# End-to-end throughput + window stall for Compressor B.1 vs stock.
# Usage: measure_throughput_stall.sh <bench> <heap> [iters]
set -u
JH=/mydata/openjdk-mmtk/build/b0test/images/jdk
DACAPO=/mydata/dacapo/dacapo-23.11/dacapo-23.11-MR2-chopin.jar
B=${1:-h2}; H=${2:-512M}; N=${3:-5}
cd /mydata/dacapo/dacapo-23.11
for cfg in None Bpf Uffd; do
  EXTRA=""
  [ $cfg != None ] && EXTRA="MMTK_COMPACT_FAULTS=$cfg MMTK_COMPACT_CONCURRENT=true MMTK_WINDOW_STATS=1"
  out=$(sudo env MMTK_PLAN=Compressor $EXTRA MMTK_NO_REFERENCE_TYPES=true MMTK_NO_FINALIZER=true \
    timeout 900 $JH/bin/java -XX:+UseThirdPartyHeap -Xms$H -Xmx$H \
    -jar $DACAPO $B -n $N 2>&1)
  ms=$(echo "$out" | grep -oP "PASSED in \K[0-9]+" | tail -1)
  # average mutator_faults and stall ratio across windows
  faults=$(echo "$out" | grep -oP "mutator_faults=\K[0-9]+" | awk '{s+=$1;n++} END{if(n)printf "%d",s/n; else print 0}')
  spins=$(echo "$out" | grep -oP "spins/stalled-fault\)" | wc -l)
  echo "$B $cfg heap=$H last_iter=${ms}ms avg_window_faults=${faults} windows=${spins}"
done
