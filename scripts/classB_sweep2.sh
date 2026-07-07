#!/bin/bash
# Class B heap sweep + metered latency: h2 -n4 at {768M,1536M,3072M} and
# xalan 1G -n4, each under stock / B.1 / Bv2 / R1.  Captures full DaCapo
# output per run (results/classB/sweep2/); prints a summary of last-iter
# time + converged "tail latency, simple" percentiles.
# Hypothesis: defer modes (Bv2/R1) cross over once windows have slack
# (fewer GCs at larger heaps -> no window-drain queuing).
set -u
JH=/mydata/openjdk-mmtk/build/b0test/images/jdk
DACAPO=/mydata/dacapo/dacapo-23.11/dacapo-23.11-MR2-chopin.jar
OUT=/mydata/gc-bpf-fault/results/classB/sweep2
mkdir -p $OUT
cd /mydata/dacapo/dacapo-23.11
base="MMTK_PLAN=Compressor MMTK_NO_REFERENCE_TYPES=true MMTK_NO_FINALIZER=true"
declare -A C=(
  [stock]=""
  [b1]="MMTK_COMPACT_FAULTS=Bpf MMTK_COMPACT_CONCURRENT=true"
  [bv2]="MMTK_COMPACT_FAULTS=Bpf MMTK_COMPACT_CONCURRENT=true MMTK_COMPACT_DEFER_FORWARD=1"
  [r1]="MMTK_COMPACT_FAULTS=Bpf MMTK_COMPACT_CONCURRENT=true MMTK_COMPACT_INKERNEL=1"
)
run() { # bench heap cfg
  local b=$1 h=$2 c=$3 log=$OUT/${1}_${2}_${3}.log
  sudo env $base ${C[$c]} timeout 1500 \
    $JH/bin/java -XX:+UseThirdPartyHeap -Xms$h -Xmx$h \
    -jar $DACAPO $b --latency-csv -n 4 > $log 2>&1
  local t=$(grep -oE "PASSED in [0-9]+" $log | grep -oE "[0-9]+")
  local lat=$(grep "tail latency, simple" $log | tail -1 | sed 's/=====//g')
  echo "RESULT $b heap=$h cfg=$c time_ms=${t:-FAIL} ${lat:-nolat}"
}
for h in 768M 1536M 3072M; do
  for c in stock b1 bv2 r1; do run h2 $h $c; done
done
for c in stock b1 bv2 r1; do run xalan 1G $c; done
echo SWEEP2_DONE
