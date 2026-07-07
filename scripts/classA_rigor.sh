#!/bin/bash
# Phase 1: ctz fwd_word validation + handler profile + bv2 h2 check.
# Phase 2: Class A rigor — 3 invocations x key heap points x configs,
# with DaCapo latency where metered (h2, lusearch).
set -u
JH=/mydata/openjdk-mmtk/build/b0test/images/jdk
DACAPO=/mydata/dacapo/dacapo-23.11/dacapo-23.11-MR2-chopin.jar
BT=/mydata/linux/tools/bpf/bpftool/bpftool
OUT=/mydata/gc-bpf-fault/results/classA/rigor
mkdir -p $OUT
cd /mydata/dacapo/dacapo-23.11

echo "### phase 1: ctz fwd_word"
baseB="MMTK_PLAN=Compressor MMTK_COMPACT_FAULTS=Bpf MMTK_COMPACT_CONCURRENT=true MMTK_NO_REFERENCE_TYPES=true MMTK_NO_FINALIZER=true"
for b in luindex fop; do
  for cfg in "bv2:MMTK_COMPACT_DEFER_FORWARD=1" "r1:MMTK_COMPACT_INKERNEL=1"; do
    n=${cfg%%:*}; e=${cfg#*:}
    r=$(timeout 300 sudo env $baseB $e $JH/bin/java -XX:+UseThirdPartyHeap -Xms512m -Xmx512m -jar $DACAPO $b 2>&1 | grep -cE "PASSED")
    echo "ctz $n $b: $([ "$r" = "1" ] && echo PASS || echo FAIL)"
  done
done
# handler profile during a bv2 h2 run
sudo env $baseB MMTK_COMPACT_DEFER_FORWARD=1 $JH/bin/java -XX:+UseThirdPartyHeap -Xms768m -Xmx768m -jar $DACAPO h2 -n 3 > $OUT/ctz_prof_run.log 2>&1 &
sleep 30
id=$(sudo $BT prog list 2>/dev/null | grep "handle_page_fault" | grep -oE "^[0-9]+" | tail -1)
echo "ctz handler profile (prog $id):"
sudo $BT prog profile id $id duration 10 cycles instructions 2>&1 | grep -E "run_cnt|cycles|instructions"
wait
grep -oE "PASSED in [0-9]+" $OUT/ctz_prof_run.log | tail -1
# bv2 h2 -n4 timing
t=$(sudo env $baseB MMTK_COMPACT_DEFER_FORWARD=1 timeout 900 $JH/bin/java -XX:+UseThirdPartyHeap -Xms768m -Xmx768m -jar $DACAPO h2 -n 4 2>&1 | grep -oE "PASSED in [0-9]+" | grep -oE "[0-9]+")
echo "RESULT ctz bv2 h2 768M: ${t:-FAIL}ms (baseline 26218)"

echo "### phase 2: Class A rigor (3 invocations)"
baseA="MMTK_PLAN=GenImmix MMTK_NO_REFERENCE_TYPES=true"
run_a() { # bench heap cfg run latencyflag
  local b=$1 h=$2 d=$3 k=$4 lat=$5 log=$OUT/${1}_${2}_${3}_run$4.log
  sudo env $baseA MMTK_DIRTY_TRACKING=$d timeout 1200 \
    $JH/bin/java -XX:+UseThirdPartyHeap -Xms$h -Xmx$h \
    -jar $DACAPO $b $lat -n 4 > $log 2>&1
  local t=$(grep -oE "PASSED in [0-9]+" $log | grep -oE "[0-9]+")
  local p=$(grep "tail latency, simple" $log | tail -1 | grep -oP "99.9% \K[0-9]+")
  echo "RESULT run=$k bench=$b heap=$h cfg=$d time_ms=${t:-FAIL} p999_us=${p:-na}"
}
for k in 1 2 3; do
  for d in Barrier Bpf; do
    run_a h2 4G $d $k --latency-csv
    run_a xalan 1664M $d $k ""
    run_a xalan 416M $d $k ""
    run_a lusearch 1216M $d $k --latency-csv
  done
  # mechanism ordering datapoints (uffd at two points, one invocation each round)
  run_a xalan 1664M Uffd $k ""
  run_a h2 4G Uffd $k --latency-csv
done
echo RIGOR_A_DONE
