#!/bin/bash
# Paper-grade rigor for the Class B headline: (1) pause probe on fixed
# Bv2/R1; (2) 5 interleaved invocations of the 6-config h2 768M matrix;
# (3) heap-sweep rows (1536M/3072M) for fixed Bv2/R1.
set -u
JH=/mydata/openjdk-mmtk/build/b0test/images/jdk
JVM=$JH/lib/server/libjvm.so
DACAPO=/mydata/dacapo/dacapo-23.11/dacapo-23.11-MR2-chopin.jar
OUT=/mydata/gc-bpf-fault/results/classB/rigor
mkdir -p $OUT
cd /mydata/dacapo/dacapo-23.11
base="MMTK_PLAN=Compressor MMTK_NO_REFERENCE_TYPES=true MMTK_NO_FINALIZER=true"
declare -A C=(
  [stock]=""
  [b1]="MMTK_COMPACT_FAULTS=Bpf MMTK_COMPACT_CONCURRENT=true"
  [bv2]="MMTK_COMPACT_FAULTS=Bpf MMTK_COMPACT_CONCURRENT=true MMTK_COMPACT_DEFER_FORWARD=1"
  [r1]="MMTK_COMPACT_FAULTS=Bpf MMTK_COMPACT_CONCURRENT=true MMTK_COMPACT_INKERNEL=1"
  [uffd_b1]="MMTK_COMPACT_FAULTS=Uffd MMTK_COMPACT_CONCURRENT=true"
  [uffd_defer]="MMTK_COMPACT_FAULTS=Uffd MMTK_COMPACT_CONCURRENT=true MMTK_COMPACT_DEFER_FORWARD=1"
)

echo "### phase 1: pauses (fixed bv2/r1, h2 768M -n2)"
for c in bv2 r1; do
  echo "=== pauses: $c ==="
  sudo env $base ${C[$c]} timeout 900 bpftrace -e "
    uprobe:$JVM:_ZL22mmtk_stop_all_mutatorsPv14MutatorClosure { @t = nsecs; }
    uprobe:$JVM:_ZL20mmtk_resume_mutatorsPv /@t/ {
      \$us = (nsecs - @t) / 1000;
      @max_us = max(\$us); @avg_us = avg(\$us); @gcs = count();
      delete(@t);
    }
  " -c "$JH/bin/java -XX:+UseThirdPartyHeap -Xms768m -Xmx768m -jar $DACAPO h2 -n 2" \
    2>&1 | grep -E "^@(max_us|avg_us|gcs)|PASSED|FAILED"
done

echo "### phase 2: 5 interleaved invocations, 6 configs, h2 768M -n4"
for k in 1 2 3 4 5; do
  for c in stock b1 bv2 r1 uffd_b1 uffd_defer; do
    log=$OUT/h2_768M_${c}_run$k.log
    sudo env $base ${C[$c]} timeout 1500 \
      $JH/bin/java -XX:+UseThirdPartyHeap -Xms768m -Xmx768m \
      -jar $DACAPO h2 --latency-csv -n 4 > $log 2>&1
    t=$(grep -oE "PASSED in [0-9]+" $log | grep -oE "[0-9]+")
    p=$(grep "tail latency, simple" $log | tail -1 | grep -oP "99.9% \K[0-9]+")
    echo "RESULT run=$k cfg=$c time_ms=${t:-FAIL} p999_us=${p:-na}"
  done
done

echo "### phase 3: heap-sweep rows for fixed bv2/r1"
for h in 1536M 3072M; do
  for c in bv2 r1; do
    log=$OUT/h2_${h}_${c}.log
    sudo env $base ${C[$c]} timeout 1500 \
      $JH/bin/java -XX:+UseThirdPartyHeap -Xms$h -Xmx$h \
      -jar $DACAPO h2 --latency-csv -n 4 > $log 2>&1
    t=$(grep -oE "PASSED in [0-9]+" $log | grep -oE "[0-9]+")
    p=$(grep "tail latency, simple" $log | tail -1 | grep -oP "99.9% \K[0-9]+")
    echo "RESULT heap=$h cfg=$c time_ms=${t:-FAIL} p999_us=${p:-na}"
  done
done
echo RIGOR_DONE
