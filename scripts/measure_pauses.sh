#!/bin/bash
# Measure GC pause distribution (gc_start..gc_end USDT) for Compressor
# configs: stock STW vs concurrent install (Bpf/Uffd).
# Usage: measure_pauses.sh <benchmark> <heap> [iterations]
set -u
BENCH=${1:-xalan}
HEAP=${2:-1G}
N=${3:-3}
JH=/mydata/openjdk-mmtk/build/b0test/images/jdk
JVM=$JH/lib/server/libjvm.so
DACAPO=/mydata/dacapo/dacapo-23.11/dacapo-23.11-MR2-chopin.jar

cd /mydata/dacapo/dacapo-23.11
for cfg in None Bpf Uffd; do
  EXTRA=""
  [ $cfg != None ] && EXTRA="MMTK_COMPACT_FAULTS=$cfg MMTK_COMPACT_CONCURRENT=true"
  echo "=== $BENCH $cfg heap=$HEAP ==="
  sudo env MMTK_PLAN=Compressor $EXTRA \
    MMTK_NO_REFERENCE_TYPES=true MMTK_NO_FINALIZER=true \
    timeout 900 bpftrace -e "
      uprobe:$JVM:_ZL22mmtk_stop_all_mutatorsPv14MutatorClosure { @t = nsecs; }
      uprobe:$JVM:_ZL20mmtk_resume_mutatorsPv /@t/ {
        \$us = (nsecs - @t) / 1000;
        @pause_us = hist(\$us);
        @max_us = max(\$us);
        @avg_us = avg(\$us);
        @gcs = count();
        delete(@t);
      }
    " -c "$JH/bin/java -XX:+UseThirdPartyHeap -Xms$HEAP -Xmx$HEAP -jar $DACAPO $BENCH -n $N" \
    2>&1 | grep -E "^@|\[[0-9]" | head -30
done
