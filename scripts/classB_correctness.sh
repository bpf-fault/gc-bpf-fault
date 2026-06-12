#!/bin/bash
# Steal-mode correctness across DaCapo (concurrent compaction is
# concurrency-heavy; broad coverage). Stable heaps per benchmark.
set -u
JH=/mydata/openjdk-mmtk/build/b0test/images/jdk
D=/mydata/dacapo/dacapo-23.11/dacapo-23.11-MR2-chopin.jar
cd /mydata/dacapo/dacapo-23.11
for b in fop pmd luindex avrora xalan sunflow; do
  for cfg in Bpf Uffd; do
    r=$(sudo env MMTK_PLAN=Compressor MMTK_COMPACT_FAULTS=$cfg MMTK_COMPACT_CONCURRENT=true \
      MMTK_NO_REFERENCE_TYPES=true MMTK_NO_FINALIZER=true \
      timeout 600 $JH/bin/java -XX:+UseThirdPartyHeap -Xms1G -Xmx1G \
      -jar $D $b -n 3 2>&1 | grep -oE "PASSED|dumped|STUCK|FAILED" | tail -1)
    echo "$b $cfg: ${r:-NO-OUTPUT}"
  done
done
