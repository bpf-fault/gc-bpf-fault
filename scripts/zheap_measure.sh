#!/bin/bash
# RSS/PSS + time: stock GenImmix vs MMTK_ZHEAP on h2 at large heap.
JDK=/mydata/openjdk-mmtk/build/b0test/images/jdk
JAR=/mydata/dacapo/dacapo-23.11/dacapo-23.11-MR2-chopin.jar
OUT=${1:-/mydata/gc-bpf-fault/results/zheap}
mkdir -p $OUT
run() { # name env...
  local name=$1; shift
  ( timeout 900 sudo env MMTK_PLAN=GenImmix "$@" $JDK/bin/java -XX:+UseThirdPartyHeap \
      -Xms2048m -Xmx2048m -jar $JAR h2 -n 4 -s large > $OUT/$name.log 2>&1 ) &
  local outer=$!
  sleep 3
  local pid=$(pgrep -n -f "UseThirdPartyHeap.*h2" )
  : > $OUT/$name.rss
  while kill -0 $outer 2>/dev/null; do
    if [ -n "$pid" ] && [ -r /proc/$pid/smaps_rollup ]; then
      echo "$(date +%s.%N) $(sudo awk '/^Rss:/{r=$2}/^Pss:/{p=$2}END{print r, p}' /proc/$pid/smaps_rollup 2>/dev/null)" >> $OUT/$name.rss
    fi
    sleep 0.5
  done
  wait $outer
  grep -E "PASSED|FAILED|in [0-9]+ msec" $OUT/$name.log | tail -6 > $OUT/$name.summary
}
run stock
run zheap MMTK_ZHEAP=2 MMTK_ZHEAP_LOG=1
for n in stock zheap; do
  echo "== $n =="; cat $OUT/$n.summary
  awk '{if($2>m)m=$2; s+=$2; c++} END{printf "RSS maxMB=%.0f avgMB=%.0f samples=%d\n", m/1024, s/c/1024, c}' $OUT/$n.rss
done
