#!/bin/bash
set -u
JH=/mydata/openjdk-mmtk/build/b0test/images/jdk
D=/mydata/dacapo/dacapo-23.11/dacapo-23.11-MR2-chopin.jar
cd /mydata/dacapo/dacapo-23.11
declare -A MIN=([lusearch]=19 [xalan]=13)
for b in lusearch xalan; do
  for heap in $(( MIN[$b]*128 ))M $(( MIN[$b]*256 ))M 4096M; do
    for cfg in Barrier Bpf Uffd; do
      best=999999
      for inv in 1 2; do
        ms=$(sudo env MMTK_PLAN=GenImmix MMTK_DIRTY_TRACKING=$cfg timeout 900 \
          "$JH/bin/java" -XX:+UseThirdPartyHeap -Xms$heap -Xmx$heap \
          -jar "$D" "$b" -n 6 2>&1 | grep -oP "PASSED in \K[0-9]+")
        [ -n "$ms" ] && [ "$ms" -lt "$best" ] && best=$ms
      done
      echo "XCROSS bench=$b heap=$heap cfg=$cfg ms=$best"
    done
  done
done
