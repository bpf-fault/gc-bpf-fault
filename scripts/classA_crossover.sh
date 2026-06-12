#!/bin/bash
# Class A heap-size crossover: page-WP barrier (Bpf) vs compiled barrier,
# swept across heap sizes to show where the per-GC re-arming cost flips
# from losing (tight heap, frequent GC) to winning (large heap, rare GC).
set -u
JH=/mydata/openjdk-mmtk/build/b0test/images/jdk
D=/mydata/dacapo/dacapo-23.11/dacapo-23.11-MR2-chopin.jar
cd /mydata/dacapo/dacapo-23.11
declare -A MIN=([lusearch]=19 [xalan]=13)
for b in lusearch xalan; do
  for mult in 2 4 8 16 32 64; do
    heap=$(( MIN[$b] * mult ))M
    for cfg in Barrier Bpf; do
      best=999999
      for inv in 1 2; do
        ms=$(sudo env MMTK_PLAN=GenImmix MMTK_DIRTY_TRACKING=$cfg timeout 600 \
          $JH/bin/java -XX:+UseThirdPartyHeap -Xms$heap -Xmx$heap \
          -jar $D $b -n 6 2>&1 | grep -oP "PASSED in \K[0-9]+")
        [ -n "$ms" ] && [ "$ms" -lt "$best" ] && best=$ms
      done
      echo "CROSS bench=$b mult=${mult}x heap=$heap cfg=$cfg ms=$best"
    done
  done
done
