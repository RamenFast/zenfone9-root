#!/usr/bin/env bash
# verify-backup.sh — md5-verify pulled Zenfone backup against on-device originals
# usage: verify-backup.sh <backup-dir> [serial]
set -u
BACKUP="${1:?usage: verify-backup.sh <backup-dir> [serial]}"
SERIAL="${2:-<SERIAL>}"
fail=0; total=0
while IFS= read -r rel; do
  [ -n "$rel" ] || continue
  total=$((total+1))
  remote=$(adb -s "$SERIAL" shell "md5sum '/sdcard/$rel'" 2>/dev/null </dev/null | awk '{print $1}')
  local_md=$(md5sum "$BACKUP/$rel" </dev/null | awk '{print $1}')
  if [ "$remote" = "$local_md" ]; then
    echo "OK   $rel"
  else
    echo "FAIL $rel  remote=$remote local=$local_md"
    fail=$((fail+1))
  fi
done < <(cd "$BACKUP" && find . -type f -printf '%P\n' | sort)
echo "checked=$total failures=$fail"
exit $(( fail > 0 ))
