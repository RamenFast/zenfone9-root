#!/system/bin/sh
# proof.sh — runs AS ROOT (uid 0, kernel domain). Demonstrates root-only operations
# and renders an on-screen proof page. Executed via: call_capset sh /data/local/tmp/proof.sh
OUT=/data/local/tmp/root-proof.txt
HTML=/sdcard/root-proof.html

{
  echo "=== ROOT PROOF — ASUS Zenfone 9 (AI2202) ==="
  echo
  echo "\$ id"
  id
  echo
  echo "\$ getenforce"
  getenforce
  echo
  echo "\$ cat /proc/kallsyms | head -3     # normally denied to shell"
  head -3 /proc/kallsyms
  echo
  echo "\$ ls /data/data | head -5          # normally denied to shell"
  ls /data/data | head -5
  echo
  echo "\$ ls /dev/block/by-name | head -5  # normally denied to shell"
  ls /dev/block/by-name | head -5
  echo
  echo "chain: CVE-2025-21479 (GPU TTBR0 hijack) -> perf PA leak -> arbitrary physical R/W"
  echo "       -> __do_sys_capset patched with commit_creds(&init_cred) -> uid 0"
} > "$OUT" 2>&1

cat "$OUT"

{
  echo '<!doctype html><meta charset=utf-8><body style="background:#0b0f14;color:#d7ffe0;'
  echo 'font-family:monospace;font-size:26px;padding:28px;line-height:1.45">'
  echo '<div style="font-size:52px;color:#57ff8a;font-weight:bold">&#10003; ROOT</div>'
  echo '<div style="color:#8ab4f8;margin-bottom:18px">uid=0(root) &middot; context=u:r:kernel:s0 &middot; ASUS Zenfone 9 (AI2202)</div>'
  echo '<pre style="white-space:pre-wrap">'
  sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' "$OUT"
  echo '</pre></body>'
} > "$HTML"
chmod 644 "$HTML"

cmd notification post -S bigtext -t "su" "root" \
  "root granted: uid=0(root) context=u:r:kernel:s0 (CVE-2025-21479)" >/dev/null 2>&1
echo "[proof] wrote $OUT and $HTML"
