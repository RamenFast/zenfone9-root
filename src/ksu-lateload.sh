#!/system/bin/sh
# KernelSU late-load, run from the rooted session:
#   adb shell "/data/local/tmp/call_capset sh /data/local/tmp/ksu-lateload.sh"
echo "== identity =="; id
echo "== module gates =="
zcat /proc/config.gz 2>/dev/null | grep -E 'MODULE_(FORCE_LOAD|SIG_FORCE)'
for s in kallsyms_lookup_name selinux_state policydb_read stop_machine; do
    printf '  %-22s %s\n' "$s" "$(grep -wm1 " $s\$" /proc/kallsyms 2>/dev/null | cut -d' ' -f1)"
done
KSUD=/data/local/tmp/ksud
chmod 755 "$KSUD"
mkdir -p /data/adb/ksu
echo "== launching ksud late-load (kmi android12-5.10) =="
"$KSUD" late-load --kmi android12-5.10 --allow-shell </dev/null >/data/local/tmp/ksud.log 2>&1 &
sleep 12
echo "== /proc/modules =="
grep -i kernelsu /proc/modules || echo "  (no kernelsu module loaded)"
echo "== ksud.log (tail) =="
tail -25 /data/local/tmp/ksud.log 2>&1
echo "== ksud state =="
ls -l /data/adb/ksud 2>&1 | head -2
