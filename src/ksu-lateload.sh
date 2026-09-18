#!/system/bin/sh
# KernelSU late-load from the rooted session:
#   adb shell "/data/local/tmp/call_capset sh /data/local/tmp/ksu-lateload.sh"
# The manager APK must already be installed: the .ko verifies the manager by APK cert hash.
echo "== identity =="; id
echo "== make SELinux enforcing OFF through the kernel's own interface (we are permissive, so the
   selinuxfs write is allowed; this is the official state, not just our patched byte) =="
setenforce 0 2>&1
echo "getenforce=$(getenforce)"
echo "== module gates =="
zcat /proc/config.gz 2>/dev/null | grep -E 'MODULE_(FORCE_LOAD|SIG_FORCE)'
for s in kallsyms_lookup_name selinux_state policydb_read stop_machine; do
    printf '  %-22s %s\n' "$s" "$(grep -wm1 " $s\$" /proc/kallsyms 2>/dev/null | cut -d' ' -f1)"
done
KSUD=/data/local/tmp/ksud
chmod 755 "$KSUD"
mkdir -p /data/adb/ksu
chmod 700 /data/adb 2>/dev/null
echo "== launching ksud late-load (kmi android12-5.10) =="
"$KSUD" late-load --kmi android12-5.10 --allow-shell </dev/null >/data/local/tmp/ksud.log 2>&1 &
sleep 15
echo "== /proc/modules =="
grep -i kernelsu /proc/modules || echo "  (no kernelsu module loaded)"
echo "== ksud.log (tail) =="
tail -30 /data/local/tmp/ksud.log 2>&1
echo "== /data/adb =="
ls -la /data/adb 2>&1 | head -8
echo "== su (KernelSU's own, from this rooted session) =="
su -c id 2>&1 | head -2
