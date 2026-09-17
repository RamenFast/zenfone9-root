#!/usr/bin/env bash
# build.sh — cross-compile the device tools. Requires an Android NDK (r25+).
#
#   export NDK=$HOME/Android/Sdk/ndk/27.0.12077973      # or any NDK with clang
#   scripts/build.sh
#
# Produces (in src/): cheese_pa, call_capset, pa_leak, host_kallsyms (host-native)
set -eu
DIR=$(cd "$(dirname "$0")/.." && pwd)
NDK=${NDK:?set NDK to your Android NDK path}
CLANG=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang
[ -x "$CLANG" ] || { echo "no clang at $CLANG" >&2; exit 1; }

cd "$DIR/src"
echo "== device binaries (aarch64) =="
for src in cheese_pa call_capset pa_leak; do
    [ -f "$src.c" ] || continue
    $CLANG -O2 -o "$src" "$src.c"
    echo "  built $src"
done

echo "== host tools =="
gcc -O2 -o host_kallsyms host_kallsyms.c && echo "  built host_kallsyms"

echo
echo "deploy:"
echo "  adb push src/cheese_pa src/call_capset /data/local/tmp/"
echo "  adb shell chmod 755 /data/local/tmp/cheese_pa /data/local/tmp/call_capset"
