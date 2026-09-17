# KernelSU on a bootloader-locked Zenfone 9 — plan

Goal: replace the "SuperSU experience" with **KernelSU** (the modern root manager) on a device whose
bootloader cannot be unlocked. Boot-image patching is therefore impossible, so the only viable route is
**late-load / LKM mode**: from a session that already has temporary root, load the KernelSU kernel
module with `insmod`-equivalent machinery and then install the manager app.

## Why plain `insmod` won't work

Every prebuilt `.ko` records a fixed vermagic (e.g. `5.10.252-dirty …`), which will never equal this
device's `5.10.205-android12-9-00029-g3f12df86bfdb-ab11799032`. They also have ~200 undefined symbols
(`kallsyms_lookup_name`, `selinux_state`, `policydb_*`, `stop_machine`, …) and an empty `__versions`.
`ksud`'s loader handles both: it relocates undefined symbols itself from `/proc/kallsyms` (marking them
`SHN_ABS`), calls `init_module()`, and if the kernel complains about the vermagic it rewrites the
`.modinfo` string in memory and retries. So: **use `ksud late-load`, not `insmod`.**
`insmod -f` is not a substitute — it needs `CONFIG_MODULE_FORCE_LOAD=y` in the target kernel (GKI does
not set it) and does nothing about the unresolved symbols.

The one hard gate that can still stop this: `CONFIG_MODULE_SIG_FORCE=y` (a signature rejection has no
fallback). Check that first.

## Pre-flight checks (read-only, from the rooted session)

```sh
echo 1 > /proc/sys/kernel/kptr_restrict
zcat /proc/config.gz | grep -E 'MODULE_(FORCE_LOAD|SIG_FORCE)|KPROBES|KALLSYMS_ALL|CFI_CLANG'
grep -wE 'sys_call_table|kallsyms_lookup_name|selinux_state|policydb_read' /proc/kallsyms
getenforce
```

## Artifacts (all from the same release as the manager APK — the kernel verifies the manager by APK
certificate hash baked into the `.ko`, so they must match)

| file | where |
|---|---|
| `KernelSU_v3.3.0_32601-release.apk` | https://github.com/tiann/KernelSU/releases/tag/v3.3.0 |
| `ksud-aarch64-linux-android` (embeds all eight `*_kernelsu.ko` + `ksuinit`) | same release |
| `lkm-aarch64-android12-5.10_kernelsu.ko` (sha256 `5ca70d23…ce03a`) | same release |
| KernelSU-Next `android12-5.10_kernelsu.ko` (alternative) | https://github.com/KernelSU-Next/KernelSU-Next/releases/tag/v3.3.0 |
| SukiSU-Ultra `aarch64-android12-5.10-lkm.zip` (alternative) | https://github.com/SukiSU-Ultra/SukiSU-Ultra/releases/tag/v4.2.0 |

This device is a GKI variant (`AI2202`, `VARIANT=gki`), so KMI `android12-5.10` is the right target and
`ksud` auto-detects it from `5.10.205-android12-9-…`.

## On-device procedure

1. Install the manager APK first (same release as the `.ko`).
2. Load the module from the rooted session:
   ```sh
   KSUD=/data/local/tmp/ksud        # or the libksud.so extracted from the APK
   chmod 755 "$KSUD"; mkdir -p /data/adb/ksu
   setsid "$KSUD" late-load --kmi android12-5.10 --allow-shell </dev/null >/tmp/ksud.log 2>&1 &
   grep -q kernelsu /proc/modules && echo loaded
   ```
   `--allow-shell` matters: late-load **re-enables SELinux enforcing** and grants shell root directly.
3. ksud then creates `/data/adb`, installs itself as `/data/adb/ksud`, extracts busybox, applies sepolicy,
   and runs its late-load / system.prop / metamodule / post-mount / service / boot-completed stages.

## Caveats

- **Late-load loses:** initrc injection, ksud kprobe hooks, safe mode, boot-log capture,
  Magisk-coexistence checks. (Documented at https://kernelsu.org/guide/module.html#late-load-mode)
- **SELinux context gotcha** ([PR #3354](https://github.com/tiann/KernelSU/pull/3354)): ksud must reset
  its stdin/stdout/stderr after loading, otherwise cmd transactions are blocked because the fd still
  carries `u:r:su:s0` instead of `u:r:ksu:s0`. Redirect ksud's stdio to a log and force-stop + restart the
  manager afterwards. Tell-tale symptom: `kernelsu` in `/proc/modules` and shell `su` works, but the
  manager reports "not installed".
- **Not persistent across reboot:** module, hooks and runtime sepolicy are lost; `/data/adb/*` state
  survives but nothing triggers it at boot.
- **Persistence without unlocking = re-load only:** after each boot, re-obtain temporary root (see
  `ROADMAP.md`) and re-run `ksud late-load`. Precedents for exactly this model:
  [ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus) (SM8475 / 5.10 offsets already
  extracted for a sibling SoC) and
  [CVE-2026-43499-root-KernelSU](https://github.com/woshimaniubi8/CVE-2026-43499-root-KernelSU).

## Status

Not yet attempted on hardware: our temporary root needs a fully reliable kernel-text patch first
(see `ROADMAP.md` §5b/§6), because `ksud late-load` must run from a *stable* rooted session.
