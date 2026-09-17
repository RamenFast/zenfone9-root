# Zenfone 9 / CVE-2025-21479 — STATUS

## ✅ TEMPORARY ROOT ACHIEVED AND VERIFIED

```
[call_capset] rooted (uid=0 euid=0 selinux ctx unchanged); exec id
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
```

Root lands in the **kernel SELinux domain** (`init_cred`'s SID), i.e. effectively unrestricted.
Root is **proven and verified**, but re-applying it is **not yet reliable** — the underlying primitive
is a race (TTBR0 update vs command execution) and KGSL throttles a context after 3 GPU faults in 3 s.
Observed: the 13-dword patch landing 13/13 on some runs (root verified) and 2/13 on others; a *partial*
patch can panic the kernel (one spontaneous reboot). Reboot restores pristine text. Engineering the
fault rate down is the remaining work (see ROADMAP §4/§6) — it is a reliability problem, not a science one.

Repeatable via `scripts/root-now.sh id` (or `sh`) once hardened. Root is per-process and RAM-only — a fresh shell
stays uid 2000, and a reboot clears it. That is inherent to this CVE lineage (all public
CVE-2025-21479 outcomes are temporary root).

**Current device state (verified):** boot_completed=1, bootloader `locked=1`, SELinux **Enforcing**,
kernel text pristine (`0xd503233f` at `__do_sys_capset`), media backup intact (44 files, MD5-verified).
Nothing persistent was modified; every experiment's effects were RAM-only and are cleared by reboot.

## The chain (four stages, each verified)

1. **CVE-2025-21479 triggers** — userland SDS packet issues `CP_SMMU_TABLE_UPDATE`; kernel log echoes our
   TTBR0 in `GPU PAGE FAULT … FAULTING BLOCK: CP`. First ASUS device in the public record for this CVE.
   Microcode is permanently vulnerable: SPL 2024-07-05 predates the June-2025 Qualcomm fix, ASUS is EOL.
2. **Deterministic physical-address leak** — `perf_event_paranoid = -1`, so a hardware watchpoint on a page
   we own returns `PERF_SAMPLE_PHYS_ADDR`. Page-granular, reproducible. This replaced the blind spray
   hunt entirely (upstream/the fork used readable `pagemap`, which this build denies).
3. **Arbitrary physical R/W** — fake page table at a *known* physical address:
   `READBACK target=0x9d3bda040 value=0xc0ffee11 SELFTEST-PASS` (reproduced twice, hash-verified binaries).
4. **Root** — offline symbol resolution from the extracted kernel image + KASLR slide derived on-device
   (`init_task.cred` → `init_cred` runtime VA; cross-checked against `sys_call_table` high dword) →
   patch `__do_sys_capset` with `commit_creds(&init_cred)` shellcode → call `capset()` → uid 0.

## Key requirements and safety rules (learned the hard way)

- **SELinux must be Permissive** for stage 4; under Enforcing the rooted process is silently killed.
  Permissive also means the device is wide open — restore Enforcing when not in use.
- **Restore the patched text immediately.** Leaving it live while permissive caused a spontaneous reboot
  (any `capset` caller silently becomes kernel-root). Reboot is the failsafe.
- **Read before write**; verify writes by readback; **never leave injected PTEs live** (that also rebooted
  the device once).
- **Verify pushed binary hashes** (a stale `cheese_pa` produced silent no-output runs).
- **Do not touch secure/TZ memory** (reading `0x80000038` reboots); the DRAM high bank (0x800000000+) is
  normal memory, and physical layout is `file offset == physical - 0xA8000000`.
- **Writes: one dword per process run.** Multi-dword writes in one command hit `EPERM` from KGSL.
- **Reads: poll the result slot, not the marker** — the `CP_MEM_TO_MEM` copy can land after the marker.
- Memory pressure panics this kernel (`panic_on_rcu_stall=1`): 4 GB / 8 GB sprays rebooted it. The
  known-PA port does no spray and never crashed.
- **Post-reboot access** (no PIN on device): `adb shell 'input keyevent KEYCODE_WAKEUP; wm dismiss-keyguard'`.

## Not achieved / not achievable by these means

- **Bootloader unlock:** every conventional route refused (`oem unlock`, `flashing unlock`,
  `flashing unlock_critical` → permission denied/unknown command; `get_unlock_ability`=0; ASUS removed the
  Developer-options toggle; the community's `oem auth-hash` prerequisite is absent on this build).
  Root cannot re-sign `vbmeta`, so **custom ROMs still require ASUS's cooperation** — root ≠ unlock.
- Persistence: not yet implemented (see ROADMAP §7 for the realistic options; app-level re-root is
  unverified because `perf_event` is normally denied to untrusted apps).
- The kernel-VA self-map (bulk/coherent physical access) still fails with `SEGV_MAPERR` despite the PTE
  being verified in DRAM — cache/walk-cache visibility, not a wrong table. Not needed for root as shipped.

## Meanwhile, the original goal is also solved without root

Internal audio capture for phosphor dev: scrcpy playback capture verified with a synthetic 997 Hz tone
(950–1050 Hz band RMS −26.3 dB vs 80–200 Hz −49.1 dB) → `artifacts/audio-capture-test.opus`. On-device
equivalent: Android's consent-based `AudioPlaybackCapture` API.

## Artifacts

`ROADMAP.md` (durable handoff: constants, procedure, gotchas, open paths) · `src/cheese_pa.c` (GPU
primitive + POKE/PROBE/SELFTEST/ROOT modes) · `src/pa_leak.{c,h}` · `src/call_capset.c` ·
`src/host_kallsyms.c` (offline resolver) · `scripts/root-now.sh`, `scripts/patch-dwords.sh` ·
`artifacts/` (SHA-256-verified ASUS OTA, extracted partitions, `kernel.Image`) ·
`~/Videos/Zenfone9-backup-NhZOcgfg`.
