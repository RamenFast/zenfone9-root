# zenfone9-root — temporary root on a bootloader-locked ASUS Zenfone 9

Research code and notes for obtaining **temporary root (uid 0) on an ASUS Zenfone 9 (AI2202) whose
bootloader cannot be unlocked** — because ASUS discontinued its unlock tool, removed the OEM-unlocking
toggle from Developer options, and hard-refuses `fastboot oem unlock` / `flashing unlock` on current
firmware.

This is not a bootloader unlock and it does not flash anything. It is a **runtime** root: a chain of
device-side primitives that ends with the calling process holding root credentials. A reboot clears it.

Verified on: ASUS Zenfone 9 (AI2202), Android 14, build `34.0304.2004.145`, SPL 2024-07-05,
kernel `5.10.205-android12-9-00029-g3f12df86bfdb-ab11799032`, SM8475 / Adreno 730, bootloader locked.

> **Authorization / scope.** Everything here runs against a device the operator owns, over an
> authorised ADB connection. No vendor server is attacked, no signing key or unlock token is bypassed,
> and nothing is written to any partition. The phone used for development is a spare, backed up, and
> kept offline. Test on hardware you own and can afford to lose.

## The chain

| Stage | What it does | Where |
|---|---|---|
| 1 | **CVE-2025-21479** (Adreno KGSL): an SDS packet is misclassified as a ringbuffer packet, letting userland issue `CP_SMMU_TABLE_UPDATE` and point the GPU's TTBR0 at an attacker-chosen physical address | `src/cheese.c` |
| 2 | **Physical-address leak**: `perf_event_paranoid = -1` on this build, so a hardware watchpoint on a page we own returns `PERF_SAMPLE_PHYS_ADDR` — that page's physical address. Replaces the `pagemap` leak upstream relied on (PFNs are zeroed here) | `src/pa_leak.{c,h}` |
| 3 | **Arbitrary physical read/write**: build the fake page table *at a known physical address* (from stage 2), so no spray lottery and no wild walks | `src/cheese_pa.c` |
| 4 | **Root**: resolve kernel symbols offline from the firmware image, derive the KASLR slide on-device, patch `__do_sys_capset` with a `commit_creds(&init_cred)` stub, call `capset()` | `src/call_capset.c`, `scripts/` |

The result is uid 0 **in the `u:r:kernel:s0` SELinux context** (it inherits `init_cred`'s SID), i.e.
effectively unrestricted. SELinux must be Permissive for this step — under Enforcing the process is
killed instead, because the credential swap bypasses the SELinux hook.

## Quick start

Set `ZF9_SERIAL` to your device serial first (all scripts read it):

```bash
export ZF9_SERIAL=<your-device-serial>
```

```bash
# 0. one-time: build and push the device binaries (needs an Android NDK)
#    see scripts/ for the exact clang invocations used
adb push cheese_pa call_capset /data/local/tmp/

# 1. full cycle: SELinux -> permissive, patch, run a command as root, restore everything
scripts/root-now.sh id
scripts/root-now.sh sh        # root shell
```

The script always restores the original kernel text and SELinux state (trap-protected), and verifies
the restore by readback.

## Current status — honest

- **Root is proven.** Verified receipt: `uid=0(root) gid=0(root) context=u:r:kernel:s0`,
  `capset(NULL,NULL) -> 0`.
- **Re-applying it is not yet fully reliable.** The underlying primitive is a *race* (the TTBR0 update
  vs the command that uses it): losing it causes a GPU page fault, and KGSL then throttles that context
  (`gpu fault threshold exceeded 3 faults in 3000 msecs`), after which further commands fail with
  `EPERM`. Observed patch success varies between 13/13 and 2/13 dwords across runs.
- **Keep the GPU busy.** The primitive races a GPU context switch: the same 13-dword patch verified
  0-2/13 dwords with an idle GPU and **11-13/13** with a `screenrecord` load running. The scripts start
  their own load for every operation (reads race too), but never run these tools' internals bare.
- **A partially patched function is dangerous** (a `capset` caller can execute garbage). The scripts
  write the entry instruction last, verify every dword, and restore on failure — but if a run degrades,
  **reboot** before retrying.
- **No persistence, no bootloader unlock.** Custom ROMs remain impossible without ASUS.

Safety rules worth keeping: read before every write, always restore what you patch, never leave an
injected page-table entry live, don't touch secure/TZ physical memory (it is fatal), and reboot to
recover a degraded state. `ROADMAP.md` has the full list of gotchas with the evidence behind each.

## Repository layout

```
ROADMAP.md      durable handoff: verified constants, procedure, gotchas, open paths
STATUS.md       current state + verification receipts
src/            pa_leak.{c,h} · cheese.c · cheese_pa.c (workhorse: PROBE/POKE/SELFTEST/ROOT modes)
                call_capset.c · host_kallsyms.c (offline symbol resolver)
scripts/        root-now.sh · patch-dwords.sh · demo-root.sh · verify-backup.sh
tools/          btf_offsets.py
```

Firmware images, OTA packages and device logs are deliberately **not** committed (see `.gitignore`).

## Credits

- [zhuowei/cheese](https://github.com/zhuowei/cheese) — the CVE-2025-21479 proof of concept this port
  builds on, plus its kallsyms parser.
- [Qingizi7/cve-2025-21479_iqooneo8](https://github.com/Qingizi7/cve-2025-21479_iqooneo8) — runtime-root
  chain on the same SoC (SM8475), which established feasibility.
- [Project Zero: Attacking the Qualcomm Adreno GPU](https://googleprojectzero.blogspot.com/2020/09/attacking-qualcomm-adreno-gpu.html)
  — the original KGSL/SMMU research and ioctl definitions.
- [Qualcomm June 2025 security bulletin](https://docs.qualcomm.com/product/publicresources/securitybulletin/june-2025-bulletin.html)
  — the microcode fix this device predates by ~11 months (ASUS ended support, so it will never land).

## License

GPLv3 — see `LICENSE`.
