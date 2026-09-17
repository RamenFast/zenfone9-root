/* host_kallsyms.c — resolve kernel symbols OFFLINE from the extracted kernel Image.
 * No device access. Uses the same kallsyms parser as the exploit.
 * Mapping verified on-device: file offset 0 == physical 0xA8000000 (ARM\x64 magic matched at +0x38).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define KALLSYMS_LOOKUP_INCLUDE
#include "kallsyms_lookup.c"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <kernel.Image>\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("open"); return 1; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    void *buf = malloc(n);
    if (fread(buf, 1, n, f) != (size_t)n) { perror("read"); return 1; }
    fclose(f);
    printf("image: %ld bytes\n", n);

    struct cheese_kallsyms_lookup kl;
    memset(&kl, 0, sizeof(kl));
    int rc = cheese_create_kallsyms_lookup(&kl, buf, (size_t)n);
    printf("create_kallsyms_lookup rc=%d  num_syms=%u  text_base=%#lx\n",
           rc, kl.kallsyms_num_syms, (unsigned long)kl.text_base);
    if (rc) { printf("parser failed\n"); return 1; }

    const char *names[] = {
        "_text", "swapper_pg_dir", "init_task", "init_cred", "init_user_ns",
        "commit_creds", "prepare_kernel_cred", "__do_sys_capset", "selinux_state", "__arm64_sys_capset", "__arm64_sys_write", "__arm64_sys_read", "__arm64_sys_getuid",
        "kallsyms_offsets", "kallsyms_names", "kallsyms_token_table",
        "kallsyms_relative_base", "sys_call_table", "tramp_pg_dir", "idmap_pg_dir",
        NULL
    };
    printf("\n%-28s %-18s %s\n", "symbol", "virtual", "physical (base 0xA8000000)");
    for (int i = 0; names[i]; i++) {
        uint64_t v = cheese_kallsyms_lookup(&kl, names[i]);
        if (v) printf("%-28s %#018lx %#lx\n", names[i], (unsigned long)v,
                      (unsigned long)(0xA8000000UL + (v - kl.text_base)));
        else   printf("%-28s %-18s (not found)\n", names[i], "-");
    }
    return 0;
}
