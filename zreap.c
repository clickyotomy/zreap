/*
 * zreap: Utility to reap zombie processes with "ptrace(2)".
 */

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

/* Buffer size for error messages. */
#define MAX_BUFF_SIZE (2 << 8)

/* Machine word size. */
#define MAX_WORD_SIZE sizeof(void *)

/* Buffer size for zombie PID list. */
#define MAX_NR_ZOMBIES (2 << 8)

/* System call number for "wait4(2)" (61). */
#define REG_NR_SYS_WAIT 0x3DU

/* Null argument for function (in the register). */
#define REG_FN_NULL_ARG 0x0U

/* Register actions. */
enum regs_action {
    GET,
    SET,
};

/* Hook actions for "ptrace(2)". */
enum hook_action {
    ATTACH,
    DETACH,
};

/* Poll actions. */
enum poll_action {
    STOP, /* Wait for the process to stop. */
    TRAP, /* Wait and confirm if the stop signal was a "SIGTRAP". */
};

/* Print the error and return the exit status. */
static int8_t errf(const char *fn, const char *msg, int8_t err, int8_t ret) {
    fprintf(stderr, "%s: %s: %s (errno: %d)\n", fn, msg, strerror(err), err);
    fflush(stderr);
    return ret;
}

/*
 * Wait for the traced process to stop (if attaching), and also
 * confirm if the process was stopped with a "SIGTRAP" (if single
 * stepping).
 */
int8_t poll(pid_t pid, enum poll_action act) {
    int32_t wstat;
    char ebuf[MAX_BUFF_SIZE] = {0};

    if (waitpid(pid, &wstat, WSTOPPED) == -1) {
        snprintf(ebuf, MAX_BUFF_SIZE, "Failed to \"wait()\" on tracee PID %d",
                 pid);

        return errf("poll", ebuf, errno, -1);
    }

    if (WIFSTOPPED(wstat)) {
        if (act == STOP)
            goto done;

        /* When stepping, the tracee should always stop with a "SIGTRAP". */
        if (WSTOPSIG(wstat) == SIGTRAP)
            goto done;

        snprintf(ebuf, MAX_BUFF_SIZE,
                 "Expected signal %d (\"%s\"), but got %d (\"%s\")", SIGTRAP,
                 strsignal(SIGTRAP), wstat, strsignal(wstat));
        return errf("poll", ebuf, EBADE, -1);
    }

    snprintf(ebuf, MAX_BUFF_SIZE,
             "Received unexpected status from \"wait()\" (%d)",
             WSTOPSIG(wstat));
    return errf("poll", ebuf, EBADE, -1);

done:
    return 0;
}

/* Attach or detach from the tracee. */
int8_t hook(enum hook_action act, pid_t pid) {
    enum __ptrace_request pr;
    char ebuf[MAX_BUFF_SIZE] = {0};

    pr = (act == ATTACH) ? PTRACE_ATTACH : PTRACE_DETACH;
    if (ptrace(pr, pid, NULL, NULL)) {
        snprintf(ebuf, MAX_BUFF_SIZE,
                 "Failed to attach (detach) to (from) PID %d", pid);
        return errf("hook", ebuf, errno, -1);
    }

    if (pr == PTRACE_DETACH)
        goto done;

    return poll(pid, STOP);

done:
    return 0;
}

/* Detach from the tracee. */
int8_t halt(pid_t pid, int8_t status) {
    if (hook(DETACH, pid) < 0)
        exit(1);

    if (status)
        exit(status);

    return 0;
}

/* Get or set the current register set from (to) the tracee. */
int8_t regs(enum regs_action act, pid_t pid, struct user_regs_struct *reg_set) {
    enum __ptrace_request pr;
    char ebuf[MAX_BUFF_SIZE] = {0};

    pr = (act == GET) ? PTRACE_GETREGS : PTRACE_SETREGS;
    if (ptrace(pr, pid, NULL, reg_set)) {
        snprintf(ebuf, MAX_BUFF_SIZE,
                 "Failed to get (set) registers from (to) PID %d", pid);
        return errf("regs", ebuf, errno, -1);
    }

    return 0;
}

/*
 * Get or set the current program text (at the
 * instruction pointer) from (to) the tracee.
 */
int8_t poke(pid_t pid, void *addr, uint8_t *new, uint8_t *old,
            size_t nr_bytes) {
    int64_t peek_data, poke_data;
    char ebuf[MAX_BUFF_SIZE] = {0};

    if (nr_bytes % sizeof(void *) != 0) {
        snprintf(ebuf, MAX_BUFF_SIZE,
                 "Text size is not a mutiple of the machine word size (%ld)",
                 sizeof(void *));
        return errf("poke", ebuf, EINVAL, -1);
    }

    if (old) {
        peek_data = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
        if (peek_data == -1 && errno) {
            snprintf(ebuf, MAX_BUFF_SIZE, "Failed to peek at address %p", addr);
            return errf("poke", ebuf, errno, -1);
        }

        memmove(old, &peek_data, sizeof(peek_data));
    }

    memmove(&poke_data, new, sizeof(poke_data));
    if (ptrace(PTRACE_POKETEXT, pid, addr, (void *)poke_data) < 0) {
        snprintf(ebuf, MAX_BUFF_SIZE, "Failed to peek at address %p", addr);
        return errf("poke", ebuf, errno, -1);
    }

    return 0;
}

/* Single-step an instruction in the tracee. */
int8_t step(pid_t pid) {
    char ebuf[MAX_BUFF_SIZE] = {0};
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)) {
        snprintf(ebuf, MAX_BUFF_SIZE, "Failed to single-step on tracee PID %d",
                 pid);
        return errf("step", ebuf, errno, -1);
    }

    return poll(pid, TRAP);
}

/* Reap the "zombie" sub-process for a given process ID ("pid"). */
void reap(pid_t pid, pid_t zombie) {
    uint8_t new_text[MAX_WORD_SIZE] = {0}, old_text[MAX_WORD_SIZE] = {0};
    int8_t ret = 1;
    struct user_regs_struct new_regs, old_regs;
    void *rip = NULL;

    /* Add the "SYSCALL" instruction. */
    new_text[0] = 0x0f;
    new_text[1] = 0x05;

    /* Attach and wait for the parent process to stop. */
    if (hook(ATTACH, pid) < 0)
        goto fail;

    /* Get the current register set. */
    if (regs(GET, pid, &old_regs) < 0)
        goto fail;

    /* Store the current instruction pointer. */
    rip = (void *)old_regs.rip;

    /*
     * Copy over the current register values and initialize
     * a new register set which contains all the necessary
     * parameters for the syscall.
     */
    memmove(&new_regs, &old_regs, sizeof(new_regs));
    new_regs.rax = REG_NR_SYS_WAIT;
    new_regs.rdi = zombie;
    new_regs.rsi = REG_FN_NULL_ARG;
    new_regs.rdx = REG_FN_NULL_ARG;
    new_regs.r10 = REG_FN_NULL_ARG;
    new_regs.r8 = REG_FN_NULL_ARG;
    new_regs.r9 = REG_FN_NULL_ARG;

    /* Modify the current register set with new ones. */
    if (regs(SET, pid, &new_regs) < 0)
        goto fail;

    /*
     * Point the instruction pointer to a "SYSCALL" instruction.
     * This also copies over the existing "text" into "old_text".
     */
    if (poke(pid, rip, new_text, old_text, sizeof(new_text)) < 0)
        goto fail;

    /* Make the system call with a single-step. */
    if (step(pid) < 0)
        goto fail;

    /* Restore the old register set. */
    if (regs(SET, pid, &old_regs) < 0)
        goto fail;

    /* Restore the old program text at RIP. */
    if (poke(pid, rip, old_text, NULL, sizeof(old_text)) < 0)
        goto fail;

    ret = 0;

fail:
    halt(pid, ret);
}

/* Display program usage. */
void help() {
    fprintf(stderr, "zreap: Reap zombie processes.\n\n"
                    "USAGE\n"
                    "  zreap -p PPID -z PID [-z PID]...\n\n"
                    "ARGUMENTS\n"
                    "  -p  PID of the parent process.\n"
                    "  -z  A list of one (or more) zombie sub-process PIDs.\n");
    fflush(stderr);
}

int main(int argc, char *argv[]) {
    pid_t ppid = 0, zpid = 0, zombies[MAX_NR_ZOMBIES] = {0};
    int32_t nr_zombies = 0, opt, i;

    while ((opt = getopt(argc, argv, "p:z:h?")) != -1) {
        switch (opt) {
        case 'p':
            ppid = atoi(optarg);
            break;
        case 'z':
            zpid = atoi(optarg);
            zombies[nr_zombies++] = zpid;
            if (nr_zombies > MAX_NR_ZOMBIES)
                exit(errf("args", "Too many zombies", E2BIG, 1));
            break;
        case 'h':
        case '?':
        default:
            help();
            exit(EXIT_FAILURE);
        }
    }

    if (ppid <= 0 || nr_zombies <= 0)
        exit(errf("args", "Bad arguments for \"-p\" or \"-z\"", EINVAL, 2));

    for (i = 0; i < nr_zombies; i++)
        reap(ppid, zombies[i]);

    return 0;
}
