/*
 * Copyright (C) 2011-2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/net.h>
#include <netinet/in.h>
#include <stdarg.h>

#include "tracedump.h"

static void _prepare(struct pid *sp)
{
	FILE *fp;
	char buf[128] = {0};

	if (sp->vdso_addr)
		return;

	/* find VDSO address */
	snprintf(buf, sizeof buf, "/proc/%d/maps", sp->pid);
	fp = fopen(buf, "r");
	while (fgets(buf, sizeof buf, fp)) {
		if (strlen(buf) < 73 + 6)
			continue;

		/* found it? */
		if (strncmp(buf + 73, "[vdso]", 6) == 0) {
			/* parse address */
			buf[12] = 0;
			sp->vdso_addr = (size_t) strtoul(buf, NULL, 16);
			dbg(1, "POINTER %p\n", sp->vdso_addr);
			break;
		}
	}
	fclose(fp);
	if (!sp->vdso_addr)
		dbg(0, "pid %d: no [vdso] memory region\n", sp->pid);

	/* inject our code */
	unsigned long code[4] = { 0x0F, 0x05, 0, 0 };
	dbg(3, "pid %d: installing code at 0x%x\n", sp->pid, sp->vdso_addr);
	ptrace_write(sp, sp->vdso_addr, code, sizeof code);
}

// Registers used for system call arguments in x86_64:
// %rdi, %rsi, %rdx, %r10, %r8 and %r9.

/** Inject getsockname(fd, sa, 16)
 * @retval -2    socket not AF_INET */
int32_t inject_getsockname_in(struct tracedump *td, struct pid *sp, int fd, struct sockaddr_in *sa)
{
	struct user_regs_struct regs, regs2;
	socklen_t size = sizeof *sa;

	/* backup */
	ptrace_getregs(sp, &regs);
	memcpy(&regs2, &regs, sizeof regs);

	/* get vdso address*/
	_prepare(sp);
	dbg(1, "FD = %d\n", fd);
	/* execute syscall */
	regs2.rax = 51; // getsockname
	regs2.rdi = fd;
	regs2.rsi = (size_t) sa; // addr
	regs2.rdx = (size_t) &size; // addr_len
	regs2.rip = sp->vdso_addr;  // gateway to int3 ?????
	ptrace_setregs(sp, &regs2);
	ptrace_cont_syscall(sp, 0, true);   // enter...
	ptrace_cont_syscall(sp, 0, true);   // ...and exit

	/* read registers back */
	ptrace_getregs(sp, &regs2);

	/* restore from backup */
	ptrace_setregs(sp, &regs);

	if (sa->sin_family != AF_INET)
		return -2;
	else
		return regs2.rax;
}

/** Inject bind(fd, {AF_INET, INADDR_ANY, .port = 0}, 16) */
int32_t inject_autobind(struct tracedump *td, struct pid *sp, int fd)
{
	struct user_regs_struct regs, regs2;
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_port   = 0,
		.sin_addr   = { INADDR_ANY }
	};
	socklen_t size = sizeof sa;

	/* backup */
	ptrace_getregs(sp, &regs);
	memcpy(&regs2, &regs, sizeof regs);

	/* get vdso address*/
	_prepare(sp);

	/* execute syscall */
	regs2.rax = 49;				// bind
	regs2.rdi = (size_t) &sa;	// addr
	regs2.rsi = (size_t) &size;	// addr_len
	regs2.rip = sp->vdso_addr;  // gateway to int3 ?????
	ptrace_setregs(sp, &regs2);
	ptrace_cont_syscall(sp, 0, true);   // enter...
	ptrace_cont_syscall(sp, 0, true);   // ...and exit

	/* read registers back */
	ptrace_getregs(sp, &regs2);

	/* restore from backup */
	ptrace_setregs(sp, &regs);

	return regs2.rax;
}

/** Inject getsockopt() */
int32_t inject_getsockopt(struct tracedump *td, struct pid *sp,	int fd, int level, int optname,
		void *optval, socklen_t *optlen)
{
	struct user_regs_struct regs, regs2;

	/* backup */
	ptrace_getregs(sp, &regs);
	memcpy(&regs2, &regs, sizeof regs);

	/* get vdso address*/
	_prepare(sp);

	/* execute syscall */
	regs2.rax = 54;		// bind
	regs2.rdi = fd;
	regs2.rsi = level;
	regs2.rdx = optname;
	regs2.r10 = (size_t) optval;
	regs2.r8 = (size_t) optlen;
	regs2.rip = sp->vdso_addr;  // gateway to int3 ?????
	ptrace_setregs(sp, &regs2);
	ptrace_cont_syscall(sp, 0, true);   // enter...
	ptrace_cont_syscall(sp, 0, true);   // ...and exit

	/* read registers back */
	ptrace_getregs(sp, &regs2);

	/* restore from backup */
	ptrace_setregs(sp, &regs);

	return regs2.rax;
}


void inject_escape_socketcall(struct tracedump *td, struct pid *sp)
{
	struct user_regs_struct regs;

	/* make backup */
	ptrace_getregs(sp, &regs);
	memcpy(&sp->regs, &regs, sizeof regs);

	/* update EBX so it is invalid */
	regs.rbx = 0;
	ptrace_setregs(sp, &regs);

	/* run the invalid socketcall and wait */
	ptrace_cont_syscall(sp, 0, true);

	/* -> now the process is in user mode */
}

void inject_restore_socketcall(struct tracedump *td, struct pid *sp)
{
	struct user_regs_struct regs2;

	/* prepare */
	_prepare(sp);
	memcpy(&regs2, &sp->regs, sizeof regs2);
	regs2.rax = sp->regs.orig_rax;
	regs2.rip = sp->vdso_addr;

	/* exec */
	ptrace_setregs(sp, &regs2);
	ptrace_cont_syscall(sp, 0, true);
	ptrace_cont_syscall(sp, 0, true);

	/* rewrite the return code */
	ptrace_getregs(sp, &regs2);
	sp->regs.rax = regs2.rax;

	/* restore */
	ptrace_setregs(sp, &sp->regs);
}
