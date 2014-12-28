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
			break;
		}
	}
	fclose(fp);
	if (!sp->vdso_addr)
		dbg(0, "pid %d: no [vdso] memory region\n", sp->pid);

	/* inject our code */
	/* "0F 05" is code for x86_64 instruction SYSCALL */
	unsigned char code[4] = { 0x0F, 0x05, 0, 0 };
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

	/* Need to put data into the stack of the tracee process */
	uint8_t *stack;
	int memory_needed = size + sizeof size;
	stack = mmatic_zalloc(td->mm, memory_needed);
	memcpy(stack, sa, size);
	memcpy(stack + size, &size, sizeof size);
	ptrace_write(sp, regs.rsp - memory_needed, stack, memory_needed);

	/* get vdso address*/
	_prepare(sp);

	/* execute syscall */
	regs2.rax = SYS_getsockname;
	regs2.rdi = fd;
	regs2.rsi = regs.rsp - memory_needed;			// addr
	regs2.rdx = regs.rsp - memory_needed + size;	// addr_len
	regs2.rip = sp->vdso_addr;
	ptrace_setregs(sp, &regs2);
	ptrace_cont_syscall(sp, 0, true);   // enter...
	ptrace_cont_syscall(sp, 0, true);   // ...and exit

	/* read registers back */
	ptrace_getregs(sp, &regs2);

	/* read back from the stack */
	ptrace_read(sp, regs.rsp - memory_needed, stack, memory_needed);
	memcpy(sa, stack, size);
	memcpy(&size, stack + size, sizeof size);


	/* restore from backup */
	ptrace_setregs(sp, &regs);

	if (size != sizeof *sa || sa->sin_family != AF_INET)
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

	/* Need to put data into the stack of the tracee process */
	uint8_t *stack;
	stack = mmatic_zalloc(td->mm, size);
	memcpy(stack, &sa, size);
	ptrace_write(sp, regs.rsp - size, stack, size);

	/* get vdso address*/
	_prepare(sp);

	/* execute syscall */
	regs2.rax = SYS_bind;
	regs2.rdi = fd;
	regs2.rsi = regs.rsp - size;			// addr
	regs2.rdx = size;	// addr_len
	regs2.rip = sp->vdso_addr;
	ptrace_setregs(sp, &regs2);
	ptrace_cont_syscall(sp, 0, true);   // enter...
	ptrace_cont_syscall(sp, 0, true);   // ...and exit

	/* read registers back */
	ptrace_getregs(sp, &regs2);

	/* read back from the stack */
	ptrace_read(sp, regs.rsp - size, stack, size);
	memcpy(&sa, stack, size);

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


	/* Need to put data into the stack of the tracee process */
	uint8_t *stack;
	int memory_needed = *optlen + sizeof *optlen;
	stack = mmatic_zalloc(td->mm, memory_needed);
	memcpy(stack, optval, *optlen);
	memcpy(stack + *optlen, optlen, sizeof *optlen);
	ptrace_write(sp, regs.rsp - memory_needed, stack, memory_needed);

	/* get vdso address*/
	_prepare(sp);

	/* execute syscall */
	/* int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen); */
	regs2.rax = SYS_getsockopt;
	regs2.rdi = fd;
	regs2.rsi = level;
	regs2.rdx = optname;
	regs2.r10 = regs.rsp - memory_needed;
	regs2.r8 = regs.rsp - memory_needed + *optlen;
	regs2.rip = sp->vdso_addr;
	ptrace_setregs(sp, &regs2);
	ptrace_cont_syscall(sp, 0, true);   // enter...
	ptrace_cont_syscall(sp, 0, true);   // ...and exit

	/* read registers back */
	ptrace_getregs(sp, &regs2);

	ptrace_read(sp, regs.rsp - memory_needed, stack, memory_needed);
	memcpy(optval, stack, *optlen);
	memcpy(optlen, stack + *optlen, sizeof *optlen);

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
	regs.rdi = 0;
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
