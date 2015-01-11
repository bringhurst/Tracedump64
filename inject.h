/*
 * Adapted for x86_64 by:
 * Ingvaras Merkys <ingvaras@gmail.com>
 */
/*
 * Copyright (C) 2011-2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#ifndef _INJECT_H_
#define _INJECT_H_

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/net.h>
#include <netinet/in.h>
#include <sys/user.h>
#include <libpjf/lib.h>

#include "tracedump.h"

/** Circumvent an on-going socketcall
 *
 * Implemented by calling socketcall with an invalid subcode, which will result in an -EINVAL.
 * This will put the traced process in normal state, ie. executing the code under EIP, which is
 * required for the inject_*() functions to work properly.
 */
void inject_escape_socketcall(struct tracedump *td, struct pid *sp);

/** Cancel inject_escape_socketcall() effects
 *
 * This function will execute the whole socketcall until it finishes
 */
void inject_restore_socketcall(struct tracedump *td, struct pid *sp);

int32_t inject_getsockname_in(struct tracedump *td, struct pid *sp, int fd, struct sockaddr_in *sa);
int32_t inject_autobind(struct tracedump *td, struct pid *sp, int fd);
int32_t inject_getsockopt(struct tracedump *td, struct pid *sp, int fd, int level, int optname,
		void *optval, socklen_t *optlen);

#endif
