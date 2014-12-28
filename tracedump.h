/*
 * Copyright (C) 2011-2012 IITiS PAN Gliwice <http://www.iitis.pl/>
 * Author: Paweł Foremski <pjf@iitis.pl>
 * Licensed under GNU GPL v. 3
 */

#ifndef _TRACEDUMP_H_
#define _TRACEDUMP_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/net.h>
#include <signal.h>
#include <pthread.h>

#include <libpjf/lib.h>

#define TRACEDUMP_VERSION "0.5"

#define VDSO_PIGGYBACK

struct tracedump;
struct pid;
struct sock;
struct port;

#include "inject.h"
#include "ptrace.h"
#include "pcap.h"
#include "pid.h"
#include "port.h"

/** Holds global program information */
struct tracedump {
	mmatic *mm;                           /**< global memory */

	/* options */
	struct {
		char **src;                       /**< packet source (pointer on argv) */
		int srclen;                       /**< number of elements in src[] */
		char *outfile;                    /**< path to output file */
		int snaplen;                      /**< PCAP snaplen */
	} opts;

	/* structures for process tracing */
	struct pid *sp;                       /**< pid cache */
	thash *pids;                          /**< traced PIDs: (int pid)->(struct pid) */
	thash *socks;                         /**< sockets: (int socknum)->(struct sock) */

	/* structures for port tracking */
	pthread_mutex_t mutex_ports;          /**< guards tcp_ports and udp_ports */
	pthread_t thread_gc;                  /**< garbage collector thread */
	thash *tcp_ports;                     /**< monitored TCP ports: (int port)->(struct port) */
	thash *udp_ports;                     /**< monitored UDP ports: (int port)->(struct port) */

	/* structures for packet capture */
	struct pcap *pc;                      /**< PCAP data */
};

/** Represents a process */
struct pid {
	struct tracedump *td;                 /**< path to the root data structure */
	int pid;                              /**< process ID */
	char cmdline[128];                    /**< process cmdline */

	bool in_socketcall;                   /**< true if in syscall 102 and its bind(), sendto() or connect() */
	int code;                             /**< socketcall code */
	struct sock *ss;                      /**< cache */

	struct user_regs_struct regs;         /**< regs backup */
	size_t vdso_addr;                   /**< VDSO address (linux-gate.so.1) */
};

/** Represents a socket */
struct sock {
	struct tracedump *td;                 /**< path to the root data structure */
	int socknum;                          /**< socket number */
	unsigned char type;                   /**< socket type, ie. SOCK_STREAM or SOCK_DGRAM */
	unsigned long port;                   /**< if TCP or UDP: port number */
};

/** Represents a monitored port */
struct port {
	struct timeval since;                 /**< time when it was first seen */
	bool local;                           /**< local port if true, remote port otherwise */
	int socknum;                          /**< socknum seen on last procfs read */
};

#endif
