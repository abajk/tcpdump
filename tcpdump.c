/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Support for splitting captures into multiple files with a maximum
 * file size:
 *
 * Copyright (c) 2001
 *	Seth Webster <swebster@sst.ll.mit.edu>
 */

/*
 * tcpdump - dump traffic on a network
 *
 * First written in 1987 by Van Jacobson, Lawrence Berkeley Laboratory.
 * Mercilessly hacked and occasionally improved since then via the
 * combined efforts of Van, Steve McCanne and Craig Leres of LBL.
 */

#include <config.h>
#ifndef TCPDUMP_CONFIG_H_
#error "The included config.h header is not from the tcpdump build."
#endif

#include "netdissect-stdinc.h"

/*
 * This must appear after including netdissect-stdinc.h, so that _U_ is
 * defined.
 */
#ifndef lint
static const char copyright[] _U_ =
    "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000\n\
The Regents of the University of California.  All rights reserved.\n";
#endif

#include <sys/stat.h>

#include <fcntl.h>

#ifdef HAVE_LIBCRYPTO
#include <openssl/crypto.h>
#endif

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#else
#include "missing/getopt_long.h"
#endif
/* Capsicum-specific code requires macros from <net/bpf.h>, which will fail
 * to compile if <pcap.h> has already been included; including the headers
 * in the opposite order works fine. For the most part anyway, because in
 * FreeBSD <pcap/pcap.h> declares bpf_dump() instead of <net/bpf.h>. Thus
 * interface.h takes care of it later to avoid a compiler warning.
 */
#ifdef HAVE_CAPSICUM
#include <sys/capsicum.h>
#include <sys/ioccom.h>
#include <net/bpf.h>
#include <libgen.h>
#ifdef HAVE_CASPER
#include <libcasper.h>
#include <casper/cap_dns.h>
#include <sys/nv.h>
#endif	/* HAVE_CASPER */
#endif	/* HAVE_CAPSICUM */
#ifdef HAVE_PCAP_OPEN
/*
 * We found pcap_open() in the capture library, so we'll be using
 * the remote capture APIs; define PCAP_REMOTE before we include pcap.h,
 * so we get those APIs declared, and the types and #defines that they
 * use defined.
 *
 * WinPcap's headers require that PCAP_REMOTE be defined in order to get
 * remote-capture APIs declared and types and #defines that they use
 * defined.
 *
 * (Versions of libpcap with those APIs, and thus Npcap, which is based on
 * those versions of libpcap, don't require it.)
 */
#define HAVE_REMOTE
#endif
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <pwd.h>
#include <grp.h>
#endif /* _WIN32 */

/*
 * Pathname separator.
 * Use this in pathnames, but do *not* use it in URLs.
 */
#ifdef _WIN32
#define PATH_SEPARATOR	'\\'
#else
#define PATH_SEPARATOR	'/'
#endif

/* capabilities convenience library */
/* If a code depends on HAVE_LIBCAP_NG, it depends also on HAVE_CAP_NG_H.
 * If HAVE_CAP_NG_H is not defined, undefine HAVE_LIBCAP_NG.
 * Thus, the later tests are done only on HAVE_LIBCAP_NG.
 */
#ifdef HAVE_LIBCAP_NG
#ifdef HAVE_CAP_NG_H
#include <cap-ng.h>
#else
#undef HAVE_LIBCAP_NG
#endif /* HAVE_CAP_NG_H */
#endif /* HAVE_LIBCAP_NG */

#ifdef __FreeBSD__
#include <sys/sysctl.h>
#endif /* __FreeBSD__ */

#include "netdissect.h"
#include "interface.h"
#include "addrtoname.h"
#include "ascii_strcasecmp.h"

#include "print.h"

#include "diag-control.h"

#include "fptype.h"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#if defined(SIGINFO)
#define SIGNAL_REQ_INFO SIGINFO
#elif defined(SIGUSR1)
#define SIGNAL_REQ_INFO SIGUSR1
#endif

#if defined(SIGUSR2)
#define SIGNAL_FLUSH_PCAP SIGUSR2
#endif

static int Bflag;			/* buffer size */
static int64_t Cflag;			/* rotate dump files after this many bytes */
static int Cflag_count;			/* Keep track of which file number we're writing */
static int Dflag;			/* list available devices and exit */
#ifdef HAVE_PCAP_FINDALLDEVS_EX
static char *remote_interfaces_source;	/* list available devices from this source and exit */
#endif

/*
 * This is exported because, in some versions of libpcap, if libpcap
 * is built with optimizer debugging code (which is *NOT* the default
 * configuration!), the library *imports*(!) a variable named dflag,
 * under the expectation that tcpdump is exporting it, to govern
 * how much debugging information to print when optimizing
 * the generated BPF code.
 *
 * This is a horrible hack; newer versions of libpcap don't import
 * dflag but, instead, *if* built with optimizer debugging code,
 * *export* a routine to set that flag.
 */
extern int dflag;
int dflag;				/* print filter code */
static int Gflag;			/* rotate dump files after this many seconds */
static int Gflag_count;			/* number of files created with Gflag rotation */
static time_t Gflag_time;		/* The last time_t the dump file was rotated. */
static int Lflag;			/* list available data link types and exit */
static int Iflag;			/* rfmon (monitor) mode */
#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
static int Jflag;			/* list available time stamp types */
static int jflag = -1;			/* packet time stamp source */
#endif
static int lflag;			/* line-buffered output */
static int pflag;			/* don't go promiscuous */
static int Qflag = -1;			/* restrict captured packet by send/receive direction */
static int Uflag;			/* "unbuffered" output of dump files */
static int Wflag;			/* recycle output files after this number of files */
static int WflagChars;
#if defined(HAVE_FORK) || defined(HAVE_VFORK)
static char *zflag = NULL;		/* compress each savefile using a specified command (like gzip or bzip2) */
#endif
static int timeout = 1000;		/* default timeout = 1000 ms = 1 s */
#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
static int immediate_mode;
#endif
static int count_mode;
static u_int packets_to_skip;

static int infodelay;
static int infoprint;

char *program_name;

/* Forwards */
static int parse_int(const char *argname, const char *string, char **endp,
    int minval, int maxval, int base);
static u_int parse_u_int(const char *argname, const char *string, char **endp,
    u_int minval, u_int maxval, int base);
static int64_t parse_int64(const char *argname, const char *string,
    char **endp, int64_t minval, int64_t maxval, int base);
static void (*setsignal (int sig, void (*func)(int)))(int);
static void cleanup(int);
#if defined(HAVE_FORK) || defined(HAVE_VFORK)
static void child_cleanup(int);
#endif
static void print_version(FILE *);
static void print_usage(FILE *);

static void print_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
static void dump_packet_and_trunc(u_char *, const struct pcap_pkthdr *, const u_char *);
static void dump_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

#ifdef SIGNAL_REQ_INFO
static void requestinfo(int);
#endif

#ifdef SIGNAL_FLUSH_PCAP
static void flushpcap(int);
#endif

#ifdef _WIN32
    static HANDLE timer_handle = INVALID_HANDLE_VALUE;
    static void CALLBACK verbose_stats_dump(PVOID param, BOOLEAN timer_fired);
#else /* _WIN32 */
  static void verbose_stats_dump(int sig);
#endif /* _WIN32 */

static void info(int);
static u_int packets_captured;

static const struct tok status_flags[] = {
#ifdef PCAP_IF_UP
	{ PCAP_IF_UP,       "Up"       },
#endif
#ifdef PCAP_IF_RUNNING
	{ PCAP_IF_RUNNING,  "Running"  },
#endif
	{ PCAP_IF_LOOPBACK, "Loopback" },
#ifdef PCAP_IF_WIRELESS
	{ PCAP_IF_WIRELESS, "Wireless" },
#endif
	{ 0, NULL }
};

static pcap_t *pd;
static pcap_dumper_t *pdd = NULL;

static int supports_monitor_mode;

extern int optind;
extern int opterr;
extern char *optarg;

struct dump_info {
	char	*WFileName;
	char	*CurrentFileName;
	pcap_t	*pd;
	pcap_dumper_t *pdd;
	netdissect_options *ndo;
#ifdef HAVE_CAPSICUM
	int	dirfd;
#endif
};

#if defined(HAVE_PCAP_SET_PARSER_DEBUG)
/*
 * We have pcap_set_parser_debug() in libpcap; declare it (it's not declared
 * by any libpcap header, because it's a special hack, only available if
 * libpcap was configured to include it, and only intended for use by
 * libpcap developers trying to debug the parser for filter expressions).
 */
#ifdef _WIN32
__declspec(dllimport)
#else /* _WIN32 */
extern
#endif /* _WIN32 */
void pcap_set_parser_debug(int);
#elif defined(HAVE_PCAP_DEBUG) || defined(HAVE_YYDEBUG)
/*
 * We don't have pcap_set_parser_debug() in libpcap, but we do have
 * pcap_debug or yydebug.  Make a local version of pcap_set_parser_debug()
 * to set the flag, and define HAVE_PCAP_SET_PARSER_DEBUG.
 */
static void
pcap_set_parser_debug(int value)
{
#ifdef HAVE_PCAP_DEBUG
	extern int pcap_debug;

	pcap_debug = value;
#else /* HAVE_PCAP_DEBUG */
	extern int yydebug;

	yydebug = value;
#endif /* HAVE_PCAP_DEBUG */
}

#define HAVE_PCAP_SET_PARSER_DEBUG
#endif // HAVE_PCAP_SET_PARSER_DEBUG, HAVE_PCAP_DEBUG, HAVE_YYDEBUG

#if defined(HAVE_PCAP_SET_OPTIMIZER_DEBUG)
/*
 * We have pcap_set_optimizer_debug() in libpcap; declare it (it's not declared
 * by any libpcap header, because it's a special hack, only available if
 * libpcap was configured to include it, and only intended for use by
 * libpcap developers trying to debug the optimizer for filter expressions).
 */
#ifdef _WIN32
__declspec(dllimport)
#else /* _WIN32 */
extern
#endif /* _WIN32 */
void pcap_set_optimizer_debug(int);
#endif // HAVE_PCAP_SET_OPTIMIZER_DEBUG

static void NORETURN
exit_tcpdump(const int status)
{
	nd_cleanup();
	exit(status);
}

/* VARARGS */
static void NORETURN PRINTFLIKE(1, 2)
error(FORMAT_STRING(const char *fmt), ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
	exit_tcpdump(S_ERR_HOST_PROGRAM);
	/* NOTREACHED */
}

/* VARARGS */
static void PRINTFLIKE(1, 2)
warning(FORMAT_STRING(const char *fmt), ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: WARNING: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
}

#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
static void NORETURN
show_tstamp_types_and_exit(pcap_t *pc, const char *device)
{
	int n_tstamp_types;
	int *tstamp_types = 0;
	const char *tstamp_type_name;
	int i;

	n_tstamp_types = pcap_list_tstamp_types(pc, &tstamp_types);
	if (n_tstamp_types < 0)
		error("%s", pcap_geterr(pc));

	if (n_tstamp_types == 0) {
		fprintf(stderr, "Time stamp type cannot be set for %s\n",
		    device);
		exit_tcpdump(S_SUCCESS);
	}
	fprintf(stdout, "Time stamp types for %s (use option -j to set):\n",
	    device);
	for (i = 0; i < n_tstamp_types; i++) {
		tstamp_type_name = pcap_tstamp_type_val_to_name(tstamp_types[i]);
		if (tstamp_type_name != NULL) {
			(void) fprintf(stdout, "  %s (%s)\n", tstamp_type_name,
			    pcap_tstamp_type_val_to_description(tstamp_types[i]));
		} else {
			(void) fprintf(stdout, "  %d\n", tstamp_types[i]);
		}
	}
	pcap_free_tstamp_types(tstamp_types);
	exit_tcpdump(S_SUCCESS);
}
#endif // HAVE_PCAP_SET_TSTAMP_TYPE

static void NORETURN
show_dlts_and_exit(pcap_t *pc, const char *device)
{
	int n_dlts, i;
	int *dlts = 0;
	const char *dlt_name;

	n_dlts = pcap_list_datalinks(pc, &dlts);
	if (n_dlts < 0)
		error("%s", pcap_geterr(pc));
	else if (n_dlts == 0 || !dlts)
		error("No data link types.");

	/*
	 * If the interface is known to support monitor mode, indicate
	 * whether these are the data link types available when not in
	 * monitor mode, if -I wasn't specified, or when in monitor mode,
	 * when -I was specified (the link-layer types available in
	 * monitor mode might be different from the ones available when
	 * not in monitor mode).
	 */
	(void) fprintf(stdout, "Data link types for ");
	if (supports_monitor_mode)
		(void) fprintf(stdout, "%s %s",
		    device,
		    Iflag ? "when in monitor mode" : "when not in monitor mode");
	else
		(void) fprintf(stdout, "%s",
		    device);
	(void) fprintf(stdout, " (use option -y to set):\n");

	for (i = 0; i < n_dlts; i++) {
		dlt_name = pcap_datalink_val_to_name(dlts[i]);
		if (dlt_name != NULL) {
			(void) fprintf(stdout, "  %s (%s)", dlt_name,
			    pcap_datalink_val_to_description(dlts[i]));

			/*
			 * OK, does tcpdump handle that type?
			 */
			if (!has_printer(dlts[i]))
				(void) fprintf(stdout, " (printing not supported)");
			fprintf(stdout, "\n");
		} else {
			(void) fprintf(stdout, "  DLT %d (printing not supported)\n",
			    dlts[i]);
		}
	}
	pcap_free_datalinks(dlts);
	exit_tcpdump(S_SUCCESS);
}

static void NORETURN
show_devices_and_exit(void)
{
	pcap_if_t *dev, *devlist;
	char ebuf[PCAP_ERRBUF_SIZE];
	int i;

	if (pcap_findalldevs(&devlist, ebuf) < 0)
		error("%s", ebuf);
	for (i = 0, dev = devlist; dev != NULL; i++, dev = dev->next) {
		printf("%d.%s", i+1, dev->name);
		if (dev->description != NULL)
			printf(" (%s)", dev->description);
		if (dev->flags != 0) {
			printf(" [");
			printf("%s", bittok2str(status_flags, "none", dev->flags));
#ifdef PCAP_IF_WIRELESS
			if (dev->flags & PCAP_IF_WIRELESS) {
				switch (dev->flags & PCAP_IF_CONNECTION_STATUS) {

				case PCAP_IF_CONNECTION_STATUS_UNKNOWN:
					printf(", Association status unknown");
					break;

				case PCAP_IF_CONNECTION_STATUS_CONNECTED:
					printf(", Associated");
					break;

				case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
					printf(", Not associated");
					break;

				case PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE:
					break;
				}
			} else {
				switch (dev->flags & PCAP_IF_CONNECTION_STATUS) {

				case PCAP_IF_CONNECTION_STATUS_UNKNOWN:
					printf(", Connection status unknown");
					break;

				case PCAP_IF_CONNECTION_STATUS_CONNECTED:
					printf(", Connected");
					break;

				case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
					printf(", Disconnected");
					break;

				case PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE:
					break;
				}
			}
#endif // PCAP_IF_WIRELESS
			printf("]");
		}
		printf("\n");
	}
	pcap_freealldevs(devlist);
	exit_tcpdump(S_SUCCESS);
}

#ifdef HAVE_PCAP_FINDALLDEVS_EX
static void NORETURN
show_remote_devices_and_exit(void)
{
	pcap_if_t *dev, *devlist;
	char ebuf[PCAP_ERRBUF_SIZE];
	int i;

	if (pcap_findalldevs_ex(remote_interfaces_source, NULL, &devlist,
	    ebuf) < 0) {
		if (strcmp(ebuf, "not supported") == 0) {
			/*
			 * macOS 14's pcap_findalldevs_ex(), which is a
			 * stub that always returns -1 with an error
			 * message of "not supported".
			 *
			 * In this case, as we passed it an rpcap://
			 * URL, treat that as meaning "remote capture
			 * not supported".
			 */
			error("Remote capture not supported");
		}
		error("%s", ebuf);
	}
	for (i = 0, dev = devlist; dev != NULL; i++, dev = dev->next) {
		printf("%d.%s", i+1, dev->name);
		if (dev->description != NULL)
			printf(" (%s)", dev->description);
		if (dev->flags != 0)
			printf(" [%s]", bittok2str(status_flags, "none", dev->flags));
		printf("\n");
	}
	pcap_freealldevs(devlist);
	exit_tcpdump(S_SUCCESS);
}
#endif /* HAVE_PCAP_FINDALLDEVS_EX */

/*
 * Short options.
 *
 * Note that there we use all letters for short options except for g, k,
 * o, and P, and those are used by other versions of tcpdump, and we should
 * only use them for the same purposes that the other versions of tcpdump
 * use them:
 *
 * macOS tcpdump uses -g to force non--v output for IP to be on one
 * line, making it more "g"repable;
 *
 * macOS tcpdump uses -k to specify that packet comments in pcapng files
 * should be printed;
 *
 * OpenBSD tcpdump uses -o to indicate that OS fingerprinting should be done
 * for hosts sending TCP SYN packets;
 *
 * macOS tcpdump uses -P to indicate that -w should write pcapng rather
 * than pcap files.
 *
 * macOS tcpdump also uses -Q to specify expressions that match packet
 * metadata, including but not limited to the packet direction.
 * The expression syntax is different from a simple "in|out|inout",
 * and those expressions aren't accepted by macOS tcpdump, but the
 * equivalents would be "in" = "dir=in", "out" = "dir=out", and
 * "inout" = "dir=in or dir=out", and the parser could conceivably
 * special-case "in", "out", and "inout" as expressions for backwards
 * compatibility, so all is not (yet) lost.
 */

/*
 * Set up flags that might or might not be supported depending on the
 * version of libpcap we're using.
 */
#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
#define j_FLAG		"j:"
#define j_FLAG_USAGE	" [ -j tstamptype ]"
#define J_FLAG		"J"
#else /* HAVE_PCAP_SET_TSTAMP_TYPE */
#define j_FLAG
#define j_FLAG_USAGE
#define J_FLAG
#endif /* HAVE_PCAP_SET_TSTAMP_TYPE */

#ifdef USE_LIBSMI
#define m_FLAG_USAGE "[ -m module ] ..."
#endif

#if defined(HAVE_FORK) || defined(HAVE_VFORK)
#define z_FLAG		"z:"
#define z_FLAG_USAGE    "[ -z postrotate-command ] "
#else
#define z_FLAG
#define z_FLAG_USAGE
#endif

#ifdef HAVE_LIBCRYPTO
#define E_FLAG		"E:"
#define E_FLAG_USAGE    "[ -E algo:secret ] "
#define M_FLAG		"M:"
#define M_FLAG_USAGE	"[ -M secret ] "
#else
#define E_FLAG
#define E_FLAG_USAGE
#define M_FLAG
#define M_FLAG_USAGE
#endif

#define SHORTOPTS "aAbB:c:C:dDe" E_FLAG "fF:gG:hHi:I" j_FLAG J_FLAG "KlLm:" M_FLAG "nNOpqQ:r:s:StT:uUvV:w:W:xXy:Y" z_FLAG "Z:#"

/*
 * Long options.
 *
 * We do not currently have long options corresponding to all short
 * options; we should probably pick appropriate option names for them.
 *
 * However, the short options where the number of times the option is
 * specified matters, such as -v and -d and -t, should probably not
 * just map to a long option, as saying
 *
 *  tcpdump --verbose --verbose
 *
 * doesn't make sense; it should be --verbosity={N} or something such
 * as that.
 *
 * For long options with no corresponding short options, we define values
 * outside the range of ASCII graphic characters, make that the last
 * component of the entry for the long option, and have a case for that
 * option in the switch statement.
 */
#define OPTION_VERSION			128
#define OPTION_TSTAMP_PRECISION		129
#define OPTION_IMMEDIATE_MODE		130
#define OPTION_PRINT			131
#define OPTION_LIST_REMOTE_INTERFACES	132
#define OPTION_TSTAMP_MICRO		133
#define OPTION_TSTAMP_NANO		134
#define OPTION_FP_TYPE			135
#define OPTION_COUNT			136
#define OPTION_PRINT_SAMPLING		137
#define OPTION_LENGTHS			138
#define OPTION_TIME_T_SIZE		139
#define OPTION_SKIP			140

static const struct option longopts[] = {
	{ "buffer-size", required_argument, NULL, 'B' },
	{ "list-interfaces", no_argument, NULL, 'D' },
#ifdef HAVE_PCAP_FINDALLDEVS_EX
	{ "list-remote-interfaces", required_argument, NULL, OPTION_LIST_REMOTE_INTERFACES },
#endif
	{ "help", no_argument, NULL, 'h' },
	{ "interface", required_argument, NULL, 'i' },
	{ "monitor-mode", no_argument, NULL, 'I' },
#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
	{ "time-stamp-type", required_argument, NULL, 'j' },
	{ "list-time-stamp-types", no_argument, NULL, 'J' },
#endif
#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
	{ "micro", no_argument, NULL, OPTION_TSTAMP_MICRO},
	{ "nano", no_argument, NULL, OPTION_TSTAMP_NANO},
	{ "time-stamp-precision", required_argument, NULL, OPTION_TSTAMP_PRECISION},
#endif
	{ "dont-verify-checksums", no_argument, NULL, 'K' },
	{ "list-data-link-types", no_argument, NULL, 'L' },
	{ "no-optimize", no_argument, NULL, 'O' },
	{ "no-promiscuous-mode", no_argument, NULL, 'p' },
	{ "direction", required_argument, NULL, 'Q' },
	{ "snapshot-length", required_argument, NULL, 's' },
	{ "absolute-tcp-sequence-numbers", no_argument, NULL, 'S' },
	{ "packet-buffered", no_argument, NULL, 'U' },
	{ "linktype", required_argument, NULL, 'y' },
#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
	{ "immediate-mode", no_argument, NULL, OPTION_IMMEDIATE_MODE },
#endif
#ifdef HAVE_PCAP_SET_PARSER_DEBUG
	{ "debug-filter-parser", no_argument, NULL, 'Y' },
#endif
	{ "relinquish-privileges", required_argument, NULL, 'Z' },
	{ "count", no_argument, NULL, OPTION_COUNT },
	{ "fp-type", no_argument, NULL, OPTION_FP_TYPE },
	{ "number", no_argument, NULL, '#' },
	{ "print", no_argument, NULL, OPTION_PRINT },
	{ "print-sampling", required_argument, NULL, OPTION_PRINT_SAMPLING },
	{ "lengths", no_argument, NULL, OPTION_LENGTHS },
	{ "time-t-size", no_argument, NULL, OPTION_TIME_T_SIZE },
	{ "ip-oneline", no_argument, NULL, 'g' },
	{ "skip", required_argument, NULL, OPTION_SKIP },
	{ "version", no_argument, NULL, OPTION_VERSION },
	{ NULL, 0, NULL, 0 }
};

#ifdef HAVE_PCAP_FINDALLDEVS_EX
#define LIST_REMOTE_INTERFACES_USAGE " [ --list-remote-interfaces remote-source ]"
#else
#define LIST_REMOTE_INTERFACES_USAGE
#endif

#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
#define IMMEDIATE_MODE_USAGE " [ --immediate-mode ]"
#else
#define IMMEDIATE_MODE_USAGE ""
#endif

#ifndef _WIN32
/* Drop root privileges and chroot if necessary */
static void
droproot(const char *username, const char *chroot_dir)
{
	struct passwd *pw = NULL;

	if (chroot_dir && !username)
		error("Chroot without dropping root is insecure");

	pw = getpwnam(username);
	if (pw) {
		if (chroot_dir) {
			if (chroot(chroot_dir) != 0 || chdir ("/") != 0)
				error("Couldn't chroot/chdir to '%.64s': %s",
				      chroot_dir, pcap_strerror(errno));
		}
#ifdef HAVE_LIBCAP_NG
		{
			int ret = capng_change_id(pw->pw_uid, pw->pw_gid, CAPNG_NO_FLAG);
			if (ret < 0)
				error("capng_change_id(): return %d", ret);
			else
				fprintf(stderr, "dropped privs to %s\n", username);
		}
#else
		if (initgroups(pw->pw_name, pw->pw_gid) != 0 ||
		    setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0)
			error("Couldn't change to '%.32s' uid=%lu gid=%lu: %s",
				username,
				(unsigned long)pw->pw_uid,
				(unsigned long)pw->pw_gid,
				pcap_strerror(errno));
		else {
			fprintf(stderr, "dropped privs to %s\n", username);
		}
#endif /* HAVE_LIBCAP_NG */
	} else
		error("Couldn't find user '%.32s'", username);
#ifdef HAVE_LIBCAP_NG
	/* We don't need CAP_SETUID, CAP_SETGID and CAP_SYS_CHROOT anymore. */
DIAG_OFF_ASSIGN_ENUM
	capng_updatev(
		CAPNG_DROP,
		CAPNG_EFFECTIVE | CAPNG_PERMITTED,
		CAP_SETUID,
		CAP_SETGID,
		CAP_SYS_CHROOT,
		-1);
DIAG_ON_ASSIGN_ENUM
	capng_apply(CAPNG_SELECT_BOTH);
#endif /* HAVE_LIBCAP_NG */

}
#endif /* _WIN32 */

static int
getWflagChars(int x)
{
	int c = 0;

	x -= 1;
	while (x > 0) {
		c += 1;
		x /= 10;
	}

	return c;
}


static void
MakeFilename(char *buffer, char *orig_name, int cnt, int max_chars)
{
        char *filename = malloc(PATH_MAX + 1);
        if (filename == NULL)
            error("%s: malloc", __func__);
        if (strlen(orig_name) == 0)
            error("an empty string is not a valid file name");

        /* Process with strftime if Gflag is set. */
        if (Gflag != 0) {
          struct tm *local_tm;

          /* Convert Gflag_time to a usable format */
          if ((local_tm = localtime(&Gflag_time)) == NULL) {
                  error("%s: localtime", __func__);
          }

          /* There's no good way to detect an error in strftime since a return
           * value of 0 isn't necessarily failure; if orig_name is an empty
           * string, the formatted string will be empty.
           *
           * However, the C90 standard says that, if there *is* a
           * buffer overflow, the content of the buffer is undefined,
           * so we must check for a buffer overflow.
           *
           * So we check above for an empty orig_name, and only call
           * strftime() if it's non-empty, in which case the return
           * value will only be 0 if the formatted date doesn't fit
           * in the buffer.
           *
           * (We check above because, even if we don't use -G, we
           * want a better error message than "tcpdump: : No such
           * file or directory" for this case.)
           */
          if (strftime(filename, PATH_MAX, orig_name, local_tm) == 0) {
            error("%s: strftime", __func__);
          }
        } else {
          strncpy(filename, orig_name, PATH_MAX);
        }

	if (cnt == 0 && max_chars == 0)
		strncpy(buffer, filename, PATH_MAX + 1);
	else
		if (snprintf(buffer, PATH_MAX + 1, "%s%0*d", filename, max_chars, cnt) > PATH_MAX)
                  /* Report an error if the filename is too large */
                  error("too many output files or filename is too long (> %d)", PATH_MAX);
        free(filename);
}

static char *
get_next_file(FILE *VFile, char *ptr)
{
	char *ret;
	size_t len;

	ret = fgets(ptr, PATH_MAX, VFile);
	if (!ret)
		return NULL;

	len = strlen (ptr);
	if (len > 0 && ptr[len - 1] == '\n')
		ptr[len - 1] = '\0';

	return ret;
}

#ifdef HAVE_CASPER
static cap_channel_t *
capdns_setup(void)
{
	cap_channel_t *capcas, *capdnsloc;
	const char *types[1];
	int families[2];

	capcas = cap_init();
	if (capcas == NULL)
		error("unable to create casper process");
	capdnsloc = cap_service_open(capcas, "system.dns");
	/* Casper capability no longer needed. */
	cap_close(capcas);
	if (capdnsloc == NULL)
		error("unable to open system.dns service");
	/* Limit system.dns to reverse DNS lookups. */
	types[0] = "ADDR";
	if (cap_dns_type_limit(capdnsloc, types, 1) < 0)
		error("unable to limit access to system.dns service");
	families[0] = AF_INET;
	/* Casper is a feature of FreeBSD, which defines AF_INET6. */
	families[1] = AF_INET6;
	if (cap_dns_family_limit(capdnsloc, families, 2) < 0)
		error("unable to limit access to system.dns service");

	return (capdnsloc);
}
#endif	/* HAVE_CASPER */

#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
static int
tstamp_precision_from_string(const char *precision)
{
	if (strncmp(precision, "nano", strlen("nano")) == 0)
		return PCAP_TSTAMP_PRECISION_NANO;

	if (strncmp(precision, "micro", strlen("micro")) == 0)
		return PCAP_TSTAMP_PRECISION_MICRO;

	return -EINVAL;
}

static const char *
tstamp_precision_to_string(int precision)
{
	switch (precision) {

	case PCAP_TSTAMP_PRECISION_MICRO:
		return "micro";

	case PCAP_TSTAMP_PRECISION_NANO:
		return "nano";

	default:
		return "unknown";
	}
}
#endif // HAVE_PCAP_SET_TSTAMP_PRECISION

#ifdef HAVE_CAPSICUM
/*
 * Ensure that, on a dump file's descriptor, we have all the rights
 * necessary to make the standard I/O library work with an fdopen()ed
 * FILE * from that descriptor.
 *
 * A long time ago in a galaxy far, far away, AT&T decided that, instead
 * of providing separate APIs for getting and setting the FD_ flags on a
 * descriptor, getting and setting the O_ flags on a descriptor, and
 * locking files, they'd throw them all into a kitchen-sink fcntl() call
 * along the lines of ioctl(), the fact that ioctl() operations are
 * largely specific to particular character devices but fcntl() operations
 * are either generic to all descriptors or generic to all descriptors for
 * regular files notwithstanding.
 *
 * The Capsicum people decided that fine-grained control of descriptor
 * operations was required, so that you need to grant permission for
 * reading, writing, seeking, and fcntl-ing.  The latter, courtesy of
 * AT&T's decision, means that "fcntl-ing" isn't a thing, but a motley
 * collection of things, so there are *individual* fcntls for which
 * permission needs to be granted.
 *
 * The FreeBSD standard I/O people implemented some optimizations that
 * requires that the standard I/O routines be able to determine whether
 * the descriptor for the FILE * is open append-only or not; as that
 * descriptor could have come from an open() rather than an fopen(),
 * that requires that it be able to do an F_GETFL fcntl() to read
 * the O_ flags.
 *
 * tcpdump uses ftell() to determine how much data has been written
 * to a file in order to, when used with -C, determine when it's time
 * to rotate capture files.  ftell() therefore needs to do an lseek()
 * to find out the file offset and must, thanks to the aforementioned
 * optimization, also know whether the descriptor is open append-only
 * or not.
 *
 * The net result of all the above is that we need to grant CAP_SEEK,
 * CAP_WRITE, and CAP_FCNTL with the CAP_FCNTL_GETFL subcapability.
 *
 * Perhaps this is the universe's way of saying that either
 *
 *	1) there needs to be an fopenat() call and a pcap_dump_openat() call
 *	   using it, so that Capsicum-capable tcpdump wouldn't need to do
 *	   an fdopen()
 *
 * or
 *
 *	2) there needs to be a cap_fdopen() call in the FreeBSD standard
 *	   I/O library that knows what rights are needed by the standard
 *	   I/O library, based on the open mode, and assigns them, perhaps
 *	   with an additional argument indicating, for example, whether
 *	   seeking should be allowed, so that tcpdump doesn't need to know
 *	   what the standard I/O library happens to require this week.
 */
static void
set_dumper_capsicum_rights(pcap_dumper_t *p)
{
	int fd = fileno(pcap_dump_file(p));
	cap_rights_t rights;

	cap_rights_init(&rights, CAP_SEEK, CAP_WRITE, CAP_FCNTL);
	if (cap_rights_limit(fd, &rights) < 0 && errno != ENOSYS) {
		error("unable to limit dump descriptor");
	}
	if (cap_fcntls_limit(fd, CAP_FCNTL_GETFL) < 0 && errno != ENOSYS) {
		error("unable to limit dump descriptor fcntls");
	}
}
#endif // HAVE_CAPSICUM

/*
 * Copy arg vector into a new buffer, concatenating arguments with spaces.
 */
static char *
copy_argv(char **argv)
{
	char **p;
	size_t len = 0;
	char *buf;
	char *src, *dst;

	p = argv;
	if (*p == NULL)
		return 0;

	while (*p)
		len += strlen(*p++) + 1;

	buf = (char *)malloc(len);
	if (buf == NULL)
		error("%s: malloc", __func__);

	p = argv;
	dst = buf;
	while ((src = *p++) != NULL) {
		while ((*dst++ = *src++) != '\0')
			;
		dst[-1] = ' ';
	}
	dst[-1] = '\0';

	return buf;
}

/*
 * On Windows, we need to open the file in binary mode, so that
 * we get all the bytes specified by the size we get from "fstat()".
 * On UNIX, that's not necessary.  O_BINARY is defined on Windows;
 * we define it as 0 if it's not defined, so it does nothing.
 */
#ifndef O_BINARY
#define O_BINARY	0
#endif

static char *
read_infile(char *fname)
{
	int i, fd;
	ssize_t cc;
	char *cp;
	our_statb buf;

	fd = open(fname, O_RDONLY|O_BINARY);
	if (fd < 0)
		error("can't open %s: %s", fname, pcap_strerror(errno));

	if (our_fstat(fd, &buf) < 0)
		error("can't stat %s: %s", fname, pcap_strerror(errno));

	/*
	 * Reject files whose size doesn't fit into an int; a filter
	 * *that* large will probably be too big.
	 */
	if (buf.st_size > INT_MAX)
		error("%s is too large", fname);

	cp = malloc((u_int)buf.st_size + 1);
	if (cp == NULL)
		error("malloc(%d) for %s: %s", (u_int)buf.st_size + 1,
			fname, pcap_strerror(errno));
	cc = read(fd, cp, (u_int)buf.st_size);
	if (cc < 0)
		error("read %s: %s", fname, pcap_strerror(errno));
	if (cc != buf.st_size)
		error("short read %s (%d != %d)", fname, (int) cc,
		    (int)buf.st_size);

	close(fd);
	/* replace "# comment" with spaces */
	for (i = 0; i < cc; i++) {
		if (cp[i] == '#')
			while (i < cc && cp[i] != '\n')
				cp[i++] = ' ';
	}
	cp[cc] = '\0';
	return (cp);
}

static long
parse_interface_number(const char *device)
{
	const char *p;
	long devnum;
	char *end;

	/*
	 * Search for a colon, terminating any scheme at the beginning
	 * of the device.
	 */
	p = strchr(device, ':');
	if (p != NULL) {
		/*
		 * We found it.  Is it followed by "//"?
		 */
		p++;	/* skip the : */
		if (strncmp(p, "//", 2) == 0) {
			/*
			 * Yes.  Search for the next /, at the end of the
			 * authority part of the URL.
			 */
			p += 2;	/* skip the // */
			p = strchr(p, '/');
			if (p != NULL) {
				/*
				 * OK, past the / is the path.
				 */
				device = p + 1;
			}
		}
	}
	devnum = strtol(device, &end, 10);
	if (device != end && *end == '\0') {
		/*
		 * It's all-numeric, but is it a valid number?
		 */
		if (devnum <= 0) {
			/*
			 * No, it's not an ordinal.
			 */
			error("Invalid adapter index %s", device);
		}
		return (devnum);
	} else {
		/*
		 * It's not all-numeric; return -1, so our caller
		 * knows that.
		 */
		return (-1);
	}
}

static char *
find_interface_by_number(const char *url
#ifndef HAVE_PCAP_FINDALLDEVS_EX
_U_
#endif
, long devnum)
{
	pcap_if_t *dev, *devlist;
	long i;
	char ebuf[PCAP_ERRBUF_SIZE];
	char *device;
#ifdef HAVE_PCAP_FINDALLDEVS_EX
	const char *endp;
	char *host_url;
#endif
	int status;

#ifdef HAVE_PCAP_FINDALLDEVS_EX
	/*
	 * Search for a colon, terminating any scheme at the beginning
	 * of the URL.
	 */
	endp = strchr(url, ':');
	if (endp != NULL) {
		/*
		 * We found it.  Is it followed by "//"?
		 */
		endp++;	/* skip the : */
		if (strncmp(endp, "//", 2) == 0) {
			/*
			 * Yes.  Search for the next /, at the end of the
			 * authority part of the URL.
			 */
			endp += 2;	/* skip the // */
			endp = strchr(endp, '/');
		} else
			endp = NULL;
	}
	if (endp != NULL) {
		/*
		 * OK, everything from device to endp is a URL to hand
		 * to pcap_findalldevs_ex().
		 */
		endp++;	/* Include the trailing / in the URL; pcap_findalldevs_ex() requires it */
		host_url = malloc(endp - url + 1);
		if (host_url == NULL && (endp - url + 1) > 0)
			error("Invalid allocation for host");

		memcpy(host_url, url, endp - url);
		host_url[endp - url] = '\0';
		status = pcap_findalldevs_ex(host_url, NULL, &devlist, ebuf);
		free(host_url);
	} else
#endif // HAVE_PCAP_FINDALLDEVS_EX
	status = pcap_findalldevs(&devlist, ebuf);
	if (status < 0)
		error("%s", ebuf);
	if (devlist == NULL)
		error("no interfaces available for capture");
	/*
	 * Look for the devnum-th entry in the list of devices (1-based).
	 */
	for (i = 0, dev = devlist; i < devnum-1 && dev != NULL;
	    i++, dev = dev->next)
		;
	if (dev == NULL) {
		pcap_freealldevs(devlist);
		error("Invalid adapter index %ld: only %ld interface%s found",
		    devnum, i, (i == 1) ? "" : "s");
	}
	device = strdup(dev->name);
	pcap_freealldevs(devlist);
	return (device);
}

#ifdef HAVE_PCAP_OPEN
/*
 * Prefixes for rpcap URLs.
 */
static char rpcap_prefix[] = "rpcap://";
static char rpcap_ssl_prefix[] = "rpcaps://";
#endif

static pcap_t *
open_interface(const char *device, netdissect_options *ndo, char *ebuf)
{
	pcap_t *pc;
	int status;
	char *cp;

#ifdef HAVE_PCAP_OPEN
	/*
	 * Is this an rpcap URL?
	 */
	if (strncmp(device, rpcap_prefix, sizeof(rpcap_prefix) - 1) == 0 ||
	    strncmp(device, rpcap_ssl_prefix, sizeof(rpcap_ssl_prefix) - 1) == 0) {
		/*
		 * Yes.  Open it with pcap_open().
		 */
		*ebuf = '\0';
		pc = pcap_open(device, ndo->ndo_snaplen,
		    pflag ? 0 : PCAP_OPENFLAG_PROMISCUOUS, timeout, NULL,
		    ebuf);
		if (pc == NULL) {
			/*
			 * macOS 14's pcap_pcap_open(), which is a
			 * stub that always returns NULL with an error
			 * message of "not supported".
			 *
			 * In this case, as we passed it an rpcap://
			 * URL, treat that as meaning "remote capture
			 * not supported".
			 */
			if (strcmp(ebuf, "not supported") == 0)
				error("Remote capture not supported");

			/*
			 * If this failed with "No such device" or "The system
			 * cannot find the device specified", that means
			 * the interface doesn't exist; return NULL, so that
			 * the caller can see whether the device name is
			 * actually an interface index.
			 */
			if (strstr(ebuf, "No such device") != NULL ||
			    strstr(ebuf, "The system cannot find the device specified") != NULL)
				return (NULL);
			error("%s", ebuf);
		}
		if (*ebuf)
			warning("%s", ebuf);
		return (pc);
	}
#endif /* HAVE_PCAP_OPEN */

	pc = pcap_create(device, ebuf);
	if (pc == NULL) {
		/*
		 * If this failed with "No such device", that means
		 * the interface doesn't exist; return NULL, so that
		 * the caller can see whether the device name is
		 * actually an interface index.
		 */
		if (strstr(ebuf, "No such device") != NULL)
			return (NULL);
		error("%s", ebuf);
	}
#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
	if (Jflag)
		show_tstamp_types_and_exit(pc, device);
#endif
#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
	status = pcap_set_tstamp_precision(pc, ndo->ndo_tstamp_precision);
	if (status != 0)
		error("%s: Can't set %ssecond time stamp precision: %s",
		    device,
		    tstamp_precision_to_string(ndo->ndo_tstamp_precision),
		    pcap_statustostr(status));
#endif

#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
	if (immediate_mode) {
		status = pcap_set_immediate_mode(pc, 1);
		if (status != 0)
			error("%s: Can't set immediate mode: %s",
			    device, pcap_statustostr(status));
	}
#endif
	/*
	 * Is this an interface that supports monitor mode?
	 */
	if (pcap_can_set_rfmon(pc) == 1)
		supports_monitor_mode = 1;
	else
		supports_monitor_mode = 0;
	if (ndo->ndo_snaplen != 0) {
		/*
		 * A snapshot length was explicitly specified;
		 * use it.
		 */
		status = pcap_set_snaplen(pc, ndo->ndo_snaplen);
		if (status != 0)
			error("%s: Can't set snapshot length: %s",
			    device, pcap_statustostr(status));
	}
	status = pcap_set_promisc(pc, !pflag);
	if (status != 0)
		error("%s: Can't set promiscuous mode: %s",
		    device, pcap_statustostr(status));
	if (Iflag) {
		status = pcap_set_rfmon(pc, 1);
		if (status != 0)
			error("%s: Can't set monitor mode: %s",
			    device, pcap_statustostr(status));
	}
	status = pcap_set_timeout(pc, timeout);
	if (status != 0)
		error("%s: pcap_set_timeout failed: %s",
		    device, pcap_statustostr(status));
	if (Bflag != 0) {
		status = pcap_set_buffer_size(pc, Bflag);
		if (status != 0)
			error("%s: Can't set buffer size: %s",
			    device, pcap_statustostr(status));
	}
#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
	if (jflag != -1) {
		status = pcap_set_tstamp_type(pc, jflag);
		if (status < 0)
			error("%s: Can't set time stamp type: %s",
			    device, pcap_statustostr(status));
		else if (status > 0)
			warning("When trying to set timestamp type '%s' on %s: %s",
			    pcap_tstamp_type_val_to_name(jflag), device,
			    pcap_statustostr(status));
	}
#endif
	status = pcap_activate(pc);
	if (status < 0) {
		/*
		 * pcap_activate() failed.
		 */
		cp = pcap_geterr(pc);
		if (status == PCAP_ERROR)
			error("%s: %s", device, cp);
		else if (status == PCAP_ERROR_NO_SUCH_DEVICE) {
			/*
			 * Return an error for our caller to handle.
			 */
			snprintf(ebuf, PCAP_ERRBUF_SIZE, "%s: %s\n(%s)",
			    device, pcap_statustostr(status), cp);
		} else if (status == PCAP_ERROR_PERM_DENIED && *cp != '\0')
			error("%s: %s\n(%s)", device,
			    pcap_statustostr(status), cp);
#ifdef PCAP_ERROR_CAPTURE_NOTSUP
		else if (status == PCAP_ERROR_CAPTURE_NOTSUP && *cp != '\0')
			error("%s: %s\n(%s)", device,
			    pcap_statustostr(status), cp);
#endif
#ifdef __FreeBSD__
		else if (status == PCAP_ERROR_RFMON_NOTSUP &&
		    strncmp(device, "wlan", 4) == 0) {
			char parent[8], newdev[8];
			char sysctl[32];
			size_t s = sizeof(parent);

			snprintf(sysctl, sizeof(sysctl),
			    "net.wlan.%d.%%parent", atoi(device + 4));
			sysctlbyname(sysctl, parent, &s, NULL, 0);
			strlcpy(newdev, device, sizeof(newdev));
			/* Suggest a new wlan device. */
			/* FIXME: incrementing the index this way is not going to work well
			 * when the index is 9 or greater but the only consequence in this
			 * specific case would be an error message that looks a bit odd.
			 */
			newdev[strlen(newdev)-1]++;
			error("%s is not a monitor mode VAP"
			    "To create a new monitor mode VAP use:\n"
			    "  ifconfig %s create wlandev %s wlanmode monitor\n"
			    "and use %s as the tcpdump interface",
			    device, newdev, parent, newdev);
		}
#endif // __FreeBSD__
		else
			error("%s: %s", device,
			    pcap_statustostr(status));
		pcap_close(pc);
		return (NULL);
	} else if (status > 0) {
		/*
		 * pcap_activate() succeeded, but it's warning us
		 * of a problem it had.
		 */
		cp = pcap_geterr(pc);
		if (status == PCAP_WARNING)
			warning("%s", cp);
		else if (status == PCAP_WARNING_PROMISC_NOTSUP &&
		         *cp != '\0')
			warning("%s: %s\n(%s)", device,
			    pcap_statustostr(status), cp);
		else
			warning("%s: %s", device,
			    pcap_statustostr(status));
	}
	if (Qflag != -1) {
		status = pcap_setdirection(pc, Qflag);
		if (status != 0)
			error("%s: pcap_setdirection() failed: %s",
			      device,  pcap_geterr(pc));
	}

	return (pc);
}

int
main(int argc, char **argv)
{
	int cnt, op, i;
	bpf_u_int32 localnet = 0, netmask = 0;
	char *cp, *infile, *cmdbuf, *device, *RFileName, *VFileName, *WFileName;
	char *endp;
	pcap_handler callback;
	int dlt;
	const char *dlt_name;
	struct bpf_program fcode;
#ifndef _WIN32
	void (*oldhandler)(int);
#endif
	struct dump_info dumpinfo;
	u_char *pcap_userdata;
	char ebuf[PCAP_ERRBUF_SIZE];
	char VFileLine[PATH_MAX + 1];
	const char *username = NULL;
#ifndef _WIN32
	const char *chroot_dir = NULL;
#endif
	char *ret = NULL;
	pcap_if_t *devlist;
	long devnum;
	int status;
	FILE *VFile;
#ifdef HAVE_CAPSICUM
	cap_rights_t rights;
	int cansandbox;
#endif	/* HAVE_CAPSICUM */
	int Oflag = 1;			/* run filter code optimizer */
	int yflag_dlt = -1;
	const char *yflag_dlt_name = NULL;
	int print = 0;
	long Cflagmult;

	netdissect_options Ndo;
	netdissect_options *ndo = &Ndo;

#ifdef _WIN32
	/*
	 * We need to look for wpcap.dll in \Windows\System32\Npcap first,
	 * as either:
	 *
	 *  1) WinPcap isn't installed and Npcap isn't installed in "WinPcap
	 *     API-compatible Mode", so there's no wpcap.dll in
	 *     \Windows\System32, only in \Windows\System32\Npcap;
	 *
	 *  2) WinPcap is installed and Npcap isn't installed in "WinPcap
	 *     API-compatible Mode", so the wpcap.dll in \Windows\System32
	 *     is a WinPcap DLL, but we'd prefer an Npcap DLL (we should
	 *     work with either one if we're configured against WinPcap,
	 *     and we'll probably require Npcap if we're configured against
	 *     it), and that's in \Windows\System32\Npcap;
	 *
	 *  3) Npcap is installed in "WinPcap API-compatible Mode", so both
	 *     \Windows\System32 and \Windows\System32\Npcap have an Npcap
	 *     wpcap.dll.
	 *
	 * Unfortunately, Windows has no notion of an rpath, so we can't
	 * set the rpath to include \Windows\System32\Npcap at link time;
	 * what we need to do is to link wpcap as a delay-load DLL and
	 * add \Windows\System32\Npcap to the DLL search path early in
	 * main() with a call to SetDllDirectory().
	 *
	 * The same applies to packet.dll.
	 *
	 * We add \Windows\System32\Npcap here.
	 *
	 * See https://npcap.com/guide/npcap-devguide.html#npcap-feature-native-dll-implicitly
	 */
	WCHAR *dll_directory = NULL;
	size_t dll_directory_buf_len = 0;	/* units of bytes */
	UINT system_directory_buf_len = 0;	/* units of WCHARs */
	UINT system_directory_len;		/* units of WCHARs */
	static const WCHAR npcap[] = L"\\Npcap";

	/*
	 * Get the system directory path, in UTF-16, into a buffer that's
	 * large enough for that directory path plus "\Npcap".
	 *
	 * String manipulation in C, plus fetching a variable-length
	 * string into a buffer whose size is fixed at the time of
	 * the call, with an oddball return value (see below), is just
	 * a huge bag of fun.
	 *
	 * And it's even more fun when dealing with UTF-16, so that the
	 * buffer sizes used in GetSystemDirectoryW() are in different
	 * units from the buffer sizes used in realloc()!   We maintain
	 * all sizes/length in units of bytes, not WCHARs, so that our
	 * heads don't explode.
	 */
	for (;;) {
		/*
		 * Try to fetch the system directory.
		 *
		 * GetSystemDirectoryW() expects a buffer size in units
		 * of WCHARs, not bytes, and returns a directory path
		 * length in units of WCHARs, not bytes.
		 *
		 * For extra fun, if GetSystemDirectoryW() succeeds,
		 * the return value is the length of the directory
		 * path in units of WCHARs, *not* including the
		 * terminating '\0', but if it fails because the
		 * path string wouldn't fit, the return value is
		 * the length of the directory path in units of WCHARs,
		 * *including* the terminating '\0'.
		 */
		system_directory_len = GetSystemDirectoryW(dll_directory,
		    system_directory_buf_len);
		if (system_directory_len == 0)
			error("GetSystemDirectoryW() failed");

		/*
		 * Did the directory path fit in the buffer?
		 *
		 * As per the above, this means that the return value
		 * *plus 1*, so that the terminating '\0' is counted,
		 * is <= the buffer size.
		 *
		 * (If the directory path, complete with the terminating
		 * '\0', fits *exactly*, the return value would be the
		 * size of the buffer minus 1, as it doesn't count the
		 * terminating '\0', so the test below would succeed.
		 *
		 * If everything *but* the terminating '\0' fits,
		 * the return value would be the size of the buffer + 1,
		 * i.e., the size that the string in question would
		 * have required.
		 *
		 * The astute reader will note that returning the
		 * size of the buffer is not one of the two cases
		 * above, and should never happen.)
		 */
		if ((system_directory_len + 1) <= system_directory_buf_len) {
			/*
			 * No.  We have a buffer that's large enough
			 * for our purposes.
			 */
			break;
		}

		/*
		 * Yes.  Grow the buffer.
		 *
		 * The space we'll need in the buffer for the system
		 * directory, in units of WCHARs, is system_directory_len,
		 * as that's the length of the system directory path
		 * including the terminating '\0'.
		 */
		system_directory_buf_len = system_directory_len;

		/*
		 * The size of the DLL directory buffer, in *bytes*, must
		 * be the number of WCHARs taken by the system directory,
		 * *minus* the terminating '\0' (as we'll overwrite that
		 * with the "\" of the "\Npcap" string), multiplied by
		 * sizeof(WCHAR) to convert it to the number of bytes,
		 * plus the size of the "\Npcap" string, in bytes (which
		 * will include the terminating '\0', as that will become
		 * the DLL path's terminating '\0').
		 */
		dll_directory_buf_len =
		    ((system_directory_len - 1)*sizeof(WCHAR)) + sizeof npcap;
		dll_directory = realloc(dll_directory, dll_directory_buf_len);
		if (dll_directory == NULL)
			error("Can't allocate string for Npcap directory");
	}

	/*
	 * OK, that worked.
	 *
	 * Now append \Npcap.  We add the length of the system directory path,
	 * in WCHARs, *not* including the terminating '\0' (which, since
	 * GetSystemDirectoryW() succeeded, is the return value of
	 * GetSystemDirectoryW(), as per the above), to the pointer to the
	 * beginning of the path, to go past the end of the system directory
	 * to point to the terminating '\0'.
	 */
	memcpy(dll_directory + system_directory_len, npcap, sizeof npcap);

	/*
	 * Now add that as a system DLL directory.
	 */
	if (!SetDllDirectoryW(dll_directory))
		error("SetDllDirectory failed");

	free(dll_directory);
#endif // _WIN32

	/*
	 * Initialize the netdissect code.
	 */
	if (nd_init(ebuf, sizeof(ebuf)) == -1)
		error("%s", ebuf);

	memset(ndo, 0, sizeof(*ndo));
	ndo_set_function_pointers(ndo);

	cnt = -1;
	device = NULL;
	infile = NULL;
	RFileName = NULL;
	VFileName = NULL;
	VFile = NULL;
	WFileName = NULL;
	dlt = -1;
	if ((cp = strrchr(argv[0], PATH_SEPARATOR)) != NULL)
		ndo->program_name = program_name = cp + 1;
	else
		ndo->program_name = program_name = argv[0];

#if defined(HAVE_PCAP_WSOCKINIT)
	if (pcap_wsockinit() != 0)
		error("Attempting to initialize Winsock failed");
#elif defined(HAVE_WSOCKINIT)
	if (wsockinit() != 0)
		error("Attempting to initialize Winsock failed");
#endif

	/*
	 * An explicit tzset() call is usually not needed as it happens
	 * implicitly the first time we call localtime() or mktime(),
	 * but in some cases (sandboxing, chroot) this may be too late.
	 */
	tzset();

	while (
	    (op = getopt_long(argc, argv, SHORTOPTS, longopts, NULL)) != -1)
		switch (op) {

		case 'a':
			/* compatibility for old -a */
			break;

		case 'A':
			++ndo->ndo_Aflag;
			break;

		case 'b':
			++ndo->ndo_bflag;
			break;

		case 'B':
			Bflag = parse_int("packet buffer size", optarg, NULL, 1,
			    INT_MAX, 10);
			/*
			 * Will multiplying it by 1024 overflow?
			 */
			if (Bflag > INT_MAX / 1024)
				error("packet buffer size %s is too large", optarg);
			Bflag *= 1024;
			break;

		case 'c':
			cnt = parse_int("packet count", optarg, NULL, 1,
			    INT_MAX, 10);
			break;

		case 'C':
			Cflag = parse_int64("file size", optarg, &endp, 1,
			    INT64_MAX, 10);

			if (*endp == '\0') {
				/*
				 * There's nothing after the file size,
				 * so the size is in units of 1 MB
				 * (1,000,000 bytes).
				 */
				Cflagmult = 1000000;
			} else {
				/*
				 * There's something after the file
				 * size.
				 *
				 * If it's a single letter, then:
				 *
				 *   if the letter is k or K, the size
				 *   is in units of 1 KiB (1024 bytes);
				 *
				 *   if the letter is m or M, the size
				 *   is in units of 1 MiB (1,048,576 bytes);
				 *
				 *   if the letter is g or G, the size
				 *   is in units of 1 GiB (1,073,741,824 bytes).
				 *
				 * Otherwise, it's an error.
				 */
				switch (*endp) {

				case 'k':
				case 'K':
					Cflagmult = 1024;
					break;

				case 'm':
				case 'M':
					Cflagmult = 1024*1024;
					break;

				case 'g':
				case 'G':
					Cflagmult = 1024*1024*1024;
					break;

				default:
					error("invalid file size %s (invalid units)", optarg);
				}

				/*
				 * OK, there was a letter that we treat
				 * as a units indication; was there
				 * anything after it?
				 */
				endp++;
				if (*endp != '\0') {
					/* Yes - error */
					error("invalid file size %s (invalid units)", optarg);
				}
			}

			/*
			 * Will multiplying it by multiplier overflow?
			 */
#ifdef HAVE_PCAP_DUMP_FTELL64
			if (Cflag > INT64_MAX / Cflagmult)
#else
			if (Cflag > LONG_MAX / Cflagmult)
#endif
				error("file size %s is too large", optarg);
			Cflag *= Cflagmult;
			break;

		case 'd':
			++dflag;
			break;

		case 'D':
			Dflag++;
			break;

#ifdef HAVE_PCAP_FINDALLDEVS_EX
		case OPTION_LIST_REMOTE_INTERFACES:
			remote_interfaces_source = optarg;
			break;
#endif

		case 'L':
			Lflag++;
			break;

		case 'e':
			++ndo->ndo_eflag;
			break;

#ifdef HAVE_LIBCRYPTO
		case 'E':
			ndo->ndo_espsecret = optarg;
			break;
#endif

		case 'f':
			++ndo->ndo_fflag;
			break;

		case 'F':
			infile = optarg;
			break;

		case 'g':
			++ndo->ndo_gflag;
			break;

		case 'G':
			Gflag = parse_int("number of seconds", optarg, NULL, 0,
			    INT_MAX, 10);

                        /* We will create one file initially. */
                        Gflag_count = 0;

			/* Grab the current time for rotation use. */
			if ((Gflag_time = time(NULL)) == (time_t)-1) {
				error("%s: can't get current time: %s",
				    __func__, pcap_strerror(errno));
			}
			break;

		case 'h':
			print_usage(stdout);
			exit_tcpdump(S_SUCCESS);
			/* NOTREACHED */

		case 'H':
			++ndo->ndo_Hflag;
			break;

		case 'i':
			device = optarg;
			break;

		case 'I':
			++Iflag;
			break;

#ifdef HAVE_PCAP_SET_TSTAMP_TYPE
		case 'j':
			jflag = pcap_tstamp_type_name_to_val(optarg);
			if (jflag < 0)
				error("invalid time stamp type %s", optarg);
			break;

		case 'J':
			Jflag++;
			break;
#endif

		case 'l':
#ifdef _WIN32
			/*
			 * _IOLBF is the same as _IOFBF in Microsoft's C
			 * libraries; the only alternative they offer
			 * is _IONBF.
			 *
			 * XXX - this should really be checking for MSVC++,
			 * not _WIN32, if, for example, MinGW has its own
			 * C library that is more UNIX-compatible.
			 */
			setvbuf(stdout, NULL, _IONBF, 0);
#else /* _WIN32 */
			setvbuf(stdout, NULL, _IOLBF, 0);
#endif /* _WIN32 */
			lflag = 1;
			break;

		case 'K':
			++ndo->ndo_Kflag;
			break;

		case 'm':
			if (nd_have_smi_support()) {
				if (nd_load_smi_module(optarg, ebuf, sizeof(ebuf)) == -1)
					error("%s", ebuf);
			} else {
				(void)fprintf(stderr, "%s: ignoring option '-m %s' ",
					      program_name, optarg);
				(void)fprintf(stderr, "(no libsmi support)\n");
			}
			break;

#ifdef HAVE_LIBCRYPTO
		case 'M':
			/* TCP-MD5 shared secret */
			ndo->ndo_sigsecret = optarg;
			break;
#endif

		case 'n':
			++ndo->ndo_nflag;
			break;

		case 'N':
			++ndo->ndo_Nflag;
			break;

		case 'O':
			Oflag = 0;
			break;

		case 'p':
			++pflag;
			break;

		case 'q':
			++ndo->ndo_qflag;
			++ndo->ndo_suppress_default_print;
			break;

		case 'Q':
			if (ascii_strcasecmp(optarg, "in") == 0)
				Qflag = PCAP_D_IN;
			else if (ascii_strcasecmp(optarg, "out") == 0)
				Qflag = PCAP_D_OUT;
			else if (ascii_strcasecmp(optarg, "inout") == 0)
				Qflag = PCAP_D_INOUT;
			else
				error("unknown capture direction '%s'", optarg);
			break;

		case 'r':
			RFileName = optarg;
			break;

		case 's':
			ndo->ndo_snaplen = parse_int("snaplen", optarg, NULL,
			    0, MAXIMUM_SNAPLEN, 0);
			break;

		case 'S':
			++ndo->ndo_Sflag;
			break;

		case 't':
			++ndo->ndo_tflag;
			break;

		case 'T':
			if (ascii_strcasecmp(optarg, "vat") == 0)
				ndo->ndo_packettype = PT_VAT;
			else if (ascii_strcasecmp(optarg, "wb") == 0)
				ndo->ndo_packettype = PT_WB;
			else if (ascii_strcasecmp(optarg, "rpc") == 0)
				ndo->ndo_packettype = PT_RPC;
			else if (ascii_strcasecmp(optarg, "rtp") == 0)
				ndo->ndo_packettype = PT_RTP;
			else if (ascii_strcasecmp(optarg, "rtcp") == 0)
				ndo->ndo_packettype = PT_RTCP;
			else if (ascii_strcasecmp(optarg, "snmp") == 0)
				ndo->ndo_packettype = PT_SNMP;
			else if (ascii_strcasecmp(optarg, "cnfp") == 0)
				ndo->ndo_packettype = PT_CNFP;
			else if (ascii_strcasecmp(optarg, "tftp") == 0)
				ndo->ndo_packettype = PT_TFTP;
			else if (ascii_strcasecmp(optarg, "aodv") == 0)
				ndo->ndo_packettype = PT_AODV;
			else if (ascii_strcasecmp(optarg, "carp") == 0)
				ndo->ndo_packettype = PT_CARP;
			else if (ascii_strcasecmp(optarg, "radius") == 0)
				ndo->ndo_packettype = PT_RADIUS;
			else if (ascii_strcasecmp(optarg, "zmtp1") == 0)
				ndo->ndo_packettype = PT_ZMTP1;
			else if (ascii_strcasecmp(optarg, "vxlan") == 0)
				ndo->ndo_packettype = PT_VXLAN;
			else if (ascii_strcasecmp(optarg, "pgm") == 0)
				ndo->ndo_packettype = PT_PGM;
			else if (ascii_strcasecmp(optarg, "pgm_zmtp1") == 0)
				ndo->ndo_packettype = PT_PGM_ZMTP1;
			else if (ascii_strcasecmp(optarg, "lmp") == 0)
				ndo->ndo_packettype = PT_LMP;
			else if (ascii_strcasecmp(optarg, "resp") == 0)
				ndo->ndo_packettype = PT_RESP;
			else if (ascii_strcasecmp(optarg, "ptp") == 0)
				ndo->ndo_packettype = PT_PTP;
			else if (ascii_strcasecmp(optarg, "someip") == 0)
				ndo->ndo_packettype = PT_SOMEIP;
			else if (ascii_strcasecmp(optarg, "domain") == 0)
				ndo->ndo_packettype = PT_DOMAIN;
			else if (ascii_strcasecmp(optarg, "quic") == 0)
				ndo->ndo_packettype = PT_QUIC;
			else
				error("unknown packet type '%s'", optarg);
			break;

		case 'u':
			++ndo->ndo_uflag;
			break;

		case 'U':
			++Uflag;
			break;

		case 'v':
			++ndo->ndo_vflag;
			break;

		case 'V':
			VFileName = optarg;
			break;

		case 'w':
			WFileName = optarg;
			break;

		case 'W':
			Wflag = parse_int("number of output files", optarg,
			    NULL, 1, INT_MAX, 10);
			WflagChars = getWflagChars(Wflag);
			break;

		case 'x':
			++ndo->ndo_xflag;
			++ndo->ndo_suppress_default_print;
			break;

		case 'X':
			++ndo->ndo_Xflag;
			++ndo->ndo_suppress_default_print;
			break;

		case 'y':
			yflag_dlt_name = optarg;
			yflag_dlt =
				pcap_datalink_name_to_val(yflag_dlt_name);
			if (yflag_dlt < 0)
				error("invalid data link type %s", yflag_dlt_name);
			break;

#ifdef HAVE_PCAP_SET_PARSER_DEBUG
		case 'Y':
			{
			/* Undocumented flag */
			pcap_set_parser_debug(1);
			}
			break;
#endif

#if defined(HAVE_FORK) || defined(HAVE_VFORK)
		case 'z':
			zflag = optarg;
			break;
#endif

		case 'Z':
			username = optarg;
			break;

		case '#':
			ndo->ndo_packet_number = 1;
			break;

		case OPTION_LENGTHS:
			ndo->ndo_lengths = 1;
			break;

		case OPTION_TIME_T_SIZE:
			printf("%zu\n", sizeof(time_t) * 8);
			return 0;

		case OPTION_VERSION:
			print_version(stdout);
			exit_tcpdump(S_SUCCESS);
			/* NOTREACHED */

#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
		case OPTION_TSTAMP_PRECISION:
			ndo->ndo_tstamp_precision = tstamp_precision_from_string(optarg);
			if (ndo->ndo_tstamp_precision < 0)
				error("unsupported time stamp precision");
			break;
#endif

#ifdef HAVE_PCAP_SET_IMMEDIATE_MODE
		case OPTION_IMMEDIATE_MODE:
			immediate_mode = 1;
			break;
#endif

		case OPTION_PRINT:
			print = 1;
			break;

		case OPTION_PRINT_SAMPLING:
			print = 1;
			++ndo->ndo_Sflag;
			ndo->ndo_print_sampling = parse_int("print sampling",
			    optarg, NULL, 1, INT_MAX, 10);
			break;

		case OPTION_SKIP:
			packets_to_skip = parse_u_int("packet skip count",
			    optarg, NULL, 0, INT_MAX, 0);
			break;

#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
		case OPTION_TSTAMP_MICRO:
			ndo->ndo_tstamp_precision = PCAP_TSTAMP_PRECISION_MICRO;
			break;

		case OPTION_TSTAMP_NANO:
			ndo->ndo_tstamp_precision = PCAP_TSTAMP_PRECISION_NANO;
			break;
#endif

		case OPTION_FP_TYPE:
			/*
			 * Print out the type of floating-point arithmetic
			 * we're doing; it's probably IEEE, unless somebody
			 * tries to run this on a VAX, but the precision
			 * may differ (e.g., it might be 32-bit, 64-bit,
			 * or 80-bit).
			 */
			float_type_check(0x4e93312d);
			return 0;

		case OPTION_COUNT:
			count_mode = 1;
			break;

		default:
			print_usage(stderr);
			exit_tcpdump(S_ERR_HOST_PROGRAM);
			/* NOTREACHED */
		}

	if (ndo->ndo_Aflag && ndo->ndo_xflag)
		error("-A and -x[x] are mutually exclusive.");
	if (ndo->ndo_Aflag && ndo->ndo_Xflag)
		error("-A and -X[X] are mutually exclusive.");
	if (ndo->ndo_xflag && ndo->ndo_Xflag)
		error("-x[x] and -X[X] are mutually exclusive.");
	if (Cflag != 0 && WFileName == NULL)
		error("-C cannot be used without -w.");
	if (Gflag != 0 && WFileName == NULL)
		error("-G cannot be used without -w.");
#if defined(HAVE_FORK) || defined(HAVE_VFORK)
	if (zflag != NULL && (WFileName == NULL || (Cflag == 0 && Gflag == 0)))
		error("-z cannot be used without -w and (-C or -G).");
#endif

	if (cnt != -1)
		if ((int)packets_to_skip > (INT_MAX - cnt))
			// cnt + (int)packets_to_skip used in pcap_loop() call
			error("Overflow (-c count) %d + (--skip count) %d", cnt,
			      (int)packets_to_skip);

	if (Dflag)
		show_devices_and_exit();
#ifdef HAVE_PCAP_FINDALLDEVS_EX
	if (remote_interfaces_source != NULL)
		show_remote_devices_and_exit();
#endif

	switch (ndo->ndo_tflag) {

	case 0: /* Default */
	case 1: /* No time stamp */
	case 2: /* Unix timeval style */
	case 3: /* Microseconds/nanoseconds since previous packet */
	case 4: /* Date + Default */
	case 5: /* Microseconds/nanoseconds since first packet */
		break;

	default: /* Not supported */
		error("only -t, -tt, -ttt, -tttt and -ttttt are supported");
		/* NOTREACHED */
	}

	if (ndo->ndo_fflag != 0 && (VFileName != NULL || RFileName != NULL))
		error("-f cannot be used with -V or -r.");

	if (VFileName != NULL && RFileName != NULL)
		error("-V and -r are mutually exclusive.");

	/*
	 * If we're printing dissected packets to the standard output,
	 * and either the standard output is a terminal or we're doing
	 * "line" buffering, set the capture timeout to .1 second rather
	 * than 1 second, as the user's probably expecting to see packets
	 * pop up immediately shortly after they arrive.
	 *
	 * XXX - would there be some value appropriate for all cases,
	 * based on, say, the buffer size and packet input rate?
	 */
	if ((WFileName == NULL || print) && (isatty(1) || lflag))
		timeout = 100;

#ifdef WITH_CHROOT
	/* if run as root, prepare for chrooting */
	if (getuid() == 0 || geteuid() == 0) {
		/* future extensibility for cmd-line arguments */
		if (!chroot_dir)
			chroot_dir = WITH_CHROOT;
	}
#endif

#ifdef WITH_USER
	/* if run as root, prepare for dropping root privileges */
	if (getuid() == 0 || geteuid() == 0) {
		/* Run with '-Z root' to restore old behaviour */
		if (!username)
			username = WITH_USER;
		else if (strcmp(username, "root") == 0)
			username = NULL;
	}
#endif

	if (RFileName != NULL || VFileName != NULL) {
		/*
		 * If RFileName is non-null, it's the pathname of a
		 * savefile to read.  If VFileName is non-null, it's
		 * the pathname of a file containing a list of pathnames
		 * (one per line) of savefiles to read.
		 *
		 * In either case, we're reading a savefile, not doing
		 * a live capture.
		 */
#ifndef _WIN32
		/*
		 * We don't need network access, so relinquish any set-UID
		 * or set-GID privileges we have (if any).
		 *
		 * We do *not* want set-UID privileges when opening a
		 * trace file, as that might let the user read other
		 * people's trace files (especially if we're set-UID
		 * root).
		 */
		if (setgid(getgid()) != 0 || setuid(getuid()) != 0 )
			fprintf(stderr, "Warning: setgid/setuid failed !\n");
#endif /* _WIN32 */
		if (VFileName != NULL) {
			if (VFileName[0] == '-' && VFileName[1] == '\0')
				VFile = stdin;
			else
				VFile = fopen(VFileName, "r");

			if (VFile == NULL)
				error("Unable to open file: %s", pcap_strerror(errno));

			ret = get_next_file(VFile, VFileLine);
			if (!ret)
				error("Nothing in %s", VFileName);
			RFileName = VFileLine;
		}

#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
		pd = pcap_open_offline_with_tstamp_precision(RFileName,
		    ndo->ndo_tstamp_precision, ebuf);
#else
		pd = pcap_open_offline(RFileName, ebuf);
#endif

		if (pd == NULL)
			error("%s", ebuf);
#ifdef HAVE_CAPSICUM
		cap_rights_init(&rights, CAP_READ);
		if (cap_rights_limit(fileno(pcap_file(pd)), &rights) < 0 &&
		    errno != ENOSYS) {
			error("unable to limit pcap descriptor");
		}
#endif
		dlt = pcap_datalink(pd);
		dlt_name = pcap_datalink_val_to_name(dlt);
		fprintf(stderr, "reading from file %s", RFileName);
		if (dlt_name == NULL) {
			fprintf(stderr, ", link-type %u", dlt);
		} else {
			fprintf(stderr, ", link-type %s (%s)", dlt_name,
				pcap_datalink_val_to_description(dlt));
		}
		fprintf(stderr, ", snapshot length %d\n", pcap_snapshot(pd));
#if defined(DLT_LINUX_SLL2) && defined(__linux__)
		if (dlt == DLT_LINUX_SLL2)
			fprintf(stderr, "Warning: interface names might be incorrect\n");
#endif
	} else if (dflag && !device) {
		int dump_dlt = DLT_EN10MB;
		/*
		 * We're dumping the compiled code without an explicit
		 * device specification.  (If a device is specified, we
		 * definitely want to open it to use the DLT of that device.)
		 * Either default to DLT_EN10MB with a warning, or use
		 * the user-specified value if supplied.
		 */
		/*
		 * If no snapshot length was specified, or a length of 0 was
		 * specified, default to 256KB.
		 */
		if (ndo->ndo_snaplen == 0)
			ndo->ndo_snaplen = MAXIMUM_SNAPLEN;
		/*
		 * If a DLT was specified with the -y flag, use that instead.
		 */
		if (yflag_dlt != -1)
			dump_dlt = yflag_dlt;
		else
			fprintf(stderr, "Warning: assuming Ethernet\n");
	        pd = pcap_open_dead(dump_dlt, ndo->ndo_snaplen);
	} else {
		/*
		 * We're doing a live capture.
		 */
		if (device == NULL) {
			/*
			 * No interface was specified.  Pick one.
			 */
			/*
			 * Find the list of interfaces, and pick
			 * the first interface.
			 */
			if (pcap_findalldevs(&devlist, ebuf) == -1)
				error("%s", ebuf);
			if (devlist == NULL)
				error("no interfaces available for capture");
			device = strdup(devlist->name);
			pcap_freealldevs(devlist);
		}

		/*
		 * Try to open the interface with the specified name.
		 */
		pd = open_interface(device, ndo, ebuf);
		if (pd == NULL) {
			/*
			 * That failed.  If we can get a list of
			 * interfaces, and the interface name
			 * is purely numeric, try to use it as
			 * a 1-based index in the list of
			 * interfaces.
			 */
			devnum = parse_interface_number(device);
			if (devnum == -1) {
				/*
				 * It's not a number; just report
				 * the open error and fail.
				 */
				error("%s", ebuf);
			}

			/*
			 * OK, it's a number; try to find the
			 * interface with that index, and try
			 * to open it.
			 *
			 * find_interface_by_number() exits if it
			 * couldn't be found.
			 */
			device = find_interface_by_number(device, devnum);
			pd = open_interface(device, ndo, ebuf);
			if (pd == NULL)
				error("%s", ebuf);
		}

		/*
		 * Let user own process after capture device has
		 * been opened.
		 */
#ifndef _WIN32
		if (setgid(getgid()) != 0 || setuid(getuid()) != 0)
			fprintf(stderr, "Warning: setgid/setuid failed !\n");
#endif /* _WIN32 */
		if (Lflag)
			show_dlts_and_exit(pd, device);
		if (yflag_dlt >= 0) {
			if (pcap_set_datalink(pd, yflag_dlt) < 0)
				error("%s", pcap_geterr(pd));
			(void)fprintf(stderr, "%s: data link type %s\n",
				      program_name,
				      pcap_datalink_val_to_name(yflag_dlt));
			(void)fflush(stderr);
		}
#if defined(DLT_LINUX_SLL2)
		else {
			/*
			 * Attempt to set default linktype to
			 * DLT_LINUX_SLL2 when capturing on the
			 * "any" device.
			 *
			 * If the attempt fails, just quietly drive
			 * on; this may be a non-Linux "any" device
			 * that doesn't support DLT_LINUX_SLL2.
			 */
			if (strcmp(device, "any") == 0) {
DIAG_OFF_WARN_UNUSED_RESULT
				(void) pcap_set_datalink(pd, DLT_LINUX_SLL2);
DIAG_ON_WARN_UNUSED_RESULT
			}
		}
#endif
		i = pcap_snapshot(pd);
		if (ndo->ndo_snaplen < i) {
			if (ndo->ndo_snaplen != 0)
				warning("snaplen raised from %d to %d", ndo->ndo_snaplen, i);
			ndo->ndo_snaplen = i;
		} else if (ndo->ndo_snaplen > i) {
			warning("snaplen lowered from %d to %d", ndo->ndo_snaplen, i);
			ndo->ndo_snaplen = i;
		}
                if(ndo->ndo_fflag != 0) {
                        if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
                                warning("foreign (-f) flag used but: %s", ebuf);
                        }
                }

	}
	if (infile)
		cmdbuf = read_infile(infile);
	else
		cmdbuf = copy_argv(&argv[optind]);

#ifdef HAVE_PCAP_SET_OPTIMIZER_DEBUG
	pcap_set_optimizer_debug(dflag);
#endif
	/*
	 * netmask is in network byte order, pcap_compile() takes it
	 * in host byte order.
	 */
	if (pcap_compile(pd, &fcode, cmdbuf, Oflag, ntohl(netmask)) < 0)
		error("%s", pcap_geterr(pd));
	if (dflag) {
		bpf_dump(&fcode, dflag);
		pcap_close(pd);
		free(cmdbuf);
		pcap_freecode(&fcode);
		exit_tcpdump(S_SUCCESS);
	}

#ifdef HAVE_CASPER
	if (!ndo->ndo_nflag)
		capdns = capdns_setup();
#endif	/* HAVE_CASPER */

	// Both localnet and netmask are in network byte order.
	init_print(ndo, localnet, netmask);

#ifndef _WIN32
	(void)setsignal(SIGPIPE, cleanup);
	(void)setsignal(SIGTERM, cleanup);
#endif /* _WIN32 */
	(void)setsignal(SIGINT, cleanup);
#if defined(HAVE_FORK) || defined(HAVE_VFORK)
	(void)setsignal(SIGCHLD, child_cleanup);
#endif
	/* Cooperate with nohup(1) */
#ifndef _WIN32
	/*
	 * In illumos /usr/include/sys/iso/signal_iso.h causes Clang to
	 * generate a -Wstrict-prototypes warning here, see [1].  The
	 * __illumos__ macro is available since at least GCC 11 and Clang 13,
	 * see [2].
	 * 1: https://www.illumos.org/issues/16344
	 * 2: https://www.illumos.org/issues/13726
	 */
#ifdef __illumos__
	DIAG_OFF_STRICT_PROTOTYPES
#endif /* __illumos__ */
	if ((oldhandler = setsignal(SIGHUP, cleanup)) != SIG_DFL)
#ifdef __illumos__
	DIAG_ON_STRICT_PROTOTYPES
#endif /* __illumos__ */
		(void)setsignal(SIGHUP, oldhandler);
#endif /* _WIN32 */

#ifndef _WIN32
	/*
	 * If a user name was specified with "-Z", attempt to switch to
	 * that user's UID.  This would probably be used with sudo,
	 * to allow tcpdump to be run in a special restricted
	 * account (if you just want to allow users to open capture
	 * devices, and can't just give users that permission,
	 * you'd make tcpdump set-UID or set-GID).
	 *
	 * tcpdump doesn't necessarily write only to one savefile;
	 * the general only way to allow a -Z instance to write to
	 * savefiles as the user under whose UID it's run, rather
	 * than as the user specified with -Z, would thus be to switch
	 * to the original user ID before opening a capture file and
	 * then switch back to the -Z user ID after opening the savefile.
	 * Switching to the -Z user ID only after opening the first
	 * savefile doesn't handle the general case.
	 */

	if (getuid() == 0 || geteuid() == 0) {
#ifdef HAVE_LIBCAP_NG
		/* Initialize capng */
		capng_clear(CAPNG_SELECT_BOTH);
		if (username) {
DIAG_OFF_ASSIGN_ENUM
			capng_updatev(
				CAPNG_ADD,
				CAPNG_PERMITTED | CAPNG_EFFECTIVE,
				CAP_SETUID,
				CAP_SETGID,
				-1);
DIAG_ON_ASSIGN_ENUM
		}
		if (chroot_dir) {
DIAG_OFF_ASSIGN_ENUM
			capng_update(
				CAPNG_ADD,
				CAPNG_PERMITTED | CAPNG_EFFECTIVE,
				CAP_SYS_CHROOT
				);
DIAG_ON_ASSIGN_ENUM
		}

		if (WFileName) {
DIAG_OFF_ASSIGN_ENUM
			capng_update(
				CAPNG_ADD,
				CAPNG_PERMITTED | CAPNG_EFFECTIVE,
				CAP_DAC_OVERRIDE
				);
DIAG_ON_ASSIGN_ENUM
		}
		capng_apply(CAPNG_SELECT_BOTH);
#endif /* HAVE_LIBCAP_NG */
		if (username || chroot_dir)
			droproot(username, chroot_dir);

	}
#endif /* _WIN32 */

	if (pcap_setfilter(pd, &fcode) < 0)
		error("%s", pcap_geterr(pd));
#ifdef HAVE_CAPSICUM
	if (RFileName == NULL && VFileName == NULL && pcap_fileno(pd) != -1) {
		static const unsigned long cmds[] = { BIOCGSTATS, BIOCROTZBUF };

		/*
		 * The various libpcap devices use a combination of
		 * read (bpf), ioctl (bpf, netmap), poll (netmap)
		 * so we add the relevant access rights.
		 */
		cap_rights_init(&rights, CAP_IOCTL, CAP_READ, CAP_EVENT);
		if (cap_rights_limit(pcap_fileno(pd), &rights) < 0 &&
		    errno != ENOSYS) {
			error("unable to limit pcap descriptor");
		}
		if (cap_ioctls_limit(pcap_fileno(pd), cmds,
		    sizeof(cmds) / sizeof(cmds[0])) < 0 && errno != ENOSYS) {
			error("unable to limit ioctls on pcap descriptor");
		}
	}
#endif
	if (WFileName) {
		/* Do not exceed the default PATH_MAX for files. */
		dumpinfo.CurrentFileName = (char *)malloc(PATH_MAX + 1);

		if (dumpinfo.CurrentFileName == NULL)
			error("malloc of dumpinfo.CurrentFileName");

		/* We do not need numbering for dumpfiles if Cflag isn't set. */
		if (Cflag != 0)
		  MakeFilename(dumpinfo.CurrentFileName, WFileName, 0, WflagChars);
		else
		  MakeFilename(dumpinfo.CurrentFileName, WFileName, 0, 0);

		pdd = pcap_dump_open(pd, dumpinfo.CurrentFileName);
#ifdef HAVE_LIBCAP_NG
		/* Give up CAP_DAC_OVERRIDE capability.
		 * Only allow it to be restored if the -C or -G flag have been
		 * set since we may need to create more files later on.
		 */
		capng_update(
			CAPNG_DROP,
			(Cflag || Gflag ? 0 : CAPNG_PERMITTED)
				| CAPNG_EFFECTIVE,
			CAP_DAC_OVERRIDE
			);
		capng_apply(CAPNG_SELECT_BOTH);
#endif /* HAVE_LIBCAP_NG */
		if (pdd == NULL)
			error("%s", pcap_geterr(pd));
#ifdef HAVE_CAPSICUM
		set_dumper_capsicum_rights(pdd);
#endif
		if (Cflag != 0 || Gflag != 0) {
#ifdef HAVE_CAPSICUM
			/*
			 * basename() and dirname() may modify their input buffer
			 * and they do since FreeBSD 12.0, but they didn't before.
			 * Hence use the return value only, but always assume the
			 * input buffer has been modified and would need to be
			 * reset before the next use.
			 */
			char *WFileName_copy;

			if ((WFileName_copy = strdup(WFileName)) == NULL) {
				error("Unable to allocate memory for file %s",
				    WFileName);
			}
			DIAG_OFF_C11_EXTENSIONS
			dumpinfo.WFileName = strdup(basename(WFileName_copy));
			DIAG_ON_C11_EXTENSIONS
			if (dumpinfo.WFileName == NULL) {
				error("Unable to allocate memory for file %s",
				    WFileName);
			}
			free(WFileName_copy);

			if ((WFileName_copy = strdup(WFileName)) == NULL) {
				error("Unable to allocate memory for file %s",
				    WFileName);
			}
			DIAG_OFF_C11_EXTENSIONS
			char *WFileName_dirname = dirname(WFileName_copy);
			DIAG_ON_C11_EXTENSIONS
			dumpinfo.dirfd = open(WFileName_dirname,
			    O_DIRECTORY | O_RDONLY);
			if (dumpinfo.dirfd < 0) {
				error("unable to open directory %s",
				    WFileName_dirname);
			}
			free(WFileName_dirname);
			free(WFileName_copy);

			cap_rights_init(&rights, CAP_CREATE, CAP_FCNTL,
			    CAP_FTRUNCATE, CAP_LOOKUP, CAP_SEEK, CAP_WRITE);
			if (cap_rights_limit(dumpinfo.dirfd, &rights) < 0 &&
			    errno != ENOSYS) {
				error("unable to limit directory rights");
			}
			if (cap_fcntls_limit(dumpinfo.dirfd, CAP_FCNTL_GETFL) < 0 &&
			    errno != ENOSYS) {
				error("unable to limit dump descriptor fcntls");
			}
#else	/* !HAVE_CAPSICUM */
			dumpinfo.WFileName = WFileName;
#endif
			callback = dump_packet_and_trunc;
			dumpinfo.pd = pd;
			dumpinfo.pdd = pdd;
			pcap_userdata = (u_char *)&dumpinfo;
		} else {
			callback = dump_packet;
			dumpinfo.WFileName = WFileName;
			dumpinfo.pd = pd;
			dumpinfo.pdd = pdd;
			pcap_userdata = (u_char *)&dumpinfo;
		}
		if (print) {
			dlt = pcap_datalink(pd);
			ndo->ndo_if_printer = get_if_printer(dlt);
			dumpinfo.ndo = ndo;
		} else
			dumpinfo.ndo = NULL;

		if (Uflag)
			pcap_dump_flush(pdd);
	} else {
		dlt = pcap_datalink(pd);
		ndo->ndo_if_printer = get_if_printer(dlt);
		callback = print_packet;
		pcap_userdata = (u_char *)ndo;
	}

#ifdef SIGNAL_REQ_INFO
	/*
	 * We can't get statistics when reading from a file rather
	 * than capturing from a device.
	 */
	if (RFileName == NULL)
		(void)setsignal(SIGNAL_REQ_INFO, requestinfo);
#endif
#ifdef SIGNAL_FLUSH_PCAP
	(void)setsignal(SIGNAL_FLUSH_PCAP, flushpcap);
#endif

	if (ndo->ndo_vflag > 0 && WFileName && RFileName == NULL && !print) {
		/*
		 * When capturing to a file, if "--print" wasn't specified,
		 *"-v" means tcpdump should, once per second,
		 * "v"erbosely report the number of packets captured.
		 * Except when reading from a file, because -r, -w and -v
		 * together used to make a corner case, in which pcap_loop()
		 * errored due to EINTR (see GH #155 for details).
		 */
#ifdef _WIN32
		/*
		 * https://blogs.msdn.microsoft.com/oldnewthing/20151230-00/?p=92741
		 *
		 * suggests that this dates back to W2K.
		 *
		 * I don't know what a "long wait" is, but we'll assume
		 * that printing the stats could be a "long wait".
		 */
		CreateTimerQueueTimer(&timer_handle, NULL,
		    verbose_stats_dump, NULL, 1000, 1000,
		    WT_EXECUTEDEFAULT|WT_EXECUTELONGFUNCTION);
		setvbuf(stderr, NULL, _IONBF, 0);
#else /* _WIN32 */
		/*
		 * Assume this is UN*X, and that it has setitimer(); that
		 * dates back to UNIX 95.
		 */
		struct itimerval timer;
		(void)setsignal(SIGALRM, verbose_stats_dump);
		timer.it_interval.tv_sec = 1;
		timer.it_interval.tv_usec = 0;
		timer.it_value.tv_sec = 1;
		timer.it_value.tv_usec = 1;
		setitimer(ITIMER_REAL, &timer, NULL);
#endif /* _WIN32 */
	}

	if (RFileName == NULL) {
		/*
		 * Live capture (if -V was specified, we set RFileName
		 * to a file from the -V file).  Print a message to
		 * the standard error on UN*X.
		 */
		if (!ndo->ndo_vflag && !WFileName) {
			(void)fprintf(stderr,
			    "%s: verbose output suppressed, use -v[v]... for full protocol decode\n",
			    program_name);
		} else
			(void)fprintf(stderr, "%s: ", program_name);
		dlt = pcap_datalink(pd);
		dlt_name = pcap_datalink_val_to_name(dlt);
		(void)fprintf(stderr, "listening on %s", device);
		if (dlt_name == NULL) {
			(void)fprintf(stderr, ", link-type %u", dlt);
		} else {
			(void)fprintf(stderr, ", link-type %s (%s)", dlt_name,
				      pcap_datalink_val_to_description(dlt));
		}
		(void)fprintf(stderr, ", snapshot length %d bytes\n", ndo->ndo_snaplen);
		(void)fflush(stderr);
	}

#ifdef HAVE_CAPSICUM
	cansandbox = (VFileName == NULL && zflag == NULL);
#ifdef HAVE_CASPER
	cansandbox = (cansandbox && (ndo->ndo_nflag || capdns != NULL));
#else
	cansandbox = (cansandbox && ndo->ndo_nflag);
#endif /* HAVE_CASPER */
	cansandbox = (cansandbox && (pcap_fileno(pd) != -1 ||
	    RFileName != NULL));

	if (cansandbox && cap_enter() < 0 && errno != ENOSYS)
		error("unable to enter the capability mode");
#endif	/* HAVE_CAPSICUM */

	do {
		status = pcap_loop(pd,
				   (cnt == -1 ? -1 : cnt + (int)packets_to_skip),
				   callback, pcap_userdata);
		if (WFileName == NULL) {
			/*
			 * We're printing packets.  Flush the printed output,
			 * so it doesn't get intermingled with error output.
			 */
			if (status == -2) {
				/*
				 * We got interrupted, so perhaps we didn't
				 * manage to finish a line we were printing.
				 * Print an extra newline, just in case.
				 */
				putchar('\n');
			}
			(void)fflush(stdout);
		}
                if (status == -2) {
			/*
			 * We got interrupted. If we are reading multiple
			 * files (via -V) set these so that we stop.
			 */
			VFileName = NULL;
			ret = NULL;
		}
		if (status == -1) {
			/*
			 * Error.  Report it.
			 */
			(void)fprintf(stderr, "%s: pcap_loop: %s\n",
			    program_name, pcap_geterr(pd));
		}
		if (RFileName == NULL) {
			/*
			 * We're doing a live capture.  Report the capture
			 * statistics.
			 */
			info(1);
		}
		pcap_close(pd);
		pd = NULL;
		if (VFileName != NULL) {
			ret = get_next_file(VFile, VFileLine);
			if (ret) {
				int new_dlt;

				RFileName = VFileLine;
				pd = pcap_open_offline(RFileName, ebuf);
				if (pd == NULL)
					error("%s", ebuf);
#ifdef HAVE_CAPSICUM
				cap_rights_init(&rights, CAP_READ);
				if (cap_rights_limit(fileno(pcap_file(pd)),
				    &rights) < 0 && errno != ENOSYS) {
					error("unable to limit pcap descriptor");
				}
#endif
				new_dlt = pcap_datalink(pd);
				if (new_dlt != dlt) {
					/*
					 * The new file has a different
					 * link-layer header type from the
					 * previous one.
					 */
					if (WFileName != NULL) {
						/*
						 * We're writing raw packets
						 * that match the filter to
						 * a pcap file.  pcap files
						 * don't support multiple
						 * different link-layer
						 * header types, so we fail
						 * here.
						 */
						error("%s: new dlt does not match original", RFileName);
					}

					/*
					 * We're printing the decoded packets;
					 * switch to the new DLT.
					 *
					 * To do that, we need to change
					 * the printer, change the DLT name,
					 * and recompile the filter with
					 * the new DLT.
					 */
					dlt = new_dlt;
					ndo->ndo_if_printer = get_if_printer(dlt);
					/* Free the old filter */
					pcap_freecode(&fcode);
					/*
					 * netmask is in network byte order, pcap_compile() takes it
					 * in host byte order.
					 */
					if (pcap_compile(pd, &fcode, cmdbuf, Oflag, ntohl(netmask)) < 0)
						error("%s", pcap_geterr(pd));
				}

				/*
				 * Set the filter on the new file.
				 */
				if (pcap_setfilter(pd, &fcode) < 0)
					error("%s", pcap_geterr(pd));

				/*
				 * Report the new file.
				 */
				dlt_name = pcap_datalink_val_to_name(dlt);
				fprintf(stderr, "reading from file %s", RFileName);
				if (dlt_name == NULL) {
					fprintf(stderr, ", link-type %u", dlt);
				} else {
					fprintf(stderr, ", link-type %s (%s)",
						dlt_name,
						pcap_datalink_val_to_description(dlt));
				}
				fprintf(stderr, ", snapshot length %d\n", pcap_snapshot(pd));
			}
		}
	}
	while (ret != NULL);

	if (count_mode && RFileName != NULL)
		fprintf(stdout, "%u packet%s\n", packets_captured,
			PLURAL_SUFFIX(packets_captured));

	free(cmdbuf);
	pcap_freecode(&fcode);
	exit_tcpdump(status == -1 ? S_ERR_HOST_PROGRAM : S_SUCCESS);
}

/*
 * Routines to parse numerical command-line arguments and check for
 * errors, including "too large for that type".
 */
static int
parse_int(const char *argname, const char *string, char **endpp,
    int minval, int maxval, int base)
{
	long val;
	char *endp;

	errno = 0;
	val = strtol(string, &endp, base);

	/*
	 * Did it either not parse any of the string, find extra stuff
	 * at the end that the caller isn't interested in, or get
	 * another parsing error?
	 */
	if (string == endp || (endpp == NULL && *endp != '\0') ||
	    (val == 0 && errno == EINVAL)) {
		error("invalid %s \"%s\" (not a valid number)", argname,
		    string);
	}

	/*
	 * Did it get a value that's out of range?
	 */
	if (((val == LONG_MAX || val == LONG_MIN) && errno == ERANGE) ||
	    val < minval || val > maxval) {
		error("invalid %s %s (must be >= %d and <= %d)",
		    argname, string, minval, maxval);
	}

	/*
	 * OK, it passes all the tests.
	 */
	if (endpp != NULL)
		*endpp = endp;
	return ((int)val);
}

static u_int
parse_u_int(const char *argname, const char *string, char **endpp,
    u_int minval, u_int maxval, int base)
{
	unsigned long val;
	char *endp;

	errno = 0;

	/*
	 * strtoul() does *NOT* report an error if the string
	 * begins with a minus sign. We do.
	 */
	if (*string == '-') {
		error("invalid %s \"%s\" (not a valid unsigned number)",
		    argname, string);
	}

	val = strtoul(string, &endp, base);

	/*
	 * Did it either not parse any of the string, find extra stuff
	 * at the end that the caller isn't interested in, or get
	 * another parsing error?
	 */
	if (string == endp || (endpp == NULL && *endp != '\0') ||
	    (val == 0 && errno == EINVAL)) {
		error("invalid %s \"%s\" (not a valid unsigned number)",
		    argname, string);
	}

	/*
	 * Did it get a value that's out of range?
	 */
	if ((val == ULONG_MAX && errno == ERANGE) ||
	    val < minval || val > maxval) {
		error("invalid %s %s (must be >= %u and <= %u)",
		    argname, string, minval, maxval);
	}

	/*
	 * OK, it passes all the tests.
	 */
	if (endpp != NULL)
		*endpp = endp;
	return ((u_int)val);
}

static int64_t
parse_int64(const char *argname, const char *string, char **endpp,
    int64_t minval, int64_t maxval, int base)
{
	intmax_t val;
	char *endp;

	errno = 0;
	val = strtoimax(string, &endp, base);

	/*
	 * Did it either not parse any of the string, find extra stuff
	 * at the end that the caller isn't interested in, or get
	 * another parsing error?
	 */
	if (string == endp || (endpp == NULL && *endp != '\0') ||
	    (val == 0 && errno == EINVAL)) {
		error("invalid %s \"%s\" (not a valid number)", argname,
		    string);
	}

	/*
	 * Did it get a value that's out of range?
	 */
	if (((val == INTMAX_MAX || val == INTMAX_MIN) && errno == ERANGE) ||
	    val < minval || val > maxval) {
		error("invalid %s %s (must be >= %" PRId64 " and <= %" PRId64 ")",
		    argname, string, minval, maxval);
	}

	/*
	 * OK, it passes all the tests.
	 */
	if (endpp != NULL)
		*endpp = endp;
	return ((int64_t)val);
}

/*
 * Catch a signal.
 */
static void
(*setsignal (int sig, void (*func)(int)))(int)
{
#ifdef _WIN32
	return (signal(sig, func));
#else
	struct sigaction old, new;

	memset(&new, 0, sizeof(new));
	new.sa_handler = func;
	if ((sig == SIGCHLD)
# ifdef SIGNAL_REQ_INFO
		|| (sig == SIGNAL_REQ_INFO)
# endif
# ifdef SIGNAL_FLUSH_PCAP
		|| (sig == SIGNAL_FLUSH_PCAP)
# endif
		)
		new.sa_flags = SA_RESTART;
	if (sigaction(sig, &new, &old) < 0)
		/* The same workaround as for SIG_DFL above. */
#ifdef __illumos__
		DIAG_OFF_STRICT_PROTOTYPES
#endif /* __illumos__ */
		return (SIG_ERR);
#ifdef __illumos__
		DIAG_ON_STRICT_PROTOTYPES
#endif /* __illumos__ */
	return (old.sa_handler);
#endif
}

/* make a clean exit on interrupts */
static void
cleanup(int signo _U_)
{
#ifdef _WIN32
	if (timer_handle != INVALID_HANDLE_VALUE) {
		DeleteTimerQueueTimer(NULL, timer_handle, NULL);
		CloseHandle(timer_handle);
		timer_handle = INVALID_HANDLE_VALUE;
        }
#else /* _WIN32 */
	struct itimerval timer;

	timer.it_interval.tv_sec = 0;
	timer.it_interval.tv_usec = 0;
	timer.it_value.tv_sec = 0;
	timer.it_value.tv_usec = 0;
	setitimer(ITIMER_REAL, &timer, NULL);
#endif /* _WIN32 */

	/*
	 * We have "pcap_breakloop()"; use it, so that we do as little
	 * as possible in the signal handler (it's probably not safe
	 * to do anything with standard I/O streams in a signal handler -
	 * the ANSI C standard doesn't say it is).
	 */
	if (pd)
		pcap_breakloop(pd);
}

/*
  On windows, we do not use a fork, so we do not care less about
  waiting a child processes to die
 */
#if defined(HAVE_FORK) || defined(HAVE_VFORK)
static void
child_cleanup(int signo _U_)
{
  while (waitpid(-1, NULL, WNOHANG) >= 0);
}
#endif /* HAVE_FORK && HAVE_VFORK */

static void
info(int verbose)
{
	struct pcap_stat stats;

	/*
	 * Older versions of libpcap didn't set ps_ifdrop on some
	 * platforms; initialize it to 0 to handle that.
	 */
	stats.ps_ifdrop = 0;
	if (pcap_stats(pd, &stats) < 0) {
		(void)fprintf(stderr, "pcap_stats: %s\n", pcap_geterr(pd));
		infoprint = 0;
		return;
	}

	if (!verbose)
		fprintf(stderr, "%s: ", program_name);

	(void)fprintf(stderr, "%u packet%s captured", packets_captured,
	    PLURAL_SUFFIX(packets_captured));
	if (!verbose)
		fputs(", ", stderr);
	else
		putc('\n', stderr);
	(void)fprintf(stderr, "%u packet%s received by filter", stats.ps_recv,
	    PLURAL_SUFFIX(stats.ps_recv));
	if (!verbose)
		fputs(", ", stderr);
	else
		putc('\n', stderr);
	(void)fprintf(stderr, "%u packet%s dropped by kernel", stats.ps_drop,
	    PLURAL_SUFFIX(stats.ps_drop));
	if (stats.ps_ifdrop != 0) {
		if (!verbose)
			fputs(", ", stderr);
		else
			putc('\n', stderr);
		(void)fprintf(stderr, "%u packet%s dropped by interface\n",
		    stats.ps_ifdrop, PLURAL_SUFFIX(stats.ps_ifdrop));
	} else
		putc('\n', stderr);
	infoprint = 0;
}

#if defined(HAVE_FORK) || defined(HAVE_VFORK)
#ifdef HAVE_FORK
#define fork_subprocess() fork()
#else
#define fork_subprocess() vfork()
#endif
static void
compress_savefile(const char *filename)
{
	pid_t child;

	child = fork_subprocess();
	if (child == -1) {
		fprintf(stderr,
			"%s: fork failed: %s\n",
			__func__, pcap_strerror(errno));
		return;
	}
	if (child != 0) {
		/* Parent process. */
		return;
	}

	/*
	 * Child process.
	 * Set to lowest priority so that this doesn't disturb the capture.
	 */
#ifdef NZERO
	setpriority(PRIO_PROCESS, 0, NZERO - 1);
#else
	setpriority(PRIO_PROCESS, 0, 19);
#endif
	if (execlp(zflag, zflag, filename, (char *)NULL) == -1)
		fprintf(stderr,
			"%s: execlp(%s, %s) failed: %s\n",
			__func__, zflag, filename, pcap_strerror(errno));
#ifdef HAVE_FORK
	exit(S_ERR_HOST_PROGRAM);
#else
	_exit(S_ERR_HOST_PROGRAM);
#endif
}
#endif /* HAVE_FORK || HAVE_VFORK */

static void
close_old_dump_file(struct dump_info *dump_info)
{
	/*
	 * Close the current file and open a new one.
	 */
	pcap_dump_close(dump_info->pdd);

#if defined(HAVE_FORK) || defined(HAVE_VFORK)
	/*
	 * Compress the file we just closed, if the user asked for it.
	 */
	if (zflag != NULL)
		compress_savefile(dump_info->CurrentFileName);
#endif
}

static void
open_new_dump_file(struct dump_info *dump_info)
{
#ifdef HAVE_CAPSICUM
	FILE *fp;
	int fd;
#endif

#ifdef HAVE_LIBCAP_NG
	capng_update(CAPNG_ADD, CAPNG_EFFECTIVE, CAP_DAC_OVERRIDE);
	capng_apply(CAPNG_SELECT_BOTH);
#endif /* HAVE_LIBCAP_NG */
#ifdef HAVE_CAPSICUM
	fd = openat(dump_info->dirfd, dump_info->CurrentFileName,
	    O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0) {
		error("unable to open file %s", dump_info->CurrentFileName);
	}
	fp = fdopen(fd, "w");
	if (fp == NULL) {
		error("unable to fdopen file %s", dump_info->CurrentFileName);
	}
	dump_info->pdd = pcap_dump_fopen(dump_info->pd, fp);
#else	/* !HAVE_CAPSICUM */
	dump_info->pdd = pcap_dump_open(dump_info->pd, dump_info->CurrentFileName);
#endif
#ifdef HAVE_LIBCAP_NG
	capng_update(CAPNG_DROP, CAPNG_EFFECTIVE, CAP_DAC_OVERRIDE);
	capng_apply(CAPNG_SELECT_BOTH);
#endif /* HAVE_LIBCAP_NG */
	if (dump_info->pdd == NULL)
		error("%s", pcap_geterr(pd));
#ifdef HAVE_CAPSICUM
	set_dumper_capsicum_rights(dump_info->pdd);
#endif
}

static void
dump_packet_and_trunc(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
	struct dump_info *dump_info;

	++packets_captured;

	++infodelay;

	dump_info = (struct dump_info *)user;

	if (packets_captured <= packets_to_skip)
		return;

	/*
	 * XXX - this won't force the file to rotate on the specified time
	 * boundary, but it will rotate on the first packet received after the
	 * specified Gflag number of seconds. Note: if a Gflag time boundary
	 * and a Cflag size boundary coincide, the time rotation will occur
	 * first thereby cancelling the Cflag boundary (since the file should
	 * be 0).
	 */
	if (Gflag != 0) {
		/* Check if it is time to rotate */
		time_t t;

		/* Get the current time */
		if ((t = time(NULL)) == (time_t)-1) {
			error("%s: can't get current_time: %s",
			    __func__, pcap_strerror(errno));
		}


		/* If the time is greater than the specified window, rotate */
		if (t - Gflag_time >= Gflag) {
			/* Update the Gflag_time */
			Gflag_time = t;
			/* Update Gflag_count */
			Gflag_count++;

			close_old_dump_file(dump_info);

			/*
			 * Check to see if we've exceeded the Wflag (when
			 * not using Cflag).
			 */
			if (Cflag == 0 && Wflag > 0 && Gflag_count >= Wflag) {
				(void)fprintf(stderr, "Maximum file limit reached: %d\n",
				    Wflag);
				info(1);
				exit_tcpdump(S_SUCCESS);
				/* NOTREACHED */
			}
			if (dump_info->CurrentFileName != NULL)
				free(dump_info->CurrentFileName);
			/* Allocate space for max filename + \0. */
			dump_info->CurrentFileName = (char *)malloc(PATH_MAX + 1);
			if (dump_info->CurrentFileName == NULL)
				error("%s: malloc", __func__);
			/*
			 * Gflag was set otherwise we wouldn't be here. Reset the count
			 * so multiple files would end with 1,2,3 in the filename.
			 * The counting is handled with the -C flow after this.
			 */
			Cflag_count = 0;

			/*
			 * This is always the first file in the Cflag
			 * rotation: e.g. 0
			 * We also don't need numbering if Cflag is not set.
			 */
			if (Cflag != 0)
				MakeFilename(dump_info->CurrentFileName, dump_info->WFileName, 0,
				    WflagChars);
			else
				MakeFilename(dump_info->CurrentFileName, dump_info->WFileName, 0, 0);

			open_new_dump_file(dump_info);
		}
	}

	/*
	 * XXX - this won't prevent capture files from getting
	 * larger than Cflag - the last packet written to the
	 * file could put it over Cflag.
	 */
	if (Cflag != 0) {
#ifdef HAVE_PCAP_DUMP_FTELL64
		int64_t size = pcap_dump_ftell64(dump_info->pdd);
#else
		/*
		 * XXX - this only handles a Cflag value > 2^31-1 on
		 * LP64 platforms; to handle ILP32 (32-bit UN*X and
		 * Windows) or LLP64 (64-bit Windows) would require
		 * a version of libpcap with pcap_dump_ftell64().
		 */
		long size = pcap_dump_ftell(dump_info->pdd);
#endif

		if (size == -1)
			error("ftell fails on output file");
		if (size > Cflag) {
			close_old_dump_file(dump_info);

			Cflag_count++;
			if (Wflag > 0) {
				if (Cflag_count >= Wflag)
					Cflag_count = 0;
			}
			if (dump_info->CurrentFileName != NULL)
				free(dump_info->CurrentFileName);
			dump_info->CurrentFileName = (char *)malloc(PATH_MAX + 1);
			if (dump_info->CurrentFileName == NULL)
				error("%s: malloc", __func__);
			MakeFilename(dump_info->CurrentFileName, dump_info->WFileName, Cflag_count, WflagChars);

			open_new_dump_file(dump_info);
		}
	}

	pcap_dump((u_char *)dump_info->pdd, h, sp);
	if (Uflag)
		pcap_dump_flush(dump_info->pdd);

	if (dump_info->ndo != NULL)
		pretty_print_packet(dump_info->ndo, h, sp, packets_captured);

	--infodelay;
	if (infoprint)
		info(0);
}

static void
dump_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
	struct dump_info *dump_info;

	++packets_captured;

	++infodelay;

	dump_info = (struct dump_info *)user;

	if (packets_captured <= packets_to_skip)
		return;

	pcap_dump((u_char *)dump_info->pdd, h, sp);
	if (Uflag)
		pcap_dump_flush(dump_info->pdd);

	if (dump_info->ndo != NULL)
		pretty_print_packet(dump_info->ndo, h, sp, packets_captured);

	--infodelay;
	if (infoprint)
		info(0);
}

static void
print_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
	++packets_captured;

	++infodelay;

	if (!count_mode && packets_captured > packets_to_skip)
		pretty_print_packet((netdissect_options *)user, h, sp, packets_captured);

	--infodelay;
	if (infoprint)
		info(0);
}

#ifdef SIGNAL_REQ_INFO
static void
requestinfo(int signo _U_)
{
	if (infodelay)
		++infoprint;
	else
		info(0);
}
#endif

#ifdef SIGNAL_FLUSH_PCAP
static void
flushpcap(int signo _U_)
{
	if (pdd != NULL)
		pcap_dump_flush(pdd);
}
#endif

static void
print_packets_captured (void)
{
	static u_int prev_packets_captured, first = 1;

	if (infodelay == 0 && (first || packets_captured != prev_packets_captured)) {
		fprintf(stderr, "Got %u\r", packets_captured);
		first = 0;
		prev_packets_captured = packets_captured;
	}
}

/*
 * Called once each second in verbose mode while dumping to file
 */
#ifdef _WIN32
static void CALLBACK verbose_stats_dump(PVOID param _U_,
    BOOLEAN timer_fired _U_)
{
	print_packets_captured();
}
#else /* _WIN32 */
static void verbose_stats_dump(int sig _U_)
{
	print_packets_captured();
}
#endif /* _WIN32 */

DIAG_OFF_DEPRECATION
static void
print_version(FILE *f)
{
	const char *smi_version_string;

	(void)fprintf(f, "%s version " PACKAGE_VERSION "\n", program_name);
	(void)fprintf(f, "%s\n", pcap_lib_version());

#if defined(HAVE_LIBCRYPTO) && defined(SSLEAY_VERSION)
	(void)fprintf (f, "%s\n", SSLeay_version(SSLEAY_VERSION));
#endif

	smi_version_string = nd_smi_version_string();
	if (smi_version_string != NULL)
		(void)fprintf (f, "SMI-library: %s\n", smi_version_string);

#if defined(__SANITIZE_ADDRESS__)
	(void)fprintf (f, "Compiled with AddressSanitizer/GCC.\n");
#elif defined(__has_feature)
#  if __has_feature(address_sanitizer)
	(void)fprintf (f, "Compiled with AddressSanitizer/Clang.\n");
#  elif __has_feature(memory_sanitizer)
	(void)fprintf (f, "Compiled with MemorySanitizer/Clang.\n");
#  endif
#endif /* __SANITIZE_ADDRESS__ or __has_feature */
	(void)fprintf (f, "%zu-bit build, %zu-bit time_t\n",
		       sizeof(void *) * 8, sizeof(time_t) * 8);
}
DIAG_ON_DEPRECATION

static void
print_usage(FILE *f)
{
	print_version(f);
	(void)fprintf(f,
"Usage: %s [-AbdDefghHI" J_FLAG "KlLnNOpqStuUvxX#] [ -B size ] [ -c count ] [--count]\n", program_name);
	(void)fprintf(f,
"\t\t[ -C file_size ] " E_FLAG_USAGE "[ -F file ] [ -G seconds ]\n");
	(void)fprintf(f,
"\t\t[ -i interface ]" IMMEDIATE_MODE_USAGE j_FLAG_USAGE "\n");
	(void)fprintf(f,
"\t\t[ --lengths ]" LIST_REMOTE_INTERFACES_USAGE "\n");
#ifdef USE_LIBSMI
	(void)fprintf(f,
"\t\t" m_FLAG_USAGE "\n");
#endif
	(void)fprintf(f,
"\t\t" M_FLAG_USAGE "[ --number ] [ --print ]\n");
	(void)fprintf(f,
"\t\t[ --print-sampling nth ] [ -Q in|out|inout ] [ -r file ]\n");
	(void)fprintf(f,
"\t\t[ -s snaplen ] [ --skip count ] [ -T type ] [ --version ]\n");
	(void)fprintf(f,
"\t\t[ -V file ] [ -w file ] [ -W filecount ] [ -y datalinktype ]\n");
#ifdef HAVE_PCAP_SET_TSTAMP_PRECISION
	(void)fprintf(f,
"\t\t[ --time-stamp-precision precision ] [ --micro ] [ --nano ]\n");
#endif
	(void)fprintf(f,
"\t\t" z_FLAG_USAGE "[ -Z user ] [ expression ]\n");
}
