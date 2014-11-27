/*
 * dsniff.c
 *
 * Password sniffer, because DrHoney wanted one.
 *
 * This is intended for demonstration purposes and educational use only.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: dsniff.c,v 1.69 2001/03/15 08:33:03 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <err.h>
#include <libnet.h>
#include <nids.h>
#include <pcap.h>

#include "options.h"
#include "pathnames.h"
#include "pcaputil.h"
#include "trigger.h"
#include "record.h"
#include "version.h"

#define MAX_LINES	6
#define MIN_SNAPLEN	1024

int	Opt_client = 0;
int	Opt_debug = 0;
u_short	Opt_dns = 1;
int	Opt_magic = 0;
int	Opt_read = 0;
int	Opt_write = 0;
int	Opt_snaplen = MIN_SNAPLEN;
int	Opt_lines = MAX_LINES;

static void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: dsniff [-cdmn] [-i interface] [-s snaplen] [-f services]\n"
		"              [-t trigger[,...]] [-r|-w savefile] [expression]\n");
	exit(1);
}

static void
sig_hup(int sig)
{
	trigger_dump();
}

static void
sig_die(int sig)
{
	record_close();
	exit(0);
}

static void
null_syslog(int type, int errnum, struct ip *iph, void *data)
{
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	char *services, *savefile, *triggers;
	int c;

	services = savefile = triggers = NULL;
	
	while ((c = getopt(argc, argv, "cdf:i:mnr:s:t:w:h?V")) != -1) {
		switch (c) {
		case 'c':
			Opt_client = 1;
			break;
		case 'd':
			Opt_debug++;
			break;
		case 'f':
			services = optarg;
			break;
		case 'i':
			nids_params.device = optarg;
			break;
		case 'm':
			Opt_magic = 1;
			break;
		case 'n':
			Opt_dns = 0;
			break;
		case 'r':
			Opt_read = 1;
			savefile = optarg;
			break;
		case 's':
			if ((Opt_snaplen = atoi(optarg)) == 0)
				usage();
			break;
		case 't':
			triggers = optarg;
			break;
		case 'w':
			Opt_write = 1;
			savefile = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	
	if (Opt_read && Opt_write)
		usage();
	
	if (!record_init(savefile))
		err(1, "record_init");
	
	signal(SIGHUP, sig_hup);
	signal(SIGINT, sig_die);
	signal(SIGTERM, sig_die);
	
	if (Opt_read) {
		record_dump();
		record_close();
		exit(0);
	}

	if (argc != 0)
		nids_params.pcap_filter = copy_argv(argv);
	nids_params.scan_num_hosts = 0;
	nids_params.syslog = null_syslog;
	
	if (!nids_init()) {
		record_close();
		errx(1, "nids_init: %s", nids_errbuf);
	}
	if (Opt_magic) {
		trigger_init_magic(DSNIFF_LIBDIR DSNIFF_MAGIC);
	}
	if (triggers) {
		trigger_init_list(triggers);
	}
	if (services == NULL) {
		services = DSNIFF_LIBDIR DSNIFF_SERVICES;
	}
	trigger_init_services(services);
	
	nids_register_ip(trigger_ip);
	nids_register_ip(trigger_udp);
		
	if (Opt_client) {
		nids_register_ip(trigger_tcp_raw);
		signal(SIGALRM, trigger_tcp_raw_timeout);
		alarm(TRIGGER_TCP_RAW_TIMEOUT);
	}
	else nids_register_tcp(trigger_tcp);
	
	if (nids_params.pcap_filter != NULL) {
		warnx("listening on %s [%s]", nids_params.device,
		      nids_params.pcap_filter);
	}
	else warnx("listening on %s", nids_params.device);
	
	nids_run();
	
	/* NOTREACHED */
	
	exit(0);
}
