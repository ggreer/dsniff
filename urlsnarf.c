/*
 * urlsnarf.c
 *
 * Sniff the network for HTTP request URLs, output in CLF format.
 *
 * Copyright (c) 1999 Dug Song <dugsong@monkey.org>
 *
 * $Id: urlsnarf.c,v 1.35 2001/03/15 09:26:13 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <regex.h>
#include <time.h>
#include <err.h>
#include <libnet.h>
#include <nids.h>
#include <pcap.h>

#include "pcaputil.h"
#include "buf.h"
#include "base64.h"
#include "version.h"

#define DEFAULT_PCAP_FILTER "tcp port 80 or port 8080 or port 3128"

u_short		Opt_dns = 1;
int		Opt_invert = 0;
regex_t	       *pregex = NULL;

static void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: urlsnarf [-n] [-i interface] [[-v] pattern [expression]]\n");
	exit(1);
}

static int
regex_match(char *string)
{
	return (pregex == NULL ||
		((regexec(pregex, string, 0, NULL, 0) == 0) ^ Opt_invert));
}

static char *
timestamp(void)
{
	static char tstr[32], sign;
	struct tm *t, gmt;
	time_t tt = time(NULL);
	int days, hours, tz, len;
	
	gmt = *gmtime(&tt);
	t = localtime(&tt);
	
	days = t->tm_yday - gmt.tm_yday;
	hours = ((days < -1 ? 24 : 1 < days ? -24 : days * 24) +
		 t->tm_hour - gmt.tm_hour);
	tz = hours * 60 + t->tm_min - gmt.tm_min;
	
	len = strftime(tstr, sizeof(tstr), "%e/%b/%Y:%X", t);
	if (len < 0 || len > sizeof(tstr) - 5)
		return (NULL);
	
	if (tz < 0) {
		sign = '-';
		tz = -tz;
	}
	else sign = '+';
	
	snprintf(tstr + len, sizeof(tstr) - len, " %c%.2d%.2d",
		 sign, tz / 60, tz % 60);
	
	return (tstr);
}

static int
process_http_request(struct tuple4 *addr, u_char *data, int len)
{
	struct buf *msg, buf;
	char *p, *req, *uri, *user, *vhost, *referer, *agent;
	int i;

	buf_init(&buf, data, len);
	
	while ((i = buf_index(&buf, "\r\n\r\n", 4)) >= 0) {
		msg = buf_tok(&buf, NULL, i);
		msg->base[msg->end] = '\0';
		buf_skip(&buf, 4);
		
		if (!regex_match(buf_ptr(msg)))
			continue;
		
		if ((req = strtok(buf_ptr(msg), "\r\n")) == NULL)
			continue;
		
		if (strncmp(req, "GET ", 4) != 0 &&
		    strncmp(req, "POST ", 5) != 0 &&
		    strncmp(req, "CONNECT ", 8) != 0)
			continue;
		
		if ((uri = strchr(req, ' ')) == NULL)
			continue;

		*uri++ = '\0';
		if (strncmp(uri, "http://", 7) == 0) {
			for (uri += 7; *uri != '/'; uri++)
				;
		}
		user = vhost = referer = agent = NULL;
		
		while ((p = strtok(NULL, "\r\n")) != NULL) {
			if (strncasecmp(p, "Authorization: Basic ", 21) == 0) {
				p += 21;
				i = base64_pton(p, p, strlen(p));
				p[i] = '\0';
				user = p;
				if ((p = strchr(p, ':')) != NULL)
					*p = '\0';
			}
			else if (strncasecmp(p, "Host: ", 6) == 0) {
				vhost = p + 6;
			}
			else if (strncasecmp(p, "Referer: ", 9) == 0) {
				referer = p + 9;
			}
			else if (strncasecmp(p, "User-Agent: ", 12) == 0) {
				agent = p + 12;
			}
			else if (strncasecmp(p, "Content-length: ", 16) == 0) {
				i = atoi(p + 16);
				buf_tok(NULL, NULL, i);
			}
		}
		if (user == NULL)
			user = "-";
		if (vhost == NULL)
			vhost = libnet_host_lookup(addr->daddr, Opt_dns);
		if (referer == NULL)
			referer = "-";
		if (agent == NULL)
			agent = "-";
		
		printf("%s - %s [%s] \"%s http://%s%s\" - - \"%s\" \"%s\"\n",
		       libnet_host_lookup(addr->saddr, Opt_dns),
		       user, timestamp(), req, vhost, uri, referer, agent);
	}
	fflush(stdout);
	
	return (len - buf_len(&buf));
}

static void
sniff_http_client(struct tcp_stream *ts, void **yoda)
{
	int i;
	
	switch (ts->nids_state) {

	case NIDS_JUST_EST:
		ts->server.collect = 1;
		
	case NIDS_DATA:
		if (ts->server.count_new != 0) {
			i = process_http_request(&ts->addr, ts->server.data,
						 ts->server.count -
						 ts->server.offset);
			nids_discard(ts, i);
		}
		break;
		
	default:
		if (ts->server.count != 0) {
			process_http_request(&ts->addr, ts->server.data,
					     ts->server.count -
					     ts->server.offset);
		}
		break;
	}
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
	int c;
	
	while ((c = getopt(argc, argv, "i:nvh?V")) != -1) {
		switch (c) {
		case 'i':
			nids_params.device = optarg;
			break;
		case 'n':
			Opt_dns = 0;
			break;
		case 'v':
			Opt_invert = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 0 && strlen(argv[0])) {
		if ((pregex = (regex_t *) malloc(sizeof(*pregex))) == NULL)
			err(1, "malloc");
		if (regcomp(pregex, argv[0], REG_EXTENDED|REG_NOSUB) != 0)
			errx(1, "invalid regular expression");
	}
	if (argc > 1) {
		nids_params.pcap_filter = copy_argv(argv + 1);
	}
	else nids_params.pcap_filter = DEFAULT_PCAP_FILTER;
	
	nids_params.scan_num_hosts = 0;
	nids_params.syslog = null_syslog;
	
	if (!nids_init())
		errx(1, "%s", nids_errbuf);
	
	nids_register_tcp(sniff_http_client);

	warnx("listening on %s [%s]", nids_params.device,
	      nids_params.pcap_filter);

	nids_run();
	
	/* NOTREACHED */
	
	exit(0);
}
