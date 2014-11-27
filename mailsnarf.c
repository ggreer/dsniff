/*
 * mailsnarf.c
 *
 * Sniff mail on a network, saving messages in Berkeley mbox format.
 *
 * Copyright (c) 1999 Dug Song <dugsong@monkey.org>
 *
 * $Id: mailsnarf.c,v 1.38 2001/03/15 08:33:04 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <regex.h>
#include <err.h>
#include <libnet.h>
#include <nids.h>
#include <pcap.h>

#include "pcaputil.h"
#include "buf.h"
#include "version.h"

/* bogus SMTP state machine */
enum {
	SMTP_NONE = 0,
	SMTP_HELO,
	SMTP_MAIL,
	SMTP_RCPT,
	SMTP_DATA
};

/* likewise, POP. */
enum {
	POP_NONE = 0,
	POP_RETR,
	POP_DATA
};

struct smtp_info {
	int state;
	char *from;
};

struct pop_info {
	int state;
};

int	 Opt_invert = 0;
regex_t	*pregex = NULL;

static void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: mailsnarf [-i interface | -p pcapfile] [[-v] pattern [expression]]\n");
	exit(1);
}

static int
regex_match(char *string)
{
	return (pregex == NULL ||
		((regexec(pregex, string, 0, NULL, 0) == 0) ^ Opt_invert));
}

static char *
grep_mail_address(char *buf)
{
	char *p, *q;
	
	if ((p = strchr(buf, '<')) != NULL) {
		p++;
		if ((q = strchr(p, '>')) != NULL)
			*q = '\0';
		if (strlen(p) > 0)
			return (strdup(p));
	}
	return (NULL);
}

static void
print_mbox_msg(char *from, char *msg)
{
	char *p;
	time_t t;

	t = time(NULL);

	if (from == NULL)
		from = "mailsnarf";
	
	printf("From %s %s", from, ctime(&t));

	while ((p = strsep(&msg, "\n")) != NULL) {
		if (strncmp(p, "From ", 5) == 0)
			putchar('>');
		for (; *p != '\r' && *p != '\0'; p++)
			putchar(*p);
		putchar('\n');
	}
	putchar('\n');
	fflush(stdout);
}

static int
process_pop_client(struct pop_info *pop, char *data, int len)
{
	struct buf *line, buf;
	int i;

	buf_init(&buf, data, len);
	
	while ((i = buf_index(&buf, "\r\n", 2)) >= 0) {
		line = buf_tok(&buf, NULL, i + 2);
		line->base[line->end] = '\0';
		
		if (strncasecmp(buf_ptr(line), "RETR ", 5) == 0) {
			pop->state = POP_RETR;
		}
		else pop->state = POP_NONE;
	}
	return (len - buf_len(&buf));
}

static int
process_pop_server(struct pop_info *pop, char *data, int len)
{
	struct buf *line, *body, buf;
	int i;

	buf_init(&buf, data, len);
	
	if (pop->state == POP_NONE)
		return (len);

	if (pop->state == POP_RETR) {
		if ((i = buf_index(&buf, "\r\n", 2)) < 0)
			return (0);
		
		line = buf_tok(&buf, NULL, i + 2);
		
		if (buf_cmp(line, "+OK", 3) == 0) {
			pop->state = POP_DATA;
		}
		else pop->state = POP_NONE;
	}
	if (pop->state == POP_DATA) {
		if ((i = buf_index(&buf, "\r\n.\r\n", 5)) >= 0) {
			body = buf_tok(&buf, NULL, i);
			buf_skip(&buf, 5);
			body->base[body->end] = '\0';

			if (regex_match(buf_ptr(body)))
				print_mbox_msg(NULL, buf_ptr(body));
			
			pop->state = POP_NONE;
		}
	}
	return (len - buf_len(&buf));
}

static int
process_smtp_client(struct smtp_info *smtp, char *data, int len)
{
	struct buf *line, *body, buf;
	char *p;
	int i;

	buf_init(&buf, data, len);
	
	if (smtp->state != SMTP_DATA) {
		while ((i = buf_index(&buf, "\r\n", 2)) >= 0) {
			line = buf_tok(&buf, NULL, i + 2);
			line->base[line->end-1] = '\0';
			p = buf_ptr(line);
			
			if (strncasecmp(p, "RSET", 4) == 0) {
				smtp->state = SMTP_HELO;
			}
			else if (smtp->state == SMTP_NONE &&
				 (strncasecmp(p, "HELO", 4) == 0 ||
				  strncasecmp(p, "EHLO", 4) == 0)) {
				smtp->state = SMTP_HELO;
			}
			else if (smtp->state == SMTP_HELO &&
				 (strncasecmp(p, "MAIL ", 5) == 0 ||
				  strncasecmp(p, "SEND ", 5) == 0 ||
				  strncasecmp(p, "SAML ", 5) == 0)) {
				smtp->from = grep_mail_address(p);
				smtp->state = SMTP_MAIL;
			}
			else if (smtp->state == SMTP_MAIL &&
				 strncasecmp(p, "RCPT ", 5) == 0) {
				smtp->state = SMTP_RCPT;
			}
			else if (smtp->state == SMTP_RCPT &&
				 strncasecmp(p, "DATA", 4) == 0) {
				smtp->state = SMTP_DATA;
				break;
			}
		}
	}
	if (smtp->state == SMTP_DATA) {
		if ((i = buf_index(&buf, "\r\n.\r\n", 5)) >= 0) {
			body = buf_tok(&buf, NULL, i);
			buf_skip(&buf, 5);
			body->base[body->end] = '\0';
			
			if (regex_match(buf_ptr(body)))
				print_mbox_msg(smtp->from, buf_ptr(body));
			
			if (smtp->from) {
				free(smtp->from);
				smtp->from = NULL;
			}
			smtp->state = SMTP_HELO;
		}
	}
	return (len - buf_len(&buf));
}

static void
sniff_pop_session(struct tcp_stream *ts, struct pop_info **pop_save)
{
	struct pop_info *pop;
	int i;
	
	if (ts->addr.dest != 110 && ts->addr.source != 110 &&	/* POP3 */
	    ts->addr.dest != 109 && ts->addr.source != 109 &&	/* POP2 */
	    ts->addr.dest != 1109 && ts->addr.source != 1109)	/* KPOP */
		return;
	
	switch (ts->nids_state) {
		
	case NIDS_JUST_EST:
		ts->server.collect = 1;
		ts->client.collect = 1;
		
		if ((pop = (struct pop_info *) malloc(sizeof(*pop))) == NULL)
			nids_params.no_mem("sniff_pop_session");
		
		pop->state = POP_NONE;
		*pop_save = pop;
		break;

	case NIDS_DATA:
		pop = *pop_save;
		
		if (ts->server.count_new > 0) {
			i = process_pop_client(pop, ts->server.data,
					       ts->server.count -
					       ts->server.offset);
			nids_discard(ts, i);
		}
		else if (ts->client.count_new > 0) {
			i = process_pop_server(pop, ts->client.data,
					       ts->client.count -
					       ts->client.offset);
			nids_discard(ts, i);
		}
		break;
		
	default:
		pop = *pop_save;
		
		if (ts->server.count > 0)
			process_pop_client(pop, ts->server.data,
					   ts->server.count -
					   ts->server.offset);
		else if (ts->client.count > 0)
			process_pop_server(pop, ts->client.data,
					   ts->client.count -
					   ts->client.offset);
		free(pop);
		break;
	}
}

/* XXX - Minimal SMTP FSM. We don't even consider server responses. */
static void
sniff_smtp_client(struct tcp_stream *ts, struct smtp_info **smtp_save)
{
	struct smtp_info *smtp;
	int i;
	
	if (ts->addr.dest != 25)
		return;
	
	switch (ts->nids_state) {
		
	case NIDS_JUST_EST:
		ts->server.collect = 1;
		
		if ((smtp = (struct smtp_info *)malloc(sizeof(*smtp))) == NULL)
			nids_params.no_mem("sniff_smtp_client");
		
		smtp->state = SMTP_NONE;
		smtp->from = NULL;
		*smtp_save = smtp;
		break;
		
	case NIDS_DATA:
		smtp = *smtp_save;
		
		if (ts->server.count_new > 0) {
			i = process_smtp_client(smtp, ts->server.data,
						ts->server.count -
						ts->server.offset);
			nids_discard(ts, i);
		}
		break;
		
	default:
		smtp = *smtp_save;
		
		if (ts->server.count > 0) {
			process_smtp_client(smtp, ts->server.data,
					    ts->server.count -
					    ts->server.offset);
		}
		if (smtp->from)
			free(smtp->from);
		free(smtp);
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
	
	while ((c = getopt(argc, argv, "i:p:vh?V")) != -1) {
		switch (c) {
		case 'i':
			nids_params.device = optarg;
			break;
                case 'p':
                        nids_params.filename = optarg;
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
	if (argc > 1) 
		nids_params.pcap_filter = copy_argv(argv + 1);
	
	nids_params.scan_num_hosts = 0;
	nids_params.syslog = null_syslog;
	
	if (!nids_init())
		errx(1, "%s", nids_errbuf);
	
	nids_register_tcp(sniff_smtp_client);
	nids_register_tcp(sniff_pop_session);

	if (nids_params.pcap_filter != NULL) {
                if (nids_params.filename == NULL) {
		        warnx("listening on %s [%s]", nids_params.device,
		              nids_params.pcap_filter);
                }
                else {
		        warnx("using %s [%s]", nids_params.filename,
		              nids_params.pcap_filter);
                }
	}
	else {
                if (nids_params.filename == NULL) {
                    warnx("listening on %s", nids_params.device);
                }
                else {
                    warnx("using %s", nids_params.filename);
                }
        }
	
	nids_run();
	
	/* NOTREACHED */
	
	exit(0);
}
