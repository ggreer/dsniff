/*
 * msgsnarf.c
 *
 * Sniff chat messages (AIM, ICQ, IRC, MSN, Yahoo) on a network.
 *
 * Copyright (c) 1999 Dug Song <dugsong@monkey.org>
 *
 * $Id: msgsnarf.c,v 1.11 2001/03/15 08:33:04 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <err.h>
#include <libnet.h>
#include <nids.h>
#include <pcap.h>
#include <pcaputil.h>
#include <time.h>

#include "buf.h"
#include "decode.h"
#include "version.h"

struct client_info {
	char	       *nick;
	char	       *peer;
	char	       *type;
	in_addr_t	ip;
	SLIST_ENTRY(client_info) next;
};

SLIST_HEAD(, client_info) client_list;
int		Opt_invert = 0;
regex_t	       *pregex = NULL;

static void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: msgsnarf [-i interface] [[-v] pattern [expression]]\n");
	exit(1);
}

static char *
timestamp(void)
{
	static char stamp[32];
	struct tm *tm;
	time_t now;

	time(&now);
	tm = localtime(&now);
	strftime(stamp, sizeof(stamp), "%b %e %T", tm);

	return (stamp);
}

static int
regex_match(char *string)
{
	return (pregex == NULL ||
		((regexec(pregex, string, 0, NULL, 0) == 0) ^ Opt_invert));
}

struct flap {
	u_char	start;
	u_char	channel;
	u_short	seqnum;
	u_short	datalen;
};

struct snac {
	u_short		family;
	u_short		subtype;
	u_short		flags;
	u_int32_t	reqid;
};

static int
process_aim(struct client_info *info, u_char *data, int len)
{
	struct buf *msg, *word, buf;
	struct flap *flap;
	struct snac *snac;
	u_char c, *p;
	int i, reply;

	buf_init(&buf, data, len);

	if (buf_cmp(&buf, "FLAPON\r\n\r\n", 10) == 0)
		buf_skip(&buf, 10);

	while (buf_len(&buf) > sizeof(*flap)) {
		flap = (struct flap *)buf_ptr(&buf);
		flap->datalen = ntohs(flap->datalen);

		i = sizeof(*flap) + flap->datalen;

		if ((msg = buf_tok(&buf, NULL, i)) == NULL)
			break;

		buf_skip(msg, sizeof(*flap));
		snac = (struct snac *)buf_ptr(msg);
		
		if (flap->start != 0x2a)
			continue;
		
		if (flap->channel == 0x01) {
			if (buf_cmp(msg, "\x00\x00\x00\x01\x00\x01\x00", 7) == 0) {
				buf_skip(msg, 7);
				buf_get(msg, &c, 1);

				if ((word = buf_getbuf(msg, 0, c)) != NULL) {
					if (info->nick) free(info->nick);
					info->nick = buf_strdup(word);
					buf_free(word);
				}
				buf_skip(msg, 3);
				buf_get(msg, &c, 1);
				buf_skip(msg, c + 4);

				if (buf_cmp(msg, "ICQ", 3) == 0)
					info->type = "ICQ";
				else info->type = "AIM";
			}
		}
		else if (flap->channel == 0x02) {
			if (buf_cmp(msg, "toc_send_im ", 12) == 0) {
				buf_skip(msg, 12);
				
				if ((word = buf_getword(msg, " ", 1)) == NULL)
					continue;
				
				buf_skip(msg, 1);
				
				if (buf_len(msg) < 3) continue;
				msg->end -= 2;
				p = buf_strdup(msg);

				if (regex_match(p))
					printf("%s AIM %s > %.*s: %s\n",
					       timestamp(), info->nick,
					       buf_len(word), buf_ptr(word), p);
				buf_free(word);
				free(p);
			}
			else if (buf_cmp(msg, "IM_IN:", 6) == 0) {
				buf_skip(msg, 6);
				
				if ((word = buf_getword(msg, ":", 1)) == NULL)
					continue;
				
				buf_skip(msg, 2);
				p = buf_strdup(msg);

				if (regex_match(p))
					printf("%s AIM %.*s > %s: %s\n",
					       timestamp(), buf_len(word),
					       buf_ptr(word), info->nick, p);
				buf_free(word);
				free(p);
			}
			else if (ntohs(snac->family) == 0x04) {
				
				if (ntohs(snac->subtype) == 0x06)
					reply = 0;
				else if (ntohs(snac->subtype) == 0x07)
					reply = 1;
				else continue;
				
				buf_skip(msg, sizeof(*snac) + 8);
				buf_get(msg, &c, 1);
				
				if ((word = buf_getbuf(msg, 0, c)) == NULL)
					continue;

				/* XXX - ugh, this is totally bogus. help! */
				if (buf_cmp(msg, "\x00\x02", 2) == 0) {
					buf_skip(msg, 17);
					while (buf_cmp(msg, "\x00", 1) == 0)
						buf_skip(msg, 1);
				}
				else if (buf_cmp(msg, "\x00\x05", 2) == 0) {
					buf_skip(msg, 97);
				}
				else if (buf_cmp(msg, "\x00\x00", 2) == 0) {
					if (buf_skip(msg, 145) < 0)
						buf_skip(msg, 57);
				}
				p = buf_strdup(msg);
				
				if (p && strlen(p) && regex_match(p)) {
					if (reply) {
						printf("%s %s %.*s > %s: %s\n",
						       timestamp(), info->type,
						       buf_len(word),
						       buf_ptr(word),
						       info->nick, p);
					}
					else printf("%s %s %s > %.*s: %s\n",
						    timestamp(), info->type,
						    info->nick, buf_len(word),
						    buf_ptr(word), p);
				}
				buf_free(word);
				if (p) free(p);
			}
		}
	}
	return (len - buf_len(&buf));
}
			
static int
process_irc(struct client_info *info, u_char *data, int len)
{
	struct buf *line, *word, *prefix, buf;
	char *p;
	int i;

	buf_init(&buf, data, len);

	while ((i = buf_index(&buf, "\n", 1)) >= 0) {
		line = buf_tok(&buf, NULL, i);
		buf_skip(&buf, 1);
		
		if (line->base[line->end-1] == '\r')
			line->end--;
		
		if (buf_cmp(line, ":", 1) == 0) {
			buf_skip(line, 1);
			if ((prefix = buf_getword(line, " ", 1)) == NULL)
				continue;
			if ((i = buf_index(prefix, "!", 1)) < 0)
				continue;
			prefix->end = i;
		}
		else prefix = NULL;

		if (buf_cmp(line, "JOIN ", 5) == 0 && prefix != NULL) {
			buf_skip(line, 5);
			if (buf_cmp(line, ":", 1) == 0)
				buf_skip(line, 1);

			printf("%s IRC *** %.*s ", timestamp(),
			       buf_len(prefix), buf_ptr(prefix));

			prefix->offset = prefix->end + 1;
			prefix->end = prefix->size;

			printf("(%.*s) has joined channel %.*s\n",
			       buf_len(prefix), buf_ptr(prefix),
			       buf_len(line), buf_ptr(line));
		}
		else if (buf_cmp(line, "PART ", 5) == 0 && prefix != NULL) {
			buf_skip(line, 5);
			if (buf_cmp(line, ":", 1) == 0)
				buf_skip(line, 1);

			if ((word = buf_getword(line, " :", 2)) == NULL)
				continue;
			
			printf("%s IRC *** %.*s has left channel %.*s\n",
			       timestamp(), buf_len(prefix), buf_ptr(prefix),
			       buf_len(word), buf_ptr(word));

			buf_free(word);
		}
		else if (buf_cmp(line, "QUIT ", 5) == 0 && prefix != NULL) {
			buf_skip(line, 5);
			if (buf_cmp(line, ":", 1) == 0)
				buf_skip(line, 1);

			printf("%s IRC *** Signoff: %.*s (%.*s)\n",
			       timestamp(), buf_len(prefix), buf_ptr(prefix),
			       buf_len(line), buf_ptr(line));
		}
		else if (buf_cmp(line, "NICK ", 5) == 0) {
			buf_skip(line, 5);
			if (buf_cmp(line, ":", 1) == 0)
				buf_skip(line, 1);
			
			if (prefix != NULL) {
				printf("%s IRC *** %.*s is now known as %.*s\n",
				       timestamp(),
				       buf_len(prefix), buf_ptr(prefix),
				       buf_len(line), buf_ptr(line));
			}
			else {
				if (info->nick) free(info->nick);
				info->nick = buf_strdup(line);
			}
		}
		else if (buf_cmp(line, "PRIVMSG ", 8) == 0) {
			buf_skip(line, 8);
			if ((word = buf_getword(line, " :", 2)) == NULL)
				continue;
			p = buf_strdup(line);
			
			if (regex_match(p)) {
				if (strncmp(p + 1, "ACTION ", 7) == 0) {
					printf("%s IRC * Action: ",
					       timestamp());
					
					if (prefix != NULL) {
						printf("%.*s %s\n",
						       buf_len(prefix),
						       buf_ptr(prefix), p + 8);
					}
					else printf("%s %s\n",
						    info->nick, p + 8);
				}
				else {
					if (prefix != NULL) {
						printf("%s IRC %.*s > ",
						       timestamp(),
						       buf_len(prefix),
						       buf_ptr(prefix));
					}
					else printf("%s IRC %s > ",
						    timestamp(),
						    info->nick);
					
					printf("%.*s: %s\n", buf_len(word),
					       buf_ptr(word), p);
				}
			}
			buf_free(word);
			free(p);
		}
	}
	return (len - buf_len(&buf));
}

static int
process_msn(struct client_info *info, u_char *data, int len)
{
	struct buf *word, *line, buf;
	char *p;
	int i, reply;

	buf_init(&buf, data, len);
	
	while ((i = buf_index(&buf, "\r\n", 2)) >= 0) {
		line = buf_tok(&buf, NULL, i);
		buf_skip(&buf, 2);
		
		if (buf_cmp(line, "USR ", 4) == 0) {
			if ((i = buf_index(line, "MD5 ", 4)) > 0) {
				buf_skip(line, i + 4);
				
				if (buf_cmp(line, "I ", 2) == 0) {
					buf_skip(line, 2);
					if (info->nick != NULL)
						free(info->nick);
					info->nick = buf_strdup(line);
				}
			}
		}
		else if (buf_cmp(line, "IRO ", 4) == 0) {
			if ((i = buf_rindex(line, "1 ", 2)) < 0)
				continue;
			buf_skip(line, i + 2);
			word = buf_getword(line, " ", 1);
			if (info->peer != NULL) free(info->peer);
			info->peer = buf_strdup(word);
			buf_free(word);
		}
		else if (buf_cmp(line, "MSG ", 4) == 0) {
			buf_skip(line, 4);
			reply = 0;

			if ((word = buf_getword(line, " ", 1)) == NULL)
				continue;

			if (buf_cmp(line, "N ", 2) == 0 ||
			    buf_cmp(line, "U ", 2) == 0) {
				reply = 1;
			}
			else {
				if (info->peer != NULL) free(info->peer);
				info->peer = buf_strdup(word);
			}
			buf_free(word);
			
			if ((i = buf_rindex(line, " ", 1)) < 0)
				continue;
			
			buf_skip(line, i + 1);
			p = buf_strdup(line);
			i = atoi(p); free(p);
			if (i <= 0) continue;
			
			if ((line = buf_tok(NULL, NULL, i)) == NULL)
				break;
			
			if (buf_index(line, "Content-Type: text/plain", 24) > 0) {
				if ((i = buf_rindex(line, "\r\n\r\n", 4)) < 0)
					continue;
				
				buf_skip(line, i + 4);
				p = buf_strdup(line);

				if (regex_match(p)) {
					if (reply) {
						printf("%s MSN %s > %s: %s\n",
						       timestamp(), info->nick,
						       info->peer, p);
					}
					else printf("%s MSN %s > %s: %s\n",
						    timestamp(), info->peer,
						    info->nick, p);
				}
				free(p);
			}
		}
	}
	return (len - buf_len(&buf));
}

struct yhoo {
	u_char		version[8];
	u_int32_t	length;		/* all fields little-endian */
	u_int32_t	service;
	u_int32_t	connid;
	u_int32_t	magic;
	u_int32_t	unknown;
	u_int32_t	type;
	u_char		nick1[36];
	u_char		nick2[36];
};

struct ymsg {
	u_char		version[8];
	u_short		length;
	u_short		type;
	u_int32_t	unknown1;
	u_int32_t	unknown2;
};

static int
process_yahoo(struct client_info *info, u_char *data, int len)
{
	struct yhoo *yhoo;
	struct ymsg *ymsg;
	struct buf *msg, *nick1, *nick2, buf;
	int i, reply;
	char *p;

	buf_init(&buf, data, len);
	
	if (buf_cmp(&buf, "YMSG", 4) == 0) {
		while (buf_len(&buf) > sizeof(*ymsg)) {
			ymsg = (struct ymsg *)buf_ptr(&buf);
			ymsg->length = ntohs(ymsg->length);
			ymsg->type = ntohs(ymsg->type);

			i = sizeof(*ymsg) + ymsg->length;

			if ((msg = buf_tok(&buf, NULL, i)) == NULL)
				break;
			
			buf_skip(msg, sizeof(*ymsg));
			
			if (ymsg->type != 0x06)
				continue;
			
			reply = (buf_cmp(msg, "1", 1) != 0);
			buf_skip(msg, 3);

			nick1 = buf_getword(msg, "\xc0\x80", 2);
			buf_skip(msg, 3);

			nick2 = buf_getword(msg, "\xc0\x80", 2);
			buf_skip(msg, 4);

			msg->end -= 2;
			p = buf_strdup(msg);

			if (regex_match(p) && nick1 && nick2 && msg) {
				printf("%s Yahoo ", timestamp());
				if (reply)
					printf("%.*s > %.*s: %s\n",
					       buf_len(nick2), buf_ptr(nick2),
					       buf_len(nick1), buf_ptr(nick1),
					       p);
				else printf("%.*s > %.*s: %s\n",
					    buf_len(nick1), buf_ptr(nick1),
					    buf_len(nick2), buf_ptr(nick2), p);
			}
			if (nick1) buf_free(nick1);
			if (nick2) buf_free(nick2);
			free(p);
		}
	}
	else {
		while (buf_len(&buf) > sizeof(*yhoo)) {
			yhoo = (struct yhoo *)buf_ptr(&buf);
			yhoo->length = pletohl(&yhoo->length);
			yhoo->service = pletohl(&yhoo->service);
			yhoo->type = pletohl(&yhoo->type);
			yhoo->nick1[sizeof(yhoo->nick1) - 1] = '\0';
			yhoo->nick2[sizeof(yhoo->nick2) - 1] = '\0';

			i = sizeof(*yhoo) + yhoo->length;
			
			if ((msg = buf_tok(&buf, NULL, i)) == NULL)
				break;
			
			buf_skip(msg, sizeof(*yhoo));
			
			if (yhoo->service != 6 || yhoo->type > 1)
				continue;
			
			if ((nick1 = buf_getword(msg, ",", 1)) == NULL)
				continue;
			
			if (memcmp(yhoo->version, "YHOO", 4) == 0) {
				buf_skip(msg, 1);
				reply = 0;
			}
			else reply = 1;

			p = buf_strdup(msg);

			if (regex_match(p)) {
				if (reply)
					printf("%s Yahoo %.*s > %s: %s\n",
					       timestamp(),
					       buf_len(nick1), buf_ptr(nick1),
					       yhoo->nick2, p);
				else
					printf("%s Yahoo %s > %.*s: %s\n",
					       timestamp(), yhoo->nick2,
					       buf_len(nick1), buf_ptr(nick1),
					       buf_ptr(msg));
			}
			free(p);
		}
	}
	return (len - buf_len(&buf));
}

static void
sniff_msgs(struct tcp_stream *ts, void **conn_save)
{
	struct client_info *c;
	int (*process_msgs)(struct client_info *, u_char *, int);
	int i;
	
	if (ts->addr.dest >= 6660 && ts->addr.dest <= 6680) {
		process_msgs = process_irc;
	}
	else if (ts->addr.dest == 5190 || ts->addr.dest == 9898) {
		process_msgs = process_aim;
	}
	else if (ts->addr.dest == 5050) {
		process_msgs = process_yahoo;
	}
	else if (ts->addr.dest == 1863) {
		process_msgs = process_msn;
	}
	else return;
	
	switch (ts->nids_state) {
		
	case NIDS_JUST_EST:
		ts->server.collect = 1;
		ts->client.collect = 1;

		i = 0;
		SLIST_FOREACH(c, &client_list, next) {
			if (c->ip == ts->addr.saddr) {
				i = 1; break;
			}
		}
		if (i == 0) {
			if ((c = malloc(sizeof(*c))) == NULL)
				nids_params.no_mem("sniff_msgs");
			c->ip = ts->addr.saddr;
			c->nick = strdup("unknown");
			SLIST_INSERT_HEAD(&client_list, c, next);
		}
		*conn_save = (void *)c;
		break;

	case NIDS_DATA:
		c = (struct client_info *)*conn_save;
		
		if (ts->server.count_new > 0) {
			i = process_msgs(c, ts->server.data,
					 ts->server.count - ts->server.offset);
			nids_discard(ts, i);
		}
		else if (ts->client.count_new > 0) {
			i = process_msgs(c, ts->client.data,
					 ts->client.count - ts->client.offset);
			nids_discard(ts, i);
		}
		fflush(stdout);
		break;
		
	default:
		c = (struct client_info *)*conn_save;
		
		if (ts->server.count > 0)
			process_msgs(c, ts->server.data,
				     ts->server.count - ts->server.offset);
		else if (ts->client.count > 0)
			process_msgs(c, ts->client.data,
				     ts->client.count - ts->client.offset);
		fflush(stdout);
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
	
	while ((c = getopt(argc, argv, "i:hv?V")) != -1) {
		switch (c) {
		case 'i':
			nids_params.device = optarg;
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

	SLIST_INIT(&client_list);
	
	nids_register_tcp(sniff_msgs);

	if (nids_params.pcap_filter != NULL) {
		warnx("listening on %s [%s]", nids_params.device,
		      nids_params.pcap_filter);
	}
	else warnx("listening on %s", nids_params.device);

	nids_run();
	
	/* NOTREACHED */
	
	exit(0);
}
