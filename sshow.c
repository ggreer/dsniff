/*
 * sshow.c
 *
 * Passive SSH traffic analysis.
 *
 * http://www.openwall.com/advisories/OW-003-ssh-traffic-analysis.txt
 *
 * Copyright (c) 2000-2001 Solar Designer <solar@openwall.com>
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: sshow.c,v 1.2 2001/03/19 06:52:15 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/times.h>
#include <time.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <err.h>
#include <nids.h>
#include <pcap.h>

#include "pcaputil.h"

#if !defined(NIDS_MAJOR) || (NIDS_MAJOR == 1 && NIDS_MINOR < 15)
#error This program requires libnids 1.15+
#endif

#define HISTORY_SIZE			16

typedef struct {
	u_int min, max;
} range;

typedef struct {
	int direction;			/* 0 for client to server */
	clock_t timestamp;		/* timestamp of this packet */
	u_int cipher_size;		/* ciphertext size */
	range plain_range;		/* possible plaintext sizes */
} record;

struct history {
	record packets[HISTORY_SIZE];	/* recent packets (circular list) */
	int index;			/* next (free) index into packets[] */
	u_int directions;		/* recent directions (bitmask) */
	clock_t timestamps[2];		/* last timestamps in each direction */
};

struct line {
	int input_count;		/* input packets (client to server) */
	int input_size;			/* input size (estimated) */
	int input_last;			/* last input packet size */
	int echo_count;			/* echo packets (server to client) */
};

struct session {
	int protocol;		/* -1 not SSH, 0 unknown, 1 or 2 once known */
	int state;		/* 1 after username, 2 after authentication */
	int compressed;		/* whether compression is known to be used */
	struct history history;	/* session history */
	struct line line;	/* current command line */
};

static int debug = 0;

static clock_t now;

static void
usage(void)
{
	fprintf(stderr, "Usage: sshow [-d] [-i interface | -p pcapfile]\n");
	exit(1);
}

static clock_t
add_history(struct session *session, int direction,
	    u_int cipher_size, range *plain_range)
{
	record *current;
	clock_t delay;

	current = &session->history.packets[session->history.index++];
	session->history.index %= HISTORY_SIZE;

	current->direction = direction;
	current->timestamp = now;
	current->cipher_size = cipher_size;
	current->plain_range = *plain_range;

	session->history.directions <<= 1;
	session->history.directions |= direction;

	delay = now - session->history.timestamps[direction];
	session->history.timestamps[direction] = now;

	return (delay);
}

static record *
get_history(struct session *session, int age)
{
	int index;

	index = session->history.index + (HISTORY_SIZE - 1) - age;
	index %= HISTORY_SIZE;

	return (&session->history.packets[index]);
}

static char *
s_saddr(struct tcp_stream *ts)
{
	static char output[32];

	snprintf(output, sizeof(output), "%s:%u",
		inet_ntoa(*((struct in_addr *)&ts->addr.saddr)),
		ts->addr.source);
	return (output);
}

static char *
s_daddr(struct tcp_stream *ts)
{
	static char output[32];

	snprintf(output, sizeof(output), "%s:%u",
		inet_ntoa(*((struct in_addr *)&ts->addr.daddr)),
		ts->addr.dest);
	return (output);
}

static char *
s_range(range *range)
{
	static char output[32];

	snprintf(output, sizeof(output),
		range->min == range->max ? "%u" : "%u to %u",
		range->min, range->max);
	return (output);
}

static void
print_data(struct half_stream *stream, u_int count)
{
	u_int i;
	int printable;

	printable = 1;
	for (i = 0; i < count; i++) {
		printf("%02x%c", (int)(u_char)stream->data[i],
			i < count - 1 && i % 24 != 23
			? ' ' : '\n');
		printable &=
			isprint(stream->data[i]) ||
			stream->data[i] == '\n';
	}
	if (printable && count >= 4 && !memcmp(stream->data, "SSH-", 4))
		fwrite(stream->data, count, 1, stdout);
}

static u_int
ssh1_plain_size(struct half_stream *stream)
{
	if (stream->count_new < 4) return (0);

	return (u_int)(u_char)stream->data[3] |
		((u_int)(u_char)stream->data[2] << 8) |
		((u_int)(u_char)stream->data[1] << 16) |
		((u_int)(u_char)stream->data[0] << 24);
}

static u_int
ssh1_cipher_size(struct half_stream *stream)
{
	return (4 + ((ssh1_plain_size(stream) + 8) & ~7));
}

static range *
ssh1_plain_range(struct half_stream *stream)
{
	static range output;

	output.min = output.max = ssh1_plain_size(stream) - 5;
	return (&output);
}

static range *
ssh2_plain_range(struct half_stream *stream)
{
	static range output;

	output.max = stream->count_new - 16;
	/* Assume min padding + 8-byte cipher blocksize */
	output.min = output.max - 7;
	if ((int)output.min < 0) output.min = 0;
	return (&output);
}

static void
client_to_server(struct tcp_stream *ts, struct session *session,
		 u_int cipher_size, range *plain_range)
{
	clock_t delay;
	int payload;
    long CLK_TCK= sysconf(_SC_CLK_TCK);

	delay = add_history(session, 0, cipher_size, plain_range);

	if (debug)
		printf("- %s -> %s: DATA (%s bytes, %.2f seconds)\n",
			s_saddr(ts), s_daddr(ts), s_range(plain_range),
			(float)delay / CLOCKS_PER_SEC);
	if (debug > 1)
		print_data(&ts->server, cipher_size);

	payload = plain_range->min;
	if (session->state == 2 && payload > 0) {
		session->line.input_count++;
		session->line.input_last = payload;
		if (session->protocol == 1)
			payload -= 4;
		else {
			payload -= 20 + 1;
			/* Assume several SSH-2 packets in this IP packet */
			if (payload % 44 == 0) {
				session->line.input_count += payload / 44;
				/* One character per SSH-2 packet (typical) */
				payload += payload / 44;
				payload %= 44;
			}
			payload++;
		}
		if (payload <= 0) {
			if (payload < 0 && !session->compressed &&
			    session->protocol == 1) {
				session->compressed = 1;
				printf("+ %s -> %s: Compression detected, "
					"guesses will be much less reliable\n",
					s_saddr(ts), s_daddr(ts));
			}
			payload = 1;
		}
		session->line.input_size += payload;
	}
}

static void
server_to_client(struct tcp_stream *ts, struct session *session,
		 u_int cipher_size, range *plain_range)
{
	clock_t delay;
	int skip;
	range string_range;
    long CLK_TCK= sysconf(_SC_CLK_TCK);
	
	delay = add_history(session, 1, cipher_size, plain_range);
	
	if (debug)
		printf("- %s <- %s: DATA (%s bytes, %.2f seconds)\n",
		       s_saddr(ts), s_daddr(ts), s_range(plain_range),
		       (float)delay / CLOCKS_PER_SEC);
	if (debug > 1)
		print_data(&ts->client, cipher_size);
	
/*
 * Some of the checks may want to skip over multiple server responses.
 * For example, there's a debugging packet sent for every option found
 * in authorized_keys, but we can't use those packets in our pattern.
 */
	skip = 0;
	while (((session->history.directions >> skip) & 3) == 3)
		if (++skip > HISTORY_SIZE - 5) break;
	
	if (session->state == 0 &&
	    session->protocol == 1 &&
	    ((session->history.directions >> skip) & 7) == 5 &&
	    plain_range->min == 0 &&
	    get_history(session, skip + 1)->plain_range.min > 4 &&
	    get_history(session, skip + 2)->plain_range.min == 0) {
		session->state = 1;
		string_range = get_history(session, skip + 1)->plain_range;
		string_range.min -= 4; string_range.max -= 4;
		printf("+ %s -> %s: GUESS: Username length is %s\n",
		       s_saddr(ts), s_daddr(ts), s_range(&string_range));
		return;
	}
	
	if (session->state == 1 &&
#ifdef USE_TIMING
	    now - get_history(session, 2)->timestamp >= CLOCKS_PER_SEC &&
#endif
	    session->protocol == 1 &&
	    (session->history.directions & 7) == 5 &&
	    plain_range->min == 0 &&
	    get_history(session, 1)->plain_range.min > 4 &&
	    get_history(session, 2)->plain_range.min == 0) {
		session->state = 2;
		string_range = get_history(session, 1)->plain_range;
		string_range.min -= 4; string_range.max -= 4;
		printf("+ %s -> %s: GUESS: Password authentication, "
		       "password length %s %s%s\n",
		       s_saddr(ts), s_daddr(ts),
		       string_range.min == 32 ? "appears to be" : "is",
		       s_range(&string_range),
		       string_range.min == 32 ? " (padded?)" : "");
	}
	
	if (session->state == 0 &&
	    session->protocol == 2 &&
	    (session->history.directions & 7) == 5) {
		if (plain_range->min == 4 + 9) {
			string_range = get_history(session, 1)->plain_range;
			
			if (string_range.min > 500 && string_range.min < 600) {
				session->state = 2;
				printf("+ %s -> %s: GUESS: DSA "
				       "authentication accepted\n",
				       s_saddr(ts), s_daddr(ts));
			} else
				if (string_range.min > 42 + 9) {
					session->state = 2;
					printf("+ %s -> %s: GUESS: Password "
					       "authentication accepted\n",
					       s_saddr(ts), s_daddr(ts));
				}
		} else if (plain_range->min > 12 + 9 &&
			   plain_range->min < 56 + 9) {
			string_range = get_history(session, 1)->plain_range;
			
			if (string_range.min > 500 && string_range.min < 600)
				printf("+ %s -> %s: GUESS: DSA "
				       "authentication failed\n",
				       s_saddr(ts), s_daddr(ts));
			else if (string_range.min > 42 + 9)
				printf("+ %s -> %s: GUESS: Password "
				       "authentication failed\n",
				       s_saddr(ts), s_daddr(ts));
		}
	}
	
	if (session->state == 1 &&
	    session->protocol == 1 &&
	    (session->history.directions & 3) == 1 &&
	    plain_range->min == 0 &&
	    get_history(session, 1)->plain_range.min == 130) {
		printf("+ %s -> %s: GUESS: RSA authentication refused\n",
		       s_saddr(ts), s_daddr(ts));
	}
	
	if (session->state == 1 &&
	    session->protocol == 1 &&
	    skip >= 1 &&
	    ((session->history.directions >> (skip - 1)) & 037) == 013 &&
	    plain_range->min == 0 &&
	    get_history(session, skip - 1 + 2)->plain_range.min == 16 &&
	    get_history(session, skip - 1 + 3)->plain_range.min == 130 &&
	    get_history(session, skip - 1 + 4)->plain_range.min == 130) {
		char *what;
		
		switch (get_history(session, 1)->plain_range.min - 4) {
		case 28:
			/* "RSA authentication accepted." */
			session->state = 2;
			if (skip > 1 && (what = alloca(64))) {
				snprintf(what, 64, "accepted "
					 "(%d+ authorized_keys option%s)",
					 skip - 1, skip - 1 == 1 ? "" : "s");
				break;
			}
			what = "accepted";
			break;
			
		case 47:
			/* "Wrong response to RSA authentication challenge." */
			what = "failed";
			break;
			
		default:
			what = "???";
		}
		printf("+ %s -> %s: GUESS: RSA authentication %s\n",
		       s_saddr(ts), s_daddr(ts), what);
	}
	
	if (session->state == 2) {
		session->line.echo_count++;
		
		/* Check for backspace */
		if (session->protocol == 1 && !session->compressed &&
		    plain_range->min == 4 + 3 &&
		    session->line.input_size >= 2)
			session->line.input_size -= 2;
		
		if (plain_range->min > 4 + session->line.input_last &&
		    session->line.input_count >= 2 &&
		    session->line.input_size >= 2) {
			int size;
			char *what;
			
			size = session->line.input_size;
			if (session->line.echo_count + 1 >=
			    session->line.input_count &&
			    size <= (session->line.input_count << 2) &&
			    size < 0x100) {
				what = "(command) line";
			}
			else {
				if (session->line.echo_count <= 2 &&
				    size <= (session->line.input_count << 1) &&
				    size >= 2 + 1 && size <= 40 + 1) {
					what = "password";
				}
				else what = NULL;
			}
			if (debug) {
				printf("- %s -> %s: sent %d packets "
				       "(%d characters), seen %d replies\n",
				       s_saddr(ts), s_daddr(ts),
				       session->line.input_count, size,
				       session->line.echo_count);
			}
			if (what) {
				printf("+ %s -> %s: GUESS: "
				       "a %s of %d character%s\n",
				       s_saddr(ts), s_daddr(ts),
				       what, size - 1, size == 2 ? "" : "s");
			}
		}
		if (plain_range->min <= 0 ||
		    plain_range->min > 4 + session->line.input_last) {
			session->line.input_count = 0;
			session->line.input_size = 0;
			session->line.echo_count = 0;
		}
	}
}

static void
process_data(struct tcp_stream *ts, struct session *session)
{
	u_int have, need;
	char *lf;
	
	if (session->protocol < 0) return;
	
	if (ts->client.count_new &&
	    (have = ts->client.count - ts->client.offset)) {
		switch (session->protocol) {
		case 1:
			if (have < (need = ssh1_cipher_size(&ts->client))) {
				if (debug) {
					printf("- %s <- %s: got %u of "
					       "%u bytes\n", s_saddr(ts),
					       s_daddr(ts), have, need);
				}
				nids_discard(ts, 0);
				return;
			}
			if (have != need && debug) {
				printf("- %s <- %s: left %u bytes\n",
				       s_saddr(ts), s_daddr(ts),
				       have - need);
			}
			nids_discard(ts, need);
			server_to_client(ts, session, need,
				ssh1_plain_range(&ts->client));
			return;
			
		case 2:
			server_to_client(ts, session, have,
					 ssh2_plain_range(&ts->client));
			return;
			
		default:
			break;
		}
	}
	if (ts->server.count_new &&
	    (have = ts->server.count - ts->server.offset)) {
		if (!session->protocol) {
			lf = (char *)memchr(ts->server.data, '\n', have);
			if (have < 7 || (!lf && have < 0x100)) {
				nids_discard(ts, 0);
				return;
			}
			if (lf && !memcmp(ts->server.data, "SSH-", 4))
				session->protocol = ts->server.data[4] - '0';
			/* some clients announce SSH-1.99 instead of SSH-2.0 */
			if (session->protocol == 1 &&
			    ts->server.data[5] == '.' &&
			    ts->server.data[6] == '9') {
				session->protocol = 2;
			}
			if (session->protocol != 1 && session->protocol != 2) {
				session->protocol = -1;
				if (debug) {
					printf("- %s -> %s: not SSH\n",
					       s_saddr(ts), s_daddr(ts));
				}
				return;
			}
			need = lf - ts->server.data + 1;
			nids_discard(ts, need);
			printf("+ %s -> %s: SSH protocol %d\n",
			       s_saddr(ts), s_daddr(ts), session->protocol);
			if (debug)
				print_data(&ts->server, have);
			return;
		}
		
		switch (session->protocol) {
		case 1:
			if (have < (need = ssh1_cipher_size(&ts->server))) {
				if (debug) {
					printf("- %s -> %s: got %u of "
					       "%u bytes\n", s_saddr(ts),
					       s_daddr(ts), have, need);
				}
				nids_discard(ts, 0);
				return;
			}
			if (have != need && debug) {
				printf("- %s -> %s: left %u bytes\n",
				       s_saddr(ts), s_daddr(ts),
				       have - need);
			}
			nids_discard(ts, need);
			client_to_server(ts, session, need,
					 ssh1_plain_range(&ts->server));
			return;
			
		case 2:
			client_to_server(ts, session, have,
					 ssh2_plain_range(&ts->server));
		}
	}
}

static void
process_event(struct tcp_stream *ts, struct session **session)
{
	struct tms buf;
	char *what;
	
	now = times(&buf);
	what = NULL;
	
	switch (ts->nids_state) {
	case NIDS_JUST_EST:
		ts->client.collect = 1;
		ts->server.collect = 1;
		if (debug) {
			printf("- %s -> %s: ESTABLISHED\n",
			       s_saddr(ts), s_daddr(ts));
		}
		if (!(*session = calloc(1, sizeof(**session)))) {
			err(1, "calloc");
		}
		(*session)->history.timestamps[0] = now;
		(*session)->history.timestamps[1] = now;
		return;
		
	case NIDS_CLOSE:
		what = "CLOSED";
		
	case NIDS_RESET:
		if (!what) what = "RESET";
		
	case NIDS_TIMED_OUT:
		if (!what) what = "TIMED OUT";
		if ((*session)->protocol > 0) {
			printf("+ %s -- %s: %s\n",
			       s_saddr(ts), s_daddr(ts), what);
		}
		else if (debug) {
			printf("- %s -- %s: %s\n",
			       s_saddr(ts), s_daddr(ts), what);
		}
		free(*session);
		return;
		
	case NIDS_DATA:
		process_data(ts, *session);
		return;
	}
}

static void
null_syslog(int type, int errnum, struct ip *iph, void *data)
{
}

static void
cleanup(int signum)
{
	exit(0);	/* Just so that atexit(3) jobs are called */
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	int c;
	
	while ((c = getopt(argc, argv, "di:p:h?")) != -1) {
		switch (c) {
		case 'd':
			debug++;
			break;
		case 'i':
			nids_params.device = optarg;
			break;
		case 'p':
			nids_params.filename = optarg;
			break;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;
	
	signal(SIGTERM, cleanup);
	signal(SIGINT, cleanup);
	signal(SIGHUP, cleanup);
	
	setlinebuf(stdout);
	
	if (argc > 0) {
		nids_params.pcap_filter = copy_argv(argv);
	}
	else nids_params.pcap_filter = "tcp";
	
	nids_params.syslog = null_syslog;
	nids_params.scan_num_hosts = 0;
	nids_params.one_loop_less = 1;
	
	if (!nids_init())
		errx(1, "nids_init: %s", nids_errbuf);
	
	nids_register_tcp(process_event);

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
	
	return (0);
}
