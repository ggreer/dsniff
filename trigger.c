/*
 * trigger.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: trigger.c,v 1.21 2001/03/15 08:33:05 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include <stdlib.h>
#include <err.h>
#include <libnet.h>
#include <nids.h>

#include "decode.h"
#include "magic.h"
#include "options.h"
#include "pathnames.h"
#include "record.h"
#include "tcp_raw.h"
#include "trigger.h"

struct trigger {
	int num;
	struct decode *decode;
};

static struct trigger	ip_triggers[32];
static struct trigger	udp_triggers[512];
static struct trigger	tcp_triggers[512];
static struct trigger	rpc_triggers[32];

static u_int		ip_cnt = 0;
static u_int		udp_cnt = 0;
static u_int		tcp_cnt = 0;
static u_int		rpc_cnt = 0;

static char		obuf[4096];

static int
trigger_compare(const void *a, const void *b)
{
	struct trigger *p, *q;

	q = (struct trigger *)a;
	p = (struct trigger *)b;
	
	if (p->num < q->num) {
		return (-1);
	}
	else if (p->num > q->num) {
		return (1);
	}
	return (0);
}

int
trigger_set_ip(int num, char *name)
{
	struct trigger *t, tr;

	tr.num = num;
	
	if ((tr.decode = getdecodebyname(name)) == NULL) {
		warnx("trigger_set_ip: unknown decode: %s", name);
		return (0);
	}
	t = (struct trigger *) bsearch(&tr, &ip_triggers, ip_cnt,
				       sizeof(tr), trigger_compare);
	if (t != NULL) {
		if (Opt_debug)
			warnx("trigger_set_ip: proto %d already set", num);
		return (0);
	}
	if (ip_cnt == sizeof(ip_triggers) / sizeof(tr)) {
		warnx("trigger_set_ip: ip_triggers full");
		return (0);
	}
	ip_triggers[ip_cnt++] = tr;
	
	qsort(&ip_triggers, ip_cnt, sizeof(tr), trigger_compare);
	
	if (Opt_debug)
		warnx("trigger_set_ip: proto %d -> %s", num, name);
	
	return (1);
}

int
trigger_set_udp(int num, char *name)
{
	struct trigger *t, tr;
	
	tr.num = num;
	
	if ((tr.decode = getdecodebyname(name)) == NULL) {
		warnx("trigger_set_udp: unknown decode: %s", name);
		return (0);
	}
	t = (struct trigger *) bsearch(&tr, &udp_triggers, udp_cnt,
				       sizeof(tr), trigger_compare);
	if (t != NULL) {
		if (Opt_debug)
			warnx("trigger_set_udp: port %d already set", num);
		return (0);
	}
	if (udp_cnt == sizeof(udp_triggers) / sizeof(tr)) {
		warnx("trigger_set_udp: udp_triggers full");
		return (0);
	}
	udp_triggers[udp_cnt++] = tr;
	
	qsort(&udp_triggers, udp_cnt, sizeof(tr), trigger_compare);
	
	if (Opt_debug)
		warnx("trigger_set_udp: port %d -> %s", num, name);

	return (1);
}

int
trigger_set_tcp(int num, char *name)
{
	struct trigger *t, tr;
	
	tr.num = num;
	
	if ((tr.decode = getdecodebyname(name)) == NULL) {
		warnx("trigger_set_tcp: unknown decode: %s", name);
		return (0);
	}
	t = (struct trigger *) bsearch(&tr, &tcp_triggers, tcp_cnt,
				       sizeof(tr), trigger_compare);
	if (t != NULL) {
		if (Opt_debug)
			warnx("trigger_set_tcp: port %d already set", num);
		return (0);
	}
	if (tcp_cnt == sizeof(tcp_triggers) / sizeof(tr)) {
		warnx("trigger_set_tcp: tcp_triggers full");
		return (0);
	}
	tcp_triggers[tcp_cnt++] = tr;
	
	qsort(&tcp_triggers, tcp_cnt, sizeof(tr), trigger_compare);
	
	if (Opt_debug)
		warnx("trigger_set_tcp: port %d -> %s", num, name);
	
	return (1);
}

int
trigger_set_rpc(int num, char *name)
{
	struct trigger *t, tr;

	tr.num = num;
	
	if ((tr.decode = getdecodebyname(name)) == NULL) {
		warnx("trigger_set_tcp: unknown decode: %s", name);
		return (0);
	}
	t = (struct trigger *) bsearch(&tr, &rpc_triggers, rpc_cnt,
				       sizeof(tr), trigger_compare);
	if (t != NULL) {
		if (Opt_debug)
			warnx("trigger_set_rpc: RPC program %d already set",
			      num);
		return (0);
	}
	if (rpc_cnt == sizeof(rpc_triggers) / sizeof(tr)) {
		warnx("trigger_set_rpc: rpc_triggers full");
		return (0);
	}
	rpc_triggers[rpc_cnt++] = tr;
	
	qsort(&rpc_triggers, rpc_cnt, sizeof(tr), trigger_compare);
	
	if (Opt_debug)
		warnx("trigger_set_rpc: program %d -> %s", num, name);
	
	return (1);
}

static int
trigger_set(char *proto, int num, char *name)
{
	if (strcasecmp(proto, "ip") == 0) {
		return (trigger_set_ip(num, name));
	}
	else if (strcasecmp(proto, "udp") == 0) {
		return (trigger_set_udp(num, name));
	}
	else if (strcasecmp(proto, "tcp") == 0) {
		return (trigger_set_tcp(num, name));
	}
	else if (strcasecmp(proto, "rpc") == 0) {
		return (trigger_set_rpc(num, name));
	}
	else warnx("trigger_set: unknown protocol %s", proto);

	return (0);
}

static struct trigger *
trigger_set_magic(int proto, int num, u_char *buf, int len)
{
	struct trigger *t, tr;
	char *name;

	if ((name = magic_match(buf, len)) == NULL)
		return (NULL);

	t = NULL;
	tr.num = num;

	if (proto == IPPROTO_UDP) {
		trigger_set_udp(num, name);
		if (strcmp(name, "portmap") == 0 ||	/* XXX - hack */
		    strcmp(name, "mountd") == 0 ||
		    strcmp(name, "yppasswd") == 0) {
			trigger_set_udp(0 - num, name);
		}
		t = (struct trigger *) bsearch(&tr, &udp_triggers, udp_cnt,
					       sizeof(tr), trigger_compare);
	}
	else if (proto == IPPROTO_TCP) {
		trigger_set_tcp(num, name);
		if (strcmp(name, "portmap") == 0 ||	/* XXX - hack */
		    strcmp(name, "mountd") == 0 ||
		    strcmp(name, "yppasswd") == 0) {
			trigger_set_tcp(0 - num, name);
		}
		t = (struct trigger *) bsearch(&tr, &tcp_triggers, tcp_cnt,
					       sizeof(tr), trigger_compare);
	}
	return (t);
}

void
trigger_dump(void)
{
	FILE *f;
	int i;

	if ((f = fopen(DSNIFF_SERVICES, "w")) == NULL) {
		warn("trigger_dump: couldn't open " DSNIFF_SERVICES);
		return;
	}
	fprintf(f, "# $Id: trigger.c,v 1.21 2001/03/15 08:33:05 dugsong Exp $\n"
		"#\n# Network services, dsniff style\n#\n");
	
	for (i = 0; i < ip_cnt; i++) {
		fprintf(f, "%s\t\t%d/ip\n", ip_triggers[i].decode->dc_name,
			ip_triggers[i].num);
	}
	for (i = 0; i < udp_cnt; i++) {
		fprintf(f, "%s\t\t%d/udp\n", udp_triggers[i].decode->dc_name,
			udp_triggers[i].num);
	}
	for (i = 0; i < tcp_cnt; i++) {
		fprintf(f, "%s\t\t%d/tcp\n", tcp_triggers[i].decode->dc_name,
			tcp_triggers[i].num);
	}
	for (i = 0; i < rpc_cnt; i++) {
		fprintf(f, "%s\t\t%d/rpc\n", rpc_triggers[i].decode->dc_name,
			rpc_triggers[i].num);
	}
	fclose(f);
}
	
void
trigger_ip(struct libnet_ipv4_hdr *ip)
{
	struct trigger *t, tr;
	u_char *buf;
	int len;

	tr.num = ip->ip_p;
	
	t = (struct trigger *) bsearch(&tr, &ip_triggers, ip_cnt,
				       sizeof(tr), trigger_compare);

	if (t == NULL)
		return;
	
	buf = (u_char *)ip + (ip->ip_hl * 4);
	len = ntohs(ip->ip_len) - (ip->ip_hl * 4);
	
	if (Opt_debug)
		warnx("trigger_ip: decoding proto %d as %s",
		      tr.num, t->decode->dc_name);
	
	if ((len = t->decode->dc_func(buf, len, obuf, sizeof(obuf))) > 0) {
		record(ip->ip_src.s_addr, ip->ip_dst.s_addr, ip->ip_p,
		       0, 0, t->decode->dc_name, obuf, len);
	}		
}

/* libnids needs a nids_register_udp()... */
void
trigger_udp(struct libnet_ipv4_hdr *ip)
{
	struct trigger *t, tr;
	struct libnet_udp_hdr *udp;
	u_char *buf;
	int len, ip_hl = ip->ip_hl * 4;
	
	len = ntohs(ip->ip_len) - ip_hl;
	
	if (ip->ip_p != IPPROTO_UDP || len < sizeof(*udp))
		return;

	buf = (u_char *)ip + ip_hl;
	udp = (struct libnet_udp_hdr *)buf;
	
	if (len != ntohs(udp->uh_ulen))
		return;
	
	buf += sizeof(*udp);
	len -= sizeof(*udp);
	
	tr.num = ntohs(udp->uh_dport);
	t = (struct trigger *) bsearch(&tr, &udp_triggers, udp_cnt,
				       sizeof(tr), trigger_compare);
	if (t == NULL) {
		tr.num = 0 - (int) ntohs(udp->uh_sport);
		t = (struct trigger *) bsearch(&tr, &udp_triggers, udp_cnt,
					       sizeof(tr), trigger_compare);
		if (t == NULL && Opt_magic)
			t = trigger_set_magic(IPPROTO_UDP,
					      ntohs(udp->uh_dport), buf, len);
		if (t == NULL)
			return;
	}
	if (Opt_debug)
		warnx("trigger_udp: decoding port %d as %s",
		      tr.num, t->decode->dc_name);
	
	if ((len = t->decode->dc_func(buf, len, obuf, sizeof(obuf))) > 0) {
		record(ip->ip_src.s_addr, ip->ip_dst.s_addr, IPPROTO_UDP,
		       ntohs(udp->uh_sport), ntohs(udp->uh_dport),
		       t->decode->dc_name, obuf, len);
	}
}

static void
trigger_tcp_half(struct tuple4 *addr, struct half_stream *hs,
		 struct trigger *t)
{
	u_char *buf;
	int len;

	buf = hs->data;
	len = hs->count - hs->offset;

	if (len == 0 || buf == NULL)
		return;
	
	if (hs->bufsize > len)
		buf[len] = '\0';

	if (t == NULL && Opt_magic)
		t = trigger_set_magic(IPPROTO_TCP, addr->dest, buf, len);

	if (t != NULL) {
		if (Opt_debug)
			warnx("trigger_tcp: decoding port %d as %s",
			      addr->dest, t->decode->dc_name);
		
		if ((len = t->decode->dc_func(buf, len,
					      obuf, sizeof(obuf))) > 0) {
			record(addr->saddr, addr->daddr, IPPROTO_TCP,
			       addr->source, addr->dest, t->decode->dc_name,
			       obuf, len);
		}
	}
	hs->collect = 0;
}

void
trigger_tcp(struct tcp_stream *ts, void **conn_save)
{
	struct trigger *ct, *st, tr;
	
	tr.num = ts->addr.dest;
	ct = (struct trigger *) bsearch(&tr, &tcp_triggers, tcp_cnt,
					sizeof(tr), trigger_compare);
	
	tr.num = 0 - (int) ts->addr.dest;
	st = (struct trigger *) bsearch(&tr, &tcp_triggers, tcp_cnt,
					sizeof(tr), trigger_compare);
	
	switch (ts->nids_state) {
		
	case NIDS_JUST_EST:
		if (ct != NULL || Opt_magic) {
			ts->server.collect = 1;
		}
		if (st != NULL) {
			ts->client.collect = 1;
		}
		break;
		
	case NIDS_DATA:
		if ((ct != NULL || Opt_magic) && ts->server.count_new) {
			if (ts->server.count - ts->server.offset >=
			    Opt_snaplen) {
				trigger_tcp_half(&ts->addr, &ts->server, ct);
			}
			else nids_discard(ts, 0);
		}
		else if (st != NULL && ts->client.count_new) {
			if (ts->client.count - ts->client.offset >=
			    Opt_snaplen) {
				trigger_tcp_half(&ts->addr, &ts->client, st);
			}
			else nids_discard(ts, 0);
		}
		break;
		
	default:
		if ((ct != NULL || Opt_magic) && ts->server.count > 0) {
			trigger_tcp_half(&ts->addr, &ts->server, ct);
		}
		if (st != NULL && ts->client.count > 0) {
			trigger_tcp_half(&ts->addr, &ts->client, st);
		}
		break;
	}
}

void
trigger_tcp_raw(struct libnet_ipv4_hdr *ip)
{
	struct trigger *t, tr;
	struct libnet_tcp_hdr *tcp;
	struct iovec *iov;
	int len, ip_hl = ip->ip_hl * 4;
	
	len = ntohs(ip->ip_len) - ip_hl;

	if (ip->ip_p != IPPROTO_TCP || len < sizeof(*tcp))
		return;

	tcp = (struct libnet_tcp_hdr *)((u_char *)ip + ip_hl);
	
	tr.num = ntohs(tcp->th_dport);
	
	t = (struct trigger *) bsearch(&tr, &tcp_triggers, tcp_cnt,
				       sizeof(tr), trigger_compare);
	if (t == NULL) {
		tr.num = 0 - (int) ntohs(tcp->th_sport);
		t = (struct trigger *) bsearch(&tr, &tcp_triggers, tcp_cnt,
					       sizeof(tr), trigger_compare);
		if (t == NULL && !Opt_magic)
			return;
	}
	if ((iov = tcp_raw_input(ip, tcp, len)) == NULL)
		return;

	if (t == NULL && Opt_magic)
		t = trigger_set_magic(IPPROTO_TCP, ntohs(tcp->th_dport),
				      iov->iov_base, iov->iov_len);

	if (t != NULL) {
		if (Opt_debug)
			warnx("trigger_tcp_raw: decoding port %d as %s",
			      tr.num, t->decode->dc_name);
		
		len = t->decode->dc_func(iov->iov_base, iov->iov_len,
					 obuf, sizeof(obuf));
		
		if (len > 0) {
			record(ip->ip_src.s_addr, ip->ip_dst.s_addr,
			       IPPROTO_TCP, ntohs(tcp->th_sport),
			       ntohs(tcp->th_dport), t->decode->dc_name,
			       obuf, len);
		}
	}
	free(iov->iov_base);
	free(iov);
}

static void
trigger_tcp_raw_callback(in_addr_t src, in_addr_t dst,
			 u_short sport, u_short dport,
			 u_char *buf, int len)
{
	struct trigger *t, tr;

	tr.num = dport;

	t = (struct trigger *) bsearch(&tr, &tcp_triggers, tcp_cnt,
				       sizeof(tr), trigger_compare);
	if (t == NULL && Opt_magic)
		t = trigger_set_magic(IPPROTO_TCP, dport, buf, len);

	if (t != NULL) {
		if (Opt_debug)
			warnx("trigger_tcp_raw_timeout: "
			      "decoding port %d as %s",
			      tr.num, t->decode->dc_name);
		
		if ((len = t->decode->dc_func(buf, len,
					      obuf, sizeof(obuf))) > 0) {
			record(src, dst, IPPROTO_TCP, sport, dport,
			       t->decode->dc_name, obuf, len);
		}
	}
}

void
trigger_tcp_raw_timeout(int signal)
{
	tcp_raw_timeout(TRIGGER_TCP_RAW_TIMEOUT, trigger_tcp_raw_callback);
	alarm(TRIGGER_TCP_RAW_TIMEOUT);
}

void
trigger_rpc(int program, int proto, int port)
{
	struct trigger *t, tr;

	tr.num = program;

	t = (struct trigger *) bsearch(&tr, &rpc_triggers, rpc_cnt,
				       sizeof(tr), trigger_compare);
	if (t == NULL)
		return;

	if (proto == IPPROTO_UDP) {
		trigger_set_udp(port, t->decode->dc_name);
	}
	else if (proto == IPPROTO_TCP) {
		trigger_set_tcp(port, t->decode->dc_name);
	}
}
	
void
trigger_init_magic(char *filename)
{
	magic_init(filename);
}

void
trigger_init_list(char *list)
{
	char *name, *port, *proto = NULL;

	while ((name = strsep(&list, ",")) != NULL) {
		if ((port = strsep(&name, "/")) == NULL ||
		    (proto = strsep(&name, "=")) == NULL) {
			errx(1, "trigger_init_list: parse error");
		}
		trigger_set(proto, atoi(port), name);
	}
}

void
trigger_init_services(char *services)
{
	FILE *f;
	char *name, *port, *proto, line[1024];
	
	if ((f = fopen(services, "r")) == NULL)
		errx(1, "couldn't open %s", services);
	
	while (fgets(line, sizeof(line), f) != NULL) {
		if (line[0] == '#' || line[0] == '\n')
			continue;
		
		if ((name = strtok(line, " \t")) == NULL ||
		    (port = strtok(NULL, " \t/")) == NULL ||
		    (proto = strtok(NULL, " \t#\n")) == NULL) {
			continue;
		}
		trigger_set(proto, atoi(port), name);
	}
	fclose(f);
}

