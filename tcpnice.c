/*
 * tcpnice.c
 *
 * Slow down TCP connections already in progress.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: tcpnice.c,v 1.17 2001/03/17 07:41:51 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <libnet.h>
#include <pcap.h>

#include "pcaputil.h"
#include "version.h"

#define MIN_WIN		1	/* XXX */
#define MIN_MTU		68	/* RFC 1191 */

static int	Opt_icmp;
static int	Opt_pmtu;
static int	Opt_win;
static int	pcap_off;
static u_char	buf[BUFSIZ];

static void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: tcpnice [-A] [-I] [-M] [-i interface] expression\n");
	exit(1);
}

static void
send_tcp_window_advertisement(libnet_t *l, struct libnet_ipv4_hdr *ip,
			     struct libnet_tcp_hdr *tcp)
{
	int len;
	
	ip->ip_hl = 5;
	ip->ip_len = htons(LIBNET_IPV4_H + LIBNET_TCP_H);
	ip->ip_id = libnet_get_prand(LIBNET_PRu16);
	memcpy(buf, (u_char *)ip, LIBNET_IPV4_H);
	
	tcp->th_off = 5;
	tcp->th_win = htons(MIN_WIN);
	memcpy(buf + LIBNET_IPV4_H, (u_char *)tcp, LIBNET_TCP_H);
	
	libnet_do_checksum(l, buf, IPPROTO_TCP, LIBNET_TCP_H);
	
	len = LIBNET_IPV4_H + LIBNET_TCP_H;
	
	if (libnet_write_raw_ipv4(l, buf, len) != len)
		warn("write");
	
	fprintf(stderr, "%s:%d > %s:%d: . ack %lu win %d\n",
		libnet_addr2name4(ip->ip_src.s_addr, 0), ntohs(tcp->th_sport),
		libnet_addr2name4(ip->ip_dst.s_addr, 0), ntohs(tcp->th_dport),
		ntohl(tcp->th_ack), 1);
}

static void
send_icmp_source_quench(libnet_t *l, struct libnet_ipv4_hdr *ip)
{
	struct libnet_icmpv4_hdr *icmp;
	int len;
	
	len = (ip->ip_hl * 4) + 8;

	icmp = (struct libnet_icmpv4_hdr *)(buf + LIBNET_IPV4_H);
	icmp->icmp_type = ICMP_SOURCEQUENCH;
	icmp->icmp_code = 0;
	memcpy((u_char *)icmp + LIBNET_ICMPV4_ECHO_H, (u_char *)ip, len);
	
	len += LIBNET_ICMPV4_ECHO_H;
	
	libnet_build_ipv4(LIBNET_IPV4_H + len, 0,
			  libnet_get_prand(LIBNET_PRu16), 0, 64, IPPROTO_ICMP,
			  0, ip->ip_dst.s_addr, ip->ip_src.s_addr,
			  (u_int8_t *) icmp, len, l, 0);
	
	if (libnet_write(l) != len)
		warn("write");
	
	fprintf(stderr, "%s > %s: icmp: source quench\n",
		libnet_addr2name4(ip->ip_dst.s_addr, 0),
		libnet_addr2name4(ip->ip_src.s_addr, 0));
}

static void
send_icmp_frag_needed(libnet_t *l, struct libnet_ipv4_hdr *ip)
{
	struct libnet_icmpv4_hdr *icmp;
	int len;

	len = (ip->ip_hl * 4) + 8;
	
	icmp = (struct libnet_icmpv4_hdr *)(buf + LIBNET_IPV4_H);
	icmp->icmp_type = ICMP_UNREACH;
	icmp->icmp_code = ICMP_UNREACH_NEEDFRAG;
	icmp->hun.frag.pad = 0;
	icmp->hun.frag.mtu = htons(MIN_MTU);
	memcpy((u_char *)icmp + LIBNET_ICMPV4_MASK_H, (u_char *)ip, len);

	len += LIBNET_ICMPV4_MASK_H;

	libnet_build_ipv4(LIBNET_IPV4_H + len, 4,
			  libnet_get_prand(LIBNET_PRu16), 0, 64, IPPROTO_ICMP,
			  0, ip->ip_dst.s_addr, ip->ip_src.s_addr,
			  (u_int8_t *) icmp, len, l, 0);
	
	if (libnet_write(l) != len)
		warn("write");
	
	fprintf(stderr, "%s > %s: icmp: ",
		libnet_addr2name4(ip->ip_dst.s_addr, 0),
		libnet_addr2name4(ip->ip_src.s_addr, 0));
	fprintf(stderr, "%s unreachable - need to frag (mtu %d)\n",
		libnet_addr2name4(ip->ip_src.s_addr, 0), MIN_MTU);
}

static void
tcp_nice_cb(u_char *user, const struct pcap_pkthdr *pcap, const u_char *pkt)
{
	struct libnet_ipv4_hdr *ip;
	struct libnet_tcp_hdr *tcp;
	int len;
	libnet_t *l;

	l = (libnet_t *)user;
	pkt += pcap_off;
	len = pcap->caplen - pcap_off;

	ip = (struct libnet_ipv4_hdr *)pkt;
	if (ip->ip_p != IPPROTO_TCP)
		return;
	
	tcp = (struct libnet_tcp_hdr *)(pkt + (ip->ip_hl << 2));
	if (tcp->th_flags & (TH_SYN|TH_FIN|TH_RST))
		return;
	
	if (ntohs(ip->ip_len) > (ip->ip_hl << 2) + (tcp->th_off << 2)) {
		if (Opt_icmp)
			send_icmp_source_quench(l, ip);
		if (Opt_win)
			send_tcp_window_advertisement(l, ip, tcp);
		if (Opt_pmtu)
			send_icmp_frag_needed(l, ip);
	}
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	int c;
	char *intf, *filter, ebuf[PCAP_ERRBUF_SIZE];
	char libnet_ebuf[LIBNET_ERRBUF_SIZE];
	libnet_t *l;
	pcap_t *pd;
	
	intf = NULL;
	
	while ((c = getopt(argc, argv, "i:AIMh?V")) != -1) {
		switch (c) {
		case 'i':
			intf = optarg;
			break;
		case 'A':
			Opt_win = 1;
			break;
		case 'I':
			Opt_icmp = 1;
			break;
		case 'M':
			Opt_pmtu = 1;
			break;
		default:
			usage();
			break;
		}
	}
	if (intf == NULL && (intf = pcap_lookupdev(ebuf)) == NULL)
		errx(1, "%s", ebuf);
	
	argc -= optind;
	argv += optind;
	
	if (argc == 0)
		usage();

	if ((Opt_win | Opt_icmp | Opt_pmtu) == 0)
		Opt_win = Opt_icmp = Opt_pmtu = 1;
	
	filter = copy_argv(argv);
	
	if ((pd = pcap_init(intf, filter, 128)) == NULL)
		errx(1, "couldn't initialize sniffing");

	if ((pcap_off = pcap_dloff(pd)) < 0)
		errx(1, "couldn't determine link layer offset");
	
	if ((l = libnet_init(LIBNET_RAW4, intf, libnet_ebuf)) == NULL)
		errx(1, "couldn't initialize sending");
	
	libnet_seed_prand(l);
	
	warnx("listening on %s [%s]", intf, filter);
	
	pcap_loop(pd, -1, tcp_nice_cb, (u_char *)l);
	
	/* NOTREACHED */
	
	exit(0);
}
