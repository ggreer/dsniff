/*
 * macof.c
 *
 * C port of macof-1.1 from the Perl Net::RawIP distribution.
 * Tests network devices by flooding local network with MAC-addresses.
 *
 * Perl macof originally written by Ian Vitek <ian.vitek@infosec.se>.
 *
 * Copyright (c) 1999 Dug Song <dugsong@monkey.org>
 *
 * $Id: macof.c,v 1.15 2001/03/15 08:33:04 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <err.h>
#include <libnet.h>
#include <pcap.h>

#include "version.h"

extern char *ether_ntoa(struct ether_addr *);
extern struct ether_addr *ether_aton(char *);

in_addr_t	Src = 0;
in_addr_t	Dst = 0;
u_char *Tha = NULL;
u_short	Dport = 0;
u_short Sport = 0;
char   *Intf = NULL;
int	Repeat = -1;

static void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: macof [-s src] [-d dst] [-e tha] [-x sport] [-y dport]"
		"\n             [-i interface] [-n times]\n");
	exit(1);
}

static void
gen_mac(u_char *mac)
{
	*((in_addr_t *)mac) = libnet_get_prand(PRu32);
	*((u_short *)(mac + 4)) = libnet_get_prand(PRu16);
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	int c, i;
	struct libnet_link_int *llif;
	char ebuf[PCAP_ERRBUF_SIZE];
	u_char sha[ETHER_ADDR_LEN], tha[ETHER_ADDR_LEN];
	in_addr_t src, dst;
	u_short sport, dport;
	u_int32_t seq;
	u_char pkt[ETH_H + IP_H + TCP_H];
	
	while ((c = getopt(argc, argv, "vs:d:e:x:y:i:n:h?V")) != -1) {
		switch (c) {
		case 'v':
			break;
		case 's':
			Src = libnet_name_resolve(optarg, 0);
			break;
		case 'd':
			Dst = libnet_name_resolve(optarg, 0);
			break;
		case 'e':
			Tha = (u_char *)ether_aton(optarg);
			break;
		case 'x':
			Sport = atoi(optarg);
			break;
		case 'y':
			Dport = atoi(optarg);
			break;
		case 'i':
			Intf = optarg;
			break;
		case 'n':
			Repeat = atoi(optarg);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	
	if (argc != 0)
		usage();
	
	if (!Intf && (Intf = pcap_lookupdev(ebuf)) == NULL)
		errx(1, "%s", ebuf);
	
	if ((llif = libnet_open_link_interface(Intf, ebuf)) == 0)
		errx(1, "%s", ebuf);
	
	libnet_seed_prand();
	
	for (i = 0; i != Repeat; i++) {
		
		gen_mac(sha);
		
		if (Tha == NULL) gen_mac(tha);
		else memcpy(tha, Tha, sizeof(tha));
		
		if (Src != 0) src = Src;
		else src = libnet_get_prand(PRu32);
		
		if (Dst != 0) dst = Dst;
		else dst = libnet_get_prand(PRu32);
		
		if (Sport != 0) sport = Sport;
		else sport = libnet_get_prand(PRu16);
		
		if (Dport != 0) dport = Dport;
		else dport = libnet_get_prand(PRu16);

		seq = libnet_get_prand(PRu32);
		
		libnet_build_ethernet(tha, sha, ETHERTYPE_IP, NULL, 0, pkt);
		
		libnet_build_ip(TCP_H, 0, libnet_get_prand(PRu16), 0, 64,
				IPPROTO_TCP, src, dst, NULL, 0, pkt + ETH_H);
		
		libnet_build_tcp(sport, dport, seq, 0, TH_SYN, 512,
				 0, NULL, 0, pkt + ETH_H + IP_H);
		
		libnet_do_checksum(pkt + ETH_H, IPPROTO_IP, IP_H);
		libnet_do_checksum(pkt + ETH_H, IPPROTO_TCP, TCP_H);
		
		if (libnet_write_link_layer(llif, Intf, pkt, sizeof(pkt)) < 0)
			errx(1, "write");

		fprintf(stderr, "%s ",
			ether_ntoa((struct ether_addr *)sha));
		fprintf(stderr, "%s %s.%d > %s.%d: S %u:%u(0) win 512\n",
			ether_ntoa((struct ether_addr *)tha),
			libnet_host_lookup(Src, 0), sport,
			libnet_host_lookup(Dst, 0), dport, seq, seq);
	}
	exit(0);
}
