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
	*((in_addr_t *)mac) = libnet_get_prand(LIBNET_PRu32);
	*((u_short *)(mac + 4)) = libnet_get_prand(LIBNET_PRu16);
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	int c, i;
	struct libnet_link_int *llif;
	char pcap_ebuf[PCAP_ERRBUF_SIZE];
	char libnet_ebuf[LIBNET_ERRBUF_SIZE];
	u_char sha[ETHER_ADDR_LEN], tha[ETHER_ADDR_LEN];
	in_addr_t src, dst;
	u_short sport, dport;
	u_int32_t seq;
	libnet_t *l;
	
	while ((c = getopt(argc, argv, "vs:d:e:x:y:i:n:h?V")) != -1) {
		switch (c) {
		case 'v':
			break;
		case 's':
			Src = libnet_name2addr4(l, optarg, 0);
			break;
		case 'd':
			Dst = libnet_name2addr4(l, optarg, 0);
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
	
	if (!Intf && (Intf = pcap_lookupdev(pcap_ebuf)) == NULL)
		errx(1, "%s", pcap_ebuf);
	
	if ((l = libnet_init(LIBNET_LINK, Intf, libnet_ebuf)) == NULL)
		errx(1, "%s", libnet_ebuf);
	
	libnet_seed_prand(l);
	
	for (i = 0; i != Repeat; i++) {
		
		gen_mac(sha);
		
		if (Tha == NULL) gen_mac(tha);
		else memcpy(tha, Tha, sizeof(tha));
		
		if (Src != 0) src = Src;
		else src = libnet_get_prand(LIBNET_PRu32);
		
		if (Dst != 0) dst = Dst;
		else dst = libnet_get_prand(LIBNET_PRu32);
		
		if (Sport != 0) sport = Sport;
		else sport = libnet_get_prand(LIBNET_PRu16);
		
		if (Dport != 0) dport = Dport;
		else dport = libnet_get_prand(LIBNET_PRu16);

		seq = libnet_get_prand(LIBNET_PRu32);
		
		libnet_build_tcp(sport, dport, seq, 0, TH_SYN, 512,
				 0, 0, LIBNET_TCP_H, NULL, 0, l, 0);
		
		libnet_build_ipv4(LIBNET_TCP_H, 0,
				  libnet_get_prand(LIBNET_PRu16), 0, 64,
				  IPPROTO_TCP, 0, src, dst, NULL, 0, l, 0);
		
		libnet_build_ethernet(tha, sha, ETHERTYPE_IP, NULL, 0, l, 0);
		
		if (libnet_write(l) < 0)
			errx(1, "write");

		libnet_clear_packet(l);

		fprintf(stderr, "%s ",
			ether_ntoa((struct ether_addr *)sha));
		fprintf(stderr, "%s %s.%d > %s.%d: S %u:%u(0) win 512\n",
			ether_ntoa((struct ether_addr *)tha),
			libnet_addr2name4(Src, 0), sport,
			libnet_addr2name4(Dst, 0), dport, seq, seq);
	}
	exit(0);
}
