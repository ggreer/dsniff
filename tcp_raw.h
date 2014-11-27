/*
 * tcp_raw.h
 *
 * Raw (best-effort, half-duplex) TCP reassembly. Haaacccck.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: tcp_raw.h,v 1.5 2001/03/15 08:33:06 dugsong Exp $
 */

#ifndef TCP_RAW_H
#define TCP_RAW_H

typedef void (*tcp_raw_callback_t)(in_addr_t src, in_addr_t dst,
				   u_short sport, u_short dport,
				   u_char *buf, int len);

struct iovec   *tcp_raw_input(struct libnet_ipv4_hdr *ip,
			      struct libnet_tcp_hdr *tcp, int len);

void		tcp_raw_timeout(int timeout, tcp_raw_callback_t callback);

#endif /* TCP_RAW_H */
