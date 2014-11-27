/*
 * trigger.h
 *
 * Trigger interface.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: trigger.h,v 1.5 2001/03/15 08:33:06 dugsong Exp $
 */

#ifndef TRIGGER_H
#define TRIGGER_H

#define TRIGGER_TCP_RAW_TIMEOUT		30

void	trigger_init_list(char *list);
void	trigger_init_magic(char *filename);
void	trigger_init_services(char *filename);

void	trigger_dump(void);

int	trigger_set_ip(int proto, char *name);
int	trigger_set_udp(int port, char *name);
int	trigger_set_tcp(int port, char *name);
int	trigger_set_rpc(int program, char *name);

void	trigger_ip(struct libnet_ipv4_hdr *ip);
void	trigger_udp(struct libnet_ipv4_hdr *ip);
void	trigger_tcp(struct tcp_stream *ts, void **conn_save);
void	trigger_tcp_raw(struct libnet_ipv4_hdr *ip);
void	trigger_tcp_raw_timeout(int signal);
void	trigger_rpc(int program, int proto, int port);

#endif /* TRIGGER_H */

