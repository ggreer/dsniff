/*
 * pcaputil.h
 *
 * pcap utility routines.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: pcaputil.h,v 1.2 2001/03/15 08:33:06 dugsong Exp $
 */

#ifndef PCAPUTIL_H
#define PCAPUTIL_H

pcap_t *pcap_init(char *intf, char *filter, int snaplen);

int	pcap_dloff(pcap_t *pd);

char   *copy_argv(char **argv);

#endif /* PCAPUTIL_H */
