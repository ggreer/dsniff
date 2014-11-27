/*
 * decode_vrrp.c
 *
 * Virtual Router Redundancy Protocol.
 *
 * Copyright (c) 2000 Eric Jackson <ericj@monkey.org>
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_vrrp.c,v 1.5 2001/03/15 08:33:03 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "buf.h"
#include "decode.h"

struct vrrp_header {
	u_char	vr_vers;	/* Version */
	u_char	vr_vrid;	/* Virtual Router ID */
	u_char	vr_prio;	/* Router Priority */
	u_char	vr_naddr;	/* # of addresses */
	u_char	vr_auth;	/* Type of Authentication */
	u_char	vr_advr;	/* ADVERTISEMENT Interval */
	u_short	vr_cksum;	/* Checksum */
	/* vr_naddr * 4 # of addresses */
};
#define VRRP_AUTH_NONE		0
#define VRRP_AUTH_SIMPLE	1
#define VRRP_AUTH_AH		2

#define VRRP_AUTH_DATA_LEN	8

int
decode_vrrp(u_char *buf, int len, u_char *obuf, int olen)
{
	struct buf *b, inbuf, outbuf;
	struct vrrp_header *vrrp;

	buf_init(&inbuf, buf, len);
	buf_init(&outbuf, obuf, olen);
	
	vrrp = (struct vrrp_header *)buf_ptr(&inbuf);
	
	if (buf_len(&inbuf) < sizeof(*vrrp))
		return (0);
	
	/* We only care about VRRP_AUTH_SIMPLE */
	if (ntohs(vrrp->vr_auth) != VRRP_AUTH_SIMPLE)
		return (0);
	
	/* XXX - probably want to verify checksum */
	
	/* Forward to Authentication Data */
	buf_skip(&inbuf, sizeof(*vrrp) + 8 + (vrrp->vr_naddr * 4));

	if ((b = buf_tok(&inbuf, NULL, VRRP_AUTH_DATA_LEN)) == NULL)
		return (0);
	
	buf_put(&outbuf, buf_ptr(b), buf_len(b));
	buf_put(&outbuf, "\n", 1);
	buf_end(&outbuf);
	
	return (buf_len(&outbuf));
}
