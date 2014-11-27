/*
 * rpc.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: rpc.c,v 1.8 2001/03/15 08:33:04 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <rpc/rpc.h>

#include <stdio.h>
#include <string.h>

#include "decode.h"
#include "rpc.h"

#define XIDMAPSIZE	64

static struct xid_map	xid_maps[XIDMAPSIZE];

static int		xid_map_next = 0;
static int		xid_map_hint = 0;

/* xid_map adapted from tcpdump's print-nfs.c */

void
xid_map_enter(u_int32_t xid, u_int32_t prog, u_int32_t vers,
	      u_int32_t proc, void *data)
{
	struct xid_map *mp;
	
	mp = &xid_maps[xid_map_next];
	
	if (++xid_map_next >= XIDMAPSIZE)
		xid_map_next = 0;
	
	mp->xid = xid;
	mp->prog = prog;
	mp->vers = vers;
	mp->proc = proc;
	mp->data = data;
}

struct xid_map *
xid_map_find(int xid)
{
	struct xid_map *mp;
	int i;
	
	/* Start searching from where we last left off. */
	i = xid_map_hint;
	do {
		mp = &xid_maps[i];
		if (mp->xid == xid) {
			/* match */
			xid_map_hint = i;
			return (mp);
		}
		if (++i >= XIDMAPSIZE)
			i = 0;
	} while (i != xid_map_hint);
	
	return (NULL);
}

int
rpc_decode(u_char *buf, int len, struct rpc_msg *msg)
{
	XDR xdrs;
	u_int32_t fraghdr;
	u_char *p, *tmp;
	int stat, tmplen;

	if (len < 20)
		return (0);
	
	p = buf + 4;

	/* If not recognizably RPC, try TCP record defragmentation */
	if (pntohl(p) != CALL && pntohl(p) != REPLY) {
		tmp = buf;
		tmplen = 0;
		
		for (;;) {
			fraghdr = pntohl(tmp);
			
			if (FRAGLEN(fraghdr) + 4 > len)
				return (0);
			
			len -= 4;
			memmove(tmp, tmp + 4, len);
			tmplen += FRAGLEN(fraghdr);
			
			if (LASTFRAG(fraghdr))
				break;
			
			tmp += FRAGLEN(fraghdr);
			len -= FRAGLEN(fraghdr);
			
			if (len < 4)
				return (0);
		}
		len = tmplen;
	}
	/* Decode RPC message. */
	memset(msg, 0, sizeof(*msg));
	
	if (ntohl(((struct rpc_msg *)buf)->rm_direction) == CALL) {
		xdrmem_create(&xdrs, buf, len, XDR_DECODE);
		
		if (!xdr_callmsg(&xdrs, msg)) {
			xdr_destroy(&xdrs);
			return (0);
		}
	}
	else if (ntohl(((struct rpc_msg *)buf)->rm_direction) == REPLY) {
		msg->acpted_rply.ar_results.proc = (xdrproc_t) xdr_void;
		xdrmem_create(&xdrs, buf, len, XDR_DECODE);
		
		if (!xdr_replymsg(&xdrs, msg)) {
			xdr_destroy(&xdrs);
			return (0);
		}
	}
	stat = xdr_getpos(&xdrs);
	xdr_destroy(&xdrs);
	
	return (stat);
}

