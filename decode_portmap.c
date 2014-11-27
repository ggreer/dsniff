/*
 * decode_portmap.c
 *
 * RPC portmap.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_portmap.c,v 1.8 2001/03/15 08:33:02 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <rpc/rpc.h>
#include <rpc/pmap_prot.h>

#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <nids.h>

#include "rpc.h"
#include "trigger.h"
#include "decode.h"

int
decode_portmap(u_char *buf, int len, u_char *obuf, int olen)
{
	XDR xdrs;
	struct rpc_msg msg;
	struct pmap *pm, pmap;
	struct xid_map *xm;
	int hdrlen;

	if ((hdrlen = rpc_decode(buf, len, &msg)) == 0)
		return (0);
	
	if (msg.rm_direction == CALL &&
	    msg.rm_call.cb_prog == PMAPPROG &&
	    msg.rm_call.cb_proc == PMAPPROC_GETPORT) {
		xdrmem_create(&xdrs, buf + hdrlen, len - hdrlen, XDR_DECODE);
		if (xdr_pmap(&xdrs, &pmap)) {
			if ((pm = malloc(sizeof(*pm))) != NULL) {
				*pm = pmap;
				xid_map_enter(msg.rm_xid, PMAPPROG, PMAPVERS,
					      PMAPPROC_GETPORT, (void *) pm);
			}
		}
		xdr_destroy(&xdrs);
	}
	else if (msg.rm_direction == REPLY &&
		 (xm = xid_map_find(msg.rm_xid)) != NULL) {
		if (msg.rm_reply.rp_stat == MSG_ACCEPTED &&
		    msg.acpted_rply.ar_stat == SUCCESS) {
			pm = (struct pmap *)xm->data;
			xdrmem_create(&xdrs, buf + hdrlen, len - hdrlen,
				      XDR_DECODE);
			if (xdr_u_long(&xdrs, &pm->pm_port)) {
				trigger_rpc(pm->pm_prog, pm->pm_prot,
					    pm->pm_port);
				trigger_rpc(pm->pm_prog, pm->pm_prot,
					    0 - (int) pm->pm_port);
			}
			xdr_destroy(&xdrs);
		}
		free(xm->data);
		memset(xm, 0, sizeof(*xm));
	}
	return (0);
}
