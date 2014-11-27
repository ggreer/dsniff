/*
 * decode_mountd.c
 *
 * RPC mountd.
 *
 * Outputs filehandle in nfsshell format. :-)
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_mountd.c,v 1.7 2001/03/15 08:33:01 dugsong Exp $
 */

#include "config.h"

#include <sys/param.h>
#include <sys/types.h>
#include <rpc/rpc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"
#include "mount.h"
#include "rpc.h"
#include "decode.h"

int
decode_mountd(u_char *buf, int len, u_char *obuf, int olen)
{
	XDR xdrs;
	struct buf outbuf;
	struct rpc_msg msg;
	struct xid_map *xm;
	struct fhstatus fhstat;
	char *p, *dir;
	int i, hdrlen;

	buf_init(&outbuf, obuf, olen);
	
	if ((hdrlen = rpc_decode(buf, len, &msg)) == 0)
		return (0);

	if (msg.rm_direction == CALL &&
	    msg.rm_call.cb_prog == MOUNTPROG &&
	    msg.rm_call.cb_proc == MOUNTPROC_MNT) {
		xdrmem_create(&xdrs, buf + hdrlen, len - hdrlen, XDR_DECODE);
		dir = NULL;
		if (xdr_string(&xdrs, &dir, MAXPATHLEN)) {
			xid_map_enter(msg.rm_xid, MOUNTPROG, MOUNTVERS,
				      MOUNTPROC_MNT, (void *) dir);
		}
		xdr_destroy(&xdrs);
	}
	else if (msg.rm_direction == REPLY &&
		 (xm = xid_map_find(msg.rm_xid)) != NULL) {
		if (msg.rm_reply.rp_stat == MSG_ACCEPTED &&
		    msg.acpted_rply.ar_stat == SUCCESS) {
			xdrmem_create(&xdrs, buf + hdrlen, len - hdrlen,
				      XDR_DECODE);
			if (xdr_fhstatus(&xdrs, &fhstat)) {
				if (fhstat.fhs_status == 0) {
					buf_putf(&outbuf, "%s [",
						 (char *)xm->data);
					
					p = fhstat.fhstatus_u.fhs_fhandle;
					
					for (i = 0; i < FHSIZE; i++) {
						buf_putf(&outbuf, "%.2x ",
							 p[i] & 0xff);
					}
					buf_put(&outbuf, "]\n", 2);
				}
			}
			xdr_destroy(&xdrs);
		}
		free(xm->data);
		memset(xm, 0, sizeof(*xm));
	}
	buf_end(&outbuf);
	
	return (buf_len(&outbuf));
}
