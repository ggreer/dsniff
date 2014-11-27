/*
 * decode_yp.c
 *
 * RPC "Yellow Pee".
 *
 * Totally untested, i don't run YP. Let me know if this works. :-)
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_yp.c,v 1.6 2001/03/15 08:33:03 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <rpc/rpc.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/yppasswd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rpc.h"
#include "decode.h"

/* XXX - <rpcsvc/yppasswd.x> varies on different systems :-( */

struct my_passwd {
	char   *pw_name;
	char   *pw_passwd;
	int	pw_uid;
	int	pw_gid;
	char   *pw_gecos;
	char   *pw_dir;
	char   *pw_shell;
};

struct my_yppasswd {
	char   *oldpass;
	struct my_passwd newpw;
};

static bool_t
xdr_my_passwd(XDR *xdrs, struct my_passwd *objp)
{
	if (xdr_string(xdrs, &objp->pw_name, ~0) &&
	    xdr_string(xdrs, &objp->pw_passwd, ~0) &&
	    xdr_int(xdrs, &objp->pw_uid) &&
	    xdr_int(xdrs, &objp->pw_gid) &&
	    xdr_string(xdrs, &objp->pw_gecos, ~0) &&
	    xdr_string(xdrs, &objp->pw_dir, ~0) &&
	    xdr_string(xdrs, &objp->pw_shell, ~0))
		return (TRUE);

	return (FALSE);
}

static bool_t
xdr_my_yppasswd(XDR *xdrs, struct my_yppasswd *objp)
{
	if (xdr_string(xdrs, &objp->oldpass, ~0) &&
	    xdr_my_passwd(xdrs, &objp->newpw))
		return (TRUE);
	
	return (FALSE);
}

int
decode_yppasswd(u_char *buf, int len, u_char *obuf, int olen)
{
	struct rpc_msg msg;
	struct my_yppasswd yp;
	XDR xdrs;
	int hdrlen;
	
	if ((hdrlen = rpc_decode(buf, len, &msg)) == 0)
		return (0);

	obuf[0] = '\0';
	
	if (msg.rm_direction == CALL &&
	    msg.rm_call.cb_prog == YPPASSWDPROG &&
	    msg.rm_call.cb_proc == YPPASSWDPROC_UPDATE) {
		xdrmem_create(&xdrs, buf + hdrlen, len - hdrlen, XDR_DECODE);
		memset(&yp, 0, sizeof(yp));
		if (xdr_my_yppasswd(&xdrs, &yp)) {
			snprintf(obuf, olen,
				 "%s\n%s:%s:%d:%d:%s:%s:%s\n",
				 yp.oldpass, yp.newpw.pw_name,
				 yp.newpw.pw_passwd, yp.newpw.pw_uid,
				 yp.newpw.pw_gid, yp.newpw.pw_gecos,
				 yp.newpw.pw_dir, yp.newpw.pw_shell);
		}
		xdr_destroy(&xdrs);
	}
	return (strlen(obuf));
}

int
decode_ypserv(u_char *buf, int len, u_char *obuf, int olen)
{
	struct rpc_msg msg;
	struct xid_map *xm;
	char *domain;
	bool_t status;
	XDR xdrs;
	int hdrlen;
	
	if ((hdrlen = rpc_decode(buf, len, &msg)) == 0)
		return (0);

	obuf[0] = '\0';
	
	if (msg.rm_direction == CALL &&
	    msg.rm_call.cb_prog == YPPROG &&
	    msg.rm_call.cb_proc == YPPROC_DOMAIN) {
		xdrmem_create(&xdrs, buf + hdrlen, len - hdrlen, XDR_DECODE);
		domain = NULL;
		if (xdr_string(&xdrs, &domain, YPMAXDOMAIN)) {
			if ((domain = strdup(domain)) != NULL)
				xid_map_enter(msg.rm_xid, YPPROG, YPVERS,
					      YPPROC_DOMAIN, (void *) domain);
		}
		xdr_destroy(&xdrs);
	}
	else if (msg.rm_direction == REPLY &&
		 (xm = xid_map_find(msg.rm_xid)) != NULL) {
		if (msg.rm_reply.rp_stat == MSG_ACCEPTED &&
		    msg.acpted_rply.ar_stat == SUCCESS) {
			xdrmem_create(&xdrs, buf + hdrlen, len - hdrlen,
				      XDR_DECODE);
			if (xdr_bool(&xdrs, &status)) {
				if (status == TRUE)
					snprintf(obuf, olen, "%s\n",
						 (char *)xm->data);
			}
			xdr_destroy(&xdrs);
		}
		free(xm->data);
		memset(xm, 0, sizeof(*xm));
	}
	return (strlen(obuf));
}
