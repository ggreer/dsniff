/*
 * rpc.h
 *
 * RPC utility routines.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: rpc.h,v 1.4 2001/03/15 08:33:06 dugsong Exp $
 */

#ifndef RPC_H
#define RPC_H

#define FRAGLEN(x)	(x & 0x7fffffff)
#define LASTFRAG(x)	(x & (1 << 31))

struct xid_map {
	u_int32_t		xid;
	u_int32_t		prog;
	u_int32_t		vers;
	u_int32_t		proc;
	void	       *data;
};

int	rpc_decode(u_char *buf, int len, struct rpc_msg *msg);

void	xid_map_enter(u_int32_t xid, u_int32_t prog, u_int32_t vers,
		      u_int32_t proc, void *data);

struct xid_map *xid_map_find(int xid);

#endif /* RPC_H */

