/*
 * decode_postgresql.c
 *
 * PostgreSQL.
 *
 * Thanks to Eric Jackson <shinobi@monkey.org> for packet traces.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_postgresql.c,v 1.6 2001/03/15 08:33:02 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "decode.h"

#define STARTUP_PKTLEN	296

int
decode_postgresql(u_char *buf, int len, u_char *obuf, int olen)
{
	u_int32_t plen;
	u_char *p;
	char *db, *user;
	
	if (len < STARTUP_PKTLEN)
		return (0);
	
	obuf[0] = '\0';
	db = user = NULL;
	
	for (;;) {
		if (len < 4) break;
		plen = pntohl(buf);
		
		if (plen > len)	break;
		p = buf + 4;
		
		if (plen == STARTUP_PKTLEN) {
			if (pntohl(p) >> 16 == 2) {
				db = p + 4; db[63] = '\0';
				user = db + 64; user[31] = '\0';
			}
		}
		else if (db != NULL && user != NULL) {
			buf[plen - 1] = '\0';
			snprintf(obuf + strlen(obuf),
				 olen - strlen(obuf),
				 "%s\n%s\n%s\n", db, user, p);
			db = user = NULL;
		}
		buf += plen;
		len -= plen;
	}
	return (strlen(obuf));
}

