/*
 * decode_oracle.c
 *
 * Oracle SQL*Net v2/Net8.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_oracle.c,v 1.6 2001/03/15 08:33:01 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "decode.h"

/* XXX - dag nasty. anyone have protocol specs? */
int
decode_oracle(u_char *buf, int len, u_char *obuf, int olen)
{
	u_char *p, *q;
	u_short i, j;
	int gotauth = 0;
	
	p = buf;
	
	i = pntohs(p);
	if (i >= len) return (0);

	if (i < 60) {		/* XXX - skip unknown "empty" packet */
		p += i;
		i = pntohs(p);
		if (p + i > buf + len) return (0);
	}
	/* Save TNS connect string. */
	p[i] = '\0';
	for (q = p + i; q > p && q[-1] != '\0'; q--)
		;
	snprintf(obuf, olen, "%s\n", q);
	p += i;
	
	/* XXX - skip initial username message. */
	if ((p = bufbuf(p, len, "(TNS V", 6)) == NULL) return (0);
	if ((i = len - (p - buf)) <= 0) return (0);
	if ((p = memchr(p, ')', i)) == NULL) return (0);
	
	/* Parse auth messages. */
	for (p++; p - buf < len; p += i) {
		i = pntohs(p);
		if (p + i > buf + len || i < 120)
			break;
		
		if (memcmp(p + 4, "\x06\x00\x00\x00\x00\x00\x03\x3a", 8) != 0)
			continue;
		
		for (q = p + i; q > p && q[-1] != '\0'; q--)
			;
		j = pntohs(p + 19);
		if (q + j > buf + len)
			return (0);
		q[j] = '\0';

		j = strlen(obuf);
		snprintf(obuf + j, olen + j, "%s\n", p + 117);
		gotauth++;
	}
	return (gotauth ? strlen(obuf) : 0);
}
