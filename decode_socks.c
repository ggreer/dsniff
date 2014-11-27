/*
 * decode_socks.c
 *
 * NEC SOCKS.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_socks.c,v 1.4 2001/03/15 08:33:02 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <strlcat.h>

#include "decode.h"

int
decode_socks(u_char *buf, int len, u_char *obuf, int olen)
{
	u_char *p;
	int i, n;
	
	p = buf;
	
	if (len < 4 || *p++ != 5)		/* SOCKS version */
		return (0);
	
	if ((n = *p++) > len - 5)		/* nmethods */
		return (0);
	
	for (i = 0; i < n; i++)			/* USERNAME/PASSWORD method? */
		if (p[i] == 2) break;
	
	if (i == n) return (0);
	
	p += n;
	if (*p++ != 1) return (0);		/* USERNAME/PASSWORD version */
	
	n = *p++;
	if (n > len - (p - buf))
		return (0);
	
	memmove(p - 1, p, n); p[n - 1] = '\0';
	snprintf(obuf, olen, "%s ", p - 1);
	p += n;
	
	n = *p++;
	if (n > len - (p - buf))
		return (0);
	
	memmove(p - 1, p, n); p[n - 1] = '\0';
	strlcat(obuf, p - 1, olen);
	strlcat(obuf, "\n", olen);
	
	return (strlen(obuf));
}

