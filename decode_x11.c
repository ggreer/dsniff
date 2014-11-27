/*
 * decode_x11.c
 *
 * X11.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_x11.c,v 1.4 2001/03/15 08:33:03 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <strlcat.h>
#include <strlcpy.h>

#include "decode.h"

int
decode_x11(u_char *buf, int len, u_char *obuf, int olen)
{
	char *p, *q;
	int i;
	
	p = buf + 12;
	
	if (strncmp(p, "MIT-MAGIC-COOKIE-1", 18) != 0 || len < 36)
		return (0);
	
	strlcpy(obuf, "MIT-MAGIC-COOKIE-1 ", olen);
	
	p += 20;
	len -= 20;
	q = obuf + 19;
	
	for (i = 0; i < 16 && i < len; i++)
		sprintf(q + (i * 2), "%.2x", (u_char)p[i]);
	strlcat(obuf, "\n", olen);
	
	return (strlen(obuf));
}

