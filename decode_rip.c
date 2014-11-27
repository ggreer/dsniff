/*
 * decode_rip.c
 *
 * Routing Information Protocol.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_rip.c,v 1.4 2001/03/15 08:33:02 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "decode.h"

int
decode_rip(u_char *buf, int len, u_char *obuf, int olen)
{
	if (len < 21)
		return (0);
	
	/* Version 2 simple password authentication. */
	if (buf[1] != 2 || memcmp(buf + 4, "\xff\xff\x00\x02", 4) != 0)
		return (0);
	
	buf[20] = '\0';
	
	return (snprintf(obuf, olen, "%s\n", buf + 20));
}
  
