/*
 * decode_napster.c
 *
 * Napster. w00w00!
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_napster.c,v 1.6 2001/03/15 08:33:01 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "buf.h"
#include "decode.h"

int
decode_napster(u_char *buf, int len, u_char *obuf, int olen)
{
	struct buf inbuf, outbuf;
	u_short i, type;

	buf_init(&inbuf, buf, len);
	buf_init(&outbuf, obuf, olen);

	if (buf_get(&inbuf, &i, sizeof(i)) != sizeof(i))
		return (0);

	i = pletohs(&i);

	if (buf_get(&inbuf, &type, sizeof(type)) != sizeof(type))
		return (0);

	type = pletohs(&type);

	if (type != 2 || i > buf_len(&inbuf))
		return (0);
	
	buf_put(&outbuf, buf_ptr(&inbuf), i);
	buf_put(&outbuf, "\n", 1);
	
	buf_end(&outbuf);
	
	return (buf_len(&outbuf));
}

