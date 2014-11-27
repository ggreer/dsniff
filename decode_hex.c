/*
 * decode_hex.c
 *
 * Hex dump, for debugging.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_hex.c,v 1.5 2001/03/15 08:32:59 dugsong Exp $
 */

#include "config.h"

#include <sys/param.h>
#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "buf.h"
#include "decode.h"

/* adapted from OpenBSD tcpdump: dump the buffer in emacs-hexl format */

int
decode_hex(u_char *buf, int len, u_char *obuf, int olen)
{
	struct buf inbuf, outbuf;
	u_int i, j, k;
	u_char c;

	buf_init(&inbuf, buf, len);
	buf_init(&outbuf, obuf, olen);
	
	while ((i = buf_len(&inbuf)) > 0) {
		i = i < 16 ? i : 16;
		k = buf_tell(&inbuf);
		
		buf_putf(&outbuf, "  %04x: ", k);
		
		for (j = 0; j < i; j++) {
			buf_get(&inbuf, &c, 1);
			buf_putf(&outbuf, "%02x", (u_int)c);
			if ((j % 2) == 1)
				buf_put(&outbuf, " ", 1);
		}
		for (; j < 16; j++) {
			buf_put(&outbuf, "   ", (j % 2) + 2);
		}
		buf_put(&outbuf, " ", 1);

		buf_seek(&inbuf, k, SEEK_SET);
		
		for (j = 0; j < i; j++) {
			buf_get(&inbuf, &c, 1);
			c = isprint(c) ? c : '.';
			buf_putf(&outbuf, "%c", c);
		}
		buf_put(&outbuf, "\n", 1);
	}
	buf_end(&outbuf);
	
	return (buf_len(&outbuf));
}
