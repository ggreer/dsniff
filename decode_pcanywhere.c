/*
 * decode_pcanywhere.c
 *
 * Symantec pcAnywhere.
 *
 * Thanks to Pascal Longpre <longprep@HOTMAIL.COM> for his BUGTRAQ post
 * on pcAnywhere encryption, and for providing me with traffic traces.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_pcanywhere.c,v 1.7 2001/03/15 08:33:01 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "buf.h"
#include "decode.h"

int
decode_pcanywhere(u_char *buf, int len, u_char *obuf, int olen)
{
	struct buf *word, inbuf, outbuf;
	u_char *p, c;
	int i;

	buf_init(&inbuf, buf, len);
	buf_init(&outbuf, obuf, olen);

	/* Skip leading zero bytes. */
	while (buf_get(&inbuf, &c, 1) == 1) {
		if (c != 0) break;
	}
	/* Version 7, no encryption */
	if (c < 0x0f && c != 0x06 /* jic */) {
		while ((word = buf_tok(&inbuf, "\r", 1)) != NULL) {
			if (buf_ptr(word)[0] == 0x6f)
				break;
			buf_putf(&outbuf, "%.*s\n",
				 buf_len(word), buf_ptr(word));
		}
	}
	/* Version 9, encrypted */
	else {
		/* Skip optional \x6f command packets. */
		while ((i = buf_index(&inbuf, "\x06", 1)) >= 0) {
			buf_skip(&inbuf, i);
			if (buf_len(&inbuf) > 2 && buf_ptr(&inbuf)[1] != 0xff)
				break;
			buf_skip(&inbuf, 2);
		}
		/* Parse \x06 auth packets. */
		while (buf_cmp(&inbuf, "\x06", 1) == 0) {
			buf_skip(&inbuf, 1);

			if (buf_get(&inbuf, &c, 1) != 1)
				break;
			
			if (buf_len(&inbuf) < c)
				break;

			p = buf_ptr(&inbuf);
			buf_skip(&inbuf, c);
			
			for (i = c - 1; i > 0; i--) {
				p[i] = p[i - 1] ^ p[i] ^ (i - 1);
			}
			p[0] ^= 0xab;
			
			buf_putf(&outbuf, "%.*s\n", c, p);
		}
	}
	buf_end(&outbuf);
		
	return (buf_len(&outbuf));
}

