/*
 * decode_ftp.c
 *
 * File Transfer Protocol.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_ftp.c,v 1.7 2001/03/15 08:32:59 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "options.h"
#include "buf.h"
#include "decode.h"

int
decode_ftp(u_char *buf, int len, u_char *obuf, int olen)
{
	struct buf *line, inbuf, outbuf;
	int i, n;

	if ((len = strip_telopts(buf, len)) == 0)
		return (0);

	buf_init(&inbuf, buf, len);
	buf_init(&outbuf, obuf, olen);

	if (!buf_isascii(&inbuf))
		return (0);

	n = 0;
	
	while ((i = buf_index(&inbuf, "\n", 1)) != -1) {
		line = buf_tok(&inbuf, NULL, i);
		buf_skip(&inbuf, 1);

		if (i > 0 && line->base[i - 1] == '\r')
			line->end--;
		line->base[line->end] = '\0';

		if (strncasecmp(buf_ptr(line), "USER ", 5) == 0 ||
		    strncasecmp(buf_ptr(line), "ACCT ", 5) == 0 ||
		    strncasecmp(buf_ptr(line), "PASS ", 5) == 0) {
			buf_putf(&outbuf, "%s\n", buf_ptr(line));
			n++;
		}
	}
	if (n < 2) return (0);

	buf_end(&outbuf);
	
	return (buf_len(&outbuf));
}

