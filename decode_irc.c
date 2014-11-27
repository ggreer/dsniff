/*
 * decode_irc.c
 *
 * Internet Relay Chat.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_irc.c,v 1.6 2001/03/15 08:33:01 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "buf.h"
#include "decode.h"

int
decode_irc(u_char *buf, int len, u_char *obuf, int olen)
{
	struct buf *line, inbuf, outbuf;
	int i, got_auth;

	buf_init(&inbuf, buf, len);
	buf_init(&outbuf, obuf, olen);
	got_auth = 0;

	while ((i = buf_index(&inbuf, "\n", 1)) != -1) {
		line = buf_tok(&inbuf, NULL, i);
		buf_skip(&inbuf, 1);
		
		if (i > 0 && line->base[i - 1] == '\r')
			line->end--;
		line->base[line->end] = '\0';

		if (buf_cmp(&inbuf, ";", 1) == 0) {
			if ((i = buf_index(line, " ", 1)) < 0)
				continue;
			buf_skip(line, i + 1);
		}
		if (buf_cmp(line, "USER ", 5) == 0 ||
		    buf_cmp(line, "NICK ", 5) == 0) {
			buf_rewind(line);
			buf_putf(&outbuf, "%s\n", buf_ptr(line));
		}
		else if (buf_cmp(line, "PASS ", 5) == 0 ||
			 buf_cmp(line, "OPER ", 5) == 0) {
			buf_rewind(line);
			buf_putf(&outbuf, "%s\n", buf_ptr(line));
			got_auth = 1;
		}
		else if (buf_cmp(line, "MODE ", 5) == 0 &&
			 buf_index(line, " +k ", 4) != -1) {
			buf_rewind(line);
			buf_putf(&outbuf, "%s\n", buf_ptr(line));
			got_auth = 1;
		}
		else if (buf_cmp(line, "JOIN ", 5) == 0) {
			buf_skip(line, 5);
			if ((i = buf_index(line, " ", 1)) < 0)
				continue;
			buf_skip(line, i + 1);
			if (buf_len(line) < 1)
				continue;
			buf_rewind(line);
			buf_putf(&outbuf, "%s\n", buf_ptr(line));
			got_auth = 1;
		}
	}
	buf_end(&outbuf);
	
	return (got_auth ? buf_len(&outbuf) : 0);
}
