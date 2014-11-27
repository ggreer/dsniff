/*
 * decode_citrix.c
 *
 * Citrix ICA.
 *
 * http://www.securityfocus.com/templates/archive.pike?list=1&date=200 \
 * 0-04-15&msg=Pine.BSO.4.20.0003290949280.2640-100000@naughty.monkey.org
 *
 * Thanks to Jeremie Kass <jeremie@monkey.org> for providing me with
 * traffic traces.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_citrix.c,v 1.5 2001/03/15 08:32:59 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "buf.h"
#include "decode.h"

static u_char ica_magic[] = { 0x32, 0x26, 0x85, 0x92, 0x58 };

int
decode_citrix(u_char *buf, int len, u_char *obuf, int olen)
{
	struct buf inbuf, outbuf;
	u_char key, c, t[2];
	int i;
	
	buf_init(&inbuf, buf, len);
	buf_init(&outbuf, obuf, olen);
	
	while ((i = buf_index(&inbuf, ica_magic, sizeof(ica_magic))) >= 0) {
		buf_skip(&inbuf, i);
		
		if (buf_len(&inbuf) < 60)
			break;
		
		buf_skip(&inbuf, 17);
		
		if (buf_get(&inbuf, &key, 1) != 1)
			break;
		
		buf_skip(&inbuf, 42);
		
		if (buf_get(&inbuf, &c, 1) != 1)
			break;

		c ^= ('C' | key);
		
		buf_put(&outbuf, &c, 1);
		
		i = 0;
		while (buf_get(&inbuf, t, 2) == 2) {
			c = t[0] ^ t[1] ^ key;
			
			if (c == '\0') {
				buf_put(&outbuf, "\n", 1);
				if (++i > 2) break;
			}
			buf_put(&outbuf, &c, 1);
		}
	}
	buf_end(&outbuf);
	
	return (buf_len(&outbuf));
}
