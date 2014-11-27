/*
 * decode_aim.c
 *
 * AOL Instant Messenger (and ICQ2000).
 * 
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_aim.c,v 1.5 2001/03/15 08:32:59 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "hex.h"
#include "buf.h"
#include "decode.h"

struct flap {
	u_char	start;
	u_char	channel;
	u_short	seqnum;
	u_short	datalen;
};

static char *aim_xor1 = "Tic/Toc";

static u_char aim_xor2[] = {
	0xf3, 0x26, 0x81, 0xc4, 0x39, 0x86, 0xdb, 0x92,
	0x71, 0xa3, 0xb9, 0xe6, 0x53, 0x7a, 0x95, 0x7c
};

int
decode_aim(u_char *buf, int len, u_char *obuf, int olen)
{
	struct buf *msg, inbuf, outbuf;
	struct flap *flap;
	u_char c, *p;
	int i, j;

	buf_init(&inbuf, buf, len);
	buf_init(&outbuf, obuf, olen);

	if (buf_cmp(&inbuf, "FLAPON\r\n\r\n", 10) == 0)
		buf_skip(&inbuf, 10);

	while (buf_len(&inbuf) > sizeof(*flap)) {
		flap = (struct flap *)buf_ptr(&inbuf);
		flap->datalen = ntohs(flap->datalen);

		i = sizeof(*flap) + flap->datalen;

		if ((msg = buf_tok(&inbuf, NULL, i)) == NULL)
			break;

		buf_skip(msg, sizeof(*flap));

		if (buf_cmp(msg, "toc_signon ", 11) == 0) {
			msg->base[msg->end - 1] = '\0';
			p = buf_ptr(msg);
			
			for (i = 0; i < 4; i++) {
				if ((j = strcspn(p, " ")) > 0)
					p += (j + 1);
			}
			if (strtok(p, " ") == NULL)
				continue;

			buf_putf(&outbuf, "%s ", buf_ptr(msg));
			
			i = strlen(p);
			j = hex_decode(p, i, p, i);

			for (i = 0; i < j; i++)
				p[i] = p[i] ^ aim_xor1[i % 7];
			p[i] = '\0';

			buf_putf(&outbuf, "[%s]\n", p);
		}
		else if (flap->start == 0x2a && flap->channel == 0x01 &&
			 buf_cmp(msg, "\x00\x00\x00\x01", 4) == 0) {
			buf_skip(msg, 7);
			
			buf_get(msg, &c, 1);
			p = buf_ptr(msg);

			if (c == 0 || buf_skip(msg, c + 3) < 0)
				continue;

			p[c] = '\0';
			
			buf_get(msg, &c, 1);

			if (buf_len(msg) < c + 1)
				continue;

			buf_putf(&outbuf, "%s\n", p);
			
			p = buf_ptr(msg);

			for (i = 0; i < c; i++) {
				p[i] = p[i] ^ aim_xor2[i % sizeof(aim_xor2)];
			}
			p[i] = '\0';
			
			buf_putf(&outbuf, "%s\n", p);
			
			break;
		}		
	}
	buf_end(&outbuf);
	
	return (buf_len(&outbuf));
}
