/*
 * decode_mmxp.c
 *
 * Meeting Maker.
 *
 * Thanks for Matt Power <mhpower@MIT.EDU> for his BUGTRAQ post
 * on Meeting Maker encryption, and for providing me with traffic traces.
 *
 * The encryption algorithm seems to be much simpler than what Matt
 * reversed - see below...
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 * 
 * $Id: decode_mmxp.c,v 1.8 2001/03/15 08:33:01 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <arpa/nameser.h>

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "buf.h"
#include "decode.h"

#define MM_SECRET	"Thisisastupidwasteoftimeandspace"

static u_char *mm_xor = MM_SECRET;

int
decode_mmxp(u_char *buf, int len, u_char *obuf, int olen)
{
	struct buf inbuf, outbuf;
	u_char *p, c;
	u_int32_t i;
	int encrypt;

	buf_init(&inbuf, buf, len);
	buf_init(&outbuf, obuf, len);

	while ((i = buf_index(&inbuf, "\x00\x00\x24\x55", 4)) != -1) {
		buf_skip(&inbuf, i + 4);

		if (buf_cmp(&inbuf, "\x7f\xff", 2) == 0)
			encrypt = 1;
		else if (buf_cmp(&inbuf, "\xff\xff", 2) == 0)
			encrypt = 0;
		else continue;

		buf_skip(&inbuf, 4);
		
		/* LPPPg? */
		if (buf_get(&inbuf, &i, sizeof(i)) < 0)
			break;

		i = ntohl(i);
		if (buf_skip(&inbuf, i + 4 + 4) < 0)
			continue;

		/* Server. */
		if (buf_get(&inbuf, &c, 1) != 1) break;
		if (buf_len(&inbuf) < c) break;
		
		buf_put(&outbuf, buf_ptr(&inbuf), c);
		buf_put(&outbuf, "\n", 1);
		buf_skip(&inbuf, c + 4);
		
		/* Username. */
		if (buf_get(&inbuf, &c, 1) != 1) break;
		if (buf_len(&inbuf) < c) break;
		
		buf_put(&outbuf, buf_ptr(&inbuf), c);
		buf_put(&outbuf, "\n", 1);
		buf_skip(&inbuf, c + 4);
	
		/* Password. */
		if (buf_get(&inbuf, &c, 1) != 1) break;
		if (buf_len(&inbuf) < c) break;

		p = buf_ptr(&inbuf);
		
		if (encrypt) {
			for (i = 0; i < c; i++)
				p[i] ^= mm_xor[i % (sizeof(MM_SECRET) - 1)];
		}
		buf_put(&outbuf, p, c);
		buf_put(&outbuf, "\n", 1);
	}
	buf_end(&outbuf);
		
	return (buf_len(&outbuf));
}
	
