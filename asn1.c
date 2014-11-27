/*
 * asn1.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: asn1.c,v 1.4 2001/03/15 08:32:58 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <arpa/nameser.h>

#include <unistd.h>

#include "buf.h"
#include "asn1.h"

int
asn1_type(buf_t buf)
{
	u_char c;

	if (buf_get(buf, &c, 1) != 1)
		return (-1);

	return (c & 0x1f);
}

int
asn1_len(buf_t buf)
{
	u_char *p, c;
	int num;

	if (buf_get(buf, &c, 1) != 1)
		return (-1);

	if (c >= 128) {
		c &= ~128;
		p = buf_ptr(buf);
		
		if (buf_skip(buf, c) < 0)
			return (-1);

		switch (c) {
		case 1:
			num = *p;
			break;
		case 2:
			GETSHORT(num, p);
			break;
		case 3:
			p--; GETLONG(num, p);
			num &= 0xfff;
			break;
		case 4:
			GETLONG(num, p);
			break;
		default:
			return (-1);
		}
	}
	else num = c;

	return (num);
}
