/*
 * decode_ldap.c
 *
 * Lightweight Directory Access Protocol.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_ldap.c,v 1.5 2001/03/15 08:33:01 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "buf.h"
#include "asn1.h"
#include "decode.h"

int
decode_ldap(u_char *buf, int len, u_char *obuf, int olen)
{
	struct buf *msg, inbuf, outbuf;
	int i, type;
	u_char *p;
	
	buf_init(&inbuf, buf, len);
	buf_init(&outbuf, obuf, olen);

	while (buf_len(&inbuf) > 10) {
		/* LDAPMessage */
		type = asn1_type(&inbuf);
		i = asn1_len(&inbuf);

		if (i <= 0 || (msg = buf_tok(&inbuf, NULL, i)) == NULL)
			break;
		
		if (type != ASN1_SEQUENCE)
			continue;
		
		/* messageID */
		type = asn1_type(msg);
		i = asn1_len(msg);
		if (type != ASN1_INTEGER || i <= 0 || buf_skip(msg, i) < 0)
			continue;
		
		/* bindRequest op - APPLICATION[0] SEQUENCE */
		if (buf_cmp(msg, "\x60", 1) != 0)
			continue;
		asn1_type(msg);
		asn1_len(msg);
		
		/* version */
		type = asn1_type(msg);
		i = asn1_len(msg);
		if (type != ASN1_INTEGER || i <= 0 || buf_skip(msg, i) < 0)
			continue;
		
		/* name */
		type = asn1_type(msg);
		i = asn1_len(msg);
		p = buf_ptr(msg);
		if (type != ASN1_STRING || i <= 0 || buf_skip(msg, i) < 0)
			continue;
		
		/* simple auth [0] */
		if (buf_cmp(msg, "\x80", 1) != 0)
			continue;
		*(buf_ptr(msg)) = '\0';
		buf_skip(msg, 1);

		/* passwd */
		i = asn1_len(msg);

		if (i <= 0 || i > buf_len(msg))
			continue;

		if (buf_tell(&outbuf) > 0)
			buf_put(&outbuf, "\n", 1);
		buf_putf(&outbuf, "%s\n", p);
		buf_put(&outbuf, buf_ptr(msg), i);
		buf_put(&outbuf, "\n", 1);
	}
	buf_end(&outbuf);
	
	return (buf_len(&outbuf));
}

