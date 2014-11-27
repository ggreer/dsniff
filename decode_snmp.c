/*
 * decode_snmp.c
 *
 * Simple Network Management Protocol.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_snmp.c,v 1.6 2001/03/15 08:33:02 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"
#include "asn1.h"
#include "decode.h"

int
decode_snmp(u_char *buf, int len, u_char *obuf, int olen)
{
	struct buf *b, inbuf, outbuf;
	u_char *p, vers;
	int i;

	buf_init(&inbuf, buf, len);
	buf_init(&outbuf, obuf, olen);
	
	if (asn1_type(&inbuf) != ASN1_SEQUENCE)
		return (0);
	asn1_len(&inbuf);		/* XXX - skip sequence length */
	
	if (asn1_type(&inbuf) != ASN1_INTEGER)
		return (0);
	if (asn1_len(&inbuf) != 1)	/* XXX - check version length */
		return (0);
	buf_get(&inbuf, &vers, sizeof(vers));
	
	if (asn1_type(&inbuf) != ASN1_STRING)
		return (0);
	i = asn1_len(&inbuf);
	b = buf_tok(&inbuf, NULL, i);
	p = buf_strdup(b);
	
	buf_putf(&outbuf, "[version %d]\n%s\n", vers + 1, p);
	free(p);
	buf_end(&outbuf);
		
	return (buf_len(&outbuf));
}

