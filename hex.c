/*
 * hex.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: hex.c,v 1.5 2001/03/15 08:33:03 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "hex.h"

int
hex_decode(char *src, int srclen, u_char *dst, int dstlen)
{
	char *p, *pe;
	u_char *q, *qe, ch, cl;
	
	pe = src + srclen;
	qe = dst + dstlen;

	if (strncmp(src, "0x", 2) == 0)
		src += 2;
	
	for (p = src, q = dst; p < pe && q < qe && isxdigit((int)*p); p += 2) {
		ch = tolower(p[0]);
		cl = tolower(p[1]);
		
		if ((ch >= '0') && (ch <= '9')) ch -= '0';
		else if ((ch >= 'a') && (ch <= 'f')) ch -= 'a' - 10;
		else return (-1);
		
		if ((cl >= '0') && (cl <= '9')) cl -= '0';
		else if ((cl >= 'a') && (cl <= 'f')) cl -= 'a' - 10;
		else return (-1);
		
		*q++ = (ch << 4) | cl;
	}
	return (q - dst);
}

/* adapted from OpenBSD tcpdump: dump the buffer in emacs-hexl format */
void
hex_print(const u_char *buf, int len, int offset)
{
	u_int i, j, jm;
	int c;
	
	printf("\n");
	for (i = 0; i < len; i += 0x10) {
		printf("  %04x: ", (u_int)(i + offset));
		jm = len - i;
		jm = jm > 16 ? 16 : jm;
		
		for (j = 0; j < jm; j++) {
			if ((j % 2) == 1) printf("%02x ", (u_int) buf[i+j]);
			else printf("%02x", (u_int) buf[i+j]);
		}
		for (; j < 16; j++) {
			if ((j % 2) == 1) printf("   ");
			else printf("  ");
		}
		printf(" ");
		
		for (j = 0; j < jm; j++) {
			c = buf[i+j];
			c = isprint(c) ? c : '.';
			printf("%c", c);
		}
		printf("\n");
	}
}

