/*
 * decode_nntp.c
 *
 * Network News Transport Protocol.
 *
 * Copyright (c) 2000 Felix von Leitner <felix@convergence.de>
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_nntp.c,v 1.5 2001/03/15 08:33:01 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <strlcat.h>

#include "base64.h"
#include "decode.h"

int
decode_nntp(u_char *buf, int len, u_char *obuf, int olen)
{
	char *p;
	int i, simple, dpa;
	
	obuf[0] = '\0';
	simple = dpa = 0;
	
	for (p = strtok(buf, "\r\n"); p != NULL; p = strtok(NULL, "\r\n")) {
		if (simple == 1) {
			strlcat(obuf, p, olen);
			strlcat(obuf, "\n", olen);
			simple = 0;
		}			
		else if (strncasecmp(p, "AUTHINFO ", 9) == 0) {
			strlcat(obuf, p, olen);
			
			if (strncasecmp(p + 9, "SIMPLE", 6) == 0) {
				simple = 1;
			}
			else if (strncasecmp(p + 9, "GENERIC ", 8) == 0) {
				if (strncasecmp(p + 17, "DPA", 3) == 0) {
					dpa = 1;
				}
				else if (dpa == 1) {
					p += 17;
					i = base64_pton(p, p, strlen(p));
					p[i] = '\0';
					i = strlen(obuf);
					snprintf(obuf + i, olen - i,
						 " [%s]", p);
				}
			}
			strlcat(obuf, "\n", olen);
		}
	}
	return (strlen(obuf));
}

