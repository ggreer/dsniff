/*
 * decode_pop.c
 *
 * Post Office Protocol.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_pop.c,v 1.4 2001/03/15 08:33:02 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <strlcat.h>

#include "base64.h"
#include "options.h"
#include "decode.h"

int
decode_poppass(u_char *buf, int len, u_char *obuf, int olen)
{
	char *p;
	
	obuf[0] = '\0';
	
	for (p = strtok(buf, "\r\n"); p != NULL; p = strtok(NULL, "\r\n")) {
		if (strncasecmp(p, "user ", 5) == 0 ||
		    strncasecmp(p, "pass ", 5) == 0 ||
		    strncasecmp(p, "newpass ", 8) == 0) {
			strlcat(obuf, p, olen);
			strlcat(obuf, "\n", olen);
		}
	}
	if (strip_lines(obuf, Opt_lines) < 3)
		return (0);
	
	return (strlen(obuf));
}

int
decode_pop(u_char *buf, int len, u_char *obuf, int olen)
{
	char *p;
	int i, j;
	
	obuf[0] = '\0';
	
	for (p = strtok(buf, "\r\n"); p != NULL; p = strtok(NULL, "\r\n")) {
		if (strncasecmp(p, "AUTH PLAIN", 10) == 0 ||
		    strncasecmp(p, "AUTH LOGIN", 10) == 0) {
			strlcat(obuf, p, olen);
			strlcat(obuf, "\n", olen);
			
			/* Decode SASL auth. */
			for (i = 0; i < 2 && (p = strtok(NULL, "\r\n")); i++) {
				strlcat(obuf, p, olen);
				j = base64_pton(p, p, strlen(p));
				p[j] = '\0';
				strlcat(obuf, " [", olen);
				strlcat(obuf, p, olen);
				strlcat(obuf, "]\n", olen);
			}
		}
		/* Save regular POP2, POP3 auth info. */
		else if (strncasecmp(p, "USER ", 5) == 0 ||
			 strncasecmp(p, "PASS ", 5) == 0 ||
			 strncasecmp(p, "HELO ", 5) == 0) {
			strlcat(obuf, p, olen);
			strlcat(obuf, "\n", olen);
		}
	}
	return (strlen(obuf));
}

