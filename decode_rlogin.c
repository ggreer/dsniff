/*
 * decode_rlogin.c
 *
 * Berkeley remote login/shell/exec.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_rlogin.c,v 1.6 2001/03/15 08:33:02 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <strlcpy.h>
#include <strlcat.h>

#include "options.h"
#include "decode.h"

int
decode_rlogin(u_char *buf, int len, u_char *obuf, int olen)
{
	u_char *p, *q;

	/* Skip first NULL, or rexec stderr port */
	for (p = buf; p - buf < len && *p == '\0'; p++)
		;	/* VOID */
	
	strlcpy(obuf, "[", olen);
	strlcat(obuf, p, olen);		/* Local username */
	strlcat(obuf, ":", olen);
	p += strlen(p) + 1;
	
	strlcat(obuf, p, olen);		/* Remote username */
	strlcat(obuf, "]\n", olen);
	p += strlen(p) + 1;
	
	p += strlen(p) + 1;			/* Skip term info */
	
	if ((q = strstr(p, "\xff\xffss")) != NULL)	/* Skip window size */
		p += 12;
	
	for (p = strtok(p, "\r\n"); p != NULL; p = strtok(NULL, "\r\n")) {
		strlcat(obuf, p, olen);
		strlcat(obuf, "\n", olen);
	}
	if (!strip_lines(obuf, Opt_lines))
		return (0);
	
	return (strlen(obuf));
}

