/*
 * decode_sniffer.c
 *
 * Network Associates Sniffer.
 * 
 * Copyright (c) 2000 Anonymous <nobody@localhost>
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_sniffer.c,v 1.4 2001/03/15 08:33:02 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <strlcat.h>
#include <strlcpy.h>

#include "base64.h"
#include "decode.h"

int 
decode_sniffer(u_char *buf, int len, u_char *obuf, int olen)
{
	u_int i, opcode;
	
	if (len < 36 || buf[0] != 5)
		return (0);
	
	opcode = pletohs(&buf[6]);
	
	if (opcode == 260) {
		if (buf[32] == 0)
			return (strlcpy(obuf, "[]\n", olen));
	}
	else if (opcode == 261) {
		if (pletohl(&buf[32]) == -1)
			return (strlcpy(obuf, "[]\n", olen));
	}
	else return (0);
	
	buf[len - 3]= '\0'; strtok(&buf[32], "\r\n");
	snprintf(obuf, olen, "%s [", &buf[32]);
	len = strlen(obuf);
	i = base64_pton(&buf[32], &obuf[len], olen - len - 3);
	obuf[len + i] = '\0';
	strlcat(obuf, "]\n", olen);
	
	return (strlen(obuf));
}

