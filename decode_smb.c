/*
 * decode_smb.c
 *
 * Microsoft Server Message Block.
 * 
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_smb.c,v 1.4 2001/03/15 08:33:02 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <arpa/nameser.h>

#include <stdio.h>
#include <string.h>
#include <strlcat.h>

#include "decode.h"

struct smbhdr {
	u_char	proto[4];
	u_char	cmd;
	u_char	err[4];
	u_char	flags1;
	u_short	flags2;
	u_short	pad[6];
	u_short	tid, pid, uid, mid;
};

int
decode_smb(u_char *buf, int len, u_char *obuf, int olen)
{
	struct smbhdr *smb;
	int i, j, k;
	u_char *p, *q, *end;
	char *user, *pass;
	
	obuf[0] = '\0';
	
	/* Skip NetBIOS session request. */
	if (len < 4 || buf[0] != 0x81) return (0);
	buf += 2;
	GETSHORT(i, buf); len -= 4;
	if (len < i) return (0);
	buf += i; len -= i;
	end = buf + len;
	
	/* Parse SMBs. */
	for (p = buf; p < end; p += i) {
		GETLONG(i, p);
		if (i > end - p || i < sizeof(*smb) + 32)
			continue;
		
		smb = (struct smbhdr *)p;
		if (memcmp(smb->proto, "\xffSMB", 4) != 0 || smb->cmd != 0x73)
			continue;
		
		user = pass = NULL;
		q = (u_char *)(smb + 1);
		
		if (*q == 10) {		/* Pre NT LM 0.12 */
			q += 15; j = pletohs(q); q += 2;
			if (j > i - (sizeof(*smb) + 15 + 6))
				continue;
			pass = q + 6;
			user = pass + j;
		}
		else if (*q == 13) {	/* NT LM 0.12 */
			q += 15; j = pletohs(q);
			q += 2;  k = pletohs(q);
			if (j > i - ((q - p) + 12) || k > i - ((q - p) + 11))
				continue;
			pass = q + 12;
			user = pass + j + k;
		}
		else continue;
		
		/* XXX - skip null IPC sessions, etc. */
		if (user && pass && strlen(user) &&
		    is_ascii_string(pass, j - 1)) {
			strlcat(obuf, user, olen);
			strlcat(obuf, " ", olen);
			strlcat(obuf, pass, olen);
			strlcat(obuf, "\n", olen);
		}
	}
	return (strlen(obuf));
}

