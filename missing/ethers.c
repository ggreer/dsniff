/* $Id: ethers.c,v 1.1 2000/04/08 20:50:28 dugsong Exp $ */
/* $OpenBSD: ethers.c,v 1.10 1998/11/18 23:28:54 deraadt Exp $ */

/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* 
 * ethers(3) a la Sun.
 * Originally Written by Roland McGrath <roland@frob.com> 10/14/93.
 * Substantially modified by Todd C. Miller <Todd.Miller@courtesan.com>
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

char *
ether_ntoa(e)
	struct ether_addr *e;
{
	static char a[] = "xx:xx:xx:xx:xx:xx";

	if (e->ether_addr_octet[0] > 0xFF || e->ether_addr_octet[1] > 0xFF ||
	    e->ether_addr_octet[2] > 0xFF || e->ether_addr_octet[3] > 0xFF ||
	    e->ether_addr_octet[4] > 0xFF || e->ether_addr_octet[5] > 0xFF) {
		errno = EINVAL;
		return (NULL);
	}

	(void)sprintf(a, "%02x:%02x:%02x:%02x:%02x:%02x",
	    e->ether_addr_octet[0], e->ether_addr_octet[1],
	    e->ether_addr_octet[2], e->ether_addr_octet[3],
	    e->ether_addr_octet[4], e->ether_addr_octet[5]);

	return (a);
}

static char *
_ether_aton(s, e)
	char *s;
	struct ether_addr *e;
{
	int i;
	long l;
	char *pp;

	while (isspace(*s))
		s++;

	/* expect 6 hex octets separated by ':' or space/NUL if last octet */
	for (i = 0; i < 6; i++) {
		l = strtol(s, &pp, 16);
		if (pp == s || l > 0xFF || l < 0)
			return (NULL);
		if (!(*pp == ':' || (i == 5 && (isspace(*pp) || *pp == '\0'))))
			return (NULL);
		e->ether_addr_octet[i] = (u_char)l;
		s = pp + 1;
	}

	/* return character after the octets ala strtol(3) */
	return (pp);
}

struct ether_addr *
ether_aton(s)
	char *s;
{
	static struct ether_addr n;

	return (_ether_aton(s, &n) ? &n : NULL);
}

