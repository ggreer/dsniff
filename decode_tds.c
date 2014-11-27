/*
 * decode_tds.c
 *
 * Tabular Data Stream (Sybase, Microsoft SQL). See www.freetds.org.
 *
 * Thanks to antilove!@#$% and Ben Lowery <blowery@monkey.org> for
 * providing me with packet traces.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 * Copyright (c) 2001 Paul van Maaren <P.v.Maaren@reseau.nl>
 *
 * $Id: decode_tds.c,v 1.10 2001/03/15 08:33:02 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <strlcat.h>
#include <arpa/inet.h>

#include "decode.h"

struct tds_hdr {
	u_char		type;
	u_char		last;
	u_short		size;
	u_int32_t	zero;
};

struct tds_login {
	char		hostname[30];
	u_char		hostlen;
	char		username[30];
	u_char		userlen;
	char		password[30];
	u_char		passlen;
	char		process[30];
	u_char		proclen;
	char		magic1[6];
	u_char		bulkcopy;
	char		magic2[9];
	char		appname[30];
	u_char		applen;
	char		servername[30];
	u_char		serverlen;
	u_char		zero;
	u_char		pass2len;
	char		password2[30];
	char		magic3[223];
	u_char		pass2len2;
	char		version[4];
	char		libname[10];
	u_char		liblen;
	char		magic4[3];
	char		language[30];
	u_char		langlen;
	u_char		nolang;
	u_short		magic5;
	u_char		encrypted;
	char		magic6[10];
	char		charset[30];
	u_char		charlen;
	u_char		magic7;
	char		blocksize[6];
	u_char		blocklen;
	char		magic8[4];	/* 4.2: 8, 4.6: 4, 5.0: 25 */
};

u_char tds7_magic1[] = {
	0x6, 0x83, 0xf2, 0xf8, 0xff, 0x0, 0x0, 0x0, 0x0, 0xe0, 0x03, 0x0,
	0x0, 0x88, 0xff, 0xff, 0xff, 0x36, 0x04, 0x00, 0x00
};

struct tds7_login {
	u_short	size;
	char	zero1[5];
	u_char	byte1;		/* 0x70 */
	char	zero2[7];
	char	magic1[21];
	u_short	servpos;
	u_short	servlen;
	u_short	userpos;	/* XXX - freetds got this wrong? */
	u_short	userlen;
	u_short	passpos;
	u_short	passlen;
	u_short	somepos;
	u_short	somelen;
	u_short	apppos;
	u_short	applen;
	char	zero4[4];
	u_short	libpos;
	u_short	liblen;
	char	skip1[8];
	char	magic2[6];
	char	skip2[8];
        /* char    servername[servlen]; */
	/* char username[userlen]; */
	/* char password[passlen]; */
	/* char appname[applen]; */
	/* char server[servlen]; */
	/* char library[liblen]; */
	/* char	magic3[48]; */
};

static void
deunicode(u_char *buf, int len)
{
	int i;
	
	for (i = 0; i < len; i++) {
		buf[i] = buf[i * 2];
	}
	buf[i] = '\0';
}


static void
tds7_decrypt(u_char *buf, int len)
{
	int i;
	
	for (i = 0; i < len; i++) {
		buf[i] = ((buf[i] << 4) | (buf[i] >> 4)) ^ 0x5a;
	}
	buf[i] = '\0';
}


int
decode_tds(u_char *buf, int len, u_char *obuf, int olen)
{
	struct tds_hdr *th;
	struct tds_login *tl;
	struct tds7_login *t7l, *myt7l;
	u_char *user, *pass, *serv;
	u_short userlen, passlen, servlen;
	
	obuf[0] = '\0';

	for (th = (struct tds_hdr *)buf;
	     len > sizeof(*th) && len >= ntohs(th->size);
	     buf += ntohs(th->size), len -= ntohs(th->size)) {
		
		if (th->type == 2) {
			/* Version 4.x, 5.0 */
			if (len < sizeof(*th) + sizeof(*tl))
				return (0);
			
			tl = (struct tds_login *)(th + 1);
			
			if (tl->userlen > sizeof(tl->username))
				return (0);
			
			tl->username[tl->userlen] = '\0';
			strlcat(obuf, tl->username, olen);
			strlcat(obuf, "\n", olen);
			
			if (tl->passlen > sizeof(tl->password))
				return (0);
			
			tl->password[tl->passlen] = '\0';
			strlcat(obuf, tl->password, olen);
			strlcat(obuf, "\n", olen);
		}
		else if (th->type == 16 && th->last == 1) {
			/* Version 7.0 */
			if (len < sizeof(*th) + sizeof(*t7l))
				return (0);
			
			t7l = (struct tds7_login *)(th + 1);
			
			myt7l = (struct tds7_login *)(buf + sizeof(*th));

			userlen = pletohs(&t7l->userlen);
			passlen = pletohs(&t7l->passlen);
			servlen = pletohs(&t7l->servlen);

			if (len < sizeof(*th) + sizeof(*t7l) +
			    (2 * (userlen + passlen))) {
				return (0);
			}

			serv = (u_char *)(t7l + 1);
			deunicode(serv, servlen);

			user = serv + (2 * servlen);
			pass = user + (2 * userlen);
			
			deunicode(user, userlen);
			
			/* XXX - when to call? */
			tds7_decrypt(pass, 2 * passlen);

			deunicode(pass, passlen);
			
			snprintf(obuf + strlen(obuf),
				 olen - strlen(obuf),
				 "%s\n%s\n", user, pass);
			return(strlen(obuf));
		}
	}
	return (strlen(obuf));
}


