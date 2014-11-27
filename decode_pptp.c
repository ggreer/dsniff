/*
 * decode_pptp.c
 *
 * Microsoft PPTP MS-CHAP. Derived from Aleph One's anger.c.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 * Copyright (c) 2000 Aleph One <aleph1@securityfocus.com>
 *
 * $Id: decode_pptp.c,v 1.4 2001/03/15 08:33:02 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "buf.h"
#include "decode.h"

struct pptp_gre_header {
	u_char flags;		/* bitfield */
	u_char ver;		/* should be PPTP_GRE_VER (enhanced GRE) */
	u_short protocol;	/* should be PPTP_GRE_PROTO (ppp-encaps) */
	u_short payload_len;	/* size of ppp payload, not inc. gre header */
	u_short call_id;	/* peer's call_id for this session */
	u_int32_t seq;		/* sequence number.  Present if S==1 */
	u_int32_t ack;		/* seq number of highest packet recieved by */
				/*  sender in this session */
};

#define PPTP_GRE_PROTO	0x880B
#define PPTP_GRE_VER	0x1

#define PPTP_GRE_IS_C(f) ((f) & 0x80)
#define PPTP_GRE_IS_R(f) ((f) & 0x40)
#define PPTP_GRE_IS_K(f) ((f) & 0x20)
#define PPTP_GRE_IS_S(f) ((f) & 0x10)
#define PPTP_GRE_IS_A(f) ((f) & 0x80)

struct ppp_header {
	u_char address;
	u_char control;
	u_short proto;
};

#define PPP_PROTO_CHAP		0xc223

struct ppp_lcp_chap_header {
	u_char code;
	u_char ident;
	u_short length;
};

#define PPP_CHAP_CODE_CHALLENGE	1
#define PPP_CHAP_CODE_RESPONSE	2

struct ppp_chap_challenge {
	u_char size;
	union {
		u_char challenge_v1[8];
		u_char challenge_v2[16];
		struct {
			u_char lanman[24];
			u_char nt[24];
			u_char flag;
		} response_v1;
		struct {
			u_char peer_challenge[16];
			u_char reserved[8];
			u_char nt[24];
			u_char flag;
		} response_v2;
	} value;
	/* name */
};

struct challenge {
	u_char version;
	u_char challenge[16];
};

int
decode_pptp(u_char *buf, int len, u_char *obuf, int olen)
{
	static struct challenge save_challenge;
	struct buf outbuf;
	struct pptp_gre_header *pgh;
	struct ppp_header *ppp;
	struct ppp_lcp_chap_header *chap;
	struct ppp_chap_challenge *chapch;
	u_short proto;
	u_char *p, name[64], digest[SHA_DIGEST_LENGTH];
	SHA_CTX ctx;
	int i, pghlen;

	buf_init(&outbuf, obuf, olen);
	
	if (len < (pghlen = sizeof(*pgh)))
		return (0);
	
	pgh = (struct pptp_gre_header *)buf;
	
	if ((pgh->ver & 0x7f) != PPTP_GRE_VER ||
	    ntohs(pgh->protocol) != PPTP_GRE_PROTO ||
	    PPTP_GRE_IS_C(pgh->flags) || PPTP_GRE_IS_R(pgh->flags) ||
	    PPTP_GRE_IS_K(pgh->flags) == 0 || (pgh->flags & 0xf) != 0) {
		return (0);
	}
	if (PPTP_GRE_IS_S(pgh->flags) == 0)
		return (0);
	
	if (PPTP_GRE_IS_A(pgh->ver) == 0)
		pghlen -= sizeof(pgh->ack);

	if (len - pghlen < ntohs(pgh->payload_len))
		return (0);

	ppp = (struct ppp_header *)(pgh + 1);

	if (ppp->address != 0xff && ppp->control != 0x3) {
		proto = pntohs(ppp);
		chap = (struct ppp_lcp_chap_header *)
			((u_char *)ppp + sizeof(proto));
	}
	else {
		proto = ntohs(ppp->proto);
		chap = (struct ppp_lcp_chap_header *)(ppp + 1);
	}
	if (proto != PPP_PROTO_CHAP)
		return (0);

	switch (chap->code) {
		
	case PPP_CHAP_CODE_CHALLENGE:
		chapch = (struct ppp_chap_challenge *)(chap + 1);
		
		if (chapch->size == 8) {
			save_challenge.version = 1;
			memcpy(save_challenge.challenge,
			       chapch->value.challenge_v1, 8);
		}
		else if (chapch->size == 16) {
			save_challenge.version = 2;
			memcpy(save_challenge.challenge,
			       chapch->value.challenge_v2, 16);
		}
		else save_challenge.version = 0;
		break;
		
	case PPP_CHAP_CODE_RESPONSE:
		if (save_challenge.version == 0)
			break;
		
		chapch = (struct ppp_chap_challenge *)(chap + 1);
		i = ntohs(chap->length) - 54;
		if (i > 63) i = 63;
		memcpy(name, (u_char *)chap + 54, i);
		name[i] = '\0';
		
		buf_putf(&outbuf, "%s:0:", name);
		
		if (save_challenge.version == 1) {
			for (i = 0; i < 8; i++) {
				buf_putf(&outbuf, "%02X",
					 save_challenge.challenge[i]);
			}
			buf_put(&outbuf, ":", 1);
			
			for (i = 0; i < 24; i++) {
				buf_putf(&outbuf, "%02X",
					 chapch->value.response_v1.lanman[i]);
			}
			buf_put(&outbuf, ":", 1);
			
			for (i = 0; i < 24; i++) {
				buf_putf(&outbuf, "%02X",
					 chapch->value.response_v1.nt[i]);
			}
			buf_put(&outbuf, "\n", 1);
		}
		else if (save_challenge.version == 2) {
			chapch = (struct ppp_chap_challenge *)(chap + 1);
			if ((p = strchr(name, '\\')) == NULL)
				p = name;
			
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, chapch->value.response_v2.peer_challenge, 16);
			SHA1_Update(&ctx, save_challenge.challenge, 16);
			SHA1_Update(&ctx, p, strlen(p));
			SHA1_Final(digest, &ctx);
			
			for (i = 0; i < 8; i++) {
				buf_putf(&outbuf, "%02X", digest[i]);
			}
			buf_putf(&outbuf, ":000000000000000000000000000000000000000000000000:");
			for (i = 0; i < 24; i++) {
				buf_putf(&outbuf, "%02X",
					 chapch->value.response_v2.nt[i]);
			}
			buf_put(&outbuf, "\n", 1);
			
			save_challenge.version = 0;
		}
		break;
	}
	buf_end(&outbuf);

	return (buf_len(&outbuf));
}

