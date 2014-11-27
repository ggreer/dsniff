/*
 * decode.h
 *
 * Protocol decoding routines.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode.h,v 1.5 2001/03/15 08:33:06 dugsong Exp $
 */

#ifndef DECODE_H
#define DECODE_H

typedef int (*decode_func)(u_char *, int, u_char *, int);

struct decode {
	char	       *dc_name;
	decode_func	dc_func;
};

struct decode *getdecodebyname(const char *name);


#define pletohs(p)	((u_short)                         \
			 ((u_short)*((u_char *)p+1)<<8|    \
			  (u_short)*((u_char *)p+0)<<0))
     
#define pletohl(p)	((u_int32_t)*((u_char *)p+3)<<24|  \
			 (u_int32_t)*((u_char *)p+2)<<16|  \
			 (u_int32_t)*((u_char *)p+1)<<8|   \
			 (u_int32_t)*((u_char *)p+0)<<0)

#define pntohs(p)	((u_short)			   \
			 ((u_short)*((u_char *)p+1)<<0|    \
			  (u_short)*((u_char *)p+0)<<8))
			 
#define pntohl(p)	((u_int32_t)*((u_char *)p+3)<<0|   \
			 (u_int32_t)*((u_char *)p+2)<<18|  \
			 (u_int32_t)*((u_char *)p+1)<<16|  \
			 (u_int32_t)*((u_char *)p+0)<<24)

int	strip_telopts(u_char *buf, int len);

int	strip_lines(char *buf, int max_lines);

int	is_ascii_string(char *buf, int len);

u_char *bufbuf(u_char *big, int blen, u_char *little, int llen);

int	decode_aim(u_char *buf, int len, u_char *obuf, int olen);
int	decode_citrix(u_char *buf, int len, u_char *obuf, int olen);
int	decode_cvs(u_char *buf, int len, u_char *obuf, int olen);
int	decode_ftp(u_char *buf, int len, u_char *obuf, int olen);
int	decode_hex(u_char *buf, int len, u_char *obuf, int olen);
int	decode_http(u_char *buf, int len, u_char *obuf, int olen);
int	decode_icq(u_char *buf, int len, u_char *obuf, int olen);
int	decode_imap(u_char *buf, int len, u_char *obuf, int olen);
int	decode_irc(u_char *buf, int len, u_char *obuf, int olen);
int	decode_ldap(u_char *buf, int len, u_char *obuf, int olen);
int	decode_mmxp(u_char *buf, int len, u_char *obuf, int olen);
int	decode_mountd(u_char *buf, int len, u_char *obuf, int olen);
int	decode_napster(u_char *buf, int len, u_char *obuf, int olen);
int	decode_nntp(u_char *buf, int len, u_char *obuf, int olen);
int	decode_oracle(u_char *buf, int len, u_char *obuf, int olen);
int	decode_ospf(u_char *buf, int len, u_char *obuf, int olen);
int	decode_pcanywhere(u_char *buf, int len, u_char *obuf, int olen);
int	decode_pop(u_char *buf, int len, u_char *obuf, int olen);
int	decode_poppass(u_char *buf, int len, u_char *obuf, int olen);
int	decode_portmap(u_char *buf, int len, u_char *obuf, int olen);
int	decode_postgresql(u_char *buf, int len, u_char *obuf, int olen);
int	decode_pptp(u_char *buf, int len, u_char *obuf, int olen);
int	decode_rip(u_char *buf, int len, u_char *obuf, int olen);
int	decode_rlogin(u_char *buf, int len, u_char *obuf, int olen);
int	decode_smb(u_char *buf, int len, u_char *obuf, int olen);
int	decode_smtp(u_char *buf, int len, u_char *obuf, int olen);
int	decode_sniffer(u_char *buf, int len, u_char *obuf, int olen);
int	decode_snmp(u_char *buf, int len, u_char *obuf, int olen);
int	decode_socks(u_char *buf, int len, u_char *obuf, int olen);
int	decode_tds(u_char *buf, int len, u_char *obuf, int olen);
int	decode_telnet(u_char *buf, int len, u_char *obuf, int olen);
int	decode_vrrp(u_char *buf, int len, u_char *obuf, int olen);
int	decode_x11(u_char *buf, int len, u_char *obuf, int olen);
int	decode_yppasswd(u_char *buf, int len, u_char *obuf, int olen);
int	decode_ypserv(u_char *buf, int len, u_char *obuf, int olen);

#endif /* DECODE_H */
