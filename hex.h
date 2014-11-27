/*
 * hex.h
 *
 * Hexadecimal conversion routines.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: hex.h,v 1.3 2001/03/15 08:33:06 dugsong Exp $
 */

#ifndef HEX_H
#define HEX_H

int	hex_decode(char *src, int srclen, u_char *buf, int len);

void	hex_print(const u_char *buf, int len, int offset);
	       
#endif /* HEX_H */

