/*
 * record.h
 *
 * Record interface.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: record.h,v 1.3 2001/03/15 08:33:06 dugsong Exp $
 */

#ifndef RECORD_H
#define RECORD_H

int	record_init(char *file);

int	record(u_int32_t src, u_int32_t dst, int proto, u_short sport,
	       u_short dport, char *name, u_char *buf, int len);

void	record_dump(void);

void	record_close(void);

#endif /* RECORD_H */

