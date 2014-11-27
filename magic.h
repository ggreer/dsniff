/*
 * magic.h
 *
 * Network application protocol identification, based on file(1) magic.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: magic.h,v 1.3 2001/03/15 08:33:06 dugsong Exp $
 */

#ifndef MAGIC_H
#define MAGIC_H

void	 magic_init(char *filename);

char	*magic_match(u_char *buf, int len);

#endif /* MAGIC_H */
