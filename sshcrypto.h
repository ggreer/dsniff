/*
 * sshcrypto.c
 *
 * SSH-1 crypto routines, adapted from OpenSSH.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 * Copyright (c) 2000 Niels Provos <provos@monkey.org>
 * Copyright (c) 2000 Markus Friedl <markus@openbsd.org>
 *
 * $Id: sshcrypto.h,v 1.3 2001/03/15 08:33:06 dugsong Exp $
 */

#ifndef SSHCRYPTO_H
#define SSHCRYPTO_H

void	 rsa_public_encrypt(BIGNUM *src, BIGNUM *dst, RSA *key);
void	 rsa_private_decrypt(BIGNUM *src, BIGNUM *dst, RSA *key);

void	*blowfish_init(u_char *sesskey, int len);
void	 blowfish_encrypt(u_char *src, u_char *dst, int len, void *state);
void	 blowfish_decrypt(u_char *src, u_char *dst, int len, void *state);

void	*des3_init(u_char *sesskey, int len);
void	 des3_encrypt(u_char *src, u_char *dst, int len, void *state);
void	 des3_decrypt(u_char *src, u_char *dst, int len, void *state);

#endif /* SSHCRYPTO_H */

