/*
 * sshcrypto.c
 *
 * SSH-1 crypto routines, adapted from OpenSSH.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 * Copyright (c) 2000 Niels Provos <provos@monkey.org>
 * Copyright (c) 2000 Markus Friedl <markus@openbsd.org>
 *
 * $Id: sshcrypto.c,v 1.5 2001/03/15 08:33:04 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/blowfish.h>
#include <openssl/des.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "sshcrypto.h"

struct blowfish_state {
	struct bf_key_st	key;
	u_char			iv[8];
};

struct des3_state {
	des_key_schedule	k1, k2, k3;
	des_cblock		iv1, iv2, iv3;
};

void
rsa_public_encrypt(BIGNUM *out, BIGNUM *in, RSA *key)
{
	u_char *inbuf, *outbuf;
	int len, ilen, olen;

	if (BN_num_bits(key->e) < 2 || !BN_is_odd(key->e))
		errx(1, "rsa_public_encrypt() exponent too small or not odd");

	olen = BN_num_bytes(key->n);
	outbuf = malloc(olen);

	ilen = BN_num_bytes(in);
	inbuf = malloc(ilen);

	if (outbuf == NULL || inbuf == NULL)
		err(1, "malloc");
	
	BN_bn2bin(in, inbuf);
	
	if ((len = RSA_public_encrypt(ilen, inbuf, outbuf, key,
				      RSA_PKCS1_PADDING)) <= 0)
		errx(1, "rsa_public_encrypt() failed");

	BN_bin2bn(outbuf, len, out);

	memset(outbuf, 0, olen);
	memset(inbuf, 0, ilen);
	free(outbuf);
	free(inbuf);
}

void
rsa_private_decrypt(BIGNUM *out, BIGNUM *in, RSA *key)
{
	u_char *inbuf, *outbuf;
	int len, ilen, olen;

	olen = BN_num_bytes(key->n);
	outbuf = malloc(olen);

	ilen = BN_num_bytes(in);
	inbuf = malloc(ilen);

	if (outbuf == NULL || inbuf == NULL)
		err(1, "malloc");
	
	BN_bn2bin(in, inbuf);

	if ((len = RSA_private_decrypt(ilen, inbuf, outbuf, key,
				       RSA_PKCS1_PADDING)) <= 0)
		errx(1, "rsa_private_decrypt() failed");
	
	BN_bin2bn(outbuf, len, out);

	memset(outbuf, 0, olen);
	memset(inbuf, 0, ilen);
	free(outbuf);
	free(inbuf);
}

/* XXX - SSH1's weirdo Blowfish... */
static void
swap_bytes(const u_char *src, u_char *dst, int n)
{
	char c[4];
	
	for (n = n / 4; n > 0; n--) {
		c[3] = *src++; c[2] = *src++;
		c[1] = *src++; c[0] = *src++;
		*dst++ = c[0]; *dst++ = c[1];
		*dst++ = c[2]; *dst++ = c[3];
	}
}

void *
blowfish_init(u_char *sesskey, int len)
{
	struct blowfish_state *state;

	if ((state = malloc(sizeof(*state))) == NULL)
		err(1, "malloc");
	
	BF_set_key(&state->key, len, sesskey);
	memset(state->iv, 0, 8);

	return (state);
}

void
blowfish_encrypt(u_char *src, u_char *dst, int len, void *state)
{
	struct blowfish_state *estate;

	estate = (struct blowfish_state *)state;
	swap_bytes(src, dst, len);
	BF_cbc_encrypt((void *)dst, dst, len, &estate->key, estate->iv,
		       BF_ENCRYPT);
	swap_bytes(dst, dst, len);
}

void
blowfish_decrypt(u_char *src, u_char *dst, int len, void *state)
{
	struct blowfish_state *dstate;

	dstate = (struct blowfish_state *)state;
	swap_bytes(src, dst, len);
	BF_cbc_encrypt((void *)dst, dst, len, &dstate->key, dstate->iv,
		       BF_DECRYPT);
	swap_bytes(dst, dst, len);
}

/* XXX - SSH1's weirdo 3DES... */
void *
des3_init(u_char *sesskey, int len)
{
	struct des3_state *state;
	
	if ((state = malloc(sizeof(*state))) == NULL)
		err(1, "malloc");

	des_set_key((void *)sesskey, state->k1);
	des_set_key((void *)(sesskey + 8), state->k2);

	if (len <= 16)
		des_set_key((void *)sesskey, state->k3);
	else
		des_set_key((void *)(sesskey + 16), state->k3);
	
	memset(state->iv1, 0, 8);
	memset(state->iv2, 0, 8);
	memset(state->iv3, 0, 8);
	
	return (state);
}
void
des3_encrypt(u_char *src, u_char *dst, int len, void *state)
{
	struct des3_state *estate;

	estate = (struct des3_state *)state;
	memcpy(estate->iv1, estate->iv2, 8);
	
	des_ncbc_encrypt(src, dst, len, estate->k1, &estate->iv1, DES_ENCRYPT);
	des_ncbc_encrypt(dst, dst, len, estate->k2, &estate->iv2, DES_DECRYPT);
	des_ncbc_encrypt(dst, dst, len, estate->k3, &estate->iv3, DES_ENCRYPT);
}

void
des3_decrypt(u_char *src, u_char *dst, int len, void *state)
{
	struct des3_state *dstate;
	
	dstate = (struct des3_state *)state;
	memcpy(dstate->iv1, dstate->iv2, 8);
	
	des_ncbc_encrypt(src, dst, len, dstate->k3, &dstate->iv3, DES_DECRYPT);
	des_ncbc_encrypt(dst, dst, len, dstate->k2, &dstate->iv2, DES_ENCRYPT);
	des_ncbc_encrypt(dst, dst, len, dstate->k1, &dstate->iv1, DES_DECRYPT);
}
