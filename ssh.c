/*
 * ssh.c
 *
 * Minimal SSH-1 protocol implementation.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: ssh.c,v 1.6 2001/03/15 08:33:04 dugsong Exp $
 */

#include "config.h"

#include <sys/param.h>
#include <sys/types.h>
#include <arpa/nameser.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/md5.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "hex.h"
#include "options.h"
#include "sshcrypto.h"
#include "ssh.h"

static u_int crc32_tab[] = {
	0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
	0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
	0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
	0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
	0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
	0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
	0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
	0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
	0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
	0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
	0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
	0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
	0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
	0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
	0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
	0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
	0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
	0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
	0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
	0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
	0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
	0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
	0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
	0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
	0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
	0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
	0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
	0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
	0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
	0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
	0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
	0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
	0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
	0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
	0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
	0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
	0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
	0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
	0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
	0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
	0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
	0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
	0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
	0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
	0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
	0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
	0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
	0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
	0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
	0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
	0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
	0x2d02ef8dL
};

static u_char	pkt[4 + 8 + SSH_MAX_PKTLEN];

static void
put_bn(BIGNUM *bn, u_char **pp)
{
	short i;
	
	i = BN_num_bits(bn);
	PUTSHORT(i, *pp);
	*pp += BN_bn2bin(bn, *pp);
}

static void
get_bn(BIGNUM *bn, u_char **pp, int *lenp)
{
	short i;
	
	if (*lenp < 2) {
		errx(1, "short buffer");
	}
	GETSHORT(i, *pp); *lenp -= 2;

	i = ((i + 7) / 8);
	
	if (*lenp < i) {
		errx(1, "short buffer");
	}
	BN_bin2bn(*pp, i, bn);

	*pp += i; *lenp -= i;
}

static u_char *
ssh_session_id(u_char *cookie, BIGNUM *hostkey_n, BIGNUM *servkey_n)
{
	static u_char sessid[16];
	u_int i, j;
	u_char *p;

	i = BN_num_bytes(hostkey_n);
	j = BN_num_bytes(servkey_n);

	if ((p = malloc(i + j + 8)) == NULL)
		return (NULL);
	
	/* XXX - conform to sshd implementation here, not RFC. */
	BN_bn2bin(hostkey_n, p);
	BN_bn2bin(servkey_n, p + i);
	memcpy(p + i + j, cookie, 8);
	
	MD5(p, i + j + 8, sessid);
	free(p);

	return (sessid);
}

static u_int
ssh_crc32(const unsigned char *p, u_int len)
{
	u_int i;
	u_int val;
	
	val = 0;
	for (i = 0;  i < len;  i ++) {
		val = crc32_tab[(val ^ p[i]) & 0xff] ^ (val >> 8);
	}
	return (val);
}

static ssize_t
atomicio(ssize_t (*f)(), int fd, void *_s, size_t n)
{
	char *s = _s;
	ssize_t res, pos = 0;
	
	while (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		switch (res) {
		case -1:
			if (errno == EINTR || errno == EAGAIN)
				continue;
		case 0:
			return (res);
		default:
			pos += res;
		}
	}
	return (pos);
}

void
SSH_init(void)
{
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_crypto_strings();
#ifndef BSD	
	if (!RAND_status()) {
		RAND_seed("if you had a real operating system, "
			  "you'd have a real kernel PRNG", 65);
	}
#endif
}

SSH_CTX *
SSH_CTX_new(void)
{
	SSH_CTX *ctx;

	if ((ctx = calloc(sizeof(*ctx), 1)) == NULL)
		return (NULL);
	
	ctx->authmask = (1 << SSH_AUTH_PASSWORD);
	ctx->encmask = ((1 << SSH_CIPHER_3DES) | (1 << SSH_CIPHER_BLOWFISH) |
			(1 << SSH_CIPHER_NONE));

	return (ctx);
}

SSH *
SSH_new(SSH_CTX *ctx)
{
	SSH *ssh;

	if ((ssh = calloc(sizeof(*ssh), 1)) == NULL)
		return (NULL);

	ssh->fd = -1;
	ssh->ctx = ctx;

	return (ssh);
}

void
SSH_set_fd(SSH *ssh, int fd)
{
	ssh->fd = fd;
}

#define SKIP(p, i, l)	{ (p) += (l); if (((i) -= (l)) < 0) return (-1); }

int
SSH_accept(SSH *ssh)
{
	BIGNUM *enckey;
	u_char *p, cipher, cookie[8], msg[1024];
	u_int32_t num;
	int i;
	
	/* Generate anti-spoofing cookie. */
	RAND_bytes(cookie, sizeof(cookie));
	
	/* Send public key. */
	p = msg;
	*p++ = SSH_SMSG_PUBLIC_KEY;			/* type */
	memcpy(p, cookie, 8); p += 8;			/* cookie */
	num = 768; PUTLONG(num, p);			/* servkey bits */
	put_bn(ssh->ctx->servkey->e, &p);		/* servkey exponent */
	put_bn(ssh->ctx->servkey->n, &p);		/* servkey modulus */
	num = 1024; PUTLONG(num, p);			/* hostkey bits */
	put_bn(ssh->ctx->hostkey->e, &p);		/* hostkey exponent */
	put_bn(ssh->ctx->hostkey->n, &p);		/* hostkey modulus */
	num = 0; PUTLONG(num, p);			/* protocol flags */
	num = ssh->ctx->encmask; PUTLONG(num, p);	/* ciphers */
	num = ssh->ctx->authmask; PUTLONG(num, p);	/* authmask */
	
	if (SSH_send(ssh, msg, p - msg) < 0) {
		warn("SSH_send");
		return (-1);
	}
	/* Receive session key. */
	if ((i = SSH_recv(ssh, pkt, sizeof(pkt))) <= 0) {
		warn("SSH_recv");
		return (-1);
	}
	p = pkt;

	/* Verify type. */
	if (p[0] != SSH_CMSG_SESSION_KEY) {
		warnx("expected packet type %d, got %d",
		      SSH_CMSG_SESSION_KEY, pkt[0]);
		return (-1);
	}
	SKIP(p, i, 1);
	
	/* Verify cipher. */
	cipher = p[0];
	if (cipher != SSH_CIPHER_NONE &&
	    (ssh->ctx->encmask & (1 << cipher)) == 0) {
		warnx("cipher type %d not supported", cipher);
		return (-1);
	}
	SKIP(p, i, 1);
	
	/* Verify cookie. */
	if (memcmp(p, cookie, 8) != 0) {
		warnx("cookie doesn't match");
		return (-1);
	}
	SKIP(p, i, 8);

	/* Get encrypted session key. */
	if ((enckey = BN_new()) == NULL) {
		warn("BN_new");
		return (-1);
	}
	get_bn(enckey, &p, &i);

	/* Skip protocol flags. */
	SKIP(p, i, 4);

	/* Decrypt session key. */
	if (BN_cmp(ssh->ctx->servkey->n, ssh->ctx->hostkey->n) > 0) {
		rsa_private_decrypt(enckey, enckey, ssh->ctx->servkey);
		rsa_private_decrypt(enckey, enckey, ssh->ctx->hostkey);
	}
	else {
		rsa_private_decrypt(enckey, enckey, ssh->ctx->hostkey);
		rsa_private_decrypt(enckey, enckey, ssh->ctx->servkey);
	}
	BN_mask_bits(enckey, sizeof(ssh->sesskey) * 8); 
	i = BN_num_bytes(enckey);
	
	if (i < 0 || i > sizeof(ssh->sesskey)) {
		warnx("session key bogus");
		return (-1);
	}
	memset(ssh->sesskey, 0, sizeof(ssh->sesskey));
	BN_bn2bin(enckey, ssh->sesskey + sizeof(ssh->sesskey) - i);
	BN_clear_free(enckey);
	
	/* Derive real session key using session id. */
	if ((p = ssh_session_id(cookie, ssh->ctx->hostkey->n,
				ssh->ctx->servkey->n)) == NULL) {
		warn("ssh_session_id");
		return (-1);
	}
	for (i = 0; i < 16; i++) {
		ssh->sesskey[i] ^= p[i];
	}
	/* Set cipher. */
	if (cipher == SSH_CIPHER_3DES) {
		ssh->estate = des3_init(ssh->sesskey, sizeof(ssh->sesskey));
		ssh->dstate = des3_init(ssh->sesskey, sizeof(ssh->sesskey));
		ssh->encrypt = des3_encrypt;
		ssh->decrypt = des3_decrypt;
	}
	else if (cipher == SSH_CIPHER_BLOWFISH) {
		ssh->estate = blowfish_init(ssh->sesskey,sizeof(ssh->sesskey));
		ssh->dstate = blowfish_init(ssh->sesskey,sizeof(ssh->sesskey));
		ssh->encrypt = blowfish_encrypt;
		ssh->decrypt = blowfish_decrypt;
	}
	
	/* Send verification. */
	msg[0] = SSH_SMSG_SUCCESS;

	if (SSH_send(ssh, msg, 1) == -1) {
		warn("SSH_send");
		return (-1);
	}
	return (0);
}

int
SSH_connect(SSH *ssh)
{
	BIGNUM *bn;
	u_char *p, cipher, cookie[8], msg[1024];
	u_int32_t num;
	int i;
	
	/* Get public key. */
	if ((i = SSH_recv(ssh, pkt, sizeof(pkt))) <= 0) {
		warn("SSH_recv");
		return (-1);
	}
	p = pkt;
	
	/* Verify type. */
	if (p[0] != SSH_SMSG_PUBLIC_KEY) {
		warnx("expected packet type %d, got %d",
		      SSH_SMSG_PUBLIC_KEY, p[0]);
		return (-1);
	}
	SKIP(p, i, 1);

	/* Get cookie. */
	if (i > 8) memcpy(cookie, p, 8);
	SKIP(p, i, 8);

	/* Get servkey. */
	ssh->ctx->servkey = RSA_new();
	ssh->ctx->servkey->n = BN_new();
	ssh->ctx->servkey->e = BN_new();

	SKIP(p, i, 4);
	get_bn(ssh->ctx->servkey->e, &p, &i);
	get_bn(ssh->ctx->servkey->n, &p, &i);

	/* Get hostkey. */
	ssh->ctx->hostkey = RSA_new();
	ssh->ctx->hostkey->n = BN_new();
	ssh->ctx->hostkey->e = BN_new();

	SKIP(p, i, 4);
	get_bn(ssh->ctx->hostkey->e, &p, &i);
	get_bn(ssh->ctx->hostkey->n, &p, &i);

	/* Get cipher, auth masks. */
	SKIP(p, i, 4);
	if (i < 8) return (-1);
	GETLONG(ssh->ctx->encmask, p);
	GETLONG(ssh->ctx->authmask, p);
	
	/* Generate session key. */
	RAND_bytes(ssh->sesskey, sizeof(ssh->sesskey));

	/* Obfuscate with session id. */
	if ((p = ssh_session_id(cookie, ssh->ctx->hostkey->n,
				ssh->ctx->servkey->n)) == NULL) {
		warn("ssh_session_id");
		return (-1);
	}
	if ((bn = BN_new()) == NULL) {
		warn("BN_new");
		return (-1);
	}
	BN_set_word(bn, 0);
	
	for (i = 0; i < sizeof(ssh->sesskey); i++) {
		BN_lshift(bn, bn, 8);
		if (i < 16) BN_add_word(bn, ssh->sesskey[i] ^ p[i]);
		else BN_add_word(bn, ssh->sesskey[i]);
	}
	/* Encrypt session key. */
	if (BN_cmp(ssh->ctx->servkey->n, ssh->ctx->hostkey->n) < 0) {
		rsa_public_encrypt(bn, bn, ssh->ctx->servkey);
		rsa_public_encrypt(bn, bn, ssh->ctx->hostkey);
	}
	else {
		rsa_public_encrypt(bn, bn, ssh->ctx->hostkey);
		rsa_public_encrypt(bn, bn, ssh->ctx->servkey);
	}
	RSA_free(ssh->ctx->servkey);
	RSA_free(ssh->ctx->hostkey);
	
	/* Verify auth and cipher type. */
	if ((ssh->ctx->authmask & (1 << SSH_AUTH_PASSWORD)) == 0) {
		warnx("password auth not supported!");
		return (-1);
	}
	if ((ssh->ctx->encmask & (1 << SSH_CIPHER_BLOWFISH))) {
		cipher = SSH_CIPHER_BLOWFISH;
	}
	else if ((ssh->ctx->encmask & (1 << SSH_CIPHER_3DES))) {
		cipher = SSH_CIPHER_3DES;
	}
	else {
		warnx("no supported cipher");
		return (-1);
	}
	/* Send SSH_CMSG_SESSION_KEY. */
	p = msg;
	*p++ = SSH_CMSG_SESSION_KEY;		/* type */
	*p++ = cipher;				/* cipher type */
	memcpy(p, cookie, 8); p += 8;		/* cookie */
	put_bn(bn, &p);				/* enc sesskey */
	num = 0; PUTLONG(num, p);		/* flags */

	BN_clear_free(bn);
	
	if (SSH_send(ssh, msg, p - msg) < 0) {
		warn("SSH_send");
		return (-1);
	}
	/* Set cipher. */
	if (cipher == SSH_CIPHER_BLOWFISH) {
		ssh->estate = blowfish_init(ssh->sesskey,sizeof(ssh->sesskey));
		ssh->dstate = blowfish_init(ssh->sesskey,sizeof(ssh->sesskey));
		ssh->encrypt = blowfish_encrypt;
		ssh->decrypt = blowfish_decrypt;
	}
	else if (cipher == SSH_CIPHER_3DES) {
		ssh->estate = des3_init(ssh->sesskey, sizeof(ssh->sesskey));
		ssh->dstate = des3_init(ssh->sesskey, sizeof(ssh->sesskey));
		ssh->encrypt = des3_encrypt;
		ssh->decrypt = des3_decrypt;
	}
	/* Get server response. */
	if ((i = SSH_recv(ssh, pkt, sizeof(pkt))) <= 0) {
		warn("SSH_recv");
		return (-1);
	}
	if (i < 1 || pkt[0] != SSH_SMSG_SUCCESS) {
		warnx("server rejected us");
		return (-1);
	}
	return (0);
}

int
SSH_recv(SSH *ssh, u_char *buf, int size)
{
	u_int32_t i, crc, len;
	u_char *p;
	
	/* Read length. */
	if (atomicio(read, ssh->fd, &len, sizeof(len)) != sizeof(len)) {
		return (-1);
	}
	len = ntohl(len);
	i = 8 - (len % 8);
	
	if (i + len > size) {
		errno = EINVAL;
		return (-1);
	}
	/* Read padding + data + crc. */
	if (atomicio(read, ssh->fd, buf, i + len) != i + len)
		return (-1);
	
	/* Decrypt payload. */
	if (ssh->decrypt != NULL) {
		ssh->decrypt(buf, buf, i + len, ssh->dstate);
	}
	/* Verify CRC. */
	len -= 4;
	p = buf + i + len;
	GETLONG(crc, p);
	
	if (ssh_crc32(buf, i + len) != crc) {
		warnx("check bytes corrupted on input");
		errno = EINVAL;
		return (-1);
	}
	/* Skip padding. */
	memmove(buf, buf + i, len);

	if (Opt_debug) {
		hex_print(buf, len, 0);
	}
	return (len);
}

int
SSH_send(SSH *ssh, u_char *buf, int len)
{
	u_char *p;
	u_int32_t i;
	
	if (len > SSH_MAX_PKTLEN) {
		errno = EMSGSIZE;
		return (-1);
	}
	p = pkt;
	
	/* Add length (msg + crc). */
	i = len + 4;
	PUTLONG(i, p);
	
	/* Add padding. */
	i = 8 - ((len + 4) % 8);
	if (ssh->encrypt != NULL) {
		RAND_bytes(p, i);
	}
	else memset(p, 0, i);
	p += i;
	
	/* Add data. */
	memmove(p, buf, len);
	p += len;
	
	/* Add CRC. */
	i = ssh_crc32(pkt + 4, (p - pkt) - 4);
	PUTLONG(i, p);
	
	i = p - pkt;
	
	/* Encrypt payload. */
	if (ssh->encrypt != NULL) {
		ssh->encrypt(pkt + 4, pkt + 4, i - 4, ssh->estate);
	}
	/* Send it. */
	if (atomicio(write, ssh->fd, pkt, i) != i)
		return (-1);
	
	return (len);
}

void
SSH_close(SSH *ssh)
{
	close(ssh->fd);
}
