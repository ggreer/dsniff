/*
 * ssh.h
 *
 * Minimal SSH-1 protocol implementation.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: ssh.h,v 1.3 2001/03/15 08:33:06 dugsong Exp $
 */

#ifndef SSH_H
#define SSH_H

#define SSH_MAX_PADLEN		8
#define SSH_MAX_PKTLEN		262144

/* Authentication types. */
#define SSH_AUTH_PASSWORD	3

/* Cipher types. */
#define SSH_CIPHER_NONE		0
#define SSH_CIPHER_3DES		3
#define SSH_CIPHER_BLOWFISH	6

/* Message types. */
#define SSH_MSG_DISCONNECT	1
#define SSH_SMSG_PUBLIC_KEY	2
#define SSH_CMSG_SESSION_KEY	3
#define SSH_CMSG_USER		4
#define SSH_CMSG_AUTH_PASSWORD	9
#define SSH_SMSG_SUCCESS	14
#define SSH_SMSG_FAILURE	15
#define SSH_CMSG_STDIN_DATA	16
#define SSH_SMSG_STDOUT_DATA	17
#define SSH_SMSG_STDERR_DATA	18
#define SSH_SMSG_EXITSTATUS	20

typedef struct ssh_ctx {
	int	 authmask;
	int	 encmask;
	RSA	*servkey;
	RSA	*hostkey;
} SSH_CTX;

typedef struct ssh {
	int	 fd;
	SSH_CTX *ctx;
	u_char	 sesskey[32];
	void	*estate;
	void	*dstate;
	void   (*encrypt)(u_char *src, u_char *dst, int len, void *state);
	void   (*decrypt)(u_char *src, u_char *dst, int len, void *state);
} SSH;

void	 SSH_init(void);

SSH_CTX	*SSH_CTX_new(void);

SSH	*SSH_new(SSH_CTX *ctx);

void	 SSH_set_fd(SSH *ssh, int fd);

int	 SSH_accept(SSH *ssh);

int	 SSH_connect(SSH *ssh);

int	 SSH_recv(SSH *ssh, u_char *buf, int size);

int	 SSH_send(SSH *ssh, u_char *buf, int len);

void	 SSH_close(SSH *ssh);

#endif /* SSH_H */
