/*
 * decode_http.c
 *
 * Hypertext Transfer Protocol.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: decode_http.c,v 1.17 2001/03/15 08:32:59 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>
#include <libgen.h>
#include <err.h>

#include "base64.h"
#include "buf.h"
#include "decode.h"

#define USER_REGEX	".*account.*|.*acct.*|.*domain.*|.*login.*|" \
			".*member.*|.*user.*|.*name|.*email|.*_id|" \
			"id|uid|mn|mailaddress"
			
#define PASS_REGEX	".*pass.*|.*pw|pw.*|additional_info"

#define REGEX_FLAGS	(REG_EXTENDED | REG_ICASE | REG_NOSUB)

static regex_t		*user_regex, *pass_regex;

static int
grep_query_auth(char *buf)
{
	char *p, *q, *tmp;
	int user, pass;

	user = pass = 0;
	
	if ((tmp = strdup(buf)) == NULL)
		return (0);
	
	for (p = strtok(tmp, "&"); p != NULL; p = strtok(NULL, "&")) {
		if ((q = strchr(p, '=')) == NULL)
			continue;
		*q = '\0';
			
		if (!user) {
			if (regexec(user_regex, p, 0, NULL, 0) == 0) {
				user = 1;
				continue;
			}
		}
		if (!pass) {
			if (regexec(pass_regex, p, 0, NULL, 0) == 0)
				pass = 1;
		}
		if (user && pass) break;
	}
	free(tmp);
	
	return (user && pass);
}

static char *
http_req_dirname(char *req)
{
	char *uri, *vers;
	
	if ((uri = strchr(req, ' ')) == NULL)
		return (req);
	
	if ((vers = strrchr(uri, ' ')) == uri) {
		vers = NULL;
	}
	else if (vers[-1] == '/') {
		return (req);
	}
	else *vers++ = '\0';
	
	strcpy(req, dirname(req));
	strcat(req, "/");
	
	if (vers) {
		strcat(req, " ");
		strcat(req, vers);
	}
	return (req);
}  

int
decode_http(u_char *buf, int len, u_char *obuf, int olen)
{
	struct buf *msg, inbuf, outbuf;
	char *p, *req, *auth, *pauth, *query, *host;
	int i;

	buf_init(&inbuf, buf, len);
	buf_init(&outbuf, obuf, olen);

	if (user_regex == NULL || pass_regex == NULL) {
		if ((user_regex = malloc(sizeof(*user_regex))) == NULL ||
		    (pass_regex = malloc(sizeof(*pass_regex))) == NULL)
			err(1, "malloc");
		
		if (regcomp(user_regex, USER_REGEX, REGEX_FLAGS) ||
		    regcomp(pass_regex, PASS_REGEX, REGEX_FLAGS))
			errx(1, "regcomp failed");
	}
	while ((i = buf_index(&inbuf, "\r\n\r\n", 4)) >= 0) {
		msg = buf_tok(&inbuf, NULL, i);
		msg->base[msg->end] = '\0';
		buf_skip(&inbuf, 4);

		if ((req = strtok(buf_ptr(msg), "\r\n")) == NULL)
			continue;

		if (strncmp(req, "GET ", 4) != 0 &&
		    strncmp(req, "POST ", 5) != 0 &&
		    strncmp(req, "CONNECT ", 8) != 0)
			continue;

		auth = pauth = query = host = NULL;

		if ((query = strchr(req, '?')) != NULL)
			query++;
		
		while ((p = strtok(NULL, "\r\n")) != NULL) {
			if (strncasecmp(p, "Authorization: Basic ", 21) == 0) {
				auth = p;
			}				
			else if (strncasecmp(p, "Proxy-authorization: "
					     "Basic ", 27) == 0) {
				pauth = p;
			}
			else if (strncasecmp(p, "Host: ", 6) == 0) {
				host = p;
			}
			else if (req[0] == 'P') {
				if (strncmp(p, "Content-type: ", 14) == 0) {
					if (strncmp(p + 14, "application/"
						    "x-www-form-urlencoded",
						    33) != 0) {
						query = NULL;
					}
				}
				else if (strncmp(p, "Content-length: ", 16) == 0) {
					p += 16;
					i = atoi(p);
					if ((msg = buf_tok(&inbuf, NULL, i)) == NULL)
						continue;
					msg->base[msg->end] = '\0';
					query = buf_ptr(msg);
				}
			}
		}
		if (auth || pauth || (query && grep_query_auth(query))) {
			if (buf_tell(&outbuf) > 0)
				buf_putf(&outbuf, "\n");
			
			if (req[0] == 'G' && auth)
				req = http_req_dirname(req);

			buf_putf(&outbuf, "%s\n", req);
			
			if (host)
				buf_putf(&outbuf, "%s\n", host);
			
			if (pauth) {
				buf_putf(&outbuf, "%s", pauth);
				p = pauth + 27;
				i = base64_pton(p, p, strlen(p));
				p[i] = '\0';
				buf_putf(&outbuf, " [%s]\n", p);
			}
			if (auth) {
				buf_putf(&outbuf, "%s", auth);
				p = auth + 21;
				i = base64_pton(p, p, strlen(p));
				p[i] = '\0';
				buf_putf(&outbuf, " [%s]\n", p);
			}
			else if (req[0] == 'P' && query) {
				buf_putf(&outbuf,
					 "Content-type: application/"
					 "x-www-form-urlencoded\n"
					 "Content-length: %d\n%s\n",
					 strlen(query), query);
			}
		}
	}
	buf_end(&outbuf);
	
	return (buf_len(&outbuf));
}
