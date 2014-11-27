/*
 * tcp_raw.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: tcp_raw.c,v 1.10 2001/03/15 08:33:04 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include <time.h>
#include <err.h>
#include <libnet.h>
#include "options.h"
#include "tcp_raw.h"

struct tha {
	in_addr_t	src;
	in_addr_t	dst;
	u_short		port;
};

struct tcp_seg {
	u_int32_t	seq;
	u_char	       *data;
	int		len;
};

struct tcp_conn {
	struct tha		tha;
	time_t			mtime;
	struct tcp_seg	       *seg;
	int			segcnt;
	int			segmax;
	struct tcp_conn	       *next;
};

#define TCP_TIMEOUT	60
#define TCP_HASHSIZE	919

static struct tcp_conn	conntab[TCP_HASHSIZE];

static int
tcp_seg_compare(const void *a, const void *b)
{
	struct tcp_seg *sa, *sb;

	sa = (struct tcp_seg *) a;
	sb = (struct tcp_seg *) b;

	if (sa->seq < sb->seq)
		return (-1);
	else if (sa->seq > sb->seq)
		return (1);
	else return (0);
}

static void
tcp_raw_delete(struct tcp_conn *conn)
{
	struct tcp_conn *hold;
	int i;
	
	if (conn->next != NULL) {
		for (i = 0; i < conn->segcnt; i++) {
			if (conn->seg[i].data)
				free(conn->seg[i].data);
		}
		free(conn->seg);
		conn->seg = NULL;
		conn->segcnt = conn->segmax = 0;

		if (conn->next->next != NULL) {
			hold = conn->next;
			*conn = *conn->next;
			free(hold);
		}
		else {
			free(conn->next);
			conn->next = NULL;
		}
	}
}

static struct iovec *
tcp_raw_reassemble(struct tcp_conn *conn, int minlen)
{
	struct iovec *iov;
	int i, len;

	len = 0;
	
	for (i = 0; i < conn->segcnt; i++)
		len += conn->seg[i].len;
	
	if (len < minlen)
		return (NULL);

	if ((iov = (struct iovec *) malloc(sizeof(*iov))) == NULL)
		err(1, "tcp_raw_reassemble: malloc");

	if ((iov->iov_base = (u_char *) malloc(len)) == NULL)
		err(1, "tcp_raw_reassemble: malloc");

	iov->iov_len = 0;
	
	qsort(conn->seg, conn->segcnt, sizeof(*conn->seg), tcp_seg_compare);
	
	for (i = 0; i < conn->segcnt; i++) {
		len = conn->seg[i].len;
		memcpy(iov->iov_base + iov->iov_len, conn->seg[i].data, len);
		iov->iov_len += len;
	}
	return (iov);
}

struct iovec *
tcp_raw_input(struct libnet_ipv4_hdr *ip, struct libnet_tcp_hdr *tcp, int len)
{
	struct tha tha;
	struct tcp_conn *conn;
	struct tcp_seg seg;
	struct iovec *iov;
	u_short cksum;
	u_char *buf;
	int tcp_hl = tcp->th_off * 4;

	/* Verify TCP checksum. */
	cksum = tcp->th_sum;
	libnet_do_checksum(NULL, (u_char *) ip, IPPROTO_TCP, len);

	if (cksum != tcp->th_sum)
		return (NULL);

	tha.src = ip->ip_src.s_addr;
	tha.dst = ip->ip_dst.s_addr;
	tha.port = ntohs(tcp->th_sport) << 16 | ntohs(tcp->th_dport);
	
	buf = (u_char *)tcp + tcp_hl;
	len -= tcp_hl;
	iov = NULL;
	
	/* Find half-duplex stream associated with this segment. */
	for (conn = &conntab[tha.port % TCP_HASHSIZE];
	     conn->next != NULL; conn = conn->next) {
		if (memcmp((char *)&tha, (char *)&conn->tha, sizeof(tha)) == 0)
			break;
	}
	/* Process by TCP flags. */
	if (conn->next == NULL) {
		if (tcp->th_flags & TH_SYN) {
			if (conn->next == NULL &&
			    (conn->next = (struct tcp_conn *)
			     calloc(1, sizeof(*conn))) == NULL) {
				err(1, "tcp_raw_input: calloc");
			}
			conn->tha = tha;

			if (conn->seg == NULL &&
			    (conn->seg = (struct tcp_seg *)
			     malloc(sizeof(seg) * 128)) == NULL) {
				err(1, "tcp_raw_input: malloc");
			}
			conn->segmax = 128;
		}
	}
	else if (tcp->th_flags & TH_FIN || tcp->th_flags & TH_RST) {
		iov = tcp_raw_reassemble(conn, 1);
	}
	else if (tcp->th_flags & TH_ACK && len > 0) {
		seg.seq = ntohl(tcp->th_seq);
		if (bsearch(&seg, conn->seg, conn->segcnt,
			    sizeof(seg), tcp_seg_compare) == NULL) {
			
			if ((seg.data = (u_char *) malloc(len)) == NULL)
				err(1, "tcp_raw_input: malloc");
			memcpy(seg.data, buf, len);
			seg.len = len;
		
			if (conn->segcnt == conn->segmax) {
				if ((conn->seg = (struct tcp_seg *)
				     realloc(conn->seg, (conn->segmax * 2) *
					     sizeof(seg))) == NULL)
					err(1, "tcp_raw_input: realloc");
				conn->segmax *= 2;
			}
			conn->seg[conn->segcnt++] = seg;
			
			iov = tcp_raw_reassemble(conn, Opt_snaplen);
		}
	}
	conn->mtime = time(NULL);
	
	/* If we successfully reassembled the stream, delete its entry. */
	if (iov != NULL) {
		tcp_raw_delete(conn);
	}
	return (iov);
}

void
tcp_raw_timeout(int timeout, tcp_raw_callback_t callback)
{
	struct tcp_conn *conn;
	struct iovec *iov;
	time_t now;
	int i;

	now = time(NULL);
	
	for (i = 0; i < TCP_HASHSIZE; i++) {
		for (conn = &conntab[i]; conn != NULL && conn->next != NULL;
		     conn = conn->next) {
			if (now - conn->mtime > timeout) {
				
				iov = tcp_raw_reassemble(conn, 1);
				
				if (iov != NULL) {
					callback(conn->tha.src, conn->tha.dst,
						 conn->tha.port >> 16,
						 conn->tha.port & 0xffff,
						 iov->iov_base, iov->iov_len);
					
					free(iov->iov_base);
					free(iov);
				}
				tcp_raw_delete(conn);
			}
		}
	}
}

