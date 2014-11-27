/*
 * filesnarf.c
 *
 * Sniff files from NFS traffic.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: filesnarf.c,v 1.13 2001/03/15 08:33:03 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <rpc/rpc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <regex.h>
#include <err.h>
#include <libnet.h>
#include <nids.h>
#include <pcap.h>

#include "decode.h"
#include "pcaputil.h"
#include "nfs_prot.h"
#include "rpc.h"
#include "version.h"

struct myreadargs {
	char *filename;
	u_int offset;
};

struct fh_map {
	u_char fh[NFS3_FHSIZE];
	char *filename;
};

#define FH_MAP_SIZE	128

struct fh_map	fh_maps[FH_MAP_SIZE];
int		fh_map_next = 0;
int		fh_map_hint = 0;
int		Opt_invert = 0;
regex_t	       *pregex = NULL;

static void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: filesnarf [-i interface | -p pcapfile] [[-v] pattern [expression]]\n");
	exit(1);
}

/* XXX - for nfs_prot_xdr.c */
bool_t
xdr_u_int64_t(XDR *xdrs, u_int64_t *nump)
{
	int i = 1;
	u_char *p = (u_char *)nump;

	if (*(char *)&i == 1) {		/* endian haack. */
		if (xdr_u_long(xdrs, (u_long *)(p + 4)))
			return (xdr_u_long(xdrs, (u_long *)p));
	}
	else {
		if (xdr_u_long(xdrs, (u_long *)p))
			return (xdr_u_long(xdrs, (u_long *)(p + 4)));
	}
	return (FALSE);
}

bool_t
xdr_int64_t(XDR *xdrs, int64_t *nump)
{
	return (xdr_u_int64_t(xdrs, (u_int64_t *)nump));
}

static void
fh_map_init(void)
{
	memset(&fh_maps, 0, sizeof(fh_maps));
}

static void
fh_map_add(char *filename, u_char *fh, int len)
{
	struct fh_map *fm;

	fm = &fh_maps[fh_map_next];

	if (++fh_map_next > FH_MAP_SIZE)
		fh_map_next = 0;

	memcpy(fm->fh, fh, len);
	
	if ((fm->filename = strdup(filename)) == NULL)
		err(1, "fh_map_add: malloc");
}

static char *
fh_map_find(u_char *fh, int len)
{
	struct fh_map *fm;
	int i;

	i = fh_map_hint;
	do {
		fm = &fh_maps[i];
		if (memcmp(fm->fh, fh, len) == 0) {
			fh_map_hint = i;
			return (fm->filename);
		}
		if (++i > FH_MAP_SIZE)
			i = 0;
	} while (i != fh_map_hint);
	
	return (NULL);
}

static int
regex_match(char *string)
{
	return (pregex == NULL ||
		((regexec(pregex, string, 0, NULL, 0) == 0) ^ Opt_invert));
}

static void
nfs_save(struct tuple4 *addr, struct myreadargs *ma, u_char *buf, int len)
{
	int fd;

	warnx("%s.%d > %s.%d: %s (%d@%d)",
	      libnet_addr2name4(addr->daddr, LIBNET_DONT_RESOLVE), addr->dest,
	      libnet_addr2name4(addr->saddr, LIBNET_DONT_RESOLVE), addr->source,
	      ma->filename, len, ma->offset);
	
	if ((fd = open(ma->filename, O_WRONLY|O_CREAT, 0644)) >= 0) {
		if (lseek(fd, ma->offset, SEEK_SET) == ma->offset)
			write(fd, buf, len);
	}
	close(fd);
}

static void
nfs2_call(u_int32_t xid, u_int32_t proc, u_char *buf, int len)
{
	XDR xdrs;
	struct diropargs dargs;
	struct readargs rargs;
	struct myreadargs *ma;
	char *fname;
	
	switch (proc) {
		
	case NFSPROC_LOOKUP:
		memset(&dargs, 0, sizeof(dargs));
		xdrmem_create(&xdrs, buf, len, XDR_DECODE);
		
		if (xdr_diropargs(&xdrs, &dargs)) {
			if (regex_match(dargs.name)) {
				xid_map_enter(xid, NFS_PROGRAM, NFS_VERSION,
					      proc, (void *)dargs.name);
			}
		}
		xdr_destroy(&xdrs);
		break;
		
	case NFSPROC_READ:
		memset(&rargs, 0, sizeof(rargs));
		xdrmem_create(&xdrs, buf, len, XDR_DECODE);
		
		if (xdr_readargs(&xdrs, &rargs)) {
			fname = fh_map_find(rargs.file.data, NFS_FHSIZE);
			if (fname != NULL) {
				ma = (struct myreadargs *) malloc(sizeof(*ma));
				if (ma != NULL) {
					ma->filename = fname;
					ma->offset = rargs.offset;
					xid_map_enter(xid, NFS_PROGRAM,
						      NFS_VERSION,
						      NFSPROC_READ,
						      (void *)ma);
				}
			}
		}
		xdr_destroy(&xdrs);
		break;
	}
}

static void
nfs2_reply(struct xid_map *xm, struct tuple4 *addr, u_char *buf, int len)
{
	XDR xdrs;
	struct diropres dres;
	struct readres rres;
	
	switch (xm->proc) {
		
	case NFSPROC_LOOKUP:
		xdrmem_create(&xdrs, buf, len, XDR_DECODE);
		memset(&dres, 0, sizeof(dres));
		
		if (xdr_diropres(&xdrs, &dres)) {
			if (dres.status == NFS_OK)
				fh_map_add((char *)xm->data,
					   dres.diropres_u.diropres.file.data,
					   NFS_FHSIZE);
		}
		xdr_destroy(&xdrs);
		break;
		
	case NFSPROC_READ:
		xdrmem_create(&xdrs, buf, len, XDR_DECODE);
		memset(&rres, 0, sizeof(rres));
		
		if (xdr_readres(&xdrs, &rres)) {
			if (rres.status == NFS_OK) {
				nfs_save(addr, (struct myreadargs *)xm->data,
					 rres.readres_u.reply.data.data_val,
					 rres.readres_u.reply.data.data_len);
			}
		}
		xdr_destroy(&xdrs);
		break;
	}
}

static void
nfs3_call(u_int32_t xid, u_int32_t proc, u_char *buf, int len)
{
	XDR xdrs;
	struct LOOKUP3args largs;
	struct READ3args rargs;
	struct myreadargs *ma;
	char *fname;
	
	switch (proc) {
		
	case NFSPROC3_LOOKUP:
		memset(&largs, 0, sizeof(largs));
		xdrmem_create(&xdrs, buf, len, XDR_DECODE);
		
		if (xdr_LOOKUP3args(&xdrs, &largs)) {
			if (regex_match(largs.what.name)) {
				xid_map_enter(xid, NFS_PROGRAM, NFS_V3,
					      proc, (void *)largs.what.name);
			}
		}
		xdr_destroy(&xdrs);
		break;
		
	case NFSPROC3_READ:
		memset(&rargs, 0, sizeof(rargs));
		xdrmem_create(&xdrs, buf, len, XDR_DECODE);
		
		if (xdr_READ3args(&xdrs, &rargs)) {
			fname = fh_map_find(rargs.file.data.data_val,
					    rargs.file.data.data_len);
			if (fname != NULL) {
				ma = (struct myreadargs *) malloc(sizeof(*ma));
				if (ma != NULL) {
					ma->filename = fname;
					ma->offset = rargs.offset;
					xid_map_enter(xid, NFS_PROGRAM, NFS_V3,
						      NFSPROC_READ,
						      (void *)ma);
				}
			}
		}
		xdr_destroy(&xdrs);
		break;
	}
}

static void
nfs3_reply(struct xid_map *xm, struct tuple4 *addr, u_char *buf, int len)
{
	XDR xdrs;
	struct LOOKUP3res lres;
	struct READ3res rres;
	
	switch (xm->proc) {
		
	case NFSPROC3_LOOKUP:
		xdrmem_create(&xdrs, buf, len, XDR_DECODE);
		memset(&lres, 0, sizeof(lres));
		
		if (xdr_LOOKUP3res(&xdrs, &lres)) {
			if (lres.status == NFS3_OK) {
				fh_map_add((char *)xm->data,
				 lres.LOOKUP3res_u.resok.object.data.data_val,
				 lres.LOOKUP3res_u.resok.object.data.data_len);
			}
		}
		xdr_destroy(&xdrs);
		break;
		
	case NFSPROC3_READ:
		xdrmem_create(&xdrs, buf, len, XDR_DECODE);
		memset(&rres, 0, sizeof(rres));
		
		if (xdr_READ3res(&xdrs, &rres)) {
			if (rres.status == NFS3_OK) {
				nfs_save(addr, (struct myreadargs *)xm->data,
					 rres.READ3res_u.resok.data.data_val,
					 rres.READ3res_u.resok.data.data_len);
			}
		}
		xdr_destroy(&xdrs);
		break;
	}
}

static void
decode_nfs(struct tuple4 *addr, u_char *buf, int len)
{
	struct rpc_msg msg;
	struct xid_map *xm;
	int hdrlen;
	
	memset(&msg, 0, sizeof(msg));
	
	if ((hdrlen = rpc_decode(buf, len, &msg)) == 0)
		return;

	buf += hdrlen;
	len -= hdrlen;
	
	if (msg.rm_direction == CALL && msg.rm_call.cb_prog == NFS_PROGRAM) {
		if (msg.rm_call.cb_vers == NFS_VERSION)
			nfs2_call(msg.rm_xid, msg.rm_call.cb_proc, buf, len);
		else if (msg.rm_call.cb_vers == NFS_V3)
			nfs3_call(msg.rm_xid, msg.rm_call.cb_proc, buf, len);
	}
	else if ((xm = xid_map_find(msg.rm_xid)) != NULL &&
		 msg.rm_direction == REPLY &&
		 msg.rm_reply.rp_stat == MSG_ACCEPTED &&
		 msg.acpted_rply.ar_stat == SUCCESS) {
		
		if (xm->vers == NFS_VERSION)
			nfs2_reply(xm, addr, buf, len);
		else if (xm->vers == NFS_V3)
			nfs3_reply(xm, addr, buf, len);
		
		free(xm->data);
		memset(xm, 0, sizeof(*xm));
	}
}

static void
decode_udp_nfs(struct libnet_ipv4_hdr *ip)
{
	static struct tuple4 addr;
	struct libnet_udp_hdr *udp;
	u_char *buf;
	int len, ip_hl = ip->ip_hl * 4;
	
	len = ntohs(ip->ip_len) - ip_hl;
	
	if (ip->ip_p != IPPROTO_UDP || len < sizeof(*udp))
		return;
	
	buf = (u_char *)ip + ip_hl;
	udp = (struct libnet_udp_hdr *)buf;

	if (ntohs(udp->uh_sport) != 2049 && ntohs(udp->uh_dport) != 2049)
		return;
	
	if (len != ntohs(udp->uh_ulen))
		return;
	
	buf += sizeof(*udp);
	len -= sizeof(*udp);

	addr.saddr = ip->ip_dst.s_addr;
	addr.daddr = ip->ip_src.s_addr;
	addr.source = ntohs(udp->uh_dport);
	addr.dest = ntohs(udp->uh_sport);
	
	decode_nfs(&addr, buf, len);
}

static int
decode_tcp_nfs_half(struct tuple4 *addr, struct half_stream *hs)
{
	u_char *p, *buf;
	int i, len, discard;
	u_int32_t fraghdr;

	buf = hs->data;
	len = hs->count - hs->offset;
	discard = 0;
	
	for (p = buf; p + 4 < buf + len; ) {
		fraghdr = pntohl(p);
		p += 4 + FRAGLEN(fraghdr);
		
		if (p > buf + len)
			return (0);

		if (LASTFRAG(fraghdr)) {
			i = p - buf;
			
			decode_nfs(addr, buf, i);
			
			buf += i;
			len -= i;
			discard += i;
		}
	}
	return (discard);
}

static void
decode_tcp_nfs(struct tcp_stream *ts, void **darth)
{
	int len = 0;
	
	if (ts->addr.dest != 2049 && ts->addr.source != 2049)
		return;

	switch (ts->nids_state) {

	case NIDS_JUST_EST:
		ts->server.collect = 1;
		ts->client.collect = 1;
		break;

	case NIDS_DATA:
		if (ts->server.count_new > 0) {
			len = decode_tcp_nfs_half(&ts->addr, &ts->server);
		}
		else if (ts->client.count_new > 0) {
			len = decode_tcp_nfs_half(&ts->addr, &ts->client);
		}
		nids_discard(ts, len);
		break;
		
	default:
		if (ts->server.count > 0) {
			decode_tcp_nfs_half(&ts->addr, &ts->server);
		}
		else if (ts->client.count > 0) {
			decode_tcp_nfs_half(&ts->addr, &ts->client);
		}
		break;
	}
}

static void
null_syslog(int type, int errnum, struct ip *iph, void *data)
{
}

int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	int c;

	while ((c = getopt(argc, argv, "i:p:vh?V")) != -1) {
		switch (c) {
		case 'i':
			nids_params.device = optarg;
			break;
		case 'p':
			nids_params.filename = optarg;
			break;
		case 'v':
			Opt_invert = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 0 && strlen(argv[0])) {
		if ((pregex = (regex_t *) malloc(sizeof(*pregex))) == NULL)
			err(1, "malloc");
		if (regcomp(pregex, argv[0], REG_EXTENDED|REG_NOSUB) != 0)
			errx(1, "invalid regular expression");
	}
	if (argc > 1)
		nids_params.pcap_filter = copy_argv(argv + 1);
	nids_params.scan_num_hosts = 0;
	nids_params.syslog = null_syslog;
	
	fh_map_init();
	
	if (!nids_init())
		errx(1, "nids_init: %s", nids_errbuf);

	nids_register_ip(decode_udp_nfs);
	nids_register_tcp(decode_tcp_nfs);

        if (nids_params.pcap_filter != NULL) {
                if (nids_params.filename == NULL) {
                        warnx("listening on %s [%s]", nids_params.device,
                              nids_params.pcap_filter);
                }
                else {
                        warnx("using %s [%s]", nids_params.filename,
                              nids_params.pcap_filter);
                }
        }
        else {
                if (nids_params.filename == NULL) {
                        warnx("listening on %s", nids_params.device);
                }
                else {
                        warnx("using %s", nids_params.filename);
                }
        }

	nids_run();

	/* NOTREACHED */

	exit(0);
}
