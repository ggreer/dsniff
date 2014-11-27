/*
 * record.c
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: record.c,v 1.10 2001/03/15 08:33:04 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>
#include <netinet/in.h>
#include <rpc/rpc.h>

#include <stdio.h>
#include <time.h>
#include <md5.h>
#ifdef HAVE_DB_185_H
#define DB_LIBRARY_COMPATIBILITY_API
#include <db_185.h>
#elif HAVE_DB_H
#include <db.h>
#endif
#include <libnet.h>

#include "options.h"
#include "record.h"

struct rec {
	time_t		time;
	in_addr_t	src;
	in_addr_t	dst;
	u_int		proto;
	u_short		sport;
	u_short		dport;
	struct netobj	name;
	struct netobj	data;
};
	
static DB *db;

static int
xdr_rec(XDR *xdrs, struct rec *rec)
{
	if (xdr_u_long(xdrs, (u_long *)&rec->time) &&
	    xdr_u_long(xdrs, (u_long *)&rec->src) &&
	    xdr_u_long(xdrs, (u_long *)&rec->dst) &&
	    xdr_u_int(xdrs, &rec->proto) &&
	    xdr_u_short(xdrs, &rec->sport) &&
	    xdr_u_short(xdrs, &rec->dport) &&
	    xdr_netobj(xdrs, &rec->name) &&
	    xdr_netobj(xdrs, &rec->data)) {
		return (1);
	}
	return (0);
}

static void
record_print(struct rec *rec)
{
	struct tm *tm;
	char *srcp, *dstp, *protop, tstr[24], spstr[8], dpstr[8];
	struct protoent *pr;
	
	tm = localtime(&rec->time);
	strftime(tstr, sizeof(tstr), "%x %X", tm);
	
	srcp = libnet_addr2name4(rec->src, Opt_dns);
	dstp = libnet_addr2name4(rec->dst, Opt_dns);

	if ((pr = getprotobynumber(rec->proto)) == NULL)
		protop = "unknown";
	else
		protop = pr->p_name;
	
	snprintf(spstr, sizeof(spstr), "%d", rec->sport);
	snprintf(dpstr, sizeof(dpstr), "%d", rec->dport);

	printf("-----------------\n");
	printf("%s %s %s%s%s -> %s%s%s (%.*s)\n",
	       tstr, protop,
	       srcp, rec->sport ? "." : "", rec->sport ? spstr : "",
	       dstp, rec->dport ? "." : "", rec->dport ? dpstr : "",
	       (int) rec->name.n_len, rec->name.n_bytes);

	fwrite(rec->data.n_bytes, 1, rec->data.n_len, stdout);
	printf("\n");
	
	fflush(stdout);
}

static DBT *
record_hash(struct rec *rec)
{
	static DBT key;
	static u_char hash[16];
	MD5_CTX ctx;

	/* Unique key: src/dst IPs, decode type, decode data. */
	
	MD5Init(&ctx);
	MD5Update(&ctx, (u_char *) &rec->src, sizeof(rec->src));
	MD5Update(&ctx, (u_char *) &rec->dst, sizeof(rec->dst));
	MD5Update(&ctx, rec->name.n_bytes, rec->name.n_len);
	MD5Update(&ctx, rec->data.n_bytes, rec->data.n_len);
	MD5Final(hash, &ctx);

	key.data = hash;
	key.size = sizeof(hash);
	
	return (&key);
}

static int
record_save(struct rec *rec)
{
	DBT *key, data;
	XDR xdrs;
	u_char buf[2048];
	
	xdrmem_create(&xdrs, buf, sizeof(buf), XDR_ENCODE);
	
	if (!xdr_rec(&xdrs, rec))
		return (0);
	
	data.data = buf;
	data.size = xdr_getpos(&xdrs);
	
	xdr_destroy(&xdrs);

	key = record_hash(rec);
	
	if (db->put(db, key, &data, R_NOOVERWRITE) == 0)
		db->sync(db, 0);
	
	return (1);
}

void
record_dump(void)
{
	DBT key, data;
	XDR xdrs;
	struct rec rec;
	
	while (db->seq(db, &key, &data, R_NEXT) == 0) {	
		memset(&rec, 0, sizeof(rec));
		xdrmem_create(&xdrs, data.data, data.size, XDR_DECODE);
		
		if (xdr_rec(&xdrs, &rec)) {
			record_print(&rec);
		}
		xdr_destroy(&xdrs);
	}
}

int
record_init(char *file)
{
	int flags, mode;
	
	if (Opt_read) {
		flags = O_RDONLY;
		mode = 0;
	}
	else {
		flags = O_RDWR|O_CREAT;
		mode = S_IRUSR|S_IWUSR;
	}
	if ((db = dbopen(file, flags, mode, DB_BTREE, NULL)) == NULL)
		return (0);

	return (1);
}

int
record(in_addr_t src, in_addr_t dst, int proto, u_short sport, u_short dport,
       char *name, u_char *buf, int len)
{
	struct rec rec;

	rec.time = time(NULL);
	
	rec.src = src;
	rec.dst = dst;
	
	rec.proto = proto;
	
	rec.sport = sport;
	rec.dport = dport;
	
	rec.name.n_bytes = name;
	rec.name.n_len = strlen(name);
	
	rec.data.n_bytes = buf;
	rec.data.n_len = len;

	if (!Opt_read && !Opt_write)
		record_print(&rec);

	record_save(&rec);

	return (1);
}

void
record_close(void)
{
	db->close(db);
}

