/*
 * magic.c
 *
 * Network application protocol identification, based on file(1) magic.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 * Copyright (c) 1987 Ian F. Darwin
 *
 * This software is not subject to any license of the American Telephone
 * and Telegraph Company or of the Regents of the University of California.
 *
 * Permission is granted to anyone to use this software for any purpose on
 * any computer system, and to alter it and redistribute it freely, subject
 * to the following restrictions:
 *
 * 1. The author is not responsible for the consequences of use of this
 *    software, no matter how awful, even if they arise from flaws in it.
 *
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits must appear in the documentation.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits must appear in the documentation.
 *
 * 4. This notice may not be removed or altered.
 * 
 * $Id: magic.c,v 1.9 2001/03/15 08:33:04 dugsong Exp $
 */

#include "config.h"

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strlcpy.h>
#include <ctype.h>
#include <time.h>
#include <err.h>

#include "options.h"
#include "magic.h"

#define LOWCASE(p)	(isupper((u_char) (p)) ? tolower((u_char) (p)) : (p))

#define INDIR		1		/* if '>(...)' appears,  */
#define UNSIGNED	2		/* comparison is unsigned */
#define ADD		4		/* if '>&' appears,  */

#define	BYTE		1
#define SHORT		2
#define LONG		4
#define STRING		5
#define DATE		6
#define BESHORT		7
#define BELONG		8
#define BEDATE		9
#define LESHORT		10
#define LELONG		11
#define LEDATE		12

struct magic {
	short		flag;
	short		cont_level;
	struct {
		int8_t	type;		/* byte short long */
		int32_t	offset;		/* offset from indirection */
	} in;
	int32_t		offset;		/* offset to magic number. */
	u_char		reln;		/* relation (0=eq, '>'=gt, etc.) */
	int8_t		type;		/* int, short, long or string */
	char		vallen;		/* length of string value, if any */
	union VALUETYPE {
		u_char	b;
		u_short	h;
		u_int32_t l;
		char	s[32];
		u_char	hs[2];		/* 2 bytes of a fixed-endian "short" */
		u_char	hl[4];		/* 4 bytes of a fixed-endian "long" */
	} value;			/* either number or string */
	u_int32_t	mask;		/* mask before comparison with value */
	char		desc[50];	/* description */
};

static char *Magictypes[12] = {
	"byte",
	"short",
	"null",
	"long",
	"string",
	"date",
	"beshort",
	"belong",
	"bedate",
	"leshort",
	"lelong",
	"ledate",
};

static struct magic Magic[512];
static int Magiccnt = 0;
static int Magicmax = sizeof(Magic) / sizeof(Magic[0]);
static char Match[128];

static void
eatsize(char **p)
{
	char *l = *p;
	
	if (LOWCASE(*l) == 'u')
		l++;
	
	switch (LOWCASE(*l)) {
	case 'l':	/* long */
	case 's':	/* short */
	case 'h':	/* short */
	case 'b':	/* char/byte */
	case 'c':	/* char/byte */
		l++;
		/*FALLTHROUGH*/
	default:
		break;
	}
	*p = l;
}

/* Single hex char to int; -1 if not a hex char. */
static int
hextoint(int c)
{
	if (!isascii((u_char) c))	return (-1);
	if (isdigit((u_char) c))	return (c - '0');
	if ((c >= 'a') && (c <= 'f'))	return (c + 10 - 'a');
	if ((c >= 'A') && (c <= 'F'))	return (c + 10 - 'A');
	return (-1);
}

/*
 * Convert a string containing C character escapes.  Stop at an unescaped
 * space or tab.
 * Copy the converted version to "p", returning its length in *slen.
 * Return updated scan pointer as function result.
 */
static char *
getstr(char *s, char *p, int plen, int *slen)
{
	char	*origs = s, *origp = p;
	char	*pmax = p + plen - 1;
	int	c;
	int	val;
	
	while ((c = *s++) != '\0') {
		if (isspace((u_char) c))
			break;
		if (p >= pmax) {
			warnx("getstr: string too long: %s", origs);
			break;
		}
		if (c == '\\') {
			switch ((c = *s++)) {
			case '\0':
				goto out;
			default:
				*p++ = (char) c;
				break;
			case 'n':
				*p++ = '\n';
				break;
			case 'r':
				*p++ = '\r';
				break;
			case 'b':
				*p++ = '\b';
				break;
			case 't':
				*p++ = '\t';
				break;
			case 'f':
				*p++ = '\f';
				break;
			case 'v':
				*p++ = '\v';
				break;
			/* \ and up to 3 octal digits */
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
				val = c - '0';
				c = *s++;  /* try for 2 */
				if (c >= '0' && c <= '7') {
					val = (val << 3) | (c - '0');
					c = *s++;  /* try for 3 */
					if (c >= '0' && c <= '7')
						val = (val << 3) | (c - '0');
					else --s;
				}
				else --s;
				*p++ = (char) val;
				break;

			/* \x and up to 2 hex digits */
			case 'x':
				val = 'x';	/* Default if no digits */
				c = hextoint(*s++);	/* Get next char */
				if (c >= 0) {
					val = c;
					c = hextoint(*s++);
					if (c >= 0) val = (val << 4) + c;
					else --s;
				}
				else --s;
				*p++ = (char) val;
				break;
			}
		}
		else *p++ = (char) c;
	}
 out:
	*p = '\0';
	*slen = p - origp;
	
	return (s);
}

/* Extend the sign bit if the comparison is to be signed. */
static u_int32_t
signextend(struct magic *m, u_int32_t v)
{
	if (!(m->flag & UNSIGNED))
		return (v);
	
	switch(m->type) {
		/*
		 * Do not remove the casts below.  They are
		 * vital.  When later compared with the data,
		 * the sign extension must have happened.
		 */
	case BYTE:
		v = (char) v;
		break;
	case SHORT:
	case BESHORT:
	case LESHORT:
		v = (short) v;
		break;
	case DATE:
	case BEDATE:
	case LEDATE:
	case LONG:
	case BELONG:
	case LELONG:
		v = (int32_t) v;
		break;
	case STRING:
		break;
	default:
		warnx("sign_extend: can't happen: m->type = %d",
		      m->type);
		return (-1);
	}
	return (v);
}

/*
 * Read a numeric value from a pointer, into the value union of a magic
 * pointer, according to the magic type.  Update the string pointer to point
 * just after the number read.  Return 0 for success, non-zero for failure.
 */
static int
getvalue(struct magic *m, char **p)
{
	int slen;
	
	if (m->type == STRING) {
		*p = getstr(*p, m->value.s, sizeof(m->value.s), &slen);
		m->vallen = slen;
	}
	else if (m->reln != 'x') {
		m->value.l = signextend(m, strtoul(*p, p, 0));
		eatsize(p);
	}
	return (0);
}

#define SZOF(a) (sizeof(a) / sizeof(a[0]))

static void
mdump(struct magic *m)
{
	static char *typ[] = {   "invalid", "byte", "short", "invalid",
				 "long", "string", "date", "beshort",
				 "belong", "bedate", "leshort", "lelong",
				 "ledate" };
	(void) fputc('[', stderr);
	(void) fprintf(stderr, ">>>>>>>> %d" + 8 - (m->cont_level & 7),
		       m->offset);
	
	if (m->flag & INDIR)
		(void) fprintf(stderr, "(%s,%d),",
			       (m->in.type >= 0 && m->in.type < SZOF(typ)) ?
			       typ[(unsigned char) m->in.type] :
			       "*bad*",
			       m->in.offset);
	
	(void) fprintf(stderr, " %s%s", (m->flag & UNSIGNED) ? "u" : "",
		       (m->type >= 0 && m->type < SZOF(typ)) ?
		       typ[(unsigned char) m->type] :
		       "*bad*");
	if (m->mask != ~0)
		(void) fprintf(stderr, " & %.8x", m->mask);
	
	(void) fprintf(stderr, ",%c", m->reln);
	if (m->reln != 'x') {
		switch (m->type) {
		case BYTE:
		case SHORT:
		case LONG:
		case LESHORT:
		case LELONG:
		case BESHORT:
		case BELONG:
			(void) fprintf(stderr, "%d", m->value.l);
			break;
		case STRING:
			fprintf(stderr, "%s", m->value.s);
			break;
		case DATE:
		case LEDATE:
		case BEDATE:
		{
			char *rt, *pp = ctime((time_t*) &m->value.l);
			if ((rt = strchr(pp, '\n')) != NULL)
				*rt = '\0';
			(void) fprintf(stderr, "%s,", pp);
			if (rt)
				*rt = '\n';
		}
		break;
		default:
			(void) fputs("*bad*", stderr);
			break;
		}
	}
	(void) fprintf(stderr, ",\"%s\"]\n", m->desc);
}

static int
magic_parse(char *p)
{
	struct magic *m;
	char *t, *s;
	int i, j;
	
	if (Magiccnt + 1 > Magicmax)
		errx(1, "magic_parse: magic table full");
	
	m = &Magic[Magiccnt];
	m->flag = 0;
	m->cont_level = 0;

	while (*p == '>') {
		p++;		/* step over */
		m->cont_level++;
	}
	if (m->cont_level != 0 && *p == '(') {
		p++;		/* step over */
		m->flag |= INDIR;
	}
	if (m->cont_level != 0 && *p == '&') {
		p++;		/* step over */
		m->flag |= ADD;
	}
	/* Get offset, then skip over it. */
	m->offset = (int) strtoul(p, &t, 0);
	if (p == t)
		errx(1, "magic_parse: offset %s invalid", p);
	p = t;

	if (m->flag & INDIR) {
		m->in.type = LONG;
		m->in.offset = 0;

		/* read [.lbs][+-]nnnnn) */
		if (*p == '.') {
			p++;
			switch (LOWCASE(*p)) {
			case 'l':
				m->in.type = LONG;
				break;
			case 'h':
			case 's':
				m->in.type = SHORT;
				break;
			case 'c':
			case 'b':
				m->in.type = BYTE;
				break;
			default:
				errx(1, "magic_parse: indirect offset "
				     "type '%c' invalid", *p);
				break;
			}
			p++;
		}
		s = p;
		if (*p == '+' || *p == '-') p++;

		if (isdigit((u_char) *p)) {
			m->in.offset = strtoul(p, &t, 0);
			if (*s == '-') m->in.offset = - m->in.offset;
		}
		else t = p;
		
		if (*t++ != ')')
			errx(1, "magic_parse: missing ')' in indirect offset");
		p = t;
	}

	while (isascii((u_char) *p) && isdigit((u_char) *p)) p++;
	while (isascii((u_char) *p) && isspace((u_char) *p)) p++;

	if (*p == 'u') {
		p++;
		m->flag |= UNSIGNED;
	}
	/* Get type, skip it. */
	t = p;
	for (i = 0; i < 12; i++) {
		j = strlen(Magictypes[i]);
		if (strncmp(p, Magictypes[i], j) == 0) {
			m->type = i + 1;
			p += j;
			break;
		}
	}
	if (p == t)
		errx(1, "magic_parse: type %s invalid", p);
	
	/* New-style and'ing: "0 byte&0x80 =0x80 dynamically linked" */
	if (*p == '&') {
		p++;
		m->mask = signextend(m, strtoul(p, &p, 0));
		eatsize(&p);
	}
	else m->mask = ~0L;

	while (isascii((u_char) *p) && isspace((u_char) *p)) p++;

	switch(*p) {
	case '>':
	case '<':
		/* Old-style and'ing: "0 byte &0x80 dynamically linked" */
	case '&':
	case '^':
	case '=':
		m->reln = *p;
		p++;
		break;
	case '!':
		if (m->type != STRING) {
			m->reln = *p;
			p++;
			break;
		}
		/* FALLTHRU */
	default:
		if (*p == 'x' && isascii((u_char) p[1]) &&
		    isspace((u_char) p[1])) {
			m->reln = *p;
			p++;
			goto parse_get_desc;   /* Bill The Cat */
		}
		m->reln = '=';
		break;
	}
	while (isascii((u_char) *p) && isspace((u_char) *p)) p++;
	
	if (getvalue(m, &p))
		return (0);
	
 parse_get_desc:
	/* Now get last part - the description. */
	while (isascii((u_char) *p) && isspace((u_char) *p)) p++;
	
	strlcpy(m->desc, p, sizeof(m->desc));
	
	if (Opt_debug) {
		mdump(m);
	}
	Magiccnt++;
	return (1);
}

void
magic_init(char *filename)
{
	FILE *f;
	char buf[BUFSIZ];

	if ((f = fopen(filename, "r")) == NULL) {
		err(1, "magic_init");
	}
	memset(&Magic, 0, sizeof(Magic));
	
	while (fgets(buf, sizeof(buf), f) != NULL) {
		if (buf[0] == '#')
			continue;
		if (strlen(buf) <= 1)
			continue;
		buf[strlen(buf) - 1] = '\0';
		
		magic_parse(buf);
	}
	fclose(f);
}

/* Convert the byte order of the data we are looking at */
static int
mconvert(union VALUETYPE *p, struct magic *m)
{
	switch (m->type) {
	case BYTE:
	case SHORT:
	case LONG:
	case DATE:
		return (1);
	case STRING:
	{
		char *ptr;
		
		/* Null terminate and eat the return */
		p->s[sizeof(p->s) - 1] = '\0';
		if ((ptr = strchr(p->s, '\n')) != NULL)
			*ptr = '\0';
		return (1);
	}
	case BESHORT:
		p->h = (short)((p->hs[0]<<8)|(p->hs[1]));
		return (1);
	case BELONG:
	case BEDATE:
		p->l = (int32_t)((p->hl[0]<<24)|(p->hl[1]<<16)|
				 (p->hl[2]<<8)|(p->hl[3]));
		return (1);
	case LESHORT:
		p->h = (short)((p->hs[1]<<8)|(p->hs[0]));
		return (1);
	case LELONG:
	case LEDATE:
		p->l = (int32_t)((p->hl[3]<<24)|(p->hl[2]<<16)|
				 (p->hl[1]<<8)|(p->hl[0]));
		return (1);
	default:
		errx(1, "mconvert: invalid type %d", m->type);
	}
	return (0);
}

static int
mget(union VALUETYPE* p, u_char *s, struct magic *m, int nbytes)
{
	int32_t offset = m->offset;

	if (offset + sizeof(union VALUETYPE) <= nbytes)
		memcpy(p, s + offset, sizeof(*p));
	else {
		/*
		 * the usefulness of padding with zeroes eludes me, it
		 * might even cause problems
		 */
		int32_t have = nbytes - offset;
		memset(p, 0, sizeof(*p));
		if (have > 0)
			memcpy(p, s + offset, have);
	}
	if (!mconvert(p, m))
		return (0);

	if (m->flag & INDIR) {
		switch (m->in.type) {
		case BYTE:
			offset = p->b + m->in.offset;
			break;
		case SHORT:
			offset = p->h + m->in.offset;
			break;
		case LONG:
			offset = p->l + m->in.offset;
			break;
		}
		if (offset + sizeof(*p) > nbytes)
			return (0);
		
		memcpy(p, s + offset, sizeof(*p));
		
		if (!mconvert(p, m))
			return (0);
	}
	return (1);
}

static int
mcheck(union VALUETYPE* p, struct magic *m)
{
	register u_int32_t l = m->value.l;
	register u_int32_t v = 0;
	int matched;
	
	if ( (m->value.s[0] == 'x') && (m->value.s[1] == '\0') ) {
		warnx("mcheck: BOINK");
		return (1);
	}
	switch (m->type) {
	case BYTE:
		v = p->b;
		break;
	case SHORT:
	case BESHORT:
	case LESHORT:
		v = p->h;
		break;
	case LONG:
	case BELONG:
	case LELONG:
	case DATE:
	case BEDATE:
	case LEDATE:
		v = p->l;
		break;
	case STRING:
		l = 0;
		/* What we want here is:
		 * v = strncmp(m->value.s, p->s, m->vallen);
		 * but ignoring any nulls.  bcmp doesn't give -/+/0
		 * and isn't universally available anyway.
		 */
		v = 0;
		{
			register u_char *a = (u_char *) m->value.s;
			register u_char *b = (u_char *) p->s;
			register int len = m->vallen;
			
			while (--len >= 0)
				if ((v = *b++ - *a++) != '\0')
					break;
		}
		break;
	default:
		errx(1, "mcheck: invalid type %d", m->type);
		/* NOTREACHED */
	}
	v = signextend(m, v) & m->mask;
	
	switch (m->reln) {
	case 'x':
		matched = 1;
		break;
	case '!':
		matched = v != l;
		break;
	case '=':
		matched = v == l;
		break;
	case '>':
		if (m->flag & UNSIGNED) {
			matched = v > l;
		}
		else matched = (int32_t) v > (int32_t) l;
		break;
	case '<':
		if (m->flag & UNSIGNED) {
			matched = v < l;
		}
		else matched = (int32_t) v < (int32_t) l;
		break;
	case '&':
		matched = (v & l) == l;
		break;
	case '^':
		matched = (v & l) != l;
		break;
	default:
		matched = 0;
		errx(1, "mcheck: can't happen: invalid relation %d", m->reln);
		/* NOTREACHED */
	}
	if (matched && Opt_debug)
		mdump(m);
	
	return (matched);
}

static int32_t
mprint(union VALUETYPE *p, struct magic *m)
{
	int32_t t = 0;

	switch (m->type) {
	case BYTE:
		t = m->offset + sizeof(char);
		break;
	case SHORT:
	case BESHORT:
	case LESHORT:
		t = m->offset + sizeof(short);
		break;
	case LONG:
	case BELONG:
	case LELONG:
		t = m->offset + sizeof(int32_t);
		break;
	case STRING:
		if (m->reln == '=') {
			t = m->offset + strlen(m->value.s);
		}
		else {
			if (*m->value.s == '\0') {
				char *cp = strchr(p->s,'\n');
				if (cp)
					*cp = '\0';
			}
			t = m->offset + strlen(p->s);
		}
		break;
	case DATE:
	case BEDATE:
	case LEDATE:
		t = m->offset + sizeof(time_t);
		break;
	default:
		errx(1, "mprint: invalid m->type (%d)", m->type);
	}
	strncpy(Match, m->desc, sizeof(Match));
	
	return (t);
}


/*
 * Go through the whole list, stopping if you find a match.  Process all
 * the continuations of that match before returning.
 *
 * We support multi-level continuations:
 *
 *	At any time when processing a successful top-level match, there is a
 *	current continuation level; it represents the level of the last
 *	successfully matched continuation.
 *
 *	Continuations above that level are skipped as, if we see one, it
 *	means that the continuation that controls them - i.e, the
 *	lower-level continuation preceding them - failed to match.
 *
 *	Continuations below that level are processed as, if we see one,
 *	it means we've finished processing or skipping higher-level
 *	continuations under the control of a successful or unsuccessful
 *	lower-level continuation, and are now seeing the next lower-level
 *	continuation and should process it.  The current continuation
 *	level reverts to the level of the one we're seeing.
 *
 *	Continuations at the current level are processed as, if we see
 *	one, there's no lower-level continuation that may have failed.
 *
 *	If a continuation matches, we bump the current continuation level
 *	so that higher-level continuations are processed.
 */
char *
magic_match(u_char *s, int len)
{
	int i, cont_level = 0;
	union VALUETYPE p;
	static int32_t *tmpoff = NULL;
	static size_t tmplen = 0;
	int32_t oldoff = 0;

	Match[0] = '\0';
	
	if (tmpoff == NULL)
		if ((tmpoff = (int32_t *) malloc(tmplen = 20)) == NULL)
			err(1, "malloc");
	
	for (i = 0; i < Magiccnt; i++) {
		/* if main entry matches, print it... */
		if (!mget(&p, s, &Magic[i], len) || !mcheck(&p, &Magic[i])) {
			    /* 
			     * main entry didn't match,
			     * flush its continuations
			     */
			while (i < Magiccnt && Magic[i + 1].cont_level != 0)
				i++;
			continue;
		}
		tmpoff[cont_level] = mprint(&p, &Magic[i]);
		
		/* and any continuations that match */
		if (++cont_level >= tmplen) {
			tmplen += 20;
			if (!(tmpoff = (int32_t *) realloc(tmpoff, tmplen)))
				err(1, "magic_match: malloc");
		}
		while (Magic[i + 1].cont_level != 0 && ++i < Magiccnt) {
			if (cont_level >= Magic[i].cont_level) {
				if (cont_level > Magic[i].cont_level) {
					/*
					 * We're at the end of the level
					 * "cont_level" continuations.
					 */
					cont_level = Magic[i].cont_level;
				}
				if (Magic[i].flag & ADD) {
					oldoff = Magic[i].offset;
					Magic[i].offset +=
						tmpoff[cont_level - 1];
				}
				if (mget(&p, s, &Magic[i], len) &&
				    mcheck(&p, &Magic[i])) {
					/* This continuation matched. */
					tmpoff[cont_level] =
						mprint(&p, &Magic[i]);

					/*
					 * If we see any continuations
					 * at a higher level, process them.
					 */
					if (++cont_level >= tmplen) {
						tmplen += 20;
						if (!(tmpoff = (int32_t *)
						     realloc(tmpoff, tmplen)))
							err(1, "magic_check: "
							    "malloc");
					}
				}
				if (Magic[i].flag & ADD) {
					Magic[i].offset = oldoff;
				}
			}
		}
		return (strlen(Match) ? Match : NULL);	/* all through */
	}
	return (NULL);			/* no match at all */
}
