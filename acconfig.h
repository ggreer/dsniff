/* Define to 'uint32_t' if <sys/types.h> doesn't define. */
#undef u_int32_t

/* Define to 'uint64_t' if <sys/types.h> doesn't define. */
#undef u_int64_t

/* Define to 'u_int32_t' if <sys/types.h> doesn't define. */
#undef in_addr_t

/* Define if you have the <db.h> header file.  */
#undef HAVE_DB_H

/* Define if you have the <db_185.h> header file.  */
#undef HAVE_DB_185_H

/* Should be in <sys/param.h>, *sigh* */
#undef HAVE_MINMAX
#ifndef HAVE_MINMAX
#define MIN(a,b)	(((a)<(b))?(a):(b))
#define MAX(a,b)	(((a)>(b))?(a):(b))
#endif

