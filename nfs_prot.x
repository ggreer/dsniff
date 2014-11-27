/* minimal spec for filesnarf. */

/*
 * Copyright (c) 1987, 1997 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/* #pragma ident	"@(#)nfs_prot.x	1.5	97/06/21 SMI" */

%#include "config.h"

const NFS_PORT          = 2049;
const NFS_MAXDATA       = 8192;
const NFS_MAXPATHLEN    = 1024;
const NFS_MAXNAMLEN	= 255;
const NFS_FHSIZE	= 32;
const NFS_COOKIESIZE	= 4;
const NFS_FIFO_DEV	= -1;	/* size kludge for named pipes */

/*
 * File types
 */
const NFSMODE_FMT  = 0170000;	/* type of file */
const NFSMODE_DIR  = 0040000;	/* directory */
const NFSMODE_CHR  = 0020000;	/* character special */
const NFSMODE_BLK  = 0060000;	/* block special */
const NFSMODE_REG  = 0100000;	/* regular */
const NFSMODE_LNK  = 0120000;	/* symbolic link */
const NFSMODE_SOCK = 0140000;	/* socket */
const NFSMODE_FIFO = 0010000;	/* fifo */

/*
 * Error status
 */
enum nfsstat {
	NFS_OK= 0,		/* no error */
	NFSERR_PERM=1,		/* Not owner */
	NFSERR_NOENT=2,		/* No such file or directory */
	NFSERR_IO=5,		/* I/O error */
	NFSERR_NXIO=6,		/* No such device or address */
	NFSERR_ACCES=13,	/* Permission denied */
	NFSERR_EXIST=17,	/* File exists */
	NFSERR_XDEV=18,		/* Cross-device link */
	NFSERR_NODEV=19,	/* No such device */
	NFSERR_NOTDIR=20,	/* Not a directory*/
	NFSERR_ISDIR=21,	/* Is a directory */
	NFSERR_INVAL=22,	/* Invalid argument */
	NFSERR_FBIG=27,		/* File too large */
	NFSERR_NOSPC=28,	/* No space left on device */
	NFSERR_ROFS=30,		/* Read-only file system */
	NFSERR_OPNOTSUPP=45,	/* Operation not supported */
	NFSERR_NAMETOOLONG=63,	/* File name too long */
	NFSERR_NOTEMPTY=66,	/* Directory not empty */
	NFSERR_DQUOT=69,	/* Disc quota exceeded */
	NFSERR_STALE=70,	/* Stale NFS file handle */
	NFSERR_REMOTE=71,	/* Object is remote */
	NFSERR_WFLUSH=72	/* write cache flushed */
};

/*
 * File types
 */
enum ftype {
	NFNON = 0,	/* non-file */
	NFREG = 1,	/* regular file */
	NFDIR = 2,	/* directory */
	NFBLK = 3,	/* block special */
	NFCHR = 4,	/* character special */
	NFLNK = 5,	/* symbolic link */
	NFSOCK = 6,	/* unix domain sockets */
	NFBAD = 7,	/* unused */
	NFFIFO = 8 	/* named pipe */
};

/*
 * File access handle
 */
struct nfs_fh {
	opaque data[NFS_FHSIZE];
};

/* 
 * Timeval
 */
struct nfstime {
	unsigned seconds;
	unsigned useconds;
};


/*
 * File attributes
 */
struct fattr {
	ftype type;		/* file type */
	unsigned mode;		/* protection mode bits */
	unsigned nlink;		/* # hard links */
	unsigned uid;		/* owner user id */
	unsigned gid;		/* owner group id */
	unsigned size;		/* file size in bytes */
	unsigned blocksize;	/* prefered block size */
	unsigned rdev;		/* special device # */
	unsigned blocks;	/* Kb of disk used by file */
	unsigned fsid;		/* device # */
	unsigned fileid;	/* inode # */
	nfstime	atime;		/* time of last access */
	nfstime	mtime;		/* time of last modification */
	nfstime	ctime;		/* time of last change */
};

typedef string filename<NFS_MAXNAMLEN>; 
typedef string nfspath<NFS_MAXPATHLEN>;

/*
 * Arguments for directory operations
 */
struct diropargs {
	nfs_fh	dir;	/* directory file handle */
	filename name;		/* name (up to NFS_MAXNAMLEN bytes) */
};

struct diropokres {
	nfs_fh file;
	fattr attributes;
};

/*
 * Results from directory operation
 */
union diropres switch (nfsstat status) {
case NFS_OK:
	diropokres diropres;
default:
	void;
};

/*
 * Arguments to remote read
 */
struct readargs {
	nfs_fh file;		/* handle for file */
	unsigned offset;	/* byte offset in file */
	unsigned count;		/* immediate read count */
	unsigned totalcount;	/* total read count (from this offset)*/
};

/*
 * Status OK portion of remote read reply
 */
struct readokres {
	fattr	attributes;	/* attributes, need for pagin*/
	opaque data<NFS_MAXDATA>;
};

union readres switch (nfsstat status) {
case NFS_OK:
	readokres reply;
default:
	void;
};

/*
 * Remote file service routines
 */
program NFS_PROGRAM {
	version NFS_VERSION {
		void 
		NFSPROC_NULL(void) = 0;

		diropres 
		NFSPROC_LOOKUP(diropargs) = 4;

		readres 
		NFSPROC_READ(readargs) = 6;
	} = 2;
} = 100003;

/*
 * Version 3 declarations and definitions.
 */

/*
 * Sizes
 */
const NFS3_FHSIZE         = 64;
const NFS3_COOKIEVERFSIZE = 8;
const NFS3_CREATEVERFSIZE = 8;
const NFS3_WRITEVERFSIZE  = 8;

/*
 * Basic data types
 */
typedef u_int64_t	uint64;
typedef int64_t		int64;
typedef unsigned int	uint32;
typedef int		int32;
typedef string		filename3<>;
typedef string		nfspath3<>;
typedef uint64		fileid3;
typedef uint64		cookie3;
typedef opaque		cookieverf3[NFS3_COOKIEVERFSIZE];
typedef opaque		createverf3[NFS3_CREATEVERFSIZE];
typedef opaque		writeverf3[NFS3_WRITEVERFSIZE];
typedef uint32		uid3;
typedef uint32		gid3;
typedef uint64		size3;
typedef uint64		offset3;
typedef uint32		mode3;
typedef uint32		count3;

/*
 * Error status
 */
enum nfsstat3 {
	NFS3_OK = 0,
	NFS3ERR_PERM = 1,
	NFS3ERR_NOENT = 2,
	NFS3ERR_IO = 5,
	NFS3ERR_NXIO = 6,
	NFS3ERR_ACCES = 13,
	NFS3ERR_EXIST = 17,
	NFS3ERR_XDEV = 18,
	NFS3ERR_NODEV = 19,
	NFS3ERR_NOTDIR = 20,
	NFS3ERR_ISDIR = 21,
	NFS3ERR_INVAL = 22,
	NFS3ERR_FBIG = 27,
	NFS3ERR_NOSPC = 28,
	NFS3ERR_ROFS = 30,
	NFS3ERR_MLINK = 31,
	NFS3ERR_NAMETOOLONG = 63,
	NFS3ERR_NOTEMPTY = 66,
	NFS3ERR_DQUOT = 69,
	NFS3ERR_STALE = 70,
	NFS3ERR_REMOTE = 71,
	NFS3ERR_BADHANDLE = 10001,
	NFS3ERR_NOT_SYNC = 10002,
	NFS3ERR_BAD_COOKIE = 10003,
	NFS3ERR_NOTSUPP = 10004,
	NFS3ERR_TOOSMALL = 10005,
	NFS3ERR_SERVERFAULT = 10006,
	NFS3ERR_BADTYPE = 10007,
	NFS3ERR_JUKEBOX = 10008
};

/*
 * File types
 */
enum ftype3 {
	NF3REG = 1,
	NF3DIR = 2,
	NF3BLK = 3,
	NF3CHR = 4,
	NF3LNK = 5,
	NF3SOCK = 6,
	NF3FIFO = 7
};

struct specdata3 {
	uint32	specdata1;
	uint32	specdata2;
};

/*
 * File access handle
 */
struct nfs_fh3 {
	opaque data<NFS3_FHSIZE>;
};

/* 
 * Timeval
 */
struct nfstime3 {
	uint32 seconds;
	uint32 nseconds;
};

/*
 * File attributes
 */
struct fattr3 {
	ftype3	  type;
	mode3	  mode;
	uint32	  nlink;
	uid3	  uid;
	gid3	  gid;
	size3	  size;
	size3	  used;
	specdata3 rdev;
	uint64	  fsid;
	fileid3	  fileid;
	nfstime3  atime;
	nfstime3  mtime;
	nfstime3  ctime;
};

/*
 * File attributes
 */
union post_op_attr switch (bool attributes_follow) {
case TRUE:
	fattr3 attributes;
case FALSE:
	void;
};	

struct wcc_attr {
	size3	 size;
	nfstime3 mtime;
	nfstime3 ctime;
};

union pre_op_attr switch (bool attributes_follow) {
case TRUE:
	wcc_attr attributes;
case FALSE:
	void;
};

struct wcc_data {
	pre_op_attr  before;
	post_op_attr after;
};

struct diropargs3 {
	nfs_fh3   dir;
	filename3 name;
};

/*
 * LOOKUP: Lookup filename
 */
struct LOOKUP3args {
	diropargs3 what;
};

struct LOOKUP3resok {
	nfs_fh3		object;
	post_op_attr	obj_attributes;
	post_op_attr	dir_attributes;
};

struct LOOKUP3resfail {
	post_op_attr	dir_attributes;
};

union LOOKUP3res switch (nfsstat3 status) {
case NFS3_OK:
	LOOKUP3resok	resok;
default:
	LOOKUP3resfail	resfail;
};

/*
 * READ: Read from file
 */
struct READ3args {
	nfs_fh3		file;
	offset3		offset;
	count3		count;
};

struct READ3resok {
	post_op_attr	file_attributes;
	count3		count;
	bool		eof;
	opaque		data<>;
};

struct READ3resfail {
	post_op_attr	file_attributes;
};

union READ3res switch (nfsstat status) {
case NFS3_OK:
	READ3resok	resok;
default:
	READ3resfail	resfail;
};

/*
 * Remote file service routines
 */
program NFS3_PROGRAM {
	version NFS_V3 {
		void 
		NFSPROC3_NULL(void) = 0;

		LOOKUP3res 
		NFSPROC3_LOOKUP(LOOKUP3args) = 3;

		READ3res 
		NFSPROC3_READ(READ3args) = 6;
	} = 3;
} = 100003;
