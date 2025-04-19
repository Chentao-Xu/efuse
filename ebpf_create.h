#ifndef __EBPF_CREATE_H__
#define __EBPF_CREATE_H__

/* The node structure that we maintain as our local cache which maps
 * the ino numbers to their full path, this address is stored as part
 * of the value of the linked list of nodes */
struct lo_inode {

    struct lo_inode *next;  /* per-dir sibling list */
    struct lo_inode *child; /* first contained file by this dir */
    struct lo_inode *parent;    /* containing directory */

    /* Full path of the underlying ext4 path
     * correspoding to its ino (easy way to extract back) */
    char *name;
    unsigned int namelen;

    /* Inode numbers and dev no's of
     * underlying EXT4 F/s for the above path */
    uint64_t ino;
    unsigned long dev;

    /* inode number sent to lower F/S */
    uint64_t lo_ino;
	/* parent inode */
	uint64_t pino;

	/* Lookup count of this node */
	uint64_t nlookup;

    /* Stats */
    int deleted;
};

/** Directory entry parameters supplied to fuse_reply_entry() */
struct fuse_entry_param {
	/** Unique inode number
	 *
	 * In lookup, zero means negative entry (from version 2.5)
	 * Returning ENOENT also means negative entry, but by setting zero
	 * ino the kernel may cache negative entries for entry_timeout
	 * seconds.
	 */
	uint64_t ino;

	/** Generation number for this entry.
	 *
	 * If the file system will be exported over NFS, the
	 * ino/generation pairs need to be unique over the file
	 * system's lifetime (rather than just the mount time). So if
	 * the file system reuses an inode after it has been deleted,
	 * it must assign a new, previously unused generation number
	 * to the inode at the same time.
	 *
	 */
	uint64_t generation;

	/** Inode attributes.
	 *
	 * Even if attr_timeout == 0, attr must be correct. For example,
	 * for open(), FUSE uses attr.st_size from lookup() to determine
	 * how many bytes to request. If this value is not correct,
	 * incorrect data will be returned.
	 */
	struct stat attr;

	/** Validity timeout (in seconds) for inode attributes. If
	    attributes only change as a result of requests that come
	    through the kernel, this should be set to a very large
	    value. */
	double attr_timeout;

	/** Validity timeout (in seconds) for the name. If directory
	    entries are changed/deleted only as a result of requests
	    that come through the kernel, this should be set to a very
	    large value. */
	double entry_timeout;
};


typedef struct create_args {
    uint8_t inode_is_null;
    int namelen;
    double attr_timeout;
    double entry_timeout;
    struct lo_inode inode;
    struct lo_inode pinode;
    struct fuse_entry_param e;
    char name[256];
    // char inode_name[256];
} create_args_t;

#endif /* __EBPF_CREATE_H__ */