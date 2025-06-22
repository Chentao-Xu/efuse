#ifndef _PATCH_H
#define _PATCH_H

// from linux-6.5/include/uapi/linux/fuse.h
/**
 * Bitmasks for fuse_setattr_in.valid
 */
#define FATTR_MODE	(1 << 0)
#define FATTR_UID	(1 << 1)
#define FATTR_GID	(1 << 2)
#define FATTR_SIZE	(1 << 3)
#define FATTR_ATIME	(1 << 4)
#define FATTR_MTIME	(1 << 5)
#define FATTR_FH	(1 << 6)
#define FATTR_ATIME_NOW	(1 << 7)
#define FATTR_MTIME_NOW	(1 << 8)
#define FATTR_LOCKOWNER	(1 << 9)
#define FATTR_CTIME	(1 << 10)
#define FATTR_KILL_SUIDGID	(1 << 11)

// from linux-6.5/include/generated/uapi/linux/version.h
#define LINUX_VERSION_CODE 394496
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
#define LINUX_VERSION_MAJOR 6
#define LINUX_VERSION_PATCHLEVEL 5
#define LINUX_VERSION_SUBLEVEL 0

#endif /* _PATCH_H */