/*
 * This module has the kernel code for ExtFUSE
 */
#define KBUILD_MODNAME "extfuse"
#include "vmlinux.h"
#include <linux/limits.h>
#include "stringify.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "ebpf.h"
#include "extfuse.h"
// #include "fuse_i.h"
#include "patch.h"

#include "ebpf_lookup.h"
#include "ebpf_attr.h"
#include "ebpf_create.h"

/********************************************************************
	HELPERS
*********************************************************************/

// #define DEBUGNOW

/* #define HAVE_PASSTHRU */

#ifndef DEBUGNOW
#define PRINTK(fmt, ...)
#else
#define PRINTK bpf_printk
#endif

// #define HANDLER(F) SEC("extfuse/"__stringify(F)) int bpf_func_##F
#define HANDLER(F) SEC("sk_msg") int bpf_func_##F

/*
	BPF_MAP_TYPE_PERCPU_HASH: each CPU core gets its own hash-table.
	BPF_MAP_TYPE_LRU_PERCPU_HASH: all cores share one hash-table but have they own LRU structures of the table.
*/
// struct bpf_map_def SEC("maps") entry_map = {
// 	.type			= BPF_MAP_TYPE_HASH,	// simple hash list
// 	.key_size		= sizeof(lookup_entry_key_t),
// 	.value_size		= sizeof(lookup_entry_val_t),
// 	.max_entries	= MAX_ENTRIES,
// 	.map_flags		= BPF_F_NO_PREALLOC,
// };
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, lookup_entry_key_t);
	__type(value, lookup_entry_val_t);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} entry_map SEC(".maps");

/* order of maps is important */
// struct bpf_map_def SEC("maps") attr_map = {
// 	.type			= BPF_MAP_TYPE_HASH,	// simple hash list
// 	.key_size		= sizeof(lookup_attr_key_t),
// 	.value_size		= sizeof(lookup_attr_val_t),
// 	.max_entries	= MAX_ENTRIES,
// 	.map_flags		= BPF_F_NO_PREALLOC,
// };
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, lookup_attr_key_t);
	__type(value, lookup_attr_val_t);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} attr_map SEC(".maps");

/* BPF_MAP_TYPE_PROG_ARRAY must ALWAYS be the last one */
// struct bpf_map_def SEC("maps") handlers = {
//    .type = BPF_MAP_TYPE_PROG_ARRAY,
//    .key_size = sizeof(u32),
//    .value_size = sizeof(u32),
//    .max_entries = FUSE_OPS_COUNT << 1,
// };
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, FUSE_OPS_COUNT << 1);
	__type(key, u32);
	__type(value, u32);
} handlers SEC(".maps");

int SEC("sk_msg") fuse_xdp_main_handler(void *ctx)
{
    struct extfuse_req *args = (struct extfuse_req *)ctx;
	__u32 opcode = 0;
    bpf_core_read(&opcode, sizeof(opcode), &args->in.h.opcode);

	bpf_printk("in fuse_xdp_main_handler opcode: %d\n", opcode);

	bpf_tail_call(ctx, &handlers, opcode);
	bpf_printk("opcode not handled: %d\n", opcode);
	return UPCALL;
}

static int gen_entry_key(void *ctx, int param, const char *op, lookup_entry_key_t *key)
{
	int64_t ret = bpf_extfuse_read_args(ctx, NODEID, &key->nodeid, sizeof(u64));
	if (ret < 0) {
		PRINTK("%s: Failed to read nodeid: %d!\n", op, ret);
		return ret;
	}

	ret = bpf_extfuse_read_args(ctx, param, key->name, NAME_MAX);
	if (ret < 0) {
		PRINTK("%s: Failed to read param %d: %d!\n", op, param, ret);
		return ret;
	}

	return 0;	
}

static int gen_attr_key(void *ctx, int param, const char *op, lookup_attr_key_t *key)
{
	int64_t ret = bpf_extfuse_read_args(ctx, NODEID, &key->nodeid, sizeof(u64));
	if (ret < 0) {
		PRINTK("%s: Failed to read nodeid: %d!\n", op, ret);
		return ret;
	}

	return 0;
}

static void create_lookup_entry(struct fuse_entry_out *out,
				lookup_entry_val_t *entry, struct fuse_attr_out *attr)
{
	// memset(out, 0, sizeof(*out));
	__builtin_memset(out, 0, sizeof(*out));
	out->nodeid				= entry->nodeid;
	out->generation			= entry->generation;
	out->entry_valid		= entry->entry_valid;
	out->entry_valid_nsec	= entry->entry_valid_nsec;
	if (attr) {
		out->attr_valid			= attr->attr_valid;
		out->attr_valid_nsec	= attr->attr_valid_nsec;
    	out->attr.ino			= attr->attr.ino;
    	out->attr.mode			= attr->attr.mode;
    	out->attr.nlink			= attr->attr.nlink;
    	out->attr.uid			= attr->attr.uid;
    	out->attr.gid			= attr->attr.gid;
    	out->attr.rdev			= attr->attr.rdev;
    	out->attr.size			= attr->attr.size;
    	out->attr.blksize		= attr->attr.blksize;
    	out->attr.blocks		= attr->attr.blocks;
    	out->attr.atime			= attr->attr.atime;
    	out->attr.mtime			= attr->attr.mtime;
    	out->attr.ctime			= attr->attr.ctime;
    	out->attr.atimensec		= attr->attr.atimensec;
    	out->attr.mtimensec		= attr->attr.mtimensec;
    	out->attr.ctimensec		= attr->attr.ctimensec;
	}
}

// new_node and new_node->name should have been allocated before calling this function
static void create_node(struct lo_inode *new_node, struct lo_inode *parent, const char *name, size_t namelen)
{
    // memcpy(new_node->name, name, namelen + 1);
	// __builtin_memcpy(new_node->name, name, namelen + 1);
    new_node->namelen = namelen;
    //node->ino = fuse->global->inode_ctr++;
    //node->gen = fuse->global->next_generation++;

    /* store this for mapping (debugging) */
    new_node->lo_ino = (uintptr_t) new_node;
    new_node->deleted = 0;
	new_node->pino = parent->ino == 1 ? 1 : (uintptr_t) parent;
	new_node->nlookup++;
    // add_node_to_parent_locked(new_node, parent);
	new_node->parent = parent;
	new_node->next = parent->child;
	parent->child = new_node;
    return;
}

HANDLER(FUSE_CREATE_ENTRY)(void *ctx)
{
#ifdef ENABLE_JFUSE_CREATE
	bpf_printk("Enter FUSE_CREATE_ENTRY\n");
	create_args_t *args = (create_args_t *)ctx;
	args->inode_is_null = 0;
	struct lo_inode *inode = &args->inode;
	struct fuse_entry_param *e = &args->e;

	int64_t res=0;

	// res = lstat(cpath, &e->attr);

	if (res) {
		// ERROR("[%d] \t %s(%s) lstat(%s) failed: %s\n",
		// 	gettid(), op, name, cpath, strerror(errno));
		// fuse_reply_err(req, errno);
		bpf_printk("lstat failed, err: %d\n", res);
		return -1;
	} else {
		// inode = lookup_child_by_name_locked(pinode, name);
    	if (args->inode_is_null)
			// acquire_node_locked(inode);
			inode->nlookup++;
    	else
			// inode = create_node_locked(pinode, name);
			create_node(inode, &args->pinode, args->name, args->namelen);
		if (!inode) {
			// ERROR("[%d] \t %s(%s) node creation failed: %s\n",
			// 		gettid(), op, name, strerror(errno));
			// pthread_mutex_unlock(&lo_data->mutex);
			// if (time)
			// 	fuse_reply_err(req, ENOMEM);
			bpf_printk("node creation failed, err: %d\n", res);
			return -1;
		}

		// INFO("[%d] \t %s new node %s id: %p\n",
		// 		gettid(), op, cpath, inode);

		inode->ino = e->attr.st_ino;
		inode->dev = e->attr.st_dev;

		e->attr_timeout = args->attr_timeout;
		e->entry_timeout = args->entry_timeout;

		/* store this for mapping (debugging) */
		e->ino = inode->lo_ino;

		// res = lookup_fetch(get_lo_data(req)->ebpf_ctxt, inode->pino,
		// 		inode->name);
		// if (res && !errno) {
		// 	INFO("[%d] \t Fetched %s nlookup: %ld inode->nlookup: %ld\n",
		// 		gettid(), res < 0 ? "stale" : "", res, inode->nlookup);
		// 	if (res < 0)
		// 		res = -res;
		// 	inode->nlookup = res + 1;
		// }
		// res = lookup_insert(get_lo_data(req)->ebpf_ctxt, inode->pino,
		// 		inode->name, inode->nlookup, e);
		// if (res)
		// 	ERROR("[%d] \t %s new node %s id: %p: %s\n",
		// 		gettid(), op, cpath, inode, strerror(errno));
	}
#endif
	return RETURN;
}

HANDLER(FUSE_LOOKUP)(void *ctx)
{
	struct extfuse_req *args = (struct extfuse_req *)ctx;
	//unsigned numargs = args->in.numargs;
	int ret = UPCALL;

#ifdef DEBUGNOW
	u64 nid = args->in.h.nodeid;
	const char *name = (const char *)args->in.args[0].value;
	const unsigned int len = args->in.args[0].size - 1;

	PRINTK("LOOKUP: parent nodeid: 0x%llx name: %s(%d)\n",
			nid, name, len);
#endif

	lookup_entry_key_t key = {0, {0}};

	// memset(key.name, 0, NAME_MAX);
	__builtin_memset(key.name, 0, NAME_MAX);
	ret = gen_entry_key(ctx, IN_PARAM_0_VALUE, "LOOKUP", &key);
	if (ret < 0)
		return UPCALL;

	//PRINTK("key name: %s nodeid: 0x%llx\n", key.name, key.nodeid);
	
	lookup_entry_val_t *entry = bpf_map_lookup_elem(&entry_map, &key);
	if (!entry || entry->stale) {
		if (entry && entry->stale)
			PRINTK("LOOKUP: STALE key name: %s nodeid: 0x%llx\n",
				key.name, key.nodeid);
		else
			PRINTK("LOOKUP: No entry for node %s\n", key.name);
		return UPCALL;
	}

	PRINTK("LOOKUP(0x%llx, %s): nlookup %lld\n",
		key.nodeid, key.name, entry->nlookup);

	/* prepare output */
	struct fuse_entry_out out;
	uint64_t nodeid = entry->nodeid;


	/* negative entries have no attr */
	if (!nodeid) {
		create_lookup_entry(&out, entry, NULL);
	} else {
		lookup_attr_val_t *attr = bpf_map_lookup_elem(&attr_map, &nodeid);
		if (!attr || attr->stale) {
			if (attr && attr->stale)
				PRINTK("LOOKUP: STALE attr for node: 0x%llx\n", nodeid);
			else {
				PRINTK("LOOKUP: No attr for node 0x%llx\n", nodeid);
				return UPCALL;
			}
		}

		PRINTK("LOOKUP nodeid 0x%llx attr ino: 0x%llx\n",
				entry->nodeid, attr->out.attr.ino);

		create_lookup_entry(&out, entry, &attr->out);
	}

	/* populate output */
	ret = bpf_extfuse_write_args(ctx, OUT_PARAM_0, &out, sizeof(out));
	if (ret) {
		PRINTK("LOOKUP: Failed to write param 0: %d!\n", ret);
		return UPCALL;
	}

	/* atomic incr to avoid data races with user/other cpus */
	__sync_fetch_and_add(&entry->nlookup, 1);
	return RETURN;
}

HANDLER(FUSE_GETATTR)(void *ctx)
{
	lookup_attr_key_t key = {0};
	int ret = gen_attr_key(ctx, IN_PARAM_0_VALUE, "GETATTR", &key);
	if (ret < 0)
		return UPCALL;

	/* get cached attr value */
	lookup_attr_val_t *attr = bpf_map_lookup_elem(&attr_map, &key);
	if (!attr) {
		PRINTK("GETATTR: No attr for node 0x%llx\n", key.nodeid);
		return UPCALL;
	}

	/* check if the attr is stale */
	if (attr->stale) {
		/* what does the caller want? */
		struct fuse_getattr_in inarg;
		ret = bpf_extfuse_read_args(ctx, IN_PARAM_0_VALUE, &inarg, sizeof(inarg));
		if (ret < 0) {
			PRINTK("GETATTR: Failed to read param 0: %d!\n", ret);
			return UPCALL;
		}

		/* check if the attr that the caller wants is stale */
		if (attr->stale & inarg.dummy) {
			PRINTK("GETATTR: STALE attr mask: 0x%x stale: 0x%x for node: 0x%llx\n",
				inarg.dummy, attr->stale, key.nodeid);
			return UPCALL;
		}
	}

	PRINTK("GETATTR(0x%llx): %lld\n", key.nodeid, attr->out.attr.ino);

	/* populate output */
	ret = bpf_extfuse_write_args(ctx, OUT_PARAM_0, &attr->out, sizeof(attr->out));
	if (ret) {
		PRINTK("GETATTR: Failed to write param 0: %d!\n", ret);
		return UPCALL;
	}

	return RETURN;
}

HANDLER(FUSE_READ)(void *ctx)
{
	lookup_attr_key_t key = {0};
	int ret = gen_attr_key(ctx, IN_PARAM_0_VALUE, "READ", &key);
	if (ret < 0)
		return UPCALL;

	/* get cached attr value */
	lookup_attr_val_t *attr = bpf_map_lookup_elem(&attr_map, &key);
	if (!attr)
		return UPCALL;

#ifndef HAVE_PASSTHRU
	if (attr->stale & FATTR_ATIME)
			return UPCALL;
#endif

	/* mark as stale to prevent future references to cached attrs */
	__sync_fetch_and_add(&attr->stale, FATTR_ATIME);									
																			
	/* delete to prevent future cached attrs */
	//bpf_map_delete_elem(&attr_map, &key.nodeid);
	PRINTK("READ: marked stale attr for node 0x%llx\n", key.nodeid);

#ifdef HAVE_PASSTHRU
	return PASSTHRU;
#else
	return UPCALL;
#endif
}

HANDLER(FUSE_WRITE)(void *ctx)
{
	lookup_attr_key_t key = {0};
	int ret = gen_attr_key(ctx, IN_PARAM_0_VALUE, "WRITE", &key);
	if (ret < 0)
		return UPCALL;

	/* get cached attr value */
	lookup_attr_val_t *attr = bpf_map_lookup_elem(&attr_map, &key);
	if (!attr)
		return UPCALL;

#ifndef HAVE_PASSTHRU
	if (attr->stale & (FATTR_ATIME | FATTR_SIZE | FATTR_MTIME))
		return UPCALL;
#endif
	/* mark as stale to prevent future references to cached attrs */
	__sync_fetch_and_add(&attr->stale, (FATTR_ATIME | FATTR_SIZE | FATTR_MTIME));

	/* delete to prevent future cached attrs */
	//bpf_map_delete_elem(&attr_map, &key.nodeid);
	PRINTK("WRITE: marked stale attr for node 0x%llx\n", key.nodeid);

#ifdef HAVE_PASSTHRU
	return PASSTHRU;
#else
	return UPCALL;
#endif
}

HANDLER(FUSE_SETATTR)(void *ctx)
{
	lookup_attr_key_t key = {0};
	int ret = gen_attr_key(ctx, IN_PARAM_0_VALUE, "SETATTR", &key);
	if (ret < 0)
		return UPCALL;

	/* delete to prevent future cached attrs */
	bpf_map_delete_elem(&attr_map, &key.nodeid);
	PRINTK("SETATTR: deleted stale attr for node 0x%llx\n", key.nodeid);

	return UPCALL;
}

HANDLER(FUSE_GETXATTR)(void *ctx)
{
	PRINTK("GETXATTR: returning ENODATA\n");
	return UPCALL;
}

HANDLER(FUSE_FLUSH)(void *ctx)
{
	return RETURN;
}

#ifndef DEBUGNOW
static int remove(void *ctx, int param, char *op, lookup_entry_key_t *key)
{																			
	// memset(key->name, 0, NAME_MAX);											
	__builtin_memset(key->name, 0, NAME_MAX);
																			
	if (gen_entry_key(ctx, param, op, key))								
		return UPCALL;														
																			
	/* lookup entry using its key <parent inode number, name> */			
	lookup_entry_val_t *entry = bpf_map_lookup_elem(&entry_map, key);		
	if (!entry || entry->stale)												
		return UPCALL;														
																			
	/* mark as stale to prevent future cached lookups for this entry */		
	__sync_fetch_and_add(&entry->stale, 1);									
																			
	PRINTK("%s key name: %s nodeid: 0x%llx", op, key->name, key->nodeid);		
	PRINTK("\t nlookup %lld Marked Stale!\n", entry->nlookup);				
																			
	/*																		
	 * if the entry is negative (i.e., nodeid=0) or has only one reference	
	 * (i.e., nlookup=1), delete it because the user-space does not track	
	 * negative entries, and knows about entries with single reference.		
	 */																		
	uint64_t nodeid = entry->nodeid;										
	if (nodeid) {															
		bpf_map_delete_elem(&attr_map, &nodeid);							
		PRINTK("\t Deleted stale attr for node 0x%llx\n", nodeid);			
	}																		
	if (entry->nlookup <= 1) {												
		bpf_map_delete_elem(&entry_map, key);								
		PRINTK("\t Deleted stale node 0x%llx\n", nodeid);					
	}																		
																			
	return UPCALL;															
}
#endif

HANDLER(FUSE_RENAME)(void *ctx)
{
#ifndef DEBUGNOW
	lookup_entry_key_t key = {0, {0}};										
	remove(ctx, IN_PARAM_1_VALUE, "RENAME", &key);
	return remove(ctx, IN_PARAM_2_VALUE, "RENAME", &key);
#else
	lookup_entry_key_t key = {0, {0}};

	/* do it for IN_PARAM_1_VALUE */
	memset(key.name, 0, NAME_MAX);
	if (gen_entry_key(ctx, IN_PARAM_1_VALUE, "RENAME", &key))
		return UPCALL;

	/* lookup by key */
	lookup_entry_val_t *entry = bpf_map_lookup_elem(&entry_map, &key);
	if (!entry || entry->stale)
		return UPCALL;

	/* mark as stale to prevent future lookups */
	__sync_fetch_and_add(&entry->stale, 1);

	PRINTK("RENAME key name: %s nodeid: 0x%llx nlookup %lld Marked Stale!\n",
		key.name, key.nodeid, entry->nlookup);

	/*
	 * if the entry is negative (i.e., nodeid=0) or has only one reference
	 * (i.e., nlookup=1), delete it because the user-space does not track
	 * negative entries, and knows about entries with single reference.
	 */
	uint64_t nodeid = entry->nodeid;
	if (nodeid) {
		bpf_map_delete_elem(&attr_map, &nodeid);
		PRINTK("\t Deleted stale attr for node 0x%llx\n", nodeid);
	}
	if (entry->nlookup <= 1) {
		bpf_map_delete_elem(&entry_map, &key);
		PRINTK("\t Deleted stale node 0x%llx\n", nodeid);
	}

	/* do it for IN_PARAM_2_VALUE */
	memset(key.name, 0, NAME_MAX);
	if (gen_entry_key(ctx, IN_PARAM_2_VALUE, "RENAME", &key))
		return UPCALL;

	/* lookup by key */
	entry = bpf_map_lookup_elem(&entry_map, &key);
	if (!entry || entry->stale)
		return UPCALL;

	/* mark as stale to prevent future lookups */
	__sync_fetch_and_add(&entry->stale, 1);

	PRINTK("RENAME key name: %s nodeid: 0x%llx nlookup %lld Marked Stale!\n",
		key.name, key.nodeid, entry->nlookup);

	/*
	 * if the entry is negative (i.e., nodeid=0) or has only one reference
	 * (i.e., nlookup=1), delete it because the user-space does not track
	 * negative entries, and knows about entries with single reference.
	 */
	nodeid = entry->nodeid;
	if (nodeid) {
		bpf_map_delete_elem(&attr_map, &nodeid);
		PRINTK("\t Deleted stale attr for node 0x%llx\n", nodeid);
	}
	if (entry->nlookup <= 1) {
		bpf_map_delete_elem(&entry_map, &key);
		PRINTK("\t Deleted stale node 0x%llx\n", nodeid);
	}

	return UPCALL;
#endif
}

HANDLER(FUSE_RMDIR)(void *ctx)
{
#ifndef DEBUGNOW
	lookup_entry_key_t key = {0, {0}};										
	return remove(ctx, IN_PARAM_0_VALUE, "RMDIR", &key);
#else
	lookup_entry_key_t key = {0, {0}};
	memset(key.name, 0, NAME_MAX);
	if (gen_entry_key(ctx, IN_PARAM_0_VALUE, "RMDIR", &key))
		return UPCALL;

	/* lookup by key */
	lookup_entry_val_t *entry = bpf_map_lookup_elem(&entry_map, &key);
	if (!entry || entry->stale)
		return UPCALL;

	/* mark as stale to prevent future lookups */
	__sync_fetch_and_add(&entry->stale, 1);

	PRINTK("RMDIR key name: %s nodeid: 0x%llx nlookup %lld Marked Stale!\n",
		key.name, key.nodeid, entry->nlookup);

	/*
	 * if the entry is negative (i.e., nodeid=0) or has only one reference
	 * (i.e., nlookup=1), delete it because the user-space does not track
	 * negative entries, and knows about entries with single reference.
	 */
	uint64_t nodeid = entry->nodeid;
	if (nodeid) {
		bpf_map_delete_elem(&attr_map, &nodeid);
		PRINTK("\t Deleted stale attr for node 0x%llx\n", nodeid);
	}
	if (entry->nlookup <= 1) {
		bpf_map_delete_elem(&entry_map, &key);
		PRINTK("\t Deleted stale node 0x%llx\n", nodeid);
	}

	return UPCALL;
#endif
}

HANDLER(FUSE_UNLINK)(void *ctx)
{
#ifndef DEBUGNOW
	lookup_entry_key_t key = {0, {0}};
	return remove(ctx, IN_PARAM_0_VALUE, "UNLINK", &key);
#else
	lookup_entry_key_t key = {0, {0}};
	memset(key.name, 0, NAME_MAX);
	if (gen_entry_key(ctx, IN_PARAM_0_VALUE, "UNLINK", &key))
		return UPCALL;

	/* lookup by key */
	lookup_entry_val_t *entry = bpf_map_lookup_elem(&entry_map, &key);
	if (!entry || entry->stale)
		return UPCALL;

	/* mark as stale to prevent future lookups */
	__sync_fetch_and_add(&entry->stale, 1);

	PRINTK("UNLINK key name: %s nodeid: 0x%llx nlookup %lld Marked Stale!\n",
		key.name, key.nodeid, entry->nlookup);

	uint64_t nodeid = entry->nodeid;
	if (nodeid) {
		bpf_map_delete_elem(&attr_map, &nodeid);
		PRINTK("\t Deleted stale attr for node 0x%llx\n", nodeid);
	}
	if (entry->nlookup <= 1) {
		bpf_map_delete_elem(&entry_map, &key);
		PRINTK("\t Deleted stale node 0x%llx\n", nodeid);
	}

	return UPCALL;
#endif
}


// for operatioin bypass

#define MAX_ENTRIES_REC 10240
#define NUM_OPERATIONS 15
#define DIR1 "/tmp/dir1"
#define DIR2 "/tmp/dir2"
#define DIR_SZ 9

struct record {
    unsigned int pid;
    int ops_cnt[NUM_OPERATIONS];
    u64 ops_time[NUM_OPERATIONS];
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES_REC);
    __type(key, u32);
    __type(value, struct record);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} record_map SEC(".maps");

#define TB_SAMPLE_T 300000000
#define TB_THRESH   100
struct temporal_bucket {
	unsigned int pid, mode, diff;
	int cnt[2];
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct temporal_bucket);
} tb_map SEC(".maps");

static int enable_bypass_open(void)
{
	u32 pid = (u32)bpf_get_current_pid_tgid();
	struct record *rec = bpf_map_lookup_elem(&record_map, &pid);
	if (!rec) {
		bpf_printk("enable_bypass_open: pid %d not found\n", pid);
		return 0;
	}
	int cur_cnt = rec->ops_cnt[5] + rec->ops_cnt[13] + rec->ops_cnt[14];

	struct temporal_bucket *tb = bpf_map_lookup_elem(&tb_map, &pid);
	if (!tb) {
		struct temporal_bucket tb = {
			.pid = pid,
			.mode = 0,
			.diff = 0,
			.cnt = {cur_cnt, cur_cnt},
		};
		bpf_map_update_elem(&tb_map, &pid, &tb, BPF_ANY);
		return 0;
	}

	// bpf_printk("BYPASS: openat %d", rec->ops_cnt[5]);
	u64 tm = bpf_ktime_get_ns();
	int idx = tm / TB_SAMPLE_T % 2;
	int a = tb->cnt[idx], b = tb->cnt[idx^1];
	if (b > a) {
		// sampling done, make a new decision
		tb->mode = b - a > TB_THRESH;
		tb->diff = b - a;
		bpf_printk("BYPASS: %s cause b-a=%d", tb->mode ? "ENABLED" : "DISABLED", b - a);
	}
	tb->cnt[idx] = cur_cnt;
	// bpf_printk("BYPASS: %s", tb->mode ? "ENABLED" : "DISABLED");
	return tb->mode;
}

// Q-Learning

struct q_learning_state {
	int state; // state or state vector
	int action; // action or action vector
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // pid
	__type(value, struct q_learning_state);
} states_map SEC(".maps");

struct q_learning_qtable {
	u64 val;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // {state, action}
	__type(value, struct q_learning_qtable);
} qtable_map SEC(".maps");
u64 q_table_get(int state, int action);
u64 q_table_future(int state);
void q_table_set(int state, int action, u64 val);

#define Q_LR_MAX    1000
#define Q_LR         100
#define Q_DISCT_MAX 1000
#define Q_DISCT      900
#define Q_EPS_MAX   1000
#define Q_EPS        100

static int q_learning_calc_state(struct record *obs, struct temporal_bucket *tb)
{
	// calculate current state vector
	int op_cnt = tb->diff;
	// int state = __builtin_clz(op_cnt); // equivalent to log2(op_cnt)
	int state = 0;
	if(op_cnt > 4096) {
		state = 3;
	} else if(op_cnt > 256) {
		state = 2;
	} else if(op_cnt > 16) {
		state = 1;
	}
	return state;
}
static int q_learning_calc_reward(struct record *obs, struct temporal_bucket *tb)
{
	// u64 tm = obs->ops_time[5] + obs->ops_time[13] + obs->ops_time[14];
	u64 tm = obs->ops_time[13];
	tm = tm / 1000000; // convert to ms

	// last time
	u32 pid = (u32)bpf_get_current_pid_tgid();
	u32 key = pid ^ (1 << 31); // this is a different type of bucket
	struct temporal_bucket *pre_tb = bpf_map_lookup_elem(&tb_map, &key);
	if(!pre_tb) {
		struct temporal_bucket tb = {
			.pid = pid,
			.mode = 0,
			.diff = 0,
			.cnt = {tm, 0},
		};
		bpf_map_update_elem(&tb_map, &key, &tb, BPF_ANY);
		return 0;
	}

	tm = tm - pre_tb->cnt[0];
	if(tm == 0) {
		bpf_printk("@@@@@@@@@ DIVISION BY ZERO @@@@@@@@@");
		return 0;
	}
	bpf_printk("cnt %d time %llu", tb->diff, tm);
	int reward = tb->diff*100 / tm;
	return reward;
}
static int q_learning_choose_action(int S)
{
	// epsilon-greedy
	int action = 0;
	if(bpf_get_prandom_u32() % Q_EPS_MAX < Q_EPS) {
		action = bpf_get_prandom_u32() % 2; // now only 2 actions
	} else {
		// choose the best action
		int max_q = 0;
		for(int i = 0; i < 2; i++) { // now only 2 actions
			int q = q_table_get(S, i);
			if(q > max_q) {
				max_q = q;
				action = i;
			}
		}
	}
	return action;
}

static int q_learning_decide(struct record *obs, int S, int reward)
{
	u32 pid = (u32)bpf_get_current_pid_tgid();

	// last state
	struct q_learning_state *pre_S = bpf_map_lookup_elem(&states_map, &pid);
	if (!pre_S) {
		struct q_learning_state S = {
			.state = 0,
			.action = 1,
		};
		bpf_map_update_elem(&states_map, &pid, &S, BPF_ANY);
		return 1; // default action
	}

	// update Q-table
	u64 pre_q = q_table_get(pre_S->state, pre_S->action);
	u64 max_fut_q = q_table_future(S);
	u64 new_q = pre_q * (Q_LR_MAX-Q_LR)/Q_LR_MAX + (reward + max_fut_q * Q_DISCT/Q_DISCT_MAX) * Q_LR/Q_LR_MAX;
	q_table_set(pre_S->state, pre_S->action, new_q);
	// bpf_printk("QL: s %d a %d r %d q %d", pre_S->state, pre_S->action, reward, new_q);
	bpf_printk("QL: action %d ==> %d", pre_S->action, reward);
	
	int action = q_learning_choose_action(S);
	pre_S->state = S;
	pre_S->action = action;
	return action;
}

static int q_learning_scheduler(void)
{
	u32 pid = (u32)bpf_get_current_pid_tgid();
	// runtime observation
	struct record *obs = bpf_map_lookup_elem(&record_map, &pid);
	if (!obs) {
		// bpf_printk("enable_bypass_open: pid %d not found\n", pid);
		return 1;
	}

	int cur_cnt = obs->ops_cnt[5];

	struct temporal_bucket *tb = bpf_map_lookup_elem(&tb_map, &pid);
	if (!tb) {
		struct temporal_bucket tb = {
			.pid = pid,
			.mode = 0,
			.diff = 0,
			.cnt = {cur_cnt, cur_cnt},
		};
		bpf_map_update_elem(&tb_map, &pid, &tb, BPF_ANY);
		return 1;
	}

	// bpf_printk("BYPASS: openat %d", rec->ops_cnt[5]);
	u64 tm = bpf_ktime_get_ns();
	int idx = tm / TB_SAMPLE_T % 2;
	int a = tb->cnt[idx], b = tb->cnt[idx^1];
	if (b > a) {
		// sampling done, make a new decision
		tb->diff = b - a;
		int cur_S = q_learning_calc_state(obs, tb);
		int reward = q_learning_calc_reward(obs, tb);
		tb->mode = q_learning_decide(obs, cur_S, reward);
		bpf_printk("DECIDE: %s", tb->mode ? "ENABLED" : "DISABLED");
	}
	tb->cnt[idx] = cur_cnt;
	// bpf_printk("BYPASS: %s", tb->mode ? "ENABLED" : "DISABLED");
	return tb->mode;
}

u64 q_table_get(int state, int action)
{
	u32 key = (state << 3) | action;
	struct q_learning_qtable *q = bpf_map_lookup_elem(&qtable_map, &key);
	if (!q) {
		struct q_learning_qtable q = {
			.val = 0,
		};
		bpf_map_update_elem(&qtable_map, &key, &q, BPF_ANY);
		return 0;
	}
	return q->val;
}
u64 q_table_future(int state)
{
	u64 max = 0;
	for(int i = 0; i < 2; i++) { // now only 2 actions
		int q = q_table_get(state, i);
		if(q > max) {
			max = q;
		}
	}
	return max;
}
void q_table_set(int state, int action, u64 val)
{
	u32 key = (state << 3) | action;
	struct q_learning_qtable q = {
		.val = val,
	};
	bpf_map_update_elem(&qtable_map, &key, &q, BPF_ANY);
}

// Q-Learning END

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	// if(!enable_bypass_open()) {
	if (!q_learning_scheduler()) {
		// bpf_printk("bypass openat DISABLED");
		return 0;
	}
	// bpf_printk("bypass openat ENABLED");
    char fname[256];
    bpf_probe_read(&fname, sizeof(fname), (char*)ctx->args[1]);
    if(bpf_strncmp(fname, DIR_SZ, DIR2) != 0) {
        return 0;
    }
    int res = bpf_probe_write_user((char*)ctx->args[1], DIR1, DIR_SZ);
    // bpf_printk("openat: %s [%d]", fname, ctx->args[0]);
    return 0;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = LINUX_VERSION_CODE;
