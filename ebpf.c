/* ExtFUSE library */
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "extfuse.skel.h"
#include "ebpf.h"
#include "fuse_opcode.h"

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,9,0)
#define bpf_map_update_elem bpf_update_elem
#define bpf_map_lookup_elem bpf_lookup_elem
#define bpf_map_delete_elem bpf_delete_elem
#endif

//#define DEBUG

#ifdef DEBUG
#define DBG(fmt, ...)   fprintf(stdout, fmt, ##__VA_ARGS__)
#else
#define DBG(fmt, ...)
#endif
#define ERROR(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

ebpf_context_t* ebpf_init(char *filename)
{
	// int i;
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    ebpf_context_t *con = NULL;
	struct extfuse_bpf *skel = NULL;
	int err;

	uid_t uid=getuid();

	if (!uid && setrlimit(RLIMIT_MEMLOCK, &r)) {
		ERROR("Failed to increase rlimits: %s\n", strerror(errno));
    }

	con = (ebpf_context_t* ) calloc(1, sizeof(ebpf_context_t));
	if (!con) {
		ERROR("Failed to allocate memory\n");
		goto err;
	}

    // if (load_bpf_file(filename)) {
	// 	ERROR("Failed to load bpf file %s: %s\n",
	// 			filename, strerror(errno));
	// 	goto err;
    // }

    // if (!prog_fd[0] || !map_fd[0]) {
	// 	ERROR("invalid prog_fd[0]=%d and map_fd[0]=%d\n",
	// 		prog_fd[0], map_fd[0]);
	// 	goto err;
    // }
	/* Load and verify BPF application */
	skel = extfuse_bpf__open();
	if (!skel) {
		ERROR("Failed to open and load BPF skeleton\n");
		goto err;
	}

	/* Load & verify BPF programs */
	err = extfuse_bpf__load(skel);
	if (err) {
		ERROR("Failed to load and verify BPF skeleton\n");
		goto err;
	}

	int handlers_map_fd = bpf_map__fd(skel->maps.handlers);
	int prog_fd;
	__u32 key;
	
	prog_fd = bpf_program__fd(skel->progs.bpf_func_FUSE_LOOKUP);
	key = FUSE_LOOKUP;
	if (bpf_map_update_elem(handlers_map_fd, &key, &prog_fd, BPF_ANY) != 0) {
			perror("Failed to update handlers map");
			goto err;
	}

	prog_fd = bpf_program__fd(skel->progs.bpf_func_FUSE_GETATTR);
	key = FUSE_GETATTR;
	if (bpf_map_update_elem(handlers_map_fd, &key, &prog_fd, BPF_ANY) != 0) {
			perror("Failed to update handlers map");
			goto err;
	}

	prog_fd = bpf_program__fd(skel->progs.bpf_func_FUSE_READ);
	key = FUSE_READ;
	if (bpf_map_update_elem(handlers_map_fd, &key, &prog_fd, BPF_ANY) != 0) {
			perror("Failed to update handlers map");
			goto err;
	}

	prog_fd = bpf_program__fd(skel->progs.bpf_func_FUSE_WRITE);
	key = FUSE_WRITE;
	if (bpf_map_update_elem(handlers_map_fd, &key, &prog_fd, BPF_ANY) != 0) {
			perror("Failed to update handlers map");
			goto err;
	}

	prog_fd = bpf_program__fd(skel->progs.bpf_func_FUSE_SETATTR);
	key = FUSE_SETATTR;
	if (bpf_map_update_elem(handlers_map_fd, &key, &prog_fd, BPF_ANY) != 0) {
			perror("Failed to update handlers map");
			goto err;
	}

	prog_fd = bpf_program__fd(skel->progs.bpf_func_FUSE_GETXATTR);
	key = FUSE_GETXATTR;
	if (bpf_map_update_elem(handlers_map_fd, &key, &prog_fd, BPF_ANY) != 0) {
			perror("Failed to update handlers map");
			goto err;
	}

	prog_fd = bpf_program__fd(skel->progs.bpf_func_FUSE_FLUSH);
	key = FUSE_FLUSH;
	if (bpf_map_update_elem(handlers_map_fd, &key, &prog_fd, BPF_ANY) != 0) {
			perror("Failed to update handlers map");
			goto err;
	}

	prog_fd = bpf_program__fd(skel->progs.bpf_func_FUSE_RENAME);
	key = FUSE_RENAME;
	if (bpf_map_update_elem(handlers_map_fd, &key, &prog_fd, BPF_ANY) != 0) {
			perror("Failed to update handlers map");
			goto err;
	}

	prog_fd = bpf_program__fd(skel->progs.bpf_func_FUSE_RMDIR);
	key = FUSE_RMDIR;
	if (bpf_map_update_elem(handlers_map_fd, &key, &prog_fd, BPF_ANY) != 0) {
			perror("Failed to update handlers map");
			goto err;
	}

	prog_fd = bpf_program__fd(skel->progs.bpf_func_FUSE_UNLINK);
	key = FUSE_UNLINK;
	if (bpf_map_update_elem(handlers_map_fd, &key, &prog_fd, BPF_ANY) != 0) {
			perror("Failed to update handlers map");
			goto err;
	}

	/* Attach tracepoints */
	err = extfuse_bpf__attach(skel);
	if (err) {
		ERROR("Failed to attach BPF skeleton\n");
		goto err;
	}

	// con->ctrl_fd = prog_fd[0];
	// for (i = 0; i < MAX_MAPS; i++)
	// 	con->data_fd[i] = map_fd[i];
	con->ctrl_fd = bpf_program__fd(skel->progs.fuse_xdp_main_handler);

	// DBG("main context created 0x%lx ctrl_fd=%d data_fd=%d\n",
	// 	(unsigned long)con, con->ctrl_fd, con->data_fd);
	con->skel = skel;
	DBG("main context created conn=0x%lx, skel=0x%lx\n", (unsigned long)con, (unsigned long)skel);
    return con;

err:
	if (skel)
		extfuse_bpf__destroy(skel);
	if (con)
		free(con);
	return NULL;
}

void ebpf_fini(ebpf_context_t *con)
{
	// int i;
	// DBG("freeing main context 0x%lx ctrl_fd=%d data_fd=%d\n",
	// 	(unsigned long)con, con->ctrl_fd, con->data_fd);
	// if (con->ctrl_fd && close(con->ctrl_fd))
	// 	ERROR("Failed to close ctrl_fd %d: %s!",
	// 		con->ctrl_fd, strerror(errno));
	// for (i = 0; i < MAX_MAPS; i++)
	// 	if (con->data_fd[i] && close(con->data_fd[i]))
	// 		ERROR("Failed to close data_fd %d: %s!",
	// 			con->data_fd[i], strerror(errno));
	// free(con);
	DBG("freeing main context conn=0x%lx, skel=0x%lx\n", (unsigned long)con, (unsigned long)con->skel);
	extfuse_bpf__destroy(con->skel);
	free(con);
	return;
}

// Control handling abstractions
// int ebpf_ctrl_update(ebpf_context_t *context,
//                 ebpf_ctrl_key_t *key,
//                 ebpf_handler_t *handler)
// {
// 	unsigned long long flags = BPF_ANY;
// 	return bpf_map_update_elem(context->skel, (void *) key,
//                         (void *) handler, flags);
// }

// int ebpf_ctrl_delete(ebpf_context_t *context,
//                 ebpf_ctrl_key_t *key)
// {
// 	return bpf_map_delete_elem(context->ctrl_fd, (void *) key);
// }

struct bpf_map* ebpf_get_map(ebpf_context_t *context, int idx)
{
	struct extfuse_bpf *skel = context->skel;
	return idx == 0 ? skel->maps.entry_map : skel->maps.attr_map;
}

int ebpf_data_next(ebpf_context_t *context, void *key, size_t key_sz, void *next, int idx)
{
	// DBG("ebpf_next_data fd: %d\n", context->data_fd[idx]);
	struct bpf_map *map = ebpf_get_map(context, idx);
	return bpf_map__get_next_key(map, key, next, key_sz);
}

// Data handling abstractions
int ebpf_data_lookup(ebpf_context_t *context, void *key, size_t key_sz, void *val, size_t val_sz, int idx)
{
	// DBG("ebpf_data_lookup fd: %d\n", context->data_fd[idx]);
	struct bpf_map *map = ebpf_get_map(context, idx);
	return bpf_map__lookup_elem(map, key, key_sz, val, val_sz, 0); // TODO: check this flags param
}

int ebpf_data_update(ebpf_context_t *context, void *key, size_t key_sz, void *val, size_t val_sz, int idx,
		int overwrite)
{
	unsigned long long flags = BPF_NOEXIST;
	if (overwrite)
		flags = BPF_ANY;
	// DBG("ebpf_data_update fd: %d\n", context->data_fd[idx]);
	struct bpf_map *map = ebpf_get_map(context, idx);
	return bpf_map__update_elem(map, key, key_sz, val, val_sz, flags);
}

int ebpf_data_delete(ebpf_context_t *context, void *key, size_t key_sz, int idx)
{
	// DBG("ebpf_data_delete fd: %d\n", context->data_fd[idx]);
	struct bpf_map *map = ebpf_get_map(context, idx);
	return bpf_map__delete_elem(map, key, key_sz, 0); // TODO: check this flags param
}

struct bpf_program* ebpf_get_handler(ebpf_context_t *context, int handler_id)
{
	struct extfuse_bpf *skel = context->skel;
	switch (handler_id) {
		case 1:
			return skel->progs.bpf_func_FUSE_CREATE_ENTRY;
		// TODO: other handlers
		default:
			return NULL;
	}
}

int ebpf_call_handler(ebpf_context_t *context, int handler_id, void *args, size_t args_sz)
{
	struct bpf_test_run_opts opts = {
		.sz = sizeof(struct bpf_test_run_opts),
		.data_in = args,
		.data_out = args,
		.data_size_in = args_sz,
		.data_size_out = args_sz,
	};
	
	struct bpf_program *handler = ebpf_get_handler(context, handler_id);
	if(!handler) {
		// ERROR("Handler not found\n");
		return -1;
	}
	int prog_fd = bpf_program__fd(handler);
	int err = bpf_prog_test_run_opts(prog_fd, &opts);
	return err;
}