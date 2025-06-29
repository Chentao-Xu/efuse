#include "asm/ptrace.h"
#include "extfuse_i.h"
#include "linux/filter.h"
#include "linux/uaccess.h"

#undef pr_fmt
#define pr_fmt(fmt)	"ExtFUSE: " fmt

/* create a copy of args for extfuse request handlers */
static void fuse_to_extfuse_req(struct fuse_req *req,
		struct extfuse_req *ereq)
{
	ereq->in.h.opcode = req->in.h.opcode;
	ereq->in.h.nodeid = req->in.h.nodeid;
	ereq->in.numargs = req->args->in_numargs;
	memcpy(ereq->in.args, req->args->in_args,
			req->args->in_numargs * sizeof(struct fuse_in_arg));
	ereq->out.argvar = req->args->out_argvar;
	ereq->out.numargs = req->args->out_numargs;
	memcpy(ereq->out.args, req->args->out_args,
			req->args->out_numargs * sizeof(struct fuse_arg));
}

/* only copy out args */
static void extfuse_to_fuse_req(struct extfuse_req *ereq,
		struct fuse_req *req)
{
	req->args->out_argvar = ereq->out.argvar;
	req->args->out_numargs = ereq->out.numargs;
	memcpy(req->args->out_args, ereq->out.args,
			ereq->out.numargs * sizeof(struct fuse_arg));
}


static int extfuse_run_prog(struct bpf_prog *eprog, struct extfuse_req *ereq)
{
	int ret = -ENOSYS;
	struct bpf_prog *prog;

	prog = READ_ONCE(eprog);
	if (prog) {
		/* run program */
		rcu_read_lock();
		ret = bpf_prog_run(prog, ereq);
		rcu_read_unlock();
	}

	return ret;
}

int extfuse_request_send(struct fuse_conn *fc, struct fuse_req *req)
{
	struct extfuse_data *data = (struct extfuse_data *)fc->fc_priv;
	ssize_t ret = -ENOSYS;

	if (data) {
		struct extfuse_req ereq;
		fuse_to_extfuse_req(req, &ereq);
		ret = extfuse_run_prog(data->prog, &ereq);
		if (ret != -ENOSYS) {
			extfuse_to_fuse_req(&ereq, req);
			req->out.h.error = (int)ret;
			ret = 0;
		}
	}
	return ret;
}

void extfuse_unload_prog(struct fuse_conn *fc)
{
	struct extfuse_data *data = (struct extfuse_data *)fc->fc_priv;
	if (data) {
		struct bpf_prog *old_prog;
		old_prog = xchg(&data->prog, NULL);
		if (old_prog) {
			bpf_prog_put(old_prog);
			pr_info("ExtFUSE bpf prog unloaded\n");
		}
		kfree(data);
		fc->fc_priv = NULL;
	}
}

int extfuse_load_prog(struct fuse_conn *fc, int fd)
{
	struct bpf_prog *prog = NULL;
	struct bpf_prog *old_prog;
	struct extfuse_data *data;

	BUG_ON(fc->fc_priv);

	data = kmalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	prog = bpf_prog_get(fd);
	if (IS_ERR(prog)) {
		pr_err("ExtFUSE bpf prog fd=%d failed: %ld\n",
			fd, PTR_ERR(prog));
		kfree(data);
		return -1;
	}

	old_prog = xchg(&data->prog, prog);
	if (old_prog)
		bpf_prog_put(old_prog);

	fc->fc_priv = (void *)data;

	pr_info("ExtFUSE bpf prog loaded fd=%d\n", fd);
	return 0;
}

/**
 * int bpf_extfuse_read_args(): attempts to copy the requested src field to dst.
 * @src: a pointer to a extfuse_req data structure
 * @type: Specifies what field of the src data structure to be copied to dst
 * @dst: a pointer to the container that will be filled with the requested data
 * @size: size of the data chunk to be copied to dst
 */
BPF_CALL_4(bpf_extfuse_read_args, void *, src, u32, type, void *, dst, size_t,
	   size)
{
	struct extfuse_req *req = (struct extfuse_req *)src;
	unsigned num_in_args = req->in.numargs;
	unsigned num_out_args = req->out.numargs;
	int ret = -EINVAL;
	const void *inptr = NULL;

	switch (type) {
	case OPCODE:
		if (size != sizeof(uint32_t))
			return -EINVAL;
		inptr = (void *)&req->in.h.opcode;
		break;
	case NODEID:
		if (size != sizeof(uint64_t))
			return -EINVAL;
		inptr = (void *)&req->in.h.nodeid;
		break;
	case NUM_IN_ARGS:
		if (size != sizeof(unsigned))
			return -EINVAL;
		inptr = (void *)&req->in.numargs;
		break;
	case NUM_OUT_ARGS:
		if (size != sizeof(unsigned))
			return -EINVAL;
		inptr = (void *)&req->out.numargs;
		break;
	case IN_PARAM_0_SIZE:
		if (size != sizeof(unsigned) || num_in_args < 1 ||
		    num_in_args > 3)
			return -EINVAL;
		inptr = &req->in.args[0].size;
		break;
	case IN_PARAM_0_VALUE:
		if (num_in_args < 1 || num_in_args > 3)
			return -EINVAL;
		if (size < req->in.args[0].size)
			return -E2BIG;
		size = req->in.args[0].size;
		inptr = req->in.args[0].value;
		break;
	case IN_PARAM_1_SIZE:
		if (size != sizeof(unsigned) || num_in_args < 2 ||
		    num_in_args > 3)
			return -EINVAL;
		inptr = &req->in.args[1].size;
		break;
	case IN_PARAM_1_VALUE:
		if (num_in_args < 2 || num_in_args > 3)
			return -EINVAL;
		if (size < req->in.args[1].size)
			return -E2BIG;
		size = req->in.args[1].size;
		inptr = req->in.args[1].value;
		break;
	case IN_PARAM_2_SIZE:
		if (size != sizeof(unsigned) || num_in_args != 3)
			return -EINVAL;
		inptr = &req->in.args[2].size;
		break;
	case IN_PARAM_2_VALUE:
		if (num_in_args != 3)
			return -EINVAL;
		if (size < req->in.args[2].size)
			return -E2BIG;
		size = req->in.args[2].size;
		inptr = req->in.args[2].value;
		break;
	case OUT_PARAM_0:
		if (num_out_args < 1 || num_out_args > 2)
			return -EINVAL;
		if (size != req->out.args[0].size)
			return -E2BIG;
		inptr = req->out.args[0].value;
		break;
	case OUT_PARAM_1:
		if (num_out_args != 2)
			return -EINVAL;
		if (size != req->out.args[1].size)
			return -E2BIG;
		inptr = req->out.args[1].value;
		break;
	default:
		return -EBADRQC;
		break;
	}

	if (!inptr) {
		pr_err("Invalid input to %s type: %d num_in_args: %d "
			"num_out_args: %d size: %ld\n",
			__func__, type, num_in_args, num_out_args, size);
		return ret;
	}

	// ret = probe_kernel_read(dst, inptr, size);
	ret = copy_from_kernel_nofault(dst, inptr, size);
	if (unlikely(ret < 0))
		memset(dst, 0, size);

	return ret;
}

const struct bpf_func_proto bpf_extfuse_read_args_proto = {
	.func		= bpf_extfuse_read_args,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING, //ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};

/**
 * int bpf_extfuse_write_args(): attempts to copy the src field to dst.
 * @src: a pointer to a extfuse_req data structure
 * @type: Specifies what field of the src data structure to be copied to dst
 * @dst: a pointer to the container that will be filled with the requested data
 * @size: size of the data chunk to be copied to dst
 */
BPF_CALL_4(bpf_extfuse_write_args, void *, dst, u32, type, const void *, src,
	   u32, size)
{
	int ret = -EINVAL;
	void *outptr = NULL;
	struct extfuse_req *req= (struct extfuse_req *)dst;
	unsigned numargs = req->out.numargs;

	/* ===== 缓存/直通 start ===== */
	if (type == READ_MAP_CACHE) {
		
		if (size != sizeof(struct efuse_cache_in))
			return -EINVAL;

		struct efuse_cache_in *in = (struct efuse_cache_in *)src;

		memcpy(req->out.args[0].value + in->copied, in->data->data + in->data_offset, in->copy_len);

		req->out.args[0].size = in->copied + in->copy_len;
		return in->copied + in->copy_len;
	}

	if (type == READ_PASSTHROUGH) {

		if (size != sizeof(struct efuse_read_in))
			return -EINVAL;

		struct efuse_read_in *in = (struct efuse_read_in *)src;

		if (!req || in->size <= 0)
			return -EINVAL;

		// pr_info("read_passthrough_size: arg0_size:%d, wrong size: %d\n",
				// req->out.args[0].size, size);

		if (req->in.numargs < 2) {
			return -EINVAL;
		}
		struct file *filp = *(struct file **)req->in.args[1].value;
		if (!filp) {
			return -EINVAL;
		}

		loff_t file_size = i_size_read(file_inode(filp));
		// pr_info("read_passthrough_size: file size: %lld\n", file_size);
		if (in->offset >= file_size) {
			// pr_info("read_passthrough: offset beyond file size\n");
			req->out.args[0].size = 0;
			return 0; // 读取偏移超出文件大小，返回0表示EOF
		}

		if (in->size <= 0) {
			// pr_info("read_passthrough: invalid size: %llu\n", in->size);
			req->out.args[0].size = 0;
			return 0;
		}

		size_t to_read = in->size;
		if (in->offset + to_read > file_size)
			to_read = file_size - in->offset;

		// pr_info("read_passthrough_size: to_read: %zu\n", to_read);

		if (numargs < 1 || req->out.args[0].size < to_read) {
			// pr_info("Insufficient buffer size\n");
			return -EINVAL;
		}

		if (in->offset + to_read > file_size) {
			// pr_info("passed size exceeds file size\n");
			return -EINVAL;
		}

		outptr = req->out.args[0].value;

		// pr_info("test: fh=%llu, offset=%llu, size=%llu\n", in->fh, in->offset, in->size);
		// pr_info("test: outptr=%p, out_size=%d\n", req->out.args[0].value, req->out.args[0].size);
		// pr_info("test: filp=%p\n", filp);
		// pr_info("test: file_size=%lld, to_read=%zu\n", file_size, to_read);

		if (to_read == in->size || to_read == req->out.args[0].size) {
			// pr_info("read_passthrough: the twice request, size: %llu, out_size: %d\n",
			// 		in->size, req->out.args[0].size);
			// req->out.args[0].size = 0;
			// return 0; // 防止虚拟机崩溃
			
			// 模拟测试
			memset(outptr, 'x', to_read);
			ret = to_read;
			req->out.args[0].size = ret;
			return ret; // 返回模拟数据
		}

		loff_t pos = in->offset;
		ret = kernel_read(filp, outptr, to_read, &pos); // 可能会导致虚拟机崩溃，不知道原因

		// 模拟测试
		memset(outptr, 'x', to_read);
		ret = to_read;

		if (ret < 0) {
			memset(outptr, 0, in->size);
			// pr_info("read_passthrough: kernel_read failed: %d\n", ret);
			return ret;
		}
		// pr_info("read_passthrough: value: %s, size: %d\n", (char *)req->out.args[0].value, ret);

		// 可选：更新实际读取的大小
		req->out.args[0].size = ret;

		return ret;

	}
	/* ===== 缓存/直通 end ===== */

	if (type == OUT_PARAM_0 && numargs >= 1 && numargs <= 2 &&
			size <= req->out.args[0].size) {
		outptr = req->out.args[0].value;
		req->out.args[0].size = size;
	}

	else if (type == OUT_PARAM_1 && numargs == 2 &&
			size <= req->out.args[1].size) {
		outptr = req->out.args[1].value;
		req->out.args[1].size = size;
	}

	if (!outptr) {
		pr_debug("Invalid input to %s type: %d "
				"num_args: %d size: %d\n",
				__func__, type, numargs, size);
		return ret;
	}

	// ret = probe_kernel_write(outptr, src, size);
	ret = copy_to_kernel_nofault(outptr, src, size);
	if (unlikely(ret < 0))
		memset(outptr, 0, size);

	return ret;
}

const struct bpf_func_proto bpf_extfuse_write_args_proto = {
	.func		= bpf_extfuse_write_args,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING, //ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_PTR_TO_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};

BPF_CALL_3(bpf_helper_memcpy, void *, dst, void *, src, size_t, len)
{
	// pr_info("[%s] called %px <= %px, %lu\n", __func__, dst, src, len);

	memcpy(dst, src, len);
	return 0;
}

const struct bpf_func_proto bpf_helper_memcpy_proto = {
	.func	   = bpf_helper_memcpy,
	.ret_type  = RET_VOID,
	.arg1_type = ARG_ANYTHING,
	.arg2_type = ARG_ANYTHING,
	.arg3_type = ARG_ANYTHING
};

BPF_CALL_1(bpf_malloc, size_t, size)
{
    return (uint64_t)(unsigned long)kvmalloc(size, GFP_KERNEL);
}

BPF_CALL_1(bpf_free, void *, pt)
{
    kvfree(pt);
    return 0;
}

BPF_CALL_5(bpf_mem_read, void *, dst, void *, src, off_t, offset, size_t, size,
           size_t, boundary)
{
    if (offset > boundary - size) {
        offset = boundary - size;
    }
    memcpy(dst, src + offset, size);
    return size;
}

BPF_CALL_5(bpf_mem_write, void *, dst, void *, src, off_t, offset, size_t, size,
           size_t, boundary)
{
    if (offset > boundary - size) {
        offset = boundary - size;
    }
    memcpy(dst + offset, src, size);
    return size;
}

BPF_CALL_3(sbpf_memcmp, void *, dst, void *, src, size_t, len)
{
	// pr_info("[%s] called\n", __func__);
	return memcmp(dst, src, len);
}

BPF_CALL_3(sbpf_memset, void *, dst, int, ch, size_t, len)
{
	return (uint64_t)(unsigned long)memset(dst, ch, len);
}

const struct bpf_func_proto bpf_malloc_proto = {
    .func      = bpf_malloc,
    .ret_type  = RET_PTR_TO_MEM,
    .arg1_type = ARG_ANYTHING,
};

const struct bpf_func_proto bpf_free_proto = {
        .func = bpf_free,
        .ret_type = RET_VOID,
        .arg1_type = ARG_ANYTHING,
};

const struct bpf_func_proto bpf_mem_read_proto = {
        .func = bpf_mem_read,
        .ret_type = RET_VOID,
        .arg1_type = ARG_ANYTHING,
        .arg2_type = ARG_ANYTHING,
        .arg3_type = ARG_ANYTHING,
        .arg4_type = ARG_ANYTHING,
        .arg5_type = ARG_ANYTHING,
};

const struct bpf_func_proto bpf_mem_write_proto = {
        .func = bpf_mem_write,
        .ret_type = RET_VOID,
        .arg1_type = ARG_ANYTHING,
        .arg2_type = ARG_ANYTHING,
        .arg3_type = ARG_ANYTHING,
        .arg4_type = ARG_ANYTHING,
        .arg5_type = ARG_ANYTHING,
};

const struct bpf_func_proto sbpf_memcmp_proto = {
        .func	   = sbpf_memcmp,
        .ret_type  = RET_INTEGER,
        .arg1_type = ARG_ANYTHING,
        .arg2_type = ARG_ANYTHING,
        .arg3_type = ARG_ANYTHING
};

const struct bpf_func_proto sbpf_memset_proto = {
		.func	   = sbpf_memset,
		.ret_type  = RET_PTR_TO_MEM,
		.arg1_type = ARG_ANYTHING,
        .arg2_type = ARG_ANYTHING,
        .arg3_type = ARG_ANYTHING
};

BPF_CALL_4(bpf_extfuse_read_passthrough, void *, dst, u64, file_handle, u64, offset, u64, size)
{
    struct file *filp;
    loff_t pos = offset;
    int ret;

    struct extfuse_req *req = (struct extfuse_req *)dst;

    if (!req || size <= 0)
        return -EINVAL;

    void *outptr = NULL;
    unsigned numargs = req->out.numargs;

    if (numargs >= 1 && req->out.args[0].size >= size) {
        outptr = req->out.args[0].value;
	}

    if (!outptr)
        return -EINVAL;

    filp = fget(file_handle);
    if (!filp)
        return -EBADF;

    ret = kernel_read(filp, outptr, size, &pos);
    fput(filp);

    if (ret < 0) {
        memset(outptr, 0, size);
        return ret;
    }

    // 可选：更新实际读取的大小
    req->out.args[0].size = ret;

    return ret;
}

static const struct bpf_func_proto bpf_extfuse_read_passthrough_proto = {
    .func       = bpf_extfuse_read_passthrough,
    .gpl_only   = true,
    .ret_type   = RET_INTEGER,
    .arg1_type  = ARG_PTR_TO_MEM,
    .arg2_type  = ARG_ANYTHING,
    .arg3_type  = ARG_CONST_SIZE,
    .arg4_type  = ARG_CONST_SIZE,
};

static const struct bpf_func_proto *
bpf_extfuse_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_extfuse_read_args:
		return &bpf_extfuse_read_args_proto;
	case BPF_FUNC_extfuse_write_args:
		return &bpf_extfuse_write_args_proto;

	case BPF_FUNC_helper_memcpy:
		return &bpf_helper_memcpy_proto;
	case BPF_FUNC_malloc:
        return &bpf_malloc_proto;
    case BPF_FUNC_free:
        return &bpf_free_proto;
    case BPF_FUNC_mem_read:
        return &bpf_mem_read_proto;
	case BPF_FUNC_mem_write:
		return &bpf_mem_write_proto;
	case BPF_FUNC_memcmp:
		return &sbpf_memcmp_proto;
	case BPF_FUNC_memset:
		return &sbpf_memset_proto;

	case BPF_FUNC_extfuse_read_passthrough:
		return &bpf_extfuse_read_passthrough_proto;

	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_tail_call:
		return &bpf_tail_call_proto;
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();
	default:
		return NULL;
	}
}

/* bpf+fuse programs can access fields of 'struct pt_regs' */
static bool bpf_extfuse_is_valid_access(int off, int size,
		enum bpf_access_type type, const struct bpf_prog *prog,
		struct bpf_insn_access_aux *info)
{
	// if (off < 0 || off >= sizeof(struct fuse_args))
	// 	return false;
	// if (type != BPF_READ)
	// 	return false;
	// if (off % size != 0)
	// 	return false;
	// /*
	//  * Assertion for 32 bit to make sure last 8 byte access
	//  * (BPF_DW) to the last 4 byte member is disallowed.
	//  */
	// if (off + size > sizeof(struct fuse_args))
	// 	return false;

	// return true;

	return true;
}

const struct bpf_verifier_ops extfuse_verifier_ops = {
	.get_func_proto  = bpf_extfuse_func_proto,
	.is_valid_access = bpf_extfuse_is_valid_access,
};

const struct bpf_prog_ops extfuse_prog_ops = {
	.test_run = NULL,
};