# extfuse

extfuse使用ebpf的方式预先缓存inode和dentry。

FUSE在内核与用户层之间的通讯使用`fuse_request_send`函数。

extfuse在`fuse_request_send`函数上挂载ebpf程序，判断文件或目录内容是否在cache中，若在cache中则直接返回(不需要访问用户态)。

## 内核修改

**extfuse 基于旧的 linux 4.x 内核**

**JFUSE 已经完成 extfuse 到新版内核的移植**

安装修改后的linux内核

```
git clone --branch ExtFUSE-1.0 https://github.com/extfuse/linux
```

### 1. 添加了新的BPF程序类型

在`include/linux/bpf_types.h`添加了EXTFUSE类型
```
BPF_PROG_TYPE(BPF_PROG_TYPE_EXTFUSE, extfuse)
```
在`include/uapi/linux/bpf.h`添加了EXTFUSE类型
```
enum bpf_prog_type {
	...
	BPF_PROG_TYPE_EXTFUSE,
};
```

在`samples/bpf/bpf_load.c`中添加了对EXTFUSE类型的内容加载

**从 Linux 5.x 开始，`bpf_load.c`不再被使用**

### 2. 在FUSE内核中添加了ebpf挂载点和相应的钩子函数

* `fs/fuse/inode.c`

调用`extfuse_load_prog`以加载ebpf程序
```
static void process_init_reply(struct fuse_conn *fc, struct fuse_req *req)
{
	...
	if (arg->flags & FUSE_FS_EXTFUSE)
		extfuse_load_prog(fc, arg->extfuse_prog_fd); //加载ebpf
	...
}
```
```
arg->flags |= 
	...
	EXTFUSE_FLAGS; //在arg->flags最后添加一位
```

* `fs/fuse/dev.c`

在`fuse_request_send`中增加了对`extfuse_request_send`的
调用，如果该函数能够对请求进行处理，则屏蔽掉Linux内核原本后续的常规处理。

```
void fuse_request_send(struct fuse_conn *fc, struct fuse_req *req)
{
	if (extfuse_request_send(fc, req) != -ENOSYS)
		return;
	__set_bit(FR_ISREPLY, &req->flags);
	if (!test_bit(FR_WAITING, &req->flags)) {
		__set_bit(FR_WAITING, &req->flags);
		atomic_inc(&fc->num_waiting);
	}
	__fuse_request_send(fc, req);
}
```

* `fs/fuse/extfuse.c`

`extfuse_load_prog`函数通过绑定数据到`fc->fc_priv`，来加载并注册ebpf程序到指定的FUSE连接。

这种方法可以显著减少用户态和内核态之间的频繁切换。

```
int extfuse_load_prog(struct fuse_conn *fc, int fd)
{
	struct bpf_prog *prog = NULL;
	struct bpf_prog *old_prog;
	struct extfuse_data *data;

	BUG_ON(fc->fc_priv);

	data = kmalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	prog = bpf_prog_get_type(fd, BPF_PROG_TYPE_EXTFUSE);
	if (IS_ERR(prog)) {
		pr_err("ExtFUSE bpf prog fd=%d failed: %ld\n", fd,
		       PTR_ERR(prog));
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
```

`extfuse_request_send`函数读取`fc->fc_priv`上挂载的ebpf程序并调用`extfuse_run_prog`来处理该请求。

若成功则返回结果。

若失败则让请求继续走标准FUSE流程，即退回给用户态。

```
int extfuse_request_send(struct fuse_conn *fc, struct fuse_req *req)
{
	struct extfuse_data *data = (struct extfuse_data *)fc->fc_priv;
	ssize_t ret = -ENOSYS;

	if (data) {
		struct extfuse_req ereq;
		fuse_to_extfuse_req(req, &ereq);
		ret = extfuse_run_prog(data->prog, &ereq); //调用ebpf程序并执行
		if (ret != -ENOSYS) {
			extfuse_to_fuse_req(&ereq, req);
			req->out.h.error = (int)ret;
			ret = 0;
		}
	}

	return ret;
}
```

`extfuse_run_prog`函数根据传入的BPF程序(`eprog`)和请求(`ereq`)来运行eBPF程序，并返回运行结果。

```
static int extfuse_run_prog(struct bpf_prog *eprog, struct extfuse_req *ereq)
{
	int ret = -ENOSYS;
	struct bpf_prog *prog;

	prog = READ_ONCE(eprog);
	if (prog) {
		/* run program */
		rcu_read_lock();
		ret = BPF_PROG_RUN(prog, ereq);
		rcu_read_unlock();
	}

	return ret;
}
```

### 3. FUSE内核中添加辅助函数

* `fs/fuse/extfuse.c`

`bpf_extfuse_read_args`函数

`src`是指向`struct extfuse_req`的指针，从该请求对象中读取指定类型(`type`)的数据，安全地复制到缓冲区`dst`中，`size`缓冲区大小。

```
BPF_CALL_4(bpf_extfuse_read_args, void *, src, u32, type, void *, dst, size_t, size)
{
	...
}

static const struct bpf_func_proto bpf_extfuse_read_args_proto = {
	.func		= bpf_extfuse_read_args,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING, //ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};
```

`bpf_extfuse_read_args`函数

`dst`是指向`struct extfuse_req`的指针，让BPF程序安全地向`extfuse_req`的输出参数区写入数据`src`。`type`是写入数据的类型，`size`是数据长度

```
BPF_CALL_4(bpf_extfuse_write_args, void *, dst, u32, type, const void *, src, u32, size)
{
	...
}

static const struct bpf_func_proto bpf_extfuse_write_args_proto = {
	.func		= bpf_extfuse_write_args,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING, //ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_PTR_TO_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};
```

在`bpf_extfuse_func_proto`添加对应的返回值

**BPF verifier 在加载 eBPF 程序时调用 `bpf_extfuse_func_proto` 来确认 eBPF 程序里用到的 helper 函数是否合法、参数/返回值类型是否匹配。**

```
static const struct bpf_func_proto *
bpf_extfuse_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_extfuse_read_args:
		return &bpf_extfuse_read_args_proto;
	case BPF_FUNC_extfuse_write_args:
		return &bpf_extfuse_write_args_proto;
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
```

向ebpf注册相应的辅助操作

`bpf_verifier_ops`结构体通常会在BPF程序加载过程中使用，在程序验证决断用来确保调用的函数是否合法等。

```
const struct bpf_verifier_ops extfuse_verifier_ops = {
	.get_func_proto = bpf_extfuse_func_proto,
	.is_valid_access = bpf_extfuse_is_valid_access,
};
```

## 用户态程序

* bpf/extfuse.c

定义存储节点信息和存储节点属性信息的eBPF映射`entry_map`和`attr_map`

```
struct bpf_map_def SEC("maps") entry_map = {
	.type			= BPF_MAP_TYPE_HASH,	// simple hash list
	.key_size		= sizeof(lookup_entry_key_t),
	.value_size		= sizeof(lookup_entry_val_t),
	.max_entries	= MAX_ENTRIES,
	.map_flags		= BPF_F_NO_PREALLOC,
};

/* order of maps is important */
struct bpf_map_def SEC("maps") attr_map = {
	.type			= BPF_MAP_TYPE_HASH,	// simple hash list
	.key_size		= sizeof(lookup_attr_key_t),
	.value_size		= sizeof(lookup_attr_val_t),
	.max_entries	= MAX_ENTRIES,
	.map_flags		= BPF_F_NO_PREALLOC,
};
```

该定义方式用的是老写法，libbpf推荐的新写法应该如下

```
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, lookup_entry_key_t);
    __type(value, lookup_entry_val_t);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} entry_map SEC(".maps");
```

定义一系列ebpf钩子函数，以`FUSE_LOOKUP`为例

```
HANDLER(FUSE_LOOKUP)(void *ctx)
{
	...
	//从 entry_map 查找对应 entry
	lookup_entry_val_t *entry = bpf_map_lookup_elem(&entry_map, &key);
	...
}
```

* 其他

还需要在文件系统初始化的时候加载ebpf程序，例如：

```
static void stackfs_ll_init(void *userdata, struct fuse_conn_info *conn)
	lo->ebpf_ctxt = ebpf_init("/tmp/extfuse.o");
```

需要在创建 entry 时，将 inode 插入 map。

