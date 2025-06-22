# JFUSE DEBUG 记录

## JFUSE 问题

1. bpf函数无法运行
   * 未加载到对应位置
   * handler程序无法正确执行 
2. 内核新增类型BPF_PROG_TYPE_EXTFUSE无用
   * 目前debug完还是无用

## 内核修改

* linux-6.5/fs/fuse/inode.c
  
    `process_init_reply` 中触发 `extfuse_load_prog` 的判定条件存在问题。

    尝试修改后还是有问题，干脆直接删除判定条件了，可能不太好，**有待进一步优化**。

    ```
    extfuse_load_prog(fc, arg->extfuse_prog_fd);
    ```

* linux-6.5/fs/fuse/extfuse.c

    `extfuse_load_prog`中无法正确获取对应的bpf程序。

    ```
	// prog = bpf_prog_get_type(fd, BPF_PROG_TYPE_EXTFUSE);
	prog = bpf_prog_get(17);
    ```

    由于未使用BPF_PROG_TYPE_EXTFUSE类型，使用`bpf_prog_get_type`会返回错误，干脆直接使用不需要类型判定的`bpf_prog_get`。

    fd变量未成功传入，暂时还没理清fd从用户态传入内核态的逻辑，这里先直接硬编码成我这的bpf程序文件描述符17，**需要进一步优化**。

    fd是在`StackFS_LL.c`中`stackfs_ll_init`获取的。

## JFUSE bpf程序修改

* extfuse.bpf.c

    原本定义的bpf函数都是SEC('xdp')，这个section在传入上下文参数的时候有点问题，改成SEC("sk_msg")

    ```
    #define HANDLER(F) SEC("sk_msg") int bpf_func_##F
    ```

    ```
    SEC("sk_msg")
    int fuse_xdp_main_handler(void *ctx)
    {
        struct extfuse_req *args = (struct extfuse_req *)ctx;
        // int opcode = (int)args->in.h.opcode;
        __u32 opcode = 0;
        bpf_core_read(&opcode, sizeof(opcode), &args->in.h.opcode);

        PRINTK("in fuse_xdp_main_handler opcode: %d\n", opcode);
        // PRINTK("Opcode %d\n", opcode);
        
        bpf_tail_call(ctx, &handlers, opcode);
        PRINTK("opcode not handled: %d\n", opcode);
        return UPCALL;
    }
    ```

    在`fuse_xdp_main_handler`中需要使用`bpf_core_read`来获取opcode值而不能直接获取。

    `bpf_core_read`要头文件`#include "ebpf_create.h"`

## 辅助修改

* extfuse_i.h
    给`struct extfuse_req`，`struct extfuse_in`，`struct extfuse_out`的定义后面都加上`__attribute__((preserve_access_index))`

    ```
    /** The request input */
    struct extfuse_in {
        /** The request header */
        struct fuse_in_header h;

        /** Number of arguments */
        unsigned numargs;

        /** Array of arguments */
        struct fuse_in_arg args[3];
    }__attribute__((preserve_access_index));

    /** The request output */
    struct extfuse_out {
        /** Header returned from userspace */
        struct fuse_out_header h;

        /** Last argument is variable length (can be shorter than
            arg->size) */
        unsigned argvar:1;

        /** Number or arguments */
        unsigned numargs;

        /** Array of arguments */
        struct fuse_arg args[2];
    }__attribute__((preserve_access_index));

    struct extfuse_req {
        /** The request input */
        struct extfuse_in in;

        /** The request output */
        struct extfuse_out out;
    }__attribute__((preserve_access_index));
    ```

    这一部分好像不改也行，但是感觉还是加上比较好

## JFUSE 用户态程序修改

* ebpf.c `ebpf_init`

需要把每个handler以外的bpf程序放到hanlders map里面。

放在 `extfuse_bpf__load(skel)` 成功之后，`extfuse_bpf__attach(skel)` 之前。

我还搞了个`fuse.h`，里面存诸如`FUSE_LOOKUP`之类的宏定义。

```
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

```

