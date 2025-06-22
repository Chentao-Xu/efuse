# RFUSE

## 介绍

基于FUSE，无需进行任何修改

利用内核和用户空间之间的**可扩展消息通信**

使用环形缓冲区作为通信通道

直接访问（Direct Access，DAX）

### 优点

* 高吞吐量
* 高可扩展性

### RFUSE 实现了

* 可扩展的内核-用户通信
* 高效的请求传输
* 与现有的基于 FUSE 的文件系统完全兼容，唯一要做的就是将文件系统与 librfuse 库相连
* **适配多核 CPU 的现代硬件环境**

### FUSE 的其他问题

在 FUSE 中，来自 VFS 层的所有请求都被放入共享的待处理队列(pending queue)中，导致严重的锁争用，尤其是当多个线程同时执行文件系统作时。

这种设计不仅无法充分利用带宽的潜力，而且还成为开发可扩展用户空间文件系统的障碍。

### 诋毁其他工具

* FUSE-passthrough 让 FUSE 驱动程序直接将 READ/WRITE 请求转发到底层文件系统。但这种方法绕过了 FUSE 守护程序，从而削弱了 FUSE 支持自定义用户空间文件系统功能的能力。
* EXTFUSE 要求文件系统开发人员在 eBPF 的约束下构建新功能，包括限制代码大小、有界循环、限制对内核数据的访问、限制指针使用等。
* XFUSE 提议使用多个通信通道来提高 FUSE 的并行性。但是，仅添加更多队列并不能完全解决锁争用。

### io_uring

RFUSE 收到了 io_uring 的启发。

通过 **双环形缓冲区** ( **提交队列 SQ** & **完成队列 CQ** )，实现用户态与内核态的异步、无锁、批量 I/O 处理。

**从 Linux 5.1 开始引入**

不能直接利用 io_uring 因为 io_uring 在用户到内核的方向执行请求提交，这与需要内核到用户提交的 FUSE 结构不一致。

### 一些有的没的

* FIO (Flexible I/O Tester) 是一个用于测试存储系统（文件系统等）读写性能的命令行工具，可能有用。
* StackFS 是一个构建在 FUSE 之上的用户空间文件系统，它仅将文件系统作传递给底层内核文件系统。

## 工作机制

### 整体架构

* FUSE 架构图

![alt text](img/fuse_architecture.png)

* RFUSE 架构图

![alt text](img/rfuse_architecture.png)

RFUSE 采用环形通道的消息传递机制。

加载 RFUSEdriver 时，会为机器中的**每个内核**创建一个环形通道，以及一个特殊的设备 `/dev/rfuse`

RFUSE 守护进程使用 `mmap()` 将这些环形通道的内存区域映射到用户的虚拟地址空间，实现用户空间文件系统与内核交换消息( 无需上下文切换 )。

### 关于环形管道

* 环形管道结构 ( 省略 forget 和 interrupt 缓冲区)

![alt text](img/rfuse_ring_channel.png)

环形管道连接了 RFUSE 驱动程序和 RFUSE 守护程序。

每个环形管道包含：

* 三个环形缓冲区 ( pending, forget, interrupt )
* 两个单独的缓冲区 ( header, argument ) 以及对应的位图
* 一个后台队列 ( background queue )

同步请求直接进入待处理(pending)环形缓冲区。

异步请求被添加到后台队列，之后再移动到pending。

RFUSE 重复使用相同的 header 缓冲区作为输出缓冲区。

当文件系统挂载时，以上组件会映射到守护进程的虚拟内存区域，实现在内核和 RFUSE 守护程序之间建立共享内存空间。

当位图满，无法向缓冲区添加更多请求时，应用程序对应的线程将进入休眠状态，等待以前提交的请求完成。请求完成后，重置位图并唤醒某个休眠程序。

* `driver/rfuse/rfuse.h`

```
// Pending queue, Complete Queue
struct ring_buffer_1{
	uint32_t tail;
	uint32_t head;
	uint32_t mask;
	uint32_t entries;

	struct rfuse_address_entry *kaddr; // kernel address
	struct rfuse_address_entry *uaddr; // user address
};

 ......
```

### 工作线程管理

对于每个CPU核，都有一个环形管道。

对于每个环形管道，守护进程会创建专用的**工作线程** (  worker threads )，处理从管道中收到的请求。

RFUSE 允许每个环形管道有多个工作线程，但限制了最大线程数（默认2）。

该设计为了尽可能消除不同工作线程之间的锁冲突并且平衡性能损耗。

### 混合轮询机制

* 轮询机制

工作线程轮询用户空间中 pending 环形缓冲区的头指针以获取传入请求。

应用程序线程在输出缓冲区 ( 即被复用的 header 缓冲区 ) 中监视其提交的请求的完成标志，等待响应。

轮询的使用消除了 FUSE 中系统调用引起的上下文切换，还消除了唤醒线程相关的延迟。但是会导致CPU资源的浪费。

* 混合轮询机制
  
在一个用户定义的时间段（ 默认为 50 μsec ）线程可以空闲执行忙等待并轮询。

若超过这个时间还没轮询到就开始 sleep 并等待被唤醒。

* `driver/rfuse/rfuse_comp.c`

```
void rfuse_sleep_comp(struct fuse_conn *fc, struct rfuse_iqueue *riq, struct rfuse_req *r_req) {
	spin_lock(&r_req->waitq.lock);
	set_bit(FR_NEEDWAKEUP, &r_req->flags);
	spin_unlock(&r_req->waitq.lock);

	spin_lock(&riq->lock);
	riq->num_sync_sleeping++;
	spin_unlock(&riq->lock);

	wait_event_interruptible(r_req->waitq, !fc->connected || test_bit(FR_FINISHED, &r_req->flags));

	spin_lock(&riq->lock);
	riq->num_sync_sleeping--;
	spin_unlock(&riq->lock);
}

int rfuse_completion_poll(struct fuse_conn *fc, struct rfuse_iqueue *riq, struct rfuse_req *r_req)
{   
	unsigned long max_idle_due = jiffies + usecs_to_jiffies(RFUSE_COMP_MAX_IDLE);
	
	while(fc->connected) {
		if(test_bit(FR_FINISHED, &r_req->flags)){
			rfuse_request_end(r_req);
			return 0;
		}

		 if(time_after(jiffies, max_idle_due)){
	 		rfuse_sleep_comp(fc, riq, r_req);
		 }

		schedule();
	}

	return -ENOTCONN;
}
```

### 对异步请求的均衡策略

由于 RFUSE 根据 CPU 内核 ID 选择环形管道，因此大量的异步请求可能会使单个环形管道不堪重负，尤其是对于单个内核线频繁读写请求。

当出现以下两个情况时，RFUSE 会以循环方式将传入的异步请求调度到不同的环形管道上。

* 当在后台队列中等待的请求数超过可驻留在 pending 环形缓冲区中的请求的最大数量时。
* 当由于 RFUSE 守护进程中的执行时间延长而导致某个线程处于 sleep 状态时。

### 环形管道信息的传输

用户空间中的 RFUSE 守护进程无法知道环形管道中各个结构的具体地址。其利用逻辑标识符（例如环形管道 ID、环形缓冲区类型和标头缓冲区索引）与内核驱动程序通信。

这样也更安全。



