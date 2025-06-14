![0.学校logo](./images/0.学校logo.png)

# eFuse-基于eBPF加速的高性能用户态文件系统

## 目录

- [一、基本信息](#一基本信息)
- [二、项目概述](#二项目概述)
  - [2.1 背景和意义](#21-背景和意义)
  - [2.2 关于eFUSE](#22-关于efuse)
- [三、项目架构](#三项目架构)
- [四、项目目标与规划](#四项目目标与规划)
  - [4.1 项目目标](#41-项目目标)
  - [4.2 初赛内容](#42-初赛内容)
  - [4.3 决赛内容](#43-决赛内容)
- [五、项目进展](#五项目进展)
- [六、测试与评估](#六测试与评估)
- [七、功能展示](#七功能展示)
- [八、致谢](#八致谢)


## 一、基本信息

| 赛题 | [proj289 基于内核态/用户态 eBPF 实现高性能用户态文件系统功能](https://github.com/oscomp/proj289-High-performance-user-mode-file-system) |
| :-: | :-: |
| **队伍名称** | FastPoke |
| **项目名称** | eFuse |
| **小组成员** | 许辰涛、冯可逸、赵胜杰 |
| **项目导师** | 郑昱笙 |
| **校内导师** | 夏文、李诗逸 |

## 二、项目概述

### 2.1 背景和意义

FUSE（Filesystem in Userspace）使开发者能够在用户态构建文件系统，极大简化了开发流程和内核安全性风险。然而，FUSE 的性能瓶颈一直备受诟病，尤其在高频繁元数据操作、大量小文件读写等场景下，内核态与用户态频繁切换成为主要性能瓶颈。

eBPF（extended Berkeley Packet Filter）是 Linux 的一项强大特性，允许开发者在不修改内核源码的情况下向内核注入用户定义逻辑，已广泛应用于网络、安全、追踪等领域。近年来，已有多项研究探索将 eBPF 引入文件系统以提升其性能，例如 ExtFuse、Fuse-BPF、XRP 等。我们期望通过本项目，探索基于 eBPF 的 FUSE 加速路径，实现低延迟、高吞吐的用户态文件系统。

### 2.2 关于eFUSE

eFuse 是一个尝试将 eBPF 深度集成到 FUSE 文件系统中的创新项目，旨在重构文件系统的执行路径，以实现以下三大目标：
- 减少内核态与用户态之间的频繁切换
- 设计高效的 I/O 和元数据缓存机制
- 实现跨核高并发优化与负载均衡机制

## 三、项目架构

架构图（TODO）  

## 四、项目目标与规划

### 4.1 项目目标
本项目分为五大技术目标模块

**目标1：FUSE内核模块扩展**
- 支持新的eBPF程序类型
- 扩展FUSE挂载点支持
- 设计并注册文件系统相关helper函数

**目标2：FUSE元数据请求优化**
- 优化 inode、目录、权限、路径等相关操作（如 LOOKUP、GETATTR）
- 使用 eBPF map 实现元数据缓存
- 内核态与用户态高效协调访问

**目标3：FUSE I/O 请求的特殊优化**
- 支持直通路径：eBPF 直接读取文件内容
- 支持缓存路径：将内容存入 eBPF map
- 设计请求调度策略实现直通与缓存路径选择

**目标4：基于内核修改的多核优化**
- 为每个核心构建独立ringbuf管道代替请求队列
- 实现可扩展的核间通信机制

**目标5：负载监控与请求均衡**
- 利用eBPF动态分析请求负载
- 根据ringbuf状态进行调度策略调整
- 避免资源瓶颈与请求拥塞

### 4.2 初赛内容

（需要修改）
- [ ] 实现基本的内核模块加载机制
- [ ] FUSE 元数据请求优化
- [ ] 请求调度策略实现直通与缓存路径选择

### 4.3 决赛内容

- [ ] 基于内核修改的多核优化
- [ ] 负载监控与请求均衡

## 五、项目进展

总体进度时间轴（TODO）

| 目标 | 时间 | 实现内容 |
| :-: | :-: | :-: |
| 目标一 | 25.3-25.5 | TODO |
| 目标二 | 25.4-25.6 | TODO |
| 目标三 | 25.4-25.6 | TODO |
| 目标四 | 25.7-25.8 | TODO |
| 目标五 | 25.7-25.8 | TODO |

## 六、测试与评估

### 6.1 对比XXX与eFUSE在以下测试集下的吞吐性能

### 6.2 TODO

## 七、功能展示

视频链接（TODO）

## 八、致谢

* 感谢 [libbpf](https://github.com/libbpf/libbpf)、[libfuse](https://github.com/libfuse/libfuse) 等优秀开源项目
