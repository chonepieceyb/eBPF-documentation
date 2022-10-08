---
# try also 'default' to start simple
theme: seriph
# random image from a curated Unsplash collection by Anthony
# like them? see https://unsplash.com/collections/94734566/slidev
background: ./arnold-francisca-FBNxmwEVpAc-unsplash.jpg
# apply any windi css classes to the current slide
class: 'text-center'
# https://sli.dev/custom/highlighters.html
highlighter: shiki
lineNumbers: true
# some information about the slides, markdown enabled
info: |
  ## Slidev Starter Template
  Presentation slides for developers.

  Learn more at [Sli.dev](https://sli.dev)
---

# eBPF编程分享

6.16 杨彬

<div class="pt-12">
  <span @click="$slidev.nav.next" class="px-2 p-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Press Space for next page <carbon:arrow-right class="inline"/>
  </span>
</div>

<a href="https://github.com/slidevjs/slidev" target="_blank" alt="GitHub"
  class="abs-br m-6 text-xl icon-btn opacity-50 !border-none !hover:text-white">
  <carbon-logo-github />
</a>

<!--
The last comment block of each slide will be treated as slide notes. It will be visible and editable in Presenter Mode along with the slide. [Read more in the docs](https://sli.dev/guide/syntax.html#notes)
-->

---
layout: two-cols
---

# eBPF Overview 

## BPF Program 
* 使用伪C作为开发语言
* 使用llvm将C代码编译为BPF字节码
* KPROBE, XDP, SCHED_ACT, SCHED_CLS...

## BPF MAP 
* eBPF程序之间的数据共享
* eBPF程序和用户态程序之间的数据共享
* HASH, ARRAY, PROG_ARRAY, LRU_HASH, PERCPU_HASH, PER_CPU_ARRAY...

## BPF Link 
* 描述eBPF程序attach到hook的关系

::right::

<style>
.div {
  position:absolute;
  top:20%;
}
</style>

<div class="div">
<img src="/eBPF_overview.png" class="h-80"/>
<center>Fig. eBPF overview</center>
</div>

---
layout: two-cols
---

# eBPF Overview: eBPF Program

<style>
h2 {
  font-size:20px;
}

ul {
  font-size:10px;
}
</style>

## eBPF程序类型
* 定义在 <kbd>./include/uapi/linux/bpf.h bpf_prog_type</kbd>
* 在实际编写代码时，不同的程序类型使用不同的函数签名

## 可使用函数调用

* eBPF帮助函数<kbd>./src/bpf_helper_defs.h</kbd>
* 自己定义的 <kbd>static __always_inline</kbd> 函数
* 宏函数

## 编程限制
* 不允许使用 unbounded loop，对于低版本的eBPF不允许使用循环
* 不允许使用全局变量
* 栈区限制 MAX_BPF_STACK(512bytes)<kbd>./include/linux/filter.h</kbd>
* 字节码长度被限制为 4096条指令 <kbd>./include/uapi/linux/bpf_common.h BPF_MAXINSNS</kbd>

::right::

```c{all|14-26|14,15|18|21|23}
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, __u64);
    __uint(max_entries, 1000);
} count SEC(".maps");

static __always_inline __u64 cal_packet_len(void *b, void *e) {
    return e - b; 
}

#define lock_xadd(ptr, val)   __sync_fetch_and_add(ptr, val)

SEC("xdp")
int test_xdp(struct xdp_md *ctx) {
    void *data = (void *)(__u64)(ctx->data);
    void *data_end = (void *)(__u64)(ctx->data_end);
    __u64 pkt_len = cal_packet_len(data, data_end);
    __u64 key = 0;
    __u64 *val_p;
    val_p = bpf_map_lookup_elem(&count, &key);
    if (val_p != NULL) {
        lock_xadd(val_p, pkt_len);
    }
    return XDP_PASS;
}
```

---
layout: two-cols
---

# eBPF Overview : BPF MAP

<style>
h2 {
  font-size:20px;
}

ul {
  font-size:10px;
}
</style>

## BPF MAP类型
* 定义在 <kbd>./include/uapi/linux/bpf.h bpf_map_tyspe</kbd>
* 常用map类型： 
  * hash: BPF_MAP_TYPE_HASH(LRU_HASH, PER_CPU_HASH)
  * 数组: BPF_MAP_TYPE_ARRAY(PER_CPU_ARRAY)

## BPF MAP定义
* 定义section
* MAP类型
* key type
* value type
* max_entries

## BPF MAP操作
* 增/改, <kbd>long bpf_map_update_elem(void *map,const void *key,const void *value,__u64 flags)</kbd>
* 删, <kbd>long bpf_map_delete_elem(void *map,const void *key)</kbd>
* 查,<kbd>void* bpf_map_lookup_elem)(void *map,const void *key)</kbd>
  
::right::

```c{all|1-6|6|2,3,4,5|21}
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, __u64);
    __uint(max_entries, 1000);
} count SEC(".maps");

static __always_inline __u64 cal_packet_len(void *b, void *e) {
    return e - b; 
}

#define lock_xadd(ptr, val)   __sync_fetch_and_add(ptr, val)

SEC("xdp")
int test_xdp(struct xdp_md *ctx) {
    void *data = (void *)(__u64)(ctx->data);
    void *data_end = (void *)(__u64)(ctx->data_end);
    __u64 pkt_len = cal_packet_len(data, data_end);
    __u64 key = 0;
    __u64 *val_p;
    val_p = bpf_map_lookup_elem(&count, &key);
    if (val_p != NULL) {
        lock_xadd(val_p, pkt_len);
    }
    return XDP_PASS;
}
```

---
layout: two-cols
---

# eBPF Overview : BPF Link
## BPF Link?
* 表示attach关系
* libbpf attach系列API会返回 <kbd>bpf_link struct</kbd>
* BPF link 也拥有fd

## BPF Link的作用
* 方便对attach关系的管理
* BPF Link会增加BPF程序的引用计数
* BPF Link可以被pin到VFS中

::right::

```c{all|5}
struct bpf_link {
	int (*detach)(struct bpf_link *link);
	void (*dealloc)(struct bpf_link *link);
	char *pin_path;		/* NULL, if not pinned */
	int fd;			/* hook FD, -1 if not applicable */
	bool disconnected;
};
```
<center>Code.bpf_link define</center>

```c
struct bpf_link *
bpf_program__attach_xdp(const struct bpf_program *prog, int ifindex);

struct bpf_link *
bpf_program__attach_kprobe(const struct bpf_program *prog, bool retprobe,
			   const char *func_name);
```
<center>Code. libbpf attach sample APIs</center>

---
layout: two-cols
---

# eBPF Overview: Libbpf

<style>
h2 {
  font-size:30px;
}

ul {
  font-size:15px;
}
</style>

## Libbpf API特点
* API不直接对fd进行操作
* API对struct进行操作，这些struct对应着前面所说的概念，例如bpf_program
* BPF大部分系统调用针对fd进行操作，libbpf提供了相应的函数从对象获取fd

## 通过Libbpf加载eBPF对象的步骤(之一)
1. Open eBPF object using <kbd>bpf_object__open</kbd>
2. Load eBPF object into kernel using <kbd>bpf_object__load</kbd>
3. Get BPF program object and fd 
4. Get BPF MAP object and fd
5. Attach to specific hook 

::right::

```c{all|4|5|11|12-15|16|19|21}
int load_bpf_object(path) {
    int res; 
    struct bpf_object* obj;
    obj = bpf_object__open(path); //bpf_object__open_file 
    res = bpf_object__load(obj);
    if (res < 0) {
        return -1;
    }
    //get prog
    struct bpf_program *prog;
    prog = bpf_object__find_program_by_name(obj, NAME);
    res = libbpf_get_error(prog);
    if (res <0 ) {
        return -1;
    }
    int prog_fd = bpf_program__fd(prog);
    //get map 
    struct bpf_map *map;
    map = bpf_object__find_map_by_name(obj, NAME);
    res = libbpf_get_error(map);
    int map_fd = bpf_map__fd(map);
    
    #attaches here
}
```
---

# eBPF Overview: Dev Big Picture


## 如何判断能否利用eBPF实现某些功能？ 
1. 根据需求查看eBPF程序类型，查找相关资料确定其功能
2. 查看该eBPF程序类型的hook, 如何加载？ 如何被调用？ 
3. 查找该程序类型的demo 
4. 根据程序复杂度以及功能，查找需要使用的 BPF_MAP
5. 具体的开发和调试

---
layout: two-cols
---

# Lifetime of eBPF Object 

<style>
h2 {
  font-size:10px;
}

ul {
  font-size:8px;
}
</style>

### BPF 对象
* BPF MAP, BPF PROG, BPF_LINK
* 每一个对象有一个引用计数 ref
* 只有当ref为0时，对象才会被内核销毁

### BPF MAP REF
* 创建MAP, ref = 1
* load prog, ref+=1 (每次使用到该map的程序被加载)
* prog被销毁, ref-=1

### BPF PROG REF
* 加载prog, ref = 1
* attach(create a link), ref += 1
* detach(delete a link), ref -= 1

### BPF Link REF
* attach, ref = 1 (global e.g. xdp,tc 应用程序退出link不会被销毁)
* detach, ref -= 1 (to be test, 同时pin和detach?)

### PIN
* fd关闭，all object ref-=1
* pin , all object ref+=1
* unpin, all object ref-=1

### Other(to be test)
* prog array
* map of map
* bpftool

::right::

<center>
<img src="/eBPF_MAP.png" class="h-120"/>
</center>

<center>Fig.BPF MAP创建流程</center>

---
layout: two-cols
---

# eBPF VFS

<style>
ul {
  font-size: 8px;
}
</style>

#### eBPF VFS本质
* eBPF VFS本质是一个虚拟的文件系统
* 对于pin到VFS的object, VFS持有该object的一个引用计数，使得object的引用计数不会变为0，被销毁
* 并不是将内存的内容保存到文件系统上
* 可以通过VFS获取object fd, 实现用户态和内核态，eBPF程序之间的map sharing

#### PIN using fd
* 通过 <kbd>int bpf_obj_pin(int fd, const char *pathname)</kbd> 将object pin到 VFS
* 通过 <kbd>int bpf_obj_get(const char *pathname)</kbd> 获取已经pin到VFS的object的fd 

#### PIN using higher-level APIs
* pin map <kbd>int bpf_map__pin(struct bpf_map *map, const char *path)</kbd>
* pin prog <kbd>int bpf_program__pin(struct bpf_program *prog, const char *path)</kbd>
* pin object <kbd>int bpf_object__pin(struct bpf_object *object, const char *path)</kbd>

#### PIN using bpftool
* 使用bpftool可以查看已经加载到内存中的object(map, program, link)
* 可以将指定的 object pin 到指定的路径


#### UNPIN
* 直接使用 rm（简单粗暴） 
* 使用 libbpf 提供的 unpin API

::right:: 

```c{all|3,4|6,7|9|all}
void pin_object(struct bpf_map *map, struct bpf_program *prog) {
    //pin use fd 
    bpf_obj_pin(bpf_map__fd(map), PATH);
    bpf_obj_pin(bpf_program__fd(prog), PATH);
    //pin use high level api 
    bpf_map__pin(map, PATH);
    bpf_program__pin(prog, PATH);
    //get pin fd 
    int fd = bpf_obj_get(PATH)
}
```
<div style="margin-top:20px">
<center>
<img src="/bpftool_pin.png"/>
</center>
</div>

<div style="margin-top:15px">
<center>
<img src="/pin_sample.png"/>
</center>
</div>

---
layout: two-cols
---

# eBPF MAP Sharing 

## 如果eBPF程序在同一.o文件内
* 根据MAP创建过程，同一.o文件内的prog使用的相同的MAP指针会被fd替换
* 同一.o文件内的prog直接共享MAP

## 如果eBPF程序在不同.o文件内
* MAP会被创建多次，因此指针被替换为不同map的fd
* 无法直接共享MAP,虽然使用的MAP名字相同但是是不同的MAP


::right::

<style>
  span {
    font-size: 6px;
  }
</style>

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, __u64);
    __uint(max_entries, 1000);
} count SEC(".maps");

SEC("xdp")
int test_xdp(struct xdp_md *ctx) {
    __u64 key = 0;
    __u64 *val_p;
    val_p = bpf_map_lookup_elem(&count, &key);
    if (val_p != NULL) lock_xadd(val_p, 1);
    return XDP_PASS;
}

SEC("xdp")
int test_xdp2(struct xdp_md *ctx) {
    __u64 key = 0;
    __u64 *val_p;
    val_p = bpf_map_lookup_elem(&count, &key);
    if (val_p != NULL) bpf_trace_printk("count %lu", *val_p);
    return XDP_PASS;
}
```


---
layout: two-cols
---

# eBPF MAP Sharing

<style>
li {
  font-size:12px;
}

ul {
  font-size:10px;
}

</style>
### 不在同一个.o文件的progs如何共享MAP?

1. 获取已创建MAP的fd
   * 调用libbpf API从object对象中获取fd(创建MAP和使用MAP是同一个进程)
   * 通过<kbd>bpf_obj_get</kbd>获取已经PIN到VFS的MAP fd

2. 使用已经创建的MAP的fd
   * 在调用<kbd>bpf_object__open</kbd>之前
   * 调用<kbd>int bpf_map__reuse_fd(struct bpf_map *map, int fd)</kbd>
3. 加载BPF object

```c{all|4,5}
void reuse_map(int reuse_fd) {
    struct bpf_object* obj;
    obj = bpf_object__open(path); 
    map = bpf_object__find_map_by_name(obj, NAME);
    bpf_map__reuse_fd(map, reuse_fd);
    bpf_object__load(obj);
}
```

::right::

<center>
<img src="/share_map.png" class="h-110"/>
</center>

<center>Fig. BPF MAP reuse fd</center>

---
layout: two-cols
---

# eBPF MAP Sharing

### 如何在用户态和内核态共享MAP?
1. 关键点:获取MAP fd(用户态和内核态使用同一个MAP fd)
   * 调用libbpf API从object对象中获取fd(创建MAP和使用MAP是同一个进程)
   * 通过<kbd>bpf_obj_get</kbd>获取已经PIN到VFS的MAP fd 

2. 用户态MAP操作
  * 增/改, <kbd>int bpf_map_update_elem(int fd,const void *key,const void *value,__u64 flags)</kbd>
  * 删, <kbd>int bpf_map_delete_elem(int fd,const void *key)</kbd>
  * 查,<kbd>int bpf_map_lookup_elem(int fd,const void *key, void *value)</kbd>
  
::right::

```c{all|3|8-13}
int lookup_flow(const char* map_path, u64 *data, u32 src, u32 dst, u16 source, u16 port) {
    int res;
    int fd = bpf_obj_get(map_path);
    if (fd <= 0) {
        return -1;
    }
    struct tcp4flow flow_key; 
    flow_key.src = src;
    flow_key.dst = dst;
    flow_key.srouce = source;
    flow_key.port = port;
    u64 bytes;
    res = bpf_map_lookup_elem(fd, &flow_key, &bytes);
    *data = bytes;
    return 0;
}
```

<center>Code. user-space bpf map sample</center>

---
layout: two-cols
---

# eBPF for Packet Processing : Overview

### Hook for eBPF Packet Processing
* ingress packets : XDP, TC
* egress packets : TC 

### ability of eBPF Packet Processing
* 统计/监控：流量监控，包监控，统计网络信息....
* 修改packet内容
* 过滤 (防火墙 iptable)
* 重定向 (负载均衡器)
* 其它...（prestack 缓存，BMC)

### 和kernel-bypass方案的比较(XDP)
* 可以通过重定向/AF_XDP的方式完全绕过内核
* 也可以对包进行一定的修改之后复用内核网络栈

::right:: 

<img src="/eBPF_packet_process.png"/>
<center>Fig. eBPF packet processing</center>

---
layout: two-cols
---

# eBPF for Packet Processing : XDP

<style>
ul {
  font-size: 10px;
}
</style>

### XDP程序参数

* <kbd>./include/uapi/linux/bpf.h struct xdp_md</kbd>
* 尚未分配skb的原始数据
* 数据包区域： $[data, data\_end)$
* 拥有最多32bytes的meta : $[data\_meta, data)$

### XDP的返回值
* 定义在 <kbd>./include/uapi/linux/bpf.h enum xdp_action</kbd>
* XDP_ABORTED = 0, BPF异常
* XDP_DROP, 将包丢弃
* XDP_PASS, 重新交给内核处理
* XDP_TX, 反射，将包从原有的nic重新发送回去
* XDP_REDIRECT,  重定向，定向到不同的cpu, XSK(AF_XDP), Nic(egress)

### XDP的功能
* direct packet access(读写数据包)
* grow/shrink packet room (bpf_xdp_adjust_head)
* redirect : 先调用bpf_redirect，再返回XDP_REDIRECT, 如果是 XDP_TX直接返回即可

::right::

```c{all|2,3|3,4|all}
struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	/* Below access go through struct xdp_rxq_info */
	__u32 ingress_ifindex; /* rxq->dev->ifindex */
	__u32 rx_queue_index;  /* rxq->queue_index  */

	__u32 egress_ifindex;  /* txq->dev->ifindex */
};
```

```c{all|1,2|3,4,6|7-10|12,14}
SEC("xdp")
int test_xdp(struct xdp_md *ctx) {
    void *data = (void *)(__u64)(ctx->data);
    void *data_end = (void *)(__u64)(ctx->data_end);
    void *pos = data;
    //eth
    struct ethhdr *eth = pos;
    if ((void*)(eth + 1) > data_end) {
        goto fail;
    }
    pos += sizeof(struct ethhdr);
    return XDP_PASS;
fail:
    return XDP_DROP;
}
```

---
layout: two-cols
---

# eBPF for Packet Processing : TC

<style>
ul {
  font-size: 10px;
}
</style>

### TC程序参数

* <kbd>./include/uapi/linux/bpf.h struct __sk_buff</kbd>
* 已经分配了sk_buff, 有丰富的信息(图中只展示一部分)
* 有20bytes的可用cb
* 通过data_meta和XDP程序共享数据
* 使用data, data_end访问线性区

### TC返回值(TC_ACT 控制码)
* 定义在 <kbd>./include/uapi/linux/pkt_cls.h</kbd>
* TC_ACT_OK, TC数据包处理流程允许继续处理数据包
* TC_ACT_SHOT, 终止数据包处理，丢弃数据包
* TC_ACT_UNSPEC(-1), 使用TC的默认操作，类似分类器返回 -1 
* TC_ACT_REDIRECT, 重定向(egress or ingress Nic)
* ...

### TC的功能
* direct packet access(读写数据包线性区域，通常是packet header)
* 使用 <kbd>bpf_skb_load_bytes bpf_skb_pull_data</kbd>来读写非线形区域(通常是应用层数据)
* grow/shrink packet room (bpf_skb_adjust_room)
* redirect : 重定向(egress or ingress Nic)(to be test)
* 和其它的TC模块进行交互(TC_CLS可以直接返回class id, 修改skb的classid?)

::right:: 

```c
struct __sk_buff {
	__u32 len;
	__u32 cb[5];
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
  ...
};

```

```c{all|1,2|3,4,6|7-10|12,14}
SEC("tc")
int test_tc(struct __sk_buff *ctx) {
    void *data = (void *)(__u64)(ctx->data);
    void *data_end = (void *)(__u64)(ctx->data_end);
    void *pos = data;
    //eth
    struct ethhdr *eth = pos;
    if ((void*)(eth + 1) > data_end) {
        goto fail;
    }
    pos += sizeof(struct ethhdr);
    return TC_ACT_SHOT;
fail:
    return TC_ACT_UNSPEC;
}
```

---
layout: two-cols
---


<style>
ul {
  font-size: 15px;
}
</style>

# eBPF for Packet Processing : Direct Packet Access

### Direct Packet Access(DPA) ? 
* DPA的含义是**直接**通过指针来访问packet
* DPA可以用来访问packet(XDP),packet线性区(TC),meta

### How to use DPA?
* 要点在于，在对指针解引用之前必须验证指针的有效性
* 有效性指的是: $ptr \in [data, data\_end)$
* 验证伴随着编程的全程，只要我们使用了一个新的指针访问数据包，就必须验证这个指针。

### TIPs for DPA 
* 切记使用指针之前进行验证
* 采用扫描的方式
  1. 从packet开始到结束，扫描packet， pos 就是扫描线，每次扫描都进行验证
  2. 用新的变量记录下已经验证过的pos (记录重要的节点)

::right::

```c
struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	/* Below access go through struct xdp_rxq_info */
	__u32 ingress_ifindex; /* rxq->dev->ifindex */
	__u32 rx_queue_index;  /* rxq->queue_index  */
};
```

```c
if ((void*)ptr + len > data_end) {
    //如果ptr不是有效的指针
    return;
}
// access ptr here
```

<center>
<img src="/direct_packet_access.png"/>
</center>

<center>
<img src="/DPA_SCAN.png"/>
</center>
---
layout: two-cols
---

# eBPF for Packet Processing : Adjust Room

### How to adjust room 
* 使用adjust room相关的eBPF帮助函(bpf_xdp_adjust_head, bpf_xdp_adjust_tail)
* 可以从头和尾两个方向进行adjust 

### Adjust room技术要点
* adjust的本质是增加packet内存，并修改指针, adjust tail 修改 data_end, adjust head 修改data 
* 通过delta参数来控制修改空间的大小，指针+=delta
* 因此对于adjust head来说，如果delta为负代表增加空间，为正减少空间，adjust tail刚好相反
* adjust空间之后，所有的指针必须重新验证。

::right::

```c{all|3-10|6|11|13-16}
SEC("xdp")
int test_xdp(struct xdp_md *ctx) {
    void *data = (void *)(__u64)(ctx->data);
    void *data_end = (void *)(__u64)(ctx->data_end);
    int res; 
    struct hdr_cursor nh = {.pos = data};   //scan
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);
    bpf_xdp_adjust_head(ctx, -BYTES) // grow, positive for shrink 
    //recheck
    data = (void *)(__u64)(ctx->data);
    data_end = (void *)(__u64)(ctx->data_end);
    nh.pos = data;     //scan
    res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);
}
```

<center>
<img src="/adjust_room.png"/>
</center>

---
layout: two-cols
---  

# eBPF Tail Call 

### What is eBPF Tail Call 
* 解决ebpf单个程序最大长度限制的问题。ebpf最多支持32次尾调用
* 划分程序结构，便于通过验证器的验证，开发和调试
* 通过尾调用动态修改eBPF程序行为（policy chain)

### eBPF Tail Call 特性
* 如果一个函数执行了尾调用，那么被调用函数和调用函数的 **bpf程序类型相同**
* 一个函数执行尾调用，跳转到另一个bpf程序之后，函数**不会返回调用函数的执行流**

### 使用eBPF Tail Call 
* 声明类型为 BPF_MAP_TYPE_PROG_ARRAY的映射(key 和 value类型均为int)
* 在用户态在prog_array对应的index，写入被调用程序的fd
* bpf程序中，在适当的时候执行该bpf_tail_call方法

::right:: 

```c{all|1-6|3-4|10|17|all}
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_XDP_ACTION_NUM);
} xdp_actions SEC(".maps");
SEC("xdp")
int entry(struct xdp_md *ctx)
{
    bpf_tail_call(ctx, &xdp_actions, 0);
    //will not go here if tailcall success
    return XDP_DROP;
}
SEC("xdp")
int prog1(struct xdp_md *ctx)
{
    bpf_trace_printk("this is prog1");
    return XDP_PASS;
}
```

```c{all|4-5}
void set_tail_call() {
    //get prog_array_fd of xdp_actions
    //get fd of prog1 
    int index = 0;
    bpf_map_update_elem(prog_array_fd, &index, &prog1_fd, 0);
}
```

---
layout: two-cols
---  

# Techniques in eMPTCP : Policy Chain

## What is Policy Chain 
* 通过eBPF尾调用实现，利用了eBPF尾调用动态修改eBPF程序行为的特性
* eBPF尾调用的增强，**动态决定一条eBPF程序尾调用链**

## Challenge
* eBPF程序不支持全局变量
* 如何知道下一个要调用的程序?(index)
* 如何处理并发问题? (例如仅仅通过普通的BPF MAP来记录下调用信息)

::right::

<img src="/policy_chain.png"/>
<center>Fig. eMPTCP design overview</center>

---
layout: two-cols
---  

# Techniques in eMPTCP : Policy Chain

### 利用Meta data来保存TailCall所需的状态信息(context)
* XDP data_meta(32bytes)
* TC cb array(20bytes) (tc没有找到操作 data_meta的接口)
* meta是每一个包都有的，解决了并发问题。

### Context
* 每当尾调用发生时, 当前的eBPF程序从meta data处获取context信息
* 从context信息获取下一个要调用的程序
* 从context信息获取参数
* 参数可以是立即数(直接保存在context中)，也可以从BPF_MAP中再读一次

::right::

```c
union chain_t{
    __u8 idx;
    __u8 next_idx;
};
struct action_t {
    union chain_t chain;
    __u8       param_type:2,
               rsv:6;
    union {
        __u16 imme;
        struct {
            __u8 offset;
            __u8 len;
        } mem;
    } param;
};
struct action_chain_t {
    struct action_t actions[ACTION_CHAIN_MAX_LEN];
};
```

<center><img src="/context.png" class="h-30"/></center>
<center>Fig. policy chain context</center>

---
layout: two-cols
---  

# Techniques in eMPTCP : Policy Chain

```c
#define XDP_POLICY_PRE_SEC \
    xdp_policy_t POLICY; \
    res = xdp_get_and_pop_policy(ctx, &POLICY);\
    CHECK_RES(res);\
    __u8 NEXT_IDX = POLICY.chain.next_idx;

#define XDP_ACTION_POST_SEC \
next:                                   \
    if (NEXT_IDX == DEFAULT_POLICY) {\
        goto exit;                   \
    }                                \
    goto next_action;
```

<center><img src="/context.png" class="h-30"/></center>
<center>Fig. policy chain context</center>

::right::

```c{all|4,5|10-12|13}
SEC("xdp")
int entry(struct xdp_md *ctx) {
    //read chain context policies from bpf_map(dymatically)
    int first_policy;
    res = xdp_set_policy_chain(ctx, policies, &first_policy);
    if (res < 0) {
        goto fail;
    }

    if (first_policy == DEFAULT_POLICY) {
        return XDP_PASS:
    }
    bpf_tail_call(ctx, &xdp_actions, first_policy);
}
```

```c{all|3|4|5|6-7}
SEC("xdp")
int subpolicy(struct xdp_md *ctx) {
    XDP_POLICY_PRE_SEC
    __u16 param = POLICY.param.imme;
    XDP_ACTION_POST_SE
next_action:
    bpf_tail_call(ctx, &NEXT_IDX);
}
```
---
layout: two-cols
---  

# Techniques in eMPTCP : Bound-Loop

### 思路
* 设置循环边界（40字节) 
* 逐字节扫描（外层for)
* 逐选项检查(SCAN_MPTCP_OPT_SUB)
* 通过指针(start/pos)记录当前扫描的位置
```c{all|2|3|4-6|7-9|10-12|all}
#define SCAN_MPTCP_OPT_SUB(pos, de, sub){\
    struct mptcp_option *opt = (pos);\
    CHECK_BOUND(opt, (de));\
    if (opt->kind == MPTCP_KIND && opt->sub == (sub)){\
        goto found;\
    }\
    if (opt->kind == 0 || opt->kind == 1) {\
        pos += 1;\
    }\
    else {\
        pos += opt->len;\
    }\
}\
```

::right::

```c{all|6|7|8|10-13|16-18|all}
static __always_inline int check_mptcp_opt(struct hdr_cursor *nh, void *data_end, int tcp_opt_len, int sub) {
    void *start = nh->pos;
    void *pos = start;
    #pragma unroll 40
    for (int index = 0; index < 40; index++) {
        int curr_idx = pos - start;
        if (curr_idx >= tcp_opt_len) goto not_exists;
        if (curr_idx == index) SCAN_MPTCP_OPT_SUB(pos, data_end, sub);
    }
found:
    //found mptcp option
    nh->pos = pos;
    return 0;
out_of_bound:
    return -1;
not_exists:
    return -2; 
}
```

### ps: 
* <kbd> CHECK_BOUND(opt, (de)); </kbd>不可省略
* 在编程时随时要验证指针有效性
* 封装API

---
layout: two-cols
---  


# Techniques in eMPTCP : Bound-Loop

```c{all|2|3|4|5-6|all}
#define COPY_TCP_OPT_TO_P(index, tcp_opt_len, pkt_dst, src, de){                \
    if ((index) >= (tcp_opt_len)) goto out;                                     \
    CHECK_BOUND_BY_SIZE(pkt_dst, de, 4);                                        \
    __builtin_memcpy((void*)(pkt_dst),(void*)(src),4);                          \
    (src) = (void*)(src) + 4;                                                   \
    (pkt_dst) = (void*)(pkt_dst) + 4;                                                   \
}\

```

**关键** 
1. <kbd> CHECK_BOUND_BY_SIZE(pkt_dst, de, 4);</kbd>不能省略
2. 随时检查指针有效性
3. SCAN的方法(pkt_dst)
4. 固定次数的循环，4字节一次，循环10次

::right::

```c{all|8-9|10|14|19-20|all}
static __always_inline int add_tcp_opts(struct hdr_cursor *nh, void *data_end, const void *opts, __u16 size) {
    if (opts == NULL) goto fail;
    if ((size & 0x3) != 0) {
        //size % 4 != 0
        goto fail;
    }

    void *pkt_dst = nh->pos;
    const void *src = opts;
    __u16 s4 = size >> 2;  

#pragma unroll 10
    for (int i = 0; i < 10; i++) {
        COPY_TCP_OPT_TO_P(i, s4, pkt_dst, src, data_end);
    out:
        break;
    }

    nh->pos = pkt_dst;
    return 0;

out_of_bound:
fail:
    return -1;
}
```


---
layout: two-cols
---  
# Techniques in eMPTCP : Packet Manipulation

<center><img src="/packet_modify.png" class="h-30"/></center>
<center>Fig. packet modify</center>
<center><img src="/packet_rmopt.png" class="h-30"/></center>
<center>Fig. packet remove opt</center>

**方法：**
* 利用 DPA 获取选项指针
* 修改指针指向的内容
* 重新计算校验和
::right::

```c
static __always_inline __sum16 csum16_add(__sum16 csum, __be16 addend)
{
	__u16 res = (__u16)csum;

	res += (__u16)addend;
	return (__sum16)(res + (res < (__u16)addend));
}
static __always_inline __sum16 csum16_sub(__sum16 csum, __be16 addend)
{
	return csum16_add(csum, ~addend);
}
static __always_inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new)
{
	*sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}
```

```c{all|3|4|5|6,7|8|all}
SEC("xdp")
int modify_recv_win(struct xdp_md *ctx) {
    XDP_POLICY_RRE_SEC
    is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);
    u16 window = POLICY.param.imme;
    csum_replace2(&tcph->check, tcph->window, window); 
    tcph->window = window;
    XDP_POLICY_POST_SEC
}
```

---
layout: two-cols
---  
# Techniques in eMPTCP : Packet Manipulation

```c{all|6,7,8|9,10|12-15|16|all}
static __always_inline int xdp_grow_tcp_header(struct xdp_md *ctx, struct hdr_cursor *nh,  __u16 tcp_opt_len, int bytes, int *modified) {
    void * data = (void *)(long)ctx->data;
    void * data_end =  (void *)(long)ctx->data_end; 
    nh->pos = data;
    int res;
    struct pkt_header_buf_t buf;
    //1. store header to buf
    restore_header(&buf, nh, data_end, tcp_opt_len);
    //2. grow header
    bpf_xdp_adjust_head(ctx, -bytes);
    //3 reset data and data_end
    data =  (void *)(long)ctx->data; 
    data_end =  (void *)(long)ctx->data_end; 
    //4. recover header 
    nh->pos = data;
    recover_header(&buf, nh, data_end, tcp_opt_len);
    return 0;
}
```

::right::

```c{all|2|3|4|5|6,7|all}
// add MP_PRIO 4bytes
xdp_grow_tcp_header(ctx, &nh, tcp_opt_len, sizeof(struct mp_prio), &modified);  //1 
is_tcp_packet(&new_nh, data_end, &eth, &iph, &tcph);  //2
add_tcp_opts(&nh, data_end, &prio_opt, sizeof(struct mp_prio));  //3
update_tcphlen_csum(iph, tcph, sizeof(struct mp_prio));  //4
//recompute checksum , mp_prio 4 bytes
add_tcpopt_csum(&tcph->check, &prio_opt, sizeof(struct mp_prio)); //5
```
<center><img src="/packet_insertopt.png" class="h-30"/></center>
<center>Fig. insert tcp opt</center>

<style>
  li {
    font-size:12px;
  }
</style>

**要点**： 
1. BPF没有提供直接扩展tcp头部的帮助函数，因此最关键的是实现增长TCP头部空间
2. move forward 也可以采用逐字节移动的方式(to be test)
3. 如果修改了包长度，一定要记得更新，ip头部和TCP伪头部校验和。

---
layout: two-cols
---  

# My eBPF Lib 
## Feture 
* 利用python 和 C 混编封装了 libbpf API
* 使用异常的风格来进行错误处理
* 封装了加载eBPF object的类
* 封装了perf_output 
* 其它方便使用eBPF的API

```python
#python func wrapper for easy usage 
lib = ct.CDLL(CONFIG.libbpf_path, use_errno = True)
lib.bpf_obj_pin.restype = ct.c_int
lib.bpf_obj_pin.argtypes = [ct.c_int, ct.c_char_p]
def bpf_obj_pin(fd, pathname):
    '''
    @param:
        fd: bpf object fd 
        pathname : path in bpf virtual file system(str)
    '''
    res = lib.bpf_obj_pin(ct.c_int(fd), pathname.encode(encoding = "utf-8"))
    check_res("bpf_obj_pin", res)
```

::right::
**使用json描述bpf object对象**
```json
XDP_ACTION_ENTRY = {
    "obj_path" : "path of xdp_action.o",
    "progs" : {
        "action_entry" : {
            "prog_type" : BPF_PROG_TYPE_XDP
        }
    },
    "pin_maps" : {
        "xdp_actions" : {
            "pin_path" : "path of xdp_actions",
            "flag" : BPFLoaderBase.PIN_MAP_FLAG.PIN_IF_NOT_EXIST
    }
}
```


**方便的加载API**
```python
#loader BPFObjectLoader / BPFBCCLoader
with load(bpf_obj, loader, unpin_only_fail = True) as entry:
   bpf_xdp_attach(if_nametoindex(interface), \
      entry.get_prog_fd("action_entry"), XDP_FLAGS.XDP_FLAGS_UPDATE_IF_NOEXIST, ct.c_void_p(None))  
```

---
layout: two-cols
--- 

```python
#create selector chian
sc = SelectorChain()
sc.add("ip_pair", SELECTOR_AND).\
   add("service", SELECTOR_AND)
#create actor chian
ac = ActionChain()
ac.add("add_subflow").add("redirect")
#create policy chain
pc = PolicyChain(sc, ac)
#apply policy chain
pc.select(0,local_addr = "10.200.0.2",\
remote_addr = "10.200.1.2").set(1, "spark")
```

::right

```c
#include "emptcp_utils.h"
#include "emptcp_common.h"
SEC("xdp")
int your_own_policy(struct xdp_md *ctx) 
{
    SELECTOR_PRE_SEC 

/*your own codes*/ 

    SELECTOR_POST_SEC
}
```
---

# Future Work

1. 首要工作时完善目前的eMPTCP
   * 完善代码
   * innetwork-computing
   * packet 伪装
   * 填坑

2. AF_XDP
   * AF_XDP作为一种 kernel-pypass 的手段
   * libxdp 

3. eBPF
   * 其它类型的eBPF程序(比如SOCK_OPTS, STRUCT_OPTS)，寻找新的use case
   * 看一下eBPF源代码，看看能不能在MAP存储等方面(JIT以上，系统调用以下的优化空间)
