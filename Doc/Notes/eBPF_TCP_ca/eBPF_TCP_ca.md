# eBPF_TCP_CA

## 数据结构

### 全局变量 unsupported_ops

不支持使用eBPF实现的函数。(get_info)

```c
static u32 unsupported_ops[] = {
	offsetof(struct tcp_congestion_ops, get_info),
};
```

**全局变量 optional_ops **

可选项，这些函数可以不需要用eBPF函数实现(并不一定要实现)

```c
static u32 optional_ops[] = {
	offsetof(struct tcp_congestion_ops, init),
	offsetof(struct tcp_congestion_ops, release),
	offsetof(struct tcp_congestion_ops, set_state),
	offsetof(struct tcp_congestion_ops, cwnd_event),
	offsetof(struct tcp_congestion_ops, in_ack_event),
	offsetof(struct tcp_congestion_ops, pkts_acked),
	offsetof(struct tcp_congestion_ops, min_tso_segs),
	offsetof(struct tcp_congestion_ops, sndbuf_expand),
	offsetof(struct tcp_congestion_ops, cong_control),
};
```



## 代码逻辑

### bpf_tcp_ca_verifier_ops

#### bpf_tcp_ca_get_func_proto



### bpf_tcp_ca_init

`static int bpf_tcp_ca_init(struct btf *btf)` 

```c
static int bpf_tcp_ca_init(struct btf *btf)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, "sock", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	sock_id = type_id;

	type_id = btf_find_by_name_kind(btf, "tcp_sock", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	tcp_sock_id = type_id;     //设置全局static变量 tcp_sock_id 
	tcp_sock_type = btf_type_by_id(btf, tcp_sock_id); //设置全局static变量 tcp_sock_type

	return 0;
}

```

主要是为了获取并出示化， tcp_sock_id 和 tcp_sock_type 这两个全局静态变量。这两个变量应该是供verifier使用, 以及定义 bpf_func_proto使用。

### bpf_tcp_ca_init_member

`static int bpf_tcp_ca_init_member(const struct btf_type *t, const struct btf_member *member,  void *kdata, const void *udata)`

bpf_struct_ops 的 init_member 钩子的实现。被调用的时候，负责： 

1. 处理非函数指针成员，flags 和 name 
2. 对于函数指针成员检查是否合法

-> `const struct tcp_congestion_ops *utcp_ca;`

-> `struct tcp_congestion_ops *tcp_ca;`

-> `int prog_fd; u32 moff;`

-> `utcp_ca = (const struct tcp_congestion_ops *)udata; tcp_ca = (struct tcp_congestion_ops *)kdata;`

-> `moff = __btf_member_bit_offset(t, member) / 8;`  获取该成员在tcp_congestion_ops结构体的字节偏移量

-> `siwtch (moff)` 

​	--> `case offsetof(struct tcp_congestion_ops, flags):` 处理 `tcp_congestion_ops.flags` 

​		---> `tcp_ca->flags = utcp_ca->flags; return 1` 

​	--> `case offsetof(struct tcp_congestion_ops, name):`  处理 `tcp_congestion_ops.name` 

​		---> `bpf_obj_name_cpy(tcp_ca->name, utcp_ca->name,  sizeof(tcp_ca->name))` 

​		---> `if (tcp_ca_find(utcp_ca->name)) return -EEXIST;` 

-> `prog_fd = (int)(*(unsigned long *)(udata + moff));` 

-> `if (!prog_fd && !is_optional(moff) && !is_unsupported(moff)) return -EINVAL;` **prog_fd=0 意味着BPF程序并没有提供该成员函数的实现**

​	--> `is_optional(moff)`   判断该函数是否是可选的函数（没有要求一定要实现） 

​	--> `is_unsupported(moff)` 判断是否支持用eBPF程序实现该函数。

-> `return 0;`

### bpf_tcp_ca_reg

将使用bpf实现的拥塞控制算法注册到拥塞控制算法链表中。

```c 
static int bpf_tcp_ca_reg(void *kdata)
{
	return tcp_register_congestion_control(kdata);
}
```

