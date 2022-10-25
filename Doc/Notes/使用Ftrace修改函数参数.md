# 使用Ftrace修改函数参数

## 引入

ebpf程序对于pt_regs变量只能读取无法修改，导致其功能被局限在tracing上，而无法对现有的内核函数进行参数的修改。Ftrace为内核模块提供了api，来对内核符号表(kallsyms)中注册的函数进行添加回调函数的操作。在内核代码([热补丁的实现原理](https://richardweiyang-2.gitbook.io/kernel-exploring/00-index-3/05-kernel_live_patch))中看到了通过使用ftrace修改regs->ip来进行跳板的跳转，于是猜想ftrace可以在回调函数中可以进行修改寄存器的操作从而修改被hook函数的参数。

## 实验流程

首先需要一个被hook的函数，这里需要自己写一个能与用户态交互的内核模块，借鉴了[这篇](https://zhuanlan.zhihu.com/p/420194002)文章来实现。具体功能是在用户态使用`cat /dev/lkm_example` 时会出发模块中的`device_read`函数，来向用户态打印hello world。这里选择hook `device_read`来进行实验。

`device_read`函数代码如下：

```c
#define DEVICE_NAME "lkm_example"
#define EXAMPLE_MSG "Hello, World!\n"
#define MSG_BUFFER_LEN 15
......
    
static char msg_buffer[MSG_BUFFER_LEN];
static char *msg_ptr;
......
    
/* When a process reads from our device, this gets called. */
static ssize_t device_read(struct file *flip, char *buffer, size_t len, loff_t *offset) {
 int bytes_read = 0;
  /* If we’re at the end, loop back to the beginning */
  if (*msg_ptr == 0) {
   msg_ptr = msg_buffer;
  }
  /* Put data in the buffer */
  while (len && *msg_ptr) {
    /* Buffer is in user data, not kernel, so you can’t just reference
     * with a pointer. The function put_user handles this for us */
    printk("lkm:flip: %lx, buffer: %lx, len: %lx, offset: %lx",flip,buffer,len,offset);//测试函数的参数是否被修改,
    put_user(*(msg_ptr++), buffer++);
    len--;
    bytes_read++;
 }
  return bytes_read;
}
```

hook点准备好了，接下来需要编写ftrace回调函数的模块了，首先需要了解几个api，时间允许可以细读[这篇](https://docs.kernel.org/trace/ftrace-uses.html)文章，省流版如下：

`struct ftrace_ops`：用来存储ftrace回调函数等信息，其中的成员`ftrace_func_t func`用来保存回调函数的指针

`ftrace_set_filter`：用来将准备好的`ftrace_ops`限制在指定的hook函数上，如果不设置，则会在hook在所有函数上(比如schedule())，很危险- -

`register_ftrace_function`：用来将准备好的ftrace_ops注册到内核中并启用该hook点，需要在设置hook点之后调用

```c
/**
 * register_ftrace_function - register a function for profiling
 * @ops:	ops structure that holds the function for profiling.
 *
 * Register a function to be called by all functions in the
 * kernel.
 *
 * Note: @ops->func and all the functions it calls must be labeled
 *       with "notrace", otherwise it will go into a
 *       recursive loop.
 * notrace宏位于<linux/ftrace.h>，用于防止回调函数也被hook而导致无限循环，但好像不用加也可以，并且ftrace提供了其他的机制来防止这一现象
 */
int register_ftrace_function(struct ftrace_ops *ops)
```



```c
/**
 * ftrace_set_filter - set a function to filter on in ftrace
 * @ops - the ops to set the filter with
 * @buf - the string that holds the function filter text.
 * @len - the length of the string.
 * @reset - non zero to reset all filters before applying this filter.
 *
 * Filters denote which functions should be enabled when tracing is enabled.
 * If @buf is NULL and reset is set, all functions will be enabled for tracing.
 * 这里第二个参数是被hook函数在内核符号表中的名字，第三个参数是名字字符串的长度，第四个参数代表是追加模式还是覆盖模式
 */
int ftrace_set_filter(struct ftrace_ops *ops, unsigned char *buf,
		       int len, int reset)
```

此外，ftrace规定了回调函数的类型声明

```c
void callback_func(unsigned long ip, unsigned long parent_ip,
                   struct ftrace_ops *op, struct pt_regs *regs);
//ip是instruction pointer，指示fentry的指令位置
//parent_ip指示被hook函数的位置
```

接下来使用api来编写ftrace模块

```c
// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>

#include <linux/sched.h> /* for wake_up_process() */
#include <linux/ftrace.h>

//自定义的回调函数
static void callback_func(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *op, struct ftrace_regs *regs){
    //代码开始和结束均是防止循环调用而加的测试代码
    int bit;
    bit = ftrace_test_recursion_trylock(ip, parent_ip);
    if (bit < 0)
        return;
	//trace逻辑为如下三行，将所有的信息均打印出来
    trace_printk("callback_func! ,ip:%lx, pip:%lx, *op:%lx, *regs:%lx, dx:%lx, ax:%lx, bx:%lx, cx:%lx, si:%lx, di:%lx, r8:%lx,r9:%lx,r12:%lx,r13:%lx,r14:%lx\n",ip,parent_ip,op,regs,regs->regs.dx,regs->regs.ax,regs->regs.bx,regs->regs.cx,regs->regs.si,regs->regs.di,regs->regs.r8,regs->regs.r9,regs->regs.r12,regs->regs.r13,regs->regs.r14);
    regs->regs.dx = 0x0000000000000001ull;//修改dx，相当于修改被hook函数的第三个参数
    trace_printk("regs changed! ,ip:%lx, pip:%lx, *op:%lx, *regs:%lx, dx:%lx, ax:%lx, bx:%lx, cx:%lx, si:%lx, di:%lx, r8:%lx,r9:%lx,r12:%lx,r13:%lx,r14:%lx\n",ip,parent_ip,op,regs,regs->regs.dx,regs->regs.ax,regs->regs.bx,regs->regs.cx,regs->regs.si,regs->regs.di,regs->regs.r8,regs->regs.r9,regs->regs.r12,regs->regs.r13,regs->regs.r14);

    ftrace_test_recursion_unlock(bit);
}

//配置ftrace_ops
static struct ftrace_ops ops = {
      .func                    = callback_func, //这里设置回调函数
      .flags                   = FTRACE_OPS_FL_SAVE_REGS //具体flag的定义详见上面那篇文章，如果需要读取修改寄存器需要添加该flag
    //   .private                 = any_private_data_structure,
};

//在模块初始化中设置hook点并启用
static int __init ftrace_direct_init(void)
{
    ftrace_set_filter(&ops, "device_read", strlen("device_read"), 0);//如果想hook其他函数，修改名字就好
    return register_ftrace_function(&ops);

}
//模块卸载时取消注册
static void __exit ftrace_direct_exit(void)
{
    unregister_ftrace_function(&ops);
}

module_init(ftrace_direct_init);
module_exit(ftrace_direct_exit);

MODULE_AUTHOR("Steven Rostedt");
MODULE_DESCRIPTION("Example use case of using register_ftrace_direct()");
MODULE_LICENSE("GPL");
```

## 实验结果

首先将两个模块编译并加载到内核后。使用`cat /proc/kallsyms | grep device_read`查询内核符号表，可以看到被hook函数出现在表中(lkm即为被hook的函数所在模块)。

![image-20221025113448249](https://lunqituchuang.oss-cn-hangzhou.aliyuncs.com/image-20221025113448249.png)

使用cat之后开启一个终端使用`sudo cat /sys/kernel/tracing/trace_pipe`来读取回调函数打印的结果。

开启另一个终端执行`cat /dev/lkm_example` 来触发被hook的函数。

查看trace_pipe中的结果如下：

![修改regs结果](https://lunqituchuang.oss-cn-hangzhou.aliyuncs.com/修改regs结果.png)

在终端中使用`sudo dmesg`查看`device_read`中`printk`打印的结果，来验证被hook函数中的参数是否真正被修改了

![image-20221025114118583](https://lunqituchuang.oss-cn-hangzhou.aliyuncs.com/image-20221025114118583.png)

可以看到dx中保存的第三个参数`len`确实被修改了，证明了实验猜想正确

## 附录

代码仓库地址:[https://github.com/balisong77/ftrace_demo](https://github.com/balisong77/ftrace_demo)

参考教程和ftrace编程样例：

[https://nixhacker.com/hooking-syscalls-in-linux-using-ftrace/](https://nixhacker.com/hooking-syscalls-in-linux-using-ftrace/)

[使用ftrace修改ip出现的问题](https://stackoverflow.com/questions/42966520/restoring-task-pt-regs-when-returning-to-original-function-from-ftrace-handler)修改ip需要`FTRACE_OPS_FL_IPMODIFY`flag被设置

[ftrace源码原理小探](https://richardweiyang-2.gitbook.io/kernel-exploring/00-index-3/04-ftrace_internal)

内核模块Makefile模板

```makefile
obj-m = hook_by_name.o
KERNEL_VER = $(shell uname -r)
all:
	make -C /lib/modules/$(KERNEL_VER)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KERNEL_VER)/build M=$(PWD) clean
```

lkm模块完整代码

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Robert W. Oliver II");
MODULE_DESCRIPTION("A simple example Linux module.");
MODULE_VERSION("0.01");

#define DEVICE_NAME "lkm_example"
#define EXAMPLE_MSG "Hello, World!\n"
#define MSG_BUFFER_LEN 15

/* Prototypes for device functions */
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);
               
static int major_num;
static int device_open_count = 0;
static char msg_buffer[MSG_BUFFER_LEN];
static char *msg_ptr;
               
/* This structure points to all of the device functions */
static struct file_operations file_ops = {
 .read = device_read,
 .write = device_write,
 .open = device_open,
 .release = device_release
};
               
/* When a process reads from our device, this gets called. */
static ssize_t device_read(struct file *flip, char *buffer, size_t len, loff_t *offset) {
 int bytes_read = 0;
  /* If we’re at the end, loop back to the beginning */
  if (*msg_ptr == 0) {
   msg_ptr = msg_buffer;
  }
  /* Put data in the buffer */
  while (len && *msg_ptr) {
    /* Buffer is in user data, not kernel, so you can’t just reference
     * with a pointer. The function put_user handles this for us */
    printk("lkm:flip: %lx, buffer: %lx, len: %lx, offset: %lx",flip,buffer,len,offset);
    put_user(*(msg_ptr++), buffer++);
    len--;
    bytes_read++;
 }
  return bytes_read;
}

/* Called when a process tries to write to our device */
static ssize_t device_write(struct file *flip, const char *buffer, size_t len, loff_t *offset) {
 /* This is a read-only device */
  printk(KERN_ALERT "This operation is not supported.\n");
  return -EINVAL;
}
         
/* Called when a process opens our device */
static int device_open(struct inode *inode, struct file *file) {
  /* If device is open, return busy */
  if (device_open_count) {
   return -EBUSY;
  }
  device_open_count++;
  try_module_get(THIS_MODULE);
  return 0;
}
         
/* Called when a process closes our device */
static int device_release(struct inode *inode, struct file *file) {
  /* Decrement the open counter and usage count. Without this, the module would not unload. */
  device_open_count--;
  module_put(THIS_MODULE);
  return 0;
}
         
static int __init lkm_example_init(void) {
  /* Fill buffer with our message */
  strncpy(msg_buffer, EXAMPLE_MSG, MSG_BUFFER_LEN);
  /* Set the msg_ptr to the buffer */
  msg_ptr = msg_buffer;
  /* Try to register character device */
  major_num = register_chrdev(0, "lkm_example", &file_ops);
  if (major_num < 0) {
   printk(KERN_ALERT "Could not register device: %d\n", major_num);
   return major_num;
  } else {
   printk(KERN_INFO "lkm_example module loaded with device major number %d\n", major_num);
   return 0;
  }
}

static void __exit lkm_example_exit(void) {
  /* Remember — we have to clean up after ourselves. Unregister the character device. */
  unregister_chrdev(major_num, DEVICE_NAME);
  printk(KERN_INFO "Goodbye, World!\n");
}

/* Register module functions */
module_init(lkm_example_init);
module_exit(lkm_example_exit);
```

