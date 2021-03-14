---
layout:     post
title:      kernel pwn入门之路（一）
subtitle:   基础知识
date:       2020-12-22
author:     X1ng
header-img: kernel.jpg
catalog: true
tags:
    - kernel pwn
    - 学习笔记

---

只会做几个烂大街的堆题目，，比赛堆题签个到走人

这好吗？这不好，，所以赶紧学学Linux kernel module pwn，记个笔记

## 环境搭建

根据[钞sir师傅的博客](https://blog.csdn.net/qq_40827990/article/details/97036109)搭建环境



## 基础知识

### kernel的作用：

kernel也是一个程序，用来管理软件发出的数据 I/O 要求，将这些要求转义为指令，交给 CPU 和计算机中的其他组件处理

1. 控制并与硬件进行交互
2. 提供 application 能运行的环境

（kernel 的 crash 通常会引起重启）

intel CPU 将 CPU 的特权级别分为 4 个级别：Ring 0、Ring 1、Ring 2、Ring 3

但是其实一般来说只用Ring 0和Ring 3就可以区分（即内核态与用户态），Ring 0只能被操作系统使用，可以使用外层资源、可以修改用户权限，Ring 3则所有程序都可以使用

- 程序进入内核态之前要先保存用户态的寄存器

- 从内核态返回的时候
    1. 在栈上布置好寄存器的值并恢复
    2. 64位下才需要执行`swapgs`，用于置换`GS`寄存器和`KernelGSbase MSR`寄存器的内容
    3. 执行`sysretq`和 `iret` 指令返回用户态（使用`iretq`指令还需要给出CS、eflags/rflags、esp/rsp等一些用户空间的信息）

>可以通过以下函数来获取并保存用户态寄存器信息
>
>```c
>unsigned long user_cs, user_ss, user_eflags, user_sp;
>void save_stats(){
>	asm(
>    "movq %%cs,%0\n"
>    "movq %%ss,%1\n"
>    "movq %%rsp,%3\n"
>    "pushfq\n"
>    "popq %2\n"
>    :"=r"(user_cs), "=r"(user_ss), "=r"(user_eflags), "=r"(user_sp)
>    :
>    :"memory"
>  );
>}
>```
>
>之后恢复的时候可以直接用这些值恢复寄存器

在比赛中，通常漏洞会存在于动态装载模块中（比如驱动程序、内核扩展模块）

### 对模块的基本操作

```
命令
insmod:加载模块
lsmod:查看模块
rmmod:删除模块

函数
open:打开模块
ioctl:操作模块
read:读模块
write:写模块
close:关闭模块
```

### 内核态函数

- printf() -> printk()，但需要注意的是 printk() 不一定会把内容显示到终端上，但一定在内核缓冲区里，可以通过 `dmesg` 查看效果

- memcpy() ->copy_from_user()/copy_to_user()

    - `copy_from_user(char *a1, char *a2, int a3); `实现了将用户空间a2的长度为a3的数据传送到内核空间a1
    - `copy_to_user(char *a1, char *a2, int a3) ;`实现了将内核空间a2的长度为a3的数据传送到用户空间a1

- malloc() -> kmalloc()，内核态的内存分配函数，和 malloc() 相似，但使用的是 `slab/slub 分配器`

- free() -> kfree()，同 kmalloc()

- misc_register()用于注册一个驱动，其参数为`miscdevice`结构体指针

    miscdevice结构体定义为：

    ![img](https://tva1.sinaimg.cn/large/0081Kckwly1glvyapez50j30gm06v0sz.jpg)

    内核在加载驱动的时候，会调用驱动程序中的`module_init()`函数，`module_init()`函数再调用相应的注册函数来向内核注册驱动（比如`misc_register()`函数）

### 设备类型

linux系统将设备分为三类：字符设备、块设备、网络设备

>字符设备：是指只能一个字节一个字节读写的设备，不能随机读取设备内存中的某一数据，读取数据需要按照先后数据。字符设备是面向流的设备，常见的字符设备有鼠标、键盘、串口、控制台和LED设备等。
>
>块设备：是指可以从设备的任意位置读取一定长度数据的设备。块设备包括硬盘、磁盘、U盘和SD卡等。

### 设备的打开过程

由于ucore文件系统实验摸鱼了，先学学文件系统相关知识

#### 注册设备驱动

如上文所说的，在使用`insmod`加载驱动的时候，内核调用`module_init()`函数，`module_init()`函数再调用`misc_register()`来向内核注册驱动

由于`miscdevice`结构体是`misc_register()`函数的参数，所以在调用`misc_register()`函数时通过`miscdevice`结构体的成员`fops`指针将`file_operations`结构体连同其主设备号一起传入内核

file_operations结构体定义为：

![](https://tva1.sinaimg.cn/large/0081Kckwly1glwm6vhgqdj316i0u0h0p.jpg)

其成员除了`owner`指向的`module`结构体之外，剩下的都是函数指针，可以通过修改其中的函数指针来达到重写某个函数的目的，如果对这个驱动调用某个其中的函数，就会调用结构体中的函数指针

举个栗子

在某个内核模块代码中

```c
struct file_operations shf_fops = {
.owner = THIS_MODULE,
.open = shf_open,
.release = shf_release,
.unlocked_ioctl = shf_unlocked_ioctrl,
}
struct miscdevice shf_device = {
.minor = MISC_DYNAMIC_MINOR,
.name = "shf",
.fops = &shf_fops,
};
misc_regiseter(&shf_device); 
```

从对`file_operations`结构体的修改可以看出这里重写了`open`函数`release`函数和`unlocked_ioctl`函数

`misc_regiseter`函数会在/dev下创建shf节点，即/dev/shf

在用户程序中只要`fd = open("/dev/shf",READONY);`就可以调用重写的`open`函数来启动该驱动，然后通过`ioctl`函数操作该驱动

#### 打开设备

在Linux下一切皆文件，设备也不例外

内核会为每一个运行中的进程在进程控制块pcb中维护一个打开文件的记录表，也就是文件描述符表，文件描述符fd就是这个表的索引，该表每一个表项都是 已打开文件的file结构体指针 

file结构体是内核中用来描述文件属性的结构体

![](https://tva1.sinaimg.cn/large/0081Kckwgy1gm82cgreu7j30x10u010j.jpg)

进程通过系统调用`open`系统调用来打开一个文件，会获得一个文件描述符，并为该文件创建一个file对象，并把该file对象存入进程打开文件表中（文件描述符数组），以便进程通过文件描述符为连接对文件进行其他操作

`close`系统调用则反之

>**FILE与file傻傻分不清**
>
>file结构体是linux内核中的结构体，每一个被打开的广义的文件（包括设备、套接字等），都有一个file结构体与之对应
>
>FILE结构体是libc中的结构体
>
>```c
>#ifndef _FILE_DEFINED
>struct _iobuf {
> 
>　　　　char *_ptr; //文件输入的下一个位置
>　　　　int _cnt; //当前缓冲区的相对位置
>　　　　char *_base; //指基础位置(即是文件的其始位置)
>　　　　int _flag; //文件标志
>　　　　int _file; //文件描述符
>　　　　int _charbuf; //检查缓冲区状况,如果无缓冲区则不读取
>　　　　int _bufsiz; //缓冲区大小
>　　　　char *_tmpfname; //临时文件名
> 
>        };
>typedef struct _iobuf FILE;
>#define _FILE_DEFINED
>```
>
>使用fopen,fclose,fread,fwrite返回FILE *文件指针，对狭义的文件（不包括设备、套接字等）进行操作

#### ioctl系统调用操作设备

在用户空间实用ioctl操作设备的时候，其接口为

```c
int ioctl(int fd,unsigned long cmd,...);
/*
fd:文件描述符
cmd:控制命令
...:可选参数:插入*argp，具体内容依赖于cmd
*/
```

而在进行系统调用时，根据linux内核中关于ioctl系统调用的源代码

![](https://tva1.sinaimg.cn/large/0081Kckwgy1gm9ezek99mj31as0jg414.jpg)

再经过一些检查之后，最终调用的`vfs_ioctl(f.file, cmd, arg)`，其第一个参数变为由fd找到的对应的file结构体

![](https://tva1.sinaimg.cn/large/0081Kckwgy1gm9f4vxy4cj31820d8gnk.jpg)

然后再从`file_operations`结构体中找到对应hook函数`unlocked_ioctl`的函数指针进行调用

可以看到最终调用了ko文件中的内核函数`unlocked_ioctl(filp, cmd, arg);`

对于设备`open`、`read`、`write`等系统调用的大致流程也都是如此，用户接口进入`SYSCALL_DEFINE3`宏后调用`vfs_XXXX`来调用`file_operations`结构体中的函数



### 题目文件

>1. `baby.ko` 就是有bug的程序（出题人编译的驱动），可以用`IDA`打开
>
>2. `bzImage` 是打包的内核，用于启动虚拟机与寻找`gadget`
>
>3. `Initramfs.cpio` 文件系统
>
>4. `startvm.sh` 启动脚本
>
>5. 有时还会有`vmlinux`文件，这是未打包的内核，一般含有符号信息，可以用于加载到`gdb`中方便调试（`gdb vmlinux`），当寻找`gadget`时，使用`objdump -d vmlinux > gadget`然后直接用编辑器搜索会比`ROPgadget`或`ropper`快很多。
>
>6. 没有`vmlinux`的情况下，可以使用`linux`源码目录下的`scripts/extract-vmlinux`来解压`bzImage`得到`vmlinux`（`extract-vmlinux bzImage > vmlinux`），当然此时的`vmlinux`是不包含调试信息的。
>
>7. 还有可能附件包中没有驱动程序`*.ko`，此时可能需要我们自己到文件系统中把它提取出来，这里给出`ext4`，`cpio`两种文件系统的提取方法：
>
>    - `ext4`：将文件系统挂载到已有目录。
>
>        - `mkdir ./rootfs`
>
>        - `sudo mount rootfs.img ./rootfs`
>
>        - 查看根目录的`init`或`etc/init.d/rcS`，这是系统的启动脚本
>
>            [![img](https://xzfile.aliyuncs.com/media/upload/picture/20200417101600-61c4e41e-8051-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20200417101600-61c4e41e-8051-1.png)
>
>            可以看到加载驱动的路径，这时可以把驱动拷出来
>
>        - 卸载文件系统，`sudo umount rootfs`
>
>    - `cpio`：解压文件系统、重打包
>
>        - `mkdir extracted; cd extracted`
>        - `cpio -i --no-absolute-filenames -F ../rootfs.cpio`
>        - 此时与其它文件系统相同，找到`rcS`文件，查看加载的驱动，拿出来
>        - `find . | cpio -o --format=newc > ../rootfs.cpio`

### 漏洞类型

![](https://tva1.sinaimg.cn/large/0081Kckwgy1glverseyswj30oe0enjtl.jpg)

>主要有以下几种保护机制：
>
>- `KPTI`：Kernel PageTable Isolation，内核页表隔离
>- `KASLR`：Kernel Address space layout randomization，内核地址空间布局随机化
>- `SMEP`：Supervisor Mode Execution Prevention，管理模式执行保护
>- `SMAP`：Supervisor Mode Access Prevention，管理模式访问保护
>- `Stack Protector`：Stack Protector又名canary，stack cookie
>- `kptr_restrict`：允许查看内核函数地址
>- `dmesg_restrict`：允许查看`printk`函数输出，用`dmesg`命令来查看
>- `MMAP_MIN_ADDR`：不允许申请`NULL`地址 `mmap(0,....)`

1. 可以通过`cat /proc/cpuinfo`来查看开启了哪些保护

    ![](https://tva1.sinaimg.cn/large/0081Kckwly1glvf27beg6j30m60c1abb.jpg)

2. `KASLR`和`Stack Protector`类似于用户态下的`ASLR`和`Canary`

3. 开启`SMEP`，内核态运行时，不允许执行用户态代码，开启`SMAP`，内核态不允许访问用户态数据；可通过修改`cr4`寄存器的值来绕过`SMEP`，`SMAP`保护

4. 调试时，`KASLR`、`SMEP`、`SMAP`可通过修改`startvm.sh`来关闭；

    ![](https://tva1.sinaimg.cn/large/0081Kckwgy1glveuriyuoj30nr09xt9m.jpg)

    `dmesg_restrict`、`dmesg_restrict`可在`rcS`文件中修改；

    ![](https://tva1.sinaimg.cn/large/0081Kckwgy1glvev351g0j30cb0b0gm1.jpg)

    `MMAP_MIN_ADDR`是`linux`源码中定义的宏，可重新编译内核进行修改（`.config`文件中），默认为4k

    ![](https://tva1.sinaimg.cn/large/0081Kckwgy1glvev8g751j30b502gglq.jpg)

5. **一般需要调用`commit_creds(prepare_kernel_cred(0));`来进行提权**

    进程都有一个cred结构体

    ```c
    struct cred {
    	atomic_t usage;
      uid_t uid;
      gid_t gid;
      struct rcu_head exterminate;
      struct group_info *group_info;
    }
    ```

    用于标记权限，调用`commit_creds(prepare_kernel_cred(0));`函数可以重新分配一个uid和gid都为0的cred结构体，此时再打开新进程（比如/bin/sh）就是root权限了



## gdb调试的栗子

- Shell1:

    1. 解压文件系统

        ```shell
        mkdir extracted; cd extracted
        cpio -i --no-absolute-filenames -F ../rootfs.cpio
        ```

        找到文件系统中的`rcS`文件/`init`文件，从`setsid`这一行修改权限为0，然后将文件系统打包

        ```shell
        find . | cpio -o --format=newc > ../rootfs.cpio
        ```

    2. start.sh加上`-gdb tcp::1234`或者`-s`，并关闭`kaslr`

        ```shell
        qemu-system-x86_64 \
        -m 256M -smp 2,cores=2,threads=1  \
        -kernel ./vmlinuz-4.15.0-22-generic \
        -initrd  ./rootfs.img \
        -append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet" \
        -cpu qemu64 -netdev user,id=t0, \
        -device e1000,netdev=t0,id=nic0 \
        -nographic \
        -gdb tcp::1234 ##加上 -gdb
        ```

        启动内核后查看驱动的基地址

        ```
        / # lsmod
        baby 16384 0 - Live 0xffffffffc031d000 (POE)
        ```

        查找两个提权用的内核函数地址

        ```shell
        cat /proc/kallsyms | grep "prepare_kernel_cred" #得到prepare_kernel_cred函数地址
        cat /proc/kallsyms | grep "commit_creds"	#得到commit_creds函数地址
        ```

- Shell2:

    1. 在当前目录下配置.gdbinit文件，设置

        ```shell
        vim .gdbinit
        ```

        在里面写上

        ```shell
        set architecture i386:x86-64
        ```

        打开gdb

        ```shell
        gdb ./baby.ko
        add-symbol-file ./baby.ko 0xffffffffc031d000 #附加驱动，让gdb对命令的反应速度快点
        target remote :1234
        ```


之后就可以进行调试了

写好exp后编译为静态二进制文件运行进行提权

```shell
gcc exp.c -o exp -static
gcc exp.c -o exp -masm=intel -static	#intel格式内联汇编
```

> 关于驱动在内核态的调试方法应该是安装驱动，对相应函数下断,运行poc,然后才可以断下来调试,和我们在用户态直接调试程序其实就是多了一个运行poc,其他方法都差不多的…





> 参考资料：
>
> [Linux kernel Exploit 内核漏洞学习(0)-环境安装](https://cc-sir.github.io/2019/07/24/Linux-kernel-0/)
>
> [ctf-wiki](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/kernel/basic_knowledge-zh/)
>
> [snowdrop的技术博客](https://www.cnblogs.com/snowdrop/articles/8678389.html)
>
> [linux字符设备驱动中内核如何调用驱动入口函数 一点记录](https://my.oschina.net/u/4418654/blog/3257483)


