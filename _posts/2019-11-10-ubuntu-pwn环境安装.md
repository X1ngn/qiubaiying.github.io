---
layout:     post
title:      Ubuntu pwn环境安装
subtitle:   在ubuntu 20.04的python3下安装pwn环境
date:       2019-11-10
author:     X1ng
header-img: pwn环境.jpg
catalog: true
tags:

    - 环境安装

---

最后修改于2021年11月27日，有些方法可能已失效

### ubuntu换源

####  1.备份原来的源

```bash
sudo cp /etc/apt/sources.list /etc/apt/sources_init.list
```
####  2.更换源

```bash
sudo gedit /etc/apt/sources.list
```
使用gedit打开一个文档（就是存放源的地址的文档）
将里面的东西全部删去，输入新的源，这里推荐使用清华源（还有很多国内的源，也可以自行百度使用其他源）
![清空sources文件](https://img-blog.csdnimg.cn/20191110202055509.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dqeF8xMTAyMTE=,size_16,color_FFFFFF,t_70)

#### 3.使用中科大源

进入下面的网站，选择对于Ubuntu版本系统，复制里面的内容到上面打开的gedit文档中

```
# 默认注释了源码仓库，如有需要可自行取消注释
deb https://mirrors.ustc.edu.cn/ubuntu/ focal main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu/ focal main restricted universe multiverse

deb https://mirrors.ustc.edu.cn/ubuntu/ focal-security main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu/ focal-security main restricted universe multiverse

deb https://mirrors.ustc.edu.cn/ubuntu/ focal-updates main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu/ focal-updates main restricted universe multiverse

deb https://mirrors.ustc.edu.cn/ubuntu/ focal-backports main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu/ focal-backports main restricted universe multiverse

# 预发布软件源，不建议启用
# deb https://mirrors.ustc.edu.cn/ubuntu/ focal-proposed main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu/ focal-proposed main restricted universe multiverse
```

可以到[Ubuntu 源使用帮助 — USTC Mirror Help 文档](https://mirrors.ustc.edu.cn/help/ubuntu.html)查看最新的源信息
![换源](https://img-blog.csdnimg.cn/20191110202517812.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dqeF8xMTAyMTE=,size_16,color_FFFFFF,t_70)

（图文不一致系列2333）

这里点击save会报警告![在这里插入图片描述](https://img-blog.csdnimg.cn/20191110203155884.png)
但是没关系，已经保存进去了，可以再次输入上面的命令打开源文件确认

#### 4.更新源

```bash
sudo apt-get update
```
更新一下软件

```bash
 sudo apt-get upgrade
```

### 安装pwntools
安装pwntools要先安装python、pip

#### 1.先安装两个库

```bash
sudo apt-get install libffi-dev
sudo apt-get install libssl-dev
```

#### 2.安装python、pip

```bash
sudo apt-get install python
```

```bash
sudo apt-get install python3-pip
```
#### 3安装pwntools

（这里可以给pip换一下源，-i + {pip源} 临时使用其他源）

```bash
pip install pwntools 
```

### 安装git
通过git clone自己需要的工具
```bash
sudo apt install git
```

### 安装pwndbg
用cd命令到自己想要保存的位置 使用git clone命令

```bash
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
cd ..
```

### 安装LibcSeacher

原来基于本地数据库的项目已经停止维护，有大佬基于 [libc-database](https://github.com/niklasb/libc-database) 云端数据库开了新的项目

```shell
pip3 install LibcSearcher
```

### 安装Ubuntu32位库

```bash
sudo apt install libc6-dev-i386
sudo apt-get install lib32z1
```

### 安装one_gadget

```shell
sudo apt-get install ruby ruby-dev
sudo gem install one_gadget
```

### 安装ROPgadget

```shell
sudo apt-get install python-capstone
git clone https://github.com/JonathanSalwan/ROPgadget.git
cd ROPgadget
sudo python3 setup.py install
cp -r ./scripts /home/tee/.local/lib/python3.8/site-packages/ROPGadget-6.6.dist-info
cd ..
```

### 安装patchelf

```shell
sudo apt-get install autoconf automake libtool

git clone https://github.com/NixOS/patchelf.git
cd patchelf
./bootstrap.sh
./configure
make
make check
sudo make install
cd ..
```



---

kali下需要安装python3的工具

安装ROPgadget时报错

![](https://tva1.sinaimg.cn/large/0081Kckwly1gkb19kaarej30x004ot97.jpg)

用git安装，之后再继续安装ROPgadget

```shell
git clone https://github.com/aquynh/capstone
cd capstone
make
make install
```





