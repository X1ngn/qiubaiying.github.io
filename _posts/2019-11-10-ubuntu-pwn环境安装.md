---
layout:     post
title:      Ubuntu16.04下pwn环境安装
subtitle:   环境安装
date:       2019-11-10
author:     X1ng
header-img: pwn环境.jpg
catalog: true
tags:

    - 环境安装

---

## ubuntu换源
###  1.备份原来的源

```bash
sudo cp /etc/apt/sources.list /etc/apt/sources_init.list
```
###  2.更换源

```bash
sudo gedit /etc/apt/sources.list
```
使用gedit打开一个文档（就是存放源的地址的文档）
将里面的东西全部删去，输入新的源，这里推荐使用清华源（还有很多国内的源，也可以自行百度使用其他源）
![清空sources文件](https://img-blog.csdnimg.cn/20191110202055509.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dqeF8xMTAyMTE=,size_16,color_FFFFFF,t_70)

### 3.使用清华源

进入下面的网站，选择对于Ubuntu版本系统，复制里面的内容到上面打开的gedit文档中
[清华源](https://mirrors.tuna.tsinghua.edu.cn/help/ubuntu/?spm=a2c4e.10696291.0.0.502319a4Niy7Ii)
![清华源](https://img-blog.csdnimg.cn/20191110202421265.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dqeF8xMTAyMTE=,size_16,color_FFFFFF,t_70)
![换源](https://img-blog.csdnimg.cn/20191110202517812.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dqeF8xMTAyMTE=,size_16,color_FFFFFF,t_70)
这里点击save会报警告![在这里插入图片描述](https://img-blog.csdnimg.cn/20191110203155884.png)
但是没关系，已经保存进去了，可以再次输入上面的命令打开源文件确认

### 4.更新源

```bash
sudo apt-get update
```
（这里还可以顺便更新一下软件）

```bash
 sudo apt-get upgrade
```

## 安装pwntools
安装pwntools要先安装python、pip

### 1.先安装两个库

```bash
sudo apt-get install libffi-dev
```

```bash
sudo apt-get install libssl-dev
```
### 2.安装python、pip

```bash
sudo apt-get install python
```

```bash
sudo apt-get install python-pip
```
### 3安装pwntools

（这里可以给pip换一下源，-i + （pip源）临时使用其他源）

```bash
pip install pwntools -i https://pypi.tuna.tsinghua.edu.cn/simple
```

## 安装git
通过git clone自己需要的工具
```bash
apt install git
```

## 安装peda
用cd命令到自己想要保存的位置 使用git clone将peda的文件clone下来

```bash
git clone https://github.com/longld/peda.git ~/peda
```

```bash
echo "source ~/peda/peda.py" >> ~/.gdbinit
```

## 安装Ubuntu32位库
如果不安装32位库Ubuntu是不能运行32位文件的

```bash
sudo apt install libc6-dev-i386
```

```bash
sudo apt-get install lib32z1
```

# 验证
**1.验证peda是否安装成功**
在root环境下输入gdb,如下现实则成功
![在这里插入图片描述](https://img-blog.csdnimg.cn/20191110212240499.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dqeF8xMTAyMTE=,size_16,color_FFFFFF,t_70)
**2.验证pwntools是否安装成功**
输入python进入python环境

```python
import pwn
pwn.asm("xor eax,eax")
```
如下显示则成功
![在这里插入图片描述](https://img-blog.csdnimg.cn/20191110211753697.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dqeF8xMTAyMTE=,size_16,color_FFFFFF,t_70)