---
layout:     post
title:      Ubuntu下pwn环境安装
subtitle:   环境安装
date:       2019-11-10
author:     X1ng
header-img: pwn环境.jpg
catalog: true
tags:

    - 环境安装

---

## Ubuntu16.04/Ubuntu18.04

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

#### 3.使用清华源

进入下面的网站，选择对于Ubuntu版本系统，复制里面的内容到上面打开的gedit文档中
[清华源](https://mirrors.tuna.tsinghua.edu.cn/help/ubuntu/?spm=a2c4e.10696291.0.0.502319a4Niy7Ii)
![清华源](https://img-blog.csdnimg.cn/20191110202421265.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dqeF8xMTAyMTE=,size_16,color_FFFFFF,t_70)
![换源](https://img-blog.csdnimg.cn/20191110202517812.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dqeF8xMTAyMTE=,size_16,color_FFFFFF,t_70)
这里点击save会报警告![在这里插入图片描述](https://img-blog.csdnimg.cn/20191110203155884.png)
但是没关系，已经保存进去了，可以再次输入上面的命令打开源文件确认

#### 4.更新源

```bash
sudo apt-get update
```
（这里还可以顺便更新一下软件）

```bash
 sudo apt-get upgrade
```

### 安装pwntools
安装pwntools要先安装python、pip

#### 1.先安装两个库

```bash
sudo apt-get install libffi-dev
```

```bash
sudo apt-get install libssl-dev
```
#### 2.安装python、pip

```bash
sudo apt-get install python
```

```bash
sudo apt-get install python-pip
```
#### 3安装pwntools

（这里可以给pip换一下源，-i + （pip源）临时使用其他源）

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
```

### 安装LibcSeacher

用cd命令到自己想要保存的位置 使用git clone命令

```
git clone https://github.com/lieanu/LibcSearcher.git
cd LibcSearcher
python setup.py develop
```

### 安装Ubuntu32位库

如果不安装32位库Ubuntu是不能运行32位文件的

```bash
sudo apt install libc6-dev-i386
```

```bash
sudo apt-get install lib32z1
```

### 安装one_gadget

```
sudo apt-get install ruby ruby-dev
sudo gem install one_gadget
```

### 安装ROPgadget

```
sudo apt-get install python-capstone
git clone https://github.com/JonathanSalwan/ROPgadget.git
cd ROPgadget
sudo python setup.py install
```


***

## Ubuntu20.04环境

与16、18环境差不多，只是使用pip安装pwntools时报错

换源后

```shell
git clone https://github.com/Gallopsled/pwntools
cd pwntools
apt --fix-broken install
apt-get install python-dev
python setup.py install
```

pwntools安装完毕，接着继续按上文路线安装



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

