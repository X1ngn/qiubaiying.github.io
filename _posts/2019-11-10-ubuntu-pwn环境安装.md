---
layout:     post
title:      Ubuntu pwn环境安装
subtitle:   在ubuntu 22.04的python3下安装pwn环境
date:       2019-11-10
author:     X1ng
header-img: pwn环境.jpg
catalog: true
tags:

    - 环境安装

---

最后修改于2023年6月9日，有些方法可能已失效

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
将里面的东西全部删去，输入新的源，这里使用中科大源（还有很多国内的源，也可以自行百度使用其他源）
![清空sources文件](https://img-blog.csdnimg.cn/20191110202055509.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dqeF8xMTAyMTE=,size_16,color_FFFFFF,t_70)

#### 3.使用中科大源

进入下面的网站，选择对于Ubuntu版本系统，复制里面的内容到上面打开的gedit文档中

```
# 默认注释了源码仓库，如有需要可自行取消注释
deb https://mirrors.ustc.edu.cn/ubuntu/ jammy main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu/ jammy main restricted universe multiverse

deb https://mirrors.ustc.edu.cn/ubuntu/ jammy-security main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu/ jammy-security main restricted universe multiverse

deb https://mirrors.ustc.edu.cn/ubuntu/ jammy-updates main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu/ jammy-updates main restricted universe multiverse

deb https://mirrors.ustc.edu.cn/ubuntu/ jammy-backports main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu/ jammy-backports main restricted universe multiverse

# 预发布软件源，不建议启用
# deb https://mirrors.ustc.edu.cn/ubuntu/ jammy-proposed main restricted universe multiverse
# deb-src https://mirrors.ustc.edu.cn/ubuntu/ jammy-proposed main restricted universe multiverse
```

可以到[Ubuntu 源使用帮助 — USTC Mirror Help 文档](https://mirrors.ustc.edu.cn/help/ubuntu.html)查看最新的源信息
![换源](https://img-blog.csdnimg.cn/20191110202517812.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dqeF8xMTAyMTE=,size_16,color_FFFFFF,t_70)

（图文不一致系列2333）

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
sudo apt-get install python3
sudo apt-get install python3-pip
```

设置软链接到python

```
x1ng@ubuntu:~/tools$ which python3
/usr/bin/python3
x1ng@ubuntu:~/tools$ sudo ln -s /usr/bin/python3 /usr/bin/python
```

#### 3.安装pwntools

（这里可以给pip换一下源，-i + {pip源} 临时使用其他源）

```bash
pip3 install pwntools -i https://pypi.mirrors.ustc.edu.cn/simple/ 
```

### 安装git
```bash
sudo apt install git
```



### 配置代理

给linux配代理，以宿主机Windows上使用clash翻墙为例

clash默认的混合端口是7890，先将clash主页界面的“允许局域网”打开

此时虚拟机为NAT网络模式，其与宿主机的IP地址分别为

![20230610020103](https://raw.githubusercontent.com/X1ngn/ctf/master/uPic/2023 06 10 02 01 03 .png)

打开ubuntu设置页面，选择`Network->VPN->Network Proxy`中的Manual，并填入IP和端口

![20230610021637](https://raw.githubusercontent.com/X1ngn/ctf/master/uPic/2023 06 10 02 16 37 .png)

在虚拟机浏览器中访问谷歌成功



### 安装pwndbg

创建tools目录存放工具文件，使用git clone命令下载工具

```bash
mkdir tools && cd tools
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
git clone https://github.com/aquynh/capstone
cd capstone
make
sudo make install

cd ..

git clone https://github.com/JonathanSalwan/ROPgadget.git
cd ROPgadget
sudo -H python3 setup.py install

cd ..
```

> 报错某个目录下缺少某个文件
>
> ```
> x1ng@ubuntu:~/tools/ROPgadget$ ROPgadget --help
> Traceback (most recent call last):
>   File "/usr/local/bin/ROPgadget", line 4, in <module>
>     __import__('pkg_resources').run_script('ROPGadget==7.3', 'ROPgadget')
>   File "/usr/lib/python3/dist-packages/pkg_resources/__init__.py", line 656, in run_script
>     self.require(requires)[0].run_script(script_name, ns)
>   File "/usr/lib/python3/dist-packages/pkg_resources/__init__.py", line 1441, in run_script
>     raise ResolutionError(
> pkg_resources.ResolutionError: Script 'scripts/ROPgadget' not found in metadata at '/home/x1ng/.local/lib/python3.10/site-packages/ROPGadget-7.3.dist-info'
> ```
>
> 按照上面的地址直接复制过去
>
> ```bash
> sudo cp -r scripts /home/x1ng/.local/lib/python3.10/site-packages/ROPGadget-7.3.dist-info
> ```
>
> 



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



### 安装glibc-all-in-one

```shell
git clone https://github.com/matrix1001/glibc-all-in-one.git
cd glibc-all-in-one/
./update_list
```

用python实现批量下载，常备各种版本的glibc

```bash
gedit download_all.py
```

输入

```python
import os

f = open('./list')
s = f.readline()
while s:
	os.system('./download '+s)
	s = f.readline()
	
f = open('./old_list')
s = f.readline()
while s:
	os.system('./download_old '+s)
	s = f.readline()
```

运行python脚本

```bash
python download_all.py
```



### 安装seccomp-tools

可以检测沙箱

```shell
sudo apt install gcc ruby-dev
sudo gem install seccomp-tools
```



### 安装docker

```shell
sudo apt install curl
curl -fsSL https://test.docker.com -o test-docker.sh
sudo sh test-docker.sh
```

设置非root用户可直接使用docker

```bash
sudo groupadd docker
sudo gpasswd -a ${USER} docker
sudo systemctl restart docker
sudo chmod a+rw /var/run/docker.sock
```



### 安装qemu

先安装一些依赖

```shell
sudo apt install ninja-build libpixman-1-dev flex bison
```

按照官网的教程

```shell
git clone https://gitlab.com/qemu-project/qemu.git
cd qemu
git submodule init
git submodule update --recursive
./configure
make
make install
cd ..
```





> ### 解决ubuntu22.04的vm-tools无法拖拽移动文件问题
>
> 1. 使用vs code辅助（推荐）
>
>     先在虚拟机开启ssh服务
>
>     ```shell
>     sudo apt install openssh-server
>     ```
>
>     生成公私钥
>
>     ```shell
>     ssh-keygen
>     cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
>     ```
>
>     之后一直回车保持默认设置即可，生成的私钥公钥分别保存在用户目录的`.ssh`目录下，其中公钥被用于服务器端身份验证，追加到authorized_keys文件中
>
>     ```
>     /home/x1ng/.ssh/id_rsa 
>     /home/x1ng/.ssh/id_rsa.pub
>     ```
>
>     然后设置ssh只允许私钥登录，打开ssh配置文件
>
>     ```shell
>     sudo gedit /etc/ssh/sshd_config
>     ```
>
>     将`PubkeyAuthentication`设置为yes、`PasswordAuthentication`设置为no，保存后重启ssh服务
>
>     ```
>     sudo systemctl restart sshd
>     ```
>
>     然后在宿主机Windows上下载好vs code并打开，在插件一栏搜索remote development安装
>
>     由于Windows自带了ssh的客户端，可以直接使用
>
>     在用户目录下创建文件夹`.ssh`，在目录下
>
>     - 创建文件id_rsa，并将ssh-keygen生成的私钥复制粘贴到该文件
>
>         **注意：复制过来末尾要多打回车，否则格式不正确）**
>
>     - 创建新文件config输入配置信息保存
>
>         ```
>         Host ubuntu22
>          HostName 192.168.68.130
>          User x1ng
>          Port 22
>          IdentityFile "C:\Users\origi\.ssh\id_rsa" #密钥的路径
>         ```
>
>     之后切换到vscode的Remote Explorer一栏，在上面的选项中选择REMOTE，选择目标SSH选项卡就可以连接到虚拟机了，第一次连接需要初始化，安装虚拟机类型选择即可
>
>     则直接在vscode文件目录中右键单击菜单中下载即可实现从虚拟机传递文件到宿主机，直接将文件拖拽到vscode文件目录中即可实现从宿主机传递文件到虚拟机
>
> 2. 设置可将文件拖拽到虚拟机桌面上
>
>     安装
>
>     ```shell
>     sudo apt install gnome-shell-extension-prefs
>     sudo apt install nemo
>     ```
>
>     工具栏中打开extension
>
>     ![20230405120001](https://raw.githubusercontent.com/X1ngn/ctf/master/uPic/2023 04 05 12 00 01 .png)
>
>     去掉Desktop icons NG 选项
>
>     工具栏中打开extension
>
>     ![20230405120055](https://raw.githubusercontent.com/X1ngn/ctf/master/uPic/2023 04 05 12 00 55 .png)
>
>     添加一个
>
>     ![20230405120200](https://raw.githubusercontent.com/X1ngn/ctf/master/uPic/2023 04 05 12 02 00 .png)
>
>     三栏分别输入
>
>     ```
>     Nemo Desktop
>     nemo-desktop
>     Nemo Desktop
>     ```
>
>     之后重启，可以将文件拖到桌面上
>
>     参考[Ubuntu22.04 中Drag and drop is not supported问题](https://blog.csdn.net/qq_41866334/article/details/125626778)

