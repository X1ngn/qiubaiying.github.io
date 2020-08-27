---
layout:     post
title:      (转)解决升级pwntools-gdb.attach不能弹起gdb
subtitle:   pwntools中gdb模块问题
date:       2020-08-19
author:     
header-img: gdb_attach.jpg
catalog: true
tags:

    - 转载
    - 解决方案


---

## （转）解决升级pwntools gdb.attach不能弹起gdb

原文https://www.dazhuanlan.com/2019/10/21/5dad66695dc53/

<--more-->

### 问题

![img](https://blog-1252049492.cos.ap-hongkong.myqcloud.com/img/fix-gdb-01.jpg)

发现 `gdb.attach`弹不出gdb窗口了…

后来发现问题出在ubuntu身上，

Ubuntu引入了一个补丁来禁止非root用户对非子进程的追踪 - 即。只有作为另一个进程的父进程的进程可以为普通用户追踪它，而root仍然可以追踪每个进程。所以为什么你可以使用gdb来通过sudo来附加。

所以我们需要使用root权限，来运行我们的`gdb.attach`

### 解决

但是，我们不也非得用`sudo`

### 临时解决方案

```
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

### 长久解决方案

修改 `/etc/sysctl.d/10-ptrace.conf`

 修改内容 `kernel.yama.ptrace_scope = 1`

 结果为 `kernel.yama.ptrace_scope = 0`



---

愚蠢地以为环境问题重装了好多次系统，，原来是ubuntu权限的问题

ubuntu18.04环境下用pwntools报错

```
[-] Waiting for debugger: debugger exited! (maybe check /proc/sys/kernel/yama/ptrace_scope)
```

用sudo启动python脚本即可，以上方法还是无效

```
sudo python exp.py
```

