---

layout:     post
title:      csapp-archlab
subtitle:   csapp-lab
date:       2020-07-31
author:     X1ng
header-img: csapp_lab5.jpg
catalog: true
tags:

- lab
- csapp





---

README看的也不是很懂，整个lab做的有点懵，总体上是跟着知乎上师傅的文章做的[[读书笔记]CSAPP：ArchLab](https://zhuanlan.zhihu.com/p/109824219)

之前没学过AT&T语法的汇编，但是有intel的基础大概看看语法差不多了

## 知识点

一、AT&T语法

1.AT&T语法中源操作数在前，目标操作数在后，与intel相反

2.AT&T语法在寄存器前要加%，在立即数前要加$

3.AT&T语法操作指令有后缀

例如：

```
b 功能不变，操作长度一字节
q 功能不变，操作长度四字节
s 功能不变，符号拓展，操作数变为有符号数
…………
```

二、了解指令处理指令的阶段

有取指(fetch)、译码(fetch)、执行(execute)、访存(memory)、写回(write back)、更新PC(PC update)几个阶段

![](https://tva1.sinaimg.cn/large/007S8ZIlly1gh9b8ef3yoj31kw0u07wh.jpg)

如对于以下汇编代码

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh9b8ww49jj31wh0u0qv5.jpg)

取0x014处的`sub %rdx,rbx`为例

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh9bby3mowj31d60u0u0y.jpg)

## archlab

解压handout后再解压sim

所有实验操作都在sim文件夹中完成

>主要包含三个实验：在A部分中，将编写一些简单的Y86-64程序，并熟悉Y86-64工具。在B部分中，对SEQ仿真器进行扩展。这两部分将为C部分（实验的核心）做好准备，在C部分中，将优化Y86-64基准程序和处理器设计。

### 实验配置

>安装Tcl/tk
>
>```c
>sudo apt install tcl tcl-dev tk tk-dev
>```
>
>修改handout里的Makefile里的tcl版本内容
>
>```c
>sed -i "s/tcl8.5/tcl8.6/g" Makefile
>sed -i "s/CFLAGS=/CFLAGS=-DUSE_INTERP_RESULT /g" Makefile
>```
>
>安装flex和bison
>
>```c
>sudo apt-get install flex bison
>```
>
>然后解压sim压缩包
>
>```c
>tar vxf sim.tar
>```
>
>然后进入sim，执行writeup上的操作
>
>```c
>cd sim
>make clean
>make
>```

### partA

要求运用Y86指令撰写并且模拟sim/misc/example.c文件中的三个函数的功能，分别写在sum.ys,rsum.ys,copy.ys中

之后编译运行

`./yas xxx.ys`

`./yis xxx.yo`

example.c

```
/* 
 * Architecture Lab: Part A 
 * 
 * High level specs for the functions that the students will rewrite
 * in Y86-64 assembly language
 */

/* $begin examples */
/* linked list element */
typedef struct ELE {
    long val;
    struct ELE *next;
} *list_ptr;

/* sum_list - Sum the elements of a linked list */
long sum_list(list_ptr ls)
{
    long val = 0;
    while (ls) {
	val += ls->val;
	ls = ls->next;
    }
    return val;
}

/* rsum_list - Recursive version of sum_list */
long rsum_list(list_ptr ls)
{
    if (!ls)
	return 0;
    else {
	long val = ls->val;
	long rest = rsum_list(ls->next);
	return val + rest;
    }
}

/* copy_block - Copy src to dest and return xor checksum of src */
long copy_block(long *src, long *dest, long len)
{
    long result = 0;
    while (len > 0) {
	long val = *src++;
	*dest++ = val;
	result ^= val;
	len--;
    }
    return result;
}
/* $end examples */
```

参考Y86-64指令集

sum.ys

```

    .pos 0	#设置当前位置为0
    irmovq stack,%rsp	#设置栈指针
    call main
    halt

    .align 8
ele1:
    .quad 0x00a
    .quad ele2
ele2:
    .quad 0x0b0
    .quad ele3
ele3:
    .quad 0xc00
    .quad 0

main:
    irmovq ele1,%rdi
    call sum_list
    ret

sum_list:
    pushq %rbx
    xorq %rax,%rax
    andq %rdi,%rdi
    je end
op:
    mrmovq (%rdi),%rbx
    addq %rbx,%rax
    mrmovq 8(%rdi),%rdi
    andq %rdi,%rdi
    jne op
end:
    popq %rbx
    ret
    
    .pos 0x200 #设置栈地址
    stack:
```

运行结果：

![](https://tva1.sinaimg.cn/large/007S8ZIlly1gh9ar3j3naj314k09q0vf.jpg)

rsum.ys

```

    .pos 0	#设置当前位置为0
    irmovq stack,%rsp	#设置栈指针
    call main
    halt

    .align 8
ele1:
    .quad 0x00a
    .quad ele2
ele2:
    .quad 0x0b0
    .quad ele3
ele3:
    .quad 0xc00
    .quad 0

main:
    irmovq ele1,%rdi
    call rsum_list
    ret

rsum_list:
    pushq %rbx
    xorq %rax,%rax
    andq %rdi,%rdi
    je end
op:
    mrmovq (%rdi),%rbx
    mrmovq 8(%rdi),%rdi
    call rsum_list
    addq %rbx,%rax
end:
    popq %rbx
    ret
    
    .pos 0x200 #设置栈地址
    stack:
```

运行结果：

![](https://tva1.sinaimg.cn/large/007S8ZIlly1gh9ar9xh5hj313k0fedji.jpg)

copy.ys

```

    .pos 0	#设置当前位置为0
    irmovq stack,%rsp	#设置栈指针
    call main
    halt

    .align 8
src:
    .quad 0x00a
    .quad 0x0b0
    .quad 0xc00
dest:
    .quad 0x111
    .quad 0x222
    .quad 0x333


main:
    irmovq src,%rdi
    irmovq dest,%rsi
    irmovq $3,%rdx
    
    call copy_block
    ret

copy_block:
    pushq %rbx
    pushq %r13
    pushq %r14
    xorq %rax,%rax
    jmp test
op:
    irmovq $1,%r13	#Y86-64指令集中不包含立即数和寄存器之间的运算指令
    irmovq $8,%r14	#需要先通过irmovq将立即数保存到寄存器中，再用该寄存器进行计算
    mrmovq (%rdi),%rbx
    addq %r14,%rdi
    rmmovq %rbx,(%rsi)
    addq %r14,%rsi
    xorq %rbx,%rax
    subq %r13,%rdx
test:
    andq %rdx,%rdx
    jne op
    popq %r14
    popq %r13
    popq %rbx
    ret
    
    .pos 0x200 #设置栈地址
    stack:
```

运行结果：

![](https://tva1.sinaimg.cn/large/007S8ZIlly1gh9arhadl0j31180e6tc9.jpg)

### partB

该部分要在sim/seq/seq-full.hcl中添加语句，想要我们对SEQ处理器进行扩展，使其支持`iaddq`指令

iaddq的指令序列示例：

|           |                    |
| :-------: | :----------------: |
|   fetch   | icode:ifun<-M1[PC] |
|           |  rA:rB<-M1[PC+1]   |
|           |   valC<-M1[PC+2]   |
|           |    ValP<-PC+10     |
|  decode   |    valB<-R[rB]     |
|  execute  |  ValE<-ValB+ValC   |
|           |       Set CC       |
|  memory   |                    |
| writeback |    R[rB]<-ValE     |
|           |      PC<-valP      |

修改seq-full.hcl后，根据文件构建新的仿真器（如果你不含有`Tcl/Tk`，需要在`Makefile`中将对应行注释掉）

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh9cb3ivk6j31h10u0gqy.jpg)

执行

`make VERSION=full`

然后

>- 在小的Y86-64程序中测试你的方法
>
>`./ssim -t ../y86-code/asumi.yo`
>
>如果失败了，还要重新修改你的实现
>
>- 使用基准程序来测试你的方法
>
>`cd ../y86-code; make testssim`
>
>这将在基准程序上运行ssim，并通过将结果处理器状态与高级ISA仿真中的状态进行比较来检查正确性。注意，这些程序均未测试添加的指令，只是确保你的方法没有为原始说明注入错误。
>
>- 一旦可以正确执行基准测试程序，则应在`../ptest`中运行大量的回归测试
>
>    测试除了`iaddq`以外的所有指令
>
>    `cd ../ptest; make SIM=../seq/ssim `
>
>    测试我们实现的`iaddq`指令
>
>    `cd ../ptest; make SIM=../seq/ssim TFLAGS=-i`

seq-full.hcl

```
#/* $begin seq-all-hcl */
####################################################################
#  HCL Description of Control for Single Cycle Y86-64 Processor SEQ   #
#  Copyright (C) Randal E. Bryant, David R. O'Hallaron, 2010       #
####################################################################

## Your task is to implement the iaddq instruction
## The file contains a declaration of the icodes
## for iaddq (IIADDQ)
## Your job is to add the rest of the logic to make it work

####################################################################
#    C Include's.  Don't alter these                               #
####################################################################

quote '#include <stdio.h>'
quote '#include "isa.h"'
quote '#include "sim.h"'
quote 'int sim_main(int argc, char *argv[]);'
quote 'word_t gen_pc(){return 0;}'
quote 'int main(int argc, char *argv[])'
quote '  {plusmode=0;return sim_main(argc,argv);}'

####################################################################
#    Declarations.  Do not change/remove/delete any of these       #
####################################################################

##### Symbolic representation of Y86-64 Instruction Codes #############
wordsig INOP 	'I_NOP'
wordsig IHALT	'I_HALT'
wordsig IRRMOVQ	'I_RRMOVQ'
wordsig IIRMOVQ	'I_IRMOVQ'
wordsig IRMMOVQ	'I_RMMOVQ'
wordsig IMRMOVQ	'I_MRMOVQ'
wordsig IOPQ	'I_ALU'
wordsig IJXX	'I_JMP'
wordsig ICALL	'I_CALL'
wordsig IRET	'I_RET'
wordsig IPUSHQ	'I_PUSHQ'
wordsig IPOPQ	'I_POPQ'
# Instruction code for iaddq instruction
wordsig IIADDQ	'I_IADDQ'

##### Symbolic represenations of Y86-64 function codes                  #####
wordsig FNONE    'F_NONE'        # Default function code

##### Symbolic representation of Y86-64 Registers referenced explicitly #####
wordsig RRSP     'REG_RSP'    	# Stack Pointer
wordsig RNONE    'REG_NONE'   	# Special value indicating "no register"

##### ALU Functions referenced explicitly                            #####
wordsig ALUADD	'A_ADD'		# ALU should add its arguments

##### Possible instruction status values                             #####
wordsig SAOK	'STAT_AOK'	# Normal execution
wordsig SADR	'STAT_ADR'	# Invalid memory address
wordsig SINS	'STAT_INS'	# Invalid instruction
wordsig SHLT	'STAT_HLT'	# Halt instruction encountered

##### Signals that can be referenced by control logic ####################

##### Fetch stage inputs		#####
wordsig pc 'pc'				# Program counter
##### Fetch stage computations		#####
wordsig imem_icode 'imem_icode'		# icode field from instruction memory
wordsig imem_ifun  'imem_ifun' 		# ifun field from instruction memory
wordsig icode	  'icode'		# Instruction control code
wordsig ifun	  'ifun'		# Instruction function
wordsig rA	  'ra'			# rA field from instruction
wordsig rB	  'rb'			# rB field from instruction
wordsig valC	  'valc'		# Constant from instruction
wordsig valP	  'valp'		# Address of following instruction
boolsig imem_error 'imem_error'		# Error signal from instruction memory
boolsig instr_valid 'instr_valid'	# Is fetched instruction valid?

##### Decode stage computations		#####
wordsig valA	'vala'			# Value from register A port
wordsig valB	'valb'			# Value from register B port

##### Execute stage computations	#####
wordsig valE	'vale'			# Value computed by ALU
boolsig Cnd	'cond'			# Branch test

##### Memory stage computations		#####
wordsig valM	'valm'			# Value read from memory
boolsig dmem_error 'dmem_error'		# Error signal from data memory


####################################################################
#    Control Signal Definitions.                                   #
####################################################################

################ Fetch Stage     ###################################

# Determine instruction code
word icode = [
	imem_error: INOP;
	1: imem_icode;		# Default: get from instruction memory
];

# Determine instruction function
word ifun = [
	imem_error: FNONE;
	1: imem_ifun;		# Default: get from instruction memory
];

bool instr_valid = icode in 
	{ INOP, IHALT, IRRMOVQ, IIRMOVQ, IRMMOVQ, IMRMOVQ,
	       IOPQ, IJXX, ICALL, IRET, IPUSHQ, IPOPQ, IIADDQ };##该信号判断是否为合法指令

# Does fetched instruction require a regid byte?
##iaddq指令需要读取寄存器rB
bool need_regids =
	icode in { IRRMOVQ, IOPQ, IPUSHQ, IPOPQ, 
		     IIRMOVQ, IRMMOVQ, IMRMOVQ, IIADDQ  };

# Does fetched instruction require a constant word?
iaddq指令需要立即数
bool need_valC =
	icode in { IIRMOVQ, IRMMOVQ, IMRMOVQ, IJXX, ICALL, IIADDQ };

################ Decode Stage    ###################################

## What register should be used as the A source?
word srcA = [
	icode in { IRRMOVQ, IRMMOVQ, IOPQ, IPUSHQ  } : rA;
	icode in { IPOPQ, IRET } : RRSP;
	1 : RNONE; # Don't need register
];

## What register should be used as the B source?
##因为iaddq要使用rB寄存器，所以需要设置srcB的源为rB
word srcB = [
	icode in { IOPQ, IRMMOVQ, IMRMOVQ,IIADDQ  } : rB;
	icode in { IPUSHQ, IPOPQ, ICALL, IRET } : RRSP;
	1 : RNONE;  # Don't need register
];

## What register should be used as the E destination?
##计算完的结果valE需要保存到寄存器rB中
word dstE = [
	icode in { IRRMOVQ } && Cnd : rB;
	icode in { IIRMOVQ, IOPQ, IIADDQ } : rB;
	icode in { IPUSHQ, IPOPQ, ICALL, IRET } : RRSP;
	1 : RNONE;  # Don't write any register
];

## What register should be used as the M destination?
word dstM = [
	icode in { IMRMOVQ, IPOPQ } : rA;
	1 : RNONE;  # Don't write any register
];

################ Execute Stage   ###################################

## Select input A to ALU
##iaddq指令需要将valC作为aluA的值
word aluA = [
	icode in { IRRMOVQ, IOPQ } : valA;
	icode in { IIRMOVQ, IRMMOVQ, IMRMOVQ, IIADDQ } : valC;
	icode in { ICALL, IPUSHQ } : -8;
	icode in { IRET, IPOPQ } : 8;
	# Other instructions don't need ALU
];

## Select input B to ALU
##iaddq指令需要将aluB的值设置为valB
word aluB = [
	icode in { IRMMOVQ, IMRMOVQ, IOPQ, ICALL, 
		      IPUSHQ, IRET, IPOPQ, IIADDQ } : valB;
	icode in { IRRMOVQ, IIRMOVQ } : 0;
	# Other instructions don't need ALU
];

## Set the ALU function
word alufun = [
	icode == IOPQ : ifun;
	1 : ALUADD;
];

## Should the condition codes be updated?
##iaddq指令需要更新CC
bool set_cc = icode in { IOPQ, IIADDQ };

################ Memory Stage    ###################################

## Set read control signal
bool mem_read = icode in { IMRMOVQ, IPOPQ, IRET };

## Set write control signal
bool mem_write = icode in { IRMMOVQ, IPUSHQ, ICALL };

## Select memory address
word mem_addr = [
	icode in { IRMMOVQ, IPUSHQ, ICALL, IMRMOVQ } : valE;
	icode in { IPOPQ, IRET } : valA;
	# Other instructions don't need address
];

## Select memory input data
word mem_data = [
	# Value from register
	icode in { IRMMOVQ, IPUSHQ } : valA;
	# Return PC
	icode == ICALL : valP;
	# Default: Don't write anything
];

## Determine instruction status
word Stat = [
	imem_error || dmem_error : SADR;
	!instr_valid: SINS;
	icode == IHALT : SHLT;
	1 : SAOK;
];

################ Program Counter Update ############################

## What address should instruction be fetched at

word new_pc = [
	# Call.  Use instruction constant
	icode == ICALL : valC;
	# Taken branch.  Use instruction constant
	icode == IJXX && Cnd : valC;
	# Completion of RET instruction.  Use value from stack
	icode == IRET : valM;
	# Default: Use incremented PC
	1 : valP;
];
#/* $end seq-all-hcl */
```

## partC

该部分在`sim/pipe`中进行，目的是让`ncopy`函数尽可能快，一般要先修改pipe-full.hc文件来增加`iaddq`指令，方法与partB完全相同

然后修改ncopy.ys文件

用`make psim VERSION=full`编译

用`./correctness.pl`测试`ncopy`函数的正确性

用`./benchmark.pl`来测试函数的性能

大于10.5为0分，小于7.5为满分60

憨憨的我又遇到了不知名的bug，增加`iaddq`指令后把能用常数操作的都改了过来

把

```
irmovq $1, %r10
subq %r10, %rdx
```

用

```
iaddq $-1, %rdx
```

代替

突然变成60分，实在是不知道为什么，希望光顾的师傅知道的话可以给我解释一哈

```
#/* $begin ncopy-ys */
##################################################################
# ncopy.ys - Copy a src block of len words to dst.
# Return the number of positive words (>0) contained in src.
#
# Include your name and ID here.
#
# Describe how and why you modified the baseline code.
#
##################################################################
# Do not modify this portion
# Function prologue.
# %rdi = src, %rsi = dst, %rdx = len
ncopy:

##################################################################
# You can modify this portion
	# Loop header
	xorq %rax,%rax		# count = 0;
	andq %rdx,%rdx		# len <= 0?
	jle Done		# if so, goto Done:

Loop:	
	mrmovq (%rdi), %r10	# read val from src...
	rmmovq %r10, (%rsi)	# ...and store it to dst
	andq %r10, %r10		# val <= 0?
	jle Npos		# if so, goto Npos:
	iaddq $1, %rax		# count++
Npos:	
	#irmovq $1, %r10
	iaddq $8, %rdi		# src++
	iaddq $8, %rsi		# dst++
	iaddq $-1, %rdx		# len--		#
	#andq %rdx,%rdx		# len > 0?
	jg Loop			# if so, goto Loop:
##################################################################
# Do not modify the following section of code
# Function epilogue.
Done:
	ret
##################################################################
# Keep the following label at the end of your function
End:
#/* $end ncopy-ys */
```

结果

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh9cxofm3rj30u02g2qg0.jpg)

虽然肯定是个假60分，但是我这水平估计连写出分数都很难

所以还是直接学习一下带师傅们的做法

[通俗解说CSAPP的archlab partC](https://zhuanlan.zhihu.com/p/61151313)	56.9分

[CSAPP: Architecture Lab](https://blog.csdn.net/u012336567/article/details/51867766)				60分

