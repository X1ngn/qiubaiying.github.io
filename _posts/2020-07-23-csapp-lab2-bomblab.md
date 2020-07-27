---
layout:     post
title:      csapp-bomblab
subtitle:   csapp-lab
date:       2020-07-23
author:     X1ng
header-img: csapp_lab2.jpg
catalog: true
tags:

- lab
- csapp



---

bomblab提供一个二进制文件，运行时，它提示用户键入6个不同的字符串。如果其中任何一个不正确，炸弹就会“爆炸”，打印错误消息并将事件记录在分级服务器上。逆向很菜的我只能借助ida pro的c伪代码和汇编代码结合才勉强能完成

## bomb.c

```
/***************************************************************************
 * Dr. Evil's Insidious Bomb, Version 1.1
 * Copyright 2011, Dr. Evil Incorporated. All rights reserved.
 *
 * LICENSE:
 *
 * Dr. Evil Incorporated (the PERPETRATOR) hereby grants you (the
 * VICTIM) explicit permission to use this bomb (the BOMB).  This is a
 * time limited license, which expires on the death of the VICTIM.
 * The PERPETRATOR takes no responsibility for damage, frustration,
 * insanity, bug-eyes, carpal-tunnel syndrome, loss of sleep, or other
 * harm to the VICTIM.  Unless the PERPETRATOR wants to take credit,
 * that is.  The VICTIM may not distribute this bomb source code to
 * any enemies of the PERPETRATOR.  No VICTIM may debug,
 * reverse-engineer, run "strings" on, decompile, decrypt, or use any
 * other technique to gain knowledge of and defuse the BOMB.  BOMB
 * proof clothing may not be worn when handling this program.  The
 * PERPETRATOR will not apologize for the PERPETRATOR's poor sense of
 * humor.  This license is null and void where the BOMB is prohibited
 * by law.
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "support.h"
#include "phases.h"

/* 
 * Note to self: Remember to erase this file so my victims will have no
 * idea what is going on, and so they will all blow up in a
 * spectaculary fiendish explosion. -- Dr. Evil 
 */

FILE *infile;

int main(int argc, char *argv[])
{
    char *input;

    /* Note to self: remember to port this bomb to Windows and put a 
     * fantastic GUI on it. */

    /* When run with no arguments, the bomb reads its input lines 
     * from standard input. */
    if (argc == 1) {  
	infile = stdin;
    } 

    /* When run with one argument <file>, the bomb reads from <file> 
     * until EOF, and then switches to standard input. Thus, as you 
     * defuse each phase, you can add its defusing string to <file> and
     * avoid having to retype it. */
    else if (argc == 2) {
	if (!(infile = fopen(argv[1], "r"))) {
	    printf("%s: Error: Couldn't open %s\n", argv[0], argv[1]);
	    exit(8);
	}
    }

    /* You can't call the bomb with more than 1 command line argument. */
    else {
	printf("Usage: %s [<input_file>]\n", argv[0]);
	exit(8);
    }

    /* Do all sorts of secret stuff that makes the bomb harder to defuse. */
    initialize_bomb();

    printf("Welcome to my fiendish little bomb. You have 6 phases with\n");
    printf("which to blow yourself up. Have a nice day!\n");

    /* Hmm...  Six phases must be more secure than one phase! */
    input = read_line();             /* Get input                   */
    phase_1(input);                  /* Run the phase               */
    phase_defused();                 /* Drat!  They figured it out!
				      * Let me know how they did it. */
    printf("Phase 1 defused. How about the next one?\n");

    /* The second phase is harder.  No one will ever figure out
     * how to defuse this... */
    input = read_line();
    phase_2(input);
    phase_defused();
    printf("That's number 2.  Keep going!\n");

    /* I guess this is too easy so far.  Some more complex code will
     * confuse people. */
    input = read_line();
    phase_3(input);
    phase_defused();
    printf("Halfway there!\n");

    /* Oh yeah?  Well, how good is your math?  Try on this saucy problem! */
    input = read_line();
    phase_4(input);
    phase_defused();
    printf("So you got that one.  Try this one.\n");
    
    /* Round and 'round in memory we go, where we stop, the bomb blows! */
    input = read_line();
    phase_5(input);
    phase_defused();
    printf("Good work!  On to the next...\n");

    /* This phase will never be used, since no one will get past the
     * earlier ones.  But just in case, make this one extra hard. */
    input = read_line();
    phase_6(input);
    phase_defused();

    /* Wow, they got it!  But isn't something... missing?  Perhaps
     * something they overlooked?  Mua ha ha ha ha! */
    
    return 0;
}
```

## phase_1

输入字符串

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh232y45erj31nq06aab7.jpg)

调用phase_1

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh2g35tjpij31na0g241i.jpg)

看函数名字，其实就是输入的字符串与"Border relations with Canada have never been better."比较，不同则炸弹爆炸

输入`Border relations with Canada have never been better.`

## phase_2

调用phase_2

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh2ga4tfpgj30x10u0x1d.jpg)

大概是从输入的字符串里读取六个数字，判断第一个数字是1且往后每一个数都是前一个数 * 2

输入`1 2 4 8 16 32`

## phase_3

调用phase_3

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh2goz84zhj30u01b8npd.jpg)

从输入的字符串里读取2个整数，如果读取的整数数量不是2则爆炸，然后switch根据第一个数的值给eax赋值，再与第二个数比较，不相等则爆炸

其c伪代码为

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh2i2bnhvbj313l0u00z1.jpg)

输入`0 207`

## phase_4

调用phase_4

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh2hk5c1bhj312d0u01b5.jpg)

从输入的字符串里读取2个整数，如果读取的整数数量不是2则爆炸，然后调用func4

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh2hurtuisj31eh0u044z.jpg)

一个递归调用

其c伪代码为

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh2i5lb268j31bk0eyabm.jpg)

输入`0 7`

## phase_5

调用phase_5

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh2i6excogj30u00zh1kx.jpg)

要求输入6个字符，然后将其asc码的低4位分别作为array_3449数组下标，从而组成新的字符串与"flyers"比较

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh2ia9k9d7j31lk0h80w3.jpg)

输入`9?>567`

## phase_6

调用phase_6

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh2id7edvcj30u01z84qq.jpg)

其c伪代码为

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh2ituyv5nj30u01ay7ht.jpg)

菜鸡的我看着c代码也毫无头绪

参考其他师傅的做法才知道

输入的字符串为6个整数，6个数都小于等于6且互不相等，分别进行`x = 7 - x`的操作

后面是关于node的操作

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh2j5d96z5j30xw06u0uq.jpg)

没看出来这是个结构体

```
struct 
{
    int value;
    int order;
    tag* next;
} tag;
```

只要保证以上文处理后的6个整数的顺序排列这个链表，保证大的在前小的在后就能通过

输入`4 3 2 1 6 5`



## secret_phase

每次调用完一个phase都会调用一次phase_defused

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh2jhxhzvkj31ed0u0dnk.jpg)

调用phase_defused

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh390hqxjjj30vz0u01i4.jpg)

需要输入的字符串数目为6，也就是拆完六个炸弹后才能从某个字符串里读取格式化字符串`%d %d %s`，然后将`%s`的字符串与"DrEvil"比较

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh3acaa1ykj31cq0ii7cd.jpg)

可以看到读取的字符串就是刚才phase_4里输入的`0 7`

所以只要在当时输入`0 7 DrEvil`，就可以进入secret_phase

调用secret_phase

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh3akqrpdyj31hp0u0gxp.jpg)

百度一下strtol函数

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh3alk2xjzj31bc0tudic.jpg)

就是从字符串里将数字字符转化为对应的整型

所以就是输入小于等于1000的数字字符串，然后调用func7，并保证返回值为2

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh3ayewj6kj31e20u0n4o.jpg)

其对应c伪代码为

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh3avii2ygj319c0eadhd.jpg)

只要保证 先让a2大于n1，然后a2大于n1 ，然后a2等于n1

也就是返回0 0+1 1 * 2

n1的的内容为

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh5k1z27bdj310w0k07df.jpg)

输入`22`

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1gh3bfxxfbuj30z40k2dlf.jpg)

