---
layout:     post
title:      csapp-datalab
subtitle:   csapp-lab
date:       2020-07-21
author:     X1ng
header-img: csapp_lab1.jpg
catalog: true
tags:

- lab
- csapp


---

## 知识点

一、补码

即“对负数的绝对值按位取反再+1”

> 更符合补码的原理,对补码更加自然的解释是：对于负数−𝑥−x,"若数据类型为n个二进制位,则补码为2𝑛−𝑥2n−x".也就是说,这个补码其实就是−𝑥−x,只不过是对2𝑛2n取模之后的−𝑥−x.这样就能理解,为什么减去一个数等于加上这个数的补码,因为补码无非是这个数在模意义下的相反数.

int类型中最小的数为

0x80000000 == 10000000 00000000 00000000 00000000B

int类型中最大的数为

0x7fffffff == 01111111 1111111 1111111 11111111

其中最左边一位为符号位，符号位为0，表示正数，为1表示负数。

二、移码

将数值加上一个特定的偏置常数bias表示

IEEE浮点标准中 bias=2^(n-1) -1（二的n减一次方减一，n为编码位数）

如当bias==8时,

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1ggyxv6losgj308i070wf7.jpg)

三、浮点数

C语言的float通常是指IEEE二进制浮点数算术标准中的单精确度，而double是指双精确度

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1ggyxuutw2qj31360gq0sq.jpg)

其中s为符号位，exp为阶码，frac为尾数

1.规范化的值

当exp的位模式既不全为0，也不全为1时，所表示的数是规范化形式

阶码字段被解释为移码表示的有符号整数（bias单精度为2^7-1=127，双精度为2^11-1=1023)，阶的值E=e-bias（e即exp表示的有符号整数）

小数字段frac被解释为描述小树值f，尾数定义为M=1+f

即表示的值为

![](https://tva1.sinaimg.cn/large/007S8ZIlgy1ggyyd25yt0j306m03k0pg.jpg)

2.非规范化的值

当exp的位模式全为0时，所表示的数是非规范化形式

阶的值E=1-bias

尾数M=F，不包含隐含的开头的1

3.特殊值

当exp的位模式全为1时

<1>小数域frac全为0，表示无穷

<2>小数域frac不全为0，表示NaN（Not a Number）

> ### 二进制1 10000010 00001000000000000000000是一个单精度浮点数，对应的十进制数是多少？
>
> 最高位为1，表示负数；
>
> 指数位为100000102 = 13010，130 – 127 = 3；
>
> 尾数为00001000000000000000000，换成十进制为1 + 1/32。注意这里的1不要忘了加。
>
> 所以表示的数为-(1 + 1/32) * 2^3 = -8.25
>
> ### 求非规约数0 00000000 00000000000000000000001所表示的十进制
>
> 因为是非规约数，所以指数位是1 -127 = -126，而不是0 - 127 = -127；
>
> 非规约数的尾数部分没有隐含的1，所以尾数部分为2^(-23)；
>
> 所以对应的十进制为2^(-23) * 2^(-126) = 2^(-149),这是非规约数所能表示的最小的正数。
>
> 同理非规约数所能表示的最大负数为1 00000000 00000000000000000000001= -2^(-149)

## datalab

```
/*
 * CS:APP Data Lab
 *
 * <Please put your name and userid here>
 *
 * bits.c - Source file with your solutions to the Lab.
 *          This is the file you will hand in to your instructor.
 *
 * WARNING: Do not include the <stdio.h> header; it confuses the dlc
 * compiler. You can still use printf for debugging without including
 * <stdio.h>, although you might get a compiler warning. In general,
 * it's not good practice to ignore compiler warnings, but in this
 * case it's OK.
 */

#if 0
/*
 * Instructions to Students:
 *
 * STEP 1: Read the following instructions carefully.
 */

You will provide your solution to the Data Lab by
editing the collection of functions in this source file.

INTEGER CODING RULES:

  Replace the "return" statement in each function with one
  or more lines of C code that implements the function. Your code
  must conform to the following style:

  int Funct(arg1, arg2, ...) {
      /* brief description of how your implementation works */
      int var1 = Expr1;
      ...
      int varM = ExprM;

      varJ = ExprJ;
      ...
      varN = ExprN;
      return ExprR;
  }

  Each "Expr" is an expression using ONLY the following:
  1. Integer constants 0 through 255 (0xFF), inclusive. You are
      not allowed to use big constants such as 0xffffffff.
  2. Function arguments and local variables (no global variables).
  3. Unary integer operations ! ~
  4. Binary integer operations & ^ | + << >>

  Some of the problems restrict the set of allowed operators even further.
  Each "Expr" may consist of multiple operators. You are not restricted to
  one operator per line.

  You are expressly forbidden to:
  1. Use any control constructs such as if, do, while, for, switch, etc.
  2. Define or use any macros.
  3. Define any additional functions in this file.
  4. Call any functions.
  5. Use any other operations, such as &&, ||, -, or ?:
  6. Use any form of casting.
  7. Use any data type other than int.  This implies that you
     cannot use arrays, structs, or unions.


  You may assume that your machine:
  1. Uses 2s complement, 32-bit representations of integers.
  2. Performs right shifts arithmetically.
  3. Has unpredictable behavior when shifting if the shift amount
     is less than 0 or greater than 31.


EXAMPLES OF ACCEPTABLE CODING STYLE:
  /*
   * pow2plus1 - returns 2^x + 1, where 0 <= x <= 31
   */
  int pow2plus1(int x) {
     /* exploit ability of shifts to compute powers of 2 */
     return (1 << x) + 1;
  }

  /*
   * pow2plus4 - returns 2^x + 4, where 0 <= x <= 31
   */
  int pow2plus4(int x) {
     /* exploit ability of shifts to compute powers of 2 */
     int result = (1 << x);
     result += 4;
     return result;
  }

FLOATING POINT CODING RULES

For the problems that require you to implement floating-point operations,
the coding rules are less strict.  You are allowed to use looping and
conditional control.  You are allowed to use both ints and unsigneds.
You can use arbitrary integer and unsigned constants. You can use any arithmetic,
logical, or comparison operations on int or unsigned data.

You are expressly forbidden to:
  1. Define or use any macros.
  2. Define any additional functions in this file.
  3. Call any functions.
  4. Use any form of casting.
  5. Use any data type other than int or unsigned.  This means that you
     cannot use arrays, structs, or unions.
  6. Use any floating point data types, operations, or constants.


NOTES:
  1. Use the dlc (data lab checker) compiler (described in the handout) to
     check the legality of your solutions.
  2. Each function has a maximum number of operations (integer, logical,
     or comparison) that you are allowed to use for your implementation
     of the function.  The max operator count is checked by dlc.
     Note that assignment ('=') is not counted; you may use as many of
     these as you want without penalty.
  3. Use the btest test harness to check your functions for correctness.
  4. Use the BDD checker to formally verify your functions
  5. The maximum number of ops for each function is given in the
     header comment for each function. If there are any inconsistencies
     between the maximum ops in the writeup and in this file, consider
     this file the authoritative source.

/*
 * STEP 2: Modify the following functions according the coding rules.
 *
 *   IMPORTANT. TO AVOID GRADING SURPRISES:
 *   1. Use the dlc compiler to check that your solutions conform
 *      to the coding rules.
 *   2. Use the BDD checker to formally verify that your solutions produce
 *      the correct answers.
 */


#endif
//1
/*
 * bitXor - x^y using only ~ and &
 *   Example: bitXor(4, 5) = 1
 *   Legal ops: ~ &
 *   Max ops: 14
 *   Rating: 1
 */
int bitXor(int x, int y) {
    //用与非表示异或
    return ~((~(~x & y))&(~(x & ~y)));
}
/*
 * tmin - return minimum two's complement integer
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 4
 *   Rating: 1
 */
int tmin(void) {
    //最小的二进制数0x80000000
    return 1<<31;
}
//2
/*
 * isTmax - returns 1 if x is the maximum, two's complement number,
 *     and 0 otherwise
 *   Legal ops: ! ~ & ^ | +
 *   Max ops: 10
 *   Rating: 1
 */
int isTmax(int x) {
    //最大的二进制数0x7fffffff
    //如果x是0x7fffffff或0xffffffff的话，则2*x+1==0成立
    //所以排除0xffffffff后，若x使2*x+1==0成立则x是0x7fffffff
    return !(!((~0)^x))&(!((x+1+x)^(~0)));
}
/*
 * allOddBits - return 1 if all odd-numbered bits in word set to 1
 *   where bits are numbered from 0 (least significant) to 31 (most significant)
 *   Examples allOddBits(0xFFFFFFFD) = 0, allOddBits(0xAAAAAAAA) = 1
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 12
 *   Rating: 2
 */
int allOddBits(int x) {
    //这题自己写的ops大于12，虽然可以通过，但是不满足要求
    //return (!((x&0xaa)^(0xAA)))&(!(((x>>8)&0xaa)^(0xAA)))&(!(((x>>16)&0xaa)^(0xAA)))&(!(((x>>24)&0xaa)^(0xAA)));
    int b16 = x & (x >> 16);
    int b8 = b16 & (b16 >> 8);
    int b4 = b8 & (b8 >> 4);
    int b2 = b4 & (b4 >> 2);
    return (b2 >> 1) & 1;
}
/*
 * negate - return -x
 *   Example: negate(1) = -1.
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 5
 *   Rating: 2
 */
int negate(int x) {
    //用"+"和"~"表示"-"，即~x+1==-x
    return (~x)+1;
}
//3
/*
 * isAsciiDigit - return 1 if 0x30 <= x <= 0x39 (ASCII codes for characters '0' to '9')
 *   Example: isAsciiDigit(0x35) = 1.
 *            isAsciiDigit(0x3a) = 0.
 *            isAsciiDigit(0x05) = 0.
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 15
 *   Rating: 3
 */
int isAsciiDigit(int x) {
    //0x30==110000B
    //0x39==111001B
    //先确定最高两位都是1，然后x其他四位与1001B(0xf)作差判断正负即可
    return (!((x>>4)^3))&(!((9+(~(x&0xf)+1))>>31));
}
/*
 * conditional - same as x ? y : z
 *   Example: conditional(2,4,5) = 4
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 16
 *   Rating: 3
 */
int conditional(int x, int y, int z) {
    //若x不为0则返回y，反之返回z
    //!!x将x变为布尔代数
    //~1+1==0xffffffff  ~0+1==0x00000000
    return ((~(!!x)+1)&y)+((~(!x)+1)&z);
}
/*
 * isLessOrEqual - if x <= y  then return 1, else return 0
 *   Example: isLessOrEqual(4,5) = 1.
 *   Legal ops: ! ~ & ^ | + << >>
 *   Max ops: 24
 *   Rating: 3
 */
int isLessOrEqual(int x, int y) {
    //直接作差比较容易整数溢出
    //需要分类讨论x和y同号或异号
    //如果x y相等，则返回1
    //如果x y异号，则x<0时返回1
    //如果x y同号，则作差比较
    return (!(x^y))|(!!(((x>>31)^(y>>31))&(x>>31)))|!!((!((x>>31)^(y>>31)))&((x+(~y+1))>>31));
}
//4
/*
 * logicalNeg - implement the ! operator, using all of
 *              the legal operators except !
 *   Examples: logicalNeg(3) = 0, logicalNeg(0) = 1
 *   Legal ops: ~ & ^ | + << >>
 *   Max ops: 12
 *   Rating: 4
 */
int logicalNeg(int x) {
    //x和(~x+1)的符号位
    //当x==0时，符号位均为0
    //当x==0x80000000时，符号位均为1
    //则~x&~(~x+1)当x为0时符号位为1
    return ((~(~x+1)&~x)>>31)&1;
}
/* howManyBits - return the minimum number of bits required to represent x in
 *             two's complement
 *  Examples: howManyBits(12) = 5
 *            howManyBits(298) = 10
 *            howManyBits(-5) = 4
 *            howManyBits(0)  = 1
 *            howManyBits(-1) = 1
 *            howManyBits(0x80000000) = 32
 *  Legal ops: ! ~ & ^ | + << >>
 *  Max ops: 90
 *  Rating: 4
 */
int howManyBits(int x) {
    //tnl，不会，抄的
  int minusOne = ~0;
  int flagMask = (x >> 31 & 1) + minusOne; // x > 0 : 0xffffffff x < 0 : 0
  int posiX =  (x & flagMask) | ~(x | flagMask); // x = x > 0 ? x : ~x
  int x1 = posiX | posiX >> 1;
  int x2 = x1 | x1 >> 2;
  int x3 = x2 | x2 >> 4;
  int x4 = x3 | x3 >> 8;
  int reguX = x4 | x4 >> 16; // change 0x001xx to 0x00111
  int ans = 0;
  int top = reguX >> 16;
  int mask = ( (!top) + minusOne ) & 16;
  reguX >>= mask;
  ans += mask;
  top = reguX >> 8;
  mask = ( (!top) + minusOne ) & 8;
  reguX >>= mask;
  ans += mask;
  top = reguX >> 4;
  mask = ( (!top) + minusOne ) & 4;
  reguX >>= mask;
  ans += mask;
  top = reguX >> 2;
  mask = ( (!top) + minusOne ) & 2;
  reguX >>= mask;
  ans += mask;
  top = reguX >> 1;
  mask = ( (!top) + minusOne ) & 1;
  reguX >>= mask;
  ans += mask;
  ans += reguX;
  return ans + 1;
}
//float
/*
 * floatScale2 - Return bit-level equivalent of expression 2*f for
 *   floating point argument f.
 *   Both the argument and result are passed as unsigned int's, but
 *   they are to be interpreted as the bit-level representation of
 *   single-precision floating point values.
 *   When argument is NaN, return argument
 *   Legal ops: Any integer/unsigned operations incl. ||, &&. also if, while
 *   Max ops: 30
 *   Rating: 4
 */
unsigned floatScale2(unsigned uf) {
    //抄的
	unsigned int exp = (0x7f800000&uf)>>23;
  	unsigned int frac = 0x007fffff&uf;
	unsigned int s = 0x80000000&uf;
	if (exp == 0xff) // NaN or infinity
    	return uf;
  	else if (exp == 0) // unnormalized
    	frac <<= 1;
  	else if (exp == 0xfe) { // become infinity
    	frac = 0;
    	exp = 0xff;
  	}
  	else
  		exp++; // normalized
  return s | (exp << 23) | frac;
}
/*
 * floatFloat2Int - Return bit-level equivalent of expression (int) f
 *   for floating point argument f.
 *   Argument is passed as unsigned int, but
 *   it is to be interpreted as the bit-level representation of a
 *   single-precision floating point value.
 *   Anything out of range (including NaN and infinity) should return
 *   0x80000000u.
 *   Legal ops: Any integer/unsigned operations incl. ||, &&. also if, while
 *   Max ops: 30
 *   Rating: 4
 */
int floatFloat2Int(unsigned uf) {
    //抄的
  unsigned flag = uf & 0x80000000;
  unsigned exp = uf >> 23 & 0xFF;
  unsigned frac = uf & 0x7fffff;
  if (exp > 157) // out of range
    return 0x80000000;
  else if (exp < 127) // too small
    return 0;
  else {
    int e = exp - 127;
    int ans = (1 << e);
    if (e) ans += frac;
    frac <<= e;
    if (frac == 0x80000000)
      ans += (ans & 1);
    else
      ans += frac > 0x80000000;
    if (flag) ans = -ans;
    return ans;
  }
}
/*
 * floatPower2 - Return bit-level equivalent of the expression 2.0^x
 *   (2.0 raised to the power x) for any 32-bit integer x.
 *
 *   The unsigned value that is returned should have the identical bit
 *   representation as the single-precision floating-point number 2.0^x.
 *   If the result is too small to be represented as a denorm, return
 *   0. If too large, return +INF.
 *
 *   Legal ops: Any integer/unsigned operations incl. ||, &&. Also if, while
 *   Max ops: 30
 *   Rating: 4
 */
unsigned floatPower2(int x) {
    //抄的
  if (x < -149)
    return 0;
  if (x < -127)
    return 1 << (x + 149);
  if (x > 127)
    return 0x7f800000;
  return (x + 127) << 23;
}

```

