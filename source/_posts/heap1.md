---
title: 堆基础原理
date: 2023-07-27 19:42:22
tags: [Pwn,heap,Basic Knowledge]
cover: "https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap1cover.jpg"
categories: [Study]
---

堆（Heap）是计算机科学中一类特殊的数据结构，它用于存储可以动态分配和删除内存块的数据。堆通常由一系列称为堆块（Heap Block）的内存块组成，每个堆块可以存储一定数量的数据。在堆中，堆块的大小可以是固定的或可变的。对于可变大小的堆块，它们的大小可以在运行时动态改变。这种灵活性使得堆成为一种非常方便的内存管理工具，可以用于实现动态数组、链表等功能。然而，由于堆中的数据可以动态分配和删除，因此也可能会出现一些安全问题。其中一种常见的问题是堆溢出（Heap Overflow）。我们首先介绍堆的基础原理：

# 一、介绍

堆可以提供动态分配的内存，允许程序申请未知的内存，是程序虚拟地址空间中的一块连续线性的区域，由低地址向高地址增长。当前 Linux 使用的堆分配器被称为 `ptmalloc2，在 glibc 中实现。对堆利用来说，不用通过栈溢出直接覆盖函数的返回地址从而控制 EIP，只能通过间接手段来劫持程序控制流。

堆的属性是可读可写的，大小通过 brk()或sbrk()函数进行控制。如图所示，在堆未初始化时，program_break 指向 BSS 段的末尾，通过调用brk()和sbrk()来移动program_break使得堆增长。在堆初始化时，如果开启了ASLR，则堆的起始地址start_brk 会在BSS 段之后的随机位移处，如果没有开启，则start_brk会紧接着BSS 段。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h1.png?x-oss-process=style/watermark)

通常来说，系统中的堆指的是主线程中main arena所管理的区域。但glibc会同时维持多个区域来供多线程使用，每个线程都有属于自己的内存（称为arena），这些连续的内存也可以称为堆。arena 指的是堆内存区域本身，并不是结构。主线程创建的堆称为main arena，由sbrk创建，它包含start_brk和 brk之间的这片连续内存，内存不够时通过brk调用来扩展。子线程堆称为per thread arena，由mmap创建，其分配的映射段大小是固定的，不可以扩展，映射段不够用时用mmap来分配新的内存。

malloc_state 管理 arena 的核心结构，包含堆的状态信息、bins 链表等。main arena 对应的 malloc state 结构存储在 glibc 全局变量中；其他线程 arena 对应的 malloc_state 存储在 arena 本身中，每个部分由heap_info管理。子线程的堆栈都是分配在内存映射区和堆区之间的区域（也可以理解为就是分配在内存映射区，因为内存映射区和堆区都是动态增长的，内存映射区向下增长，堆区向上增长）。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h2.png?x-oss-process=style/watermark)

glibc的想法是:当用户申请堆块时，从堆中按顺序分配堆块交给用户，用户保存指向这些堆块的指针;当用户释放堆块时，glibc会将释放的堆块组织成链表;当两块相邻堆块都为释放状态时将之合并成一个新的堆块;由此解决内存碎片的问题。

chunk是glibc管理内存的基本单位,整个堆在初始化后会被当成一个free chunk,称为 top chunk,每次用户请求内存时，如果 bins中没有合适的chunk，malloc就会从top chunk中进行划分,如果top chunk 的大小不够，则调用 brk()扩展堆的大小，然后从新生成的 top chunk 中进行切分。用户正在使用中的堆块叫作allocated chunk，被释放的堆块叫作free chunk，由free chunk组成的链表叫作bin。我们称当前chunk低地址处相邻的chunk为上一个(后面的)chunk,高地址处相邻的chunk为下一个(前面的)chunk。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h3.png?x-oss-process=style/watermark)

用户释放内存时，glibc 会先根据情况将释放的chunk与其他相邻的free chunk 合并，然后加入合适的 bin中。如图所示，用户连续申请了三个堆块 A、B、C，此时释放chunk B，由于它与 top chunk不相邻，所以会被放入 bin中，成为一个free chunk。现在再次申请一个与B相同大小的堆块，则malloc将从 bin中取出 chunk B，回到一开始的状态bin的表头也会指向null。但如果用户连续释放chunk A和 chunk B，由于它们相邻且都是free chunk，那么就会被合并成一个大的chunk放入 bin中。为了方便管理，glibc将不同大小范围的chunk组织成不同的 bin。如fast bin、small bin、large bin等，在这些链表中的chunk分别叫作 fast chunk、small chunk 和 large chunk。

堆分配的大致流程如上，接下来详细介绍各个部分的细节。

------

# 二、堆的各个结构

## 2.1 malloc_state

大部分情况下对于每个线程而言其都会单独有着一个 arena 实例用以管理属于该线程的堆内存区域。ptmalloc内部的内存池结构是由 malloc_state 结构体进行定义的，即 arena本身便为 malloc_state 的一个实例对象。malloc_state结构体定义于malloc/malloc.c中：

```c
struct malloc_state
{
  mutex_t mutex;//mutex 变量即为多线程互斥锁，用以保证线程安全
  int flags;//标志位，用以表示 arena 的一些状态，如：是否有 fastbin 、内存是否连续等
  mfastbinptr fastbinsY[NFASTBINS];//存放 fastbin chunk 的数组
  mchunkptr top;//指向 Top Chunk 的指针
  mchunkptr last_remainder;//chunk 切割中的剩余部分。
  mchunkptr bins[NBINS * 2 - 2];//存放闲置 chunk 的数组。
  unsigned int binmap[BINMAPSIZE];//记录 bin 是否为空的 bitset 。
  struct malloc_state *next;//指向下一个 arena 的指针
  struct malloc_state *next_free;//指向下一个空闲的arena的指针。
  INTERNAL_SIZE_T attached_threads;//与该 arena 相关联的线程数。
  INTERNAL_SIZE_T system_mem;//记录当前 arena 在堆区中所分配到的内存的总大小
  INTERNAL_SIZE_T max_system_mem;//记录 system_mem 的最大值
};
```

值得注意的是：

- **mfastbinptr fastbinsY[NFASTBINS]**：fastbinsY 是一个bin数组，里面有NFASTBINS个fastbin。
- **last_remainder**：chunk 切割中的剩余部分。malloc 在分配 chunk 时若是没找到 size 合适的 chunk 而是找到了一个 size 更大的 chunk ，则会从大 chunk 中切割掉一块返回给用户，剩下的那一块便是 last_remainder ，其随后会被放入 unsorted bin 中。
- **binmap**：记录 bin 是否为空的 bitset 。需要注意的是chunk被取出后若一个bin空了并不会立即被置0，而会在下一次遍历到时重新置位。
- **mchunkptr bins[NBINS \* 2 - 2]：**bins也是一个bin数组，大小为126。记录的是unsorted bin（1）、small bin（2~63）、large bin链（64~126）。

各类bin详细介绍在第3章。

## 2.2 main_arena

如之前所说，main arena 无需维护多个堆，当空间耗尽时，main arena 可以通过sbrk拓展堆段，直至堆段「碰」到内存映射段。管理main arena 的 arena header作为一个全局变量，可以在 libc.so 的数据段中找到。main_arena 为一个定义于 malloc.c 中的静态的 malloc_state 结构体。

```c
static struct malloc_state main_arena =
{
	.mutex =_LIBC_LOCK_INITIALIZER,
	.next =&main_arena,
	.attached_threads = 1
};
```

由于其为libc中的静态变量，该arena会被随着libc文件一同加载到Memory Mapping Segment。因此在堆题中通常通过泄露arena的地址以获得 libc 在内存中的基地址。thread arena则不同，通常有多片连续内存，这些内存被称为heap。每一个heap都有自己的 heap header（heap_info），用以管理堆。**堆被分为若干个chunk，每个chunk由malloc_chunk管理（详见2.4节）**。main arena 和 thread arena 的图示如下：

图片来源于：https://blog.csdn.net/u014377094/article/details/123938344

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h4.png)

总结来说，main arena只有一块空间，管理main arena的是malloc_state，在libc里面存储。main arena没有heap_info。thread arena有多块空间，每个空间都是heap，每个heap都有自己的heap header(heap_info)管理。heap_info介绍如下：

## 2.3 heap_info

heap_info 位于一个 heap 块的开头，用以记录通过 mmap 系统调用从 Memory Mapping Segment 处申请到的内存块的信息。定义于 arena.c 中。

```c
typedef struct _heap_info
{
  mstate ar_ptr; //指向管理该堆块的 arena
  struct _heap_info *prev; //该heap_info所链接的上一个 heap_info
  size_t size;   //记录该堆块的大小
  size_t mprotect_size; //记录该堆块中被保护（mprotected）的大小
  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];//padding
} heap_info;
```

pad：即 padding ，用以在 SIZE_SZ 不正常的情况下进行填充以让内存对齐，正常情况下 pad 所占用空间应为 0 字节。多个heap的图示如下：

图片来源于：https://blog.csdn.net/u014377094/article/details/123938344

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h5.png)

thread arena有且只有一个malloc_state（即 arena header），保存在第一个heap中。两个 heap 通过 mmap 从操作系统申请内存，两者在内存布局上并不相邻而是分属于不同的内存区间，所以为了便于管理，第二个 heap_info 结构体的 prev 成员指向了第一个 heap_info 结构体的起始位置（即 ar_ptr 成员），而第一个 heap_info 结构体的 ar_ptr 成员指向了 malloc_state，这样就构成了一个单链表(**malloc_state****à****heap_info(1)****à****heap_info(2)****à**)，其中malloc_state的top chunk指向第二个heap的top chunk，方便后续管理。

## 2.4 malloc_chunk

由 malloc 申请的内存为 chunk，这块内存在 ptmalloc 中被称为 malloc_chunk 结构体表示。无论一个 chunk 的大小如何，处于分配状态还是释放状态，它们都使用一个统一的结构。虽然它们使用了同一个数据结构，但是根据是否被释放，它们的表现形式会有所不同。

```c
struct malloc_chunk {

  INTERNAL_SIZE_T      prev_size;  //前一个 chunk 的大小
  INTERNAL_SIZE_T      size;   //该 chunk 的大小    
  struct malloc_chunk* fd;   //指向下一个空闲的 chunk     
  struct malloc_chunk* bk;   //指向上一个空闲的 chunk
  struct malloc_chunk* fd_nextsize; //指向前一个与当前 chunk 大小不同的第一个空闲块
  struct malloc_chunk* bk_nextsize; //指向后一个与当前 chunk 大小不同的第一个空闲块
};
```

**prev_size：**如果前一个 chunk 是空闲的话，记录物理相邻前一个 chunk 的大小；否则存储前一个 chunk 的用户数据（一部分而已，主要是为了能够充分利用这块内存空间）。

**size**：该 chunk 的大小，必须是 2*SIZE_SZ 的整数倍，后三位分别是：NON_MAIN _ARENA（A）、IS_MAPPED（M）、PREV_INUSE（P）。A表示该 chunk 属于主分配区（0）或者非主分配区（1）。M记录当前 chunk 是否是由 mmap 分配的，M 为 1 表示该 chunk 是从 mmap 映射区域分配的，否则是从 heap 区域分配的。P记录前一个 chunk 块是否被分配。一般来说，堆中第一个被分配的内存块的 size 字段的 P 位都会被设置为 1，以便于防止访问前面的非法内存。当一个 chunk 的 size 的 P 位为 0 时，我们能通过 prev_size 字段来获取上一个 chunk 的大小以及地址。这也方便进行空闲 chunk 之间的合并。

**fd、bk**：chunk 处于分配时从 fd 字段开始就是用户数据了，chunk 空闲时会被添加到对应的空闲管理链表中。fd：指向下一个（非物理相邻）空闲的 chunk。bk：指向上一个（非物理相邻）空闲的 chunk。通过 fd 和 bk 可以将空闲的 chunk 块加入到空闲的 chunk 块链表进行统一管理。

**fd_nextsize， bk_nextsize**：也是只有 chunk 空闲的时候才使用，不过其用于较大的 chunk（**large chunk**）。fd_nextsize：指向前一个与当前 chunk 大小不同的第一个空闲块，不包含 bin 的头指针。bk_nextsize：指向后一个与当前 chunk 大小不同的第一个空闲块，不包含 bin 的头指针。一般空闲的 large chunk 在 fd 的遍历顺序中，按照由大到小的顺序排列。这样做可以避免在寻找合适 chunk 时挨个遍历。

如图所示，处于使用状态的chunk：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h6.png?x-oss-process=style/watermark)

chunk由两部分组成，即pre_size和 size组成的chunk header和后面供用户使用的user data。chunk 指针指向一个 chunk 的开始，一个 chunk 中包含了用户请求的内存区域和相关的控制信息。malloc()函数返回给用户的实际上是指向用户数据的mem指针。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h7.png?x-oss-process=style/watermark)

由于当前chunk处于释放状态,此时fd和bk成员有效( fd_nextsize和 bk_nextsize在large chunk时有效)，所以下一个chunk 的 P比特位一定是0，prev_size表示上一个chunk 的大小。由于 bk之后的空间大小可能为0，也就是说一个chunk的大小最小可能是32字节(64位系统）或者16字节(32位系统)，即两个SIZE_SZ的大小加上两个指针的大小。

总结一下glibc如何在malloc_chunk上节省内存。首先，**prev_size仅在上一个chunk为释放状态时才需要，否则它会加入上一个chunk 的user data部分**，节省出一个SIZE_SZ大小的内存。其次，size最后三位由于内存对齐的原因，被用来标记chunk的状态。最后，fd和 bk仅在释放状态下才需要,所以和user data复用,节省了2\*SIZE_SZ大小的内存。fd_nextsize和 bk_nextsize仅在当前chunk为large chunk时才需要，所以在较小的chunk 中并未预留空间，节省了2\*SIZE_SZ大小的内存。

| 机器类型 | 对齐位数 | size_t |
| :------: | :------: | :----: |
|   64位   |    16    |   8    |
|   32位   |    8     |   4    |

一般情况下，物理相邻的两个空闲 chunk 会被合并为一个 chunk 。堆管理器会通过 prev_size 字段以及 size 字段合并两个物理相邻的空闲 chunk 块。如果前一个 chunk 处于使用状态，那么不需要去通过链表串起来，所以当前 chunk 也就不需要 prev_size。当申请的内存大小对 2\*size_t 取余之后比 size_t 小于等于的话就可以用它的下一个 chunk 的 prev_size。

## 三、各类bin

chunk被释放时，glibc会将它们重新组织起来，构成不同的bin链表，当用户再次申请时，就从中寻找合适的 chunk返回用户。不同大小区间的 chunk被划分到不同的 bin中，再加上一种特殊的bin，一共有四种: Fast bin、Small bin、Large bin和 Unsorted bin。这些bin记录在malloc_state结构中。

bins 数组每连续两个 chunk 指针维护一个 bin（即 fd 和 bk ），其结构如下图所示（64位）。其中 small bins 中 chunk 大小已给出。large bins 的每个 bin 中的 chunk 大小在一个范围内。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h8.png?x-oss-process=style/watermark)

## 3.1 fast bin

在实践中，程序申请和释放的堆块往往都比较小，所以glibc对这类bin使用单链表结构，并采用**LIFO(后进先出)**的分配策略。为了加快速度，fast bin里的chunk不会进行合并操作，除非调用malloc_consolidate 函数。所以**下一个chunk的 P始终标记为1**，使其处于使用状态。同一个fast bin里chunk 大小相同，并且在fastbinsY数组里按照从小到大的顺序排列，序号为0的fast bin中容纳的chunk大小为4\*SIZE_SZ字节，随着序号增加，所容纳的chunk递增2\*SIZE_SZ字节。如图所示（以64位系统为例)。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h9.png?x-oss-process=style/watermark)

在内存分配和释放过程中，fast bin 是所有 bin 中操作速度最快的。fast bin chunk大小最大64字节，但是其可以支持的 chunk 的数据空间（除去pre_size、chunk_size）最大为 80 字节。因此**不超过** **0x80** **的内存释放会进入** **fast bin**。除此之外， fastbin 最多可以支持的 bin 的个数为 10 个，从数据空间为 8 字节开始一直到 80 字节。64位：在0x20~0x80之间。32位：在0x10~0x40之间（包含区间边界）。

## 3.2 unsorted bin

一定大小的chunk被释放时，在进入small bin或者large bin之前，会先加人unsorted bin。在实践中，一个被释放的chunk常常很快就会被重新使用，所以将其先加入unsorted bin可以加快分配的速度。unsorted bin使用**循环双链表**结构，并采用**FIFO(先进先出)**的分配策略。unsorted bin **只有** **1** **个**。不同于其他的 bin （包括 fast bin ），在 unsorted bin 中，对 chunk 的**大小并没有限制**，任何大小的 chunk 都可以归属到 unsorted bin 中。如图所示（以64位系统为例)。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h10.png?x-oss-process=style/watermark)

unsorted bin 可以视为空闲 chunk 回归其所属 bin 之前的缓冲区，unsorted bin 中的空闲 chunk 处于乱序状态，主要有两个来源：当一个较大的 chunk 被分割成两半后，如果剩下的部分大于 MINSIZE，就会被放到 unsorted bin 中。释放一个不属于 fast bin 的 chunk，并且该 chunk 不和 top chunk 紧邻时，该 chunk 会被首先放到 unsorted bin 中。

## 3.3 small bin

同一个small bin里chunk 的大小相同，采用循环双链表结构，使用频率介于fast bin和 large bin之间。small bin在bins里居第2到第63位，共62个。根据排序，每个small bin的大小为2*SIZE_SZ*idx( idx表示bins数组的下标)在64位系统下，最小的small chunk为2×8×2=32字节，最大的small chunk为2×8×63=1008字节。small bins 中每个 bin 对应的链表**采用** **FIFO (先进先出)**的规则。如图所示（以64位系统为例)。 

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h11.png?x-oss-process=style/watermark)

由于small bin和 fast bin有重合的部分，所以这些chunk在某些情况下会被加入 small bin 中。

## 3.4 large bin

**采用FIFO(先进先出)**，large bin在 bins里居第64到第126位，共63个，被分成了6组，每组 bin所能容纳的chunk按顺序排成等差数列，公差分别如下。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h12.png?x-oss-process=style/watermark)

32位系统下第一个large bin的chunk最小为512字节,第二个large bin的chunk最小为512+64字节(处于[512,512+64)之间的chunk都属于第一个large bin )，以此类推。64位系统也是一样的，第一个large bin的chunk最小为1024字节，第二个large bin的chunk最小为1024+64字节(处于[1024,1024+64)之间的chunk都属于第一个large bin )，以此类推。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h13.png?x-oss-process=style/watermark)

large bin也是采用双链表结构，里面的chunk从头结点的f指针开始，按大小顺序进行排列。为了加快检索速度，fd_nextsize和 bk_nextsize指针用于指向第一个与自己大小不同的chunk，所以也只有在加入了大小不同的chunk时，这两个指针才会被修改。根据 fd_nextsize 和 bk_nextsize 指针**从大到小**排序。

