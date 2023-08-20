---
title: 堆释放
date: 2023-07-31 14:24:20
tags: [Pwn,heap,Basic Knowledge]
cover: "https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap3cover.jpg"
categories: [Study]
---

堆释放（Heap Release）是将已分配的堆内存返还给操作系统，以供其他部分使用。在C语言中，可以使用free()函数来释放动态分配的内存。堆释放的目的是为了释放无用的内存，避免内存泄漏和内存碎片问题，同时提高内存利用率。

------

# 一、__libc_free

同malloc()函数一样，free()函数实际上是_libc_free()，其定义如下。

```c
void __libc_free(void *mem) {
    mstate    ar_ptr;
    mchunkptr p; //chunk的mem指针  
    void (*hook)(void *, const void *) = atomic_forced_read(__free_hook);//全局变量__free_hook 赋给了局部变量 hook
    if (__builtin_expect(hook != NULL, 0)) {//判断__free_hook是否有值
        (*hook)(mem, RETURN_ADDRESS(0));//有值就当成函数指针使用
        return;
    }
    if (mem == 0) // mem为0,free没有作用
        return;
    p = mem2chunk(mem);// 将mem转换为chunk状态    
    if (chunk_is_mmapped(p)) // 如果该块内存是mmap得到的
    {//mp_.no_dyn_threshold变量标志着是否启用了动态调整阈值机制。如果它为true，则不需要执行后续代码，直接返回即可
        if (!mp_.no_dyn_threshold && chunksize_nomask(p) > mp_.mmap_threshold &&//比较释放内存块p的大小
            chunksize_nomask(p) <= DEFAULT_MMAP_THRESHOLD_MAX &&//MAX此次最大允许动态阈值调整的上限
            !DUMPED_MAIN_ARENA_CHUNK(p)) {//nomask(p)的大小不在规定范围内或没有符合条件的内存块空闲，不会进行后续操作。
            mp_.mmap_threshold = chunksize(p);//符合条件的内存块空闲，就将动态阈值设置为当前内存块大小
            mp_.trim_threshold = 2 * mp_.mmap_threshold;//避免频繁释放和重新分配中产生的内存碎片
            LIBC_PROBE(memory_mallopt_free_dyn_thresholds, 2,//调用LIBC_PROBE()函数触发性能事件通知
                       mp_.mmap_threshold, mp_.trim_threshold);
        }//此代码段用于启用和更新内存分配器的动态阈值机制，并触发有关性能和状态的事件通知
        munmap_chunk(p);//就调用munmap释放它
        return;
    }    
    ar_ptr = arena_for_chunk(p);// 根据chunk获得分配区的指针    
    _int_free(ar_ptr, p, 0);// 执行释放
}
```

这里主要关注\_\_free_hook和\_int_free函数，free_hook函数在后续溢出get_shell的时候会遇到，_int_free则是后续执行free的主体。

------

# 二、_int_free

首先定义一系列所需的变量。

```c
static void _int_free (mstate av, mchunkptr p, int have_lock) {
  INTERNAL_SIZE_T size;        /* 释放的chunk的size */
  mfastbinptr *fb;             /* 对应的fastbin */
  mchunkptr nextchunk;         /* 内存空间中下一个chunk */
  INTERNAL_SIZE_T nextsize;    /* 下一个chunk的大小 */
  int nextinuse;               /* 下一个chunk是否在使用 */
  INTERNAL_SIZE_T prevsize;    /* 内存空间中上一个chunk */
  mchunkptr bck;               /* 用于储存bin链表指针 */
  mchunkptr fwd;               /* 用于储存bin链表指针 */

  const char *errstr = NULL;   /* 保存错误的指针 */
  int locked = 0;              /* 初始化locked */
  size = chunksize (p);        /*获取chunk的size */
```

对chunk做—些检查。

```c
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0) || __builtin_expect (misaligned_chunk (p), 0)) {
    errstr = "free(): invalid pointer";//指针不能指向非法的地址, 指针必须得对齐
  errout:
    if (!have_lock && locked)//在当前尚未获取锁但是之前已经加过锁时
      (void) mutex_unlock (&av->mutex);//解锁
    malloc_printerr (check_action, errstr, chunk2mem (p), av);//打印错误信息
    return;
  }
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size))) {//chunk的大小必须大于等于MINSIZE且对齐
    errstr = "free(): invalid size";
    goto errout;//打印错误信息
  }
  check_inuse_chunk(av, p);//检查该chunk是否处于使用状态
```

然后，判断该chunk是否在fast bin范围内，如果是，就插入到fast bin中。

```c
  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())
#if TRIM_FASTBINS//默认 #define TRIM_FASTBINS 0，因此默认情况下下面的语句不会执行    
   && (chunk_at_offset(p, size) != av->top)//不会将靠近top chunk的fast bin删掉
#endif
 ){//当前free的chunk属于fastbin   
    if (__builtin_expect (// 下一个chunk的大小不能小于两倍的SIZE_SZ
		chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0) || 
		__builtin_expect (//下一个chunk的大小不能大于system_mem
			chunksize (chunk_at_offset (p, size)) >= av->system_mem, 0)) {
	    if (have_lock || ({ //如果已经获取锁
			assert (locked == 0); //还未加锁
			mutex_lock(&av->mutex);//加锁
			locked = 1;//将locked设置为1以表示此时Arena被锁定
			chunk_at_offset (p, size)->size <= 2 * SIZE_SZ || //chunk大小不合法
				chunksize (chunk_at_offset (p, size)) >= av->system_mem;
		  })) {
	      errstr = "free(): invalid next size (fast)";
	      goto errout;//打印错误信息
	    }
	    if (! have_lock) {//未被锁定且当前线程已获取了该链表所对应的锁
	      (void)mutex_unlock(&av->mutex);//释放分配区的锁
	      locked = 0;//将locked设置为0以表示此时Arena未被锁定
	    }
    }
    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);//将chunk的mem部分全部设置为perturb_byte
    set_fastchunks(av);//设置fast chunk的标记位
    unsigned int idx = fastbin_index(size);// 根据大小获取fast bin的索引
    fb = &fastbin (av, idx);// 获取对应fastbin的头指针，被初始化后为NULL
    mchunkptr old = *fb, old2;// 执行 *fb 语句获取当前空闲链表指针的值，并将其赋值给 old2 变量
    unsigned int old_idx = ~0u;//声明并初始化一个名为 old_idx 的 unsigned int 类型局部变量
    do {
	    if (__builtin_expect (old == p, 0)) {// 防止对 fast bin double free
	      errstr = "double free or corruption (fasttop)";
	      goto errout;//打印错误信息
	    }
	    if (have_lock && old != NULL)//如果当前线程持有锁并且链表不为空
	      old_idx = fastbin_index(chunksize(old));//计算所处空闲链表索
	    p->fd = old2 = old;//将当前释放的内存块 p 插入到链表头部
    } while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2)) != old2);//操作失败则需要重复操作直至成功
    if (have_lock && old != NULL && __builtin_expect (old_idx != idx, 0)) {// 确保fast bin的加入前与加入后相同
	    errstr = "invalid fastbin entry (free)";//如果当前线程持有锁并且链表不为空且没有正确插入
	    goto errout;
    }
  } 
```

如果该chunk并非mmap()生成的，就需要进行合并。先向后合并，再向前合并。在没有锁的情况下，先获得锁，然后确认该chunk可以合并。

```c
	else if (!chunk_is_mmapped(p)) 
	{//不属于fast chunk且当前free的chunk不是通过mmap分配的		  
      if (! have_lock) {//并且当前还没有获得分配区的锁
        (void)mutex_lock(&av->mutex);//获取分配区的锁 
         locked = 1;//将locked设置为1以表示此时Arena被锁定
    }		
    nextchunk = chunk_at_offset(p, size);//获取下一块chunk的地址
    if (__glibc_unlikely (p == av->top)) {//free的是top chunk     
	    errstr = "double free or corruption (top)";
	    goto errout;//打印错误信息
    }
    if (__builtin_expect (contiguous (av) && //当前free的chunk的下一个chunk不能超过arena的边界
		 (char *) nextchunk >= ((char *) av->top + chunksize(av->top)), 0)) {    
	    errstr = "double free or corruption (out)";
	    goto errout;//打印错误信息
    }
    if (__glibc_unlikely (!prev_inuse(nextchunk))) {//该chunk已经是free状态      
	    errstr = "double free or corruption (!prev)";
	    goto errout;//打印错误信息
    }
    nextsize = chunksize(nextchunk);//获取下一个chunk的大小		
    if (__builtin_expect (nextchunk->size <= 2 * SIZE_SZ, 0) || //查看下一个相邻的chunk的大小是否合法
		__builtin_expect (nextsize >= av->system_mem, 0)) {//或是否大于分配区所分配的内存总量     
	    errstr = "free(): invalid next size (normal)";
	    goto errout;//打印错误信息
    }
    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);//将指针的mem部分全部设置为perturb_byte
```

之后进行合并。向后合并、向前合并、unlink单独介绍。如果合并后的 chunk 的大小大于FASTBIN_CONSOLIDATION_THRESHOLD，那就向系统返还内存。一般合并到 top chunk 都会执行这部分代码。

```c
    if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) 
	{//当前free的chunk不属于fastbin   
      if (have_fastchunks(av))// 如果有 fast chunk 
	      malloc_consolidate(av);//就用malloc_consolidate进行合并
      if (av == &main_arena) {//chunk主分配区
#ifndef MORECORE_CANNOT_TRIM//如果定义了该宏，则表示不支持在 main arena 上进行 heap 内存的收缩操作
	      if ((unsigned long)(chunksize(av->top)) >= (unsigned long)(mp_.trim_threshold))
          //如果当前分配区为主分配区且top chunk的大小大于heap的收缩阈值,调用systrim函数收缩heap
	        systrim(mp_.top_pad, av);
#endif
      } else {//为非主分配区,调用heap_trim函数收缩非主分配区的sub_heap        
	      heap_info *heap = heap_for_ptr(top(av));//通过top获取 heap 的地址
	      assert(heap->ar_ptr == av);//确保 ar_ptr指向正确 
	      heap_trim(heap, mp_.top_pad);//heap空间的收缩操作
      }
    }
    if (! have_lock) {//未被锁定且当前线程已获取了该链表所对应的锁    
      assert (locked);
      (void)mutex_unlock(&av->mutex);//释放分配区的锁
    }
  } else {//否则调用munma_chunk释放    
      munmap_chunk (p);
  }
}
```

## **整体流程：**

①如果在 fastbin 范围则加入到 fast bin 头部并返回。否则转下一步。

②如果不是 mmap 申请的内存，就进行合并。先向后合并，再向前合并。

③如果合并后的 chunk 的大小大于FASTBIN_CONSOLIDATION_THRESHOLD 就向系统返还内存。否则调用munmap_chunk 释放 chunk。

------

# 三、unlink

unlink在合并和切割remainder时会用到。先介绍unlink，基础unlink代码如下：

```c
unlink_chunk (mstate av, mchunkptr p)
{
  if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))//检查当前size和nextchunk的prevsize是否相同
    malloc_printerr ("corrupted size vs. prev_size");
  FD = p->fd;//获取p的下一个空闲块指针
  BK = p->bk;//获取p的上一个空闲块指针
  if (__builtin_expect (FD->bk != p || BK->fd != p, 0))//检查下一个chunk的bk指针和上一个chunk的fd指针是否指向p
    malloc_printerr ("corrupted double-linked list");
  FD->bk = BK;//将下一个chunk的bk指针指向上一个chunk
  BK->fd = FD;//将上一个chunk的fd指针指向下一个chunk
```

1、首先，检查当前内存块 P 的大小与下一个内存块的 prev_size 是否一致。如果不一致，表示堆数据结构出现了错误。

2、保存当前内存块 P 的前驱和后继节点的指针到 BK 和 FD 变量中。

3、检查前驱节点的 bk 指针和后继节点的 fd 指针是否正确指向当前内存块 P。如果不正确，表示双向链表的链接关系出现了错误。

4、如果前驱和后继节点的链接关系正确，就将前驱节点的 bk 指针指向后继节点，后继节点的 fd 指针指向前驱节点。即将当前内存块 P 从双向链表中移除。

如图所示：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h17.png?x-oss-process=style/watermark)

剩余代码如下:

```c
  if (!in_smallbin_range (chunksize_nomask (p)) && p->fd_nextsize != NULL)//如果当前内存块 P 为large chunk。
    {
      if (p->fd_nextsize->bk_nextsize != p //检查p的下一个大小不同的空闲chunk的bk_nextsize指针是否指向p
          || p->bk_nextsize->fd_nextsize != p)//检查p的上一个大小不同的空闲chunk的fd_nextsize指针是否指向p
        malloc_printerr ("corrupted double-linked list (not small)");
      if (FD->fd_nextsize == NULL)//判断下一个chunk是否为lagre chunk（只有p在lagre bin）
        {
          if (p->fd_nextsize == p)//如果p的fd_nextsiz指向自己（large bin只有一个large chunk）
            FD->fd_nextsize = FD->bk_nextsize = FD;//将下一个空闲块fd_nextsize、bk_nextsize都指向它本身
          else
            {
              FD->fd_nextsize = p->fd_nextsize;//将下一个chunk的fd_nextsize指向p的fd_nextsize
              FD->bk_nextsize = p->bk_nextsize;//将下一个chunk的bk_nextsize指向p的fd_nextsize
              p->fd_nextsize->bk_nextsize = FD;//将p的下一块大小不同的chunk的bk_nextsize指向下一块chunk
              p->bk_nextsize->fd_nextsize = FD;//将p的上一块大小不同的chunk的fd_nextsize指向p的下一块chunk
            }
        }
      else
        {                                              //在lagre bin链条上
          p->fd_nextsize->bk_nextsize = p->bk_nextsize;//将p的下一块chunk的bk_nextsize指向p的上一块chunk
          p->bk_nextsize->fd_nextsize = p->fd_nextsize;//将p的上一块chunk的fd_nextsize指向p的下一块chunk
        }
    }
}
```

5、判断它是否在large bin的链表中。即当前内存块 P 不属于小型内存块范围（in_smallbin_range），并且具有 fd_nextsize 指针。在的话转到第6步，不在就结束程序。

6、检查 P 的fd_nextsize、bk_nextsize是否正确链接到前后节点。如果不正确，表示大型large bin的链接关系出现错误。

7、判断下一个chunk的fd_nextsize是否为空。即判断P是否是当前链表中的唯一一个在large bin中的空闲块。如果不是，转到第10步。

8、判断p的下一个大小不同的空闲块是否指向自身，即判断是否是large bin中唯一一个chunk。如果是，将下一个空闲块fd_nextsize、bk_nextsize都指向它本身，即重新初始化large bin。

9、否则，将下一个空闲块fd_nextsize、bk_nextsize指向p的fd_nextsize、bk_nextsize，将lagre bin上p的前后节点都指向下一个空闲块。(使p的下一块chunk替代p)

10、将前驱节点的 bk_nextsize 指针指向后继节点，后继节点的 fd_nextsize 指针指向前驱节点。即将当前内存块 P 从large bin中移除。

------

# 四、向后合并

合并**低地址处**相邻的chunk，会先更新 p 的 size 以及指向，然后调用 unlink() 宏将 chunk 从其链接的 bin 中脱链。代码如下：

```c
if (!prev_inuse(p)) {
	prevsize = p->prev_size;//获取前一块的size
    size += prevsize;//更新size
    p = chunk_at_offset(p, -((long) prevsize));//获得前一块chunk的指针，更新p
    unlink(av, p, bck, fwd);//脱链
}
```

①检查当前chunk的前一块chunk是否是free（检查p的previnuse位是否为0）（如果空闲就返回为真，进行向后合并)

②获取前一块chunk的size，并更新size

③通过减p->prev_size来获得指向前一块chunk的指针，chunk_at_offset将p+size这段内存强制看成一个chunk结构体。

④把p指向的块进行脱链，也就是前一块chunk进行unlink

如图所示：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h18.png?x-oss-process=style/watermark)

在这里值得注意的是，这里的size是一个变量，P->size并没有发生改变；其次chunk_at_offset只是返回一个地址（指针），即只是P的指向改变了，其它内存布局都没有变。后续会在向前合并中，通过set_head来改变内存布局（一定会发生）。

------

# 五、向前合并

合并**高地址**处相邻的chunk。**如果向前相邻** **top_chunk****，则直接合并到** **top_chunk****。**

```c
if (nextchunk != av->top) {
	...
 }
else {
	size += nextsize;//更新size
	set_head(p, size | PREV_INUSE);//设置状态位P为1
	av->top = p;//更新p
	check_chunk(av, p);
}
```

该操作会将size加上top chunk的size，通过set_head将p、size和状态位设置到内存块头部（top chunk的PREV_INUSE始终为1），然后将top chunk指针指向p。

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h19.png?x-oss-process=style/watermark)

**如果向前不相邻** **top_chunk，则尝试向前合并后插入到 unsorted_bin**

```c
if (nextchunk != av->top) {
	nextinuse = inuse_bit_at_offset(nextchunk, nextsize);//检测nextchunk是否已经free
	if (!nextinuse) {
		unlink(av, nextchunk, bck, fwd);//是的话就将nextchunk脱链
		size += nextsize;//更新size
	}
	else
		clear_inuse_bit_at_offset(nextchunk, 0);//没有free的就修改nextchunk状态位P为0
	bck = unsorted_chunks(av);//获取unsorted_bin指针
	fwd = bck->fd;//下一个bin指针
	if (__glibc_unlikely (fwd->bk != bck))//判断unsorted是否被破坏
		malloc_printerr ("free(): corrupted unsorted chunks");
	p->fd = fwd;//修改p的指针
	p->bk = bck;
	if (!in_smallbin_range(size)){//是large_bin就设置fd_nextsize、bk_nextsize
		p->fd_nextsize = NULL;
        p->bk_nextsize = NULL;
    }
    bck->fd = p;//双向链，unsorted指针指向p
    fwd->bk = p;
    set_head(p, size | PREV_INUSE);//将size以及状态位设置到内存块头部
    set_foot(p, size);//size检查，也就是内存完整性检查
 	check_free_chunk(av, p);
 }
```

检测nextchunk是否free，是通过inuse_bit_at_offset(nextchunk, nextsize)来获得nextchunk的相邻下一块chunk的的PREV_INUSE（P）位实现的。P为 0就表示已经被free，就进入unlink流程。如果nextchunk不是free，就修改nextchunk的PREV_INUSE（P）为0，表示当前chunk是free的。

执行前：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h20.png?x-oss-process=style/watermark)

执行后：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h21.png?x-oss-process=style/watermark)

如果可以向前合并就合并，不论是否合并，都会将其插入到unsorted_bin中，然后执行set_head和set_foot，来重设chunk。
