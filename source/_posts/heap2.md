---
title: 堆分配
date: 2023-07-29 19:42:22
tags: [Pwn,heap,Basic Knowledge]
cover: "https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap2cover.jpg"
categories: [Study]
---

堆分配（Heap Allocation）是一种内存分配方式，它允许程序在运行时动态分配和释放内存。与静态内存分配方式不同，堆分配不需要在编译时确定内存分配的大小，而是可以在程序运行时根据需要动态地分配和回收内存。在堆分配中，内存被划分为一系列大小不同的堆块。当程序需要动态分配内存时，可以使用堆管理器（Heap Manager）来分配一个适当大小的堆块，以满足程序的需求。当程序不再需要分配的内存时，可以请求堆管理器释放该内存。

# 一、堆初始化

在第一次调用malloc的时候，此时内存中各个bin还未初始化。系统会先执行**__libc_malloc**函数，该函数首先会发现当前fast bin为空，就转交给small bin处理，进而又发现small bin 也为空，就调用malloc_consolidate函数对malloc_state结构体进行初始化。

## 1.1 __libc_malloc

__libc_malloc 是内存分配的底层函数，它可以直接在堆上分配指定大小的内存块。

```c
void *__libc_malloc (size_t bytes)
{
	mstate ar_ptr;
	void *victim;
	void *(*hook) (size_t, const void *)// 判断__malloc_hook中是否有值，有值就当成函数指针调用 
		= atomic_forced_read (__malloc_hook);
	if (__builtin_expect (hook != NULL, 0))
		return (*hook)(bytes, RETURN_ADDRESS (0));
	arena_get (ar_ptr, bytes);// 获取分配区指针，并锁住分配区内存
	victim = _int_malloc (ar_ptr, bytes);//分配内存
	if (!victim && ar_ptr != NULL)// 内存分配失败，尝试寻找其他可用的arena进行分配 
	{
		LIBC_PROBE (memory_malloc_retry, 1, bytes);
		ar_ptr = arena_get_retry (ar_ptr, bytes);
		victim = _int_malloc (ar_ptr, bytes);
	}
	if (ar_ptr != NULL)//解除分配区内存锁
		(void) mutex_unlock (&ar_ptr->mutex);
	assert (!victim || chunk_is_mmapped (mem2chunk (victim)) || //mem2chunk,根据 mem 地址得到 chunk 地址
	ar_ptr == arena_for_chunk (mem2chunk (victim)));//通过倒数第二个比特位判断内存属性 
	return victim;
}
```

程序第一次运行\_\_libc_malloc时，\_\_malloc_hook中的值是hook.c中的malloc_hook_ini函数（如下图），因此会调用该函数，用于对\_\_malloc_hook进行初始化，初始化结束后值为NULL，然后回调\_\_libc_malloc。

```c
void *weak_variable (*__malloc_hook) //hook是一个函数指针变量，被赋值成了__malloc_hook
  (size_t __size, const void *) = malloc_hook_ini;

static void *
malloc_hook_ini (size_t sz, const void *caller)
{//保证在多次调用__libc_malloc的情况下，代码中的hook回调函数只会被调用一次
	__malloc_hook = NULL;			//将__malloc_hook置0
	ptmalloc_init ();				//初始化ptmalloc
	return __libc_malloc (sz);		//回到__libc_malloc
}
```

紧接着对管理器会调用arena_get 获取到管理空闲空间的分配区地址，然后调用\_int_malloc分配内存。其中**_int_malloc**是内存分配的核心函数，将在堆分配章节介绍。

## 1.2 malloc_consolidate

在分配了一些初始内存块后，可能会存在一些相邻的空闲块。为了提高内存的利用效率，malloc_consolidate 函数会对这些相邻的空闲块进行合并，以形成更大的连续可用空间。因此，malloc_consolidate 通常会在 __libc_malloc 执行后被调用，以优化堆的内存布局。

malloc_consolidate() 函数是定义在 malloc.c 中的一个函数，用于将 fastbin 中的空闲 chunk 合并整理到 unsorted_bin 中以及进行**初始化堆**的工作，在 malloc() 以及 free() 中均有可能调用 malloc_consolidate() 函数。

```c
if (get_max_fast ( != 0){
	...
}
else {
	malloc_init_state(av); //堆初始化
	check_malloc_state(av);
}
```

如代码所示，进入 malloc_consolidate()，当进程第一次调用 malloc() 申请分配的时候，get_max_fast() 返回值等于 0。

首先通过 get_max_fast()判断当前malloc_state结构体中的fast bin是否为空，如果为空就说明整个malloc_state都没有完成初始化，需要对malloc_state进行初始化。malloc_state的初始化操作由函数malloc_init_state(av)完成，该函数先初始化除fast bin之外的所有的bins，再初始化fast bins。在初次初始化完成时，unsorted bin是空的。

```c
static void malloc_init_state(mstate av) {
    int i;
    mbinptr bin;
	//对每个bin进行初始化操作
    for (i = 1; i < NBINS; ++i) {//遍历bins中的每个bin
        bin = bin_at (av, i);
        bin->fd = bin->bk = bin;//将fd和bk指针指向对应的bin
    }
#if MORECORE_CONTIGUOUS
    if (av != &main_arena)
#endif
    set_noncontiguous(av);
    if (av == &main_arena)
        set_max_fast(DEFAULT_MXFAST);//设置对应的fast chunk的尺寸
    av->flags |= FASTCHUNKS_BIT;//设置arena的flags字段表明初始化了fastbins
    av->top = initial_top (av);//用initial_top初始化top chunk
}
```

如果 get_max_fast() 返回值不等于 0，说明堆已经初始化，就会**清空** **fastbin**，将 fastbin 中的每一个 chunk 合并整理到 unsorted_bin 或 top_chunk。

**malloc_consolidate总体流程如下**：

1. 若 get_max_fast() 返回 0，则进行堆的初始化工作，然后进入第 7 步
2. 从 fastbin 中获取一个空闲 chunk
3. 尝试向后合并 前一个chunk非free的，不会发生向后合并操作
4. 若向前相邻 top_chunk，则直接合并到 top_chunk，然后进入第 6 步
5. 否则尝试向前合并后，插入到 unsorted_bin 中
6. 获取下一个空闲 chunk，回到第 2 步，直到所有 fastbin 清空后进入第 7 步
7. 退出函数

**流程图：**

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h14.png?x-oss-process=style/watermark)

malloc_consolidate()了解到这里就可以了。这里提到的向后合并和向前合并将在另一篇[堆释放](https://wutong01304.github.io/2023/07/31/heap3/)进行介绍。

------

# 二、堆分配

## 2.1 代码分析

**_int_malloc**是内存分配的核心函数，总结在末尾，以下是代码分析： 

```c
static void *
_int_malloc (mstate av, size_t bytes)
{
  INTERNAL_SIZE_T nb;               /* 对齐后的所需内存大小 */
  unsigned int idx;                 /* 保存所需chunk在bins中的下标 *//
  mbinptr bin;                      /* 保存bin */
  mchunkptr victim;                 /* 保存chunk */
  INTERNAL_SIZE_T size;             /* 保存chunk的size */
  int victim_index;                 /* 保存chunk在bins中的下标 */
  mchunkptr remainder;              /* 保存chunk分配内存后剩余内存的指针 */
  unsigned long remainder_size;     /* 保存剩余部分内存大小 */
  unsigned int block;               /* 已分配内存块的块 */
  unsigned int bit;                 /* 二进制映射指针 */
  unsigned int map;                 /* 二进制映射的当前字 */
  mchunkptr fwd;                    /* 保存chunk的fd指针 */
  mchunkptr bck;                    /* 保存chunk的bk指针 */

  const char *errstr = NULL;        /* 保存错误的指针 */
  checked_request2size (bytes, nb); /* 取得对齐后的size值 */
```

首先定义一系列所需的变量，checked_request2size (bytes, nb)将申请的字节数bytes根据2*SIZE_SZ对齐转换成实际分配的字节数nb，并做了一些安全检查，确保不会溢出。

如果没有合适的arena，就调用sysmalloc，用mmap分配chunk并返回。

```c
//如果没有合适的arena，就调用sysmalloc，用mmap分配chunk并返回。
  if (__glibc_unlikely (av == NULL))//av是__libc_malloc中调用arena_get获得的分配区指针
    {//如果为null，就表示没有分配区可用
      void *p = sysmalloc (nb, av);//调用sysmalloc通过mmap获取chunk
      if (p != NULL)
         alloc_perturb (p, bytes);//对分配的内存块进行初始化操作。
      return p;
    }
```

其次，检查fastbin中是否有合适的chunk。如果需要分配的内存大小nb落在fastbin的范围内,那么尝试从 fast bins 中分配 chunk

```c
//如果需要分配的内存大小nb落在fastbin的范围内,那么尝试从 fast bins 中 分配 chunk 
  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {//get_max_fast返回fastbin可以存储内存的最大值，它在ptmalloc的初始化函数malloc_init_state中定义。
      idx = fastbin_index (nb);//获取fastbin索引
      mfastbinptr *fb = &fastbin (av, idx);//根据idx获取对应链表的头指针    
      mchunkptr pp = *fb;//获取对应大小的fatbin的链表中的第一个空闲的chunk
      do
        {//将链表的第一个chunk作为victim取出，插入时也插入在链表头，即LIFO
          victim = pp;//victim是我们取出的chunk的地址
          if (victim == NULL)
            break;
        }//pp  == victim 导致循环退出
      while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))
             != victim);//catomic_compare将链表头设置为该空闲chunk的下一个chunk(victim->fd)
      if (victim != 0)
	  {
          if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))//检查索引和size是否正确
		  {
              errstr = "malloc(): memory corruption (fast)";
            errout:
              malloc_printerr (check_action, errstr, chunk2mem (victim), av);//打印错误信息。
              return NULL;
		  }
          check_remalloced_chunk (av, victim, nb);//检查分配的内存块是否有效
          void *p = chunk2mem (victim);//把chunk的指针转换成mem的指针
          alloc_perturb (p, bytes);//对分配的内存块进行初始化
          return p;
        }
    }
```

然后，检查small bin中是否有合适的chunk。

```c
 if (in_smallbin_range (nb))//如果 nb 属于 smallbins
    {
      idx = smallbin_index (nb);//获得索引
      bin = bin_at (av, idx);//通过idx获取对应的small bin链表表头指针
      if ((victim = last (bin)) != bin)// 获取对应链表的最后一个chunk,
      {//如果victim等于表头，表示该链表为空，跳过下面部分
          if (victim == 0) //victim为0表示smallbin还未初始化
            malloc_consolidate (av);//调用malloc_consolidate完成初始化操作
          else
            {
             bck = victim->bk;//获取此chunk的上一个chunk的地址             
    	     if (__glibc_unlikely (bck->fd != victim))             
             {//检查victim上一个chunk的fd是否与victim相等
                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;//打印错误信息
              }
              set_inuse_bit_at_offset (victim, nb);//将下一个相邻的chunk的 inuse bit 为 1             
              bin->bk = bck;//将bin从链表中取出，相当于unlink
              bck->fd = bin;
              if (av != &main_arena)
                victim->size |= NON_MAIN_ARENA;//如果不是主线程则设置NON_MAIN_ARENA位
              check_malloced_chunk (av, victim, nb);//检查分配的内存块是否有效
              void *p = chunk2mem (victim);//将chunk指针转化为mem指针
              alloc_perturb (p, bytes);//对分配的内存块进行初始化
              return p;
            }
        }
    }
```

如果fast bin、small bin都不能满足，就调用malloc_consolidate整理fastbins。

```c
 else//若所需大小不属于small bins，则可能位于large bins中
    {
      idx = largebin_index (nb);//获取对应大小的large bin的索引
      if (have_fastchunks (av))//检查fastbin链表是否为空，
      	 malloc_consolidate (av);//整理 fastbins
    }

```

然后进入一个外层for循环，包含了_int_malloc之后的所有过程。紧接着是内层第一个while循环，遍历unsorted bin中的每一个chunk，如果大小正好合适，就将其取出，否则就将其放入small bin或者large bin。这是唯一将chunk放进small bin或者large bin的过程。

```c
 for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))         
      {//如果链表不为空，则循环遍历 unsorted 所有的chunk
          bck = victim->bk;//获取下一块chunk
          if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0) //判断chunk大小是否合法
				|| __builtin_expect (victim->size > av->system_mem, 0))//如果不合法就打印错误信息
					malloc_printerr (check_action, "malloc(): memory corruption", chunk2mem (victim), av);
		  size = chunksize (victim);     //若合法则取出size位
```

在内层第一个循环内部，当请求的chunk属于smallbin、unsortedbin只有一个chunk为last remainder并且满足拆分条件时，就将其拆分。

```c
          if (in_smallbin_range (nb) && //如果要申请的大小在smallbin范围
              bck == unsorted_chunks (av) && // 且 unsorted chunks 只有一个chunk
              victim == av->last_remainder && //且victim是last_remainder
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))//chunk 的大小可以进行切割
		   {//分割reminder，并将新的reminder插入到unsorted bin中
              remainder_size = size - nb;//计算剩下reminder的大小
              remainder = chunk_at_offset (victim, nb);//获取剩下的reminder的地址
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;//将新的reminder插入到unsorted bin中
              av->last_remainder = remainder;//last_reminder重新指向新的reminder
              remainder->bk = remainder->fd = unsorted_chunks (av);//新reminder的fd与bk指向unsorted bin 的链表头
              if (!in_smallbin_range (remainder_size))
                {//如果新的remind的size不在small bin中，而是在large bin中，则把fd_nextsize,fd_nextsize清零
                  remainder->fd_nextsize = NULL;
                  remainder->bk_nextsize = NULL;
                }  
              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0));//设置victim的chunk头
              set_head (remainder, remainder_size | PREV_INUSE);//设置remainder的chunk头
              set_foot (remainder, remainder_size);//设置remainder的物理相邻的下一个chunk的prev_size
              check_malloced_chunk (av, victim, nb);//检查分配的内存块是否有效
              void *p = chunk2mem (victim);//将chunk指针转化为mem指针
              alloc_perturb (p, bytes);//对分配的内存块进行初始化
              return p;
            }
```

否则，将chunk从unsored bin中移除，如果大小正好合适，就将其返回给用户。

```c
          unsorted_chunks (av)->bk = bck;//将bin从unsortedbin中取出
          bck->fd = unsorted_chunks (av);
          if (size == nb)
            {//如果申请的大小转化后正好等于victim size，直接返回即可
              set_inuse_bit_at_offset (victim, size);//设置victim的下一个chunk的prev_inuse位
              if (av != &main_arena)//如果av不是主进程main_arena 
                victim->size |= NON_MAIN_ARENA;//设置NON_MAIN_ARENA位              
              check_malloced_chunk (av, victim, nb);//检查分配的内存块是否有效
              void *p = chunk2mem (victim);//将chunk指针转化为mem指针
              alloc_perturb (p, bytes);//对分配的内存块进行初始化
              return p;
            }
```

如果chunk大小不合适，就将其插入到对应的bin中（small bin、large bin）。。若large bin不为空，则按顺序插入。当iters大于最大的iters（10000）时，即遍历完unsorted bin，程序退出。到此第一个while内循环结束

```c
          if (in_smallbin_range (size))
            {//若size属于small bins，则将chunk加入到bck和fwd之间，作为small bins的第一个chunk
              victim_index = smallbin_index (size);//获取大小对应的索引
              bck = bin_at (av, victim_index);//通过 bin index 获得 bin 的链表指针
              fwd = bck->fd;//bck->fd 指向下一个chunk（small bin为头插法）
            }
          else
            {//若不在small bin的范围中，则
              victim_index = largebin_index (size);//获取大小对应的索引
              bck = bin_at (av, victim_index);//通过 bin index 获得 bin 的链表指针
              fwd = bck->fd;// fwd指向下一个chunk              
              if (fwd != bck)   //若fwd不等于bck，说明large bins中存在空闲chunk
			   {
					size |= PREV_INUSE;//将 PREV_INUSE 标志的位置设置为1
					assert ((bck->bk->size & NON_MAIN_ARENA) == 0);	//验证之前分配的内存块											  
					if ((unsigned long) (size) < (unsigned long) (bck->bk->size))
					{//如果当前size比最后一个chunk size还要小，则将当前size的chunk加入到chunk size链表尾
						fwd = bck;//fwd指向链表指针bin
						bck = bck->bk;//bck指向链表指针bin的上一个chunk
						victim->fd_nextsize = fwd->fd;//指向链表指针bin的下一个chunk
						victim->bk_nextsize = fwd->fd->bk_nextsize;//指向链表指针bin的下一个chunk的bk_nextsize
						fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;//下一个chunk的指针指向自己
					}
				    else
					{//否则遍历chunk size链表
						assert ((fwd->size & NON_MAIN_ARENA) == 0);	//验证之前分配的内存块
						while ((unsigned long) size < fwd->size)
						{//正向遍历chunk size链表，找到第一个chunk大小小于等于当前大小的chunk
							fwd = fwd->fd_nextsize;
							assert ((fwd->size & NON_MAIN_ARENA) == 0);
						}//若已经存在相同大小的chunk，则将当前chunk插入到同大小chunk链表的尾部 								
						if ((unsigned long) size == (unsigned long) fwd->size)
							fwd = fwd->fd;					
						else
						{// 否则延伸出一个大小等于当前size的chunk链表，将该链表加入到chunk size链表尾
							victim->fd_nextsize = fwd;//fd_nextsize指向下一个chunk
							victim->bk_nextsize = fwd->bk_nextsize;//bk_nextsize指向下一个chunk的bk_nextsize
							fwd->bk_nextsize = victim;//下一个chunk的bk_nextsize指向自己
							victim->bk_nextsize->fd_nextsize = victim;//下一个大小不同的chunk的fd_nextsize指向自己
						}
						bck = fwd->bk;//指向下一个chunk的上一个chunk
					}
				}
              else //large bin为空直接将其加入
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }
    
          mark_bin (av, victim_index);//标记为特定状态
          victim->bk = bck;//当前chunk的bk指针指向链表头
          victim->fd = fwd;//当前chunk的fd指针指向下一块chunk
          fwd->bk = victim;//下一块chunk的bk指针指向当前chunk
          bck->fd = victim;//链表头的fd指针指向当前chunk
          if (++iters >= MAX_ITERS)//遍历完unsorted bin退出
            break;
       }//第一个内循环结束  
```

如果用户申请的chunk是large chunk，就在第一个循环结束后搜索large bin。

```c
      if (!in_smallbin_range (nb))//判断chunk是否位于large bins中
        {
          bin = bin_at (av, idx); //获取bin链表指针             
          if ((victim = first (bin)) != bin &&//如果large bins不为空
              (unsigned long) (victim->size) >= (unsigned long) (nb))//且大小满足
            {
              victim = victim->bk_nextsize;//指向上一个大小不同的chunk
              while (((unsigned long) (size = chunksize (victim)) <
                      (unsigned long) (nb)))//遍历chunk size链表，找到大于等于所需大小的chunk链表
                victim = victim->bk_nextsize;              
              if (victim != last (bin) && victim->size == victim->fd->size)//不是唯一一个large chunk
                victim = victim->fd;//指向victim的下一块chunk，取出chunk
              remainder_size = size - nb;//计算剩余size
              unlink (av, victim, bck, fwd);//然后脱链            
              if (remainder_size < MINSIZE)
                {//若剩余部分小于MIN_SIZE，则将整个chunk分配给非主分配区（内存映射区）
                  set_inuse_bit_at_offset (victim, size);//设置inuse标志位
                  if (av != &main_arena)
                    victim->size |= NON_MAIN_ARENA;////将 NON_MAIN_ARENA 标志设置为1
                }            
              else
                {//否则将剩余部分作为新chunk加入到unsorted bins中
                  remainder = chunk_at_offset (victim, nb);//获取剩余部分指针
                  bck = unsorted_chunks (av);//获取unsorted bin链表指针
                  fwd = bck->fd;//获取下一块unsoted chunk指针
      			  if (__glibc_unlikely (fwd->bk != bck))
                    {//安全检查，如果下一块的上一块不等于链表指针
                      errstr = "malloc(): corrupted unsorted chunks";
                      goto errout;//打印错误信息
                    }
                  remainder->bk = bck;//将 remainder插入到unsoeted bin
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;
                  if (!in_smallbin_range (remainder_size))
                    {//如果remainder大小在large bin中，设置fd_nextsize、bk_nextsize为NULL
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |//设置获取到的chunk头
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
				  //如果av不等于&main_arena，则设置NON_MAIN_ARENA标志，否则设置为0
                  set_head (remainder, remainder_size | PREV_INUSE);//设置remainder的chunk头
                  set_foot (remainder, remainder_size);//设置remainder的下一块chunk的presize
                }
              check_malloced_chunk (av, victim, nb);//检查分配的内存块是否有效
              void *p = chunk2mem (victim);//将chunk指针转化为mem指针
              alloc_perturb (p, bytes);//对分配的内存块进行初始化
              return p;
            }
        }
```

接下来，进入内层第二个for循环。在small bins和large bins中都没有找到大小合适的chunk，尝试从大小比所需大小更大的空闲chunk中寻找合适的。根据binmap来搜索bin，使用binmap主要时为了加快查找空闲chunk的效率，这里只查询比所需chunk大的bin中是否有空闲chunk可用。获取下一个相邻bin的空闲chunk链表，并获取该bin对于binmap中的bit位的值，binmap中标识了相应bin中是否存在空闲chunk，按照block进行管理，每个block为一个int，共32bit，可以表示32个bin中是否存在空闲chunk。

```c
     //获取当前内存块的bin、位图映射和位索引等信息    
      ++idx;//将idx变量增加1
      bin = bin_at (av, idx);//获取bin指针
      block = idx2block (idx);//将当前索引idx转换为块索引
      map = av->binmap[block];//从av分配器的binmap数组中获取指定块索引对应的位图（bitmap）映射
      bit = idx2bit (idx);//将当前索引idx转换为位索引
    
      for (;; )
        {
          if (bit > map || bit == 0)
            {//遍历下一个block，直到找到一个不为0的block或遍历完所有的block 
              do
                {
                  if (++block >= BINMAPSIZE) 
                    goto use_top;
                }//没有找到合适chunk，尝试使用top chunk分配
              while ((map = av->binmap[block]) == 0);    
              bin = bin_at (av, (block << BINMAPSHIFT));//设置bin指向block的第一个bit对应的bin 
              bit = 1;//将bit置为1，表示该block中bit1对应的bin
            }
```

在内层第二个循环内部，找第一个不为空的block，再根据比特位找到合适的bin。然后检查bit对应的bin是否为空，如果是，就清空对应的比特位，从下一个bin开始再次循环，否则将victim从bm中取出来。将取出的victim进行切分并把remainder加人unsorted bin，如果victim不够切分，就直接返回给用户。内层第二个循环到此结束。

```c
          while ((bit & map) == 0)
            {//在block中遍历对应的bin，直到找到一个不为0的bit
              bin = next_bin (bin);
              bit <<= 1;
              assert (bit != 0);
            }    
          victim = last (bin);// 将chunk加入链表尾  
          if (victim == bin)//若victim与bin链表头指针相同，表示该bin中没有空闲chunk
            {//binmap中的相应位设置不准确，将其清零
              av->binmap[block] = map &= ~bit;
              bin = next_bin (bin);
              bit <<= 1;
            }
    
          else
            {
              size = chunksize (victim);//获得size
              assert ((unsigned long) (size) >= (unsigned long) (nb));//判断chunk大小是否满足
              remainder_size = size - nb;//计算分配后的剩余大小
              unlink (av, victim, bck, fwd);//脱链
             if (remainder_size < MINSIZE)
                {//若剩余部分小于MIN_SIZE，则将整个chunk分配给非主分配区（内存映射区）
                  set_inuse_bit_at_offset (victim, size);//设置inuse标志位
                  if (av != &main_arena)
                    victim->size |= NON_MAIN_ARENA;////将 NON_MAIN_ARENA 标志设置为1
                }            
              else
                {//否则将剩余部分作为新chunk加入到unsorted bins中
                  remainder = chunk_at_offset (victim, nb);//获取剩余部分指针
                  bck = unsorted_chunks (av);//获取unsorted bin链表指针
                  fwd = bck->fd;//获取下一块unsoted chunk指针
      			  if (__glibc_unlikely (fwd->bk != bck))
                    {//安全检查，如果下一块的上一块不等于链表指针
                      errstr = "malloc(): corrupted unsorted chunks";
                      goto errout;//打印错误信息
                    }
                  remainder->bk = bck;//将 remainder插入到unsoeted bin
                  remainder->fd = fwd;
                  bck->fd = remainder;
                  fwd->bk = remainder;			  
				  if (in_smallbin_range (nb))//若分配大小属于small bin
					  av->last_remainder = remainder;//将last_remainder设置为剩余部分构成的chunk
                  if (!in_smallbin_range (remainder_size))
                    {//如果remainder大小在large bin中，设置fd_nextsize、bk_nextsize为NULL
                      remainder->fd_nextsize = NULL;
                      remainder->bk_nextsize = NULL;
                    }
                  set_head (victim, nb | PREV_INUSE |//设置获取到的chunk头
                            (av != &main_arena ? NON_MAIN_ARENA : 0));
				  //如果av不等于&main_arena，则设置NON_MAIN_ARENA标志，否则设置为0
                  set_head (remainder, remainder_size | PREV_INUSE);//设置remainder的chunk头
                  set_foot (remainder, remainder_size);//设置remainder的下一块chunk的presize
                }
              check_malloced_chunk (av, victim, nb);//检查分配的内存块是否有效
              void *p = chunk2mem (victim);//将chunk指针转化为mem指针
              alloc_perturb (p, bytes);//对分配的内存块进行初始化
              return p;
            }
        }
```

注意以下代码，即如果找不到合适的chunk，就从top chunk上进行切分。

```c
              do
                {
                  if (++block >= BINMAPSIZE) 
                    goto use_top;
                }//没有找到合适chunk，尝试使用top chunk分配
              while ((map = av->binmap[block]) == 0);    
```

如果top chunk的大小不能满足条件，且fast bins 还有 chunk，就再次调用malloc_consolidate整理fsat bins，此时会重新设置binmap中对应位置的标志位，表示该bin中有可用的空闲块。然后，重新计算索引，回到do while循环（也就是ues_top）。如果fast bins 没有 chunk了，就会调用sysmalloc申请内存。

```c
    use_top:        
      victim = av->top;//获得top chunk指针与大小
      size = chunksize (victim);//获得top chunk大小    
      if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
        {//必须满足top chunk size > nb + MINSIZE的情况下才能分配
          remainder_size = size - nb;//从top chunk分配内存后，剩余的部分将作为新的top chunk
          remainder = chunk_at_offset (victim, nb);//获取剩余内存指针
          av->top = remainder;//修改top指针
          set_head (victim, nb | PREV_INUSE |//设置获取到的chunk头
                    (av != &main_arena ? NON_MAIN_ARENA : 0));
		   //如果av不等于&main_arena，则设置NON_MAIN_ARENA标志，否则设置为0
          set_head (remainder, remainder_size | PREV_INUSE); //设置remainder的chunk头
          check_malloced_chunk (av, victim, nb);//检查分配的内存块是否有效
          void *p = chunk2mem (victim);//将chunk指针转化为mem指针
          alloc_perturb (p, bytes);//对分配的内存块进行初始化
          return p;
        }
      else if (have_fastchunks (av))
        {//若top chunk也无法满足要求，则检查fast bins中是否存在空闲chunk
          malloc_consolidate (av);//整理fast bin
          if (in_smallbin_range (nb))//大小在small bin中
            idx = smallbin_index (nb);//获取small bin的下标idx
          else
            idx = largebin_index (nb);//否则获取large bin的下标
        }     
      else
        {//所有方法都行不通，最后的解决方案是向系统申请一块新的内存 
          void *p = sysmalloc (nb, av);
          if (p != NULL)
            alloc_perturb (p, bytes);//对分配的内存块进行初始化
          return p;
        }
	}
}
```

## 2.2 整体流程

1. 如果 arena 未初始化，则调用 sysmalloc 向系统申请内存，然后返回获取的chunk 
2. 检查fast bins中是否有合适的chunk，如果可以在fast bins中找到一个所需大小的chunk，就从对应的 fast bin 的头部获取 chunk分配给用户，结束程序。否则转到第3步。
3. 判断所需大小是否在small bins中，如果在，就根据所需分配的chunk的大小，找到具体所在的某个small bin，从该bin的尾部摘取一个恰好满足大小的chunk。若成功，则分配结束，否则，转到第4步。
4. 如果fast bin、small bin都不能满足。调用 malloc_consolidate 函数将 fast bin 中的 chunk 合并后放入 unsorted bin。
5. 遍历 unsorted bin 中的 chunk，如果满足条件就分配chunk后返回，否则将根据 chunk 的大小将其放入 small bins 或是 large bins 中，遍历完成后，转入第6步。(第一个大循环)在这个循环里，已经判断了chunk大小是否恰好等于申请的大小，也就是说，如果是属于small bins的申请大小，在这一步就已经成功分配了，没有分配成功则证明大小在large bins范围内。因此下一步只考虑large bins分配。
6. 如果申请chunk的大小在large bins中，就从large bins中按大小顺序找一个合适的chunk，从中划分一块所需大小的chunk，并将剩下的部分链接回到unsorted bins头部。若操作成功，则分配结束，否则转到第7步。
7. 在small bins和large bins中都没有找到大小合适的chunk，尝试从大小比所需大小更大的空闲chunk中寻找合适的。这一步使用binmap优化。如果所有的操作都不满足条件，就调用sysmalloc 向系统申请内存，然后返回给用户。（第二个大循环）

**sysmalloc()函数的大概流程如下。**

- 当申请的大小nb大于mp.mmap_threshold时，通过mmap()函数进行分配。其中mp_.mmap_threshold的默认大小为128×l024字节
- 尝试用brk()扩展堆内存，形成新的top chunk，而旧的top chunk会被释放。然后从新的top chunk中切分出nb大小的chunk，返回给用户

**整体流程图如下：**

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h15.png?x-oss-process=style/watermark)

对第5步和第7步两个循环进行详细介绍如下：

**第一个循环：**

①首先遍历unsorted bins中每一个chunk。 

②如果用户的申请的大小在 small bin 范围内，且当前chunk 是last_remainder，且last_remainder是 unsorted bin中的唯一一个 chunk，且last_remainder可以切割，则从last_reminder中切下一块内存返回。否则，转到下一步。

③将chunk从unsored bin中移除。

④如果该chunk 的大小恰好等于申请的 chunk 大小，就将其返回给用户。如果大小不合适，就转到下一步。

⑤根据 chunk 的大小将其放入 small bin 或 large bin 中。对于 small bin 直接从链表头部加入；对于 large bin，如果链表为空，就直接加入；如果在链表尾部，就直接加入；否则遍历large size的大小，找到大小相同的，就加入该large链的尾部，否则就延伸一个large链表，加入尾部并更新nextsize指针。

⑥如果iters大于设置的MAX_ITERS(10000),就退出循环

流程图：

![](https://wutongblogs.oss-cn-beijing.aliyuncs.com/blogs/heap/h16.png?x-oss-process=style/watermark)

**第二个循环：**

第二个循环是用来找一个 chunk 范围比申请 chunk 大的，即在非空 bin 里面找最后一个 chunk，这个过程用 binmap 优化。

①遍历每一个block，即块索引，也就是遍历每一个空闲chunk，如果没有找到合适chunk，就尝试使用top chunk分配。转到第3步。

②找到合适的chunk，如果不可以切分，就返回整个chunk。如果可以切分，就切分这个 chunk，剩余部分remainder在small bin范围内就放入small bin，否则放入unsorted bin，然后返回获取的 chunk 。

③如果 top chunk 可以切分，就切分后返回chunk，top chunk不能满足要求且fastbins中存在空闲chunk，就调用 malloc_consolidate 合并 fast bin 中的 chunk 并放入 unsorted bin 中，此时会重新设置binmap中对应位置的标志位，然后回到第1步。否则（fastbins中无空闲chunk），使用 sysmalloc 系统调用向操作系统申请内存分配 chunk 。
