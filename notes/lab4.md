# Lab4: Address Space

Address Space是现代操作系统中的一个重要机制。通过在代码和物理内存之间添加抽象层，它将开发人员从痛苦的内存安排工作中解放出来，帮助他们更多地关注代码而不是硬件。

下图概述了Address Space工作原理：

![](https://rcore-os.github.io/rCore-Tutorial-Book-v3/_images/address-translation.png)

启用后Address Space，代码只能看到Virtual Address. 如果一个进程想要访问任何地址virt_addr，都会首先Physical Address由CPU的MMU模块根据进程的页表进行转换。

## 0x00 Hardware supports for Multilevel Paging in RISCV

MMU 默认情况下是禁用的，因此以前任何程序都可以访问任何物理内存。我们可以通过设置一个名为 的寄存器来启用 MMU satp：

![](https://rcore-os.github.io/rCore-Tutorial-Book-v3/_images/satp.png)

上图展示了中位的含义satp：

MODE控制 MMU 如何转换地址。当MODE= 0 时，MMU 被禁用，当“MODE”= 8 时，MMU 使用页表机制来转换地址。

ASID通过 id 来识别地址空间，因为我们还没有实现进程，但我们只是忽略它。

PPN是根页表项的物理页号。

页表机制下的地址格式由两部分组成：页号和偏移量：

![](https://rcore-os.github.io/rCore-Tutorial-Book-v3/_images/sv39-va-pa.png)

每个页表项由3级虚拟页号（vpn）和几个标志位组成：

![](https://rcore-os.github.io/rCore-Tutorial-Book-v3/_images/sv39-pte.png)

有了这些知识我们就可以很容易理解MMU是如何翻译虚拟内存地址的：

![](https://rcore-os.github.io/rCore-Tutorial-Book-v3/_images/sv39-full.png)

### TLB

sfence.vmaTLB（翻译后备缓冲区）的工作方式类似于某些类型的缓存，请注意，在更改或任何页表条目后，我们必须使用指令来刷新它satp。

## 0x01 Address Space of Kernel and User

启用后satp，内核和用户应用程序的内存是分离的，我们需要仔细处理不同地址空间之间的交互。在 rCore 中，设计者使用 aTrampoline来桥接内核和用户模式应用程序：

![](https://rcore-os.github.io/rCore-Tutorial-Book-v3/_images/kernel-as-high.png)

每个用户空间和内核空间的虚拟地址Trampoline完全相同。guard page请注意，内核堆栈之间存在一个。hole对地址空间中的这些进行了设置，以防止内核堆栈中的缓冲区溢出损坏。

内核的地址空间如下图所示：

![](https://rcore-os.github.io/rCore-Tutorial-Book-v3/_images/kernel-as-low.png)

这里的权限对于系统安全至关重要：没有页表可以同时可写和可执行。此外，我们在这里使用相同的映射，因此内核可以轻松地读/写任何用户空间内存。

在用户模式下，地址空间是我们非常熟悉的：

![](https://rcore-os.github.io/rCore-Tutorial-Book-v3/_images/app-as-full.png)

我们将其放置TrapContext在Trampoline.

## 0x02 Multi-tasking with Address Space

__all_traps 和 trap_return 应该负责地址空间切换。请注意，对于每个任务，我们应该将其 TaskContext 的初始值设置ra为 trap_return。我们没有ra第一次推送内核堆栈来运行任务，所以我们必须手动处理这个问题。

调用syscall堆栈是：

```
syscall: user space ecall -> __all_traps(trampoline) -> trap_handler -> do syscall -> trap_return -> __restore -> user space
```

The `switch` process is:

```
switch: user space -> Interrupt::SupervisorTimer/yield -> __all_traps(trampoline) -> trap_handler -> set_next_trigger&&suspend_current_and_run_next -> schedule -> __switch(change kernel stack) -> trap_return -> __restore -> user space
```

```rust
// os/src/syscall/process.rs

pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    let len = size_of::<TimeVal>();
    let mut ts_buffers = translated_byte_buffers(current_user_token(), ts.cast(), len);
    // At least one buf
    if ts_buffers.len() <= 0 {
        return -1;
    }
    let us = get_time_us();
    let ts: *mut TimeVal = ts_buffers[0].as_mut_ptr().cast();
    unsafe {
        *ts = TimeVal {
            sec: us / 1_000_000,
            usec: us % 1_000_000,
        };
    }
    0
}
```

```rust
// os/src/syscall/memory.rs

use crate::config::PAGE_SIZE;
use crate::mm::{
    PageTable,
    VirtAddr, 
    MapPermission,
    VPNRange,
};
use crate::task::{
    current_user_token, 
    current_memory_set_mmap, 
    current_memory_set_munmap,
    current_id,
};

pub fn sys_mmap(start: usize, len: usize, prot: usize) -> isize {
    if (start & (PAGE_SIZE - 1)) != 0 
        || (prot & !0x7) != 0
        || (prot & 0x7) == 0 {
        return -1;
    }

    let len = ( (len + PAGE_SIZE - 1) / PAGE_SIZE ) * PAGE_SIZE;
    let start_vpn =  VirtAddr::from(start).floor();
    let end_vpn =  VirtAddr::from(start + len).ceil();
    
    let page_table_user = PageTable::from_token(current_user_token());
    // make sure there are no mapped pages in [start..start+len)
    for vpn in VPNRange::new(start_vpn, end_vpn) {
        if let Some(_) = page_table_user.translate(vpn) {
            return -1;
        }
    }
    let mut map_perm = MapPermission::U;
    if (prot & 0x1) != 0 {
        map_perm |= MapPermission::R;
    }
    if (prot & 0x2) !=0 {
        map_perm |= MapPermission::W;
    }
    if (prot & 0x4) !=0 {
        map_perm |= MapPermission::X;
    }

    match current_memory_set_mmap(
        VirtAddr::from(start), 
        VirtAddr::from(start + len), 
        map_perm) {
            Ok(_) => 0,
            Err(e) => {
                error!("[Kernel]: mmap error {}, task id={}", e, current_id());
                -1
            }
    }
}

pub fn sys_munmap(start: usize, len: usize) -> isize {
    if (start & (PAGE_SIZE - 1)) != 0 {
        return -1;
    }

    let len = ( (len + PAGE_SIZE - 1) / PAGE_SIZE ) * PAGE_SIZE;
    let start_vpn =  VirtAddr::from(start).floor();
    let end_vpn =  VirtAddr::from(start + len).ceil();

    let page_table_user = PageTable::from_token(current_user_token());
    // make sure there are no unmapped pages in [start..start+len)
    for vpn in VPNRange::new(start_vpn, end_vpn) {
        if let None = page_table_user.translate(vpn) {
            return -1;
        }
    }
    
    current_memory_set_munmap( VirtAddr::from(start), VirtAddr::from(start + len))
}
```
