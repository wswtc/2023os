
任务的上下文（Context）包括任务在执行过程中需要保存和恢复的状态信息。其中，任务的上文指的是在任务被中断或切换出去之前需要保存的状态信息。

具体来说，任务的上文包括以下内容：

1. 寄存器的值：任务执行过程中使用的寄存器（如通用寄存器、标志寄存器等）的当前值需要保存，以便在任务恢复执行时能够恢复这些寄存器的值。

2. 程序计数器（PC）：PC 指向任务即将执行的下一条指令的地址。在任务切换时，需要保存当前任务的 PC 值，以便在任务再次执行时能够从上次中断的地方继续执行。

3. 栈指针（SP）：栈指针指向当前任务的栈顶位置。任务切换时需要保存当前任务的栈指针，以便在任务再次执行时能够正确恢复任务的栈状态。

4. 其他相关状态：根据具体的系统和架构，可能还需要保存其他与任务执行相关的状态信息，例如特定的硬件寄存器状态、浮点寄存器状态等。

保存任务的上文是为了能够在任务再次执行时恢复到中断或切换出去时的状态，保证任务的连续执行。上文保存在任务的上下文数据结构中，例如任务控制块（Task Control Block，TCB）或上下文切换相关的数据结构中。当任务被调度器切换回来时，调度器会从上下文中恢复任务的上文，使任务能够继续执行。

## sys_time


1、为什么用双端队列


在实验2中，我们实现了一个批处理操作系统，允许用户一次性提交一堆程序，然后只需等待结果。此外，我们进行了一些基本的安全检查，以防止用户程序中的内存故障（或攻击）影响其他程序或操作系统。尽管这大大节省了人力，但与现代操作系统相比仍然相去甚远。

想想现代操作系统的行为：多任务处理（你感觉好像在同时进行许多工作）、实时交互（每次点击或按键都能立即获得响应）、内存管理、I/O 设备管理和网络实用程序。正是这些特性，由复杂的底层机制支持，让我们以一种令人满意和高效的方式操作计算机。在这个实验中，我们将着手解决多任务处理问题，这是朝着我们现代操作系统目标迈出的重要一步。

在单个 CPU 上实现多任务处理的基本思想非常简单：我们为每个任务运行一小段时间，然后切换到下一个任务并重复此过程。如果我们切换得足够快，那么看起来就像我们在同时运行许多程序。

![](https://gitee.com/itewqq/images/raw/master/20220211162803.png)

关键问题：

如何分配程序的内存？ 我们需要在内存中保留任务的上下文（寄存器、栈等），这样当我们切换回来时，一切都像以前一样正常运行。

如何在任务之间进行切换？ 当用户的程序占用 CPU 时，操作系统代码无法运行，因此我们需要从用户程序那里获取这种控制权，而不对它们造成破坏。

如何调度这些任务？ 应该在何时间隔内执行任务切换？如何决定下一个应该运行的任务？

接下来，我们将逐个讨论这些问题。

## 0x00 Multiprogramming in Memory

### Multi-program placement


在第二章中，所有以 ELF 格式的应用可执行文件都通过使用 objcopy 实用程序删除所有 ELF 头和符号，并且通过将应用程序直接链接到内核数据段来转换为二进制映像，该过程在编译时通过将 link_user.S 文件以相同格式嵌入到操作系统内核中完成。不同之处在于我们已经调整了相关模块：在第二章中，应用加载和执行进度控制都交给了 batch 子模块，而在第三章中，我们将功能中的应用加载部分独立为 loader 子模块，将应用程序的执行和切换功能交给了 task 子模块。

需要注意的是，我们需要调整每个应用程序构建时使用的链接器脚本 linker.ld 中的起始地址 BASE_ADDRESS，这是由内核将应用程序加载到内存中的起始地址。这意味着应用程序知道它将被加载到特定地址，并且内核确实将应用程序加载到它指定的地址。这在某种程度上是应用程序和内核之间的一种协议。之所以有这种严格的条件，是因为当前操作系统内核还比较脆弱，不提供足够的应用程序通用性支持（例如，不支持将应用程序加载到内存的任意地址），这进一步导致了应用程序编程的缺乏便利性和通用性（应用程序需要指定自己的内存地址）。事实上，当前应用程序寻址的方式是基于绝对位置的，而不是位置独立的，并且内核不提供相应的地址重定位机制。

由于每个应用程序被加载到不同的位置，它们在链接器脚本 linker.ld 中的 BASE_ADDRESS 是不同的。实际上，我们没有直接使用 cargo build 来构建应用程序的链接器脚本，而是编写了一个脚本定制工具 build.py，用于为每个应用程序定制链接器脚本：

```python
 # user/build.py

 import os

 base_address = 0x80400000
 step = 0x20000
 linker = 'src/linker.ld'

 app_id = 0
 apps = os.listdir('src/bin')
 apps.sort()
 for app in apps:
     app = app[:app.find('.')]
     lines = []
     lines_before = []
     with open(linker, 'r') as f:
         for line in f.readlines():
             lines_before.append(line)
             line = line.replace(hex(base_address), hex(base_address+step*app_id))
             lines.append(line)
     with open(linker, 'w+') as f:
         f.writelines(lines)
     os.system('cargo build --bin %s --release' % app)
     print('[build.py] application %s start with address %s' %(app, hex(base_address+step*app_id)))
     with open(linker, 'w+') as f:
         f.writelines(lines_before)
     app_id = app_id + 1
```

### Application loader


应用程序的加载方式与前一章节也有所不同。在前一章节中解释的加载方法是让所有应用程序共享相同的固定物理地址进行加载。因此，一次只能有一个应用程序驻留在内存中，当其完成运行或以错误退出时，操作系统的批处理子模块会加载一个新的应用程序来替换它。而在本章中，所有应用程序在内核初始化时都被加载到内存中。为了避免覆盖，它们自然需要加载到不同的物理地址上。这是通过调用 loader 子模块的 load_apps 函数来实现的：

```rust
 // os/src/loader.rs

 pub fn load_apps() {
     extern "C" { fn _num_app(); }
     let num_app_ptr = _num_app as usize as *const usize;
     let num_app = get_num_app();
     let app_start = unsafe {
         core::slice::from_raw_parts(num_app_ptr.add(1), num_app + 1)
     };
     // clear i-cache first
     unsafe { asm!("fence.i" :::: "volatile"); }
     // load apps
     for i in 0..num_app {
         let base_i = get_base_i(i);
         // clear region
         (base_i..base_i + APP_SIZE_LIMIT).for_each(|addr| unsafe {
             (addr as *mut u8).write_volatile(0)
         });
         // load app from data section to memory
         let src = unsafe {
             core::slice::from_raw_parts(
                 app_start[i] as *const u8,
                 app_start[i + 1] - app_start[i]
             )
         };
         let dst = unsafe {
             core::slice::from_raw_parts_mut(base_i as *mut u8, src.len())
         };
         dst.copy_from_slice(src);
     }
 }

 // os/src/loader.rs

 fn get_base_i(app_id: usize) -> usize {
     APP_BASE_ADDRESS + app_id * APP_SIZE_LIMIT
 }
```

### Application Excution

当多遍应用程序的初始放置完成时，或者当应用程序完成运行或出错时，我们希望调用该run_next_app函数来切换到下一个应用程序。此时CPU运行在操作系统的S权限下，操作系统希望能够切换到U权限下运行应用程序。此过程与上一章执行应用程序部分中描述的过程类似。相对的区别在于，操作系统知道每个应用程序在内存中预加载的位置，这需要设置应用程序返回的不同 Trap 上下文（Trap 上下文保存应用程序epc起始地址所在的寄存器的内容）：



## 0x01 Task Switch

### The Concept of Task

至此，我们将应用程序的一次执行（也是一个控制流）称为任务，并将应用程序执行的某个时间片上的执行片或空闲片称为“计算任务片”或“空闲任务片”。然而，一旦应用程序的所有任务片都完成，则该应用程序的一个任务就完成了。从一个应用程序中的任务切换到另一应用程序中的任务称为任务切换。为了保证切换后的任务能够正确继续执行，操作系统需要支持“暂停”和“恢复”任务的执行。

我们再次看到熟悉的“暂停-恢复”组合。一旦一个控制流需要支持“挂起-继续”，就需要提供控制流切换的机制，需要保证控制流切换前和切换后程序执行继续正确执行这就要求程序执行的状态（也称为上下文），即执行过程中同步变化的资源（例如寄存器、堆栈等）保持不变或者在其期望的范围内变化。并非所有资源都需要保存，事实上，只有那些对于程序的正确执行仍然有用并且在切换时有被覆盖风险的资源才值得保存。这些需要保存和恢复的资源称为Task Contexts。

### Design and Implementation of Task Switching

本节介绍的任务切换是除第2章提到的Trap控制流切换之外的另一种异常控制流，都是描述两个控制流之间的切换，与Trap切换相比，有以下相同点和不同点。

与Trap切换不同的是，它不涉及特权级别切换。

与陷阱切换不同，它部分是在编译器的帮助下完成的。

与陷阱切换一样，它对应用程序是透明的。

事实上，任务切换是内核中两个不同应用程序的Trap控制流之间的切换。当应用程序陷入S模式操作系统内核进行进一步处理时（即进入操作系统的Trap控制流），其Trap控制流可以调用特殊__switch函数。该函数表面上是一个普通的函数调用：返回后__switch，从调用该函数的位置继续执行。但其间隐藏着复杂的控制流切换过程。具体地，调用后__switch直至返回，首先将原来的Trap控制流A挂起并切换出去，CPU运行内核中应用的另一个Trap控制流B。然后，在某个适当的时间，原始陷阱 A 从陷阱 C 之一（很可能不是它切换到的 B）切换回来，继续执行并最终返回。然而，从实现的角度来看，该__switch函数与普通函数的核心区别就在于它切换了堆栈。



![](https://gitee.com/itewqq/images/raw/master/20220211165323.png)

当 Trap 控制流准备调用__switch函数使任务从运行状态进入挂起状态时，让我们检查一下其内核堆栈的情况。如上图左侧所示，在函数__switch调用之前，内核栈从栈底到栈顶包含Trap上下文，保存了应用程序的执行状态，以及调用栈信息处理 Trap 期间内核留下的。由于我们稍后必须恢复执行，因此我们必须保存 CPU 当前状态的某些寄存器，我们将其称为任务上下文。稍后我们将描述其中包含哪些寄存器。至于上下文存储在哪里，下一节我们将介绍任务管理器TaskManager，其中可以找到一个数组tasks，每个数组都是一个TaskControlBlock，负责存储任务的状态，而 则TaskContext存储在TaskControlBlock。TaskManager在内核运行时，我们初始化了:的全局实例TASK_MANAGER，因此所有任务上下文实际上都存储在 中，从内存布局的角度来看，TASK_MANAGER它被放置在内核的全局数据段中。.data当我们保存完任务上下文后，它们就转变为下图右侧的状态。当我们从另一个任务切换回这个任务时，CPU 将读取相同的位置并从中恢复任务上下文。

对于当前正在执行的任务的Trap控制流，我们使用一个名为named的变量current_task_cx_ptr来保存当前任务上下文的地址，并使用一个名为named的变量next_task_cx_ptr来保存下一个要执行的任务的上下文地址。

__switch从栈上内容来看整体流程：

![](https://gitee.com/itewqq/images/raw/master/20220211165700.png)

Trap 控制流在调用之前需要准确知道它要切换到哪个 Trap 控制流__switch，因此__switch有两个参数，第一个代表它自己，第二个代表它要切换到的 Trap 控制流。这里我们使用上面提到的current_task_cx_ptr和next_task_cx_ptr作为代理。上图中我们假设一个__switch调用要从Trap控制流A切换到B。有四个阶段，每个阶段我们给出A和B内核堆栈的内容。

阶段[1]：在__switchTrap控制流A调用之前，A的内核堆栈上唯一的信息是Trap上下文和Trap处理程序的调用堆栈，而B之前已被切换出。
阶段[2]：A在A任务上下文空间里面保存CPU当前寄存器的快照。
阶段[3]：这一步极为关键，读取 指向的B任务上下文，并根据B任务上下文中保存的内容next_task_cx_ptr恢复ra寄存器、s0~s11寄存器、寄存器。sp只有完成这一步后，才能__switch跨两个控制流执行函数，即通过改变堆栈来切换控制流。
阶段[4]：经过上一步寄存器恢复后，可以看到sp寄存器恢复并切换到任务B的内核堆栈中，从而实现控制流切换。这就是为什么__switch能够跨两个控制流执行一个函数。之后，当CPU执行ret指令并且__switch函数返回时，任务B可以从它调用的地方继续沿着堆栈向下移动__switch。
结果，我们看到控制流A和控制流B的状态交换了，A在保存任务上下文后进入挂起状态，而B恢复上下文并继续在CPU上执行。
```asm
# os/src/task/switch.S

.altmacro
.macro SAVE_SN n
    sd s\n, (\n+2)*8(a0)
.endm
.macro LOAD_SN n
    ld s\n, (\n+2)*8(a1)
.endm
    .section .text
    .globl __switch
__switch:
    # Phase [1]
    # __switch(
    #     current_task_cx_ptr: *mut TaskContext,
    #     next_task_cx_ptr: *const TaskContext
    # )
    # Phase [2]
    # save kernel stack of current task
    sd sp, 8(a0)
    # save ra & s0~s11 of current execution
    sd ra, 0(a0)
    .set n, 0
    .rept 12
        SAVE_SN %n
        .set n, n + 1
    .endr
    # Phase [3]
    # restore ra & s0~s11 of next execution
    ld ra, 0(a1)
    .set n, 0
    .rept 12
        LOAD_SN %n
        .set n, n + 1
    .endr
    # restore kernel stack of next task
    ld sp, 8(a1)
    # Phase [4]
    ret
```

save 很重要ra，它记录了函数返回后跳转到的位置__switch，以便任务切换完成后能够到达正确的位置并ret。对于普通函数，Rust/C 编译器会在函数开头自动生成代码，以将寄存器保存s0到s11调用者保存的寄存器中。然而，__switch它是一个用汇编代码编写的特殊函数，Rust/C编译器不会处理，因此我们需要手动编写汇编代码来__switch保存s0~s11. 不需要保存其他寄存器，因为： 其他寄存器中，属于调用者保存的寄存器是由高级语言编写的调用函数中编译器自动生成的代码完成的；还有一些寄存器属于临时寄存器，不需要保存和恢复。

我们将把这段汇编代码中的全局符号解释__switch为 Rust 函数：

```rust
// os/src/task/context.rs

pub struct TaskContext {
    ra: usize,
    sp: usize,
    s: [usize; 12],
}

// os/src/task/switch.rs

global_asm!(include_str!("switch.S"));

use super::TaskContext;

extern "C" {
    pub fn __switch(
        current_task_cx_ptr: *mut TaskContext,
        next_task_cx_ptr: *const TaskContext
    );
}
```

我们将调用这个函数来完成switch功能，而不是直接跳转到符号的地址__switch。所以Rust编译器会自动帮我们插入汇编代码，在调用前后保存/恢复调用者的保存寄存器。

## 0x02 Task Scheduling

### Preemptive Scheduling

现代任务调度算法本质上基本上是抢占式的，要求每个应用程序只能连续执行一段时间，然后内核强制其切换出去。时间片一般用作应用程序连续执行时长的度量单位，每个时间片可能是毫秒量级。调度算法需要考虑在切换之前给应用程序执行多少个时间片，以及切换到哪个应用程序。调度算法可以从性能（主要是吞吐量和延迟指标）和公平性两个方面进行评估，这就要求分配给多个应用程序的时间片百分比不要相差太大。

调度的核心机制在于时序：我们利用时钟中断来强制阻塞用户态程序的执行，从而让操作系统能够使用CPU并行使其任务管理权。

```rust
// os/src/trap/mod.rs

match scause.cause() {
    Trap::Interrupt(Interrupt::SupervisorTimer) => {
        set_next_trigger();
        suspend_current_and_run_next();
    }
}

// os/src/main.rs

#[no_mangle]
pub fn rust_main() -> ! {
    clear_bss();
    println!("[kernel] Hello, world!");
    trap::init();
    loader::load_apps();
    trap::enable_timer_interrupt();
    timer::set_next_trigger();
    task::run_first_task();
    panic!("Unreachable in rust_main!");
}

// os/src/trap/mod.rs

use riscv::register::sie;

pub fn enable_timer_interrupt() {
    unsafe { sie::set_stimer(); }
}
```

应用程序运行 10ms 后，会触发 S 特权时钟中断。由于应用程序运行在U权限，并且sie寄存器设置正确，所以中断并没有被屏蔽，而是跳转到我们trap_handler内部的S权限进行处理，并顺利切换到下一个应用程序。这就是我们所期望的抢占式调度机制。

### Task Management

We use a global task manager to control all the scheduling:

```rust
mod context;
mod switch;
mod task;
pub mod scheduler;

use crate::config::MAX_APP_NUM;
use crate::loader::{get_num_app, init_app_cx};
use crate::sync::UPSafeCell;
use alloc::boxed::Box;
use lazy_static::*;
use switch::__switch;
use task::{TaskControlBlock, TaskStatus};
use scheduler::{BIG_STRIDE, StrideScheduler};

pub use context::TaskContext;

pub struct TaskManager {
    num_app: usize,
    inner: UPSafeCell<TaskManagerInner>,
}

struct TaskManagerInner {
    tasks: [TaskControlBlock; MAX_APP_NUM],
    current_task: usize,
    scheduler: Box<StrideScheduler>,
}

lazy_static! {
    pub static ref TASK_MANAGER: TaskManager = {
        let num_app = get_num_app();
        let mut stride_scheduler: StrideScheduler = StrideScheduler::new();
        let mut tasks = [
            TaskControlBlock {
                id: 0,
                task_cx: TaskContext::zero_init(),
                task_status: TaskStatus::UnInit,
                priority: 16,
                pass: 0,
            };
            MAX_APP_NUM
        ];
        for i in 0..num_app {
            tasks[i].id = i;
            tasks[i].task_cx = TaskContext::goto_restore(init_app_cx(i));
            tasks[i].task_status = TaskStatus::Ready;
            stride_scheduler.create_task(i);
        }
        TaskManager {
            num_app,
            inner: unsafe { UPSafeCell::new(TaskManagerInner {
                tasks,
                current_task: 0,
                scheduler: Box::new(stride_scheduler),
            })},
        }
    };
}

impl TaskManager {
    fn run_first_task(&self) -> ! {
        let mut inner = self.inner.exclusive_access();
        let next = inner.scheduler.find_next_task().unwrap();// let it panic or not
        let task0 = &mut inner.tasks[next];
        task0.task_status = TaskStatus::Running;
        let next_task_cx_ptr = &task0.task_cx as *const TaskContext;
        drop(inner);
        let mut _unused = TaskContext::zero_init();
        // before this, we should drop local variables that must be dropped manually
        unsafe {
            __switch(
                &mut _unused as *mut TaskContext,
                next_task_cx_ptr,
            );
        }
        panic!("unreachable in run_first_task!");
    }

    fn mark_current_suspended(&self) {
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].task_status = TaskStatus::Ready;
    }

    fn mark_current_exited(&self) {
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].task_status = TaskStatus::Exited;
    }

    fn find_next_task(&self) -> Option<usize> {
        let mut inner = self.inner.exclusive_access();
        loop {
            let next = inner.scheduler.find_next_task();
            if let Some(id) = next {
                if inner.tasks[id].task_status == TaskStatus::Ready {
                    return next;
                }else {
                    continue; // no ready so removed? 
                }
            }else {
                return None;
            }
        }
    }

    fn run_next_task(&self) {
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].pass += BIG_STRIDE / inner.tasks[current].priority;
        let current_pass = inner.tasks[current].pass;
        inner.scheduler.insert_task(current, current_pass);
        drop(inner);
        if let Some(next) = self.find_next_task() {
            let mut inner = self.inner.exclusive_access();
            inner.tasks[next].task_status = TaskStatus::Running;
            inner.current_task = next;
            let current_task_cx_ptr = &mut inner.tasks[current].task_cx as *mut TaskContext;
            let next_task_cx_ptr = &inner.tasks[next].task_cx as *const TaskContext;
            drop(inner);
            // before this, we should drop local variables that must be dropped manually
            unsafe {
                __switch(
                    current_task_cx_ptr,
                    next_task_cx_ptr,
                );
            }
            // go back to user mode
        } else {
            panic!("All applications completed!");
        }
    }

    fn set_current_prio(&self, prio: usize) {
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].priority = prio;
    }
}

pub fn run_first_task() {
    TASK_MANAGER.run_first_task();
}

fn run_next_task() {
    TASK_MANAGER.run_next_task();
}

fn mark_current_suspended() {
    TASK_MANAGER.mark_current_suspended();
}

fn mark_current_exited() {
    TASK_MANAGER.mark_current_exited();
}

pub fn set_current_prio(prio: usize) {
    let prio = if prio < BIG_STRIDE {prio} else {BIG_STRIDE};
    TASK_MANAGER.set_current_prio(prio);
}

pub fn suspend_current_and_run_next() {
    mark_current_suspended();
    run_next_task();
}

pub fn exit_current_and_run_next() {
    mark_current_exited();
    run_next_task();
}
```

Besides, we implemetend a stride scheduler(see Refrence 2), which enables priorities in scheduling:

```rust
use core::cmp::{Ord, Ordering};
use alloc::collections::BinaryHeap;

pub const BIG_STRIDE: usize = 1_000;

#[derive(Copy, Clone, Eq)]
pub struct Stride {
    id: usize,
    pass: usize,
}

impl Stride {
    pub fn new(id: usize, pass: usize) -> Self {
        Self { id, pass, }
    }

    pub fn zeros() -> Self {
        Self { id: 0, pass: 0, }
    }
}

impl Ord for Stride {
    fn cmp(&self, other: &Self) -> Ordering {
        self.pass.cmp(&other.pass).reverse()
    }
}

impl PartialOrd for Stride {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Stride {
    fn eq(&self, other: &Self) -> bool {
        self.pass == other.pass
    }
}

pub struct StrideScheduler {
    queue: BinaryHeap<Stride>,
}

impl StrideScheduler {
    pub fn new() -> Self {
        Self {queue: BinaryHeap::new()}
    }

    pub fn create_task(&mut self, id: usize) {
        self.queue.push(Stride::new(id, 0));
    }

    pub fn insert_task(&mut self, id: usize, pass: usize){
        self.queue.push(Stride::new(id, pass));
    }

    pub fn find_next_task(&mut self) -> Option<usize> {
        let next = self.queue.pop();
        if let Some(node) = next {
            Some(node.id)
        } else {
            None
        }
    }
}
```

请注意，为了使用alloc::collections::BinaryHeap，我们必须实现全局分配器，这将在下一章中说明，mm详细信息请参阅子模块。

我们使用 rCore-Tutorial-Book-v3 提供的代码来测试步幅调度器：

```sh
(base) test@HPserver:/home/test/rCore-dev/os$ make clean && make run TEST=3
(rustup target list | grep "riscv64gc-unknown-none-elf (installed)") || rustup target add riscv64gc-unknown-none-elf
riscv64gc-unknown-none-elf (installed)
cargo install cargo-binutils --vers =0.3.3
     Ignored package `cargo-binutils v0.3.3` is already installed, use --force to override
rustup component add rust-src
info: component 'rust-src' is up to date
rustup component add llvm-tools-preview
info: component 'llvm-tools-preview' for target 'x86_64-unknown-linux-gnu' is up to date
make[1]: Entering directory '/home/qsp/rCore-dev/user'
   Compiling scopeguard v1.1.0
   Compiling spin v0.7.1
   Compiling spin v0.5.2
   Compiling bitflags v1.3.2
   Compiling lock_api v0.4.6
   Compiling lazy_static v1.4.0
   Compiling buddy_system_allocator v0.6.0
   Compiling spin v0.9.2
   Compiling user_lib v0.1.0 (/home/qsp/rCore-dev/user)
    Finished release [optimized] target(s) in 2.29s
[build.py] application test3_stride0 start with address 0x80400000
   Compiling user_lib v0.1.0 (/home/qsp/rCore-dev/user)
    Finished release [optimized] target(s) in 0.27s
[build.py] application test3_stride1 start with address 0x80420000
   Compiling user_lib v0.1.0 (/home/qsp/rCore-dev/user)
    Finished release [optimized] target(s) in 0.26s
[build.py] application test3_stride2 start with address 0x80440000
   Compiling user_lib v0.1.0 (/home/qsp/rCore-dev/user)
    Finished release [optimized] target(s) in 0.27s
[build.py] application test3_stride3 start with address 0x80460000
   Compiling user_lib v0.1.0 (/home/qsp/rCore-dev/user)
    Finished release [optimized] target(s) in 0.26s
[build.py] application test3_stride4 start with address 0x80480000
   Compiling user_lib v0.1.0 (/home/qsp/rCore-dev/user)
    Finished release [optimized] target(s) in 0.25s
[build.py] application test3_stride5 start with address 0x804a0000
make[1]: Leaving directory '/home/qsp/rCore-dev/user'
Platform: qemu
   Compiling memchr v2.4.1
   Compiling semver-parser v0.7.0
   Compiling regex-syntax v0.6.25
   Compiling lazy_static v1.4.0
   Compiling log v0.4.14
   Compiling cfg-if v1.0.0
   Compiling bitflags v1.3.2
   Compiling bit_field v0.10.1
   Compiling spin v0.7.1
   Compiling spin v0.5.2
   Compiling os v0.1.0 (/home/qsp/rCore-dev/os)
   Compiling buddy_system_allocator v0.6.0
   Compiling semver v0.9.0
   Compiling rustc_version v0.2.3
   Compiling bare-metal v0.2.5
   Compiling aho-corasick v0.7.18
   Compiling regex v1.5.4
   Compiling riscv-target v0.1.2
   Compiling riscv v0.6.0 (https://github.com/rcore-os/riscv#11d43cf7)
    Finished release [optimized] target(s) in 6.54s
[rustsbi] RustSBI version 0.2.0-alpha.6
.______       __    __      _______.___________.  _______..______   __
|   _  \     |  |  |  |    /       |           | /       ||   _  \ |  |
|  |_)  |    |  |  |  |   |   (----`---|  |----`|   (----`|  |_)  ||  |
|      /     |  |  |  |    \   \       |  |      \   \    |   _  < |  |
|  |\  \----.|  `--'  |.----)   |      |  |  .----)   |   |  |_)  ||  |
| _| `._____| \______/ |_______/       |__|  |_______/    |______/ |__|

[rustsbi] Implementation: RustSBI-QEMU Version 0.0.2
[rustsbi-dtb] Hart count: cluster0 with 1 cores
[rustsbi] misa: RV64ACDFIMSU
[rustsbi] mideleg: ssoft, stimer, sext (0x222)
[rustsbi] medeleg: ima, ia, bkpt, la, sa, uecall, ipage, lpage, spage (0xb1ab)
[rustsbi] pmp0: 0x10000000 ..= 0x10001fff (rwx)
[rustsbi] pmp1: 0x80000000 ..= 0x8fffffff (rwx)
[rustsbi] pmp2: 0x0 ..= 0xffffffffffffff (---)
qemu-system-riscv64: clint: invalid write: 00000004
[rustsbi] enter supervisor 0x80200000
[kernel] Hello, world!
priority = 9, exitcode = 35427600
priority = 10, exitcode = 39471200
priority = 8, exitcode = 31496000
[kernel] Application exited with code 0
[kernel] Application exited with code 0
priority = 7, exitcode = 27814000
priority = 6, exitcode = 23706000
[kernel] Application exited with code 0
[kernel] Application exited with code 0
priority = 5, exitcode = 19708000
[kernel] Application exited with code 0
[kernel] Application exited with code 0
Panicked at src/task/mod.rs:129 All applications completed!
```

结果与我们的预测一致，每个程序的运行时间与优先级成正比。
## 0x03 References

1. [https://rcore-os.github.io/rCore-Tutorial-Book-v3/chapter3/](https://rcore-os.github.io/rCore-Tutorial-Book-v3/chapter3/)
2. [https://nankai.gitbook.io/ucore-os-on-risc-v64/lab6/tiao-du-suan-fa-kuang-jia#stride-suan-fa](https://nankai.gitbook.io/ucore-os-on-risc-v64/lab6/tiao-du-suan-fa-kuang-jia#stride-suan-fa)
3. [https://web.eecs.utk.edu/~smarz1/courses/ece356/notes/assembly/](https://web.eecs.utk.edu/~smarz1/courses/ece356/notes/assembly/)

>All of the figures credit to rCore-Tutorial-Book-v3

