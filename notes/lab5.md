# Process

## 0x00 The Concepts and Syscalls

很难定义 aprocess是什么。通常是操作系统选择一个可执行文件并进行动态执行的过程。在执行过程中，进程与硬件或虚拟资源之间会有很多交互，我们知道这些交互是由操作系统通过系统调用来处理的。此外，还有一些专门用于进程管理的重要系统调用fork/exec/waitpid：：

fork：当一个进程（我们将其命名为A）调用fork时，内核将创建一个与A几乎相同的新进程（我们将其命名为B）：它们具有完全相同的堆栈，.text段或其他数据段内容，并且每个进程寄存器除外a0，它存储系统调用的返回值。它们位于不同的地址空间中，但这些地址空间中的字节存储在返回时完全相同fork。进程可以确定它是新进程还是旧父进程的唯一方法是fork新出生进程的返回值 : 0 和pid父进程的子进程的返回值。这种父子关系在类unix操作系统中非常重要。

exec：这将帮助我们在当前的地址空间中运行一个新的程序，使用它fork我们可以轻松地创建一个运行新程序的进程。

waitpid：当进程返回时，其消耗的内存资源无法通过exit系统调用完全回收，例如当前的kernel stack. 一个典型的解决方案是将进程标记为zombie，然后它的父进程完成其余的回收工作并通过waitpid系统调用获取退出状态。

## 0x01 Data Structures for Process

RAII大量用于帮助我们安全的内存管理。对于一个进程，我们将其pid、kernel stack、 和绑定address space(MemorySet)到 a TaskControlBlock。TCB 存储在由进程之间的父子关系（通过 fork&exec 创建）形成的树中：

```rust
pub struct TaskControlBlock {
    // immutable
    pub pid: PidHandle,
    pub kernel_stack: KernelStack,
    // mutable
    inner: UPSafeCell<TaskControlBlockInner>,
}

pub struct TaskControlBlockInner {
    pub trap_cx_ppn: PhysPageNum,
    pub base_size: usize,
    pub priority: usize,
    pub pass: usize,
    pub task_cx: TaskContext,
    pub task_status: TaskStatus,
    pub memory_set: MemorySet,
    pub parent: Option<Weak<TaskControlBlock> >,
    pub children: Vec<Arc<TaskControlBlock> >,
    pub exit_code: i32,
}
```

这里我们使用alloc::sync::Weak包装指针parent，这样父级和子级之间就不会出现循环引用。

相对于上一章的另一个重大修改是我们将原来的任务管理器模块拆分为Processor和TaskManager。

该Processor模块维护CPU的状态，包括当前进程和空闲任务上下文。在单核CPU环境中，我们只创建一个全局的Processor.
TaskManager将所有Arcs 存储在 a 中，BTreeMap以便我们可以使用调度程序轻松获取/删除或添加/插入任务（进程）。

```rust
pub struct TaskManager {
    ready_queue: BTreeMap<usize, Arc<TaskControlBlock>>,
    scheduler: Box<Scheduler>,
}

impl TaskManager {
    pub fn new() -> Self {
        let stride_scheduler: Scheduler = Scheduler::new();
        Self {
            ready_queue: BTreeMap::new(),
            scheduler: Box::new(stride_scheduler),
        }
    }

    pub fn add(&mut self, task: Arc<TaskControlBlock>) {
        // update pass for stride scheduler
        let mut task_inner = task.inner_exclusive_access();
        task_inner.pass += BIG_STRIDE / task_inner.priority;
        drop(task_inner);
        self.scheduler.insert_task(task.getpid(), task.clone().inner_exclusive_access().pass);
        self.ready_queue.insert(task.getpid(), task);
    }

    pub fn fetch(&mut self) -> Option<Arc<TaskControlBlock>> {
        let next_pid = loop {
            if let Some(next_pid) = self.scheduler.find_next_task() {
                // TODO how about wait state
                if self.ready_queue.contains_key(&next_pid){
                    break next_pid
                }
            } else {
                return None;
            }
            
        };
        let (_, task) = self.ready_queue.remove_entry(&next_pid).unwrap();
        Some(task)
    }
}
```

## 0x02 Process Management

请注意，我们需要手动设置一个派生所有其他进程的根进程。这样的根进程通常称为initproc. 在rCore中initproc实现如下：

```rust
#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

use user_lib::{exec, fork, wait, yield_};

#[no_mangle]
fn main() -> i32 {
    if fork() == 0 {
        exec("user_shell\0");
    } else {
        loop {
            let mut exit_code: i32 = 0;
            let pid = wait(&mut exit_code);
            if pid == -1 {
                yield_();
                continue;
            }
            println!(
                "[initproc] Released a zombie process, pid={}, exit_code={}",
                pid, exit_code,
            );
        }
    }
    0
}
```

该iniproc进程是os启动后运行的第一个任务，它只有两个任务：

创建shell流程

收养所有孤儿进程，等待它们退出并回收资源

虽然initproc很特殊，但它仍然只是一个用户态进程。

然后我们根据其语义实现了 fork/exit/waitpid 系统调用。

```rust
pub fn sys_fork() -> isize {
    let current = current_task().unwrap();
    let child_task = current.fork();
    let child_pid = child_task.pid.0;
    // modify return address in trap context
    let trap_cx = child_task.inner_exclusive_access().get_trap_cx();
    // return value of child is 0
    trap_cx.x[10] = 0;  //x[10] is a0 reg
    // add task to scheduler queue
    add_task(child_task);
    child_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}

// If pid == -1, try to recycle every child
// If there is not a child process whose pid is same as given, return -1.
// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    // no such child
    if inner.children
        .iter()
        .find(|p| {pid == -1 || pid as usize == p.getpid()})
        .is_none() {
        return -1;
    }
    // get child
    let pair = inner.children
        .iter()
        .enumerate()
        .find(|(_, p)| {
            // ++++ temporarily access child PCB exclusively
            p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
            // ++++ stop exclusively accessing child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after removing from children list
        // so that after dropped, the kernel stack and pagetable and pid_handle will be recycled
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        let exit_code = child.inner_exclusive_access().exit_code;
        // write exit_code to the user space
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
}
```

The corresponding apis of `TaskControlBlock` are as follows:

```rust
impl TaskControlBlock {
    pub fn inner_exclusive_access(&self) -> RefMut<'_, TaskControlBlockInner> {
        self.inner.exclusive_access()
    }
    
    pub fn getpid(&self) -> usize {
        self.pid.0
    }

    pub fn new(elf_data: &[u8]) -> Self {
        // map user space memory set
        let (memory_set, user_sp, entry_point) = MemorySet::from_elf(elf_data);
        let trap_cx_ppn = memory_set
            .translate(VirtAddr::from(TRAP_CONTEXT).into())
            .unwrap()
            .ppn();
        let task_status = TaskStatus::Ready;
        // alloc a pid and a kernel stack in kernel space
        let pid_handle = pid_alloc();
        let kernel_stack = KernelStack::new(&pid_handle);
        let kernel_stack_top = kernel_stack.get_top();
         // push a task context which goes to trap_return to the top of kernel stack
        let task_control_block = Self {
            pid: pid_handle,
            kernel_stack,
            inner: unsafe { UPSafeCell::new(TaskControlBlockInner {
                trap_cx_ppn,
                base_size: user_sp,
                priority: 16,
                pass: 0,
                task_cx: TaskContext::goto_trap_return(kernel_stack_top),
                task_status,
                memory_set,
                parent: None,
                children: Vec::new(),
                exit_code: 0,
            })},
        };
        // prepare TrapContext in user space
        let trap_cx = task_control_block.inner_exclusive_access().get_trap_cx();
        *trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.exclusive_access().token(),
            kernel_stack_top,
            trap_handler as usize,
        );
        task_control_block
    }

    pub fn exec(&self, elf_data: &[u8]) {
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, user_sp, entry_point) = MemorySet::from_elf(elf_data);
        // substitute memory_set
        let trap_cx_ppn = memory_set
            .translate(VirtAddr::from(TRAP_CONTEXT).into())
            .unwrap()
            .ppn();
        let mut inner = self.inner_exclusive_access();
        inner.memory_set = memory_set;
        // update trap_cx ppn
        inner.trap_cx_ppn = trap_cx_ppn;
        // initialize trap_cx
        let trap_cx = inner.get_trap_cx();
        *trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.exclusive_access().token(),
            self.kernel_stack.get_top(),
            trap_handler as usize,
        );
    }
    pub fn fork(self: &Arc<TaskControlBlock>) -> Arc<TaskControlBlock> {
        // get parent PCB
        let mut parent_inner = self.inner.exclusive_access();
        // make a copy of memory space 
        let memory_set = MemorySet::from_existed_userspace(
            &parent_inner.memory_set);
        // allocate a pid and kernel stack
        let pid_handle = pid_alloc();
        let kernel_stack = KernelStack::new(&pid_handle);
        let kernel_stack_top = kernel_stack.get_top();
        // get trap context ppn
        let trap_cx_ppn = memory_set
            .translate(VirtAddr::from(TRAP_CONTEXT).into())
            .unwrap()
            .ppn();
        // create inner
        let task_control_block_inner = unsafe { UPSafeCell::new(TaskControlBlockInner { 
            trap_cx_ppn: trap_cx_ppn, 
            base_size: parent_inner.base_size, 
            priority: parent_inner.priority, 
            pass: parent_inner.pass, 
            task_cx: TaskContext::goto_trap_return(kernel_stack_top), 
            task_status: TaskStatus::Ready, 
            memory_set, 
            parent: Some(Arc::downgrade(self)), 
            children: Vec::new(), 
            exit_code: 0, 
        })};
        // modify kernel sp in child's trap_cx
        let trap_cx = task_control_block_inner.exclusive_access().get_trap_cx();
        trap_cx.kernel_sp = kernel_stack_top;
        // create child's PCB
        let task_control_block = Arc::new(TaskControlBlock {
            pid: pid_handle,
            kernel_stack,
            inner: task_control_block_inner,
        });
        // add child to parent
        parent_inner.children.push(task_control_block.clone());
        // return
        task_control_block
    }
}
```

然后我们实现主要的任务管理功能：

```rust
pub fn suspend_current_and_run_next() {
    let task = take_current_task().unwrap();

    // ---- access current TCB exclusively
    let mut task_inner = task.inner_exclusive_access();
    let task_cx_ptr = &mut task_inner.task_cx as *mut TaskContext;
    // Change status to Ready
    task_inner.task_status = TaskStatus::Ready;
    drop(task_inner);
    // ---- stop exclusively accessing current PCB

    // push back to ready queue.
    add_task(task);
    // jump to scheduling cycle
    schedule(task_cx_ptr);
}

pub fn exit_current_and_run_next(exit_code: i32) {
    // take from processor
    let task = take_current_task().unwrap();
    // access current TCB exclusively
    let mut inner = task.inner_exclusive_access();
    // change status to Zombie
    inner.task_status = TaskStatus::Zombie;
    // record exit code
    inner.exit_code = exit_code;
    // initproc collects children
    {
        let mut initproc_inner = INITPROC.inner_exclusive_access();
        for child in inner.children.iter() {
            child.inner_exclusive_access().parent = Some(Arc::downgrade(&INITPROC));
            initproc_inner.children.push(child.clone());
        }
    }
    inner.children.clear();
    // dealloc memory in user space,
    // but the page table in phys memory still here and will be recycled by parent with sys_waitpid
    inner.memory_set.recycle_data_pages();
    drop(inner);
    // drop task, so there is only one ref to it in it's parent
    drop(task);
    // No task context
    let mut _unused = TaskContext::zero_init();
    schedule(&mut _unused as *mut _);
}
```

## References

[rCore-Tutorial-Book-v3/chapter5](https://rcore-os.github.io/rCore-Tutorial-Book-v3/chapter5/index.html)
