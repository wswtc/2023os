#                    chapter2：批处理系统

## 实验目的

#### **1、让用户程序运行在用户态**

​        在chapter1中，我们输出"helloworld"的工作是在内核中完成的，我们需要把用户程序所做的工作转移到用户态。

#### 2、实现批处理操作系统

​       将多个任务打包放入系统中，当一个任务完成或者因意外退出时，自动跳转到下一个任务去执行。



## 实验过程

####  1、用户程序的编译和打包

**解析启动os2的make命令**

```makefile
#os2/Makefile

run: build
     @qemu-system-riscv64 \
         -machine virt \
         -nographic \
         -bios $(BOOTLOADER) \
         -device loader,file=$(KERNEL_BIN),addr=$(KERNEL_ENTRY_PA)

build: env $(KERNEL_BIN)

$(KERNEL_BIN): kernel
	@$(OBJCOPY) $(KERNEL_ELF) --strip-all -O binary $@

kernel:
	@make -C ../user build TEST=$(TEST) CHAPTER=$(CHAPTER) BASE=$(BASE)
	@cargo build --release
```

可以看到，在os中执行make run的时候，会转而进入../user目录中执行make build，我们继续看user/Makefile中的相关内容：

```makefile
BUILD_DIR := build
APP_DIR := src/bin
BASE ?= 0
CHAPTER ?= 0
TEST ?= $(CHAPTER)

ifeq ($(TEST), 0) # No test, deprecated, previously used in v3
	APPS :=  $(filter-out $(wildcard $(APP_DIR)/ch*.rs), $(wildcard $(APP_DIR)/*.rs))
else ifeq ($(TEST), 1) # All test
	APPS :=  $(wildcard $(APP_DIR)/ch*.rs)
else
	TESTS := $(shell seq $(BASE) $(TEST))
	ifeq ($(BASE), 0) # Normal tests only
		APPS := $(foreach T, $(TESTS), $(wildcard $(APP_DIR)/ch$(T)_*.rs))
	else ifeq ($(BASE), 1) # Basic tests only
		APPS := $(foreach T, $(TESTS), $(wildcard $(APP_DIR)/ch$(T)b_*.rs))
	else # Basic and normal
		APPS := $(foreach T, $(TESTS), $(wildcard $(APP_DIR)/ch$(T)*.rs))
	endif
endif

ELFS := $(patsubst $(APP_DIR)/%.rs, $(TARGET_DIR)/%, $(APPS))

build: clean pre binary
     @$(foreach t, $(ELFS), cp $(t).bin $(BUILD_DIR)/bin/;)
     @$(foreach t, $(ELFS), cp $(t).elf $(BUILD_DIR)/elf/;)
     
pre:
	@mkdir -p $(BUILD_DIR)/bin/
	@mkdir -p $(BUILD_DIR)/elf/
	@mkdir -p $(BUILD_DIR)/app/
	@mkdir -p $(BUILD_DIR)/asm/
	@$(foreach t, $(APPS), cp $(t) $(BUILD_DIR)/app/;)

binary:
	@echo $(ELFS)
	@if [ ${CHAPTER} -gt 3 ]; then \
		cargo build --release ;\
	else \
		CHAPTER=$(CHAPTER) python3 build.py ;\
	fi
	@$(foreach elf, $(ELFS), \
		$(OBJCOPY) $(elf) --strip-all -O binary $(patsubst $(TARGET_DIR)/%, $(TARGET_DIR)/%.bin, $(elf)); \
		cp $(elf) $(patsubst $(TARGET_DIR)/%, $(TARGET_DIR)/%.elf, $(elf));)
```

相关代码比较长，我们一部分一部分来做分析：

<font color='redorange'>make build</font>执行之前，会做三个前置工作：clean，pre和binary，其中clean从字面意义就可以理解为清理，下面看看<font color='redorange'>make pre</font>:

```makefile
pre:
	@mkdir -p $(BUILD_DIR)/bin/
	@mkdir -p $(BUILD_DIR)/elf/
	@mkdir -p $(BUILD_DIR)/app/
	@mkdir -p $(BUILD_DIR)/asm/
	@$(foreach t, $(APPS), cp $(t) $(BUILD_DIR)/app/;)
```

可以看到，<font color='redorange'>make pre</font>  在<font color='redorange'>user/build</font>目录下创建了$\textcolor{blue}{bin} $  、$\textcolor{blue}{elf} $  、$\textcolor{blue}{app} $  、$\textcolor{blue}{asm} $   4个目录，然后将<font color='green'>$(APPS)</font>中的内容copy到app目录下。APPS中保存着当前命令下被选择执行的应用名。

再来看看<font color='redorange'>make binary</font>:

```makefile
binary:
	@echo $(ELFS)
	@if [ ${CHAPTER} -gt 3 ]; then \
		cargo build --release ;\
	else \
		CHAPTER=$(CHAPTER) python3 build.py ;\
	fi
	@$(foreach elf, $(ELFS), \
		$(OBJCOPY) $(elf) --strip-all -O binary $(patsubst $(TARGET_DIR)/%, $(TARGET_DIR)/%.bin, $(elf)); \
		cp $(elf) $(patsubst $(TARGET_DIR)/%, $(TARGET_DIR)/%.elf, $(elf));)


```

此时chapter = 2，所以运行脚本build.py，这是一个python文件，我们来看看它的内容：

```python
import os

base_address = 0x80400000
step = 0x20000
linker = "src/linker.ld"

app_id = 0
apps = os.listdir("build/app")
apps.sort()
chapter = os.getenv("CHAPTER")

for app in apps:
     app = app[: app.find(".")]
     os.system(
         "cargo rustc --bin %s --release -- -Clink-args=-Ttext=%x"
         % (app, base_address + step * app_id)
    )
      print(
         "[build.py] application %s start with address %s"
         % (app, hex(base_address + step * app_id))
     )
     if chapter == '3':
         app_id = app_id + 1
```

可以看到，当chapter=2时，每个程序入口地址均为0x80400000（其实也可以看出来chapter 3的设计，即app_id增加1，则入口地址往后偏移0x2000B。）

继续看<font color='redorange'>make binary</font>：

```makefile
ELFS := $(patsubst $(APP_DIR)/%.rs, $(TARGET_DIR)/%, $(APPS))
TARGET := riscv64gc-unknown-none-elf
MODE := release
APP_DIR := src/bin
TARGET_DIR := target/$(TARGET)/$(MODE)
binary:
	@echo $(ELFS)
	@if [ ${CHAPTER} -gt 3 ]; then \
		cargo build --release ;\
	else \
		CHAPTER=$(CHAPTER) python3 build.py ;\
	fi
	@$(foreach elf, $(ELFS), \
		$(OBJCOPY) $(elf) --strip-all -O binary $(patsubst $(TARGET_DIR)/%, $(TARGET_DIR)/%.bin, $(elf)); \
		cp $(elf) $(patsubst $(TARGET_DIR)/%, $(TARGET_DIR)/%.elf, $(elf));)
```

<font color='blue'>ELFS</font>中是<font color='green'>$(TARGET_DIR)</font>中存放的编译好的elf文件的路径，通过OBJCOPY工具可以将其处理成.bin为后缀的二进制可执行文件等待执行，再保存一份elf文件，以.elf后缀结尾。

做好这些准备后，执行<font color='redorange'>make build</font>：

```makefile
build: clean pre binary
     @$(foreach t, $(ELFS), cp $(t).bin $(BUILD_DIR)/bin/;)
     @$(foreach t, $(ELFS), cp $(t).elf $(BUILD_DIR)/elf/;)
```

将刚才编译好的.bin和.elf文件分别复制到user/build/bin和user/build/elf下。至此，user目录下的<font color='redorange'>make build</font>完成。

此时，回到了os目录下，执行<font color='redorange'>cargo build</font>，根据cargo的规则，需要在构建时执行os/build.rs:

```rust
fn main() {
     println!("cargo:rerun-if-changed=../user/src/");
     println!("cargo:rerun-if-changed={}", TARGET_PATH);
     insert_app_data().unwrap();
}


static TARGET_PATH: &str = "../user/build/bin/";



fn insert_app_data() -> Result<()> {
     let mut f = File::create("src/link_app.S").unwrap();
     let mut apps: Vec<_> = read_dir("../user/build/bin/")
         .unwrap()
         .into_iter()
         .map(|dir_entry| {
             let mut name_with_ext = dir_entry.unwrap().file_name().into_string().unwrap();
             name_with_ext.drain(name_with_ext.find('.').unwrap()..name_with_ext.len());
             name_with_ext
         })
         .collect();
     apps.sort();


     writeln!(
         f,
         r#"
     .align 3
     .section .data
     .global _num_app
_num_app:
     .quad {}"#,
         apps.len()
     )?;


     for i in 0..apps.len() {
         writeln!(f, r#"    .quad app_{}_start"#, i)?;
     }
     writeln!(f, r#"    .quad app_{}_end"#, apps.len() - 1)?;


     for (idx, app) in apps.iter().enumerate() {
         println!("app_{}: {}", idx, app);
         writeln!(
             f,
             r#"
     .section .data
     .global app_{0}_start
     .global app_{0}_end
app_{0}_start:
     .incbin "{2}{1}.bin"
app_{0}_end:"#,
             idx, app, TARGET_PATH
         )?;
     }
     Ok(())
}
```

这一部分比较复杂，其实就是形成了一个文件link_app.S,其内容为：

```
.align 3
    .section .data
    .global _num_app
_num_app:
    .quad 7
    .quad app_0_start
    .quad app_1_start
    .quad app_2_start
    .quad app_3_start
    .quad app_4_start
    .quad app_5_start
    .quad app_6_start
    .quad app_6_end

    .section .data
    .global app_0_start
    .global app_0_end

app_0_start:
    .incbin "../user/build/bin/ch2b_bad_address.bin"
app_0_end:

    .section .data
    .global app_1_start
    .global app_1_end

app_1_start:
    .incbin "../user/build/bin/ch2b_bad_instructions.bin"
app_1_end:

    .section .data
    .global app_2_start
    .global app_2_end

app_2_start:
    .incbin "../user/build/bin/ch2b_bad_register.bin"
app_2_end:

    .section .data
    .global app_3_start
    .global app_3_end

app_3_start:
    .incbin "../user/build/bin/ch2b_hello_world.bin"
app_3_end:

    .section .data
    .global app_4_start
    .global app_4_end

app_4_start:
    .incbin "../user/build/bin/ch2b_power_3.bin"
app_4_end:

    .section .data
    .global app_5_start
    .global app_5_end

app_5_start:
    .incbin "../user/build/bin/ch2b_power_5.bin"
app_5_end:

    .section .data
    .global app_6_start
    .global app_6_end

app_6_start:
    .incbin "../user/build/bin/ch2b_power_7.bin"
app_6_end:
```

其基本功能为，在内核程序的.data段中存放刚才编译好的各个应用的二进制可执行文件，并且以app_id_start和app_id_end来标识每个app的起点和终点位置。

就此，我们实现了用户程序和内核程序的编译和打包，并且将用户程序形成的二进制文件放入了内核程序的.data段中。



#### 2、构建程序运行所需要的条件

**分配堆栈**

​        程序要正常运行，需要两个栈：分别是用户栈和内核栈。chapter2中一个任务执行完毕后下一个任务才会执行，因此栈空间可以复用。下面的代码就是分配栈：

```rust
#[repr(align(4096))]
struct KernelStack {
     data: [u8; KERNEL_STACK_SIZE],
}

#[repr(align(4096))]
struct UserStack {
     data: [u8; USER_STACK_SIZE],
}

static KERNEL_STACK: KernelStack = KernelStack {
     data: [0; KERNEL_STACK_SIZE],
};
static USER_STACK: UserStack = UserStack {
     data: [0; USER_STACK_SIZE],
};


```

在内核程序的.data段中分配了KERNEL_STACK和USER_STACK的空间供用户程序使用。



**特权级切换机制及相关支持**

​       应用运行在用户态，内核运行在内核态。从用户态到内核态通过中断机制来实现，而用户程序主动陷入内核态的接口被称为系统调用。在chapter2中，我们主要使用的系统调用只有write()和exit()

```rust
//   user/lib.rs
pub fn exit(exit_code: i32) -> ! {
     console::flush();
     sys_exit(exit_code);
}

pub fn write(fd: usize, buf: &[u8]) -> isize {
     sys_write(fd, buf)
}     
```

​       

```rust
pub fn syscall(id: usize, args: [usize; 3]) -> isize {
    let mut ret: isize;
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("x10") args[0] => ret,
            in("x11") args[1],
            in("x12") args[2],
            in("x17") id
        );
    }
    ret
}

pub fn sys_write(fd: usize, buffer: &[u8]) -> isize {
     syscall(SYSCALL_WRITE, [fd, buffer.as_ptr() as usize, buffer.len()])
}


pub fn sys_exit(exit_code: i32) -> ! {
    syscall(SYSCALL_EXIT, [exit_code as usize, 0, 0]);
    panic!("sys_exit never returns!");
}
```

通过ecall命令，用户程序触发了内中断，并传递了必要的参数的寄存器中。

​       内核中也有接受中断的机制：

```rust
// os/trap/mod.rs 
pub fn init() {
    extern "C" {
        fn __alltraps();
    }
    unsafe {
        stvec::write(__alltraps as usize, TrapMode::Direct);
    }
}
```

通过对stvec寄存器的写操作，我们将所有中断的入口设为_alltraps，也就是说只要触发了中断，就会跳转到内核态下的__alltraps位置去运行。下面是   _alltraps位置的内容。

```
__alltraps:
    csrrw sp, sscratch, sp
    # now sp->kernel stack, sscratch->user stack
    # allocate a TrapContext on kernel stack
    addi sp, sp, -34*8
    # save general-purpose registers
    sd x1, 1*8(sp)
    # skip sp(x2), we will save it later
    sd x3, 3*8(sp)
    # skip tp(x4), application does not use it
    # save x5~x31
    .set n, 5
    .rept 27
        SAVE_GP %n
        .set n, n+1
    .endr
    # we can use t0/t1/t2 freely, because they were saved on kernel stack
    csrr t0, sstatus
    csrr t1, sepc
    sd t0, 32*8(sp)
    sd t1, 33*8(sp)
    # read user stack from sscratch and save it on the kernel stack
    csrr t2, sscratch
    sd t2, 2*8(sp)
    # set input argument of trap_handler(cx: &mut TrapContext)
    mv a0, sp
    call trap_handler
```

可以看到，它把各个寄存器的值都保存在了栈中，然后把栈顶地址赋值给了a0，跳转执行trap_handler。

```rust
#[no_mangle]
pub fn trap_handler(cx: &mut TrapContext) -> &mut TrapContext {
    let scause = scause::read();
    let stval = stval::read();
    match scause.cause() {
        Trap::Exception(Exception::UserEnvCall) => {
            cx.sepc += 4;
            cx.x[10] = syscall(cx.x[17], [cx.x[10], cx.x[11], cx.x[12]]) as usize;
        }
        Trap::Exception(Exception::StoreFault) | Trap::Exception(Exception::StorePageFault) => {
            error!("[kernel] PageFault in application, core dumped.");
            run_next_app();
        }
        Trap::Exception(Exception::IllegalInstruction) => {
            error!("[kernel] IllegalInstruction in application, core dumped.");
            run_next_app();
        }
        _ => {
            panic!(
                "Unsupported trap {:?}, stval = {:#x}!",
                scause.cause(),
                stval
            );
        }
    }
    cx
}

// os/src/syscall.rs
pub fn syscall(syscall_id: usize, args: [usize; 3]) -> isize {
    match syscall_id {
        SYSCALL_WRITE => sys_write(args[0], args[1] as *const u8, args[2]),
        SYSCALL_EXIT => sys_exit(args[0] as i32),
        _ => panic!("Unsupported syscall_id: {}", syscall_id),
    }
}
```

产生页错误和非法指令时，会直接执行run_next_app()。接受到系统调用时，则执行syscall()。而syscall()则根据参数选择不同的系统调用实现函数。sys_write在chapter 1中已经实现，下面看一下sys_exit()函数的功能。

```rust
pub fn sys_exit(exit_code: i32) -> ! {
    info!("[kernel] Application exited with code {}", exit_code);
    run_next_app()
}
```

可以看到，当一个任务结束时，也会调用run_next_app()方法去执行下一个任务。所以run_next_app()方法是我们需要实现的核心方法。在此之前，需要先了解从内核态恢复到用户程序的方法_restore：

```
__restore:
    # case1: start running app by __restore
    # case2: back to U after handling trap
    mv sp, a0
    # now sp->kernel stack(after allocated), sscratch->user stack
    # restore sstatus/sepc
    ld t0, 32*8(sp)
    ld t1, 33*8(sp)
    ld t2, 2*8(sp)
    csrw sstatus, t0
    csrw sepc, t1
    csrw sscratch, t2
    # restore general-purpuse registers except sp/tp
    ld x1, 1*8(sp)
    ld x3, 3*8(sp)
    .set n, 5
    .rept 27
        LOAD_GP %n
        .set n, n+1
    .endr
    # release TrapContext on kernel stack
    addi sp, sp, 34*8
    # now sp->kernel stack, sscratch->user stack
    csrrw sp, sscratch, sp
    sret
```

__restore有一个参数为将要恢复的任务的上下文地址，即该任务陷入内核态时的栈顶地址。根据任务的上下文可以恢复该任务。sret指令使系统返回用户态。



**任务上下文以及实现任务跳转**

​        任务上下文包含该任务运行的全部信息，内核态下，通过把这些内容放入对应的寄存器中，就可以跳转到对应的任务中。任务上下文的结构为：

```rust
#[repr(C)]
pub struct TrapContext {
    pub x: [usize; 32],
    pub sstatus: Sstatus,
    pub sepc: usize,
}

impl TrapContext {
    pub fn set_sp(&mut self, sp: usize) {
        self.x[2] = sp;
    }
    pub fn app_init_context(entry: usize, sp: usize) -> Self {
        let mut sstatus = sstatus::read();
        sstatus.set_spp(SPP::User);
        let mut cx = Self {
            x: [0; 32],
            sstatus,
            sepc: entry,
        };
        cx.set_sp(sp);
        cx
    }
}
```

x为寄存器的值，sstatus为此时状态寄存器的值，sepc为返回时任务继续执行的代码地址。

​      在chapter2中，程序运行时各通用寄存器的值并不重要，所以赋值为0，需要给定的值为sepc的值和sp(对应TrapContext在x[2]中存放）的值，TrapContext中的所有寄存器的值作为_restore的参数时都会被推入到对应的寄存器中，因此设sstatus.set_spp(SPP::User)，则在_restore的过程中系统会进入用户态。显然，在chapter2中，对于每个任务来说，它的sepc都应该置为0x80400000，sp置为USER_STACK。并且，为了跟_restore接口一致，在任务切换之前，应该把对应的TrapContext推入内核栈中，给出对应的栈的地址作为参数，另外，应该把该任务的代码从.data中取出，放入以0x80400000为起点的代码段中。

```rust
struct AppManager {
    num_app: usize,
    current_app: usize,
    app_start: [usize; MAX_APP_NUM + 1],
}

impl AppManager {
    pub fn print_app_info(&self) {
        info!("[kernel] num_app = {}", self.num_app);
        for i in 0..self.num_app {
            info!(
                "[kernel] app_{} [{:#x}, {:#x})",
                i,
                self.app_start[i],
                self.app_start[i + 1]
            );
        }
    }

    unsafe fn load_app(&self, app_id: usize) {
        if app_id >= self.num_app {
            panic!("All applications completed!");
        }
        info!("[kernel] Loading app_{}", app_id);
        // clear icache
        core::arch::asm!("fence.i");
        // clear app area
        core::slice::from_raw_parts_mut(APP_BASE_ADDRESS as *mut u8, APP_SIZE_LIMIT).fill(0);
        let app_src = core::slice::from_raw_parts(
            self.app_start[app_id] as *const u8,
            self.app_start[app_id + 1] - self.app_start[app_id],
        );
        let app_dst = core::slice::from_raw_parts_mut(APP_BASE_ADDRESS as *mut u8, app_src.len());
        app_dst.copy_from_slice(app_src);
    }

    pub fn get_current_app(&self) -> usize {
        self.current_app
    }

    pub fn move_to_next_app(&mut self) {
        self.current_app += 1;
    }
}

lazy_static! {
    static ref APP_MANAGER: UPSafeCell<AppManager> = unsafe {
        UPSafeCell::new({
            extern "C" {
                fn _num_app();
            }
            let num_app_ptr = _num_app as usize as *const usize;
            let num_app = num_app_ptr.read_volatile();
            let mut app_start: [usize; MAX_APP_NUM + 1] = [0; MAX_APP_NUM + 1];
            let app_start_raw: &[usize] =
                core::slice::from_raw_parts(num_app_ptr.add(1), num_app + 1);
            app_start[..=num_app].copy_from_slice(app_start_raw);
            AppManager {
                num_app,
                current_app: 0,
                app_start,
            }
        })
    };
}
```

AppManeger是管理App的数据结构，对各个App的运行情况做一个整体的描述，而APP_MANAGER是AppManeger的一个实体，用来管理当前运行的App，这种先定义管理结构再用lazy_static!定义全局实体的方式在实验中经常出现。可以看到，通过load_app(app_id)，就可以把对应app_id的app代码加载到预定区域。在此基础上，我们最终实现了run_next_app()：

```rust
pub fn run_next_app() -> ! {
    let mut app_manager = APP_MANAGER.exclusive_access();
    let current_app = app_manager.get_current_app();
    unsafe {
        app_manager.load_app(current_app);
    }
    app_manager.move_to_next_app();
    drop(app_manager);
    // before this we have to drop local variables related to resources manually
    // and release the resources
    extern "C" {
        fn __restore(cx_addr: usize);
    }
    unsafe {
        __restore(KERNEL_STACK.push_context(TrapContext::app_init_context(
            APP_BASE_ADDRESS,
            USER_STACK.get_sp(),
        )) as *const _ as usize);
    }
    panic!("Unreachable in batch::run_current_app!");
}
```



以上，即为**chapter2：批处理操作系统**的主要结构。