# 710 MB libtprt Trace：运行内容分析

> 输入：`/Users/ashenone/work/tools/GumTrace/artifacts/avm_follow.log`
> 大小：710,614,235 B / 7,655,977 行 GumTrace
> 采集线程：Android 主线程
> 模块：`libtprt.so`（单模块 Trace）
> 结论性质：运行期观察 + 静态反汇编交叉验证；VM 脚本语义仍是推断

## 结论摘要

这段 Trace 的主体不是普通 JNI/网络业务，而是 **libtprt 内部的一个
32 位线程化解释器（threaded-code VM）及其调度器**。

观察到的事实：

- `libtprt` 的 `0x137b44` 遍历一个 VM context 链表，对每个 context 调用
  解释器 `0x137c28`；解释器以 `0x249f0`（150,000）为一次执行预算。
- `0x137c40–0x137d20` 是解释器主循环：从 context 的 `+0x178` 取 VM 内存/
  指令流，`PC=x24`、`instruction_index=x24>>2`，从 `+0x68` 取每指令 handler
  表，读取 32 位指令字，然后 `blr` 到 handler。
- Context 的 VM 寄存器位于 `+0x100 + 8*n`，PC 在 `+0x108`，flags 在
  `+0x110`，分支/PC 更新标志在 `+0x120`，VM 内存基址在 `+0x178`。
- 本次 Trace 共执行 **123,946 条 VM 指令**，覆盖 **3,889 个唯一指令索引**、
  **56 种 handler**；程序索引范围约 `0xa78–0x9428`（约 35K 条指令）。
- 其中约 26,750 次是同一个 4 指令循环：`0x85f9–0x85fc`，分别执行
  “存字节 / 加立即数 / 比较并写 flags / 条件分支”。
- 该循环向 VM 内存写入了 27,140 个字节、16,769 个地址；写入的字符串包括
  `com.manjuu.promilia`、`VM_TprtHashCaculator`、
  `VM_TprtHashCaculator_nofuse`、`!do invoke crash, key:%s, desc:%s`、
  `ExitKey`、`#*038.Quit` 和一个 29 字符十六进制 key。

推断：

- 这是 libtprt 内部的 **VM 脚本运行时**，不是 `libtersafe2` 的 AVM；
  两者的指令形态、context 布局和 handler 都不同。
- 脚本正在构造应用/模块标识、HashCalculator 名称、key 和崩溃/退出路径，
  很可能是 **启动期的完整性/哈希校验或反篡改检查**。Trace 中大量
  `pthread_mutex`、`access`、`malloc/memcpy`、`inet_ntop`、socket 调用
  与这一用途相符，但它们只占少数，主体仍是 VM 计算。
- 4 指令热循环不是业务计算本身，而是 **字符串/数据表的逐字节构造循环**；
  它把包名和其他标识写入 VM 内存，后续 handler 再进行算术、比较和调用。

## 1. 解释器与调度器

### 1.1 调度器 `0x137b44`

静态反汇编：

```asm
0x137b44  stp x29, x30, [sp, #-0x40]!
0x137b58  ldr x23, [x0]              ; VM context list head
0x137b78  ldr w9, [x23, #0x128]      ; context status
0x137b88  add x0, x23, #0x10         ; VM context
0x137b90  bl #0x137c28               ; run interpreter slice
0x137bc0  ldr x23, [x23]             ; next context
0x137bc4  cbnz x23, #0x137b78
```

调用点 `0x137b08` 传入的预算为：

```text
mov w2, #0x49f0
movk w2, #2, lsl #16    ; w2 = 0x249f0 = 150,000
```

因此这不是单个函数的普通循环，而是 **多 VM context 的时间片调度器**。

### 1.2 解释器 `0x137c28`

关键循环：

```asm
0x137c40  ldr x22, [x0, #0x178]      ; VM memory / instruction stream
0x137c60  ldr x24, [x19, #0x108]     ; PC (byte address)
0x137c78  lsr x25, x24, #2           ; instruction index
0x137c84  ldr x8, [x21, x25, lsl #3] ; per-index handler
0x137c88  ldr w0, [x22, x25, lsl #2] ; 32-bit instruction word
0x137c8c  blr x8                     ; execute handler
0x137c98  ldr x8, [x19, #0x108]      ; handler may update PC
0x137c9c  cmp x8, x24
0x137ca0  b.ne #0x137cc0
0x137ca8  add x24, x24, #4           ; default: next instruction
0x137cac  str x24, [x19, #0x108]
```

这是典型的 **threaded-code interpreter**：每条指令有一个 handler 指针，
handler 接收 `w0`（32 位指令字）和 `x1`（VM context）。

### 1.3 Context 布局

从 handler 和 Trace 观察到的字段：

| Context 偏移 | 作用 |
|---|---|
| `+0x68` | 每指令 handler 表 |
| `+0x100 + 8*n` | VM 虚拟寄存器 |
| `+0x108` | VM PC（字节地址） |
| `+0x110` | VM flags |
| `+0x118` | stop/loop 标志 |
| `+0x120` | handler 修改 PC/分支标志 |
| `+0x128` | 当前时间片已执行计数 |
| `+0x12c` | 累计执行计数 |
| `+0x178` | VM 扁平内存/指令流基址 |
| `+0x188` | VM active 标志 |
| `+0x190` | 函数/对象查找上下文 |

本次 Trace 的运行时地址：

```text
module base      = 0x7a2dd3f000
VM context       = 0x7b6cb21010
VM memory        = 0x7aa6dca000
handler table    = 0x7a31e05dc0
```

## 2. VM 指令集与执行分布

### 2.1 指令编码

指令是 32 位字，至少包含以下字段：

- bits 0–4：目标/基址寄存器，31 表示特殊寄存器；
- bits 5–9：源寄存器；
- bits 10–21：12 位立即数/偏移；
- bit 22：立即数缩放/模式；
- bit 31：符号/方向。

例如 handler `0x14165c` 解码 `UBFX w9,w0,#5,#5`、`UBFX w11,w0,#10,#12`、
`AND w9,w0,#0x1f`，然后写 `ctx+0x100+8*n`，是加法/立即数类指令。

已确认的 handler：

| 偏移 | 作用（静态判读） |
|---|---|
| `0x14165c` | 立即数加法/寄存器更新 |
| `0x1416d0` | 64 位寄存器 ALU/组合运算 |
| `0x1420f4` | 条件分支，更新 VM PC |
| `0x142150` | 通过 `ctx+0x190` 查找并调用目标 |
| `0x143e84` | 位域/移位/掩码操作 |
| `0x1449fc` | 存字节到 VM 扁平内存 |
| `0x14504c` | 比较/减法并写 VM flags |
| `0x13a810` | host bridge（调用宿主内存函数） |
| `0x13aac4` | host bridge（调用宿主函数） |

这组 handler 足以证明它是完整的 VM，而不是普通事件回调。

### 2.2 执行统计

| 指标 | 数值 |
|---|---:|
| VM 指令执行次数 | 123,946 |
| 唯一指令索引 | 3,889 |
| handler 种类 | 56 |
| 指令索引范围 | `0xa78–0x9428` |
| 最热 4 条指令 | `0x85f9–0x85fc`，各约 26,750 次 |

最热循环：

| VM 索引 | Handler | 32 位字 | 作用 |
|---|---|---|---|
| `0x85f9` | `0x1449fc` | `0x9caa6528` | 存字节 |
| `0x85fa` | `0x14165c` | `0x9980094a` | 加立即数 |
| `0x85fb` | `0x14504c` | `0xc340095f` | 比较/flags |
| `0x85fc` | `0x1420f4` | `0xc1ffffb1` | 条件分支回跳 |

这是一个 **逐字节构造/拷贝循环**，不是哈希压缩本身。它写了 27,140 个字节，
覆盖 16,769 个地址。

## 3. 写入的字符串与可能的用途

从 `0x144a78`（`strb w22,[x8,x0]`）的 `mem_w` 与寄存器值重建出的连续
可打印内容：

| 运行时地址 | 内容 |
|---|---|
| `0x7aa6dfece8` | `com.manjuu.promilia` |
| `0x7aa6dfea58` | `VM_TprtHashCaculator` |
| `0x7a31c92000` | `VM_TprtHashCaculator_nofuse` |
| `0x7a9419a155` | `#*038.Quit` |
| `0x7a9419a196` | `!do invoke crash, key:%s, desc:%s` |
| `0x7a9419b4f7` | `ExitKey` |
| `0x7a31e8b6c0` | `8F651F6FEAC9FE4C077CC3320000` |

这些不是普通游戏业务字符串，而是应用标识、HashCalculator 名称、退出/崩溃
路径和一个十六进制 key 的组合。

`libtprt.so` 的静态 `.rodata`（文件偏移 `0x19ba68` 附近）还存在一段元数据：

```text
367e52eb8b7becaafd11dcb2278b4e7d
9743d6f974639d68913c96054ade1774
b28345760256250032a41f24dfbca1fe
*U*I*N*F*L*T*F*
#T#A#P#I#P*O#E#
com.manjuu.promilia
libtprt.so
0.3.0
2022.3.62f3
```

三个 128 位十六进制值很像哈希/签名；包名、库名、版本和 Unity 版本是明确的
环境标识。`VM_TprtHashCaculator` 等运行时字符串不在该静态明文中，说明 VM
还构造/解出了额外的标识。

## 4. Host 调用

Trace 中调用注解统计：

| 函数 | 次数 |
|---|---:|
| `pthread_mutex_lock` / `unlock` | 169 / 169 |
| `memcpy_generic` | 60 |
| `__strlen_aarch64` | 36 |
| `memset` | 30 |
| `free` | 21 |
| `malloc` | 19 |
| `access` | 7 |
| `inet_ntop` | 7 |
| `random` | 5 |
| `sendto` / `select` / `recvfrom` | 4 / 3 / 3 |
| `socket` / `connect` / `close` | 各 1 |

与 123,946 条 VM 指令相比，host 调用很少，说明这段时间主要在执行 VM 计算；
host 侧主要用于锁、内存、字符串、文件访问和少量网络/环境探测。

## 5. 判断与边界

可以确认：

- `libtprt` 内存在 32 位线程化解释器/调度器；
- 本次 Trace 执行的是一个真实 VM 程序，不是普通回调循环；
- 热循环在构造字节串/数据；
- 构造内容直接包含包名、HashCalculator 名称、退出/崩溃路径和 key。

合理推断：

- 该 VM 很可能属于 tprt 的启动期完整性/哈希校验或反篡改脚本；
- `VM_TprtHashCaculator` / `_nofuse` 是校验或降级路径的候选；
- `!do invoke crash`、`ExitKey`、`#*038.Quit` 可能是校验失败后的处理。

仍未知：

- 32 位指令集的完整 opcode 映射；
- VM 脚本的完整控制流和哈希算法；
- `8F651F...` 是期望值、密钥还是中间结果；
- 该 VM 与 `a64.dat` 的精确关系；
- 为什么启动期有如此长的 VM 计算（本次采集窗口内仍未结束）。

不能把“HashCaculator”字符串直接当成已确认的哈希算法，也不能把该 VM
与 `libtersafe2` 的 AVM 混为一谈；两者是不同模块中的两套运行时。
