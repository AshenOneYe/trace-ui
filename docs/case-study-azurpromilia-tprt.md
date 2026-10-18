# AzurPromilia / tprt AVM 能力评估

> 评估日期：2026-10-18
> Trace UI 基线：`23cdb74`（`feat: add staged large-trace and VM analysis platform`）
> 外部样本：`/Volumes/SMB/work/il2cpp-reverse/AzurPromilia/tprt`（只读）
> 评估性质：静态证据审阅 + AVM 形态合成探针 + 真机 GumTrace 尝试；
> **已获得 GumTrace 日志，但尚无包含 AVM 的 Trace**

## 结论摘要

Trace UI 的 VM 分析方向与目标匹配，输入格式也匹配，但**当前还不能宣称已经分析
了 AzurPromilia 的真实 AVM**。

可以确认的部分：

- `libtersafe2.so` 中存在 AVM / `Antzhu_VM`，有平铺客户机内存
  `PmemRead/PmemWrite(paddr_t, width)` 和巨型解释器函数。
- `sub_35DCD0` 内存在大量宿主 `br` 跳转表，guest 字节取指位于
  `0x35dfc4`–`0x35dfe4`；真实 Trace 中这些点可以被 Trace UI 的
  间接跳转发现逻辑看到。
- 只要把**正确的单一 guest 分发点**交给现有分析器，handler 切分和聚类可以工作；
  合成对照中 16 个 handler 区间、5 个 cluster、0 个重叠区间。

当前不能确认的部分：

- 还没有一份包含 AVM 的真实执行 Trace，因此没有验证真实 handler 语义、真实虚拟
  CFG、跨运行聚类或 `a64.dat` 的关系。
- 现有算法会把 OLLVM 状态分发、7 路 guest 跳转表和嵌套跳转表都当成
  dispatcher。合成探针中 3 个真实跳转点产生了 38 个候选，并出现 67 对重叠的
  handler 区间。
- 现有 `VirtualPc` 推断取“间接跳转寄存器”，会把 `x8`/`x13`/`x14` 这类跳转表
  寄存器误标成 VPC；真正参与 guest 取指的 `x25` 反而不会被识别。
- 现有“VM IR / CFG”描述的是宿主 ARM64 handler 区间，不是 guest 指令集语义。
- 在真实的 710 MB `libtprt` Trace 上，索引只需 3.2 秒，但 VM 分析在 10 万行
  就产生 1,560 个 dispatcher 候选，50 万行耗时 112 秒，全量无法在可接受时间内
  完成。

因此当前评价是：**基础管线可用，AVM 专用语义层尚未通过真实样本验证；需要先取得
真实 Trace，并补齐 dispatcher 归类、站点去重和 VPC 推断，才能完成验收。**

## 1. 输入材料与静态事实

已读取的核心文档：

- `docs/README.md`
- `docs/ARCHITECTURE-tprt.md`
- `docs/ARCHITECTURE-tersafe2.md`
- `docs/OBFUSCATION.md`
- `docs/FINDINGS.md`
- `docs/METHODOLOGY.md`
- `docs/DYNAMIC-PLAN.md`
- `docs/HANDOFF.md`
- `docs/TECHNIQUES.md`

关键静态证据：

| 证据 | 位置 | 说明 | 强度 |
|---|---|---|---|
| AVM 符号 | `@0xa81db`、`@0xa8214` | `AVM::BopMemoryOperation::PmemRead/PmemWrite` | 已确认 |
| 内部代号 | `@0xab619` | `Antzhu_VM` | 已确认 |
| 客户机内存模型 | `sub_332EB8 @ 0x332eb8` | 按 1/2/4/8 字节读写 `*(ctx+8)+paddr` | 已确认 |
| 巨型函数 | `sub_35DCD0 @ 0x35dcd0` | 76,164 B，1,789 基本块，单 switch 1,580 case | 已确认 |
| 第二巨型函数 | `sub_3332F4 @ 0x3332f4` | 69,836 B，2,527 基本块 | 已确认 |
| guest 取指 | `0x35dfc4`–`0x35dfe4` | `LDRB` 客户机字节 → `AND #0xF` → 7 路 switch | 已确认 |
| 目标 ISA | — | 未定；文档已收回“ARM64 模拟器”推断 | 未知 |
| `a64.dat` | `libtprt.so @ 0x174bba` | APK 内不存在，运行期生成/解出 | 待运行期确认 |

`sub_35DCD0` 的取指/分发片段（静态反汇编）：

```asm
0x35dfc0  br x8                     ; OLLVM 状态表候选
0x35dfc4  ldr x8,  [sp, #0xe8]      ; VM 上下文
0x35dfc8  ldr x8,  [x8]
0x35dfcc  ldr x11, [x8, #8]         ; 客户机内存基址
0x35dfd0  add x10, x11, x25         ; 基址 + 客户机 PC 候选
0x35dfd4  ldrb w12, [x10, #1]       ; 取 guest 指令字节
0x35dfd8  and w8, w12, #0xf
0x35dfdc  subs w9, w8, #5
0x35dfe0  cmp w9, #6
0x35dfe4  b.hi 0x35e46c
0x35dff8  adr x14, 0x35e010
0x35dffc  ldrh w15, [x13, x9, lsl #1]
0x35e000  add x14, x14, x15, lsl #2
0x35e00c  br x14                    ; 7 路 guest 跳转表
0x35e02c  br x13                    ; 嵌套 4 路跳转表
```

代码统计（Capstone 反汇编，只读检查）：

- `sub_35DCD0` 内共有 **782** 个 `br`/`blr` 点。
- `sub_3332F4` 内共有 **677** 个 `br`/`blr` 点。
- `0x35dfc0` 的 `br x8` 前有 `ldr x8, [x21, w8, uxtw #3]`，且用
  `mov w8, #0x5c2` 作为候选索引；这与文档所述 1,580-case 状态表吻合。

### 结构判读

以下是从上述证据得到的推断，不是已经由运行 Trace 证实的事实：

1. `0x35dfc0` 更像 **OLLVM 控制流平坦化的状态分发**，不是 guest 操作码分发。
2. `0x35dfc4`–`0x35dfe4` 是 guest 指令取指/字段提取。
3. `0x35e00c` 是 7 路 guest 跳转表，`0x35e02c` 是嵌套 4 路跳转表；真实
   handler 切分应优先围绕这些点，而不是 `0x35dfc0`。
4. `x25` 是 guest PC 的有力候选；`x11` 是客户机内存基址；`x10` 是本次取指的
   临时地址，不是稳定的 bytecode base。

这些区别对 Trace UI 很关键：当前算法只看“间接跳转点是否有多个目标”，无法区分
上述三种控制转移。

## 2. Trace UI 的输入兼容性

Trace UI 接受两种宿主 ARM64 指令级 Trace：

- **GumTrace**：`[module] 0xABS!0xOFFSET mnemonic ...; xN=0x...`
- **Unidbg**：README 所述定制格式，内存读写需要 `mem[READ/WRITE] abs=0x...`

对本 AVM，采集时必须满足：

1. `br xN` / `blr xN` 行带 `xN=0x...`，否则
   `phase2::extract_blr_target` 返回 0，dispatcher 无法建立目标集合。
2. guest 内存读写带绝对地址（GumTrace 的 `mem_r=`/`mem_w=`，或 Unidbg 的
   `mem[READ/WRITE] abs=`），否则状态和内存证据为空。
3. Trace 包含 `libtersafe2.so` 的模块名/绝对地址，最好同时保存
   `/proc/<pid>/maps`，用于把绝对地址换算回 IDA 偏移。

现有 VM 事件只保留绝对地址，`DispatcherCandidate`、`VmStateCandidate` 和
evidence 中没有模块基址/相对偏移。GumTrace 行里其实已有 `!0xOFFSET`，但解析后
没有进入 VM 结果。这会导致：

- 不同 ASLR 运行的地址无法稳定对比；
- 结果不能直接回查 IDA 的 `0x35dcd0`/`0x35e00c`；
- 跨 Trace 的 cluster/evidence 对齐缺少可靠锚点。

## 3. AVM 形态合成探针

真实 Trace 缺失时，用合成样本只能验证“结构行为”，不能证明真实 AVM 语义。
探针位于：

[`crates/trace-core/tests/vm_avm_shape_probe.rs`](../crates/trace-core/tests/vm_avm_shape_probe.rs)

探针把真实偏移映射到一个合成基址，构造 132 条宿主事件、16 次 guest 指令循环，
并交错使用三个间接跳转点：

- `+0x35dfc0`：OLLVM 状态表，2 个目标；
- `+0x35e00c`：7 路 guest 表，4 个目标；
- `+0x35e02c`：嵌套表，2 个目标；
- 每次 `ldrb` 附带 guest 内存读地址；
- handler 末尾回到 `+0x35dfc0`。

复现命令：

```bash
cargo test -p trace-core --test vm_avm_shape_probe -- --ignored --nocapture
```

关键输出：

```text
events=132 regions=1 dispatchers=38 handlers=36 clusters=12 states=13 cfg_edges=71
unique_dispatcher_sites=3 handler_intervals_with_end_before_entry=0 overlapping_handler_pairs=67
state role=VirtualPc location=reg:x13
state role=VirtualPc location=reg:x14
state role=VirtualPc location=reg:x8
state role=VmContext location=reg:x10
state role=BytecodeBase location=reg:x10
cfg fallthrough=35 conditional=0 unconditional=20 uncertain=16
single_site dispatchers=16 handlers=16 clusters=5 overlapping_handler_pairs=0
single_site state role=VirtualPc location=reg:x14
```

对照实验只保留 `+0x35e00c` 作为间接分发点，结果是 16 个 handler、5 个 cluster、
0 个重叠区间。说明：

- **handler 切分本身不是完全不可用**，问题主要在于把多个跳转点混在一起；
- dispatcher 仍按“每次执行”生成候选（16 次执行 → 16 个候选），而不是按站点聚合；
- 即使只剩正确站点，`VirtualPc` 仍被标成 `x14`，而不是 `x25`。

探针中的 67 对重叠区间是合成结果，不代表真实 Trace 的精确数量；它证明的是
多分发点交错时现有切分逻辑会产生系统性重叠，而不是偶发噪声。

## 4. 能力矩阵

| 能力 | 当前表现 | 评价 |
|---|---|---|
| GumTrace/Unidbg 解析 | 支持两种格式，自动检测 | 格式层面匹配 |
| AVM 区域发现 | 能看到重复执行和间接跳转 | 区域会偏宽，CFF 会放大 |
| dispatcher 候选 | 能发现多目标间接跳转 | 每次执行生成一个候选；CFF/guest 表混杂 |
| handler 切分 | 单一正确站点下可用 | 多站点交错时大量重叠 |
| handler 聚类 | 按助记符+寄存器数量模板哈希 | 忽略立即数/内存偏移/入口地址，易合并或拆分 |
| VPC 推断 | 取间接跳转寄存器 | 在本样本上会误判 `x8/x13/x14` |
| guest 内存模型 | 可记录绝对读写地址 | 未建立 `[ctx+8]`、`x11`、`x25` 的数据流 |
| VM IR | 汇总宿主 ARM64 指令 | 不是 guest ISA 语义 |
| 虚拟 CFG | 使用宿主分支目标和执行顺序 | 不是 VPC 驱动的 guest CFG |
| 证据/假设工作流 | evidence-linked hypothesis、锁定/撤销 | 设计可用，是当前最强部分 |
| 跨 Trace 对比 | 基于本地 cluster 序列 | 缺模块偏移归一化，跨 ASLR 运行不可靠 |
| 大 Trace | 有分级索引和持久任务 | VM 分析仍逐行解析指定范围，需定向采集 |

## 5. 阻塞问题与优先级

### P0：dispatcher 必须按站点聚合和分类

现状代码：

- `find_dispatchers` 对每个执行行 push 一个候选；
- handler 切分用 `dispatches.get(dispatch_index + 1).line`，但候选按地址排序，
  不是按行号排序；
- 所有多目标 `br` 都被同等对待。

建议：

1. 按 `address` 聚合：一个站点一个候选，累计 target set、执行次数和行范围。
2. 候选按首次执行行号排序后再切分区间。
3. 增加 AVM 专用签名评分：
   - 站点前存在 guest 内存 `LDRB`；
   - 存在 `AND #0xF`/移位/比较；
   - 存在 `LDRH`/表项加载 + `ADD` + `BR`；
   - 目标集合落在 handler 入口附近。
4. 单独标记 OLLVM 状态分发：目标集合是同一函数内的状态块，通常共享后继集合，
   不应作为 guest handler 切分点。

### P0：VPC 不能等于间接跳转寄存器

现状 `infer_state_candidates` 把 `indirect_register` 直接标为 `VirtualPc`。在本样本中：

- `x8` 是 OLLVM 状态表目标；
- `x14`/`x13` 是 guest 跳转表目标；
- `x25` 才参与 `base + guest_pc` 取指。

建议增加数据流规则：

1. 识别 `ADD addr_reg, mem_base_reg, pc_reg`；
2. 紧随其后出现 `LDRB/LDRH/LDR [addr_reg + imm]`；
3. 把 `pc_reg` 作为 VPC 候选，把 `mem_base_reg` 作为客户机内存基址候选；
4. 跟踪 `pc_reg` 在 handler 之间的写入，推断 guest 指令长度和下一 VPC；
5. 区分 `BytecodeBase`（稳定基址）与 `BytecodeCursor`（当前取指地址）。

### P0：guest ISA 语义缺失

当前 `infer_semantics` 和 `operation_for_mnemonic` 处理的是宿主 ARM64 助记符。
对 AVM 来说，handler 内部的 `ldrb/and/subs` 不等于 guest 指令的 `load/and/sub`。

在目标 ISA 未定之前，最多只能做：

- handler 模板聚类；
- 宿主执行序列/热点；
- 候选语义和 unknown effects；

不能输出“已恢复 guest 指令语义”或“已恢复完整虚拟 CFG”。

### P1：聚类与 CFG

- `template_hash` 只哈希助记符和寄存器数量，建议加入入口偏移、立即数、内存偏移、
  调用目标，并对 helper 调用做折叠。
- 虚拟 CFG 现在依赖宿主 `branch_target` 是否等于某个 handler 入口。AVM 的
  handler 通常回到分发器，而不是直接跳到下一个 handler；应改为根据两次 dispatch
  之间的 VPC 变化建立 `observed_next_vpc` 边，并明确标记“执行顺序边”和
  “条件边”的区别。
- 跨 Trace 对比应把绝对地址归一化为模块偏移，并使用稳定 handler 特征，而不是
  本地 `cluster-N` 序号。

### P2：采集规模

GumTrace 的逐指令寄存器和内存快照会非常大。建议只采集：

- `libtersafe2.so`；
- `sub_35DCD0` / `sub_3332F4` 及其调用路径；
- 固定数量的 guest dispatch 或固定时间窗；
- 必需的 `br` 寄存器值和内存绝对地址。

不要默认采集全进程长时间 Trace。

## 6. 真实样本验收标准

取得真实 Trace 后，至少满足以下条件才可把“支持该 AVM”从推断升级为验证：

1. **可回查地址**：Trace 同时保存模块映射，`+0x35e00c`、`+0x35e02c`、
   `+0x35dfc4` 能在结果中定位。
2. **dispatcher 正确归类**：`+0x35e00c` 被识别为 guest 分发点；
   `+0x35dfc0` 不被当作唯一 handler 切分点。
3. **VPC 证据**：`x25`（或对应栈槽）被列为 VPC 候选，并有 `ADD`/`LDRB`
   数据流证据；跳转表寄存器不被列为唯一 VPC。
4. **handler 稳定性**：同一 guest 程序在 3 次运行、至少 2 个 ASLR 基址下，
   handler cluster 数量和代表模板稳定；人工抽查至少 10 个 cluster 的语义。
5. **guest CFG**：边来自 VPC 转移，能区分顺序边、条件边和未观测边；
   不再把“宿主分支目标等于 handler 入口”作为主依据。
6. **真实内存模型**：能显示客户机内存基址 `[ctx+8]`、guest 读写地址和宽度，
   并与 `PmemRead/PmemWrite` 的调用证据对应。
7. **可重复性**：固定输入 Trace 的分析结果确定；同一 Trace 重跑得到相同
   hypothesis/evidence。

## 7. 真实 Trace 采集方案

当前环境：

- `adb devices`：`9a2c471`，`arm64-v8a`，Android 13；
- 已安装 `com.manjuu.promilia`；
- 目标进程当前**未运行**；
- 项目规则要求不得擅自重启客户端，因此本次没有启动游戏。

建议采集步骤（需要用户允许启动客户端后执行）：

1. 启动 `com.manjuu.promilia`，等待 `libtersafe2.so` 加载。
2. 保存 `/proc/<pid>/maps`，记录 `libtersafe2.so` 基址。
3. 用 GumTrace/Frida Stalker 只跟踪 `libtersafe2.so` 的目标范围：
   - `sub_35DCD0 @ +0x35dcd0`；
   - `sub_3332F4 @ +0x3332f4`；
   - 其直接调用路径。
4. 打开寄存器快照和内存读写绝对地址；确保 `br xN` 行带 `xN=0x...`。
5. 采集固定数量的 dispatch（例如 20,000–100,000 条宿主指令），或固定
   10–30 秒窗口，并限制文件大小。
6. 至少重复 3 次，覆盖不同 ASLR 基址；保留原始 Trace、maps 和采集脚本版本。
7. 用 `trace-cli index --file <trace>` 建索引，再通过 MCP
   `start_analysis_job(kind="vm_analysis", ...)` 或 GUI 的 VM Analysis 运行。

若采集时进程因反调试静默退出，按 `docs/DYNAMIC-PLAN.md` 的建议先挂
`exit_group/_exit` 定位，不要 patch 目标代码。

### 7.1 实机尝试结果（2026-10-18，未取得 AVM Trace）

使用 GumTrace `main`（Frida Gum 17.8.3 静态库，NDK 26.3 构建）和本机
`9a2c471`（arm64-v8a / Android 13）进行了采集。结果是：

| 步骤 | 结果 |
|---|---|
| 原版库基线启动 | 约 10 秒后 `stack corruption detected`，SIGBUS |
| 授权相机/存储/通知/录音权限 | 仍在约 10 秒退出，权限弹窗不是根因 |
| Frida 17.5.1 spawn | 报 “jailed Android”，无法 spawn |
| root 启动 17.9.1 `florida-server` | spawn 成功 |
| Hook `+0x35dcd0` / `+0x3332f4` | 进程在 AVM 命中前终止，无 hit |
| 无 hook、跟踪主线程 | 成功产出 710,614,235 B / 7,655,977 行日志，但 100% 为 `libtprt.so`，没有 `libtersafe2.so` |
| 跟踪第二游戏线程 | 产出 69 KB / 296 KB 日志，包含 `libtersafe2.so`，但停在 `+0x4c937c`，没有 AVM 偏移 |
| 延迟 7 秒挂载 / Stand 模式 | 进程提前退出或日志为 0 B |
| 补丁库（`kill/_exit/exit → getpid`） | 基线存活时间延长到约 25 秒，但仍周期崩溃；没有改变 AVM 采集结果 |

关键观察：

- 游戏线程一挂 Stalker 就快速退出，Trace 总在同一段
  `libtersafe2 +0x4c937c`（`blr x8` 返回后的 `ldr w8, [sp]`）附近结束。
- 主线程可以稳定跑 12 秒，但没有执行 `libtersafe2`，因此只能证明 GumTrace
  链路可用，不能用于 AVM 评估。
- `libtersafe2` 的 AVM 入口在整个尝试窗口内没有被观察到。
- 设备的 ftrace 只有 `kprobe_events`，没有 `uprobe_events`，无法用 uprobe
  先定位调用线程。

本次尝试的结论是：**在当前的 root/Frida/反调试环境下，GumTrace 能产出宿主
ARM64 日志，但不能稳定跟踪执行 AVM 的游戏线程，因此没有拿到可用于验证
VM 分析能力的真实 AVM Trace。**

实机侧已恢复：

- `libtersafe2.so`、`libtprt.so`、`libmsaoaidsec.so` 已恢复原始哈希；
- 本次授予的运行时权限已撤销；
- 本次启动的 `florida-server` 已停止；
- 设备上的临时 `avm_*.log` 和大体积 Trace 已删除。

本地保留的采集产物（不进入仓库）：

- `/Users/ashenone/work/tools/GumTrace/`：GumTrace 源码、构建产物和采集脚本；
- `/Users/ashenone/work/tools/GumTrace/artifacts/avm_follow.log`：710 MB
  主线程日志，仅含 `libtprt.so`；
- `/Users/ashenone/work/tools/GumTrace/artifacts/avm_thread.log`、
  `avm_thread5.log`：包含 `libtersafe2.so` 的短日志，未到 AVM。

后续若要继续，必须先解决“游戏线程挂 Stalker 即退出”的问题，例如改用不修改
代码的硬件断点/内核观测，或在一个能通过反调试的隔离环境中采集；在拿到包含
`+0x35e00c` 的真实 Trace 之前，不应继续扩展 VM 语义算法。

### 7.2 710 MB 真实 Trace 的分析结果

虽然这份 Trace 只包含 `libtprt.so`，仍足以检验 Trace UI 在处理真实 GumTrace
时的索引、函数统计和 VM 分析表现。

复现工具：
[`crates/trace-core/examples/avm_probe_trace.rs`](../crates/trace-core/examples/avm_probe_trace.rs)。

索引阶段（release 构建）：

| 指标 | 结果 |
|---|---|
| 文件大小 | 710,614,235 B |
| 行数 | 7,655,977 |
| 格式检测 | GumTrace |
| 首次建索引 | **3.21 秒** |
| 峰值 RSS | **2.44 GB** |
| 再次加载缓存 | 35 ms |
| 函数调用 | 546 次，26 个函数 |

函数统计结果合理，例如 `pthread_mutex_lock/unlock` 各 169 次、`memcpy_generic`
60 次、`__strlen_aarch64` 36 次，说明解析、调用注解和索引层工作正常。

VM 分析结果（默认配置）：

| 范围 | 耗时 | dispatcher | handler | cluster | state | CFG 边 | 峰值 RSS |
|---|---:|---:|---:|---:|---:|---:|---:|
| 0–100k 行 | 1.02 秒 | 1,560 | 1,559 | 85 | 52 | 3,117 | 821 MB |
| 0–500k 行 | 112.3 秒 | 6,621 | 6,619 | 213 | 60 | 13,237 | 1.17 GB |
| 全量 7.66M 行 | >131 秒未完成 | — | — | — | — | — | 3.09 GB |

主要问题：

1. **把普通回调循环当成 VM 分发器**。`libtprt +0x137c8c` 实际是
   `ldr x8, [x21, x25, lsl #3]; ...; blr x8` 的函数指针循环，不是 guest
   指令分发；它被识别为 dispatcher，100k 行时有 30 个目标，500k 行时有 48 个
   目标、6,553 次执行。
2. **同一站点按执行次数重复生成候选**。该站点在 100k 行产生 1,550 个
   dispatcher，在 500k 行产生 6,553 个；最终 handler 数量几乎与候选数量相同。
3. **handler 切分是超线性的**。输入扩大 5 倍，耗时从 1.02 秒增长到 112.3 秒
   （约 110 倍），符合“每个 dispatcher 都重新过滤全部事件”的二次复杂度；
   全量 Trace 在 131 秒时仍未完成。
4. **虚拟 CFG 没有语义价值**。100k 行结果中 1,558 条 fallthrough、1,559 条
   uncertain，conditional/unconditional 均为 0；它只是执行区间顺序，不是
   guest 控制流。
5. **状态推断误报明显**。该 Trace 中 `VirtualPc=reg:x8` 来自回调寄存器和
   普通分支，不是客户机 PC；`BytecodeBase` 还会落到 `sp`/`x0`。

结论：**Trace UI 的索引与函数浏览能力已经能处理 710 MB / 765 万行真实日志，
但 VM 分析层在当前实现下既慢又不可信；这份实测数据直接验证了 P0 的
dispatcher 去重/分类和 handler 切分性能问题。**

## 8. 尚未解决的问题

- AVM 的 guest ISA 是什么（自定义字节码、16 位指令集或其他）。
- AVM 的入口和首个 guest 程序来源。
- `a64.dat` 是否就是 AVM 的 guest 镜像，还是另一层载荷。
- 1,580-case 状态表与 guest 7 路/4 路表之间的精确调用关系。
- handler 表项到 guest 操作码的映射。
- 真实 guest 程序的 CFG、循环和异常路径。

在这些问题有运行期证据前，报告和 UI 应继续把 handler 语义、VPC 和虚拟 CFG
标为 heuristic/partial，不要把候选写成已确认事实。

## 9. 建议的下一步

1. **先采集一份真实定向 Trace**，这是把评估从“结构匹配”推进到“真实验证”的
   唯一缺口。
2. 用该 Trace 验证 P0 的三个判断：dispatcher 归类、站点聚合、VPC 数据流。
3. 修复 P0 后，再评估 cluster 稳定性和跨 ASLR 对比。
4. 在 guest ISA 有独立解码证据前，不实现“guest 指令语义恢复”的对外承诺。
