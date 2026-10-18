# Trace UI VM 分析优化方案

> 基线：`23cdb74` + 本次真实 Trace 评估
> 实测样本：`avm_follow.log`，710,614,235 B / 7,655,977 行 GumTrace
> 目标：先把真实大 Trace 上的误报和性能问题解决，再进入 AVM 语义验证

## 0. 实施结果（2026-10-18）

P0 的 dispatcher 聚合、分类、时间线切分和保守回退已经落地。

| 场景 | 优化前 | 优化后 |
|---|---:|---:|
| 710 MB Trace / 100k 行 | 1.02 秒；1,560 dispatcher；1,559 handler | **0.13 秒**；2 dispatcher；0 handler |
| 710 MB Trace / 500k 行 | 112.3 秒；6,621 dispatcher；6,619 handler | **0.66 秒**；3 dispatcher；0 handler |
| 710 MB Trace / 全量 7.66M 行 | >131 秒未完成 | **10.95 秒**；4 dispatcher；0 handler |
| 合成 AVM 探针 | 38 dispatcher；67 对重叠 | **3 dispatcher；16 handler；0 重叠** |
| 合成 AVM 单分发点 | 16 个重复候选 | **1 个站点候选；16 handler；0 重叠** |

关键结果：

- `libtprt +0x137c8c` 被正确标为 `Callback`（indexed function-pointer load +
  `blr`），不再生成 12 万级 handler。
- 真实 `libtersafe2` 短 Trace 在缺少强 VM 特征时返回 2 个 `Unknown`
  dispatcher、0 handler，不再触发 provisional 假阳性。
- AVM 探针仍能识别 `+0x35e00c` 为 `VmPrimary`、`+0x35e02c` 为
  `VmNested`。
- 新增了 VPC 数据流候选：`ADD base, pc` + `LDRB` 会把 `x25` 标为
  `VirtualPc`，间接分发寄存器改为 `DispatchTarget`。

仍未完成：

- 全量 Trace RSS 约 **3.59 GB**，尚未达到 <1.5 GB；两遍流式和寄存器/事件
  紧凑化仍是后续 P0.4。
- 虚拟 CFG 仍以宿主目标/执行顺序为主，尚未改为 VPC 转移驱动（P2）。
- 跨 ASLR 的模块偏移归一化尚未接入 VM 结果（P1.2）。

## 1. 基线数据

### 1.1 索引层

| 指标 | 结果 |
|---|---|
| 首次建索引 | 3.21 秒 |
| 峰值 RSS | 2.44 GB |
| 缓存大小 | 约 591 MB |
| 缓存重载 | 35 ms |
| 函数调用 | 546 次 / 26 个函数 |

索引层已经能处理 710 MB / 765 万行日志，不是当前主要瓶颈。

### 1.2 VM 分析层

| 范围 | 耗时 | dispatcher | handler | cluster | 峰值 RSS |
|---|---:|---:|---:|---:|---:|
| 0–100k 行 | 1.02 秒 | 1,560 | 1,559 | 85 | 821 MB |
| 0–500k 行 | 112.3 秒 | 6,621 | 6,619 | 213 | 1.17 GB |
| 全量 7.66M 行 | >131 秒未完成 | — | — | — | 3.09 GB |

主要误报：`libtprt +0x137c8c` 是 `ldr x8, [x21, x25, lsl #3]; blr x8`
的函数指针回调循环，被当成 VM dispatcher；100k 行报了 1,550 次，500k 行报了
6,553 次。

## 2. 根因

| 现象 | 代码位置 | 根因 |
|---|---|---|
| 同一站点重复生成候选 | `analysis/vm.rs:538` `find_dispatchers` | 每个执行行 push 一个 `DispatcherCandidate` |
| handler 区间重叠 | `analysis/vm.rs:308` 起 | 候选按地址而不是首次执行行号排序；多站点交错 |
| 分析超线性 | `analysis/vm.rs:316` 起 | 每个 dispatcher 都重新过滤全部事件，O(D×N) |
| 回调循环被当成 VM | `analysis/vm.rs:538` | 只看“间接跳转 + 多目标”，没有调用形态分类 |
| VPC 误判 | `analysis/vm.rs:596` | 直接把 `indirect_register` 当 `VirtualPc` |
| cluster 过粗 | `analysis/vm.rs:875` `template_hash` | 只哈希助记符和寄存器数量，忽略立即数/偏移/入口 |
| CFG 无语义 | `analysis/vm.rs:454` 起 | 主要使用宿主分支目标和执行顺序，不是 VPC 转移 |
| ASLR 不可比 | `analysis/diff.rs:12` | 有 `normalize_module_address`，但 VM 结果未使用 |
| 默认结果过大 | `trace-mcp/src/tools.rs:791` | MCP 固定默认配置，未暴露站点/候选上限和进度 |

## 3. 目标与不变量

### 3.1 目标

1. 7.66M 行完整 Trace 的 VM 分析在 **30 秒内**完成，峰值 RSS **低于 1.5 GB**。
2. 每个间接跳转站点只生成一个候选，不再按执行次数重复。
3. 回调循环、OLLVM 状态分发、VM 分发和嵌套表能被分类，而不是全部混在
   `dispatchers` 里。
4. handler 区间单调、互不重叠，且切分复杂度为 O(N + D log D)。
5. VM 分析结果默认有界、可分页、可取消、有进度。

### 3.2 不变量

- 没有 guest 取指证据时，不把任意间接跳转寄存器标成 VPC。
- 没有 VPC 转移证据时，不把宿主分支目标称为虚拟 CFG 边。
- 候选可以“未知/有歧义”，但不能为了凑结果强行分类。
- 原始 Trace 事实和推断分开保存；所有推断保留行号/native 地址证据。

## 4. P0：先解决真实 Trace 上的爆炸和误报

### 4.1 按站点聚合 dispatcher

把 `find_dispatchers` 改为两阶段：

```text
struct DispatchSite {
    address: u64,
    module_offset: Option<u64>,
    executions: u64,
    first_line: GlobalLine,
    last_line: GlobalLine,
    targets: BTreeSet<u64>,
    branch_register: Option<String>,
    kind: DispatchKind,
    confidence: f32,
    evidence: Vec<EvidenceRef>,
}
```

第一阶段只扫描间接分支，按 `(module_offset 或 address)` 聚合：

- 一个站点只产生一个候选；
- 累计 target set、执行次数、首末行；
- 保存站点前的 8–16 条指令签名，供分类使用；
- 候选按 `first_line` 排序后再做 handler 切分。

验收：

- 100k 行不再出现 1,550 个同地址候选；
- 合成 AVM 探针中 3 个跳转站点只产生 3 个站点候选；
- 同一 Trace 重跑结果确定。

### 4.2 dispatcher 分类，而不是“多目标即 VM”

新增 `DispatchKind`：

- `VmPrimary`：主 guest 操作码分发；
- `VmNested`：主分发后的二级/三级表；
- `Callback`：函数指针数组循环、事件回调、PLT 跳转；
- `OllvmState`：同一大函数内的 CFF 状态表；
- `Unknown`：证据不足。

评分建议（特征权重可调）：

| 特征 | 方向 | 说明 |
|---|---|---|
| 站点前有 `ADD base, mem_base, pc` | + | guest PC + 客户机内存基址 |
| 随后有 `LDRB/LDRH/LDR [addr+imm]` | + | 取 guest 指令/字段 |
| 有 `AND #0xF`、移位、比较 | + | 字节/半字节译码 |
| 表项加载 + `ADD` + `BR` | + | 跳转表形态 |
| 目标集合稳定且指向 handler 区 | + | VM 分发特征 |
| `ldr xN, [array, index, lsl #3]; blr xN` | − | 回调循环，优先判为 `Callback` |
| 目标都在同一巨型函数、共享后继集 | − | OLLVM 状态分发 |
| 站点位于另一个主分发 handler 内 | − | 更可能是 `VmNested` |

关键原则：

- 负证据必须参与分类，不能只按目标数量排序；
- 无法判定时输出 `Unknown` + 原因，不进入主 handler 切分；
- 同一站点的 30/48 个目标本身不是重复候选的理由。

验收：

- `libtprt +0x137c8c` 被标为 `Callback`，不再产生 6,553 个 handler；
- 合成 AVM 中 `+0x35dfc0` 标为 `OllvmState`，`+0x35e00c` 标为
  `VmPrimary`，`+0x35e02c` 标为 `VmNested`；
- 真实 Trace 无 VM 时返回空的 `VmPrimary` 集合并给出解释。

### 4.3 单次时间线切分 handler

不要对每个 dispatcher 过滤全部事件。改为：

1. 为每个主站点建立按行号排序的执行行列表；
2. 只在该列表的相邻行之间生成 handler 区间；
3. 嵌套站点归入当前父 handler，不参与顶层切分；
4. 用单调游标生成区间，保证不重叠。

伪代码：

```text
lines_by_site: Map<site_id, Vec<GlobalLine>>
for event in events:
    if event.is_indirect_branch:
        lines_by_site[site_id(event.address)].push(event.line)

for site in primary_sites_sorted_by_first_line:
    for window in lines_by_site[site].windows(2):
        handler = (window[0]+1, window[1])
```

验收：

- 0–500k 行从 112 秒降到 **2 秒以内**；
- 7.66M 行在 **30 秒以内**；
- `overlapping_handler_pairs = 0`；
- 取消延迟小于 1 秒。

### 4.4 两遍流式分析，去掉全量 NativeEvent 常驻

当前 `NativeEvent` 每行保存 `disasm: String`、`reads/writes: Vec<String>`、
内存地址 Vec，7.66M 行常驻会占用数 GB。

建议：

- Pass 1：只解析分支/目标/内存基址/站点点位，构建 `DispatchSite`；
- Pass 2：只在选中的主站点区间内解析完整 handler 语义；
- 语义结果用紧凑结构：
  - 寄存器用 bitmask/`RegId`，不存 `String`；
  - 内存访问只存 `(abs, width, is_write)`；
  - 原始 disasm 用 line index 回读，不在每个事件复制；
- 分析按索引 Chunk 推进，支持进度、取消和结果分页。

验收：

- 7.66M 行峰值 RSS < 1.5 GB；
- 不因 Trace 大小线性复制字符串；
- 结果仍可回到原始行取证。

### 4.5 配置和可观测性

MCP `VmAnalysisRequest` 增加：

- `max_dispatch_sites`（默认 200，硬上限 1000）；
- `max_handler_instances`；
- `max_events` / `max_scan_lines`；
- `dispatch_kind_filter`（vm/callback/cff/nested/unknown）；
- `include_unknown`；
- `progress` 字段（阶段、已扫描行、候选数、耗时、预计剩余）。

默认行为：

- 超过上限时返回截断警告和分页句柄，不返回百万级数组；
- 分析前给出预检：文件行数、格式、预估事件数、是否需要分段；
- 结果中返回 `duration_ms`、`peak_candidates`、`truncated`。

## 5. P1：AVM 语义相关优化

### 5.1 VPC 不能等于间接跳转寄存器

新增轻量数据流规则：

1. 识别 `ADD addr_reg, mem_base_reg, pc_reg`；
2. 紧随其后出现 `LDRB/LDRH/LDR [addr_reg + imm]`；
3. 把 `pc_reg` 作为 `VirtualPc` 候选，`mem_base_reg` 作为客户机内存基址；
4. 跟踪 `pc_reg` 在 handler 之间的写入，推断下一次 VPC；
5. 区分 `BytecodeBase`（稳定基址）和 `BytecodeCursor`（当前取指地址）。

没有上述证据时：

- 不生成高置信度 `VirtualPc`；
- 跳转表寄存器（如 AVM 的 `x8/x13/x14`）只能作为 `DispatchTargetReg`，
  不能作为 VPC。

验收：

- 合成 AVM 中 VPC 命中 `x25`，不再把 `x8/x14` 作为唯一 VPC；
- 真实 `libtprt` Trace 中不产生 `VirtualPc=x8` 的高置信度候选。

### 5.2 模块偏移归一化

GumTrace 行已经包含 `!0xOFFSET`，但 VM 结果只保留了绝对地址。

改造：

- `NativeEvent` / `EvidenceRef` 增加 `module_name` 和 `module_offset`；
- `DispatcherCandidate`、`VmStateCandidate`、`VmInstruction` 的 ID 使用
  `module+offset` 作为稳定 key；
- 绝对地址继续保留在 evidence 中，便于回查原始 Trace；
- 跨 Trace 对比使用归一化地址和稳定模板特征，不使用本地 `cluster-N`。

验收：

- 同一次 Trace 重跑 ID 稳定；
- 两个 ASLR 基址的同一站点映射到同一 `module+offset`；
- 结果可直接回查 IDA 的 `+0x35e00c`。

### 5.3 聚类模板增强

`template_hash` 至少加入：

- handler 入口的模块偏移；
- 指令 opcode 序列；
- 立即数、移位量、内存偏移；
- 调用目标/PLT 目标；
- 分支目标形态；
- helper 调用折叠（`PmemRead/PmemWrite`、锁、内存分配等）。

聚类键建议：

```text
(module_offset(entry), normalized_opcode_hash, immediate_hash, memory_offset_hash)
```

避免：

- 只按助记符序列合并不同操作数语义的 handler；
- 把不同入口但相似形状的 handler 合并为一个 cluster；
- 把 helper 调用展开进 handler 主体。

验收：

- 合成 AVM 的 4 个 handler 不被合并成 1 个；
- 同一 handler 在 3 次运行中 cluster 稳定；
- 至少 10 个 cluster 可人工对照入口证据。

## 6. P2：虚拟 CFG 和跨 Trace 对比

### 6.1 CFG 以 VPC 转移为主

边来源改为：

- `VPC_i -> VPC_{i+1}`：observed next-VPC 边；
- 同一个 handler 观察到两个后继 VPC：conditional 候选；
- 只在宿主分支目标等于已观测 handler 入口时，才作为辅助证据；
- 未观测目标标为 uncertain，不伪造成 fallthrough。

验收：

- CFG 不再全部是 fallthrough/uncertain；
- 条件边能关联到 VPC 转移和原始行；
- 不能在没有 VPC 证据时输出“完整虚拟 CFG”。

### 6.2 跨 Trace 对齐

- 特征：模块偏移 + handler 模板 + 状态角色 + 语义操作；
- 不依赖本地 cluster 序号；
- 对齐结果输出 matched/left-only/right-only/uncertain；
- 先做同 Trace 自对齐，再做不同 ASLR 基址、不同设备/版本。

验收：

- 同 Trace 自对齐 100%；
- 不同 ASLR 的 handler 对齐率 >90%；
- 低置信度匹配明确标注。

### 6.3 UI / MCP 展示

- VM 结果默认先返回 summary，候选列表分页；
- 每个候选显示“为什么是/不是 VM”的负证据；
- 提供 `VmPrimary / Callback / OllvmState / VmNested / Unknown` 过滤；
- 时间线视图中标出 dispatcher 站点和 handler 区间；
- 超过上限时显示截断原因和继续分页入口。

验收：

- 710 MB Trace 打开后 VM 首屏 1 秒内返回 summary；
- 不因百万级候选冻结 UI；
- 用户可以从候选跳转到原始行并查看证据。

## 7. 实施顺序

| 阶段 | 内容 | 预计收益 |
|---|---|---|
| P0.1 | dispatcher 按站点聚合、按行排序 | 去掉 1,550/6,553 级别重复 |
| P0.2 | 单次时间线切分 handler | 112 秒 → 2 秒级 |
| P0.3 | dispatcher 分类（Callback/CFF/VmPrimary/Nested） | 去掉 `libtprt +0x137c8c` 误报 |
| P0.4 | 两遍流式 + 紧凑事件 | 全量 RSS <1.5 GB |
| P1.1 | VPC 数据流 | 不再把跳转表寄存器当 VPC |
| P1.2 | 模块偏移归一化 | 跨 ASLR/IDA 可回查 |
| P1.3 | 聚类模板增强 | handler 级别更稳定 |
| P2.1 | VPC 驱动 CFG | 从“执行顺序”变成 guest 控制流候选 |
| P2.2 | 跨 Trace 对齐 | 版本/运行差异可比较 |
| P2.3 | UI/MCP 分页与进度 | 大 Trace 可用性 |

## 8. 测试矩阵

| 用例 | 期望 |
|---|---|
| 710 MB `libtprt` Trace | 全量 <30 秒，无 OOM，无同站点重复候选 |
| 合成 AVM 探针 | 1 个 `VmPrimary` + 1 个 `VmNested` + 1 个 `OllvmState` |
| `libtprt +0x137c8c` 回调循环 | 判为 `Callback`，不切 handler |
| 100k/500k/7.66M 范围 | 耗时近似线性，候选数量按站点而非执行次数增长 |
| 多站点交错 | handler 区间 0 重叠 |
| 缺少 `br xN=...` 寄存器值 | 低置信度 + 明确警告，不误判 |
| 不同 ASLR 基址 | 同一站点映射到同一 `module+offset` |
| 重跑同一 Trace | 结果确定、ID 稳定 |

## 9. 暂不做的事

- 不在没有真实 AVM Trace 前扩展 guest ISA 解码或宣称完整语义；
- 不通过简单提高 `min_dispatch_targets` 掩盖误报；
- 不在 UI 层去重后端已经生成的百万级候选；
- 不把 `Callback`/`OllvmState` 强行归为 VM 分发；
- 不为了跨版本兼容而牺牲证据可回查性。
