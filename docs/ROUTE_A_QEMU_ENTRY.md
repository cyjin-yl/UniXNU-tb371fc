# Route A：独立 QEMU 入口诊断

`scripts/probe_route_a_qemu_entry.py` 把已有普通 ARM64 平台候选送入独立的标准 QEMU `virt`。它消费[真实 loader 合同](ROUTE_A_LOADER_CONTRACT.md)产出的 `kernel.load.bin`，在 `__start` 物理地址设置硬件断点，读取真实 PC／x0／PSTATE，再单步执行入口的 `B`，要求实际到达 `_start_first_cpu`。UART 中的“即将跳转”或翻译日志不会单独获得入口执行通过标志。

这是针对内核早期代码的实验入口。机器为单核 TCG、512 MiB RAM、GICv3，没有磁盘或网络设备；它不启动原厂 TB371FC QEMU、不接触平板，也不提供完整 Darwin 用户态。真实设备启动、UEFI 所有权、板级 ADT、iPadOS／macOS 启动都继续独立验收。

## 2026-11-26 真实执行

第三次尝试实际执行了固定平台候选的入口分支。EL1h 下的 PC 从 `0x50511488` 单步到 `0x5051305c`，对应 `__start` → `_start_first_cpu`；`x0` 在前后均为 `0x52000000`，实际读出的指令字节为 `f5060014`。随后继续执行，在高虚拟地址 `0xfffffff0072f5fe4` 捕获第一条 Undefined Instruction，原指令字为 `0xe7ffdeff`，异常转入 EL1 vector `0xfffffff00750c000`。完整摘要与原报告身份见[本轮证据](evidence/route-a-qemu-entry-20261126.json)。

| 尝试／源码 | 实际结果 | 后续处理 |
| --- | --- | --- |
| run001／`2760826` | 工具版本检查失败，尚未启动 QEMU；`ld.lld` 被路径规范化变成 generic `lld` | `5932fa3` 保留调用路径与 basename，二进制身份单独记录；补入真实 symlink 回归 |
| run002／`5932fa3` | QEMU 处于初始暂停态；target XML 的未声明 `xi` 前缀导致解析失败，未继续 guest | `1768703` 增加有限 XML 方言支持、完整寄存器校验和解析前证据保存 |
| run003／`1768703` | 入口硬断点／单步通过，随后捕获上述真实异常；所有声明输入复核不变 | 原始结果保留；源码层原因与调用路径按独立定位证据跟进 |

run003 整个诊断入口在北京时间 **02:34:28–02:34:44** 执行，其中 QEMU 进程运行 **1.08898 秒**。原始报告为 15,859 字节，SHA-256 `321b7e4c5947ae6d5dfd13e467dd516fef20aa62b9f0d53227736131f7213370`。捕获异常后由主机 SIGTERM 停止 QEMU，退出码为 0 且已回收；这个退出码不表示 guest 启动成功。

本次已观察到高虚拟地址执行和异常转入，但没有独立完成整个 MMU／slide 交接验收。两个 QEMU 入口标志为 true；UEFI、板级 ADT、TB371FC 实机与 OS boot 资格仍为 false。前两次失败不回填为成功；本地及独立的 33 项定向回归均通过，实际 CI 以相应提交的作业结果为准。

## run004：同一启动输入下的 panic 快照

北京时间 **2026-11-26 03:06:20–03:06:32**，`d9052126` 的显式快照模式完成真实执行。它复用了 run003 的 256 字节 seed；独立结束检查确认旧报告未变，`entry.bin`（4,344 字节）、`boot-args.bin`（16,384 字节）及合成 ADT（1,780 字节）的长度和 SHA-256 均与 run003 一致。观察方式增加了 debugger 入口断点，运行时确定性没有因此得到保证。[run004 公开证据](evidence/route-a-qemu-debugger-20261126.json)保存原报告、重放检查和各输入的完整摘要。

原入口单步仍通过；随后在 `_DebuggerTrapWithState` 的首指令前停于 `0xfffffff0072f5ef4`，实际指令字节 `ff0306d1` 与固定候选一致，PSTATE 为 `0x600003c4`（AArch64 EL1t）。全部 34 个 core 寄存器已捕获，`x0=0x3` 表示 panic，`x1` 字符串为 `panic`，`x2` 格式为 `%s %s (start: %llu, end: %llu)%s`。

| 有限读取 | 实际读取／上限 | 结果 |
| --- | --- | --- |
| message、panic format | 各 64／512 字节 | 均完整，已见 NUL，无截断 |
| `x3` cursor cell | 8／8 字节 | `0xfffffff007d47978` → `0xfffffff007d47990` |
| 参数槽、SP 栈窗口 | 各 256／256 字节 | 均完整，没有额外追踪指针或回溯 |

参数槽中已捕获的第二个字符串为 `1.984 ms >= 1.920 ms`，第五个字符串为空。start 为 **2,827,029 ticks**，end 为 **2,951,072 ticks**，差值 **124,043 ticks**；按现场记录的 **62.5 MHz**，对应 **1.984688 ms**。第一个字符串 `preemption disable timeout exceeded:` 来自同一固定候选的静态只读提取，公开证据单独标记其来源，未把它写成本次额外 guest 读取。

caller 归因也使用实际指令核对：`x7-4 = 0xfffffff00736cb4c` 位于 `_kern_timeout_try_panic`，原字 `0x941e9b15` 解码为到 `_panic` 的 `BL`；`x30-4 = 0xfffffff0072f74f0` 的 `0x97fffa81` 则调用 `_DebuggerTrapWithState`。`x7` 本身恰位于下一 `_timer_init` 符号边界，不能直接用返回地址的最近符号命名 panic 来源。

QEMU 实际运行 **0.98557 秒**；断点移除后保持暂停，由主机 SIGTERM 停止，退出码 0 且已回收，输入复核全部不变。本次获得完整有限快照资格；它没有继续执行 debugger 函数体，因此 `exception_observed=false` 不代表原异常已经解决。原报告为 **26,398 字节**、SHA-256 `931db1b66f0c30ea58980f470a386e345e3e2be6bfb0582632ee475412b25071`。计时阈值与时钟行为的进一步来源仍需独立核对，不能据这一次观察把 TCG 等机制判为唯一原因；完整 MMU／slide、板级、实机和 OS boot 资格保持 false。

## 输入与布局

输入为固定的 `46eff436…` 平台候选、对应 loader 报告和内存映像。脚本重算候选与映像摘要、检查 loader 的三个实际通过标志与输入复核结果，并重新解析真实段、local relocation 和入口符号。它逐字节重建完整内存映像，包括段间间隙和 BSS；修改映像并同步修改报告摘要也不能获得通过。

默认物理布局如下，均位于本实验所拥有的 QEMU RAM：

| 对象 | 地址或约束 |
| --- | --- |
| QEMU RAM | `[0x40000000, 0x60000000)` |
| EL1 诊断 trampoline | `0x40080000`，最多占用 64 KiB |
| 内核物理基址 | `0x50004000`，低 21 位与固定虚拟基址一致 |
| `boot_args` | `0x52000000`，16 KiB 对齐 |
| 合成 ADT | `boot_args + 0x1000` |
| `deviceTreeP` | 对应的内核虚拟地址，保持零虚拟 slide |
| `topOfKernelData` | 16 KiB boot buffer 的物理末尾 |

检查同时覆盖内核与 boot buffer 不重叠、trampoline 不被覆盖、2 MiB block 的前缀属于 QEMU RAM，以及全部输入位于保守的初始映射范围。上游原入口实验的默认 `0x50000000` 物理基址不满足本候选的低 21 位条件；接近 RAM 尾部的 `0x5ff00000` boot buffer 也会被拒绝。

默认 `--adt qemu-virt` 生成小型 Apple 格式设备树，记录实际选定的 CPU 名称、GICv3、PL011 和 RAM。它没有 iPad 身份、Qualcomm UFS 占位节点、磁盘、ramdisk 或 trustcache。实际 trampoline 读出的计数器频率必须与 ADT 的 62.5 MHz 相符。256 字节随机种子保留在输出 ADT 中，结果报告绑定完整 ADT 摘要。`--adt none` 用于明确无设备树的边界实验，两个设备树 boot_args 字段均为零。

## 执行

需要 Linux、Python 3.11+、Clang／LLD／llvm-objcopy 和支持所选 CPU 的 `qemu-system-aarch64`。不需要运行 GDB 客户端：脚本通过仅位于输出目录的 Unix socket 使用 QEMU GDB remote protocol，先验证 QEMU 提供的 AArch64 寄存器 XML，再按已验证的布局读取寄存器。工具的调用路径保留 `ld.lld` 等 multicall 名称，实际指向的二进制身份另行记录。

QEMU 的 [`get_feature_xml()`](https://github.com/qemu/qemu/blob/v10.0.0/gdbstub/gdbstub.c) 会生成没有声明 `xmlns:xi` 的 `<xi:include>`。解析器仅支持这类已知的字面标签及本地 feature 名称，仍要求唯一 `aarch64` architecture、首个且唯一的 core include，以及全部 34 个 core 寄存器的名称、编号、位宽与顺序。它不展开 namespace 或 XInclude，不加载外部 DTD，不支持实体和内部 DTD subset；标准 `gdb-target.dtd` 声明只作为元数据接受。每份收到的原始 XML 和各段 qXfer 响应在解析前保存为 `gdb-*.xml`／`.responses.json`，报告保存其身份，解析失败也保留证据。

在满足主机资源与共享构建槽约定后执行；输出必须是仓库外的新目录：

```sh
python3 scripts/probe_route_a_qemu_entry.py \
  --kernel /absolute/link-attempt-004/mach.platform-link-probe.unstripped.noctf \
  --loader-report /absolute/loader-attempt-003/report.json \
  --loaded-image /absolute/loader-attempt-003/kernel.load.bin \
  --cpu cortex-a76 \
  --adt qemu-virt \
  --timeout 10 \
  --output /absolute/new/qemu-entry-attempt
```

工具可以通过 `--clang`、`--linker`、`--objcopy`、`--qemu` 指定。CPU 选择必须真实存在于所选 QEMU；不把 A76／A710 模型的结果当作 Snapdragon 870 实机资格。单次运行最多 60 秒，QEMU 的每份输出文件有 16 MiB 硬上限。观察第一条 QEMU 异常、达到时间／日志限制或 QEMU 退出后即结束；必要时先 SIGTERM、两秒后 SIGKILL，并回收子进程。异常是否致命仍由保存的日志与代码位置判断。

## 可选 debugger 入口快照与 seed 复用

在上述命令中显式加入 `--debugger-snapshot`，才会启用第二个观察点。脚本先完成原来的 `__start` 断点与单步，再在固定候选自身的 `_DebuggerTrapWithState` 入口设置硬断点。地址由实际 Mach-O 的唯一强 section 符号解析，并核对纯指令 section、同一可执行段、文件后备范围与 4 字节对齐；没有人工指定地址的参数。命中后还要验证 PC、AArch64 EL1 状态和与候选一致的原始首指令字节。

观察器保存全部 34 个 core 寄存器及原始 core 回复，并仅通过 GDB `m` 读取以下字段：

| 字段 | 固定上限与解释 |
| --- | --- |
| `x1` / message、`x2` / panic format | 各最多 512 字节，遇 NUL 停止；原始字节为准，UTF-8 文本只供阅读 |
| `x3` / `va_list*` cell | 恰好 8 字节，按 LE64 读出一个 cursor |
| cursor 的参数槽 | 最多 256 字节原始数据；只做上述一次间接读 |
| `sp` 栈窗口 | 最多 256 字节，不回溯栈帧 |
| `x7`、`x30`、`x29` | 保存原始 caller / LR / FP 值，不自动归因到最近符号 |

Darwin ARM64 的 `va_list` 是 `char*`，变参使用 8 字节栈槽，见 [Apple 官方 ABI 文档](https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms#Update-code-that-passes-arguments-to-variadic-functions)。这里的参数是 `va_list*`，因此先读 cursor cell，再读有限参数槽；不会将 guest 的 format string 交给 host `printf`，也不做通用指针追踪。所有实际读取的非空指针必须落在声明的初始线性映射与 QEMU RAM 的交集中，每个请求最多 64 字节且不跨 4 KiB 边界，地址计算不得溢出 uint64。这个窗口是读取上界，仍需实际 GDB 读取成功，不构成页表验证。

`x1`／`x2`／`x3` 或变参 cursor 的合法 NULL 明确记为 `null`，不读取；SP 不能为 NULL。未知／越界指针、不可读 cell、非法 cursor、槽空间不足、字符串没有 NUL、超时与断点移除失败分别保留状态。已经取得的寄存器、各段原始字节和错误回复仍保留在 `debugger_snapshot` 中。只有所需字段完整读取或合法为空、断点清理及后续输入／EL／计数器检查均通过，才会得到 `qemu_debugger_snapshot_verified=true` 和 `status=qemu_debugger_snapshot_observed`；任何截断都不能获得这一完整快照标志。此模式的报告地址及寄存器用十六进制字符串表示，以避免高虚拟地址在 JSON 使用方被舍入。

快照使用与原入口观察相同的总超时。命中后不再继续或单步，不执行函数体或跳过 trap；移除硬断点后保持暂停，由主机停止并回收 QEMU。寄存器和内存均不写入，原内核文件不改动。没有传入该选项时，仍采用原来的入口证明后运行至首异常／时间限制流程。

可另加 `--seed-file /absolute/path/run003-random-seed.bin`，复用恰好 256 字节的合成 ADT seed。只接受普通文件，拒绝 symlink、FIFO、目录与错误长度，且只适用于 `--adt qemu-virt`。seed 的输入身份与结束复核纳入报告；默认仍生成新 seed。要声称复用了旧启动输入，必须在新尝试中独立比对旧、新 ADT、`boot-args.bin` 和 `entry.bin` 的实际摘要，并核对 CPU、布局、命令行与原工具／源码身份；指定同一 seed 本身不代表整个实验已冻结，也不改变旧尝试的报告。

## 单变量计时诊断

`--clock-mode host-virtual` 是默认值，保留 run004 的原 QEMU 参数，不添加 `-icount`。显式选择 `--clock-mode instruction-1ns` 时，只增加固定参数 `-icount shift=0,align=off,sleep=off`。没有任意 QEMU extra-args 接口；未知模式在启动 QEMU 前拒绝。报告中的 `qemu.clock_mode`、`qemu.icount` 与实际执行的完整 `argv` 同时记录。

固定 [QEMU v10.0.13 的 icount 实现](https://github.com/qemu/qemu/blob/v10.0.13/accel/tcg/icount-common.c)按 instruction count 左移 shift 得到纳秒，`shift=0` 对应每条 guest instruction 1 ns；`sleep=off` 下空闲时间还可推进至下一 timer。[TCG 的 virtual clock 路径](https://github.com/qemu/qemu/blob/v10.0.13/accel/tcg/tcg-accel-ops.c)用于这一模式。它是计时模型隔离实验，不是周期精确模拟或处理器性能测量。

两种模式使用同一 CPU／GIC、62.5 MHz 计数器检查、seed／ADT／boot buffer／trampoline 生成方式及 guest panic／timeout 代码。比较实验仍需独立核对生成物摘要。主机观察总时限不变；在截止前没有命中 debugger 观察点，只能记为未观察到，快照资格保持 false，不能据此宣称 panic 消失、早期初始化完成或 TB371FC／OS 启动通过。

## 结果怎么读

输出包括 `report.json`、原始 UART／异常／stderr、编译命令与输出、trampoline、boot buffer 和合成 ADT。报告保存输入、工具及源码身份、QEMU 命令、实际 stop reason／退出码、子进程回收状态，以及入口单步前后寄存器。对首个异常能映射回候选时，另记虚拟地址、所属段与原指令字。

`status=qemu_entry_observed`、`qemu_kernel_entry_executed=true` 的含义限于实际单步证明的入口分支；`qemu_early_cpu_entry_observed=true` 表示观察到 early CPU 起点，不代表其函数体运行成功。运行时 slide、UEFI 分配、板级 ADT、TB371FC 内核资格和 OS boot 标志均保持 false。定时停止且未捕获异常，也不代表内核已经正常启动。

每次结束重新检查声明的输入与工具。任何变化都会令结果失败并清零入口通过标志。失败尝试与已有输出保留，新一次实验使用新目录；不要修改旧报告。GDB 断点仅用于观察，不修改原内核字节。未来新候选需先更新其 loader 合同与来源，不通过修改报告绕过固定候选门槛。

## 来源与回归

`scripts/route_a_qemu_entry/` 原样保留固定 UniXNU [`8542980d`](https://github.com/UniXNU/UniXNU/tree/8542980d02b4d2cc5c32ee3542de1760b2562aac) 的 `scripts/qemu-entry/entry.S`、`link.ld` 及完整 BSD-2-Clause-Patent `LICENSE`。`sources.json` 记录逐文件长度、SHA-256 和 Git blob，执行前核对。ADT 格式与平台字段参考同版本的 [`make-dt.py`](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/qemu-entry/make-dt.py) 和 [`devicetree.py`](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/unixnu/devicetree.py)；本入口只构造上述有限 QEMU 设备。

```sh
python3 -m unittest discover -s tests -p test_route_a_qemu_entry.py -v
```

回归覆盖输入改写、BSS 补零、入口证据、物理布局、ADT 资源一致性、GDB 校验／分包／RLE、意外 PC 以及 UART 意图与实际执行的区别。可选快照另覆盖真实 nlist 归属、完整 core 包、指针／页／字节／时间边界、NULL、截断、一次变参间接读、partial 证据、seed 普通文件与复核、后置检查撤销通过标志及默认路径兼容性。它们使用自写合成 Mach-O，不需要私有候选，也不会启动 QEMU；真实候选的运行结果另存本次证据，不能从单元测试推断。
