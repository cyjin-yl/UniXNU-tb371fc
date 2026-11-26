# Route A：非 TPRO 启动合同的精确输入检查

本轮连接实际 dyld 的入口、完整候选指令清单与真实内核的 syscall 38 表项，并提供有限片段执行器。**A01 尚未闭合**：已执行静态绑定和定向回归；有限片段尚未编译／运行。真实 XNU 用户态 SVC、全部状态传播、commpage、VM fallback 和缓存交接仍有独立门槛。

[公开摘要](evidence/route-a-nontpro-static-20261126.json)绑定输入、源码与原始私有报告摘要。[原 TPRO 合同](ROUTE_A_TPRO.md)、[内核能力发布](ROUTE_A_TPRO_KERNEL_PUBLICATION.md)和[MemoryManager 调用边界](ROUTE_A_MEMORY_MANAGER_CALL.md)继续有效，历史记录保持。

## 实际完成的检查

原始 standalone dyld 为 iPad17,3 / 27.0.1 / 24A446 的固定文件，1,447,088 字节，SHA-256 为 `ab9887ed96c9c08ad68d4c6a5c27e8289fb0c9e55ec3e134547292a1ec579608`。检查器核对整个输入、Mach-O 几何、UUID、347 个 CodeDirectory 代码页、`LC_UNIXTHREAD` 和 `LC_FUNCTION_STARTS`；代码页通过不表示 CMS 或 Apple trust 已验证。

| 实际结果 | 含义 |
| --- | --- |
| 入口 `0x5a90`，直接分支至 `0x3be0` | 固定五条指令在对齐 SP 前把原 SP 保存到 X0 |
| 116 条 TCHANGEF，120 条 TCHANGEB | 候选指令范围内合计 236 条 |
| 652 次 MRS，280 次 MSR | 仅统计两个明确跟踪的寄存器编码，共 932 处 |
| `s3_3_c4_c0_3` 304 处，`s3_6_c15_c1_5` 628 处 | 同样纳入路径与状态合同 |
| 119 个函数区间、158 条区间外直接入边 | 依据真实函数起点和分支编码；不是完整调用图 |

119 组包括 startup 1 组、MemoryManager initialization 2 组、readonly callback 31 组、MemoryManager readonly block 42 组、API/runtime state 42 组和 private cache mapping 1 组。分类只辅助排查。每组的间接入边、状态写入者、callee 合同和 `closed` 均保持 false。旧记录的 TCHANGE 分组与本轮加入系统寄存器访问后的分组范围不同。

流式扫描避免把全部候选字保存在内存。完整私有账本记录位置、实际指令字、函数区间摘要和直接入边；公开摘要保留计数、范围及账本 SHA-256，不分发系统文件或整段反汇编。

## syscall 38 的精确绑定

数字 38 本身不足以确定服务。实际 dyld stub 固定为设置 `X16=+38`、`SVC #0x80`、返回；前面的 wrapper 将 X0、X1、X2 置零，以 X3 传入用户栈上的指针槽。检查器同时核对 stub 和完整 wrapper 字节摘要。

[route_a_nontpro_xnu.py](../scripts/route_a_nontpro_xnu.py)连接声明的源文件、编译 recipe、生成表、对象重定位和最终候选：

1. 从实际 `init_sysent.o` 的表区间及 `_nsysent=558` 确认槽大小 24 字节，检查槽 38 的两条 ARM64 64-bit unsigned 外部重定位和零 addend。
2. 要求目标为 `_sys_crossarch_trap`、munger 为 `_munge_w`，返回类型、参数数和 32 位参数长度分别为 1、1、4。
3. 按最终 MH_EXECUTE 的真实 nlist 重新定位；检查 section owner、VA／文件偏移 affine 映射、段范围、执行权限和纯指令标志。零 section 的段也必须满足文件范围不大于虚拟范围。
4. 对象中完整 24 字节函数必须与最终文件逐字相同。固定函数对 namespace 0 返回 45（ENOTSUP），其他 32 位 namespace 返回 22（EINVAL），不写查询输出内存。
5. 最后重新核对所有输入；`-D`、`-U` 和相对源码路径按实际 recipe 处理。

实际候选为 `46eff436250d905e9f3aec59dbcc8c04d594e614e790860236917c7cbfe39f1b`，21,942,456 字节。槽 38 位于 `0xfffffff0071cf550`，目标为 `0xfffffff007806288`；这些地址只属于本候选。加入 provider 或重新链接后必须重新解析。

这关闭了“fixture 返回值是否对应最终已编译目标”的静态缺口，没有执行 XNU 异常入口、参数拷贝、MAC／syscall rejection 过滤或错误返回。当前 `systemcalls.o` recipe 明确启用 `CONFIG_DEBUG_SYSCALL_REJECTION`；初始进程／线程过滤状态及没有 DTrace 表替换仍需实证。`actual_xnu_dispatch_verified`、`error_return_machine_path_verified` 和 `runtime_filter_state_verified` 均为 false。

## 显式、有限的原始字节片段执行器

[probe_route_a_nontpro_fragments.py](../scripts/probe_route_a_nontpro_fragments.py)和原创 [entry.S](../scripts/route-a-nontpro/entry.S)准备 20 个有界 case。它加载原始 dyld 指令，在 QEMU EL0 执行 apple 向量定位／查找、MemoryManager 构造、禁用状态的默认 TPRO stack 和 ProtectedStack 构造／查询。

输入包含首／中／末位置、重复项、裸键、相似前缀、空值和字符串值 0。`dyld_hw_tpro=0` 与空值仍按键存在处理。整个 apple 向量与 commpage 明确为合成数据。

唯一 EL1 syscall 行为是 `SVC #0x80 / X16=+38 / namespace=0` 的合成错误返回。先捕获 X0–X7、X16、X30、ESR、ELR、SP_EL0、SPSR 及有界指针槽，再校验服务号和参数；匹配后返回 X0=45、X1=0，仅设置 CF。其他异常或参数模式停止。该行为依据静态合同，报告仍将真实 XNU dispatch 标为 false。

GDB 仅读取寄存器／内存、管理硬断点和继续执行，不修改 guest 内存或寄存器。结束时核对原始代码字节、结果和 syscall 捕获；时间与日志有界，所拥有的 QEMU 进程必须回收。工具保留 invocation basename，并记录父目录／symlink 链和最终 binary；version 前后及最终 input recheck 都核身份，任何变化撤销片段资格。

QEMU 使用独立 `virt`、单 CPU、256 MiB RAM、GICv3 和 `-cpu max`。它观察原始 arm64e 函数语义，不能证明改写后的普通 ARM64、真实 Darwin 进程、OS 或 TB371FC 可运行。即使全部 case 通过，也不会提升 A01 或全系统标志。

## 使用入口

只读 standalone 账本：

```sh
python3 scripts/audit_route_a_nontpro.py \
  --input /path/to/original/usr/lib/dyld \
  --report /path/to/new-standalone-ledger.json
```

可增加 `--cache /path/to/dyld_shared_cache_arm64e`，绑定固定主文件和 dyld 所在子缓存的摘要、UUID、代码几何及对应危险指令。仍只检查选定 image；坐标或字节相等不代表 standalone→cache 交接已执行。本轮 validation-003 未执行此可选路径。

静态 syscall 绑定：

```sh
python3 scripts/route_a_nontpro_xnu.py \
  --kernel /path/to/kernel.macho \
  --objects /path/to/bsd/DEVELOPMENT \
  --prepared /path/to/prepared-xnu \
  --filelist /path/to/platform-link.filelist \
  --report /path/to/new-syscall38-binding.json
```

有限 fixture 的待执行命令：

```sh
python3 scripts/probe_route_a_nontpro_fragments.py \
  --input /path/to/original/usr/lib/dyld \
  --kernel /path/to/kernel.macho \
  --objects /path/to/bsd/DEVELOPMENT \
  --prepared /path/to/prepared-xnu \
  --filelist /path/to/platform-link.filelist \
  --output /path/to/new-fixture-run \
  --timeout 15
```

结果路径必须新建。远端扫描、测试及 QEMU 遵守工作区资源准入；本轮没有绕过重任务协调。

## 验证及剩余门槛

前三次独立轻量执行为 17／17、7／7、13／13，全部零跳过；其间共覆盖 29 个不同测试，没有声称一次运行完整现行套件。validation-003 同时重绑真实候选并生成完整 standalone 账本，超时界限 60 秒、地址空间上限 96 MiB，实际 22.98 秒，峰值 RSS 32,684 KiB。之后新增两项 linked-segment 拒绝变体，当前共有 31 项测试；其验证任务在 host 资源准入阶段退出 75，CT driver 未启动，因此两项新变体尚未执行，最终两处源码变化也没有冒称复测。公开摘要分别保存已验证源码与这次后续变化的身份。

新回归覆盖 in-bounds 但不符合加载映射的 section、错误 owner、零 section 段、不可执行纯指令区间，以及相同 binary 字节下的父目录 alias 更换、version 中途变化和观察结束后工具变化撤销资格。

仍须逐项完成：

- 内核生成的完整 apple 向量、所有后续发布点及各进程入口的能力键缺省。
- MemoryManager／ProtectedStack 状态到每个必要调用点的传播，全部 119 组的前驱、写入者和 callback 合同。
- 用户入口时的 commpage 实际值和普通 VM 保护路径，不能仅用分配时清零推断。
- standalone→cache dyld 的交接及之后加载器入口。
- 有限原始字节片段运行，以及最终候选中的真实用户 SVC／返回合同。

任一门槛未闭合都不把 A01 记为完成。完整 Darwin 用户态启动及板级验收另行记录。

## 七组真实 XNU 预处理的后续证据

[2026-11-27 公开摘要](evidence/route-a-a01-cpp-20261127.json)记录一次已经完成的真实预处理及本次只读复核。原控制器在 UTC 2026-11-26 15:19:37–15:27:21 运行，耗时 **463.772 秒**；119 项输入身份记录、23 条实际命令均完成，命令退出码全为 0。七组为 `kern_crossarch`、`systemcalls`、生成的 `init_sysent`、`mach_loader`、`kern_exec`、`status` 和 `pcb`。每组分别执行依赖分析、预处理正文和宏表输出，另有编译器版本与 resource-dir 两条命令。本次没有重跑实验。

这次只读复核重新计算了原 receipt、plan 及七份正文／七份宏表的 SHA-256，并与既有身份记录相符；原始依赖身份来自收据，没有声称本次又重哈希全部依赖。公开摘要只保留配置、摘要、函数定位、结论及范围。

| 实际展开的内容 | 本次可确认的范围 |
| --- | --- |
| `exec_save_path` 与 `exec_copyout_strings` 完整函数 | 首项固定加 `executable_path=` 前缀；argv、envv 分别终止，apple 区由保存的首项与 `ip_endenvv` 起的后续项组成。 |
| `exec_add_apple_strings` 完整函数 | 所检查分支没有构造两项 `dyld_hw_tpro*` 键；仍明确发布 `security_config`，其值不能假定为零。本配置的 MTE 条件段未进入正文，函数也没有添加 `has_sec_transition`。 |
| `mach_loader`、exec 的所选调用点 | 保留 dyld thread-state／entry-point 选择，以及复制字符串后设置 SP、在 dynlinker 分支再压入主 Mach header 的操作；这些仍以相应加载和复制成功为条件。 |
| `status` 与 `pcb` 的完整所选函数 | 线程状态初始化与 entry-point 设置中的已检查 PAC 条件段被裁去；这没有替代最终对象、汇编返回与真实寄存器验证。 |
| crossarch 与 syscall 表／返回路径 | 展开的 namespace 0 返回 45，生成表保留对应目标；DTrace、MACF、debug syscall rejection 相关配置仍启用，运行时过滤状态没有被省略。 |

七组最终宏表均有 `__arm64__=1`、`XNU_TARGET_OS_IOS=1`、`ARM64_BOARD_CONFIG_BCM2837=1`；所列 PAC、arm64e、MTE、SPTM／monitor 宏未定义。宏表反映每组的最终状态，函数结论来自实际正文，不以“未定义”推导所有条件点或其他编译单元。`NO_MONITOR=1` 也不被当成全内核 PPL 配置的替代证据。

两项 TPRO 键在本次 `kern_exec` 正文中的字面计数为零，只辅助定位完整函数审查；它不证明其他发布点、后续向量修改或所有运行中的进程都没有这些键。先前记录的 dyld 入口会在调整 SP 前保存原 SP 到 X0，属于另一份精确输入观察。本次所选内核调用点不能单独证明最终 SP、header、X0 与该 dyld 输入已经接通。

**A01 仍未完成。** `task`、commpage、pmap／pmap_data 和 `vm_map` 不在七组中；实际配置、对象、最终链接选择与相关写入者仍须绑定。原收据也明确保持“原构建环境已重建”“全部外部预处理输入已绑定”“已链接内核身份已绑定”“真实 dyld 入口”“全部 A01 hazard 闭合”“运行时执行”均为 false。后续验收仍包括实际 apple 向量、commpage 字节、VM fallback、全部 119 组状态传播、cache dyld 交接及真实 XNU SVC／返回；预处理退出 0 不构成这些项目的通过结果。
