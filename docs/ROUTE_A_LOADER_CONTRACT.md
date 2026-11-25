# Route A：DarwinBoot 加载与启动参数合同

新增 [probe_route_a_loader.py](../scripts/probe_route_a_loader.py) 把平台候选接到固定 DarwinBoot 的实际 C parser 与内存复制代码。检查覆盖 Mach-O 接受性、固定虚拟地址下的完整 local relocation 表、按虚拟地址差装载的内核字节、入口 trampoline 和 `boot_args` 声明布局。真实候选固定为 [平台链接结果](ROUTE_A_PLATFORM_RESULT.md) 的 `46eff436250d905e9f3aec59dbcc8c04d594e614e790860236917c7cbfe39f1b`，21,942,456 字节。

本入口在主机进程中生成 `kernel.load.bin`，内容是内核各段的内存映像，按段地址间距保留空隙并补零。它只适用于这份固定的普通 ARM64 `MH_EXECUTE`。物理内存分配、板级 ADT、UEFI 交接、内核指令执行和 27 启动分别验收；生成的文件不具备独立启动资格。

## 2026-11-24 真实执行结果

第三次尝试已返回 `host_loader_contract_verified`，实际进程退出码 0。输入始终是同一份平台候选；前两次失败发生在外层检查阶段，没有编译 host C 或复制内核字节。三个输出目录和原始报告分别保留。

| 尝试 | 实际结果 | 后续处理 |
| --- | --- | --- |
| [attempt-001](evidence/route-a-loader-20261124/attempt-001/report.json)，driver-v1 | `unsupported segment flags or protections`；三个 host verified 均为 false | 真实段表含 `SG_NORELOC=0x4`。核对固定格式定义后显式支持这一个注记，保留其余 flag／protection 拒绝 |
| [attempt-002](evidence/route-a-loader-20261124/attempt-002/report.json)，driver-v2 | `dynamic symbol table retains undefined symbols or relocations`；三个 host verified 均为 false | 实际 undefined／external relocations 为 0，但有 102,103 条 local unsigned64 记录。增加固定 VA 合同与全表验证，未忽略该表 |
| [attempt-003](evidence/route-a-loader-20261124/attempt-003/report.json)，driver-v3 | 原 parser、原复制循环、全部 local records、入口分支和 ABI 均通过 | 仅三个 host verified 为 true；设备 entry、UEFI／ADT、完整 ISA／板级资格和 OS boot 继续为 false |

第三次执行检查了 10 个已加载段，生成 23,035,904 字节 heap 内存映像，SHA-256 为 `3b7fd3784364b4392b2b0fcded0ec0d99dc2075dd149fd32972a1709fce50f5c`；两个段尾和三个 zero-fill section 的补零内容通过。host C 使用 `-Wall -Wextra -Werror` 编译成功，编译 stdout／stderr 均为零字节。两个真实 `boot_args` 声明的 13 个顶层字段与 6 个 Video 成员布局一致，大小均为 1,152 字节；实际 prepared `assym.s` 的 10 个汇编偏移定义也匹配。

全表共 102,103 条，检查 102,103 条、跳过 0 条、改写 0 条。816,824 字节表的 SHA-256 为 `10e8066c80e3f621ef811f313ffa0cfb95cc56a0660079289e104682aeb832de`；完整绑定摘要为 `fa3a9285e725336e38d5d3ead99e991b16ce5ac81e21ef01c9bdbd96231a3a83`。其中 102,101 个值位于声明的非空 section 内，2 个属于精确的空 section 边界；存储地址模 8 为 0／4 的数量分别为 92,343／9,760。实际复制后对应指针字节保持一致。三次尝试各自的 16 项声明输入均在结束时复核不变。

版本变化以 [v1→v2](evidence/route-a-loader-20261124/patches/driver-v1-to-v2.patch) 和 [v2→v3](evidence/route-a-loader-20261124/patches/driver-v2-to-v3.patch) 两份 patch 保留。按逆序应用可从当前驱动精确恢复两次失败使用的脚本与配置，已逐字节验证；每次 transfer manifest 另绑定全部 10 个传输文件。当前代码没有被回填成旧尝试执行过的版本。完整摘要见 [本轮证据](evidence/route-a-loader-contract-20261124.json)。

## 固定来源

[配置](../configs/route-a-loader-probe.json) 保存每份输入的长度、SHA-256 和公开文件的 Git blob。原始 229 份设备源码／许可证清单保持不变。

| 来源 | 固定版本 | 使用范围 |
| --- | --- | --- |
| UniXNU catalog | [`8542980d02b4d2cc5c32ee3542de1760b2562aac`](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/components.toml) | 选择已声明的 DarwinBoot 组件 |
| DarwinBoot | [`3c75734014cdab0acd9541e88057b7606ee7ae08`](https://github.com/UniXNU/DarwinBoot/tree/3c75734014cdab0acd9541e88057b7606ee7ae08) | `DarwinBoot.c`、`BootArgs.h`、`Entry.S` 与原始 `LICENSE` |
| XNU | [`ac9718fb1af618d5ce8678d0dc6e8a58f252216f`](https://github.com/apple-oss-distributions/xnu/tree/ac9718fb1af618d5ce8678d0dc6e8a58f252216f) | 原始 `pexpert/pexpert/arm64/boot.h` 与 `APPLE_LICENSE` |
| 实际 prepared XNU | 成功的 `DEVELOPMENT_ARM64_BCM2837` 工作树 | 原样 `boot.h`、已应用所选补丁的 `start.s`、实际生成的 `assym.s` |
| 实际链接报告 | `link-attempt-004`，SHA-256 `738a7af11b32c08d0a4261611ba69f325d5a29bf424791b18e98879864feff7c` | 绑定候选字节、baseline 重现、callback 链接及前一轮输入保护结果 |

DarwinBoot 的 BSD-2-Clause-Patent 许可证、版权原文和各源文件 SPDX 保留在输出的 `sources/` 中。XNU header 保留 Apple／OSF 通知，`APPLE_LICENSE` 同样保存；这些声明没有改标为本项目或 DarwinBoot 的许可证。

实际 prepared `start.s` 还能由固定 [原始 start.s](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/osfmk/arm64/start.s) 依次应用 UniXNU `8542980d` 的 [apple-only-cpu-tunables.patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/apple-only-cpu-tunables.patch) 和 [native-4k-bootstrap-capacity.patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/native-4k-bootstrap-capacity.patch) 重建。独立内存应用核验得到相同的 25,194 字节、SHA-256 `115d15ee67b62c480b2122ced06bfd64e0151c514cf63a2cd578a1feff19548d`、Git blob `a757713d9cffc305dd37c2df64fef2f12f252c76`；两项补丁也保留在原 [71 项准备记录](evidence/route-a-kernel-preparation-20261123.json) 的来源清单中。这条绑定覆盖 prepared 源文件，不自动覆盖最终所有条件编译路径或生成的机器码。

## 执行的五层检查

### 1. 原始 parser 与外层普通 ARM64 约束

入口按固定边界提取 `SEGMENT` / `KERNEL` 声明、`ParseKernelHeader` 和 `ParseKernel`，保持函数源码字节不变；报告记录来源行号、提取长度及摘要。主机 C 编译使用 `-std=c11 -O2 -Wall -Wextra -Werror -shared -fPIC`，编译参数、stdout／stderr 和生成库均有摘要。

外层独立解析仍要求 ordinary ARM64 subtype 0、iOS 27.0 的部署命令、零未定义／common 外部符号、唯一 file-backed executable entry、匹配的 section 地址关系、段名唯一和无段重叠。section 自身的 `nreloc` 必须为零；动态表中的 local pointer 记录由下节完整检查。只接受本次非 prelinked 候选需要的 metadata 命令；遇到其他 load command、未支持的 fixup、非空 data-in-code 等形式给出拒绝原因。

生产 parser 本身支持的范围更广，例如它接受 arm64e；它也没有独立禁止不同虚拟段复用同一文件区间。测试保留并观察这些原行为，由外层明确拒绝不满足本次普通指针合同的输入。生产函数没有因本 probe 改写。

段标志仅显式接受 `0` 和 `SG_NORELOC=0x4`。固定 [XNU Mach-O 定义](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/EXTERNAL_HEADERS/mach-o/loader.h) 将 `SG_NORELOC` 定义为该段内及指向该段没有重定位的注记；它不改变 file-to-memory 复制方式。该注记不替代实际 relocation／undefined／load-command 检查，也不证明所有 loader fixup 闭合。`SG_HIGHVM`、`SG_FVMLIB`、保护／fixup 后只读标志以及所有未知 bit／组合继续拒绝。报告为每段保留 flags、maxprot、initprot 和长度，诊断包含段名与实际数值。

### 2. 固定虚拟地址与完整 local pointer 表

第一条 `LC_SEGMENT_64`、实际装载的 Mach-O header 和非空段的最低虚拟地址必须同为 `0xfffffff007004000`。这与本次真实链接命令和固定 [MakeInc.def](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/makedefs/MakeInc.def) 的 iOS ARM64 链接地址一致；检查器明确固定 `virtual_slide=0`。它拒绝另一个链接基址、`MH_SPLIT_SEGS`、`MH_DYLIB_IN_CACHE`、非空 `__thread_starts`、外部 relocation、未定义符号、间接符号／module／reference 表和不支持的记录形式。

固定 [loader.h](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/EXTERNAL_HEADERS/mach-o/loader.h) 把该动态表的 `r_address` 定义为相对于第一段虚拟地址的偏移，并说明 local relocation 用于离开静态链接地址时的调整。格式字段另外绑定同版本的 [reloc.h](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/EXTERNAL_HEADERS/mach-o/reloc.h) 和 [arm64/reloc.h](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/EXTERNAL_HEADERS/mach-o/arm64/reloc.h)。物理复制地址改变不自动构成这里的虚拟地址 slide。

本次合同逐条验收整个 `LC_DYSYMTAB` local 表：

- 表长严格为 `nlocrel * 8`，全部位于唯一 `__LINKEDIT` 文件区间内，不与 nlist 或 string table 重叠；local／external-defined／undefined symbol group 必须完整分割实际 nlist 表。
- 每条记录只能是非 scattered、local `ARM64_RELOC_UNSIGNED`、`r_length=3`、`r_pcrel=0`、`r_extern=0`；`r_symbolnum` 必须是实际存在的非零 section ordinal。
- 存储位置由第一段基址加有符号 `r_address` 得出，完整 8 字节必须唯一归属一条 file-backed segment。重复或部分重叠的存储区间全部拒绝。
- 读出的 64 位值必须位于记录声明的非空 section 的半开虚拟地址范围内；目标可以在 BSS／common，存储值本身必须来自文件。段名唯一性保证 section 父归属不会被同名空段遮蔽。
- 对零长度 section，只允许值精确等于它的起止边界，且该地址仍在其实际已加载父段内。该分类单独记录为 `empty_section_boundary`，不证明地址可解引用，也不放行一般非空 section 的 one-past 值。
- 存储段或目标父段若有 `SG_NORELOC` 注记，就与这条实际记录矛盾并失败。注记不能代替逐记录验证。

表本体保存完整 SHA-256；每条记录按原始顺序参与另一份固定宽度 binding 摘要，覆盖 index、存储 VA、文件偏移、目标 VA、section ordinal 和边界分类。报告记录所有条目的检查数、零跳过数、分类计数、前五条普通样本和所有 empty boundary，不以抽样代替完整循环。

`r_length=3` 表示存储宽度为 8 字节，没有要求存储位置必须 8 字节对齐。检查器按字节读取并报告 `VA % 8` 分布；这不证明目标 CPU 上任意未对齐访问的运行行为。它不改指针、不改原 relocation 表、不设置运行时 slide，也不宣称支持通用重定位。

真实候选中的两个空 section 边界存储位置有 `_CurrentVNode`、`_EndVNode` 符号，目标是零长度 `__DATA,__llvm_prf_vnds` 的起止地址。固定 [LLVM profile 源码](https://github.com/llvm/llvm-project/blob/58c46bae21181fb4240cf964461bea738d96d50e/compiler-rt/lib/profile/InstrProfilingPlatformDarwin.c) 用 section start/end 值初始化这两个指针，为边界分类提供源码解释；这是语义参考，不新增该已编译 runtime provider 的来源证明。检查器不要求不存在的目标 nlist，也没有人工补充目标地址根。

### 3. 原始复制代码与逐字节装载

从 `Boot()` 提取原样 `ZeroMem` 和按段 `CopyMem` 循环。主机 wrapper 将目标设为独立 heap 缓冲区，`Used` 只取 `Kernel.End - Kernel.Base`。生产 `Boot()` 的完整 `Used` 还包括启动参数、ADT 和实际提供的 sidecar；这些区域没有在本次 heap 实验中构造。

目标内存先填 `0xA5`，前后各放 64 字节 guard，再执行实际提取的复制代码。随后独立检查：

- C parser 返回的非空段列表、base、end、entry 与独立解析完全一致。
- 每段 file-backed 字节与原文件对应区间逐字节相同。
- `vmsize - filesize` 的尾部、段间空隙以及声明为 zero-fill 的 section 实际为零。
- 两端 guard 保持不变，目标大小严格等于内核 memory span。

原 Mach-O 不被修改。输出的 `kernel.load.bin` 另有完整 SHA-256；报告也保存每段复制摘要、所有补零区间和入口字节。只有完整复制验证成功后，报告才写入 `copied_pointer_storage_bytes_unchanged=true`，把上节验证的原始指针值与实际 heap 内存映像连接起来。

### 4. 真实入口的有界检查

`LC_UNIXTHREAD` 必须选中实际 `__start` 符号。`__start` 和 `_start_first_cpu` 都必须是唯一强定义，`n_sect` 必须指向实际包含该地址的 pure-instruction section，并且至少完整包含 4 字节。

当前普通 ARM64 候选的 `__start` 首字是 `0x140006f5`。检查器只解码这一条 AArch64 立即数 `B`，按有符号 26 位偏移计算目的地址，并要求它等于 `_start_first_cpu`。`BL`、其他指令或指向另一地址都会拒绝。这是单条 trampoline 的有界事实，不覆盖 early CPU 函数体控制流或实际异常行为。

固定 `Entry.S` 的源码约定为 EL1 下把 boot_args 物理地址放在 `x0`、向物理 entry 跳转；它还包含 cache maintenance 和 MMU 关闭。此文件在本轮仅固定来源与摘要，未编译为固件或执行。

### 5. 真实 boot_args 声明与构建生成偏移

主机翻译单元采用 DarwinBoot `BootArgs.h` 的真实声明，以及固定 XNU `boot.h` 中原样的 `Boot_Video`、`boot_args` 声明，逐字段计算 `offsetof`／`sizeof`。检查 13 个主要字段和 Video 的 6 个成员；结构总大小必须为 `0x480`。

| 字段 | 偏移 | 字节数 |
| --- | --- | --- |
| `Revision` / `Version` | `0x0` / `0x2` | 各 2 |
| `virtBase` / `physBase` / `memSize` / `topOfKernelData` | `0x8` / `0x10` / `0x18` / `0x20` | 各 8 |
| `Video` | `0x28` | 48，6 个成员各 8 |
| `machineType` | `0x58` | 4 |
| `deviceTreeP` / `deviceTreeLength` | `0x60` / `0x68` | 8 / 4 |
| `CommandLine` | `0x6c` | 1,024 |
| `bootFlags` / `memSizeActual` | `0x470` / `0x478` | 各 8 |

真实候选的 target 构建产物 `assym.s` 进一步核对 `BA_VIRT_BASE`、`BA_PHYS_BASE`、`BA_MEM_SIZE`、`BA_TOP_OF_KERNEL_DATA`、`BA_BOOT_FLAGS` 及各自 `_NUM`，共 10 个定义。重复、缺失或偏移不一致都会失败。

主机要求 little-endian LP64，UEFI 标量类型映射为固定宽度整数／`size_t`，unaligned read 与内存操作由 libc adapter 提供。提取 parser 只返回 SUCCESS、LOAD_ERROR、UNSUPPORTED 三类结果；host `EFI_STATUS=int`、`EFI_ERROR(s)=(s!=0)` 只保留这里的成功／失败分类。测试中返回的 `1`、`3` 是 host adapter 的枚举值，不是固件原始高位 EFI_STATUS。此检查不声明所有 UEFI 类型／服务、一般重叠内存复制或跨 ABI 行为等价。

## 物理布局保留为待绑定合同

固定 DarwinBoot 保留 `Args.VirtualBase = Kernel.Base`，独立选择 physical base。实际 prepared `start.s` 从 boot_args 读取两者，建立初始 identity／kernel virtual 映射，并把继续执行地址与 boot_args 按 `+VirtualBase-PhysicalBase` 转到虚拟地址。固定 [arm_init.c](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/osfmk/arm/arm_init.c) 的普通非 fileset 分支用运行时 header 地址减 `VM_KERNEL_LINK_ADDRESS` 计算 slide。因此，在上述固定 header／链接基址和实际交接正确成立的条件下，可以推导该虚拟映射采用零 slide，不能给 pointer 加上物理地址差。

这是一条源码层面的条件性推导。prepared `start.s` 已按上节精确绑定；`arm_init.c` 的支持限于固定原始版本，没有独立核对 candidate 的最终 prepared 全文件与预处理机器码。主机检查没有执行 `start_first_cpu`、启用 MMU 或观察 `vm_kernel_slide`；报告明确 `runtime_kernel_slide_verified=false`。本轮只对 entry 的一条直接 `B` 做机器码核验，没有把全部早期页表／`arm_init` 函数体纳入机器码审计。

入口不会选择臆测的物理基址，也不会生成假定的板级 ADT 或 boot_args 实例。报告中的 `physical_base`、`board_adt`、`uefi_window_size` 保持 `null`，同时明确保存固定 loader 的计算规则：

| 项目 | 规则 |
| --- | --- |
| kernel 物理基址 | 在实际 `EfiConventionalMemory` 连续区间中分配；低 21 位必须与 kernel virtual base 一致 |
| entry 物理地址 | `physical_base + entry_offset` |
| boot_args 物理地址 | `align_up(physical_base + memory_span, 16384)` |
| ADT 物理地址 | boot_args 物理地址加 4,096 |
| `deviceTreeP` | `virtual_base + ADT_physical - physical_base`，是对应虚拟地址 |
| `topOfKernelData` | 实际 physical base 加包括 ADT／sidecar 的完整 `Used` |

固定 parser 的内核 span 上限为 254 MiB，源码初始 window 为 256 MiB。二者都是软件限制／初始设置，不证明设备拥有可分配的连续内存。真正的 window 还受实际 ADT、UEFI memory map、reserved memory、sidecar 大小和 loader 分配成功约束。

实际 prepared bootstrap 用 2 MiB L2 block：虚拟与物理基址的低 21 位都必须为 `0x4000`，映射会从各自基址向下取整的 block 开始。初始 window 为 2 MiB 的整数倍时，它包含声明基址前的 16 KiB，并在声明 window 尾部留下尚未映射的 16 KiB。生产 loader 的 `Used <= WindowSize - 2 MiB` 留量不等于这些页已获得 UEFI 所有权。将来必须用真实 memory map 和分配结果验证此前缀、所有实际使用页与保留区；本次 heap 复制不覆盖该项。

## 输入保护与结果文件

probe 使用新输出目录，并拒绝把输出放入已有 source、kernel build 或输入目录。它固定并前后复核候选、链接报告、prepared header／startup source／assym、公开 loader 输入、当前驱动及两个 Python helper、配置和 host compiler 的身份；不接受以文件符号链接代替普通输入。读取使用已规范化的同一物理路径。

结果保留 `report.json`、实际生成的 `loader-probe.c`、主机库、编译 stdout／stderr、原始 source/license 副本和 `kernel.load.bin`。发生失败仍保存报告与已有输出，旧目录不覆盖。结束复核若发现任一保护输入变化，状态改为 failed，三个 host 通过旗标全部清零。

保护范围是声明的文件，不包含整个主机文件系统或系统 header／动态库的冻结证明。所有成功标志均属于 host 检查；`kernel_entry_executed`、`uefi_allocation_verified`、`board_adt_verified`、`full_instruction_set_audited`、`tb371fc_kernel_qualified`、`os_boot_verified` 持续为 false。

## 复现

先准备六份固定公开输入。此步骤不下载 Apple 系统二进制，也不下载完整 XNU 工作树：

```sh
python3 scripts/probe_route_a_loader.py prepare-sources \
  --output /absolute/new/loader-public-sources
```

真实候选检查还需要原成功 build 工作树、`link-attempt-004/report.json` 与候选本体；这些输入不得用本地合成 fixture 代替：

```sh
python3 scripts/probe_route_a_loader.py run \
  --sources /absolute/loader-public-sources \
  --kernel /absolute/link-attempt-004/mach.platform-link-probe.unstripped.noctf \
  --link-report /absolute/link-attempt-004/report.json \
  --xnu-work /absolute/kernel-build/.cache/xnu-work \
  --assym /absolute/kernel-build/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/osfmk/DEVELOPMENT/assym.s \
  --output /absolute/new/loader-attempt \
  --cc /usr/bin/cc
```

生产输入的版本／摘要不匹配会拒绝。新内核版本需单独审查合同和来源，不通过手改历史报告或跳过固定输入门槛推进。

## 回归与下一步

`tests/test_route_a_loader.py` 的 32 项定向回归包含 7 项实际生产 C 提取测试。它们覆盖段重叠／越界、文件与虚拟地址关系、zero-fill 实际内容、`SG_NORELOC` 空／非空段与其他 flag／组合的拒绝、arm64e 与不支持命令的外层拒绝、入口 section 归属、正负 B 偏移、Video 成员错位、assym 缺失／重复，以及晚期输入改写使所有通过旗标清零。

local relocation 回归另外覆盖完整表、packed 存储、BSS 目标、精确空 section 边界、同名空父段歧义、重复／重叠存储、非法 ordinal／type／length／pcrel／extern／scattered 形式、表越界／metadata 重叠、`SG_NORELOC` 矛盾、非零 slide 和 threaded fixup 拒绝。生产 C 复制回归核对这些指针原字节保持不变。Mach-O 样本由测试自写，不能计作 XNU 启动。

```sh
ROUTE_A_LOADER_SOURCES=/absolute/loader-public-sources \
  python3 -m unittest discover -s tests -p test_route_a_loader.py -v
```

未设置 `ROUTE_A_LOADER_SOURCES` 时真实 production C 测试类明确跳过；纯结构测试仍可执行。[CI](../.github/workflows/source-check.yml) 会准备同一批固定源文件并设置该变量，pager C 源准备继续单独执行。

下一项启动证据需要真实板级 ADT、可用且无保留区冲突的 UEFI memory map、完整 provider／prelink 依赖和匹配的固件交接产物。随后才能在可恢复的设备路径中观察真正的 `__start`／early CPU 执行及首个失败点；本次 host 合同不会替代那些门槛。

2026-11-26 新增的 [DarwinBoot 分配前缀修复](ROUTE_A_ALLOCATION_PREFIX.md) 单独处理上文 2 MiB block 映射覆盖未拥有前缀的问题，并在合成 memory map 上执行提取的原版／修复版 allocator C。该工作没有更改本文历史输入或通过旗标，真实 UEFI 分配、末尾初始映射与设备启动继续各自验收。
