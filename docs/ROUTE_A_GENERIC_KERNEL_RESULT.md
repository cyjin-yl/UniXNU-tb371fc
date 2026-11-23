# Route A：普通 ARM64 通用内核候选构建成功

记录时间：2026-11-24，Asia/Shanghai。

第二轮真实 XNU 构建已完成编译与链接，产出普通 ARM64 的 Mach-O 内核候选。它建立了 Route A 的通用源码构建基线；完整 TB371FC 板级集成、全部指令集兼容性和 iPadOS 27 用户空间启动仍未验证。

## 已完成的构建

| 项目 | 实测结果 |
| --- | --- |
| 构建驱动源码 | `ce834a0e2e9d63803d920f39f30012e4759102cf`，随后通过 PR #1 合入主线 |
| LLVM | `58c46bae21181fb4240cf964461bea738d96d50e`，自建 Clang 24.0.0git |
| XNU | `xnu-12377.121.6` / `ac9718fb1af618d5ce8678d0dc6e8a58f252216f` |
| UniXNU | `8542980d02b4d2cc5c32ee3542de1760b2562aac` |
| 源码选择 | 通用 ARM64 架构、Darwin 26 ABI 补丁、plain pager，再应用已验证的单个构建修复 |
| 构建配置名称 | `DEVELOPMENT_ARM64_BCM2837`；这是本轮通用候选沿用的配置名，尚不具备完整 TB371FC 板级资格 |
| 生产编译器 CPU | `generic`，通过真实 CommandLineTools shim 检查 |
| 构建结束 | 2026-11-24 01:15:20（北京时间），builder 退出码 `0` |
| 编译结果 | 1,086 个 `.o` / `.cpo` 文件，错误诊断 `0` |
| 链接输入 | 1 份 `link.filelist`，1,067 个非空行；与编译产物计数分别记录 |
| 内核文件 | `.unstripped` 和 `.unstripped.noctf`，各 21,905,888 字节（约 20.89 MiB），内容摘要相同 |
| Mach-O 头 | `CPU_TYPE_ARM64`、subtype `0`、`MH_EXECUTE` |
| 未定义符号 | `llvm-nm-19 --undefined-only --format=posix` 退出码 `0`，标准输出与错误输出均为空 |

内核文件 SHA-256：

```text
a58cdeedb9b7a4c152867c3487f28658a3799b0158f5046bbad6d2d58e741469
```

这份文件来自已固定版本的开放源码 XNU 与 UniXNU 补丁。构建环境中的 iOS 27.0 / 24A446 SDK 标记表示目标适配环境，不能把它解释成已经取得或启动了 Apple 原版 iPadOS 27 内核。

完整参数、输入摘要、三层源码清单、产物摘要和原始报告摘要见[构建记录](evidence/route-a-generic-kernel-build-20261124.json)。原 builder 的 `kernel_compiled` / `kernel_linked` 字段仍用于尚未完成的完整候选资格检查；本记录用 `generic_kernel_compiled_and_linked=true` 单独表述已实际完成的通用编译与链接，完整板级资格保持为 `false`。

## 本轮解决的阻塞

第一轮在 716 个对象文件之后失败，报错来自 `unixnu_fileset_unmapped` 对 `__builtin_ptrauth_strip` 的无条件调用。修复在普通 ARM64 下保留返回地址和原有 panic 参数，在具备 PAuth 编译特性时继续保留 strip 调用。第一轮目录、错误诊断与日志摘要已保留，见[首次失败记录](evidence/route-a-first-kernel-failure-20261124.json)。

真实编译还揭示 Darwin 目标默认 CPU 会选择带 PAuth 的 Apple CPU。生产环境已显式加入 `-mcpu=generic`；构建前的探针直接调用安装后的 CLT shim，使用实际生产环境，不在探针参数中额外补 `-mcpu` 或 `-march`，CPU 选择由真实 wrapper 环境提供。IR、汇编和对象文件的 7 项检查均通过。修复代码和构建门槛已经通过 [PR #1](https://github.com/cyjin-yl/UniXNU-tb371fc/pull/1) 合入。

完整 `debug.c` 现已在真实内核构建中生成 `debug.o`。对目标函数的独立反汇编确认返回地址路径使用 `0xd50320ff`（`XPACLRI`，兼容 HINT 编码），并保留指向 `_panic` 的 `ARM64_RELOC_BRANCH26` 重定位。这里没有把单函数检查扩大成整个内核的指令集证明；见[对象文件证据](evidence/route-a-compiled-fileset-helper-20261124.json)。

## 内核产物的限定范围审计

审计读取原内核，不改写文件，并在前后核对内核和 `.noctf` 摘要。Mach-O 解析没有报告 warning 或 blocker。

| 扫描项 | 结果与范围 |
| --- | --- |
| 候选区域 | 3 个非空、标记为指令的 section 范围，共 8,880,652 字节 |
| 候选四字节字 | 2,220,163 个；没有将它们全部宣称为可达指令 |
| 非 HINT PAuth | 项目原始 Armv8.3 PAuth 分类器命中 `0` |
| POE2 | 项目精确 `TCHANGEF` / `TCHANGEB` 编码规则命中 `0` |
| 兼容 PAuth HINT | 180 个 `XPACLRI` / `0xd50320ff`，已保存全部位置和邻近符号 |
| `LC_DATA_IN_CODE` | 条目 `0`；缺少此标记的字面量池仍可能位于候选范围内 |
| 完整 ISA / 可达性 / 启动 | 均未证明 |

扫描覆盖的是明确列出的编码集合，未覆盖所有后续架构扩展。`llvm-nm` 的结果记录了该产物符号表没有未定义项，仍不能替代外部驱动、运行时符号或完整板级依赖闭包检查。

见[审计摘要](evidence/route-a-kernel-candidate-audit-20261124.json)和[原始证据目录](evidence/route-a-kernel-audit-20261124/)。该目录保存原始报告、180 条编码记录、Mach-O 几何信息、工具输出、实际执行的审计脚本、固定版本分类器和逐文件摘要。审计脚本是本轮固定路径、固定产物的执行快照；需要复跑时应先复制脚本、`source-manifest.json` 和 `classifiers/` 到空目录，并准备同一摘要的候选文件。保留原始快照，不能直接在证据目录内重跑覆盖记录。

## QEMU 并行成果

[QEMU PR #2](https://github.com/cyjin-yl/qemu-tb371fc/pull/2) 已合入 `tb371fc`，提交 `69ca28dec6add998d252fa6436dfcc9b9cab6e36`。[最终 CI](https://github.com/cyjin-yl/qemu-tb371fc/actions/runs/45224664341) 成功，包含 55 个组件检查、4 个 Linux 检查、23 个 C SMMU qtest（无跳过）、18 个既有迁移检查、26 组新页粒度检查、852 个 A77 guest 检查以及 15 个 UFS PCI 检查。

SMMUv2 增加显式 4 / 16 / 64 KiB 页粒度配置及相应页表遍历、权限和故障处理，默认仍仅声明 4 KiB。额外 CT102 测试完成 28 组检查和 5 次迁移尝试，覆盖旧 v2 状态到默认配置的迁移后 ATS / DMA，以及不兼容配置的预期拒绝。该额外测试使用较早 CI 构建的同模型源码二进制，原始记录与最终 CI 二进制摘要分别保留；见 [QEMU 发布证据](https://github.com/cyjin-yl/qemu-tb371fc/tree/69ca28dec6add998d252fa6436dfcc9b9cab6e36/tb371fc/evidence/smmuv2-granules-20261123)。这些结果尚不证明整板迁移、GPU 执行或 Android / iPadOS 启动。

## 接下来的集成门槛

1. 在本轮成功基线上补齐 TB371FC 板级 profile、provider 与 archive / prelink 依赖闭包，逐项记录新增驱动和链接输入。
2. 对完整候选继续检查 A77 指令集和加载入口，建立最小串口 / panic 路径的启动证据。
3. 与已有 dyld、共享缓存和 TPRO / POE2 适配工作会合，验证真实 iPadOS 27 用户空间启动链。
4. QEMU 继续作为可重复的设备与异常路径验证环境；原生 Route A 仍是性能目标。

本轮结束时：通用 ARM64 内核编译与链接成功；完整 TB371FC 启动和 iPadOS / macOS 27 启动均未验证。
