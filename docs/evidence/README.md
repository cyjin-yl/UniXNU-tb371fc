# 路线 A 证据索引

本目录保存可公开、可追溯的结果摘要。系统二进制和原始私有日志不在仓库分发。文件名日期是该次记录日期，不代表之后所有改动都已重新执行相同测试。

## 通用内核编译／链接成功：2026-11-24

第二轮真实 builder 已返回 0，生成普通 ARM64 `MH_EXECUTE`、subtype 0 的通用候选。完整说明见 [ROUTE_A_GENERIC_KERNEL_RESULT.md](../ROUTE_A_GENERIC_KERNEL_RESULT.md)。

| 记录 | 实际结果 | 范围 |
| --- | --- | --- |
| [第二轮通用候选构建](route-a-generic-kernel-build-20261124.json) | 1,086 个 `.o` / `.cpo`；link filelist 有 1,067 个非空行；候选为 21,905,888 bytes（20.89 MiB）；0 编译 error | `generic_kernel_compiled_and_linked=true`；完整 TB371FC profile、provider/archive、ISA 与 27 启动仍未验收 |
| [真实 debug.o 中的 fileset helper](route-a-compiled-fileset-helper-20261124.json) | 整份 `debug.c` 编译完成；helper 使用 `0xd50320ff` HINT 字；分支重定位仍指向 `_panic` | 关闭首次源码编译阻塞；不覆盖其他函数、外部 archives 或硬件执行 |
| [候选有限编码与符号检查](route-a-kernel-candidate-audit-20261124.json) | 3 个区域、2,220,163 个候选 4 字节字；分类器识别的非 HINT PAuth 为 0，精确 POE2 TCHANGE 为 0，180 个 `XPACLRI` HINT；未定义符号为 0 | 指令区间和规则范围固定；不证明可达性、全部 ISA 或完整板级依赖 |
| [原始审计证据目录](route-a-kernel-audit-20261124/) | 原始报告、180 条位置记录、Mach-O 几何、工具输出、执行脚本、固定分类器和逐文件摘要 | 保留实际执行快照；复跑须使用新目录，不覆盖这些记录 |

第二轮记录保留真实 driver、源码、工具和产物摘要。原 builder 中 `kernel_compiled` / `kernel_linked` 表示完整候选资格，仍为 false；通用候选实际编译／链接成功单独记录，避免把板级与启动资格一并提升。第一次失败的 716 个对象、日志和报告继续留存。

## 定制编译器完成与首次内核失败：2026-11-24

提交 [ce834a0](https://github.com/cyjin-yl/UniXNU-tb371fc/commit/ce834a0e2e9d63803d920f39f30012e4759102cf) 的 [CI](https://github.com/cyjin-yl/UniXNU-tb371fc/actions/runs/45221437252) 已通过 **210 项回归，0 跳过**，以及固定源码 staging。原 71 项基线与补齐 headers 后的清单保持历史摘要，独立 fileset 修复层已实际应用；[本轮回归与 staging 记录](route-a-build-fix-validation-20261124.json) 绑定提交、作业、artifact 及最终源码摘要。完整 XNU retry 的实际执行结果另行记录。

| 记录 | 实际结果 | 范围 |
| --- | --- | --- |
| [定制 Clang 与组合工具链完成](route-a-toolchain-success-20261124.json) | Clang 24 固定源码构建完成；19 个 XNU 类型语义断言通过；19 个最终工具输出有摘要 | 旧探针未证明完整指令集；新发现的默认 Apple CPU 问题另行修复 |
| [首轮真实 XNU 编译失败](route-a-first-kernel-failure-20261124.json) | 716 个目标文件；无条件 PAuth builtin 产生唯一 Clang error；builder 返回 2 | 没有完整 kernel candidate、link filelist 或 OS 启动结果 |
| [fileset panic 修复实际测试](route-a-fileset-ptrauth-20261124.json) | 定制 Clang 4/4 真实回归通过，0 跳过；保留两个前次失败与 generic codegen 结果 | [修复说明](../ROUTE_A_FILESET_PTRAUTH.md)；本记录未替代真实 compiler wrapper 验收 |
| [真实生产 Clang wrapper 检查](route-a-production-shim-20261124.json) | 3 次真实编译、7 项返回地址检查通过；参数来自 frozen builder；compiler/shim 摘要前后一致 | 普通 ARM64 返回地址样本使用 generic CPU 和兼容 HINT #7；完整内核 ISA 仍未审计 |

此前“Clang 正在构建”的快照保持原样。新增记录绑定实际完成的旧 driver、真实 compiler SHA-256、原始报告与完整失败日志的摘要，不将后来修订的脚本当成旧构建执行过的版本。

## 先前工具链、局部路径与构建输入：2026-11-23

提交 [3a52649](https://github.com/cyjin-yl/UniXNU-tb371fc/commit/3a52649f837f49f8df638d165f3dbbb7aa20e953) 的两个 [CI 作业](https://github.com/cyjin-yl/UniXNU-tb371fc/actions/runs/45181619136) 均通过：**191 项回归、0 跳过**，229 份原始源码／许可证摘要保持一致。33 项 TPRO 回归、9 项工具链回归与 6 项首次构建入口回归包含在总数中；9 项提取真实 pager C 的检查仍实际执行。

| 记录 | 实际结果 | 范围 |
| --- | --- | --- |
| [真实 dyld 局部路径](route-a-tpro-local-paths-20261123.json) | 固定原始文件实际重跑；4 个入口均匹配，2 个条件区域闭合 | 另外 2 个仍有调用／异常／间接转移缺口；全程序和全部 236 处 TCHANGE 未证明 |
| [首轮构建输入 staging](route-a-kernel-staging-20261123.json) | 7 份固定源码；21 个已有 header 保留，5 个 TrustCache header 新增 | 包含 artifact、原始报告、原始／新增后 inventory 摘要；未执行完整 XNU builder |
| [主机工具语义验收](route-a-host-tools-smoke-20261123.json) | 3 组自写样本，15 次真实命令成功；工具前后摘要一致 | 普通 ARM64 archive/kernel-mode 链接、MIGCOM 生成、LZFSE 往返；完整 XNU 和 SDK 未验证 |
| [候选内核能力发布源码核对](../ROUTE_A_TPRO_KERNEL_PUBLICATION.md) | 已检查的 exec 函数没有构造两个 TPRO 键，有 security_config 发布与继承 | 最终 generated config、pmap 选择、commpage 实际值及其他写入者仍需核验 |
| [MemoryManager 调用边界](../ROUTE_A_MEMORY_MANAGER_CALL.md) | `0x719c` 定位到 syscall 38 / crossarch 查询，核对候选内核错误返回 | 后续字符串扫描、commpage 与最终 syscall 约定未验证；原 blocker 保持 |
| [实际构建任务快照](route-a-build-execution-20261123.json) | 定制 Clang 正在编译；host components 与 staging 已完成；接续任务已启动 | 记录时完整 kernel builder 尚未开始，后台完成状态必须另取新记录 |

公开 staging 报告只替换 CI 临时目录前缀，主机工具报告只替换开发工作目录前缀；原始报告 SHA-256 保留，其他摘要和结果没有改变。实际开发容器 staging 得到与 CI 一致的 XNU source inventory。主机工具样本使用 stock Clang 19.1.7；定制 Clang、最终组合工具链与完整 builder 的结果单独记录。

主机验收脚本与这些文档随后发布于 [0e0edaf](https://github.com/cyjin-yl/UniXNU-tb371fc/commit/0e0edaf6d65ea4b28eb795a466005ef9b34ca73f)，其 [CI](https://github.com/cyjin-yl/UniXNU-tb371fc/actions/runs/45183600246) 同样实际通过 191 项回归、0 跳过及 source/header staging。CI 不执行远端主机样本，样本的实际报告另有工具与输入绑定。

## 前次源码准备集成：2026-11-23

提交 [5524e74](https://github.com/cyjin-yl/UniXNU-tb371fc/commit/5524e745ea50c71916b8abeb718b167e2d3c3350) 的两个 [CI 作业](https://github.com/cyjin-yl/UniXNU-tb371fc/actions/runs/45173610144) 均通过：

- [本轮验证汇总](route-a-continuation-validation-20261123.json)：**162/162 项，0 跳过**；包含 9 项提取真实 pager C、19 项 TPRO 审计和 23 项内核准备测试。
- [通用内核源码准备报告](route-a-kernel-preparation-20261123.json)：71 项补丁实际应用，6,119 个源码条目有摘要，普通 arm64 配置探针生成 subtype 0 的 Mach-O 对象。

这是架构、Darwin 26 兼容和 plain-pager 源码子集。1 项依赖板级 PMGR/watchdog 的 boot-progress 补丁明确延后，完整 profile 未应用。该次记录中完整 XNU 尚未编译／链接／启动，Clang 18.1.3 的 XNU type builtin 探针实际失败；后续定制工具链与通用候选成功结果见上节，历史 JSON 保持原样。

该次 162 项检查没有重新执行首轮设备函数或 Apple 用户空间改写，也尚未重新采集 TPRO 真实输入。后续 TPRO 重跑见上节；下列首轮 JSON 保持原样。

## 首轮结果：2026-11-23

对应成果提交：[eb2ccfa](https://github.com/cyjin-yl/UniXNU-tb371fc/commit/eb2ccfaa6bf93b542c0234f28efd7ec93d3c7c61)。[该提交的 CI](https://github.com/cyjin-yl/UniXNU-tb371fc/actions/runs/45146081342) 已通过；完整回归为 120 项，其中包含 9 项提取真实 pager C 的测试，0 跳过。后续提交的检查结果应查看 [Actions](https://github.com/cyjin-yl/UniXNU-tb371fc/actions)，不沿用本次数字。

| 记录 | 结果 | 范围与限制 |
| --- | --- | --- |
| [验证汇总](route-a-validation-20261123.json) | 120/120 主机检查、229 份原始源码／许可证摘要 | 全局启动、完整 ISA、整机硬件仍为未验证 |
| [设备原生测试](route-a-native-20261123.json) | 23/23 组；46 次基准与转换函数的独立子进程执行 | TB371FC Android 环境；合成函数，不是 Darwin 程序 |
| [独立汇编器](route-a-assembler-20261123.json) | 原始编码 54/54；普通替换编码 45/45 | GNU Binutils 2.44；9 条拒绝向量只核验原始编码 |
| [输入 profile](route-a-input-profile-20261123.json) | 27.0.1 / 24A446、iPad17,3 / j820ap 清单信息 | 清单身份与任意输入文件的归属证明分开 |
| [真实输入提取](route-a-extraction-20261123.json) | 官方镜像来源、工具与两个原始文件哈希 | 分段读取统计仅限记录范围；没有分发系统文件 |
| [launchd 改写](route-a-launchd-27.0.1-20261123.json) | 2,409 处；150 个 4 KiB 签名页独立验证 | 暂存输出；Darwin 进程未启动 |
| [dyld 改写](route-a-dyld-27.0.1-20261123.json) | 5,385 处；347 个 4 KiB 签名页独立验证 | 236 条 FEAT_S1POE2 指令保留；目标 ISA 未全部证明 |
| [TPRO 局部分流](route-a-dyld-tpro-20261123.json) | 部分构造、callback 和保护栈分支核验 | 早启动、键注入及全部路径仍不完整 |

`launchd` 和 `dyld` 的原始 cdhash 均在匹配 trust cache 中找到；新条目的属性已准备，但 `owner_trust_bundle_installed=false`。签名代码页验证通过不表示 Apple 签名有效或内核已经接受产物。

## 源码与补丁证据

| 记录 | 用途 |
| --- | --- |
| [CFG／缓存工具来源](../../upstream/route-a-sources.json) | 固定上游 commit、原始文件摘要及许可证 |
| [pager 来源与各阶段摘要](../../upstream/route-a-kernel-sources.json) | 四个 XNU 文件、前置补丁、本地补丁与应用／反向恢复状态 |
| [提取工具来源](../../upstream/route-a-extraction/sources.json) | ipsw、go-apfs、type 4 补丁与工具版本 |
| [内核补丁说明](../ROUTE_A_PLAIN_AUTH_PATCH.md) | 支持范围、提取 C 验证与没有覆盖的内核集成 |
| [开发验证命令](../../DEVELOPMENT.md) | 完整主机检查入口及跳过项的含义 |

CPU 翻译粒度、XNU VM 页、CodeDirectory 签名页和 dyld slide 页分别记录；表中的 4 KiB 签名页不表示完整内核已经选定同样的页大小。

## 后续审计与准备入口

- [TPRO 审计器](../ROUTE_A_TPRO.md) 对固定 24A446 原始 dyld 生成清单及四个保守局部路径结果；合成回归与真实输入执行分别记录。
- [普通 arm64 内核准备器](../ROUTE_A_KERNEL_BUILD.md) 和 [首次 builder 的 staging](../ROUTE_A_FIRST_KERNEL_BUILD.md) 实际结果保存在 CI 的 `route-a-kernel-preparation` 产物中。源码应用、配置探针、输入准备、完整编译与启动状态分别记录。
- [定制工具链](../ROUTE_A_TOOLCHAIN.md) 提供可恢复构建、19 项 compiler 语义断言和主机组件验收。成功组件 manifest 绑定源码和产物，不凭文件存在认定已通过。

## 后续记录需要包含什么

新增结果应绑定输入与产物哈希、源码提交、工具版本、命令、执行环境、成功／失败／跳过数量及实际覆盖范围。首轮 JSON 保持原样，以新文件记录后续进展。公开记录省略序列号、账号、凭据、私有路径和无关设备日志。

对于系统集成，分别标记：

- 静态分析和输入覆盖是否通过。
- 改写产物和独立哈希检查是否通过。
- 完整内核是否编译／链接，是否在设备启动。
- Darwin 进程、图形桌面与每项硬件是否实测。

任何一层成功都不自动证明后一层。当前通用内核候选已完成源码编译／链接，完整 TB371FC 板级依赖、ISA、27 用户空间和实机启动仍待集成；下一步见 [路线图](../../ROADMAP.md)。
