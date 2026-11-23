# 路线 A 证据索引

本目录保存可公开、可追溯的结果摘要。系统二进制和原始私有日志不在仓库分发。文件名日期是该次记录日期，不代表之后所有改动都已重新执行相同测试。

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

- [TPRO 审计器](../ROUTE_A_TPRO.md) 可为固定 24A446 原始 dyld 生成新清单。其合成回归与真实输入执行分开；没有新真实输入报告时不扩展既有 TPRO 结论。
- [普通 arm64 内核准备器](../ROUTE_A_KERNEL_BUILD.md) 的实际结果保存在每次 CI 的 `route-a-kernel-preparation` 产物中。源码应用、配置探针、完整编译与启动状态分别记录。

## 后续记录需要包含什么

新增结果应绑定输入与产物哈希、源码提交、工具版本、命令、执行环境、成功／失败／跳过数量及实际覆盖范围。首轮 JSON 保持原样，以新文件记录后续进展。公开记录省略序列号、账号、凭据、私有路径和无关设备日志。

对于系统集成，分别标记：

- 静态分析和输入覆盖是否通过。
- 改写产物和独立哈希检查是否通过。
- 完整内核是否编译／链接，是否在设备启动。
- Darwin 进程、图形桌面与每项硬件是否实测。

任何一层成功都不自动证明后一层。当前项目仍处于离线工具与原生执行基础验证阶段；下一步见 [路线图](../../ROADMAP.md)。
