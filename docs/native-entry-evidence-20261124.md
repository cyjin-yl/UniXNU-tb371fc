# 本机 DT 入口与 Novatek 诊断证据：路线 A 的接入条件

日期：2026-11-24（Asia/Shanghai）。本次文档基于 UniXNU `main`
`f016cc9ae750b798b60a3e3e1a0f0955bf9a78b0`。本页接入 Linux 工程取得的
Android 只读观察、备份格式检查和一项驱动修复，未构建或启动新的 XNU 候选。

路线 A 继续采用离线 arm64e → 普通 arm64、CPU 原生执行及全链路普通指针 ABI。
iPadOS 27 与 macOS 27 仍独立验收。Linux 原有硬件台账保持 **44 项：12 项阻塞、
32 项未运行、本机原生 Linux 通过数 0**；下列证据不转记为 XNU 硬件通过。

## 当前启动描述已能逐项对应

来源是 Linux 仓库的 [live Android 元数据][live]与[实际备份 DT 检查][backup]。
2026-11-24 10:23:24 取得的 Android 属性和内核命令行白名单一致报告：
槽位 `_a`，基础树 `dtb_idx=0`，覆盖项 `dtbo_idx=2`。
它们是两个一致的报告视图，没有重放 ABL 的选择过程。

| 层次 | 当前准确身份 | 对本仓库的含义 |
| --- | --- | --- |
| 备份 `boot_a` 的基础树索引 0 | 538,388 字节；SoC ID `<356 131073>`；板 ID `<0 0>`；kona v2.1 | 锁定第一层来源；它仍不是应用了板级覆盖和启动器修改的完整树 |
| 备份 `dtbo_a` 的覆盖表项 2 | 502,232 字节；板 ID `<11 0>`；QRD compatible | 与当前 live 板标识相符；匹配不能代替实际合成和加载证据 |
| live FDT | 973,052 字节、4,276 节点；SoC ID `<356 131073>`、板 ID `<11 0>` | 作为板级元数据来源；未验证 XNU 入口可直接使用这份树 |

每份 boot/recovery 的 DTB 组件实际包含 4 份串联 FDT。`boot_a` 的索引 0 与
其余三份镜像中的索引 0 字节不同，不能仅凭名称或 SoC ID 换用。
两份 recovery-DTBO 与两份 dtbo 分区的有效表体都是 14 项、4,299,963 字节，
SHA-256 为 `279910628e61cad149ccdb16ae0aa0a3a2f46441e21132ac3a1323e565219679`。
AVB、回滚兼容性、实际加载位置与可达恢复仍需各自验证。

[对应报告][correlation]已经使用上述实际公开输入运行；重复、冲突、非法或越界的
索引不采用第一条值继续推断。报告中的 35 个 reserved-memory 节点已采集元数据
与基础树一致，但基础树的 RAM 仍是占位，model、compatible 和板 ID 也与 live 树
不同。报告保持 `runtime_abl_replayed=false` 和
`per_byte_runtime_selection_verified=false`，不把分层标识对应升级为完整入口证明。

### 独立字段核对通过，离线树仍不是 live 树

[独立 libfdt 回执][libfdt]于 2026-11-24 10:35:27 实际完成：DTC 1.7.2 工具执行
136 条命令，基础树 56 项及覆盖项 7 项同输入字段读取全部与先前解析结果相等，
且未导入项目自身的 DT 解析器。这 63 项字段核对属于解析证据，不是设备通过数。

实际 `fdtoverlay(base0, overlay2)` 返回 0，仍未复现 live 树的四组公开字段：

| 字段 | 离线合成产物 | live Android |
| --- | --- | --- |
| root compatible | `qcom,kona` | `qcom,kona-qrd / qcom,kona / qcom,qrd` |
| root model | `kona v2.1 SoC` | `kona QRD` |
| Qualcomm ID 组 | 板 ID `<0 0>` | 板 ID `<11 0>`；SoC ID 相同 |
| `/memory/reg` | `(0, 0)` 占位 | 下述两段 RAM |

因此原生 XNU 平台入口仍需要明确启动器修订及交接后的描述。离线覆盖成功不能使
RAM 占位成为可用内存，也不能证明 XNU 能消费最终设备树或已经重放 ABL。

### 内存与 provider 的启动依赖

live `/memory/reg` 描述的半开区间是 `[0x80000000, 0xbbb00000)` 和
`[0xc0000000, 0x280000000)`。备份基础树内仍有 `(0, 0)` 内存占位；不能把
离线基础树的占位或单一 RAM 容量直接交给 XNU 物理内存初始化。

live 树有 35 个 reserved-memory 子节点：23 个静态范围和 12 个动态分配请求。
静态范围合并后为 7 个区间，显示 dump 与 continuous splash 在 `0x9c000000`
重叠 8 MiB。XNU 平台描述需要分别承接保留范围、动态需求及相关设备所有权，
再建立 kernel/provider/DMA 的释放时机。DT 静态排除区不是完整的固件或 loader
使用图，动态请求也不是可以静默丢弃的 Linux 私有标记。

live 树有两处非零属性对齐填充：偏移 821109 和 821537，各自 3 字节填充中有
1 个非零字节。原严格检查失败已保留。显式 forensic 读取只返回有界元数据并标记
`format_compliant=false`；备份与候选产物仍走严格解析。这不构成放宽 XNU
Mach-O、CFG、proof、签名页或原生 DT 入口门禁的理由。

## Novatek 错误路径可用于原生适配审查

Linux 已合并的 [PR #9][novatek-pr] 修正了 WDT 历史诊断忽略选页／SPI 返回值及未检查分配的
问题：失败进入清理路径，尝试恢复 event page，保留首个 errno；诊断失败仍继续
原来的固件重载调用。它保留成功数据格式和固件选择／下载协议。

[固定来源报告][novatek-report]已经保留 24 项实际 C 检查、3 处原版缺陷复现和
ARM64 模块构建。新模块 698,512 字节，SHA-256
`998623b5b8d5666493162b04b01e3b3453777b3586d644d2296b23674881dc69`，
未签名、未安装、未加载；没有替换原来的 84 模块 R5 集合。完整 WDT/ESD 事务、
重载错误处理、笔状态恢复和物理输入功能仍开放。

本仓库的 `package/NovatekProtocol/`、`package/QcomGeniSpi/` 与
`package/Tb371fcTouch/` 应分别核对传输的成功／失败语义、页选择、诊断可选性和恢复
顺序，再建立 IOKit 原生的失败回归。可共享的是协议事实和失败向量；Linux 模块不能
直接载入 XNU，C 函数检查也不代表 XNU 线程、IRQ、DMA 或电源生命周期已经正确。

## 下一份有用的路线 A 证据

1. 将平台输入绑定到确切基础树、覆盖项和启动器修改记录。保留报告索引与实际合成
   结果的区别；离线生成树必须另记输入、工具版本和产物摘要。
2. 在 XNU 启动参数／平台适配层明确 RAM banks、固件／loader 保留区及动态分配需求，
   让每个 provider 的 MMIO、DMA、IRQ 与电源依赖对应同一来源。
3. 在完整 provider/archive、普通 ARM64 ISA 和 ABI 门禁下验证具体入口；再分别记录
   设备内核启动、Darwin 进程、iPadOS 27 和 macOS 27 的系统服务与桌面。
4. 原生触控／笔验证继续使用本仓库自己的 HID、休眠恢复和延迟回执。Linux、QEMU
   或社区作者的通过结果保留原有来源，不填入这里的物理设备验收栏。

本页只保存可公开的摘要和来源链接。原始 DT、原厂与 Apple 系统文件、私有备份及
原始设备日志保持在仓库外。公开记录身份：

| 记录 | SHA-256 |
| --- | --- |
| live FDT 字节 | `5114262a0dea5ef82b53db69b3d489ddbe57040e1a50b57365e87a28d2946207` |
| 公开 live JSON | `e071f91b43a063ff6f96cb401269469e20703ab695e64dd37a1d5b86113ba745` |
| 公开备份检查 JSON | `3ac35a67582837d4eb7009e224dd8e4beb69377a2c832549466eb4cc3f21d5e6` |
| 确定性对应报告 | `ac050fe46cf5df81b672cd22fe45605f4962ae6dbc905ca3ee9791089b69c654` |
| 独立 libfdt 回执 | `49286ad739400926b17b1dd6732a09b6be1686f0f63809d5f40ba0fbdd0a6f35` |

[live]: https://github.com/cyjin-yl/TB371FC-6.12/blob/0d733edba701b45613670bc7d1e2c060db1a5e3d/docs/research/2026-11-24/evidence/native-dt/live-android.json
[backup]: https://github.com/cyjin-yl/TB371FC-6.12/blob/0d733edba701b45613670bc7d1e2c060db1a5e3d/docs/research/2026-11-24/evidence/native-dt/backup-final.json
[correlation]: https://github.com/cyjin-yl/TB371FC-6.12/blob/0d733edba701b45613670bc7d1e2c060db1a5e3d/docs/research/2026-11-24/evidence/native-dt/correlation.json
[libfdt]: https://github.com/cyjin-yl/TB371FC-6.12/blob/0d733edba701b45613670bc7d1e2c060db1a5e3d/docs/research/2026-11-24/evidence/native-dt/libfdt-final.json
[novatek-pr]: https://github.com/cyjin-yl/TB371FC-6.12/pull/9
[novatek-report]: https://github.com/cyjin-yl/TB371FC-6.12/blob/53a4c27a3fa1af401ec4f824343d8b044ad35929/docs/research/2026-11-24/novatek-wdt-history.md
