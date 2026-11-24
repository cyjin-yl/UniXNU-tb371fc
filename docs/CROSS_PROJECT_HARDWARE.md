# TB371FC：主线 Linux、QEMU 与路线 A 的共用硬件资料

记录日期：2026-11-24（Asia/Shanghai）。本次核对的 UniXNU `main` 为 `573ea14a917648f38fd3f2f920020aaf7a28f6ff`。

同轮文档的 Linux 研究基线为 `ec42c48405eb3966ca2539e53d96d02a5e725059`（`research/reproducible-build-gpu-20261123`），QEMU 已发布基线为 `69ca28dec6add998d252fa6436dfcc9b9cab6e36`（`tb371fc`）。这些是本轮引用的快照，后续代码进展仍由各自分支与新证据记录。

主线 Linux 适合作为这台平板的长期通用系统方向；本仓库继续推进既定的路线 A：离线 arm64e → 普通 arm64 转换、CPU 原生执行，先 iPadOS 27，再独立验证 macOS 27。三条工程线共享板级事实和测试输入，各自完成操作系统接口与运行验收。厂商源码的来源核验、Linux 驱动补齐与 XNU 板级集成可以并行。

本轮变更只补充工程文档，没有重建内核、启动 27 或改变历史硬件验收状态。

后续取得的本机 DTB/DTBO 索引、内存保留区和 Linux Novatek 修复证据见
[原生入口资料接续](native-entry-evidence-20261124.md)。新增资料为平台与驱动适配提供
具体输入，未提升本仓库的 XNU、iPadOS 27 或 macOS 27 运行状态。

## 1. 已有结果与下一步的准确起点

| 层次 | 本次核对到的证据 | 对后续工作的含义 |
| --- | --- | --- |
| 当前分支 | `main` 的 [Source integrity 运行 45229207625](https://github.com/cyjin-yl/UniXNU-tb371fc/actions/runs/45229207625) 已成功 | 仓库检查、回归及源码准备结果；CI 的源码准备作业不执行完整 XNU 构建 |
| 通用 XNU 候选 | [第二轮构建](ROUTE_A_GENERIC_KERNEL_RESULT.md) 实际编译／链接成功，1,086 个对象、21,905,888 字节，SHA-256 `a58cdeedb9b7a4c152867c3487f28658a3799b0158f5046bbad6d2d58e741469` | 可以在固定源码、工具链和普通 ARM64 ABI 上补 TB371FC profile；完整 provider/archive 闭包、ISA 和板级启动资格仍待完成 |
| Android 上的 CPU 测试 | [合成原生测试](evidence/route-a-native-20261123.json) 23/23 组、46 次独立执行；`AT_HWCAP=0x119fff`，`paca=false`、`pacg=false` | 证明对应普通 AArch64 合成函数的行为；未执行原始 PAuth 指令，也未运行 Apple 程序或 Darwin ABI |
| 设备驱动源码 | `drivers/`、`package/` 已有 Adreno、SMMU、显示、Novatek/GENI 输入、按键、UFS 门禁等来源固定的实现 | 保留和逐项集成这些资产；仍需面向 27 的结构布局、调用接口、生命周期与实机验证 |
| iPadOS 17 / V135 | [历史记录](STATUS.md) 有上游桌面、触摸、GPU 和存储结果，也记载电池、音量键等不足 | 作为硬件线索及回归参考；不填入本轮 27 验收栏 |
| macOS 27 | [目标配置](../configs/route-a-targets.json) 固定为 `macos-27.3-26C5035r`，`target_kernel_abi=not-yet-qualified`、`boot_verified=false` | 已有目标描述，尚无本项目 macOS 用户空间运行结果 |
| QEMU | 已发布的 [`69ca28d`](https://github.com/cyjin-yl/qemu-tb371fc/commit/69ca28dec6add998d252fa6436dfcc9b9cab6e36) 有 SMMUv2 页粒度／迁移等组件证据 | 提供可重复的设备模型验证；模型能力、完整板启动、物理设备行为分别验收，后续开发以该仓库最新报告为准 |

源码中存在一个驱动目录、通用内核完成链接、系统进入桌面，是三种不同进度。[ROADMAP](../ROADMAP.md) 的整机验收仍要求显示模式、触控笔、键盘、网络、音频、相机、USB、存储、充电、温控及休眠恢复达到可稳定使用的状态。

### 本机 Android 只读基线

同日取得的[本机摘要](https://github.com/cyjin-yl/TB371FC-6.12/blob/docs/mainline-strategy-20261124/docs/evidence/2026-11-24-live-android-baseline.json) 绑定 `TB371FC / spinel`、Android 14、`ZUI_16.0.474_ST_241129`、`4.19.157-perf+`，没有采集原始输入事件或刷写设备。这些是后续驱动定位的具体起点：

| 本次观察 | 对驱动工作的约束 |
| --- | --- |
| `spi0.0` 绑定 `NVT-ts`，compatible 为 `novatek,NVT-ts-spi`；输入有 `NVTCapacitiveTouchScreen` 与 `NVTCapacitivePen` | 核对现有 Novatek/GENI 实现与此设备固件；枚举成功不证明笔压、倾角或 XNU HID 正确 |
| Precision Pen 3 的 Mouse/Consumer Control 为总线 `0005`、`17ef:612b`；键盘配件为总线 `0018`、`17ef:6175`，有键盘、触控板和 Consumer Control | 笔的蓝牙附加事件、屏幕笔输入与 I2C 键盘分别适配，不能把所有输入归到一个触摸驱动 |
| 四个 I2C 地址 `6-0034` 至 `6-0037` 实际绑定 `tfa98xx` | 音频功放以实际绑定为优先线索；DT 中的 WSA881x 节点不能自动当作实际扬声器芯片，具体 TFA 型号和校准仍需确认 |
| `2-0011` / `4-0011` 分别绑定 `ktz8866a` / `ktz8866b`，`1-0055` 绑定 `mm8013` | 双背光与电量计进入板级清单；读到绑定不证明亮度范围、电量算法或休眠恢复 |
| QCA6390 节点有 `cnss2` / `bt_power`，FSA4480 节点绑定 `fsa4480-driver` | 对照本机无线与 Type-C 音频开关路径；FSA4480 节点本身不证明完整 PD 控制器或全部 USB-C 能力 |
| CPU 特征导出未列 `paca`、`pacg`、`bti`；厂商 DT 顶层仍叫 `kona QRD` | 以实际产品属性锁定 TB371FC，不能把通用 DT 名称当成另一块板；CPU 导出视图按第 4 节限定解释 |

这些观察仍属于 Android 环境，未提升 Linux 或 XNU 的功能验收状态。

## 2. 共用什么、各自实现什么

Linux 的现有 SoC 支持、设备树和驱动是可核对的硬件参考；XNU 有不同的设备匹配、内存、DMA、同步、电源管理和 IOKit 接口。Linux 驱动不能作为一个二进制或简单改名模块直接装进 XNU。Apple 自身的 [XNU README](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/README.md) 也明确其内核与 IOKit 驱动框架的构成。

优先产出下列共用资料，再决定哪一层需要编写代码。寄存器常量和协议事实、可复用源代码与二进制固件分别记录来源；复用源文件时保留其逐文件许可与版权，不能因为外层项目使用 BSD 就把 Linux 或第三方代码改标为 BSD。

| 共用资料 | Linux 工程 | QEMU 工程 | 本仓库 / XNU 工程 |
| --- | --- | --- | --- |
| 板卡身份、DT/DTBO、MMIO 区间、IRQ 编号与类型 | 设备树、binding、驱动匹配和资源申请 | 机器资源映射、中断连线、复位值 | 平台描述、IOService 匹配、MMIO 和中断适配 |
| 时钟、reset、regulator、GDSC、互连与电源时序 | 复用现有框架，补实际板级连接和差异 | 只模拟有证据的状态机，记录未实现副作用 | 原生 provider、引用计数、启动／停止及休眠恢复 |
| SMMU stream ID、页粒度、地址宽度、缓存一致性 | IOMMU 与 DMA 映射／故障测试 | 页表遍历、权限、故障、中断及迁移测试 | IOMemoryDescriptor、映射生命周期、错误传播与 DMA 同步 |
| 固件名称、摘要、版本、加载顺序和消息协议 | 固件加载及 remoteproc／传输驱动 | 受限协议模型与可重复超时、复位路径 | 原生传输、固件握手、恢复和操作系统服务接口 |
| 面板时序、DCS 命令、背光、触摸／笔报文、配件 ID | DRM/KMS、输入、HID 与板级配置 | 可解释的 MMIO/IRQ/输入序列模型 | 显示 provider、HID 事件、图形与输入生命周期 |
| 故障序列、边界条件和预期事件 | 驱动回归与真实设备跟踪 | 确定性的负向向量和模型回归 | 内核／服务级测试以及匹配的硬件回读 |

硬件事实应绑定“设备型号／板卡修订 + 原厂 build + 内核／DT 摘要 + 来源”。同一 SM8250 家族其他产品的 GPIO、触控芯片、USB-C 控制器、面板与电源连接，只能先作为候选。发现冲突时保留两个来源和适用范围，再以本机证据裁定。

### 每项记录的最低内容

1. 来源定位：固定仓库 commit 与文件、公开硬件文档，或去标识的本机观察摘要；区分 `source-described`、`android-observed`、`model-tested`、`linux-tested`、`xnu-tested`。
2. 身份绑定：板卡、OS build、采集方法、输入及产物摘要、日期；不公开序列号、MAC 地址、账号、分区个人数据或原始私有日志。
3. 行为合同：输入、依赖、寄存器／消息含义、成功事件、超时／错误、复位与停止顺序。读到一个寄存器值只证明该次读值，不能自动推导可写位或所有状态转换。
4. 消费者：Linux binding/driver、QEMU model/test、本仓库 provider/driver 的对应路径，各自补丁与验证记录。
5. 还缺的证据：硬件实测、并发、热插拔、恢复和性能分别列出；未知项保持未知，不填默认“通过”。

共用测试输入可以包含合成 MMIO 序列、消息格式和自建的触摸报文；真实固件与 Apple 系统文件继续保存在仓库外。公开清单保存摘要、所需版本、取得方式与使用范围。

## 3. 当前 XNU 驱动资产如何接到新工作上

下表中的“已有”是本次固定提交可读到的源码。27 的硬件运行仍全部按 [整机矩阵](../ROADMAP.md#整机硬件验收矩阵) 另行验收。

| 子系统 | 本仓库已有入口 | 接收主线 Linux / 实机资料后要完成的 XNU 工作 | 下一份有效证据 |
| --- | --- | --- | --- |
| CPU / 中断 / 时钟 | 通用 ARM64 候选；历史 CPU 记录 | TB371FC 平台入口、所有启用 CPU 的能力交集、timer/IPI、GIC、内存保留区和时钟电源依赖 | 新候选的串口／panic 入口、逐核 timer/IPI、内存压力与实际异常日志 |
| SMMU / DMA | `drivers/ArmSmmu4K/`、`drivers/Adreno650/NativeAdrenoSmmu*` | 对实际 stream/context、cache/TLB、页尺寸和所有权建模；接到 XNU VM 生命周期 | 页表边界、权限故障、映射撤销、reset 后 DMA 与真实设备回读 |
| GPU | `drivers/Adreno650/`、`AdrenoFirmware/`、`AdrenoPM4/`、`AdrenoMetal/` | GMU/固件/电源／同步与 27 IOGPU、IOSurface、Metal 接口；核对已有 Turnip/桥接代码来源和 ABI | 真正提交／完成及显示正确性；固定场景帧时间、温度和持续负载 |
| 显示 / 背光 | `package/Tb371fcDisplay/` | 对本机面板、显示模式、亮度与灭屏恢复建立完整生命周期；帧缓冲接管后逐步接完整图形 | 分辨率、目标刷新率、亮度、重复灭屏／亮屏及渲染同步 |
| 触摸 / 触控笔 | `package/NovatekProtocol/`、`QcomGeniSpi/`、`Tb371fcTouch/`、`ShengHidInput/` | 核对本机触控硬件／固件和笔协议，补 HID 描述与启动、停止、恢复；历史触摸不代表笔压／倾角已实现 | 多点坐标、笔功能、丢包、延迟、休眠恢复，分别记录 |
| 键盘 / 按键 | `package/Tb371fcButtons/`、`Tb371fcInput/` | 核对 PMIC 按键和实际键盘配件总线、ID、报文、供电与连接顺序 | 音量／电源、全键位、热插拔、重复连接和恢复 |
| UFS / 文件系统 | `package/UfsProducerGate/`、`RootLog/` 与 UFS 来源锁 | 迁入完整原生 UFS provider，匹配 DMA、中断、异常恢复；分别核验目标 APFS/root/Data 依赖 | 校验读写、持久回读、重启恢复、负载和错误注入结果 |
| Wi-Fi / 蓝牙 | 历史 `porting.toml` 为 planned | 先锁定真实芯片、总线、固件与校准需求，再确定 native transport 与 27 网络接口 | 扫描、连接、持续收发、配对、掉线恢复及待机恢复 |
| 音频 / 摄像头 / 传感器 | 27 没有已验收路径 | DSP/codec、sensor、时钟电源、传输格式与对应系统服务；优先从可独立验证的最小路径推进 | 各实际输入／输出路线、格式、启停、权限与恢复 |
| USB / Type-C / PD | 历史恢复入口与目标 profile 作为参考 | 分别处理主机／设备角色、PHY、mux、充电协商和 OS 服务；按本机硬件锁定控制器 | 两种角色、热插拔、速度、充电状态与异常恢复 |
| 电池 / 温控 / 休眠 | `package/PlatformPower/`、`NativeBatteryBoard.h` | 核对充电与电量计、热区、调频和电源状态；熄屏与系统休眠分别实现 | 电量／温度与 Android 参考对照、负载节流、重复休眠及待机功耗 |

## 4. CPU 原生执行的资格

路线 A 保留 CPU 原生执行目标。它的成本包括离线转换、普通指针约定和后续图形适配；不能在尚无运行数据时承诺零性能开销或原生 macOS 的安全特性完全保留。

[当前原生报告](evidence/route-a-native-20261123.json) 没有暴露 PAC HWCAP。Linux 的 [HWCAP 规范](https://docs.kernel.org/arch/arm64/elf_hwcaps.html) 描述的是内核向用户空间保证可用的功能；[CPU feature register ABI](https://docs.kernel.org/arch/arm64/cpu-feature-registers.html) 还会按所有 CPU 的安全交集和内核支持过滤字段。因此，Android 4.19 的 HWCAP 或 `/proc/cpuinfo` 缺少一个标志，不是对全部硬件寄存器的完整审计。

后续能力记录应同时固定用户态 HWCAP、受支持的 ID register 读取方式／返回值、CPU 集合、内核配置与实际生成代码。异构 CPU 的调度不能仅按其中一个大核的能力编译。不得以“执行一次没有 SIGILL”证明任意特性存在；不支持的功能也不保证以同一种异常失败。

Apple 的 [arm64e 文档](https://developer.apple.com/documentation/security/preparing-your-app-to-work-with-pointer-authentication) 将其指针认证语义与普通 arm64 区分。本项目的 plain-pointer ABI 明确不保留 PAC 认证；所有指针生产者、dyld fixups、pager、内核和相互调用的组件必须采用相同约定。真实 `dyld` 的 236 条 FEAT_S1POE2 指令、全部 cache/kext/archive 的 ISA 和早期能力发布仍需要逐项审计，不能从 23 组函数测试或通用 kernel 编译结果推导整体兼容。

QEMU 的 CPU／SMMU 可配置能力只说明模型；其 16／64 KiB 支持也不能代替物理 SMMU 的页粒度核验。CPU translation granule、XNU VM page、CodeDirectory hash page、dyld slide page 和设备 IOMMU granule 分项记录，避免以一个“4K/16K”标签替代所有层。

## 5. macOS 27 是独立适配目标

Apple 的 [macOS 27 兼容列表](https://support.apple.com/en-us/127255) 只给出受支持的 Mac。TB371FC 的路径是本项目的实验移植，需要独立证明以下条件；iPadOS 27 的任何后续通过结果只能成为复用证据。

本仓库目标配置与固定的 [UniXNU macOS profile](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/os/macos-27.3-26C5035r/profile.toml) 指向 `27.3 / 26C5035r / Mac17,11`。这是版本化输入声明，本次文档核对没有下载或验证该完整 IPSW。现有 XNU 基线仍为 Apple 发布的 `xnu-12377.121.6`，tag 对应 `ac9718fb1af618d5ce8678d0dc6e8a58f252216f`；固定 profile 用 Darwin 26 接口补丁作适配。它不能被写成“已取得完整 macOS 27 原生内核源码”。

| 门槛 | 必须提交的证据 | 当前范围 |
| --- | --- | --- |
| macOS 输入身份 | 官方输入地址、BuildManifest 的版本／build／product，实际 kernelcache、全部主／子 cache、root/SystemOS/App 与 trust 输入摘要 | 目标配置已有；本仓库没有 macOS 完整输入验收 |
| 普通 ARM64 执行 | 对 macOS 自己的指令与指针格式、全部加载对象、ISA 和签名页作审计；loader/pager/ABI 完整闭合 | 复用路线 A 工具与算法；尚无 macOS 全包通过 |
| 内核和驱动 ABI | `target=macosx`、Darwin syscall/KPI、kext metaclass/vtable/exports、完整 provider 与启动依赖闭包 | 固定上游 profile 有适配设计；TB371FC 普通 ARM64 目标未验收 |
| 地址空间与根卷 | 独立验证 macOS user VA、所选 shared-region 大小、APFS、Data、firmlinks、cryptex 和根目录服务 | 现有[内核缺口文档](ROUTE_A_KERNEL_GAPS.md) 已记录具体上游差异；不得沿用 iPadOS 参数后默认通过 |
| 进程与系统服务 | 在目标 XNU 上运行受控普通 ARM64 程序，再验证 dyld、launchd、服务稳定性与可诊断的错误路径 | 未运行 |
| 桌面与图形 | WindowServer、登录、显示、HID、IOSurface/IOGPU/Metal、实际应用 | 未运行；Linux DRM/Mesa 成功也不会自动满足这些接口 |
| 整机与性能 | 独立 macOS 的硬件矩阵、稳定性、性能、温控及待机功耗 | 未验收 |

开放源码 XNU 只覆盖系统的一部分。图形和系统服务、目标 ABI 输入、固件与其他 provider 需要分别列出来源和可用性。仓库已有的 [许可证及构建输入边界](ROUTE_A_KERNEL_GAPS.md#5-实质依赖与阻断项) 继续适用，不把外层仓库许可扩展到 Apple 系统二进制或受限 provider。

## 6. 跨仓库推进顺序

1. TB371FC-6.12 的[主线策略](https://github.com/cyjin-yl/TB371FC-6.12/blob/docs/mainline-strategy-20261124/docs/MAINLINE_STRATEGY.md)和[驱动路线图](https://github.com/cyjin-yl/TB371FC-6.12/blob/docs/mainline-strategy-20261124/docs/DRIVER_ROADMAP.md)维护板级清单、主线／下游差异、固件需求和 Linux 实机验收；先确认已有可复用驱动，再补设备树、板级差异或缺失驱动。
2. qemu-tb371fc 的[跨项目硬件合同](https://github.com/cyjin-yl/qemu-tb371fc/blob/docs/mainline-hardware-contract-20261124/tb371fc/docs/cross-project-hardware-contract.md)对共享硬件事实建立可解释的模型与回归，分别记录完整原厂 DT、精简 DT、guest 镜像和启用设备。模型测试不会提升本仓库的物理验收状态。
3. 本仓库将相同硬件事实映射到 XNU provider／驱动，先接齐 TB371FC 板级与加载闭包，再推进普通 ARM64 进程、iPadOS 27 和 macOS 27 各自的系统服务。
4. 每个成功案例写回原有仓库的证据索引，并用固定提交互相引用；保存负向、超时和恢复结果。多个任务同时推进时使用独立分支与新增证据文件，发布前重新读取目标 head。

优先补齐 Linux 对这台设备的长期支持，并不要求暂停已有路线 A 或重写已成立的通用驱动。每条线下一次实现都应对应矩阵中的一个具体缺口及其可重复验收。

上述跨仓库文档链接指向本轮独立文档分支，避免覆盖各项目正在推进的实现分支；合并后可按对应提交更新永久链接。
