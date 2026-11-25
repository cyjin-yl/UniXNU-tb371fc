# 路线图与验收

更新：2026-11-26。目标是 **TB371FC 上可稳定使用、硬件功能完整的 iPadOS 27 原生执行方案**；macOS 27 作为后续独立目标。CPU 采用路线 A 的离线转换与普通 arm64 指针约定。本文记录任务和验收条件，已取得的证据见 [索引](docs/evidence/README.md)。

主线 Linux 的长期设备支持与本路线并行推进；板级描述、固件协议和边界测试在 [跨仓库硬件资料](docs/CROSS_PROJECT_HARDWARE.md) 中约定复用方式。Linux 驱动、QEMU 模型和 XNU provider 各自适配接口并完成运行验收；本轮文档整理不更改下表完成状态。

## 已有基础

- [x] 固定输入版本、来源、工具与依赖记录。
- [x] PAuth 等长转换、严格 Mach-O / CFG / 签名代码页检查。
- [x] TB371FC 原生合成函数 23/23 组、46 次独立执行。
- [x] 真实 27.0.1 `launchd`、`dyld` 离线改写和独立代码页复核。
- [x] 原始 trust cache 条目属性提取；新 cdhash 条目信息准备。
- [x] v3/v5/分块 v5 与 dyld pager 普通指针补丁、错误返回修正及局部 C 验证。
- [x] 共享缓存完整 proof 门禁实现与合成回归检查。
- [x] 普通 arm64 / XNU 12377 通用源码准备：71 项补丁、源码摘要和配置编译探针通过。
- [x] 首次构建的公开输入 staging：7 份固定源码，保留 21 个已适配 header，补齐 5 个缺失 header。
- [x] 主机组件构建及自写样本：普通 ARM64 静态链接、MIGCOM 生成、LZFSE 往返通过。
- [x] 定制 Clang 固定版本编译与 19 个类型语义断言通过，最终组合工具链完成。
- [x] 首轮真实 XNU builder 执行，保留 716 个目标文件与首个 PAuth 编译错误。
- [x] 第二轮通用候选编译／链接成功：1,086 个对象、1,067 行 link filelist、普通 ARM64 `MH_EXECUTE` 候选。
- [x] 候选有限编码核对和未定义符号检查完成；完整 ISA 与实机资格仍未完成。
- [x] 固定 `ArmDTPlatform`、`ArmCpu` 实际编译和真实 `cpu.c` callback 接线对象独立链接；完整 provider 闭包另验。
- [x] 同一真实平台候选通过固定 DarwinBoot parser／段复制、102,103 条 local pointer 全表及 boot_args ABI 的主机合同检查；设备 entry 未执行。
- [x] 固定平台候选在独立标准 QEMU 中完成真实入口单步，并捕获高虚拟地址的首个异常；TB371FC 实机与 OS boot 另验。
- [x] 同一 QEMU 启动输入下取得完整有限 debugger 入口快照，实际 caller 与参数指向 preemption timeout panic；计时行为另验。
- [ ] 真实 27 完整共享缓存转换。
- [ ] 完整 TB371FC profile、provider/archive 依赖的 XNU 构建和设备启动。
- [ ] 27 的 Darwin 进程、桌面及整机硬件验收。

“门禁实现”与“真实完整输入通过门禁”分别计数；已完成单文件转换不能替代整包验证。

## 当前并行工作

| ID | 任务 | 当前证据 | 本阶段完成条件 |
| --- | --- | --- | --- |
| A01 | `dyld` 非 TPRO 启动约定 | 4 个实际局部分支匹配，2 个条件区域闭合、2 个保持不完整；内核能力发布源码已核对 | 追踪 apple 向量键来源、早启动与相关寄存器路径；全部 236 处仍需逐项闭合 |
| A02 | 普通 arm64、XNU 12377 构建 | 通用候选与新增两份平台 provider／真实 callback 的独立链接完成；有限编码核对、真实候选 host loader／local pointers／boot_args 合同通过 | 完成 TB371FC profile、完整 provider/archive 依赖、完整 ISA 与设备加载／启动链 |
| A03 | 真实完整 27 shared cache | 严格 proof 与改写器已有实现，完整输入未验证 | 提取完整主／子缓存集合，锁定来源与 UUID，完整覆盖、改写及签名页检查通过 |
| A04 | 加载与普通指针 ABI 闭合 | 用户文件新信任条目信息准备；尚未安装 | dyld fixups、共享区、pager、信任目录和所有指针生产者采用一致约定 |

A01 的可重复入口见 [TPRO 审计](docs/ROUTE_A_TPRO.md) 与 [内核能力发布核对](docs/ROUTE_A_TPRO_KERNEL_PUBLICATION.md)；A02 依次使用 [内核准备](docs/ROUTE_A_KERNEL_BUILD.md)、[工具链](docs/ROUTE_A_TOOLCHAIN.md) 和 [首次 builder](docs/ROUTE_A_FIRST_KERNEL_BUILD.md)。每一步是否实际通过，以对应输入报告为准。

A02 的[第二轮结果](docs/ROUTE_A_GENERIC_KERNEL_RESULT.md)保存 21,905,888 bytes（20.89 MiB）的普通 ARM64、subtype 0 候选。独立检查覆盖 3 个指令区间的 2,220,163 个候选 4 字节字：分类器识别的非 HINT PAuth 为 0、精确 POE2 TCHANGE 为 0，记录 180 个 `XPACLRI` HINT。该计数不证明可达性或全部 ISA；原始首次失败的 716 个对象和日志保持留存。

随后[平台候选](docs/ROUTE_A_PLATFORM_RESULT.md)已加入实际 `ArmDTPlatform`、`ArmCpu` 与真实 `cpu.c` callback，候选 SHA 为 `46eff436250d905e9f3aec59dbcc8c04d594e614e790860236917c7cbfe39f1b`。该候选的 [DarwinBoot 合同](docs/ROUTE_A_LOADER_CONTRACT.md)已在第三次真实执行中通过：生产 parser 和复制代码处理 10 段，23,035,904 字节映像一致，102,103 条 local pointer 全表、入口 trampoline 和 boot_args 布局完成核验；前两次失败及原 driver 可精确恢复。UEFI 分配、板级 ADT、MMU 交接、设备 entry 及 OS boot 保持独立门槛。

2026-11-26 的[独立 QEMU 诊断](docs/ROUTE_A_QEMU_ENTRY.md)已实际观察 `__start` → `_start_first_cpu`，随后在 `0xfffffff0072f5fe4` 捕获 Undefined Instruction。run004 复用同一 ADT／boot buffer／trampoline，停在 debugger 函数入口，取得完整有限寄存器与参数快照；实际 `BL` caller 及文本指向 preemption timeout panic，计数差值对应 1.984688 ms。下一步独立核对计时阈值和时钟行为；这些合成 ADT／标准 `virt` 结果不填写设备 M3 或整机硬件验收状态。

A01 不能通过“把 `dyld_hw_tpro` 设为 0”关闭硬件路径，已有二进制检查只看键是否存在。还需分别核对 DATA_CONST pager 的 TPRO 策略和早期能力发布。不得用批量 NOP 掩盖未证明的指令路径。

fileset 修复轮次的 [CI](https://github.com/cyjin-yl/UniXNU-tb371fc/actions/runs/45221437252) 已完成 **210 项回归（0 跳过）**、通用源码准备和包含 fileset 修复的公开输入 staging。原 71 项 inventory 与 headers 后清单仍匹配历史摘要，修复后最终源码清单为 `9a2f18aa42773260f52adeeeff20a5f0257fc4360858aa90a3871714f7b84008`。`zzz-boot-progress.patch` 的 PMGR／watchdog 前置依赖待 TB371FC 板级接入，报告明确 `full_upstream_profile_applied=false`；它需要在后续实际板级配置中恢复验证。

A02 不能直接选择针对旧 XNU 的 arm64 profile，也不能把 V135 的保留内核替换几条指令当作 27 内核。当前目标基于固定 XNU 12377.121.6 加 Darwin 26 兼容工作；目标用户空间版本不等于内核源码已经升级成完整 Darwin 26。细项见 [内核缺口](docs/ROUTE_A_KERNEL_GAPS.md)。

TB371FC 的 QEMU 板级模型在 [qemu-tb371fc](https://github.com/cyjin-yl/qemu-tb371fc) 并行推进，作为可重复验证中断、地址转换、DMA 与设备状态的环境。SMMU 迁移修复及 Linux 验证保存在该仓库的独立提交和 CI；QEMU 组件结果不填入下方实机 27 硬件验收表。

SMMU 16／64 KiB granule 与迁移兼容工作已通过[最终 CI](https://github.com/cyjin-yl/qemu-tb371fc/actions/runs/45224664341)，并由 [PR #2](https://github.com/cyjin-yl/qemu-tb371fc/pull/2) 合并到 `69ca28d`。这项模型进展不改变以下 27 实机验收状态。

## 集成里程碑

| 阶段 | 进入条件 | 验收证据 |
| --- | --- | --- |
| M1：可审计的离线用户空间 | A01、A03 的输入与范围完整 | 全部文件／缓存来源、改写报告、剩余 ISA 清单与运行路径约定 |
| M2：可重现的内核与加载链 | A02、A04 具备匹配配置 | 干净构建日志、工具和源码版本、内核及配套产物哈希；构建与启动状态分开 |
| M3：内核和首批进程 | 设备启动与恢复方案已具体落实 | TB371FC 上的内核、存储、根卷、`launchd`、`dyld` 日志；能定位首个失败点 |
| M4：图形与输入 | 系统服务能稳定启动 | 图形服务、桌面、Adreno 650 提交／完成、显示和触摸证据 |
| M5：硬件完整与性能 | M4 可稳定复现 | 以下硬件矩阵全部验收；记录稳定性、性能和电源管理 |
| M6：macOS 27 独立适配 | 可复用的构建、加载与驱动基础 | macOS 自己的输入、ABI、服务、UI 和硬件证据 |

阶段可交叉推进；每项完成以证据为准。**M4 进入桌面只算中间里程碑。** M2 已有通用候选编译／链接记录，但完整 TB371FC profile、archives、ISA 和加载链尚未验收；M3—M6 仍无 27 运行结果。

## 整机硬件验收矩阵

下表全部针对 **27 路线**。旧 iPadOS 17 / V135 的状态保留在历史文档，不能直接填入本表。

| 子系统 | 当前 27 状态 | 验收内容 |
| --- | --- | --- |
| CPU / 内存 / 中断 | 未启动系统 | 多核调度、计时、IPI、内存压力与长时间负载 |
| GPU / Metal | 未验证 | 提交与完成、同步、图形正确性、持续负载、帧时间 |
| 显示 / 刷新率 | 未验证 | 正确分辨率、所有目标显示模式、刷新率、亮度、灭屏／亮屏 |
| 触摸 / 触控笔 | 未验证 | 多点触摸、坐标、笔压／倾角等设备具备的功能、延迟 |
| 键盘 / 按键 | 未验证 | 外接键盘、目标配件、音量／电源键、输入生命周期 |
| Wi-Fi / 蓝牙 | 未验证 | 连接、数据传输、外设配对、重连与休眠恢复 |
| 音频 | 未验证 | 扬声器、麦克风、耳机／USB 音频、路由和休眠恢复 |
| 相机 | 未验证 | 各相机预览、采集、格式、权限与生命周期 |
| USB | 未验证 | 主机／设备模式、数据传输和热插拔 |
| UFS / 文件系统 | 未验证 | 数据持久性、校验、负载、重启及异常恢复 |
| 传感器 / 其他板载功能 | 未验证 | 按实机硬件清单核验旋转、自动亮度等已有功能及其休眠恢复 |
| 电池 / 充电 / 温控 | 未验证 | 电量、充电状态、充电控制、温度、持续负载与节流 |
| 休眠 / 唤醒 | 未验证 | 多次循环、待机功耗、唤醒后的全部外设与网络恢复 |

性能测量记录输入场景、显示模式、温度、电源状态、软件版本、帧时间分布与 CPU／内存占用。原生函数正确性测试不提供“整机损耗百分比”；目前没有应用、GPU 或功耗基准。

## 更新规则

任务完成时链接具体提交和证据，并保留先前记录。对尚未执行的测试使用“未验证”，失败附可重跑命令与最小诊断，缺少条件说明实际缺口。不要根据代码存在、编译成功、镜像生成或刷写 ACK 推断下一阶段已经通过。
