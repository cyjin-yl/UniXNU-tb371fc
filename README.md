# UniXNU-tb371fc

联想小新 Pad Pro 12.7（2023，**TB371FC / Snapdragon 870 / Adreno 650**）的 UniXNU 设备适配与 27 代系统原生执行实验。

开发仓库：[cyjin-yl/UniXNU-tb371fc](https://github.com/cyjin-yl/UniXNU-tb371fc)。`main` 保存已合并的开发成果；`route-a/arm64e-27` 用于路线 A 集成。设备移植原始来源为 [xiuyityer/UniXNU-tb371fc](https://github.com/xiuyityer/UniXNU-tb371fc)，来源和许可证持续保留。

## 当前目标与进度

采用 **离线 arm64e → 普通 arm64 转换、CPU 原生执行**的路线 A，先推进 **iPadOS 27.0.1 / 24A446**，再验证 macOS 27。转换采用普通指针 ABI，不保留 PAC 认证；加载器、内核 pager 和指针生产者必须遵守同一约定。

**当前没有启动 iPadOS 27 或 macOS 27。** 已取得的结果如下；完整证据与适用范围见 [证据索引](docs/evidence/README.md)。

| 已完成工作 | 可核验结果 | 证明范围 |
| --- | --- | --- |
| 平板原生正确性测试 | TB371FC 上 23/23 组，46 次独立函数执行 | Android 环境的合成 AArch64 函数 |
| 真实 27.0.1 `launchd` 改写 | 2,409 处；150 个签名代码页通过独立校验 | 离线单文件暂存产物 |
| 真实 27.0.1 `dyld` 改写 | 5,385 处；347 个签名代码页通过独立校验 | 仍保留 236 条 FEAT_S1POE2 指令；非 TPRO 路径待完整验证 |
| 普通 arm64 / XNU 12377 源码准备 | **71 项所选补丁**应用成功，6,119 个源码条目有摘要；配置探针编译通过 | 通用源码子集，1 项板级进度／看门狗补丁明确延后；完整 TB371FC profile 尚未接入 |
| 首次内核构建输入 | 7 份固定公开源码；21 个已适配 header 保留，补齐 5 个 TrustCache header | CI 与开发容器的 staged source 摘要一致；[实际报告](docs/evidence/route-a-kernel-staging-20261123.json) |
| 定制 Clang 与组合工具链 | 固定 Clang 24 构建完成，**19 个类型语义断言通过**；host-tools finalization 完成 | [实际报告](docs/evidence/route-a-toolchain-success-20261124.json)；完整指令集资格单独验证 |
| 实际生产 compiler wrapper | **3 次真实编译、7 项返回地址检查通过**；CPU 配置由真实构建环境提供 | [实际报告](docs/evidence/route-a-production-shim-20261124.json)；样本不含要求 PAuth 的指令，完整内核 ISA 待审计 |
| 第二轮通用内核编译／链接 | **成功**；1,086 个 `.o` / `.cpo`，link filelist 有 1,067 个非空行；生成普通 ARM64 `MH_EXECUTE`、subtype 0 候选 | [实际结果](docs/ROUTE_A_GENERIC_KERNEL_RESULT.md)；21,905,888 bytes（20.89 MiB），0 编译 error、0 未定义符号；完整板级和启动资格未完成 |
| 候选的有限编码核对 | 扫描 3 个区域、2,220,163 个候选 4 字节字；分类器识别的非 HINT PAuth 为 0，精确 POE2 TCHANGE 为 0；180 个 `XPACLRI` HINT | [独立记录](docs/evidence/route-a-kernel-candidate-audit-20261124.json)；不证明可达性，也不覆盖全部 ISA 或外部 archives |
| 平台组件与真实 kernel callback | 固定 `ArmDTPlatform`、`ArmCpu` 实际编译，真实 `cpu.c` callback 接线对象完成独立链接；21,942,456 字节新候选，强／弱未定义均为 0 | [平台结果](docs/ROUTE_A_PLATFORM_RESULT.md)；完整 provider 闭包、运行时匹配与设备 entry 继续单独验收 |
| 真实候选的 DarwinBoot 主机装载 | 原 C parser／复制代码通过；10 段、23,035,904 字节映像逐字节一致；102,103 条 local pointer 记录全部核验，`boot_args` ABI 一致 | [实际结果与前两次失败](docs/ROUTE_A_LOADER_CONTRACT.md)；固定虚拟地址合同，未执行 UEFI 分配、MMU 交接或设备内核入口 |
| 独立 QEMU 入口、快照与计时诊断 | 实际入口单步、run004 完整有限 panic 快照；相同 guest 输入的 run005 首异常为 Data Abort，快照因原窗口与长度限制保留 `partial`／失败 | [五次实际尝试](docs/ROUTE_A_QEMU_ENTRY.md)；标准 `virt`／Cortex-A76、合成 ADT；新故障依赖、完整 MMU／slide、TB371FC 实机和 OS boot 继续独立验收 |
| 首轮编译失败保留 | 716 个目标文件后因 fileset panic 的无条件 PAuth builtin 退出；旧目录和日志保留 | [历史失败证据](docs/evidence/route-a-first-kernel-failure-20261124.json)；第二轮已越过该阻塞 |
| 主机工具实际验收 | 普通 ARM64 样本链接、MIG 接口生成、LZFSE 往返 **3/3 组通过** | 自写样本；完整 XNU、SDK 和定制 Clang 资格单独验证 |
| 真实 dyld 局部 TPRO 路径 | 4 个分支均匹配；2 个条件区域闭合，2 个仍有调用／异常／间接转移缺口 | 固定原始 dyld；全部 236 处与早期运行时路径仍未证明 |
| 普通指针 pager 补丁 | v3/v5/分块 v5、dyld pager 和错误返回传播 | 固定源码应用／反向恢复；提取 C 函数验证 |
| fileset 修复轮次的主机回归 | **210 项通过，0 跳过**，包含 9 项提取真实 pager C 的测试 | 该轮 fileset、构建修复与 CPU 约定检查；[历史 CI](https://github.com/cyjin-yl/UniXNU-tb371fc/actions/runs/45221437252)，后续新增检查以对应报告为准 |
| 独立汇编器复核 | 54/54 原始编码，45/45 替换编码 | 编码与基础 `armv8-a` 输出核对 |

普通 arm64 通用候选已经完成源码编译与链接。TB371FC 板级 profile、完整 provider/archive 依赖、全部 ISA、27 共享缓存和 Darwin 进程启动仍在集成。macOS 27 当前只有目标配置记录，没有对应用户空间实测。最终验收包括 GPU、显示与刷新率、触控笔、键盘、网络、音频、相机、USB、存储、充电与休眠唤醒；进入桌面是中间里程碑。

## 继续开发的入口

| 入口 | 内容 |
| --- | --- |
| [开发指南](DEVELOPMENT.md) | 克隆、依赖、包含真实 pager C 的完整检查、输入输出约定 |
| [路线图与验收表](ROADMAP.md) | 进行中的任务、依赖、完成条件和整机硬件矩阵 |
| [Linux / QEMU / XNU 共用硬件资料](docs/CROSS_PROJECT_HARDWARE.md) | 板级事实复用、原生 CPU 资格与 macOS 27 独立验收 |
| [路线 A 实现](docs/ROUTE_A.md) | 转换规则、严格检查、真实 27 输入结果和使用方法 |
| [证据索引](docs/evidence/README.md) | 来源、测试报告、未证明范围与 CI |
| [普通指针内核补丁](docs/ROUTE_A_PLAIN_AUTH_PATCH.md) | 固定 XNU 基线、补丁与提取 C 测试 |
| [内核与加载器缺口](docs/ROUTE_A_KERNEL_GAPS.md) | XNU、27 ABI、页大小、信任目录与驱动集成 |
| [TPRO 审计入口](docs/ROUTE_A_TPRO.md) | 固定真实 dyld 来源的指令清单、静态引用与两类启动能力键检查 |
| [普通 arm64 内核准备](docs/ROUTE_A_KERNEL_BUILD.md) | XNU 12377 补丁顺序、干净源码树与编译器配置探针 |
| [定制 Clang 与主机工具](docs/ROUTE_A_TOOLCHAIN.md) | 固定编译器、19 项语义断言、主机组件和实际验收 |
| [第一次完整内核编译入口](docs/ROUTE_A_FIRST_KERNEL_BUILD.md) | 固定 source/header staging、真实 builder、失败与产物记录 |
| [通用内核编译／链接结果](docs/ROUTE_A_GENERIC_KERNEL_RESULT.md) | 第二轮成功候选、实际 helper 代码、有限编码核对和剩余资格 |
| [平台组件与 callback 链接](docs/ROUTE_A_PLATFORM_RESULT.md) | 固定 provider 编译、真实 callback C 对象与独立内核候选 |
| [DarwinBoot 加载与启动参数](docs/ROUTE_A_LOADER_CONTRACT.md) | 生产 parser／复制代码、真实候选装载合同、入口 trampoline 与 boot_args ABI |
| [独立 QEMU 入口、快照与计时诊断](docs/ROUTE_A_QEMU_ENTRY.md) | 入口单步、完整／不完整快照、固定计时模型对照与五次实际尝试 |
| [首个编译阻塞与 CPU 修复](docs/ROUTE_A_FILESET_PTRAUTH.md) | fileset panic 能力分支、实际返回地址 codegen 与生产 CPU 约定 |
| [内核 TPRO 能力发布核对](docs/ROUTE_A_TPRO_KERNEL_PUBLICATION.md) | apple 向量、task security_config、commpage 与最终配置边界 |
| [输入提取方法](docs/ROUTE_A_EXTRACTION.md) | 官方镜像定位、分段读取与 APFS type 4 支持 |

```sh
git clone https://github.com/cyjin-yl/UniXNU-tb371fc.git
cd UniXNU-tb371fc
python3 scripts/check_repository.py
python3 scripts/check_catalog.py
```

以上两项检查核验仓库源码与设备目录。完整开发验证请继续执行 [DEVELOPMENT.md](DEVELOPMENT.md) 中的步骤；只跑源码检查不等于执行回归测试。

## 上游历史记录

下文的 iPadOS 17 / V135 结果来自上游既有记录，用于设备移植参考。它们没有在当前 27 路线中重新验收。

## 上游 iPadOS 17.7.11 基线

上游实机基线为 **V135，iPadOS 17.7.11（21H461）**。上游用户确认 V135 应用、设置、触摸和 GPU 正常；壁纸仍为黑屏，已停止该项实机调试。本项目仍在开发，不能作为日常使用系统。

仓库现已包含 V135 内核定点派生、原生 macOS 固件构建和 Android boot 镜像打包入口。V135 的这条构建路径保留已验证的 21H461 内核父镜像，并只对一个显示时序状态查询作等长 ARM64 指令替换；27 路线的[完整源码构建](docs/ROUTE_A_FIRST_KERNEL_BUILD.md)另行验证。干净固件重编译已完成；用留存的 V135 固件快速打包可逐字节复现实机镜像。详见[构建说明](docs/BUILDING.md)及[V135 恢复记录](docs/V135-RESUME.md)。

## 上游 iPadOS 17 / V135 支持状态

| 项目 | 当前结果 |
| --- | --- |
| 设备 | Lenovo TB371FC；bootloader 产品名 `spinel`；测试配置 8 GB + 128 GB |
| 系统 | iPadOS 17.7.11 / 21H461 已进入桌面 |
| CPU | 八核启动；日志确认各核计时器和 IPI 活动 |
| UFS / Data | 原生存储访问；持久 Data 写入和回读已验证 |
| 显示 | 可显示桌面与启动进度 |
| 触摸 | 桌面滑动可用；V128 日志确认 HID 上报无错误 |
| GPU | Adreno 650 已工作；V129 用户反馈滑动较 V128 提高约 5–10 FPS，V135 用户确认 GPU 正常 |
| 电源键 | 用户已验证息屏、亮屏 |
| 音量键 | 尚未正常工作，需要继续修复 |
| 应用与设置 | V135 用户确认应用 Waiting 修复及设置 About 页面正常 |
| 壁纸 | V135–V138 尝试未解决，用户决定暂停壁纸调试 |
| 电池与充电 | 容量、充电状态尚未正常识别 |
| 其他功能 | 未列出的功能不代表已支持 |

帧率来自用户左上角显示工具在滑动桌面时的观察；不是统一条件下的帧时间基准。GPU 性能优化按用户决定暂告一段落。

## 源码目录

- `package/Tb371fcTouch`、`Tb371fcButtons`、`Tb371fcInput`：触摸、PMIC 按键与 HID 生命周期。
- `package/Tb371fcGpu`、`Tb371fcDisplay`：目标 GPU 启动、帧缓冲与显示生命周期。
- `drivers/Adreno650`、`ArmSmmu4K`、`A650Gmu`、`AdrenoPM4`、`AdrenoFirmware`：GPU 和 SMMU 相关源码。
- `drivers/AdrenoMetal`：当前使用的 Metal 前端、桥接源码与 21 项 Pipa 转译补丁。
- `package/PlatformPower`、`Tb371fcEmbeddedFat`、`Tb371fcFastbootReturn`：平台与启动恢复集成源码。
- `package/RootLog`、`UfsProducerGate`：通用日志及 UFS 生产者门禁源码；不包含设备专属绑定记录。
- `patches/`：V129 连续内存分配策略改动。
- `patches/v135-display-timing-query.patch`：V135 GOP timing-enable 查询派生。
- `upstream/`：上游固定版本、UFS 来源记录及逐文件 SHA-256。

不含 iPadOS 系统文件、Apple 原始二进制、设备固件、个人设备备份、原始设备日志或账号凭据。

## 官网设备目录

根目录 `board.toml` 提供官网识别所需的设备身份，`porting.toml` 记录 13 个子系统的实现、限制和下一步。配置保持 `example=true`，完整独立构建尚未整理完成。官网收录由 UniXNU 上游同步与部署决定，添加文件不等于页面已经上线。

详见 [官网收录说明](docs/CATALOG.md) 和 [公开验证摘要](docs/VALIDATION.md)。

## 复现上游 V135 历史基线

以下步骤只针对上游 iPadOS 17 / V135；27 路线请从 [开发指南](DEVELOPMENT.md) 开始。

1. 阅读 [上游实机状态与里程碑](docs/STATUS.md)。
2. 查看 [上游来源与许可证](docs/UPSTREAM.md)。
3. 克隆并检查公开源码（只读源码与格式检查）：

   ```sh
   git clone https://github.com/cyjin-yl/UniXNU-tb371fc.git
   cd UniXNU-tb371fc
   python3 scripts/check_repository.py
   ```

   该命令核验源码清单和仓库内容，不会连接设备或刷写。

4. 要生成 V135 boot 镜像，按[构建说明](docs/BUILDING.md)准备维护者保留的本地输入包。Apple 系统、设备数据、固件、原始恢复备份和生成 ABI 不在公开仓库中。

## 上游致谢

本项目基于 UniXNU 社区的工作，并参考、复用 xVanTuring 的 Pipa / Adreno 650 实现、sheng 的主线实现、FFT-infra 的原生 UFS 实现，以及 metal2vulkan、Mesa 等项目。设备适配不等于这些通用驱动的原创实现；具体来源见 [UPSTREAM.md](docs/UPSTREAM.md)。

不同文件保留各自许可证与版权声明。根目录默认许可证为 BSD-2-Clause-Patent；MIT、BSD-2-Clause 等组件按原许可证使用，见 [NOTICE.md](NOTICE.md)。
