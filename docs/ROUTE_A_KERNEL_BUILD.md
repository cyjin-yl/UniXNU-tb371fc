# Route A：普通 arm64 / XNU 12377 源码准备

这一步为 TB371FC / Snapdragon 870 建立独立的 **XNU 12377 源码候选**，服务于已离线转换的 iPadOS 27.0.1 / 24A446 用户态。它还不是可启动内核，也没有接管历史 V135 的构建入口。

配置在 [kernel-route-a-ipados27.json](../configs/kernel-route-a-ipados27.json)，准备器在 [prepare_route_a_kernel.py](../scripts/prepare_route_a_kernel.py)。准备器只读取本地 Git object store，不在运行时自动下载源码、工具链、crypto provider 或 Apple 系统文件。

后续[第二轮真实构建](ROUTE_A_GENERIC_KERNEL_RESULT.md)已经将本基线加公开 headers 和独立 fileset 修复编译、链接为普通 ARM64 通用候选：1,086 个 `.o` / `.cpo`，1,067 行非空 link filelist，21,905,888 bytes（20.89 MiB）的 `MH_EXECUTE`、subtype 0 产物，0 编译 error、0 未定义符号。完整 TB371FC profile、provider/archive 依赖、全部 ISA 和 27 实机启动仍未验收；本页的准备器本身仍只负责源码准备与配置探针。

## 为什么新增这个入口

上游 27 profile 固定 Apple XNU 12377.121.6，并用 Darwin 26 兼容补丁衔接新用户态；其架构入口是 arm64e。上游旧 arm64 profile 的补丁来自另一代 XNU，直接切换会把不同基线混合。本候选从固定 12377 patch series 建立 architecture + Darwin 26 + plain-pager 源码子集，明确剔除两个硬件 PAC 补丁，暂缓一个依赖未解析板级 PMGR/watchdog 层的 boot-progress 补丁，再加入本仓库的无 PAC pager 修复。它不表示完整上游 OS/SoC/board profile 已经应用。

| 项目 | 固定选择 | 证据范围 |
| --- | --- | --- |
| UniXNU | `8542980d02b4d2cc5c32ee3542de1760b2562aac` | 从 commit 读取 profile、series 和 patch bytes |
| Apple XNU | `ac9718fb1af618d5ce8678d0dc6e8a58f252216f`，12377.121.6 / Darwin 25.5.0 | 新建干净源码快照，不读取脏 checkout 文件 |
| 配置探针架构 | `arm64-apple-ios27.0`、`-march=armv8-a` | 本准备器生成普通 arm64 配置对象；后续真实 builder 另显式选择 `-mcpu=generic` |
| 机器配置 | 上游 generic `BCM2837` | 通用 ARMv8 源码配置名称，不表示完整 TB371FC 板级适配 |
| 页尺寸 | translation granule 4 KiB、VM page 4 KiB | 与此候选选用的 4 KiB patches 对应 |
| 指针 ABI | plain-pointer ABI | 不提供 PAC 认证 |
| 保留事项 | Darwin 26 syscalls/KPI/shared-region、4 KiB pager | 成功应用不等于运行时 ABI 完整 |

### 保留 PAN 的显式上下文重基

真实完整 source preparation 已暴露一个顺序依赖：上游 `native-arm-pan.patch` 的尾部 context 引用了被排除的 PAC header 注释。该补丁自身的五行新增代码仍需保留，因此使用 [route-a-native-arm-pan-12377.patch](../patches/route-a-native-arm-pan-12377.patch) 重基到普通 arm64 header 的 `ASSEMBLER` guard，并保留此前 `no-apple-cpu-counters.patch` 已插入的 CPMU 注释和定义。这个本地补丁只改变 context，不删除或修改 PAN 功能。

配置显式绑定原始 patch SHA-256 `9d171dd00a8ac07c0ca6374258f4ee6ce6d02667abd0117415585d616b0e08e8` 和本地补丁 SHA-256 `902608946c2ba69692ceb08d234b041d2711fe65c6e36d6e1d4af596b4e90ca6`。准备器同时验证两份 bytes 的摘要、目标文件/hunk identity 与全部新增/删除行一致；重新计算 digest 不能绕过功能差异检查。报告为替换项保存原始路径/摘要、本地路径/摘要与原因，实际应用仍使用严格 `git apply --check`，不启用模糊匹配或跳过失败 hunk。

排除项是 `native-pac-keys.patch` 与 `native-pac-arm64-user-jop.patch`。准备器要求这两个名字在原始固定 series 中确实存在，拒绝旧版 `patches/xnu/`、重复项、缺失必要 patch、路径逃逸，以及新加入 `HAS_NATIVE_PAC` / `HAS_APPLE_PAC` 定义的 patch。PAN 也列入 required patch，不能通过丢弃它来消除上下文冲突。**排除两个 patch 只证明选择策略；其余内核源码、汇编、外部 archives 和原厂 kext 仍需完整 ISA 审计。**

## 明确暂缓板级 boot-progress 层

完整顺序应用暴露了第二项真实依赖：`zzz-boot-progress.patch` 引用 `bsd_init` 中的 `sheng_pmgr_run()` block，而该 block 来自先行的 SoC/board `sheng-platform-power.patch`，不在所选 12377 架构列表中。该诊断层还加入 `sheng_boot_watchdog_policy` 调用；它不只是独立打印函数。

固定上游 resolver 按 `board.kernel.patch_series` 的声明顺序应用，迁移示例是 arch → soc → os → device。上游 Sirius 文档记录过相同缺失 PMGR context 的失败，并在 SoC series 中补入前置 patch。当前通用候选尚未选择 TB371FC 的完整 SoC/board closure，因此配置 **显式暂缓** 这一个补丁，保留 67 项架构补丁（含 PAN 上下文重基）、3 项 Darwin 26 ABI 补丁与本仓库 plain-auth，共 71 项所选补丁。

暂缓项绑定固定 source SHA-256 `2e765b4416bab549027a7024c4777b003ca833b80addcc29daafbbcf65241e28`。准备器仍从固定 commit 读取它并验证摘要，报告保存其原始顺序位置、未应用状态、理由与板级集成待办。只能暂缓这个确切名字；required Darwin 26 / PAN / pager patches 不能通过此机制移除。输出明确记录 `preparation_scope=architecture-darwin26-plain-pager` 与 `full_upstream_profile_applied=false`。

`build-environment.json` 使用上游实际支持的 `XNU_BOOT_PROGRESS=0`。固定 `build-xnu-4k-baseline.sh` 将此环境变量读入 `BOOT_PROGRESS`，再传为 `-DXNU_BOOT_PROGRESS=$BOOT_PROGRESS`。本准备器没有执行完整 builder；后续实际构建必须传递该环境，并在明确的 TB371FC board/PMGR/watchdog/archive 配方中恢复和审计暂缓层。不能为了使 patch 应用成功而添加未接线的其他设备 PMGR 实现。

来源：

- [有序 resolver](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/unixnu/patches.py)
- [arch / soc / os / device 顺序示例](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/docs/porting/migration.md)
- [PMGR hook patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu/sheng-platform-power.patch)
- [相同失败的 Sirius 记录](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/docs/devices/sirius.md)
- [boot-progress patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/zzz-boot-progress.patch)
- [读取并传递 XNU_BOOT_PROGRESS 的 builder](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/build-xnu-4k-baseline.sh)

## 最初源码准备验证

提交 `5524e745ea50c71916b8abeb718b167e2d3c3350` 的 [CI](https://github.com/cyjin-yl/UniXNU-tb371fc/actions/runs/45173610144) 实际应用上述 71 项所选补丁，生成覆盖 6,119 个源码条目的清单，并以 Ubuntu Clang 18.1.3 编译通过普通 arm64 配置探针。完整报告见 [源码准备证据](evidence/route-a-kernel-preparation-20261123.json)。

该次对象为 Mach-O `MH_OBJECT`、ARM64、subtype 0，只是通用配置小程序。当时三个 XNU type builtins 的编译探针实际失败，内核尚未编译、链接或启动；历史报告保持原样。之后定制 Clang 与匹配 headers 已完成，首轮 builder 的 716 对象失败被留存，第二轮[通用候选编译／链接成功](evidence/route-a-generic-kernel-build-20261124.json)。

## 复现

需要 Python 3.11 或更新版本、Git、能生成 arm64 Mach-O 对象的 Clang，以及足够存放完整源码的工作目录。源码和输出目录应在设备仓库之外。以下 fetch 下载的都是公开源码，不会下载系统镜像或 crypto provider。

```sh
mkdir -p /path/to/route-a-sources
git init --bare /path/to/route-a-sources/unixnu.git
git -C /path/to/route-a-sources/unixnu.git fetch --depth 1 \
  https://github.com/UniXNU/UniXNU.git \
  8542980d02b4d2cc5c32ee3542de1760b2562aac

git init --bare /path/to/route-a-sources/xnu.git
git -C /path/to/route-a-sources/xnu.git fetch --depth 1 \
  https://github.com/apple-oss-distributions/xnu.git \
  ac9718fb1af618d5ce8678d0dc6e8a58f252216f

python3 scripts/prepare_route_a_kernel.py \
  --unixnu-repository /path/to/route-a-sources/unixnu.git \
  --xnu-repository /path/to/route-a-sources/xnu.git \
  --output /path/to/new-kernel-candidate \
  --clang clang
```

输出目录必须是新的。准备器不会覆盖已有目录，也不会改变输入仓库的 HEAD、index 或工作树。输出通过显式获取固定提交建立独立 Git object store，即使输入只有 `FETCH_HEAD`、没有分支且为浅层仓库也能处理；准备完成后，输出中的 Git 对象不依赖输入仓库路径。

Ubuntu runner 可以使用发行版 Clang 完成此处的通用配置探针。完整 XNU build 另需带 `__builtin_xnu_type_*` 支持的定制 Clang、MIG/IIG、Mach-O 工具链、headers 和全部已选组件；普通 Clang 能完成探针，不表示这些依赖已经满足。

## 准备器实际检查什么

1. 验证配置的 XNU 版本、commit、普通 arm64 target、4 KiB 选择和 build environment 一致，拒绝在配置里声称“已编译/已启动”。
2. 通过 `git show <fixed-commit>:<path>` 获取上游 profile 和完整 patch bytes。工作树的本地改动不能悄悄替代输入。
3. 解析 12377 架构和 OS series，排除两项硬件 PAC 补丁并单独绑定/记录暂缓的 board boot-progress patch，验证 required patch、版本和顺序。最后加入 SHA-256 已固定的 `route-a-plain-auth-12377.patch`，要求其 4 KiB shared-region prerequisite 已在前面。
4. 从固定 XNU commit 建立新的干净 tree；每项先 `git apply --check`，再实际应用。失败时立刻停止，报告只记录已经成功应用的 patch，不把部分 tree 当作完整候选。
5. 对全部源文件和 symlink 生成路径、模式、长度及 SHA-256 清单；清单不包含 `.git`。生成树的新增文件也参与摘要。
6. 用选定 Clang 编译通用机器头文件探针。代码要求 `__arm64e__` / `ptrauth_calls` 不启用、该机器头文件不定义硬件 PAC；输出必须是 Mach-O `MH_OBJECT`、ARM64、subtype 0。失败会使 CLI 返回非零。
7. 实际编译三个 XNU type builtin 表达式，记录当前 Clang 是否支持。缺失会进入 full-build blockers；它不妨碍保存已经通过的源码准备结果。
8. 始终保留 `kernel_compiled=false`、`kernel_linked=false`、`os_boot_verified=false` 和 `full_kernel_isa_audited=false`。

宏探针只编译一个自包含的小文件。它既不是完整 `board_config.h`/kernel 的预处理证明，也没有执行任何目标内核代码。只有后续完整构建与输出审计才能关闭这一缺口。

## 输出和退出语义

| 文件 | 用途 |
| --- | --- |
| `tree/` | 应用所选补丁后的 XNU 源码 |
| `patches/` | 按应用顺序保存的确切 patch bytes |
| `preparation-report.json` | 输入身份、原始/替换 patch 对应关系、已应用项、成功或失败、探针退出码/有限诊断和未完成事项 |
| `selected-patches.json` | 成功准备后的精确 patch order 与每项 SHA-256 |
| `source-inventory.json` | 全部生成源文件的内容清单 |
| `build-environment.json` | 后续完整构建需要显式传递的架构/版本变量；不是可直接启动的 build recipe |
| `compiler-probes/` | 两个探针、普通 arm64 对象、宏输出和编译器诊断 |

退出码 0 只表示上面明确界定的 71 项所选 patch sequence 和通用 arm64 配置探针成功，完整 board/OS profile 仍未应用；任何缺失源码、digest 不匹配、patch 失败或配置探针失败都返回 2。失败目录及报告保留，便于诊断；重试使用另一个新目录。

源码准备结果由运行生成的报告决定。本文不把工具实现或测试 fixture 当成真实固定源树已经应用成功的证据。CI / 开发机应保存实际 `preparation-report.json`，并在变更说明中标出其状态和运行 commit。

## 后续构建工作

配置内的 component inventory 列出了上游 common source-build 路径涉及的 firehose、compiler runtime、crypto、pthread、ArmDTPlatform 与 ArmCpu 输入，但 **TB371FC 的完整 archive closure 尚未解析**。存储、显示、GPU 和其他外设输入须按当前板级实现重新连接到 12377；不能把别的 Qualcomm 平台 archive 当作 TB371FC 已验证产物。

定制 Linux Clang、组合工具链和匹配 headers 已取得[实际完成记录](evidence/route-a-toolchain-success-20261124.json)。[真实 builder](ROUTE_A_FIRST_KERNEL_BUILD.md) 在独立 fileset 修复和显式 CPU 检查后，第二轮已成功编译／链接通用候选，并保存真实 link filelist。独立[有限编码核对](evidence/route-a-kernel-candidate-audit-20261124.json)覆盖 3 个区域、2,220,163 个候选 4 字节字：分类器识别的非 HINT PAuth 为 0、精确 POE2 TCHANGE 为 0，记录 180 个 `XPACLRI` HINT；这仍不证明全部 ISA 或可达性。

后续需明确选择并接入完整 TB371FC provider/archives，保存各自源版本和摘要。完整候选还必须经过 kernel/archive/kext ISA 与系统寄存器审计、27 userland 与 TPRO contract 验证、板级最小启动和最终硬件验收。具体缺口见 [集成审计](ROUTE_A_KERNEL_GAPS.md) 与 [plain-auth 补丁说明](ROUTE_A_PLAIN_AUTH_PATCH.md)。

## 固定来源

- [27 profile](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/os/ipados-27.0.1-24A446/profile.toml)
- [12377 架构 patch series](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/arch/arm64e/patches/xnu/series)
- [generic 机器配置 patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/bcm2837-machine-config.patch)
- [native PAC keys patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/native-pac-keys.patch)
- [上游 common.config](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/arch/arm64e/configs/common.config)
- [Linux 工具链 requirements](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/docs/guide/requirements.md)
- [XNU type builtin compiler patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/linux/llvm-xnu-builtin-type.patch)
