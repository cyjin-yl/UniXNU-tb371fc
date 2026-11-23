# Route A：公开平台归档与隔离内核链接

记录批次：2026-11-24，Asia/Shanghai。

`ArmDTPlatform` 与 `ArmCpu` 已在本轮成功的通用 XNU 构建环境中完成实际 C++ 编译和归档。第二次尝试 `attempt-002` 于北京时间 **2026-11-24 03:42:36** 完成（UTC `2026-11-23T19:42:36Z`），报告状态为 `archives_built`，两个对象均为普通 ARM64、subtype `0`、iOS 27.0，脚本列出的保护输入前后摘要一致。

**`link-attempt-004` 已通过真实平台兼容性链接验收。** 在逐字节重现原内核后，它加入两个 provider，并用来源绑定的 callback 对象替换唯一 `cpu.o`，得到 21,942,456 字节的普通 ARM64 候选。实际 map、constructor table、callback 定义及最终符号检查均通过，1,137 项声明输入前后保持一致；此前三次链接尝试的失败报告和诊断完整保留。

这个结果完成了两份公开平台归档与 kernel callback 的独立链接验证。完整 TB371FC 板级依赖、运行时驱动匹配、睡眠恢复和 iPadOS / macOS 27 启动仍分别待验收。通用内核本身此前完成的编译和链接见 [ROUTE_A_GENERIC_KERNEL_RESULT.md](ROUTE_A_GENERIC_KERNEL_RESULT.md)。

## 实际产物

构建目录为仓库外的 `/work/route-a-platform-20261124/attempt-002`。原 `attempt-001` 的失败报告和日志保留；第二次尝试使用新的 driver 快照和输出目录。

| 文件，相对于 `attempt-002` | 字节数 | SHA-256 |
| --- | ---: | --- |
| `ArmDTPlatform/ArmDTPlatform.o` | 199,384 | `c106ef44295f0f4b6dd9984e7b0f2eea774ea25c3404f96e430930b5ccc5c75e` |
| `ArmDTPlatform/libArmDTPlatform.a` | 200,736 | `e7ac03171cd30f9cb265e6445167898ec2ea3282148489dc1dd059729e759873` |
| `ArmCpu/ArmCpu.o` | 294,368 | `84dc248bce8dbcaa30349859ea7d59ca79b6177cbf02ce8dc9e0134686a4dc33` |
| `ArmCpu/libArmCpu.a` | 297,152 | `34ca2e7a0f970608f8924b6a8fc755e3ae594259c825f6351ac9e436548e751a` |

两份 `.o` 的实际格式检查均通过：Mach-O 64 位、`MH_OBJECT`、`CPU_TYPE_ARM64`、完整 subtype 值恰为 `0`，且只有一条 `LC_BUILD_VERSION`，platform 为 `2`、minos 为 `0x001b0000`，即 iOS 27.0。`.a` 是 Darwin 格式归档；目标格式检查针对其中的实际对象成员。归档成员清单及 `ar p` 取出的成员字节也必须与对应 `.o` 的摘要一致。

两次真实 compiler 子进程的退出码均为 `0`，两个 compiler stderr 文件均为零字节。本次九项保护输入复核全部通过，`protected_inputs_unchanged=true`。它指编译入口明确记录并前后复核的输入，包括原内核候选、原 C++ recipe、原 `IOPlatformExpert.cpo`、实际 Clang、构建报告、toolchain 状态及 archiver；不能扩大解释成已完成整个文件系统或设备状态的审计。

原始报告已取回，见[归档结果摘要](evidence/route-a-platform-archives-20261124.json)和[公共文本证据目录](evidence/route-a-platform-20261124/)。绑定摘要如下；原对象、归档及 `ar p` 产生的二进制 stdout 继续保留在仓库外。

| 原始报告 | 实际状态 | SHA-256 |
| --- | --- | --- |
| [attempt-001/report.json](evidence/route-a-platform-20261124/attempt-001/report.json) | `failed`；两个 compiler 退出码均为 `1` | `4681edc208e3a31ef40722fc388fc68b74a545b13b3005ee376f91e4d5e3785f` |
| [attempt-002/report.json](evidence/route-a-platform-20261124/attempt-002/report.json) | `archives_built` | `15f04371f0d1b472d14ef4a69d739dcaecfdacd05df4f074b58563ce0f487a04` |

### 已观察到的符号名字比较

第二次尝试的 [symbol-comparison.json](evidence/route-a-platform-20261124/attempt-002/symbol-comparison.json) 摘要为 `5f24044797fdbb1a83de59588b5d73ef20e5c325dd227862e0b6a10bf48837bb`。它将两个对象的外部引用与通用 kernel 及两个 provider 的定义集合比较：

| 对象 | 未匹配的强引用 | 未匹配的弱引用 |
| --- | ---: | --- |
| ArmDTPlatform | 0 | 无 |
| ArmCpu | 0 | `_arm64_platform_sleep_hook` |

报告中的潜在重复名字集合为空，common / unsupported external 类别也为空。其 scope 明确是 `external-symbol-name-set-comparison-only`，`link_verified=false`。这些结果为实际 linker 提供下一步输入检查，不能证明 archive 已被抽取、重定位已经完成、constructor 能运行或驱动已经匹配设备。

## 固定来源与编译基线

组件选择来自 [UniXNU 固定 catalog](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/components.toml)。新入口 [build_route_a_platform.py](../scripts/build_route_a_platform.py) 与 [route-a-platform.json](../configs/route-a-platform.json) 将 repository、commit、参与编译的文件及其 Git blob 固定下来。

| 输入 | 固定版本 / 文件 | 本轮用途 |
| --- | --- | --- |
| UniXNU | `8542980d02b4d2cc5c32ee3542de1760b2562aac` | catalog、原驱动 warning policy、通用构建配方 |
| XNU | `ac9718fb1af618d5ce8678d0dc6e8a58f252216f`，`xnu-12377.121.6` | 已成功构建的源码、生成头文件和实际 IOKit ABI |
| [ArmDTPlatform](https://github.com/UniXNU/ArmDTPlatform/tree/417ff95d6a6e8607ddea9309ec45c3bfd4a67c60) | `417ff95d6a6e8607ddea9309ec45c3bfd4a67c60`；`ArmDTPlatform.cpp`、`LICENSE` | 基于真实 `IODTPlatformExpert` 的公开平台 expert |
| [ArmCpu](https://github.com/UniXNU/ArmCpu/tree/5f3702697ed80fd2e98594de1af7e32b4b77b08b) | `5f3702697ed80fd2e98594de1af7e32b4b77b08b`；`ArmCpu.cpp`、`ArmCpuSleep.h`、`LICENSE` | CPU、GIC / timer 等平台接口的公开实现 |
| LLVM / Clang | `58c46bae21181fb4240cf964461bea738d96d50e`，定制 Clang 24.0.0git | 与成功通用内核相同的编译器及 XNU type builtins |
| 归档器 | 本轮使用 `/usr/bin/llvm-ar-19` | 实际执行 `--format=darwin rcsD`，工具 SHA / version 进入报告 |

两份 provider 源码均使用 BSD-2-Clause-Patent；对应来源的 [ArmDTPlatform LICENSE](https://github.com/UniXNU/ArmDTPlatform/blob/417ff95d6a6e8607ddea9309ec45c3bfd4a67c60/LICENSE) 与 [ArmCpu LICENSE](https://github.com/UniXNU/ArmCpu/blob/5f3702697ed80fd2e98594de1af7e32b4b77b08b/LICENSE) 随编译输入快照完整保存。上游 catalog 的历史 ABI 标记和本轮真实编译结果分别记录，不能据此自动改写全部 board/profile 的兼容资格。

关键编译输入绑定如下：

| 输入 | SHA-256 |
| --- | --- |
| 已成功的通用内核候选，21,905,888 字节 | `a58cdeedb9b7a4c152867c3487f28658a3799b0158f5046bbad6d2d58e741469` |
| 原始成功内核 `build-report.json` | `34c40f71b43000dff0cc39b97264fc93ef1fd3b3027735c4a710817863b71044` |
| 原始 `IOPlatformExpert.cpo.json` | `d6cc5213a5aba343dde41bdb3a1ea8c72e91605284af5e10b886bf3af71b3132` |
| 实际 Clang 二进制 | `85d220e32bd83d75de788c8beab0bea646a4684e1112f7c06266ca71e651bb04` |
| 第二次 provider 构建 driver | `3593172a4cf9695e1cc0efd4d110e65af7ca293a91e276bab6df96b86788009f` |
| 第二次 provider 配置 | `a0c1d3b19dd639495e764a2e353c919f5c5bdf8c09cf45690664c5d167b985fc` |
| 共用 toolchain helper | `9680894acc78dbbdf2e990860a3f4506742ae5f4e945d9fc84a606618ddde275` |

原 recipe 位于成功 kernel 工作树的 `build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json`。它明确包含 `-mcpu=generic`、普通 `arm64` 架构和 iOS 27.0 目标。入口使用其实际生成 / 导出的内核头文件；源文件与 `-o` 替换为独立输出路径，不生成替代 ABI 声明或手工布局 shim。

## 首轮失败与第二轮修复

第一次尝试沿用固定上游 [build-arm-driver.py](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/build-arm-driver.py) 的 warning 处理：删除 recipe 中已有的 warning 参数，再添加八条驱动 warning policy。真实编译因此丢失了成功内核 recipe 中已经存在的两条 Clang 兼容选项。

实际诊断包括 KALLOC 宏展开中的 `-Wmissing-designated-field-initializers`，以及 `ArmCpu` 的 `gController` 触发的 `-Wunused-but-set-global`。首次失败完整保留，没有将编译失败归类为归档成功。

第二次尝试将下列两条单独列为 `retained_recipe_warnings`：

```text
-Wno-missing-designated-field-initializers
-Wno-unused-but-set-global
```

它们在原始成功 recipe 中分别出现三次、一次。入口只允许这一固定集合，并要求每项确实出现在原 recipe 中；缺失、重复配置或新增其他 retained warning 都会拒绝。报告分别记录上游八条 warning policy、实际继承的这两条兼容选项及原始出现次数。`-Wall -Wextra -Werror`、目标约束和全部格式检查继续启用，两份 provider 的源码不因这次修复而改写。

这一修复有明确的输入依据：恢复成功内核已经使用的编译器兼容选项。它没有引入任意 warning 开关，也没有靠删除 ABI 检查获得通过。针对输入身份、输出隔离、真实子进程失败日志、目标约定、Mach-O 强弱符号和 retained warning 边界的 [13 项回归](../tests/test_route_a_platform.py) 已通过；这些测试与两份真实归档的构建证据分别记录。

## 输入与输出隔离

入口只接受两个预先准备好的源码 checkout：`sources/ArmDTPlatform` 与 `sources/ArmCpu`。它核对 HEAD、tracked 工作树状态，并逐文件比较固定 Git blob 与当前文件字节，再把声明的源文件及 LICENSE 复制到新输出目录。未跟踪的同名头文件不会加入编译输入。

编译参数只接受已审查的形式；响应文件、插件参数、架构 / CPU 改写和未知副作用参数会被拒绝。原 recipe 的工作目录只用于解析真实相对头文件路径。对象输出、dependency 文件、可能存在的 `-MJ` 输出、临时文件和日志全部指向新目录，并关闭 Clang 默认配置文件的隐式读取。实际依赖清单分别记录 356 / 358 个文件，包含 translation unit 本身、生成头、SDK 头和编译器 resource header 的路径及摘要；这些计数不是单独的头文件数量。

kernel 与 toolchain 的既有锁以只读方式打开，并在尝试期间持有共享锁。失败、超时或可捕获的中断会保存原子 JSON 状态和已落盘日志；强制终止进程时，最后运行状态与已写日志保留供外层 runner 判断。脚本拒绝复用输出目录，也不覆盖原 kernel 的 recipe、对象或候选文件。

## 复现独立归档构建

大型输入和实际执行继续放在 CT102 的 `unixnu-route-a-dev` 容器中。下列 `ROUTE_A_SOURCE` 应指向包含上述固定 driver / config / helper 的本仓库 checkout 或保留快照，并维持 `scripts/` 与 `configs/` 的相对布局。

前置条件是上述成功 kernel 工作树、已验证的 toolchain，以及两个表中 commit 的干净源码 checkout 已存在。本入口不下载源码、不安装工具链；原 kernel recipe 的原始摘要和绝对路径也已绑定，不能把复制到其他路径的工作树直接当作同一个输入。

以下使用新的 `attempt-replay-001`，以保留已完成的 `attempt-001` 与 `attempt-002`：

```sh
ROUTE_A_SOURCE=/absolute/path/to/UniXNU-tb371fc
ROUTE_A_PLATFORM=/work/route-a-platform-20261124

python3 "$ROUTE_A_SOURCE/scripts/build_route_a_platform.py" \
  --kernel-dir /work/route-a-continue-20261123/kernel-build \
  --toolchain-work /work/route-a-continue-20261123/toolchain-work \
  --sources "$ROUTE_A_PLATFORM/sources" \
  --output "$ROUTE_A_PLATFORM/attempt-replay-001" \
  --ar /usr/bin/llvm-ar-19
```

成功必须同时满足进程退出码 `0`、`report.json` 的 `status=archives_built`、两项组件 `status=archive_built` 以及输入复核通过。若输出目录已存在，应保留它并选择新的目录名。

## 独立链接验证与完整尝试记录

[link_route_a_platform.py](../scripts/link_route_a_platform.py) 执行独立兼容性实验。它读取成功归档报告及原始 kernel 链接输入，产物写入新的外部目录，不调用原 builder 重写已成功的内核工作树。

该入口的强制门槛是：先从固定 `.LDFLAGS`、archive 参数、Make 规则、1,067 项 `link.filelist` 和四个额外对象恢复普通 non-LTO 链接命令，实际重放通用 baseline。**只有重放产物逐字节命中原内核 SHA-256 `a58cdeed…e741469`，才允许第二次链接加入两个 provider 的 `force_load`。** 原 1,071 个对象及其余声明输入都会记录并在结束时复核。

第二次链接若完成，还须重新解析实际 Mach-O 的普通 ARM64 subtype、iOS 27.0 部署目标、入口及符号，并从真实 link map 和 constructor table 确认两个 archive 成员、初始化函数、metaclass 和观察符号进入产物。源对象中 `N_WEAK_REF` 表示的弱未定义引用单独记录；名字集合比较不能替代真实链接结果，弱定义也不能一概当作强符号冲突。

复现命令如下；未补充 kernel callback 时，它会保留同一缺失符号的实际链接失败：

```sh
python3 "$ROUTE_A_SOURCE/scripts/link_route_a_platform.py" \
  --kernel-dir /work/route-a-continue-20261123/kernel-build \
  --toolchain-work /work/route-a-continue-20261123/toolchain-work \
  --platform-report "$ROUTE_A_PLATFORM/attempt-replay-001/report.json" \
  --output "$ROUTE_A_PLATFORM/link-replay-001"
```

对本次已完成归档做实验时，`--platform-report` 使用 `attempt-002/report.json`，链接输出仍须选择全新目录。baseline 不匹配、真实 linker 错误、强未定义符号、成员 / constructor 检查失败或保护输入变化都会停止，并保留实际失败阶段和日志。

`link-attempt-002` 实际记录 `baseline_reproduced=true`、`platform_link_compatible=false`。这两个字段分别由重放 SHA 与真实 provider 链接结果决定。

### 第一次重放：还原 ld64 的两个实际输入

`link-attempt-001` 的真实 linker 已返回 `0`，得到同为 21,905,888 字节的文件，但其 SHA 为 `791d4cfce73dccc67e7c66a3c7a432488a27f77a65b003d70cf80a15f6aa497a`。完整 SHA 门槛因此拒绝继续，两个 provider 尚未加入这次链接。1,114 项声明输入在结束时全部复核一致，见[原始失败报告](evidence/route-a-platform-20261124/link-attempt-001/report.json)。

逐字节比较精确找到 21 个不同字节：16 个位于 `LC_UUID`，另 5 个位于 `LC_SOURCE_VERSION`；其余字节完全相同。[差异记录](evidence/route-a-platform-20261124/link-attempt-001/baseline-difference.json)保留命令偏移及原始字节。固定 cctools-port `3e694ee7393af2a4ce8bd6e7dae28fe37450aa87` 的实现解释了这两项输入：

- [OutputFile::computeContentUUID](https://github.com/tpoechtrager/cctools-port/blob/3e694ee7393af2a4ce8bd6e7dae28fe37450aa87/cctools/ld64/src/ld/OutputFile.cpp#L3928) 在输出参数含 `/` 时，把最后一个 `/` 开始的尾段纳入摘要。新目录可以不同，输出 basename 应与原命令一致。
- [Options 的构建环境读取](https://github.com/tpoechtrager/cctools-port/blob/3e694ee7393af2a4ce8bd6e7dae28fe37450aa87/cctools/ld64/src/ld/Options.cpp#L4908) 在 source version 尚为零时使用 `RC_ProjectSourceVersion`。原构建使用 `12377.121.6`，其编码 `0x0030591e40600000` 对应实际观察到的 `000060401e593000` 小端字节；第一次重放遗漏了该环境变量。

源码版本也参与内容摘要，因此 UUID 差异受这两项输入共同影响。实际候选没有 `LC_CODE_SIGNATURE`，此处不涉及签名标识修补。

修复保留新的独立目录，使用原 basename `mach.development.bcm2837.unstripped.noctf`，并从已绑定 SHA 的成功 build report 中读取、验证 `UNIXNU_XNU_VERSION=12377.121.6`，据此恢复 `RC_ProjectSourceVersion`。没有覆盖原候选、修改重放后的 Mach-O 字节或豁免任何摘要差异。修复源码为 [7a63313](https://github.com/cyjin-yl/UniXNU-tb371fc/commit/7a6331344e721cff222f1e5af1642c3098d829b9)，第二次实际链接尝试仍以完整 SHA 一致为先决条件。

### 第二次重放：基线一致，真实平台链接指出 kernel callback 缺口

`link-attempt-002` 于 UTC `2026-11-23T20:01:04Z` 完成。baseline 的实际 linker 退出码为 `0`，产物为 21,905,888 字节，完整 SHA-256 为 `a58cdeedb9b7a4c152867c3487f28658a3799b0158f5046bbad6d2d58e741469`，与原内核完全一致。

随后原有 1,071 个对象加上 `ArmDTPlatform`、`ArmCpu` 两个 `force_load` 归档的真实 linker 退出码为 `1`。唯一报告的未定义符号是 `_arm64_platform_sleep_hook`，引用来自 `libArmCpu.a(ArmCpu.o)` 的 `ArmCpu::start(IOService*)`。见[原始报告](evidence/route-a-platform-20261124/link-attempt-002/report.json)与[linker stderr](evidence/route-a-platform-20261124/link-attempt-002/platform-link.stderr)。报告 SHA 为 `d863658c8b5fec0415406984a6ac9aaf6449870aaa457867d39f20792628655a`；结束时 1,114 项保护输入全部一致。

这个符号是由 XNU `cpu.c` 定义并在 `ml_arm_sleep()` 中调用的函数指针变量。[固定 ArmCpu](https://github.com/UniXNU/ArmCpu/blob/5f3702697ed80fd2e98594de1af7e32b4b77b08b/ArmCpu.cpp) 对它使用 `weak_import`，但本次实际静态 kernel 链接仍要求解析它；先前的弱引用名字比较没有证明链接可通过。

对应来源为 [Sheng 的 sleep patch](https://github.com/UniXNU/UniXNU-sheng/blob/c8f92b208068eeaa4cd2b0f592671f04ee70076e/patches/xnu-12377/sheng-platform-sleep.patch)，Git blob `8517a5278e7fa5446a569aa111344b0c40140ce5`。其中 `cpu.c` 的三个功能 hunk 定义指针，并把 boot CPU / secondary CPU 的真实 sleep 调用路径接到它；boot CPU 返回后调用原有 `arm_init_cpu` 唤醒入口。整份 patch 还修改 `cpu_common.c`、`IOPMrootDomain.cpp`，并依赖 Sheng 的 `sheng_sigp_recover()` 前置改动，因此不能把整份补丁直接视为本通用构建的独立输入。

针对这个缺口，后续采用来源绑定的 `cpu.c` 三处接线适配，在新目录使用这个翻译单元的真实 C 编译记录生成替换对象；只在平台链接的新 filelist 中替换唯一 `cpu.o`。原 baseline 仍先按完整 SHA 验收。完整睡眠策略、唤醒源注册、IPI 恢复和设备实测属于后续独立门槛；这次实验未设置 `platform-sleep=1`。

### 第三次链接：两个 linker 成功，map 的二进制字面值触发解析失败

`link-attempt-003` 于 UTC `2026-11-23T20:46:49Z` 完成，两次真实 linker 的退出码均为 `0`，baseline 也完整命中原 SHA。但 ld64 的 map 中含有 `literal string` 记录：偏移 924,961 的 `0x86` 是 OID 字节，不能按严格 UTF-8 解码。检查器因此保留 `status=failed`、`platform_link_compatible=false`。1,134 项保护输入在结束时全部一致，见[原始失败报告](evidence/route-a-platform-20261124/link-attempt-003/report.json)及[只读字节诊断](evidence/route-a-platform-20261124/link-attempt-003/map-decode-diagnostic.json)。

修复 [09e02e6](https://github.com/cyjin-yl/UniXNU-tb371fc/commit/09e02e6436aa39a945819bc1be0f9c57d6d6f8d7) 读取同一份原始 map 字节，用可逆 `surrogateescape` 保留非 UTF-8 字节，并验证完整 round trip。记录只按 LF 分行，结构字段只接受 ASCII 数字、空格和 TAB；参与资格判定的 constructor / metaclass 名称必须是可打印 ASCII，路径、marker 和 callback 名称仍精确匹配。回归覆盖实际 OID、正常 Unicode、伪造 Unicode 行界／空白／数字及损坏目标名称。原 map 和已生成的 Mach-O 字节均未修改。

### 第四次链接：平台成员、callback 与符号验收通过

`link-attempt-004` 于 UTC **2026-11-23T21:00:30Z** 完成。它从新目录重新执行完整 baseline 和平台链接，两次退出码均为 `0`；[原始报告](evidence/route-a-platform-20261124/link-attempt-004/report.json)状态为 `platform_link_compatible`，`kernel_callback_linked=true`。

| 项目 | 实际结果 |
| --- | --- |
| 原 baseline | 21,905,888 B；SHA `a58cdeedb9b7a4c152867c3487f28658a3799b0158f5046bbad6d2d58e741469`，逐字节一致 |
| 新候选 | 21,942,456 B；SHA `46eff436250d905e9f3aec59dbcc8c04d594e614e790860236917c7cbfe39f1b` |
| Mach-O / 目标 | 普通 ARM64，subtype `0`，`MH_EXECUTE`，iOS 27.0 deployment target |
| `ArmDTPlatform` | 实际 archive member 分配 43 个非零大小符号，constructor、metaclass、观察符号保留 |
| `ArmCpu` | 实际 archive member 分配 164 个非零大小符号，constructor、metaclass、观察符号保留 |
| callback 对象 | map 索引 318 对应新的 `cpu.o`，旧对象未进入；8 B hook 定义和 328 B `_ml_arm_sleep` 均来自替换对象 |
| constructor table | 101 个不同 pointer；包含两个 provider 的实际 constructor 地址 |
| 最终未定义符号 | 强未定义 0、弱未定义 0；common external 检查通过 |
| map 字节 | 7,555,941 B；2 个非 UTF-8 字节无损保留，整份 SHA `e9f2ff46924e73690c62f07eb6d70786fb2f54c815580a22484ad56674268165` |
| 输入复核 | 1,137 项全部一致，changes 为空 |

报告 SHA 为 `738a7af11b32c08d0a4261611ba69f325d5a29bf424791b18e98879864feff7c`。平台 filelist 恰替换第 317 行（零基索引 316）的一个 `cpu.o`，保留其余 **1,070 个原链接对象**，再加入两个 provider 的归档成员；报告里的 `linked_original_object_count=1071` 是恢复的 baseline 配方计数。实际 [原 filelist](evidence/route-a-platform-20261124/link-attempt-004/inputs/link.filelist)、[平台 filelist](evidence/route-a-platform-20261124/link-attempt-004/inputs/platform-link.filelist)和输入清单一并保留。

第三、四次生成候选的 SHA 相同；第三次的失败来源是 map 解析器，仍保留为失败记录。第四次依据重新运行的 linker、实际 map 和对象检查获得本轮通过状态。两个 constructor 的装载已经核验，其运行、IOService 匹配及 sleep 分支在设备上的执行仍未验证。

## Kernel callback：实际 C 编译与生成代码验收

新增 [callback 编译入口](../scripts/build_route_a_kernel_callback.py)、[固定配置](../configs/route-a-kernel-callback.json)和[三个 hunk 的原样选择](../patches/route-a-kernel-sleep-callback-12377.patch)，首版源码提交为 [ede99e1](https://github.com/cyjin-yl/UniXNU-tb371fc/commit/ede99e14ddcaba6916894d1c68da981531ee1bdb)。固定来源的 BSD-2-Clause-Patent 许可证与本仓库 `LICENSES/BSD-2-Clause-Patent.txt` 字节相同；原 `cpu.c` 的 Apple 通知保留，不对 XNU 重新授权。

原 prepared `cpu.c` 为 38,492 字节、SHA `6ea14e16fab1d5a16cf3483e630863b830e07190db35d1180850f29a27d9f968`。三个完整上下文在这份源码中唯一匹配第 99、1109、1151 行；相对上游补丁头的行号偏移分别为 0、−32、−32。保留补丁字节，通过精确完整上下文定位，不使用模糊匹配。应用后的独立副本为 39,238 字节、SHA `7b8eb68b50971168a7bc3d8ec05b8c76dbc9ee0b77e5f280b02d0c34a8c89bfc`。

这个翻译单元使用自己的 `osfmk/DEVELOPMENT/cpu.o.json`，SHA 为 `bfd7ad809f8b5704f8815a4f9214cba8de8a58c949825a1d8a0bf48fb22a0002`。实际 505 项 C recipe 重放为 511 项：保留 CPU、架构、目标、宏、优化和 77 项 warning 的原始顺序；改变源与输出路径，把 `-I .` 解析为原 cwd 的绝对路径，增加独立 dependency 输出及禁用隐式 Clang config。编译 cwd 为新 `replacement/` 目录。**这份 C recipe 原本没有 `-Werror`；不能与上面的 C++ provider warning policy 混为一谈。**

### callback-attempt-001：编译成功，检查器拒绝未覆盖的尾块布局

首次真实尝试于 UTC `2026-11-23T20:31:09Z` 完成。patch check、patch apply、C compiler、objdump version 与实际反汇编五个子进程全部返回 `0`。新的 `cpu.o` 为普通 ARM64 / subtype 0、iOS 27.0，123,440 字节、SHA `c0c63fb0c8d75a968f0c3914d91bd45c1d7d97bee3ca11c960b3523c1ae2ee68`。415 项保护输入回执全部一致。

[这次 C compiler stderr](evidence/route-a-platform-20261124/callback-attempt-001/logs/cpu-compile.stderr)为 179,542 字节，并非空日志：包含 2 条 `-Wmissing-include-dirs`、190 条 `-Wshadow-header` 和 111 条 `-Wunsafe-buffer-usage` warning 行，0 条 error。Clang 的末尾计数为 301，不含前两条 driver warning。这里保留原 C recipe 的诊断策略和完整日志，不新增 warning 抑制。

该次报告状态仍是 `failed`，失败阶段为 `checking_generated_callback`，不是 compiler failure。首版有界检查器只识别相邻的 pointer load / CBZ / 参数设置 / BLR；实际 Clang 把 secondary 回调放在函数尾块，用非零条件的直接分支进入：

| 路径 | 真实对象内地址和操作 |
| --- | --- |
| boot CPU | `0xce0` ADRP + `0xce4` LDR 均有 hook relocation；`0xce8` CBZ 跳过回调；`0xcec` 置 TRUE，`0xcf0` BLR |
| boot 返回 | `0xcf4` 设置原 cpu-data 参数，`0xcf8` 第二参数置零，`0xcfc` BL relocation 指向 `_arm_init_cpu` |
| secondary 分支 | `0xd38` ADRP + `0xd3c` LDR 均有 hook relocation；`0xd40` CBNZ `x8` 到 `0xda0` |
| secondary 尾块 | `0xda0` 设置 FALSE，`0xda4` BLR `x8`；该实际 taken edge 上没有改写目标寄存器 |

函数范围为 `0xc68..0xdb0`。尾块前的物理指令 `0xd9c` 是跳往 `0xca4` 的无条件分支，不能把中间另一条循环路径的物理排列当成 callback 的执行顺序。该布局成为下述检查器修复的实际输入。[原始失败报告](evidence/route-a-platform-20261124/callback-attempt-001/report.json) SHA 为 `91c8cee6413d271792d876a29c505f6328af8216a64fc5468d888a4d349b1578`，[完整反汇编](evidence/route-a-platform-20261124/callback-attempt-001/logs/cpu-disassembly.stdout)、raw symbols、relocations、dependencies 和旧尝试均保留。

### 检查器修复与首轮对象的只读复测

[6dd4dd7](https://github.com/cyjin-yl/UniXNU-tb371fc/commit/6dd4dd7c2f26b77e0e2817f3e1fd50d20cef8843) 中的检查器增加这一明确的前向 CBNZ 尾块形状：要求真实 hook 的 ADRP / LDR relocation、相邻的 64 位 LDR / CBNZ，以及直接进入尾块的 taken edge。尾块前缀最多八条指令，只接受已审查的 MOV / MOVZ / NOP，拒绝目标寄存器及其 W 寄存器别名被覆盖；FALSE 参数必须在这条路径内定义。物理 fallthrough、第二条局部显式入边和错误的重定位形式均不能充当这条边的证据。

最终 driver 的 SHA 为 `4ba0df5c65159714fec9f30b39221c8f3c2dc2a17a70d85e68f0b8260e76a651`。对首轮 `c0c63fb0…` 对象的[本地只读复测](evidence/route-a-platform-20261124/callback-matcher-v2-recheck.json)通过，报告 SHA 为 `f0b94bbbb04cf3cd3ce404e89e6e919a302fe4f16dcefc836f1d3f169aaaa46a`。它识别两处有 relocation 依据的 hook 调用及 boot resume，并拒绝 11 种内存变异，包括错边、错误或窄化的寄存器、跳过参数、目标寄存器覆盖与额外入边。这次复测没有重新编译或链接，首轮报告继续为 `failed`。

### callback-attempt-002：新的实际编译与有界代码检查通过

第二次尝试使用独立的 `callback-driver-v2` 与全新输出目录，于 UTC **2026-11-23T20:45:00Z** 完成，即北京时间 **2026-11-24 04:45:00**。原始报告的状态为 `kernel_callback_built`，五个子进程全部退出 `0`，生成代码检查 `passed=true`。完整结果见 [callback 汇总](evidence/route-a-kernel-callback-20261124.json)。

| 本轮记录 / 产物 | 字节数 | SHA-256 |
| --- | ---: | --- |
| [callback-attempt-002/report.json](evidence/route-a-platform-20261124/callback-attempt-002/report.json) | 182,661 | `b358db0ec1087a80fcfc447d5fd128ed0630bf2eeb79b346e4be73a84d263432` |
| 仓库外的 `callback-attempt-002/replacement/cpu.o` | 123,440 | `c555d97897615fb786d375f5510906fb52a7a4102962ea09ad3ecf450a076d5d` |
| [callback-evidence.json](evidence/route-a-platform-20261124/callback-attempt-002/callback-evidence.json) | 14,060 | `abb30328dc42f67b62bac2192ffd2d6109c2beb1e6e2aa96821bd248d6ce3f1a` |

新对象为普通 ARM64、完整 subtype `0`、`MH_OBJECT`，`LC_BUILD_VERSION` 为 platform `2` / iOS 27.0。本轮实际生成代码再次确认 `0xcf0` 的 TRUE 调用、`0xd40 → 0xda0 → 0xda4` 的 FALSE 调用，以及 `0xcfc` 指向 `_arm_init_cpu` 的 resume relocation。hook 为初值 NULL 的强数据定义。第二次独立输出的完整对象 SHA 与首轮不同；本轮证据绑定的是 `c555d978…`，没有拿首轮对象的本地复测替代新对象检查。

源文件、三个 hunk、配置及原 C recipe 的 ABI / 77 项 warning 参数保持不变。[本轮 compiler stderr](evidence/route-a-platform-20261124/callback-attempt-002/logs/cpu-compile.stderr)仍为 179,542 字节，独立核对得到 303 条 warning 行：2 条 driver warning、190 条 `-Wshadow-header`、111 条 `-Wunsafe-buffer-usage`，0 条 error；Clang 尾部仍报告 301 条。

[实际依赖清单](evidence/route-a-platform-20261124/callback-attempt-002/replacement/dependencies.json)记录 **395 个文件**，包括翻译单元本身。保护输入的 **415 条回执全部一致，对应 414 个唯一路径**；新 `cpu.c` 既单独受到保护，也列在依赖清单内，因此有两条回执。原 `cpu.c`、原 `cpu.o` 和原 baseline 均通过前后复核。

这次通过的是替换对象的真实编译和有界生成代码验收。报告仍明确 `full_control_flow_proven=false`、`full_instruction_set_audited=false`、`provider_kernel_link_verified=false`；没有启用 `platform-sleep=1`，没有应用整份 Sheng sleep patch，也没有验证睡眠恢复、板级唤醒源或 OS 启动。独立平台链接继续使用自己的实际结果和资格字段。

### 复现 callback 与替换链接

下列名字均使用新的 replay 目录。带 callback 的 producer / linker 使用同一含 Capstone 5.0.6 的 Python；冻结目录需保留四个脚本、配置、patch、许可证及实际报告引用的文件。

```sh
/work/route-a-venv/bin/python -I \
  "$ROUTE_A_SOURCE/scripts/build_route_a_kernel_callback.py" \
  --kernel-dir /work/route-a-continue-20261123/kernel-build \
  --toolchain-work /work/route-a-continue-20261123/toolchain-work \
  --output "$ROUTE_A_PLATFORM/callback-replay-001"

/work/route-a-venv/bin/python -I \
  "$ROUTE_A_SOURCE/scripts/link_route_a_platform.py" \
  --kernel-dir /work/route-a-continue-20261123/kernel-build \
  --toolchain-work /work/route-a-continue-20261123/toolchain-work \
  --platform-report "$ROUTE_A_PLATFORM/attempt-002/report.json" \
  --kernel-callback-report "$ROUTE_A_PLATFORM/callback-replay-001/report.json" \
  --output "$ROUTE_A_PLATFORM/link-replay-002"
```

consumer 逐 token 重算 C recipe，并用实际对象字节重新运行有界生成代码检查。原 baseline 的完整 SHA 通过后，新的 `inputs/platform-link.filelist` 才替换唯一 `cpu.o`；其余 1,070 个原链接对象保持不变。实际 map 必须证明替换对象进入、旧对象未进入，hook 与 `_ml_arm_sleep` 来自新对象，两个 archive 的成员与 constructors 照常验收。`kernel_callback_built`、`platform_link_compatible` 与睡眠 / OS boot 的资格分别判定。

## 新平台候选的限定编码审计

新增审计针对 `link-attempt-004` 的**同一个实际候选文件**，同时固定其路径、21,942,456 B 大小、`46eff436…bfe39f1b` 摘要和成功链接报告 `738a7af1…4feff7c`。完整记录见[审计摘要](evidence/route-a-platform-kernel-audit-20261124.json)、[原始 audit.json](evidence/route-a-platform-kernel-audit-20261124/audit.json)与[执行来源清单](evidence/route-a-platform-kernel-audit-20261124/source-manifest.json)。前后读取均指这一份候选，未推断额外的 CTF 或 `.noctf` 伴随构建。

| 检查 | 实际结果 |
| --- | --- |
| 声明为指令的候选范围 | 3 段、8,900,600 B，共 2,225,150 个四字节字；这些字节数不是整文件大小 |
| 原始 Armv8.3 PAuth 分类器的非 HINT 形式 | 0 命中 |
| 既有精确 POE2 TCHANGEF / TCHANGEB 分类器 | 0 命中 |
| 兼容 HINT 类编码 | 181 个 XPACLRI；逐项位置与上下文保留 |
| `llvm-nm` 未定义符号 | 0，原 stdout 为空 |
| `LC_DATA_IN_CODE` | 0 项，因此本次排除数据字节与字对齐扩展均为 0 |
| 输入复核 | 12 项审计源、报告、候选和工具身份全部一致，候选前后 SHA 相同 |
| 审计状态 | `completed`，`limited_checks_passed=true`，退出码 0 |

原始审计报告为 21,686 B，SHA `61bdea1cf7cb5f66e4afc407c58626ad6b96cf960b8d4f09e620de3c5dab17bd`。三个分类器保持与前次通用候选审计相同的固定字节；新的 adapter 单独记录来源，并要求 Python `-I`、禁用 `-O` / `-OO`、使用 Capstone 5.0.6。所有命中均写入 [encoding-findings.jsonl](evidence/route-a-platform-kernel-audit-20261124/encoding-findings.jsonl)，工具命令、版本、输出与实际 Mach-O 几何一并保留。

新 adapter 还纠正了旧脚本对 parser 数据区字段的解释：`excluded_data_ranges` 是 `(offset, length)`，应按 `length` 求和，并将整字排除带来的对齐扩展单列。旧通用候选和本次候选都没有 DIC 项，所以旧记录的零值不受影响；旧脚本和报告未改写。

复跑本次保留输入时，输出须为新目录：

```sh
/work/route-a-venv/bin/python -I \
  "$ROUTE_A_SOURCE/docs/evidence/route-a-platform-kernel-audit-20261124/audit.py" \
  --candidate "$ROUTE_A_PLATFORM/link-attempt-004/mach.platform-link-probe.unstripped.noctf" \
  --expected-sha256 46eff436250d905e9f3aec59dbcc8c04d594e614e790860236917c7cbfe39f1b \
  --expected-bytes 21942456 \
  --link-report "$ROUTE_A_PLATFORM/link-attempt-004/report.json" \
  --expected-link-report-sha256 738a7af11b32c08d0a4261611ba69f325d5a29bf424791b18e98879864feff7c \
  --report-dir "$ROUTE_A_PLATFORM/kernel-audit-replay-001"
```

该结果的范围是保留规则覆盖的编码统计。候选范围标志、Capstone 解码及邻近符号都不能证明实际执行或可达性；未匹配的字也没有获得 A77 兼容证明。完整指令特性、系统寄存器、loader、板级设备及 sleep / OS boot 继续保持未验证状态。

## 仓库回归

[09e02e6](https://github.com/cyjin-yl/UniXNU-tb371fc/commit/09e02e6436aa39a945819bc1be0f9c57d6d6f8d7) 的 [CI](https://github.com/cyjin-yl/UniXNU-tb371fc/actions/runs/45264914874) 实际通过 **267 项回归、0 跳过**，原 229 份源码／许可证摘要不变，独立源码准备作业成功。包含 13 项 provider、9 项 callback producer 与 35 项 linker 专项检查。[CI 记录](evidence/route-a-platform-validation-20261124.json)保留前序 249、264、266 项运行及这次结果，与真实 compiler / linker 报告分开保存；合成 Mach-O、模拟 linker 和有界指令测试的范围分别注明。

## 当前资格与后续门槛

| 层次 | 本记录的状态 |
| --- | --- |
| 两个公开 provider 对真实 XNU 12377 头文件的编译 | 已实际成功，保留 `-Werror` |
| 普通 ARM64 / iOS 27.0 对象及对应归档成员 | 已实际检查通过 |
| 声明的保护输入前后摘要 | 一致 |
| baseline 重放 | 已逐字节重现，完整 SHA 一致 |
| kernel callback 的实际 C 编译与有界生成代码检查 | `callback-attempt-002` 通过；真实调用路径运行尚未验证 |
| 两个 provider 与 callback 的实际内核链接 | `link-attempt-004` 通过；实际成员、constructor、metaclass 与符号验收成功 |
| 新候选的限定 PAuth / POE2 编码统计 | 已完成 2,225,150 个候选字；覆盖规则内的非 HINT PAuth / 精确 POE2 命中均为 0 |
| 完整 TB371FC board/profile、crypto / pthread / 其他 archive 闭包 | 未完成 |
| provider 全部指令、寄存器及运行时接口在 A77 上的兼容性 | 未完成整体验证 |
| ADT、GIC / timer、CPU 启动、电源、存储、显示与 GPU 的板级运行 | 未验证 |
| 设备内核启动、Darwin 进程、iPadOS 27 桌面 | 未验证 |
| macOS 27 | 仍需独立工作链与验证 |

本次完成了两份公开平台组件的实际编译、callback 接线对象的真实 C 编译，以及它们与普通 ARM64 内核的独立链接。下一步仍需完成完整 provider 选择、板级配置、加载与 prelink 路径以及实际设备启动验证。相关总路线见 [ROADMAP.md](../ROADMAP.md)，用户空间与共享缓存工作保持各自证据边界。
