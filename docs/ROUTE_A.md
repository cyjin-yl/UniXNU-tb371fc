# 路线 A：在 TB371FC 上推进 27 代系统原生执行

更新：2026-11-23。

后续集成已完成 162 项主机回归和 71 项通用内核源码补丁准备，具体范围见 [最新验证汇总](evidence/route-a-continuation-validation-20261123.json) 与 [内核准备报告](ROUTE_A_KERNEL_BUILD.md)。以下首轮实机和 Apple 输入结果保留原有范围。

首轮成果（提交 `eb2ccfa`）的合并验证为 **120 项测试全部通过，包含 9 项提取真实 pager C 函数的主机测试，没有跳过项**；原始 229 份源码／许可证摘要及设备目录检查也通过。完整口径见 [验证汇总](evidence/route-a-validation-20261123.json)。

目标设备是 Lenovo TB371FC、Snapdragon 870、Adreno 650。采用离线转换 arm64e 程序、尽量保留等长 AArch64 指令、让 CPU 直接执行的路线。第一阶段选用 iPadOS 27；macOS 27 保留为后续目标，两者的用户空间、内核接口和设备服务需要分别验证。

## 当前结果和边界

| 项目 | 本分支状态 |
| --- | --- |
| PAuth 指令解码及等长转换 | 已实现；不支持的形式明确拒绝 |
| Mach-O 结构和代码／数据边界 | 已实现；只允许已验证的候选范围进入改写 |
| 单文件 CFG 分析、改写和签名页面重算 | 已实现；真实 27.0.1 `launchd` / `dyld` 分别改写 2,409 / 5,385 处，150 / 347 个签名代码页独立校验通过 |
| 共享缓存完整性和改写检查 | 已实现；绑定所有子缓存、结果数组、规则和分析器版本 |
| TB371FC 原生合成函数测试 | **23/23 组通过，46 次独立子进程执行** |
| 完整 Cortex-A77 指令集兼容 | 未验证；PAuth 转换成功不能覆盖其他 ISA 差异 |
| iPadOS 27 完整共享缓存和用户空间 | 尚未完成整包转换与运行验证 |
| 27 的 dyld／内核 pager／普通指针 ABI | pager 补丁已验证应用／反向恢复及关键 C 函数；尚未完成内核集成 |
| iPadOS 27 / macOS 27 启动 | **未验证** |
| 27 的 GPU、触摸、电源和其他外设 | **未验证** |

测试结果见 [原生验证记录](evidence/route-a-native-20261123.json)。报告只保留设备型号、CPU 能力及合成测试结果，不包含设备序列号、账号、私有文件或 Apple 系统二进制。

另用独立 GNU Binutils 2.44 汇编器核对了 **54/54 条原始编码和 45/45 条普通指令替换编码**；替换编码全部在基础 `armv8-a` 目标下生成。9 条设计上拒绝转换的向量只核对原始编码，不把汇编器检查当作语义或拒绝策略的证明。见 [独立汇编器验证记录](evidence/route-a-assembler-20261123.json)。

上游 V135 的 iPadOS 17.7.11 桌面、触摸和 GPU 记录是硬件移植参考。它不是本分支的 27 系统测试结果，也不能证明 17 的保留内核可以直接加载 27 的用户空间。具体差异见 [内核与加载器缺口](ROUTE_A_KERNEL_GAPS.md)。

真实输入来自官方 `27.0.1 / 24A446` IPSW 的 OS 卷，提取来源、工具补丁和 SHA-256 见 [提取方法](ROUTE_A_EXTRACTION.md) 与 [记录](evidence/route-a-extraction-20261123.json)。两份输出均保持文件长度，记录明确 `hardware_tested=false`、`os_boot_verified=false`。这次没有在 Android 上尝试执行这些 Darwin 程序。

| 真实输入 | 文件长度 | 指令改写数 | 独立验证的 4 KiB 签名页 | 输出 cdhash |
| --- | ---: | ---: | ---: | --- |
| [launchd 记录](evidence/route-a-launchd-27.0.1-20261123.json) | 639,376 | 2,409 | 150 | `66046a8149547198b0e269952c20bad26cb3484b` |
| [dyld 记录](evidence/route-a-dyld-27.0.1-20261123.json) | 1,447,088 | 5,385 | 347 | `ba62a408cfa8b123e95038f5e31d955019546e06` |

两者的原 cdhash 均在本次 IPSW 的原始信任缓存中找到；新条目保留原 `hash_type=2`、`flags=0`、`constraint_category=2`。条目信息已准备，`owner_trust_bundle_installed=false`。当前输入实际使用 `trcs`（Cryptex OS）IM4P 类型；工具只允许明确的 `trst` / `trcs`，解包后仍严格要求 v2、24 字节模块头和 24 字节 entry。类型及布局依据见 Apple 的 [TypesConfig.h](https://github.com/apple-oss-distributions/xnu/blob/42e220869062b56f8d7d0726fd4c88954f87902c/EXTERNAL_HEADERS/TrustCache/TypesConfig.h) 与 [RawTypes.h](https://github.com/apple-oss-distributions/xnu/blob/42e220869062b56f8d7d0726fd4c88954f87902c/EXTERNAL_HEADERS/TrustCache/RawTypes.h)。

内核补丁覆盖 v3、v5、分块 v5 普通指针写回及 dyld pager，并修复 dispatcher 丢弃 fixup 失败返回值的问题。参见 [补丁实现和验证](ROUTE_A_PLAIN_AUTH_PATCH.md)。这些测试不等于完整 XNU 已编译或已经在设备启动。

### dyld 仍需要非 TPRO 运行路径

当前真实 `dyld` 含 236 条 FEAT_S1POE2 指令：116 条 `TCHANGEF`、120 条 `TCHANGEB`。旧解码器不识别这两个 opcode，使严格 CFG 遍历及调用者证明失败。按固定 LLVM 定义补齐解码后，未证明的 PAuth 候选由 863 降到 0；没有新增人工地址根、改变 strict-walk 规则或把数据算作代码。

转换产物保留这 236 条原始指令，并报告 `native_on_a77=false`、`runtime_dispatch_verified=false`。A77 不能直接执行它们；还需审计 Apple 专用系统寄存器访问以及其他非 PAuth ISA 要求。

实际二进制已确认若干正规的非 TPRO 分支：`MemoryManager` 与保护栈策略查询内核传入的 apple 向量键 `dyld_hw_tpro`；键不存在时可以走普通 callback / 非保护栈路径。这是 Apple 启动参数向量，不是 Android 普通 shell 环境。**不能用 `dyld_hw_tpro=0` 代表关闭，因为当前检查只看键是否存在。** 部分构造和分流已核验，但早期启动、该键的注入路径及全部 236 处的可达性仍待确认。证据和未完成范围见 [TPRO 分流记录](evidence/route-a-dyld-tpro-20261123.json)。

## 为什么先选这条路线

当前平板用户态的 HWCAP 为 `0x119fff`，PACA/PACG 均未公布；实机原生测试也在这一环境执行。路线 A 为转换后的程序约定普通指针 ABI：签名、认证和剥离 PAC 的操作需要与所有指针生产者、加载器及内核协同处理。

在这个约定成立时，认证跳转、调用、返回可以改为普通跳转、调用和返回，部分认证加载可以改为普通加载，签名／认证指令可以省去。已接受的转换保持每条 4 字节，保留原有代码地址布局。这避免了全系统动态指令翻译这一层，但**还没有应用性能、GPU 帧率或整机功耗基准**，不能给出“损耗百分之几”。

普通指针 ABI 不保留 PAC 的安全认证能力。`XPAC → NOP` 只在输入指针已由全链路保证为普通指针时成立，不是通用的 PAC 去除算法。只改指令而继续让加载器生成带 PAC 的指针，不能正常工作。

## 目标版本及来源

目标记录位于 [route-a-targets.json](../configs/route-a-targets.json)，来源固定为 UniXNU commit `8542980d02b4d2cc5c32ee3542de1760b2562aac`：

| 目标 | 版本／构建 | profile 设备 | 当前定位 |
| --- | --- | --- | --- |
| iPadOS | 27.0.1 / 24A446 | iPad17,3 / j820ap | 首个用户空间分析目标 |
| macOS | 27.3 / 26C5035r | Mac17,11 / k114cap | 后续实验目标 |

profile 内的 Apple 设备身份用于定位恢复镜像，不会将 TB371FC 变成该 Apple 硬件。`--profile` 也不是“已兼容”的开关。传入 `--build-manifest` 会校验版本、构建、产品和设备类别，并记录清单 SHA-256；单凭清单不能证明任意输入文件确实来自对应 IPSW，报告明确保留 `binary_membership_verified=false`。

## 实现组成

| 路径 | 作用 |
| --- | --- |
| `scripts/route_a.py` | 目标查询、单文件审计和暂存改写 CLI |
| `scripts/arm64_lowering/instructions.py` | 精确 PAuth 解码、普通指针转换策略和拒绝原因 |
| `scripts/arm64_lowering/macho.py` | 严格 Mach-O 解析及代码候选范围 |
| `scripts/arm64_lowering/pipeline.py` | 连接 CFG 改写和独立代码页签名复核 |
| `scripts/arm64_lowering/proof.py` | 共享缓存 proof 的输入、规则、覆盖和 edit 校验 |
| `scripts/route_a_zeta/` | 许可明确、固定来源的 CFG／缓存／签名工具及本地适配 |
| `scripts/route_a_native_probe.py` | 23 组原生函数正确性测试 |
| `scripts/route_a_cache_flush.S` | 无 libc 依赖的 AArch64 指令缓存同步辅助库 |
| `tests/test_route_a_*.py` | 解析、解码、进程隔离、CFG、签名和 proof 回归验证 |

复用代码来自 [UniXNU-zeta](https://github.com/none24smu/UniXNU-zeta/tree/eb489285a1d9153872f00c93ebb519a269b249b5)，commit、原始 SHA-256 和长度记录在 [来源清单](../upstream/route-a-sources.json)，保留 BSD-2-Clause-Patent 许可证。具体适配见 [工具说明](../scripts/route_a_zeta/README.md)。

### 当前接受的指令转换

- 普通指针约定下的寄存器 PAC／AUT／XPAC 转换为 NOP。
- HINT 空间的 PAC／AUT 指令保留原字；在没有相应能力的 CPU 上按 HINT 处理。
- BRAA／BRAB／BRAAZ／BRABZ 转为 BR，认证调用转为 BLR，RETAA／RETAB 转为 RET。
- 能用一条普通 LDR／LDUR 表达的 LDRAA／LDRAB，保留偏移及基址写回语义。

PACGA、异常返回认证、无法单指令表达的加载偏移，以及有约束不可预测寄存器重叠的形式，目前明确拒绝。后续要扩展这些形式，需要先确定对应的运行时语义，再实现独立验证；不以返回常数或近似哈希代替。

### 改写前后的检查

Mach-O 解析器检查命令、段、节、文件和虚拟地址边界；只让可执行且标为指令的节进入候选集合，排除 `LC_DATA_IN_CODE` 涵盖的完整指令字。FAT、fileset、加密输入和未知必需命令不被当作普通薄用户程序处理。扫描命中只叫“候选”，不等于控制流已证实为代码。

单文件改写使用 CFG 区分代码和数据，并再次确认每个 edit 的范围、对齐和唯一性。改写前后独立验证 SHA-256 CodeDirectory 的代码页哈希，保持文件长度，生成新的 cdhash。默认保留原有 platform/runtime 字段；CodeDirectory 的 platform 字节不是“目标系统版本”。代码页哈希正确不代表 Apple 签名或系统信任策略已经满足。

共享缓存 proof 绑定有序主缓存／子缓存集合、UUID、大小、SHA-256、image 清单、规则源码、Capstone／NumPy／LLVM 版本和每份 NPZ 结果。只分析部分 image、遗漏候选、残留 unproven/unlowerable、重复或越界 edit、原字不匹配、伪造数据跳过等情况都会拒绝。prover 的 `--only` 是诊断模式，返回非零，不会获得完整改写资格。

## 复现开发验证

完整、包含真实 pager C 的检查步骤见 [开发指南](../DEVELOPMENT.md)。以下是工具使用示例；没有设置已验证的 `ROUTE_A_XNU_PREPARED_DIR` 时，C 测试会跳过。

Python 3.11+、NumPy 和 Capstone 是完整检查入口的依赖；遇到 Capstone 无法识别的指令时，上游 CFG 工具还会调用 `llvm-mc`。在约定的开发容器中运行：

```sh
python3 -m venv /work/route-a-venv
/work/route-a-venv/bin/python -m pip install -r requirements-route-a.txt
/work/route-a-venv/bin/python scripts/check_repository.py
/work/route-a-venv/bin/python scripts/check_catalog.py
/work/route-a-venv/bin/python scripts/check_route_a.py
/work/route-a-venv/bin/python scripts/route_a.py targets
```

`check_route_a.py` 运行合成输入测试。它不连接设备，也不刷写或启动操作系统。CI 另用 `prepare_route_a_xnu.py` 下载并校验四个固定版本的公开 XNU 源文件，验证补丁应用／反向恢复，再执行从修改后源码提取的 C 函数测试；不会构建完整系统。

如环境中有 `aarch64-linux-gnu-as` 和 `aarch64-linux-gnu-objcopy`，可独立复核编码；此脚本不导入转换实现：

```sh
python3 scripts/route_a_checks/verify_fixture.py \
  --fixture tests/fixtures/route_a_instruction_vectors.json \
  --out /work/route-a-oracle
```

### 审计与暂存单文件

输入需由开发者从对应官方恢复镜像取得，放在仓库外或已忽略的工作目录。以下输出路径必须是新文件：

```sh
python3 scripts/route_a.py audit \
  --profile ipados27 \
  --build-manifest /work/input/BuildManifest.plist \
  --input /work/input/launchd \
  --report /work/results/launchd-audit.json

python3 scripts/route_a.py rewrite \
  --profile ipados27 \
  --build-manifest /work/input/BuildManifest.plist \
  --input /work/input/launchd \
  --output /work/results/launchd.arm64 \
  --report /work/results/launchd-rewrite.json \
  --plain-pointer-abi
```

审计会列出结构、候选指令和当前不支持的形式。改写输出标记为 `staged_userland_binary`；它还不是可部署的系统文件。加入 `--apple-trust-cache` 可从匹配的原始条目继承 hash type、flags 和 constraint category，生成新 cdhash 的条目信息；把该条目集成进匹配内核的 owner trust bundle 是下一步工作。

### 复现平板原生测试

在 AArch64 交叉工具链容器中构建缓存同步辅助库：

```sh
aarch64-linux-gnu-as -o /work/flush.o scripts/route_a_cache_flush.S
aarch64-linux-gnu-ld -shared --hash-style=both -z separate-code \
  -z max-page-size=16384 -z noexecstack \
  -soname libroute_a_clear_cache.so \
  -o /work/libroute_a_clear_cache.so /work/flush.o
```

将 `scripts/route_a_native_probe.py`、`scripts/arm64_lowering/` 和辅助库放到平板独立测试目录，再运行：

```sh
python3 scripts/route_a_native_probe.py --run --timeout 2 \
  --cache-flush-library /absolute/path/libroute_a_clear_cache.so
```

测试不用 Apple 代码。每组普通基准函数和转换函数分别在子进程运行，使用 RW → 缓存同步 → RX 的内存权限流程；有超时和信号隔离。原始 PAC 指令只进入报告，不被执行。2026-11-23 的 23 组测试覆盖普通指针签名／认证消除、跳转／调用／返回、X30 调用目标、正负加载偏移、写回和 SP 基址。

## 接下来的集成顺序

持续更新的任务和验收条件见 [ROADMAP.md](../ROADMAP.md)。

1. 已取得并完成真实 27 的 `launchd`、`dyld` 及对应信任条目处理；继续取得完整共享缓存集合，保留镜像和提取工具来源，审计整包覆盖。
2. 建立完整共享缓存 proof，处理实际遇到的不可等长形式，并验证非 PAuth 的 Cortex-A77 ISA 要求及 CPU feature dispatch。
3. 对齐 XNU、dyld fixups、共享区和 dyld pager、4K／16K 页面处理以及代码签名／信任目录，让普通指针约定覆盖所有生产者和消费者。
4. 在可复现、可恢复的 TB371FC 启动链上取得内核 → `launchd` → 图形用户空间证据，再验证 Adreno 650 的 Metal 前端、显示和触摸。
5. 验收目标包括正确分辨率和刷新率、GPU、笔、键盘、Wi-Fi、音频、相机、USB、存储、充电、电池及休眠唤醒。进入桌面只算中间里程碑。

性能评估安排在系统能够稳定运行以后，以相同场景的帧时间、CPU 开销、内存压力和功耗对比。当前原生函数测试是正确性证据，不是整机性能测量。
