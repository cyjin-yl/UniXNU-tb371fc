# Route A：固定源 CoreCrypto 的完整表适配与可复现链路

本页描述一条独立、显式的普通 ARM64 构建和 QEMU 诊断路径。它针对固定 XNU 12377.121.6 的 `crypto_functions` 合同，补齐旧 provider 未赋值的 13 个槽，并验证真实 provider、POST、PRNG 和 XNU 消费者。构建结果、实际运行、后续 XNU 初始化、Darwin 用户态和 TB371FC 硬件资格分别记录。

脚本和测试 fixture 本身不会产生运行时成功证据。新的正负运行结果应以该次脚本身份、完整输入、原始报告和实际进程收据为准。旧实验 006 的 `ctx_size=240`、007 的 POST 返回 0 和 008 的 POST 返回非零仍只有各自原始范围；008 停在 POST 返回处，不能当作本页要求的实际拒绝路径。

## 输入与来源

完整引用见 [sources.json](../scripts/route_a_corecrypto/sources.json)。provider 来源是固定的第三方快照 `ONLYA/corecrypto-2023`，commit `11fba65b12d8830630e248dfa8344caf8b065f26`，源归档 SHA-256 为 `fd04cb46cb733fdd8e6334702081a33b202ae7645140f59fa55b7d47de7e688f`。本链路没有把它认证为 Apple 发布归档，也没有产生密码模块认证结论。源归档及其派生二进制由操作者在仓库外提供、保存。

XNU 启动钩子从 [Apple 固定原始 prng_random.c](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/osfmk/prng/prng_random.c) 重建：原始文件为 15,271 字节、SHA-256 `584dc0e00b65096c426697b66c029fb0aefe1769e78905d0eafefeb8203a7153`；应用 [UniXNU 8542980d 的 source-corecrypto14-bootstrap.patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/source-corecrypto14-bootstrap.patch)，补丁为 5,107 字节、SHA-256 `7f678a620312094e5a31fb98659a01ba0e6e6318658e329feb16e4e006f614dd`。控制器以 `git show` 取得指定原始 commit，仅接受精确单文件追加 hunk，核对全部上下文与行数，再要求重建结果为 `cc677a1bd2effd70dd55af8d907bfbd37594f0a9a1679e4a55875fec705d9a5f`。准备树中的文件只作逐字节见证。原始版权头和补丁的 BSD-2-Clause-Patent 许可证随私有构建收据保留。

本地原创内容包括 [adapter.h](../scripts/route_a_corecrypto/adapter.h)、[consumer_probe.h](../scripts/route_a_corecrypto/consumer_probe.h)、固定 [namespace.h](../scripts/route_a_corecrypto/namespace.h) 和用于核对上下文尺寸/对齐的 [abi_contract.h](../scripts/route_a_corecrypto/abi_contract.h)。它们不覆盖上游固定源清单中的已有代码。provider 的 POST、43 个原有赋值、注册和 PRNG 初始化顺序保持；适配插入点必须唯一，且不得覆盖已有槽。

无关 XNU 对象来自已识别的 retained platform link 输入。控制器检查固定平台报告、全部受保护输入、原始候选、链接文件列表和工具身份，仅重编本次启动钩子及 provider；因此本页不是从零编译整个 XNU 的声明。

## 56 槽的合同

固定表大小为 448 字节，即 56 个普通 64 位指针槽。旧 provider 赋值 43 项，以下 13 项由真实 provider 原语适配：

| 类别 | 补齐的字段 | 行为 |
| --- | --- | --- |
| 旧 digest final | `ccdigest_final_fn` | `void *` 输出的真实 thunk，调用 provider 的 `ccdigest_final` |
| 新 digest | `digest_ctx_size_fn`、`digest_init_fn`、`digest_update_fn`、`digest_final_fn`、`digest_fn` | 使用实际 digest descriptor、上下文尺寸和原语 |
| 新 HMAC | `hmac_ctx_size_fn`、`hmac_init_fn`、`hmac_update_fn`、`hmac_final_generate_fn`、`hmac_final_verify_fn`、`hmac_generate_fn`、`hmac_verify_fn` | 使用实际 HMAC 上下文、生成和常量时间比较 |

支持固定枚举的 MD5、SHA-1、SHA-256、SHA-384 和 SHA-512。`NONE` 或未知枚举会 panic；这里提供旧系统 ABI 的完整算法选择，不把 MD5/SHA-1 描述成新安全协议的推荐算法。上下文尺寸由真实 descriptor 计算，调用方必须提供非空且足够大的缓冲区。非空输入不得带空指针；长度 0 的输入或密钥允许空指针。

本桥接明确采用“非空前缀”输出合同：digest/HMAC 生成长度必须在 1 至原算法输出长度之间，越界或零长度生成请求会 panic，不能用零填充伪造更长输出。HMAC 验证对空、零长度或过长 tag 返回 false；有效长度使用真实 `cc_cmp_safe` 比较完整所请求前缀。final 后清理实际使用的上下文和临时完整结果。该行为必须同时与固定消费者源码及运行向量核对，不推断未公开版本的私有实现细节。

编译会对原 43 个赋值和新增 13 个函数指针分别执行真实 C 类型断言，启用不兼容指针的错误门槛。provider 与 XNU 消费者使用各自真实编译头文件输出 carrier record layouts，比较字段、类型、偏移、大小和对齐；仅规范化固定 namespace 引起的 `cc14_ccsha256_di`、`cc14_ccsha512_di` 两个字段名，任何其他差异都失败。64 个冲突符号由固定 namespace 重命名，归档必须无剩余内核外部符号冲突。

XNU 侧探针在真实 provider 成功返回后调用已发布的 `g_crypto_funcs`：检查所有 56 槽非空，逐个算法执行单次与流式 digest/HMAC、空输入与空密钥、截断输出、正确与错误 tag、越界 tag 拒绝和缓冲区哨兵；另执行长密钥 HMAC-SHA256 和旧 final 回调。每个新 final 和 final_verify 路径结束后，还检查实际使用的上下文区间全部归零，包括错误内容和空、零长度、过长 tag 的拒绝路径。期望输出在本机测试中用独立 `hashlib`/`hmac` 重新核验。只有整个消费者检查结束才写成功状态。它补充 provider 原有 POST，不代替 POST，也不提供空回调或假随机上下文大小。

## 构建与二次复现

使用 [build_route_a_corecrypto.py](../scripts/build_route_a_corecrypto.py)。所有编译、链接和 QEMU 任务必须置于操作者既有的 `agent-heavy` 前台持锁包装中，并沿用会话规定的内存、swap 和 CPU 限额。不要从另一个通道绕过资源准入。

输入目录要保留原 XNU `refer/xnu` Git 对象、固定编译 recipe、头文件和被识别的 retained link 对象。命令示意：

```sh
python3 scripts/build_route_a_corecrypto.py \
  --source-archive /private/inputs/source.tar.gz \
  --kernel-build /private/kernel-build \
  --compiler /private/toolchain/llvm/bin/clang-24 \
  --platform-report /private/platform-link/report.json \
  --loader-sources /private/loader-public-sources \
  --output /private/a02-build-001
```

输出目录必须是仓库外的新目录。源归档先做摘要、成员路径、链接/特殊文件和解压大小检查；固定 PBX target 必须解析出 529 个唯一 C 源文件。采用真实普通 ARM64/iOS 27 编译选项、`CC_USE_ASM=0`、串行编译，每个对象单独留下源码摘要、实际 argv、依赖文件、stdout/stderr 和对象身份。完整表 ABI 在 529 TU 编译前先检查。

每条命令在独立 session / process group 中运行。控制器在正常返回、超时和中断路径均回收直接子进程及本组被收养的后代，并在收据中记录退出后和清理后的组状态。直接子进程即使返回 0，只要进程组仍存在，这条命令仍判失败；清理成功不把它改称正常完成。失败的 Journal 不再启动下一条命令。二次复现对编译、归档、ABI 和链接等全部命令重新要求组已消失且退出收据一致，不能仅凭直接子进程 `reaped=true` 取得通过。

控制器固定 `SOURCE_DATE_EPOCH`、`ZERO_AR_DATE` 和时区，禁止展开日期时间宏，并用 Clang 的文件/调试前缀映射和固定 compilation directory 消除新目录名称；ld64 的 `oso_prefix` 仅移除本次新输出前缀。归档使用固定源码顺序和确定性模式。框架头的目录链接、实际文件、编译器资源头和每次编译真实消费的依赖均需已声明，结束再核身份。

链接保留平台命令，仅替换本次 `prng_random.o`、加入 provider 归档和独立输出/调试路径。封装只处理两个原有 static-if 测试 key 的 10 个已识别 B/NOP 状态，再计算真实 POST HMAC；它不跳过自检。内核必须通过原普通 ARM64 Mach-O 严格检查；固定 DarwinBoot 原始 C 提取负责再次核对段复制、零填充、边界哨兵和 boot_args ABI。

重复运行同一命令，但把输出改为另一个新目录 `a02-build-002`。这会实际重编全部 529 TU 和启动钩子，重新链接、封装和加载。然后比较：

```sh
python3 scripts/build_route_a_corecrypto.py \
  --compare-builds /private/a02-build-001/report.json /private/a02-build-002/report.json \
  --output /private/a02-reproduction-001
```

比较器要求不同输出目录、两个通过的完整编译收据、相同源输入和确定性环境，并逐项重读 529 个对象、启动钩子对象、归档、封装内核和加载镜像。它核对原平台报告中的 `kernel_callback.filelist_replacement`，从固定原始列表重放唯一的 CPU 对象替换，再验证当前构建允许的 bootstrap / PACGA 对象替换。生成的 `platform.filelist` 原始字节在链接前后受保护；比较不同输出根时，只对这个经过独立重构的列表按有序成员路径和身份规范化，保留实际文件的原始 hash。

ABI 门槛重新读取两侧真实编译器布局输出，核对全部 carrier 和 `abi.json`。封存门槛从本次未封存链接产物重放固定 static-if 改写与 POST HMAC，要求结果逐字节等于本次封存内核。输出中性列表漂移、未执行/未回收的命令、ABI 日志或 seal 收据漂移均不能以相同最终产物取得通过。`build_verified` 只覆盖类型、布局、构建和装载，`runtime_provider_verified` 仍为 false。

## 显式接入 PACGA 对象

`--pacga-stage-report /private/pacga-stage/stage-report.json` 可选地接入已通过真实 `sleh.c` 编译的普通 ARM64 对象。两次 fresh CoreCrypto 构建应选择同一份固定 stage 收据；原始 retained XNU 对象、这个 PACGA 对象及其来源仍属于被绑定的输入，不能据此宣称重新编译了完整 XNU。

接入首先验证 stage 的成功且已回收的编译/依赖发现命令、固定 clang-24、源文件、完整 recipe、helper/patch/ABI、实际头依赖闭合和对象身份。准备后的 `sleh.c` 必须等于固定 XNU `ac9718fb1af618d5ce8678d0dc6e8a58f252216f` 原始文件的 SHA-256；其 `sleh.o.json` 也采用独立记录的固定身份。接入器独立重放固定 PACGA patch 的两个追加 hunk，逐项验证文件名、原始上下文、行号和行数，不允许模糊匹配；实际 stage TU 必须逐字节等于重建结果。只修改 TU 并同步更新自报 hash、依赖收据仍会被拒绝。两个生产脚本须匹配 `PACGA_PINS` 中的独立文件身份：`build_route_a_pacga.py` 采用新增有界 `--compile-timeout` 的固定生产脚本（默认 300 秒、可选整数 1–900 秒，仅作用于正式编译，报告绑定实际选择），`route_a_pacga_probe/run.py` 采用已合入 `e766bca5` 的执行器。正式 `<sys/random.h>` 声明修复要求 fresh stage 和新的 patch / descriptor 身份；旧失败收据不改写，也不改称来自新提交。所有实际生产源文件仍须存在并通过内容与 generation 重验。

完成语义检查并登记所有受保护输入后，接入器再次对 stage 原始工具及文件的 hash 和 generation 复核，避免中途发生的变更被登记为新 baseline。链接只替换原列表中恰好一个、且旧对象 hash 与固定平台 inventory 相符的 `sleh.o`。新对象必须包含普通 ARM64 Mach-O 元数据和准确的非代码 PACGA 描述符。随后执行全新链接、static-if 改写和 HMAC 封存，最后对新封存内核再次核对描述符和整文件绑定。现有已封存映像不参与修改。

```sh
python3 scripts/build_route_a_corecrypto.py \
  --source-archive /private/corecrypto.tar.gz \
  --kernel-build /private/retained-kernel-build \
  --compiler /private/pinned-toolchain/clang-24 \
  --platform-report /private/pinned-platform/report.json \
  --loader-sources /private/loader-public-sources \
  --pacga-stage-report /private/pacga-stage/stage-report.json \
  --output /private/a02-pacga-build-001
```

`pacga_runtime` 在这里表示新内核的来源和 ABI 描述符绑定；其 `runtime_boot_verified` 保持 false。真实随机密钥初始化、XNU 中的 SVC 分派和 Darwin 进程执行仍需运行时证据。

## 实际运行的正负门槛

[probe_route_a_corecrypto.py](../scripts/probe_route_a_corecrypto.py) 读取通过的构建收据，重新核对内核、加载镜像、实际段与零填充、表偏移和启动符号。固定 replay seed、QEMU virt/GICv3、Cortex-A76、512 MiB/单核、62.5 MHz ADT、原 command line 和固定一纳秒指令计时。最长 60 秒；每个日志限 16 MiB。无磁盘、网络设备或物理平板操作。

```sh
python3 scripts/probe_route_a_corecrypto.py \
  --build-report /private/a02-build-001/report.json \
  --seed-file /private/frozen-seed.bin \
  --mode positive --output /private/a02-positive-001

python3 scripts/probe_route_a_corecrypto.py \
  --build-report /private/a02-build-001/report.json \
  --seed-file /private/frozen-seed.bin \
  --mode negative-post --output /private/a02-negative-001
```

所有 PC 来自实际 candidate 的唯一强 section symbol、可执行段和有界函数体；不接受外部给定地址。先在密钥生成前用硬断点加单步验证原 `__start` 分支。之后每次观察先按 `p` 请求读取 PC / CPSR，再只读取该语义所需的寄存器；不请求全量 `g` 包，也不保留停止回复附带的寄存器字段。`read_random` 返回观察仅读取 PC / CPSR，不读取密钥材料或可能残留材料的数据寄存器。

正例动态寻找 provider 到 POST 的真实 BL 和紧随的 CBNZ，要求 W0=0。随后停在真实 `vm_map_store_crypto_init` 入口，捕获 LR 并绑定其实际 BL/BLR 调用；继续到该消费者调用 `crypto_random_kmem_ctx_size` 的返回点。此时要求表指针及该槽目标与真实符号相同、全部槽非空、`crypto_init=1`、`prng_ready=1`、bootstrap status=0，以及独立消费者检查完成。继续到整个 `vm_map_store_crypto_init` 返回，再观察真实 `bsd_init` 入口或下一次 panic。

负例从当前正例输入复制出独立文件，只翻转存储 POST HMAC 的一位，并在加载镜像的对应位置作同一位改变；代码字节不变。要求真实 POST 返回非零，继续走到真实 `DebuggerTrapWithState(db_op=3)`，核对 caller 是 provider 中实际 BL panic 的返回地址、格式是有界的 POST 失败文本，并重新核对 table/init/PRNG/consumer status 未发布。停在 POST 返回处看见零状态不足以通过该门槛。

读取仅限固定符号声明的状态单元、448 字节表、实际指令，以及最多两个 512 字节的 file-backed 静态字符串。`prng_ready` 按固定源的完整 32 位 `int` 读取。不会追栈、`va_list` 或任意 guest 指针。所有请求在发送前检查同一 deadline；门槛所需的读取遇到短包、错误或截断，以及异常退出、清理失败或输入变更，均不能保留成功资格。完整消费者返回后若出现后续 panic，其附加文本读取状态单独保留，不扩大此前 provider 层的资格。QEMU 是独立拥有的进程组，所有结束路径终止并回收。

即使完整 provider 层通过，后续 `bsd_init`、用户态、非 TPRO 合同、SVC/PACGA 运行时和实际板级启动仍需各自证据。指令计时实验不证明真实设备性能。

## 本机回归入口

```sh
python3 -m unittest discover -s tests -p test_route_a_corecrypto.py -v
```

这些测试覆盖独立已知向量、补丁精确重建、唯一插入点、类型布局差异保留、真实 BL/BLR 解码、符号与代码范围、框架链接改向、截止时间前拒发、短读保真和失败撤销资格。进程回归实际派生子孙进程，分别验证直接子进程退出 0 后遗留工作进程、超时和 SIGTERM 中断，以及回收后拒绝继续执行；遗留工作进程还会忽略 SIGTERM，要求有界 SIGKILL 和 wait 回收。fixture 不会启动 QEMU，也不能代替两次真实构建或运行时正负例。
