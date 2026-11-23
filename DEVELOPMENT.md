# 开发指南

本仓库的当前工作是 TB371FC 的路线 A：离线转换 arm64e 用户空间，再以普通 arm64 指针 ABI 推进 iPadOS 27 原生运行。已完成内容见 [证据索引](docs/evidence/README.md)，下一步见 [ROADMAP.md](ROADMAP.md)。

## 1. 获取源码

```sh
git clone https://github.com/cyjin-yl/UniXNU-tb371fc.git
cd UniXNU-tb371fc
git status --short --branch
```

`main` 是成果与文档入口；`route-a/arm64e-27` 用于集成。开始新任务时从最新提交建立独立工作分支。上游设备源码来自 `xiuyityer/UniXNU-tb371fc`；不要把其中的 V135 结果算作本仓库的 27 实测。

## 2. 开发环境

主机检查需要 Python 3.11+、Git、能生成并加载本机共享库的 C 编译器，以及 [requirements-route-a.txt](requirements-route-a.txt) 中的依赖。建议在独立 Linux 开发容器里运行。准备固定 XNU 源文件的步骤需要访问公开的 GitHub raw 文件；其余单元测试使用合成输入及已准备源码。

真实 Mach-O / 共享缓存分析还需要 LLVM 的 `llvm-mc`；独立指令编码复核需要 GNU AArch64 binutils。这些检查工具与完整 XNU 构建工具链不同，安装普通 LLVM 不代表已经具备完整内核构建环境。

大体积镜像、缓存、构建树和结果放在仓库外。以下示例使用仓库旁的独立工作目录；路径变量不改变系统环境变量：

```sh
ROUTE_A_WORK="$(mktemp -d ../route-a-work.XXXXXXXX)"
ROUTE_A_WORK="$(cd "$ROUTE_A_WORK" && pwd)"
python3 -m venv "$ROUTE_A_WORK/venv"
"$ROUTE_A_WORK/venv/bin/python" -m pip install -r requirements-route-a.txt
```

## 3. 完整主机验证

从仓库根目录执行：

```sh
"$ROUTE_A_WORK/venv/bin/python" scripts/check_repository.py
"$ROUTE_A_WORK/venv/bin/python" scripts/check_catalog.py

"$ROUTE_A_WORK/venv/bin/python" scripts/prepare_route_a_xnu.py \
  --output "$ROUTE_A_WORK/xnu-pager"

ROUTE_A_XNU_PREPARED_DIR="$ROUTE_A_WORK/xnu-pager/tree" \
  "$ROUTE_A_WORK/venv/bin/python" scripts/check_route_a.py

"$ROUTE_A_WORK/venv/bin/python" scripts/route_a.py targets
```

`prepare_route_a_xnu.py` 只下载四个固定版本的公开 XNU VM 文件与前置补丁，核对长度及 SHA-256，并验证应用、反向恢复、再次应用。它的 `--output` 必须是仓库外的新目录，成功后可重用其 `tree`。

`ROUTE_A_XNU_PREPARED_DIR` 让回归测试编译并调用修改后的真实 pager C 函数。**没有准备该源码树时，相关 C 测试会跳过；这不能复现首轮“120 项通过、0 跳过”的完整结果。** 首轮 120 是历史快照，之后新增测试应以本次输出为准。检查终端最后的通过、失败和跳过数量，不以进程返回 0 单独代表全覆盖。

这些 C 测试替换了部分内核类型和诊断依赖，覆盖普通指针解码、分块边界、调用顺序及错误传播；没有编译或启动完整 XNU。[CI](.github/workflows/source-check.yml) 使用同一准备步骤与测试入口。

可选的独立编码复核：

```sh
"$ROUTE_A_WORK/venv/bin/python" scripts/route_a_checks/verify_fixture.py \
  --fixture tests/fixtures/route_a_instruction_vectors.json \
  --out "$ROUTE_A_WORK/assembler-oracle"
```

## 4. 真实输入和改写

目标版本与官方地址在 [configs/route-a-targets.json](configs/route-a-targets.json)。真实输入的提取和来源记录方法见 [ROUTE_A_EXTRACTION.md](docs/ROUTE_A_EXTRACTION.md)。`BuildManifest.plist` 校验版本和设备身份，但不能单独证明任意文件来自该镜像。

以准备好的 `launchd` 为例：

```sh
"$ROUTE_A_WORK/venv/bin/python" scripts/route_a.py audit \
  --profile ipados27 \
  --build-manifest "$ROUTE_A_WORK/input/BuildManifest.plist" \
  --input "$ROUTE_A_WORK/input/launchd" \
  --report "$ROUTE_A_WORK/launchd-audit.json"

"$ROUTE_A_WORK/venv/bin/python" scripts/route_a.py rewrite \
  --profile ipados27 \
  --build-manifest "$ROUTE_A_WORK/input/BuildManifest.plist" \
  --input "$ROUTE_A_WORK/input/launchd" \
  --output "$ROUTE_A_WORK/launchd.arm64" \
  --report "$ROUTE_A_WORK/launchd-rewrite.json" \
  --plain-pointer-abi
```

输入需先按提取文档取得；这些命令不会自动下载系统。所有输出必须是新文件，审计发现阻塞时先解释原因再修改实现。改写产物的状态是 `staged_userland_binary`，签名代码页通过校验也不表示已安装系统信任条目或能运行 Darwin 进程。

完整共享缓存需同时提供主缓存和全部子缓存，并通过源码、工具版本、覆盖与 edit 绑定检查。诊断性的部分 image 分析不能获得完整改写资格。

## 5. 继续进行集成验证

集成入口按实际依赖顺序使用：

- [TPRO 审计](docs/ROUTE_A_TPRO.md)：对固定的原始 24A446 `dyld` 统计 TCHANGE、重点寄存器与静态引用，并保守核验四个局部分支；apple 向量检查同时包含硬件与 pager 两类能力键。实际重跑结果见 [局部路径证据](docs/evidence/route-a-tpro-local-paths-20261123.json)。
- [普通 arm64 内核准备](docs/ROUTE_A_KERNEL_BUILD.md)：从固定的两个公开 Git 源仓库建立 XNU 12377 候选，逐项应用完整所选补丁，再编译普通 arm64 配置探针。它不链接完整内核。
- [定制工具链](docs/ROUTE_A_TOOLCHAIN.md)：实际构建带 XNU type builtins 的 Clang，执行 19 项语义断言；cctools/MIG/IIG/lzfse 可并行构建，最终安装时重新核验组合工具链。
- [第一次完整编译](docs/ROUTE_A_FIRST_KERNEL_BUILD.md)：`stage` 固定公开 reference 与缺失 headers，保留已适配文件；`run` 调用实际 upstream builder，记录退出码、部分对象及候选 Mach-O。一次构建使用一个新工作树，失败产物保留。
- [平台组件实验](docs/ROUTE_A_PLATFORM_RESULT.md)：基于真实成功 kernel recipe 编译固定的 `ArmDTPlatform` / `ArmCpu`，保留源码与依赖身份、失败诊断及归档成员摘要。独立链接实验先要求逐字节重现原内核，再核验新成员及构造函数实际进入候选；全部输出使用新目录。
- kernel callback 接线实验使用 `build_route_a_kernel_callback.py`：只选择固定上游的三个 `cpu.c` hunk，用原 C 配方编译外部副本；`link_route_a_platform.py --kernel-callback-report` 在通过原 baseline SHA 后替换唯一对象。完整睡眠策略、唤醒和设备运行分别验收。

CI 的 `Prepare ordinary arm64 kernel sources` 作业实际执行 71 项 patch 准备及 source/header staging；它不在每次提交时编译整个 LLVM 或 XNU。准备报告、源码摘要和编译器诊断保存在该次 Actions 产物中。[191 项回归对应的实际 staging 报告](docs/evidence/route-a-kernel-staging-20261123.json) 记录了 7 份公开源码、21 个保留 header 和 5 个新增 header。

安装组件后可执行 `scripts/check_route_a_host_tools.py`，用自写样本核验归档／链接、MIGCOM 输出和 LZFSE 往返。它不改动工具 prefix，每次输出目录必须新建；命令见工具链文档。组件检查与定制 Clang、SDK、完整 XNU 的验证分别记录。

## 6. 文件导航

| 路径 | 工作范围 |
| --- | --- |
| `scripts/arm64_lowering/` | 指令、Mach-O、普通指针、改写与 proof 校验 |
| `scripts/route_a_zeta/` | 固定来源的 CFG、用户空间及共享缓存工具 |
| `scripts/route_a.py` | 目标、审计与改写 CLI |
| `scripts/prepare_route_a_xnu.py` | 局部 pager 源准备与补丁往返验证 |
| `scripts/prepare_route_a_kernel.py` | 71 项源码候选和普通 arm64 配置探针 |
| `scripts/prepare_route_a_toolchain.py` | 定制 Clang、语义验证、主机组件与安装 |
| `scripts/run_route_a_kernel_build.py` | source/header staging 和实际首次 XNU builder |
| `scripts/build_route_a_platform.py` | 固定平台源码、真实 C++ 配方重放与独立归档 |
| `scripts/build_route_a_kernel_callback.py` | 真实 `cpu.c` 配方重编译、来源绑定的接线与有限生成代码检查 |
| `scripts/link_route_a_platform.py` | 原候选字节一致重放、平台成员装载与输入保护核验 |
| `scripts/check_route_a_host_tools.py` | 已构建主机工具的实际语义小样本 |
| `tests/test_route_a_*.py` | 回归检查；由统一入口发现 |
| `patches/route-a-*.patch` | 本轮提取工具与内核补丁 |
| `configs/` | 实验目标及准备配置 |
| `upstream/route-a-*` | 固定来源、长度、哈希与许可证 |
| `docs/evidence/` | 可公开的结果摘要；不含系统二进制 |
| `package/`、`drivers/` | 继承的设备移植源码与驱动参考 |

## 7. 提交和继续开发

每次提交说明具体问题、修改后的行为、实际验证和仍未覆盖的范围。源码或工具复用保留固定 commit、原始摘要与许可证；`upstream/source-manifest.json` 描述原始 229 份源码／许可证，不能为了让检查通过而重写成修改后的值。

完整内核构建、内核启动、`launchd` 启动、图形桌面和硬件验收是不同状态。新增记录绑定实际 Git 提交、输入哈希、工具版本、运行命令、测试数量和跳过项。历史证据保留原样，新结果新增文件；原始私有日志在公开前只提取所需事实。

Apple 系统文件、设备固件、账号数据、原始恢复备份和生成镜像留在仓库外。源码仓库不承担这些输入的分发。

优先任务以 [ROADMAP.md](ROADMAP.md) 为准。当前从非 TPRO 启动约定、普通 arm64 内核准备和真实完整共享缓存三处继续推进；不从旧 `build_v135.py` 推导出 27 内核已经可用。
