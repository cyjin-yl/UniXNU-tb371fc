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

## 5. 文件导航

| 路径 | 工作范围 |
| --- | --- |
| `scripts/arm64_lowering/` | 指令、Mach-O、普通指针、改写与 proof 校验 |
| `scripts/route_a_zeta/` | 固定来源的 CFG、用户空间及共享缓存工具 |
| `scripts/route_a.py` | 目标、审计与改写 CLI |
| `scripts/prepare_route_a_xnu.py` | 局部 pager 源准备与补丁往返验证 |
| `tests/test_route_a_*.py` | 回归检查；由统一入口发现 |
| `patches/route-a-*.patch` | 本轮提取工具与内核补丁 |
| `configs/` | 实验目标及准备配置 |
| `upstream/route-a-*` | 固定来源、长度、哈希与许可证 |
| `docs/evidence/` | 可公开的结果摘要；不含系统二进制 |
| `package/`、`drivers/` | 继承的设备移植源码与驱动参考 |

## 6. 提交和继续开发

每次提交说明具体问题、修改后的行为、实际验证和仍未覆盖的范围。源码或工具复用保留固定 commit、原始摘要与许可证；`upstream/source-manifest.json` 描述原始 229 份源码／许可证，不能为了让检查通过而重写成修改后的值。

完整内核构建、内核启动、`launchd` 启动、图形桌面和硬件验收是不同状态。新增记录绑定实际 Git 提交、输入哈希、工具版本、运行命令、测试数量和跳过项。历史证据保留原样，新结果新增文件；原始私有日志在公开前只提取所需事实。

Apple 系统文件、设备固件、账号数据、原始恢复备份和生成镜像留在仓库外。源码仓库不承担这些输入的分发。

优先任务以 [ROADMAP.md](ROADMAP.md) 为准。当前从非 TPRO 启动约定、普通 arm64 内核准备和真实完整共享缓存三处继续推进；不从旧 `build_v135.py` 推导出 27 内核已经可用。
