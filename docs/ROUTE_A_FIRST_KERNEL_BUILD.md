# Route A：71 项源码候选的真实第一轮内核构建

[run_route_a_kernel_build.py](../scripts/run_route_a_kernel_build.py) 将已经通过的普通 arm64 XNU 12377 源码候选接入固定上游 `build-xnu-4k-baseline.sh`。`stage` 准备真实源码与 headers；`run` 执行实际 builder、保留完整日志、非零退出与部分编译产物。它没有复制另一套内核 Makefile，也没有添加不接线的 board/provider stub。

这是 architecture + Darwin 26 + plain-pager 子集的首次编译入口。67 项架构 patch、3 项 Darwin 26 patch 和 1 项 plain-auth patch 已应用；两个硬件 PAC patch 被排除，依赖板级 PMGR/watchdog 的 boot-progress patch 仍明确暂缓。完整 TB371FC board/SoC/archive profile 未解析，源码背景和真实 CI 证据见 [ROUTE_A_KERNEL_BUILD.md](ROUTE_A_KERNEL_BUILD.md)。

## 已取得的真实构建结果：2026-11-24 记录

定制 Clang 已完成构建，19 个 XNU type builtin 语义断言通过，最终 host-tools 状态为 `host_tools_built`、`combined_toolchain_verified=true`。[工具链完成记录](evidence/route-a-toolchain-success-20261124.json) 保留实际执行的旧 driver 身份及原始报告摘要；当时的探针只验收类型语义和 Mach-O header，没有覆盖完整指令集。

首次完整 builder 已真正执行，生成 **716 个 `.o` / `.cpo` 文件**，随后以 2 退出。唯一 Clang error 为 `osfmk/kern/debug.c:2590:6: this target does not support pointer authentication`，出现在 950,343 行日志的第 538,726 行；之后其他并行 make job 的 warning 会把它挤出日志尾部。没有生成 link filelist 或普通 ARM64 kernel candidate，完整内核仍未编译／链接成功。详见[首次失败证据](evidence/route-a-first-kernel-failure-20261124.json)。

错误来自上游新增的 `unixnu_fileset_unmapped` 无条件使用 `__builtin_ptrauth_strip`。新增[局部修复](ROUTE_A_FILESET_PTRAUTH.md)按编译器能力保留认证操作，同时保留普通 ARM64 的返回地址和 panic 行为。实际测试还发现 Darwin target 默认 `apple-a12` 可使 `__builtin_return_address` 生成 `XPACI`；完整构建现在显式选择 `-mcpu=generic`，并在调用 builder 前通过实际安装的 Clang shim 运行返回地址 codegen 检查。该检查不在自己的参数里补 CPU，因而能发现真实环境遗漏或覆盖。

## 固定输入和目录

工作目录就是独立的 UniXNU checkout 根。`scripts/`、`refer/`、`.cache/`、`build/` 与 `.route-a/` 都在这一根下；本项目 checkout 与大型构建输出分开。

| 输入 / 位置 | 固定身份 |
| --- | --- |
| UniXNU 工作树 | `8542980d02b4d2cc5c32ee3542de1760b2562aac` |
| `.cache/xnu-work` | XNU `ac9718fb1af618d5ce8678d0dc6e8a58f252216f`，加已选 71 项 patch |
| 原始候选清单 | 6,119 个条目；SHA-256 `16aed427ee21f60f7e8697dbd21f1fce75db653749e677a787c4844c44a438b8` |
| `refer/xnu` / DriverKit | 未修改的相同 XNU 12377 commit |
| `refer/libplatform` | `libplatform-375.120.2`；`b7ed7cf5cf7dd12b98672435db2225a860f199d8` |
| `refer/libdispatch` | `libdispatch-1542.100.32`；`701f4d1a24ae9c6863901bbbb22624b7d1b87321` |
| `refer/AvailabilityVersions` | `AvailabilityVersions-157.2`；`149b1777f3e8c2133042d8e188f72e3adf6a7110` |
| TrustCache headers | XNU `xnu-8796.101.5`；`aca3beaa3dfbd42498b42c5e5ce20a938e6554e5` |
| Linux compiler runtime | LLVM `58c46bae21181fb4240cf964461bea738d96d50e` 的 compiler-rt profile 源码 |
| Linux Libc 辅助 headers | Libc `899a3b2d52d95d75e05fb286a5e64975ec3de757`，1592.100.35 |

前三项 Apple reference 来源由固定 [27 profile](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/os/ipados-27.0.1-24A446/profile.toml) 交叉检查，不使用旧 `feeds.toml` 的默认版本。TrustCache 是该 profile 指定的最后一个仍包含这些公开 headers 的 tag，stage 将它进一步绑定到 commit。compiler-rt / Libc 是固定 [Linux 辅助配方](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/linux/prepare-xnu.py) 的真实依赖。

这个步骤尚不构建 profile 中的 libpthread、IOStorageFamily 或 IOHIDFamily provider。公开 source interface 的版本匹配也不表示已验证原厂 stripped kext 的二进制 ABI。

## 先 stage，可与 LLVM 编译并行

该步骤已在 [提交 3a52649 的 CI](https://github.com/cyjin-yl/UniXNU-tb371fc/actions/runs/45181619136) 和开发容器实际通过。两次 staged source inventory 都是 `93f9ac5f67205a884ff11dd6c1d949bd3deac6b0b2fdc6776bd592ef006a240a`。共记录 7 份源码和 26 个 headers，其中 21 个保留原准备结果，5 个为新增 TrustCache 文件；[公开报告](evidence/route-a-kernel-staging-20261123.json) 保留 CI 原始 artifact 与报告摘要及完整来源。此结果的状态为 `inputs_staged`，完整 builder 的执行结果另行记录。

```sh
python3 SOURCE/scripts/run_route_a_kernel_build.py stage \
  --unixnu-repository WORK/sources/unixnu.git \
  --prepared-kernel WORK/prepared-kernel \
  --work-dir WORK/kernel-build \
  --llvm-repository WORK/toolchain-work/llvm-project
```

`prepared-kernel` 是 [prepare_route_a_kernel.py](../scripts/prepare_route_a_kernel.py) 的完整成功输出目录，包含 `tree`、报告、selected patches 与 source inventory。stage 验证固定版本、原始完整 inventory digest、每项文件内容/模式和实际 patch bytes，复制后再检查一次。修改过的源码或额外加入的文件不能悄悄进入候选。

`--work-dir` 必须不存在。失败目录与日志保留；重新尝试时使用新的工作树，或者由操作者把旧工作树保留到另一个名字后重新 staging。脚本不 reset、清空或删除旧源码/对象。

可选的 `--llvm-repository` 接受正常、已有固定 HEAD 的 LLVM working repository，并通过 Git shared objects 建立 sparse compiler-rt checkout，避免重复下载大型 LLVM 仓库。**需要一直保留这个输入目录及其 Git objects**；该依赖记录在 stage report 中。它只读取 commit 中的源码，不复制正在构建的 LLVM 工作树改动。省略该参数会从固定公开 URL 获取独立 sparse checkout。其他源码通过显式 `git init` / fixed-commit fetch 创建，可接受 bare、shallow、只有 `FETCH_HEAD` 的输入。

### Header restoration 的边界

固定上游 `prepare-xnu-source.py` 原本根据 tag 从 GitHub API 获取 header 列表。stage 直接从已固定 Git objects 生成它会读取的三个 cache JSON，并安装所有缺失 headers。因此原 helper 在本工作树中不需要重新解析可移动 tag。

已经存在的 DriverKit/TrustCache 文件可能含 71 项 series 的 Darwin 26 适配，不能被原始旧 headers 覆盖。stage 保留这些已在 inventory 中验证的 bytes，记录 source header SHA、实际安装 SHA 和 `preserved_prepared_header`。随后会对添加 headers 后的整个 XNU source tree 生成第二份 inventory，供真实执行前复核。

Linux helper 的 LLVM/Libc cache 也预先设置为它实际要求的固定 HEAD，避免触发其“不同 HEAD 则 rmtree 后重取”分支。所有 sources、许可证文件、目录身份和共享对象依赖都留在持久工作树。

### 独立的构建修复层

[route-a-build-fixes.json](../upstream/route-a-build-fixes.json) 绑定原始 71 项 inventory、每个本地 patch 的 SHA-256 以及修改文件的前后摘要。stage 在 headers 准备后先保存 `pre-build-fix-source-inventory.json`，再检查并应用补丁，最后生成用于实际编译的完整 inventory。原始 71 项补丁和准备报告保持原样。

每个修复只能修改 manifest 声明的文件。应用前检查 patch bytes、目标源文件摘要和 `git apply --numstat` 的路径集合；应用后核对整个文件清单，只允许声明的文件内容变化，模式和类型不能改变。run 再次比较当前 manifest、保存的 patch、receipt 和最终源码，拒绝使用被更换或未登记的修复。

## 工具链完成后执行真实 builder

先完成 [ROUTE_A_TOOLCHAIN.md](ROUTE_A_TOOLCHAIN.md) 的定制 Clang 与最终 host-tools 步骤，`--sdk-root` 必须选择这个工作树的 `.cache/fakeroot`。然后执行：

```sh
python3 SOURCE/scripts/run_route_a_kernel_build.py run \
  --work-dir WORK/kernel-build \
  --toolchain-work WORK/toolchain-work \
  --jobs 2
```

run 检查 source staging 状态、XNU files、每个公开 reference 的 HEAD/工作树，以及当前 compiler 和 host outputs 的摘要。在实际执行期间对工具链 build/host 锁持共享锁，避免编译中途被另一项安装替换；工作树自己持独占锁。

它调用固定的 `bash scripts/build-xnu-4k-baseline.sh`。环境明确选择普通 `arm64`、`arm64-apple-ios27.0`、XNU 12377 / Darwin 25.5.0、`XNU_BOOT_PROGRESS=0` 和 `XNU_BOOTSTRAP=1`。上游会实际安装 Availability 与 XNU headers，构建 firehose 和 Linux compiler runtime，再进入完整 XNU `build` target。上游 compiler-runtime recipe 的独立 profile objects 仍使用其原始 `arm64-apple-ios17.0` 参数，这项实际行为保留在源码和日志中，不能把该 archive 直接当成已完成 27 ABI 审核。

`UNIXNU_PATCH_LIST` 指向保存了真实 71 项 patch 路径的非空文件。固定 builder 使用这个变量判断 resolver 已完成，避免再次应用面向旧 XNU 的 legacy patch loop。完整有序 patch 证据仍是原始 preparation report，非空变量本身不构成 patch 成功证明。

调用者环境里的其他 `XNU_*`、`UNIXNU_*`、交叉 compiler flags、make flags 和外来 link archives 会清除，再设置本候选的明确环境。当前没有选择 source crypto、pthread、ArmCpu 或其他 board provider；这些输入必须在完整 closure 解决后单独接入。入口不会继承某个别的板子曾留下的环境来制造“成功”。

## 退出、报告与后续工作

每个 staged 工作树只允许执行一次第一轮 builder。`run` 不接受已有 `build/` 或既往 build report，避免上游用于失效处理的 unlink/rm 分支破坏先前实验。首次执行的所有部分源码、headers、对象、logs 与失败报告保留。

| 输出 | 作用 |
| --- | --- |
| `.route-a/stage-report.json` | 固定输入、headers 的原始/实际摘要、共享 Git object 依赖和 stage 成功或失败 |
| `.route-a/stage.log` | 真实 source acquisition 日志 |
| `.route-a/source-inventory.json` | 已通过 71 patch 准备的原始 inventory |
| `.route-a/pre-build-fix-source-inventory.json` | 添加缺失 headers 后、局部修复前的 source inventory |
| `.route-a/build-fixes/` | 构建修复 manifest 与原始 patch bytes |
| `.route-a/staged-source-inventory.json` | headers 与局部构建修复完成后的最终 source inventory |
| `.route-a/selected-patches.txt` / `patches/` | 真实 patch bytes 与固定上游 skip-legacy 入口 |
| `.route-a/build.log` | 实际上游 builder 的完整 stdout/stderr |
| `.route-a/cpu-verification/` | 真实 compiler shim 的返回地址 C、IR、汇编、对象和 CPU 约定检查 |
| `.route-a/build-report.json` | 实际 exit code、首批错误及总数、完整日志摘要、对象数量、link filelist、候选 kernel 摘要与真实 Mach-O header 检查 |

非零 builder 退出会使 CLI 返回 2，并记录 `builder_failed`；不会将“生成了一些 headers”归类为 kernel build 成功。builder 返回 0 后，还要求实际候选文件为 Mach-O 64 位、ARM64、subtype 0、`MH_EXECUTE`；缺失或不符会记录 `output_check_failed` 并返回 2，原始 builder exit code 仍保存为 0。只有这一步也通过才记录 `builder_completed`。报告记录每个候选的真实 header words，但完整 board/archive、最终 ISA/ABI、预链接和启动验证没有由这个 header 检查自动证明。`kernel_compiled`、`kernel_linked` 与 `os_boot_verified` 的完整候选资格字段继续为 false，实际生成了什么由独立 artifact 列表和真实 exit code 描述。

下一轮应根据实际首个 compile/link error 修复明确输入，保存编译命令和 provider/link filelist，继续关闭未定义符号、指令集、Darwin 26 / dyld TPRO、TB371FC boot 与外设依赖。没有完整链接/硬件证据之前，不能称其为可启动 iPadOS 27 内核。

## 固定上游入口

- [真实 XNU builder](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/build-xnu-4k-baseline.sh)
- [公开 header restoration](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/prepare-xnu-source.py)
- [Linux source / runtime helper](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/linux/prepare-xnu.py)
- [27 profile 与公共 source pins](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/os/ipados-27.0.1-24A446/profile.toml)
