# Route A：Linux 定制 Clang 与主机构建工具

[prepare_route_a_toolchain.py](../scripts/prepare_route_a_toolchain.py) 实际构建固定版本的 LLVM/Clang 和 Linux 主机工具，目标是让 [71 项补丁源码候选](ROUTE_A_KERNEL_BUILD.md) 进入真实 XNU 编译。它不下载 iPadOS 镜像，也不选择 crypto provider。内核第一轮构建入口另见 [ROUTE_A_FIRST_KERNEL_BUILD.md](ROUTE_A_FIRST_KERNEL_BUILD.md)。

已有 CI 证明普通 Clang 能生成普通 arm64 配置探针，但三个 `__builtin_xnu_type_*` 表达式不能编译。因此继续添加普通 Clang 宏检查不能消除缺口。本入口应用上游自己的 type builtin 实现，真正重建编译器，并验证其常量求值行为。

## 固定源码与实际产物

全部配方来自 [UniXNU `8542980d`](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/linux/setup-toolchain.py)。读取 Git commit 中的内容，工作树里的同名文件不能替代它。上游使用 tag 的三项主机依赖在这里进一步固定到解析后的 commit。

| 输入 | 版本 / commit | 用途 |
| --- | --- | --- |
| LLVM | `58c46bae21181fb4240cf964461bea738d96d50e` | AArch64 backend、Clang、resource headers |
| XNU type patch | 固定 UniXNU 的 `scripts/linux/llvm-xnu-builtin-type.patch` | 三个 XNU type builtins 与 usage semantics |
| cctools-port | `1030.6.3-ld64-956.6`；`3e694ee7393af2a4ce8bd6e7dae28fe37450aa87` | Darwin ld64、libtool、nm、lipo、libmacho、libstuff |
| Swift libdispatch | `swift-6.4.0-RELEASE`；`024805abec6daa9cdda569fd736b9c7686dfd735` | cctools 所需的 Linux libdispatch / BlocksRuntime |
| bootstrap_cmds | `bootstrap_cmds-138`；`c71d2d72f48995baaea76148f61002e5299841de` | MIG / migcom |
| iig-port | `ea6d147d668ca15d490da638012243fcd705f30d` | IIG；同时应用固定 UniXNU 的 Darwin target patch |
| lzfse | `e634ca58b4821d9f3d560cdc6df5dec02ffc93fd` | 后续 kernelcache 压缩工具 |

主机上的 Swift libdispatch 与内核 headers / firehose 使用的 Apple libdispatch 是两个不同的输入。后者固定为 27 profile 中的 `libdispatch-1542.100.32`，由内核 staging 入口准备。

`build-clang` 只构建 AArch64 Clang，使用发行版的原生 Clang/Clang++ 编译它，使用 lld 完成 ELF 主机链接。最终 XNU 的 Mach-O kernel 链接由 cctools 的 ld64 负责；不能拿 lld 的安装成功替代 ld64 的 kernel link 验证。这个选择与固定上游安装配方一致。

## 容器与依赖

大型 LLVM 源码、build tree 和产物应放在持久工作卷中。当前项目的构建环境是 CT102 内的 `unixnu-route-a-dev`，容器内 `/work` 为构建卷，内存上限 6 GiB。本轮使用编译并发 2、链接并发 1；主机工具可另外以并发 1 构建。不要在磁盘紧张的聊天 scratch、PVE host 或其他设备项目的目录中启动构建。

在 Debian/Ubuntu 专用容器中安装下列依赖；此清单来自固定上游的 `COMMON_PACKAGES` 与 `PACKAGES['apt']`，不是要求运行上游安装器的 `main()`：

```sh
apt-get update
apt-get install -y \
  git patch flex bison bzip2 cpio rsync curl wget ca-certificates tcsh \
  unifdef cmake clang lld mtools build-essential pkg-config ninja-build \
  python3 python3-dev xz-utils libssl-dev zlib1g-dev libbsd-dev uuid-dev \
  llvm-dev libclang-dev device-tree-compiler
```

`llvm-config` 应与主机 Clang/libclang 开发包匹配。主机工具步骤会用这些选定路径执行真实的 libclang 编译、链接和运行检查，不只检查文件名。不同发行版提供的工具版本会进入 identity 报告；它们不会被假定与其他机器逐字节可复现。

## 执行顺序

以下 `SOURCE` 是本仓库 checkout，`WORK` 是仓库外的新持久目录；不要将它们设置为系统保留变量。`UNIXNU_GIT` 指向已获取固定 `8542980d` commit 的本地仓库，可使用 [源码准备文档](ROUTE_A_KERNEL_BUILD.md) 的 bare fetch 命令。

### 1. 实际构建定制 Clang

```sh
python3 SOURCE/scripts/prepare_route_a_toolchain.py build-clang \
  --unixnu-repository UNIXNU_GIT \
  --work-dir WORK/toolchain-work \
  --prefix WORK/toolchain \
  --host-cc clang --host-cxx clang++ --jobs 2
```

初次运行固定源码、patch bytes、主机工具身份与完整 CMake 参数，建立 `identity.json`。源码存于 `toolchain-work/llvm-project`，构建目录为 `llvm-build`，安装到 `toolchain/llvm`。源码更改清单包括 patch 新增的未跟踪文件，避免只记录 `git diff` 而漏掉新实现。失败后保留源码、对象、日志和状态。

以相同脚本、参数、源码与工具重跑可恢复构建。输入 identity 变化会拒绝复用，应换新工作目录。正在运行的旧 driver 快照不应被覆盖；特别是早期已启动快照使用 `LLVM_USE_LINKER=lld`，较新的 driver 将保留 argv[0] 的绝对 `ld.lld` 路径传给 CMake。正在进行的旧 build 应使用原快照恢复，并在最终证据中保留其实际 identity。

### 2. 并行构建不依赖定制 Clang 的主机组件

等步骤 1 建立 `identity.json` 后，可在另一个进程执行：

```sh
python3 SOURCE/scripts/prepare_route_a_toolchain.py host-tools \
  --unixnu-repository UNIXNU_GIT \
  --work-dir WORK/toolchain-work \
  --sdk-root WORK/kernel-build/.cache/fakeroot \
  --llvm-config llvm-config --jobs 1 --components-only
```

它调用固定上游安装器的 cctools、MIG、IIG、host-cc、lzfse 配方；每次实际构建拥有新的 `host-attempts/run-NNN`。不调用原安装器的 LLVM 或 package-manager 步骤，也不使用其自动清理临时目录的路径。源码获取按已审计 commit 进行，拒绝覆盖不同或有修改的 checkout。

固定安装器的四处“已有输出就跳过”逻辑经过精确文本形状校验后移除，配方主体保持不变。仅成功产物 manifest 的源码、主机 compiler/libclang、支持文件和每项输出摘要都匹配时，才允许复用。未知的已有二进制不能仅凭存在就被认领为本次成功产物。

此模式成功状态为 `host_components_built_clang_pending`，明确 `combined_toolchain_verified=false`，不会安装最终的系统 shims。它使用独立 `host-tools.lock`，因此可以和 LLVM 编译同时运行。

### 3. Clang 完成后安装并核验组合工具链

重复步骤 2 的命令，去掉 `--components-only`。已核验的 host component cache 可复用。最终阶段额外取得 `build.lock`，检查当前 Clang 与成功构建记录的摘要一致，并再次运行下面的语义探针，再安装、检查 shims。

这一步要求 Linux 专用 Docker/Podman 容器的 root，因为固定上游把 `xcrun`、`plutil`、`codesign` shims 安装到 `/usr/bin`。项目 prefix 内的 `clang`、`clang++`、`cc`、`install`、`gm4` 也被记录。原生主机工具仍由 Linux compiler 编译，交叉 wrapper 则明确使用 `arm64-apple-ios27.0`。`codesign`/`plutil` shims 的存在不表示设备固件或系统镜像得到 Apple 授权签名。

最终成功状态是 `host_tools_built`，并写入 `toolchain-environment.json`。它表示此处的编译器、组件、shim 检查完成；SDK kernel headers、XNU 生成的 MIG/IIG interfaces、完整 kernel link 和设备启动仍各自待验证。

## 编译器语义验证

单独检查已有编译器可运行：

```sh
python3 SOURCE/scripts/prepare_route_a_toolchain.py verify-clang \
  --clang WORK/toolchain/llvm/bin/clang --output WORK/new-clang-verification
```

这会真正编译一个 C++17 freestanding 文件，执行 19 个 `static_assert`，覆盖 pointer/data、数组、union、usage semantics、padding、summary 位、type compatibility、void 和模板实例化。期望值直接根据上游 patch 的八字节 granule 编码设置；不是只检查 `__has_builtin` 或把编译成功的表达式当成语义正确。

探针显式使用 `arm64-apple-ios27.0 -march=armv8-a`，拒绝 `__arm64e__` 或 `ptrauth_calls`，并检查真实输出为 Mach-O 64 位 `MH_OBJECT`、ARM64、subtype 0。保存 compiler identity、精确命令、源文件与对象摘要、退出码及有限 stderr。输出目录必须新建，失败不会覆盖旧证据。

该探针能证明所测 compiler 语义与普通 arm64 code generation，不能证明 XNU 每个 translation unit 或外部 archive 都兼容 Snapdragon 870。所有工具链报告保留 `kernel_compiled=false`、`kernel_linked=false`、`os_boot_verified=false`。

## 日志、身份和许可

| 文件 | 含义 |
| --- | --- |
| `identity.json` / `patched-source.json` | 固定源码、patch、CMake 参数、主机工具身份与源码更改摘要 |
| `logs/fetch-llvm.log` / `configure-clang.log` / `build-clang.log` | 真实长任务日志 |
| `state.json` | Clang 当前步骤、实际失败或 `clang_verified` 结果 |
| `checks/run-NNN/verification.json` | 每次语义验证的证据 |
| `host-attempts/run-NNN/` | 固定上游支持文件、sources、原生 link probe 与完整 host build log |
| `host-components.json` | 允许复用的成功组件和输入/输出摘要 |
| `host-tools-state.json` | 当前 host 任务；区分 components-only 与组合工具链 |

各仓库的 LICENSE/APPLE_LICENSE 和文件头保留在源码 checkout。上游 Linux 支持文件导出时也保存 UniXNU 根 LICENSE。本仓库只提交准备器、测试、文档与规范化证据，不包含下载的第三方源码、编译后二进制或 Apple 系统文件。不同组件的许可适用于各自来源，UniXNU 的许可证不替代它们。

本入口不下载 `ONLYA/corecrypto-2023`。完整 kernel/archive closure 的 provider 选择和使用条件仍须单独解决；原生工具链安装完成不会消除这项依赖，也不会自动接通 TB371FC 的存储、显示、GPU 或启动链。

## 固定来源

- [Linux 安装配方](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/linux/setup-toolchain.py)
- [Clang type builtin 实现 patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/linux/llvm-xnu-builtin-type.patch)
- [Linux clang wrapper](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/linux/clang)
- [IIG Darwin target patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/linux/iig-port-darwin-target.patch)
- [实际 kernel build 环境](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/unixnu/kernel.py)
