# 2026-11-24：真实候选 loader 合同证据

本目录保存三次实际尝试的原始文本证据。输入是同一份已链接平台候选，完整结果与来源见 [汇总](../route-a-loader-contract-20261124.json) 和 [合同说明](../../ROUTE_A_LOADER_CONTRACT.md)。所有原报告按字节取回和保存，没有通过 JavaScript 数字重序列化；报告中的 64 位虚拟地址仍是原始整数。

| 尝试 | 驱动 | 结果 | 报告 SHA-256 |
| --- | --- | --- | --- |
| attempt-001 | v1 | segment flag 门槛失败，未编译／装载 | `605a9bb3a16a5c1c8e352580164b3bde89846ab7c9721db637f534f3a0d4f80a` |
| attempt-002 | v2 | local relocation 表门槛失败，未编译／装载 | `571a416e1858ccc0660286d1850786925599daed6a2284dac6e8ff5bc8fba34f` |
| attempt-003 | v3 | host loader 合同通过，设备 entry 未执行 | `300da6b39a2fa06a7cde38043eca046ce27e4be5c96f55a6afa6aff758f7fb98` |

各目录的 `transfer-manifest.json` 绑定实际使用的两个驱动文件、两个既有 Python helper 和六份固定公开源码／许可证。失败时三个 host verified 都为 false；成功时 host parser、字节装载和 ABI 为 true。三次尝试的 16 项声明输入都复核不变。

## 第三次实际生成的 C 与许可证

[loader-probe.c.txt](attempt-003/loader-probe.c.txt) 是实际编译的 `loader-probe.c` 原始字节，仅以 `.txt` 后缀保存为证据文本。长度为 17,396 字节，SHA-256 为 `6f20d5b6c4860a78afd7c2712dd1c7040b5171f10f6c9068cd09ebd04399cfd3`；可与原报告的 `host_compile.source` 直接核对。

DarwinBoot 的原始 [LICENSE](attempt-003/sources/darwinboot/LICENSE) 与 XNU 的 [APPLE_LICENSE](attempt-003/sources/xnu/APPLE_LICENSE) 随同保留。翻译单元中的真实 parser、复制循环和声明保留各自的版权／SPDX／Apple／OSF 通知，host adapter 与 wrapper 明确区分；没有将原源代码改归本项目许可。

`compile.stdout` 和 `compile.stderr` 都是实际编译产生的空文件。host library 与 23,035,904 字节 kernel heap 映像没有发布，原报告保留其完整摘要。生成的文本不是预编译固件，也未执行 kernel entry。

## 精确恢复旧失败驱动

当前 [脚本](../../../scripts/probe_route_a_loader.py) 和 [配置](../../../configs/route-a-loader-probe.json) 对应 driver-v3。两份 patch 只记录这两个文件的版本变化：

- [driver-v1-to-v2.patch](patches/driver-v1-to-v2.patch)：显式支持固定 `SG_NORELOC` 注记、逐段 receipt 和具体诊断。
- [driver-v2-to-v3.patch](patches/driver-v2-to-v3.patch)：固定零 VA slide、全部 local unsigned64 记录、精确空 section 边界和资格边界。

以下命令在仓库根目录运行，只在一个新的临时目录中恢复旧文件：

```sh
LOADER_REPO=$(pwd)
LOADER_HISTORY=$(mktemp -d)
mkdir -p "$LOADER_HISTORY/scripts" "$LOADER_HISTORY/configs"
cp scripts/probe_route_a_loader.py "$LOADER_HISTORY/scripts/"
cp configs/route-a-loader-probe.json "$LOADER_HISTORY/configs/"
(
  cd "$LOADER_HISTORY"
  git apply --reverse "$LOADER_REPO/docs/evidence/route-a-loader-20261124/patches/driver-v2-to-v3.patch"
  sha256sum scripts/probe_route_a_loader.py configs/route-a-loader-probe.json
  git apply --reverse "$LOADER_REPO/docs/evidence/route-a-loader-20261124/patches/driver-v1-to-v2.patch"
  sha256sum scripts/probe_route_a_loader.py configs/route-a-loader-probe.json
)
```

| 版本 | 脚本 SHA-256 | 配置 SHA-256 |
| --- | --- | --- |
| v1 | `68c6e3b7473676a59a786df55f1f64e42d2f4d5b6dfa14b65f84b3ce4b66025b` | `d66d9e078441c851fe4c6f1abc429c4e5c8cbfc6262fccebdf726e57482ac4d2` |
| v2 | `90ea8d86e618ddf173976c935149210db9f65830342ccee5f7e221019b71a530` | `f07fd43457da22454df9b16c3ab2aa2c0a0b8e9d43f60977a0df9efd8e4a4af3` |
| v3 | `9957a85ecb92fbe962b22a01e36a34422d65b443002d50fe9ff672d236a74fb9` | `fd029b04c8953d825dea1a9e5fb878b169a38fcbe163d0def7678eac939b84e1` |

这条逆向恢复链已实际运行，并逐字节与两个 frozen driver 目录比较一致。完整重跑仍需相同六份公开输入、原候选、原链接报告和真实 prepared build；这些 patch 只恢复驱动，不替代输入。

## 本地回归范围

[local-regression.log](local-regression.log) 保留本地完整入口原输出：`Ran 295 tests`、`OK (skipped=10)`。loader 新增 32 项全部实际通过，包含 7 项生产 C 提取测试。9 个 pager C 测试因为本地没有 prepared source tree 跳过；另 1 个 class-level skip 因本地无 Clang，涉及该 fileset 类的 4 个方法。此记录不是完整 CI。测试样本均为自写 Mach-O，不能计作 XNU 启动。
