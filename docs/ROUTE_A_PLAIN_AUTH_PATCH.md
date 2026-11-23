# Route A：XNU 12377 的 plain-auth pager 补丁草案

日期：2026-11-23。状态：**已在固定源文件上验证补丁应用与反向恢复，已运行独立 C 函数测试；尚未编译完整内核，尚未在设备上启动。** 本文对应 [补丁](../patches/route-a-plain-auth-12377.patch)、[来源与验证记录](../upstream/route-a-kernel-sources.json)、[Python 参考实现](../scripts/arm64_lowering/slide_v5.py) 和 [测试](../tests/test_route_a_slide_v5.py)。更广的构建、27 ABI 与设备缺口见 [内核集成审计](ROUTE_A_KERNEL_GAPS.md)。

## 解决的具体问题

主线 UniXNU 的 4 KiB pager 把一个 16 KiB v5 slide page 分成四个部分，使用 `vm_shared_region_slide_part_v5()` 逐部分解析指针链。该函数原先只在 `__has_feature(ptrauth_calls)` 为真时写回 authenticated 指针；普通 arm64 构建会保留原始链编码。zeta 旧 plain-auth 补丁仅修改完整页的 v3/v5 函数，覆盖不到这条新路径。[U-4K] [Z-SHARED]

本补丁把三条 shared-region 路径与 zeta 的 dyld pager 修改放在同一份可审计 diff 中：

| 源文件 / 路径 | 改动 | 来源 |
| --- | --- | --- |
| `vm_shared_region.c` / `vm_shared_region_slide_page_v3` | 无 PAC 编译时把解析出的普通地址写回 authenticated 链位置 | zeta 原有修改 |
| 同文件 / `vm_shared_region_slide_page_v5` | 同上，遵守 v5 的 34-bit runtime offset | zeta 原有修改 |
| 同文件 / `vm_shared_region_slide_part_v5` | 在 `apply=true` 时补上同样的无 PAC 写回；发现链位置时不改 source bytes | **本地新增**，适配主线新 4 KiB 算法 |
| `vm_dyld_pager.c` / `signPointer` | 无 PAC 编译时，已有 IA/DA A-key 路径输出普通地址；保留 null 处理和原有其他 key 的失败分支 | zeta 原有修改 |
| 同文件 / `fixupPageAuth64`、`fixupCachePageAuth64`、`fixup_page` | 在无 `HAS_APPLE_PAC` 构建中保留已有 arm64e 格式处理入口；将 `ptrauth.h` 类型/枚举 include 移到该宏之外 | zeta 原有修改 |
| 同文件 / `fixup_page` | 各 pointer-format 分支直接返回 helper 结果，避免把无效 key / bind / 链范围错误改报成功 | **本地新增**错误传播修复 |

这里选择的是统一的 **plain-pointer ABI**：代码转换器、dyld、内核 pager 和全部参与的映像必须一致地使用普通指针。它不提供 PAC 认证，也不能让任意未转换的 arm64e 程序直接运行。补丁没有新增或承诺支持未审计的 27 pointer format。[Z-SHARED] [Z-DYLD]

原 `fixup_page()` 丢弃各 helper 的返回值。本补丁将这些调用改成直接 `return`。它的调用方 `dyld_pager_data_request()` 已有失败处理：设置 `retval = KERN_FAILURE`，在清理路径调用 `upl_abort()`，因此无需改变外层签名或引入新 VM 生命周期。测试执行到真实 dispatcher 的错误返回；完整 UPL abort / commit 路径只做了源码核对，仍需内核环境验证。[XNU-DYLD]

## 固定输入与应用顺序

| 顺序 | 固定输入 | Revision |
| --- | --- | --- |
| 1 | Apple XNU `xnu-12377.121.6` | `ac9718fb1af618d5ce8678d0dc6e8a58f252216f` |
| 2 | UniXNU `patches/xnu-12377/native-4k-shared-region-slide.patch` | `8542980d02b4d2cc5c32ee3542de1760b2562aac` |
| 3 | 本仓库 `patches/route-a-plain-auth-12377.patch` | SHA-256 见来源 JSON |

zeta 两份原补丁来自 `none24smu/UniXNU` 的 `a8b90c0c645fd62ae850cd43e80c87bab4cc157d`。它们已合入步骤 3，**不要另行重复应用**。zeta 的旧 `native-shared-region-small-pages.patch` 是另一套分块实现，也不应叠加到这里的主线 prerequisite。上述验证只证明这一明确顺序，不代表整套 OS、arch、board patch series 已通过组合测试。[Z-SHARED] [Z-DYLD] [U-4K]

实测只取得四个公开 XNU 文件，不下载系统镜像或整树：`vm_shared_region.c`、`vm_shared_region_internal.h`、`vm_shared_region_pager.c`、`vm_dyld_pager.c`。来源 JSON 记录了每个原文件的长度、SHA-256、URL，以及应用 prerequisite 后和最终补丁后的摘要。正向应用、反向恢复到 prerequisite、再反向恢复到原始文件、重新应用两份补丁，均已逐文件比对成功。

## 复现补丁应用与恢复

[prepare CLI](../scripts/prepare_route_a_xnu.py) 从脚本所在位置定位仓库，可从任意工作目录调用。`--output` 必须指向仓库外的**新目录**；已有目录会直接报错，不覆盖其中内容。脚本需要 Python 3、Git 和访问固定 GitHub raw URL 的网络；运行 C 测试还需要宿主 C 编译器。

在本仓库根目录执行：

```sh
ROUTE_A_PREPARED_ROOT="$(mktemp -d)"
python scripts/prepare_route_a_xnu.py --output "$ROUTE_A_PREPARED_ROOT/xnu"
PYTHONDONTWRITEBYTECODE=1 \
ROUTE_A_XNU_PREPARED_DIR="$ROUTE_A_PREPARED_ROOT/xnu/tree" \
python -m unittest discover -s tests -p test_route_a_slide_v5.py -v
```

成功时输出 `prepared_dir=.../tree` 和 `verification=.../verification.json`。该 JSON 包含固定输入摘要、各阶段的四文件摘要、Git 命令与返回值。CI 可直接使用相同的 `tree` 路径设置 `ROUTE_A_XNU_PREPARED_DIR`，再运行 `scripts/check_route_a.py`，使 C 测试实际执行。

脚本验证下载长度与 SHA-256，复制已验证的本地补丁和 upstream 许可文本，并执行 apply、reverse、reapply。每一阶段都核对四个文件的完整摘要和原始许可证头；任一步不符即返回非零。失败时保留 `verification.json` 与已取得的材料以便定位，但不会报告 prepared。它不下载整树、SDK、系统镜像或私有构建输入。

## 已运行的测试与边界

本次在 x86-64 主机上使用 Python 3.12.14 和 GCC 14.2.0，**23 个测试全部通过，没有跳过项**。其中 14 个为 Python 向量，9 个从已校验摘要的真实 patched 源文件提取 C 函数，以 `-std=c11 -O2 -Wall -Wextra -Werror -shared -fPIC` 编译后执行。测试的来源摘要与执行记录位于来源 JSON。

| 检查 | 实际覆盖 |
| --- | --- |
| 指针值 | auth / nonauth、非零 slide、nonauth high8、auth diversity / address diversity / data-key 元数据、uint64 wrap |
| 跨 4 KiB 链 | 链穿过四个部分，含 `0xff8 → 0x1000`；24 种请求顺序均匹配手工列出的普通地址结果 |
| 链布局 | 首链位于最后一部分、跳过中间部分、`NO_REBASE`、单 4 KiB slide page；发现模式保留原始字节 |
| 负对照 | 删除新增的 part-v5 无 PAC 写回后仍残留链编码；恢复旧 dispatcher 后坏 key / bind / 起点会误报成功；修正版均通过相应断言 |
| v3 与 dyld helper | 实际 v3 auth 写回；实际 `signPointer` 的 A-key、null 和非零 B-key 失败路径 |
| dyld 错误传播 | 真实 `fixup_page` + auth helpers 拒绝 IB/DB key、auth / nonauth bind ordinal 越界、指针起点越界、链跨 4 KiB；正确 rebase / bind 和 shared-cache high8 仍成功 |
| 输入拒绝 | Python 模型拒绝坏范围、越界链、重复部分、未显式确认 plain-pointer ABI；实际 C part 函数只另测了其已有的起点未对齐拒绝 |

不设置 `ROUTE_A_XNU_PREPARED_DIR` 时，9 个 C 测试会明确显示为 skipped；剩余 Python 向量仍可离线运行。显式设置后，源文件摘要不匹配或缺少编译器会使测试失败。

以下事项仍然未完成，不能由这些测试推出：

- **完整 kernel 编译与 ABI。** C harness 提取七个函数：v3、v5、part-v5、`signPointer`、`fixupPageAuth64`、`fixupCachePageAuth64`、`fixup_page`。它使用小型类型、诊断 stub 和 nospec 步进的普通 C 模型，非 auth 32/64-bit helper 则为 stub；因此不证明真实 header 布局、架构 speculation barrier、`ptrauth.h` 工具链可用性、整个 `vm_dyld_pager`、内核链接或 arm64 目标生成代码。
- **pager 锁与页生命周期。** 测试从不可变原始字节独立发现每部分链位置，没有执行 kernel fault、真实缓存锁、APFS page-in、busy-page 生命周期、签名验证或并发。24 种顺序是顺序调用排列，不是并发测试。
- **完整 bounds。** Python 模型比继承的 C 更严格：例如越过 slide page 的链在 Python 中报错，原 part-v5 会结束链。本补丁修复 dispatcher 的错误传播，但没有审计全部 link-info 格式边界、整数溢出或旧 32-bit chain helper 的内部错误传播，不能称整个 pager 已通过安全性证明。[XNU-DYLD]
- **27 与设备启动。** 此补丁没有添加 Darwin 26 syscall / KPI 兼容层、TB371FC board profile、TrustCache / AMFI 集成、匹配的 launchd/dyld/cache 闭包或驱动。当前设备仍是 Android 14、bootloader locked、verified boot green；本次未取得或核验私有 V135 内核输入。[内核集成审计](ROUTE_A_KERNEL_GAPS.md)

## 来源与许可

UniXNU/zeta 适配代码的 `BSD-2-Clause-Patent` 许可文本已保留在 [upstream LICENSE 副本](../scripts/route_a_zeta/LICENSE)，原项目的版权与专利条件继续适用。[U-LICENSE] [Z-LICENSE] XNU 两个修改文件各自保留原始 APSL-2.0 / OSREFERENCE 声明；补丁仅在声明后增加 dated modification notice，不把这些文件重新标为 BSD。`vm_dyld_pager.c` 的原始 OSREFERENCE 声明还含 Apple OS 授权相关条件，应随源文件一并保留。[XNU-SHARED] [XNU-DYLD] 本仓库没有复制 Apple 系统二进制、SDK、私有内核或 corecrypto provider。

[U-4K]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/native-4k-shared-region-slide.patch
[Z-SHARED]: https://github.com/none24smu/UniXNU/blob/a8b90c0c645fd62ae850cd43e80c87bab4cc157d/patches/xnu-12377/native-shared-region-plain-auth.patch
[Z-DYLD]: https://github.com/none24smu/UniXNU/blob/a8b90c0c645fd62ae850cd43e80c87bab4cc157d/patches/xnu-12377/native-dyld-pager-plain-auth.patch
[XNU-SHARED]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/osfmk/vm/vm_shared_region.c
[XNU-DYLD]: https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/osfmk/vm/vm_dyld_pager.c
[U-LICENSE]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/LICENSE
[Z-LICENSE]: https://github.com/none24smu/UniXNU/blob/a8b90c0c645fd62ae850cd43e80c87bab4cc157d/LICENSE
