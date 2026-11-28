# Route A：27 用户态与 TB371FC 内核的集成缺口

## 2026-11-28 更新：真实目标 kernelcache 与兼容基线

**当前 Route A 构建并运行的是公开 XNU 12377.121.6 的普通 arm64 兼容候选。** 固定的[上游 iPadOS profile][U-IPAD]明确选择该源码，并用补丁补入较新接口；本仓库原有 README 和下文初始评估也将它列为 XNU 12377。这是有意的跨版本兼容路线。本次取得的原厂二进制补充了目标版本与实际依赖，现有 12377 构建和 CoreCrypto 运行成果继续保留。

### 同一官方输入的实际观测

沿[原有输入提取方法](ROUTE_A_EXTRACTION.md)及留存的源 URL，使用现有 `ipsw v3.1.750` 只读取[Apple 官方 24A446 恢复包](https://updates.cdn-apple.com/2026FallFCS/6074e110-d48d-40c2-b0e8-b611520941a3/iPad17,1,iPad17,2,iPad17,3,iPad17,4_27.0.1_24A446_Restore.ipsw)中的 KernelCache 成员。完整 IPSW 为 11,654,176,243 字节；本次没有下载整包、加载该内核或执行 provider。

| 项目 | 实际读取结果 |
| --- | --- |
| 目标与成员 | iPadOS 27.0.1 / 24A446；`iPad17,3`、`j820ap`；BuildManifest 的 `kernelcache.release.ipad17` |
| 解压内核 | 80,035,840 字节；SHA-256 `38e6d9fa5f789b8228f4617ef4c6d2a3fd8ab564abdc9b62920f1db53fc1780a`，与固定 profile 的 kernelcache pin 一致 |
| 内核自身版本字符串 | `Darwin Kernel Version 27.0.0: Thu Aug 13 21:42:06 PDT 2026; root:xnu-13432.2.10~2/RELEASE_ARM64_T8142` |
| 装载形态 | `MH_FILESET`，308 个 fileset entries；原厂 provider 位于同一 KC 的共享段 |
| `com.apple.security.AppleImage4` | 版本 7.0.0；`MH_KEXT_BUNDLE`、CPU subtype `0xc0000002`（arm64e）；符号表 `nsyms=0` |
| `com.apple.driver.AppleMobileFileIntegrity` | 版本 1.0.5；同为 arm64e `MH_KEXT_BUNDLE`、`nsyms=0` |

提取命令可使用同一工具和新的输出目录重现；它按指定设备选择 kernelcache：

```sh
ipsw extract --remote --kernel --device iPad17,3 \
  --output NEW_OUTPUT_DIRECTORY --json --json-format artifacts \
  'https://updates.cdn-apple.com/2026FallFCS/6074e110-d48d-40c2-b0e8-b611520941a3/iPad17,1,iPad17,2,iPad17,3,iPad17,4_27.0.1_24A446_Restore.ipsw'
```

本次使用的工具二进制 SHA-256 为 `b1fbe15d8619523d431ab418ac5a32f765c6a6385453527fd75336d035fb5db3`，与原有提取工具 pin 相同。版本、load commands 和依赖来自实际 Mach-O 与 `__PRELINK_INFO`，不是从 profile 名字推算。官方文件和私有提取产物继续保存在源码仓库外。

### 与当前运行结果的关系

[CoreCrypto 正负运行](ROUTE_A_CORECRYPTO.md)已经在 QEMU virt 的 12377 候选中越过真实 POST、PRNG、消费者和 kmem crypto 初始化；下一处实际 panic 为 `image4 interface not available`。该候选是普通 arm64 `MH_EXECUTE`，没有包含上述原厂 fileset providers。现有 `img4_interface_register`、`image4_v2_interface_register`、AMFI 表布局适配属于接收实现的接口；它们本身不提供 Image4/AMFI 验证实现。

KC 中两个 provider 的代码、数据和 `__LINKEDIT` 分散在共享文件偏移，不能把一个 Mach-O header 后的连续切片当作独立可链接对象。它们的 arm64e 指针/调用约定、已剥离符号和 13432 依赖，还没有与当前 12377 普通指针 ABI 完成匹配。固定 profile 的 `darwin=25.5.0` 和 Darwin 26 补丁说明的是所选兼容基线；本次 KC 的实际版本为 Darwin 27，不能把前者用作完整目标 ABI 的证明。

`__PRELINK_INFO` 声明 AppleImage4 依赖 CoreTrust、corecrypto、IOCryptoAcceleratorFamily 和相应 kernel KPI；AMFI 还依赖 ApplePMGR、CoreAnalyticsFamily、AppleImage4 及 `com.apple.security.Image4`。这些是需要解析、装入和初始化的真实依赖，尚未证明在当前候选内可用。

### 已核对的公开源码与下一接入前提

2026-11-28 UTC 查询 Apple 官方仓库：[精确 `xnu-13432.2.10` ref](https://api.github.com/repos/apple-oss-distributions/xnu/git/ref/tags/xnu-13432.2.10)返回 404，[`refs/tags/xnu-13432` 前缀查询](https://api.github.com/repos/apple-oss-distributions/xnu/git/matching-refs/tags/xnu-13432)返回空列表；同一接口的[`xnu-12377.121.6` 阳性对照](https://api.github.com/repos/apple-oss-distributions/xnu/git/ref/tags/xnu-12377.121.6)正常存在。[官方 macOS 26.5 分发清单](https://github.com/apple-oss-distributions/distribution-macOS/blob/macos-265/release.json)将 XNU 映射到 12377.121.6，[官方 `distribution-iOS` 的 `refs/tags/ios-27` 查询](https://api.github.com/repos/apple-oss-distributions/distribution-iOS/git/matching-refs/tags/ios-27)为空。因此本次没有找到可 pin 的官方 13432.2.10 匹配源 tag；结论限于这些实际查询的官方 refs 和分发清单。

接下来保留已验证的 12377 路线，推进真实 provider 接入：

1. 准备固定的 XnuPrelink 工具与符号参考。当前工作树的 `kits/XnuPrelink` 目录为空，profile 指定的 `build/xnu/fileset-reference/mach.release.bcm2837.unstripped.noctf` 也不存在；应先补齐真实输入，再检查跨版本调用能否全部解析。
2. 对所选 provider 的代码和指针完成普通 arm64 约定转换及依赖解析。profile 中的 bring-up 选项 `--allow-missing` 与未映射调用报告桩不能作为依赖已闭合的结果。
3. 使真实 Image4/AMFI 实现在 trust-cache 初始化前注册，保留原有签名、信任与失败路径；以实际内核运行为接入结果。
4. 若日后核验到精确官方新源，另开匹配源码路线并复用当前成果；本次不替换 12377 源码，也不把原厂 arm64e provider 记作已经适配。

以下保留 2026-11-23 的初始源码评估，涉及“尚未编译”等表述按当时范围阅读。最新构建、QEMU 运行和 provider 输入结果以上述更新及相应实际运行记录为准。

---

审计日期：2026-11-23。范围是源码与构建配方的只读比对；没有编译候选内核，没有安装或启动 27 系统。本文的“27”分别指上游固定的 iPadOS `27.0.1 / 24A446` 与 macOS `27.3 / 26C5035r`，不表示任意后续 27 版本。[U-IPAD] [U-MAC]

## 判断与证据范围

**现有 V135 产物不能直接充当已经具备 27 ABI 的测试内核。下一步应建立独立的 plain-arm64、XNU 12377 源码构建目标，合入必要的 27 ABI 和无 PAC pager 修复，再验证 27 的最小进程闭包。** 当前公开 V135 入口只从固定父内核派生显示补丁，并校验结果的固定 SHA-256；它没有完整 XNU 源码构建或替换为新内核的入口。[L-BUILD] [L-RESUME] [L-BUILDER]

本轮设备只读检查由主任务记录为 Android 14、bootloader locked / verified boot green；本文没有取得或检查该设备对应的 V135 私有内核。仓库 README 中的 V135 / iPadOS 17.7.11 历史记录，与本轮连接设备的现状必须分开。历史桌面、GPU 和触摸结论不构成本轮 27 启动证据。[L-README] [L-RESUME]

| 对象 | 本次能核验的证据 | 不能据此推出的结论 |
| --- | --- | --- |
| 本仓库 V135 | 公开构建器、固定父镜像派生规则、输出内核摘要；完整源码重建明确未完成 | 未取得的实际内核已经带有 27 syscalls、v5 plain-auth 或新的 dyld pager ABI |
| 当前 Route A 转换器 | 本仓库已接入严格 Mach-O 边界、PAuth 指令规则及完整 cache proof gate | 实际 27 全部代码可以转换；未知新指令/JIT 可以在 A77 执行 |
| UniXNU 主线 27 profile | 固定 XNU revision、OS 输入身份、patch series、arm64e 构建与 prelink 配方 | 该 profile 可直接运行在没有 PAC 的 Snapdragon 870 |
| zeta fork | 源码中的 plain-auth、small-page pager 修复；README 对特定 iOS 26 / SM8350 启动的记录 | 所有这些修复已存在于 TB371FC 内核，或已在 TB371FC / 27 验证 |

主线审计 commit 是 `8542980d02b4d2cc5c32ee3542de1760b2562aac`；zeta 设备仓库是 `eb489285a1d9153872f00c93ebb519a269b249b5`；zeta 内核 fork 的 `ios26-ufs-owner-root` 是 `a8b90c0c645fd62ae850cd43e80c87bab4cc157d`。下面的外部链接固定这些 revision，不依赖移动分支。[U-IPAD] [Z-README] [Z-SHARED]

## 1. 上游 27 profile 的实际内核

两个 27 profile 都固定 `xnu-12377.121.6`，源码 commit `ac9718fb1af618d5ce8678d0dc6e8a58f252216f`，Darwin 标记 `25.5.0`。profile 注释说明其采用补入 Darwin 26 接口的旧一代公开内核；macOS profile 另记录原厂 kernel 为 `xnu-13432.60.57`。这是所审计配方的事实，不应扩展为“本文已核验截至今天 Apple 所有公开源码的发布状态”。[U-IPAD] [U-MAC]

`profiles/os/*/patches/xnu/series` 首先选择 `darwin26-syscalls.patch`、`darwin26-kpi.patch`、`darwin26-shared-region.patch`。这些是兼容实现，并非整个 Darwin 26 内核的替代证明。例如：[U-IPAD-SERIES] [U-MAC-SERIES]

| 补丁中的接口 | 具体实现及对验证的影响 |
| --- | --- |
| syscall 148 `pipe2`、149 `dup3` | 新增实现，处理相应 close-on-exec / close-on-fork 等标志；旧内核相应槽原为 `nosys` |
| syscall 214 `fchflagsat`、215 `getumask` | 增补目录相对操作与读取 umask |
| syscall 246 `aio_readv`、247 `aio_writev` | 明确返回 `ENOTSUP`，依赖调用方回退；不是完整 vectored AIO 支持 |
| syscall 249 `fsctlat`、352 `guarded_ftruncate_np` | 增补相应 VFS / guarded-fd 路径 |
| 新 cdhash / TrustCache KPI | 增补带长度参数的入口，但仍以旧内核 20-byte cdhash 为支持范围；不能假设支持新接口允许的全部 hash 长度 |
| `vfs_context_iopolicy_unassigned_0x8000` | 因旧内核没有该 policy 位，兼容实现返回 false |
| AMFI / Image4 / Sandbox / APFS KPI | 涉及 TrustCache interface v5、Image4 v2 注册、MAC policy 参数及 cluster 更新，不仅是几个 syscall 编号 |

上表逐项来自 [U-SYSCALLS]、[U-KPI]。即使所有补丁成功应用，也要对本次提取的 27 `launchd`、`dyld`、libsystem 与所选 kext 闭包做静态导入和运行时失败记录；不能由“文件名叫 27”或“源代码能 link”推断 syscall、Mach trap、commpage、pthread/workqueue、dyld SPI 全部兼容。

## 2. arm64e 配方与 A77 的关键冲突

27 profile 的 `os.arch = arm64e` 进入 `profiles/arch/arm64e/patches/xnu/series`。其中 `native-pac-keys.patch` 在 `BCM2837.h` 的 `__arm64e__` 分支定义 `HAS_APPLE_PAC` 和 `HAS_NATIVE_PAC`，并在 `PAC_INIT_KEY_STATE` 写入 APIA/APIB/APDA/APDB/APGA key registers。`native-pac-arm64-user-jop.patch` 还会在 EL0/EL1 切换时控制 PAC keys。[U-ARCH] [U-PAC] [U-JOP]

这组改动面向具备硬件 PAC 的非 Apple CPU。对于本路线的无 PAC A77，不能保留 arm64e kernel code 再期待关闭一个开关即可正常执行。新目标必须明确选择普通 arm64 编译和链接，并检查生成代码及外部 archives / kexts 的 ISA。与此同时，不能直接退回旧 `profiles/arch/arm64`：它的 series 主要指向 `patches/xnu/` 的旧版本补丁，27 要用的是重新审计后的 `patches/xnu-12377/` 基线。[U-ARCH] [U-ARCH64] [U-BUILD]

`CPU_SUBTYPE_ARM64_ALL` 只解决转换后用户映像的架构选择问题。它不会新增缺失 syscall，不会调整 kernel C++ vtable，也不会替 pager 把 authenticated pointer 转为普通指针。[L-CONVERTER] [U-SYSCALLS] [Z-DYLD]

## 3. 必须成套接通的指针和页路径

### Shared-cache 的两条问题不能混为一条

第一条是**页尺寸与链位置**。16 KiB slide page 的链可能从前一个 4 KiB 部分跨入当前页。主线 `native-4k-shared-region-slide.patch` 增加 `vm_shared_region_slide_part_v5()`、每部分 chain-start 缓存以及 `shared_region_pager_peek()`；在读取前页前释放当前 source page，避免 APFS 完整性 page-in 等待自己持有的 busy page。zeta 较早的 `native-shared-region-small-pages.patch` 使用 scratch buffer 方案。二者是同一路径的不同实现，不能把两份 pager patch 不加比对地叠加。[U-SLIDE] [Z-SMALL]

第二条是**无 PAC 时是否真正写回解析后的地址**。zeta `native-shared-region-plain-auth.patch` 给 `vm_shared_region_slide_page_v3()` 和 `_v5()` 的 authenticated 分支增加 `!__has_feature(ptrauth_calls)` 下的普通地址写回。主线新增加的 `vm_shared_region_slide_part_v5()` 中，同一 authenticated 分支的写回仍位于 `#if __has_feature(ptrauth_calls)` 内，没有无 PAC 的 `else`。所以，仅合入 zeta 旧补丁的两处 hunk，仍会漏掉主线新增的分块 v5 路径。[Z-SHARED] [U-SLIDE]

建议以主线较新的分块 pager 为基准，分别检查并覆盖 v3、v5 整页和 v5 分块三条路径；普通 auth target 必须正确加上 `value_add`、slide，并只写回属于当前页的目标。非 auth 指针的 high8 行为、链增量、空页标志和 bounds 要保持原语义。这里的结果是整个进程一致的 plain-pointer ABI，不提供 pointer authentication。[Z-SHARED] [U-SLIDE]

### 非 shared-cache 的 dyld pager 也需要处理

zeta 还有独立的 `native-dyld-pager-plain-auth.patch`：它使 `vm_dyld_pager.c` 的 `fixupPageAuth64()` / `fixupCachePageAuth64()` 在无 PAC 编译中可达，并让 `signPointer()` 对被支持的 A-key 路径输出普通地址。`fixup_page()` 不能再用 `HAS_APPLE_PAC` 把 arm64e pointer-format cases 整段排除。[Z-DYLD]

这说明“保留 chained fixups，让改写后的 dyld 处理”不是所有加载路径的充分条件：当 dyld 使用内核 map-with-linking 服务时，内核本身也要理解这些格式。27 实际采用的 pointer formats、bind ordinal、addend、页大小和失败返回必须从真实输入确认；zeta 26-era patch 不能自动覆盖未来格式。[Z-DYLD] [L-CONVERTER]

### 四种页尺寸需要分别记录

需要单独记录 CPU translation granule、XNU VM `PAGE_SIZE`、CodeDirectory hash page size、dyld slide page size。zeta 后期 `NativeAdreno-16k-vm.patch` 明确允许 4 KiB translation granule 上的 16 KiB VM page；因此不能把某次 zeta“4K”描述解读为所有层都固定 4096。[Z-GPU-PAGES]

主线 `native-4k-user-abi.patch` 则统一普通 4 KiB 构建的 runtime page shift、用户 map、commpage 和 shared-region submap。CodeDirectory 可选择离线重签为 4 KiB，或使用内核 `native-4k-signature-hash-cache` 从验证过的原 16 KiB block 派生 4 KiB hash。两种方案应明确选择、记录和验证，不能把“cache 已重签”当成所有 standalone、kext、supplemental signature 都已适配。[U-PAGES] [U-USER-PAGES] [L-CACHE-REWRITE]

## 4. 下一步集成表

“本仓库已有”只指公开源码或明确记录，不表示本轮设备已载入这些组件。

| 顺序 / 层 | 本仓库已有或可复用 | 27 / Route A 需要补齐 | 可接受的下一项证据 |
| --- | --- | --- | --- |
| 1. 构建目标 | V135 固件打包、显示派生、来源清单 | 新的 TB371FC arm64 + xnu-12377 profile；不能覆盖 V135 常量与恢复入口；`board.toml` 仍是 `example=true`、无完整组件配方 | resolver 输出精确 commit、patch order、arm64 compile target、完整 archive 列表 [L-BUILDER] [L-BOARD] [U-BUILD] |
| 2. CPU / kernel ISA | TB371FC CPU、启动、平台适配源码；用户态转换规则 | 不启用 `HAS_NATIVE_PAC`；审计新 kernel、archives、prelinked kext 的非 A77 指令 | 编译记录和输出 ISA census；无需要 PAC hardware 的代码路径 [U-PAC] [L-CONVERTER] |
| 3. Kernel/user ABI | 历史 iPadOS 17 用户态记录 | 上述 Darwin 26 syscalls/KPI、Mach/dyld/libsystem 接口逐项确认 | syscall/导入清单与 microprobe 结果；fallback、ENOTSUP 单独记载 [U-SYSCALLS] [U-KPI] |
| 4. Shared-cache pager | 已有 offline cache proof/rewrite；上游有分块 pager | 合入分块算法及 v3/v5/part-v5 的 plain-auth 写回 | 有跨 4 KiB 边界、首链在后页、无 rebase、坏 bounds、并发 page-in 的独立向量及 kernel 观测 [U-SLIDE] [Z-SHARED] |
| 5. Dyld chained pager | 转换器保留原 chained-fixup metadata | 审计并移植 `native-dyld-pager-plain-auth`；拒绝未知 27 format | 实际 27 dyld 使用的服务/格式得到记录；bind 与 rebase 结果一致 [Z-DYLD] |
| 6. 签名与 trust | 转换器重算受支持的 SHA-256 CodeDirectory；默认保留 policy 字段 | 匹配 AMFI/TrustCache ABI、原输入 trust entries、owner trust 输出与页签名策略 | 每页验证、原 trust attribute 来源、输出 hash 绑定；不把 26-era platform byte 写成 27 [L-CONVERTER] [U-KPI] |
| 7. APFS / root / Data | UFS 与 root 相关源码，V135 私有包接口 | 当前目标的 APFS/crypto/AMFI 闭包、27 OS/SystemOS 与新 Data；若沿用旧闭包，需独立文件系统兼容证据 | 可追溯 closure report、只读 root mount 和目录/文件读取；不是只有 IPSW 下载成功 [U-IPAD] [L-BUILD] |
| 8. Kext ABI | 21H461 显示/HID/GPU 适配 | 新内核结构布局、metaclass、vtables、导出符号与闭包匹配；先允许最小 console/headless 路径 | 未匹配调用为零，或具体不可达路径有单独证据；不能以 `--allow-missing` 作为通过 [U-IPAD] [L-DISPLAY] |
| 9. ELF/Mach-O 到 EL0 | 本轮指令 microprobe 与 synthetic Mach-O 测试设施 | 在目标 Darwin kernel 上先验证普通小程序，再验证转换后的 27 dyld 和受控小客户端 | 实际 EL0 PC、返回值、异常与 loader 日志；Android ELF 成功不等于 Darwin ABI 成功 [L-CONVERTER] |
| 10. 27 PID 1 | 上游 27 profile 与 zeta 26 的历史参考 | 完整匹配的 launchd + dyld + cache/standalone closure、root/Data、commpage/syscalls | 新候选启动产生 PID 1，并在缓存映射后持续工作；单次跑第二个 launchd 的退出码不算 [U-IPAD] [Z-README] |
| 11. macOS 增量 | 同一 A77 指令转换机制可继续复用 | macOS target 的 KPI/IOKit 布局、地址空间、8 GiB shared region、root union/firmlinks、额外服务 | 先完成 macOS 最小用户态，然后再做登录与图形；不能复用 iPadOS 成功判定 [U-MAC] [U-MAC-VA] [U-MAC-REGION] [U-MAC-MACHINE] |

macOS 的 VA 问题已经发生在 `launchd` 所用 allocator 层：上游 `macos-user-address-space.patch` 记载 xzone 固定映射到 455–512 GiB 的需求；`macos-shared-region-size.patch` 为所选 cache 把 region 改为 8 GiB。这些不是显示驱动后期才遇到的问题。[U-MAC-VA] [U-MAC-REGION]

## 5. 实质依赖与阻断项

1. **本轮没有合格的可启动新内核。** 没有持有/核验 V135 私有父镜像；即使取得它，也只能证明 V135 的固定派生。公开设备仓库还没有完整新 XNU build wiring。必须保存新源码、配置、patch order、工具链和 archive 的身份，建立可复现候选。[L-BUILD] [L-BUILDER] [L-BOARD]
2. **27 profile 的 kext 闭包不是无条件可用。** iPadOS profile 指定 kernelcache digest、固定 slide、AMFI early-security 入口和 symbol-bearing reference，同时带有 bring-up 用的 `--allow-missing`。源 kernel 能 link 不代表所有原厂 kext 调用都已匹配；更不能直接在 A77 执行其中未处理的 arm64e code。[U-IPAD]
3. **SDK/工具链应按实际步骤区分。** V135 固件入口强制原生 macOS。上游当前已提供 Linux XNU toolchain（定制 Clang、cctools/MIG/IIG 等）和 Linux header preparation，不能声称“没有 Mac 就绝对不能编译新内核”。另一方面，设备 ABI builders、某些 SDK 引用、原厂 KDK/系统输入、Data image 工具仍需按选中配方准备。zeta 旧 `build-xnu-12377.sh` 明确使用固定 KDK，而主线新 builder 的输入路径不同；不能把两个 recipe 的依赖混用。[L-BUILDER] [U-HOST] [U-BUILD] [Z-BUILD]
4. **真实 27 输入闭包需要本地保存并绑定身份。** launchd 与 dyld 两个文件不足以构成可启动系统；还需所有 subcache、动态依赖、trust、root/SystemOS/Data 及 kernelcache/kext ABI 输入。公开仓库只保存清单、摘要和可分发源代码，不放 Apple 系统、设备备份、固件或生成镜像。[U-IPAD] [U-MAC] [U-CONTRIBUTING] [L-BUILD]
5. **许可证按组件计算。** UniXNU/zeta 的适配代码采用 BSD-2-Clause-Patent；XNU 自带 APSL-2.0 及逐文件声明，不能把整棵改过的 XNU 自动改标 BSD。默认 source-provider recipe 还指向 `corecrypto-2023` commit `11fba65b12d8830630e248dfa8344caf8b065f26`；已读取该 commit 的 `License.txt`，其中许可限定为下载后 90 天内的内部安全性/正确性验证，且禁止再分发。因此不能仅凭外层仓库的 BSD 许可宣称整个 kernel/provider 可自由再分发。适用授权或替代实现需要单独解决；本文没有复制该 provider 或 Apple 二进制。[U-LICENSE] [XNU-LICENSE] [U-FEEDS] [CC-LICENSE]

这些条件中，CPU/loader/pager/ABI 是运行正确性工作；构建输入与许可证决定能否复现和分发相应产物。二者不能靠放宽转换器 proof gate 相互替代。

## 6. 可独立完成的下一份小提交

建议先做 **plain-arm64 27 profile 的静态检查器和 pager 算法向量**，而不把未经构建的候选写成可启动 profile：

- 输入只含固定 upstream revisions、目标 XNU 版本、架构、所选 patch series 和它们的 SHA-256；校验目标是 `arm64`、所有架构补丁来自匹配的 12377 基线、Darwin 26 ABI patches 已列入，并拒绝启用 native-PAC 配方。
- 对准备后的源代码检查 `vm_shared_region_slide_page_v3`、`_v5`、`slide_part_v5`、`vm_dyld_pager::signPointer` 四条路径是否具备显式 plain-pointer 分支；输出“检查通过/缺失”的报告，不输出“可启动”。不能仅搜索补丁文件名，因为旧两处 plain-auth hunk 覆盖不到新增 part-v5 函数。
- 抽取或独立实现可审计的 v5 单页/分块重定位测试函数，用手工编码的 auth/nonauth 指针链比较完整 16 KiB 参考结果与四个 4 KiB 请求结果。覆盖非零 slide、high8、跨页链、从后页开始、空页、坏链范围；另保留真实 kernel 的锁/页生命周期验证为未完成事项。
- 增加一份 syscall/KPI 需求清单，将上述八个 syscall entries 的“完整实现/ENOTSUP 回退/未验证”分开。实际 27 二进制提取后把 imports、syscall wrappers 和失败日志附到清单，而不是推测其使用了哪些调用。

这个小提交不需要私有 OS 二进制或设备写入，可先确定合并策略是否漏项。后续才是新 XNU 源码构建、最小硬件启动、完整 27 输入审计与 PID 1 验证。本文没有实现这份后续提交。

## 固定来源

### 本仓库

- [L-README] [README](../README.md)：V135 历史状态。
- [L-BUILD] [BUILDING](BUILDING.md)：V135 输入及构建边界。
- [L-RESUME] [V135-RESUME](V135-RESUME.md)：内核派生与验证范围。
- [L-BUILDER] [build_v135.py](../scripts/build_v135.py)：`KERNEL_SHA`、`patched()`、`full_xnu_source_build=False`。
- [L-BOARD] [board.toml](../board.toml)：`example=true`、17.7.11 profile、空 component wiring。
- [L-DISPLAY] [v135-display-timing-query.patch](../patches/v135-display-timing-query.patch)：21H461 方法/槽位适配。
- [L-CONVERTER] [Route A vendor 说明](../scripts/route_a_zeta/README.md)：plain-pointer contract 与现有转换范围。
- [L-CACHE-REWRITE] [rewrite-zeta-dyld-cache.py](../scripts/route_a_zeta/rewrite-zeta-dyld-cache.py)：`--page-shift`。

### UniXNU 主线

- [U-IPAD] [iPadOS profile](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/os/ipados-27.0.1-24A446/profile.toml)
- [U-MAC] [macOS profile](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/os/macos-27.3-26C5035r/profile.toml)
- [U-IPAD-SERIES] [iPadOS patch series](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/os/ipados-27.0.1-24A446/patches/xnu/series)
- [U-MAC-SERIES] [macOS patch series](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/os/macos-27.3-26C5035r/patches/xnu/series)
- [U-ARCH] [arm64e patch series](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/arch/arm64e/patches/xnu/series)
- [U-ARCH64] [arm64 patch series](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/arch/arm64/patches/xnu/series)
- [U-PAC] [native-pac-keys.patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/native-pac-keys.patch)
- [U-JOP] [native-pac-arm64-user-jop.patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/native-pac-arm64-user-jop.patch)
- [U-SYSCALLS] [darwin26-syscalls.patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/darwin26-syscalls.patch)
- [U-KPI] [darwin26-kpi.patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/darwin26-kpi.patch)
- [U-SLIDE] [native-4k-shared-region-slide.patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/native-4k-shared-region-slide.patch)
- [U-USER-PAGES] [native-4k-user-abi.patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/native-4k-user-abi.patch)
- [U-PAGES] [Four-kilobyte pages](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/docs/xnu/four-k-page-tables.md)
- [U-MAC-VA] [macos-user-address-space.patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/os/macos-27.3-26C5035r/patches/xnu-12377/macos-user-address-space.patch)
- [U-MAC-REGION] [macos-shared-region-size.patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/os/macos-27.3-26C5035r/patches/xnu-12377/macos-shared-region-size.patch)
- [U-MAC-MACHINE] [macos-machine-config.patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/os/macos-27.3-26C5035r/patches/xnu-12377/macos-machine-config.patch)
- [U-BUILD] [build-xnu-4k-baseline.sh](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/build-xnu-4k-baseline.sh)
- [U-HOST] [Requirements](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/docs/guide/requirements.md)
- [U-FEEDS] [feeds.toml](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/feeds.toml)
- [U-CONTRIBUTING] [CONTRIBUTING](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/CONTRIBUTING.md)
- [U-LICENSE] [UniXNU LICENSE](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/LICENSE)

### zeta 与其他原始许可文本

- [Z-README] [zeta README](https://github.com/none24smu/UniXNU-zeta/blob/eb489285a1d9153872f00c93ebb519a269b249b5/README.md)：前部 Stage 表曾落后于后部已记录的 bounded runtime 观察；本文不把任何单次观察扩展为 TB371FC 验证。
- [Z-SHARED] [native-shared-region-plain-auth.patch](https://github.com/none24smu/UniXNU/blob/a8b90c0c645fd62ae850cd43e80c87bab4cc157d/patches/xnu-12377/native-shared-region-plain-auth.patch)
- [Z-SMALL] [native-shared-region-small-pages.patch](https://github.com/none24smu/UniXNU/blob/a8b90c0c645fd62ae850cd43e80c87bab4cc157d/patches/xnu-12377/native-shared-region-small-pages.patch)
- [Z-DYLD] [native-dyld-pager-plain-auth.patch](https://github.com/none24smu/UniXNU/blob/a8b90c0c645fd62ae850cd43e80c87bab4cc157d/patches/xnu-12377/native-dyld-pager-plain-auth.patch)
- [Z-BUILD] [build-xnu-12377.sh](https://github.com/none24smu/UniXNU/blob/a8b90c0c645fd62ae850cd43e80c87bab4cc157d/scripts/build-xnu-12377.sh)
- [Z-GPU-PAGES] [NativeAdreno-16k-vm.patch](https://github.com/none24smu/UniXNU-zeta/blob/eb489285a1d9153872f00c93ebb519a269b249b5/package/NativeAdreno-16k-vm.patch)
- [XNU-LICENSE] [XNU APPLE_LICENSE](https://github.com/apple-oss-distributions/xnu/blob/main/APPLE_LICENSE)：许可总文本；具体 source revision 仍应保存其逐文件声明。
- [CC-LICENSE] [固定 corecrypto provider 的 License.txt](https://github.com/ONLYA/corecrypto-2023/blob/11fba65b12d8830630e248dfa8344caf8b065f26/License.txt)：本次直接读取的固定输入许可；也比对了 [Apple 发布的许可](https://github.com/apple/corecrypto/blob/main/License.txt)。

[L-README]: ../README.md
[L-BUILD]: BUILDING.md
[L-RESUME]: V135-RESUME.md
[L-BUILDER]: ../scripts/build_v135.py
[L-BOARD]: ../board.toml
[L-DISPLAY]: ../patches/v135-display-timing-query.patch
[L-CONVERTER]: ../scripts/route_a_zeta/README.md
[L-CACHE-REWRITE]: ../scripts/route_a_zeta/rewrite-zeta-dyld-cache.py
[U-IPAD]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/os/ipados-27.0.1-24A446/profile.toml
[U-MAC]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/os/macos-27.3-26C5035r/profile.toml
[U-IPAD-SERIES]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/os/ipados-27.0.1-24A446/patches/xnu/series
[U-MAC-SERIES]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/os/macos-27.3-26C5035r/patches/xnu/series
[U-ARCH]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/arch/arm64e/patches/xnu/series
[U-ARCH64]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/arch/arm64/patches/xnu/series
[U-PAC]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/native-pac-keys.patch
[U-JOP]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/native-pac-arm64-user-jop.patch
[U-SYSCALLS]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/darwin26-syscalls.patch
[U-KPI]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/darwin26-kpi.patch
[U-SLIDE]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/native-4k-shared-region-slide.patch
[U-USER-PAGES]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/native-4k-user-abi.patch
[U-PAGES]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/docs/xnu/four-k-page-tables.md
[U-MAC-VA]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/os/macos-27.3-26C5035r/patches/xnu-12377/macos-user-address-space.patch
[U-MAC-REGION]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/os/macos-27.3-26C5035r/patches/xnu-12377/macos-shared-region-size.patch
[U-MAC-MACHINE]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/profiles/os/macos-27.3-26C5035r/patches/xnu-12377/macos-machine-config.patch
[U-BUILD]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/build-xnu-4k-baseline.sh
[U-HOST]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/docs/guide/requirements.md
[U-FEEDS]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/feeds.toml
[U-CONTRIBUTING]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/CONTRIBUTING.md
[U-LICENSE]: https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/LICENSE
[Z-README]: https://github.com/none24smu/UniXNU-zeta/blob/eb489285a1d9153872f00c93ebb519a269b249b5/README.md
[Z-SHARED]: https://github.com/none24smu/UniXNU/blob/a8b90c0c645fd62ae850cd43e80c87bab4cc157d/patches/xnu-12377/native-shared-region-plain-auth.patch
[Z-SMALL]: https://github.com/none24smu/UniXNU/blob/a8b90c0c645fd62ae850cd43e80c87bab4cc157d/patches/xnu-12377/native-shared-region-small-pages.patch
[Z-DYLD]: https://github.com/none24smu/UniXNU/blob/a8b90c0c645fd62ae850cd43e80c87bab4cc157d/patches/xnu-12377/native-dyld-pager-plain-auth.patch
[Z-BUILD]: https://github.com/none24smu/UniXNU/blob/a8b90c0c645fd62ae850cd43e80c87bab4cc157d/scripts/build-xnu-12377.sh
[Z-GPU-PAGES]: https://github.com/none24smu/UniXNU-zeta/blob/eb489285a1d9153872f00c93ebb519a269b249b5/package/NativeAdreno-16k-vm.patch
[XNU-LICENSE]: https://github.com/apple-oss-distributions/xnu/blob/main/APPLE_LICENSE
[CC-LICENSE]: https://github.com/ONLYA/corecrypto-2023/blob/11fba65b12d8830630e248dfa8344caf8b065f26/License.txt
