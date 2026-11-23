# Route A：fileset 未映射调用诊断的普通 ARM64 修复

## 实际失败和原因

第一次真实 XNU 构建已使用成功完成 19 项语义断言的定制 Clang 24，生成 716 个对象文件后失败。实际编译错误为 `osfmk/kern/debug.c:2590: this target does not support pointer authentication`。

该位置属于固定 UniXNU [fileset-unmapped-call.patch](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/patches/xnu-12377/fileset-unmapped-call.patch) 新增的 `unixnu_fileset_unmapped`。这个诊断函数无条件调用 `__builtin_ptrauth_strip`，即使构建目标为普通 `arm64-apple-ios27.0 -march=armv8-a`。因此即使它只在未映射的原始组件调用发生时进入 panic，编译器仍会拒绝它的函数体。

源错误不表示应启用 arm64e 或 PAuth。这个源码补丁不改变目标 CPU、普通指针约定或编译器配置；下文另列真实编译时发现的默认 CPU 问题。

## 最小修改

[route-a-fileset-unmapped-ptrauth.patch](../patches/route-a-fileset-unmapped-ptrauth.patch) 只修改这个函数：先读取一次返回地址；当编译器提供 PAuth intrinsics 时，保留原来的 key 0 strip；普通目标直接将原始返回地址传给 panic。

能力条件采用 `__has_feature(ptrauth_intrinsics) || defined(__PTRAUTH__)`，与固定 LLVM [ptrauth.h](https://github.com/llvm/llvm-project/blob/58c46bae21181fb4240cf964461bea738d96d50e/clang/lib/Headers/ptrauth.h) 的 intrinsic 可用性条件一致。仅检查 `ptrauth_calls` 会遗漏“支持显式 intrinsic，但没有启用 arm64e 调用 ABI”的配置；这由独立编译用例覆盖。显式 intrinsics 用法也见该 LLVM 版本的 [CodeGen 测试](https://github.com/llvm/llvm-project/blob/58c46bae21181fb4240cf964461bea738d96d50e/clang/test/CodeGen/ptrauth-intrinsics.c)。

函数的 `noinline`、`noreturn`、`used` 属性、panic 文本、两个参数和失败行为保持不变。未映射调用仍进入 panic；没有把它改成成功返回，也没有用编译开关给目标增加 PAC 能力。这个 strip 只为诊断取地址，不是指针认证成功的证明。

## 来源与固定摘要

输入为 XNU `ac9718fb1af618d5ce8678d0dc6e8a58f252216f`，加既有 71 项 architecture / Darwin 26 / plain-pager 补丁后的实际 `debug.c`。原来的 71 项准备结果与历史 inventory 保持原样，本修复作为后续 build-fix 层应用。

| 内容 | SHA-256 |
| --- | --- |
| 实际准备文件 `osfmk/kern/debug.c`，修复前 | `fd749f59d773dac9cb95f8183ff9dece13f2ae2888f5da6f2efd9197acc9e5b0` |
| 同一文件，修复后 | `061de685fab552a0031ab547d75600a16b9d993a54740b461760ebf038b8b5be` |
| 本地修复 patch | `d3bebb609f6f1b6d11018c9be3aec36e941625019845c442aea6cf9506e62abe` |

已在完整实际文件上执行 `git apply --check`、应用、反向检查和反向恢复；修复后与恢复后的完整文件摘要均匹配预期。上游新增函数遵循 UniXNU 的 BSD-2-Clause-Patent 许可；原 XNU 文件的版权和许可头未修改。

## 编译回归与范围

[专项测试](../tests/test_route_a_fileset_ptrauth.py) 将实际上游 helper 放入最小 freestanding translation unit，应用同一个 patch，再调用真实 Clang。`panic` 只有声明，带原有格式检查及 noreturn 契约；无需 Apple SDK，也不执行生成的目标程序。

```sh
ROUTE_A_FILESET_CLANG=/absolute/path/to/verified/clang \
  python3 -m unittest discover -s tests -p 'test_route_a_fileset_ptrauth.py' -v
```

四项检查分别要求：

- 原始无条件 strip 在普通 ARM64 上实际编译失败，并包含对应 PAuth 诊断。
- 修复后的 `arm64-apple-ios27.0 -mcpu=generic -march=armv8-a` 输出没有 PAuth intrinsic IR 或要求 PAuth 的指令，Mach-O 为 ARM64 subtype 0 / `MH_OBJECT`，panic 及两个参数仍保留。LLVM 为返回地址生成的 `XPACLRI` 位于 HINT 空间，在没有 PAuth 的架构上是 hint，不等同于要求 PAuth 的 `XPACI` / `XPACD`。
- arm64e 输出仍有 key 0 的 strip，Mach-O 保持 arm64e subtype，panic 及参数仍保留。
- 普通 ARM64 调用 ABI 配合显式 `-fptrauth-intrinsics` 时仍保留 strip，防止用 `ptrauth_calls` 错误裁掉支持的路径。

缺少 Clang 时该专项会明确跳过，不能算作编译验收完成；使用的编译器需要支持这些显式 PAuth 配置。当前专项已在同一真实定制 Clang 24.0.0git（LLVM `58c46bae…`）上取得 **4 / 4 通过、0 skipped**，编译器二进制执行前后 SHA-256 均为 `85d220e32bd83d75de788c8beab0bea646a4684e1112f7c06266ca71e651bb04`。

该次执行目录为 `fileset-pauth-probe-20261124-v3`，测试文件 SHA-256 为 `b04ae4bd4d954c7863235eeee6e9e2b41e70fa0504e135ebaaf7b3836b1e9f7f`，完整 `compile-tests.log` SHA-256 为 `65594fb3e3a53241691f55199193d8c78295eba2d190b111798d6e35e3d43e44`。额外保留的 `generic-codegen.json` SHA-256 为 `3458e3bd15c7639dae84347cc627e39d2ab8d7700d4546490e1dcb4f84011942`；它记录普通路径的 `target-cpu="generic"`、`+fp-armv8,+neon,+v8a`、`hint #7` 和实际 ARM64 对象头。源文件、IR、汇编及对象编译均在临时 `/tmp` 目录进行，未改动第一次内核构建树。

## 专项编译暴露的默认 CPU 风险

在实际定制 Clang 24 上，只有 `-target arm64-apple-ios27.0 -march=armv8-a` 时，IR 的 `target-cpu` 仍为 `apple-a12`。修复后的 helper 已成功通过前端、没有 PAuth intrinsic IR，但后端对 `__builtin_return_address(0)` 发出了 `xpaci x30`。第二次专项执行真实捕获了这个失败，不能把它解释为生产普通 ARM64 已满足指令集要求。

固定 LLVM 的 [AArch64 返回地址 lowering](https://github.com/llvm/llvm-project/blob/58c46bae21181fb4240cf964461bea738d96d50e/llvm/lib/Target/AArch64/AArch64ISelLowering.cpp) 根据 `Subtarget->hasPAuth()` 选择 `XPACI`，否则选择向后兼容的 `XPACLRI`（HINT #7）。专项的普通目标因而显式设置 `-mcpu=generic`；arm64e 正例显式设置 `-mcpu=apple-a12`。这区分了源码可用性修复与 CPU 选择契约，不能用修改后的单位测试替代生产 compiler wrapper / builder 参数的核对。

前两次专项的原始结果均保留：首次失败是 LLVM 24 将 `llvm.returnaddress` 更名为 `llvm.returnaddress.p0` 后的测试断言不兼容；第二次失败是上述真实 `XPACI` 指令。测试兼容两种 intrinsic 名称，并继续拒绝依赖 PAuth 的实际指令，没有把失败改为跳过。

## 构建环境与共享 codegen 检查

`prepare_route_a_toolchain.py` 生成的 `CROSS_EXTRA_FLAGS` 现在显式包含 `-mcpu=generic`；定制 Clang 的独立资格检查也为原 19 项语义断言使用普通 ARM64 / generic CPU，并增加返回地址 codegen 检查。这只改变新运行时生成的环境与验收代码，不重新安装编译器或改写已完成的旧执行记录。

共享入口为 `verify_return_address_codegen(clang, output, *, target_flags=(), env=None)`。它编译一个实际调用 `__builtin_return_address(0)` 的函数，检查 generic CPU 属性、返回地址 IR、PAuth intrinsic / 指令、ARM64 对象头，并保存每次命令、输出文件及摘要。`XPACLRI` / `hint #7` 允许通过。已有目录拒绝覆盖；失败会保留 `verification.json` 后抛出错误。

这个共享入口不会隐式补入 `-target`、`-mcpu` 或 `-march`。独立 Clang 检查明确传入这些参数；生产入口则应通过实际 CLT compiler shim、实际 builder 参数和实际构建环境调用，使 CPU 选择只能来自生产配置。测试覆盖了 Apple CPU、`XPACI`、错误对象 subtype、编译失败等拒绝分支；这些合成输出测试只证明验收逻辑，实际生产 shim 的通过结果应另行记录。

这些回归只验证该诊断函数的源码选择和生成结果。完整 XNU 编译／链接、所有文件的指令集、外部 archive、板级配置与设备启动均需要各自的后续证据。
