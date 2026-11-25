# DarwinBoot：拥有初始映射前缀

固定 [DarwinBoot `3c757340`](https://github.com/UniXNU/DarwinBoot/blob/3c75734014cdab0acd9541e88057b7606ee7ae08/DarwinBootPkg/Driver/DarwinBoot.c) 的 `AllocateWindow()` 在连续 conventional-memory 区间内选择 kernel PA，使其低 21 位与 kernel VA 相等，再从该 PA 分配 `WindowSize` 字节。

当前普通 ARM64 候选的 VA 是 `0xfffffff007004000`，因此 PA 的低 21 位为 `0x4000`。已绑定的 XNU `start.s` 用 `memSize >> 21` 个 2 MiB block 建立初始映射，block descriptor 向下取整。由源码可推导：映射还覆盖 kernel PA 前 16 KiB，但原来的 `AllocatePages()` 没有取得这四页的所有权。它们当时属于空闲描述符，不代表分配后仍由 loader 独占。

这是分配范围与初始页表范围的缺口，尚无实机访问该前缀或因此崩溃的证据。源码推导的条件与 prepared `start.s` 摘要保存在 [配置](../configs/route-a-allocation-probe.json)；既有 [loader 合同](ROUTE_A_LOADER_CONTRACT.md) 绑定该 prepared source，不把这项新检查当作运行时页表观察。

## 最小变更

[补丁](../patches/route-a-darwinboot-owned-prefix.patch) 只应用于上述固定 DarwinBoot 版本。它将 kernel 地址与实际 UEFI 分配地址分开：

| 项目 | 修复后含义 |
| --- | --- |
| `AllocationAddress` | conventional-memory 区间内向上取整的 2 MiB 地址 |
| `AllocationSize` | `WindowSize + (Kernel.Base % 2 MiB)` |
| kernel `Address` | `AllocationAddress + (Kernel.Base % 2 MiB)` |
| `AllocatePages()` | 分配完整 allocation pair |
| `ZeroMem()` | 从 allocation base 清零前缀和原有 `Used` payload |
| `DarwinEnter()` cache 参数 | 完整 allocation pair |
| 失败后的 `FreePages()` | 释放同一 allocation pair；以非零 size 判断所有权，支持分配地址为零 |

`boot_args.physBase` 仍然是 kernel PA，`memSize` / `memSizeActual` 仍然是 `WindowSize`，`topOfKernelData`、ADT VA 和 entry PA 计算不变。额外前缀不成为广告给 XNU 的可管理 RAM。

以 PA `0x50004000`、window 256 MiB 为例：

| 区间 | 半开范围 |
| --- | --- |
| XNU 广告内存 | `[0x50004000, 0x60004000)` |
| 源码推导的初始 block 映射 | `[0x50000000, 0x60000000)` |
| 修复后的 UEFI 分配请求 | `[0x50000000, 0x60004000)` |
| 仍未被初始 block 映射覆盖的广告尾页 | `[0x60000000, 0x60004000)` |

补丁没有增加页表项，也没有宣称最后四页已映射。现有 `Used <= WindowSize - 2 MiB` 约束保证实际 kernel、boot_args、ADT 和 sidecar payload 位于初始映射内，前提是现有布局与该候选合同成立。前缀和 payload 被清零；其余尚未使用的分配区没有在这项修复中新增清零。cache 汇编收到完整分配范围，但本轮没有执行 cache 指令。

## 可重复的主机验证

新 [probe](../scripts/probe_route_a_allocation.py) 验证固定原始文件和补丁摘要，在新目录应用补丁，并分别提取原版／修复版的完整 `RunEnd()`、`AllocateWindow()` C 函数。它还提取 `Boot()` 中实际的 zero、entry 和 free 调用表达式。

提取的 C 以 `-std=c11 -O2 -Wall -Wextra -Werror` 编译，主机 adapter 提供合成 UEFI memory map、记录 `AllocateAddress` 请求，并验证请求完全落在 conventional-memory 联合区间中。`ZeroMem()` 在有 guard 的主机缓冲区实际执行；cache 和 free adapter 只记录调用参数。它们不证明真实固件服务或 cache 指令运行。

```sh
python3 scripts/probe_route_a_allocation.py prepare-sources \
  --output /absolute/new/darwinboot-allocation-sources

ROUTE_A_ALLOCATION_SOURCES=/absolute/new/darwinboot-allocation-sources \
  python3 -m unittest discover -s tests -p test_route_a_allocation.py -v

python3 scripts/probe_route_a_allocation.py run \
  --sources /absolute/new/darwinboot-allocation-sources \
  --output /absolute/new/allocation-run
```

仅下载固定公开 C、window helper、entry 汇编和原始许可证；原始 229 份设备来源清单保持不变。新检查没有修改既有 loader probe 或将补丁自动部署到固件。

回归覆盖原版前缀遗漏、零／最大 page-aligned 前缀、相邻乱序 free descriptors、保留区间断、差一页容量、分配失败及下一连续区重试、地址零分配／释放、非法对齐和溢出描述符，以及 guard、清零／cache／释放范围的一致性。源码派生的区间检查还覆盖全部 512 种 page-aligned 前缀。

当 `ROUTE_A_ALLOCATION_SOURCES` 缺失时，提取 C 的测试明确跳过，不能把该轮描述为完整回归。成功报告使用 `host_allocator_contract_verified`；`patched_firmware_compiled`、`uefi_allocation_verified`、`bootstrap_mapping_executed`、`cache_maintenance_executed`、`kernel_entry_executed` 和 `os_boot_verified` 均保持 false。真正的固件构建、实际 memory map／分配收据与设备启动仍需后续验收。
