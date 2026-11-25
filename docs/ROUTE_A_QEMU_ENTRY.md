# Route A：独立 QEMU 入口诊断

`scripts/probe_route_a_qemu_entry.py` 把已有普通 ARM64 平台候选送入独立的标准 QEMU `virt`。它消费[真实 loader 合同](ROUTE_A_LOADER_CONTRACT.md)产出的 `kernel.load.bin`，在 `__start` 物理地址设置硬件断点，读取真实 PC／x0／PSTATE，再单步执行入口的 `B`，要求实际到达 `_start_first_cpu`。UART 中的“即将跳转”或翻译日志不会单独获得入口执行通过标志。

这是针对内核早期代码的实验入口。机器为单核 TCG、512 MiB RAM、GICv3，没有磁盘或网络设备；它不启动原厂 TB371FC QEMU、不接触平板，也不提供完整 Darwin 用户态。真实设备启动、UEFI 所有权、板级 ADT、iPadOS／macOS 启动都继续独立验收。

## 输入与布局

输入为固定的 `46eff436…` 平台候选、对应 loader 报告和内存映像。脚本重算候选与映像摘要、检查 loader 的三个实际通过标志与输入复核结果，并重新解析真实段、local relocation 和入口符号。它逐字节重建完整内存映像，包括段间间隙和 BSS；修改映像并同步修改报告摘要也不能获得通过。

默认物理布局如下，均位于本实验所拥有的 QEMU RAM：

| 对象 | 地址或约束 |
| --- | --- |
| QEMU RAM | `[0x40000000, 0x60000000)` |
| EL1 诊断 trampoline | `0x40080000`，最多占用 64 KiB |
| 内核物理基址 | `0x50004000`，低 21 位与固定虚拟基址一致 |
| `boot_args` | `0x52000000`，16 KiB 对齐 |
| 合成 ADT | `boot_args + 0x1000` |
| `deviceTreeP` | 对应的内核虚拟地址，保持零虚拟 slide |
| `topOfKernelData` | 16 KiB boot buffer 的物理末尾 |

检查同时覆盖内核与 boot buffer 不重叠、trampoline 不被覆盖、2 MiB block 的前缀属于 QEMU RAM，以及全部输入位于保守的初始映射范围。上游原入口实验的默认 `0x50000000` 物理基址不满足本候选的低 21 位条件；接近 RAM 尾部的 `0x5ff00000` boot buffer 也会被拒绝。

默认 `--adt qemu-virt` 生成小型 Apple 格式设备树，记录实际选定的 CPU 名称、GICv3、PL011 和 RAM。它没有 iPad 身份、Qualcomm UFS 占位节点、磁盘、ramdisk 或 trustcache。实际 trampoline 读出的计数器频率必须与 ADT 的 62.5 MHz 相符。256 字节随机种子保留在输出 ADT 中，结果报告绑定完整 ADT 摘要。`--adt none` 用于明确无设备树的边界实验，两个设备树 boot_args 字段均为零。

## 执行

需要 Linux、Python 3.11+、Clang／LLD／llvm-objcopy 和支持所选 CPU 的 `qemu-system-aarch64`。不需要运行 GDB 客户端：脚本通过仅位于输出目录的 Unix socket 使用 QEMU GDB remote protocol，先验证 QEMU 提供的 AArch64 寄存器 XML，再按已验证的布局读取寄存器。工具的调用路径保留 `ld.lld` 等 multicall 名称，实际指向的二进制身份另行记录。

QEMU 的 [`get_feature_xml()`](https://github.com/qemu/qemu/blob/v10.0.0/gdbstub/gdbstub.c) 会生成没有声明 `xmlns:xi` 的 `<xi:include>`。解析器仅支持这类已知的字面标签及本地 feature 名称，仍要求唯一 `aarch64` architecture、首个且唯一的 core include，以及全部 34 个 core 寄存器的名称、编号、位宽与顺序。它不展开 namespace 或 XInclude，不加载外部 DTD，不支持实体和内部 DTD subset；标准 `gdb-target.dtd` 声明只作为元数据接受。每份收到的原始 XML 和各段 qXfer 响应在解析前保存为 `gdb-*.xml`／`.responses.json`，报告保存其身份，解析失败也保留证据。

在满足主机资源与共享构建槽约定后执行；输出必须是仓库外的新目录：

```sh
python3 scripts/probe_route_a_qemu_entry.py \
  --kernel /absolute/link-attempt-004/mach.platform-link-probe.unstripped.noctf \
  --loader-report /absolute/loader-attempt-003/report.json \
  --loaded-image /absolute/loader-attempt-003/kernel.load.bin \
  --cpu cortex-a76 \
  --adt qemu-virt \
  --timeout 10 \
  --output /absolute/new/qemu-entry-attempt
```

工具可以通过 `--clang`、`--linker`、`--objcopy`、`--qemu` 指定。CPU 选择必须真实存在于所选 QEMU；不把 A76／A710 模型的结果当作 Snapdragon 870 实机资格。单次运行最多 60 秒，QEMU 的每份输出文件有 16 MiB 硬上限。观察第一条 QEMU 异常、达到时间／日志限制或 QEMU 退出后即结束；必要时先 SIGTERM、两秒后 SIGKILL，并回收子进程。异常是否致命仍由保存的日志与代码位置判断。

## 结果怎么读

输出包括 `report.json`、原始 UART／异常／stderr、编译命令与输出、trampoline、boot buffer 和合成 ADT。报告保存输入、工具及源码身份、QEMU 命令、实际 stop reason／退出码、子进程回收状态，以及入口单步前后寄存器。对首个异常能映射回候选时，另记虚拟地址、所属段与原指令字。

`status=qemu_entry_observed`、`qemu_kernel_entry_executed=true` 的含义限于实际单步证明的入口分支；`qemu_early_cpu_entry_observed=true` 表示观察到 early CPU 起点，不代表其函数体运行成功。运行时 slide、UEFI 分配、板级 ADT、TB371FC 内核资格和 OS boot 标志均保持 false。定时停止且未捕获异常，也不代表内核已经正常启动。

每次结束重新检查声明的输入与工具。任何变化都会令结果失败并清零入口通过标志。失败尝试与已有输出保留，新一次实验使用新目录；不要修改旧报告。GDB 断点仅用于观察，不修改原内核字节。未来新候选需先更新其 loader 合同与来源，不通过修改报告绕过固定候选门槛。

## 来源与回归

`scripts/route_a_qemu_entry/` 原样保留固定 UniXNU [`8542980d`](https://github.com/UniXNU/UniXNU/tree/8542980d02b4d2cc5c32ee3542de1760b2562aac) 的 `scripts/qemu-entry/entry.S`、`link.ld` 及完整 BSD-2-Clause-Patent `LICENSE`。`sources.json` 记录逐文件长度、SHA-256 和 Git blob，执行前核对。ADT 格式与平台字段参考同版本的 [`make-dt.py`](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/qemu-entry/make-dt.py) 和 [`devicetree.py`](https://github.com/UniXNU/UniXNU/blob/8542980d02b4d2cc5c32ee3542de1760b2562aac/scripts/unixnu/devicetree.py)；本入口只构造上述有限 QEMU 设备。

```sh
python3 -m unittest discover -s tests -p test_route_a_qemu_entry.py -v
```

回归覆盖输入改写、BSS 补零、入口证据、物理布局、ADT 资源一致性、GDB 校验／分包／RLE、意外 PC 以及 UART 意图与实际执行的区别。它们使用自写合成 Mach-O，不需要私有候选，也不会启动 QEMU；真实候选的运行结果另存本次证据，不能从单元测试推断。
