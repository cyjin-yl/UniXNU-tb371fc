# Route A：MemoryManager 的 `0x719c` 调用边界

## 结论与范围

对固定 24A446 原始 `dyld` 的只读追踪，已把 `0x719c` 的直接调用明确到 **crossarch 查询 syscall**：调用目标 `0xa99c` 经 `0xa9d0` 设置 `X16=38`，执行 `SVC #0x80`。实际候选 XNU 的 syscall 38 是 `sys_crossarch_trap`；其已检查实现对这里传入的 namespace 0 返回 `ENOTSUP`，不写入用户输出指针。

这提供了一个具体的候选内核接口约定，但**没有将原局部路径检查改为通过**。最终 generated syscall table、链接实现、异常返回及用户内存条件仍未运行验证；调用返回后还会到达 `has_sec_transition` 的字符串查找和 commpage 读取。现有 [TPRO 报告](evidence/route-a-tpro-local-paths-20261123.json) 的 `0x719c` blocker 保持原样，审计器没有增加 syscall 白名单或跳过调用。

## 固定输入与已读片段

检查日期为 2026-11-23，环境为 CT102 的开发容器，Python 3.13.5、Capstone 5.0.6。解析复用 `audit_route_a_tpro.py` 的 Mach-O 候选范围和直接分支解码；该文件 SHA-256 为 `4376dfb49ca1c2f19c814d831e4ab81362952da8bca162198bd75edddf7e628d`。

原始输入为 iPadOS 27.0.1 / 24A446 / iPad17,3 的 `usr/lib/dyld`，1,447,088 字节，读取前重新核对完整 SHA-256：

```text
ab9887ed96c9c08ad68d4c6a5c27e8289fb0c9e55ec3e134547292a1ec579608
```

下列范围的地址与文件偏移在此输入中相同；结束地址不包含在片段内。公开记录只保存摘要与行为事实，没有复制函数反汇编或系统二进制。

| 已完整读取的目标片段 | 字节数 | SHA-256 |
| --- | --- | --- |
| MemoryManager `0x713c..0x7208` | 204 | `5b5ff1d3acc76f5376beec745a7b2ef370cf9617dea3c57ba93f5a7691656219` |
| 查询包装 `0xa99c..0xa9d0` | 52 | `8ec7f497c6b92b8122106cf58133365625d6722b2800e656035977214db909b6` |
| syscall stub `0xa9d0..0xa9dc` | 12 | `0a93fea11555ed8a905577afd8e8cb1c16f7159d619bee2b0438e622ed0395c8` |

## 调用点、入参和返回后的实际分支

1. 构造函数保存对象地址到 `X20`、apple 列表地址到 `X21`，并初始化对象字段。对象 `+0x21` 和 `+0x22` 在这段初始化中置零。当前局部 gate 仍假设 `0x7188` 首次访问时 `X0=0`，转到 `0x7194`；本次没有补全该假设的全部前驱。
2. `0x7194` 把调用者栈上的一字节临时值置零；`0x7198` 将它的地址放入 `X0`；`0x719c` 调用 `0xa99c`。
3. `0xa99c` 的包装另建栈帧，把收到的指针放进本帧的一槽中，设置 `X0=X1=X2=0`、`X3=该槽地址`，在 `0xa9c0` 调用 `0xa9d0`。后者以 `X16=38` 发出 `SVC #0x80`，随后普通返回；包装恢复栈帧并以原始 `RETAB` 返回。
4. `0x71a0` 检查返回的 `W0`。只有为零时才在 `0x71b0..0x71b4` 读取那个临时字节并写到对象 `+0x21`；非零路径读取原有的 `+0x21`。这两条路径随后按该字节最低位决定是否跳过下一次字符串查找。
5. 若查询返回非零且对象 `+0x21` 保持初始化的零，正常路径到达 `0x71bc`。`0x71c8` 再次调用 `0x6e78`，使用保存的 apple 列表及位于 `0xa5e36` 的 **`has_sec_transition`** 字符串。该返回非空时，对象 `+0x22` 被置 1。
6. `0x71d8..0x71e8` 还读取地址 `0xfffffc162` 的字节（commpage 基址加 `0x162`）；若 bit 7 为 1，则清除对象 `+0x22`。随后保存构造实参、恢复寄存器和栈，并在 `0x7204` 以原始 `RETAB` 返回。

这里的 `has_sec_transition` 与 `dyld_hw_tpro` 是两个实际不同的字符串。没有依据将前者直接解释为 TPRO 开关，也不能仅凭两个已知 TPRO key 缺失就省略这段后续路径。

公开 dyld 的 [Allocator.cpp](https://github.com/apple-oss-distributions/dyld/blob/fd8d0c4d52320ebf64db34f3cb280310d905c5ae/lsl/Allocator.cpp) 在 MemoryManager 构造函数中以 `rosetta_dyld_is_translated` 查询一个先清零的 bool，成功时才保存查询结果。这与本次包装和返回值分支的形状相符；该公开源码是另一份固定版本，**不能用它给封闭构建补充未观察到的符号或字段语义**。

## 候选 XNU 中实际核对到的接口

检查对象为已成功准备的 XNU `ac9718fb1af618d5ce8678d0dc6e8a58f252216f` 加 71 项所选 patch，原始源码 inventory SHA-256 为 `16aed427ee21f60f7e8697dbd21f1fce75db653749e677a787c4844c44a438b8`。以下行号属于实际补丁树。

| 路径 | 实际源码事实 |
| --- | --- |
| `osfmk/arm64/proc_reg.h`、`osfmk/mach/arm/thread_status.h` | syscall 编号寄存器为 16；64 位状态的 SVC number 从该寄存器取值。 |
| `osfmk/arm64/sleh.c`，2743–2787 | `handle_svc` 按 trap 编号分流；38 进入 Unix syscall 路径。 |
| `bsd/dev/arm/systemcalls.c`，90–207、372–414、468–541 | 选择 `sysent`；直接的 64 位调用从 `X0` 开始复制参数。非零错误写入保存状态的 `X0`、清 `X1` 并设置 carry。还存在配置相关的 syscall filter、审计和调试分支。 |
| `bsd/kern/syscalls.master`，92 | syscall 38 的接口为 `sys_crossarch_trap(uint32_t name)`；不是把 `X0` 当用户指针解引用。 |
| `bsd/sys/crossarch.h`，35–40 | namespace 0 对应当前合法 namespace 上限。 |
| `bsd/kern/kern_crossarch.c`，35–41 | 超出 namespace 上限返回 `EINVAL`；否则返回 `ENOTSUP`。该函数没有用户内存写入，也不使用 `X3` 所指的参数槽。 |
| `bsd/sys/errno.h`，114、146 | `EINVAL=22`，`ENOTSUP=45`。 |

因此，在**最终内核确实链接并执行这些实现、参数与正常异常返回符合上述约定**的条件下，这个调用的 namespace 为 0，返回 `W0=45`；dyld 的成功分支不取，临时输出字节仍为零。再假设构造对象未被其他写入改变，即可推导到后续 `0x71c8` 字符串查找。这个条件推导没有覆盖 syscall filter 的全部副作用、异常/信号、并发写入、用户栈可访问性或返回目标完整性。

固定公开基线可追溯至 [syscalls.master](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/syscalls.master)、[kern_crossarch.c](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/kern_crossarch.c)、[crossarch.h](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/sys/crossarch.h)、[ARM syscall 处理](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/dev/arm/systemcalls.c) 和 [SVC 分流](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/osfmk/arm64/sleh.c)。公开基线与实际补丁树的身份分别记录，不能把链接视为最终 kernel 的执行证据。

## 下一处应验证的具体依赖

- 完整 builder 生成的 syscall table、最终链接中的 syscall 38、实际 64 位异常进入/返回路径，需与这里已读源码核对。
- `0x71c8→0x6e78` 的字符串扫描需要独立的可读列表、终止、返回值和寄存器保持契约；本次只定位到它，没有重新证明其函数体。
- `0xfffffc162` 的字段意义、初始化与实际填充值尚未核验；不能在未经确认时直接假定为零或擅自设置。
- 原始包装和构造函数含 PAC 序言／返回。现有离线普通指针改写有自己的报告，本次没有重新验证这些片段在改写文件中的全部返回和栈语义。

本次没有执行 dyld 或 syscall，没有编译新的内核，也没有修改源码、审计器、任何 `verified` 标记或历史证据。`callee_bodies_verified`、`runtime_dispatch_verified`、完整 ISA 和系统启动仍保持未证明。

## 实际已读源码文件 SHA-256

| 文件 | SHA-256 |
| --- | --- |
| `bsd/kern/syscalls.master` | `0e22c8fa035bcdbd826e64afd9bf0bb85c4d2a6e8e43e503f278fdc5aab668d2` |
| `bsd/kern/kern_crossarch.c` | `07bfe90e3036a36bb0dcfb978dc0f11b218981b7a67d4834ac150b2f5c271a91` |
| `bsd/sys/crossarch.h` | `ab141a34762225d0411466c39bf3427dc2a65da58423a6304422cd81d650696d` |
| `bsd/dev/arm/systemcalls.c` | `7eb44232e6da37c8e6f5d2317ed5cf1d55d02032410b0ddf7007e4ca7b495df4` |
| `bsd/sys/errno.h` | `b16e5eb195f153793b14c3826e6b04db945e9ed6a37c5a9046196555bded6906` |
| `osfmk/arm64/sleh.c` | `4eeb208fb2510bfdc0338d1a1d7d2d702fe9eb65d332eea388720ef6574375d1` |
| `osfmk/mach/arm/thread_status.h` | `60434026c659eebe0137ad2dd6536637e7330cf355958f580afe95bc34a82e95` |
| `osfmk/arm64/proc_reg.h` | `5bdb14d2cc33dfa5d771f81794dea0a961801331be519904c02fdc6141f57ab5` |
