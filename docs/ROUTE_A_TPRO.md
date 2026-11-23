# Route A：dyld 的非 TPRO 启动契约

本页把 **TPRO 证据收集** 和 **普通 arm64 可执行性证明** 分开记录。
`audit_route_a_tpro.py` 是只读审计器，固定到已经提取的
iPadOS 27.0.1 / 24A446 / iPad17,3 原始 `usr/lib/dyld`。
它列出下一轮需要逐一处理的指令、字符串引用和直接分支，并检查输入是否仍是
同一份文件。它不修改或模拟 TCHANGE，也不将这些静态信息升级为开机成功。

已有二进制取证见
[route-a-dyld-tpro-20261123.json](evidence/route-a-dyld-tpro-20261123.json)。
该记录观察到部分非 TPRO 分支，全部 236 处 TCHANGE 的入口门控仍未证明。
新增审计器输出的真实输入报告应由下方命令重新生成；没有提交新的整程序门控结论。

## 固定输入

| 属性 | 值 |
| --- | --- |
| 文件 | `usr/lib/dyld` |
| 产品、系统、构建 | iPad17,3 / 27.0.1 / 24A446 |
| 文件大小 | 1,447,088 字节 |
| SHA-256 | `ab9887ed96c9c08ad68d4c6a5c27e8289fb0c9e55ec3e134547292a1ec579608` |
| 已观察的 TCHANGEF x0, #2 | 116 处，字 `0xd5900040` |
| 已观察的 TCHANGEB x0, #0 | 120 处，字 `0xd5940000` |

这套地址和字符串断言只接受上述**原始**文件。改写后的普通 arm64 文件有不同
SHA-256，审计器会拒绝；另一系统构建也不会因为文件名同为 dyld 而通过。
计数断言用于发现取证流程变化，不能替代控制流证明。

## 启动契约必须包含两个独立开关

Apple 公开 dyld 源码把两类能力分开：

| apple 向量键 | 对应能力 | 普通 arm64 路径的约束 |
| --- | --- | --- |
| `dyld_hw_tpro` | 硬件 TPRO heap，以及 protected stack 的先决条件 | 不应提供此键值项 |
| `dyld_hw_tpro_pagers` | DATA_CONST 的 TPRO pager 策略 | 不应提供此键值项 |

这些是进程启动的 **apple 向量**，不是 Android shell 环境变量。
`dyld_hw_tpro=0`、`dyld_hw_tpro_pagers=0` 和空值仍然是存在的键值项。
审计器把它们列为不满足非 TPRO 契约；裸键名被单独列为格式不明确的项并保守拒绝。

公开源码证据是
[DyldProcessConfig.cpp](https://github.com/apple-oss-distributions/dyld/blob/fd8d0c4d52320ebf64db34f3cb280310d905c5ae/dyld/DyldProcessConfig.cpp)
中的 `defaultTproHW()`、`defaultTproDataConst()` 和
`defaultTproStack()`。
该公开源码版本不声称与 24A446 的封闭构建完全对应。
第一项的部分门控已经在实际 dyld 中观察到；第二项和完整早期启动需要继续对
实际二进制验证。

仅检查输入向量还不够。早期启动可能构造新向量、切换到 shared-cache dyld，
或者经过带有独立条件的回调。因此还需证明以下条件：

1. 实际启动流程不会在后续重新插入上述能力键。
2. commpage 中公布的能力与 Cortex-A77 的实际指令集一致。
3. dyld 的普通 `mprotect` / VM 保护回退可以工作。
4. protected-stack 对象的构造实参和各回调入口均遵循禁用状态。
5. shared-cache dyld、之后加载的库及子进程入口遵循相同契约。

## 可重复的只读审计

在已经安装 `requirements-route-a.txt` 的环境运行：

```sh
python3 scripts/audit_route_a_tpro.py \
  --input /path/to/original/usr/lib/dyld \
  --report /path/to/new-tpro-audit.json
```

输出报告的路径必须尚不存在。原始文件不被改写。
审计器验证整个输入的固定 SHA-256、Mach-O 几何和 CodeDirectory 代码页，
然后生成：

- 所有候选指令范围内的 TCHANGE 地址、指令字及操作数。
- 系统寄存器访问清单，以及 `s3_6_c15_c1_5`、
  `s3_3_c4_c0_3` 两类已知重点寄存器的逐处记录。
- 通过 ADR 或紧邻 ADRP + ADD 形成的两个已知字符串地址的静态引用。
- 指向所选启动函数区间的外部直接分支，以及直接的 protected-stack 构造调用。
- 四个固定分支的保守局部路径检查，区分可闭合的禁用路径和仍需调用契约的路径。
- 始终为 false 的整程序、目标 ISA、运行时分派和系统启动验证标记。

字符串引用扫描只覆盖明确实现的编码模式。经 GOT、数据指针或非相邻计算得到
的地址仍需另查，故 `literal_references_complete` 保持 false。
候选范围不是可达代码的证明；直接分支清单也不是完整调用图。

若已有合法取得的启动 apple 向量，可以把它保存为 JSON 字符串列表并附加：

```sh
python3 scripts/audit_route_a_tpro.py \
  --input /path/to/original/usr/lib/dyld \
  --apple-vector /path/to/captured-apple-vector.json \
  --report /path/to/new-tpro-audit.json
```

报告只输出两类能力键的检查结果，不复制整份向量内容。
`non_tpro_keys_absent=true` 只表示给定列表满足这一局部约束；
它不会把 `runtime_dispatch_verified`、`commpage_verified` 或
`vm_protection_verified` 改为 true。

`--include-disassembly` 可额外输出选定函数的反汇编窗口，供本地进一步取证。
这些诊断窗口和系统二进制留在开发环境；提交仓库的成果应以审计器、原始合成
测试、来源标识和精简结论为主。

## 从指令清单到局部路径检查

`local_gate_analyses` 将四个已经观察到的分支固定到原始文件及具体指令字段。
分支种类、条件、寄存器、宽度或跳转目标有一个不符，就返回 `gate_mismatch`，
不会继续采用旧假设。

| 局部入口 | 首次采用的条件边 | 检查边界 |
| --- | --- | --- |
| MemoryManager，`0x7188` | CBZ X0 → `0x7194` | 到构造函数结尾 `0x7208`；`0x719c` 的调用需要单独契约 |
| defaultTproStack，`0x2128c` | CBZ X0 → `0x212e0` | 到 `0x212f0`；实际片段为寄存器恢复、栈恢复和返回 |
| ProtectedStack，`0x3cb4c` | CBZ W1 → `0x3cb58` | 到 `0x3cb68`；实际片段跳过栈分配调用 |
| ReadOnlyCallback，`0x3048` | B.NE → `0x31e4` | 到 `0x3284`；回调及其前置 protected-stack 路径仍需单独处理 |

这里**假设首次执行该分支时满足指定条件**。检查器从这个入口追踪正常控制流，
对其后的条件分支同时探索两边。若循环再次回到同一个入口，第二次及后续访问
不再强制选择禁用边，因为中间代码可能改变条件。这一点有专门反例测试：重复
套用首次条件会错误地把循环之后可达的 TCHANGE 隐藏掉。

到达已知 TCHANGE 或两类重点系统寄存器访问时，报告会保留可达路径作为反例。
遇到未知指令、未证明的调用、间接跳转、软件异常、越过函数区间、进入非指令
候选范围或耗尽状态预算时，结果保持不完整；检查器不把这些缺口当成返回或
普通顺序执行。它只在所有已探索正常路径都闭合且没有经过这些已知危险指令时，
设置局部字段 `conditional_region_without_tracked_hazards=true`。

这个局部字段不表示整个函数都由该分支支配，也不表示内存访问一定不会异常。
以下内容仍明确为未证明：到入口的所有前驱、条件值的数据来源、被调用函数、
返回值及返回目标、终止性、完整 TPRO 指令覆盖及运行时能力分派。局部路径只在
普通 LR 返回指令处结束；使用其他返回寄存器的 RET 会作为间接目标缺口阻塞。
即使一个没有危险指令的
循环构成闭合区域，`termination_verified` 也继续为 false。

局部路径检查按需要逐条解码；完整诊断反汇编仍须显式选择
`--include-disassembly`。默认报告没有整段 Apple 函数反汇编。

## 实际早期字符串引用的用途

在本页固定 SHA-256 的实际 dyld 中，静态相邻引用把
`dyld_hw_tpro=1` 定位到了 `start` 的 `0x4518`。
`0x452c` 至 `0x4548` 逐字节读取并比较 14 字节，匹配时转到 `0x3d08`；
不匹配时在 `0x454c` 读取下一个指针，列表用尽时转到 `0x3c88`。
这段引用是**读取和比较字符串**，不是将字符串写入 apple 向量。

这一发现只解释已经找到的引用。相邻 ADR(P) 扫描不能排除其他寻址形式，
仍需要核对输入指针的来源、进入比较循环的分支及成功/失败后各自路径，
不能据此宣布早期启动已不可能重新发布能力键。

## 目前最有价值的下一步

已完成的候选 XNU 源码核对见 [内核 TPRO 能力发布](ROUTE_A_TPRO_KERNEL_PUBLICATION.md)。检查到的 `exec_add_apple_strings` 没有构造两个 `dyld_hw_tpro*` 项，但明确发布 `security_config`；task 状态可继承，最终 pmap／commpage 配置也尚未由完整内核确认。这些事实限定后续检查位置，尚不构成整个启动链的非 TPRO 证明。

1. 补全实际 `dyld_hw_tpro=1` 比较循环的前驱和输入指针来源，并覆盖不能由
   相邻 ADR(P) 扫描找到的引用。分清能力检测、普通内存访问与能力发布。
2. 从 `start` 的全部入口与分支出发验证 `0x4944`、`0x4aac` 附近路径，
   同时覆盖 Apple 寄存器路径；仅检查 TCHANGE 两个字是不完整的。
3. 把 `defaultTproStack` 的结果传播到每个 `ProtectedStack(bool)` 调用点。
4. 为每个受影响函数记录“哪个能力检查支配哪些指令”的证据，然后对全部
   236 处做覆盖核对。未知路径继续保留为阻塞项。
5. 在相匹配的普通 arm64 XNU 中验证 apple 向量、commpage 和 VM 保护行为，
   再进入实际用户态启动测试。

首轮工具集成的 [CI](https://github.com/cyjin-yl/UniXNU-tb371fc/actions/runs/45173610144) 通过了 19 项合成回归。本次新增局部控制流检查后，专项测试为 **33 项通过**，并已对固定原始 dyld 实际重跑：四个分支匹配，其中两个条件区域闭合，另外两个在已记录的调用／异常／间接转移处保持不完整。见 [真实输入局部路径报告](evidence/route-a-tpro-local-paths-20261123.json)。全程序分派、完整 ISA 和启动状态仍为未验证。

回归测试覆盖直接分支的符号偏移、系统寄存器编码类别、ADR/ADRP 引用的边界、
非代码数据排除、严格来源绑定、两类能力键和报告不覆盖行为，以及局部路径的
分支变化、回到入口、未知解码、调用、间接跳转、异常、范围和预算反例：

```sh
python3 -m unittest discover -s tests -p 'test_route_a_tpro.py' -v
```

合成测试通过只说明审计器的这些检查工作正常，不说明实际 dyld 的所有硬件
路径已经不可达，也不说明 iPadOS 已在平板运行。
