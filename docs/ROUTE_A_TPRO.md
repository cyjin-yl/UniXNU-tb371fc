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

## 目前最有价值的下一步

1. 追踪实际 `dyld_hw_tpro=1` 字符串地址 `0xa5e9c` 的所有引用，确定是否会
   在早期启动重新加入 apple 向量，以及完整条件。
2. 从 `start` 的全部入口与分支出发验证 `0x4944`、`0x4aac` 附近路径，
   同时覆盖 Apple 寄存器路径；仅检查 TCHANGE 两个字是不完整的。
3. 把 `defaultTproStack` 的结果传播到每个 `ProtectedStack(bool)` 调用点。
4. 为每个受影响函数记录“哪个能力检查支配哪些指令”的证据，然后对全部
   236 处做覆盖核对。未知路径继续保留为阻塞项。
5. 在相匹配的普通 arm64 XNU 中验证 apple 向量、commpage 和 VM 保护行为，
   再进入实际用户态启动测试。

本轮 [CI](https://github.com/cyjin-yl/UniXNU-tb371fc/actions/runs/45173610144) 已运行通过本工具的 **19 项合成回归**。新增脚本尚未对实际原始 dyld 产出本轮已核验的报告；既有二进制取证仍以上方首轮记录为准。

回归测试覆盖直接分支的符号偏移、系统寄存器编码类别、ADR/ADRP 引用的边界、
非代码数据排除、严格来源绑定、两类能力键和报告不覆盖行为：

```sh
python3 -m unittest discover -s tests -p 'test_route_a_tpro.py' -v
```

合成测试通过只说明审计器的这些检查工作正常，不说明实际 dyld 的所有硬件
路径已经不可达，也不说明 iPadOS 已在平板运行。
