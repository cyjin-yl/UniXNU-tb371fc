# Route A 候选 XNU：TPRO 能力发布源码核对

## 输入与结论

只读核对对象为实际准备的 `WORK/kernel-prepared/tree`（公开路径占位符）：
XNU ac9718fb1af618d5ce8678d0dc6e8a58f252216f / xnu-12377.121.6，71 补丁，
status=sources_prepared，范围 architecture-darwin26-plain-pager。
Profile SHA-256: 4c555caf8bfb3d725d50d375c51bc555c562780bc20f33e70e657c4cfe76e70b。
6119 文件清单 SHA-256: 16aed427ee21f60f7e8697dbd21f1fce75db653749e677a787c4844c44a438b8。

完整读取 exec_add_apple_strings 的各添加分支及键宏后，可确认此函数的已检查实现
没有构造 dyld_hw_tpro 或 dyld_hw_tpro_pagers 项；另有 security_config 的明确发布通道。
这是一条源码级路径事实，不是整个最终内核/启动链不会发布能力的证明。
没有发现足以确认的误报 TPRO 硬件能力 bug，本轮没有修改内核或审计工具。

## 已确认的赋值路径

1. bsd/kern/kern_exec.c:2484 调用 exec_add_apple_strings。
   函数7056–7380完整读取；6936–7004键宏已展开核对。
   ip_applec初值1对应已保存的executable path，其后按明确分支追加各系统项。
   7313–7329明确追加 security_config=0x%x，值来自 task_get_security_config(task)。
   两个 dyld_hw_tpro* 键没有相应构造分支。需要继续检查向量之前的首项来源、
   其他组件及之后启动器/共享缓存dyld的向量变换，不能从此推断全程序不存在发布者。

2. kern_exec.c:1103–1105的TPRO entitlement表只保存
   com.apple.security.hardened-process.dyld-ro名称。
   exec_check_security_entitlement():1159–1188检查所选条目并返回状态；
   表条目本身不构造apple键、不证明CPU能力已启用。

3. osfmk/kern/task.h:186–203有独立tpro位域。
   task.c:9941–9958的宏生成getter/setter/clear；9974实例化tpro。
   task_get_security_config():9961–9964直接返回整个值，不按CPU能力过滤TPRO位。
   task.c:1496–1509在parent_task && inherit_memory时继承整个security_config。
   因此不能因未搜到直接setter调用就说该位永远为零；外部组件和继承仍有边界。
   若实际发现不一致，应追踪具体写入者，不能把整个security_config清零。

4. 已检查的非SPTM osfmk/arm/pmap/pmap.c:
   pmap_set_tpro_internal():12841–12844为空操作；
   pmap_get_tpro():12859–12862恒false；
   pmap_set_tpro():12848–12855根据XNU_MONITOR选择PPL包装/直接调用。
   最终链接哪个pmap实现仍须完整构建配置确认。

## commpage 与 CPU 宏

pmap_create_commpages():11415起：
XNU_MONITOR分支在11430/11433显式memset零；
非monitor分支11441调用pmap_pages_alloc_zeroed，RO映射别名指向同页。
本轮读到了调用点；扩展读取zeroed函数体的最后请求因设备断连失败，
未将未读的函数体计入新增证据。

commpage.c:106创建页，121调用能力初始化。
commpage_init_cpu_capabilities():879从bits=0开始；925–926写32/64位能力字段。
commpage.c:490–521的PAuth相关位由ID_AA64ISAR1_EL1字段条件设置，
所检查实现没有把BCM2837名称直接当成PAuth支持。

cpu_capabilities.h:335–368的已命名相关项为+c0/+c8、
+100/+104/+108，然后+120；已检查的头文件和填充实现没有为dyld读取的
+10c模式字节、+d0/+d8常量提供命名赋值。
条件推论：若选择该页创建/填充路径，zeroed分配约定成立，且没有其他写入者，
这些未填字段应保留零。尚未观察实际运行内核字节，也未排除裸地址写入。
不能为使新dyld接受模式而将+10c直接设成2/3/4；已见dyld据此进入
Apple寄存器或S1POE2路径。

BCM2837.h:8–24设置generic ARMv8和显式选择的PAN，无TPRO/SPRR/APRR/PAC定义。
board_config.h:307–315以ARM64_BOARD_CONFIG_BCM2837选择它。
当前成功探针contract.c只直接包含BCM2837.h，检查ordinary arm64、
ptrauth_calls关闭和无PAC宏；它没有展开整个generated config和最终链接选择。
尤其NO_MONITOR=1（EL3语境）不能等同XNU_MONITOR=0（PPL相关路径）。
macros.txt SHA-256: 9cfd7adf738270f3e0ee65c8e3c07ff0b690c8bae0c1500d0ab9dfada845b4af。

## 最小后续验证

- 对最终generated config/目标参数/所选pmap建立记录，不能沿用单头探针冒充全内核验证。
- 在exec完成、进入dyld前记录两个key的存在性、task的TPRO状态及security_config值。
  不公开完整apple向量中的熵和私有信息。
- 采样实际commpage模式字节、相关常量、CPU capability位，与实际CPU功能对应。
- 验证dyld自启动/切换到cache dyld、fork和重新exec后的相同约束。
- 这些步骤完成前，kernel boot、runtime dispatch、全部236处覆盖仍未证明。

## 实际文件 SHA-256

| 文件 | SHA-256 |
| --- | --- |
| bsd/kern/kern_exec.c | bd6670be93ce1f3c39a4a5dd9ba9d666afe33332d3b51d9dba4c0bd6afce6d33 |
| osfmk/kern/task.c | f76e453fa002df0efcc3fc71335642e552120effa324072a4993d9e47524d4e9 |
| osfmk/kern/task.h | 102b0b08628f94dbea11ed2577a3d13c5b3ee97aaf1f528bdfd5965e3640abc9 |
| osfmk/arm/commpage/commpage.c | f08701126879021d4f409356910a4b2833f32b2b2a9b1894f8bf28b72596ae81 |
| osfmk/arm/cpu_capabilities.h | 8936b19289b96b6249719fa641c29d31a2050cd7db39e4dc0e8b741b14f2975d |
| osfmk/arm/pmap/pmap.c | 9d50460dd488e98488be3629416bb9c7f7b57672f95515b1f00e217d3c0dd570 |
| osfmk/arm64/proc_reg.h | 5bdb14d2cc33dfa5d771f81794dea0a961801331be519904c02fdc6141f57ab5 |
| pexpert/pexpert/arm64/BCM2837.h | 72f19d77aeae88bbf67c75091f0041388fc41192ee5181d49d238889929c8d51 |
| pexpert/pexpert/arm64/board_config.h | 0e1e3e12f44de907a4fe70f5a7f865ebc4fbfbcdfa0731646a8041e47fe3e02f |

行号指上述实际补丁树。原始基线可追溯至
https://github.com/apple-oss-distributions/xnu/tree/ac9718fb1af618d5ce8678d0dc6e8a58f252216f ，
不以公开基线行号冒充实际补丁树行号。没有发布原始Apple反汇编或私有启动向量。

## 后续：七组实际预处理的限定进展

[实际 CPP 摘要](evidence/route-a-a01-cpp-20261127.json)与[启动合同增补](ROUTE_A_NONTPRO_STARTUP.md#七组真实-xnu-预处理的后续证据)补充了生成配置下的真实 `kern_exec` 正文：完整读取保存路径、apple 构造与字符串复制函数，确认首项固定前缀和 argv／envv／apple 的终止边界；所检查构造函数没有两个 TPRO 键，仍发布未证明取值的 `security_config`。这是所选成功路径的源码事实，未被推广为所有运行时发布者均无键。

这七组不包含 `task`、commpage、pmap／pmap_data 或 `vm_map`；上文关于这些组件的条件与最终链接／运行时缺口继续有效。新增预处理证据没有改变 A01、commpage、真实用户入口或 OS boot 的未验证状态。
