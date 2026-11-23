# 项目开发约定

## 当前方向

- 目标设备为 Lenovo TB371FC / Snapdragon 870 / Adreno 650。
- 当前路线 A：离线 arm64e 转普通 arm64，CPU 原生执行，使用全链路普通指针 ABI。先 iPadOS 27.0.1 / 24A446，macOS 27 独立验证。
- 工作仓库是 cyjin-yl/UniXNU-tb371fc。入口为 README、DEVELOPMENT、ROADMAP 和 docs/evidence/README.md。
- iPadOS 17 / V135 是继承的上游历史记录，不是本轮 27 或当前设备的复现结果。
- 当前尚未启动 27。进入桌面之后仍需完成 ROADMAP 的整机硬件、稳定性和性能验收。

## 实现与证据

保持严格 Mach-O／代码边界／CFG／proof／签名页检查。未支持的形式给出具体原因；不通过放宽校验、添加人工地址根或静默跳过残留指令制造成功。普通指针转换不保留 PAC 认证，也不是通用的去 PAC 算法。

dyld 仍保留 FEAT_S1POE2 指令；审计 decoder 成功与运行时路径可用分别记录。apple 向量中的 dyld_hw_tpro 按存在性启用，字符串值 0 不能当作禁用。

完整内核构建、局部 C 函数测试、设备内核启动、Darwin 进程启动、图形桌面和硬件验收分别记录。不要以某一层的成功更改其他层的 verified 状态。新增证据绑定真实输入、版本、执行范围及跳过项；历史 JSON 不重写为本轮结果。

## 来源与文件

保留复用代码的版权／许可证／固定 commit 和原始摘要。upstream/source-manifest.json 对应原始 229 份源码及许可证；有意修改受固定清单覆盖的代码时先明确其来源和验证策略，不靠重算清单掩盖变化。

源码仓库只保存源码、配置、补丁、文档和可公开的证据摘要。大型工作树、Apple 系统文件、设备固件、生成镜像、私有备份、账号及原始设备日志放在仓库外。

## 验证与提交

开发环境和完整命令以 DEVELOPMENT.md 为准。常规验证入口：

```sh
python3 scripts/check_repository.py
python3 scripts/check_catalog.py
ROUTE_A_XNU_PREPARED_DIR=/absolute/path/to/verified/tree \
  python3 scripts/check_route_a.py
```

prepared tree 由 scripts/prepare_route_a_xnu.py 准备；缺失时 C 测试会跳过。报告实际通过、失败和跳过数，不把部分检查标作完整回归。

优先为实际语义或失败模式加入有价值的回归；文档整理用链接与命令核对即可。完成合理范围的验证后提交，说明问题、改动行为、证据和具体剩余项。硬件操作遵循当前会话授权与设备工作区的实际约定。
