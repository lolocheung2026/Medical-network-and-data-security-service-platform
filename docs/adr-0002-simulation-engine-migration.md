# ADR-0002：v0.2 沙盘推演引擎迁移

日期：2026-09-23
状态：已接受（乐叔确认 4 项决策：全量迁入 / 内置拓扑先行 / API+报告页 / 结果落库）

## 背景

路线图 v0.2 = 沙盘推演引擎迁移：源沙盘 `2026-07-12-11-28-56/健康医疗数据安全沙盘/` 的
engine/（9 模块 4328 行，纯标准库零第三方依赖）与 scenarios/（18 场景 2894 行）接入平台，
驱动"攻防推演 + 整改报告"功能模块。

## 决策

1. **拷贝入库（否决外部引用）**：engine/ + scenarios/ 全量迁入 `app/simulation/`，
   修包内导入路径（源沙盘为 `from engine import ...` 绝对导入，共 3 处引擎文件 +
   18 处场景基类导入，Python 脚本批量替换并零残留验证）。
   否决方案 B（sys.path 挂载源目录）：耦合本机路径，GitHub 克隆即断，违背平台自包含。
2. **引擎库模式注册**：ScenarioManager 显式传场景模块路径列表（不依赖沙盘 config.py），
   进程级单例，18 场景注册一次、多请求复用推演现场。
3. **拓扑来源分期**：本迭代 = 场景内置拓扑；用户上传脱密拓扑替换场景拓扑留 v0.2.1
   （需先定义拓扑 JSON 格式对齐规范，工作量大，不并入本迭代）。
4. **一键推演语义**：reset → start → `_run_all_steps()`（顺序执行攻击步，内部处理前置
   依赖与防御判定）→ `generate_report()` → 落库。纯仿真，零接触真实网络。
5. **结果落库**：新增 `SimulationRun` 模型（tenant_id / scenario_id / status / result_json），
   符合表级租户隔离；报告中心与整改建议可追溯。
6. **前端分期**：本迭代 = 场景列表页 + 报告摘要/整改建议渲染（服务端模板 + 原生 JS）；
   Canvas/SVG 拓扑可视化渲染迁移留后续迭代（前端工程量约等于半个沙盘）。
7. **红线豁免（迁移资产）**：engine/scenario_base.py 单文件 1527 行，超过 300 行红线。
   迁移资产不改写重构，仅修导入；新代码仍守 300 行约束。

## 影响

- `app/simulation/`：engine/（9 模块）+ scenarios/（18 场景）+ routes.py（4 端点）+
  templates/simulation.html
- `app/models.py`：新增 SimulationRun
- 报告中心（`app/reports`）后续迭代可聚合 SimulationRun 输出整改报告

## 冒烟证据（2026-09-23 实测）

- 场景清单 18 个全量注册；ransomware/web_vuln/iot_medical 三场景推演成功落库
- 报告含 21 字段（summary/attack_steps/remediation/timeline/scorecard/aar + 免责声明）
- 租户隔离实测：第二租户历史为空、跨租户访问 run 记录 404
- 旧功能回归：合法字典脱密入库 ✓、PII 阻断 ✓

## 未决项

- 用户拓扑格式对齐规范（v0.2.1）
- 推演并发隔离：当前场景实例为进程级共享，多租户并发推演同一场景会互踩现场
  （假设性预判，未经证实；v1.0 前需评估 per-request 实例或加锁）
- 概率模式（prob_mode）默认关闭，平台入口暂未暴露，后续迭代补开关
