# ADR-0010：沙盘原生推演工作台整体迁移

日期：2026-09-26
状态：已接受

## 背景

乐叔要求：平台「攻防推演」入口进入的操作界面与原安全沙盘 100% 一致
（操作方式、推演方式全部一致）。ADR-0002 曾将前端迁移留后续（"前端工程量
约等于半个沙盘"），本次执行该迁移。

## 决策

1. **前端资产整体迁入（零 JS 改动）**：原沙盘 templates/dashboard.html、
   scenario.html、static/css/style.css、static/js/app.js（1952 行）原样拷贝；
   JS 中硬编码路径（/api/...、/scenario/...、/static/...）在平台根级原样挂载，
   因此 app.js 一行未改。
2. **API 层全量适配**：原沙盘 30+ 端点薄转发平台 ScenarioManager（引擎方法
   100% 同源对应）；新增 sandbox_ui Blueprint（无前缀）挂载根级路径；
   全部端点加平台登录门禁（原沙盘无登录）。
3. **推演操作 100% 一致**：逐步攻击/防御切换/概率模式/行为模拟（蒙特卡洛）/
   脱敏开关/ATT&CK 覆盖/两轮整改闭环（remediate_sim）全部可用。
4. **拓扑库为已知边界**：TopologyManager 与 topology_library/topology_view
   页面不迁移——平台由「沙盒上传 + 用户拓扑」机制替代。相关端点返回明确
   "迁移中"提示，前端不崩。
5. **模板微调仅 3 处**：dashboard 导航链接改"返回平台"；scenario 返回按钮
   指向 /simulation/。其余零改动。

## 影响

- app/static/css/style.css、app/static/js/app.js（原样迁入）
- app/templates/sandbox_dashboard.html、scenario.html（原样迁入）
- app/simulation/sandbox_ui.py（新增，30+ 端点薄转发）
- app/simulation/routes.py：/simulation/ 改渲染沙盘工作台

## 冒烟证据（2026-09-26 实测）

- 工作台 200：18 场景卡片；场景页完整（Canvas/攻击步骤/防御/整改/资产 tabs）
- API 链：快照 8 节点 → start → attack s1 → defense d5 → report 21 字段 →
  reset → behavior_sim 蒙特卡洛（置信区间字段齐全）
- 浏览器实测（playwright）：Canvas 1060×652、攻击 7 条加载、点击主按钮后
  "第 1 轮推演 · 第 1/7 步"逐步动画运行、JS 零错误

## 未决项

- 拓扑库页面（topology_library/topology_view）迁移：依赖 TopologyManager 与
  文件解析器，是否需要 100% 一致迁移待乐叔确认
- 六步工作流（workflow/run）依赖拓扑库，迁移中
- 整改产物拓扑生成（apply_remediation）依赖拓扑库，迁移中
