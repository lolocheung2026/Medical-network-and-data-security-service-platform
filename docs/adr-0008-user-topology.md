# ADR-0008：v0.2.1 用户拓扑格式对齐

日期：2026-09-26
状态：已接受

## 背景

ADR-0002 未决项：用户上传脱密拓扑替换场景内置拓扑。乐叔 2026-09-26
指示执行 v0.2.1。

## 决策

1. **拓扑 JSON 规范**（docs/topology-format.md）：nodes（id/label/type/desc）+
   edges（from/to/label）简洁格式，对齐场景内置拓扑结构；不接受用户坐标，
   平台环形自动布局。
2. **校验器**（app/simulation/topology_spec.py）：node id 唯一性/字符集、
   type 九类枚举、edges 引用完整性、数量上限（节点 100/边 500），错误逐条返回。
3. **引用方式**：POST /simulation/run/<sid> 传 JSON body {"topo_id": 已脱敏
   拓扑 upload id}；拓扑必须本租户、kind=topology、status=deidentified。
4. **共享实例防污染**：场景实例进程级共享，用户拓扑应用前备份
   (nodes/edges/node_states)，推演 finally 恢复——实测下一轮推演内置拓扑完整。
5. **语义**：攻击步引用的节点 id 与用户拓扑不一致时按前置不满足处理，
   报告如实呈现（不做智能映射，避免引入不可解释行为）。
6. **迁移资产只加不改**：scenario_base.py 仅新增 apply_user_topology 方法，
   reset 等既有逻辑不动。

## 影响

- app/simulation/topology_spec.py（新增，校验器）
- app/simulation/routes.py（topo_id 参数 + 备份恢复）
- app/simulation/engine/scenario_base.py（+apply_user_topology）
- app/templates/simulation.html（拓扑选择下拉）
- docs/topology-format.md（格式规范 v1）

## 冒烟证据（2026-09-26 实测）

- 用户拓扑上传 → 脱密入库（IP 假名化）
- 带 topo_id 推演：报告节点 = 用户 5 节点（firewall/his/internet/mailsrv/pc1）
- 随后无 topo 推演：内置 8 节点完整（backup/pacs 均在）——防污染生效
- 校验失败路径：非法 topo_id → 400

## 未决项

- 多租户并发推演同一场景互踩风险仍存（备份恢复只解决串行场景）
- 前端拓扑预览/编辑（上传后可视化确认）留后续迭代
