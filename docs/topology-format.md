# 用户拓扑 JSON 格式规范（v0.2.1）

版本：2026-09-26 · 状态：v1（ADR-0002 未决项落地）

## 用途

客户上传**经沙盒脱密后**的拓扑图（JSON），用于替换攻防推演场景的内置拓扑，
在客户自己的网络逻辑结构上跑仿真推演。原始拓扑上传入口 = 沙盒上传页
（kind=topology），脱密（IP 假名化/机构名假名化/PII 阻断）通过后才可被推演引用。

## 格式

```json
{
  "name": "我院网络逻辑拓扑（可选，≤64 字）",
  "nodes": [
    {"id": "his",  "label": "HIS服务器", "type": "server", "desc": "核心业务系统（可选）"},
    {"id": "pc1",  "label": "门诊工作站", "type": "workstation"},
    {"id": "fw",   "label": "边界防火墙", "type": "firewall"},
    {"id": "net",  "label": "互联网出口", "type": "external"}
  ],
  "edges": [
    {"from": "net", "to": "fw"},
    {"from": "fw",  "to": "pc1"},
    {"from": "pc1", "to": "his"}
  ]
}
```

## 校验规则（topology_spec.validate_topology）

| 字段 | 规则 |
|------|------|
| nodes | 必填数组，2-100 个 |
| node.id | 必填唯一，1-32 位 `[A-Za-z0-9_-]` |
| node.label | 可选，≤64 字，默认取 id |
| node.type | 可选，枚举：external / server / workstation / firewall / database / router / switch / iot / other（默认 other） |
| node.desc | 可选，≤200 字 |
| edges | 可选数组，≤500 条；from/to 必须引用已定义 node.id |
| edge.label | 可选，≤64 字 |
| 坐标 | 不接受用户坐标；平台按环形自动布局 |

## 语义说明

- 推演场景的攻击步引用内置节点 id（如 ransomware 场景的 his/pc1）；用户拓扑
  节点 id 与之不一致时，相关攻击步按「前置不满足」处理，报告会如实呈现。
- 建议：需要更贴合真实攻击链时，节点 id 尽量对齐内置场景命名（his/pacs/emr/
  backup/pc1/mailsrv/firewall/internet）。
- 数据红线：上传入口必经脱密引擎，检出 PII 值即整体拒绝（ADR-0003）。
- 并发隔离（假设性预判，未经证实）：场景实例进程级共享，用户拓扑在推演
  前后做备份/恢复；多租户并发推演同一场景仍存在互踩风险，v1.0 前评估
  per-request 实例化或加锁。
