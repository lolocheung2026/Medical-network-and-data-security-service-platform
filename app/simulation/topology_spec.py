"""用户拓扑 JSON 格式规范与校验（v0.2.1，ADR-0002 未决项落地）。

用户上传脱密拓扑（沙盒脱密后入库）用于替换推演场景内置拓扑。
格式对齐场景内置拓扑的 nodes/edges 结构，坐标由平台自动布局。

规范（docs/topology-format.md）：
{
  "name": "可选，拓扑名称",
  "nodes": [{"id": "his", "label": "HIS服务器", "type": "server", "desc": "可选"}],
  "edges": [{"from": "pc1", "to": "his", "label": "可选"}]
}
"""
import json
import math
import re

NODE_TYPES = {"external", "server", "workstation", "firewall", "database",
              "router", "switch", "iot", "other"}

RE_NODE_ID = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

MAX_NODES = 100
MAX_EDGES = 500


def validate_topology(text):
    """校验用户拓扑 JSON。

    返回 (ok, payload, errors)；ok=True 时 payload 为规范化拓扑
    （nodes 已补自动布局坐标）。
    """
    try:
        topo = json.loads(text)
    except json.JSONDecodeError as e:
        return False, None, [f"JSON 解析失败：{e}"]

    if not isinstance(topo, dict):
        return False, None, ["顶层必须是 JSON 对象"]

    errors = []
    nodes = topo.get("nodes")
    if not isinstance(nodes, list) or not (2 <= len(nodes) <= MAX_NODES):
        errors.append(f"nodes 必须为数组且数量在 2-{MAX_NODES} 之间")
        return False, None, errors

    seen = set()
    clean_nodes = []
    for i, n in enumerate(nodes):
        if not isinstance(n, dict):
            errors.append(f"节点[{i}] 必须是对象")
            continue
        nid = str(n.get("id", ""))
        if not RE_NODE_ID.match(nid):
            errors.append(f"节点[{i}] id 非法（1-32 位字母数字_-）")
        elif nid in seen:
            errors.append(f"节点[{i}] id 重复：{nid}")
        seen.add(nid)
        ntype = str(n.get("type", "other"))
        if ntype not in NODE_TYPES:
            errors.append(f"节点[{i}] type 非法：{ntype}（允许 {sorted(NODE_TYPES)}）")
        clean_nodes.append({
            "id": nid,
            "label": str(n.get("label", nid))[:64],
            "type": ntype if ntype in NODE_TYPES else "other",
            "desc": str(n.get("desc", ""))[:200],
        })

    edges = topo.get("edges", [])
    clean_edges = []
    if not isinstance(edges, list) or len(edges) > MAX_EDGES:
        errors.append(f"edges 必须为数组且不超过 {MAX_EDGES} 条")
    else:
        for i, e in enumerate(edges):
            if not isinstance(e, dict):
                errors.append(f"边[{i}] 必须是对象")
                continue
            src, dst = str(e.get("from", "")), str(e.get("to", ""))
            if src not in seen:
                errors.append(f"边[{i}] from 引用不存在的节点：{src}")
            if dst not in seen:
                errors.append(f"边[{i}] to 引用不存在的节点：{dst}")
            clean_edges.append({
                "from": src, "to": dst,
                "label": str(e.get("label", ""))[:64],
            })

    if errors:
        return False, None, errors

    # 自动环形布局（用户拓扑不带坐标，推演/渲染需要）
    n = len(clean_nodes)
    r = 60 * n / (2 * math.pi)
    for i, node in enumerate(clean_nodes):
        ang = 2 * math.pi * i / n - math.pi / 2
        node["x"] = round(640 + r * math.cos(ang))
        node["y"] = round(300 + r * math.sin(ang))

    return True, {
        "name": str(topo.get("name", ""))[:64],
        "nodes": clean_nodes,
        "edges": clean_edges,
    }, []
