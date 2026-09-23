"""
攻击图引擎（B 档）：基于拓扑边做多路径可达分析 + 必经节点（瓶颈）识别。
替代"固定线性脚本"视角，呈现"从外部入口到关键资产的多条可达路径与横向移动通道"。
"""
from collections import deque


class AttackGraph:
    MAX_PATH_LEN = 16   # 最大路径节点数，防止路径爆炸
    MAX_PATHS_PER_TARGET = 40  # 单目标最多保留路径数

    def __init__(self, scenario):
        self.nodes = {n["id"]: n for n in scenario.nodes}
        self.edges = scenario.edges
        self.defenses = scenario.defenses
        self.defense_states = scenario.defense_states
        self.attack_steps = scenario.attack_steps
        self.step_states = scenario.step_states

        # 邻接表（有向）
        self.adj = {}
        for e in self.edges:
            self.adj.setdefault(e["from"], []).append(e["to"])

    def entry_nodes(self):
        return [nid for nid, n in self.nodes.items() if n["type"] == "external"]

    def target_nodes(self):
        """攻击步 effects 指向的目标节点，去重。"""
        tgts = []
        seen = set()
        for s in self.attack_steps:
            for ef in s.get("effects", []):
                t = ef["target"]
                if t not in seen and t in self.nodes:
                    seen.add(t)
                    tgts.append(t)
        return tgts

    def _all_paths(self, src, dst):
        """DFS 枚举 src→dst 的简单路径（限长、限量）。"""
        paths = []

        def dfs(cur, visited, path):
            if len(paths) >= self.MAX_PATHS_PER_TARGET:
                return
            if cur == dst:
                paths.append(list(path))
                return
            if len(path) >= self.MAX_PATH_LEN:
                return
            for nxt in self.adj.get(cur, []):
                if nxt in visited:
                    continue
                visited.add(nxt)
                path.append(nxt)
                dfs(nxt, visited, path)
                path.pop()
                visited.discard(nxt)

        dfs(src, {src}, [src])
        return paths

    def _sec_on_path(self, path):
        """路径上经过的安全设备节点（防御部署点）。"""
        sec = {"firewall", "gap", "isolator", "behavior"}
        return [nid for nid in path if self.nodes[nid]["type"] in sec]

    def analyze(self):
        entries = self.entry_nodes()
        targets = self.target_nodes()

        target_paths = []
        for t in targets:
            paths = []
            for src in entries:
                for p in self._all_paths(src, t):
                    secs = self._sec_on_path(p)
                    paths.append({
                        "source": src,
                        "target": t,
                        "nodes": p,
                        "length": len(p) - 1,  # 跳数
                        "via_defenses": secs,
                        "defended": len(secs) > 0,
                    })
            # 按路径长度排序（短路径=高优先级攻击面）
            paths.sort(key=lambda x: (x["length"], -len(x["via_defenses"])))
            target_paths.append({
                "target": t,
                "target_label": self.nodes[t]["label"],
                "target_type": self.nodes[t]["type"],
                "path_count": len(paths),
                "paths": paths[:self.MAX_PATHS_PER_TARGET],
            })

        # 必经节点（瓶颈）：在所有入口→目标路径中出现次数占比
        bottlenecks = self._bottlenecks(entries, targets)

        return {
            "entry_points": [{"id": nid, "label": self.nodes[nid]["label"]} for nid in entries],
            "target_count": len(targets),
            "targets": target_paths,
            "bottlenecks": bottlenecks,
            "total_paths": sum(t["path_count"] for t in target_paths),
        }

    def _bottlenecks(self, entries, targets):
        """统计安全设备/网络节点在所有路径中的出现次数，识别高频必经节点。"""
        counts = {}
        for t in targets:
            for src in entries:
                for p in self._all_paths(src, t):
                    for nid in p:
                        if nid in (src, t):
                            continue
                        counts[nid] = counts.get(nid, 0) + 1
        # 总路径数（用于计算经过占比）
        total = sum(1 for t in targets for src in entries
                    for _ in self._all_paths(src, t))
        result = []
        for nid, c in counts.items():
            n = self.nodes[nid]
            if n["type"] in ("firewall", "gap", "isolator", "behavior", "switch", "network"):
                result.append({
                    "node": nid,
                    "label": n["label"],
                    "type": n["type"],
                    "on_paths": c,
                    "ratio": round(c / total, 3) if total else 0,
                })
        result.sort(key=lambda x: -x["ratio"])
        return result[:8]
