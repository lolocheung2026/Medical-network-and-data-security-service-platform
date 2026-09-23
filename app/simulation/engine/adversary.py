"""
攻击者智能体 + 蒙特卡洛仿真（行为模拟模式，阶段一~三）。

核心：攻击者 = 有目标、有能力约束、会权衡成本、会感知对抗的决策主体。
决策循环：目标锁定 → 侦察可达面 → 效用计算选路 → 执行（成功/检测双向概率）→ 评估（被拦换路）。
贴近真实的四个机制：
  1. 目标导向决策（效用函数，可解释输出）
  2. 能力分层画像（脚本小子 / 职业黑客 / APT）
  3. 对抗适应（被拦/被检测换路径）
  4. 时间竞赛（MTTC vs MTTD+MTTR）
"""
import random
from collections import defaultdict
from . import realism
from .scenario_base import NodeState


# ============ 攻击者能力画像 ============
# 量化参数（skill_bonus/stealth/patience）为可调假设值；
# ttp_key 绑定数据安全库 threat_actors 表真实组织 TTP（叙事层，量化权重不取自情报表）。
PROFILES = {
    "script_kiddie": {
        "name": "低阶攻击者",  # 2026-09-06 专业命名（原"脚本小子"）
        "desc": "Script Kiddie：现成工具/钓鱼模板，无提权能力，核心库不可达",
        "skill_bonus": 0.0,     # 成功率加成
        "stealth": 0.30,        # 隐蔽性（越高越不易被检测）
        "patience": 4,          # 最多行动步数
        "can_priv_esc": False,  # 能否提权（2026-09-06 起真正消费：核心数据节点需提权）
        "defense_mult": 0.15,   # 已激活防御对其成功率的削弱（防御压制最强）
        "ttp_key": None,        # 无对应组织情报（低阶攻击者无组织归属）
        # 2026-09-06 P0-P2 三维度补全（DSB Tier I / GAO L1 对齐，KB-03-0212）
        "vuln_cap": "known_only",  # P0 漏洞能力：仅能利用有公开EXP的中低危（CVSS>=7 衰减x0.3）
        "tool_tier": 1,            # P1 工具链：现成工具照搬（检测概率 x1.0）
        "malware_cap": "use",      # P2 恶意软件：RaaS 租赁客户端（勒索可达成，叙事=租用）
    },
    "professional": {
        "name": "网络犯罪组织",  # 2026-09-06 专业命名（原"职业黑客"）
        "desc": "RaaS 勒索团伙（LockBit 类）：完整攻击链、横向移动、提权",
        "skill_bonus": 0.15,
        "stealth": 0.60,
        "patience": 8,
        "can_priv_esc": True,
        "defense_mult": 0.4,
        "ttp_key": "TA-002",    # LockBit 3.0（医疗/教育重点目标，RaaS 双重勒索）
        # 2026-09-06 P0-P2（DSB Tier III-IV / GAO L2-L3）
        "vuln_cap": "cve_high",    # P0：已知 CVE 全档（含 CVSS>=9），0day 不可
        "tool_tier": 3,            # P1：自研工具链/免杀改装（检测概率 x0.4）
        "malware_cap": "modify",   # P2：修改变种/双重勒索
    },
    "apt": {
        "name": "高级持续性威胁",  # 2026-09-06 专业命名（原"APT 高级威胁"）
        "desc": "APT（APT41 类）：0day、供应链攻击、隐蔽驻留、反取证",
        "skill_bonus": 0.30,
        "stealth": 0.90,
        "patience": 12,
        "can_priv_esc": True,
        "defense_mult": 0.7,    # 穿透防御能力强，防御削弱最小
        "ttp_key": "TA-001",    # APT41（科技/医疗/游戏/电信，供应链攻击/Web Shell/凭据窃取）
        # 2026-09-06 P0-P2（DSB Tier IV-V / GAO L3-L4）
        "vuln_cap": "zero_day",    # P0：全档 + 未公开漏洞（无校准数据取 0.9 上限）
        "tool_tier": 4,            # P1：武器化+反取证清痕（检测概率 x0.15）
        "malware_cap": "develop",  # P2：定制恶意软件/rootkit
    },
    "insider": {
        "name": "内部威胁",      # 2026-09-06 新增第四档（乐叔批准 A 项）
        "desc": "Insider：内鬼/厂商滥用权限，内网入口、熟知防御盲区",
        "skill_bonus": 0.20,
        "stealth": 0.85,        # 内鬼熟悉监控盲区
        "patience": 10,
        "can_priv_esc": True,   # 本身持有权限
        "defense_mult": 0.85,   # 熟知防御盲区，防御削弱最小
        "ttp_key": None,
        # 2026-09-06 P0-P2（位置维度正交：能力按"可信内部人"中位取值）
        "vuln_cap": "cve_high",    # P0：同犯罪组织（内鬼靠权限，漏洞非主通道）
        "tool_tier": 2,            # P1：EXP框架+合法管理工具滥用（检测概率 x0.7）
        "malware_cap": "use",      # P2：现成工具使用
    },
}

# P1 工具链检测系数（DSB/Security+ 对齐：工具代差决定特征明显度）
TOOL_DETECT_MULT = {1: 1.0, 2: 0.7, 3: 0.4, 4: 0.15}

# 攻击目标导向加权（2026-09-06 新增 B 项）：改变攻击目标集与节点价值权重
OBJECTIVE_WEIGHTS = {
    "exfil":   {"database": 1.6, "server": 1.0, "workstation": 0.6,
                "_label": ["人口", "数据", "病历", "精子", "EMR"], "_label_mult": 1.5},
    "ransom":  {"database": 1.0, "server": 1.3, "workstation": 0.5,
                "_label": ["备份", "灾备", "Backup"], "_label_mult": 2.0},
    "destroy": {"database": 0.5, "server": 1.6, "workstation": 0.7,
                "_label": ["HIS", "EMR", "病历"], "_label_mult": 1.6},
}


def profile_ttp(profile_id):
    """画像叙事层：从数据安全库 threat_actors 表绑定真实组织 TTP。
    返回 {actor, region, targets, motive, active_since, ttp, source, url}，
    无对应组织或 DB 不可用返回 None。
    【边界声明】仅提供组织定性情报（TTP/动机/来源），不提供量化参数——
    skill_bonus/stealth 等权重仍为场景假设值，防止「组织名真实、参数仍拍」。"""
    key = (PROFILES.get(profile_id) or {}).get("ttp_key")
    if not key:
        return None
    try:
        from . import attck_db
        actors = attck_db.load_threat_actors()
        for a in actors or []:
            if a.get("actor_id") == key:
                return a
    except Exception:
        pass
    return None


# ============ 节点价值分（目标导向的"价值"维度）============
# 高价值资产关键词 → 价值分；类型 → 基础分
HIGH_VALUE_KEYWORDS = ["人口", "HIS", "精子", "数据库", "EMR", "病历", "PACS", "备份"]

NODE_VALUE_BY_TYPE = {
    "database": 10,
    "server": 6,
    "workstation": 3,
    "network": 2,
    "switch": 2,
    "firewall": 1,
    "gap": 1,
    "isolator": 1,
    "behavior": 1,
    "iot": 4,
    "external": 0,
    "cloud": 8,
}


def node_value(node):
    """节点价值：关键词命中（高价值资产）+ 类型基础分。
    人口数据为最高优先级（extreme 风险），其次精子/HIS/EMR。"""
    label = node.get("label", "")
    val = NODE_VALUE_BY_TYPE.get(node.get("type", "server"), 5)
    if "人口" in label:
        val = max(val, 12)
    elif "精子" in label or "HIS" in label or "EMR" in label:
        val = max(val, 10)
    elif any(kw in label for kw in HIGH_VALUE_KEYWORDS):
        val = max(val, 8)
    return val


class AdversaryAgent:
    """攻击者智能体：目标导向、效用选路、对抗适应、可解释。"""

    # 效用函数权重（可解释超参，可调）
    W_VALUE = 0.35       # 目标价值
    W_SUCCESS = 0.25     # 成功概率
    W_STEALTH = 0.10     # 隐蔽性
    W_PROXIMITY = 0.20   # 目标接近度（越逼近 goal 越高，避免贪心绕路）
    W_COST = 0.10        # 成本

    def __init__(self, scenario, profile="professional", seed=None, objective=None):
        self.scenario = scenario
        self.nodes = {n["id"]: n for n in scenario.nodes}
        self.edges = scenario.edges
        self.defenses = scenario.defenses
        self.attack_steps = scenario.attack_steps
        self.profile = PROFILES[profile]
        self.profile_id = profile
        self.objective = objective if objective in OBJECTIVE_WEIGHTS else None
        self.rng = random.Random(seed)

        self.adj = defaultdict(list)
        for e in self.edges:
            self.adj[e["from"]].append(e["to"])
            # 内部威胁（2026-09-06 insider 死路修复）：内鬼熟知内网且横向移动
            # 不限方向——工作站多为叶子节点（有向边仅指向它，无出边），单向
            # 邻接下 insider 入口即死路（实测恒 0 目标）。insider 邻接双向化。
            if profile == "insider":
                self.adj[e["to"]].append(e["from"])

        self.entry_nodes = [nid for nid, n in self.nodes.items() if n["type"] == "external"]
        # 内部威胁（2026-09-06 A 项）：入口在内网（内鬼/厂商已在网内），无需破边界
        if profile == "insider":
            self.entry_nodes = self._insider_entries()
        self.goals = self._identify_goals()      # 目标清单（top N，逐个攻陷）
        self.goal = self.goals[0] if self.goals else None  # 首要目标（兼容旧字段）
        self.goal_label = self.nodes[self.goal]["label"] if self.goal else "无目标"

        # 节点 -> 保护它的防御（从 attack_steps effects + defense blocks 反推）
        self.node_defenses = self._map_node_defenses()

        # 状态
        self.compromised = set()
        self.detected = False
        self.clock = 0.0
        self.decisions = []   # 可解释决策轨迹

        # P2-1 信息不完整博弈：攻击者"已知地图"，初始只知入口及其一跳邻接
        self.known = set(self.entry_nodes)
        for e in self.entry_nodes:
            for nxt in self.adj.get(e, []):
                self.known.add(nxt)
        # 内部人熟悉内网拓扑：已知地图扩至两跳
        if profile == "insider":
            for n1 in list(self.known):
                for n2 in self.adj.get(n1, []):
                    self.known.add(n2)

    def _insider_entries(self):
        """内部威胁立足点：最低价值内网节点（最可能的工作站/运维终端）。"""
        cands = [(nid, node_value(n)) for nid, n in self.nodes.items()
                 if n["type"] == "workstation"]
        if not cands:
            cands = [(nid, node_value(n)) for nid, n in self.nodes.items()
                     if n["type"] not in ("external", "switch", "network")]
        if not cands:
            return []
        cands.sort(key=lambda kv: kv[1])
        return [cands[0][0]]

    def _identify_goals(self, n=3):
        """识别高价值目标清单（top N）：攻击者逐个攻陷，攻陷一个继续下一个。
        排除外部节点与基础设施。2026-09-06 B 项：按攻击目标导向加权排序。"""
        scored = sorted(self.nodes.items(), key=lambda kv: -self._objective_value(kv[1]))
        goals = []
        for nid, node in scored:
            if node["type"] in ("external", "switch", "network"):
                continue
            if node_value(node) <= 0:
                continue
            goals.append(nid)
            if len(goals) >= n:
                break
        return goals

    def _objective_value(self, node):
        """攻击目标导向加权：窃密偏核心库、勒索偏备份+生产、破坏偏可用性系统。"""
        base = node_value(node)
        w = OBJECTIVE_WEIGHTS.get(self.objective or "")
        if not w:
            return base
        mult = w.get(node["type"], 1.0)
        label = node.get("label", "")
        if any(k in label for k in w.get("_label", [])):
            mult = max(mult, w.get("_label_mult", 1.0))
        return base * mult

    def _requires_priv_esc(self, node_id):
        """核心数据节点（价值≥8：数据库/高价值关键词资产）需提权能力才能攻陷。
        2026-09-06 难度杠杆：低阶攻击者（can_priv_esc=False）不可达。"""
        return node_value(self.nodes[node_id]) >= 8

    def _remaining_goals(self):
        return [g for g in self.goals if g not in self.compromised]

    def _map_node_defenses(self):
        """攻击步 effects 的目标节点，被哪些 defense 的 blocks 保护。"""
        steps = {s["id"]: s for s in self.attack_steps}
        m = defaultdict(list)
        for d in self.defenses:
            for sid in d["blocks"]:
                step = steps.get(sid)
                if not step:
                    continue
                for ef in step.get("effects", []):
                    m[ef["target"]].append(d)
        return m

    def _defense_active(self, node_id):
        """该节点是否有已激活防御保护（当前推演态的防御激活）。"""
        return any(
            self.scenario.defense_states.get(d["id"])
            for d in self.node_defenses.get(node_id, [])
        )

    def _exploitability(self, node_id):
        """节点可利用性：优先漏扫校准值，其次攻击步 CVSS，最后默认。
        P0（2026-09-06 乐叔指令，KB-03-0212）：画像漏洞能力上限——
        低阶遇高危漏洞（CVSS>=7）能力不符衰减 x0.3；APT 面对未公开
        漏洞（无校准数据）取 0.9 上限基准（0day 能力）。"""
        cal = self.scenario.calibration.get(node_id)
        if cal and cal.get("exploitability") is not None:
            exp = cal["exploitability"]
            cvss = cal.get("cvss")
            if self.profile.get("vuln_cap") == "known_only" and cvss is not None and cvss >= 7.0:
                exp *= 0.3   # 低阶仅能利用有公开EXP的中低危
            return exp
        for s in self.attack_steps:
            for ef in s.get("effects", []):
                if ef["target"] == node_id:
                    base = s.get("exploitability", 0.8)
                    if self.profile.get("vuln_cap") == "zero_day":
                        return max(base, 0.9)
                    return base
        return 0.9 if self.profile.get("vuln_cap") == "zero_day" else 0.8

    def _reachable_actions(self):
        """从入口 + 所有已攻陷节点沿边枚举下一步动作（仅限"已知地图"内）。
        frontier = 入口 ∪ 已攻陷，避免攻陷死胡同节点后卡住。"""
        frontier = set(self.entry_nodes) | self.compromised
        actions = []
        seen = set()
        for src in frontier:
            for dst in self.adj.get(src, []):
                if dst in self.compromised or dst in self.entry_nodes:
                    continue
                if dst in seen:
                    continue
                if dst not in self.known:  # 未发现的节点需先侦察，暂不可攻击
                    continue
                # 提权门槛（2026-09-06 难度杠杆）：核心数据节点需提权能力，
                # 低阶攻击者（can_priv_esc=False）直接不可达
                if not self.profile.get("can_priv_esc", True) and self._requires_priv_esc(dst):
                    continue
                seen.add(dst)
                actions.append({"from": src, "target": dst})
        return actions

    def _node_defense_category(self, node_id):
        """节点防御类别（用于检测率），取保护它的防御的类别。"""
        for d in self.node_defenses.get(node_id, []):
            return d.get("category", "")
        return ""

    def _dist_to_goal(self, node_id):
        """到最近未攻陷目标的最短跳数（BFS，正向邻接）。多目标攻击：攻陷一个继续下一个。"""
        remaining = self._remaining_goals()
        if not remaining:
            return 0
        if node_id in remaining:
            return 0
        from collections import deque
        q = deque([(node_id, 0)])
        seen = {node_id}
        while q:
            cur, d = q.popleft()
            if d > 8:
                return 999
            for nxt in self.adj.get(cur, []):
                if nxt in remaining:
                    return d + 1
                if nxt not in seen:
                    seen.add(nxt)
                    q.append((nxt, d + 1))
        return 999

    def _action_utility(self, action):
        """效用 = 价值 + 成功率 + 隐蔽性 + 目标接近度 - 成本，全部可解释返回。"""
        target = action["target"]
        node = self.nodes[target]
        value = node_value(node)

        # 成功率：CVSS 可利用性 × 画像加成 × 防御削弱（按画像分级，
        # 2026-09-06：低阶 0.15 / 组织 0.4 / APT 0.7 / 内鬼 0.85，防御压制差异化）
        exp = self._exploitability(target)
        defense_mult = self.profile.get("defense_mult", 0.4) if self._defense_active(target) else 1.0
        success = min(exp * (1 + self.profile["skill_bonus"]) * defense_mult, 1.0)

        # 隐蔽性：1 - 检测概率（检测率 × 画像隐蔽）
        det = realism.detection_rate(self._node_defense_category(target))
        # P1（2026-09-06）：工具链代差修正检测概率——自研/武器化工具特征更隐蔽
        detect = det * (1 - self.profile["stealth"]) * TOOL_DETECT_MULT.get(
            self.profile.get("tool_tier", 2), 0.7)
        stealth = 1 - detect

        # 目标接近度：越逼近 goal 越高（引导直奔目标，避免绕路）
        dist = self._dist_to_goal(target)
        proximity = 1.0 if dist == 0 else (1.0 / (1 + dist))

        # 成本：按节点类型
        cost = {"database": 0.6, "server": 0.4, "workstation": 0.3,
                "network": 0.2, "switch": 0.2, "firewall": 0.3,
                "gap": 0.3, "isolator": 0.3, "iot": 0.3}.get(node["type"], 0.3)

        total = (self.W_VALUE * value / 10 +
                 self.W_SUCCESS * success +
                 self.W_STEALTH * stealth +
                 self.W_PROXIMITY * proximity -
                 self.W_COST * cost)
        return {
            "value": value,
            "success": round(success, 3),
            "stealth": round(stealth, 3),
            "proximity": round(proximity, 3),
            "cost": cost,
            "detect": round(detect, 3),
            "total": round(total, 3),
        }

    def _execute(self, action, util):
        """执行动作：成功/检测双向概率判定，返回结果。"""
        target = action["target"]
        node = self.nodes[target]

        # 成功判定
        success = self.rng.random() < util["success"]
        # 检测判定（即使失败也可能暴露）
        detected = self.rng.random() < util["detect"]

        # 时间推进：攻击耗时 + 检测响应
        step_time = 5 + self.rng.uniform(0, 10)
        self.clock += step_time
        if detected:
            self.detected = True
            # 被检测 → 该节点防御被激活（防御响应，对抗适应）
            for d in self.node_defenses.get(target, []):
                self.scenario.defense_states[d["id"]] = True

        if success:
            self.compromised.add(target)
            # P2-1：攻陷后侦察到该节点的邻接，扩展已知地图
            for nxt in self.adj.get(target, []):
                self.known.add(nxt)

        return success, detected, step_time

    def step(self):
        """执行一步决策，返回该步结果 dict；无路可走或耐心耗尽返回 None。
        同步将攻陷节点写入 scenario.node_states，供前端 canvas 实时渲染。"""
        if len(self.decisions) >= self.profile["patience"]:
            return None
        actions = self._reachable_actions()
        if not actions:
            return None

        # 效用计算 + 选最优
        best_action, best_util, best_score = None, None, float("-inf")
        for a in actions:
            u = self._action_utility(a)
            if u["total"] > best_score:
                best_action, best_util, best_score = a, u, u["total"]

        success, detected, step_time = self._execute(best_action, best_util)

        # 攻击叙事（基于目标节点类型，技术动作分阶段）
        node = self.nodes[best_action["target"]]
        svc = realism.NODE_SERVICES.get(node["type"], {"port": "80", "proto": "HTTP"})
        narrative = [
            {"t": round(self.clock - 4, 1), "action": f"对 {node['label']} 发起主动探测"},
            {"t": round(self.clock - 2, 1), "action": f"识别 {svc['proto']} 服务运行于 {svc['port']} 端口"},
            {"t": round(self.clock, 1), "action": f"尝试利用暴露面渗透 {node['label']}"},
        ]

        decision = {
            "step": len(self.decisions) + 1,
            "from": best_action["from"],
            "target": best_action["target"],
            "target_label": node["label"],
            "target_type": node["type"],
            "utility": best_util,
            "success": success,
            "detected": detected,
            "time": round(self.clock, 1),
            "narrative": narrative,
        }
        self.decisions.append(decision)

        # 同步节点状态到 scenario（供前端 canvas 显示）
        if success:
            self.scenario.node_states[best_action["target"]] = NodeState.COMPROMISED
            if best_action["target"] in self.goals:
                self.scenario.node_states[best_action["target"]] = NodeState.EXFILTRATED
        return decision

    @property
    def done(self):
        """推演结束：所有目标攻陷，或无路可走/耐心耗尽。"""
        if not self._remaining_goals():  # 所有目标已攻陷
            return True
        if len(self.decisions) >= self.profile["patience"]:
            return True
        if not self._reachable_actions():
            return True
        return False

    def run(self):
        """决策循环直到攻陷全部目标或耗尽耐心。返回本轮结果。"""
        while not self.done:
            self.step()

        achieved_goals = [g for g in self.goals if g in self.compromised]
        achieved = len(achieved_goals) > 0
        # MTTC：首个目标达成时刻
        mttc = None
        for d in self.decisions:
            if d["target"] in self.goals and d["success"]:
                mttc = d["time"]
                break

        return {
            "achieved": achieved,
            "achieved_count": len(achieved_goals),
            "goal_count": len(self.goals),
            "goals": self.goals,
            "goals_labels": [self.nodes[g]["label"] for g in self.goals],
            "mttc": mttc,
            "compromised": sorted(self.compromised),
            "detected": self.detected,
            "decisions": self.decisions,
            "goal": self.goal,
            "goal_label": self.nodes[self.goal]["label"] if self.goal else "无目标",
        }


def optimize_defense(scenario, budget):
    """P2-2：防御方按风险预算优化部署——贪心选性价比最高（拦截步数/成本）的防御。
    返回激活的 defense id 列表。"""
    cost_map = {"低": 1, "中": 2, "高": 3}
    candidates = []
    for d in scenario.defenses:
        c = cost_map.get(d.get("cost", "中"), 2)
        value = len(d.get("blocks", []))
        if value == 0:
            continue
        candidates.append({"ratio": value / c, "cost": c, "id": d["id"],
                           "name": d["name"], "value": value})
    candidates.sort(key=lambda x: (-x["ratio"], -x["value"]))
    selected, used = [], 0
    for c in candidates:
        if used + c["cost"] <= budget:
            selected.append(c["id"])
            used += c["cost"]
    for did in selected:
        scenario.defense_states[did] = True
    return selected


def monte_carlo(scenario, profile="professional", rounds=100, seed=None,
                defense_mode="none", defense_budget=None, objective=None):
    """蒙特卡洛仿真：N 轮统计攻击成功率、MTTC、最可能突破点、关键瓶颈。

    defense_mode:
      - none:      防御全关（现状基线，攻击者面对无防护网络）
      - all:       防御全开（理想防线）
      - partial:   半开（随机激活一半防御，贴近真实"部分部署"）
      - optimized: 防御方按风险预算优化部署（defense_budget 控制预算分）
    objective: 攻击目标导向（None/exfil 窃密/ransom 勒索/destroy 破坏），
      改变攻击目标集与节点价值权重（2026-09-06 B 项）。
    """
    rng = random.Random(seed)
    base_defense = dict(scenario.defense_states)  # 保存初始防御态

    achieved_count = 0
    goal_achieved_total = 0   # 累计攻陷目标数（多目标统计）
    mttc_list = []
    breach_count = defaultdict(int)   # 节点被攻陷次数
    block_count = defaultdict(int)    # 防御节点阻断次数（被检测激活后）
    sample_paths = []
    worst_case = None                 # 被突破最深一轮的完整决策轨迹

    all_defense_ids = list(scenario.defense_states.keys())

    for r in range(rounds):
        # 每轮重置防御态到初始，再按 defense_mode 设置
        # keep_behavior=True：行为模拟按用户所选画像跑，采样循环不得清画像（2026-09-14）
        scenario.reset(keep_behavior=True)
        for did, active in base_defense.items():
            scenario.defense_states[did] = active

        if defense_mode == "all":
            for did in all_defense_ids:
                scenario.defense_states[did] = True
        elif defense_mode == "partial":
            # 随机激活约一半防御
            k = max(1, len(all_defense_ids) // 2)
            for did in rng.sample(all_defense_ids, k):
                scenario.defense_states[did] = True
        elif defense_mode == "optimized":
            # P2-2：防御方按预算贪心优化部署
            budget = defense_budget if defense_budget is not None else 3
            optimize_defense(scenario, budget)

        agent = AdversaryAgent(scenario, profile=profile,
                               seed=rng.randint(0, 10**9), objective=objective)
        result = agent.run()

        if result["achieved"]:
            achieved_count += 1
        goal_achieved_total += result.get("achieved_count", 0)
        if result["mttc"] is not None:
            mttc_list.append(result["mttc"])
        for nid in result["compromised"]:
            breach_count[nid] += 1
        for d in result["decisions"]:
            if d["detected"] and d["target"]:
                block_count[d["target"]] += 1
        if len(sample_paths) < 5 and result["achieved"]:
            sample_paths.append({
                "path": [d["target"] for d in result["decisions"] if d["success"]],
                "mttc": result["mttc"],
                "detected": result["detected"],
            })
        # 记录被突破最深的一轮（攻陷节点最多，其次达成目标）
        if worst_case is None or len(result["compromised"]) > len(worst_case["compromised"]):
            worst_case = result

    # 仿真结束恢复场景初始状态：蒙特卡洛是旁路统计计算，
    # 不应把最后一轮的攻陷残留留在画布上（2026-09-06 逻辑审计发现）。
    # keep_behavior=True：模拟结束不清用户画像配置（2026-09-14）。
    scenario.reset(keep_behavior=True)
    for did, active in base_defense.items():
        scenario.defense_states[did] = active

    # 最可能被突破的节点（按攻陷频次排序）
    node_label = {nid: n["label"] for nid, n in
                  {n["id"]: n for n in scenario.nodes}.items()}
    most_breached = sorted(
        [{"node": nid, "label": node_label.get(nid, nid), "count": c}
         for nid, c in breach_count.items()],
        key=lambda x: -x["count"]
    )[:8]

    # 最差一轮复盘（被突破最深的完整决策轨迹，含效用分解）
    worst = None
    if worst_case:
        worst = {
            "achieved": worst_case["achieved"],
            "goal": worst_case["goal"],
            "goal_label": worst_case["goal_label"],
            "compromised": worst_case["compromised"],
            "detected": worst_case["detected"],
            "decisions": worst_case["decisions"],
        }

    # P0-2 置信区间（正态近似 95% CI）
    p = achieved_count / rounds
    se = (p * (1 - p) / rounds) ** 0.5 if rounds > 0 else 0
    confidence_interval = (
        round(max(0.0, p - 1.96 * se), 3),
        round(min(1.0, p + 1.96 * se), 3),
    )

    return {
        "profile": profile,
        "profile_name": PROFILES[profile]["name"],
        "ttp": profile_ttp(profile),
        "rounds": rounds,
        "defense_mode": defense_mode,
        "objective": objective,
        "success_rate": round(p, 3),
        "confidence_interval": confidence_interval,
        "achieved_count": achieved_count,
        "avg_goals_achieved": round(goal_achieved_total / rounds, 2),
        "goal_count": len(agent.goals),
        "goals_labels": [agent.nodes[g]["label"] for g in agent.goals],
        "avg_mttc": round(sum(mttc_list) / len(mttc_list), 1) if mttc_list else None,
        "goal": agent.goal,
        "goal_label": agent.goal_label,
        "most_breached": most_breached,
        "sample_paths": sample_paths,
        "worst_case": worst,
        "note": ("蒙特卡洛结果用于相对风险排序，非绝对概率预言；"
                 "skill_bonus/stealth 等量化权重为可调假设值；"
                 "ttp 字段为威胁组织定性情报（MITRE/CISA 公开来源），不提供量化参数；"
                 "成功率附 95% 置信区间"),
    }
