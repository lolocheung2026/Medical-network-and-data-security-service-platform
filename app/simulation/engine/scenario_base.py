"""
Scenario base class - defines network topology, attack steps, defenses, and state tracking.
"""
import os
import random
import uuid
from datetime import datetime
from enum import Enum

from . import realism


class NodeState(Enum):
    SAFE = "safe"
    COMPROMISED = "compromised"
    ISOLATED = "isolated"
    DEFENDED = "defended"
    TARGET = "target"
    EXFILTRATED = "exfiltrated"
    ENCRYPTED = "encrypted"


class StepState(Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    BLOCKED = "blocked"


class ScenarioBase:
    """Base class for all sandbox scenarios."""

    # Subclasses must override these
    SCENARIO_ID = ""
    SCENARIO_NAME = ""
    SCENARIO_DESC = ""
    SCENARIO_CATEGORY = ""
    SCENARIO_DIFFICULTY = ""
    SCENARIO_TAGS = []

    # 内部威胁免边界标记（2026-09-20）：_behavior_gate 对内部威胁画像返回该标记，
    # 表示初始访问（边界突破）步骤自动达成——内鬼已在内网，不走外部入口。
    INSIDER_BYPASS = "__insider_bypass__"

    def __init__(self):
        self.nodes = []
        self.edges = []
        self.attack_steps = []
        self.defenses = []
        self.events = []
        self.step_states = {}
        self.defense_states = {}
        self.node_states = {}
        # P1-1（2026-09-14）：BLOCKED 拦截来源登记 step_id -> "defense"|"gate"。
        # 行为门槛（_behavior_gate）与防御拦截共用 BLOCKED 状态，
        # 分列后报告「现状已拦」口径不再被能力门槛污染。
        self.block_sources = {}
        self.started = False
        self.start_time = None
        self.session_id = str(uuid.uuid4())[:8]
        self.prob_mode = False   # 概率仿真模式：防御有绕过率
        self.bypassed_count = 0  # 本轮推演防御被绕过次数
        self.clock = 0.0         # D 档：虚拟推演时钟（分钟）
        self.timeline = []       # D 档：检测-响应时间线
        self.calibration = {}    # 漏扫校准：node_id -> {cve_id, cvss, exploitability}
        # 脱敏开关（2026-09-18 产品化 P1-6）：默认值由环境变量控制。
        # 沙盘现状 = 0（保持演示用真实设备名）；产品部署 = SANDBOX_DEFAULT_ANONYMIZE=1
        # （对齐产品设计文档 KB-03-0215 决策 #25：报告脱敏默认开启）。
        self.anonymize = os.environ.get("SANDBOX_DEFAULT_ANONYMIZE", "0") == "1"
        self.decision_points = []  # P1-5 推演中决策点（人在环，CHESS 回合制思想）
        self.candidate_remediations = []  # 增量整改候选措施库（2026-09-06 乐叔口径）
        # 行为模拟配置（2026-09-06 乐叔四点要求）：画像 + 攻击目标导向影响推演结果。
        # 默认最低档：低阶攻击者 + 无偏好（不进入行为模拟选择直接推演时的口径）。
        # 2026-09-14：reset() 改为复位这两项（此前"配置持久"导致乐叔 16:28/16:31
        # 设置画像后重置不干净，09-06 已报同类残留）。口径：重置=恢复初始状态。
        self.behavior_profile = "script_kiddie"
        self.behavior_objective = None

    def set_behavior_config(self, profile, objective=None):
        """设置行为模拟配置（画像白名单 + 目标导向白名单）。"""
        valid_profiles = ("script_kiddie", "professional", "apt", "insider")
        valid_objectives = (None, "", "exfil", "ransom", "destroy")
        if profile not in valid_profiles:
            return {"ok": False, "error": f"未知画像: {profile}"}
        if objective not in valid_objectives:
            return {"ok": False, "error": f"未知目标导向: {objective}"}
        self.behavior_profile = profile
        self.behavior_objective = objective or None
        return {"ok": True, "profile": profile, "objective": self.behavior_objective}

    def _behavior_gate(self, step):
        """行为模拟配置门槛：画像提权门槛 + 攻击目标导向闭包。
        返回 None=放行；否则拦截原因字符串（步骤被 BLOCKED）；
        内部威胁画像对初始访问战术步骤返回 INSIDER_BYPASS（自动达成，非拦截）。"""
        from .adversary import node_value
        # 画像提权门槛：低阶攻击者无法攻陷核心数据资产（价值≥8 需提权）
        if self.behavior_profile == "script_kiddie":
            for ef in step.get("effects", []):
                n = next((x for x in self.nodes if x["id"] == ef.get("target")), None)
                if n and node_value(n) >= 8:
                    return f"低阶攻击者无提权能力，核心资产 [{n['label']}] 不可达"
        # 内部威胁（2026-09-20 乐叔方案C-A）：已在内网、熟防御盲区，
        # 初始访问（外部边界突破）步骤免执行自动达成——内鬼不钓鱼、不打暴露面
        if self.behavior_profile == "insider":
            mitre = step.get("mitre", "") or ""
            base = mitre.split(".")[0] if "." in mitre else mitre
            tactic = (realism.MITRE_TACTICS.get(mitre)
                      or realism.MITRE_TACTICS.get(base))
            if tactic and tactic[0] == "Initial Access":
                return self.INSIDER_BYPASS
        # 攻击目标导向：步骤不在目标导向攻击计划闭包内则排除
        if self.behavior_objective:
            obj_label = {"exfil": "数据窃取", "ransom": "勒索加密", "destroy": "破坏瘫痪"}.get(
                self.behavior_objective, self.behavior_objective)
            if step["id"] not in self._objective_step_closure():
                return f"非「{obj_label}」攻击目标路径，不在本轮攻击计划"
        return None

    def _objective_final_state(self, nid, state):
        """攻击目标导向的攻陷终态改写（2026-09-06 乐叔要求3 落点）：
        线性步骤链下闭包排除恒全集（过滤无效），目标导向的影响体现在
        攻陷节点的终态类型上——窃密=数据泄露、勒索=已加密、破坏=攻陷。"""
        if not self.behavior_objective:
            return state
        from .adversary import node_value
        n = next((x for x in self.nodes if x["id"] == nid), None)
        if not n:
            return state
        if self.behavior_objective == "exfil":
            if n["type"] == "database" or node_value(n) >= 8:
                return NodeState.EXFILTRATED.value
        elif self.behavior_objective == "ransom":
            if n["type"] in ("server", "database"):
                # P2（2026-09-06 乐叔指令，KB-03-0212）：恶意软件能力门槛——
                # 无勒索能力画像（malware_cap=none）降级为攻陷；
                # use（RaaS 租赁）及以上可达成加密终态。
                from .adversary import PROFILES
                cap = PROFILES.get(self.behavior_profile, {}).get("malware_cap", "use")
                if cap == "none":
                    return NodeState.COMPROMISED.value
                return NodeState.ENCRYPTED.value
        elif self.behavior_objective == "destroy":
            return NodeState.COMPROMISED.value
        return state

    def _objective_step_closure(self):
        """目标导向步骤闭包：加权 top3 目标 ← 命中目标的步骤 ← 递归前置链
        （step_completed 直接前置 + node_compromised 反查产出步骤）。"""
        from .adversary import node_value, OBJECTIVE_WEIGHTS
        w = OBJECTIVE_WEIGHTS.get(self.behavior_objective or "")
        if not w:
            return {s["id"] for s in self.attack_steps}

        def oval(n):
            mult = w.get(n["type"], 1.0)
            if any(k in n.get("label", "") for k in w.get("_label", [])):
                mult = max(mult, w.get("_label_mult", 1.0))
            return node_value(n) * mult

        scored = sorted(self.nodes, key=oval, reverse=True)
        goals = []
        for n in scored:
            if n["type"] in ("external", "switch", "network") or node_value(n) <= 0:
                continue
            goals.append(n["id"])
            if len(goals) >= 3:
                break
        goal_set = set(goals)
        steps = {s["id"]: s for s in self.attack_steps}
        keep = set()
        for s in self.attack_steps:
            if any(ef.get("target") in goal_set for ef in s.get("effects", [])):
                keep.add(s["id"])

        def add_pre(sid):
            for pre in steps[sid].get("preconditions", []):
                if pre["type"] == "step_completed" and pre["step"] in steps:
                    if pre["step"] not in keep:
                        keep.add(pre["step"])
                        add_pre(pre["step"])
                elif pre["type"] == "node_compromised":
                    for s2 in self.attack_steps:
                        if any(ef.get("target") == pre["node"] for ef in s2.get("effects", [])):
                            if s2["id"] not in keep:
                                keep.add(s2["id"])
                                add_pre(s2["id"])
        for sid in list(keep):
            add_pre(sid)
        return keep

    def _apply_demotions(self):
        """前端防线缺口化（2026-09-06 方案A）：把场景类属性 DEMOTED_DEFENSES
        列出的现状防御降级为整改候选措施——现状防护存在真实缺口（攻击可突破），
        整改后补上缺口实现 0 攻陷。语义：现状缺前端纵深防线，后端防线仍在。
        在场景 __init__ 的 _build_defenses/_build_remediations 之后调用。"""
        demoted = getattr(self, "DEMOTED_DEFENSES", [])
        if not demoted:
            return
        kept, moved = [], []
        for d in self.defenses:
            (moved if d["id"] in demoted else kept).append(d)
        self.defenses = kept
        for d in moved:
            self.candidate_remediations.append({
                "id": f"rd_{d['id']}",
                "name": d["name"],
                "desc": d["desc"],
                "covers": d["blocks"],
                "cost": d["cost"],
                "category": d["category"],
                "dept": self.DEPT_MAP.get(d.get("category", ""),
                                         "信息中心（数字化建设办公室）"),
                "root_cause": f"现状未部署「{d['name']}」，攻击在对应环节畅通",
                "trap": False,
            })

    # 责任部门映射（建议值，需按院内实际组织架构调整）
    DEPT_MAP = {
        "架构整改": "信息中心（数字化建设办公室）",
        "边界防护": "信息中心（数字化建设办公室）",
        "网络防护": "信息中心（数字化建设办公室）",
        "终端防护": "信息中心 + 各使用科室",
        "数据安全": "信息中心 + 数据治理责任部门",
        "灾备恢复": "信息中心（数字化建设办公室）",
        "监控审计": "信息中心 + 安全管理归口部门",
        "访问控制": "信息中心（数字化建设办公室）",
        "资产管理": "设备科 + 信息中心",
        "应急-检测": "信息中心 + 应急办",
        "应急-抑制": "信息中心 + 应急办",
        "应急-根除": "信息中心 + 应急办",
        "应急-恢复": "信息中心 + 应急办",
        "应急-复盘": "应急办 + 信息中心",
        "云上检测": "云服务商 + 信息中心",
        "云上隔离": "云服务商 + 信息中心",
        "云上配置": "云服务商 + 信息中心",
        "云地联动": "云服务商 + 信息中心",
        "配置管理": "信息中心（数字化建设办公室）",
        "系统加固": "信息中心（数字化建设办公室）",
        "高可用": "信息中心（数字化建设办公室）",
    }

    # 结论边界声明（防止推演结果被误用作安全结论）
    DISCLAIMER = (
        "【结论边界声明】本推演为剧本化桌面推演：攻击链与防御对策为预设内容，"
        "节点为网络逻辑抽象（不含主机级端口/补丁细节），防御拦截为二元判定"
        "（概率模式下含预设绕过率）。推演结果用于风险沟通、培训与整改优先级论证，"
        "不构成安全评估结论，不能替代等保测评或渗透测试。攻击链技术细节未经验证，"
        "引用前须核实证据来源（见场景描述中的 KB 编号与核实记录）。"
    )

    def _add_node(self, nid, label, ntype, x, y, desc="", awareness="中", remediation=None):
        node = {
            "id": nid,
            "label": label,
            "type": ntype,
            "x": x,
            "y": y,
            "desc": desc,
            # P0-1 人为因素（GHOSTS 思想）：安全意识等级影响钓鱼/诱导类攻击成功率
            "awareness": awareness,
        }
        # 整改设备节点标记（前端渲染品红样式 + 「改」角标）
        if remediation:
            node["remediation"] = remediation
        self.nodes.append(node)
        self.node_states[nid] = NodeState.SAFE

    def _add_edge(self, src, dst, label=""):
        self.edges.append({"from": src, "to": dst, "label": label})

    def apply_user_topology(self, topo):
        """v0.2.1：用用户上传的脱密拓扑替换场景内置拓扑。

        topo 为 topology_spec.validate_topology 产出的规范化结构
        （nodes 含自动布局坐标）。仅在推演开始前调用；攻击步/防御/整改
        仍引用场景内置节点 id——节点 id 不匹配时相关步骤按不满足前置处理。
        """
        self.nodes = []
        self.edges = []
        self.node_states = {}
        for n in topo["nodes"]:
            self._add_node(n["id"], n["label"], n["type"], n.get("x", 0),
                           n.get("y", 0), n.get("desc", ""))
        for e in topo["edges"]:
            self._add_edge(e["from"], e["to"], e.get("label", ""))
        self.user_topology_applied = True


    def _add_attack_step(self, sid, name, desc, preconditions, effects,
                         detection="中", technique="", mitre=""):
        step = {
            "id": sid,
            "name": name,
            "desc": desc,
            "preconditions": preconditions,
            "effects": effects,
            "detection": detection,
            "technique": technique,
            "mitre": mitre,
        }
        # A 档：补全 MITRE 战术 / CWE / CVE / CVSS
        step = realism.enrich_attack_step(step)
        # P0-1 人为因素调整（GHOSTS 思想）：钓鱼/诱导类技术 × 目标节点安全意识
        from . import realism as _realism
        if step["mitre"] and step["mitre"].split(".")[0] in _realism.HUMAN_FACTOR_TECHS:
            target = effects[0]["target"] if effects else None
            node = next((n for n in self.nodes if n["id"] == target), None)
            if node:
                aw = node.get("awareness", "中")
                factor = {"低": 1.3, "中": 1.0, "高": 0.6}.get(aw, 1.0)
                if factor != 1.0:
                    step["exploitability"] = round(
                        min(step.get("exploitability", 0.9) * factor, 1.0), 3)
                step["human_factor"] = {
                    "target": target,
                    "awareness": aw,
                    "factor": factor,
                    "note": ("目标人员安全意识低，钓鱼诱导成功率上调" if factor > 1
                             else ("目标人员安全意识高，钓鱼诱导成功率下调" if factor < 1
                                   else "目标人员安全意识中等，无调整")),
                }
        self.attack_steps.append(step)
        self.step_states[sid] = StepState.PENDING

    def _add_defense(self, did, name, desc, blocks, cost="低", category="", bypass_rate=0.2,
                     detection_rate=None, remediation=False):
        """bypass_rate: 概率模式下攻击绕过该防御的概率（0-1），默认 0.2
        detection_rate: C 档检出率（0-1），None 时按类别自动取值
        remediation: True = 整改新增措施（拓扑整改设备节点映射），拦截来源标注用"""
        if detection_rate is None:
            detection_rate = realism.detection_rate(category)
        self.defenses.append({
            "id": did,
            "name": name,
            "desc": desc,
            "blocks": blocks,
            "cost": cost,
            "category": category,
            "bypass_rate": bypass_rate,
            "detection_rate": detection_rate,
            "remediation": remediation,
        })
        self.defense_states[did] = False

    def _add_remediation(self, rid, name, desc, covers, cost="中", category="",
                         dept=None, root_cause="", trap=False):
        """增量整改候选措施（2026-09-06 乐叔口径）：
        针对「现状防护全开仍存在的薄弱环节」设计的新增措施。
        - 与 defenses（现状防护）分离：不进入现状推演，仅在整改推演轮2按需生效
        - covers = 覆盖的攻击步 id 列表（可含侦察步 s1，诱捕/监测语义）
        - trap=True：欺骗防御/监测诱捕类，可拦截侦察步（蜜罐思想）
        - root_cause：该措施对应的薄弱环节根因（用于整改报告根因分析）
        """
        self.candidate_remediations.append({
            "id": rid,
            "name": name,
            "desc": desc,
            "covers": covers,
            "cost": cost,
            "category": category,
            "dept": dept or self.DEPT_MAP.get(category, "信息中心（数字化建设办公室）"),
            "root_cause": root_cause,
            "trap": trap,
        })

    # ===== P1-5 推演中决策点（人在环，CHESS 桌面兵棋回合制思想）=====

    def add_decision_point(self, step_id, question, options):
        """在攻击步执行前插入决策点：用户二选一，影响后续推演分支。
        options: [{id, label, description, block_steps: [...], log: "..."}]"""
        self.decision_points.append({
            "id": f"dp_{step_id}",
            "step_id": step_id,
            "question": question,
            "options": options,
        })

    def resolve_decision(self, decision_id, option_id):
        """应用决策：将所选分支的 block_steps 置为 BLOCKED（决策阻断），
        记录事件，返回影响说明。2026-09-23 增：登记 resolved 标记，
        供演练评估打分（决策参与维度）使用。"""
        dp = next((d for d in self.decision_points if d["id"] == decision_id), None)
        if not dp:
            return {"ok": False, "error": "决策点不存在"}
        opt = next((o for o in dp["options"] if o["id"] == option_id), None)
        if not opt:
            return {"ok": False, "error": "决策选项不存在"}
        blocked = []
        for sid in opt.get("block_steps", []):
            if sid in self.step_states and self.step_states[sid] == StepState.PENDING:
                self.step_states[sid] = StepState.BLOCKED
                blocked.append(sid)
        dp["resolved"] = option_id
        self._log("decision", f"推演决策 [{dp['question']}] → {opt['label']}：{opt.get('log', '')}",
                  severity="warning")
        return {"ok": True, "decision": decision_id, "option": option_id,
                "blocked_steps": blocked, "log": opt.get("log", "")}

    def _log(self, event_type, message, node=None, severity="info"):
        self.events.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": event_type,
            "message": message,
            "node": node,
            "severity": severity,
        })

    def threat_briefing(self, limit=3):
        """威胁态势开场：真实统计（数据安全库 security_trends 表），
        DB 不可用回退内置静态条目。仅供叙事背景，不参与推演计算。"""
        try:
            from . import attck_db
            return attck_db.load_threat_briefing(limit=limit)
        except Exception:
            try:
                from . import attck_db
                return attck_db.DEFAULT_BRIEFING
            except Exception:
                return []

    def metadata(self):
        return {
            "id": self.SCENARIO_ID,
            "name": self.SCENARIO_NAME,
            "desc": self.SCENARIO_DESC,
            "category": self.SCENARIO_CATEGORY,
            "difficulty": self.SCENARIO_DIFFICULTY,
            "tags": self.SCENARIO_TAGS,
            "node_count": len(self.nodes),
            "attack_steps": len(self.attack_steps),
            "defenses": len(self.defenses),
            "remediation_count": len(self.candidate_remediations),
        }

    def snapshot(self):
        """Return full current state for the frontend."""
        return {
            "metadata": self.metadata(),
            "session_id": self.session_id,
            "started": self.started,
            "start_time": self.start_time,
            "prob_mode": self.prob_mode,
            "bypassed": self.bypassed_count,
            "clock": self.clock,
            "timeline": self.timeline,
            "threat_briefing": self.threat_briefing(),
            "decision_points": self.decision_points,
            "nodes": [
                {**n, "state": self.node_states[n["id"]].value}
                for n in self.nodes
            ],
            "edges": self.edges,
            "attack_steps": [
                {**s, "state": self.step_states[s["id"]].value}
                for s in self.attack_steps
            ],
            "defenses": [
                {**d, "active": self.defense_states[d["id"]]}
                for d in self.defenses
            ],
            "candidate_remediations": self.candidate_remediations,
            "behavior_profile": self.behavior_profile,      # 行为模拟配置（前端回显）
            "behavior_objective": self.behavior_objective,
            "events": self.events[-50:],
        }

    def start(self):
        self.started = True
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._log("system", f"场景已启动: {self.SCENARIO_NAME}", severity="info")

    def execute_attack(self, step_id):
        if step_id not in self.step_states:
            return {"ok": False, "error": "步骤不存在"}
        if self.step_states[step_id] != StepState.PENDING:
            return {"ok": False, "error": "步骤已执行过"}

        step = next(s for s in self.attack_steps if s["id"] == step_id)

        # 行为模拟配置门槛（2026-09-06 乐叔四点要求：画像/目标导向影响推演结果）
        # 命中即拦截（步骤 BLOCKED），动画路径与批量路径（_run_all_steps）单点生效
        gate = self._behavior_gate(step)
        if gate:
            if gate == self.INSIDER_BYPASS:
                # 内部威胁免边界（2026-09-20 方案C-A）：初始访问步骤自动达成。
                # 内鬼已在内网，无需钓鱼/暴露面突破，effects 直接生效，
                # 不计入时钟推进与防御判定（边界防御对其无拦截面）。
                for effect in step["effects"]:
                    nid = effect["target"]
                    new_state = self._objective_final_state(nid, effect["state"])
                    self.node_states[nid] = NodeState(new_state)
                    self._log("attack", f"[{step['name']}] {nid} -> {new_state}",
                              node=nid, severity="danger")
                self.step_states[step_id] = StepState.COMPLETED
                self._log("attack",
                          f"攻击步骤 [{step['name']}] 自动达成：内部威胁已在内网，免外部边界突破",
                          severity="warning")
                self._timeline_add(round(self.clock, 1), "attack",
                                   f"内部威胁免边界突破：{step['name']} 自动达成（已在内网）",
                                   step_id=step_id, severity="warning")
                return {"ok": True, "blocked": False,
                        "insider_bypass": True, "narrative": []}
            self.step_states[step_id] = StepState.BLOCKED
            self.block_sources[step_id] = "gate"
            self._log("defense", f"攻击步骤 [{step['name']}] 未达成：{gate}", severity="info")
            self._timeline_add(round(self.clock, 1), "block",
                               f"行为模拟配置拦截：{gate}", step_id=step_id,
                               severity="info")
            return {"ok": True, "blocked": True, "defense": gate, "narrative": []}

        # 攻击叙事：技术动作分阶段展开（真实感）
        narrative = self._build_narrative(step)

        # Check preconditions
        # node_compromised 前置接受"已攻陷及更深状态"（exfiltrated/encrypted 均以攻陷为前提）
        BREACHED_STATES = (NodeState.COMPROMISED, NodeState.EXFILTRATED, NodeState.ENCRYPTED)
        for pre in step["preconditions"]:
            if pre["type"] == "node_compromised":
                if self.node_states.get(pre["node"]) not in BREACHED_STATES:
                    return {"ok": False, "error": f"前置条件未满足: 需先攻陷 {pre['node']}"}
            elif pre["type"] == "step_completed":
                if self.step_states.get(pre["step"]) != StepState.COMPLETED:
                    return {"ok": False, "error": f"前置条件未满足: 需先完成步骤 {pre['step']}"}

        # D 档：虚拟时钟推进（攻击执行耗时）
        self.clock += self._step_duration(step)
        t_attack = round(self.clock, 1)
        self._timeline_add(t_attack, "attack", f"攻击发起: {step['name']}",
                           step_id=step_id, severity="danger")

        # Check if blocked by an active defense
        for d in self.defenses:
            if self.defense_states[d["id"]] and step_id in d["blocks"]:
                # C 档：概率模式按 CVSS 可利用性 × (1-检出率) 判定穿透
                if self.prob_mode:
                    bypass = self._dynamic_bypass_rate(step, d)
                    if random.random() < bypass:
                        self.bypassed_count += 1
                        self._log("attack",
                                  f"攻击步骤 [{step['name']}] 绕过防御 [{d['name']}]"
                                  f"（CVSS 可利用性 {step.get('exploitability', 0):.2f}"
                                  f" × 检出率 {d.get('detection_rate', 0):.0%} → 绕过率 {bypass:.0%}）",
                                  severity="danger")
                        self._timeline_add(t_attack, "bypass",
                                           f"绕过防御 [{d['name']}]", step_id=step_id,
                                           severity="danger")
                        continue  # 继续检查其他防御 / 放行
                self.step_states[step_id] = StepState.BLOCKED
                self.block_sources[step_id] = "defense"
                t_block = round(t_attack + self._mttd(step), 1)
                self._timeline_add(t_block, "block",
                                   f"防御 [{d['name']}] 拦截（检测+阻断 {self._mttd(step)}min）",
                                   step_id=step_id, severity="success")
                self._log("defense", f"攻击步骤 [{step['name']}] 被防御 [{d['name']}] 拦截",
                          severity="success")
                return {"ok": True, "blocked": True, "defense": d["name"],
                        "narrative": narrative}

        # Apply effects（行为模拟目标导向终态改写：窃密=泄露/勒索=加密/破坏=攻陷）
        for effect in step["effects"]:
            nid = effect["target"]
            new_state = self._objective_final_state(nid, effect["state"])
            self.node_states[nid] = NodeState(new_state)
            self._log("attack", f"[{step['name']}] {nid} -> {new_state}",
                      node=nid, severity="danger")

        self.step_states[step_id] = StepState.COMPLETED
        self._log("attack", f"攻击步骤完成: {step['name']}", severity="warning")

        # D 档：检测与响应时间线（攻击得手后的 MTTD / MTTR）
        t_detect = round(t_attack + self._mttd(step), 1)
        self._timeline_add(t_detect, "detect",
                           f"检测到异常（MTTD {self._mttd(step)}min，检测难度: {step.get('detection','中')}）",
                           step_id=step_id, severity="warning")
        t_respond = round(t_detect + self._mttr(), 1)
        self._timeline_add(t_respond, "respond",
                           f"应急响应启动（MTTR {self._mttr()}min）",
                           step_id=step_id, severity="info")

        # Check if all steps completed
        all_done = all(
            self.step_states[s["id"]] in (StepState.COMPLETED, StepState.BLOCKED)
            for s in self.attack_steps
        )
        if all_done:
            self._log("system", "所有攻击步骤已完成", severity="warning")

        return {"ok": True, "blocked": False, "narrative": narrative}

    def _build_narrative(self, step):
        """攻击叙事：把攻击步展开成有技术细节的分阶段动作（真实感）。"""
        templates = realism.attack_narrative(step.get("mitre", ""))
        target = step["effects"][0]["target"] if step["effects"] else None
        node = next((n for n in self.nodes if n["id"] == target), None)
        svc = realism.NODE_SERVICES.get(node["type"], {"port": "80", "proto": "HTTP"}) if node else {"port": "80", "proto": "HTTP"}
        label = node["label"] if node else (target or "目标")
        t = self.clock
        return [{"t": round(t + i * 2, 1),
                 "action": tpl.format(label=label, port=svc["port"], proto=svc["proto"])}
                for i, tpl in enumerate(templates)]

    def toggle_defense(self, defense_id):
        if defense_id not in self.defense_states:
            return {"ok": False, "error": "防御不存在"}

        defense = next(d for d in self.defenses if d["id"] == defense_id)
        self.defense_states[defense_id] = not self.defense_states[defense_id]
        active = self.defense_states[defense_id]

        if active:
            self._log("defense", f"防御已激活: {defense['name']}", severity="success")
            # Revert blocked steps' effects if defense covers completed steps? No - defense only blocks future steps.
        else:
            self._log("defense", f"防御已关闭: {defense['name']}", severity="info")

        return {"ok": True, "active": active}

    # ===== D 档：检测-响应时间线建模 =====
    DETECT_DELAY = {"高": 3, "中": 12, "低": 30}  # 分钟（无监控时的检测延迟）
    MONITOR_CATS = {"监控审计", "云上检测", "终端防护", "应急-检测"}
    RESPOND_CATS = {"应急-抑制", "应急-根除", "云上隔离", "网络防护",
                    "应急-恢复", "灾备恢复"}

    def _step_duration(self, step):
        """单个攻击步的执行耗时（分钟），按技术复杂度估算。"""
        d = step.get("detection", "中")
        base = {"低": 5, "中": 15, "高": 30}[d]
        return base + random.uniform(0, base * 0.3)

    def _timeline_add(self, t, etype, message, step_id=None, severity="info"):
        self.timeline.append({
            "t": t,
            "type": etype,
            "message": message,
            "step_id": step_id,
            "severity": severity,
        })

    def _mttd(self, step):
        """MTTD 平均检测时间（分钟）：检测难度 × 是否部署监控。"""
        base = self.DETECT_DELAY.get(step.get("detection", "中"), 12)
        monitored = any(
            self.defense_states.get(d["id"]) and d.get("category") in self.MONITOR_CATS
            for d in self.defenses
        )
        if monitored:
            base = max(1, base * 0.4)
        return round(base, 1)

    def _mttr(self):
        """MTTR 平均响应时间（分钟）：是否部署响应/隔离能力。"""
        has_response = any(
            self.defense_states.get(d["id"]) and d.get("category") in self.RESPOND_CATS
            for d in self.defenses
        )
        return 15 if has_response else 60

    # ===== 防御价值量化（2026-09-02 v2：防御贡献 + 整改闭环；损失金额已按乐叔要求移除）=====

    def defense_contribution(self):
        """每道激活防御的拦截贡献（确定性推演）：
        blocked_steps = 该防御 blocks 中实际处于 BLOCKED 状态的步骤。
        精确归属：每个 BLOCKED 步骤只归属给按 defenses 顺序第一个
        blocks 它的激活防御（与实际触发者一致），避免多防御重复认领。
        source: existing=现状防护 / remediation=整改新增措施（2026-09-06）。"""
        out = []
        claimed = set()
        for d in self.defenses:
            if not self.defense_states.get(d["id"]):
                continue
            blocked_steps = [b for b in d["blocks"]
                             if self.step_states.get(b) == StepState.BLOCKED
                             and b not in claimed]
            claimed.update(blocked_steps)
            out.append({
                "defense": d["name"],
                "defense_id": d["id"],
                "category": d.get("category", ""),
                "cost": d["cost"],
                "blocked_steps": blocked_steps,
                "source": "remediation" if d.get("remediation") else "existing",
            })
        return out

    # ===== 防御策略调优体检（2026-09-23 丈八「策略验证」产品思想借鉴）=====
    # 只基于推演事实（确定性口径）做现状防御效能体检，不改变推演判定：
    # 现状防御「覆盖了却被突破」或「部分覆盖未实际拦截」时给出策略核查建议。
    # 建议方向为通用工程核查清单（按防御类别），属提示性建议非整改承诺。

    TUNING_DIRECTIONS = {
        "访问控制": "核查策略规则顺序与作用域：deny 规则前置、any 规则收窄、源/目的精确匹配",
        "边界防护": "核查边界策略下发状态与接口绑定，确认策略未因设备负载或配置漂移失效",
        "网络防护": "核查策略规则顺序与作用域：deny 规则前置、any 规则收窄",
        "监控审计": "核查日志采集覆盖范围与告警阈值，确认关键资产流量进入审计",
        "终端防护": "核查终端 agent 部署覆盖率与病毒库/策略更新状态",
        "系统加固": "核查加固基线（口令策略/补丁/服务最小化）是否按期复检",
        "配置管理": "核查配置变更审批与基线定期比对，防配置漂移",
        "资产管理": "核查资产台账完整性，防止失管资产成为攻击入口",
        "数据安全": "核查 DLP 策略与加密范围是否覆盖高敏数据流转路径",
        "灾备恢复": "核查备份周期与恢复演练记录，验证备份可恢复性",
        "高可用": "核查主备切换策略与心跳配置，组织故障切换演练验证",
    }

    def defense_tuning_review(self, round_result):
        """基于一轮确定性推演事实，对现状防御做策略效能体检。
        round_result：_run_round 返回的轮次结果。只检查 remediation=False
        的现状防御。返回 [{defense, defense_id, severity, fact, advice}]，
        severity: 高（覆盖环节全部被突破）/ 中（部分被突破且自身零拦截）。"""
        completed = set(round_result.get("completed_steps", []))
        contrib = round_result.get("defense_contribution", [])
        contrib_by_id = {c["defense_id"]: c for c in contrib}
        suggestions = []
        for d in self.defenses:
            if d.get("remediation"):
                continue
            covers = [b for b in d["blocks"] if b in self.step_states]
            if not covers:
                continue
            breached = [b for b in covers if b in completed]
            if not breached:
                continue  # 覆盖环节全部被拦：效能正常，不生成建议
            c = contrib_by_id.get(d["id"])
            blocked_here = set(c["blocked_steps"]) if c else set()
            if len(breached) == len(covers):
                suggestions.append({
                    "defense": d["name"],
                    "defense_id": d["id"],
                    "severity": "高",
                    "fact": f"其覆盖的 {len(covers)} 个攻击环节在现状推演中全部被突破",
                    "advice": self.TUNING_DIRECTIONS.get(
                        d.get("category", ""), "核查该防御的策略配置与实际覆盖范围"),
                })
            elif not blocked_here:
                suggestions.append({
                    "defense": d["name"],
                    "defense_id": d["id"],
                    "severity": "中",
                    "fact": f"覆盖 {len(covers)} 个环节、其中 {len(breached)} 个被突破，"
                           f"自身未实际拦截任何步骤",
                    "advice": self.TUNING_DIRECTIONS.get(
                        d.get("category", ""), "核查该防御的策略配置与实际覆盖范围"),
                })
        # 监控覆盖体检（2026-09-23）：薄弱环节存在 + 无监控审计类防御激活
        # → 检测延迟偏高（MTTD 依据 DETECT_DELAY 档位）。事实性建议。
        if completed and not any(
                d.get("category") in self.MONITOR_CATS and not d.get("remediation")
                for d in self.defenses):
            delays = sorted(set(self.DETECT_DELAY.values()))
            suggestions.append({
                "defense": "全网监控审计体系",
                "defense_id": "__monitor__",
                "severity": "高",
                "fact": f"现状推演存在 {len(completed)} 个被突破环节，且未部署监控审计类防御，"
                       f"检测延迟达 {min(delays)}-{max(delays)} 分钟",
                "advice": "核查现有监控体系覆盖与告警阈值配置，压缩 MTTD；"
                         "若确无监控能力，参照第四节候选措施规划补建",
            })
        return suggestions

    # ===== 演练评估打分（2026-09-23 丈八「人才培养 PDCA」产品思想借鉴）=====
    # 推演完成后对防御方表现自动评分：决策参与（人在环决策点）、拦截成效、
    # 关键资产保全三维度。全部基于推演事实，权重归一处理 N/A 维度
    # （无决策点/无高价值节点的场景）。分数用于演练考核的相对排序，
    # 非绝对能力判定（声明随报告输出）。

    SCORECARD_WEIGHTS = {"decision": 30, "interception": 30, "asset": 40}

    def evaluation_scorecard(self):
        """基于当前实例状态生成演练评估评分卡。
        返回 {total, grade, dimensions, note, disclaimer}。"""
        total_steps = len(self.attack_steps)
        blocked = sum(1 for s in self.step_states.values() if s == StepState.BLOCKED)
        resolved = sum(1 for dp in self.decision_points if dp.get("resolved"))

        from .adversary import node_value
        high_nodes = [n for n in self.nodes if node_value(n) >= 8]
        breached = set(nid for nid, s in self.node_states.items()
                       if s in (NodeState.COMPROMISED, NodeState.EXFILTRATED,
                                NodeState.ENCRYPTED))
        safe_high = sum(1 for n in high_nodes if n["id"] not in breached)

        dims = []
        if self.decision_points:
            score = round(30 * resolved / len(self.decision_points))
            dims.append({"name": "决策参与", "score": score, "max": 30,
                         "detail": f"{resolved}/{len(self.decision_points)} 个决策点已处理"})
        if total_steps:
            score = round(30 * blocked / total_steps)
            dims.append({"name": "拦截成效", "score": score, "max": 30,
                         "detail": f"拦截 {blocked}/{total_steps} 个攻击环节"})
        if high_nodes:
            score = round(40 * safe_high / len(high_nodes))
            dims.append({"name": "关键资产保全", "score": score, "max": 40,
                         "detail": f"高价值资产保全 {safe_high}/{len(high_nodes)}"})

        if not dims:
            return {"total": 0, "grade": "未推演", "dimensions": [], "note": "尚无推演数据",
                    "disclaimer": "演练评分为相对排序参考，非绝对能力判定"}
        # 权重归一：N/A 维度的权重按比例重分配到有效维度
        total = round(sum(d["score"] for d in dims)
                      * 100 / sum(d["max"] for d in dims))
        grade = ("优秀" if total >= 90 else "良好" if total >= 75
                 else "及格" if total >= 60 else "需加强")
        return {
            "total": total,
            "grade": grade,
            "dimensions": dims,
            "note": "N/A 维度（无决策点/无高价值资产）已按权重归一",
            "disclaimer": "演练评分为相对排序参考，非绝对能力判定",
        }

    # 防御类别 -> 拓扑设备类型（整改建议体现到拓扑图时用；
    # 必须映射到拓扑导入可识别的安全设备类型，导入后自动生成防御）
    CATEGORY_DEVICE_TYPE = {
        "访问控制": "firewall",
        "边界防护": "firewall",
        "网络防护": "firewall",
        "高可用": "firewall",
        "监控审计": "behavior",
        "终端防护": "behavior",
        "系统加固": "behavior",
        "配置管理": "behavior",
        "资产管理": "behavior",
        "数据安全": "isolator",
        "灾备恢复": "isolator",
    }

    def build_remediated_topology(self, remediation_ids):
        """把所选整改建议体现到拓扑图中：为每项整改生成防护设备节点并挂接到
        被保护节点，返回整改后拓扑 JSON（拓扑库格式：edges 用 source/target）。
        remediation_ids：整改候选措施 id（candidate_remediations）；
        向后兼容旧调用（场景 defenses id 亦可解析）。"""
        nodes = [{**n, "state": "safe"} for n in self.nodes]
        # 场景边 from/to → 拓扑库边 source/target
        edges = [{"source": e["from"], "target": e["to"], "label": e.get("label", "")}
                 for e in self.edges]
        # 措施来源解析：候选库优先，defenses 兜底（兼容旧调用）
        src = []
        for rid in remediation_ids:
            c = next((x for x in self.candidate_remediations if x["id"] == rid), None)
            if c:
                src.append({"id": c["id"], "name": c["name"], "desc": c["desc"],
                            "blocks": c["covers"], "cost": c["cost"],
                            "category": c["category"]})
            else:
                d = next((x for x in self.defenses if x["id"] == rid), None)
                if d:
                    src.append(d)
        applied = []
        anchor_offset = {}  # 2026-09-06：同 anchor 多整改设备坐标错开，防节点叠加/名称重影
        for d in src:
            # 找该措施覆盖的攻击步目标节点作为挂接点
            anchors = []
            for b in d["blocks"]:
                step = next((s for s in self.attack_steps if s["id"] == b), None)
                if step:
                    for ef in step.get("effects", []):
                        if ef["target"] not in anchors:
                            anchors.append(ef["target"])
            if not anchors:
                anchors = [n["id"] for n in nodes[:1]]
            anchor = anchors[0]
            a = next((n for n in nodes if n["id"] == anchor), None)
            if not a:
                continue
            # anchor 若为安全设备，沿出边下探到首个非安全设备节点：
            # BFS 拦截模型「遇到安全设备即停」，挂在安全设备上游会被遮蔽而失效
            if a["type"] in ("firewall", "gap", "isolator", "behavior"):
                for e in self.edges:
                    if e["from"] == anchor:
                        dn = next((n for n in nodes if n["id"] == e["to"]), None)
                        if dn and dn["type"] not in ("firewall", "gap", "isolator", "behavior"):
                            anchor = e["to"]
                            a = dn
                            break
            # 整改设备节点：挂在目标节点前（作为其上游防护设备）
            # 坐标错开 + 避让：同 anchor 第 N 个设备纵向偏移 N*60；
            # 且必须避让拓扑中所有已有节点（2026-09-06 乐叔二次指正：
            # 整改设备曾落在边界防火墙层上与现有节点重叠）。
            # 2026-09-08 遮挡根治：避让半径 56 小于 SVG 渲染框（90x26）需求，
            # 提升为水平 110（两半宽90+间隙20）/ 垂直 46（26+20），步进同步放大。
            off = anchor_offset.get(anchor, 0)
            anchor_offset[anchor] = off + 1
            dev_id = f"rem_{d['id']}"
            dev_type = self.CATEGORY_DEVICE_TYPE.get(d.get("category", ""), "firewall")
            px = max(a["x"] - 90, 30)
            py = a["y"] + 40 + off * 60
            while any(abs(n["x"] - px) < 110 and abs(n["y"] - py) < 46
                      for n in nodes):
                px += 120
                if px > 760:
                    px = 30
                    py += 60
            nodes.append({
                "id": dev_id,
                "label": f"[整改] {d['name']}",
                "type": dev_type,
                "x": px,
                "y": py,
                "desc": d["desc"],
                "remediation": d["id"],
            })
            # 挂接：首条原场景入边改指本设备；仅改指原场景边（source 非 rem_ 前缀），
            # 避免整改设备之间链式串联（上游设备在 BFS 中被遮蔽）；
            # 后续设备并行接入（直接连 anchor）
            redirected = False
            for e in edges:
                if (e["target"] == anchor and e["source"] != dev_id
                        and not e["source"].startswith("rem_")):
                    if not redirected:
                        e["target"] = dev_id
                        redirected = True
            edges.append({"source": dev_id, "target": anchor, "label": "整改接入"})
            applied.append({
                "defense_id": d["id"],
                "name": d["name"],
                "device_node": dev_id,
                "category": d.get("category", ""),
                "cost": d["cost"],
            })
        return {
            "id": f"{self.SCENARIO_ID}_remediated",
            "name": f"{self.SCENARIO_NAME}（整改后）",
            "description": "由整改方案落地生成的拓扑（含整改防护设备节点）",
            "created": datetime.now().strftime("%Y-%m-%d"),
            "tags": self.SCENARIO_TAGS + ["整改后"],
            "sites": [],
            "networks": [],
            "nodes": nodes,
            "edges": edges,
            "risks": [],
            "remediation": {
                "source_scenario": self.SCENARIO_ID,
                "applied": applied,
            },
        }

    def remediate_sim(self, remediation_ids=None):
        """整改闭环两轮推演（2026-09-06 乐叔修订口径）：
        轮1 现状 = 现有防护全部启用，识别「有防护仍被突破」的薄弱环节；
        轮2 整改 = 现状防护 + 本轮新增整改措施（候选库，非原有防御开关），
        拦截来源区分「现状已拦 / 整改新增拦截」+「防御拦截 / 行为门槛」（P1-1，
        2026-09-14），附概率模式突破率对比（纵深加固效果量化）。
        输出不含损失金额。调用后实例恢复到干净态（P1-2，2026-09-14：
        不残留轮2 终态，避免污染画布与后续手动推演）。"""
        saved_defs = list(self.defenses)  # 轮2 注入的措施推演后移除
        saved_pm = self.prob_mode
        try:
            # 整改闭环两轮对比必须确定性口径：无论用户是否开着全局概率模式，
            # 轮1/轮2 都强制确定性拦截（否则两轮结论随机化、报告不可复现）。
            # 概率采样只在 _prob_breach_comparison 环节内部启用。
            self.prob_mode = False
            # ===== 轮1：现状（现有防护全部启用）=====
            r1 = self._run_round([d["id"] for d in self.defenses])
            compromised1 = r1["compromised_nodes"]
            weak_steps = [{"step": s["id"], "name": s["name"]} for s in self.attack_steps
                          if s["id"] in r1["completed_steps"]]
            # 防御策略调优体检（2026-09-23 丈八「策略验证」思想）：基于轮1 事实，
            # 现状防御覆盖失效/零拦截时给出策略核查建议（与增量整改措施区分）
            tuning_suggestions = self.defense_tuning_review(r1)

            # ===== 整改单：候选措施（可指定，缺省全部；成本快赢优先）=====
            cands = list(self.candidate_remediations)
            if remediation_ids is not None:
                cands = [c for c in cands if c["id"] in remediation_ids]
            plan = sorted(cands, key=lambda x: {"低": 1, "中": 2, "高": 3}.get(x["cost"], 9))

            # ===== 轮2：现状防护 + 整改措施（临时注入 defenses）=====
            for c in plan:
                self.defenses.append({
                    "id": c["id"], "name": c["name"], "desc": c["desc"],
                    "blocks": c["covers"], "cost": c["cost"],
                    "category": c["category"],
                    "bypass_rate": 0.0,   # 整改闭环确定性验证口径：新措施为强拦
                    "detection_rate": 0.95,
                    "remediation": True,  # 来源标记：整改新增
                })
                self.defense_states[c["id"]] = False
            r2 = self._run_round([d["id"] for d in self.defenses])
            compromised2 = r2["compromised_nodes"]
            # 拦截来源区分：现状已拦 = 轮1 blocked；整改新增拦截 = 轮1 突破、轮2 被拦
            newly_blocked = [s for s in r2["blocked_steps"] if s in r1["completed_steps"]]
            contribution = r2["defense_contribution"]
            residual = r2["residual_risks"]

            # ===== 概率对比：现状 vs 整改后突破率（纵深加固量化，N 轮采样）=====
            prob_cmp = self._prob_breach_comparison(plan)

            return {
                "ok": True,
                "scenario": self.SCENARIO_NAME,
                "baseline_note": "轮1 现状口径：现有防护全部启用（非无防御）",
                "round1": {
                    "completed_steps": r1["completed_steps"],
                    "blocked_steps": r1["blocked_steps"],
                    "blocked_by_defense": r1["blocked_by_defense"],
                    "blocked_by_gate": r1["blocked_by_gate"],
                    "compromised_nodes": compromised1,
                    "weak_steps": weak_steps,
                },
                "remediation_plan": [
                    {"defense_id": c["id"], "item": c["name"], "cost": c["cost"],
                     "category": c["category"],
                     "detail": c["desc"],
                     "dept": c["dept"],
                     "root_cause": c["root_cause"],
                     "covers": c["covers"],
                     "trap": c["trap"]}
                    for c in plan
                ],
                "round2": {
                    "completed_steps": r2["completed_steps"],
                    "blocked_steps": r2["blocked_steps"],
                    "blocked_by_defense": r2["blocked_by_defense"],
                    "blocked_by_gate": r2["blocked_by_gate"],
                    "compromised_nodes": compromised2,
                    "newly_blocked_steps": newly_blocked,
                    "existing_blocked_steps": r1["blocked_steps"],
                },
                "defense_contribution": contribution,
                "residual_risks": residual,
                "tuning_suggestions": tuning_suggestions,
                "prob_comparison": prob_cmp,
                "conclusion": {
                    "compromised_reduced": len(compromised1) - len(compromised2),
                    "newly_blocked": len(newly_blocked),
                    "value_note": (f"现状攻陷 {len(compromised1)} → 整改后 {len(compromised2)} 个；"
                                   f"整改新增拦截 {len(newly_blocked)} 步；"
                                   f"残余风险步骤 {len(residual)} 个"),
                },
                "disclaimer": self.DISCLAIMER,
            }
        finally:
            self.defenses = saved_defs
            # 重建防御态（清掉轮2 注入措施的幽灵键）
            self.defense_states = {d["id"]: False for d in saved_defs}
            self.prob_mode = saved_pm
            # P1-2（2026-09-14）：恢复现场到干净态，不残留轮2 终态。
            # keep_behavior=True：画像为用户配置，闭环结束不复位（2026-09-14）。
            self.reset(keep_behavior=True)

    def _prob_breach_comparison(self, plan, samples=200, seed=42):
        """概率模式突破率对比：现状（现有防御全开）vs 整改后（+新增措施）。
        N 轮蒙特卡洛采样，量化纵深加固效果。返回 {round1_rate, round2_rate,
        samples, note}。仅用于相对排序，非绝对概率预言。
        注意：轮1 采样必须剔除已注入的整改措施（remediate_sim 轮2 注入后
        调用本方法，若不剔除则轮1 基线被污染）。"""
        saved_defs = list(self.defenses)
        saved_states = dict(self.defense_states)
        saved_pm = self.prob_mode
        try:
            self.prob_mode = True
            # 现状防御集合（剔除任何整改措施）
            baseline_defs = [d for d in saved_defs if not d.get("remediation")]
            # 整改防御集合（现状 + 本轮措施）
            remediated_defs = baseline_defs + [
                {"id": c["id"], "name": c["name"], "desc": c["desc"],
                 "blocks": c["covers"], "cost": c["cost"],
                 "category": c["category"],
                 "bypass_rate": 0.1,
                 "detection_rate": 0.95,
                 "remediation": True}
                for c in plan
            ]
            rates = {}
            for tag, defs in (("round1_rate", baseline_defs),
                              ("round2_rate", remediated_defs)):
                self.defenses = list(defs)
                self.defense_states = {d["id"]: False for d in defs}
                random.seed(seed)
                breach = 0
                for _ in range(samples):
                    self.reset(keep_behavior=True)  # 采样循环保留用户画像（2026-09-14）
                    self.start()
                    for d in self.defenses:
                        self.defense_states[d["id"]] = True
                    r = self._run_all_steps()
                    if r["completed"]:
                        breach += 1
                rates[tag] = round(breach / samples, 4)
        finally:
            self.defenses = saved_defs
            self.defense_states = saved_states
            self.prob_mode = saved_pm
        return {
            **rates,
            "samples": samples,
            "seed": seed,
            "reduction": round(rates.get("round1_rate", 0) - rates.get("round2_rate", 0), 4),
            "note": "概率模式蒙特卡洛采样（防御绕过率生效），量化纵深加固后的整体突破率变化；"
                    "用于相对排序，非绝对概率预言",
        }

    def _run_all_steps(self):
        """顺序执行全部攻击步，返回 {completed, blocked, stalled,
        blocked_by_defense, blocked_by_gate}。
        P1-1（2026-09-14）：blocked 保留纯 id 列表（向后兼容），
        来源分列按 block_sources 登记拆分——防御拦截 vs 行为门槛。"""
        completed, blocked, stalled = [], [], []
        for s in self.attack_steps:
            r = self.execute_attack(s["id"])
            if r.get("blocked"):
                blocked.append(s["id"])
            elif r.get("ok"):
                completed.append(s["id"])
            else:
                stalled.append(s["id"])
        return {
            "completed": completed,
            "blocked": blocked,
            "stalled": stalled,
            "blocked_by_defense": [s for s in blocked
                                   if self.block_sources.get(s) == "defense"],
            "blocked_by_gate": [s for s in blocked
                                if self.block_sources.get(s) == "gate"],
        }

    # ===== P0-2 多方案对比推演（丈八「方案自动生成」思想）=====

    def _run_round(self, defense_ids):
        """公共轮次推演方法（2026-09-14 提取，替代三处重复逻辑）：
        按指定防御集合跑一轮确定性推演，返回
        {completed_steps, blocked_steps, blocked_by_defense, blocked_by_gate,
         compromised_nodes, residual_risks, defense_contribution}。
        调用结束后防御态恢复为进入时状态（不泄漏现场）。"""
        saved = dict(self.defense_states)
        try:
            self.reset(keep_behavior=True)  # 轮次推演保留用户画像（2026-09-14）
            self.start()
            for did in defense_ids:
                if did in self.defense_states:
                    self.defense_states[did] = True
            r = self._run_all_steps()
            compromised = [nid for nid, s in self.node_states.items()
                           if s in (NodeState.COMPROMISED, NodeState.EXFILTRATED,
                                    NodeState.ENCRYPTED)]
            residual = [{"step": s["id"], "name": s["name"]}
                        for s in self.attack_steps
                        if self.step_states[s["id"]] == StepState.COMPLETED]
            return {
                "completed_steps": r["completed"],
                "blocked_steps": r["blocked"],
                "blocked_by_defense": r["blocked_by_defense"],
                "blocked_by_gate": r["blocked_by_gate"],
                "compromised_nodes": compromised,
                "residual_risks": residual,
                "defense_contribution": self.defense_contribution(),
            }
        finally:
            self.defense_states = saved

    def _round_with_defenses(self, defense_ids):
        """按指定防御集合跑一轮确定性推演，返回轮结果（委托公共轮次方法）。"""
        r = self._run_round(defense_ids)
        return {
            "completed_steps": r["completed_steps"],
            "blocked_steps": r["blocked_steps"],
            "compromised_nodes": r["compromised_nodes"],
            "residual_risks": r["residual_risks"],
        }

    def compare_plans(self):
        """多方案对比推演（2026-09-06 口径）：
        基线 = 现状（现有防护全部启用）；
        方案A = 现状 + 低成本快赢整改措施（候选措施 cost 低/中）；
        方案B = 现状 + 全量整改措施。三轮推演对比。"""
        all_defenses = [d["id"] for d in self.defenses]
        rems = self.candidate_remediations
        plan_a_rems = [c["id"] for c in rems if c.get("cost") in ("低", "中")]
        plan_b_rems = [c["id"] for c in rems]

        def plan_detail(rids):
            return [
                {"defense_id": c["id"], "name": c["name"], "cost": c["cost"],
                 "category": c["category"]}
                for c in rems if c["id"] in rids
            ]

        def round_with(remediation_ids):
            saved = dict(self.defense_states)
            saved_defs = list(self.defenses)
            try:
                # 注入本轮整改措施
                for c in rems:
                    if c["id"] in remediation_ids:
                        self.defenses.append({
                            "id": c["id"], "name": c["name"], "desc": c["desc"],
                            "blocks": c["covers"], "cost": c["cost"],
                            "category": c["category"],
                            "bypass_rate": 0.0,
                            "detection_rate": 0.95,
                            "remediation": True,
                        })
                        self.defense_states[c["id"]] = False
                # 现状防护全开（基线口径）+ 本轮整改措施
                r = self._run_round(
                    all_defenses + [c["id"] for c in rems if c["id"] in remediation_ids])
                return {
                    "completed_steps": r["completed_steps"],
                    "blocked_steps": r["blocked_steps"],
                    "compromised_nodes": r["compromised_nodes"],
                    "residual_risks": r["residual_risks"],
                }
            finally:
                self.defenses = saved_defs
                self.defense_states = saved

        baseline = round_with([])
        round_a = round_with(plan_a_rems)
        round_b = round_with(plan_b_rems)
        result = {
            "ok": True,
            "scenario": self.SCENARIO_NAME,
            "baseline_note": "基线口径：现状（现有防护全部启用）",
            "baseline": baseline,
            "plan_a": {
                "name": "方案A：现状+低成本快赢整改",
                "defenses": plan_detail(plan_a_rems),
                "count": len(plan_a_rems),
                "result": round_a,
            },
            "plan_b": {
                "name": "方案B：现状+全量整改",
                "defenses": plan_detail(plan_b_rems),
                "count": len(plan_b_rems),
                "result": round_b,
            },
            "comparison": {
                "compromised": {
                    "baseline": len(baseline["compromised_nodes"]),
                    "plan_a": len(round_a["compromised_nodes"]),
                    "plan_b": len(round_b["compromised_nodes"]),
                },
                "blocked_steps": {
                    "baseline": len(baseline["blocked_steps"]),
                    "plan_a": len(round_a["blocked_steps"]),
                    "plan_b": len(round_b["blocked_steps"]),
                },
            },
            "disclaimer": self.DISCLAIMER,
        }
        # 2026-09-18 P1-5 修复：调用后恢复干净态
        # （此前 node_states/step_states 停在最后方案轮次终态，与 remediate_sim 修复前同型泄漏）
        self.reset(keep_behavior=True)
        return result

    # ===== P0-3 ATT&CK 覆盖度报告（Atomic Red Team coverage map 思想）=====

    def attck_coverage(self):
        """场景级 ATT&CK 覆盖：14 战术 × 覆盖技术/步数。"""
        from . import realism
        tactics = {}
        techs = {}
        for s in self.attack_steps:
            m = s.get("mitre", "")
            if not m:
                continue
            base = m.split(".")[0]
            techs.setdefault(base, {"name": s.get("technique", ""), "count": 0,
                                    "steps": []})
            techs[base]["count"] += 1
            techs[base]["steps"].append(s["id"])
            tac = s.get("mitre_tactic_zh") or "未分类"
            tactics.setdefault(tac, []).append(base)
        # 战术顺序固定
        order = ["侦察", "初始访问", "执行", "持久化", "权限提升", "防御规避",
                 "凭据访问", "发现", "横向移动", "收集", "命令与控制", "数据渗出",
                 "影响", "未分类"]
        matrix = []
        for tac in order:
            if tac in tactics:
                uniq = sorted(set(tactics[tac]))
                matrix.append({
                    "tactic": tac,
                    "technique_count": len(uniq),
                    "step_count": sum(techs[t]["count"] for t in uniq),
                    "techniques": [{"id": t, "name": techs[t]["name"]}
                                   for t in uniq],
                })
        return {
            "scenario": self.SCENARIO_ID,
            "total_techniques": len(techs),
            "total_steps": len(self.attack_steps),
            "covered_tactics": len(matrix),
            "tactic_order_total": len(order),
            "matrix": matrix,
        }

    def _dynamic_bypass_rate(self, step, defense):
        """C 档：绕过率 = CVSS 可利用性 × (1 - 防御检出率)。"""
        exp = step.get("exploitability", 0.9)
        det = defense.get("detection_rate", 0.5)
        return round(exp * (1 - det), 3)

    def reset(self, keep_behavior=False):
        """复位推演状态。keep_behavior=True 时保留行为模拟配置（画像/目标导向）
        与概率模式——供内部推演流程（两轮闭环/蒙特卡洛/多方案对比）复用，
        避免推演中途清掉用户配置；用户点「重置」按钮走默认全量复位
        （2026-09-14 乐叔口径：重置=恢复启动推演前画面，再次推演过程可重复，
        画像与概率开关一并复位）。"""
        for nid in self.node_states:
            self.node_states[nid] = NodeState.SAFE
        for sid in self.step_states:
            self.step_states[sid] = StepState.PENDING
        for did in self.defense_states:
            self.defense_states[did] = False
        self.events.clear()
        self.started = False
        self.start_time = None
        self.session_id = str(uuid.uuid4())[:8]
        self.bypassed_count = 0
        self.clock = 0.0
        self.timeline.clear()
        self.block_sources = {}
        # 决策点解决标记复位（2026-09-23 演练评估打分用；决策效果已随
        # step_states 复位，resolved 标记必须同步清，防跨轮残留）
        for dp in self.decision_points:
            dp["resolved"] = None
        if not keep_behavior:
            # 2026-09-14（乐叔 16:41/17:15 报告重置不干净）：行为模拟配置复位为默认，
            # 概率模式同步关闭——否则推演前设置的画像/目标导向/概率开关跨轮残留，
            # 与"重置=恢复启动推演前"口径冲突。
            self.behavior_profile = "script_kiddie"
            self.behavior_objective = None
            self.prob_mode = False

    def set_prob_mode(self, on):
        self.prob_mode = bool(on)
        self._log("system",
                  f"概率仿真模式已{'开启' if on else '关闭'}"
                  f"（防御绕过率见各防御条目）", severity="info")

    # ===== P0：脱敏 =====
    def anonymize_map(self):
        """生成 node_id -> 代号的脱敏映射。高敏资产用固定代号，其余按类型代号。"""
        high_keywords = ["人口", "精子", "HIS", "EMR", "病历", "PACS"]
        type_zh = {"server": "服务器", "database": "数据库", "workstation": "终端",
                   "switch": "交换机", "firewall": "防火墙", "network": "网络设备",
                   "external": "外部节点", "isolator": "隔离设备", "gap": "网闸",
                   "behavior": "审计设备", "iot": "物联设备"}
        m = {}
        hi = 0
        for n in self.nodes:
            label = n["label"]
            if any(k in label for k in high_keywords):
                hi += 1
                m[n["id"]] = f"高敏资产{hi}"
            else:
                m[n["id"]] = f"{type_zh.get(n['type'], '节点')}{len(m) + 1}"
        return m

    def _display_label(self, nid, anon_map=None):
        if self.anonymize and anon_map:
            return anon_map.get(nid, nid)
        node = next((x for x in self.nodes if x["id"] == nid), None)
        return node["label"] if node else nid

    # ===== P1-3/P3：业务后果 + AAR 复盘 + 合规映射 =====
    def business_consequences(self, anon_map=None):
        """汇总被攻陷节点的业务后果、患者安全等级、合规条款。"""
        breached = [nid for nid, s in self.node_states.items()
                    if s in (NodeState.COMPROMISED, NodeState.EXFILTRATED, NodeState.ENCRYPTED)]
        items = []
        max_safety = "低"
        safety_order = {"低": 1, "中": 2, "高": 3}
        compliance_set = set()
        for nid in breached:
            node = next((x for x in self.nodes if x["id"] == nid), None)
            if not node:
                continue
            impact = realism.asset_impact(node)
            state = self.node_states[nid].value
            items.append({
                "node": self._display_label(nid, anon_map),
                "state": state,
                "sensitivity": impact["sensitivity"],
                "business": impact["business"],
                "patient_safety": impact["patient_safety"],
                "compliance": impact["compliance"],
                "compliance_detail": impact.get("compliance_detail", []),
            })
            if safety_order.get(impact["patient_safety"], 1) > safety_order.get(max_safety, 1):
                max_safety = impact["patient_safety"]
            for c in impact["compliance"]:
                compliance_set.add(c)
        return {
            "breached_assets": items,
            "max_patient_safety": max_safety,
            "compliance_obligations": sorted(compliance_set),
            "impact_chain": self.impact_chain(anon_map),
        }

    def impact_chain(self, anon_map=None):
        """P1-6 影响传播链（兵棋多域复合影响思想）：
        从攻陷节点沿业务影响依赖图传播，输出网络域→业务域→组织域的链与覆盖。"""
        breached = [nid for nid, s in self.node_states.items()
                    if s in (NodeState.COMPROMISED, NodeState.EXFILTRATED, NodeState.ENCRYPTED)]
        chains = []
        reached = set()
        for nid in breached:
            node = next((x for x in self.nodes if x["id"] == nid), None)
            if not node:
                continue
            label = self._display_label(nid, anon_map)
            chain_items = []
            for item in realism.impact_propagation(node["label"]):
                domain = realism.impact_domain(item)
                chain_items.append({"node": item, "domain": domain})
                reached.add(item)
            chains.append({"source": label, "state": self.node_states[nid].value,
                           "chain": chain_items})
        domains = sorted({c["domain"] for ch in chains for c in ch["chain"]})
        return {
            "chains": chains,
            "reached_domains": domains,
            "reached_count": len(reached),
            "note": "影响链为剧本化推演的定性传播路径，用于风险沟通，非实测定量",
        }

    def aar_report(self, anon_map=None):
        """P3：AAR 复盘（攻击链 + 防御缺口 + 改进项）。"""
        # 攻击链（已完成的攻击步）
        completed = [s for s in self.attack_steps if self.step_states[s["id"]] == StepState.COMPLETED]
        blocked = [s for s in self.attack_steps if self.step_states[s["id"]] == StepState.BLOCKED]
        attack_chain = [
            {"step": s["id"], "name": s["name"],
             "mitre": s.get("mitre", ""), "tactic": s.get("mitre_tactic_zh", "")}
            for s in completed
        ]
        # 防御缺口（未激活的防御）
        gaps = [
            {"id": d["id"], "name": d["name"], "cost": d["cost"],
             "category": d.get("category", "")}
            for d in self.defenses if not self.defense_states.get(d["id"])
        ]
        # 改进项 = 未激活防御 + 已完成攻击对应的整改
        improvements = [
            {"item": d["name"], "reason": "防御未激活，攻击链可直达",
             "dept": self.DEPT_MAP.get(d.get("category", ""), "信息中心（数字化建设办公室）")}
            for d in gaps
        ]
        return {
            "attack_chain": attack_chain,
            "blocked_count": len(blocked),
            "defense_gaps": gaps,
            "improvements": improvements,
        }

    def generate_report(self):
        completed = sum(1 for s in self.step_states.values() if s == StepState.COMPLETED)
        blocked = sum(1 for s in self.step_states.values() if s == StepState.BLOCKED)
        pending = sum(1 for s in self.step_states.values() if s == StepState.PENDING)
        compromised = sum(1 for s in self.node_states.values() if s == NodeState.COMPROMISED)
        defended = sum(1 for d in self.defense_states.values() if d)

        # 整改建议单：优先增量候选措施库（2026-09-06 口径）；
        # 无候选措施时兜底用 defenses 映射（旧行为）
        priority_order = {"低": 1, "中": 2, "高": 3}
        remediation = []
        if self.candidate_remediations:
            for c in sorted(self.candidate_remediations,
                            key=lambda x: priority_order.get(x["cost"], 9)):
                remediation.append({
                    "defense_id": c["id"],
                    "item": c["name"],
                    "detail": c["desc"],
                    "cost": c["cost"],
                    "priority_hint": "快赢（成本低，建议先行）" if c["cost"] == "低"
                                     else ("重点（中期实施）" if c["cost"] == "中"
                                           else "架构级（纳入规划）"),
                    "dept": c["dept"],
                    "category": c["category"],
                    "blocks_steps": c["covers"],
                    "trap": c["trap"],
                    "root_cause": c["root_cause"],
                    "bypass_rate": 0.0,
                })
        else:
            for d in sorted(self.defenses, key=lambda x: priority_order.get(x["cost"], 9)):
                remediation.append({
                    "defense_id": d["id"],
                    "item": d["name"],
                    "detail": d["desc"],
                    "cost": d["cost"],
                    "priority_hint": "快赢（成本低，建议先行）" if d["cost"] == "低"
                                     else ("重点（中期实施）" if d["cost"] == "中"
                                           else "架构级（纳入规划）"),
                    "dept": self.DEPT_MAP.get(d["category"], "信息中心（数字化建设办公室）"),
                    "category": d["category"],
                    "blocks_steps": d["blocks"],
                    "bypass_rate": d.get("bypass_rate", 0.0),
                })

        anon_map = self.anonymize_map() if self.anonymize else None

        return {
            "scenario": self.SCENARIO_NAME,
            "scenario_id": self.SCENARIO_ID,
            "session_id": self.session_id,
            "start_time": self.start_time,
            "prob_mode": self.prob_mode,
            "anonymize": self.anonymize,
            "classification": "内部" if self.anonymize else "秘密·涉真实资产",
            "disclaimer": self.DISCLAIMER,
            # 推演参数标注（2026-09-18 产品化 P1-8，对齐 KB-03-0215 §7.5 可复现性）：
            # 画像/目标导向/prob_mode/seed 全量留痕，同参数推演可复现。
            "simulation_params": {
                "behavior_profile": self.behavior_profile,
                "behavior_objective": self.behavior_objective,
                "prob_mode": self.prob_mode,
                "monte_carlo_seed": "42（蒙特卡洛固定种子，保证可复现）",
                "calibration_note": "概率参数为工程分级标定，用于相对风险排序，非绝对概率预言",
            },
            "threat_briefing": self.threat_briefing(),
            "summary": {
                "total_steps": len(self.attack_steps),
                "completed": completed,
                "blocked": blocked,
                "pending": pending,
                "nodes_compromised": compromised,
                "total_nodes": len(self.nodes),
                "defenses_active": defended,
                "total_defenses": len(self.defenses),
                "bypassed": self.bypassed_count,
            },
            "remediation": remediation,
            "events": self.events,
            "timeline": sorted(self.timeline, key=lambda x: x["t"]),
            "business_consequences": self.business_consequences(anon_map),
            "defense_contribution": self.defense_contribution(),
            "scorecard": self.evaluation_scorecard(),
            "aar": self.aar_report(anon_map),
            "attack_steps": [
                {**s, "state": self.step_states[s["id"]].value}
                for s in self.attack_steps
            ],
            "nodes": [
                {**n, "state": self.node_states[n["id"]].value,
                 "label": self._display_label(n["id"], anon_map)}
                for n in self.nodes
            ],
            "defenses": [
                {**d, "active": self.defense_states[d["id"]]}
                for d in self.defenses
            ],
        }
