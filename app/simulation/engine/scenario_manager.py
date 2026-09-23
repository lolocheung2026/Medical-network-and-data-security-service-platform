"""
Scenario manager - loads scenarios, manages instances, coordinates API calls.
"""
import glob
import importlib


class ScenarioManager:
    def __init__(self, packages=None):
        """packages: 场景模块路径列表。None = 尝试从 config.py 读取（沙盘内使用）；
        显式传入 = 引擎库模式（外部产品引用，不依赖沙盘 config）。2026-09-18 库化改造。"""
        self._registry = {}   # class registry: id -> class
        self._instances = {}  # active instances: id -> instance
        self._behavior_agents = {}  # sid -> AdversaryAgent（逐步推演会话）
        self._load_scenarios(packages)

    def _load_scenarios(self, packages=None):
        if packages is None:
            try:
                from config import SCENARIO_PACKAGES
                packages = SCENARIO_PACKAGES
            except ImportError:
                # 引擎库模式：外部项目无沙盘 config，跳过自动加载，
                # 场景由调用方用 register_scenario 显式注册。
                packages = []
        for pkg_path in packages:
            mod = importlib.import_module(pkg_path)
            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                if (isinstance(attr, type)
                        and attr.__module__ == mod.__name__
                        and hasattr(attr, "SCENARIO_ID")
                        and attr.SCENARIO_ID
                        and attr.__name__ != "ScenarioBase"):
                    instance = attr()
                    self._registry[attr.SCENARIO_ID] = attr
                    self._instances[attr.SCENARIO_ID] = instance

    def register_scenario(self, scenario_class):
        """引擎库模式：外部产品显式注册场景类（2026-09-18 库化新增）。"""
        instance = scenario_class()
        sid = scenario_class.SCENARIO_ID
        self._registry[sid] = scenario_class
        self._instances[sid] = instance
        return sid

    def list_scenarios(self):
        return [inst.metadata() for inst in self._instances.values()]

    def get_instance(self, sid):
        if sid not in self._instances:
            return None
        return self._instances[sid]

    def unregister(self, sid):
        """移除动态注册场景（拓扑删除/重建时用，2026-09-16）。
        清实例、注册表与行为推演会话三处。"""
        self._instances.pop(sid, None)
        self._registry.pop(sid, None)
        self._behavior_agents.pop(sid, None)
        return {"ok": True}

    def get_snapshot(self, sid):
        inst = self.get_instance(sid)
        if not inst:
            return None
        return inst.snapshot()

    def start(self, sid):
        inst = self.get_instance(sid)
        if not inst:
            return {"ok": False, "error": "场景不存在"}
        inst.reset(keep_behavior=True)  # 启动推演不清用户画像（2026-09-14）
        inst.start()
        return {"ok": True}

    def execute_attack(self, sid, step_id):
        inst = self.get_instance(sid)
        if not inst:
            return {"ok": False, "error": "场景不存在"}
        return inst.execute_attack(step_id)

    def toggle_defense(self, sid, defense_id):
        inst = self.get_instance(sid)
        if not inst:
            return {"ok": False, "error": "场景不存在"}
        return inst.toggle_defense(defense_id)

    def set_all_defenses(self, sid, enable):
        """一键开启/关闭所有防护措施。"""
        inst = self.get_instance(sid)
        if not inst:
            return {"ok": False, "error": "场景不存在"}
        for did in inst.defense_states:
            inst.defense_states[did] = bool(enable)
        active = sum(1 for v in inst.defense_states.values() if v)
        return {"ok": True, "active": active, "total": len(inst.defense_states)}

    def set_prob_mode(self, sid, enable):
        inst = self.get_instance(sid)
        if not inst:
            return {"ok": False, "error": "场景不存在"}
        inst.set_prob_mode(enable)
        return {"ok": True, "prob_mode": inst.prob_mode}

    def reset(self, sid):
        inst = self.get_instance(sid)
        if not inst:
            return {"ok": False, "error": "场景不存在"}
        inst.reset()
        return {"ok": True}

    def get_report(self, sid):
        inst = self.get_instance(sid)
        if not inst:
            return None
        return inst.generate_report()

    def remediate_sim(self, sid, remediation_ids=None):
        """整改闭环两轮推演（2026-09-06 口径）：轮1 现状（现有防护全开）
        → 增量整改措施 → 轮2 整改后对比。remediation_ids 可指定应用措施。"""
        inst = self.get_instance(sid)
        if not inst:
            return {"ok": False, "error": "场景不存在"}
        return inst.remediate_sim(remediation_ids=remediation_ids)

    # ===== P1-7 周期回归推演（BAS 持续验证思想）=====

    def regression_run(self, scenario_ids=None):
        """对场景集合跑三档回归快照（2026-09-06 口径）：
        档1 无防御攻陷 / 档2 现状（防护全开）攻陷 / 档3 整改后（现状+候选措施）攻陷，
        落盘 reports/regression_<ts>.json 供趋势对比，返回本次+历史对比。"""
        import json
        import os
        from datetime import datetime
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        report_dir = os.path.join(base, "reports")
        os.makedirs(report_dir, exist_ok=True)

        targets = scenario_ids or [s["id"] for s in self.list_scenarios()]
        snapshots = []
        for sid in targets:
            inst = self.get_instance(sid)
            if not inst:
                continue
            # 档1：无防御攻陷数
            base_res = inst._round_with_defenses([])
            # 档2：现状（现有防护全开）攻陷数
            all_def = [d["id"] for d in inst.defenses]
            current_res = inst._round_with_defenses(all_def)
            # 档3：整改后（现状 + 候选措施全量注入）
            rem = inst.remediate_sim()
            remediated_res = rem.get("round2", {}) if rem.get("ok") else {}
            snapshots.append({
                "scenario_id": sid,
                "scenario_name": inst.SCENARIO_NAME,
                "no_defense_compromised": len(base_res["compromised_nodes"]),
                "current_compromised": len(current_res["compromised_nodes"]),
                "remediated_compromised": len(remediated_res.get("compromised_nodes", [])),
                "remediated_newly_blocked": len(remediated_res.get("newly_blocked_steps", [])),
                "remediation_count": len(inst.candidate_remediations),
                "attack_steps": len(inst.attack_steps),
            })
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = os.path.join(report_dir, f"regression_{ts}.json")
        payload = {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scenario_count": len(snapshots),
            "snapshots": snapshots,
            "note": "周期回归推演快照（2026-09-06 三档口径）："
                    "档1 无防御 / 档2 现状（防护全开）/ 档3 整改后（现状+候选措施）。"
                    "剧本化推演口径，非实测",
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        # 历史对比（最近一次前快照）
        history = []
        for fp in sorted(glob.glob(os.path.join(report_dir, "regression_*.json")))[-2:]:
            if fp == path:
                continue
            try:
                with open(fp, encoding="utf-8") as f:
                    history.append(json.load(f))
            except Exception:
                pass
        return {"ok": True, "report_path": path, "snapshots": snapshots,
                "history": history}

    def get_attack_graph(self, sid):
        inst = self.get_instance(sid)
        if not inst:
            return None
        from .attack_graph import AttackGraph
        return AttackGraph(inst).analyze()

    def behavior_sim(self, sid, profile="professional", rounds=100, seed=None,
                     defense_mode="none", defense_budget=None, objective=None):
        inst = self.get_instance(sid)
        if not inst:
            return None
        from .adversary import monte_carlo, PROFILES
        profile = profile if profile in PROFILES else "professional"
        rounds = max(1, min(int(rounds), 1000))
        defense_mode = defense_mode if defense_mode in ("none", "all", "partial", "optimized") else "none"
        if objective not in ("exfil", "ransom", "destroy"):
            objective = None
        return monte_carlo(inst, profile=profile, rounds=rounds, seed=seed,
                           defense_mode=defense_mode, defense_budget=defense_budget,
                           objective=objective)

    def set_behavior_config(self, sid, profile, objective=None):
        """行为模拟配置（2026-09-06：画像+目标导向影响推演结果）。"""
        inst = self.get_instance(sid)
        if not inst:
            return {"ok": False, "error": "场景不存在"}
        return inst.set_behavior_config(profile, objective)

    def set_anonymize(self, sid, enable):
        inst = self.get_instance(sid)
        if not inst:
            return {"ok": False, "error": "场景不存在"}
        inst.anonymize = bool(enable)
        return {"ok": True, "anonymize": inst.anonymize}

    def import_vulns(self, sid, vulns):
        """P1-1：漏扫批量导入——{node_id: [cve_id, ...]} 或 [{node_id, cve_id}]。
        支持内置库与数据安全库外部 CVE；外部 CVE 附适用性校验提示。"""
        inst = self.get_instance(sid)
        if not inst:
            return {"ok": False, "error": "场景不存在"}
        from . import vuln_db
        node_ids = {n["id"] for n in inst.nodes}
        node_labels = {n["id"]: n["label"] for n in inst.nodes}
        applied = []
        if isinstance(vulns, dict):
            mappings = []
            for nid, cves in vulns.items():
                if isinstance(cves, str):
                    cves = [cves]
                for c in cves:
                    mappings.append({"node_id": nid, "cve_id": c})
            vulns = mappings
        for v in vulns:
            nid = v.get("node_id", "")
            cve_id = v.get("cve_id", "")
            if nid not in node_ids:
                continue
            cve = vuln_db.get_cve(cve_id)
            if not cve and not vuln_db.external_cve_lookup(cve_id):
                continue
            exp = vuln_db.exploitability_of(cve_id)
            applies, hint = vuln_db.cve_applies_to_node(cve_id, node_labels[nid])
            inst.calibration[nid] = {
                "cve_id": cve_id,
                "cvss": cve["cvss"] if cve else vuln_db.external_cve_lookup(cve_id)["cvss"],
                "exploitability": exp,
                "applicability": ("适用" if applies else ("未知" if applies is None else "不匹配")),
                "applicable_hint": hint,
            }
            applied.append({"node_id": nid, "cve_id": cve_id,
                            "cvss": inst.calibration[nid]["cvss"],
                            "applicability": inst.calibration[nid]["applicability"]})
        return {"ok": True, "applied_count": len(applied), "applied": applied}

    def list_profiles(self):
        from .adversary import PROFILES, profile_ttp
        return [{"id": k, **v, "ttp": profile_ttp(k)} for k, v in PROFILES.items()]

    def calibrate(self, sid, mappings):
        """漏扫校准：将真实 CVE 绑定到节点，覆盖 exploitability。
        适用性校验：外部 CVE 按厂商/产品/设备类别匹配节点，防张冠李戴。"""
        inst = self.get_instance(sid)
        if not inst:
            return {"ok": False, "error": "场景不存在"}
        from . import vuln_db
        node_ids = {n["id"] for n in inst.nodes}
        node_labels = {n["id"]: n["label"] for n in inst.nodes}
        applied = []
        for mp in mappings:
            nid = mp.get("node_id", "")
            cve_id = mp.get("cve_id", "")
            if nid not in node_ids:
                continue
            if cve_id:  # 绑定真实 CVE
                v = vuln_db.get_cve(cve_id)
                ext = vuln_db.external_cve_lookup(cve_id) if not v else None
                if not v and not ext:
                    continue
                exp = vuln_db.exploitability_of(cve_id)
                applies, hint = vuln_db.cve_applies_to_node(cve_id, node_labels[nid])
                inst.calibration[nid] = {
                    "cve_id": cve_id,
                    "cvss": v["cvss"] if v else ext["cvss"],
                    "exploitability": exp,
                    "applicability": ("适用" if applies else ("未知" if applies is None else "不匹配")),
                    "applicable_hint": hint,
                }
                applied.append({"node_id": nid, "cve_id": cve_id,
                                "cvss": inst.calibration[nid]["cvss"],
                                "applicability": inst.calibration[nid]["applicability"],
                                "hint": hint})
            else:  # 清空校准
                inst.calibration.pop(nid, None)
                applied.append({"node_id": nid, "cve_id": None, "cvss": None})
        return {"ok": True, "applied": applied, "calibration": inst.calibration}

    def get_calibration(self, sid):
        inst = self.get_instance(sid)
        if not inst:
            return None
        return inst.calibration

    # ===== 行为模拟逐步推演（融合到一键推演）=====
    def behavior_start(self, sid, profile="professional"):
        inst = self.get_instance(sid)
        if not inst:
            return {"ok": False, "error": "场景不存在"}
        from .adversary import AdversaryAgent, PROFILES
        profile = profile if profile in PROFILES else "professional"
        inst.reset(keep_behavior=True)  # 行为模拟不清用户画像（2026-09-14）
        agent = AdversaryAgent(inst, profile=profile)
        self._behavior_agents[sid] = agent
        return {
            "ok": True,
            "profile": profile,
            "goals": agent.goals,
            "goals_labels": [agent.nodes[g]["label"] for g in agent.goals],
            "goal_count": len(agent.goals),
            "goal": agent.goal,
            "goal_label": agent.goal_label,
        }

    def behavior_step(self, sid):
        agent = self._behavior_agents.get(sid)
        if not agent:
            return {"ok": False, "error": "行为推演未启动"}
        decision = agent.step()
        inst = self.get_instance(sid)
        return {
            "ok": True,
            "decision": decision,
            "done": agent.done,
            "achieved_count": len([g for g in agent.goals if g in agent.compromised]),
            "goal_count": len(agent.goals),
            "goals_labels": [agent.nodes[g]["label"] for g in agent.goals],
            "compromised": sorted(agent.compromised),
            "nodes": inst.snapshot()["nodes"] if inst else [],
        }
