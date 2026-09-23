"""
六步推演工作流引擎（2026-09-03 按乐叔修订版流程落地）。

运行机制（乐叔定义，2026-09-03 修订）：
1. 导入拓扑图（可选：不导入则用默认场景）
2. 首次推演（轮1：现状）
3. 给出整改方案
4. 将整改方案中的建议体现到拓扑图中（生成整改后拓扑并导入）
5. 第二次推演（轮2：整改后拓扑上推演）
6. 给出最终推演报告（聚合两轮 + 落盘 markdown）

注：按乐叔要求，输出不含损失金额（万美元等财务口径）。
"""
import os
import json
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_DIR = os.path.join(BASE_DIR, "reports")

WORKFLOW_DISCLAIMER = (
    "【工作流声明】本推演为剧本化桌面推演：攻击链与防御对策为预设内容，"
    "推演结果用于风险沟通、培训与整改优先级论证，不构成安全评估结论，"
    "不含损失金额测算（2026-09-03 乐叔要求）。"
)


def run_workflow(manager, topo_manager, topology_id=None, scenario_id=None,
                 defense_ids=None):
    """六步推演工作流。返回 {ok, steps, scenario_id, report_path, ...}。

    topology_id 优先（步骤1 导入拓扑）；否则用 scenario_id（默认场景）。"""
    steps = {}

    # ===== 步骤1：导入拓扑图（或选默认场景）=====
    sid = None
    import_info = {"mode": "default_scenario", "imported": False}
    if topology_id:
        result = topo_manager.import_as_scenario(topology_id, manager)
        if not result.get("ok"):
            return {"ok": False, "error": f"拓扑导入失败: {result.get('error', '')}"}
        sid = result.get("scenario_id") or f"topo_{topology_id}"
        topo = topo_manager.get_topology(topology_id) or {}
        import_info = {
            "mode": "topology_import",
            "imported": True,
            "topology_id": topology_id,
            "topology_name": topo.get("name", topology_id),
            "risk_count": len(topo.get("risks", [])),
        }
    else:
        available = [s["id"] for s in manager.list_scenarios()]
        if scenario_id and scenario_id in available:
            sid = scenario_id
        elif available:
            sid = available[0]
        else:
            return {"ok": False, "error": "无可用场景"}
        import_info["scenario_id"] = sid
    steps["1_import"] = import_info

    inst = manager.get_instance(sid)
    if not inst:
        return {"ok": False, "error": f"场景不存在: {sid}"}

    # ===== 步骤2-3：现状推演 → 整改方案（2026-09-06 口径：轮1 现状防护全开）=====
    # defense_ids（勾选集合）同时约束整改单/轮2 注入/概率对比，保证全链口径一致
    sim = inst.remediate_sim(remediation_ids=defense_ids)
    if not sim.get("ok"):
        return {"ok": False, "error": "推演执行失败"}

    steps["2_sim_round1"] = {
        "completed_steps": sim["round1"]["completed_steps"],
        "blocked_steps": sim["round1"]["blocked_steps"],
        "compromised_nodes": sim["round1"]["compromised_nodes"],
        "weak_steps": sim["round1"]["weak_steps"],
        "baseline_note": sim.get("baseline_note", ""),
        # 防御策略调优体检（2026-09-23 丈八「策略验证」思想）
        "tuning_suggestions": sim.get("tuning_suggestions", []),
    }
    steps["3_remediation"] = {
        "plan": sim["remediation_plan"],
        "count": len(sim["remediation_plan"]),
        "note": ("" if sim["remediation_plan"] else
                 "该场景/拓扑无增量整改候选措施，"
                 "整改需补充安全设备后重新导入推演。"),
    }
    # 概率突破率对比（现状 vs 整改后，纵深加固量化）
    steps["prob_comparison"] = sim.get("prob_comparison", {})

    # ===== 步骤4：整改建议体现到拓扑图 → 导入整改后拓扑 =====
    # chosen 与 sim.remediation_plan 同源（均受 defense_ids 约束），保证一致
    chosen = [p["defense_id"] for p in sim["remediation_plan"]]
    remediated_topo = inst.build_remediated_topology(chosen)
    # 整改产物统一归入「场景整改产物」组（2026-09-06 乐叔要求：
    # 拓扑库业务区只显示原始拓扑，整改产物为派生缓存单列折叠区）
    remediated_topo["group"] = "场景整改产物"
    tid2 = remediated_topo["id"]
    topo_manager.save_topology(remediated_topo)
    imp2 = topo_manager.import_as_scenario(tid2, manager)
    if not imp2.get("ok"):
        return {"ok": False, "error": f"整改后拓扑导入失败: {imp2.get('error', '')}"}
    sid2 = imp2.get("scenario_id") or f"topo_{tid2}"
    steps["4_apply_topology"] = {
        "topology_id": tid2,
        "scenario_id": sid2,
        "applied": remediated_topo["remediation"]["applied"],
        "device_nodes": len(remediated_topo["remediation"]["applied"]),
    }

    # ===== 步骤5：第二次推演（双口径，2026-09-06）=====
    # 5a) 原场景注入整改措施推演：步骤 id 与轮1 一致，新增拦截可精确对比
    sim_round2 = sim.get("round2", {})
    # 5b) 整改后拓扑场景推演：节点 id 一致（节点级攻陷对比），
    #     防御贡献带「整改新增」来源标注（拓扑整改设备映射）
    inst2 = manager.get_instance(sid2)
    if not inst2:
        return {"ok": False, "error": "整改后场景不存在"}
    saved_states = dict(inst2.defense_states)
    try:
        inst2.reset(keep_behavior=True)  # 轮2 推演沿用用户画像（2026-09-14）
        inst2.start()
        for d in inst2.defenses:
            inst2.defense_states[d["id"]] = True
        r2 = inst2._run_all_steps()
        compromised2 = [nid for nid, s in inst2.node_states.items()
                        if s.value in ("compromised", "exfiltrated", "encrypted")]
        contribution = inst2.defense_contribution()
        # 演练评估评分卡（2026-09-23 丈八「人才培养 PDCA」思想）：基于整改后
        # 场景轮2 终态打分（自动推演无人在环决策 → 决策参与维度按 N/A 归一）
        scorecard = inst2.evaluation_scorecard()
    finally:
        inst2.defense_states = saved_states
    # 残余风险：同场景口径（sim 轮2，步骤名可读、与轮1 同体系）
    residual = sim.get("residual_risks", [])
    round2_info = {
        "completed_steps": sim_round2.get("completed_steps", []),
        "blocked_steps": sim_round2.get("blocked_steps", []),
        # 攻陷对比主口径 = 同场景注入推演（节点体系一致，可精确对比）
        "compromised_nodes": sim_round2.get("compromised_nodes", []),
        # 拓扑验证口径（整改后拓扑场景推演）：防御贡献带来源标注
        "topo_validation": {
            "compromised_nodes": compromised2,
            "defense_contribution": contribution,
        },
        "residual_risks": residual,
        "newly_blocked_steps": sim_round2.get("newly_blocked_steps", []),
        "existing_blocked_steps": sim_round2.get("existing_blocked_steps", []),
        "scorecard": scorecard,
    }
    steps["5_sim_round2"] = round2_info

    # ===== 步骤6：最终推演报告（聚合 + 落盘）=====
    conclusion = {
        "compromised_reduced": len(sim["round1"]["compromised_nodes"])
                               - len(compromised2),
        "newly_blocked": len(round2_info["newly_blocked_steps"]),
        "value_note": (f"现状攻陷 {len(sim['round1']['compromised_nodes'])}"
                       f" → 整改后 {len(compromised2)} 个；"
                       f"整改新增拦截 {len(round2_info['newly_blocked_steps'])} 步；"
                       f"残余风险步骤 {len(residual)} 个"),
    }
    report_path = _write_final_report(sid, sid2, inst, inst2, steps, conclusion)
    steps["6_final_report"] = {
        "report_path": report_path,
        "conclusion": conclusion,
        "disclaimer": WORKFLOW_DISCLAIMER,
    }

    return {
        "ok": True,
        "workflow_id": datetime.now().strftime("%Y%m%d-%H%M%S"),
        "scenario_id": sid,
        "remediated_scenario_id": sid2,
        "scenario_name": inst.SCENARIO_NAME,
        "step_names": {s["id"]: s["name"] for s in inst.attack_steps},
        # 拓扑场景步骤名映射（拦截来源展示用，t 系 → 风险标题）
        "topo_step_names": ({s["id"]: s["name"] for s in inst2.attack_steps}
                            if inst2 else {}),
        "steps": steps,
        "report_path": report_path,
    }


def _write_final_report(sid, sid2, inst, inst2, steps, conclusion):
    """最终整改推演报告落盘（markdown，2026-09-06 六段决策型结构），返回文件路径。
    六段：执行摘要 / 风险发现 / 根因分析 / 整改措施与责任 / 整改效果评估 /
    残余风险与下一步。面向决策者，每条发现附业务影响与合规依据。"""
    os.makedirs(REPORT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(REPORT_DIR, f"workflow_{sid}_{ts}.md")

    r1 = steps["2_sim_round1"]
    r2 = steps["5_sim_round2"]
    plan = steps["3_remediation"]["plan"]
    prob = steps.get("prob_comparison", {})
    step_names = {s["id"]: s["name"] for s in inst.attack_steps}
    node_map = {n["id"]: n for n in inst.nodes}

    def step_impact(step_id):
        """薄弱步骤的资产影响：取步骤 effects 目标节点，按 label 匹配资产影响库。"""
        step = next((s for s in inst.attack_steps if s["id"] == step_id), None)
        if not step:
            return None
        targets = [ef["target"] for ef in step.get("effects", [])]
        impacts = []
        for t in targets:
            node = node_map.get(t)
            if node:
                try:
                    from . import realism
                    impacts.append(realism.asset_impact(node))
                except Exception:
                    pass
        return impacts[0] if impacts else None

    weak = r1.get("weak_steps", [])
    newly_blocked = r2.get("newly_blocked_steps", [])
    residual = r2.get("residual_risks", [])
    n_attack = len(inst.attack_steps)
    topo_names = ({s["id"]: s["name"] for s in inst2.attack_steps}
                  if inst2 else {})
    prob_note = ""
    if prob.get("samples"):
        prob_note = (f"概率模式 {prob['samples']} 轮采样：整体突破率 "
                     f"{prob['round1_rate']:.0%} → {prob['round2_rate']:.0%}")

    lines = [
        f"# 整改推演报告 · {inst.SCENARIO_NAME}",
        "",
        f"- 生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 推演场景：{sid}（{inst.metadata()['category']} / {inst.metadata()['difficulty']}）",
        f"- 整改后场景：{sid2}（整改拓扑导入生成）",
        f"- 推演口径：轮1 现状（现有防护全部启用）→ 整改新增措施 → 轮2 整改后验证",
        f"- 证据来源：见场景定义（KB 编号）与《素材溯源表.md》",
        "",
        "---",
        "",
        "## 一、执行摘要",
        "",
    ]
    if weak:
        weak_names = "、".join(step_names.get(w["step"], w["step"]) for w in weak)
        lines.append(f"现状防护全部启用的情况下，仍有 {len(weak)} 个环节可被攻击方突破"
                     f"（{weak_names}），暴露出现有防护的覆盖盲区与单点依赖。")
    else:
        lines.append("现状防护全部启用的情况下，现有攻击链各环节均被拦截，未发现明显覆盖盲区。")
    if newly_blocked:
        nb_names = "、".join(step_names.get(s, s) for s in newly_blocked)
        lines.append(f"本轮 {len(plan)} 项整改措施落地后，新增拦截 {len(newly_blocked)} 个攻击环节"
                     f"（{nb_names}）。{prob_note}。")
    else:
        lines.append(f"本轮 {len(plan)} 项整改措施落地后，确定性拦截保持稳定。{prob_note}。")
    lines += [
        f"整改后残余风险 {len(residual)} 项（见第六节）。",
        "",
        "**核心结论：**",
        "",
    ]
    for i, w in enumerate(weak, 1):
        lines.append(f"{i}. 现状薄弱环节「{step_names.get(w['step'], w['step'])}」"
                     f"——现有防护覆盖不到")
    if newly_blocked:
        lines.append(f"{len(weak) + 1}. 整改措施对薄弱环节形成有效补位，新增拦截 "
                     f"{len(newly_blocked)} 个攻击环节")
    lines += [
        f"{len(weak) + 2}. 残余风险："
        + ("、".join(step_names.get(x['step'], x['step']) for x in residual)
           if residual else "无（整改后无可达攻击环节）"),
        "",
        "---",
        "",
        "## 二、风险发现（现状推演暴露的薄弱环节）",
        "",
    ]
    if not weak:
        lines.append("- 现状防护全部启用下未发现可被突破的环节，风险主要来自概率绕过可能（见第五节）。")
    for w in weak:
        sid_w = w["step"]
        imp = step_impact(sid_w)
        step = next((s for s in inst.attack_steps if s["id"] == sid_w), None)
        lines.append(f"### 薄弱环节：{step_names.get(sid_w, sid_w)}（{sid_w}）")
        lines.append("")
        if step and step.get("technique"):
            lines.append(f"- 攻击技术：{step.get('technique')}"
                         + (f"（MITRE {step['mitre']}）" if step.get("mitre") else ""))
        if imp:
            lines.append(f"- 影响资产：敏感度 **{imp['sensitivity']['level']}**"
                         f"（{imp['sensitivity']['grade']}）")
            lines.append(f"- 业务影响：{imp['business']}")
            lines.append(f"- 患者安全影响：{imp['patient_safety']}")
            comp = "、".join(imp.get("compliance", []))
            lines.append(f"- 合规依据：{comp}")
        lines.append("")

    lines += [
        "---",
        "",
        "## 三、根因分析",
        "",
    ]
    # 根因按措施归类（一条措施对应一类根因）
    seen_roots = []
    for p in plan:
        rc = p.get("root_cause", "")
        if rc and rc not in seen_roots:
            seen_roots.append(rc)
            lines.append(f"- {rc}")
            covers = p.get("covers", [])
            if covers:
                cnames = "、".join(step_names.get(c, c) for c in covers)
                lines.append(f"  - 对应薄弱环节：{cnames}；措施：{p['item']}")
    if not seen_roots:
        lines.append("- 该场景未提供增量整改候选措施，无法给出根因-措施对应（需补充安全设备后重新推演）。")

    lines += [
        "",
        "---",
        "",
        "## 四、整改措施与责任",
        "",
        "| 序号 | 整改措施 | 类别 | 成本 | 责任部门 | 针对的薄弱环节 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for i, p in enumerate(plan, 1):
        covers = "、".join(step_names.get(c, c) for c in p.get("covers", []))
        trap_mark = "（诱捕/监测）" if p.get("trap") else ""
        lines.append(f"| {i} | {p['item']}{trap_mark} | {p['category']} | {p['cost']} | "
                     f"{p['dept']} | {covers} |")
    if not plan:
        lines.append("| - | 无增量整改候选措施 | - | - | - | - |")

    lines += [
        "",
        "---",
        "",
        "## 五、整改效果评估",
        "",
        "### 5.1 确定性推演对比",
        "",
        f"| 指标 | 现状（防护全开） | 整改后 | 变化 |",
        f"| --- | --- | --- | --- |",
        f"| 攻陷节点 | {len(r1['compromised_nodes'])} 个 | {len(r2['compromised_nodes'])} 个 | "
        f"减少 {len(r1['compromised_nodes']) - len(r2['compromised_nodes'])} 个 |",
        f"| 完成攻击步 | {len(r1['completed_steps'])}/{n_attack} | "
        f"{len(r2['completed_steps'])}/{n_attack} | 薄弱环节全收敛 |",
        f"| 现状已拦 | {len(r1['blocked_steps'])} 步 | {len(r2['existing_blocked_steps'])} 步 | 保持 |",
        f"| 整改新增拦截 | - | {len(newly_blocked)} 步 | **本轮增量** |",
        "",
        "### 5.2 拦截来源（现状防护 vs 整改新增）",
        "",
    ]
    for d in r2.get("topo_validation", {}).get("defense_contribution", []):
        src = "【整改新增】" if d.get("source") == "remediation" else "【现状防护】"
        hit_names = "、".join(topo_names.get(b, b) for b in d["blocked_steps"])
        hit = hit_names if d["blocked_steps"] else "本轮未触发"
        lines.append(f"- {src} {d['defense']}（{d['cost']}）：拦截 {hit}")
    if prob.get("samples"):
        lines += [
            "",
            "### 5.3 概率模式突破率对比（纵深加固量化）",
            "",
            f"- 现状：整体突破率 {prob['round1_rate']:.0%}"
            f"（{prob['samples']} 轮蒙特卡洛采样，防御绕过率生效）",
            f"- 整改后：整体突破率 {prob['round2_rate']:.0%}，"
            f"降幅 {prob['reduction']:.0%}",
            f"- 说明：{prob.get('note', '')}",
        ]

    # 5.4 行为画像蒙特卡洛快照（2026-09-20 乐叔方案C-B：画像差异量化可见，
    # 内部威胁等画像在主推演步骤级差异之外，附相对风险排序统计）
    try:
        from .adversary import monte_carlo
        mc = monte_carlo(
            inst,
            profile=getattr(inst, "behavior_profile", "script_kiddie"),
            rounds=100, seed=42,
            objective=getattr(inst, "behavior_objective", None),
            defense_mode="none",
        )
        prof_names = {"script_kiddie": "低阶攻击者", "professional": "网络犯罪组织",
                      "apt": "高级持续性威胁", "insider": "内部威胁"}
        obj_names = {None: "无偏好", "exfil": "数据窃取",
                     "ransom": "勒索加密", "destroy": "破坏瘫痪"}
        mb = mc.get("most_breached", [])
        mb_lines = "、".join(
            f"{b.get('label', b.get('node'))}（{b['count']}/100 轮）"
            for b in mb[:3]) or "无"
        mttc_line = (f"- 平均攻陷耗时 MTTC：{mc.get('avg_mttc')} min"
                     if mc.get("avg_mttc") is not None
                     else "- 平均攻陷耗时 MTTC：本轮未达成目标")
        lines += [
            "",
            "### 5.4 行为画像蒙特卡洛快照（相对风险排序）",
            "",
            f"- 攻击者画像：{prof_names.get(mc.get('profile'), mc.get('profile'))}"
            f" · 目标导向：{obj_names.get(mc.get('objective'), mc.get('objective'))}",
            f"- 目标达成率：{mc.get('success_rate', 0):.0%}"
            f"（95% CI {mc['confidence_interval'][0]:.0%}~"
            f"{mc['confidence_interval'][1]:.0%}）",
            f"- 平均攻陷目标：{mc.get('avg_goals_achieved')}/{mc.get('goal_count')}"
            f"（蒙特卡洛 {mc.get('rounds')} 轮）",
            mttc_line,
            f"- 最可能突破点：{mb_lines}",
            f"- 说明：{mc.get('note', '')}",
        ]
    except Exception as exc:
        lines += [
            "",
            "### 5.4 行为画像蒙特卡洛快照",
            "",
            f"- 快照生成失败（{exc}），本节跳过。",
        ]

    # 5.5 防御策略调优体检（2026-09-23 丈八「策略验证」产品思想）：
    # 基于轮1 推演事实，现状防御覆盖失效/零拦截时给出策略核查建议。
    # 与第四节整改措施（增量部署新设备）区分：本节针对现有防御的参数调优。
    tuning = r1.get("tuning_suggestions", [])
    lines += [
        "",
        "### 5.5 防御策略调优体检（现有防御参数核查）",
        "",
    ]
    if tuning:
        lines += [
            "基于现状推演事实，以下现有防御存在「覆盖未生效」疑点，"
            "建议优先核查策略配置（区别于第四节的新增整改措施）：",
            "",
            "| 优先级 | 防御 | 推演事实 | 核查建议 |",
            "| --- | --- | --- | --- |",
        ]
        for t in tuning:
            lines.append(f"| {t['severity']} | {t['defense']} | {t['fact']} | {t['advice']} |")
    else:
        lines.append("- 现状防御均有效拦截或覆盖环节未被突破，未发现策略调优疑点。")

    # 5.6 演练评估评分卡（2026-09-23 丈八「人才培养 PDCA」思想）：
    # 整改后推演终态的防御方表现评分（决策参与/拦截成效/关键资产保全）
    sc = r2.get("scorecard", {})
    lines += [
        "",
        "### 5.6 演练评估评分卡",
        "",
    ]
    if sc.get("dimensions"):
        lines.append(f"**综合得分：{sc['total']} 分（{sc['grade']}）**")
        lines.append("")
        lines.append("| 维度 | 得分 | 说明 |")
        lines.append("| --- | --- | --- |")
        for d in sc["dimensions"]:
            lines.append(f"| {d['name']} | {d['score']}/{d['max']} | {d['detail']} |")
        if sc.get("note"):
            lines.append(f"- {sc['note']}")
        lines.append(f"- {sc.get('disclaimer', '')}")
    else:
        lines.append("- 评分卡数据不可用（推演未产生有效数据）。")

    lines += [
        "",
        "---",
        "",
        "## 六、残余风险与下一步建议",
        "",
    ]
    if residual:
        for x in residual:
            imp = step_impact(x["step"])
            lines.append(f"- **{x['name']}**（{x['step']}）")
            if imp:
                lines.append(f"  - 业务影响：{imp['business']}")
                lines.append(f"  - 合规：{'、'.join(imp.get('compliance', []))}")
        lines += [
            "",
            "**下一步建议：**",
            "",
            "1. 将残余风险纳入下一轮整改候选措施库，持续迭代推演验证",
            "2. 按《素材溯源表.md》核对各措施证据来源（KB 编号），落地前补充现场核实",
            "3. 按责任部门清单推进整改，优先级参考「成本 + 覆盖环节数」排序",
        ]
    else:
        lines.append("- 整改后无残余可达攻击环节。建议按计划开展周期回归推演（BAS 持续验证），防止防护退化。")

    lines += [
        "",
        "---",
        "",
        "## 边界声明",
        "",
        WORKFLOW_DISCLAIMER,
        "",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    _prune_workflow_reports(keep=30)
    return path


def _prune_workflow_reports(keep=30):
    """报告清理机制（2026-09-06）：workflow_*.md 按修改时间保留最近 keep 份，
    防 reports/ 堆积。regression_*.json 不在此列。"""
    try:
        files = sorted(
            (os.path.join(REPORT_DIR, fn) for fn in os.listdir(REPORT_DIR)
             if fn.startswith("workflow_") and fn.endswith(".md")),
            key=os.path.getmtime,
            reverse=True,
        )
        for old in files[keep:]:
            try:
                os.remove(old)
            except OSError:
                pass
    except OSError:
        pass
