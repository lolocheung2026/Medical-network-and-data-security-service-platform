"""沙盘原生推演工作台迁移（2026-09-26，乐叔要求操作界面 100% 对齐原沙盘）。

前端资产（templates/scenario.html、sandbox_dashboard.html、static/css/style.css、
static/js/app.js）整体迁入，JS 零改动——API 路径模式与原沙盘完全一致。

路由挂载于平台根级（无 Blueprint 前缀）：/scenario/<sid>、/api/scenario/*、
/api/cves、/api/report/*。全部端点过平台登录门禁（原沙盘无登录）。
拓扑库相关端点（TopologyManager 未迁）返回明确未迁移错误。
"""
import json
import os

from flask import Blueprint, jsonify, render_template, request

from ..auth.routes import login_required
from .routes import _manager

bp = Blueprint("sandbox_ui", __name__)


@bp.route("/scenario/<sid>")
@login_required
def scenario_view(sid):
    inst = _manager().get_instance(sid)
    if not inst:
        return "场景不存在", 404
    meta = inst.metadata()
    return render_template("scenario.html", meta=meta, sid=sid)


# ===== 原沙盘 API（薄转发 manager，登录门禁） =====

@bp.route("/api/scenario/<sid>")
@login_required
def api_get(sid):
    snap = _manager().get_snapshot(sid)
    if not snap:
        return jsonify({"ok": False, "error": "场景不存在"}), 404
    return jsonify(snap)


@bp.route("/api/scenario/<sid>/start", methods=["POST"])
@login_required
def api_start(sid):
    return jsonify(_manager().start(sid))


@bp.route("/api/scenario/<sid>/reset", methods=["POST"])
@login_required
def api_reset(sid):
    return jsonify(_manager().reset(sid))


@bp.route("/api/scenario/<sid>/attack", methods=["POST"])
@login_required
def api_attack(sid):
    step_id = (request.json or {}).get("step_id", "")
    return jsonify(_manager().execute_attack(sid, step_id))


@bp.route("/api/scenario/<sid>/defense", methods=["POST"])
@login_required
def api_defense(sid):
    defense_id = (request.json or {}).get("defense_id", "")
    return jsonify(_manager().toggle_defense(sid, defense_id))


@bp.route("/api/scenario/<sid>/defense_all", methods=["POST"])
@login_required
def api_defense_all(sid):
    enable = bool((request.json or {}).get("enable", True))
    return jsonify(_manager().set_all_defenses(sid, enable))


@bp.route("/api/scenario/<sid>/prob_mode", methods=["POST"])
@login_required
def api_prob_mode(sid):
    enable = bool((request.json or {}).get("enable", False))
    return jsonify(_manager().set_prob_mode(sid, enable))


@bp.route("/api/scenario/<sid>/report")
@login_required
def api_report(sid):
    report = _manager().get_report(sid)
    if not report:
        return jsonify({"ok": False, "error": "场景不存在"}), 404
    return jsonify(report)


@bp.route("/api/scenario/<sid>/attack_graph")
@login_required
def api_attack_graph(sid):
    graph = _manager().get_attack_graph(sid)
    if graph is None:
        return jsonify({"ok": False, "error": "场景不存在"}), 404
    return jsonify(graph)


@bp.route("/api/scenario/<sid>/behavior_sim", methods=["POST"])
@login_required
def api_behavior_sim(sid):
    body = request.json or {}
    result = _manager().behavior_sim(
        sid, profile=body.get("profile", "professional"),
        rounds=body.get("rounds", 100), seed=body.get("seed"),
        defense_mode=body.get("defense_mode", "none"),
        defense_budget=body.get("defense_budget"),
        objective=body.get("objective"))
    if result is None:
        return jsonify({"ok": False, "error": "场景不存在"}), 404
    return jsonify(result)


@bp.route("/api/scenario/<sid>/behavior_config", methods=["POST"])
@login_required
def api_behavior_config(sid):
    body = request.json or {}
    return jsonify(_manager().set_behavior_config(
        sid, body.get("profile", "script_kiddie"), body.get("objective")))


@bp.route("/api/scenario/<sid>/anonymize", methods=["POST"])
@login_required
def api_anonymize(sid):
    enable = bool((request.json or {}).get("enable", False))
    return jsonify(_manager().set_anonymize(sid, enable))


@bp.route("/api/scenario/<sid>/import_vulns", methods=["POST"])
@login_required
def api_import_vulns(sid):
    body = request.json or {}
    return jsonify(_manager().import_vulns(sid, body.get("vulns", [])))


@bp.route("/api/scenario/<sid>/profiles")
@login_required
def api_profiles(sid):
    return jsonify(_manager().list_profiles())


@bp.route("/api/scenario/<sid>/calibrate", methods=["POST"])
@login_required
def api_calibrate(sid):
    body = request.json or {}
    return jsonify(_manager().calibrate(sid, body.get("mappings", [])))


@bp.route("/api/scenario/<sid>/calibration")
@login_required
def api_calibration(sid):
    cal = _manager().get_calibration(sid)
    if cal is None:
        return jsonify({"ok": False, "error": "场景不存在"}), 404
    return jsonify(cal)


@bp.route("/api/scenario/<sid>/behavior_start", methods=["POST"])
@login_required
def api_behavior_start(sid):
    profile = (request.json or {}).get("profile", "professional")
    return jsonify(_manager().behavior_start(sid, profile=profile))


@bp.route("/api/scenario/<sid>/behavior_step", methods=["POST"])
@login_required
def api_behavior_step(sid):
    return jsonify(_manager().behavior_step(sid))


@bp.route("/api/cves")
@login_required
def api_cves():
    from ..simulation.engine import vuln_db
    return jsonify({"cves": vuln_db.list_cves(), "source": vuln_db.SOURCE_NOTE})


@bp.route("/api/attck/coverage")
@login_required
def api_attck_coverage_all():
    result = {"scenarios": []}
    for _sid, inst in _manager()._instances.items():
        result["scenarios"].append(inst.attck_coverage())
    return jsonify(result)


@bp.route("/api/scenario/<sid>/attck_coverage")
@login_required
def api_attck_coverage(sid):
    inst = _manager().get_instance(sid)
    if not inst:
        return jsonify({"ok": False, "error": "场景不存在"}), 404
    return jsonify(inst.attck_coverage())


@bp.route("/api/scenario/<sid>/briefing", methods=["POST"])
@login_required
def api_briefing(sid):
    from ..simulation.engine import attck_db
    body = request.json or {}
    profile = body.get("profile", "professional")
    return jsonify({"briefing": attck_db.briefing_for_profile(profile),
                    "profile": profile})


@bp.route("/api/scenario/<sid>/decision", methods=["POST"])
@login_required
def api_decision(sid):
    inst = _manager().get_instance(sid)
    if not inst:
        return jsonify({"ok": False, "error": "场景不存在"}), 404
    body = request.json or {}
    return jsonify(inst.resolve_decision(body.get("decision_id", ""),
                                         body.get("option_id", "")))


# ===== 未迁移边界（依赖 TopologyManager / 落盘报告体系） =====

@bp.route("/api/topologies")
@login_required
def api_topo_list():
    """平台拓扑由沙盒上传 + 用户拓扑机制替代；返回空列表兼容 dashboard JS。"""
    return jsonify([])


@bp.route("/api/topology/<tid>/import", methods=["POST"])
@login_required
def api_topo_import(tid):
    return jsonify({"ok": False,
                    "error": "拓扑库迁移中：请使用平台「沙盒上传」入口上传拓扑"}), 400


@bp.route("/api/scenario/<sid>/remediate_sim", methods=["POST"])
@login_required
def api_remediate_sim(sid):
    """两轮整改闭环推演（不依赖拓扑库的轮次对比部分）。"""
    return jsonify(_manager().remediate_sim(sid))


@bp.route("/api/scenario/<sid>/compare_plans", methods=["POST"])
@login_required
def api_compare_plans(sid):
    inst = _manager().get_instance(sid)
    if not inst:
        return jsonify({"ok": False, "error": "场景不存在"}), 404
    return jsonify(inst.compare_plans())


@bp.route("/api/scenario/<sid>/apply_remediation", methods=["POST"])
@login_required
def api_apply_remediation(sid):
    return jsonify({"ok": False,
                    "error": "整改产物拓扑库迁移中，暂不可用"}), 400


@bp.route("/api/workflow/run", methods=["POST"])
@login_required
def api_workflow_run():
    return jsonify({"ok": False,
                    "error": "六步工作流依赖拓扑库，迁移中"}), 400


@bp.route("/api/regression/run", methods=["POST"])
@login_required
def api_regression_run():
    body = request.json or {}
    result = _manager().regression_run(scenario_ids=body.get("scenario_ids"))
    if not result.get("ok"):
        return jsonify(result), 400
    return jsonify(result)


@bp.route("/api/reports")
@login_required
def api_report_list():
    return jsonify({"ok": True, "reports": []})


@bp.route("/api/report/view")
@login_required
def api_report_view():
    return jsonify({"ok": False, "error": "报告落盘体系迁移中"}), 400
