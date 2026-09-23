"""攻防推演模块 v0.2（2026-09-23）。

沙盘引擎库模式接入：18 场景全量迁入 app/simulation/，
ScenarioManager 显式注册（不依赖沙盘 config.py）。

本迭代边界（ADR-0002）：
- 拓扑来源 = 场景内置拓扑；用户脱密拓扑替换场景拓扑留 v0.2.1。
- 一键推演 = reset → start → 顺序执行全部攻击步 → generate_report → 落库。
- 纯仿真推演，零接触真实网络（产品红线）。
"""
import json
import pkgutil

from flask import Blueprint, jsonify, render_template, request, session

from ..auth.routes import login_required
from ..extensions import db
from ..models import SimulationRun
from . import scenarios as scenario_pkg
from .engine.scenario_manager import ScenarioManager

bp = Blueprint("simulation", __name__)

_mgr = None


def _manager():
    """进程级单例：18 场景注册一次，多请求复用实例状态（推演现场）。"""
    global _mgr
    if _mgr is None:
        mods = [f"app.simulation.scenarios.{m.name}"
                for m in pkgutil.iter_modules(scenario_pkg.__path__)]
        _mgr = ScenarioManager(packages=mods)
    return _mgr


def _run_scenario(sid):
    """一键推演，返回 (run_summary, report) 或 (error_msg, None)。"""
    mgr = _manager()
    inst = mgr.get_instance(sid)
    if not inst:
        return "场景不存在", None
    inst.reset(keep_behavior=True)  # 保留用户画像配置，仅清推演现场
    inst.start()
    run = inst._run_all_steps()
    report = inst.generate_report()
    return run, report


@bp.route("/")
@login_required
def index():
    scenarios = _manager().list_scenarios()
    return render_template("simulation.html", scenarios=scenarios)


@bp.route("/scenarios")
@login_required
def scenarios_api():
    return jsonify(_manager().list_scenarios())


@bp.route("/run/<sid>", methods=["POST"])
@login_required
def run(sid):
    """执行一次推演并落库，返回完整报告 JSON。"""
    run, report = _run_scenario(sid)
    if report is None:
        return jsonify({"ok": False, "error": run}), 404

    rec = SimulationRun(
        tenant_id=session["tenant_id"],
        scenario_id=sid,
        scenario_name=report.get("scenario", sid),
        status=SimulationRun.STATUS_OK,
        result_json=json.dumps(report, ensure_ascii=False),
    )
    db.session.add(rec)
    db.session.commit()
    return jsonify({"ok": True, "run_id": rec.id, "summary": run, "report": report})


@bp.route("/runs")
@login_required
def runs_api():
    """本租户历史推演记录清单（不含报告全文）。"""
    recs = (SimulationRun.query
            .filter_by(tenant_id=session["tenant_id"])
            .order_by(SimulationRun.id.desc())
            .limit(50).all())
    return jsonify([{
        "id": r.id, "scenario_id": r.scenario_id,
        "scenario_name": r.scenario_name, "status": r.status,
        "created_at": r.created_at.strftime("%Y-%m-%d %H:%M:%S"),
    } for r in recs])


@bp.route("/runs/<int:run_id>")
@login_required
def run_detail(run_id):
    """单次推演报告全文（租户隔离）。"""
    rec = SimulationRun.query.filter_by(
        id=run_id, tenant_id=session["tenant_id"]).first_or_404()
    return jsonify({
        "id": rec.id, "scenario_id": rec.scenario_id,
        "scenario_name": rec.scenario_name, "status": rec.status,
        "created_at": rec.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        "report": json.loads(rec.result_json) if rec.result_json else None,
    })
