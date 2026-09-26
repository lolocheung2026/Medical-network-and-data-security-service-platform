"""攻防推演模块 v0.2.1（2026-09-23 + 2026-09-26 用户拓扑支持）。

沙盘引擎库模式接入：18 场景全量迁入 app/simulation/，
ScenarioManager 显式注册（不依赖沙盘 config.py）。

v0.2.1（ADR-0002 未决项落地，2026-09-26）：
- 用户上传脱密拓扑可替换场景内置拓扑：POST /run/<sid> 传 topo_id。
- 场景实例进程级共享 → 用户拓扑应用前后做备份/恢复（finally 保证不污染）。
- 纯仿真推演，零接触真实网络（产品红线）。
"""
import json
import pkgutil

from flask import Blueprint, jsonify, render_template, request, session

from ..auth.routes import login_required
from ..extensions import db
from ..models import SimulationRun, Upload
from . import scenarios as scenario_pkg
from .engine.scenario_manager import ScenarioManager
from .topology_spec import validate_topology

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


def _load_user_topology(topo_id):
    """读取本租户已脱密入库的拓扑并校验，返回 (ok, topo, err)。"""
    rec = Upload.query.filter_by(
        id=topo_id, tenant_id=session["tenant_id"],
        kind=Upload.KIND_TOPOLOGY, status=Upload.STATUS_DEIDENTIFIED,
    ).first()
    if not rec:
        return False, None, "拓扑不存在或未脱密入库"
    with open(rec.stored_path, encoding="utf-8") as fp:
        ok, topo, errors = validate_topology(fp.read())
    if not ok:
        return False, None, "；".join(errors[:3])
    return True, topo, None


def _run_scenario(sid, topo=None):
    """一键推演，返回 (run_summary, report) 或 (error_msg, None)。"""
    mgr = _manager()
    inst = mgr.get_instance(sid)
    if not inst:
        return "场景不存在", None
    saved = None
    if topo:
        saved = (inst.nodes, inst.edges, inst.node_states)
        inst.apply_user_topology(topo)
    try:
        inst.reset(keep_behavior=True)  # 保留用户画像配置，仅清推演现场
        inst.start()
        run = inst._run_all_steps()
        report = inst.generate_report()
    finally:
        if saved:  # 进程级共享实例：推演后恢复内置拓扑，防跨租户污染
            inst.nodes, inst.edges, inst.node_states = saved
    return run, report


@bp.route("/")
@login_required
def index():
    scenarios = _manager().list_scenarios()
    topologies = (Upload.query
                  .filter_by(tenant_id=session["tenant_id"],
                             kind=Upload.KIND_TOPOLOGY,
                             status=Upload.STATUS_DEIDENTIFIED)
                  .order_by(Upload.id.desc()).all())
    return render_template("simulation.html", scenarios=scenarios,
                           topologies=topologies)


@bp.route("/scenarios")
@login_required
def scenarios_api():
    return jsonify(_manager().list_scenarios())


@bp.route("/run/<sid>", methods=["POST"])
@login_required
def run(sid):
    """执行一次推演并落库，返回完整报告 JSON。

    可选 JSON body：{"topo_id": <已脱密拓扑的 upload id>}
    """
    topo = None
    topo_id = request.json.get("topo_id") if request.is_json else None
    if topo_id:
        ok, topo, err = _load_user_topology(int(topo_id))
        if not ok:
            return jsonify({"ok": False, "error": f"拓扑校验失败：{err}"}), 400

    run, report = _run_scenario(sid, topo)
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
