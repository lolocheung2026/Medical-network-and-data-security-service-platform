from flask import Blueprint, jsonify

from ..auth.routes import login_required

bp = Blueprint("simulation", __name__)


@bp.route("/status")
@login_required
def status():
    return jsonify({
        "module": "攻防推演",
        "state": "seeding",
        "note": "沙盘引擎（engine/ + 18 场景）迁移挂载中，下一迭代接入脱密拓扑库",
    })
