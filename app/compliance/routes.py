from flask import Blueprint, jsonify

from ..auth.routes import login_required

bp = Blueprint("compliance", __name__)


@bp.route("/status")
@login_required
def status():
    return jsonify({
        "module": "合规判断",
        "state": "phase2",
        "anchors": ["等保 2.0", "医疗卫生机构网络安全管理办法", "GB/T 39725"],
        "note": "二期上线：规则库建设依赖一期分类分级产出的数据资产清单",
    })
