from flask import Blueprint, jsonify, session

from ..auth.routes import login_required
from ..models import Upload

bp = Blueprint("reports", __name__)


@bp.route("/list")
@login_required
def list_reports():
    """报告中心 v1：本租户上传与脱密记录清单（整改报告生成随推演模块接入）。"""
    recs = (Upload.query.filter_by(tenant_id=session["tenant_id"])
            .order_by(Upload.created_at.desc()).limit(50).all())
    return jsonify([{
        "id": r.id, "kind": r.kind, "file": r.original_filename,
        "status": r.status, "time": r.created_at.isoformat(),
    } for r in recs])
