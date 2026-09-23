from flask import Blueprint, jsonify, session

from ..auth.routes import login_required
from ..models import Upload
from .rules import LEVELS, classify_data_dict_csv

bp = Blueprint("classify", __name__)


@bp.route("/run/<int:upload_id>")
@login_required
def run(upload_id):
    """对已脱密入库的数据字典执行分类分级。"""
    rec = Upload.query.filter_by(
        id=upload_id, tenant_id=session["tenant_id"],
        kind=Upload.KIND_DATA_DICT, status=Upload.STATUS_DEIDENTIFIED,
    ).first_or_404()
    with open(rec.stored_path, encoding="utf-8") as fp:
        results = classify_data_dict_csv(fp.read())
    dist = {LEVELS[i]: sum(1 for r in results if r["level"] == i) for i in range(1, 6)}
    return jsonify({"upload_id": upload_id, "total": len(results),
                    "distribution": dist, "items": results})


@bp.route("/levels")
@login_required
def levels():
    return jsonify(LEVELS)
