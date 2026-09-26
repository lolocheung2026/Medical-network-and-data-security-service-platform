from flask import Blueprint, jsonify, render_template, session

from ..auth.routes import current_user, login_required
from ..models import Upload
from .rules import LEVELS, classify_data_dict_csv

bp = Blueprint("classify", __name__)


def _level_color(level):
    return {1: "#888780", 2: "#185FA5", 3: "#c98a1b", 4: "#c0392b", 5: "#7b1fa2"}[level]


@bp.route("/")
@login_required
def index():
    """分类分级页面：列出本租户已脱密入库的数据字典。"""
    dicts = Upload.query.filter_by(
        tenant_id=session["tenant_id"],
        kind=Upload.KIND_DATA_DICT, status=Upload.STATUS_DEIDENTIFIED,
    ).order_by(Upload.id.desc()).all()
    return render_template("classify.html", user=current_user(),
                           dicts=dicts, result=None, upload_id=None)


@bp.route("/result/<int:upload_id>")
@login_required
def result_page(upload_id):
    """分类结果页：逐字段定级 + 规则溯源 + 分布统计。"""
    rec = Upload.query.filter_by(
        id=upload_id, tenant_id=session["tenant_id"],
        kind=Upload.KIND_DATA_DICT, status=Upload.STATUS_DEIDENTIFIED,
    ).first_or_404()
    with open(rec.stored_path, encoding="utf-8") as fp:
        results = classify_data_dict_csv(fp.read())
    dist = {i: sum(1 for r in results if r["level"] == i) for i in range(1, 6)}
    total = len(results)
    dicts = Upload.query.filter_by(
        tenant_id=session["tenant_id"],
        kind=Upload.KIND_DATA_DICT, status=Upload.STATUS_DEIDENTIFIED,
    ).order_by(Upload.id.desc()).all()
    return render_template("classify.html", user=current_user(), dicts=dicts,
                           result=results, dist=dist, total=total,
                           upload_id=upload_id,
                           level_color=_level_color, LEVELS=LEVELS)


@bp.route("/run/<int:upload_id>")
@login_required
def run(upload_id):
    """对已脱密入库的数据字典执行分类分级（JSON API）。"""
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
