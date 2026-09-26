from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from ..auth.routes import current_user, login_required
from ..extensions import db
from ..models import ClassificationCorrection, Upload
from .rules import LEVELS, classify_data_dict_csv

bp = Blueprint("classify", __name__)


def _level_color(level):
    return {1: "#888780", 2: "#185FA5", 3: "#c98a1b", 4: "#c0392b", 5: "#7b1fa2"}[level]


def _corrections_for(tenant_id):
    """本租户人工校正映射：{(table, field): {"level": int, "reason": str}}。"""
    return {
        (c.table_name, c.field_name): {"level": c.corrected_level, "reason": c.reason}
        for c in ClassificationCorrection.query.filter_by(tenant_id=tenant_id).all()
    }


def _dicts_for(tenant_id):
    return (Upload.query.filter_by(
        tenant_id=tenant_id, kind=Upload.KIND_DATA_DICT,
        status=Upload.STATUS_DEIDENTIFIED)
        .order_by(Upload.id.desc()).all())


@bp.route("/")
@login_required
def index():
    """分类分级页面：列出本租户已脱密入库的数据字典。"""
    return render_template("classify.html", user=current_user(),
                           dicts=_dicts_for(session["tenant_id"]),
                           result=None, upload_id=None)


@bp.route("/result/<int:upload_id>")
@login_required
def result_page(upload_id):
    """分类结果页：逐字段定级 + 规则溯源 + 分布统计（含人工校正回流）。"""
    rec = Upload.query.filter_by(
        id=upload_id, tenant_id=session["tenant_id"],
        kind=Upload.KIND_DATA_DICT, status=Upload.STATUS_DEIDENTIFIED,
    ).first_or_404()
    with open(rec.stored_path, encoding="utf-8") as fp:
        results = classify_data_dict_csv(fp.read(),
                                         _corrections_for(session["tenant_id"]))
    dist = {i: sum(1 for r in results if r["level"] == i) for i in range(1, 6)}
    total = len(results)
    return render_template("classify.html", user=current_user(),
                           dicts=_dicts_for(session["tenant_id"]),
                           result=results, dist=dist, total=total,
                           upload_id=upload_id,
                           level_color=_level_color, LEVELS=LEVELS)


@bp.route("/correct", methods=["POST"])
@login_required
def correct():
    """人工校正：覆盖某字段定级（以 table.field 为键，后续分类优先命中）。"""
    upload_id = int(request.form.get("upload_id", 0))
    table = request.form.get("table", "").strip()[:128]
    field = request.form.get("field", "").strip()[:128]
    try:
        corrected_level = int(request.form.get("level", 0))
    except ValueError:
        corrected_level = 0
    reason = request.form.get("reason", "").strip()[:256]
    if not (table and field) or corrected_level not in LEVELS:
        return jsonify({"ok": False, "msg": "参数非法"}), 400

    rec = Upload.query.filter_by(
        id=upload_id, tenant_id=session["tenant_id"],
        kind=Upload.KIND_DATA_DICT, status=Upload.STATUS_DEIDENTIFIED,
    ).first_or_404()
    with open(rec.stored_path, encoding="utf-8") as fp:
        results = classify_data_dict_csv(fp.read())  # 规则原始定级
    original = next((r["level"] for r in results
                     if r["table"] == table and r["field"] == field), None)
    if original is None:
        return jsonify({"ok": False, "msg": "字段不存在于该字典"}), 404

    corr = ClassificationCorrection.query.filter_by(
        tenant_id=session["tenant_id"], table_name=table,
        field_name=field).first()
    if not corr:
        corr = ClassificationCorrection(
            tenant_id=session["tenant_id"], table_name=table, field_name=field)
        db.session.add(corr)
    corr.original_level = original
    corr.corrected_level = corrected_level
    corr.reason = reason
    db.session.commit()
    return redirect(url_for("classify.result_page", upload_id=upload_id))


@bp.route("/run/<int:upload_id>")
@login_required
def run(upload_id):
    """对已脱密入库的数据字典执行分类分级（JSON API，含校正回流）。"""
    rec = Upload.query.filter_by(
        id=upload_id, tenant_id=session["tenant_id"],
        kind=Upload.KIND_DATA_DICT, status=Upload.STATUS_DEIDENTIFIED,
    ).first_or_404()
    with open(rec.stored_path, encoding="utf-8") as fp:
        results = classify_data_dict_csv(fp.read(),
                                         _corrections_for(session["tenant_id"]))
    dist = {LEVELS[i]: sum(1 for r in results if r["level"] == i) for i in range(1, 6)}
    return jsonify({"upload_id": upload_id, "total": len(results),
                    "distribution": dist, "items": results})


@bp.route("/levels")
@login_required
def levels():
    return jsonify(LEVELS)
