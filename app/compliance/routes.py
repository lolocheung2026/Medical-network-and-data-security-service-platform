"""合规判断模块 v1.0（2026-09-26，ADR-0006/0007）。

法源：22 部法律法规（乐叔 2026-09-26 定，见 seed_data.REGULATIONS）。
边界：不碰密评（报告仅引导咨询密评机构）。
规则内容：检查项为要点草案，正式条文由乐叔按官方文本审定后替换。
"""
from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from ..auth.routes import current_user, login_required
from ..extensions import db
from ..models import ComplianceAssessment, ComplianceItem, RegulationSource
from .seed_data import REGULATIONS, SEED_ITEMS

bp = Blueprint("compliance", __name__)

STATUS_LABELS = {
    ComplianceAssessment.STATUS_COMPLIANT: "符合",
    ComplianceAssessment.STATUS_NON_COMPLIANT: "不符合",
    ComplianceAssessment.STATUS_NOT_APPLICABLE: "不适用",
    ComplianceAssessment.STATUS_PENDING: "待评估",
}


def seed_items():
    """幂等种子：22 部法源 + 检查项草案；旧三锚点数据自动清理。"""
    from ..models import ComplianceItem as CI
    for code, name, short, cat in REGULATIONS:
        if not RegulationSource.query.filter_by(code=code).first():
            db.session.add(RegulationSource(tenant_id=0, code=code, name=name,
                                            short_name=short, category=cat))
    db.session.flush()

    # 清理旧版三锚点样例（2026-09-26 上午的骨架数据）及其评估记录
    for old in ("mlps", "measures", "gb39725"):
        for it in CI.query.filter_by(anchor=old).all():
            ComplianceAssessment.query.filter_by(item_id=it.id).delete()
            db.session.delete(it)

    if CI.query.first() is None:
        for anchor, article, title, provision, checkpoint, hint in SEED_ITEMS:
            db.session.add(CI(tenant_id=0, anchor=anchor, article=article,
                              title=title, provision=provision,
                              checkpoint=checkpoint, evidence_hint=hint))
    db.session.commit()


def _sources():
    return {s.code: s for s in RegulationSource.query.filter_by(active=True).all()}


def _status_of(tenant_id):
    return {a.item_id: a for a in ComplianceAssessment.query.filter_by(
        tenant_id=tenant_id).all()}


@bp.route("/")
@login_required
def index():
    items = ComplianceItem.query.filter_by(active=True).order_by(
        ComplianceItem.anchor, ComplianceItem.article).all()
    sources = _sources()
    # 按效力层级分组 → 组内按法源 → 检查项
    grouped = {}
    for it in items:
        src = sources.get(it.anchor)
        if not src:
            continue
        cat = grouped.setdefault(src.category, {})
        lst = cat.setdefault(src.name, [])
        lst.append(it)
    assessments = _status_of(session["tenant_id"])
    return render_template(
        "compliance.html", user=current_user(),
        grouped=grouped, assessments=assessments, status_labels=STATUS_LABELS)


@bp.route("/assess/<int:item_id>", methods=["POST"])
@login_required
def assess(item_id):
    """提交/更新某检查项的评估状态（本租户）。"""
    ComplianceItem.query.filter_by(id=item_id, active=True).first_or_404()
    status = request.form.get("status", "")
    if status not in STATUS_LABELS:
        return jsonify({"ok": False, "msg": "非法状态值"}), 400
    evidence = request.form.get("evidence", "")[:2000]

    rec = ComplianceAssessment.query.filter_by(
        tenant_id=session["tenant_id"], item_id=item_id).first()
    if not rec:
        rec = ComplianceAssessment(tenant_id=session["tenant_id"], item_id=item_id)
        db.session.add(rec)
    rec.status = status
    rec.evidence = evidence
    db.session.commit()
    return redirect(url_for("compliance.index"))


@bp.route("/report")
@login_required
def report():
    """符合率汇总（按法源）。"""
    items = ComplianceItem.query.filter_by(active=True).all()
    assessments = _status_of(session["tenant_id"])
    sources = _sources()
    total, compliant, non_compliant, na, pending = 0, 0, 0, 0, 0
    by_src = {}
    for it in items:
        st = (assessments.get(it.id).status
              if it.id in assessments else ComplianceAssessment.STATUS_PENDING)
        key = ("符合" if st == ComplianceAssessment.STATUS_COMPLIANT else
               "不符合" if st == ComplianceAssessment.STATUS_NON_COMPLIANT else
               "不适用" if st == ComplianceAssessment.STATUS_NOT_APPLICABLE else
               "待评估")
        src = sources.get(it.anchor)
        if not src:
            continue
        a = by_src.setdefault(src.name, {"total": 0, "符合": 0, "不符合": 0,
                                         "不适用": 0, "待评估": 0})
        a["total"] += 1
        a[key] += 1
        total += 1
        compliant += st == ComplianceAssessment.STATUS_COMPLIANT
        non_compliant += st == ComplianceAssessment.STATUS_NON_COMPLIANT
        na += st == ComplianceAssessment.STATUS_NOT_APPLICABLE
        pending += st == ComplianceAssessment.STATUS_PENDING
    assessed = total - pending
    rate = (compliant / assessed * 100) if assessed else 0
    return jsonify({
        "total": total, "compliant": compliant, "non_compliant": non_compliant,
        "not_applicable": na, "pending": pending,
        "compliance_rate": round(rate, 1),
        "by_source": by_src,
        "disclaimer": "评估结果为机构自述证据的参考性整理，不构成等保测评结论；"
                      "商用密码应用评估请咨询密评机构。",
    })


@bp.route("/status")
@login_required
def status():
    return jsonify({
        "module": "合规判断",
        "state": "v1.0（22 部法源，检查项草案待审定）",
        "sources": [s.name for s in _sources().values()],
        "note": "不碰密评；报告仅引导咨询密评机构",
    })
