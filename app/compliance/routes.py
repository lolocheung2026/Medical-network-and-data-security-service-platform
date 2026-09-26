"""合规判断模块 v1.0 骨架（2026-09-26，ADR-0006）。

锚点三件套：等保 2.0（三级基线）/《医疗卫生机构网络安全管理办法》/ GB/T 39725。
边界：不碰密评（报告仅引导咨询密评机构）。
本骨架：检查项列表（按锚点分组）+ 租户评估提交 + 符合率汇总。
规则内容：SEED_ITEMS 为样例条文（仅结构验证用，标注"样例待审定"），
正式条文库由乐叔按官方文本审定后替换（组织分工：乐叔出领域规则）。
"""
from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from ..auth.routes import current_user, login_required
from ..extensions import db
from ..models import ComplianceAssessment, ComplianceItem

bp = Blueprint("compliance", __name__)

STATUS_LABELS = {
    ComplianceAssessment.STATUS_COMPLIANT: "符合",
    ComplianceAssessment.STATUS_NON_COMPLIANT: "不符合",
    ComplianceAssessment.STATUS_NOT_APPLICABLE: "不适用",
    ComplianceAssessment.STATUS_PENDING: "待评估",
}

# 样例条文（仅结构验证；正式规则由乐叔审定后替换，见 ADR-0006）
SEED_ITEMS = [
    {
        "anchor": "mlps", "article": "8.1.4.1", "title": "边界防护",
        "provision": "应保证跨越边界的访问和数据流通过边界设备提供的受控接口进行通信。",
        "checkpoint": "互联网边界是否部署受控接口（防火墙/安全网关），是否存在绕过边界的直连通道？",
        "evidence_hint": "网络拓扑图、防火墙策略截图",
    },
    {
        "anchor": "mlps", "article": "8.1.3.2", "title": "访问控制",
        "provision": "应删除或停用多余、过期的账户，避免共享账户的存在。",
        "checkpoint": "是否定期清理多余/过期账户，是否存在多人共用账户？",
        "evidence_hint": "账户清单、清理记录",
    },
    {
        "anchor": "measures", "article": "第八条", "title": "等级保护落实",
        "provision": "医疗卫生机构应当落实网络安全等级保护制度，对重要网络和信息系统开展定级备案。",
        "checkpoint": "核心业务系统（HIS 等）是否完成定级备案？",
        "evidence_hint": "定级备案证明（样例，以官方发布文本为准）",
    },
    {
        "anchor": "measures", "article": "第九条", "title": "数据分类分级",
        "provision": "医疗卫生机构应当按照健康医疗数据分类分级相关标准，对数据实行分类分级管理。",
        "checkpoint": "是否建立数据资产清单并完成分类分级？",
        "evidence_hint": "分类分级结果（可与本平台分类分级模块联动）（样例，以官方发布文本为准）",
    },
    {
        "anchor": "gb39725", "article": "6.1", "title": "数据分类分级方法",
        "provision": "依据数据重要程度与安全影响，对健康医疗数据进行分类分级。",
        "checkpoint": "数据分类分级是否覆盖全部数据资产，定级是否可溯源？",
        "evidence_hint": "定级清单与规则溯源（样例，以标准原文为准）",
    },
]


def seed_items():
    """平台内置样例条文（幂等：已存在则跳过）。"""
    if ComplianceItem.query.first():
        return
    for it in SEED_ITEMS:
        db.session.add(ComplianceItem(tenant_id=0, **it))
    db.session.commit()


def _status_of(tenant_id):
    return {a.item_id: a for a in ComplianceAssessment.query.filter_by(
        tenant_id=tenant_id).all()}


@bp.route("/")
@login_required
def index():
    items = ComplianceItem.query.filter_by(active=True).order_by(
        ComplianceItem.anchor, ComplianceItem.article).all()
    by_anchor = {}
    for it in items:
        by_anchor.setdefault(it.anchor, []).append(it)
    assessments = _status_of(session["tenant_id"])
    return render_template(
        "compliance.html", user=current_user(),
        anchors=ComplianceItem.ANCHORS, by_anchor=by_anchor,
        assessments=assessments, status_labels=STATUS_LABELS)


@bp.route("/assess/<int:item_id>", methods=["POST"])
@login_required
def assess(item_id):
    """提交/更新某检查项的评估状态（本租户）。"""
    item = ComplianceItem.query.filter_by(
        id=item_id, active=True).first_or_404()
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
    """符合率汇总（按锚点）。"""
    items = ComplianceItem.query.filter_by(active=True).all()
    assessments = _status_of(session["tenant_id"])
    total, compliant, non_compliant, na, pending = 0, 0, 0, 0, 0
    by_anchor = {}
    for it in items:
        st = (assessments.get(it.id).status
              if it.id in assessments else ComplianceAssessment.STATUS_PENDING)
        key = ("符合" if st == ComplianceAssessment.STATUS_COMPLIANT else
               "不符合" if st == ComplianceAssessment.STATUS_NON_COMPLIANT else
               "不适用" if st == ComplianceAssessment.STATUS_NOT_APPLICABLE else
               "待评估")
        a = by_anchor.setdefault(it.anchor, {"total": 0, "符合": 0, "不符合": 0,
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
        "by_anchor": {ComplianceItem.ANCHORS[k]: v for k, v in by_anchor.items()},
        "disclaimer": "评估结果为机构自述证据的参考性整理，不构成等保测评结论；"
                      "商用密码应用评估请咨询密评机构。",
    })


@bp.route("/status")
@login_required
def status():
    return jsonify({
        "module": "合规判断",
        "state": "v1.0 骨架（规则内容待审定）",
        "anchors": list(ComplianceItem.ANCHORS.values()),
        "note": "不碰密评；报告仅引导咨询密评机构",
    })
