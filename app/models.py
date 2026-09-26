from datetime import datetime

from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db


class Tenant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    org_type = db.Column(db.String(32), nullable=False, default="hospital")  # hospital | health_commission
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    users = db.relationship("User", backref="tenant", lazy=True)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    disclaimer_signed_at = db.Column(db.DateTime, nullable=True)

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)


class Upload(db.Model):
    """沙盒上传记录：数据字典 / 拓扑图，脱密后才入库。"""

    KIND_DATA_DICT = "data_dict"
    KIND_TOPOLOGY = "topology"

    STATUS_REJECTED = "rejected"
    STATUS_DEIDENTIFIED = "deidentified"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False)
    kind = db.Column(db.String(16), nullable=False)
    original_filename = db.Column(db.String(256), nullable=False)
    stored_path = db.Column(db.String(512), nullable=True)  # 脱密后文件路径；被拒绝时为 None
    status = db.Column(db.String(16), nullable=False, default=STATUS_DEIDENTIFIED)
    deidentify_report = db.Column(db.Text, nullable=True)  # JSON：脱密动作+风险标记
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class SimulationRun(db.Model):
    """攻防推演记录：租户 × 场景 × 一次推演结果（v0.2）。"""

    STATUS_OK = "ok"
    STATUS_ERROR = "error"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False)
    scenario_id = db.Column(db.String(64), nullable=False)
    scenario_name = db.Column(db.String(128), nullable=False)
    status = db.Column(db.String(16), nullable=False, default=STATUS_OK)
    result_json = db.Column(db.Text, nullable=True)  # 推演报告 JSON（generate_report 输出）
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class RegulationSource(db.Model):
    """合规判断法源库（v1.0 扩展，2026-09-26 乐叔定 22 部）。

    平台级共享：tenant_id=0。效力层级：法律 / 行政法规 / 部门规章 /
    规范性文件 / 地方性法规。
    """

    CATEGORIES = ["法律", "行政法规", "部门规章", "规范性文件", "地方性法规"]

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, default=0, nullable=False)
    code = db.Column(db.String(32), unique=True, nullable=False)    # 内部代码
    name = db.Column(db.String(128), nullable=False)                # 全称
    short_name = db.Column(db.String(64), nullable=True)            # 常用简称
    category = db.Column(db.String(16), nullable=False)             # 效力层级
    active = db.Column(db.Boolean, default=True)


class ComplianceItem(db.Model):
    """合规检查项规则库（v1.0 骨架，2026-09-26 扩展为 22 部法源）。

    平台级共享条文：tenant_id=0；anchor 存法源代码（RegulationSource.code）。
    检查项内容由乐叔按官方文本审定（见 ADR-0006/0007）。
    """

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, default=0, nullable=False)  # 0=平台内置共享
    anchor = db.Column(db.String(32), nullable=False)             # 法源代码
    article = db.Column(db.String(32), nullable=False)            # 条款号，如 8.1.4.1
    title = db.Column(db.String(128), nullable=False)             # 条款标题/控制项名
    provision = db.Column(db.Text, nullable=False)                # 条款原文/要点
    checkpoint = db.Column(db.String(256), nullable=False)        # 可判定检查点
    evidence_hint = db.Column(db.String(256), nullable=True)      # 证据要求提示
    active = db.Column(db.Boolean, default=True)


class ComplianceAssessment(db.Model):
    """租户合规评估记录（v1.0 骨架）：租户 × 检查项 × 判定状态。"""

    STATUS_COMPLIANT = "compliant"
    STATUS_NON_COMPLIANT = "non_compliant"
    STATUS_NOT_APPLICABLE = "not_applicable"
    STATUS_PENDING = "pending"

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey("compliance_item.id"), nullable=False)
    status = db.Column(db.String(16), nullable=False, default=STATUS_PENDING)
    evidence = db.Column(db.Text, nullable=True)                  # 证据描述（客户自述）
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow)


class ClassificationCorrection(db.Model):
    """分类分级人工校正记录（v0.3 迭代，2026-09-26）。

    租户对字段定级的人工修正；分类引擎查询校正表优先于规则库命中，
    实现"人工校正→规则回流"闭环。校正以 (table_name, field_name) 为键。
    """

    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False)
    table_name = db.Column(db.String(128), nullable=False)
    field_name = db.Column(db.String(128), nullable=False)
    comment = db.Column(db.String(256), nullable=True)
    original_level = db.Column(db.Integer, nullable=False)        # 规则引擎原定级
    corrected_level = db.Column(db.Integer, nullable=False)       # 人工修正级别
    reason = db.Column(db.String(256), nullable=True)             # 修正理由
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
