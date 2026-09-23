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
