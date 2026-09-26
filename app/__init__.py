import os

from flask import Flask, redirect, session, url_for

from .extensions import db


def create_app(config_object="config.Config"):
    app = Flask(__name__)
    app.config.from_object(config_object)
    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)

    db.init_app(app)

    from .auth.routes import bp as auth_bp
    from .sandbox.routes import bp as sandbox_bp
    from .classify.routes import bp as classify_bp
    from .simulation.routes import bp as simulation_bp
    from .simulation.sandbox_ui import bp as sandbox_ui_bp
    from .compliance.routes import bp as compliance_bp
    from .reports.routes import bp as reports_bp
    from .export.routes import bp as export_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(sandbox_bp, url_prefix="/sandbox")
    app.register_blueprint(classify_bp, url_prefix="/classify")
    app.register_blueprint(simulation_bp, url_prefix="/simulation")
    app.register_blueprint(sandbox_ui_bp)  # 沙盘原生工作台：根级路径（/scenario、/api/...）
    app.register_blueprint(compliance_bp, url_prefix="/compliance")
    app.register_blueprint(reports_bp, url_prefix="/reports")
    app.register_blueprint(export_bp, url_prefix="/export")

    @app.route("/")
    def index():
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
        return redirect(url_for("dashboard"))

    @app.route("/dashboard")
    def dashboard():
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
        from flask import render_template

        return render_template("dashboard.html")

    with app.app_context():
        db.create_all()
        _seed_dev_account()
        from .compliance.routes import seed_items
        seed_items()

    return app


def _seed_dev_account():
    """开发期种子账号：admin / admin123（上线前必须删除）。"""
    from .models import Tenant, User

    if User.query.filter_by(username="admin").first():
        return
    t = Tenant(name="开发测试医院", org_type="hospital")
    db.session.add(t)
    db.session.flush()
    u = User(tenant_id=t.id, username="admin")
    u.set_password("admin123")
    db.session.add(u)
    db.session.commit()
