from datetime import datetime
from functools import wraps

from flask import (Blueprint, redirect, render_template, request, session,
                   url_for)

from ..extensions import db
from ..models import User

bp = Blueprint("auth", __name__)


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)

    return wrapper


def current_user():
    uid = session.get("user_id")
    return User.query.get(uid) if uid else None


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = User.query.filter_by(username=request.form.get("username", "")).first()
        if u and u.check_password(request.form.get("password", "")):
            if not request.form.get("disclaimer"):
                error = "请阅读并勾选免责声明"
            else:
                if not u.disclaimer_signed_at:
                    u.disclaimer_signed_at = datetime.utcnow()
                    db.session.commit()
                session["user_id"] = u.id
                session["tenant_id"] = u.tenant_id
                return redirect(url_for("dashboard"))
        else:
            error = "用户名或密码错误"
    return render_template("login.html", error=error)


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
