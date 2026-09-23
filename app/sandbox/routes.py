import json
import os
import time

from flask import Blueprint, current_app, render_template, request, session

from ..auth.routes import current_user, login_required
from ..extensions import db
from ..models import Upload
from .deidentify import deidentify_data_dict, deidentify_topology

bp = Blueprint("sandbox", __name__)

ALLOWED_EXT = {".csv", ".json", ".txt"}


@bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    result = None
    if request.method == "POST":
        f = request.files.get("file")
        kind = request.form.get("kind", Upload.KIND_DATA_DICT)
        if not f or not f.filename:
            result = {"ok": False, "msg": "未选择文件"}
        elif os.path.splitext(f.filename)[1].lower() not in ALLOWED_EXT:
            result = {"ok": False, "msg": "仅支持 CSV / JSON / TXT"}
        elif kind not in (Upload.KIND_DATA_DICT, Upload.KIND_TOPOLOGY):
            result = {"ok": False, "msg": "未知数据类型"}
        else:
            text = f.read().decode("utf-8", errors="replace")
            tenant_id = session["tenant_id"]
            if kind == Upload.KIND_DATA_DICT:
                r = deidentify_data_dict(text, tenant_id)
            else:
                r = deidentify_topology(text, tenant_id)

            stored_path = None
            if not r.blocked:
                fn = f"t{tenant_id}_{int(time.time())}_{kind}.txt"
                stored_path = os.path.join(current_app.config["UPLOAD_DIR"], fn)
                with open(stored_path, "w", encoding="utf-8") as fp:
                    fp.write(r.text)

            rec = Upload(
                tenant_id=tenant_id,
                kind=kind,
                original_filename=f.filename,
                stored_path=stored_path,
                status=Upload.STATUS_REJECTED if r.blocked else Upload.STATUS_DEIDENTIFIED,
                deidentify_report=json.dumps(r.report_dict(), ensure_ascii=False),
            )
            db.session.add(rec)
            db.session.commit()
            result = {"ok": not r.blocked, "msg": r.block_reason or "脱密完成，已入库",
                      "report": r.report_dict()}
    return render_template("upload.html", result=result, user=current_user())
