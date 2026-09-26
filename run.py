"""开发服务器入口。

debug 默认关闭：Flask reloader 会起父子双进程，双进程同时打开 SQLite 会
产生 journal 锁竞争（disk I/O error）。需要热重载时显式 FLASK_DEBUG=1。
"""
import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", "5577")),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
