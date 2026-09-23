"""
损失估算参数模块（2026-09-02 新增）：从数据安全库动态读取真实统计参数，
供沙盘场景"后果推演/损失估算"引用。库更新后参数自动刷新，无需改本文件。

数据源：/Users/lolocheung/WorkBuddy/2026-07-09-10-16-46/数据安全集/数据安全.db
  - data_breaches 表：IBM Cost of a Data Breach 2026 / Verizon DBIR 2026
  - cve_vulnerabilities 表：CVE 严重度分布（NVD/CISA KEV 口径）
来源可溯源：每条带 source_report 与 source_url。
"""
import sqlite3

DATA_SECURITY_DB = "/Users/lolocheung/WorkBuddy/2026-07-09-10-16-46/数据安全集/数据安全.db"


def load_breach_params():
    """读取泄露成本与初始入口统计（IBM 2026 / DBIR 2026）。DB 不可用返回 None。"""
    try:
        conn = sqlite3.connect(DATA_SECURITY_DB)
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute(
            "SELECT stat_id, category, metric, value, time_period, industry, source_report, source_url FROM data_breaches")]
        conn.close()
        params = {}
        for r in rows:
            key = r["stat_id"]
            params[key] = r
        return params
    except Exception:
        return None


def cve_severity_distribution():
    """CVE 严重度分布（库内 33 条实测）。"""
    conn = sqlite3.connect(DATA_SECURITY_DB)
    dist = dict(conn.execute(
        "SELECT severity, COUNT(*) FROM cve_vulnerabilities GROUP BY severity"))
    conn.close()
    return dist


def estimate_breach_loss(asset_grade, records_hint=None):
    """场景损失估算：按资产分级取医疗行业泄露成本基准（IBM 口径）。

    asset_grade: '极高' | '高' | '中' | '一般'（沙盘 ASSET_IMPACT 的 sensitivity.level）
    返回 (成本基准万美元, 说明, 来源URL)
    【边界声明】返回值为行业平均成本基准（IBM Cost of a Data Breach），
    非本机构实际损失测算；用于整改价值相对对比，不得作为财务结论。"""
    p = load_breach_params()
    med = p.get("DB-002") if p else None  # 医疗行业平均成本 1093万美元(2025)
    global_ = p.get("DB-001") if p else None  # 全球平均 499万美元(2026)
    med_cost = float(med["value"].replace("万美元", "").replace("$", "").split()[0]) if med else 1093
    global_cost = float(global_["value"].replace("万美元", "").replace("$", "").split()[0]) if global_ else 499
    if asset_grade == "极高":
        base, note = med_cost, "医疗行业平均泄露成本基准（连续14年全行业最高）"
    elif asset_grade == "高":
        base, note = med_cost * 0.7, "高敏感资产按医疗行业基准的70%估算"
    else:
        base, note = global_cost, "全球平均泄露成本基准"
    src = (med or global_)["source_url"] if (med or global_) else ""
    return round(base, 1), note, src
