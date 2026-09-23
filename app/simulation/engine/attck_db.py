"""
数据安全库动态读取层（2026-09-02 新增）。

按「沙盘优化建议 v2」落地四项数据反哺的统一入口：
1. MITRE ATT&CK 战术清单（threat_intelligence 表，v19.1 权威源）
2. 医疗行业真实 CVE（cve_vulnerabilities 表，含 vendor/product/device_category，支持适用性校验）
3. 现行法规条款（data_security_regulations 表，条文+URL 可溯源）
4. 威胁态势统计（security_trends 表，用于场景开场）

设计原则（批判性复审结论）：
- 「素材真实」不得伪装成「推演真实」：所有外部参数仅供标注/叙事/引用，
  量化权重（成功率/绕过率）仍由场景显式定义并标注假设。
- DB 不可用（路径迁移/表缺失/锁）必须静默降级返回 None，
  调用方回退到内置静态表，沙盘启动绝不因外部库崩溃。
"""
import os
import threading

DATA_SECURITY_DB = os.environ.get(
    "SANDBOX_DATA_DB",
    "/Users/lolocheung/WorkBuddy/2026-07-09-10-16-46/数据安全集/数据安全.db",
)

_lock = threading.Lock()
_cache = {}


def _query(sql, params=()):
    """DB 读取兜底：任何异常返回 None（调用方降级）。"""
    try:
        import sqlite3
        conn = sqlite3.connect(DATA_SECURITY_DB)
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute(sql, params)]
        conn.close()
        return rows
    except Exception:
        return None


def _cached(key, loader):
    """模块级轻量缓存：资产影响等高频调用不反复查库。"""
    if key in _cache:
        return _cache[key]
    with _lock:
        if key in _cache:
            return _cache[key]
        val = loader()
        if val is not None:
            _cache[key] = val
        return val


# ============ 1. MITRE ATT&CK 战术清单 ============

def load_tactics():
    """TA 编号 -> {name, name_zh, description, source, url}。DB 不可用返回 None。"""
    def _load():
        rows = _query(
            "SELECT tid, name, description, source, source_url FROM threat_intelligence "
            "WHERE framework='MITRE ATT&CK'")
        if not rows:
            return None
        t = {}
        for r in rows:
            name = r.get("name") or ""
            # 名称形如 "初始访问(Initial Access)"
            zh, en = name.split("(", 1) if "(" in name else (name, name)
            en = en.rstrip(")")
            t[r["tid"]] = {
                "name_zh": zh.strip(),
                "name_en": en.strip(),
                "description": r.get("description", ""),
                "source": r.get("source", ""),
                "url": r.get("source_url", ""),
            }
        return t
    return _cached("tactics", _load)


# ============ 2. 医疗行业真实 CVE ============

def load_external_cves():
    """数据安全库 CVE（33 条）：[{id, vendor, product, device_category, cwe, cvss,
    severity, exploit_available, description, source, url}]。DB 不可用返回 None。"""
    def _load():
        rows = _query(
            "SELECT cve_id, vendor, product, device_category, cwe, cvss_score, "
            "severity, exploit_available, description, source, source_url "
            "FROM cve_vulnerabilities")
        if not rows:
            return None
        return [{
            "id": r["cve_id"],
            "vendor": r.get("vendor", ""),
            "product": r.get("product", ""),
            "device_category": r.get("device_category", ""),
            "cwe": r.get("cwe", ""),
            "cvss": r.get("cvss_score", 0.0),
            "severity": r.get("severity", ""),
            "exploit_available": r.get("exploit_available", ""),
            "description": r.get("description", ""),
            "source": r.get("source", ""),
            "url": r.get("source_url", ""),
        } for r in rows]
    return _cached("cves", _load)


# ============ 3. 现行法规条款 ============

def load_regulations():
    """[{reg_id, title, article, key_provision, status, source_url}]。"""
    def _load():
        rows = _query(
            "SELECT reg_id, title, article, key_provision, status, source_url "
            "FROM data_security_regulations WHERE status='现行有效'")
        if not rows:
            return None
        return [{
            "reg_id": r["reg_id"],
            "title": r.get("title", ""),
            "article": r.get("article", ""),
            "key_provision": r.get("key_provision", ""),
            "status": r.get("status", ""),
            "source_url": r.get("source_url", ""),
        } for r in rows]
    return _cached("regulations", _load)


def regulation_detail(compliance_texts):
    """给定内置 compliance 条款文本列表（如「《网络安全法》第 21 条」），
    从法规库匹配条文原文与 URL。返回 [{article, provision, url}]，无匹配返回 []。"""
    regs = load_regulations()
    if not regs:
        return []
    out = []
    for text in compliance_texts:
        compact_text = text.replace("《", "").replace("》", "").replace(" ", "")
        for r in regs:
            title = r["title"]
            article = r["article"]
            law_short = title.replace("中华人民共和国", "")
            # 标题 + 条号同时命中（忽略空格差异）才算匹配，避免张冠李戴
            if law_short.rstrip("法") in compact_text and article.replace(" ", "") in compact_text:
                out.append({
                    "article": f"{title} {article}",
                    "provision": r["key_provision"],
                    "url": r["source_url"],
                })
                break
    return out


# ============ 5. 威胁组织画像（叙事层，非量化） ============

def load_threat_actors():
    """[{actor_id, name, origin, target_industries, motivation, active_since,
    notable_techniques, source, url}]。DB 不可用返回 None。"""
    def _load():
        rows = _query(
            "SELECT actor_id, name, origin, target_industries, motivation, "
            "active_since, notable_techniques, source, source_url "
            "FROM threat_actors")
        if not rows:
            return None
        return [{
            "actor_id": r["actor_id"],
            "name": r.get("name", ""),
            "origin": r.get("origin", ""),
            "target_industries": r.get("target_industries", ""),
            "motivation": r.get("motivation", ""),
            "active_since": r.get("active_since", ""),
            "notable_techniques": r.get("notable_techniques", ""),
            "source": r.get("source", ""),
            "url": r.get("source_url", ""),
        } for r in rows]
    return _cached("actors", _load)


# ============ 4. 威胁态势开场 ============

DEFAULT_BRIEFING = [{
    "metric": "CNCERT 2026 上半年勒索软件攻击同比变化",
    "value": "+40%",
    "time_period": "2026 H1",
    "region": "中国",
    "source_report": "CNCERT 2026年上半年网络安全态势报告",
    "key_insight": "勒索软件攻击激增，医疗行业属重点目标",
    "url": "https://www.cert.org.cn/",
}]


def load_threat_briefing(limit=3):
    """威胁态势开场数据。DB 不可用返回内置兜底（真实来源，静态）。"""
    def _load():
        rows = _query(
            "SELECT metric, value, time_period, region, source_report, key_insight, "
            "source_url FROM security_trends ORDER BY id DESC LIMIT ?", (limit,))
        if not rows:
            return DEFAULT_BRIEFING
        return [{
            "metric": r["metric"],
            "value": r.get("value", ""),
            "time_period": r.get("time_period", ""),
            "region": r.get("region", ""),
            "source_report": r.get("source_report", ""),
            "key_insight": r.get("key_insight", ""),
            "url": r.get("source_url", ""),
        } for r in rows]
    val = _cached("briefing", _load)
    return val or DEFAULT_BRIEFING


def briefing_for_profile(profile_id, limit=3):
    """P0-4 情报开场升级（CALDERA 情报驱动思想）：按攻击者画像组织 TTP
    关键词重排威胁态势条目，匹配画像动机的条目排前（如职业黑客=勒索优先）。"""
    from .adversary import profile_ttp
    ttp = profile_ttp(profile_id)
    keywords = []
    if ttp:
        for k in [ttp.get("motivation", ""), ttp.get("notable_techniques", ""),
                  ttp.get("target_industries", "")]:
            keywords.extend([w for w in k.replace("/", " ").replace("、", " ").split()
                             if len(w) >= 2])
    rows = load_threat_briefing(limit=12)
    if not keywords:
        return rows[:limit]
    def score(r):
        text = " ".join([r.get("metric", ""), r.get("key_insight", ""),
                         r.get("category", "")])
        return sum(1 for kw in keywords if kw.lower() in text.lower())
    ranked = sorted(rows, key=score, reverse=True)
    return ranked[:limit]
