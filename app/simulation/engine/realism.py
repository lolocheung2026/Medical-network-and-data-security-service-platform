"""
威胁情报知识库（A/C 档支撑）：
- MITRE ATT&CK 技术 → 战术映射（Enterprise matrix，权威编号）
- CWE 弱点分类 + 代表性 CVE 示例（明确标注"代表性示例"，非特定资产实际漏洞）
- CVSS 3.1 exploitability 解析（逐漏洞量化可利用率）

数据来源均为 MITRE ATT&CK / MITRE CWE / NVD 公开权威数据，可溯源。
"""
import re

# ============ A 档：MITRE ATT&CK 战术映射 ============
# 技术编号 -> (战术英文, 战术中文)
MITRE_TACTICS = {
    "T1590": ("Reconnaissance", "侦察"),
    "T1592": ("Reconnaissance", "侦察"),
    "T1595": ("Reconnaissance", "侦察"),
    "T1190": ("Initial Access", "初始访问"),
    "T1566": ("Initial Access", "初始访问"),
    "T1566.001": ("Initial Access", "初始访问"),
    "T1133": ("Initial Access", "初始访问"),
    "T1078": ("Defense Evasion", "防御规避"),
    "T1204": ("Execution", "执行"),
    "T1204.002": ("Execution", "执行"),
    "T1059": ("Execution", "执行"),
    "T1203": ("Execution", "执行"),
    "T1068": ("Privilege Escalation", "权限提升"),
    "T1547": ("Persistence", "持久化"),
    "T1505": ("Persistence", "持久化"),
    "T1136": ("Persistence", "持久化"),
    "T1562": ("Defense Evasion", "防御规避"),
    "T1578": ("Defense Evasion", "防御规避"),
    "T1003": ("Credential Access", "凭据访问"),
    "T1110": ("Credential Access", "凭据访问"),
    "T1552": ("Credential Access", "凭据访问"),
    "T1557": ("Credential Access", "凭据访问"),
    "T1040": ("Discovery", "发现"),
    "T1046": ("Discovery", "发现"),
    "T1526": ("Discovery", "发现"),
    "T1580": ("Discovery", "发现"),
    "T1619": ("Discovery", "发现"),
    "T1021": ("Lateral Movement", "横向移动"),
    "T1210": ("Lateral Movement", "横向移动"),
    "T1570": ("Lateral Movement", "横向移动"),
    "T1005": ("Collection", "收集"),
    "T1039": ("Collection", "收集"),
    "T1213": ("Collection", "收集"),
    "T1530": ("Collection", "收集"),
    "T1041": ("Exfiltration", "数据渗出"),
    "T1048": ("Exfiltration", "数据渗出"),
    "T1567": ("Exfiltration", "数据渗出"),
    "T1485": ("Impact", "影响"),
    "T1486": ("Impact", "影响"),
    "T1498": ("Impact", "影响"),
    "T1499": ("Impact", "影响"),
    "T1565": ("Impact", "影响"),
}

TACTIC_ZH = {
    "Reconnaissance": "侦察",
    "Initial Access": "初始访问",
    "Execution": "执行",
    "Persistence": "持久化",
    "Privilege Escalation": "权限提升",
    "Defense Evasion": "防御规避",
    "Credential Access": "凭据访问",
    "Discovery": "发现",
    "Lateral Movement": "横向移动",
    "Collection": "收集",
    "Command and Control": "命令与控制",
    "Exfiltration": "数据渗出",
    "Impact": "影响",
}

# P0-1 人为因素敏感技术（GHOSTS 思想）：成功率受目标人员安全意识影响
HUMAN_FACTOR_TECHS = {
    "T1566",      # 钓鱼
    "T1204",      # 用户执行
    "T1078",      # 有效账户滥用（弱口令/共享账户）
    "T1552",      # 凭据疏忽（明文口令存放）
}


# ============ A 档：CWE 弱点 + 代表性 CVE ============
# 每条含权威 CWE 分类与业界公认代表性 CVE（标注 representative，非资产实际漏洞）
MITRE_CWE = {
    "T1190": {"cwe": "CWE-94 代码注入 / CWE-502 反序列化",
              "cve": [{"id": "CVE-2021-44228", "name": "Log4Shell（Log4j2 RCE）"},
                      {"id": "CVE-2017-5638", "name": "Struts2 远程代码执行"}],
              "note": "代表性示例，非该资产实际漏洞"},
    "T1210": {"cwe": "CWE-94 代码注入",
              "cve": [{"id": "CVE-2019-0708", "name": "BlueKeep（RDP 远程代码执行）"},
                      {"id": "CVE-2017-0144", "name": "EternalBlue（SMB 远程代码执行）"}],
              "note": "代表性示例，非该资产实际漏洞"},
    "T1566": {"cwe": "CWE-20 输入验证 / CWE-94 代码注入",
              "cve": [{"id": "CVE-2017-11882", "name": "微软公式编辑器远程代码执行"}],
              "note": "代表性示例，非该资产实际漏洞"},
    "T1566.001": {"cwe": "CWE-20 输入验证 / CWE-94 代码注入",
                  "cve": [{"id": "CVE-2017-11882", "name": "微软公式编辑器远程代码执行"}],
                  "note": "代表性示例，非该资产实际漏洞"},
    "T1204.002": {"cwe": "CWE-94 代码注入（恶意宏）",
                  "cve": [{"id": "CVE-2017-11882", "name": "微软公式编辑器远程代码执行"}],
                  "note": "代表性示例，非该资产实际漏洞"},
    "T1110": {"cwe": "CWE-307 暴力破解防护不足 / CWE-521 弱口令",
              "cve": [], "note": "弱口令为配置缺陷，无单一 CVE"},
    "T1003": {"cwe": "CWE-522 凭据保护不足",
              "cve": [], "note": "凭据转储工具依赖，无单一 CVE"},
    "T1068": {"cwe": "CWE-269 权限管理不当",
              "cve": [], "note": "提权依赖具体内核/应用漏洞"},
    "T1552": {"cwe": "CWE-522 凭据保护不足",
              "cve": [], "note": "配置缺陷"},
    "T1557": {"cwe": "CWE-300 通道可被中间人利用",
              "cve": [], "note": "协议设计缺陷"},
    "T1021": {"cwe": "CWE-287 认证绕过",
              "cve": [], "note": "远程服务弱认证"},
    "T1570": {"cwe": "CWE-1104 工具传输通道",
              "cve": [], "note": "依赖既有通道"},
    "T1048": {"cwe": "CWE-200 敏感信息暴露",
              "cve": [], "note": "数据外泄"},
    "T1567": {"cwe": "CWE-200 敏感信息暴露",
              "cve": [], "note": "数据外泄"},
    "T1041": {"cwe": "CWE-200 敏感信息暴露",
              "cve": [], "note": "数据外泄"},
    "T1040": {"cwe": "CWE-311 传输未加密",
              "cve": [], "note": "明文协议"},
    "T1005": {"cwe": "CWE-200 敏感信息暴露",
              "cve": [], "note": "本地数据收集"},
    "T1039": {"cwe": "CWE-200 敏感信息暴露",
              "cve": [], "note": "共享数据收集"},
    "T1213": {"cwe": "CWE-200 敏感信息暴露",
              "cve": [], "note": "数据仓库收集"},
    "T1530": {"cwe": "CWE-200 敏感信息暴露",
              "cve": [], "note": "云存储数据收集"},
    "T1485": {"cwe": "CWE-459 清理不彻底",
              "cve": [], "note": "数据破坏"},
    "T1486": {"cwe": "CWE-521 弱口令 + 数据加密勒索",
              "cve": [], "note": "勒索软件"},
    "T1498": {"cwe": "CWE-400 资源耗尽",
              "cve": [], "note": "网络拒绝服务"},
    "T1499": {"cwe": "CWE-400 资源耗尽",
              "cve": [], "note": "终端拒绝服务"},
    "T1565": {"cwe": "CWE-345 数据完整性校验不足",
              "cve": [], "note": "数据篡改"},
    "T1526": {"cwe": "CWE-200 敏感信息暴露",
              "cve": [], "note": "云服务发现"},
    "T1580": {"cwe": "CWE-200 敏感信息暴露",
              "cve": [], "note": "云基础设施发现"},
    "T1619": {"cwe": "CWE-200 敏感信息暴露",
              "cve": [], "note": "云存储对象发现"},
    "T1590": {"cwe": "CWE-200 敏感信息暴露",
              "cve": [], "note": "网络信息收集"},
    "T1592": {"cwe": "CWE-200 敏感信息暴露",
              "cve": [], "note": "主机信息收集"},
    "T1595": {"cwe": "CWE-200 敏感信息暴露",
              "cve": [], "note": "主动扫描"},
    "T1046": {"cwe": "CWE-200 敏感信息暴露",
              "cve": [], "note": "网络服务发现"},
    "T1078": {"cwe": "CWE-287 认证绕过",
              "cve": [], "note": "有效账户滥用"},
}


# ============ C 档：CVSS 3.1 exploitability ============
# 默认 CVSS 向量（按技术类型给合理值），exploitability 子分数 0~1 归一化
CVSS_DEFAULTS = {
    "T1190": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "T1210": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "T1110": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "T1566": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "T1566.001": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "T1204.002": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "T1068": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "T1003": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
    "T1021": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "T1570": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "T1048": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "T1567": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "T1041": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "T1040": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "T1005": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "T1039": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "T1213": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "T1530": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "T1485": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
    "T1486": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
    "T1498": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "T1499": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "T1565": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
    "T1526": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "T1580": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "T1619": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "T1590": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "T1592": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "T1595": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "T1046": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "T1078": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
}


def _cvss_metric(vector, key, default):
    m = re.search(r"/" + key + r":([A-Z])", vector)
    return m.group(1) if m else default


def cvss_exploitability(vector):
    """CVSS 3.1 exploitability 子分数，归一化到 0~1。
    公式：8.22 * AV * AC * PR * UI，最大 3.89，除以 3.89 归一化。"""
    AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}.get(_cvss_metric(vector, "AV", "N"), 0.85)
    AC = {"L": 0.77, "H": 0.44}.get(_cvss_metric(vector, "AC", "L"), 0.77)
    PR = {"N": 0.85, "L": 0.62, "H": 0.27}.get(_cvss_metric(vector, "PR", "N"), 0.85)
    UI = {"N": 0.85, "R": 0.62}.get(_cvss_metric(vector, "UI", "N"), 0.85)
    exp = 8.22 * AV * AC * PR * UI
    return round(min(exp / 3.89, 1.0), 3)


def _infer_mitre(step):
    """拓扑导入场景无 mitre 编号时，按 desc/technique 关键词推断技术编号。"""
    text = (step.get("desc", "") + " " + step.get("name", "") + " " +
            step.get("technique", ""))
    if "爆破" in text or "弱口令" in text or "口令" in text:
        return "T1110"
    if "勒索" in text or "加密" in text:
        return "T1486"
    if "横向" in text or "渗透" in text or "移动" in text:
        return "T1021"
    if "逻辑隔离" in text or "绕过" in text or "切换" in text:
        return "T1190"
    if "无安全设备" in text or "零防护" in text or "裸奔" in text or "直连" in text or "暴露" in text:
        return "T1190"
    if "导出" in text or "外泄" in text or "泄露" in text or "窃取" in text:
        return "T1567"
    if "扫描" in text or "侦察" in text:
        return "T1595"
    if "权限" in text or "提权" in text:
        return "T1068"
    if "凭据" in text:
        return "T1003"
    return "T1190"


def enrich_attack_step(step):
    """为攻击步补全 MITRE 战术、CWE/CVE、CVSS。原地修改并返回 step。"""
    mitre = step.get("mitre") or ""
    if not mitre:
        mitre = _infer_mitre(step)
        step["mitre"] = mitre
    # 归一化子技术编号（T1566.001 -> T1566）
    base = mitre.split(".")[0]

    tactic_en, tactic_zh = MITRE_TACTICS.get(mitre, MITRE_TACTICS.get(base, ("", "")))
    step["mitre_tactic"] = tactic_en
    step["mitre_tactic_zh"] = tactic_zh

    # 战术权威引用（数据安全库 MITRE ATT&CK v19.1，DB 不可用自动降级为空）
    step["tactic_ref"] = {}
    if tactic_en:
        try:
            from . import attck_db
            tactics = attck_db.load_tactics()
            for tid, t in (tactics or {}).items():
                if t.get("name_en") == tactic_en:
                    step["tactic_ref"] = {
                        "tactic_id": tid,
                        "name_zh": t.get("name_zh", tactic_zh),
                        "source": t.get("source", ""),
                        "url": t.get("url", ""),
                    }
                    break
        except Exception:
            pass

    cwe = MITRE_CWE.get(mitre) or MITRE_CWE.get(base) or \
        {"cwe": "", "cve": [], "note": ""}
    step["cwe"] = cwe["cwe"]
    step["cve"] = cwe["cve"]
    step["cve_note"] = cwe["note"]

    if not step.get("cvss"):
        step["cvss"] = CVSS_DEFAULTS.get(mitre) or CVSS_DEFAULTS.get(base) or \
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    step["exploitability"] = cvss_exploitability(step["cvss"])
    return step


# 防御类别 -> 默认检出率（C 档：绕过率 = exploitability × (1 - detection_rate)）
DETECTION_RATES = {
    "监控审计": 0.8,
    "云上检测": 0.8,
    "云上隔离": 0.6,
    "边界防护": 0.6,
    "网络防护": 0.6,
    "终端防护": 0.7,
    "访问控制": 0.5,
    "数据安全": 0.7,
    "灾备恢复": 0.3,
    "资产管理": 0.3,
    "配置管理": 0.4,
    "系统加固": 0.5,
    "高可用": 0.4,
    "云上配置": 0.5,
    "云地联动": 0.6,
    "应急-检测": 0.8,
    "应急-抑制": 0.7,
    "应急-根除": 0.7,
    "应急-恢复": 0.5,
    "应急-复盘": 0.4,
    "拓扑防护设备": 0.6,
}


def detection_rate(category):
    return DETECTION_RATES.get(category, 0.5)


# ============ P1-2/P1-3/P3：资产影响库（敏感度 + 业务后果 + 合规映射）============
# 医疗资产 → CVSS 环境修正（CR/IR/AR）+ 业务后果 + 患者安全 + 法规条款
ASSET_IMPACT = {
    "人口": {
        "sensitivity": {"level": "极高", "CR": "H", "IR": "H", "AR": "H",
                        "grade": "重要数据（个人信息 + 人口健康数据）"},
        "business": "3000 万人口健康数据泄露，社会影响重大",
        "patient_safety": "低（数据类）",
        "compliance": ["《数据安全法》第 21/27/45 条", "《个人信息保护法》第 28 条",
                       "《网络安全法》第 21 条", "GB/T 22239-2019 等保三级"],
    },
    "精子": {
        "sensitivity": {"level": "极高", "CR": "H", "IR": "H", "AR": "H",
                        "grade": "敏感个人信息（基因 / 生物特征）"},
        "business": "人类精子库数据泄露，伦理与法律后果严重",
        "patient_safety": "中",
        "compliance": ["《个人信息保护法》第 28 条", "《人类遗传资源管理条例》", "等保三级"],
    },
    "HIS": {
        "sensitivity": {"level": "高", "CR": "H", "IR": "H", "AR": "H",
                        "grade": "重要数据（诊疗信息）"},
        "business": "HIS 宕机 → 挂号 / 收费 / 医嘱 / 手术排期中断",
        "patient_safety": "高",
        "compliance": ["《网络安全法》第 21 条", "GB/T 22239-2019 等保三级"],
    },
    "EMR": {
        "sensitivity": {"level": "高", "CR": "H", "IR": "H", "AR": "M",
                        "grade": "重要数据（电子病历）"},
        "business": "病历不可用 → 诊疗记录中断",
        "patient_safety": "中",
        "compliance": ["《电子病历应用管理规范（试行）》", "等保三级"],
    },
    "病历": {
        "sensitivity": {"level": "高", "CR": "H", "IR": "H", "AR": "M", "grade": "重要数据（病历）"},
        "business": "病历不可用 → 诊疗记录中断", "patient_safety": "中",
        "compliance": ["《电子病历应用管理规范（试行）》", "等保三级"],
    },
    "PACS": {
        "sensitivity": {"level": "高", "CR": "M", "IR": "H", "AR": "M", "grade": "影像数据"},
        "business": "影像不可用 → 诊断 / 手术导航中断", "patient_safety": "高",
        "compliance": ["等保三级"],
    },
    "备份": {
        "sensitivity": {"level": "高", "CR": "H", "IR": "M", "AR": "M", "grade": "灾备数据"},
        "business": "备份被加密 → 勒索后无法恢复", "patient_safety": "高",
        "compliance": ["《网络安全法》第 21 条（备份要求）", "等保三级"],
    },
    "数据库": {
        "sensitivity": {"level": "高", "CR": "H", "IR": "H", "AR": "H", "grade": "数据存储"},
        "business": "核心数据库受损 → 业务数据不可用", "patient_safety": "中",
        "compliance": ["《数据安全法》第 27 条", "等保三级"],
    },
}


def asset_impact(node):
    """按节点 label 关键词匹配资产影响（敏感度 + 业务后果 + 合规），无匹配返回通用。
    合规条款含条文原文与来源 URL（数据安全库，不可用时仅保留内置条款文本）。"""
    label = node.get("label", "")
    impact = None
    for kw, _imp in ASSET_IMPACT.items():
        if kw in label:
            impact = dict(_imp)
            break
    if impact is None:
        impact = {
            "sensitivity": {"level": "中", "CR": "M", "IR": "M", "AR": "M", "grade": "一般数据"},
            "business": "一般业务系统受影响",
            "patient_safety": "低",
            "compliance": ["《网络安全法》第 21 条"],
        }
    # 合规条文补充：真实条文 + 来源 URL（数据安全库 data_security_regulations 表）
    impact["compliance_detail"] = []
    try:
        from . import attck_db
        impact["compliance_detail"] = attck_db.regulation_detail(
            impact.get("compliance", []))
    except Exception:
        pass
    return impact


# ============ P1-6 影响传播链（兵棋多域复合影响思想）============
# 资产关键词 -> 下游影响传播链（网络域 → 业务域 → 组织域）
IMPACT_PROPAGATION = {
    "HIS": ["门诊挂号/收费/医嘱业务中断", "患者滞留与投诉", "监管通报（卫健委）", "舆情发酵"],
    "EMR": ["病历调阅中断，诊疗记录受阻", "患者安全风险上升", "监管通报（卫健委）"],
    "病历": ["病历调阅中断，诊疗记录受阻", "患者安全风险上升", "监管通报（卫健委）"],
    "PACS": ["影像诊断中断", "择期手术延误", "患者安全风险上升"],
    "数据库": ["数据批量泄露", "监管通报（网信/公安）", "舆情发酵", "法律责任与赔偿"],
    "备份": ["灾备能力失效，RTO 恶化", "恢复无望，业务长期停摆"],
    "人口": ["3000 万人口健康数据泄露", "社会影响重大", "监管通报（多部门）", "舆情发酵"],
    "精子": ["敏感个人信息泄露", "伦理与法律后果", "监管通报"],
    "OA": ["行政办公中断", "内部运转受阻"],
}


def impact_propagation(node_label):
    """按节点 label 返回影响传播链（列表），无匹配返回通用链。"""
    for kw, chain in IMPACT_PROPAGATION.items():
        if kw in node_label:
            return chain
    return ["一般业务受影响", "内部通报"]


def impact_domain(chain_item):
    """影响链节点 → 影响域分类（网络域/业务域/组织域）。"""
    if any(k in chain_item for k in ["中断", "泄露", "停摆", "失效", "受阻", "延误", "恶化"]):
        return "业务域"
    if any(k in chain_item for k in ["通报", "投诉", "舆情", "责任", "赔偿", "后果"]):
        return "组织域"
    return "网络域"


# ============ 攻击叙事引擎：技术细节 + 节奏（真实性体验）============
# 节点类型 -> 默认端口/服务（医疗场景常见）
NODE_SERVICES = {
    "database": {"port": "3306", "proto": "MySQL"},
    "server": {"port": "22", "proto": "SSH"},
    "workstation": {"port": "445", "proto": "SMB"},
    "firewall": {"port": "443", "proto": "HTTPS 管理口"},
    "isolator": {"port": "443", "proto": "管理接口"},
    "gap": {"port": "443", "proto": "管理接口"},
    "behavior": {"port": "80", "proto": "审计平台"},
    "switch": {"port": "22", "proto": "SSH"},
    "network": {"port": "443", "proto": "HTTPS"},
    "iot": {"port": "1883", "proto": "MQTT"},
    "cloud": {"port": "443", "proto": "云 API"},
    "external": {"port": "80", "proto": "HTTP"},
}

# MITRE 技术 -> 攻击动作叙事模板（分阶段，{label}/{port}/{proto} 占位）
ATTACK_NARRATIVE = {
    "T1190": [
        "对 {label} 发起主动探测，识别开放服务",
        "识别 {proto} 服务运行于 {port} 端口，检索已知漏洞",
        "构造针对性恶意载荷，尝试远程代码执行",
    ],
    "T1110": [
        "对 {label} 的 {port}({proto})发起暴力破解",
        "加载弱口令字典，逐组尝试登录凭证",
        "尝试常见默认口令组合",
    ],
    "T1021": [
        "利用已窃取凭据尝试远程登录 {label}",
        "通过 {proto} 建立横向连接通道",
        "验证目标访问权限，准备下一步行动",
    ],
    "T1567": [
        "在 {label} 上定位并压缩打包敏感数据",
        "通过加密通道分批外传数据",
        "清理访问痕迹，规避审计",
    ],
    "T1048": [
        "在 {label} 上封装敏感数据",
        "通过 {port} 端口建立隐蔽外传隧道",
        "分批渗出数据",
    ],
    "T1486": [
        "向 {label} 投递勒索加密载荷",
        "遍历核心文件进行加密",
        "尝试清除备份与恢复点",
    ],
    "T1003": [
        "在 {label} 内存中提取系统凭据",
        "转储账号哈希与明文口令",
        "整理凭据用于后续横向移动",
    ],
    "T1566": [
        "向 {label} 投递伪装成通知的钓鱼邮件",
        "附带恶意附件，诱导用户打开",
        "等待目标触发恶意代码",
    ],
    "T1566.001": [
        "向 {label} 投递伪装成卫健委通知的钓鱼邮件",
        "附带恶意 Word 附件，诱导启用宏",
        "等待目标打开附件触发载荷",
    ],
    "T1204.002": [
        "目标打开恶意附件并启用宏",
        "恶意代码在 {label} 后台静默执行",
        "植入远控木马，建立回连通道",
    ],
    "T1068": [
        "在 {label} 上探测本地权限配置",
        "利用内核/服务漏洞尝试权限提升",
        "获取更高权限继续深入",
    ],
    "T1526": [
        "扫描云端资产，枚举 {label} 暴露面",
        "比对安全配置，定位无防护入口",
        "确认攻击路径",
    ],
    "T1595": [
        "对 {label} 发起端口与资产扫描",
        "识别开放端口与服务指纹",
        "标记可利用的暴露面",
    ],
    "T1046": [
        "对 {label} 的 {port} 端口发起服务探测",
        "识别 {proto} 服务版本",
        "记录服务指纹用于漏洞匹配",
    ],
}

# 通用兜底叙事
DEFAULT_NARRATIVE = [
    "对 {label} 发起攻击",
    "探测 {port} 端口({proto})",
    "尝试利用暴露面渗透",
]


def attack_narrative(mitre):
    """返回技术对应的叙事模板（含子技术归一化）。"""
    base = (mitre or "").split(".")[0]
    return ATTACK_NARRATIVE.get(mitre) or ATTACK_NARRATIVE.get(base) or DEFAULT_NARRATIVE
