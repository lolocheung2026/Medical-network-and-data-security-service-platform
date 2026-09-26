"""自动脱密引擎 v2（v0.3 加固，schema 白名单制）。

红线：原始医疗数据在此拦截，永不入库。
输入：数据字典（CSV/JSON，schema 级描述）或拓扑图（JSON）。
输出：脱密后文本 + 脱密报告（动作明细 + 重识别风险标记）。

v2 变更（ADR-0003）：
- 白名单制：数据字典只允许 schema 级描述文本，任何 PII 值（含变形写法）
  出现即整体拒绝，不再"清除后放行"（v1 阈值=3 已废弃）。
- 变形写法覆盖：身份证加空格/连字符、手机号带分隔符、繁体机构名。
- 拓扑路径：IP 假名化保留（拓扑合法元素）；PII 值出现即拒。
"""
import hashlib
import json
import re

# --- PII 模式（含变形写法） ---
RE_ID_CARD = re.compile(r"\b\d{17}[\dXx]\b")
RE_ID_CARD_SPACED = re.compile(
    r"\b\d{6}(?:[\s-]+\d{8}[\s-]*\d{3}[\dXx]|\d{8}[\s-]+\d{3}[\dXx])\b"
)
RE_PHONE = re.compile(r"\b1[3-9]\d{9}\b")
RE_PHONE_SEP = re.compile(
    r"\b1[3-9]\d(?:[\s-]\d{4}[\s-]?\d{4}|\d{4}[\s-]\d{4})\b"
)
RE_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")
RE_MRN = re.compile(r"(?:病历号|就诊卡号|住院号|MRN)[:：]?\s*[A-Za-z0-9-]{4,}")

# 机构名线索（简/繁体均覆盖）
RE_ORG_HINT = re.compile(
    r"(医院|醫院|卫生院|衛生院|社区卫生服务中心|社區衛生服務中心)"
)

# --- 拓扑元素 ---
RE_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")

# PII 检测组（字典与拓扑共用）：[(正则, 名称)]
_PII_PATTERNS = [
    (RE_ID_CARD, "证件号"),
    (RE_ID_CARD_SPACED, "证件号(变形)"),
    (RE_PHONE, "手机号"),
    (RE_PHONE_SEP, "手机号(变形)"),
    (RE_EMAIL, "邮箱"),
    (RE_MRN, "病历/就诊标识"),
]


class DeidentifyResult:
    def __init__(self, text, actions, risk_flags, blocked, block_reason=None):
        self.text = text
        self.actions = actions          # list[str] 脱密动作明细
        self.risk_flags = risk_flags    # list[str] 重识别风险标记
        self.blocked = blocked          # True = 拒绝入库
        self.block_reason = block_reason

    def report_dict(self):
        return {
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "actions": self.actions,
            "risk_flags": self.risk_flags,
        }


def _salted_token(kind, value, tenant_id):
    h = hashlib.sha256(f"{kind}:{value}:tenant-{tenant_id}".encode()).hexdigest()
    return f"{kind[:3].upper()}-{h[:8]}"


def _find_pii(text):
    """返回 [(名称, 命中数)]；任何 PII 值出现即构成阻断依据。"""
    found = []
    for pattern, label in _PII_PATTERNS:
        n = len(pattern.findall(text))
        if n:
            found.append((label, n))
    return found


def _block_reason(found):
    total = sum(n for _, n in found)
    detail = "、".join(f"{label} {n} 处" for label, n in found)
    return (f"检出 {total} 处疑似原始个人数据（{detail}）。"
            "白名单制：数据字典仅允许 schema 级描述，任何 PII 值出现即拒绝入库")


def _pseudonymize_ips(text, actions):
    mapping = {}

    def repl(m):
        ip = m.group(0)
        if ip not in mapping:
            seg = f"{m.group(1)}.{m.group(2)}"
            base = sum(int(m.group(i)) << (8 * (4 - i)) for i in range(1, 5))
            mapping[ip] = f"10.{(base >> 8) % 250 + 1}.{(base % 250) + 1}.{(base >> 16) % 250 + 1}"
            actions.append(f"IP 假名化：{seg}.x.x → 网段重编（保留连通关系）")
        return mapping[ip]

    return RE_IPV4.sub(repl, text), len(mapping)


def deidentify_data_dict(text, tenant_id):
    """数据字典脱密（白名单制）：检出任何 PII 值 → 整体拒绝。"""
    found = _find_pii(text)
    if found:
        return DeidentifyResult(None, [], ["原始数据上传尝试"], True,
                                _block_reason(found))

    actions, risk_flags = [], []
    out = text
    if RE_ORG_HINT.search(out):
        risk_flags.append("文本含机构名称线索，建议确认是否需假名化")
    actions.append("未检出敏感模式，原样通过")
    return DeidentifyResult(out, actions, risk_flags, False)


def deidentify_topology(text, tenant_id):
    """拓扑 JSON 脱密：PII 值即拒；IP 假名化 + 设备/机构名假名化。"""
    found = _find_pii(text)
    if found:
        return DeidentifyResult(None, [], ["原始数据上传尝试"], True,
                                _block_reason(found))

    actions, risk_flags = [], []
    out = text

    try:
        topo = json.loads(text)
    except json.JSONDecodeError:
        topo = None

    out, ip_count = _pseudonymize_ips(out, actions)

    if topo and isinstance(topo, dict):
        nodes = topo.get("nodes", [])
        orgs = set()
        for node in nodes:
            label = str(node.get("label", "")) if isinstance(node, dict) else ""
            for m in re.findall(r"[\u4e00-\u9fa5]{2,}(?:医院|醫院|卫生院|衛生院|中心)", label):
                orgs.add(m)
        for org in orgs:
            token = _salted_token("org", org, tenant_id)
            out = out.replace(org, token)
            actions.append(f"机构名假名化：{org[:4]}*** → {token}")
        risk_flags.append("拓扑连通关系保留，攻击路径推演可用；若含真实 VLAN/部门编号需人工复核")

    if ip_count == 0 and not actions:
        actions.append("未检出敏感模式，原样通过")
    return DeidentifyResult(out, actions, risk_flags, False)
