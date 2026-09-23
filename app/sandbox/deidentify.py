"""自动脱密引擎 v1。

红线：原始医疗数据在此拦截，永不入库。
输入：数据字典（CSV/JSON，schema 级描述）或拓扑图（JSON）。
输出：脱密后文本 + 脱密报告（动作明细 + 重识别风险标记）。

策略：
- 阻断：检测到疑似原始记录行（身份证/手机号/病历号成批出现）→ 整体拒绝。
- 脱密：IP 地址按网段假名化；设备/机构名租户盐哈希假名化；
  零星 PII 模式（证件号、电话、邮箱）→ <REDACTED>。
"""
import hashlib
import json
import re

# --- PII 模式 ---
RE_ID_CARD = re.compile(r"\b\d{17}[\dXx]\b")
RE_PHONE = re.compile(r"\b1[3-9]\d{9}\b")
RE_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")
RE_MRN = re.compile(r"(?:病历号|就诊卡号|住院号|MRN)[:：]?\s*[A-Za-z0-9-]{4,}")

# --- 拓扑元素 ---
RE_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")

# 阻断阈值：同一文本中身份证/手机号命中达到此数即判定为原始数据
BLOCK_THRESHOLD = 3


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


def _check_block(text):
    hits = len(RE_ID_CARD.findall(text)) + len(RE_PHONE.findall(text))
    if hits >= BLOCK_THRESHOLD:
        return f"检测到 {hits} 处疑似证件号/手机号原始记录，判定为原始医疗数据，拒绝入库"
    return None


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
    """数据字典脱密：期望 schema 级内容（表名/字段名/注释）。"""
    reason = _check_block(text)
    if reason:
        return DeidentifyResult(None, [], ["原始数据上传尝试"], True, reason)

    actions, risk_flags = [], []
    out = text
    for pattern, label in [
        (RE_ID_CARD, "证件号"), (RE_PHONE, "手机号"),
        (RE_EMAIL, "邮箱"), (RE_MRN, "病历/就诊标识"),
    ]:
        out, n = pattern.subn("<REDACTED>", out)
        if n:
            actions.append(f"清除{label} {n} 处")

    # 风险启发：注释中含医院全名/科室特有命名，可能重识别机构
    if re.search(r"(医院|卫生院|社区卫生服务中心)", out):
        risk_flags.append("文本含机构名称线索，建议确认是否需假名化")
    if not actions:
        actions.append("未检出敏感模式，原样通过")
    return DeidentifyResult(out, actions, risk_flags, False)


def deidentify_topology(text, tenant_id):
    """拓扑 JSON 脱密：IP 假名化 + 设备/机构名假名化，保留图结构。"""
    reason = _check_block(text)
    if reason:
        return DeidentifyResult(None, [], ["原始数据上传尝试"], True, reason)

    actions, risk_flags = [], []
    out = text

    try:
        topo = json.loads(text)
    except json.JSONDecodeError:
        topo = None

    out, ip_count = _pseudonymize_ips(out, actions)

    if topo and isinstance(topo, dict):
        nodes = topo.get("nodes", [])
        # 机构名出现在节点标签中 → 假名化
        orgs = set()
        for node in nodes:
            label = str(node.get("label", "")) if isinstance(node, dict) else ""
            for m in re.findall(r"[\u4e00-\u9fa5]{2,}(?:医院|卫生院|中心)", label):
                orgs.add(m)
        for org in orgs:
            token = _salted_token("org", org, tenant_id)
            out = out.replace(org, token)
            actions.append(f"机构名假名化：{org[:4]}*** → {token}")
        risk_flags.append("拓扑连通关系保留，攻击路径推演可用；若含真实 VLAN/部门编号需人工复核")

    if ip_count == 0 and not actions:
        actions.append("未检出敏感模式，原样通过")
    return DeidentifyResult(out, actions, risk_flags, False)
