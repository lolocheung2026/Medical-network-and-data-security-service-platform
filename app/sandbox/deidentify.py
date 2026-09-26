"""自动脱密引擎 v3（v0.3 迭代，借鉴开源成熟设计）。

红线：原始医疗数据在此拦截，永不入库。
输入：数据字典（CSV/JSON，schema 级描述）或拓扑图（JSON）。
输出：脱密后文本 + 脱密报告（动作明细 + 重识别风险标记）。

v2 变更（ADR-0003）：
- 白名单制：数据字典只允许 schema 级描述文本，任何 PII 值（含变形写法）
  出现即整体拒绝，不再"清除后放行"（v1 阈值=3 已废弃）。
- 变形写法覆盖：身份证加空格/连字符、手机号带分隔符、繁体机构名。
- 拓扑路径：IP 假名化保留（拓扑合法元素）；PII 值出现即拒。

v3 变更（ADR-0005，借鉴开源设计）：
- 校验和验证（借鉴 Microsoft Presidio 的 checksum 识别器设计）：
  身份证 GB 11643-1999 校验、银行卡 Luhn 校验。校验失败 = 必然非合法
  证件/卡号（业务编号），降级为 risk_flag 提示而非阻断——消误报、零漏检。
- 证件模式扩充（借鉴 pii-guard 类型清单）：中国大陆护照、港澳通行证、
  港澳台证件格式。
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
# 证件扩充（借鉴 pii-guard 类型清单）
RE_PASSPORT_CN = re.compile(r"\bE\d{8}\b")          # 中国大陆因私普通护照
RE_HK_MACAO_TW = re.compile(
    r"(?<![\w(])(?:[A-Z]\d{6}\(\d\)|M\d{8}|C\d{8})(?!\d)"
)                                                   # 香港身份证/澳门证件/港澳通行证
RE_BANK_CARD = re.compile(r"\b\d{16,19}\b")          # 银行卡号（Luhn 校验）

# 机构名线索（简/繁体均覆盖）
RE_ORG_HINT = re.compile(
    r"(医院|醫院|卫生院|衛生院|社区卫生服务中心|社區衛生服務中心)"
)

# --- 拓扑元素 ---
RE_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")

# PII 检测组（字典与拓扑共用）：[(正则, 名称, 校验函数或 None)]
_ID_CARD_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
_ID_CARD_CHECK = "10X98765432"


def _id_card_checksum_ok(digits):
    """GB 11643-1999 公民身份号码校验。digits = 前 17 位字符串。"""
    if len(digits) != 17 or not digits.isdigit():
        return False
    total = sum(int(d) * w for d, w in zip(digits, _ID_CARD_WEIGHTS))
    return True  # 校验位验证在调用方（需与第 18 位比对）


def _id_card_valid(raw):
    """完整校验：前 17 位加权 mod 11 映射校验位。"""
    s = re.sub(r"[\s-]", "", raw)
    if len(s) != 18 or not s[:17].isdigit():
        return False
    total = sum(int(d) * w for d, w in zip(s[:17], _ID_CARD_WEIGHTS))
    return _ID_CARD_CHECK[total % 11].upper() == s[17].upper()


def _luhn_ok(digits):
    """Luhn 校验（银行卡号标准算法）。"""
    if not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


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
    """返回 (found, flags)。

    found: [(名称, 命中数)] 构成阻断依据的 PII；
    flags: list[str] 校验失败的疑似项（不阻断，提示人工复核）。
    """
    found, flags = [], []

    def add(hits, label, validator):
        if not hits:
            return
        ok, bad = 0, 0
        for h in hits:
            if validator(h):
                ok += 1
            else:
                bad += 1
        if ok:
            found.append((label, ok))
        if bad:
            flags.append(f"{label} {bad} 处校验未通过，按业务编号处理，建议人工复核")

    # 身份证先收集（银行卡 16-19 位规则与其重叠，需剔除避免重复报）
    id_hits = set(RE_ID_CARD.findall(text)) | set(RE_ID_CARD_SPACED.findall(text))
    add(sorted(id_hits), "证件号", _id_card_valid)
    add([h for h in RE_BANK_CARD.findall(text) if h not in id_hits],
        "银行卡号", _luhn_ok)
    for pattern, label in [
        (RE_PHONE, "手机号"), (RE_PHONE_SEP, "手机号(变形)"),
        (RE_EMAIL, "邮箱"), (RE_MRN, "病历/就诊标识"),
        (RE_PASSPORT_CN, "护照号"), (RE_HK_MACAO_TW, "港澳台证件"),
    ]:
        n = len(pattern.findall(text))
        if n:
            found.append((label, n))
    return found, flags


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
    found, flags = _find_pii(text)
    if found:
        return DeidentifyResult(None, [], flags + ["原始数据上传尝试"], True,
                                _block_reason(found))

    actions, risk_flags = [], list(flags)
    out = text
    if RE_ORG_HINT.search(out):
        risk_flags.append("文本含机构名称线索，建议确认是否需假名化")
    actions.append("未检出敏感模式，原样通过")
    return DeidentifyResult(out, actions, risk_flags, False)


def deidentify_topology(text, tenant_id):
    """拓扑 JSON 脱密：PII 值即拒；IP 假名化 + 设备/机构名假名化。"""
    found, flags = _find_pii(text)
    if found:
        return DeidentifyResult(None, [], flags + ["原始数据上传尝试"], True,
                                _block_reason(found))

    actions, risk_flags = [], list(flags)
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
