"""Scenario: 被借用的通道 — 第三方运维入口被利用（优化建议二梯 P1-7 修正版）。

证据来源：
- KB-03-0206 攻防演练场景库：渗透测试流程（红队视角）——信息收集→漏洞扫描→
  漏洞利用→权限提升→横向移动→痕迹清理；纵深防御（蓝队视角）。
- KB-03-0207 医院云网攻防场景库（L3 合成）：本地攻防体系映射。
- KB-03-0196 安全评估报告：HIS/EMR 由厂商运维（华为 2288H 等设备），
  远程运维通道是医院真实攻击面（A4 台账登记矛盾亦暴露运维资产管理混乱）。
- 修正说明（批判性复审）：不做"开源组件投毒"（医院自研软件少，素材错配），
  聚焦医院真实面——HIS 厂商远程运维通道（VPN+堡垒机）被利用。
"""
from ..engine.scenario_base import ScenarioBase


class ThirdPartyMaintScenario(ScenarioBase):
    SCENARIO_ID = "third_party_maint"
    SCENARIO_NAME = "被借用的通道：厂商远程运维入口被利用"
    SCENARIO_DESC = ("HIS 厂商远程运维通道（VPN+堡垒机）是医院真实攻击面"
                     "（KB-03-0196 台账厂商运维记录），"
                     "推演攻击者窃取运维凭据沿信任通道直达核心系统，"
                     "验证运维通道管控（双因子/录屏审计/最小权限）的拦截效果")
    SCENARIO_CATEGORY = "攻防对抗层"
    SCENARIO_DIFFICULTY = "高级"
    SCENARIO_TAGS = ["第三方运维", "供应链通道", "堡垒机", "信任滥用", "KB-03-0206"]
    DEMOTED_DEFENSES = ["d1", "d2", "d3"]

    def __init__(self):
        super().__init__()
        self._build_topology()
        self._build_attacks()
        self._build_defenses()
        self._build_remediations()
        self._apply_demotions()

    def _build_topology(self):
        self._add_node("internet", "攻击者", "external", 960, 210,
                       "外部攻击源（互联网）")
        self._add_node("vpn", "运维 VPN 网关", "firewall", 1140, 210,
                       "厂商远程运维入口（HIS/EMR 厂商）")
        self._add_node("bastion", "运维堡垒机", "server", 1320, 210,
                       "运维审计通道（若录屏审计缺失则为信任黑洞）", awareness="低")
        self._add_node("ops_net", "运维管理网", "network", 1500, 210,
                       "运维通道专用网段")
        self._add_node("his", "HIS 服务器", "server", 1200, 60,
                       "华为 2288H（厂商运维对象）")
        self._add_node("emr", "EMR 服务器", "server", 1200, 360,
                       "电子病历（厂商运维对象）")
        self._add_node("db", "HIS 数据库", "database", 1680, 210,
                       "患者诊疗数据")
        self._add_node("backup", "备份系统", "database", 1320, 510,
                       "灾备数据")

        self._add_edge("internet", "vpn", "运维 VPN")
        self._add_edge("vpn", "bastion", "")
        self._add_edge("bastion", "ops_net", "")
        self._add_edge("ops_net", "his", "运维通道")
        self._add_edge("ops_net", "emr", "运维通道")
        self._add_edge("his", "db", "")
        self._add_edge("emr", "backup", "")

    def _build_attacks(self):
        self._add_attack_step(
            "s1", "运维入口侦察",
            "探测厂商运维 VPN 入口，识别 VPN 品牌版本与登录页，"
            "收集厂商驻场人员信息（社交工程素材）",
            preconditions=[],
            effects=[{"target": "vpn", "state": "target"}],
            detection="低", technique="Active Scanning", mitre="T1595",
        )
        self._add_attack_step(
            "s2", "运维凭据爆破/窃取",
            "对运维 VPN 账号爆破（厂商默认口令/弱口令），"
            "或钓鱼驻场运维人员窃取账号",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "vpn", "state": "compromised"}],
            detection="中", technique="Brute Force", mitre="T1110",
        )
        self._add_attack_step(
            "s3", "经 VPN 进入运维网络",
            "使用窃取的运维凭据建立 VPN 隧道进入运维管理网",
            preconditions=[{"type": "node_compromised", "node": "vpn"}],
            effects=[{"target": "ops_net", "state": "compromised"}],
            detection="低", technique="External Remote Services", mitre="T1133",
        )
        self._add_attack_step(
            "s4", "堡垒机信任滥用",
            "运维通道对堡垒机'已认证身份'天然信任，"
            "无录屏审计/无行为基线时攻击者自由操作不被察觉",
            preconditions=[{"type": "node_compromised", "node": "ops_net"}],
            effects=[{"target": "bastion", "state": "compromised"}],
            detection="中", technique="Valid Accounts", mitre="T1078",
        )
        self._add_attack_step(
            "s5", "借运维权限直达 HIS/EMR",
            "以'厂商运维'身份直达 HIS/EMR 服务器，"
            "运维权限即系统权限，无需漏洞利用",
            preconditions=[{"type": "node_compromised", "node": "bastion"}],
            effects=[{"target": "his", "state": "compromised"},
                     {"target": "emr", "state": "compromised"}],
            detection="低", technique="Remote Services", mitre="T1021",
        )
        self._add_attack_step(
            "s6", "拖库与数据篡改",
            "导出 HIS 数据库患者数据，篡改电子病历（可植入虚假诊疗记录）",
            preconditions=[{"type": "node_compromised", "node": "his"}],
            effects=[{"target": "db", "state": "compromised"},
                     {"target": "emr", "state": "compromised"}],
            detection="中", technique="Data Manipulation", mitre="T1565",
        )
        self._add_attack_step(
            "s7", "数据外泄并清理痕迹",
            "批量外传患者数据，清理堡垒机日志痕迹（无录屏则无痕可查）",
            preconditions=[{"type": "node_compromised", "node": "db"}],
            effects=[{"target": "db", "state": "exfiltrated"}],
            detection="高", technique="Exfiltration Over C2 Channel", mitre="T1041",
        )

    def _build_defenses(self):
        self._add_defense(
            "d1", "运维账号双因子+最小权限",
            "运维 VPN 强制双因子认证，账号按任务最小权限、"
            "到期回收（厂商账号定期清理）",
            blocks=["s2"], cost="低", category="访问控制",
        )
        self._add_defense(
            "d2", "堡垒机全程录屏+行为审计",
            "运维会话全程录屏 + 操作审计 + 异常行为告警，"
            "信任滥用可发现可追溯",
            blocks=["s4"], cost="中", category="监控审计",
        )
        self._add_defense(
            "d3", "运维通道专用 VLAN 隔离",
            "运维管理网与业务网隔离，运维通道仅可达授权目标，"
            "阻断借道横向",
            blocks=["s3", "s5"], cost="中", category="网络防护",
        )
        self._add_defense(
            "d4", "数据库审计+敏感操作阻断",
            "数据库审计开启，批量导出/敏感字段访问触发告警并阻断",
            blocks=["s6"], cost="中", category="数据安全",
        )
        self._add_defense(
            "d5", "外联通道管控",
            "服务器区外联白名单，阻断数据外传",
            blocks=["s7"], cost="中", category="数据安全",
        )

    def _build_remediations(self):
        """增量整改候选措施（2026-09-06）：针对现状防护全开仍存在的薄弱环节设计，
        仅整改推演轮2生效，不进入现状防护。"""
        self._add_remediation(
            "r1", "诱饵凭据+运维蜜罐",
            "部署运维诱饵账号与蜜罐，运维入口侦察与凭据爆破即被诱捕",
            covers=['s1'], cost="低", category="监控审计",
            root_cause="运维入口侦察无感知，攻击者可摸清运维通道", trap=True,
        )
        self._add_remediation(
            "r2", "数据库敏感操作实时阻断",
            "数据库审计升级实时阻断，拖库与数据篡改即断连",
            covers=['s6'], cost="中", category="数据安全",
            root_cause="拖库防护依赖审计单道，缺实时阻断", trap=False,
        )
        self._add_remediation(
            "r3", "运维行为基线分析",
            "建立运维行为基线，堡垒机信任滥用异常行为实时告警",
            covers=['s4'], cost="中", category="监控审计",
            root_cause="堡垒机信任滥用依赖录屏审计，缺行为基线检测", trap=False,
        )
