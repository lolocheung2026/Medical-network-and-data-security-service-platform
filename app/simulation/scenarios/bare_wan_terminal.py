"""Scenario: 裸奔的专网终端 — 政务外网/医保专网无安全设备（评估报告 P0-3）。

证据来源：研究院IT基础设施安全评估报告（KB-03-0196）P0-3：
1. 渝北电子政务外网无安全设备，终端直连数字重庆/IRS；
2. 医保专网无安全设备，直连终端；
3. 江北：16台服务器与医保专网终端经5楼通讯机房互联，内部防火墙是唯一边界
（逻辑拓扑图 v2/v3 实证，KB-03-0194）。
推演：专网终端零防护 → 被入侵 → 沿"可信通道"逆向攻击外部平台 → 经互联点跳入内网。
"""
from ..engine.scenario_base import ScenarioBase


class BareWanTerminalScenario(ScenarioBase):
    SCENARIO_ID = "bare_wan_terminal"
    SCENARIO_NAME = "裸奔的专网终端：政务外网与医保专网零防护"
    SCENARIO_DESC = ("两条专网终端无任何安全设备（P0-3实测），推演零防护终端被入侵后"
                     "沿可信通道逆向攻击数字重庆/IRS与医保平台、并经互联点跳入内网的完整链")
    SCENARIO_CATEGORY = "攻防对抗层"
    SCENARIO_DIFFICULTY = "高级"
    SCENARIO_TAGS = ["专网裸奔", "零防护终端", "可信通道逆向", "P0发现", "两院区"]
    DEMOTED_DEFENSES = ["d1", "d3", "d4"]

    def __init__(self):
        super().__init__()
        self._build_topology()
        self._build_attacks()
        self._build_defenses()
        self._build_remediations()
        self._apply_demotions()

    def _build_topology(self):
        # 渝北：政务外网无安全设备直连终端，终端可信连接数字重庆/IRS
        # 医保专网无安全设备直连终端，终端可信连接医保结算平台
        # 江北：医保终端与16台服务器经5楼通讯机房互联，内部防火墙是唯一边界
        self._add_node("internet", "攻击者", "external", 800, 60,
                       "外部攻击源（钓鱼邮件/互联网侧）")
        self._add_node("e_gov", "电子政务外网", "network", 800, 260,
                       "专网线路【无安全设备，P0-3】")
        self._add_node("gov_terminal", "政务外网终端", "workstation", 1400, 260,
                       "直连数字重庆/IRS，无准入无杀毒", awareness="低")
        self._add_node("digital_cq", "数字重庆/IRS平台", "external", 2000, 60,
                       "外部政务平台（可信通道终点）")
        self._add_node("ins_net", "医保专网", "network", 800, 460,
                       "专网线路【无安全设备，P0-3】")
        self._add_node("ins_terminal", "医保专网终端", "workstation", 1400, 460,
                       "医保结算终端，直连医保平台")
        self._add_node("ins_platform", "医保结算平台", "external", 800, 660,
                       "外部医保平台（可信通道终点）")
        self._add_node("server_group", "江北服务器群×16", "server", 2000, 660,
                       "经5楼通讯机房与医保终端互联（内部防火墙是唯一边界）")
        self._add_node("af", "内部防火墙", "firewall", 1700, 460,
                       "江北服务器区唯一边界")
        self._add_node("core", "核心交换机", "network", 1100, 460,
                       "内网核心")
        self._add_node("pc", "内网终端", "workstation", 2000, 260,
                       "临床/办公终端")
        self._add_node("his", "HIS服务器", "server", 2000, 460,
                       "核心HIS系统")

        # 攻击入口
        self._add_edge("internet", "e_gov", "")
        self._add_edge("internet", "ins_net", "")
        # 渝北政务外网链路（零防护）
        self._add_edge("e_gov", "gov_terminal", "无安全设备直连")
        self._add_edge("gov_terminal", "digital_cq", "可信通道")
        # 医保专网链路（零防护）
        self._add_edge("ins_net", "ins_terminal", "无安全设备直连")
        self._add_edge("ins_terminal", "ins_platform", "可信通道")
        # 江北互联点 → 内网
        self._add_edge("ins_terminal", "server_group", "5楼通讯机房互联")
        self._add_edge("server_group", "af", "内部防火墙(唯一边界)")
        self._add_edge("af", "core", "")
        self._add_edge("core", "pc", "")
        self._add_edge("core", "his", "")
        # 两专网终端间可达（政务→医保）
        self._add_edge("gov_terminal", "ins_terminal", "专网间互联窗口")

    def _build_attacks(self):
        self._add_attack_step(
            "s1", "专网链路侦察",
            "攻击者探测两条专网链路，确认终端零防护且直连外部平台"
            "（数字重庆/IRS、医保结算），专网无防火墙/IPS/准入",
            preconditions=[],
            effects=[{"target": "gov_terminal", "state": "target"}],
            detection="低", technique="Gather Victim Network Information", mitre="T1590",
        )
        self._add_attack_step(
            "s2", "政务外网终端入侵",
            "钓鱼邮件直接拿下零防护终端——无杀毒、无准入、无EDR",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "gov_terminal", "state": "compromised"}],
            detection="中", technique="Phishing", mitre="T1566",
        )
        self._add_attack_step(
            "s3", "可信通道逆向攻击",
            "利用政务外网终端与数字重庆/IRS的可信连接逆向渗透外部政务平台",
            preconditions=[{"type": "node_compromised", "node": "gov_terminal"}],
            effects=[{"target": "digital_cq", "state": "compromised"}],
            detection="中", technique="Exploit Public-Facing Application", mitre="T1190",
        )
        self._add_attack_step(
            "s4", "医保专网终端入侵",
            "经专网间互联窗口从政务终端横跳医保专网，拿下医保结算终端",
            preconditions=[{"type": "step_completed", "step": "s2"}],
            effects=[{"target": "ins_terminal", "state": "compromised"}],
            detection="中", technique="Lateral Tool Transfer", mitre="T1570",
        )
        self._add_attack_step(
            "s5", "医保结算平台渗透",
            "沿医保终端与结算平台的可信通道逆向攻击医保平台",
            preconditions=[{"type": "node_compromised", "node": "ins_terminal"}],
            effects=[{"target": "ins_platform", "state": "compromised"}],
            detection="中", technique="Exploit Public-Facing Application", mitre="T1190",
        )
        self._add_attack_step(
            "s6", "经互联点跳入内网",
            "利用江北'医保终端-服务器群互联、内部防火墙唯一边界'结构，"
            "从医保终端横向至服务器群并穿透边界攻陷HIS",
            preconditions=[{"type": "node_compromised", "node": "ins_terminal"}],
            effects=[{"target": "server_group", "state": "compromised"},
                     {"target": "his", "state": "compromised"}],
            detection="中", technique="Remote Services", mitre="T1021",
        )
        self._add_attack_step(
            "s7", "结算与患者数据外泄",
            "HIS患者数据+医保结算数据经专网通道回传C2",
            preconditions=[{"type": "node_compromised", "node": "his"}],
            effects=[{"target": "his", "state": "exfiltrated"}],
            detection="高", technique="Exfiltration Over Alternative Protocol", mitre="T1048",
        )

    def _build_defenses(self):
        self._add_defense(
            "d1", "政务外网终端准入+EDR",
            "政务外网终端部署准入控制与终端检测响应（P0-3整改）",
            blocks=["s2"], cost="中", category="终端防护",
        )
        self._add_defense(
            "d2", "专网出口安全网关",
            "政务外网链路加装防火墙/IPS，外部平台连接收敛为白名单",
            blocks=["s3"], cost="高", category="边界防护",
        )
        self._add_defense(
            "d3", "医保专网终端防护",
            "医保终端部署准入+杀毒，专网间互联窗口关闭或加管控",
            blocks=["s4"], cost="中", category="终端防护",
        )
        self._add_defense(
            "d4", "医保平台连接白名单",
            "与医保结算平台的连接限定业务IP+协议白名单",
            blocks=["s5"], cost="低", category="访问控制",
        )
        self._add_defense(
            "d5", "互联点网闸隔离",
            "江北医保终端与服务器群之间部署网闸，消除唯一边界依赖",
            blocks=["s6"], cost="高", category="架构整改",
        )

    def _build_remediations(self):
        """增量整改候选措施（2026-09-06）：针对现状防护全开仍存在的薄弱环节设计，
        仅整改推演轮2生效，不进入现状防护。"""
        self._add_remediation(
            "r1", "蜜罐诱捕专线侦察",
            "专线链路旁路部署蜜罐，攻击者链路侦察即被诱捕",
            covers=['s1'], cost="低", category="监控审计",
            root_cause="专网链路侦察无感知，缺欺骗防御", trap=True,
        )
        self._add_remediation(
            "r2", "DLP结算数据外泄阻断",
            "互联点部署DLP，结算与患者数据外泄实时阻断",
            covers=['s7'], cost="高", category="数据安全",
            root_cause="结算与患者数据外泄步骤现状无防护覆盖，属盲区", trap=False,
        )
        self._add_remediation(
            "r3", "专线流量异常基线",
            "建立专线流量基线，可信通道逆向攻击类异常流量实时告警",
            covers=['s3'], cost="中", category="监控审计",
            root_cause="可信通道逆向攻击仅靠出口网关单道防护", trap=False,
        )
