"""Scenario: 裸奔的专网终端 — 终端准入缺失与 802.1X 落地（优化建议一梯 P1-5）。

证据来源：
- KB-03-0196 安全评估报告 P0-3：渝北政务外网终端直连数字重庆/IRS（无安全设备）；
  江北医保专网终端无防火墙/无准入/无审计，横向渗透可直达政务平台与医保结算数据。
- HCIP 终端接入安全模块（KB-03-0203 知识地图）：802.1X + WinRadius 终端准入标准方案。
- 处置建议（评估报告）：两终端前加下一代防火墙 + 终端准入（802.1X），关闭双网卡混接。

与 bare_wan_terminal（专网无安全设备）的差异：本场景聚焦「终端准入层」——
专网出口设备存在与否之外，终端身份不可信、双网卡混接是隔离击穿的根因，
防御主题为 802.1X 准入 + 双网卡管控。
"""
from ..engine.scenario_base import ScenarioBase


class TerminalAdmissionScenario(ScenarioBase):
    SCENARIO_ID = "terminal_admission"
    SCENARIO_NAME = "裸奔的专网终端：身份不可信与 802.1X 准入"
    SCENARIO_DESC = ("政务外网/医保专网终端无准入无审计（评估报告 P0-3 实测），"
                     "推演攻击者经专网终端横向渗透政务平台与医保结算系统，"
                     "对比「无准入 vs 802.1X+WinRadius 准入」的拦截效果")
    SCENARIO_CATEGORY = "攻防对抗层"
    SCENARIO_DIFFICULTY = "中级"
    SCENARIO_TAGS = ["终端准入", "802.1X", "专网裸奔", "P0-3风险", "政务外网", "真实拓扑"]
    DEMOTED_DEFENSES = ["d1", "d5"]

    def __init__(self):
        super().__init__()
        self._build_topology()
        self._build_attacks()
        self._build_defenses()
        self._build_remediations()
        self._apply_demotions()

    def _build_topology(self):
        self._add_node("internet", "攻击者", "external", 960, 210,
                       "外部攻击源（经政务外网入口渗透）")
        self._add_node("router", "专网接入路由器", "network", 1140, 210,
                       "政务外网接入设备（无终端准入能力）")
        self._add_node("sw", "专网接入交换机", "network", 1320, 210,
                       "【无准入】端口即插即用，无 802.1X 认证（P0-3）")
        self._add_node("t_gov", "政务终端", "workstation", 1110, 60,
                       "直连数字重庆/IRS 业务终端，无防护无审计", awareness="低")
        self._add_node("t_ins", "医保终端", "workstation", 1110, 360,
                       "医保结算终端，无防护无审计", awareness="低")
        self._add_node("gov_plat", "政务平台（IRS）", "server", 1290, 60,
                       "数字重庆/IRS 政务平台")
        self._add_node("ins_plat", "医保结算系统", "server", 1290, 360,
                       "医保结算数据（敏感个人信息）")
        self._add_node("inner_sw", "内网接入交换机", "network", 1500, 210,
                       "内网核心区接入（双网卡桥接可达）")
        self._add_node("his", "HIS 服务器", "server", 1680, 210,
                       "内网 HIS（华为 2288H）")

        self._add_edge("internet", "router", "政务外网")
        self._add_edge("router", "sw", "")
        self._add_edge("sw", "t_gov", "无准入")
        self._add_edge("sw", "t_ins", "无准入")
        self._add_edge("t_gov", "gov_plat", "直连政务平台")
        self._add_edge("t_ins", "ins_plat", "直连医保结算")
        self._add_edge("t_gov", "inner_sw", "双网卡混接（违规）")
        self._add_edge("inner_sw", "his", "")

    def _build_attacks(self):
        self._add_attack_step(
            "s1", "终端暴露面侦察",
            "扫描专网终端网段，确认终端无准入认证、无主机防护，"
            "且发现政务终端存在双网卡混接（内网可达）",
            preconditions=[],
            effects=[{"target": "t_gov", "state": "target"}],
            detection="低", technique="Active Scanning", mitre="T1595",
        )
        self._add_attack_step(
            "s2", "钓鱼投递攻陷政务终端",
            "向政务终端投递伪装政务通知的钓鱼邮件（恶意附件），"
            "无准入无 EDR，触发即沦陷",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "t_gov", "state": "compromised"}],
            detection="中", technique="Phishing", mitre="T1566",
        )
        self._add_attack_step(
            "s3", "凭据窃取",
            "在政务终端提取系统凭据与政务平台登录凭据",
            preconditions=[{"type": "node_compromised", "node": "t_gov"}],
            effects=[{"target": "t_gov", "state": "compromised"}],
            detection="低", technique="OS Credential Dumping", mitre="T1003",
        )
        self._add_attack_step(
            "s4", "横向至医保终端",
            "利用窃取凭据横向登录医保终端（同网段无分段无准入）",
            preconditions=[{"type": "node_compromised", "node": "t_gov"}],
            effects=[{"target": "t_ins", "state": "compromised"}],
            detection="中", technique="Remote Services", mitre="T1021",
        )
        self._add_attack_step(
            "s5", "直达政务平台与医保结算",
            "以受信终端身份直连政务平台（IRS）与医保结算系统，"
            "终端无行为审计，访问无异常告警",
            preconditions=[{"type": "node_compromised", "node": "t_ins"}],
            effects=[{"target": "gov_plat", "state": "compromised"},
                     {"target": "ins_plat", "state": "compromised"}],
            detection="中", technique="Remote Services", mitre="T1021",
        )
        self._add_attack_step(
            "s6", "双网卡桥接击穿内网",
            "利用政务终端双网卡混接，将专网流量桥接至内网，"
            "传输攻击工具直攻内网 HIS",
            preconditions=[{"type": "node_compromised", "node": "t_gov"}],
            effects=[{"target": "his", "state": "compromised"}],
            detection="高", technique="Lateral Tool Transfer", mitre="T1570",
        )
        self._add_attack_step(
            "s7", "医保结算数据外泄",
            "打包医保结算敏感个人信息经政务外网通道外传 C2",
            preconditions=[{"type": "node_compromised", "node": "ins_plat"}],
            effects=[{"target": "ins_plat", "state": "exfiltrated"}],
            detection="高", technique="Exfiltration Over C2 Channel", mitre="T1041",
        )

    def _build_defenses(self):
        self._add_defense(
            "d1", "终端准入 802.1X + WinRadius",
            "接入交换机启用 802.1X 端口认证，未认证终端默认隔离 VLAN，"
            "陌生设备接入即被阻断（HCIP 终端接入安全模块标准方案）",
            blocks=["s2", "s4"], cost="中", category="终端防护",
        )
        self._add_defense(
            "d2", "专网出口下一代防火墙",
            "两专网出口各加一台下一代防火墙（利旧），"
            "边界访问控制 + 入侵防御（评估报告 P0-3 处置）",
            blocks=["s4"], cost="低", category="边界防护",
        )
        self._add_defense(
            "d3", "终端 EDR 与凭据保护",
            "终端部署 EDR + LSA 凭据保护，阻断凭据转储",
            blocks=["s3"], cost="中", category="终端防护",
        )
        self._add_defense(
            "d4", "平台访问白名单",
            "政务平台/医保结算系统按终端指纹 + IP 白名单访问，"
            "异常来源访问被拒绝",
            blocks=["s5"], cost="中", category="访问控制",
        )
        self._add_defense(
            "d5", "双网卡混接管控",
            "物理/管理措施关闭终端双网卡混接，专网终端禁止接入内网，"
            "桥接通道不复存在",
            blocks=["s6"], cost="低", category="配置管理",
        )

    def _build_remediations(self):
        """增量整改候选措施（2026-09-06）：针对现状防护全开仍存在的薄弱环节设计，
        仅整改推演轮2生效，不进入现状防护。"""
        self._add_remediation(
            "r1", "蜜罐诱捕暴露面侦察",
            "专网边界部署蜜罐，终端暴露面侦察即被诱捕",
            covers=['s1'], cost="低", category="监控审计",
            root_cause="终端暴露面侦察无感知", trap=True,
        )
        self._add_remediation(
            "r2", "DLP医保数据外泄阻断",
            "专网出口部署DLP，医保结算数据外泄实时阻断",
            covers=['s7'], cost="高", category="数据安全",
            root_cause="医保结算数据外泄步骤现状无防护覆盖，属盲区", trap=False,
        )
        self._add_remediation(
            "r3", "终端零信任动态评分",
            "部署零信任终端评分，终端风险状态动态调整访问权限",
            covers=['s4'], cost="中", category="终端防护",
            root_cause="横向至医保终端依赖准入单道防护", trap=False,
        )
