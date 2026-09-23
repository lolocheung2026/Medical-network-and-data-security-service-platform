"""Scenario: 切换的代价 — 单一AC逻辑隔离的内外网切换（P0-2 已核实关闭，演练素材）。

证据来源：
1. 台账渝北 4F AC-1000SK1300 承担内外网切换（内外网逻辑隔离）。
2. 乐叔 2026-07-28 16:11 核实：该 AC 设备具备逻辑隔离功能，P0-2 风险关闭。
3. 对照：江北有安恒网闸（物理隔离），渝北无独立网闸（逻辑拓扑v3修正结论）。
本场景推演逻辑隔离的固有边界与单点依赖风险：
管理面被攻陷 → 隔离策略被篡改 → 内外网直通 → 专网侧风险涌入内网。
属演练素材，非对现状的指控。
"""
from ..engine.scenario_base import ScenarioBase


class IsolationSwitchScenario(ScenarioBase):
    SCENARIO_ID = "isolation_switch"
    SCENARIO_NAME = "切换的代价：单一AC逻辑隔离的内外网切换"
    SCENARIO_DESC = ("渝北内外网切换依赖 4F 单一 AC 逻辑隔离（P0-2 已核实关闭），"
                     "推演管理面被攻陷后隔离失效、专网风险涌入内网的完整代价链")
    SCENARIO_CATEGORY = "攻防对抗层"
    SCENARIO_DIFFICULTY = "高级"
    SCENARIO_TAGS = ["内外网切换", "逻辑隔离", "单点依赖", "渝北院区"]
    DEMOTED_DEFENSES = ["d1", "d2", "d3", "d4"]

    def __init__(self):
        super().__init__()
        self._build_topology()
        self._build_attacks()
        self._build_defenses()
        self._build_remediations()
        self._apply_demotions()

    def _build_topology(self):
        # 渝北真实结构：互联网 / 政务外网·卫生专网 → 4F AC 内外网切换（逻辑隔离）
        # → 1楼对面机房串链（AF→IPS→WAF→AC-A400）→ 6F 核心 → 内网
        self._add_node("internet", "攻击者", "external", 800, 60,
                       "互联网侧攻击源")
        self._add_node("gov", "政务外网/卫生专网", "external", 800, 460,
                       "专网出口（终端无安全设备，P0-3）")
        self._add_node("gov_terminal", "政务外网终端", "workstation", 800, 660,
                       "专网侧终端（无准入/无杀毒，P0-3 现状）", awareness="低")
        self._add_node("ac_switch", "4F AC-1000SK1300", "firewall", 800, 260,
                       "内外网切换（逻辑隔离；乐叔16:11核实具备逻辑隔离功能，P0-2关闭）")
        self._add_node("af", "AF防火墙", "firewall", 1000, 260,
                       "1楼对面机房")
        self._add_node("ips", "IPS", "firewall", 1200, 260,
                       "1楼对面机房")
        self._add_node("waf", "WAF", "firewall", 1200, 460,
                       "1楼对面机房")
        self._add_node("ac_a400", "AC-1000-A400", "firewall", 1600, 260,
                       "1楼对面机房上网行为管理")
        self._add_node("core6f", "6F核心", "network", 1800, 260,
                       "核心层（角色错配见另一场景）")
        self._add_node("switch_int", "内网交换机", "network", 1400, 260,
                       "办公/临床区汇聚")
        self._add_node("pc_int", "办公终端", "workstation", 2000, 60,
                       "行政办公")
        self._add_node("pc_clinic", "临床终端", "workstation", 2000, 260,
                       "门诊工作站")
        self._add_node("his", "HIS服务器", "server", 1600, 460,
                       "核心HIS（401机房）")
        self._add_node("emr", "EMR服务器", "server", 2000, 460,
                       "电子病历")

        self._add_edge("internet", "ac_switch", "互联网")
        self._add_edge("gov", "ac_switch", "政务外网/卫生专网")
        self._add_edge("gov_terminal", "gov", "")
        self._add_edge("ac_switch", "af", "")
        self._add_edge("af", "ips", "")
        self._add_edge("ips", "waf", "")
        self._add_edge("waf", "ac_a400", "")
        self._add_edge("ac_a400", "core6f", "")
        self._add_edge("core6f", "switch_int", "")
        self._add_edge("switch_int", "pc_int", "")
        self._add_edge("switch_int", "pc_clinic", "")
        self._add_edge("core6f", "his", "")
        self._add_edge("his", "emr", "")

    def _build_attacks(self):
        self._add_attack_step(
            "s1", "隔离机制侦察",
            "攻击者探测内外网切换点，确认隔离由单一AC以逻辑隔离（ACL级）实现，"
            "无独立网闸（渝北无网闸，对照江北安恒网闸）",
            preconditions=[],
            effects=[{"target": "ac_switch", "state": "target"}],
            detection="低", technique="Gather Victim Network Information", mitre="T1590",
        )
        self._add_attack_step(
            "s2", "专网终端入侵",
            "政务外网终端无准入无杀毒（P0-3现状），被钓鱼拿下作为跳板",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "gov_terminal", "state": "compromised"}],
            detection="中", technique="Phishing", mitre="T1566",
        )
        self._add_attack_step(
            "s3", "AC管理面入侵",
            "爆破AC管理接口（弱口令/无源IP限制）取得内外网切换设备控制权",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "ac_switch", "state": "compromised"}],
            detection="中", technique="Brute Force", mitre="T1110",
        )
        self._add_attack_step(
            "s4", "隔离策略篡改",
            "篡改内外网ACL策略，逻辑隔离失效——内外网直通，"
            "且AC为唯一隔离点，无第二道隔离兜底",
            preconditions=[{"type": "node_compromised", "node": "ac_switch"}],
            effects=[{"target": "switch_int", "state": "compromised"}],
            detection="高", technique="Modify Cloud Compute Infrastructure", mitre="T1578",
        )
        self._add_attack_step(
            "s5", "专网风险涌入内网",
            "隔离失效后，专网侧恶意流量与跳板直入内网，办公/临床终端批量沦陷",
            preconditions=[{"type": "node_compromised", "node": "switch_int"}],
            effects=[{"target": "pc_int", "state": "compromised"},
                     {"target": "pc_clinic", "state": "compromised"}],
            detection="中", technique="Lateral Tool Transfer", mitre="T1570",
        )
        self._add_attack_step(
            "s6", "核心业务横向移动",
            "从临床终端横向移动至HIS/EMR服务器",
            preconditions=[{"type": "node_compromised", "node": "pc_clinic"}],
            effects=[{"target": "his", "state": "compromised"},
                     {"target": "emr", "state": "compromised"}],
            detection="中", technique="Remote Services", mitre="T1021",
        )
        self._add_attack_step(
            "s7", "患者数据外泄",
            "经失效隔离通道将HIS患者数据外传",
            preconditions=[{"type": "node_compromised", "node": "his"}],
            effects=[{"target": "his", "state": "exfiltrated"}],
            detection="高", technique="Exfiltration Over Alternative Protocol", mitre="T1048",
        )

    def _build_defenses(self):
        self._add_defense(
            "d1", "AC管理面加固",
            "管理接口限源IP+强口令+双因子，守住隔离设备本身",
            blocks=["s3"], cost="低", category="访问控制",
        )
        self._add_defense(
            "d2", "隔离策略变更审计",
            "AC策略变更留痕+季度完整性复核，篡改即发现",
            blocks=["s4"], cost="中", category="监控审计",
        )
        self._add_defense(
            "d3", "内外网物理网闸",
            "内外网间增加独立网闸（参照江北安恒网闸部署），"
            "协议剥离级物理隔离，AC被破仍有第二道隔离",
            blocks=["s5"], cost="高", category="架构整改",
        )
        self._add_defense(
            "d4", "专网终端准入防护",
            "政务外网/医保专网终端部署准入+EDR（对应P0-3整改），消除跳板",
            blocks=["s2"], cost="中", category="终端防护",
        )
        self._add_defense(
            "d5", "出口数据防泄漏",
            "出口DLP监测外传流量，阻断患者数据外泄",
            blocks=["s7"], cost="高", category="数据安全",
        )

    def _build_remediations(self):
        """增量整改候选措施（2026-09-06）：针对现状防护全开仍存在的薄弱环节设计，
        仅整改推演轮2生效，不进入现状防护。"""
        self._add_remediation(
            "r1", "蜜罐诱捕隔离侦察",
            "专网边界部署蜜罐，攻击者隔离机制侦察即被诱捕",
            covers=['s1'], cost="低", category="监控审计",
            root_cause="隔离机制侦察无感知，攻击者可摸清隔离拓扑", trap=True,
        )
        self._add_remediation(
            "r2", "内网横向行为检测",
            "部署NDR对内网横向移动行为检测与阻断",
            covers=['s6'], cost="中", category="监控审计",
            root_cause="核心业务横向移动步骤现状无防护覆盖，属盲区", trap=False,
        )
        self._add_remediation(
            "r3", "专网终端双因子+白名单",
            "专网终端登录升级双因子与设备白名单，加固终端准入",
            covers=['s2'], cost="中", category="终端防护",
            root_cause="专网终端准入依赖单道防护，缺纵深认证", trap=False,
        )
