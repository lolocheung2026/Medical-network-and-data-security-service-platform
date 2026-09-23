"""Scenario: Ransomware attack chain in hospital setting."""
from ..engine.scenario_base import ScenarioBase


class RansomwareScenario(ScenarioBase):
    SCENARIO_ID = "ransomware"
    SCENARIO_NAME = "勒索病毒攻击链推演"
    SCENARIO_DESC = "模拟勒索病毒从钓鱼邮件入侵到全院系统加密的完整攻击链，推演各环节防御对策"
    SCENARIO_CATEGORY = "攻防对抗层"
    SCENARIO_DIFFICULTY = "高级"
    SCENARIO_TAGS = ["勒索病毒", "钓鱼攻击", "横向移动", "数据加密"]
    DEMOTED_DEFENSES = ["d1", "d2", "d3", "d4"]

    def __init__(self):
        super().__init__()
        self._build_topology()
        self._build_attacks()
        self._build_defenses()
        self._build_remediations()
        self._apply_demotions()

    def _build_topology(self):
        self._add_node("internet", "攻击者", "external", 1140, 210, "外部攻击源")
        self._add_node("mailsrv", "邮件服务器", "server", 1020, 60, "医院邮件系统")
        self._add_node("firewall", "边界防火墙", "firewall", 1110, 360, "NGFW")
        self._add_node("pc1", "护士站PC", "workstation", 1200, 60, "行政办公终端")
        self._add_node("his", "HIS服务器", "server", 1380, 60, "核心HIS系统")
        self._add_node("pacs", "PACS服务器", "server", 1320, 210, "影像系统")
        self._add_node("emr", "EMR服务器", "server", 1290, 360, "电子病历")
        self._add_node("backup", "备份存储", "database", 1500, 210, "灾备系统")

        self._add_edge("internet", "mailsrv")
        self._add_edge("internet", "firewall")
        self._add_edge("mailsrv", "pc1")
        self._add_edge("pc1", "his")
        self._add_edge("pc1", "pacs")
        self._add_edge("his", "emr")
        self._add_edge("pacs", "emr")
        self._add_edge("emr", "backup")
        self._add_edge("his", "backup")

    def _build_attacks(self):
        self._add_attack_step(
            "s1", "钓鱼邮件投递",
            "攻击者向护士站发送伪装成卫健委通知的钓鱼邮件，附带恶意Word附件",
            preconditions=[],
            effects=[{"target": "mailsrv", "state": "target"}],
            detection="中", technique="Spearphishing Attachment", mitre="T1566.001",
        )
        self._add_attack_step(
            "s2", "恶意宏执行",
            "护士打开附件启用宏，恶意代码执行，植入Cobalt Strike Beacon",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "pc1", "state": "compromised"}],
            detection="低", technique="User Execution", mitre="T1204.002",
        )
        self._add_attack_step(
            "s3", "权限提升",
            "利用Windows本地提权漏洞(EternalRomance)获取SYSTEM权限",
            preconditions=[{"type": "node_compromised", "node": "pc1"}],
            effects=[{"target": "pc1", "state": "compromised"}],
            detection="中", technique="Exploitation for Privilege Escalation", mitre="T1068",
        )
        self._add_attack_step(
            "s4", "凭据窃取",
            "使用Mimikatz从内存中提取域账号凭据，获取HIS访问权限",
            preconditions=[{"type": "step_completed", "step": "s3"}],
            effects=[{"target": "his", "state": "compromised"}],
            detection="低", technique="OS Credential Dumping", mitre="T1003",
        )
        self._add_attack_step(
            "s5", "横向移动至PACS/EMR",
            "利用 stolen credentials 横向移动到PACS和EMR服务器",
            preconditions=[{"type": "node_compromised", "node": "his"}],
            effects=[{"target": "pacs", "state": "compromised"},
                     {"target": "emr", "state": "compromised"}],
            detection="中", technique="Remote Services", mitre="T1021",
        )
        self._add_attack_step(
            "s6", "数据外泄",
            "压缩患者数据并通过DNS隧道外泄至C2服务器",
            preconditions=[{"type": "node_compromised", "node": "emr"}],
            effects=[{"target": "emr", "state": "exfiltrated"}],
            detection="高", technique="Exfiltration Over Alternative Protocol", mitre="T1048",
        )
        self._add_attack_step(
            "s7", "全院加密勒索",
            "部署WannaCry变种，加密HIS/PACS/EMR全部服务器数据并投递勒索信",
            preconditions=[{"type": "node_compromised", "node": "pacs"},
                           {"type": "node_compromised", "node": "emr"}],
            effects=[{"target": "his", "state": "encrypted"},
                     {"target": "pacs", "state": "encrypted"},
                     {"target": "emr", "state": "encrypted"}],
            detection="高", technique="Data Encrypted for Impact", mitre="T1486",
        )

    def _build_defenses(self):
        self._add_defense(
            "d1", "邮件安全网关",
            "部署邮件沙箱，拦截恶意附件和钓鱼链接",
            blocks=["s1"], cost="中", category="边界防护",
        )
        self._add_defense(
            "d2", "EDR终端防护",
            "部署终端检测响应系统，识别恶意宏执行和提权行为",
            blocks=["s2", "s3"], cost="高", category="终端防护",
        )
        self._add_defense(
            "d3", "最小权限策略",
            "实施RBAC，护士站PC无HIS服务器直接管理权限",
            blocks=["s4"], cost="低", category="访问控制",
        )
        self._add_defense(
            "d4", "网络微隔离",
            "服务器之间实施微隔离，阻断横向移动路径",
            blocks=["s5"], cost="中", category="网络防护",
        )
        self._add_defense(
            "d5", "离线灾备",
            "部署不可变离线备份，确保加密后可快速恢复",
            blocks=["s7"], cost="高", category="灾备恢复",
        )

    def _build_remediations(self):
        """增量整改候选措施（2026-09-06）：针对现状防护全开仍存在的薄弱环节设计，
        仅整改推演轮2生效，不进入现状防护。"""
        self._add_remediation(
            "r1", "蜜罐+钓鱼邮件沙箱",
            "部署蜜罐群与邮件附件沙箱，钓鱼投递即被诱捕、邮件载荷动态引爆检测",
            covers=['s1'], cost="中", category="监控审计",
            root_cause="钓鱼投递仅靠邮件网关单道拦截，无诱捕与载荷引爆分析", trap=True,
        )
        self._add_remediation(
            "r2", "DLP数据外泄阻断",
            "部署DLP对出向流量敏感数据识别与阻断，堵住勒索前的数据外泄通道",
            covers=['s6'], cost="高", category="数据安全",
            root_cause="数据外泄步骤现状无任何防护覆盖，属盲区", trap=False,
        )
        self._add_remediation(
            "r3", "终端勒索行为实时检测",
            "EDR升级勒索行为引擎：加密速率异常、批量改扩展名即实时阻断",
            covers=['s7'], cost="中", category="终端防护",
            root_cause="加密勒索仅依赖离线灾备兜底，缺加密行为实时拦截能力", trap=False,
        )
