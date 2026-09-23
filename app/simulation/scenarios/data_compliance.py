"""Scenario: Data security compliance - PIPL and Data Security Law."""
from ..engine.scenario_base import ScenarioBase


class DataComplianceScenario(ScenarioBase):
    SCENARIO_ID = "data_compliance"
    SCENARIO_NAME = "数据安全合规推演"
    SCENARIO_DESC = "模拟医疗数据全生命周期(采集-处理-存储-共享-销毁)中的安全风险与合规要求，推演数据安全法和个人信息保护法合规路径"
    SCENARIO_CATEGORY = "数据安全层"
    SCENARIO_DIFFICULTY = "中级"
    SCENARIO_TAGS = ["数据安全法", "个人信息保护法", "数据脱敏", "合规"]
    DEMOTED_DEFENSES = ["d1", "d2"]

    def __init__(self):
        super().__init__()
        self._build_topology()
        self._build_attacks()
        self._build_defenses()
        self._build_remediations()
        self._apply_demotions()

    def _build_topology(self):
        self._add_node("collector", "数据采集", "server", 800, 360, "门诊/住院采集")
        self._add_node("processor", "数据处理", "server", 1400, 360, "ETL/清洗/标注")
        self._add_node("storage", "数据存储", "database", 800, 60, "数据仓库")
        self._add_node("sharing", "数据共享", "server", 800, 660, "科研/第三方共享")
        self._add_node("audit", "审计系统", "server", 2000, 360, "日志/审计")
        self._add_node("external", "外部接收方", "external", 2000, 660, "科研机构/厂商")

        self._add_edge("collector", "processor")
        self._add_edge("processor", "storage")
        self._add_edge("processor", "sharing")
        self._add_edge("storage", "sharing")
        self._add_edge("storage", "audit")
        self._add_edge("sharing", "external")
        self._add_edge("sharing", "audit")

    def _build_attacks(self):
        self._add_attack_step(
            "s1", "越权访问数据仓库",
            "利用数据处理服务器的过高权限，未授权访问患者数据仓库",
            preconditions=[],
            effects=[{"target": "processor", "state": "compromised"},
                     {"target": "storage", "state": "target"}],
            detection="中", technique="Valid Accounts", mitre="T1078",
        )
        self._add_attack_step(
            "s2", "患者数据泄露",
            "通过数据共享通道将未脱敏的患者个人信息发送至外部接收方",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "storage", "state": "exfiltrated"},
                     {"target": "sharing", "state": "compromised"},
                     {"target": "external", "state": "target"}],
            detection="高", technique="Data Exfiltration", mitre="T1041",
        )
        self._add_attack_step(
            "s3", "违反数据安全法",
            "未对重要数据进行分类分级保护，违反《数据安全法》第27条",
            preconditions=[{"type": "node_compromised", "node": "sharing"}],
            effects=[{"target": "sharing", "state": "compromised"}],
            detection="高", technique="Compliance Violation", mitre="",
        )
        self._add_attack_step(
            "s4", "侵犯患者隐私权",
            "未经患者知情同意共享敏感医疗信息，违反《个人信息保护法》第29条",
            preconditions=[{"type": "step_completed", "step": "s3"}],
            effects=[{"target": "external", "state": "compromised"}],
            detection="高", technique="Privacy Violation", mitre="",
        )

    def _build_defenses(self):
        self._add_defense(
            "d1", "数据分类分级",
            "按数据安全法要求对医疗数据进行分类分级，实施差异化保护",
            blocks=["s1"], cost="低", category="合规治理",
        )
        self._add_defense(
            "d2", "数据脱敏处理",
            "共享前对患者信息进行k-匿名/差分隐私脱敏处理",
            blocks=["s2"], cost="中", category="数据保护",
        )
        self._add_defense(
            "d3", "全链路审计",
            "部署数据操作审计系统，记录所有访问和共享行为",
            blocks=["s3"], cost="中", category="审计追溯",
        )
        self._add_defense(
            "d4", "知情同意管理",
            "建立患者知情同意电子签署流程，确保数据共享合法合规",
            blocks=["s4"], cost="低", category="合规治理",
        )

    def _build_remediations(self):
        """增量整改候选措施（2026-09-06）：针对现状防护全开仍存在的薄弱环节设计，
        仅整改推演轮2生效，不进入现状防护。"""
        self._add_remediation(
            "r1", "越权行为分析引擎",
            "部署UEBA行为分析，越权访问数据仓库即触发动态风险评分与告警",
            covers=['s1'], cost="中", category="监控审计",
            root_cause="越权访问依赖静态权限配置，缺动态行为检测", trap=False,
        )
        self._add_remediation(
            "r2", "动态脱敏引擎",
            "部署动态脱敏，查询结果按角色实时脱敏，杜绝批量明文导出",
            covers=['s2'], cost="中", category="数据安全",
            root_cause="静态脱敏存在旁路，缺查询级动态脱敏", trap=False,
        )
        self._add_remediation(
            "r3", "合规审计自动化闭环",
            "部署自动化合规审计平台，违规行为自动留证、自动生成合规报告",
            covers=['s3'], cost="低", category="审计追溯",
            root_cause="合规审计依赖人工抽样，缺全链路自动化留证", trap=False,
        )
