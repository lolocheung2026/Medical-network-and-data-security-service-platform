"""Scenario: Medical IoT device simulation - DICOM/HL7 attack surface."""
from ..engine.scenario_base import ScenarioBase


class IoTMEDICALScenario(ScenarioBase):
    SCENARIO_ID = "iot_medical"
    SCENARIO_NAME = "医疗IoT设备模拟"
    SCENARIO_DESC = "模拟医疗物联网设备(DICOM/HL7协议)的攻击面，推演设备发现到参数篡改的完整攻击链"
    SCENARIO_CATEGORY = "基础设施层"
    SCENARIO_DIFFICULTY = "高级"
    SCENARIO_TAGS = ["DICOM", "HL7", "医疗IoT", "设备安全"]
    DEMOTED_DEFENSES = ["d1", "d3"]

    def __init__(self):
        super().__init__()
        self._build_topology()
        self._build_attacks()
        self._build_defenses()
        self._build_remediations()
        self._apply_demotions()

    def _build_topology(self):
        self._add_node("internet", "攻击者", "external", 1050, 210, "外部攻击源")
        self._add_node("gateway", "IoT网关", "firewall", 1230, 210, "医疗设备网关")
        self._add_node("monitor", "病人监护仪", "iot", 1110, 60, "ICU多参数监护")
        self._add_node("pump", "智能输液泵", "iot", 1410, 210, "输液速率控制")
        self._add_node("mri", "MRI扫描仪", "iot", 1110, 360, "磁共振设备")
        self._add_node("pacs", "PACS服务器", "server", 1290, 60, "影像归档")
        self._add_node("his", "HIS服务器", "server", 1290, 360, "医院信息系统")
        self._add_node("worklist", "设备工作列表", "database", 1590, 210, "DICOM Worklist")

        self._add_edge("internet", "gateway")
        self._add_edge("gateway", "monitor")
        self._add_edge("gateway", "pump")
        self._add_edge("gateway", "mri")
        self._add_edge("monitor", "pacs")
        self._add_edge("mri", "pacs")
        self._add_edge("pacs", "worklist")
        self._add_edge("his", "worklist")
        self._add_edge("pacs", "his")

    def _build_attacks(self):
        self._add_attack_step(
            "s1", "设备发现",
            "通过DICOM C-ECHO广播扫描医疗设备网络，发现在线设备",
            preconditions=[],
            effects=[{"target": "gateway", "state": "target"}],
            detection="中", technique="Network Service Discovery", mitre="T1046",
        )
        self._add_attack_step(
            "s2", "DICOM协议漏洞利用",
            "利用DICOM未授权C-FIND漏洞，无需认证即可查询患者影像",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "pacs", "state": "compromised"}],
            detection="低", technique="Exploit Public-Facing Application", mitre="T1190",
        )
        self._add_attack_step(
            "s3", "患者数据截获",
            "在PACS与监护仪之间实施中间人攻击，截获患者生理数据流",
            preconditions=[{"type": "node_compromised", "node": "pacs"}],
            effects=[{"target": "monitor", "state": "compromised"}],
            detection="高", technique="Adversary-in-the-Middle", mitre="T1557",
        )
        self._add_attack_step(
            "s4", "输液泵参数篡改",
            "利用HL7消息注入修改输液泵速率参数，造成医疗安全事故",
            preconditions=[{"type": "node_compromised", "node": "pacs"}],
            effects=[{"target": "pump", "state": "compromised"}],
            detection="高", technique="Data Manipulation", mitre="T1565",
        )
        self._add_attack_step(
            "s5", "横向渗透HIS",
            "通过Worklist服务器跳板渗透HIS系统，获取全院患者信息",
            preconditions=[{"type": "node_compromised", "node": "pacs"}],
            effects=[{"target": "worklist", "state": "compromised"},
                     {"target": "his", "state": "compromised"}],
            detection="中", technique="Lateral Movement", mitre="T1021",
        )

    def _build_defenses(self):
        self._add_defense(
            "d1", "设备认证机制",
            "启用DICOM TLS双向认证，拒绝未授权设备连接",
            blocks=["s2"], cost="中", category="设备安全",
        )
        self._add_defense(
            "d2", "通信加密",
            "医疗设备间通信全链路TLS加密，防止数据截获",
            blocks=["s3"], cost="中", category="通信安全",
        )
        self._add_defense(
            "d3", "设备网络隔离",
            "医疗设备网络与办公网络物理/逻辑隔离",
            blocks=["s5"], cost="低", category="网络防护",
        )
        self._add_defense(
            "d4", "异常行为监控",
            "部署医疗设备行为基线监控，检测参数篡改和异常指令",
            blocks=["s4"], cost="高", category="检测响应",
        )

    def _build_remediations(self):
        """增量整改候选措施（2026-09-06）：针对现状防护全开仍存在的薄弱环节设计，
        仅整改推演轮2生效，不进入现状防护。"""
        self._add_remediation(
            "r1", "医疗设备蜜罐+资产测绘",
            "部署医疗设备仿真蜜罐，设备发现扫描即被诱捕，同时补齐资产台账",
            covers=['s1'], cost="低", category="监控审计",
            root_cause="物联网设备无感知测绘，攻击者可无扰枚举设备", trap=True,
        )
        self._add_remediation(
            "r2", "DICOM协议深度检测",
            "部署协议级IPS对DICOM协议异常字段与畸形包深度检测",
            covers=['s2'], cost="中", category="设备安全",
            root_cause="DICOM漏洞利用仅靠设备认证单道防护", trap=False,
        )
        self._add_remediation(
            "r3", "数据流加密+审计",
            "设备数据传输全加密，异常读取行为审计告警",
            covers=['s3'], cost="中", category="数据安全",
            root_cause="患者数据截获防护依赖单道通信加密", trap=False,
        )
