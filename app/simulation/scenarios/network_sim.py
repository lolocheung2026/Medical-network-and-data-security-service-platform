"""Scenario: Network protocol simulation - hospital network topology."""
from ..engine.scenario_base import ScenarioBase


class NetworkSimScenario(ScenarioBase):
    SCENARIO_ID = "network_sim"
    SCENARIO_NAME = "网络协议模拟"
    SCENARIO_DESC = "模拟医院网络拓扑结构，推演网络扫描、端口探测、漏洞利用到横向移动的完整攻击链路"
    SCENARIO_CATEGORY = "基础设施层"
    SCENARIO_DIFFICULTY = "中级"
    SCENARIO_TAGS = ["TCP/IP", "网络扫描", "横向移动", "医院网络"]
    DEMOTED_DEFENSES = ["d1", "d2", "d3"]

    def __init__(self):
        super().__init__()
        self._build_topology()
        self._build_attacks()
        self._build_defenses()
        self._build_remediations()
        self._apply_demotions()

    def _build_topology(self):
        self._add_node("internet", "互联网", "external", 1050, 210, "外部网络")
        self._add_node("firewall", "边界防火墙", "firewall", 1230, 210, "WAF + NGFW")
        self._add_node("switch", "核心交换机", "switch", 1410, 210, "内网核心交换")
        self._add_node("his", "HIS服务器", "server", 1110, 60, "医院信息系统")
        self._add_node("pacs", "PACS服务器", "server", 1590, 210, "影像归档系统")
        self._add_node("emr", "EMR服务器", "server", 1110, 360, "电子病历系统")
        self._add_node("pc1", "护士站PC", "workstation", 1290, 60, "护士工作站")
        self._add_node("iot1", "病人监护仪", "iot", 1290, 360, "ICU监护设备")

        self._add_edge("internet", "firewall")
        self._add_edge("firewall", "switch")
        self._add_edge("switch", "his")
        self._add_edge("switch", "pacs")
        self._add_edge("switch", "emr")
        self._add_edge("his", "pc1")
        self._add_edge("pacs", "iot1")
        self._add_edge("emr", "pc1")
        self._add_edge("emr", "iot1")

    def _build_attacks(self):
        self._add_attack_step(
            "s1", "网络扫描",
            "攻击者从外部对医院网络进行端口扫描，发现开放服务",
            preconditions=[],
            effects=[{"target": "firewall", "state": "target"}],
            detection="中", technique="Port Scan", mitre="T1046",
        )
        self._add_attack_step(
            "s2", "防火墙绕过",
            "利用防火墙配置缺陷绕过访问控制，进入内网",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "firewall", "state": "compromised"},
                     {"target": "switch", "state": "target"}],
            detection="高", technique="Firewall Bypass", mitre="T1190",
        )
        self._add_attack_step(
            "s3", "PACS服务漏洞利用",
            "利用PACS服务器DICOM协议未授权访问漏洞，获取系统权限",
            preconditions=[{"type": "step_completed", "step": "s2"}],
            effects=[{"target": "pacs", "state": "compromised"}],
            detection="中", technique="Service Exploit", mitre="T1210",
        )
        self._add_attack_step(
            "s4", "横向移动至EMR",
            "利用PACS与EMR之间的信任关系，横向移动到电子病历系统",
            preconditions=[{"type": "node_compromised", "node": "pacs"}],
            effects=[{"target": "emr", "state": "compromised"}],
            detection="低", technique="Lateral Movement", mitre="T1021",
        )
        self._add_attack_step(
            "s5", "患者数据窃取",
            "从EMR系统导出患者电子病历数据，进行数据外泄",
            preconditions=[{"type": "node_compromised", "node": "emr"}],
            effects=[{"target": "emr", "state": "exfiltrated"},
                     {"target": "iot1", "state": "compromised"}],
            detection="高", technique="Data Exfiltration", mitre="T1041",
        )

    def _build_defenses(self):
        self._add_defense(
            "d1", "防火墙ACL强化",
            "配置严格的访问控制列表，仅允许必要端口通信",
            blocks=["s2"], cost="低", category="网络防护",
        )
        self._add_defense(
            "d2", "网络微分段",
            "将HIS/PACS/EMR部署在不同VLAN，限制横向流量",
            blocks=["s4"], cost="中", category="网络防护",
        )
        self._add_defense(
            "d3", "IDS/IPS部署",
            "部署入侵检测/防御系统，识别异常扫描和漏洞利用行为",
            blocks=["s3"], cost="中", category="检测响应",
        )
        self._add_defense(
            "d4", "数据外泄监控",
            "部署DLP系统监控异常数据流出，阻断外泄通道",
            blocks=["s5"], cost="高", category="数据保护",
        )

    def _build_remediations(self):
        """增量整改候选措施（2026-09-06）：针对现状防护全开仍存在的薄弱环节设计，
        仅整改推演轮2生效，不进入现状防护。"""
        self._add_remediation(
            "r1", "内网蜜罐诱捕",
            "在核心交换机旁路部署蜜罐群，攻击者网络扫描即被诱捕、告警并阻断侦察链",
            covers=['s1'], cost="低", category="监控审计",
            root_cause="内网侦察无感知：现状无欺骗防御，攻击者可无扰绘制资产地图", trap=True,
        )
        self._add_remediation(
            "r2", "DLP出口外联管控",
            "在互联网出口部署DLP，对患者数据外泄通道进行实时检测与阻断",
            covers=['s5'], cost="高", category="数据安全",
            root_cause="数据外泄仅单道防护：绕过即失守，缺出口侧兜底", trap=False,
        )
        self._add_remediation(
            "r3", "全网流量基线异常检测",
            "建立内网流量行为基线，对防火墙绕过与漏洞利用类异常流量二次检测",
            covers=['s2', 's3'], cost="中", category="检测响应",
            root_cause="边界与内网检测依赖单点IDS/IPS，缺纵深第二道检测", trap=False,
        )
