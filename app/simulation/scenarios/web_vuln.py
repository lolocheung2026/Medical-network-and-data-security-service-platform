"""Scenario: Web vulnerability range - hospital portal."""
from ..engine.scenario_base import ScenarioBase


class WebVulnScenario(ScenarioBase):
    SCENARIO_ID = "web_vuln"
    SCENARIO_NAME = "Web漏洞靶场"
    SCENARIO_DESC = "模拟医院在线服务门户的常见Web漏洞，推演SQL注入、认证绕过到数据泄露的攻击链"
    SCENARIO_CATEGORY = "攻防对抗层"
    SCENARIO_DIFFICULTY = "中级"
    SCENARIO_TAGS = ["SQL注入", "XSS", "认证绕过", "OWASP Top10"]
    DEMOTED_DEFENSES = ["d1", "d2", "d3"]

    def __init__(self):
        super().__init__()
        self._build_topology()
        self._build_attacks()
        self._build_defenses()
        self._build_remediations()
        self._apply_demotions()

    def _build_topology(self):
        self._add_node("internet", "攻击者", "external", 1050, 210, "外部攻击源")
        self._add_node("nginx", "反向代理", "firewall", 1230, 210, "Nginx")
        self._add_node("webapp", "Web应用", "server", 1410, 210, "医院门户系统")
        self._add_node("appsrv", "应用服务器", "server", 1200, 60, "业务逻辑层")
        self._add_node("db", "数据库", "database", 1200, 360, "患者信息数据库")
        self._add_node("admin", "管理后台", "workstation", 1590, 210, "系统管理面板")

        self._add_edge("internet", "nginx")
        self._add_edge("nginx", "webapp")
        self._add_edge("webapp", "appsrv")
        self._add_edge("webapp", "db")
        self._add_edge("appsrv", "db")
        self._add_edge("appsrv", "admin")

    def _build_attacks(self):
        self._add_attack_step(
            "s1", "信息收集",
            "对医院门户进行目录扫描和指纹识别，发现登录页面和管理后台路径",
            preconditions=[],
            effects=[{"target": "nginx", "state": "target"}],
            detection="低", technique="Active Scanning", mitre="T1595",
        )
        self._add_attack_step(
            "s2", "SQL注入",
            "在登录表单username字段注入 ' OR 1=1-- 构造永真条件",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "webapp", "state": "compromised"},
                     {"target": "db", "state": "target"}],
            detection="中", technique="SQL Injection", mitre="T1190",
        )
        self._add_attack_step(
            "s3", "认证绕过",
            "利用SQL注入绕过身份验证，获取普通用户会话",
            preconditions=[{"type": "node_compromised", "node": "webapp"}],
            effects=[{"target": "appsrv", "state": "compromised"}],
            detection="中", technique="Valid Accounts", mitre="T1078",
        )
        self._add_attack_step(
            "s4", "患者数据提取",
            "通过UNION注入提取患者个人信息表(patient_info)全部记录",
            preconditions=[{"type": "node_compromised", "node": "appsrv"}],
            effects=[{"target": "db", "state": "exfiltrated"}],
            detection="高", technique="Data from Information Repositories", mitre="T1213",
        )
        self._add_attack_step(
            "s5", "管理后台提权",
            "利用管理后台未授权访问漏洞，获取系统管理员权限",
            preconditions=[{"type": "step_completed", "step": "s4"}],
            effects=[{"target": "admin", "state": "compromised"}],
            detection="高", technique="Privilege Escalation", mitre="T1068",
        )

    def _build_defenses(self):
        self._add_defense(
            "d1", "WAF部署",
            "部署Web应用防火墙，拦截SQL注入和XSS攻击载荷",
            blocks=["s2"], cost="中", category="边界防护",
        )
        self._add_defense(
            "d2", "参数化查询",
            "所有数据库操作使用预编译语句，消除注入风险",
            blocks=["s2", "s4"], cost="低", category="代码安全",
        )
        self._add_defense(
            "d3", "多因素认证",
            "管理后台启用MFA，防止凭据泄露后的未授权访问",
            blocks=["s3", "s5"], cost="低", category="访问控制",
        )
        self._add_defense(
            "d4", "最小权限DB账户",
            "Web应用使用只读DB账户，限制数据操作范围",
            blocks=["s4"], cost="低", category="访问控制",
        )

    def _build_remediations(self):
        """增量整改候选措施（2026-09-06）：针对现状防护全开仍存在的薄弱环节设计，
        仅整改推演轮2生效，不进入现状防护。"""
        self._add_remediation(
            "r1", "蜜罐诱捕信息收集",
            "WEB入口部署蜜罐站点，攻击者信息收集与扫描即被诱捕告警",
            covers=['s1'], cost="低", category="监控审计",
            root_cause="攻击前信息收集无感知，缺欺骗防御能力", trap=True,
        )
        self._add_remediation(
            "r2", "数据库行为实时审计阻断",
            "部署数据库审计与实时阻断，患者数据批量提取即告警并断连",
            covers=['s4'], cost="中", category="数据安全",
            root_cause="数据提取防护依赖应用层单点，缺数据库侧兜底", trap=False,
        )
        self._add_remediation(
            "r3", "会话令牌绑定强化",
            "会话绑定设备指纹+IP+时间窗，认证绕过类攻击失效",
            covers=['s3'], cost="低", category="访问控制",
            root_cause="认证机制缺会话级纵深校验", trap=False,
        )
