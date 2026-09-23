"""Scenario: OSS数据泄露 — 人口数据Bucket权限误配（医院云网攻防场景库场景2）。

证据来源：
1. 医院云网攻防场景库.md（L3蒸馏）：OSS数据泄露场景——Bucket权限误配→
   检测到异常下载→收紧ACL+开启版本控制追回；
2. 评估报告（KB-03-0196）：云端人口数据分类分级倒挂、无审计（P0-4关联）。
推演：公开读Bucket被批量拖取→数据外流→覆盖破坏→凭据提取横向。
"""
from ..engine.scenario_base import ScenarioBase


class CloudOssLeakScenario(ScenarioBase):
    SCENARIO_ID = "cloud_oss_leak"
    SCENARIO_NAME = "OSS数据泄露：人口数据Bucket权限误配"
    SCENARIO_DESC = ("云端人口数据Bucket权限误配为公开读，推演匿名批量拖取3000万画像数据、"
                     "覆盖破坏、泄漏凭据横向，与版本控制/Audit审计缺失的追回困境")
    SCENARIO_CATEGORY = "数据安全层"
    SCENARIO_DIFFICULTY = "高级"
    SCENARIO_TAGS = ["云安全", "OSS", "权限误配", "数据泄露", "云攻防"]
    DEMOTED_DEFENSES = ["d1", "d2", "d5"]

    def __init__(self):
        super().__init__()
        self._build_topology()
        self._build_attacks()
        self._build_defenses()
        self._build_remediations()
        self._apply_demotions()

    def _build_topology(self):
        self._add_node("attacker", "攻击者", "external", 870, 210,
                       "互联网侧攻击源")
        self._add_node("eip", "云公网入口", "network", 1050, 210,
                       "第三方云入口")
        self._add_node("oss_bucket", "人口数据Bucket", "database", 1020, 60,
                       "存储桶【权限误配：公开读】")
        self._add_node("oss_obj", "数据对象(3000万画像)", "database", 1230, 210,
                       "人口画像数据对象")
        self._add_node("audit", "访问日志审计", "database", 1200, 60,
                       "日志审计能力（未开启）")
        self._add_node("ver_ctrl", "版本控制", "database", 1410, 210,
                       "版本控制能力（未开启）")
        self._add_node("ecs_app", "应用服务器", "server", 1380, 60,
                       "数据写入方")
        self._add_node("sec_center", "云安全中心", "server", 1590, 210,
                       "云上威胁检测")
        self._add_node("local_fw", "本地防火墙", "firewall", 1770, 210,
                       "医院本地边界")
        self._add_node("local_his", "本地HIS", "server", 1200, 360,
                       "本地核心业务")

        self._add_edge("attacker", "eip", "")
        self._add_edge("eip", "oss_bucket", "公开读入口")
        self._add_edge("oss_bucket", "oss_obj", "")
        self._add_edge("oss_bucket", "audit", "")
        self._add_edge("oss_bucket", "ver_ctrl", "")
        self._add_edge("ecs_app", "oss_bucket", "")
        self._add_edge("sec_center", "oss_bucket", "")
        self._add_edge("oss_bucket", "local_fw", "云地数据交换")
        self._add_edge("local_fw", "local_his", "")

    def _build_attacks(self):
        self._add_attack_step(
            "s1", "Bucket暴露侦察",
            "扫描发现人口数据Bucket权限误配为公开读，匿名可列目录",
            preconditions=[],
            effects=[{"target": "oss_bucket", "state": "target"}],
            detection="低", technique="Cloud Storage Object Discovery", mitre="T1619",
        )
        self._add_attack_step(
            "s2", "匿名读取探测",
            "匿名列出全部数据对象清单，确认无任何鉴权拦截",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "oss_obj", "state": "target"}],
            detection="中", technique="Data from Cloud Storage", mitre="T1530",
        )
        self._add_attack_step(
            "s3", "批量拖取",
            "脚本批量下载数据对象，访问日志审计未开启，全程无告警",
            preconditions=[{"type": "step_completed", "step": "s2"}],
            effects=[{"target": "oss_obj", "state": "compromised"}],
            detection="中", technique="Data from Cloud Storage", mitre="T1530",
        )
        self._add_attack_step(
            "s4", "3000万画像外流",
            "数据对象全部外流至攻击者侧存储",
            preconditions=[{"type": "node_compromised", "node": "oss_obj"}],
            effects=[{"target": "oss_obj", "state": "exfiltrated"}],
            detection="高", technique="Exfiltration Over Web Service", mitre="T1567",
        )
        self._add_attack_step(
            "s5", "覆盖破坏",
            "删除原对象并覆盖为勒索信——版本控制未开启，数据无法追回",
            preconditions=[{"type": "step_completed", "step": "s4"}],
            effects=[{"target": "oss_obj", "state": "encrypted"}],
            detection="高", technique="Data Destruction", mitre="T1485",
        )
        self._add_attack_step(
            "s6", "凭据提取横向",
            "从Bucket配置文件提取泄漏的AK/SK，横向登录应用服务器",
            preconditions=[{"type": "step_completed", "step": "s3"}],
            effects=[{"target": "ecs_app", "state": "compromised"}],
            detection="中", technique="Unsecured Credentials", mitre="T1552",
        )
        self._add_attack_step(
            "s7", "云地联动扩散",
            "利用云上立足点经云地数据交换链路攻本地HIS",
            preconditions=[{"type": "node_compromised", "node": "ecs_app"}],
            effects=[{"target": "local_his", "state": "compromised"}],
            detection="中", technique="Remote Services", mitre="T1021",
        )

    def _build_defenses(self):
        self._add_defense(
            "d1", "Bucket ACL收紧",
            "Bucket默认私有，仅授权应用与角色可访问，关闭公开读",
            blocks=["s2"], cost="低", category="云上配置",
        )
        self._add_defense(
            "d2", "访问日志审计+下载告警",
            "开启日志审计，异常批量下载实时告警",
            blocks=["s3"], cost="低", category="云上检测",
        )
        self._add_defense(
            "d3", "敏感数据加密",
            "对象存储服务端加密+密钥托管",
            blocks=["s4"], cost="中", category="数据安全",
        )
        self._add_defense(
            "d4", "版本控制+MFA删除",
            "开启版本控制与MFA删除保护，覆盖可回滚",
            blocks=["s5"], cost="低", category="云上配置",
        )
        self._add_defense(
            "d5", "AK/SK最小权限+轮换",
            "访问密钥最小权限化+定期轮换+异常调用告警",
            blocks=["s6"], cost="低", category="访问控制",
        )

    def _build_remediations(self):
        """增量整改候选措施（2026-09-06）：针对现状防护全开仍存在的薄弱环节设计，
        仅整改推演轮2生效，不进入现状防护。"""
        self._add_remediation(
            "r1", "云配置合规扫描",
            "部署云配置合规扫描，Bucket暴露配置即自动发现并告警",
            covers=['s1'], cost="低", category="云上配置",
            root_cause="Bucket暴露侦察无感知，配置风险靠人工排查", trap=True,
        )
        self._add_remediation(
            "r2", "云地联动封堵",
            "建立云地联动封堵机制，云侧泄露事件即联动本地封堵扩散",
            covers=['s7'], cost="中", category="云地联动",
            root_cause="云地联动扩散步骤现状无防护覆盖，属盲区", trap=False,
        )
        self._add_remediation(
            "r3", "下载速率异常限流",
            "对Bucket下载设置速率阈值与批量下载限流告警",
            covers=['s3'], cost="低", category="云上检测",
            root_cause="批量拖取依赖日志审计单道防护", trap=False,
        )
