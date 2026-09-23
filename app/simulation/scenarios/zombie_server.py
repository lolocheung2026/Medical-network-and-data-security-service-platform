"""Scenario: 僵尸服务器复活 — 关停不彻底的隐性资产（账实不符 A3 + P1）。

证据来源：研究院IT基础设施安全评估报告（KB-03-0196）：
1. 账实不符 A3：5台服务器"关了"但仍带电在柜；
2. 台账：新华三 S5800 旧核心标注"停用"，但仍在网带电；
3. P1：全网无统一日志审计，僵尸设备活动无监控。
推演：被遗忘的带电资产被入侵者唤醒——旧漏洞、残留数据、旧凭据三重风险叠加。
"""
from ..engine.scenario_base import ScenarioBase


class ZombieServerScenario(ScenarioBase):
    SCENARIO_ID = "zombie_server"
    SCENARIO_NAME = "僵尸服务器复活：关停不彻底的隐性资产"
    SCENARIO_DESC = ("5台'已关停'服务器与停用旧核心S5800实际带电在柜（账实不符A3），"
                     "推演入侵者唤醒僵尸资产：旧漏洞拿下→残留数据/旧凭据提取→绕过审计横向→灾备污染")
    SCENARIO_CATEGORY = "攻防对抗层"
    SCENARIO_DIFFICULTY = "高级"
    SCENARIO_TAGS = ["僵尸资产", "账实不符", "残留数据", "审计盲区"]
    DEMOTED_DEFENSES = ["d1", "d2", "d4"]

    def __init__(self):
        super().__init__()
        self._build_topology()
        self._build_attacks()
        self._build_defenses()
        self._build_remediations()
        self._apply_demotions()

    def _build_topology(self):
        self._add_node("internet", "攻击者", "external", 960, 210,
                       "外部攻击源（含内鬼路径）")
        self._add_node("firewall", "边界防火墙", "firewall", 1140, 210,
                       "网络边界")
        self._add_node("core", "核心层", "network", 1320, 210,
                       "核心转发区")
        self._add_node("zombie1", "关停服务器×5(带电)", "server", 1020, 360,
                       "台账标注'关了'实际带电在柜（A3），无监控无补丁")
        self._add_node("zombie2", "旧核心S5800(停用)", "network", 1110, 60,
                       "台账标注'停用'仍在网带电，旧网段残留")
        self._add_node("old_seg", "旧网段/旧链路", "network", 1200, 360,
                       "僵尸设备仍挂接的遗留链路")
        self._add_node("prod_his", "HIS服务器", "server", 1290, 60,
                       "生产核心（口令多年未轮换，P0-1人为因素）", awareness="低")
        self._add_node("prod_emr", "EMR服务器", "server", 1500, 210,
                       "生产电子病历")
        self._add_node("backup", "备份系统", "database", 1380, 360,
                       "灾备中心")
        self._add_node("ops_pc", "运维终端", "workstation", 1680, 210,
                       "运维入口")

        self._add_edge("internet", "firewall", "")
        self._add_edge("firewall", "core", "")
        self._add_edge("core", "zombie1", "带电在柜(无监控)")
        self._add_edge("core", "zombie2", "停用但带电")
        self._add_edge("zombie1", "old_seg", "旧链路残留")
        self._add_edge("zombie2", "old_seg", "旧网段")
        self._add_edge("core", "prod_his", "")
        self._add_edge("core", "prod_emr", "")
        self._add_edge("core", "backup", "")
        self._add_edge("old_seg", "backup", "旧链路可达")
        self._add_edge("prod_his", "ops_pc", "")
        self._add_edge("backup", "ops_pc", "")

    def _build_attacks(self):
        self._add_attack_step(
            "s1", "僵尸资产发现",
            "扫描发现台账标注'已关停'的5台服务器与'停用'旧核心S5800实际带电在线，"
            "且不在任何监控与审计范围（P1：无统一日志审计）",
            preconditions=[],
            effects=[{"target": "zombie1", "state": "target"}],
            detection="低", technique="Network Service Discovery", mitre="T1046",
        )
        self._add_attack_step(
            "s2", "旧漏洞利用",
            "僵尸服务器长期无人维护、补丁停滞，利用旧系统/EOL组件漏洞直接拿下",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "zombie1", "state": "compromised"}],
            detection="低", technique="Exploit Public-Facing Application", mitre="T1190",
        )
        self._add_attack_step(
            "s3", "残留数据与配置提取",
            "盘上残留历史患者数据、旧配置文件、数据库口令与SNMP共同体串",
            preconditions=[{"type": "node_compromised", "node": "zombie1"}],
            effects=[{"target": "zombie2", "state": "compromised"}],
            detection="低", technique="Data from Local System", mitre="T1005",
        )
        self._add_attack_step(
            "s4", "旧凭据复用",
            "用残留配置中的旧凭据尝试登录生产系统——口令多年未轮换，直接命中HIS",
            preconditions=[{"type": "node_compromised", "node": "zombie2"}],
            effects=[{"target": "prod_his", "state": "compromised"}],
            detection="中", technique="Valid Accounts", mitre="T1078",
        )
        self._add_attack_step(
            "s5", "僵尸作跳板横向",
            "沿旧网段残留链路横向至备份系统，全程无日志审计无告警",
            preconditions=[{"type": "node_compromised", "node": "zombie1"}],
            effects=[{"target": "backup", "state": "compromised"}],
            detection="低", technique="Remote Services", mitre="T1021",
        )
        self._add_attack_step(
            "s6", "备份污染",
            "篡改/加密备份数据，灾备能力静默失效",
            preconditions=[{"type": "node_compromised", "node": "backup"}],
            effects=[{"target": "backup", "state": "encrypted"}],
            detection="高", technique="Data Manipulation", mitre="T1565",
        )
        self._add_attack_step(
            "s7", "生产加密勒索",
            "灾备已失效，加密生产系统后无恢复路径",
            preconditions=[{"type": "step_completed", "step": "s6"}],
            effects=[{"target": "prod_emr", "state": "encrypted"},
                     {"target": "prod_his", "state": "encrypted"}],
            detection="高", technique="Data Encrypted for Impact", mitre="T1486",
        )

    def _build_defenses(self):
        self._add_defense(
            "d1", "关停彻底化",
            "关停即下电+清数据+台账注销，消除带电僵尸资产",
            blocks=["s2"], cost="低", category="资产管理",
        )
        self._add_defense(
            "d2", "残留数据清除",
            "退役设备磁盘销毁/格式化，旧网段链路拆除",
            blocks=["s3"], cost="低", category="数据安全",
        )
        self._add_defense(
            "d3", "凭据全面轮换",
            "生产口令/SNMP共同体串全面轮换，旧凭据作废",
            blocks=["s4"], cost="低", category="访问控制",
        )
        self._add_defense(
            "d4", "网络微隔离+审计",
            "旧网段隔离拆除，全网日志审计+异常访问告警",
            blocks=["s5"], cost="中", category="监控审计",
        )
        self._add_defense(
            "d5", "不可变备份",
            "备份存储不可变+异质副本，防止篡改污染",
            blocks=["s6"], cost="高", category="灾备恢复",
        )

    def _build_remediations(self):
        """增量整改候选措施（2026-09-06）：针对现状防护全开仍存在的薄弱环节设计，
        仅整改推演轮2生效，不进入现状防护。"""
        self._add_remediation(
            "r1", "蜜罐+资产存活测绘",
            "部署蜜罐与资产存活探测，僵尸资产被发现时同时诱捕攻击者",
            covers=['s1'], cost="低", category="监控审计",
            root_cause="僵尸资产无人知晓，攻击者可静默控制", trap=True,
        )
        self._add_remediation(
            "r2", "备份完整性验证+勒索防护",
            "部署备份完整性自动验证与勒索行为检测，堵住备份污染与生产加密",
            covers=['s7'], cost="高", category="灾备恢复",
            root_cause="生产加密勒索步骤现状无防护覆盖，属盲区", trap=False,
        )
        self._add_remediation(
            "r3", "僵尸资产自动发现机制",
            "建立资产定期存活扫描与下线审批流程，僵尸资产动态清零",
            covers=['s2'], cost="低", category="资产管理",
            root_cause="旧漏洞利用依赖关停执行，缺自动发现长效机制", trap=False,
        )
