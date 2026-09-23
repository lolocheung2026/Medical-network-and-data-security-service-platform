"""Scenario: 云主机入侵 — 云端人口系统ECS零防护（P0-4，医院云网攻防场景库场景1）。

证据来源：
1. 评估报告（KB-03-0196）P0-4：云端3000万人口数据无防护，为最高风险，
   处置建议含云等保套餐+白名单+审计+责任协议；
2. 医院云网攻防场景库.md（L3蒸馏）：云主机入侵场景——ECS被爆破→云安全中心告警
   →安全组封禁源IP→快照回滚。
对照：OA系统服务器三级等保+云WAF配套，人口系统无任何防护——数据分类分级严重倒挂。
"""
from ..engine.scenario_base import ScenarioBase


class CloudEcsBreachScenario(ScenarioBase):
    SCENARIO_ID = "cloud_ecs_breach"
    SCENARIO_NAME = "云主机入侵：人口系统ECS零防护"
    SCENARIO_DESC = ("云端3000万人口数据系统无任何防护（P0-4最高风险），对照OA三级等保，"
                     "推演零防护ECS被爆破→数据库被掏→勒索加密→云内横向→云地渗透")
    SCENARIO_CATEGORY = "攻防对抗层"
    SCENARIO_DIFFICULTY = "高级"
    SCENARIO_TAGS = ["云安全", "人口数据", "P0发现", "分类分级倒挂", "云攻防"]
    DEMOTED_DEFENSES = ["d1", "d2", "d4", "d5"]

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
                       "第三方云EIP/公网出口")
        self._add_node("pop_ecs", "人口系统ECS", "server", 1020, 60,
                       "3000万人口数据入口【无防护，P0-4】")
        self._add_node("pop_db", "人口数据库", "database", 1230, 210,
                       "3000万人口数据存储，无加密无审计")
        self._add_node("oa_ecs", "OA服务器", "server", 1200, 60,
                       "三级等保（对照）")
        self._add_node("oa_waf", "云WAF(仅OA配套)", "firewall", 1410, 210,
                       "安全设备仅OA配套，人口系统裸奔")
        self._add_node("sec_center", "云安全中心", "server", 1380, 60,
                       "威胁检测平台")
        self._add_node("vpn_gw", "VPN网关", "network", 1590, 210,
                       "云地通道")
        self._add_node("local_fw", "本地防火墙", "firewall", 1770, 210,
                       "医院本地边界")
        self._add_node("local_net", "本地内网", "network", 1200, 360,
                       "渝北/江北内网")

        self._add_edge("attacker", "eip", "")
        self._add_edge("eip", "pop_ecs", "公网暴露(无防护)")
        self._add_edge("eip", "oa_waf", "")
        self._add_edge("oa_waf", "oa_ecs", "有防护对照")
        self._add_edge("pop_ecs", "pop_db", "")
        self._add_edge("pop_ecs", "sec_center", "")
        self._add_edge("pop_ecs", "vpn_gw", "云地链路")
        self._add_edge("oa_ecs", "sec_center", "")
        self._add_edge("vpn_gw", "local_fw", "VPN通道")
        self._add_edge("local_fw", "local_net", "")

    def _build_attacks(self):
        self._add_attack_step(
            "s1", "云资产侦察",
            "扫描云上资产：人口系统ECS公网暴露且无WAF/安全组，"
            "对照OA有云WAF配套——分类分级严重倒挂被确认",
            preconditions=[],
            effects=[{"target": "pop_ecs", "state": "target"}],
            detection="低", technique="Cloud Service Discovery", mitre="T1526",
        )
        self._add_attack_step(
            "s2", "ECS弱口令爆破",
            "无防护入口被爆破拿下ECS（无云安全中心告警兜底）",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "pop_ecs", "state": "compromised"}],
            detection="中", technique="Brute Force", mitre="T1110",
        )
        self._add_attack_step(
            "s3", "数据库提权直连",
            "ECS提权后直连人口数据库——无白名单、无独立VPC隔离",
            preconditions=[{"type": "node_compromised", "node": "pop_ecs"}],
            effects=[{"target": "pop_db", "state": "compromised"}],
            detection="低", technique="Exploitation for Privilege Escalation", mitre="T1068",
        )
        self._add_attack_step(
            "s4", "3000万人口数据导出",
            "数据无加密无DLP审计，批量导出3000万人口数据",
            preconditions=[{"type": "node_compromised", "node": "pop_db"}],
            effects=[{"target": "pop_db", "state": "exfiltrated"}],
            detection="高", technique="Exfiltration Over Web Service", mitre="T1567",
        )
        self._add_attack_step(
            "s5", "勒索加密数据库",
            "无快照策略兜底，加密人口数据库投递勒索信",
            preconditions=[{"type": "step_completed", "step": "s4"}],
            effects=[{"target": "pop_db", "state": "encrypted"}],
            detection="高", technique="Data Encrypted for Impact", mitre="T1486",
        )
        self._add_attack_step(
            "s6", "云内横向至OA区",
            "云内隔离不足，从人口ECS横向至OA服务器区",
            preconditions=[{"type": "node_compromised", "node": "pop_ecs"}],
            effects=[{"target": "oa_ecs", "state": "compromised"}],
            detection="中", technique="Remote Services", mitre="T1021",
        )
        self._add_attack_step(
            "s7", "云地渗透",
            "沿VPN通道反向渗透本地内网",
            preconditions=[{"type": "node_compromised", "node": "pop_ecs"}],
            effects=[{"target": "local_net", "state": "compromised"}],
            detection="中", technique="Remote Services", mitre="T1021",
        )

    def _build_defenses(self):
        self._add_defense(
            "d1", "云安全中心威胁检测",
            "开启云安全中心，爆破/异常登录实时告警并联动封禁源IP",
            blocks=["s2"], cost="中", category="云上检测",
        )
        self._add_defense(
            "d2", "数据库独立VPC+白名单",
            "人口数据库独立VPC，仅允许应用服务器白名单访问",
            blocks=["s3"], cost="中", category="云上隔离",
        )
        self._add_defense(
            "d3", "敏感数据加密+DLP",
            "人口数据加密存储+出口DLP审计（P0-4处置建议）",
            blocks=["s4"], cost="高", category="数据安全",
        )
        self._add_defense(
            "d4", "云内微隔离",
            "安全组精细化，人口区与OA区实例级隔离",
            blocks=["s6"], cost="中", category="云上隔离",
        )
        self._add_defense(
            "d5", "VPN通道加固",
            "VPN双因子+最小权限+云地联动封堵",
            blocks=["s7"], cost="中", category="访问控制",
        )

    def _build_remediations(self):
        """增量整改候选措施（2026-09-06）：针对现状防护全开仍存在的薄弱环节设计，
        仅整改推演轮2生效，不进入现状防护。"""
        self._add_remediation(
            "r1", "云蜜罐诱捕侦察",
            "云VPC部署蜜罐ECS，云资产侦察即被诱捕",
            covers=['s1'], cost="低", category="云上检测",
            root_cause="云资产侦察无感知，缺欺骗防御", trap=True,
        )
        self._add_remediation(
            "r2", "不可变快照防勒索",
            "数据库启用不可变快照+异地容灾，勒索加密可即时恢复",
            covers=['s5'], cost="高", category="灾备恢复",
            root_cause="勒索加密数据库步骤现状无防护覆盖，属盲区", trap=False,
        )
        self._add_remediation(
            "r3", "云安全中心行为基线",
            "云安全中心升级行为基线分析，爆破与异常登录二次检测",
            covers=['s2'], cost="中", category="云上检测",
            root_cause="ECS爆破防护依赖单道威胁检测", trap=False,
        )
