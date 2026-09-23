"""Scenario: 云地横向移动 — 本地渗透经VPN通道入云扩散（医院云网攻防场景库场景3）。

证据来源：
1. 医院云网攻防场景库.md（L3蒸馏）：云地横向移动场景——本地内网被渗透→
   经VPN通道进VPC→云上横向扩散→云地联合封堵；
2. 关键结论：云安全中心+本地IDS/IPS需日志联动，否则形成检测盲区；
   云上"安全组"等价本地"防火墙策略"，但粒度更细（实例级）。
3. 评估报告（KB-03-0196）：江北16台服务器与医保终端互联、内部防火墙唯一边界
   （本地弱侧入口的现实依据）。
"""
from ..engine.scenario_base import ScenarioBase


class CloudGroundLateralScenario(ScenarioBase):
    SCENARIO_ID = "cloud_ground_lateral"
    SCENARIO_NAME = "云地横向移动：本地渗透经VPN入云扩散"
    SCENARIO_DESC = ("本地内网弱侧被渗透后经VPN通道入云（云地双面攻防面），"
                     "推演云内无微隔离横向扩散至人口系统、数据外泄、反向回攻本地")
    SCENARIO_CATEGORY = "攻防对抗层"
    SCENARIO_DIFFICULTY = "高级"
    SCENARIO_TAGS = ["云地联动", "VPN通道", "横向移动", "检测盲区", "云攻防"]
    DEMOTED_DEFENSES = ["d1", "d2", "d3", "d4"]

    def __init__(self):
        super().__init__()
        self._build_topology()
        self._build_attacks()
        self._build_defenses()
        self._build_remediations()
        self._apply_demotions()

    def _build_topology(self):
        self._add_node("attacker", "攻击者", "external", 800, 260,
                       "外部攻击源")
        self._add_node("pc_local", "本地受控终端", "workstation", 1200, 260,
                       "本地内网已沦陷终端（场景假设入口，见desc）")
        self._add_node("local_fw", "本地防火墙", "firewall", 1600, 260,
                       "医院本地边界")
        self._add_node("vpn_gw", "VPN网关", "network", 800, 60,
                       "云地通道入口（运维弱口令习惯，P0-1人为因素）", awareness="低")
        self._add_node("vpc", "VPC云网络", "network", 800, 460,
                       "云上网络")
        self._add_node("cloud_a", "云主机A", "server", 1400, 60,
                       "云上业务主机")
        self._add_node("cloud_b", "云主机B", "server", 2000, 260,
                       "云上业务主机")
        self._add_node("pop_ecs", "人口系统ECS", "server", 1400, 460,
                       "3000万人口数据入口")
        self._add_node("pop_db", "人口数据库", "database", 800, 660,
                       "3000万人口数据")
        self._add_node("sec_center", "云安全中心", "server", 2000, 60,
                       "云上威胁检测")
        self._add_node("local_his", "本地HIS", "server", 2000, 460,
                       "本地核心业务")

        self._add_edge("attacker", "pc_local", "已沦陷入口")
        self._add_edge("pc_local", "local_fw", "")
        self._add_edge("local_fw", "vpn_gw", "VPN通道")
        self._add_edge("vpn_gw", "vpc", "")
        self._add_edge("vpc", "cloud_a", "")
        self._add_edge("vpc", "cloud_b", "")
        self._add_edge("vpc", "pop_ecs", "")
        self._add_edge("pop_ecs", "pop_db", "")
        self._add_edge("sec_center", "vpc", "")
        self._add_edge("local_fw", "local_his", "")

    def _build_attacks(self):
        self._add_attack_step(
            "s1", "云地链路侦察",
            "从本地受控终端识别VPN通道与云内拓扑，确认云地双面攻防面",
            preconditions=[],
            effects=[{"target": "vpn_gw", "state": "target"}],
            detection="低", technique="Cloud Infrastructure Discovery", mitre="T1580",
        )
        self._add_attack_step(
            "s2", "VPN弱凭据接入",
            "利用VPN弱口令/无双因子接入云上VPC",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "vpn_gw", "state": "compromised"}],
            detection="中", technique="Valid Accounts", mitre="T1078",
        )
        self._add_attack_step(
            "s3", "入云扩散",
            "进入VPC后横向至云主机A/B——云内无微隔离，横向畅通",
            preconditions=[{"type": "node_compromised", "node": "vpn_gw"}],
            effects=[{"target": "cloud_a", "state": "compromised"},
                     {"target": "cloud_b", "state": "compromised"}],
            detection="中", technique="Remote Services", mitre="T1021",
        )
        self._add_attack_step(
            "s4", "人口系统渗透",
            "从云主机横向至人口系统ECS",
            preconditions=[{"type": "node_compromised", "node": "cloud_a"}],
            effects=[{"target": "pop_ecs", "state": "compromised"}],
            detection="中", technique="Remote Services", mitre="T1021",
        )
        self._add_attack_step(
            "s5", "数据库攻陷",
            "ECS提权直连人口数据库",
            preconditions=[{"type": "node_compromised", "node": "pop_ecs"}],
            effects=[{"target": "pop_db", "state": "compromised"}],
            detection="低", technique="Exploitation for Privilege Escalation", mitre="T1068",
        )
        self._add_attack_step(
            "s6", "人口数据外泄",
            "3000万人口数据经VPN通道回传（云地日志未联动，检测盲区）",
            preconditions=[{"type": "node_compromised", "node": "pop_db"}],
            effects=[{"target": "pop_db", "state": "exfiltrated"}],
            detection="高", technique="Exfiltration Over Alternative Protocol", mitre="T1048",
        )
        self._add_attack_step(
            "s7", "反向回攻本地",
            "以云为跳板反向渗透本地HIS——云地双向通道成为双向攻击面",
            preconditions=[{"type": "node_compromised", "node": "pop_ecs"}],
            effects=[{"target": "local_his", "state": "compromised"}],
            detection="中", technique="Remote Services", mitre="T1021",
        )

    def _build_defenses(self):
        self._add_defense(
            "d1", "VPN双因子+最小权限",
            "VPN接入双因子认证+最小权限，仅授权运维网段可入",
            blocks=["s2"], cost="低", category="访问控制",
        )
        self._add_defense(
            "d2", "VPC内微隔离",
            "安全组实例级隔离，云主机间横向阻断",
            blocks=["s3"], cost="中", category="云上隔离",
        )
        self._add_defense(
            "d3", "云地联动告警",
            "云安全中心与本地IDS/IPS日志联动，消除检测盲区",
            blocks=["s4"], cost="中", category="云地联动",
        )
        self._add_defense(
            "d4", "人口区独立VPC+白名单",
            "人口系统独立VPC，访问白名单化",
            blocks=["s5"], cost="中", category="云上隔离",
        )
        self._add_defense(
            "d5", "云地联合封堵",
            "检测到异常后云端+本地联合阻断通道、封禁源",
            blocks=["s7"], cost="中", category="云地联动",
        )

    def _build_remediations(self):
        """增量整改候选措施（2026-09-06）：针对现状防护全开仍存在的薄弱环节设计，
        仅整改推演轮2生效，不进入现状防护。"""
        self._add_remediation(
            "r1", "云蜜罐诱捕链路侦察",
            "云地链路旁路部署蜜罐，链路侦察即被诱捕",
            covers=['s1'], cost="低", category="云上检测",
            root_cause="云地链路侦察无感知", trap=True,
        )
        self._add_remediation(
            "r2", "DLP人口数据外泄阻断",
            "人口数据区出口部署DLP，数据外泄实时识别阻断",
            covers=['s6'], cost="高", category="数据安全",
            root_cause="人口数据外泄步骤现状无防护覆盖，属盲区", trap=False,
        )
        self._add_remediation(
            "r3", "VPN行为分析",
            "VPN接入升级行为分析，弱凭据接入与异常登录二次校验",
            covers=['s2'], cost="中", category="访问控制",
            root_cause="VPN接入防护依赖双因子单道校验", trap=False,
        )
