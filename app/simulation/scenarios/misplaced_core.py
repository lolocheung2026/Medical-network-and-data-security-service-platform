"""Scenario: 错配的核心 — 上网行为管理设备充当核心交换机（评估报告 P0-1）。

证据来源：研究院IT基础设施安全评估报告（KB-03-0196）P0-1 发现：
渝北"核心交换机"实为深信服 AC-1000-SK1300-FP 上网行为管理设备，角色错配；
旧核心新华三 S5800 已停用，核心交换能力存在真空。
链路依据逻辑拓扑图 v3（KB-03-0194，2026-07-28 现场核实修正版）。
"""
from ..engine.scenario_base import ScenarioBase


class MisplacedCoreScenario(ScenarioBase):
    SCENARIO_ID = "misplaced_core"
    SCENARIO_NAME = "错配的核心：AC上网行为管理充当核心交换机"
    SCENARIO_DESC = ("渝北院区6F'核心'实为深信服AC上网行为管理设备（P0-1实测），"
                     "推演攻击者利用角色错配引发的性能、管理与隔离三重缺陷瘫痪全院")
    SCENARIO_CATEGORY = "攻防对抗层"
    SCENARIO_DIFFICULTY = "高级"
    SCENARIO_TAGS = ["角色错配", "核心交换", "P0发现", "真实拓扑", "渝北院区"]
    DEMOTED_DEFENSES = ["d1", "d2", "d3"]

    def __init__(self):
        super().__init__()
        self._build_topology()
        self._build_attacks()
        self._build_defenses()
        self._build_remediations()
        self._apply_demotions()

    def _build_topology(self):
        # 真实链路（逻辑拓扑图v3实证）:
        # 卫生专网/政务外网→光端机→4F AC认证切换→1楼对面机房串链(AF→IPS→WAF→AC-A400)→6F AC"核心"→汇聚→接入→终端
        # 401机房服务器群挂 AF-1120 之下
        self._add_node("internet", "攻击者", "external", 800, 460,
                       "外部攻击源（经政务外网/卫生专网入口）")
        self._add_node("optic", "光端机", "network", 1040, 460,
                       "专网光端机（台账漏登项A1，拓扑图有）")
        self._add_node("ac4f", "4F AC-1000SK1300", "firewall", 800, 60,
                       "内外网切换/上网认证（P0-2已核实具备逻辑隔离）")
        self._add_node("af", "AF防火墙", "firewall", 1280, 460,
                       "1楼对面机房（AF/IPS/WAF/AC-A400串链）")
        self._add_node("ips", "IPS", "firewall", 800, 260,
                       "1楼对面机房")
        self._add_node("waf", "WAF", "firewall", 1760, 460,
                       "1楼对面机房")
        self._add_node("ac_a400", "AC-1000-A400", "firewall", 1400, 260,
                       "1楼对面机房上网行为管理")
        self._add_node("core6f", "6F AC-SK1300-FP", "network", 1200, 60,
                       "【错配】上网行为管理充当核心交换机，无核心交换引擎（P0-1）")
        self._add_node("agg4f", "4F汇聚 S5700S", "network", 1600, 60,
                       "汇聚交换机")
        self._add_node("acc1", "楼层接入 S5048PV2", "network", 2000, 60,
                       "3/5/8楼弱电井接入")
        self._add_node("pc", "业务终端", "workstation", 2000, 260,
                       "临床/行政终端")
        self._add_node("fw1120", "AF-1120防火墙", "firewall", 2000, 460,
                       "401机房服务器区边界")
        self._add_node("his", "HIS服务器", "server", 1520, 460,
                       "华为2288H（401机房）")
        self._add_node("pacs", "PACS服务器", "server", 2000, 660,
                       "影像系统（401机房）")
        self._add_node("backup", "备份存储", "database", 800, 660,
                       "灾备系统")

        # 边界链路（专网入口 → 串链）
        self._add_edge("internet", "optic", "卫生专网/政务外网")
        self._add_edge("optic", "ac4f", "")
        self._add_edge("ac4f", "af", "")
        self._add_edge("af", "ips", "")
        self._add_edge("ips", "waf", "")
        self._add_edge("waf", "ac_a400", "")
        self._add_edge("ac_a400", "core6f", "上联'核心'")
        # 核心 → 汇聚 → 接入 → 终端
        self._add_edge("core6f", "agg4f", "")
        self._add_edge("agg4f", "acc1", "")
        self._add_edge("acc1", "pc", "")
        # 服务器区
        self._add_edge("core6f", "fw1120", "服务器区上联")
        self._add_edge("fw1120", "his", "")
        self._add_edge("fw1120", "pacs", "")
        self._add_edge("his", "backup", "")
        self._add_edge("pacs", "backup", "")

    def _build_attacks(self):
        self._add_attack_step(
            "s1", "设备指纹识别",
            "攻击者探测6F'核心'，识别出AC-1000-SK1300-FP实为上网行为管理设备"
            "（无交换引擎、CPU软件转发），确认角色错配可被利用",
            preconditions=[],
            effects=[{"target": "core6f", "state": "target"}],
            detection="低", technique="Gather Victim Network Information", mitre="T1590",
        )
        self._add_attack_step(
            "s2", "性能耗尽攻击",
            "利用AC软件转发缺陷发起大流量泛洪：核心CPU处理全部东西向流量，"
            "正常业务+攻击流量叠加即挤占CPU，全网转发拥塞",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "core6f", "state": "compromised"}],
            detection="中", technique="Endpoint Denial of Service", mitre="T1499",
        )
        self._add_attack_step(
            "s3", "管理面弱口令爆破",
            "扫描AC管理接口（Web/SSH），利用弱口令与无源IP限制爆破取得管理权限",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "ac4f", "state": "compromised"}],
            detection="中", technique="Brute Force", mitre="T1110",
        )
        self._add_attack_step(
            "s4", "安全策略篡改",
            "取得AC管理权限后关闭上网审计与访问控制策略，"
            "AC从'认证闸门'变为'透明通道'，内网东西向访问失控",
            preconditions=[{"type": "node_compromised", "node": "ac4f"}],
            effects=[{"target": "agg4f", "state": "compromised"}],
            detection="高", technique="Modify Cloud Compute Infrastructure", mitre="T1578",
        )
        self._add_attack_step(
            "s5", "横向移动至服务器区",
            "核心无交换级VLAN/ACL隔离矩阵，攻击者经汇聚直通401机房服务器区，"
            "攻陷HIS与PACS",
            preconditions=[{"type": "node_compromised", "node": "core6f"}],
            effects=[{"target": "his", "state": "compromised"},
                     {"target": "pacs", "state": "compromised"}],
            detection="中", technique="Remote Services", mitre="T1021",
        )
        self._add_attack_step(
            "s6", "患者数据外泄",
            "压缩HIS患者数据经外联通道回传C2（核心无出口审计能力兜底）",
            preconditions=[{"type": "node_compromised", "node": "his"}],
            effects=[{"target": "his", "state": "exfiltrated"}],
            detection="高", technique="Exfiltration Over Alternative Protocol", mitre="T1048",
        )
        self._add_attack_step(
            "s7", "全院业务中断",
            "核心转发拥塞叠加策略失效，HIS/PACS/终端全部不可达，"
            "门诊业务停摆（旧核心S5800已停用，无冗余核心可切换）",
            preconditions=[{"type": "node_compromised", "node": "core6f"}],
            effects=[{"target": "pc", "state": "isolated"},
                     {"target": "his", "state": "isolated"},
                     {"target": "pacs", "state": "isolated"}],
            detection="高", technique="Network Denial of Service", mitre="T1498",
        )

    def _build_defenses(self):
        self._add_defense(
            "d1", "恢复真核心交换机",
            "部署/启用真三层核心（硬件转发），AC归还出口本职，"
            "消除软件转发性能瓶颈（对应评估报告P0-1整改）",
            blocks=["s2"], cost="高", category="架构整改",
        )
        self._add_defense(
            "d2", "AC管理面加固",
            "管理接口限源IP+强口令+双因子+独立管理VLAN",
            blocks=["s3"], cost="低", category="访问控制",
        )
        self._add_defense(
            "d3", "核心VLAN/ACL隔离矩阵",
            "核心层按业务域划VLAN+ACL最小权限，阻断服务器区横向直通",
            blocks=["s5"], cost="中", category="网络防护",
        )
        self._add_defense(
            "d4", "配置篡改监控",
            "核心设备配置变更审计+SNMP性能阈值告警，篡改即发现",
            blocks=["s4"], cost="中", category="监控审计",
        )
        self._add_defense(
            "d5", "核心双活冗余",
            "核心层双机热备（VGMP）或链路冗余，单点失效自动接管",
            blocks=["s7"], cost="高", category="高可用",
        )

    def _build_remediations(self):
        """增量整改候选措施（2026-09-06）：针对现状防护全开仍存在的薄弱环节设计，
        仅整改推演轮2生效，不进入现状防护。"""
        self._add_remediation(
            "r1", "蜜罐诱捕指纹识别",
            "核心区旁路部署蜜罐，攻击者设备指纹识别即被诱捕告警",
            covers=['s1'], cost="低", category="监控审计",
            root_cause="攻击者对核心设备指纹识别无感知", trap=True,
        )
        self._add_remediation(
            "r2", "DLP患者数据外泄阻断",
            "核心区出口部署DLP，患者数据外泄实时识别阻断",
            covers=['s6'], cost="高", category="数据安全",
            root_cause="患者数据外泄步骤现状无防护覆盖，属盲区", trap=False,
        )
        self._add_remediation(
            "r3", "全网流量可视化",
            "部署流量可视化平台，横向移动行为基于基线实时告警",
            covers=['s5'], cost="中", category="监控审计",
            root_cause="横向移动检测依赖静态ACL矩阵，缺流量行为分析", trap=False,
        )
