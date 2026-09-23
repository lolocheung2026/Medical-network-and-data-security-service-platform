"""Scenario: 无备的核心 — 核心单点故障与双机热备（优化建议一梯 P0-2）。

证据来源：
- KB-03-0196 安全评估报告 P0-1：渝北"核心交换机"实为深信服 AC-1000-SK1300-FP
  行为管理设备；旧核心新华三 S5800 已停用，全网核心无冗余，宕机=全院断网。
- HCIP 模块 07 双机热备（KB-03-0203 知识地图）：USG 主备/负载分担、hrp enable/VGMP、
  display hrp state（华为标准双机热备方案）。
- 损失量化：datalib_params 医疗行业泄露成本基准（IBM 2025/2026 口径）。

与 misplaced_core（角色错配性能缺陷）的差异：本场景聚焦「单点架构」——即使核心
功能正常，单台设备故障/被击穿即全院中断，防御主题为双机热备与链路冗余。
"""
from ..engine.scenario_base import ScenarioBase


class HotStandbyScenario(ScenarioBase):
    SCENARIO_ID = "hot_standby"
    SCENARIO_NAME = "无备的核心：单点故障致全院断网与双机热备"
    SCENARIO_DESC = ("渝北核心交换能力由单台设备承载（评估报告 P0-1 实测），旧核心 S5800 停用无冗余。"
                     "推演攻击者瘫痪核心后利用断网窗口实施数据窃取，"
                     "对比「无热备 vs 双机热备（VGMP 主备）」的后果差异")
    SCENARIO_CATEGORY = "攻防对抗层"
    SCENARIO_DIFFICULTY = "高级"
    SCENARIO_TAGS = ["单点故障", "双机热备", "高可用", "P0-1风险", "渝北院区", "真实拓扑"]
    DEMOTED_DEFENSES = ["d1", "d2", "d3"]

    def __init__(self):
        super().__init__()
        self._build_topology()
        self._build_attacks()
        self._build_defenses()
        self._build_remediations()
        self._apply_demotions()

    def _build_topology(self):
        # 渝北真实链路（KB-03-0194 逻辑拓扑 v3）：专网→光端机→4F AC→边界串链→6F核心→汇聚→接入→终端
        self._add_node("internet", "攻击者", "external", 800, 260,
                       "外部攻击源（经政务外网/卫生专网入口）")
        self._add_node("optic", "光端机", "network", 1280, 260,
                       "专网光端机（台账漏登项 A1）")
        self._add_node("ac4f", "4F AC-1000SK1300", "firewall", 800, 60,
                       "内外网切换/上网认证（P0-2 已核实具备逻辑隔离）")
        self._add_node("boundary", "边界串链 AF/IPS/WAF", "firewall", 1520, 260,
                       "1楼对面机房四层纵深（AF→IPS→WAF→AC-A400）")
        self._add_node("core", "6F 核心（单点）", "network", 1760, 260,
                       "【单点】核心转发仅此一台，旧核心 S5800 已停用（P0-1）")
        self._add_node("agg", "4F 汇聚 S5700S", "network", 2000, 260,
                       "汇聚交换机")
        self._add_node("acc", "楼层接入 S5048PV2", "network", 1040, 260,
                       "3/5/8 楼弱电井接入")
        self._add_node("pc", "业务终端", "workstation", 2000, 60,
                       "临床/行政终端")
        self._add_node("fw401", "AF-1120 防火墙", "firewall", 800, 460,
                       "401 机房服务器区边界")
        self._add_node("his", "HIS 服务器", "server", 2000, 460,
                       "华为 2288H（401 机房）")
        self._add_node("pacs", "PACS 服务器", "server", 1400, 460,
                       "影像系统（401 机房）")
        self._add_node("backup", "备份存储", "database", 800, 660,
                       "灾备系统")

        self._add_edge("internet", "optic", "卫生专网/政务外网")
        self._add_edge("optic", "ac4f", "")
        self._add_edge("ac4f", "boundary", "")
        self._add_edge("boundary", "core", "上联核心")
        self._add_edge("core", "agg", "")
        self._add_edge("agg", "acc", "")
        self._add_edge("acc", "pc", "")
        self._add_edge("core", "fw401", "服务器区上联")
        self._add_edge("fw401", "his", "")
        self._add_edge("fw401", "pacs", "")
        self._add_edge("his", "backup", "")
        self._add_edge("pacs", "backup", "")

    def _build_attacks(self):
        self._add_attack_step(
            "s1", "架构侦察：确认单点核心",
            "攻击者探测核心区，确认转发集中在一台设备且无冗余心跳链路"
            "（旧核心已停用），锁定'打瘫核心=全院断网'的杠杆点",
            preconditions=[],
            effects=[{"target": "core", "state": "target"}],
            detection="低", technique="Gather Victim Network Information", mitre="T1590",
        )
        self._add_attack_step(
            "s2", "核心泛洪瘫痪",
            "对核心设备发起大流量攻击叠加畸形报文，CPU 过载转发失效，"
            "全院网络中断（无冗余设备可接管）",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "core", "state": "compromised"},
                     {"target": "pc", "state": "isolated"},
                     {"target": "his", "state": "isolated"},
                     {"target": "pacs", "state": "isolated"}],
            detection="高", technique="Network Denial of Service", mitre="T1498",
        )
        self._add_attack_step(
            "s3", "断网窗口混入管理通道",
            "利用断网导致的告警洪泛与运维忙乱，爆破核心管理接口，"
            "在故障处置窗口植入持久化后门",
            preconditions=[{"type": "node_compromised", "node": "core"}],
            effects=[{"target": "core", "state": "compromised"}],
            detection="中", technique="Brute Force", mitre="T1110",
        )
        self._add_attack_step(
            "s4", "恢复后横向移动",
            "核心恢复转发后，利用植入后门与窃取凭据横向移动至服务器区",
            preconditions=[{"type": "node_compromised", "node": "core"}],
            effects=[{"target": "his", "state": "compromised"},
                     {"target": "pacs", "state": "compromised"}],
            detection="中", technique="Remote Services", mitre="T1021",
        )
        self._add_attack_step(
            "s5", "患者数据批量外泄",
            "打包 HIS/PACS 数据经隐蔽隧道外传，"
            "核心无冗余期间出口审计亦受故障影响，检出延迟",
            preconditions=[{"type": "node_compromised", "node": "his"}],
            effects=[{"target": "his", "state": "exfiltrated"}],
            detection="高", technique="Exfiltration Over Alternative Protocol", mitre="T1048",
        )
        self._add_attack_step(
            "s6", "备份加密勒索",
            "加密备份存储，勒索赎金，无灾备可恢复",
            preconditions=[{"type": "node_compromised", "node": "pacs"}],
            effects=[{"target": "backup", "state": "encrypted"}],
            detection="中", technique="Data Encrypted for Impact", mitre="T1486",
        )
        self._add_attack_step(
            "s7", "二次瘫痪验证",
            "再次发起泛洪验证无自动接管能力，业务长时间不可用",
            preconditions=[{"type": "node_compromised", "node": "core"}],
            effects=[{"target": "pc", "state": "isolated"},
                     {"target": "agg", "state": "isolated"}],
            detection="高", technique="Endpoint Denial of Service", mitre="T1499",
        )

    def _build_defenses(self):
        self._add_defense(
            "d1", "核心双机热备（VGMP 主备）",
            "部署两台核心设备主备模式（hrp enable / hrp interface 心跳直连），"
            "主设备失效自动切换（华为 USG 双机热备标准方案，HCIP 模块 07）；"
            "切换后业务中断从小时级降至秒级",
            blocks=["s2", "s7"], cost="高", category="高可用",
        )
        self._add_defense(
            "d2", "核心管理面加固",
            "管理接口限源 IP + 强口令 + 双因子，阻断爆破",
            blocks=["s3"], cost="低", category="访问控制",
        )
        self._add_defense(
            "d3", "服务器区隔离与微隔离",
            "核心层 VLAN/ACL 按业务域最小权限，阻断横向直通 401 机房",
            blocks=["s4"], cost="中", category="网络防护",
        )
        self._add_defense(
            "d4", "出口外联管控",
            "外联白名单 + 流量审计，阻断隐蔽外传隧道",
            blocks=["s5"], cost="中", category="数据安全",
        )
        self._add_defense(
            "d5", "备份离线隔离",
            "备份定期离线/异介质留存，防勒索加密",
            blocks=["s6"], cost="低", category="灾备恢复",
        )

    def _build_remediations(self):
        """增量整改候选措施（2026-09-06）：针对现状防护全开仍存在的薄弱环节设计，
        仅整改推演轮2生效，不进入现状防护。"""
        self._add_remediation(
            "r1", "蜜罐诱捕架构侦察",
            "核心区旁路部署蜜罐，架构侦察即被诱捕告警",
            covers=['s1'], cost="低", category="监控审计",
            root_cause="攻击者对核心架构侦察无感知", trap=True,
        )
        self._add_remediation(
            "r2", "全链路流量加密",
            "核心业务流量全加密，患者数据批量外泄被阻断",
            covers=['s5'], cost="中", category="数据安全",
            root_cause="患者数据外泄仅靠出口管控单道防护", trap=False,
        )
        self._add_remediation(
            "r3", "核心异常流量清洗",
            "核心前置流量清洗设备，泛洪与异常流量自动清洗",
            covers=['s2'], cost="高", category="网络防护",
            root_cause="核心泛洪瘫痪依赖双机热备兜底，缺流量清洗纵深", trap=False,
        )
