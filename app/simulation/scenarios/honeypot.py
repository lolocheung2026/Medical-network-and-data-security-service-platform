"""Scenario: 蜜罐的陷阱 — 欺骗防御与蜜罐绕过概率（优化建议二梯 P0-1 修正版）。

证据来源：
- KB-03-0206 攻防演练场景库（L2 蒸馏）：渗透测试对抗 → 蜜罐诱捕条目，
  明确建议沙盘新增"IDS/IPS 检测对抗"与蜜罐维度。
- 主动防御论文：周成胜《基于生成式人工智能的网络安全主动防御技术》
  （蜜罐技术+PPDR）；扈红超《网络安全主动防御技术：策略、方法和挑战》
  （欺骗防御/诱骗系统）。
- 落地形态：内网低成本蜜罐变体（开源 honeypot 模拟 HIS 影子服务），
  匹配医院预算实际（蜜罐按需部署于服务器区旁路）。

【参数边界声明（批判性复审结论）】蜜罐 bypass_rate=0.35 为演示假设值：
业界无统一权威的"蜜罐绕过率"统计，该值基于蜜罐保真度不足可被识别的
经验设定（开源蜜罐指纹可识别），仅用于相对风险演示，非实测概率。
"""
from ..engine.scenario_base import ScenarioBase


class HoneypotScenario(ScenarioBase):
    SCENARIO_ID = "honeypot"
    SCENARIO_NAME = "蜜罐的陷阱：欺骗防御与绕过概率"
    SCENARIO_DESC = ("内网横向扫描遭遇欺骗防御（KB-03-0206 蜜罐诱捕条目），"
                     "推演攻击者踩蜜罐被诱捕 vs 识别指纹绕过，"
                     "验证蜜罐对侦察行为的检测增益与保真度风险")
    SCENARIO_CATEGORY = "攻防对抗层"
    SCENARIO_DIFFICULTY = "高级"
    SCENARIO_TAGS = ["蜜罐", "欺骗防御", "主动防御", "检测对抗", "绕过概率", "KB-03-0206"]
    DEMOTED_DEFENSES = ["d2", "d3", "d4"]

    def __init__(self):
        super().__init__()
        self._build_topology()
        self._build_attacks()
        self._build_defenses()
        self._build_remediations()
        self._apply_demotions()
        # P1-5 推演中决策点（CHESS 回合制思想）：蜜罐告警后的处置策略选择
        self.add_decision_point(
            "s4",
            "蜜罐触发诱捕告警，处置策略？",
            [
                {"id": "opt_block", "label": "立即阻断并溯源",
                 "description": "立即封禁攻击源 IP 并启动溯源，攻击链中断",
                 "block_steps": ["s4"],
                 "log": "攻击者被蜜罐诱捕后立即阻断，攻击链中断并进入溯源流程"},
                {"id": "opt_monitor", "label": "持续诱捕收集情报",
                 "description": "放行攻击者继续行动以收集 TTP 情报，但真实 HIS 面临风险",
                 "block_steps": ["s5"],
                 "log": "高交互监视模式：放行蜜罐交互收集情报，在攻击者触达真实 HIS 前切断"},
            ],
        )

    def _build_topology(self):
        self._add_node("internet", "攻击者", "external", 960, 210,
                       "外部攻击源（经卫生专网入口渗透）")
        self._add_node("edge", "边界防火墙", "firewall", 1140, 210,
                       "边界访问控制")
        self._add_node("dmz", "DMZ 服务区", "server", 1110, 60,
                       "对外服务（门户/预约）")
        self._add_node("jump", "办公终端（跳板）", "workstation", 1105, 360,
                       "内网办公终端，弱口令防护不足")
        self._add_node("core", "核心交换机", "network", 1320, 210,
                       "内网核心")
        self._add_node("honeypot", "蜜罐节点（HIS 影子）", "server", 1295, 360,
                       "开源 honeypot 模拟 HIS 服务，旁路部署诱捕横向扫描")
        self._add_node("his", "HIS 服务器（真）", "server", 1500, 210,
                       "真实 HIS（华为 2288H）")
        self._add_node("db", "HIS 数据库", "database", 1680, 210,
                       "患者诊疗数据")
        self._add_node("monitor", "安全监控平台", "network", 1290, 60,
                       "SIEM/告警汇聚（蜜罐告警接入点）")

        self._add_edge("internet", "edge", "卫生专网")
        self._add_edge("edge", "dmz", "")
        self._add_edge("edge", "jump", "办公区")
        self._add_edge("jump", "core", "")
        self._add_edge("dmz", "core", "")
        self._add_edge("core", "his", "")
        self._add_edge("core", "honeypot", "旁路诱捕")
        self._add_edge("his", "db", "")
        self._add_edge("honeypot", "monitor", "告警联动")
        self._add_edge("his", "monitor", "")

    def _build_attacks(self):
        self._add_attack_step(
            "s1", "内网入口侦察",
            "扫描边界暴露面，锁定办公终端弱口令入口",
            preconditions=[],
            effects=[{"target": "jump", "state": "target"}],
            detection="低", technique="Active Scanning", mitre="T1595",
        )
        self._add_attack_step(
            "s2", "爆破办公终端",
            "对办公终端 SSH/RDP 弱口令爆破，取得立足点",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "jump", "state": "compromised"}],
            detection="中", technique="Brute Force", mitre="T1110",
        )
        self._add_attack_step(
            "s3", "内网横向扫描",
            "以办公终端为跳板扫描内网服务，寻找 HIS 与数据库入口",
            preconditions=[{"type": "node_compromised", "node": "jump"}],
            effects=[{"target": "core", "state": "target"}],
            detection="低", technique="Network Service Discovery", mitre="T1046",
        )
        self._add_attack_step(
            "s4", "遭遇蜜罐：诱捕或绕过",
            "横向扫描命中蜜罐暴露的'伪 HIS 服务'（影子数据库诱饵）："
            "蜜罐保真度不足时攻击者可识别指纹绕过，识别失败则被诱捕",
            preconditions=[{"type": "step_completed", "step": "s3"}],
            effects=[{"target": "honeypot", "state": "target"}],
            detection="低", technique="Network Service Discovery", mitre="T1046",
        )
        self._add_attack_step(
            "s5", "攻陷真实 HIS",
            "绕过/未触发蜜罐告警后，利用 HIS 服务漏洞攻陷真实系统",
            preconditions=[{"type": "step_completed", "step": "s4"}],
            effects=[{"target": "his", "state": "compromised"}],
            detection="中", technique="Exploit Public-Facing Application", mitre="T1190",
        )
        self._add_attack_step(
            "s6", "数据库拖取",
            "从 HIS 数据库批量导出患者诊疗数据",
            preconditions=[{"type": "node_compromised", "node": "his"}],
            effects=[{"target": "db", "state": "compromised"}],
            detection="中", technique="Data from Information Repositories", mitre="T1213",
        )
        self._add_attack_step(
            "s7", "数据外泄与持久化",
            "外传患者数据并在 HIS 植入持久化后门（无出口管控与主机审计时成功）",
            preconditions=[{"type": "node_compromised", "node": "db"}],
            effects=[{"target": "db", "state": "exfiltrated"}],
            detection="高", technique="Exfiltration Over C2 Channel", mitre="T1041",
        )

    def _build_defenses(self):
        self._add_defense(
            "d1", "内网蜜罐群部署（欺骗防御）",
            "服务器区旁路部署开源蜜罐（模拟 HIS/数据库影子服务），"
            "横向扫描触发诱捕告警，攻击链在 s4 中断并进入溯源",
            blocks=["s4"], cost="中", category="监控审计",
            # 检出率=蜜罐诱捕成功率（演示假设值 0.65）：
            # 概率模式下绕过率 = exploitability × (1-0.65) ≈ 35%，
            # 语义 = 蜜罐保真度不足时攻击者识别指纹绕过的概率。
            # 业界无统一权威统计，此值为经验设定，仅用于相对风险演示，非实测概率。
            detection_rate=0.65,
        )
        self._add_defense(
            "d2", "终端准入与加固",
            "办公终端强口令策略 + 登录失败锁定 + 准入认证",
            blocks=["s2"], cost="低", category="访问控制",
        )
        self._add_defense(
            "d3", "网络分段（办公区/服务器区隔离）",
            "办公区与服务器区 VLAN 隔离 + ACL，横向扫描不可达 HIS 网段",
            blocks=["s3"], cost="中", category="网络防护",
        )
        self._add_defense(
            "d4", "HIS 补丁与 WAF",
            "HIS 系统漏洞修补 + 应用层防护，阻断远程代码执行",
            blocks=["s5"], cost="中", category="系统加固",
        )
        self._add_defense(
            "d5", "出口外联管控",
            "外联白名单 + 流量审计，阻断数据外传隧道",
            blocks=["s7"], cost="中", category="数据安全",
        )

    def _build_remediations(self):
        """增量整改候选措施（2026-09-06）：针对现状防护全开仍存在的薄弱环节设计，
        仅整改推演轮2生效，不进入现状防护。"""
        self._add_remediation(
            "r1", "入口蜜罐扩容+诱捕",
            "内网入口蜜罐扩容至全覆盖，入口侦察即被诱捕",
            covers=['s1'], cost="低", category="监控审计",
            root_cause="内网入口侦察无感知，蜜罐覆盖不足", trap=True,
        )
        self._add_remediation(
            "r2", "数据库拖取实时阻断",
            "部署数据库审计实时阻断，拖取行为即断连",
            covers=['s6'], cost="中", category="数据安全",
            root_cause="数据库拖取步骤现状无防护覆盖，属盲区", trap=False,
        )
        self._add_remediation(
            "r3", "蜜罐联动溯源反制",
            "蜜罐告警联动防火墙自动封禁攻击源，诱捕后自动化反制",
            covers=['s4'], cost="中", category="监控审计",
            root_cause="蜜罐诱捕后缺乏联动反制闭环", trap=False,
        )
