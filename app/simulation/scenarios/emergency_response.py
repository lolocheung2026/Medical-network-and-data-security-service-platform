"""Scenario: 应急六步推演 — 勒索病毒事件下的医院应急响应（应急演练脚本.md 转化）。

证据来源：应急演练脚本.md（L3蒸馏·应急响应×等保2.0×医院HIS）：
- 应急响应六步：准备→检测→抑制→根除→恢复→复盘（GB/T 24363-2009）；
- 医院典型事件处置要点：勒索病毒优先保HIS/EMR可用；
- 桌面推演模板：T+0发现→T+15min抑制→T+2h根除→T+4h恢复→T+24h复盘，
  评估RTO/RPO达成度、通报时效、处置规范性（GB/T 20985事件分类分级）。
本场景将"事件恶化链"与"应急六步动作"对照推演：每步防御对应一个应急动作。
"""
from ..engine.scenario_base import ScenarioBase


class EmergencyResponseScenario(ScenarioBase):
    SCENARIO_ID = "emergency_response"
    SCENARIO_NAME = "应急六步推演：勒索病毒事件处置"
    SCENARIO_DESC = ("勒索病毒在医院爆发，推演事件恶化链与应急六步的对抗："
                     "检测发现→隔离抑制→根除→备份恢复→业务保活→通报复盘，"
                     "评估RTO/RPO达成度与通报时效")
    SCENARIO_CATEGORY = "治理与响应层"
    SCENARIO_DIFFICULTY = "中级"
    SCENARIO_TAGS = ["应急响应", "应急六步", "勒索病毒", "等保2.0", "RTO/RPO"]
    DEMOTED_DEFENSES = ["d1"]

    def __init__(self):
        super().__init__()
        self._build_topology()
        self._build_attacks()
        self._build_defenses()
        self._build_remediations()
        self._apply_demotions()
        # P1-5 推演中决策点（CHESS 回合制思想）：T+0 告警后的处置策略选择
        self.add_decision_point(
            "s2",
            "T+0 检测到勒索病毒首爆告警，立即处置策略？",
            [
                {"id": "opt_isolation", "label": "立即全网断网隔离",
                 "description": "应急六步-抑制：立即隔离阻断扩散，代价是门诊业务中断",
                 "block_steps": ["s2", "s3"],
                 "log": "全网断网隔离，病毒扩散被遏制，但业务中断需灾备切换恢复"},
                {"id": "opt_locate", "label": "先定位再隔离",
                 "description": "先定位感染范围再处置，保业务连续性，但扩散窗口延长",
                 "block_steps": [],
                 "log": "定位期间病毒继续扩散，HIS/EMR 面临加密风险"},
            ],
        )

    def _build_topology(self):
        self._add_node("attacker", "攻击者", "external", 800, 460,
                       "勒索病毒投放源")
        self._add_node("inet_gw", "互联网出口", "network", 1400, 460,
                       "外联通道")
        self._add_node("mail", "邮件服务器", "server", 800, 60,
                       "钓鱼入口")
        self._add_node("pc1", "首台感染终端", "workstation", 800, 260,
                       "病毒首爆点")
        self._add_node("pc2", "科室终端", "workstation", 1100, 460,
                       "横向扩散面")
        self._add_node("his", "HIS服务器", "server", 1400, 60,
                       "核心业务（优先级最高）")
        self._add_node("emr", "EMR服务器", "server", 1400, 260,
                       "电子病历")
        self._add_node("pacs", "PACS服务器", "server", 1700, 460,
                       "影像系统")
        self._add_node("backup", "备份系统", "database", 800, 660,
                       "灾备中心")
        self._add_node("soc", "安全监控中心", "network", 2000, 60,
                       "检测能力（告警发现）")
        self._add_node("ir_team", "应急响应组", "network", 2000, 260,
                       "指挥/技术/业务/通报四组")
        self._add_node("notice", "通报渠道", "network", 2000, 460,
                       "上级/监管/患者通报")

        self._add_edge("attacker", "inet_gw", "")
        self._add_edge("inet_gw", "mail", "钓鱼邮件")
        self._add_edge("mail", "pc1", "")
        self._add_edge("pc1", "pc2", "内网共享")
        self._add_edge("pc1", "his", "")
        self._add_edge("his", "emr", "")
        self._add_edge("his", "pacs", "")
        self._add_edge("emr", "backup", "")
        self._add_edge("pacs", "backup", "")
        self._add_edge("his", "soc", "监控覆盖")
        self._add_edge("soc", "ir_team", "告警上报")
        self._add_edge("ir_team", "notice", "通报")
        self._add_edge("ir_team", "backup", "恢复路径")

    def _build_attacks(self):
        self._add_attack_step(
            "s1", "事件爆发",
            "勒索病毒在首台终端激活，开始加密本地文件（T+0）",
            preconditions=[],
            effects=[{"target": "pc1", "state": "encrypted"}],
            detection="高", technique="Data Encrypted for Impact", mitre="T1486",
        )
        self._add_attack_step(
            "s2", "横向扩散",
            "未及时发现告警，病毒经内网共享扩散至科室终端并触达HIS（T+15min）",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "pc2", "state": "encrypted"},
                     {"target": "his", "state": "compromised"}],
            detection="中", technique="Lateral Tool Transfer", mitre="T1570",
        )
        self._add_attack_step(
            "s3", "核心系统加密",
            "HIS/EMR核心业务被加密，门诊挂号缴费中断",
            preconditions=[{"type": "node_compromised", "node": "his"}],
            effects=[{"target": "his", "state": "encrypted"},
                     {"target": "emr", "state": "encrypted"}],
            detection="高", technique="Data Encrypted for Impact", mitre="T1486",
        )
        self._add_attack_step(
            "s4", "备份目标锁定",
            "病毒扫描定位备份系统，尝试加密灾备数据",
            preconditions=[{"type": "step_completed", "step": "s3"}],
            effects=[{"target": "backup", "state": "target"}],
            detection="中", technique="Data from Network Shared Drive", mitre="T1039",
        )
        self._add_attack_step(
            "s5", "备份加密",
            "备份系统被加密，灾备能力失效——RPO归零风险",
            preconditions=[{"type": "step_completed", "step": "s4"}],
            effects=[{"target": "backup", "state": "encrypted"}],
            detection="高", technique="Data Encrypted for Impact", mitre="T1486",
        )
        self._add_attack_step(
            "s6", "业务全面中断",
            "PACS等剩余系统被加密，全院业务停摆（RTO恶化）",
            preconditions=[{"type": "step_completed", "step": "s3"}],
            effects=[{"target": "pacs", "state": "encrypted"}],
            detection="高", technique="Data Encrypted for Impact", mitre="T1486",
        )
        self._add_attack_step(
            "s7", "数据外泄+通报迟滞",
            "攻击者外泄患者数据并勒索；未及时通报上级与患者，合规危机叠加",
            preconditions=[{"type": "step_completed", "step": "s5"}],
            effects=[{"target": "his", "state": "exfiltrated"}],
            detection="高", technique="Exfiltration Over Alternative Protocol", mitre="T1048",
        )

    def _build_defenses(self):
        self._add_defense(
            "d1", "检测：监控告警发现",
            "安全监控实时告警，T+0发现首爆（应急六步-检测）",
            blocks=["s2"], cost="中", category="应急-检测",
        )
        self._add_defense(
            "d2", "抑制：隔离断网",
            "T+15min隔离受染主机、封禁共享、断网止损（应急六步-抑制）",
            blocks=["s3"], cost="低", category="应急-抑制",
        )
        self._add_defense(
            "d3", "根除：杀毒补丁改密",
            "T+2h清除恶意程序、修复漏洞、全面改密（应急六步-根除）",
            blocks=["s4"], cost="中", category="应急-根除",
        )
        self._add_defense(
            "d4", "恢复：不可变备份",
            "不可变离线备份，备份系统无法被加密（应急六步-恢复基础）",
            blocks=["s5"], cost="高", category="应急-恢复",
        )
        self._add_defense(
            "d5", "恢复：灾备切换保业务",
            "T+4h从灾备恢复HIS/EMR，核心业务优先（RTO<4h）",
            blocks=["s6"], cost="高", category="应急-恢复",
        )
        self._add_defense(
            "d6", "复盘：通报与合规",
            "T+24h事件报告+根因分析，及时通报上级与患者（GB/T 20985分级）",
            blocks=["s7"], cost="低", category="应急-复盘",
        )

    def _build_remediations(self):
        """增量整改候选措施（2026-09-06）：针对现状防护全开仍存在的薄弱环节设计，
        仅整改推演轮2生效，不进入现状防护。"""
        self._add_remediation(
            "r1", "SOAR自动化编排平台",
            "部署SOAR：事件爆发即自动研判、自动下发隔离指令，响应从小时级到分钟级",
            covers=['s1'], cost="高", category="应急-检测",
            root_cause="事件发现依赖人工值守，缺自动化发现与响应能力", trap=True,
        )
        self._add_remediation(
            "r2", "常态化攻防演练机制",
            "建立季度攻防演练机制，横向扩散场景预演与响应流程固化",
            covers=['s2'], cost="低", category="应急-复盘",
            root_cause="横向扩散处置依赖临时指挥，缺常态化演练沉淀", trap=False,
        )
        self._add_remediation(
            "r3", "通报预警自动化",
            "对接监管通报平台实现预警自动化，通报迟滞风险消除",
            covers=['s7'], cost="低", category="应急-复盘",
            root_cause="通报流程依赖人工，存在迟滞风险", trap=False,
        )
