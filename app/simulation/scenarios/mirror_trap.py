"""Scenario: 镜像的陷阱 — 两院服务器同构带来的漏洞面复制（评估报告风险5）。

证据来源：研究院IT基础设施安全评估报告（KB-03-0196）：
两院服务器型号高度重复——主备/PACS/智慧医院/叫号/胎心/银联/接口/EDR/
自助/病案/前置机共11类业务系统同构；
且江北内部防火墙是服务器区唯一边界（弱侧），渝北四层纵深（强侧）。
推演：弱侧突破→配置模板提取→攻击模板复制到强侧→主备同时被控，灾备同漏洞失效。
"""
from ..engine.scenario_base import ScenarioBase


class MirrorTrapScenario(ScenarioBase):
    SCENARIO_ID = "mirror_trap"
    SCENARIO_NAME = "镜像的陷阱：两院同构服务器的漏洞面复制"
    SCENARIO_DESC = ("两院11类服务器同型号同配置（评估报告风险5），推演弱侧(江北唯一边界)"
                     "突破后提取配置模板、攻击手法跨院复制，主备同构致灾备同步失效")
    SCENARIO_CATEGORY = "攻防对抗层"
    SCENARIO_DIFFICULTY = "高级"
    SCENARIO_TAGS = ["同构镜像", "跨院横向", "主备同漏洞", "两院区"]
    DEMOTED_DEFENSES = ["d1", "d2", "d3", "d4"]

    def __init__(self):
        super().__init__()
        self._build_topology()
        self._build_attacks()
        self._build_defenses()
        self._build_remediations()
        self._apply_demotions()

    def _build_topology(self):
        # 江北（弱侧：内部防火墙唯一边界） —— 渝北（强侧：四层纵深） —— 主备跨院
        self._add_node("internet", "攻击者", "external", 870, 210,
                       "外部攻击源")
        self._add_node("jb_fw", "江北内部防火墙", "firewall", 1050, 210,
                       "服务器区【唯一边界，弱侧】")
        self._add_node("jb_pacs", "江北PACS", "server", 1110, 60,
                       "同构模板（与渝北同型号）")
        self._add_node("jb_his", "江北HIS", "server", 1230, 210,
                       "同构（与渝北同型号）")
        self._add_node("jb_backup", "江北备份(备)", "database", 1110, 360,
                       "主备镜像，与渝北主备份同构")
        self._add_node("yb_link", "两院互联链路", "network", 1410, 210,
                       "跨院区链路")
        self._add_node("yb_af", "渝北AF防火墙", "firewall", 1590, 210,
                       "强侧四层纵深第一道")
        self._add_node("yb_pacs", "渝北PACS", "server", 1290, 60,
                       "与江北PACS同型号同配置")
        self._add_node("yb_his", "渝北HIS", "server", 1770, 210,
                       "与江北HIS同型号")
        self._add_node("yb_backup", "渝北备份(主)", "database", 1290, 360,
                       "主备份，与江北备备份同构")

        self._add_edge("internet", "jb_fw", "唯一边界")
        self._add_edge("jb_fw", "jb_pacs", "")
        self._add_edge("jb_fw", "jb_his", "")
        self._add_edge("jb_fw", "jb_backup", "")
        self._add_edge("jb_fw", "yb_link", "跨院链路")
        self._add_edge("yb_link", "yb_af", "")
        self._add_edge("yb_af", "yb_pacs", "")
        self._add_edge("yb_af", "yb_his", "")
        self._add_edge("yb_af", "yb_backup", "")
        self._add_edge("jb_pacs", "yb_pacs", "同构镜像")
        self._add_edge("jb_backup", "yb_backup", "主备同构")

    def _build_attacks(self):
        self._add_attack_step(
            "s1", "同构侦察",
            "识别两院11类服务器同型号同配置（主备/PACS/智慧医院/叫号/胎心/"
            "银联/接口/EDR/自助/病案/前置机），漏洞面全院复制",
            preconditions=[],
            effects=[{"target": "jb_pacs", "state": "target"}],
            detection="低", technique="Gather Victim Host Information", mitre="T1592",
        )
        self._add_attack_step(
            "s2", "弱侧突破",
            "江北服务器区内部防火墙是唯一边界，突破即直入全部同构服务器",
            preconditions=[{"type": "step_completed", "step": "s1"}],
            effects=[{"target": "jb_pacs", "state": "compromised"}],
            detection="中", technique="Exploit Public-Facing Application", mitre="T1190",
        )
        self._add_attack_step(
            "s3", "配置模板提取",
            "从弱侧同构服务器提取配置模板：补丁清单、口令策略、服务基线全盘复制",
            preconditions=[{"type": "node_compromised", "node": "jb_pacs"}],
            effects=[{"target": "jb_his", "state": "compromised"}],
            detection="低", technique="Data from Local System", mitre="T1005",
        )
        self._add_attack_step(
            "s4", "攻击模板跨院复制",
            "将攻破江北的手法原样复制到渝北同型号设备——同漏洞、同配置、同弱点",
            preconditions=[{"type": "node_compromised", "node": "jb_his"}],
            effects=[{"target": "yb_pacs", "state": "compromised"}],
            detection="中", technique="Exploit Public-Facing Application", mitre="T1190",
        )
        self._add_attack_step(
            "s5", "主备同时被控",
            "主备份(渝北)与备备份(江北)同构同漏洞，灾备节点一并沦陷",
            preconditions=[{"type": "step_completed", "step": "s4"}],
            effects=[{"target": "yb_backup", "state": "compromised"},
                     {"target": "jb_backup", "state": "compromised"}],
            detection="中", technique="Remote Services", mitre="T1021",
        )
        self._add_attack_step(
            "s6", "双院区同步沦陷",
            "渝北HIS沿用同模板被控，两院核心业务全在攻击者手中",
            preconditions=[{"type": "step_completed", "step": "s5"}],
            effects=[{"target": "yb_his", "state": "compromised"}],
            detection="中", technique="Remote Services", mitre="T1021",
        )
        self._add_attack_step(
            "s7", "灾备失效+生产加密",
            "主备备份同漏洞加密，生产HIS同步加密——镜像的终极代价：灾备救不了",
            preconditions=[{"type": "step_completed", "step": "s6"}],
            effects=[{"target": "yb_backup", "state": "encrypted"},
                     {"target": "jb_backup", "state": "encrypted"},
                     {"target": "yb_his", "state": "encrypted"}],
            detection="高", technique="Data Encrypted for Impact", mitre="T1486",
        )

    def _build_defenses(self):
        self._add_defense(
            "d1", "江北边界加固",
            "江北服务器区边界双防火墙+分区域划分，消除唯一边界单点",
            blocks=["s2"], cost="高", category="边界防护",
        )
        self._add_defense(
            "d2", "差异化加固",
            "两院同构设备差异化：不同口令/不同补丁策略/不同网段，模板不可复用",
            blocks=["s3"], cost="中", category="配置管理",
        )
        self._add_defense(
            "d3", "攻击面收敛",
            "同构设备去EOL组件+服务最小化+基线核查，压缩跨院复用攻击面",
            blocks=["s4"], cost="中", category="系统加固",
        )
        self._add_defense(
            "d4", "主备异构",
            "主备份与备备份异构（不同厂商/型号/存储），杜绝主备同漏洞",
            blocks=["s5"], cost="高", category="架构整改",
        )
        self._add_defense(
            "d5", "备份不可变+异质",
            "备份不可变存储+离线异质副本，加密可恢复",
            blocks=["s7"], cost="高", category="灾备恢复",
        )

    def _build_remediations(self):
        """增量整改候选措施（2026-09-06）：针对现状防护全开仍存在的薄弱环节设计，
        仅整改推演轮2生效，不进入现状防护。"""
        self._add_remediation(
            "r1", "蜜罐诱捕同构侦察",
            "两院区同构区部署差异化蜜罐，同构侦察即被诱捕",
            covers=['s1'], cost="低", category="监控审计",
            root_cause="攻击者对同构架构侦察无感知", trap=True,
        )
        self._add_remediation(
            "r2", "跨院区威胁情报联动",
            "建立两院区威胁情报联动平台，一侧发现攻击即全集团封堵",
            covers=['s6'], cost="中", category="监控审计",
            root_cause="双院区同步沦陷步骤现状无防护覆盖，属盲区", trap=False,
        )
        self._add_remediation(
            "r3", "配置漂移监测",
            "部署配置漂移监测，配置模板被提取复制时实时告警",
            covers=['s3'], cost="中", category="配置管理",
            root_cause="配置模板提取依赖差异化加固单道防护", trap=False,
        )
