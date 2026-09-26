# ADR-0009：分类人工校正回流通道

日期：2026-09-26
状态：已接受

## 背景

方案风险 #2：分类规则硬编码，真实医院字段命名多样，首月命中率可能不足
60%，需预留"人工校正→规则回流"通道。乐叔 2026-09-26 指示执行。

## 决策

1. **校正表 ClassificationCorrection**：租户级，以 (table_name, field_name)
   为键，记录原定级/校正级别/理由。
2. **回流语义**：分类引擎查询校正表**优先于规则命中**——命中即返回校正级别，
   类别标"人工校正"，溯源含理由。校正作用于本租户全部字典（跨字典生效），
   不跨租户。
3. **规则引擎签名扩展**：classify_data_dict_csv(text, corrections=None)，
   corrections 由 routes 层从校正表构建（引擎保持纯函数，DB 依赖在路由层）。
4. **UI**：结果页逐字段行内校正表单（级别下拉 + 理由），提交即回流重算。
5. **与 L2 决策的关系**：校正通道解决个案（如"结算金额"落 L3）；全局规则
   关键词是否扩充（"金额/结算"入 L3）仍是独立决策，两机制互补。

## 影响

- app/models.py：+ClassificationCorrection
- app/classify/rules.py：classify_data_dict_csv 支持 corrections 参数
- app/classify/routes.py：+POST /correct；结果页/JSON API 加载校正
- app/templates/classify.html：行内校正表单列

## 冒烟证据（2026-09-26 实测）

- 提交校正 302 → amount 重新分类 L3 人工校正（原 L2），溯源含理由
- 校正记录落库（tenant 隔离）

## 未决项

- 校正数据的平台级汇聚分析（哪些字段高频被校正 → 反哺全局规则库），
  需跨租户匿名化统计，涉及多租户数据使用边界，v1.0 打磨项
- 校正撤销/历史版本管理未做（当前覆盖式）
