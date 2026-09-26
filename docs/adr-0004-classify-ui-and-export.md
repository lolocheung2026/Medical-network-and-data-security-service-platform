# ADR-0004：v0.3 分类结果页与报告导出

日期：2026-09-26
状态：已接受

## 背景

v0.3 路线图 = 脱密引擎加固（ADR-0003）+ 分类分级前端结果页 + 报告导出。
本 ADR 记录后两项的实现决策。

## 决策

1. **分类结果页走服务端模板渲染**（延续现有 UI 体系），不引前端框架：
   - `/classify/`：本租户已脱密数据字典列表
   - `/classify/result/<upload_id>`：五级分布条形统计 + 逐字段定级表
     （表名/字段/注释/级别/类别/命中关键词，规则溯源可见）
   - 级别配色：L1 灰 / L2 蓝 / L3 橙 / L4 红 / L5 紫
2. **导出格式 = DOCX**（乐叔 2026-09-26 选定）：python-docx 1.2.0 生成，
   微软雅黑正文 + 蓝色标题（乐叔文档交付偏好）。导出范围 = 推演报告 +
   分类结果两个模块。
3. **导出端点**：`GET /export/simulation/<run_id>`、`GET /export/classify/<upload_id>`，
   数据均来自落库结果（SimulationRun.result_json / 脱密字典+规则引擎），
   无旁路重新计算，租户隔离沿用 first_or_404 过滤。
4. **分类规则库不动**：规则扩充属乐叔领域决策，发现"结算金额"未命中 L3
   支付财务类（规则库无"金额/结算"关键词），列为待乐叔确认项。

## 影响

- `app/classify/routes.py`：+index / +result_page 两个页面端点（JSON API 保留）
- `app/templates/classify.html`（新增）、`base.html` 导航加"分类分级"
- `app/export/routes.py`（新增 Blueprint，153 行）、simulation.html/classify.html
  加"导出 DOCX"按钮
- `app/__init__.py` 注册 export Blueprint

## 冒烟证据（2026-09-26 实测）

- 分类页 200，字典列表 6 条；结果页 8 字段全级别分布 + 逐字段溯源正确
- 导出两端点 200，DOCX 可解析（python-docx 回读验证内容完整）
- 定级抽查：id_card/phone/name→L4、gene_seq/hiv_test→L5、intro→L1、
  duty→L3 均正确；amount（结算金额）→L2 为规则缺口（待乐叔定规则）

## 未决项

- "金额/结算"等财务类关键词是否入 L3 规则（乐叔决策）
- 分类规则命中率实测与人工校正回流通道（方案风险 #2）
- 导出 DOCX 的页眉/LOGO/正式公文格式（上线前美化）
