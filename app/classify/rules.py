"""数据分类分级规则引擎 v1（GB/T 39725《健康医疗数据安全指南》对齐）。

五级定级：L1 可公开 → L5 极敏感（严格管控）。
规则按关键词命中字段名/注释，取最高级别；未命中默认 L2。
规则库后续迁移到数据库，支持在线维护。
"""

LEVELS = {
    1: "L1 可公开",
    2: "L2 内部一般",
    3: "L3 敏感（个人信息/运营）",
    4: "L4 高度敏感（健康医疗个人数据）",
    5: "L5 极敏感（基因/生物识别/精卵胚胎/传染病）",
}

RULES = [
    # (级别, 类别, 关键词)
    (5, "人类遗传资源/生殖医学", ["基因", "dna", "rna", "染色体", "精子", "卵子", "胚胎", "遗传"]),
    (5, "生物识别", ["指纹", "人脸", "虹膜", "声纹", "掌纹"]),
    (5, "法定传染病", ["传染病", "艾滋病", "hiv", "梅毒", "结核"]),
    (4, "直接标识符", ["身份证", "证件号", "护照", "姓名", "手机号", "电话", "住址", "社保卡"]),
    (4, "诊疗健康数据", ["诊断", "病历", "检验", "检查", "处方", "用药", "手术", "过敏",
                     "影像", "病理", "体温", "血压", "血糖", "主诉", "既往史"]),
    (4, "医疗支付关联", ["医保卡号", "就诊卡", "住院号", "门诊号"]),
    (3, "支付财务", ["费用", "收费", "发票", "账户", "银行卡"]),
    (3, "运营数据", ["排班", "绩效", "工资", "科室成本", "设备台账"]),
    (1, "公开信息", ["科室介绍", "专家简介", "就医指南", "健康宣教"]),
]

CATEGORY_DEFAULT = 2


def classify_field(field_name, comment=""):
    """对单个字段定级。返回 (级别, 类别, 命中关键词)。"""
    text = f"{field_name} {comment}".lower()
    best = None
    for level, category, keywords in RULES:
        for kw in keywords:
            if kw in text:
                if best is None or level > best[0]:
                    best = (level, category, kw)
    if best:
        return best
    return (CATEGORY_DEFAULT, "未识别（默认内部）", None)


def classify_data_dict_csv(text):
    """输入数据字典 CSV（表名,字段名,注释 三列起步），输出逐字段定级结果。"""
    import csv
    import io

    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    if not rows:
        return []
    header = [c.strip() for c in rows[0]]
    results = []
    for row in rows[1:]:
        if not any(row):
            continue
        table = row[0].strip() if len(row) > 0 else ""
        field = row[1].strip() if len(row) > 1 else ""
        comment = row[2].strip() if len(row) > 2 else ""
        level, category, kw = classify_field(f"{table}.{field}", comment)
        results.append({
            "table": table, "field": field, "comment": comment,
            "level": level, "level_label": LEVELS[level],
            "category": category, "hit_keyword": kw,
        })
    return results
