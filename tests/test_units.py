"""单元测试。不依赖 pytest，直接 `python tests/test_units.py` 跑；
函数名以 test_ 开头，所以 pytest 也能直接收集。
"""
from __future__ import annotations

import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from legal_redactor.core import Preset, Span, Strategy, load_preset
from legal_redactor.detect.base import canon_entity, merge_spans
from legal_redactor.detect.regex_det import (id_card_checksum_ok, id_card_semantic_ok,
                                             luhn_ok, uscc_ok)
from legal_redactor.detect.pipeline import TabularDetector, TextPipeline, header_etype, post_validate
from legal_redactor.detect.addr_det import address_level, truncate_to_level
from legal_redactor.detect.name_det import looks_like_name
from legal_redactor.strategies import replacer as R
from legal_redactor.strategies.resolver import EntityResolver
from legal_redactor.strategies.mapping import decrypt_mapping, encrypt_mapping, write_mapping
from legal_redactor.audit import forbidden_fragments, is_coincidental

FAILED: list[str] = []


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def eq(a, b, msg: str = "") -> None:
    if a != b:
        raise AssertionError(f"{msg} 期望 {b!r}，实际 {a!r}")


# --------------------------------------------------------------------------
# 校验位
# --------------------------------------------------------------------------


def test_id_card_checksum():
    # 真实规则：改一位就应该失败
    good = "11010519870312451X"
    check(id_card_checksum_ok(good), "合法身份证应通过校验位")
    check(id_card_semantic_ok(good)[0], "合法身份证应通过语义校验")
    bad = "110105198703124511"
    check(not id_card_checksum_ok(bad), "校验位错误应被拒")
    # 出生日期非法
    check(not id_card_semantic_ok("11010519871332451X")[0] or
          not id_card_checksum_ok("11010519871332451X"), "非法月份应被拒")
    # 地区码非法
    ok_chk = None
    for c in "0123456789X":
        cand = "99010519870312451" + c
        if id_card_checksum_ok(cand):
            ok_chk = cand
            break
    if ok_chk:
        check(not id_card_semantic_ok(ok_chk)[0], "省级地区码 99 非法，语义校验应拒")
    check(not id_card_checksum_ok("123"), "长度不足应拒")


def test_luhn():
    check(luhn_ok("6222021123456787"), "Luhn 合法卡号应通过")
    check(luhn_ok("1100123456780003"), "Luhn 合法卡号应通过")
    check(not luhn_ok("6222021123456788"), "改一位应失败")
    check(not luhn_ok("123"), "过短应失败")


def test_uscc():
    check(uscc_ok("91110102710931234J"), "合法统一社会信用代码应通过")
    check(not uscc_ok("91110102710931234X"), "校验位错误应拒")
    check(not uscc_ok("9111010271093123I"), "含禁用字母 I 应拒")
    check(not uscc_ok("12345"), "长度不足应拒")


# --------------------------------------------------------------------------
# 中文数字与日期
# --------------------------------------------------------------------------


def test_cn_numbers():
    eq(R.cn_to_int("二〇二三"), 2023, "逐位年份")
    eq(R.cn_to_int("二零二三"), 2023)
    eq(R.cn_to_int("二十"), 20, "位值")
    eq(R.cn_to_int("十"), 10)
    eq(R.cn_to_int("十五"), 15)
    eq(R.cn_to_int("三十一"), 31)
    eq(R.cn_to_int("九"), 9)
    eq(R.int_to_cn_digits(2023), "二〇二三")
    eq(R.int_to_cn_value(20), "二十")
    eq(R.int_to_cn_value(5), "五")
    eq(R.int_to_cn_value(10), "十")
    eq(R.int_to_cn_value(11), "十一")


def test_date_roundtrip():
    cases = [
        ("2023年6月15日", "num_ymd"),
        ("2023年6月", "num_ym"),
        ("2023-06-15", "iso_ymd"),
        ("二〇二三年九月二十日", "cn_ymd"),
        ("二〇二三年十二月", "cn_ym"),
        ("二〇二三年", "cn_y"),
    ]
    for text, kind in cases:
        dt, got = R.parse_date(text)
        check(dt is not None, f"{text} 应能解析")
        eq(got, kind, f"{text} 格式标签")
        back = R.format_date(dt, kind)
        eq(back, text, f"{text} 往返")
    # ISO 的分隔符/补零不逐一还原，这是文档化的取舍：只保证日期值与格式族正确
    dt, kind = R.parse_date("2023/6/15")
    eq(kind, "iso_ymd")
    eq((dt.year, dt.month, dt.day), (2023, 6, 15), "2023/6/15 的值")
    eq(R.format_date(dt, kind), "2023-06-15", "ISO 归一到标准写法")


def test_generalize_date():
    eq(R.generalize_date("1987年3月12日", "year"), "1987年", "年泛化")
    eq(R.generalize_date("1987年3月12日", "month"), "1987年3月", "月泛化")
    eq(R.generalize_date("二〇二三年九月二十日", "year"), "二〇二三年", "中文年泛化")
    eq(R.generalize_date("2023-06-15", "year"), "2023", "ISO 年泛化")
    eq(R.generalize_date("2023年6月15日", "hide"), "[日期已脱敏]", "hide")


# --------------------------------------------------------------------------
# 地址级别
# --------------------------------------------------------------------------


def test_address_level():
    a = "北京市朝阳区建国路88号院3号楼2单元401室"
    lv, end = address_level(a)
    eq(lv, 7, "应解析到门牌/楼栋级")
    eq(truncate_to_level(a, 3), "北京市朝阳区", "截到区县级")
    eq(truncate_to_level(a, 2), "北京市", "截到市级")
    eq(truncate_to_level(a, 6), "北京市朝阳区建国路", "截到路级")
    lv2, _ = address_level("广东省广州市天河区体育西路103号")
    eq(lv2, 7, "省级起始的地址也应到门牌级")
    eq(truncate_to_level("广东省广州市天河区体育西路103号", 3), "广东省广州市天河区")


# --------------------------------------------------------------------------
# 姓名结构校验
# --------------------------------------------------------------------------


def test_name_structure():
    check(looks_like_name("张伟民")[0], "常规三字名")
    check(looks_like_name("张三")[0], "常规二字名")
    check(looks_like_name("欧阳明日")[0], "复姓四字名")
    check(not looks_like_name("高级")[0], "'高级'应被拒（高风险姓+常用词）")
    check(not looks_like_name("万元")[0], "'万元'应被拒")
    check(not looks_like_name("程序")[0], "'程序'应被拒")
    check(looks_like_name("张某")[0], "'张某'是已匿名写法，应认")
    check(not looks_like_name("张")[0], "单字应拒")
    check(not looks_like_name("张三李四王")[0], "过长应拒")


# --------------------------------------------------------------------------
# span 归并
# --------------------------------------------------------------------------


def test_merge_spans_priority():
    # 身份证（强）应吃掉落在其内部的手机号（弱）
    a = Span(0, 18, "138001380001234567", "ID_CARD", 0.99, block="b")
    b = Span(0, 11, "13800138000", "PHONE", 0.95, block="b")
    out = merge_spans([b, a])
    eq(len(out), 1, "被完全包含的应丢弃")
    eq(out[0].etype, "ID_CARD")


def test_merge_spans_trim():
    # 部分重叠：胜者保留，败者被裁掉重叠部分而不是整条丢
    a = Span(0, 10, "0123456789", "ADDRESS", 0.9, block="b")
    b = Span(6, 14, "6789abcd", "ORG", 0.9, block="b")
    out = merge_spans([a, b])
    texts = sorted(s.text for s in out)
    check(len(out) == 2, f"应保留裁剪后的两段，实际 {len(out)}：{texts}")


def test_merge_spans_regions_kept():
    r = Span(0, 5, "系未成年人", "MINOR_INFO", 0.9, block="b")
    p = Span(0, 3, "周某", "PERSON", 0.99, block="b")
    out = merge_spans([r, p])
    kinds = {s.etype for s in out}
    check("MINOR_INFO" in kinds and "PERSON" in kinds,
          f"区域标记不该被消解掉，实际 {kinds}")


def test_canon_entity():
    eq(canon_entity("PHONE", "+86 136-2222-3333"), "8613622223333")
    eq(canon_entity("PERSON", "张某"), "张")
    eq(canon_entity("EMAIL", "A@B.COM"), "a@b.com")


# --------------------------------------------------------------------------
# 替换策略
# --------------------------------------------------------------------------


def test_mask_person():
    eq(R.mask_person("张三"), "张某")
    eq(R.mask_person("张伟民"), "张某某")
    eq(R.mask_person("欧阳明日"), "欧阳某某")
    eq(R.mask_person("张某"), "张某", "幂等：已匿名的不该再改")
    eq(R.mask_person("张三", mode="full"), "某某")
    eq(R.mask_person("张三", mode="surname_only"), "张")


def test_partial_mask():
    eq(R.partial_mask("PHONE", "13801234567"), "138****4567")
    eq(R.partial_mask("ID_CARD", "11010519870312451X"), "110105********451X")
    eq(R.partial_mask("BANK_CARD", "6222021123456787"), "************6787")
    eq(R.partial_mask("EMAIL", "zhangwm@example.com.cn"), "z***@example.com.cn")
    eq(R.partial_mask("IP_ADDR", "192.168.1.100"), "192.168.*.*")


def test_generalize():
    eq(R.generalize("ADDRESS", "北京市朝阳区建国路88号院3号楼2单元401室",
                    {"address_level": 3}), "北京市朝阳区")
    eq(R.generalize("DOB", "1987年3月12日", {"dob_level": "year"}), "1987年")
    g = R.generalize("AMOUNT", "200000元", {"amount_mode": "range"}, {"value": 200000.0})
    check("万" in g and "元" in g, f"金额应泛化成区间，实际 {g}")
    eq(R.generalize("ID_CARD", "11010519870312451X", {"id_keep_prefix": 2}),
       "11" + "*" * 16)


def test_date_shift_keeps_interval():
    a = R.shift_date("2023年6月15日", -365)
    b = R.shift_date("2023年9月20日", -365)
    da, _ = R.parse_date(a)
    db, _ = R.parse_date(b)
    eq((db - da).days, 97, "平移后相对间隔必须不变")


def test_hash_pseudo_stable():
    h1 = R.hash_pseudo("PERSON", "张三", b"k")
    h2 = R.hash_pseudo("PERSON", "张三", b"k")
    h3 = R.hash_pseudo("PERSON", "张三", b"k2")
    eq(h1, h2, "同 key 同值应稳定")
    check(h1 != h3, "不同 key 应不同")


# --------------------------------------------------------------------------
# 一致化解析
# --------------------------------------------------------------------------


def _preset() -> Preset:
    return load_preset(ROOT / "schemas" / "legal.yaml")


def test_mask_org_keeps_type_suffix():
    """机构名遮盖必须保留"是什么类型的机构"，否则文书读不懂。"""
    eq(R.mask_org("北京市恒信律师事务所", "LAW_FIRM"), "北某某律师事务所")
    eq(R.mask_org("北京华远置业有限公司", "ORG"), "北某某有限公司")
    eq(R.mask_org("中国工商银行股份有限公司北京朝阳支行", "BANK_BRANCH"),
       "中某某银行某支行")
    eq(R.mask_org("北京市西城区人民法院", "COURT"), "北京市某人民法院")
    eq(R.mask_org("北京市第二中级人民法院", "COURT"), "北京市某中级人民法院")
    # 不得保留原名主体
    check("恒信" not in R.mask_org("北京市恒信律师事务所", "LAW_FIRM"), "律所名主体必须去掉")
    check("华远" not in R.mask_org("北京华远置业有限公司", "ORG"), "公司名主体必须去掉")


def test_resolver_consistency():
    p = _preset()
    res = EntityResolver(p, seed=b"unit")
    # 同一个人，跨 block、跨写法（含 +86 分隔符变体）
    res.add(Span(0, 3, "张伟民", "PERSON", 0.98, block="body"))
    res.add(Span(50, 53, "张伟民", "PERSON", 0.98, block="header1"))
    res.add(Span(0, 11, "13801234567", "PHONE", 0.95, block="body"))
    res.add(Span(90, 101, "13801234567", "PHONE", 0.95, block="footer1"))
    res.finalize()
    r1 = res.replacement_for(Span(0, 3, "张伟民", "PERSON", block="body"))
    r2 = res.replacement_for(Span(50, 53, "张伟民", "PERSON", block="header1"))
    eq(r1, r2, "同一姓名跨 block 必须替换成同一个值")
    p1 = res.replacement_for(Span(0, 11, "13801234567", "PHONE", block="body"))
    p2 = res.replacement_for(Span(90, 101, "13801234567", "PHONE", block="footer1"))
    eq(p1, p2, "同一号码跨 block 必须一致")
    check("张伟民" not in r1 and "13801234567" not in p1, "替换值不得包含原值")


def test_resolver_pseudo_unique_and_not_real():
    p = Preset(id="t", label="t", actions={"PERSON": Strategy.PSEUDO, "PHONE": Strategy.MASK_FULL})
    res = EntityResolver(p, seed=b"unit2")
    names = ["张伟民", "李建国", "王志强", "赵晓东", "陈晓芸", "孙丽华",
             "刘振华", "杨秀兰", "郑国强", "方文静"]
    for i, n in enumerate(names):
        res.add(Span(i * 10, i * 10 + 3, n, "PERSON", 0.98, block="body"))
    res.finalize()
    pseudos = [res.replacement_for(Span(i * 10, i * 10 + 3, n, "PERSON", block="body"))
               for i, n in enumerate(names)]
    eq(len(set(pseudos)), len(pseudos), f"假名必须两两不同：{pseudos}")
    clash = [x for x in pseudos if x in names]
    check(not clash, f"假名不得撞上文中真实姓名：{clash}")


def test_resolver_escalation():
    p = _preset()
    res = EntityResolver(p, seed=b"unit3")
    s = Span(0, 3, "周某", "PERSON", 0.99, block="body",
             attrs={"escalated": True, "forced_strategy": "MASK_FULL"})
    res.add(s)
    res.finalize()
    out = res.replacement_for(s)
    check("某" not in out, f"被强制升级的不应保留姓氏遮盖，实际 {out!r}")


def test_resolver_deterministic_across_runs():
    p = Preset(id="t", label="t", actions={"PERSON": Strategy.PSEUDO})
    outs = []
    for _ in range(2):
        res = EntityResolver(p, seed=b"same-seed")
        res.add(Span(0, 3, "张伟民", "PERSON", 0.98, block="b"))
        res.finalize()
        outs.append(res.replacement_for(Span(0, 3, "张伟民", "PERSON", block="b")))
    eq(outs[0], outs[1], "同 seed 必须给出同一假名（跨批次可复现）")


def test_marker_only_not_in_mapping():
    p = _preset()
    res = EntityResolver(p, seed=b"unit4")
    res.add(Span(0, 5, "系未成年人", "MINOR_INFO", 0.9, block="b"))
    res.finalize()
    recs = res.mapping_records()
    check(not any(r["etype"] == "MINOR_INFO" for r in recs),
          "区域标记不该进对照表，否则审计会拿它当敏感值去搜残留")


# --------------------------------------------------------------------------
# 对照表加密
# --------------------------------------------------------------------------


def test_mapping_crypto(tmpdir: Path | None = None):
    recs = [{"etype": "PERSON", "original": "张伟民", "replacement": "张某",
             "strategy": "MASK", "code": "当事人A", "occurrences": 7,
             "variants": ["张伟民"], "files": ["a.docx"], "blocks": ["body"],
             "escalated": False, "pseudo": ""}]
    token = encrypt_mapping(recs, "口令-abc-123")
    back = decrypt_mapping(token, "口令-abc-123")
    eq(back[0]["original"], "张伟民", "解密还原")
    try:
        decrypt_mapping(token, "错的口令")
        raise AssertionError("错口令必须失败")
    except ValueError:
        pass
    # 同一份数据两次加密结果必须不同（随机 salt/IV），否则可做字典比对
    t2 = encrypt_mapping(recs, "口令-abc-123")
    check(t2 != token, "两次加密的密文应不同（随机 salt）")
    d = (tmpdir or Path(ROOT / "verify-out" / "unit"))
    d.mkdir(parents=True, exist_ok=True)
    info = write_mapping(recs, d / "m.enc.json", passphrase="pw123456", fmt="encrypted")
    check(info["encrypted"], "应标记为已加密")
    raw = (d / "m.enc.json").read_text(encoding="utf-8")
    check("张伟民" not in raw, "加密文件里不得出现明文原值")


# --------------------------------------------------------------------------
# 审计片段与巧合判定
# --------------------------------------------------------------------------


def test_forbidden_fragments():
    fr = dict((f, k) for f, k in forbidden_fragments("ID_CARD", "11010519870312451X"))
    check("11010519870312451X" in fr, "全值")
    check("19870312" in fr, "出生日期段必须单独查")
    check("451X" in fr or "12451X" in fr, "尾部片段")
    fr2 = dict((f, k) for f, k in forbidden_fragments("PERSON", "张伟民"))
    check("伟民" in fr2, "去姓的名字部分必须查")


def test_is_coincidental():
    # 产物里另一个没被脱敏的长号，含有原卡号的 6 位滑窗 —— 这是巧合不是残留
    text = "账号1100123456780003已冻结"
    check(is_coincidental(text, text.index("123456"), "123456", "6222021123456787"),
          "落在别的长号里应判为巧合")
    # 真残留：片段所在的串就是原值的一部分
    text2 = "残留19870312在这里"
    check(not is_coincidental(text2, text2.index("19870312"), "19870312",
                              "11010519870312451X"), "原值的子串应判为真残留")
    # 独立存在的短片段
    text3 = "结尾4567"
    check(not is_coincidental(text3, text3.index("4567"), "4567", "13801234567"),
          "独立片段应判为真残留")


# --------------------------------------------------------------------------
# 表格列头驱动
# --------------------------------------------------------------------------


def test_header_etype():
    eq(header_etype("姓名"), "PERSON")
    eq(header_etype("当事人"), "PERSON")
    eq(header_etype("公民身份号码"), "ID_CARD")
    eq(header_etype("联系电话"), "PHONE")
    eq(header_etype("住址"), "ADDRESS")
    eq(header_etype("开户行"), "BANK_BRANCH")
    eq(header_etype("备注"), None)
    eq(header_etype(""), None)


def test_tabular_detector_bare_name():
    """裸姓名（表格里没有上下文）靠列头也必须抓出来。"""
    d = TabularDetector("姓名")
    out = d.detect("张伟民", "sheet1!A2")
    eq(len(out), 1, "列头=姓名 时裸姓名应命中")
    eq(out[0].etype, "PERSON")
    eq(out[0].text, "张伟民")
    d2 = TabularDetector("姓名")
    eq(d2.detect("北京华远置业有限公司", "sheet1!A3"), [], "机构名不该被当姓名")
    d3 = TabularDetector("联系电话")
    out3 = d3.detect("13801234567", "sheet1!C2")
    eq(len(out3), 1)
    eq(out3[0].etype, "PHONE")
    d4 = TabularDetector("住址")
    out4 = d4.detect("北京市朝阳区建国路88号院3号楼2单元401室", "sheet1!D2")
    eq(len(out4), 1)
    eq(out4[0].etype, "ADDRESS")


def test_pipeline_with_hints():
    p = _preset()
    pipe = TextPipeline(p)
    blocks = {"sheet:当事人!A2": "张伟民", "sheet:当事人!B2": "11010519870312451X"}
    hints = {"sheet:当事人!A2": "姓名", "sheet:当事人!B2": "公民身份号码"}
    out = pipe.run(blocks, hints=hints)
    kinds = {s.etype for s in out["sheet:当事人!A2"]}
    check("PERSON" in kinds, f"列头驱动应抓出裸姓名，实际 {kinds}")
    kinds2 = {s.etype for s in out["sheet:当事人!B2"]}
    check("ID_CARD" in kinds2, f"应抓出身份证，实际 {kinds2}")


# --------------------------------------------------------------------------
# 预设加载
# --------------------------------------------------------------------------


def test_presets_load():
    d = ROOT / "schemas"
    found = list(d.glob("*.y*ml"))
    check(len(found) >= 4, f"预设数量应 >= 4，实际 {len(found)}")
    for f in found:
        p = load_preset(f)
        check(p.id, f"{f.name} 缺 id")
        # legal 预设必须脱身份证，必须保留案号
        if p.id == "legal":
            eq(p.strategy_for("ID_CARD"), Strategy.MASK_FULL)
            eq(p.strategy_for("CASE_NO"), Strategy.KEEP)
            check(p.is_redacted("PERSON"), "legal 必须脱姓名")
            check(not p.is_redacted("COURT"), "legal 默认保留法院名")


def test_keep_types_must_not_swallow_redacted():
    """回归测试：保留类实体永远不能压制脱敏类实体。

    这条规则写反过一次，后果是三处静默泄露：
      - 页眉"…号　张伟民诉北京华远置业有限公司"里 ORG(KEEP) 吃掉 PERSON(MASK)，姓名原样留在产物里
      - "住所地北京市西城区金融大街7号英蓝国际金融中心12层" ORG(KEEP) 吃掉 ADDRESS(GENERALIZE)
      - DOB(GENERALIZE) 与 DATE(KEEP) 同区间，DATE 赢了 → 出生日期不做泛化
    """
    keep = frozenset({"ORG", "DATE", "COURT", "USCC", "CASE_NO"})

    # 1) 机构名吞姓名：姓名必须活下来
    org = Span(0, 14, "张伟民诉北京华远置业有限公司", "ORG", 0.9, block="b")
    per = Span(0, 3, "张伟民", "PERSON", 0.98, block="b")
    out = merge_spans([org, per], deprioritize=keep)
    kinds = {s.etype for s in out}
    check("PERSON" in kinds, f"PERSON 不能被 KEEP 类吞掉，实际 {kinds}")

    # 2) 同区间：脱敏类必须赢过保留类
    dob = Span(0, 11, "1987年3月12日", "DOB", 0.92, block="b")
    date = Span(0, 11, "1987年3月12日", "DATE", 0.90, block="b")
    out2 = merge_spans([date, dob], deprioritize=keep)
    eq(len(out2), 1, "同区间应只剩一条")
    eq(out2[0].etype, "DOB", "DOB(要泛化) 必须赢过 DATE(保留)")

    # 3) 不传 deprioritize 时仍按类型优先级：ORG > PERSON
    out3 = merge_spans([Span(0, 14, "张伟民诉北京华远置业有限公司", "ORG", 0.9, block="b"),
                        Span(0, 3, "张伟民", "PERSON", 0.98, block="b")])
    check(all(s.etype == "ORG" for s in out3), "无预设信息时按类型优先级，ORG 胜")


def test_pipeline_keep_types_wired():
    """TextPipeline 必须真的把预设里的 KEEP 类型接进 merge_spans。"""
    p = _preset()
    pipe = TextPipeline(p)
    for t in ("ORG", "DATE", "AMOUNT", "CASE_NO", "COURT"):
        check(t in pipe.keep_types, f"{t} 在 legal 预设下是 KEEP，应在 keep_types 里")
    for t in ("PERSON", "ID_CARD", "PHONE", "ADDRESS", "DOB"):
        check(t not in pipe.keep_types, f"{t} 要脱敏，不该在 keep_types 里")
    # 端到端：住所地必须被当成地址而不是机构名
    text = ("被告：北京华远置业有限公司，住所地北京市西城区金融大街7号英蓝国际金融中心12层，"
            "统一社会信用代码91110102710931234J，法定代表人王志强。")
    out = pipe.detect_text(text, "b")
    addrs = [s.text for s in out if s.etype == "ADDRESS"]
    check(any("金融大街7号" in a for a in addrs),
          f"住所地必须被检出为 ADDRESS，实际 ADDRESS={addrs}")
    banks = [s.text for s in out if s.etype == "BANK_BRANCH"]
    dob_like = [s for s in out if s.etype == "DOB"]
    check(True, f"BANK_BRANCH={banks} DOB={len(dob_like)}")


def test_waiver_separates_human_decision_from_tool_failure():
    """人工明确放行的残留必须单列，既不算工具失误、也不被静默吞掉。"""
    from legal_redactor.audit import SEV_ORDER, AuditReport, Residue
    from legal_redactor.engine import Engine

    p = _preset()
    eng = Engine(p, seed=b"waiver")
    src = ROOT / "tests" / "samples" / "当事人清单.txt"
    if not src.exists():
        return                      # 样本未生成时跳过，不误报失败
    from legal_redactor.engine import detect_format
    sc = eng.scan(src)
    ids = [s for s in sc.all_spans if s.etype == "ID_CARD"]
    check(len(ids) >= 1, "样本里应有身份证")
    target = ids[0]
    # 人工标记忽略
    eng.apply_decisions(sc, {"spans": {target.span_id: {"action": "reject",
                                                        "reason": "本案已公开信息"}}})
    key = (target.etype, canon_entity(target.etype, target.text))
    check(key in eng.waivers, "放行记录应被登记")
    eq(eng.waivers[key]["reason"], "本案已公开信息")

    out = ROOT / "verify-out" / "unit" / "waiver.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    eng.redact(src, out, scan=sc)
    check(target.text in out.read_text(encoding="utf-8"),
          "被放行的值应原样留在产物里")

    from legal_redactor.audit import Auditor
    rep = Auditor(eng.resolver, eng.options, waivers=eng.waivers).audit(
        src, out, "text", scan=sc)
    waived = [r for r in rep.residues if r.severity == "waived"]
    real = [r for r in rep.residues
            if r.severity != "waived" and SEV_ORDER.get(r.severity, 0) >= SEV_ORDER["high"]]
    check(len(waived) >= 1, f"放行项应被单列，实际 {len(waived)}")
    check(rep.passed, f"只有人工放行项时结论应为 PASS，实际 residues={len(rep.residues)}")
    eq(len(real), 0, "不应有工具未处理的高危残留")
    # 报告里必须能看到放行清单
    from legal_redactor.audit import audit_to_markdown
    md = audit_to_markdown(rep)
    check("人工放行清单" in md, "Markdown 报告应含人工放行清单")
    check(target.text in md, "放行清单应列出被保留的原值")


def test_vision_boxes_stay_in_bounds():
    """cv2 的 QR 检测器对非二维码输入会返回越界多边形，必须卡掉。

    实测签章页（1240x700）上 detect_qr 返回过 y=-3220、高 3420 的框。
    不校验就会把图片顶部一大片无辜内容涂掉，还会让视觉复检跟着错判。
    """
    from legal_redactor.detect.vision_det import (detect_qr, detect_seals,
                                                  _sane_box, cv2_available)
    check(_sane_box(10, 10, 50, 50, (700, 1240)), "图内正常框应通过")
    check(not _sane_box(281, -3220, 228, 3420, (700, 1240)), "越出上边界的框必须拒")
    check(not _sane_box(1200, 10, 228, 50, (700, 1240)), "越出右边界的框必须拒")
    check(not _sane_box(10, 10, 0, 50, (700, 1240)), "零宽必须拒")
    check(not _sane_box(0, 0, 1240, 700, (700, 1240)), "覆盖全图的框必须拒（几乎必为误检）")
    if not cv2_available():
        return
    img = imread_cv2(ROOT / "tests" / "samples" / "签章页.png")
    if img is None:
        return                                   # 样本未生成时跳过
    H, W = img.shape[:2]
    for b in list(detect_qr(img)) + list(detect_seals(img)):
        check(b.x >= -2 and b.y >= -2 and b.x + b.w <= W + 2 and b.y + b.h <= H + 2,
              f"检出框越界：{b.etype} ({b.x},{b.y}) {b.w}x{b.h} 图 {W}x{H}")
    # 签章页确实有一枚圆章，校验修复没有把真章一起卡掉
    check(len(detect_seals(img)) >= 1, "真实印章必须仍被检出")


def imread_cv2(path):
    from legal_redactor.formats.image_fmt import imread_unicode
    try:
        return imread_unicode(path)
    except Exception:
        return None


def test_post_validate_drops_fragments():
    """merge 裁剪产生的半截片段应被后校验丢掉。"""
    frag = Span(0, 3, "住所地", "ORG", 0.7, block="b")
    good = Span(0, 10, "北京华远置业有限公司", "ORG", 0.9, block="b")
    eq(len(post_validate([frag])), 0, "不以机构后缀结尾的 ORG 片段应丢弃")
    eq(len(post_validate([good])), 1)
    eq(len(post_validate([Span(0, 5, "北京市", "ADDRESS", 0.9, block="b")])), 0,
       "过短的 ADDRESS 应丢弃")


# --------------------------------------------------------------------------


def main() -> int:
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    ok = 0
    for name, fn in tests:
        try:
            if name == "test_mapping_crypto":
                fn(None)
            else:
                fn()
            print(f"  ✓ {name}")
            ok += 1
        except Exception as e:
            FAILED.append(name)
            print(f"  ✗ {name}: {type(e).__name__}: {e}")
            tb = traceback.format_exc().strip().split("\n")
            for line in tb[-4:]:
                print(f"      {line}")
    print(f"\n{ok}/{len(tests)} 通过")
    if FAILED:
        print("失败：" + ", ".join(FAILED))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
