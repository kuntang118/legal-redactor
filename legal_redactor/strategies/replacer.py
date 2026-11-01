"""脱敏替换策略实现。

每个策略都是纯函数：给定 (实体类型, 原文, 选项) → 替换串。
一致性（同一实体全批次同一替换）由 resolver.EntityResolver 负责，
这里只管"一个值该变成什么样"。
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import re
from typing import Any, Mapping

from ..core import Strategy
from ..detect.addr_det import truncate_to_level
from ..detect.legal_det import amount_to_range

# --------------------------------------------------------------------------
# 常量
# --------------------------------------------------------------------------

DEFAULT_PLACEHOLDER = "[已脱敏]"
MASK_CHAR = "■"

# 各类型 PARTIAL 策略的保留规则：(前保留位数, 后保留位数)
PARTIAL_RULES: dict[str, tuple[int, int]] = {
    "PHONE": (3, 4),
    "TEL": (3, 4),
    "ID_CARD": (6, 4),
    "SUSPECT_ID": (6, 2),
    "BANK_CARD": (0, 4),
    "USCC": (4, 4),
    "PASSPORT": (1, 2),
    "HK_MO_PERMIT": (1, 2),
    "LICENSE_NO": (4, 2),
    "EMAIL": (1, 0),          # 特殊处理：保留首字母 + 完整域名
    "MAC_ADDR": (0, 5),
    "IP_ADDR": (0, 0),        # 特殊处理：保留前两段
    "PLATE": (2, 1),
    "IM_ACCOUNT": (1, 1),
}

# 各类型 CODE 策略的前缀
CODE_PREFIX: dict[str, str] = {
    "PERSON": "当事人",
    "ORG": "单位",
    "COURT": "法院",
    "LAW_FIRM": "律所",
    "ADDRESS": "地址",
    "BANK_BRANCH": "银行",
    "ID_CARD": "证件",
    "PHONE": "电话",
    "TEL": "电话",
    "EMAIL": "邮箱",
    "BANK_CARD": "账户",
    "USCC": "信用代码",
    "PLATE": "车辆",
    "CASE_NO": "案号",
    "DOB": "出生日期",
    "DATE": "日期",
    "AMOUNT": "金额",
    "SEAL": "印章",
    "QR_CODE": "码",
    "IMG_TEXT": "图内文字",
    "MINOR_INFO": "未成年人信息",
    "MEDICAL": "医疗信息",
}


# --------------------------------------------------------------------------
# 中文数字
# --------------------------------------------------------------------------

_CN_DIGIT_MAP = {
    "〇": 0, "零": 0, "○": 0, "Ｏ": 0,
    "一": 1, "壹": 1, "１": 1,
    "二": 2, "贰": 2, "两": 2, "２": 2,
    "三": 3, "叁": 3, "３": 3,
    "四": 4, "肆": 4, "４": 4,
    "五": 5, "伍": 5, "５": 5,
    "六": 6, "陆": 6, "６": 6,
    "七": 7, "柒": 7, "７": 7,
    "八": 8, "捌": 8, "８": 8,
    "九": 9, "玖": 9, "９": 9,
}
_CN_UNIT_MAP = {"十": 10, "拾": 10, "百": 100, "佰": 100, "千": 1000, "仟": 1000}
_DIGIT_TO_CN = "〇一二三四五六七八九"


def cn_to_int(s: str) -> int | None:
    """中文数字转整数，支持"二〇二三"（逐位）与"二十""十五""三十一"（位值）两种写法。"""
    s = s.strip()
    if not s:
        return None
    if s.isdigit():
        return int(s)
    # 逐位写法：全部是数位字符且无单位
    if all(c in _CN_DIGIT_MAP for c in s):
        try:
            return int("".join(str(_CN_DIGIT_MAP[c]) for c in s))
        except Exception:
            return None
    # 位值写法
    if any(c in _CN_UNIT_MAP for c in s):
        total = 0
        cur = 0
        for c in s:
            if c in _CN_DIGIT_MAP:
                cur = _CN_DIGIT_MAP[c]
            elif c in _CN_UNIT_MAP:
                u = _CN_UNIT_MAP[c]
                total += (cur if cur else 1) * u
                cur = 0
            else:
                return None
        return total + cur
    return None


def int_to_cn_digits(n: int) -> str:
    """整数转逐位中文（年份用）：2023 → 二〇二三。"""
    return "".join(_DIGIT_TO_CN[int(d)] for d in str(n))


def int_to_cn_value(n: int) -> str:
    """整数转位值中文（月日用）：20 → 二十，5 → 五，10 → 十。"""
    if n <= 0:
        return str(n)
    if n < 10:
        return _DIGIT_TO_CN[n]
    if n < 20:
        return "十" + (_DIGIT_TO_CN[n % 10] if n % 10 else "")
    if n < 100:
        return _DIGIT_TO_CN[n // 10] + "十" + (_DIGIT_TO_CN[n % 10] if n % 10 else "")
    return str(n)


# --------------------------------------------------------------------------
# 日期解析与重写
# --------------------------------------------------------------------------

_DATE_PATTERNS = [
    # (正则, 是否为中文数字格式)
    (re.compile(r"^(?P<y>(?:19|20)\d{2})年(?P<m>1[0-2]|0?[1-9])月(?P<d>3[01]|[12]\d|0?[1-9])[日号]?$"), False),
    (re.compile(r"^(?P<y>(?:19|20)\d{2})年(?P<m>1[0-2]|0?[1-9])月$"), False),
    (re.compile(r"^(?P<y>(?:19|20)\d{2})年$"), False),
    (re.compile(r"^(?P<y>(?:19|20)\d{2})[-/.](?P<m>0?[1-9]|1[0-2])[-/.](?P<d>0?[1-9]|[12]\d|3[01])$"), False),
    (re.compile(r"^(?P<y>(?:19|20)\d{2})[-/.](?P<m>0?[1-9]|1[0-2])$"), False),
]
_CN_DATE_PATTERNS = [
    # 量词必须用懒惰匹配：贪婪的 {1,3} 会把"二十日"整块吞进日组，
    # 导致 cn_to_int 拿到"二十日"而返回 None，整条中文日期解析失败
    (re.compile(r"^(?P<y>[\u4e00-\u9fa5〇零○Ｏ１２３４５６７８９0-9]{2,5}?)年"
                r"(?P<m>[\u4e00-\u9fa5]{1,3}?)月(?P<d>[\u4e00-\u9fa5]{1,3}?)[日号]?$"), True),
    (re.compile(r"^(?P<y>[\u4e00-\u9fa5〇零○Ｏ0-9]{2,5}?)年(?P<m>[\u4e00-\u9fa5]{1,3}?)月$"), True),
    (re.compile(r"^(?P<y>[\u4e00-\u9fa5〇零○Ｏ0-9]{2,5}?)年$"), True),
]


def parse_date(text: str) -> tuple[_dt.date | None, str]:
    """解析日期文本，返回 (date 或 None, 格式标签)。

    格式标签用于按原样式重写：'cn_ymd' / 'cn_ym' / 'cn_y' / 'iso_ymd' / 'iso_ym' / 'num_ymd' …
    """
    t = text.strip()
    for rx, _ in _DATE_PATTERNS:
        m = rx.match(t)
        if not m:
            continue
        gd = m.groupdict()
        y = int(gd["y"])
        mo = int(gd.get("m") or 1)
        d = int(gd.get("d") or 1)
        try:
            dt = _dt.date(y, mo, d)
        except ValueError:
            continue
        kind = "num_ymd" if "d" in gd else ("num_ym" if "m" in gd else "num_y")
        if rx.pattern.startswith(r"^(?P<y>(?:19|20)\d{2})[-/.]"):
            kind = kind.replace("num_", "iso_")
        return dt, kind
    for rx, _ in _CN_DATE_PATTERNS:
        m = rx.match(t)
        if not m:
            continue
        gd = m.groupdict()
        y = cn_to_int(gd["y"])
        mo = cn_to_int(gd.get("m") or "一")
        d = cn_to_int(gd.get("d") or "一")
        if y is None or mo is None or d is None:
            continue
        try:
            dt = _dt.date(y, mo, d)
        except ValueError:
            continue
        kind = "cn_ymd" if "d" in gd else ("cn_ym" if "m" in gd else "cn_y")
        return dt, kind
    return None, ""


def format_date(dt: _dt.date, kind: str) -> str:
    """按原格式标签重写日期。

    注意：ISO 风格的分隔符与补零不逐一还原（2023/6/15 会写成 2023-06-15）。
    这是有意的取舍——DATE 在法律预设下默认 KEEP，只有医疗等场景才会用
    DATE_SHIFT/GENERALIZE，此时统一成标准 ISO 既不影响可读性也不产生泄露。
    """
    y, m, d = dt.year, dt.month, dt.day
    if kind == "num_ymd":
        return f"{y}年{m}月{d}日"
    if kind == "num_ym":
        return f"{y}年{m}月"
    if kind == "num_y":
        return f"{y}年"
    if kind == "iso_ymd":
        return f"{y}-{m:02d}-{d:02d}"
    if kind == "iso_ym":
        return f"{y}-{m:02d}"
    if kind == "iso_y":
        return f"{y}"
    if kind == "cn_ymd":
        return f"{int_to_cn_digits(y)}年{int_to_cn_value(m)}月{int_to_cn_value(d)}日"
    if kind == "cn_ym":
        return f"{int_to_cn_digits(y)}年{int_to_cn_value(m)}月"
    if kind == "cn_y":
        return f"{int_to_cn_digits(y)}年"
    return f"{y}年{m}月{d}日"


def generalize_date(text: str, level: str) -> str:
    """日期泛化。level: year | month | day | hide"""
    dt, kind = parse_date(text)
    if dt is None:
        return DEFAULT_PLACEHOLDER
    if level == "hide":
        return "[日期已脱敏]"
    if level == "year":
        y_kind = kind if kind.endswith("_y") else kind.replace("ymd", "y").replace("ym", "y")
        return format_date(_dt.date(dt.year, 1, 1), y_kind)
    if level == "month":
        if kind.endswith("_y"):
            return format_date(dt, kind)
        return format_date(_dt.date(dt.year, dt.month, 1), kind.replace("ymd", "ym"))
    return text


# --------------------------------------------------------------------------
# 各策略
# --------------------------------------------------------------------------


def mask_person(name: str, mode: str = "surname") -> str:
    """姓名遮盖。法律文书惯例：张三→张某，张三丰→张某某。"""
    from ..detect.lexicon import COMPOUND_SURNAMES

    if not name:
        return DEFAULT_PLACEHOLDER
    if name.endswith("某"):
        return name  # 已匿名，幂等
    surname = name[0]
    for cs in COMPOUND_SURNAMES:
        if name.startswith(cs):
            surname = cs
            break
    body_len = len(name) - len(surname)
    if mode == "full":
        return "某" * len(name)
    if mode == "surname_only":
        return surname
    return surname + "某" * max(1, body_len)


def mask_org(name: str, etype: str) -> str:
    """机构名遮盖：保留"是什么类型的机构"，去掉"是哪一家"。

    法律读者需要知道"这是一间律所""这是一家有限公司"才能读懂文书，
    但不需要知道具体是哪家。逐字盖成"北某某某某某某某某所"既难读，
    又把"律师事务所"这个类型信息一起毁了（实测产物就是这样）。
    """
    from ..detect.lexicon import COURT_SUFFIXES, ORG_SUFFIXES

    if not name:
        return DEFAULT_PLACEHOLDER
    if etype == "LAW_FIRM":
        return name[0] + "某某律师事务所"
    if etype == "COURT":
        for suf in sorted(set(COURT_SUFFIXES), key=len, reverse=True):
            if name.endswith(suf):
                head = name[: -len(suf)]
                # 保留到第一个行政区后缀为止（北京市 / 广东省 / 海淀区），
                # 读者仍能看出审级与地域范围，但定位不到具体法院
                m = re.search(r"(自治区|自治州|特别行政区|省|市|县|区|旗)", head)
                keep = head[: m.end()] if (m and m.end() <= 4) else head[:2]
                return (keep + "某" if keep else "某") + suf
        return "某司法机关"
    if etype == "BANK_BRANCH":
        m = re.search(r"(农村商业银行|农村信用合作联社|村镇银行|银行|信用社)", name)
        b = re.search(r"(分行|支行|分理处|营业部|营业室|储蓄所|办事处|分社)$", name)
        brand = m.group(1) if m else "银行"
        return name[0] + "某某" + brand + ("某" + b.group(1) if b else "")
    for suf in sorted(set(ORG_SUFFIXES), key=len, reverse=True):
        if name.endswith(suf):
            return name[0] + "某某" + suf
    if len(name) <= 2:
        return name[0] + "某"
    return name[0] + "某" * (len(name) - 2) + name[-1]


def mask_full(text: str, placeholder: str | None = None, shape: str = "placeholder") -> str:
    """整体遮盖。shape: placeholder（[已脱敏]）| block（■■■，保留长度）| fixed（固定长度）"""
    if shape == "block":
        return MASK_CHAR * max(1, len(text))
    if shape == "fixed":
        return MASK_CHAR * 6
    return placeholder or DEFAULT_PLACEHOLDER


def partial_mask(etype: str, text: str, opts: Mapping[str, Any] | None = None) -> str:
    """部分保留。规则见 PARTIAL_RULES，可被 opts 覆盖。"""
    opts = dict(opts or {})
    if etype == "EMAIL":
        keep_domain = opts.get("email_keep_domain", True)
        local, _, dom = text.partition("@")
        if not dom:
            return mask_full(text)
        head = opts.get("email_keep_head", 1)
        return (local[:head] + "***" + ("@" + dom if keep_domain else "@***"))
    if etype == "IP_ADDR":
        segs = text.split(".")
        keep = int(opts.get("ip_keep_segments", 2))
        return ".".join(segs[:keep] + ["*"] * (len(segs) - keep))
    if etype == "MAC_ADDR":
        parts = re.split(r"[:\-]", text)
        return ":".join(["*"] * (len(parts) - 1) + parts[-1:])

    head, tail = PARTIAL_RULES.get(etype, (0, 0))
    head = int(opts.get(f"{etype.lower()}_keep_head", head))
    tail = int(opts.get(f"{etype.lower()}_keep_tail", tail))
    digits = text
    if len(digits) <= head + tail:
        return mask_full(digits, shape="block")
    mid_len = len(digits) - head - tail
    # 保留原文里的分隔符样式：直接按位置遮
    out = []
    replaced = 0
    for ch in digits:
        if ch in "- 　":
            out.append(ch)
            continue
        idx = len([c for c in out if c not in "- 　"])
        if idx < head or idx >= head + mid_len:
            out.append(ch)
        else:
            out.append("*")
            replaced += 1
    return "".join(out)


def generalize(etype: str, text: str, opts: Mapping[str, Any] | None = None,
               attrs: Mapping[str, Any] | None = None) -> str:
    """泛化：把精确值降到一个区间/上位概念，抗组合重识别。"""
    opts = dict(opts or {})
    attrs = dict(attrs or {})

    if etype == "ADDRESS":
        level = int(opts.get("address_level", 3))
        return truncate_to_level(text, level)

    if etype in ("DOB", "DATE"):
        level = opts.get("dob_level" if etype == "DOB" else "date_level", "year")
        return generalize_date(text, level)

    if etype == "AMOUNT":
        v = attrs.get("value")
        if v is None:
            m = re.search(r"(\d[\d,]*(?:\.\d+)?)\s*(亿元|万元|千元|元|圆)", text)
            if m:
                mult = {"亿元": 1e8, "万元": 1e4, "千元": 1e3, "元": 1.0, "圆": 1.0}[m.group(2)]
                v = float(m.group(1).replace(",", "")) * mult
        if opts.get("amount_mode", "range") == "hide":
            return "[金额已脱敏]"
        return amount_to_range(v if v is not None else 0.0)

    if etype == "ID_CARD":
        # 只保留省级地区码，其余全遮；出生日期是重识别关键，不留
        keep = int(opts.get("id_keep_prefix", 2))
        return text[:keep] + "*" * max(0, len(text) - keep)

    if etype == "PHONE":
        return text[:3] + "********"

    if etype == "BANK_CARD":
        return "****" + text[-4:] if len(text) >= 4 else mask_full(text)

    if etype == "PERSON":
        return mask_person(text, opts.get("person_mask_mode", "surname"))

    return mask_full(text)


def hash_pseudo(etype: str, text: str, key: bytes, length: int = 8) -> str:
    """HMAC 假名：跨库可关联，但不暴露原值。"""
    h = hmac.new(key, f"{etype}|{text}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{CODE_PREFIX.get(etype, 'X')[0]}#{h[:length].upper()}"


def shift_date(text: str, days: int) -> str:
    """日期平移，保持相对间隔（医疗/时间序列分析场景）。"""
    dt, kind = parse_date(text)
    if dt is None:
        return text
    try:
        return format_date(dt + _dt.timedelta(days=days), kind)
    except (OverflowError, ValueError):
        return text


def delete(_etype: str, _text: str) -> str:
    return ""


# --------------------------------------------------------------------------
# 统一入口
# --------------------------------------------------------------------------


def apply_strategy(strategy: Strategy, etype: str, text: str,
                   opts: Mapping[str, Any] | None = None,
                   attrs: Mapping[str, Any] | None = None,
                   pseudo: str | None = None,
                   code: str | None = None,
                   key: bytes = b"") -> str:
    """按策略算出替换串。pseudo/code 由 EntityResolver 提供以保证一致性。"""
    opts = dict(opts or {})
    attrs = dict(attrs or {})
    s = Strategy(strategy)

    if s == Strategy.KEEP:
        return text
    if s == Strategy.DELETE:
        return ""
    if s == Strategy.MASK:
        if etype == "PERSON":
            return mask_person(text, opts.get("person_mask_mode", "surname"))
        if etype in ("ORG", "LAW_FIRM", "COURT", "BANK_BRANCH"):
            return mask_org(text, etype)
        if etype == "ADDRESS":
            return generalize("ADDRESS", text, opts, attrs)
        return mask_full(text, opts.get("placeholder"), opts.get("mask_shape", "placeholder"))
    if s == Strategy.MASK_FULL:
        return mask_full(text, opts.get("placeholder"), opts.get("mask_shape", "placeholder"))
    if s == Strategy.PARTIAL:
        return partial_mask(etype, text, opts)
    if s == Strategy.PSEUDO:
        if pseudo is None:
            return mask_full(text, opts.get("placeholder"), "placeholder")
        return pseudo
    if s == Strategy.CODE:
        if code is None:
            return mask_full(text, opts.get("placeholder"), "placeholder")
        return code
    if s == Strategy.GENERALIZE:
        return generalize(etype, text, opts, attrs)
    if s == Strategy.DATE_SHIFT:
        return shift_date(text, int(opts.get("date_shift_days", -365)))
    if s == Strategy.HASH:
        return hash_pseudo(etype, text, key or b"legal-redactor",
                           int(opts.get("hash_length", 8)))
    return mask_full(text)
