"""法律领域实体：案号、金额、日期、出生日期、未成年人信息、医疗信息。"""
from __future__ import annotations

import re
from typing import Iterable

from ..core import Span
from .base import Detector
from . import lexicon as L

# --------------------------------------------------------------------------
# 案号
# --------------------------------------------------------------------------


class CaseNoDetector(Detector):
    name = "case_no"
    produces = ("CASE_NO",)

    def detect(self, text: str, block: str = "body") -> list[Span]:
        out = []
        for m in L.CASE_NO_RE.finditer(text):
            raw = m.group(0)
            year = m.group(1)
            court_code = m.group(2)
            kind = m.group(3)
            num = m.group(4)
            if not (1980 <= int(year) <= 2100):
                continue
            out.append(Span(m.start(), m.end(), raw, "CASE_NO", confidence=0.97,
                            source=self.name,
                            reason=f"案号：{year}年 / 法院代字{court_code} / 案件类型{kind} / 序号{num}",
                            attrs={"year": year, "court_code": court_code, "kind": kind, "no": num},
                            block=block))
        return out


# --------------------------------------------------------------------------
# 金额
# --------------------------------------------------------------------------

_CN_DIGITS = "零壹贰叁肆伍陆柒捌玖拾佰仟萬"
_AMOUNT_RE = re.compile(
    r"(?:人民币|RMB|¥|￥)?\s*"
    r"(\d{1,3}(?:,\d{3})+|\d+)"
    r"(?:\.(\d{1,2}))?\s*"
    r"(亿元|万元|千元|百元|元|圆)"
    r"(?:\s*(余|多|左右|以上|以下|整))?"
)
_CN_AMOUNT_RE = re.compile(
    rf"[{_CN_DIGITS}]{{1,12}}(?:元|圆)(?:整|正|[{_CN_DIGITS}]{{1,6}}[角分])?"
)
_AMOUNT_RANGE_RE = re.compile(
    r"(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d{1,2}))?\s*(亿元|万元|元|圆)"
    r"\s*(?:至|到|-|~|—)\s*"
    r"(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d{1,2}))?\s*(亿元|万元|元|圆)"
)


def amount_to_float(m: re.Match) -> float | None:
    try:
        base = float(m.group(1).replace(",", ""))
        if m.group(2):
            base = float(m.group(1).replace(",", "") + "." + m.group(2))
        unit = m.group(3)
        mult = {"亿元": 1e8, "万元": 1e4, "千元": 1e3, "百元": 1e2, "元": 1.0, "圆": 1.0}[unit]
        return base * mult
    except Exception:
        return None


def amount_to_range(v: float) -> str:
    """金额泛化：落到数量级区间。"""
    if v is None:
        return "[金额已脱敏]"
    if v < 1000:
        return "1000元以下"
    if v < 10000:
        lo = int(v // 1000) * 1000
        return f"{lo}元至{lo + 1000}元"
    if v < 100000:
        lo = int(v // 10000) * 10000
        return f"{lo // 10000}万元至{(lo + 10000) // 10000}万元"
    if v < 1000000:
        lo = int(v // 100000) * 100000
        return f"{lo // 10000}万元至{(lo + 100000) // 10000}万元"
    if v < 100000000:
        lo = int(v // 1000000) * 1000000
        return f"{lo // 10000}万元至{(lo + 1000000) // 10000}万元"
    lo = int(v // 100000000) * 100000000
    return f"{lo // 100000000}亿元至{(lo + 100000000) // 100000000}亿元"


class AmountDetector(Detector):
    name = "amount"
    produces = ("AMOUNT",)

    def detect(self, text: str, block: str = "body") -> list[Span]:
        out = []
        # 区间先匹配，避免被拆成两个单值
        ranges = []
        for m in _AMOUNT_RANGE_RE.finditer(text):
            ranges.append((m.start(), m.end()))
            out.append(Span(m.start(), m.end(), m.group(0), "AMOUNT", confidence=0.9,
                            source=self.name, reason="金额区间",
                            attrs={"kind": "range"}, block=block))
        for m in _AMOUNT_RE.finditer(text):
            if any(a <= m.start() < b or a < m.end() <= b for a, b in ranges):
                continue
            v = amount_to_float(m)
            # 过滤明显非金额：法条序号（"第X条"）、条目编号
            # 只在紧邻位置判断，不能用大窗口——否则"注册资本5000万元"会被"日"误杀
            ctx_a = max(0, m.start() - 10)
            ctx = text[ctx_a:m.start()]
            if re.search(r"(第\s*[一二三四五六七八九十百千\d]+\s*[条款项章节]|[条款项章节]\s*|"
                         r"^[一二三四五六七八九十]+\s*[、.]\s*$)", ctx):
                continue
            # 纯"X元"且前面紧贴年/月/日 → 更像日期后的编号
            if m.group(3) == "元" and re.search(r"(年|月|日|号)$", ctx) and not re.search(
                    r"(人民币|价款|赔偿|支付|给付|返还|借款|欠款|租金|工资|报酬|费用|定金|押金)$", ctx):
                continue
            if m.group(3) in ("元", "圆") and v is not None and v > 1e12:
                continue
            out.append(Span(m.start(), m.end(), m.group(0), "AMOUNT", confidence=0.88,
                            source=self.name, reason=f"金额，折算约{v:.0f}元" if v else "金额",
                            attrs={"kind": "arabic", "value": v}, block=block))
        for m in _CN_AMOUNT_RE.finditer(text):
            if any(a <= m.start() < b for a, b in ranges):
                continue
            out.append(Span(m.start(), m.end(), m.group(0), "AMOUNT", confidence=0.85,
                            source=self.name, reason="中文大写金额",
                            attrs={"kind": "cn"}, block=block))
        return out


# --------------------------------------------------------------------------
# 日期 / 出生日期
# --------------------------------------------------------------------------

_CN_NUM = "〇零一二三四五六七八九十○Ｏ0１２３４５６７８９"
_DATE_RE = re.compile(
    rf"(?:(?P<y1>(?:19|20)\d{{2}})|(?P<y2>[{_CN_NUM}]{{4}}))\s*年"
    rf"\s*(?:(?P<m1>1[0-2]|0?[1-9])|(?P<m2>[十]?[{_CN_NUM}]{{1,2}}))\s*月"
    rf"(?:\s*(?:(?P<d1>3[01]|[12]\d|0?[1-9])|(?P<d2>[{_CN_NUM}]{{1,3}}))\s*[日号])?"
)
_DATE_ISO_RE = re.compile(r"(?<!\d)((?:19|20)\d{2})[-/.](0?[1-9]|1[0-2])(?:[-/.](0?[1-9]|[12]\d|3[01]))?(?!\d)")

_DOB_HINT_RE = re.compile(
    r"(出生日期|出生年月|出生年月日|生于|出生于|出生时间|生日)[：:\s]*"
)
_DOB_TAIL_RE = re.compile(r"(出生|生\b|年生)")


class DateDetector(Detector):
    name = "date"
    produces = ("DATE", "DOB")

    def detect(self, text: str, block: str = "body") -> list[Span]:
        out: list[Span] = []
        dob_spans: list[Span] = []

        # 出生日期：提示词 + 日期。span 只覆盖日期本体，不含提示词
        for m in _DOB_HINT_RE.finditer(text):
            d = self._match_date_at(text, m.end())
            if d:
                s, e, val = d
                dob_spans.append(Span(s, e, val, "DOB",
                                      confidence=0.95, source=self.name,
                                      reason=f"出生日期提示词'{m.group(1)}'后的日期",
                                      attrs={"date": val, "hint": m.group(1)}, block=block))
        # 出生日期：日期 + "出生"。span 只覆盖日期本身，
        # 不含"出生"二字，否则泛化后会把动词一起吃掉
        for m in _DATE_RE.finditer(text):
            tail = text[m.end():m.end() + 4]
            tm = _DOB_TAIL_RE.match(tail)
            if tm:
                out_dob = Span(m.start(), m.end(), m.group(0), "DOB",
                               confidence=0.92, source=self.name,
                               reason=f"日期后紧跟'{tm.group(0)}'",
                               attrs={"date": m.group(0), "year": self._year(m)},
                               block=block)
                dob_spans.append(out_dob)

        out.extend(dob_spans)

        # 普通日期
        for m in _DATE_RE.finditer(text):
            if m.group(0).strip() in ("", "年"):
                continue
            out.append(Span(m.start(), m.end(), m.group(0), "DATE", confidence=0.9,
                            source=self.name, reason="中文日期",
                            attrs={"year": self._year(m)}, block=block))
        for m in _DATE_ISO_RE.finditer(text):
            out.append(Span(m.start(), m.end(), m.group(0), "DATE", confidence=0.85,
                            source=self.name, reason="ISO 风格日期",
                            attrs={"year": m.group(1)}, block=block))
        return out

    @staticmethod
    def _year(m: re.Match) -> str:
        return m.group("y1") or m.group("y2") or ""

    def _match_date_at(self, text: str, pos: int):
        m = _DATE_RE.match(text, pos)
        if not m:
            m2 = _DATE_ISO_RE.match(text, pos)
            if m2:
                return m2.start(), m2.end(), m2.group(0)
            return None
        return m.start(), m.end(), m.group(0)


# --------------------------------------------------------------------------
# 未成年人信息（区域标记）
# --------------------------------------------------------------------------


class MinorInfoDetector(Detector):
    """未成年人信息区域标记。

    产出的是"区域"，engine 会把落在该区域内的 PERSON / DOB / ADDRESS / ID_CARD
    强制升级到 MASK_FULL，对应《最高人民法院关于人民法院在互联网公布裁判文书的规定》
    第十条对未成年人信息的删除处理要求。

    区域边界不能简单取 ±N 字：那样会把紧随其后的成年证人信息一起吃掉。
    实际边界是"上一个角色词/句读"到"下一个角色词/句读"。
    """

    name = "minor"
    produces = ("MINOR_INFO",)

    WINDOW = 200
    # 只用句末标点做边界，不用换行——中文法律文书的换行是排版而非语义边界，
    # 用换行会把同一个人的身份证号/电话切到区域外
    _BOUNDARY_RE = re.compile(r"[。；;！!？?]")

    def detect(self, text: str, block: str = "body") -> list[Span]:
        from .name_det import TRIGGER_RE

        out = []
        for m in L.MINOR_HINT_RE.finditer(text):
            # 向前找最近的句读或角色词
            lo = max(0, m.start() - self.WINDOW)
            ws = lo
            for bm in self._BOUNDARY_RE.finditer(text, lo, m.start()):
                ws = bm.end()
            for tm in TRIGGER_RE.finditer(text, ws, m.start()):
                ws = tm.start()
            # 向后找最近的句读或角色词
            hi = min(len(text), m.end() + self.WINDOW)
            we = hi
            bm = self._BOUNDARY_RE.search(text, m.end(), hi)
            if bm:
                we = bm.start()
            tm = TRIGGER_RE.search(text, m.end(), we)
            if tm:
                we = min(we, tm.start())
            out.append(Span(m.start(), m.end(), m.group(0), "MINOR_INFO",
                            confidence=0.9, source=self.name,
                            reason=f"未成年人提示词；作用区域 [{ws},{we}) 内身份信息强制脱敏",
                            attrs={"window_start": ws, "window_end": we},
                            block=block))
        return out


# --------------------------------------------------------------------------
# 医疗信息（区域标记）
# --------------------------------------------------------------------------

_MED_RE = re.compile(
    r"(病历号|病案号|住院号|门诊号|就诊号|手术号|医保号|社会保障号|社保号|新农合号|"
    r"诊断|确诊|病情|病史|既往史|过敏史|手术名称|出院小结|入院日期|出院日期)"
    r"[：:\s]*([\u4e00-\u9fa5A-Za-z0-9\-（）()]{0,40})"
)


class MedicalDetector(Detector):
    name = "medical"
    produces = ("MEDICAL",)

    def detect(self, text: str, block: str = "body") -> list[Span]:
        out = []
        for m in _MED_RE.finditer(text):
            val = (m.group(2) or "").strip()
            if not val:
                continue
            s = m.end() - len(val)
            out.append(Span(s, m.end(), val, "MEDICAL", confidence=0.8, source=self.name,
                            reason=f"医疗信息提示词'{m.group(1)}'后的取值",
                            attrs={"kind": m.group(1)}, block=block))
        return out
