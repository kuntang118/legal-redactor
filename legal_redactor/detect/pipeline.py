"""文本检测流水线：编排各检测器 + 姓名两遍学习 + 区域升级。"""
from __future__ import annotations

import re
from typing import Iterable, Mapping, Sequence

from ..core import Preset, Span, Strategy, ENTITY_TYPES
from .base import REGION_TYPES, Detector, canon_entity, merge_spans
from .regex_det import StrongIdentifierDetector
from .name_det import PersonNameDetector
from .addr_det import AddressDetector, BankBranchDetector
from .org_det import CourtDetector, LawFirmDetector, OrgDetector
from .legal_det import (AmountDetector, CaseNoDetector, DateDetector,
                        MedicalDetector, MinorInfoDetector)


class CustomDetector(Detector):
    """用户自定义：正则或词表。YAML 里 options.custom 定义。"""

    name = "custom"
    produces = ("CUSTOM",)

    def __init__(self, patterns: Sequence[Mapping] = ()):
        self.rules: list[tuple[str, re.Pattern | None, set[str], str]] = []
        for p in patterns:
            label = str(p.get("label") or p.get("name") or "自定义")
            etype = str(p.get("etype") or "CUSTOM")
            rx = p.get("regex")
            words = p.get("words") or []
            self.rules.append((
                label,
                re.compile(rx) if rx else None,
                set(words),
                etype,
            ))

    def enabled(self, options: dict) -> bool:
        return bool(self.rules)

    def detect(self, text: str, block: str = "body") -> list[Span]:
        out: list[Span] = []
        for label, rx, words, etype in self.rules:
            if rx is not None:
                for m in rx.finditer(text):
                    g = m.group(1) if m.groups() else m.group(0)
                    s = m.start(1) if m.groups() else m.start()
                    out.append(Span(s, s + len(g), g, etype, confidence=0.95,
                                    source=f"custom:{label}", reason=f"用户自定义规则 {label}",
                                    block=block))
            for w in words:
                if not w:
                    continue
                start = 0
                while True:
                    i = text.find(w, start)
                    if i < 0:
                        break
                    start = i + 1
                    out.append(Span(i, i + len(w), w, etype, confidence=1.0,
                                    source=f"custom:{label}", reason=f"用户自定义词表 {label}",
                                    block=block))
        return out


_ORG_TAIL = re.compile(
    r"(" + "|".join(re.escape(s) for s in
                    sorted({"人民法院", "人民检察院", "检察院", "律师事务所", "仲裁委员会",
                            "公安局", "派出所", "司法局", "人民政府", "管委会"}, key=len, reverse=True)) + ")$"
)


def post_validate(spans: Sequence[Span]) -> list[Span]:
    """结构不变量校验。

    merge_spans 的裁剪会产生"半截"片段（例如把机构名让给 COURT 后，
    ADDRESS 只剩"住所地"三个字）。这里按类型检查收尾/长度，丢掉不成立的片段。
    """
    from .addr_det import _TERMINATOR_RE
    from . import lexicon as L
    from .name_det import looks_like_name

    org_suffix_re = re.compile("(" + "|".join(
        re.escape(s) for s in sorted(L.ORG_SUFFIXES, key=len, reverse=True)) + ")$")
    bank_tail_re = re.compile(
        r"(分行|支行|分理处|营业部|营业室|储蓄所|办事处|分社|信用社|银行|"
        r"农村信用合作联社|农村商业银行|村镇银行)$")

    out: list[Span] = []
    for s in spans:
        t = s.text
        if not t:
            continue
        if s.etype == "ORG":
            if not org_suffix_re.search(t) or len(t) < 5:
                continue
        elif s.etype == "COURT":
            if not _ORG_TAIL.search(t) or len(t) < 4:
                continue
        elif s.etype == "LAW_FIRM":
            if not t.endswith("律师事务所"):
                continue
        elif s.etype == "BANK_BRANCH":
            if not bank_tail_re.search(t) or len(t) < 4:
                continue
        elif s.etype == "ADDRESS":
            if len(t) < 6 or not _TERMINATOR_RE.search(t):
                continue
        elif s.etype == "PERSON":
            if t.endswith("某") or t.endswith("某某"):
                pass
            else:
                ok, _ = looks_like_name(t, strict=False)
                if not ok or len(t) < 2:
                    continue
        elif s.etype in ("DATE", "DOB"):
            if not re.search(r"(年|月|日|\d)", t):
                continue
        elif s.etype == "AMOUNT":
            if not re.search(r"(元|圆|角|分|万|亿)", t):
                continue
        elif s.etype == "CASE_NO":
            if "号" not in t:
                continue
        out.append(s)
    return out


#: 列头关键词 → 实体类型。表格里的裸值没有上下文，列头就是决定性证据。
HEADER_RULES: list[tuple[tuple[str, ...], str]] = [
    (("姓名", "名字", "当事人", "联系人", "负责人", "法定代表人", "法人代表", "代理人",
      "证人", "申请人", "被申请人", "原告", "被告", "经办人", "承办人", "收件人", "寄件人",
      "持卡人", "开户名", "户名", "投保人", "被保险人", "受益人", "签署人", "签名",
      "被告人", "嫌疑人", "被害人", "员工", "劳动者", "监护人", "被监护人", "业主",
      "承租人", "出租人", "借款人", "出借人", "买受人", "出卖人", "甲方", "乙方"), "PERSON"),
    (("身份证", "证件号", "身份号码", "公民身份", "身份证号", "证件号码"), "ID_CARD"),
    (("手机", "电话", "联系方式", "联系电话", "tel", "phone", "mobile"), "PHONE"),
    (("住址", "地址", "住所", "户籍", "居住地", "通讯地址", "送达地址", "经营场所",
      "注册地址", "籍贯", "出生地"), "ADDRESS"),
    (("账号", "卡号", "账户", "帐号", "银行卡"), "BANK_CARD"),
    (("开户行", "开户银行", "银行"), "BANK_BRANCH"),
    (("邮箱", "邮件", "email", "e-mail", "e_mail"), "EMAIL"),
    (("车牌", "号牌", "牌照", "车号"), "PLATE"),
    (("微信", "qq", "QQ", "扣扣"), "IM_ACCOUNT"),
    (("出生", "生日"), "DOB"),
    (("信用代码", "统一社会", "营业执照", "注册号"), "USCC"),
    (("护照",), "PASSPORT"),
    (("执业证", "许可证", "资格证"), "LICENSE_NO"),
    (("ip", "IP",), "IP_ADDR"),
    (("金额", "数额", "价款", "标的"), "AMOUNT"),
]

_CJK_ONLY = re.compile(r"^[\u4e00-\u9fa5]{2,6}$")


def header_etype(header: str) -> str | None:
    h = (header or "").strip().lower()
    if not h:
        return None
    for keys, etype in HEADER_RULES:
        for k in keys:
            if k.lower() in h:
                return etype
    return None


class TabularDetector(Detector):
    """列头驱动的强制类型判定。

    表格里"张伟民"单独占一格，没有角色词、没有"男，1987年"这类上下文，
    任何基于上下文的规则都会漏。但列头写着"姓名"，这就是决定性证据。
    只在常规检测器没抓到该单元格时补一发，避免与它们打架。
    """

    name = "tabular"
    produces = tuple({e for _, e in HEADER_RULES})

    def __init__(self, hint: str):
        self.hint = hint
        self.etype = header_etype(hint)

    def enabled(self, options: dict) -> bool:
        return self.etype is not None

    def detect(self, text: str, block: str = "body") -> list[Span]:
        if not self.etype or not text or not text.strip():
            return []
        t = text.strip()
        et = self.etype
        reason = f"列头“{self.hint}”指示该列为{et}"

        if et == "PERSON":
            from .name_det import _extract_candidate
            if _CJK_ONLY.match(t):
                from .name_det import looks_like_name
                ok, _ = looks_like_name(t, strict=False)
                if ok or len(t) <= 4:
                    return [Span(text.index(t), text.index(t) + len(t), t, "PERSON",
                                 confidence=0.95, source=self.name, reason=reason,
                                 attrs={"path": "T", "header": self.hint}, block=block)]
                return []
            got = _extract_candidate(text, max(0, text.find(t)), require_boundary=False)
            if got:
                cand, end = got
                s = text.find(cand)
                return [Span(s, s + len(cand), cand, "PERSON", confidence=0.9,
                             source=self.name, reason=reason + "（单元格内含其他内容）",
                             attrs={"path": "T", "header": self.hint}, block=block)]
            return []

        if et == "ID_CARD":
            if re.fullmatch(r"\d{17}[\dXx]|\d{15}", t):
                return [Span(text.index(t), text.index(t) + len(t), t,
                             "ID_CARD" if len(t) == 18 else "SUSPECT_ID",
                             confidence=0.9, source=self.name, reason=reason, block=block)]
            return []

        if et == "PHONE":
            d = re.sub(r"\D", "", t)
            if 7 <= len(d) <= 15:
                kind = "PHONE" if len(d) == 11 and d.startswith("1") else "TEL"
                return [Span(text.index(t), text.index(t) + len(t), t, kind,
                             confidence=0.92, source=self.name, reason=reason, block=block)]
            return []

        if et == "BANK_CARD":
            d = re.sub(r"[^0-9A-Za-z]", "", t)
            if 12 <= len(d) <= 25:
                return [Span(text.index(t), text.index(t) + len(t), t, "BANK_CARD",
                             confidence=0.85, source=self.name, reason=reason, block=block)]
            return []

        if et == "ADDRESS":
            if len(t) >= 6:
                return [Span(text.index(t), text.index(t) + len(t), t, "ADDRESS",
                             confidence=0.85, source=self.name, reason=reason,
                             attrs={"header": self.hint}, block=block)]
            return []

        # 其余类型：整格作为一个值
        if len(t) >= 3:
            return [Span(text.index(t), text.index(t) + len(t), t, et,
                         confidence=0.88, source=self.name, reason=reason, block=block)]
        return []


class TextPipeline:
    """把多个检测器编排成一条流水线。

    关键机制：
    1. **姓名两遍学习**——第一遍取高置信姓名（角色词/落款路径），
       作为 learned 名单跑第二遍，抓全文其余出现位置。这是纯规则方案里
       提升姓名召回最有效的一步。
    2. **区域升级**——MINOR_INFO / MEDICAL 区域内的 PERSON / DOB / ADDRESS /
       ID_CARD 强制升级为 MASK_FULL，不允许"保留姓氏"这种弱脱敏。
    3. **结构不变量后校验**——裁掉 merge 阶段产生的半截片段。
    """

    #: 区域内需要被强制升级的实体类型
    ESCALATE_TYPES = {"PERSON", "DOB", "ADDRESS", "ID_CARD", "PHONE", "BANK_CARD",
                      "SUSPECT_ID", "PASSPORT", "HK_MO_PERMIT", "IM_ACCOUNT", "EMAIL"}

    def __init__(self, preset: Preset, extra_names: Sequence[str] = (),
                 custom_rules: Sequence[Mapping] = ()):
        self.preset = preset
        self.options = dict(preset.options or {})
        self.extra_names = list(extra_names)
        self.custom_rules = list(custom_rules) or list(self.options.get("custom") or [])
        # 当前预设下"保留不动"的类型：它们在重叠消解里必须让位给要脱敏的类型，
        # 否则会出现"机构名把当事人姓名整个吞掉、然后原样保留"的漏洞
        self.keep_types: frozenset[str] = frozenset(
            t for t in ENTITY_TYPES if not preset.is_redacted(t))
        self._detectors = self._build()

    def _build(self) -> list[Detector]:
        d: list[Detector] = [
            StrongIdentifierDetector(),
            CaseNoDetector(),
            AddressDetector(),
            BankBranchDetector(),
            CourtDetector(),
            LawFirmDetector(),
            OrgDetector(),
            AmountDetector(),
            DateDetector(),
            MinorInfoDetector(),
            MedicalDetector(),
        ]
        if self.custom_rules:
            d.append(CustomDetector(self.custom_rules))
        return d

    # ------------------------------------------------------------------
    def name_detector(self, learned: Sequence[str] = ()) -> PersonNameDetector:
        return PersonNameDetector(learned_names=list(self.extra_names) + list(learned),
                                  enable_c_path=bool(self.options.get("name_c_path", True)))

    def detect_text(self, text: str, block: str = "body") -> list[Span]:
        """单块文本检测（含姓名两遍学习）。供视觉流水线的 OCR 框复用。"""
        return self._run_blocks({block: text}).get(block, [])

    def run(self, blocks: Mapping[str, str],
            hints: Mapping[str, str] | None = None) -> dict[str, list[Span]]:
        """多块检测。blocks: {block_id: text}，例如 {'body':…, 'header1':…, 'page3':…}。

        hints: {block_id: 列头文本}，表格类格式用来做列头驱动的强制判定。
        """
        return self._run_blocks(dict(blocks), dict(hints or {}))

    # ------------------------------------------------------------------
    def _run_blocks(self, blocks: dict[str, str],
                    hints: dict[str, str] | None = None) -> dict[str, list[Span]]:
        hints = hints or {}
        # ---- 第一遍：所有检测器 + 姓名（无 learned）
        raw: dict[str, list[Span]] = {}
        name_det_1 = self.name_detector([])
        for bid, text in blocks.items():
            if not text:
                raw[bid] = []
                continue
            spans: list[Span] = []
            for d in self._detectors:
                if not d.enabled(self.options):
                    continue
                try:
                    spans.extend(d.detect(text, bid))
                except Exception as e:  # 单个检测器崩了不能拖垮全局
                    spans.append(Span(0, 0, "", "CUSTOM", confidence=0.0,
                                      source=d.name, reason=f"检测器异常：{type(e).__name__}: {e}",
                                      block=bid))
            spans.extend(name_det_1.detect(text, bid))
            # 列头驱动：只在常规检测没覆盖到这个块时补
            hint = hints.get(bid)
            if hint:
                td = TabularDetector(hint)
                if td.enabled(self.options):
                    try:
                        extra = td.detect(text, bid)
                    except Exception:
                        extra = []
                    if extra and not any(s.start == e.start and s.end == e.end
                                         for s in spans for e in extra):
                        covered = any(s.etype == e.etype and s.overlaps(e)
                                      for s in spans for e in extra)
                        if not covered:
                            spans.extend(extra)
            raw[bid] = post_validate(merge_spans(spans, self.keep_types))

        # ---- 收集高置信姓名，作为 learned 名单
        learned: set[str] = set()
        for bid, spans in raw.items():
            for s in spans:
                if s.etype != "PERSON":
                    continue
                if s.confidence < 0.88:
                    continue
                if s.attrs.get("already_anonymized"):
                    continue
                nm = canon_entity("PERSON", s.text)
                if 2 <= len(nm) <= 5:
                    learned.add(nm)
        # 用户在复核界面手工加进来的名字也算
        for nm in self.extra_names:
            learned.add(canon_entity("PERSON", nm))

        # ---- 第二遍：带 learned 名单重跑姓名检测，并合并
        if learned:
            name_det_2 = self.name_detector(sorted(learned))
            for bid, text in blocks.items():
                if not text:
                    continue
                extra = name_det_2.detect(text, bid)
                if extra:
                    raw[bid] = post_validate(merge_spans(list(raw[bid]) + extra,
                                                         self.keep_types))

        # ---- 区域升级
        for bid, spans in raw.items():
            self._escalate(spans)
            # 低置信度候选标记为需人工复核
            for s in spans:
                if s.confidence < 0.75 and s.action == "auto":
                    s.action = "review"
        return raw

    def _escalate(self, spans: list[Span]) -> None:
        regions = [s for s in spans if s.etype in REGION_TYPES]
        if not regions:
            return
        for r in regions:
            ws = r.attrs.get("window_start", r.start)
            we = r.attrs.get("window_end", r.end)
            for s in spans:
                if s is r or s.etype in REGION_TYPES:
                    continue
                if s.etype not in self.ESCALATE_TYPES:
                    continue
                if s.start < we and s.end > ws:
                    s.attrs["escalated"] = True
                    s.attrs["escalated_by"] = r.etype
                    s.attrs["forced_strategy"] = Strategy.MASK_FULL.value
                    s.confidence = max(s.confidence, r.confidence)
                    if s.reason:
                        s.reason += f"；被{ENTITY_TYPES[r.etype].label}区域强制升级"
                    else:
                        s.reason = f"被{ENTITY_TYPES[r.etype].label}区域强制升级"

    # ------------------------------------------------------------------
    def active_types(self) -> list[str]:
        """当前预设下会被实际脱敏的实体类型。"""
        return [t for t in ENTITY_TYPES if self.preset.is_redacted(t)]


def merge_all(block_spans: Mapping[str, Sequence[Span]]) -> list[Span]:
    """把所有 block 的 span 汇成一条列表（复核界面/导出用）。"""
    out: list[Span] = []
    for bid, spans in block_spans.items():
        out.extend(spans)
    out.sort(key=lambda s: (s.block, s.start))
    return out
