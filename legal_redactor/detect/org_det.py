"""机构类实体：法院、律所、公司/组织。"""
from __future__ import annotations

import re
from typing import Iterable

from ..core import Span
from .base import Detector
from . import lexicon as L

# 机构名向前回溯时的停止字符
_STOP_CHARS = set("，。、；：？！\n\r\t,;:?!|“”\"'《》〈〉【】[]（）()·…—- 　")
# 机构名之前常见的虚词/动词，遇到即停（含多字，按最长匹配）
_STOP_WORDS = sorted([
    "原告", "被告", "第三人", "上诉人", "被上诉人", "申请人", "被申请人", "被告人",
    "犯罪嫌疑人", "被害人", "证人", "鉴定人", "审判员", "审判长", "书记员", "法官助理",
    "法定代表人", "负责人", "经营者", "委托代理人", "诉讼代理人", "辩护人", "代理人",
    "申请执行人", "被执行人", "担保人", "承租人", "出租人", "借款人", "贷款人",
    "买受人", "出卖人", "甲方", "乙方", "丙方", "发包方", "承包方",
    "于", "在", "和", "与", "及", "或", "向", "对", "由", "经", "系", "为", "的",
    "自", "从", "给", "等", "并", "将", "把", "被", "受", "至", "据", "依", "按照",
    "诉", "诉称", "起诉", "上诉", "抗诉", "申诉", "答辩", "辩称", "陈述", "称",
    "委托", "指定", "受委托", "就读于", "任职于", "供职于", "就职于", "开户于",
    "送达", "移送", "移交", "转交", "提交", "出具", "签发", "盖章",
    "住所地", "住所", "住址", "地址", "位于", "经营场所", "注册地址", "办公地址",
    "住所地为", "住", "址",
    "本院", "该院", "贵院", "我局", "我公司", "该公司", "本企业", "本单位",
    "原", "现", "曾", "即", "如", "若", "则", "但", "而", "又", "再",
], key=len, reverse=True)


def _grow_back(text: str, end: int, min_len: int = 4, max_len: int = 40) -> int:
    """从 end（机构后缀结束处）向前回溯机构名起点。"""
    i = end
    start = end
    limit = max(0, end - max_len)
    while i > limit:
        ch = text[i - 1]
        if ch in _STOP_CHARS:
            break
        if not ("\u4e00" <= ch <= "\u9fa5" or ch.isalnum() or ch in "·"):
            break
        # 命中停止词
        hit = False
        for w in _STOP_WORDS:
            if text[max(0, i - len(w)):i] == w:
                i -= len(w)
                hit = True
                break
        if hit:
            break
        i -= 1
        start = i
    if end - start < min_len:
        return end
    return start


class CourtDetector(Detector):
    name = "court"
    produces = ("COURT",)

    _RE = re.compile(
        r"[\u4e00-\u9fa5A-Za-z0-9]{1,20}?"
        r"(?:人民法院|海事法院|铁路运输法院|铁路运输中级法院|知识产权法院|互联网法院|"
        r"金融法院|军事法院|林区基层法院|矿区法院|人民检察院|检察院|"
        r"仲裁委员会|仲裁委|司法局|公安局|公安分局|派出所|监察委员会|纪委监委)"
    )

    def detect(self, text: str, block: str = "body") -> list[Span]:
        out = []
        for m in self._RE.finditer(text):
            raw = m.group(0)
            start = _grow_back(text, m.end(), min_len=3, max_len=30)
            # 去掉可能残留的"本院""该院"
            body = text[start:m.end()]
            body = re.sub(r"^(本院|该院|贵院|我市|我省|我区|该县|该)", "", body)
            start = m.end() - len(body)
            if len(body) < 4:
                continue
            out.append(Span(start, m.end(), body, "COURT", confidence=0.95,
                            source=self.name, reason="司法机关名称模式",
                            attrs={"kind": self._kind(body)}, block=block))
        return out

    @staticmethod
    def _kind(name: str) -> str:
        for k in ("最高人民法院", "高级人民法院", "中级人民法院", "人民法院", "海事法院",
                  "知识产权法院", "互联网法院", "金融法院", "铁路运输法院", "军事法院",
                  "人民检察院", "检察院", "仲裁委员会", "公安局", "派出所", "司法局"):
            if name.endswith(k):
                return k
        return "司法机关"


class LawFirmDetector(Detector):
    name = "law_firm"
    produces = ("LAW_FIRM",)

    def detect(self, text: str, block: str = "body") -> list[Span]:
        out = []
        for m in L.LAW_FIRM_RE.finditer(text):
            start = _grow_back(text, m.end(), min_len=5, max_len=30)
            body = text[start:m.end()]
            out.append(Span(start, m.end(), body, "LAW_FIRM", confidence=0.95,
                            source=self.name, reason="律师事务所名称模式",
                            block=block))
        return out


class OrgDetector(Detector):
    """公司/机构名称。后缀驱动 + 向前回溯。"""

    name = "org"
    produces = ("ORG",)

    _SUFFIXES = sorted(L.ORG_SUFFIXES, key=len, reverse=True)
    _RE = re.compile("(" + "|".join(re.escape(s) for s in _SUFFIXES) + ")")

    # 明显不是机构名的结尾（避免"有限公司"前面的东西被过度吞并）
    _GENERIC = {"公司", "企业", "单位", "机构", "组织", "部门"}

    def detect(self, text: str, block: str = "body") -> list[Span]:
        out: list[Span] = []
        for m in self._RE.finditer(text):
            suf = m.group(1)
            start = _grow_back(text, m.end(), min_len=len(suf) + 2, max_len=45)
            body = text[start:m.end()]
            if len(body) - len(suf) < 2:
                continue
            # 排除"本院""该公司"这类指代
            if re.match(r"^(本|该|其|此|贵|我|原|现)", body) and len(body) - len(suf) <= 3:
                continue
            # 排除法院/律所（由专门检测器负责）
            if body.endswith(("人民法院", "人民检察院", "律师事务所", "仲裁委员会")):
                continue
            conf = 0.9 if len(body) >= 8 else 0.72
            out.append(Span(start, m.end(), body, "ORG", confidence=conf,
                            source=self.name,
                            reason=f"机构后缀'{suf}'+向前回溯{len(body) - len(suf)}字",
                            attrs={"suffix": suf}, block=block))
        # 括号内曾用名：XX公司（原YY厂）
        for m in re.finditer(r"[（(]\s*(?:原|前|曾用名)\s*([\u4e00-\u9fa5A-Za-z0-9]{4,30})\s*[）)]", text):
            out.append(Span(m.start(1), m.end(1), m.group(1), "ORG", confidence=0.75,
                            source=self.name, reason="括号内曾用名/原名", block=block))
        return out
