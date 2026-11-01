"""检测器基类、Span 归并/冲突消解、文本归一化工具。"""
from __future__ import annotations

import re
import unicodedata
from abc import ABC, abstractmethod
from typing import Iterable, Sequence

from ..core import Span, entity_group, GROUP_STRONG, GROUP_WEAK, GROUP_VISUAL

# 组优先级：数字越大越优先保留
GROUP_PRIORITY = {
    GROUP_STRONG: 100,
    GROUP_VISUAL: 80,
    GROUP_WEAK: 50,
    "discretion": 30,
}

# 区域标记类型：标识"这一段需要加强处理"，不参与 span 重叠消解
REGION_TYPES = frozenset({"MINOR_INFO", "MEDICAL", "TRADE_SECRET", "CUSTOM"})

# 同组内的类型优先级（处理重叠时，谁吃掉谁）
# 数值只用于同组内比较；跨组先比 GROUP_PRIORITY
TYPE_PRIORITY = {
    "ID_CARD": 95,
    "BANK_CARD": 90,
    "USCC": 90,
    "LICENSE_NO": 88,
    "PASSPORT": 88,
    "HK_MO_PERMIT": 88,
    "SUSPECT_ID": 70,
    "PHONE": 85,
    "TEL": 80,
    "EMAIL": 85,
    "IP_ADDR": 60,
    "MAC_ADDR": 60,
    "PLATE": 75,
    "IM_ACCOUNT": 65,
    "CASE_NO": 72,
    # 机构类必须压过 ADDRESS：否则"北京市西城区人民法院"会被当成地址
    "BANK_BRANCH": 60,
    "COURT": 58,
    "LAW_FIRM": 57,
    # ADDRESS 必须压过 ORG："住所地北京市西城区金融大街7号英蓝国际金融中心"
    # 里，地址是主要信息，机构名是它的副产品
    "ADDRESS": 56,
    "ORG": 55,
    "PERSON": 40,
    "DOB": 44,
    "AMOUNT": 20,
    "DATE": 10,
    "URL": 5,
    # 区域标记类：故意压低，让它们被具体实体 span 覆盖，
    # 由 engine 用 overlap 关系反向升级这些具体实体的处理强度
    "MINOR_INFO": 4,
    "MEDICAL": 4,
    "TRADE_SECRET": 4,
    "CUSTOM": 4,
}


def type_priority(etype: str) -> int:
    return TYPE_PRIORITY.get(etype, 30) + GROUP_PRIORITY.get(entity_group(etype), 0)


# --------------------------------------------------------------------------
# 归一化
# --------------------------------------------------------------------------

# 全角 → 半角
def to_halfwidth(s: str) -> str:
    return unicodedata.normalize("NFKC", s)


_WS_RE = re.compile(r"[\s\u3000]+")
_DASH_RE = re.compile(r"[-\u2010-\u2015\u2212_/\\.\u00b7]")


def norm_digits(s: str) -> str:
    """把数字串归一化：全角转半角、去空格与分隔符。用于号码类匹配。"""
    s = to_halfwidth(s)
    s = _WS_RE.sub("", s)
    s = _DASH_RE.sub("", s)
    return s


def norm_text(s: str) -> str:
    """一般文本归一化：全角转半角、压缩空白。"""
    s = to_halfwidth(s)
    s = _WS_RE.sub(" ", s)
    return s.strip()


def canon_entity(etype: str, value: str) -> str:
    """实体归一化键：用于全局实体解析（同一人不同写法归并）。"""
    v = to_halfwidth(value).strip()
    v = _WS_RE.sub("", v)
    if etype in {"PHONE", "TEL", "ID_CARD", "BANK_CARD", "USCC", "PASSPORT",
                 "HK_MO_PERMIT", "MAC_ADDR", "IP_ADDR", "IM_ACCOUNT", "SUSPECT_ID"}:
        # "+" 必须一起去掉："+86 136-2222-3333" 与 "13622223333" 是同一个号码，
        # 归一化后必须落到同一个键上，否则会被当成两个实体、给出两个替换值
        v = _DASH_RE.sub("", v).lstrip("+").upper()
    if etype == "PERSON":
        # "张三" / "张三某" / "张某" 归并到 "张"  + 去尾"某"
        v = re.sub(r"某+$", "", v)
    if etype in {"EMAIL", "URL"}:
        v = v.lower()
    return v


# --------------------------------------------------------------------------
# 检测器接口
# --------------------------------------------------------------------------


class Detector(ABC):
    """文本检测器基类。子类实现 detect(text, block) -> list[Span]。"""

    name: str = "base"
    #: 该检测器产出的实体类型
    produces: tuple[str, ...] = ()

    @abstractmethod
    def detect(self, text: str, block: str = "body") -> list[Span]:
        ...

    def enabled(self, options: dict) -> bool:
        return True


class VisionDetector(ABC):
    """视觉检测器基类。输入图像（numpy BGR），输出 Box 列表。"""

    name: str = "vision_base"
    produces: tuple[str, ...] = ()

    @abstractmethod
    def detect(self, image, page: int = 0):
        ...

    def enabled(self, options: dict) -> bool:
        return bool(options.get("vision", True))


# --------------------------------------------------------------------------
# Span 归并与冲突消解
# --------------------------------------------------------------------------


def merge_spans(spans: Iterable[Span],
                deprioritize: frozenset[str] = frozenset()) -> list[Span]:
    """去重 + 解决重叠。

    规则：
    1. 区域标记类型（MINOR_INFO / MEDICAL / TRADE_SECRET / CUSTOM）不参与消解，
       原样保留——它们是"这一段要加强处理"的信号，由 engine 反向作用于覆盖到的实体。
    2. 完全相同 (block,start,end) 的：保留 type_priority 最高的，confidence 取最大。
    3. 部分重叠的：priority 高者胜；相同则长者胜。败者被完全包含则丢弃，
       否则截断保留残余，避免漏检。
    4. `deprioritize` 里的类型（当前预设下策略为 KEEP 的类型）**无条件让位**。

    第 4 条是必须的：页眉"（2023）京0102民初18765号　张伟民诉北京华远置业有限公司"
    里，ORG 检测器向前回溯会把"张伟民诉"一起吃进机构名，而 ORG 在 legal 预设下
    保留、PERSON 要脱敏，于是姓名被保留类实体整个吞掉且不做任何替换——
    Word 打开产物，页眉里"张伟民"三个字原样躺在那儿。
    """
    all_spans = list(spans)
    regions = [s for s in all_spans if s.etype in REGION_TYPES]
    items = sorted(
        (s for s in all_spans if s.etype not in REGION_TYPES),
        key=lambda s: (s.block, s.start, -s.length, -type_priority(s.etype)),
    )

    def rank(s: Span) -> tuple:
        """(是否未被降级, 类型优先级, 长度)。元组直接比大小，大的胜。

        第一位：未降级=1、被降级=0。**方向不能写反**——写成"被降级=1"会让
        保留类实体反而吃掉脱敏类实体，实测后果是住所地地址整条不脱敏、
        出生日期不做泛化、开户行原样保留。
        """
        return (0 if s.etype in deprioritize else 1, type_priority(s.etype), s.length)

    # 第一步：同区间去重
    dedup: dict[tuple, Span] = {}
    order: list[tuple] = []
    for s in items:
        k = (s.block, s.start, s.end)
        if k in dedup:
            old = dedup[k]
            if rank(s) > rank(old):
                s.confidence = max(s.confidence, old.confidence)
                s.attrs = {**old.attrs, **s.attrs}
                dedup[k] = s
            else:
                old.confidence = max(old.confidence, s.confidence)
        else:
            dedup[k] = s
            order.append(k)

    pool = [dedup[k] for k in order]
    pool.sort(key=lambda s: (s.block, s.start, -rank(s)[0], -rank(s)[1], -s.length))

    # 第二步：按 block 分组做区间消解
    out: list[Span] = []
    by_block: dict[str, list[Span]] = {}
    for s in pool:
        by_block.setdefault(s.block, []).append(s)

    for block, group in by_block.items():
        kept: list[Span] = []
        for s in group:
            conflict = None
            for k in kept:
                if s.overlaps(k):
                    conflict = k
                    break
            if conflict is None:
                kept.append(s)
                continue
            # 有重叠：先比"是否被降级"，再比类型优先级，最后比长度
            sr, kr = rank(s), rank(conflict)
            if sr > kr:
                # s 胜，裁剪 conflict
                kept.remove(conflict)
                trimmed = _trim(conflict, s)
                kept.extend(trimmed)
                kept.append(s)
            else:
                # conflict 胜，裁剪 s
                trimmed = _trim(s, conflict)
                kept.extend(trimmed)
        out.extend(kept)

    # 区域标记原样并入（不消解），engine 会用重叠关系反向升级具体实体的处理强度
    out.extend(regions)

    out.sort(key=lambda s: (s.block, s.start))
    _assign_ids(out)
    return out


def _trim(loser: Span, winner: Span) -> list[Span]:
    """把 loser 裁掉与 winner 重叠的部分，保留残余。"""
    if winner.start <= loser.start and winner.end >= loser.end:
        return []  # 完全被吃掉
    res = []
    if loser.start < winner.start:
        res.append(Span(
            start=loser.start, end=winner.start,
            text=loser.text[: winner.start - loser.start],
            etype=loser.etype, confidence=loser.confidence * 0.8,
            source=loser.source, reason=loser.reason + "（被裁剪）",
            attrs=dict(loser.attrs), block=loser.block, action=loser.action,
        ))
    if loser.end > winner.end:
        off = winner.end - loser.start
        res.append(Span(
            start=winner.end, end=loser.end,
            text=loser.text[off:],
            etype=loser.etype, confidence=loser.confidence * 0.8,
            source=loser.source, reason=loser.reason + "（被裁剪）",
            attrs=dict(loser.attrs), block=loser.block, action=loser.action,
        ))
    return [r for r in res if r.length > 0 and r.text.strip()]


def _assign_ids(spans: Sequence[Span]) -> None:
    for i, s in enumerate(spans):
        if not s.span_id:
            s.span_id = f"s{i:05d}"


def merge_adjacent_same(spans: list[Span], max_gap: int = 2) -> list[Span]:
    """合并相邻的同类型同值 span（跨 run 切分导致的碎片）。"""
    if not spans:
        return spans
    spans = sorted(spans, key=lambda s: (s.block, s.start))
    out = [spans[0]]
    for s in spans[1:]:
        p = out[-1]
        if (p.block == s.block and p.etype == s.etype
                and 0 <= s.start - p.end <= max_gap
                and p.text == s.text):
            p.end = s.end
            p.confidence = max(p.confidence, s.confidence)
        else:
            out.append(s)
    return out


def group_by_value(spans: Iterable[Span]) -> dict[tuple[str, str], list[Span]]:
    """按 (类型, 归一化值) 分组，供全局实体解析使用。"""
    g: dict[tuple[str, str], list[Span]] = {}
    for s in spans:
        g.setdefault((s.etype, canon_entity(s.etype, s.text)), []).append(s)
    return g


def context_window(text: str, start: int, end: int, before: int = 24, after: int = 24) -> str:
    """取上下文片段，供复核界面与审计报告展示。"""
    a = max(0, start - before)
    b = min(len(text), end + after)
    prefix = "…" if a > 0 else ""
    suffix = "…" if b < len(text) else ""
    return prefix + text[a:start] + "【" + text[start:end] + "】" + text[end:b] + suffix
