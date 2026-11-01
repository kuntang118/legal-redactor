"""全局实体解析：保证同一实体在整个批次内映射到同一个替换值。

这是法律文书脱敏能不能"读"的关键。同一个人前半段叫"李某某"后半段叫"王某"，
文书逻辑就断了，读者还能靠矛盾反推身份。
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import random
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from ..core import Preset, Span, Strategy
from . import replacer as R

#: 只做区域标记、本身不产生替换的类型（与 engine.MARKER_ONLY_TYPES 保持一致）
MARKER_ONLY = frozenset({"MINOR_INFO"})

# 假名姓池（避开常见姓氏组合造成的"撞真人"，实际使用时还会排除文中已出现的姓）
PSEUDO_SURNAMES = [
    "沈", "韩", "杨", "朱", "秦", "尤", "许", "何", "吕", "施", "张", "孔", "曹",
    "严", "华", "金", "魏", "陶", "姜", "戚", "谢", "邹", "喻", "柏", "水", "窦",
    "章", "苏", "潘", "葛", "奚", "范", "彭", "郎", "鲁", "韦", "昌", "苗", "凤",
    "俞", "袁", "鲍", "史", "唐", "费", "廉", "岑", "薛", "贺", "倪", "汤", "滕",
    "殷", "罗", "毕", "郝", "邬", "安", "常", "乐", "傅", "皮", "卞", "齐", "康",
    "伍", "余", "元", "卜", "顾", "孟", "黄", "穆", "萧", "尹", "姚", "邵", "汪",
]

# 假名字池（中性、无明显性别/年代倾向，避免引入新的推断线索）
PSEUDO_GIVEN = [
    "子涵", "雨桐", "思远", "嘉懿", "宇轩", "欣怡", "泽宇", "静怡", "浩然", "婉清",
    "明轩", "若曦", "俊豪", "雅静", "天佑", "梦琪", "文博", "诗涵", "志强", "语嫣",
    "承泽", "书瑶", "景行", "清和", "怀瑾", "瑜璟", "沐辰", "言蹊", "知微", "行简",
    "守正", "抱朴", "致远", "宁静", "见山", "临川", "观澜", "听雨", "望舒", "既明",
    "单字", "某甲", "某乙", "某丙", "子", "文", "武", "安", "宁", "康", "泰", "和",
]


@dataclass
class Entity:
    """一个被解析出来的实体（跨文件、跨写法归并后的结果）。"""

    etype: str
    canon: str                       # 归一化键
    display: str                     # 首次出现的原文写法
    code: str = ""                   # 编号化替换值
    pseudo: str = ""                 # 一致化假名
    variants: set[str] = field(default_factory=set)
    count: int = 0
    files: list[str] = field(default_factory=list)
    blocks: list[str] = field(default_factory=list)
    escalated: bool = False
    already_anonymized: bool = False
    attrs: dict[str, Any] = field(default_factory=dict)
    replacement: str | None = None   # 缓存
    strategy_used: str = ""

    @property
    def key(self) -> tuple[str, str]:
        return (self.etype, self.canon)

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["variants"] = sorted(self.variants)
        return d


class EntityResolver:
    """实体解析器 + 一致化替换值分配器。"""

    def __init__(self, preset: Preset, seed: bytes = b"",
                 options: Mapping[str, Any] | None = None):
        self.preset = preset
        self.options = dict(preset.options or {})
        if options:
            self.options.update(options)
        self.seed = seed or b"legal-redactor-default-seed"
        self.entities: dict[tuple[str, str], Entity] = {}
        self._code_seq: dict[str, int] = {}
        self._used_pseudo: set[str] = set()
        self._finalized = False
        self._key = hashlib.sha256(self.seed).digest()

    # ------------------------------------------------------------------
    def add(self, span: Span, file_id: str = "") -> Entity:
        """登记一个 span。可在 finalize 之前反复调用。"""
        from ..detect.base import canon_entity

        canon = canon_entity(span.etype, span.text)
        if not canon:
            canon = span.text
        k = (span.etype, canon)
        e = self.entities.get(k)
        if e is None:
            e = Entity(etype=span.etype, canon=canon, display=span.text)
            self.entities[k] = e
        e.variants.add(span.text)
        e.count += 1
        if file_id and file_id not in e.files:
            e.files.append(file_id)
        if span.block and span.block not in e.blocks:
            e.blocks.append(span.block)
        if span.attrs.get("escalated"):
            e.escalated = True
        if span.attrs.get("already_anonymized"):
            e.already_anonymized = True
        # 合并有用属性
        for ak in ("level", "value", "region", "birth", "platform", "kind"):
            if ak in span.attrs and ak not in e.attrs:
                e.attrs[ak] = span.attrs[ak]
        self._finalized = False
        return e

    def add_all(self, spans: Iterable[Span], file_id: str = "") -> None:
        for s in spans:
            self.add(s, file_id)

    # ------------------------------------------------------------------
    def finalize(self) -> None:
        """分配编号与假名。必须在所有 span 登记完成后调用一次。"""
        if self._finalized:
            return
        real_names = {e.canon for e in self.entities.values() if e.etype == "PERSON"}
        real_surnames = {n[0] for n in real_names if n}

        # 假名姓池排除文中已出现的姓，降低"假名恰好是另一个当事人"的概率
        pool_surnames = [s for s in PSEUDO_SURNAMES if s not in real_surnames] or PSEUDO_SURNAMES

        self._used_pseudo = set(real_names)

        for e in sorted(self.entities.values(), key=lambda x: (x.etype, -x.count, x.canon)):
            e.code = self._next_code(e.etype)
            if e.etype == "PERSON" and not e.already_anonymized:
                e.pseudo = self._make_pseudo(e.canon, pool_surnames)
            elif e.etype in ("ORG", "LAW_FIRM", "COURT", "BANK_BRANCH"):
                e.pseudo = self._make_pseudo_org(e.etype, e.canon)
        self._finalized = True

    def _next_code(self, etype: str) -> str:
        prefix = R.CODE_PREFIX.get(etype, "实体")
        n = self._code_seq.get(prefix, 0) + 1
        self._code_seq[prefix] = n
        letter = ""
        if etype == "PERSON":
            # 当事人A/B/C…，超过 26 个退回数字
            letter = chr(ord("A") + n - 1) if n <= 26 else str(n)
            return f"{prefix}{letter}"
        return f"{prefix}{n}"

    def _make_pseudo(self, canon: str, pool_surnames: Sequence[str]) -> str:
        """按 canon 的哈希确定性地挑一个假名，冲突则线性探测。"""
        h = hmac.new(self._key, f"PERSON|{canon}".encode("utf-8"), hashlib.sha256).digest()
        rng = random.Random(int.from_bytes(h[:8], "big"))
        # 目标长度与原姓名一致，读起来自然
        target = len(canon) if 2 <= len(canon) <= 4 else 3
        for attempt in range(500):
            sur = pool_surnames[rng.randrange(len(pool_surnames))]
            if target <= 1:
                cand = sur + "某"
            elif target == 2:
                given_pool = [g for g in PSEUDO_GIVEN if len(g) == 1]
                cand = sur + (given_pool[rng.randrange(len(given_pool))] if given_pool else "某")
            else:
                given_pool = [g for g in PSEUDO_GIVEN if len(g) == target - 1]
                if not given_pool:
                    given_pool = [g for g in PSEUDO_GIVEN if len(g) >= 1]
                cand = sur + given_pool[rng.randrange(len(given_pool))]
                cand = cand[:target]
            if cand in self._used_pseudo:
                continue
            self._used_pseudo.add(cand)
            return cand
        # 兜底
        fallback = f"当事人{len(self._used_pseudo)}"
        self._used_pseudo.add(fallback)
        return fallback

    def _make_pseudo_org(self, etype: str, canon: str) -> str:
        h = hmac.new(self._key, f"{etype}|{canon}".encode("utf-8"), hashlib.sha256).digest()
        rng = random.Random(int.from_bytes(h[:8], "big"))
        sur = PSEUDO_SURNAMES[rng.randrange(len(PSEUDO_SURNAMES))]
        tail = {
            "ORG": ["某科技有限公司", "某贸易有限公司", "某实业有限公司", "某咨询有限公司",
                    "某建设工程有限公司", "某投资管理有限公司"],
            "LAW_FIRM": ["某律师事务所"],
            "COURT": ["某人民法院"],
            "BANK_BRANCH": ["某银行某支行"],
        }.get(etype, ["某单位"])
        cand = sur + "氏" + tail[rng.randrange(len(tail))] if etype == "ORG" else sur + tail[rng.randrange(len(tail))]
        n = 0
        while cand in self._used_pseudo and n < 200:
            n += 1
            cand = f"{sur}{tail[rng.randrange(len(tail))]}{n}"
        self._used_pseudo.add(cand)
        return cand

    # ------------------------------------------------------------------
    def strategy_for(self, e: Entity) -> Strategy:
        """实体最终采用的策略：区域升级 > 人工覆盖 > 预设。"""
        if e.already_anonymized and e.etype == "PERSON":
            return Strategy.KEEP
        if e.escalated:
            forced = e.attrs.get("forced_strategy")
            if forced:
                return Strategy(forced)
            return Strategy.MASK_FULL
        return self.preset.strategy_for(e.etype)

    def replacement_for(self, span: Span) -> str:
        """算出某个 span 的替换串（带缓存，保证一致性）。"""
        if not self._finalized:
            self.finalize()
        from ..detect.base import canon_entity

        canon = canon_entity(span.etype, span.text) or span.text
        e = self.entities.get((span.etype, canon))
        if e is None:
            e = self.add(span)
            self.finalize()

        # 人工覆盖优先
        strat = span.decision_strategy or self.strategy_for(e)
        if span.attrs.get("forced_strategy") and not span.decision_strategy:
            strat = Strategy(span.attrs["forced_strategy"])

        cache_key = (strat, span.text)
        if e.replacement is not None and e.strategy_used == cache_key[0] and e.display == span.text:
            return e.replacement

        val = R.apply_strategy(
            Strategy(strat), e.etype, span.text,
            opts=self.options, attrs={**e.attrs, **span.attrs},
            pseudo=e.pseudo or None, code=e.code or None, key=self._key,
        )
        if e.display == span.text:
            e.replacement = val
            e.strategy_used = strat
        return val

    # ------------------------------------------------------------------
    def learned_names(self) -> list[str]:
        """已确认的自然人姓名，回喂给检测器提升召回。"""
        return sorted(e.canon for e in self.entities.values()
                      if e.etype == "PERSON" and not e.already_anonymized
                      and 2 <= len(e.canon) <= 5)

    def mapping_records(self) -> list[dict[str, Any]]:
        """对照表：原文 → 替换值。这是脱敏后必须严格保管的东西。"""
        if not self._finalized:
            self.finalize()
        out = []
        for e in sorted(self.entities.values(), key=lambda x: (x.etype, x.code or x.canon)):
            # 区域标记类型不产生替换，也就不该出现在对照表里
            # （否则审计会拿"系未成年人"这种标记词去搜残留，误报 critical）
            if e.etype in MARKER_ONLY:
                continue
            strat = self.strategy_for(e)
            if strat == Strategy.KEEP:
                continue
            rep = R.apply_strategy(strat, e.etype, e.display, opts=self.options,
                                   attrs=e.attrs, pseudo=e.pseudo or None,
                                   code=e.code or None, key=self._key)
            out.append({
                "etype": e.etype,
                "original": e.display,
                "variants": sorted(e.variants),
                "replacement": rep,
                "strategy": strat if isinstance(strat, str) else strat.value,
                "code": e.code,
                "pseudo": e.pseudo,
                "occurrences": e.count,
                "files": e.files,
                "blocks": e.blocks,
                "escalated": e.escalated,
            })
        return out

    def stats(self) -> dict[str, Any]:
        by_type: dict[str, int] = {}
        for e in self.entities.values():
            by_type[e.etype] = by_type.get(e.etype, 0) + e.count
        return {
            "unique_entities": len(self.entities),
            "total_occurrences": sum(e.count for e in self.entities.values()),
            "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
            "escalated": sum(1 for e in self.entities.values() if e.escalated),
        }
