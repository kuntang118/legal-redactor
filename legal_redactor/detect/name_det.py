"""中文自然人姓名检测。

四条路径，置信度递减：
  A. 法律角色触发词（原告/被告/审判员/证人… 后接姓名）——法律文书主力路径
  B. 落款与署名模式
  C. 姓氏词典 + 边界/上下文约束——只产出待复核候选
  D. learned 名单精确匹配——由 EntityResolver 或人工复核反哺，跨文档提升召回
"""
from __future__ import annotations

import re
from typing import Iterable, Sequence

from ..core import Span
from .base import Detector
from . import lexicon as L

# 姓名候选：复姓优先
_CAND_RE = re.compile(
    rf"(?:{L.COMPOUND_SURNAME_RE}(?P<cbody>[\u4e00-\u9fa5]{{1,3}})"
    rf"|(?P<sbody>[\u4e00-\u9fa5]{{1,4}}))"
)

# 触发词按长度降序，保证最长匹配（"委托诉讼代理人" 优先于 "代理人"）
_TRIGGER_WORDS = sorted(set(L.ROLE_TRIGGERS), key=len, reverse=True)


def _flex(word: str) -> str:
    """允许角色词内部夹空白——真实裁判文书里"审 判 长""书 记 员"很常见。"""
    return r"[\s\u3000]*".join(re.escape(c) for c in word)


TRIGGER_RE = re.compile("(" + "|".join(_flex(w) for w in _TRIGGER_WORDS) + ")")

# 机构后缀：角色词后面跟的是机构名而不是人名时，用来一票否决
_ORG_SUFFIX_RE = re.compile(
    "(" + "|".join(re.escape(s) for s in
                   sorted(set(L.ORG_SUFFIXES) | set(L.COURT_SUFFIXES), key=len, reverse=True)) + ")"
)

# 姓名后允许出现的字符（边界判定）
BOUNDARY_CHARS = set(
    "，。、；：？！\u3000 \t\r\n（）()【】\\[\\]《》〈〉—…·\"'“”‘’-.!?;:,~｜|"
    "男女某"
    "汉回满蒙藏苗彝壮侗朝维白傣土畲黎京"
    "辩述称诉请未已等均系是在为与和及或被把将向于自因由对至委代律出到参经并又再后前曾现住籍身该其此这那"
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)
BOUNDARY_CHARS = {c for c in BOUNDARY_CHARS if c not in "\\[]"}

# 姓名后允许出现的词
BOUNDARY_WORDS = [
    "辩称", "诉称", "陈述", "述称", "答辩", "辩称", "称", "诉", "委托", "代理", "律师",
    "出庭", "到庭", "参加", "诉讼", "男，", "女，", "汉族", "出生", "生于", "现住", "住址",
    "身份证", "公民身份号码", "公民身份证号", "系", "等人", "等", "与", "及其", "之子", "之女",
    "之父", "之母", "之妻", "之夫", "配偶", "本人", "亲自", "签名", "捺印", "到庭",
]

# 姓名前允许出现的插入语（角色词与姓名之间）
_FILLER_CHARS = set("：:、，,（）()【】[]{} 　\t\n\r-—–《》\"'“”‘’·.。;；")

# 平衡括号对
_BRACKETS = {"（": "）", "(": ")", "【": "】", "[": "]", "《": "》", "〈": "〉", "{": "}"}


def looks_like_name(s: str, strict: bool = True) -> tuple[bool, str]:
    """结构校验一个候选是否为中文姓名。返回 (是否, 原因)。

    注意：通用词过滤（GENERIC_WORDS）不放在这里，只用于 C 路径。
    角色词路径（A）精度本来就高，"原告：王文明"这类名字含通用词的
    情况必须放过；C 路径才需要靠通用词表压误报。
    """
    if not s or len(s) < 2 or len(s) > 5:
        return False, "长度不在2-5"
    if any(ch in L.NAME_FORBIDDEN_CHARS for ch in s):
        return False, "含虚词/标点字符"
    if s in L.NON_NAME_WORDS:
        return False, "命中非人名词表"
    if s in L.ANONYMIZED_SUFFIXES or s.endswith("某某"):
        return True, "已匿名写法"

    # 姓氏前缀
    compound = None
    for cs in L.COMPOUND_SURNAMES:
        if s.startswith(cs):
            compound = cs
            break
    if compound:
        body = s[len(compound):]
        if len(body) < 1 or len(body) > 3:
            return False, "复姓后名长异常"
        return True, f"复姓{compound}"

    sur = s[0]
    if sur not in L.ALL_SURNAMES:
        return False, f"首字'{sur}'非姓氏"

    body = s[1:]
    if strict and sur in L.SURNAMES_RISKY:
        risky_words = L.SURNAMES_RISKY[sur]
        for w in risky_words:
            if s == w or w.startswith(s):
                return False, f"'{sur}'为高风险姓且命中常用词'{w}'"

    if len(body) < 1 or len(body) > 3:
        return False, "名长异常"

    # 全部由常见名字用字组成 → 加分（在 attrs 里体现，这里不拒）
    return True, f"单姓{sur}"


def _is_boundary(text: str, pos: int) -> bool:
    if pos >= len(text):
        return True
    ch = text[pos]
    if ch in BOUNDARY_CHARS:
        return True
    for w in BOUNDARY_WORDS:
        if text.startswith(w, pos):
            return True
    return False


def _contains_role_trigger(s: str) -> bool:
    """候选姓名里若含角色词（如"向原告发"里的"原告"），判为误报。"""
    return bool(TRIGGER_RE.search(s))


def _starts_role_trigger(text: str, pos: int) -> bool:
    """候选之后紧跟角色词 → 说明候选本身是半个短语（"向原"后面是"原告"）。"""
    if pos >= len(text):
        return False
    return bool(TRIGGER_RE.match(text, pos))


def _cross_bigram_generic(text: str, end: int, cand: str) -> bool:
    """跨界二字词命中通用词表 → 断句错了（"张三委|托律师"里的"委托"）。"""
    if end >= len(text) or not cand:
        return False
    return (cand[-1] + text[end]) in L.GENERIC_WORDS


def _prev_bigram_generic(text: str, pos: int, cand: str) -> bool:
    """候选的首字与前一个字组成通用词 → 起点错了。

    OCR 文本里"住上海市"会被从"海"起切成"海市"，
    而"上海"正是通用词，据此否掉。
    """
    if pos <= 0 or not cand:
        return False
    return (text[pos - 1] + cand[0]) in L.GENERIC_WORDS


def _follows_org_suffix(text: str, pos: int, end: int) -> bool:
    """角色词后面其实是机构名（"被告华远置业有限公司"）→ 一票否决。"""
    window = text[pos:min(len(text), end + 8)]
    m = _ORG_SUFFIX_RE.search(window)
    if not m:
        return False
    # 机构后缀必须紧贴候选（中间没有句读），否则可能是下一个分句里的机构
    gap = window[:m.start()]
    return not any(c in gap for c in "，。；、！？：\n\r")


def _candidate_ok(text: str, pos: int, cand: str, end: int,
                  require_boundary: bool, strict_generic: bool) -> bool:
    if not all("\u4e00" <= c <= "\u9fa5" for c in cand):
        return False
    ok, _why = looks_like_name(cand, strict=True)
    if not ok:
        return False
    if _contains_role_trigger(cand):
        return False
    if L.contains_generic_word(cand, only_at_start=not strict_generic):
        return False
    if _cross_bigram_generic(text, end, cand):
        return False
    if _prev_bigram_generic(text, pos, cand):
        return False
    if _starts_role_trigger(text, end):
        return False
    if _follows_org_suffix(text, pos, end):
        return False
    if require_boundary and not _is_boundary(text, end):
        return False
    return True


def _extract_candidate(text: str, pos: int, strict_generic: bool = False,
                       require_boundary: bool = True):
    """从 pos 开始（已跳过插入语），尝试提取姓名。

    长度尝试顺序按中文姓名的真实分布：3 字 > 2 字 > 4 字。
    先试 4 字会让"证人孙丽华陈述"被吃成"孙丽华陈"，
    而 4 字汉族姓名在法律文书里极少（复姓走单独分支）。

    require_boundary=False（角色词路径）时不强制要求后面是边界字符——
    "书记员方文静担任法庭记录"里的"担"既不是标点也不在边界词表里，
    强制边界会把这个真名整条漏掉；改用一组否决规则来控精度。
    """
    # 复姓：总长 4(复姓+2) / 3(复姓+1) / 5(复姓+3)
    for cs in L.COMPOUND_SURNAMES:
        if text.startswith(cs, pos):
            for extra in (2, 1, 3):
                end = pos + len(cs) + extra
                if end > len(text):
                    continue
                cand = text[pos:end]
                if _candidate_ok(text, pos, cand, end, require_boundary, strict_generic):
                    return cand, end
            return None

    sur = text[pos] if pos < len(text) else ""
    if sur not in L.ALL_SURNAMES:
        return None
    for extra in (2, 1, 3):
        end = pos + 1 + extra
        if end > len(text):
            continue
        cand = text[pos:end]
        if _candidate_ok(text, pos, cand, end, require_boundary, strict_generic):
            return cand, end
    return None
    return None


def _skip_filler(text: str, pos: int, budget: int) -> int:
    """跳过角色词与姓名之间的分隔符与平衡括号插入语。"""
    end = min(len(text), pos + budget)
    i = pos
    while i < end:
        ch = text[i]
        if ch in _FILLER_CHARS:
            # 平衡括号：整段跳过
            if ch in _BRACKETS:
                close = _BRACKETS[ch]
                depth = 1
                j = i + 1
                while j < end and depth:
                    if text[j] == ch:
                        depth += 1
                    elif text[j] == close:
                        depth -= 1
                    j += 1
                i = j
                continue
            i += 1
            continue
        break
    return i


class PersonNameDetector(Detector):
    """自然人姓名检测。"""

    name = "person"
    produces = ("PERSON",)

    def __init__(self, learned_names: Sequence[str] = (), enable_c_path: bool = True):
        self.learned_names: set[str] = set(learned_names)
        self.enable_c_path = enable_c_path

    # ------------------------------------------------------------------
    def detect(self, text: str, block: str = "body") -> list[Span]:
        out: list[Span] = []
        out.extend(self._path_a_roles(text, block))
        out.extend(self._path_b_signature(text, block))
        out.extend(self._path_d_learned(text, block))
        if self.enable_c_path:
            # C 路径跳过 A/B/D 已覆盖的位置，避免同一处重复报低置信候选
            covered = [(s.block, s.text, s) for s in out]
            ranges = [(s.block, s) for s in out]
            spans = list(self._path_c_surname(text, block))
            keep = []
            for c in spans:
                overlap = False
                for s in out:
                    if s.block == c.block and s.overlaps(c):
                        overlap = True
                        break
                if not overlap:
                    keep.append(c)
            out.extend(keep)
        return out

    # -- A: 角色触发 ---------------------------------------------------
    def _path_a_roles(self, text: str, block: str) -> Iterable[Span]:
        for m in TRIGGER_RE.finditer(text):
            role = m.group(1)
            pos = _skip_filler(text, m.end(), L.ROLE_MAX_GAP)
            if pos >= len(text):
                continue
            # 同一角色后可能列多个当事人：张三、李四、王五
            guard = 0
            while guard < 8:
                guard += 1
                got = _extract_candidate(text, pos, require_boundary=False)
                if not got:
                    break
                cand, end = got
                if cand.endswith("某") or cand.endswith("某某"):
                    attrs = {"already_anonymized": True}
                    conf = 0.99
                    reason = f"角色词'{role}'后的已匿名写法"
                else:
                    attrs = {}
                    conf = 0.95
                    reason = f"角色词'{role}'后接姓名"
                yield Span(pos, end, cand, "PERSON", confidence=conf,
                           source=self.name, reason=reason,
                           attrs={**attrs, "role": role, "path": "A"}, block=block)
                pos = end
                # 顿号/和/及 连接的下一个当事人
                nxt = _skip_filler(text, pos, 4)
                if nxt > pos and text[pos:nxt].strip(" ") and any(
                        c in text[pos:nxt] for c in "、，,和及与"):
                    pos = nxt
                    continue
                break

    # -- B: 落款 -------------------------------------------------------
    def _path_b_signature(self, text: str, block: str) -> Iterable[Span]:
        for pat in L.SIGNATURE_PATTERNS:
            for m in re.finditer(pat, text):
                try:
                    cand = m.group("n")
                except (IndexError, re.error):
                    continue
                s = m.start("n")
                e = m.end("n")
                ok, why = looks_like_name(cand)
                if not ok:
                    continue
                yield Span(s, e, cand, "PERSON", confidence=0.9, source=self.name,
                           reason=f"落款/署名模式：{pat.split('[')[0]}（{why}）",
                           attrs={"path": "B"}, block=block)

    # -- D: learned 名单 -----------------------------------------------
    def _path_d_learned(self, text: str, block: str) -> Iterable[Span]:
        for nm in self.learned_names:
            if len(nm) < 2:
                continue
            start = 0
            while True:
                i = text.find(nm, start)
                if i < 0:
                    break
                start = i + 1
                yield Span(i, i + len(nm), nm, "PERSON", confidence=0.98,
                           source=self.name, reason="learned 名单精确匹配（本批次其他位置已确认）",
                           attrs={"path": "D", "learned": True}, block=block)

    # -- C: 姓氏扫描 ---------------------------------------------------
    def _path_c_surname(self, text: str, block: str) -> Iterable[Span]:
        """只在有上下文支持时产出候选，避免把"高级""万元"当人名。"""
        # 已有 A/B/D 覆盖的位置，C 不再重复
        covered: list[tuple[int, int]] = []
        for m in TRIGGER_RE.finditer(text):
            covered.append((m.start(), min(len(text), m.end() + L.ROLE_MAX_GAP)))

        i = 0
        n = len(text)
        while i < n:
            ch = text[i]
            if ch not in L.ALL_SURNAMES:
                i += 1
                continue
            got = _extract_candidate(text, i, strict_generic=True)
            if not got:
                i += 1
                continue
            cand, end = got
            if cand.endswith("某"):
                i = end
                continue
            # 高风险姓必须有上下文支持
            risky = cand[0] in L.SURNAMES_RISKY
            ctx_a = max(0, i - 30)
            ctx_b = min(n, end + 30)
            ctx = text[ctx_a:ctx_b]

            support = 0.0
            reasons = []
            if re.search(r"(男|女)[，,、\s]", ctx[end - i:]):
                support += 0.25
                reasons.append("后接性别")
            if re.search(r"(19|20)\d{2}\s*年", ctx[end - i:end - i + 30]):
                support += 0.25
                reasons.append("后接出生年份")
            if re.search(r"(汉族|回族|满族|蒙古族|藏族|苗族|彝族|壮族)", ctx[end - i:]):
                support += 0.15
                reasons.append("后接民族")
            if any(ch2 in ctx[: i - ctx_a] for ch2 in "：:") and re.search(
                    r"(当事人|名单|署名|签名|在场|见证|联系|经办|承办|记录)", ctx[: i - ctx_a]):
                support += 0.2
                reasons.append("前有当事人/名单类提示")
            if re.search(r"(身份证|公民身份|户籍|住所地?|住址)", ctx):
                support += 0.1
                reasons.append("上下文含身份信息词")
            if any(c in L.NAME_COMMON_CHARS for c in cand[1:]):
                support += 0.1
                reasons.append("含常见名字用字")
            # 该姓名在文中多次出现 → 更像真名而非偶然词
            occurrences = text.count(cand)
            if occurrences >= 3:
                support += 0.2
                reasons.append(f"全文出现{occurrences}次")
            elif occurrences == 2:
                support += 0.1
                reasons.append("全文出现2次")

            in_role_window = any(a <= i < b for a, b in covered)
            if in_role_window:
                support += 0.15
                reasons.append("位于角色词窗口内")

            if risky and support < 0.45:
                i = end
                continue
            if support < 0.3:
                i = end
                continue

            conf = min(0.6 + support, 0.85)
            yield Span(i, end, cand, "PERSON", confidence=round(conf, 2),
                       source=self.name,
                       reason="姓氏词典候选：" + ("、".join(reasons) if reasons else "无强上下文"),
                       attrs={"path": "C", "support": round(support, 2), "risky": risky},
                       block=block)
            i = end
