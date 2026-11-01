"""地址检测与行政级别解析。

思路：不做通用地址 NER，而是"锚点 + 地址字符集前向吞噬 + 级别回溯"。
锚点来自两类：提示词（住址/住所地/位于/现住…）与省市名。
吞噬到句读为止，再回溯确定到达的行政级别，供泛化策略按级截断。
"""
from __future__ import annotations

import re
from typing import Iterable

from ..core import Span
from .base import Detector
from . import lexicon as L

# 地址内允许出现的字符
_ADDR_CHARS = set("0123456789ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺ"
                  "abcdefghijｋlmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                  "-—–()（）·．.号甲乙丙丁东西南北中")
# 遇到即停止
_ADDR_STOP = set("，。；：、！？\n\r\t,;:!?|“”\"'《》〈〉【】")

# 提示词（按长度降序，最长匹配）
_HINTS = sorted(L.ADDR_HINTS, key=len, reverse=True)
_HINT_RE = re.compile("(" + "|".join(re.escape(h) for h in _HINTS) + r")[：:是为]?\s*")

# 直辖市/省名（含简称），作为无提示词时的锚点
_PROV_RE = re.compile("(" + "|".join(re.escape(p) for p in L.PROVINCES) + "|"
                      + "|".join(re.escape(p) for p in sorted(L.PROVINCE_SHORT, key=len, reverse=True)) + ")")

# 各级后缀
_LEVEL_SUFFIX_RE = [
    (1, re.compile(r"(自治区|特别行政区|省)(?![\u4e00-\u9fa5]*委)")),
    (2, re.compile(r"(自治州|地区|盟|市)")),
    (3, re.compile(r"(自治县|林区|特区|旗|区|县|市)")),
    (4, re.compile(r"(街道办事处|街道|民族乡|苏木|镇|乡)")),
    (5, re.compile(r"(居委会|村委会|社区|新村|花园|公寓|大厦|广场|小区|苑|村|屯|寨|组|队)")),
    (6, re.compile(r"(大道|大街|公路|高速|匝道|胡同|路|街|道|巷|弄|里|条)")),
    (7, re.compile(r"(号院|号楼|号门|摊位|车间|仓库|单元|号|幢|栋|座|层|楼|室|房|户|间|铺)")),
]

MIN_ADDR_LEN = 6
MAX_ADDR_LEN = 60

# 地址必须以下列成分收尾，否则回溯截断到最后一个收尾成分
_TERMINATOR_RE = re.compile(
    r"(号院|号楼|号门|大道|大街|公路|胡同|小巷|新村|花园|公寓|大厦|广场|小区|"
    r"中心|仓库|车间|摊位|营业室|营业部|办公室|"
    r"号|室|房|户|间|铺|层|楼|栋|幢|座|院|村|屯|寨|组|队|路|街|道|巷|弄|里|条|园|所|站|单元)$"
)

# 收尾处悬挂的括号/引号
_TRAILING_JUNK_RE = re.compile(r"[）)】\]》〉>”\"'’、，,。．.；;：:\-—…\s]+$")

# 这些后缀说明抓到的其实是机构名而不是地址
_ORG_TAIL_RE = re.compile(
    r"(人民法院|人民检察院|律师事务所|仲裁委员会|有限公司|股份公司|有限责任公司|"
    r"集团|银行|信用社|医院|学校|大学|学院|中学|小学|幼儿园|派出所|公安局|"
    r"司法局|人民政府|管委会|管理局|事务所|公证处)$"
)


def address_level(run: str) -> tuple[int, int]:
    """回溯地址行政级别。返回 (最深层级, 该层结束位置)。

    层级：1省 2市 3区县 4镇街 5村居 6路 7门牌/楼栋室
    必须按顺序出现，避免"路"里的"道"误判。
    """
    pos = 0
    level = 0
    end_pos = 0
    for lv, rx in _LEVEL_SUFFIX_RE:
        if lv <= level:
            continue
        best = None
        for m in rx.finditer(run, pos):
            best = m
            break
        if best is None:
            continue
        level = lv
        pos = best.end()
        end_pos = pos
    return level, end_pos


def truncate_to_level(run: str, target_level: int) -> str:
    """把地址截断到指定行政级别。找不到该级时退到更高级。"""
    lv, end = address_level(run)
    if end == 0:
        return run[:2] + "…" if len(run) > 2 else run
    if lv <= target_level:
        return run  # 本来就没超过目标级别
    # 找目标级别的结束位置
    pos = 0
    keep_end = 0
    cur = 0
    for lv2, rx in _LEVEL_SUFFIX_RE:
        if lv2 > target_level:
            break
        m = rx.search(run, pos)
        if m is None:
            continue
        cur = lv2
        pos = m.end()
        keep_end = pos
    if keep_end == 0:
        return run[:min(3, len(run))]
    return run[:keep_end]


class AddressDetector(Detector):
    name = "address"
    produces = ("ADDRESS",)

    def detect(self, text: str, block: str = "body") -> list[Span]:
        out: list[Span] = []
        seen: set[tuple[int, int]] = set()

        # 1) 提示词锚点
        for m in _HINT_RE.finditer(text):
            span = self._grow(text, m.end(), block, hint=m.group(1))
            if span and (span.start, span.end) not in seen:
                seen.add((span.start, span.end))
                out.append(span)

        # 2) 省市名锚点（无提示词）
        for m in _PROV_RE.finditer(text):
            if any(m.start() >= s and m.start() < e for s, e in seen):
                continue
            span = self._grow(text, m.start(), block, hint=None, force_start=True)
            if span and (span.start, span.end) not in seen:
                seen.add((span.start, span.end))
                out.append(span)

        return out

    def _grow(self, text: str, pos: int, block: str, hint: str | None,
              force_start: bool = False) -> Span | None:
        n = len(text)
        i = pos
        limit = min(n, pos + MAX_ADDR_LEN)
        # 吞地址字符
        while i < limit:
            ch = text[i]
            if ch in _ADDR_STOP:
                break
            if "\u4e00" <= ch <= "\u9fa5" or ch in _ADDR_CHARS:
                i += 1
                continue
            break
        run = text[pos:i]
        start = pos

        # 1) 去掉尾部悬挂的括号/标点
        run = _TRAILING_JUNK_RE.sub("", run)
        # 2) 去掉尾部悬挂的连接词
        while True:
            r2 = re.sub(r"(的|之|与|和|及|或|在|系|为|等|以|于|后|前|中|内|外)$", "", run)
            if r2 == run:
                break
            run = r2
        # 2.5) 去掉开头残留的提示词。
        #      "原告原住址住北京市东城区…"里 _HINT_RE 吃掉"住址"后，
        #      run 会从一个多余的"住"开始，必须剥掉，否则替换后语义不通。
        changed = True
        while changed and len(run) > MIN_ADDR_LEN:
            changed = False
            for h in _HINTS:
                if run.startswith(h) and len(run) - len(h) >= MIN_ADDR_LEN:
                    run = run[len(h):]
                    start += len(h)
                    changed = True
                    break
            if changed:
                continue
            for c in "：:是为，,、 　":
                if run.startswith(c) and len(run) - 1 >= MIN_ADDR_LEN:
                    run = run[1:]
                    start += 1
                    changed = True
                    break
        if len(run) < MIN_ADDR_LEN:
            return None

        # 3) 必须以地址成分收尾；否则回溯到最后一个收尾成分
        #    截断用的成分表比 _TERMINATOR_RE 少一个"房"：
        #    "…401室房屋"若把"房"当收尾会多吞一字
        if not _TERMINATOR_RE.search(run):
            last = None
            for m in re.finditer(
                    r"(号院|号楼|号门|大道|大街|公路|胡同|新村|花园|公寓|大厦|广场|小区|"
                    r"中心|仓库|车间|摊位|营业室|营业部|办公室|"
                    r"号|室|户|间|铺|层|楼|栋|幢|座|院|村|屯|寨|组|队|路|街|道|巷|弄|里|条|园|所|站|单元)",
                    run):
                last = m
            if last is None:
                return None
            run = run[: last.end()]
            if len(run) < MIN_ADDR_LEN:
                return None

        # 4) 收尾是机构名的，交给 ORG/COURT 检测器，这里不报
        if _ORG_TAIL_RE.search(run):
            return None

        end = start + len(run)
        lv, lv_end = address_level(run)
        if lv < 2:
            # 至少要解析到市级，否则多半是误报
            if not force_start or lv < 1:
                return None

        has_detail = bool(re.search(
            r"(路|街|道|巷|弄|号|栋|幢|座|单元|层|楼|室|村|社区|小区|组|屯|院)", run))
        conf = 0.9 if (hint and has_detail) else (0.8 if hint else (0.7 if has_detail else 0.5))

        level_names = {1: "省级", 2: "市级", 3: "区县级", 4: "镇街级", 5: "村居级",
                       6: "路级", 7: "门牌/楼栋级"}
        return Span(start, end, run, "ADDRESS", confidence=conf, source=self.name,
                    reason=f"锚点{'“'+hint+'”' if hint else '省市名'}，解析到{level_names.get(lv, '未知')}，"
                           f"{'含' if has_detail else '不含'}门牌细节",
                    attrs={"level": lv, "level_name": level_names.get(lv, ""),
                           "has_detail": has_detail, "hint": hint or ""},
                    block=block)


class BankBranchDetector(Detector):
    """开户行/支行名称。"""

    name = "bank_branch"
    produces = ("BANK_BRANCH",)

    _RE = re.compile(
        r"[\u4e00-\u9fa5A-Za-z0-9（）()]{2,25}?"
        r"(?:银行|信用社|信用合作联社|储蓄所|邮政储蓄|农村商业银行|村镇银行)"
        r"[\u4e00-\u9fa5A-Za-z0-9]{0,20}?"
        r"(?:分行|支行|分理处|营业部|营业室|储蓄所|办事处|分社|信用社|分中心|营业部)"
    )
    _RE2 = re.compile(
        r"[\u4e00-\u9fa5]{2,14}(?:银行|农村信用合作联社|农村商业银行|村镇银行|信用社)"
        r"(?:股份有限公司|有限责任公司|有限公司)?"
    )

    # 前缀里出现这些词，说明回溯越界了，从最后一个之后切开
    _PREFIX_STOP = [
        "通过", "于", "在", "经", "向", "由", "自", "从", "至", "据", "依照", "按照",
        "将", "把", "被", "给", "汇至", "汇入", "转入", "存入", "支付", "给付",
        "年", "月", "日", "号", "第", "元", "万元", "，", "。", "、", "：", "；",
        "账户", "账号", "卡号", "开户",
    ]

    def _clean_prefix(self, text: str, start: int, end: int) -> int:
        """把机构名的前缀裁到最后一个停用词之后。

        "原告于2023年4月3日通过中国工商银行股份有限公司北京朝阳支行"
        直接回溯会得到一整句，这里从"通过"之后切开。
        """
        body = text[start:end]
        cut = 0
        for w in self._PREFIX_STOP:
            i = body.rfind(w)
            if i >= 0 and i + len(w) > cut:
                cut = i + len(w)
        return start + cut

    def detect(self, text: str, block: str = "body") -> list[Span]:
        out = []
        taken: list[tuple[int, int]] = []
        for m in self._RE.finditer(text):
            s = self._clean_prefix(text, m.start(), m.end())
            body = text[s:m.end()]
            if len(body) < 6:
                continue
            out.append(Span(s, m.end(), body, "BANK_BRANCH",
                            confidence=0.93, source=self.name,
                            reason="开户行/支行名称（含分支机构后缀）",
                            attrs={"kind": "branch"}, block=block))
            taken.append((s, m.end()))
        for m in self._RE2.finditer(text):
            if any(a <= m.start() < b or a < m.end() <= b for a, b in taken):
                continue
            # 排除"银行卡""银行账户"这类非机构名
            tail = text[m.end():m.end() + 3]
            if re.match(r"^(卡|账户|账号|帐号)", tail):
                continue
            s = self._clean_prefix(text, m.start(), m.end())
            body = text[s:m.end()]
            if len(body) < 4:
                continue
            out.append(Span(s, m.end(), body, "BANK_BRANCH",
                            confidence=0.78, source=self.name,
                            reason="银行机构名称（无分支机构后缀）",
                            attrs={"kind": "bank"}, block=block))
        return out
