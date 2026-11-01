"""强标识符检测：正则 + 校验位。

这一层的原则是"宁可漏，不可错杀"与"宁可错杀，不可漏"之间取平衡：
校验位通过的给高置信度直接脱敏；形似但校验不过的降级为 SUSPECT_ID，
只提交人工复核，不自动改。
"""
from __future__ import annotations

import datetime as _dt
import re
from typing import Iterator

from ..core import Span, Strategy
from .base import Detector

# --------------------------------------------------------------------------
# 校验算法
# --------------------------------------------------------------------------

_ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
_ID_CHECK = "10X98765432"

# 省级行政区代码（GB/T 2260 前两位）
_VALID_PROVINCE_CODES = {
    "11", "12", "13", "14", "15", "21", "22", "23", "31", "32", "33", "34", "35",
    "36", "37", "41", "42", "43", "44", "45", "46", "50", "51", "52", "53", "54",
    "61", "62", "63", "64", "65", "71", "81", "82", "91",
}


def id_card_checksum_ok(id18: str) -> bool:
    """GB 11643-1999 身份证校验位。"""
    if len(id18) != 18:
        return False
    body, chk = id18[:17], id18[17].upper()
    if not body.isdigit() or chk not in "0123456789X":
        return False
    s = sum(int(body[i]) * _ID_WEIGHTS[i] for i in range(17))
    return _ID_CHECK[s % 11] == chk


def id_card_semantic_ok(id18: str) -> tuple[bool, str]:
    """进一步语义校验：地区码 + 出生日期合法性 + 年份范围。"""
    if id18[:2] not in _VALID_PROVINCE_CODES:
        return False, "省级地区码非法"
    y, m, d = id18[6:10], id18[10:12], id18[12:14]
    try:
        birth = _dt.date(int(y), int(m), int(d))
    except ValueError:
        return False, "出生日期非法"
    now = _dt.date.today()
    if birth > now:
        return False, "出生日期在未来"
    if birth.year < 1900:
        return False, "出生年份早于1900"
    if (now - birth).days // 365 > 130:
        return False, "年龄超过130岁"
    return True, ""


def luhn_ok(num: str) -> bool:
    """银行卡 Luhn 校验。"""
    digits = [int(c) for c in num if c.isdigit()]
    if len(digits) < 13:
        return False
    s = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        s += d
    return s % 10 == 0


_USCC_CHARS = "0123456789ABCDEFGHJKLMNPQRTUWXY"
_USCC_WEIGHTS = [1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28]


def uscc_ok(code: str) -> bool:
    """GB 32100-2015 统一社会信用代码校验位。"""
    code = code.upper().replace(" ", "")
    if len(code) != 18:
        return False
    if any(c not in _USCC_CHARS for c in code):
        return False
    s = sum(_USCC_CHARS.index(code[i]) * _USCC_WEIGHTS[i] for i in range(17))
    c18 = 31 - (s % 31)
    if c18 == 31:
        c18 = 0
    return _USCC_CHARS[c18] == code[17]


# --------------------------------------------------------------------------
# 正则
# --------------------------------------------------------------------------

# 手机号：允许 +86 / 86 前缀、空格、连字符
PHONE_RE = re.compile(
    r"(?<![\d])"
    r"(?:\+?86[\s\-]?)?"
    r"(1[3-9]\d)"
    r"[\s\-]?(\d{4})[\s\-]?(\d{4})"
    r"(?![\d])"
)

# 固定电话：区号(3-4位) - 号码(7-8位)，可带分机
TEL_RE = re.compile(
    r"(?<![\d\-])"
    r"(?:0\d{2,3})[\s\-—]?\d{7,8}"
    r"(?:[\s\-]?(?:转|ext\.?|分机)\s?\d{1,6})?"
    r"(?![\d])"
)

EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9_.+-])"
    r"[A-Za-z0-9_.+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){1,4}"
    r"(?![A-Za-z0-9_.\-])"
)

URL_RE = re.compile(
    r"(?<![\w])(?:https?://|www\.)[^\s\u4e00-\u9fa5<>\"'（）()【】\[\]，。；、]{3,200}",
    re.IGNORECASE,
)

IP_RE = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])"
)
# IP 前后出现这些词时视为版本号/编号，跳过
IP_FALSE_CONTEXT = re.compile(r"(版本|v\d|V\d|版|No\.|编号|第\s*[\d一二三四五六七八九十]+\s*章|条款)", re.I)

# 注意：lookbehind 不能用 \w —— Python 的 \w 在 str 模式下匹配汉字，
# 而中文里 MAC/车牌前面几乎总跟着汉字（"MAC地址00:1A:2B…"）
MAC_RE = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}"
    r"(?![0-9A-Fa-f:])"
)

# 车牌：普通 7 位 + 新能源 8 位
# 注意：不能用前向断言排除 CJK——中文里车牌前面几乎总跟着汉字（"其名下车辆粤A12345"）
_PLATE_PROV = "京津冀晋蒙辽吉黑沪苏浙皖闽赣鲁豫鄂湘粤桂琼渝川贵云藏陕甘青宁新使领学警港澳"
PLATE_RE = re.compile(
    rf"[{_PLATE_PROV}][A-HJ-NP-Z]"
    r"[\s\-·]?"
    r"(?:[0-9]{5}[0-9A-HJ-NP-Z]|[0-9A-HJ-NP-Z][0-9]{4}[0-9A-HJ-NP-Z]|[A-HJ-NP-Z0-9]{5})"
    r"(?![0-9A-HJ-NP-Z])"
)

# 提示词触发的各类编号（律师执业证、营业执照、许可证等）
LICENSE_HINT_RE = re.compile(
    r"(律师执业证号?|执业证号|执业证书号|法律职业资格证号?|营业执照号?|"
    r"注册号|许可证号?|备案号?|登记证号?|资格证书号?|税务登记证号?|"
    r"组织机构代码|机构代码|批准文号|批复文号)"
    r"[：:\s是为]*([0-9A-Za-z\-]{6,32})"
)

PASSPORT_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:护照号?码?|passport(?:\s*no\.?)?)[：:\s]*"
    r"([EGDSPHM]\d{8})(?![A-Za-z0-9])", re.IGNORECASE
)
PASSPORT_BARE_RE = re.compile(r"(?<![A-Za-z0-9])([EGDSPHM]\d{8})(?![A-Za-z0-9])")

HK_MO_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:港澳(?:通行证|居民来往内地通行证)?号?码?|通行证号?)[：:\s]*"
    r"([CWcw]\d{8})(?![A-Za-z0-9])"
)

# 18 位身份证（末位可为 X）
ID18_RE = re.compile(r"(?<!\d)(\d{17}[\dXx])(?!\d)")
# 15 位老身份证
ID15_RE = re.compile(r"(?<!\d)(\d{15})(?!\d)")
# 形似身份证但含分隔符：110105 19900101 123X
ID_SPACED_RE = re.compile(r"(?<!\d)(\d{6})[\s\-](\d{8})[\s\-](\d{3}[\dXx])(?!\d)")

# 13-19 位纯数字，可能是银行卡
BANK_CANDIDATE_RE = re.compile(r"(?<!\d)(\d{13,19})(?!\d)")
# 常见发卡行 BIN 前缀（提高精度）
BANK_BINS = (
    "62", "60", "4", "5", "35", "37", "9", "41", "42", "43", "44", "45", "46",
    "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59",
    "34", "36", "30", "38", "39",
)
BANK_HINT_RE = re.compile(
    r"(银行卡|卡号|账号|账户|帐号|借记卡|信用卡|储蓄卡|开户行|开户账号|"
    r"收款账户|付款账户|工商银行|农业银行|中国银行|建设银行|交通银行|招商银行|"
    r"邮储银行|浦发银行|民生银行|兴业银行|光大银行|华夏银行|平安银行|中信银行|"
    r"广发银行|北京银行|上海银行|农村商业银行|农村信用社|村镇银行)"
)

# 统一社会信用代码
USCC_RE = re.compile(r"(?<![0-9A-Za-z])([0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10})(?![0-9A-Za-z])")
# 老 15 位工商注册号 / 组织机构代码
OLD_BIZ_REG_RE = re.compile(r"(?<!\d)(\d{15})(?!\d)")

QQ_RE = re.compile(
    r"(QQ|qq|Q号|扣扣|腾讯QQ)[号号码码]?[：:\s是为]*"
    r"([1-9]\d{4,10})(?!\d)"
)
WECHAT_RE = re.compile(
    r"(微信|微信号|weixin|wechat|wx|vx|VX|薇信|微❤|威信)"
    r"[号号码]?[：:\s是为]*"
    r"([A-Za-z][\-_A-Za-z0-9]{5,19}|1[3-9]\d{9}|[1-9]\d{5,10})"
    r"(?![\w])",
    re.IGNORECASE,
)

# --------------------------------------------------------------------------


class StrongIdentifierDetector(Detector):
    """强标识符检测器。"""

    name = "strong_regex"
    produces = (
        "ID_CARD", "SUSPECT_ID", "PHONE", "TEL", "BANK_CARD", "USCC", "EMAIL",
        "IP_ADDR", "MAC_ADDR", "PLATE", "PASSPORT", "HK_MO_PERMIT", "IM_ACCOUNT",
        "URL", "LICENSE_NO",
    )

    def detect(self, text: str, block: str = "body") -> list[Span]:
        out: list[Span] = []
        out.extend(self._id_card(text, block))
        out.extend(self._phone(text, block))
        out.extend(self._tel(text, block))
        out.extend(self._bank_card(text, block))
        out.extend(self._uscc(text, block))
        out.extend(self._email(text, block))
        out.extend(self._ip(text, block))
        out.extend(self._mac(text, block))
        out.extend(self._plate(text, block))
        out.extend(self._passport(text, block))
        out.extend(self._hkmo(text, block))
        out.extend(self._im(text, block))
        out.extend(self._license(text, block))
        out.extend(self._url(text, block))
        return out

    # -- 身份证 ---------------------------------------------------------
    def _id_card(self, text: str, block: str) -> Iterator[Span]:
        for m in ID18_RE.finditer(text):
            v = m.group(1).upper()
            if id_card_checksum_ok(v):
                ok, why = id_card_semantic_ok(v)
                if ok:
                    yield Span(m.start(), m.end(), m.group(1), "ID_CARD",
                               confidence=0.99, source=self.name,
                               reason=f"18位+校验位通过+地区码{v[:2]}+出生{v[6:14]}",
                               attrs={"birth": v[6:14], "region": v[:6], "gender": int(v[16]) % 2},
                               block=block)
                else:
                    yield Span(m.start(), m.end(), m.group(1), "SUSPECT_ID",
                               confidence=0.5, source=self.name,
                               reason=f"校验位通过但语义异常：{why}", block=block)
            else:
                yield Span(m.start(), m.end(), m.group(1), "SUSPECT_ID",
                           confidence=0.35, source=self.name,
                           reason="18位数字形似身份证，校验位不通过", block=block)

        # 带分隔符的身份证
        for m in ID_SPACED_RE.finditer(text):
            joined = (m.group(1) + m.group(2) + m.group(3)).upper()
            if id_card_checksum_ok(joined):
                yield Span(m.start(), m.end(), m.group(0), "ID_CARD",
                           confidence=0.97, source=self.name,
                           reason="分隔符变体，拼接后校验位通过", block=block)

        # 15 位老证：只在校验出生年份合理时给出，且降级为 SUSPECT_ID
        for m in ID15_RE.finditer(text):
            v = m.group(1)
            yy, mm, dd = int(v[6:8]), int(v[8:10]), int(v[10:12])
            if 1 <= mm <= 12 and 1 <= dd <= 31 and v[:2] in _VALID_PROVINCE_CODES:
                year = 1900 + yy if yy > 25 else 2000 + yy
                if 1900 <= year <= _dt.date.today().year:
                    yield Span(m.start(), m.end(), v, "SUSPECT_ID",
                               confidence=0.45, source=self.name,
                               reason=f"15位老身份证格式，推断出生{year}-{mm:02d}-{dd:02d}",
                               attrs={"birth": f"{year}{mm:02d}{dd:02d}"}, block=block)

    # -- 手机 ------------------------------------------------------------
    def _phone(self, text: str, block: str) -> Iterator[Span]:
        for m in PHONE_RE.finditer(text):
            digits = m.group(1) + m.group(2) + m.group(3)
            # 前后若是身份证/银行卡的一部分则跳过（由 merge 兜底，这里先粗筛）
            yield Span(m.start(), m.end(), m.group(0), "PHONE",
                       confidence=0.95, source=self.name,
                       reason=f"手机号段{digits[:3]}，归一化后{digits}",
                       attrs={"digits": digits}, block=block)

    # -- 固话 ------------------------------------------------------------
    def _tel(self, text: str, block: str) -> Iterator[Span]:
        for m in TEL_RE.finditer(text):
            # 排除手机号被误判（TEL_RE 不会匹配 11 位手机，但保险起见）
            raw = m.group(0)
            digits = re.sub(r"\D", "", raw)
            if len(digits) == 11 and digits.startswith("1") and digits[1] in "3456789":
                continue
            yield Span(m.start(), m.end(), raw, "TEL",
                       confidence=0.8, source=self.name,
                       reason=f"固定电话，区号{raw.split('-')[0].split(' ')[0]}",
                       attrs={"digits": digits}, block=block)

    # -- 银行卡 ----------------------------------------------------------
    def _bank_card(self, text: str, block: str) -> Iterator[Span]:
        for m in BANK_CANDIDATE_RE.finditer(text):
            v = m.group(1)
            # 已被身份证规则覆盖的 18 位不重复报
            if len(v) == 18 and id_card_checksum_ok(v):
                continue
            if not luhn_ok(v):
                continue
            # BIN 前缀校验
            if not any(v.startswith(b) for b in BANK_BINS):
                continue
            # 上下文加分：附近有银行/卡号提示词则置信度拉满
            ctx_a = max(0, m.start() - 30)
            ctx_b = min(len(text), m.end() + 30)
            hinted = bool(BANK_HINT_RE.search(text[ctx_a:ctx_b]))
            conf = 0.95 if hinted else 0.72
            yield Span(m.start(), m.end(), v, "BANK_CARD",
                       confidence=conf, source=self.name,
                       reason=("Luhn通过" + ("+上下文含银行/卡号提示词" if hinted else "，BIN前缀合理，无上下文提示")) ,
                       attrs={"tail": v[-4:], "bin": v[:6], "hinted": hinted}, block=block)

    # -- 统一社会信用代码 ------------------------------------------------
    def _uscc(self, text: str, block: str) -> Iterator[Span]:
        for m in USCC_RE.finditer(text):
            v = m.group(1)
            if uscc_ok(v):
                yield Span(m.start(), m.end(), v, "USCC",
                           confidence=0.97, source=self.name,
                           reason=f"18位统一社会信用代码，校验位通过，登记管理部门代码{v[0]}",
                           attrs={"reg_dept": v[0], "region": v[2:8]}, block=block)

    # -- 邮箱 ------------------------------------------------------------
    def _email(self, text: str, block: str) -> Iterator[Span]:
        for m in EMAIL_RE.finditer(text):
            v = m.group(0)
            if v.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".pdf", ".docx", ".xlsx")):
                continue  # 更像文件名
            yield Span(m.start(), m.end(), v, "EMAIL",
                       confidence=0.98, source=self.name,
                       reason="邮箱格式", attrs={"domain": v.split("@")[-1]}, block=block)

    # -- IP --------------------------------------------------------------
    def _ip(self, text: str, block: str) -> Iterator[Span]:
        for m in IP_RE.finditer(text):
            v = m.group(0)
            octs = [int(x) for x in v.split(".")]
            # 版本号常见形态 x.y.z 且第一段很小 / 或前后有版本字样
            ctx_a = max(0, m.start() - 12)
            ctx_b = min(len(text), m.end() + 12)
            if IP_FALSE_CONTEXT.search(text[ctx_a:ctx_b]):
                continue
            if octs[0] == 0:
                continue
            conf = 0.6
            reason = "IPv4 点分十进制"
            if octs[0] in (10, 127) or (octs[0] == 192 and octs[1] == 168) or (octs[0] == 172 and 16 <= octs[1] <= 31):
                conf = 0.9
                reason = "内网/保留网段，几乎必为真实 IP"
            elif any(re.search(k, text[ctx_a:ctx_b]) for k in ("IP", "ip地址", "IP地址", "登录", "服务器", "来源")):
                conf = 0.9
                reason = "上下文含 IP/登录/服务器提示词"
            yield Span(m.start(), m.end(), v, "IP_ADDR",
                       confidence=conf, source=self.name, reason=reason,
                       attrs={"octets": octs}, block=block)

    # -- MAC -------------------------------------------------------------
    def _mac(self, text: str, block: str) -> Iterator[Span]:
        for m in MAC_RE.finditer(text):
            yield Span(m.start(), m.end(), m.group(0), "MAC_ADDR",
                       confidence=0.85, source=self.name, reason="MAC 地址格式", block=block)

    # -- 车牌 ------------------------------------------------------------
    def _plate(self, text: str, block: str) -> Iterator[Span]:
        for m in PLATE_RE.finditer(text):
            v = m.group(0)
            core = re.sub(r"[\s\-·]", "", v)
            if len(core) not in (7, 8):
                continue
            # 全部由数字组成的尾段容易是编号误报，要求至少含一个字母或为纯 5 位数字+省份
            tail = core[2:]
            if tail.isdigit() and len(core) == 8:
                continue
            yield Span(m.start(), m.end(), v, "PLATE",
                       confidence=0.88, source=self.name,
                       reason=f"车牌：{core[0]}{core[1]}发牌机关+{core[2:]}",
                       attrs={"province": core[0], "issuer": core[1], "len": len(core)},
                       block=block)

    # -- 执业证/许可证等编号 ---------------------------------------------
    def _license(self, text: str, block: str) -> Iterator[Span]:
        for m in LICENSE_HINT_RE.finditer(text):
            hint, val = m.group(1), m.group(2)
            # 只报编号本体，不含提示词，便于替换后语义仍通顺
            s = m.start(2)
            e = m.end(2)
            yield Span(s, e, val, "LICENSE_NO", confidence=0.95, source=self.name,
                       reason=f"'{hint}'后的编号", attrs={"hint": hint}, block=block)

    # -- 护照 / 港澳通行证 ------------------------------------------------
    # 只报号码本体，不含"护照号"这类标签词：替换后语义仍通顺（"护照号[已脱敏]"）
    def _passport(self, text: str, block: str) -> Iterator[Span]:
        seen = set()
        for m in PASSPORT_RE.finditer(text):
            yield Span(m.start(1), m.end(1), m.group(1), "PASSPORT",
                       confidence=0.95, source=self.name, reason="护照号（带提示词）", block=block)
            seen.add(m.group(1))
        for m in PASSPORT_BARE_RE.finditer(text):
            if m.group(1) in seen:
                continue
            ctx_a = max(0, m.start() - 20)
            ctx_b = min(len(text), m.end() + 20)
            ctx = text[ctx_a:ctx_b]
            if re.search(r"(护照|passport|出入境|签证|出国)", ctx, re.I):
                yield Span(m.start(1), m.end(1), m.group(1), "PASSPORT",
                           confidence=0.8, source=self.name, reason="护照号（上下文含出入境词）",
                           block=block)

    def _hkmo(self, text: str, block: str) -> Iterator[Span]:
        for m in HK_MO_RE.finditer(text):
            yield Span(m.start(1), m.end(1), m.group(1), "HK_MO_PERMIT",
                       confidence=0.95, source=self.name, reason="港澳通行证号", block=block)

    # -- QQ / 微信 -------------------------------------------------------
    def _im(self, text: str, block: str) -> Iterator[Span]:
        for m in QQ_RE.finditer(text):
            yield Span(m.start(2), m.end(2), m.group(2), "IM_ACCOUNT",
                       confidence=0.95, source=self.name, reason=f"QQ号（提示词'{m.group(1)}'）",
                       attrs={"platform": "QQ"}, block=block)
        for m in WECHAT_RE.finditer(text):
            yield Span(m.start(2), m.end(2), m.group(2), "IM_ACCOUNT",
                       confidence=0.9, source=self.name, reason=f"微信号（提示词'{m.group(1)}'）",
                       attrs={"platform": "WeChat"}, block=block)

    # -- URL -------------------------------------------------------------
    def _url(self, text: str, block: str) -> Iterator[Span]:
        for m in URL_RE.finditer(text):
            v = m.group(0).rstrip(".,;:!?。，、；：")
            if not v:
                continue
            yield Span(m.start(), m.start() + len(v), v, "URL",
                       confidence=0.99, source=self.name, reason="URL", block=block)
