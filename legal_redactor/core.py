"""核心数据模型：实体类型注册表、Span、预设、策略枚举。"""
from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

# --------------------------------------------------------------------------
# 脱敏策略
# --------------------------------------------------------------------------


class Strategy(str, Enum):
    """脱敏策略。值即序列化用的字符串，方便 YAML/JSON 直写。"""

    KEEP = "KEEP"                # 保留
    MASK = "MASK"                # 遮盖：姓名→张某，其余→****
    MASK_FULL = "MASK_FULL"      # 整体替换为占位符 [已脱敏]
    PARTIAL = "PARTIAL"          # 部分保留（如身份证保留前6后4）
    PSEUDO = "PSEUDO"            # 一致化假名
    CODE = "CODE"                # 编号化（当事人A / P1）
    GENERALIZE = "GENERALIZE"    # 泛化（地址截到区县、日期截到年、金额取区间）
    DATE_SHIFT = "DATE_SHIFT"    # 日期平移
    DELETE = "DELETE"            # 删除
    HASH = "HASH"                # HMAC 假名


# 每种策略产出的占位符默认模板，可被预设覆盖
PLACEHOLDER_DEFAULT = "[已脱敏]"


# --------------------------------------------------------------------------
# 实体类型
# --------------------------------------------------------------------------

GROUP_STRONG = "strong"      # 强标识符：正则+校验位可判定
GROUP_WEAK = "weak"          # 弱标识符/准标识符：需上下文
GROUP_VISUAL = "visual"      # 视觉实体
GROUP_DISCRETION = "discretion"  # 自由裁量


@dataclass(frozen=True)
class EntityType:
    id: str
    label: str
    group: str
    default_strategy: Strategy = Strategy.MASK_FULL
    sensitive: bool = True
    hint: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["default_strategy"] = self.default_strategy.value
        return d


def _t(id: str, label: str, group: str, strat: Strategy, hint: str = "", sensitive: bool = True) -> EntityType:
    return EntityType(id=id, label=label, group=group, default_strategy=strat, hint=hint, sensitive=sensitive)


# 实体类型注册表 —— 全工具的单一事实来源
ENTITY_TYPES: dict[str, EntityType] = {}


def _register(*ets: EntityType) -> None:
    for e in ets:
        ENTITY_TYPES[e.id] = e


_register(
    # --- 强标识符 ---
    _t("ID_CARD", "居民身份证号", GROUP_STRONG, Strategy.MASK_FULL,
       "18位，GB11643 校验位验证；不通过则降级为 SUSPECT_ID"),
    _t("SUSPECT_ID", "疑似证件号", GROUP_STRONG, Strategy.MASK_FULL,
       "形似身份证但校验不过，需人工确认", sensitive=True),
    _t("PHONE", "手机号", GROUP_STRONG, Strategy.MASK_FULL, "1[3-9]开头11位"),
    _t("TEL", "固定电话", GROUP_STRONG, Strategy.MASK_FULL, "区号-号码"),
    _t("BANK_CARD", "银行卡号", GROUP_STRONG, Strategy.MASK_FULL, "13-19位，Luhn 校验"),
    _t("USCC", "统一社会信用代码", GROUP_STRONG, Strategy.MASK_FULL,
       "18位，GB32100 校验；法人标识，法律预设默认可保留"),
    _t("EMAIL", "电子邮箱", GROUP_STRONG, Strategy.MASK_FULL, ""),
    _t("IP_ADDR", "IP 地址", GROUP_STRONG, Strategy.MASK_FULL, "已排除版本号误报"),
    _t("PLATE", "车牌号", GROUP_STRONG, Strategy.MASK_FULL, "含新能源8位"),
    _t("PASSPORT", "护照号", GROUP_STRONG, Strategy.MASK_FULL, ""),
    _t("HK_MO_PERMIT", "港澳通行证号", GROUP_STRONG, Strategy.MASK_FULL, ""),
    _t("IM_ACCOUNT", "QQ/微信号", GROUP_STRONG, Strategy.MASK_FULL, "触发词+账号串"),
    _t("LICENSE_NO", "执业证/许可证号", GROUP_STRONG, Strategy.MASK_FULL,
       "律师执业证号、营业执照号、许可证号等由提示词触发的编号"),
    _t("URL", "网络链接", GROUP_STRONG, Strategy.KEEP, "法律预设默认保留", sensitive=False),
    _t("MAC_ADDR", "MAC 地址", GROUP_STRONG, Strategy.MASK_FULL, ""),

    # --- 弱标识符 / 准标识符 ---
    _t("PERSON", "自然人姓名", GROUP_WEAK, Strategy.MASK,
       "法律角色触发词 + 百家姓词典；召回有上限，需人工复核"),
    _t("ADDRESS", "住址/地址", GROUP_WEAK, Strategy.GENERALIZE,
       "级联解析到省市区县镇村路号楼室，泛化时按行政级截断"),
    _t("COURT", "法院名称", GROUP_WEAK, Strategy.KEEP, "公开信息，默认保留", sensitive=False),
    _t("LAW_FIRM", "律师事务所", GROUP_WEAK, Strategy.MASK, ""),
    _t("ORG", "机构/公司名称", GROUP_WEAK, Strategy.KEEP,
       "法人名称在裁判文书中属公开信息，默认保留", sensitive=False),
    _t("DOB", "出生日期", GROUP_WEAK, Strategy.GENERALIZE, "准标识符，组合可重识别"),
    _t("DATE", "日期", GROUP_WEAK, Strategy.KEEP, "默认保留", sensitive=False),
    _t("AMOUNT", "金额", GROUP_WEAK, Strategy.KEEP, "默认保留", sensitive=False),
    _t("CASE_NO", "案号", GROUP_WEAK, Strategy.KEEP, "公开信息，默认保留", sensitive=False),
    _t("BANK_BRANCH", "开户行", GROUP_WEAK, Strategy.MASK, ""),

    # --- 视觉实体 ---
    _t("SEAL", "印章", GROUP_VISUAL, Strategy.MASK_FULL,
       "cv2 HSV 红色掩膜+轮廓，覆盖骑缝章"),
    _t("QR_CODE", "二维码/条码", GROUP_VISUAL, Strategy.MASK_FULL, "一扫可能跳原始链接"),
    _t("IMG_TEXT", "图片内文字", GROUP_VISUAL, Strategy.MASK_FULL, "RapidOCR 文本框"),
    _t("FACE", "人脸", GROUP_VISUAL, Strategy.KEEP, "默认不启用（需模型权重）", sensitive=False),
    _t("SIGNATURE", "手写签名", GROUP_VISUAL, Strategy.KEEP, "默认不启用", sensitive=False),

    # --- 自由裁量 ---
    _t("MINOR_INFO", "未成年人信息", GROUP_DISCRETION, Strategy.MASK,
       "裁判文书上网规定第十条要求删除"),
    _t("TRADE_SECRET", "商业秘密段落", GROUP_DISCRETION, Strategy.KEEP, "需人工圈定", sensitive=False),
    _t("MEDICAL", "病历/健康信息", GROUP_DISCRETION, Strategy.MASK_FULL, ""),
    _t("CUSTOM", "自定义", GROUP_DISCRETION, Strategy.MASK_FULL, "用户正则/词表"),
)


def entity_label(etype: str) -> str:
    e = ENTITY_TYPES.get(etype)
    return e.label if e else etype


def entity_group(etype: str) -> str:
    e = ENTITY_TYPES.get(etype)
    return e.group if e else GROUP_DISCRETION


# --------------------------------------------------------------------------
# Span：一次检出
# --------------------------------------------------------------------------


@dataclass
class Span:
    """文本中一次实体检出。start/end 为 Python 切片语义 [start, end)。"""

    start: int
    end: int
    text: str
    etype: str
    confidence: float = 1.0
    source: str = ""            # 检测器名
    reason: str = ""            # 证据说明，给人看
    attrs: dict[str, Any] = field(default_factory=dict)
    block: str = ""             # 位置提示：body / header2 / page3 / sheet1!A1
    # 复核状态
    action: str = "auto"        # auto | accept | reject | manual
    decision_strategy: str | None = None   # 人工覆盖的策略
    span_id: str = ""

    def __post_init__(self) -> None:
        if not self.text:
            self.text = ""
        if self.end < self.start:
            self.start, self.end = self.end, self.start

    @property
    def length(self) -> int:
        return self.end - self.start

    def key(self) -> tuple:
        return (self.block, self.start, self.end, self.etype)

    def overlaps(self, other: "Span") -> bool:
        return self.start < other.end and other.start < self.end

    def contains(self, other: "Span") -> bool:
        return self.start <= other.start and other.end <= self.end

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Span":
        known = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class Box:
    """视觉实体：页/图上的矩形区域。"""

    x: float
    y: float
    w: float
    h: float
    etype: str
    confidence: float = 1.0
    source: str = ""
    reason: str = ""
    page: int = 0               # PDF 页码（0基）或图片序号
    text: str = ""              # OCR 出来的文字（若有）
    action: str = "auto"
    box_id: str = ""

    @property
    def rect(self) -> tuple[float, float, float, float]:
        return (self.x, self.y, self.x + self.w, self.y + self.h)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Box":
        known = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known})


# --------------------------------------------------------------------------
# 预设
# --------------------------------------------------------------------------


@dataclass
class Preset:
    """行业预设：etype -> Strategy 的动作表。未列出的类型取 EntityType.default_strategy。"""

    id: str
    label: str
    description: str = ""
    actions: dict[str, Strategy] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)

    def strategy_for(self, etype: str) -> Strategy:
        if etype in self.actions:
            return self.actions[etype]
        e = ENTITY_TYPES.get(etype)
        return e.default_strategy if e else Strategy.KEEP

    def is_redacted(self, etype: str) -> bool:
        s = self.strategy_for(etype)
        e = ENTITY_TYPES.get(etype)
        if e is not None and not e.sensitive and s == Strategy.KEEP:
            return False
        return s != Strategy.KEEP

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "actions": {k: v.value for k, v in self.actions.items()},
            "options": self.options,
        }


def load_preset(path: str | Path) -> Preset:
    """从 YAML 加载预设。"""
    import yaml

    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    actions = {}
    for k, v in (raw.get("actions") or {}).items():
        if k not in ENTITY_TYPES:
            raise ValueError(f"预设 {path} 含未知实体类型: {k}")
        actions[k] = Strategy(v)
    return Preset(
        id=raw.get("id") or Path(path).stem,
        label=raw.get("label") or Path(path).stem,
        description=raw.get("description", ""),
        actions=actions,
        options=raw.get("options") or {},
    )


def dump_registry(path: str | Path) -> None:
    """导出实体注册表为 JSON，供前端/文档使用。"""
    out = {
        "entity_types": [e.to_dict() for e in ENTITY_TYPES.values()],
        "strategies": [s.value for s in Strategy],
    }
    Path(path).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")


def group_types() -> dict[str, list[EntityType]]:
    g: dict[str, list[EntityType]] = {}
    for e in ENTITY_TYPES.values():
        g.setdefault(e.group, []).append(e)
    return g


def all_type_ids() -> list[str]:
    return list(ENTITY_TYPES.keys())


def iter_sensitive() -> Iterable[EntityType]:
    return (e for e in ENTITY_TYPES.values() if e.sensitive)
