"""脱敏后残留自检（本工具的核心交付物）。

脱敏完成 ≠ 脱敏成功。产物必须被当成"敌意输入"反向攻击一次：
重新解包、把所有部件的字节流按多种编码抠成文本、对每个原始敏感值做
多粒度匹配，再检查元数据/修订/批注/视觉残留，最后给出 PASS/FAIL。
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .core import Box, Span, Strategy
from .detect.base import canon_entity, norm_digits, norm_text
from .formats.docx_fmt import _loose_text, read_docx_text
from .strategies.resolver import EntityResolver

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "waived": -1}

#: 会被判定为"不通过"的最低严重级
FAIL_THRESHOLD = "high"

#: PDF 文本层少于此字符数即视为"无文本层"（扫描件），改用像素级判据
SCAN_TEXT_MIN = 24


@dataclass
class Residue:
    kind: str            # full | normalized | substring | structural | metadata | revision | comment | visual | placeholder
    etype: str
    original: str
    found: str
    part: str            # 部件路径 / 页码 / EXIF
    offset: int = -1
    context: str = ""
    severity: str = "medium"
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class AuditReport:
    src: str
    dst: str
    fmt: str
    passed: bool = True
    residues: list[Residue] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: _dt.datetime.now().isoformat(timespec="seconds"))

    @property
    def worst(self) -> str:
        if not self.residues:
            return "none"
        return max((r.severity for r in self.residues), key=lambda s: SEV_ORDER.get(s, 0))

    def by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.residues:
            out[r.severity] = out.get(r.severity, 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "src": self.src, "dst": self.dst, "fmt": self.fmt,
            "passed": self.passed, "worst_severity": self.worst,
            "by_severity": self.by_severity(),
            "residues": [r.to_dict() for r in self.residues],
            "checks": [c.to_dict() for c in self.checks],
            "stats": self.stats, "warnings": self.warnings,
            "generated_at": self.generated_at,
        }


# --------------------------------------------------------------------------
# 文本抽取：把产物按格式拆成 [(part_name, text)]
# --------------------------------------------------------------------------


class Part(tuple):
    """(部件名, 文本, 是否二进制)。

    二进制部件（OLE、缩略图、媒体）是按 latin-1/utf-16 硬抠出来的字节流，
    在里面搜 4 位短片段会撞到大量巧合（JPEG 的 DCT 系数里出现"4567"），
    所以短片段检查只对文本部件生效——这是有意的设计，不是漏检。
    """

    __slots__ = ()

    def __new__(cls, part: str, text: str, binary: bool = False):
        return super().__new__(cls, (part, text, binary))

    @property
    def part(self) -> str:
        return self[0]

    @property
    def text(self) -> str:
        return self[1]

    @property
    def binary(self) -> bool:
        return self[2]


def extract_all_text(path: str | Path, fmt: str, options: Mapping[str, Any] | None = None
                     ) -> list[Part]:
    """尽最大努力把产物里所有可能藏文本的地方抽出来。"""
    path = Path(path)
    options = dict(options or {})
    out: list[Part] = []

    if not path.exists():
        return [Part("<missing>", "", False)]

    if fmt == "docx":
        with zipfile.ZipFile(path, "r") as z:
            for name in z.namelist():
                data = z.read(name)
                if name.endswith((".xml", ".rels")):
                    out.append(Part(name, data.decode("utf-8", errors="replace"), False))
                elif name.startswith("word/media/") or name.startswith("docProps/thumbnail"):
                    out.append(Part(name, f"<binary {len(data)} bytes>", True))
                else:
                    # OLE / 嵌入对象：按 UTF-8、UTF-16LE、Latin-1 三种编码都扫一遍
                    out.append(Part(name, _loose_text(data), True))
        out.append(Part("<rendered>", read_docx_text(path), False))

    elif fmt == "xlsx":
        with zipfile.ZipFile(path, "r") as z:
            for name in z.namelist():
                data = z.read(name)
                if name.endswith((".xml", ".rels")):
                    out.append(Part(name, data.decode("utf-8", errors="replace"), False))
                else:
                    out.append(Part(name, _loose_text(data), True))
        try:
            from .formats.xlsx_fmt import read_xlsx_all
            out.append(Part("<cells>", read_xlsx_all(path), False))
        except Exception as e:
            out.append(Part("<cells-error>", str(e), False))

    elif fmt == "text":
        from .formats.text_fmt import read_text_any
        raw = path.read_bytes()
        out.append(Part(path.name, read_text_any(path), False))
        out.append(Part(f"{path.name}#utf16", raw.decode("utf-16-le", errors="ignore"), True))
        out.append(Part(f"{path.name}#latin1", raw.decode("latin-1", errors="ignore"), True))

    elif fmt == "pdf":
        from .formats.pdf_fmt import read_pdf_text
        out.append(Part("<textlayer>", read_pdf_text(path), False))
        # 原始字节：增量更新历史里的旧对象只能靠扫字节发现
        raw = path.read_bytes()
        out.append(Part("<rawbytes>", _loose_text(raw), True))
        if options.get("ocr_output", True):
            try:
                out.extend(_pdf_page_ocr(path, options))
            except Exception as e:
                out.append(Part("<ocr-error>", f"{type(e).__name__}: {e}", False))

    elif fmt == "image":
        try:
            out.extend(_image_ocr(path))
        except Exception as e:
            out.append(Part("<ocr-error>", f"{type(e).__name__}: {e}", False))

    else:
        out.append(Part(path.name, _loose_text(path.read_bytes()), True))

    return out


def _pdf_page_ocr(path: Path, options: Mapping[str, Any]) -> list[Part]:
    from .formats.pdf_fmt import pymupdf_available
    from .detect.vision_det import ocr_boxes

    if not pymupdf_available():
        return []
    import fitz
    import numpy as np
    out: list[Part] = []
    dpi = int(options.get("pdf_render_dpi", 150))
    with fitz.open(str(path)) as doc:
        for i, page in enumerate(doc):
            pix = page.get_pixmap(matrix=fitz.Matrix(dpi / 72.0, dpi / 72.0), alpha=False)
            arr = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width, pix.n)
            if pix.n == 4:
                arr = arr[:, :, :3]
            bgr = arr[:, :, ::-1].copy()
            boxes = ocr_boxes(bgr, page=i)
            txt = "\n".join(b.text for b in boxes if b.text)
            out.append(Part(f"<page{i + 1}#ocr>", txt, False))
    return out


def _image_ocr(path: Path) -> list[Part]:
    from .formats.image_fmt import imread_unicode
    from .detect.vision_det import ocr_boxes

    img = imread_unicode(path)
    if img is None:
        return [Part(str(path), "<decode-failed>", False)]
    boxes = ocr_boxes(img, page=0)
    return [Part(f"{Path(path).name}#ocr", "\n".join(b.text for b in boxes if b.text), False)]


# --------------------------------------------------------------------------
# 片段生成
# --------------------------------------------------------------------------


def forbidden_fragments(etype: str, value: str, min_len: int = 6) -> list[tuple[str, str]]:
    """为一个原始值生成所有"不该再出现"的片段。返回 [(片段, 种类)]。"""
    out: list[tuple[str, str]] = []
    v = value.strip()
    if not v:
        return out
    out.append((v, "full"))
    nv = norm_digits(v) if etype in {"ID_CARD", "PHONE", "TEL", "BANK_CARD", "USCC",
                                     "PASSPORT", "HK_MO_PERMIT", "MAC_ADDR", "IM_ACCOUNT",
                                     "SUSPECT_ID", "LICENSE_NO"} else norm_text(v)
    if nv and nv != v:
        out.append((nv, "normalized"))

    digits = re.sub(r"\D", "", v)
    if etype in {"ID_CARD", "SUSPECT_ID"} and len(digits) >= 15:
        # 出生日期段（第 7-14 位）与顺序码（第 15-17 位）都是重识别关键
        out.append((digits[6:14], "structural"))       # 出生日期 YYYYMMDD
        out.append((digits[14:17], "structural"))      # 顺序码
        out.append((digits[-6:], "structural"))        # 后 6 位
        out.append((digits[:6], "structural"))         # 地区码（单独不足以定位，low）
    elif etype == "PHONE" and len(digits) >= 11:
        out.append((digits[3:7], "structural"))        # 中间 4 位
        out.append((digits[-4:], "structural"))        # 后 4 位
    elif etype == "BANK_CARD" and len(digits) >= 13:
        out.append((digits[-4:], "structural"))
        out.append((digits[:6], "structural"))         # BIN
    elif etype == "USCC" and len(nv) >= 18:
        out.append((nv[8:17], "structural"))           # 主体标识码
    elif etype == "PERSON":
        cn = canon_entity("PERSON", v)
        if len(cn) >= 2:
            out.append((cn[1:], "structural"))         # 去掉姓的名字部分
    elif etype == "EMAIL":
        local, _, dom = v.partition("@")
        if local:
            out.append((local, "structural"))
    elif etype == "ADDRESS":
        # 门牌级细节：号/室/栋/单元后面的数字串
        for m in re.finditer(r"(\d{1,5}\s*(?:号|室|栋|幢|座|单元|层|楼|院))", v):
            out.append((m.group(1), "structural"))
    elif etype in {"PASSPORT", "HK_MO_PERMIT", "LICENSE_NO"} and len(nv) >= 8:
        out.append((nv[-6:], "structural"))

    # 长数字/字母串再做滑窗子串（>= min_len）
    if len(nv) >= min_len + 2 and re.fullmatch(r"[0-9A-Za-z\-_:.\s]+", nv):
        compact = re.sub(r"[^0-9A-Za-z]", "", nv)
        if len(compact) >= min_len + 2:
            for i in range(0, len(compact) - min_len + 1):
                frag = compact[i:i + min_len]
                if frag.isdigit() or frag.isalnum():
                    out.append((frag, "substring"))

    # 去重，保留最强种类。
    # 最小长度按类型定：姓名的"去姓部分"（张伟民→伟民）只有 2 字，
    # 但它是实打实的重识别线索，不能被通用的 4 字门槛过滤掉。
    min_len = 2 if etype == "PERSON" else 4
    best: dict[str, str] = {}
    for frag, kind in out:
        if len(frag) < min_len:
            continue
        # 单字与纯标点没有意义
        if not re.search(r"[\u4e00-\u9fa50-9A-Za-z]", frag):
            continue
        prev = best.get(frag)
        if prev is None or SEV_ORDER.get(_sev_for(kind, etype), 0) > SEV_ORDER.get(_sev_for(prev, etype), 0):
            best[frag] = kind
    return [(f, k) for f, k in best.items()]


def _sev_for(kind: str, etype: str) -> str:
    if kind in ("full", "normalized"):
        return "critical"
    if kind == "substring":
        return "high"
    # structural
    if etype in {"ID_CARD", "BANK_CARD", "USCC", "PHONE"}:
        return "medium"
    if etype == "PERSON":
        return "high"
    if etype == "ADDRESS":
        return "medium"
    return "medium"


# --------------------------------------------------------------------------
# 审计器
# --------------------------------------------------------------------------


class Auditor:
    def __init__(self, resolver: EntityResolver, options: Mapping[str, Any] | None = None,
                 waivers: Mapping[tuple[str, str], Any] | None = None):
        self.resolver = resolver
        self.options = dict(options or {})
        #: (etype, 归一化原值) -> 放行说明。人工在复核界面明确标了"忽略"的项，
        #: 不算工具失误，但必须在报告里单列出来——法律场景下"谁决定保留的"
        #: 和"保留了什么"一样重要。
        self.waivers = dict(waivers or {})

    # ------------------------------------------------------------------
    def audit(self, src: str | Path, dst: str | Path, fmt: str,
              scan: Any = None) -> AuditReport:
        rep = AuditReport(src=str(src), dst=str(dst), fmt=fmt)
        dst = Path(dst)

        if not dst.exists():
            rep.passed = False
            rep.checks.append(CheckResult("产物存在", False, f"文件不存在：{dst}"))
            return rep
        rep.checks.append(CheckResult("产物存在", True, f"{dst} ({dst.stat().st_size} 字节)"))

        parts = extract_all_text(dst, fmt, self.options)
        rep.stats["parts_scanned"] = len(parts)
        rep.stats["chars_scanned"] = sum(len(p.text) for p in parts)
        rep.stats["binary_parts"] = sum(1 for p in parts if p.binary)

        # --- 1) 敏感值残留 ---
        records = self.resolver.mapping_records()
        rep.stats["sensitive_entities"] = len(records)
        n_res = 0
        for rec in records:
            for frag, kind in forbidden_fragments(rec["etype"], rec["original"]):
                for p in parts:
                    text = p.text
                    if not text or text.startswith("<binary"):
                        continue
                    # 二进制部件里不做短片段检查（见 Part 的说明）
                    if p.binary and (kind == "structural" or len(frag) < 8):
                        continue
                    idx = _find_fragment(text, frag, kind)
                    if idx < 0:
                        continue
                    # 短数字片段在长数字里撞车概率很高，先排掉巧合
                    if kind in ("substring", "structural") and is_coincidental(
                            text, idx, frag, rec["original"]):
                        continue
                    sev = _sev_for(kind, rec["etype"])
                    if kind == "substring":
                        sev = "high"
                    # 短结构片段（手机后4位、卡号后4位）单独出现时噪声大，降级为 low
                    if kind == "structural" and len(frag) < 6:
                        sev = "low"
                    # 例外：替换值本身可能合法地包含某片段（例如 PARTIAL 保留后4位）
                    if frag in (rec.get("replacement") or ""):
                        sev = "info"
                    # 人工在复核时明确放行过这个值 → 不算工具失误，但单列出来
                    wkey = (rec["etype"], canon_entity(rec["etype"], rec["original"]))
                    if wkey in self.waivers:
                        sev = "waived"
                        w = self.waivers[wkey] or {}
                        note = ("人工复核放行：" + (w.get("reason") or "标记为误报/有意保留")
                                + f"（位置 {w.get('block', '?')}）")
                    else:
                        note = (f"策略={rec['strategy']} 替换值={rec['replacement']!r}"
                                + ("（二进制部件，字节巧合可能性高）" if p.binary else ""))
                    rep.residues.append(Residue(
                        kind=kind, etype=rec["etype"], original=rec["original"],
                        found=frag, part=p.part, offset=idx,
                        context=_ctx(text, idx, len(frag)), severity=sev, note=note))
                    n_res += 1
                    break      # 一个片段在一个部件里报一次即可
        waived_n = sum(1 for r in rep.residues if r.severity == "waived")
        rep.stats["waived_residues"] = waived_n
        rep.checks.append(CheckResult(
            "敏感值残留", n_res - waived_n == 0,
            f"{len(records)} 个敏感实体 × {len(parts)} 个部件，命中 {n_res} 处"
            + (f"，其中 {waived_n} 处为人工放行" if waived_n else "")))

        # --- 2) 元数据 ---
        meta_res = self._check_metadata(dst, fmt)
        rep.residues.extend(meta_res)
        rep.checks.append(CheckResult("元数据清理", not meta_res,
                                      f"{len(meta_res)} 处残留" if meta_res else "已清空/无残留"))

        # --- 3) 修订与批注（DOCX 专有，最容易漏） ---
        if fmt == "docx":
            rev = self._check_docx_structure(dst)
            rep.residues.extend(rev)
            rep.checks.append(CheckResult("修订/批注痕迹", not rev,
                                          f"{len(rev)} 处残留" if rev else "无 w:ins/w:del/批注残留"))

        # --- 4) 视觉复检 ---
        vis = self._check_visual(dst, fmt)
        rep.residues.extend(vis)
        rep.checks.append(CheckResult("视觉复检", not [v for v in vis if v.severity in ("critical", "high")],
                                      f"{len(vis)} 处视觉残留" if vis else "无印章/二维码/OCR 敏感文字残留"))

        # --- 5) 替换确实发生了 ---
        text_layer = next((p.text for p in parts if p.part == "<textlayer>"), "")
        has_text_layer = fmt != "pdf" or len(text_layer.strip()) >= SCAN_TEXT_MIN
        if fmt == "image" or not has_text_layer:
            # 图片、以及没有文本层的扫描 PDF：产物里本来就不存在"替换值"，
            # 脱敏是靠实心覆盖完成的，判据只能是"像素变了 + 视觉复检干净"
            import filecmp
            if fmt == "image":
                changed = not filecmp.cmp(str(src), str(dst), shallow=False)
            else:
                changed = not filecmp.cmp(str(src), str(dst), shallow=False)
            vis_bad = [v for v in vis if v.severity in ("critical", "high")]
            label = "像素已改写" if fmt == "image" else "扫描页已覆盖"
            if changed and not vis_bad:
                detail = ("产物与原文件不同，且复检无印章/二维码/敏感文字"
                          + ("（无文本层，靠实心覆盖脱敏）" if fmt == "pdf" else ""))
            elif not changed:
                detail = "产物与原文件完全相同——打码没有写进去"
            else:
                detail = f"仍有 {len(vis_bad)} 处视觉残留"
            rep.checks.append(CheckResult(label, bool(changed and not vis_bad), detail))
            rep.stats["pixels_changed"] = changed
            rep.stats["has_text_layer"] = has_text_layer
        else:
            ph = self._check_placeholders(dst, fmt, records)
            rep.checks.append(CheckResult("替换落地", ph["ok"], ph["detail"]))
            rep.stats["placeholder_hits"] = ph["hits"]

        # --- 6) 组合重识别风险提示 ---
        quasi = self._check_quasi_identifiers(dst, fmt, parts)
        if quasi["level"] >= int(self.options.get("quasi_id_warn_threshold", 3)):
            rep.warnings.append(
                f"产物中仍保留 {quasi['level']} 类准标识符（{', '.join(quasi['kinds'])}）。"
                f"单个字段不敏感，但组合起来可能足以重新定位到个人，建议人工判断是否需要进一步泛化。")
        rep.stats["quasi_identifiers"] = quasi

        # --- 结论 ---
        bad = [r for r in rep.residues
               if SEV_ORDER.get(r.severity, 0) >= SEV_ORDER.get(FAIL_THRESHOLD, 3)]
        rep.passed = not bad
        return rep

    # ------------------------------------------------------------------
    def _check_metadata(self, dst: Path, fmt: str) -> list[Residue]:
        out: list[Residue] = []
        if fmt == "docx":
            with zipfile.ZipFile(dst, "r") as z:
                for name in ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml"):
                    if name not in z.namelist():
                        continue
                    txt = z.read(name).decode("utf-8", errors="replace")
                    for m in re.finditer(
                            r"<(?:dc:creator|cp:lastModifiedBy|dc:title|dc:subject|"
                            r"dc:description|cp:keywords|Company|Manager|dc:contributor)"
                            r"[^>]*>([^<]+)</", txt):
                        val = m.group(1).strip()
                        if val:
                            out.append(Residue("metadata", "META", val, val, name,
                                               m.start(1), _ctx(txt, m.start(1), len(val)),
                                               "high", "文档属性未清空"))
        elif fmt == "pdf":
            # 只查真正可能带身份信息的字段。
            # PyMuPDF 的 metadata 里 'format'（"PDF 1.7"）、'encryption' 是技术信息，
            # 不是残留；之前把它当 high 报出来是误判。
            sensitive_keys = {"author", "title", "subject", "keywords", "creator", "producer"}
            try:
                import fitz
                with fitz.open(str(dst)) as d:
                    md = d.metadata or {}
                    for k, v in md.items():
                        if k.lower() not in sensitive_keys:
                            continue
                        if isinstance(v, str) and v.strip():
                            out.append(Residue("metadata", "META", v, v, f"/Info:{k}",
                                               -1, "", "high", "PDF 元数据未清空"))
                    try:
                        xmp = d.get_xml_metadata() or ""
                    except Exception:
                        xmp = ""
                    if xmp.strip():
                        # XMP 里出现原值才算残留，空的 XMP 容器不算
                        hits = [r["original"] for r in self.resolver.mapping_records()
                                if r["original"] and r["original"] in xmp]
                        if hits:
                            out.append(Residue("metadata", "META", ", ".join(hits[:3]),
                                               xmp[:80], "XMP", -1, "", "high",
                                               "XMP 元数据里含原始敏感值"))
            except Exception as e:
                out.append(Residue("metadata", "META", "", str(e), "<error>", -1, "",
                                   "low", "无法读取 PDF 元数据"))
        elif fmt == "xlsx":
            try:
                import openpyxl
                wb = openpyxl.load_workbook(str(dst))
                p = wb.properties
                for f in ("creator", "lastModifiedBy", "title", "subject", "description",
                          "keywords", "category"):
                    v = getattr(p, f, None)
                    if v:
                        out.append(Residue("metadata", "META", str(v), str(v),
                                           f"docProps:{f}", -1, "", "high", "文档属性未清空"))
            except Exception:
                pass
        elif fmt == "image":
            try:
                from PIL import Image
                with Image.open(dst) as im:
                    ex = im.getexif()
                    if ex:
                        for k, v in ex.items():
                            if k in (271, 272, 305, 306, 0x8825, 34853):   # Make/Model/Software/DateTime/GPS
                                out.append(Residue("metadata", "META", str(v), str(v),
                                                   f"EXIF:{k}", -1, "",
                                                   "critical" if k in (0x8825, 34853) else "medium",
                                                   "EXIF 未剥离" + ("（含 GPS）" if k in (0x8825, 34853) else "")))
            except Exception:
                pass
        return out

    def _check_docx_structure(self, dst: Path) -> list[Residue]:
        out: list[Residue] = []
        with zipfile.ZipFile(dst, "r") as z:
            names = z.namelist()
            for name in names:
                if not name.endswith(".xml"):
                    continue
                data = z.read(name)
                for tag, label, sev in (
                        (b"<w:del ", "w:del 修订（被删原文仍在文件里）", "critical"),
                        (b"<w:ins ", "w:ins 修订记录", "medium"),
                        (b"<w:delText", "w:delText 被删文本", "critical"),
                        (b"<w:moveFrom", "w:moveFrom 移动修订", "critical"),
                        (b"<w:rPrChange", "格式修订记录", "low"),
                        (b"<w:pPrChange", "格式修订记录", "low"),
                ):
                    if tag in data:
                        out.append(Residue("revision", "REVISION", label, tag.decode(), name,
                                           data.find(tag), "", sev, label))
            if "word/comments.xml" in names:
                data = z.read("word/comments.xml")
                if b"<w:comment " in data:
                    out.append(Residue("comment", "COMMENT", "批注未清除", "w:comment",
                                       "word/comments.xml", data.find(b"<w:comment "), "",
                                       "high", "批注里常有承办人的内部意见与当事人真名"))
            if "word/people.xml" in names:
                data = z.read("word/people.xml")
                for m in re.finditer(rb'w:author="([^"]+)"', data):
                    out.append(Residue("comment", "COMMENT", m.group(1).decode("utf-8", "replace"),
                                       m.group(1).decode("utf-8", "replace"), "word/people.xml",
                                       m.start(1), "", "high", "批注作者名"))
        return out

    def _check_visual(self, dst: Path, fmt: str) -> list[Residue]:
        from .detect.vision_det import cv2_available, detect_qr, detect_seals, ocr_boxes
        from .formats.image_fmt import imread_unicode

        out: list[Residue] = []
        if not cv2_available():
            return out
        if not self.options.get("vision", True):
            return out

        images: list[tuple[str, Any]] = []
        if fmt == "image":
            img = imread_unicode(dst)
            if img is not None:
                images.append((dst.name, img))
        elif fmt == "docx":
            import numpy as np
            import cv2
            with zipfile.ZipFile(dst, "r") as z:
                for name in z.namelist():
                    if not name.startswith("word/media/"):
                        continue
                    if Path(name).suffix.lower() not in {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp"}:
                        continue
                    arr = cv2.imdecode(np.frombuffer(z.read(name), np.uint8), cv2.IMREAD_COLOR)
                    if arr is not None:
                        images.append((name, arr))
        elif fmt == "pdf":
            try:
                import fitz
                import numpy as np
                dpi = int(self.options.get("pdf_render_dpi", 150))
                with fitz.open(str(dst)) as d:
                    for i, page in enumerate(d):
                        pix = page.get_pixmap(matrix=fitz.Matrix(dpi / 72.0, dpi / 72.0), alpha=False)
                        arr = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width, pix.n)
                        if pix.n == 4:
                            arr = arr[:, :, :3]
                        images.append((f"page{i + 1}", arr[:, :, ::-1].copy()))
            except Exception as e:
                out.append(Residue("visual", "VISUAL", "", str(e), "<error>", -1, "", "low",
                                   "无法渲染 PDF 做视觉复检"))

        for name, img in images:
            for b in detect_seals(img, page=0):
                out.append(Residue("visual", "SEAL", "印章", f"{b.w:.0f}x{b.h:.0f}", name,
                                   int(b.x), "", "high", b.reason))
            for b in detect_qr(img, page=0):
                out.append(Residue("visual", "QR_CODE", "二维码", "", name, int(b.x), "",
                                   "high", b.reason))
            if self.options.get("ocr", True):
                for b in ocr_boxes(img, page=0):
                    hits = self._ocr_sensitive(b.text or "")
                    if hits:
                        out.append(Residue("visual", "IMG_TEXT", b.text or "", ", ".join(hits),
                                           name, int(b.x), "", "high",
                                           "产物图片里仍能 OCR 出敏感信息"))
        return out

    def _ocr_sensitive(self, text: str) -> list[str]:
        if not text.strip():
            return []
        from .detect.regex_det import StrongIdentifierDetector
        d = StrongIdentifierDetector()
        hits = []
        for s in d.detect(text, "ocr"):
            if s.etype in {"ID_CARD", "PHONE", "BANK_CARD", "EMAIL", "USCC", "PASSPORT",
                           "HK_MO_PERMIT", "IM_ACCOUNT", "PLATE", "LICENSE_NO"}:
                hits.append(f"{s.etype}={s.text}")
        # 对照表里的原值
        for rec in self.resolver.mapping_records():
            if rec["etype"] == "PERSON" and rec["original"] and rec["original"] in text:
                hits.append(f"PERSON={rec['original']}")
        return hits

    def _check_placeholders(self, dst: Path, fmt: str, records: Sequence[Mapping]) -> dict[str, Any]:
        """确认替换真的写进去了，而不是"检测到了但没改"。"""
        if not records:
            return {"ok": True, "detail": "本次无需脱敏项", "hits": 0}
        parts = extract_all_text(dst, fmt, {**self.options, "ocr_output": False})
        blob = "\n".join(p.text for p in parts if not p.binary)
        reps = {r["replacement"] for r in records if r.get("replacement")}
        hits = sum(blob.count(r) for r in reps if r)
        ok = hits > 0
        return {"ok": ok,
                "detail": (f"产物中找到 {hits} 处替换值" if ok else
                           "产物中找不到任何替换值——脱敏可能没有真正写入"),
                "hits": hits}

    def _check_quasi_identifiers(self, dst: Path, fmt: str,
                                 parts: Sequence[Part]) -> dict[str, Any]:
        """产物里还剩哪些准标识符。单个不敏感，组合起来可能重识别。"""
        blob = "\n".join(p.text for p in parts if not p.binary)
        kinds: list[str] = []
        if re.search(r"(19|20)\d{2}\s*年", blob):
            kinds.append("年份")
        if re.search(r"[\u4e00-\u9fa5]{2,}(省|市|区|县)", blob):
            kinds.append("行政区划")
        if re.search(r"(男|女)[，,、]", blob):
            kinds.append("性别")
        if re.search(r"(汉族|回族|满族|蒙古族|藏族|苗族|彝族|壮族)", blob):
            kinds.append("民族")
        if re.search(r"\d[\d,]*\s*(元|万元)", blob):
            kinds.append("金额")
        if re.search(r"(职业|职务|工作单位|学历|婚姻状况|籍贯)", blob):
            kinds.append("社会属性")
        return {"level": len(kinds), "kinds": kinds}


# --------------------------------------------------------------------------


def _find_fragment(text: str, frag: str, kind: str) -> int:
    if not frag:
        return -1
    i = text.find(frag)
    if i >= 0:
        return i
    if kind in ("full", "normalized"):
        # 归一化后再试：产物里可能带空格/全角
        nt = norm_digits(text) if kind == "normalized" else text
        j = nt.find(norm_digits(frag))
        return j if j >= 0 else -1
    return -1


_RUN_RE = re.compile(r"[0-9A-Za-z]")


def containing_run(text: str, idx: int, length: int) -> str:
    """取出包含 text[idx:idx+length] 的极大字母数字串。"""
    a = idx
    while a > 0 and _RUN_RE.match(text[a - 1]):
        a -= 1
    b = idx + length
    while b < len(text) and _RUN_RE.match(text[b]):
        b += 1
    return text[a:b]


def is_coincidental(text: str, idx: int, frag: str, original: str) -> bool:
    """判断一次片段命中是不是"撞上了别的数字"。

    6 位滑窗子串在长数字里撞车的概率很高：产物里另一个没被脱敏的账号
    "1100123456789012" 就含有原银行卡号 "6222021123456787" 的窗口 "123456"。
    判据：命中片段所在的极大字母数字串，如果不是原值的子串，就是巧合。
    """
    if not re.fullmatch(r"[0-9A-Za-z]+", frag):
        return False
    run = containing_run(text, idx, len(frag))
    if run == frag:
        return False           # 片段独立存在，是真残留
    norm_orig = re.sub(r"[^0-9A-Za-z]", "", original)
    return run not in norm_orig


def _ctx(text: str, idx: int, length: int, before: int = 30, after: int = 30) -> str:
    a = max(0, idx - before)
    b = min(len(text), idx + length + after)
    s = text[a:b].replace("\n", "⏎").replace("\r", "")
    mark_start = idx - a
    return s[:mark_start] + "【" + s[mark_start:mark_start + length] + "】" + s[mark_start + length:]


# --------------------------------------------------------------------------
# 报告输出
# --------------------------------------------------------------------------


def write_audit(rep: AuditReport, out_dir: str | Path, stem: str | None = None) -> dict[str, str]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = stem or (Path(rep.dst).stem + ".audit")
    paths = {
        "json": str(out_dir / f"{stem}.json"),
        "md": str(out_dir / f"{stem}.md"),
        "html": str(out_dir / f"{stem}.html"),
    }
    Path(paths["json"]).write_text(json.dumps(rep.to_dict(), ensure_ascii=False, indent=2),
                                   encoding="utf-8")
    Path(paths["md"]).write_text(audit_to_markdown(rep), encoding="utf-8")
    Path(paths["html"]).write_text(audit_to_html(rep), encoding="utf-8")
    return paths


def audit_to_markdown(rep: AuditReport) -> str:
    sev_cn = {"critical": "致命", "high": "高", "medium": "中", "low": "低", "info": "提示", "none": "无"}
    L = [
        f"# 脱敏残留自检报告",
        "",
        f"- **结论：{'✅ 通过' if rep.passed else '❌ 不通过'}**（最高严重级：{sev_cn.get(rep.worst, rep.worst)}）",
        f"- 原文件：`{rep.src}`",
        f"- 产物：`{rep.dst}`",
        f"- 格式：{rep.fmt}",
        f"- 生成时间：{rep.generated_at}",
        "",
        "## 检查项",
        "",
        "| 检查 | 结果 | 说明 |",
        "|---|:--:|---|",
    ]
    for c in rep.checks:
        L.append(f"| {c.name} | {'✅' if c.passed else '❌'} | {c.detail} |")
    L += ["", "## 统计", ""]
    for k, v in rep.stats.items():
        if isinstance(v, dict):
            v = json.dumps(v, ensure_ascii=False)
        L.append(f"- {k}: {v}")
    if rep.residues:
        waived = [r for r in rep.residues if r.severity == "waived"]
        real = [r for r in rep.residues if r.severity != "waived"]
        if real:
            L += ["", "## 残留明细（工具未处理）", "",
                  "| 严重级 | 种类 | 类型 | 原值 | 命中片段 | 位置 | 上下文 |",
                  "|---|---|---|---|---|---|---|"]
            for r in sorted(real, key=lambda x: -SEV_ORDER.get(x.severity, 0)):
                L.append(f"| {sev_cn.get(r.severity, r.severity)} | {r.kind} | {r.etype} "
                         f"| `{r.original[:30]}` | `{r.found[:30]}` | `{r.part}` "
                         f"| `{r.context[:80]}` |")
        else:
            L += ["", "## 残留明细（工具未处理）", "", "未发现残留。"]
        if waived:
            L += ["", "## 人工放行清单", "",
                  "> 以下项由复核人明确标记为「忽略」，工具按指示未做脱敏。",
                  "> 这不是工具失误，但**责任在人**：交付前请确认每一条都有依据。", "",
                  "| 类型 | 原值 | 位置 | 依据 |", "|---|---|---|---|"]
            for r in waived:
                L.append(f"| {r.etype} | `{r.original[:40]}` | `{r.part}` | {r.note} |")
    else:
        L += ["", "## 残留明细", "", "未发现残留。"]
    if rep.warnings:
        L += ["", "## 风险提示", ""]
        for w in rep.warnings:
            L.append(f"- {w}")
    L.append("")
    return "\n".join(L)


def audit_to_html(rep: AuditReport) -> str:
    import html as _h
    sev_color = {"critical": "#c0392b", "high": "#e67e22", "medium": "#f1c40f",
                 "low": "#7f8c8d", "info": "#95a5a6", "waived": "#2f5fd0"}
    sev_cn = {"critical": "致命", "high": "高", "medium": "中", "low": "低",
              "info": "提示", "waived": "人工放行"}
    rows = []
    for c in rep.checks:
        rows.append(f"<tr><td>{_h.escape(c.name)}</td>"
                    f"<td class='{'ok' if c.passed else 'bad'}'>{'通过' if c.passed else '不通过'}</td>"
                    f"<td>{_h.escape(c.detail)}</td></tr>")
    real = [r for r in rep.residues if r.severity != "waived"]
    waived = [r for r in rep.residues if r.severity == "waived"]

    def _row(r):
        col = sev_color.get(r.severity, "#999")
        return (f"<tr><td><span class='pill' style='background:{col}'>"
                f"{sev_cn.get(r.severity, r.severity)}</span></td>"
                f"<td>{_h.escape(r.kind)}</td><td>{_h.escape(r.etype)}</td>"
                f"<td class='mono'>{_h.escape(r.original[:40])}</td>"
                f"<td class='mono'>{_h.escape(r.found[:40])}</td>"
                f"<td class='mono'>{_h.escape(r.part)}</td>"
                f"<td class='mono ctx'>{_h.escape(r.context[:160])}</td>"
                f"<td>{_h.escape(r.note[:120])}</td></tr>")

    res_rows = [_row(r) for r in
                sorted(real, key=lambda x: -SEV_ORDER.get(x.severity, 0))]
    wrows = [_row(r) for r in waived]
    warns = "".join(f"<li>{_h.escape(w)}</li>" for w in rep.warnings)
    stats = "".join(
        f"<li><b>{_h.escape(str(k))}</b>: {_h.escape(json.dumps(v, ensure_ascii=False) if isinstance(v, dict) else str(v))}</li>"
        for k, v in rep.stats.items())
    verdict = "通过" if rep.passed else "不通过"
    vcolor = "#27ae60" if rep.passed else "#c0392b"
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>脱敏残留自检报告 - {_h.escape(Path(rep.dst).name)}</title>
<style>
 body{{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;margin:0;padding:32px;
      background:#f6f7f9;color:#1c1e21}}
 .card{{background:#fff;border-radius:10px;padding:24px;margin-bottom:20px;
        box-shadow:0 1px 3px rgba(0,0,0,.08)}}
 h1{{font-size:22px;margin:0 0 8px}} h2{{font-size:16px;margin:24px 0 10px}}
 .verdict{{display:inline-block;padding:6px 18px;border-radius:20px;color:#fff;
           font-weight:600;background:{vcolor}}}
 table{{width:100%;border-collapse:collapse;font-size:13px}}
 th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid #eef0f2;vertical-align:top}}
 th{{background:#fafbfc;font-weight:600;color:#57606a}}
 .ok{{color:#27ae60;font-weight:600}} .bad{{color:#c0392b;font-weight:600}}
 .mono{{font-family:ui-monospace,Consolas,monospace;font-size:12px}}
 .ctx{{max-width:420px;word-break:break-all;color:#57606a}}
 .pill{{color:#fff;padding:2px 8px;border-radius:10px;font-size:11px}}
 ul{{margin:6px 0;padding-left:20px;font-size:13px;line-height:1.7}}
 .warn{{background:#fff8e6;border-left:4px solid #f1c40f;padding:12px 16px;border-radius:4px}}
 .waived{{background:#f5f8ff;border-left:4px solid #2f5fd0}}
 .wnote{{font-size:13px;color:#3b4654;margin:4px 0 10px}}
</style></head><body>
<div class="card">
 <h1>脱敏残留自检报告</h1>
 <p><span class="verdict">{verdict}</span>
 &nbsp;最高严重级：{sev_cn.get(rep.worst, '无')}</p>
 <ul>
  <li>原文件：<span class="mono">{_h.escape(rep.src)}</span></li>
  <li>产物：<span class="mono">{_h.escape(rep.dst)}</span></li>
  <li>格式：{_h.escape(rep.fmt)}　生成时间：{_h.escape(rep.generated_at)}</li>
 </ul>
</div>
<div class="card"><h2>检查项</h2><table><tr><th>检查</th><th>结果</th><th>说明</th></tr>
{''.join(rows)}</table></div>
<div class="card"><h2>统计</h2><ul>{stats}</ul></div>
{'<div class="card warn"><h2>风险提示</h2><ul>' + warns + '</ul></div>' if warns else ''}
<div class="card"><h2>残留明细 · 工具未处理（{len(real)}）</h2>
{'<table><tr><th>级</th><th>种类</th><th>类型</th><th>原值</th><th>命中</th><th>位置</th><th>上下文</th><th>备注</th></tr>' + ''.join(res_rows) + '</table>' if res_rows else '<p>未发现残留。</p>'}
</div>
{'<div class="card waived"><h2>人工放行清单（' + str(len(waived)) + '）</h2><p class="wnote">以下项由复核人明确标记为「忽略」，工具按指示未做脱敏。这不是工具失误，但<b>责任在人</b>：交付前请逐条确认有依据。</p><table><tr><th>级</th><th>种类</th><th>类型</th><th>原值</th><th>命中</th><th>位置</th><th>上下文</th><th>依据</th></tr>' + ''.join(wrows) + '</table></div>' if wrows else ''}
</body></html>"""
