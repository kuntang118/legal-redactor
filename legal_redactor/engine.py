"""总编排：解析 → 检测 → 复核决策 → 一致化替换 → 落盘 → 交给审计。

跨文件一致性在这里保证：批量模式下先扫全部文件、把所有实体登记进同一个
EntityResolver、用确认过的姓名回喂检测器再扫一遍，最后才统一写盘。
"""
from __future__ import annotations

import io
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .core import Box, Preset, Span, Strategy, ENTITY_TYPES
from .detect import TextPipeline, VisionPipeline, cv2_available, ocr_available
from .detect.base import REGION_TYPES, canon_entity
from .formats.docx_fmt import DocxRedactor, Replacement, _loose_text
from .formats.text_fmt import TextRedactor
from .formats.image_fmt import IMAGE_EXTS, ImageRedactor, fill_boxes
from .strategies.resolver import EntityResolver

#: 只做区域标记、本身不对应可替换文本的类型
MARKER_ONLY_TYPES = {"MINOR_INFO"}

FORMAT_BY_EXT = {
    ".docx": "docx",
    ".txt": "text", ".md": "text", ".markdown": "text", ".csv": "text",
    ".log": "text", ".json": "text", ".yaml": "text", ".yml": "text", ".xml": "text",
    ".pdf": "pdf",
    ".xlsx": "xlsx", ".xlsm": "xlsx",
    ".png": "image", ".jpg": "image", ".jpeg": "image", ".bmp": "image",
    ".tif": "image", ".tiff": "image", ".webp": "image",
}

#: 明确不支持、必须拒绝处理的格式（不能假装能脱敏）
REFUSE_EXTS = {
    ".doc": "老式二进制 Word（.doc）无法安全做真删除——黑底覆盖后原文仍在二进制流里。"
            "请先用 Word/WPS 另存为 .docx 再处理。",
    ".xls": "老式二进制 Excel（.xls）同理，请另存为 .xlsx。",
    ".ppt": "老式二进制 PowerPoint，请另存为 .pptx（本版本尚未支持 pptx）。",
    ".rtf": "RTF 的控制字与明文混排，本版本未实现真删除。",
    ".odt": "ODF 格式本版本未实现。",
}


@dataclass
class FileScan:
    path: str
    fmt: str
    blocks: dict[str, str] = field(default_factory=dict)
    spans: dict[str, list[Span]] = field(default_factory=dict)
    boxes_by_page: dict[int, list[Box]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    #: 表格类格式的列头提示：block_id -> 列头文本
    hints: dict[str, str] = field(default_factory=dict)
    #: 扫描阶段打开的适配器，写盘时复用。
    #: 必须复用：DocxRedactor 的"接受修订"发生在 extract() 里，
    #: 换一个新实例而不 extract()，替换和修订清理都会静默失效。
    adapter: Any = field(default=None, repr=False, compare=False)

    @property
    def all_spans(self) -> list[Span]:
        out: list[Span] = []
        for v in self.spans.values():
            out.extend(v)
        return out

    @property
    def all_boxes(self) -> list[Box]:
        out: list[Box] = []
        for v in self.boxes_by_page.values():
            out.extend(v)
        return out


@dataclass
class FileResult:
    path: str
    out_path: str
    fmt: str
    scan: FileScan
    replacements: int = 0
    adapter_report: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path, "out_path": self.out_path, "fmt": self.fmt,
            "replacements": self.replacements,
            "adapter_report": self.adapter_report,
            "warnings": self.warnings,
            "spans": len(self.scan.all_spans),
            "boxes": len(self.scan.all_boxes),
        }


def detect_format(path: str | Path) -> str:
    ext = Path(path).suffix.lower()
    if ext in REFUSE_EXTS:
        raise ValueError(f"不支持的格式 {ext}：{REFUSE_EXTS[ext]}")
    fmt = FORMAT_BY_EXT.get(ext)
    if fmt is None:
        raise ValueError(f"未识别的扩展名 {ext}；支持的格式：{sorted(set(FORMAT_BY_EXT))}")
    return fmt


class Engine:
    """脱敏引擎。一个 Engine 实例对应一个批次，共享同一个 EntityResolver。"""

    def __init__(self, preset: Preset, options: Mapping[str, Any] | None = None,
                 extra_names: Sequence[str] = (), seed: bytes | str = b"",
                 learned_names: Sequence[str] = ()):
        self.preset = preset
        self.options: dict[str, Any] = dict(preset.options or {})
        if options:
            self.options.update(options)
        if isinstance(seed, str):
            seed = seed.encode("utf-8")
        self.seed = seed or b""
        self.extra_names = list(extra_names)
        #: 人工在复核界面明确"忽略"的项。审计会把它单列为"人工放行"，
        #: 既不算工具失误、也不被静默吞掉。
        self.waivers: dict[tuple[str, str], dict[str, Any]] = {}
        self.pipe = TextPipeline(preset, extra_names=self.extra_names + list(learned_names),
                                 custom_rules=self.options.get("custom") or [])
        self.resolver = EntityResolver(preset, seed=self.seed, options=self.options)
        self._vision: VisionPipeline | None = None
        self._learned: list[str] = list(learned_names)

    # ------------------------------------------------------------------
    @property
    def vision(self) -> VisionPipeline | None:
        if not self.options.get("vision", True) or not cv2_available():
            return None
        if self._vision is None:
            self._vision = VisionPipeline(
                text_detect=self.pipe.detect_text,
                enable_ocr=bool(self.options.get("ocr", True)) and ocr_available(),
                enable_seal=bool(self.options.get("detect_seal", True)),
                enable_qr=bool(self.options.get("detect_qr", True)),
            )
        return self._vision

    # ------------------------------------------------------------------
    def scan(self, path: str | Path) -> FileScan:
        """只检测，不写盘。"""
        path = Path(path)
        fmt = detect_format(path)
        scan = FileScan(path=str(path), fmt=fmt)

        if fmt == "image":
            self._scan_image(path, scan)
            return scan

        adapter = self._open_adapter(path, fmt)
        if adapter is None:
            scan.warnings.append("无法打开文件")
            return scan
        try:
            blocks = adapter.extract()
        except Exception as e:
            scan.warnings.append(f"提取文本失败：{type(e).__name__}: {e}")
            return scan
        scan.blocks = blocks
        scan.adapter = adapter
        scan.hints = dict(getattr(adapter, "block_hints", None) or {})

        # 文本检测（若批次里已有确认过的姓名，用 learned 名单提升召回）
        if self._learned:
            self.pipe.extra_names = list(dict.fromkeys(self.pipe.extra_names + self._learned))
        scan.spans = self.pipe.run(blocks, hints=scan.hints)

        # 视觉检测
        vis = self.vision
        if vis is not None:
            try:
                if fmt == "pdf":
                    for i in range(adapter.doc.page_count):
                        img, zoom = adapter.page_image(i)
                        boxes = vis.detect(img, page=i)
                        if boxes:
                            scan.boxes_by_page[i] = boxes
                            # OCR 出来的文字要登记成实体，否则扫描件/图章里的
                            # 敏感值既进不了对照表，审计也无从核对
                            self._register_ocr_spans(scan, boxes, f"page{i + 1}#ocr")
                elif fmt == "docx":
                    self._scan_docx_media(adapter, vis, scan)
            except Exception as e:
                scan.warnings.append(f"视觉检测失败：{type(e).__name__}: {e}")

        # 登记到 resolver（批量一致性）
        self.resolver.add_all(scan.all_spans, file_id=path.name)
        return scan

    def _register_ocr_spans(self, scan: FileScan, boxes: Sequence[Box], block: str) -> None:
        """把 OCR 文本框里的内容跑一遍文本检测，登记进 scan.spans。

        这些 span 的偏移只在 OCR 文本内有效，不参与版面替换
        （替换由 Box 填充完成），但会进对照表、参与一致化、被审计核对。
        """
        ocr_text = "\n".join(b.text for b in boxes if b.text)
        if not ocr_text.strip():
            return
        spans = self.pipe.detect_text(ocr_text, block)
        if spans:
            scan.spans[block] = spans
            scan.blocks[block] = ocr_text

    def _open_adapter(self, path: Path, fmt: str):
        if fmt == "docx":
            return DocxRedactor(path, self.options)
        if fmt == "text":
            return TextRedactor(path, self.options)
        if fmt == "pdf":
            from .formats.pdf_fmt import PdfRedactor
            return PdfRedactor(path, self.options)
        if fmt == "xlsx":
            from .formats.xlsx_fmt import XlsxRedactor
            return XlsxRedactor(path, self.options)
        return None

    def _scan_image(self, path: Path, scan: FileScan) -> None:
        from .formats.image_fmt import has_exif_gps, imread_unicode

        img = imread_unicode(path)
        if img is None:
            scan.warnings.append("图片解码失败")
            return
        scan.blocks = {"body": ""}
        if has_exif_gps(path):
            scan.warnings.append("原图 EXIF 含 GPS 信息，产物会剥离（这是最容易被忽略的泄露点）")
        vis = self.vision
        if vis is None:
            return
        boxes = vis.detect(img, page=0)
        if boxes:
            scan.boxes_by_page[0] = boxes
        # OCR 出来的文字也要登记进 resolver，保证与正文一致化
        self._register_ocr_spans(scan, boxes, "image#ocr")

    def _scan_docx_media(self, adapter: DocxRedactor, vis: VisionPipeline, scan: FileScan) -> None:
        """扫描 DOCX 内嵌图片。"""
        import numpy as np
        import cv2

        if not cv2_available():
            return
        for name in adapter.media_parts():
            data = adapter._parts[name]
            ext = Path(name).suffix.lower()
            if ext in (".emf", ".wmf"):
                scan.warnings.append(
                    f"{name} 是矢量图（EMF/WMF），cv2 无法栅格化处理，"
                    f"其中的文字与印章可能残留；建议在 Word 里转成位图后重跑")
                continue
            if ext not in IMAGE_EXTS:
                scan.warnings.append(f"{name} 非位图格式，未做视觉检测")
                continue
            arr = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
            if arr is None:
                scan.warnings.append(f"{name} 解码失败")
                continue
            boxes = vis.detect(arr, page=0)
            if boxes:
                scan.boxes_by_page.setdefault(-1, [])
                scan.boxes_by_page[-1].extend(boxes)
                scan.warnings.append(f"{name} 检出 {len(boxes)} 个视觉敏感区域")
                self._register_ocr_spans(scan, boxes, f"{name}#ocr")
        # 嵌入对象
        for name in adapter.embedding_parts():
            ext = Path(name).suffix.lower()
            if ext not in (".docx", ".xlsx"):
                scan.warnings.append(
                    f"{name} 是 OLE/二进制嵌入对象，无法安全做真删除；"
                    f"建议开启 strip_embeddings 直接移除，或在原文档里删掉该对象")

    # ------------------------------------------------------------------
    def apply_decisions(self, scan: FileScan, decisions: Mapping[str, Any] | None) -> None:
        """把人工复核决策打到 span 上。

        decisions 结构：
          {'spans': {span_id: {'action':'reject'|'accept', 'strategy':'MASK'}},
           'extra_spans': [{'block':…,'start':…,'end':…,'etype':'PERSON'}],
           'extra_names': ['张三'],
           'boxes': {box_id: {'action':'reject'}}}
        """
        if not decisions:
            return
        fname = Path(scan.path).name
        by_id = {s.span_id: s for s in scan.all_spans}
        for sid, d in (decisions.get("spans") or {}).items():
            s = by_id.get(sid)
            if s is None:
                continue
            act = d.get("action")
            if act == "reject":
                s.action = "reject"
                # 记下"谁决定保留的、保留了什么"，审计报告里单列
                key = (s.etype, canon_entity(s.etype, s.text) or s.text)
                self.waivers[key] = {
                    "text": s.text, "etype": s.etype, "block": s.block,
                    "file": fname, "confidence": s.confidence,
                    "reason": d.get("reason") or "人工复核标记为误报/有意保留",
                }
            elif act == "accept":
                s.action = "accept"
            if d.get("strategy"):
                s.decision_strategy = Strategy(d["strategy"]).value

        for extra in (decisions.get("extra_spans") or []):
            block = extra.get("block", "body")
            start = int(extra.get("start", 0))
            end = int(extra.get("end", start))
            text = scan.blocks.get(block, "")[start:end]
            if not text:
                continue
            s = Span(start, end, text, extra.get("etype", "CUSTOM"),
                     confidence=1.0, source="manual", reason="人工补标",
                     block=block, action="accept")
            s.span_id = f"m{len(by_id) + 1:05d}"
            scan.spans.setdefault(block, []).append(s)
            self.resolver.add(s, file_id=Path(scan.path).name)

        for name in (decisions.get("extra_names") or []):
            self.extra_names.append(name)
            self._learned.append(name)

        for bid, d in (decisions.get("boxes") or {}).items():
            for boxes in scan.boxes_by_page.values():
                for b in boxes:
                    if b.box_id == bid and d.get("action") == "reject":
                        b.action = "reject"

    # ------------------------------------------------------------------
    def build_replacements(self, scan: FileScan) -> tuple[dict[str, list[Replacement]], int]:
        """根据 span 与 resolver 生成每个 block 的替换清单。"""
        self.resolver.finalize()
        out: dict[str, list[Replacement]] = {}
        n = 0
        for block, spans in scan.spans.items():
            items: list[Replacement] = []
            for s in spans:
                if s.etype in MARKER_ONLY_TYPES:
                    continue
                if s.action == "reject":
                    continue
                e = self.resolver.entities.get((s.etype, canon_entity(s.etype, s.text) or s.text))
                if e is None:
                    e = self.resolver.add(s, file_id=Path(scan.path).name)
                    self.resolver.finalize()
                strat = Strategy(s.decision_strategy) if s.decision_strategy \
                    else self.resolver.strategy_for(e)
                if strat == Strategy.KEEP:
                    continue
                new = self.resolver.replacement_for(s)
                if new == s.text:
                    continue
                items.append(Replacement(s.start, s.end, new, s.etype, s.span_id))
                n += 1
            if items:
                out[block] = items
        return out, n

    # ------------------------------------------------------------------
    def redact(self, path: str | Path, dst: str | Path,
               decisions: Mapping[str, Any] | None = None,
               scan: FileScan | None = None) -> FileResult:
        """单文件脱敏。scan 可复用之前的扫描结果（复核界面走这条路）。"""
        path = Path(path)
        dst = Path(dst)
        fmt = detect_format(path)

        if scan is None or scan.path != str(path):
            scan = self.scan(path)
        self.apply_decisions(scan, decisions)
        # 人工补标后需要重算
        replacements, n = self.build_replacements(scan)

        res = FileResult(path=str(path), out_path=str(dst), fmt=fmt, scan=scan,
                         replacements=n, warnings=list(scan.warnings))

        if fmt == "image":
            self._redact_image(path, dst, scan, res)
        elif fmt == "docx":
            self._redact_docx(path, dst, scan, replacements, res)
        elif fmt == "pdf":
            self._redact_pdf(path, dst, scan, replacements, res)
        elif fmt == "text":
            ad = scan.adapter if isinstance(scan.adapter, TextRedactor) \
                else TextRedactor(path, self.options)
            rep = ad.write(dst, replacements)
            res.replacements = rep.replacements
            res.adapter_report = rep.to_dict()
            res.warnings.extend(rep.warnings)
        elif fmt == "xlsx":
            from .formats.xlsx_fmt import XlsxRedactor
            ad = scan.adapter if isinstance(scan.adapter, XlsxRedactor) \
                else XlsxRedactor(path, self.options)
            rep = ad.write(dst, replacements)
            res.adapter_report = rep.to_dict()
            res.warnings.extend(rep.warnings)
        return res

    # -- 各格式落盘 ------------------------------------------------------
    def _redact_image(self, path: Path, dst: Path, scan: FileScan, res: FileResult) -> None:
        ad = ImageRedactor(path, self.options)
        boxes = [b for b in scan.boxes_by_page.get(0, []) if b.action != "reject"]
        rep = ad.write(dst, boxes)
        res.adapter_report = rep.to_dict()
        res.warnings.extend(rep.warnings)

    def _redact_docx(self, path: Path, dst: Path, scan: FileScan,
                     replacements: dict[str, list[Replacement]], res: FileResult) -> None:
        import numpy as np
        import cv2

        ad = scan.adapter if isinstance(scan.adapter, DocxRedactor) \
            else DocxRedactor(path, self.options)
        if not ad._projections and not ad._roots:
            # 复用失败或全新实例：必须 extract()，否则"接受修订"和投影都不会发生
            try:
                ad.extract()
            except Exception as e:
                res.warnings.append(f"DOCX 提取失败：{type(e).__name__}: {e}")
        vis = self.vision
        # 图片框按媒体部件分组（scan 阶段用 page=-1 汇总，这里按顺序重算更可靠）
        media_boxes: dict[str, list[Box]] = {}
        if vis is not None:
            for name in ad.media_parts():
                ext = Path(name).suffix.lower()
                if ext not in IMAGE_EXTS:
                    continue
                arr = cv2.imdecode(np.frombuffer(ad._parts[name], np.uint8), cv2.IMREAD_COLOR)
                if arr is None:
                    continue
                boxes = vis.detect(arr, page=0)
                boxes = [b for b in boxes if b.action != "reject"]
                if boxes:
                    media_boxes[name] = boxes

        def media_hook(name: str, data: bytes) -> bytes | None:
            ext = Path(name).suffix.lower()
            if ext not in IMAGE_EXTS:
                return None
            boxes = media_boxes.get(name)
            arr = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
            if arr is None:
                return None
            if boxes:
                arr, _ = fill_boxes(arr, boxes, pad=int(self.options.get("fill_pad", 2)))
            ok, buf = cv2.imencode(ext if ext != ".tif" else ".tiff", arr)
            return buf.tobytes() if ok else None

        def embedding_hook(name: str, data: bytes) -> bytes | None:
            ext = Path(name).suffix.lower()
            if self.options.get("strip_embeddings", False):
                return b""    # 由 write 阶段跳过写入（见下）
            if ext not in (".docx", ".xlsx"):
                return None
            # 递归处理嵌入的 Office 文档
            with tempfile.TemporaryDirectory() as td:
                tmp_in = Path(td) / ("in" + ext)
                tmp_out = Path(td) / ("out" + ext)
                tmp_in.write_bytes(data)
                try:
                    sub = Engine(self.preset, self.options, extra_names=self.extra_names,
                                 seed=self.seed, learned_names=self.resolver.learned_names())
                    sub.redact(tmp_in, tmp_out)
                    return tmp_out.read_bytes()
                except Exception as e:
                    res.warnings.append(f"嵌入对象 {name} 递归处理失败：{type(e).__name__}: {e}")
                    return None

        rep = ad.write(dst, replacements, media_hook=media_hook,
                       embedding_hook=embedding_hook if not self.options.get("strip_embeddings") else None)
        res.adapter_report = rep.to_dict()
        res.warnings.extend(rep.warnings)
        ad.close()
        scan.adapter = None

        # strip_embeddings：把嵌入部件从产物里删掉
        if self.options.get("strip_embeddings", False):
            _strip_zip_members(dst, [n for n in ad.embedding_parts()])
            res.adapter_report["embeddings_removed"] = ad.embedding_parts()

    def _redact_pdf(self, path: Path, dst: Path, scan: FileScan,
                    replacements: dict[str, list[Replacement]], res: FileResult) -> None:
        from .formats.pdf_fmt import PdfRedactor, PdfSpanReplacement

        # block 'page3' -> 页索引 2。偏移量直接用投影坐标，比 search_for 可靠
        page_repls: dict[int, list[PdfSpanReplacement]] = {}
        for block, items in replacements.items():
            if not block.startswith("page"):
                continue
            tail = block[4:]
            if not tail.isdigit():
                continue      # 'page1#ocr' 这类只用于登记实体，不做版面替换
            pno = int(tail) - 1
            lst = page_repls.setdefault(pno, [])
            for r in items:
                orig = scan.blocks.get(block, "")[r.start:r.end]
                lst.append(PdfSpanReplacement(start=r.start, end=r.end, new=r.new,
                                              text=orig, etype=r.etype,
                                              page=pno, span_id=r.span_id))

        boxes_by_page = {k: [b for b in v if b.action != "reject"]
                         for k, v in scan.boxes_by_page.items()}

        ad = scan.adapter if isinstance(scan.adapter, PdfRedactor) else PdfRedactor(path, self.options)
        try:
            rep = ad.write(dst, page_repls, vision_boxes_by_page=boxes_by_page)
        finally:
            ad.close()
            scan.adapter = None
        res.adapter_report = rep.to_dict()
        res.warnings.extend(rep.warnings)

        # 安全网：有文本没定位到的页，整页栅格化（彻底没有文本层）
        if rep.not_found and self.options.get("pdf_rasterize_on_miss", True):
            pages = sorted({int(x.split(":", 1)[0][1:]) - 1 for x in rep.not_found})
            res.warnings.append(
                f"{len(rep.not_found)} 处文本在 PDF 里定位不到（跨行/异形编码），"
                f"已对第 {[p + 1 for p in pages]} 页整页栅格化以确保无文本层残留")
            try:
                _rasterize_pdf_pages(path, dst, pages, self, boxes_by_page)
                res.adapter_report["rasterized_pages"] = [p + 1 for p in pages]
            except Exception as e:
                res.warnings.append(f"整页栅格化失败：{type(e).__name__}: {e}；产物可能存在文本层残留")

    # ------------------------------------------------------------------
    def redact_batch(self, items: Sequence[tuple[str | Path, str | Path]],
                     decisions_by_path: Mapping[str, Mapping[str, Any]] | None = None,
                     progress=None) -> list[FileResult]:
        """批量脱敏，跨文件一致化。

        items: [(src, dst), …]
        流程：全部扫描 → 汇总实体 → 用确认过的姓名回喂重扫 → 统一写盘。
        """
        decisions_by_path = dict(decisions_by_path or {})
        scans: dict[str, FileScan] = {}

        # 第一遍扫描
        for src, _ in items:
            src = str(src)
            try:
                scans[src] = self.scan(src)
            except Exception as e:
                s = FileScan(path=src, fmt="unknown")
                s.warnings.append(f"扫描失败：{type(e).__name__}: {e}")
                scans[src] = s
            if progress:
                progress("scan", src)

        # 姓名回喂：把第一遍确认的姓名灌进检测器，重扫一遍
        learned = self.resolver.learned_names()
        if learned and self.options.get("two_pass_names", True):
            self._learned = list(dict.fromkeys(self._learned + learned))
            self.pipe.extra_names = list(dict.fromkeys(self.pipe.extra_names + learned))
            for src in list(scans):
                sc = scans[src]
                if sc.fmt in ("unknown",) or not sc.blocks:
                    continue
                try:
                    sc.spans = self.pipe.run(sc.blocks, hints=sc.hints)
                    self.resolver.add_all(sc.all_spans, file_id=Path(src).name)
                except Exception as e:
                    sc.warnings.append(f"二遍扫描失败：{type(e).__name__}: {e}")
                if progress:
                    progress("rescan", src)

        self.resolver.finalize()

        # 写盘
        out: list[FileResult] = []
        for src, dst in items:
            src = str(src)
            sc = scans.get(src)
            if sc is None or sc.fmt == "unknown":
                out.append(FileResult(path=src, out_path=str(dst), fmt="unknown",
                                      scan=sc or FileScan(path=src, fmt="unknown"),
                                      warnings=["扫描失败，未处理"]))
                continue
            try:
                r = self.redact(src, dst, decisions_by_path.get(src), scan=sc)
            except Exception as e:
                r = FileResult(path=src, out_path=str(dst), fmt=sc.fmt, scan=sc,
                               warnings=[f"脱敏失败：{type(e).__name__}: {e}"])
            out.append(r)
            if progress:
                progress("redact", src)
        return out


# --------------------------------------------------------------------------
# 工具函数
# --------------------------------------------------------------------------


def _strip_zip_members(zip_path: Path, members: Sequence[str]) -> None:
    """从 zip 里物理删除指定部件（用于 strip_embeddings）。"""
    import zipfile

    if not members:
        return
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td) / "out.docx"
        with zipfile.ZipFile(zip_path, "r") as zin, \
                zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename in set(members):
                    continue
                zout.writestr(item, zin.read(item.filename))
        shutil.move(str(tmp), str(zip_path))


def _rasterize_pdf_pages(src: Path, dst: Path, pages: Sequence[int], engine: "Engine",
                         boxes_by_page: Mapping[int, Sequence[Box]]) -> None:
    """把指定页替换成"已打码的位图页"，彻底消除文本层残留。

    页面图像从**原文件**渲染（这样能拿到完整原始版面），敏感区域全部填实，
    然后替换进**已脱敏的产物**并另存。产物其余页保持不动。
    """
    import fitz
    import numpy as np
    import PIL.Image as _Image

    dpi = int(engine.options.get("pdf_render_dpi", 200))
    zoom = dpi / 72.0
    vis = engine.vision

    rendered: dict[int, Any] = {}
    with fitz.open(str(src)) as sdoc:
        for pno in pages:
            if pno < 0 or pno >= sdoc.page_count:
                continue
            page = sdoc[pno]
            pix = page.get_pixmap(matrix=fitz.Matrix(zoom, zoom), alpha=False)
            arr = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width, pix.n)
            if pix.n == 4:
                arr = arr[:, :, :3]
            bgr = arr[:, :, ::-1].copy()
            boxes = list(boxes_by_page.get(pno, []))
            if vis is not None:
                extra = [b for b in vis.detect(bgr, page=pno) if b.action != "reject"]
                boxes = _merge_box_lists(boxes, extra)
            if boxes:
                bgr, _ = fill_boxes(bgr, boxes, pad=int(engine.options.get("fill_pad", 2)))
            rendered[pno] = bgr[:, :, ::-1].copy()   # BGR -> RGB

    if not rendered:
        return

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td) / "rasterized.pdf"
        with fitz.open(str(dst)) as ddoc:
            for pno, rgb in rendered.items():
                if pno >= ddoc.page_count:
                    continue
                page = ddoc[pno]
                # 整页 redaction：清掉文本层与原有图像
                page.add_redact_annot(page.rect, fill=(1, 1, 1))
                img_mode = getattr(fitz, "PDF_REDACT_IMAGE_PIXELS", 2)
                try:
                    page.apply_redactions(images=img_mode)
                except TypeError:
                    page.apply_redactions()
                buf = io.BytesIO()
                _Image.fromarray(rgb).save(buf, format="PNG")
                page.insert_image(page.rect, stream=buf.getvalue())
            if engine.options.get("strip_metadata", True):
                try:
                    ddoc.set_metadata({})
                    ddoc.del_xml_metadata()
                except Exception:
                    pass
            ddoc.save(str(tmp), garbage=4, deflate=True, clean=True)
        shutil.move(str(tmp), str(dst))


def _merge_box_lists(a: Sequence[Box], b: Sequence[Box]) -> list[Box]:
    out = list(a)
    for x in b:
        if not any(_same_box(x, y) for y in out):
            out.append(x)
    return out


def _same_box(a: Box, b: Box, tol: float = 3.0) -> bool:
    return (abs(a.x - b.x) <= tol and abs(a.y - b.y) <= tol
            and abs(a.w - b.w) <= tol and abs(a.h - b.h) <= tol)
