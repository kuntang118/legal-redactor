"""PDF 适配器：真 redaction（删文本层）+ 视觉链路（印章/二维码/扫描页 OCR）。

关键点：
  - 必须用 `add_redact_annot` + `apply_redactions`，画黑框是骗人的
  - `apply_redactions` 后必须**另存为新文件**并 garbage=4/clean，
    否则 PDF 增量更新历史里的旧对象还留在文件尾部，能直接捞回原文
  - 文本检测不能直接用 `page.get_text()`：它会在换行处插入 \\n，
    把一个地址/证件号从中间切断，导致后半截永远检不出来。
    这里用 `rawdict` 做**字符级投影**（与 DOCX 同一套思路）：
    同一段落内的换行不投影成字符，跨行实体保持连续；
    每个字符记着自己的 bbox，替换时按行分组成矩形。
  - 扫描页没有文本层，走"渲染 → 视觉检测 → 坐标换算回 PDF 空间"
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    import fitz  # PyMuPDF
    _FITZ = True
except Exception:  # pragma: no cover
    fitz = None
    _FITZ = False

try:
    import pypdfium2 as pdfium
    _PDFIUM = True
except Exception:  # pragma: no cover
    pdfium = None
    _PDFIUM = False

import numpy as np

from ..core import Box
from ..detect.name_det import TRIGGER_RE

#: 页面文本少于此字符数即视为扫描页
SCAN_PAGE_THRESHOLD = 24

#: 上一行以这些标点结尾时，才在投影文本里插入换行
_LINE_BREAK_AFTER = set("。；;！!？?：:")


def pymupdf_available() -> bool:
    return _FITZ


def pypdfium_available() -> bool:
    return _PDFIUM


# --------------------------------------------------------------------------


@dataclass
class PageProjection:
    """一页的字符级投影。bboxes[i] 对应 text[i]，插入的分隔换行为 None。"""

    page: int
    text: str = ""
    bboxes: list[Any] = field(default_factory=list)


@dataclass
class PdfSpanReplacement:
    """PDF 上的一次替换。优先用 start/end 偏移（投影坐标），
    偏移无效时退回按 text 搜索。"""

    start: int = -1
    end: int = -1
    new: str = ""
    text: str = ""
    etype: str = ""
    page: int = 0
    span_id: str = ""
    rects: list = field(default_factory=list)
    found: bool = False


@dataclass
class PdfReport:
    pages: int = 0
    text_replacements: int = 0
    not_found: list[str] = field(default_factory=list)
    vision_boxes: int = 0
    scan_pages: list[int] = field(default_factory=list)
    metadata_stripped: bool = False
    embedded_files_removed: list[str] = field(default_factory=list)
    backend: str = ""
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def build_projection(page, pno: int, join_lines: bool = True) -> PageProjection:
    """用 rawdict 建字符级投影。

    join_lines=True（默认）时**不插入任何分隔符**：PDF 的换行是排版产物，
    不是语义边界，插进去会把"北京市朝阳区建国路88号院3号楼2单元401室"
    从中间切断，后半截永远检不出来。中文本身靠标点断句，检测器的边界
    判定用的就是标点，所以直接连起来是安全的。
    跨行的 span 在替换时按 y 坐标聚类成多个矩形（见 _rects_for），
    首行写替换值、其余行涂黑。
    """
    proj = PageProjection(page=pno)
    chars: list[str] = []
    boxes: list[Any] = []
    try:
        d = page.get_text("rawdict")
    except Exception:
        d = {"blocks": []}

    def push_break(prev_tail: str, next_text: str) -> None:
        if not join_lines:
            chars.append("\n")
            boxes.append(None)
            return
        # 只在明确的语义边界插换行：上一行以句末标点结束，
        # 或下一行以法律角色词开头（落款区"审 判 长　刘振华"这种）
        if prev_tail in _LINE_BREAK_AFTER or TRIGGER_RE.match(next_text):
            chars.append("\n")
            boxes.append(None)

    prev_tail = ""
    for block in d.get("blocks", []):
        if block.get("type", 0) != 0:      # 1 = 图像块
            continue
        block_lines: list[list] = []
        for line in block.get("lines", []):
            line_chars = [(ch.get("c", ""), ch.get("bbox"))
                          for span in line.get("spans", [])
                          for ch in span.get("chars", [])]
            if line_chars:
                block_lines.append(line_chars)
        if not block_lines:
            continue
        for line_chars in block_lines:
            next_text = "".join(c for c, _ in line_chars)
            if chars:
                push_break(prev_tail, next_text)
            for c, bb in line_chars:
                chars.append(c)
                boxes.append(bb)
            prev_tail = line_chars[-1][0] if line_chars else ""

    proj.text = "".join(chars)
    proj.bboxes = boxes
    return proj


def _group_lines(proj: PageProjection, start: int, end: int) -> list[list[int]]:
    """把 [start,end) 的字符按 y 坐标聚成行，返回每行的字符下标列表。"""
    groups: list[list[int]] = []
    cur: list[int] = []
    cur_y: float | None = None
    for i in range(start, min(end, len(proj.bboxes))):
        bb = proj.bboxes[i]
        if bb is None:
            continue
        y = (bb[1] + bb[3]) / 2.0
        h = max(1.0, bb[3] - bb[1])
        if cur_y is None or abs(y - cur_y) <= max(2.0, h * 0.5):
            cur.append(i)
            cur_y = y if cur_y is None else (cur_y + y) / 2.0
        else:
            if cur:
                groups.append(cur)
            cur = [i]
            cur_y = y
    if cur:
        groups.append(cur)
    return groups


def _rects_for(proj: PageProjection, start: int, end: int, pad: float = 0.6) -> list:
    """把一段字符区间转成每行一个矩形。"""
    rects = []
    for g in _group_lines(proj, start, end):
        x0 = min(proj.bboxes[i][0] for i in g)
        y0 = min(proj.bboxes[i][1] for i in g)
        x1 = max(proj.bboxes[i][2] for i in g)
        y1 = max(proj.bboxes[i][3] for i in g)
        r = fitz.Rect(x0 - pad, y0 - pad, x1 + pad, y1 + pad)
        rects.append(r)
    return rects


class PdfRedactor:
    def __init__(self, src: str | Path, options: Mapping[str, Any] | None = None):
        if not _FITZ:
            raise RuntimeError("未安装 PyMuPDF；可用 pypdfium2 栅格化兜底")
        self.src = Path(src)
        self.options = dict(options or {})
        self.report = PdfReport(backend="pymupdf")
        self.doc = fitz.open(str(self.src))
        self.report.pages = self.doc.page_count
        self.projections: dict[int, PageProjection] = {}

    def close(self) -> None:
        try:
            self.doc.close()
        except Exception:
            pass

    def __enter__(self) -> "PdfRedactor":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------
    def extract(self) -> dict[str, str]:
        blocks: dict[str, str] = {}
        for i, page in enumerate(self.doc):
            proj = build_projection(page, i)
            self.projections[i] = proj
            blocks[f"page{i + 1}"] = proj.text
            if len(proj.text.strip()) < SCAN_PAGE_THRESHOLD:
                self.report.scan_pages.append(i)
        return blocks

    def page_image(self, index: int, dpi: int | None = None):
        dpi = dpi or int(self.options.get("pdf_render_dpi", 200))
        page = self.doc[index]
        zoom = dpi / 72.0
        pix = page.get_pixmap(matrix=fitz.Matrix(zoom, zoom), alpha=False)
        arr = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width, pix.n)
        if pix.n == 4:
            arr = arr[:, :, :3]
        return arr[:, :, ::-1].copy(), zoom

    # ------------------------------------------------------------------
    def locate(self, page_repls: Mapping[int, Sequence[PdfSpanReplacement]]) -> None:
        """把每个替换项定位成"每行一个矩形"。"""
        for pno, items in page_repls.items():
            if pno < 0 or pno >= self.doc.page_count:
                continue
            proj = self.projections.get(pno) or build_projection(self.doc[pno], pno)
            page = self.doc[pno]
            for it in items:
                rects: list = []
                if proj is not None and 0 <= it.start < it.end <= len(proj.text):
                    rects = _rects_for(proj, it.start, it.end)
                if not rects:
                    # 退回按文本搜索（例如偏移来自别处）
                    target = it.text or (proj.text[it.start:it.end] if proj else "")
                    for frag in _split_fragments(target) or [target]:
                        rects.extend(self._search(page, frag))
                it.rects = rects
                it.found = bool(rects)
                if not rects:
                    label = it.text or (proj.text[it.start:it.end]
                                        if proj and 0 <= it.start < it.end else "?")
                    self.report.not_found.append(f"p{pno + 1}: {label[:40]!r}")

    @staticmethod
    def _search(page, text: str) -> list:
        t = (text or "").strip()
        if not t:
            return []
        try:
            r = page.search_for(t, quads=True)
        except Exception:
            r = []
        out = []
        for q in r or []:
            try:
                out.append(fitz.Quad(q).rect)
            except Exception:
                out.append(q)
        return out

    # ------------------------------------------------------------------
    def write(self, dst: str | Path,
              page_repls: Mapping[int, Sequence[PdfSpanReplacement]] | None = None,
              vision_boxes_by_page: Mapping[int, Sequence[Box]] | None = None) -> PdfReport:
        page_repls = dict(page_repls or {})
        dst = Path(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)

        style = self.options.get("pdf_style", "text")     # text | box
        placeholder = self.options.get("placeholder", "[已脱敏]")

        # 1) 文本层 redaction
        self.locate(page_repls)
        for pno, items in page_repls.items():
            if pno < 0 or pno >= self.doc.page_count:
                continue
            page = self.doc[pno]
            for it in items:
                for r in it.rects:
                    try:
                        page.add_redact_annot(r, fill=(0, 0, 0) if style == "box" else None)
                    except Exception as e:
                        self.report.warnings.append(f"p{pno + 1} 添加 redaction 失败：{e}")
                if it.found:
                    self.report.text_replacements += 1

        # 2) 视觉 redaction（印章/二维码/扫描页 OCR）
        zoom = int(self.options.get("pdf_render_dpi", 200)) / 72.0
        for pno, boxes in (vision_boxes_by_page or {}).items():
            if pno < 0 or pno >= self.doc.page_count:
                continue
            page = self.doc[pno]
            for b in boxes:
                r = fitz.Rect(b.x / zoom, b.y / zoom, (b.x + b.w) / zoom, (b.y + b.h) / zoom)
                try:
                    page.add_redact_annot(r, fill=(0, 0, 0))
                except Exception as e:
                    self.report.warnings.append(f"p{pno + 1} 视觉 redaction 失败：{e}")
                self.report.vision_boxes += 1

        # 3) 执行 redaction：删文本 + 擦图像像素
        img_mode = getattr(fitz, "PDF_REDACT_IMAGE_PIXELS", 2)
        for page in self.doc:
            if page.first_annot:
                try:
                    page.apply_redactions(images=img_mode)
                except TypeError:
                    page.apply_redactions()
                except Exception as e:
                    self.report.warnings.append(f"apply_redactions 失败：{e}")

        # 4) 回写替换文本（style == text）：首行写替换值，其余行涂黑
        if style == "text":
            for pno, items in page_repls.items():
                if pno < 0 or pno >= self.doc.page_count:
                    continue
                page = self.doc[pno]
                for it in items:
                    if not it.found:
                        continue
                    new = it.new or placeholder
                    if not new:
                        continue
                    for li, r in enumerate(it.rects):
                        if li > 0:
                            page.draw_rect(r, color=None, fill=(0, 0, 0))
                            continue
                        fs = max(4.0, min(11.0, r.height * 0.82))
                        ok = False
                        for try_fs in (fs, fs * 0.75, fs * 0.55, 4.0):
                            try:
                                rc = page.insert_textbox(r, new, fontname="china-s",
                                                         fontsize=try_fs, align=0,
                                                         color=(0, 0, 0))
                            except Exception:
                                rc = -1
                            if rc is not None and rc >= 0:
                                ok = True
                                break
                        if not ok:
                            page.draw_rect(r, color=None, fill=(0, 0, 0))

        # 5) 清掉注释里可能残留的弹窗文本
        for page in self.doc:
            for a in list(page.annots() or []):
                try:
                    info = a.info or {}
                    if info.get("content") or info.get("title"):
                        a.set_info(content="", title="")
                        a.update()
                except Exception:
                    pass

        # 6) 删除嵌入文件
        try:
            for name in list(self.doc.embfile_names() or []):
                try:
                    self.doc.embfile_delete(name)
                    self.report.embedded_files_removed.append(name)
                except Exception as e:
                    self.report.warnings.append(f"删除嵌入文件 {name} 失败：{e}")
        except Exception:
            pass

        # 7) 元数据
        if self.options.get("strip_metadata", True):
            try:
                self.doc.set_metadata({})
                self.report.metadata_stripped = True
            except Exception as e:
                self.report.warnings.append(f"清空元数据失败：{e}")
            try:
                self.doc.del_xml_metadata()
            except Exception:
                pass

        # 8) 另存为新文件（非增量）+ 回收间接对象。
        #    这一步防止 PDF 增量更新历史把原文留在文件尾部。
        try:
            self.doc.save(str(dst), garbage=4, deflate=True, clean=True, incremental=False)
        except TypeError:
            self.doc.save(str(dst), garbage=4, deflate=True, clean=True)
        except Exception as e:
            self.report.warnings.append(f"保存失败，退回默认参数：{e}")
            self.doc.save(str(dst))
        return self.report


def _split_fragments(text: str, min_len: int = 3) -> list[str]:
    import re as _re
    return [p for p in _re.split(r"[\s\u3000，。、；：！？,.;:!?\-—…·]+", text or "")
            if len(p) >= min_len]


# --------------------------------------------------------------------------
# pypdfium2 兜底：整页栅格化，产物没有文本层（最安全但不可搜索）
# --------------------------------------------------------------------------


class PdfRasterFallback:
    """无 PyMuPDF 时的兜底路径：渲染每页 → 图上打码 → 重建纯图像 PDF。

    产物彻底没有文本层，从原理上不可能残留可搜索的原文；
    代价是不可搜索、不可复制、体积变大。许可证上 pypdfium2 是
    Apache-2.0/BSD，比 PyMuPDF 的 AGPL 更适合分发。
    """

    def __init__(self, src: str | Path, options: Mapping[str, Any] | None = None):
        if not _PDFIUM:
            raise RuntimeError("未安装 pypdfium2")
        self.src = Path(src)
        self.options = dict(options or {})
        self.report = PdfReport(backend="pypdfium2-raster")
        self.pdf = pdfium.PdfDocument(str(self.src))
        self.report.pages = len(self.pdf)

    def close(self) -> None:
        try:
            self.pdf.close()
        except Exception:
            pass

    def page_image(self, index: int, dpi: int | None = None):
        dpi = dpi or int(self.options.get("pdf_render_dpi", 200))
        page = self.pdf[index]
        scale = dpi / 72.0
        pil = page.render(scale=scale).to_pil().convert("RGB")
        return np.asarray(pil)[:, :, ::-1].copy(), scale

    def write(self, dst: str | Path,
              vision_boxes_by_page: Mapping[int, Sequence[Box]] | None = None,
              dpi: int | None = None) -> PdfReport:
        from PIL import Image
        from .image_fmt import fill_boxes

        dst = Path(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dpi = dpi or int(self.options.get("pdf_render_dpi", 200))
        pages: list[Any] = []
        for i in range(len(self.pdf)):
            img, _scale = self.page_image(i, dpi)
            boxes = list((vision_boxes_by_page or {}).get(i, []))
            if boxes:
                img, n = fill_boxes(img, boxes, pad=2)
                self.report.vision_boxes += n
            pages.append(Image.fromarray(img[:, :, ::-1]))
        if pages:
            pages[0].save(dst, "PDF", resolution=float(dpi), save_all=True,
                          append_images=pages[1:])
        return self.report


def read_pdf_text(path: str | Path) -> str:
    """审计用：抽取文本层。"""
    if _FITZ:
        out = []
        with fitz.open(str(path)) as d:
            for i, p in enumerate(d):
                out.append(f"--- page {i + 1} ---\n" + (p.get_text("text") or ""))
        return "\n".join(out)
    if _PDFIUM:
        out = []
        pdf = pdfium.PdfDocument(str(path))
        for i in range(len(pdf)):
            tp = pdf[i].get_textpage()
            out.append(f"--- page {i + 1} ---\n" + (tp.get_text_bounded() or ""))
            tp.close()
        pdf.close()
        return "\n".join(out)
    return ""
