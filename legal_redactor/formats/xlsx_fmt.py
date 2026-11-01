"""XLSX 适配器。

要处理的远不止单元格值：共享字符串表、公式里硬编码的字面量、批注、
定义名称、数据验证列表、页眉页脚、文档属性。
用 openpyxl 处理后**另存**，不保留原表——原表的 sharedStrings.xml
是全局去重存储，原地改单元格而不动共享串是经典漏点。

已知代价：openpyxl 以 data_only=False 读入时会丢掉公式的缓存计算值，
另存后需要 Excel 重算。对脱敏产物来说这个代价可以接受，审计报告会写明。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from .docx_fmt import Replacement
from .text_fmt import TextReport

XLSX_EXTS = {".xlsx", ".xlsm"}


@dataclass
class XlsxReport:
    sheets: int = 0
    cells_scanned: int = 0
    cells_changed: int = 0
    comments_changed: int = 0
    formulas_changed: int = 0
    defined_names_changed: int = 0
    header_footer_changed: int = 0
    validation_changed: int = 0
    metadata_stripped: bool = False
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


class XlsxRedactor:
    def __init__(self, src: str | Path, options: dict[str, Any] | None = None):
        import openpyxl

        self.src = Path(src)
        self.options = dict(options or {})
        self.report = XlsxReport()
        self.wb = openpyxl.load_workbook(str(self.src), data_only=False, keep_vba=False)
        self.report.sheets = len(self.wb.sheetnames)
        #: block_id -> 该单元格所在列的列头文本，供列头驱动检测使用
        self.block_hints: dict[str, str] = {}

    # ------------------------------------------------------------------
    def _header_row(self, ws) -> int:
        """猜表头所在行：前 5 行里，非空字符串单元格最多且都能被列头规则识别的那一行。"""
        from ..detect.pipeline import header_etype

        best, best_score = 1, -1.0
        for r in range(1, min(6, ws.max_row or 1) + 1):
            vals = [c.value for c in ws[r]]
            strs = [str(v).strip() for v in vals if isinstance(v, str) and v.strip()]
            if len(strs) < 2:
                continue
            hits = sum(1 for s in strs if header_etype(s))
            score = hits * 2 + len(strs) * 0.1
            if score > best_score:
                best, best_score = r, score
        return best if best_score > 0 else 1

    # ------------------------------------------------------------------
    def extract(self) -> dict[str, str]:
        """把每个可能含文本的位置抽成一个 block。

        block id 形式：
          'sheet:工作表1!A1'          单元格值 / 公式
          'comment:工作表1!A1'        批注
          'hf:工作表1!header'         页眉页脚
          'dv:工作表1!0'              数据验证列表
          'dn:名称'                   定义名称
        """
        blocks: dict[str, str] = {}
        for ws in self.wb.worksheets:
            hrow = self._header_row(ws)
            headers: dict[int, str] = {}
            for c in ws[hrow]:
                if isinstance(c.value, str) and c.value.strip():
                    headers[c.column] = c.value.strip()
            for row in ws.iter_rows():
                for cell in row:
                    self.report.cells_scanned += 1
                    v = cell.value
                    bid = f"sheet:{ws.title}!{cell.coordinate}"
                    if cell.row != hrow and cell.column in headers:
                        self.block_hints[bid] = headers[cell.column]
                    if v is None:
                        pass
                    elif isinstance(v, str) and v.strip():
                        blocks[bid] = v
                    # 批注
                    cmt = getattr(cell, "comment", None)
                    if cmt is not None and getattr(cmt, "text", None):
                        blocks[f"comment:{ws.title}!{cell.coordinate}"] = cmt.text
            # 页眉页脚
            for part in ("oddHeader", "oddFooter", "evenHeader", "evenFooter",
                         "firstPageHeader", "firstPageFooter"):
                hf = getattr(ws, part, None)
                if hf is None:
                    continue
                txt = "".join(str(getattr(hf, x, "") or "")
                              for x in ("left", "center", "right"))
                if txt.strip():
                    blocks[f"hf:{ws.title}!{part}"] = txt
            # 数据验证里的字面量列表
            try:
                for i, dv in enumerate(ws.data_validations.dataValidation):
                    if dv.formula1 and isinstance(dv.formula1, str) and "," in dv.formula1:
                        blocks[f"dv:{ws.title}!{i}"] = dv.formula1
            except Exception:
                pass
        # 定义名称
        try:
            for name, dn in dict(self.wb.defined_names).items():
                val = getattr(dn, "value", None) or getattr(dn, "attr_text", None)
                if isinstance(val, str) and val.strip():
                    blocks[f"dn:{name}"] = val
        except Exception:
            pass
        return blocks

    # ------------------------------------------------------------------
    def write(self, dst: str | Path,
              replacements: dict[str, list[Replacement]] | None = None) -> XlsxReport:
        replacements = replacements or {}
        dst = Path(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)

        def apply_to(text: str, repls: Sequence[Replacement]) -> str:
            out = text
            n = 0
            for r in sorted(repls, key=lambda x: -x.start):
                if r.start < 0 or r.end > len(out) or r.start >= r.end:
                    continue
                out = out[: r.start] + r.new + out[r.end:]
                n += 1
            return out if n else text, n

        for bid, repls in replacements.items():
            if not repls:
                continue
            kind, rest = bid.split(":", 1)
            try:
                if kind == "sheet":
                    sheet, coord = rest.split("!", 1)
                    cell = self.wb[sheet][coord]
                    old = cell.value if isinstance(cell.value, str) else str(cell.value or "")
                    new, n = apply_to(old, repls)
                    if n:
                        if cell.data_type == "f" or (isinstance(old, str) and old.startswith("=")):
                            cell.value = new
                            self.report.formulas_changed += n
                        else:
                            cell.value = new
                            self.report.cells_changed += n
                elif kind == "comment":
                    sheet, coord = rest.split("!", 1)
                    cell = self.wb[sheet][coord]
                    if cell.comment is not None:
                        new, n = apply_to(cell.comment.text or "", repls)
                        if n:
                            cell.comment.text = new
                            self.report.comments_changed += n
                elif kind == "hf":
                    sheet, part = rest.split("!", 1)
                    ws = self.wb[sheet]
                    hf = getattr(ws, part)
                    # 页眉页脚分左中右三段，按整串匹配后回填到 left
                    whole = "".join(str(getattr(hf, x, "") or "") for x in ("left", "center", "right"))
                    new, n = apply_to(whole, repls)
                    if n:
                        hf.left, hf.center, hf.right = new, None, None
                        self.report.header_footer_changed += n
                elif kind == "dv":
                    sheet, idx = rest.split("!", 1)
                    ws = self.wb[sheet]
                    dv = ws.data_validations.dataValidation[int(idx)]
                    new, n = apply_to(dv.formula1 or "", repls)
                    if n:
                        dv.formula1 = new
                        self.report.validation_changed += n
                elif kind == "dn":
                    dn = self.wb.defined_names.get(rest)
                    if dn is not None:
                        val = getattr(dn, "value", None) or getattr(dn, "attr_text", None) or ""
                        new, n = apply_to(val, repls)
                        if n:
                            try:
                                dn.value = new
                            except Exception:
                                dn.attr_text = new
                            self.report.defined_names_changed += n
            except Exception as e:
                self.report.warnings.append(f"处理 {bid} 失败：{type(e).__name__}: {e}")

        # 文档属性
        if self.options.get("strip_metadata", True):
            p = self.wb.properties
            for f in ("creator", "lastModifiedBy", "title", "subject", "description",
                      "keywords", "category", "identifier", "language", "version",
                      "revision", "contentStatus"):
                if hasattr(p, f):
                    try:
                        setattr(p, f, "")
                    except Exception:
                        pass
            self.report.metadata_stripped = True

        try:
            self.wb.save(str(dst))
        except Exception as e:
            self.report.warnings.append(f"保存失败：{type(e).__name__}: {e}")
            raise
        return self.report


def read_xlsx_all(path: str | Path) -> str:
    """审计用：把工作簿里所有可读文本拼成一大串。"""
    import openpyxl

    wb = openpyxl.load_workbook(str(path), data_only=False, read_only=False)
    out: list[str] = []
    for ws in wb.worksheets:
        for row in ws.iter_rows():
            for cell in row:
                if cell.value is not None:
                    out.append(str(cell.value))
                if getattr(cell, "comment", None) is not None:
                    out.append(str(cell.comment.text or ""))
    try:
        for name, dn in dict(wb.defined_names).items():
            out.append(f"{name}={getattr(dn, 'value', '')}")
    except Exception:
        pass
    p = wb.properties
    for f in ("creator", "lastModifiedBy", "title", "subject", "description", "keywords"):
        v = getattr(p, f, None)
        if v:
            out.append(f"{f}={v}")
    return "\n".join(out)
