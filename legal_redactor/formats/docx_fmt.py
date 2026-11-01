"""DOCX 真删除适配器。

不用 python-docx 的原因：它不暴露页眉页脚之外的部件（customXml、embeddings），
也不能干净地清掉修订标记。这里直接对 OOXML zip 做手术。

核心难点是 Word 会把一个实体切进多个 w:r/w:t（拼写检查、格式变化、proofErr
都会切分）。解法是**段落级文本投影**：
  1. 把一个 w:p 里所有 w:t 按文档序拼成一条逻辑串
  2. 同时记下每个字符属于哪个 w:t、在其中第几位
  3. 在逻辑串上做检测和替换，再把结果反投影回各个 w:t
"""
from __future__ import annotations

import io
import re
import shutil
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from lxml import etree

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
CP = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
DC = "http://purl.org/dc/elements/1.1/"
DCTERMS = "http://purl.org/dc/terms/"
EP = "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
VT = "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"


def _w(tag: str) -> str:
    return f"{{{W}}}{tag}"


# 需要按正文处理的部件（含 w:p 结构）
TEXT_PART_PATTERNS = [
    (re.compile(r"^word/document\.xml$"), "body"),
    (re.compile(r"^word/header(\d+)\.xml$"), "header"),
    (re.compile(r"^word/footer(\d+)\.xml$"), "footer"),
    (re.compile(r"^word/footnotes\.xml$"), "footnotes"),
    (re.compile(r"^word/endnotes\.xml$"), "endnotes"),
    (re.compile(r"^word/comments\.xml$"), "comments"),
    (re.compile(r"^word/commentsIds\.xml$"), None),       # 无文本
    (re.compile(r"^word/commentsExtended\.xml$"), None),   # 无文本
    (re.compile(r"^word/people\.xml$"), "people"),
    (re.compile(r"^word/glossary/document\.xml$"), "glossary"),
]

# 修订相关标记：接受修订时要处理
_REVISION_REMOVE = ["del", "moveFrom", "moveFromRangeStart", "moveFromRangeEnd",
                    "rPrChange", "pPrChange", "sectPrChange", "tblPrChange",
                    "trPrChange", "tcPrChange", "gridColChange", "numberingChange",
                    "cellIns", "cellDel", "cellMerge", "customXmlDelRangeStart",
                    "customXmlDelRangeEnd", "customXmlInsRangeStart",
                    "customXmlInsRangeEnd", "moveToRangeStart", "moveToRangeEnd"]
_REVISION_UNWRAP = ["ins", "moveTo"]

# 文档属性里要清空的字段
_CORE_CLEAR = ["creator", "lastModifiedBy", "title", "subject", "description",
               "keywords", "category", "contentStatus", "identifier", "language",
               "version", "revision"]
_APP_CLEAR = ["Company", "Manager", "Template", "Application", "AppVersion",
              "DocSecurity", "HyperlinkBase", "TotalTime"]


@dataclass
class Replacement:
    """一次替换：把 [start, end) 换成 new。"""
    start: int
    end: int
    new: str
    etype: str = ""
    span_id: str = ""


@dataclass
class Projection:
    """一个段落的文本投影。"""
    block: str
    text: str
    #: char index -> (w:t 元素, 元素内偏移)
    nodes: list[tuple[Any, int]]
    #: w:t 元素按序
    elems: list[Any] = field(default_factory=list)


@dataclass
class DocxReport:
    parts_processed: list[str] = field(default_factory=list)
    paragraphs: int = 0
    replacements: int = 0
    revisions_accepted: bool = False
    comments_stripped: bool = False
    metadata_stripped: bool = False
    media_replaced: list[str] = field(default_factory=list)
    embeddings_processed: list[str] = field(default_factory=list)
    thumbnail_removed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "parts_processed": self.parts_processed,
            "paragraphs": self.paragraphs,
            "replacements": self.replacements,
            "revisions_accepted": self.revisions_accepted,
            "comments_stripped": self.comments_stripped,
            "metadata_stripped": self.metadata_stripped,
            "media_replaced": self.media_replaced,
            "embeddings_processed": self.embeddings_processed,
            "warnings": self.warnings,
        }


# --------------------------------------------------------------------------
# 修订处理
# --------------------------------------------------------------------------


def accept_revisions(root: etree._Element) -> int:
    """接受所有修订：w:ins/w:moveTo 提升为正常内容，w:del/w:moveFrom 整体删除，
    各类 *Change 格式修订记录一并清除。返回删除/改写的元素数。"""
    n = 0
    # 1) 删除被删内容（先 list() 快照，避免迭代中改树）
    for tag in _REVISION_REMOVE:
        for el in list(root.iter(_w(tag))):
            parent = el.getparent()
            if parent is None:
                continue
            parent.remove(el)
            n += 1

    # 2) 展开插入内容
    for tag in _REVISION_UNWRAP:
        for el in list(root.iter(_w(tag))):
            parent = el.getparent()
            if parent is None:
                continue
            idx = list(parent).index(el)
            for child in list(el):
                el.remove(child)
                parent.insert(idx, child)
                idx += 1
            parent.remove(el)
            n += 1

    # 3) 段落标记修订：w:rPr/w:ins 表示"段落标记被插入"，删掉即可
    for el in list(root.iter(_w("rPr"))):
        for ins in list(el.iter(_w("ins"))):
            el.remove(ins)
            n += 1
    return n


def strip_comment_refs(root: etree._Element) -> int:
    """移除正文里的批注引用与批注范围标记。"""
    n = 0
    for tag in ("commentReference", "commentRangeStart", "commentRangeEnd"):
        for el in list(root.iter(_w(tag))):
            parent = el.getparent()
            if parent is None:
                continue
            # commentReference 通常裹在一个空 w:r 里，顺手清掉
            if tag == "commentReference" and parent.tag == _w("r"):
                gp = parent.getparent()
                if gp is not None:
                    gp.remove(parent)
                    n += 1
                    continue
            parent.remove(el)
            n += 1
    return n


# --------------------------------------------------------------------------
# 文本投影
# --------------------------------------------------------------------------

_TEXT_TAGS = {_w("t"), _w("instrText")}


def project_paragraph(p: etree._Element, block_prefix: str, index: int) -> Projection | None:
    """把一个 w:p 投影成逻辑字符串。"""
    elems: list[Any] = []
    nodes: list[tuple[Any, int]] = []
    buf: list[str] = []
    for t in p.iter():
        if t.tag in _TEXT_TAGS and isinstance(t.text, str):
            elems.append(t)
            for k, ch in enumerate(t.text):
                nodes.append((t, k))
                buf.append(ch)
    text = "".join(buf)
    if not text.strip():
        return None
    return Projection(block=f"{block_prefix}:p{index}", text=text, nodes=nodes, elems=elems)


def apply_replacements(proj: Projection, repls: Sequence[Replacement]) -> int:
    """把替换反投影回 w:t。返回实际改写次数。"""
    if not repls or not proj.nodes:
        return 0
    # 从右往左，避免偏移失效
    ordered = sorted(repls, key=lambda r: -r.start)
    count = 0
    for r in ordered:
        if r.start >= r.end or r.end > len(proj.nodes):
            continue
        first_elem, first_off = proj.nodes[r.start]
        last_elem, last_off = proj.nodes[r.end - 1]

        if first_elem is last_elem:
            t = first_elem.text or ""
            first_elem.text = t[:first_off] + r.new + t[last_off + 1:]
        else:
            first_elem.text = (first_elem.text or "")[:first_off] + r.new
            # 中间元素清空
            seen = {id(first_elem), id(last_elem)}
            for elem, _ in proj.nodes[r.start:r.end]:
                if id(elem) in seen:
                    continue
                seen.add(id(elem))
                elem.text = ""
            last_elem.text = (last_elem.text or "")[last_off + 1:]
        count += 1

    # 收尾：给含首尾空格或已清空的 w:t 打上 xml:space，删除空 run
    for t in proj.elems:
        txt = t.text or ""
        if txt != txt.strip() or txt == "":
            t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
    return count


def prune_empty_runs(root: etree._Element) -> int:
    """删掉只剩 w:rPr 的空 run，避免产物里留下垃圾节点。"""
    n = 0
    for r in list(root.iter(_w("r"))):
        has_content = False
        for child in r:
            if child.tag in (_w("rPr"),):
                continue
            if child.tag in _TEXT_TAGS and not (child.text or ""):
                continue
            has_content = True
            break
        if not has_content:
            parent = r.getparent()
            if parent is not None:
                parent.remove(r)
                n += 1
    return n


# --------------------------------------------------------------------------
# 元数据
# --------------------------------------------------------------------------


def clear_core_props(data: bytes) -> bytes:
    try:
        root = etree.fromstring(data)
    except Exception:
        return data
    for tag in _CORE_CLEAR:
        for el in root.iter(f"{{{CP}}}{tag}"):
            el.text = ""
        for el in root.iter(f"{{{DC}}}{tag}"):
            el.text = ""
        for el in root.iter(f"{{{DCTERMS}}}{tag}"):
            el.text = ""
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)


def clear_app_props(data: bytes) -> bytes:
    try:
        root = etree.fromstring(data)
    except Exception:
        return data
    for tag in _APP_CLEAR:
        for el in root.iter(f"{{{EP}}}{tag}"):
            el.getparent().remove(el)
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)


def clear_custom_props(data: bytes) -> bytes:
    """docProps/custom.xml：自定义属性可能藏着承办人、案件编号，整个清空。"""
    try:
        root = etree.fromstring(data)
    except Exception:
        return data
    ns = root.nsmap.get(None)
    for el in list(root):
        root.remove(el)
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)


# --------------------------------------------------------------------------
# 主适配器
# --------------------------------------------------------------------------


class DocxRedactor:
    """DOCX 解析 + 真删除。

    用法：
        d = DocxRedactor(src, options)
        blocks = d.extract()                    # {block_id: text}
        ... 检测 + 生成 {block_id: [Replacement]} ...
        d.write(dst, replacements, media_hook)  # 落盘
    """

    def __init__(self, src: str | Path, options: dict[str, Any] | None = None):
        self.src = Path(src)
        self.options = dict(options or {})
        self.report = DocxReport()
        self._zip = zipfile.ZipFile(self.src, "r")
        self._parts: dict[str, bytes] = {n: self._zip.read(n) for n in self._zip.namelist()}
        self._projections: dict[str, list[Projection]] = {}
        self._roots: dict[str, etree._Element] = {}
        self._removed: set[str] = set()

    # -- 关闭 ------------------------------------------------------------
    def close(self) -> None:
        try:
            self._zip.close()
        except Exception:
            pass

    def __enter__(self) -> "DocxRedactor":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- 部件分类 --------------------------------------------------------
    def _part_kind(self, name: str) -> tuple[str | None, str]:
        for rx, prefix in TEXT_PART_PATTERNS:
            m = rx.match(name)
            if m:
                if prefix is None:
                    return None, name
                if m.groups():
                    return f"{prefix}{m.group(1)}", name
                return prefix, name
        return None, name

    def text_parts(self) -> list[tuple[str, str]]:
        """[(prefix, part_name), …]"""
        out = []
        for name in self._parts:
            prefix, _ = self._part_kind(name)
            if prefix:
                out.append((prefix, name))
        return sorted(out, key=lambda x: x[1])

    def media_parts(self) -> list[str]:
        return sorted(n for n in self._parts if n.startswith("word/media/"))

    def embedding_parts(self) -> list[str]:
        return sorted(n for n in self._parts if n.startswith("word/embeddings/"))

    # -- 提取 ------------------------------------------------------------
    def extract(self) -> dict[str, str]:
        """抽取所有段落文本，返回 {block_id: text}。"""
        blocks: dict[str, str] = {}
        if self.options.get("accept_revisions", True):
            # 先接受修订，否则 w:del 里的原文既看不见也删不掉
            for prefix, name in self.text_parts():
                try:
                    root = etree.fromstring(self._parts[name])
                except Exception as e:
                    self.report.warnings.append(f"{name} 解析失败：{e}")
                    continue
                n = accept_revisions(root)
                if n:
                    self.report.revisions_accepted = True
                    self._parts[name] = etree.tostring(
                        root, xml_declaration=True, encoding="UTF-8", standalone=True)

        for prefix, name in self.text_parts():
            if prefix == "comments" and self.options.get("strip_comments", False):
                continue
            try:
                root = etree.fromstring(self._parts[name])
            except Exception as e:
                self.report.warnings.append(f"{name} 解析失败：{e}")
                continue
            self._roots[name] = root
            projs: list[Projection] = []
            for i, p in enumerate(root.iter(_w("p"))):
                proj = project_paragraph(p, prefix, i)
                if proj is None:
                    continue
                projs.append(proj)
                blocks[proj.block] = proj.text
            self._projections[name] = projs
            self.report.paragraphs += len(projs)
            self.report.parts_processed.append(name)
        return blocks

    # -- 写回 ------------------------------------------------------------
    def write(self, dst: str | Path,
              replacements: dict[str, list[Replacement]] | None = None,
              media_hook: Callable[[str, bytes], bytes | None] | None = None,
              embedding_hook: Callable[[str, bytes], bytes | None] | None = None) -> DocxReport:
        """落盘。replacements: {block_id: [Replacement]}。"""
        replacements = replacements or {}
        dst = Path(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)

        # 1) 批注处理
        if self.options.get("strip_comments", False):
            for name in list(self._parts):
                if name == "word/comments.xml":
                    self._empty_part(name)
                    self.report.comments_stripped = True
                elif name in ("word/commentsExtended.xml", "word/commentsIds.xml",
                              "word/people.xml"):
                    # 必须同时清掉 lxml 树：第 2 步会把 _roots 里的树重新序列化回
                    # _parts，只改字节会被覆盖回去（people.xml 的批注作者名就是这么漏的）
                    self._empty_part(name)
            for name, root in self._roots.items():
                if strip_comment_refs(root):
                    self._parts[name] = etree.tostring(
                        root, xml_declaration=True, encoding="UTF-8", standalone=True)

        # 1.5) Word 缩略图：docProps/thumbnail.jpeg 是文档首页的位图快照，
        #      页眉页脚里的当事人姓名、电话都在里面。直接删部件 + 删关系 + 删 Override。
        if self.options.get("strip_thumbnail", True):
            self._strip_thumbnail()

        # 2) 文本替换
        by_block: dict[str, list[Replacement]] = {}
        for bid, repls in replacements.items():
            if repls:
                by_block[bid] = repls

        for name, projs in self._projections.items():
            changed = False
            for proj in projs:
                repls = by_block.get(proj.block)
                if not repls:
                    continue
                n = apply_replacements(proj, repls)
                if n:
                    self.report.replacements += n
                    changed = True
            root = self._roots.get(name)
            if root is None:
                continue
            if changed or self.options.get("prune_empty_runs", True):
                prune_empty_runs(root)
            self._parts[name] = etree.tostring(
                root, xml_declaration=True, encoding="UTF-8", standalone=True)

        # 3) 媒体（图片）
        if media_hook is not None:
            for name in self.media_parts():
                try:
                    new = media_hook(name, self._parts[name])
                except Exception as e:
                    self.report.warnings.append(f"处理 {name} 失败：{type(e).__name__}: {e}")
                    continue
                if new is not None and new != self._parts[name]:
                    self._parts[name] = new
                    self.report.media_replaced.append(name)

        # 4) 嵌入对象
        if embedding_hook is not None:
            for name in self.embedding_parts():
                try:
                    new = embedding_hook(name, self._parts[name])
                except Exception as e:
                    self.report.warnings.append(f"处理嵌入对象 {name} 失败：{type(e).__name__}: {e}")
                    continue
                if new is not None and new != self._parts[name]:
                    self._parts[name] = new
                    self.report.embeddings_processed.append(name)

        # 5) 元数据
        if self.options.get("strip_metadata", True):
            for name in list(self._parts):
                if name == "docProps/core.xml":
                    self._parts[name] = clear_core_props(self._parts[name])
                    self.report.metadata_stripped = True
                elif name == "docProps/app.xml":
                    self._parts[name] = clear_app_props(self._parts[name])
                elif name == "docProps/custom.xml":
                    self._parts[name] = clear_custom_props(self._parts[name])
                elif name.startswith("customXml/") and name.endswith(".xml"):
                    # 自定义 XML 部件可能带业务敏感字段，保守起见扫描后告警
                    if self.options.get("strip_custom_xml", False):
                        self._parts[name] = b'<?xml version="1.0" encoding="UTF-8"?><root/>'

        # 6) 重新打包。保留压缩方式与顺序，未改动的部件原样写回
        infos = {i.filename: i for i in self._zip.infolist()}
        with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
            for name in self._zip.namelist():
                data = self._parts.get(name)
                if data is None:
                    continue
                zi = infos.get(name)
                if zi is not None:
                    new_info = zipfile.ZipInfo(zi.filename, date_time=zi.date_time)
                    new_info.compress_type = zi.compress_type
                    new_info.external_attr = zi.external_attr
                    new_info.internal_attr = zi.internal_attr
                    new_info.create_system = zi.create_system
                    z.writestr(new_info, data)
                else:
                    z.writestr(name, data)
        return self.report

    # -- 辅助 ------------------------------------------------------------
    def _empty_part(self, name: str) -> None:
        """清空一个 XML 部件的子节点，字节和 lxml 树同步更新。"""
        old = self._parts.get(name)
        if old is None:
            return
        try:
            root = etree.fromstring(old)
        except Exception:
            return
        for el in list(root):
            root.remove(el)
        data = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)
        self._parts[name] = data
        if name in self._roots:
            self._roots[name] = root

    def _strip_thumbnail(self) -> None:
        """删除 docProps/thumbnail.* 及其关系与内容类型声明。"""
        thumb = [n for n in self._parts if n.startswith("docProps/thumbnail")]
        if not thumb:
            return
        for n in thumb:
            self._removed.add(n)
            self._parts.pop(n, None)
            self.report.thumbnail_removed.append(n)

        # _rels/.rels 里指向缩略图的关系
        rels_name = "_rels/.rels"
        if rels_name in self._parts:
            try:
                root = etree.fromstring(self._parts[rels_name])
                for rel in list(root):
                    typ = (rel.get("Type") or "").lower()
                    tgt = (rel.get("Target") or "").lower()
                    if "thumbnail" in typ or "thumbnail" in tgt:
                        root.remove(rel)
                self._parts[rels_name] = etree.tostring(
                    root, xml_declaration=True, encoding="UTF-8", standalone=True)
            except Exception as e:
                self.report.warnings.append(f"清理缩略图关系失败：{e}")

        # [Content_Types].xml 里的 Override / Default
        ct_name = "[Content_Types].xml"
        if ct_name in self._parts:
            try:
                root = etree.fromstring(self._parts[ct_name])
                for el in list(root):
                    pn = (el.get("PartName") or "").lower()
                    if "thumbnail" in pn:
                        root.remove(el)
                self._parts[ct_name] = etree.tostring(
                    root, xml_declaration=True, encoding="UTF-8", standalone=True)
            except Exception as e:
                self.report.warnings.append(f"清理缩略图内容类型失败：{e}")

    def _empty_comments(self, name: str) -> bytes:
        self._empty_part(name)
        return self._parts.get(name, b"")

    def _empty_root(self, name: str) -> bytes:
        self._empty_part(name)
        return self._parts.get(name, b"")

    # -- 供审计使用 ------------------------------------------------------
    @staticmethod
    def dump_all_text(path: str | Path) -> list[tuple[str, str]]:
        """审计用：把 docx 里所有部件的原始文本抽出来（不做渲染，直接扫 XML/二进制）。"""
        out: list[tuple[str, str]] = []
        with zipfile.ZipFile(path, "r") as z:
            for name in z.namelist():
                data = z.read(name)
                if name.endswith(".xml") or name.endswith(".rels"):
                    try:
                        s = data.decode("utf-8", errors="replace")
                    except Exception:
                        s = ""
                    out.append((name, s))
                elif name.startswith("word/media/"):
                    out.append((name, f"<binary {len(data)} bytes>"))
                else:
                    # OLE/嵌入对象：也按 latin-1 扫一遍可见 ASCII 与 UTF-16 片段
                    out.append((name, _loose_text(data)))
        return out


def _loose_text(data: bytes) -> str:
    """从二进制里尽力抠出可读文本，用于残留自检（宁可多扫）。"""
    chunks = []
    try:
        chunks.append(data.decode("utf-8", errors="ignore"))
    except Exception:
        pass
    try:
        chunks.append(data.decode("utf-16-le", errors="ignore"))
    except Exception:
        pass
    chunks.append(data.decode("latin-1", errors="ignore"))
    return "\n".join(chunks)


def read_docx_text(path: str | Path) -> str:
    """渲染级文本（给人看/做检测），按段落换行。"""
    with zipfile.ZipFile(path, "r") as z:
        names = [n for n in z.namelist()
                 if any(rx.match(n) for rx, _ in TEXT_PART_PATTERNS)]
        out = []
        for n in sorted(names):
            try:
                root = etree.fromstring(z.read(n))
            except Exception:
                continue
            for p in root.iter(_w("p")):
                txt = "".join(t.text or "" for t in p.iter() if t.tag in _TEXT_TAGS)
                if txt.strip():
                    out.append(f"[{n}] {txt}")
    return "\n".join(out)
