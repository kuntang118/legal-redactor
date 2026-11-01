"""纯文本 / Markdown / CSV 适配器。"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from .docx_fmt import Replacement


_ENCODINGS = ("utf-8-sig", "utf-8", "gb18030", "gbk", "big5", "utf-16", "utf-16-le", "latin-1")


def sniff_encoding(data: bytes) -> str:
    for enc in _ENCODINGS:
        try:
            data.decode(enc)
            return enc
        except (UnicodeDecodeError, LookupError):
            continue
    return "utf-8"


@dataclass
class TextReport:
    encoding: str = "utf-8"
    chars: int = 0
    replacements: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "encoding": self.encoding, "chars": self.chars,
            "replacements": self.replacements, "warnings": self.warnings,
        }


class TextRedactor:
    """整份文本作为单个 block（'body'），偏移量直接对应文件字符位置。"""

    def __init__(self, src: str | Path, options: dict[str, Any] | None = None):
        self.src = Path(src)
        self.options = dict(options or {})
        self.report = TextReport()
        raw = self.src.read_bytes()
        self.encoding = sniff_encoding(raw)
        self.text = raw.decode(self.encoding, errors="replace")
        self.report.encoding = self.encoding
        self.report.chars = len(self.text)

    def extract(self) -> dict[str, str]:
        return {"body": self.text}

    def write(self, dst: str | Path,
              replacements: dict[str, list[Replacement]] | None = None) -> TextReport:
        repls = sorted((replacements or {}).get("body", []), key=lambda r: -r.start)
        out = self.text
        n = 0
        for r in repls:
            if r.start < 0 or r.end > len(out) or r.start >= r.end:
                continue
            out = out[: r.start] + r.new + out[r.end:]
            n += 1
        self.report.replacements = n
        dst = Path(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        # 统一用 UTF-8 输出，避免 GBK 写不回某些替换字符
        enc = "utf-8" if self.options.get("force_utf8", True) else self.encoding
        if self.encoding == "utf-8-sig":
            enc = "utf-8-sig" if not self.options.get("force_utf8", True) else "utf-8"
        dst.write_text(out, encoding=enc, newline="")
        self.report.encoding = enc
        return self.report


def read_text_any(path: str | Path) -> str:
    """审计用：按嗅探到的编码读回文本。"""
    raw = Path(path).read_bytes()
    return raw.decode(sniff_encoding(raw), errors="replace")
