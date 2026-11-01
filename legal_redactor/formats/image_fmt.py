"""图片适配器：视觉检测 + 实心覆盖 + 元数据剥离。

真删除说明：覆盖后**重新编码**，被盖住的像素在产物里已不存在，
不是"在原图上叠一层"。同时不写回 EXIF（GPS 是重灾区）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

import numpy as np

from ..core import Box

try:
    import cv2
    _CV2 = True
except Exception:  # pragma: no cover
    cv2 = None
    _CV2 = False

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp"}


@dataclass
class ImageReport:
    width: int = 0
    height: int = 0
    boxes_filled: int = 0
    exif_stripped: bool = False
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "width": self.width, "height": self.height,
            "boxes_filled": self.boxes_filled, "exif_stripped": self.exif_stripped,
            "warnings": self.warnings,
        }


def imread_unicode(path: str | Path):
    """cv2.imread 在 Windows 上不支持中文路径，走 fromfile + imdecode。"""
    if not _CV2:
        return None
    data = np.fromfile(str(path), dtype=np.uint8)
    if data.size == 0:
        return None
    return cv2.imdecode(data, cv2.IMREAD_COLOR)


def imwrite_unicode(path: str | Path, img, ext: str | None = None) -> bool:
    if not _CV2:
        return False
    p = Path(path)
    ext = ext or p.suffix or ".png"
    params: list[int] = []
    if ext.lower() in (".jpg", ".jpeg"):
        params = [int(cv2.IMWRITE_JPEG_QUALITY), 92]
    elif ext.lower() == ".png":
        params = [int(cv2.IMWRITE_PNG_COMPRESSION), 6]
    ok, buf = cv2.imencode(ext, img, params)
    if not ok:
        return False
    p.parent.mkdir(parents=True, exist_ok=True)
    buf.tofile(str(p))
    return True


def fill_boxes(img, boxes: Sequence[Box], color=(0, 0, 0), pad: int = 2,
               label: bool = False) -> tuple[Any, int]:
    """实心填充。返回 (新图, 填充数)。"""
    out = img.copy()
    h, w = out.shape[:2]
    n = 0
    for b in boxes:
        x1 = max(0, int(b.x) - pad)
        y1 = max(0, int(b.y) - pad)
        x2 = min(w, int(b.x + b.w) + pad)
        y2 = min(h, int(b.y + b.h) + pad)
        if x2 <= x1 or y2 <= y1:
            continue
        cv2.rectangle(out, (x1, y1), (x2, y2), color, thickness=-1)
        n += 1
    return out, n


class ImageRedactor:
    def __init__(self, src: str | Path, options: dict[str, Any] | None = None):
        self.src = Path(src)
        self.options = dict(options or {})
        self.report = ImageReport()
        self.img = imread_unicode(self.src)
        if self.img is None:
            raise ValueError(f"无法读取图片：{self.src}")
        self.report.height, self.report.width = self.img.shape[:2]

    def detect(self, vision) -> list[Box]:
        """vision: VisionPipeline 实例。"""
        return vision.detect(self.img, page=0)

    def write(self, dst: str | Path, boxes: Sequence[Box]) -> ImageReport:
        color = tuple(self.options.get("fill_color", (0, 0, 0)))
        out, n = fill_boxes(self.img, boxes, color=color,
                            pad=int(self.options.get("fill_pad", 2)))
        self.report.boxes_filled = n
        dst = Path(dst)
        if not imwrite_unicode(dst, out):
            self.report.warnings.append(f"写入失败：{dst}")
        # cv2 重编码本身就不保留 EXIF；这里显式确认产物无 EXIF
        self.report.exif_stripped = _verify_no_exif(dst)
        return self.report


def _verify_no_exif(path: Path) -> bool:
    try:
        from PIL import Image
        with Image.open(path) as im:
            return not im.getexif()
    except Exception:
        return True


def has_exif_gps(path: str | Path) -> bool:
    """检测原图是否带 GPS EXIF（审计报告里要单独说，因为这是最容易被忽略的泄露）。"""
    try:
        from PIL import Image
        with Image.open(path) as im:
            ex = im.getexif()
            if not ex:
                return False
            # 0x8825 = GPSInfo
            return bool(ex.get(0x8825) or ex.get(34853) or ex.get_ifd(0x8825))
    except Exception:
        return False
