"""视觉实体检测：红章（含骑缝章）、二维码/条码、图片内文字。

全部走本地：OpenCV（HSV + 轮廓）与 RapidOCR ONNX（CPU），不依赖 GPU、不联网。
"""
from __future__ import annotations

import re
from typing import Callable, Iterable, Sequence

from ..core import Box, Span

try:
    import cv2
    import numpy as np
    _CV2_OK = True
except Exception:  # pragma: no cover
    cv2 = None
    np = None
    _CV2_OK = False

# 敏感实体类型（图内文字命中这些才打码）
SENSITIVE_IN_IMAGE = {
    "ID_CARD", "PHONE", "TEL", "BANK_CARD", "EMAIL", "USCC", "PASSPORT",
    "HK_MO_PERMIT", "IM_ACCOUNT", "PLATE", "IP_ADDR", "MAC_ADDR", "PERSON",
    "ADDRESS", "SUSPECT_ID", "MINOR_INFO", "MEDICAL",
}


def cv2_available() -> bool:
    return _CV2_OK


def _sane_box(x: float, y: float, w: float, h: float, img_shape,
              min_area_ratio: float = 1e-5, max_area_ratio: float = 0.9) -> bool:
    """检测框必须真的落在图内，且面积合理。

    cv2.QRCodeDetector 在照片/印章这类"非二维码"输入上会返回**荒谬的多边形**，
    实测签章页给出过 y=-3220、高 3420 的框——越界到图片外面。
    不校验的话会把一大片无辜内容涂掉，还会让审计的视觉复检跟着错判。
    """
    H, W = img_shape[:2]
    if w <= 0 or h <= 0:
        return False
    if x < -2 or y < -2 or x + w > W + 2 or y + h > H + 2:
        return False
    area_ratio = (w * h) / float(max(1, W * H))
    return min_area_ratio <= area_ratio <= max_area_ratio


# --------------------------------------------------------------------------
# 红章
# --------------------------------------------------------------------------


def detect_seals(img, page: int = 0, min_area_ratio: float = 0.0015) -> list[Box]:
    """红色印章检测。

    覆盖：圆形公章、椭圆章、方形章、骑缝章（贴边半圆/条状）。
    """
    if not _CV2_OK:
        return []
    h_img, w_img = img.shape[:2]
    img_area = float(h_img * w_img)
    min_area = max(200.0, img_area * min_area_ratio)

    hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
    # 红色跨 0 度，需两段
    m1 = cv2.inRange(hsv, np.array([0, 60, 60]), np.array([10, 255, 255]))
    m2 = cv2.inRange(hsv, np.array([156, 60, 60]), np.array([180, 255, 255]))
    mask = cv2.bitwise_or(m1, m2)

    k = max(3, int(min(h_img, w_img) * 0.012)) | 1
    mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, np.ones((k, k), np.uint8))
    mask = cv2.dilate(mask, np.ones((3, 3), np.uint8), iterations=2)

    contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    out: list[Box] = []
    border_tol = max(2, int(min(h_img, w_img) * 0.01))
    for c in contours:
        area = float(cv2.contourArea(c))
        if area < min_area:
            continue
        x, y, w, h = cv2.boundingRect(c)
        if w < 12 or h < 12:
            continue
        peri = cv2.arcLength(c, True)
        circ = (4 * np.pi * area / (peri * peri)) if peri > 0 else 0.0
        aspect = w / float(h)
        rect_fill = area / float(w * h)

        touches_edge = (x <= border_tol or y <= border_tol
                        or x + w >= w_img - border_tol or y + h >= h_img - border_tol)

        kind = None
        conf = 0.0
        if 0.55 <= aspect <= 1.8 and (circ >= 0.55 or rect_fill >= 0.6):
            kind, conf = "圆形/方形印章", min(0.95, 0.6 + circ * 0.4)
        elif touches_edge and (aspect > 1.8 or aspect < 0.55) and rect_fill >= 0.35:
            kind, conf = "骑缝章/边缘章", 0.8
        elif rect_fill >= 0.75 and area > min_area * 2:
            kind, conf = "方形印章", 0.75
        elif touches_edge and rect_fill >= 0.25 and area > min_area * 1.5:
            kind, conf = "疑似骑缝章", 0.55
        if kind is None:
            continue
        if not _sane_box(x, y, w, h, img.shape):
            continue

        out.append(Box(x=float(x), y=float(y), w=float(w), h=float(h), etype="SEAL",
                       confidence=round(float(conf), 3), source="cv2_hsv",
                       reason=f"{kind}：红色面积{area:.0f}px²、圆度{circ:.2f}、宽高比{aspect:.2f}"
                              f"{'、贴边' if touches_edge else ''}",
                       page=page, text=""))
    return out


# --------------------------------------------------------------------------
# 二维码 / 条码
# --------------------------------------------------------------------------


def detect_qr(img, page: int = 0) -> list[Box]:
    """二维码/条码检测。

    cv2.QRCodeDetector 对非二维码输入（照片、红章、密集文字）会返回越界或
    退化的多边形，必须用 _sane_box 卡掉，否则会误涂大片正常内容。
    """
    if not _CV2_OK:
        return []
    H, W = img.shape[:2]
    out: list[Box] = []
    det = cv2.QRCodeDetector()
    try:
        ok, pts, _ = det.detectAndDecode(img)
    except Exception:
        ok, pts = False, None
    if pts is not None and len(pts) > 0:
        for poly in np.atleast_3d(pts).reshape(-1, 4, 2):
            xs, ys = poly[:, 0], poly[:, 1]
            x, y = float(xs.min()), float(ys.min())
            w, h = float(xs.max() - x), float(ys.max() - y)
            if not _sane_box(x, y, w, h, img.shape):
                continue
            # 二维码近似正方形；退化多边形（一边极短）判为噪声
            if min(w, h) < max(8.0, 0.004 * min(W, H)):
                continue
            if not (0.35 <= w / h <= 2.9):
                continue
            out.append(Box(x=x, y=y, w=w, h=h,
                           etype="QR_CODE", confidence=0.95 if ok else 0.8,
                           source="cv2_qr",
                           reason="OpenCV QRCodeDetector 检出（扫码可能跳转原始链接）"
                                  + ("" if ok else "，未解出内容，置信度已下调"),
                           page=page))
    # 条码（仅 contrib 版可用）
    try:
        bd = cv2.barcode.BarcodeDetector()  # type: ignore[attr-defined]
        res = bd.detectAndDecode(img)
        corners = res[1] if isinstance(res, tuple) else None
        if corners is not None:
            for poly in np.array(corners).reshape(-1, 4, 2):
                xs, ys = poly[:, 0], poly[:, 1]
                x, y = float(xs.min()), float(ys.min())
                w, h = float(xs.max() - x), float(ys.max() - y)
                if not _sane_box(x, y, w, h, img.shape):
                    continue
                out.append(Box(x=x, y=y, w=w, h=h,
                               etype="QR_CODE", confidence=0.9, source="cv2_barcode",
                               reason="条码检出", page=page))
    except Exception:
        pass
    return out


# --------------------------------------------------------------------------
# OCR
# --------------------------------------------------------------------------

_OCR = None


def get_ocr():
    """惰性加载 RapidOCR（首次加载会初始化 ONNX 会话）。"""
    global _OCR
    if _OCR is None:
        from rapidocr_onnxruntime import RapidOCR
        _OCR = RapidOCR()
    return _OCR


def ocr_available() -> bool:
    try:
        import rapidocr_onnxruntime  # noqa: F401
        return True
    except Exception:
        return False


def ocr_boxes(img, page: int = 0) -> list[Box]:
    """OCR 出所有文本框（未过滤），text 字段为识别文字。"""
    if not ocr_available():
        return []
    eng = get_ocr()
    try:
        res, _ = eng(img)
    except Exception:
        return []
    out: list[Box] = []
    if not res:
        return out
    for item in res:
        poly, text, score = item[0], item[1], float(item[2])
        pts = np.array(poly).reshape(-1, 2)
        x, y = float(pts[:, 0].min()), float(pts[:, 1].min())
        out.append(Box(x=x, y=y,
                       w=float(pts[:, 0].max() - x), h=float(pts[:, 1].max() - y),
                       etype="IMG_TEXT", confidence=round(score, 3), source="rapidocr",
                       reason="OCR 文本框", page=page, text=text))
    return out


# --------------------------------------------------------------------------
# 视觉流水线
# --------------------------------------------------------------------------


class VisionPipeline:
    """把印章/二维码/OCR 三路合成，并用文本检测器过滤出真正含敏感信息的 OCR 框。"""

    name = "vision"
    produces = ("SEAL", "QR_CODE", "IMG_TEXT")

    def __init__(self, text_detect: Callable[[str, str], Sequence[Span]] | None = None,
                 enable_ocr: bool = True, enable_seal: bool = True, enable_qr: bool = True):
        self.text_detect = text_detect
        self.enable_ocr = enable_ocr
        self.enable_seal = enable_seal
        self.enable_qr = enable_qr

    def detect(self, img, page: int = 0) -> list[Box]:
        if not _CV2_OK:
            return []
        out: list[Box] = []
        if self.enable_seal:
            out.extend(detect_seals(img, page))
        if self.enable_qr:
            out.extend(detect_qr(img, page))
        if self.enable_ocr and self.text_detect is not None:
            for b in ocr_boxes(img, page):
                spans = list(self.text_detect(b.text or "", f"page{page + 1}#ocr"))
                hits = [s for s in spans if s.etype in SENSITIVE_IN_IMAGE]
                if not hits:
                    continue
                b.reason = "OCR 文本框内含敏感实体：" + "、".join(
                    sorted({f"{s.etype}({s.text})" for s in hits}))
                b.confidence = round(max(b.confidence, max(s.confidence for s in hits)), 3)
                b.text = b.text
                out.append(b)
        # 去重：同页重叠框只留面积大的
        return _dedup_boxes(out)


def _dedup_boxes(boxes: Iterable[Box]) -> list[Box]:
    items = sorted(boxes, key=lambda b: (b.page, -(b.w * b.h)))
    kept: list[Box] = []
    for b in items:
        if any(_box_overlap_ratio(b, k) > 0.6 for k in kept):
            continue
        kept.append(b)
    kept.sort(key=lambda b: (b.page, b.y, b.x))
    for i, b in enumerate(kept):
        if not b.box_id:
            b.box_id = f"b{i:05d}"
    return kept


def _box_overlap_ratio(a: Box, b: Box) -> float:
    ax2, ay2 = a.x + a.w, a.y + a.h
    bx2, by2 = b.x + b.w, b.y + b.h
    ix = max(0.0, min(ax2, bx2) - max(a.x, b.x))
    iy = max(0.0, min(ay2, by2) - max(a.y, b.y))
    inter = ix * iy
    if inter <= 0:
        return 0.0
    return inter / max(1.0, min(a.w * a.h, b.w * b.h))


# --------------------------------------------------------------------------
# 工具：坐标换算
# --------------------------------------------------------------------------


def scale_boxes(boxes: Sequence[Box], sx: float, sy: float) -> list[Box]:
    """把在缩放图上检出的坐标映射回原图/页面坐标。"""
    out = []
    for b in boxes:
        out.append(Box(x=b.x * sx, y=b.y * sy, w=b.w * sx, h=b.h * sy,
                       etype=b.etype, confidence=b.confidence, source=b.source,
                       reason=b.reason, page=b.page, text=b.text, action=b.action))
    return out
