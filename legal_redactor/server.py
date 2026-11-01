"""本地复核界面：stdlib http.server，不联网、不引外部资源、无端口依赖。

刻意不用 FastAPI：Python312 环境里没有，而且一个单机单人用的复核台
不需要 ASGI。上传走"裸 body + X-Filename 头"，绕开 multipart 解析
（cgi 模块在 3.13 已被移除，不想留隐患）。
"""
from __future__ import annotations

import json
import mimetypes
import re
import secrets
import shutil
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .core import ENTITY_TYPES, Preset, Strategy, entity_label, group_types, load_preset
from .engine import Engine, FileScan, FORMAT_BY_EXT, REFUSE_EXTS, detect_format
from .audit import Auditor, write_audit
from .strategies.mapping import write_mapping

from . import resources

# 打包后 __file__ 的上级目录不是项目根，静态资源必须走 resources 解析
WEB_DIR = resources.web_dir()

_SESSIONS: dict[str, dict[str, Any]] = {}
_LOCK = threading.Lock()


class Session:
    def __init__(self, sid: str, preset: Preset, options: dict, workdir: Path):
        self.sid = sid
        self.preset = preset
        self.options = options
        self.workdir = workdir
        self.src_dir = workdir / "src"
        self.out_dir = workdir / "out"
        self.report_dir = workdir / "report"
        for d in (self.src_dir, self.out_dir, self.report_dir):
            d.mkdir(parents=True, exist_ok=True)
        self.files: list[dict[str, Any]] = []
        self.engine: Engine | None = None
        self.scans: dict[str, FileScan] = {}
        self.results: list = []
        self.lock = threading.Lock()

    def to_dict(self) -> dict[str, Any]:
        return {"sid": self.sid, "preset": self.preset.id,
                "files": [f["name"] for f in self.files]}


def _new_engine(s: Session) -> Engine:
    return Engine(s.preset, options=s.options, seed=f"web-{s.sid}".encode())


def _scan_payload(s: Session) -> dict[str, Any]:
    out = []
    res = s.engine.resolver if s.engine else None
    for f in s.files:
        sc = s.scans.get(f["id"])
        if sc is None:
            continue
        blocks = dict(sc.blocks)
        spans = []
        for ss in sc.spans.values():
            for sp in ss:
                d = sp.to_dict()
                d["label"] = entity_label(sp.etype)
                d["ctx"] = _context(blocks.get(sp.block, ""), sp.start, sp.end)
                d["strategy"] = _strategy_of(s, sp)
                spans.append(d)
        boxes = []
        for pg, bs in sc.boxes_by_page.items():
            for b in bs:
                d = b.to_dict()
                d["label"] = entity_label(b.etype)
                d["page_label"] = ("内嵌图片" if pg == -1 else f"第{pg + 1}页")
                boxes.append(d)
        out.append({
            "id": f["id"], "name": f["name"], "fmt": sc.fmt,
            "blocks": blocks, "spans": spans, "boxes": boxes,
            "warnings": sc.warnings,
            "n_spans": len(spans), "n_boxes": len(boxes),
        })
    return {"files": out}


def _strategy_of(s: Session, sp) -> str:
    """该 span 当前会被采用的策略。"""
    from .detect.base import canon_entity

    if sp.decision_strategy:
        return sp.decision_strategy
    if sp.action == "reject":
        return Strategy.KEEP.value
    if sp.etype in ("MINOR_INFO",):
        return Strategy.KEEP.value + "（区域标记，不替换）"
    if s.engine is None:
        return s.preset.strategy_for(sp.etype).value
    ent = s.engine.resolver.entities.get(
        (sp.etype, canon_entity(sp.etype, sp.text) or sp.text))
    if ent is None:
        return s.preset.strategy_for(sp.etype).value
    return s.engine.resolver.strategy_for(ent).value


def _context(text: str, start: int, end: int, before: int = 28, after: int = 28) -> str:
    a = max(0, start - before)
    b = min(len(text), end + after)
    return (("…" if a > 0 else "") + text[a:start] + "\u27e6" + text[start:end]
            + "\u27e7" + text[end:b] + ("…" if b < len(text) else ""))


# --------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    server_version = "FaYin/0.1"
    protocol_version = "HTTP/1.1"

    # -- 基础 ------------------------------------------------------------
    def log_message(self, fmt, *args):     # 静音默认日志
        pass

    def _send(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8",
              extra: dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _json(self, obj: Any, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"))

    def _err(self, msg: str, code: int = 400) -> None:
        self._json({"ok": False, "error": msg}, code)

    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _json_body(self) -> dict:
        raw = self._body()
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"请求体不是合法 JSON：{e}")

    def _session(self) -> Session | None:
        q = parse_qs(urlparse(self.path).query)
        sid = (q.get("session") or [self.headers.get("X-Session", "")])[0]
        return _SESSIONS.get(sid)

    # -- GET -------------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        try:
            if path in ("/", "/index.html"):
                return self._static(WEB_DIR / "index.html", "text/html; charset=utf-8")
            if path == "/api/presets":
                return self._api_presets(parse_qs(u.query))
            if path == "/api/types":
                return self._api_types()
            if path == "/api/strategies":
                return self._json({"ok": True, "strategies": [s.value for s in Strategy]})
            if path == "/api/listdir":
                return self._api_listdir(parse_qs(u.query))
            if path == "/api/scan":
                s = self._session()
                if not s:
                    return self._err("会话不存在", 404)
                return self._json({"ok": True, **_scan_payload(s)})
            if path.startswith("/api/download/"):
                return self._api_download(path[len("/api/download/"):], parse_qs(u.query))
            if path == "/api/health":
                from .detect.vision_det import cv2_available, ocr_available
                from .formats.pdf_fmt import pymupdf_available, pypdfium_available
                return self._json({"ok": True, "cv2": cv2_available(), "ocr": ocr_available(),
                                   "pymupdf": pymupdf_available(),
                                   "pypdfium2": pypdfium_available()})
            return self._err("not found", 404)
        except Exception as e:
            traceback.print_exc()
            return self._err(f"{type(e).__name__}: {e}", 500)

    def _static(self, p: Path, ctype: str):
        if not p.exists():
            return self._err(f"缺少前端文件 {p}", 500)
        self._send(200, p.read_bytes(), ctype)

    def _api_presets(self, q):
        d = Path(q.get("dir", [str(resources.schema_dir())])[0])
        out = []
        for f in sorted(d.glob("*.y*ml")):
            try:
                p = load_preset(f)
                out.append({"id": p.id, "label": p.label, "description": p.description,
                            "file": str(f),
                            "n_redacted": sum(1 for k in ENTITY_TYPES if p.is_redacted(k))})
            except Exception as e:
                out.append({"id": f.stem, "label": f.stem, "description": f"解析失败：{e}",
                            "file": str(f), "n_redacted": 0})
        self._json({"ok": True, "presets": out, "dir": str(d)})

    def _api_types(self):
        g = group_types()
        self._json({"ok": True, "groups": {
            k: [e.to_dict() for e in v] for k, v in g.items()},
            "labels": {k: v.label for k, v in ENTITY_TYPES.items()}})

    def _api_listdir(self, q):
        p = Path(q.get("path", ["."])[0]).expanduser()
        try:
            p = p.resolve()
        except Exception:
            return self._err("路径无法解析")
        if not p.exists():
            return self._err("路径不存在", 404)
        if not p.is_dir():
            p = p.parent
        items = []
        try:
            for f in sorted(p.iterdir(), key=lambda x: (x.is_file(), x.name.lower())):
                if f.name.startswith("."):
                    continue
                ext = f.suffix.lower()
                items.append({
                    "name": f.name, "path": str(f), "dir": f.is_dir(),
                    "supported": f.is_dir() or ext in FORMAT_BY_EXT,
                    "refused": REFUSE_EXTS.get(ext, ""),
                    "size": (f.stat().st_size if f.is_file() else 0),
                })
        except PermissionError:
            return self._err("没有读取权限", 403)
        self._json({"ok": True, "path": str(p),
                    "parent": str(p.parent) if p.parent != p else None, "items": items})

    def _api_download(self, rel: str, q):
        s = self._session()
        if not s:
            return self._err("会话不存在", 404)
        rel = unquote(rel)
        if ".." in rel or rel.startswith(("/", "\\")):
            return self._err("非法路径")
        # 允许下载 out/ 与 report/ 下的文件
        cand = None
        for base in (s.out_dir, s.report_dir, s.workdir):
            p = (base / rel).resolve()
            try:
                p.relative_to(s.workdir.resolve())
            except Exception:
                continue
            if p.exists() and p.is_file():
                cand = p
                break
        if cand is None:
            return self._err("文件不存在", 404)
        ctype = mimetypes.guess_type(cand.name)[0] or "application/octet-stream"
        data = cand.read_bytes()
        from urllib.parse import quote
        self._send(200, data, ctype, {
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(cand.name)}"})

    # -- POST ------------------------------------------------------------
    def do_POST(self):
        u = urlparse(self.path)
        path = u.path
        try:
            if path == "/api/session":
                return self._api_new_session()
            if path == "/api/upload":
                return self._api_upload(parse_qs(u.query))
            if path == "/api/pick":
                return self._api_pick()
            if path == "/api/scan":
                return self._api_scan()
            if path == "/api/redact":
                return self._api_redact()
            if path == "/api/reset":
                return self._api_reset()
            return self._err("not found", 404)
        except ValueError as e:
            return self._err(str(e))
        except Exception as e:
            traceback.print_exc()
            return self._err(f"{type(e).__name__}: {e}", 500)

    def _api_new_session(self):
        body = self._json_body()
        preset_id = body.get("preset", "legal")
        schema_dir = Path(body.get("schema_dir") or resources.schema_dir())
        cand = schema_dir / f"{preset_id}.yaml"
        if Path(preset_id).exists():
            cand = Path(preset_id)
        if not cand.exists():
            return self._err(f"找不到预设 {preset_id}")
        preset = load_preset(cand)
        options = dict(preset.options or {})
        options.update(body.get("options") or {})
        sid = secrets.token_hex(8)
        workdir = Path(body.get("workdir") or (resources.data_dir("web") / sid))
        s = Session(sid, preset, options, workdir)
        s.engine = _new_engine(s)
        with _LOCK:
            _SESSIONS[sid] = s
        self._json({"ok": True, "session": sid, "preset": preset.id,
                    "workdir": str(workdir), "options": options})

    def _api_upload(self, q):
        s = self._session()
        if not s:
            return self._err("会话不存在", 404)
        name = self.headers.get("X-Filename") or ""
        name = Path(unquote(name)).name if name else ""
        if not name:
            return self._err("缺少 X-Filename 头")
        ext = Path(name).suffix.lower()
        if ext in REFUSE_EXTS:
            return self._err(REFUSE_EXTS[ext])
        if ext not in FORMAT_BYEXT_SAFE():
            return self._err(f"不支持的扩展名 {ext}")
        data = self._body()
        if not data:
            return self._err("空文件")
        fid = f"{len(s.files) + 1:03d}-{secrets.token_hex(3)}"
        dst = s.src_dir / f"{fid}{ext}"
        dst.write_bytes(data)
        s.files.append({"id": fid, "name": name, "path": str(dst), "size": len(data)})
        self._json({"ok": True, "id": fid, "name": name, "size": len(data)})

    def _api_pick(self):
        """从本机路径直接加入（本地工具，省去上传）。"""
        s = self._session()
        if not s:
            return self._err("会话不存在", 404)
        body = self._json_body()
        paths = body.get("paths") or []
        added, refused = [], []
        for raw in paths:
            p = Path(raw).expanduser()
            files: list[Path] = []
            if p.is_dir():
                files = sorted([f for f in (p.rglob("*") if body.get("recursive", True) else p.glob("*"))
                                if f.is_file() and f.suffix.lower() in FORMAT_BY_EXT])
            elif p.is_file():
                files = [p]
            for f in files:
                ext = f.suffix.lower()
                if ext in REFUSE_EXTS:
                    refused.append({"name": f.name, "why": REFUSE_EXTS[ext]})
                    continue
                fid = f"{len(s.files) + 1:03d}-{secrets.token_hex(3)}"
                dst = s.src_dir / f"{fid}{ext}"
                shutil.copy2(f, dst)
                s.files.append({"id": fid, "name": f.name, "path": str(dst),
                                "origin": str(f), "size": f.stat().st_size})
                added.append({"id": fid, "name": f.name, "size": f.stat().st_size})
        self._json({"ok": True, "added": added, "refused": refused})

    def _api_scan(self):
        s = self._session()
        if not s:
            return self._err("会话不存在", 404)
        body = self._json_body()
        if body.get("preset"):
            schema_dir = Path(body.get("schema_dir") or resources.schema_dir())
            cand = Path(body["preset"])
            if not cand.exists():
                cand = schema_dir / f"{body['preset']}.yaml"
            if cand.exists():
                s.preset = load_preset(cand)
                s.options = dict(s.preset.options or {})
                s.options.update(body.get("options") or {})
                s.engine = _new_engine(s)
                s.scans = {}
        with s.lock:
            s.engine = _new_engine(s)
            s.scans = {}
            errors = []
            for f in s.files:
                try:
                    s.scans[f["id"]] = s.engine.scan(Path(f["path"]))
                except Exception as e:
                    errors.append({"name": f["name"], "error": f"{type(e).__name__}: {e}"})
            s.engine.resolver.finalize()
        self._json({"ok": True, "errors": errors, **_scan_payload(s),
                    "stats": s.engine.resolver.stats(),
                    "mapping": s.engine.resolver.mapping_records()})

    def _api_redact(self):
        s = self._session()
        if not s:
            return self._err("会话不存在", 404)
        body = self._json_body()
        decisions = body.get("decisions") or {}
        passphrase = body.get("mapping_pass") or None
        with s.lock:
            results = []
            audits = []
            for f in s.files:
                sc = s.scans.get(f["id"])
                if sc is None:
                    results.append({"name": f["name"], "ok": False, "error": "未扫描"})
                    continue
                src = Path(f["path"])
                dst = s.out_dir / f"{Path(f['name']).stem}.脱敏{src.suffix}"
                d = decisions.get(f["id"]) or decisions.get(f["name"])
                try:
                    res = s.engine.redact(src, dst, decisions=d, scan=sc)
                except Exception as e:
                    results.append({"name": f["name"], "ok": False,
                                    "error": f"{type(e).__name__}: {e}",
                                    "tb": traceback.format_exc()})
                    continue
                aud = Auditor(s.engine.resolver, s.engine.options,
                            waivers=s.engine.waivers)
                rep = aud.audit(str(src), str(dst), res.fmt, scan=sc)
                paths = write_audit(rep, s.report_dir, dst.stem)
                audits.append(rep.to_dict())
                results.append({
                    "id": f["id"], "name": f["name"], "ok": True,
                    "out": dst.name, "out_path": str(dst),
                    "fmt": res.fmt, "replacements": res.replacements,
                    "warnings": res.warnings, "adapter": res.adapter_report,
                    "audit_passed": rep.passed, "audit_worst": rep.worst,
                    "audit_by_severity": rep.by_severity(),
                    "audit_checks": [c.to_dict() for c in rep.checks],
                    "audit_residues": [r.to_dict() for r in rep.residues],
                    "audit_warnings": rep.warnings,
                    "report": {k: Path(v).name for k, v in paths.items()},
                })
            s.results = results
            mapping_info = None
            if passphrase:
                mapping_info = write_mapping(s.engine.resolver.mapping_records(),
                                             s.out_dir / "脱敏对照表.enc.json",
                                             passphrase=passphrase, fmt="encrypted")
            else:
                mapping_info = write_mapping(s.engine.resolver.mapping_records(),
                                             s.report_dir / "脱敏对照表.json",
                                             fmt="json")
                mapping_info["note"] = ("明文对照表写在 report/ 下，不在交付目录里。"
                                        "它是还原钥匙，别跟产物一起发出去。")
            self._json({"ok": True, "results": results, "audits": audits,
                        "mapping": mapping_info,
                        "stats": s.engine.resolver.stats(),
                        "records": s.engine.resolver.mapping_records()})

    def _api_reset(self):
        s = self._session()
        if not s:
            return self._err("会话不存在", 404)
        with _LOCK:
            _SESSIONS.pop(s.sid, None)
        shutil.rmtree(s.workdir, ignore_errors=True)
        self._json({"ok": True})


def FORMAT_BYEXT_SAFE():
    return FORMAT_BY_EXT


def run_server(host: str = "127.0.0.1", port: int = 8765, preset: Preset | None = None,
               schema_dir: Path | None = None, workdir: Path | None = None) -> None:
    """阻塞式启动。"""
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
