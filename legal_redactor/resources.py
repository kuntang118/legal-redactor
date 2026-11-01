"""资源路径解析：源码态与 PyInstaller 冻结态行为一致。

打包后 `Path(__file__).parents[1]` 不再是项目根——源码树根本不存在，
`schemas/*.yaml` 与 `web/index.html` 会全部找不到。所有路径都必须走这里。

三种布局：
  源码态     项目根 = 本文件的 parents[1]
  onedir     只读资源在 <exe目录>/_internal/，即 sys._MEIPASS
  onefile    只读资源在每次启动解出来的临时目录，即 sys._MEIPASS

可写目录（会话临时文件、默认产物）永远不放只读资源区：
onedir/onefile 下放 exe 同级，源码态放项目 out/。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def is_frozen() -> bool:
    """是否运行在 PyInstaller 打包后的 exe 里。"""
    return bool(getattr(sys, "frozen", False))


def bundle_dir() -> Path:
    """只读资源根目录。"""
    if is_frozen():
        p = getattr(sys, "_MEIPASS", None)
        if p:
            return Path(p)
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


def exe_dir() -> Path:
    """exe 所在目录（冻结态）或项目根（源码态）。用户可见、可写。"""
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


def schema_dir() -> Path:
    """预设目录。

    冻结态下优先用 exe 同级的 `schemas/`——这样用户能自己加预设、
    改动作表，不必重新打包。找不到才回落到打进包里的内置预设。
    """
    if is_frozen():
        user = exe_dir() / "schemas"
        if user.is_dir() and any(user.glob("*.y*ml")):
            return user
    d = bundle_dir() / "schemas"
    if d.is_dir():
        return d
    # 兜底：源码态但被当模块装进了 site-packages
    return exe_dir() / "schemas"


def web_dir() -> Path:
    """复核界面静态资源目录。"""
    return bundle_dir() / "web"


def data_dir(sub: str = "") -> Path:
    """可写工作目录（会话临时文件、默认产物）。"""
    base = exe_dir() / "work" if is_frozen() else exe_dir() / "out"
    d = base / sub if sub else base
    d.mkdir(parents=True, exist_ok=True)
    return d


def describe() -> dict:
    """给 doctor 命令用：把实际解析到的路径打出来，打包出问题一眼能看出来。"""
    return {
        "frozen": is_frozen(),
        "mode": ("onedir/onefile" if is_frozen() else "source"),
        "executable": str(Path(sys.executable).resolve()),
        "bundle_dir": str(bundle_dir()),
        "exe_dir": str(exe_dir()),
        "schema_dir": str(schema_dir()),
        "schemas_found": sorted(p.name for p in schema_dir().glob("*.y*ml"))
        if schema_dir().is_dir() else [],
        "web_index": str(web_dir() / "index.html"),
        "web_index_exists": (web_dir() / "index.html").exists(),
        "data_dir": str(data_dir()),
        "env_tmp": os.environ.get("TMP") or os.environ.get("TEMP") or "",
    }
