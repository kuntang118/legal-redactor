"""构建法隐 LegalRedactor 的 Windows exe。

默认 **onefile**：交付就一个 exe，双击直接进复核界面。
代价要看清——onefile 每次启动把整个运行时解到 %TEMP% 下的 _MEIxxxxxx，
冷启动比 onedir 慢几秒，个别杀软对单文件包更敏感。
`--onedir` 保留：启动即用、便于排查、体积略小（不重复压缩）。

onedir 的 _internal 实测构成（决定体积的大头）：
    cv2.pyd 82MB · mupdfcpp64.dll 25MB · numpy openblas 20MB
    onnxruntime 28MB · OCR 模型 16MB · Cryptodome 8MB

    python build_exe.py            # onefile 单文件
    python build_exe.py --onedir   # 目录版 + 双击启动器
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"
ENTRY = ROOT / "fayin_main.py"     # 必须是根目录顶层脚本，不能指向包内的 cli.py

APP_NAME = "FaYin"
APP_DISPLAY = "法隐 LegalRedactor"
VERSION = "0.1.0"

# 这些包的数据文件不在 .py 里，PyInstaller 默认不会带：
#   rapidocr_onnxruntime —— 3 个 ONNX 模型 + config.yaml，缺了扫描件与图片全废
#   docx                 —— default.docx / default-comments.xml 模板
COLLECT_DATA = ["rapidocr_onnxruntime", "docx"]
COLLECT_ALL = ["onnxruntime"]          # 含 dll 与 pyd，binaries+datas 一起收
COLLECT_BINARIES = ["cv2", "pymupdf", "fitz"]

# pyzipper 的 AES 支持在 pyzipper/zipfile_aes.py 里 import Cryptodome.*，
# 而 pyzipper/__init__.py 是延迟导入它的 —— PyInstaller 静态分析看不到，
# 结果就是构建能过、exe 也能跑，直到你第一次加 --zip-pass 才 ModuleNotFoundError。
# 这种"只在某个分支炸"的缺失必须显式声明。
CRYPTODOME_HIDDEN = [
    "Cryptodome", "Cryptodome.Protocol.KDF", "Cryptodome.Cipher",
    "Cryptodome.Cipher.AES", "Cryptodome.Hash", "Cryptodome.Hash.HMAC",
    "Cryptodome.Hash.SHA1", "Cryptodome.Util", "Cryptodome.Util.Counter",
    "Cryptodome.Random",
]

HIDDEN_IMPORTS = [
    "pyzipper",                          # 加密交付包，运行时才 import
    "cryptography.hazmat.primitives.kdf.pbkdf2",
    "cryptography.hazmat.primitives.hashes",
    "cryptography.hazmat.primitives.ciphers",
    "cryptography.fernet",
    "PIL._tkinter_finder",
    "PIL.Image",
    "openpyxl",
    "openpyxl.comments",
    "lxml.etree",
    "lxml._elementpath",
    "yaml",
    "typer", "rich", "tabulate", "tqdm",
    "legal_redactor.resources",
    "legal_redactor.detect.pipeline",
    "legal_redactor.detect.vision_det",
    "legal_redactor.formats.pdf_fmt",
    "legal_redactor.formats.xlsx_fmt",
    "legal_redactor.formats.image_fmt",
    "legal_redactor.strategies.mapping",
]

# 用不到的大块头，明确排掉。scipy 115MB，本项目一行没用。
EXCLUDES = ["scipy", "matplotlib", "tkinter", "pandas", "IPython",
            "jupyter", "notebook", "sympy", "torch", "transformers",
            "PyQt5", "PySide6", "pytest"]

VERSION_INFO = f'''# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({VERSION.replace(".", ", ")},0),
    prodvers=({VERSION.replace(".", ", ")},0),
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1,
    subtype=0x0, date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable("080404b0", [
        StringStruct("CompanyName", "法隐 LegalRedactor"),
        StringStruct("FileDescription", "{APP_DISPLAY} - 中文法律文书本地脱敏工具"),
        StringStruct("FileVersion", "{VERSION}"),
        StringStruct("InternalName", "{APP_NAME}"),
        StringStruct("LegalCopyright", "本地工具，无远程调用"),
        StringStruct("OriginalFilename", "{APP_NAME}.exe"),
        StringStruct("ProductName", "{APP_DISPLAY}"),
        StringStruct("ProductVersion", "{VERSION}"),
        StringStruct("Comments", "纯本地运行：规则+词典+OpenCV+RapidOCR，不联网、不吃 GPU"),
      ])
    ]),
    VarFileInfo([VarStruct("Translation", [2052, 1200])])
  ]
)
'''


def run(args: list[str]) -> None:
    print(">", " ".join(str(a) for a in args)[:400])
    subprocess.run([str(a) for a in args], cwd=ROOT, check=True)


def _find_cjk_font():
    """找一个能渲染中文的字体画图标。找不到返回 None，调用方会退回默认字体。"""
    cands = ["simhei.ttf", "msyh.ttc", "simsun.ttc", "simfang.ttf", "simkai.ttf",
             "Deng.ttf", "NotoSansCJK-Regular.ttc", "wqy-microhei.ttc"]
    dirs = [Path("C:/Windows/Fonts"), Path("/usr/share/fonts"), Path("/System/Library/Fonts")]
    for d in dirs:
        if not d.is_dir():
            continue
        for c in cands:
            f = d / c
            if f.exists():
                return str(f)
    return None


def make_icon(out: Path) -> bool:
    """画一个图标：深色盾形 + 白"法"字。没有现成 ico，用 PIL 生成多尺寸。"""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except Exception as e:
        print(f"  跳过图标（PIL 不可用：{e}）")
        return False
    font_path = _find_cjk_font()
    sizes = [16, 24, 32, 48, 64, 128, 256]
    imgs = []
    for s in sizes:
        im = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        d = ImageDraw.Draw(im)
        pad = max(1, s // 16)
        # 盾形：上圆角矩形 + 下方三角收尖
        top = pad
        bot = s - pad
        mid = s // 2
        d.rounded_rectangle([pad, top, s - pad, int(bot * 0.62)],
                            radius=max(1, s // 8), fill=(31, 45, 74, 255))
        d.polygon([(pad, int(bot * 0.58)), (s - pad, int(bot * 0.58)), (mid, bot)],
                  fill=(31, 45, 74, 255))
        # 顶部一道浅色，做出层次
        d.rounded_rectangle([pad, top, s - pad, top + max(1, s // 14)],
                            radius=max(1, s // 10), fill=(58, 84, 138, 255))
        try:
            f = ImageFont.truetype(font_path, int(s * 0.52))
        except Exception:
            f = ImageFont.load_default()
        d.text((mid, int(s * 0.50)), "法", font=f, fill=(255, 255, 255, 255), anchor="mm")
        imgs.append(im)
    out.parent.mkdir(parents=True, exist_ok=True)
    imgs[-1].save(out, format="ICO", sizes=[(s, s) for s in sizes],
                  append_images=imgs[:-1])
    print(f"  图标 → {out} ({out.stat().st_size} 字节)")
    return out.exists()


def write_version_file(out: Path) -> Path:
    out.write_text(VERSION_INFO, encoding="utf-8")
    return out


def build(onefile: bool) -> Path:
    DIST.mkdir(parents=True, exist_ok=True)
    BUILD.mkdir(parents=True, exist_ok=True)

    icon = ROOT / "assets" / "fayin.ico"
    make_icon(icon)
    vfile = write_version_file(BUILD / "version_info.txt")

    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--onefile" if onefile else "--onedir",
        "--console",
        "--name", APP_NAME,
        "--version-file", str(vfile),
        # 项目自带的资源
        "--add-data", f"{ROOT / 'schemas'};schemas",
        "--add-data", f"{ROOT / 'web'};web",
        "--add-data", f"{ROOT / 'README.md'};.",
        "--add-data", f"{ROOT / 'docs'};docs",
    ]
    if icon.exists():
        args += ["--icon", str(icon)]
    for pkg in COLLECT_DATA:
        args += ["--collect-data", pkg]
    for pkg in COLLECT_ALL:
        args += ["--collect-all", pkg]
    for pkg in COLLECT_BINARIES + ["Cryptodome"]:
        args += ["--collect-binaries", pkg]
    for h in HIDDEN_IMPORTS + CRYPTODOME_HIDDEN:
        args += ["--hidden-import", h]
    for e in EXCLUDES:
        args += ["--exclude-module", e]
    # 中间产物全部落 G 盘，不污染 C 盘
    args += [
        "--distpath", str(DIST),
        "--workpath", str(BUILD / ("work-onefile" if onefile else "work-onedir")),
        "--specpath", str(BUILD),
        str(ENTRY),
    ]
    run(args)

    out = (DIST / f"{APP_NAME}.exe") if onefile else (DIST / APP_NAME / f"{APP_NAME}.exe")
    if not out.exists():
        raise SystemExit(f"构建失败：{out} 不存在")
    return out


def add_launchers(app_dir: Path) -> None:
    """放几个双击即用的 .bat，省得记命令行。"""
    bats = {
        "启动复核台.bat": '@echo off\r\nchcp 65001 >nul\r\ncd /d "%~dp0"\r\n'
                          f'{APP_NAME}.exe serve --port 8765\r\npause\r\n',
        "依赖与资源自检.bat": '@echo off\r\nchcp 65001 >nul\r\ncd /d "%~dp0"\r\n'
                              f'{APP_NAME}.exe doctor\r\npause\r\n',
        "把文件拖到这里脱敏.bat": '@echo off\r\nchcp 65001 >nul\r\ncd /d "%~dp0"\r\n'
                                  'if "%~1"=="" (echo 请把要脱敏的文件拖到本 bat 图标上)&pause&exit /b\r\n'
                                  f'{APP_NAME}.exe redact %* -o "脱敏产物" --preset legal\r\npause\r\n',
    }
    for name, content in bats.items():
        (app_dir / name).write_bytes(content.encode("utf-8"))
    # 预设在 exe 同级也放一份，用户可自己改，不必重新打包
    ext = app_dir / "schemas"
    ext.mkdir(exist_ok=True)
    for f in (ROOT / "schemas").glob("*.y*ml"):
        shutil.copy2(f, ext / f.name)
    shutil.copy2(ROOT / "README.md", app_dir / "README.md")


def make_zip(app_dir: Path) -> Path:
    zpath = DIST / f"{APP_NAME}-{VERSION}-win64.zip"
    zpath.unlink(missing_ok=True)
    n = 0
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for f in sorted(app_dir.rglob("*")):
            if f.is_file():
                z.write(f, f.relative_to(app_dir.parent))
                n += 1
    return zpath


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--onedir", action="store_true", help="打目录版（启动快，带双击启动器）")
    ap.add_argument("--no-zip", action="store_true")
    a = ap.parse_args()
    onefile = not a.onedir

    t0 = time.time()
    exe = build(onefile)
    app_dir = exe.parent if not onefile else DIST

    print(f"\n构建完成，用时 {time.time() - t0:.0f}s")
    print(f"  exe     : {exe}  ({exe.stat().st_size / 1048576:.1f} MB)")
    if not onefile:
        add_launchers(exe.parent)
        total = sum(f.stat().st_size for f in exe.parent.rglob("*") if f.is_file())
        print(f"  目录总计: {total / 1048576:.1f} MB")
        print(f"  启动器  : 双击 exe 或 {APP_NAME}.exe serve 均进复核界面")
    else:
        print(f"  形态    : 单文件，双击直接进复核界面；带参数即命令行")
        print(f"  提醒    : 每次启动会解运行时到 %TEMP%\\_MEIxxxxxx，冷启动慢几秒")

    if not a.no_zip:
        src = exe if onefile else None
        zpath = DIST / f"{APP_NAME}-{VERSION}-win64.zip"
        zpath.unlink(missing_ok=True)
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            if onefile:
                z.write(exe, exe.name)
                for extra in ("README.md",):
                    p = ROOT / extra
                    if p.exists():
                        z.write(p, extra)
            else:
                for f in sorted(exe.parent.rglob("*")):
                    if f.is_file():
                        z.write(f, f.relative_to(exe.parent.parent))
        print(f"  便携包  : {zpath}  ({zpath.stat().st_size / 1048576:.1f} MB)")
        print(f"  SHA256  : {sha256(zpath)}")
    print(f"  SHA256(exe): {sha256(exe)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
