"""PyInstaller 入口脚本。

必须是**项目根下的顶层脚本**，不能直接指向 legal_redactor/cli.py：
包内模块被当顶层脚本执行时没有父包上下文，`from .core import ...`
会直接 ImportError: attempted relative import with no known parent package。
PyInstaller 的 "Build complete!" 不会报这个错，只有真跑 exe 才暴露。
"""
from __future__ import annotations

import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

# 源码态直接跑本文件时，保证能 import 到同目录的包
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))


def ensure_console_utf8() -> None:
    """把控制台码页切到 UTF-8，并给 stdio 加编码兜底。

    冻结态下 cmd/PowerShell 的控制台码页是 936(GBK)。rich 在 legacy Windows
    渲染路径上会用该码页编码输出，遇到 ✓ ✗ ✅ ┌ 这类字符直接
    UnicodeEncodeError 把整条命令炸掉——打包后第一次跑 doctor 就是这个崩的。
    errors="replace" 是第二道保险：任何编码问题最多显示成 ?，不能崩。
    """
    if sys.platform == "win32":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            k32.SetConsoleOutputCP(65001)
            k32.SetConsoleCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def launch_gui(argv: list[str]) -> int:
    """双击 exe（无任何参数）时直接进复核界面。

    只监听 127.0.0.1：这是处理敏感卷宗的本地工具，绝不开到局域网。
    """
    ensure_console_utf8()
    from legal_redactor import resources
    from legal_redactor.core import load_preset
    from legal_redactor.server import run_server

    # 找一个没被占用的端口，重复双击不会撞车
    port = 8765
    for cand in range(8765, 8785):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if s.connect_ex(("127.0.0.1", cand)) != 0:
                port = cand
                break

    try:
        preset = load_preset(resources.schema_dir() / "legal.yaml")
    except Exception as e:
        print(f"无法加载预设 legal.yaml：{e}")
        return 1

    url = f"http://127.0.0.1:{port}/"
    print("=" * 58)
    print("  法隐 · 法律文书脱敏复核台")
    print(f"  地址：{url}")
    print(f"  预设：{preset.label}")
    print(f"  工作目录：{resources.data_dir('web')}")
    print("  关闭：直接关掉本窗口")
    print("=" * 58)

    def opener() -> None:
        time.sleep(1.2)
        try:
            webbrowser.open(url)
        except Exception:
            print(f"浏览器没自动打开，请手动访问 {url}")

    threading.Thread(target=opener, daemon=True).start()
    try:
        run_server(host="127.0.0.1", port=port, preset=preset,
                   schema_dir=resources.schema_dir(),
                   workdir=resources.data_dir("web"))
    except KeyboardInterrupt:
        print("\n已停止")
    return 0


def run(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return launch_gui(argv)

    ensure_console_utf8()
    from legal_redactor.cli import main
    sys.argv = [sys.argv[0]] + argv
    try:
        main()
    except SystemExit as e:
        return int(e.code or 0)
    except KeyboardInterrupt:
        print("\n已中断")
        return 130
    except Exception as e:
        # 打包后没有 traceback 可看，异常必须落到文件，否则用户只见到一闪而过的窗口
        import traceback
        tb = traceback.format_exc()
        sys.stderr.write(tb + "\n")
        try:
            from legal_redactor import resources
            log = resources.exe_dir() / "crash.log"
            with open(log, "a", encoding="utf-8") as f:
                f.write(tb + "\n" + "=" * 60 + "\n")
            sys.stderr.write(f"错误详情已追加到 {log}\n")
        except Exception:
            pass
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
