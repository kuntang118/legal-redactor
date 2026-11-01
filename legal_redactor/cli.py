"""法隐 LegalRedactor CLI。

    python -m legal_redactor scan   文件...
    python -m legal_redactor redact 文件... -o 输出目录
    python -m legal_redactor batch  目录 -o 输出目录
    python -m legal_redactor audit  原文件 产物
    python -m legal_redactor serve
    python -m legal_redactor schema list
"""
from __future__ import annotations

import json
import shutil
import sys
import zipfile
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .core import (ENTITY_TYPES, Preset, Strategy, dump_registry, entity_label,
                   group_types, load_preset)

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="中文法律文书本地脱敏工具（纯本地、零成本、真删除 + 残留自检）")
console = Console()
err_console = Console(stderr=True, style="bold red")

from . import resources

ROOT = resources.bundle_dir()
# 打包后源码树不存在，schemas/ 与 web/ 必须走 resources 解析
DEFAULT_SCHEMA_DIR = resources.schema_dir()

SEV_STYLE = {"critical": "bold white on red", "high": "bold red", "medium": "yellow",
             "low": "dim", "info": "dim cyan", "none": "green"}


# --------------------------------------------------------------------------
# 公共辅助
# --------------------------------------------------------------------------


def _resolve_preset(preset: str, schema_dir: Optional[Path]) -> Preset:
    d = Path(schema_dir) if schema_dir else DEFAULT_SCHEMA_DIR
    p = Path(preset)
    if p.exists() and p.suffix in (".yaml", ".yml"):
        return load_preset(p)
    cand = d / f"{preset}.yaml"
    if cand.exists():
        return load_preset(cand)
    cand2 = d / f"{preset}.yml"
    if cand2.exists():
        return load_preset(cand2)
    avail = sorted(x.stem for x in d.glob("*.y*ml")) if d.exists() else []
    raise typer.BadParameter(f"找不到预设 '{preset}'；可用：{avail}")


def _build_options(preset: Preset, opt) -> dict:
    options = dict(preset.options or {})
    for kv in (opt or ()):
        if "=" not in kv:
            raise typer.BadParameter(f"--opt 需要 key=value 形式，收到 '{kv}'")
        k, v = kv.split("=", 1)
        k = k.strip()
        vl: object = v.strip()
        if vl.lower() in ("true", "yes", "on", "1"):
            vl = True
        elif vl.lower() in ("false", "no", "off", "0"):
            vl = False
        else:
            try:
                vl = int(vl)
            except ValueError:
                try:
                    vl = float(vl)
                except ValueError:
                    pass
        options[k] = vl
    return options


def _out_name(src: Path, outdir: Path, suffix: str = ".脱敏") -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir / f"{src.stem}{suffix}{src.suffix}"


def _print_audit(rep, verbose: bool = False) -> None:
    t = Table(title="残留自检", show_lines=False, expand=True)
    t.add_column("检查", style="bold")
    t.add_column("结果", justify="center")
    t.add_column("说明")
    for c in rep.checks:
        t.add_row(c.name, "[green]✓ 通过[/]" if c.passed else "[red]✗ 不通过[/]", c.detail)
    console.print(t)

    if rep.residues:
        from .audit import SEV_ORDER
        real = [r for r in rep.residues if r.severity != "waived"]
        waived = [r for r in rep.residues if r.severity == "waived"]
        if real:
            rt = Table(title=f"残留明细 · 工具未处理（{len(real)} 条）", expand=True)
            rt.add_column("严重级")
            rt.add_column("种类")
            rt.add_column("类型")
            rt.add_column("原值")
            rt.add_column("命中")
            rt.add_column("位置")
            for r in sorted(real, key=lambda x: -SEV_ORDER.get(x.severity, 0)):
                if not verbose and r.severity in ("low", "info"):
                    continue
                rt.add_row(f"[{SEV_STYLE.get(r.severity, 'dim')}]{r.severity}[/]",
                           r.kind, r.etype, r.original[:28], r.found[:28], r.part[:40])
            console.print(rt)
        else:
            console.print("[green]工具未处理的残留：0[/]")
        if waived:
            wt = Table(title=f"人工放行清单（{len(waived)} 条）", expand=True)
            wt.add_column("类型")
            wt.add_column("原值")
            wt.add_column("位置")
            for r in waived:
                wt.add_row(r.etype, r.original[:36], r.part[:40])
            console.print(wt)
            console.print("[yellow]这些是复核时明确标记「忽略」的，工具按指示没脱敏。"
                          "不算工具失误，但交付前请逐条确认有依据。[/]")
    else:
        console.print("[green]未发现残留。[/]")

    for w in rep.warnings:
        console.print(f"[yellow]⚠ {w}[/]")

    verdict = "[bold green]✅ 通过[/]" if rep.passed else "[bold red]❌ 不通过[/]"
    console.print(f"\n结论：{verdict}　最高严重级：{rep.worst}")


# --------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------


@app.command()
def scan(
    files: List[Path] = typer.Argument(..., exists=True, readable=True, help="待扫描文件"),
    preset: str = typer.Option("legal", "--preset", "-p", help="预设名或 YAML 路径"),
    schema_dir: Optional[Path] = typer.Option(None, "--schema-dir", help="预设目录"),
    opt: List[str] = typer.Option(None, "--opt", "-O", help="覆盖选项 key=value，可多次"),
    show_all: bool = typer.Option(False, "--all", help="显示全部检出项而非按类型汇总"),
    out_json: Optional[Path] = typer.Option(None, "--json", help="把检出结果写成 JSON"),
):
    """只检测不改动，用来评估一份文件里有多少敏感信息。"""
    from .engine import Engine

    p = _resolve_preset(preset, schema_dir)
    eng = Engine(p, options=_build_options(p, opt))

    payload = []
    for f in files:
        console.rule(f"[bold]{f.name}[/]")
        try:
            sc = eng.scan(f)
        except Exception as e:
            err_console.print(f"✗ {f.name}: {type(e).__name__}: {e}")
            continue
        by_type: dict[str, list] = {}
        for s in sc.all_spans:
            by_type.setdefault(s.etype, []).append(s)

        t = Table(expand=True)
        t.add_column("类型")
        t.add_column("数量", justify="right")
        t.add_column("值（前 6 个）")
        for et in sorted(by_type, key=lambda k: -len(by_type[k])):
            items = by_type[et]
            vals = "、".join(dict.fromkeys(s.text for s in items))
            shown = "、".join(list(dict.fromkeys(s.text for s in items))[:6])
            t.add_row(f"{entity_label(et)}\n[dim]{et}[/]", str(len(items)),
                      shown if not show_all else vals)
        console.print(t)

        if sc.all_boxes:
            bt = Table(title="视觉检出", expand=True)
            bt.add_column("类型")
            bt.add_column("页/图")
            bt.add_column("位置")
            bt.add_column("置信")
            bt.add_column("依据")
            for b in sc.all_boxes:
                bt.add_row(entity_label(b.etype), str(b.page),
                           f"({b.x:.0f},{b.y:.0f}) {b.w:.0f}×{b.h:.0f}",
                           f"{b.confidence:.2f}", b.reason[:60])
            console.print(bt)

        for w in sc.warnings:
            console.print(f"[yellow]⚠ {w}[/]")

        payload.append({
            "file": str(f), "fmt": sc.fmt,
            "spans": [s.to_dict() for s in sc.all_spans],
            "boxes": [b.to_dict() for b in sc.all_boxes],
            "warnings": sc.warnings,
        })

    st = eng.resolver.stats()
    console.print(f"\n[bold]合计[/]：唯一实体 {st['unique_entities']} 个，"
                  f"出现 {st['total_occurrences']} 次，其中 {st['escalated']} 个被强制升级")
    for k, v in st["by_type"].items():
        console.print(f"  {entity_label(k):<14} {v}")

    if out_json:
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"\n[dim]检出明细已写入 {out_json}[/]")


# --------------------------------------------------------------------------
# redact
# --------------------------------------------------------------------------


@app.command()
def redact(
    files: List[Path] = typer.Argument(..., exists=True, readable=True, help="待脱敏文件"),
    outdir: Path = typer.Option(Path("out"), "--outdir", "-o", help="产物目录"),
    preset: str = typer.Option("legal", "--preset", "-p", help="预设名或 YAML 路径"),
    schema_dir: Optional[Path] = typer.Option(None, "--schema-dir", help="预设目录"),
    opt: List[str] = typer.Option(None, "--opt", "-O", help="覆盖选项 key=value"),
    seed: str = typer.Option("", "--seed", help="假名/编号种子；同一种子跨批次结果一致"),
    passphrase: Optional[str] = typer.Option(None, "--mapping-pass",
                                             help="对照表口令；给了就加密导出"),
    mapping_out: Optional[Path] = typer.Option(None, "--mapping-out",
                                               help="对照表输出路径"),
    insecure_mapping: bool = typer.Option(False, "--insecure-mapping",
                                          help="允许明文导出对照表（不建议）"),
    no_audit: bool = typer.Option(False, "--no-audit", help="跳过残留自检"),
    zip_pass: Optional[str] = typer.Option(None, "--zip-pass",
                                           help="把产物打成带口令的 zip（pyzipper）"),
    zip_reports: bool = typer.Option(False, "--zip-reports",
                                     help="把审计报告也放进交付包。默认不放：报告在有残留时"
                                          "会列出原始敏感值，属于内部质检件而非交付件"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="显示低级别残留"),
):
    """脱敏并做残留自检。跨文件保证同一实体替换一致。"""
    from .audit import Auditor, write_audit
    from .engine import Engine
    from .strategies.mapping import write_mapping

    p = _resolve_preset(preset, schema_dir)
    options = _build_options(p, opt)
    eng = Engine(p, options=options, seed=seed.encode("utf-8") if seed else b"")

    items = [(f, _out_name(f, outdir)) for f in files]
    results = eng.redact_batch(items, progress=lambda stage, src: None)

    all_ok = True
    audit_paths: list[Path] = []
    for res in results:
        console.rule(f"[bold]{Path(res.path).name}[/]")
        if res.warnings:
            for w in res.warnings:
                console.print(f"[yellow]⚠ {w}[/]")
        if not Path(res.out_path).exists():
            err_console.print(f"✗ 未产出文件")
            all_ok = False
            continue
        console.print(f"替换 {res.replacements} 处 → [cyan]{res.out_path}[/]")
        if no_audit:
            continue
        from .formats.pdf_fmt import pymupdf_available
        aud = Auditor(eng.resolver, eng.options, waivers=eng.waivers)
        rep = aud.audit(res.path, res.out_path, res.fmt, scan=res.scan)
        _print_audit(rep, verbose=verbose)
        paths = write_audit(rep, outdir / "audit", Path(res.out_path).stem)
        audit_paths.extend(Path(v) for v in paths.values())
        console.print(f"[dim]审计报告：{paths['html']}[/]")
        all_ok = all_ok and rep.passed

    # 对照表。文件名必须体现是否加密：一个叫 .json 的文件躺在交付目录里，
    # 没人会去确认它到底是明文还是密文。
    records = eng.resolver.mapping_records()
    mpath = mapping_out or (outdir / ("脱敏对照表.enc.json" if passphrase
                                      else "脱敏对照表.json"))
    if passphrase:
        info = write_mapping(records, mpath, passphrase=passphrase, fmt="encrypted")
        console.print(f"\n[green]对照表已加密[/] → {info['path']}（{info['records']} 条，"
                      f"PBKDF2-SHA256 39万次 + Fernet）")
    elif insecure_mapping:
        info = write_mapping(records, mpath, fmt="json")
        console.print(f"\n[yellow]对照表以明文写出[/] → {info['path']}（{info['records']} 条）"
                      f"　这份表等于还原钥匙，请与产物分开保管")
    else:
        console.print("\n[yellow]未导出对照表[/]：加 --mapping-pass 口令导出加密版，"
                      "或 --insecure-mapping 明文导出（不建议）")

    # 加密打包
    if zip_pass:
        _zip_secure(outdir, zip_pass, audit_paths, results, include_reports=zip_reports)

    st = eng.resolver.stats()
    console.print(f"\n[bold]批次统计[/]：唯一实体 {st['unique_entities']}，"
                  f"出现 {st['total_occurrences']} 次，强制升级 {st['escalated']} 个")
    if not all_ok:
        raise typer.Exit(code=2)


def _zip_secure(outdir: Path, passphrase: str, audit_paths: list[Path], results,
                include_reports: bool = False) -> None:
    try:
        import pyzipper
    except Exception:
        err_console.print("未安装 pyzipper，无法生成加密 zip")
        return
    zpath = outdir / "脱敏交付包.zip"
    members: set[Path] = {Path(r.out_path) for r in results if Path(r.out_path).exists()}
    if include_reports:
        members.update(p for p in audit_paths if p.exists())
    with pyzipper.AESZipFile(zpath, "w", compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(passphrase.encode("utf-8"))
        for m in sorted(members):
            zf.write(m, arcname=m.name)
    console.print(f"[green]加密交付包[/] → {zpath}（{len(members)} 个文件，AES-256）")
    if not include_reports:
        console.print("[dim]交付包只含脱敏产物，不含审计报告"
                      "（报告在有残留时会列出原始敏感值，属内部质检件）。"
                      "需要一起打包加 --zip-reports[/]")


# --------------------------------------------------------------------------
# batch
# --------------------------------------------------------------------------


@app.command()
def batch(
    src_dir: Path = typer.Argument(..., exists=True, file_okay=False, help="输入目录"),
    outdir: Path = typer.Option(Path("out/batch"), "--outdir", "-o"),
    preset: str = typer.Option("legal", "--preset", "-p"),
    schema_dir: Optional[Path] = typer.Option(None, "--schema-dir"),
    opt: List[str] = typer.Option(None, "--opt", "-O"),
    recursive: bool = typer.Option(True, "--recursive/--no-recursive"),
    seed: str = typer.Option("", "--seed"),
    passphrase: Optional[str] = typer.Option(None, "--mapping-pass"),
    zip_pass: Optional[str] = typer.Option(None, "--zip-pass"),
    skip_refused: bool = typer.Option(True, "--skip-refused/--fail-refused",
                                        help="遇到 .doc/.xls 等不支持格式时跳过而非报错"),
):
    """整目录批量脱敏，跨文件一致化。"""
    from .audit import Auditor, write_audit
    from .engine import Engine, FORMAT_BY_EXT, REFUSE_EXTS, detect_format
    from .strategies.mapping import write_mapping

    p = _resolve_preset(preset, schema_dir)
    eng = Engine(p, options=_build_options(p, opt),
                 seed=seed.encode("utf-8") if seed else b"")

    globber = src_dir.rglob("*") if recursive else src_dir.glob("*")
    items, skipped = [], []
    for f in sorted(globber):
        if not f.is_file():
            continue
        ext = f.suffix.lower()
        if ext in REFUSE_EXTS:
            skipped.append((f, REFUSE_EXTS[ext]))
            if not skip_refused:
                err_console.print(f"✗ {f.name}: {REFUSE_EXTS[ext]}")
                raise typer.Exit(2)
            continue
        if ext not in FORMAT_BY_EXT:
            skipped.append((f, f"未支持的扩展名 {ext}"))
            continue
        rel = f.relative_to(src_dir)
        items.append((f, outdir / rel.parent / f"{f.stem}.脱敏{f.suffix}"))

    if not items:
        err_console.print("目录里没有可处理的文件")
        raise typer.Exit(1)

    console.print(f"[bold]待处理 {len(items)} 个文件[/]，跳过 {len(skipped)} 个")
    for f, why in skipped:
        console.print(f"  [dim]- {f.name}：{why}[/]")

    done = {"n": 0}

    def progress(stage: str, src: str) -> None:
        if stage == "redact":
            done["n"] += 1
            console.print(f"  [{done['n']}/{len(items)}] {Path(src).name}")

    results = eng.redact_batch(items, progress=progress)

    all_ok = True
    audit_paths: list[Path] = []
    for res in results:
        if not Path(res.out_path).exists():
            err_console.print(f"✗ {Path(res.path).name}: 未产出")
            all_ok = False
            continue
        aud = Auditor(eng.resolver, eng.options, waivers=eng.waivers)
        rep = aud.audit(res.path, res.out_path, res.fmt, scan=res.scan)
        mark = "[green]PASS[/]" if rep.passed else "[red]FAIL[/]"
        console.print(f"  {mark} {Path(res.out_path).name}　替换{res.replacements}处　"
                      f"残留{len(rep.residues)}条（{rep.worst}）")
        paths = write_audit(rep, outdir / "audit", Path(res.out_path).stem)
        audit_paths.extend(Path(v) for v in paths.values())
        all_ok = all_ok and rep.passed

    records = eng.resolver.mapping_records()
    if passphrase:
        info = write_mapping(records, outdir / "脱敏对照表.enc.json",
                             passphrase=passphrase, fmt="encrypted")
        console.print(f"[green]对照表已加密[/] → {info['path']}（{info['records']} 条）")
    else:
        console.print("[yellow]未导出对照表（加 --mapping-pass 可加密导出）[/]")

    if zip_pass:
        _zip_secure(outdir, zip_pass, audit_paths, results)

    console.print(f"\n[bold]完成[/]：{len(results)} 个文件，"
                  f"{'全部通过自检' if all_ok else '有文件未通过自检'}")
    if not all_ok:
        raise typer.Exit(code=2)


# --------------------------------------------------------------------------
# audit
# --------------------------------------------------------------------------


@app.command()
def audit(
    src: Path = typer.Argument(..., exists=True, help="原文件"),
    dst: Path = typer.Argument(..., exists=True, help="脱敏产物"),
    fmt: Optional[str] = typer.Option(None, "--fmt", help="docx|pdf|text|xlsx|image，默认按扩展名"),
    preset: str = typer.Option("legal", "--preset", "-p"),
    schema_dir: Optional[Path] = typer.Option(None, "--schema-dir"),
    opt: List[str] = typer.Option(None, "--opt", "-O"),
    outdir: Optional[Path] = typer.Option(None, "--report-dir", help="审计报告输出目录"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """对一对"原文件 / 产物"做残留自检。

    注意：独立运行时会重新检测原文件来重建对照表，
    如果产物是用人工复核决策生成的，结果可能与当时不完全一致。
    """
    from .audit import Auditor, write_audit
    from .engine import Engine, detect_format

    p = _resolve_preset(preset, schema_dir)
    eng = Engine(p, options=_build_options(p, opt))
    f = fmt or detect_format(src)
    sc = eng.scan(src)
    eng.redact(src, Path(str(dst) + ".tmp-audit-probe"), scan=sc) if False else None
    eng.resolver.finalize()

    aud = Auditor(eng.resolver, eng.options, waivers=eng.waivers)
    rep = aud.audit(src, dst, f, scan=sc)
    _print_audit(rep, verbose=verbose)
    if outdir:
        paths = write_audit(rep, outdir, dst.stem)
        console.print(f"\n[dim]报告：{paths['md']} / {paths['html']} / {paths['json']}[/]")
    if not rep.passed:
        raise typer.Exit(code=2)


# --------------------------------------------------------------------------
# schema
# --------------------------------------------------------------------------


@app.command()
def schema(
    action: str = typer.Argument("list", help="list | show <预设> | types | export <路径>"),
    arg: Optional[str] = typer.Argument(None),
    schema_dir: Optional[Path] = typer.Option(None, "--schema-dir"),
):
    """查看实体类型注册表与行业预设。"""
    d = Path(schema_dir) if schema_dir else DEFAULT_SCHEMA_DIR
    if action == "list":
        t = Table(title=f"可用预设（{d}）")
        t.add_column("ID")
        t.add_column("名称")
        t.add_column("脱敏项数")
        t.add_column("说明")
        for f in sorted(d.glob("*.y*ml")):
            try:
                pr = load_preset(f)
            except Exception as e:
                t.add_row(f.stem, f"[red]解析失败：{e}[/]", "-", "")
                continue
            n = sum(1 for k in ENTITY_TYPES if pr.is_redacted(k))
            t.add_row(pr.id, pr.label, str(n), (pr.description or "").strip()[:60])
        console.print(t)
    elif action == "types":
        g = group_types()
        for grp, label in (("strong", "强标识符（正则+校验位）"),
                           ("weak", "弱标识符/准标识符（需上下文）"),
                           ("visual", "视觉实体"),
                           ("discretion", "自由裁量")):
            t = Table(title=label)
            t.add_column("ID")
            t.add_column("名称")
            t.add_column("默认策略")
            t.add_column("说明")
            for e in g.get(grp, []):
                t.add_row(e.id, e.label, e.default_strategy.value, e.hint)
            console.print(t)
    elif action == "show":
        if not arg:
            raise typer.BadParameter("show 需要预设名")
        pr = _resolve_preset(arg, schema_dir)
        t = Table(title=f"{pr.label}（{pr.id}）")
        t.add_column("实体类型")
        t.add_column("策略")
        t.add_column("会脱敏")
        for k in ENTITY_TYPES:
            s = pr.strategy_for(k)
            t.add_row(f"{entity_label(k)} ({k})", s.value,
                      "[green]是[/]" if pr.is_redacted(k) else "[dim]否[/]")
        console.print(t)
        ot = Table(title="选项")
        ot.add_column("key")
        ot.add_column("value")
        for k, v in (pr.options or {}).items():
            ot.add_row(k, str(v))
        console.print(ot)
    elif action == "export":
        out = Path(arg or "entity_registry.json")
        dump_registry(out)
        console.print(f"已导出实体注册表 → {out}")
    else:
        raise typer.BadParameter(f"未知动作 '{action}'")


# --------------------------------------------------------------------------
# mapping
# --------------------------------------------------------------------------


@app.command()
def mapping(
    path: Path = typer.Argument(..., exists=True, help="加密对照表"),
    passphrase: str = typer.Option(..., "--pass", prompt=True, hide_input=True,
                                   confirmation_prompt=True, help="口令"),
    out: Optional[Path] = typer.Option(None, "--out", help="解密后写到这个文件（默认打印）"),
):
    """解密查看对照表。"""
    from .strategies.mapping import decrypt_mapping

    try:
        records = decrypt_mapping(path.read_text(encoding="utf-8"), passphrase)
    except Exception as e:
        err_console.print(f"✗ 解密失败：{e}")
        raise typer.Exit(1)
    t = Table(title=f"对照表（{len(records)} 条）")
    t.add_column("类型")
    t.add_column("原文")
    t.add_column("替换为")
    t.add_column("策略")
    t.add_column("次数", justify="right")
    for r in records:
        t.add_row(entity_label(r["etype"]), r["original"], r["replacement"],
                  r["strategy"], str(r.get("occurrences", 0)))
    console.print(t)
    if out:
        out.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"[yellow]明文已写出 → {out}（这是还原钥匙，注意保管）[/]")


# --------------------------------------------------------------------------
# serve
# --------------------------------------------------------------------------


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="只监听回环，别改成 0.0.0.0"),
    port: int = typer.Option(8765, "--port"),
    preset: str = typer.Option("legal", "--preset", "-p"),
    schema_dir: Optional[Path] = typer.Option(None, "--schema-dir"),
    workdir: Optional[Path] = typer.Option(None, "--workdir", help="允许在界面里浏览的目录"),
    no_browser: bool = typer.Option(False, "--no-browser"),
):
    """启动本地复核界面（stdlib http.server，不联网、无外部资源）。"""
    from .server import run_server

    p = _resolve_preset(preset, schema_dir)
    url = f"http://{host}:{port}/"
    console.print(f"[bold green]法隐复核界面[/] → {url}")
    console.print("[dim]只监听本机回环。关闭终端即停止。[/]")
    if not no_browser:
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:
            pass
    run_server(host=host, port=port, preset=p,
               schema_dir=(Path(schema_dir) if schema_dir else DEFAULT_SCHEMA_DIR),
               workdir=(Path(workdir) if workdir else resources.data_dir("web")))


@app.command()
def doctor():
    """检查本机依赖是否齐备。"""
    checks = [
        ("python-docx", "docx"), ("lxml", "lxml"), ("PyMuPDF", "fitz"),
        ("pypdfium2", "pypdfium2"), ("opencv", "cv2"), ("numpy", "numpy"),
        ("Pillow", "PIL"), ("openpyxl", "openpyxl"), ("cryptography", "cryptography"),
        ("pyzipper", "pyzipper"), ("RapidOCR", "rapidocr_onnxruntime"),
        ("typer", "typer"), ("rich", "rich"), ("PyYAML", "yaml"),
    ]
    t = Table(title=f"法隐 LegalRedactor v{__version__} 依赖检查")
    t.add_column("组件")
    t.add_column("状态")
    t.add_column("影响")
    import importlib
    impact = {
        "fitz": "PDF 真 redaction 不可用，只能走 pypdfium2 栅格化兜底",
        "pypdfium2": "PDF 栅格化兜底不可用",
        "cv2": "印章/二维码检测与图片脱敏不可用",
        "rapidocr_onnxruntime": "扫描件与图片内文字无法识别",
        "cryptography": "对照表无法加密",
        "pyzipper": "无法生成 AES 加密交付包",
        "openpyxl": "XLSX 不支持",
    }
    missing = []
    for label, mod in checks:
        try:
            importlib.import_module(mod)
            t.add_row(label, "[green]✓ 已安装[/]", "")
        except Exception:
            missing.append(label)
            t.add_row(label, "[red]✗ 缺失[/]", impact.get(mod, "部分功能不可用"))
    console.print(t)

    pt = Table(title="资源路径（打包后这里最容易出问题）")
    pt.add_column("项")
    pt.add_column("值")
    info = resources.describe()
    pt.add_row("运行形态", f"[green]{info['mode']}[/]" if info["frozen"] else "source")
    pt.add_row("资源根", info["bundle_dir"])
    pt.add_row("预设目录", f"{info['schema_dir']}  "
                           f"({'[green]' + str(len(info['schemas_found'])) + ' 个[/]' if info['schemas_found'] else '[red]空[/]'})")
    for f in info["schemas_found"]:
        pt.add_row("", f"[dim]{f}[/]")
    pt.add_row("复核界面", f"{info['web_index']}  "
                          f"{'[green]存在[/]' if info['web_index_exists'] else '[red]缺失[/]'}")
    pt.add_row("可写工作目录", info["data_dir"])
    console.print(pt)

    if not info["schemas_found"] or not info["web_index_exists"]:
        err_console.print("✗ 资源文件缺失，打包时漏了 --add-data")
        raise typer.Exit(1)
    if missing:
        console.print(f"[yellow]缺失：{', '.join(missing)}[/]")
        raise typer.Exit(1)
    console.print("[green]依赖与资源齐备。[/]")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
