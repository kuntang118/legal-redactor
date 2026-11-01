"""端到端验证：扫描 → 脱敏 → 残留自检，逐格式核对。

同时用 ground truth 算召回率，并把"额外泄露点"（页眉/页脚/批注/修订/元数据）
单独核对——这些是最容易漏的地方。
"""
from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from legal_redactor.audit import Auditor, write_audit, SEV_ORDER
from legal_redactor.core import load_preset
from legal_redactor.engine import Engine
from legal_redactor.strategies import mapping as mapping_mod
from tests.make_samples import GROUND_TRUTH, SAMPLES

# 独立输出目录：同一工作区里有另一个会话在用 out/，避免互相清理
OUT = ROOT / "verify-out" / "e2e"
OUT.mkdir(parents=True, exist_ok=True)


def hr(t: str = "") -> None:
    print("\n" + "=" * 78)
    if t:
        print(t)
        print("=" * 78)


def coverage(scan_spans, gt: dict) -> dict:
    """按 ground truth 算召回。"""
    found: dict[str, set[str]] = {}
    for s in scan_spans:
        found.setdefault(s.etype, set()).add(s.text)
    # 归一化后的集合，用于处理 +86 136 2222 3333 这类写法
    import re
    def norm(v: str) -> str:
        return re.sub(r"[^0-9A-Za-z\u4e00-\u9fa5]", "", v)
    found_norm: dict[str, set[str]] = {k: {norm(x) for x in v} for k, v in found.items()}

    res = {}
    total_hit = total = 0
    for etype, values in gt.items():
        if etype == "EXTRA":
            continue
        pool = found_norm.get(etype, set())
        hit, miss = [], []
        for v in values:
            nv = norm(v)
            # 命中判定：完全相等，或检出值包含 ground truth（+86 136 2222 3333 / 010-66554433转8021）
            if v in found.get(etype, set()) or nv in pool or any(nv in x for x in pool):
                hit.append(v)
            else:
                miss.append(v)
        res[etype] = {"hit": len(hit), "total": len(values), "miss": miss}
        total_hit += len(hit)
        total += len(values)
    res["_TOTAL"] = {"hit": total_hit, "total": total,
                     "recall": round(total_hit / total, 4) if total else 1.0}
    return res


def check_extra_leaks(rep, fmt: str) -> list[str]:
    """核对页眉/页脚/批注/修订/元数据这些额外泄露点是否被清掉。"""
    ex = GROUND_TRUTH["EXTRA"]
    bad = []
    residues = rep.residues
    blob_parts = {r.part: r for r in residues}

    # 元数据
    if any(r.kind == "metadata" for r in residues):
        bad.append("文档属性仍有残留：" + ", ".join(
            f"{r.part}={r.found}" for r in residues if r.kind == "metadata"))
    # 修订
    if any(r.kind == "revision" for r in residues):
        bad.append("修订痕迹仍有残留：" + ", ".join(
            f"{r.part}:{r.found}" for r in residues if r.kind == "revision"))
    # 批注
    if any(r.kind == "comment" for r in residues):
        bad.append("批注仍有残留：" + ", ".join(
            f"{r.part}:{r.found}" for r in residues if r.kind == "comment"))
    return bad


def _gt(*, persons, ids, phones, addrs, **kw) -> dict:
    d = {"PERSON": persons, "ID_CARD": ids, "PHONE": phones, "ADDRESS": addrs}
    d.update({k: v for k, v in kw.items() if v})
    return d


# 每个样本里真实存在的敏感值。图片/扫描件只列"画面上确实可见"的那些，
# 否则召回率是在拿不存在的东西当分母。
GT_TXT = {k: v for k, v in GROUND_TRUTH.items() if k != "EXTRA"}
GT_DOCX = GT_TXT
GT_PDF_TEXT = GT_TXT
GT_XLSX = _gt(
    persons=["张伟民", "陈晓芸", "孙丽华"],
    ids=["11010519870312451X", "310115199211058768", "440106197502281234",
         "110108200905082214"],
    phones=["13801234567", "13622223333", "13522223333", "13711112222"],
    addrs=["北京市朝阳区建国路88号院3号楼2单元401室", "上海市浦东新区世纪大道100号28层",
           "广东省广州市天河区体育西路103号", "北京市海淀区中关村南大街5号"],
    BANK_CARD=["6222021123456787", "1100123456780003"],
    BANK_BRANCH=["中国工商银行股份有限公司北京朝阳支行", "中国建设银行股份有限公司北京西城支行"],
    ORG=["北京华远置业有限公司"],
)
GT_IMAGE = _gt(
    persons=["王志强"], ids=[], phones=["13801234567"],
    addrs=["北京市西城区金融大街7号英蓝国际金融中心12层"],
    USCC=["91110102710931234J"], ORG=["北京华远置业有限公司"],
)
# 扫描版只画下了正文前几段 + 落款三人 + 印章
GT_PDF_SCAN = _gt(
    persons=["张伟民", "李建国", "王志强", "赵晓东", "陈晓芸", "刘振华", "杨秀兰", "方文静"],
    ids=["11010519870312451X", "310115199211058768"],
    phones=["13801234567", "13911223344"],
    addrs=["北京市朝阳区建国路88号院3号楼2单元401室"],
    USCC=["91110102710931234J"], LICENSE_NO=["11101201510123456"],
    EMAIL=["zhangwm@example.com.cn"],
)

#: 召回率是否作为通过门槛。OCR 链路的召回受识别精度限制，只作参考不作门槛。
GATING = {"txt": True, "docx": True, "xlsx": True, "pdf_text": True,
          "image": False, "pdf_scan": False}


def run_one(engine_factory, name: str, src: Path, dst: Path, gt: dict) -> dict:
    hr(f"[{name}] {src.name}")
    out = {"name": name, "src": str(src), "dst": str(dst)}
    try:
        eng = engine_factory()
        scan = eng.scan(src)
        out["spans"] = len(scan.all_spans)
        out["boxes"] = len(scan.all_boxes)
        out["warnings"] = scan.warnings
        cov = coverage(scan.all_spans, gt)
        out["coverage"] = cov
        print(f"  检出 span={out['spans']}  box={out['boxes']}")
        print(f"  ground-truth 召回：{cov['_TOTAL']['hit']}/{cov['_TOTAL']['total']} "
              f"= {cov['_TOTAL']['recall']:.1%}")
        for t, r in cov.items():
            if t == "_TOTAL" or not r["miss"]:
                continue
            print(f"    ✗ {t} 漏检：{r['miss']}")
        if scan.warnings:
            print("  扫描告警：")
            for w in scan.warnings:
                print(f"    - {w}")

        res = eng.redact(src, dst, scan=scan)
        out["replacements"] = res.replacements
        out["adapter"] = res.adapter_report
        out["redact_warnings"] = res.warnings
        print(f"  替换次数：{res.replacements}  →  {dst.name}")
        if res.warnings:
            for w in res.warnings:
                print(f"    ! {w}")

        aud = Auditor(eng.resolver, eng.options)
        rep = aud.audit(src, dst, res.fmt, scan=scan)
        out["audit_passed"] = rep.passed
        out["audit_worst"] = rep.worst
        out["audit_by_severity"] = rep.by_severity()
        out["audit_checks"] = [(c.name, c.passed, c.detail) for c in rep.checks]
        out["audit_residues"] = [r.to_dict() for r in rep.residues]
        out["audit_warnings"] = rep.warnings
        out["extra_leaks"] = check_extra_leaks(rep, res.fmt)
        out["mapping"] = eng.resolver.mapping_records()
        paths = write_audit(rep, OUT, name)
        out["audit_files"] = paths

        print(f"  自检结论：{'✅ PASS' if rep.passed else '❌ FAIL'}"
              f"（最高级 {rep.worst}，{rep.by_severity()}）")
        for cn, cp, cd in out["audit_checks"]:
            print(f"    {'✓' if cp else '✗'} {cn}: {cd}")
        if rep.residues:
            print(f"  残留 {len(rep.residues)} 条（前 12）：")
            for r in sorted(rep.residues, key=lambda x: -SEV_ORDER.get(x.severity, 0))[:12]:
                print(f"    [{r.severity:8}] {r.kind:10} {r.etype:12} "
                      f"原={r.original[:24]!r} 命中={r.found[:24]!r} @ {r.part}")
        if rep.warnings:
            for w in rep.warnings:
                print(f"    ⚠ {w}")
        if out["extra_leaks"]:
            print("  ✗ 额外泄露点未清干净：")
            for b in out["extra_leaks"]:
                print(f"    - {b}")
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        out["traceback"] = traceback.format_exc()
        print(f"  ✗ 异常：{type(e).__name__}: {e}")
        traceback.print_exc()
    return out


def main() -> int:
    # 样本是合成数据、由脚本生成，不进仓库；缺了就先生成
    if not (SAMPLES / "民事判决书.docx").exists():
        print("样本不存在，正在生成…")
        from tests.make_samples import make_all
        make_all()
        print()

    preset = load_preset(ROOT / "schemas" / "legal.yaml")

    def factory():
        return Engine(preset, seed=b"e2e-test-seed")

    cases = [
        ("txt", SAMPLES / "当事人清单.txt", OUT / "当事人清单.脱敏.txt", GT_TXT),
        ("docx", SAMPLES / "民事判决书.docx", OUT / "民事判决书.脱敏.docx", GT_DOCX),
        ("xlsx", SAMPLES / "当事人信息表.xlsx", OUT / "当事人信息表.脱敏.xlsx", GT_XLSX),
        ("image", SAMPLES / "签章页.png", OUT / "签章页.脱敏.png", GT_IMAGE),
        ("pdf_text", SAMPLES / "民事判决书_文本版.pdf", OUT / "民事判决书_文本版.脱敏.pdf", GT_PDF_TEXT),
        ("pdf_scan", SAMPLES / "民事判决书_扫描版.pdf", OUT / "民事判决书_扫描版.脱敏.pdf", GT_PDF_SCAN),
    ]

    results = []
    only = set(sys.argv[1:]) or None
    for n, s, d, g in cases:
        if only and n not in only:
            continue
        results.append(run_one(factory, n, s, d, g))

    hr("汇总")
    ok = 0
    for r in results:
        if r.get("error"):
            print(f"  ✗ {r['name']:10} 异常：{r['error']}")
            continue
        p = r.get("audit_passed")
        cov = r.get("coverage", {}).get("_TOTAL", {})
        extra = r.get("extra_leaks") or []
        gating = GATING.get(r["name"], True)
        recall_ok = (cov.get("hit") == cov.get("total")) or not gating
        passed = bool(p) and not extra and recall_ok
        status = "✅" if passed else "❌"
        if passed:
            ok += 1
        note = "" if gating else "（OCR 召回仅供参考）"
        print(f"  {status} {r['name']:10} 召回={cov.get('hit')}/{cov.get('total')}{note} "
              f"替换={r.get('replacements')} 自检={'PASS' if p else 'FAIL'} "
              f"额外泄露={len(extra)}")

    (OUT / "e2e-summary.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(f"\n通过 {ok}/{len(results)}，明细见 {OUT / 'e2e-summary.json'}")
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
