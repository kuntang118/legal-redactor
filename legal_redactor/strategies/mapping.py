"""对照表（mapping）导出与加密。

脱敏做完把对照表跟产物一起发出去，等于没脱敏。所以：
  - 默认与产物分离存放
  - 支持口令加密（PBKDF2-SHA256 派生 Fernet 密钥，Fernet = AES-128-CBC + HMAC-SHA256）
  - 明文导出时必须显式 --insecure 才允许
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
from typing import Any, Iterable, Sequence

MAGIC = "FAYIN-MAP"
VERSION = 1
KDF_ITERATIONS = 390_000


def derive_key(passphrase: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def encrypt_mapping(records: Sequence[dict[str, Any]], passphrase: str) -> str:
    """把对照表加密成一个自描述的文本文件内容。"""
    from cryptography.fernet import Fernet

    salt = os.urandom(16)
    key = derive_key(passphrase, salt)
    payload = json.dumps({"v": VERSION, "records": list(records)},
                         ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    token = Fernet(key).encrypt(payload).decode("ascii")
    return json.dumps({
        "magic": MAGIC,
        "v": VERSION,
        "kdf": "pbkdf2-sha256",
        "iterations": KDF_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "cipher": "fernet(aes-128-cbc+hmac-sha256)",
        "token": token,
    }, ensure_ascii=False, indent=2)


def decrypt_mapping(text: str, passphrase: str) -> list[dict[str, Any]]:
    from cryptography.fernet import Fernet, InvalidToken

    obj = json.loads(text)
    if obj.get("magic") != MAGIC:
        raise ValueError("不是本工具生成的加密对照表")
    salt = base64.b64decode(obj["salt"])
    key = derive_key(passphrase, salt, int(obj.get("iterations", KDF_ITERATIONS)))
    try:
        payload = Fernet(key).decrypt(obj["token"].encode("ascii"))
    except InvalidToken as e:
        raise ValueError("口令错误或文件已损坏") from e
    return json.loads(payload.decode("utf-8"))["records"]


def write_mapping(records: Sequence[dict[str, Any]], path: str | Path,
                  passphrase: str | None = None, fmt: str = "auto") -> dict[str, Any]:
    """写对照表。

    fmt: auto | json | csv | encrypted
    返回 {'path':…, 'format':…, 'encrypted':bool, 'records':N}
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "auto":
        fmt = "encrypted" if passphrase else "json"

    if fmt == "encrypted":
        if not passphrase:
            raise ValueError("encrypted 格式需要口令")
        path.write_text(encrypt_mapping(records, passphrase), encoding="utf-8")
        return {"path": str(path), "format": "encrypted", "encrypted": True,
                "records": len(records)}

    if fmt == "csv":
        buf = io.StringIO()
        cols = ["etype", "original", "replacement", "strategy", "code",
                "occurrences", "escalated", "variants", "files"]
        w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in records:
            row = dict(r)
            for k in ("variants", "files"):
                if isinstance(row.get(k), (list, tuple)):
                    row[k] = "|".join(map(str, row[k]))
            w.writerow(row)
        path.write_text("\ufeff" + buf.getvalue(), encoding="utf-8")   # BOM，Excel 直接打开不乱码
        return {"path": str(path), "format": "csv", "encrypted": False,
                "records": len(records)}

    path.write_text(json.dumps({"v": VERSION, "records": list(records)},
                               ensure_ascii=False, indent=2), encoding="utf-8")
    return {"path": str(path), "format": "json", "encrypted": False,
            "records": len(records)}


def mapping_to_markdown(records: Iterable[dict[str, Any]]) -> str:
    """对照表的人读版本（放进复核报告，不进交付包）。"""
    from ..core import entity_label

    rows = list(records)
    if not rows:
        return "_（本次没有需要脱敏的实体）_\n"
    lines = ["| 类型 | 原文 | 替换为 | 策略 | 编号 | 出现次数 | 升级 |",
             "|---|---|---|---|---|---:|:--:|"]
    for r in sorted(rows, key=lambda x: (x["etype"], -(x.get("occurrences") or 0))):
        lines.append(
            f"| {entity_label(r['etype'])} | `{r['original']}` | `{r['replacement']}` "
            f"| {r['strategy']} | {r.get('code') or '-'} | {r.get('occurrences', 0)} "
            f"| {'是' if r.get('escalated') else ''} |")
    return "\n".join(lines) + "\n"
