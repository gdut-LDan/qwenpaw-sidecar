"""Read-only checks for a source release. Prints locations, never secret values."""
from pathlib import Path
import ipaddress
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
IGNORED = {".git", ".venv", "var", "backups", "dist", "build", "__pycache__", "plugin-build"}
FORBIDDEN_NAMES = {"credentials.yaml", ".vault_key", ".env"}


def files():
    p = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True)
    if p.returncode == 0:
        return [ROOT / x.decode("utf-8") for x in p.stdout.split(b"\0") if x]
    return [p for p in ROOT.rglob("*") if p.is_file() and not set(p.relative_to(ROOT).parts) & IGNORED]


def main():
    problems = []
    for p in files():
        rel = p.relative_to(ROOT)
        if (set(rel.parts) & IGNORED or p.name in FORBIDDEN_NAMES or
                p.suffix in (".db", ".sqlite", ".sqlite3", ".pem", ".key", ".p12", ".pfx")):
            problems.append((rel, "禁止发布数据、凭证、构建产物或环境目录"))
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        # These patterns are built in pieces so the scanner doesn't match its own source.
        if ("-----BEGIN " + "PRIVATE KEY-----") in text or re.search(
                r"Bearer " + r"[A-Za-z0-9_-]{32,}", text):
            problems.append((rel, "疑似私钥或静态 Bearer 凭证"))
        for value in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                continue
            documentation = any(ip in ipaddress.ip_network(net) for net in (
                "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
            if not (ip.is_loopback or ip.is_unspecified or documentation):
                problems.append((rel, "包含环境专属 IP，请改成配置或文档保留地址"))
                break
    for rel, reason in problems:
        print(f"{rel}: {reason}", file=sys.stderr)
    if problems:
        return 1
    print("发布源文件检查通过；这不替代人工检查和 GitHub secret scanning。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
