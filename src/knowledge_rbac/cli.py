"""Install, inspect and operate a standalone sidecar without copying live data."""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
import zipfile
from pathlib import Path

from .config import Settings

HUB_COLUMNS = {
    "hub_users": {"user_id", "username", "role", "disabled", "deleted_at", "created_at"},
    "runtimes": {"runtime_id", "tenant_id", "owner_user_id", "desired_state", "observed_state",
                 "endpoint_json", "deleted_at"},
    "tenant_credentials": {"tenant_id", "scope", "credential_name", "encrypted_value"},
}


def owner_id(settings):
    path = settings.hub_dir / "control.db"
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=3) as db:
        field, value = ("user_id", settings.admin_user_id) if settings.admin_user_id else (
            "username", settings.admin_username)
        row = db.execute(f"SELECT user_id FROM hub_users WHERE {field}=? "
                         "AND disabled=0 AND deleted_at IS NULL", (value,)).fetchone()
    return row[0] if row else None


def doctor(settings, online=False):
    errors = settings.deployment_errors()
    db_path = settings.hub_dir / "control.db"
    if not db_path.is_file():
        errors.append("HUB_DATA_DIR/control.db 不存在；请先部署并初始化 QwenPaw Hub")
    else:
        try:
            with sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True, timeout=3) as db:
                for table, required in HUB_COLUMNS.items():
                    actual = {r[1] for r in db.execute("PRAGMA table_info(" + table + ")")}
                    if not required <= actual:
                        errors.append(f"Hub {table} 结构不兼容：缺少 {', '.join(sorted(required - actual))}")
            if not errors and not owner_id(settings):
                errors.append("指定的 Hub 管理账号不存在、被禁用或已删除")
        except sqlite3.Error:
            errors.append("无法只读打开 Hub 数据库，请检查服务账号权限")
    if not (settings.hub_dir / "secrets/.vault_key").is_file():
        errors.append("缺少 Hub secrets/.vault_key，跨用户分发不能连接运行时")
    if online and not errors:
        import httpx
        checks = [
            ("Hub", settings.hub_url + "/api/auth/status", {}),
            ("RAGFlow", settings.ragflow_url + "/api/v1/datasets",
             {"Authorization": "Bearer " + settings.ragflow_key}),
        ]
        with httpx.Client(timeout=10, trust_env=False, follow_redirects=False) as client:
            for name, url, headers in checks:
                try:
                    r = client.get(url, headers=headers)
                    if r.status_code != 200:
                        errors.append(f"{name} 连接检查失败：HTTP {r.status_code}")
                    elif name == "RAGFlow" and r.json().get("code") != 0:
                        errors.append("RAGFlow API 未通过认证或返回不兼容响应")
                except (httpx.HTTPError, ValueError):
                    errors.append(name + " 连接检查失败（未输出地址、响应正文或密钥）")
    return errors


def generate_plugin(settings, output):
    folder = Path(output).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    dest = folder / "qwenpaw-sidecar-plugin.zip"
    if dest.exists():
        raise ValueError("插件 ZIP 已存在，请使用新的输出目录或先保留旧包")
    source = Path(__file__).parent / "plugin"
    script = (source / "index.js").read_text(encoding="utf-8")
    script = script.replace("const configuredURL = null;",
                            "const configuredURL = " + json.dumps(settings.public_url + "/admin/") + ";", 1)
    with zipfile.ZipFile(dest, "x", zipfile.ZIP_DEFLATED) as z:
        z.writestr("plugin.json", (source / "plugin.json").read_bytes())
        z.writestr("index.js", script.encode("utf-8"))
    return dest


def backup(settings, output):
    source = settings.data_dir / "data/permissions.sqlite3"
    if not source.is_file():
        raise ValueError("旁挂数据库不存在，尚未初始化")
    dest = Path(output).resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    # Create exclusively; never replace a previous backup.
    fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    with sqlite3.connect(source.as_uri() + "?mode=ro", uri=True) as src, sqlite3.connect(str(dest)) as out:
        src.backup(out)
    return dest


def main(argv=None):
    parser = argparse.ArgumentParser(description="QwenPaw Sidecar 旁挂管理服务")
    parser.add_argument("--config", help="配置文件，默认当前目录 .env；环境变量优先")
    sub = parser.add_subparsers(dest="command", required=True)
    d = sub.add_parser("doctor", help="只读检查配置、Hub 数据结构与管理员")
    d.add_argument("--online", action="store_true", help="另检查 Hub/RAGFlow HTTP 连通")
    sub.add_parser("init", help="初始化空权限库，不复制用户密码或业务数据")
    sub.add_parser("serve", help="单进程启动 Web/MCP 服务")
    p = sub.add_parser("plugin", help="生成当前部署专用的插件 ZIP")
    p.add_argument("--output", default="plugin-build")
    b = sub.add_parser("backup", help="在线备份旁挂 SQLite；输出含敏感数据，请私密保存")
    b.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    if args.config:
        os.environ["SIDECAR_CONFIG"] = str(Path(args.config).resolve())
    try:
        settings = Settings.load()
        if args.command in ("doctor", "init", "serve"):
            errors = doctor(settings, getattr(args, "online", False))
            if errors:
                for error in errors:
                    print("ERROR: " + error, file=sys.stderr)
                return 2
        if args.command == "doctor":
            print("配置和当前适配结构检查通过。模型问答、运行时动态接口仍需按验收清单测试。")
        elif args.command == "init":
            from .store import Store
            policy = Store(settings.data_dir / "data/permissions.sqlite3",
                           credential_days=settings.credential_days)
            print("初始化完成：用户默认未分配角色，新知识库默认无授权。")
            print("已有数据库则保留其角色、用户绑定和授权，不重置。")
        elif args.command == "serve":
            import uvicorn
            uvicorn.run("knowledge_rbac.server:app", host=settings.bind_host,
                        port=settings.port, workers=1, access_log=False,
                        proxy_headers=False)
        elif args.command == "plugin":
            print(generate_plugin(settings, args.output))
        elif args.command == "backup":
            print(backup(settings, args.output))
        return 0
    except (ValueError, OSError, sqlite3.Error) as e:
        # Avoid tracebacks that might echo configuration contents or credentials.
        print("操作失败：" + (str(e) if isinstance(e, ValueError) else type(e).__name__),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
