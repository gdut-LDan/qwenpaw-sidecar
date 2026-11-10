"""Linux installation bundle: isolated releases, backup and bounded rollback.

No recursive deletion, no Hub modifications, no credentials in command arguments.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.request
import uuid

SOURCE = Path(__file__).resolve().parents[1]
MARKER = ".qwenpaw-sidecar-install.json"
UNIT_NAME = "qwenpaw-sidecar.service"
UNIT_MARK = "# Managed by qwenpaw-sidecar installer"


class InstallError(Exception):
    pass


def run(command, *, env=None, capture=False):
    result = subprocess.run([str(x) for x in command], env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        # Pip and doctor may emit config/URL details. Save private logs, not terminal.
        raise InstallError("命令执行失败：" + Path(str(command[0])).name +
                           "（请检查私密安装日志或配置；未输出凭证）")
    return result.stdout if capture else ""


def private_write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(value)


def atomic_json(path, value):
    temp = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    private_write(temp, json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    os.replace(temp, path)


def prefix_path(value):
    path = Path(value).expanduser()
    if not path.is_absolute() or any(c in str(path) for c in '\n\r"%'):
        raise InstallError("安装目录必须是无换行、双引号或 % 的绝对路径")
    resolved = path.resolve()
    if resolved in {Path("/"), Path("/opt"), Path("/srv"), Path("/usr"), Path("/etc"),
                    Path("/var"), Path("/home"), Path.home().resolve(), SOURCE}:
        raise InstallError("请选择专用子目录，不能使用系统根目录、用户主目录或源码目录")
    if path != resolved:
        raise InstallError("安装目录不能包含符号链接或 ..")
    return resolved


def load_manifest(prefix):
    file = prefix / MARKER
    if not file.is_file() or file.is_symlink():
        raise InstallError("该目录不是本安装器管理的目录；不会覆盖已有项目或现网旁挂服务")
    manifest = json.loads(file.read_text())
    if manifest.get("format") != 1 or manifest.get("prefix") != str(prefix):
        raise InstallError("安装标记无效")
    for key in ("release", "config"):
        if key in manifest:
            path = Path(manifest[key])
            if not path.is_absolute() or not path.is_relative_to(prefix):
                raise InstallError("安装标记中的路径越界")
    return manifest


def validate_unit(path):
    if path.exists() and (path.is_symlink() or UNIT_MARK not in path.read_text()):
        raise InstallError("已有同名 systemd 服务不属于本安装器，不会覆盖")


def systemctl(*args):
    return run(["systemctl", *args])


def service_active():
    return subprocess.run(["systemctl", "is-active", "--quiet", UNIT_NAME],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def clean_env(config):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("SIDECAR_", "HUB_", "MCP_", "RAGFLOW_", "ADMIN_", "CREDENTIAL_"))}
    env["SIDECAR_CONFIG"] = str(config)
    return env


def read_settings(python, config):
    code = """
import json
from knowledge_rbac.config import Settings
s=Settings.load()
print(json.dumps(dict(data=str(s.data_dir),hub=str(s.hub_dir),port=s.port,bind=s.bind_host)))
"""
    return json.loads(run([python, "-c", code], env=clean_env(config), capture=True))


def verify_bundle():
    """If supplied by release builder, verify every source file before executing pip."""
    manifest = SOURCE / "MANIFEST.sha256.json"
    if not manifest.exists():
        return
    for relative, expected in json.loads(manifest.read_text()).items():
        path = SOURCE / relative
        if not path.resolve().is_relative_to(SOURCE) or path.is_symlink() or not path.is_file():
            raise InstallError("补丁包文件缺失或路径异常")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise InstallError("补丁包校验失败，请重新下载")


def wizard(destination, prefix):
    if not sys.stdin.isatty():
        raise InstallError("需要 --config 指定已填写的私密配置，或在交互终端填写")
    print("已有 QwenPaw Hub 和 RAGFlow 才能安装；不会修改它们的源码或创建账号。")
    print("密钥在终端隐藏输入，不会保存到源码。按 Ctrl+C 取消。")
    fields = [
        ("HUB_DATA_DIR", "Hub 的 hub/ 目录（含 control.db）", ""),
        ("HUB_URL", "服务器访问 Hub 的 URL", "http://127.0.0.1:8088"),
        ("HUB_PUBLIC_URL", "浏览器访问 Hub 的 URL", ""),
        ("SIDECAR_PUBLIC_URL", "旁挂浏览器公开 URL（含 https://）", ""),
        ("MCP_PUBLIC_URL", "容器能访问的 MCP URL（以 /mcp 结尾）", ""),
        ("ADMIN_USERNAME", "允许管理旁挂的已有 Hub 用户名", ""),
        ("RAGFLOW_BASE_URL", "RAGFlow API URL", "http://127.0.0.1:9380"),
        ("SIDECAR_BIND", "旁挂监听地址", "127.0.0.1"),
        ("SIDECAR_PORT", "旁挂监听端口", "20600"),
    ]
    values = {"SIDECAR_DATA_DIR": str(prefix / "state")}
    for key, label, default in fields:
        while True:
            answer = input(label + (f" [{default}]" if default else "") + "：").strip() or default
            if answer and "\n" not in answer and "\r" not in answer:
                values[key] = answer
                break
            print("该项不能为空。")
    values["HUB_ORIGINS"] = values["HUB_PUBLIC_URL"].rstrip("/")
    values["RAGFLOW_API_KEY"] = getpass.getpass("RAGFlow API Key（隐藏输入）：")
    if not values["RAGFLOW_API_KEY"]:
        raise InstallError("RAGFlow API Key 不能为空")
    # JSON string quoting is also valid for python-dotenv's double quoted values.
    text = "\n".join(k + "=" + json.dumps(v, ensure_ascii=False) for k, v in values.items()) + "\n"
    private_write(destination, text)


def copy_configuration(source, destination, python):
    source = source.expanduser().resolve()
    if not source.is_file():
        raise InstallError("配置文件不存在")
    settings = read_settings(python, source)
    # Preserve semantics of relative paths when relocating the config file.
    text = source.read_text(encoding="utf-8").rstrip() + "\n"
    text += "\n# Installation-normalized absolute paths:\n"
    text += "SIDECAR_DATA_DIR=" + json.dumps(settings["data"], ensure_ascii=False) + "\n"
    text += "HUB_DATA_DIR=" + json.dumps(settings["hub"], ensure_ascii=False) + "\n"
    private_write(destination, text)


def service_text(release, config, prefix, user):
    # Paths reject quotes/%/newlines; quote each path for systemd.
    return f"""{UNIT_MARK}
[Unit]
Description=QwenPaw Sidecar management and MCP service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
WorkingDirectory={prefix}
Environment="SIDECAR_CONFIG={config}"
ExecStart="{release}/.venv/bin/qwenpaw-sidecar" serve
Restart=on-failure
RestartSec=5
UMask=0077
TimeoutStopSec=30
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""


def health(settings):
    host = settings["bind"]
    if host in ("0.0.0.0", "::"):
        host = "127.0.0.1"
    if ":" in host:
        host = "[" + host + "]"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(25):
        try:
            with opener.open(f"http://{host}:{settings['port']}/healthz", timeout=2) as r:
                data = json.load(r)
                if r.status == 200 and data.get("service") == "qwenpaw-sidecar":
                    return
        except (OSError, ValueError):
            pass
        time.sleep(1)
    raise InstallError("新服务健康检查失败，正在恢复原版本")


def sqlite_snapshot(source, destination):
    if not source.exists():
        return False
    with sqlite3.connect(source.as_uri() + "?mode=ro", uri=True) as src, \
            sqlite3.connect(str(destination)) as dest:
        src.backup(dest)
    destination.chmod(0o600)
    return True


def restore_database(snapshot, destination):
    # Use SQLite's transaction/backup API, not ad-hoc deletion of WAL files.
    with sqlite3.connect(snapshot.as_uri() + "?mode=ro", uri=True) as src, \
            sqlite3.connect(str(destination)) as dest:
        src.backup(dest)


def install(args):
    verify_bundle()
    prefix = prefix_path(args.prefix)
    upgrading = args.command == "upgrade"
    manifest = load_manifest(prefix) if upgrading else None
    if not upgrading and prefix.exists() and any(prefix.iterdir()):
        raise InstallError("安装目录非空。已有安装请用 upgrade.sh；其他目录不会被覆盖")
    if upgrading and args.config:
        raise InstallError("升级保留原配置；请先单独编辑已安装配置，不通过 --config 覆盖")
    if upgrading and manifest.get("service") != (not args.no_service):
        raise InstallError("升级请保持原安装模式；无 systemd 安装必须继续传 --no-service")
    if upgrading and manifest.get("uninstalled_at"):
        raise InstallError("该安装已卸载；请在新目录重新安装，旧数据保持原样")
    unit = Path("/etc/systemd/system") / UNIT_NAME
    if not args.no_service:
        if os.geteuid() != 0:
            raise InstallError("注册 systemd 服务需使用 sudo；仅准备文件可用 --no-service")
        validate_unit(unit)
    prefix.mkdir(parents=True, exist_ok=True)
    prefix.chmod(0o700)
    # A file lock serializes install/upgrade/uninstall on this prefix.
    import fcntl
    with (prefix / ".installer.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = prefix / "current"
        if current.exists() and not current.is_symlink():
            raise InstallError("current 被非符号链接文件占用，不覆盖")
        if upgrading:
            config = Path(manifest["config"])
            if not config.is_file():
                raise InstallError("已安装配置缺失")
        else:
            config = prefix / "config" / "sidecar.env"
            config.parent.mkdir(mode=0o700)
        release = prefix / "releases" / (time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8])
        release.mkdir(parents=True, mode=0o700)
        python = release / ".venv/bin/python"
        log = prefix / ("install-" + release.name + ".log")
        print("正在隔离环境中安装依赖。详细日志仅保存在安装目录，权限 600。", flush=True)
        with log.open("x", encoding="utf-8") as out:
            os.chmod(log, 0o600)
            command = [sys.executable, "-m", "venv", str(release / ".venv")]
            subprocess.run(command, check=True, stdout=out, stderr=out)
            command = [str(python), "-m", "pip", "install", str(SOURCE)]
            if args.wheelhouse:
                command += ["--no-index", "--find-links", str(Path(args.wheelhouse).resolve())]
            result = subprocess.run(command, stdout=out, stderr=out)
            if result.returncode:
                raise InstallError(f"依赖安装失败，查看私密日志：{log}；原服务未停止")
        if not upgrading:
            if args.config:
                copy_configuration(Path(args.config), config, python)
            else:
                wizard(config, prefix)
        env = clean_env(config)
        cli = release / ".venv/bin/qwenpaw-sidecar"
        # Validate config/schema before stopping an installed service.
        run([cli, "doctor", "--online"], env=env)
        settings = read_settings(python, config)
        data = Path(settings["data"]) / "data" / "permissions.sqlite3"
        if not upgrading and data.exists():
            raise InstallError("首次安装的配置指向已有权限数据库；请选择新数据目录，不能隐式接管")
        service_user = manifest.get("service_user") if upgrading else (
            args.service_user or pwd.getpwuid(os.getuid()).pw_name)
        if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_-]*", service_user):
            raise InstallError("服务账号名称无效")
        if not args.no_service and pwd.getpwnam(service_user).pw_uid != os.getuid():
            raise InstallError("当前首版以安装执行账号运行；指定其他服务账号请使用手工部署 ACL")
        was_active = service_active() if not args.no_service else False
        old_unit = unit.read_text() if not args.no_service and unit.exists() else None
        backup = prefix / "backups" / release.name
        backup.mkdir(parents=True, mode=0o700)
        shutil.copy2(config, backup / "sidecar.env")
        had_database, stopped, new_unit = False, False, False
        try:
            if not args.no_service and upgrading:
                systemctl("stop", UNIT_NAME)
                stopped = True
            if data.exists():
                with sqlite3.connect(data.as_uri() + "?mode=ro", uri=True) as db:
                    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    if "distribution_jobs" in tables and db.execute(
                            "SELECT count(*) FROM distribution_jobs WHERE status IN ('queued','running')").fetchone()[0]:
                        raise InstallError("存在排队或执行中的分发任务，请先完成或核对任务状态后升级")
                had_database = sqlite_snapshot(data, backup / "permissions.sqlite3")
            if manifest:
                private_write(backup / "previous-install.json", json.dumps(manifest, ensure_ascii=False, indent=2))
            run([cli, "init"], env=env)
            plugin = prefix / "plugin-build" / release.name
            run([cli, "plugin", "--output", plugin], env=env)
            if not args.no_service:
                text = service_text(release, config, prefix, service_user)
                temp = unit.with_name("." + UNIT_NAME + "." + uuid.uuid4().hex + ".tmp")
                private_write(temp, text)
                os.replace(temp, unit)
                unit.chmod(0o644)
                new_unit = True
                systemctl("daemon-reload")
                systemctl("enable", UNIT_NAME)
                systemctl("restart", UNIT_NAME)
                health(settings)
            new_manifest = {
                "format": 1, "prefix": str(prefix), "release": str(release), "config": str(config),
                "service": not args.no_service, "service_user": service_user,
                "data_dir": settings["data"], "plugin": str(plugin / "qwenpaw-sidecar-plugin.zip"),
                "previous_release": manifest.get("release") if manifest else None,
                "backup": str(backup), "updated_at": int(time.time()),
            }
            temp_link = prefix / (".current-" + uuid.uuid4().hex)
            temp_link.symlink_to(release, target_is_directory=True)
            os.replace(temp_link, current)
            atomic_json(prefix / MARKER, new_manifest)
        except BaseException:
            if new_unit:
                systemctl("stop", UNIT_NAME)
            if had_database:
                restore_database(backup / "permissions.sqlite3", data)
            if new_unit:
                if old_unit is not None:
                    unit.write_text(old_unit)
                else:
                    systemctl("disable", UNIT_NAME)
                    unit.unlink(missing_ok=True)
                systemctl("daemon-reload")
            if stopped and was_active:
                systemctl("start", UNIT_NAME)
            if manifest:
                rollback_link = prefix / (".current-rollback-" + uuid.uuid4().hex)
                rollback_link.symlink_to(Path(manifest["release"]), target_is_directory=True)
                os.replace(rollback_link, current)
                atomic_json(prefix / MARKER, manifest)
            raise
        print("升级完成。" if upgrading else "安装完成。")
        print("配置：" + str(config))
        print("插件 ZIP：" + str(plugin / "qwenpaw-sidecar-plugin.zip"))
        print("请在管理者的 QwenPaw 插件界面上传此 ZIP 并刷新；Hub/用户运行时未被重启。")
        if args.no_service:
            print(f"未注册服务。启动：{prefix}/current/.venv/bin/qwenpaw-sidecar --config {config} serve")
        else:
            print("旁挂服务已启动。TLS 与反代仍需按 deploy/ 示例在本机配置。")


def uninstall(args):
    prefix = prefix_path(args.prefix)
    manifest = load_manifest(prefix)
    if not args.yes:
        if not sys.stdin.isatty() or input("停止并移除旁挂服务，保留全部数据和代码？输入 yes：") != "yes":
            raise InstallError("已取消。非交互卸载需显式 --yes")
    import fcntl
    with (prefix / ".installer.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if manifest["service"]:
            if os.geteuid() != 0:
                raise InstallError("移除 systemd 服务需 sudo")
            unit = Path("/etc/systemd/system") / UNIT_NAME
            validate_unit(unit)
            if unit.exists():
                systemctl("disable", "--now", UNIT_NAME)
                unit.unlink()
                systemctl("daemon-reload")
        current = prefix / "current"
        if current.is_symlink():
            current.unlink()
        manifest["uninstalled_at"] = int(time.time())
        atomic_json(prefix / MARKER, manifest)
    print("已停用旁挂服务。配置、数据库、备份、安装日志和版本代码全部保留在：" + str(prefix))
    print("未修改 Hub、知识库或用户助手；需要时在 QwenPaw 中手动停用侧边栏插件。")


def main(argv=None):
    parser = argparse.ArgumentParser(description="QwenPaw Sidecar 功能补丁安装器")
    parser.add_argument("command", choices=["install", "upgrade", "uninstall"])
    parser.add_argument("--prefix", default="/opt/qwenpaw-sidecar", help="专用安装目录")
    parser.add_argument("--config", help="首次安装使用的私密 .env，升级不覆盖")
    parser.add_argument("--no-service", action="store_true", help="不注册 systemd，需自行确保旧进程已停止")
    parser.add_argument("--service-user", help="默认使用安装执行账号，不自动扩大 Hub 文件权限")
    parser.add_argument("--wheelhouse", help="可选本地 wheel 目录，离线依赖须由部署者准备")
    parser.add_argument("--yes", action="store_true", help="确认卸载；始终保留数据")
    args = parser.parse_args(argv)
    os.umask(0o077)
    if sys.platform != "linux" or sys.version_info < (3, 12):
        print("补丁安装器要求 Linux + Python 3.12+。", file=sys.stderr)
        return 2
    try:
        if args.command == "uninstall":
            uninstall(args)
        else:
            install(args)
        return 0
    except (InstallError, OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as e:
        print("安装器停止：" + (str(e) if isinstance(e, InstallError) else type(e).__name__),
              file=sys.stderr)
        print("已有代码与私密日志保留，未执行递归删除。", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("已取消；已有代码和日志保留。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
