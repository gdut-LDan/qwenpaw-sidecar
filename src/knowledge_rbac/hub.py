"""Read-only Hub identity adapter; never changes Hub tables or passwords."""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .store import Denied


class HubDirectory:
    def __init__(self, path, runtime_root):
        self.path = Path(path)
        self.runtime_root = Path(runtime_root)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=3)
        db.row_factory = sqlite3.Row
        try:
            yield db
        finally:
            db.close()

    def users(self):
        with self.connect() as db:
            return [dict(r) for r in db.execute(
                "SELECT user_id,username,role,disabled FROM hub_users "
                "WHERE deleted_at IS NULL ORDER BY created_at")]

    def require_user(self, user_id, runtime_id=None):
        with self.connect() as db:
            row = db.execute(
                "SELECT user_id,username,role,disabled FROM hub_users "
                "WHERE user_id=? AND disabled=0 AND deleted_at IS NULL", (user_id,)).fetchone()
            if row is None:
                raise Denied("平台账号已禁用、已删除或不存在")
            if runtime_id is not None:
                runtime = db.execute(
                    "SELECT runtime_id FROM runtimes WHERE runtime_id=? AND owner_user_id=? "
                    "AND deleted_at IS NULL AND desired_state!='disabled'",
                    (runtime_id, user_id)).fetchone()
                if runtime is None:
                    raise Denied("运行时已失效或不属于该用户")
        return dict(row)

    def agents(self, user_id):
        self.require_user(user_id)
        with self.connect() as db:
            rows = db.execute(
                "SELECT runtime_id FROM runtimes WHERE owner_user_id=? AND deleted_at IS NULL "
                "AND desired_state!='disabled'", (user_id,)).fetchall()
        result = []
        for row in rows:
            rt = row["runtime_id"]
            root = self.runtime_root / rt / "working" / "workspaces"
            if root.is_symlink() or not root.is_dir():
                continue
            for workspace in root.iterdir():
                if workspace.is_symlink() or not workspace.is_dir():
                    continue
                try:
                    workspace.resolve().relative_to(self.runtime_root.resolve())
                except ValueError:
                    continue
                if (workspace / "agent.json").is_file():
                    result.append({"runtime_id": rt, "agent_id": workspace.name})
        return result

    def runtimes(self, user_id):
        self.require_user(user_id)
        with self.connect() as db:
            return [dict(r) for r in db.execute(
                "SELECT runtime_id,observed_state FROM runtimes WHERE owner_user_id=? "
                "AND deleted_at IS NULL AND desired_state!='disabled'", (user_id,))]

    def install_driver(self, user_id, runtime_id, agent_id, token, mcp_url):
        """Only our one managed driver; do not overwrite unrelated MCPs."""
        import yaml
        import secrets
        if not any(a["runtime_id"] == runtime_id and a["agent_id"] == agent_id
                   for a in self.agents(user_id)):
            raise ValueError("用户运行时或智能体不存在")
        relative = Path(runtime_id) / "working" / "workspaces" / agent_id / "drivers" / "mcp"
        if relative.is_absolute() or any(p in ("..", ".") for p in relative.parts):
            raise ValueError("非法智能体路径")
        # Hold directory descriptors, forbidding symlinks at every component.
        fd = os.open(self.runtime_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in relative.parts:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            driver = {
                "name": "ragflow-gateway", "protocol": "mcp",
                "endpoint": {"transport": "streamable_http", "url": mcp_url,
                             "headers": {"Authorization": {"source": "literal", "value": "Bearer " + token}}},
                "credentials": {},
                "config": {"display_name": "组织知识库", "description": "按当前用户角色授权的知识库", "tools": None},
                "enabled": True,
                "policy": {"default_effect": "allow", "rules": []},
            }
            temp = ".rbac-" + secrets.token_hex(8) + ".tmp"
            out = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                          0o600, dir_fd=fd)
            with os.fdopen(out, "w") as stream:
                yaml.safe_dump(driver, stream, allow_unicode=True, sort_keys=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, "ragflow-gateway.yaml", src_dir_fd=fd, dst_dir_fd=fd)
        finally:
            os.close(fd)
