"""Authoritative local policy store; all unassigned users are denied."""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
import unicodedata
import uuid
from contextlib import contextmanager
from pathlib import Path

DEFAULT_ROLES = {"privileged": "高级角色", "ordinary": "普通角色"}


class Denied(Exception):
    pass


class Store:
    def __init__(self, path, credential_days=90):
        self.path = Path(path)
        self.credential_days = credential_days
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS roles(
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, name_key TEXT NOT NULL UNIQUE,
                    description TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1
                        CHECK(enabled IN (0,1)),
                    revision INTEGER NOT NULL DEFAULT 1,
                    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS subjects(
                    user_id TEXT PRIMARY KEY, role_id TEXT,
                    FOREIGN KEY(role_id) REFERENCES roles(id));
                CREATE TABLE IF NOT EXISTS datasets(
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1);
                CREATE TABLE IF NOT EXISTS grants(
                    role_id TEXT NOT NULL, dataset_id TEXT NOT NULL,
                    search INTEGER NOT NULL DEFAULT 0, read INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(role_id,dataset_id),
                    FOREIGN KEY(dataset_id) REFERENCES datasets(id));
                CREATE TABLE IF NOT EXISTS credentials(
                    digest TEXT PRIMARY KEY, user_id TEXT NOT NULL, runtime_id TEXT NOT NULL,
                    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                    revoked_at INTEGER, label TEXT NOT NULL DEFAULT '');
                CREATE TABLE IF NOT EXISTS audit(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
                    actor TEXT NOT NULL, action TEXT NOT NULL, allowed INTEGER NOT NULL,
                    resource TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '');
                CREATE TABLE IF NOT EXISTS rbac_migrations(
                    name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL);
            """)
            self._migrate_roles(db)
        self.path.chmod(0o600)

    @staticmethod
    def _migrate_roles(db):
        """Atomic v1 migration: preserve bindings, grants, tokens and release data."""
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM rbac_migrations WHERE name='dynamic-roles-v1'").fetchone():
            return
        now = int(time.time())
        for rid, name in DEFAULT_ROLES.items():
            db.execute("INSERT OR IGNORE INTO roles(id,name,name_key,created_at,updated_at) VALUES(?,?,?,?,?)",
                       (rid, name, unicodedata.normalize("NFKC", name).casefold(), now, now))
        # Preserve any legacy references instead of silently dropping authorization.
        refs = db.execute("SELECT role_id FROM subjects WHERE role_id IS NOT NULL "
                          "UNION SELECT role_id FROM grants").fetchall()
        for row in refs:
            rid = row[0]
            if not db.execute("SELECT 1 FROM roles WHERE id=?", (rid,)).fetchone():
                db.execute("INSERT INTO roles(id,name,name_key,created_at,updated_at) VALUES(?,?,?,?,?)",
                           (rid, rid, unicodedata.normalize("NFKC", rid).casefold(), now, now))
        # Rebuild the two small policy tables to remove the old enum CHECK and add FKs.
        db.execute("CREATE TABLE subjects_dynamic(user_id TEXT PRIMARY KEY,role_id TEXT,"
                   "FOREIGN KEY(role_id) REFERENCES roles(id))")
        db.execute("INSERT INTO subjects_dynamic SELECT user_id,role_id FROM subjects")
        db.execute("CREATE TABLE grants_dynamic(role_id TEXT NOT NULL,dataset_id TEXT NOT NULL,"
                   "search INTEGER NOT NULL DEFAULT 0,read INTEGER NOT NULL DEFAULT 0,"
                   "PRIMARY KEY(role_id,dataset_id),FOREIGN KEY(role_id) REFERENCES roles(id),"
                   "FOREIGN KEY(dataset_id) REFERENCES datasets(id))")
        db.execute("INSERT INTO grants_dynamic SELECT role_id,dataset_id,search,read FROM grants")
        db.execute("DROP TABLE grants")
        db.execute("DROP TABLE subjects")
        db.execute("ALTER TABLE subjects_dynamic RENAME TO subjects")
        db.execute("ALTER TABLE grants_dynamic RENAME TO grants")
        db.execute("INSERT INTO rbac_migrations VALUES('dynamic-roles-v1',?)", (now,))
        Store._event(db, "migration", "roles.migrate", True,
                     detail="preserved subjects, grants and personal credentials")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(str(self.path), timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def event(self, actor, action, allowed, resource="", detail=""):
        with self.connect() as db:
            self._event(db, actor, action, allowed, resource, detail)

    @staticmethod
    def _event(db, actor, action, allowed, resource="", detail=""):
        db.execute(
            "INSERT INTO audit(ts,actor,action,allowed,resource,detail) VALUES(?,?,?,?,?,?)",
            (int(time.time()), actor, action, int(allowed), resource, detail[:500]),
        )

    def seed(self, users, datasets):
        """One-time migration preserving existing project-library access."""
        with self.connect() as db:
            if db.execute("SELECT count(*) FROM subjects").fetchone()[0]:
                return
            for user in users:
                db.execute("INSERT INTO subjects VALUES(?,?)", (
                    user["user_id"], "privileged" if user["role"] == "admin" else "ordinary"))
            for dataset in datasets:
                db.execute("INSERT OR IGNORE INTO datasets(id,name) VALUES(?,?)",
                           (dataset["id"], dataset["name"]))
                for role in DEFAULT_ROLES:
                    db.execute("INSERT OR IGNORE INTO grants VALUES(?,?,1,1)",
                               (role, dataset["id"]))
            self._event(db, "migration", "seed", True, detail="preserved existing dataset access")

    def set_role(self, actor, user_id, role):
        with self.connect() as db:
            if role is not None and not db.execute(
                    "SELECT 1 FROM roles WHERE id=? AND enabled=1", (role,)).fetchone():
                raise ValueError("角色不存在或已停用，请选择有效角色或未授权")
            db.execute("INSERT INTO subjects VALUES(?,?) ON CONFLICT(user_id) "
                       "DO UPDATE SET role_id=excluded.role_id", (user_id, role))
            self._event(db, actor, "role.assign", True, user_id, role or "unassigned")

    @staticmethod
    def role_fields(name, description, enabled):
        if not isinstance(name, str) or not isinstance(description, str) or type(enabled) is not bool:
            raise ValueError("角色名称、说明或状态格式无效")
        name = unicodedata.normalize("NFKC", name).strip()
        description = description.strip()
        if not name or len(name) > 60 or len(description) > 500 or any(ord(c) < 32 for c in name):
            raise ValueError("角色名称为 1 至 60 字，说明不超过 500 字，名称不能包含换行")
        return name, name.casefold(), description, int(enabled)

    def create_role(self, actor, name, description="", enabled=True):
        name, name_key, description, enabled = self.role_fields(name, description, enabled)
        rid, now = "role_" + uuid.uuid4().hex, int(time.time())
        with self.connect() as db:
            if db.execute("SELECT 1 FROM roles WHERE name_key=?", (name_key,)).fetchone():
                raise ValueError("角色名称已存在（包括已停用角色），请使用其他名称")
            db.execute("INSERT INTO roles VALUES(?,?,?,?,?,1,?,?)",
                       (rid, name, name_key, description, enabled, now, now))
            self._event(db, actor, "role.create", True, rid, name)
        return rid

    def update_role(self, actor, role_id, *, name, description, enabled, revision):
        name, name_key, description, enabled = self.role_fields(name, description, enabled)
        if type(revision) is not int or revision < 1:
            raise ValueError("角色版本无效，请刷新后重试")
        with self.connect() as db:
            row = db.execute("SELECT * FROM roles WHERE id=?", (role_id,)).fetchone()
            if not row:
                raise ValueError("角色不存在")
            if row["revision"] != revision:
                raise ValueError("角色已被更新，请刷新后重新编辑")
            if db.execute("SELECT 1 FROM roles WHERE name_key=? AND id!=?", (name_key, role_id)).fetchone():
                raise ValueError("角色名称已存在（包括已停用角色），请使用其他名称")
            updated = db.execute(
                "UPDATE roles SET name=?,name_key=?,description=?,enabled=?,revision=revision+1,updated_at=? "
                "WHERE id=? AND revision=?", (name, name_key, description, enabled,
                                             int(time.time()), role_id, revision))
            if updated.rowcount != 1:
                raise ValueError("角色已被更新，请刷新后重新编辑")
            self._event(db, actor, "role.update", True, role_id,
                        json.dumps({"name": name, "enabled": bool(enabled)}, ensure_ascii=False))

    def sync_datasets(self, actor, datasets):
        # Absent resources are disabled so stale grants cannot remain active.
        ids = [d["id"] for d in datasets]
        if len(ids) != len(set(ids)):
            raise ValueError("知识库列表有重复 ID")
        with self.connect() as db:
            db.execute("UPDATE datasets SET enabled=0")
            for d in datasets:
                db.execute("INSERT INTO datasets(id,name,enabled) VALUES(?,?,1) "
                           "ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=1",
                           (d["id"], d["name"]))
            self._event(db, actor, "datasets.sync", True, detail=str(len(ids)))

    def set_grants(self, actor, role, grants):
        ids = [g["dataset_id"] for g in grants]
        if len(ids) != len(set(ids)):
            raise ValueError("重复的知识库授权")
        with self.connect() as db:
            if not db.execute("SELECT 1 FROM roles WHERE id=?", (role,)).fetchone():
                raise ValueError("角色不存在，请刷新后重试")
            known = {r[0] for r in db.execute("SELECT id FROM datasets WHERE enabled=1")}
            if set(ids) - known:
                raise ValueError("只能授权已同步且有效的知识库")
            db.execute("DELETE FROM grants WHERE role_id=?", (role,))
            for g in grants:
                if type(g.get("search")) is not bool or type(g.get("read")) is not bool:
                    raise ValueError("授权值必须是布尔值")
                db.execute("INSERT INTO grants VALUES(?,?,?,?)",
                           (role, g["dataset_id"], int(g["search"]), int(g["read"])))
            self._event(db, actor, "grants.replace", True, role, json.dumps(grants))

    def allowed(self, user_id, action):
        if action not in ("search", "read"):
            raise ValueError("未知操作")
        with self.connect() as db:
            rows = db.execute(f"""
                SELECT d.id,d.name FROM subjects s
                JOIN roles r ON r.id=s.role_id AND r.enabled=1
                JOIN grants g ON s.role_id=g.role_id JOIN datasets d ON d.id=g.dataset_id
                WHERE s.user_id=? AND d.enabled=1 AND g.{action}=1
            """, (user_id,)).fetchall()
        return {r["id"]: r["name"] for r in rows}

    def require(self, user_id, action, dataset_id):
        if dataset_id not in self.allowed(user_id, action):
            self.event(user_id, action, False, dataset_id)
            raise Denied("没有访问该知识库的权限")

    def issue(self, actor, user_id, runtime_id, label="", days=None):
        days = self.credential_days if days is None else days
        token = "krb_" + secrets.token_urlsafe(40)
        with self.connect() as db:
            role = db.execute("SELECT s.role_id FROM subjects s JOIN roles r ON r.id=s.role_id "
                              "WHERE s.user_id=? AND r.enabled=1", (user_id,)).fetchone()
            if not role or not role[0]:
                raise Denied("先为用户分配已启用的角色，再连接知识库")
            db.execute("INSERT INTO credentials VALUES(?,?,?,?,?,NULL,?)",
                       (self.digest(token), user_id, runtime_id, int(time.time()),
                        int(time.time()) + days * 86400, label))
            self._event(db, actor, "credential.issue", True, user_id, label)
        return token

    def resolve(self, token):
        with self.connect() as db:
            row = db.execute(
                "SELECT c.* FROM credentials c JOIN subjects s ON s.user_id=c.user_id "
                "JOIN roles r ON r.id=s.role_id AND r.enabled=1 "
                "WHERE c.digest=? AND c.revoked_at IS NULL AND c.expires_at>? "
                "AND s.role_id IS NOT NULL", (self.digest(token), int(time.time()))).fetchone()
        if not row:
            raise Denied("个人凭证无效、已撤销、已过期或用户未分配角色")
        return dict(row)

    def revoke(self, actor, user_id):
        with self.connect() as db:
            db.execute("UPDATE credentials SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
                       (int(time.time()), user_id))
            self._event(db, actor, "credential.revoke", True, user_id)

    def snapshot(self):
        with self.connect() as db:
            return {
                "roles": [dict(r) for r in db.execute(
                    "SELECT r.id,r.name,r.description,r.enabled,r.revision,r.created_at,r.updated_at,"
                    "(SELECT count(*) FROM subjects s WHERE s.role_id=r.id) AS user_count "
                    "FROM roles r ORDER BY r.created_at,r.rowid")],
                "subjects": [dict(r) for r in db.execute("SELECT * FROM subjects")],
                "datasets": [dict(r) for r in db.execute("SELECT * FROM datasets ORDER BY name")],
                "grants": [dict(r) for r in db.execute("SELECT * FROM grants")],
                "credentials": [dict(r) for r in db.execute(
                    "SELECT user_id,runtime_id,label,created_at,expires_at,revoked_at FROM credentials")],
                "audit": [dict(r) for r in db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 80")],
            }
