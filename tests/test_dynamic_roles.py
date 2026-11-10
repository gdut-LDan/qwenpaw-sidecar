"""Dynamic-role policy behavior and legacy enum migration contracts."""
import sqlite3
import tempfile
import unittest
from pathlib import Path

from knowledge_rbac.store import Store, Denied


class RoleContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "policy.sqlite3"
        self.store = Store(self.path)
        self.store.seed([{"user_id": "alice", "role": "user"}], [{"id": "public", "name": "公共库"}])

    def tearDown(self):
        self.temp.cleanup()

    def test_new_role_has_no_grants_and_user_can_only_have_one_role(self):
        role = self.store.create_role("manager", "局长", "试点业务角色")
        self.store.set_role("manager", "alice", role)
        self.assertEqual(self.store.allowed("alice", "search"), {})
        self.store.set_grants("manager", role, [{"dataset_id": "public", "search": True, "read": False}])
        self.assertEqual(self.store.allowed("alice", "search"), {"public": "公共库"})
        self.assertEqual(self.store.allowed("alice", "read"), {})
        self.store.set_role("manager", "alice", "ordinary")
        rows = [s for s in self.store.snapshot()["subjects"] if s["user_id"] == "alice"]
        self.assertEqual(rows, [{"user_id": "alice", "role_id": "ordinary"}])

    def test_rename_preserves_assignment_grants_and_existing_credential(self):
        token = self.store.issue("manager", "alice", "runtime")
        role = next(r for r in self.store.snapshot()["roles"] if r["id"] == "ordinary")
        self.store.update_role("manager", role["id"], name="项目成员", description="已改名",
                               enabled=True, revision=role["revision"])
        self.assertEqual(self.store.resolve(token)["user_id"], "alice")
        self.assertEqual(self.store.allowed("alice", "read"), {"public": "公共库"})
        reloaded = Store(self.path)
        renamed = next(r for r in reloaded.snapshot()["roles"] if r["id"] == "ordinary")
        self.assertEqual(renamed["name"], "项目成员")
        self.assertEqual(renamed["description"], "已改名")
        self.assertEqual(renamed["user_count"], 1)

    def test_disable_blocks_existing_credentials_new_issues_and_assignments_then_resume(self):
        role = self.store.create_role("manager", "秘书")
        self.store.set_grants("manager", role, [{"dataset_id": "public", "search": True, "read": True}])
        self.store.set_role("manager", "alice", role)
        token = self.store.issue("manager", "alice", "runtime")
        self.store.update_role("manager", role, name="秘书", description="", enabled=False, revision=1)
        self.assertEqual(self.store.allowed("alice", "search"), {})
        with self.assertRaises(Denied):
            self.store.resolve(token)
        with self.assertRaises(Denied):
            self.store.issue("manager", "alice", "runtime")
        with self.assertRaises(ValueError):
            self.store.set_role("manager", "bob", role)
        self.assertEqual(next(s for s in self.store.snapshot()["subjects"] if s["user_id"] == "alice")["role_id"], role)
        self.store.update_role("manager", role, name="秘书", description="", enabled=True, revision=2)
        self.assertEqual(self.store.resolve(token)["user_id"], "alice")
        self.assertEqual(self.store.allowed("alice", "read"), {"public": "公共库"})

    def test_duplicate_normalized_names_validation_and_stale_edit_are_rejected(self):
        role = self.store.create_role("manager", "信息科")
        with self.assertRaises(ValueError):
            self.store.create_role("manager", " 信息科 ")
        with self.assertRaises(ValueError):
            self.store.create_role("manager", " \n ")
        with self.assertRaises(ValueError):
            self.store.create_role("manager", "a" * 61)
        self.store.create_role("manager", "IT")
        with self.assertRaises(ValueError):
            self.store.create_role("manager", "ｉｔ")
        with self.assertRaises(ValueError):
            self.store.update_role("manager", role, name="普通角色", description="", enabled=True, revision=1)
        self.store.update_role("manager", role, name="信息科", description="第一次修改", enabled=False, revision=1)
        with self.assertRaises(ValueError):
            self.store.update_role("manager", role, name="被覆盖", description="", enabled=True, revision=1)
        current = next(r for r in self.store.snapshot()["roles"] if r["id"] == role)
        self.assertFalse(current["enabled"])
        self.assertEqual(current["description"], "第一次修改")

    def test_role_foreign_keys_reject_dangling_grants_and_assignments(self):
        with self.assertRaises(sqlite3.IntegrityError), self.store.connect() as db:
            db.execute("INSERT INTO subjects VALUES('bad-user','missing-role')")
        with self.assertRaises(sqlite3.IntegrityError), self.store.connect() as db:
            db.execute("INSERT INTO grants VALUES('missing-role','public',1,1)")
        self.assertFalse(any(s["user_id"] == "bad-user" for s in self.store.snapshot()["subjects"]))

    def test_revoked_token_stays_revoked_after_role_reenable(self):
        token = self.store.issue("manager", "alice", "runtime")
        self.store.revoke("manager", "alice")
        self.store.update_role("manager", "ordinary", name="普通角色", description="", enabled=False, revision=1)
        self.store.update_role("manager", "ordinary", name="普通角色", description="", enabled=True, revision=2)
        with self.assertRaises(Denied):
            self.store.resolve(token)


class LegacyMigrationContracts(unittest.TestCase):
    def test_old_enum_migration_preserves_grants_users_tokens_and_unrelated_assets(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "legacy.sqlite3"
            with sqlite3.connect(str(path)) as db:
                db.executescript("""
                    CREATE TABLE subjects(user_id TEXT PRIMARY KEY,role_id TEXT,
                        CHECK(role_id IS NULL OR role_id IN ('privileged','ordinary')));
                    CREATE TABLE datasets(id TEXT PRIMARY KEY,name TEXT NOT NULL,enabled INTEGER DEFAULT 1);
                    CREATE TABLE grants(role_id TEXT,dataset_id TEXT,search INTEGER,read INTEGER,
                        PRIMARY KEY(role_id,dataset_id),FOREIGN KEY(dataset_id) REFERENCES datasets(id));
                    CREATE TABLE credentials(digest TEXT PRIMARY KEY,user_id TEXT,runtime_id TEXT,
                        created_at INTEGER,expires_at INTEGER,revoked_at INTEGER,label TEXT);
                    CREATE TABLE asset_releases(id TEXT PRIMARY KEY);
                    INSERT INTO subjects VALUES('alice','ordinary'),('bob','privileged'),('new-user',NULL);
                    INSERT INTO datasets VALUES('public','公共库',1);
                    INSERT INTO grants VALUES('ordinary','public',1,0),('privileged','public',1,1);
                    INSERT INTO asset_releases VALUES('published-before-migration');
                """)
                db.execute("INSERT INTO credentials VALUES(?,?,?,?,?,?,?)",
                           (Store.digest("existing-token"), "alice", "runtime", 1, 9999999999, None, "default"))
                before = {t: db.execute("SELECT * FROM " + t).fetchall()
                          for t in ["subjects", "grants", "credentials", "asset_releases"]}
            store = Store(path)
            with store.connect() as db:
                after = {t: [tuple(r) for r in db.execute("SELECT * FROM " + t)]
                         for t in before}
                self.assertEqual(before, after)
                self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
                self.assertNotIn("CHECK", db.execute(
                    "SELECT sql FROM sqlite_master WHERE name='subjects'").fetchone()[0])
            self.assertEqual(store.resolve("existing-token")["user_id"], "alice")
            role = store.create_role("manager", "新增动态角色")
            store.set_role("manager", "alice", role)
            self.assertEqual(store.allowed("alice", "search"), {})
            reloaded = Store(path)
            self.assertEqual(len(reloaded.snapshot()["roles"]), 3)
            self.assertEqual(reloaded.resolve("existing-token")["user_id"], "alice")


if __name__ == "__main__":
    unittest.main()
