import contextlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from knowledge_rbac.config import Settings
from knowledge_rbac import cli


class PortableInstallContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.file = self.root / "site.env"
        hub = self.root / "local-hub"
        (hub / "secrets").mkdir(parents=True)
        (hub / "runtimes").mkdir()
        (hub / "secrets/.vault_key").write_text("fixture-key")
        db = sqlite3.connect(str(hub / "control.db"))
        db.executescript("""
            CREATE TABLE hub_users(user_id TEXT,username TEXT,role TEXT,disabled INTEGER,deleted_at TEXT,created_at TEXT);
            CREATE TABLE runtimes(runtime_id TEXT,tenant_id TEXT,owner_user_id TEXT,desired_state TEXT,
                observed_state TEXT,endpoint_json TEXT,deleted_at TEXT);
            CREATE TABLE tenant_credentials(tenant_id TEXT,scope TEXT,credential_name TEXT,encrypted_value TEXT);
            INSERT INTO hub_users VALUES('local-owner','owner','user',0,NULL,'0');
        """)
        db.close()
        self.file.write_text(
            "SIDECAR_DATA_DIR=private-state\nHUB_DATA_DIR=local-hub\nADMIN_USERNAME=owner\n"
            "HUB_URL=http://127.0.0.1:8088\nHUB_PUBLIC_URL=https://hub.example.test\n"
            "SIDECAR_PUBLIC_URL=https://sidecar.example.test\nMCP_PUBLIC_URL=https://sidecar.example.test/mcp\n"
            "RAGFLOW_API_KEY=synthetic-test-key\nCREDENTIAL_DAYS=30\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def settings(self, **overrides):
        return Settings.load({"SIDECAR_CONFIG": str(self.file), **overrides})

    def test_config_paths_are_relative_to_config_file_and_env_has_precedence(self):
        settings = self.settings(SIDECAR_PORT="20777")
        self.assertEqual(settings.port, 20777)
        self.assertEqual(settings.data_dir, self.root / "private-state")
        self.assertEqual(settings.hub_dir, self.root / "local-hub")
        self.assertEqual(settings.hub_origins, ("https://hub.example.test",))
        self.assertIn("sidecar.example.test", settings.mcp_hosts)
        self.assertEqual(settings.credential_days, 30)

    def test_fresh_init_creates_empty_policy_without_privileging_hub_users(self):
        with patch.dict(os.environ, {"SIDECAR_CONFIG": str(self.file)}, clear=True):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(["init"]), 0)
                self.assertEqual(cli.main(["init"]), 0)
            self.assertNotIn("synthetic-test-key", out.getvalue())
        path = self.root / "private-state/data/permissions.sqlite3"
        with sqlite3.connect(str(path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM roles").fetchone()[0], 2)
            for table in ("subjects", "grants", "credentials"):
                self.assertEqual(db.execute("SELECT count(*) FROM " + table).fetchone()[0], 0)

    def test_doctor_is_read_only_and_missing_admin_is_closed(self):
        settings = self.settings()
        self.assertEqual(cli.doctor(settings), [])
        self.assertFalse(settings.data_dir.exists())
        self.assertTrue(cli.doctor(self.settings(ADMIN_USERNAME="missing")))
        self.assertTrue(cli.doctor(self.settings(ADMIN_USERNAME="", ADMIN_USER_ID="missing")))
        self.assertIn("必须设置 ADMIN_USERNAME 或 ADMIN_USER_ID",
                      Settings.load({}).deployment_errors())

    def test_plugin_contains_only_generated_site_url_not_key_or_hub_vault(self):
        output = self.root / "plugin"
        dest = cli.generate_plugin(self.settings(), output)
        with zipfile.ZipFile(dest) as z:
            self.assertEqual(set(z.namelist()), {"index.js", "plugin.json"})
            js = z.read("index.js").decode()
            self.assertIn("https://sidecar.example.test/admin/", js)
            self.assertNotIn("synthetic-test-key", js)
            self.assertNotIn("fixture-key", js)
            self.assertNotIn("configuredURL = null", js)
        with self.assertRaises(ValueError):
            cli.generate_plugin(self.settings(), output)

    def test_backup_is_online_snapshot_and_never_overwrites(self):
        with patch.dict(os.environ, {"SIDECAR_CONFIG": str(self.file)}, clear=True):
            self.assertEqual(cli.main(["init"]), 0)
        target = self.root / "private-backups/policy.sqlite3"
        cli.backup(self.settings(), target)
        with sqlite3.connect(str(target)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM roles").fetchone()[0], 2)
        with self.assertRaises(FileExistsError):
            cli.backup(self.settings(), target)

    def test_invalid_origin_url_prefix_and_credential_bounds_are_rejected(self):
        for change in [
            {"HUB_ORIGINS": "*"},
            {"HUB_ORIGINS": "https://hub.example.test/path"},
            {"SIDECAR_PUBLIC_URL": "https://sidecar.example.test/prefix"},
            {"MCP_PUBLIC_URL": "https://sidecar.example.test/wrong"},
            {"HUB_URL": "http://user:secret@localhost:8088"},
            {"SIDECAR_PORT": "0"},
            {"CREDENTIAL_DAYS": "0"},
            {"MCP_ALLOWED_HOSTS": "*"},
        ]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.settings(**change)


if __name__ == "__main__":
    unittest.main()
