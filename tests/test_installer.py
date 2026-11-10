"""Installer protection/rollback contracts; never touches host systemd."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "sidecar_installer", Path(__file__).resolve().parents[1] / "scripts/installer.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallerContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_rejects_broad_or_unmanaged_targets_and_foreign_unit(self):
        for path in ["/", "/opt", "/srv", str(Path.home()), "relative/path"]:
            with self.subTest(path=path), self.assertRaises(installer.InstallError):
                installer.prefix_path(path)
        prefix = self.root / "some-existing-app"
        prefix.mkdir()
        (prefix / "user-file").write_text("preserve")
        with self.assertRaises(installer.InstallError):
            installer.load_manifest(prefix)
        unit = self.root / "foreign.service"
        unit.write_text("[Service]\nExecStart=/some/application\n")
        with self.assertRaises(installer.InstallError):
            installer.validate_unit(unit)
        unit.write_text(installer.UNIT_MARK + "\nWorkingDirectory=/different-installation\n")
        with self.assertRaises(installer.InstallError):
            installer.validate_unit(unit, prefix)
        self.assertEqual((prefix / "user-file").read_text(), "preserve")

    def test_configuration_copy_preserves_relative_path_meaning_without_overwrite(self):
        source = self.root / "original.env"
        source.write_text("SIDECAR_DATA_DIR=./private\nRAGFLOW_API_KEY=synthetic-only\n")
        target = self.root / "installed.env"
        settings = {"data": str(self.root / "private"), "hub": str(self.root / "hub")}
        with patch.object(installer, "read_settings", return_value=settings):
            installer.copy_configuration(source, target, "python")
            with self.assertRaises(FileExistsError):
                installer.copy_configuration(source, target, "python")
        text = target.read_text()
        self.assertIn(str(self.root / "private"), text)
        self.assertIn("synthetic-only", text)
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)

    def installation(self):
        prefix = self.root / "managed"
        config = prefix / "config/sidecar.env"
        config.parent.mkdir(parents=True)
        config.write_text("SYNTHETIC=preserved\n")
        release = prefix / "releases/old"
        release.mkdir(parents=True)
        (prefix / "current").symlink_to(release)
        data = prefix / "state/data/permissions.sqlite3"
        data.parent.mkdir(parents=True)
        with sqlite3.connect(str(data)) as db:
            db.executescript("CREATE TABLE subjects(id TEXT); INSERT INTO subjects VALUES('preserved-user');")
        manifest = {"format": 1, "prefix": str(prefix), "config": str(config),
                    "release": str(release), "service": False,
                    "service_user": "root", "data_dir": str(prefix / "state")}
        installer.atomic_json(prefix / installer.MARKER, manifest)
        return prefix, config, data, manifest

    def test_failed_upgrade_restores_database_manifest_and_current_link(self):
        prefix, config, data, manifest = self.installation()
        args = type("Args", (), {"command": "upgrade", "prefix": str(prefix),
                                "config": None, "no_service": True, "wheelhouse": None})()
        def fake_run(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, "")
        def native_cli(command, **kwargs):
            if "init" in [str(x) for x in command]:
                with sqlite3.connect(str(data)) as db:
                    db.execute("UPDATE subjects SET id='modified-during-failed-migration'")
                raise installer.InstallError("synthetic migration failure")
            return ""
        with patch.object(installer, "verify_bundle"), \
             patch.object(installer.subprocess, "run", side_effect=fake_run), \
             patch.object(installer, "run", side_effect=native_cli), \
             patch.object(installer, "read_settings", return_value={
                 "data": str(prefix / "state"), "hub": str(self.root / "hub"), "port": 20600, "bind": "127.0.0.1"}):
            with self.assertRaises(installer.InstallError):
                installer.install(args)
        self.assertEqual(json.loads((prefix / installer.MARKER).read_text()), manifest)
        self.assertEqual((prefix / "current").resolve(), Path(manifest["release"]))
        self.assertEqual(config.read_text(), "SYNTHETIC=preserved\n")
        with sqlite3.connect(str(data)) as db:
            self.assertEqual(db.execute("SELECT id FROM subjects").fetchone()[0], "preserved-user")
        self.assertTrue(list((prefix / "backups").glob("*/permissions.sqlite3")))

    def test_uninstall_preserves_database_configuration_releases_and_backups(self):
        prefix, config, data, manifest = self.installation()
        args = type("Args", (), {"prefix": str(prefix), "yes": True})()
        installer.uninstall(args)
        self.assertFalse((prefix / "current").is_symlink())
        self.assertTrue(data.is_file())
        self.assertTrue(config.is_file())
        self.assertTrue(Path(manifest["release"]).is_dir())
        self.assertIn("uninstalled_at", json.loads((prefix / installer.MARKER).read_text()))

    def test_manifest_paths_cannot_escape_managed_prefix(self):
        prefix, _, _, manifest = self.installation()
        manifest["release"] = "/some/unrelated/application"
        installer.atomic_json(prefix / installer.MARKER, manifest)
        with self.assertRaises(installer.InstallError):
            installer.load_manifest(prefix)


if __name__ == "__main__":
    unittest.main()
