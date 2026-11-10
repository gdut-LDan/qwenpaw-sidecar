"""Real CLI/server cold-start with disposable synthetic Hub and RAGFlow services."""
import base64
import contextlib
import http.server
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile

import httpx
import yaml
from cryptography.fernet import Fernet


class FixtureService(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def respond(self, value, status=200):
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/api/auth/status":
            return self.respond({"enabled": True, "has_users": True})
        if self.path == "/api/auth/verify":
            auth = self.headers.get("Authorization", "")
            user = {"Bearer owner-session": {"user_id": "owner-id", "username": "owner", "role": "user"},
                    "Bearer other-session": {"user_id": "other-id", "username": "other", "role": "admin"}}.get(auth)
            return self.respond({"valid": True, "user": user}, 200) if user else self.respond({}, 401)
        if self.path.startswith("/api/v1/datasets"):
            return self.respond({"code": 0, "data": [{"id": "fixture-library", "name": "Synthetic library"}]})
        return self.respond({}, 404)

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        if self.path == "/api/auth/login":
            if data.get("username") == "owner" and data.get("password") == "fixture-password":
                return self.respond({"token": "owner-session"})
            return self.respond({}, 401)
        if self.path == "/api/v1/retrieval":
            assert data["dataset_ids"] == ["fixture-library"]
            return self.respond({"code": 0, "data": {"chunks": [{
                "dataset_id": "fixture-library", "document_id": "fixture-doc",
                "id": "fixture-chunk", "document_keyword": "Synthetic document",
                "content": "Only synthetic fixture material."}]}})
        return self.respond({}, 404)


class ColdStartContract(unittest.TestCase):
    def test_installation_from_empty_policy_can_login_authorize_and_query_mcp(self):
        fixture = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FixtureService)
        thread = threading.Thread(target=fixture.serve_forever, daemon=True)
        thread.start()
        def cleanup_fixture():
            fixture.shutdown()
            fixture.server_close()
            thread.join(timeout=2)
        self.addCleanup(cleanup_fixture)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            hub = root / "hub"
            (hub / "secrets").mkdir(parents=True)
            (hub / "secrets/.vault_key").write_bytes(Fernet.generate_key())
            workspace = hub / "runtimes/member-runtime/working/workspaces/default"
            workspace.mkdir(parents=True)
            (workspace / "agent.json").write_text("{}")
            with sqlite3.connect(str(hub / "control.db")) as db:
                db.executescript("""
                    CREATE TABLE hub_users(user_id TEXT,username TEXT,role TEXT,disabled INTEGER,
                        deleted_at TEXT,created_at TEXT);
                    CREATE TABLE runtimes(runtime_id TEXT,tenant_id TEXT,owner_user_id TEXT,
                        desired_state TEXT,observed_state TEXT,endpoint_json TEXT,deleted_at TEXT);
                    CREATE TABLE tenant_credentials(tenant_id TEXT,scope TEXT,credential_name TEXT,encrypted_value TEXT);
                    INSERT INTO hub_users VALUES('owner-id','owner','user',0,NULL,'0');
                    INSERT INTO hub_users VALUES('other-id','other','admin',0,NULL,'1');
                    INSERT INTO hub_users VALUES('member-id','member','user',0,NULL,'2');
                    INSERT INTO runtimes VALUES('member-runtime','member-tenant','member-id','running','running','{}',NULL);
                """)
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                sidecar_port = sock.getsockname()[1]
            public = f"http://127.0.0.1:{sidecar_port}"
            upstream = f"http://127.0.0.1:{fixture.server_port}"
            config = root / "sidecar.env"
            config.write_text("\n".join([
                f"SIDECAR_DATA_DIR={root / 'state'}", f"HUB_DATA_DIR={hub}",
                "ADMIN_USERNAME=owner", f"HUB_URL={upstream}", f"HUB_PUBLIC_URL={upstream}",
                f"HUB_ORIGINS={upstream}", f"SIDECAR_PUBLIC_URL={public}", f"MCP_PUBLIC_URL={public}/mcp",
                f"SIDECAR_PORT={sidecar_port}", f"RAGFLOW_BASE_URL={upstream}",
                "RAGFLOW_API_KEY=synthetic-fixture-key"]), encoding="utf-8")
            env = {k: v for k, v in os.environ.items() if not k.startswith((
                "SIDECAR_", "HUB_", "MCP_", "RAGFLOW_", "ADMIN_", "KNOWLEDGE_", "CREDENTIAL_"))}
            cmd = [sys.executable, "-m", "knowledge_rbac.cli", "--config", str(config)]
            for args in (["doctor", "--online"], ["init"], ["plugin", "--output", str(root / "plugin")]):
                result = subprocess.run(cmd + args, env=env, cwd=root, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("synthetic-fixture-key", result.stdout + result.stderr)
            with zipfile.ZipFile(root / "plugin/qwenpaw-sidecar-plugin.zip") as z:
                self.assertIn(public + "/admin/", z.read("index.js").decode())
            policy_path = root / "state/data/permissions.sqlite3"
            with sqlite3.connect(str(policy_path)) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM subjects").fetchone()[0], 0)
            smoke = os.environ.get("RUN_INSTALLER_SMOKE") == "1"
            prefix = root / "patch-installed"
            if smoke:
                bundle = Path(__file__).resolve().parents[1]
                installed_config = root / "installer-input.env"
                installed_config.write_text(config.read_text().replace(
                    str(root / "state"), str(root / "installed-state")), encoding="utf-8")
                result = subprocess.run([sys.executable, str(bundle / "scripts/installer.py"),
                    "install", "--prefix", str(prefix), "--config", str(installed_config),
                    "--no-service"], cwd=root, env=env, capture_output=True, text=True, timeout=180)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("synthetic-fixture-key", result.stdout + result.stderr)
                manifest = json.loads((prefix / ".qwenpaw-sidecar-install.json").read_text())
                command = [str(prefix / "current/.venv/bin/qwenpaw-sidecar"),
                           "--config", manifest["config"], "serve"]
                policy_path = root / "installed-state/data/permissions.sqlite3"
            else:
                command = cmd + ["serve"]
            process = subprocess.Popen(command, env=env, cwd=root,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                with httpx.Client(base_url=public, timeout=8, trust_env=False) as client:
                    for _ in range(100):
                        if process.poll() is not None:
                            self.fail("Cold-start server exited before becoming ready")
                        try:
                            if client.get("/healthz").status_code == 200:
                                break
                        except httpx.HTTPError:
                            time.sleep(0.1)
                    else:
                        self.fail("Cold-start server did not become ready")
                    denied = client.post("/admin/sso-ticket", headers={
                        "Origin": upstream, "Authorization": "Bearer other-session"})
                    self.assertEqual(denied.status_code, 403)
                    ticket = client.post("/admin/sso-ticket", headers={
                        "Origin": upstream, "Authorization": "Bearer owner-session"})
                    self.assertEqual(ticket.status_code, 200)
                    login = client.post("/admin/api/login", headers={"Origin": public},
                                        json={"sso_ticket": ticket.json()["ticket"]})
                    self.assertEqual(login.status_code, 200)
                    headers = {"Origin": public, "X-CSRF-Token": login.json()["csrf"]}
                    state = client.get("/admin/api/state").json()
                    self.assertEqual(state["subjects"], [])
                    self.assertEqual(client.post("/admin/api/sync", headers=headers, json={}).status_code, 200)
                    role = client.post("/admin/api/roles/create", headers=headers,
                                       json={"name": "Research"}).json()["role_id"]
                    self.assertEqual(client.post("/admin/api/grants", headers=headers, json={
                        "role_id": role, "grants": [{"dataset_id": "fixture-library",
                                                     "search": True, "read": True}]}).status_code, 200)
                    self.assertEqual(client.post("/admin/api/role", headers=headers,
                        json={"user_id": "member-id", "role_id": role}).status_code, 200)
                    self.assertEqual(client.post("/admin/api/connect", headers=headers, json={
                        "user_id": "member-id", "runtime_id": "member-runtime", "agent_id": "default"}).status_code, 200)
                    driver = yaml.safe_load((workspace / "drivers/mcp/ragflow-gateway.yaml").read_text())
                    mcp_headers = {"Authorization": driver["endpoint"]["headers"]["Authorization"]["value"],
                                   "Accept": "application/json, text/event-stream"}
                    response = client.post("/mcp", headers=mcp_headers, json={
                        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "search_knowledge", "arguments": {"question": "fixture"}}})
                    self.assertEqual(response.status_code, 200)
                    self.assertIn("Synthetic document", response.text)
                    self.assertNotIn("synthetic-fixture-key", response.text)
                    self.assertEqual(client.post("/admin/api/roles/update", headers=headers, json={
                        "role_id": role, "name": "Research", "description": "", "enabled": False,
                        "revision": 1}).status_code, 200)
                    response = client.post("/mcp", headers=mcp_headers, json={
                        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
                    self.assertEqual(response.status_code, 401)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            if smoke:
                with sqlite3.connect(str(policy_path)) as db:
                    prior = {t: db.execute("SELECT * FROM " + t + " ORDER BY 1").fetchall()
                             for t in ("roles", "subjects", "grants", "credentials")}
                for operation in ("upgrade", "uninstall"):
                    command = [sys.executable, str(bundle / "scripts/installer.py"),
                               operation, "--prefix", str(prefix), "--no-service"]
                    if operation == "uninstall":
                        command.append("--yes")
                    result = subprocess.run(command, env=env, cwd=root,
                        capture_output=True, text=True, timeout=180)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((prefix / "current").is_symlink())
                self.assertTrue(Path(manifest["config"]).is_file())
                with sqlite3.connect(str(policy_path)) as db:
                    after = {t: db.execute("SELECT * FROM " + t + " ORDER BY 1").fetchall() for t in prior}
                self.assertEqual(prior, after)


if __name__ == "__main__":
    unittest.main()
