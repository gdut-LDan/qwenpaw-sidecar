"""Authorization contracts exercised through the real MCP HTTP endpoint."""
from __future__ import annotations

import asyncio
import importlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from starlette.testclient import TestClient

from knowledge_rbac.hub import HubDirectory
from knowledge_rbac.store import Denied, Store


class PolicyContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "policy.db")
        self.store.seed(
            [{"user_id": "leader", "role": "admin"}, {"user_id": "staff", "role": "user"}],
            [{"id": "public", "name": "公共模拟资料"}, {"id": "restricted", "name": "受限模拟资料"}])
        self.store.set_grants("admin", "ordinary", [
            {"dataset_id": "public", "search": True, "read": False}])

    def tearDown(self):
        self.tmp.cleanup()

    def test_roles_are_distinct_and_unassigned_users_are_denied(self):
        self.assertEqual(set(self.store.allowed("leader", "read")), {"public", "restricted"})
        self.assertEqual(set(self.store.allowed("staff", "search")), {"public"})
        self.assertEqual(self.store.allowed("staff", "read"), {})
        self.assertEqual(self.store.allowed("new-user", "search"), {})
        with self.assertRaises(Denied):
            self.store.require("staff", "read", "public")
        with self.assertRaises(Denied):
            self.store.require("staff", "search", "restricted")

    def test_role_changes_and_per_user_revocation_are_immediate(self):
        leader = self.store.issue("admin", "leader", "runtime-leader")
        staff = self.store.issue("admin", "staff", "runtime-staff")
        self.store.set_role("admin", "leader", "ordinary")
        self.assertEqual(self.store.resolve(leader)["user_id"], "leader")
        with self.assertRaises(Denied):
            self.store.require("leader", "read", "restricted")
        self.store.revoke("admin", "leader")
        with self.assertRaises(Denied):
            self.store.resolve(leader)
        self.assertEqual(self.store.resolve(staff)["user_id"], "staff")

    def test_bad_grant_replacement_is_atomic_and_new_resources_default_deny(self):
        before = self.store.allowed("leader", "read")
        with self.assertRaises(ValueError):
            self.store.set_grants("admin", "privileged", [
                {"dataset_id": "public", "search": True, "read": "true"}])
        self.assertEqual(self.store.allowed("leader", "read"), before)
        self.store.sync_datasets("admin", [{"id": k, "name": k} for k in ["public", "restricted", "new"]])
        self.assertNotIn("new", self.store.allowed("leader", "read"))
        self.store.sync_datasets("admin", [{"id": "public", "name": "public"}])
        self.assertNotIn("restricted", self.store.allowed("leader", "read"))


class MCPContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / ".env").write_text("RAGFLOW_API_KEY=test-only\n", encoding="utf-8")
        self.environment = patch.dict(os.environ, {
            "SIDECAR_CONFIG": str(root / ".env"), "SIDECAR_DATA_DIR": str(root),
            "HUB_DATA_DIR": str(root / "hub"), "HUB_ORIGINS": "http://127.0.0.1:8088",
            "HUB_URL": "http://127.0.0.1:8088", "HUB_PUBLIC_URL": "http://127.0.0.1:8088",
            "SIDECAR_PUBLIC_URL": "http://127.0.0.1:20600", "ADMIN_USERNAME": "owner",
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        from knowledge_rbac import server
        server = importlib.reload(server)
        self.server = server
        self.policy = Store(root / "test-policy.db")
        self.policy.seed(
            [{"user_id": "leader", "role": "admin"}, {"user_id": "staff", "role": "user"}],
            [{"id": "public", "name": "合成公共库"}, {"id": "restricted", "name": "合成受限库"}])
        self.policy.set_grants("admin", "ordinary", [
            {"dataset_id": "public", "search": True, "read": False}])
        db = sqlite3.connect(str(root / "hub.db"))
        db.executescript("""
          CREATE TABLE hub_users(user_id TEXT,username TEXT,role TEXT,disabled INTEGER,
              deleted_at TEXT,created_at TEXT);
          CREATE TABLE runtimes(runtime_id TEXT,owner_user_id TEXT,deleted_at TEXT,desired_state TEXT,
              observed_state TEXT);
          INSERT INTO hub_users VALUES('leader','leader','admin',0,NULL,'1');
          INSERT INTO hub_users VALUES('staff','staff','user',0,NULL,'2');
          INSERT INTO runtimes VALUES('runtime-leader','leader',NULL,'running','running');
          INSERT INTO runtimes VALUES('runtime-staff','staff',NULL,'running','running');
        """)
        db.close()
        self.hub = HubDirectory(root / "hub.db", root / "runtimes")
        self.tokens = {u: self.policy.issue("admin", u, "runtime-" + u) for u in ["leader", "staff"]}
        self.calls = []

        async def backend(method, path, **kwargs):
            self.calls.append((method, path, kwargs))
            if path.endswith("/retrieval"):
                ids = kwargs["json"]["dataset_ids"]
                return {"chunks": [{"id": "chunk", "dataset_id": ids[0], "document_id": "doc",
                                     "document_keyword": "合成文件", "content": "仅供测试的合成内容"}]}
            if path.endswith("/documents"):
                doc = "doc" if "/public/" in path else "secret-doc"
                wanted = kwargs.get("params", {}).get("id")
                return {"docs": [{"id": doc, "name": "合成文件"}] if wanted in (None, doc) else [], "total": 1}
            if path.endswith("/chunks"):
                return {"chunks": [{"id": "chunk", "content": "合成正文"}], "total": 1}
            return []

        self.patches = [
            patch.object(server, "POLICY", self.policy),
            patch.object(server, "HUB", self.hub),
            patch.object(server, "backend", backend),
            patch.object(server, "ADMIN_USER_ID", "leader"),
            patch.object(server, "DISTRIBUTION", server.Distribution(self.policy, self.hub, "http://localhost/mcp")),
        ]
        for p in self.patches:
            p.start()
        self.app = server.build_app()
        self.client = TestClient(self.app, base_url="http://127.0.0.1:20600")
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def rpc(self, user, tool, arguments):
        r = self.client.post("/mcp", headers={
            "Authorization": "Bearer " + self.tokens.get(user, user),
            "Accept": "application/json, text/event-stream",
        }, json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                 "params": {"name": tool, "arguments": arguments}})
        if r.status_code != 200:
            return r, None
        data = [line[6:] for line in r.text.splitlines() if line.startswith("data: ")]
        return r, json.loads(data[-1]) if data else r.json()

    def test_search_scope_is_server_side_and_result_is_cited(self):
        r, data = self.rpc("staff", "search_knowledge",
                           {"question": "测试", "user_id": "leader", "role": "privileged"})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(data["result"].get("isError", False))
        self.assertEqual(self.calls[0][2]["json"]["dataset_ids"], ["public"])
        self.assertIn("合成文件", str(data))
        self.assertNotIn("restricted", str(data))

    def test_backend_scope_mismatch_is_not_exposed(self):
        async def leaking_backend(*args, **kwargs):
            return {"chunks": [{"dataset_id": "restricted", "content": "SHOULD_NOT_ESCAPE"}]}
        with patch.object(self.server, "backend", leaking_backend):
            _, data = self.rpc("staff", "search_knowledge", {"question": "测试"})
        self.assertTrue(data["result"]["isError"])
        self.assertNotIn("SHOULD_NOT_ESCAPE", str(data))

    def test_revocation_during_backend_request_blocks_response(self):
        async def slow_backend(*args, **kwargs):
            self.policy.revoke("admin", "staff")
            return {"chunks": [{"dataset_id": "public", "content": "SHOULD_NOT_ESCAPE"}]}
        with patch.object(self.server, "backend", slow_backend):
            _, data = self.rpc("staff", "search_knowledge", {"question": "测试"})
        self.assertTrue(data["result"]["isError"])
        self.assertNotIn("SHOULD_NOT_ESCAPE", str(data))

    def test_driver_installation_stays_inside_user_workspace(self):
        workspace = self.hub.runtime_root / "runtime-staff/working/workspaces/demo"
        workspace.mkdir(parents=True)
        (workspace / "agent.json").write_text("{}")
        self.hub.install_driver("staff", "runtime-staff", "demo", "test-token",
                                "http://localhost:20600/mcp")
        self.assertTrue((workspace / "drivers/mcp/ragflow-gateway.yaml").is_file())
        (workspace / "drivers/mcp/ragflow-gateway.yaml").unlink()
        (workspace / "drivers/mcp").rmdir()
        outside = Path(self.tmp.name) / "outside"
        outside.mkdir()
        (workspace / "drivers/mcp").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            self.hub.install_driver("staff", "runtime-staff", "demo", "test-token",
                                    "http://localhost:20600/mcp")
        self.assertEqual(list(outside.iterdir()), [])

    def test_read_and_cross_dataset_guesses_never_reach_backend(self):
        _, data = self.rpc("staff", "read_document",
                                {"dataset_id": "restricted", "document_id": "secret-doc"})
        self.assertTrue(data["result"]["isError"])
        self.assertEqual(self.calls, [])
        _, data = self.rpc("staff", "list_documents", {"dataset_id": "public"})
        self.assertTrue(data["result"]["isError"])
        self.assertEqual(self.calls, [])
        _, data = self.rpc("leader", "read_document",
                                {"dataset_id": "public", "document_id": "secret-doc"})
        self.assertTrue(data["result"]["isError"])
        self.assertFalse(any(c[1].endswith("/chunks") for c in self.calls))

    def test_disabled_account_and_revoked_token_are_rejected(self):
        self.policy.revoke("admin", "staff")
        r, _ = self.rpc("staff", "list_knowledge_bases", {})
        self.assertEqual(r.status_code, 401)
        with sqlite3.connect(str(self.hub.path)) as db:
            db.execute("UPDATE hub_users SET disabled=1 WHERE user_id='leader'")
            db.commit()
        r, _ = self.rpc("leader", "list_knowledge_bases", {})
        self.assertEqual(r.status_code, 401)

    def test_admin_api_requires_hub_admin_and_csrf(self):
        r = self.client.get("/admin/api/state")
        self.assertEqual(r.status_code, 403)
        self.server.SESSIONS["test"] = {"token": "opaque", "csrf": "test-csrf",
                                      "expires": time_now() + 60}
        self.client.cookies.set(self.server.COOKIE, "test")
        async def verify(_):
            return {"user_id": "staff", "username": "admin", "role": "admin"}
        with patch.object(self.server, "verify_hub", verify):
            r = self.client.get("/admin/api/state")
            self.assertEqual(r.status_code, 403)
        async def verify_admin(_):
            return {"user_id": "leader", "username": "owner", "role": "user"}
        with patch.object(self.server, "verify_hub", verify_admin):
            r = self.client.get("/admin/api/state")
            self.assertEqual(r.status_code, 200)
            r = self.client.post("/admin/api/role", json={"user_id": "staff", "role_id": "privileged"})
            self.assertEqual(r.status_code, 403)
            r = self.client.post("/admin/api/role", headers={
                "Origin": "http://127.0.0.1:20600", "X-CSRF-Token": "test-csrf"},
                json={"user_id": "staff", "role_id": "privileged"})
            self.assertEqual(r.status_code, 200)
        self.server.SESSIONS.pop("test")

    def test_sso_only_designated_user_can_exchange_single_use_ticket(self):
        origin = "http://127.0.0.1:8088"
        async def verify(token):
            return {"user_id": "leader" if token == "owner-token" else "staff",
                    "username": "owner" if token == "owner-token" else "admin", "role": "user"}
        with patch.object(self.server, "verify_hub", verify):
            r = self.client.post("/admin/sso-ticket", headers={
                "Origin": "http://untrusted.example", "Authorization": "Bearer owner-token"})
            self.assertEqual(r.status_code, 403)
            r = self.client.post("/admin/sso-ticket", headers={
                "Origin": origin, "Authorization": "Bearer admin-token"})
            self.assertEqual(r.status_code, 403)
            r = self.client.options("/admin/sso-ticket", headers={"Origin": origin})
            self.assertEqual(r.headers["access-control-allow-origin"], origin)
            r = self.client.post("/admin/sso-ticket", headers={
                "Origin": origin, "Authorization": "Bearer owner-token"})
            self.assertEqual(r.status_code, 200)
            ticket = r.json()["ticket"]
            self.assertNotIn("owner-token", r.text)
            r = self.client.post("/admin/api/login", headers={"Origin": "http://127.0.0.1:20600"},
                                 json={"sso_ticket": ticket})
            self.assertEqual(r.status_code, 200)
            self.assertNotIn("owner-token", r.text)
            r = self.client.get("/admin/api/state")
            self.assertEqual(r.status_code, 200)
            r = self.client.post("/admin/api/login", headers={"Origin": "http://127.0.0.1:20600"},
                                 json={"sso_ticket": ticket})
            self.assertEqual(r.status_code, 403)
            self.server.SSO_TICKETS["expired-test"] = {"token": "owner-token", "expires": time_now() - 1}
            r = self.client.post("/admin/api/login", headers={"Origin": "http://127.0.0.1:20600"},
                                 json={"sso_ticket": "expired-test"})
            self.assertEqual(r.status_code, 403)

    def test_previous_other_user_session_is_rejected_after_access_policy_change(self):
        self.server.SESSIONS["old-admin"] = {"token": "opaque", "csrf": "test-csrf",
                                            "expires": time_now() + 60}
        self.client.cookies.set(self.server.COOKIE, "old-admin")
        async def verify(_):
            return {"user_id": "staff", "username": "admin", "role": "admin"}
        with patch.object(self.server, "verify_hub", verify):
            r = self.client.get("/admin/api/state")
            self.assertEqual(r.status_code, 403)
        self.server.SESSIONS.pop("old-admin")

    def test_asset_and_distribution_routes_reject_other_users_and_missing_csrf(self):
        for endpoint in ["asset/publish", "asset/source", "distribution/queue", "distribution/retry"]:
            r = self.client.post("/admin/api/" + endpoint, json={})
            self.assertEqual(r.status_code, 403)

    def test_source_skill_publication_requires_reviewed_digest(self):
        from knowledge_rbac.assets import fingerprint
        import base64
        self.server.SESSIONS["publisher"] = {"token": "opaque", "csrf": "publish-csrf",
                                           "expires": time_now() + 60}
        self.client.cookies.set(self.server.COOKIE, "publisher")
        async def verify(_):
            return {"user_id": "leader", "username": "owner", "role": "user"}
        bundle = {"SKILL.md": base64.b64encode(
            b"---\nname: example\ndescription: Example\n---\nInstructions").decode()}
        body = {"kind": "skill", "asset_key": "example", "version": "1", "name": "Example",
                "source": {"user_id": "staff", "runtime_id": "runtime-staff",
                           "agent_id": "default", "skill_name": "example"},
                "source_digest": "stale-digest"}
        headers = {"Origin": "http://127.0.0.1:20600", "X-CSRF-Token": "publish-csrf"}
        with patch.object(self.server, "verify_hub", verify), \
                patch.object(self.server, "snapshot_skill", return_value=bundle):
            r = self.client.post("/admin/api/asset/publish", headers=headers, json=body)
            self.assertEqual(r.status_code, 400)
            body["source_digest"] = fingerprint(bundle)
            r = self.client.post("/admin/api/asset/publish", headers=headers, json=body)
            self.assertEqual(r.status_code, 200)
            release = self.server.DISTRIBUTION.release(r.json()["release_id"])
            self.assertEqual(release["payload"], {"files": bundle})
        self.server.SESSIONS.pop("publisher")

    def test_role_management_http_single_assignment_and_disabled_owner_still_manages(self):
        self.server.SESSIONS["role-manager"] = {"token": "opaque", "csrf": "role-csrf",
                                              "expires": time_now() + 60}
        self.client.cookies.set(self.server.COOKIE, "role-manager")
        async def verify(_):
            return {"user_id": "leader", "username": "owner", "role": "user"}
        headers = {"Origin": "http://127.0.0.1:20600", "X-CSRF-Token": "role-csrf"}
        with patch.object(self.server, "verify_hub", verify):
            denied = self.client.post("/admin/api/roles/create", json={"name": "局长"})
            self.assertEqual(denied.status_code, 403)
            r = self.client.post("/admin/api/roles/create", headers=headers,
                                 json={"name": "局长", "description": "测试角色"})
            self.assertEqual(r.status_code, 200)
            role = r.json()["role_id"]
            r = self.client.post("/admin/api/role", headers=headers,
                                 json={"user_id": "staff", "role_id": role})
            self.assertEqual(r.status_code, 200)
            r = self.client.post("/admin/api/roles/update", headers=headers, json={
                "role_id": role, "name": "局长（试点）", "description": "", "enabled": False, "revision": 1})
            self.assertEqual(r.status_code, 200)
            r = self.client.post("/admin/api/role", headers=headers,
                                 json={"user_id": "leader", "role_id": role})
            self.assertEqual(r.status_code, 400)
            # Backend management identity is independent of business-role status.
            self.policy.update_role("leader", "privileged", name="领导", description="", enabled=False, revision=1)
            r = self.client.get("/admin/api/state")
            self.assertEqual(r.status_code, 200)
            self.assertFalse(next(s for s in r.json()["roles"] if s["id"] == role)["enabled"])
            self.assertEqual(next(s for s in r.json()["subjects"] if s["user_id"] == "staff")["role_id"], role)
        self.server.SESSIONS.pop("role-manager")

    def test_disabled_role_rejects_mcp_then_reenable_restores_existing_token(self):
        self.policy.update_role("leader", "ordinary", name="普通角色", description="", enabled=False, revision=1)
        r, _ = self.rpc("staff", "list_knowledge_bases", {})
        self.assertEqual(r.status_code, 401)
        self.policy.update_role("leader", "ordinary", name="普通角色", description="", enabled=True, revision=2)
        r, data = self.rpc("staff", "list_knowledge_bases", {})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(data["result"].get("isError", False))

    def test_tls_proxy_uses_configured_public_origin_and_secure_cookie(self):
        from dataclasses import replace
        async def verify(_):
            return {"user_id": "leader", "username": "owner", "role": "user"}
        settings = replace(self.server.SETTINGS, public_url="https://sidecar.example.test")
        with patch.object(self.server, "SETTINGS", settings), patch.object(self.server, "verify_hub", verify):
            r = self.client.post("/admin/api/login", headers={"Origin": "https://sidecar.example.test"},
                                 json={"hub_token": "synthetic-token"})
            self.assertEqual(r.status_code, 200)
            self.assertIn("Secure", r.headers["set-cookie"])
            self.assertIn("HttpOnly", r.headers["set-cookie"])
            r = self.client.post("/admin/api/login", headers={"Origin": "http://127.0.0.1:20600"},
                                 json={"hub_token": "synthetic-token"})
            self.assertEqual(r.status_code, 403)


def time_now():
    import time
    return time.time()


if __name__ == "__main__":
    unittest.main()
