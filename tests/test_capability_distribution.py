"""Behavioral contracts for publication, cross-user installs and durable retry."""
from __future__ import annotations

import asyncio
import base64
import io
import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from knowledge_rbac.assets import Distribution, snapshot_skill, fingerprint, validate_files
from knowledge_rbac.hub import HubDirectory
from knowledge_rbac.runtime_api import RuntimeUnavailable
from knowledge_rbac.store import Store, Denied

CONTENT = "---\nname: report-helper\ndescription: 合成测试技能\n---\n请先核对资料，再回答。\n"


def files(content=CONTENT):
    return {"SKILL.md": base64.b64encode(content.encode()).decode()}


class FakeRuntime:
    """Protocol fake persists actual installed files for whole-tree conflict checks."""
    def __init__(self, root):
        self.root = root
        self.online = True
        self.agents = {"default": {"id": "default", "description": ""}}
        self.prompts = {"default": "PRIVATE_PROMPT"}
        self.skill_lists = {"default": []}
        self.calls = []
        self.fail_prompt = False

    def connection(self, uid, rt):
        if not self.online:
            raise RuntimeUnavailable("目标用户运行时未启动，请用户登录后重试")
        return "http://127.0.0.1:1234", "never-exposed"

    async def request(self, uid, rt, method, path, *, agent_id=None, **kwargs):
        self.connection(uid, rt)
        self.calls.append((method, path, kwargs))
        if path == "/agents":
            if method == "GET":
                return {"agents": list(self.agents.values())}
            data = kwargs["json"]
            if data["id"] in self.agents:
                raise RuntimeUnavailable("conflict")
            self.agents[data["id"]] = data.copy()
            self.prompts[data["id"]] = "BUILTIN_DEFAULT"
            self.skill_lists[data["id"]] = []
            workspace = self.root / rt / "working/workspaces" / data["id"]
            workspace.mkdir(parents=True)
            (workspace / "agent.json").write_text(json.dumps(data))
            return {"id": data["id"]}
        if path.endswith("/workspace/files/AGENTS.md"):
            if method == "GET":
                return {"content": self.prompts[agent_id]}
            if self.fail_prompt:
                raise RuntimeUnavailable("模拟写入失败")
            self.prompts[agent_id] = kwargs["json"]["content"]
            return {"written": True}
        if path.endswith("/skills"):
            return self.skill_lists[agent_id]
        if path.endswith("/skills/upload"):
            name = kwargs["params"]["target_name"]
            data = kwargs["files"]["file"][1]
            folder = self.root / rt / "working/workspaces" / agent_id / "skills" / name
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for entry in z.infolist():
                    out = folder / entry.filename
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_bytes(z.read(entry))
            self.skill_lists[agent_id].append({"name": name})
            return {"count": 1, "imported": [name]}
        return {}

    @staticmethod
    def agent_path(agent, suffix=""):
        return "/agents/" + agent + suffix


class DistributionContracts(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        db = sqlite3.connect(str(root / "hub.db"))
        db.executescript("""
            CREATE TABLE hub_users(user_id TEXT,username TEXT,role TEXT,disabled INTEGER,
                deleted_at TEXT,created_at TEXT);
            CREATE TABLE runtimes(runtime_id TEXT,owner_user_id TEXT,deleted_at TEXT,
                desired_state TEXT,observed_state TEXT);
            INSERT INTO hub_users VALUES('owner','owner','user',0,NULL,'1');
            INSERT INTO hub_users VALUES('receiver','member','user',0,NULL,'2');
            INSERT INTO runtimes VALUES('rt','receiver',NULL,'running','running');
        """)
        db.close()
        self.hub = HubDirectory(root / "hub.db", root / "runtimes")
        workspace = self.hub.runtime_root / "rt/working/workspaces/default"
        workspace.mkdir(parents=True)
        (workspace / "agent.json").write_text('{"private_secret":"DO_NOT_COPY"}')
        (workspace / "credentials.yaml").write_text("private: DO_NOT_COPY")
        (workspace / "chats.json").write_text('["PRIVATE_CHAT"]')
        self.store = Store(root / "policy.db")
        self.store.seed([{"user_id": "receiver", "role": "user"}], [])
        self.distribution = Distribution(self.store, self.hub, "http://localhost/mcp")
        self.fake = FakeRuntime(self.hub.runtime_root)
        self.distribution.runtime = self.fake
        self.skill = self.distribution.publish("owner", {
            "kind": "skill", "asset_key": "helper", "version": "1.0", "name": "合成技能",
            "payload": {"files": files()}})

    def tearDown(self):
        self.tmp.cleanup()

    def template(self, **payload):
        return self.distribution.publish("owner", {
            "kind": "template", "asset_key": "analyst", "version": "1.0", "name": "合成分析员",
            "payload": {"prompt": "SHARED_INSTRUCTIONS_ONLY", "skills": [self.skill], "knowledge": False, **payload}})

    def enqueue(self, rid, agent=""):
        return self.distribution.enqueue("owner", {"release_id": rid, "request_id": "test-request-id-12345",
            "targets": [{"user_id": "receiver", "runtime_id": "rt", "agent_id": agent}]})[0]

    async def test_template_creates_independent_agent_without_copying_private_assets(self):
        job = self.enqueue(self.template())
        await self.distribution.drain()
        item = self.distribution.catalog()["jobs"][0]
        self.assertEqual(item["status"], "succeeded")
        agent = item["phase"]["agent_id"]
        self.assertEqual(self.fake.prompts[agent], "SHARED_INSTRUCTIONS_ONLY")
        posted = next(c[2]["json"] for c in self.fake.calls if c[:2] == ("POST", "/agents"))
        self.assertEqual(set(posted), {"id", "name", "description", "language", "skill_names"})
        folder = self.hub.runtime_root / "rt/working/workspaces" / agent
        self.assertFalse((folder / "credentials.yaml").exists())
        self.assertFalse((folder / "chats.json").exists())
        self.assertEqual(self.fake.prompts["default"], "PRIVATE_PROMPT")
        self.assertEqual(len(self.fake.skill_lists[agent]), 1)

    async def test_offline_failure_can_retry_without_duplicate_agents(self):
        rid = self.template()
        jid = self.enqueue(rid)
        self.fake.online = False
        await self.distribution.drain()
        self.assertEqual(self.distribution.catalog()["jobs"][0]["status"], "failed")
        self.assertEqual(len(self.fake.agents), 1)
        self.fake.online = True
        self.distribution.retry("owner", jid)
        await self.distribution.drain()
        self.assertEqual(self.distribution.catalog()["jobs"][0]["status"], "succeeded")
        self.assertEqual(self.enqueue(rid), jid)
        await self.distribution.drain()
        self.assertEqual(len(self.fake.agents), 2)

    async def test_partial_failure_resumes_and_rejects_private_prompt_edits(self):
        jid = self.enqueue(self.template())
        self.fake.fail_prompt = True
        await self.distribution.drain()
        item = self.distribution.catalog()["jobs"][0]
        self.assertTrue(item["phase"]["created"])
        self.assertEqual(item["status"], "failed")
        self.fake.prompts[item["phase"]["agent_id"]] = "USER_CHANGED_PROMPT"
        self.fake.fail_prompt = False
        self.distribution.retry("owner", jid)
        await self.distribution.drain()
        self.assertEqual(self.distribution.catalog()["jobs"][0]["status"], "failed")
        self.assertEqual(self.fake.prompts[item["phase"]["agent_id"]], "USER_CHANGED_PROMPT")

    async def test_skill_installs_through_native_upload_and_is_idempotent(self):
        jid = self.enqueue(self.skill, "default")
        await self.distribution.drain()
        job = self.distribution.catalog()["jobs"][0]
        self.assertEqual(job["status"], "succeeded")
        self.assertTrue(any(c[1].endswith("/skills/upload") for c in self.fake.calls))
        again = self.distribution.enqueue("owner", {"release_id": self.skill, "request_id": "another-request-id-123",
            "targets": [{"user_id": "receiver", "runtime_id": "rt", "agent_id": "default"}]})
        await self.distribution.drain()
        self.assertEqual(self.distribution.catalog()["jobs"][0]["status"], "succeeded")
        self.assertEqual(sum(c[1].endswith("/skills/upload") for c in self.fake.calls), 1)
        installed = job["phase"]["installed_skill"]
        folder = self.hub.runtime_root / "rt/working/workspaces/default/skills" / installed
        (folder / "SKILL.md").write_text("USER_EDITED")
        self.distribution.enqueue("owner", {"release_id": self.skill, "request_id": "third-request-id-12345",
            "targets": [{"user_id": "receiver", "runtime_id": "rt", "agent_id": "default"}]})
        await self.distribution.drain()
        self.assertEqual(self.distribution.catalog()["jobs"][0]["status"], "failed")
        self.assertEqual((folder / "SKILL.md").read_text(), "USER_EDITED")

    async def test_receiver_knowledge_credential_is_personal(self):
        self.enqueue(self.template(knowledge=True))
        await self.distribution.drain()
        job = self.distribution.catalog()["jobs"][0]
        self.assertEqual(job["status"], "succeeded")
        p = self.hub.runtime_root / "rt/working/workspaces" / job["phase"]["agent_id"] / "drivers/mcp/ragflow-gateway.yaml"
        import yaml
        token = yaml.safe_load(p.read_text())["endpoint"]["headers"]["Authorization"]["value"][7:]
        credential = self.store.resolve(token)
        self.assertEqual(credential["user_id"], "receiver")
        self.assertEqual(credential["runtime_id"], "rt")
        self.assertEqual(self.store.allowed("receiver", "read"), {})

    def test_versions_are_immutable_and_credentials_not_published(self):
        body = {"kind": "template", "asset_key": "same", "version": "1", "name": "演示",
                "payload": {"prompt": "hello", "credentials": "DO_NOT_PUBLISH", "memory": "PRIVATE"}}
        rid = self.distribution.publish("owner", body)
        self.assertNotIn("DO_NOT_PUBLISH", json.dumps(self.distribution.release(rid)))
        body["payload"]["prompt"] = "different"
        with self.assertRaises(ValueError):
            self.distribution.publish("owner", body)

    def test_bundle_rejects_traversal_hidden_credentials_and_missing_frontmatter(self):
        for name in ["../SKILL.md", "scripts/../../key", "assets/.env", "scripts/private.key", "/tmp/a"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_files({**files(), name: base64.b64encode(b"x").decode()})
        with self.assertRaises(ValueError):
            self.distribution.publish("owner", {"kind": "skill", "asset_key": "bad",
                "version": "1", "name": "bad", "payload": {"files": files("not a skill header")}})

    def test_source_snapshot_does_not_include_config_and_rejects_symlinks(self):
        skill = self.hub.runtime_root / "rt/working/workspaces/default/skills/source"
        (skill / "scripts").mkdir(parents=True)
        (skill / "SKILL.md").write_text(CONTENT)
        (skill / "config.json").write_text('{"secret":"DO_NOT_COPY"}')
        (skill / "scripts/helper.py").write_text("print('hello')")
        snap = snapshot_skill(self.hub, "receiver", "rt", "default", "source")
        self.assertEqual(set(snap), {"SKILL.md", "scripts/helper.py"})
        (skill / "scripts/linked.py").symlink_to(skill / "config.json")
        with self.assertRaises(ValueError):
            snapshot_skill(self.hub, "receiver", "rt", "default", "source")

    async def test_disabled_target_or_actor_cannot_receive_or_distribute(self):
        jid = self.enqueue(self.template())
        with sqlite3.connect(str(self.hub.path)) as db:
            db.execute("UPDATE hub_users SET disabled=1 WHERE user_id='owner'")
        await self.distribution.drain()
        self.assertEqual(self.distribution.catalog()["jobs"][0]["status"], "failed")
        self.assertEqual(len(self.fake.agents), 1)

    async def test_restart_marks_running_job_failed_then_retries_saved_phases(self):
        jid = self.enqueue(self.template())
        with self.store.connect() as db:
            db.execute("UPDATE distribution_jobs SET status='running' WHERE id=?", (jid,))
        restarted = Distribution(self.store, self.hub, "http://localhost/mcp")
        restarted.runtime = self.fake
        self.assertEqual(restarted.catalog()["jobs"][0]["status"], "failed")
        restarted.retry("owner", jid)
        await restarted.drain()
        self.assertEqual(restarted.catalog()["jobs"][0]["status"], "succeeded")

    def test_idempotency_key_cannot_be_reused_for_a_different_release(self):
        self.enqueue(self.template())
        with self.assertRaises(ValueError):
            self.enqueue(self.skill, "default")


if __name__ == "__main__":
    unittest.main()
