"""Immutable releases and durable, per-target distribution operations."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import os
import re
import stat
import time
import uuid
import zipfile
from pathlib import Path, PurePosixPath

from .runtime_api import RuntimeAPI, RuntimeUnavailable
from .store import Denied

MAX_BUNDLE = 3 * 1024 * 1024
MAX_FILES = 160
KEY = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,47}$")
VERSION = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}$")


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":")).encode()).hexdigest()


def skill_path(name):
    p = PurePosixPath(name)
    if "\\" in name or p.is_absolute() or str(p) != name or ".." in p.parts:
        raise ValueError("技能中有非法文件路径")
    if name != "SKILL.md" and (len(p.parts) < 2 or p.parts[0] not in ("scripts", "references", "assets")):
        raise ValueError("仅发布 SKILL.md、scripts/、references/ 和 assets/")
    if any(part.startswith(".") for part in p.parts):
        raise ValueError("技能包不能包含隐藏文件或凭证文件")
    if any(x in p.name.lower() for x in ("credentials", ".pem", ".key", ".p12", ".pfx")):
        raise ValueError("技能包不能包含凭证文件")
    return name


def validate_files(files):
    if not isinstance(files, dict) or "SKILL.md" not in files or len(files) > MAX_FILES:
        raise ValueError("技能必须包含 SKILL.md，文件数不能超过 160")
    total = 0
    for name, encoded in files.items():
        skill_path(name)
        data = base64.b64decode(encoded, validate=True)
        total += len(data)
        if total > MAX_BUNDLE:
            raise ValueError("技能解包后不能超过 3 MB")
    content = base64.b64decode(files["SKILL.md"], validate=True).decode("utf-8")
    if not content.strip() or len(content) > 120000:
        raise ValueError("SKILL.md 为空或过长")
    return files


def bundle_bytes(files):
    validate_files(files)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in sorted(files.items()):
            z.writestr(name, base64.b64decode(data, validate=True))
    return out.getvalue()


def snapshot_skill(hub, uid, rt, agent, name):
    if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,127}", name):
        raise ValueError("技能名必须是字母开头的英文、数字、下划线或连字符")
    if not any(a["runtime_id"] == rt and a["agent_id"] == agent for a in hub.agents(uid)):
        raise ValueError("来源智能体不存在")
    relative = Path(rt) / "working/workspaces" / agent / "skills" / name
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("非法技能路径")
    fd = os.open(hub.runtime_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in relative.parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        files = {}

        def walk(directory_fd, prefix=""):
            if len(PurePosixPath(prefix).parts) > 12:
                raise ValueError("技能附件目录嵌套过深")
            with os.scandir(directory_fd) as entries:
                listing = list(entries)
            for entry in listing:
                name = prefix + entry.name
                # Root-level configuration, sessions and hidden assets are excluded.
                if not prefix and entry.name not in ("SKILL.md", "scripts", "references", "assets"):
                    continue
                if entry.is_symlink():
                    raise ValueError("技能包含符号链接，不能发布")
                if entry.is_dir(follow_symlinks=False):
                    if prefix and not any(name.startswith(x + "/") for x in ("scripts", "references", "assets")):
                        raise ValueError("非法技能目录")
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                    try:
                        walk(child, name + "/")
                    finally:
                        os.close(child)
                else:
                    skill_path(name)
                    file_fd = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                    with os.fdopen(file_fd, "rb") as stream:
                        info = os.fstat(stream.fileno())
                        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BUNDLE:
                            raise ValueError("技能包含不支持的文件或过大文件")
                        data = stream.read(MAX_BUNDLE + 1)
                    files[name] = base64.b64encode(data).decode()
                    if len(files) > MAX_FILES or sum(len(v) for v in files.values()) > 4 * MAX_BUNDLE // 3 + 1024:
                        raise ValueError("技能包超过上限")
        walk(fd)
        return validate_files(files)
    finally:
        os.close(fd)


class Distribution:
    def __init__(self, policy, hub, mcp_url):
        self.policy, self.hub, self.mcp_url = policy, hub, mcp_url
        self.runtime = RuntimeAPI(hub)
        self._lock = asyncio.Lock()
        self._task = None
        with policy.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS asset_releases(
                    id TEXT PRIMARY KEY, kind TEXT NOT NULL, asset_key TEXT NOT NULL,
                    version TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL,
                    payload_json TEXT NOT NULL, digest TEXT NOT NULL, actor TEXT NOT NULL,
                    created_at INTEGER NOT NULL, UNIQUE(kind,asset_key,version));
                CREATE TABLE IF NOT EXISTS distribution_jobs(
                    id TEXT PRIMARY KEY, batch_key TEXT NOT NULL, release_id TEXT NOT NULL,
                    user_id TEXT NOT NULL, runtime_id TEXT NOT NULL, agent_id TEXT NOT NULL,
                    actor TEXT NOT NULL, status TEXT NOT NULL, phase_json TEXT NOT NULL,
                    error TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                    FOREIGN KEY(release_id) REFERENCES asset_releases(id),
                    UNIQUE(batch_key,user_id,runtime_id,agent_id));
            """)
            db.execute("UPDATE distribution_jobs SET status='failed',error='服务重启中断，请重试',updated_at=? "
                       "WHERE status='running'", (int(time.time()),))

    def catalog(self):
        with self.policy.connect() as db:
            assets = [dict(r) for r in db.execute(
                "SELECT id,kind,asset_key,version,name,description,digest,actor,created_at "
                "FROM asset_releases ORDER BY created_at DESC,rowid DESC")]
            jobs = [dict(r) for r in db.execute(
                "SELECT j.*,a.name AS asset_name,a.version,a.kind FROM distribution_jobs j "
                "JOIN asset_releases a ON a.id=j.release_id ORDER BY j.created_at DESC,j.rowid DESC LIMIT 150")]
        for job in jobs:
            job["phase"] = json.loads(job.pop("phase_json"))
        return {"releases": assets, "jobs": jobs}

    def release(self, release_id):
        with self.policy.connect() as db:
            row = db.execute("SELECT * FROM asset_releases WHERE id=?", (release_id,)).fetchone()
        if not row:
            raise ValueError("发布版本不存在")
        result = dict(row)
        result["payload"] = json.loads(result.pop("payload_json"))
        return result

    def publish(self, actor, body):
        kind = body.get("kind")
        if kind not in ("template", "skill"):
            raise ValueError("未知发布类型")
        key, version = body.get("asset_key", ""), body.get("version", "")
        if not KEY.fullmatch(key) or not VERSION.fullmatch(version):
            raise ValueError("标识用英文字母开头的英文/数字/_/-，版本用英文/数字/点/_/-")
        name, description = body.get("name", "").strip(), body.get("description", "").strip()
        if not name or len(name) > 100 or len(description) > 1000:
            raise ValueError("名称为空或名称、描述过长")
        payload = body.get("payload", {})
        if kind == "template":
            prompt = payload.get("prompt", "")
            deps = payload.get("skills", [])
            if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 100000:
                raise ValueError("请填写不超过十万字的模板指令")
            if not isinstance(deps, list) or len(deps) > 20 or len(deps) != len(set(deps)):
                raise ValueError("技能依赖重复或过多")
            for dep in deps:
                if self.release(dep)["kind"] != "skill":
                    raise ValueError("模板依赖只能是技能版本")
            knowledge = payload.get("knowledge", False)
            if type(knowledge) is not bool:
                raise ValueError("知识库选项无效")
            payload = {"prompt": prompt, "skills": deps, "knowledge": knowledge}
        else:
            files = validate_files(payload.get("files", {}))
            # Require the native SKILL.md header, so invalid bundles fail at publication.
            content = base64.b64decode(files["SKILL.md"]).decode("utf-8")
            if not content.lstrip().startswith("---"):
                raise ValueError("SKILL.md 需要 YAML 头，包含 name 和 description")
            import yaml
            parts = content.lstrip().split("---", 2)
            try:
                meta = yaml.safe_load(parts[1]) if len(parts) == 3 else None
            except yaml.YAMLError as e:
                raise ValueError("SKILL.md 的 YAML 头格式错误") from e
            if not isinstance(meta, dict) or not isinstance(meta.get("name"), str) or not meta["name"].strip() or not isinstance(meta.get("description"), str) or not meta["description"].strip():
                raise ValueError("SKILL.md 需要 name 和 description")
            payload = {"files": files}
        digest, rid = fingerprint({"name": name, "description": description, "payload": payload}), uuid.uuid4().hex
        with self.policy.connect() as db:
            existing = db.execute("SELECT id,digest FROM asset_releases WHERE kind=? AND asset_key=? AND version=?",
                                  (kind, key, version)).fetchone()
            if existing:
                if existing["digest"] == digest:
                    return existing["id"]
                raise ValueError("同标识同版本已发布，内容不可变，请修改版本号")
            db.execute("INSERT INTO asset_releases VALUES(?,?,?,?,?,?,?,?,?,?)", (
                rid, kind, key, version, name, description, json.dumps(payload, ensure_ascii=False),
                digest, actor, int(time.time())))
            self.policy._event(db, actor, "asset.publish", True, rid, kind + ":" + key + "@" + version)
        return rid

    def enqueue(self, actor, body):
        release = self.release(body["release_id"])
        batch = body.get("request_id", "")
        if not isinstance(batch, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{16,80}", batch):
            raise ValueError("请刷新页面后重新提交")
        targets = body.get("targets", [])
        if not isinstance(targets, list) or not 1 <= len(targets) <= 50:
            raise ValueError("请选择 1 至 50 个分发目标")
        normalized = []
        for t in targets:
            uid, rt = t["user_id"], t["runtime_id"]
            self.hub.require_user(uid, rt)
            agent = t.get("agent_id", "") if release["kind"] == "skill" else ""
            if release["kind"] == "skill" and not any(
                    a["runtime_id"] == rt and a["agent_id"] == agent for a in self.hub.agents(uid)):
                raise ValueError("目标智能体不存在")
            normalized.append((uid, rt, agent))
        if len(normalized) != len(set(normalized)):
            raise ValueError("目标重复")
        ids = []
        with self.policy.connect() as db:
            # A reused idempotency key may not change the batch's meaning.
            previous = db.execute("SELECT release_id,user_id,runtime_id,agent_id FROM distribution_jobs "
                                  "WHERE batch_key=?", (batch,)).fetchall()
            if previous and (any(r["release_id"] != release["id"] for r in previous) or
                             set((r["user_id"], r["runtime_id"], r["agent_id"]) for r in previous) != set(normalized)):
                raise ValueError("提交标识已使用，请重新选择后提交")
            for uid, rt, agent in normalized:
                old = db.execute("SELECT id FROM distribution_jobs WHERE batch_key=? AND user_id=? "
                                 "AND runtime_id=? AND agent_id=?", (batch, uid, rt, agent)).fetchone()
                if old:
                    ids.append(old["id"])
                    continue
                job_id, now = uuid.uuid4().hex, int(time.time())
                db.execute("INSERT INTO distribution_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                           (job_id, batch, release["id"], uid, rt, agent, actor, "queued", "{}", "", now, now))
                ids.append(job_id)
            self.policy._event(db, actor, "distribution.queue", True, release["id"], str(len(ids)) + " targets")
        return ids

    def retry(self, actor, job_id):
        with self.policy.connect() as db:
            row = db.execute("SELECT * FROM distribution_jobs WHERE id=?", (job_id,)).fetchone()
            if not row or row["status"] != "failed":
                raise ValueError("只能重试失败任务")
            self.hub.require_user(row["user_id"], row["runtime_id"])
            db.execute("UPDATE distribution_jobs SET status='queued',error='',updated_at=? WHERE id=?",
                       (int(time.time()), job_id))
            self.policy._event(db, actor, "distribution.retry", True, job_id)

    def kick(self):
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self.drain())

    def save_phase(self, job, phase):
        with self.policy.connect() as db:
            db.execute("UPDATE distribution_jobs SET phase_json=?,updated_at=? WHERE id=?",
                       (json.dumps(phase), int(time.time()), job["id"]))

    async def drain(self):
        async with self._lock:
            while True:
                with self.policy.connect() as db:
                    row = db.execute("SELECT * FROM distribution_jobs WHERE status='queued' "
                                     "ORDER BY created_at,rowid LIMIT 1").fetchone()
                    if not row:
                        return
                    job = dict(row)
                    db.execute("UPDATE distribution_jobs SET status='running',updated_at=? WHERE id=?",
                               (int(time.time()), job["id"]))
                try:
                    await self.execute(job)
                    status, error = "succeeded", ""
                except asyncio.CancelledError:
                    self.finish(job, "failed", "操作被中断，请重试")
                    raise
                except Exception as e:
                    status = "failed"
                    if isinstance(e, (ValueError, Denied, RuntimeUnavailable)):
                        error = str(e)[:240]
                    elif isinstance(e, OSError):
                        error = "文件或服务凭证不可用，请检查运行时状态"
                    else:
                        error = "操作失败，请检查服务连接后重试"
                self.finish(job, status, error)

    def finish(self, job, status, error):
        with self.policy.connect() as db:
            db.execute("UPDATE distribution_jobs SET status=?,error=?,updated_at=? WHERE id=?",
                       (status, error, int(time.time()), job["id"]))
            self.policy._event(db, job["actor"], "distribution." + status,
                               status == "succeeded", job["id"], error)

    async def execute(self, job):
        uid, rt = job["user_id"], job["runtime_id"]
        release = self.release(job["release_id"])
        payload, phase = release["payload"], json.loads(job["phase_json"])
        self.hub.require_user(job["actor"])
        self.runtime.connection(uid, rt)
        if release["kind"] == "skill":
            await self.install_skill(uid, rt, job["agent_id"], release, phase, job)
            return
        agent = "dist_" + job["id"][:24]
        phase["agent_id"] = agent
        self.save_phase(job, phase)
        api = self.runtime
        marker = "[distribution:" + job["id"] + "]"
        agents = await api.request(uid, rt, "GET", "/agents")
        existing = next((a for a in agents.get("agents", []) if a["id"] == agent), None)
        if not phase.get("created"):
            if existing:
                # Crash between create and journal save: do not assume ownership.
                raise ValueError("目标助手已存在但创建阶段未确认，未覆盖；请检查后新建分发")
            # Persist target before call; a timeout won't create another id on retry.
            await api.request(uid, rt, "POST", "/agents", json={
                "id": agent, "name": release["name"], "description": (release["description"] + "\n" + marker)[:1500],
                "language": "zh", "skill_names": []})
            phase["created"] = True
            self.save_phase(job, phase)
        elif not existing or marker not in existing.get("description", ""):
            raise ValueError("分发助手已被删除或归属标记改变，未覆盖")
        if not phase.get("prompt"):
            p = api.agent_path(agent, "/workspace/files/AGENTS.md")
            current = await api.request(uid, rt, "GET", p, agent_id=agent)
            current_hash = fingerprint(current.get("content", ""))
            if phase.get("original_prompt") and current_hash not in (
                    phase["original_prompt"], fingerprint(payload["prompt"])):
                raise ValueError("助手指令已被修改，重试未覆盖；请检查后重新分发")
            phase.setdefault("original_prompt", current_hash)
            self.save_phase(job, phase)
            await api.request(uid, rt, "PUT", p, agent_id=agent, json={"content": payload["prompt"]})
            phase["prompt"] = True
            self.save_phase(job, phase)
        for dep in payload["skills"]:
            await self.install_skill(uid, rt, agent, self.release(dep), phase, job)
        if payload["knowledge"] and not phase.get("knowledge"):
            token = self.policy.issue(job["actor"], uid, rt, label=agent)
            try:
                self.hub.install_driver(uid, rt, agent, token, self.mcp_url)
            except Exception:
                with self.policy.connect() as db:
                    db.execute("UPDATE credentials SET revoked_at=? WHERE digest=?",
                               (int(time.time()), self.policy.digest(token)))
                raise
            phase["knowledge"] = True
            self.save_phase(job, phase)
        # The native config update reloads prompt/skills/MCP on the new agent only.
        current_config = await api.request(uid, rt, "GET", api.agent_path(agent), agent_id=agent)
        await api.request(uid, rt, "PUT", api.agent_path(agent), agent_id=agent,
                          json={"id": agent, "name": current_config.get("name", release["name"])})
        phase["ready"] = True
        self.save_phase(job, phase)

    async def install_skill(self, uid, rt, agent, release, phase, job):
        # Managed version-specific name avoids overwriting personal or older skills.
        name = release["asset_key"] + "_" + release["id"][:10]
        done_key = "skill:" + release["id"]
        if phase.get(done_key):
            return
        files = release["payload"]["files"]
        body = bundle_bytes(files)
        current = await self.runtime.request(uid, rt, "GET",
            self.runtime.agent_path(agent, "/skills"), agent_id=agent)
        existing = next((x for x in current if x.get("name") == name), None)
        if existing:
            # Compare the whole tree including attachments; never overwrite differences.
            on_disk = snapshot_skill(self.hub, uid, rt, agent, name)
            if fingerprint(on_disk) != fingerprint(files):
                raise ValueError("目标存在同名但不同内容的技能，未覆盖")
        else:
            result = await self.runtime.request(uid, rt, "POST",
                self.runtime.agent_path(agent, "/skills/upload"), agent_id=agent,
                params={"enable": "true", "target_name": name},
                files={"file": (name + ".zip", body, "application/zip")})
            if not result.get("count", 0) and not result.get("imported") and not result.get("installed"):
                # Follow up by checking native listing; response shapes vary by version.
                check = await self.runtime.request(uid, rt, "GET",
                    self.runtime.agent_path(agent, "/skills"), agent_id=agent)
                if not any(s.get("name") == name for s in check):
                    raise RuntimeUnavailable("原生技能安装未确认，请查看扫描或冲突结果")
        phase[done_key] = True
        phase["installed_skill"] = name
        self.save_phase(job, phase)
