"""MCP retrieval and administration for the explicitly configured Hub owner."""
from __future__ import annotations

import asyncio
import contextvars
import json
import os
import secrets
import time
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

from .hub import HubDirectory
from .store import Denied, Store
from .assets import Distribution, snapshot_skill
from .runtime_api import RuntimeUnavailable
from .config import Settings, origin as url_origin

SETTINGS = Settings.load()
BASE = SETTINGS.data_dir
HUB_URL = SETTINGS.hub_url
MCP_URL = SETTINGS.mcp_url
POLICY = Store(BASE / "data" / "permissions.sqlite3", credential_days=SETTINGS.credential_days)
HUB = HubDirectory(SETTINGS.hub_dir / "control.db", SETTINGS.hub_dir / "runtimes")
DISTRIBUTION = Distribution(POLICY, HUB, MCP_URL)
CURRENT = contextvars.ContextVar("knowledge_principal", default=None)
SESSIONS = {}
SSO_TICKETS = {}
def resolve_admin_user_id():
    configured = SETTINGS.admin_user_id
    if configured:
        return configured
    if not SETTINGS.admin_username:
        return ""
    try:
        import sqlite3
        path = SETTINGS.hub_dir / "control.db"
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=3) as db:
            row = db.execute(
                "SELECT user_id FROM hub_users WHERE username=? AND disabled=0 "
                "AND deleted_at IS NULL", (SETTINGS.admin_username,)).fetchone()
        return str(row[0]) if row else ""
    except sqlite3.Error:
        return ""


ADMIN_USER_ID = resolve_admin_user_id()
TRUSTED_HUB_ORIGINS = set(SETTINGS.hub_origins)
LOGIN_ATTEMPTS = defaultdict(list)
COOKIE = SETTINGS.cookie_name
SESSION_TTL = 8 * 3600


RAGFLOW_URL = SETTINGS.ragflow_url
RAGFLOW_KEY = SETTINGS.ragflow_key


class BackendError(Exception):
    pass


async def backend(method, path, **kwargs):
    async with httpx.AsyncClient(timeout=60, trust_env=False) as client:
        response = await client.request(method, RAGFLOW_URL + path,
            headers={"Authorization": "Bearer " + RAGFLOW_KEY}, **kwargs)
        response.raise_for_status()
        data = response.json()
        if data.get("code") != 0:
            # Backend error messages may contain internal details; don't relay them.
            raise BackendError("知识库后端返回错误，请检查服务日志")
        return data.get("data")


def principal():
    user = CURRENT.get()
    if user is None:
        raise Denied("未认证")
    return user


def checked(action, dataset_id=None):
    user = principal()
    # Recheck each tool call, including accounts revoked after HTTP authentication.
    POLICY.resolve(user["bearer"])
    HUB.require_user(user["user_id"], user["runtime_id"])
    if dataset_id is not None:
        POLICY.require(user["user_id"], action, dataset_id)
    return user


mcp = FastMCP("organization-knowledge", stateless_http=True,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True,
        allowed_hosts=list(SETTINGS.mcp_hosts),
        allowed_origins=list(SETTINGS.mcp_origins)))


@mcp.tool()
async def list_knowledge_bases() -> str:
    """列出当前用户可访问的知识库及搜索、正文读取权限。"""
    u = checked("search")
    search = POLICY.allowed(u["user_id"], "search")
    read = POLICY.allowed(u["user_id"], "read")
    POLICY.event(u["user_id"], "knowledge.list", True)
    return json.dumps([{"id": k, "name": (search | read)[k], "search": k in search, "read": k in read}
                       for k in sorted(set(search) | set(read))], ensure_ascii=False)


@mcp.tool()
async def search_knowledge(question: str, top_n: int = 6) -> str:
    """仅检索当前用户被授权搜索的知识库，返回有来源标识的资料片段。"""
    u = checked("search")
    allowed = POLICY.allowed(u["user_id"], "search")
    if not allowed:
        POLICY.event(u["user_id"], "knowledge.search", False)
        raise Denied("当前角色没有可搜索的知识库，请联系管理员授权")
    data = await backend("POST", "/api/v1/retrieval", json={
        "question": question[:8000], "dataset_ids": list(allowed), "page": 1,
        "page_size": max(1, min(top_n, 20)), "similarity_threshold": 0.2,
        "vector_similarity_weight": 0.3, "top_k": 1024, "keyword": False})
    chunks = (data or {}).get("chunks") or []
    checked("search")
    allowed = POLICY.allowed(u["user_id"], "search")
    # Backend filtering is necessary, but validate the returned resource IDs too.
    for ch in chunks:
        kb = ch.get("dataset_id") or ch.get("kb_id")
        ids = kb if isinstance(kb, list) else [kb]
        if not ids or not all(x in allowed for x in ids):
            POLICY.event(u["user_id"], "knowledge.search", False, detail="backend scope mismatch")
            raise Denied("检索结果的知识库范围无法确认")
    POLICY.event(u["user_id"], "knowledge.search", True, detail=f"{len(chunks)} chunks")
    return json.dumps([{
        "dataset_id": ch.get("dataset_id") or ch.get("kb_id"),
        "document_id": ch.get("document_id"), "chunk_id": ch.get("id"),
        "source": ch.get("document_keyword"), "content": ch.get("content", "")[:20000],
    } for ch in chunks], ensure_ascii=False) if chunks else "在授权知识库中未找到相关资料。"


@mcp.tool()
async def list_documents(dataset_id: str, page: int = 1, page_size: int = 100) -> str:
    """列出当前用户有正文读取权限的知识库文档；不可读取的库不暴露目录。"""
    u = checked("read", dataset_id)
    data = await backend("GET", f"/api/v1/datasets/{safe_id(dataset_id)}/documents",
                         params={"page": max(1, page), "page_size": max(1, min(page_size, 100))})
    checked("read", dataset_id)
    POLICY.event(u["user_id"], "document.list", True, dataset_id)
    return json.dumps({"total": (data or {}).get("total"), "docs": [
        {"id": d.get("id"), "name": d.get("name"), "chunk_count": d.get("chunk_count")}
        for d in (data or {}).get("docs", [])]}, ensure_ascii=False)


def safe_id(value):
    if not value or len(value) > 160 or not all(c.isalnum() or c in "_-" for c in value):
        raise ValueError("非法资源 ID")
    return value


@mcp.tool()
async def read_document(dataset_id: str, document_id: str, max_chunks: int = 40,
                        page: int = 1) -> str:
    """分页读取有权限的文档正文；document_id 可通过 list_documents 获取。"""
    u = checked("read", dataset_id)
    dataset_id, document_id = safe_id(dataset_id), safe_id(document_id)
    # Establish ownership independently before fetching any document chunks.
    meta = await backend("GET", f"/api/v1/datasets/{dataset_id}/documents",
                         params={"id": document_id, "page": 1, "page_size": 100})
    matches = [d for d in (meta or {}).get("docs", []) if d.get("id") == document_id]
    if not matches:
        POLICY.event(u["user_id"], "document.read", False, dataset_id, "document not in dataset")
        raise Denied("文档不存在或不属于该知识库")
    data = await backend("GET", f"/api/v1/datasets/{dataset_id}/documents/{document_id}/chunks",
                         params={"page": max(1, page), "page_size": max(1, min(max_chunks, 100))})
    checked("read", dataset_id)
    POLICY.event(u["user_id"], "document.read", True, dataset_id, document_id)
    chunks, remaining = [], 100000
    for item in (data or {}).get("chunks", []):
        content = item.get("content", "")[:min(30000, remaining)]
        chunks.append({"id": item.get("id"), "content": content})
        remaining -= len(content)
        if remaining <= 0:
            break
    return json.dumps({"document_id": document_id, "source": matches[0].get("name"),
                      "total": (data or {}).get("total"), "page": max(1, page),
                      "truncated": remaining <= 0, "chunks": chunks}, ensure_ascii=False)


class Authentication(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if not request.url.path.startswith("/mcp"):
            return await call_next(request)
        raw = request.headers.get("authorization", "")
        if not raw.startswith("Bearer "):
            return JSONResponse({"error": "missing bearer token"}, status_code=401)
        token = raw[7:].strip()
        try:
            user = POLICY.resolve(token)
            HUB.require_user(user["user_id"], user["runtime_id"])
        except Denied:
            return JSONResponse({"error": "invalid or revoked credential"}, status_code=401)
        except Exception:
            return JSONResponse({"error": "identity service unavailable"}, status_code=503)
        user["bearer"] = token
        mark = CURRENT.set(user)
        try:
            return await call_next(request)
        finally:
            CURRENT.reset(mark)


async def verify_hub(token):
    async with httpx.AsyncClient(timeout=8, trust_env=False) as client:
        response = await client.get(HUB_URL + "/api/auth/verify",
                                     headers={"Authorization": "Bearer " + token})
    if response.status_code != 200:
        raise Denied("平台登录已失效，请重新登录")
    user = response.json().get("user", {})
    if not user.get("user_id"):
        raise Denied("无法确认平台身份")
    return user


def same_origin(request):
    origin = request.headers.get("origin")
    if not origin or origin != url_origin(SETTINGS.public_url):
        raise Denied("请求来源无效，请从本页面操作")


def require_console_admin(user):
    if not ADMIN_USER_ID or user.get("user_id") != ADMIN_USER_ID:
        raise Denied("仅部署配置中指定的 Hub 账号可以进入权限后台")


async def sso_ticket(request):
    origin = request.headers.get("origin", "")
    if origin not in TRUSTED_HUB_ORIGINS:
        return JSONResponse({"error": "不受信任的登录入口"}, status_code=403)
    headers = {"Access-Control-Allow-Origin": origin, "Vary": "Origin",
               "Access-Control-Allow-Methods": "POST, OPTIONS",
               "Access-Control-Allow-Headers": "Authorization, Content-Type"}
    if request.method == "OPTIONS":
        return JSONResponse({"ok": True}, headers=headers)
    try:
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            raise Denied("请先登录 QwenPaw")
        token = auth[7:].strip()
        user = await verify_hub(token)
        require_console_admin(user)
        now = time.time()
        for k in list(SSO_TICKETS):
            if SSO_TICKETS[k]["expires"] < now:
                del SSO_TICKETS[k]
        ticket = secrets.token_urlsafe(40)
        SSO_TICKETS[ticket] = {"token": token, "expires": now + 60}
        return JSONResponse({"ticket": ticket}, headers=headers)
    except Denied as e:
        return JSONResponse({"error": str(e)}, status_code=403, headers=headers)
    except httpx.HTTPError:
        return JSONResponse({"error": "平台身份服务不可用"}, status_code=503, headers=headers)


async def admin_session(request):
    sid = request.cookies.get(COOKIE, "")
    session = SESSIONS.get(sid)
    if not session or session["expires"] < time.time():
        SESSIONS.pop(sid, None)
        raise Denied("请使用配置的管理账号登录，或从已登录的 QwenPaw 进入")
    user = await verify_hub(session["token"])
    require_console_admin(user)
    if request.method != "GET":
        same_origin(request)
        if not secrets.compare_digest(request.headers.get("x-csrf-token", ""), session["csrf"]):
            raise Denied("页面会话已过期，请刷新")
    return user, session


async def login(request):
    same_origin(request)
    now = time.time()
    ip = request.client.host if request.client else "unknown"
    LOGIN_ATTEMPTS[ip] = [t for t in LOGIN_ATTEMPTS[ip] if t > now - 60]
    if len(LOGIN_ATTEMPTS[ip]) >= 8:
        return JSONResponse({"error": "登录尝试过多，请一分钟后重试"}, status_code=429)
    LOGIN_ATTEMPTS[ip].append(now)
    body = await request.json()
    token = body.get("hub_token")
    if "sso_ticket" in body:
        ticket = SSO_TICKETS.pop(str(body["sso_ticket"]), None)
        if not ticket or ticket["expires"] < now:
            raise Denied("快捷登录已过期，请从 QwenPaw 重新点击进入")
        token = ticket["token"]
    if not isinstance(token, str) or not token:
        async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
            response = await client.post(HUB_URL + "/api/auth/login", json={
                "username": str(body.get("username", ""))[:128],
                "password": str(body.get("password", ""))[:512]})
        if response.status_code != 200:
            return JSONResponse({"error": "账号或密码错误，或账号已禁用"}, status_code=401)
        data = response.json()
        token = data.get("token") or data.get("access_token")
    if not token:
        raise Denied("平台未返回有效登录凭证")
    user = await verify_hub(token)
    try:
        require_console_admin(user)
    except Denied:
        POLICY.event(user["user_id"], "admin.login", False)
        raise
    # Only the Hub token lives in server memory; no password is saved.
    sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    for k in list(SESSIONS):
        if SESSIONS[k]["expires"] < now:
            del SESSIONS[k]
    SESSIONS[sid] = {"token": token, "csrf": csrf, "expires": now + SESSION_TTL}
    POLICY.event(user["user_id"], "admin.login", True)
    result = JSONResponse({"user": user, "csrf": csrf})
    result.set_cookie(COOKIE, sid, max_age=SESSION_TTL, path="/admin",
                      httponly=True, samesite="strict", secure=SETTINGS.public_url.startswith("https://"))
    return result


async def admin_api(request):
    try:
        if request.headers.get("content-length", "0").isdigit() and int(request.headers.get("content-length", 0)) > 512000:
            return JSONResponse({"error": "请求过大"}, status_code=413)
        path = request.path_params["path"]
        if path == "login" and request.method == "POST":
            return await login(request)
        user, session = await admin_session(request)
        actor = user["user_id"]
        if path == "session" and request.method == "GET":
            return JSONResponse({"user": user, "csrf": session["csrf"]})
        if path == "state" and request.method == "GET":
            state = POLICY.snapshot()
            state["users"] = HUB.users()
            state["agents"] = {u["user_id"]: HUB.agents(u["user_id"])
                               for u in state["users"] if not u["disabled"]}
            state["mcp_url"] = MCP_URL
            state["runtimes"] = {u["user_id"]: HUB.runtimes(u["user_id"])
                                 for u in state["users"] if not u["disabled"]}
            state.update(DISTRIBUTION.catalog())
            return JSONResponse(state)
        body = await request.json() if request.method == "POST" else {}
        if request.method != "POST":
            return JSONResponse({"error": "接口不存在"}, status_code=404)
        if path == "logout":
            SESSIONS.pop(request.cookies.get(COOKIE, ""), None)
            result = JSONResponse({"ok": True})
            result.delete_cookie(COOKIE, path="/admin")
            return result
        if path == "asset/publish":
            if body.get("kind") == "skill" and "source" in body:
                source = body["source"]
                # Publishing is explicit; only the selected skill's allowed files.
                files = await asyncio.to_thread(snapshot_skill, HUB, source["user_id"],
                    source["runtime_id"], source["agent_id"], source["skill_name"])
                from .assets import fingerprint
                if not body.get("source_digest") or body["source_digest"] != fingerprint(files):
                    raise ValueError("来源技能已改变，请重新预览后发布")
                body["payload"] = {"files": files}
            release_id = DISTRIBUTION.publish(actor, body)
            return JSONResponse({"ok": True, "release_id": release_id})
        elif path == "asset/detail":
            release = DISTRIBUTION.release(body["release_id"])
            payload = release["payload"]
            if release["kind"] == "skill":
                # Never echo source credentials; only the immutable published bundle.
                import base64
                payload = {"content": base64.b64decode(payload["files"]["SKILL.md"]).decode("utf-8"),
                           "files": list(payload["files"])}
            return JSONResponse({"release": {k: v for k, v in release.items()
                                 if k != "payload"}, "payload": payload})
        elif path == "asset/source":
            uid, rt, agent = body["user_id"], body["runtime_id"], body["agent_id"]
            HUB.require_user(uid, rt)
            api = DISTRIBUTION.runtime
            if not any(a["runtime_id"] == rt and a["agent_id"] == agent for a in HUB.agents(uid)):
                raise ValueError("来源智能体不存在")
            if body.get("kind") == "skills":
                items = await api.request(uid, rt, "GET", api.agent_path(agent, "/skills"), agent_id=agent)
                return JSONResponse({"skills": [{"name": s["name"], "description": s.get("description", "")}
                                                for s in items]})
            if body.get("kind") == "skill-preview":
                files = await asyncio.to_thread(snapshot_skill, HUB, uid, rt, agent, body["skill_name"])
                import base64
                from .assets import fingerprint
                return JSONResponse({"content": base64.b64decode(files["SKILL.md"]).decode("utf-8"),
                                     "files": list(files), "source_digest": fingerprint(files)})
            data = await api.request(uid, rt, "GET",
                api.agent_path(agent, "/workspace/files/AGENTS.md"), agent_id=agent)
            return JSONResponse({"prompt": data.get("content", ""),
                                 "notice": "仅展开 AGENTS.md，请确认不含个人资料或密钥后再发布"})
        elif path == "distribution/queue":
            ids = DISTRIBUTION.enqueue(actor, body)
            DISTRIBUTION.kick()
            return JSONResponse({"ok": True, "jobs": ids})
        elif path == "distribution/retry":
            DISTRIBUTION.retry(actor, body["job_id"])
            DISTRIBUTION.kick()
        elif path == "roles/create":
            rid = POLICY.create_role(actor, body["name"], body.get("description", ""), body.get("enabled", True))
            return JSONResponse({"ok": True, "role_id": rid})
        elif path == "roles/update":
            POLICY.update_role(actor, body["role_id"], name=body["name"],
                               description=body.get("description", ""),
                               enabled=body["enabled"], revision=body["revision"])
        elif path == "role":
            HUB.require_user(body["user_id"])
            POLICY.set_role(actor, body["user_id"], body.get("role_id"))
        elif path == "grants":
            POLICY.set_grants(actor, body["role_id"], body["grants"])
        elif path == "sync":
            datasets, page = [], 1
            while page <= 100:
                data = await backend("GET", "/api/v1/datasets",
                                     params={"page": page, "page_size": 100})
                items = data if isinstance(data, list) else (data or {}).get("datasets", [])
                datasets.extend({"id": d["id"], "name": d["name"]} for d in items)
                if len(items) < 100:
                    break
                page += 1
            else:
                raise BackendError("知识库超过同步上限，未修改现有授权")
            POLICY.sync_datasets(actor, datasets)
        elif path == "connect":
            uid, rt, agent = body["user_id"], body["runtime_id"], body["agent_id"]
            HUB.require_user(uid, rt)
            token = POLICY.issue(actor, uid, rt, label=agent)
            try:
                HUB.install_driver(uid, rt, agent, token, MCP_URL)
            except Exception:
                # Revoke only the credential from this failed installation.
                with POLICY.connect() as db:
                    db.execute("UPDATE credentials SET revoked_at=? WHERE digest=?",
                               (int(time.time()), POLICY.digest(token)))
                raise
            POLICY.event(actor, "agent.connect", True, uid, agent)
        elif path == "revoke":
            POLICY.revoke(actor, body["user_id"])
        else:
            return JSONResponse({"error": "接口不存在"}, status_code=404)
        return JSONResponse({"ok": True})
    except Denied as e:
        return JSONResponse({"error": str(e)}, status_code=403)
    except ValueError as e:
        message = str(e) if path == "role" or path.startswith(("asset/", "distribution/", "roles/")) else "参数无效，请刷新后重试"
        return JSONResponse({"error": message}, status_code=400)
    except (KeyError, TypeError):
        return JSONResponse({"error": "参数无效，请刷新后重试"}, status_code=400)
    except (httpx.HTTPError, BackendError):
        return JSONResponse({"error": "依赖服务不可用，未完成操作"}, status_code=503)
    except RuntimeUnavailable as e:
        return JSONResponse({"error": str(e)}, status_code=409)
    except Exception:
        import logging
        logging.getLogger(__name__).exception("RBAC operation failed")
        return JSONResponse({"error": "操作失败，请检查服务日志"}, status_code=500)


async def page(request):
    public = json.dumps({"hubUrl": SETTINGS.hub_public_url,
                         "adminLabel": SETTINGS.admin_username or "配置指定的管理员",
                         "credentialDays": SETTINGS.credential_days},
                        ensure_ascii=False).replace("<", "\\u003c")
    source = (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(source.replace("__SIDECAR_PUBLIC_CONFIG__", public))


async def health(request):
    return JSONResponse({"ok": True, "service": "qwenpaw-sidecar", "version": "0.4.1"})


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/admin"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        return response


def build_app():
    app = mcp.streamable_http_app()
    native_lifespan = app.router.lifespan_context

    from contextlib import asynccontextmanager
    @asynccontextmanager
    async def lifespan(instance):
        async with native_lifespan(instance):
            DISTRIBUTION.kick()
            try:
                yield
            finally:
                task = DISTRIBUTION._task
                if task and not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
    app.router.lifespan_context = lifespan
    app.routes.extend([
        Route("/admin", lambda request: RedirectResponse("/admin/")),
        Route("/admin/", page),
        Route("/admin/sso-ticket", sso_ticket, methods=["POST", "OPTIONS"]),
        Route("/admin/api/{path:path}", admin_api, methods=["GET", "POST"]),
        Route("/healthz", health),
    ])
    app.add_middleware(Authentication)
    app.add_middleware(SecurityHeaders)
    return app


app = build_app()
