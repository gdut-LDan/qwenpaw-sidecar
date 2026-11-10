"""Server-side adapter to local runtime APIs; boundary tokens never leave host."""
from __future__ import annotations

import json
from urllib.parse import quote

import httpx
from cryptography.fernet import Fernet

from .store import Denied


class RuntimeUnavailable(Exception):
    pass


class RuntimeAPI:
    def __init__(self, hub):
        self.hub = hub

    def connection(self, user_id, runtime_id):
        self.hub.require_user(user_id, runtime_id)
        with self.hub.connect() as db:
            row = db.execute("SELECT * FROM runtimes WHERE runtime_id=? AND owner_user_id=? "
                             "AND deleted_at IS NULL", (runtime_id, user_id)).fetchone()
            if not row or row["observed_state"] != "running":
                raise RuntimeUnavailable("目标用户运行时未启动，请用户登录后重试")
            endpoint = json.loads(row["endpoint_json"])
            # Never follow browser-provided URLs or non-local registry endpoints.
            if endpoint.get("host") not in ("127.0.0.1", "localhost", "::1"):
                raise RuntimeUnavailable("仅支持已登记的本机隔离运行时")
            port = endpoint.get("port")
            if not isinstance(port, int) or not 1 <= port <= 65535:
                raise RuntimeUnavailable("目标运行时端口无效")
            scope = "runtime-control:" + row["tenant_id"] + ":" + runtime_id
            cred = db.execute(
                "SELECT encrypted_value FROM tenant_credentials "
                "WHERE tenant_id='__qwenpaw_hub_system__' AND scope=? "
                "AND credential_name='QWENPAW_RUNTIME_INTERNAL_TOKEN'", (scope,)).fetchone()
            if cred is None:
                raise RuntimeUnavailable("运行时服务凭证不可用")
        key = (self.hub.path.parent / "secrets/.vault_key").read_bytes()
        token = Fernet(key).decrypt(cred[0].encode()).decode()
        return f"http://127.0.0.1:{port}", token

    async def request(self, user_id, runtime_id, method, path, *, agent_id=None, **kwargs):
        base, token = self.connection(user_id, runtime_id)
        headers = {"X-QwenPaw-Runtime-Token": token}
        if agent_id:
            headers["X-Agent-Id"] = agent_id
        async with httpx.AsyncClient(timeout=90, trust_env=False, follow_redirects=False) as client:
            response = await client.request(method, base + "/api" + path, headers=headers, **kwargs)
        if response.status_code >= 400:
            messages = {401: "运行时认证失败", 403: "运行时拒绝此操作",
                        404: "目标智能体或接口不存在", 409: "目标已存在同名内容，未覆盖",
                        422: "原生校验或技能安全扫描未通过"}
            raise RuntimeUnavailable(messages.get(response.status_code,
                                                  f"运行时返回错误 HTTP {response.status_code}"))
        if not 200 <= response.status_code < 300:
            raise RuntimeUnavailable("运行时返回了不受支持的重定向")
        return response.json()

    @staticmethod
    def agent_path(agent_id, suffix=""):
        return "/agents/" + quote(agent_id, safe="") + suffix
