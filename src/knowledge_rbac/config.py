"""Portable configuration. Environment overrides .env; no production defaults."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import dotenv_values


def http_url(value, key):
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError(f"{key} 必须是无内嵌凭据的 HTTP(S) URL")
    if parsed.query or parsed.fragment:
        raise ValueError(f"{key} 不能带 query 或 fragment")
    return value.rstrip("/")


def origin(value):
    parsed = urlsplit(value)
    return parsed.scheme + "://" + parsed.netloc


@dataclass(frozen=True)
class Settings:
    config_file: Path
    data_dir: Path
    hub_dir: Path
    hub_url: str
    hub_public_url: str
    public_url: str
    mcp_url: str
    ragflow_url: str
    ragflow_key: str
    admin_user_id: str
    admin_username: str
    hub_origins: tuple[str, ...]
    mcp_hosts: tuple[str, ...]
    mcp_origins: tuple[str, ...]
    bind_host: str
    port: int
    credential_days: int
    cookie_name: str

    @classmethod
    def load(cls, environ=None):
        env = dict(os.environ if environ is None else environ)
        file = Path(env.get("SIDECAR_CONFIG", ".env")).expanduser().resolve()
        values = dict(dotenv_values(file)) if file.is_file() else {}
        values.update(env)

        def get(key, default=""):
            return str(values.get(key) or default).strip()

        def path(key, default):
            raw = Path(get(key, str(default))).expanduser()
            return (file.parent / raw).resolve() if not raw.is_absolute() else raw.resolve()

        data = path("SIDECAR_DATA_DIR", "var")
        hub = path("HUB_DATA_DIR", "qwenpaw-data/hub")
        hub_url = http_url(get("HUB_URL", "http://127.0.0.1:8088"), "HUB_URL")
        hub_public = http_url(get("HUB_PUBLIC_URL", hub_url), "HUB_PUBLIC_URL")
        public = http_url(get("SIDECAR_PUBLIC_URL", "http://127.0.0.1:20600"), "SIDECAR_PUBLIC_URL")
        mcp = http_url(get("MCP_PUBLIC_URL", public + "/mcp"), "MCP_PUBLIC_URL")
        if urlsplit(public).path not in ("", "/") or urlsplit(mcp).path != "/mcp":
            raise ValueError("SIDECAR_PUBLIC_URL 不支持路径前缀，MCP_PUBLIC_URL 路径必须是 /mcp")
        ragflow = http_url(get("RAGFLOW_BASE_URL", "http://127.0.0.1:9380"), "RAGFLOW_BASE_URL")
        origins = tuple(x.strip() for x in get("HUB_ORIGINS", origin(hub_public)).split(",") if x.strip())
        for item in origins:
            if http_url(item, "HUB_ORIGINS") != origin(item) or "*" in item:
                raise ValueError("HUB_ORIGINS 必须是精确的 scheme://host[:port]，不允许通配符")
        default_hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
        default_origins = ["http://127.0.0.1:*", "http://localhost:*"]
        for url in (public, mcp):
            p = urlsplit(url)
            host = p.hostname
            host = "[" + host + "]" if ":" in host else host
            default_hosts.extend([p.netloc, host + ":*"])
            default_origins.append(origin(url))
        hosts = tuple(dict.fromkeys(default_hosts + [x.strip() for x in get("MCP_ALLOWED_HOSTS").split(",") if x.strip()]))
        mcp_origins = tuple(dict.fromkeys(default_origins + [x.strip() for x in get("MCP_ALLOWED_ORIGINS").split(",") if x.strip()]))
        if any(x == "*" for x in hosts + mcp_origins):
            raise ValueError("MCP 白名单不允许直接使用 *")
        port, days = int(get("SIDECAR_PORT", "20600")), int(get("CREDENTIAL_DAYS", "90"))
        if not 1 <= port <= 65535 or not 1 <= days <= 365:
            raise ValueError("端口应为 1..65535，凭证天数应为 1..365")
        return cls(file, data, hub, hub_url, hub_public, public, mcp, ragflow,
                   get("RAGFLOW_API_KEY"), get("ADMIN_USER_ID"), get("ADMIN_USERNAME"),
                   origins, hosts, mcp_origins, get("SIDECAR_BIND", "127.0.0.1"),
                   port, days, get("SIDECAR_COOKIE_NAME", "qwenpaw_sidecar_session"))

    def deployment_errors(self):
        errors = []
        if not self.admin_user_id and not self.admin_username:
            errors.append("必须设置 ADMIN_USERNAME 或 ADMIN_USER_ID")
        if not self.ragflow_key:
            errors.append("必须设置 RAGFLOW_API_KEY")
        if any(".example.com" in value for value in (
                self.hub_public_url, self.public_url, self.mcp_url)):
            errors.append("请替换示例域名后再启动")
        return errors
