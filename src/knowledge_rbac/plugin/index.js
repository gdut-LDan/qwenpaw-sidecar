(function () {
  const api = window.QwenPaw;
  if (!api || !api.menu) return;
  const configuredURL = null;
  if (!configuredURL) return; // Generate a site-specific plugin with the CLI.
  const target = new URL(configuredURL);
  async function enter(event) {
    event.preventDefault();
    const popup = window.open("about:blank", "_blank");
    if (!popup) { window.alert("请允许此站点打开知识库权限后台窗口"); return; }
    popup.opener = null;
    try {
      const token = api.host.getApiToken ? api.host.getApiToken() : localStorage.getItem("qwenpaw_auth_token");
      if (!token) throw new Error("请先登录 QwenPaw");
      const response = await fetch(new URL("/admin/sso-ticket", target), {
        method: "POST", headers: { Authorization: "Bearer " + token }
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "快捷登录失败");
      const destination = new URL(target);
      destination.hash = "sso=" + encodeURIComponent(data.ticket);
      popup.location.replace(destination.toString());
    } catch (error) {
      popup.close();
      window.alert(error.message || "快捷登录失败");
    }
  }
  // Capture the native menu's external link too, so both entries use SSO.
  document.addEventListener("click", function (event) {
    const link = event.target.closest && event.target.closest("a");
    if (link && link.href === target.toString()) {
      event.stopPropagation();
      enter(event);
    }
  }, true);
  api.menu.add("knowledge-rbac-admin", {
    id: "knowledge-rbac-admin.home",
    location: "primary.settings",
    label: "知识库与权限",
    href: target.toString()
  });
  // The chat skin renders navigation in a collapsible tools panel. This
  // supported slot keeps the management link visible in the normal sidebar.
  if (api.slot && api.host && api.host.React) {
    api.slot.fill("knowledge-rbac-admin", "sider.bottom", function () {
      return api.host.React.createElement("a", {
        href: target.toString(), target: "_blank", rel: "noopener noreferrer",
        style: { display: "block", margin: "10px 14px", padding: "11px 14px",
          border: "1px solid #d5ddeb", borderRadius: "9px", fontSize: "13px",
          color: "#315681", background: "#ffffffb8", textAlign: "center",
          textDecoration: "none" }
      }, "知识库与权限 ↗");
    }, { id: "knowledge-rbac-admin.sidebar" });
  }
})();
