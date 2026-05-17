"""白泽 HTTP API 客户端"""

import requests


class BaizeClient:
    """白泽治理框架 HTTP API 封装"""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers["Content-Type"] = "application/json"

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _headers(self, agent_id: str | None = None) -> dict:
        h = {}
        if agent_id:
            h["x-agent-id"] = agent_id
        return h

    # ─── Agent 管理 ───

    def register_agent(self, name: str, level: int, zones: list[str],
                       parent: str | None = None) -> dict:
        body = {"name": name, "level": level, "zones": zones}
        if parent:
            body["parent_id"] = parent
        resp = self.session.post(
            self._url("/api/v0/agents"),
            json=body,
            headers=self._headers("baize-root"),
        )
        resp.raise_for_status()
        return resp.json()

    def list_agents(self) -> list[dict]:
        resp = self.session.get(
            self._url("/api/v0/agents"),
            headers=self._headers("baize-root"),
        )
        resp.raise_for_status()
        return resp.json()

    # ─── 文件操作 ───

    def file_write(self, agent_id: str, path: str, content: str,
                   labels: dict | None = None) -> dict:
        body: dict = {"content": content}
        if labels:
            body["labels"] = labels
        resp = self.session.post(
            self._url(f"/api/v0/files/{path}"),
            json=body,
            headers=self._headers(agent_id),
        )
        resp.raise_for_status()
        return resp.json()

    def file_read(self, agent_id: str, path: str) -> dict:
        resp = self.session.get(
            self._url(f"/api/v0/files/{path}"),
            headers=self._headers(agent_id),
        )
        resp.raise_for_status()
        return resp.json()

    def file_delete(self, agent_id: str, path: str) -> None:
        resp = self.session.delete(
            self._url(f"/api/v0/files/{path}"),
            headers=self._headers(agent_id),
        )
        resp.raise_for_status()

    def file_list(self, agent_id: str) -> list[str]:
        resp = self.session.get(
            self._url("/api/v0/files"),
            headers=self._headers(agent_id),
        )
        resp.raise_for_status()
        return resp.json()["files"]

    # ─── Push / Pull ───

    def push(self, agent_id: str, message: str, ref: str | None = None) -> dict:
        body: dict = {"message": message}
        if ref:
            body["ref"] = ref
        resp = self.session.post(
            self._url("/api/v0/push"),
            json=body,
            headers=self._headers(agent_id),
        )
        resp.raise_for_status()
        return resp.json()

    def pull(self, agent_id: str, ref: str | None = None) -> dict:
        body: dict = {}
        if ref:
            body["ref"] = ref
        resp = self.session.post(
            self._url("/api/v0/pull"),
            json=body,
            headers=self._headers(agent_id),
        )
        resp.raise_for_status()
        return resp.json()

    # ─── 审计 ───

    def audit_query(self, agent: str | None = None,
                    audit_type: str | None = None) -> dict:
        params = {}
        if agent:
            params["agent"] = agent
        if audit_type:
            params["type"] = audit_type
        resp = self.session.get(
            self._url("/api/v0/audit"),
            params=params,
            headers=self._headers("baize-root"),
        )
        resp.raise_for_status()
        return resp.json()

    # ─── 身份追溯 ───

    def trace_identity(self, agent_id: str) -> list[dict]:
        resp = self.session.get(
            self._url(f"/api/v0/trace/identity/{agent_id}"),
            headers=self._headers("baize-root"),
        )
        resp.raise_for_status()
        return resp.json()["chain"]
