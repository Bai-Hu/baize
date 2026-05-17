//! HTTP 客户端实现
//!
//! 通过白泽 HTTP API 与白泽服务端通信。
//! 适用于外部 agent 或远程 agent 架构。

use crate::client::BaizeClient;
use crate::error::{ClientError, ClientResult};
use crate::types::*;

/// 白泽 HTTP 客户端
///
/// 通过 HTTP API 与白泽通信。每个实例绑定一个 agent_id。
pub struct BaizeHttpClient {
    base_url: String,
    agent_id: String,
    client: reqwest::blocking::Client,
}

impl BaizeHttpClient {
    /// 创建 HTTP 客户端
    ///
    /// - `base_url`: 白泽服务地址，如 `http://127.0.0.1:3000/api/v0`
    /// - `agent_id`: 绑定的 agent ID，用于 `x-agent-id` 请求头
    pub fn new(base_url: &str, agent_id: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            agent_id: agent_id.to_string(),
            client: reqwest::blocking::Client::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path)
    }

    /// 将 HTTP 响应映射为 ClientError
    fn map_status(resp: reqwest::blocking::Response) -> ClientError {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        let msg = if let Ok(err) = serde_json::from_str::<ErrorResponse>(&body) {
            err.error
        } else {
            body
        };
        match status.as_u16() {
            400 => ClientError::Validation(msg),
            401 => ClientError::Auth(msg),
            403 => ClientError::PermissionDenied(msg),
            404 => ClientError::NotFound(msg),
            409 => ClientError::Conflict(msg),
            422 => ClientError::UserDecision(msg),
            500 => ClientError::Server(msg),
            _ => ClientError::Other(format!("HTTP {}: {}", status, msg)),
        }
    }

    fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> ClientResult<T> {
        let resp = self
            .client
            .get(self.url(path))
            .header("x-agent-id", &self.agent_id)
            .send()
            .map_err(|e| ClientError::Connection(e.to_string()))?;

        if resp.status().is_success() {
            resp.json::<T>()
                .map_err(|e| ClientError::Other(format!("parse response: {}", e)))
        } else {
            Err(Self::map_status(resp))
        }
    }

    fn post<B: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> ClientResult<T> {
        let resp = self
            .client
            .post(self.url(path))
            .header("x-agent-id", &self.agent_id)
            .json(body)
            .send()
            .map_err(|e| ClientError::Connection(e.to_string()))?;

        if resp.status().is_success() {
            resp.json::<T>()
                .map_err(|e| ClientError::Other(format!("parse response: {}", e)))
        } else {
            Err(Self::map_status(resp))
        }
    }

    fn post_no_body<T: serde::de::DeserializeOwned>(&self, path: &str) -> ClientResult<T> {
        let resp = self
            .client
            .post(self.url(path))
            .header("x-agent-id", &self.agent_id)
            .send()
            .map_err(|e| ClientError::Connection(e.to_string()))?;

        if resp.status().is_success() {
            resp.json::<T>()
                .map_err(|e| ClientError::Other(format!("parse response: {}", e)))
        } else {
            Err(Self::map_status(resp))
        }
    }

    fn put_json(&self, path: &str, body: &impl serde::Serialize) -> ClientResult<()> {
        let resp = self
            .client
            .put(self.url(path))
            .header("x-agent-id", &self.agent_id)
            .json(body)
            .send()
            .map_err(|e| ClientError::Connection(e.to_string()))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Self::map_status(resp))
        }
    }

    fn delete(&self, path: &str) -> ClientResult<()> {
        let resp = self
            .client
            .delete(self.url(path))
            .header("x-agent-id", &self.agent_id)
            .send()
            .map_err(|e| ClientError::Connection(e.to_string()))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Self::map_status(resp))
        }
    }

    fn post_empty_result(&self, path: &str, body: &impl serde::Serialize) -> ClientResult<()> {
        let resp = self
            .client
            .post(self.url(path))
            .header("x-agent-id", &self.agent_id)
            .json(body)
            .send()
            .map_err(|e| ClientError::Connection(e.to_string()))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Self::map_status(resp))
        }
    }

    /// 对 query string 值做 percent-encoding
    fn encode_query(value: &str) -> String {
        let mut encoded = String::with_capacity(value.len());
        for byte in value.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(byte as char)
                }
                _ => {
                    encoded.push('%');
                    encoded.push_str(&format!("{:02X}", byte).to_uppercase());
                }
            }
        }
        encoded
    }

    /// 对 URL 路径段做 percent-encoding（保留 `/`）
    fn encode_path(path: &str) -> String {
        let mut encoded = String::with_capacity(path.len());
        for byte in path.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                    encoded.push(byte as char)
                }
                _ => {
                    encoded.push('%');
                    encoded.push_str(&format!("{:02X}", byte).to_uppercase());
                }
            }
        }
        encoded
    }
}

impl BaizeClient for BaizeHttpClient {
    // ─── Agent 管理 ───

    fn agent_register(&self, req: AgentRegisterRequest) -> ClientResult<AgentRegisterResponse> {
        self.post("agents", &req)
    }

    fn agent_list(&self) -> ClientResult<Vec<AgentInfo>> {
        self.get("agents")
    }

    fn agent_revoke(&self, id: &str) -> ClientResult<()> {
        self.delete(&format!("agents/{}", Self::encode_path(id)))
    }

    // ─── Blob 操作 ───

    fn blob_write(&self, req: BlobWriteRequest) -> ClientResult<BlobInfo> {
        self.post("blobs", &req)
    }

    fn blob_read(&self, hash: &str) -> ClientResult<BlobInfo> {
        self.get(&format!("blobs/{}", Self::encode_path(hash)))
    }

    fn blob_query(&self, req: BlobQueryRequest) -> ClientResult<Vec<BlobInfo>> {
        self.post("blobs/query", &req)
    }

    // ─── 文件操作 ───

    fn file_write(&self, path: &str, req: FileWriteRequest) -> ClientResult<FileRecord> {
        self.post(&format!("files/{}", Self::encode_path(path)), &req)
    }

    fn file_read(&self, path: &str) -> ClientResult<FileContent> {
        self.get(&format!("files/{}", Self::encode_path(path)))
    }

    fn file_delete(&self, path: &str) -> ClientResult<()> {
        self.delete(&format!("files/{}", Self::encode_path(path)))
    }

    fn file_list(&self) -> ClientResult<Vec<String>> {
        let resp: FileListResponse = self.get("files")?;
        Ok(resp.files)
    }

    // ─── 数据同步 ───

    fn push(&self, req: PushRequest) -> ClientResult<PushResponse> {
        self.post("push", &req)
    }

    fn pull(&self, req: PullRequest) -> ClientResult<PullResponse> {
        self.post("pull", &req)
    }

    fn git_log(&self, limit: Option<usize>) -> ClientResult<Vec<GitCommitInfo>> {
        let path = match limit {
            Some(l) => format!("log?limit={}", l),
            None => "log".to_string(),
        };
        let resp: LogResponse = self.get(&path)?;
        Ok(resp.commits)
    }

    // ─── Label ───

    fn label_add(&self, req: LabelAddRequest) -> ClientResult<()> {
        self.post_empty_result("labels", &req)
    }

    fn label_query(&self, key: &str, value: Option<&str>) -> ClientResult<Vec<LabelInfo>> {
        let path = match value {
            Some(v) => format!(
                "labels/query?key={}&value={}",
                Self::encode_query(key),
                Self::encode_query(v)
            ),
            None => format!("labels/query?key={}", Self::encode_query(key)),
        };
        let resp: LabelQueryResponse = self.get(&path)?;
        Ok(resp.labels)
    }

    // ─── Git Ref ───

    fn ref_set(&self, name: &str, oid: &str) -> ClientResult<()> {
        let body = RefSetRequest { oid: oid.to_string() };
        self.put_json(&format!("refs/{}", Self::encode_path(name)), &body)
    }

    fn ref_get(&self, name: &str) -> ClientResult<RefGetResponse> {
        self.get(&format!("refs/{}", Self::encode_path(name)))
    }

    fn ref_delete(&self, name: &str) -> ClientResult<()> {
        self.delete(&format!("refs/{}", Self::encode_path(name)))
    }

    fn ref_list(&self) -> ClientResult<Vec<String>> {
        let resp: RefListResponse = self.get("refs")?;
        Ok(resp.refs)
    }

    // ─── Elevation ───

    fn elevation_request(&self, req: ElevationCreateRequest) -> ClientResult<String> {
        let resp: ElevationCreateResponse = self.post("elevation", &req)?;
        Ok(resp.request_id)
    }

    fn elevation_approve(&self, id: &str) -> ClientResult<ElevationStatus> {
        let resp: ElevationApproveResponse =
            self.post_no_body(&format!("elevation/{}/approve", Self::encode_path(id)))?;
        Ok(resp.status)
    }

    fn elevation_return(
        &self,
        id: &str,
        req: ElevationReturnRequest,
    ) -> ClientResult<ElevationStatus> {
        let resp: ElevationReturnResponse =
            self.post(&format!("elevation/{}/return", Self::encode_path(id)), &req)?;
        Ok(resp.status)
    }

    fn elevation_list(&self) -> ClientResult<Vec<ElevationRecord>> {
        let resp: ElevationListResponse = self.get("elevation")?;
        Ok(resp.requests)
    }

    // ─── Trace ───

    fn trace_identity(&self, agent_id: &str) -> ClientResult<Vec<TraceIdentityInfo>> {
        let resp: TraceIdentityResponse =
            self.get(&format!("trace/identity/{}", Self::encode_path(agent_id)))?;
        Ok(resp.chain)
    }

    // ─── Audit ───

    fn audit_query(
        &self,
        agent: Option<&str>,
        audit_type: Option<&str>,
    ) -> ClientResult<Vec<AuditRecord>> {
        let mut path = "audit".to_string();
        let mut sep = '?';
        if let Some(a) = agent {
            path = format!("{}{}agent={}", path, sep, Self::encode_query(a));
            sep = '&';
        }
        if let Some(t) = audit_type {
            path = format!("{}{}type={}", path, sep, Self::encode_query(t));
        }
        let resp: AuditResponse = self.get(&path)?;
        Ok(resp.records)
    }

    // ─── Import / Export ───

    fn import_data(&self, req: ImportRequest) -> ClientResult<ImportResponse> {
        self.post("import", &req)
    }

    fn export_data(&self, hash: &str) -> ClientResult<BlobInfo> {
        self.get(&format!("export/{}", Self::encode_path(hash)))
    }

    // ─── Repo Stats ───

    fn repo_stats(&self) -> ClientResult<RepoStats> {
        self.get("repo/stats")
    }
}
