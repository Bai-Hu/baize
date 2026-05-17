//! 白泽 API 数据类型
//!
//! 与 HTTP API 一一对应的请求/响应 DTO。
//! agent 框架通过这些类型与白泽交互。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─── Agent ───

#[derive(Debug, Clone, Serialize)]
pub struct AgentRegisterRequest {
    pub name: String,
    pub level: u8,
    pub zones: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentRegisterResponse {
    pub id: String,
    pub agent_id: String,
    pub level: u8,
    pub zones: Vec<String>,
    pub cert_pem: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentInfo {
    pub id: String,
    pub level: u8,
    pub zones: Vec<String>,
    pub parent_id: Option<String>,
}

// ─── Blob ───

#[derive(Debug, Clone, Serialize)]
pub struct BlobWriteRequest {
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlobInfo {
    pub hash: String,
    pub content: String,
    pub labels: HashMap<String, String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlobQueryRequest {
    pub labels: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
}

// ─── 文件操作 ───

#[derive(Debug, Clone, Serialize)]
pub struct FileWriteRequest {
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileRecord {
    pub path: String,
    pub hash: String,
    pub size: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileContent {
    pub path: String,
    pub content: String,
    pub hash: String,
    pub size: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileListResponse {
    pub files: Vec<String>,
}

// ─── Push / Pull ───

#[derive(Debug, Clone, Serialize)]
pub struct PushRequest {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PushResponse {
    pub files: usize,
    pub pending: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PullRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PullResponse {
    pub files: usize,
}

// ─── Git Log ───

#[derive(Debug, Clone, Deserialize)]
pub struct LogResponse {
    pub commits: Vec<GitCommitInfo>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GitCommitInfo {
    pub hash: String,
    pub message: String,
    pub author: Option<String>,
    pub time: String,
}

// ─── Label ───

#[derive(Debug, Clone, Serialize)]
pub struct LabelAddRequest {
    pub entity_hash: String,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LabelQueryResponse {
    pub labels: Vec<LabelInfo>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LabelInfo {
    pub entity_hash: String,
    pub key: String,
    pub value: String,
}

// ─── Git Ref ───

#[derive(Debug, Clone, Serialize)]
pub struct RefSetRequest {
    pub oid: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RefGetResponse {
    pub name: String,
    pub oid: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RefListResponse {
    pub refs: Vec<String>,
}

// ─── Elevation ───

/// 借权访问模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ElevationMode {
    ReadOnly,
    Write,
    ReadWrite,
}

#[derive(Debug, Clone, Serialize)]
pub struct ElevationCreateRequest {
    pub agent_id: String,
    pub zones: Vec<String>,
    pub mode: ElevationMode,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ElevationCreateResponse {
    pub request_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ElevationApproveResponse {
    pub status: ElevationStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct ElevationReturnRequest {
    pub agent_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ElevationReturnResponse {
    pub status: ElevationStatus,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ElevationListResponse {
    pub requests: Vec<ElevationRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ElevationStatus {
    Pending,
    Approved,
    Expired,
    Revoked,
    Returned,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ElevationRecord {
    pub id: String,
    pub agent_id: String,
    pub mode: String,
    pub reason: String,
    pub status: ElevationStatus,
    pub created_at: String,
    pub expires_at: Option<String>,
}

// ─── Trace ───

#[derive(Debug, Clone, Deserialize)]
pub struct TraceIdentityResponse {
    pub chain: Vec<TraceIdentityInfo>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TraceIdentityInfo {
    pub agent_id: String,
    pub parent_id: Option<String>,
    pub level: u8,
    pub zones: Vec<String>,
}

// ─── Audit ───

#[derive(Debug, Clone, Deserialize)]
pub struct AuditResponse {
    pub records: Vec<AuditRecord>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditRecord {
    pub hash: String,
    #[serde(rename = "type")]
    pub op_type: String,
    pub agent: String,
    pub result: String,
    pub target: Option<String>,
    pub time: String,
}

// ─── Import / Export ───

#[derive(Debug, Clone, Serialize)]
pub struct ImportRequest {
    pub content: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportResponse {
    pub hash: String,
    pub trust_level: u8,
}

// ─── Repo Stats ───

#[derive(Debug, Clone, Deserialize)]
pub struct RepoStats {
    pub total_blobs: i64,
    pub total_commits: i64,
    pub total_refs: i64,
}

// ─── API 错误响应 ───

#[derive(Debug, Clone, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}
