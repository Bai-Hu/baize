use std::sync::Arc;
use tokio::sync::Mutex;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{request::Parts, StatusCode},
    routing::{get, post, put, delete},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

use crate::pipeline::{
    Baize,
    AgentRegistry, ElevationManager, DataOps, FileSync, GitOps,
};
use baize_core::scope::{ElevationMode, Level};

// ─── 错误辅助 ───

/// 将内部错误映射为安全的 HTTP 响应，不暴露内部细节
fn error_response(status: StatusCode, error_type: &str) -> axum::response::Response {
    (
        status,
        Json(serde_json::json!({"error": error_type})),
    ).into_response()
}

/// 根据 Error 类型返回合适的 HTTP 状态码 + 安全消息
fn map_error(e: baize_core::Error) -> axum::response::Response {
    let (status, msg) = match &e {
        baize_core::Error::NotFound(_) => (StatusCode::NOT_FOUND, "not found"),
        baize_core::Error::Validation(_) => (StatusCode::BAD_REQUEST, "validation failed"),
        baize_core::Error::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
        baize_core::Error::PermissionDenied(_) => (StatusCode::FORBIDDEN, "permission denied"),
        baize_core::Error::NeedUserDecision(_) => (StatusCode::UNPROCESSABLE_ENTITY, "user decision required"),
        baize_core::Error::Certificate(_) => (StatusCode::BAD_REQUEST, "certificate error"),
        baize_core::Error::Storage(..) => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        baize_core::Error::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    error_response(status, msg)
}

// ─── AgentId Extractor ───

/// 从 x-agent-id 请求头提取 agent 身份
struct AgentId(String);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for AgentId {
    type Rejection = axum::response::Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.headers.get("x-agent-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| AgentId(s.to_string()))
            .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, "missing x-agent-id header"))
    }
}

// ─── 应用状态 ───

pub type AppState = Arc<Mutex<Baize>>;

pub fn app(baize: Baize) -> Router {
    let state = Arc::new(Mutex::new(baize));
    Router::new()
        // Agent 管理
        .route("/api/v0/agents", post(register_agent))
        .route("/api/v0/agents", get(list_agents))
        .route("/api/v0/agents/{id}", delete(revoke_agent))
        // Blob 操作
        .route("/api/v0/blobs", post(blob_write))
        .route("/api/v0/blobs/{hash}", get(blob_read))
        .route("/api/v0/blobs/query", post(blob_query))
        // Git log
        .route("/api/v0/log", get(git_log_handler))
        // Label 操作
        .route("/api/v0/labels", post(label_add))
        .route("/api/v0/labels/query", get(label_query))
        // Git refs
        .route("/api/v0/refs", get(git_ref_list_handler))
        .route("/api/v0/refs/{name}", get(git_ref_get_handler))
        .route("/api/v0/refs/{name}", put(git_ref_set_handler))
        .route("/api/v0/refs/{name}", delete(git_ref_delete_handler))
        // Elevation
        .route("/api/v0/elevation", post(elevation_request))
        .route("/api/v0/elevation/{id}/approve", post(elevation_approve))
        .route("/api/v0/elevation", get(elevation_list))
        // Trace
        .route("/api/v0/trace/identity/{id}", get(trace_identity))
        // Import/Export
        .route("/api/v0/import", post(import_data))
        .route("/api/v0/export/{hash}", get(export_data))
        .route("/api/v0/audit", get(audit_query))
        .route("/api/v0/elevation/{id}/return", post(elevation_return))
        // File 操作（网关代理）
        .route("/api/v0/files/{*path}", post(file_write))
        .route("/api/v0/files/{*path}", get(file_read))
        .route("/api/v0/files/{*path}", delete(file_delete))
        .route("/api/v0/files", get(file_list))
        // Push / Pull
        .route("/api/v0/push", post(push))
        .route("/api/v0/pull", post(pull))
        // Repo
        .route("/api/v0/repo/stats", get(repo_stats_handler))
        .with_state(state)
}

// ─── DTO ───

#[derive(Deserialize)]
struct RegisterAgentRequest {
    name: String,
    level: u8,
    zones: Vec<String>,
    parent_id: Option<String>,
}

#[derive(Serialize)]
struct AgentResponse {
    id: String,
    level: u8,
    zones: Vec<String>,
    parent_id: Option<String>,
}

#[derive(Deserialize)]
struct BlobWriteRequest {
    content: String,
    labels: Option<std::collections::HashMap<String, String>>,
}

#[derive(Serialize)]
struct BlobResponse {
    hash: String,
    content: String,
    labels: std::collections::HashMap<String, String>,
    created_at: String,
}

#[derive(Deserialize)]
struct BlobQueryRequest {
    labels: std::collections::HashMap<String, String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Deserialize)]
struct LabelAddRequest {
    entity_hash: String,
    key: String,
    value: String,
}

#[derive(Deserialize)]
struct ElevationRequestDto {
    agent_id: String,
    zones: Vec<String>,
    mode: String,
    reason: String,
    duration: Option<String>,
}

#[derive(Deserialize)]
struct LogQueryParams {
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct ImportRequest {
    content: String,
    source: String,
    trust_level: Option<u8>,
    labels: Option<std::collections::HashMap<String, String>>,
}

#[derive(Deserialize)]
struct FileWriteRequest {
    content: String,
    labels: Option<std::collections::HashMap<String, String>>,
}

#[derive(Serialize)]
struct FileResponse {
    path: String,
    hash: String,
    size: usize,
}

#[derive(Serialize)]
struct FileContentResponse {
    path: String,
    content: String,
    hash: String,
    size: usize,
}

#[derive(Deserialize)]
struct PushRequest {
    message: String,
    r#ref: Option<String>,
}

#[derive(Deserialize)]
struct PullRequest {
    r#ref: Option<String>,
}

// ─── Handler ───

async fn register_agent(
    State(state): State<AppState>,
    _agent: AgentId,
    Json(req): Json<RegisterAgentRequest>,
) -> impl IntoResponse {
    let mut baize = state.lock().await;
    match baize.agent_register(
        &req.name,
        Level(req.level),
        req.zones.iter().map(|s| s.as_str()).collect(),
        req.parent_id.as_deref(),
    ) {
        Ok((id, bundle)) => (StatusCode::CREATED, Json(serde_json::json!({
            "id": id,
            "agent_id": bundle.identity.agent_id,
            "level": bundle.identity.level,
            "zones": bundle.identity.zones,
            "cert_pem": bundle.cert_pem,
        }))).into_response(),
        Err(e) => map_error(e),
    }
}

async fn list_agents(State(state): State<AppState>) -> impl IntoResponse {
    let baize = state.lock().await;
    let agents: Vec<AgentResponse> = baize.agent_list().into_iter().map(|(id, identity)| {
        AgentResponse {
            id,
            level: identity.level,
            zones: identity.zones,
            parent_id: identity.parent_id,
        }
    }).collect();
    Json(agents)
}

async fn revoke_agent(
    State(state): State<AppState>,
    _agent: AgentId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut baize = state.lock().await;
    match baize.agent_revoke(&id) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => map_error(e),
    }
}

async fn blob_write(
    State(state): State<AppState>,
    agent: AgentId,
    Json(req): Json<BlobWriteRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    let labels = req.labels.unwrap_or_default();
    match baize.pipe_blob_write(&agent.0, &req.content, &labels) {
        Ok(blob) => (StatusCode::CREATED, Json(BlobResponse {
            hash: blob.hash,
            content: blob.content,
            labels: blob.labels,
            created_at: blob.created_at,
        })).into_response(),
        Err(e) => map_error(e),
    }
}

async fn blob_read(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.storage.blob_read(&hash) {
        Ok(blob) => Json(BlobResponse {
            hash: blob.hash,
            content: blob.content,
            labels: blob.labels,
            created_at: blob.created_at,
        }).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn blob_query(
    State(state): State<AppState>,
    Json(req): Json<BlobQueryRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.storage.blob_query_paginated(&req.labels, req.limit, req.offset) {
        Ok(blobs) => {
            let results: Vec<BlobResponse> = blobs.into_iter().map(|b| BlobResponse {
                hash: b.hash,
                content: b.content,
                labels: b.labels,
                created_at: b.created_at,
            }).collect();
            Json(results).into_response()
        }
        Err(e) => map_error(e),
    }
}

async fn git_log_handler(
    State(state): State<AppState>,
    Query(params): Query<LogQueryParams>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    let limit = params.limit.unwrap_or(50).min(200);
    match baize.git_log(limit) {
        Ok(commits) => Json(serde_json::json!({
            "commits": commits.iter().map(|c| serde_json::json!({
                "hash": c.hash,
                "message": c.message,
                "author": c.author,
                "time": c.time,
            })).collect::<Vec<_>>()
        })).into_response(),
        Err(e) => map_error(e),
    }
}

async fn label_add(
    State(state): State<AppState>,
    agent: AgentId,
    Json(req): Json<LabelAddRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.pipe_label_add(&agent.0, &req.entity_hash, &req.key, &req.value) {
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(e) => map_error(e),
    }
}

async fn label_query(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    let key = params.get("key").map(|s| s.as_str()).unwrap_or("");
    let value = params.get("value").map(|s| s.as_str());

    if key.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "key is required"}))).into_response();
    }

    match baize.storage.label_query(key, value) {
        Ok(labels) => Json(serde_json::json!({
            "labels": labels.iter().map(|l| serde_json::json!({
                "entity_hash": l.entity_hash,
                "key": l.key,
                "value": l.value,
            })).collect::<Vec<_>>()
        })).into_response(),
        Err(e) => map_error(e),
    }
}

async fn git_ref_list_handler(State(state): State<AppState>) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.git_ref_list() {
        Ok(refs) => Json(serde_json::json!({"refs": refs})).into_response(),
        Err(e) => map_error(e),
    }
}

async fn git_ref_get_handler(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.git_ref_get(&name) {
        Ok(oid) => Json(serde_json::json!({"name": name, "oid": oid})).into_response(),
        Err(e) => map_error(e),
    }
}

#[derive(Deserialize)]
struct RefSetRequest {
    oid: String,
}

async fn git_ref_set_handler(
    State(state): State<AppState>,
    _agent: AgentId,
    Path(name): Path<String>,
    Json(req): Json<RefSetRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.git_ref_set(&name, &req.oid) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => map_error(e),
    }
}

async fn git_ref_delete_handler(
    State(state): State<AppState>,
    _agent: AgentId,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.git_ref_delete(&name) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => map_error(e),
    }
}

async fn elevation_request(
    State(state): State<AppState>,
    Json(req): Json<ElevationRequestDto>,
) -> impl IntoResponse {
    let mut baize = state.lock().await;
    let mode = match ElevationMode::from_str_lower(&req.mode) {
        Some(m) => m,
        None => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": format!("invalid mode '{}', expected: readonly, write, readwrite", req.mode)
            }))).into_response();
        }
    };
    match baize.elevation_request(
        &req.agent_id,
        req.zones.iter().map(|s| s.as_str()).collect(),
        mode,
        &req.reason,
        req.duration.as_deref(),
    ) {
        Ok(id) => (StatusCode::CREATED, Json(serde_json::json!({"request_id": id}))).into_response(),
        Err(e) => map_error(e),
    }
}

async fn elevation_approve(
    State(state): State<AppState>,
    agent: AgentId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut baize = state.lock().await;
    match baize.elevation_approve(&id, &agent.0) {
        Ok(()) => Json(serde_json::json!({"status": "approved"})).into_response(),
        Err(e) => map_error(e),
    }
}

async fn elevation_list(State(state): State<AppState>) -> impl IntoResponse {
    let baize = state.lock().await;
    let requests = match baize.elevation_list() {
        Ok(r) => r,
        Err(e) => return map_error(e),
    };
    let items: Vec<_> = requests.iter().map(|r| {
        let mut obj = serde_json::json!({
            "id": r.id,
            "agent_id": r.agent_id,
            "mode": format!("{:?}", r.mode),
            "reason": r.reason,
            "status": format!("{:?}", r.status),
            "created_at": r.created_at,
        });
        if let Some(ref expires) = r.expires_at {
            obj["expires_at"] = serde_json::Value::String(expires.clone());
        }
        obj
    }).collect();
    Json(serde_json::json!({"requests": items})).into_response()
}

async fn trace_identity(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.trace_identity(&id) {
        Ok(chain) => Json(serde_json::json!({
            "chain": chain.iter().map(|i| serde_json::json!({
                "agent_id": i.agent_id,
                "parent_id": i.parent_id,
                "level": i.level,
                "zones": i.zones,
            })).collect::<Vec<_>>()
        })).into_response(),
        Err(e) => map_error(e),
    }
}

async fn import_data(
    State(state): State<AppState>,
    agent: AgentId,
    Json(req): Json<ImportRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    let trust_level = req.trust_level.unwrap_or(2);
    match baize.pipe_import(&agent.0, &req.content, &req.source, trust_level, req.labels.clone()) {
        Ok(blob) => (StatusCode::CREATED, Json(serde_json::json!({
            "hash": blob.hash,
            "trust_level": trust_level,
        }))).into_response(),
        Err(e) => map_error(e),
    }
}

async fn export_data(
    State(state): State<AppState>,
    agent: AgentId,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.pipe_export(&agent.0, &hash) {
        Ok(blob) => Json(serde_json::json!({
            "hash": blob.hash,
            "content": blob.content,
            "labels": blob.labels,
        })).into_response(),
        Err(e) => map_error(e),
    }
}

#[derive(Deserialize)]
struct ElevationReturnDto {
    agent_id: String,
}

async fn elevation_return(
    State(state): State<AppState>,
    agent: AgentId,
    Path(id): Path<String>,
    Json(req): Json<ElevationReturnDto>,
) -> impl IntoResponse {
    let mut baize = state.lock().await;
    match baize.elevation_return(&id, &req.agent_id, &agent.0) {
        Ok(()) => Json(serde_json::json!({"status": "returned"})).into_response(),
        Err(e) => map_error(e),
    }
}

// ─── 审计查询 ───

async fn audit_query(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    let mut filter = std::collections::HashMap::new();
    filter.insert("x-audit".to_string(), "true".to_string());
    if let Some(agent) = params.get("agent") {
        filter.insert("x-audit-agent".to_string(), agent.clone());
    }
    if let Some(audit_type) = params.get("type") {
        filter.insert("x-audit-type".to_string(), audit_type.clone());
    }
    match baize.storage.blob_query_metadata(&filter) {
        Ok(records) => Json(serde_json::json!({
            "records": records.iter().map(|(hash, labels)| serde_json::json!({
                "hash": hash,
                "type": labels.get("x-audit-type").unwrap_or(&"-".to_string()),
                "agent": labels.get("x-audit-agent").unwrap_or(&"-".to_string()),
                "result": labels.get("x-audit-result").unwrap_or(&"-".to_string()),
                "target": labels.get("x-audit-target").unwrap_or(&"-".to_string()),
                "time": labels.get("x-audit-time").unwrap_or(&"-".to_string()),
            })).collect::<Vec<_>>()
        })).into_response(),
        Err(e) => map_error(e),
    }
}

// ─── 文件操作 Handler ───

async fn file_write(
    State(state): State<AppState>,
    agent: AgentId,
    Path(path): Path<String>,
    Json(req): Json<FileWriteRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    let labels = req.labels.unwrap_or_default();
    match baize.pipe_file_write(&agent.0, &path, req.content.as_bytes(), Some(labels)) {
        Ok(record) => (StatusCode::CREATED, Json(FileResponse {
            path: record.path,
            hash: record.hash,
            size: record.size,
        })).into_response(),
        Err(e) => map_error(e),
    }
}

async fn file_read(
    State(state): State<AppState>,
    agent: AgentId,
    Path(path): Path<String>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.pipe_file_read(&agent.0, &path) {
        Ok(content) => {
            let text = String::from_utf8_lossy(&content.content).to_string();
            Json(FileContentResponse {
                path: content.path,
                content: text,
                hash: content.hash,
                size: content.size,
            }).into_response()
        }
        Err(e) => map_error(e),
    }
}

async fn file_delete(
    State(state): State<AppState>,
    agent: AgentId,
    Path(path): Path<String>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.pipe_file_delete(&agent.0, &path) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => map_error(e),
    }
}

async fn file_list(
    State(state): State<AppState>,
    agent: AgentId,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.pipe_file_list(&agent.0) {
        Ok(files) => Json(serde_json::json!({"files": files})).into_response(),
        Err(e) => map_error(e),
    }
}

async fn push(
    State(state): State<AppState>,
    agent: AgentId,
    Json(req): Json<PushRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.pipe_push(&agent.0, &req.message, req.r#ref.as_deref()) {
        Ok(result) => (StatusCode::CREATED, Json(serde_json::json!({
            "files": result.files,
            "pending": result.pending,
        }))).into_response(),
        Err(e) => map_error(e),
    }
}

async fn pull(
    State(state): State<AppState>,
    agent: AgentId,
    Json(req): Json<PullRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.pipe_pull(&agent.0, req.r#ref.as_deref()) {
        Ok(result) => Json(serde_json::json!({
            "files": result.files,
        })).into_response(),
        Err(e) => map_error(e),
    }
}

// ─── Repo Stats ───

async fn repo_stats_handler(State(state): State<AppState>) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.repo_stats() {
        Ok(stats) => Json(serde_json::json!({
            "total_blobs": stats.total_blobs,
            "total_commits": stats.total_commits,
            "total_refs": stats.total_refs,
        })).into_response(),
        Err(e) => map_error(e),
    }
}

// ─── 启动服务器 ───

pub async fn serve(baize: Baize, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let app = app(baize);
    axum::serve(listener, app).await?;
    Ok(())
}
