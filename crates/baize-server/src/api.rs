use std::sync::Arc;
use std::collections::HashMap;
use std::time::Instant;
use tokio::sync::Mutex;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{request::Parts, StatusCode, Request},
    routing::{get, post, put, delete},
    response::IntoResponse,
    body::Body,
    middleware::{self, Next},
};
use serde::{Deserialize, Serialize};

use crate::pipeline::{
    Baize,
    AgentRegistry, ElevationManager, DataOps, FileSync, GitOps,
    ApprovalManager,
};
use crate::pipeline::agent_manager::PermissionGuard;
use crate::pipeline::auditor::Auditor;
use baize_core::labels::*;
use baize_core::scope::{ElevationMode, Level};
use baize_core::approval::ApprovalRule;

// ─── 错误辅助 ───

/// 将内部错误映射为安全的 HTTP 响应，不暴露内部细节
fn error_response(status: StatusCode, error_type: &str) -> axum::response::Response {
    (
        status,
        Json(serde_json::json!({"error": error_type})),
    ).into_response()
}

/// 从 label map 取值，缺失时返回 JSON null（而非占位符字符串）
fn label_val(labels: &std::collections::HashMap<String, String>, key: &str) -> serde_json::Value {
    labels.get(key)
        .map(|v| serde_json::Value::String(v.clone()))
        .unwrap_or(serde_json::Value::Null)
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
        baize_core::Error::ChannelClosed(_) => (StatusCode::GONE, "channel closed"),
        baize_core::Error::ConstraintViolation(_) => (StatusCode::BAD_REQUEST, "constraint violation"),
        baize_core::Error::ChainBroken(_) => (StatusCode::BAD_REQUEST, "chain broken"),
        baize_core::Error::SignatureInvalid(_) => (StatusCode::UNAUTHORIZED, "authentication failed"),
        baize_core::Error::ExpiredTimestamp(_) => (StatusCode::UNAUTHORIZED, "authentication failed"),
        baize_core::Error::CredentialExpired(_) => (StatusCode::GONE, "credential expired"),
        baize_core::Error::IntentExpired(_) => (StatusCode::GONE, "intent expired"),
        baize_core::Error::AuthorizationExpired(_) => (StatusCode::GONE, "authorization expired"),
        baize_core::Error::KeyRotation(_) => (StatusCode::CONFLICT, "key rotation error"),
        baize_core::Error::ProofRequired(_) => (StatusCode::FORBIDDEN, "proof required"),
        baize_core::Error::ApprovalPending(_) => (StatusCode::ACCEPTED, "approval pending"),
        baize_core::Error::ApprovalRejected(_) => (StatusCode::FORBIDDEN, "approval rejected"),
        baize_core::Error::Unsupported(_) => (StatusCode::METHOD_NOT_ALLOWED, "unsupported operation"),
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

/// v2 nonce 重放防护缓存
pub type NonceCache = Arc<tokio::sync::Mutex<HashMap<String, Instant>>>;

const NONCE_WINDOW_SECS: u64 = 300; // 5 分钟
const NONCE_CACHE_MAX: usize = 100_000; // 防止内存撑爆

// ─── v1 签名验证 middleware ───

/// v1 请求签名验证 middleware
///
/// - 有 x-signature + x-timestamp 头时：验证签名（Ed25519 或 HMAC-SHA256）
/// - 无签名头时：直接放行（fallback 到纯 x-agent-id，过渡期）
async fn v1_signature_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    // v2 路径由 v2 中间件处理，跳过
    if req.uri().path().starts_with("/api/v2") {
        return next.run(req).await;
    }

    let headers = req.headers();
    let has_sig = headers.get("x-signature").is_some() && headers.get("x-timestamp").is_some();

    if !has_sig {
        // 无签名头 → 放行（fallback 到纯 x-agent-id）
        return next.run(req).await;
    }

    // 提取签名相关头
    let agent_id = match headers.get("x-agent-id").and_then(|v| v.to_str().ok()) {
        Some(id) => id.to_string(),
        None => return error_response(StatusCode::UNAUTHORIZED, "missing x-agent-id header"),
    };
    let timestamp = match headers.get("x-timestamp").and_then(|v| v.to_str().ok()) {
        Some(ts) => ts.to_string(),
        None => return error_response(StatusCode::UNAUTHORIZED, "missing x-timestamp header"),
    };
    let signature = match headers.get("x-signature").and_then(|v| v.to_str().ok()) {
        Some(sig) => sig.to_string(),
        None => return error_response(StatusCode::UNAUTHORIZED, "missing x-signature header"),
    };

    let method = req.method().to_string();
    let path = req.uri().path().to_string();

    // 消费 body 用于签名验证
    let (parts, body) = req.into_parts();
    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "failed to read request body"),
    };
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    // 获取 agent 签名密钥
    let baize = state.lock().await;
    match get_agent_signing_key(&baize, &agent_id) {
        Ok(key) => {
            // v1: 允许 HMAC 兼容（旧客户端可能仍用 hmac-sha256: 前缀）
            if let Err(e) = crate::pipeline::auth::verify_signature(
                baize.crypto.request_signer.as_ref(),
                &key, &timestamp, &method, &path, &body_str, &signature,
                true,
            ) {
                return map_error(e);
            }
        }
        Err(_) => {
            // 密钥未找到 → 有签名头但无法验证，拒绝请求
            return error_response(StatusCode::UNAUTHORIZED, "no signing key found for agent");
        }
    }
    drop(baize);

    // 重建请求
    let new_req = Request::from_parts(parts, Body::from(body_bytes));
    next.run(new_req).await
}

/// 获取 agent 的签名密钥
///
/// 查找 IDN_SIGN 用途的 agent-key blob，解密后提取 Ed25519 私钥 seed。
/// 若无法解析 Ed25519 PEM，回退到 HMAC-SHA256（兼容旧数据）。
fn get_agent_signing_key(baize: &Baize, agent_id: &str) -> Result<Vec<u8>, String> {
    use crate::pipeline::agent_manager::KmsManager;
    let pem = baize.kms_get_active_key(agent_id, "IDN_SIGN")
        .map_err(|e| format!("no signing key for agent {}: {}", agent_id, e))?;
    Ok(crate::pipeline::auth::extract_signing_key(&pem))
}

// ─── v2 签名强制 middleware ───

/// v2 请求签名验证 middleware
///
/// 与 v1 相同的签名验证逻辑，但**无签名时直接拒绝**（不 fallback）。
/// 签名方案：Ed25519（默认），密钥来源 INF-KMS IDN_SIGN 用途密钥。
/// 可选 nonce 重放防护：x-nonce 头存在时检查缓存防重放。
async fn v2_signature_middleware(
    State(state): State<AppState>,
    axum::Extension(nonce_cache): axum::Extension<NonceCache>,
    req: Request<Body>,
    next: Next,
) -> axum::response::Response {
    // 只拦截 /api/v2 路径，其他路径直接放行
    let path = req.uri().path().to_string();
    if !path.starts_with("/api/v2") {
        return next.run(req).await;
    }

    let headers = req.headers();

    // v2 强制签名：三个头都必须存在
    let agent_id = match headers.get("x-agent-id").and_then(|v| v.to_str().ok()) {
        Some(id) => id.to_string(),
        None => return error_response(StatusCode::UNAUTHORIZED, "missing x-agent-id header"),
    };
    let timestamp = match headers.get("x-timestamp").and_then(|v| v.to_str().ok()) {
        Some(ts) => ts.to_string(),
        None => return error_response(StatusCode::UNAUTHORIZED, "missing x-timestamp header"),
    };
    let signature = match headers.get("x-signature").and_then(|v| v.to_str().ok()) {
        Some(sig) => sig.to_string(),
        None => return error_response(StatusCode::UNAUTHORIZED, "missing x-signature header"),
    };

    let method = req.method().to_string();

    // 消费 body 用于签名验证
    let (parts, body) = req.into_parts();
    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "failed to read request body"),
    };
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    // 获取 agent 签名密钥并验证
    let baize = state.lock().await;
    match get_agent_signing_key(&baize, &agent_id) {
        Ok(key) => {
            // v2: 只接受 Ed25519 签名（不允许 HMAC 回退）
            if let Err(e) = crate::pipeline::auth::verify_signature(
                baize.crypto.request_signer.as_ref(),
                &key, &timestamp, &method, &path, &body_str, &signature,
                false,
            ) {
                return map_error(e);
            }
        }
        Err(_) => {
            return error_response(StatusCode::UNAUTHORIZED, "no signing key found for agent");
        }
    }
    drop(baize);

    // 可选 nonce 重放防护：x-nonce 存在时检查是否已使用
    if let Some(nonce) = parts.headers.get("x-nonce").and_then(|v| v.to_str().ok()) {
        let mut cache = nonce_cache.lock().await;
        let now = Instant::now();
        // 淘汰过期条目
        cache.retain(|_, t| now.duration_since(*t).as_secs() < NONCE_WINDOW_SECS);
        if cache.contains_key(nonce) {
            return error_response(StatusCode::CONFLICT, "nonce already used");
        }
        // 超过上限时拒绝新 nonce（防止内存攻击）
        if cache.len() >= NONCE_CACHE_MAX {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "nonce cache full, retry later");
        }
        cache.insert(nonce.to_string(), now);
    }

    // 重建请求
    let new_req = Request::from_parts(parts, Body::from(body_bytes));
    next.run(new_req).await
}

pub fn app(baize: Baize) -> Router {
    let state = Arc::new(Mutex::new(baize));
    let nonce_cache: NonceCache = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    Router::new()
        // ─── v0 路由（保持不变）───
        .route("/api/v0/agents", post(register_agent))
        .route("/api/v0/agents", get(list_agents))
        .route("/api/v0/agents/{id}", delete(revoke_agent))
        .route("/api/v0/blobs", post(blob_write))
        .route("/api/v0/blobs/{hash}", get(blob_read))
        .route("/api/v0/blobs/query", post(blob_query))
        .route("/api/v0/log", get(git_log_handler))
        .route("/api/v0/labels", post(label_add))
        .route("/api/v0/labels/query", get(label_query))
        .route("/api/v0/refs", get(git_ref_list_handler))
        .route("/api/v0/refs/{name}", get(git_ref_get_handler))
        .route("/api/v0/refs/{name}", put(git_ref_set_handler))
        .route("/api/v0/refs/{name}", delete(git_ref_delete_handler))
        .route("/api/v0/elevation", post(elevation_request))
        .route("/api/v0/elevation/{id}/approve", post(elevation_approve))
        .route("/api/v0/elevation", get(elevation_list))
        .route("/api/v0/trace/identity/{id}", get(trace_identity))
        .route("/api/v0/import", post(import_data))
        .route("/api/v0/export/{hash}", get(export_data))
        .route("/api/v0/audit", get(audit_query))
        .route("/api/v0/elevation/{id}/return", post(elevation_return))
        .route("/api/v0/files/{*path}", post(file_write))
        .route("/api/v0/files/{*path}", get(file_read))
        .route("/api/v0/files/{*path}", delete(file_delete))
        .route("/api/v0/files", get(file_list))
        .route("/api/v0/push", post(push))
        .route("/api/v0/pull", post(pull))
        .route("/api/v0/repo/stats", get(repo_stats_handler))

        // ─── v1 路由（v0 全部端点 + v1 新增）───
        // v0 兼容端点
        .route("/api/v1/agents", post(register_agent))
        .route("/api/v1/agents", get(list_agents))
        .route("/api/v1/agents/{id}", delete(revoke_agent))
        .route("/api/v1/blobs", post(blob_write))
        .route("/api/v1/blobs/{hash}", get(blob_read))
        .route("/api/v1/blobs/query", post(blob_query))
        .route("/api/v1/log", get(git_log_handler))
        .route("/api/v1/labels", post(label_add))
        .route("/api/v1/labels/query", get(label_query))
        .route("/api/v1/refs", get(git_ref_list_handler))
        .route("/api/v1/refs/{name}", get(git_ref_get_handler))
        .route("/api/v1/refs/{name}", put(git_ref_set_handler))
        .route("/api/v1/refs/{name}", delete(git_ref_delete_handler))
        .route("/api/v1/elevation", post(elevation_request))
        .route("/api/v1/elevation/{id}/approve", post(elevation_approve))
        .route("/api/v1/elevation", get(elevation_list))
        .route("/api/v1/trace/identity/{id}", get(trace_identity))
        .route("/api/v1/import", post(import_data))
        .route("/api/v1/export/{hash}", get(export_data))
        .route("/api/v1/files/{*path}", post(file_write))
        .route("/api/v1/files/{*path}", get(file_read))
        .route("/api/v1/files/{*path}", delete(file_delete))
        .route("/api/v1/files", get(file_list))
        .route("/api/v1/push", post(push))
        .route("/api/v1/pull", post(pull))
        .route("/api/v1/repo/stats", get(repo_stats_handler))

        // v1 新增端点
        .route("/api/v1/intents", post(v1_intent_create))
        .route("/api/v1/intents/derive", post(v1_intent_derive))
        .route("/api/v1/intents/{hash}", get(v1_intent_read))
        .route("/api/v1/intents", get(v1_intent_query))
        .route("/api/v1/receipts", post(v1_receipt_create))
        .route("/api/v1/receipts/{hash}", get(v1_receipt_read))
        .route("/api/v1/receipts", get(v1_receipt_query))
        .route("/api/v1/authorizations", post(v1_authorization_create))
        .route("/api/v1/authorizations/delegate", post(v1_authorization_delegate))
        .route("/api/v1/authorizations/{hash}/verify", post(v1_authorization_verify))
        .route("/api/v1/authorizations/{hash}", get(v1_authorization_read))
        .route("/api/v1/sessions", post(v1_session_create))
        .route("/api/v1/sessions/{id}/accept", post(v1_session_accept))
        .route("/api/v1/sessions/{id}", get(v1_session_read))
        .route("/api/v1/sessions/{id}/close", post(v1_session_close))
        .route("/api/v1/cnv/verify", post(v1_cnv_verify))
        .route("/api/v1/audit", get(v1_audit_query))
        .route("/api/v1/audit/verify-chain", post(v1_audit_verify_chain))
        .route("/api/v1/agents/{id}/status", get(v1_agent_status))
        .route("/api/v1/agents/{id}/status", put(v1_agent_update_status))
        .route("/api/v1/agents/{id}/proof", post(v1_agent_proof))
        .route("/api/v1/agents/{id}/keys/rotate", post(v1_key_rotate))

        // v1 签名验证 middleware（仅对 /api/v1 生效）
        .layer(middleware::from_fn_with_state(state.clone(), v1_signature_middleware))

        // ─── v2 路由（签名强制）───
        .route("/api/v2/blobs", post(blob_write))
        .route("/api/v2/files/{*path}", post(file_write))
        .route("/api/v2/intents", post(v1_intent_create))
        .route("/api/v2/intents/derive", post(v1_intent_derive))
        .route("/api/v2/authorizations", post(v1_authorization_create))
        .route("/api/v2/authorizations/delegate", post(v1_authorization_delegate))
        .route("/api/v2/receipts", post(v1_receipt_create))
        .route("/api/v2/sessions", post(v1_session_create))
        .route("/api/v2/sessions/{id}/accept", post(v1_session_accept))
        .route("/api/v2/sessions/{id}", get(v1_session_read))
        .route("/api/v2/sessions/{id}/close", post(v1_session_close))
        .route("/api/v2/sessions/{id}/message", post(v2_session_message))
        .route("/api/v2/agents/{id}/keys/rotate", post(v1_key_rotate))
        .route("/api/v2/agents/{id}/proof", post(v1_agent_proof))
        .route("/api/v2/agents/{id}/proof/verify", get(v2_proof_verify))
        .route("/api/v2/cnv/verify", post(v1_cnv_verify))

        // v2 审批管理
        .route("/api/v2/approval/pending", get(approval_pending_list))
        .route("/api/v2/approval/requests/{id}", get(approval_request_show))
        .route("/api/v2/approval/requests/{id}/approve", post(approval_request_approve))
        .route("/api/v2/approval/requests/{id}/reject", post(approval_request_reject))
        .route("/api/v2/approval/requests/{id}/escalate", post(approval_request_escalate))
        .route("/api/v2/approval/preauth", get(approval_preauth_list))
        .route("/api/v2/approval/preauth", post(approval_preauth_create))
        .route("/api/v2/approval/preauth/{id}", delete(approval_preauth_delete))
        .route("/api/v2/approval/policy", get(approval_policy_get))
        .route("/api/v2/approval/policy", put(approval_policy_update))

        // v2 签名强制 middleware + nonce 重放防护
        .layer(middleware::from_fn_with_state(state.clone(), v2_signature_middleware))
        .layer(axum::Extension(nonce_cache))
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

// ─── v1 新增 DTO ───

#[derive(Deserialize)]
struct V1IntentCreateRequest {
    content: String,
}

#[derive(Deserialize)]
struct V1IntentDeriveRequest {
    content: String,
}

#[derive(Deserialize)]
struct V1ReceiptCreateRequest {
    content: String,
}

#[derive(Deserialize)]
struct V1AuthorizationCreateRequest {
    content: String,
}

#[derive(Deserialize)]
struct V1AuthorizationDelegateRequest {
    content: String,
}

#[derive(Deserialize)]
struct V1AuthorizationVerifyRequest {
    action_type: String,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    target: Option<serde_json::Value>,
    #[serde(default)]
    amount: Option<f64>,
    #[serde(default)]
    environment: Option<String>,
}

#[derive(Deserialize)]
struct V1SessionCreateRequest {
    session_id: String,
    peer_a: String,
    peer_b: String,
    #[serde(default)]
    ephemeral_pub: String,
    #[serde(default)]
    cipher_suites: Vec<String>,
    #[serde(default)]
    credential_digest_a: String,
    #[serde(default)]
    credential_digest_b: String,
    #[serde(default)]
    handshake_transcript_digest: String,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Deserialize)]
struct V1SessionAcceptRequest {
    credential_digest_responder: String,
    ephemeral_pub: String,
    selected_cipher_suite: String,
    handshake_transcript_digest: String,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Deserialize)]
struct V1SessionCloseRequest {
    reason: Option<String>,
}

#[derive(Deserialize)]
struct V2SessionMessageRequest {
    /// 加密消息内容（服务端不解密）
    ciphertext: String,
    /// 消息序列号（必须单调递增）
    #[serde(rename = "seq")]
    message_seq: u64,
}

#[derive(Deserialize)]
struct V1CnvVerifyRequest {
    receipt_digest: String,
}

#[derive(Deserialize)]
struct V1AgentUpdateStatusRequest {
    status: String,
    #[serde(default)]
    reason: String,
}

#[derive(Deserialize)]
struct V1AgentProofRequest {
    #[serde(default)]
    instance_state_attributes: Option<serde_json::Value>,
    #[serde(default = "default_proof_anchor")]
    proof_anchor_mode: String,
}

fn default_proof_anchor() -> String {
    "CREDENTIAL_ANCHORED".to_string()
}

// ─── 审批 DTO ───

#[derive(Deserialize)]
struct ApprovalApproveRequest {
    granted_count: u32,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Deserialize)]
struct ApprovalRejectRequest {
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
struct ApprovalEscalateRequest {
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
struct PreauthCreateRequest {
    grantee_id: String,
    action: String,
    count: u32,
}

#[derive(Deserialize)]
struct ApprovalPolicyUpdateRequest {
    rules: Vec<ApprovalRule>,
}

// ─── v0 Handler ───

async fn register_agent(
    State(state): State<AppState>,
    agent: AgentId,
    Json(req): Json<RegisterAgentRequest>,
) -> impl IntoResponse {
    let mut baize = state.lock().await;
    match baize.agent_register(
        &agent.0,
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
    agent: AgentId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut baize = state.lock().await;
    match baize.agent_revoke(&agent.0, &id) {
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

// ─── v0 审计查询 ───

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
                "type": label_val(labels, "x-audit-type"),
                "agent": label_val(labels, "x-audit-agent"),
                "result": label_val(labels, "x-audit-result"),
                "target": label_val(labels, "x-audit-target"),
                "time": label_val(labels, "x-audit-time"),
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

// ─── v1 新增 Handler ───

// INT：意图创建（通过 blob write，从 content 解析完整 labels）
async fn v1_intent_create(
    State(state): State<AppState>,
    agent: AgentId,
    Json(req): Json<V1IntentCreateRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    // 从 content JSON 解析 payload，用 adapter 生成完整 labels
    let payload = match baize_asl::AslAdapter::intent_from_blob(&req.content) {
        Ok(p) => p,
        Err(e) => return map_error(e),
    };
    let labels = baize_asl::AslAdapter::intent_to_labels(&payload);
    match baize.pipe_blob_write(&agent.0, &req.content, &labels) {
        Ok(blob) => (StatusCode::CREATED, Json(serde_json::json!({
            "hash": blob.hash,
        }))).into_response(),
        Err(e) => map_error(e),
    }
}

// INT：子意图派生（通过 blob write，从 content 解析完整 labels）
async fn v1_intent_derive(
    State(state): State<AppState>,
    agent: AgentId,
    Json(req): Json<V1IntentDeriveRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    let payload = match baize_asl::AslAdapter::sub_intent_from_blob(&req.content) {
        Ok(p) => p,
        Err(e) => return map_error(e),
    };
    let labels = baize_asl::AslAdapter::sub_intent_to_labels(&payload);
    match baize.pipe_blob_write(&agent.0, &req.content, &labels) {
        Ok(blob) => (StatusCode::CREATED, Json(serde_json::json!({
            "hash": blob.hash,
        }))).into_response(),
        Err(e) => map_error(e),
    }
}

// INT：读取意图
async fn v1_intent_read(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.storage.blob_read(&hash) {
        Ok(blob) => {
            let blob_type = blob.labels.get("type").unwrap_or(&"-".to_string()).clone();
            if blob_type != BLOB_TYPE_INTENT && blob_type != BLOB_TYPE_SUB_INTENT {
                return error_response(StatusCode::NOT_FOUND, "not an intent blob");
            }
            Json(serde_json::json!({
                "hash": blob.hash,
                "content": blob.content,
                "labels": blob.labels,
                "created_at": blob.created_at,
            })).into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

// INT：查询意图
async fn v1_intent_query(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    let mut filter = std::collections::HashMap::new();
    filter.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
    if let Some(status) = params.get("status") {
        filter.insert(LABEL_INTENT_STATUS.to_string(), status.clone());
    }
    if let Some(owner) = params.get("owner") {
        filter.insert(LABEL_INTENT_OWNER.to_string(), owner.clone());
    }
    match baize.storage.blob_query_metadata(&filter) {
        Ok(records) => Json(serde_json::json!({
            "intents": records.iter().map(|(hash, labels)| serde_json::json!({
                "hash": hash,
                "intent_id": label_val(labels, LABEL_INTENT_ID),
                "owner": label_val(labels, LABEL_INTENT_OWNER),
                "status": label_val(labels, LABEL_INTENT_STATUS),
                "expires": label_val(labels, LABEL_INTENT_EXPIRES),
            })).collect::<Vec<_>>()
        })).into_response(),
        Err(e) => map_error(e),
    }
}

// INT：创建回执（从 content 解析完整 labels）
async fn v1_receipt_create(
    State(state): State<AppState>,
    agent: AgentId,
    Json(req): Json<V1ReceiptCreateRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    let payload = match baize_asl::AslAdapter::receipt_from_blob(&req.content) {
        Ok(p) => p,
        Err(e) => return map_error(e),
    };
    let labels = baize_asl::AslAdapter::receipt_to_labels(&payload);
    match baize.pipe_blob_write(&agent.0, &req.content, &labels) {
        Ok(blob) => (StatusCode::CREATED, Json(serde_json::json!({
            "hash": blob.hash,
        }))).into_response(),
        Err(e) => map_error(e),
    }
}

// INT：读取回执
async fn v1_receipt_read(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.storage.blob_read(&hash) {
        Ok(blob) => {
            let blob_type = blob.labels.get("type").unwrap_or(&"-".to_string()).clone();
            if blob_type != BLOB_TYPE_RECEIPT {
                return error_response(StatusCode::NOT_FOUND, "not a receipt blob");
            }
            Json(serde_json::json!({
                "hash": blob.hash,
                "content": blob.content,
                "labels": blob.labels,
                "created_at": blob.created_at,
            })).into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

// INT：查询回执
async fn v1_receipt_query(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    let mut filter = std::collections::HashMap::new();
    filter.insert("type".to_string(), BLOB_TYPE_RECEIPT.to_string());
    if let Some(executor) = params.get("executor") {
        filter.insert(LABEL_RECEIPT_EXECUTOR.to_string(), executor.clone());
    }
    if let Some(status) = params.get("status") {
        filter.insert(LABEL_RECEIPT_STATUS.to_string(), status.clone());
    }
    match baize.storage.blob_query_metadata(&filter) {
        Ok(records) => Json(serde_json::json!({
            "receipts": records.iter().map(|(hash, labels)| serde_json::json!({
                "hash": hash,
                "receipt_id": label_val(labels, LABEL_RECEIPT_ID),
                "executor": label_val(labels, LABEL_RECEIPT_EXECUTOR),
                "status": label_val(labels, LABEL_RECEIPT_STATUS),
            })).collect::<Vec<_>>()
        })).into_response(),
        Err(e) => map_error(e),
    }
}

// AZN：创建授权（从 content 解析完整 labels）
async fn v1_authorization_create(
    State(state): State<AppState>,
    agent: AgentId,
    Json(req): Json<V1AuthorizationCreateRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    let payload = match baize_asl::AslAdapter::authorization_from_blob(&req.content) {
        Ok(p) => p,
        Err(e) => return map_error(e),
    };
    let labels = baize_asl::AslAdapter::authorization_to_labels(&payload);
    match baize.pipe_blob_write(&agent.0, &req.content, &labels) {
        Ok(blob) => (StatusCode::CREATED, Json(serde_json::json!({
            "hash": blob.hash,
        }))).into_response(),
        Err(e) => map_error(e),
    }
}

// AZN：委托子授权（从 content 解析完整 labels）
async fn v1_authorization_delegate(
    State(state): State<AppState>,
    agent: AgentId,
    Json(req): Json<V1AuthorizationDelegateRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    let payload = match baize_asl::AslAdapter::authorization_from_blob(&req.content) {
        Ok(p) => p,
        Err(e) => return map_error(e),
    };
    let labels = baize_asl::AslAdapter::authorization_to_labels(&payload);
    match baize.pipe_blob_write(&agent.0, &req.content, &labels) {
        Ok(blob) => (StatusCode::CREATED, Json(serde_json::json!({
            "hash": blob.hash,
        }))).into_response(),
        Err(e) => map_error(e),
    }
}

// AZN：校验授权（AZN-VER）
async fn v1_authorization_verify(
    State(state): State<AppState>,
    Path(hash): Path<String>,
    Json(req): Json<V1AuthorizationVerifyRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    let exec_ctx = baize_asl::verify::ExecutionContext {
        subject: req.subject,
        target: req.target,
        amount: req.amount,
        environment: req.environment,
    };
    match baize_asl::verify::verify_authorization(baize.store(), &hash, &req.action_type, &exec_ctx) {
        Ok(result) => {
            let checks_map: std::collections::BTreeMap<&str, bool> = [
                ("credential_authenticity", result.checks[0]),
                ("credential_validity", result.checks[1]),
                ("intent_reference", result.checks[2]),
                ("delegation_chain", result.checks[3]),
                ("execution_applicability", result.checks[4]),
            ].into_iter().collect();
            Json(serde_json::json!({
                "valid": result.valid,
                "checks": checks_map,
                "errors": result.errors,
            })).into_response()
        }
        Err(e) => map_error(e),
    }
}

// AZN：读取授权
async fn v1_authorization_read(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.storage.blob_read(&hash) {
        Ok(blob) => {
            let blob_type = blob.labels.get("type").unwrap_or(&"-".to_string()).clone();
            if blob_type != BLOB_TYPE_AUTHORIZATION {
                return error_response(StatusCode::NOT_FOUND, "not an authorization blob");
            }
            Json(serde_json::json!({
                "hash": blob.hash,
                "content": blob.content,
                "labels": blob.labels,
                "created_at": blob.created_at,
            })).into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

// LNK：创建会话（session-init blob）
async fn v1_session_create(
    State(state): State<AppState>,
    agent: AgentId,
    Json(req): Json<V1SessionCreateRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    let now = chrono::Utc::now();
    let expires_at = req.expires_at.unwrap_or_else(|| {
        (now + chrono::Duration::minutes(30)).to_rfc3339()
    });
    let content = serde_json::json!({
        "session_id": req.session_id,
        "peer_a": req.peer_a,
        "peer_b": req.peer_b,
        "credential_hash_a": req.credential_digest_a,
        "credential_hash_b": req.credential_digest_b,
        "handshake_transcript_hash": req.handshake_transcript_digest,
        "ephemeral_pub": req.ephemeral_pub,
        "cipher_suites": req.cipher_suites,
        "established_at": now.to_rfc3339(),
        "expires_at": expires_at,
    }).to_string();
    let labels = std::collections::HashMap::from([
        ("type".to_string(), "session-init".to_string()),
        (LABEL_SESSION_ID.to_string(), req.session_id.clone()),
        (LABEL_SESSION_PEER_A.to_string(), req.peer_a.clone()),
        (LABEL_SESSION_PEER_B.to_string(), req.peer_b.clone()),
        (LABEL_SESSION_STATUS.to_string(), "active".to_string()),
    ]);
    match baize.pipe_blob_write(&agent.0, &content, &labels) {
        Ok(blob) => (StatusCode::CREATED, Json(serde_json::json!({
            "hash": blob.hash,
            "session_id": req.session_id,
            "peer_a": req.peer_a,
            "peer_b": req.peer_b,
            "status": "active",
        }))).into_response(),
        Err(e) => map_error(e),
    }
}

// LNK：接受会话（session-accept blob）
async fn v1_session_accept(
    State(state): State<AppState>,
    agent: AgentId,
    Path(id): Path<String>,
    Json(req): Json<V1SessionAcceptRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;

    // 查找对应的 session-init blob
    let mut init_filter = std::collections::HashMap::new();
    init_filter.insert("type".to_string(), "session-init".to_string());
    init_filter.insert(LABEL_SESSION_ID.to_string(), id.clone());
    let init_blobs = match baize.storage.blob_query(&init_filter) {
        Ok(b) => b,
        Err(e) => return map_error(e),
    };

    if init_blobs.is_empty() {
        return error_response(StatusCode::NOT_FOUND, "session not found");
    }

    let init_blob = &init_blobs[0];
    let now = chrono::Utc::now();
    let expires_at = req.expires_at.unwrap_or_else(|| {
        (now + chrono::Duration::minutes(30)).to_rfc3339()
    });

    let content = serde_json::json!({
        "session_id": id,
        "initiator": init_blob.labels.get(LABEL_SESSION_PEER_A).unwrap_or(&String::new()),
        "responder": init_blob.labels.get(LABEL_SESSION_PEER_B).unwrap_or(&String::new()),
        "credential_digest_responder": req.credential_digest_responder,
        "session_init_digest": init_blob.hash,
        "ephemeral_pub": req.ephemeral_pub,
        "selected_cipher_suite": req.selected_cipher_suite,
        "handshake_transcript_digest": req.handshake_transcript_digest,
        "established_at": now.to_rfc3339(),
        "expires_at": expires_at,
    }).to_string();

    let labels = std::collections::HashMap::from([
        ("type".to_string(), "session-accept".to_string()),
        (LABEL_SESSION_ID.to_string(), id.clone()),
        (LABEL_SESSION_PEER_A.to_string(), init_blob.labels.get(LABEL_SESSION_PEER_A).cloned().unwrap_or_default()),
        (LABEL_SESSION_PEER_B.to_string(), init_blob.labels.get(LABEL_SESSION_PEER_B).cloned().unwrap_or_default()),
        (LABEL_SESSION_STATUS.to_string(), "active".to_string()),
        ("parent".to_string(), init_blob.hash.clone()),
    ]);

    match baize.pipe_blob_write(&agent.0, &content, &labels) {
        Ok(blob) => (StatusCode::CREATED, Json(serde_json::json!({
            "hash": blob.hash,
            "session_id": id,
            "status": "active",
        }))).into_response(),
        Err(e) => map_error(e),
    }
}

// LNK：读取会话
async fn v1_session_read(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    let mut filter = std::collections::HashMap::new();
    filter.insert("type".to_string(), "session-init".to_string());
    filter.insert(LABEL_SESSION_ID.to_string(), id.clone());
    match baize.storage.blob_query(&filter) {
        Ok(blobs) => {
            if let Some(blob) = blobs.first() {
                Json(serde_json::json!({
                    "session_id": id,
                    "content": blob.content,
                    "labels": blob.labels,
                    "created_at": blob.created_at,
                })).into_response()
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

// LNK：关闭 session
async fn v1_session_close(
    State(state): State<AppState>,
    agent: AgentId,
    Path(id): Path<String>,
    Json(req): Json<V1SessionCloseRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;

    // 验证 session 存在且未关闭
    let mut session_filter = std::collections::HashMap::new();
    session_filter.insert("type".to_string(), "session-init".to_string());
    session_filter.insert(LABEL_SESSION_ID.to_string(), id.clone());
    match baize.storage.blob_query(&session_filter) {
        Ok(blobs) if !blobs.is_empty() => {
            // 检查是否已关闭
            let close_filter = vec![
                ("type".to_string(), "session-close".to_string()),
                (LABEL_SESSION_ID.to_string(), id.clone()),
            ];
            let close_map: std::collections::HashMap<String, String> = close_filter.into_iter().collect();
            if let Ok(close_blobs) = baize.storage.blob_query(&close_map) {
                if !close_blobs.is_empty() {
                    return error_response(StatusCode::CONFLICT, "session already closed");
                }
            }
        }
        _ => return error_response(StatusCode::NOT_FOUND, "session not found"),
    }

    let now = chrono::Utc::now().to_rfc3339();
    let reason = req.reason.unwrap_or_default();

    // 计算最终会话摘要：session_id + closed_by + timestamp
    let final_input = format!("{}:{}:{}", id, agent.0, now);
    let final_hash = format!("sha256:{}", {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(final_input.as_bytes());
        hex::encode(hasher.finalize())
    });

    let content = serde_json::json!({
        "session_id": id,
        "action": "close",
        "closed_by": agent.0,
        "reason": reason,
        "final_hash": final_hash,
    }).to_string();
    let mut labels = std::collections::HashMap::from([
        ("type".to_string(), "session-close".to_string()),
        (LABEL_SESSION_ID.to_string(), id.clone()),
        (LABEL_SESSION_STATUS.to_string(), "closed".to_string()),
        (LABEL_SESSION_CLOSED_AT.to_string(), now),
        (LABEL_SESSION_FINAL_HASH.to_string(), final_hash),
    ]);
    if !reason.is_empty() {
        labels.insert(LABEL_SESSION_CLOSE_REASON.to_string(), reason);
    }
    match baize.pipe_blob_write(&agent.0, &content, &labels) {
        Ok(blob) => (StatusCode::CREATED, Json(serde_json::json!({
            "hash": blob.hash,
            "session_id": id,
            "status": "closed",
        }))).into_response(),
        Err(e) => map_error(e),
    }
}

// LNK-DTX：session 内加密消息（v2 专用，签名强制）
async fn v2_session_message(
    State(state): State<AppState>,
    agent: AgentId,
    Path(id): Path<String>,
    Json(req): Json<V2SessionMessageRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;

    // 构造 message content（服务端不解密，只记录密文）
    let content = serde_json::json!({
        "session_id": id,
        "action": "message",
        "from": agent.0,
        "ciphertext": req.ciphertext,
        "seq": req.message_seq,
    }).to_string();

    let labels = std::collections::HashMap::from([
        ("type".to_string(), baize_core::labels::BLOB_TYPE_SESSION_MESSAGE.to_string()),
        (baize_core::labels::LABEL_SESSION_ID.to_string(), id.clone()),
        (baize_core::labels::LABEL_MESSAGE_SEQ.to_string(), req.message_seq.to_string()),
    ]);

    match baize.pipe_blob_write(&agent.0, &content, &labels) {
        Ok(blob) => (StatusCode::CREATED, Json(serde_json::json!({
            "hash": blob.hash,
            "session_id": id,
            "seq": req.message_seq,
        }))).into_response(),
        Err(e) => map_error(e),
    }
}

// INT：CNV 全链路校验
async fn v1_cnv_verify(
    State(state): State<AppState>,
    Json(req): Json<V1CnvVerifyRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize_asl::verify::cnv_verify(baize.store(), &req.receipt_digest) {
        Ok(result) => {
            let intent_chain: Vec<serde_json::Value> = result.intent_chain.iter().map(|node| {
                serde_json::json!({
                    "hash": node.digest,
                    "intent_id": node.intent_id,
                    "depth": node.depth,
                    "valid": true,
                })
            }).collect();
            let authorization_chain = serde_json::json!([{
                "authz_found": result.authz_checks.authz_found,
                "issuer_valid": result.authz_checks.issuer_valid,
                "source_intent_match": result.authz_checks.source_intent_match,
                "delegation_chain_valid": result.authz_checks.delegation_chain_valid,
            }]);
            Json(serde_json::json!({
                "valid": result.valid,
                "intent_chain": intent_chain,
                "authorization_chain": authorization_chain,
                "errors": result.errors,
            })).into_response()
        }
        Err(e) => map_error(e),
    }
}

// AUDIT：v1 审计查询（含链信息）
async fn v1_audit_query(
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
                "type": label_val(labels, "x-audit-type"),
                "agent": label_val(labels, "x-audit-agent"),
                "result": label_val(labels, "x-audit-result"),
                "target": label_val(labels, "x-audit-target"),
                "time": label_val(labels, "x-audit-time"),
                "chain_index": label_val(labels, LABEL_AUDIT_CHAIN_INDEX),
                "prev": label_val(labels, LABEL_AUDIT_PREV),
            })).collect::<Vec<_>>()
        })).into_response(),
        Err(e) => map_error(e),
    }
}

// AUDIT：审计链验证
async fn v1_audit_verify_chain(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.verify_chain() {
        Ok(result) => Json(serde_json::json!({
            "valid": result.valid,
            "chain_length": result.chain_length,
            "head_digest": result.head_digest,
            "genesis_digest": result.genesis_digest,
            "errors": result.errors,
        })).into_response(),
        Err(e) => map_error(e),
    }
}

// IDN：查询凭证状态
async fn v1_agent_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.credential_status(&id) {
        Ok(status) => Json(serde_json::json!({
            "agent_id": id,
            "status": status.to_string(),
        })).into_response(),
        Err(e) => map_error(e),
    }
}

// IDN：更新凭证状态
async fn v1_agent_update_status(
    State(state): State<AppState>,
    _agent: AgentId,
    Path(id): Path<String>,
    Json(req): Json<V1AgentUpdateStatusRequest>,
) -> impl IntoResponse {
    let mut baize = state.lock().await;
    let status = match req.status.parse::<baize_core::cert::CredentialStatus>() {
        Ok(s) => s,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": format!("invalid status '{}', expected: active, suspended, revoked, expired", req.status)
            }))).into_response();
        }
    };
    match baize.update_credential_status(&id, status, &req.reason) {
        Ok(()) => Json(serde_json::json!({
            "agent_id": id,
            "status": status.to_string(),
        })).into_response(),
        Err(e) => map_error(e),
    }
}

// IDN：生成运行态证明
async fn v1_agent_proof(
    State(state): State<AppState>,
    _agent: AgentId,
    Path(id): Path<String>,
    Json(req): Json<V1AgentProofRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    // 验证 agent 存在且凭证有效
    if let Err(e) = baize.credential_status(&id) {
        return map_error(e);
    }

    // 查找 agent-cert blob 获取 credential_digest
    let mut cert_filter = std::collections::HashMap::new();
    cert_filter.insert("type".to_string(), "agent-cert".to_string());
    cert_filter.insert("agent-id".to_string(), id.clone());
    let certs = baize.storage.blob_query(&cert_filter).unwrap_or_default();
    let credential_digest = certs.first()
        .map(|c| c.hash.clone())
        .unwrap_or_default();

    let now = chrono::Utc::now();
    let proof_id = format!("proof-{}-{}", id, now.timestamp_millis());
    let expires = (now + chrono::Duration::minutes(5)).to_rfc3339();

    let instance_attrs = req.instance_state_attributes
        .unwrap_or(serde_json::json!({
            "instance_id": id,
            "instance_status": "running"
        }));

    // Phase 4: 使用 3 组属性计算正确的 binding_context_digest
    let cert_labels = certs.first()
        .map(|c| c.labels.clone())
        .unwrap_or_default();
    let binding_digest = baize_asl::AslAdapter::compute_binding_context_digest(
        &cert_labels,
        &instance_attrs,
    );

    let anchor_mode = match req.proof_anchor_mode.as_str() {
        "ENVIRONMENT_ANCHORED" => baize_asl::payload::ProofAnchorMode::EnvironmentAnchored,
        _ => baize_asl::payload::ProofAnchorMode::CredentialAnchored,
    };

    let proof = baize_asl::payload::RuntimeProofContent {
        proof_id: proof_id.clone(),
        credential_digest: credential_digest.clone(),
        instance_state_attributes: instance_attrs,
        binding_context_digest: binding_digest,
        proof_anchor_mode: anchor_mode,
        issued_at: now.to_rfc3339(),
        expires_at: expires.clone(),
    };
    let content = serde_json::to_string(&proof).unwrap();

    let labels = std::collections::HashMap::from([
        ("type".to_string(), "runtime-proof".to_string()),
        (LABEL_PROOF_AGENT.to_string(), id.clone()),
        (LABEL_PROOF_CREDENTIAL.to_string(), credential_digest),
    ]);
    match baize.pipe_blob_write(&id, &content, &labels) {
        Ok(blob) => (StatusCode::CREATED, Json(serde_json::json!({
            "hash": blob.hash,
            "proof_id": proof_id,
            "expires_at": expires,
        }))).into_response(),
        Err(e) => map_error(e),
    }
}

// ─── INF-KMS 密钥轮换 ───

#[derive(serde::Deserialize)]
struct KeyRotateRequest {
    purpose: String,
}

async fn v1_key_rotate(
    State(state): State<AppState>,
    agent: AgentId,
    Path(id): Path<String>,
    Json(req): Json<KeyRotateRequest>,
) -> axum::response::Response {
    // 权限隔离：只有 agent 本人或 baize-root 可以轮换密钥
    if agent.0 != id && agent.0 != baize_core::ROOT_AGENT_ID {
        return error_response(StatusCode::FORBIDDEN, "only the agent itself or root can rotate keys");
    }
    let mut baize = state.lock().await;
    use crate::pipeline::agent_manager::KmsManager;
    match baize.kms_rotate_key(&id, &req.purpose) {
        Ok(new_key_hash) => (StatusCode::OK, Json(serde_json::json!({
            "agent_id": id,
            "purpose": req.purpose,
            "new_key_hash": new_key_hash,
        }))).into_response(),
        Err(e) => map_error(e),
    }
}

// ─── v2 新增 Handler ───

// IDN-ATH：验证 agent 是否持有有效运行态证明
async fn v2_proof_verify(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.require_valid_proof(&id) {
        Ok(proof) => (StatusCode::OK, Json(serde_json::json!({
            "valid": true,
            "proof_id": proof.proof_id,
            "expires_at": proof.expires_at,
        }))).into_response(),
        Err(e) => map_error(e),
    }
}

// ─── 审批管理 Handler ───

// 列出待当前 agent 审批的请求
async fn approval_pending_list(
    State(state): State<AppState>,
    agent: AgentId,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.approval_pending(&agent.0) {
        Ok(requests) => Json(serde_json::json!({
            "requests": requests.iter().map(|r| serde_json::json!({
                "id": r.id,
                "requester_id": r.requester_id,
                "requester_level": r.requester_level,
                "action": r.action.to_string(),
                "status": r.status.to_string(),
                "created_at": r.created_at,
            })).collect::<Vec<_>>()
        })).into_response(),
        Err(e) => map_error(e),
    }
}

// 查看审批请求详情（含完整传导链）
async fn approval_request_show(
    State(state): State<AppState>,
    agent: AgentId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.approval_show(&id, &agent.0) {
        Ok(req) => Json(serde_json::json!({
            "id": req.id,
            "requester_id": req.requester_id,
            "requester_level": req.requester_level,
            "action": req.action.to_string(),
            "status": req.status.to_string(),
            "pending_at": req.pending_at,
            "granted_count": req.granted_count,
            "remaining_count": req.remaining_count,
            "created_at": req.created_at,
            "expires_at": req.expires_at,
            "chain": req.chain.iter().map(|hop| serde_json::json!({
                "agent_id": hop.agent_id,
                "level": hop.level,
                "decision": hop.decision.to_string(),
                "note": hop.note,
                "decided_at": hop.decided_at,
            })).collect::<Vec<_>>(),
        })).into_response(),
        Err(e) => map_error(e),
    }
}

// 审批通过
async fn approval_request_approve(
    State(state): State<AppState>,
    agent: AgentId,
    Path(id): Path<String>,
    Json(req): Json<ApprovalApproveRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.approval_approve(&id, &agent.0, req.granted_count, req.note.as_deref()) {
        Ok(status) => Json(serde_json::json!({
            "request_id": id,
            "status": status.to_string(),
        })).into_response(),
        Err(e) => map_error(e),
    }
}

// 驳回请求
async fn approval_request_reject(
    State(state): State<AppState>,
    agent: AgentId,
    Path(id): Path<String>,
    Json(req): Json<ApprovalRejectRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.approval_reject(&id, &agent.0, req.reason.as_deref()) {
        Ok(status) => Json(serde_json::json!({
            "request_id": id,
            "status": status.to_string(),
        })).into_response(),
        Err(e) => map_error(e),
    }
}

// 越权上传
async fn approval_request_escalate(
    State(state): State<AppState>,
    agent: AgentId,
    Path(id): Path<String>,
    Json(req): Json<ApprovalEscalateRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.approval_escalate(&id, &agent.0, req.reason.as_deref()) {
        Ok(status) => Json(serde_json::json!({
            "request_id": id,
            "status": status.to_string(),
        })).into_response(),
        Err(e) => map_error(e),
    }
}

// 列出预授权
async fn approval_preauth_list(
    State(state): State<AppState>,
    agent: AgentId,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.approval_list_preauth(&agent.0) {
        Ok(preauths) => Json(serde_json::json!({
            "preauths": preauths.iter().map(|pa| serde_json::json!({
                "id": pa.id,
                "granter_id": pa.granter_id,
                "grantee_id": pa.grantee_id,
                "action": pa.action.to_string(),
                "granted_count": pa.granted_count,
                "remaining_count": pa.remaining_count,
                "created_at": pa.created_at,
            })).collect::<Vec<_>>()
        })).into_response(),
        Err(e) => map_error(e),
    }
}

// 创建预授权
async fn approval_preauth_create(
    State(state): State<AppState>,
    agent: AgentId,
    Json(req): Json<PreauthCreateRequest>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    let action = match req.action.parse::<baize_core::approval::ApprovalAction>() {
        Ok(a) => a,
        Err(msg) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("invalid action: {}", msg)
        }))).into_response(),
    };
    match baize.approval_preauth(&agent.0, &req.grantee_id, &action, req.count) {
        Ok(pa) => (StatusCode::CREATED, Json(serde_json::json!({
            "id": pa.id,
            "granter_id": pa.granter_id,
            "grantee_id": pa.grantee_id,
            "action": pa.action.to_string(),
            "granted_count": pa.granted_count,
            "remaining_count": pa.remaining_count,
        }))).into_response(),
        Err(e) => map_error(e),
    }
}

// 删除预授权（仅 root 或授权者可操作）
async fn approval_preauth_delete(
    State(state): State<AppState>,
    agent: AgentId,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    match baize.approval_delete_preauth(&id, &agent.0) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => map_error(e),
    }
}

// 查看审批策略
async fn approval_policy_get(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let baize = state.lock().await;
    let rules = baize.approval_policy_get();
    Json(serde_json::json!({ "rules": rules })).into_response()
}

// 更新审批策略（仅 root 可操作）
async fn approval_policy_update(
    State(state): State<AppState>,
    agent: AgentId,
    Json(req): Json<ApprovalPolicyUpdateRequest>,
) -> impl IntoResponse {
    if agent.0 != baize_core::ROOT_AGENT_ID {
        return error_response(StatusCode::FORBIDDEN, "only root can update approval policy");
    }
    let baize = state.lock().await;
    match baize.approval_policy_update(req.rules) {
        Ok(()) => Json(serde_json::json!({ "status": "updated" })).into_response(),
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
