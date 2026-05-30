//! 白泽全特性集成测试 — 共享基础设施
//!
//! 被以下测试文件引用:
//!   - all_features_v0.rs
//!   - all_features_v1.rs
//!   - all_features_v2.rs
//!   - all_features_e2e.rs
//!   - all_features_security.rs

use axum::body::Body;
use axum::Router;
use baize_server::api;
use baize_server::pipeline::auth;
use baize_server::pipeline::agent_manager::KmsManager;
use baize_server::Baize;
use baize_core::crypto::CryptoProvider;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

/// 创建测试用的 axum Router（内存数据库）
pub fn test_app() -> Router {
    let baize = Baize::init_in_memory().unwrap();
    api::app(baize)
}

/// 创建带签名密钥提取的 Baize 实例和 Router
pub fn test_app_with_key(agent_id: &str, level: u8, zones: &[&str]) -> (Router, Vec<u8>) {
    let mut baize = Baize::init_in_memory().unwrap();
    use baize_server::pipeline::AgentRegistry;
    use baize_core::scope::Level;
    baize.agent_register("baize-root", agent_id, Level(level), zones.to_vec(), None).unwrap();
    let key = {
        let pem = baize.kms_get_active_key(agent_id, "IDN_SIGN").unwrap();
        auth::extract_signing_key(&pem)
    };
    let app = api::app(baize);
    (app, key)
}

/// 发送 HTTP 请求，返回 (状态码, JSON 响应体)
pub async fn send(router: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.expect("oneshot failed");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("collect failed").to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, body)
}

// ─── 请求构建辅助 ───

pub fn post_json(uri: &str, body: Value, agent_id: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(id) = agent_id {
        builder = builder.header("x-agent-id", id);
    }
    builder.body(Body::from(serde_json::to_string(&body).unwrap())).unwrap()
}

pub fn get_req(uri: &str) -> Request<Body> {
    Request::builder().method("GET").uri(uri).body(Body::empty()).unwrap()
}

pub fn get_req_with_agent(uri: &str, agent_id: &str) -> Request<Body> {
    Request::builder()
        .method("GET").uri(uri)
        .header("x-agent-id", agent_id)
        .body(Body::empty()).unwrap()
}

pub fn delete_req(uri: &str, agent_id: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE").uri(uri)
        .header("x-agent-id", agent_id)
        .body(Body::empty()).unwrap()
}

pub fn put_json(uri: &str, body: Value, agent_id: &str) -> Request<Body> {
    Request::builder()
        .method("PUT").uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", agent_id)
        .body(Body::from(serde_json::to_string(&body).unwrap())).unwrap()
}

/// 创建带 HMAC-SHA256 签名的请求
pub fn signed_request(
    method: &str,
    uri: &str,
    body: Value,
    agent_id: &str,
    key: &[u8],
    nonce: Option<&str>,
) -> Request<Body> {
    let body_str = serde_json::to_string(&body).unwrap();
    let timestamp = chrono::Utc::now().to_rfc3339();
    let signer = CryptoProvider::default();
    let sig = auth::compute_signature(signer.request_signer.as_ref(), key, &timestamp, method, uri, &body_str);
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", agent_id)
        .header("x-timestamp", &timestamp)
        .header("x-signature", &sig);
    if let Some(n) = nonce {
        builder = builder.header("x-nonce", n);
    }
    builder.body(Body::from(body_str)).unwrap()
}

pub fn signed_get_req(uri: &str, agent_id: &str, key: &[u8]) -> Request<Body> {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let signer = CryptoProvider::default();
    let sig = auth::compute_signature(signer.request_signer.as_ref(), key, &timestamp, "GET", uri, "");
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-agent-id", agent_id)
        .header("x-timestamp", &timestamp)
        .header("x-signature", &sig)
        .body(Body::empty())
        .unwrap()
}

// ─── 时间戳辅助 ───

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

pub fn now_plus_minutes(minutes: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::minutes(minutes)).to_rfc3339()
}

pub fn now_minus_minutes(minutes: i64) -> String {
    (chrono::Utc::now() - chrono::Duration::minutes(minutes)).to_rfc3339()
}

// ─── X25519 公钥辅助 ───

pub fn gen_ephemeral_pub() -> String {
    let (_, pub_pem) = baize_core::crypto::generate_x25519_keypair().unwrap();
    pub_pem.lines().find(|l| !l.starts_with('-')).unwrap().to_string()
}
