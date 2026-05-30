use axum::body::Body;
use baize_server::api;
use baize_server::Baize;
use baize_server::pipeline::AgentRegistry;
use baize_server::pipeline::DataOps;
use baize_core::crypto::CryptoProvider;
use baize_core::labels::*;
use baize_core::scope::Level;
use http_body_util::BodyExt;
use http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

// ─── 辅助函数 ───

fn test_app() -> axum::Router {
    let baize = Baize::init_in_memory().unwrap();
    api::app(baize)
}

/// 通过 Router 发送请求，返回 (状态码, 响应体 JSON)
/// 接收 &Router 引用，内部 clone 以支持同一 app 连续请求
async fn send(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let response = router.clone().oneshot(req).await
        .expect("tower oneshot should not fail for valid requests");
    let status = response.status();
    let body_bytes = response.into_body()
        .collect()
        .await
        .expect("body collect should not fail")
        .to_bytes();
    let body: Value = serde_json::from_slice(&body_bytes).unwrap_or(json!(null));
    (status, body)
}

/// 辅助：生成合法 X25519 公钥 base64（用于 session 测试）
fn gen_ephemeral_pub() -> String {
    let (_, pub_pem) = baize_core::crypto::generate_x25519_keypair().unwrap();
    pub_pem.lines().find(|l| !l.starts_with('-')).unwrap().to_string()
}

fn post_json(uri: &str, body: Value, agent_id: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(id) = agent_id {
        builder = builder.header("x-agent-id", id);
    }
    builder.body(Body::from(serde_json::to_string(&body).unwrap())).unwrap()
}

fn get_req(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

fn get_req_with_agent(uri: &str, agent_id: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-agent-id", agent_id)
        .body(Body::empty())
        .unwrap()
}

fn delete_req(uri: &str, agent_id: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("x-agent-id", agent_id)
        .body(Body::empty())
        .unwrap()
}

/// 创建带 HMAC-SHA256 签名的 POST 请求
fn post_json_signed(
    uri: &str,
    body: Value,
    agent_id: &str,
    signing_key: &[u8],
) -> Request<Body> {
    let body_str = serde_json::to_string(&body).unwrap();
    let timestamp = chrono::Utc::now().to_rfc3339();
    let method = "POST";
    let sig = baize_server::pipeline::auth::compute_signature(
        CryptoProvider::default().request_signer.as_ref(),
        signing_key, &timestamp, method, uri, &body_str,
    );
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", agent_id)
        .header("x-timestamp", &timestamp)
        .header("x-signature", &sig)
        .body(Body::from(body_str))
        .unwrap()
}

/// 获取 agent 的签名密钥（从 test app 的 Baize 实例中）
/// 注意：这需要在创建 app 前提取密钥，或使用已知密钥。
/// 为简化测试，直接用 extract_signing_key 从已知 PEM 计算。
fn get_test_signing_key(baize: &Baize, agent_id: &str) -> Vec<u8> {
    let mut filter = std::collections::HashMap::new();
    filter.insert("type".to_string(), "agent-key".to_string());
    filter.insert("agent-id".to_string(), agent_id.to_string());
    filter.insert("x-key-purpose".to_string(), "IDN_SIGN".to_string());
    let keys = baize.storage.blob_query(&filter).unwrap_or_default();
    let key_blob = keys.first().expect("agent should have an IDN_SIGN key");
    baize_server::pipeline::auth::extract_signing_key(&key_blob.content)
}

// ─── 1. Agent 管理 ───

#[tokio::test]
async fn test_register_agent() {
    let app = test_app();
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "agent-1", "level": 3, "zones": ["A", "B", "C"]}),
        Some("baize-root"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["id"], "agent-1");
    assert_eq!(body["level"], 3);
    assert!(body["zones"].as_array().unwrap().len() >= 2);
    assert!(body["cert_pem"].as_str().unwrap().contains("CERTIFICATE"));
}

#[tokio::test]
async fn test_list_agents() {
    let app = test_app();
    // 注册 agent
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "list-test", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);

    // 列表应包含 root + list-test
    let req = get_req("/api/v0/agents");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    let agents = body.as_array().unwrap();
    assert!(agents.len() >= 2);
    assert!(agents.iter().any(|a| a["id"] == "baize-root"));
    assert!(agents.iter().any(|a| a["id"] == "list-test"));
}

#[tokio::test]
async fn test_revoke_agent() {
    let app = test_app();
    // 注册
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "to-revoke", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);

    // 撤销
    let req = delete_req("/api/v0/agents/to-revoke", "baize-root");
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // 列表中不应包含 to-revoke
    let req = get_req("/api/v0/agents");
    let (_, body) = send(&app, req).await;
    let agents = body.as_array().unwrap();
    assert!(!agents.iter().any(|a| a["id"] == "to-revoke"));
}

#[tokio::test]
async fn test_revoke_root_fails() {
    let app = test_app();
    let req = delete_req("/api/v0/agents/baize-root", "baize-root");
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_register_duplicate_agent_fails() {
    let app = test_app();
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "dup", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);

    // 同名注册应返回 409 Conflict
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "dup", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

// ─── 2. Blob 操作 ───

#[tokio::test]
async fn test_blob_write_read_roundtrip() {
    let app = test_app();
    // 写入
    let req = post_json(
        "/api/v0/blobs",
        json!({"content": "hello baize", "labels": {"type": "greeting"}}),
        Some("baize-root"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);
    let hash = body["hash"].as_str().unwrap().to_string();

    // 读取
    let req = get_req(&format!("/api/v0/blobs/{}", hash));
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["content"], "hello baize");
    assert_eq!(body["labels"]["type"], "greeting");
}

#[tokio::test]
async fn test_blob_query_by_labels() {
    let app = test_app();
    // 写入两个不同标签的 blob
    let req1 = post_json(
        "/api/v0/blobs",
        json!({"content": "alpha data", "labels": {"kind": "alpha"}}),
        Some("baize-root"),
    );
    send(&app, req1).await;

    let req2 = post_json(
        "/api/v0/blobs",
        json!({"content": "beta data", "labels": {"kind": "beta"}}),
        Some("baize-root"),
    );
    send(&app, req2).await;

    // 查询 kind=alpha
    let req = post_json(
        "/api/v0/blobs/query",
        json!({"labels": {"kind": "alpha"}}),
        None,
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    let results = body.as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["content"], "alpha data");
}

#[tokio::test]
async fn test_blob_write_requires_auth() {
    let app = test_app();
    let req = post_json(
        "/api/v0/blobs",
        json!({"content": "unauthorized"}),
        None,
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ─── 3. Label 操作 ───

#[tokio::test]
async fn test_label_add_and_query() {
    let app = test_app();
    // 写入 blob
    let req = post_json("/api/v0/blobs", json!({"content": "labeled"}), Some("baize-root"));
    let (_, b) = send(&app, req).await;
    let hash = b["hash"].as_str().unwrap();

    // 添加 label
    let req = post_json(
        "/api/v0/labels",
        json!({"entity_hash": hash, "key": "priority", "value": "high"}),
        Some("baize-root"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);

    // 查询 label
    let req = get_req("/api/v0/labels/query?key=priority&value=high");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    let labels = body["labels"].as_array().unwrap();
    assert_eq!(labels.len(), 1);
    assert_eq!(labels[0]["entity_hash"], hash);
    assert_eq!(labels[0]["key"], "priority");
}

#[tokio::test]
async fn test_label_add_to_nonexistent_entity() {
    let app = test_app();
    let req = post_json(
        "/api/v0/labels",
        json!({"entity_hash": "deadbeef00", "key": "x", "value": "y"}),
        Some("baize-root"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ─── 5. Elevation 流程 ───

#[tokio::test]
async fn test_elevation_request_approve_list() {
    let app = test_app();
    // 注册 agent
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "worker", "level": 3, "zones": ["A", "B", "C"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 申请借权
    let req = post_json(
        "/api/v0/elevation",
        json!({"agent_id": "worker", "zones": ["B"], "mode": "readonly", "reason": "need B access"}),
        None,
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);
    let req_id = body["request_id"].as_str().unwrap().to_string();

    // 列表 → pending
    let req = get_req("/api/v0/elevation");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    let requests = body["requests"].as_array().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0]["status"].as_str().unwrap().contains("Pending"));

    // 审批
    let req = post_json(
        &format!("/api/v0/elevation/{}/approve", req_id),
        json!({}),
        Some("baize-root"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "approved");
}

#[tokio::test]
async fn test_elevation_zone_beyond_scope_succeeds() {
    // 借权允许申请超出自己 scope 的 zone
    let app = test_app();
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "limited", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // limited 只有 zone A，但可以申请 zone Z（超出 scope，需审批）
    let req = post_json(
        "/api/v0/elevation",
        json!({"agent_id": "limited", "zones": ["Z"], "mode": "readonly", "reason": "need Z"}),
        None,
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn test_elevation_nonexistent_agent_fails() {
    let app = test_app();
    let req = post_json(
        "/api/v0/elevation",
        json!({"agent_id": "ghost", "zones": ["A"], "mode": "readonly", "reason": "test"}),
        None,
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ─── 7. Trace 操作 ───

#[tokio::test]
async fn test_trace_identity() {
    let app = test_app();
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "child", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    let req = get_req("/api/v0/trace/identity/child");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    let chain = body["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0]["agent_id"], "child");
    assert_eq!(chain[1]["agent_id"], "baize-root");
}

// ─── 8. Import/Export ───

#[tokio::test]
async fn test_import_with_labels() {
    let app = test_app();
    let req = post_json(
        "/api/v0/import",
        json!({"content": "external data", "source": "unittest", "trust_level": 2}),
        Some("baize-root"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(!body["hash"].as_str().unwrap().is_empty());
    assert_eq!(body["trust_level"], 2);
}

#[tokio::test]
async fn test_export_roundtrip() {
    let app = test_app();
    // import
    let req = post_json(
        "/api/v0/import",
        json!({"content": "roundtrip test", "source": "test", "trust_level": 2}),
        Some("baize-root"),
    );
    let (_, body) = send(&app, req).await;
    let hash = body["hash"].as_str().unwrap();

    // export
    let req = get_req_with_agent(&format!("/api/v0/export/{}", hash), "baize-root");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["content"], "roundtrip test");
    assert_eq!(body["labels"]["imported"], "true");
    assert_eq!(body["labels"]["source"], "test");
}

#[tokio::test]
async fn test_import_size_limit() {
    let app = test_app();
    let large_content = "x".repeat(10 * 1024 * 1024 + 1);
    let req = post_json(
        "/api/v0/import",
        json!({"content": large_content, "source": "test", "trust_level": 0}),
        Some("baize-root"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

// ─── 9. Auth ───

#[tokio::test]
async fn test_write_endpoints_require_agent_id() {
    let endpoints: Vec<(&str, Value)> = vec![
        ("/api/v0/blobs", json!({"content": "x"})),
        ("/api/v0/labels", json!({"entity_hash": "x", "key": "x", "value": "x"})),
    ];

    for (uri, body) in endpoints {
        let app = test_app();
        let req = post_json(uri, body.clone(), None);
        let (status, _) = send(&app, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "expected 401 for {}", uri);
    }
}

// ─── 10. 三层决策 ───

#[tokio::test]
async fn test_level0_sandbox_write_denied() {
    // Level 0 agent 不能写入，应返回 403
    let app = test_app();
    // 注册 Level 0 agent
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "sandbox", "level": 0, "zones": []}),
        Some("baize-root"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);

    // sandbox agent 尝试 blob write → 应被拒
    let req = post_json(
        "/api/v0/blobs",
        json!({"content": "sandbox data"}),
        Some("sandbox"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "permission denied");
}

#[tokio::test]
async fn test_nonroot_agent_can_write() {
    // 非 root 的普通 agent（Level >= 1）可以正常写入
    let app = test_app();
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "worker", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);

    // worker agent 写入 blob → 应成功
    let req = post_json(
        "/api/v0/blobs",
        json!({"content": "worker data", "labels": {"owner": "worker"}}),
        Some("worker"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(!body["hash"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn test_nonexistent_agent_write_denied() {
    // 不存在的 agent 尝试写入 → 应返回 422 (NeedUserDecision)
    let app = test_app();
    let req = post_json(
        "/api/v0/blobs",
        json!({"content": "ghost data"}),
        Some("ghost-agent"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"], "user decision required");
}

#[tokio::test]
async fn test_export_allows_sandbox_agent() {
    // Level 0 sandbox agent 可以导出（读操作不限制 level）
    let app = test_app();
    // root 写入 blob
    let req = post_json(
        "/api/v0/blobs",
        json!({"content": "exportable data"}),
        Some("baize-root"),
    );
    let (_, body) = send(&app, req).await;
    let hash = body["hash"].as_str().unwrap();

    // 注册 sandbox agent
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "sandbox", "level": 0, "zones": []}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // sandbox 导出 → 应成功
    let req = get_req_with_agent(&format!("/api/v0/export/{}", hash), "sandbox");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["content"], "exportable data");
}

// ─── 11. 借权 Duration + 审批路由 ───

#[tokio::test]
async fn test_elevation_with_duration() {
    let app = test_app();
    // 注册 agent
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "worker", "level": 3, "zones": ["A", "B"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 申请借权（带 duration）
    let req = post_json(
        "/api/v0/elevation",
        json!({"agent_id": "worker", "zones": ["B"], "mode": "readonly", "reason": "need B", "duration": "30m"}),
        None,
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);
    let req_id = body["request_id"].as_str().unwrap();

    // 审批
    let req = post_json(
        &format!("/api/v0/elevation/{}/approve", req_id),
        json!({}),
        Some("baize-root"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);

    // 列表应显示已审批 + expires_at
    let req = get_req("/api/v0/elevation");
    let (_, body) = send(&app, req).await;
    let requests = body["requests"].as_array().unwrap();
    let found = requests.iter().find(|r| r["id"] == req_id).unwrap();
    assert!(found["expires_at"].as_str().is_some());
}

#[tokio::test]
async fn test_approval_routing() {
    let app = test_app();
    // 注册 parent + child
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "parent", "level": 3, "zones": ["A", "B"]}),
        Some("baize-root"),
    );
    send(&app, req).await;
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "child", "level": 2, "zones": ["A"], "parent_id": "parent"}),
        Some("parent"),
    );
    send(&app, req).await;

    // child 申请 zone A（在 parent scope 内）
    let req = post_json(
        "/api/v0/elevation",
        json!({"agent_id": "child", "zones": ["A"], "mode": "readonly", "reason": "need A"}),
        None,
    );
    let (_, body) = send(&app, req).await;
    let req_id = body["request_id"].as_str().unwrap();

    // parent 审批 → 应成功
    let req = post_json(
        &format!("/api/v0/elevation/{}/approve", req_id),
        json!({}),
        Some("parent"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
}

// ─── 12. 导出审批（P2-1） ───

#[tokio::test]
async fn test_export_sensitive_blob() {
    let app = test_app();

    // root 写入 sensitivity=high 的 blob
    let req = post_json(
        "/api/v0/blobs",
        json!({"content": "top secret", "labels": {"sensitivity": "high"}}),
        Some("baize-root"),
    );
    let (_, body) = send(&app, req).await;
    let hash = body["hash"].as_str().unwrap();

    // 注册 level 1 agent
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "low-agent", "level": 1, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // level 1 agent 导出 sensitivity=high → 403
    let req = get_req_with_agent(&format!("/api/v0/export/{}", hash), "low-agent");
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // root 导出 → 200
    let req = get_req_with_agent(&format!("/api/v0/export/{}", hash), "baize-root");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["content"], "top secret");
}

#[tokio::test]
async fn test_export_zone_restricted_blob() {
    let app = test_app();

    // root 写入 zone=B 的 blob
    let req = post_json(
        "/api/v0/blobs",
        json!({"content": "zone B data", "labels": {"zone": "B"}}),
        Some("baize-root"),
    );
    let (_, body) = send(&app, req).await;
    let hash = body["hash"].as_str().unwrap();

    // 注册 scope=["A"] 的 agent
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "agent-a", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // agent-a 导出 zone=B 的 blob → 403
    let req = get_req_with_agent(&format!("/api/v0/export/{}", hash), "agent-a");
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // root (zones=*) 导出 → 200
    let req = get_req_with_agent(&format!("/api/v0/export/{}", hash), "baize-root");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["content"], "zone B data");
}

// ─── 13. 用户决策层 ───

#[tokio::test]
async fn test_nonexistent_agent_returns_user_decision() {
    let app = test_app();

    // 不存在的 agent 尝试写入 → 422 (Unprocessable Entity)
    let req = post_json(
        "/api/v0/blobs",
        json!({"content": "test"}),
        Some("ghost-agent"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"], "user decision required");
}

// ─── 14. 审计查询 ───

#[tokio::test]
async fn test_audit_query() {
    let app = test_app();

    // 写入 blob（产生审计记录）
    let req = post_json(
        "/api/v0/blobs",
        json!({"content": "audited data"}),
        Some("baize-root"),
    );
    let (_, _) = send(&app, req).await;

    // 查询审计日志
    let req = get_req("/api/v0/audit");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    let records = body["records"].as_array().unwrap();
    assert!(!records.is_empty());
    assert_eq!(records[0]["type"], "blob_write");
    assert_eq!(records[0]["agent"], "baize-root");
}

#[tokio::test]
async fn test_audit_filter_by_agent() {
    let app = test_app();

    // root 写入
    let req = post_json(
        "/api/v0/blobs",
        json!({"content": "root data"}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 注册 agent 并写入
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "worker", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;
    let req = post_json(
        "/api/v0/blobs",
        json!({"content": "worker data"}),
        Some("worker"),
    );
    send(&app, req).await;

    // 过滤 worker 的审计记录
    let req = get_req("/api/v0/audit?agent=worker");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    let records = body["records"].as_array().unwrap();
    assert!(records.iter().all(|r| r["agent"] == "worker"));
}

// ─── 15. 文件操作 ───

#[tokio::test]
async fn test_file_write_and_read() {
    let app = test_app();

    // 写入文件
    let req = post_json(
        "/api/v0/files/config/app.yaml",
        json!({"content": "key: value\n"}),
        Some("baize-root"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["path"], "config/app.yaml");
    assert!(!body["hash"].as_str().unwrap().is_empty());
    assert_eq!(body["size"], 11);

    // 读取文件
    let req = get_req_with_agent("/api/v0/files/config/app.yaml", "baize-root");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["content"], "key: value\n");
    assert_eq!(body["path"], "config/app.yaml");
    assert_eq!(body["size"], 11);
}

#[tokio::test]
async fn test_file_write_creates_blob() {
    let app = test_app();

    // 写入文件
    let req = post_json(
        "/api/v0/files/notes/log.txt",
        json!({"content": "hello file", "labels": {"kind": "note"}}),
        Some("baize-root"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);

    // 查询 blob — 应有 type=file, action=write 的记录
    let req = post_json(
        "/api/v0/blobs/query",
        json!({"labels": {"type": "file", "path": "notes/log.txt"}}),
        None,
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    let results = body.as_array().unwrap();
    assert!(!results.is_empty());
    let blob = &results[0];
    assert_eq!(blob["labels"]["action"], "write");
    assert_eq!(blob["labels"]["agent"], "baize-root");
}

#[tokio::test]
async fn test_file_delete() {
    let app = test_app();

    // 写入
    let req = post_json(
        "/api/v0/files/temp/cache.tmp",
        json!({"content": "tmp data"}),
        Some("baize-root"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);

    // 删除
    let req = delete_req("/api/v0/files/temp/cache.tmp", "baize-root");
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // 再读取应 404
    let req = get_req_with_agent("/api/v0/files/temp/cache.tmp", "baize-root");
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_file_delete_records_audit() {
    let app = test_app();

    // 写入
    let req = post_json(
        "/api/v0/files/data/info.txt",
        json!({"content": "info"}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 删除
    let req = delete_req("/api/v0/files/data/info.txt", "baize-root");
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // 审计应有 file_delete 记录
    let req = get_req("/api/v0/audit?type=file_delete");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    let records = body["records"].as_array().unwrap();
    assert!(records.iter().any(|r| r["type"] == "file_delete"));
}

#[tokio::test]
async fn test_file_zone_check_blocks() {
    let app = test_app();

    // 注册 scope=["A"] 的 agent
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "zone-a", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 尝试写入 zone B 的文件 → 应被拒
    let req = post_json(
        "/api/v0/files/B/secret.txt",
        json!({"content": "forbidden"}),
        Some("zone-a"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body["error"].as_str().unwrap().contains("permission denied"));
}

#[tokio::test]
async fn test_file_zone_root_accessible() {
    let app = test_app();

    // 注册 scope=["A"] 的 agent
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "zone-a", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // root 写入根级文件（无 / 前缀段）→ push 到主仓库
    let req = post_json(
        "/api/v0/files/README.md",
        json!({"content": "# Hello"}),
        Some("baize-root"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);

    // root push 到主仓库
    let req = post_json(
        "/api/v0/push",
        json!({"message": "add README"}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // zone-a pull → 文件出现在 zone-a workspace
    let req = post_json(
        "/api/v0/pull",
        json!({}),
        Some("zone-a"),
    );
    send(&app, req).await;

    // zone-a agent 可以读取根级文件（无 zone 限制）
    let req = get_req_with_agent("/api/v0/files/README.md", "zone-a");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["content"], "# Hello");
}

#[tokio::test]
async fn test_file_list() {
    let app = test_app();

    // 写入两个文件
    let req = post_json(
        "/api/v0/files/A/one.txt",
        json!({"content": "one"}),
        Some("baize-root"),
    );
    send(&app, req).await;
    let req = post_json(
        "/api/v0/files/A/two.txt",
        json!({"content": "two"}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 列出 root workspace 的文件
    let req = get_req_with_agent("/api/v0/files", "baize-root");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    let files = body["files"].as_array().unwrap();
    assert!(files.len() >= 2);
    assert!(files.iter().any(|f| f.as_str() == Some("A/one.txt")));
    assert!(files.iter().any(|f| f.as_str() == Some("A/two.txt")));
}

#[tokio::test]
async fn test_file_level0_cannot_write() {
    let app = test_app();

    // 注册 Level 0 sandbox agent
    let req = post_json(
        "/api/v0/agents",
        json!({"name": "sandbox", "level": 0, "zones": []}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // sandbox 尝试写入文件 → 应被拒
    let req = post_json(
        "/api/v0/files/data.txt",
        json!({"content": "sandbox write"}),
        Some("sandbox"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body["error"].as_str().unwrap().contains("permission denied"));
}

// ─── v1 API 集成测试 ───

fn put_json(uri: &str, body: Value, agent_id: &str) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", agent_id)
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

#[tokio::test]
async fn test_v1_intent_create_and_read() {
    let app = test_app();

    let intent_content = json!({
        "intent_id": "int-test-001",
        "intent_owner": "baize-root",
        "intent_creator": "baize-root",
        "intent_goal": "deploy",
        "intent_constraints": {"budget": 100},
        "version": "1.0",
        "created_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-12-31T23:59:59Z",
    });
    let req = post_json(
        "/api/v1/intents",
        json!({"content": serde_json::to_string(&intent_content).unwrap()}),
        Some("baize-root"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);
    let hash = body["hash"].as_str().unwrap();
    assert!(!hash.is_empty());

    let req = get_req(&format!("/api/v1/intents/{}", hash));
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["hash"], hash);
    assert!(body["content"].as_str().unwrap().contains("int-test-001"));
}

#[tokio::test]
async fn test_v1_intent_create_invalid_json() {
    let app = test_app();
    let req = post_json(
        "/api/v1/intents",
        json!({"content": "not valid json for intent"}),
        Some("baize-root"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_v1_intent_query() {
    let app = test_app();
    let intent_content = json!({
        "intent_id": "int-q-001",
        "intent_owner": "baize-root",
        "intent_creator": "baize-root",
        "intent_goal": "query-test",
        "intent_constraints": {"budget": 50},
        "version": "1.0",
        "created_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-12-31T23:59:59Z",
    });
    let req = post_json(
        "/api/v1/intents",
        json!({"content": serde_json::to_string(&intent_content).unwrap()}),
        Some("baize-root"),
    );
    send(&app, req).await;

    let req = get_req("/api/v1/intents?status=active");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    let intents = body["intents"].as_array().unwrap();
    assert!(!intents.is_empty());
}

#[tokio::test]
async fn test_v1_receipt_create_and_read() {
    let app = test_app();

    // 先创建 intent（receipt 需要引用真实存在的 intent digest）
    let intent_content = json!({
        "intent_id": "int-rct-001",
        "intent_owner": "baize-root",
        "intent_creator": "baize-root",
        "intent_goal": "receipt-test",
        "intent_constraints": {"budget": 100},
        "version": "1.0",
        "created_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-12-31T23:59:59Z",
    });
    let req = post_json(
        "/api/v1/intents",
        json!({"content": serde_json::to_string(&intent_content).unwrap()}),
        Some("baize-root"),
    );
    let (_, body) = send(&app, req).await;
    let intent_hash = body["hash"].as_str().unwrap();

    // 注册 agent 并创建 agent-cert blob（receipt 引用的 authorization 需要 issuer 有 cert）
    let req = post_json(
        "/api/v1/agents",
        json!({"name": "rct-agent", "level": 3, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 创建 authorization
    let authz_content = json!({
        "authorization_id": "authz-rct-001",
        "issuer": "baize-root",
        "subject": "rct-agent",
        "grant_type": "execute",
        "constraints": {"amount_scope": {"max_amount": 200}},
        "delegatable": false,
        "source_intent_digest": intent_hash,
        "root_authorizer": "baize-root",
        "nbf": "2026-01-01T00:00:00Z",
        "exp": "2026-12-31T23:59:59Z",
        "iat": "2026-01-01T00:00:00Z",
        "jti": "jti-rct-001",
        "version": "1.0",
    });
    let req = post_json(
        "/api/v1/authorizations",
        json!({"content": serde_json::to_string(&authz_content).unwrap()}),
        Some("baize-root"),
    );
    let (_, body) = send(&app, req).await;
    let authz_hash = body["hash"].as_str().unwrap();

    // 创建 receipt
    let receipt_content = json!({
        "receipt_id": "rct-001",
        "executor_id": "baize-root",
        "task_id": "task-001",
        "action_type": "execute",
        "intent_digest": intent_hash,
        "authorization_digest": authz_hash,
        "result_status": "SUCCEEDED",
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:01:00Z",
    });
    let req = post_json(
        "/api/v1/receipts",
        json!({"content": serde_json::to_string(&receipt_content).unwrap()}),
        Some("baize-root"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);
    let hash = body["hash"].as_str().unwrap();

    let req = get_req(&format!("/api/v1/receipts/{}", hash));
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["content"].as_str().unwrap().contains("rct-001"));
}

#[tokio::test]
async fn test_v1_authorization_create_and_verify() {
    let app = test_app();

    let req = post_json(
        "/api/v1/agents",
        json!({"name": "auth-agent", "level": 3, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 创建意图
    let intent_content = json!({
        "intent_id": "int-auth-001",
        "intent_owner": "baize-root",
        "intent_creator": "baize-root",
        "intent_goal": "authorize-test",
        "intent_constraints": {"budget": 200},
        "version": "1.0",
        "created_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-12-31T23:59:59Z",
    });
    let req = post_json(
        "/api/v1/intents",
        json!({"content": serde_json::to_string(&intent_content).unwrap()}),
        Some("baize-root"),
    );
    let (_, body) = send(&app, req).await;
    let intent_hash = body["hash"].as_str().unwrap();

    // 创建授权
    let authz_content = json!({
        "authorization_id": "authz-001",
        "issuer": "baize-root",
        "subject": "auth-agent",
        "grant_type": "execute",
        "constraints": {"amount_scope": {"max_amount": 200}},
        "delegatable": false,
        "source_intent_digest": intent_hash,
        "root_authorizer": "baize-root",
        "nbf": "2026-01-01T00:00:00Z",
        "exp": "2026-12-31T23:59:59Z",
        "iat": "2026-01-01T00:00:00Z",
        "jti": "jti-001",
        "version": "1.0",
    });
    let req = post_json(
        "/api/v1/authorizations",
        json!({"content": serde_json::to_string(&authz_content).unwrap()}),
        Some("baize-root"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);
    let authz_hash = body["hash"].as_str().unwrap();

    // 读取授权
    let req = get_req(&format!("/api/v1/authorizations/{}", authz_hash));
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["content"].as_str().unwrap().contains("authz-001"));

    // 校验授权
    let req = post_json(
        &format!("/api/v1/authorizations/{}/verify", authz_hash),
        json!({"action_type": "execute"}),
        None,
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["valid"], true);
    // 验证 checks 为命名对象格式（协议 §13.4）
    assert!(body["checks"]["credential_authenticity"].is_boolean());
    assert!(body["checks"]["delegation_chain"].is_boolean());
}

#[tokio::test]
async fn test_v1_audit_verify_chain() {
    let app = test_app();

    let req = post_json(
        "/api/v1/blobs",
        json!({"content": "chain test data"}),
        Some("baize-root"),
    );
    send(&app, req).await;
    let req = post_json(
        "/api/v1/blobs",
        json!({"content": "chain test data 2"}),
        Some("baize-root"),
    );
    send(&app, req).await;

    let req = post_json("/api/v1/audit/verify-chain", json!({}), None);
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["valid"], true);
    assert!(body["chain_length"].as_u64().unwrap() >= 2);
}

#[tokio::test]
async fn test_v1_agent_status() {
    let app = test_app();

    let req = post_json(
        "/api/v1/agents",
        json!({"name": "status-agent", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    let req = get_req("/api/v1/agents/status-agent/status");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "active");

    let req = put_json(
        "/api/v1/agents/status-agent/status",
        json!({"status": "suspended", "reason": "testing"}),
        "baize-root",
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "suspended");

    let req = get_req("/api/v1/agents/status-agent/status");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "suspended");
}

#[tokio::test]
async fn test_v1_cnv_verify_invalid_receipt() {
    let app = test_app();
    let req = post_json(
        "/api/v1/cnv/verify",
        json!({"receipt_digest": "sha256:nonexistent"}),
        None,
    );
    let (status, body) = send(&app, req).await;
    // 不存在的 receipt 返回 400（ChainBroken）
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("chain broken"));
}

#[tokio::test]
async fn test_v1_v0_routes_work_under_v1() {
    let app = test_app();
    let req = post_json(
        "/api/v1/agents",
        json!({"name": "compat-agent", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);

    let req = get_req("/api/v1/agents");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().unwrap().iter().any(|a| a["id"] == "compat-agent"));
}

#[tokio::test]
async fn test_v1_session_close() {
    let app = test_app();

    let req = post_json(
        "/api/v1/agents",
        json!({"name": "peer-a", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;
    let req = post_json(
        "/api/v1/agents",
        json!({"name": "peer-b", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 创建 session-init
    let init_content = json!({
        "ephemeral_pub": gen_ephemeral_pub(),
        "cipher_suites": ["AES-256-GCM"],
        "credential_digest": "sha256:fake-cred-a",
    });
    let req = post_json(
        "/api/v1/blobs",
        json!({"content": serde_json::to_string(&init_content).unwrap(), "labels": {
            "type": "session-init",
            "x-session-id": "sess-close-test",
            "x-session-peer-a": "peer-a",
            "x-session-peer-b": "peer-b",
        }}),
        Some("peer-a"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);

    // 创建 session-accept（关闭前需要完成握手）
    let accept_content = json!({
        "ephemeral_pub": gen_ephemeral_pub(),
        "selected_cipher_suite": "AES-256-GCM",
    });
    let req = post_json(
        "/api/v1/blobs",
        json!({"content": serde_json::to_string(&accept_content).unwrap(), "labels": {
            "type": "session-accept",
            "x-session-id": "sess-close-test",
            "x-session-peer-a": "peer-a",
            "x-session-peer-b": "peer-b",
        }}),
        Some("peer-b"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);

    // 关闭 session
    let req = post_json(
        "/api/v1/sessions/sess-close-test/close",
        json!({"reason": "done"}),
        Some("peer-a"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["session_id"], "sess-close-test");
    assert_eq!(body["status"], "closed");
}

#[tokio::test]
async fn test_v1_session_create_and_read() {
    let app = test_app();

    let req = post_json(
        "/api/v1/agents",
        json!({"name": "sess-peer-a", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;
    let req = post_json(
        "/api/v1/agents",
        json!({"name": "sess-peer-b", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 创建会话
    let req = post_json(
        "/api/v1/sessions",
        json!({
            "session_id": "sess-api-test",
            "peer_a": "sess-peer-a",
            "peer_b": "sess-peer-b",
            "ephemeral_pub": gen_ephemeral_pub(),
            "cipher_suites": ["AES-256-GCM"],
            "credential_digest": "sha256:test-cred",
        }),
        Some("sess-peer-a"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["session_id"], "sess-api-test");
    assert_eq!(body["peer_a"], "sess-peer-a");
    assert_eq!(body["peer_b"], "sess-peer-b");
    assert_eq!(body["status"], "active");

    // 读取会话
    let req = get_req("/api/v1/sessions/sess-api-test");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["session_id"], "sess-api-test");

    // 读取不存在的会话
    let req = get_req("/api/v1/sessions/nonexistent");
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_v1_cnv_verify_response_format() {
    let app = test_app();

    // 创建完整的 intent → authz → receipt 链
    let intent_content = json!({
        "intent_id": "int-cnv-fmt",
        "intent_owner": "baize-root",
        "intent_creator": "baize-root",
        "intent_goal": "cnv-format-test",
        "intent_constraints": {"budget": 100},
        "version": "1.0",
        "created_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-12-31T23:59:59Z",
    });
    let req = post_json(
        "/api/v1/intents",
        json!({"content": serde_json::to_string(&intent_content).unwrap()}),
        Some("baize-root"),
    );
    let (_, body) = send(&app, req).await;
    let intent_hash = body["hash"].as_str().unwrap();

    let req = post_json(
        "/api/v1/agents",
        json!({"name": "cnv-executor", "level": 3, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    let authz_content = json!({
        "authorization_id": "authz-cnv-fmt",
        "issuer": "baize-root",
        "subject": "cnv-executor",
        "grant_type": "execute",
        "constraints": {"amount_scope": {"max_amount": 200}},
        "delegatable": false,
        "source_intent_digest": intent_hash,
        "root_authorizer": "baize-root",
        "nbf": "2026-01-01T00:00:00Z",
        "exp": "2026-12-31T23:59:59Z",
        "iat": "2026-01-01T00:00:00Z",
        "jti": "jti-cnv-fmt",
        "version": "1.0",
    });
    let req = post_json(
        "/api/v1/authorizations",
        json!({"content": serde_json::to_string(&authz_content).unwrap()}),
        Some("baize-root"),
    );
    let (_, body) = send(&app, req).await;
    let authz_hash = body["hash"].as_str().unwrap();

    let receipt_content = json!({
        "receipt_id": "rct-cnv-fmt",
        "executor_id": "baize-root",
        "task_id": "task-cnv-fmt",
        "action_type": "execute",
        "intent_digest": intent_hash,
        "authorization_digest": authz_hash,
        "result_status": "SUCCEEDED",
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:01:00Z",
    });
    let req = post_json(
        "/api/v1/receipts",
        json!({"content": serde_json::to_string(&receipt_content).unwrap()}),
        Some("baize-root"),
    );
    let (_, body) = send(&app, req).await;
    let receipt_hash = body["hash"].as_str().unwrap();

    // 执行 CNV 校验
    let req = post_json(
        "/api/v1/cnv/verify",
        json!({"receipt_digest": receipt_hash}),
        None,
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    // 验证响应格式（协议 §13.6）
    assert!(body["valid"].is_boolean());
    assert!(body["intent_chain"].is_array());
    assert!(body["authorization_chain"].is_array());
    assert!(body["errors"].is_array());
}

// ─── 签名认证测试 ───

#[tokio::test]
async fn test_v1_signature_verified_request_succeeds() {
    // 先获取 Baize 实例的密钥，再创建 app
    let baize = Baize::init_in_memory().unwrap();
    let signing_key = get_test_signing_key(&baize, "baize-root");
    let app = api::app(baize);

    let req = post_json_signed(
        "/api/v1/blobs",
        json!({"content": "signed blob data", "labels": {"type": "test-signed"}}),
        "baize-root",
        &signing_key,
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(body["hash"].is_string());
}

#[tokio::test]
async fn test_v1_signature_wrong_key_rejected() {
    let baize = Baize::init_in_memory().unwrap();
    let app = api::app(baize);

    // 用错误的密钥签名
    let wrong_key = baize_server::pipeline::auth::extract_signing_key("wrong-key-pem");
    let req = post_json_signed(
        "/api/v1/blobs",
        json!({"content": "tampered data"}),
        "baize-root",
        &wrong_key,
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "authentication failed");
}

#[tokio::test]
async fn test_v1_signature_expired_timestamp_rejected() {
    let baize = Baize::init_in_memory().unwrap();
    let signing_key = get_test_signing_key(&baize, "baize-root");
    let app = api::app(baize);

    // 用 10 分钟前的时间戳（超过 5 分钟窗口）
    let past = (chrono::Utc::now() - chrono::Duration::minutes(10)).to_rfc3339();
    let body_str = serde_json::to_string(&json!({"content": "expired"})).unwrap();
    let sig = baize_server::pipeline::auth::compute_signature(
        CryptoProvider::default().request_signer.as_ref(),
        &signing_key, &past, "POST", "/api/v1/blobs", &body_str,
    );
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/blobs")
        .header("content-type", "application/json")
        .header("x-agent-id", "baize-root")
        .header("x-timestamp", &past)
        .header("x-signature", &sig)
        .body(Body::from(body_str))
        .unwrap();

    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "authentication failed");
}

#[tokio::test]
async fn test_v1_no_signature_fallback_succeeds() {
    let app = test_app();
    // 无签名头的普通请求仍能通过（过渡期 fallback）
    let req = post_json(
        "/api/v1/blobs",
        json!({"content": "unsigned data"}),
        Some("baize-root"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(body["hash"].is_string());
}

// ─── 补充测试：Agent Proof 生成 ───

#[tokio::test]
async fn test_v1_agent_proof_generation() {
    let app = test_app();

    // 注册 agent
    let req = post_json(
        "/api/v1/agents",
        json!({"name": "proof-agent", "level": 3, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 生成运行态证明
    let req = post_json(
        "/api/v1/agents/proof-agent/proof",
        json!({"instance_state_attributes": {"instance_id": "proof-agent", "status": "running"}}),
        Some("baize-root"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(body["hash"].is_string());
    assert!(body["proof_id"].as_str().unwrap().starts_with("proof-proof-agent-"));
    assert!(body["expires_at"].is_string());
}

#[tokio::test]
async fn test_v1_agent_proof_default_attrs() {
    let app = test_app();

    let req = post_json(
        "/api/v1/agents",
        json!({"name": "proof-default", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 不提供 instance_state_attributes，使用默认值
    let req = post_json(
        "/api/v1/agents/proof-default/proof",
        json!({}),
        Some("baize-root"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(body["hash"].is_string());
}

// ─── 补充测试：CNV 正向全链路校验 ───

#[tokio::test]
async fn test_v1_cnv_verify_full_chain_valid() {
    let app = test_app();

    // 创建意图
    let intent_content = json!({
        "intent_id": "int-cnv-full",
        "intent_owner": "baize-root",
        "intent_creator": "baize-root",
        "intent_goal": "cnv-full-valid-test",
        "intent_constraints": {"budget": 500},
        "version": "1.0",
        "created_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-12-31T23:59:59Z",
    });
    let req = post_json(
        "/api/v1/intents",
        json!({"content": serde_json::to_string(&intent_content).unwrap()}),
        Some("baize-root"),
    );
    let (_, body) = send(&app, req).await;
    let intent_hash = body["hash"].as_str().unwrap();

    // 注册 executor
    let req = post_json(
        "/api/v1/agents",
        json!({"name": "cnv-exec-full", "level": 3, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 创建授权
    let authz_content = json!({
        "authorization_id": "authz-cnv-full",
        "issuer": "baize-root",
        "subject": "cnv-exec-full",
        "grant_type": "execute",
        "constraints": {"amount_scope": {"max_amount": 500}},
        "delegatable": false,
        "source_intent_digest": intent_hash,
        "root_authorizer": "baize-root",
        "nbf": "2026-01-01T00:00:00Z",
        "exp": "2026-12-31T23:59:59Z",
        "iat": "2026-01-01T00:00:00Z",
        "jti": "jti-cnv-full",
        "version": "1.0",
    });
    let req = post_json(
        "/api/v1/authorizations",
        json!({"content": serde_json::to_string(&authz_content).unwrap()}),
        Some("baize-root"),
    );
    let (_, body) = send(&app, req).await;
    let authz_hash = body["hash"].as_str().unwrap();

    // 创建回执
    let receipt_content = json!({
        "receipt_id": "rct-cnv-full",
        "executor_id": "baize-root",
        "task_id": "task-cnv-full",
        "action_type": "execute",
        "intent_digest": intent_hash,
        "authorization_digest": authz_hash,
        "result_status": "SUCCEEDED",
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:01:00Z",
    });
    let req = post_json(
        "/api/v1/receipts",
        json!({"content": serde_json::to_string(&receipt_content).unwrap()}),
        Some("baize-root"),
    );
    let (_, body) = send(&app, req).await;
    let receipt_hash = body["hash"].as_str().unwrap();

    // CNV 校验应通过
    let req = post_json(
        "/api/v1/cnv/verify",
        json!({"receipt_digest": receipt_hash}),
        None,
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["valid"], true, "CNV should be valid: {:?}", body["errors"]);
    assert!(body["errors"].as_array().unwrap().is_empty());
}

// ─── 补充测试：凭证状态非法转换 ───

#[tokio::test]
async fn test_v1_credential_invalid_transition_revoked_to_active() {
    let app = test_app();

    let req = post_json(
        "/api/v1/agents",
        json!({"name": "transition-agent", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 撤销
    let req = put_json(
        "/api/v1/agents/transition-agent/status",
        json!({"status": "revoked", "reason": "compromised"}),
        "baize-root",
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);

    // 尝试恢复已撤销的凭证（应该失败）
    let req = put_json(
        "/api/v1/agents/transition-agent/status",
        json!({"status": "active", "reason": "attempt reactivate"}),
        "baize-root",
    );
    let (status, body) = send(&app, req).await;
    // revoked agent 已从内存移除，返回 404 (not found) 或 400 (validation)
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::BAD_REQUEST,
        "revoked→active should fail, got {} {:?}",
        status, body,
    );
}

#[tokio::test]
async fn test_v1_credential_suspend_and_reactivate() {
    let app = test_app();

    let req = post_json(
        "/api/v1/agents",
        json!({"name": "suspend-agent", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 暂停
    let req = put_json(
        "/api/v1/agents/suspend-agent/status",
        json!({"status": "suspended", "reason": "maintenance"}),
        "baize-root",
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "suspended");

    // 恢复
    let req = put_json(
        "/api/v1/agents/suspend-agent/status",
        json!({"status": "active", "reason": "restored"}),
        "baize-root",
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "active");
}

// ─── 补充测试：Receipt Query Filters ───

#[tokio::test]
async fn test_v1_receipt_query_with_filters() {
    let app = test_app();

    // 创建意图
    let intent_content = json!({
        "intent_id": "int-rq",
        "intent_owner": "baize-root",
        "intent_creator": "baize-root",
        "intent_goal": "receipt-query-test",
        "intent_constraints": {"budget": 100},
        "version": "1.0",
        "created_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-12-31T23:59:59Z",
    });
    let req = post_json(
        "/api/v1/intents",
        json!({"content": serde_json::to_string(&intent_content).unwrap()}),
        Some("baize-root"),
    );
    let (_, body) = send(&app, req).await;
    let intent_hash = body["hash"].as_str().unwrap();

    let authz_content = json!({
        "authorization_id": "authz-rq",
        "issuer": "baize-root",
        "subject": "baize-root",
        "grant_type": "execute",
        "constraints": {"amount_scope": {"max_amount": 200}},
        "delegatable": false,
        "source_intent_digest": intent_hash,
        "root_authorizer": "baize-root",
        "nbf": "2026-01-01T00:00:00Z",
        "exp": "2026-12-31T23:59:59Z",
        "iat": "2026-01-01T00:00:00Z",
        "jti": "jti-rq",
        "version": "1.0",
    });
    let req = post_json(
        "/api/v1/authorizations",
        json!({"content": serde_json::to_string(&authz_content).unwrap()}),
        Some("baize-root"),
    );
    let (_, body) = send(&app, req).await;
    let authz_hash = body["hash"].as_str().unwrap();

    // 创建 2 个回执
    for i in 1..=2 {
        let receipt_content = json!({
            "receipt_id": format!("rct-q{}", i),
            "executor_id": "baize-root",
            "task_id": format!("task-q{}", i),
            "action_type": "execute",
            "intent_digest": intent_hash,
            "authorization_digest": authz_hash,
            "result_status": "SUCCEEDED",
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": "2026-01-01T00:01:00Z",
        });
        let req = post_json(
            "/api/v1/receipts",
            json!({"content": serde_json::to_string(&receipt_content).unwrap()}),
            Some("baize-root"),
        );
        let (status, _) = send(&app, req).await;
        assert_eq!(status, StatusCode::CREATED);
    }

    // 按状态查询
    let req = get_req("/api/v1/receipts?status=SUCCEEDED");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    let receipts = body["receipts"].as_array().unwrap();
    assert!(receipts.len() >= 2, "should find at least 2 receipts");

    // 按 executor 查询
    let req = get_req("/api/v1/receipts?executor=baize-root");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["receipts"].as_array().unwrap().len() >= 2);
}

// ─── 补充测试：Session Close 存在性验证 ───

#[tokio::test]
async fn test_v1_session_close_not_found() {
    let app = test_app();

    // 尝试关闭不存在的 session
    let req = post_json(
        "/api/v1/sessions/nonexistent-session/close",
        json!({"reason": "test"}),
        Some("baize-root"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["error"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn test_v1_session_close_already_closed() {
    let app = test_app();

    // 注册 peers
    let req = post_json(
        "/api/v1/agents",
        json!({"name": "close-peer-a", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;
    let req = post_json(
        "/api/v1/agents",
        json!({"name": "close-peer-b", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 创建 session-init（通过 blob write，与 test_v1_session_close 一致）
    let init_content = json!({
        "ephemeral_pub": gen_ephemeral_pub(),
        "cipher_suites": ["AES-256-GCM"],
        "credential_digest": "sha256:test-cred-dbl",
    });
    let req = post_json(
        "/api/v1/blobs",
        json!({"content": serde_json::to_string(&init_content).unwrap(), "labels": {
            "type": "session-init",
            "x-session-id": "sess-dbl-close",
            "x-session-peer-a": "close-peer-a",
            "x-session-peer-b": "close-peer-b",
        }}),
        Some("close-peer-a"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);

    // 第一次关闭：成功
    let req = post_json(
        "/api/v1/sessions/sess-dbl-close/close",
        json!({"reason": "first close"}),
        Some("close-peer-a"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED, "first close failed: {:?}", body);

    // 第二次关闭：冲突
    let req = post_json(
        "/api/v1/sessions/sess-dbl-close/close",
        json!({"reason": "second close"}),
        Some("close-peer-a"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body["error"].as_str().unwrap().contains("already closed"));
}

// ─── Session Accept 端点测试 ───

#[tokio::test]
async fn test_v1_session_accept() {
    let app = test_app();

    // 注册两个 agent
    let req = post_json(
        "/api/v1/agents",
        json!({"name": "accept-a", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;
    let req = post_json(
        "/api/v1/agents",
        json!({"name": "accept-b", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 创建 session-init
    let req = post_json(
        "/api/v1/sessions",
        json!({
            "session_id": "sess-accept-test",
            "peer_a": "accept-a",
            "peer_b": "accept-b",
            "ephemeral_pub": gen_ephemeral_pub(),
            "cipher_suites": ["AES-256-GCM"],
        }),
        Some("accept-a"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED, "session create failed: {:?}", body);

    // 接受会话
    let req = post_json(
        "/api/v1/sessions/sess-accept-test/accept",
        json!({
            "credential_digest_responder": "sha256:responder-cred",
            "ephemeral_pub": gen_ephemeral_pub(),
            "selected_cipher_suite": "AES-256-GCM",
            "handshake_transcript_digest": "sha256:handshake",
        }),
        Some("accept-b"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED, "session accept failed: {:?}", body);
    assert_eq!(body["session_id"], "sess-accept-test");
    assert_eq!(body["status"], "active");
}

#[tokio::test]
async fn test_v1_session_accept_not_found() {
    let app = test_app();

    let req = post_json(
        "/api/v1/agents",
        json!({"name": "accept-nf-a", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 尝试接受不存在的 session
    let req = post_json(
        "/api/v1/sessions/nonexistent-session/accept",
        json!({
            "credential_digest_responder": "sha256:cred",
            "ephemeral_pub": gen_ephemeral_pub(),
            "selected_cipher_suite": "AES-256-GCM",
            "handshake_transcript_digest": "sha256:handshake",
        }),
        Some("accept-nf-a"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_v1_session_accept_duplicate() {
    let app = test_app();

    let req = post_json(
        "/api/v1/agents",
        json!({"name": "accept-dup-a", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;
    let req = post_json(
        "/api/v1/agents",
        json!({"name": "accept-dup-b", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 创建 session-init
    let req = post_json(
        "/api/v1/sessions",
        json!({
            "session_id": "sess-dup-accept",
            "peer_a": "accept-dup-a",
            "peer_b": "accept-dup-b",
            "ephemeral_pub": gen_ephemeral_pub(),
            "cipher_suites": ["AES-256-GCM"],
        }),
        Some("accept-dup-a"),
    );
    send(&app, req).await;

    // 第一次 accept
    let req = post_json(
        "/api/v1/sessions/sess-dup-accept/accept",
        json!({"credential_digest_responder": "sha256:cred", "ephemeral_pub": gen_ephemeral_pub(), "selected_cipher_suite": "AES-256-GCM", "handshake_transcript_digest": "sha256:handshake"}),
        Some("accept-dup-b"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);

    // 第二次 accept：冲突
    let req = post_json(
        "/api/v1/sessions/sess-dup-accept/accept",
        json!({"credential_digest_responder": "sha256:cred2", "ephemeral_pub": gen_ephemeral_pub(), "selected_cipher_suite": "AES-256-GCM", "handshake_transcript_digest": "sha256:handshake2"}),
        Some("accept-dup-b"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CONFLICT, "expected CONFLICT, got {:?}: {:?}", status, body);
    assert_eq!(body["error"], "conflict");
}

// ─── Phase 4: Level 3+ Proof Enforcement 集成测试 ───

/// 辅助：注册 Level 3 agent 并生成合法 proof
async fn setup_l3_agent_with_proof(app: &axum::Router, agent_name: &str) {
    // 注册 Level 3 agent
    let req = post_json(
        "/api/v1/agents",
        json!({"name": agent_name, "level": 3, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(app, req).await;

    // 生成 runtime proof（由 root 代为签发）
    let req = post_json(
        &format!("/api/v1/agents/{}/proof", agent_name),
        json!({"instance_state_attributes": {"instance_id": agent_name, "instance_status": "running"}}),
        Some("baize-root"),
    );
    let (status, body) = send(app, req).await;
    assert_eq!(status, StatusCode::CREATED, "proof generation failed: {:?}", body);
}

#[tokio::test]
async fn test_l3_authz_without_proof_rejected() {
    let app = test_app();

    // 注册 Level 3 agent（无 proof）
    let req = post_json(
        "/api/v1/agents",
        json!({"name": "l3-no-proof", "level": 3, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 写 intent（Level 3 agent 不需要 proof 的 blob type，先创建依赖）
    let req = post_json(
        "/api/v1/blobs",
        json!({"content": serde_json::json!({
            "intent_id": "int-l3-no-proof",
            "intent_constraints": {"budget": 100},
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2099-12-31T23:59:59Z",
        }).to_string(), "labels": {
            "type": "intent",
            "x-intent-id": "int-l3-no-proof",
            "x-intent-status": "active",
            "x-intent-expires": "2099-12-31T23:59:59Z",
        }}),
        Some("l3-no-proof"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED, "intent write failed: {:?}", body);

    // 尝试写 authorization（需 proof 的 blob type）→ 应被拒
    let req = post_json(
        "/api/v1/blobs",
        json!({"content": serde_json::json!({
            "authorization_id": "authz-no-proof",
            "issuer": "baize-root",
            "subject": "l3-no-proof",
            "grant_type": "execute",
            "constraints": {"target_scope": ["zone-A"]},
            "delegatable": false,
            "source_intent_digest": body["hash"],
            "root_authorizer": "baize-root",
            "nbf": "2026-01-01T00:00:00Z",
            "exp": "2099-12-31T23:59:59Z",
            "iat": "2026-01-01T00:00:00Z",
            "jti": "jti-no-proof",
            "version": "1.0",
        }).to_string(), "labels": {
            "type": "authorization",
            "x-authz-status": "valid",
        }}),
        Some("l3-no-proof"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "Level 3 authz without proof should be FORBIDDEN, got {:?}: {:?}", status, body);
    assert!(body["error"].as_str().unwrap().contains("proof"));
}

#[tokio::test]
async fn test_l3_authz_with_proof_accepted() {
    let app = test_app();

    setup_l3_agent_with_proof(&app, "l3-with-proof").await;

    // 写 intent
    let req = post_json(
        "/api/v1/blobs",
        json!({"content": serde_json::json!({
            "intent_id": "int-l3-proof",
            "intent_constraints": {"budget": 100},
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2099-12-31T23:59:59Z",
        }).to_string(), "labels": {
            "type": "intent",
            "x-intent-id": "int-l3-proof",
            "x-intent-status": "active",
            "x-intent-expires": "2099-12-31T23:59:59Z",
        }}),
        Some("l3-with-proof"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED, "intent write failed: {:?}", body);
    let intent_hash = body["hash"].as_str().unwrap();

    // 写 authorization（Level 3 + 有 proof）→ 应成功
    let req = post_json(
        "/api/v1/blobs",
        json!({"content": serde_json::json!({
            "authorization_id": "authz-with-proof",
            "issuer": "baize-root",
            "subject": "l3-with-proof",
            "grant_type": "execute",
            "constraints": {"target_scope": ["zone-A"]},
            "delegatable": false,
            "source_intent_digest": intent_hash,
            "root_authorizer": "baize-root",
            "nbf": "2026-01-01T00:00:00Z",
            "exp": "2099-12-31T23:59:59Z",
            "iat": "2026-01-01T00:00:00Z",
            "jti": "jti-with-proof",
            "version": "1.0",
        }).to_string(), "labels": {
            "type": "authorization",
            "x-authz-status": "valid",
            "x-source-intent": intent_hash,
        }}),
        Some("l3-with-proof"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED, "Level 3 authz with valid proof should succeed, got {:?}: {:?}", status, body);
}

#[tokio::test]
async fn test_l3_file_write_without_proof_rejected() {
    let app = test_app();

    // 注册 Level 3 agent（无 proof）
    let req = post_json(
        "/api/v1/agents",
        json!({"name": "l3-file-no-proof", "level": 3, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 尝试写文件 → 应被拒
    let req = post_json(
        "/api/v0/files/A/test.txt",
        json!({"content": "secret data"}),
        Some("l3-file-no-proof"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "Level 3 file write without proof should be FORBIDDEN, got {:?}: {:?}", status, body);
}

#[tokio::test]
async fn test_l3_file_write_with_proof_accepted() {
    let app = test_app();

    setup_l3_agent_with_proof(&app, "l3-file-proof").await;

    // 写文件（有 proof）→ 应成功
    let req = post_json(
        "/api/v0/files/A/test.txt",
        json!({"content": "secret data"}),
        Some("l3-file-proof"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED, "Level 3 file write with proof should succeed, got {:?}: {:?}", status, body);
    assert_eq!(body["path"], "A/test.txt");
}

#[tokio::test]
async fn test_l2_authz_without_proof_accepted() {
    let app = test_app();

    // 注册 Level 2 agent
    let req = post_json(
        "/api/v1/agents",
        json!({"name": "l2-no-proof", "level": 2, "zones": ["A"]}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // 写 intent
    let req = post_json(
        "/api/v1/blobs",
        json!({"content": serde_json::json!({
            "intent_id": "int-l2",
            "intent_constraints": {"budget": 100},
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2099-12-31T23:59:59Z",
        }).to_string(), "labels": {
            "type": "intent",
            "x-intent-id": "int-l2",
            "x-intent-status": "active",
            "x-intent-expires": "2099-12-31T23:59:59Z",
        }}),
        Some("l2-no-proof"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED, "intent write failed: {:?}", body);
    let intent_hash = body["hash"].as_str().unwrap();

    // Level 2 写 authorization 无需 proof → 应成功
    let req = post_json(
        "/api/v1/blobs",
        json!({"content": serde_json::json!({
            "authorization_id": "authz-l2",
            "issuer": "baize-root",
            "subject": "l2-no-proof",
            "grant_type": "execute",
            "constraints": {"target_scope": ["zone-A"]},
            "delegatable": false,
            "source_intent_digest": intent_hash,
            "root_authorizer": "baize-root",
            "nbf": "2026-01-01T00:00:00Z",
            "exp": "2099-12-31T23:59:59Z",
            "iat": "2026-01-01T00:00:00Z",
            "jti": "jti-l2",
            "version": "1.0",
        }).to_string(), "labels": {
            "type": "authorization",
            "x-authz-status": "valid",
            "x-source-intent": intent_hash,
        }}),
        Some("l2-no-proof"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED, "Level 2 authz without proof should succeed");
}

// ─── Phase 5: v2 签名强制集成测试 ───

/// 辅助：从 agent-key blob 获取签名密钥（SHA-256 of PEM）
fn get_signing_key_for_agent(baize: &Baize, agent_id: &str) -> Vec<u8> {
    use baize_core::labels::*;
    let mut filter = std::collections::HashMap::new();
    filter.insert("type".to_string(), "agent-key".to_string());
    filter.insert(LABEL_KEY_OWNER.to_string(), agent_id.to_string());
    filter.insert(LABEL_KEY_PURPOSE.to_string(), "IDN_SIGN".to_string());
    let keys = baize.storage.blob_query(&filter).unwrap();

    let key_content = if let Some(key_blob) = keys.iter().find(|b| !b.labels.contains_key(LABEL_KEY_REVOKED)) {
        key_blob.content.clone()
    } else {
        keys[0].content.clone()
    };

    // 解密（如有 master secret）
    let pem = if let Some(secret) = baize_core::crypto::master_secret_from_env() {
        baize_core::crypto::decrypt_key(&key_content, &secret).unwrap()
    } else {
        key_content
    };

    // 使用 auth 模块的 extract_signing_key 统一提取逻辑
    baize_server::pipeline::auth::extract_signing_key(&pem)
}

/// 辅助：计算 Ed25519 签名
fn compute_ed25519_signature(key: &[u8], timestamp: &str, method: &str, path: &str, body: &str) -> String {
    use ed25519_dalek::{SigningKey, Signer};
    let input = format!("{}\n{}\n{}\n{}", timestamp, method, path, body);
    let signing_key = SigningKey::from_bytes(key.try_into().expect("key must be 32 bytes"));
    let signature = signing_key.sign(input.as_bytes());
    format!("ed25519:{}", hex::encode(signature.to_bytes()))
}

/// 辅助：构造带签名的 v2 POST 请求
fn v2_signed_post(
    uri: &str,
    body: &Value,
    agent_id: &str,
    signing_key: &[u8],
) -> Request<Body> {
    let body_str = serde_json::to_string(body).unwrap();
    let timestamp = chrono::Utc::now().to_rfc3339();
    let signature = compute_ed25519_signature(signing_key, &timestamp, "POST", uri, &body_str);
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", agent_id)
        .header("x-timestamp", timestamp)
        .header("x-signature", signature)
        .body(Body::from(body_str))
        .unwrap()
}

/// 辅助：构造带签名的 v2 GET 请求
fn v2_signed_get(
    uri: &str,
    agent_id: &str,
    signing_key: &[u8],
) -> Request<Body> {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let signature = compute_ed25519_signature(signing_key, &timestamp, "GET", uri, "");
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-agent-id", agent_id)
        .header("x-timestamp", timestamp)
        .header("x-signature", signature)
        .body(Body::empty())
        .unwrap()
}

/// 辅助：构造无签名的 v2 POST 请求
fn v2_unsigned_post(uri: &str, body: &Value, agent_id: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", agent_id)
        .body(Body::from(serde_json::to_string(body).unwrap()))
        .unwrap()
}

#[tokio::test]
async fn test_v2_unsigned_request_rejected() {
    let app = test_app();

    // 无签名头的 v2 请求 → 401
    let req = v2_unsigned_post(
        "/api/v2/blobs",
        &json!({"content": "test", "labels": {}}),
        "baize-root",
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "unsigned v2 request should be rejected: {:?}", body);
    assert!(body["error"].as_str().unwrap().contains("missing"));
}

#[tokio::test]
async fn test_v2_invalid_signature_rejected() {
    let app = test_app();

    let timestamp = chrono::Utc::now().to_rfc3339();
    let body_str = serde_json::to_string(&json!({"content": "test", "labels": {}})).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v2/blobs")
        .header("content-type", "application/json")
        .header("x-agent-id", "baize-root")
        .header("x-timestamp", &timestamp)
        .header("x-signature", "ed25519:deadbeef")
        .body(Body::from(body_str))
        .unwrap();

    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "invalid signature should be rejected");
}

#[tokio::test]
async fn test_v2_valid_signature_accepted() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("baize-root", "sig-tester", Level(2), vec!["A"], None).unwrap();
    let signing_key = get_signing_key_for_agent(&baize, "sig-tester");
    let app = api::app(baize);

    // 带有效签名的 v2 blob write → 成功
    let req = v2_signed_post(
        "/api/v2/blobs",
        &json!({"content": "signed data", "labels": {}}),
        "sig-tester",
        &signing_key,
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED, "valid signed v2 request should succeed: {:?}", body);
    assert!(!body["hash"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn test_v2_expired_timestamp_rejected() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("baize-root", "ts-tester", Level(2), vec!["A"], None).unwrap();
    let signing_key = get_signing_key_for_agent(&baize, "ts-tester");
    let app = api::app(baize);

    // 10 分钟前的时间戳 → 超出 5 分钟窗口
    let past = (chrono::Utc::now() - chrono::Duration::minutes(10)).to_rfc3339();
    let body_str = serde_json::to_string(&json!({"content": "expired ts", "labels": {}})).unwrap();
    let signature = compute_ed25519_signature(&signing_key, &past, "POST", "/api/v2/blobs", &body_str);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v2/blobs")
        .header("content-type", "application/json")
        .header("x-agent-id", "ts-tester")
        .header("x-timestamp", &past)
        .header("x-signature", &signature)
        .body(Body::from(body_str))
        .unwrap();

    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "expired timestamp should be rejected");
}

#[tokio::test]
async fn test_v2_proof_verify_endpoint() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("baize-root", "verify-target", Level(3), vec!["A"], None).unwrap();

    // 先生成 proof
    let cert_filter = {
        use baize_core::labels::*;
        let mut f = std::collections::HashMap::new();
        f.insert("type".to_string(), "agent-cert".to_string());
        f.insert("agent-id".to_string(), "verify-target".to_string());
        f
    };
    let certs = baize.storage.blob_query(&cert_filter).unwrap();
    let cert_hash = certs[0].hash.clone();
    let cert_labels = certs[0].labels.clone();

    let instance_state = serde_json::json!({"instance_id": "verify-target", "instance_status": "running"});
    let binding_digest = baize_asl::AslAdapter::compute_binding_context_digest(&cert_labels, &instance_state);
    let now = chrono::Utc::now();
    let proof = baize_asl::payload::RuntimeProofContent {
        proof_id: format!("proof-{}", now.timestamp_millis()),
        credential_digest: cert_hash,
        instance_state_attributes: instance_state,
        binding_context_digest: binding_digest,
        proof_anchor_mode: baize_asl::payload::ProofAnchorMode::CredentialAnchored,
        issued_at: now.to_rfc3339(),
        expires_at: (now + chrono::Duration::minutes(5)).to_rfc3339(),
    };
    let proof_labels = std::collections::HashMap::from([
        ("type".to_string(), "runtime-proof".to_string()),
        (LABEL_PROOF_AGENT.to_string(), "verify-target".to_string()),
        (LABEL_PROOF_CREDENTIAL.to_string(), proof.credential_digest.clone()),
    ]);
    baize.storage.blob_write(&serde_json::to_string(&proof).unwrap(), &proof_labels).unwrap();

    let signing_key = get_signing_key_for_agent(&baize, "baize-root");
    let app = api::app(baize);

    // v2 proof verify 端点 — 需要签名
    let req = v2_signed_get(
        "/api/v2/agents/verify-target/proof/verify",
        "baize-root",
        &signing_key,
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK, "proof verify should succeed: {:?}", body);
    assert_eq!(body["valid"], true);
    assert!(body["proof_id"].as_str().unwrap().starts_with("proof-"));
}

// ─── v2 nonce 重放防护测试 ───

#[tokio::test]
async fn test_v2_nonce_replay_rejected() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("baize-root", "nonce-tester", Level(2), vec!["A"], None).unwrap();
    let signing_key = get_signing_key_for_agent(&baize, "nonce-tester");
    let app = api::app(baize);

    let body = json!({"content": "nonce test", "labels": {}});
    let body_str = serde_json::to_string(&body).unwrap();
    let timestamp = chrono::Utc::now().to_rfc3339();
    let signature = compute_ed25519_signature(&signing_key, &timestamp, "POST", "/api/v2/blobs", &body_str);
    let nonce = "unique-nonce-12345";

    // 第一次请求（带 nonce）→ 成功
    let req1 = Request::builder()
        .method("POST")
        .uri("/api/v2/blobs")
        .header("content-type", "application/json")
        .header("x-agent-id", "nonce-tester")
        .header("x-timestamp", &timestamp)
        .header("x-signature", &signature)
        .header("x-nonce", nonce)
        .body(Body::from(body_str.clone()))
        .unwrap();
    let (status, _) = send(&app, req1).await;
    assert_eq!(status, StatusCode::CREATED, "first request with nonce should succeed");

    // 第二次请求（相同 nonce，新签名）→ 409 Conflict
    let timestamp2 = chrono::Utc::now().to_rfc3339();
    let signature2 = compute_ed25519_signature(&signing_key, &timestamp2, "POST", "/api/v2/blobs", &body_str);
    let req2 = Request::builder()
        .method("POST")
        .uri("/api/v2/blobs")
        .header("content-type", "application/json")
        .header("x-agent-id", "nonce-tester")
        .header("x-timestamp", &timestamp2)
        .header("x-signature", &signature2)
        .header("x-nonce", nonce)
        .body(Body::from(body_str))
        .unwrap();
    let (status, body) = send(&app, req2).await;
    assert_eq!(status, StatusCode::CONFLICT, "replayed nonce should be rejected: {:?}", body);
}

#[tokio::test]
async fn test_v2_no_nonce_accepted() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("baize-root", "no-nonce-tester", Level(2), vec!["A"], None).unwrap();
    let signing_key = get_signing_key_for_agent(&baize, "no-nonce-tester");
    let app = api::app(baize);

    // 不带 nonce 的 v2 请求（只有签名）→ 仍然成功
    let req = v2_signed_post(
        "/api/v2/blobs",
        &json!({"content": "no nonce", "labels": {}}),
        "no-nonce-tester",
        &signing_key,
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED, "v2 request without nonce should succeed");
}

// ─── v2 session message 测试 ───

fn session_init_labels(session_id: &str, peer_a: &str, peer_b: &str) -> std::collections::HashMap<String, String> {
    std::collections::HashMap::from([
        ("type".to_string(), "session-init".to_string()),
        (LABEL_SESSION_ID.to_string(), session_id.to_string()),
        (LABEL_SESSION_PEER_A.to_string(), peer_a.to_string()),
        (LABEL_SESSION_PEER_B.to_string(), peer_b.to_string()),
        (LABEL_SESSION_STATUS.to_string(), "active".to_string()),
    ])
}

fn session_accept_labels(session_id: &str, peer_a: &str, peer_b: &str) -> std::collections::HashMap<String, String> {
    std::collections::HashMap::from([
        ("type".to_string(), "session-accept".to_string()),
        (LABEL_SESSION_ID.to_string(), session_id.to_string()),
        (LABEL_SESSION_PEER_A.to_string(), peer_a.to_string()),
        (LABEL_SESSION_PEER_B.to_string(), peer_b.to_string()),
        (LABEL_SESSION_STATUS.to_string(), "active".to_string()),
    ])
}

/// 创建有效的 session-init content（含 X25519 ephemeral_pub）
fn session_init_content(session_id: &str) -> String {
    let (_, pub_pem) = baize_core::crypto::generate_x25519_keypair().unwrap();
    serde_json::to_string(&json!({
        "session_id": session_id,
        "ephemeral_pub": pub_pem,
        "cipher_suites": ["AES-256-GCM"]
    })).unwrap()
}

/// 创建有效的 session-accept content（含 X25519 ephemeral_pub）
fn session_accept_content(session_id: &str) -> String {
    let (_, pub_pem) = baize_core::crypto::generate_x25519_keypair().unwrap();
    serde_json::to_string(&json!({
        "session_id": session_id,
        "ephemeral_pub": pub_pem,
        "selected_cipher_suite": "AES-256-GCM",
        "handshake_transcript_digest": "sha256:test"
    })).unwrap()
}

#[tokio::test]
async fn test_v2_session_message_ok() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("baize-root", "alice", Level(2), vec!["A"], None).unwrap();
    baize.agent_register("baize-root", "bob", Level(2), vec!["A"], None).unwrap();

    // 建立 session：init + accept
    baize.pipe_blob_write("alice", &session_init_content("sess-1"), &session_init_labels("sess-1", "alice", "bob")).unwrap();
    baize.pipe_blob_write("bob", &session_accept_content("sess-1"), &session_accept_labels("sess-1", "alice", "bob")).unwrap();

    let signing_key = get_signing_key_for_agent(&baize, "alice");
    let app = api::app(baize);

    // v2 session message (seq=1) → 成功
    let req = v2_signed_post(
        "/api/v2/sessions/sess-1/message",
        &json!({"ciphertext": "encrypted-payload", "seq": 1}),
        "alice",
        &signing_key,
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED, "v2 session message should succeed: {:?}", body);
    assert_eq!(body["seq"], 1);
}

#[tokio::test]
async fn test_v2_session_message_seq_skip_fails() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("baize-root", "alice", Level(2), vec!["A"], None).unwrap();
    baize.agent_register("baize-root", "bob", Level(2), vec!["A"], None).unwrap();

    baize.pipe_blob_write("alice", &session_init_content("sess-2"), &session_init_labels("sess-2", "alice", "bob")).unwrap();
    baize.pipe_blob_write("bob", &session_accept_content("sess-2"), &session_accept_labels("sess-2", "alice", "bob")).unwrap();

    let signing_key = get_signing_key_for_agent(&baize, "alice");
    let app = api::app(baize);

    // seq=5 跳过了 seq=1 → 应该被拒
    let req = v2_signed_post(
        "/api/v2/sessions/sess-2/message",
        &json!({"ciphertext": "data", "seq": 5}),
        "alice",
        &signing_key,
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "seq skip should be rejected");
}

#[tokio::test]
async fn test_v2_session_message_closed_session_fails() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("baize-root", "alice", Level(2), vec!["A"], None).unwrap();
    baize.agent_register("baize-root", "bob", Level(2), vec!["A"], None).unwrap();

    baize.pipe_blob_write("alice", &session_init_content("sess-3"), &session_init_labels("sess-3", "alice", "bob")).unwrap();
    baize.pipe_blob_write("bob", &session_accept_content("sess-3"), &session_accept_labels("sess-3", "alice", "bob")).unwrap();

    // 关闭 session
    let close_labels = std::collections::HashMap::from([
        ("type".to_string(), "session-close".to_string()),
        (LABEL_SESSION_ID.to_string(), "sess-3".to_string()),
        (LABEL_SESSION_STATUS.to_string(), "closed".to_string()),
    ]);
    baize.pipe_blob_write("alice", r#"{"action":"close"}"#, &close_labels).unwrap();

    let signing_key = get_signing_key_for_agent(&baize, "alice");
    let app = api::app(baize);

    // 向已关闭的 session 发消息 → 应被拒
    let req = v2_signed_post(
        "/api/v2/sessions/sess-3/message",
        &json!({"ciphertext": "data", "seq": 1}),
        "alice",
        &signing_key,
    );
    let (status, _) = send(&app, req).await;
    assert!(status != StatusCode::CREATED, "message to closed session should be rejected");
}
