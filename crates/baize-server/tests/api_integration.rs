use axum::body::Body;
use baize_server::api;
use baize_server::Baize;
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

// ─── 3. Commit 操作 ───

#[tokio::test]
async fn test_commit_create_with_blobs() {
    let app = test_app();
    // 写入 blob
    let req = post_json(
        "/api/v0/blobs",
        json!({"content": "commit data"}),
        Some("baize-root"),
    );
    let (_, body) = send(&app, req).await;
    let blob_hash = body["hash"].as_str().unwrap();

    // 创建 commit
    let req = post_json(
        "/api/v0/commits",
        json!({"blob_hashes": [blob_hash], "message": "initial commit"}),
        Some("baize-root"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["message"], "initial commit");
    assert_eq!(body["author"], "baize-root");
    assert!(body["hash"].as_str().unwrap().len() == 64);
    assert!(body["blob_hashes"].as_array().unwrap().len() == 1);
}

#[tokio::test]
async fn test_commit_log() {
    let app = test_app();
    // 创建两个 commit 链
    let req = post_json("/api/v0/blobs", json!({"content": "d1"}), Some("baize-root"));
    let (_, b) = send(&app, req).await;
    let h1 = b["hash"].as_str().unwrap();
    let req = post_json("/api/v0/commits", json!({"blob_hashes": [h1], "message": "first"}), Some("baize-root"));
    let (_, b) = send(&app, req).await;
    let c1 = b["hash"].as_str().unwrap();

    let req = post_json("/api/v0/blobs", json!({"content": "d2"}), Some("baize-root"));
    let (_, b) = send(&app, req).await;
    let h2 = b["hash"].as_str().unwrap();
    let req = post_json(
        "/api/v0/commits",
        json!({"blob_hashes": [h2], "message": "second", "parent_hash": c1}),
        Some("baize-root"),
    );
    send(&app, req).await;

    // log
    let req = get_req("/api/v0/log");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    let commits = body["commits"].as_array().unwrap();
    assert_eq!(commits.len(), 2);
    assert_eq!(commits[0]["message"], "second");
    assert_eq!(commits[1]["message"], "first");
}

#[tokio::test]
async fn test_commit_chain_parent_link() {
    let app = test_app();
    let req = post_json("/api/v0/blobs", json!({"content": "d1"}), Some("baize-root"));
    let (_, b) = send(&app, req).await;
    let h1 = b["hash"].as_str().unwrap();
    let req = post_json("/api/v0/commits", json!({"blob_hashes": [h1], "message": "first"}), Some("baize-root"));
    let (_, b) = send(&app, req).await;
    let c1 = b["hash"].as_str().unwrap();

    let req = post_json("/api/v0/blobs", json!({"content": "d2"}), Some("baize-root"));
    let (_, b) = send(&app, req).await;
    let h2 = b["hash"].as_str().unwrap();
    let req = post_json(
        "/api/v0/commits",
        json!({"blob_hashes": [h2], "message": "second", "parent_hash": c1}),
        Some("baize-root"),
    );
    let (_, body) = send(&app, req).await;
    assert_eq!(body["parent_hash"], c1);
}

// ─── 4. Label 操作 ───

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

// ─── 5. Ref 操作 ───

#[tokio::test]
async fn test_ref_set_get_delete() {
    let app = test_app();
    // 创建 commit
    let req = post_json("/api/v0/blobs", json!({"content": "ref data"}), Some("baize-root"));
    let (_, b) = send(&app, req).await;
    let h = b["hash"].as_str().unwrap();
    let req = post_json("/api/v0/commits", json!({"blob_hashes": [h], "message": "ref commit"}), Some("baize-root"));
    let (_, b) = send(&app, req).await;
    let c_hash = b["hash"].as_str().unwrap();

    // set ref
    let req = post_json(
        "/api/v0/refs",
        json!({"name": "v1", "commit_hash": c_hash}),
        Some("baize-root"),
    );
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);

    // get ref
    let req = get_req("/api/v0/refs/v1");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["commit_hash"], c_hash);

    // delete ref
    let req = delete_req("/api/v0/refs/v1", "baize-root");
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // get should fail
    let req = get_req("/api/v0/refs/v1");
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_ref_delete_head_fails() {
    let app = test_app();
    // 创建 commit（自动设置 HEAD）
    let req = post_json("/api/v0/blobs", json!({"content": "data"}), Some("baize-root"));
    let (_, b) = send(&app, req).await;
    let h = b["hash"].as_str().unwrap();
    let req = post_json("/api/v0/commits", json!({"blob_hashes": [h], "message": "head commit"}), Some("baize-root"));
    send(&app, req).await;

    // 删除 HEAD 应失败
    let req = delete_req("/api/v0/refs/HEAD", "baize-root");
    let (status, _) = send(&app, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_ref_list() {
    let app = test_app();
    let req = post_json("/api/v0/blobs", json!({"content": "data"}), Some("baize-root"));
    let (_, b) = send(&app, req).await;
    let h = b["hash"].as_str().unwrap();
    let req = post_json("/api/v0/commits", json!({"blob_hashes": [h], "message": "first"}), Some("baize-root"));
    let (_, b) = send(&app, req).await;
    let c_hash = b["hash"].as_str().unwrap();

    // set extra ref
    let req = post_json("/api/v0/refs", json!({"name": "stable", "commit_hash": c_hash}), Some("baize-root"));
    send(&app, req).await;

    // list
    let req = get_req("/api/v0/refs");
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    let refs = body["refs"].as_array().unwrap();
    assert!(refs.len() >= 2);
    assert!(refs.iter().any(|r| r["name"] == "HEAD"));
    assert!(refs.iter().any(|r| r["name"] == "stable"));
}

// ─── 6. Elevation 流程 ───

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
async fn test_trace_data() {
    let app = test_app();
    // 创建 commit 链
    let req = post_json("/api/v0/blobs", json!({"content": "d1"}), Some("baize-root"));
    let (_, b) = send(&app, req).await;
    let h1 = b["hash"].as_str().unwrap();
    let req = post_json("/api/v0/commits", json!({"blob_hashes": [h1], "message": "first"}), Some("baize-root"));
    let (_, b) = send(&app, req).await;
    let c1 = b["hash"].as_str().unwrap();

    let req = post_json("/api/v0/blobs", json!({"content": "d2"}), Some("baize-root"));
    let (_, b) = send(&app, req).await;
    let h2 = b["hash"].as_str().unwrap();
    let req = post_json(
        "/api/v0/commits",
        json!({"blob_hashes": [h2], "message": "second", "parent_hash": c1}),
        Some("baize-root"),
    );
    let (_, b) = send(&app, req).await;
    let c2 = b["hash"].as_str().unwrap();

    // trace
    let req = get_req(&format!("/api/v0/trace/data/{}", c2));
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    let chain = body["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0]["hash"], c2);
    assert_eq!(chain[1]["hash"], c1);
}

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
        ("/api/v0/commits", json!({"blob_hashes": ["x"], "message": "x"})),
        ("/api/v0/labels", json!({"entity_hash": "x", "key": "x", "value": "x"})),
        ("/api/v0/refs", json!({"name": "x", "commit_hash": "x"})),
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

    // worker 创建 commit → 应成功
    let hash = body["hash"].as_str().unwrap();
    let req = post_json(
        "/api/v0/commits",
        json!({"blob_hashes": [hash], "message": "worker commit"}),
        Some("worker"),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["message"], "worker commit");
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
