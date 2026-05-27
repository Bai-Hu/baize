//! v2 API 集成测试（强制签名 + nonce 重放防护）
//!
//! 覆盖: v2 全部端点的强制签名认证、nonce 重放防护、proof 验证

mod common;
use common::*;
use axum::body::Body;
use serde_json::{json, Value};
use http::{Request, StatusCode};

// ═══════════════════════════════════════════════════════════════
// 辅助: 创建带签名密钥的 agent
// ═══════════════════════════════════════════════════════════════

fn setup_signed_agent(name: &str, level: u8, zones: &[&str]) -> (axum::Router, Vec<u8>) {
    test_app_with_key(name, level, zones)
}

// ═══════════════════════════════════════════════════════════════
// 强制签名认证
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn v2_blob_write_without_signature_fails() {
    let (app, _) = setup_signed_agent("v2a", 2, &["A"]);
    let req = post_json("/api/v2/blobs", json!({"content": "no-sig", "labels": {"type": "generic"}}), Some("v2a"));
    let (s, _) = send(&app, req).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn v2_blob_write_with_signature_succeeds() {
    let (app, key) = setup_signed_agent("v2b", 2, &["A"]);
    let req = signed_request("POST", "/api/v2/blobs", json!({"content": "signed", "labels": {"type": "generic"}}), "v2b", &key, None);
    let (s, b) = send(&app, req).await;
    assert_eq!(s, StatusCode::CREATED);
    assert!(!b["hash"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn v2_file_write_with_signature() {
    let (app, key) = setup_signed_agent("v2c", 2, &["A"]);
    let req = signed_request("POST", "/api/v2/files/A/config.yaml", json!({"content": "k: v"}), "v2c", &key, None);
    let (s, b) = send(&app, req).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(b["path"], "A/config.yaml");
}

#[tokio::test]
async fn v2_intent_with_signature() {
    let (app, key) = setup_signed_agent("v2d", 3, &["deploy"]);
    let content = json!({
        "intent_id": "int-v2", "intent_owner": "v2d", "intent_creator": "v2d",
        "intent_goal": "g", "intent_constraints": {"target_scope": ["deploy"]},
        "version": "1.0", "created_at": now_rfc3339(), "expires_at": now_plus_minutes(60)
    }).to_string();
    let req = signed_request("POST", "/api/v2/intents", json!({"content": content}), "v2d", &key, None);
    let (s, b) = send(&app, req).await;
    assert_eq!(s, StatusCode::CREATED);
    assert!(!b["hash"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn v2_authz_with_signature() {
    let (app, key) = setup_signed_agent("v2e", 2, &["deploy"]);

    let intent_content = json!({
        "intent_id": "int-v2a", "intent_owner": "v2e", "intent_creator": "v2e",
        "intent_goal": "g", "intent_constraints": {"target_scope": ["deploy"]},
        "version": "1.0", "created_at": now_rfc3339(), "expires_at": now_plus_minutes(60)
    }).to_string();
    let req = signed_request("POST", "/api/v2/intents", json!({"content": intent_content}), "v2e", &key, None);
    let (_, b) = send(&app, req).await;
    let intent_hash = b["hash"].as_str().unwrap().to_string();

    let authz_content = json!({
        "authorization_id": "av2", "issuer": "v2e", "subject": "v2e",
        "grant_type": "execute", "constraints": {"target_scope": ["deploy"]},
        "delegatable": false, "source_intent_digest": intent_hash,
        "root_authorizer": "v2e", "nbf": now_rfc3339(),
        "exp": now_plus_minutes(30), "iat": now_rfc3339(), "jti": "j", "version": "1.0"
    }).to_string();
    let req = signed_request("POST", "/api/v2/authorizations", json!({"content": authz_content}), "v2e", &key, None);
    let (s, b) = send(&app, req).await;
    assert_eq!(s, StatusCode::CREATED);
    assert!(!b["hash"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn v2_receipt_with_signature() {
    let (app, key) = setup_signed_agent("v2f", 2, &["deploy"]);

    // 需要 proof（L3+）的端点用 L2 测试普通签名即可
    // 这里测试 v2 receipt 端点可达（但可能因缺少 intent/authz 而失败）
    let receipt_content = json!({
        "receipt_id": "rct-v2", "executor_id": "v2f", "task_id": "T1",
        "action_type": "execute", "intent_digest": "sha256:fake",
        "authorization_digest": "sha256:fake", "result_status": "SUCCEEDED",
        "started_at": now_rfc3339(), "finished_at": now_rfc3339()
    }).to_string();
    let req = signed_request("POST", "/api/v2/receipts", json!({"content": receipt_content}), "v2f", &key, None);
    let (s, _) = send(&app, req).await;
    // 可能 400（fake hash）但不应是 401
    assert_ne!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn v2_session_with_signature() {
    let (app, key_a) = setup_signed_agent("v2alice", 2, &["A"]);
    // 需要在同一个 app 上注册 bob
    send(&app, post_json("/api/v0/agents", json!({"name": "v2bob", "level": 2, "zones": ["A"]}), Some("baize-root"))).await;

    let req = signed_request("POST", "/api/v2/sessions", json!({
        "session_id": "sv2", "peer_a": "v2alice", "peer_b": "v2bob",
        "ephemeral_pub": gen_ephemeral_pub(), "cipher_suites": ["AES-256-GCM"],
        "credential_digest_a": "sha256:a", "credential_digest_b": "sha256:b",
        "handshake_transcript_digest": "sha256:t"
    }), "v2alice", &key_a, None);
    let (s, b) = send(&app, req).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(b["session_id"], "sv2");
}

#[tokio::test]
async fn v2_key_rotate_with_signature() {
    let (app, key) = setup_signed_agent("v2k", 3, &["A"]);
    let req = signed_request("POST", "/api/v2/agents/v2k/keys/rotate", json!({"purpose": "INT_SIGN"}), "v2k", &key, None);
    let (s, b) = send(&app, req).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!b["new_key_hash"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn v2_proof_with_signature() {
    let (app, key) = setup_signed_agent("v2p", 3, &["A"]);
    let req = signed_request("POST", "/api/v2/agents/v2p/proof", json!({
        "instance_state_attributes": {"instance_id": "h1", "instance_status": "running"}
    }), "v2p", &key, None);
    let (s, b) = send(&app, req).await;
    assert_eq!(s, StatusCode::CREATED);
    assert!(!b["proof_id"].as_str().unwrap().is_empty());
}

// ═══════════════════════════════════════════════════════════════
// Nonce 重放防护
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn v2_nonce_replay_protection() {
    let (app, key) = setup_signed_agent("v2nonce", 2, &["A"]);
    let nonce = "nonce-e2e-unique-001";
    let body = json!({"content": "with-nonce", "labels": {"type": "generic"}});

    // 第一次请求
    let req1 = signed_request("POST", "/api/v2/blobs", body.clone(), "v2nonce", &key, Some(nonce));
    let (s1, _) = send(&app, req1).await;
    assert_eq!(s1, StatusCode::CREATED);

    // 相同 nonce 第二次请求 → 409 Conflict
    let req2 = signed_request("POST", "/api/v2/blobs", body, "v2nonce", &key, Some(nonce));
    let (s2, _) = send(&app, req2).await;
    assert_eq!(s2, StatusCode::CONFLICT);
}

#[tokio::test]
async fn v2_different_nonce_ok() {
    let (app, key) = setup_signed_agent("v2nonce2", 2, &["A"]);
    let body = json!({"content": "nonce-test", "labels": {"type": "generic"}});

    let req1 = signed_request("POST", "/api/v2/blobs", body.clone(), "v2nonce2", &key, Some("nonce-1"));
    let (s1, _) = send(&app, req1).await;
    assert_eq!(s1, StatusCode::CREATED);

    let req2 = signed_request("POST", "/api/v2/blobs", body, "v2nonce2", &key, Some("nonce-2"));
    let (s2, _) = send(&app, req2).await;
    assert_eq!(s2, StatusCode::CREATED);
}

// ═══════════════════════════════════════════════════════════════
// 签名错误场景
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn v2_wrong_signature_fails() {
    let (app, _key) = setup_signed_agent("v2bad", 2, &["A"]);
    // 使用一个错误的密钥生成签名
    let wrong_key = vec![0u8; 32];
    let req = signed_request("POST", "/api/v2/blobs", json!({"content": "bad-sig"}), "v2bad", &wrong_key, None);
    let (s, _) = send(&app, req).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn v2_expired_timestamp_fails() {
    let (app, key) = setup_signed_agent("v2old", 2, &["A"]);
    let body_str = serde_json::to_string(&json!({"content": "old", "labels": {"type": "generic"}})).unwrap();
    let old_ts = (chrono::Utc::now() - chrono::Duration::minutes(10)).to_rfc3339();
    let sig = baize_server::pipeline::auth::compute_signature(&key, &old_ts, "POST", "/api/v2/blobs", &body_str);

    let req = Request::builder()
        .method("POST").uri("/api/v2/blobs")
        .header("content-type", "application/json")
        .header("x-agent-id", "v2old")
        .header("x-timestamp", &old_ts)
        .header("x-signature", &sig)
        .body(axum::body::Body::from(body_str)).unwrap();

    let (s, _) = send(&app, req).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

// ═══════════════════════════════════════════════════════════════
// v2 Proof 验证
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn v2_proof_verify_valid() {
    let (app, key) = setup_signed_agent("v2pv", 3, &["A"]);

    let req = signed_request("POST", "/api/v2/agents/v2pv/proof", json!({
        "instance_state_attributes": {"instance_id": "host-01", "instance_status": "running"}
    }), "v2pv", &key, None);
    let (_, b) = send(&app, req).await;
    let proof_id = b["proof_id"].as_str().unwrap();

    let req = signed_get_req("/api/v2/agents/v2pv/proof/verify", "v2pv", &key);
    let (s, b) = send(&app, req).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["valid"], true);
    assert_eq!(b["proof_id"], proof_id);
}
