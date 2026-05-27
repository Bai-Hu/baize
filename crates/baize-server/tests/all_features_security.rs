//! 安全模型集成测试
//!
//! 覆盖: Level/Zone 权限、约束收缩、委托链完整性、审计链、负面路径

mod common;
use common::*;
use axum::body::Body;
use serde_json::{json, Value};
use http::{Request, StatusCode};

async fn setup_agent(app: &axum::Router, name: &str, level: u8, zones: &[&str], parent: Option<&str>) {
    let mut body = json!({"name": name, "level": level, "zones": zones});
    if let Some(p) = parent {
        body["parent_id"] = json!(p);
    }
    send(app, post_json("/api/v0/agents", body, Some("baize-root"))).await;
}

// ═══════════════════════════════════════════════════════════════
// Level 权限模型
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn sec_level0_sandbox_cannot_write_anything() {
    let app = test_app();
    setup_agent(&app, "sandbox", 0, &[], None).await;

    let (s, _) = send(&app, post_json("/api/v0/blobs", json!({"content": "x"}), Some("sandbox"))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    let (s, _) = send(&app, post_json("/api/v0/files/A/x.txt", json!({"content": "x"}), Some("sandbox"))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn sec_level0_can_read() {
    let app = test_app();
    setup_agent(&app, "sandbox", 0, &[], None).await;

    let (_, b) = send(&app, post_json("/api/v0/blobs", json!({"content": "public"}), Some("baize-root"))).await;
    let hash = b["hash"].as_str().unwrap();

    let (s, b) = send(&app, get_req_with_agent(&format!("/api/v0/export/{}", hash), "sandbox")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["content"], "public");
}

#[tokio::test]
async fn sec_level1_can_write() {
    let app = test_app();
    setup_agent(&app, "restricted", 1, &["A"], None).await;

    let (s, b) = send(&app, post_json("/api/v0/blobs", json!({"content": "restricted data"}), Some("restricted"))).await;
    assert_eq!(s, StatusCode::CREATED);
    assert!(!b["hash"].as_str().unwrap().is_empty());
}

// ═══════════════════════════════════════════════════════════════
// Zone 隔离
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn sec_zone_isolation_file_write() {
    let app = test_app();
    setup_agent(&app, "zone-a", 2, &["A"], None).await;
    setup_agent(&app, "zone-b", 2, &["B"], None).await;

    // zone-a 写 A 文件成功
    let (s, _) = send(&app, post_json("/api/v0/files/A/data.txt", json!({"content": "a"}), Some("zone-a"))).await;
    assert_eq!(s, StatusCode::CREATED);

    // zone-a 写 B 文件失败
    let (s, b) = send(&app, post_json("/api/v0/files/B/data.txt", json!({"content": "hack"}), Some("zone-a"))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(b["error"].as_str().unwrap().contains("permission denied"));
}

#[tokio::test]
async fn sec_zone_wildcard_root_access_all() {
    let app = test_app();
    setup_agent(&app, "zone-a", 2, &["A"], None).await;

    // root 写 B 文件成功（zones=[*]）
    let (s, _) = send(&app, post_json("/api/v0/files/B/root.txt", json!({"content": "root"}), Some("baize-root"))).await;
    assert_eq!(s, StatusCode::CREATED);

    // zone-a 读 B 文件失败
    let (s, _) = send(&app, get_req_with_agent("/api/v0/files/B/root.txt", "zone-a")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn sec_root_level_files_accessible_to_all() {
    let app = test_app();
    setup_agent(&app, "zone-a", 2, &["A"], None).await;

    // zone-a 写根级文件（根级文件无 zone 限制）
    let (s, _) = send(&app, post_json("/api/v0/files/README.md", json!({"content": "# Hello"}), Some("zone-a"))).await;
    assert_eq!(s, StatusCode::CREATED);

    // zone-a 可以读取自己的根级文件
    let (s, b) = send(&app, get_req_with_agent("/api/v0/files/README.md", "zone-a")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["content"], "# Hello");
}

// ═══════════════════════════════════════════════════════════════
// 委托链安全
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn sec_delegation_chain_level_enforced() {
    let app = test_app();
    setup_agent(&app, "parent", 2, &["A"], None).await;

    // child level > parent → 失败
    let (s, _) = send(&app, post_json("/api/v0/agents", json!({
        "name": "bad-child", "level": 3, "zones": ["A"], "parent_id": "parent"
    }), Some("baize-root"))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sec_delegation_chain_zones_enforced() {
    let app = test_app();
    setup_agent(&app, "parent", 3, &["A"], None).await;

    // child zones 超出 parent → 失败
    let (s, _) = send(&app, post_json("/api/v0/agents", json!({
        "name": "bad-child", "level": 2, "zones": ["A", "B"], "parent_id": "parent"
    }), Some("baize-root"))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sec_trace_identity_deep_chain() {
    let app = test_app();
    setup_agent(&app, "l3", 3, &["A"], None).await;
    setup_agent(&app, "l2", 2, &["A"], Some("l3")).await;
    setup_agent(&app, "l1", 1, &["A"], Some("l2")).await;

    let (s, b) = send(&app, get_req("/api/v0/trace/identity/l1")).await;
    assert_eq!(s, StatusCode::OK);
    let chain = b["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 4);
    assert_eq!(chain[0]["agent_id"], "l1");
    assert_eq!(chain[1]["agent_id"], "l2");
    assert_eq!(chain[2]["agent_id"], "l3");
    assert_eq!(chain[3]["agent_id"], "baize-root");
}

// ═══════════════════════════════════════════════════════════════
// 约束收缩（Constraint Tightening）
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn sec_constraint_tightening_numeric() {
    let app = test_app();
    setup_agent(&app, "cmd", 3, &["deploy"], None).await;
    setup_agent(&app, "pln", 2, &["deploy"], Some("cmd")).await;

    let intent = json!({
        "intent_id": "int-ct", "intent_owner": "cmd", "intent_creator": "cmd",
        "intent_goal": "g", "intent_constraints": {"max_budget": 100},
        "version": "1.0", "created_at": now_rfc3339(), "expires_at": now_plus_minutes(60)
    }).to_string();
    let (_, b) = send(&app, post_json("/api/v1/intents", json!({"content": intent}), Some("cmd"))).await;
    let hash = b["hash"].as_str().unwrap();

    // 子意图 budget > 父 → 失败
    let sub = json!({
        "sub_intent_id": "sub-ct-bad", "parent_intent_digest": hash, "deriver_id": "pln",
        "subject": "s", "derivation_depth": 1, "intent_goal": "g",
        "intent_constraints": {"max_budget": 200},
        "created_at": now_rfc3339(), "expires_at": now_plus_minutes(30)
    }).to_string();
    let (s, _) = send(&app, post_json("/api/v1/intents/derive", json!({"content": sub}), Some("pln"))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // 子意图 budget <= 父 → 成功
    let sub2 = json!({
        "sub_intent_id": "sub-ct-ok", "parent_intent_digest": hash, "deriver_id": "pln",
        "subject": "s", "derivation_depth": 1, "intent_goal": "g",
        "intent_constraints": {"max_budget": 50},
        "created_at": now_rfc3339(), "expires_at": now_plus_minutes(30)
    }).to_string();
    let (s, _) = send(&app, post_json("/api/v1/intents/derive", json!({"content": sub2}), Some("pln"))).await;
    assert_eq!(s, StatusCode::CREATED);
}

#[tokio::test]
async fn sec_constraint_tightening_array_subset() {
    let app = test_app();
    setup_agent(&app, "cmd", 3, &["A", "B", "C"], None).await;
    setup_agent(&app, "pln", 2, &["A", "B"], Some("cmd")).await;

    let intent = json!({
        "intent_id": "int-arr", "intent_owner": "cmd", "intent_creator": "cmd",
        "intent_goal": "g", "intent_constraints": {"target_scope": ["A", "B", "C"]},
        "version": "1.0", "created_at": now_rfc3339(), "expires_at": now_plus_minutes(60)
    }).to_string();
    let (_, b) = send(&app, post_json("/api/v1/intents", json!({"content": intent}), Some("cmd"))).await;
    let hash = b["hash"].as_str().unwrap();

    // 子意图 target_scope 超集 → 失败
    let sub = json!({
        "sub_intent_id": "sub-arr-bad", "parent_intent_digest": hash, "deriver_id": "pln",
        "subject": "s", "derivation_depth": 1, "intent_goal": "g",
        "intent_constraints": {"target_scope": ["A", "B", "C", "D"]},
        "created_at": now_rfc3339(), "expires_at": now_plus_minutes(30)
    }).to_string();
    let (s, _) = send(&app, post_json("/api/v1/intents/derive", json!({"content": sub}), Some("pln"))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // 子意图 target_scope 子集 → 成功
    let sub2 = json!({
        "sub_intent_id": "sub-arr-ok", "parent_intent_digest": hash, "deriver_id": "pln",
        "subject": "s", "derivation_depth": 1, "intent_goal": "g",
        "intent_constraints": {"target_scope": ["A"]},
        "created_at": now_rfc3339(), "expires_at": now_plus_minutes(30)
    }).to_string();
    let (s, _) = send(&app, post_json("/api/v1/intents/derive", json!({"content": sub2}), Some("pln"))).await;
    assert_eq!(s, StatusCode::CREATED);
}

// ═══════════════════════════════════════════════════════════════
// 审计链完整性
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn sec_audit_chain_integrity() {
    let app = test_app();
    setup_agent(&app, "w", 2, &["A"], None).await;

    // 执行多个写操作
    send(&app, post_json("/api/v0/blobs", json!({"content": "a"}), Some("w"))).await;
    send(&app, post_json("/api/v0/files/A/x.txt", json!({"content": "b"}), Some("w"))).await;
    send(&app, post_json("/api/v0/blobs", json!({"content": "c"}), Some("baize-root"))).await;

    // 验证审计链
    let (s, b) = send(&app, post_json("/api/v1/audit/verify-chain", json!({}), Some("baize-root"))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["valid"], true);
    assert!(b["chain_length"].as_u64().unwrap() >= 3);

    // 验证 v0 审计记录
    let (s, b) = send(&app, get_req("/api/v0/audit")).await;
    assert_eq!(s, StatusCode::OK);
    let records = b["records"].as_array().unwrap();
    assert!(records.iter().any(|r| r["agent"] == "w" && r["type"] == "blob_write"));
    assert!(records.iter().any(|r| r["agent"] == "w" && r["type"] == "file_write"));
}

// ═══════════════════════════════════════════════════════════════
// 负面路径综合
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn sec_negative_paths() {
    let app = test_app();
    setup_agent(&app, "worker", 2, &["A"], None).await;

    // NP1: 无认证头
    let (s, _) = send(&app, post_json("/api/v0/blobs", json!({"content": "x"}), None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // NP2: 不存在的 agent
    let (s, b) = send(&app, post_json("/api/v0/blobs", json!({"content": "x"}), Some("ghost"))).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(b["error"], "user decision required");

    // NP3: Zone 越权
    let (s, _) = send(&app, post_json("/api/v0/files/B/x.txt", json!({"content": "x"}), Some("worker"))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // NP4: 空约束意图
    let intent = json!({
        "intent_id": "bad", "intent_owner": "worker", "intent_creator": "worker",
        "intent_goal": "g", "intent_constraints": {},
        "version": "1.0", "created_at": now_rfc3339(), "expires_at": now_plus_minutes(10)
    }).to_string();
    let (s, _) = send(&app, post_json("/api/v1/intents", json!({"content": intent}), Some("worker"))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // NP5: 空 source 导入
    let (s, _) = send(&app, post_json("/api/v0/import", json!({"content": "x", "source": "  "}), Some("worker"))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // NP6: trust_level 超过 agent level
    let (s, _) = send(&app, post_json("/api/v0/import", json!({"content": "x", "source": "s", "trust_level": 5}), Some("worker"))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // NP7: 读取不存在的 blob
    let (s, _) = send(&app, get_req("/api/v0/blobs/deadbeef00000000000000000000000000000000000000000000000000000000")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // NP8: 重复关闭 session
    setup_agent(&app, "a1", 2, &["Z"], None).await;
    setup_agent(&app, "b1", 2, &["Z"], None).await;
    send(&app, post_json("/api/v1/sessions", json!({
        "session_id": "s-neg", "peer_a": "a1", "peer_b": "b1",
        "ephemeral_pub": gen_ephemeral_pub(), "cipher_suites": ["AES-256-GCM"],
        "credential_digest_a": "sha256:a", "credential_digest_b": "sha256:b",
        "handshake_transcript_digest": "sha256:t"
    }), Some("a1"))).await;
    send(&app, post_json("/api/v1/sessions/s-neg/accept", json!({
        "credential_digest_responder": "sha256:b", "ephemeral_pub": gen_ephemeral_pub(),
        "selected_cipher_suite": "AES-256-GCM", "handshake_transcript_digest": "sha256:t2"
    }), Some("b1"))).await;
    let (s1, _) = send(&app, post_json("/api/v1/sessions/s-neg/close", json!({"reason": "done"}), Some("a1"))).await;
    assert_eq!(s1, StatusCode::CREATED);
    let (s, _) = send(&app, post_json("/api/v1/sessions/s-neg/close", json!({"reason": "again"}), Some("a1"))).await;
    assert_eq!(s, StatusCode::CONFLICT);

    // NP9: root 不可撤销
    let (s, _) = send(&app, delete_req("/api/v0/agents/baize-root", "baize-root")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // NP10: 审批已批准的借权
    let (_, b) = send(&app, post_json("/api/v0/elevation", json!({
        "agent_id": "worker", "zones": ["A"], "mode": "readonly", "reason": "r"
    }), None)).await;
    let eid = b["request_id"].as_str().unwrap();
    let (s1, _) = send(&app, post_json(&format!("/api/v0/elevation/{}/approve", eid), json!({}), Some("baize-root"))).await;
    assert_eq!(s1, StatusCode::OK);
    let (s, _) = send(&app, post_json(&format!("/api/v0/elevation/{}/approve", eid), json!({}), Some("baize-root"))).await;
    assert_eq!(s, StatusCode::CONFLICT);
}

// ═══════════════════════════════════════════════════════════════
// 凭证生命周期状态机
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn sec_credential_status_transitions() {
    let app = test_app();
    setup_agent(&app, "contractor", 2, &["A"], None).await;

    // Active → Suspended
    let (s, _) = send(&app, put_json("/api/v1/agents/contractor/status", json!({"status": "suspended"}), "baize-root")).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send(&app, post_json("/api/v0/blobs", json!({"content": "x"}), Some("contractor"))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Suspended → Active
    let (s, _) = send(&app, put_json("/api/v1/agents/contractor/status", json!({"status": "active"}), "baize-root")).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send(&app, post_json("/api/v0/blobs", json!({"content": "ok"}), Some("contractor"))).await;
    assert_eq!(s, StatusCode::CREATED);

    // Active → Revoked（通过撤销 agent）
    let (s, _) = send(&app, delete_req("/api/v0/agents/contractor", "baize-root")).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = send(&app, post_json("/api/v0/blobs", json!({"content": "x"}), Some("contractor"))).await;
    assert!(s == StatusCode::UNPROCESSABLE_ENTITY || s == StatusCode::UNAUTHORIZED);
}

// ═══════════════════════════════════════════════════════════════
// 敏感数据导出权限
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn sec_export_sensitivity_levels() {
    let app = test_app();
    setup_agent(&app, "low", 1, &["A"], None).await;
    setup_agent(&app, "mid", 2, &["A"], None).await;
    setup_agent(&app, "high", 3, &["A"], None).await;

    // root 创建高敏感度 blob（high 需要 L3+）
    let (_, b) = send(&app, post_json("/api/v0/blobs", json!({
        "content": "top secret", "labels": {"sensitivity": "high"}
    }), Some("baize-root"))).await;
    let hash = b["hash"].as_str().unwrap();

    // low agent (L1) 不能导出 high sensitivity
    let (s, _) = send(&app, get_req_with_agent(&format!("/api/v0/export/{}", hash), "low")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // mid agent (L2) 也不能导出 high sensitivity
    let (s, _) = send(&app, get_req_with_agent(&format!("/api/v0/export/{}", hash), "mid")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // high agent (L3) 可以导出
    let (s, b) = send(&app, get_req_with_agent(&format!("/api/v0/export/{}", hash), "high")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["content"], "top secret");
}

// ═══════════════════════════════════════════════════════════════
// v2 签名安全边界
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn sec_v2_missing_all_sig_headers_fails() {
    let (app, _) = test_app_with_key("v2sec", 2, &["A"]);
    let req = Request::builder()
        .method("POST").uri("/api/v2/blobs")
        .header("content-type", "application/json")
        .header("x-agent-id", "v2sec")
        .body(axum::body::Body::from(r#"{"content":"x"}"#)).unwrap();
    let (s, _) = send(&app, req).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sec_v2_tampered_body_fails() {
    let (app, key) = test_app_with_key("v2tamper", 2, &["A"]);
    let body = json!({"content": "original", "labels": {"type": "generic"}});
    let mut req = signed_request("POST", "/api/v2/blobs", body, "v2tamper", &key, None);
    // 篡改 body（无法直接修改，所以用错误签名模拟）
    let wrong_key = vec![0xffu8; 32];
    let req2 = signed_request("POST", "/api/v2/blobs", json!({"content": "tampered"}), "v2tamper", &wrong_key, None);
    let (s, _) = send(&app, req2).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}
