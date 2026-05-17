use std::collections::HashMap;

use baize_core::cert::CertTool;
use baize_core::scope::{ElevationMode, Level};
use baize_server::Baize;
use baize_server::pipeline::{AgentRegistry, ElevationManager};

/// 1. 完整委托链：root → parent → child，验证证书链 + 身份追溯
#[test]
fn test_full_delegation_chain() {
    let mut baize = Baize::init_in_memory().unwrap();

    let (_, parent_bundle) = baize.agent_register("parent", Level(3), vec!["A", "B", "C"], None).unwrap();
    let (_, child_bundle) = baize.agent_register("child", Level(2), vec!["A"], Some("parent")).unwrap();

    // 身份追溯
    let chain = baize.trace_identity("child").unwrap();
    assert_eq!(chain.len(), 3); // child → parent → root
    assert_eq!(chain[0].agent_id, "child");
    assert_eq!(chain[0].parent_id.as_deref(), Some("parent"));
    assert_eq!(chain[1].agent_id, "parent");
    assert_eq!(chain[1].parent_id.as_deref(), Some("baize-root"));
    assert_eq!(chain[2].agent_id, "baize-root");
    assert!(chain[2].parent_id.is_none());

    // 直接从注册返回值获取证书，验证证书链
    let root_cert_pem = {
        let mut root_filter = HashMap::new();
        root_filter.insert("type".to_string(), "root-ca".to_string());
        let root_certs = baize.storage.blob_query(&root_filter).unwrap();
        root_certs[0].content.clone()
    };

    let result = CertTool::verify_chain(
        &[&child_bundle.cert_pem, &parent_bundle.cert_pem],
        &root_cert_pem,
    );
    assert!(result.is_ok());
}

/// 2. child level > parent level 应失败
#[test]
fn test_scope_level_exceeds_parent() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("parent", Level(2), vec!["A"], None).unwrap();

    let result = baize.agent_register("child", Level(3), vec!["A"], Some("parent"));
    assert!(result.is_err());
}

/// 3. child zones ⊄ parent zones 应失败
#[test]
fn test_scope_zones_not_subset() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("parent", Level(3), vec!["A", "B"], None).unwrap();

    // "C" 不在 parent 的 zones 中
    let result = baize.agent_register("child", Level(2), vec!["A", "C"], Some("parent"));
    assert!(result.is_err());
}

/// 4. 借权允许申请超出自己 scope 的 zone（需要审批）
#[test]
fn test_elevation_beyond_scope() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("worker", Level(2), vec!["A", "B"], None).unwrap();

    // scope 内的 zone → 成功
    let result = baize.elevation_request("worker", vec!["A"], ElevationMode::ReadOnly, "need A", None);
    assert!(result.is_ok());

    // scope 外的 zone 也可以申请（借权的意义就是获取超出 scope 的权限）
    let result = baize.elevation_request("worker", vec!["Z"], ElevationMode::ReadOnly, "need Z", None);
    assert!(result.is_ok());

    // 不存在的 agent 应失败
    let result = baize.elevation_request("ghost", vec!["A"], ElevationMode::ReadOnly, "hack", None);
    assert!(result.is_err());
}

/// 5. 撤销 parent 后 child trace 断裂
#[test]
fn test_revoke_cascading() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("parent", Level(3), vec!["A", "B", "C"], None).unwrap();
    baize.agent_register("child", Level(2), vec!["A"], Some("parent")).unwrap();

    baize.agent_revoke("parent").unwrap();

    // 列表中只剩 root + child
    let agents = baize.agent_list();
    assert_eq!(agents.len(), 2);
    assert!(agents.iter().any(|(id, _)| id == "baize-root"));
    assert!(agents.iter().any(|(id, _)| id == "child"));

    // child 的 trace 因 parent 不在内存而断裂
    let chain = baize.trace_identity("child").unwrap();
    assert_eq!(chain.len(), 1); // 只有 child 自己
    assert_eq!(chain[0].agent_id, "child");
}

/// 6. register → blob 完整审计记录
#[test]
fn test_audit_trail() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();

    baize.storage.blob_write("task data", &HashMap::new()).unwrap();

    // 查询审计记录
    let mut audit_filter = HashMap::new();
    audit_filter.insert("x-audit".to_string(), "true".to_string());
    let audit_blobs = baize.storage.blob_query(&audit_filter).unwrap();

    // 至少有 agent_register 审计
    assert!(!audit_blobs.is_empty());
    let register_audit = audit_blobs.iter().find(|b| {
        b.labels.get("x-audit-type") == Some(&"agent_register".to_string())
    });
    assert!(register_audit.is_some());
    assert!(register_audit.unwrap().content.contains("worker"));
}

/// 7. 跨 Baize 实例 agent 恢复
#[test]
fn test_agent_persistence() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db_path = tmp.path().join("test.db");
    let ws_path = tmp.path().join("workspaces");
    let db_str = db_path.to_string_lossy().to_string();
    let ws_str = ws_path.to_string_lossy().to_string();
    let main_path = tmp.path().join("main");
    let main_str = main_path.to_string_lossy().to_string();

    // 实例 1：注册 agent
    {
        let mut baize = Baize::init(&db_str, &ws_str, &main_str).unwrap();
        baize.agent_register("persistent", Level(3), vec!["X", "Y"], None).unwrap();
    }

    // 实例 2：验证 agent 恢复
    let baize2 = Baize::init(&db_str, &ws_str, &main_str).unwrap();
    let agents = baize2.agent_list();
    assert!(agents.iter().any(|(id, _)| id == "persistent"));

    let persistent = agents.iter().find(|(id, _)| id == "persistent").unwrap();
    assert_eq!(persistent.1.level, 3);
    assert!(persistent.1.zones.contains(&"X".to_string()));
    assert!(persistent.1.zones.contains(&"Y".to_string()));

    // 身份追溯
    let chain = baize2.trace_identity("persistent").unwrap();
    assert_eq!(chain.len(), 2); // persistent → root
    assert_eq!(chain[0].agent_id, "persistent");
    assert_eq!(chain[1].agent_id, "baize-root");
}

/// 8. 跨 Baize 实例 revoked agent 不恢复
#[test]
fn test_revoke_persistence() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db_path = tmp.path().join("test.db");
    let ws_path = tmp.path().join("workspaces");
    let db_str = db_path.to_string_lossy().to_string();
    let ws_str = ws_path.to_string_lossy().to_string();
    let main_path = tmp.path().join("main");
    let main_str = main_path.to_string_lossy().to_string();

    // 实例 1：注册 + 撤销
    {
        let mut baize = Baize::init(&db_str, &ws_str, &main_str).unwrap();
        baize.agent_register("temp", Level(2), vec!["Z"], None).unwrap();
        baize.agent_revoke("temp").unwrap();
    }

    // 实例 2：验证 temp 不恢复
    let baize2 = Baize::init(&db_str, &ws_str, &main_str).unwrap();
    let agents = baize2.agent_list();
    assert!(!agents.iter().any(|(id, _)| id == "temp"));
    assert_eq!(agents.len(), 1); // 只有 root

    // trace 不存在的 agent 应失败
    let result = baize2.trace_identity("temp");
    assert!(result.is_err());
}
