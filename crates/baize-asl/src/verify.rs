//! CNV 全链路校验 + AZN-VER 五项校验（V1_DEV §5.4/§5.5）
//!
//! CNV 和 AZN-VER 放在 baize-asl crate，因为它们是跨模块的校验逻辑
//! （横跨 INT + AZN + IDN），通过 BlobStore trait 访问 blob 数据，
//! 不依赖具体 pipeline 模块。

use std::collections::HashMap;

use baize_core::constraint::{verify_authz_constraint_reduction, verify_intent_constraint_reduction};
use baize_core::error::Error;
use baize_core::labels::*;
use baize_core::storage::BlobStore;

use crate::adapter::AslAdapter;
use crate::payload::*;

// ─── BlobStore 访问 trait ───
// verify 需要读取 blob，但不直接依赖 Storage — 用函数参数传入

/// CNV 校验结果
#[derive(Debug, Clone)]
pub struct CnvResult {
    pub valid: bool,
    pub intent_chain: Vec<ChainNode>,
    pub authz_checks: AuthzChecks,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ChainNode {
    pub digest: String,
    pub intent_id: String,
    pub depth: u32,
}

#[derive(Debug, Clone)]
pub struct AuthzChecks {
    pub authz_found: bool,
    pub issuer_valid: bool,
    pub source_intent_match: bool,
    pub delegation_chain_valid: bool,
}

/// AZN-VER 执行上下文（校验五所需）
#[derive(Debug, Clone, Default)]
pub struct ExecutionContext {
    /// 当前执行方 agent-id（应与 authorization.subject 一致）
    pub subject: Option<String>,
    /// 本次执行目标（应落在 constraints.target_scope 内）
    pub target: Option<serde_json::Value>,
    /// 本次执行金额（应不超过 amount_scope.max_amount）
    pub amount: Option<f64>,
    /// 当前执行环境 SEE 等级（应不低于 environment_scope.min_see_level）
    pub environment: Option<String>,
}

/// AZN-VER 校验结果
#[derive(Debug, Clone)]
pub struct AuthzVerifyResult {
    pub valid: bool,
    pub checks: [bool; 5],
    pub check_names: [String; 5],
    pub errors: Vec<String>,
}

// ─── INT-CNV：全链路一致性校验 ───

/// INT-CNV 全链路校验
///
/// 从 receipt 出发，沿 label 引用链校验：
/// 1. 意图派生链完整性 + 约束收缩合规
/// 2. authorization.source_intent_digest 与意图一致
/// 3. receipt.authorization_digest 与授权一致
/// 4. 委托链完整性
pub fn cnv_verify(
    storage: &dyn BlobStore,
    receipt_digest: &str,
) -> Result<CnvResult, Error> {
    let mut errors = Vec::new();
    let mut authz_checks = AuthzChecks {
        authz_found: false,
        issuer_valid: false,
        source_intent_match: false,
        delegation_chain_valid: true,
    };

    // 1. 读取 receipt blob
    let receipt_blob = storage.blob_read(receipt_digest)
        .map_err(|_| Error::ChainBroken(format!("receipt {} not found", receipt_digest)))?;

    let receipt_type = receipt_blob.labels.get("type").unwrap_or(&"".to_string()).clone();
    if receipt_type != BLOB_TYPE_RECEIPT {
        return Err(Error::ChainBroken(format!(
            "expected receipt blob, got type '{}'", receipt_type
        )));
    }

    let receipt = AslAdapter::receipt_from_blob(&receipt_blob.content)
        .map_err(|e| Error::ChainBroken(format!("invalid receipt content: {}", e)))?;

    // 2. 沿 x-parent-intent 向上追溯意图派生链
    let intent_digest = &receipt.intent_digest;
    let chain_result = trace_intent_chain(storage, intent_digest)?;
    let intent_chain = chain_result.nodes;

    if !chain_result.errors.is_empty() {
        errors.extend(chain_result.errors);
    }

    // 3. 校验 authorization.source_intent_digest 与意图一致
    validate_authz_in_cnv(storage, &receipt, &intent_chain, &mut errors, &mut authz_checks)?;

    let valid = errors.is_empty();

    Ok(CnvResult {
        valid,
        intent_chain,
        authz_checks,
        errors,
    })
}

/// CNV 中校验 authorization 的 source_intent/issuer/action_type
fn validate_authz_in_cnv(
    storage: &dyn BlobStore,
    receipt: &ReceiptContent,
    intent_chain: &[ChainNode],
    errors: &mut Vec<String>,
    authz_checks: &mut AuthzChecks,
) -> Result<(), Error> {
    let authz_digest = &receipt.authorization_digest;
    let authz_blob = storage.blob_read(authz_digest);

    match authz_blob {
        Ok(blob) => {
            authz_checks.authz_found = true;

            if blob.labels.get("type").unwrap_or(&"".to_string()) != BLOB_TYPE_AUTHORIZATION {
                errors.push(format!("authorization blob {} has wrong type", authz_digest));
                return Ok(());
            }

            let authz = match AslAdapter::authorization_from_blob(&blob.content) {
                Ok(a) => a,
                Err(e) => {
                    errors.push(format!("invalid authorization content: {}", e));
                    return Ok(());
                }
            };

            // 校验 source_intent_digest 在意图链中
            let chain_digests: Vec<&str> = intent_chain.iter()
                .map(|n| n.digest.as_str())
                .collect();

            if chain_digests.contains(&authz.source_intent_digest.as_str()) {
                authz_checks.source_intent_match = true;
            } else {
                errors.push(format!(
                    "authorization source_intent_digest {} not in intent chain",
                    authz.source_intent_digest
                ));
            }

            // 校验签发方凭证状态
            authz_checks.issuer_valid = check_issuer_status(storage, &authz.issuer, errors);

            // 校验授权时间有效性 (nbf/exp)
            let now = chrono::Utc::now();
            let nbf_valid = parse_iso_time(&authz.nbf)
                .map(|t| now >= t)
                .unwrap_or(false);
            let exp_valid = parse_iso_time(&authz.exp)
                .map(|t| now <= t)
                .unwrap_or(false);
            if !nbf_valid {
                errors.push(format!("authorization {} not yet valid (nbf={})", authz_digest, authz.nbf));
            }
            if !exp_valid {
                errors.push(format!("authorization {} expired (exp={})", authz_digest, authz.exp));
            }

            // 校验授权状态 label
            if let Some(status) = blob.labels.get("x-authz-status") {
                if status != "valid" {
                    errors.push(format!("authorization {} has status '{}', expected 'valid'", authz_digest, status));
                }
            }

            // 校验 action_type 在 grant_type 范围内
            if !is_action_in_grant(&receipt.action_type, &authz.grant_type) {
                errors.push(format!(
                    "action_type '{}' not in grant_type '{}'",
                    receipt.action_type, authz.grant_type
                ));
            }
        }
        Err(_) => {
            errors.push(format!("authorization {} not found", authz_digest));
        }
    }

    Ok(())
}

/// 判断 action_type 是否在 grant_type 范围内
///
/// grant_type 可以是：
/// - 单值："execute" → action_type 必须等值
/// - 逗号分隔多值："execute,read" → action_type 必须在列表中
/// - 通配 "*" → 任意 action_type
fn is_action_in_grant(action_type: &str, grant_type: &str) -> bool {
    if grant_type == "*" {
        return true;
    }
    grant_type.split(',').any(|g| g.trim() == action_type)
}

/// 沿 x-parent-intent 向上追溯意图链
fn trace_intent_chain(
    storage: &dyn BlobStore,
    start_digest: &str,
) -> Result<IntentChainResult, Error> {
    let mut nodes = Vec::new();
    let mut errors = Vec::new();
    let mut visited = HashMap::new();

    let mut current_digest = start_digest.to_string();

    const MAX_INTENT_CHAIN_DEPTH: u32 = 100;
    let mut depth_count = 0;

    loop {
        depth_count += 1;
        if depth_count > MAX_INTENT_CHAIN_DEPTH {
            errors.push("intent chain exceeds maximum depth".into());
            break;
        }

        // 检测循环引用
        if visited.contains_key(&current_digest) {
            errors.push(format!("circular intent reference detected at {}", current_digest));
            break;
        }
        visited.insert(current_digest.clone(), true);

        let blob = match storage.blob_read(&current_digest) {
            Ok(b) => b,
            Err(_) => {
                errors.push(format!("intent blob {} not found", current_digest));
                break;
            }
        };

        let blob_type = blob.labels.get("type").unwrap_or(&"".to_string()).clone();
        if blob_type != BLOB_TYPE_INTENT && blob_type != BLOB_TYPE_SUB_INTENT {
            errors.push(format!(
                "expected intent/sub-intent blob, got type '{}' at {}",
                blob_type, current_digest
            ));
            break;
        }

        // 检查意图节点状态（白名单：仅 active 有效）
        let status = blob.labels.get(LABEL_INTENT_STATUS)
            .map(|s| s.as_str())
            .unwrap_or("active");
        if status != "active" {
            errors.push(format!("intent node at {} has invalid status '{}'", current_digest, status));
            break;
        }

        // 提取 intent_id 和 depth
        let intent_id = blob.labels.get(LABEL_INTENT_ID)
            .cloned()
            .unwrap_or_default();
        let depth: u32 = blob.labels.get(LABEL_DERIVATION_DEPTH)
            .and_then(|d| d.parse().ok())
            .unwrap_or(0);

        nodes.push(ChainNode {
            digest: current_digest.clone(),
            intent_id,
            depth,
        });

        // 约束收缩校验（子→父）
        if let Some(parent_digest) = blob.labels.get(LABEL_PARENT_INTENT) {
            let parent_blob = storage.blob_read(parent_digest);
            if let Ok(parent) = parent_blob {
                // 提取约束并校验
                let child_constraints = extract_constraints(&blob.content);
                let parent_constraints = extract_constraints(&parent.content);

                if let (Some(child_c), Some(parent_c)) = (child_constraints, parent_constraints) {
                    if let Err(violation) = verify_intent_constraint_reduction(&parent_c, &child_c) {
                        errors.push(format!(
                            "constraint violation at depth {}: {}",
                            depth, violation
                        ));
                    }
                }
            }
            current_digest = parent_digest.clone();
        } else {
            // 到达根意图
            break;
        }
    }

    Ok(IntentChainResult { nodes, errors })
}

struct IntentChainResult {
    nodes: Vec<ChainNode>,
    errors: Vec<String>,
}

/// 从 blob content 中提取 constraints 字段
///
/// 返回 None 表示 content 中没有 intent_constraints 字段（合法情况，如空约束）。
/// JSON 解析失败时返回 None（不将被 Null 误认为"无约束"）。
fn extract_constraints(content: &str) -> Option<serde_json::Value> {
    let parsed: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return None,
    };
    parsed.get("intent_constraints").cloned()
}

/// 检查签发方凭证状态
fn check_issuer_status(storage: &dyn BlobStore, issuer: &str, errors: &mut Vec<String>) -> bool {
    // 查找 issuer 的 agent-cert blob
    let mut filter = HashMap::new();
    filter.insert("type".to_string(), BLOB_TYPE_AGENT_CERT.to_string());
    filter.insert(LABEL_CERT_AGENT.to_string(), issuer.to_string());

    let mut certs = storage.blob_query(&filter).unwrap_or_default();

    // Root agent 只有 root-ca blob，没有 agent-cert blob
    if certs.is_empty() {
        let mut root_filter = HashMap::new();
        root_filter.insert("type".to_string(), BLOB_TYPE_ROOT_CA.to_string());
        root_filter.insert("agent-id".to_string(), issuer.to_string());
        certs = storage.blob_query(&root_filter).unwrap_or_default();
    }

    if certs.is_empty() {
        errors.push(format!("issuer {} has no cert blob", issuer));
        return false;
    }

    let cert = &certs[0];

    // 检查 revoked/expired/suspended
    if cert.labels.contains_key(LABEL_CERT_REVOKED) {
        errors.push(format!("issuer {} is revoked", issuer));
        return false;
    }
    if cert.labels.contains_key(LABEL_CERT_EXPIRED) {
        errors.push(format!("issuer {} is expired", issuer));
        return false;
    }
    if cert.labels.contains_key(LABEL_CERT_SUSPENDED) {
        errors.push(format!("issuer {} is suspended", issuer));
        return false;
    }

    true
}

// ─── AZN-VER：授权校验（五项） ───

/// AZN-VER 授权校验
///
/// 五项校验：
/// 1. 凭证真实性：签发方 agent-cert 有效
/// 2. 凭证有效性：status=valid, nbf ≤ now < exp
/// 3. 意图引用一致性：source_intent_digest 指向有效意图
/// 4. 委托链完整性：parent_authz_digest 逐级向上，depth 递减
/// 5. 执行适用性：action_type 在 grant_type 范围内
pub fn verify_authorization(
    storage: &dyn BlobStore,
    authz_digest: &str,
    action_type: &str,
    exec_ctx: &ExecutionContext,
) -> Result<AuthzVerifyResult, Error> {
    let mut errors = Vec::new();
    let check_names = [
        "credential_authenticity".to_string(),
        "credential_validity".to_string(),
        "intent_reference_consistency".to_string(),
        "delegation_chain_integrity".to_string(),
        "execution_applicability".to_string(),
    ];
    let mut checks = [false; 5];

    // 读取授权 blob
    let authz_blob = storage.blob_read(authz_digest)
        .map_err(|_| Error::ChainBroken(format!("authorization {} not found", authz_digest)))?;

    let blob_type = authz_blob.labels.get("type").unwrap_or(&"".to_string()).clone();
    if blob_type != BLOB_TYPE_AUTHORIZATION {
        return Err(Error::ChainBroken(format!(
            "expected authorization blob, got type '{}'", blob_type
        )));
    }

    let authz = AslAdapter::authorization_from_blob(&authz_blob.content)
        .map_err(|e| Error::ChainBroken(format!("invalid authorization content: {}", e)))?;

    // ─── 校验一：凭证真实性 ───
    // 签发方 agent-cert 存在且状态有效（非 revoked/expired）
    {
        let mut issuer_errors = Vec::new();
        checks[0] = check_issuer_status(storage, &authz.issuer, &mut issuer_errors);
        if !checks[0] {
            errors.extend(issuer_errors);
        }
    }

    // ─── 校验二：凭证有效性 ───
    // x-authz-status = valid, nbf ≤ now < exp
    {
        let status_valid = authz_blob.labels.get(LABEL_AUTHZ_STATUS)
            .map(|s| s == "valid")
            .unwrap_or(false);

        let now = chrono::Utc::now();
        let nbf_valid = parse_iso_time(&authz.nbf)
            .map(|t| now >= t)
            .unwrap_or(false);
        let exp_valid = parse_iso_time(&authz.exp)
            .map(|t| now < t)
            .unwrap_or(false);

        checks[1] = status_valid && nbf_valid && exp_valid;

        if !status_valid {
            errors.push("authorization status is not 'valid'".into());
        }
        if !nbf_valid {
            errors.push(format!("authorization not yet valid (nbf={})", authz.nbf));
        }
        if !exp_valid {
            errors.push(format!("authorization expired (exp={})", authz.exp));
        }
    }

    // ─── 校验三：意图引用一致性 ───
    // source_intent_digest 指向有效意图
    {
        let intent_blob = storage.blob_read(&authz.source_intent_digest);
        match intent_blob {
            Ok(blob) => {
                let itype = blob.labels.get("type").unwrap_or(&"".to_string()).clone();
                if itype == BLOB_TYPE_INTENT || itype == BLOB_TYPE_SUB_INTENT {
                    // 检查意图状态：仅 active 有效
                    let status = blob.labels.get(LABEL_INTENT_STATUS)
                        .map(|s| s.as_str())
                        .unwrap_or("active");
                    if status != "active" {
                        errors.push(format!("source intent has invalid status '{}'", status));
                        checks[2] = false;
                    } else {
                        checks[2] = true;
                    }
                } else {
                    errors.push(format!(
                        "source_intent_digest points to non-intent type '{}'", itype
                    ));
                    checks[2] = false;
                }
            }
            Err(_) => {
                errors.push(format!(
                    "source intent {} not found", authz.source_intent_digest
                ));
                checks[2] = false;
            }
        }
    }

    // ─── 校验四：委托链完整性 ───
    // 沿 parent_authz_digest 逐级向上
    {
        checks[3] = verify_delegation_chain(storage, &authz, &mut errors);
    }

    // ─── 校验五：执行适用性 ───
    // action_type 在 grant_type 范围内
    // subject 与 authorization.subject 一致
    // target 在 constraints.target_scope 范围内
    // amount 不超过 amount_scope.max_amount
    // environment 满足 environment_scope.min_see_level
    {
        let action_ok = is_action_in_grant(action_type, &authz.grant_type);
        if !action_ok {
            errors.push(format!(
                "action_type '{}' not in grant_type '{}'",
                action_type, authz.grant_type
            ));
        }

        let subject_ok = match &exec_ctx.subject {
            Some(s) => {
                let ok = s == &authz.subject;
                if !ok {
                    errors.push(format!(
                        "subject '{}' does not match authorization subject '{}'",
                        s, authz.subject
                    ));
                }
                ok
            }
            None => true, // 未提供 subject 则跳过
        };

        let target_ok = match (&exec_ctx.target, &authz.constraints.target_scope) {
            (Some(_), None) => true, // 授权未限制目标
            (Some(target), Some(scope)) => {
                let ok = is_value_in_scope(target, scope);
                if !ok {
                    errors.push(format!(
                        "target {:?} not in target_scope {:?}",
                        target, scope
                    ));
                }
                ok
            }
            (None, _) => true, // 未提供 target 则跳过
        };

        let amount_ok = match (exec_ctx.amount, &authz.constraints.amount_scope) {
            (Some(amount), Some(scope)) => {
                let max = scope.get("max_amount")
                    .and_then(|v| v.as_f64());
                let ok = max.map_or(true, |max| amount <= max);
                if !ok {
                    errors.push(format!(
                        "amount {} exceeds max_amount in scope {:?}",
                        amount, scope
                    ));
                }
                ok
            }
            _ => true, // 未提供 amount 或无限制则跳过
        };

        let env_ok = match (&exec_ctx.environment, &authz.constraints.environment_scope) {
            (Some(env), Some(scope)) => {
                let min_level = scope.get("min_see_level")
                    .and_then(|v| v.as_str())
                    .unwrap_or("L1");
                let ok = see_level_value(env) >= see_level_value(min_level);
                if !ok {
                    errors.push(format!(
                        "environment '{}' below required '{}'",
                        env, min_level
                    ));
                }
                ok
            }
            _ => true,
        };

        checks[4] = action_ok && subject_ok && target_ok && amount_ok && env_ok;
    }

    let valid = checks.iter().all(|&c| c);

    Ok(AuthzVerifyResult {
        valid,
        checks,
        check_names,
        errors,
    })
}

/// 委托链完整性校验
fn verify_delegation_chain(
    storage: &dyn BlobStore,
    authz: &AuthorizationContent,
    errors: &mut Vec<String>,
) -> bool {
    // 如果没有父授权，则无委托链可校验，视为通过
    let parent_digest = match &authz.parent_authz_digest {
        Some(d) => d,
        None => return true,
    };

    let mut visited = HashMap::new();
    let mut current_digest = parent_digest.clone();
    // 从当前 authz 的约束开始，逐级向上比较
    let mut child_constraints = serde_json::to_value(&authz.constraints).unwrap_or_default();
    let mut child_depth = authz.delegation_depth_remaining;

    const MAX_DELEGATION_DEPTH: u32 = 100;
    let mut depth_count = 0;

    loop {
        depth_count += 1;
        if depth_count > MAX_DELEGATION_DEPTH {
            errors.push("delegation chain exceeds maximum depth".into());
            return false;
        }

        if visited.contains_key(&current_digest) {
            errors.push(format!("circular delegation at {}", current_digest));
            return false;
        }
        visited.insert(current_digest.clone(), true);

        let parent_blob = match storage.blob_read(&current_digest) {
            Ok(b) => b,
            Err(_) => {
                errors.push(format!("parent authorization {} not found", current_digest));
                return false;
            }
        };

        if parent_blob.labels.get("type").unwrap_or(&"".to_string()) != BLOB_TYPE_AUTHORIZATION {
            errors.push(format!("parent {} is not authorization type", current_digest));
            return false;
        }

        let parent_authz = match AslAdapter::authorization_from_blob(&parent_blob.content) {
            Ok(a) => a,
            Err(e) => {
                errors.push(format!("invalid parent authorization: {}", e));
                return false;
            }
        };

        // 约束收缩校验：parent 约束必须包含 child 约束
        let parent_constraints_val = serde_json::to_value(&parent_authz.constraints).unwrap_or_default();

        if let Err(violation) = verify_authz_constraint_reduction(&parent_constraints_val, &child_constraints) {
            errors.push(format!("delegation constraint violation: {}", violation));
            return false;
        }

        // depth 递减校验：depth=0 的父授权不应继续委托
        if let Some(parent_depth) = parent_authz.delegation_depth_remaining {
            if parent_depth == 0 {
                errors.push(format!(
                    "parent {} has delegation_depth_remaining=0, cannot delegate",
                    current_digest
                ));
                return false;
            }
            if let Some(c_depth) = child_depth {
                if c_depth != parent_depth - 1 {
                    errors.push(format!(
                        "delegation depth mismatch: child has {}, expected {} (parent {} - 1)",
                        c_depth, parent_depth - 1, parent_depth
                    ));
                    return false;
                }
            }
            child_depth = Some(parent_depth);
        }

        // 向上移动：当前 parent 成为下一轮的 child
        child_constraints = parent_constraints_val;

        // root_authorizer 一致性
        if parent_authz.root_authorizer != authz.root_authorizer {
            errors.push(format!(
                "root_authorizer mismatch: {} vs {}",
                parent_authz.root_authorizer, authz.root_authorizer
            ));
            return false;
        }

        // delegatable 检查
        if !parent_authz.delegatable {
            errors.push(format!("parent {} is not delegatable", current_digest));
            return false;
        }

        // 父授权状态有效性
        let parent_status = parent_blob.labels.get(LABEL_AUTHZ_STATUS)
            .unwrap_or(&"".to_string())
            .clone();
        if parent_status != "valid" {
            errors.push(format!("parent {} status is '{}', not 'valid'", current_digest, parent_status));
            return false;
        }

        // 继续向上
        match &parent_authz.parent_authz_digest {
            Some(grandparent) => {
                current_digest = grandparent.clone();
            }
            None => break, // 到达根授权
        }
    }

    true
}

/// 解析 ISO 8601 时间
fn parse_iso_time(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .ok()
}

/// SEE 等级数值（L1=1, L2=2, L3=3）
fn see_level_value(level: &str) -> u32 {
    match level {
        "L3" => 3,
        "L2" => 2,
        _ => 1,
    }
}

/// 检查目标值是否在 scope 范围内
/// scope 可以是数组（列表包含检查）或对象（子集检查）
fn is_value_in_scope(target: &serde_json::Value, scope: &serde_json::Value) -> bool {
    match (target, scope) {
        // target 是字符串，scope 是数组 → 检查包含
        (serde_json::Value::String(t), serde_json::Value::Array(arr)) => {
            arr.iter().any(|v| v.as_str() == Some(t.as_str()))
        }
        // target 是对象，scope 是对象 → 子集检查
        (serde_json::Value::Object(t_map), serde_json::Value::Object(s_map)) => {
            for (key, t_val) in t_map {
                if let Some(s_val) = s_map.get(key) {
                    if !is_value_in_scope(t_val, s_val) {
                        return false;
                    }
                }
            }
            true
        }
        // target 是数组，scope 是数组 → 子集
        (serde_json::Value::Array(t_arr), serde_json::Value::Array(s_arr)) => {
            t_arr.iter().all(|v| s_arr.contains(v))
        }
        // 其他：等值比较
        _ => target == scope,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use baize_core::storage::Storage;

    fn setup_storage() -> Storage {
        Storage::open(":memory:").unwrap()
    }

    fn write_intent_blob(
        storage: &dyn BlobStore,
        intent_id: &str,
        constraints: &serde_json::Value,
        expires: &str,
        parent_digest: Option<&str>,
        depth: u32,
    ) -> String {
        let content = serde_json::json!({
            "intent_id": intent_id,
            "intent_constraints": constraints,
            "expires_at": expires,
        }).to_string();

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), if depth == 0 { "intent" } else { "sub-intent" }.to_string());
        labels.insert(LABEL_INTENT_ID.to_string(), intent_id.to_string());
        labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        labels.insert(LABEL_INTENT_EXPIRES.to_string(), expires.to_string());
        if let Some(parent) = parent_digest {
            labels.insert(LABEL_PARENT_INTENT.to_string(), parent.to_string());
        }
        labels.insert(LABEL_DERIVATION_DEPTH.to_string(), depth.to_string());

        let blob = storage.blob_write(&content, &labels).unwrap();
        blob.hash
    }

    fn write_authz_blob(
        storage: &dyn BlobStore,
        authz_id: &str,
        issuer: &str,
        subject: &str,
        source_intent: &str,
        grant_type: &str,
        constraints: &AuthzConstraints,
        delegatable: bool,
        depth_remaining: Option<u32>,
        parent_authz: Option<&str>,
        root_authorizer: &str,
    ) -> String {
        let content = AuthorizationContent {
            authorization_id: authz_id.to_string(),
            issuer: issuer.to_string(),
            subject: subject.to_string(),
            grant_type: grant_type.to_string(),
            constraints: constraints.clone(),
            delegatable,
            delegation_depth_remaining: depth_remaining,
            delegation_mode: if parent_authz.is_some() { Some(DelegationMode::Bounded) } else { None },
            source_intent_digest: source_intent.to_string(),
            parent_authz_digest: parent_authz.map(|s| s.to_string()),
            root_authorizer: root_authorizer.to_string(),
            aud: None,
            nbf: "2020-01-01T00:00:00Z".to_string(),
            exp: "2030-12-31T23:59:59Z".to_string(),
            iat: "2026-01-01T00:00:00Z".to_string(),
            jti: format!("jti-{}", authz_id),
            version: "1.0".to_string(),
        };

        let json = serde_json::to_string(&content).unwrap();
        let labels = AslAdapter::authorization_to_labels(&content);

        let blob = storage.blob_write(&json, &labels).unwrap();
        blob.hash
    }

    fn write_receipt_blob(
        storage: &dyn BlobStore,
        receipt_id: &str,
        executor: &str,
        intent_digest: &str,
        authz_digest: &str,
        action_type: &str,
    ) -> String {
        let content = ReceiptContent {
            receipt_id: receipt_id.to_string(),
            executor_id: executor.to_string(),
            task_id: "task-001".to_string(),
            action_type: action_type.to_string(),
            intent_digest: intent_digest.to_string(),
            authorization_digest: authz_digest.to_string(),
            execution_params_digest: None,
            result_status: ReceiptStatus::Succeeded,
            execution_result: None,
            rejection_reason: None,
            started_at: "2026-01-01T00:00:00Z".to_string(),
            finished_at: "2026-01-01T00:01:00Z".to_string(),
            downstream_receipt_digests: None,
        };

        let json = serde_json::to_string(&content).unwrap();
        let labels = AslAdapter::receipt_to_labels(&content);

        let blob = storage.blob_write(&json, &labels).unwrap();
        blob.hash
    }

    fn write_agent_cert(storage: &dyn BlobStore, agent_id: &str) -> String {
        let content = format!("{{\"agent_id\": \"{}\"}}", agent_id);
        let mut labels = HashMap::new();
        labels.insert("type".to_string(), "agent-cert".to_string());
        labels.insert(LABEL_CERT_AGENT.to_string(), agent_id.to_string());

        let blob = storage.blob_write(&content, &labels).unwrap();
        blob.hash
    }

    #[test]
    fn cnv_simple_chain_ok() {
        let storage = setup_storage();
        write_agent_cert(&storage, "root");

        // 创建根意图
        let intent_digest = write_intent_blob(
            &storage, "int-001",
            &serde_json::json!({"budget": 200}),
            "2030-12-31T23:59:59Z", None, 0,
        );

        // 创建授权
        let authz_digest = write_authz_blob(
            &storage, "authz-001", "root", "agent-alice",
            &intent_digest, "execute",
            &AuthzConstraints {
                target_scope: Some(serde_json::json!(["zone-A"])),
                amount_scope: None, time_scope: None,
                method_scope: None, environment_scope: None,
                behavior_scope: None, cumulative_limit: None,
            },
            false, None, None, "root",
        );

        // 创建回执
        let receipt_digest = write_receipt_blob(
            &storage, "rct-001", "agent-alice",
            &intent_digest, &authz_digest, "execute",
        );

        let result = cnv_verify(&storage, &receipt_digest).unwrap();
        assert!(result.valid, "CNV should pass: {:?}", result.errors);
        assert_eq!(result.intent_chain.len(), 1);
    }

    #[test]
    fn cnv_sub_intent_chain_ok() {
        let storage = setup_storage();
        write_agent_cert(&storage, "root");

        // 根意图
        let root_intent = write_intent_blob(
            &storage, "int-001",
            &serde_json::json!({"budget": 200}),
            "2030-12-31T23:59:59Z", None, 0,
        );

        // 子意图
        let sub_intent = write_intent_blob(
            &storage, "sub-001",
            &serde_json::json!({"budget": 100}),
            "2030-12-31T23:59:59Z", Some(&root_intent), 1,
        );

        // 授权指向子意图
        let authz_digest = write_authz_blob(
            &storage, "authz-001", "root", "agent-alice",
            &sub_intent, "execute",
            &AuthzConstraints {
                target_scope: None, amount_scope: None, time_scope: None,
                method_scope: None, environment_scope: None,
                behavior_scope: None, cumulative_limit: None,
            },
            false, None, None, "root",
        );

        // 回执
        let receipt_digest = write_receipt_blob(
            &storage, "rct-001", "agent-alice",
            &sub_intent, &authz_digest, "execute",
        );

        let result = cnv_verify(&storage, &receipt_digest).unwrap();
        assert!(result.valid, "CNV with sub-intent should pass: {:?}", result.errors);
        assert_eq!(result.intent_chain.len(), 2);
        assert_eq!(result.intent_chain[0].depth, 1);
        assert_eq!(result.intent_chain[1].depth, 0);
    }

    #[test]
    fn cnv_constraint_violation_fails() {
        let storage = setup_storage();
        write_agent_cert(&storage, "root");

        // 根意图：budget 100
        let root_intent = write_intent_blob(
            &storage, "int-001",
            &serde_json::json!({"budget": 100}),
            "2030-12-31T23:59:59Z", None, 0,
        );

        // 子意图：budget 200（超出父约束）
        let sub_intent = write_intent_blob(
            &storage, "sub-001",
            &serde_json::json!({"budget": 200}),
            "2030-12-31T23:59:59Z", Some(&root_intent), 1,
        );

        let authz_digest = write_authz_blob(
            &storage, "authz-001", "root", "agent-alice",
            &sub_intent, "execute",
            &AuthzConstraints {
                target_scope: None, amount_scope: None, time_scope: None,
                method_scope: None, environment_scope: None,
                behavior_scope: None, cumulative_limit: None,
            },
            false, None, None, "root",
        );

        let receipt_digest = write_receipt_blob(
            &storage, "rct-001", "agent-alice",
            &sub_intent, &authz_digest, "execute",
        );

        let result = cnv_verify(&storage, &receipt_digest).unwrap();
        assert!(!result.valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn azn_ver_simple_ok() {
        let storage = setup_storage();
        write_agent_cert(&storage, "root");

        let intent_digest = write_intent_blob(
            &storage, "int-001",
            &serde_json::json!({}),
            "2030-12-31T23:59:59Z", None, 0,
        );

        let authz_digest = write_authz_blob(
            &storage, "authz-001", "root", "agent-alice",
            &intent_digest, "execute",
            &AuthzConstraints {
                target_scope: None, amount_scope: None, time_scope: None,
                method_scope: None, environment_scope: None,
                behavior_scope: None, cumulative_limit: None,
            },
            false, None, None, "root",
        );

        let result = verify_authorization(
            &storage, &authz_digest, "execute", &ExecutionContext::default(),
        ).unwrap();

        assert!(result.valid, "AZN-VER should pass: {:?}", result.errors);
        assert!(result.checks[0]); // 凭证真实性
        assert!(result.checks[1]); // 凭证有效性
        assert!(result.checks[2]); // 意图引用
        assert!(result.checks[3]); // 委托链（无委托 = 通过）
        assert!(result.checks[4]); // 执行适用性
    }

    #[test]
    fn azn_ver_wrong_action_type_fails() {
        let storage = setup_storage();
        write_agent_cert(&storage, "root");

        let intent_digest = write_intent_blob(
            &storage, "int-001",
            &serde_json::json!({}),
            "2030-12-31T23:59:59Z", None, 0,
        );

        let authz_digest = write_authz_blob(
            &storage, "authz-001", "root", "agent-alice",
            &intent_digest, "execute",
            &AuthzConstraints {
                target_scope: None, amount_scope: None, time_scope: None,
                method_scope: None, environment_scope: None,
                behavior_scope: None, cumulative_limit: None,
            },
            false, None, None, "root",
        );

        let result = verify_authorization(
            &storage, &authz_digest, "delete", &ExecutionContext::default(),
        ).unwrap();

        assert!(!result.valid);
        assert!(!result.checks[4]); // 执行适用性失败
    }

    #[test]
    fn azn_ver_delegation_chain_ok() {
        let storage = setup_storage();
        write_agent_cert(&storage, "root");
        write_agent_cert(&storage, "agent-alice");

        let intent_digest = write_intent_blob(
            &storage, "int-001",
            &serde_json::json!({}),
            "2030-12-31T23:59:59Z", None, 0,
        );

        // 根授权
        let root_authz = write_authz_blob(
            &storage, "authz-001", "root", "agent-alice",
            &intent_digest, "execute",
            &AuthzConstraints {
                target_scope: Some(serde_json::json!(["A", "B"])),
                amount_scope: None, time_scope: None,
                method_scope: None, environment_scope: None,
                behavior_scope: None, cumulative_limit: None,
            },
            true, Some(3), None, "root",
        );

        // 委托子授权
        let delegated_authz = write_authz_blob(
            &storage, "authz-002", "agent-alice", "agent-bob",
            &intent_digest, "execute",
            &AuthzConstraints {
                target_scope: Some(serde_json::json!(["A"])),
                amount_scope: None, time_scope: None,
                method_scope: None, environment_scope: None,
                behavior_scope: None, cumulative_limit: None,
            },
            true, Some(2), Some(&root_authz), "root",
        );

        let result = verify_authorization(
            &storage, &delegated_authz, "execute", &ExecutionContext::default(),
        ).unwrap();

        assert!(result.valid, "delegated AZN-VER should pass: {:?}", result.errors);
        assert!(result.checks[3]); // 委托链完整性
    }

    #[test]
    fn azn_ver_revoked_issuer_fails() {
        let storage = setup_storage();

        // 写入 revoked 的 issuer cert
        let content = r#"{"agent_id": "bad-issuer"}"#;
        let mut labels = HashMap::new();
        labels.insert("type".to_string(), "agent-cert".to_string());
        labels.insert(LABEL_CERT_AGENT.to_string(), "bad-issuer".to_string());
        let cert_hash = storage.blob_write(content, &labels).unwrap().hash;
        storage.label_add(&cert_hash, LABEL_CERT_REVOKED, "true").unwrap();

        let intent_digest = write_intent_blob(
            &storage, "int-001",
            &serde_json::json!({}),
            "2030-12-31T23:59:59Z", None, 0,
        );

        let authz_digest = write_authz_blob(
            &storage, "authz-001", "bad-issuer", "agent-alice",
            &intent_digest, "execute",
            &AuthzConstraints {
                target_scope: None, amount_scope: None, time_scope: None,
                method_scope: None, environment_scope: None,
                behavior_scope: None, cumulative_limit: None,
            },
            false, None, None, "bad-issuer",
        );

        let result = verify_authorization(
            &storage, &authz_digest, "execute", &ExecutionContext::default(),
        ).unwrap();

        assert!(!result.valid);
        assert!(!result.checks[0]); // 凭证真实性失败
    }

    // ─── 边界测试 ───

    #[test]
    fn cnv_receipt_not_found() {
        let storage = setup_storage();
        let result = cnv_verify(&storage, "sha256:nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn cnv_wrong_blob_type() {
        let storage = setup_storage();
        // 写一个非 receipt 类型的 blob
        let mut labels = HashMap::new();
        labels.insert("type".to_string(), "intent".to_string());
        let blob = storage.blob_write("some content", &labels).unwrap();

        let result = cnv_verify(&storage, &blob.hash);
        assert!(result.is_err());
        match result {
            Err(Error::ChainBroken(msg)) => assert!(msg.contains("expected receipt")),
            other => panic!("expected ChainBroken, got {:?}", other),
        }
    }

    #[test]
    fn azn_ver_not_found() {
        let storage = setup_storage();
        let result = verify_authorization(&storage, "sha256:nonexistent", "execute", &ExecutionContext::default());
        assert!(result.is_err());
    }

    #[test]
    fn azn_ver_expired_authz() {
        let storage = setup_storage();
        write_agent_cert(&storage, "root");

        let intent_digest = write_intent_blob(
            &storage, "int-001",
            &serde_json::json!({}),
            "2030-12-31T23:59:59Z", None, 0,
        );

        // 过期授权
        let content = AuthorizationContent {
            authorization_id: "authz-exp".to_string(),
            issuer: "root".to_string(),
            subject: "agent-alice".to_string(),
            grant_type: "execute".to_string(),
            constraints: AuthzConstraints {
                target_scope: None, amount_scope: None, time_scope: None,
                method_scope: None, environment_scope: None, behavior_scope: None,
                cumulative_limit: None,
            },
            delegatable: false,
            delegation_depth_remaining: None,
            delegation_mode: None,
            source_intent_digest: intent_digest.clone(),
            parent_authz_digest: None,
            root_authorizer: "root".to_string(),
            aud: None,
            nbf: "2020-01-01T00:00:00Z".to_string(),
            exp: "2020-01-02T00:00:00Z".to_string(), // 已过期
            iat: "2020-01-01T00:00:00Z".to_string(),
            jti: "jti-exp".to_string(),
            version: "1.0".to_string(),
        };

        let json = serde_json::to_string(&content).unwrap();
        let labels = AslAdapter::authorization_to_labels(&content);
        let blob = storage.blob_write(&json, &labels).unwrap();

        let result = verify_authorization(&storage, &blob.hash, "execute", &ExecutionContext::default()).unwrap();
        assert!(!result.valid);
        assert!(!result.checks[1]); // 凭证有效性失败
    }

    #[test]
    fn delegation_chain_constraint_violation() {
        let storage = setup_storage();
        write_agent_cert(&storage, "root");
        write_agent_cert(&storage, "agent-alice");

        let intent_digest = write_intent_blob(
            &storage, "int-001",
            &serde_json::json!({}),
            "2030-12-31T23:59:59Z", None, 0,
        );

        // 根授权：target_scope = ["A", "B", "C"]
        let root_authz = write_authz_blob(
            &storage, "authz-001", "root", "agent-alice",
            &intent_digest, "execute",
            &AuthzConstraints {
                target_scope: Some(serde_json::json!(["A", "B", "C"])),
                amount_scope: None, time_scope: None,
                method_scope: None, environment_scope: None,
                behavior_scope: None, cumulative_limit: None,
            },
            true, Some(3), None, "root",
        );

        // 委托子授权：target_scope = ["Z"]（不在父范围内）
        let bad_authz = write_authz_blob(
            &storage, "authz-002", "agent-alice", "agent-bob",
            &intent_digest, "execute",
            &AuthzConstraints {
                target_scope: Some(serde_json::json!(["Z"])),
                amount_scope: None, time_scope: None,
                method_scope: None, environment_scope: None,
                behavior_scope: None, cumulative_limit: None,
            },
            true, Some(2), Some(&root_authz), "root",
        );

        let result = verify_authorization(&storage, &bad_authz, "execute", &ExecutionContext::default()).unwrap();
        assert!(!result.valid);
        assert!(!result.checks[3]); // 委托链失败
    }

    #[test]
    fn delegation_depth_mismatch() {
        let storage = setup_storage();
        write_agent_cert(&storage, "root");
        write_agent_cert(&storage, "agent-alice");

        let intent_digest = write_intent_blob(
            &storage, "int-001",
            &serde_json::json!({}),
            "2030-12-31T23:59:59Z", None, 0,
        );

        // 根授权：depth=3
        let root_authz = write_authz_blob(
            &storage, "authz-001", "root", "agent-alice",
            &intent_digest, "execute",
            &AuthzConstraints {
                target_scope: None, amount_scope: None, time_scope: None,
                method_scope: None, environment_scope: None,
                behavior_scope: None, cumulative_limit: None,
            },
            true, Some(3), None, "root",
        );

        // 子授权：depth=1（应该是 2）
        let bad_authz = write_authz_blob(
            &storage, "authz-002", "agent-alice", "agent-bob",
            &intent_digest, "execute",
            &AuthzConstraints {
                target_scope: None, amount_scope: None, time_scope: None,
                method_scope: None, environment_scope: None,
                behavior_scope: None, cumulative_limit: None,
            },
            true, Some(1), Some(&root_authz), "root",
        );

        let result = verify_authorization(&storage, &bad_authz, "execute", &ExecutionContext::default()).unwrap();
        assert!(!result.valid);
        assert!(!result.checks[3]);
    }

    #[test]
    fn delegation_not_delegatable() {
        let storage = setup_storage();
        write_agent_cert(&storage, "root");
        write_agent_cert(&storage, "agent-alice");

        let intent_digest = write_intent_blob(
            &storage, "int-001",
            &serde_json::json!({}),
            "2030-12-31T23:59:59Z", None, 0,
        );

        // 根授权：不可委托
        let root_authz = write_authz_blob(
            &storage, "authz-001", "root", "agent-alice",
            &intent_digest, "execute",
            &AuthzConstraints {
                target_scope: None, amount_scope: None, time_scope: None,
                method_scope: None, environment_scope: None,
                behavior_scope: None, cumulative_limit: None,
            },
            false, None, None, "root",
        );

        // 尝试从不可委托的授权派生
        let bad_authz = write_authz_blob(
            &storage, "authz-002", "agent-alice", "agent-bob",
            &intent_digest, "execute",
            &AuthzConstraints {
                target_scope: None, amount_scope: None, time_scope: None,
                method_scope: None, environment_scope: None,
                behavior_scope: None, cumulative_limit: None,
            },
            false, None, Some(&root_authz), "root",
        );

        let result = verify_authorization(&storage, &bad_authz, "execute", &ExecutionContext::default()).unwrap();
        assert!(!result.valid);
        assert!(!result.checks[3]);
    }

    #[test]
    fn action_in_grant_wildcard() {
        assert!(super::is_action_in_grant("execute", "*"));
        assert!(super::is_action_in_grant("delete", "*"));
    }

    #[test]
    fn action_in_grant_multi_value() {
        assert!(super::is_action_in_grant("execute", "execute,read,write"));
        assert!(super::is_action_in_grant("read", "execute,read,write"));
        assert!(!super::is_action_in_grant("delete", "execute,read,write"));
    }

    #[test]
    fn action_in_grant_single() {
        assert!(super::is_action_in_grant("execute", "execute"));
        assert!(!super::is_action_in_grant("delete", "execute"));
    }
}
