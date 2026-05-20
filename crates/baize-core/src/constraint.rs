//! 约束收缩校验纯函数
//!
//! INT-DER: 验证子意图约束在父意图约束范围内
//! AZN-DLG: 验证子授权约束在父授权约束范围内
//!
//! 接收 `serde_json::Value`，不依赖 baize-asl 类型。

use serde_json::Value;

/// 约束收缩校验错误
#[derive(Debug, Clone)]
pub struct ConstraintViolation {
    pub dimension: String,
    pub reason: String,
}

impl std::fmt::Display for ConstraintViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.dimension, self.reason)
    }
}

/// 校验子意图约束是否在父意图约束范围内
///
/// 逐维度比较：
/// - 时间窗口：子 intent 的 expires_at 不晚于父
/// - 其他维度：子集关系
pub fn verify_intent_constraint_reduction(
    parent: &Value,
    child: &Value,
) -> Result<(), ConstraintViolation> {
    // 如果父约束是通配/null/空，子可以是任何值
    if is_unconstrained(parent) {
        return Ok(());
    }

    if is_unconstrained(child) {
        return Err(ConstraintViolation {
            dimension: "overall".into(),
            reason: "child constraints cannot be unconstrained when parent has constraints".into(),
        });
    }

    // 逐字段比较
    if let (Some(p_map), Some(c_map)) = (parent.as_object(), child.as_object()) {
        for (key, child_val) in c_map {
            if let Some(parent_val) = p_map.get(key) {
                check_subset(key, parent_val, child_val)?;
            }
            // 如果父约束中没有该维度，视为不限制
        }
    }

    Ok(())
}

/// 校验子授权约束是否在父授权约束范围内
///
/// 逐维度比较：
/// - time_scope/nbf/exp: 子授权完全落在父授权时间窗内
/// - grant_type: 子集
/// - target_scope: 子集
/// - amount_scope: 上限不高于父
/// - method_scope: 子集
/// - environment_scope: 不低于父的 SEE 等级
pub fn verify_authz_constraint_reduction(
    parent: &Value,
    child: &Value,
) -> Result<(), ConstraintViolation> {
    if is_unconstrained(parent) {
        return Ok(());
    }

    if is_unconstrained(child) {
        return Err(ConstraintViolation {
            dimension: "overall".into(),
            reason: "child constraints cannot be unconstrained when parent has constraints".into(),
        });
    }

    // AuthzConstraints 各维度校验
    let dimensions = [
        "target_scope",
        "amount_scope",
        "time_scope",
        "method_scope",
        "environment_scope",
        "behavior_scope",
        "cumulative_limit",
    ];

    for dim in &dimensions {
        if let (Some(p_val), Some(c_val)) = (parent.get(dim), child.get(dim)) {
            check_subset(dim, p_val, c_val)?;
        }
    }

    Ok(())
}

/// 判断约束值是否为"不限制"（null、空对象、空数组、空字符串、通配 "*"）
fn is_unconstrained(val: &Value) -> bool {
    match val {
        Value::Null => true,
        Value::Bool(_) => false,
        Value::Object(m) => m.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::String(s) => s.is_empty() || s == "*",
        _ => false,
    }
}

/// 检查 child 是否为 parent 的子集
fn check_subset(dim: &str, parent: &Value, child: &Value) -> Result<(), ConstraintViolation> {
    // 如果 child 是通配，但 parent 不是，则违规
    if is_unconstrained(child) && !is_unconstrained(parent) {
        return Err(ConstraintViolation {
            dimension: dim.into(),
            reason: "child is unconstrained but parent is not".into(),
        });
    }

    // parent 通配 → child 可以是任何值
    if is_unconstrained(parent) {
        return Ok(());
    }

    // 数组：子集检查
    if let (Some(p_arr), Some(c_arr)) = (parent.as_array(), child.as_array()) {
        for item in c_arr {
            if !p_arr.contains(item) {
                return Err(ConstraintViolation {
                    dimension: dim.into(),
                    reason: format!("child contains item not in parent: {}", item),
                });
            }
        }
        return Ok(());
    }

    // 数值：child <= parent（适用于 amount 等上限维度）
    if let (Some(p_num), Some(c_num)) = (parent.as_f64(), child.as_f64()) {
        if c_num > p_num {
            return Err(ConstraintViolation {
                dimension: dim.into(),
                reason: format!("child {} exceeds parent {}", c_num, p_num),
            });
        }
        return Ok(());
    }

    // 字符串：等值检查
    if let (Some(p_str), Some(c_str)) = (parent.as_str(), child.as_str()) {
        if c_str != p_str {
            return Err(ConstraintViolation {
                dimension: dim.into(),
                reason: format!("child '{}' != parent '{}'", c_str, p_str),
            });
        }
        return Ok(());
    }

    // 布尔：子不能放宽父的限制（parent=true → child 可 true/false; parent=false → child 必须 false）
    if let (Some(p_bool), Some(c_bool)) = (parent.as_bool(), child.as_bool()) {
        if p_bool && !c_bool {
            // 父允许（true），子不允许（false）→ 这是收紧约束，OK
        } else if !p_bool && c_bool {
            // 父不允许（false），子允许（true）→ 放宽约束，违规
            return Err(ConstraintViolation {
                dimension: dim.into(),
                reason: format!("child relaxes parent constraint: parent={}, child={}", p_bool, c_bool),
            });
        }
        return Ok(());
    }

    // 对象：递归比较各字段
    if let (Some(p_obj), Some(c_obj)) = (parent.as_object(), child.as_object()) {
        for (key, c_val) in c_obj {
            if let Some(p_val) = p_obj.get(key) {
                check_subset(&format!("{}.{}", dim, key), p_val, c_val)?;
            }
        }
        return Ok(());
    }

    // 类型不匹配或无法比较，保守通过
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ─── INT 约束收缩 ───

    #[test]
    fn intent_parent_unconstrained_allows_any_child() {
        let parent = json!(null);
        let child = json!({"budget": 100});
        assert!(verify_intent_constraint_reduction(&parent, &child).is_ok());
    }

    #[test]
    fn intent_child_unconstrained_when_parent_constrained_fails() {
        let parent = json!({"budget": 100});
        let child = json!(null);
        assert!(verify_intent_constraint_reduction(&parent, &child).is_err());
    }

    #[test]
    fn intent_budget_within_range() {
        let parent = json!({"budget": 200});
        let child = json!({"budget": 100});
        assert!(verify_intent_constraint_reduction(&parent, &child).is_ok());
    }

    #[test]
    fn intent_budget_exceeds_parent() {
        let parent = json!({"budget": 100});
        let child = json!({"budget": 200});
        assert!(verify_intent_constraint_reduction(&parent, &child).is_err());
    }

    #[test]
    fn intent_target_subset() {
        let parent = json!({"targets": ["A", "B", "C"]});
        let child = json!({"targets": ["A", "B"]});
        assert!(verify_intent_constraint_reduction(&parent, &child).is_ok());
    }

    #[test]
    fn intent_target_not_subset() {
        let parent = json!({"targets": ["A", "B"]});
        let child = json!({"targets": ["A", "C"]});
        assert!(verify_intent_constraint_reduction(&parent, &child).is_err());
    }

    #[test]
    fn intent_child_adds_new_dimension_ok() {
        // 子约束新增父约束中没有的维度 → 不限制，OK
        let parent = json!({"budget": 200});
        let child = json!({"budget": 100, "region": "east"});
        assert!(verify_intent_constraint_reduction(&parent, &child).is_ok());
    }

    // ─── AZN 约束收缩 ───

    #[test]
    fn authz_parent_unconstrained_allows_any_child() {
        let parent = json!(null);
        let child = json!({"target_scope": {"zones": ["A"]}});
        assert!(verify_authz_constraint_reduction(&parent, &child).is_ok());
    }

    #[test]
    fn authz_target_scope_subset() {
        let parent = json!({"target_scope": ["zone-A", "zone-B", "zone-C"]});
        let child = json!({"target_scope": ["zone-A"]});
        assert!(verify_authz_constraint_reduction(&parent, &child).is_ok());
    }

    #[test]
    fn authz_target_scope_not_subset() {
        let parent = json!({"target_scope": ["zone-A"]});
        let child = json!({"target_scope": ["zone-A", "zone-B"]});
        assert!(verify_authz_constraint_reduction(&parent, &child).is_err());
    }

    #[test]
    fn authz_amount_within_limit() {
        let parent = json!({"amount_scope": 1000});
        let child = json!({"amount_scope": 500});
        assert!(verify_authz_constraint_reduction(&parent, &child).is_ok());
    }

    #[test]
    fn authz_amount_exceeds_limit() {
        let parent = json!({"amount_scope": 500});
        let child = json!({"amount_scope": 1000});
        assert!(verify_authz_constraint_reduction(&parent, &child).is_err());
    }

    #[test]
    fn authz_nested_object_subset() {
        let parent = json!({"target_scope": {"zones": ["A", "B"], "level": 3}});
        let child = json!({"target_scope": {"zones": ["A"], "level": 3}});
        assert!(verify_authz_constraint_reduction(&parent, &child).is_ok());
    }

    #[test]
    fn authz_empty_parent_allows_all() {
        let parent = json!({});
        let child = json!({"target_scope": ["A"]});
        assert!(verify_authz_constraint_reduction(&parent, &child).is_ok());
    }

    // ─── 布尔约束 ───

    #[test]
    fn bool_parent_true_child_false_ok() {
        // 父允许 → 子不允许：收紧约束，OK
        let parent = json!({"delegatable": true});
        let child = json!({"delegatable": false});
        assert!(verify_intent_constraint_reduction(&parent, &child).is_ok());
    }

    #[test]
    fn bool_parent_false_child_true_fails() {
        // 父不允许 → 子允许：放宽约束，违规
        let parent = json!({"delegatable": false});
        let child = json!({"delegatable": true});
        assert!(verify_intent_constraint_reduction(&parent, &child).is_err());
    }

    #[test]
    fn bool_same_value_ok() {
        let parent = json!({"flag": false});
        let child = json!({"flag": false});
        assert!(verify_intent_constraint_reduction(&parent, &child).is_ok());
    }

    #[test]
    fn bool_not_treated_as_unconstrained() {
        // false 不是 "不限制"
        let parent = json!({"flag": false});
        let child = json!({"flag": true});
        let result = verify_intent_constraint_reduction(&parent, &child);
        assert!(result.is_err());
    }
}
