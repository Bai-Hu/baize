use std::collections::HashMap;

use baize_core::error::Error;
use baize_core::labels::*;

use super::Baize;

// ─── 审计链常量 ───

/// 创世节点的前一条 hash（哨兵值）
const GENESIS_PREV: &str = "genesis";

// ─── 返回类型 ───

/// 审计哈希链验证结果
#[derive(Debug)]
pub struct ChainVerifyResult {
    pub valid: bool,
    pub chain_length: u64,
    pub head_digest: String,
    pub genesis_digest: String,
    pub errors: Vec<String>,
}

// ─── trait ───

/// 审计接口：所有写操作通过此接口留痕
pub trait Auditor {
    /// 写入审计记录（含哈希链串联）
    /// target: 操作对象标识（如 blob hash、agent id、file path），可为空
    fn audit(&self, audit_type: &str, agent_id: &str, result: &str, target: Option<&str>) -> Result<(), Error>;

    /// v1：验证审计哈希链完整性
    fn verify_chain(&self) -> Result<ChainVerifyResult, Error>;
}

impl Auditor for Baize {
    fn audit(&self, audit_type: &str, agent_id: &str, result: &str, target: Option<&str>) -> Result<(), Error> {
        // 1. 获取当前 audit-head（最新审计 blob 的 hash）
        let prev_digest = self.get_audit_head()?;

        // 2. 计算下一个 chain-index
        let next_index = self.get_next_chain_index(&prev_digest)?;

        // 3. 纳秒时间戳（保持与 v0 兼容）
        let seq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        // 4. 构造 labels
        let mut labels = HashMap::from([
            ("type".to_string(), BLOB_TYPE_AUDIT.to_string()),
            ("x-audit".to_string(), "true".to_string()),
            ("x-audit-type".to_string(), audit_type.to_string()),
            ("x-audit-agent".to_string(), agent_id.to_string()),
            ("x-audit-result".to_string(), result.to_string()),
            ("x-audit-time".to_string(), chrono::Utc::now().to_rfc3339()),
            ("x-audit-seq".to_string(), seq.to_string()),
            (LABEL_AUDIT_PREV.to_string(), prev_digest.clone()),
            (LABEL_AUDIT_CHAIN_INDEX.to_string(), next_index.to_string()),
        ]);
        if let Some(t) = target {
            labels.insert("x-audit-target".to_string(), t.to_string());
        }

        // 5. 构造 content
        let mut content = serde_json::json!({
            "type": audit_type,
            "agent": agent_id,
            "result": result,
            "seq": seq,
            "chain_index": next_index,
            "prev": prev_digest,
        });
        if let Some(t) = target {
            content["target"] = serde_json::Value::String(t.to_string());
        }

        // 6. 写入审计 blob
        let _blob = self.storage.blob_write(&content.to_string(), &labels)?;

        Ok(())
    }

    fn verify_chain(&self) -> Result<ChainVerifyResult, Error> {
        let mut errors = Vec::new();

        // 1. 获取 audit-head
        let head_digest = self.get_audit_head()?;

        if head_digest == GENESIS_PREV {
            // 空链（无审计记录）
            return Ok(ChainVerifyResult {
                valid: true,
                chain_length: 0,
                head_digest: String::new(),
                genesis_digest: String::new(),
                errors: Vec::new(),
            });
        }

        // 2. 从 head 沿 x-audit-prev 向前追溯
        let mut current_hash = head_digest.clone();
        let mut chain_length: u64 = 0;
        let mut genesis_digest = String::new();
        let mut prev_index: Option<u64> = None;
        let mut visited = std::collections::HashSet::new();

        loop {
            // 循环检测
            if !visited.insert(current_hash.clone()) {
                errors.push(format!("cycle detected at {}", current_hash));
                break;
            }

            // 读取当前审计 blob
            let blob = match self.storage.blob_read(&current_hash) {
                Ok(b) => b,
                Err(e) => {
                    errors.push(format!("missing audit blob {}: {}", current_hash, e));
                    break;
                }
            };

            // 校验 type
            match blob.labels.get("type") {
                Some(t) if t == BLOB_TYPE_AUDIT => {}
                Some(t) => {
                    errors.push(format!("blob {} has type '{}', expected 'audit'", current_hash, t));
                    break;
                }
                None => {
                    errors.push(format!("blob {} missing type label", current_hash));
                    break;
                }
            }

            // 读取 chain-index
            let index: u64 = match blob.labels.get(LABEL_AUDIT_CHAIN_INDEX) {
                Some(v) => match v.parse() {
                    Ok(i) => i,
                    Err(e) => {
                        errors.push(format!("invalid chain-index at {}: {}", current_hash, e));
                        break;
                    }
                },
                None => {
                    errors.push(format!("missing {} at {}", LABEL_AUDIT_CHAIN_INDEX, current_hash));
                    break;
                }
            };

            // 校验 chain-index 单调递减
            if let Some(prev) = prev_index {
                if index != prev - 1 {
                    errors.push(format!(
                        "chain-index gap: expected {}, got {} at {}",
                        prev - 1, index, current_hash
                    ));
                }
            }

            chain_length += 1;

            // 读取 prev hash
            let prev_hash = match blob.labels.get(LABEL_AUDIT_PREV) {
                Some(v) => v.clone(),
                None => {
                    errors.push(format!("missing {} at {}", LABEL_AUDIT_PREV, current_hash));
                    break;
                }
            };

            // 到达创世节点
            if prev_hash == GENESIS_PREV {
                if index != 0 {
                    errors.push(format!(
                        "genesis prev but chain-index is {}, expected 0",
                        index
                    ));
                }
                genesis_digest = current_hash.clone();
                break;
            }

            // 验证 prev 指向的 blob 确实存在（blob_read 在循环开头处理）

            prev_index = Some(index);
            current_hash = prev_hash;

            // 安全上限
            if chain_length > 1_000_000 {
                errors.push("chain exceeds safety limit (1M)".to_string());
                break;
            }
        }

        let valid = errors.is_empty();

        Ok(ChainVerifyResult {
            valid,
            chain_length,
            head_digest,
            genesis_digest,
            errors,
        })
    }
}

// ─── 内部辅助方法（在 Baize impl 上） ───

impl Baize {
    /// 获取当前链头（最大 chain-index 的审计 blob hash）
    /// 如果没有审计记录，返回 "genesis"
    fn get_audit_head(&self) -> Result<String, Error> {
        let mut filter = HashMap::new();
        filter.insert("x-audit".to_string(), "true".to_string());
        let audits = self.storage.blob_query_metadata(&filter)?;

        if audits.is_empty() {
            return Ok(GENESIS_PREV.to_string());
        }

        // 找到 chain-index 最大的审计 blob
        let mut max_index: Option<u64> = None;
        let mut head_hash = String::new();
        for (hash, labels) in &audits {
            if let Some(idx_str) = labels.get(LABEL_AUDIT_CHAIN_INDEX) {
                if let Ok(idx) = idx_str.parse::<u64>() {
                    if max_index.map_or(true, |m| idx > m) {
                        max_index = Some(idx);
                        head_hash = hash.clone();
                    }
                }
            }
        }

        if head_hash.is_empty() {
            // 无有效 chain-index 的审计记录（v0 遗留），视为空链
            Ok(GENESIS_PREV.to_string())
        } else {
            Ok(head_hash)
        }
    }

    /// 计算下一个 chain-index
    fn get_next_chain_index(&self, prev_digest: &str) -> Result<u64, Error> {
        if prev_digest == GENESIS_PREV {
            return Ok(0);
        }

        let prev_blob = self.storage.blob_read(prev_digest)?;
        match prev_blob.labels.get(LABEL_AUDIT_CHAIN_INDEX) {
            Some(v) => {
                let index: u64 = v.parse()
                    .map_err(|e| Error::Internal(anyhow::anyhow!("invalid chain-index '{}': {}", v, e)))?;
                Ok(index + 1)
            }
            None => Ok(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() -> Baize {
        Baize::init_in_memory().unwrap()
    }

    #[test]
    fn audit_creates_chain_labels() {
        let baize = init();
        baize.audit("test_event", "agent-001", "ok", None).unwrap();

        let mut filter = HashMap::new();
        filter.insert("x-audit".to_string(), "true".to_string());
        let blobs = baize.storage.blob_query(&filter).unwrap();
        assert_eq!(blobs.len(), 1);

        let blob = &blobs[0];
        assert_eq!(blob.labels.get(LABEL_AUDIT_CHAIN_INDEX).unwrap(), "0");
        assert_eq!(blob.labels.get(LABEL_AUDIT_PREV).unwrap(), GENESIS_PREV);
    }

    #[test]
    fn audit_chain_sequential() {
        let baize = init();
        baize.audit("event1", "agent-001", "ok", None).unwrap();
        baize.audit("event2", "agent-001", "ok", None).unwrap();
        baize.audit("event3", "agent-001", "ok", None).unwrap();

        let mut filter = HashMap::new();
        filter.insert("x-audit".to_string(), "true".to_string());
        let blobs = baize.storage.blob_query(&filter).unwrap();
        assert_eq!(blobs.len(), 3);

        // 找到 head（index=2）
        let head = blobs.iter().find(|b| b.labels.get(LABEL_AUDIT_CHAIN_INDEX) == Some(&"2".to_string())).unwrap();
        assert_eq!(head.labels.get("x-audit-type").unwrap(), "event3");

        // 找到 index=0（genesis）
        let genesis = blobs.iter().find(|b| b.labels.get(LABEL_AUDIT_CHAIN_INDEX) == Some(&"0".to_string())).unwrap();
        assert_eq!(genesis.labels.get(LABEL_AUDIT_PREV).unwrap(), GENESIS_PREV);

        // index=1 的 prev 指向 index=0 的 hash
        let mid = blobs.iter().find(|b| b.labels.get(LABEL_AUDIT_CHAIN_INDEX) == Some(&"1".to_string())).unwrap();
        assert_eq!(mid.labels.get(LABEL_AUDIT_PREV).unwrap(), &genesis.hash);

        // index=2 的 prev 指向 index=1 的 hash
        assert_eq!(head.labels.get(LABEL_AUDIT_PREV).unwrap(), &mid.hash);
    }

    #[test]
    fn verify_chain_empty() {
        let baize = init();
        let result = baize.verify_chain().unwrap();
        assert!(result.valid);
        assert_eq!(result.chain_length, 0);
    }

    #[test]
    fn verify_chain_valid() {
        let baize = init();
        baize.audit("event1", "agent-001", "ok", None).unwrap();
        baize.audit("event2", "agent-001", "ok", None).unwrap();
        baize.audit("event3", "agent-001", "ok", None).unwrap();

        let result = baize.verify_chain().unwrap();
        assert!(result.valid);
        assert_eq!(result.chain_length, 3);
        assert!(!result.genesis_digest.is_empty());
    }

    #[test]
    fn verify_chain_single_record() {
        let baize = init();
        baize.audit("solo", "agent-001", "ok", None).unwrap();

        let result = baize.verify_chain().unwrap();
        assert!(result.valid);
        assert_eq!(result.chain_length, 1);
        assert!(!result.genesis_digest.is_empty());
    }

    #[test]
    fn audit_with_target() {
        let baize = init();
        baize.audit("file_write", "agent-001", "success", Some("config/app.yaml")).unwrap();

        let mut filter = HashMap::new();
        filter.insert("x-audit".to_string(), "true".to_string());
        let blobs = baize.storage.blob_query(&filter).unwrap();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].labels.get("x-audit-target").unwrap(), "config/app.yaml");
        assert_eq!(blobs[0].labels.get(LABEL_AUDIT_CHAIN_INDEX).unwrap(), "0");
    }

    #[test]
    fn audit_idempotent_not_swallowed() {
        let baize = init();
        // 两条相同内容的审计，因为 chain labels 不同（prev/index 不同），不会被幂等合并
        baize.audit("blob_write", "cc-writer", "success", None).unwrap();
        baize.audit("blob_write", "cc-writer", "success", None).unwrap();

        let mut filter = HashMap::new();
        filter.insert("x-audit".to_string(), "true".to_string());
        let blobs = baize.storage.blob_query(&filter).unwrap();
        assert_eq!(blobs.len(), 2, "duplicate audit events must not be swallowed");
    }
}
