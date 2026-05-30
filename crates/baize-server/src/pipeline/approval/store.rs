//! ApprovalStore trait + BlobApprovalStore 默认实现
//!
//! 审批数据存储为 JSON blob content + 结构化 labels，复用现有 BlobStore。

use std::collections::HashMap;
use std::sync::Arc;

use baize_core::approval::{
    ApprovalAction, ApprovalRequest, ApprovalStatus, PreAuthorization,
};
use baize_core::error::{Error, Result};
use baize_core::labels::*;
use baize_core::storage::BlobStore;

// ─── ApprovalStore trait ───

/// 审批数据存储接口
pub trait ApprovalStore: Send + Sync {
    // ─── 请求 CRUD ───

    fn create_request(&self, req: &ApprovalRequest) -> Result<()>;
    fn get_request(&self, id: &str) -> Result<Option<ApprovalRequest>>;
    fn update_request(&self, req: &ApprovalRequest) -> Result<()>;
    fn list_pending_for(&self, agent_id: &str) -> Result<Vec<ApprovalRequest>>;
    fn list_requests_by_action(&self, action: &ApprovalAction) -> Result<Vec<ApprovalRequest>>;
    /// 查找 agent 的活跃已批准请求（status=Approved + remaining>0），用于 gate 快速匹配
    fn find_active_for(&self, agent_id: &str, action: &ApprovalAction) -> Result<Option<ApprovalRequest>>;
    fn decrement_remaining(&self, id: &str) -> Result<u32>;
    fn expire_requests(&self) -> Result<usize>;

    // ─── 预授权 ───

    fn create_preauth(&self, preauth: &PreAuthorization) -> Result<()>;
    fn find_preauth(&self, grantee_id: &str, action: &ApprovalAction) -> Result<Option<PreAuthorization>>;
    fn list_preauth_for(&self, grantee_id: &str) -> Result<Vec<PreAuthorization>>;
    fn decrement_preauth(&self, id: &str) -> Result<u32>;
    fn delete_preauth(&self, id: &str) -> Result<()>;
}

// ─── BlobApprovalStore ───

/// 基于 BlobStore 的默认审批存储实现
pub struct BlobApprovalStore {
    storage: Arc<dyn BlobStore>,
}

impl BlobApprovalStore {
    pub fn new(storage: Arc<dyn BlobStore>) -> Self {
        Self { storage }
    }

    /// 根据 approval ID label 查找 blob
    fn find_blob_by_approval_id(&self, approval_id: &str) -> Result<Option<baize_core::storage::Blob>> {
        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "approval-request".to_string());
        filter.insert(LABEL_APPROVAL_ID.to_string(), approval_id.to_string());
        let blobs = self.storage.blob_query(&filter)?;
        Ok(blobs.into_iter().next())
    }

    /// 根据 preauth ID label 查找 blob
    fn find_blob_by_preauth_id(&self, preauth_id: &str) -> Result<Option<baize_core::storage::Blob>> {
        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "approval-preauth".to_string());
        filter.insert(LABEL_PREAUTH_ID.to_string(), preauth_id.to_string());
        let blobs = self.storage.blob_query(&filter)?;
        Ok(blobs.into_iter().next())
    }

    /// 序列化请求并写入 blob，返回 blob（用于 update 时 hash 匹配）
    fn write_request_blob(&self, req: &ApprovalRequest) -> Result<baize_core::storage::Blob> {
        let content = serde_json::to_string(req)
            .map_err(|e| Error::Internal(anyhow::anyhow!("serialize approval request: {}", e)))?;
        let labels = labels! {
            "type" => "approval-request",
            LABEL_APPROVAL_ID => &req.id,
            LABEL_APPROVAL_ACTION => &req.action.to_string(),
            LABEL_APPROVAL_REQUESTER => &req.requester_id,
            LABEL_APPROVAL_STATUS => &req.status.to_string(),
            LABEL_APPROVAL_GRANTED => &req.granted_count.to_string(),
            LABEL_APPROVAL_REMAINING => &req.remaining_count.to_string(),
            LABEL_APPROVAL_REQUESTER_LEVEL => &req.requester_level.to_string(),
        };
        let mut lbls = labels;
        if let Some(ref pending_at) = req.pending_at {
            lbls.insert(LABEL_APPROVAL_PENDING_AT.to_string(), pending_at.clone());
        }
        self.storage.blob_write(&content, &lbls)
    }
}

impl ApprovalStore for BlobApprovalStore {
    fn create_request(&self, req: &ApprovalRequest) -> Result<()> {
        self.write_request_blob(req)?;
        Ok(())
    }

    fn get_request(&self, id: &str) -> Result<Option<ApprovalRequest>> {
        let blob = match self.find_blob_by_approval_id(id)? {
            Some(b) => b,
            None => return Ok(None),
        };
        let req: ApprovalRequest = serde_json::from_str(&blob.content)
            .map_err(|e| Error::Internal(anyhow::anyhow!("deserialize approval request: {}", e)))?;
        Ok(Some(req))
    }

    fn update_request(&self, req: &ApprovalRequest) -> Result<()> {
        // 先写新 blob（write-before-delete 避免数据丢失）
        let new_blob = self.write_request_blob(req)?;

        // 查询所有同 id blob，删除非新 blob 的旧 blob
        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "approval-request".to_string());
        filter.insert(LABEL_APPROVAL_ID.to_string(), req.id.to_string());
        let all_blobs = self.storage.blob_query(&filter)?;

        for blob in &all_blobs {
            if blob.hash != new_blob.hash {
                let _ = self.storage.blob_delete(&blob.hash);
            }
        }
        Ok(())
    }

    fn list_pending_for(&self, agent_id: &str) -> Result<Vec<ApprovalRequest>> {
        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "approval-request".to_string());
        filter.insert(LABEL_APPROVAL_PENDING_AT.to_string(), agent_id.to_string());
        filter.insert(LABEL_APPROVAL_STATUS.to_string(), ApprovalStatus::Pending.to_string());
        let blobs = self.storage.blob_query(&filter)?;
        let mut requests = Vec::new();
        for blob in blobs {
            if let Ok(req) = serde_json::from_str::<ApprovalRequest>(&blob.content) {
                requests.push(req);
            }
        }
        Ok(requests)
    }

    fn list_requests_by_action(&self, action: &ApprovalAction) -> Result<Vec<ApprovalRequest>> {
        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "approval-request".to_string());
        filter.insert(LABEL_APPROVAL_ACTION.to_string(), action.to_string());
        let blobs = self.storage.blob_query(&filter)?;
        let mut requests = Vec::new();
        for blob in blobs {
            if let Ok(req) = serde_json::from_str::<ApprovalRequest>(&blob.content) {
                requests.push(req);
            }
        }
        Ok(requests)
    }

    fn find_active_for(&self, agent_id: &str, action: &ApprovalAction) -> Result<Option<ApprovalRequest>> {
        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "approval-request".to_string());
        filter.insert(LABEL_APPROVAL_REQUESTER.to_string(), agent_id.to_string());
        filter.insert(LABEL_APPROVAL_ACTION.to_string(), action.to_string());
        filter.insert(LABEL_APPROVAL_STATUS.to_string(), ApprovalStatus::Approved.to_string());
        let blobs = self.storage.blob_query(&filter)?;
        for blob in blobs {
            if let Ok(req) = serde_json::from_str::<ApprovalRequest>(&blob.content) {
                if req.remaining_count > 0 {
                    return Ok(Some(req));
                }
            }
        }
        Ok(None)
    }

    fn decrement_remaining(&self, id: &str) -> Result<u32> {
        let blob = self.find_blob_by_approval_id(id)?
            .ok_or_else(|| Error::NotFound(format!("approval request {}", id)))?;
        let mut req: ApprovalRequest = serde_json::from_str(&blob.content)
            .map_err(|e| Error::Internal(anyhow::anyhow!("deserialize: {}", e)))?;
        if req.remaining_count == 0 {
            return Err(Error::Validation("no remaining count".into()));
        }
        req.remaining_count -= 1;
        let new_remaining = req.remaining_count;
        if new_remaining == 0 {
            req.status = ApprovalStatus::Executed;
        }

        // 更新 labels 中的 remaining（新 blob 的 labels）
        let mut labels = blob.labels.clone();
        labels.insert(LABEL_APPROVAL_REMAINING.to_string(), new_remaining.to_string());
        if new_remaining == 0 {
            labels.insert(LABEL_APPROVAL_STATUS.to_string(), ApprovalStatus::Executed.to_string());
        }

        // 先写新 blob 再删旧 blob（write-before-delete 避免数据丢失）
        let content = serde_json::to_string(&req)
            .map_err(|e| Error::Internal(anyhow::anyhow!("serialize: {}", e)))?;
        self.storage.blob_write(&content, &labels)?;
        self.storage.blob_delete(&blob.hash)?;
        Ok(new_remaining)
    }

    fn expire_requests(&self) -> Result<usize> {
        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "approval-request".to_string());
        filter.insert(LABEL_APPROVAL_STATUS.to_string(), ApprovalStatus::Pending.to_string());
        let blobs = self.storage.blob_query(&filter)?;
        let now = chrono::Utc::now();
        let mut expired_count = 0;

        for blob in &blobs {
            let req: ApprovalRequest = match serde_json::from_str(&blob.content) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if let Some(ref expires_str) = req.expires_at {
                if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(expires_str) {
                    if now > expires {
                        self.storage.label_set(&blob.hash, LABEL_APPROVAL_STATUS, &ApprovalStatus::Expired.to_string())?;
                        expired_count += 1;
                    }
                }
            }
        }
        Ok(expired_count)
    }

    // ─── 预授权 ───

    fn create_preauth(&self, preauth: &PreAuthorization) -> Result<()> {
        let content = serde_json::to_string(preauth)
            .map_err(|e| Error::Internal(anyhow::anyhow!("serialize preauth: {}", e)))?;
        let labels = labels! {
            "type" => "approval-preauth",
            LABEL_PREAUTH_ID => &preauth.id,
            LABEL_PREAUTH_GRANTER => &preauth.granter_id,
            LABEL_PREAUTH_GRANTEE => &preauth.grantee_id,
            LABEL_PREAUTH_ACTION => &preauth.action.to_string(),
            LABEL_PREAUTH_REMAINING => &preauth.remaining_count.to_string(),
        };
        self.storage.blob_write(&content, &labels)?;
        Ok(())
    }

    fn find_preauth(&self, grantee_id: &str, action: &ApprovalAction) -> Result<Option<PreAuthorization>> {
        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "approval-preauth".to_string());
        filter.insert(LABEL_PREAUTH_GRANTEE.to_string(), grantee_id.to_string());
        filter.insert(LABEL_PREAUTH_ACTION.to_string(), action.to_string());
        let blobs = self.storage.blob_query(&filter)?;

        // 收集所有 remaining > 0 的预授权，优先返回 remaining 最多的
        let mut candidates: Vec<PreAuthorization> = blobs.into_iter()
            .filter_map(|blob| serde_json::from_str::<PreAuthorization>(&blob.content).ok())
            .filter(|pa| pa.remaining_count > 0)
            .collect();
        candidates.sort_by(|a, b| b.remaining_count.cmp(&a.remaining_count));
        Ok(candidates.into_iter().next())
    }

    fn list_preauth_for(&self, grantee_id: &str) -> Result<Vec<PreAuthorization>> {
        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "approval-preauth".to_string());
        filter.insert(LABEL_PREAUTH_GRANTEE.to_string(), grantee_id.to_string());
        let blobs = self.storage.blob_query(&filter)?;
        let mut preauths = Vec::new();
        for blob in blobs {
            if let Ok(pa) = serde_json::from_str::<PreAuthorization>(&blob.content) {
                preauths.push(pa);
            }
        }
        Ok(preauths)
    }

    fn decrement_preauth(&self, id: &str) -> Result<u32> {
        let blob = self.find_blob_by_preauth_id(id)?
            .ok_or_else(|| Error::NotFound(format!("preauth {}", id)))?;
        let mut pa: PreAuthorization = serde_json::from_str(&blob.content)
            .map_err(|e| Error::Internal(anyhow::anyhow!("deserialize preauth: {}", e)))?;
        if pa.remaining_count == 0 {
            return Err(Error::Validation("preauth exhausted".into()));
        }
        pa.remaining_count -= 1;
        let new_remaining = pa.remaining_count;

        // 更新 labels 中的 remaining（新 blob 的 labels）
        let mut labels = blob.labels.clone();
        labels.insert(LABEL_PREAUTH_REMAINING.to_string(), new_remaining.to_string());

        // 先写新 blob 再删旧 blob（write-before-delete）
        let content = serde_json::to_string(&pa)
            .map_err(|e| Error::Internal(anyhow::anyhow!("serialize: {}", e)))?;
        self.storage.blob_write(&content, &labels)?;
        self.storage.blob_delete(&blob.hash)?;
        Ok(new_remaining)
    }

    fn delete_preauth(&self, id: &str) -> Result<()> {
        if let Some(blob) = self.find_blob_by_preauth_id(id)? {
            self.storage.blob_delete(&blob.hash)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use baize_core::approval::ApprovalAction;
    use baize_core::storage::Storage;

    fn setup_store() -> (BlobApprovalStore, Arc<dyn BlobStore>) {
        let storage: Arc<dyn BlobStore> = Arc::new(Storage::open(":memory:").unwrap());
        let store = BlobApprovalStore::new(storage.clone());
        (store, storage)
    }

    fn sample_request(id: &str) -> ApprovalRequest {
        ApprovalRequest {
            id: id.to_string(),
            requester_id: "agent-001".to_string(),
            requester_level: 2,
            action: ApprovalAction::Push,
            operation_payload: "{}".to_string(),
            chain: vec![],
            status: ApprovalStatus::Pending,
            pending_at: Some("parent".to_string()),
            granted_count: 0,
            remaining_count: 0,
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
        }
    }

    #[test]
    fn create_and_get_request() {
        let (store, _) = setup_store();
        let req = sample_request("apr-001");
        store.create_request(&req).unwrap();

        let fetched = store.get_request("apr-001").unwrap().unwrap();
        assert_eq!(fetched.id, "apr-001");
        assert_eq!(fetched.action, ApprovalAction::Push);
        assert_eq!(fetched.status, ApprovalStatus::Pending);
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let (store, _) = setup_store();
        assert!(store.get_request("apr-nope").unwrap().is_none());
    }

    #[test]
    fn update_request() {
        let (store, _) = setup_store();
        let mut req = sample_request("apr-002");
        store.create_request(&req).unwrap();

        req.status = ApprovalStatus::Approved;
        req.granted_count = 5;
        req.remaining_count = 5;
        store.update_request(&req).unwrap();

        let fetched = store.get_request("apr-002").unwrap().unwrap();
        assert_eq!(fetched.status, ApprovalStatus::Approved);
        assert_eq!(fetched.granted_count, 5);
    }

    #[test]
    fn list_pending_for() {
        let (store, _) = setup_store();
        let mut req1 = sample_request("apr-010");
        req1.pending_at = Some("approver-a".to_string());
        store.create_request(&req1).unwrap();

        let mut req2 = sample_request("apr-011");
        req2.pending_at = Some("approver-b".to_string());
        store.create_request(&req2).unwrap();

        let pending_a = store.list_pending_for("approver-a").unwrap();
        assert_eq!(pending_a.len(), 1);
        assert_eq!(pending_a[0].id, "apr-010");

        let pending_b = store.list_pending_for("approver-b").unwrap();
        assert_eq!(pending_b.len(), 1);
    }

    #[test]
    fn decrement_remaining() {
        let (store, _) = setup_store();
        let mut req = sample_request("apr-020");
        req.status = ApprovalStatus::Approved;
        req.granted_count = 3;
        req.remaining_count = 3;
        store.create_request(&req).unwrap();

        let rem = store.decrement_remaining("apr-020").unwrap();
        assert_eq!(rem, 2);
        let rem = store.decrement_remaining("apr-020").unwrap();
        assert_eq!(rem, 1);
        let rem = store.decrement_remaining("apr-020").unwrap();
        assert_eq!(rem, 0);

        // 0 时应标记为 Executed
        let fetched = store.get_request("apr-020").unwrap().unwrap();
        assert_eq!(fetched.status, ApprovalStatus::Executed);

        // 再减应报错
        let result = store.decrement_remaining("apr-020");
        assert!(result.is_err());
    }

    #[test]
    fn create_and_find_preauth() {
        let (store, _) = setup_store();
        let pa = PreAuthorization {
            id: "pre-001".to_string(),
            granter_id: "root".to_string(),
            grantee_id: "agent-001".to_string(),
            action: ApprovalAction::Push,
            granted_count: 5,
            remaining_count: 5,
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        store.create_preauth(&pa).unwrap();

        let found = store.find_preauth("agent-001", &ApprovalAction::Push).unwrap().unwrap();
        assert_eq!(found.id, "pre-001");
        assert_eq!(found.remaining_count, 5);

        // 不匹配的 action
        let not_found = store.find_preauth("agent-001", &ApprovalAction::FileWrite).unwrap();
        assert!(not_found.is_none());

        // 不匹配的 grantee
        let not_found = store.find_preauth("agent-999", &ApprovalAction::Push).unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn decrement_preauth_count() {
        let (store, _) = setup_store();
        let pa = PreAuthorization {
            id: "pre-002".to_string(),
            granter_id: "root".to_string(),
            grantee_id: "agent-001".to_string(),
            action: ApprovalAction::Push,
            granted_count: 2,
            remaining_count: 2,
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        store.create_preauth(&pa).unwrap();

        let rem = store.decrement_preauth("pre-002").unwrap();
        assert_eq!(rem, 1);
        let rem = store.decrement_preauth("pre-002").unwrap();
        assert_eq!(rem, 0);

        // 耗尽后 find_preauth 应不再返回
        let found = store.find_preauth("agent-001", &ApprovalAction::Push).unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn delete_preauth() {
        let (store, _) = setup_store();
        let pa = PreAuthorization {
            id: "pre-003".to_string(),
            granter_id: "root".to_string(),
            grantee_id: "agent-001".to_string(),
            action: ApprovalAction::Push,
            granted_count: 1,
            remaining_count: 1,
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        store.create_preauth(&pa).unwrap();
        store.delete_preauth("pre-003").unwrap();
        assert!(store.find_preauth("agent-001", &ApprovalAction::Push).unwrap().is_none());
    }

    #[test]
    fn expire_requests() {
        let (store, _) = setup_store();
        let mut req = sample_request("apr-exp");
        req.status = ApprovalStatus::Pending;
        req.expires_at = Some("2020-01-01T00:00:00Z".to_string()); // 过去时间
        store.create_request(&req).unwrap();

        let count = store.expire_requests().unwrap();
        assert_eq!(count, 1);

        // 已标记为 Expired
        let mut filter = HashMap::new();
        filter.insert(LABEL_APPROVAL_ID.to_string(), "apr-exp".to_string());
        let blobs = store.storage.blob_query(&filter).unwrap();
        assert_eq!(blobs[0].labels.get(LABEL_APPROVAL_STATUS).unwrap(), "expired");
    }
}
