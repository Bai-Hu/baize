# 白泽 v2 设计：ASL 全量实现

> 版本：v2 安全增强设计
> 对齐标准：IIFAA ASL V1.0（INF / IDN / LNK / INT / AZN）
> 基于 v1 代码库增量开发

---

## 1 现状分析

### 1.1 v1 已完成

- `baize-asl` crate：payload 结构、adapter（blob↔ASL 转换）、verify（CNV + AZN-VER 五项校验）
- 签名认证（HMAC-SHA256，optional fallback）
- 审计哈希链
- 凭证生命周期（4 态状态机）
- v1 API 端点（intent/authz/receipt/session/cnv/audit/proof）
- 319 个测试全部通过

### 1.2 v1 的核心问题：设计完备但未强制执行

| 能力 | 设计 | 运行时 | 差距 |
|------|------|--------|------|
| 凭证状态检查 | ✅ 4 态状态机 | ❌ verify_write_agent 不检查 | Suspended/Expired 仍可写 |
| Intent 有效期 | ✅ expires_at 字段 | ❌ 无运行时验证 | 过期 intent 仍可派生子意图 |
| Authz 有效期 | ✅ nbf/exp 字段 | ❌ 无运行时验证 | 过期 authz 仍可创建 receipt |
| 约束收缩 | ✅ constraint.rs 纯函数 | ❌ pipe_* 不调用 | 子意图/子授权约束可能超范围 |
| Elevation 运行时 | ✅ 申请/审批流程 | ❌ file ops 不检查借权 | 跨 zone 操作不验证 elevation |
| INF-KMS 密钥 | ✅ 5 用途 label 定义 | ❌ 无实际密钥生成 | 只存 label，无密码学 |
| LNK 加密 | ✅ session 状态管理 | ❌ 无 ECDH/AES | 消息明文传输 |
| IDN-ATH Proof | ✅ proof 生成 | ❌ 无强制验证 | proof 可忽略 |

---

## 2 v2 目标

将 ASL 五类安全能力全部落地为运行时强制：

1. **管道强制** — pipe_* 操作必须经过 ASL 校验
2. **INF-KMS** — 实际密钥生成/加密存储/轮换
3. **LNK-DTX** — ECDH 密钥协商 + AES-256-GCM 端到端加密
4. **IDN-ATH** — 运行态证明生成与强制验证

---

## 3 Phase 1：管道安全强制

> 无新依赖，只修改现有代码，可独立完成并测试。

### 3.1 凭证状态检查

**文件**: `agent_manager.rs` — `verify_write_agent` / `verify_read_agent`

```rust
fn verify_write_agent(&self, agent_id: &str) -> Result<CertIdentity, Error> {
    let (identity, _) = self.agents.get(agent_id).ok_or(...)?;
    if identity.level < 1 { return Err(PermissionDenied); }
    match identity.status {
        CredentialStatus::Active => {},
        CredentialStatus::Suspended => return Err(PermissionDenied("agent suspended")),
        CredentialStatus::Revoked => return Err(CredentialExpired("agent revoked")),
        CredentialStatus::Expired => return Err(CredentialExpired("agent expired")),
    }
    Ok(identity.clone())
}
```

### 3.2 Intent 有效期运行时检查

**文件**: `data_ops.rs`

```rust
BLOB_TYPE_INTENT => {
    validate_intent_blob(&self.storage, content, labels)?;
    enforce_not_expired(labels.get(LABEL_INTENT_EXPIRES))?;  // 新增
}
```

### 3.3 Authorization 有效期运行时检查

Receipt 创建时验证引用的 authz 未过期：
```rust
BLOB_TYPE_RECEIPT => {
    validate_receipt_blob(&self.storage, content, labels)?;
    enforce_authz_valid(&self.storage, labels)?;  // 新增：查 authz 的 exp
}
```

### 3.4 Elevation 运行时强制

**文件**: `file_sync.rs`

新增 `is_zone_accessible(agent_id, identity, path)`:
- 检查 agent 自身 zones（直接包含）
- 检查已审批、未过期、未归还的 elevation zones
- path 首段在任一集合中即通过

```rust
fn pipe_file_write(&self, agent_id: &str, path: &str, ...) {
    let identity = self.verify_write_agent(agent_id)?;
    if !self.is_zone_accessible(agent_id, &identity, path) {
        return Err(PermissionDenied);
    }
    ...
}
```

### 3.5 审计增强

审计记录新增：
- `x-audit-credential-status` — 操作时 agent 的凭证状态
- `x-audit-binding-context` — 操作时的 binding context digest

---

## 4 Phase 2：INF-KMS 密钥管理

### 4.1 密钥生成

**文件**: `baize-core/src/crypto.rs`

每个 agent 注册时生成 5 个用途密钥：

| 用途 | 算法 | 说明 |
|------|------|------|
| IDN_SIGN | Ed25519 | 身份签名 + 请求签名 |
| INT_SIGN | Ed25519 | 意图 payload 签名 |
| AZN_SIGN | Ed25519 | 授权 payload 签名 |
| RCT_SIGN | Ed25519 | 回执 payload 签名 |
| SESSION | X25519 | 会话密钥协商 |

依赖：`ed25519-dalek` + `x25519-dalek`

### 4.2 密钥存储加密

- 密钥序列化为 bytes → AES-256-GCM 加密 → 写入 blob（type=agent-key）
- master secret 通过 `BAIZE_MASTER_SECRET` 环境变量传入
- 无 master secret → 明文存储 + 启动警告（开发模式）

### 4.3 密钥轮换

```
POST /api/v2/agents/{id}/keys/rotate
Body: { "purpose": "IDN_SIGN" }
```

流程：
1. 生成新密钥 → 写入新 blob
2. 旧密钥追加 `x-key-revoked: true` label
3. 过渡期：旧签名仍接受（检查 revoked=false）
4. 下一分钟：只接受新密钥签名

### 4.4 签名强制化

**文件**: `auth.rs`

| API 版本 | 签名要求 |
|----------|---------|
| /api/v0 | x-agent-id（无签名） |
| /api/v1 | x-agent-id（签名可选，有则验证） |
| /api/v2 | 必须携带有效签名 |

v2 端点按操作类型使用对应用途密钥：
- blob write → IDN_SIGN
- intent → INT_SIGN
- authorization → AZN_SIGN
- receipt → RCT_SIGN

---

## 5 Phase 3：LNK 端到端加密

### 5.1 ECDH 密钥协商

**文件**: `crypto.rs` 扩展

```rust
pub fn ecdh_key_exchange(
    my_private: &x25519_dalek::StaticSecret,
    peer_public: &x25519_dalek::PublicKey,
) -> x25519_dalek::SharedSecret
```

Session 建立流程：
```
1. peer-a → session-init blob:
   content = { ephemeral_pub: X25519(a) }

2. peer-b → session-accept blob:
   content = { ephemeral_pub: X25519(b) }

3. 双方各自计算:
   shared_secret = ECDH(my_private, peer_public)
   session_key = HKDF-SHA256(shared_secret, info=session_id)
```

### 5.2 加密消息

带 `x-session-id` 的 blob（非 init/accept/close）为加密消息：
- content = `AES-256-GCM(key=session_key, plaintext, aad=session_id)`
- 服务端**不解密**，只校验 session 状态
- 客户端负责加密/解密

**设计决策**: 服务端不解密是 ASL 端到端安全的核心要求。服务端只管 session 状态（init/accept/seq/close），不持有会话密钥。

### 5.3 Session 生命周期强制

**文件**: `data_ops.rs` — `validate_session_message_blob`

```rust
fn validate_session_message_blob(storage, labels) -> Result<()> {
    // 1. session 必须已完成 accept（有 init + accept blob）
    // 2. session 不能已关闭（无 session-close blob）
    // 3. x-message-seq 必须递增
}
```

---

## 6 Phase 4：IDN-ATH 运行态证明

### 6.1 Proof 生成增强

**文件**: `identity.rs` 扩展

当前 proof 只记录证明信息。增强为包含：
- agent 当前凭证 hash（agent-cert blob hash）
- binding_context_digest（聚合三组身份属性 SHA-256）
- 有效期 5 分钟

### 6.2 Proof 验证强制

新增管道方法：
```rust
fn require_valid_proof(&self, agent_id: &str) -> Result<RuntimeProof, Error>
```

调用时机：
- Level 3+ 的敏感写操作
- authorization 创建
- receipt 创建
- proof 过期或不存在 → `Err(CredentialExpired("proof required"))`

### 6.3 Binding Context Digest 验证

三组属性 → 拼接 → SHA-256：
- 主体状态：agent_id, level, zones, status, parent
- 环境状态：SEE level, environment ID, host identity
- 实例状态：runtime proof 中的 instance_state_attributes

任何属性变化 → digest 变化 → proof 失效 → 需要重新生成

---

## 7 Phase 5：v2 API + 集成测试

### 7.1 v2 API 端点

| 端点 | 说明 |
|------|------|
| `POST /api/v2/blobs` | 签名强制的 blob write |
| `POST /api/v2/files/{path}` | 签名强制的文件 write |
| `POST /api/v2/intents` | 签名强制 + 有效期验证 |
| `POST /api/v2/authorizations` | 签名强制 + 有效期验证 |
| `POST /api/v2/receipts` | 签名强制 + authz 有效性 |
| `POST /api/v2/sessions/{id}/message` | 加密消息 |
| `POST /api/v2/agents/{id}/keys/rotate` | 密钥轮换 |
| `POST /api/v2/agents/{id}/proof` | Proof 生成 |
| `GET /api/v2/agents/{id}/proof/verify` | Proof 验证 |

v0/v1 所有端点保持不变（向后兼容）。

### 7.2 集成测试

新增 v2 wave 测试：

| 测试 | 覆盖 |
|------|------|
| `test_v2_suspended_agent_blocked` | 暂停 agent 被拒绝写操作 |
| `test_v2_expired_intent_rejected` | 过期 intent 不能创建 sub-intent |
| `test_v2_expired_authz_rejected` | 过期 authz 不能创建 receipt |
| `test_v2_elevation_enforced` | 无 elevation 的跨 zone 操作被拒 |
| `test_v2_encrypted_session` | 端到端加密消息流 |
| `test_v2_proof_required_for_sensitive_ops` | Level 3+ 需要 proof |
| `test_v2_key_rotation` | 密钥轮换流程 |
| `test_v2_signing_enforced` | v2 端点拒绝 unsigned 请求 |

---

## 8 设计决策

### D1: Ed25519 + X25519 而非 RSA

Ed25519 签名更短更快（64 bytes vs 256+ bytes），X25519 ECDH 是现代标准。RSA 密钥大、性能差、不易在前端/嵌入式使用。

### D2: 服务端不解密 LNK 消息

ASL 端到端安全的核心要求。服务端只管 session 状态，不持有会话密钥。

### D3: v2 签名强制但 v1 兼容

/api/v2 必须签名，/api/v0 和 /api/v1 保持向后兼容。给用户迁移时间。

### D4: Proof 按需而非全局强制

只有 Level 3+ 的敏感操作需要 proof。普通 Level 1-2 操作不需要。平衡安全性和可用性。

### D5: Phase 1 独立于 Phase 2-4

管道安全强制不需要新 crypto 依赖，可先独立完成。

---

## 9 实施顺序

```
Phase 1: 管道安全强制
  3.1 verify_write_agent 凭证状态检查
  3.2 verify_read_agent 凭证状态检查
  3.3 Intent 有效期检查
  3.4 Authz 有效期检查
  3.5 Elevation 运行时强制
  3.6 审计增强

Phase 2: INF-KMS 密钥管理
  4.1 密钥生成（Ed25519 + X25519）
  4.2 密钥加密存储
  4.3 密钥轮换 API
  4.4 签名强制化

Phase 3: LNK 端到端加密
  5.1 ECDH 密钥协商
  5.2 加密消息处理
  5.3 Session 生命周期强制

Phase 4: IDN-ATH 运行态证明
  6.1 Proof 生成增强
  6.2 Proof 验证强制
  6.3 Binding context digest 验证

Phase 5: v2 API + 集成测试
  7.1 v2 API 端点
  7.2 集成测试
```

## 10 关键文件

| 文件 | Phase | 操作 |
|------|-------|------|
| `baize-server/src/pipeline/agent_manager.rs` | 1 | 修改：凭证状态检查 |
| `baize-server/src/pipeline/data_ops.rs` | 1,3 | 修改：有效期 + 加密消息 |
| `baize-server/src/pipeline/file_sync.rs` | 1 | 修改：elevation zone 检查 |
| `baize-server/src/pipeline/auditor.rs` | 1 | 修改：审计增强 |
| `baize-server/src/pipeline/identity.rs` | 4 | 修改：proof 增强 |
| `baize-server/src/pipeline/auth.rs` | 2 | 修改：签名强制 |
| `baize-core/src/crypto.rs` | 2,3 | 新建/扩展：密钥管理 + ECDH |
| `baize-server/src/api.rs` | 2,3,5 | 修改：v2 路由 |
| `baize-server/tests/wave_integration.rs` | 5 | 扩展：v2 测试 |
