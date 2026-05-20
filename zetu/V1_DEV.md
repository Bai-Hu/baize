# 白泽 v1 项目开发文档

> 版本：v1 全量设计
> 对应协议规范：`zetu/PROTOCOL_SPEC_V1.md`
> 基于 v0.1 代码库增量开发

---

## 1 概述

### 1.1 v1 目标

白泽 v1 在 v0.1 基础上新增两大能力：

1. **ASL 合规层** — 实现 IIFAA ASL V1.0 规范定义的五类安全能力（INF / IDN / LNK / INT / AZN），支持与其他 ASL 合规 Agent 互操作
2. **泽图安全增强** — 审计哈希链、请求签名认证、凭证生命周期管理

v1 是 v0.1 的超集，所有 v0 blob 类型和操作不变。

### 1.2 与 v0 的关系

| 维度 | v0.1 | v1 |
|------|------|-----|
| blob 类型 | audit, agent-cert, agent-key, root-ca, file, push-auth, elevation-request | + receipt, authorization, runtime-proof（核心）；intent, sub-intent（可扩展锚点，需 agent 运行时消费） |
| 认证 | x-agent-id 请求头 | + 请求签名（X-Signature, X-Timestamp） |
| 审计 | 记录写操作 | + 哈希链 + 链验证 |
| 凭证 | 注册即永久有效 | + 生命周期（active/suspended/revoked/expired） |
| 意图/授权 | 无 | 完整 INT + AZN |
| 可信通讯 | 无 | LNK session（隐式，基于 blob label） |
| API 路径 | /api/v0 | /api/v1（包含 v0 全部端点） |

### 1.3 设计原则

- **blob+label 是唯一原语** — 所有 v1 新增载荷统一以 blob 承载，以 label 标注元数据
- **存储层不变** — SQLite schema 不需要变更，新 blob 类型自然适配现有 blob/label 表
- **模块增量** — 在现有 6 个 pipeline 模块基础上新增 1 个模块（identity.rs），扩展现有模块，不重写现有代码
- **对内 blob，对外 ASL** — 内部 blob+label 存储，对外通过适配层输出 ASL 载荷格式

---

## 2 架构

### 2.1 crate 结构

新增第四个 crate，负责 ASL 合规：

```
crates/
├── baize-core/          # 核心库：数据类型 + 存储引擎
│   └── src/
│       ├── storage.rs   # 不变
│       ├── cert.rs      # 扩展（CertIdentity 新增 status: CredentialStatus）
│       ├── scope.rs     # 不变
│       ├── workspace.rs # 不变
│       ├── error.rs     # 扩展（新增错误类型）
│       ├── labels.rs    # 新增：全部 label 常量（v0 + v1 + audit 集中管理）
│       └── constraint.rs # 新增：约束收缩校验纯函数
├── baize-asl/           # 新增：ASL 合规层 + 适配
│   └── src/
│       ├── lib.rs       # 模块声明
│       ├── payload.rs   # ASL 载荷结构定义（intent/authorization/receipt/proof）
│       ├── adapter.rs   # ASL payload ↔ blob+label 双向转换
│       └── verify.rs    # 约束收缩校验 + CNV 全链路 + AZN-VER 五项校验
├── baize-server/        # HTTP 服务 + 业务逻辑
│   └── src/
│       ├── api.rs       # 扩展（新增 v1 路由）
│       ├── lib.rs       # 扩展（新增模块声明）
│       ├── hook.rs      # 不变
│       └── pipeline/
│           ├── mod.rs       # 扩展（新增字段）
│           ├── agent_manager.rs # 扩展（IDN-LCM, INF labels）
│           ├── auditor.rs       # 扩展（审计哈希链）
│           ├── data_ops.rs      # 扩展（INT/AZN/LNK type dispatch）
│           ├── elevation.rs     # 不变
│           ├── file_sync.rs     # 不变
│           ├── git_ops.rs       # 不变
│           └── identity.rs      # 新增：运行态证明
└── baize-cli/           # CLI 工具
    └── src/main.rs      # 扩展（新增命令）
```

### 2.2 Baize struct 变更

```rust
// v0.1
pub struct Baize {
    pub storage: Storage,
    pub workspace_mgr: WorkspaceManager,
    pub(super) main_repo: PathBuf,
    pub(super) hooks: HookRegistry,
    pub(super) agents: HashMap<String, (CertIdentity, IssuerCtx)>,
}

// v1 新增字段
pub struct Baize {
    // v0.1 字段不变
    pub storage: Storage,
    pub workspace_mgr: WorkspaceManager,
    pub(super) main_repo: PathBuf,
    pub(super) hooks: HookRegistry,
    pub(super) agents: HashMap<String, (CertIdentity, IssuerCtx)>,
    // v1 新增
    pub(super) asl: baize_asl::AslContext,  // ASL 合规上下文（适配 + 校验）
}
```

`AslContext` 初始版本为无状态 struct，后续可扩展 ASL 版本号、外部端点配置、信任锚材料等。pipeline 模块通过 `&self.asl` 访问适配和校验能力。

### 2.3 模块依赖图

```
baize-asl（独立 crate）
┌─────────────────────────────────────────────┐
│  payload.rs    adapter.rs    verify.rs       │
│  ASL 载荷定义   ASL↔blob 转换  CNV/AZN-VER  │
└──────────┬──────────────┬───────────────────┘
           │              │
  pipeline 模块通过 Baize.asl 调用
           │              │
           ↓              ↓

                ┌───────────┐
                │ auditor   │ ← 扩展：审计哈希链（不依赖 baize-asl）
                └─────┬─────┘
                      │
    ┌─────────────────┼──────────────────────┐
    │                 │                      │
┌───┴──────────┐ ┌────┴──────┐ ┌────────────┴───┐
│ agent_mgr   │ │ git_ops   │ │ data_ops       │ ← 扩展
│ + INF labels│ │           │ │ INT/AZN/LNK    │
│ + IDN-LCM   │ │           │ │ type dispatch  │
└──────┬───────┘ └───────────┘ │ ──→ asl.verify │
       │                       └───────┬────────┘
       │                               │
┌──────┴──────┐  ┌─────────────────────┘
│ elevation   │  │
│             │  │
└─────────────┘  │
                 │
           ┌─────┴──────┐
           │ identity   │ ← 新增
           │ IDN-ATH    │
           └────────────┘
```

依赖方向：
- **baize-asl** 是独立 crate，被 pipeline 模块依赖（通过 `Baize.asl`）
- **data_ops** 按 blob type label 分发，INT/AZN 类型调用 `asl.verify` 做 CNV 和 AZN-VER 校验，调用 `asl.adapter` 做 ASL 载荷转换
- **identity** 调用 `asl.adapter` 做 ASL 载荷转换
- **auditor** 不依赖 baize-asl（审计链是泽图扩展，不是 ASL 规范）
- **baize-asl** 不依赖 pipeline 模块（单向依赖）

---

## 3 数据模型

### 3.1 新增 blob content 类型

文件：`crates/baize-asl/src/payload.rs`（ASL 载荷定义，也是 blob content 的内部格式）

blob content 直接存储 ASL JSON，不需要两套类型。baize-core 保持纯存储层不变，不感知 v1 载荷。

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── 通用意图 (INT-GIR) ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentContent {
    pub intent_id: String,
    pub intent_owner: String,
    pub intent_creator: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    pub intent_goal: String,
    pub intent_constraints: serde_json::Value, // 灵活 JSON
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_preferences: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_input_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_input_excerpt: Option<String>,
    pub version: String,
    pub created_at: String,
    pub expires_at: String,
}

// ─── 子意图 (INT-DER) ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubIntentContent {
    pub sub_intent_id: String,
    pub parent_intent_digest: String,
    pub deriver_id: String,
    pub subject: String,
    pub derivation_depth: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_basis: Option<String>,
    pub intent_goal: String,
    pub intent_constraints: serde_json::Value,
    pub created_at: String,
    pub expires_at: String,
}

// ─── 执行回执 (INT-RCT) ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptContent {
    pub receipt_id: String,
    pub executor_id: String,
    pub task_id: String,
    pub action_type: String,
    pub intent_digest: String,
    pub authorization_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_params_digest: Option<String>,
    pub result_status: ReceiptStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
    pub started_at: String,
    pub finished_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downstream_receipt_digests: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReceiptStatus {
    Succeeded,
    Failed,
    Partial,
    Rejected,
    Cancelled,
    Expired,
}

// ─── 授权载荷 (AZN-APR) ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationContent {
    pub authorization_id: String,
    pub issuer: String,
    pub subject: String,
    pub grant_type: String,
    pub constraints: AuthzConstraints,
    pub delegatable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_depth_remaining: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_mode: Option<DelegationMode>,
    pub source_intent_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_authz_digest: Option<String>,
    pub root_authorizer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
    pub nbf: String,
    pub exp: String,
    pub iat: String,
    pub jti: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzConstraints {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_scope: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_scope: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_scope: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_scope: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment_scope: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behavior_scope: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cumulative_limit: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DelegationMode {
    Specified,
    Bounded,
}

// ─── 运行态证明 (IDN-ATH) ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeProofContent {
    pub proof_id: String,
    pub credential_digest: String,               // 引用的 agent-cert blob digest
    pub instance_state_attributes: serde_json::Value, // 实例状态属性（IDN-ATT 第三组）
    pub binding_context_digest: String,          // 三组属性的聚合摘要（IDN-ATT 锚点）
    pub proof_anchor_mode: ProofAnchorMode,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofAnchorMode {
    CredentialAnchored,
    EnvironmentAnchored,
}

// ─── 凭证生命周期 (IDN-LCM) ───
// CredentialStatus 定义在 baize-core/cert.rs（CertIdentity 的 status 字段）
// 见 §5.2 IDN-LCM
```

> `CredentialStatus` 枚举定义在 `baize-core/cert.rs` 中，因为它是 `CertIdentity` 的字段。baize-asl/payload.rs 不重复定义。

### 3.2 Label 命名空间常量

文件：`crates/baize-core/src/labels.rs`

所有 label 常量集中管理（v0 + v1 + audit）。baize-core 已有领域概念（CertIdentity, Scope, Level），label key 是同类别的数据契约定义。baize-asl 不再单独定义 labels。

```rust

// INF labels
pub const LABEL_SEE_LEVEL: &str = "x-see-level";
pub const LABEL_SEE_ENV_ID: &str = "x-see-environment-id";
pub const LABEL_SEE_PLATFORM_STATE: &str = "x-see-platform-state";
pub const LABEL_SEE_ATTESTATION: &str = "x-see-attestation-support";

// KMS labels
pub const LABEL_KEY_PURPOSE: &str = "x-key-purpose";
pub const LABEL_KEY_OWNER: &str = "x-key-owner";
pub const LABEL_KEY_SEE_LEVEL: &str = "x-key-see-level";
pub const LABEL_KEY_NONEXPORTABLE: &str = "x-key-nonexportable";
pub const LABEL_KEY_ALGORITHM: &str = "x-key-algorithm";

// IDN labels (IDN-ATT 三组属性映射)
// ── 主体状态属性 (subject_state_attributes) ──
pub const LABEL_CERT_AGENT: &str = "x-cert-agent";           // agent_id
pub const LABEL_CERT_LEVEL: &str = "x-cert-level";           // scope.level
pub const LABEL_CERT_PARENT: &str = "x-cert-parent";         // control_relation.parent
pub const LABEL_CERT_ZONES: &str = "x-cert-zones";           // scope.zones
pub const LABEL_CERT_STATUS: &str = "x-cert-status";         // subject_state (active/suspended/revoked/expired)
// ── 环境属性 (environment_attributes) ──
// x-see-level, x-see-environment-id, x-see-platform-state, x-see-attestation-support 已在 INF labels 中定义
pub const LABEL_CERT_HOST_IDENTITY: &str = "x-cert-host-identity";     // host_identity
// ── 实例状态属性 (instance_state_attributes) ──
// 由 runtime-proof blob 的 content.instance_state_attributes 承载
// ── 凭证状态标志（持久化用，与 IDN-LCM 对应）──
pub const LABEL_CERT_SUSPENDED: &str = "x-cert-suspended";
pub const LABEL_CERT_REVOKED: &str = "x-cert-revoked";
pub const LABEL_CERT_EXPIRED: &str = "x-cert-expired";
// ── 绑定上下文摘要 ──
pub const LABEL_BINDING_CONTEXT_DIGEST: &str = "x-binding-context-digest";

// Intent labels
pub const LABEL_INTENT_ID: &str = "x-intent-id";
pub const LABEL_INTENT_OWNER: &str = "x-intent-owner";
pub const LABEL_INTENT_STATUS: &str = "x-intent-status";
pub const LABEL_INTENT_EXPIRES: &str = "x-intent-expires";
pub const LABEL_PARENT_INTENT: &str = "x-parent-intent";
pub const LABEL_DERIVATION_DEPTH: &str = "x-derivation-depth";

// Authorization labels
pub const LABEL_AUTHZ_ID: &str = "x-authz-id";
pub const LABEL_AUTHZ_ISSUER: &str = "x-authz-issuer";
pub const LABEL_AUTHZ_SUBJECT: &str = "x-authz-subject";
pub const LABEL_AUTHZ_STATUS: &str = "x-authz-status";
pub const LABEL_SOURCE_INTENT: &str = "x-source-intent";
pub const LABEL_PARENT_AUTHZ: &str = "x-parent-authz";

// Receipt labels
pub const LABEL_RECEIPT_ID: &str = "x-receipt-id";
pub const LABEL_RECEIPT_EXECUTOR: &str = "x-receipt-executor";
pub const LABEL_RECEIPT_STATUS: &str = "x-receipt-status";
pub const LABEL_RECEIPT_INTENT: &str = "x-receipt-intent";
pub const LABEL_RECEIPT_AUTHZ: &str = "x-receipt-authz";

// Session labels (LNK, protocol §8)
pub const LABEL_SESSION_ID: &str = "x-session-id";
pub const LABEL_SESSION_PEER_A: &str = "x-session-peer-a";
pub const LABEL_SESSION_PEER_B: &str = "x-session-peer-b";
pub const LABEL_SESSION_STATUS: &str = "x-session-status";
pub const LABEL_SESSION_CLOSED_AT: &str = "x-session-closed-at";
pub const LABEL_SESSION_CLOSE_REASON: &str = "x-session-close-reason";
pub const LABEL_SESSION_FINAL_HASH: &str = "x-session-final-hash";
pub const LABEL_MESSAGE_ID: &str = "x-message-id";
pub const LABEL_MESSAGE_SEQ: &str = "x-message-seq";

// Runtime proof labels
pub const LABEL_PROOF_AGENT: &str = "x-proof-agent";
pub const LABEL_PROOF_CREDENTIAL: &str = "x-proof-credential";

// Audit chain labels
pub const LABEL_AUDIT_PREV: &str = "x-audit-prev";
pub const LABEL_AUDIT_CHAIN_INDEX: &str = "x-audit-chain-index";
```

---

## 4 安全机制

### 4.1 请求签名认证

**目标**：所有写操作必须携带有效签名，拒绝无签名请求。

**签名方案**：HMAC-SHA256

**请求头**：

```
X-Agent-ID: <agent-id>
X-Timestamp: <ISO 8601 UTC>
X-Signature: <HMAC-SHA256(agent-key, timestamp + method + path + body)>
```

**签名输入**：`timestamp\nmethod\npath\nbody`

**校验规则**：
- 签名不匹配 → 401
- 时间戳超出 ±5 分钟窗口 → 401
- 缺少签名头 → 401

**实现位置**：`crates/baize-server/src/auth.rs`（新建），Axum middleware

### 4.2 密钥加密存储

**目标**：私钥不以明文存储在 SQLite 中。

**加密方案**：AES-256-GCM，master secret 通过环境变量 `BAIZE_MASTER_SECRET` 或命令行参数传入。

**实现位置**：`crates/baize-core/src/crypto.rs`（新建）

```rust
pub fn encrypt_key(plaintext: &str, master_secret: &[u8]) -> Result<String, Error>;
pub fn decrypt_key(ciphertext: &str, master_secret: &[u8]) -> Result<String, Error>;
```

### 4.3 审计哈希链

**目标**：所有审计 blob 通过哈希链串联，任何中间记录的删除或篡改可被检测。

每条审计 blob 追加两个 label：
- `x-audit-prev`：前一条审计 blob 的 hash
- `x-audit-chain-index`：链中序号（单调递增）

链头通过 blob 存储（`type: audit-head`）。详见 §5.6、§9.3。

---

## 5 模块设计

### 5.1 INF：安全执行环境声明 + 密钥管理

**实现方式**：不新建模块，扩展现有 `agent_manager.rs`。

#### INF-SEE

SEE level 描述运行环境隔离等级（L1/L2/L3）。当前白泽部署在普通 Linux 环境，均为 SEE-L1。SEE 声明机制复用现有 cert 扩展 + label 体系，具体实现后续处理。

#### INF-KMS

密钥用途隔离，复用现有 `agent-key` blob + label 存储机制。每个 agent 注册时创建 5 个 agent-key blob（仅生成实际需要的用途）：

```rust
// agent_manager.rs — agent_register() 扩展
// 现有：创建 1 个 agent-key (IDN_SIGN)
// v1：创建最多 5 个 agent-key，通过 x-key-purpose label 区分

for purpose in &["IDN_SIGN", "INT_SIGN", "AZN_SIGN", "RCT_SIGN", "SESSION"] {
    let key = KeyPair::generate()?;
    let key_labels = labels! {
        "type" => "agent-key",
        "x-key-owner" => name,
        "x-key-purpose" => purpose,
        "x-key-nonexportable" => "true",
        "x-key-algorithm" => "Ed25519",
    };
    storage.blob_write(&key.serialize_pem(), &key_labels)?;
}
```

用途说明：

| 用途 | 签什么 | 复用情况 |
|------|--------|---------|
| `IDN_SIGN` | 身份凭证 + 请求签名 | v0 已有，扩展用于请求签名 |
| `INT_SIGN` | 意图载荷 | 新增 |
| `AZN_SIGN` | 授权凭证 | 新增 |
| `RCT_SIGN` | 执行回执 | 新增 |
| `SESSION` | 会话密钥派生 | 复用现有 agent-key 基础设施，少量代码 |

请求签名（§4.1）使用 `IDN_SIGN` 密钥——请求签名的本质是证明身份，与 IDN_SIGN 用途一致。

### 5.2 IDN：身份属性 + 凭证生命周期 + 运行态证明

#### IDN-ATT（身份属性 — ASL 合规映射）

ASL-IDN-ATT 定义三组身份属性，通过 `binding_context_digest` 聚合。泽图将三组属性分散存储在 agent-cert blob 的 labels 和 runtime-proof blob 的 content 中，通过适配层聚合为 ASL 结构。

**三组属性 → blob label 映射：**

| ASL 属性组 | ASL 字段 | 泽图存储位置 | label / content 字段 |
|-----------|---------|------------|---------------------|
| **主体状态属性** | agent_id | agent-cert label | `x-cert-agent` |
| | subject_state | agent-cert label（由 IDN-LCM 维护） | `x-cert-status: active/suspended/revoked/expired` |
| | scope.level | agent-cert label | `x-cert-level` |
| | scope.zones | agent-cert label | `x-cert-zones` |
| | control_relation.parent | agent-cert label | `x-cert-parent` |
| **环境属性** | see_level | agent-cert label | `x-see-level` |
| | environment_id | agent-cert label | `x-see-environment-id` |
| | host_identity | agent-cert label | `x-cert-host-identity` |
| | platform_integrity_state | agent-cert label | `x-see-platform-state` |
| | attestation_support | agent-cert label | `x-see-attestation-support` |
| **实例状态属性** | instance_id | runtime-proof content | `instance_state_attributes.instance_id` |
| | instance_status | runtime-proof content | `instance_state_attributes.instance_status` |

**binding_context_digest** 计算：

```rust
// baize-asl/adapter.rs
fn compute_binding_context_digest(
    cert_labels: &HashMap<String, String>,  // agent-cert blob labels
    instance_state: &serde_json::Value,      // runtime-proof content
) -> String {
    // 按固定顺序序列化三组属性，计算 SHA-256
    // 1. 主体状态属性：从 cert_labels 提取 x-cert-* 相关字段
    // 2. 环境属性：从 cert_labels 提取 x-see-* 相关字段
    // 3. 实例状态属性：从 instance_state_attributes
    // 拼接后 hash
}
```

适配层（`baize-asl/adapter.rs`）负责将分散的 labels + runtime-proof content 聚合为 ASL-IDN-ATT 标准载荷。

#### IDN-LCM（凭证生命周期管理）

**实现方式**：扩展 `agent_manager.rs`，新增方法。

```rust
// agent_manager.rs — 新增

/// 查询凭证状态
fn credential_status(&self, agent_id: &str) -> Result<CredentialStatus, Error> {
    // 查询内存中 CertIdentity.status 字段
}

/// 更新凭证状态（active → suspended/revoked/expired, suspended → active/revoked/expired, 任意 → expired）
fn update_credential_status(&mut self, agent_id: &str, new_status: CredentialStatus, reason: &str)
    -> Result<(), Error>
{
    // 1. 查询当前状态
    // 2. 校验状态迁移合法性
    // 3. 追加 x-cert-status label（或通过审计 blob 记录迁移）
    // 4. 如果 revoking：从 self.agents 中移除
    // 5. 审计记录
}
```

**凭证状态存储**：运行时状态机，不使用 blob。`CertIdentity` 加 `status: CredentialStatus` 字段，内存中直接维护。状态变更时同步持久化（用于重启恢复）并生成审计记录。

持久化方式：状态变更时在 agent-cert blob 上追加标志 label（`x-cert-suspended: true`、`x-cert-revoked: true`、`x-cert-expired: true`），init 恢复时检查这些 label 重建状态。优先级：revoked > expired > suspended > active（无负面 label 即 active）。

**联动失效**： revoked agent 签发的 authorization 在 AZN-VER 校验时通过 IDN-LCM 查询签发方状态来识别。

#### IDN-ATH（运行态证明）

**文件**：`crates/baize-server/src/pipeline/identity.rs`（新建）

```rust
pub trait IdentityAuth {
    /// 生成运行态证明
    fn generate_runtime_proof(
        &self,
        agent_id: &str,
    ) -> Result<(String, HashMap<String, String>), Error>;
    // 返回 (blob_digest, labels)

    /// 身份鉴别（凭证 + 运行态证明组合校验）
    fn authenticate(
        &self,
        agent_id: &str,
        require_runtime_proof: bool,
    ) -> Result<(), Error>;
}
```

运行态证明是短时有效的 blob（5 分钟过期），每次身份鉴别时动态生成。

### 5.3 LNK：可信连接能力

对应泽图协议 §8（LNK-SES + LNK-DTX）。

| LNK 安全要求 | blob+label 实现 |
|-------------|----------------|
| 会话绑定（双方身份） | session-init/accept blob 引用 credential_digest，blob 写入需要 agent 认证 |
| 保密性 | 会话密钥加密 blob content（AES-256-GCM），端到端加密 |
| 完整性 | blob 不可变 + `parent` label 构成链式引用 |
| 防重放 | `x-message-seq` label 单调递增 |
| 会话隔离 | 不同 `x-session-id` 的 blob 集合天然隔离 |
| 握手摘要 | `handshake_transcript_digest = hash(init_blob \|\| accept_blob)` |
| 密钥销毁 | session 关闭后会话密钥不再使用 |

不新建模块。扩展 `data_ops.rs` 的 blob write，按 type label 分发处理 session-init/session-accept 和加密消息。

#### LNK-SES：会话建立（密钥协商）

session 的前两个 blob 完成密钥协商：

```json
// 1. 发起方写入 session-init blob
{
  "content": "{\"ephemeral_pub\":\"...\",\"cipher_suites\":[\"AES-256-GCM\"],\"credential_digest\":\"sha256:...\"}",
  "labels": {
    "type": "session-init",
    "x-session-id": "sess-4d1b2f",
    "x-session-peer-a": "agent-alice",
    "x-session-peer-b": "agent-bob"
  }
}

// 2. 响应方写入 session-accept blob
{
  "content": "{\"ephemeral_pub\":\"...\",\"selected_cipher_suite\":\"AES-256-GCM\",\"credential_digest\":\"sha256:...\"}",
  "labels": {
    "type": "session-accept",
    "x-session-id": "sess-4d1b2f",
    "parent": "<init-blob-digest>"
  }
}
```

双方各自从 init + accept 的 ephemeral_pub 派生共享密钥（ECDH）。`handshake_transcript_digest = hash(init_blob || accept_blob)`。密钥协商使用 INF-KMS 的 `SESSION` 用途密钥。

#### LNK-DTX：加密传输

会话密钥建立后，session 内后续 blob 的 content 用会话密钥加密。labels 不加密（用于路由和查询）。

```json
{
  "content": "<AES-256-GCM(session_key, 实际载荷 JSON)>",
  "labels": {
    "type": "intent",
    "x-session-id": "sess-4d1b2f",
    "x-message-seq": "1",
    "parent": "<accept-blob-digest>"
  }
}
```

#### 关闭 session

写入一条带 `x-session-status: closed` label 的 blob 即关闭。后续带相同 `x-session-id` 的写入被拒绝。会话密钥不再使用。

#### 实现

不新建文件。扩展 `data_ops.rs` 的 blob write 逻辑：

```rust
// data_ops.rs — blob_write 扩展

fn blob_write(&self, content: &str, labels: &HashMap<String, String>) -> Result<Blob, Error> {
    let blob_type = labels.get("type").unwrap_or(&"");

    match blob_type {
        // LNK-SES：会话建立
        "session-init" => {
            // 校验 peer_b 是已注册 agent
            // 校验 x-session-id 全局唯一
            // 存储发起方 ephemeral_pub（用于后续 accept 时密钥派生）
        }

        "session-accept" => {
            // 校验 parent 指向的 session-init blob 存在
            // 校验 accept 方是 session-init 中 x-session-peer-b
            // 记录 session 为已协商状态
        }

        // LNK-DTX：session 内消息
        _ if labels.contains_key(LABEL_SESSION_ID) => {
            let session_id = labels.get(LABEL_SESSION_ID).unwrap();

            // 查询该 session 是否已关闭
            // 校验 session-init + session-accept 已完成
            // 校验 seq 单调递增
            // content 为密文，服务端不负责加解密
        }

        _ => { /* 现有 blob write 逻辑 */ }
    }
}
```

**加解密职责**：白泽服务端负责 session 状态管理（init/accept 流程、seq 校验、close 检查）。加解密由客户端 agent 负责——白泽存储密文 blob，不持有会话密钥。这符合 ASL 端到端安全原则。

### 5.4 INT：意图表达 + 派生 + 回执 + CNV 校验

对应泽图协议 §9（INT-GIR / INT-DER / INT-RCT / INT-CNV）。

intent / sub-intent / receipt 本质是带特定 labels 的 blob。blob+label 原语满足 INT 的全部要求：

| INT 安全要求 | blob+label 天然满足 |
|-------------|-------------------|
| 意图不可篡改 | blob 不可变，content-addressed |
| 派生链可追溯 | `x-parent-intent` label 构成链式引用 |
| 约束收缩可验证 | 每级约束存储在 blob content 中，CNV 沿链逐级比较 |
| 回执绑定意图+授权 | `x-receipt-intent` / `x-receipt-authz` label 双摘要绑定 |
| 意图唯一性 | `x-intent-id` label 唯一性校验 |

#### blob write 时校验（扩展 data_ops.rs）

不新建文件。扩展 `data_ops.rs` 的 blob write，按 `type` label 分派校验逻辑：

```rust
// data_ops.rs — blob_write 扩展

fn blob_write(&self, content: &str, labels: &HashMap<String, String>) -> Result<Blob, Error> {
    let blob_type = labels.get("type").unwrap_or(&"");

    match blob_type {
        // INT-GIR：通用意图
        "intent" => {
            // 校验 intent_constraints 非空
            // 校验 expires_at > created_at
            // 校验 x-intent-id 在有效期内唯一
            // 校验 intent_constraints 存在且非空
        }

        // INT-DER：子意图派生
        "sub-intent" => {
            // 读取 parent_intent_digest 对应的父 blob
            // 校验父 blob 存在且 type 为 intent 或 sub-intent
            // 校验约束收缩（调用 constraint::verify_intent_constraint_reduction）
            // 校验 derivation_depth = 父 depth + 1
            // 校验 expires_at 不晚于父 expires_at
            // 校验 derivation_depth 单调递增
        }

        // INT-RCT：执行回执
        "receipt" => {
            // 校验 intent_digest 对应 blob 存在且为 intent/sub-intent
            // 校验 authorization_digest 对应 blob 存在且为 authorization
            // 校验 action_type 在授权 grant_type 范围内
            // 校验 result_status 与 execution_result/rejection_reason 一致性
        }

        _ => { /* 现有 blob write 逻辑 */ }
    }
}
```

#### 约束收缩校验

**文件**：`crates/baize-core/src/constraint.rs`（新建）

纯函数，不依赖 baize-asl 类型，接收 `serde_json::Value`：

```rust
/// 校验子意图约束是否在父意图约束范围内
pub fn verify_intent_constraint_reduction(
    parent_constraints: &serde_json::Value,
    child_constraints: &serde_json::Value,
) -> Result<(), ConstraintViolation> {
    // 逐维度比较：
    // - 动作范围：子集
    // - 目标范围：子集或等值
    // - 金额上限：不大于
    // - 时间窗口：完全落在父窗口内
    // - expires_at：不晚于
}
```

#### INT-CNV：全链路一致性校验

CNV 是唯一的 INT 新增逻辑。本质是沿 blob label 引用链做图遍历。

**文件**：`crates/baize-asl/src/verify.rs`（已有）

```rust
/// INT-CNV 全链路校验
pub fn cnv_verify(
    storage: &dyn BlobStore,
    receipt_digest: &str,
) -> Result<CnvResult, Error> {
    // 1. 读取 receipt blob
    // 2. 校验一：沿 x-parent-intent 向上追溯意图派生链
    //    - 每级约束收缩合规（verify_intent_constraint_reduction）
    //    - derivation_depth 单调递减至 0
    //    - 检测循环引用（记录已访问 hash）
    // 3. 校验二：authorization.source_intent_digest 与意图一致
    //    - authorization 约束在意图范围内
    //    - 签发方凭证状态有效（查 x-cert-suspended/revoked label）
    // 4. 校验三：receipt.authorization_digest 与授权一致
    //    - action_type 在 grant_type 范围内
    // 5. 校验四：委托链完整性（调用 verify_delegation_chain）
}

pub struct CnvResult {
    pub valid: bool,
    pub intent_chain: Vec<ChainNode>,
    pub authz_checks: AuthzChecks,
    pub errors: Vec<String>,
}
```

CNV 放在 baize-asl/verify.rs 而非 data_ops.rs，因为它是跨模块的校验逻辑（横跨 INT + AZN + IDN），通过 storage trait 访问 blob 数据，不依赖具体 pipeline 模块。

### 5.5 AZN：授权载荷 + 凭证签发 + 多级委托 + 授权校验

对应泽图协议 §10（AZN-APR / AZN-ISS / AZN-DLG / AZN-VER）。

authorization 本质是带特定 labels 的 blob，与 INT 同理。AZN-APR/ISS/DLG 是 blob write + 校验，AZN-VER 是沿 label 引用链的图遍历。

#### blob write 时校验（扩展 data_ops.rs）

不新建文件。与 INT 共用同一套 type 分派逻辑：

```rust
// data_ops.rs — blob_write 扩展（续）

        // AZN-APR + AZN-ISS：授权签发
        "authorization" => {
            // 校验 source_intent_digest 对应 blob 存在且有效
            // 校验 constraints 在意图约束范围内
            // 校验签发方凭证状态（查 x-cert-suspended/revoked label）
            // 校验 exp 不晚于意图 expires_at
            // 校验 jti 在签发方范围内唯一
        }

        // AZN-DLG：委托子授权（有 parent_authz_digest 时）
        // 在 "authorization" 分支内进一步判断：
        if let Some(parent_digest) = content.get("parent_authz_digest") {
            // 读取父授权 blob
            // 校验父授权存在且 x-authz-status = valid
            // 校验约束收缩（调用 constraint::verify_authz_constraint_reduction）
            // 校验 delegation_depth_remaining = 父 - 1
            // 校验 root_authorizer 与父一致
            // 校验父 delegatable = true
        }
```

#### AZN-DLG 约束收缩校验

**文件**：`crates/baize-core/src/constraint.rs`（与 INT 共用同一文件）

```rust
/// 校验子授权约束是否在父授权约束范围内
pub fn verify_authz_constraint_reduction(
    parent: &serde_json::Value,
    child: &serde_json::Value,
) -> Result<(), ConstraintViolation> {
    // 逐维度比较：
    // - time_scope/nbf/exp：子授权完全落在父授权时间窗内
    // - grant_type：子集
    // - target_scope：子集
    // - amount_scope：上限不高于父
    // - method_scope：子集
    // - environment_scope：不低于父的 SEE 等级
    // - delegation_depth_remaining：严格等于父 - 1
    // - delegation_mode：只允许 BOUNDED → SPECIFIED 收缩
    // - aud：子集
}
```

#### AZN-VER：授权校验

与 INT-CNV 同理，放在 `baize-asl/verify.rs`。五项校验通过 blob label 引用链遍历完成。

```rust
// baize-asl/src/verify.rs — AZN-VER

pub fn verify_authorization(
    storage: &dyn BlobStore,
    authz_digest: &str,
    action_type: &str,
    execution_context: &serde_json::Value,
) -> Result<AuthzVerifyResult, Error> {
    // 校验一：凭证真实性
    //   - 签发方 agent-cert 签名合法
    //   - 签发方凭证状态有效（查 x-cert-revoked label）
    //
    // 校验二：凭证有效性
    //   - x-authz-status = valid
    //   - nbf ≤ now < exp
    //
    // 校验三：意图引用一致性
    //   - source_intent_digest 指向有效意图
    //   - grant_type 和 constraints 在意图范围内
    //
    // 校验四：委托链完整性
    //   - 沿 parent_authz_digest 逐级向上
    //   - delegation_depth_remaining 单调递减
    //   - 各级 root_authorizer 一致
    //   - 各级约束收缩合规（verify_authz_constraint_reduction）
    //   - 各级父凭证有效（x-authz-status, 时间）
    //
    // 校验五：执行适用性
    //   - action_type 在 grant_type 范围内
    //   - 执行目标/金额/环境在 constraints 内
    //   - subject 与执行方一致
}

pub struct AuthzVerifyResult {
    pub valid: bool,
    pub checks: [bool; 5],
    pub errors: Vec<String>,
}
```

### 5.6 AUDIT：审计哈希链 + 链验证

**实现方式**：扩展现有 `auditor.rs`。

```rust
// auditor.rs — 扩展

pub trait Auditor {
    fn audit(&self, audit_type: &str, agent_id: &str, result: &str, target: Option<&str>)
        -> Result<(), Error>;

    // v1 新增
    fn verify_chain(&self) -> Result<ChainVerifyResult, Error>;
}

pub struct ChainVerifyResult {
    pub valid: bool,
    pub chain_length: u64,
    pub head_digest: String,
    pub genesis_digest: String,
    pub errors: Vec<String>,
}
```

#### audit() 方法变更

```rust
fn audit(&self, ...) -> Result<(), Error> {
    // 1. 查询当前 audit-head blob 获取前一条审计 hash
    let prev_digest = self.get_audit_head()?;

    // 2. 查询当前最大 chain-index
    let next_index = self.get_next_chain_index()?;

    // 3. 构造审计 blob，追加链 labels
    let mut audit_labels = labels! {
        "type" => "audit",
        "x-audit" => "true",
        "x-audit-type" => audit_type,
        "x-audit-agent" => agent_id,
        "x-audit-result" => result,
        "x-audit-time" => &Utc::now().to_rfc3339(),
        LABEL_AUDIT_PREV => &prev_digest,
        LABEL_AUDIT_CHAIN_INDEX => &next_index.to_string(),
    };
    if let Some(t) = target {
        audit_labels.insert("x-audit-target".to_string(), t.to_string());
    }

    // 4. 写入 blob
    let blob = self.storage.blob_write(&content_json, &audit_labels)?;

    // 5. 更新 audit-head blob（type: audit-head）
    self.set_audit_head(&blob.digest)?;

    Ok(())
}
```

#### verify_chain() 方法

```rust
fn verify_chain(&self) -> Result<ChainVerifyResult, Error> {
    // 1. 从 audit-head blob 获取链头 hash（label query: type=audit-head）
    // 2. 逐条沿 x-audit-prev 向前追溯
    // 3. 校验 x-audit-chain-index 单调递减
    // 4. 到达 genesis（index=0, prev="genesis"）时完成
    // 5. 统计总记录数与最大 index + 1 比较
}
```

---

## 6 API 设计

### 6.1 v1 路由表

文件：`crates/baize-server/src/api.rs`

新增路由挂在 `/api/v1` 下，v0 路由保持不变。

```
POST   /api/v1/intents                         创建通用意图
POST   /api/v1/intents/derive                   派生子意图
GET    /api/v1/intents/{hash}                   读取意图
GET    /api/v1/intents?status=active            查询意图

POST   /api/v1/receipts                         创建执行回执
GET    /api/v1/receipts/{hash}                  读取回执
GET    /api/v1/receipts?executor={id}           查询回执

POST   /api/v1/authorizations                   签发授权
POST   /api/v1/authorizations/delegate          委托子授权
POST   /api/v1/authorizations/{hash}/verify     校验授权
GET    /api/v1/authorizations/{hash}            读取授权

POST   /api/v1/sessions/{id}/close              关闭 session

POST   /api/v1/cnv/verify                       全链路校验

GET    /api/v1/audit                            查询审计日志
POST   /api/v1/audit/verify-chain               验证审计哈希链

GET    /api/v1/agents                           列出 Agent（同 v0）
GET    /api/v1/agents/{id}/status               查询凭证状态
PUT    /api/v1/agents/{id}/status               更新凭证状态
POST   /api/v1/agents/{id}/proof                生成运行态证明
GET    /api/v1/trace/identity/{id}              身份追溯（同 v0）

POST   /api/v1/agents                           注册 Agent（同 v0）
DELETE /api/v1/agents/{id}                      撤销 Agent（同 v0）
```

session 消息传输复用现有 blob write/query API（带 `x-session-id` label），仅关闭操作提供专用端点。

v0 全部端点在 `/api/v1` 下继续可用。

### 6.2 请求签名

v1 写操作需要签名认证头：

```
X-Agent-ID: agent-alice
X-Timestamp: 2026-05-18T10:00:00Z
X-Signature: hmac-sha256:<hex>
```

签名输入：`timestamp\nmethod\npath\nbody`

### 6.3 错误码扩展

v1 新增错误码：

| HTTP 状态 | error-type | 含义 |
|-----------|-----------|------|
| 400 | constraint violation | 约束收缩校验失败 |
| 400 | chain broken | 链路断裂（hash 不匹配、节点缺失） |
| 401 | invalid signature | 请求签名验证失败 |
| 401 | expired timestamp | 请求时间戳超出窗口 |
| 410 | credential expired | 凭证已过期 |
| 410 | intent expired | 意图已过期 |
| 410 | authorization expired | 授权已过期 |
| 410 | session closed | session 已关闭 |

---

## 7 CLI 扩展

### 7.1 v1 新增命令

```
# 意图
bz intent create --goal "..." --constraints '{"budget": 150}' --agent <ID>
bz intent derive <parent-hash> --goal "..." --constraints '...' --subject <ID> --agent <ID>
bz intent read <hash>
bz intent query --status active

# 回执
bz receipt create --action-type <TYPE> --intent <hash> --authz <hash> --status SUCCEEDED --agent <ID>
bz receipt read <hash>

# 授权
bz authz issue --subject <ID> --grant-type <TYPE> --intent <hash> --constraints '...' --agent <ID>
bz authz delegate <parent-hash> --subject <ID> --constraints '...' --agent <ID>
bz authz verify <hash> --action-type <TYPE>
bz authz read <hash>

# session（消息传输复用 blob write/query，仅关闭需专用命令）
bz session close <session-id> --agent <ID>

# CNV
bz cnv verify --receipt <hash>

# 审计链
bz audit chain-verify

# 凭证状态
bz agent status <ID>
bz agent suspend <ID> --reason "..."
bz agent revoke <ID> --reason "..."  # 扩展：支持 reason

# 运行态证明
bz agent proof <ID>

# INF
bz agent register <NAME> --level 3 --zones A,B --see-level L1 --agent <ID>
```

---

## 9 存储层变更

### 9.1 SQLite schema

**不需要变更**。v1 所有新增 blob 类型使用现有的 `blobs` 和 `labels` 表。

### 9.2 数据存储方式

新 blob 类型的 content 字段为 JSON 字符串（通过 `serde_json::to_string()` 序列化），存储在 `blobs.content` 列。需要查询的字段同步存储为 label。

### 9.3 审计链 head

审计链 head 通过 blob 存储：

- `type: audit-head`
- content 为最新审计 blob 的 hash
- 每次写入审计 blob 时更新（幂等，同一时刻只有一个 audit-head blob）
- 通过 label query 查询，不依赖 Git

---

