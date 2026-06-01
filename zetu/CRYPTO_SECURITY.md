# 白泽密码体系与安全分析

> 基于 `crates/baize-core/src/crypto.rs`、`crates/baize-server/src/pipeline/agent_manager.rs` 源码审查。
> 最后更新：2026-06-02

---

## 1. 密码算法清单

白泽使用 6 种密码学原语，分为 5 个可插拔维度 + 1 个证书签发：

| 维度 | 用途 | 默认算法 | 密钥长度 | 依赖库 |
|------|------|---------|---------|--------|
| 请求签名 (RequestSigner) | API 认证 | Ed25519 | 32 字节 seed | `ed25519-dalek` |
| 密钥交换 (KeyExchange) | ECDH 会话建立 | X25519 | 32 字节 | `x25519-dalek` |
| 密钥加密 (KeyEncryption) | 私钥加密存储 | AES-256-GCM | 32 字节 | `aes-gcm` |
| 密钥派生 (KeyDerivation) | 共享密钥 → 会话密钥 | HKDF-SHA256 | 任意输出 | `hkdf` |
| 会话加解密 (SessionCipher) | LNK 消息 E2E 加密 | AES-256-GCM | 32 字节 | `aes-gcm` |
| 证书签发 | X.509 子 agent 证书 | EC P-256 | 256 bit | `rcgen` |

辅助原语：

| 原语 | 用途 | 依赖库 |
|------|------|--------|
| SHA-256 | blob 内容寻址、审计链、binding_context_digest | `sha2` |
| HMAC-SHA256 | v1 兼容签名（已废弃） | `hmac` |
| Base64 | PEM 密钥编码、密文序列化 | `base64` |
| Hex | 签名输出、公钥表示 | `hex` |

---

## 2. 密钥体系全景

### 2.1 每个 Agent 的密钥矩阵

每个 agent 注册时生成 6 把密钥：

```
Agent 注册
├── cert-sign  (EC P-256)     ← rcgen 生成，签发子 agent 的 X.509 证书
├── IDN_SIGN   (Ed25519)      ← 身份签名，v2 API 请求认证
├── INT_SIGN   (Ed25519)      ← 意图签名（预留）
├── AZN_SIGN   (Ed25519)      ← 授权签名（预留）
├── RCT_SIGN   (Ed25519)      ← 回执签名（预留）
└── SESSION    (X25519)       ← ECDH 密钥交换
```

代码位置：`agent_manager.rs:159-184`

```rust
for purpose in KEY_PURPOSES {
    let (key_pem, algorithm) = if purpose == &"IDN_SIGN" {
        let (priv_pem, _) = baize_core::crypto::generate_ed25519_keypair()?;
        (priv_pem, "Ed25519")
    } else if purpose == &"SESSION" {
        let (priv_pem, _) = self.crypto.key_exchange.generate_keypair()?;
        (priv_pem, "X25519")
    } else {
        let (priv_pem, _) = baize_core::crypto::generate_ed25519_keypair()?;
        (priv_pem, "Ed25519")
    };
}
```

### 2.2 密钥用途标签

每把密钥以 blob 形式存入 SQLite，通过 labels 标记：

```
type:            agent-key
agent-id:        <agent-name>
x-key-owner:     <agent-name>
x-key-purpose:   IDN_SIGN | INT_SIGN | AZN_SIGN | RCT_SIGN | SESSION
x-key-algorithm: Ed25519 | X25519
x-key-nonexportable: true
x-key-see-level: L1
```

### 2.3 密钥存储加密

```
BAIZE_MASTER_SECRET 环境变量
    │
    ├── 未设置（默认）→ 私钥明文存入 SQLite
    │
    └── 已设置 → 私钥经 AES-256-GCM 加密后存入 SQLite
                  │
                  ├── master secret → HKDF-SHA256 → 32 字节加密密钥
                  ├── 随机 12 字节 nonce
                  └── 密文格式: base64(nonce || ciphertext || tag)
```

代码位置：`agent_manager.rs:170-174`

### 2.4 密钥轮换

| 密钥 | Root 可轮换 | 非 Root 可轮换 |
|------|-----------|--------------|
| IDN_SIGN | **禁止** | 允许 |
| INT_SIGN | 允许 | 允许 |
| AZN_SIGN | 允许 | 允许 |
| RCT_SIGN | 允许 | 允许 |
| SESSION | 允许 | 允许 |

轮换流程：撤销旧 key（打 `x-key-revoked` label）→ 生成新 key → 加密存储。

代码位置：`agent_manager.rs:348-410`

### 2.5 签名验证流程

```
v2 请求到达
    │
    v2_signature_middleware (api.rs:118-194)
    │
    ├── 提取 x-agent-id, x-timestamp, x-signature
    ├── get_agent_signing_key(baize, agent_id)
    │       │
    │       └── kms_get_active_key(agent_id, "IDN_SIGN")
    │               │
    │               ├── 从 DB 查询 x-key-purpose=IDN_SIGN 且未撤销的 blob
    │               ├── 如有 master secret → AES-256-GCM 解密
    │               └── extract_signing_key(pem) → 32 字节私钥 seed
    │
    ├── verify_signature(signer, key, timestamp, method, path, body, sig)
    │       │
    │       ├── signing_input = "{ts}\n{method}\n{path}\n{body}"
    │       ├── Ed25519 签名验证
    │       └── timestamp ±5 分钟窗口校验
    │
    └── 可选 nonce 重放防护
```

---

## 3. 会话密钥建立（LNK）

```
Peer A                           Server                           Peer B
  │                                │                                │
  │  POST /api/v2/sessions         │                                │
  │  {peer_a, peer_b,              │                                │
  │   ephemeral_pub: X25519_PEM}   │                                │
  │ ──────────────────────────────>│                                │
  │                                │ 验证 peer_b 已注册              │
  │                                │ 验证 ephemeral_pub X25519 格式  │
  │                                │ 存储 session-init blob          │
  │                                │                                │
  │                                │  POST /api/v2/sessions/{id}/accept
  │                                │  {ephemeral_pub: X25519_PEM,   │
  │                                │   selected_cipher_suite}        │
  │                                │<────────────────────────────── │
  │                                │ 验证 accept 方是 peer_b        │
  │                                │ 存储 session-accept blob        │
  │                                │                                │
  │  双方离线协商:                                                     │
  │  shared = X25519_ECDH(my_priv, peer_pub)                         │
  │  session_key = HKDF-SHA256(shared,                               │
  │      info="baize-session-key/{sid}/{pub_a}:{pub_b}")             │
  │                                                                   │
  │  消息加密: AES-256-GCM(session_key, plaintext, aad=session_id)    │
```

---

## 4. 安全分析

### 4.1 做对了的

| 实践 | 说明 |
|------|------|
| 现代算法选择 | Ed25519/X25519/AES-256-GCM 都是当前业界推荐 |
| 密钥用途分离 | 5 个 purpose 独立，有 label 标记，不混用 |
| AEAD 认证加密 | AES-256-GCM 提供加密+完整性，有 CSPRNG nonce |
| 签名防重放 | timestamp ±5min 窗口 + 可选 nonce 缓存 |
| 非对称签名 | v2 强制 Ed25519，攻击者无私钥无法伪造请求 |
| Provider 可插拔 | 5 个维度都可以替换为自定义实现 |
| 密钥轮换 | 非 root agent 支持所有 purpose 的密钥轮换 |
| Zone + Level | 双维度访问控制，最小权限原则 |

### 4.2 风险与建议

#### P0: Master Secret 默认关闭 — 私钥明文存储

**现状**：`BAIZE_MASTER_SECRET` 未设置时，所有私钥以明文 PEM 存入 SQLite blob。

**风险**：攻击者获取 DB 文件（文件系统访问、备份泄露、SQLite 文件权限过宽）即可提取所有 agent 的 Ed25519 私钥 seed，从而伪造任意 agent 的 API 请求。

**建议**：生产模式强制要求设置 master secret，仅开发模式允许明文。

```rust
// 建议改写 crypto.rs:451-458
pub fn master_secret_from_env() -> Option<Vec<u8>> {
    match std::env::var("BAIZE_MASTER_SECRET") {
        Ok(s) if !s.is_empty() => Some(s.into_bytes()),
        _ => {
            if std::env::var("BAIZE_DEV_MODE").is_ok() {
                eprintln!("[WARN] dev mode: keys stored in plaintext");
                return None;
            }
            panic!("BAIZE_MASTER_SECRET required in production. \
                    Set BAIZE_DEV_MODE=1 for development.");
        }
    }
}
```

#### P1: 签名验证加载私钥到内存 — 应只存公钥

**现状**：v2 middleware 验签时从 DB 解密完整 PEM → 提取 32 字节私钥 seed → 推导公钥验签。

```
api.rs:104-108
    get_agent_signing_key() → extract_signing_key(pem) → 32 字节私钥 seed

crypto.rs:354-358
    let signing_key = SigningKey::from_bytes(&key_array);  // 私钥
    let verifying_key = signing_key.verifying_key();        // 推导公钥
    verifying_key.verify(message, &sig)                     // 验签
```

**风险**：内存 dump 或侧信道攻击可获取私钥。验签只需要公钥，不需要加载私钥。

**建议**：`get_agent_signing_key` 改名为 `get_agent_verifying_key`，返回 Ed25519 公钥（32 字节），verify 直接用公钥验签。

#### P2: Root IDN_SIGN 不可轮换 — 不可恢复的单点

**现状**：root 的 IDN_SIGN 密钥禁止轮换（`agent_manager.rs:349-350`）。

**风险**：如果 root 的 IDN_SIGN 私钥泄露，攻击者可以：
- 以 root 身份执行任何操作
- 注册任意 level 的子 agent
- 删除/修改其他 agent
- 整个信任体系崩溃，且无法恢复

**建议**：设计 root 密钥轮换协议（需要离线签名的恢复流程或多人分片机制），或至少在文档中明确标注这一限制和对应的操作安全要求。

#### P3: INT_SIGN / AZN_SIGN / RCT_SIGN 注册但未消费

**现状**：`KEY_PURPOSES = ["IDN_SIGN", "INT_SIGN", "AZN_SIGN", "RCT_SIGN", "SESSION"]`，但管道中只有 IDN_SIGN 和 SESSION 被实际使用。

**风险**：
- 增加 3 个可被窃取的私钥（扩大攻击面）
- 增加管理复杂度（每 agent 6 把密钥而非 3 把）
- 用户可能误以为这些密钥在保护什么

**建议**：要么在管道中接入（INT 签名、AZN 签名、RCT 签名），要么从 `KEY_PURPOSES` 中移除。需要时再按需注册。

#### P4: Ed25519 verify 双路径

**现状**：`Ed25519RequestSigner::verify` 将同一个 32 字节先当私钥 seed 试一次，再当公钥试一次。

```
crypto.rs:354-366
    // 路径 1：当作私钥 seed → 推导公钥 → 验签
    let signing_key = SigningKey::from_bytes(&key_array);
    let verifying_key = signing_key.verifying_key();
    if verifying_key.verify(message, &sig).is_ok() { return true; }
    // 路径 2：当作公钥 → 直接验签
    if let Ok(vk) = VerifyingKey::from_bytes(&key_array) {
        if vk.verify(message, &sig).is_ok() { return true; }
    }
```

**风险**：不必要的复杂度，且可能掩盖密钥管理中的类型混淆问题。

**建议**：当前只使用路径 1（私钥 seed），移除路径 2。如果未来需要纯公钥验签，应使用独立的函数。

### 4.3 攻击面矩阵

| 攻击向量 | 防御现状 | 风险 | 对应建议 |
|---------|---------|------|---------|
| 窃取 DB 文件 | AES-256-GCM 加密可选 | **高**（默认关闭） | P0 |
| 网络嗅探重放 | timestamp ±5min + nonce | 低 | — |
| 伪造签名 | Ed25519 签名验证 | 低 | — |
| Root 私钥泄露 | 不可轮换 → 不可恢复 | **高** | P2 |
| 内存 dump | 私钥 seed 在验签时驻留 | **中** | P1 |
| 侧信道攻击 | 标准 Ed25519 实现 | 低 | — |
| 子 agent 横向移动 | zone + level 约束 | 低 | — |
| 密钥用途混用 | label 标记 but 无强制校验 | 中 | P3 |
| 降级攻击 | v0/v1 已废弃，仅保留 v2 | 低 | — |

---

## 5. 密钥生命周期

```
                        ┌──────────────┐
                        │  Agent 注册   │
                        └──────┬───────┘
                               │
                    ┌──────────▼──────────┐
                    │ 生成 6 把密钥          │
                    │ cert-sign + 5 purpose │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
               ┌─── │ 可选 AES-256-GCM 加密 │ ───┐
               │    └──────────┬──────────┘    │
               │               │               │
         有 master        无 master        有 master
               │               │               │
        密文 blob         明文 blob        密文 blob
               │               │               │
               └───────┬───────┘───────┬───────┘
                       │               │
              ┌────────▼────────┐      │
              │ IDN_SIGN: 签名请求│      │
              │ SESSION: ECDH   │      │
              │ 其他: 预留      │      │
              └────────┬────────┘      │
                       │               │
              ┌────────▼────────┐      │
              │   密钥轮换       │◄─────┘
              │ (非 root IDN)   │  kms_rotate_key
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │ 旧 key 打 revoked │
              │ 新 key 加密存储   │
              └─────────────────┘
```

---

## 6. 算法替换指南

每个密码学维度都通过 trait 定义，可以独立替换：

```rust
// crypto.rs 中的 5 个 trait
pub trait KeyEncryption: Send + Sync { ... }     // 替换密钥加密
pub trait KeyExchange: Send + Sync { ... }       // 替换密钥交换
pub trait KeyDerivation: Send + Sync { ... }     // 替换密钥派生
pub trait SessionCipher: Send + Sync { ... }     // 替换会话加密
pub trait RequestSigner: Send + Sync { ... }     // 替换请求签名

// CryptoProvider 聚合
pub struct CryptoProvider {
    pub key_encryption: Box<dyn KeyEncryption>,  // 默认: AES-256-GCM
    pub key_exchange: Box<dyn KeyExchange>,      // 默认: X25519
    pub key_derivation: Box<dyn KeyDerivation>,  // 默认: HKDF-SHA256
    pub session_cipher: Box<dyn SessionCipher>,  // 默认: AES-256-GCM
    pub request_signer: Box<dyn RequestSigner>,  // 默认: Ed25519
}
```

替换示例：

```rust
let mut crypto = CryptoProvider::default();
crypto.key_encryption = Box::new(MyChacha20Poly1305);
crypto.request_signer = Box::new(MyDilithiumSigner);
```

---

## 7. 历史教训

### P0-1: 非 Root Agent 的 IDN_SIGN 密钥为 EC P-256（已修复）

**问题**：`CertTool::issue_agent` 生成 P-256 证书密钥对（rcgen 默认），其 `bundle.key_pem` 被错误复用为 IDN_SIGN。仅 root 是真正的 Ed25519，其余 agent 的 IDN_SIGN 实际是 P-256。

**影响**：所有非 root agent 的 v2 请求 → 401 authentication failed。多 agent 协作场景完全无法运转。

**修复**：`agent_manager.rs:160-162` 为 IDN_SIGN 独立生成 Ed25519 密钥对。

### 根因

两个不同的密码系统被混淆：
- **cert-sign**：EC P-256，用于 X.509 证书签发（rcgen 默认）
- **IDN_SIGN**：Ed25519，用于 API 请求签名

它们的密钥不应共享。修复后各自独立生成。
