# 泽图协议 v1 路线图

> 记录从 v0 到 v1 之间需要解决的协议级问题、建议和优先级。
> 更新时间: 2026-05-19
> 详细开发设计见: `zetu/V1_DEV.md`
> 白泽实现路线图见: `baize/V1_ROADMAP.md`

---

## 1. 当前 v0 状态

v0 实现已完成:
- blob 鉴权凭证存储（内容寻址，不可变）
- label 元数据（append-only，可查询）
- Agent 注册 + 证书链 + 身份追溯
- Zone/Level 权限模型
- 借权（Elevation）申请/审批流程
- 文件 I/O 网关代理（workspace）
- 审计日志（通过鉴权 blob + x-audit labels）
- HTTP API + CLI
- HTTP API 客户端中间件（`baize-middleware` crate）

**已完成的重构**:
- 主仓库已改为 Git 仓库（使用 git2 crate）
- 自实现的 commit/ref 机制已移除（commits/commit_blobs/refs 表已删除）
- push/pull 已重构：push 写入主仓库工作区，pull 从工作区同步文件
- blob_query 支持 limit/offset 分页
- git ref 操作（set/get/delete/list）已映射到 Git API
- repo/stats 端点已实现
- log 端点已改为 Git log

---

## 2. v1 范围总览

v1 在 v0 基础上扩展两大方向：

1. **ASL 合规** — 实现 IIFAA ASL V1.0 规范五类安全能力（INF / IDN / LNK / INT / AZN），支持与其他 ASL 合规 Agent 互操作
2. **安全增强** — 审计哈希链、请求签名认证、凭证生命周期管理

| 能力域 | ASL 对应 | v1 新增 | V1_DEV 状态 |
|--------|---------|---------|------------|
| INF-SEE | 安全执行环境 | SEE level 声明 | ✅ 已设计 |
| INF-KMS | 密钥管理 | 5 用途密钥隔离 + x-key-algorithm | ✅ 已设计 |
| IDN-ATT | 身份属性 | 三组属性 → label 映射 + binding_context_digest | ✅ 已设计 |
| IDN-LCM | 凭证生命周期 | 4 态状态机（Active/Suspended/Revoked/Decommissioned） | ✅ 已设计 |
| IDN-ATH | 运行态证明 | 短时证明 + CRED_ATH/RTP_ATH 双鉴别 | ✅ 已设计 |
| INT-GIR/DER/RCT/CNV | 意图表达 | 意图创建/派生/回执/全链路校验 | ✅ 已设计 |
| AZN-APR/ISS/DLG/VER | 授权 | 签发/委托/五项校验 | ✅ 已设计 |
| LNK-SES/DTX | 可信通讯 | ECDH 密钥协商 + AES-256-GCM 端到端加密 | ✅ 已设计 |
| 审计哈希链 | — | hash chain + 链验证 | ✅ 已设计 |
| 请求签名 | — | HMAC-SHA256 | ✅ 已设计 |
| 密钥加密存储 | — | AES-256-GCM | ✅ 已设计 |
| 借权运行时强制 | — | pipe_* 权限检查 + 过期/归还失效 | ⚠️ 未涉及 |
| 协议版本协商 | — | X-Protocol-Version + Supported-Versions | ⚠️ 未涉及 |
| 多实例信任 | — | 信任锚 + 跨实例验证 + 审计同步 | ⚠️ 未涉及 |

---

## 3. P0：已设计，待实现

### 3.1 请求签名认证

**问题**: 当前所有 API 请求通过 `agent_id` 字段标识身份，无签名、无验证。任何知道 agent_id 的人都可以冒充。

**已决策**：应用层 HMAC-SHA256 签名（非 mTLS，非 JWT）。

- 请求携带 `X-Agent-ID` + `X-Signature` + `X-Timestamp`
- 签名输入：`timestamp\nmethod\npath\nbody`
- 使用 INF-KMS 的 `IDN_SIGN` 用途密钥
- 时间戳 ±5 分钟窗口
- 实现位置：baize-server auth middleware

> 详细设计见 V1_DEV §4.1、§5.1

### 3.2 审计哈希链

**问题**: 审计记录之间没有链式关系，无法证明某条记录未被删除或遗漏。

**已决策**：hash chain，链头存储在 blob（type: audit-head）。

- 每条审计 blob 追加 `x-audit-prev` + `x-audit-chain-index` label
- 链头通过 blob 存储（`type: audit-head`），非 ref、非特殊 label
- verify_chain() 接口沿链向前追溯，校验完整性和序号连续性

> 详细设计见 V1_DEV §4.3、§5.6

### 3.3 密钥加密存储

**问题**: Agent 私钥以明文存储在数据库中。

**已决策**：AES-256-GCM，master secret 通过环境变量 `BAIZE_MASTER_SECRET` 或命令行参数传入。

> 详细设计见 V1_DEV §4.2

---

## 4. P1：v1 应处理

### 4.1 借权运行时强制 ⚠️ 未涉及

**问题**: 借权（Elevation）有申请/审批流程，但运行时不检查。agent 通过审批获得 zone Z 的读权限后，实际执行操作时不会验证 agent 是否真的有这个权限。

**建议**:
- `pipe_*` 系列方法在执行前检查 agent 当前权限（含已审批的借权）
- 借权过期自动失效
- 借权归还后立即失效

**当前状态**: V1_DEV 中 elevation.rs 标注"不变"，此条目未纳入设计。应在 v1 开发中补充。

### 4.2 协议版本协商 ⚠️ 未涉及

**问题**: 当前没有协议版本字段。客户端和服务端无法协商能力。

**建议**:
- HTTP API 增加 `X-Protocol-Version: zetu/1` 头
- 服务端返回 `Supported-Versions` 头
- 客户端不匹配时返回 `400 Unsupported Version`
- 与现有 URL 路径版本化（/api/v0 vs /api/v1）互补

**当前状态**: V1_DEV 仅用 URL 路径版本化，未包含协议版本头。

### 4.3 多实例信任 ⚠️ 未涉及

**问题**: 白泽当前是单实例。生产环境中可能需要多个白泽实例互相信任。

**建议**:
- 定义信任锚（Trust Anchor）：哪些 root CA 被信任
- 跨实例 agent 证书验证：验证对端 root CA 是否在信任锚中
- 跨实例审计同步：通过 push/pull 传递审计记录

**当前状态**: V1_DEV 和白泽 Roadmap 均未涉及。可在 v1 后期或 v2 处理。

---

## 5. ASL 合规能力（v1 新增主体）

以下能力均已设计（见 V1_DEV），此处列出协议级要点。

### 5.1 INF：安全执行环境 + 密钥管理

- **INF-SEE**: SEE level 声明（L1/L2/L3），复用 cert 扩展 + label 体系
- **INF-KMS**: 5 用途密钥隔离（IDN_SIGN / INT_SIGN / AZN_SIGN / RCT_SIGN / SESSION），每个 agent 最多 5 个 agent-key blob，通过 `x-key-purpose` + `x-key-algorithm` label 标注

### 5.2 IDN：身份管理

- **IDN-ATT**: 三组身份属性（主体状态 / 环境 / 实例状态）→ blob label 映射，`binding_context_digest` 聚合三组属性摘要
- **IDN-LCM**: 凭证四态（Active / Suspended / Revoked / Decommissioned），通过 agent-cert blob 标志 label 持久化（`x-cert-suspended` / `x-cert-revoked` / `x-cert-decommissioned`）
- **IDN-ATH**: 运行态证明（5 分钟短时 blob），CRED_ATH（凭证校验）+ RTP_ATH（运行态校验）双鉴别

### 5.3 INT：意图体系

- **INT-GIR**: 通用意图 blob，携带 `x-intent-id` / `x-intent-owner` / `x-intent-status` labels
- **INT-DER**: 子意图派生，`x-parent-intent` 构成链式引用，约束收缩校验（`constraint.rs`）
- **INT-RCT**: 执行回执，`x-receipt-intent` + `x-receipt-authz` 双摘要绑定
- **INT-CNV**: 全链路一致性校验（baize-asl/verify.rs），沿 label 引用链图遍历

### 5.4 AZN：授权体系

- **AZN-APR/ISS**: 授权签发，`x-source-intent` 关联意图
- **AZN-DLG**: 多级委托，`x-parent-authz` 构成委托链，约束收缩校验
- **AZN-VER**: 五项校验（凭证真实性 / 有效性 / 意图一致性 / 委托链完整性 / 执行适用性）

### 5.5 LNK：可信通讯

- **LNK-SES**: session-init / session-accept blob 交换，ECDH 密钥协商
- **LNK-DTX**: AES-256-GCM 端到端加密 blob content，服务端不持有会话密钥
- Channel 生命周期：init → accept → 加密消息 → close（`x-channel-closed` label）

---

## 6. P2：可推迟

| 问题 | 说明 | 推迟理由 |
|------|------|---------|
| Zone 层级 | 当前 zone 是扁平字符串，不支持 `prod/db/write` 这种层级 | MVP 阶段扁平足够，层级通过约定实现 |
| 分布式存储 | 当前 SQLite 单机存储 | 单机先验证协议正确性 |
| 并发控制 | blob write 无锁，commit 无事务 | 内容寻址天然幂等，commit 并发冲突概率低 |
| 传输加密 | HTTP 明文传输 | 部署在可信网络时不需要，生产用 TLS 反代 |
| 多租户 | 单实例单租户 | 协议级问题，v1 先验证单租户 |
| 配额/限流 | 无操作频率限制 | 运维层面问题，不影响协议设计 |
| 合规 | 无 GDPR/SOC2 相关设计 | 需要专门的合规分析，v1 先做技术正确 |

---

## 7. 实施顺序

v1 实施分两个并行主线：

**主线 A：安全增强（泽图原生）**
```
1. baize-core 基础（labels, errors, CredentialStatus, crypto, constraint）
   ↓
2a. 请求签名 middleware + agent_manager 扩展（INF/IDN）
```

**主线 B：ASL 合规**
```
2b. baize-asl crate（payload → adapter → verify）
```

**合并后**：
```
2a + 2b
   ↓
3. 业务能力（identity, INT/AZN/LNK type dispatch）
   ↓
4. 审计哈希链 + v1 API + CLI
   ↓
5. 集成测试 + 文档
```

> 白泽实现的详细分阶段计划见 `baize/V1_ROADMAP.md`

---

## 8. 设计决策记录

### 8.1 应用层 HMAC-SHA256 而非 mTLS

mTLS 需要 PKI 基础设施，对 Agent 客户端要求高。应用层 HMAC-SHA256 签名更灵活：
- Agent 只需持有自己的密钥
- 签名验证在应用层，不需要 TLS 终端配置
- 适合 CLI、HTTP API、SDK 多种接入方式
- 使用 INF-KMS IDN_SIGN 用途密钥

如果未来需要 mTLS，可以在反向代理层实现，不影响协议层签名。

### 8.2 HMAC-SHA256 而非 JWT

请求签名是即时验证，不需要跨服务传递。HMAC 更轻量，不需要额外的 JWT 库。签名密钥已通过 INF-KMS 管理。

### 8.3 Hash chain 而非 Merkle Tree

Hash chain 更简单，验证更容易。Merkle Tree 的优势（批量验证、部分证明）在审计场景中不是刚需。v1 先用 hash chain，如果性能成为问题再考虑 Merkle。

### 8.4 审计链头用 blob 而非 ref

审计链头存储方式从 ref 改为 blob（type: audit-head）：
- 统一存储原语（blob+label 是唯一原语）
- 不依赖 Git ref 机制
- 通过 label query 查询

### 8.5 LNK 端到端加密，服务端不持有密钥

会话密钥由客户端通过 ECDH 协商，服务端只管理 channel 状态（init/accept/seq/close）：
- 符合 ASL 端到端安全原则
- 降低服务端密钥泄露风险
- 服务端存储密文 blob

### 8.6 借权不是 P0

借权是 v0 引入的新特性，当前没有生产使用。P0 修复的是 v0 已有功能的安全问题（认证、审计、密钥）。借权强制是功能完善，不是安全修复。但作为 P1 应在 v1 中处理。
