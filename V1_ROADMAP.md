# 白泽 v1 开发路线图

> 基于 zetu/V1_STATUS.md 和 zetu/V1_DEV.md，规划白泽（泽图协议实现）从 v0.1 到 v1 的分阶段开发计划。
> 生成时间: 2026-05-19

---

## 依赖关系总览

```
Phase 0（准备）
  ↓
Phase 1（baize-core 基础）
  ↓
Phase 2（安全增强）──┐
                      ├── 可并行
Phase 3（baize-asl）─┘
  ↓
Phase 4（业务能力）
  ↓
Phase 5（审计 + API + CLI）
  ↓
Phase 6（集成测试 + 文档）
```

---

## Phase 0：准备工作

**目标**：建立 v1 开发分支，确认 v0.1 基线可测试。

| 任务 | 说明 | 产出 |
|------|------|------|
| 创建开发分支 | `git checkout -b v1-dev` | 分支 |
| v0.1 回归测试 | 确认现有测试全部通过 | 测试基线 |
| 梳理现有测试覆盖 | 记录哪些模块有测试、哪些没有 | 测试覆盖报告 |

**完成标准**：`cargo test` 全部通过，开发分支就绪。

---

## Phase 1：baize-core 基础设施

**目标**：为 v1 所有后续开发提供基础类型和常量。

| # | 任务 | 涉及文件 | 依赖 | 产出 |
|---|------|---------|------|------|
| 1.1 | label 常量集中管理 | `crates/baize-core/src/labels.rs`（新建） | 无 | 所有 v0 + v1 label 常量（含 IDN-ATT 三组属性映射、INF-KMS x-key-algorithm） |
| 1.2 | 错误类型扩展 | `crates/baize-core/src/error.rs` | 无 | ChannelClosed, ConstraintViolation, ChainBroken, SignatureInvalid, ExpiredTimestamp 等 |
| 1.3 | CredentialStatus 枚举 | `crates/baize-core/src/cert.rs` | 无 | Active/Suspended/Revoked/Decommissioned + CertIdentity.status 字段 |
| 1.4 | 约束收缩纯函数 | `crates/baize-core/src/constraint.rs`（新建） | 1.1 | verify_intent_constraint_reduction, verify_authz_constraint_reduction |
| 1.5 | 密钥加密存储 | `crates/baize-core/src/crypto.rs`（新建） | 1.2 | AES-256-GCM 加解密、master secret 管理 |

**完成标准**：
- `cargo test -p baize-core` 全部通过
- label 常量覆盖 zetu/V1_DEV §3.2 全部定义
- CredentialStatus 四种状态可序列化/反序列化
- crypto 模块可加密解密密钥对

---

## Phase 2：安全增强（可与 Phase 3 并行）

**目标**：请求签名认证 + agent_manager 扩展。

| # | 任务 | 涉及文件 | 依赖 | 产出 |
|---|------|---------|------|------|
| 2.1 | 请求签名 middleware | `crates/baize-server/src/pipeline/auth.rs`（新建） | 1.5, 1.2 | HMAC-SHA256 签名验证 Axum middleware |
| 2.2 | INF-SEE labels 扩展 | `crates/baize-server/src/pipeline/agent_manager.rs` | 1.1 | x-see-level/x-see-zones 注册支持 |
| 2.3 | INF-KMS 5 密钥注册 | `crates/baize-server/src/pipeline/agent_manager.rs` | 1.1, 1.5 | signing/encryption/transport/session/audit 密钥注册 + x-key-algorithm label |
| 2.4 | IDN-ATT 属性写入 | `crates/baize-server/src/pipeline/agent_manager.rs` | 1.1 | agent-cert labels 三组属性映射 |
| 2.5 | IDN-LCM 凭证生命周期 | `crates/baize-server/src/pipeline/agent_manager.rs` | 1.3 | credential_status / update_credential_status |
| 2.6 | IDN-TRC 凭证状态追溯 | `crates/baize-server/src/pipeline/agent_manager.rs` | 2.5 | trace_identity 增加 CredentialStatus 信息 |

**完成标准**：
- 请求签名 middleware 可拦截未签名请求
- Agent 注册时自动写入 INF-SEE、INF-KMS、IDN-ATT labels
- 凭证状态可在 Active/Suspended/Revoked/Decommissioned 间转换

---

## Phase 3：baize-asl 合规层（可与 Phase 2 并行）

**目标**：新建 baize-asl crate，实现 ASL 载荷定义、转换和校验。

| # | 任务 | 涉及文件 | 依赖 | 产出 |
|---|------|---------|------|------|
| 3.1 | 新建 crate 骨架 | `crates/baize-asl/Cargo.toml` + `src/lib.rs` | 无 | crate 结构 |
| 3.2 | payload.rs | `crates/baize-asl/src/payload.rs` | 3.1 | IntentContent, SubIntentContent, ReceiptContent, AuthorizationContent, RuntimeProofContent（字段统一 `_digest` 后缀） |
| 3.3 | adapter.rs | `crates/baize-asl/src/adapter.rs` | 3.2, 1.1 | ASL payload ↔ blob+label 双向转换 + binding_context_digest 计算 |
| 3.4 | verify.rs | `crates/baize-asl/src/verify.rs` | 3.3, 1.4 | 约束收缩校验 + CNV 全链路校验 + AZN-VER 五项校验 |

**完成标准**：
- `cargo test -p baize-asl` 全部通过
- payload 序列化/反序列化正确
- adapter 转换往返无损
- verify 模块可校验完整 CNV 链和 AZN 五项

---

## Phase 4：业务能力

**目标**：实现 v1 核心业务流（意图、授权、会话、身份）。

| # | 任务 | 涉及文件 | 依赖 | 产出 |
|---|------|---------|------|------|
| 4.1 | 运行态证明 + 身份鉴别 | `crates/baize-server/src/pipeline/identity.rs`（新建） | 2.x, 3.x | IDN-ATH：短时证明生成/过期、CRED_ATH + RTP_ATH 双鉴别 |
| 4.2 | INT type dispatch | `crates/baize-server/src/pipeline/data_ops.rs` | 3.x | intent / sub-intent / receipt blob 校验 + 约束检查 |
| 4.3 | AZN type dispatch | `crates/baize-server/src/pipeline/data_ops.rs` | 3.x | authorization blob 校验 + 委托子授权 + AZN-VER |
| 4.4 | LNK type dispatch | `crates/baize-server/src/pipeline/data_ops.rs` | 3.x | session-init/session-accept/channel 消息 + 端到端加密 blob |
| 4.5 | Baize struct 扩展 | `crates/baize-server/src/pipeline/mod.rs` | 3.x | 新增 `asl: AslContext` 字段 |

**完成标准**：
- 意图创建→派生→回执→CNV 校验完整流程可走通
- 授权签发→委托→AZN-VER 五项校验完整流程可走通
- 会话建立→加密消息→关闭可走通
- 运行态证明生成→过期→身份鉴别可走通

---

## Phase 5：审计增强 + API + CLI

**目标**：完善审计哈希链，暴露 v1 API 端点，扩展 CLI。

| # | 任务 | 涉及文件 | 依赖 | 产出 |
|---|------|---------|------|------|
| 5.1 | 审计哈希链 | `crates/baize-server/src/pipeline/auditor.rs` | 4.x | x-audit-prev + x-audit-chain-index + audit-head blob |
| 5.2 | 审计链验证 | `crates/baize-server/src/pipeline/auditor.rs` | 5.1 | verify_chain 接口 |
| 5.3 | v1 路由表 | `crates/baize-server/src/api.rs` | 4.x, 5.1 | 全部 v1 新增端点（见 zetu/V1_STATUS §2.5） |
| 5.4 | v0→v1 兼容 | `crates/baize-server/src/api.rs` | 5.3 | v0 端点在 /api/v1 下继续可用 |
| 5.5 | CLI 扩展 | `crates/baize-cli/src/main.rs` | 5.3 | intent / receipt / authz / channel / cnv / audit / agent 新命令 |

**完成标准**：
- 审计哈希链写入正确，链验证通过
- v1 全部 17 个新增 API 端点可用
- v0 端点在 /api/v1 下向后兼容
- CLI 可操作所有 v1 新增功能

---

## Phase 6：集成测试 + 文档

**目标**：端到端验证 + 文档更新。

| # | 任务 | 说明 |
|---|------|------|
| 6.1 | CNV 端到端测试 | 完整意图→子意图→回执→CNV 校验 |
| 6.2 | AZN-VER 端到端测试 | 授权→委托→AZN-VER 五项校验 |
| 6.3 | 审计链端到端测试 | 多次操作→审计链验证→防篡改验证 |
| 6.4 | 请求签名端到端测试 | 签名请求→验证→过期窗口→重放 |
| 6.5 | 会话加密端到端测试 | session-init→accept→加密消息→close |
| 6.6 | 更新 API.md | v1 API 文档 |
| 6.7 | 更新 PROTOCOL_SPEC_V1.md | 与实际实现对齐 |

**完成标准**：
- 全部集成测试通过
- API 文档与实际端点一致
- 协议规范与实现一致

---

## 风险与注意事项

| 风险 | 缓解措施 |
|------|---------|
| Phase 2 和 3 并行可能有 label 常量冲突 | Phase 1 先完成 label 定义，两个 Phase 共享 |
| data_ops 扩展改动范围大 | 保持 type dispatch 模式，每种 type 独立函数，避免互相影响 |
| 审计哈希链变更影响现有审计数据 | 链头为空时从零开始，不影响 v0 审计记录 |
| baize-asl 作为新 crate 需要单独测试 | payload → adapter → verify 逐层测试，每层独立可验证 |

---

## 里程碑检查点

| 里程碑 | Phase | 可验证产出 |
|--------|-------|-----------|
| M1: 基础就绪 | Phase 0 + 1 | `cargo test -p baize-core` 通过 |
| M2: 安全可用 | Phase 2 | 请求签名 middleware 生效，agent 注册含 INF/IDN labels |
| M3: ASL 合规 | Phase 3 | `cargo test -p baize-asl` 通过，CNV/AZN 校验逻辑就绪 |
| M4: 业务闭环 | Phase 4 | 意图/授权/会话全流程可走通 |
| M5: 接口完整 | Phase 5 | v1 API + CLI 全部可用 |
| M6: 发布就绪 | Phase 6 | 集成测试通过，文档完整 |
