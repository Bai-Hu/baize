# 白泽全特性集成测试项目

## 项目概述

本项目对白泽（Baize）Agent 治理框架的全部 API 特性进行系统化集成测试。

**运行方式**:
```bash
# 运行全部集成测试
cargo test -p baize-server --test all_features_v0
cargo test -p baize-server --test all_features_v1
cargo test -p baize-server --test all_features_v2
cargo test -p baize-server --test all_features_e2e
cargo test -p baize-server --test all_features_security

# 或一次性运行全部
cargo test -p baize-server --test all_features_

# 仅运行特定模块
cargo test -p baize-server --test all_features_v0 -- v0_agent
cargo test -p baize-server --test all_features_security -- sec_zone
```

## 测试架构

```
crates/baize-server/tests/
├── common/mod.rs              # 共享测试基础设施
├── all_features_v0.rs         # v0 API 测试 (34 个用例)
├── all_features_v1.rs         # v1 API 测试 (22 个用例)
├── all_features_v2.rs         # v2 API 测试 (16 个用例)
├── all_features_e2e.rs        # 端到端场景 (4 个场景)
└── all_features_security.rs   # 安全模型测试 (16 个用例)
```

## 测试覆盖矩阵

### v0 API (MVP)

| 功能域 | 测试数量 | 覆盖要点 |
|--------|---------|---------|
| Agent 管理 | 7 | 注册、列表、撤销、父级约束、重复检测、level/zones 校验 |
| Blob 操作 | 5 | 写入、读取、查询、幂等性、认证要求 |
| Label 操作 | 2 | 添加、查询、重复检测 |
| Push/Pull | 2 | 推送、拉取、空工作区拒绝 |
| Git 操作 | 3 | Ref 列表、Log、Stats |
| Elevation | 3 | 申请、审批、归还、列表、越 scope 申请 |
| Trace | 1 | 四层身份链追溯 |
| Import/Export | 2 | 导入导出、trust_level 超限 |
| File 操作 | 5 | 读写删、列表、zone 检查、level0 拒绝 |
| Audit | 3 | 查询、按 agent 过滤、按 type 过滤 |

### v1 API (ASL 五域增强)

| 功能域 | 测试数量 | 覆盖要点 |
|--------|---------|---------|
| Intent (INT) | 4 | 创建、读取、查询、空约束拒绝、时间戳校验 |
| Sub-intent | 3 | 派生、约束收缩、depth 校验 |
| Authz (AZN) | 3 | 签发、空约束拒绝、委托、委托约束收缩 |
| AZN-VER | 1 | 五项校验（凭证真实性、有效性、意图引用、委托链、执行适用性） |
| Receipt (RCT) | 2 | 创建、查询、REJECTED 缺 reason 拒绝 |
| CNV | 1 | 收敛验证全链路 |
| Session (LNK) | 2 | 创建、接受、关闭、重复关闭 |
| IDN-LCM | 3 | 状态查询、更新、挂起阻断、恢复放行 |
| Proof (IDN-ATH) | 1 | 生成、v2 验证端点 |
| KMS | 2 | 密钥轮换、root IDN_SIGN 不可轮换 |
| 增强审计 | 2 | 链验证、chain_index 存在性 |

### v2 API (签名强制)

| 功能域 | 测试数量 | 覆盖要点 |
|--------|---------|---------|
| 强制签名 | 8 | Blob、File、Intent、Authz、Receipt、Session、KMS、Proof |
| Nonce 重放 | 2 | 相同 nonce 拒绝、不同 nonce 放行 |
| 签名错误 | 2 | 错误密钥、过期时间戳 |
| Proof 验证 | 1 | v2 专用验证端点 |

### 端到端场景

| 场景 | 说明 |
|------|------|
| E2E-1 完整部署生命周期 | 四层 Agent 树 + INT→AZN→RCT→CNV + File + Elevation + Audit |
| E2E-2 波次协作评审 | Mako-Wave 模式：并行意见→汇总→授权→回执→收敛 |
| E2E-3 跨 Agent 文件同步 | Push/Pull 双向同步、zone 过滤 |
| E2E-4 借权审批链 | 父子审批、非 parent 拒绝、root 豁免 |

### 安全模型

| 功能域 | 测试数量 | 覆盖要点 |
|--------|---------|---------|
| Level 权限 | 3 | L0 不能写、L0 可以读、L1 可以写 |
| Zone 隔离 | 3 | 同 zone 成功、跨 zone 拒绝、根级文件全局可读 |
| 委托链安全 | 3 | level 超限、zones 超限、深层链追溯 |
| 约束收缩 | 2 | 数值维度、数组维度 |
| 审计链 | 1 | 完整性验证、记录存在性 |
| 负面路径 | 1 | 10 个负面场景综合 |
| 凭证生命周期 | 1 | Active→Suspended→Active→Revoked 状态机 |
| 导出敏感数据 | 1 | sensitivity level 分级 |
| v2 签名边界 | 2 | 缺失头、篡改 body |

## 总计: ~92 个测试用例

## 特性覆盖完整度

| 特性 | 状态 |
|------|------|
| v0 Agent 管理 | ✅ 完全覆盖 |
| v0 Blob 操作 | ✅ 完全覆盖 |
| v0 Label 操作 | ✅ 完全覆盖 |
| v0 Push/Pull | ✅ 完全覆盖 |
| v0 Git 操作 | ✅ 完全覆盖 |
| v0 Elevation | ✅ 完全覆盖 |
| v0 Trace | ✅ 完全覆盖 |
| v0 Import/Export | ✅ 完全覆盖 |
| v0 File 操作 | ✅ 完全覆盖 |
| v0 Audit | ✅ 完全覆盖 |
| v1 Intent/Sub-intent | ✅ 完全覆盖 |
| v1 Authz/Delegation | ✅ 完全覆盖 |
| v1 AZN-VER | ✅ 完全覆盖 |
| v1 Receipt | ✅ 完全覆盖 |
| v1 CNV | ✅ 完全覆盖 |
| v1 Session | ✅ 完全覆盖 |
| v1 IDN-LCM | ✅ 完全覆盖 |
| v1 Proof | ✅ 完全覆盖 |
| v1 KMS | ✅ 完全覆盖 |
| v1 增强审计 | ✅ 完全覆盖 |
| v2 强制签名 | ✅ 完全覆盖 |
| v2 Nonce 防护 | ✅ 完全覆盖 |
| 安全模型 | ✅ 完全覆盖 |
| 端到端场景 | ✅ 完全覆盖 |
