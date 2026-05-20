# 泽图协议（Zétú Protocol）Specification v1

> **泽图** 取自《白泽图》。传说黄帝东巡遇神兽白泽，白泽通晓万物，能言人语。
> 黄帝命人将白泽所述天下万物之形貌习性记录成图，颁告天下。
> 泽图协议如其名 — 将 Agent 的交互记录为标准图谱，供所有系统查阅。

---

## 1 概述与协议边界

### 1.1 背景与定位

#### 背景

Agent 技术的快速发展使得自主化软件实体能够代表用户感知环境、制定计划并执行动作。当多个 Agent 协同完成任务时，它们需要在不同权限边界、不同系统层级之间传递身份、共享执行权、传递操作意图，并对执行结果承担可追溯的责任。

这一协作模式带来了核心安全挑战：Agent 的身份如何在动态环境中得到可验证的证明？用户的原始意图如何在多跳传递中保持语义连续性？授权边界如何在多级委托中严格不扩张？执行动作如何形成可追溯的事实记录？

泽图协议（Zétú Protocol）正是为应对上述挑战而设计。

#### 协议定位

泽图协议是一个 **符合 IIFAA ASL（Agent Security Link）V1.0 规范** 的 Agent 治理协议，同时提供 ASL 规范未覆盖的 Agent 治理扩展能力。

泽图协议的职责分为两层：

**ASL 合规层** — 泽图实现 ASL 协议定义的五类安全能力，支持与其他 ASL 合规 Agent 互操作：

- INF：安全执行环境声明与密钥管理
- IDN：可信身份 — 身份凭证、运行态证明、生命周期管理
- LNK：可信连接 — 会话管理、可信数据传输
- INT：可信意图 — 意图表达、意图派生、执行回执、全链路一致性校验
- AZN：可信授权 — 授权载荷、凭证签发、多级委托、授权校验

**泽图扩展层** — 泽图在 ASL 合规层之上提供 Agent 治理的扩展能力：

- Zone/Level 权限模型 — 数据隔离与权限等级
- Blob/Label 存储 — 内容寻址的不可变凭证存储与可扩展元数据
- Workspace 管理 — Agent 独立工作目录
- Push/Pull 同步 — Agent 与主仓库之间的数据同步
- 文件操作网关 — 代理式文件 I/O

两层之间的关系：

```
┌──────────────────────────────────────────────────┐
│              泽图扩展层（Zétú Extensions）          │
│  zone/level 治理 · blob/label 存储 · workspace    │
│  push/pull 同步 · 文件网关 · 审计哈希链            │
├──────────────────────────────────────────────────┤
│              ASL 合规层（ASL Compliance）           │
│  INF 执行环境 · IDN 身份 · LNK 连接                │
│  INT 意图 · AZN 授权                               │
│  符合 ASL 安全规范 · 支持与其他 ASL Agent 互操作     │
└──────────────────────────────────────────────────┘
```

**适配层**：泽图内部使用 blob+label 存储 ASL 载荷，对外通讯使用 ASL 定义的载荷格式。两层之间通过适配层完成字段映射和格式转换。

泽图协议不替代底层传输加密（如 TLS），不定义具体业务流程，不替代业务系统的访问控制或风控决策。

### 1.2 协议范围

#### 协议规范范围

泽图协议规范覆盖以下内容：

**ASL 合规部分：**

- ASL INF 能力的泽图实现：执行环境声明与密钥管理要求
- ASL IDN 能力的泽图实现：身份凭证产生与校验、运行态证明、生命周期管理
- ASL LNK 能力的泽图实现：会话建立、维护、关闭与可信数据传输
- ASL INT 能力的泽图实现：通用意图表达、意图派生、执行回执、全链路一致性校验
- ASL AZN 能力的泽图实现：授权载荷表达、凭证签发、多级委托、授权校验

**泽图扩展部分：**

- Blob/Label 对象模型与操作
- Zone/Level 权限模型
- Agent 注册、撤销与身份追溯
- Workspace 管理与文件操作网关
- Push/Pull 数据同步
- 审计记录与审计哈希链

#### 不在协议规范范围内

以下技术组件和问题不在泽图协议规范覆盖范围之内：

- 承载泽图协议实现的宿主应用逻辑
- 底层网络传输机制（如 TLS）
- 业务语义正确性验证、账户体系、KYC、监管报备
- 密钥的物理存储方式和硬件安全模块的具体实现
- 拒绝服务防护

#### 部署依赖条件

泽图协议的正确运行依赖以下外部条件，由部署方负责满足：

- 宿主应用负责将业务语义映射为协议载荷输入
- 密钥材料存储在与声明的 SEE 等级相符的保护环境中
- 验证方能够通过可靠渠道获取信任锚材料（root CA 证书等）
- 网络传输层提供基础的传输机密性和连接完整性（如 TLS）

### 1.3 规范性用语

本协议采用以下规范性用语：

- **应 (SHALL)** — 必须满足的要求
- **不应 (SHALL NOT)** — 必须避免的要求
- **宜 (SHOULD)** — 推荐满足的要求
- **不宜 (SHOULD NOT)** — 建议避免的要求
- **可 (MAY)** — 可选满足的要求

关于字段存在性：

- **必备** — 字段必须存在且具备有效值
- **条件必备** — 在特定条件成立时必须存在且具备有效值
- **可选** — 字段允许存在，存在时值必须有效

### 1.4 版本兼容性（v0 → v1）

v1 是 v0 的超集，向后兼容。v0 的所有 blob 类型和操作在 v1 中继续有效，v1 新增能力不影响 v0 实现。具体兼容清单见 §5.3 和 §13.9。

---

## 2 术语与缩略语

### 2.1 术语

| 术语 | 定义 |
|------|------|
| **Agent（智能体）** | 参与协作的自主化软件实体，具有可验证身份，能够代表用户或上游委托方执行动作 |
| **blob** | 内容寻址的不可变凭证，SHA-256 hash 作为唯一标识，所有协议载荷统一以 blob 承载 |
| **label** | 挂载在 blob 上的 key-value 元数据，append-only（可追加新 key，不可修改或删除已有 key） |
| **zone** | 数据隔离区域标签，Agent 只能操作自身 zone 范围内的数据，`"*"` 表示通配 |
| **level** | Agent 权限等级（0-4），子 Agent 的 level 严格小于父 Agent |
| **workspace** | Agent 的独立工作目录，与主仓库隔离，通过 push/pull 同步 |
| **主仓库（main repo）** | Git 仓库，存储所有经过 commit 推送的数据，提供版本历史、分支、标签 |
| **审计哈希链（audit hash chain）** | 审计 blob 通过 prev-hash 串联形成的防篡改链，链头存储在 ref 中 |
| **身份追溯（identity tracing）** | 从指定 Agent 到 root 的证书签发链追踪 |
| **借权（elevation）** | Agent 临时申请超出自身 scope 的权限，需审批 |
| **Push** | Agent 将 workspace 文件推送到主仓库工作区 |
| **Pull** | 从主仓库工作区拉取文件到 Agent workspace |

以下术语的定义参见 ASL 规范 §2：

| 术语 | 说明 |
|------|------|
| 签发方（Issuer） | 签发身份凭证或授权凭证的可信主体 |
| 验证方（Verifier） | 对协议载荷执行校验的主体 |
| 执行方（Executor） | 实际执行授权动作并签发执行回执的主体 |
| 身份凭证（Identity Credential） | 绑定主体身份属性与公钥材料的凭证 |
| 运行态证明（Runtime Proof） | 携带实例状态属性的短时有效证明材料 |
| 通用意图（General Intent） | 用户或上游的原始目标与约束的结构化表达 |
| 子意图（Sub-Intent） | 从上游意图派生的意图，约束只能收缩不能扩张 |
| 授权载荷（Authorization Payload） | 描述执行方被授权的操作边界与约束的结构化载荷 |
| 授权凭证（Authorization Credential） | 授权载荷签名后形成的可验证凭证 |
| 执行回执（Execution Receipt） | 执行完成后由执行方签名生成的可验证执行事实记录 |
| 委托（Delegation） | 将部分执行权授予下游主体的行为 |
| 约束收缩规则（Constraint Reduction Rules） | 子意图或子授权的约束维度只能收缩不能扩张的规则 |
| 全链路一致性校验（Convergence Verification） | 从原始意图经授权到执行回执的完整性校验 |
| 联动失效（Cascading Invalidation） | 上游凭证吊销时，下游凭证同步失效 |

### 2.2 缩略语

| 缩略语 | 全称 | 说明 |
|--------|------|------|
| ASL | Agent Security Link | IIFAA 智能体安全可信互连协议 |
| INF | Infrastructure | 安全基础设施能力域 |
| IDN | Identity | 可信身份能力域 |
| LNK | Link | 可信连接能力域 |
| INT | Intent | 可信意图能力域 |
| AZN | Authorization | 可信授权能力域 |
| SEE | Secure Execution Environment | 安全执行环境 |
| KMS | Key Management System | 密钥管理体系 |
| CNV | Convergence Verification | 全链路一致性校验 |

### 2.3 组件代码表

| 组件代码 | 组件名称 | 所在章节 |
|---------|---------|---------|
| ZETU-INF-SEE | 安全执行环境声明 | §6.2 |
| ZETU-INF-KMS | 密钥管理要求 | §6.3 |
| ZETU-IDN-REG | Agent 注册与凭证签发 | §7.2 |
| ZETU-IDN-LCM | 凭证生命周期管理 | §7.3 |
| ZETU-IDN-ATH | 身份鉴别与运行态证明 | §7.4 |
| ZETU-IDN-TRC | 身份链追溯 | §7.5 |
| ZETU-LNK-SES | 会话管理 | §8.2 |
| ZETU-LNK-DTX | 可信数据传输 | §8.3 |
| ZETU-INT-GIR | 通用意图表达 | §9.2 |
| ZETU-INT-DER | 意图派生 | §9.3 |
| ZETU-INT-RCT | 执行回执 | §9.4 |
| ZETU-INT-CNV | 全链路一致性校验 | §9.5 |
| ZETU-AZN-APR | 授权载荷 | §10.2 |
| ZETU-AZN-ISS | 授权凭证签发 | §10.3 |
| ZETU-AZN-DLG | 多级委托 | §10.4 |
| ZETU-AZN-VER | 授权校验 | §10.5 |
| ZETU-AUDIT-LOG | 审计记录 | §11.2 |
| ZETU-AUDIT-CHAIN | 审计哈希链 | §11.3 |
| ZETU-AUDIT-VERIFY | 链完整性验证 | §11.4 |

---

## 3 安全模型

本章定义泽图协议的安全模型，采用与 ASL 相同的"安全问题（威胁/假设/约束）→ 安全目标 → 能力要求"推导链。使用 T.XXX 标识威胁、A.XXX 标识假设条件、P.XXX 标识设计约束、O.XXX 标识安全目标。

### 3.1 保护资产

| 资产标识 | 资产名称 | 说明 |
|---------|---------|------|
| ASSET.IDENTITY | Agent 身份材料 | 公钥、证书、身份属性、运行环境绑定证明。核心保护属性为真实性与完整性 |
| ASSET.SESSION | 会话上下文 | 会话标识、交互记录、上下文绑定关系。核心保护属性为完整性 |
| ASSET.AUTHZ_CHAIN | 授权凭证链 | 从根授权到末端执行的授权载荷、凭证及委托引用关系。核心保护属性为完整性与不可扩张性 |
| ASSET.INTENT | 意图载荷与执行回执 | 原始意图、派生子意图及执行回执。核心保护属性为完整性与语义连续性 |
| ASSET.AUDIT | 审计记录 | 操作日志与审计哈希链。核心保护属性为完整性与不可篡改性 |
| ASSET.KEY | 密钥材料 | Agent 私钥及签名记录。核心保护属性为机密性与不可导出性 |

### 3.2 威胁定义

本节威胁分析在 A.CRYPTO_STRENGTH 假设成立的前提下有效。

| 威胁标识 | 威胁名称 | 攻击行为描述 | 受影响资产 |
|---------|---------|-------------|-----------|
| T.IDENTITY_SPOOFING | 身份伪造 | 攻击者伪造、重放或替换 Agent 身份材料，冒充合法 Agent 发起交互 | ASSET.IDENTITY |
| T.ENV_COMPROMISE | 执行环境破坏 | 攻击者破坏或伪造执行环境证明材料，使不可信环境通过可信验证 | ASSET.IDENTITY, ASSET.KEY |
| T.SESSION_ATTACK | 会话攻击 | 攻击者重放历史会话消息、劫持会话或实施跨会话混淆 | ASSET.SESSION, ASSET.INTENT, ASSET.AUTHZ_CHAIN |
| T.KEY_ABUSE | 密钥滥用 | 攻击者在未获授权的情况下调用密钥执行签名操作 | ASSET.KEY, ASSET.AUTHZ_CHAIN |
| T.DELEGATION_ESCALATION | 委托越权 | 攻击者在委托过程中扩大授权边界，使下游凭证权限超出原始授权 | ASSET.AUTHZ_CHAIN |
| T.INTENT_FORGERY | 意图伪造 | 攻击者替换或篡改意图载荷，改变执行方实际收到的任务指令语义 | ASSET.INTENT, ASSET.AUTHZ_CHAIN |
| T.RECEIPT_FORGERY | 回执伪造 | 攻击者伪造或篡改执行回执，虚构未发生的执行事实 | ASSET.INTENT |
| T.KEY_COMPROMISE | 密钥泄露 | 攻击者获取 Agent 私钥的实质控制权，或因缺乏有效吊销机制导致泄露密钥持续被信任 | ASSET.KEY, ASSET.IDENTITY, ASSET.AUTHZ_CHAIN |
| T.AUDIT_TAMPER | 审计篡改 | 攻击者删除或篡改审计记录，破坏操作可追溯性 | ASSET.AUDIT |

### 3.3 假设条件

以下条件由部署方负责满足，不属于协议实现范围。

| 假设标识 | 假设名称 | 说明 |
|---------|---------|------|
| A.CRYPTO_STRENGTH | 密码学强度 | 本协议采用的密码学原语在预期生命周期内具备足够安全强度 |
| A.SEE_INTEGRITY | 执行环境完整性 | 实现声明的 SEE 等级对应的隔离性质在运行期间持续成立 |
| A.KEY_PROTECTION | 密钥保护 | 私钥材料存储在与声明 SEE 等级相符的保护环境中，未以明文暴露于协议运行边界之外 |
| A.TRUST_MATERIAL | 信任材料 | 验证方能够通过可靠渠道获取并校验信任锚材料（root CA 证书等） |
| A.CANONICAL_CONSISTENCY | 规范化一致性 | 同一部署中的签发方与验证方对载荷采用一致的规范化规则 |
| A.TIME_SOURCE | 时间与状态 | 实现能够获取满足协议要求的可信时间来源；吊销状态查询服务在协议规定时效内可达 |

### 3.4 设计约束

以下约束来源于安全工程实践的要求，是安全目标推导的依据。

| 约束标识 | 约束名称 | 说明 |
|---------|---------|------|
| P.CONSTRAINT_REDUCTION | 约束收缩 | 子意图和子授权的约束只能在父级基础上收缩，不能扩张 |
| P.AUDIT_TRACEABILITY | 审计可追溯 | 执行动作与其授权依据、意图来源和执行主体之间存在可验证的引用关系 |
| P.IMMUTABLE_RECORD | 记录不可变 | blob 一旦写入不可修改、不可删除 |
| P.APPEND_ONLY_METADATA | 元数据追加 | label 可追加新 key，不可修改或删除已有 key |
| P.PURPOSE_SEPARATION | 用途隔离 | 不同用途的密钥应相互隔离，不得跨用途复用 |
| P.LEAST_DISCLOSURE | 最小披露 | 载荷中携带的信息以完成当前交互所需的最小集合为限 |

### 3.5 安全目标

#### 协议安全目标

以下安全目标由各能力域模块落实。

| 目标标识 | 目标名称 | 说明 | 覆盖来源 |
|---------|---------|------|---------|
| O.IDENTITY_BINDING | 身份绑定 | 建立 Agent 主体、公钥材料与运行环境之间的可验证绑定关系 | T.IDENTITY_SPOOFING, T.ENV_COMPROMISE, A.CRYPTO_STRENGTH, A.TRUST_MATERIAL, P.LEAST_DISCLOSURE |
| O.SESSION_BINDING | 会话绑定 | 建立基于身份验证的会话绑定机制，防止会话劫持、重放和跨会话混淆 | T.SESSION_ATTACK, A.CRYPTO_STRENGTH, A.CANONICAL_CONSISTENCY, A.TIME_SOURCE |
| O.DELEGATION_CONTROL | 委托控制 | 授权边界在多级委托中严格不扩张，委托链可验证，委托深度受限 | T.DELEGATION_ESCALATION, T.INTENT_FORGERY, A.TIME_SOURCE, P.CONSTRAINT_REDUCTION |
| O.INTENT_CONTINUITY | 意图连续性 | 原始意图在跨主体传递和多级派生中保持语义连续性，子意图约束不超出父意图，全链路可验证 | T.INTENT_FORGERY, T.RECEIPT_FORGERY, A.CANONICAL_CONSISTENCY, P.AUDIT_TRACEABILITY |
| O.EXECUTION_PROOF | 执行证明 | 为每次执行动作生成可验证的执行回执，包含执行主体、授权依据和执行结果 | T.RECEIPT_FORGERY, P.AUDIT_TRACEABILITY |
| O.KEY_CONTROL | 密钥访问控制 | 密钥调用受访问控制策略约束，密钥用途隔离得到执行 | T.KEY_ABUSE, T.ENV_COMPROMISE, A.KEY_PROTECTION, P.PURPOSE_SEPARATION |
| O.LIFECYCLE_INTEGRITY | 生命周期完整性 | 身份凭证和授权凭证具备生命周期管理机制，上游凭证吊销时下游凭证联动失效 | T.KEY_COMPROMISE, T.DELEGATION_ESCALATION, P.AUDIT_TRACEABILITY |

#### v1 实施范围

| 安全目标 | v1 状态 | 说明 |
|---------|--------|------|
| O.IDENTITY_BINDING | **v1 实现** | 完整实现 |
| O.SESSION_BINDING | **v1 实现** | 完整实现 |
| O.DELEGATION_CONTROL | **v1 实现** | 完整实现 |
| O.INTENT_CONTINUITY | **v1 实现** | 完整实现 |
| O.EXECUTION_PROOF | **v1 实现** | 完整实现 |
| O.KEY_CONTROL | **v1 渐进** | 基础密钥用途隔离；控制证明和密钥证明标记为后续版本 |
| O.LIFECYCLE_INTEGRITY | **v1 渐进** | 基础凭证状态管理和联动失效；吊销推送机制标记为后续版本 |

### 3.6 安全目标索引（目标 → 能力域）

| 安全目标 | 落实模块 |
|---------|---------|
| O.IDENTITY_BINDING | ZETU-IDN-REG, ZETU-IDN-ATH |
| O.SESSION_BINDING | ZETU-LNK-SES, ZETU-LNK-DTX |
| O.DELEGATION_CONTROL | ZETU-AZN-APR, ZETU-AZN-ISS, ZETU-AZN-DLG, ZETU-AZN-VER, ZETU-INT-CNV |
| O.INTENT_CONTINUITY | ZETU-INT-GIR, ZETU-INT-DER, ZETU-INT-CNV, ZETU-AZN-APR |
| O.EXECUTION_PROOF | ZETU-INT-RCT, ZETU-INT-CNV |
| O.KEY_CONTROL | ZETU-INF-KMS, ZETU-INF-SEE |
| O.LIFECYCLE_INTEGRITY | ZETU-IDN-LCM, ZETU-AZN-VER, ZETU-INT-CNV |

---

## 4 协议架构

### 4.1 概述（核心原语 + 能力域分层）

泽图协议采用"核心原语 + 能力域"的分层结构。核心原语为 blob 和 label，所有协议载荷统一以 blob 承载、以 label 标注元数据。能力域在核心原语之上构建，分为 ASL 合规层和泽图扩展层。

```
┌─────────────────────────────────────────────────────────┐
│                   泽图扩展层                              │
│  审计能力 (AUDIT)                                        │
│  审计哈希链 · 操作记录 · 链完整性验证                      │
├─────────────────────────────────────────────────────────┤
│                   ASL 合规层                              │
│                                                          │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│   │  可信身份  │  │  可信连接  │  │  可信意图  │  │ 可信授权 │ │
│   │  (IDN)   │  │  (LNK)   │  │  (INT)   │  │  (AZN)  │ │
│   └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬────┘ │
│        │              │              │              │      │
│   ┌────┴──────────────┴──────────────┴──────────────┴───┐ │
│   │        安全基础设施能力 (INF)                         │ │
│   │        执行环境声明 · 密钥管理要求                     │ │
│   └─────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────┤
│                   核心原语层                               │
│          Blob（不可变凭证）· Label（可扩展元数据）            │
└─────────────────────────────────────────────────────────┘
```

### 4.2 模块分组

#### 基础设施层（INF）

INF 能力域包含安全执行环境声明（INF-SEE）和密钥管理要求（INF-KMS），构成协议的执行基础层。INF 层是所有上层能力模块的执行前提。

#### 能力模块层

**IDN — 可信身份**

IDN 能力域（REG/LCM/ATH/TRC）负责建立和维护 Agent 的可验证身份，直接落实 O.IDENTITY_BINDING，并为 LNK、AZN、INT 提供身份基础。

**LNK — 可信连接**

LNK 能力域（SES/DTX）在 IDN 身份基础之上建立会话级安全通道，落实 O.SESSION_BINDING。

**INT — 可信意图**

INT 能力域（GIR/DER/RCT/CNV）负责意图的结构化表达、跨主体派生、执行回执生成和全链路一致性校验，落实 O.INTENT_CONTINUITY 和 O.EXECUTION_PROOF。

**AZN — 可信授权**

AZN 能力域（APR/ISS/DLG/VER）负责授权载荷的结构化表达、凭证签发、多级委托和验证，落实 O.DELEGATION_CONTROL。

#### 审计层（AUDIT）

审计能力（LOG/CHAIN/VERIFY）为所有写操作提供不可篡改的事实记录，跨域横切。

### 4.3 依赖关系图

```
INF ──────────────────────────────────────────────────────
 │                                                        │
 ├──→ IDN ──→ LNK                                        │
 │     │                  │                               │
 │     │           ┌──────┴──────┐                        │
 │     │           ↓             ↓                        │
 │     ├──→ INT ←────── AZN ←───┘                         │
 │     │      ↑                                            │
 │     │      └── CNV（横跨 INT/AZN/IDN）                  │
 │     │                                                   │
 └─────┴──→ AUDIT（所有写操作的横切关注点）                  │
                                                           
核心原语：blob + label（所有模块共用）
```

依赖方向：
- INF 是最底层，所有模块依赖
- IDN 是身份基础，LNK/AZN/INT 依赖 IDN
- LNK 依赖 IDN（会话需要身份）
- AZN 依赖 IDN（授权需要身份）和 INT（授权引用意图）
- INT 依赖 IDN（意图需要身份）
- CNV 横跨 INT/AZN/IDN（全链路校验）
- AUDIT 横跨所有域（所有写操作自动审计）

---

## 5 对象模型

### 5.1 Blob

```
Blob {
    hash:       string    // SHA-256(content), 由实现计算
    content:    string    // 凭证内容（ASL 载荷经适配层转换后存储）
    created_at: datetime  // ISO 8601 UTC, 由实现自动设置
    labels:     map<string, string>  // 可扩展元数据
}
```

**语义：**

- blob 是不可变凭证，内容寻址，相同 content 产生相同 hash
- blob 一旦写入不可修改、不可删除
- created_at 由实现在写入时自动设置
- labels 在写入时指定初始值，写入后为 append-only
- 所有 ASL 载荷（身份凭证、意图、授权、回执等）通过适配层转换为 blob content 存储

**ASL 载荷映射：**

对外通讯使用 ASL 定义的载荷格式和字段名。对内存储时，ASL 载荷序列化为 blob content，ASL 载荷中需要查询的字段同步存储为 label。

| ASL 载荷 | blob type | 详细定义 |
|---------|-----------|---------|
| 身份凭证 | `agent-cert` | §7.2 |
| 通用意图 | `intent` | §9.2 |
| 子意图 | `sub-intent` | §9.3 |
| 授权载荷 | `authorization` | §10.2 |
| 执行回执 | `receipt` | §9.4 |
| 会话上下文 | `session` | §8.2 |
| 运行态证明 | `runtime-proof` | §7.4 |

### 5.2 Label

```
Label {
    entity_hash:  string    // 挂载的 blob hash
    key:          string    // 键
    value:        string    // 值
}
```

**语义：**

- label 是 key-value 对，挂在 blob 上
- 同一 blob 可有多个 label
- label 是 append-only：可追加新 key，不可修改或删除已有 key
- 同一 (entity_hash, key) 组合重复添加返回冲突错误
- label 支持按 key+value 查询，用于路由和过滤

**Label 命名空间：**

| 前缀 | 命名空间 | 说明 | 示例 |
|------|---------|------|------|
| 无前缀 | 内建 | 协议定义的 label | `type`, `parent` |
| `x-` | 能力域扩展 | 各能力域的元数据 | `x-intent-id`, `x-authz-status`, `x-audit-prev` |
| `com.xxx.` | 私有扩展 | 私有命名空间 | `com.acme.score` |

### 5.3 Blob 类型体系

blob 的 `type` label 标明其用途。

**v0 继承：**

| type 值 | 用途 |
|---------|------|
| `audit` | 审计记录，所有写操作自动产生 |
| `agent-cert` | Agent 证书 |
| `agent-key` | Agent 私钥 |
| `root-ca` | Root CA 证书 |
| `file` | 文件操作凭证 |
| `push-auth` | Push 操作鉴权凭证 |
| `elevation-request` | 借权请求 |

**v1 新增（ASL 合规）：**

| type 值 | 用途 | 详细定义 |
|---------|------|---------|
| `intent` | 通用意图 | §9.2 |
| `sub-intent` | 子意图（约束收缩） | §9.3 |
| `receipt` | 执行回执 | §9.4 |
| `authorization` | 授权载荷 | §10.2 |
| `session` | 会话上下文 | §8.2 |
| `runtime-proof` | 运行态证明 | §7.4 |

实现 SHALL 为每个 blob 设置 `type` label。自定义类型使用 `x-` 前缀。

---

## 6 安全基础设施能力（INF）

### 6.1 能力定位与安全目标对应

INF 能力域是泽图协议所有上层能力模块的执行前提，直接落实 O.KEY_CONTROL，并对应部署前提要求。安全目标映射见 §3.6。

泽图的 INF 实现采用自己的方式：以 blob+label 承载环境声明和密钥元数据，不规定具体的硬件安全模块或 TEE 实现。

### 6.2 INF-SEE：安全执行环境声明

#### 功能描述

定义泽图实现对运行环境隔离能力的分级声明。协议实现在部署时声明其 SEE 等级，并通过环境证明材料证明声明的真实性。SEE 等级约束了协议实现可声称的密钥保护能力和环境证明能力的上限。

#### SEE 等级定义

| 等级 | 名称 | 描述 |
|------|------|------|
| SEE-L1 | 软件隔离级 | 通过进程隔离、内存保护或容器机制实现运行隔离。密钥依赖软件保护，无硬件级证明能力 |
| SEE-L2 | 硬件隔离级 | 基于 TEE 技术实现硬件级隔离。支持密钥不可导出和远程证明能力 |
| SEE-L3 | 高保障级 | 基于专用安全元件。在 SEE-L2 基础上强化物理攻击防护和侧信道防护 |

#### SEE 状态声明

Agent 注册时通过 agent-cert blob 的 labels 声明 SEE 状态：

| label key | 值域 | 说明 |
|-----------|------|------|
| `x-see-level` | `L1` / `L2` / `L3` | 声明的 SEE 等级 |
| `x-see-environment-id` | string | 执行环境实例标识 |
| `x-see-platform-state` | `verified` / `failed` / `unknown` | 平台完整性状态 |
| `x-see-attestation-support` | `true` / `false` | 是否支持环境证明 |

#### 安全要求

- 载荷的规范化表示、摘要计算和签名调用 **应** 在声明的 SEE 等级对应的环境中完成
- SEE 等级声明 **不应** 高于实际能力
- 当部署环境无法满足声明等级时，相关载荷的生成 **应** 被拒绝
- 高风险操作（如大额支付、关键凭证签发）**宜** 要求 SEE-L2 以上

### 6.3 INF-KMS：密钥管理要求

#### 功能描述

定义泽图协议实现中密钥管理的规范性要求。KMS 为所有上层模块的签名操作和密钥调用提供访问控制执行点。

#### 密钥用途隔离

密钥按用途分类，不得跨用途复用：

| 用途标识 | 说明 |
|---------|------|
| `IDN_SIGN` | 身份凭证签名 |
| `INT_SIGN` | 意图载荷签名 |
| `AZN_SIGN` | 授权凭证签名 |
| `RCT_SIGN` | 执行回执签名 |
| `SESSION` | 会话密钥派生 |

#### 密钥注册信息

Agent 的 agent-key blob 通过 labels 记录密钥元数据：

| label key | 值域 | 说明 |
|-----------|------|------|
| `x-key-purpose` | `IDN_SIGN` / `INT_SIGN` / `AZN_SIGN` / `RCT_SIGN` / `SESSION` | 密钥用途 |
| `x-key-owner` | agent ID | 密钥所属 Agent |
| `x-key-see-level` | `L1` / `L2` / `L3` | 绑定的最低 SEE 等级 |
| `x-key-nonexportable` | `true` / `false` | 是否禁止明文导出 |
| `x-key-algorithm` | string | 允许的算法 |

#### 安全要求

- 密钥 **应** 按用途隔离，不得跨用途复用（落实 P.PURPOSE_SEPARATION）
- 私钥 **应** 加密存储，不以明文暴露于协议运行边界之外（落实 A.KEY_PROTECTION）
- 密钥调用 **应** 受访问控制策略约束
- 高权限密钥调用 **宜** 生成控制证明（control proof）
- v1 渐进实现：基础密钥用途隔离和加密存储为 v1 必备；控制证明和密钥证明标记为后续版本

---

## 7 可信身份能力（IDN）

### 7.1 能力定位与安全目标对应

IDN 能力域负责建立和维护 Agent 的可验证身份，直接落实 O.IDENTITY_BINDING 和 O.LIFECYCLE_INTEGRITY。IDN 同时为 LNK、AZN、INT 提供身份基础。安全目标映射见 §3.6。

### 7.2 IDN-REG：Agent 注册与凭证签发（v0 继承）

#### 功能描述

注册 Agent 时签发 PKI 证书，建立从 root 到子 Agent 的证书层级。注册过程产生 `root-ca`、`agent-cert`、`agent-key` 三个 blob。

#### 注册请求

```
POST /agents
x-agent-id: <parent-agent-id>

{
  "name": "agent-name",
  "level": 3,
  "zones": ["zone-a", "zone-b"],
  "parent_id": "baize-root"
}
```

| 字段 | 存在性 | 说明 |
|------|--------|------|
| name | 必备 | Agent 名称，全局唯一 |
| level | 必备 | 权限等级 0-4 |
| zones | 必备 | 可操作的 zone 列表，`["*"]` 表示全部 |
| parent_id | 可选 | 父 Agent ID，默认 root |

#### 产生 blob

| blob type | content | labels |
|-----------|---------|--------|
| `root-ca` | PEM（仅初始化时产生） | `type: root-ca` |
| `agent-cert` | PEM 证书 | `type: agent-cert`, `x-cert-agent: <name>`, `x-cert-level: <level>`, `x-cert-parent: <parent>`, `x-cert-zones: <zones>`, `x-cert-status: active` |
| `agent-key` | PEM 加密私钥 | `type: agent-key`, `x-key-owner: <name>`, `x-key-purpose: IDN_SIGN`, `x-key-nonexportable: true` |

#### 规则

- 子 Agent 的 level **应** 严格小于父 Agent 的 level
- 子 Agent 的 zones **应** 是父 Agent zones 的子集（父含 `"*"` 时无限制）
- 名称 **不应** 重复
- root Agent **不应** 被撤销
- 注册 **应** 自动生成审计记录

### 7.3 IDN-LCM：凭证生命周期管理（v1 新增）

#### 功能描述

定义 Agent 证书的生命周期管理规范，包括凭证状态定义、状态迁移规则和联动失效机制。

#### 凭证状态

| status 值 | 说明 |
|-----------|------|
| `active` | 正常有效，可用于身份鉴别 |
| `suspended` | 临时暂停，不可用于新鉴别（可恢复） |
| `revoked` | 永久吊销（终态，不可逆） |
| `expired` | 自然过期（终态，不可逆） |

凭证状态通过运行时状态机维护。状态变更同步持久化（用于重启恢复），并自动生成审计记录。

#### 状态迁移

| 当前状态 | 目标状态 | 触发条件 | 可逆 |
|---------|---------|---------|------|
| `active` | `suspended` | 疑似安全异常，待核查 | 是 |
| `active` | `revoked` | 密钥泄露确认，安全事件 | 否（终态） |
| `suspended` | `active` | 核查通过 | — |
| `suspended` | `revoked` | 确认安全问题 | 否（终态） |
| 任意 | `expired` | 自然过期 | 否（终态） |

`revoked` 和 `expired` 为终态。若需恢复 Agent 的交互能力，**应** 重新签发新凭证。

#### 联动失效

Agent 证书被吊销后：

- 依赖该证书签发的所有 authorization blob 在 AZN-VER 校验时 **应** 被识别为无效
- 基于该证书建立的活跃会话 **宜** 在下次校验时被识别为失效
- 联动失效在下一次校验时生效

#### v1 渐进实现

- v1 必备：凭证状态管理（active/suspended/revoked/expired）+ 查询时校验
- 后续版本：吊销推送机制、实时状态查询服务

### 7.4 IDN-ATH：身份鉴别与运行态证明（v1 新增）

#### 功能描述

定义 Agent 的身份鉴别机制。鉴别过程由独立的原子鉴别项组合完成。

#### 原子鉴别项

| 鉴别项标识 | 名称 | 验证内容 |
|-----------|------|---------|
| `CRED_ATH` | 身份凭证鉴别 | agent-cert 签名合法、未过期、未被吊销 |
| `RTP_ATH` | 运行态证明鉴别 | 当前实例状态与凭证绑定一致 |

各鉴别项为原子操作，通过组合实现不同强度的鉴别。

#### 运行态证明

运行态证明在每次身份鉴别时动态生成，以 `runtime-proof` blob 承载。

runtime-proof blob content：

```json
{
  "proof_id": "proof-001",
  "credential_hash": "sha256:...",
  "instance_state_attributes": {
    "instance_id": "inst-7c91d2",
    "instance_status": "running"
  },
  "binding_context_hash": "sha256:...",
  "proof_anchor_mode": "CREDENTIAL_ANCHORED",
  "issued_at": "2026-05-18T10:00:00Z",
  "expires_at": "2026-05-18T10:05:00Z"
}
```

| 字段 | 存在性 | 说明 |
|------|--------|------|
| proof_id | 必备 | 证明唯一标识 |
| credential_hash | 必备 | 引用的 agent-cert blob hash |
| instance_state_attributes | 必备 | 实例状态快照 |
| binding_context_hash | 必备 | 当前交互上下文摘要 |
| proof_anchor_mode | 必备 | `CREDENTIAL_ANCHORED` / `ENVIRONMENT_ANCHORED` |
| issued_at | 必备 | 生成时间 |
| expires_at | 必备 | 失效时间（短时有效） |

labels：
- `type: runtime-proof`
- `x-proof-agent: <agent-id>`
- `x-proof-credential: <cert-hash>`

#### 鉴别规则

- 高风险授权、跨信任边界场景，鉴别组合 **应** 至少包含 `CRED_ATH` 和 `RTP_ATH`
- 鉴别项 **应** 完整执行；任意一项失败，整体鉴别结果 **应** 为失败
- 运行态证明跨信任边界传递时 **应** 附加签名保护

### 7.5 IDN-TRC：身份链追溯（v0 继承）

#### 功能描述

追踪 Agent 的证书签发链，从指定 Agent 到 root 的完整链路。通过 agent-cert blob 的 `x-cert-parent` label 构建追溯链。

#### 追溯请求

```
GET /trace/identity/{agent-id}
```

#### 响应

```json
{
  "chain": [
    {
      "agent_id": "child-agent",
      "parent_id": "parent-agent",
      "level": 2,
      "zones": ["zone-a"]
    },
    {
      "agent_id": "parent-agent",
      "parent_id": "baize-root",
      "level": 3,
      "zones": ["zone-a", "zone-b"]
    },
    {
      "agent_id": "baize-root",
      "parent_id": null,
      "level": 4,
      "zones": ["*"]
    }
  ]
}
```

---

## 8 可信连接能力（LNK）

### 8.1 能力定位与安全目标对应

LNK 能力域负责在 Agent 之间建立有状态的会话上下文，为会话内的消息传输提供完整性保护和防重放机制。LNK 直接落实 O.SESSION_BINDING。安全目标映射见 §3.6。

### 8.2 LNK-SES：会话管理（v1 新增）

#### 功能描述

定义安全会话的建立、维护与关闭。会话是两个 Agent 之间具有共享上下文的通信关系，以 `session` blob 记录。

#### 会话建立

两个 Agent 建立会话时产生 session blob：

session blob content：

```json
{
  "session_id": "sess-4d1b2f",
  "peer_a": "agent-alice",
  "peer_b": "agent-bob",
  "credential_hash_a": "sha256:...",
  "credential_hash_b": "sha256:...",
  "handshake_transcript_hash": "sha256:...",
  "established_at": "2026-05-18T10:00:00Z",
  "expires_at": "2026-05-18T10:30:00Z"
}
```

| 字段 | 孅在性 | 说明 |
|------|--------|------|
| session_id | 必备 | 会话唯一标识 |
| peer_a | 必备 | 发起方 Agent |
| peer_b | 必备 | 响应方 Agent |
| credential_hash_a | 必备 | 发起方 agent-cert blob hash |
| credential_hash_b | 必备 | 响应方 agent-cert blob hash |
| handshake_transcript_hash | 必备 | 握手消息摘要 |
| established_at | 必备 | 建立时间 |
| expires_at | 必备 | 过期时间 |

labels：
- `type: session`
- `x-session-id: <session-id>`
- `x-session-peer-a: <agent-a>`
- `x-session-peer-b: <agent-b>`
- `x-session-status: active`

#### 会话维护

- 超过 `expires_at` 的会话 **不应** 继续用于新消息
- 长会话 **宜** 支持重协商或会话更新，更新时产生新的 session blob
- 会话更新时 `session_id` **宜** 保持一致，通过 `parent` label 引用上一版本

#### 会话关闭

关闭时更新 session blob 的 `x-session-status` label 为 `closed`，并追加关闭记录：

| label | 值 |
|-------|-----|
| `x-session-status` | `closed` |
| `x-session-closed-at` | ISO 8601 时间戳 |
| `x-session-close-reason` | 关闭原因 |
| `x-session-final-hash` | 最终会话摘要 |

#### 安全要求

- 会话建立时双方 **应** 完成双向身份校验（IDN-ATH）
- 会话密钥 **应** 以不可导出方式保留
- 不同会话 **应** 使用独立的上下文，不得跨会话复用
- 会话关闭时 **应** 销毁会话相关临时资源

### 8.3 LNK-DTX：可信数据传输（v1 新增）

#### 功能描述

定义会话内消息传输的结构与保护规范。每个传输消息以 blob 承载，与所属会话显式绑定。

#### 传输消息结构

消息 blob content：

```json
{
  "session_id": "sess-4d1b2f",
  "message_id": "msg-0007",
  "sequence_no": 7,
  "payload_type": "INTENT",
  "payload_hash": "sha256:...",
  "response_to": "msg-0006",
  "sent_at": "2026-05-18T10:01:12Z"
}
```

| 字段 | 存在性 | 说明 |
|------|--------|------|
| session_id | 必备 | 所属会话 |
| message_id | 必备 | 消息唯一标识 |
| sequence_no | 必备 | 顺序号（防重放） |
| payload_type | 必备 | 载荷类型（INTENT / AUTHORIZATION / RECEIPT 等） |
| payload_hash | 必备 | 载荷 blob hash |
| response_to | 条件必备 | 响应消息时必备，引用被响应消息的 message_id |
| sent_at | 必备 | 发送时间 |

labels：
- `type: <payload_type 对应的 blob type>`
- `x-session-id: <session-id>`
- `x-message-id: <message-id>`
- `x-message-seq: <sequence_no>`
- `parent: <前一条消息 blob hash>`

#### 安全要求

- 每条消息 **应** 绑定唯一 session_id
- 消息 **应** 通过 `sequence_no` 提供防重放保护，**应** 拒绝序号回退的消息
- 响应消息 **应** 通过 `response_to` 明确引用被响应消息
- 消息通过 blob 不可变性和 `parent` label 构建消息链，保证完整性
- 消息链中的任一消息 hash 不匹配 **应** 导致链完整性校验失败

---

## 9 可信意图能力（INT）

### 9.1 能力定位与安全目标对应

INT 能力域负责意图的结构化表达、跨主体派生、执行回执生成和全链路一致性校验。INT 直接落实 O.INTENT_CONTINUITY 和 O.EXECUTION_PROOF。INT-CNV 同时验证授权边界的收缩合规性，因此也覆盖 O.DELEGATION_CONTROL。安全目标映射见 §3.6。

### 9.2 INT-GIR：通用意图表达（v1 新增）

#### 功能描述

定义通用意图的结构规范。通用意图是操作目标的结构化表达，是授权凭证签发、子意图派生和全链路校验的依据。对应 ASL INT-GIR。

#### intent blob

content 采用 ASL 定义的通用意图字段结构：

```json
{
  "intent_id": "urn:zetu:intent:001",
  "intent_owner": "agent-alice",
  "intent_creator": "agent-alice",
  "task_id": "task-20260518-0001",
  "intent_goal": "在预算范围内续费手机套餐",
  "intent_constraints": {
    "budget_limit": 150.00,
    "currency": "CNY",
    "deadline": "2026-05-31T23:59:59Z"
  },
  "intent_preferences": {
    "preferred_channel": "ALIPAY"
  },
  "origin_input_hash": "sha256:...",
  "origin_input_excerpt": "帮我续费手机套餐，不要超过150元",
  "version": "1",
  "created_at": "2026-05-18T09:00:00Z",
  "expires_at": "2026-05-31T23:59:59Z"
}
```

| 字段 | 存在性 | 说明 |
|------|--------|------|
| intent_id | 必备 | 意图唯一标识 |
| intent_owner | 必备 | 意图拥有方（授权或委托该意图执行的 Agent） |
| intent_creator | 必备 | 意图创建方（实际生成该意图的 Agent，可与 owner 相同） |
| task_id | 可选 | 关联任务标识 |
| intent_goal | 必备 | 高层意图目标 |
| intent_constraints | 必备 | 执行约束集合（动作范围、金额限制、时间窗口等） |
| intent_preferences | 可选 | 执行偏好（不具有强制约束力） |
| origin_input_hash | 可选 | 原始用户输入的摘要 |
| origin_input_excerpt | 可选 | 原始用户输入的简短摘录 |
| version | 必备 | 意图版本号 |
| created_at | 必备 | 创建时间 |
| expires_at | 必备 | 失效时间 |

labels：
- `type: intent`
- `x-intent-id: <intent_id>`
- `x-intent-owner: <owner>`
- `x-intent-status: active`
- `x-intent-expires: <expires_at>`

#### 安全要求

- `intent_constraints` 为必备字段，实现 **不应** 签发空约束的意图
- `expires_at` **应** 大于 `created_at`
- intent_id 在有效期内 **应** 唯一
- `origin_input_excerpt` **不宜** 携带完整原始输入（落实 P.LEAST_DISCLOSURE）

### 9.3 INT-DER：意图派生（v1 新增）

#### 功能描述

定义子意图的派生规范。子意图从父意图或上级子意图派生，在父约束范围内细化目标。约束只能收缩，不能扩张。对应 ASL INT-DER。

#### sub-intent blob

```json
{
  "sub_intent_id": "urn:zetu:subintent:001",
  "parent_intent_hash": "sha256:...",
  "deriver_id": "agent-planner",
  "subject": "agent-executor",
  "derivation_depth": 1,
  "derivation_basis": "在父意图预算内锁定续费对象",
  "intent_goal": "向中国移动完成套餐续费",
  "intent_constraints": {
    "merchant": "CHINA_MOBILE",
    "max_amount": 150.00,
    "currency": "CNY"
  },
  "created_at": "2026-05-18T09:05:00Z",
  "expires_at": "2026-05-31T23:59:59Z"
}
```

| 字段 | 存在性 | 说明 |
|------|--------|------|
| sub_intent_id | 必备 | 子意图唯一标识 |
| parent_intent_hash | 必备 | 父意图（通用意图或上级子意图）blob hash |
| deriver_id | 必备 | 派生方 Agent |
| subject | 必备 | 预期执行方 Agent |
| derivation_depth | 必备 | 派生深度（通用意图 = 0，每派生一级递增） |
| derivation_basis | 可选 | 派生依据说明 |
| intent_goal | 必备 | 子意图目标 |
| intent_constraints | 必备 | 收缩后的约束集合 |
| created_at | 必备 | 创建时间 |
| expires_at | 必备 | 失效时间（不得晚于父意图 expires_at） |

labels：
- `type: sub-intent`
- `x-intent-id: <sub_intent_id>`
- `x-parent-intent: <parent_intent_hash>`
- `x-derivation-depth: <depth>`
- `x-intent-owner: <subject>`

#### 约束收缩规则

子意图的约束 **应** 在父意图约束基础上收缩：

| 约束维度 | 子意图规则 |
|---------|-----------|
| 动作范围 | 须为父意图动作范围的子集 |
| 目标范围 | 须为父意图目标范围的子集或等值 |
| 金额上限 | 不得超过父意图金额上限 |
| 有效时间 | 须完全落在父意图时间窗内 |
| expires_at | 不得晚于父意图 expires_at |

违反收缩规则的子意图 **应** 被拒绝。

#### 安全要求

- 每个子意图 **应** 通过 `parent_intent_hash` 显式引用父意图
- `derivation_depth` **应** 从通用意图的 0 起单调递增
- `expires_at` **不应** 晚于父意图的 `expires_at`
- 派生链中任一节点失效 **应** 导致整条链路校验失败

### 9.4 INT-RCT：执行回执（v1 新增）

#### 功能描述

定义执行回执的结构规范。执行回执由执行方在完成动作后生成，同时引用意图和授权，是全链路校验和审计追溯的核心依据。对应 ASL INT-RCT。

#### receipt blob

```json
{
  "receipt_id": "urn:zetu:receipt:001",
  "executor_id": "agent-executor",
  "task_id": "task-20260518-0001",
  "action_type": "SUBSCRIPTION_RENEWAL",
  "intent_hash": "sha256:...",
  "authorization_hash": "sha256:...",
  "execution_params_hash": "sha256:...",
  "result_status": "SUCCEEDED",
  "execution_result": "套餐续费成功，金额 128 元",
  "started_at": "2026-05-18T09:06:00Z",
  "finished_at": "2026-05-18T09:06:05Z"
}
```

| 字段 | 存在性 | 说明 |
|------|--------|------|
| receipt_id | 必备 | 回执唯一标识 |
| executor_id | 必备 | 执行方 Agent |
| task_id | 必备 | 关联任务标识 |
| action_type | 必备 | 执行动作类型（须在授权范围内） |
| intent_hash | 必备 | 所依据的意图 blob hash |
| authorization_hash | 必备 | 所依据的授权 blob hash |
| execution_params_hash | 可选 | 执行参数摘要 |
| result_status | 必备 | 执行结果状态 |
| execution_result | 条件必备 | SUCCEEDED / PARTIAL 时必备 |
| rejection_reason | 条件必备 | REJECTED 时必备 |
| started_at | 必备 | 开始时间 |
| finished_at | 必备 | 完成时间 |
| downstream_receipt_hashes | 可选 | 下级执行方回执 hash 列表（多级协作） |

`result_status` 取值：

| 状态 | 说明 |
|------|------|
| `SUCCEEDED` | 执行成功 |
| `FAILED` | 执行失败 |
| `PARTIAL` | 部分执行 |
| `REJECTED` | 被拒绝（授权/约束校验未通过） |
| `CANCELLED` | 被取消 |
| `EXPIRED` | 意图/授权已过期 |

labels：
- `type: receipt`
- `x-receipt-id: <receipt_id>`
- `x-receipt-executor: <executor_id>`
- `x-receipt-status: <result_status>`
- `x-receipt-intent: <intent_hash>`
- `x-receipt-authz: <authorization_hash>`

#### 安全要求

- 回执 **应** 同时携带 `intent_hash` 和 `authorization_hash`（双摘要绑定）
- `REJECTED` 状态 **应** 填写 `rejection_reason`
- `SUCCEEDED` / `PARTIAL` 状态 **应** 填写 `execution_result`
- `started_at` **应** 早于或等于 `finished_at`
- 多级协作时上级 **宜** 通过 `downstream_receipt_hashes` 汇聚下级回执

### 9.5 INT-CNV：全链路一致性校验（v1 新增）

#### 功能描述

定义"意图 → 授权 → 执行"全链路的一致性校验规范。CNV 是横跨 GIR、DER、RCT 三个模块的校验环节。对应 ASL INT-CNV。

#### 触发时机

| 时机 | 校验范围 |
|------|---------|
| 授权签发前 | intent → authorization 绑定 |
| 执行方接受任务前 | intent → sub-intent → authorization 完整性 |
| 执行完成生成回执时 | receipt → authorization → intent 摘要一致性 |
| 审计核查时 | 全链路 |

#### 校验规则

**校验一：意图派生链完整性**

1. 从 receipt 的 `intent_hash` 出发
2. 沿 sub-intent 的 `parent_intent_hash` 逐级向上
3. 直至 `derivation_depth` = 0 的通用意图
4. 验证每级约束收缩合规
5. 任一节点失效 → 整条链路校验失败

**校验二：授权与意图的绑定一致性**

1. authorization 的 `source_intent_hash` 与实际意图摘要一致
2. authorization 的约束在意图约束范围内
3. 签发方身份凭证状态有效（通过 IDN-LCM 查询）

**校验三：回执与授权的绑定一致性**

1. receipt 的 `authorization_hash` 与实际授权摘要一致
2. receipt 的 `action_type` 在授权约束范围内
3. receipt 的 `intent_hash` 与授权引用的意图一致或为其派生子意图

**校验四：委托链完整性**

遵循 AZN-VER 校验四规则（见 §10.5）。委托链中任一级失效 → 最终执行授权失效。

#### 安全要求

- CNV **应** 以意图派生链完整性为首要前提
- 链路断裂（hash 不匹配、节点缺失）时 **应** 拒绝执行
- 校验过程中 **应** 通过 IDN-LCM 查询相关方身份凭证状态
- 校验结果 **应** 完整记录（审计追溯）
- 遍历派生链时 **应** 检测循环引用

---

## 10 可信授权能力（AZN）

### 10.1 能力定位与安全目标对应

AZN 能力域负责将意图目标收敛为可执行的授权边界，通过授权凭证在多级协作链中向下传递执行权。AZN 直接落实 O.DELEGATION_CONTROL，通过引用 source_intent_hash 同时支撑 O.INTENT_CONTINUITY。安全目标映射见 §3.6。

### 10.2 AZN-APR：授权载荷（v1 新增）

#### 功能描述

定义授权载荷的结构规范。授权载荷是授权凭证的核心内容，规定执行方在意图边界内可执行的动作范围、约束集合与委托权限。对应 ASL AZN-APR。

#### authorization blob

content 采用 ASL 定义的授权载荷字段结构：

```json
{
  "authorization_id": "urn:zetu:authz:001",
  "issuer": "agent-planner",
  "subject": "agent-executor",
  "grant_type": "SUBSCRIPTION_RENEWAL",
  "constraints": {
    "target_scope": { "merchant": ["CHINA_MOBILE"] },
    "amount_scope": { "max_amount": 150.00, "currency": "CNY" },
    "time_scope": { "not_before": "2026-05-18T09:00:00Z", "expires_at": "2026-05-31T23:59:59Z" },
    "method_scope": { "payment_methods": ["ALIPAY"] },
    "environment_scope": { "min_see_level": "L1" }
  },
  "delegatable": true,
  "delegation_depth_remaining": 1,
  "delegation_mode": "SPECIFIED",
  "source_intent_hash": "sha256:...",
  "root_authorizer": "agent-alice",
  "aud": ["agent-executor"],
  "nbf": "2026-05-18T09:05:00Z",
  "exp": "2026-05-31T23:59:59Z",
  "iat": "2026-05-18T09:05:00Z",
  "jti": "urn:zetu:authz:jti:001",
  "version": "1"
}
```

| 字段 | 存在性 | 说明 |
|------|--------|------|
| authorization_id | 必备 | 授权载荷唯一标识 |
| issuer | 必备 | 授权签发方 |
| subject | 必备 | 授权接收方（执行方） |
| grant_type | 必备 | 授权动作类型 |
| constraints | 必备 | 执行约束集合 |
| delegatable | 必备 | 是否可委托 |
| delegation_depth_remaining | 条件必备 | delegatable 为 true 时必备；剩余委托层级 |
| delegation_mode | 条件必备 | delegatable 为 true 时必备；`SPECIFIED` / `BOUNDED` |
| source_intent_hash | 必备 | 引用的意图 blob hash |
| parent_authz_hash | 条件必备 | 子授权时必备；父授权 blob hash |
| root_authorizer | 必备 | 委托链根授权方（全链路一致） |
| aud | 可选 | 授权受众限定 |
| nbf | 必备 | 生效时间 |
| exp | 必备 | 失效时间（不得晚于意图 expires_at） |
| iat | 必备 | 签发时间 |
| jti | 必备 | 防重放唯一标识 |
| version | 必备 | 版本号 |

constraints 子结构：

| 子字段 | 存在性 | 说明 |
|--------|--------|------|
| target_scope | 可选 | 允许的目标对象范围 |
| amount_scope | 可选 | 金额范围约束 |
| time_scope | 可选 | 时间窗口约束 |
| method_scope | 可选 | 执行方式约束 |
| environment_scope | 可选 | 执行环境要求（如最低 SEE 等级） |
| behavior_scope | 可选 | 行为约束 |
| cumulative_limit | 可选 | 累计上限（金额、次数等） |

labels：
- `type: authorization`
- `x-authz-id: <authorization_id>`
- `x-authz-issuer: <issuer>`
- `x-authz-subject: <subject>`
- `x-authz-status: valid`
- `x-source-intent: <source_intent_hash>`

#### 安全要求

- `source_intent_hash` **应** 指向有效的意图（未过期、未吊销）
- constraints 中的所有约束 **应** 在所引用意图的 intent_constraints 范围内
- `exp` **不应** 晚于所引用意图的 `expires_at`
- `jti` **应** 在同一签发方范围内唯一，防重放

### 10.3 AZN-ISS：授权凭证签发（v1 新增）

#### 功能描述

定义授权凭证的签发规范。签发方在签发前完成对意图有效性的验证，生成 authorization blob。对应 ASL AZN-ISS。

#### 签发流程

1. 验证 `source_intent_hash` 指向的意图有效（未过期、未吊销）
2. 验证 `grant_type` 和 `constraints` 在意图约束范围内
3. 验证签发方身份凭证状态有效（通过 IDN-LCM）
4. 生成 authorization blob，设置 labels
5. 自动生成审计记录

#### 安全要求

- 授权载荷发生变化时 **不应** 复用已有 blob，**应** 重新签发
- 跨主体执行权下传时 **应** 生成新的 authorization blob
- 签发 **应** 通过 IDN-LCM 确认签发方身份凭证未被吊销

### 10.4 AZN-DLG：多级委托（v1 新增）

#### 功能描述

定义多级委托场景下子授权的边界收缩校验规则。每一级委托均在父授权边界内收缩，不得在时间、动作、对象、金额等维度扩张。对应 ASL AZN-DLG。

#### 约束收缩规则

| 字段 | 子授权规则 |
|------|-----------|
| time_scope / nbf / exp | 须完全落在父授权时间窗内 |
| grant_type（动作范围） | 须为父授权动作范围的子集 |
| target_scope | 须为父授权目标范围的子集或等值 |
| amount_scope | 上限不得高于父授权 |
| cumulative_limit | 累计上限不得高于父授权；多个子授权并存时累计之和不得溢出 |
| method_scope | 须为父授权执行方式的子集 |
| environment_scope | 不得低于父授权声明的最低 SEE 等级 |
| aud | 须为父授权受众的子集 |
| delegation_depth_remaining | 严格等于父授权值 - 1 |
| delegation_mode | 只允许 `BOUNDED` → `SPECIFIED` 收缩 |
| delegatable | 父授权为 false 时不得生成子授权 |

违反收缩规则的子授权 **应** 被拒绝签发，**应** 被接收方拒绝。

#### 委托链关系

每一级子授权通过以下字段维护委托链：

- `parent_authz_hash`：引用父授权 blob hash
- `root_authorizer`：全链路保持一致，不得被覆盖
- `delegation_depth_remaining`：严格递减

#### 父凭证联动失效

父授权失效（revoked / expired / consumed）时，所有子授权 **应** 同步失效。

#### 安全要求

- 收缩校验 **应** 在子授权签发前执行
- `delegation_depth_remaining` 为 0 的凭证 **不应** 继续委托
- 委托链中每一级的 `root_authorizer` **应** 与根授权一致，不一致时校验 **应** 失败

### 10.5 AZN-VER：授权校验（v1 新增）

#### 功能描述

定义执行方在使用授权凭证前的校验规范。校验是执行动作前的最后一道授权门控。对应 ASL AZN-VER。

#### 校验规则

**校验一：凭证真实性**

- 签发方 agent-cert blob 签名合法
- 签发方身份凭证状态有效（通过 IDN-LCM 查询，非 revoked）

**校验二：凭证有效性**

- `x-authz-status` 为 `valid`
- 当前时间满足 `nbf` ≤ now < `exp`

**校验三：意图引用一致性**

- `source_intent_hash` 指向有效意图（未过期、未吊销）
- `grant_type` 和 constraints 在意图约束范围内

**校验四：委托链完整性**

- `delegation_depth_remaining` 沿链单调递减
- 沿 `parent_authz_hash` 逐级向上，验证每级父凭证有效
- 各级 `root_authorizer` 与根授权一致
- 各级约束收缩合规

**校验五：执行适用性**

- 本次动作类型在 `grant_type` 范围内
- 本次执行目标在 constraints 范围内
- 本次金额在 amount_scope 范围内
- 当前执行环境满足 environment_scope 要求
- authorization 的 subject 与当前执行方身份一致

任意一项失败，执行 **应** 被拒绝，并生成 `REJECTED` 回执。

#### 安全要求

- 五项校验 **应** 完整执行；部分通过 **不应** 被视为有效
- 凭证状态 **应** 实时查询，**不应** 以本地缓存替代
- 校验失败时 **应** 生成包含 `rejection_reason` 的 receipt blob

---

## 11 审计能力（AUDIT）

### 11.1 能力定位与安全目标对应

审计能力为所有写操作提供不可篡改的事实记录，是泽图扩展层的核心横切能力。AUDIT 落实 O.AUDIT_INTEGRITY（泽图在 ASL 安全目标之外增加的目标）和 P.AUDIT_TRACEABILITY。安全目标映射见 §3.6。

注：ASL 未定义独立的审计模块，审计要求分布在 P.AUDIT_TRACEABILITY 约束中。泽图将审计提升为一等公民。

### 11.2 AUDIT-LOG：审计记录（v0 继承）

#### 功能描述

所有写操作（blob write、label add、agent register/revoke、file write/delete、push、import 等）自动生成审计记录。审计记录以 `type: "audit"` blob 承载，不可关闭。

#### audit blob

content：

```json
{
  "type": "blob_write",
  "agent": "agent-alice",
  "result": "success",
  "target": "sha256:a1b2c3...",
  "seq": 1747567200000000000
}
```

| 字段 | 存在性 | 说明 |
|------|--------|------|
| type | 必备 | 操作类型（blob_write / agent_register / push 等） |
| agent | 必备 | 执行操作的 Agent |
| result | 必备 | 操作结果（success / failure） |
| target | 可选 | 操作对象标识（blob hash / agent id / file path） |
| seq | 必备 | 单调递增序号（纳秒时间戳） |

labels：
- `type: audit`
- `x-audit: true`
- `x-audit-type: <操作类型>`
- `x-audit-agent: <agent-id>`
- `x-audit-result: <result>`
- `x-audit-time: <ISO 8601 时间戳>`
- `x-audit-seq: <序号>`
- `x-audit-target: <target>`（可选）

#### 安全要求

- 所有写操作 **应** 自动生成审计 blob
- 审计记录 **不应** 被关闭或跳过
- target 字段 **宜** 记录操作对象的标识

### 11.3 AUDIT-CHAIN：审计哈希链（v1 新增）

#### 功能描述

审计 blob 通过 hash chain 串联，形成防篡改链。任何中间记录的删除或篡改都可以被检测。

#### 链结构

每条审计 blob 额外携带两个 label：

| label key | 值 | 说明 |
|-----------|-----|------|
| `x-audit-prev` | 前一条审计 blob 的 hash | 链式引用 |
| `x-audit-chain-index` | 在链中的序号 | 单调递增 |

```
audit-0 (index=0, prev=genesis)
  → audit-1 (index=1, prev=hash-0)
    → audit-2 (index=2, prev=hash-1)
      → ... 
        → audit-N (index=N, prev=hash-N-1) ← audit-head
```

链头（最新的审计 hash）存储在特殊 ref `audit-head` 中。

#### 安全要求

- 每条审计 blob **应** 携带 `x-audit-prev` 指向前一条记录
- `x-audit-chain-index` **应** 单调递增
- 链头 ref `audit-head` **应** 在每次审计写入后更新
- genesis（index=0）的 `x-audit-prev` **应** 为固定值 `genesis`

### 11.4 AUDIT-VERIFY：链完整性验证（v1 新增）

#### 功能描述

验证审计哈希链的完整性，检测任何删除或篡改。

#### 验证算法

1. 从 `audit-head` ref 获取最新审计 blob hash
2. 读取该 blob，验证 `x-audit-prev` 指向的 blob 存在且 hash 正确
3. 沿 `x-audit-prev` 逐条向前追溯
4. 验证 `x-audit-chain-index` 单调递减
5. 到达 genesis（index=0）时验证完成
6. 统计总记录数，与 `x-audit-chain-index` 最大值 + 1 比较

#### 验证结果

```json
{
  "valid": true,
  "chain_length": 42,
  "head_hash": "sha256:...",
  "genesis_hash": "sha256:...",
  "errors": []
}
```

| 字段 | 说明 |
|------|------|
| valid | 链是否完整 |
| chain_length | 链中记录总数 |
| head_hash | 链头 hash |
| genesis_hash | 创世记录 hash |
| errors | 错误列表（缺失记录、hash 不匹配、序号跳跃等） |

#### 安全要求

- 缺失记录、hash 不匹配或序号跳跃 **应** 报告为链完整性被破坏
- 验证结果 **应** 完整记录

---

## 12 数据操作与文件同步（DATA/FILE）

本章定义泽图扩展层的数据操作和文件同步能力。这些能力属于泽图扩展层，不在 ASL 规范范围内。

### 12.1 Blob 操作（v0 继承）

#### blob/write

写入 blob。相同内容幂等（返回已有 hash），新 labels 合并到已有 labels（冲突 key 跳过）。

```
输入:
  content:  string              // 必备
  labels:   map<string, string> // 可选，默认 {}

输出:
  hash:     string              // SHA-256 hash
```

Level 0 Agent **不应** 写入。

#### blob/read

按 hash 读取 blob。无需认证。hash 不存在返回错误。

#### blob/query

按 labels 查询 blob，AND 语义。空 labels 返回所有 blob。

```
输入:
  labels:   map<string, string> // 匹配条件
  limit:    option<uint32>      // 最大返回数
  offset:   option<uint32>      // 偏移量

输出:
  blobs:    list<Blob>
```

### 12.2 Label 操作（v0 继承）

#### label/add

向已有 blob 追加 label。append-only：key 已存在返回冲突错误。

```
输入:
  entity_hash:  string  // blob hash
  key:          string  // 必备
  value:        string  // 必备

输出:
  ok: bool
```

#### label/query

按 key-value 查询关联的 blob。

```
输入:
  key:       string
  value:     option<string>  // null = 查所有 value

输出:
  results:   list<{ entity_hash, key, value }>
```

### 12.3 导入/导出（v0 继承）

#### import

导入外部数据，产生 blob 并附加来源和信任级别标签。

```
输入:
  content:      string              // 必备
  source:       string              // 必备，来源标识
  trust_level:  u8                  // 可选，0-4，默认 2
  labels:       map<string, string> // 可选

输出:
  hash:         string
  trust_level:  u8
```

额外 labels：`source`、`trust-level`、`imported: true`。trust_level 为 0 时追加 `sandbox: true`。

#### export

导出指定 hash 的 blob。需要认证，校验敏感度和 zone 权限。

```
输入:
  hash:  string  // 必备

输出:
  blob:  Blob
```

敏感度检查：`sensitivity: "high"` 需要 level ≥ 3，`"medium"` 需要 level ≥ 2。

### 12.4 文件操作网关（v0 继承）

文件操作通过白泽 API 代理，所有文件存储在 Agent 的 workspace 目录中。每次操作自动计算 hash、记录 blob 并审计。

#### file/write

```
POST /files/{path}
输入: { "content": "...", "labels": {} }
输出: { "path": "config/app.yaml", "hash": "sha256...", "size": 1024 }
```

#### file/read

```
GET /files/{path}
输出: { "path": "config/app.yaml", "content": "...", "hash": "sha256...", "size": 1024 }
```

#### file/delete

```
DELETE /files/{path}
输出: 204 No Content
```

#### file/list

```
GET /files
输出: { "files": ["config/app.yaml", "data/log.txt"] }
```

#### Zone 规则

文件路径首段（`/` 之前）视为 zone：
- `config/app.yaml` — 根级文件，所有 Agent 可访问
- `A/data.txt` — zone A，需要 Agent scope 包含 `"A"` 或 `"*"`

Level 0 Agent **不应** 写入文件。

### 12.5 Push/Pull 同步（v0 继承）

#### push（workspace → 主仓库工作区）

将 Agent workspace 文件推送到主仓库工作区。文件到达后等待用户审批 git commit。

```
输入:
  agent_id:  string  // 必备
  message:   string  // 必备，commit 描述
  ref:       string  // 可选，目标 ref

输出:
  files:     uint32  // 推送文件数
  pending:   bool    // 等待用户审批
```

执行流程：验证身份和 zone → workspace 文件写入主仓库工作区 → 创建鉴权 blob → 等待用户审批。

#### pull（主仓库工作区 → workspace）

从主仓库工作区拉取文件到 Agent workspace。无 zone 权限的文件被静默跳过。

```
输入:
  agent_id:  string  // 必备
  ref:       string  // 可选，来源 ref

输出:
  files:     uint32  // 拉取文件数
```

**注意**：pull **会** 清空 workspace。调用方 **应** 保证先 pull 再 write，否则 write 的内容会被 pull 清空。

#### Git 操作（用户控制）

主仓库的 Git 操作由用户控制，不由 Agent 触发：

| 操作 | 执行者 | 说明 |
|------|--------|------|
| git commit | 用户审批后 | 工作区变更写入 Git 历史 |
| git ref 管理 | 用户 | branch/tag 创建、更新、删除 |
| git log/diff/revert | 用户 | 版本历史查询和回退 |

---

## 13 HTTP REST API

本章定义泽图 v1 的 HTTP REST API 传输层。v1 端点包含 v0 全部端点并新增。

### 13.1 通用约定

- 基础路径：`/api/v1`
- 内容类型：`application/json`
- 写操作认证：`x-agent-id` 请求头（v1 增强后替换为签名认证）
- 错误响应：`{ "error": "<error-type>" }`

| HTTP 状态 | error-type | 含义 |
|-----------|-----------|------|
| 400 | validation failed | 请求参数不合法 |
| 401 | missing x-agent-id header | 缺少认证头 |
| 403 | permission denied | 权限不足 |
| 404 | not found | 资源不存在 |
| 409 | conflict | 资源冲突（label key 已存在、名称重复等） |
| 422 | user decision required | 需要用户决策（如 Agent 未注册） |
| 500 | internal error | 内部错误 |

### 13.2 意图端点

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| POST | `/intents` | 创建通用意图 | 需要 |
| POST | `/intents/derive` | 派生子意图 | 需要 |
| GET | `/intents/{hash}` | 读取意图 blob | 无需 |
| GET | `/intents?status=active` | 查询意图 | 无需 |

POST `/intents` 请求体字段定义见 §9.2 intent blob content。

POST `/intents/derive` 请求体字段定义见 §9.3 sub-intent blob content。
```

### 13.3 执行回执端点

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| POST | `/receipts` | 创建执行回执 | 需要 |
| GET | `/receipts/{hash}` | 读取回执 blob | 无需 |
| GET | `/receipts?executor={id}` | 查询回执 | 无需 |

POST `/receipts` 请求体字段定义见 §9.4 receipt blob content。
```

### 13.4 授权端点

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| POST | `/authorizations` | 签发授权 | 需要 |
| POST | `/authorizations/delegate` | 委托子授权 | 需要 |
| POST | `/authorizations/{hash}/verify` | 校验授权 | 需要 |
| GET | `/authorizations/{hash}` | 读取授权 blob | 无需 |

POST `/authorizations` 请求体：authorization blob 的完整 content 字段。

POST `/authorizations/{hash}/verify` 响应：

```json
{
  "valid": true,
  "checks": {
    "credential_authenticity": true,
    "credential_validity": true,
    "intent_reference": true,
    "delegation_chain": true,
    "execution_applicability": true
  },
  "errors": []
}
```

### 13.5 会话端点

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| POST | `/sessions` | 创建会话 | 需要 |
| POST | `/sessions/{id}/close` | 关闭会话 | 需要 |
| GET | `/sessions/{id}` | 读取会话 blob | 无需 |

### 13.6 全链路校验端点

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| POST | `/cnv/verify` | 全链路一致性校验 | 无需 |

请求体：

```json
{
  "receipt_hash": "sha256:...",
  "verify_depth": "full"
}
```

响应：

```json
{
  "valid": true,
  "intent_chain": [
    { "hash": "sha256:...", "type": "intent", "valid": true },
    { "hash": "sha256:...", "type": "sub-intent", "valid": true }
  ],
  "authorization_chain": [
    { "hash": "sha256:...", "valid": true }
  ],
  "errors": []
}
```

### 13.7 审计链端点

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| GET | `/audit` | 查询审计日志 | 无需 |
| POST | `/audit/verify-chain` | 验证审计哈希链 | 无需 |

GET `/audit` 支持查询参数：`?agent=<id>&type=<type>`

POST `/audit/verify-chain` 响应格式见 §11.4 验证结果。

### 13.8 Agent 生命周期端点

| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| GET | `/agents` | 列出 Agent | 无需 |
| GET | `/agents/{id}/status` | 查询凭证状态 | 无需 |
| PUT | `/agents/{id}/status` | 更新凭证状态 | 需要 |
| GET | `/trace/identity/{id}` | 身份追溯 | 无需 |

PUT `/agents/{id}/status` 请求体：

```json
{
  "status": "suspended",
  "reason": "疑似安全异常，待核查"
}
```

### 13.9 v0 端点（向后兼容）

以下 v0 端点在 v1 中继续可用：

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/blobs` | blob/write |
| GET | `/blobs/{hash}` | blob/read |
| POST | `/blobs/query` | blob/query |
| POST | `/labels` | label/add |
| GET | `/labels/query` | label/query |
| POST | `/push` | push |
| POST | `/pull` | pull |
| GET | `/log` | Git log |
| GET | `/refs` | ref/list |
| GET | `/refs/{name}` | ref/get |
| PUT | `/refs/{name}` | ref/set |
| DELETE | `/refs/{name}` | ref/delete |
| POST | `/agents` | agent/register |
| DELETE | `/agents/{id}` | agent/revoke |
| POST | `/elevation` | elevation/request |
| POST | `/elevation/{id}/approve` | elevation/approve |
| POST | `/elevation/{id}/return` | elevation/return |
| GET | `/elevation` | elevation/list |
| POST | `/import` | import |
| GET | `/export/{hash}` | export |
| POST | `/files/{path}` | file/write |
| GET | `/files/{path}` | file/read |
| DELETE | `/files/{path}` | file/delete |
| GET | `/files` | file/list |
| GET | `/repo/stats` | repo/stats |

---

## 14 典型应用场景

### 14.1 UC-1：单次授权执行

**场景**：用户通过 Agent 发起一次有明确边界的原子动作。

**参与方**：用户、Alice（编排 Agent）、Bob（执行 Agent）、业务服务。

**流程**：

```
阶段一：身份与会话
  1. Alice 和 Bob 各自完成身份准备
  2. Alice 向 Bob 发起会话建立（LNK-SES），产生 session blob
  3. 双方完成身份鉴别（IDN-ATH）

阶段二：意图与授权
  4. 用户向 Alice 提交目标和约束
  5. Alice 创建通用意图 blob（INT-GIR）
  6. Alice 基于意图签发授权 blob（AZN-APR + AZN-ISS）
  7. Alice 通过会话将意图 + 授权传递给 Bob（LNK-DTX）

阶段三：执行
  8. Bob 校验意图 + 授权（AZN-VER），校验通过后向业务服务发起动作
  9. 业务服务返回结果
  10. Bob 生成执行回执 blob（INT-RCT），双摘要绑定

阶段四：闭环
  11. Bob 将回执返回 Alice
  12. Alice 执行全链路校验（INT-CNV）
  13. Alice 关闭会话（LNK-SES）

涉及模块：INF-SEE(L1+)、IDN-REG、IDN-ATH、LNK-SES、LNK-DTX、
INT-GIR、INT-RCT、INT-CNV、AZN-APR、AZN-ISS、AZN-VER、AUDIT-LOG
```

### 14.2 UC-2：多级委托执行

**场景**：用户下达复合任务，Agent 在约定边界内自主委托子任务。

**参与方**：用户、Alice（编排 Agent）、Broker（中间 Agent）、Executor（执行 Agent）。

**流程**：

```
阶段一：初始配置
  1. 用户向 Alice 提交复合任务目标和约束
  2. Alice 创建通用意图 blob（INT-GIR），表达整体约束
  3. Alice 签发授权 blob（AZN-ISS），delegatable=true,
     delegation_depth_remaining=2

阶段二：委托
  4. Alice 将意图 + 授权传递给 Broker
  5. Broker 在约束范围内委托子授权（AZN-DLG），
     delegation_depth_remaining=1
  6. Broker 将子授权传递给 Executor

阶段三：执行
  7. Executor 校验子授权（AZN-VER），委托链逐级验证
  8. Executor 执行动作，生成回执 blob（INT-RCT）
  9. 回执沿 Executor → Broker → Alice 逐级返回

阶段四：校验
  10. Alice 执行全链路校验（INT-CNV）
      - 意图链完整性
      - 授权约束逐级收缩
      - 回执与授权绑定

涉及模块：INF-SEE(L1+)、IDN-REG、LNK-SES、LNK-DTX、
INT-GIR、INT-RCT、INT-CNV、AZN-APR、AZN-ISS、AZN-DLG、AZN-VER、AUDIT-LOG
```

### 14.3 UC-3：意图派生与并行执行

**场景**：复合任务拆解为多个并行子意图，各子意图由不同 Agent 执行。

**参与方**：用户、Alice（编排 Agent）、Executor-A、Executor-B、Executor-C。

**流程**：

```
阶段一：意图分解
  1. 用户向 Alice 提交复合任务
  2. Alice 创建通用意图 blob（INT-GIR），包含整体约束
  3. Alice 派生三个子意图 blob（INT-DER），
     每个子意图约束在父意图范围内收缩
  4. Alice 为每个子意图签发独立授权 blob（AZN-ISS）

阶段二：并行执行
  5. 三个 Executor 分别接收各自的子意图 + 授权
  6. 各自校验授权（AZN-VER），各自执行
  7. 各自生成执行回执 blob（INT-RCT）

阶段三：汇聚校验
  8. 三个回执返回 Alice
  9. Alice 对每条链路独立执行 CNV 校验
  10. Alice 验证三条子意图的约束汇总不超出父意图

涉及模块：INF-SEE(L1+)、IDN-REG、LNK-SES、
INT-GIR、INT-DER、INT-RCT、INT-CNV、
AZN-APR、AZN-ISS、AZN-VER、AUDIT-LOG
```

### 14.4 UC-4：借权与临时授权

**场景**：Agent 临时需要超出自身 scope 的权限，申请借权并审批。

**参与方**：Alice（申请方 Agent）、Bob（审批方 Agent）。

**流程**：

```
阶段一：申请
  1. Alice 创建借权请求 blob（type: elevation-request）
     - 申请的 zones、mode（readonly/write/readwrite）
     - 有效时长、原因
  2. 借权请求进入 Pending 状态

阶段二：审批
  3. Bob 审批借权请求
  4. Bob 校验：自身 level >= Alice level，
     申请的 zones 是 Bob zones 的子集
  5. 审批通过，借权进入 Approved 状态

阶段三：使用
  6. Alice 在借权有效期内获得临时权限
  7. 借权到期后自动失效（Expired）

阶段四：归还
  8. Alice 可主动归还借权
  9. 清理 Alice workspace 中借权相关的临时数据

涉及模块：IDN-REG、IDN-LCM、AUDIT-LOG
注：借权是泽图扩展能力，不在 ASL 规范范围内。
```

### 14.5 模块适用性汇总

| 模块 | UC-1 | UC-2 | UC-3 | UC-4 |
|------|------|------|------|------|
| INF-SEE | ●(L1+) | ●(L1+) | ●(L1+) | — |
| IDN-REG | ● | ● | ● | ● |
| IDN-ATH | ● | ● | ● | — |
| IDN-LCM | △ | △ | △ | ● |
| LNK-SES | ● | ● | ● | — |
| LNK-DTX | ● | ● | ● | — |
| INT-GIR | ● | ● | ● | — |
| INT-DER | — | — | ● | — |
| INT-RCT | ● | ● | ● | — |
| INT-CNV | ● | ● | ● | — |
| AZN-APR | ● | ● | ● | — |
| AZN-ISS | ● | ● | ● | — |
| AZN-DLG | — | ● | — | — |
| AZN-VER | ● | ● | ● | — |
| AUDIT-LOG | ● | ● | ● | ● |

● = 应调用，△ = 可调用，— = 不涉及

---

## 15 设计决策记录

### 15.1 为什么泽图采用 blob+label 而不是独立载荷结构？

泽图的核心原语只有 blob 和 label，所有 ASL 载荷统一以 blob 承载。原因：

- **不可变性免费获得**：blob 写入即固化，天然满足凭证不可篡改的需求
- **内容寻址天然去重**：相同载荷 = 相同 hash，避免重复存储
- **label 提供查询能力**：ASL 载荷中需要检索的字段映射为 label，支持高效查询
- **极简实现**：实现只需支持两种对象，不需要为每种 ASL 载荷定义独立的存储结构

### 15.2 为什么意图和授权是 blob 而不是独立对象？

ASL 定义了独立的意图载荷和授权载荷结构。泽图将其统一为 blob：

- blob 的不可变性满足意图"一旦发出不可篡改"的需求
- blob 的内容寻址满足授权凭证"可引用、可校验"的需求
- label 的 append-only 支持状态变迁（如 `x-authz-status: valid` → `consumed`）
- 对外通讯时通过适配层转换为 ASL 标准格式，不影响互操作

### 15.3 为什么约束只能收缩不能扩张？

ASL 的核心安全原则：授权边界在逐级委托中只能收缩，不能扩张。这是防止 T.DELEGATION_ESCALATION 的根本机制。

如果允许扩张，中间 Agent 可以扩大授权范围，绕过原始意图的约束，用户的原始意图就失去了意义。

### 15.4 为什么全链路校验是算法而不是新的协议原语？

CNV 是验证算法，不需要新的数据结构。它通过追溯 blob 的 hash 引用链验证完整性。这样保持了协议的极简性 — blob + label 仍是唯二的原语。

### 15.5 为什么 INF 用泽图自己的方式实现？

ASL 的 INF 规定了 TEE/KMS 的具体实现要求（如 ARM TrustZone、Intel TDX）。泽图不规定具体硬件实现，而是：

- 定义 SEE 等级声明格式（通过 agent-cert blob 的 labels）
- 定义密钥用途隔离要求（通过 agent-key blob 的 labels）
- 规定安全要求（加密存储、用途隔离），具体实现由部署方选择

这保持了协议层与实现层的分离。

### 15.6 为什么审计是泽图的一等公民而 ASL 没有？

ASL 将审计要求分散在 P.AUDIT_TRACEABILITY 约束中，没有独立的审计模块。泽图将审计提升为一等公民：

- 所有写操作自动生成审计 blob，不可关闭
- 审计哈希链提供防篡改保证
- 链完整性验证可独立执行

这是因为泽图的定位是 Agent 治理框架，审计是治理的核心需求。

### 15.7 为什么用 hash chain 而不是 Merkle Tree？

Hash chain 实现简单，验证直观（从 head 到 genesis 线性遍历）。Merkle Tree 的优势（批量验证、部分证明）在审计场景中不是刚需。如果未来需要高效的部分审计证明，可升级为 Merkle。

### 15.8 为什么保留 v0 的所有操作和 blob 类型？

v1 是 v0 的超集，不是替代。v0 的 blob 类型（audit、agent-cert、agent-key、root-ca、file、push-auth、elevation-request）和操作（push/pull/file ops 等）在 v1 中继续有效，不做破坏性变更。

---

## 16 版本

- **v0** — 初始版本：blob + label 核心原语，Agent 注册，Zone/Level 权限，文件操作，审计
- **v1** — ASL 合规 + 泽图扩展：INF 声明，IDN 身份管理，LNK 会话，INT 意图/派生/回执/CNV，AZN 授权/委托/校验，审计哈希链
- 遵循语义化版本：补丁修复不改变协议，小版本向后兼容，大版本允许破坏性变更
- v1 与 v0 向后兼容：v0 的所有操作和 blob 类型在 v1 中继续有效
