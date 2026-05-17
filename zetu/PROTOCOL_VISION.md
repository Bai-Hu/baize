# 白泽（Baize）— 协议级愿景

## 名字

**白泽（Baize）** — 项目名。取自中国神话中的博识神兽，通晓万物，象征知识的系统化记录与共享。

**泽图（Zétú）** — 协议名。取自《白泽图》，即白泽所述万物知识的标准图谱。泽图协议定义了 Agent 交互数据的记录、版本化和查询标准。

> 黄帝遇白泽 → 白泽口述万物知识 → 记录成白泽图 → 颁告天下
>
> Agent 产生交互 → 泽图协议记录 → blob/query 可查 → 所有系统共享

## 定位

白泽是 **prompt 领域的 Git** — 每个 Agent 框架都必须掌握的基础设施层。

不是工具，不是框架，是协议。协议叫泽图。

## 核心原则

1. **规范先行** — 先定义独立于实现的协议规范，再做标杆实现
2. **最稳固最简** — 参考实现只做最小核心，保证极致稳定
3. **元操作即通讯** — push/pull 不是额外协议，就是 blob/write 和 blob/query

## 最小对象模型（草案）

### 三个原语

1. **blob** — 鉴权凭证（记录操作）
   - SHA-256 hash 作为唯一标识
   - 不可变
   - 记录"谁在什么权限下做了什么操作"

2. **commit** — Agent ↔ 主仓库的数据同步操作
   - 白泽 commit = Agent 将 workspace 文件推送到主仓库工作区
   - git commit = 主仓库更新 Git 版本历史，**需要用户审批**
   - 主仓库是 Git 仓库，Git 原生提供版本历史、分支、标签、差异比较

3. **labels** — 任意 key-value 元数据（扩展）
   - 挂在 blob 上
   - append-only（可追加，不可修改或删除）
   - 所有上层语义通过 labels 约定

### 非原语（通过 labels + API 约定构建）

| 概念 | 如何从原语构建 |
|------|--------------|
| pair | `labels: { role: "prompt" }` + `labels: { role: "response", parent: "<hash>" }` |
| session | `labels: { session_id: "xxx" }` 聚合 |
| evaluation | `labels: { type: "eval-input" }` + `type: "eval-output"` |
| comparison | `labels: { type: "comparison", ref_a: "...", ref_b: "..." }` |
| thread | `labels: { thread_id: "xxx", from: "...", to: "...", msg_type: "task" }` |

## 类比 Git

| Git | 白泽/泽图 | 说明 |
|-----|-----------|------|
| blob | blob | Git 存文件内容，白泽存鉴权凭证 |
| tree | (不需要) | Agent 间通讯没有目录结构 |
| commit | 白泽 commit ≠ git commit | 白泽: Agent→主仓库推送; Git: 用户审批后版本固化 |
| tag/branch | Git branch/tag | 主仓库 Git 原生提供，用户控制 |
| - | labels | **Git 没有的** — 可扩展元数据层 |
| push/pull | **元操作** | Agent↔Agent: blob/write=query; Agent↔主仓库: 白泽 commit/pull |

## Push/Pull 的本质

### 关键洞察

Push/pull 传输的是 **blob-data 对**（blob 用于鉴权，data 是实际内容）。

白泽有两条数据路线：

1. **Agent ↔ Agent**：通过 blob 操作 + labels 路由完成
   - Agent push = blob/write（写入交互数据）
   - 仲裁器 pull = blob/query（按 thread_id 聚合）
   - 仲裁器 push = blob/write（下发任务/决策）
   - Agent pull = blob/query（查询分配给自己的任务）

2. **Agent ↔ 主仓库**：通过白泽 commit 完成（Agent 推送 + 用户审批 git commit）
   - Agent 白泽 commit = workspace → 主仓库工作区（blob 鉴权）
   - 用户审批 → git commit（版本固化）
   - Agent pull = Git 历史 → workspace（blob 鉴权）

因此 **泽图 v0 协议已经是完整的**，不需要额外的同步协议。

## 要达到协议级别需要什么

1. ~~独立的协议规范文档~~ — 已完成（`PROTOCOL_SPEC.md`）
2. **多语言客户端** — 至少覆盖 Rust、Python、TypeScript
3. ~~远程同步协议~~ — 不需要，push/pull 就是元操作
4. **Agent 框架集成标准** — 定义 Agent 如何对接（类似 Git hooks）

## 协议的延伸价值：模型训练数据基础

白泽存储的不是"提示词"，而是**结构化的交互数据** — 每条记录都有明确角色、质量评估、模型标识、上下文链路。这些是模型训练的核心原料：

| 训练场景 | 白泽提供什么 |
|---------|------------|
| SFT（监督微调） | 高质量 prompt-response pair，按 `labels: { quality: "high" }` 筛选 |
| RLHF / DPO | 同一 prompt 的多模型响应 + evaluation 对比结果，天然偏好数据 |
| 基准测试 | 标准化 prompt 集 + 多模型响应，量化模型能力 |

协议设计对训练数据质量的保障：

- **labels 聚合查询** — 按质量、领域、难度筛选大批量数据
- **commit 版本化** — 数据集版本可追溯，训练可复现
- **append-only** — 训练数据不可篡改

导出格式是上层工具的事。白泽只管存储和查询。

## 当前状态

- 泽图 v0 协议规范已完成（`PROTOCOL_SPEC.md`）
- 白泽 v0.1 参考实现完成（Rust，CLI + HTTP API）
- Labels 系统已实现（EAV 表 + append-only + 查询 API）
- 主仓库 Git 化完成（自实现 commit/ref 已移除，改用 git2）
- Push/Pull 架构重构完成（push 写入工作区，pull 从工作区同步）
- Agent 证书链 + 身份追溯已完成
- Zone/Level 权限模型已完成
- 借权（Elevation）申请/审批/归还已完成
- 审计系统已完成（所有写操作自动生成审计 blob）
- HTTP API 客户端中间件已完成（`baize-middleware` crate）

## 下一步

1. 请求签名 + 证书认证（v1 P0 — 当前仅有 `x-agent-id` 明文标识）
2. 审计哈希链（v1 P0 — 防篡改审计记录）
3. 密钥加密存储（v1 P0 — 私钥安全）
4. 撰写多语言客户端集成指南
5. Agent 框架集成标准定义
