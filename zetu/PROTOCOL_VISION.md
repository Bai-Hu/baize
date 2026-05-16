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

1. **blob** — 内容寻址的原始文本（原子）
   - SHA-256 hash 作为唯一标识
   - 不可变
   - 天然去重

2. **commit** — 一组 blob 的快照 + 元数据（版本）
   - 指向一组 blob hash
   - 有序、有父子关系
   - 支持分支和标签

3. **labels** — 任意 key-value 元数据（扩展）
   - 可挂在 blob 或 commit 上
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
| blob | blob | 内容寻址的原子数据 |
| tree | (不需要) | prompt 没有目录结构 |
| commit | commit | 快照 + 元数据 |
| tag/branch | tag/branch | 指向 commit 的命名引用 |
| - | labels | **Git 没有的** — 可扩展元数据层 |
| push/pull | **元操作** | blob/write = push, blob/query = pull |

## Push/Pull 的本质

### 关键洞察

白泽管理的不是"一套代码"（Git 模型），而是**无数条独立的交互数据流**。

- Git: 所有人在同一份文件上协作编辑 → push/pull = 同步 + 合并
- 白泽: 每个 Agent/Session 是独立的数据流 → push/pull = 写入 + 查询

Agent 之间的通讯、Agent 与仲裁器的交互，全部通过 blob 操作 + labels 路由完成：

```
Agent push   = blob/write（写入交互数据）
仲裁器 pull  = blob/query（按 thread_id 聚合）
仲裁器 push  = blob/write（下发任务/决策）
Agent pull   = blob/query（查询分配给自己的任务）
```

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
- Labels 系统尚未实现（是协议的核心扩展机制）

## 下一步

1. 实现 labels 系统（EAV 表 + append-only + 查询 API）
2. 基于泽图协议规范重构现有实现，使其符合 v0 协议
3. 撰写多语言客户端集成指南
4. Agent 框架集成标准定义
