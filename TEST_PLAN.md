# 白泽 MVP 测试计划

## 测试分层

```
E2E 测试 — 完整业务流程（CLI 端到端）
  ↑
集成测试 — 多模块协作（HTTP API + 管道 + 存储）
  ↑
单元测试 — 单模块内部逻辑（存储引擎、Scope、证书）
```

---

## 1. 单元测试

### 1.1 baize-core：存储引擎

| 测试 | 验证 |
|------|------|
| blob write 返回正确 hash | SHA-256(content) |
| blob write 幂等 | 相同内容返回相同 hash |
| blob read 正确读取 | content + labels + created_at |
| blob read 不存在返回错误 | hash 不存在 |
| blob query 按 label 过滤 | AND 语义，只返回匹配项 |
| blob query 空 label 返回全部 | 无过滤条件 |
| commit create 正确链接 parent | parent_hash 指向 HEAD |
| commit create 空 blobs 报错 | VALIDATION 错误 |
| commit create 不存在的 blob hash 报错 | NOT_FOUND 错误 |
| commit log 从 HEAD 回溯 | 按 parent 链逆序 |
| ref set 更新指针 | 旧值被覆盖 |
| ref delete HEAD 报错 | 不可删除 HEAD |
| label add 追加成功 | 新 key-value 写入 |
| label add 已有 key 报错 | LABEL_CONFLICT |
| label query 按 key+value 过滤 | 返回匹配的实体 |
| label query value=null 返回所有值 | 忽略 value 过滤 |

### 1.2 baize-core：Scope 模型

| 测试 | 验证 |
|------|------|
| Scope 子集判断 | Level 2 zones [A] ⊆ Level 3 zones [A,B,C] |
| Scope 递减合法 | parent L3 [A,B,C] → child L2 [A,B] 通过 |
| Scope Level 越界 | parent L2 → child L3 拒绝 |
| Scope Zone 越界 | parent [A,B] → child [A,B,C] 拒绝 |
| Scope Zone 超出 Level 上限 | Level 1 持有 Zone B 拒绝 |
| Scope 等于父级 | child = parent 通过 |
| Scope 空集 | child zones [] 通过（最小权限） |
| Scope 交叉检查 | parent [A,B] child [B,C] → C 越界拒绝 |

### 1.3 baize-core：证书工具

| 测试 | 验证 |
|------|------|
| Root CA 生成 | 自签名证书，subject = "Baize Root CA" |
| Agent 证书签发 | 由 Root CA 签名，包含 agent_id + scope |
| 子 Agent 证书签发 | 由 Agent 证书签发，scope 收窄 |
| 证书链验证（合法） | Root → Agent → Sub-Agent 全链通过 |
| 证书链验证（断裂） | 中间证书缺失，验证失败 |
| 证书链验证（篡改） | 证书内容被修改，验证失败 |
| 证书 scope 字段解析 | 从证书中提取 level + zones |
| 证书撤销标记 | status=revoked 的证书验证失败 |

### 1.4 baize-core：工作目录

| 测试 | 验证 |
|------|------|
| 创建工作目录 | 注册 Agent 时目录存在 |
| 销毁工作目录 | 撤销 Agent 时目录不存在 |
| Scope 内文件保留 | 清理后 scope 内文件仍存在 |
| 超出 scope 文件删除 | 清理后超出 scope 的文件被删除 |
| 空目录清理 | 无文件时不报错 |

---

## 2. 集成测试

### 2.1 五关口管道

| 测试 | 验证 |
|------|------|
| 合法请求通过管道 | pre hook 通过 → 执行 → post hook 审计 |
| 无证书请求被拒绝 | pre hook 身份验证失败 |
| scope 不足请求被拒绝 | pre hook 权限检查失败 |
| pre hook deny 不执行操作 | 操作未执行，无 blob 产生 |
| post hook 写审计 blob | 审计 blob 存在于仓库中 |
| Hook 可替换 | 注册自定义 hook 后，默认 hook 被覆盖 |

### 2.2 Scope Elevation 流程

| 测试 | 验证 |
|------|------|
| 申请借权成功 | 请求记录产生，状态 pending |
| 父 Agent 审批通过 | scope 临时扩展，证书更新 |
| 借权后可操作新 Zone | 新 Zone 内操作不再被拒绝 |
| 借权到期自动归还 | scope 回到原始状态 |
| 借权归还后 workspace 清理 | 超出 scope 的文件被删除 |
| 只读借权写操作被拒 | mode=readonly 时 write 返回错误 |
| 超出父 scope 的借权申请上报 | 自动路由到白泽审批 |

### 2.3 闭环数据管理

| 测试 | 验证 |
|------|------|
| 导入文件产生 blob | content + labels(source, trust) 写入 |
| 非可信数据进沙箱 | trust-level 0 → 不进主仓库 |
| 可信数据进主仓库 | trust-level ≥ 1 → 进主仓库 |
| 导出需要审批 | 未审批的导出被拒绝 |
| 导出产生审计记录 | 审计 blob 记录谁导出了什么 |
| Agent 直接读外部被拒 | 闭环检查：外部数据未导入不可访问 |

### 2.4 三层决策路由

| 测试 | 验证 |
|------|------|
| scope 内操作 → 自主决策 | 直接执行，无审批 |
| scope 外可借权 → 授权决策 | 进入 elevation 流程 |
| scope 外不可借权 → 用户决策 | 返回需要用户确认 |
| 白泽策略强制用户确认 | 即使 scope 内也需用户批准 |

---

## 3. E2E 测试

### 3.1 完整单 Agent 任务

```
步骤:
  1. bz init
  2. bz agent register agent-a --level 2 --zones A
  3. bz import task.md --source filesystem --trust-level 2
  4. bz blob write --content "整理桌面" --labels 'from=user,to=agent-001,type=task'
  5. bz blob write --content "已完成" --labels 'from=agent-001,to=user,type=result,parent=<task>'
  6. bz export <result-hash> --output result.md
  7. bz trace <result-hash>
  8. bz audit log

断言:
  - 步骤 3: blob 存在，labels 含 source=filesystem
  - 步骤 4: blob 存在，审计记录产生
  - 步骤 5: blob 的 parent label 指向步骤 4 的 hash
  - 步骤 6: result.md 内容正确，导出审计 blob 存在
  - 步骤 7: 追溯链: result → task → import
  - 步骤 8: 审计日志包含所有步骤的操作记录
```

### 3.2 多 Agent 层级委派

```
步骤:
  1. bz init
  2. bz agent register coordinator --level 3 --zones A,B,D
  3. bz agent delegate coordinator agent-a --level 2 --zones A
  4. bz agent delegate coordinator agent-b --level 2 --zones B
  5. bz blob write --content "主任务" --labels 'from=user,to=coordinator,type=task'
  6. bz blob write --content "子任务A" --labels 'from=coordinator,to=agent-a,type=task,parent=<main>'
  7. bz blob write --content "子任务B" --labels 'from=coordinator,to=agent-b,type=task,parent=<main>'
  8. bz blob write --content "结果A" --labels 'from=agent-a,to=coordinator,type=result,parent=<sub-a>'
  9. bz blob write --content "结果B" --labels 'from=agent-b,to=coordinator,type=result,parent=<sub-b>'
  10. bz blob write --content "汇总" --labels 'from=coordinator,to=user,type=result,parent=<main>'
  11. bz trace <汇总hash>
  12. bz agent revoke agent-a-id
  13. bz agent revoke agent-b-id

断言:
  - 步骤 3/4: 子 Agent 证书链可验证到 Root
  - 步骤 6/7: coordinator 有 Zone D，可委派
  - 步骤 8/9: agent-a 只有 Zone A，不能访问 Zone B 数据
  - 步骤 11: 追溯链完整（汇总 → 主任务 → 子任务 → 结果）
  - 步骤 12/13: Agent 撤销后 workspace 销毁，blob 保留
```

### 3.3 借权与 Workspace 清理

```
步骤:
  1. bz init
  2. bz agent register agent-a --level 2 --zones A
  3. bz blob write --content "需要网络数据" --labels 'from=user,to=agent-001,type=task'
  4. bz elevate request --zones C --mode readonly --reason "查询 API"
  5. bz elevate approve <request-id>
  6. bz import http://api.example.com/data --source api --trust-level 1
  7. （Agent 在 workspace 中存入 API 数据）
  8. 借权到期
  9. 检查 workspace：Zone A 文件保留，Zone C 数据已清理
  10. Agent 尝试访问 Zone C → 被拒绝

断言:
  - 步骤 5: Agent scope 临时包含 Zone C
  - 步骤 6: API 数据成功导入（借权 scope 内）
  - 步骤 8: scope 回到 Zone A
  - 步骤 9: workspace 清理正确
  - 步骤 10: Zone C 操作被拒绝
```

### 3.4 闭环数据安全

```
步骤:
  1. bz init
  2. bz agent register agent-a --level 2 --zones A
  3. bz import trusted.txt --source filesystem --trust-level 2
  4. bz import untrusted.bin --source unknown --trust-level 0
  5. Agent 读取 trusted.txt blob → 成功
  6. Agent 读取 untrusted.bin blob → 失败（在沙箱，不在主仓库）
  7. Agent 尝试直接读外部文件 → 失败（闭环检查）
  8. bz export <trusted-hash> --output out.txt → 成功
  9. bz audit query --agent agent-001

断言:
  - 步骤 3: trusted blob 在主仓库
  - 步骤 4: untrusted blob 在沙箱区
  - 步骤 5: scope 内可读
  - 步骤 6: 沙箱数据 Agent 不可访问
  - 步骤 7: 闭环强制执行
  - 步骤 8: 导出有审计记录
  - 步骤 9: 所有操作可查
```

---

## 测试执行

```bash
# 单元测试
cargo test -p baize-core

# 集成测试
cargo test -p baize-server

# E2E（需要编译好的 bz 二进制）
cargo build
./tests/e2e.sh

# 全量
cargo test --workspace
```

## 测试统计目标

| 层级 | 目标数量 |
|------|---------|
| 单元测试 | ~80（存储 40 + Scope 20 + 证书 15 + 工作目录 5） |
| 集成测试 | ~25（管道 6 + 借权 7 + 闭环 6 + 决策 6） |
| E2E 测试 | 4（完整场景） |
| **总计** | **~109** |
