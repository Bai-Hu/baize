#!/usr/bin/env bash
# 白泽 E2E 测试
# 测试 CLI 二进制的完整生命周期场景
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BZ="$SCRIPT_DIR/../target/release/bz"
TEST_DIR=""
PASS=0
FAIL=0
TOTAL=0

# ─── 辅助函数 ───

setup() {
    TEST_DIR=$(mktemp -d /tmp/baize-e2e-XXXXXX)
    cd "$TEST_DIR"
}

teardown() {
    if [ -n "$TEST_DIR" ]; then
        cd /
        rm -rf "$TEST_DIR"
    fi
}

assert_ok() {
    local desc="$1"; shift
    TOTAL=$((TOTAL + 1))
    if "$@" >/dev/null 2>&1; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: $desc"
        "$@" 2>&1 || true
    fi
}

assert_fail() {
    local desc="$1"; shift
    TOTAL=$((TOTAL + 1))
    if "$@" >/dev/null 2>&1; then
        FAIL=$((FAIL + 1))
        echo "FAIL (expected error): $desc"
    else
        PASS=$((PASS + 1))
    fi
}

assert_output_contains() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    TOTAL=$((TOTAL + 1))
    if echo "$actual" | grep -qF "$expected"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: $desc"
        echo "  expected to contain: $expected"
        echo "  actual: $actual"
    fi
}

extract_hash() {
    # 从 "Blob 写入成功: <hash>" 或 "Commit 创建成功: <hash>" 提取 hash
    # 只取第一个出现的 64 位 hex（即 commit/blob hash，忽略后续的 blob hash 列表）
    echo "$1" | grep -oP '[0-9a-f]{64}' | head -1 | tr -d '\n'
}

extract_elev_id() {
    # 从 "借权申请已提交: <hash>" 提取 hash（64 位 hex）
    echo "$1" | grep -oP '[0-9a-f]{64}' | head -1 | tr -d '\n'
}

# ─── 场景 1: 完整数据生命周期 ───
# init → blob → commit → log → ref → label → trace → audit

test_full_lifecycle() {
    echo "=== 场景 1: 完整数据生命周期 ==="
    setup

    # init (使用默认路径 baize.db + .baize/workspaces)
    assert_ok "init" $BZ init
    [ -f baize.db ] || { FAIL=$((FAIL + 1)); echo "FAIL: db file not created"; TOTAL=$((TOTAL + 1)); }

    # blob write
    out=$($BZ blob write --content "hello baize" --labels "type=greeting,lang=zh")
    assert_output_contains "blob write success" "写入成功" "$out"
    BLOB_HASH=$(extract_hash "$out")
    [ -n "$BLOB_HASH" ] || { FAIL=$((FAIL + 1)); echo "FAIL: no blob hash"; TOTAL=$((TOTAL + 1)); }

    # blob read
    out=$($BZ blob read "$BLOB_HASH")
    assert_output_contains "blob read content" "hello baize" "$out"
    assert_output_contains "blob read label" "greeting" "$out"

    # blob query
    out=$($BZ blob query --labels "type=greeting")
    assert_output_contains "blob query result" "$BLOB_HASH" "$out"

    # commit
    out=$($BZ commit create --blobs "$BLOB_HASH" -m "initial commit")
    assert_output_contains "commit success" "创建成功" "$out"
    COMMIT_HASH=$(extract_hash "$out")
    [ -n "$COMMIT_HASH" ] || { FAIL=$((FAIL + 1)); echo "FAIL: no commit hash"; TOTAL=$((TOTAL + 1)); }

    # log
    out=$($BZ log)
    assert_output_contains "log shows commit" "initial commit" "$out"

    # ref
    assert_ok "ref set" $BZ ref set v1 "$COMMIT_HASH"
    out=$($BZ ref get v1)
    assert_output_contains "ref get" "$COMMIT_HASH" "$out"

    # ref list
    out=$($BZ ref list)
    assert_output_contains "ref list has v1" "v1" "$out"

    # label
    assert_ok "label add" $BZ label add "$BLOB_HASH" "priority" "high"
    out=$($BZ label query priority --value high)
    assert_output_contains "label query" "$BLOB_HASH" "$out"

    # trace data
    out=$($BZ trace "$COMMIT_HASH")
    assert_output_contains "trace data" "initial commit" "$out"

    # audit (only export audit from this session)
    # init doesn't audit, so audit log may be empty or have export audit
    # Skip audit check for this scenario - covered in scenario 6

    teardown
}

# ─── 场景 2: Agent 注册 + 身份追溯 ───
# 注意：CLI 每个命令独立打开 Baize 实例，agents 信息在内存中不跨命令保留。
# delegate 需要父 agent 的 IssuerCtx 来签发子证书，这在 CLI 中无法跨命令完成。
# 所以这里只测试直接注册 agent 的场景（issuer 是 root）。

test_agent_registration() {
    echo "=== 场景 2: Agent 注册 + 身份追溯 ==="
    setup

    assert_ok "init" $BZ init

    # register agent (parent = root, by default)
    out=$($BZ agent register operator --level 3 --zones A,B,C)
    assert_output_contains "operator registered" "注册成功" "$out"
    assert_output_contains "operator level" "Level: 3" "$out"

    # register another agent
    out=$($BZ agent register worker --level 2 --zones A)
    assert_output_contains "worker registered" "注册成功" "$out"

    # list agents (independent open_baize: only root from init)
    # agent list works because it reads from memory, but after reopen only root is there
    # so we just verify the command succeeds
    out=$($BZ agent list)
    assert_output_contains "list has root" "baize-root" "$out"

    # revoke root should fail
    assert_fail "revoke root" $BZ agent revoke baize-root

    teardown
}

# ─── 场景 3: Agent 委托链（单命令内通过 API 测试）───
# 测试 pipeline 内部的委托能力

test_agent_delegation() {
    echo "=== 场景 3: Agent 委托链 + scope 校验 ==="
    setup

    assert_ok "init" $BZ init

    # 成功路径：注册父 agent，然后委托子 agent
    assert_ok "register parent" $BZ agent register ops --level 3 --zones A,B,C
    out=$($BZ agent delegate ops worker --level 2 --zones A)
    assert_output_contains "delegate success" "注册成功" "$out"

    # 验证列表包含 root + ops + worker
    out=$($BZ agent list)
    assert_output_contains "list has ops" "ops" "$out"
    assert_output_contains "list has worker" "worker" "$out"

    # scope exceed: child level > root level 4 should fail
    assert_fail "invalid level 5" $BZ agent register bad --level 5 --zones A

    # invalid zones for level 0 (0 zones allowed)
    assert_ok "level 0 with zones (allowed, but cannot write)" $BZ agent register sandbox --level 0 --zones A

    teardown
}

# ─── 场景 4: 借权流程 ───
# 注意：elevation_request 需要 agent 在内存 HashMap 中。
# CLI 每个命令独立 init，所以 elevation 只能对 baize-root 操作（因为 root 总在）。

test_elevation_flow() {
    echo "=== 场景 4: 借权流程 ==="
    setup

    assert_ok "init" $BZ init

    # request elevation for root (root is always in memory)
    out=$($BZ elevate request --zones A --mode readonly --reason "test elevation" --agent baize-root)
    assert_output_contains "elevation requested" "借权申请已提交" "$out"
    ELEV_ID=$(extract_elev_id "$out")
    [ -n "$ELEV_ID" ] || { FAIL=$((FAIL + 1)); echo "FAIL: no elevation id"; TOTAL=$((TOTAL + 1)); }

    # list pending (独立 open_baize，但 elevation 持久化在 SQLite 中)
    out=$($BZ elevate list)
    assert_output_contains "elevation list" "baize-root" "$out"

    # approve
    assert_ok "elevation approve" $BZ elevate approve "$ELEV_ID"

    # verify approved
    out=$($BZ elevate list)
    assert_output_contains "elevation approved" "Approved" "$out"

    # approve again should fail
    assert_fail "re-approve" $BZ elevate approve "$ELEV_ID"

    # nonexistent agent should fail
    assert_fail "ghost agent" $BZ elevate request --zones A --mode readonly --reason "x" --agent ghost

    teardown
}

# ─── 场景 5: 数据导入导出 ───

test_import_export() {
    echo "=== 场景 5: 数据导入导出 ==="
    setup

    assert_ok "init" $BZ init

    # create source file
    echo "external data content" > "$TEST_DIR/source.txt"

    # import
    out=$($BZ import "$TEST_DIR/source.txt" --source unittest --trust-level 2)
    assert_output_contains "import success" "导入成功" "$out"
    IMPORT_HASH=$(extract_hash "$out")
    [ -n "$IMPORT_HASH" ] || { FAIL=$((FAIL + 1)); echo "FAIL: no import hash"; TOTAL=$((TOTAL + 1)); }

    # export
    assert_ok "export" $BZ export "$IMPORT_HASH" --output "$TEST_DIR/exported.txt"

    # verify content matches
    TOTAL=$((TOTAL + 1))
    if diff "$TEST_DIR/source.txt" "$TEST_DIR/exported.txt" >/dev/null 2>&1; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: export content mismatch"
    fi

    # import with sandbox (trust-level 0)
    out=$($BZ import "$TEST_DIR/source.txt" --source untrusted --trust-level 0)
    assert_output_contains "sandbox import" "trust-level: 0" "$out"

    # query imported blobs
    out=$($BZ blob query --labels "imported=true")
    assert_output_contains "query imported" "2" "$out"  # two imported blobs

    # path traversal should fail
    assert_fail "import path traversal" $BZ import ../../etc/passwd --source evil --trust-level 0

    teardown
}

# ─── 场景 6: Commit 链 + 数据追溯 ───

test_commit_chain_and_trace() {
    echo "=== 场景 6: Commit 链 + 数据追溯 ==="
    setup

    assert_ok "init" $BZ init

    # write 3 blobs
    B1=$($BZ blob write --content "version 1" | grep -oP '[0-9a-f]{64}')
    B2=$($BZ blob write --content "version 2" | grep -oP '[0-9a-f]{64}')
    B3=$($BZ blob write --content "version 3" | grep -oP '[0-9a-f]{64}')

    # commit chain: c1 → c2 → c3
    C1=$($BZ commit create --blobs "$B1" -m "first" | head -1 | grep -oP '[0-9a-f]{64}')
    C2=$($BZ commit create --blobs "$B2" -m "second" --parent "$C1" | head -1 | grep -oP '[0-9a-f]{64}')
    C3=$($BZ commit create --blobs "$B3" -m "third" --parent "$C2" | head -1 | grep -oP '[0-9a-f]{64}')

    # log should show 3 commits (newest first)
    out=$($BZ log)
    assert_output_contains "log has third" "third" "$out"
    assert_output_contains "log has second" "second" "$out"
    assert_output_contains "log has first" "first" "$out"

    # trace from c2 → c1
    out=$($BZ trace "$C2")
    assert_output_contains "trace c2" "second" "$out"
    assert_output_contains "trace c2 parent" "first" "$out"

    # HEAD should point to c3
    out=$($BZ ref get HEAD)
    assert_output_contains "head is c3" "$C3" "$out"

    # ref operations
    assert_ok "ref set stable" $BZ ref set stable "$C1"
    out=$($BZ ref get stable)
    assert_output_contains "stable ref" "$C1" "$out"

    assert_ok "ref delete stable" $BZ ref delete stable
    assert_fail "ref delete HEAD" $BZ ref delete HEAD

    teardown
}

# ─── 场景 7: 审计完整性 ───

test_audit_integrity() {
    echo "=== 场景 7: 审计完整性 ==="
    setup

    assert_ok "init" $BZ init

    # register an agent (generates audit record)
    $BZ agent register auditor --level 2 --zones A >/dev/null

    # check audit has the register record
    out=$($BZ audit)
    assert_output_contains "audit register" "agent_register" "$out"
    assert_output_contains "audit auditor" "auditor" "$out"

    # export generates audit too
    B1=$($BZ blob write --content "test" | grep -oP '[0-9a-f]{64}')
    $BZ export "$B1" --output "$TEST_DIR/out.txt" >/dev/null

    out=$($BZ audit)
    assert_output_contains "audit export" "export" "$out"

    teardown
}

# ─── 场景 8: 跨命令 Agent 委托链 ───
# 验证 agent 状态跨命令持久化：register → delegate → trace → revoke

test_cross_cmd_delegation() {
    echo "=== 场景 8: 跨命令 Agent 委托链 ==="
    setup

    assert_ok "init" $BZ init

    # 注册父 agent
    out=$($BZ agent register ops --level 3 --zones A,B,C)
    assert_output_contains "ops registered" "注册成功" "$out"

    # 委托子 agent（跨命令，agent 状态从 SQLite 恢复）
    out=$($BZ agent delegate ops worker --level 2 --zones A)
    assert_output_contains "worker delegated" "注册成功" "$out"
    assert_output_contains "worker parent" "ops" "$out"

    # 列表显示 3 个 agent（root, ops, worker）
    out=$($BZ agent list)
    assert_output_contains "list has root" "baize-root" "$out"
    assert_output_contains "list has ops" "ops" "$out"
    assert_output_contains "list has worker" "worker" "$out"

    # trace identity worker → ops → root
    out=$($BZ trace --identity worker)
    assert_output_contains "trace worker" "worker" "$out"
    assert_output_contains "trace ops" "ops" "$out"
    assert_output_contains "trace root" "baize-root" "$out"

    # 撤销子 agent
    assert_ok "revoke worker" $BZ agent revoke worker

    # 列表只剩 root + ops
    out=$($BZ agent list)
    assert_output_contains "after revoke root" "baize-root" "$out"
    assert_output_contains "after revoke ops" "ops" "$out"

    # 撤销不存在的 agent 应失败
    assert_fail "revoke ghost" $BZ agent revoke ghost

    # scope 递减违规：child level > parent level 应失败
    assert_fail "scope exceed" $BZ agent delegate ops bad --level 4 --zones A

    teardown
}

# ─── 场景 9: 跨命令非 Root Agent 借权 ───
# 验证注册的 agent 跨命令可以申请借权

test_cross_cmd_elevation() {
    echo "=== 场景 9: 跨命令非 Root Agent 借权 ==="
    setup

    assert_ok "init" $BZ init

    # 注册 agent
    $BZ agent register worker --level 2 --zones A,B >/dev/null

    # 跨命令：agent 状态恢复，worker 可申请借权
    out=$($BZ elevate request --zones A --mode readonly --reason "need A access" --agent worker)
    assert_output_contains "worker elevation" "借权申请已提交" "$out"
    ELEV_ID=$(extract_elev_id "$out")
    [ -n "$ELEV_ID" ] || { FAIL=$((FAIL + 1)); echo "FAIL: no elevation id"; TOTAL=$((TOTAL + 1)); }

    # 跨命令审批
    assert_ok "approve" $BZ elevate approve "$ELEV_ID"

    # 验证已批准
    out=$($BZ elevate list)
    assert_output_contains "approved status" "Approved" "$out"
    assert_output_contains "elevation agent" "worker" "$out"

    # 申请超出 scope 的 zone 也应成功（借权的意义就是获取超出 scope 的权限）
    assert_ok "zone beyond scope" $BZ elevate request --zones Z --mode readonly --reason "need Z" --agent worker

    teardown
}

# ─── 场景 10: 跨命令 Agent 状态恢复 ───
# 验证多次 open_baize 后 agent 列表一致

test_cross_cmd_agent_persistence() {
    echo "=== 场景 10: 跨命令 Agent 状态恢复 ==="
    setup

    assert_ok "init" $BZ init

    # 注册 3 个 agent
    $BZ agent register alpha --level 3 --zones A,B,C >/dev/null
    $BZ agent register beta --level 2 --zones A >/dev/null
    $BZ agent delegate alpha gamma --level 1 --zones A >/dev/null

    # 跨命令：agent list 从存储恢复所有 agent
    out=$($BZ agent list)
    assert_output_contains "has alpha" "alpha" "$out"
    assert_output_contains "has beta" "beta" "$out"
    assert_output_contains "has gamma" "gamma" "$out"
    assert_output_contains "has root" "baize-root" "$out"

    # 验证 trace identity gamma → alpha → root 链完整
    out=$($BZ trace --identity gamma)
    assert_output_contains "gamma chain" "gamma" "$out"
    assert_output_contains "gamma parent alpha" "alpha" "$out"
    assert_output_contains "gamma root" "baize-root" "$out"

    # 撤销 alpha（gamma 仍存在但 parent 已不在内存中）
    assert_ok "revoke alpha" $BZ agent revoke alpha

    # 列表应该没有 alpha（作为 agent ID，而非 parent 引用）
    out=$($BZ agent list)
    TOTAL=$((TOTAL + 1))
    if echo "$out" | grep -qP '^\s*alpha \|'; then
        FAIL=$((FAIL + 1))
        echo "FAIL: alpha should be revoked"
    else
        PASS=$((PASS + 1))
    fi

    teardown
}

# ─── 场景 11: 借权归还流程 ───
# 注册 agent → 申请借权(duration) → 审批 → 归还 → 验证状态

test_elevation_return() {
    echo "=== 场景 11: 借权归还流程 ==="
    setup

    assert_ok "init" $BZ init

    # 注册 agent
    $BZ agent register worker --level 3 --zones A,B >/dev/null

    # 申请借权（带 duration）
    out=$($BZ elevate request --zones B --mode readonly --reason "need B" --agent worker --duration 30m)
    assert_output_contains "elevation requested" "借权申请已提交" "$out"
    ELEV_ID=$(extract_elev_id "$out")
    [ -n "$ELEV_ID" ] || { FAIL=$((FAIL + 1)); echo "FAIL: no elevation id"; TOTAL=$((TOTAL + 1)); }

    # 审批
    assert_ok "approve" $BZ elevate approve "$ELEV_ID"

    # 验证已批准
    out=$($BZ elevate list)
    assert_output_contains "approved" "Approved" "$out"

    # 归还
    assert_ok "return" $BZ elevate return "$ELEV_ID" --agent worker

    # 验证已归还
    out=$($BZ elevate list)
    assert_output_contains "returned" "Returned" "$out"

    teardown
}

# ─── 运行 ───

main() {
    echo "白泽 E2E 测试"
    echo "Binary: $BZ"
    echo ""

    # build if needed
    if [ ! -f "$BZ" ]; then
        echo "Building release binary..."
        cargo build --release --manifest-path "$(dirname "$0")/../Cargo.toml"
    fi

    test_full_lifecycle
    test_agent_registration
    test_agent_delegation
    test_elevation_flow
    test_import_export
    test_commit_chain_and_trace
    test_audit_integrity
    test_cross_cmd_delegation
    test_cross_cmd_elevation
    test_cross_cmd_agent_persistence
    test_elevation_return

    echo ""
    echo "========================================"
    echo "E2E 结果: $PASS/$TOTAL 通过, $FAIL 失败"
    echo "========================================"

    [ "$FAIL" -eq 0 ] || exit 1
}

main "$@"
