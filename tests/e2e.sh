#!/usr/bin/env bash
# 白泽 E2E 测试
# 测试 CLI 二进制的完整 Agent 治理生命周期
# 架构：blob = 鉴权凭证，主仓库 = Git 仓库，push/pull = workspace ↔ 主仓库
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
    echo "$1" | grep -oP '[0-9a-f]{64}' | head -1 | tr -d '\n'
}

extract_elev_id() {
    echo "$1" | grep -oP '[0-9a-f]{64}' | head -1 | tr -d '\n'
}

# ─── 场景 1: 完整 Agent 数据生命周期 ───
# init → register agent → file write → push → log → ref → label → audit → stats

test_full_lifecycle() {
    echo "=== 场景 1: 完整 Agent 数据生命周期 ==="
    setup

    # init
    assert_ok "init" $BZ init
    [ -f baize.db ] || { FAIL=$((FAIL + 1)); echo "FAIL: db file not created"; TOTAL=$((TOTAL + 1)); }

    # register agent
    out=$($BZ agent register worker --level 2 --zones A,B)
    assert_output_contains "worker registered" "注册成功" "$out"

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

    # file write to workspace
    out=$($BZ file write A/config.yaml --content "key: value" --agent worker)
    assert_output_contains "file write success" "写入成功" "$out"
    out=$($BZ file write A/data.txt --content "agent data" --agent worker)
    assert_output_contains "file write 2" "写入成功" "$out"

    # file list
    out=$($BZ file ls --agent worker)
    assert_output_contains "file list has config" "config.yaml" "$out"
    assert_output_contains "file list has data" "data.txt" "$out"

    # push: workspace → 主仓库工作区
    out=$($BZ push -m "worker initial files" --agent worker)
    assert_output_contains "push success" "Push 成功" "$out"
    assert_output_contains "push files" "2" "$out"
    assert_output_contains "push pending" "等待用户审批" "$out"

    # log (git log — 应该为空，因为还没有用户审批的 git commit)
    out=$($BZ log)
    assert_output_contains "log empty" "Git" "$out"

    # ref list (新仓库只有初始化时的 HEAD)
    out=$($BZ ref list)
    assert_output_contains "ref list works" "Git Refs" "$out"

    # label
    assert_ok "label add" $BZ label add "$BLOB_HASH" "priority" "high"
    out=$($BZ label query priority --value high)
    assert_output_contains "label query" "$BLOB_HASH" "$out"

    # trace identity (现在是唯一模式)
    out=$($BZ trace worker)
    assert_output_contains "trace worker" "worker" "$out"
    assert_output_contains "trace root" "baize-root" "$out"

    # stats
    out=$($BZ stats)
    assert_output_contains "stats blobs" "Blobs" "$out"

    teardown
}

# ─── 场景 2: Agent 注册 + 身份追溯 ───

test_agent_registration() {
    echo "=== 场景 2: Agent 注册 + 身份追溯 ==="
    setup

    assert_ok "init" $BZ init

    # register agent
    out=$($BZ agent register operator --level 3 --zones A,B,C)
    assert_output_contains "operator registered" "注册成功" "$out"
    assert_output_contains "operator level" "Level: 3" "$out"

    out=$($BZ agent register worker --level 2 --zones A)
    assert_output_contains "worker registered" "注册成功" "$out"

    # list agents
    out=$($BZ agent list)
    assert_output_contains "list has root" "baize-root" "$out"

    # revoke root should fail
    assert_fail "revoke root" $BZ agent revoke baize-root

    teardown
}

# ─── 场景 3: Agent 委托链 + scope 校验 ───

test_agent_delegation() {
    echo "=== 场景 3: Agent 委托链 + scope 校验 ==="
    setup

    assert_ok "init" $BZ init

    # register parent → delegate child
    assert_ok "register parent" $BZ agent register ops --level 3 --zones A,B,C
    out=$($BZ agent delegate ops worker --level 2 --zones A)
    assert_output_contains "delegate success" "注册成功" "$out"

    out=$($BZ agent list)
    assert_output_contains "list has ops" "ops" "$out"
    assert_output_contains "list has worker" "worker" "$out"

    # scope exceed
    assert_fail "invalid level 5" $BZ agent register bad --level 5 --zones A

    # level 0 is allowed (sandbox, cannot write)
    assert_ok "level 0 sandbox" $BZ agent register sandbox --level 0 --zones A

    teardown
}

# ─── 场景 4: 借权流程 ───

test_elevation_flow() {
    echo "=== 场景 4: 借权流程 ==="
    setup

    assert_ok "init" $BZ init

    # request elevation for root
    out=$($BZ elevate request --zones A --mode readonly --reason "test elevation" --agent baize-root)
    assert_output_contains "elevation requested" "借权申请已提交" "$out"
    ELEV_ID=$(extract_elev_id "$out")
    [ -n "$ELEV_ID" ] || { FAIL=$((FAIL + 1)); echo "FAIL: no elevation id"; TOTAL=$((TOTAL + 1)); }

    # list pending
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
    assert_output_contains "query imported" "2" "$out"

    # path traversal should fail
    assert_fail "import path traversal" $BZ import ../../etc/passwd --source evil --trust-level 0

    teardown
}

# ─── 场景 6: Push/Pull 跨 Agent 协作 ───

test_push_pull_cross_agent() {
    echo "=== 场景 6: Push/Pull 跨 Agent 协作 ==="
    setup

    assert_ok "init" $BZ init

    # 注册两个 agent
    $BZ agent register alice --level 2 --zones A >/dev/null
    $BZ agent register bob --level 2 --zones A >/dev/null

    # alice 写文件并 push
    $BZ file write A/shared.txt --content "from alice" --agent alice >/dev/null
    out=$($BZ push -m "alice's work" --agent alice)
    assert_output_contains "alice push" "Push 成功" "$out"
    assert_output_contains "alice push files" "1" "$out"

    # bob pull → 拿到 alice 的文件
    out=$($BZ pull --agent bob)
    assert_output_contains "bob pull" "Pull 成功" "$out"
    assert_output_contains "bob pull files" "1" "$out"

    # 验证 bob 能读到 alice 的文件
    out=$($BZ file read A/shared.txt --agent bob)
    assert_output_contains "bob reads alice file" "from alice" "$out"

    teardown
}

# ─── 场景 7: Zone 隔离 ───

test_zone_isolation() {
    echo "=== 场景 7: Zone 隔离 ==="
    setup

    assert_ok "init" $BZ init

    # alice 有 zone A，bob 有 zone B
    $BZ agent register alice --level 2 --zones A >/dev/null
    $BZ agent register bob --level 2 --zones B >/dev/null

    # alice 写 zone A 文件
    $BZ file write A/data.txt --content "alice data" --agent alice >/dev/null

    # alice 尝试写 zone B → 应失败
    assert_fail "alice write zone B" $BZ file write B/evil.txt --content "hack" --agent alice

    # alice push zone A 文件
    $BZ push -m "alice zone A" --agent alice >/dev/null

    # bob pull → 只有 zone B 文件被拉取（zone A 被跳过）
    out=$($BZ pull --agent bob)
    assert_output_contains "bob pull from alice" "Pull 成功" "$out"
    # bob 的 workspace 应为空（只有 A 文件，bob 是 zone B）
    out=$($BZ file ls --agent bob)
    # bob 不应有 A/data.txt
    TOTAL=$((TOTAL + 1))
    if echo "$out" | grep -qF "A/data.txt"; then
        FAIL=$((FAIL + 1))
        echo "FAIL: bob should not see zone A files"
    else
        PASS=$((PASS + 1))
    fi

    teardown
}

# ─── 场景 8: 审计完整性 ───

test_audit_integrity() {
    echo "=== 场景 8: 审计完整性 ==="
    setup

    assert_ok "init" $BZ init

    # register an agent (generates audit record)
    $BZ agent register auditor --level 2 --zones A >/dev/null

    # check audit has the register record
    out=$($BZ audit)
    assert_output_contains "audit register" "agent_register" "$out"
    assert_output_contains "audit auditor" "auditor" "$out"

    # file write generates audit
    $BZ file write A/test.txt --content "audit test" --agent auditor >/dev/null

    out=$($BZ audit)
    assert_output_contains "audit file write" "file_write" "$out"

    # push generates audit
    $BZ push -m "audit test push" --agent auditor >/dev/null

    out=$($BZ audit)
    assert_output_contains "audit push" "push" "$out"

    # export generates audit
    B1=$($BZ blob write --content "test" | grep -oP '[0-9a-f]{64}')
    $BZ export "$B1" --output "$TEST_DIR/out.txt" >/dev/null

    out=$($BZ audit)
    assert_output_contains "audit export" "export" "$out"

    teardown
}

# ─── 场景 9: 跨命令 Agent 委托链 ───

test_cross_cmd_delegation() {
    echo "=== 场景 9: 跨命令 Agent 委托链 ==="
    setup

    assert_ok "init" $BZ init

    # 注册父 agent
    out=$($BZ agent register ops --level 3 --zones A,B,C)
    assert_output_contains "ops registered" "注册成功" "$out"

    # 委托子 agent（跨命令，agent 状态从 SQLite 恢复）
    out=$($BZ agent delegate ops worker --level 2 --zones A)
    assert_output_contains "worker delegated" "注册成功" "$out"
    assert_output_contains "worker parent" "ops" "$out"

    # 列表显示 3 个 agent
    out=$($BZ agent list)
    assert_output_contains "list has root" "baize-root" "$out"
    assert_output_contains "list has ops" "ops" "$out"
    assert_output_contains "list has worker" "worker" "$out"

    # trace identity worker → ops → root
    out=$($BZ trace worker)
    assert_output_contains "trace worker" "worker" "$out"
    assert_output_contains "trace ops" "ops" "$out"
    assert_output_contains "trace root" "baize-root" "$out"

    # 撤销子 agent
    assert_ok "revoke worker" $BZ agent revoke worker

    # 列表只剩 root + ops
    out=$($BZ agent list)
    assert_output_contains "after revoke root" "baize-root" "$out"
    assert_output_contains "after revoke ops" "ops" "$out"

    assert_fail "revoke ghost" $BZ agent revoke ghost
    assert_fail "scope exceed" $BZ agent delegate ops bad --level 4 --zones A

    teardown
}

# ─── 场景 10: 跨命令非 Root Agent 借权 ───

test_cross_cmd_elevation() {
    echo "=== 场景 10: 跨命令非 Root Agent 借权 ==="
    setup

    assert_ok "init" $BZ init

    $BZ agent register worker --level 2 --zones A,B >/dev/null

    # 跨命令：agent 状态恢复，worker 可申请借权
    out=$($BZ elevate request --zones A --mode readonly --reason "need A access" --agent worker)
    assert_output_contains "worker elevation" "借权申请已提交" "$out"
    ELEV_ID=$(extract_elev_id "$out")
    [ -n "$ELEV_ID" ] || { FAIL=$((FAIL + 1)); echo "FAIL: no elevation id"; TOTAL=$((TOTAL + 1)); }

    assert_ok "approve" $BZ elevate approve "$ELEV_ID"

    out=$($BZ elevate list)
    assert_output_contains "approved status" "Approved" "$out"
    assert_output_contains "elevation agent" "worker" "$out"

    # 申请超出 scope 的 zone 也应成功
    assert_ok "zone beyond scope" $BZ elevate request --zones Z --mode readonly --reason "need Z" --agent worker

    teardown
}

# ─── 场景 11: 跨命令 Agent 状态恢复 ───

test_cross_cmd_agent_persistence() {
    echo "=== 场景 11: 跨命令 Agent 状态恢复 ==="
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

    # trace identity gamma → alpha → root 链完整
    out=$($BZ trace gamma)
    assert_output_contains "gamma chain" "gamma" "$out"
    assert_output_contains "gamma parent alpha" "alpha" "$out"
    assert_output_contains "gamma root" "baize-root" "$out"

    # 撤销 alpha
    assert_ok "revoke alpha" $BZ agent revoke alpha

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

# ─── 场景 12: 借权归还流程 ───

test_elevation_return() {
    echo "=== 场景 12: 借权归还流程 ==="
    setup

    assert_ok "init" $BZ init

    $BZ agent register worker --level 3 --zones A,B >/dev/null

    # 申请借权（带 duration）
    out=$($BZ elevate request --zones B --mode readonly --reason "need B" --agent worker --duration 30m)
    assert_output_contains "elevation requested" "借权申请已提交" "$out"
    ELEV_ID=$(extract_elev_id "$out")
    [ -n "$ELEV_ID" ] || { FAIL=$((FAIL + 1)); echo "FAIL: no elevation id"; TOTAL=$((TOTAL + 1)); }

    assert_ok "approve" $BZ elevate approve "$ELEV_ID"

    out=$($BZ elevate list)
    assert_output_contains "approved" "Approved" "$out"

    # 归还
    assert_ok "return" $BZ elevate return "$ELEV_ID" --agent worker

    out=$($BZ elevate list)
    assert_output_contains "returned" "Returned" "$out"

    teardown
}

# ─── 场景 13: Push 后文件确实到达主仓库工作区 ───

test_push_files_in_main_repo() {
    echo "=== 场景 13: Push 后文件在主仓库工作区 ==="
    setup

    assert_ok "init" $BZ init
    $BZ agent register writer --level 2 --zones X >/dev/null

    # 写入多个文件并 push
    $BZ file write X/app.py --content "print('hello')" --agent writer >/dev/null
    $BZ file write X/config.json --content '{"port": 8080}' --agent writer >/dev/null
    out=$($BZ push -m "v1" --agent writer)
    assert_output_contains "push 2 files" "2" "$out"

    # 验证文件在主仓库工作区（.baize/main/ 目录下）
    TOTAL=$((TOTAL + 1))
    if [ -f ".baize/main/X/app.py" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: X/app.py not found in main repo"
    fi

    TOTAL=$((TOTAL + 1))
    if [ -f ".baize/main/X/config.json" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: X/config.json not found in main repo"
    fi

    teardown
}

# ─── 场景 14: Push 空工作区应失败 ───

test_push_empty_fails() {
    echo "=== 场景 14: Push 空工作区应失败 ==="
    setup

    assert_ok "init" $BZ init
    $BZ agent register worker --level 2 --zones A >/dev/null

    # workspace 为空 → push 应失败
    assert_fail "push empty workspace" $BZ push -m "empty" --agent worker

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
    test_push_pull_cross_agent
    test_zone_isolation
    test_audit_integrity
    test_cross_cmd_delegation
    test_cross_cmd_elevation
    test_cross_cmd_agent_persistence
    test_elevation_return
    test_push_files_in_main_repo
    test_push_empty_fails

    echo ""
    echo "========================================"
    echo "E2E 结果: $PASS/$TOTAL 通过, $FAIL 失败"
    echo "========================================"

    [ "$FAIL" -eq 0 ] || exit 1
}

main "$@"
