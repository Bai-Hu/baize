#!/usr/bin/env bash
# 白泽 Agent 集群 — Wave 协作模式
# 入口: 编译 → 启动 server → 运行集群 → 验证 → 停止
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/../.." && pwd)"
BZ="${BZ:-$PROJECT/target/release/bz}"
DIR="/tmp/baize-cluster"
PORT="${PORT:-9478}"
BASE="http://127.0.0.1:$PORT"

echo "============================================"
echo "  白泽 Agent 集群 — 全流程测试"
echo "============================================"
echo ""

# 1. 编译
echo "--- 编译白泽 ---"
cargo build --release --manifest-path "$PROJECT/Cargo.toml" 2>&1 | tail -1
echo "  二进制: $BZ"
echo ""

# 2. 清理 + 初始化
echo "--- 初始化 ---"
rm -rf "$DIR" && mkdir -p "$DIR" && cd "$DIR"
$BZ init --db "$DIR/baize.db" --workspace "$DIR/workspaces" --main-repo "$DIR/main"
echo "  目录: $DIR"
echo ""

# 3. 启动 server
echo "--- 启动 server ---"
$BZ serve --addr "127.0.0.1:$PORT" \
    --db "$DIR/baize.db" \
    --workspace "$DIR/workspaces" \
    --main-repo "$DIR/main" &
SERVER_PID=$!

cleanup() {
    echo ""
    echo "--- 停止 server (PID=$SERVER_PID) ---"
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 等待 server 就绪
for i in $(seq 1 30); do
    if curl -s "$BASE/api/v0/agents" >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done
echo "  server 已就绪: $BASE"
echo ""

# 4. 运行集群
echo "--- 运行集群 ---"
python3 "$PROJECT/tests/agents/cluster.py" --base "$BASE" --project "$PROJECT"
EXIT_CODE=$?

exit $EXIT_CODE
