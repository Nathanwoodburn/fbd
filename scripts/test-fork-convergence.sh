#!/usr/bin/env bash
# test-fork-convergence.sh
#
# Spins up a private regtest network of N nodes, partitions it into two
# halves of configurable size with configurable miners per side, runs
# independent mining + covenant operations on each half, then heals the
# partition and verifies all nodes converge on the heaviest chain with a
# consistent name-tree state.
#
# This is the empirical validation of the chain-split fixes. If this
# script reports SUCCESS, the bug class causing mainnet chain splits is
# reproducibly fixed in the current build.
#
# Requirements: bash 3.2+, curl, jq, the fbd binary already built at
# .build/debug/fbd or specified via FBD env var.
#
# Configuration (all via environment variables with sensible defaults):
#   NODES                (default 3)   total number of nodes
#   PARTITION_A_SIZE     (default 1)   nodes assigned to partition A
#                                      (partition B gets NODES - A_SIZE)
#   MINERS_A             (default 1)   miners within partition A
#   MINERS_B             (default 1)   miners within partition B
#   PRE_PARTITION_BLOCKS (default 5)   blocks mined before partitioning
#   PARTITION_A_BLOCKS   (default 8)   total blocks mined on A side
#                                      (split round-robin among MINERS_A)
#   PARTITION_B_BLOCKS   (default 12)  total blocks mined on B side
#                                      (split round-robin among MINERS_B)
#   CONVERGE_TIMEOUT     (default 90)  seconds to wait for convergence
#   FBD                  (default .build/debug/fbd)  binary path
#   TEST_DIR             (default .test-fork-net)    scratch dir
#   KEEP_LOGS            (default 0)   keep test dir on exit
#
# Usage:
#   ./scripts/test-fork-convergence.sh                      # default 3-node
#   NODES=7 PARTITION_A_SIZE=3 MINERS_A=2 MINERS_B=3 \
#       PARTITION_A_BLOCKS=12 PARTITION_B_BLOCKS=20 \
#       ./scripts/test-fork-convergence.sh                  # 7-node, 3v4 split
#   NODES=5 KEEP_LOGS=1 ./scripts/test-fork-convergence.sh  # 5-node, keep logs

set -u  # error on undefined variable; intentionally NOT using -e so we
        # can collect/print logs and clean up regardless of failures

# ----- config ---------------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FBD_BIN="${FBD:-$REPO_ROOT/.build/debug/fbd}"
TEST_DIR="${TEST_DIR:-$REPO_ROOT/.test-fork-net}"
KEEP_LOGS="${KEEP_LOGS:-0}"

# Topology — all configurable via env vars.
NODES="${NODES:-3}"
PARTITION_A_SIZE="${PARTITION_A_SIZE:-1}"
MINERS_A="${MINERS_A:-1}"
MINERS_B="${MINERS_B:-1}"

# Block count tunables
PRE_PARTITION_BLOCKS="${PRE_PARTITION_BLOCKS:-5}"
PARTITION_A_BLOCKS="${PARTITION_A_BLOCKS:-8}"
# PARTITION_B_BLOCKS is the old PARTITION_BC_BLOCKS renamed for clarity.
PARTITION_B_BLOCKS="${PARTITION_B_BLOCKS:-${PARTITION_BC_BLOCKS:-12}}"
# Convergence and group-sync timeouts. Scale with node count: larger
# meshes take longer to propagate since each block gets re-broadcast
# by every peer and passive nodes have more drain work.
CONVERGE_TIMEOUT="${CONVERGE_TIMEOUT:-$((60 + NODES * 6))}"
GROUP_SYNC_TIMEOUT="${GROUP_SYNC_TIMEOUT:-$((30 + NODES * 4))}"

# Validate topology before we start anything
if ! [[ "$NODES" =~ ^[0-9]+$ ]] || [ "$NODES" -lt 2 ]; then
    echo "ERROR: NODES must be an integer >= 2 (got: $NODES)" >&2
    exit 1
fi
if [ "$NODES" -gt 30 ]; then
    echo "ERROR: NODES > 30 not supported by this test (port allocation)" >&2
    exit 1
fi
# In a fully-connected mesh, every node needs (NODES - 1) peer slots.
# Half of those are outbound (from "connect i j" where i < j), half
# inbound. We give a modest headroom to cover fluctuations.
MAX_OUTBOUND=$((NODES + 2))
MAX_INBOUND=$((NODES + 2))
if [ "$PARTITION_A_SIZE" -lt 1 ] || [ "$PARTITION_A_SIZE" -ge "$NODES" ]; then
    echo "ERROR: PARTITION_A_SIZE must be in 1..$((NODES - 1)) (got: $PARTITION_A_SIZE)" >&2
    exit 1
fi
PARTITION_B_SIZE=$((NODES - PARTITION_A_SIZE))
if [ "$MINERS_A" -lt 1 ] || [ "$MINERS_A" -gt "$PARTITION_A_SIZE" ]; then
    echo "ERROR: MINERS_A must be in 1..$PARTITION_A_SIZE (got: $MINERS_A)" >&2
    exit 1
fi
if [ "$MINERS_B" -lt 1 ] || [ "$MINERS_B" -gt "$PARTITION_B_SIZE" ]; then
    echo "ERROR: MINERS_B must be in 1..$PARTITION_B_SIZE (got: $MINERS_B)" >&2
    exit 1
fi
if [ "$PARTITION_A_BLOCKS" -ge "$PARTITION_B_BLOCKS" ]; then
    echo "ERROR: PARTITION_A_BLOCKS ($PARTITION_A_BLOCKS) must be < PARTITION_B_BLOCKS ($PARTITION_B_BLOCKS) so B's chain is heavier" >&2
    exit 1
fi

# Generate node metadata. NODE_NAMES is "N1".."Nk", with port ranges
# allocated in fixed blocks per role so that NODES up to 20 all fit in
# the 25000s.
NODE_NAMES=()
P2P_PORTS=()
RPC_PORTS=()
NS_PORTS=()
PIDS=()
WALLET_ADDRS=()
for i in $(seq 0 $((NODES - 1))); do
    NODE_NAMES+=("N$((i + 1))")
    P2P_PORTS+=($((25001 + i)))
    RPC_PORTS+=($((25101 + i)))
    NS_PORTS+=($((25201 + i)))
    PIDS+=(0)
    WALLET_ADDRS+=("")
done

# Partition assignment. Indices [0..A_SIZE) are on partition A; the rest
# are on partition B.
A_INDICES=()
B_INDICES=()
for i in $(seq 0 $((PARTITION_A_SIZE - 1))); do A_INDICES+=($i); done
for i in $(seq $PARTITION_A_SIZE $((NODES - 1))); do B_INDICES+=($i); done

# Miner selection: pick the first MINERS_A nodes from each partition.
# (Arbitrary but deterministic — callers who need fancier selection can
# set MINER_A_INDICES / MINER_B_INDICES directly.)
A_MINER_INDICES=()
B_MINER_INDICES=()
for i in $(seq 0 $((MINERS_A - 1))); do A_MINER_INDICES+=(${A_INDICES[$i]}); done
for i in $(seq 0 $((MINERS_B - 1))); do B_MINER_INDICES+=(${B_INDICES[$i]}); done

# Names used to exercise the covenant/name-tree path through reorgs.
# All long enough to avoid the "premium" (≤6 char) restriction and
# definitely not in the blacklist (test/example/invalid/etc).
SHARED_NAME="sharedforkname001"   # opened on the pre-partition shared chain
LOSING_NAME="losingforkname001"   # opened on partition A's losing chain
WINNING_NAME="winningforkname001" # opened on partition B's winning chain
POSTCONVERGE_NAME="postconverge01" # opened after heal to prove tree state is sane

# ----- helpers --------------------------------------------------------------

color() { printf "\033[%sm%s\033[0m" "$1" "$2"; }
info()  { echo "$(color '1;34' '[INFO]') $*"; }
ok()    { echo "$(color '1;32' '[ OK ]') $*"; }
warn()  { echo "$(color '1;33' '[WARN]') $*"; }
fail()  { echo "$(color '1;31' '[FAIL]') $*"; }

# Call an RPC method on a node by index. Args: <node_idx> <method> [json_params]
rpc() {
    local idx="$1"; local method="$2"; local params="${3:-[]}"
    local port="${RPC_PORTS[$idx]}"
    local body
    body="$(curl -fsS -m 10 \
        -H 'Content-Type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
        "http://127.0.0.1:$port/" 2>/dev/null)"
    local rc=$?
    if [ $rc -ne 0 ]; then
        echo "RPC_ERROR_$rc"
        return $rc
    fi
    echo "$body"
}

# Extract .result field from an RPC response.
rpc_result() {
    local idx="$1"; local method="$2"; local params="${3:-[]}"
    rpc "$idx" "$method" "$params" | jq -r '.result // empty'
}

wait_for_rpc() {
    local idx="$1"
    local port="${RPC_PORTS[$idx]}"
    local name="${NODE_NAMES[$idx]}"
    local deadline=$((SECONDS + 30))
    while [ $SECONDS -lt $deadline ]; do
        if curl -fsS -m 1 \
            -H 'Content-Type: application/json' \
            --data '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}' \
            "http://127.0.0.1:$port/" >/dev/null 2>&1; then
            ok "Node $name (RPC :$port) is responding"
            return 0
        fi
        sleep 0.5
    done
    fail "Node $name RPC at :$port did not come up within 30s"
    return 1
}

# Poll until two nodes agree on the same tip hash (or timeout).
# Args: <idx1> <idx2> [timeout_seconds]
wait_for_sync() {
    local a="$1"; local b="$2"; local timeout="${3:-30}"
    local name_a="${NODE_NAMES[$a]}"
    local name_b="${NODE_NAMES[$b]}"
    local deadline=$((SECONDS + timeout))
    while [ $SECONDS -lt $deadline ]; do
        local ha; ha="$(best_hash "$a")"
        local hb; hb="$(best_hash "$b")"
        if [ -n "$ha" ] && [ "$ha" = "$hb" ]; then
            ok "Nodes $name_a and $name_b agree on tip"
            return 0
        fi
        sleep 0.3
    done
    fail "Nodes $name_a and $name_b did not sync within ${timeout}s"
    return 1
}

# Wait until all nodes in a group (space-separated index list) agree on
# the same tip hash. Used after intra-partition mining to make sure the
# miners and passive nodes are in sync before we assert anything.
# Args: <"idx1 idx2 ..."> [timeout_seconds]
wait_for_group_sync() {
    local group_str="$1"; local timeout="${2:-30}"
    local -a group
    # shellcheck disable=SC2206
    group=($group_str)
    if [ ${#group[@]} -lt 2 ]; then return 0; fi
    local first=${group[0]}
    local name_first="${NODE_NAMES[$first]}"
    local deadline=$((SECONDS + timeout))
    while [ $SECONDS -lt $deadline ]; do
        local hf; hf="$(best_hash "$first")"
        if [ -n "$hf" ]; then
            local all_match=1
            for idx in "${group[@]:1}"; do
                local h; h="$(best_hash "$idx")"
                if [ "$h" != "$hf" ]; then all_match=0; break; fi
            done
            if [ $all_match -eq 1 ]; then
                ok "Group [${group_str}] synced on tip ${hf:0:16}..."
                return 0
            fi
        fi
        sleep 0.3
    done
    fail "Group [${group_str}] did not fully sync within ${timeout}s"
    return 1
}

start_node() {
    local idx="$1"
    local name="${NODE_NAMES[$idx]}"
    local datadir="$TEST_DIR/node$name"
    mkdir -p "$datadir"

    info "Starting node $name (P2P :${P2P_PORTS[$idx]} RPC :${RPC_PORTS[$idx]})"

    # --nodes "" tells fbd to listen-only (no outbound connections by
    # default). We'll explicitly addnode later when we want connections.
    "$FBD_BIN" \
        --network regtest \
        --datadir "$datadir" \
        --host 127.0.0.1 \
        --port "${P2P_PORTS[$idx]}" \
        --rpc-host 127.0.0.1 \
        --rpc-port "${RPC_PORTS[$idx]}" \
        --ns-host 127.0.0.1 \
        --ns-port "${NS_PORTS[$idx]}" \
        --no-auth \
        --max-outbound "$MAX_OUTBOUND" \
        --max-inbound "$MAX_INBOUND" \
        --log-level debug \
        --agent "/fbd-fork-test/$name/" \
        > "$TEST_DIR/node$name.log" 2>&1 &
    PIDS[$idx]=$!
}

stop_all_nodes() {
    info "Stopping all nodes"
    for pid in "${PIDS[@]}"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
        fi
    done
    sleep 1
    for pid in "${PIDS[@]}"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null
        fi
    done
}

# Connect node $1 → node $2 via P2P.
connect() {
    local from="$1"; local to="$2"
    rpc "$from" "addnode" "[\"127.0.0.1:${P2P_PORTS[$to]}\"]" >/dev/null
}

# Form a fully-connected mesh across all N nodes. We only initiate one
# outbound per unordered pair; the receiving node sees the inbound. Each
# node ends up with (N-1) peers.
form_full_mesh() {
    for i in "${!NODE_NAMES[@]}"; do
        for j in "${!NODE_NAMES[@]}"; do
            if [ "$i" -lt "$j" ]; then
                connect "$i" "$j"
            fi
        done
    done
}

# Disconnect a SINGLE pair (both directions).
disconnect_pair() {
    local a="$1"; local b="$2"
    rpc "$a" "disconnectnode" "[\"127.0.0.1:${P2P_PORTS[$b]}\"]" >/dev/null 2>&1
    rpc "$b" "disconnectnode" "[\"127.0.0.1:${P2P_PORTS[$a]}\"]" >/dev/null 2>&1
}

# Disconnect all cross-partition edges between two index groups.
# Args: <"a_indices"> <"b_indices">
disconnect_partitions() {
    local a_str="$1"; local b_str="$2"
    local -a a_idx b_idx
    # shellcheck disable=SC2206
    a_idx=($a_str)
    # shellcheck disable=SC2206
    b_idx=($b_str)
    for a in "${a_idx[@]}"; do
        for b in "${b_idx[@]}"; do
            disconnect_pair "$a" "$b"
        done
    done
}

# Reconnect all cross-partition edges between two index groups.
# Args: <"a_indices"> <"b_indices">
reconnect_partitions() {
    local a_str="$1"; local b_str="$2"
    local -a a_idx b_idx
    # shellcheck disable=SC2206
    a_idx=($a_str)
    # shellcheck disable=SC2206
    b_idx=($b_str)
    for a in "${a_idx[@]}"; do
        for b in "${b_idx[@]}"; do
            connect "$a" "$b"
            connect "$b" "$a"
        done
    done
}

peer_count() {
    local idx="$1"
    rpc "$idx" "getpeerinfo" | jq -r '.result | length'
}

block_count() {
    local idx="$1"
    rpc "$idx" "getblockcount" | jq -r '.result // 0'
}

best_hash() {
    local idx="$1"
    rpc "$idx" "getbestblockhash" | jq -r '.result // ""'
}

mine_blocks() {
    local idx="$1"; local count="$2"
    local name="${NODE_NAMES[$idx]}"
    # The node must have a wallet at this point (createwallet runs in
    # phase 1.5 before any mining). Mining to the node's own wallet
    # address means its coinbase is spendable for later covenant txs.
    local addr="${WALLET_ADDRS[$idx]}"
    if [ -z "$addr" ]; then
        fail "mine_blocks: node $name has no wallet address (call create_wallet first)"
        return 1
    fi
    info "Mining $count blocks on node $name"
    local resp
    resp="$(rpc "$idx" "generate" "[$count, \"$addr\"]")"
    local err
    err="$(echo "$resp" | jq -r '.error // empty')"
    if [ -n "$err" ] && [ "$err" != "null" ]; then
        fail "Mining failed on node $name: $err"
        return 1
    fi
}

# Compute the per-block gap for round-robin mining. Scales with both
# NODES (propagation target count) and miner_count (broadcast churn).
# The gap needs to be long enough that passive nodes in a partition can
# process one block's broadcast before the next one arrives. Otherwise
# passive nodes fall behind, trigger orphan-retry bursts on the next
# batch, and can even deadlock header sync.
#
# Args: <miner_count>
# Output: gap in seconds (float)
compute_mine_gap() {
    local miner_count="$1"
    # Base gap: 300ms floor.
    # Add 30ms for every extra node beyond 3.
    # Add 100ms for every extra miner beyond 1.
    local node_add=$(( (NODES - 3) * 30 ))
    if [ "$node_add" -lt 0 ]; then node_add=0; fi
    local miner_add=$(( (miner_count - 1) * 100 ))
    if [ "$miner_add" -lt 0 ]; then miner_add=0; fi
    local total_ms=$(( 300 + node_add + miner_add ))
    # Cap at 2.5 seconds — beyond that the test becomes too slow.
    if [ "$total_ms" -gt 2500 ]; then total_ms=2500; fi
    # Output as seconds.milliseconds (e.g. 300ms → "0.300", 1500ms → "1.500").
    local secs=$((total_ms / 1000))
    local ms=$((total_ms % 1000))
    printf "%d.%03d\n" "$secs" "$ms"
}

# Mine `total` blocks across a group of miners in round-robin fashion,
# one block at a time with a gap between blocks so each broadcast drains
# to the other nodes before the next block is mined. Works equally well
# with 1 miner (sequential mining with appropriate gap) or many miners
# (exercises the multi-miner churn path).
#
# Args: <"miner_idx1 miner_idx2 ..."> <total_blocks>
mine_blocks_round_robin() {
    local miners_str="$1"; local total="$2"
    local -a miners
    # shellcheck disable=SC2206
    miners=($miners_str)
    local miner_count=${#miners[@]}
    if [ "$miner_count" -lt 1 ]; then
        fail "mine_blocks_round_robin: empty miner list"
        return 1
    fi
    local gap
    gap="$(compute_mine_gap "$miner_count")"
    local cursor=0
    local remaining=$total
    while [ "$remaining" -gt 0 ]; do
        local idx=${miners[$((cursor % miner_count))]}
        mine_blocks "$idx" 1 || return 1
        remaining=$((remaining - 1))
        cursor=$((cursor + 1))
        sleep "$gap"
    done
}

# --- Wallet & covenant helpers ---------------------------------------------

# Create a wallet on a node and store its receive address.
create_wallet() {
    local idx="$1"
    local name="${NODE_NAMES[$idx]}"
    local wallet_name="w$name"
    info "Creating wallet '$wallet_name' on node $name"
    local resp
    resp="$(rpc "$idx" "createwallet" "[\"$wallet_name\"]")"
    local err
    err="$(echo "$resp" | jq -r '.error // empty')"
    if [ -n "$err" ] && [ "$err" != "null" ]; then
        fail "createwallet failed on node $name: $err"
        return 1
    fi
    # Ask for a receive address
    local addr
    addr="$(rpc_result "$idx" "getnewaddress")"
    if [ -z "$addr" ]; then
        fail "getnewaddress returned empty on node $name"
        return 1
    fi
    WALLET_ADDRS[$idx]="$addr"
    ok "Wallet on node $name: $addr"
}

# Poll until a node's wallet has at least $2 spendable dollarydoos.
# Args: <idx> <min_spendable>
wait_wallet_spendable() {
    local idx="$1"; local min="$2"
    local name="${NODE_NAMES[$idx]}"
    local deadline=$((SECONDS + 15))
    while [ $SECONDS -lt $deadline ]; do
        local spendable
        spendable="$(rpc "$idx" "getwalletinfo" | jq -r '.result.spendable // 0')"
        if [ "$spendable" -ge "$min" ] 2>/dev/null; then
            ok "Wallet $name has spendable=$spendable (>= $min)"
            return 0
        fi
        sleep 0.3
    done
    fail "Wallet $name never reached spendable >= $min"
    return 1
}

# Send a sendopen covenant tx on a node. Args: <idx> <name>
cov_open() {
    local idx="$1"; local cov_name="$2"
    local node_name="${NODE_NAMES[$idx]}"
    info "Node $node_name: sendopen \"$cov_name\""
    local resp
    resp="$(rpc "$idx" "sendopen" "[\"$cov_name\"]")"
    local err
    err="$(echo "$resp" | jq -r '.error // empty')"
    if [ -n "$err" ] && [ "$err" != "null" ]; then
        fail "sendopen \"$cov_name\" failed on $node_name: $err"
        return 1
    fi
    local txid
    txid="$(echo "$resp" | jq -r '.result.txid // empty')"
    if [ -z "$txid" ]; then
        fail "sendopen \"$cov_name\" returned no txid on $node_name"
        return 1
    fi
    ok "sendopen \"$cov_name\" accepted on $node_name (txid ${txid:0:16}...)"
}

# Return the name state as reported by getnameinfo.result.state.
# Outputs "INACTIVE" if the name isn't known (fresh / rolled back).
name_state() {
    local idx="$1"; local cov_name="$2"
    local resp
    resp="$(rpc "$idx" "getnameinfo" "[\"$cov_name\"]")"
    echo "$resp" | jq -r '.result.state // "INACTIVE"'
}

# Assert a name has a given state on a node. Args: <idx> <name> <expected_state_or_not>
# If expected starts with '!', asserts the state is NOT that value.
# Multiple expected values can be provided as a pipe-separated list: "INACTIVE|PENDING"
assert_name_state() {
    local idx="$1"; local cov_name="$2"; local expected="$3"
    local node_name="${NODE_NAMES[$idx]}"
    local actual
    actual="$(name_state "$idx" "$cov_name")"
    if [ "${expected:0:1}" = "!" ]; then
        local not="${expected:1}"
        if [ "$actual" = "$not" ]; then
            fail "Node $node_name: \"$cov_name\" state is \"$actual\" (expected NOT \"$not\")"
            return 1
        fi
        ok "Node $node_name: \"$cov_name\" state is \"$actual\" (≠ \"$not\")"
    else
        # Allow pipe-separated list of acceptable states
        local IFS='|'
        local -a options
        read -ra options <<< "$expected"
        for opt in "${options[@]}"; do
            if [ "$actual" = "$opt" ]; then
                ok "Node $node_name: \"$cov_name\" state is \"$actual\""
                return 0
            fi
        done
        fail "Node $node_name: \"$cov_name\" state is \"$actual\" (expected one of: $expected)"
        return 1
    fi
}

print_state() {
    local label="$1"
    info "------ $label ------"
    for i in "${!NODE_NAMES[@]}"; do
        local name="${NODE_NAMES[$i]}"
        local h; h="$(block_count "$i")"
        local hash; hash="$(best_hash "$i")"
        local peers; peers="$(peer_count "$i")"
        # Partition label: A/B, plus * if this node is a miner.
        local label_side="B "
        for a in "${A_INDICES[@]}"; do
            if [ "$a" = "$i" ]; then label_side="A "; break; fi
        done
        local is_miner=""
        for m in "${A_MINER_INDICES[@]}" "${B_MINER_INDICES[@]}"; do
            if [ "$m" = "$i" ]; then is_miner="*"; break; fi
        done
        printf "  Node %-4s [%s%s] height=%-4s peers=%-2s tip=%s...\n" \
            "$name" "$label_side" "$is_miner" "$h" "$peers" "${hash:0:16}"
    done
}

cleanup() {
    local exit_code=$?
    stop_all_nodes
    if [ "$KEEP_LOGS" = "1" ] || [ $exit_code -ne 0 ]; then
        info "Logs preserved in $TEST_DIR"
        info "Inspect with: ls $TEST_DIR/node*.log"
    else
        rm -rf "$TEST_DIR"
    fi
    exit $exit_code
}
trap cleanup EXIT INT TERM

# ----- preflight ------------------------------------------------------------

if [ ! -x "$FBD_BIN" ]; then
    fail "fbd binary not found at $FBD_BIN"
    info "Build it with: swift build"
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    fail "jq is required but not installed (brew install jq)"
    exit 1
fi

# Reset test directory
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

info "fbd binary: $FBD_BIN"
info "Test dir:   $TEST_DIR"
echo

# ----- phase 1: bring up the network ----------------------------------------

info "=== Phase 1: bring up 3 nodes and form a fully-connected mesh ==="

for i in "${!NODE_NAMES[@]}"; do
    start_node "$i"
done

for i in "${!NODE_NAMES[@]}"; do
    if ! wait_for_rpc "$i"; then
        fail "Phase 1: a node failed to start"
        exit 1
    fi
done

# Form a fully-connected mesh. One outbound per unordered pair — the
# receiver gets an inbound, so every node ends up with (NODES - 1)
# peers. Larger meshes need a longer settle time before we check.
info "Connecting $NODES nodes into a fully-connected mesh (${NODES} nodes → $((NODES * (NODES - 1) / 2)) edges)"
form_full_mesh
# More nodes = more handshakes; scale the settle time a bit.
settle=$((2 + NODES / 4))
sleep "$settle"

# Sanity-check: each node should see (NODES - 1) peers.
expected_peers=$((NODES - 1))
all_connected=1
for i in "${!NODE_NAMES[@]}"; do
    pc="$(peer_count "$i")"
    if [ "$pc" != "$expected_peers" ]; then
        warn "Node ${NODE_NAMES[$i]} has $pc peers (expected $expected_peers)"
        all_connected=0
    fi
done
if [ "$all_connected" -eq 1 ]; then
    ok "All nodes fully meshed ($expected_peers peers each)"
else
    fail "Mesh formation failed; check logs"
    exit 1
fi

# ----- phase 1.5: create wallets on all nodes -------------------------------

info "=== Phase 1.5: create a wallet on each node ==="
for i in "${!NODE_NAMES[@]}"; do
    if ! create_wallet "$i"; then
        fail "Wallet creation failed on node ${NODE_NAMES[$i]}"
        exit 1
    fi
done

# ----- phase 2: shared history ---------------------------------------------

# The first miner in partition A does all the shared-history mining so
# it has spendable coinbase UTXOs for the shared covenant open. Other
# nodes sync the blocks but don't own the coinbases.
SHARED_MINER="${A_MINER_INDICES[0]}"
SHARED_MINER_NAME="${NODE_NAMES[$SHARED_MINER]}"

info "=== Phase 2: build shared history ($PRE_PARTITION_BLOCKS blocks mined on $SHARED_MINER_NAME) ==="
# Use round-robin (with a single miner) so the inter-block gap scales
# with NODES. `mine_blocks N count` via generate-in-one-call mines too
# fast for large meshes to drain propagation.
mine_blocks_round_robin "$SHARED_MINER" "$PRE_PARTITION_BLOCKS"

# Wait for every node to catch up (more nodes = more propagation hops).
ALL_INDICES_STR="${!NODE_NAMES[*]}"
wait_for_group_sync "$ALL_INDICES_STR" "$GROUP_SYNC_TIMEOUT" || exit 1
print_state "after shared mining"

# ----- phase 2.5: shared covenant open (exercises name tree) ---------------

info "=== Phase 2.5: open \"$SHARED_NAME\" on the shared chain (miner: $SHARED_MINER_NAME) ==="
# Regtest coinbaseMaturity=2 → the first coinbase is spendable after 2
# more blocks. We mined PRE_PARTITION_BLOCKS ≥ 5, so several are mature.
wait_wallet_spendable "$SHARED_MINER" 1 || exit 1

cov_open "$SHARED_MINER" "$SHARED_NAME" || exit 1
# Mine one more block to include the open tx in a block.
mine_blocks "$SHARED_MINER" 1
SHARED_TOTAL=$((PRE_PARTITION_BLOCKS + 1))
wait_for_group_sync "$ALL_INDICES_STR" "$GROUP_SYNC_TIMEOUT" || exit 1

# All nodes should now see the name in an active auction state. Exact
# state (OPENING/BIDDING/REVEAL) depends on height, so we only check
# that the name is not INACTIVE.
for i in "${!NODE_NAMES[@]}"; do
    assert_name_state "$i" "$SHARED_NAME" "!INACTIVE" || exit 1
done
ok "Shared covenant open propagated to all $NODES nodes (shared height = $SHARED_TOTAL)"

# ----- phase 3: partition the network --------------------------------------

info "=== Phase 3: partition the network ==="
info "Creating partition: {A} | {B,C}"

A_INDICES_STR="${A_INDICES[*]}"
B_INDICES_STR="${B_INDICES[*]}"
A_MINERS_STR="${A_MINER_INDICES[*]}"
B_MINERS_STR="${B_MINER_INDICES[*]}"

info "Partition A: nodes [$A_INDICES_STR], miners [$A_MINERS_STR]"
info "Partition B: nodes [$B_INDICES_STR], miners [$B_MINERS_STR]"
disconnect_partitions "$A_INDICES_STR" "$B_INDICES_STR"
sleep 2

# Verify the partition: within each partition, each node should see
# exactly (partition_size - 1) peers (i.e., the other nodes on its side).
verify_partition() {
    local side_name="$1"; local indices_str="$2"; local expected_intra="$3"
    local -a idxs
    # shellcheck disable=SC2206
    idxs=($indices_str)
    for i in "${idxs[@]}"; do
        local pc; pc="$(peer_count "$i")"
        if [ "$pc" != "$expected_intra" ]; then
            warn "$side_name node ${NODE_NAMES[$i]} has $pc peers (expected $expected_intra)"
            return 1
        fi
    done
    return 0
}
expected_intra_a=$((PARTITION_A_SIZE - 1))
expected_intra_b=$((PARTITION_B_SIZE - 1))
if verify_partition "A" "$A_INDICES_STR" "$expected_intra_a" \
   && verify_partition "B" "$B_INDICES_STR" "$expected_intra_b"; then
    ok "Partition successful: A nodes see $expected_intra_a peer(s), B nodes see $expected_intra_b peer(s)"
else
    warn "Partition check had unexpected peer counts (disconnectnode is best-effort)"
    # Not a hard failure — the sync-isolation check below is the real test.
fi

# ----- phase 4: independent mining with covenants --------------------------

info "=== Phase 4: each side mines independently with covenants ==="

# --- A's side: open losing name, then mine PARTITION_A_BLOCKS blocks -------
# The primary A-miner already has mature coinbases from the shared phase,
# so it can send the open before mining any new blocks.
A_PRIMARY="${A_MINER_INDICES[0]}"
A_PRIMARY_NAME="${NODE_NAMES[$A_PRIMARY]}"
info "A-side: $A_PRIMARY_NAME opens \"$LOSING_NAME\", then [$A_MINERS_STR] mine $PARTITION_A_BLOCKS blocks round-robin"
cov_open "$A_PRIMARY" "$LOSING_NAME" || exit 1
mine_blocks_round_robin "$A_MINERS_STR" "$PARTITION_A_BLOCKS" || exit 1
wait_for_group_sync "$A_INDICES_STR" "$GROUP_SYNC_TIMEOUT" || exit 1
assert_name_state "$A_PRIMARY" "$LOSING_NAME" "!INACTIVE" || exit 1

# --- B's side: primary miner needs its own coins first, then opens -------
# The B-side primary miner has zero wallet balance right now (all shared
# coinbases went to the A-side primary). It must mine enough warmup
# blocks for its own coinbase to mature (coinbaseMaturity=2 → 3 blocks
# suffice). We give it +1 for safety.
B_PRIMARY="${B_MINER_INDICES[0]}"
B_PRIMARY_NAME="${NODE_NAMES[$B_PRIMARY]}"
B_WARMUP=4
if [ "$PARTITION_B_BLOCKS" -le "$B_WARMUP" ]; then
    fail "PARTITION_B_BLOCKS ($PARTITION_B_BLOCKS) must be > $B_WARMUP (B-side coinbase warmup)"
    exit 1
fi
info "B-side: $B_PRIMARY_NAME mines $B_WARMUP warmup blocks to get spendable coins"
# Warmup must be mined by B_PRIMARY specifically so the coinbase lands
# in its wallet for the sendopen below. Round-robin with a single miner
# gives us the node-count-scaled gap for free.
mine_blocks_round_robin "$B_PRIMARY" "$B_WARMUP"
wait_for_group_sync "$B_INDICES_STR" "$GROUP_SYNC_TIMEOUT" || exit 1
wait_wallet_spendable "$B_PRIMARY" 1 || exit 1

info "B-side: $B_PRIMARY_NAME opens \"$WINNING_NAME\", then [$B_MINERS_STR] mine $((PARTITION_B_BLOCKS - B_WARMUP)) more blocks round-robin"
cov_open "$B_PRIMARY" "$WINNING_NAME" || exit 1
mine_blocks_round_robin "$B_MINERS_STR" $((PARTITION_B_BLOCKS - B_WARMUP)) || exit 1
wait_for_group_sync "$B_INDICES_STR" "$GROUP_SYNC_TIMEOUT" || exit 1
print_state "after partitioned mining"

# Verify covenant visibility within each partition.
for i in "${A_INDICES[@]}"; do
    assert_name_state "$i" "$LOSING_NAME"  "!INACTIVE" || exit 1
done
for i in "${B_INDICES[@]}"; do
    assert_name_state "$i" "$WINNING_NAME" "!INACTIVE" || exit 1
done

# Partition isolation: A must not see WINNING_NAME, B must not see LOSING_NAME.
for i in "${A_INDICES[@]}"; do
    if [ "$(name_state "$i" "$WINNING_NAME")" != "INACTIVE" ]; then
        fail "A-side node ${NODE_NAMES[$i]} somehow sees \"$WINNING_NAME\" despite partition"
        exit 1
    fi
done
for i in "${B_INDICES[@]}"; do
    if [ "$(name_state "$i" "$LOSING_NAME")" != "INACTIVE" ]; then
        fail "B-side node ${NODE_NAMES[$i]} somehow sees \"$LOSING_NAME\" despite partition"
        exit 1
    fi
done
ok "Each partition has its own covenant name and doesn't see the other's"

# Verify the chains have actually diverged and the heights are as expected.
# Each partition should be internally consistent (already verified by
# wait_for_group_sync) and the A and B tips should differ.
a_tip="$(best_hash "$A_PRIMARY")"
b_tip="$(best_hash "$B_PRIMARY")"
a_height="$(block_count "$A_PRIMARY")"
b_height="$(block_count "$B_PRIMARY")"
expected_a=$((SHARED_TOTAL + PARTITION_A_BLOCKS))
expected_b=$((SHARED_TOTAL + PARTITION_B_BLOCKS))
if [ "$a_height" != "$expected_a" ]; then
    fail "A-side height $a_height, expected $expected_a"
    exit 1
fi
if [ "$b_height" != "$expected_b" ]; then
    fail "B-side height $b_height, expected $expected_b"
    exit 1
fi
if [ "$a_tip" = "$b_tip" ]; then
    fail "A and B tips are identical — partition failed?"
    exit 1
fi

# Sanity-check that the first post-shared block on each side is
# genuinely different (guards against deterministic mining producing
# bit-identical blocks when miner addresses collide).
first_post_shared=$((SHARED_TOTAL + 1))
a_first="$(rpc_result "$A_PRIMARY" "getblockhash" "[$first_post_shared]")"
b_first="$(rpc_result "$B_PRIMARY" "getblockhash" "[$first_post_shared]")"
if [ -z "$a_first" ] || [ -z "$b_first" ]; then
    fail "Could not fetch block hash at height $first_post_shared"
    exit 1
fi
if [ "$a_first" = "$b_first" ]; then
    fail "A and B have IDENTICAL blocks at height $first_post_shared — chains aren't actually diverged"
    exit 1
fi
ok "Chains genuinely diverge at height $first_post_shared:"
ok "  A's block: ${a_first:0:24}..."
ok "  B's block: ${b_first:0:24}..."
ok "Chain A at height $a_height, chain B at height $b_height"
ok "A's tip: ${a_tip:0:16}..."
ok "B's tip: ${b_tip:0:16}..."

# ----- phase 5: heal the partition -----------------------------------------

info "=== Phase 5: heal the partition ==="
info "Reconnecting all A ↔ B edges"
reconnect_partitions "$A_INDICES_STR" "$B_INDICES_STR"

# ----- phase 6: wait for convergence ---------------------------------------

info "=== Phase 6: wait for convergence (timeout ${CONVERGE_TIMEOUT}s) ==="

start_time=$SECONDS
converged=0
last_state=""
while [ $((SECONDS - start_time)) -lt "$CONVERGE_TIMEOUT" ]; do
    # Build a compact state string for all nodes.
    state=""
    all_agree=1
    first_hash=""
    for i in "${!NODE_NAMES[@]}"; do
        local_hash="$(best_hash "$i")"
        local_height="$(block_count "$i")"
        state="$state ${NODE_NAMES[$i]}=$local_height/${local_hash:0:8}"
        if [ -z "$first_hash" ]; then
            first_hash="$local_hash"
        elif [ "$local_hash" != "$first_hash" ] || [ -z "$local_hash" ]; then
            all_agree=0
        fi
    done
    if [ "$state" != "$last_state" ]; then
        info " $state"
        last_state="$state"
    fi
    if [ "$all_agree" -eq 1 ] && [ -n "$first_hash" ]; then
        converged=1
        break
    fi
    sleep 1
done

if [ "$converged" -ne 1 ]; then
    fail "Nodes did NOT converge within ${CONVERGE_TIMEOUT}s"
    print_state "final state"
    info "Inspect logs at $TEST_DIR/node*.log for the failure mode"
    exit 1
fi

# ----- phase 7: validate the right chain won -------------------------------

info "=== Phase 7: validate the heavier chain won ==="

final_height="$(block_count "$A_PRIMARY")"
final_hash="$(best_hash "$A_PRIMARY")"
expected_winner="$((SHARED_TOTAL + PARTITION_B_BLOCKS))"

if [ "$final_height" != "$expected_winner" ]; then
    fail "Converged on wrong height: $final_height (expected $expected_winner)"
    exit 1
fi

# All N nodes should be on the SAME tip.
for i in "${!NODE_NAMES[@]}"; do
    h="$(best_hash "$i")"
    if [ "$h" != "$final_hash" ]; then
        fail "Node ${NODE_NAMES[$i]} has tip $h (expected $final_hash)"
        exit 1
    fi
done

ok "Convergence on heavier chain confirmed (height $final_height, hash ${final_hash:0:16}...)"
print_state "post-convergence"

# ----- phase 7.5: name tree state after reorg ------------------------------

info "=== Phase 7.5: verify name tree state after reorg ==="
#
# Expected final state on ALL nodes:
#   SHARED_NAME      → in auction state (from shared history — survived)
#   WINNING_NAME     → in auction state (from winning chain — still there)
#   LOSING_NAME      → INACTIVE or PENDING
#     INACTIVE = tx evicted from mempool (e.g. it referenced a
#     disconnected-chain UTXO that no longer exists).
#     PENDING = tx is back in the mempool but NOT in the name tree. The
#     on-chain state was rolled back correctly; the mempool re-adding
#     disconnected-block txs is standard behavior.
#
# The critical check is that LOSING_NAME is NOT in any on-chain auction
# state (OPENING, BIDDING, REVEAL, CLOSED). If it is, the name tree
# rollback during reorg is buggy — which is exactly the mainnet bug
# the fixes in this session address.

for i in "${!NODE_NAMES[@]}"; do
    assert_name_state "$i" "$SHARED_NAME"  "!INACTIVE" || exit 1
    assert_name_state "$i" "$WINNING_NAME" "!INACTIVE" || exit 1
    assert_name_state "$i" "$LOSING_NAME"  "INACTIVE|PENDING" || exit 1
done
ok "Name tree consistent across all $NODES nodes after reorg"

# ----- phase 8: post-convergence mining + covenant sanity check ------------

info "=== Phase 8: post-convergence mining + covenant sanity check ==="

# Open a brand new name on the A-primary (which got reorged). This
# exercises the name tree state from the winning chain's perspective:
# on A-primary the tree was rolled back AND re-applied, so any residual
# corruption would surface here as a tree-root mismatch.
info "Open \"$POSTCONVERGE_NAME\" on $A_PRIMARY_NAME (reorged A-side primary)"

# Make sure the A-primary still has spendable coins. After the reorg it
# lost its losing-chain coinbases but kept the shared-history ones.
wait_wallet_spendable "$A_PRIMARY" 1 || exit 1

cov_open "$A_PRIMARY" "$POSTCONVERGE_NAME" || exit 1
info "Mining 3 more blocks on $A_PRIMARY_NAME to include the open tx"
mine_blocks_round_robin "$A_PRIMARY" 3
wait_for_group_sync "$ALL_INDICES_STR" "$GROUP_SYNC_TIMEOUT" || exit 1

expected_post=$((expected_winner + 3))
for i in "${!NODE_NAMES[@]}"; do
    h="$(block_count "$i")"
    if [ "$h" != "$expected_post" ]; then
        fail "Post-convergence: node ${NODE_NAMES[$i]} at height $h (expected $expected_post)"
        exit 1
    fi
done
ok "All $NODES nodes accepted the new blocks (height $expected_post)"

# The new open should have propagated to all nodes — this only works
# if the name tree was consistent after the reorg.
for i in "${!NODE_NAMES[@]}"; do
    assert_name_state "$i" "$POSTCONVERGE_NAME" "!INACTIVE" || exit 1
done
ok "Post-reorg covenant propagated correctly"

# ----- phase 9: silent-failure check ---------------------------------------
#
# The auto-repair path (`Tree root mismatch — attempting auto-repair`) is a
# safety net that wipes and rebuilds the entire urkel tree from the
# blockstore. It self-heals, so observable state is fine — but it indicates
# the rollback path left the tree in an inconsistent state. On a real node
# with many names this is an expensive recovery, and earlier versions of the
# script silently passed even when the bug was firing every reorg. Fail loud
# instead.
info "=== Phase 9: scan node logs for silent tree-repair fallbacks ==="
repair_hits=0
for i in "${!NODE_NAMES[@]}"; do
    name="${NODE_NAMES[$i]}"
    log="$TEST_DIR/node$name.log"
    if [ -f "$log" ] && grep -qE "Tree root mismatch|Tree repair complete" "$log"; then
        fail "Node $name fell back to tree auto-repair (rollback path is buggy):"
        grep -nE "Tree root mismatch|Tree repair complete" "$log" | sed 's/^/    /'
        repair_hits=$((repair_hits + 1))
    fi
done
if [ "$repair_hits" -gt 0 ]; then
    fail "$repair_hits node(s) needed tree auto-repair — reorg path is masking a bug"
    exit 1
fi
ok "No tree auto-repair fallbacks — reorg rollback is clean"

# ----- success -------------------------------------------------------------

echo
echo "$(color '1;32' '╔══════════════════════════════════════════════════════════╗')"
echo "$(color '1;32' '║        FORK CONVERGENCE TEST: PASSED                     ║')"
echo "$(color '1;32' '╚══════════════════════════════════════════════════════════╝')"
echo
echo "Summary:"
echo "  - $NODES nodes formed a fully-connected mesh"
echo "  - Each node created a wallet"
echo "  - Shared covenant \"$SHARED_NAME\" opened on the shared chain"
echo "  - Network partitioned: A = [${NODE_NAMES[@]:0:$PARTITION_A_SIZE}] (${MINERS_A} miner(s))"
echo "                        B = [${NODE_NAMES[@]:$PARTITION_A_SIZE}] (${MINERS_B} miner(s))"
echo "  - A side mined $PARTITION_A_BLOCKS blocks round-robin + opened \"$LOSING_NAME\""
echo "  - B side mined $PARTITION_B_BLOCKS blocks round-robin + opened \"$WINNING_NAME\""
echo "  - Partition healed"
echo "  - All $NODES nodes converged on the heavier chain (height $expected_winner)"
echo "  - Losing-chain covenant rolled back from name tree (reorg path exercised)"
echo "  - Winning-chain covenant propagated to all nodes"
echo "  - Post-reorg covenant \"$POSTCONVERGE_NAME\" opened + propagated (height $expected_post)"
echo
echo "This empirically validates the chain-split fixes against the"
echo "specific failure mode you saw on mainnet, AND exercises the name"
echo "tree rollback/reapply path through a real reorg. Run with KEEP_LOGS=1"
echo "to inspect the per-node logs."
exit 0
