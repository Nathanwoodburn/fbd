#!/usr/bin/env bash
# test-fork-randomized.sh
#
# Runs the fork-convergence test N times with RANDOM topology parameters,
# explicitly covering the full range from tiny 2-node networks up to
# large 25+ node meshes with many miners. Reports per-run status and
# aggregates pass/fail counts.
#
# Usage:
#   ./scripts/test-fork-randomized.sh          # default: 10 runs
#   RUNS=20 ./scripts/test-fork-randomized.sh  # custom run count
#   SEED=1234 ./scripts/test-fork-randomized.sh  # reproducible random

set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/test-fork-convergence.sh"
RUNS="${RUNS:-10}"

if [ ! -x "$SCRIPT" ]; then
    echo "ERROR: $SCRIPT not executable"
    exit 1
fi

# Seed bash's $RANDOM so reruns can be reproducible via the SEED env var.
if [ -n "${SEED:-}" ]; then
    RANDOM="$SEED"
    echo "Random seed: $SEED"
else
    # Default: use PID so successive runs differ.
    RANDOM=$$
    echo "Random seed: $$"
fi

# --- topology generator ----------------------------------------------------

# Pick a node count with a deliberately-varied distribution: some tiny
# networks (2-3 nodes), some medium (4-10), some large (15-25). Each
# bucket gets a roughly proportional share of the test budget.
pick_nodes() {
    local slot="$1"  # 1..RUNS
    # Distribution:
    #   1/10 tests → minimum (2)
    #   2/10 tests → small (3-5)
    #   3/10 tests → medium (6-12)
    #   2/10 tests → large (13-19)
    #   2/10 tests → very large (20-25)
    # For 10 runs the slot-based mapping is exact; for other counts we
    # map proportionally.
    local bucket=$(( (slot - 1) * 10 / RUNS ))
    case $bucket in
        0) echo 2 ;;
        1|2) echo $((3 + RANDOM % 3)) ;;                # 3-5
        3|4|5) echo $((6 + RANDOM % 7)) ;;              # 6-12
        6|7) echo $((13 + RANDOM % 7)) ;;               # 13-19
        8|9) echo $((20 + RANDOM % 6)) ;;               # 20-25
        *) echo $((5 + RANDOM % 20)) ;;
    esac
}

generate_config() {
    local slot="$1"
    local nodes=$(pick_nodes "$slot")

    # At minimum 2 nodes: partition is forced to 1v1
    local a_size b_size miners_a miners_b
    a_size=$((1 + RANDOM % (nodes - 1)))
    b_size=$((nodes - a_size))
    miners_a=$((1 + RANDOM % a_size))
    miners_b=$((1 + RANDOM % b_size))

    # Block counts. B must be strictly > A (heavier chain wins), and
    # also > 4 (B's warmup budget). Keep counts modest — larger = slower.
    local a_blocks b_blocks margin
    a_blocks=$((6 + RANDOM % 7))          # 6-12
    margin=$((3 + RANDOM % 6))            # 3-8
    b_blocks=$((a_blocks + margin))

    echo "$nodes $a_size $miners_a $miners_b $a_blocks $b_blocks"
}

# --- runner ----------------------------------------------------------------

color() { printf "\033[%sm%s\033[0m" "$1" "$2"; }
pass_count=0
fail_count=0
declare -a results

for i in $(seq 1 "$RUNS"); do
    read -r nodes a_size miners_a miners_b a_blocks b_blocks <<< "$(generate_config "$i")"
    config_str="NODES=$nodes A=$a_size/$miners_a B=$((nodes - a_size))/$miners_b blocks=$a_blocks-vs-$b_blocks"
    printf "%s " "$(color '1;36' "[$i/$RUNS]")"
    printf "%s " "$config_str"
    start=$SECONDS
    NODES="$nodes" \
    PARTITION_A_SIZE="$a_size" \
    MINERS_A="$miners_a" \
    MINERS_B="$miners_b" \
    PARTITION_A_BLOCKS="$a_blocks" \
    PARTITION_B_BLOCKS="$b_blocks" \
    "$SCRIPT" > "/tmp/fork_random_$i.log" 2>&1
    rc=$?
    dur=$((SECONDS - start))
    if [ $rc -eq 0 ]; then
        echo "$(color '1;32' "PASS") (${dur}s)"
        pass_count=$((pass_count + 1))
        results[$i]="PASS $dur $config_str"
    else
        echo "$(color '1;31' "FAIL") (${dur}s) — log: /tmp/fork_random_$i.log"
        fail_count=$((fail_count + 1))
        results[$i]="FAIL $dur $config_str"
        # Print the last few lines of the failing log for quick triage
        echo "  $(color '1;33' '---- last 10 lines ----')"
        tail -10 "/tmp/fork_random_$i.log" | sed 's/^/  /'
        echo "  $(color '1;33' '-----------------------')"
    fi
done

echo
echo "$(color '1;34' '=========================================')"
echo "$(color '1;34' "Results: $pass_count passed, $fail_count failed (of $RUNS)")"
echo "$(color '1;34' '=========================================')"
for i in $(seq 1 "$RUNS"); do
    echo "  $i: ${results[$i]}"
done

if [ $fail_count -gt 0 ]; then
    exit 1
fi
exit 0
