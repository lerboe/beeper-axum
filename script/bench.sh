#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

TESTS=(bl fp sp)
PROTOS=("" --http2)
QPS=(1000 2000 3000 4000)

for test in "${TESTS[@]}"; do
    for proto in "${PROTOS[@]}"; do
        for qps in "${QPS[@]}"; do
            args=("$test")
            [[ -n $proto ]] && args+=("$proto")
            args+=(-q "$qps")

            echo "==> just bench ${args[*]}"
            just bench "${args[@]}"
        done
    done
done
