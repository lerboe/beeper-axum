#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

TESTS=(bl fp sp)
PROTOS=("" --http2)
QPS=(1000 2000 3000 4000)
FILE_SIZES=(1KB 8KB 32KB 128KB)

while getopts "qs" opt; do
    case "$opt" in
        q) FILE_SIZES=(8KB) ;;
        s) QPS=(1000) ;;
        *) echo "usage: $0 [-q] [-s]" >&2; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

for test in "${TESTS[@]}"; do
    for proto in "${PROTOS[@]}"; do
        for size in "${FILE_SIZES[@]}"; do
            for qps in "${QPS[@]}"; do
                args=("$test" "$size")
                [[ -n $proto ]] && args+=("$proto")
                args+=(-q "$qps")

                echo "==> just bench ${args[*]}"
                just bench "${args[@]}"
            done
        done
    done
done
