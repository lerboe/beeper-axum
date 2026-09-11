#!/bin/bash

set -e

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

WORKSPACE=$(dirname "$(readlink -f "$0")")/..
RES_DIR=${WORKSPACE}/res
RUN_DIR=${RES_DIR}/run

SERVER=${WORKSPACE}/target/release/example
SERVER_PORT=${SERVER_PORT:-8080}

SERVER_HOST=$(uname -n)

LOAD_GEN_DIR="/tmp/beeper"

CONNECTIONS=${CONNECTIONS:-100}
DURATION=${DURATION:-30s}

TESTS=(bl fp sp)
PROTOS=("" "--http2")
RATES=(600 800 1000)

if [[ -z ${LOAD_GEN_HOST} ]]; then
    echo -e "${COLOR_RED}LOAD_GEN_HOST not set${COLOR_OFF}"
    exit 1
fi

if [[ $(ulimit -n) -lt 10000 ]]; then
    echo -e "${COLOR_RED}Low open files limit ($(ulimit -n)). Please increase and try again.${COLOR_OFF}"
    exit 1
fi

function may_fail {
    ($@ > /dev/null 2>&1) || true
}

function wait_for_term {
    while true; do
        pid=$(pgrep -f '[t]arget/release/example' | head -n1)
        if [[ -z "$pid" ]]; then
            return 0
        fi
        sleep 0.1
    done
}

function cpu_governor {
    echo -e "${COLOR_YELLOW}Set CPU governor: $1${COLOR_OFF}"
    echo $1 | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null
}

function kill_server {
    may_fail sudo pkill -f '[t]arget/release/example'
    wait_for_term
}

function open_port {
    LOAD_GEN_HOST_IP=$(getent hosts ${LOAD_GEN_HOST} | awk '{ print $1 }')
    RULE="from ${LOAD_GEN_HOST_IP} to any port ${SERVER_PORT} proto tcp"
    if $1; then
        echo -e "${COLOR_YELLOW}Open port ${SERVER_PORT}${COLOR_OFF}"
        sudo ufw allow ${RULE}
    else
        echo -e "${COLOR_YELLOW}Close port ${SERVER_PORT}${COLOR_OFF}"
        sudo ufw deny ${RULE}
    fi
}

function teardown {
    local code=$?

    kill_server
    cpu_governor "schedutil"
    open_port false

    exit ${code}
}

echo -e "${COLOR_YELLOW}Building example server${COLOR_OFF}"
cargo build -r --bin example --manifest-path ${WORKSPACE}/Cargo.toml

trap teardown INT TERM ERR

cpu_governor "performance"
open_port true

echo -e "${COLOR_YELLOW}Upload load tests to ${LOAD_GEN_HOST}${COLOR_OFF}"
ssh ${LOAD_GEN_HOST} "rm -rf ${LOAD_GEN_DIR}; mkdir -p ${LOAD_GEN_DIR}"
for test in "${TESTS[@]}"; do
    # the URLs are written against localhost, the load generator has to reach
    # the server over the network
    sed -E "s#^http://[^/]+#http://${SERVER_HOST}:${SERVER_PORT}#" ${RES_DIR}/oha/${test}.txt \
        | ssh ${LOAD_GEN_HOST} "cat > ${LOAD_GEN_DIR}/${test}.txt"
done

mkdir -p ${RUN_DIR}

for test in "${TESTS[@]}"; do
    # the baseline serves the fast path assets from user space
    if [[ ${test} == "bl" ]]; then
        SERVER_FLAGS="--no-fastpath"
    else
        SERVER_FLAGS=""
    fi

    for proto in "${PROTOS[@]}"; do
        for rate in "${RATES[@]}"; do
            NAME=${test}
            if [[ -n ${proto} ]]; then
                NAME=${NAME}-http2
            fi
            NAME=${NAME}-q-${rate}

            echo -e "${COLOR_YELLOW}Launch ${test} server on ${SERVER_HOST}:${SERVER_PORT}${COLOR_OFF}"
            kill_server
            RUST_LOG= ${SERVER} ${SERVER_FLAGS} --addr 0.0.0.0:${SERVER_PORT} > ${RUN_DIR}/${NAME}.server.log 2>&1 &

            echo -e "${COLOR_YELLOW}Performing load test ${NAME} from ${LOAD_GEN_HOST}...${COLOR_OFF}"
            ssh -t ${LOAD_GEN_HOST} "~/.cargo/bin/oha -c ${CONNECTIONS} -z ${DURATION} --latency-correction --urls-from-file ${proto} -q ${rate} ${LOAD_GEN_DIR}/${test}.txt -o ${LOAD_GEN_DIR}/${NAME}.log"

            scp ${LOAD_GEN_HOST}:${LOAD_GEN_DIR}/${NAME}.log ${RUN_DIR}/
            echo -e "${COLOR_GREEN}Wrote ${RUN_DIR}/${NAME}.log${COLOR_OFF}"
        done
    done
done

teardown
