#!/usr/bin/env just --justfile

kill-server:
    sudo pkill -f '[t]arget/release/example' || true

start-server *FLAGS:
    just kill-server
    cargo b -r --bin example
    RUST_LOG= sudo --preserve-env=RUST_LOG taskset -c 1 target/release/example {{ FLAGS }} &
    sleep 1

load NAME *FLAGS:
    mkdir -p res/run
    taskset -c 10 oha {{ FLAGS }} -c 100 -z 30s --latency-correction --urls-from-file res/oha/load.txt -o res/run/{{ NAME }}{{ if FLAGS == "" { "" } else { "-" + replace(replace(trim(FLAGS), "-", ""), " ", "-") } }}.log

@cpu-governor GOV:
    echo {{ GOV }} | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

bench TEST *FLAGS:
    just cpu-governor performance

    just start-server {{ if TEST == "bl" { "--no-fastpath" } else { "" } }}
    just load {{ TEST }} {{ FLAGS }}

    just kill-server

    just cpu-governor schedutil
