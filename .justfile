#!/usr/bin/env just --justfile

kill-server:
    # bracket keeps the pattern from matching this recipe's own shell
    sudo pkill -f '[t]arget/release/example' || true

start-server *FLAGS:
    just kill-server
    RUST_LOG= cargo run -r --bin example -- {{ FLAGS }} &
    sleep 1

load TEST *FLAGS:
    mkdir -p res/run
    oha -c 100 -q 1000 -z 30s --latency-correction --urls-from-file {{ FLAGS }} res/oha/{{ TEST }}.txt -o res/run/{{ TEST }}{{ if FLAGS == "" { "" } else { "-" + replace(replace(trim(FLAGS), "-", ""), " ", "-") } }}.log

@cpu-governor GOV:
    echo {{ GOV }} | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

bench TEST *FLAGS:
    just cpu-governor "performance"

    just start-server {{ if TEST == "bl" { "--no-fastpath" } else { "" } }}
    just load {{ TEST }} {{ FLAGS }}

    just kill-server

    just cpu-governor "schedutil"
