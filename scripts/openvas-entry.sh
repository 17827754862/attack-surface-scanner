#!/usr/bin/env bash
set -Eeuo pipefail

/scripts/start.sh &
gvmd_pid=$!
proxy_pid=""

cleanup() {
    trap - TERM INT
    if [ -n "$proxy_pid" ]; then
        kill "$proxy_pid" 2>/dev/null || true
    fi
    kill "$gvmd_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
    wait "$gvmd_pid" 2>/dev/null || true
    exit 0
}
trap cleanup TERM INT

for _ in $(seq 1 120); do
    [ -S /run/gvmd/gvmd.sock ] && break
    sleep 2
done

if [ ! -S /run/gvmd/gvmd.sock ]; then
    wait "$gvmd_pid"
    exit $?
fi

socat \
    OPENSSL-LISTEN:9390,reuseaddr,fork,verify=0,cert=/var/lib/gvm/CA/servercert.pem,key=/var/lib/gvm/private/CA/serverkey.pem \
    UNIX-CONNECT:/run/gvmd/gvmd.sock &
proxy_pid=$!

wait "$gvmd_pid"
