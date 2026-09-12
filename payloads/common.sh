#!/usr/bin/env bash
set -Eeuo pipefail
emit() { printf 'VPS_INIT_PROTOCOL=1\nVPS_INIT_STEP=%s\nVPS_INIT_RESULT=%s\n' "$1" "$2"; }
fail() { printf 'VPS_INIT_ERROR_CODE=%s\nVPS_INIT_SUMMARY=%s\n' "$1" "$2" >&2; exit 1; }
require_root() { [[ "$(id -u)" == 0 ]] || fail NOT_ROOT "必须以 root 执行"; }
