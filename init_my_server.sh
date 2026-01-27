#!/usr/bin/env bash
set -euo pipefail

need_root() {
  [[ "${EUID:-0}" -eq 0 ]] || { echo "[×] 请用 root 执行（sudo -i 后再跑）。" >&2; exit 1; }
}

fetch() { # fetch <url> <out>
  local url="$1" out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSLo "$out" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
  else
    echo "[×] 需要 curl 或 wget" >&2
    exit 1
  fi
}

run_remote() { # run_remote <url> [args...]
  local url="$1"; shift
  local tmp
  tmp="$(mktemp)"
  fetch "$url" "$tmp"
  bash "$tmp" "$@"
  rm -f "$tmp"
}

usage() {
  cat <<'EOF'
用法：
  bash all.sh [--dd] [init.sh 的参数...]

模式：
  --dd    只运行 DD 重装脚本（bin456789/reinstall）
  默认    依次运行 init.sh -> firewall.sh（参数透传给 init.sh）

示例：
  bash all.sh --user syrcco
  bash all.sh --dd
EOF
}

# ===== Repo URLs =====
RAW_BASE="${RAW_BASE:-https://raw.githubusercontent.com/syrcco/server_init/main}"
INIT_URL="${INIT_URL:-${RAW_BASE}/init.sh}"
FIREWALL_URL="${FIREWALL_URL:-${RAW_BASE}/firewall.sh}"

# ===== DD defaults (override via env) =====
DD_OS_1="${DD_OS_1:-debian}"
DD_OS_2="${DD_OS_2:-12}"
DD_SSH_PORT="${DD_SSH_PORT:-31415}"
DD_SSH_KEY="${DD_SSH_KEY:-ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGE3rQl0o4KRV3UggBH7VlCmQDS8xT/eRUwBFKOyO/f/}"

DD_ONLY=0
INIT_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dd) DD_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) INIT_ARGS+=("$1"); shift ;;
  esac
done

need_root

if [[ "$DD_ONLY" -eq 1 ]]; then
  # ⚠️ 破坏性操作：会重装系统
  ( fetch "https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh" "reinstall.sh" \
    || wget -O reinstall.sh "https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh" )
  bash reinstall.sh "${DD_OS_1}" "${DD_OS_2}" --ssh-port "${DD_SSH_PORT}" --ssh-key "${DD_SSH_KEY}"
  exit 0
fi

# Normal mode: init -> firewall
run_remote "${INIT_URL}" "${INIT_ARGS[@]}"
run_remote "${FIREWALL_URL}"
