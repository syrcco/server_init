#!/usr/bin/env bash
set -euo pipefail

# 1. 显式初始化变量，防止环境变量污染
DD_ONLY=0
INIT_ARGS=()

need_root() {
    [[ "${EUID:-0}" -eq 0 ]] || { echo "[×] 请用 root 执行（sudo -i 后再跑）。" >&2; exit 1; }
}

fetch() {
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

run_remote() {
    local url="$1"; shift
    local tmp
    tmp="$(mktemp)"
    fetch "$url" "$tmp"
    # 优化点：使用 < /dev/null 确保远程脚本不会误吞管道中的后续指令
    bash "$tmp" "$@" < /dev/null
    rm -f "$tmp"
}

usage() {
    cat <<'EOF'
用法：
  bash all.sh [--dd] [init.sh 的参数...]

模式：
  --dd    只运行 DD 重装脚本（bin456789/reinstall）
  默认    依次运行 init.sh -> firewall.sh

注意：使用管道 curl | bash 时，请务必使用 -- 分隔参数。
EOF
}

# ===== 配置区 =====
RAW_BASE="${RAW_BASE:-https://raw.githubusercontent.com/syrcco/server_init/main}"
INIT_URL="${INIT_URL:-${RAW_BASE}/init.sh}"
FIREWALL_URL="${FIREWALL_URL:-${RAW_BASE}/firewall.sh}"

DD_OS_1="${DD_OS_1:-debian}"
DD_OS_2="${DD_OS_2:-12}"
DD_SSH_PORT="${DD_SSH_PORT:-31415}"
DD_SSH_KEY="${DD_SSH_KEY:-ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGE3rQl0o4KRV3UggBH7VlCmQDS8xT/eRUwBFKOyO/f/}"

# ===== 参数解析优化 =====
# 即使通过 bash -s 传入，也能稳健处理
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dd)
            DD_ONLY=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            INIT_ARGS+=("$1")
            shift
            ;;
    esac
done

need_root

# ===== 核心逻辑：互斥执行 =====
if [[ "$DD_ONLY" -eq 1 ]]; then
    echo "[!] 进入 DD 重装模式..."
    REINSTALL_URL="https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh"
    fetch "$REINSTALL_URL" "reinstall.sh"
    # 强制退出，确保 DD 之后绝不执行后续逻辑
    exec bash reinstall.sh "${DD_OS_1}" "${DD_OS_2}" --ssh-port "${DD_SSH_PORT}" --ssh-key "${DD_SSH_KEY}"
else
    echo "[+] 进入标准初始化模式..."
    run_remote "${INIT_URL}" "${INIT_ARGS[@]}"
    run_remote "${FIREWALL_URL}"
fi
