#!/usr/bin/env bash
set -euo pipefail

# ═══════ 可配置项 ═══════
SS_PORT=59875
SS_METHOD="aes-128-gcm"

DIR_BASE="/opt/ss-landing"
SS_BIN="$DIR_BASE/ssserver"
SS_CONF="$DIR_BASE/config.json"
META_FILE="$DIR_BASE/.meta.json"

SS_REPO="shadowsocks/shadowsocks-rust"
# ═══════════════════════

readonly RC_EXIT_MENU=42

# ── 架构检测 ──
case $(uname -m) in
    amd64|x86_64)   SS_ARCH="x86_64-unknown-linux-gnu" ;;
    aarch64|armv8*)  SS_ARCH="aarch64-unknown-linux-gnu" ;;
    *)  echo "仅支持 amd64/arm64"; exit 1 ;;
esac

# ── 颜色 ──
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${GREEN}✓${NC} $*"; }
warn()  { echo -e "${YELLOW}⚠${NC} $*"; }
error() { echo -e "${RED}✗${NC} $*"; }
title() { echo -e "\n${BOLD}${CYAN}── $* ──${NC}\n"; }

press_enter() {
    echo ""
    read -rp "按回车返回..."
}

# ── 前置检查 ──
check_root() {
    [[ $EUID -eq 0 ]] || { error "请以 root 身份运行"; exit 1; }
}

check_deps() {
    for cmd in curl jq openssl tar; do
        command -v "$cmd" &>/dev/null || { error "缺少依赖: $cmd"; exit 1; }
    done
}

is_installed() {
    [[ -f "$SS_BIN" && -f "$SS_CONF" && -f "$META_FILE" ]]
}

ensure_installed() {
    is_installed || { error "尚未安装，请先执行安装部署"; press_enter; return 1; }
}

get_public_ip() {
    local ip
    ip=$(curl -4 -s --max-time 10 https://one.one.one.one/cdn-cgi/trace | grep -oP 'ip=\K.*' || true)
    if [[ -z "$ip" ]]; then
        warn "无法获取公网 IP，链接将显示 UNKNOWN"
        echo "UNKNOWN"
    else
        echo "$ip"
    fi
}

check_bbr() {
    local cc
    cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
    if [[ "$cc" != "bbr" ]]; then
        warn "当前拥塞控制: $cc（未启用 BBR，建议启用以提升吞吐量）"
    else
        info "BBR 已启用"
    fi
}

# ── SS 链接生成 ──
gen_ss_link() {
    local ip="$1"
    local method password port label userinfo
    method=$(jq -r '.method' "$SS_CONF")
    password=$(jq -r '.password' "$SS_CONF")
    port=$(jq -r '.server_port' "$SS_CONF")
    userinfo=$(printf '%s' "${method}:${password}" | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')
    label="LANDING-$(hostname -s | tr '[:lower:]' '[:upper:]')"
    echo "ss://${userinfo}@${ip}:${port}#${label}"
}

# ── 下载 ──
download_ss() {
    local ver=${1:-}
    if [[ -z "$ver" ]]; then
        ver=$(curl -s "https://api.github.com/repos/${SS_REPO}/releases/latest" | jq -r '.tag_name // empty') || true
        [[ -z "$ver" || "$ver" == "null" ]] && { error "获取版本失败"; return 1; }
    fi
    info "下载 shadowsocks-rust $ver ..."
    local tmp; tmp=$(mktemp -d)
    curl -L --fail -o "$tmp/ss.tar.xz" \
        "https://github.com/${SS_REPO}/releases/download/${ver}/shadowsocks-${ver}.${SS_ARCH}.tar.xz" \
        || { rm -rf "$tmp"; error "下载失败"; return 1; }
    mkdir -p "$DIR_BASE"
    tar xJf "$tmp/ss.tar.xz" -C "$DIR_BASE" ssserver
    chmod +x "$SS_BIN"
    rm -rf "$tmp"
    info "shadowsocks-rust $ver 已安装"
}

# ── systemd 服务 ──
install_service() {
    cat > /etc/systemd/system/ss-landing.service <<EOF
[Unit]
Description=Shadowsocks-Rust Landing Server
After=network.target

[Service]
Type=simple
ExecStart=$SS_BIN -c $SS_CONF
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
User=nobody
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    # 配置文件属主改为 nobody，否则 User=nobody 读不到 600 权限的文件
    chown nobody:nogroup "$SS_CONF" "$META_FILE"
    systemctl daemon-reload
    systemctl enable ss-landing >/dev/null 2>&1
}

# ═══════════════════════════════════════════════════
#  安装部署
# ═══════════════════════════════════════════════════
do_install() {
    title "安装部署"
    check_deps

    if is_installed; then
        warn "已检测到现有安装 ($DIR_BASE)"
        echo "如需重装，请先卸载。"
        press_enter
        return
    fi

    # 选择加密方式
    echo "加密方式:"
    echo "  1) aes-128-gcm (推荐，x86 硬件加速)"
    echo "  2) chacha20-ietf-poly1305 (ARM 设备推荐)"
    echo ""
    read -rp "请选择 [1]: " enc_choice
    local method
    case "${enc_choice:-1}" in
        1|"") method="aes-128-gcm" ;;
        2) method="chacha20-ietf-poly1305" ;;
        *) method="aes-128-gcm" ;;
    esac

    # 端口
    read -rp "监听端口 [${SS_PORT}]: " port
    port=${port:-$SS_PORT}
    [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) || { error "端口无效"; press_enter; return; }

    # 生成密码
    local password
    password=$(openssl rand -base64 16)

    echo ""
    echo -e "  加密方式: ${BOLD}${method}${NC}"
    echo -e "  监听端口: ${BOLD}${port}${NC}"
    echo ""
    read -rp "确认安装？[Y/n]: " confirm
    [[ "$confirm" =~ ^[nN] ]] && return

    echo ""

    # 下载
    download_ss || return

    # 写入配置
    jq -n \
      --arg method "$method" \
      --arg password "$password" \
      --argjson port "$port" \
      '{
        server: "0.0.0.0",
        server_port: $port,
        password: $password,
        method: $method,
        mode: "tcp_and_udp",
        fast_open: true,
        no_delay: true
      }' > "$SS_CONF"
    chmod 600 "$SS_CONF"

    # 写入元数据
    jq -n --argjson port "$port" --arg method "$method" \
      '{ port: $port, method: $method, installed_at: (now | todate) }' > "$META_FILE"
    chmod 600 "$META_FILE"

    # 安装服务并启动
    install_service
    systemctl start ss-landing
    info "ss-landing 已启动"

    # 防火墙
    ufw allow "$port/tcp" >/dev/null 2>&1 || true
    ufw allow "$port/udp" >/dev/null 2>&1 || true
    info "UFW 已放行端口 $port"

    # BBR 检查
    echo ""
    check_bbr

    # 输出结果
    echo ""
    local pub_ip; pub_ip=$(get_public_ip)
    echo -e "${BOLD}${GREEN}════════ 安装完成 ════════${NC}"
    echo ""
    echo -e "${BOLD}SS 链接:${NC}"
    gen_ss_link "$pub_ip"
    echo ""
    echo "将此链接粘贴到入口机 add_outbound 即可"
    press_enter
}

# ═══════════════════════════════════════════════════
#  查看状态
# ═══════════════════════════════════════════════════
show_status() {
    ensure_installed || return
    title "服务状态"

    if systemctl is-active --quiet ss-landing 2>/dev/null; then
        echo -e "  ss-landing\t${GREEN}● running${NC}"
    else
        echo -e "  ss-landing\t${RED}● stopped${NC}"
    fi

    local method port
    method=$(jq -r '.method' "$SS_CONF")
    port=$(jq -r '.server_port' "$SS_CONF")
    echo ""
    echo "  端口: $port"
    echo "  加密: $method"
    echo ""
    check_bbr
    press_enter
}

# ═══════════════════════════════════════════════════
#  查看链接
# ═══════════════════════════════════════════════════
show_link() {
    ensure_installed || return
    title "SS 链接"
    local pub_ip; pub_ip=$(get_public_ip)
    gen_ss_link "$pub_ip"
    echo ""
    press_enter
}

# ═══════════════════════════════════════════════════
#  更新
# ═══════════════════════════════════════════════════
do_update() {
    ensure_installed || return
    title "更新"
    local cur_ver
    cur_ver=$("$SS_BIN" --version 2>/dev/null | head -1 || echo "未知")
    echo "当前版本: $cur_ver"
    echo ""
    download_ss || { press_enter; return; }
    systemctl restart ss-landing && info "已更新并重启"
    press_enter
}

# ═══════════════════════════════════════════════════
#  卸载
# ═══════════════════════════════════════════════════
do_uninstall() {
    ensure_installed || return
    title "卸载"

    echo -e "${YELLOW}⚠ 即将删除:${NC}"
    echo "  • ssserver 二进制 + 配置 + systemd 服务"
    echo ""
    read -rp "确认卸载？[y/N]: " confirm
    [[ "$confirm" =~ ^[yY] ]] || return

    local port
    port=$(jq -r '.server_port' "$SS_CONF" 2>/dev/null || echo "$SS_PORT")

    systemctl stop ss-landing 2>/dev/null || true
    systemctl disable ss-landing 2>/dev/null || true
    rm -f /etc/systemd/system/ss-landing.service
    systemctl daemon-reload 2>/dev/null || true
    info "服务已停止并移除"

    ufw delete --force allow "$port/tcp" 2>/dev/null || true
    ufw delete --force allow "$port/udp" 2>/dev/null || true
    info "防火墙规则已清理"

    rm -rf "$DIR_BASE"
    info "已删除 $DIR_BASE"

    echo ""
    echo -e "${GREEN}✓ 卸载完成${NC}"
    press_enter
}

# ═══════════════════════════════════════════════════
#  主菜单
# ═══════════════════════════════════════════════════
show_main_menu() {
    clear
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════╗"
    echo "║     SS Landing 落地机管理       ║"
    echo "╚══════════════════════════════════╝"
    echo -e "${NC}"

    if is_installed; then
        local port method
        port=$(jq -r '.server_port' "$SS_CONF")
        method=$(jq -r '.method' "$SS_CONF")
        echo -e "  状态: ${GREEN}已安装${NC}  端口: ${BOLD}${port}${NC}  加密: ${BOLD}${method}${NC}"
    else
        echo -e "  状态: ${YELLOW}未安装${NC}"
    fi

    echo ""
    echo "  1) 安装部署"
    echo "  2) 查看状态"
    echo "  3) 查看链接"
    echo "  4) 更新"
    echo "  5) 卸载"
    echo ""
    echo "  0) 退出"
    echo ""
    read -rp "请选择 [0-5]: " choice
    echo ""
    case "$choice" in
        1) do_install ;;
        2) show_status ;;
        3) show_link ;;
        4) do_update ;;
        5) do_uninstall ;;
        0) echo "再见！"; exit $RC_EXIT_MENU ;;
        *) warn "无效选项" ;;
    esac
}

# ── 入口 ──
check_root
command -v flock &>/dev/null || { error "缺少依赖: flock (apt install util-linux)"; exit 1; }
mkdir -p "$DIR_BASE"
exec 9>"$DIR_BASE/.lock"
flock -n 9 || { error "已有另一个实例在运行"; exit 1; }

while true; do
    rc=0
    ( show_main_menu ) || rc=$?
    if [[ $rc -eq $RC_EXIT_MENU ]]; then
        exit 0
    elif [[ $rc -ne 0 ]]; then
        press_enter
    fi
done
