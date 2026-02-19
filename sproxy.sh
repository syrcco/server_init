#!/usr/bin/env bash
set -euo pipefail

# ═══════ 可配置项 ═══════
DOMAIN="kaemito.com"

# 完整模式端口
CADDY_HTTPS_PORT=1443
SITE_PORT=8080
SS_PORT=59876
HY2_PORT=8443

# Shadowsocks 端口（完整模式可选）
LEGACY_SS_PORT=59877

# 轻量模式端口
LITE_SS_PORT=59875

# sing-box 版本锁定
SINGBOX_VERSION_PREFIX="1.12"

# 镜像
SITE_IMAGE="ghcr.io/syrcco/login_site:latest"

# 目录
DIR_BASE="/opt/sproxy"
DIR_CADDY="/opt/caddy"
DIR_SITE="/opt/fake-site"
# ═══════════════════════

SINGBOX_BIN="$DIR_BASE/sing-box"
CONF_FILE="$DIR_BASE/config.json"
META_FILE="$DIR_BASE/.meta.json"
MODE_FILE="$DIR_BASE/.mode"
CUSTOM_RULES_FILE="$DIR_BASE/custom-rules.json"
SS_WHITELIST_FILE="$DIR_BASE/.ss-whitelist"
CADDY_BIN="$DIR_CADDY/caddy"
CADDYFILE="$DIR_CADDY/Caddyfile"

CADDY_REPO="caddyserver/caddy"

readonly RC_EXIT_MENU=42

# ── 架构检测 ──
case $(uname -m) in
    amd64|x86_64)
        SINGBOX_ARCH="amd64"
        CADDY_ARCH="amd64"
        DEFAULT_SS_METHOD="aes-128-gcm"
        ;;
    aarch64|armv8*)
        SINGBOX_ARCH="arm64"
        CADDY_ARCH="arm64"
        DEFAULT_SS_METHOD="chacha20-ietf-poly1305"
        ;;
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

check_deps_lite() {
    for cmd in curl jq openssl base64 tar flock ss; do
        command -v "$cmd" &>/dev/null || { error "缺少依赖: $cmd"; exit 1; }
    done
}

check_deps_full() {
    for cmd in curl jq openssl base64 tar unzip ss flock shuf; do
        command -v "$cmd" &>/dev/null || { error "缺少依赖: $cmd"; exit 1; }
    done
}

check_docker() {
    command -v docker &>/dev/null || { error "未安装 Docker (fake-site 需要)"; exit 1; }
    docker compose version &>/dev/null || { error "未安装 docker compose 插件"; exit 1; }
}

check_port_available() {
    local port=$1 proto=${2:-tcp}
    local flag="-tlnp"
    [[ "$proto" == "udp" ]] && flag="-ulnp"
    if ss -H $flag "sport = :${port}" 2>/dev/null | grep -q .; then
        error "端口 $port/$proto 已被占用:"
        ss $flag "sport = :${port}" 2>/dev/null
        return 1
    fi
}

# ── 模式检测 ──
get_mode() { cat "$MODE_FILE" 2>/dev/null || echo "unknown"; }

is_installed() {
    [[ -f "$SINGBOX_BIN" && -f "$CONF_FILE" && -f "$META_FILE" && -f "$MODE_FILE" ]]
}

ensure_installed() {
    is_installed || { error "尚未安装，请先执行安装部署"; press_enter; return 1; }
}

# ── 元数据读取 ──
meta_get()      { jq -r ".$1" "$META_FILE"; }
get_node()      { meta_get "node"; }
get_fqdn()      { echo "$(get_node).$DOMAIN"; }
get_public_key() { meta_get "reality_public_key"; }
get_short_id()  { meta_get "short_id"; }

get_public_ip() {
    local ip
    ip=$(curl -4 -s --max-time 10 https://one.one.one.one/cdn-cgi/trace | sed -n 's/^ip=//p' || true)
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

# ── base64url 编解码 ──
base64url_encode() {
    printf '%s' "$1" | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='
}

base64url_decode() {
    local input="$1"
    local mod=$((${#input} % 4))
    if [[ $mod -eq 2 ]]; then input="${input}=="
    elif [[ $mod -eq 3 ]]; then input="${input}="
    fi
    echo "$input" | tr -- '-_' '+/' | base64 -d
}

# ── SS 链接解析 ──
_parse_hostport() {
    local hp="$1"
    if [[ "$hp" == \[* ]]; then
        SS_PARSED_ADDR="${hp%%\]:*}"; SS_PARSED_ADDR="${SS_PARSED_ADDR#\[}"
        SS_PARSED_PORT="${hp##*\]:}"
    else
        SS_PARSED_ADDR="${hp%:*}"; SS_PARSED_PORT="${hp##*:}"
    fi
}

parse_ss_link() {
    local link="$1"
    link="${link#ss://}"
    local main="${link%%#*}"
    if [[ "$main" == *@* ]]; then
        local userinfo="${main%@*}" hostport="${main##*@}"
        local decoded; decoded=$(base64url_decode "$userinfo") || return 1
        SS_PARSED_METHOD="${decoded%%:*}"; SS_PARSED_PASSWORD="${decoded#*:}"
        _parse_hostport "$hostport"
    else
        local decoded; decoded=$(base64url_decode "$main") || return 1
        local userinfo="${decoded%@*}" hostport="${decoded##*@}"
        SS_PARSED_METHOD="${userinfo%%:*}"; SS_PARSED_PASSWORD="${userinfo#*:}"
        _parse_hostport "$hostport"
    fi
}

# ── DNS 验证 ──
verify_dns() {
    local fqdn=$1
    local server_ip dns_result
    server_ip=$(curl -4 -s --max-time 10 https://one.one.one.one/cdn-cgi/trace | sed -n 's/^ip=//p' || true)
    [[ -z "$server_ip" ]] && { warn "无法获取本机公网 IP，跳过 DNS 验证"; return 0; }
    dns_result=$(curl -s --max-time 10 -H "accept: application/dns-json" \
        "https://one.one.one.one/dns-query?name=${fqdn}&type=A" | jq -r '.Answer[]?.data // empty' || true)
    if [[ -z "$dns_result" ]]; then
        warn "域名 $fqdn 无 A 记录"
        warn "HTTP-01 证书签发可能失败，请确认 DNS 设置"
        read -rp "是否继续？[y/N]: " confirm
        [[ "$confirm" =~ ^[yY] ]] || return 1
    elif [[ "$dns_result" != *"$server_ip"* ]]; then
        warn "域名 $fqdn 解析到 $dns_result，本机 IP 为 $server_ip"
        read -rp "是否继续？[y/N]: " confirm
        [[ "$confirm" =~ ^[yY] ]] || return 1
    else
        info "DNS 验证通过: $fqdn → $server_ip"
    fi
}

# ── 配置管理 ──
update_config() {
    local filter="$1"; shift
    local tmp
    tmp=$(mktemp "${CONF_FILE}.XXXXXX")
    if jq "$@" "$filter" "$CONF_FILE" > "$tmp"; then
        chmod 600 "$tmp"
        mv -f "$tmp" "$CONF_FILE"
    else
        rm -f "$tmp"
        error "JSON 操作失败"
        return 1
    fi
}

validate_config() {
    if ! "$SINGBOX_BIN" check -c "$CONF_FILE" 2>/dev/null; then
        error "配置验证失败:"
        "$SINGBOX_BIN" check -c "$CONF_FILE" 2>&1 | tail -5
        return 1
    fi
}

restart_sproxy() {
    if validate_config; then
        if systemctl restart sproxy; then
            info "sproxy 已重启"
        else
            error "systemctl restart 失败，尝试前台诊断:"
            timeout 10 "$SINGBOX_BIN" run -c "$CONF_FILE" 2>&1 | head -20 || true
            return 1
        fi
    else
        error "配置无效，未重启"
        return 1
    fi
}

# ── 自定义路由合并 ──
read_custom_rules() {
    if [[ -f "$CUSTOM_RULES_FILE" ]]; then
        jq '.' "$CUSTOM_RULES_FILE" 2>/dev/null || echo "[]"
    else
        echo "[]"
    fi
}

rebuild_route_rules() {
    local custom smart_rules user_routes defaults merged

    # per-user 路由（如 us → chain-us），优先级最高，确保固定出口用户的所有流量走指定出站
    # 排除 smart 的 auth_user 规则（那些是从 custom-rules.json 注入的，会重新生成）
    user_routes=$(jq '[.route.rules[] | select(.auth_user and ((.auth_user | index("smart")) | not))]' "$CONF_FILE" 2>/dev/null || echo "[]")

    # smart 自定义规则：注入 auth_user 限制仅对 smart 生效，不影响其他节点
    custom=$(read_custom_rules)
    smart_rules=$(jq '[.[] | . + {auth_user: ["smart", "ss-smart"]}]' <<< "$custom")

    # 默认屏蔽规则（全局）
    defaults='[
      {"action":"sniff"},
      {"protocol":"bittorrent","action":"block"},
      {"rule_set":"geosite-ads","action":"block"},
      {"rule_set":"geoip-cn","action":"block"},
      {"ip_is_private":true,"action":"block"}
    ]'

    # 合并顺序: per-user → smart 自定义 → 默认屏蔽 → direct(隐式)
    merged=$(jq -n --argjson a "$user_routes" --argjson b "$smart_rules" --argjson c "$defaults" '$a + $b + $c')

    local tmp
    tmp=$(mktemp "${CONF_FILE}.XXXXXX")
    if jq --argjson rules "$merged" '.route.rules = $rules' "$CONF_FILE" > "$tmp"; then
        chmod 600 "$tmp"
        mv -f "$tmp" "$CONF_FILE"
    else
        rm -f "$tmp"
        error "rebuild_route_rules: JSON 操作失败"
        return 1
    fi
}

# ═══════════════════════════════════════════════════
#  下载函数
# ═══════════════════════════════════════════════════
download_singbox() {
    local ver
    ver=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases?per_page=100" \
        | jq -r --arg pfx "v${SINGBOX_VERSION_PREFIX}." \
          '[.[] | select(.tag_name | startswith($pfx)) | .tag_name][0] // empty') || true
    [[ -z "$ver" ]] && { error "获取 sing-box 版本失败"; return 1; }
    info "下载 sing-box $ver ..." >&2
    local tmp; tmp=$(mktemp -d)
    local ver_num="${ver#v}"
    curl -L --fail -o "$tmp/sb.tar.gz" \
        "https://github.com/SagerNet/sing-box/releases/download/${ver}/sing-box-${ver_num}-linux-${SINGBOX_ARCH}.tar.gz" \
        || { rm -rf "$tmp"; error "下载失败"; return 1; }
    mkdir -p "$DIR_BASE"
    tar xzf "$tmp/sb.tar.gz" -C "$tmp"
    cp -f "$tmp/sing-box-${ver_num}-linux-${SINGBOX_ARCH}/sing-box" "$SINGBOX_BIN"
    chmod +x "$SINGBOX_BIN"
    rm -rf "$tmp"
    info "sing-box $ver 已安装" >&2
    echo "$ver_num"
}

download_caddy() {
    local cf_mode=${1:-}
    if [[ -n "$cf_mode" ]]; then
        info "下载 Caddy (带 cloudflare DNS 插件) ..."
        mkdir -p "$DIR_CADDY"
        curl -L --fail -o "$CADDY_BIN" \
            "https://caddyserver.com/api/download?os=linux&arch=${CADDY_ARCH}&p=github.com/caddy-dns/cloudflare" \
            || { error "下载 Caddy 失败"; return 1; }
    else
        local ver
        ver=$(curl -s "https://api.github.com/repos/${CADDY_REPO}/releases/latest" | jq -r '.tag_name // empty') || true
        [[ -z "$ver" || "$ver" == "null" ]] && { error "获取 Caddy 版本失败"; return 1; }
        info "下载 Caddy $ver ..."
        local tmp; tmp=$(mktemp -d)
        curl -L --fail -o "$tmp/caddy.tar.gz" \
            "https://github.com/${CADDY_REPO}/releases/download/${ver}/caddy_${ver#v}_linux_${CADDY_ARCH}.tar.gz" \
            || { rm -rf "$tmp"; error "下载 Caddy 失败"; return 1; }
        mkdir -p "$DIR_CADDY"
        tar xzf "$tmp/caddy.tar.gz" -C "$DIR_CADDY" caddy
        rm -rf "$tmp"
    fi
    chmod +x "$CADDY_BIN"
    info "Caddy 已安装"
}

# ── Caddy 证书路径探测 ──
find_caddy_cert() {
    local fqdn="$1"
    local cert_dir="$DIR_CADDY/data/caddy/certificates"
    local crt
    crt=$(find "$cert_dir" -path '*/staging*' -prune -o -name "${fqdn}.crt" -type f -print 2>/dev/null | head -1)
    [[ -n "$crt" ]] && echo "$(dirname "$crt")" || return 1
}

# ═══════════════════════════════════════════════════
#  systemd 服务
# ═══════════════════════════════════════════════════
install_sproxy_service() {
    cat > /etc/systemd/system/sproxy.service <<EOF
[Unit]
Description=sing-box Proxy Service
After=network.target nss-lookup.target caddy.service

[Service]
Type=simple
ExecStart=$SINGBOX_BIN run -c $CONF_FILE
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=3
RestartPreventExitStatus=23
LimitNOFILE=1048576
LimitNPROC=10000
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
User=root
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sproxy >/dev/null 2>&1
}

install_caddy_service() {
    mkdir -p "$DIR_CADDY/data" "$DIR_CADDY/config"

    cat > /etc/systemd/system/caddy.service <<EOF
[Unit]
Description=Caddy Web Server
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
ExecStart=$CADDY_BIN run --environ --config $CADDYFILE --adapter caddyfile
ExecReload=$CADDY_BIN reload --config $CADDYFILE --adapter caddyfile
TimeoutStopSec=5s
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
EnvironmentFile=-$DIR_CADDY/.env
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
User=root
PrivateTmp=true
ProtectSystem=full
Environment=XDG_DATA_HOME=$DIR_CADDY/data
Environment=XDG_CONFIG_HOME=$DIR_CADDY/config

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable caddy >/dev/null 2>&1
}

# ═══════════════════════════════════════════════════
#  轻量模式安装
# ═══════════════════════════════════════════════════
do_install_lite() {
    title "轻量安装 (落地机)"
    check_deps_lite

    if is_installed; then
        warn "已检测到现有安装 ($DIR_BASE)"
        echo "如需重装，请先卸载。"
        press_enter; return
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
        *) method="$DEFAULT_SS_METHOD" ;;
    esac

    # 端口
    read -rp "监听端口 [${LITE_SS_PORT}]: " port
    port=${port:-$LITE_SS_PORT}
    [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) || { error "端口无效"; press_enter; return; }
    check_port_available "$port" || { press_enter; return; }
    check_port_available "$port" udp || { press_enter; return; }

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

    # 下载 sing-box
    local sb_ver
    sb_ver=$(download_singbox) || return

    # 生成 config.json
    jq -n \
      --arg method "$method" \
      --arg password "$password" \
      --argjson port "$port" \
      '{
        log: { level: "warn" },
        inbounds: [{
          type: "shadowsocks",
          tag: "ss",
          listen: "::",
          listen_port: $port,
          method: $method,
          password: $password
        }],
        outbounds: [
          { type: "direct", tag: "direct" },
          { type: "block", tag: "block" }
        ],
        route: {
          rule_set: [{
            type: "remote",
            tag: "geoip-cn",
            format: "binary",
            url: "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
            download_detour: "direct"
          }],
          rules: [{
            rule_set: "geoip-cn",
            rule_set_ip_cidr_match_source: true,
            action: "block"
          }]
        }
      }' > "$CONF_FILE"
    chmod 600 "$CONF_FILE"

    # 写入元数据
    jq -n --argjson port "$port" --arg method "$method" --arg sv "$sb_ver" \
      '{ mode: "lite", port: $port, method: $method, singbox_version: $sv, installed_at: (now | todate) }' > "$META_FILE"
    chmod 600 "$META_FILE"
    echo "lite" > "$MODE_FILE"

    # 验证
    if ! validate_config; then
        rm -rf "$DIR_BASE"
        error "配置验证失败，安装已回滚"
        press_enter; return
    fi

    # 安装服务并启动
    install_sproxy_service
    systemctl start sproxy
    info "sproxy 已启动"

    # 防火墙
    apply_ss_whitelist "$port"

    # BBR
    echo ""
    check_bbr

    # 输出结果
    echo ""
    local pub_ip; pub_ip=$(get_public_ip)
    echo -e "${BOLD}${GREEN}════════ 安装完成 ════════${NC}"
    echo ""
    echo -e "${BOLD}SS 链接:${NC}"
    gen_lite_ss_link "$pub_ip"
    echo ""
    echo "将此链接粘贴到入口机 add_outbound 即可"
    press_enter
}

# ── 轻量模式链接生成 ──
gen_lite_ss_link() {
    local ip="$1"
    local method password port label userinfo
    method=$(jq -r '.inbounds[0].method' "$CONF_FILE")
    password=$(jq -r '.inbounds[0].password' "$CONF_FILE")
    port=$(jq -r '.inbounds[0].listen_port' "$CONF_FILE")
    userinfo=$(printf '%s' "${method}:${password}" | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')
    label="LANDING-$(hostname -s | tr '[:lower:]' '[:upper:]')"
    echo "ss://${userinfo}@${ip}:${port}#${label}"
}

# ── 轻量模式查看状态 ──
show_lite_status() {
    ensure_installed || return
    title "服务状态"
    if systemctl is-active --quiet sproxy 2>/dev/null; then
        echo -e "  sproxy\t${GREEN}● running${NC}"
    else
        echo -e "  sproxy\t${RED}● stopped${NC}"
    fi
    local method port
    method=$(jq -r '.inbounds[0].method' "$CONF_FILE")
    port=$(jq -r '.inbounds[0].listen_port' "$CONF_FILE")
    echo ""
    echo "  端口: $port"
    echo "  加密: $method"
    echo ""
    check_bbr
    press_enter
}

# ── 轻量模式查看链接 ──
show_lite_link() {
    ensure_installed || return
    title "SS 链接"
    local pub_ip; pub_ip=$(get_public_ip)
    gen_lite_ss_link "$pub_ip"
    echo ""
    press_enter
}

# ── 轻量模式重置链接 ──
do_lite_reset() {
    ensure_installed || return
    title "重置链接"

    local cur_port cur_method
    cur_port=$(jq -r '.inbounds[0].listen_port' "$CONF_FILE")
    cur_method=$(jq -r '.inbounds[0].method' "$CONF_FILE")

    echo "当前配置:"
    echo "  端口: $cur_port  加密: $cur_method"
    echo ""
    echo "  1) 仅重置密码（保留端口和加密方式）"
    echo "  2) 重置全部（重新选择端口、加密方式、生成新密码）"
    echo ""
    read -rp "请选择 [1-2]: " reset_mode

    local new_password new_method new_port
    new_password=$(openssl rand -base64 16)

    case "$reset_mode" in
        1)
            new_method="$cur_method"
            new_port="$cur_port"
            ;;
        2)
            echo ""
            echo "加密方式:"
            echo "  1) aes-128-gcm"
            echo "  2) chacha20-ietf-poly1305"
            read -rp "请选择 [回车保持 $cur_method]: " enc_choice
            case "${enc_choice}" in
                1) new_method="aes-128-gcm" ;;
                2) new_method="chacha20-ietf-poly1305" ;;
                *) new_method="$cur_method" ;;
            esac
            read -rp "新端口 [回车保持 $cur_port]: " new_port
            new_port=${new_port:-$cur_port}
            [[ "$new_port" =~ ^[0-9]+$ ]] && (( new_port >= 1 && new_port <= 65535 )) || { error "端口无效"; press_enter; return; }
            ;;
        *) warn "无效选项"; press_enter; return ;;
    esac

    # 更新配置
    update_config '.inbounds[0].password = $pw | .inbounds[0].method = $m | .inbounds[0].listen_port = ($p | tonumber)' \
        --arg pw "$new_password" --arg m "$new_method" --arg p "$new_port"

    # 更新 UFW（端口变更时）
    if [[ "$new_port" != "$cur_port" ]]; then
        ufw_clean_port "$cur_port"
        apply_ss_whitelist "$new_port"
    fi

    # 更新元数据
    if jq --arg m "$new_method" --argjson p "$new_port" '.method = $m | .port = $p' "$META_FILE" > "${META_FILE}.tmp"; then
        mv -f "${META_FILE}.tmp" "$META_FILE"
    else
        rm -f "${META_FILE}.tmp"
        error "元数据更新失败"
        press_enter; return
    fi

    restart_sproxy || { press_enter; return; }

    echo ""
    local pub_ip; pub_ip=$(get_public_ip)
    echo -e "${BOLD}新 SS 链接:${NC}"
    gen_lite_ss_link "$pub_ip"
    echo ""
    warn "旧链接已失效，请更新入口机 outbound 配置"
    press_enter
}

# ── 轻量模式更新 ──
do_lite_update() {
    ensure_installed || return
    title "更新 sing-box"
    local cur_ver
    cur_ver=$("$SINGBOX_BIN" version 2>/dev/null | head -1 || echo "未知")
    echo "当前版本: $cur_ver"
    echo ""
    download_singbox || { press_enter; return; }
    systemctl restart sproxy && info "已更新并重启"
    press_enter
}

# ── 轻量模式卸载 ──
do_lite_uninstall() {
    ensure_installed || return
    title "卸载"

    echo -e "${YELLOW}⚠ 即将删除:${NC}"
    echo "  • sing-box 二进制 + 配置 + systemd 服务"
    echo ""
    read -rp "确认卸载？[y/N]: " confirm
    [[ "$confirm" =~ ^[yY] ]] || return

    local port
    port=$(jq -r '.inbounds[0].listen_port' "$CONF_FILE" 2>/dev/null || echo "$LITE_SS_PORT")

    systemctl stop sproxy 2>/dev/null || true
    systemctl disable sproxy 2>/dev/null || true
    rm -f /etc/systemd/system/sproxy.service
    systemctl daemon-reload 2>/dev/null || true
    info "服务已停止并移除"

    ufw_clean_port "$port"
    info "防火墙规则已清理"

    rm -rf "$DIR_BASE"
    info "已删除 $DIR_BASE"

    echo ""
    echo -e "${GREEN}✓ 卸载完成${NC}"
    press_enter
}

# ═══════════════════════════════════════════════════
#  完整模式安装
# ═══════════════════════════════════════════════════
install_rollback() {
    trap - ERR
    warn "正在回滚安装..."
    systemctl stop sproxy 2>/dev/null || true
    systemctl stop caddy 2>/dev/null || true
    systemctl disable sproxy 2>/dev/null || true
    systemctl disable caddy 2>/dev/null || true
    rm -f /etc/systemd/system/sproxy.service /etc/systemd/system/caddy.service
    systemctl daemon-reload 2>/dev/null || true
    if [[ -d "$DIR_SITE" ]]; then
        cd "$DIR_SITE" && docker compose down 2>/dev/null || true
    fi
    rm -rf "$DIR_BASE" "$DIR_CADDY" "$DIR_SITE"
    ufw delete --force allow 443/tcp 2>/dev/null || true
    ufw delete --force allow "${CADDY_HTTPS_PORT}/tcp" 2>/dev/null || true
    ufw delete --force allow 80/tcp 2>/dev/null || true
    ufw delete --force allow "${SS_PORT}/tcp" 2>/dev/null || true
    ufw delete --force allow "${SS_PORT}/udp" 2>/dev/null || true
    error "安装已回滚，请检查上方错误信息"
    press_enter
}

do_install_full() {
    title "完整安装 (入口机)"
    check_deps_full
    check_docker

    if is_installed; then
        warn "已检测到现有安装 ($DIR_BASE)"
        echo "如需重装，请先卸载。"
        press_enter; return
    fi

    # 检测端口冲突
    local port_conflict=false
    for p in 443 "$CADDY_HTTPS_PORT" 80 "$SS_PORT" "$SITE_PORT"; do
        check_port_available "$p" || port_conflict=true
    done
    check_port_available "$SS_PORT" udp || port_conflict=true
    [[ "$port_conflict" == "true" ]] && { press_enter; return; }

    # 交互提问
    local node cf_token
    read -rp "域名前缀 (如 hk1, us1): " node
    node=$(echo "$node" | tr '[:upper:]' '[:lower:]')
    [[ -z "$node" ]] && { error "域名前缀不能为空"; press_enter; return; }
    [[ "$node" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || { error "域名前缀格式无效"; press_enter; return; }

    echo ""
    echo "Cloudflare API Token（用于 DNS-01 验证自动签证书）"
    echo "如果跳过，Caddy 将使用 HTTP-01 自动验证（需要 DNS A 记录已指向本机）"
    read -rp "CF API Token (回车跳过): " cf_token

    local fqdn="${node}.${DOMAIN}"

    # DNS 验证
    if [[ -z "$cf_token" ]]; then
        verify_dns "$fqdn" || return
    else
        info "使用 DNS-01 验证，跳过 A 记录校验"
    fi

    echo ""
    echo -e "  节点域名: ${BOLD}${fqdn}${NC}"
    echo -e "  证书验证: ${BOLD}$([ -n "$cf_token" ] && echo "DNS-01 (Cloudflare)" || echo "HTTP-01 (自动)")${NC}"
    echo ""
    read -rp "确认开始安装？[Y/n]: " confirm
    [[ "$confirm" =~ ^[nN] ]] && return

    trap 'install_rollback' ERR
    echo ""

    # [1] 下载二进制
    echo -e "${BOLD}下载 sing-box ...${NC}"
    local sb_ver
    sb_ver=$(download_singbox) || return

    echo -e "${BOLD}下载 Caddy ...${NC}"
    if [[ -n "$cf_token" ]]; then
        download_caddy cf
    else
        download_caddy
    fi

    # [2] 部署 fake-site
    echo ""
    echo -e "${BOLD}部署 fake-site ...${NC}"
    mkdir -p "$DIR_SITE"
    cat > "$DIR_SITE/docker-compose.yml" <<YAML
services:
  fake-site:
    image: ${SITE_IMAGE}
    container_name: fake-site
    restart: unless-stopped
    ports:
      - "127.0.0.1:${SITE_PORT}:80"
YAML
    cd "$DIR_SITE"
    docker compose pull -q
    docker compose up -d
    info "fake-site 已部署"

    # [3] 生成密钥
    echo ""
    echo -e "${BOLD}生成密钥 ...${NC}"
    local reality_output priv_key pub_key short_id smart_uuid
    local ss_server_key ss_smart_key

    reality_output=$("$SINGBOX_BIN" generate reality-keypair)
    priv_key=$(echo "$reality_output" | awk '/PrivateKey/{print $NF}')
    pub_key=$(echo "$reality_output" | awk '/PublicKey/{print $NF}')
    [[ -z "$priv_key" || -z "$pub_key" ]] && { error "无法解析 REALITY 密钥"; install_rollback; return; }

    short_id=$("$SINGBOX_BIN" generate rand --hex 8)
    smart_uuid=$("$SINGBOX_BIN" generate uuid)
    ss_server_key=$(openssl rand -base64 16)
    ss_smart_key=$(openssl rand -base64 16)

    # [4] 写入 Caddyfile
    echo -e "${BOLD}写入配置 ...${NC}"
    if [[ -n "$cf_token" ]]; then
        cat > "$CADDYFILE" <<EOF
${fqdn}:${CADDY_HTTPS_PORT} {
    tls {
        dns cloudflare {env.CF_API_TOKEN}
    }
    reverse_proxy 127.0.0.1:${SITE_PORT}
}

:80 {
    redir https://{host}:${CADDY_HTTPS_PORT}{uri} permanent
}
EOF
        echo "CF_API_TOKEN=${cf_token}" > "$DIR_CADDY/.env"
        chmod 600 "$DIR_CADDY/.env"
    else
        cat > "$CADDYFILE" <<EOF
${fqdn}:${CADDY_HTTPS_PORT} {
    tls {
        issuer acme {
            disable_tlsalpn_challenge
        }
    }
    reverse_proxy 127.0.0.1:${SITE_PORT}
}

:80 {
    redir https://{host}:${CADDY_HTTPS_PORT}{uri} permanent
}
EOF
    fi

    # [5] 安装 Caddy 服务并启动（先于 sing-box，等证书签发）
    install_caddy_service
    systemctl start caddy
    info "caddy 已启动"

    # [6] 生成 sing-box config.json
    jq -n \
      --arg priv "$priv_key" \
      --arg fqdn "$fqdn" \
      --arg sid "$short_id" \
      --arg uuid "$smart_uuid" \
      --arg ss_srv "$ss_server_key" \
      --arg ss_usr "$ss_smart_key" \
      --argjson caddy_port "$CADDY_HTTPS_PORT" \
      --argjson ss_port "$SS_PORT" \
      '{ log: { level: "warn" },
        inbounds: [
          {
            type: "vless",
            tag: "vless-reality",
            listen: "::",
            listen_port: 443,
            users: [
              { uuid: $uuid, name: "smart", flow: "xtls-rprx-vision" }
            ],
            tls: {
              enabled: true,
              server_name: $fqdn,
              reality: {
                enabled: true,
                handshake: { server: "127.0.0.1", server_port: $caddy_port },
                private_key: $priv,
                short_id: [$sid]
              }
            }
          },
          {
            type: "shadowsocks",
            tag: "ss2022",
            listen: "::",
            listen_port: $ss_port,
            method: "2022-blake3-aes-128-gcm",
            password: $ss_srv,
            users: [
              { name: "ss-smart", password: $ss_usr }
            ],
            multiplex: { enabled: true }
          }
        ],
        outbounds: [
          { type: "direct", tag: "direct" },
          { type: "block", tag: "block" }
        ],
        route: {
          auto_detect_interface: true,
          rule_set: [
            {
              type: "remote", tag: "geoip-cn", format: "binary",
              url: "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
              download_detour: "direct"
            },
            {
              type: "remote", tag: "geosite-ads", format: "binary",
              url: "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
              download_detour: "direct"
            }
          ],
          rules: [
            { action: "sniff" },
            { protocol: "bittorrent", action: "block" },
            { rule_set: "geosite-ads", action: "block" },
            { rule_set: "geoip-cn", action: "block" },
            { ip_is_private: true, action: "block" }
          ]
        }
      }' > "$CONF_FILE"
    chmod 600 "$CONF_FILE"

    # [7] 写入元数据
    jq -n \
      --arg node "$node" --arg domain "$DOMAIN" \
      --arg pbk "$pub_key" --arg sid "$short_id" \
      --arg sv "$sb_ver" --argjson ss_port "$SS_PORT" \
      '{
        mode: "full", node: $node, domain: $domain,
        reality_public_key: $pbk, short_id: $sid,
        ss_port: $ss_port, singbox_version: $sv,
        installed_at: (now | todate)
      }' > "$META_FILE"
    chmod 600 "$META_FILE"
    echo "full" > "$MODE_FILE"

    # [8] 验证配置
    if ! validate_config; then
        install_rollback; return
    fi

    # [9] 安装 sproxy 服务并启动
    install_sproxy_service
    systemctl start sproxy
    info "sproxy 已启动"

    # [10] 安装证书 reload cron
    ( { crontab -l 2>/dev/null || true; } | grep -v 'systemctl reload sproxy' || true; echo "0 3 * * * systemctl reload sproxy 2>/dev/null || true") | crontab -

    # [11] UFW
    ufw allow 443/tcp >/dev/null 2>&1 || true
    ufw allow "${CADDY_HTTPS_PORT}/tcp" >/dev/null 2>&1 || true
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ufw allow "${SS_PORT}/tcp" >/dev/null 2>&1 || true
    ufw allow "${SS_PORT}/udp" >/dev/null 2>&1 || true
    info "UFW 已放行端口 443, ${CADDY_HTTPS_PORT}, 80, ${SS_PORT}"

    trap - ERR

    # [12] 验证服务
    echo ""
    echo "等待服务启动..."
    sleep 3
    local all_ok=true
    for name in sproxy caddy; do
        if systemctl is-active --quiet "$name"; then
            info "$name 运行中"
        else
            error "$name 未运行！"
            all_ok=false
        fi
    done
    if docker ps --format '{{.Names}}' | grep -qw fake-site; then
        info "fake-site 运行中"
    else
        error "fake-site 未运行！"
        all_ok=false
    fi

    # [13] 输出结果
    local pub_ip; pub_ip=$(get_public_ip)
    echo ""
    echo -e "${BOLD}${GREEN}════════ 安装完成 ════════${NC}"
    echo ""
    echo -e "${BOLD}=== VLESS+REALITY ===${NC}"
    echo -e "${CYAN}[smart]${NC}"
    gen_vless_link "$smart_uuid" "smart" "$pub_ip"
    echo ""
    echo -e "${BOLD}=== SS2022 ===${NC}"
    echo -e "${CYAN}[ss-smart]${NC}"
    gen_ss2022_link "$ss_smart_key" "ss-smart" "$pub_ip"
    echo ""
    info "Hysteria2 默认未启用，可在菜单中手动开启"
    echo ""
    if [[ "$all_ok" == "false" ]]; then
        warn "部分服务未正常启动，请检查 journalctl -u sproxy / journalctl -u caddy"
    fi
    press_enter
}

# ═══════════════════════════════════════════════════
#  分享链接生成
# ═══════════════════════════════════════════════════
gen_vless_link() {
    local uuid="$1" name="$2" server="$3"
    local node fqdn pbk sid label
    node=$(get_node); fqdn=$(get_fqdn); pbk=$(get_public_key); sid=$(get_short_id)
    label=$(echo "${node}-${name}" | tr '[:lower:]' '[:upper:]')
    echo "vless://${uuid}@${server}:443?type=tcp&security=reality&sni=${fqdn}&fp=chrome&pbk=${pbk}&sid=${sid}&flow=xtls-rprx-vision#${label}"
}

gen_hy2_link() {
    local password="$1" name="$2" server="$3"
    local node fqdn label hy2_port
    node=$(get_node); fqdn=$(get_fqdn)
    hy2_port=$(meta_get "hy2_port")
    label=$(echo "${node}-${name}" | tr '[:lower:]' '[:upper:]')
    echo "hysteria2://${password}@${server}:${hy2_port}?sni=${fqdn}&alpn=h3#${label}"
}

gen_ss2022_link() {
    local user_key="$1" name="$2" server="$3"
    local node server_key method userinfo label ss_port
    node=$(get_node)
    server_key=$(jq -r '.inbounds[] | select(.tag=="ss2022") | .password' "$CONF_FILE")
    method=$(jq -r '.inbounds[] | select(.tag=="ss2022") | .method' "$CONF_FILE")
    ss_port=$(jq -r '.inbounds[] | select(.tag=="ss2022") | .listen_port' "$CONF_FILE")
    userinfo=$(base64url_encode "${method}:${server_key}:${user_key}")
    label=$(echo "${node}-${name}" | tr '[:lower:]' '[:upper:]')
    echo "ss://${userinfo}@${server}:${ss_port}#${label}"
}

# ═══════════════════════════════════════════════════
#  UFW 端口清理（含 per-IP 规则）
# ═══════════════════════════════════════════════════
ufw_clean_port() {
    local port="$1"
    command -v ufw &>/dev/null || return 0
    ufw delete --force allow "$port/tcp" 2>/dev/null || true
    ufw delete --force allow "$port/udp" 2>/dev/null || true
    while ufw status numbered | grep -qE "\\b${port}/(tcp|udp)\\b"; do
        local num
        num=$(ufw status numbered | grep -E "\\b${port}/(tcp|udp)\\b" | head -1 | grep -oE '^\[ *[0-9]+\]' | tr -dc '0-9')
        [[ -z "$num" ]] && break
        yes | ufw delete "$num" >/dev/null 2>&1 || break
    done
}

# ═══════════════════════════════════════════════════
#  SS 端口 IP 白名单（UFW）
# ═══════════════════════════════════════════════════
apply_ss_whitelist() {
    local port="$1"
    if ! command -v ufw &>/dev/null; then
        warn "ufw 未安装，跳过防火墙配置"
        return 0
    fi
    # 先清除该端口所有规则
    ufw delete --force allow "$port/tcp" 2>/dev/null || true
    ufw delete --force allow "$port/udp" 2>/dev/null || true
    # 清除已有的 per-IP 规则
    while ufw status numbered | grep -qE "\\b${port}/(tcp|udp)\\b"; do
        local num
        num=$(ufw status numbered | grep -E "\\b${port}/(tcp|udp)\\b" | head -1 | grep -oE '^\[ *[0-9]+\]' | tr -dc '0-9')
        [[ -z "$num" ]] && break
        yes | ufw delete "$num" >/dev/null 2>&1 || break
    done

    if [[ -f "$SS_WHITELIST_FILE" ]] && [[ -s "$SS_WHITELIST_FILE" ]]; then
        while IFS= read -r ip; do
            [[ -z "$ip" || "$ip" == \#* ]] && continue
            ufw allow from "$ip" to any port "$port" proto tcp >/dev/null 2>&1 || true
            ufw allow from "$ip" to any port "$port" proto udp >/dev/null 2>&1 || true
        done < "$SS_WHITELIST_FILE"
        info "白名单已应用 ($(wc -l < "$SS_WHITELIST_FILE" | tr -d ' ') 条规则)"
    else
        ufw allow "$port/tcp" >/dev/null 2>&1 || true
        ufw allow "$port/udp" >/dev/null 2>&1 || true
        info "端口 $port 已全开放"
    fi
}

show_ss_whitelist_menu() {
    local port="$1"
    while true; do
        title "SS 端口 IP 白名单 (端口 $port)"
        if [[ -f "$SS_WHITELIST_FILE" ]] && [[ -s "$SS_WHITELIST_FILE" ]]; then
            echo "当前白名单:"
            local i=1
            while IFS= read -r ip; do
                [[ -z "$ip" || "$ip" == \#* ]] && continue
                printf "  [%d] %s\n" "$i" "$ip"
                ((i++))
            done < "$SS_WHITELIST_FILE"
        else
            echo -e "  白名单: ${YELLOW}未启用 (全开放)${NC}"
        fi
        echo ""
        echo "  a) 添加 IP    d) 删除 IP    c) 清空白名单 (恢复全开放)    0) 返回"
        echo ""
        read -rp "请选择: " choice
        case "$choice" in
            a)
                read -rp "输入 IP 地址 (如 1.2.3.4): " new_ip
                [[ -z "$new_ip" ]] && { warn "IP 不能为空"; continue; }
                if ! [[ "$new_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
                    warn "IP 格式无效"; continue
                fi
                echo "$new_ip" >> "$SS_WHITELIST_FILE"
                apply_ss_whitelist "$port"
                ;;
            d)
                [[ ! -s "$SS_WHITELIST_FILE" ]] && { warn "白名单为空"; continue; }
                local ips=()
                while IFS= read -r ip; do
                    [[ -z "$ip" || "$ip" == \#* ]] && continue
                    ips+=("$ip")
                done < "$SS_WHITELIST_FILE"
                read -rp "选择要删除的编号 [1-${#ips[@]}]: " idx
                [[ "$idx" =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= ${#ips[@]} )) || { warn "无效编号"; continue; }
                local del_ip="${ips[$((idx-1))]}"
                grep -vxF "$del_ip" "$SS_WHITELIST_FILE" > "${SS_WHITELIST_FILE}.tmp" || true
                mv -f "${SS_WHITELIST_FILE}.tmp" "$SS_WHITELIST_FILE"
                apply_ss_whitelist "$port"
                ;;
            c)
                rm -f "$SS_WHITELIST_FILE"
                apply_ss_whitelist "$port"
                ;;
            0) return ;;
            *) warn "无效选项" ;;
        esac
    done
}

# ═══════════════════════════════════════════════════
#  Hysteria2 管理（完整模式，开关型设置）
# ═══════════════════════════════════════════════════
has_hy2() {
    jq -e '.inbounds[] | select(.tag=="hy2")' "$CONF_FILE" >/dev/null 2>&1
}

hy2_enable() {
    local fqdn; fqdn=$(get_fqdn)
    local cert_dir
    cert_dir=$(find_caddy_cert "$fqdn" 2>/dev/null || true)
    if [[ -z "$cert_dir" ]]; then
        error "证书未就绪 (${fqdn})，无法启用 Hysteria2"
        warn "请确认 Caddy 已正常运行并签发证书"
        press_enter; return
    fi
    info "证书已就绪: $cert_dir"

    check_port_available "$HY2_PORT" udp || { press_enter; return; }

    # 收集现有节点，为每个生成 hy2 密码
    local users_json="[]"
    while read -r name; do
        local pw; pw=$(openssl rand -base64 16)
        users_json=$(jq --arg n "$name" --arg pw "$pw" '. += [{name:$n,password:$pw}]' <<< "$users_json")
    done < <(list_nodes)

    # 构建 HY2 inbound
    local hy2_inbound
    hy2_inbound=$(jq -n \
      --argjson users "$users_json" \
      --arg cert_crt "${cert_dir}/${fqdn}.crt" \
      --arg cert_key "${cert_dir}/${fqdn}.key" \
      --argjson hy2_port "$HY2_PORT" \
      --argjson caddy_port "$CADDY_HTTPS_PORT" \
      '{
        type: "hysteria2", tag: "hy2", listen: "::", listen_port: $hy2_port,
        users: $users,
        tls: { enabled: true, alpn: ["h3"], certificate_path: $cert_crt, key_path: $cert_key },
        masquerade: ("https://127.0.0.1:" + ($caddy_port | tostring))
      }')

    update_config '.inbounds += [$ib]' --argjson ib "$hy2_inbound"

    # 更新 meta
    if jq --argjson p "$HY2_PORT" '.hy2_port = $p' "$META_FILE" > "${META_FILE}.tmp"; then
        mv -f "${META_FILE}.tmp" "$META_FILE"
    fi

    ufw allow "${HY2_PORT}/udp" >/dev/null 2>&1 || true
    restart_sproxy || { press_enter; return; }

    echo ""
    info "Hysteria2 已启用 (端口 ${HY2_PORT}/UDP)"
    echo ""
    local pub_ip; pub_ip=$(get_public_ip)
    echo -e "${BOLD}HY2 链接:${NC}"
    while read -r name; do
        local pw
        pw=$(jq -r --arg n "$name" '.inbounds[] | select(.tag=="hy2") | .users[] | select(.name==$n) | .password' "$CONF_FILE")
        echo -e "${CYAN}[$name]${NC}"
        gen_hy2_link "$pw" "$name" "$pub_ip"
    done < <(list_nodes)
    press_enter
}

hy2_disable() {
    read -rp "确认关闭 Hysteria2？[y/N]: " confirm
    [[ "$confirm" =~ ^[yY] ]] || return
    update_config '.inbounds |= map(select(.tag != "hy2"))'
    ufw delete --force allow "${HY2_PORT}/udp" 2>/dev/null || true
    if jq 'del(.hy2_port)' "$META_FILE" > "${META_FILE}.tmp"; then
        mv -f "${META_FILE}.tmp" "$META_FILE"
    fi
    restart_sproxy
    info "Hysteria2 已关闭"
    press_enter
}

show_hy2_menu() {
    ensure_installed || return
    title "Hysteria2 管理"
    if has_hy2; then
        local hy2_port
        hy2_port=$(jq -r '.inbounds[] | select(.tag=="hy2") | .listen_port' "$CONF_FILE")
        echo -e "  状态: ${GREEN}已启用${NC}  端口: ${BOLD}${hy2_port}/UDP${NC}"
        echo ""
        echo "  1) 查看链接"
        echo "  2) 关闭"
        echo "  0) 返回"
        echo ""
        read -rp "请选择: " choice
        case "$choice" in
            1)
                echo ""
                local pub_ip; pub_ip=$(get_public_ip)
                while read -r name; do
                    local pw
                    pw=$(jq -r --arg n "$name" '.inbounds[] | select(.tag=="hy2") | .users[] | select(.name==$n) | .password' "$CONF_FILE")
                    echo -e "${CYAN}[$name]${NC}"
                    gen_hy2_link "$pw" "$name" "$pub_ip"
                done < <(list_nodes)
                press_enter
                ;;
            2) hy2_disable ;;
            0) return ;;
            *) warn "无效选项" ;;
        esac
    else
        echo -e "  状态: ${YELLOW}未启用${NC}"
        echo ""
        echo "  1) 启用"
        echo "  0) 返回"
        echo ""
        read -rp "请选择: " choice
        case "$choice" in
            1) hy2_enable ;;
            0) return ;;
            *) warn "无效选项" ;;
        esac
    fi
}

# ═══════════════════════════════════════════════════
#  Shadowsocks 管理（完整模式可选）
# ═══════════════════════════════════════════════════
has_legacy_ss() {
    jq -e '.inbounds[] | select(.tag=="ss-legacy")' "$CONF_FILE" >/dev/null 2>&1
}

gen_legacy_ss_link() {
    local ip="$1"
    local method password port node label userinfo
    method=$(jq -r '.inbounds[] | select(.tag=="ss-legacy") | .method' "$CONF_FILE")
    password=$(jq -r '.inbounds[] | select(.tag=="ss-legacy") | .password' "$CONF_FILE")
    port=$(jq -r '.inbounds[] | select(.tag=="ss-legacy") | .listen_port' "$CONF_FILE")
    node=$(get_node)
    userinfo=$(printf '%s' "${method}:${password}" | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')
    label=$(echo "${node}-SS-LEGACY" | tr '[:lower:]' '[:upper:]')
    echo "ss://${userinfo}@${ip}:${port}#${label}"
}

show_legacy_ss_menu() {
    ensure_installed || return
    while true; do
        title "Shadowsocks 管理"
        if has_legacy_ss; then
            local method port
            method=$(jq -r '.inbounds[] | select(.tag=="ss-legacy") | .method' "$CONF_FILE")
            port=$(jq -r '.inbounds[] | select(.tag=="ss-legacy") | .listen_port' "$CONF_FILE")
            echo -e "  状态: ${GREEN}已开启${NC}  端口: ${BOLD}${port}${NC}  加密: ${BOLD}${method}${NC}"
            echo ""
            echo "  1) 查看链接"
            echo "  2) 重置密码"
            echo "  3) IP 白名单"
            echo "  4) 关闭"
        else
            echo -e "  状态: ${YELLOW}未开启${NC}"
            echo ""
            echo "  1) 开启"
        fi
        echo "  0) 返回"
        echo ""
        read -rp "请选择: " choice
        if has_legacy_ss; then
            case "$choice" in
                1) echo ""; local pub_ip; pub_ip=$(get_public_ip); gen_legacy_ss_link "$pub_ip"; press_enter ;;
                2) legacy_ss_reset ;;
                3) show_ss_whitelist_menu "$port" ;;
                4) legacy_ss_disable ;;
                0) return ;;
                *) warn "无效选项" ;;
            esac
        else
            case "$choice" in
                1) legacy_ss_enable ;;
                0) return ;;
                *) warn "无效选项" ;;
            esac
        fi
    done
}

legacy_ss_enable() {
    echo ""
    echo "加密方式:"
    echo "  1) aes-128-gcm (推荐，x86 硬件加速)"
    echo "  2) chacha20-ietf-poly1305 (ARM 推荐)"
    echo ""
    read -rp "请选择 [1]: " enc_choice
    local method
    case "${enc_choice:-1}" in
        1|"") method="aes-128-gcm" ;;
        2) method="chacha20-ietf-poly1305" ;;
        *) method="$DEFAULT_SS_METHOD" ;;
    esac
    local port
    read -rp "监听端口 [${LEGACY_SS_PORT}]: " port
    port=${port:-$LEGACY_SS_PORT}
    [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) || { error "端口无效"; press_enter; return; }
    check_port_available "$port" || { press_enter; return; }
    check_port_available "$port" udp || { press_enter; return; }

    local password
    password=$(openssl rand -base64 16)

    update_config '.inbounds += [$ib]' --argjson ib "$(jq -n \
        --arg method "$method" --arg pw "$password" --argjson port "$port" \
        '{type:"shadowsocks",tag:"ss-legacy",listen:"::",listen_port:$port,method:$method,password:$pw}')"
    # 封禁大陆来源 IP（仅 ss-legacy）
    update_config '.route.rules += [$r]' --argjson r '{"inbound":["ss-legacy"],"rule_set":"geoip-cn","rule_set_ip_cidr_match_source":true,"action":"block"}'
    apply_ss_whitelist "$port"
    restart_sproxy || { press_enter; return; }

    echo ""
    local pub_ip; pub_ip=$(get_public_ip)
    info "Shadowsocks 已开启"
    echo -e "${BOLD}SS 链接:${NC}"
    gen_legacy_ss_link "$pub_ip"
    press_enter
}

legacy_ss_disable() {
    local port
    port=$(jq -r '.inbounds[] | select(.tag=="ss-legacy") | .listen_port' "$CONF_FILE")
    read -rp "确认关闭？[y/N]: " confirm
    [[ "$confirm" =~ ^[yY] ]] || return
    update_config '.inbounds |= map(select(.tag != "ss-legacy")) | .route.rules |= map(select(.inbound != ["ss-legacy"]))'
    ufw_clean_port "$port"
    restart_sproxy
    info "Shadowsocks 已关闭"
    press_enter
}

legacy_ss_reset() {
    local password
    password=$(openssl rand -base64 16)
    update_config '(.inbounds[] | select(.tag=="ss-legacy")).password = $pw' --arg pw "$password"
    restart_sproxy || { press_enter; return; }
    echo ""
    local pub_ip; pub_ip=$(get_public_ip)
    info "密码已重置"
    echo -e "${BOLD}新 SS 链接:${NC}"
    gen_legacy_ss_link "$pub_ip"
    press_enter
}

# ═══════════════════════════════════════════════════
#  出站管理（仅完整模式）
# ═══════════════════════════════════════════════════
list_outbounds() {
    jq -r '.outbounds[] | "\(.tag)\t\(.type)\t\(if .type=="shadowsocks" then "\(.server):\(.server_port)" else "-" end)"' "$CONF_FILE" 2>/dev/null
}

outbound_exists() {
    local tag="$1"
    jq -e --arg t "$tag" '[.outbounds[].tag] | index($t) != null' "$CONF_FILE" >/dev/null 2>&1
}

show_outbound_menu() {
    ensure_installed || return
    while true; do
        title "出站管理"
        echo "当前出站:"
        local i=1
        while IFS=$'\t' read -r tag proto dest; do
            printf "  [%d] %-14s (%s" "$i" "$tag" "$proto"
            [[ "$dest" != "-" ]] && printf " → %s" "$dest"
            echo ")"
            ((i++))
        done < <(list_outbounds)
        echo ""
        echo "  a) 添加出站    d) 删除出站    0) 返回"
        echo ""
        read -rp "请选择: " choice
        case "$choice" in
            a) add_outbound ;; d) delete_outbound ;; 0) return ;; *) warn "无效选项" ;;
        esac
    done
}

add_outbound() {
    title "添加出站"
    echo "出站类型:"
    echo "  1) direct (自由出站)"
    echo "  2) shadowsocks (链式转发到落地服务器)"
    echo ""
    read -rp "请选择 [1-2]: " otype

    local tag
    read -rp "Tag 名称 (如 chain-us): " tag
    [[ -z "$tag" ]] && { error "Tag 不能为空"; press_enter; return; }
    outbound_exists "$tag" && { error "出站 $tag 已存在"; press_enter; return; }

    case "$otype" in
        1)
            update_config '.outbounds += [{type:"direct",tag:$tag}]' --arg tag "$tag"
            info "出站 $tag (direct) 已添加"
            ;;
        2)
            local addr port method key ss_mode
            echo ""
            echo "  1) 粘贴 SS 链接（自动解析）"
            echo "  2) 手动输入"
            echo ""
            read -rp "请选择 [1-2]: " ss_mode
            case "$ss_mode" in
                1)
                    local ss_link
                    read -rp "SS 链接: " ss_link
                    [[ ! "$ss_link" =~ ^ss:// ]] && { error "无效的 SS 链接格式"; press_enter; return; }
                    if ! parse_ss_link "$ss_link"; then
                        error "SS 链接解析失败"; press_enter; return
                    fi
                    addr="$SS_PARSED_ADDR"; port="$SS_PARSED_PORT"
                    method="$SS_PARSED_METHOD"; key="$SS_PARSED_PASSWORD"
                    echo ""
                    info "解析结果: ${addr}:${port} ($method)"
                    read -rp "确认添加？[Y/n]: " confirm
                    [[ "$confirm" =~ ^[Nn] ]] && return
                    ;;
                2)
                    read -rp "落地服务器 IP: " addr
                    read -rp "端口 [59875]: " port; port=${port:-59875}
                    read -rp "加密方式 [aes-128-gcm]: " method; method=${method:-aes-128-gcm}
                    read -rp "密码: " key
                    ;;
                *) warn "无效选项"; return ;;
            esac
            [[ -z "$addr" || -z "$key" ]] && { error "地址和密码不能为空"; press_enter; return; }
            [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) || { error "端口无效"; press_enter; return; }

            local ob_json
            ob_json=$(jq -n --arg tag "$tag" --arg addr "$addr" --argjson port "$port" --arg method "$method" --arg key "$key" \
                '{type:"shadowsocks",tag:$tag,server:$addr,server_port:$port,method:$method,password:$key}')
            update_config '.outbounds += [$ob]' --argjson ob "$ob_json"
            info "出站 $tag (shadowsocks → ${addr}:${port}) 已添加"
            ;;
        *) warn "无效选项"; return ;;
    esac
    restart_sproxy
    press_enter
}

delete_outbound() {
    title "删除出站"
    local tags=()
    while IFS=$'\t' read -r tag proto dest; do
        [[ "$tag" == "direct" || "$tag" == "block" ]] && continue
        tags+=("$tag")
    done < <(list_outbounds)

    [[ ${#tags[@]} -eq 0 ]] && { echo "  (没有可删除的出站)"; press_enter; return; }

    echo "可删除的出站:"
    local i=1
    for tag in "${tags[@]}"; do
        printf "  [%d] %s\n" "$i" "$tag"
        ((i++))
    done
    echo ""
    read -rp "选择要删除的编号: " idx
    [[ "$idx" =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= ${#tags[@]} )) || { warn "无效编号"; press_enter; return; }

    local del_tag="${tags[$((idx-1))]}"

    # 检查自定义路由引用
    local custom_refs=""
    if [[ -f "$CUSTOM_RULES_FILE" ]]; then
        custom_refs=$(jq -r --arg t "$del_tag" '.[] | select(.outbound==$t) | keys[0] + ": " + (.[keys[0]] | if type=="array" then join(", ") else tostring end)' "$CUSTOM_RULES_FILE" 2>/dev/null || true)
    fi

    # 检查 auth_user 路由引用
    local user_refs
    user_refs=$(jq -r --arg t "$del_tag" '.route.rules[] | select(.auth_user and .outbound==$t) | .auth_user[]' "$CONF_FILE" 2>/dev/null || true)

    if [[ -n "$custom_refs" || -n "$user_refs" ]]; then
        warn "以下规则引用了出站 $del_tag:"
        [[ -n "$user_refs" ]] && echo "$user_refs" | while read -r u; do echo "  - 用户路由: $u"; done
        [[ -n "$custom_refs" ]] && echo "$custom_refs" | while read -r r; do echo "  - 自定义路由: $r"; done
        read -rp "删除出站将同时删除相关规则。继续？[y/N]: " confirm
        [[ "$confirm" =~ ^[yY] ]] || return
    else
        read -rp "确认删除出站 $del_tag？[y/N]: " confirm
        [[ "$confirm" =~ ^[yY] ]] || return
    fi

    update_config '
      .route.rules |= map(select(.outbound != $tag or (.auth_user | not))) |
      .outbounds |= map(select(.tag != $tag))
    ' --arg tag "$del_tag"
    # 删除自定义路由中引用此出站的
    if [[ -f "$CUSTOM_RULES_FILE" ]]; then
        local tmp; tmp=$(mktemp "${CUSTOM_RULES_FILE}.XXXXXX")
        jq --arg t "$del_tag" 'map(select(.outbound != $t))' "$CUSTOM_RULES_FILE" > "$tmp" && mv -f "$tmp" "$CUSTOM_RULES_FILE"
    fi
    rebuild_route_rules

    info "出站 $del_tag 已删除"
    restart_sproxy
    press_enter
}

# ═══════════════════════════════════════════════════
#  节点管理（三协议联动，仅完整模式）
# ═══════════════════════════════════════════════════
list_nodes() {
    jq -r '.inbounds[] | select(.tag=="vless-reality") | .users[].name' "$CONF_FILE" 2>/dev/null
}

get_node_outbound() {
    local name="$1"
    [[ "$name" == "smart" ]] && { echo "smart 路由 (自定义规则)"; return; }
    local out
    out=$(jq -r --arg n "$name" --arg sn "ss-$name" \
      '.route.rules[] | select(.auth_user and ((.auth_user | index($n)) or (.auth_user | index($sn)))) | .outbound' \
      "$CONF_FILE" 2>/dev/null || true)
    echo "${out:-direct (默认)}"
}

show_node_menu() {
    ensure_installed || return
    while true; do
        title "节点管理 (三协议联动)"
        echo "当前节点:"
        local i=1
        while read -r name; do
            local out; out=$(get_node_outbound "$name")
            if [[ "$name" == "smart" ]]; then
                printf "  [%d] %-12s → %s    ← 不可删除\n" "$i" "$name" "$out"
            else
                printf "  [%d] %-12s → %s\n" "$i" "$name" "$out"
            fi
            ((i++))
        done < <(list_nodes)
        echo ""
        echo "  a) 添加节点    d) 删除节点    0) 返回"
        echo ""
        read -rp "请选择: " choice
        case "$choice" in
            a) add_node ;; d) delete_node ;; 0) return ;; *) warn "无效选项" ;;
        esac
    done
}

add_node() {
    title "添加节点"
    local name
    read -rp "节点名称 (如 us, jp): " name
    name=$(echo "$name" | tr '[:upper:]' '[:lower:]')
    [[ -z "$name" ]] && { error "名称不能为空"; press_enter; return; }
    [[ "$name" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || { error "名称格式无效"; press_enter; return; }

    # 检查是否已存在
    jq -e --arg n "$name" '.inbounds[] | select(.tag=="vless-reality") | .users[] | select(.name==$n)' "$CONF_FILE" >/dev/null 2>&1 && \
        { error "节点 $name 已存在"; press_enter; return; }

    # 选择出站
    echo ""
    echo "可用出站:"
    local out_tags=() j=1
    while IFS=$'\t' read -r tag proto dest; do
        out_tags+=("$tag")
        printf "  [%d] %s" "$j" "$tag"
        [[ "$dest" != "-" ]] && printf " (%s → %s)" "$proto" "$dest"
        echo ""
        ((j++))
    done < <(list_outbounds)
    echo ""
    read -rp "选择出站 [1-${#out_tags[@]}]: " oidx
    [[ "$oidx" =~ ^[0-9]+$ ]] && (( oidx >= 1 && oidx <= ${#out_tags[@]} )) || { warn "无效编号"; press_enter; return; }
    local out_tag="${out_tags[$((oidx-1))]}"

    # 生成凭证
    local uuid ss_key hy2_pw
    uuid=$("$SINGBOX_BIN" generate uuid)
    ss_key=$(openssl rand -base64 16)
    hy2_pw=$(openssl rand -base64 16)
    local ss_name="ss-${name}"

    update_config '
      (.inbounds[] | select(.tag=="vless-reality")).users += [{uuid:$id,name:$n,flow:"xtls-rprx-vision"}] |
      (.inbounds[] | select(.tag=="hy2")).users += [{name:$n,password:$hy2pw}] |
      (.inbounds[] | select(.tag=="ss2022")).users += [{name:$ssn,password:$sspw}] |
      if $out != "direct" then .route.rules += [{auth_user:[$n,$ssn],outbound:$out}] else . end
    ' --arg id "$uuid" --arg n "$name" --arg hy2pw "$hy2_pw" \
      --arg ssn "$ss_name" --arg sspw "$ss_key" --arg out "$out_tag"
    rebuild_route_rules
    restart_sproxy

    echo ""
    info "节点 $name 已添加 (出站: $out_tag)"
    echo ""
    local pub_ip; pub_ip=$(get_public_ip)
    echo -e "${BOLD}分享链接:${NC}"
    echo -e "${CYAN}[VLESS]${NC}"
    gen_vless_link "$uuid" "$name" "$pub_ip"
    if jq -e '.inbounds[] | select(.tag=="hy2")' "$CONF_FILE" >/dev/null 2>&1; then
        echo -e "${CYAN}[Hysteria2]${NC}"
        gen_hy2_link "$hy2_pw" "$name" "$pub_ip"
    fi
    echo -e "${CYAN}[SS2022]${NC}"
    gen_ss2022_link "$ss_key" "$ss_name" "$pub_ip"
    press_enter
}

delete_node() {
    title "删除节点"
    local names=()
    while read -r name; do
        [[ "$name" == "smart" ]] && continue
        names+=("$name")
    done < <(list_nodes)
    [[ ${#names[@]} -eq 0 ]] && { echo "  (没有可删除的节点)"; press_enter; return; }

    echo "可删除的节点:"
    local i=1
    for name in "${names[@]}"; do
        printf "  [%d] %-12s → %s\n" "$i" "$name" "$(get_node_outbound "$name")"
        ((i++))
    done
    echo ""
    read -rp "选择要删除的编号: " idx
    [[ "$idx" =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= ${#names[@]} )) || { warn "无效编号"; press_enter; return; }

    local del_name="${names[$((idx-1))]}"
    local del_ss="ss-${del_name}"

    read -rp "确认删除节点 $del_name（三个协议）？[y/N]: " confirm
    [[ "$confirm" =~ ^[yY] ]] || return

    update_config '
      (.inbounds[] | select(.tag=="vless-reality")).users |= map(select(.name != $n)) |
      (.inbounds[] | select(.tag=="hy2")).users |= map(select(.name != $n)) |
      (.inbounds[] | select(.tag=="ss2022")).users |= map(select(.name != $sn)) |
      .route.rules |= [.[] | select(if .auth_user then (.auth_user | index($n) or index($sn)) | not else true end)]
    ' --arg n "$del_name" --arg sn "$del_ss"
    rebuild_route_rules
    restart_sproxy
    info "节点 $del_name 已删除"
    press_enter
}

# ═══════════════════════════════════════════════════
#  自定义路由管理（仅完整模式）
# ═══════════════════════════════════════════════════
show_custom_route_menu() {
    ensure_installed || return
    while true; do
        title "自定义路由管理 (仅 smart 用户生效)"
        echo "当前规则:"
        if [[ -f "$CUSTOM_RULES_FILE" ]] && jq -e 'length > 0' "$CUSTOM_RULES_FILE" >/dev/null 2>&1; then
            local i=1
            while IFS= read -r line; do
                printf "  [%d] %s\n" "$i" "$line"
                ((i++))
            done < <(jq -r '.[] | (keys - ["outbound"])[0] as $k | "  \($k): \(.[$k] | if type=="array" then join(", ") else tostring end)  → \(.outbound)"' "$CUSTOM_RULES_FILE" 2>/dev/null)
        else
            echo "  (无自定义规则)"
        fi
        echo ""
        echo "  a) 添加规则    d) 删除规则    e) 手动编辑    v) 验证并应用    0) 返回"
        echo ""
        read -rp "请选择: " choice
        case "$choice" in
            a) add_custom_rule ;; d) delete_custom_rule ;; e) edit_custom_rules ;; v) apply_custom_rules ;; 0) return ;; *) warn "无效选项" ;;
        esac
    done
}

add_custom_rule() {
    title "添加自定义规则"
    echo "规则类型:"
    echo "  1) 域名后缀   (如 .netflix.com)"
    echo "  2) 域名关键词  (如 openai)"
    echo "  3) 完整域名   (如 telegram.org)"
    echo "  4) IP 段      (如 91.108.0.0/16)"
    echo ""
    read -rp "请选择 [1-4]: " rtype

    local key values
    case "$rtype" in
        1) key="domain_suffix"; read -rp "域名后缀 (逗号分隔): " values ;;
        2) key="domain_keyword"; read -rp "域名关键词 (逗号分隔): " values ;;
        3) key="domain"; read -rp "完整域名 (逗号分隔): " values ;;
        4) key="ip_cidr"; read -rp "IP 段 (逗号分隔): " values ;;
        *) warn "无效选项"; return ;;
    esac
    [[ -z "$values" ]] && { error "值不能为空"; press_enter; return; }

    # 选择出站
    echo ""
    echo "可用出站:"
    local out_tags=() j=1
    while IFS=$'\t' read -r tag proto dest; do
        out_tags+=("$tag")
        printf "  [%d] %s" "$j" "$tag"
        [[ "$dest" != "-" ]] && printf " (%s → %s)" "$proto" "$dest"
        echo ""
        ((j++))
    done < <(list_outbounds)
    echo ""
    read -rp "选择出站 [1-${#out_tags[@]}]: " oidx
    [[ "$oidx" =~ ^[0-9]+$ ]] && (( oidx >= 1 && oidx <= ${#out_tags[@]} )) || { warn "无效编号"; press_enter; return; }
    local out_tag="${out_tags[$((oidx-1))]}"

    # 构建 JSON 数组
    local val_json
    val_json=$(echo "$values" | tr ',' '\n' | sed 's/^ *//;s/ *$//' | jq -R . | jq -s .)

    # 写入 custom-rules.json
    [[ ! -f "$CUSTOM_RULES_FILE" ]] && echo '[]' > "$CUSTOM_RULES_FILE"
    local tmp; tmp=$(mktemp "${CUSTOM_RULES_FILE}.XXXXXX")
    jq --arg k "$key" --argjson v "$val_json" --arg out "$out_tag" \
        '. += [{($k): $v, outbound: $out}]' "$CUSTOM_RULES_FILE" > "$tmp" && mv -f "$tmp" "$CUSTOM_RULES_FILE"

    info "规则已添加: $key → $out_tag"
    apply_custom_rules
}

delete_custom_rule() {
    if [[ ! -f "$CUSTOM_RULES_FILE" ]] || ! jq -e 'length > 0' "$CUSTOM_RULES_FILE" >/dev/null 2>&1; then
        echo "  (无自定义规则)"; press_enter; return
    fi
    local count
    count=$(jq 'length' "$CUSTOM_RULES_FILE")
    read -rp "选择要删除的编号 [1-${count}]: " idx
    [[ "$idx" =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= count )) || { warn "无效编号"; press_enter; return; }
    local tmp; tmp=$(mktemp "${CUSTOM_RULES_FILE}.XXXXXX")
    jq --argjson i "$((idx-1))" 'del(.[$i])' "$CUSTOM_RULES_FILE" > "$tmp" && mv -f "$tmp" "$CUSTOM_RULES_FILE"
    info "规则已删除"
    apply_custom_rules
}

edit_custom_rules() {
    [[ ! -f "$CUSTOM_RULES_FILE" ]] && echo '[]' > "$CUSTOM_RULES_FILE"
    local editor="${EDITOR:-vi}"
    "$editor" "$CUSTOM_RULES_FILE"
    if ! jq '.' "$CUSTOM_RULES_FILE" >/dev/null 2>&1; then
        error "JSON 格式无效"; press_enter; return
    fi
    apply_custom_rules
}

apply_custom_rules() {
    # 校验 outbound 存在性
    if [[ -f "$CUSTOM_RULES_FILE" ]] && jq -e 'length > 0' "$CUSTOM_RULES_FILE" >/dev/null 2>&1; then
        local bad
        bad=$(jq -r '.[].outbound' "$CUSTOM_RULES_FILE" | while read -r ob; do
            jq -e --arg t "$ob" '[.outbounds[].tag] | index($t) != null' "$CONF_FILE" >/dev/null 2>&1 || echo "$ob"
        done)
        if [[ -n "$bad" ]]; then
            error "以下出站不存在: $bad"
            press_enter; return
        fi
    fi
    rebuild_route_rules
    if validate_config; then
        restart_sproxy
    else
        error "配置验证失败，请检查规则"
        press_enter
    fi
}

# ═══════════════════════════════════════════════════
#  查看分享链接（仅完整模式）
# ═══════════════════════════════════════════════════
show_links() {
    ensure_installed || return
    title "分享链接"
    echo "  1) VLESS+REALITY"
    echo "  2) Hysteria2"
    echo "  3) SS2022"
    has_legacy_ss && echo "  4) Shadowsocks"
    echo "  0) 全部显示"
    echo ""
    read -rp "请选择: " link_choice
    echo ""

    local pub_ip; pub_ip=$(get_public_ip)
    local show_vless=false show_hy2=false show_ss=false show_legacy=false
    case "$link_choice" in
        1) show_vless=true ;; 2) show_hy2=true ;; 3) show_ss=true ;;
        4) has_legacy_ss && show_legacy=true || { warn "Shadowsocks 未开启"; press_enter; return; } ;;
        0) show_vless=true; show_hy2=true; show_ss=true; has_legacy_ss && show_legacy=true ;;
        *) warn "无效选项"; press_enter; return ;;
    esac

    if [[ "$show_vless" == "true" ]]; then
        echo -e "${BOLD}=== VLESS+REALITY ===${NC}"
        while read -r name; do
            local uuid
            uuid=$(jq -r --arg n "$name" '.inbounds[] | select(.tag=="vless-reality") | .users[] | select(.name==$n) | .uuid' "$CONF_FILE")
            echo -e "${CYAN}[$name]${NC}"
            gen_vless_link "$uuid" "$name" "$pub_ip"
            echo ""
        done < <(list_nodes)
    fi

    if [[ "$show_hy2" == "true" ]]; then
        if jq -e '.inbounds[] | select(.tag=="hy2")' "$CONF_FILE" >/dev/null 2>&1; then
            echo -e "${BOLD}=== Hysteria2 ===${NC}"
            while read -r name; do
                local pw
                pw=$(jq -r --arg n "$name" '.inbounds[] | select(.tag=="hy2") | .users[] | select(.name==$n) | .password' "$CONF_FILE")
                echo -e "${CYAN}[$name]${NC}"
                gen_hy2_link "$pw" "$name" "$pub_ip"
                echo ""
            done < <(list_nodes)
        else
            echo -e "${BOLD}=== Hysteria2 ===${NC}"
            warn "未启用 (证书未就绪)"
            echo ""
        fi
    fi

    if [[ "$show_ss" == "true" ]]; then
        echo -e "${BOLD}=== SS2022 ===${NC}"
        while read -r name; do
            local pw ss_name
            [[ "$name" == "smart" ]] && ss_name="ss-smart" || ss_name="ss-${name}"
            pw=$(jq -r --arg n "$ss_name" '.inbounds[] | select(.tag=="ss2022") | .users[] | select(.name==$n) | .password' "$CONF_FILE")
            echo -e "${CYAN}[$ss_name]${NC}"
            gen_ss2022_link "$pw" "$ss_name" "$pub_ip"
            echo ""
        done < <(list_nodes)
    fi

    if [[ "$show_legacy" == "true" ]]; then
        echo -e "${BOLD}=== Shadowsocks ===${NC}"
        gen_legacy_ss_link "$pub_ip"
        echo ""
    fi

    press_enter
}

# ═══════════════════════════════════════════════════
#  服务管理（仅完整模式）
# ═══════════════════════════════════════════════════
show_service_menu() {
    ensure_installed || return
    while true; do
        title "服务管理"
        echo "服务状态:"
        for name in sproxy caddy; do
            if systemctl is-active --quiet "$name" 2>/dev/null; then
                echo -e "  ${name}\t${GREEN}● running${NC}"
            else
                echo -e "  ${name}\t${RED}● stopped${NC}"
            fi
        done
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -qw fake-site; then
            echo -e "  fake-site\t${GREEN}● running${NC}"
        else
            echo -e "  fake-site\t${RED}● stopped${NC}"
        fi
        echo ""
        echo "  1) 重启 sproxy       4) 重启全部"
        echo "  2) 重启 caddy        5) 查看 sproxy 日志"
        echo "  3) 重启 fake-site    6) 查看 caddy 日志"
        echo "  0) 返回"
        echo ""
        read -rp "请选择: " choice
        case "$choice" in
            1) restart_sproxy; press_enter ;;
            2) if systemctl restart caddy; then info "caddy 已重启"; else error "caddy 重启失败"; fi; press_enter ;;
            3) if cd "$DIR_SITE" && docker compose restart; then info "fake-site 已重启"; else error "fake-site 重启失败"; fi; press_enter ;;
            4)
                restart_sproxy || true
                systemctl restart caddy 2>&1 || true
                cd "$DIR_SITE" && docker compose restart 2>&1 || true
                info "全部服务已重启"
                press_enter
                ;;
            5) journalctl -u sproxy --no-pager -n 50; press_enter ;;
            6) journalctl -u caddy --no-pager -n 50; press_enter ;;
            0) return ;;
            *) warn "无效选项" ;;
        esac
    done
}

# ═══════════════════════════════════════════════════
#  更新管理（仅完整模式）
# ═══════════════════════════════════════════════════
show_update_menu() {
    ensure_installed || return
    title "更新管理"

    local sb_ver caddy_ver
    sb_ver=$("$SINGBOX_BIN" version 2>/dev/null | head -1 || echo "未知")
    caddy_ver=$("$CADDY_BIN" version 2>/dev/null | head -1 | cut -d' ' -f1 || echo "未知")

    echo "当前版本:"
    echo "  sing-box: $sb_ver"
    echo "  Caddy:    $caddy_ver"
    echo ""
    echo "  1) 更新 sing-box (锁定 ${SINGBOX_VERSION_PREFIX}.x)"
    echo "  2) 更新 Caddy"
    echo "  3) 更新 fake-site 镜像"
    echo "  0) 返回"
    echo ""
    read -rp "请选择: " choice

    case "$choice" in
        1)
            download_singbox || { press_enter; return; }
            systemctl restart sproxy && info "sing-box 已更新并重启"
            ;;
        2)
            local has_cf=false
            [[ -f "$DIR_CADDY/.env" ]] && grep -q CF_API_TOKEN "$DIR_CADDY/.env" && has_cf=true
            if [[ "$has_cf" == "true" ]]; then
                download_caddy cf
            else
                download_caddy
            fi
            systemctl restart caddy && info "Caddy 已更新并重启"
            ;;
        3)
            cd "$DIR_SITE" && docker compose pull && docker compose up -d && info "fake-site 已更新"
            ;;
        0) return ;;
        *) warn "无效选项" ;;
    esac
    press_enter
}

# ═══════════════════════════════════════════════════
#  完整模式卸载
# ═══════════════════════════════════════════════════
do_full_uninstall() {
    ensure_installed || return
    title "卸载"

    echo -e "${YELLOW}⚠ 即将删除:${NC}"
    echo "  • sing-box 二进制 + 配置 + systemd 服务"
    echo "  • caddy 二进制 + 配置 + 证书 + systemd 服务"
    echo "  • fake-site 容器"
    echo ""
    read -rp "确认卸载？[y/N]: " confirm
    [[ "$confirm" =~ ^[yY] ]] || return

    echo ""
    systemctl stop sproxy 2>/dev/null || true
    systemctl disable sproxy 2>/dev/null || true
    rm -f /etc/systemd/system/sproxy.service
    info "sproxy 服务已停止并移除"

    systemctl stop caddy 2>/dev/null || true
    systemctl disable caddy 2>/dev/null || true
    rm -f /etc/systemd/system/caddy.service
    info "caddy 服务已停止并移除"

    systemctl daemon-reload 2>/dev/null || true

    if [[ -d "$DIR_SITE" ]]; then
        cd "$DIR_SITE" && docker compose down 2>/dev/null || true
        info "fake-site 容器已停止"
    fi

    # 清理 crontab
    (crontab -l 2>/dev/null | grep -v 'systemctl reload sproxy') | crontab - 2>/dev/null || true

    ufw_clean_port 443
    ufw_clean_port "$CADDY_HTTPS_PORT"
    ufw_clean_port 80
    ufw_clean_port "$SS_PORT"
    # HY2（如果启用过）
    if has_hy2 2>/dev/null; then
        ufw_clean_port "$HY2_PORT"
    fi
    # legacy SS（含 per-IP 白名单规则）
    local legacy_port
    legacy_port=$(jq -r '.inbounds[] | select(.tag=="ss-legacy") | .listen_port' "$CONF_FILE" 2>/dev/null || true)
    if [[ -n "$legacy_port" && "$legacy_port" != "null" ]]; then
        ufw_clean_port "$legacy_port"
    fi
    info "UFW 规则已清理"

    rm -rf "$DIR_BASE" "$DIR_CADDY" "$DIR_SITE"
    info "已删除 $DIR_BASE $DIR_CADDY $DIR_SITE"

    echo ""
    echo -e "${GREEN}✓ 卸载完成${NC}"
    press_enter
}

# ═══════════════════════════════════════════════════
#  使用须知
# ═══════════════════════════════════════════════════
show_usage_info() {
    title "使用须知"
    echo "  sproxy 是基于 sing-box 的统一代理管理脚本"
    echo ""
    echo "  完整模式 (入口机):"
    echo "    • VLESS+REALITY (443/TCP) + Hysteria2 (UDP) + SS2022"
    echo "    • 配套 Caddy (TLS证书+伪装站) + fake-site (Docker)"
    echo "    • 三协议联动用户管理、出站链式转发、自定义路由"
    echo ""
    echo "  轻量模式 (落地机):"
    echo "    • 传统 Shadowsocks，封禁大陆源 IP"
    echo "    • 无额外组件，仅 sing-box"
    echo ""
    echo "  依赖:"
    echo "    完整: curl jq openssl base64 tar unzip ss flock shuf docker"
    echo "    轻量: curl jq openssl base64 tar flock"
    press_enter
}

# ═══════════════════════════════════════════════════
#  菜单
# ═══════════════════════════════════════════════════
show_uninstalled_menu() {
    clear
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════╗"
    echo "║        sproxy 管理面板           ║"
    echo "╚══════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  状态: ${YELLOW}未安装${NC}"
    echo ""
    echo "  1) 完整安装 (入口机: VLESS+REALITY + Hysteria2 + SS2022)"
    echo "  2) 轻量安装 (落地机: Shadowsocks)"
    echo "  3) 使用须知"
    echo ""
    echo "  0) 退出"
    echo ""
    read -rp "请选择 [0-3]: " choice
    echo ""
    case "$choice" in
        1) do_install_full ;;
        2) do_install_lite ;;
        3) show_usage_info ;;
        0) echo "再见！"; exit $RC_EXIT_MENU ;;
        *) warn "无效选项" ;;
    esac
}

show_full_menu() {
    clear
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════╗"
    echo "║      sproxy 管理面板 (完整)      ║"
    echo "╚══════════════════════════════════╝"
    echo -e "${NC}"

    local node_fqdn="unknown"
    is_installed && node_fqdn=$(get_fqdn)
    local status_color="$RED" status_text="已停止"
    if systemctl is-active --quiet sproxy 2>/dev/null; then
        status_color="$GREEN"; status_text="运行中"
    fi
    echo -e "  状态: ${status_color}${status_text}${NC}  节点: ${BOLD}${node_fqdn}${NC}"

    echo ""
    echo "  1) 管理出站 (outbound)"
    echo "  2) 管理节点 (三协议联动)"
    echo "  3) 管理自定义路由"
    echo "  4) 查看分享链接"
    echo "  5) Hysteria2 $(has_hy2 && echo "(已启用)" || echo "(未启用)")"
    echo "  6) Shadowsocks $(has_legacy_ss && echo "(已开启)" || echo "(未开启)")"
    echo "  7) 服务管理"
    echo "  8) 更新管理"
    echo "  9) 卸载"
    echo ""
    echo "  0) 退出"
    echo ""
    read -rp "请选择 [0-9]: " choice
    echo ""
    case "$choice" in
        1) show_outbound_menu ;;
        2) show_node_menu ;;
        3) show_custom_route_menu ;;
        4) show_links ;;
        5) show_hy2_menu ;;
        6) show_legacy_ss_menu ;;
        7) show_service_menu ;;
        8) show_update_menu ;;
        9) do_full_uninstall ;;
        0) echo "再见！"; exit $RC_EXIT_MENU ;;
        *) warn "无效选项" ;;
    esac
}

show_lite_menu() {
    clear
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════╗"
    echo "║      sproxy 管理面板 (轻量)      ║"
    echo "╚══════════════════════════════════╝"
    echo -e "${NC}"

    local status_color="$RED" status_text="已停止"
    if systemctl is-active --quiet sproxy 2>/dev/null; then
        status_color="$GREEN"; status_text="运行中"
    fi
    local port method
    port=$(jq -r '.inbounds[0].listen_port' "$CONF_FILE" 2>/dev/null || echo "?")
    method=$(jq -r '.inbounds[0].method' "$CONF_FILE" 2>/dev/null || echo "?")
    echo -e "  状态: ${status_color}${status_text}${NC}  端口: ${BOLD}${port}${NC}  加密: ${BOLD}${method}${NC}"

    echo ""
    echo "  1) 查看状态"
    echo "  2) 查看链接"
    echo "  3) 重置链接"
    echo "  4) IP 白名单"
    echo "  5) 更新 sing-box"
    echo "  6) 卸载"
    echo ""
    echo "  0) 退出"
    echo ""
    read -rp "请选择 [0-6]: " choice
    echo ""
    case "$choice" in
        1) show_lite_status ;;
        2) show_lite_link ;;
        3) do_lite_reset ;;
        4) show_ss_whitelist_menu "$port" ;;
        5) do_lite_update ;;
        6) do_lite_uninstall ;;
        0) echo "再见！"; exit $RC_EXIT_MENU ;;
        *) warn "无效选项" ;;
    esac
}

# ═══════════════════════════════════════════════════
#  入口
# ═══════════════════════════════════════════════════
check_root
command -v flock &>/dev/null || { error "缺少依赖: flock (apt install util-linux)"; exit 1; }
mkdir -p "$DIR_BASE"
exec 9>"$DIR_BASE/.lock"
flock -n 9 || { error "已有另一个 sproxy 实例在运行"; exit 1; }

while true; do
    rc=0
    MODE=$(get_mode)
    case "$MODE" in
        full) ( show_full_menu ) || rc=$? ;;
        lite) ( show_lite_menu ) || rc=$? ;;
        *)    ( show_uninstalled_menu ) || rc=$? ;;
    esac
    if [[ $rc -eq $RC_EXIT_MENU ]]; then
        exit 0
    elif [[ $rc -ne 0 ]]; then
        press_enter
    fi
done
