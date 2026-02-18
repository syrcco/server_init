#!/usr/bin/env bash
set -euo pipefail

# ═══════ 可配置项 ═══════
DOMAIN="kaemito.com"
SS_PORT=59876
CADDY_HTTPS_PORT=1443
SITE_PORT=8080
SS_METHOD="2022-blake3-aes-128-gcm"

SITE_IMAGE="ghcr.io/syrcco/login_site:latest"

DIR_BASE="/opt/xproxy"
DIR_XRAY="$DIR_BASE/xray"
DIR_CADDY="$DIR_BASE/caddy"
DIR_SITE="$DIR_BASE/fake-site"
# ═══════════════════════

XRAY_BIN="$DIR_XRAY/xray"
CONF_DIR="$DIR_XRAY/conf"
CONF_BASE="$CONF_DIR/00-base.json"
CONF_CUSTOM="$CONF_DIR/10-custom.json"
META_FILE="$DIR_XRAY/.meta.json"
CADDY_BIN="$DIR_CADDY/caddy"
CADDYFILE="$DIR_CADDY/Caddyfile"

XRAY_REPO="XTLS/Xray-core"
CADDY_REPO="caddyserver/caddy"
GEODATA_REPO="Loyalsoldier/v2ray-rules-dat"

# ── 退出码 ──
readonly RC_EXIT_MENU=42

# ── 架构检测 ──
case $(uname -m) in
    amd64|x86_64)   XRAY_ARCH="64";        CADDY_ARCH="amd64" ;;
    aarch64|armv8*)  XRAY_ARCH="arm64-v8a"; CADDY_ARCH="arm64" ;;
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
    for cmd in openssl base64 curl jq unzip ss flock tar shuf; do
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

is_installed() {
    [[ -f "$CONF_BASE" && -f "$META_FILE" && -f "$XRAY_BIN" ]]
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
get_api_port()  { meta_get "api_port"; }

# ── 密钥生成 ──
gen_short_id() { openssl rand -hex 8; }

gen_ss_key() {
    case "$SS_METHOD" in
        *aes-128*) openssl rand -base64 16 ;;
        *aes-256*) openssl rand -base64 32 ;;
        *) error "未知 SS_METHOD=$SS_METHOD"; exit 1 ;;
    esac
}

gen_api_port() { shuf -i 10000-60000 -n 1; }

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
        # IPv6: [addr]:port
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

# ── 分享链接生成 ──
gen_vless_link() {
    local uuid="$1" email="$2"
    local node fqdn pbk sid label
    node=$(get_node); fqdn=$(get_fqdn); pbk=$(get_public_key); sid=$(get_short_id)
    label=$(echo "${node}-${email}" | tr '[:lower:]' '[:upper:]')
    echo "vless://${uuid}@${fqdn}:443?type=tcp&security=reality&sni=${fqdn}&fp=chrome&pbk=${pbk}&sid=${sid}&flow=xtls-rprx-vision#${label}"
}

gen_ss_link() {
    local user_key="$1" email="$2"
    local node fqdn server_key method userinfo label
    node=$(get_node); fqdn=$(get_fqdn)
    server_key=$(jq -r '(.inbounds[] | select(.tag=="ss2022")).settings.password' "$CONF_BASE")
    method="$SS_METHOD"
    userinfo=$(base64url_encode "${method}:${server_key}:${user_key}")
    label=$(echo "${node}-${email}" | tr '[:lower:]' '[:upper:]')
    echo "ss://${userinfo}@${fqdn}:${SS_PORT}#${label}"
}

# ── jq 辅助 ──
update_base() {
    local filter="$1"
    shift
    local tmp
    tmp=$(mktemp "${CONF_BASE}.XXXXXX")
    if jq "$@" "$filter" "$CONF_BASE" > "$tmp"; then
        chmod 600 "$tmp"
        mv -f "$tmp" "$CONF_BASE"
    else
        rm -f "$tmp"
        error "JSON 操作失败"
        return 1
    fi
}

# ── 配置验证 ──
validate_xray_config() {
    if ! "$XRAY_BIN" -test -confdir "$CONF_DIR" >/dev/null 2>&1; then
        error "配置验证失败:"
        "$XRAY_BIN" -test -confdir "$CONF_DIR" 2>&1 | tail -5
        return 1
    fi
}

restart_xray() {
    if validate_xray_config; then
        systemctl restart xray >/dev/null 2>&1 && info "xray 已重启" || error "xray 重启失败"
    else
        error "配置无效，未重启 xray"
        return 1
    fi
}

# ── DNS 解析验证 ──
verify_dns() {
    local fqdn=$1
    local server_ip dns_result
    server_ip=$(curl -4 -s --max-time 10 https://one.one.one.one/cdn-cgi/trace | grep -oP 'ip=\K.*' || true)
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

# ── outbound 是否存在 ──
outbound_exists() {
    local tag="$1" found_in=""
    jq -e --arg t "$tag" '[.outbounds // [] | .[] | .tag] | index($t) != null' "$CONF_BASE" >/dev/null 2>&1 && found_in="base"
    [[ -z "$found_in" && -f "$CONF_CUSTOM" ]] && \
        jq -e --arg t "$tag" '[.outbounds // [] | .[] | .tag] | index($t) != null' "$CONF_CUSTOM" >/dev/null 2>&1 && found_in="custom"
    if [[ "$found_in" == "custom" ]]; then
        warn "出站 $tag 存在于 10-custom.json 中（脚本不管理此文件）"
    fi
    [[ -n "$found_in" ]]
}

# ── 下载函数 ──
download_xray() {
    local ver=${1:-}
    if [[ -z "$ver" ]]; then
        ver=$(curl -s "https://api.github.com/repos/${XRAY_REPO}/releases/latest" | jq -r '.tag_name // empty') || true
        [[ -z "$ver" || "$ver" == "null" ]] && { error "获取 Xray 最新版本失败"; return 1; }
    fi
    info "下载 Xray $ver ..."
    local tmp; tmp=$(mktemp -d)
    curl -L --fail -o "$tmp/xray.zip" \
        "https://github.com/${XRAY_REPO}/releases/download/${ver}/Xray-linux-${XRAY_ARCH}.zip" || { rm -rf "$tmp"; error "下载 Xray 失败"; return 1; }
    mkdir -p "$DIR_XRAY"
    unzip -qo "$tmp/xray.zip" xray geoip.dat geosite.dat -d "$DIR_XRAY"
    chmod +x "$XRAY_BIN"
    rm -rf "$tmp"
    info "Xray $ver 已安装"
}

download_caddy() {
    local ver=${1:-} cf_mode=${2:-}
    if [[ -n "$cf_mode" ]]; then
        info "下载 Caddy (带 cloudflare DNS 插件) ..."
        mkdir -p "$DIR_CADDY"
        curl -L --fail -o "$CADDY_BIN" \
            "https://caddyserver.com/api/download?os=linux&arch=${CADDY_ARCH}&p=github.com/caddy-dns/cloudflare" \
            || { error "下载 Caddy 失败"; return 1; }
    else
        if [[ -z "$ver" ]]; then
            ver=$(curl -s "https://api.github.com/repos/${CADDY_REPO}/releases/latest" | jq -r '.tag_name // empty') || true
            [[ -z "$ver" || "$ver" == "null" ]] && { error "获取 Caddy 最新版本失败"; return 1; }
        fi
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

update_geodata() {
    local base_url="https://github.com/${GEODATA_REPO}/releases/latest/download"
    info "更新 geoip.dat ..."
    curl -L --fail -o "$DIR_XRAY/geoip.dat.tmp" "$base_url/geoip.dat" && \
        mv "$DIR_XRAY/geoip.dat.tmp" "$DIR_XRAY/geoip.dat"
    info "更新 geosite.dat ..."
    curl -L --fail -o "$DIR_XRAY/geosite.dat.tmp" "$base_url/geosite.dat" && \
        mv "$DIR_XRAY/geosite.dat.tmp" "$DIR_XRAY/geosite.dat"
    restart_xray
}

# ── systemd 服务创建 ──
install_xray_service() {
    cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=$XRAY_BIN run -confdir $CONF_DIR
Restart=on-failure
RestartSec=3
RestartPreventExitStatus=23
LimitNOFILE=1048576
LimitNPROC=10000
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
User=root
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable xray >/dev/null 2>&1
}

install_caddy_service() {
    # 创建 caddy 用户
    id caddy &>/dev/null || useradd -r -s /usr/sbin/nologin caddy
    mkdir -p "$DIR_CADDY/data" "$DIR_CADDY/config"
    chown -R caddy:caddy "$DIR_CADDY/data" "$DIR_CADDY/config"
    [[ -f "$DIR_CADDY/.env" ]] && chown caddy:caddy "$DIR_CADDY/.env"

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
LimitNPROC=10000
EnvironmentFile=-$DIR_CADDY/.env
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
User=caddy
Group=caddy
PrivateTmp=true
Environment=XDG_DATA_HOME=$DIR_CADDY/data
Environment=XDG_CONFIG_HOME=$DIR_CADDY/config

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable caddy >/dev/null 2>&1
}

# ── 安装回滚 ──
install_rollback() {
    trap - ERR
    warn "正在回滚安装..."
    systemctl stop xray 2>/dev/null || true
    systemctl stop caddy 2>/dev/null || true
    systemctl disable xray 2>/dev/null || true
    systemctl disable caddy 2>/dev/null || true
    rm -f /etc/systemd/system/xray.service /etc/systemd/system/caddy.service
    systemctl daemon-reload 2>/dev/null || true
    if [[ -d "$DIR_SITE" ]]; then
        cd "$DIR_SITE" && docker compose down 2>/dev/null || true
    fi
    rm -rf "$DIR_BASE"
    ufw delete allow 443/tcp 2>/dev/null || true
    ufw delete allow "${CADDY_HTTPS_PORT}/tcp" 2>/dev/null || true
    ufw delete allow 80/tcp 2>/dev/null || true
    ufw delete allow "${SS_PORT}/tcp" 2>/dev/null || true
    ufw delete allow "${SS_PORT}/udp" 2>/dev/null || true
    error "安装已回滚，请检查上方错误信息"
    press_enter
}

# ═══════════════════════════════════════════════════
#  安装部署
# ═══════════════════════════════════════════════════
do_install() {
    title "安装部署"
    check_deps
    check_docker

    if is_installed; then
        warn "已检测到现有安装 ($DIR_BASE)"
        echo "如需重装，请先卸载。"
        press_enter
        return
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
    echo -e "${BOLD}下载 Xray ...${NC}"
    download_xray

    echo -e "${BOLD}下载 Caddy ...${NC}"
    if [[ -n "$cf_token" ]]; then
        download_caddy "" cf
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
    local x25519_output priv_key pub_key short_id smart_uuid ss_server_key ss_smart_key api_port
    x25519_output=$("$XRAY_BIN" x25519)
    priv_key=$(echo "$x25519_output" | awk 'NR==1{print $NF}')
    pub_key=$(echo "$x25519_output" | awk 'NR==2{print $NF}')
    [[ -z "$priv_key" || -z "$pub_key" ]] && { error "无法解析 x25519 密钥"; install_rollback; return; }
    short_id=$(gen_short_id)
    smart_uuid=$("$XRAY_BIN" uuid)
    [[ -z "$smart_uuid" ]] && { error "无法生成 UUID"; install_rollback; return; }
    ss_server_key=$(gen_ss_key)
    ss_smart_key=$(gen_ss_key)
    api_port=$(gen_api_port)

    # [4] 写入 Xray 配置
    echo -e "${BOLD}写入配置 ...${NC}"
    mkdir -p "$CONF_DIR"

    jq -n \
      --arg priv "$priv_key" \
      --arg fqdn "$fqdn" \
      --arg sid "$short_id" \
      --arg uuid "$smart_uuid" \
      --arg ss_srv "$ss_server_key" \
      --arg ss_usr "$ss_smart_key" \
      --arg ss_method "$SS_METHOD" \
      --argjson caddy_port "$CADDY_HTTPS_PORT" \
      --argjson sport "$SS_PORT" \
      --argjson api_port "$api_port" \
      '{
        "log": { "loglevel": "warning" },
        "api": { "tag": "api", "services": ["HandlerService"] },
        "inbounds": [
          {
            "tag": "api",
            "listen": "127.0.0.1",
            "port": $api_port,
            "protocol": "dokodemo-door",
            "settings": { "address": "127.0.0.1" }
          },
          {
            "tag": "vless-reality",
            "listen": "0.0.0.0",
            "port": 443,
            "protocol": "vless",
            "settings": {
              "clients": [
                { "id": $uuid, "flow": "xtls-rprx-vision", "email": "smart" }
              ],
              "decryption": "none"
            },
            "streamSettings": {
              "network": "tcp",
              "security": "reality",
              "realitySettings": {
                "dest": ("127.0.0.1:" + ($caddy_port | tostring)),
                "serverNames": [$fqdn],
                "privateKey": $priv,
                "shortIds": [$sid]
              }
            },
            "sniffing": {
              "enabled": true,
              "destOverride": ["http", "tls"],
              "routeOnly": true
            }
          },
          {
            "tag": "ss2022",
            "listen": "0.0.0.0",
            "port": $sport,
            "protocol": "shadowsocks",
            "settings": {
              "method": $ss_method,
              "password": $ss_srv,
              "clients": [
                { "password": $ss_usr, "email": "ss-smart" }
              ],
              "network": "tcp,udp"
            },
            "sniffing": {
              "enabled": true,
              "destOverride": ["http", "tls"]
            }
          }
        ],
        "outbounds": [
          { "tag": "direct", "protocol": "freedom" },
          { "tag": "block", "protocol": "blackhole" }
        ],
        "routing": {
          "domainStrategy": "IPIfNonMatch",
          "rules": [
            { "type": "field", "inboundTag": ["api"], "outboundTag": "api" },
            { "type": "field", "protocol": ["bittorrent"], "outboundTag": "block" },
            { "type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block" },
            { "type": "field", "ip": ["geoip:cn"], "outboundTag": "block" },
            { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" }
          ]
        }
      }' > "$CONF_BASE"

    echo '{}' > "$CONF_CUSTOM"
    chmod 600 "$CONF_BASE" "$CONF_CUSTOM"
    chmod 700 "$CONF_DIR"

    # [5] 写入 Caddyfile
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

    # [6] 写入元数据
    jq -n \
      --arg node "$node" \
      --arg domain "$DOMAIN" \
      --arg pbk "$pub_key" \
      --arg sid "$short_id" \
      --argjson sport "$SS_PORT" \
      --argjson api_port "$api_port" \
      '{
        node: $node, domain: $domain,
        reality_public_key: $pbk, short_id: $sid,
        ss_port: $sport, api_port: $api_port,
        installed_at: (now | todate)
      }' > "$META_FILE"
    chmod 600 "$META_FILE"

    # [7] 验证配置
    if ! validate_xray_config; then
        install_rollback
        return
    fi

    # [8] 安装 systemd 服务并启动
    install_xray_service
    install_caddy_service
    systemctl start xray
    systemctl start caddy
    info "xray 已启动"
    info "caddy 已启动"

    # [9] UFW
    ufw allow 443/tcp >/dev/null 2>&1 || true
    ufw allow "${CADDY_HTTPS_PORT}/tcp" >/dev/null 2>&1 || true
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ufw allow "${SS_PORT}/tcp" >/dev/null 2>&1 || true
    ufw allow "${SS_PORT}/udp" >/dev/null 2>&1 || true
    info "UFW 已放行端口 443, ${CADDY_HTTPS_PORT}, 80, ${SS_PORT}"

    trap - ERR

    # [10] 验证
    echo ""
    echo "等待服务启动..."
    sleep 3
    local all_ok=true
    for name in xray caddy; do
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

    # [11] 输出结果
    echo ""
    echo -e "${BOLD}${GREEN}════════ 安装完成 ════════${NC}"
    echo ""
    echo -e "${BOLD}=== VLESS+REALITY ===${NC}"
    echo -e "${CYAN}[smart]${NC}"
    gen_vless_link "$smart_uuid" "smart"
    echo ""
    echo -e "${BOLD}=== SS2022 ===${NC}"
    echo -e "${CYAN}[ss-smart]${NC}"
    gen_ss_link "$ss_smart_key" "ss-smart"
    echo ""
    if [[ "$all_ok" == "false" ]]; then
        warn "部分服务未正常启动，请检查 journalctl -u xray / journalctl -u caddy"
    fi
    press_enter
}

# ═══════════════════════════════════════════════════
#  出站管理
# ═══════════════════════════════════════════════════
list_outbounds() {
    jq -r '.outbounds[] | "\(.tag)\t\(.protocol)\t\(if .settings.servers then (.settings.servers[0] | "\(.address):\(.port)") else "-" end)"' "$CONF_BASE" 2>/dev/null
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
        echo "操作:"
        echo "  a) 添加出站"
        echo "  d) 删除出站"
        echo "  0) 返回主菜单"
        echo ""
        read -rp "请选择: " choice
        case "$choice" in
            a) add_outbound ;;
            d) delete_outbound ;;
            0) return ;;
            *) warn "无效选项" ;;
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
            update_base '.outbounds += [{"tag":$tag,"protocol":"freedom"}]' --arg tag "$tag"
            info "出站 $tag (direct) 已添加"
            ;;
        2)
            local addr port method key ss_mode
            echo ""
            echo "  添加方式:"
            echo "    1) 粘贴 SS 链接（自动解析）"
            echo "    2) 手动输入"
            echo ""
            read -rp "请选择 [1-2]: " ss_mode
            case "$ss_mode" in
                1)
                    local ss_link
                    read -rp "SS 链接: " ss_link
                    [[ ! "$ss_link" =~ ^ss:// ]] && { error "无效的 SS 链接格式"; press_enter; return; }
                    if ! parse_ss_link "$ss_link"; then
                        error "SS 链接解析失败（base64 解码错误）"; press_enter; return
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
                    read -rp "端口 [8388]: " port; port=${port:-8388}
                    read -rp "加密方式 [${SS_METHOD}]: " method; method=${method:-$SS_METHOD}
                    read -rp "密钥: " key
                    ;;
                *) warn "无效选项"; return ;;
            esac
            [[ -z "$addr" || -z "$key" ]] && { error "地址和密钥不能为空"; press_enter; return; }
            [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) || { error "端口无效"; press_enter; return; }

            local ob_json
            ob_json=$(jq -n --arg tag "$tag" --arg addr "$addr" --argjson port "$port" --arg method "$method" --arg key "$key" \
                '{ tag:$tag, protocol:"shadowsocks", settings:{ servers:[{ address:$addr, port:$port, method:$method, password:$key }] } }')
            update_base '.outbounds += [$ob]' --argjson ob "$ob_json"
            info "出站 $tag (shadowsocks → ${addr}:${port}) 已添加"
            ;;
        *) warn "无效选项"; return ;;
    esac
    restart_xray
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

    # 提示关联用户（仅提示）
    local refs
    refs=$(jq -r --arg tag "$del_tag" \
      '.routing.rules[] | select(.outboundTag==$tag) | (.user // [])[]' \
      "$CONF_BASE" 2>/dev/null || true)
    if [[ -n "$refs" ]]; then
        warn "以下用户正在使用此出站:"
        echo "$refs" | while read -r email; do echo "  - $email"; done
        read -rp "删除出站将同时删除相关用户和路由规则。继续？[y/N]: " confirm
        [[ "$confirm" =~ ^[yY] ]] || return
        # 一次性删除：clients + routing rules + outbound
        local emails_json
        emails_json=$(echo "$refs" | jq -R . | jq -s .)
        update_base '
          (.inbounds[] | select(.tag=="vless-reality")).settings.clients |=
            map(select(.email as $e | $emails | index($e) | not)) |
          (.inbounds[] | select(.tag=="ss2022")).settings.clients |=
            map(select(.email as $e | $emails | index($e) | not)) |
          .routing.rules |= map(select(.outboundTag != $tag)) |
          .outbounds |= map(select(.tag != $tag))
        ' --argjson emails "$emails_json" --arg tag "$del_tag"
    else
        read -rp "确认删除出站 $del_tag？[y/N]: " confirm
        [[ "$confirm" =~ ^[yY] ]] || return
        # 无关联用户，仍需删除可能存在的路由规则
        update_base '
          .routing.rules |= map(select(.outboundTag != $tag)) |
          .outbounds |= map(select(.tag != $tag))
        ' --arg tag "$del_tag"
    fi

    info "出站 $del_tag 已删除"
    restart_xray
    press_enter
}

# ═══════════════════════════════════════════════════
#  VLESS 节点管理
# ═══════════════════════════════════════════════════
list_vless_clients() {
    jq -r '(.inbounds[] | select(.tag=="vless-reality")).settings.clients[] | .email' "$CONF_BASE" 2>/dev/null
}

get_vless_outbound() {
    local email="$1"
    [[ "$email" == "smart" ]] && { echo "(smart路由，编辑 10-custom.json)"; return; }
    local out
    out=$(jq -r --arg email "$email" '.routing.rules[] | select(.user and (.user | index($email))) | .outboundTag' "$CONF_BASE" 2>/dev/null || true)
    echo "${out:-direct (默认)}"
}

show_vless_menu() {
    ensure_installed || return
    while true; do
        title "VLESS 节点管理"
        echo "当前节点:"
        local i=1
        while read -r email; do
            local out; out=$(get_vless_outbound "$email")
            if [[ "$email" == "smart" ]]; then
                printf "  [%d] %-12s → %s    ← 不可删除\n" "$i" "$email" "$out"
            else
                printf "  [%d] %-12s → %s\n" "$i" "$email" "$out"
            fi
            ((i++))
        done < <(list_vless_clients)
        echo ""
        echo "  a) 添加节点    d) 删除节点    0) 返回"
        echo ""
        read -rp "请选择: " choice
        case "$choice" in
            a) add_vless ;; d) delete_vless ;; 0) return ;; *) warn "无效选项" ;;
        esac
    done
}

add_vless() {
    title "添加 VLESS 节点"
    local name
    read -rp "节点名称 (如 us, jp, netflix): " name
    name=$(echo "$name" | tr '[:upper:]' '[:lower:]')
    [[ -z "$name" ]] && { error "名称不能为空"; press_enter; return; }
    [[ "$name" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || { error "名称格式无效（仅限小写字母、数字、连字符）"; press_enter; return; }
    jq -e --arg email "$name" '(.inbounds[] | select(.tag=="vless-reality")).settings.clients[] | select(.email==$email)' "$CONF_BASE" >/dev/null 2>&1 && \
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

    local uuid; uuid=$("$XRAY_BIN" uuid)
    update_base '(.inbounds[] | select(.tag=="vless-reality")).settings.clients += [{"id":$id,"flow":"xtls-rprx-vision","email":$email}]' \
        --arg id "$uuid" --arg email "$name"
    [[ "$out_tag" != "direct" ]] && \
        update_base '.routing.rules += [{"type":"field","user":[$user],"outboundTag":$out}]' --arg user "$name" --arg out "$out_tag"

    restart_xray
    echo ""
    info "VLESS 节点 $name 已添加 (出站: $out_tag)"
    echo -e "${BOLD}分享链接:${NC}"
    gen_vless_link "$uuid" "$name"
    press_enter
}

delete_vless() {
    title "删除 VLESS 节点"
    local emails=()
    while read -r email; do
        [[ "$email" == "smart" ]] && continue
        emails+=("$email")
    done < <(list_vless_clients)
    [[ ${#emails[@]} -eq 0 ]] && { echo "  (没有可删除的节点)"; press_enter; return; }

    echo "可删除的节点:"
    local i=1
    for email in "${emails[@]}"; do
        printf "  [%d] %-12s → %s\n" "$i" "$email" "$(get_vless_outbound "$email")"
        ((i++))
    done
    echo ""
    read -rp "选择要删除的编号: " idx
    [[ "$idx" =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= ${#emails[@]} )) || { warn "无效编号"; press_enter; return; }

    local del_email="${emails[$((idx-1))]}"
    update_base '(.inbounds[] | select(.tag=="vless-reality")).settings.clients |= map(select(.email != $email))' --arg email "$del_email"
    update_base '.routing.rules |= map(select((.user // []) | index($email) | not))' --arg email "$del_email"
    restart_xray
    info "VLESS 节点 $del_email 已删除"
    press_enter
}

# ═══════════════════════════════════════════════════
#  SS2022 节点管理
# ═══════════════════════════════════════════════════
list_ss_clients() {
    jq -r '(.inbounds[] | select(.tag=="ss2022")).settings.clients[] | .email' "$CONF_BASE" 2>/dev/null
}

get_ss_outbound() {
    local email="$1"
    [[ "$email" == "ss-smart" ]] && { echo "(smart路由，编辑 10-custom.json)"; return; }
    local out
    out=$(jq -r --arg email "$email" '.routing.rules[] | select(.user and (.user | index($email))) | .outboundTag' "$CONF_BASE" 2>/dev/null || true)
    echo "${out:-direct (默认)}"
}

show_ss_menu() {
    ensure_installed || return
    while true; do
        title "SS2022 节点管理"
        echo "当前节点:"
        local i=1
        while read -r email; do
            local out; out=$(get_ss_outbound "$email")
            if [[ "$email" == "ss-smart" ]]; then
                printf "  [%d] %-14s → %s    ← 不可删除\n" "$i" "$email" "$out"
            else
                printf "  [%d] %-14s → %s\n" "$i" "$email" "$out"
            fi
            ((i++))
        done < <(list_ss_clients)
        echo ""
        echo "  a) 添加节点    d) 删除节点    0) 返回"
        echo ""
        read -rp "请选择: " choice
        case "$choice" in
            a) add_ss ;; d) delete_ss ;; 0) return ;; *) warn "无效选项" ;;
        esac
    done
}

add_ss() {
    title "添加 SS2022 节点"
    local name
    read -rp "节点名称 (如 us, jp): " name
    name=$(echo "$name" | tr '[:upper:]' '[:lower:]')
    [[ -z "$name" ]] && { error "名称不能为空"; press_enter; return; }
    [[ "$name" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || { error "名称格式无效（仅限小写字母、数字、连字符）"; press_enter; return; }
    local email="ss-${name}"
    jq -e --arg email "$email" '(.inbounds[] | select(.tag=="ss2022")).settings.clients[] | select(.email==$email)' "$CONF_BASE" >/dev/null 2>&1 && \
        { error "节点 $email 已存在"; press_enter; return; }

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

    local user_key; user_key=$(gen_ss_key)
    update_base '(.inbounds[] | select(.tag=="ss2022")).settings.clients += [{"password":$pw,"email":$email}]' \
        --arg pw "$user_key" --arg email "$email"
    [[ "$out_tag" != "direct" ]] && \
        update_base '.routing.rules += [{"type":"field","user":[$user],"outboundTag":$out}]' --arg user "$email" --arg out "$out_tag"

    restart_xray
    echo ""
    info "SS2022 节点 $email 已添加 (出站: $out_tag)"
    echo -e "${BOLD}分享链接:${NC}"
    gen_ss_link "$user_key" "$email"
    press_enter
}

delete_ss() {
    title "删除 SS2022 节点"
    local emails=()
    while read -r email; do
        [[ "$email" == "ss-smart" ]] && continue
        emails+=("$email")
    done < <(list_ss_clients)
    [[ ${#emails[@]} -eq 0 ]] && { echo "  (没有可删除的节点)"; press_enter; return; }

    echo "可删除的节点:"
    local i=1
    for email in "${emails[@]}"; do
        printf "  [%d] %-14s → %s\n" "$i" "$email" "$(get_ss_outbound "$email")"
        ((i++))
    done
    echo ""
    read -rp "选择要删除的编号: " idx
    [[ "$idx" =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= ${#emails[@]} )) || { warn "无效编号"; press_enter; return; }

    local del_email="${emails[$((idx-1))]}"
    update_base '(.inbounds[] | select(.tag=="ss2022")).settings.clients |= map(select(.email != $email))' --arg email "$del_email"
    update_base '.routing.rules |= map(select((.user // []) | index($email) | not))' --arg email "$del_email"
    restart_xray
    info "SS2022 节点 $del_email 已删除"
    press_enter
}

# ═══════════════════════════════════════════════════
#  查看分享链接
# ═══════════════════════════════════════════════════
show_links() {
    ensure_installed || return
    title "分享链接"

    echo -e "${BOLD}=== VLESS+REALITY ===${NC}"
    while read -r email; do
        local uuid
        uuid=$(jq -r --arg e "$email" '(.inbounds[] | select(.tag=="vless-reality")).settings.clients[] | select(.email==$e) | .id' "$CONF_BASE")
        echo -e "${CYAN}[$email]${NC}"
        gen_vless_link "$uuid" "$email"
        echo ""
    done < <(list_vless_clients)

    echo -e "${BOLD}=== SS2022 ===${NC}"
    while read -r email; do
        local pw
        pw=$(jq -r --arg e "$email" '(.inbounds[] | select(.tag=="ss2022")).settings.clients[] | select(.email==$e) | .password' "$CONF_BASE")
        echo -e "${CYAN}[$email]${NC}"
        gen_ss_link "$pw" "$email"
        echo ""
    done < <(list_ss_clients)

    press_enter
}

# ═══════════════════════════════════════════════════
#  服务管理
# ═══════════════════════════════════════════════════
show_service_menu() {
    ensure_installed || return
    while true; do
        title "服务管理"

        echo "服务状态:"
        for name in xray caddy; do
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
        echo "  1) 重启 xray        4) 重启全部"
        echo "  2) 重启 caddy       5) 查看 xray 日志"
        echo "  3) 重启 fake-site   6) 查看 caddy 日志"
        echo "  0) 返回主菜单"
        echo ""
        read -rp "请选择: " choice

        case "$choice" in
            1) restart_xray; press_enter ;;
            2) systemctl restart caddy && info "caddy 已重启" || error "caddy 重启失败"; press_enter ;;
            3) cd "$DIR_SITE" && docker compose restart && info "fake-site 已重启" || error "fake-site 重启失败"; press_enter ;;
            4)
                restart_xray || true
                systemctl restart caddy 2>&1 || true
                cd "$DIR_SITE" && docker compose restart 2>&1 || true
                info "全部服务已重启"
                press_enter
                ;;
            5) journalctl -u xray --no-pager -n 50; press_enter ;;
            6) journalctl -u caddy --no-pager -n 50; press_enter ;;
            0) return ;;
            *) warn "无效选项" ;;
        esac
    done
}

# ═══════════════════════════════════════════════════
#  更新
# ═══════════════════════════════════════════════════
show_update_menu() {
    ensure_installed || return
    title "更新管理"

    local xray_ver caddy_ver
    xray_ver=$("$XRAY_BIN" version 2>/dev/null | head -1 || echo "未知")
    caddy_ver=$("$CADDY_BIN" version 2>/dev/null | head -1 | cut -d' ' -f1 || echo "未知")

    echo "当前版本:"
    echo "  Xray:  $xray_ver"
    echo "  Caddy: $caddy_ver"
    echo ""
    echo "  1) 更新 Xray"
    echo "  2) 更新 Caddy"
    echo "  3) 更新 geoip/geosite 路由规则"
    echo "  0) 返回"
    echo ""
    read -rp "请选择: " choice

    case "$choice" in
        1)
            download_xray
            systemctl restart xray && info "Xray 已更新并重启"
            ;;
        2)
            local has_cf=false
            [[ -f "$DIR_CADDY/.env" ]] && grep -q CF_API_TOKEN "$DIR_CADDY/.env" && has_cf=true
            if [[ "$has_cf" == "true" ]]; then
                download_caddy "" cf
            else
                download_caddy
            fi
            systemctl restart caddy && info "Caddy 已更新并重启"
            ;;
        3) update_geodata ;;
        0) return ;;
        *) warn "无效选项" ;;
    esac
    press_enter
}

# ═══════════════════════════════════════════════════
#  卸载
# ═══════════════════════════════════════════════════
do_uninstall() {
    ensure_installed || return
    title "卸载"

    echo -e "${YELLOW}⚠ 即将删除:${NC}"
    echo "  • xray 二进制 + 配置 + 密钥 + systemd 服务"
    echo "  • caddy 二进制 + 配置 + 证书 + systemd 服务"
    echo "  • fake-site 容器"
    echo ""
    read -rp "确认卸载？[y/N]: " confirm
    [[ "$confirm" =~ ^[yY] ]] || return

    echo ""
    systemctl stop xray 2>/dev/null || true
    systemctl disable xray 2>/dev/null || true
    rm -f /etc/systemd/system/xray.service
    info "xray 服务已停止并移除"

    systemctl stop caddy 2>/dev/null || true
    systemctl disable caddy 2>/dev/null || true
    rm -f /etc/systemd/system/caddy.service
    info "caddy 服务已停止并移除"

    systemctl daemon-reload 2>/dev/null || true

    if [[ -d "$DIR_SITE" ]]; then
        cd "$DIR_SITE" && docker compose down 2>/dev/null || true
        info "fake-site 容器已停止"
    fi

    rm -rf "$DIR_BASE"
    info "已删除 $DIR_BASE"

    ufw delete allow 443/tcp 2>/dev/null || true
    ufw delete allow "${CADDY_HTTPS_PORT}/tcp" 2>/dev/null || true
    ufw delete allow 80/tcp 2>/dev/null || true
    ufw delete allow "${SS_PORT}/tcp" 2>/dev/null || true
    ufw delete allow "${SS_PORT}/udp" 2>/dev/null || true
    info "UFW 规则已清理"

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
    echo "║       xproxy v2 管理面板        ║"
    echo "╚══════════════════════════════════╝"
    echo -e "${NC}"

    if is_installed; then
        local node; node=$(get_node)
        echo -e "  状态: ${GREEN}已安装${NC}  节点: ${BOLD}${node}.${DOMAIN}${NC}"
    else
        echo -e "  状态: ${YELLOW}未安装${NC}"
    fi

    echo ""
    echo "  1) 安装部署"
    echo "  2) 管理出站 (outbound)"
    echo "  3) 管理 VLESS 节点"
    echo "  4) 管理 SS2022 节点"
    echo "  5) 查看分享链接"
    echo "  6) 服务管理"
    echo "  7) 更新管理"
    echo "  8) 卸载"
    echo ""
    echo "  0) 退出"
    echo ""
    read -rp "请选择 [0-8]: " choice
    echo ""
    case "$choice" in
        1) do_install ;;
        2) show_outbound_menu ;;
        3) show_vless_menu ;;
        4) show_ss_menu ;;
        5) show_links ;;
        6) show_service_menu ;;
        7) show_update_menu ;;
        8) do_uninstall ;;
        0) echo "再见！"; exit $RC_EXIT_MENU ;;
        *) warn "无效选项" ;;
    esac
}

# ── 入口 ──
check_root
command -v flock &>/dev/null || { error "缺少依赖: flock (apt install util-linux)"; exit 1; }
mkdir -p "$DIR_BASE"
exec 9>"$DIR_BASE/.lock"
flock -n 9 || { error "已有另一个 xproxy 实例在运行"; exit 1; }

while true; do
    rc=0
    ( show_main_menu ) || rc=$?
    if [[ $rc -eq $RC_EXIT_MENU ]]; then
        exit 0
    elif [[ $rc -ne 0 ]]; then
        press_enter
    fi
done
