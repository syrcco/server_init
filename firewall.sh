#!/usr/bin/env bash
set -euo pipefail

# =========================
# Config (override via env)
# =========================
# 允许哪些“对主机入站”的 TCP 端口（默认：从 sshd_config 自动识别 SSH 端口 + 80/443）
EXTRA_INPUT_TCP_PORTS="${EXTRA_INPUT_TCP_PORTS:-}"   # 例如：EXTRA_INPUT_TCP_PORTS="25 8443"
UFW_RESET="${UFW_RESET:-1}"                          # 1=清空 ufw 规则后重建；0=保留现有规则仅追加/修改
IPV6_LOCKDOWN="${IPV6_LOCKDOWN:-auto}"               # auto|1|0

# 允许“公网 -> 容器转发”的主机端口（默认只允许 80/443）
FORWARD_ALLOW_HOST_PORTS="${FORWARD_ALLOW_HOST_PORTS:-80 443}"

# =========================
# Helpers
# =========================
log() { echo -e "\033[1;32m[+] $*\033[0m"; }
warn() { echo -e "\033[1;33m[!] $*\033[0m" >&2; }
die() { echo -e "\033[1;31m[×] $*\033[0m" >&2; exit 1; }

need_root() {
  [[ "${EUID:-0}" -eq 0 ]] || die "请用 root 执行（sudo -i 后再跑）。"
}

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local ts
  ts="$(date +%F_%H%M%S)"
  cp -a "$f" "${f}.bak.${ts}"
}

detect_sshd_ports() {
  if command -v sshd >/dev/null 2>&1; then
    sshd -T -f /etc/ssh/sshd_config 2>/dev/null | awk '/^port /{print $2}' | xargs || true
  fi
  # fallback
  [[ -n "${ports:-}" ]] && echo "$ports" || echo "22"
}

make_docker_user_block() {
  local ports="$1"
  local block=""
  block+="# BEGIN DOCKER-USER LOCKDOWN\n"
  block+=":DOCKER-USER - [0:0]\n\n"
  block+="# 放行已建立连接\n"
  block+="-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN\n\n"
  block+="# 放行容器发起的流量（容器互通/出网）\n"
  block+="-A DOCKER-USER -i docker0 -j RETURN\n"
  block+="-A DOCKER-USER -i br+ -j RETURN\n"
  block+="-A DOCKER-USER -i docker+ -j RETURN\n\n"
  block+="# 只允许外部 -> 容器：按“原始访问主机端口”匹配（防止 8080:80 这类绕过）\n"
  for p in ${ports}; do
    block+="-A DOCKER-USER -o docker0 -p tcp -m conntrack --ctorigdstport ${p} -j RETURN\n"
    block+="-A DOCKER-USER -o br+    -p tcp -m conntrack --ctorigdstport ${p} -j RETURN\n"
  done
  block+="\n# 其他任何外部 -> 容器转发，一律丢弃\n"
  block+="-A DOCKER-USER -o docker0 -j DROP\n"
  block+="-A DOCKER-USER -o br+    -j DROP\n\n"
  block+="# 其余不处理\n"
  block+="-A DOCKER-USER -j RETURN\n"
  block+="# END DOCKER-USER LOCKDOWN\n"
  printf "%b" "${block}"
}

inject_block_before_commit_in_filter_table() {
  local file="$1"
  local block="$2"

  [[ -f "$file" ]] || die "找不到文件：$file"

  if grep -q "BEGIN DOCKER-USER LOCKDOWN" "$file"; then
    log "已存在 DOCKER-USER LOCKDOWN 区块：$file（跳过注入）"
    return 0
  fi

  backup_file "$file"

  local tmp
  tmp="$(mktemp)"

  awk -v block="$block" '
    BEGIN{in_filter=0; added=0}
    {
      if ($0=="*filter") {in_filter=1}
      if (in_filter && $0=="COMMIT" && added==0) {
        print block
        added=1
      }
      print $0
      if (in_filter && $0=="COMMIT") {in_filter=0}
    }
    END{
      if (added==0) {
        print "ERROR: failed to inject block (no COMMIT inside *filter?)" > "/dev/stderr"
        exit 1
      }
    }
  ' "$file" > "$tmp"

  cat "$tmp" > "$file"
  rm -f "$tmp"
  log "已注入 DOCKER-USER LOCKDOWN 到：$file"
}

enable_ip_forward() {
  log "确保开启 IPv4 转发（Docker 通常需要）"
  cat >/etc/sysctl.d/99-docker-ipforward.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
  sysctl --system >/dev/null || sysctl -w net.ipv4.ip_forward=1 >/dev/null
}

install_ufw() {
  log "安装 ufw"
  apt-get update -y
  apt-get install -y ufw
}

configure_ufw() {
  local ssh_ports="$1"
  local input_ports="80 443 ${ssh_ports} ${EXTRA_INPUT_TCP_PORTS}"

  log "禁用 ufw（应用新规则前）"
  ufw --force disable || true

  if [[ "$UFW_RESET" == "1" ]]; then
    log "重置 ufw 规则（UFW_RESET=1）"
    ufw --force reset
  else
    warn "保留现有 ufw 规则（UFW_RESET=0），仅会追加必要配置"
  fi

  log "设置默认策略：拒绝入站 / 允许出站"
  ufw default deny incoming
  ufw default allow outgoing

  log "放行主机入站 TCP 端口：${input_ports}（SSH 端口用 limit）"
  for p in ${input_ports}; do
    [[ -n "$p" ]] || continue
    if [[ " ${ssh_ports} " == *" ${p} "* ]]; then
      ufw limit "${p}/tcp" comment "limit ssh tcp ${p}" >/dev/null
    else
      ufw allow "${p}/tcp" comment "allow tcp ${p}" >/dev/null
    fi
  done

  log "允许转发（Docker 依赖 DEFAULT_FORWARD_POLICY=ACCEPT）"
  sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw

  log "启用 ufw"
  yes | ufw enable >/dev/null

  log "ufw 状态："
  ufw status verbose || true
}

configure_docker_user_lockdown() {
  local after_rules="/etc/ufw/after.rules"
  local after6_rules="/etc/ufw/after6.rules"

  log "配置 DOCKER-USER 转发兜底（只允许转发到容器的主机端口：${FORWARD_ALLOW_HOST_PORTS}）"

  local block
  block="$(make_docker_user_block "${FORWARD_ALLOW_HOST_PORTS}")"
  inject_block_before_commit_in_filter_table "$after_rules" "$block"

  # IPv6：auto 时根据 /etc/default/ufw 判断
  local do_ipv6="0"
  if [[ "$IPV6_LOCKDOWN" == "1" ]]; then
    do_ipv6="1"
  elif [[ "$IPV6_LOCKDOWN" == "0" ]]; then
    do_ipv6="0"
  else
    if grep -Eq '^[[:space:]]*IPV6=yes' /etc/default/ufw 2>/dev/null; then
      do_ipv6="1"
    fi
  fi

  if [[ "$do_ipv6" == "1" ]]; then
    if [[ -f "$after6_rules" ]]; then
      local block6
      block6="$(make_docker_user_block "${FORWARD_ALLOW_HOST_PORTS}")"
      inject_block_before_commit_in_filter_table "$after6_rules" "$block6"
    else
      warn "未找到 ${after6_rules}，跳过 IPv6 规则注入。"
    fi
  else
    warn "IPv6 兜底未开启（IPV6_LOCKDOWN=${IPV6_LOCKDOWN}）。"
  fi
}

reload_and_restart() {
  log "重载 ufw"
  ufw reload >/dev/null || true

  # Docker 可能未安装/未启用：尽量不报错
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files | grep -q '^docker\.service'; then
      log "重启 docker（让 DOCKER-USER 跳转/规则稳定生效）"
      systemctl restart docker || warn "docker 重启失败（可能未安装/未运行），请自行确认。"
    else
      warn "系统未检测到 docker.service（可能未安装 Docker），跳过 docker 重启。"
    fi
  fi

  log "验证（可能需要安装 iptables 命令）："
  command -v iptables >/dev/null 2>&1 && iptables -S DOCKER-USER || warn "iptables 不可用或未找到 DOCKER-USER（Docker 未运行时也可能这样）。"
  command -v ip6tables >/dev/null 2>&1 && ip6tables -S DOCKER-USER || true
}

main() {
  need_root

  local ssh_ports
  ssh_ports="$(detect_sshd_ports)"
  log "检测到 sshd 端口：${ssh_ports}"
  if echo "${ssh_ports}" | grep -qw "22"; then
    warn "检测到 SSH 仍可能在 22 端口。若你已改到 31415，可用：SSH_PORTS='31415' 运行脚本以只放行 31415。"
  fi

  install_ufw
  enable_ip_forward
  configure_ufw "${ssh_ports}"
  configure_docker_user_lockdown
  reload_and_restart

  log "完成。你现在应当具备：主机只开 SSH/80/443；Docker 端口误映射也只能对公网暴露 80/443。"
  warn "注意：不要用 network_mode: host（host 模式不走 DOCKER-USER 兜底）。"
}

main "$@"
